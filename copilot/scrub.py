"""Redaction for writeups before they are embedded (RAG) or trained on (QLoRA).

Per source:
- ``engagement`` (your own client work): everything that identifies the client or is a secret is replaced by a
  stable per-document placeholder (``<IP_1>``, ``<HOST_2>``, ``<EMAIL_1>``, ``<USER_1>``, ``<SECRET>``), so the text
  still reads as one story ("foothold on <IP_1>, pivot to <IP_2>") but names nobody.
- ``htb`` / ``blog`` / ``pwk`` (public or course material): lab IPs and box names stay, they are useful context and
  identify nobody. Only hard secrets (private keys, JWTs, cloud keys, bearer tokens) and your own redact terms are
  removed.

This is pattern matching, so it is best effort: run ``python -m copilot.ingest --dry-run --show-redactions`` and read
the result before client notes go anywhere. Standard library only.
"""
import ipaddress
import re

# public reference domains that identify no client; kept readable in engagement notes
PUBLIC_DOMAINS = {
    "github.com", "githubusercontent.com", "gitlab.com", "exploit-db.com", "nvd.nist.gov", "cve.mitre.org", "mitre.org",
    "attack.mitre.org", "microsoft.com", "learn.microsoft.com", "docs.microsoft.com", "owasp.org", "portswigger.net",
    "hacktricks.xyz", "book.hacktricks.xyz", "gtfobins.github.io", "lolbas-project.github.io", "nmap.org",
    "kali.org", "offsec.com", "hackthebox.com", "tryhackme.com", "python.org", "pypi.org", "npmjs.com", "google.com",
    "cisa.gov", "first.org", "rapid7.com", "metasploit.com", "wikipedia.org", "stackoverflow.com", "debian.org",
    "ubuntu.com", "apache.org", "oracle.com", "mozilla.org", "cloudflare.com", "letsencrypt.org", "example.com",
    "example.org", "example.net", "localhost",
}
# TLDs treated as host names. Deliberately excludes ones that collide with file extensions (sh, py, md, pl, rs, so, ps,
# js, cs, ts, rb, go, ai...), otherwise every "script.sh" or "config.php" would be eaten.
TLDS = {
    "com", "net", "org", "io", "co", "biz", "info", "gov", "edu", "mil", "int", "local", "lan", "internal", "corp",
    "intranet", "home", "htb", "thm", "lab", "test", "de", "uk", "fr", "nl", "at", "ch", "it", "es", "eu", "us",
    "ca", "au", "jp", "cn", "ru", "in", "br", "se", "no", "dk", "fi", "pl", "be", "cz", "ie", "pt", "tech", "cloud",
    "dev", "app", "online", "site", "xyz",
}
KEEP_USERS = {"public", "default", "default user", "all users", "administrator", "root", "guest", "localsystem"}
NOT_DOMAINS = {"HKLM", "HKCU", "HKCR", "HKU", "HKCC", "BUILTIN", "NT", "SYSTEM", "HKEY_LOCAL_MACHINE",
               "HKEY_CURRENT_USER", "HKEY_USERS", "HKEY_CLASSES_ROOT", "WINDOWS", "SYSVOL", "NETLOGON"}

# ---- hard secrets: removed from every source ---------------------------------------------------------------------
HARD_SECRETS = [
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S), "<PRIVATE_KEY>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "<JWT>"),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "<AWS_KEY>"),
    (re.compile(r"(?i)(aws_secret_access_key\s*[=:]\s*)\S+"), r"\1<SECRET>"),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/-]{12,}=*"), r"\1 <SECRET>"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "<GITHUB_TOKEN>"),
    (re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}\b"), "<SLACK_TOKEN>"),
]

# ---- credentials and hashes: engagement notes only --------------------------------------------------------------
CRED_PATTERNS = [
    # Kerberos / crypt / NetNTLM style hashes
    (re.compile(r"\$krb5(?:tgs|asrep|pa)\$[^\s]+"), "<HASH>"),
    (re.compile(r"\$(?:1|2[abxy]?|5|6|y|argon2(?:id|i|d)?)\$[^\s:]+"), "<HASH>"),
    (re.compile(r"\b[^\s:]+::[^\s:]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+"), "<NETNTLM_HASH>"),
    (re.compile(r"\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b"), "<NTLM_HASH>"),
    (re.compile(r"\b[a-fA-F0-9]{64}\b"), "<HASH>"),
    (re.compile(r"\b[a-fA-F0-9]{40}\b"), "<HASH>"),
    (re.compile(r"\b[a-fA-F0-9]{32}\b"), "<HASH>"),
    # key=value style secrets
    (re.compile(r"(?i)\b(password|passwd|pwd|pass|passphrase|secret|api[_-]?key|access[_-]?token|token)"
                r"(\s*[:=]\s*|\s+is\s+)([\"']?)([^\s\"']{3,})\3"), r"\1\2\3<SECRET>\3"),
    # tool flags that carry a password
    (re.compile(r"(?i)(--password[= ])([\"']?)[^\s\"']+\2"), r"\1\2<SECRET>\2"),
    (re.compile(r"(?i)(/p:)(\S+)"), r"\1<SECRET>"),
    (re.compile(r"(?i)\b((?:evil-winrm|crackmapexec|cme|netexec|nxc|xfreerdp|sshpass|mysql|psql|hydra|kerbrute|"
                r"smbmap|rpcclient|wmiexec(?:\.py)?|psexec(?:\.py)?|smbexec(?:\.py)?)\b[^\n]*?\s-p\s*)([\"']?)[^\s\"']+\2"),
     r"\1\2<SECRET>\2"),
    # credentials in URLs
    (re.compile(r"(://)([^:/\s@]+):([^@/\s]+)@"), r"\1\2:<SECRET>@"),
]
# credentials that carry a user name: the user goes through the registry so it gets the same placeholder everywhere.
# These run BEFORE the hash patterns above (they need the raw hashes to recognise the line).
RX_SECRETSDUMP = re.compile(r"^([^\s:]+):(\d+):[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::", re.M)
RX_IMPACKET = re.compile(r"\b([\w.-]+)/([\w.$-]+):([^@\s]+)@")
RX_SMB_U = re.compile(r"(-U\s+[\"']?)([^%\s\"']+)%([^\s\"']+)")

RX_EMAIL = re.compile(r"\b[\w.+-]+@([\w-]+\.)+[A-Za-z]{2,}\b")
RX_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\d)")
RX_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}(?![\w:])")
RX_HOST = re.compile(r"(?<![\w.<@-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24}))(?![\w-])")
# user names may contain dots but never END in sentence punctuation ("... /home/svc_backup." must not swallow the period
# into the name, which would also give the same user a second placeholder)
_NAME_END = r"[^\\\s\"'.,;:)\]]"
RX_WINUSER = re.compile(r"(?i)(C:\\Users\\)([^\\\s\"']*" + _NAME_END + ")")
RX_NIXUSER = re.compile(r"(/home/)([A-Za-z0-9_-](?:[A-Za-z0-9._-]*[A-Za-z0-9_-])?)")
RX_DOMUSER = re.compile(r"\b([A-Z][A-Z0-9-]{1,14})\\([A-Za-z0-9_$-](?:[A-Za-z0-9._$-]*[A-Za-z0-9_$-])?)")
RX_FLAGUSER = re.compile(r"(?i)\b((?:evil-winrm|crackmapexec|cme|netexec|nxc|hydra|kerbrute|smbmap)\b[^\n]*?\s-u\s*)"
                         r"([\"']?)([^\s\"']*" + _NAME_END + r")\2")
RX_RDPUSER = re.compile(r"(?i)(/u:)([^\s\"']*" + _NAME_END + ")")


class Registry:
    """Stable placeholders per document: the same value always maps to the same <KIND_n>."""

    def __init__(self):
        self.maps = {}
        self.counts = {}

    def get(self, kind, value):
        key = value.lower()
        m = self.maps.setdefault(kind, {})
        if key not in m:
            m[key] = f"<{kind}_{len(m) + 1}>"
        self.counts[kind] = self.counts.get(kind, 0) + 1
        return m[key]

    def bump(self, kind):
        self.counts[kind] = self.counts.get(kind, 0) + 1


def _is_public_host(host):
    h = host.lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in PUBLIC_DOMAINS)


def _keep_ip(ip):
    """Loopback, any, broadcast and netmasks identify nobody; everything else in client notes is redacted."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True                                   # not an IP (e.g. 999.1.1.1): leave alone
    if addr.is_loopback or addr.is_unspecified or str(addr).startswith("255.") or str(addr).endswith(".255"):
        return True
    return False


def _apply(patterns, text, reg, kind):
    for rx, repl in patterns:
        text, n = rx.subn(repl, text)
        for _ in range(n):
            reg.bump(kind)
    return text


def compile_terms(terms):
    """Your own redact list (client names, internal project names, domains). Longest first, case-insensitive."""
    clean = sorted({t.strip() for t in terms if t.strip() and not t.strip().startswith("#")}, key=len, reverse=True)
    return [(t, re.compile(r"(?<![\w])" + re.escape(t) + r"(?![\w])", re.I)) for t in clean]


def load_terms(path):
    if not path:
        return []
    with open(path, encoding="utf-8") as f:
        return compile_terms(f.read().splitlines())


def _user(reg, name):
    return name if name.lower() in KEEP_USERS else reg.get("USER", name)


def scrub(text, source, terms=()):
    """Returns (scrubbed_text, report) where report counts replacements per kind.

    Order matters for engagement notes: user-bearing credentials first (they need the raw line), then value-only
    secrets and hashes, then e-mails, DOMAIN\\user / tool -u / profile paths, then host names and only THEN your own
    terms - a term replaced early would hide the DOMAIN\\user or host around it from the patterns that remove them."""
    reg = Registry()
    text = _apply(HARD_SECRETS, text, reg, "SECRET")
    if source == "engagement":
        text = RX_SECRETSDUMP.sub(lambda m: f"{_user(reg, m.group(1))}:{m.group(2)}:<LM_HASH>:<NT_HASH>:::", text)
        text = RX_IMPACKET.sub(lambda m: f"{m.group(1)}/{reg.get('USER', m.group(2))}:<SECRET>@", text)
        text = RX_SMB_U.sub(lambda m: f"{m.group(1)}{reg.get('USER', m.group(2))}%<SECRET>", text)
        text = _apply(CRED_PATTERNS, text, reg, "SECRET")
        text = RX_EMAIL.sub(lambda m: reg.get("EMAIL", m.group(0)), text)
        text = RX_DOMUSER.sub(lambda m: m.group(0) if m.group(1) in NOT_DOMAINS
                              else reg.get("DOMAIN", m.group(1)) + "\\" + _user(reg, m.group(2)), text)
        text = RX_FLAGUSER.sub(lambda m: m.group(1) + m.group(2) + reg.get("USER", m.group(3)) + m.group(2), text)
        text = RX_RDPUSER.sub(lambda m: m.group(1) + reg.get("USER", m.group(2)), text)
        text = RX_WINUSER.sub(lambda m: m.group(1) + _user(reg, m.group(2)), text)
        text = RX_NIXUSER.sub(lambda m: m.group(1) + _user(reg, m.group(2)), text)
        text = RX_HOST.sub(lambda m: m.group(0) if (m.group(2).lower() not in TLDS or _is_public_host(m.group(1)))
                           else reg.get("HOST", m.group(1)), text)
    for term, rx in terms:                             # your terms, every source
        text = rx.sub(lambda m, t=term: reg.get("TERM", t), text)
    if source == "engagement":
        text = RX_IPV4.sub(lambda m: m.group(0) if _keep_ip(m.group(0)) else reg.get("IP", m.group(0)), text)
        text = RX_IPV6.sub(lambda m: reg.get("IP6", m.group(0)), text)
    return text, dict(sorted(reg.counts.items()))
