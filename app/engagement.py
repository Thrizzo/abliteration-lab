"""The copilot's engagement: scope statement, rules of engagement, scope, exclusions, time window, prohibited tools,
protected data and auto-run tiers. One engagement is active at a time; every save is a new version under
workspace/engagement/ and goes into the audit log, with who saved it.

The console sends the active version with each copilot run. n8n's scope gate and policy gate enforce it
(deploy/n8n/policy.js), with LAB_ALLOWLIST and LAB_AUTORUN_* as the ceiling: the engagement can narrow the scope and
switch tiers off, never widen them. This module checks what the GUI saves (formats, the ceiling when the console knows
it: the same copilot-scope ConfigMap n8n reads) and hands the payload over; it decides nothing at run time. Its hints
point at rules the prose states but only the judge would enforce (hosts, data); they are worked out on every read and
never applied. Standard library only.
"""
import ipaddress
import json
import os
import re
import tempfile
import threading
import unicodedata
from datetime import datetime, timezone

LIMITS = {"name": 120, "scope_statement": 4000, "roe": 8000, "note": 300}
MAX_ENTRIES = 64
# RFC 1123 host names, lower case (the gate compares host names exactly, so case is normalised here)
_HOST = re.compile(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def now_iso():
    t = datetime.now(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def scope_entry(value):
    """One scope entry as the gate reads it: an IPv4 address, an IPv4 network (CIDR) or an exact host name. Returns
    (kind, normalised text); ValueError otherwise. No IPv6 and no wildcards: the gate cannot verify them."""
    s = str(value or "").strip().lower()
    if not s:
        raise ValueError("empty entry")
    if "/" in s:
        try:
            net = ipaddress.IPv4Network(s, strict=False)
        except ValueError:
            raise ValueError(f"{value!r} is not an IPv4 network (e.g. 10.10.10.0/24)") from None
        return "net", str(net)
    try:
        return "ip", str(ipaddress.IPv4Address(s))
    except ValueError:
        pass
    if re.fullmatch(r"[0-9.]+", s):
        raise ValueError(f"{value!r} is not an IPv4 address")
    if not _HOST.fullmatch(s):
        raise ValueError(f"{value!r} is not an IPv4 address, IPv4 network or host name (no wildcards, no IPv6)")
    return "host", s


def parse_ceiling(text):
    """LAB_ALLOWLIST ("10.10.10.0/24,192.168.56.0/24,box.htb") as entries; entries that do not parse are left out, as
    the gate never matches them."""
    out = []
    for part in str(text or "").split(","):
        try:
            out.append(scope_entry(part))
        except ValueError:
            continue
    return out


def within(entry, ceiling):
    """Whether a scope entry lies inside the ceiling: an address in one of its networks or equal to one of its
    addresses, a network inside one of its networks (or the single address of a /32), a host name listed exactly."""
    kind, val = entry
    if kind == "host":
        return any(k == "host" and v == val for k, v in ceiling)
    if kind == "ip":
        ip = ipaddress.IPv4Address(val)
        return any((k == "net" and ip in ipaddress.IPv4Network(v)) or (k == "ip" and v == val) for k, v in ceiling)
    net = ipaddress.IPv4Network(val)
    return any((k == "net" and net.subnet_of(ipaddress.IPv4Network(v)))
               or (k == "ip" and net.num_addresses == 1 and str(net.network_address) == v) for k, v in ceiling)


def _text(fields, key, errors):
    v = fields.get(key)
    v = "" if v is None else str(v)
    v = v.replace("\r\n", "\n").strip()
    if _CTRL.search(v):
        errors.append(f"{key}: control characters are not allowed")
    if len(v) > LIMITS[key]:
        errors.append(f"{key}: at most {LIMITS[key]} characters ({len(v)} given)")
    return v


def _lines(value):
    """A list from the GUI: a JSON list, or text with one entry per line or comma-separated."""
    if isinstance(value, list):
        items = value
    else:
        items = re.split(r"[\n,]", str(value or ""))
    return [str(x).strip() for x in items if str(x or "").strip()]


def _when(value, key, errors):
    s = str(value or "").strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00") if s.endswith("Z") else s)
    except ValueError:
        errors.append(f"{key}: {s!r} is not a date and time (e.g. 2026-11-26T08:00+01:00)")
        return None
    if dt.tzinfo is None:
        errors.append(f"{key}: give a time zone (e.g. +01:00 or Z), so n8n and the console mean the same moment")
        return None
    return dt.isoformat(timespec="seconds")      # one canonical form, which n8n's Date.parse reads


_SENTENCE = re.compile(r"(?<=[.;!?])\s+|\n+")                    # not at ":": "backup01.lab ...: do not touch it" is one
_NEGATED = re.compile(r"\b(not|never|no|don't|avoid|exclude[ds]?|excluding|forbidden|prohibited|off-limits|out of scope)\b", re.I)
_IP_IN_TEXT = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])")
_TLDS = r"(?:lab|local|htb|thm|corp|internal|lan|intra|com|net|org|io|de)"
_HOST_IN_TEXT = re.compile(rf"\b(?:[a-z0-9-]+\.)+{_TLDS}\b", re.I)


def rule_hints(fields):
    """Hosts that a sentence of the rules or the scope statement puts off-limits ("do not touch backup01.lab", "not a
    target") while Out of scope leaves them open. Only Out of scope is enforced in code; measured with Qwen3-8B as the
    judge, rules like that were missed in 2 of 2 cases (copilot/README.md, "Judge eval")."""
    excluded = []
    for raw in _lines(fields.get("scope_out")):
        try:
            excluded.append(scope_entry(raw))
        except ValueError:
            continue
    out, seen = [], set()
    for key in ("roe", "scope_statement"):
        for sentence in _SENTENCE.split(str(fields.get(key) or "")):
            if not _NEGATED.search(sentence):
                continue
            for m in list(_IP_IN_TEXT.finditer(sentence)) + list(_HOST_IN_TEXT.finditer(sentence)):
                try:
                    entry = scope_entry(m.group(0))
                except ValueError:
                    continue
                if entry[1] in seen or any(within(entry, [x]) for x in excluded):
                    continue
                seen.add(entry[1])
                out.append({"host": entry[1], "sentence": sentence.strip()[:200]})
    return out


# ---------------------------------------------------------------- protected data
# Names of files, folders, shares, tables or buckets no command may name (protected_data, e.g. customers.csv, /backup/,
# HR$, \Users\jdoe\Documents, *.kdbx). n8n's policy gate enforces them (deploy/n8n/policy.js: protectedEntry,
# protectedCheck); the console checks what it saves and is stricter, so every entry it accepts compiles in the gate to
# the same key. copilot/tests/fixtures/protected_vectors.json pins both sides.
PROTECTED_MAX = 128                                  # characters per entry (PD_MAX_LEN in policy.js)
PROTECTED_NAMES = 16                                 # names per entry (PD_MAX_TOKENS)
_BUCKET_SCHEMES = {"s3", "s3a", "gs", "az", "abfs", "abfss", "wasb", "wasbs"}
_EXT_ALONE = {"csv", "tsv", "xlsx", "xls", "docx", "doc", "pdf", "sql", "bak", "txt", "json", "xml", "db", "sqlite", "kdbx", "pst",
              "ost", "zip", "7z", "tar", "gz", "tgz", "dump", "dmp", "ldif", "pfx", "p12", "key", "pem", "mdb", "accdb"}
_HOST_NAME = re.compile(rf"(?:[a-z0-9-]+\.)+{_TLDS}", re.I)


def fold(s):
    """policy.js pdFold, the gate's reading of entries and commands alike: NFKC (fullwidth and compatibility forms),
    format characters removed (zero width, bidi), then upper and lower case (dotless i reads as i, sharp s as ss)."""
    s = unicodedata.normalize("NFKC", str(s))
    return "".join(c for c in s if unicodedata.category(c) != "Cf").upper().lower()


def _entry_char(c):
    return c in "_-$~.* /\\" or unicodedata.category(c)[0] in "LMN"


def protected_key(p):
    """What the gate compiles an entry to: the fold, \\ read as /, repeated slashes as one, spaces next to a slash and
    repeated * dropped. Two entries with the same key are one."""
    k = re.sub(r" ?/ ?", "/", re.sub(r" +", " ", fold(p).replace("\\", "/")))
    return re.sub(r"\*+", "*", re.sub(r"/{2,}", "/", k)).strip()


def _scope_pairs(hosts):
    """Scope entries as scope_entry() pairs; text is parsed, what does not parse is left out."""
    out = []
    for h in hosts or ():
        if isinstance(h, tuple):
            out.append(h)
            continue
        try:
            out.append(scope_entry(h))
        except ValueError:
            continue
    return out


def _scope_host(name, scope):
    """Whether the gate blanks this name before reading a command: a host name in scope, or an address inside it."""
    if any(kind == "host" and val == name for kind, val in scope):
        return True
    try:
        ip = str(ipaddress.IPv4Address(name))
    except ValueError:
        return False
    return within(("ip", ip), scope)


def protected_entry(value, hosts=()):
    """One protected_data entry as it is stored (trimmed, inner whitespace as one space), or ValueError("protected_data:
    ..."), with a message that names the form that works. hosts: the scope (scope_in and the ceiling), as scope_entry()
    pairs or text."""
    p = re.sub(r"\s+", " ", str(value or "")).strip()
    q = p[:40]

    def bad(message):
        return ValueError(f"protected_data: {q!r}{message}")
    if not p:
        raise ValueError("protected_data: an empty entry")
    if len(p) > PROTECTED_MAX:
        raise bad(f" is longer than {PROTECTED_MAX} characters")
    if any(unicodedata.category(c) in ("Cc", "Cs") or ord(c) > 0xFFFF for c in p):
        raise bad(" has control characters or characters outside the Basic Multilingual Plane")
    m = re.match(r"([A-Za-z][A-Za-z0-9+.-]*)://", p)
    if m:
        if m.group(1).lower() in _BUCKET_SCHEMES:
            raise bad(" has a scheme: write the bucket and path without it (acme-hr-exports/2026)")
        raise bad(" names a host: write the path without scheme and host (/backup/customers.csv)")
    if re.match(r"[\\/]{2}", p):                       # the gate reads \ as /: \/ and /\ start with a host too
        raise bad(" names a host: leave it out (HR$, not \\\\fs01\\HR$); the gate cannot tell a host name from its address, "
                  "and hosts belong in Out of scope")
    if re.match(r"[A-Za-z]:", p):
        raise bad(" starts with a drive letter: write \\Users\\jdoe (it also covers C$\\Users\\jdoe)")
    if re.match(r"[\\/]?[A-Za-z]\$[\\/]", p):
        raise bad(" starts with an admin share: write \\Users\\jdoe (it also covers C:\\Users\\jdoe)")
    if p.startswith("~"):
        raise bad(" starts with ~: write the folder itself (home/jdoe/.ssh, or .ssh for every user's)")
    if re.search(r"\\[ '\"]", p):
        raise bad(" is shell-escaped: write the name as it is (Personnel Files)")
    f = fold(p)
    # the folded text too: NFKC can turn a letter into punctuation the gate refuses (the middle dot of L with middle dot)
    if not all(_entry_char(c) for c in p + f):
        raise bad(": only letters, digits, spaces and _ - $ ~ . * (with / or \\ between names); no quotes, %, :, @, =, commas "
                  "or brackets")
    try:
        ipaddress.IPv4Network(f, strict=False)
    except ValueError:
        pass
    else:
        raise bad(" is an address or network: put it in Out of scope")
    if not re.search(r"[\\/*]", p) and _HOST_NAME.fullmatch(f):
        raise bad(" is a host: put it in Out of scope")
    names = [n for n in re.split(r"[\\/ ]+", f) if n]
    scope = _scope_pairs(hosts)
    if any(_scope_host(n, scope) for n in names):
        raise bad(" contains a host in scope, which the gate never reads as data: put it in Out of scope")
    if any(set(n) <= {".", "*"} and "." in n for n in names):
        raise bad(" has a . or .. folder: name the folder itself")
    if any(set(n) - {"*"} and sum(unicodedata.category(c)[0] in "LN" for c in n) < 2 for n in names):
        raise bad(" is too broad: every name needs two letters or digits (write *.csv, not *)")
    if not any(unicodedata.category(c)[0] == "L" for c in f):
        raise bad(" needs a letter")
    # the gate splits on slashes after dropping one at each end: a part of spaces only ("a/ /b") is an empty name there
    s = re.sub(r"/{2,}", "/", f.replace("\\", "/"))
    s = s[1:] if s.startswith("/") else s
    if any(not part.strip(" ") for part in (s[:-1] if s.endswith("/") else s).split("/")):
        raise bad(" has an empty name between two slashes")
    if len(names) == 1 and names[0] in _EXT_ALONE and not p.startswith(("/", "\\")):   # /csv/ is a folder, csv any .csv
        raise bad(f" alone matches every .{names[0]} name: write *.{names[0]} if you mean that")
    if len(names) > PROTECTED_NAMES:
        raise bad(f" has more than {PROTECTED_NAMES} names")
    return p


def protected_list(value, errors, hosts=()):
    """validate()'s protected_data: a JSON list, or text with one entry per line or comma-separated. Every refused entry
    goes to errors; duplicates (the same key) are dropped, the first spelling kept."""
    scope = _scope_pairs(hosts)
    out, keys = [], set()
    for raw in _lines(value):
        try:
            p = protected_entry(raw, scope)
        except ValueError as e:
            errors.append(str(e))
            continue
        k = protected_key(p)
        if k not in keys:
            keys.add(k)
            out.append(p)
    if len(out) > MAX_ENTRIES:
        errors.append(f"protected_data: at most {MAX_ENTRIES} entries")
    return out[:MAX_ENTRIES]


# Hints: names the rules protect in prose while Protected data does not list them. Measured, the judge alone authorized
# "curl ... /backup/customers.csv -o customers.csv" under "do not download personal data" (copilot/README.md, "Judge
# eval"). Only sentences with a negation or protective cue and a data word, category or concrete name count.
_PROTECT = re.compile(r"\b(stop|report|protect(?:ed)?|confidential|sensitive|untouched|must remain|nicht|kein\w*|niemals|verboten|tabu)\b",
                      re.I)
_DATA_WORD = re.compile(r"\b(download|copy|exfiltrat\w*|retrieve|read|open|access|dump|collect|take|transfer|extract|keep|store|data|"
                        r"files?|folders?|director(?:y|ies)|shares?|tables?|databases?|records?|documents?|backups?|buckets?|exports?|"
                        r"herunterladen|kopieren|lesen|öffnen|daten|dateien|freigabe|ordner|tabelle|datenbank)\b", re.I)
_CATEGORY = re.compile(r"\b(personal data|personal information|pii|customer data|client data|employee data|hr data|payroll|salar\w*|"
                       r"medical|patient\w*|health data|credit card|cardholder|social security|passport|bank account|iban|gdpr|dsgvo|"
                       r"personenbezogen\w*|kundendaten|mitarbeiterdaten|gehalt\w*|patientendaten|personalakte\w*)\b", re.I)
_DATA_EXT = "csv|tsv|xlsx|xls|docx|doc|pdf|sql|bak|dump|dmp|db|sqlite|mdb|accdb|pst|ost|kdbx|json|xml|zip|7z|tar|gz|tgz|ldif|pfx|p12"
_DATA_EXTS = set(_DATA_EXT.split("|"))
# a word may start only where no name character precedes it: tried once per word, so these stay linear on long text
_CONCRETE = re.compile(rf"\\\\|://|(?<![\w:/])//[\w.-]|(?<![\w-])[\w-]+\.(?:{_DATA_EXT})\b|\w\$(?!\w)", re.I)
_DOTTED = re.compile(r"(?<![\w-])-*(\w[\w-]*(?:\.[\w-]+)+)")             # a dotted name, its last part decides
_KEYWORDS = ((re.compile(r"\bkeepass\b|\bpassword (?:vault|database)s?\b", re.I), "*.kdbx"),
             (re.compile(r"\boutlook data files?\b|\bpst files?\b", re.I), "*.pst"))
_STOP = {"file", "files", "network", "shared", "server", "drive", "production", "main", "whole", "entire", "same", "other", "any", "every",
         "this", "that", "data", "new", "old", "test", "temp", "big", "central", "customer", "client", "employee"}
_UNC_PART = r"[\w$.-]+(?: [A-Z0-9][\w$.-]*)*"        # a space only before a capital: "Personnel Files", not "HR$ or the backups"
# The path candidate's lookbehind holds every character the path itself may hold: a match then starts only where a path
# starts, never again at each later "/" (a run of "*/" took quadratic time).
_CANDIDATES = (
    (re.compile(rf"(?:\\\\|(?<![\w:/])//)[\w.-]+[\\/]({_UNC_PART}(?:[\\/]{_UNC_PART})*)"), lambda m: m.group(1).rstrip(" .")),  # UNC
    (re.compile(r"\b(?:https?|ftp|smb)://[\w.-]+(?::\d+)?(/[\w/.%$-]*[\w$]/?)", re.I), lambda m: m.group(1)),   # URL: its path
    (re.compile(r"\b(?:s3|gs)://([\w.-]+(?:/[\w/.-]*)?)", re.I), lambda m: m.group(1).rstrip("/.")),             # bucket and path
    (re.compile(r"\b[A-Za-z]:((?:\\[\w$.*-]+)+)"), lambda m: m.group(1).rstrip(".")),                             # C:\a\b -> \a\b
    (re.compile(r"(?<![\w/:.*$-])(/(?:[\w.*$-]+/)*[\w.*$-]*[A-Za-z][\w.*$-]*/?)"), lambda m: m.group(1).rstrip(".")),  # /srv/exports/
    (_DOTTED, lambda m: m.group(1) if m.group(1).rsplit(".", 1)[1].lower() in _DATA_EXTS else ""),               # customers.csv
    (re.compile(r"(?<![\w\\/$])([A-Za-z][\w-]{1,30}\$)(?![\w$])"), lambda m: m.group(1)),                         # HR$
    (re.compile(r"\b[Tt]he (?:\"([\w$. -]{2,40})\"|'([\w$. -]{2,40})'|([A-Z][\w$.-]{1,40}|[\w$.-]{0,20}[\d$_.][\w$.-]{0,20})) "
                r"(?:share|folder|directory|bucket)\b"), lambda m: (m.group(1) or m.group(2) or m.group(3)).strip()),  # the X share
    (re.compile(r"\b[Tt]he ([\"']?)([A-Za-z_][\w$.-]{2,40})\1 (?:table|collection)\b"),
     lambda m: "" if m.group(2).lower() in _STOP else m.group(2)),                                               # the X table
)
_UNC, _THE_SHARE, _THE_TABLE = 0, 7, 8                  # their places in _CANDIDATES
_TOOL_DIRS = {"bin", "sbin", "libexec", "tools", "wordlists", "seclists"}     # the runner's programs and wordlists
BROAD = {"share", "shared", "public", "common", "users", "user", "data", "files", "home", "temp", "tmp", "admin", "docs", "documents",
         "scans", "logs", "web", "www", "root", "opt", "usr", "wordlists", "seclists", "kali", "passwords", "test", "db", "it", "hr"}
_DESCRIPTIVE = re.compile(r"\s(?:share|folder|directory|table|database|bucket|collection|files)$", re.I)
# a sentence that states the scope ("Scope: the API at https://api.acme.lab/v2/ (no production data)", "the shop at
# http://10.10.10.5/shop/ is in scope, but ..."), and the clauses it is split into: a name it gives counts only with a
# negation or protective cue in its own clause
_STATES_SCOPE = re.compile(r"\b(?:in[ -]scope|within (?:the )?scope|(?:limited|restricted) to)\b|\bscope\s*:", re.I)
_CLAUSE = re.compile(r"[,;()]|\bbut\b|\band\b(?=\s+(?:must|should|shall|may|will|can|cannot|do|does|is|are)\b)", re.I)


def _names(c):
    return [n for n in protected_key(c).strip("/").split("/") if n]


def _names_within(c, d):
    """Whether c's names stand, in order and whole, among d's: HR$/Payroll holds HR$ and Payroll, not HR$/Pay. A name
    also stands for its hidden share (HR in HR$), as "the HR share" names \\\\fs01\\HR$."""
    a, b = _names(c), _names(d)
    return bool(a) and any(all(x == y or x + "$" == y for x, y in zip(a, b[i:i + len(a)])) for i in range(len(b) - len(a) + 1))


def _candidates(sentence, scope, scoped=False):
    """The names a sentence gives that the console would accept, as (name, verbatim): verbatim for a UNC path or a
    quoted name, a share or folder spelled as it is. One mention matched twice gives one name: a name inside another's
    match (the file name of a URL or a path), or "the HR share" whose names another candidate spells (HR$). Two mentions
    stay two (customers.csv and customers.csv.bak, \\\\fs01\\HR$ and \\\\fs01\\HR$\\Payroll). scoped: the sentence states
    the scope, so a name needs a negation or protective cue in its own clause."""
    found = []
    for i, (rx, pick) in enumerate(_CANDIDATES):
        for m in rx.finditer(sentence):
            c = pick(m)
            if c:
                found.append((c, m.span(), i in (_THE_SHARE, _THE_TABLE), i == _UNC or (i == _THE_SHARE and bool(m.group(1) or m.group(2)))))
    found = found[:64] + [(entry, None, False, False) for rx, entry in _KEYWORDS if rx.search(sentence)]
    valid = []
    for c, span, described, verbatim in found:
        try:
            valid.append((protected_entry(c, scope), span, described, verbatim))    # hosts are rule_hints' business
        except ValueError:
            continue

    def merged(c, d):
        if protected_key(c[0]) == protected_key(d[0]):
            return False                                   # the same name twice: data_hints keeps the first
        if c[1] and d[1] and d[1][0] <= c[1][0] and c[1][1] <= d[1][1] and (c[1] != d[1] or len(d[0]) > len(c[0])):
            return True                                    # inside the other's match: one mention matched twice
        return c[2] and _names_within(c[0], d[0])          # "the HR share" next to \\fs01\HR$

    cuts = [m.span() for m in _CLAUSE.finditer(sentence)] if scoped else []

    def cued(c):
        if not scoped:
            return True
        clause = sentence if not c[1] else sentence[max([e for s, e in cuts if e <= c[1][0]], default=0):
                                                    min([s for s, e in cuts if s >= c[1][1]], default=len(sentence))]
        return bool(_NEGATED.search(clause) or _PROTECT.search(clause))
    return [(c[0], c[3]) for c in valid if cued(c) and not any(merged(c, d) for d in valid if d is not c)]


def _short(key):
    """A lone name of three or fewer letters or digits (it, db, key) hits every spelling; a hidden share (HR$), a dotfile
    (.env) or an extension (*.csv) stays narrow however short."""
    name = key.strip("/")
    if re.search(r"[/ ]", name) or name.endswith("$") or name.startswith((".", "*.")):
        return False
    return len(re.sub(r"\W", "", name)) <= 3


# Whether a listed entry already blocks a command that names a candidate: the gate's own match (policy.js nameMatch and
# entryIn), so customers or *.csv cover customers.csv. Hints only; enforcement stays in the gate.
def _name_match(tok, comp, left_whole, right_whole):
    return _name_match1(tok, comp, left_whole, right_whole) or (
        len(comp) > 1 and comp.endswith("$") and not tok.endswith(("$", "*")) and _name_match1(tok, comp[:-1], left_whole, right_whole))


def _name_match1(tok, comp, left_whole, right_whole):
    def at_start(i):
        return i == 0 or (not left_whole and comp[i - 1] == ".")

    def at_end(j):
        return j == len(comp) or (not right_whole and comp[j] == ".")
    if "*" not in tok:
        i = comp.find(tok)
        while i >= 0:
            if at_start(i) and at_end(i + len(tok)):
                return True
            i = comp.find(tok, i + 1)
        return False
    pieces = tok.split("*")
    first, last = pieces[0], pieces[-1]
    s = 0 if first == "" else next((i for i in _finds(comp, first) if at_start(i)), -1)        # leftmost start
    if s < 0:
        return False
    e = len(comp) if last == "" else next((j + len(last) for j in reversed(list(_finds(comp, last))) if at_end(j + len(last))), -1)
    if e < 0:                                                                                  # rightmost end
        return False
    pos, limit = s + len(first) + (first == ""), e - len(last)     # a leading * takes at least one character
    if pos > limit:
        return False
    for piece in pieces[1:-1]:
        if piece:
            at = comp.find(piece, pos)
            if at < 0 or at + len(piece) > limit:
                return False
            pos = at + len(piece)
    return True


def _finds(text, sub):
    i = text.find(sub)
    while i >= 0:
        yield i
        i = text.find(sub, i + 1)


def _compiled(entry):
    """An entry as the gate compiles it: its names, the separator before each, and whether it is whole at each end."""
    k = protected_key(entry)
    toks, seps = [], []
    for part in k.strip("/").split("/"):
        for j, word in enumerate(w for w in part.split(" ") if w):
            seps.append(None if not toks else (" " if j else "/"))
            toks.append(word)
    return {"toks": toks, "seps": seps, "lead": k.startswith("/"), "trail": len(k) > 1 and k.endswith("/"),
            "names": [n for n in k.strip("/").split("/") if n]}


def _reading(cand):
    """A candidate as the gate reads a command word: its names, and its components with the separator before each."""
    t = re.sub(r"/+", "/", re.sub(r"\s+", " ", fold(cand).replace("\\", "/"))).strip()
    comps, seps, cur, sep = [], [], "", ""
    for c in t + "\0":
        if c != "\0" and (c in "._$~-" or unicodedata.category(c)[0] in "LMN"):
            cur += c
            continue
        if cur:
            comps.append(cur)
            seps.append(sep)
            cur, sep = "", ""
        sep += c
    return {"names": [n for n in protected_key(cand).strip("/").split("/") if n], "comps": comps, "seps": seps}


def _covers(entry, r):
    want, names = entry["names"], r["names"]
    if want and any(names[i:i + len(want)] == want for i in range(len(names) - len(want) + 1)):
        return True                                   # the same names in order (also a glob listed as written)
    toks, k, comps = entry["toks"], len(entry["toks"]), r["comps"]
    return k > 0 and any(all((j == 0 or r["seps"][i + j] == entry["seps"][j])
                             and _name_match(toks[j], comps[i + j], j > 0 or entry["lead"], j < k - 1 or entry["trail"])
                             for j in range(k)) for i in range(len(comps) - k + 1))


def data_hints(fields, hosts=()):
    """[{kind, entry, sentence}]: suggest (the rules protect a name Protected data does not list), broad (a common or
    very short name, from the rules or saved), descriptive (a saved entry that reads like a description), unnamed (the
    rules protect personal data but name nothing, while the list is empty), move (a Prohibited entry that looks like
    data). Deterministic, from fixed patterns; never stored, never applied."""
    scope = _scope_pairs(hosts)
    listed = _lines(fields.get("protected_data"))
    cover = [_compiled(e) for e in listed]
    out, seen, unnamed, verbatim = [], set(), None, []
    for key in ("roe", "scope_statement"):
        for sentence in _SENTENCE.split(str(fields.get(key) or "")):
            if not ((_NEGATED.search(sentence) or _PROTECT.search(sentence))
                    and (_DATA_WORD.search(sentence) or _CATEGORY.search(sentence) or _CONCRETE.search(sentence)
                         or any(rx.search(sentence) for rx, _ in _KEYWORDS))):
                continue
            found = _candidates(sentence, scope, scoped=key == "scope_statement" or bool(_STATES_SCOPE.search(sentence)))
            verbatim += [c for c, spelled in found if spelled]
            cands = [c for c, _ in found]
            for cand in cands:
                if len(out) >= 8:                                  # at most 8 from the rules
                    break
                k = protected_key(cand)
                if k in seen:
                    continue
                r = _reading(cand)
                if any(_covers(e, r) for e in cover):              # a listed entry blocks it already
                    continue
                seen.add(k)
                out.append({"kind": "broad" if k.strip("/") in BROAD else "suggest", "entry": cand, "sentence": sentence.strip()[:200]})
            if not cands and not listed and unnamed is None and _CATEGORY.search(sentence):
                unnamed = {"kind": "unnamed", "entry": None, "sentence": sentence.strip()[:200]}
    if unnamed and not any(h["kind"] == "suggest" for h in out):
        out.append(unnamed)
    for e in listed:
        k = protected_key(e)
        if k.strip("/") in BROAD or _short(k):
            out.append({"kind": "broad", "entry": e, "sentence": None})
        elif _DESCRIPTIVE.search(e) and not any(_names_within(e, v) for v in verbatim):   # "Personnel Files" from a UNC path is a name
            out.append({"kind": "descriptive", "entry": e, "sentence": None})
    for p in _lines(fields.get("prohibited")):           # Prohibited matches the raw text only
        if re.search(r"\s", p) or p.startswith("-"):    # a command or a flag (rm -rf /, -oN out/x), not a name
            continue
        if not (re.search(r"[/\\]", p) or re.search(rf"\.(?:{_DATA_EXT})$", p, re.I) or re.search(r"\w\$$", p)):
            continue
        # a move only where Protected data takes the entry (C$, a URL, ../ are refused there) and reads it at least as
        # strictly: a tool or wordlist path (/usr/bin/hydra, /usr/share/wordlists/rockyou.txt) is a local position there,
        # which waits for a human, while Prohibited blocks it
        try:
            protected_entry(p, scope)
        except ValueError:
            continue
        names = _names(p)
        if any(n in _TOOL_DIRS for n in names) and not re.search(rf"\.(?:{_DATA_EXT})$", names[-1], re.I):
            continue
        out.append({"kind": "move", "entry": p, "sentence": None})
    return out


def _stored(rec, key):
    """A stored field; a record saved before protected_data existed has no such key, which is an empty list, not a change."""
    return rec.get(key, [] if key == "protected_data" else None)


class Engagements:
    def __init__(self, project, audit=None, feed=None, ceiling=None, autorun=None, http_error=None):
        self.dir = os.path.join(project, "engagement")
        self.audit, self.feed = audit, feed
        # LAB_ALLOWLIST / LAB_AUTORUN_* as n8n reads them (ConfigMap copilot-scope); None: the console does not know them
        self.ceiling = parse_ceiling(ceiling) if ceiling else None
        self.ceiling_text = ceiling or None
        self.autorun = autorun or {}
        self.http_error = http_error or (lambda status, msg: ValueError(f"{status}: {msg}"))
        self.lock = threading.Lock()

    # ---------------------------------------------------------------- validation
    def validate(self, fields):
        """The fields as they are stored and sent, or http_error(400) listing every problem."""
        if not isinstance(fields, dict):
            raise self.http_error(400, "the engagement is a JSON object")
        errors = []
        out = {k: _text(fields, k, errors) for k in ("name", "scope_statement", "roe")}
        for key in ("scope_in", "scope_out"):
            entries, seen = [], set()
            for raw in _lines(fields.get(key)):
                try:
                    kind, val = scope_entry(raw)
                except ValueError as e:
                    errors.append(f"{key}: {e}")
                    continue
                if key == "scope_in" and self.ceiling is not None and not within((kind, val), self.ceiling):
                    errors.append(f"scope_in: {val} is outside LAB_ALLOWLIST ({self.ceiling_text}): the copilot could never "
                                  f"reach it. Widen LAB_ALLOWLIST first (deploy/k8s, copilot scope)")
                if val not in seen:
                    seen.add(val)
                    entries.append(val)
            if len(entries) > MAX_ENTRIES:
                errors.append(f"{key}: at most {MAX_ENTRIES} entries")
            out[key] = entries[:MAX_ENTRIES]
        prohibited = []
        for p in _lines(fields.get("prohibited")):
            p = re.sub(r"\s+", " ", p)
            if len(p) > 64 or _CTRL.search(p):
                errors.append(f"prohibited: {p[:40]!r} is longer than 64 characters or has control characters")
            elif p.lower() not in (x.lower() for x in prohibited):
                prohibited.append(p)
        if len(prohibited) > MAX_ENTRIES:
            errors.append(f"prohibited: at most {MAX_ENTRIES} entries")
        out["prohibited"] = prohibited[:MAX_ENTRIES]
        out["protected_data"] = protected_list(fields.get("protected_data"), errors, self.scope(out))
        out["window_start"] = _when(fields.get("window_start"), "window_start", errors)
        out["window_end"] = _when(fields.get("window_end"), "window_end", errors)
        if out["window_start"] and out["window_end"] and \
                datetime.fromisoformat(out["window_end"]) <= datetime.fromisoformat(out["window_start"]):
            errors.append("window_end: must be after window_start")
        for key in ("autorun_passive", "autorun_active", "active"):
            v = fields.get(key, key == "active")
            if not isinstance(v, bool):
                errors.append(f"{key}: true or false")
                v = False
            out[key] = v
        if errors:
            raise self.http_error(400, "; ".join(errors))
        return out

    def scope(self, fields):
        """The hosts the gate counts as in scope, which it blanks before it reads a command for protected data: the
        engagement's scope_in and the ceiling, as scope_entry() pairs."""
        return _scope_pairs(_lines(fields.get("scope_in"))) + list(self.ceiling or [])

    # ---------------------------------------------------------------- storage
    def _path(self, version):
        return os.path.join(self.dir, "versions", f"v{int(version):04d}.json")

    def _read(self, path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def _write(self, path, obj):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)

    def current(self):
        """The active record {version, saved, by, note, ...fields}, or None before the first save."""
        return self._read(os.path.join(self.dir, "current.json"))

    def get(self, version):
        rec = self._read(self._path(version))
        if not rec:
            raise self.http_error(404, f"no engagement version {version}")
        return rec

    def versions(self, limit=50):
        try:
            names = sorted((n for n in os.listdir(os.path.join(self.dir, "versions")) if re.fullmatch(r"v\d{4,}\.json", n)), reverse=True)
        except OSError:
            return []
        out = []
        for n in names[:limit]:
            rec = self._read(os.path.join(self.dir, "versions", n)) or {}
            out.append({k: rec.get(k) for k in ("version", "saved", "by", "note", "name", "active")})
        return out

    def save(self, fields, who=None, note=""):
        """A new version from the GUI's fields (validated); saving the same fields again changes nothing."""
        clean = self.validate(fields)
        hints = {"hints": rule_hints(clean), "data_hints": data_hints(clean, self.scope(clean))}   # not stored: worked out each time
        note = str(note or "").strip()[:LIMITS["note"]]
        with self.lock:
            cur = self.current()
            if cur and all(_stored(cur, k) == v for k, v in clean.items()):
                return {**cur, **hints}
            version = max([int(v["version"]) for v in self.versions(limit=1) if v.get("version")] + [0]) + 1
            rec = {"version": version, "saved": now_iso(), "by": (who or {}).get("user") or (who or {}).get("ip"), "note": note, **clean}
            self._write(self._path(version), rec)
            self._write(os.path.join(self.dir, "current.json"), rec)
        changed = sorted(k for k, v in clean.items() if not cur or _stored(cur, k) != v)
        rec = {**rec, **hints}
        msg = f"engagement v{version} saved" + (f": {clean['name']}" if clean["name"] else "") + ("" if clean["active"] else " (inactive)")
        data = {"version": version, "changed": changed, "note": note, "scope_in": clean["scope_in"], "scope_out": clean["scope_out"],
                "prohibited": clean["prohibited"], "protected_data": clean["protected_data"],
                "window": [clean["window_start"], clean["window_end"]], "active": clean["active"]}
        if self.audit:
            self.audit.write("copilot", "engagement", msg, who=who or {}, data=data)
        elif self.feed:
            self.feed.emit("copilot", "engagement", msg, "info", data)
        return rec

    # ---------------------------------------------------------------- what a run gets
    def payload(self):
        """The active engagement as the workflow reads it, or None (no engagement, or switched off): then n8n applies
        LAB_ALLOWLIST alone."""
        cur = self.current()
        if not cur or not cur.get("active", True):
            return None
        keys = ("name", "version", "scope_statement", "roe", "scope_in", "scope_out", "window_start", "window_end", "prohibited",
                "autorun_passive", "autorun_active")
        out = {k: cur.get(k) for k in keys}
        if cur.get("protected_data"):          # only when set: a run without it is exactly what it was before the field
            out["protected_data"] = cur["protected_data"]
        return out

    def status(self):
        cur = self.current()
        return {"current": cur, "hints": rule_hints(cur) if cur else [], "versions": self.versions(20),
                "data_hints": data_hints(cur, self.scope(cur)) if cur else [],
                "ceiling": {"known": self.ceiling is not None, "allowlist": self.ceiling_text,
                            "autorun_passive": self.autorun.get("passive"), "autorun_active": self.autorun.get("active")}}
