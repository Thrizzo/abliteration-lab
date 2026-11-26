/*
 * Deterministic scope + command policy for the pentest-copilot workflow.
 *
 * This is the one layer in the buffer that an LLM cannot be talked out of: it is plain code that
 * runs on the *structured* proposal, never on the abliterated model's free text as instructions.
 * The n8n "Scope gate" and "Policy gate" Code nodes paste the body of this file and call decide().
 * It is kept as its own module so it can be unit-tested outside n8n (see policy.test.js).
 *
 * No dependencies: n8n Code nodes run sandboxed without npm modules.
 */

// ---- IPv4 / CIDR -----------------------------------------------------------------------------
function ipToInt(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function inCidr(ip, cidr) {
  const [net, bitsRaw] = cidr.split('/');
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  const ipInt = ipToInt(ip);
  const netInt = ipToInt(net);
  if (ipInt === null || netInt === null || bits < 0 || bits > 32) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

// A target is in scope if it is an allowlisted hostname, or an IP inside an allowlisted CIDR/host.
function targetInScope(target, allowlist) {
  if (!target) return false;
  const t = String(target).trim().toLowerCase();
  for (const entry of allowlist) {
    const e = String(entry).trim().toLowerCase();
    if (e.includes('/')) {
      if (inCidr(t, e)) return true; // t is an IP, e is a CIDR
    } else if (ipToInt(e) !== null) {
      if (t === e) return true; // both plain IPs
    } else if (t === e) {
      return true; // hostname match (exact; no wildcard on purpose)
    }
  }
  return false;
}

// ---- pull every host / IP a command string refers to -----------------------------------------
// Greedy where it is safe to be: anything in host position of a URL, //unc path or user@host is a host whatever its
// TLD; a bare dotted name is a host unless it ends in a file extension (common.txt, shell.php are wordlists and files,
// not domains - treating them as hosts blocked legitimate gobuster runs).
const FILE_EXT = new Set(['txt', 'lst', 'list', 'php', 'html', 'htm', 'xml', 'json', 'yml', 'yaml', 'py', 'sh', 'js', 'ts',
  'conf', 'cfg', 'ini', 'log', 'bak', 'old', 'zip', 'gz', 'tgz', 'tar', 'bz2', 'xz', '7z', 'rar', 'exe', 'dll', 'msi', 'ps1',
  'psm1', 'bat', 'cmd', 'vbs', 'aspx', 'asp', 'jsp', 'jspx', 'war', 'jar', 'md', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv',
  'sql', 'db', 'sqlite', 'key', 'pem', 'crt', 'cer', 'pub', 'ovpn', 'kirbi', 'ccache', 'so', 'rb', 'pl', 'go', 'rs', 'c',
  'cpp', 'h', 'java', 'class', 'elf', 'bin', 'img', 'iso', 'pcap', 'pcapng', 'nmap', 'gnmap', 'out', 'png', 'jpg', 'gif']);

function extractTargets(command) {
  const found = new Set();
  const text = String(command || '');
  for (const m of text.matchAll(/(?<![\w.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![\w.]*\d)/g)) found.add(m[0]);
  for (const m of text.matchAll(/\b[a-z][a-z0-9+.-]*:\/\/(?:[^@\/\s]*@)?(\[[^\]]+\]|[^:\/\s?#"']+)/gi)) found.add(m[1].toLowerCase());
  for (const m of text.matchAll(/(?:^|[\s"'=])\/\/([^\/\s"']+)/g)) found.add(m[1].toLowerCase());          // //host/share
  for (const m of text.matchAll(/\b[\w.$-]+@([a-z0-9][\w.-]*[a-z0-9])\b/gi)) found.add(m[1].toLowerCase()); // user@host
  for (const m of text.matchAll(/\b((?:[a-z0-9-]+\.)+([a-z]{2,24}))\b/gi)) {
    if (!FILE_EXT.has(m[2].toLowerCase())) found.add(m[1].toLowerCase());
  }
  if (/\blocalhost\b/i.test(text)) found.add('127.0.0.1');
  for (const h of [...found]) if (h === 'localhost') { found.delete(h); found.add('127.0.0.1'); }
  return [...found].filter((h) => !/^\d+\.\d+(\.\d+)?$/.test(h)); // drop version-like 1.2 / 1.2.3 fragments
}

// Target forms the scope check cannot verify: a placeholder copied from a reference note (measured: the operator
// proposed "nmap -p- -T4 <other-host-ip>"), shell variables and substitutions, target list files, and alternative IP
// encodings that tools accept but the dotted-quad check does not see (curl http://134744072/ is 8.8.8.8). None of these
// may auto-run; a human sees them. nmap -iR (random internet hosts) is denied outright in decide().
const UNVERIFIABLE = [
  [/<[A-Za-z][\w-]{0,40}>/, 'placeholder instead of a host'],
  [/\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$\(|`/, 'shell variable or command substitution'],
  [/(^|\s)-iL\b/, 'nmap target list file (-iL)'],
  [/(?<![\w.:\/-])\d{8,10}(?![\w.])/, 'integer IP encoding'],
  [/\b0x[0-9a-f]{6,8}\b/i, 'hex IP encoding'],
  [/(?<![\w.])0\d{1,3}\.\d{1,4}\.\d{1,4}\.\d{1,4}\b/, 'octal IP encoding'],
  [/(?<![\w:.\/])(?=[0-9a-f:]*[0-9a-f])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])/i, 'IPv6 literal'],
];

function findUnverifiable(command) {
  const cmd = String(command || '');
  return UNVERIFIABLE.filter(([rx]) => rx.test(cmd)).map(([, why]) => why);
}

// Commands that must never run regardless of target: destroying the operator box, exfil to the
// internet, pivoting out of the lab, clearing your own logs, fork bombs. Extend per engagement.
const DEFAULT_DENY = [
  /\brm\s+-rf?\s+\/(?![\w.])/i, // rm -rf / (bare root), whatever follows the slash
  /\bmkfs\b/i,
  /\bdd\s+if=.*of=\/dev\/[sh]d/i,
  /:\(\)\s*\{\s*:\|:&\s*\}\s*;/, // fork bomb
  /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b/i, // pipe remote script to shell
  /\bshutdown\b|\breboot\b|\bhalt\b/i,
  /history\s+-c|\btruncate\b.*\/var\/log|\b>\s*\/var\/log/i, // anti-forensics
];

// ---- read-only classification ----------------------------------------------------------------
// Decides whether a command is safe to auto-run (passive recon) or must wait for a human.
// FAIL-SAFE: anything not confidently read-only returns false, so uncertainty gates, never runs.
const READONLY_TOOLS = new Set([
  'nmap', 'rustscan', 'masscan', 'ping', 'fping', 'traceroute', 'tracepath', 'arp',
  'host', 'dig', 'nslookup', 'whois', 'dnsrecon', 'dnsenum', 'fierce', 'amass', 'subfinder', 'theharvester',
  'curl', 'wget', 'httpx', 'whatweb', 'wafw00f', 'sslscan', 'sslyze', 'testssl.sh',
  'gobuster', 'ffuf', 'feroxbuster', 'dirb', 'dirbuster', 'wfuzz', 'nikto',
  'enum4linux', 'enum4linux-ng', 'smbmap', 'smbclient', 'ldapsearch', 'rpcclient', 'rpcinfo', 'showmount',
  'snmpwalk', 'onesixtyone', 'nbtscan', 'ike-scan', 'netstat', 'ss', 'nc', 'ncat',
]);
// local filters allowed as pipe targets (they touch local stdout/files, never the target). Not xargs: it runs whatever
// program it is given (curl ... | xargs -n1 curl -sO fetches every name a server lists).
const FILTER_TOOLS = new Set([
  'grep', 'egrep', 'fgrep', 'awk', 'sed', 'cut', 'sort', 'uniq', 'head', 'tail', 'tee', 'tr',
  'wc', 'cat', 'less', 'more', 'jq', 'column', 'tr', 'rev', 'base64', 'cat',
]);
// patterns that make a command mutating/active even if its tool is in READONLY_TOOLS
const MUTATING_PATTERNS = [
  /\b(curl|wget)\b[^|;&]*(-d\b|--data|-F\b|--form|-T\b|--upload-file|-X\s*(POST|PUT|DELETE|PATCH)|--request\s*(POST|PUT|DELETE|PATCH))/i,
  /\bsmbclient\b[^|;&]*-c\b[^|;&]*\b(put|mkdir|rmdir|del|rename|rm)\b/i,
  // rpcclient subcommands that change the domain: setuserinfo2 (a password), createdomuser, deletedomuser, chgpasswd, ...
  /\brpcclient\b[^|;&]*-c\b[^|;&]*(^|[\s'"])(create|delete|del|set|add|chg)\w*/i,
  /\bnc\b(?![^|;&]*-z)[^|;&]*-[a-z]*l/i, // netcat listener (-l) that isn't a -z port check
];
const PASSIVE_NSE = new Set(['safe', 'default']); // the only NSE categories cheap enough for the passive tier

// A tool on the read-only list, or a local filter, that can still run a program, listen or change a share. Each of these
// auto-ran in the passive tier before (found by the protected-data red team, checked against this gate).
function execEscape(bin, seg) {
  const args = seg.split(/\s+/).slice(1);
  if (['nc', 'ncat', 'netcat'].includes(bin) && args.some((t) => /^-[A-Za-z]*[ecl][A-Za-z]*$/.test(t) || /^--(sh-|lua-)?exec(=|$)|^--listen\b/.test(t)))
    return 'netcat that runs a program or listens (-e, -c, --exec, --sh-exec, --lua-exec, -l)';
  if (bin === 'ffuf' && /(^|\s)--?input-cmd\b/.test(seg)) return 'ffuf -input-cmd runs a program';
  if (bin === 'awk' && /system\s*\(|\|\s*"|\|&|getline/.test(seg)) return 'awk that runs a program (system, pipes, getline)';
  if (bin === 'sed' && /(^|[;\n{}\s0-9$\/'"])e(\s|;|'|"|$)|\/[gpiImM0-9]*e[gpiImMwW0-9]*(\s|;|}|'|"|$)/.test(seg)) return 'sed e runs a program';
  if (bin === 'smbclient' && /['";]\s*(!|(mput|put|mkdir|md|rmdir|rd|del|deltree|rm|rename|mv|setmode)\b)/i.test(seg))
    return 'smbclient command that runs a local shell (!) or changes the share';
  if (bin === 'smbmap' && /(^|\s)-[A-Za-z]*x|(^|\s)--(upload|delete|mkdir)\b/.test(seg)) return 'smbmap that runs a command (-x) or changes the share';
  return '';
}

function classifyReadOnly(command) {
  const cmd = String(command || '').trim();
  if (!cmd) return { readOnly: false, reason: 'empty command' };
  if (MUTATING_PATTERNS.some((rx) => rx.test(cmd))) return { readOnly: false, reason: 'command performs a write/active operation' };
  // nmap NSE is passive only if EVERY script in the list is safe/default (a lone "default" prefix must not smuggle in vuln)
  const scriptVal = (cmd.match(/(?:^|\s)--?script[=\s]+("?)([^"\s]+)\1/i) || [])[2];   // nmap reads -script like --script
  if (scriptVal && !scriptVal.split(',').map((s) => s.trim().toLowerCase()).every((s) => PASSIVE_NSE.has(s))) {
    return { readOnly: false, reason: 'nmap NSE beyond safe/default (active-recon tier or human)' };
  }
  // split into segments across line breaks, ; && || and pipes (a shell runs each line as its own command); every segment
  // must be a known read-only tool or local filter
  const segments = cmd.split(/\r\n|\r|\n|\||;|&&|\|\||&/).map((s) => s.trim()).filter(Boolean);
  for (const seg of segments) {
    // strip leading env assignments and sudo
    const toks = seg.split(/\s+/).filter((t) => !/^[A-Z_][A-Z0-9_]*=/.test(t));
    let bin = toks[0] || '';
    if (bin === 'sudo') bin = toks[1] || '';
    bin = bin.replace(/^.*\//, '').toLowerCase(); // basename
    if (!READONLY_TOOLS.has(bin) && !FILTER_TOOLS.has(bin)) {
      return { readOnly: false, reason: `"${bin || '(empty)'}" is not on the read-only tool allowlist` };
    }
    const esc = execEscape(bin, seg);
    if (esc) return { readOnly: false, reason: esc };
  }
  return { readOnly: true, reason: 'passive recon (read-only tools only)' };
}

// ---- active-recon tier (opt-in) --------------------------------------------------------------
// A middle tier between passive recon and "needs a human": active but non-destructive scanning that
// a pentester runs constantly — safe-category nmap NSE and sqlmap in enumerate-only mode. Off unless
// LAB_AUTORUN_ACTIVE_RECON=true. Still fail-safe: anything outside these exact shapes returns false.
const SAFE_NSE = new Set(['safe', 'default', 'discovery', 'version', 'banner']);
const DANGER_NSE = /\b(vuln|exploit|brute|dos|intrusive|malware|fuzzer|external|backdoor)\b/i;
const SQLMAP_ENUM = /--(banner|current-user|current-db|hostname|is-dba|users|dbs|tables|columns|schema|count)\b|(^|\s)-b(\s|$)/i;
const SQLMAP_DANGER = /--(os-shell|os-pwn|os-cmd|sql-shell|sql-query|file-write|file-dest|file-read|reg-add|reg-del|reg-write|dump|dump-all|passwords|eval|udf-inject|priv-esc|crawl)\b/i;

function nmapSafeScripts(cmd) {
  const m = cmd.match(/(?:^|\s)--?script[=\s]+("?)([^"\s]+)\1/i);
  if (!m) return false;                       // no --script => not this tier (plain nmap is passive tier)
  if (DANGER_NSE.test(m[2])) return false;
  return m[2].split(',').map((s) => s.trim().toLowerCase()).every((s) => SAFE_NSE.has(s));
}

// sqlmap rewrites leading Unicode dashes to "-" and "-word" to "--word" (lib/parse/cmdline.py) and accepts unique prefixes
const SQLMAP_RISKY = ['os-shell', 'os-pwn', 'os-cmd', 'os-bof', 'os-smbrelay', 'sql-shell', 'sql-query', 'sql-file', 'file-write', 'file-dest',
  'file-read', 'reg-add', 'reg-del', 'reg-write', 'reg-read', 'dump', 'dump-all', 'passwords', 'eval', 'udf-inject', 'shared-lib', 'priv-esc',
  'crawl', 'search', 'all'];
function sqlmapRisky(words) {
  const n = words.map((t) => t.replace(/^[\u2010\u2013\u2212\u2014\u4e00\u1680\ufe63\uff0d]+/, (m) => '-'.repeat(m.length)));
  if (n.some((t) => /^-[armlgcz]/.test(t))) return true;           // -a all, -r/-m/-l/-c files, -g dork, -z mnemonics
  return n.some((t) => { const m = /^--?([A-Za-z][\w-]*)/.exec(t); if (!m) return false; const x = m[1].toLowerCase();
    return x.length >= 2 && SQLMAP_RISKY.some((d) => d === x || d.startsWith(x) || x.startsWith(d + '-')); });
}

function sqlmapEnumOnly(cmd) {
  if (!/\bsqlmap\b/i.test(cmd)) return false;
  if (SQLMAP_DANGER.test(cmd)) return false;  // any shell/file/registry/dump flag => needs a human
  return SQLMAP_ENUM.test(cmd);               // must actually be an enumeration run, not a blind inject
}

function classifyActiveRecon(command) {
  const cmd = String(command || '').trim();
  if (!cmd) return { ok: false, reason: 'empty command' };
  if (/[\r\n]|\||;|&&|&/.test(cmd)) return { ok: false, reason: 'chained/piped or multi-line commands are not eligible for the active tier' };
  if (DEFAULT_DENY.some((rx) => rx.test(cmd))) return { ok: false, reason: 'denied pattern' };
  if (nmapSafeScripts(cmd)) return { ok: true, reason: 'nmap NSE, safe categories only' };
  if (/\bsqlmap\b/i.test(cmd) && sqlmapRisky(cmd.split(/\s+/))) return { ok: false, reason: 'sqlmap option that dumps, searches or reads files' };
  if (sqlmapEnumOnly(cmd)) return { ok: true, reason: 'sqlmap enumerate-only' };
  return { ok: false, reason: 'not an allowed active-recon shape' };
}

// ---- injection aimed at the judge ------------------------------------------------------------
// The abliterated operator's command is the only text the judge model reads, so it is the only channel an injection
// (from a poisoned writeup, a hostile banner the operator saw, ...) can use to talk the judge into AUTHORIZE. Real shell
// commands almost never contain instructions to an AI, so a deterministic check is both cheaper and far more accurate
// than an LLM guard here (measured: Granite Guardian flagged 8/8 legitimate pentest commands as harmful/jailbreak,
// because every command in a pentest copilot is offensive by design). A hit never auto-runs and always goes to a human.
const INJECTION_PATTERNS = [
  /\b(ignore|disregard|forget|override|bypass)\b[^\n]{0,40}\b(instruction|rule|polic|previous|prior|above|guideline|safeguard|check)/i,
  /\bAUTHORI[SZ]E\b/i,                                   // the judge's own verdict word ("Authorization:" headers do not match)
  /\b(pre-?approved|approve (it|this|every|all)|must not reject|do not reject|don'?t reject|never reject)\b/i,
  /\b(ai reviewer|reviewer|the judge|assistant|as an ai|language model|llm|chatgpt|developer mode|jailbreak|system override|unrestricted assistant)\b/i,
  /\byou are (now|an?)\b|\bfrom now on\b|\bnew (instructions|policy|rules)\b|\bgranted an exception\b/i,
];

function detectInjection(command) {
  const cmd = String(command || '');
  const hits = INJECTION_PATTERNS.filter((rx) => rx.test(cmd)).map((rx) => String(rx));
  return { suspected: hits.length > 0, hits };
}

// ---- the engagement (from the console): narrows the scope, never widens it ---------------------
// The console sends its active engagement with every run: scope entries, exclusions, a time window, prohibited tools or
// flags, protected data, and whether its auto-run tiers are on. LAB_ALLOWLIST and the LAB_AUTORUN_* variables stay the
// ceiling: a host has to be in LAB_ALLOWLIST AND in the engagement scope (when it lists any) AND not excluded, and a tier
// auto-runs only when both the variable and the engagement allow it. A run without an engagement (the web form) uses the
// ceiling alone. Mirrored for display and validation in app/engagement.py; this is the copy that decides.
const asList = (v) => (Array.isArray(v) ? v : []).map((s) => String(s ?? '').trim()).filter(Boolean).slice(0, 64);

function engagementConfig(eng, base) {
  const cfg = { allowlist: base.allowlist || [], autoRunReadOnly: base.autoRunReadOnly === true,
    autoRunActiveRecon: base.autoRunActiveRecon === true, now: base.now };
  if (!eng || typeof eng !== 'object' || Array.isArray(eng)) return cfg;
  return { ...cfg, scopeIn: asList(eng.scope_in), scopeOut: asList(eng.scope_out), prohibited: asList(eng.prohibited),
    protectedData: asList(eng.protected_data),
    window: { start: eng.window_start || null, end: eng.window_end || null },
    autoRunReadOnly: cfg.autoRunReadOnly && eng.autorun_passive === true,
    autoRunActiveRecon: cfg.autoRunActiveRecon && eng.autorun_active === true };
}

// why a host is out of scope ('' when it is in): the ceiling first, then the engagement's scope and exclusions
const SCOPE_WHY = { allowlist: 'not in the allowlist (LAB_ALLOWLIST)', engagement: 'outside the engagement scope', excluded: 'excluded by the engagement' };
function scopeWhy(host, cfg) {
  if (!targetInScope(host, cfg.allowlist || [])) return 'allowlist';
  if ((cfg.scopeIn || []).length && !targetInScope(host, cfg.scopeIn)) return 'engagement';
  if ((cfg.scopeOut || []).length && targetInScope(host, cfg.scopeOut)) return 'excluded';
  return '';
}

// the engagement window, fail-closed: a bound that cannot be read closes it
function windowCheck(win, now) {
  if (!win || (!win.start && !win.end)) return { open: true, reason: '' };
  const t = typeof now === 'number' ? now : Date.now();
  const s = win.start ? Date.parse(win.start) : null;
  const e = win.end ? Date.parse(win.end) : null;
  if (Number.isNaN(s) || Number.isNaN(e)) return { open: false, reason: 'the engagement window cannot be read' };
  if (s !== null && t < s) return { open: false, reason: `outside the engagement window (it starts ${win.start})` };
  if (e !== null && t >= e) return { open: false, reason: `outside the engagement window (it ended ${win.end})` };
  return { open: true, reason: '' };
}

// prohibited entries are words, flags or phrases (no regular expressions: the console checks the same list in Python),
// matched case-insensitively as whole tokens: "hydra" hits /usr/bin/hydra and thc-hydra, "brute" hits ssh-brute
function prohibitedHits(command, prohibited) {
  const cmd = String(command || '');
  return asList(prohibited).filter((p) => new RegExp('(?<![A-Za-z0-9_])' + p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?![A-Za-z0-9_])', 'i').test(cmd));
}

// ---- protected data: files, folders, shares and tables no command may name ------------------------------------------
// The engagement's protected_data lists names (customers.csv, /backup/, HR$, \Users\jdoe\Documents, *.kdbx). The model:
// - words: the command is split the way bash hands it to each program (quotes, escapes, $'...', comments, operators,
//   redirections, heredocs), so a quoted ; or an escaped & splits nothing and cust""omers is customers (shellSegments);
// - positions: a word is data (sent to or used on the target: a URL, a share, a remote path, SQL, a positional argument),
//   local (on the runner: an output file, a wordlist, a key file, an exclusion, a local filter's argument, the program)
//   or ignored (option names, accounts and passwords, file descriptors) (wordClasses);
// - readings: each data or local word is folded (NFKC, format characters dropped, case) with the in-scope hosts blanked,
//   then read with backslashes as path separators, without PowerShell and cmd escapes, without backslashes, without
//   its option letters, and percent-decoded for up to three rounds (wordReadings);
// - block or human: an entry in a data word blocks, like an out-of-scope host. An entry only in a local word, the names
//   of a path entry apart in one command, bulk retrieval (recursion, mget, globs, crawling scripts, dumps) and names
//   read at run time (list and config files, pipes, < files) need a human. An empty list changes nothing.
// Entries become tokens, never regular expressions, and the check is linear in the command length for a given list.
// Mirrored for validation in app/engagement.py (protected_entry); copilot/tests/fixtures/protected_vectors.json pins both.
const PD_CMD_MAX = 4000, PD_MAX_LEN = 128, PD_MAX_TOKENS = 16, PD_MAX_REVIEW = 6;

// the same fold for entries and commands: NFKC (fullwidth and compatibility forms), format characters removed (zero
// width, bidi, soft hyphen), then upper and lower case, which maps dotless i to i and sharp s to ss
const pdFold = (s) => String(s).normalize('NFKC').replace(/\p{Cf}/gu, '').toUpperCase().toLowerCase();
const PD_NAME_CHAR = /[\p{L}\p{M}\p{N}_$~-]/u;                  // a name; with "." a component (customers.csv.gz)
const pdCompChar = (c) => c === '.' || PD_NAME_CHAR.test(c);

// one entry -> { entry, toks, seps, lead, trail } or { entry, error }. A leading or trailing slash means the name must be
// whole on that side; "/" or "\" separates names, a space joins words of one name; "*" is the only wildcard.
function protectedEntry(raw) {
  const entry = String(raw ?? '').trim().replace(/\s+/g, ' ');
  const bad = (error) => ({ entry, error });
  if (!entry) return bad('empty');
  if (entry.length > PD_MAX_LEN) return bad(`longer than ${PD_MAX_LEN} characters`);
  if (/[\u0000-\u001f\u007f\ud800-\udfff]/.test(entry)) return bad('control characters or characters outside the Basic Multilingual Plane');
  let s = pdFold(entry).replace(/\\/g, '/');
  if (s.startsWith('//')) return bad('names a host');
  for (const ch of s) if (!(pdCompChar(ch) || ch === '*' || ch === '/' || ch === ' ')) return bad(`the character "${ch}"`);
  const lead = s.startsWith('/'), trail = s.length > 1 && s.endsWith('/');
  s = s.replace(/\/{2,}/g, '/').replace(/^\/|\/$/g, '');
  const toks = [], seps = [];
  for (const part of s.split('/')) {
    const words = part.split(' ').filter(Boolean);
    if (!words.length) return bad('an empty name');
    words.forEach((w, i) => { seps.push(toks.length ? (i ? ' ' : '/') : null); toks.push(w); });
  }
  if (toks.length > PD_MAX_TOKENS) return bad(`more than ${PD_MAX_TOKENS} names`);
  if (toks.some((t) => /^[.*]+$/.test(t) && t.includes('.'))) return bad('a . or .. folder');
  if (toks.some((t) => !/^\*+$/.test(t) && (t.match(/[\p{L}\p{N}]/gu) || []).length < 2)) return bad('a name with fewer than two letters or digits');
  if (!/\p{L}/u.test(s)) return bad('no letter');
  return { entry, toks: toks.map((t) => t.replace(/\*+/g, '*')), seps, lead, trail };
}

// A token matches a dot-aligned run of a command component: it starts at the component start or right after a ".", and
// ends at the component end or right before a ".", unless that side must be whole. "*" matches any component characters,
// dots included, at least one when it starts the token. A component ending in "$" also matches without it (HR covers HR$).
function nameMatch(tok, comp, leftWhole, rightWhole) {
  return nameMatch1(tok, comp, leftWhole, rightWhole)
    || (comp.length > 1 && comp.endsWith('$') && !tok.endsWith('$') && !tok.endsWith('*') && nameMatch1(tok, comp.slice(0, -1), leftWhole, rightWhole));
}
function nameMatch1(tok, comp, leftWhole, rightWhole) {
  const isStart = (i) => i === 0 || (!leftWhole && comp[i - 1] === '.');
  const isEnd = (j) => j === comp.length || (!rightWhole && comp[j] === '.');
  if (!tok.includes('*')) {
    for (let i = comp.indexOf(tok); i >= 0; i = comp.indexOf(tok, i + 1)) if (isStart(i) && isEnd(i + tok.length)) return true;
    return false;
  }
  const pieces = tok.split('*'), first = pieces[0], last = pieces[pieces.length - 1];
  let s = -1;                                                     // leftmost valid start with the first piece
  if (first === '') s = 0;
  else for (let i = comp.indexOf(first); i >= 0; i = comp.indexOf(first, i + 1)) if (isStart(i)) { s = i; break; }
  if (s < 0) return false;
  let e = -1;                                                     // rightmost valid end with the last piece
  if (last === '') e = comp.length;
  else for (let j = comp.lastIndexOf(last); j >= 0; j = j > 0 ? comp.lastIndexOf(last, j - 1) : -1) if (isEnd(j + last.length)) { e = j + last.length; break; }
  if (e < 0) return false;
  let pos = s + first.length + (first === '' ? 1 : 0);           // a leading * takes at least one character
  const limit = e - last.length;
  if (pos > limit) return false;
  for (let k = 1; k < pieces.length - 1; k++) {                   // middle pieces, leftmost (exact for *-only globs)
    if (!pieces[k]) continue;
    const at = comp.indexOf(pieces[k], pos);
    if (at < 0 || at + pieces[k].length > limit) return false;
    pos = at + pieces[k].length;
  }
  return true;
}
// contiguous: the entry's tokens on consecutive components with exactly the entry's separators ('/' or ' ') between them
function entryIn(e, R) {
  const k = e.toks.length;
  for (let i = 0; i + k <= R.comps.length; i++) {
    let ok = true;
    for (let j = 0; j < k && ok; j++) {
      if (j > 0 && R.seps[i + j] !== e.seps[j]) ok = false;
      else ok = nameMatch(e.toks[j], R.comps[i + j], j > 0 || e.lead, j < k - 1 || e.trail);
    }
    if (ok) return true;
  }
  return false;
}
// a reading -> its components (maximal runs of component characters) and the separator text before each
function pdComponents(r) {
  const comps = [], seps = [];
  let sep = '', cur = '';
  for (const ch of r) {
    if (pdCompChar(ch)) { cur += ch; continue; }
    if (cur) { comps.push(cur); seps.push(sep); cur = ''; sep = ''; }
    sep += ch;
  }
  if (cur) { comps.push(cur); seps.push(sep); }
  return { comps, seps };
}

// The bash subset the gate needs -> [{ words: [{ text, redir, unqBrace }], pipedIn, procSub }]. text is the argument the
// program gets. redir marks redirection targets: in, out, fd, herestr, heredoc (the delimiter) and heredocBody. It never
// fails: an unterminated quote runs to the end. $(...), ${...} and backticks are copied verbatim (they are unverifiable).
const PD_ANSI_C = new Map([['a', '\x07'], ['b', '\b'], ['e', '\x1b'], ['E', '\x1b'], ['f', '\f'], ['n', '\n'], ['r', '\r'], ['t', '\t'],
  ['v', '\v'], ['\\', '\\'], ["'", "'"], ['"', '"'], ['?', '?']]);
function shellSegments(command) {
  const s = String(command ?? '');
  const segs = [];
  let seg = { words: [], pipedIn: false, procSub: false };
  let w = null, redir = null, hdStrip = false, heredocs = [];
  const start = () => { if (!w) w = { text: '', quoted: false, unqBrace: false, br: 0, brSep: false }; };
  const endWord = () => {
    if (!w) return;
    if (redir === 'heredoc') heredocs.push({ delim: w.text, strip: hdStrip, seg });
    seg.words.push({ text: w.text, redir, unqBrace: w.unqBrace });
    w = null; redir = null;
  };
  const endSeg = (piped) => {
    endWord(); redir = null;
    if (seg.words.length) segs.push(seg);
    seg = { words: [], pipedIn: piped, procSub: false };
  };
  const balanced = (i) => {                                       // i at the ( or {; returns the index after its match
    const open = s[i], close = open === '(' ? ')' : '}';
    let d = 0;
    for (; i < s.length; i++) { if (s[i] === open) d++; else if (s[i] === close && --d === 0) return i + 1; }
    return s.length;
  };
  const backtick = (i) => { const j = s.indexOf('`', i + 1); return j < 0 ? s.length : j + 1; };
  const ansiC = (i) => {                                          // $'...' decoded the way bash decodes it
    while (i < s.length && s[i] !== "'") {
      if (s[i] !== '\\') { w.text += s[i++]; continue; }
      const n = s[i + 1];
      let m;
      if (PD_ANSI_C.has(n)) { w.text += PD_ANSI_C.get(n); i += 2; }
      else if ((m = /^[0-7]{1,3}/.exec(s.slice(i + 1, i + 4)))) { w.text += String.fromCharCode(parseInt(m[0], 8) & 0xff); i += 1 + m[0].length; }
      else if (n === 'x' && (m = /^[0-9a-fA-F]{1,2}/.exec(s.slice(i + 2, i + 4)))) { w.text += String.fromCharCode(parseInt(m[0], 16)); i += 2 + m[0].length; }
      else if (n === 'u' && (m = /^[0-9a-fA-F]{1,4}/.exec(s.slice(i + 2, i + 6)))) { w.text += String.fromCharCode(parseInt(m[0], 16)); i += 2 + m[0].length; }
      else if (n === 'U' && (m = /^[0-9a-fA-F]{1,8}/.exec(s.slice(i + 2, i + 10)))) {
        const cp = parseInt(m[0], 16);
        if (cp <= 0x10ffff) w.text += String.fromCodePoint(cp);
        i += 2 + m[0].length;
      } else if (n === 'c' && i + 2 < s.length) { w.text += String.fromCharCode(s.charCodeAt(i + 2) & 0x1f); i += 3; }
      else { w.text += '\\'; i += 1; }
    }
    return i + 1;
  };
  const dquote = (i) => {                                         // "..." and $"...": \ escapes only $ ` " \ and newline
    while (i < s.length && s[i] !== '"') {
      const c = s[i];
      if (c === '\\' && i + 1 < s.length) {
        if (s[i + 1] === '\n') i += 2;
        else if ('$`"\\'.includes(s[i + 1])) { w.text += s[i + 1]; i += 2; }
        else { w.text += '\\'; i++; }
      } else if (c === '$' && (s[i + 1] === '(' || s[i + 1] === '{')) { const j = balanced(i + 1); w.text += s.slice(i, j); i = j; }
      else if (c === '`') { const j = backtick(i); w.text += s.slice(i, j); i = j; }
      else { w.text += c; i++; }
    }
    return i + 1;
  };
  const readHeredocs = (i) => {                                   // the lines after the declaring line, up to the delimiter
    for (const h of heredocs) {
      const lines = [];
      while (i < s.length) {
        const nl = s.indexOf('\n', i), end = nl < 0 ? s.length : nl;
        let line = s.slice(i, end);
        i = nl < 0 ? s.length : nl + 1;
        if (h.strip) line = line.replace(/^\t+/, '');
        if (line === h.delim) break;
        lines.push(line);
      }
      h.seg.words.push({ text: lines.join('\n'), redir: 'heredocBody', unqBrace: false });
    }
    heredocs = [];
    return i;
  };
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '\n') { endSeg(false); i++; if (heredocs.length) i = readHeredocs(i); continue; }
    if (c === ' ' || c === '\t' || c === '\r') { endWord(); i++; continue; }
    if (c === '\\') {
      if (s[i + 1] !== '\n') { start(); w.quoted = true; if (i + 1 < s.length) w.text += s[i + 1]; }
      i += 2; continue;
    }
    if (c === "'") { start(); w.quoted = true; const j = s.indexOf("'", i + 1), end = j < 0 ? s.length : j; w.text += s.slice(i + 1, end); i = end + 1; continue; }
    if (c === '$' && s[i + 1] === "'") { start(); w.quoted = true; i = ansiC(i + 2); continue; }
    if (c === '$' && s[i + 1] === '"') { start(); w.quoted = true; i = dquote(i + 2); continue; }
    if (c === '"') { start(); w.quoted = true; i = dquote(i + 1); continue; }
    if (c === '#' && !w) { const j = s.indexOf('\n', i); i = j < 0 ? s.length : j; continue; }   // a comment
    if (c === '$' && (s[i + 1] === '(' || s[i + 1] === '{')) { start(); const j = balanced(i + 1); w.text += s.slice(i, j); i = j; continue; }
    if (c === '`') { start(); const j = backtick(i); w.text += s.slice(i, j); i = j; continue; }
    if (c === '|') { if (s[i + 1] === '|') { endSeg(false); i += 2; } else { endSeg(true); i += s[i + 1] === '&' ? 2 : 1; } continue; }
    if (c === '&') {
      if (s[i + 1] === '&') { endSeg(false); i += 2; continue; }
      if (s[i + 1] === '>') { endWord(); redir = 'out'; i += s[i + 2] === '>' ? 3 : 2; continue; }
      endSeg(false); i++; continue;
    }
    if (c === ';' || c === '(' || c === ')') { endSeg(false); i++; continue; }
    if (c === '<' || c === '>') {
      if (w && !w.quoted && /^\d+$/.test(w.text)) w = null; else endWord();   // "2>" "0<": the digits are a descriptor
      if (s[i + 1] === '(') { seg.procSub = true; endSeg(false); i += 2; continue; }
      if (s.startsWith('<<<', i)) { redir = 'herestr'; i += 3; continue; }
      if (s.startsWith('<<', i)) { redir = 'heredoc'; i += 2; hdStrip = s[i] === '-'; if (hdStrip) i++; continue; }
      if (s.startsWith('<&', i) || s.startsWith('>&', i)) { redir = 'fd'; i += 2; continue; }
      if (s.startsWith('<>', i)) { redir = 'in'; i += 2; continue; }
      if (c === '<') { redir = 'in'; i++; continue; }
      redir = 'out'; i += (s[i + 1] === '>' || s[i + 1] === '|') ? 2 : 1; continue;
    }
    start();                                                      // {a,b} and {1..9}: bash expands them before the program runs
    if (c === '{') w.br++;
    else if (c === '}' && w.br > 0) { if (w.brSep) w.unqBrace = true; w.br--; }
    else if (w.br > 0 && (c === ',' || (c === '.' && s[i + 1] === '.'))) w.brSep = true;
    w.text += c; i++;
  }
  endSeg(false);
  return segs;
}
// the program word: after redirections, VAR=value words and one sudo (sudo VAR=value prog too), as classifyReadOnly
// reads it; the program is that word's basename, lowercased
function pdProgramIndex(words) {
  const skip = (k) => { while (k < words.length && (words[k].redir || /^[A-Z_][A-Z0-9_]*=/.test(words[k].text))) k++; return k; };
  let k = skip(0);
  if (k < words.length && words[k].text === 'sudo') k = skip(k + 1);
  return k;
}

// Word classes. Local programs only read the runner's files and stdout. Options whose value is a local file make that
// value local; identity options (accounts, passwords, domains) make it ignored when it looks like one. A value that names
// a remote place (scheme, UNC path, host:/path, an in-scope host) is data wherever it stands.
const PD_LOCAL_PROGRAMS = FILTER_TOOLS;                           // without xargs, which runs programs
const PD_LOCAL_OPTS = new Map([
  ...['-o', '-O', '--output', '--output-file', '--output-document', '--output-dir', '-od', '-oN', '-oX', '-oG', '-oA', '-oS'].map((o) => [o, 'output file']),
  ...['-w', '--wordlist', '-iL', '-L', '-P', '-C', '--input-file', '--files-from'].map((o) => [o, 'wordlist or input file']),
  ...['-i', '-F', '-K', '--config'].map((o) => [o, 'key or input file'])]);
const PD_ID_OPTS = new Set(['-u', '-U', '--user', '--username', '-l', '--login', '-p', '--password', '--pass', '--hashes', '-hashes', '--domain', '-W', '--workgroup']);
const pdExclusion = (opt, program) => /^--(exclude|reject)/.test(opt) || opt === '--dont-scan'
  || ((program === 'wget' || program === 'wget2') && (opt === '-X' || opt === '-R'));
const pdOptionKind = (opt, program) => PD_LOCAL_OPTS.get(opt) || (pdExclusion(opt, program) ? 'exclusion' : PD_ID_OPTS.has(opt) ? 'identity' : '');
const pdHostComponent = (t, hosts) => pdComponents(pdFold(t).replace(/\\/g, '/')).comps.some((c) => hosts.has(c));
const pdRemote = (t, hosts) => /:\/\/|^[\\/]{2}|^[^\s/\\:]+:\//.test(t) || pdHostComponent(t, hosts);
const pdIdentityLike = (t, hosts) => !t.includes('://') && !/^[\\/.~]/.test(t) && (t.match(/[\\/]/g) || []).length <= 1 && !pdHostComponent(t, hosts);
function wordClasses(segment, hosts) {
  const ws = segment.words, k = pdProgramIndex(ws);
  const program = k < ws.length ? ws[k].text.replace(/^.*\//, '').toLowerCase() : '';
  const value = (w, kind) => {                                    // the value of a table option
    if (kind !== 'identity') return { w, cls: pdRemote(w.text, hosts) ? 'data' : 'local', kind };
    if (pdIdentityLike(w.text, hosts)) return { w, cls: 'ignored' };
    return pdRemote(w.text, hosts) ? { w, cls: 'data' } : { w, cls: 'local', kind: 'wordlist or input file' };
  };
  const words = [];
  let endOpts = false, pending = '';
  ws.forEach((w, idx) => {
    const t = w.text;
    if (w.redir === 'out') return words.push({ w, cls: 'local', kind: 'redirection' });
    if (w.redir === 'in') return words.push({ w, cls: 'local', kind: 'input file' });
    if (w.redir === 'fd' || w.redir === 'heredoc') return words.push({ w, cls: 'ignored' });
    if (w.redir) return words.push({ w, cls: 'data' });                        // here-strings and heredoc bodies
    if (idx < k) return words.push({ w, cls: 'data' });                        // VAR=value and sudo before the program
    if (idx === k) return words.push({ w, cls: pdRemote(t, hosts) ? 'data' : 'local', kind: 'program name' });
    if (PD_LOCAL_PROGRAMS.has(program)) return words.push({ w, cls: 'local', kind: 'local filter' });
    if (pending) { const kind = pending; pending = ''; return words.push(value(w, kind)); }
    if (endOpts) return words.push({ w, cls: 'data' });
    if (t === '--') { endOpts = true; return words.push({ w, cls: 'ignored' }); }
    if (/^--[^-]/.test(t)) {                                                   // --name (ignored), --name=value
      const eq = t.indexOf('='), kind = pdOptionKind(eq < 0 ? t : t.slice(0, eq), program);
      if (eq < 0) { pending = kind; return words.push({ w, cls: 'ignored' }); }
      const v = { ...w, text: t.slice(eq + 1) };
      return words.push(kind ? value(v, kind) : { w: v, cls: 'data' });
    }
    if (/^-[^-]/.test(t)) {                                                    // -o file, -ofile, -Tcustomers
      const kind = pdOptionKind(t, program);
      if (kind) { pending = kind; return words.push({ w, cls: 'ignored' }); }
      const attachedKind = t.length > 2 ? pdOptionKind(t.slice(0, 2), program) : '';
      if (attachedKind) return words.push(value({ ...w, text: t.slice(2) }, attachedKind));
      return words.push({ w, cls: 'data', attached: true });
    }
    words.push({ w, cls: 'data' });
  });
  return { program, k, words };
}

// Readings of one word. In-scope hosts (and the user part of user@host) are blanked first: they are never data, and a
// blanked host cannot glue a share to a name. Every reading is tidied: whitespace and slash runs collapse, /./ goes.
function pdPercentRound(s) {
  return s.replace(/%u[0-9a-fA-F]{4}|(?:%[0-9a-fA-F]{2})+/g, (run) => {
    if (run[1] === 'u') return String.fromCharCode(parseInt(run.slice(2), 16));              // IIS %uXXXX
    try { return decodeURIComponent(run); } catch (e) {                                     // not UTF-8: bytes >= 0x80 separate
      return run.replace(/%([0-9a-fA-F]{2})/g, (m, h) => { const n = parseInt(h, 16); return n < 0x80 ? String.fromCharCode(n) : ' '; });
    }
  });
}
const pdTidy = (s) => s.replace(/\s+/g, ' ').replace(/\/{2,}/g, '/').replace(/\/(?:\.\/)+/g, '/').trim();
function pdBlank(f, hosts) {
  if (!hosts.size) return f;
  const ac = [...f.replace(/\\/g, '/')], chars = [...f], spans = [];
  let cur = '', st = 0;
  for (let p = 0; p <= ac.length; p++) {
    if (p < ac.length && pdCompChar(ac[p])) { if (!cur) st = p; cur += ac[p]; continue; }
    if (!cur) continue;
    let len = hosts.has(cur) ? cur.length : 0;
    if (!len) for (const h of hosts) if (h.length > len && cur.startsWith(h + '.')) len = h.length;   // hr.lab.xml: the host part
    if (len) {
      spans.push([st, st + len]);
      if (ac[st - 1] === '@') {                                   // user@host, DOMAIN/user:pass@host: the user part too
        let b = st - 1;
        while (b > 0 && !/[\s='"]/.test(ac[b - 1]) && !(ac[b - 1] === '/' && ac[b - 2] === '/')) b--;
        spans.push([b, st]);
      }
    }
    cur = '';
  }
  for (const [x, y] of spans) for (let q = x; q < y; q++) chars[q] = ' ';
  return chars.join('');
}
function wordReadings(cw, hosts) {
  const text = cw.w.text, f = pdBlank(pdFold(text), hosts);
  const bases = [f.replace(/\\/g, '/')];                          // A, the plain reading: backslash is a path separator
  if (/[`^]/.test(f)) bases.push(f.replace(/[`^]/g, '').replace(/\\/g, '/'));       // B: PowerShell and cmd escapes removed
  if (f.includes('\\')) bases.push(f.replace(/\\/g, ''));         // E: backslash escapes a shell inside the argument
  if (cw.attached) {                                              // -Tcustomers, -vTcustomers: the value after the letters
    for (let n = 2; n <= 4 && n < text.length; n++) {
      if (!/^[A-Za-z]+$/.test(text.slice(1, n))) break;
      bases.push(pdBlank(pdFold(text.slice(n)), hosts).replace(/\\/g, '/'));
    }
  }
  const readings = [], seen = new Set();
  const add = (r, plain) => { r = pdTidy(r); if (!seen.has(r)) { seen.add(r); readings.push({ r, plain, ...pdComponents(r) }); } };
  let nested = false;
  bases.forEach((b, idx) => {
    add(b, idx === 0);
    let d = b;
    for (let round = 0; round < 3; round++) { const n = pdPercentRound(d); if (n === d) break; d = n; }
    if (pdPercentRound(d) !== d) nested = true;
    if (d !== b) add(pdFold(d).replace(/\\/g, '/').replace(/\+/g, ' '), false);
  });
  return { readings, nested };
}

// Bulk retrieval (names the command fetches without spelling them) and names read at run time, for the programs that can
// auto-run. A risky option counts in any spelling: a prefix of its long name (--mi is --mirror), =value, or its letter in
// a short-option cluster before the first letter that takes a value (wget: n takes the next letter). A safety flag (-g,
// -n, --no-glob) counts only in its exact standalone spelling. Every other program needs a human anyway.
const PD_VALUE_LETTERS = { wget: 'eoaiBtOTwQPlARDIXU', wget2: 'eoaiBtOTwQPlARDIXU', curl: 'AbcCdDeEFHKmoPQrtTuUwxXyYz' };
const pdLong = (args, names) => args.some((t) => {
  const m = /^--([A-Za-z0-9][\w-]*)/.exec(t);
  return !!m && /[A-Za-z]/.test(m[1]) && names.some((n) => n.startsWith(m[1].toLowerCase()));
});
// the values of a long option in any spelling (--execute v, --exe=v); null when none follows
const pdLongValues = (args, name) => args.flatMap((t, i) => {
  const m = /^--([A-Za-z0-9][\w-]*)(?:=([\s\S]*))?$/.exec(t);
  if (!m || !/[A-Za-z]/.test(m[1]) || !name.startsWith(m[1].toLowerCase())) return [];
  return [m[2] !== undefined ? m[2] : (i + 1 < args.length ? args[i + 1] : null)];
});
// short-option clusters: does a risky letter come before the first letter that takes a value; the values of one letter
function pdClusterScan(t, program, onLetter) {
  if (!/^-[A-Za-z0-9]/.test(t)) return;
  const vals = PD_VALUE_LETTERS[program] || '';
  for (let p = 1; p < t.length; p++) {
    if ((program === 'wget' || program === 'wget2') && t[p] === 'n') { p++; continue; }
    if (onLetter(t[p], p) || vals.includes(t[p]) || !/[A-Za-z0-9]/.test(t[p])) return;
  }
}
const pdCluster = (args, program, risky) => args.some((t) => { let hit = false; pdClusterScan(t, program, (c) => (hit = risky.includes(c))); return hit; });
const pdClusterValues = (args, program, letter) => args.flatMap((t, i) => {
  const out = [];
  pdClusterScan(t, program, (c, p) => {
    if (c !== letter) return false;
    out.push(p + 1 < t.length ? t.slice(p + 1) : (i + 1 < args.length ? args[i + 1] : null));
    return true;
  });
  return out;
});
// a one-dash word holding a letter anywhere (smbmap -A, smbclient -T, ...), and what follows that letter or the next word
const pdLetter = (args, letter) => args.some((t) => /^-[^-]/.test(t) && t.includes(letter));
const pdLetterValues = (args, letter) => args.flatMap((t, i) => {
  if (!/^-[^-]/.test(t) || !t.includes(letter)) return [];
  const rest = t.slice(t.indexOf(letter) + 1);
  return [rest, i + 1 < args.length ? args[i + 1] : ''].filter(Boolean);
});
const PD_NSE_OK = new Set(['default', 'version', 'banner']);
// READONLY_TOOLS without a bulk or run-time form; the generic rules (pipes, < files) cover their client forms
const PD_BULK_NONE = new Set(['masscan', 'ping', 'fping', 'traceroute', 'tracepath', 'arp', 'host', 'dig', 'nslookup', 'whois',
  'dnsrecon', 'dnsenum', 'fierce', 'amass', 'subfinder', 'theharvester', 'sslscan', 'sslyze', 'testssl.sh', 'gobuster',
  'enum4linux', 'enum4linux-ng', 'ldapsearch', 'rpcclient', 'rpcinfo', 'showmount', 'snmpwalk', 'onesixtyone', 'nbtscan',
  'ike-scan', 'netstat', 'ss', 'nc', 'ncat']);
// a one- or two-dash word abbreviating name to at least min letters (Getopt::Long and getopt_long_only accept these)
const pdAbbrev = (args, name, min, anyCase) => args.some((t) => {
  const m = /^--?([A-Za-z][\w-]*)/.exec(t);
  return !!m && m[1].length >= min && name.startsWith(anyCase ? m[1].toLowerCase() : m[1]);
});
// program, its non-redirect words after the program, the segment's classified words, the in-scope hosts. Options that load
// settings from a file count as names read at run time: wget --config, curl -K, ffuf, httpx and nikto -config, wfuzz
// --recipe, nmap --datadir and --resume, rustscan --config-path and custom scripts.
function bulkReasons(program, args, classifiedWords, hosts) {
  const bulk = [], runtime = [];
  const settings = (label) => runtime.push(`${label} (settings the gate cannot see)`);
  if (program === 'wget' || program === 'wget2') {
    if (pdCluster(args, program, 'rmp') || pdLong(args, ['recursive', 'mirror', 'page-requisites'])) bulk.push('wget -r/-m/-p (recursion)');
    if (!args.includes('--no-glob') && args.some((t) => /^ftp:\/\//i.test(t) && /[*?[]/.test(t))) bulk.push('wget FTP wildcard');
    if (pdCluster(args, program, 'i') || pdLong(args, ['input-file'])) runtime.push('wget -i (URLs from a file)');
    const exec = pdClusterValues(args, program, 'e').concat(pdLongValues(args, 'execute'));      // -e v, -qe v, --exe=v
    if (pdLong(args, ['config']) || exec.some((v) => v === null || !/^robots\s*=\s*off$/i.test(v.trim()))) settings('wget --config/-e');
  }
  if (program === 'curl') {
    // every URL curl gets, with or without a scheme (an in-scope host names one), or after --url
    const urls = args.filter((t) => pdRemote(t, hosts)).concat(pdLongValues(args, 'url').filter((v) => v !== null));
    if (!args.includes('-g') && !args.includes('--globoff') && urls.some((u) => /[[\]{}]/.test(u))) bulk.push('curl URL glob ([...] or {...})');
    if (pdCluster(args, program, 'K') || pdLong(args, ['config'])) runtime.push('curl -K/--config');
    if (pdLong(args, ['variable', 'expand-']) || args.some((t) => /^--expand-/i.test(t))) runtime.push('curl --variable/--expand');
    if (pdLongValues(args, 'url').some((v) => v !== null && v.startsWith('@'))) runtime.push('curl --url @file');
  }
  if (program === 'httpx') {
    if (args.some((t) => /^--?(l|list|path|request|rr)(=|$)/.test(t))) runtime.push('httpx -l/-path/-request (names from a file)');
    if (args.some((t) => /^--?config(=|$)/.test(t))) settings('httpx -config');
  }
  if ((program === 'whatweb' || program === 'wafw00f') && (pdLetter(args, 'i') || pdLong(args, ['input-file', 'input']))) {
    runtime.push(`${program} -i (URLs from a file)`);
  }
  if (program === 'nikto') {
    if (pdAbbrev(args, 'save', 2, true)) bulk.push('nikto -Save (keeps responses)');
    if (pdAbbrev(args, 'config', 2, true)) settings('nikto -config');
  }
  if (program === 'feroxbuster') {
    // recursion is off only with an exact -n or --no-recursion, or when every depth given is 1
    const depth = args.flatMap((t, i) => ((t === '-d' || t === '--depth') && i + 1 < args.length ? [args[i + 1]] : t.startsWith('--depth=') ? [t.slice(8)] : []));
    if (!args.includes('-n') && !args.includes('--no-recursion') && !(depth.length && depth.every((v) => v === '1'))) bulk.push('feroxbuster recursion (on by default)');
    if (pdLong(args, ['stdin', 'resume-from'])) runtime.push('feroxbuster --stdin/--resume-from');
  }
  if (program === 'dirb' && !args.includes('-r')) bulk.push('dirb recursion (on by default)');
  if (program === 'dirbuster') bulk.push('dirbuster');
  if (program === 'ffuf') {
    if (args.some((t) => /^--?recursion(=|$)/.test(t))) bulk.push('ffuf -recursion');
    if (args.some((t) => /^--?od(=|$)/.test(t))) bulk.push('ffuf -od (keeps responses)');
    if (args.some((t) => /^--?request(=|$)/.test(t))) runtime.push('ffuf -request (request from a file)');
    if (args.some((t) => /^--?config(=|$)/.test(t))) settings('ffuf -config');
  }
  if (program === 'wfuzz') {
    if (pdLetter(args, 'R')) bulk.push('wfuzz -R (recursion)');
    if (pdLong(args, ['field', 'efield'])) bulk.push('wfuzz --field/--efield (prints responses)');
    if (pdLong(args, ['recipe'])) settings('wfuzz --recipe');
  }
  if (program === 'smbmap' && pdLetter(args, 'A')) bulk.push('smbmap -A (downloads files matching a pattern)');
  if (program === 'smbclient') {
    // commands from -c in any spelling (-c, -Nc, -c'mget *', --comm=...), here-strings and heredoc bodies
    const cmds = pdLetterValues(args, 'c').concat(pdLongValues(args, 'command').filter((v) => v !== null),
      classifiedWords.filter((cw) => cw.w.redir === 'herestr' || cw.w.redir === 'heredocBody').map((cw) => cw.w.text));
    const fetchesAll = cmds.some((c) => c.split(/[;\n]/).some((x) => {
      const f = (x.trim().split(/\s+/)[0] || '').toLowerCase();
      return (f.length >= 2 && 'mget'.startsWith(f)) || (f.length >= 3 && ('recurse'.startsWith(f) || 'tarmode'.startsWith(f)));
    }));
    if (fetchesAll || pdLetter(args, 'T') || pdLong(args, ['tar'])) bulk.push('smbclient mget/recurse/tar');
  }
  if (program === 'nmap' || program === 'rustscan') {
    const scripts = args.flatMap((t, i) => (/^--?script$/.test(t) ? args.slice(i + 1, i + 2) : /^--?script=/.test(t) ? [t.slice(t.indexOf('=') + 1)] : []));
    if (scripts.some((v) => v.split(',').some((x) => !PD_NSE_OK.has(x.trim().toLowerCase())))) bulk.push('nmap NSE beyond default, version and banner');
    if (args.some((t) => /^--?script-args/.test(t))) bulk.push('nmap --script-args');
    if (pdAbbrev(args, 'datadir', 5) || pdAbbrev(args, 'resume', 3)) settings('nmap --datadir/--resume');
  }
  if (program === 'rustscan') {
    const own = args.includes('--') ? args.slice(0, args.indexOf('--')) : args;            // after -- the words go to nmap
    if (pdLetter(own, 'c') || pdLong(own, ['config-path']) || pdLongValues(own, 'scripts').some((v) => v !== 'none' && v !== 'default')) {
      settings('rustscan --config-path/--scripts');
    }
  }
  if (program === 'sqlmap' && sqlmapRisky(args)) bulk.push('sqlmap dump, search or file read');
  return { bulk, runtime };
}
const PD_CONFIG_ENV = new Set(['WGETRC', 'SYSTEMWGETRC', 'CURL_HOME', 'HOME', 'XDG_CONFIG_HOME']);
const PD_SHORT_NAME = /^[\p{L}\p{N}_$-]{1,6}~\d{1,6}(\.[\p{L}\p{N}_$-]{1,3})?$/u;   // CUSTOM~1.CSV can stand for customers.csv

// -> { hits: entries named in a data position (as written, list order), decoded: hits seen only after decoding,
//      review: why a human must look (at most PD_MAX_REVIEW lines), count: entries in force, unreadable ones included }
function protectedCheck(command, entries, inScopeHosts) {
  const compiled = asList(entries).map(protectedEntry);
  const out = { hits: [], decoded: [], review: [], count: compiled.length };
  if (!compiled.length) return out;
  const local = [], apart = [], bulk = [], runtime = [], cannot = [];
  for (const e of compiled) if (e.error) cannot.push(`the entry "${e.entry.slice(0, 40)}" cannot be read (${e.error})`);
  const cmd = String(command ?? '');
  if (cmd.length > PD_CMD_MAX) cannot.push(`command longer than ${PD_CMD_MAX} characters`);
  else {
    const hosts = new Set((Array.isArray(inScopeHosts) ? inScopeHosts : []).map((h) => pdFold(h)));
    const segs = shellSegments(cmd).map((seg) => {
      const c = wordClasses(seg, hosts);
      for (const cw of c.words) if (cw.cls !== 'ignored') cw.read = wordReadings(cw, hosts);
      return { seg, ...c };
    });
    for (const e of compiled.filter((x) => !x.error)) {
      let hit = false, plain = false, localKind = '';
      scan: for (const s of segs) {
        for (const cw of s.words) {
          if (cw.cls === 'ignored' || (cw.cls === 'local' && (hit || localKind))) continue;
          for (const R of cw.read.readings) {
            if (!entryIn(e, R)) continue;
            if (cw.cls === 'local') { localKind = cw.kind; break; }        // the first local word that names it
            hit = true;
            if (R.plain) { plain = true; break scan; }
          }
        }
      }
      if (hit) { out.hits.push(e.entry); if (!plain) out.decoded.push(e.entry); continue; }
      if (localKind) { local.push(`${e.entry} (${localKind})`); continue; }
      // apart: two or more real names (a lone * is no evidence), each in some data word of one segment
      const real = e.toks.map((t, j) => [t, j]).filter(([t]) => t !== '*');
      if (real.length > 1 && segs.some((s) => real.every(([t, j]) => s.words.some((cw) => cw.cls === 'data'
        && cw.read.readings.some((R) => R.comps.some((comp) => nameMatch(t, comp, j > 0 || e.lead, j < e.toks.length - 1 || e.trail))))))) {
        apart.push(e.entry);
      }
    }
    for (const s of segs) {
      const args = s.seg.words.slice(s.k + 1).filter((w) => !w.redir).map((w) => w.text);
      const r = bulkReasons(s.program, args, s.words, hosts);
      bulk.push(...r.bulk);
      runtime.push(...r.runtime);
      if (s.program === 'xargs') runtime.push('xargs');
      else if (s.seg.pipedIn && !PD_LOCAL_PROGRAMS.has(s.program)) runtime.push(`${s.program || 'a program'} reads a pipe`);
      for (const w of s.seg.words) if (w.redir === 'in' && pdFold(w.text) !== '/dev/null') runtime.push(`input from a file (<${w.text.slice(0, 30)})`);
      if (s.seg.procSub) runtime.push('process substitution');
      for (const w of s.seg.words.slice(0, s.k)) {
        const m = /^([A-Z_][A-Z0-9_]*)=/.exec(w.text);
        if (m && PD_CONFIG_ENV.has(m[1])) runtime.push(`${m[1]} points a tool at another config`);
      }
      for (const cw of s.words) {
        const written = cw.kind === 'output file' || cw.kind === 'redirection' || (s.program === 'tee' && cw.kind === 'local filter');
        if (written && /(^|\/)\.[^./\s]/.test(cw.w.text)) runtime.push(`writes a dotfile that can change later commands (${cw.w.text.slice(0, 30)})`);
        if (cw.cls !== 'data') continue;
        if (cw.w.unqBrace) cannot.push('bash expands {a,b} into names the gate does not see');
        if (cw.read.nested) cannot.push('percent-encoding nested more than 3 times');
        for (const R of cw.read.readings) for (const comp of R.comps) if (PD_SHORT_NAME.test(comp)) cannot.push(`a Windows short name (${comp.toUpperCase()})`);
      }
    }
  }
  const uniq = (a) => [...new Set(a)];
  out.review = uniq([
    ...(local.length ? [`protected data only in a local position: ${uniq(local).join(', ')}`] : []),
    ...(apart.length ? [`protected data named apart: ${uniq(apart).join(', ')}`] : []),
    ...(bulk.length ? [`bulk retrieval while data is protected: ${uniq(bulk).join(', ')}`] : []),
    ...(runtime.length ? [`names read at run time while data is protected: ${uniq(runtime).join(', ')}`] : []),
    ...uniq(cannot).map((x) => `cannot check for protected data: ${x}`),
  ]).slice(0, PD_MAX_REVIEW);
  return out;
}
// the block line: entries as written, in list order, at most five
const protectedReason = (hits, decoded) => 'command names protected data: '
  + hits.slice(0, 5).map((h) => h + (decoded.includes(h) ? ' (after decoding)' : '')).join(', ') + (hits.length > 5 ? ` and ${hits.length - 5} more` : '');

// ---- the gate --------------------------------------------------------------------------------
// proposal: { command, target, rationale }  (already parsed out of the abliterated model's text, or typed by the operator)
// config:   { allowlist: string[], deny?: RegExp[], scopeIn?, scopeOut?, prohibited?, protectedData?, window?, now?, autoRun* }
//           (engagementConfig() builds it from LAB_ALLOWLIST, the LAB_AUTORUN_* variables and the engagement)
function decide(proposal, config) {
  const deny = config.deny || DEFAULT_DENY;
  const reasons = [];
  const command = (proposal && proposal.command ? String(proposal.command) : '').trim();
  const declared = proposal && proposal.target ? String(proposal.target).trim() : '';

  if (!command) reasons.push('empty command');

  // 1. the declared target must be in scope
  const declaredWhy = scopeWhy(declared, config);
  if (declaredWhy) {
    reasons.push(`declared target "${declared || '(none)'}" is ${SCOPE_WHY[declaredWhy]}`);
  }

  // 2. every host/IP mentioned in the command must be in scope (catches a command that quietly
  //    reaches a second, out-of-scope host even when the declared target is fine)
  const mentioned = extractTargets(command);
  const outOfScope = mentioned.filter((h) => scopeWhy(h, config));
  if (outOfScope.length) {
    const short = { allowlist: 'not in LAB_ALLOWLIST', engagement: 'outside the engagement scope', excluded: 'excluded by the engagement' };
    reasons.push(`command references out-of-scope host(s): ${outOfScope.map((h) => `${h} (${short[scopeWhy(h, config)]})`).join(', ')}`);
  }

  // 3. hard denylist, target-independent; the engagement's prohibited tools, its protected data and its time window
  const hit = deny.find((rx) => rx.test(command));
  if (hit) reasons.push(`command matches a denied pattern: ${hit}`);
  if (/(^|\s)-iR\b/.test(command)) reasons.push('nmap -iR scans random internet hosts');
  const banned = prohibitedHits(command, config.prohibited);
  if (banned.length) reasons.push(`prohibited by the rules of engagement: ${banned.join(', ')}`);
  // 3b. protected data: a name in a data position blocks; local positions, bulk and run-time names wait for a human
  const inScope = mentioned.filter((h) => !outOfScope.includes(h));
  const data = protectedCheck(command, config.protectedData, inScope);
  if (data.hits.length) reasons.push(protectedReason(data.hits, data.decoded));
  const win = windowCheck(config.window, config.now);
  if (!win.open) reasons.push(win.reason);

  const allowed = reasons.length === 0;
  const ro = classifyReadOnly(command);
  const ar = classifyActiveRecon(command);
  const inj = detectInjection(command);
  const unverifiable = findUnverifiable(command);
  // the command must positively name a host, and every host it names must be in scope - "no host found" is not a pass
  const namesInScopeHost = mentioned.length > 0 && outOfScope.length === 0;
  // auto-run a command that passed every check, positively targets in-scope hosts only, has no target the check cannot
  // verify, gives no protected-data reason for a human, carries no text aimed at the judge, and is in an enabled auto-run
  // tier; everything else gates.
  // passive tier (LAB_AUTORUN_READONLY) and the opt-in active-recon tier (LAB_AUTORUN_ACTIVE_RECON) are independent.
  const passiveAuto = config.autoRunReadOnly === true && ro.readOnly;
  const activeAuto = config.autoRunActiveRecon === true && ar.ok;
  const autoRun = allowed && namesInScopeHost && unverifiable.length === 0 && data.review.length === 0 && !inj.suspected && (passiveAuto || activeAuto);
  const tier = !autoRun ? null : (passiveAuto ? 'passive' : 'active_recon');
  return {
    allowed,
    readOnly: ro.readOnly,
    readOnlyReason: ro.reason,
    activeRecon: ar.ok,
    activeReconReason: ar.reason,
    injectionSuspected: inj.suspected,
    injectionHits: inj.hits,
    unverifiable,
    namesInScopeHost,
    autoRun,
    tier,
    requiresApproval: allowed && !autoRun,
    reasons,
    prohibited: banned,
    command,
    target: declared,
    mentioned,
    protectedData: data.hits,          // entries named in a data position, as written (they block)
    dataReview: data.review,           // why a human must look at it while data is protected (no auto-run)
    protectedEntries: data.count,      // entries in force: the console checks that this workflow enforced them all
  };
}

// exported for the unit test; harmless inside an n8n Code node
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { decide, classifyReadOnly, classifyActiveRecon, detectInjection, findUnverifiable, targetInScope, extractTargets, inCidr, ipToInt,
    engagementConfig, scopeWhy, windowCheck, prohibitedHits, execEscape, sqlmapRisky, DEFAULT_DENY,
    protectedEntry, protectedCheck, shellSegments, nameMatch, PD_BULK_NONE, READONLY_TOOLS };
}
