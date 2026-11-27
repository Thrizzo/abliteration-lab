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

// Web-server file extensions that are no TLD: inside the path or query of a URL such a name is a file (status.cgi,
// web.config, login.action), anywhere else still a host. do and inc are TLDs: files only as a whole path segment (/login.do).
const WEB_PATH_EXT = new Set(['cgi', 'config', 'action', 'shtml', 'phtml', 'cfm', 'asmx', 'ashx', 'axd', 'svc', 'nsf', 'jsf', 'xhtml', 'do', 'inc']);
const PATH_TLD_EXT = new Set(['do', 'inc']);
// The IPv4 ranges in a text as scanners read them -> 'lo-hi' strings (two dotted quads, IP_RANGE). nmap takes a list, a
// range or * in any octet (10.10.10.5-254, 10.10.1-3.5, 10.10.10.1,7, 10.10.10.*, 10.10.10.200-: an open end is 255),
// nbtscan the last-octet form, masscan and ike-scan two whole addresses (10.10.10.1-10.10.10.254). A range runs from the
// lowest to the highest address it covers: a list or a range in a middle octet covers less than that, so the scope check
// is exact for the allowlist and stricter for an exclusion (any overlap excludes).
const IP_RANGE = /^\d{1,3}(?:\.\d{1,3}){3}-\d{1,3}(?:\.\d{1,3}){3}$/;
function octetRange(spec) {
  let lo = 256, hi = -1;
  for (const item of spec.split(',')) {
    if (item === '*') { lo = 0; hi = 255; continue; }
    const m = /^(\d{0,3})(-(\d{0,3}))?$/.exec(item);
    if (!m || (!m[1] && !m[2])) return null;
    const a = m[1] ? Number(m[1]) : 0, b = m[2] ? (m[3] ? Number(m[3]) : 255) : a;
    if (a > 255 || b > 255 || a > b) return null;
    lo = Math.min(lo, a); hi = Math.max(hi, b);
  }
  return [lo, hi];
}
function ipRanges(text) {
  const out = [];
  const quad = (o) => o.join('.');
  for (const m of text.matchAll(/(?<![\w.,*-])([\d,*-]+)\.([\d,*-]+)\.([\d,*-]+)\.([\d,*-]+)(?![\w.,*-])/g)) {
    if (!/[-,*]/.test(m[0])) continue;                            // a plain address: extracted as one
    const r = m.slice(1, 5).map(octetRange);
    if (r.every(Boolean)) out.push(`${quad(r.map((x) => x[0]))}-${quad(r.map((x) => x[1]))}`);
  }
  for (const m of text.matchAll(/(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])/g)) {
    const a = ipToInt(m[1]), b = ipToInt(m[2]);
    if (a !== null && b !== null) out.push(a <= b ? `${m[1]}-${m[2]}` : `${m[2]}-${m[1]}`);
  }
  return out;
}
// A name in a host position (a URL, //host, \\host, user@host) that looks like a range is a host name to the tool: a
// trailing dot keeps it out of rangeScopeWhy, so only an exact allowlist entry admits it (curl resolves it through DNS)
const asName = (h) => (IP_RANGE.test(h) ? `${h}.` : h);
// a network (nmap 10.10.10.0/24, httpx -u 10.10.10.0/8) and a host name with a mask (nmap web01.lab/24) outside a URL
const NET_RX = /(?<![\w.\/@:])(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})(?![\w.\/])/g;
const MASK_RX = /(?<![\w.\/@:])[a-z][\w-]*(?:\.[\w-]+)+\/\d{1,2}(?![\w.\/])/gi;
function extractTargets(command) {
  const found = new Set(), urlHosts = new Set(), paths = [];
  const text = String(command || '');
  for (const m of text.matchAll(/(?<![\w.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![\w.]*\d)/g)) found.add(m[0]);
  // a network outside a URL: the scope check needs all of it in scope
  for (const m of text.matchAll(NET_RX)) found.add(`${m[1]}/${m[2]}`);
  for (const r of ipRanges(text)) found.add(r);                   // a range: all of it must be in scope too
  // a URL's host whatever it looks like (http://127.1/ is 127.0.0.1 to curl, no version number), every URL's, also one that
  // stands in another URL's path or after it in the same word (nmap --proxies http://10.10.10.6:8080,socks4://gw:1080 relays
  // through both), and where each URL's path runs
  for (const m of text.matchAll(/\b[a-z][a-z0-9+.-]*:\/\/(?:[^@\/\s]*@)?(\[[^\]]+\]|[^:\/\s?#"']+)/gi)) urlHosts.add(asName(m[1].toLowerCase()));
  for (const m of text.matchAll(/\b[a-z][a-z0-9+.-]*:\/\/(?:[^@\/\s]*@)?(\[[^\]]+\]|[^:\/\s?#"']+)([^\s"']*)/gi)) {
    paths.push([m.index + m[0].length - m[2].length, m.index + m[0].length]);
  }
  for (const m of text.matchAll(/(?:^|[\s"'=])\/\/([^\/\s"']+)/g)) found.add(asName(m[1].toLowerCase()));  // //host/share
  for (const m of text.matchAll(/\b[\w.$-]+@([a-z0-9][\w.-]*[a-z0-9])\b/gi)) found.add(asName(m[1].toLowerCase())); // user@host
  const inPath = (i) => paths.some(([a, b]) => i > a && i < b);
  for (const m of text.matchAll(/\b((?:[a-z0-9-]+\.)+([a-z]{2,24}))\b/gi)) {
    const ext = m[2].toLowerCase();
    if (FILE_EXT.has(ext)) continue;
    if (WEB_PATH_EXT.has(ext) && inPath(m.index) && (!PATH_TLD_EXT.has(ext) || text[m.index - 1] === '/')) continue;
    found.add(m[1].toLowerCase());
  }
  if (/\blocalhost\b/i.test(text)) found.add('127.0.0.1');
  const kept = [...found].filter((h) => !/^\d+\.\d+(\.\d+)?$/.test(h)).concat([...urlHosts]);   // drop version-like 1.2 / 1.2.3 fragments
  return [...new Set(kept.map((h) => (h === 'localhost' ? '127.0.0.1' : h)))];
}
// A UNC path with backslashes names its server (smbclient's service \\host\share, rpcclient's printer names \\EVIL\p), read
// only from the words bash hands a program: in the raw text a doubled backslash inside double quotes is one backslash
// (tr -d "\\r", grep -oP "\\d+"). smbclient's commands (-c, --command) and start directory (-D, --directory) take paths on
// the share (cd \\Public, get \\Windows\win.ini; client.c do_cd), never a server.
const uncHosts = (word) => [...String(word).matchAll(/(?:^|[\s"'=])\\{2,}([A-Za-z0-9][^\\\/\s"']*)/g)].map((m) => asName(m[1].toLowerCase()));
function uncWords(program, args) {
  if (toolOf(program) !== 'smbclient') return args;
  const w = walkOpts(args, OPT_SPECS.smbclient);
  return w.operands.concat(w.opts.filter(([n, v]) => v !== null && !['-c', '--command', '-D', '--directory'].includes(n)).map(([, v]) => v));
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
  [new RegExp(MASK_RX.source, 'i'), 'host name with a network mask (nmap scans the whole network around it)'],
];
const MASK_WHY = UNVERIFIABLE[UNVERIFIABLE.length - 1][1];
// segments (pdProgram results) and a global pattern -> a test: does a token it matches stand only in the schemeless URLs
// curl and wget read (curl -s 10.10.10.5/10 and wget web01.lab/2 fetch the path /10 and /2 from the host: a local HTTP
// server logged GET /10 and GET /2), never in another word. Whole words only: an attached --url=... counts as another word.
function urlPathOnly(segs, rx) {
  const inUrl = new Set(), inOther = new Set();
  const tokens = (w) => [...String(w).matchAll(rx)].map((m) => m[0].toLowerCase());
  for (const s of segs) {
    const rest = [...s.args];
    const urls = ['curl', 'wget'].includes(toolOf(s.program)) ? (toolTargets(s.program, s.args) || []).filter(([, k]) => k === 'url').map(([v]) => v) : [];
    for (const u of urls) {
      const i = rest.indexOf(u);
      if (i >= 0) { rest.splice(i, 1); for (const t of tokens(u)) inUrl.add(t); }
    }
    for (const w of rest) for (const t of tokens(w)) inOther.add(t);
  }
  return (h) => inUrl.has(String(h).toLowerCase()) && !inOther.has(String(h).toLowerCase());
}

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
  'curl', 'wget', 'httpx', 'httpx-toolkit', 'whatweb', 'wafw00f', 'sslscan', 'sslyze', 'testssl.sh', 'testssl',
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
  // curl's options are case-sensitive (-f fails, -D dumps headers) and start a word (index-f.html is a path); wget's -d,
  // -F and -T are debug, --force-html and --timeout, and execEscape reads both programs' words
  /\b[Cc][Uu][Rr][Ll]\b[^|;&]*\s(-d\b|--data|-F\b|--form|-T\b|--upload-file|-X\s*(POST|PUT|DELETE|PATCH)|--request\s*(POST|PUT|DELETE|PATCH))/,
  /\bnc\b(?![^|;&]*-z)[^|;&]*-[a-z]*l/i, // netcat listener (-l) that isn't a -z port check
];
// smbclient and rpcclient -c commands that write, on the raw text: /\bPROGRAM\b[^|;&]*-c\b[^|;&]*COMMAND/i in linear time.
// In each stretch without | ; &, take the first program name, the first -c after it, then look for the command anywhere
// after that: the earliest of each leaves the most room for the next, so this matches exactly when the regex does. The
// regex itself backtracks over every pair of positions (up to 67 ms on 2000 characters, decide() then passed 100 ms).
const RAW_SUBCOMMANDS = [
  ['smbclient', String.raw`\b(put|mkdir|rmdir|del|rename|rm)\b`],
  // rpcclient subcommands that change the domain: setuserinfo2 (a password), createdomuser, deletedomuser, chgpasswd, ...
  ['rpcclient', String.raw`(^|[\s'"])(create|delete|del|set|add|chg)\w*`],
];
function rawSubcommandWrites(cmd) {
  const after = (source, s, from) => { const rx = new RegExp(source, 'gi'); rx.lastIndex = from; return rx.test(s) ? rx.lastIndex : -1; };
  return cmd.split(/[|;&]/).some((part) => RAW_SUBCOMMANDS.some(([program, command]) => {
    const p = after(String.raw`\b${program}\b`, part, 0), c = p < 0 ? -1 : after(String.raw`-c\b`, part, p);
    return c >= 0 && after(command, part, c) >= 0;
  }));
}
// The NSE scripts each tier runs, counted in nmap's script.db (619 scripts): default holds 128, none intrusive or broadcast;
// two of them reach a third party through the target (http-open-proxy and socks-open-proxy fetch a public page through it
// when it is an open proxy), accepted because nmap -sC and -A run default too. safe holds 355, of which 27 are external
// (whois, ASN, DNS blacklist and other third-party services) and 44 broadcast (DHCP, multicast DNS and other broadcasts to
// hosts the command does not name); discovery holds 320 (22 external, 19 broadcast, 51 intrusive). So the passive tier
// runs default only, the active tier default, version (48 scripts, the ones -sV runs) and banner (one script), and safe,
// discovery and everything else waits for a human.
const PASSIVE_NSE = new Set(['default']);

// sed and awk are local filters, but GNU sed runs a program with e (the command, and the s command's flag) and awk with
// system(), pipes and getline, and both read programs from files. The gate reads their scripts from the words bash hands
// them, the way the programs read them; whatever it cannot read waits for a human.
//
// A sed script read the way GNU sed compiles it (sed/compile.c, alike from 4.2.2 to 4.9): commands split by ; and
// newlines, then addresses (N, $, /re/I, \cREc, first~step, a,+N, a,~N), an optional !, the command letter and its
// arguments. In a regex a bracket expression can hold the delimiter (s/[/]/x/); a, i and c take text to the end of the
// line, r, R, w and W a file name, b, t, T, : and v a label. -> 'e' when it runs a program, '?' when the gate cannot read
// it, '' otherwise. Compared with GNU sed 4.9 on generated scripts without r and w (sed --sandbox then refuses exactly
// those with an e): none was read differently. With `files`, the names its w and W commands and its s commands' w flag
// write go there: the rest of the line after the blanks (sed -n 'w .curlrc', s/^/x/w .curlrc, 1,$w .curlrc)
function sedScan(s, files) {
  const n = s.length;
  let i = 0, depth = 0;
  const digits = () => { while (s[i] >= '0' && s[i] <= '9') i++; };
  const blank = () => { while (s[i] === ' ' || s[i] === '\t') i++; };
  const toEol = () => { while (i < n && s[i] !== '\n') i++; };
  const label = () => { blank(); while (i < n && !' \t\n;}#'.includes(s[i])) i++; };
  const endOfCmd = () => {                                        // ; newline or the end, or } and # left for the next command
    blank();
    if (s[i] === '}' || s[i] === '#') return true;
    if (i >= n || s[i] === ';' || s[i] === '\n') { i++; return true; }
    return false;
  };
  const delim = (d) => d !== undefined && d !== '\n' && d.charCodeAt(0) < 0x80;    // sed refuses a newline; a multibyte one depends on the locale
  const bracket = () => {                                         // after [: true when its ] closes it (snarf_char_class)
    if (s[i] === '^') i++;
    if (s[i] === ']') i++;
    for (let state = 0, cls = ''; i < n; i++) {
      const c = s[i];
      if (c === '\n' || c.charCodeAt(0) >= 0x80) return false;
      if ((c === '.' || c === ':' || c === '=') && (state === 1 || (state === 2 && c === cls))) { if (state === 1) cls = c; state++; continue; }
      if (c === '[') { if (state === 0) state = 1; continue; }
      if (c === ']') { if (state < 2) { i++; return true; } if (state === 3) state = 0; }
      state &= ~1;
    }
    return false;
  };
  const part = (d, regex) => {                                    // up to the delimiter d (match_slash): true when found
    while (i < n && s[i] !== '\n') {
      const c = s[i++];
      if (c === d) return true;
      if (c === '\\') { if (i >= n) return false; i++; } else if (c === '[' && regex && !bracket()) return false;
    }
    return false;
  };
  const address = () => {                                         // true, false (none here) or 'step' (+N, ~N); null: refused
    const c = s[i];
    if (c === '/' || c === '\\') {
      i++;
      const d = c === '/' ? c : s[i++];
      if (!delim(d) || !part(d, true)) return null;
      for (;;) { blank(); if (s[i] === 'I' || s[i] === 'M') i++; else return true; }
    }
    if (c >= '0' && c <= '9') { digits(); blank(); if (s[i] === '~') { i++; blank(); digits(); } return true; }
    if (c === '+' || c === '~') { i++; blank(); const at = i; digits(); return /[1-9]/.test(s.slice(at, i)) ? 'step' : true; }   // +0 is no step
    if (c === '$') { i++; return true; }
    return false;
  };
  for (;;) {
    while (i < n && (s[i] === ';' || ' \t\n\v\f\r'.includes(s[i]))) i++;
    if (i >= n) return depth ? '?' : '';
    const a1 = address();
    if (a1 === null || a1 === 'step') return '?';
    if (a1) {
      blank();
      if (s[i] === ',') { i++; blank(); if (!address()) return '?'; blank(); }
    }
    if (s[i] === '!') { i++; blank(); if (s[i] === '!') return '?'; }
    const c = s[i++];
    switch (c) {
      case 'e': return 'e';
      case '#': if (a1) return '?'; toEol(); continue;
      case 'v': label(); continue;
      case '{': depth++; continue;
      case '}': if (!depth || a1 || !endOfCmd()) return '?'; depth--; continue;
      case 'a': case 'i': case 'c':                               // a\ and the text on the next line, a\text or a text
        blank();
        if (i >= n) return '?';
        if (s[i] === '\\') i += 2;
        while (i < n && s[i] !== '\n') i += s[i] === '\\' ? 2 : 1;
        continue;
      case ':': { if (a1) return '?'; blank(); const at = i; label(); if (i === at) return '?'; continue; }
      case 'b': case 't': case 'T': label(); continue;
      case 'q': case 'Q': case 'l': case 'L': blank(); digits(); if (!endOfCmd()) return '?'; continue;
      case '=': case 'd': case 'D': case 'F': case 'g': case 'G': case 'h': case 'H': case 'n': case 'N': case 'p': case 'P': case 'z': case 'x':
        if (!endOfCmd()) return '?';
        continue;
      case 'r': case 'R': case 'w': case 'W': {
        blank();
        if (i >= n || s[i] === '\n') return '?';
        const at = i;
        toEol();
        if (files && (c === 'w' || c === 'W')) files.push(s.slice(at, i));
        continue;
      }
      case 'y': { const d = s[i++]; if (!delim(d) || !part(d, false) || !part(d, false) || !endOfCmd()) return '?'; continue; }
      case 's': {
        const d = s[i++];
        if (!delim(d) || !part(d, true) || !part(d, false)) return '?';
        for (;;) {                                                // its flags, blanks between them allowed
          blank();
          const f = s[i++];
          if (f === 'e') return 'e';
          if (f === 'g' || f === 'p' || f === 'i' || f === 'I' || f === 'm' || f === 'M') continue;
          if (f >= '0' && f <= '9') { digits(); continue; }
          if (f === 'w') { blank(); if (i >= n || s[i] === '\n') return '?'; const at = i; toEol(); if (files) files.push(s.slice(at, i)); break; }
          if (f === '}' || f === '#') { i--; break; }
          if (f === undefined || f === ';' || f === '\n') break;
          if (f === '\r' && s[i] === '\n') { i++; break; }
          return '?';
        }
        continue;
      }
      default: return '?';
    }
  }
}
// a long option as getopt_long reads it: its name in table, or '' when unknown or ambiguous
const longName = (given, table) => {
  if (Object.prototype.hasOwnProperty.call(table, given)) return given;
  const hits = Object.keys(table).filter((o) => o.startsWith(given));
  return given && hits.length === 1 ? hits[0] : '';
};
// GNU sed's long options: 1 takes a value (=v or the next word), 2 only an attached =v, 0 none
const SED_LONG = { expression: 1, file: 1, 'line-length': 1, 'in-place': 2, binary: 0, 'regexp-extended': 0, debug: 0, 'null-data': 0,
  'zero-terminated': 0, quiet: 0, posix: 0, silent: 0, sandbox: 0, separate: 0, unbuffered: 0, version: 0, help: 0, 'follow-symlinks': 0 };
// sed's words as GNU getopt hands them over: -n -E -r -s -u -z -b combine, -i takes only an attached suffix (-ie is -i with
// suffix e), -e -f -l take the rest of the word or the next word, long options take unique prefixes, options may follow
// operands. The -e scripts are one script joined by newlines (a\ in one -e continues into the next); without -e or -f the
// first operand is the script, and an operand before the first -e is read too (with POSIXLY_CORRECT set, sed stops
// reading options there). --sandbox makes sed refuse e in every script it compiles afterwards, so it counts only before
// the first script and operand. -> { read (the scripts), file (-f), sandbox, bad, inPlace (-i's suffix, null without -i),
// operands, script (the first operand is the script) }
function sedArgs(args) {
  const scripts = [], operands = [];
  let first = null, early = null, file = false, sandbox = false, bad = false, opts = true, inPlace = null;
  for (let k = 0; k < args.length; k++) {
    const t = args[k];
    if (!opts || t === '-' || !t.startsWith('-')) { operands.push(t); if (first === null) { first = t; if (!scripts.length && !file) early = t; } continue; }
    if (t === '--') { opts = false; continue; }
    if (t.startsWith('--')) {
      const eq = t.indexOf('='), name = longName(eq < 0 ? t.slice(2) : t.slice(2, eq), SED_LONG), kind = name ? SED_LONG[name] : -1;
      let v = eq < 0 ? null : t.slice(eq + 1);
      if (kind === 1 && v === null && k + 1 < args.length) v = args[++k];
      if (kind < 0 || (kind === 1 && v === null) || (kind === 0 && v !== null)) bad = true;
      else if (name === 'expression') scripts.push(v);
      else if (name === 'file') file = true;
      else if (name === 'in-place') inPlace = v ?? '';
      else if (name === 'sandbox' && !scripts.length && !file && first === null) sandbox = true;
      continue;
    }
    for (let p = 1; p < t.length; p++) {
      const c = t[p];
      if ('bsnrzuE'.includes(c)) continue;
      if (c === 'i') { inPlace = t.slice(p + 1); break; }        // the rest of the word is its suffix
      if ('eflV'.includes(c)) {
        const v = p + 1 < t.length ? t.slice(p + 1) : k + 1 < args.length ? args[++k] : null;
        if (v === null || c === 'V') bad = true; else if (c === 'e') scripts.push(v); else if (c === 'f') file = true;
        break;
      }
      bad = true;
      break;
    }
  }
  const read = scripts.length ? [scripts.join('\n')].concat(early === null ? [] : [early]) : first === null ? [] : [first];
  return { read, file, sandbox, bad, inPlace, operands, script: !scripts.length && !file };
}
// sed's words -> 'e', 'f' (a script from a file), '?' (an option or a script the gate cannot read) or ''
function sedEscape(args) {
  const g = sedArgs(args);
  if (g.bad) return '?';
  if (g.sandbox) return '';
  if (g.file) return 'f';
  for (const s of g.read) { const r = sedScan(s); if (r) return r; }
  return '';
}
// the files sed writes: what the w and W commands and the s command's w flag of every script it reads name, and with -i
// every input file and its backup: the suffix appended, or every * in it replaced by the file's name (sed -i'.*' s/a/b/
// curlrc backs curlrc up as .curlrc, a local run), next to the file or under the working directory. A regex (/Windows/p)
// writes nothing. A script from a file (-f) or one the gate cannot read never gets here: execEscape waits for it first
function sedWrites(args) {
  const g = sedArgs(args), paths = [];
  for (const s of g.read) sedScan(s, paths);
  if (g.inPlace !== null) {
    for (const f of g.script ? g.operands.slice(1) : g.operands) {
      const cut = f.lastIndexOf('/') + 1, backup = g.inPlace.includes('*') ? g.inPlace.split('*').join(f.slice(cut)) : f.slice(cut) + g.inPlace;
      paths.push(f, ...(g.inPlace ? [backup, f.slice(0, cut) + backup] : []));
    }
  }
  return paths;
}
const SED_WHY = { e: 'sed e runs a program', f: 'sed that runs a script from a file (-f)', '?': 'sed script or option the gate cannot read' };

// gawk's long options and mawk's -W options -> 'value' (=v or the next word), 'program' (program text, likewise), 'run'
// (a program file, an include, a library, the debugger's command file) or 0 (a flag, or an attached =value)
const AWK_LONG = { assign: 'value', 'field-separator': 'value', source: 'program', file: 'run', exec: 'run', include: 'run', load: 'run',
  debug: 'run', 'characters-as-bytes': 0, traditional: 0, copyright: 0, 'dump-variables': 0, 'gen-pot': 0, help: 0, csv: 0, lint: 0,
  'non-decimal-data': 0, 'use-lc-numeric': 0, optimize: 0, 'no-optimize': 0, 'pretty-print': 0, profile: 0, bignum: 0, posix: 0,
  're-interval': 0, sandbox: 0, 'lint-old': 0, version: 0, trace: 0, compat: 0, dump: 0, interactive: 0, random: 0, sprintf: 0, usage: 0,
  posix_space: 0 };
// one awk program text -> 'run' (a system( call, getline, a lone | or |&: || is a logical or), 'at' (@include, @load, an
// indirect @name() call) or ''. A backslash-newline continues a line, so the text is read as written and joined. system
// only runs as a call: gawk 5.2 and mawk 1.3.4 refuse the bare word, and a newline or comment before the (, so the word
// in a regex or a string (/system/, $1=="system") is a plain filter. Like the raw pattern in execEscape, no word
// boundary: 1system("id") calls system.
function awkProgram(text) {
  for (const t of [text, text.replace(/\\\r?\n/g, '')]) {
    if (/system\s*\(|getline/.test(t)) return 'run';
    for (let i = 0; i < t.length; i++) if (t[i] === '|') { if (t[i + 1] !== '|') return 'run'; i++; }
    if (/@\s*[A-Za-z_]/.test(t)) return 'at';
  }
  return '';
}
// awk's words -> 'run', 'at', 'file' (-f, -E, -i, -l, -D, mawk -W exec), '?' (an option the gate cannot read) or ''. gawk
// options: -F -v -e -f -E -i -l -W take the rest of the word or the next word, -d -D -L -o -p only an attached value,
// -W name is --name; gawk and mawk stop reading options at the first operand, the program text unless -e, --source or -f
// gave one. A later word that looks like an option waits too, for an awk that reads options there.
function awkEscape(args) {
  const programs = [];
  let k = 0, file = false, bad = false, given = false;
  const next = () => (k + 1 < args.length ? args[++k] : null);
  const long = (spec) => {                                        // --name[=v], or the value of -W
    const eq = spec.indexOf('='), name = longName(eq < 0 ? spec : spec.slice(0, eq), AWK_LONG), kind = name ? AWK_LONG[name] : -1;
    const v = eq >= 0 ? spec.slice(eq + 1) : kind === 'value' || kind === 'program' ? next() : null;
    if (kind === -1 || ((kind === 'value' || kind === 'program') && v === null)) bad = true;
    else if (kind === 'run') file = true;
    else if (kind === 'program') { programs.push(v); given = true; }
  };
  for (; k < args.length; k++) {
    const t = args[k];
    if (t === '--') { k++; break; }
    if (t === '-' || !t.startsWith('-')) break;
    if (t.startsWith('--')) { long(t.slice(2)); continue; }
    for (let p = 1; p < t.length; p++) {
      const c = t[p];
      if ('bcCghknNOMPrSstVY'.includes(c)) continue;
      if ('dLop'.includes(c)) break;                              // an optional value, attached
      if (c === 'D') { file = true; break; }
      if ('FvefEilW'.includes(c)) {
        const v = p + 1 < t.length ? t.slice(p + 1) : next();
        if (v === null) bad = true;
        else if (c === 'e') { programs.push(v); given = true; } else if (c === 'W') long(v); else if (c !== 'F' && c !== 'v') file = true;
        break;
      }
      bad = true;
      break;
    }
  }
  const ops = args.slice(k);
  if (!given && !file) programs.push(...ops.splice(0, 1));
  if (file) return 'file';
  if (bad || ops.some((t) => t.length > 1 && t.startsWith('-'))) return '?';
  for (const p of programs) { const r = awkProgram(p); if (r) return r; }
  return '';
}
const AWK_WHY = { run: 'awk that runs a program (system, pipes, getline)', at: 'awk that loads or calls code the gate cannot see (@include, @load, @name())',
  file: 'awk that runs a program from a file or a library (-f, -E, -i, -l, -D)', '?': 'awk option the gate cannot read' };
const READ_METHOD = /^(GET|HEAD|OPTIONS|TRACE|PROPFIND)$/i;       // the request methods that only read (RFC 9110, RFC 4918)
const curlLong = (args) => args.map((t) => t.replace(/^--expand-/, '--'));   // curl --expand-X is option X with {{variables}} expanded

// A tool on the read-only list, or a local filter, that can still run a program, listen, change a share or send data, or
// that runs commands or settings the gate cannot see. Each of these auto-ran in the passive tier before (found by the
// protected-data red team and the verification of the review fixes, checked against this gate). seg is a segment of
// shellSegments(), whose words are what bash hands the program, so quoting hides nothing (nc '-e', awk 'sys''tem(',
// sed 's/x/id/'\e, smbclient -c \!id, curl -X 'DELETE'); a raw string is split on whitespace and only the raw patterns
// read it. An option counts in the spellings the tool accepts: netcat's attached values and clusters (-e/bin/sh,
// -ve/bin/sh, -lp4444) and long-option prefixes (--exe, --lis), smbmap's prefixes (--upl, --dele), curl's clusters (-sd,
// -sXPUT), sed's and awk's option rules (sedEscape, awkEscape); smbclient's and rpcclient's commands are read in
// reconEscape against the lists of commands that only read.
// A variable set for the program alone points it at settings, scripts, libraries or a binary the gate cannot see
// (CURL_HOME, WGETRC, XDG_CONFIG_HOME and HOME load a .curlrc or .wgetrc, NMAPDIR scripts, LESSOPEN a preprocessor,
// LD_PRELOAD a library, PATH another curl). Only the locale and the time zone with a plain value (no slash) auto-run.
const PLAIN_ENV = /^(LANG|LANGUAGE|LC_[A-Z]+|TZ)=[\w.@:+-]*$/;
function execEscape(bin, seg) {
  const words = typeof seg === 'string' ? null : seg.words;
  const args = words ? pdProgram(words).args : String(seg).split(/\s+/).slice(1);
  const text = words ? args.join(' ') : String(seg);
  const env = !words ? null : words.slice(0, pdProgramIndex(words)).find((w) => !w.redir && /^[A-Z_][A-Z0-9_]*=/.test(w.text) && !PLAIN_ENV.test(w.text));
  if (env) return `environment variable ${env.text.slice(0, env.text.indexOf('=')).slice(0, 40)} (settings, scripts or programs the gate cannot see)`;
  // GNU sort runs the program --compress-program names on every temporary file it writes (with -S1 from 300 bytes of input)
  if (bin === 'sort' && pdLong(args, ['compress-program'])) return 'sort --compress-program runs a program';
  // ncat --lua-exec-internal FILE runs a Lua file too, --broker listens (it implies --listen), --chat and --talk are brokers
  if (['nc', 'ncat', 'netcat'].includes(bin) && (args.some((t) => /^-[A-Za-z]*[ecl]/.test(t) || /^--(sh-|lua-)?exec(=|$)|^--listen\b|^--lua/i.test(t))
    || pdLong(args, ['exec', 'sh-exec', 'lua-exec', 'listen', 'broker', 'chat', 'talk'])))
    return 'netcat that runs a program or listens (-e, -c, --exec, --sh-exec, --lua-exec, -l, --broker, --chat)';
  if (bin === 'ffuf' && /(^|\s)--?input-cmd\b/.test(text)) return 'ffuf -input-cmd runs a program';
  if (bin === 'awk' && /system\s*\(|\|\s*"|\|&|getline/.test(text)) return AWK_WHY.run;
  if (bin === 'sed' && /(^|[;\n{}\s0-9$\/'"])e(\s|;|'|"|$)|\/[gpiImM0-9]*e[gpiImMwW0-9]*(\s|;|}|'|"|$)/.test(text)) return SED_WHY.e;
  if (words && bin === 'awk') { const r = awkEscape(args); if (r) return AWK_WHY[r]; }
  if (words && bin === 'sed') { const r = sedEscape(args); if (r) return SED_WHY[r]; }
  // smbclient commands that write, on the raw text too; reconEscape reads every command from the words
  if (bin === 'smbclient' && /['";]\s*(!|(mput|put|mkdir|md|rmdir|rd|del|deltree|rm|rename|mv|setmode)\b)/i.test(text))
    return 'smbclient command that runs a local shell (!) or changes the share';
  // both read commands from stdin: a < file, a pipe or a process substitution hands them commands the gate never sees
  // (reconEscape reads smbclient's here-strings and heredocs; rpcclient's are not read at all)
  if (words && (bin === 'smbclient' || bin === 'rpcclient') && (seg.pipedIn || seg.procSub || words.some((w) => (w.redir === 'in'
    && pdFold(w.text) !== '/dev/null') || (bin === 'rpcclient' && /^(herestr|heredoc|heredocBody)$/.test(w.redir)))))
    return `${bin} reads its commands from a file or a pipe (commands the gate cannot see)`;
  if (bin === 'smbmap' && (/(^|\s)-[A-Za-z]*x|(^|\s)--(upload|delete|mkdir)\b/.test(text) || args.some((t) => /^-[A-Za-z]*x/.test(t))
    || pdLong(args, ['upload', 'delete', 'mkdir']))) return 'smbmap that runs a command (-x) or changes the share';
  // a request that sends data or uses a method that writes, in every spelling (-sd, -sXPUT, -X 'DELETE', --request=PATCH,
  // --dat, --expand-data): curl's value letters end a cluster (-sSLo file holds no d); -G still sends -d (as a query): it
  // waits too
  if (words && bin === 'curl' && (pdCluster(args, 'curl', 'dFT') || pdLong(curlLong(args), ['data', 'data-ascii', 'data-binary', 'data-raw',
    'data-urlencode', 'form', 'form-string', 'upload-file', 'json'])
    || pdClusterValues(args, 'curl', 'X').concat(pdLongValues(curlLong(args), 'request')).some((m) => m === null || !READ_METHOD.test(m))))
    return 'curl that sends data or a non-read method (-d, -F, -T, --json, -X POST)';
  if (words && (bin === 'wget' || bin === 'wget2') && (pdLong(args, ['post-data', 'post-file', 'body-data', 'body-file'])
    || pdLongValues(args, 'method').some((m) => m === null || !READ_METHOD.test(m))))
    return 'wget that sends data or a non-read method (--post-data, --post-file, --body-data, --body-file, --method)';
  const settings = words ? settingsFile(bin, args) : '';
  if (settings) return `${settings} (settings the gate cannot see)`;
  // nmap loads NSE scripts from --datadir and reads its whole option list back from a --resume log, the service probes -sV
  // sends from --versiondb and its port table from --servicedb (getopt_long_only: one dash and unique prefixes count; rustscan
  // hands nmap the words after --); rustscan's custom scripts and config file run whatever they name
  const nmapArgs = bin === 'nmap' ? args : bin === 'rustscan' && args.includes('--') ? args.slice(args.indexOf('--') + 1) : null;
  if (nmapArgs && (pdAbbrev(nmapArgs, 'datadir', 5) || pdAbbrev(nmapArgs, 'resume', 3))) return 'nmap --datadir or --resume (scripts or options the gate cannot see)';
  if (nmapArgs && nmapWalk(nmapArgs).opts.some(([n]) => n === '--versiondb' || n === '--servicedb')) return 'nmap --versiondb or --servicedb (service probes or port tables from a file the gate cannot see)';
  if (bin === 'rustscan') {
    const own = args.includes('--') ? args.slice(0, args.indexOf('--')) : args;          // after -- the words go to nmap
    if (pdLetter(own, 'c') || pdLong(own, ['config-path']) || pdLongValues(own, 'scripts').some((v) => v !== 'none' && v !== 'default'))
      return 'rustscan --config-path or custom --scripts (programs the gate cannot see)';
  }
  // curl, wget, netcat and the HTTP scanners: every form that runs or loads code, listens, writes to the target, reaches a
  // host the command does not name, or takes requests, headers or targets from a file or stdin (toolEscape); the SMB, RPC,
  // LDAP, SNMP and NFS clients, the scanners, arp and ss likewise (reconEscape)
  if (words) { const t = toolEscape(bin, args, seg) || reconEscape(bin, args, seg); if (t) return t; }
  return '';
}

// ---- curl, wget, netcat and the HTTP scanners: their words read the way each tool's own parser reads them --------------
// Each table holds the options that take a value and every long name (for unique prefixes), from the tools' sources:
// curl 8.5.0 and master tool_getparam.c (names match case-insensitively), wget 1.21.4 main.c, Debian's nc.openbsd and
// traditional netcat (getopt), ncat 7.94 ncat_main.c, WhatWeb's GetoptLong table, wafw00f's optparse, sslyze's argparse,
// testssl's parse_cmd_line (exact words), wfuzz's getopt (clparser.py), dirb 2.22's usage, feroxbuster's clap table.
const wordSet = (s) => new Set(s.split(' '));
const CURL_VALUE = 'abstract-unix-socket alt-svc aws-sigv4 cacert capath cert cert-type ciphers config connect-timeout connect-to continue-at '
  + 'cookie cookie-jar create-file-mode crlfile curves data data-ascii data-binary data-raw data-urlencode delegation dns-interface dns-ipv4-addr '
  + 'dns-ipv6-addr dns-servers doh-url dump-header ech egd-file engine etag-compare etag-save expect100-timeout form form-string ftp-account '
  + 'ftp-alternative-to-user ftp-method ftp-port ftp-ssl-ccc-mode happy-eyeballs-timeout-ms haproxy-clientip header help hostpubmd5 hostpubsha256 '
  + 'hsts httpsig-algo httpsig-headers httpsig-key httpsig-keyid interface ip-tos ipfs-gateway json keepalive-cnt keepalive-time key key-type '
  + 'knownhosts krb krb4 libcurl limit-rate local-port login-options mail-auth mail-from mail-rcpt max-filesize max-redirs max-time netrc-file '
  + 'noproxy oauth2-bearer output output-dir parallel-max parallel-max-host pass pinnedpubkey preproxy proto proto-default proto-redir proxy '
  + 'proxy-cacert proxy-capath proxy-cert proxy-cert-type proxy-ciphers proxy-crlfile proxy-header proxy-key proxy-key-type proxy-pass '
  + 'proxy-pinnedpubkey proxy-service-name proxy-tls13-ciphers proxy-tlsauthtype proxy-tlspassword proxy-tlsuser proxy-user proxy1.0 pubkey '
  + 'quote random-file range rate referer request request-target resolve retry retry-delay retry-max-time sasl-authzid service-name sigalgs '
  + 'socks4 socks4a socks5 socks5-gssapi-service socks5-hostname speed-limit speed-time ssl-sessions stderr telnet-option tftp-blksize '
  + 'time-cond tls-max tls13-ciphers tlsauthtype tlspassword tlsuser trace trace-ascii trace-config unix-socket upload-file upload-flags url '
  + 'url-query user user-agent variable vlan-priority write-out';
const CURL_FLAG = 'alpn anyauth append basic buffer ca-native cert-status clobber compressed compressed-ssh create-dirs crlf digest disable '
  + 'disable-eprt disable-epsv disallow-username-in-url doh-cert-status doh-insecure dump-ca-embed eprt epsv fail fail-early fail-with-body '
  + 'false-start follow form-escape ftp-create-dirs ftp-pasv ftp-pret ftp-skip-pasv-ip ftp-ssl ftp-ssl-ccc ftp-ssl-control ftp-ssl-reqd get '
  + 'globoff haproxy-protocol head http0.9 http1.0 http1.1 http2 http2-prior-knowledge http3 http3-only ignore-content-length include insecure '
  + 'ipv4 ipv6 junk-session-cookies keepalive list-only location location-trusted mail-rcpt-allowfails manual metalink mptcp negotiate netrc '
  + 'netrc-optional next npn ntlm ntlm-wb out-null parallel parallel-immediate path-as-is post301 post302 post303 progress-bar progress-meter '
  + 'proxy-anyauth proxy-basic proxy-ca-native proxy-digest proxy-http2 proxy-http3 proxy-insecure proxy-negotiate proxy-ntlm '
  + 'proxy-ssl-allow-beast proxy-ssl-auto-client-cert proxy-tlsv1 proxytunnel raw remote-header-name remote-name remote-name-all remote-time '
  + 'remove-on-error retry-all-errors retry-connrefused sasl-ir sessionid show-error show-headers silent skip-existing socks5-basic '
  + 'socks5-gssapi socks5-gssapi-nec ssl ssl-allow-beast ssl-auto-client-cert ssl-no-revoke ssl-reqd ssl-revoke-best-effort sslv2 sslv3 '
  + 'styled-output suppress-connect-headers tcp-fastopen tcp-nodelay test-duphandle test-event tftp-no-options tls-earlydata tlsv1 tlsv1.0 '
  + 'tlsv1.1 tlsv1.2 tlsv1.3 tr-encoding trace-ids trace-time use-ascii verbose version wdebug xattr';
const WGET_VALUE = 'accept accept-regex append-output base bind-address bind-dns-address body-data body-file ca-certificate ca-directory '
  + 'certificate certificate-type ciphers compression config connect-timeout crl-file cut-dirs default-page directory-prefix dns-servers '
  + 'dns-timeout domains dot-style egd-file exclude-directories exclude-domains execute follow-tags ftp-password ftp-user header hsts-file '
  + 'http-passwd http-password http-user ignore-tags include-directories input-file input-metalink level limit-rate load-cookies local-encoding '
  + 'max-redirect metalink-index method no output-document output-file password pinnedpubkey post-data post-file prefer-family '
  + 'preferred-location private-key private-key-type progress proxy-passwd proxy-password proxy-user proxy__compat quota random-file '
  + 'read-timeout referer regex-type reject reject-regex rejected-log remote-encoding retry-on-http-error save-cookies secure-protocol start-pos '
  + 'timeout tries use-askpass user user-agent wait waitretry warc-dedup warc-file warc-header warc-max-size warc-tempdir';
const WGET_BOOL = 'adjust-extension ask-password auth-no-challenge background backup-converted backups cache check-certificate '
  + 'content-disposition content-on-error continue convert-file-only convert-links cookies debug delete-after directories dns-cache follow-ftp '
  + 'force-directories force-html ftp-stmlf ftps-clear-data-connection ftps-fallback-to-ftp ftps-implicit ftps-resume-ssl glob host-directories '
  + 'hsts html-extension htmlify http-keep-alive https-only if-modified-since ignore-case ignore-length inet4-only inet6-only iri keep-badhash '
  + 'keep-session-cookies metalink-over-http mirror netrc no-clobber no-config no-parent page-requisites passive-ftp preserve-permissions '
  + 'protocol-directories proxy quiet random-wait recursive relative remove-listing report-speed restrict-file-names retr-symlinks '
  + 'retry-connrefused retry-on-host-error save-headers server-response show-progress span-hosts spider strict-comments timestamping '
  + 'trust-server-names unlink use-server-timestamps verbose warc-cdx warc-compression warc-digests warc-keep-log wdebug xattr';
const NCAT_VALUE = 'g G exec sh-exec lua-exec lua-exec-internal max-conns delay output hex-dump idle-timeout source-port source deny denyfile '
  + 'allow allowfile wait proxy proxy-type proxy-auth proxy-dns nsock-engine ssl-cert ssl-key ssl-trustfile ssl-ciphers ssl-servername ssl-alpn';
const WHATWEB_VALUE = 'plugins info-plugins search-plugins dorks colour color log-object log-brief log-xml log-json log-json-verbose '
  + 'log-magictree log-verbose log-mongo-collection log-mongo-host log-mongo-database log-mongo-username log-mongo-password log-elastic-index '
  + 'log-elastic-host log-sql log-sql-create log-errors input-file user-agent aggression max-threads follow-redirect max-redirects proxy '
  + 'proxy-user url-prefix url-suffix url-pattern custom-plugin grep open-timeout read-timeout header cookie cookie-jar user wait '
  + 'output-buffer-size';
const SSLYZE_VALUE = 'custom_tls_config cert key keyform pass json_out targets_in https_tunnel starttls xmpp_to sni certinfo_ca_file '
  + 'resum_attempts mozilla_config';
const WFUZZ_VALUE = 'efield ee zE zD field ip slice zP oF recipe dump-recipe req-delay conn-delay sc sh sl sw ss hc hh hl hw hs ntlm basic '
  + 'digest script-help script script-args prefilter filter';
const FEROX_VALUE = 'url resume-from request-file data-urlencoded data-json proxy replay-proxy replay-codes user-agent extensions methods data '
  + 'headers cookies query protocol dont-scan scope filter-size filter-regex filter-words filter-lines filter-status filter-similar-to '
  + 'status-codes timeout server-certs client-cert client-key threads depth scan-limit parallel rate-limit response-size-limit time-limit '
  + 'wordlist dont-collect output debug-log limit-bars';
// spec: short (letters that take a value), long (names that take one), all (every long name, for unique prefixes; empty:
// exact names only), prefix, fold (case-insensitive names), exact (testssl: a word is one option, matched exactly), multi
// (clap options that take every following word up to the next option)
const optSpec = (short, value, flags, more = {}) => ({ short, long: wordSet(value), all: wordSet(`${value} ${flags}`.trim()), prefix: true, ...more });
const OPT_SPECS = {
  curl: optSpec('AbcCdDeEFHKmoPQrtTuUwxXyYz', CURL_VALUE, CURL_FLAG, { fold: true, curl: true }),
  wget: optSpec('ABDIOPQRTUXYaeilnotw', WGET_VALUE, `${WGET_BOOL} ${WGET_BOOL.split(' ').map((b) => 'no-' + b).join(' ')} clobber dont-remove-listing help parent version`),
  nc: optSpec('IiMmOPpqsTVWwXxgGoec', '', ''),                    // nc.openbsd (46bCDdFhI:i:klM:m:NnO:P:p:q:rSs:T:tUuV:vW:w:X:x:Zz) and traditional -g -G -o -e -c
  ncat: optSpec('cegGimpqdoxsw', NCAT_VALUE, '4 6 unixsock vsock crlf help listen append-output keep-open recv-only send-only no-shutdown '
    + 'broker chat talk telnet udp sctp version verbose nodns test ssl ssl-verify'),
  whatweb: optSpec('piUatgHcuI', WHATWEB_VALUE, 'help short-help verbose list-plugins no-errors no-cookies debug version quiet output-sync'),
  wafw00f: optSpec('tofipH', 'test output format input-file proxy headers', 'verbose findall noredirect list version help'),
  sslyze: optSpec('', SSLYZE_VALUE, 'help update_trust_stores quiet slow_connection certinfo compression early_data elliptic_curves ems fallback '
    + 'heartbleed http_headers openssl_ccs reneg resum robot sslv2 sslv3 tlsv1 tlsv1_1 tlsv1_2 tlsv1_3'),
  'testssl.sh': { short: '', exact: true, long: wordSet('--add-CA --add-ca --basicauth --color --connect-timeout --csvfile --csvfile-parent --debug '
    + '--file --htmlfile --htmlfile-parent --ip --jsonfile --jsonfile-parent --jsonfile-pretty --jsonfile-pretty-parent --local --logfile '
    + '--logfile-parent --mapping --mode --mtls --nodns --openssl --openssl-timeout --outFile --outfile --outprefix --proxy --reqheader --severity '
    + '--single-cipher --single_cipher --starttls --user-agent --warnings --xmpphost -V -iL -n -oA -oC -oH -oJ -oL -oa -oj -t -x') },
  wfuzz: optSpec('XbeRDdzrftwVHmospu', WFUZZ_VALUE, 'no-cache filter-help AAA AA follow interact help version dry-run prev'),
  dirb: optSpec('acEHNopPuxXz', '', ''),
  feroxbuster: optSpec('upPRaxmHbQSXWNCsTtdLwIo', FEROX_VALUE, 'stdin burp burp-replay smart thorough random-agent add-slash unique redirects '
    + 'insecure no-recursion force-recursion extract-links dont-extract-links auto-tune auto-bail dont-filter collect-extensions collect-backups '
    + 'collect-words scan-dir-listings verbosity silent quiet json no-state update help version', { prefix: false, eqShort: true,
    multi: wordSet('-R -x -m -H -b -Q -S -X -W -N -C -s -w -I --replay-codes --extensions --methods --headers --cookies --query --dont-scan '
      + '--scope --filter-size --filter-regex --filter-words --filter-lines --filter-status --filter-similar-to --status-codes --server-certs '
      + '--wordlist --dont-collect') }),
};
// The SMB, RPC, LDAP, SNMP and NFS clients and fping, from their own parsers: smbclient and rpcclient 4.19 and master use
// popt (exact long names; a short option's attached value drops one leading =, so -c=ls is -c ls; source3/client/client.c,
// source3/rpcclient/rpcclient.c and the common Samba, connection and credential tables of their --help), ldapsearch 2.6
// getopt "a:Ab:cE:F:l:Ls:S:tT:uz:Cd:D:e:f:H:IMnNO:o:P:QR:U:vVw:WxX:y:Y:Z", snmpwalk 5.9 getopt
// "Y:VhHm:M:O:I:P:D:dv:r:t:c:Z:e:E:n:u:l:x:X:a:A:p:T:-:3:L:s:" plus C: (--name=value is the option - with a value),
// showmount's getopt_long table, rpcinfo's getopt "a:bdlmn:pstT:u" (rpcbind 1.2.6), fping 5's optparse table (exact names)
const SAMBA_VALUE = 'debuglevel configfile option log-basename name-resolve socket-options max-protocol netbiosname netbios-scope workgroup '
  + 'realm user password authentication-file simple-bind-dn use-kerberos use-krb5-ccache client-protection';
const SAMBA_FLAG = 'debug-stdout leak-report leak-report-full no-pass pw-nt-hash machine-pass use-winbind-ccache kerberos version help usage';
Object.assign(OPT_SPECS, {
  smbclient: optSpec('dslROmnWUAMILTDcbtp', `${SAMBA_VALUE} message ip-address list tar directory command send-buffer timeout port`,
    `${SAMBA_FLAG} stderr grepable quiet browse`, { prefix: false, eqShort: true }),
  rpcclient: optSpec('dslROmnWUAcIp', `${SAMBA_VALUE} command dest-ip port`, SAMBA_FLAG, { prefix: false, eqShort: true }),
  ldapsearch: optSpec('abEFlsSTzdDefHOoPRUwXyYhp', '', '', { prefix: false }),     // and 2.4's h: and p: (2.5 removed both)
  snmpwalk: optSpec('YmMOIPDvrtcZeEnulxXaApT3LsC', '', '', { prefix: false }),
  showmount: optSpec('', '', 'all directories exports help version no-headers'),
  rpcinfo: optSpec('anT', '', '', { prefix: false }),
  fping: optSpec('bBcCHiIkOpQrStxXf', 'size backoff count vcount ttl interval iface fwmark tos period squiet retry src timeout reachable '
    + 'fast-reachable file', 'ipv4 ipv6 alive addr rdns timestamp elapsed generate help json loop all dontfrag name netdata outage quiet random '
    + 'stats unreach version', { prefix: false }),
  // whois.c (rfc1036/whois): getopt_long "abBcdFg:Gh:Hi:IKlLmMp:q:rRs:t:T:v:V:x" and longopts[] (the long RIPE flags take a
  // value even where their letter does not)
  whois: optSpec('ghipqstTvV', 'server host port exact all-more one-more all-less one-less reverse-domain irt select-types sources template '
    + 'ripe-verbose diff-versions show-version filter-tag-include filter-tag-exclude', 'version verbose help no-recursion abuse-contact brief '
    + 'primary-keys persistent-connection no-referenced no-filtering no-grouping all-sources types ripe-version list-sources list-versions '
    + 'resource show-personal no-personal show-tag-info no-tag-info'),
  // dnsrecon 1.1.5 and fierce 1.5 (argparse: unique prefixes, -nX and -n=X, nargs='+' takes every word up to an option)
  dnsrecon: optSpec('dnrDxcjt', 'domain name_server range dictionary threads lifetime db xml csv json type', 'tcp iw disable_check_recursion '
    + 'disable_check_bindversion version verbose help', { eqShort: true }),
  fierce: optSpec('', 'domain traverse search range delay subdomains subdomain-file dns-servers dns-file', 'connect wide tcp help',
    { multi: wordSet('--search --subdomains --dns-servers') }),
  // traceroute 2.1.5 (libsupp/clif.c option_list), iputils ping (getopt "h?4bRT:6F:N:aABc:CdDe:fHi:I:l:Lm:M:nOp:qQ:rs:S:t:UvVw:W:"),
  // onesixtyone 0.3.4 (getopt "c:di:o:p:s:w:q": -s takes a word too), enum4linux 0.9.1 (Getopt::Std
  // "UMNSPGlLDu:dp:f:rR:s:k:vAow:hnaiPK:"), enum4linux-ng 1.3 (argparse with one-dash names: -As, -Gm, -oJ are options of
  // their own, read as whole words; -R takes a number optionally, read here as a flag), smbmap 1.10 (argparse; -r takes its
  // path optionally, read here as a flag), iputils tracepath 20240117 (getopt "46nbh?l:m:p:V"), nbtscan 1.7.2 (getopt
  // "vrdelqhm:s:t:b:f:")
  traceroute: optSpec('fgimNptlwqszMOP', 'first gateway interface max-hops sim-queries port tos flowlabel wait queries source sendwait module '
    + 'options sport fwmark protocol', 'debug dont-fragment icmp tcp extensions as-path-lookups udp UL dccp mtu back version help'),
  tracepath: optSpec('lmp', '', '', { prefix: false }),
  nbtscan: optSpec('mstbf', '', '', { prefix: false }),
  ping: optSpec('TFNceiIlmMpQsStwW', '', '', { prefix: false }),
  onesixtyone: optSpec('ciopsw', '', '', { prefix: false }),
  enum4linux: optSpec('upfRskwK', '', '', { prefix: false }),
  'enum4linux-ng': { short: '', exact: true, long: wordSet('-w -u -p -K -H -k -r -s -t -oJ -oY -oA') },
  smbmap: optSpec('HupsdPxgAF', 'host-file username password dc-ip timeout mode list-dir-timeout csv depth exclude search-path search-timeout '
    + 'download upload delete', 'prompt kerberos no-pass version signing admin no-banner no-color no-update dir-only no-write-check skip help',
  { eqShort: true, multi: wordSet('--exclude') }),
});
// ike-scan 1.9.5 (getopt_long_only "f:hs:d:r:t:i:b:w:vl:z:m:Ve:a:o::u:n:y:g:p:AG:I:qMRT::P::O:Nc:B:L:Z:E:C:D:S:j:k:2X:" and
// long_options[]: 1 a value, 2 an optional one, 0 none)
const IKE_SHORT = { value: 'fsdrtibwlzmeaunygpGIOcBLZECDSjkX', optional: 'oTP', all: 'fhsdrtibwvlzmVeaounygpAGIqMRTPONcBLZECDSjk2X' };
const IKE_LONG = Object.fromEntries([...('file sport dport retry timeout interval backoff selectwait lifetime lifesize auth vendor trans fuzz id idtype '
  + 'dhgroup patterns gssid vidpatterns tcptimeout noncelen bandwidth headerlen mbz headerver certreq doi situation protocol transid spisize '
  + 'hdrflags hdrmsgid cookie exchange nextpayload writepkttofile randomseed sourceip bindip rcookie readpktfromfile experimental').split(' ')
  .map((n) => [n, 1]), ...['showbackoff', 'tcp', 'pskcrack'].map((n) => [n, 2]),
...'help verbose version aggressive quiet multiline random nodns timestamp shownum ikev2 nat-t'.split(' ').map((n) => [n, 0])]);
// the transports net-snmp reads before a colon in an agent (udp:host:161); anything else before a colon is a host name
const SNMP_TRANSPORTS = wordSet('udp tcp udp6 tcp6 udpv6 tcpv6 udpipv6 tcpipv6 unix uds alias callback ipx aal5pvc pvc dtlsudp dtlssctp tlstcp ssh');
// the server an smbclient or rpcclient target names, or why it cannot count: a NetBIOS name (one label) resolves by WINS or
// a broadcast (name resolve order "lmhosts wins host bcast"), unless -I gives the address to connect to
function sambaServer(name, tool, out, viaIp) {
  const n = String(name).replace(/#.*$/, '');                    // host#20: a NetBIOS name type
  if (viaIp) return;                                              // -I is the address; the name is only the one it calls
  if (!n) out.push([`an empty server name`, 'bad']);
  else if (!n.includes('.') && !/^[\d:[]/.test(n) && n.toLowerCase() !== 'localhost') {
    out.push([`a NetBIOS name (${n.slice(0, 40)}): ${tool} resolves it by WINS or a broadcast`, 'bad']);
  } else out.push([n, 'host']);
}
// the tool behind each name a READONLY_TOOLS member also goes by: wget2 may stand in for wget, netcat for nc, testssl and
// httpx-toolkit are the Debian and Kali names of testssl.sh and httpx
const TOOL_ALIAS = { wget2: 'wget', netcat: 'nc', testssl: 'testssl.sh', 'httpx-toolkit': 'httpx' };
const toolOf = (program) => TOOL_ALIAS[program] || program;
// a long option as the tool reads it -> [name, takes a value]: an exact name, else a unique prefix where the parser takes
// one; '' when unknown or ambiguous (the tool then refuses to run), still taking a value when every candidate takes one
function optName(given, spec) {
  let g = spec.fold ? given.toLowerCase() : given;
  if (spec.curl) { g = g.replace(/^expand-/, ''); if (g.startsWith('no-') && !spec.all.has(g)) g = g.slice(3); }   // --expand-url, --no-buffer
  if (spec.all.has(g)) return [g, spec.long.has(g)];
  if (!spec.prefix || !g) return ['', false];
  let hit = '', n = 0, allValue = true;
  for (const name of spec.all) if (name.startsWith(g)) { hit = name; n++; allValue = allValue && spec.long.has(name); }
  return n === 1 ? [hit, spec.long.has(hit)] : ['', n > 1 && allValue];
}
// a tool's words -> { opts: [[name, value or null]], operands }; name is '-x' for a short letter, '--name' for a long option
// (the full name when the tool reads a prefix as one). Options count wherever they stand, also where a parser stops
// reading them at the first operand (testssl, wfuzz): stricter, and such a command fails before it sends anything.
function walkOpts(args, spec) {
  const opts = [], operands = [];
  const take = (name, v, k) => {                                  // clap: an option of several values takes every next word up to an option
    opts.push([name, v]);
    if (!spec.multi || !spec.multi.has(name)) return k;
    while (k + 1 < args.length && !args[k + 1].startsWith('-')) opts.push([name, args[++k]]);
    return k;
  };
  for (let k = 0; k < args.length; k++) {
    const t = args[k];
    if (t === '--') { operands.push(...args.slice(k + 1)); break; }
    if (spec.exact && t.length > 1 && t.startsWith('-')) {
      const eq = t.indexOf('='), name = eq < 0 ? t : t.slice(0, eq);
      opts.push([name, eq >= 0 ? t.slice(eq + 1) : spec.long.has(name) && k + 1 < args.length ? args[++k] : null]);
      continue;
    }
    if (t.startsWith('--') && t.length > 2) {
      const eq = t.indexOf('='), given = eq < 0 ? t.slice(2) : t.slice(2, eq), [name, valued] = optName(given, spec);
      let v = eq < 0 ? null : t.slice(eq + 1);
      if (v === null && valued && k + 1 < args.length) v = args[++k];
      k = take('--' + (name || given), v, k);
      continue;
    }
    if (t.length > 1 && t.startsWith('-')) {
      for (let p = 1; p < t.length; p++) {
        if (!spec.short.includes(t[p])) { opts.push(['-' + t[p], null]); continue; }
        let v = p + 1 < t.length ? t.slice(p + 1) : k + 1 < args.length ? args[++k] : null;
        if (spec.eqShort && v !== null && p + 1 < t.length && v.startsWith('=')) v = v.slice(1);     // clap: -m=PUT
        k = take('-' + t[p], v, k);
        break;
      }
      continue;
    }
    operands.push(t);
  }
  return { opts, operands };
}
const optValues = (w, names) => w.opts.filter(([n, v]) => names.includes(n) && v !== null).map(([, v]) => v);
const optHas = (w, names) => w.opts.some(([n]) => names.includes(n));
// Go's flag package (ffuf, httpx, gobuster 3.7): -name or --name, exact and case-sensitive, =value or the next word
const goWord = (t) => /^--?([^-=][^=]*)(?:=([\s\S]*))?$/.exec(t);
const goValues = (args, names) => args.flatMap((t, i) => { const m = goWord(t); return m && names.includes(m[1]) ? [m[2] !== undefined ? m[2] : i + 1 < args.length ? args[i + 1] : ''] : []; });
const goOn = (args, names) => args.some((t) => { const m = goWord(t); return !!m && names.includes(m[1]) && !/^(0|f|F|false|FALSE|False)$/.test(m[2] ?? ''); });
// goOn and goValues read every word, stricter for a flag that makes a tool wait. A flag that lets a tool auto-run (httpx
// -duc, -r) counts only where Go's flag package takes it: a flag that is no boolean takes the next word whatever it holds
// (-H -duc is a header), and parsing stops at the first word that is no flag. httpx's booleans (runner/options.go BoolVar),
// and its goflags DynamicVar and CallbackVar flags, which report IsBoolFlag: -bp/-body-preview, -cdn, -strip, -up/-update,
// -auth (httpx 1.12.0: 'httpx -duc -cdn -version' prints the version, -cdn leaves the next word alone)
const HTTPX_BOOL = wordSet('asn auth auto-referer body-preview bp cdn cl cname content-length content-type cpe csp-probe csv ct dashboard debug debug-req debug-resp '
  + 'disable-update-check duc efqdn ehb esb exclude-headless-body exclude-screenshot-bytes extract-fqdn favicon fd fep fhr filter-duplicates '
  + 'filter-error-page follow-host-redirects follow-redirects fr hc health-check http2 include-chain include-response include-response-base64 '
  + 'include-response-header ip irh irr irrb j jarm json kb knowledge-base lc ldp ldv leave-default-ports line-count list-dsl-variables '
  + 'list-output-fields location lof markdown md method nc nf nfs no-color no-decode no-fallback no-fallback-scheme no-screenshot-full-page '
  + 'no-stdin oa ob omit-body output-all pa pd pipeline probe probe-all-ips random-agent rdb rdbor respect-hsts response-time result-db '
  + 'result-db-omit-raw resume rhsts rt s sc screenshot sd server silent skip-dedupe sr ss stats status-code store-chain store-response '
  + 'store-vision-recon-cluster stream strip svrc system-chrome td tech-detect title tls-grab tls-probe tr trace unsafe up update v verbose version vhost '
  + 'vhost-input wc web-server websocket word-count wordpress wp ws ztls');
const goTaken = (args, bools) => {
  const out = [];
  for (let k = 0; k < args.length; k++) {
    const m = goWord(args[k]);
    if (!m) break;                                                // -- and the first word that is no flag end the flags
    out.push([m[1], m[2] !== undefined ? m[2] : bools.has(m[1]) ? null : k + 1 < args.length ? args[++k] : null]);
  }
  return out;
};
const GOBUSTER_VALUE = { dir: 'cxXHmPsbuaUoptw', vhost: 'cHmPuaUoptw', fuzz: 'BcbHmPuaUoptw', dns: 'droptw', tftp: 'soptw' };   // gobuster 3.6, per mode
const gobusterWalk = (args) => {
  const mode = args.find((t) => !t.startsWith('-')) || '';
  return { mode, w: walkOpts(args, { short: GOBUSTER_VALUE[mode] || '', long: wordSet('url domain server method body headers proxy resolver cookies '
    + 'useragent username password output pattern threads wordlist delay timeout status-codes status-codes-blacklist extensions extensions-file '
    + 'exclude-length excludestatuscodes retry-attempts wordlist-offset client-cert-p12 client-cert-p12-password client-cert-pem '
    + 'client-cert-pem-key'), all: new Set(), prefix: false }) };
};

// ---- the hosts a tool contacts: every value in a host position must name a host the scope check reads ----------------
// A host as the scope check reads it, or why it cannot: an IPv6 literal, or a numeric host that is not a plain dotted
// quad (curl, wget, nc and OpenSSL take 127.1, 2130706433, 0x7f.1 and 0177.0.0.1 for 127.0.0.1). Any other name is a host
// (a single label, a file-like or non-ASCII name, a fullwidth dot): exact names, so the scope check blocks it unless the
// allowlist holds that very name.
function hostOf(h) {
  const x = String(h || '').trim().toLowerCase();
  if (!x) return { bad: 'an empty host' };
  if (x.startsWith('[') || /^[0-9a-f]*:[0-9a-f:]*$/.test(x)) return { bad: `an IPv6 literal (${x.slice(0, 40)})` };
  if (x === 'localhost') return { host: '127.0.0.1' };
  if (IP_RANGE.test(x)) return { host: asName(x) };              // a host name that looks like a range (asName)
  if (/^[0-9.]+$/.test(x) || /^0x|\.0x/.test(x)) {
    return ipToInt(x) !== null && !/(^|\.)0\d/.test(x) ? { host: x } : { bad: `an IP address the scope check cannot read (${x.slice(0, 40)})` };
  }
  return { host: x };
}
// the host of a URL (scheme://[user@]host[:port][/path], or without a scheme), as curl reads it and as the WHATWG parsers
// read it (a backslash ends the host there, http://10.10.10.5\@evil.com/): both hosts count
function urlHosts(u) {
  const rest = String(u).replace(/^[A-Za-z][A-Za-z0-9+.-]*:\/{1,3}/, '');
  return [/[\/?#]/, /[\/?#\\]/].map((end) => {
    let auth = rest.search(end) < 0 ? rest : rest.slice(0, rest.search(end));
    auth = auth.slice(auth.lastIndexOf('@') + 1);
    return auth.startsWith('[') ? auth : auth.replace(/:[^:]*$/, '');
  });
}
const hostPort = (v) => (/:\/\//.test(v) ? urlHosts(v) : [String(v).slice(String(v).lastIndexOf('@') + 1).replace(/^([^\[][^:]*):.*$/, '$1')]);
// a target value of a given kind -> the raw host strings it names
function targetHostStrings(value, kind) {
  const v = String(value);
  if (kind === 'url') return urlHosts(v);
  if (kind === 'hostport') return hostPort(v);
  if (kind === 'connect-to') { const p = v.split(':'); return [p[0], p[2]].filter((x) => x !== undefined && x !== ''); }   // HOST1:PORT1:HOST2:PORT2
  if (kind === 'resolve') { const p = v.replace(/^[+-]/, '').split(':'); return [p[0], ...(p.slice(2).join(':') ? p.slice(2).join(':').split(',') : [])]; }
  if (kind === 'sslyze') { const m = /^(.*?)(?:\{([^}]*)\})?$/.exec(v); return hostPort(m[1]).concat(m[2] ? [m[2]] : []); }   // host:port{ip}
  return [v];                                                     // 'host'
}
// a value bash expands at run time ($IP, $(cat ip), `cmd`): the gate cannot read the host it names, so such a target waits
// (findUnverifiable flags it too)
const expansionWhy = (v) => (/[$`]/.test(String(v)) ? `a shell expansion the gate cannot read (${String(v).slice(0, 40)})` : '');
// every target value a tool reads (operands, -u, proxies, connect-to, ...) for the tools whose targets the gate reads,
// or null for any other program. [value, kind] pairs; kind 'bad' carries a reason.
function toolTargets(program, args) {
  const tool = toolOf(program), out = [];
  const add = (vals, kind) => { for (const v of vals) out.push([v, kind]); };
  const addRead = (vals, kind) => { for (const v of vals) out.push(expansionWhy(v) ? [expansionWhy(v), 'bad'] : [v, kind]); };
  if (tool === 'curl') {
    const w = walkOpts(args, OPT_SPECS.curl);
    add(w.operands, 'url');
    add(optValues(w, ['--url']).filter((v) => !v.startsWith('@') && !v.includes('{{')), 'url');   // @file and {{var}} wait anyway
    add(optValues(w, ['-x', '--proxy', '--preproxy', '--socks4', '--socks4a', '--socks5', '--socks5-hostname', '--proxy1.0', '--doh-url',
      '--ipfs-gateway']).filter((v) => !v.includes('{{')), 'hostport');
    add(optValues(w, ['--connect-to']).filter((v) => !v.includes('{{')), 'connect-to');
    add(optValues(w, ['--resolve']).filter((v) => !v.includes('{{')), 'resolve');
    add(optValues(w, ['--dns-servers']).flatMap((v) => v.split(',')), 'hostport');
    return out;
  }
  // wget's operands, and --dns-servers (a build with c-ares sends every lookup to these host[:port] servers: main.c)
  if (tool === 'wget') {
    const w = walkOpts(args, OPT_SPECS.wget);
    return w.operands.map((v) => [v, 'url']).concat(optValues(w, ['--dns-servers']).flatMap((v) => v.split(',')).map((v) => [v, 'hostport']));
  }
  if (tool === 'nc' || tool === 'ncat') {
    const w = walkOpts(args, OPT_SPECS[tool]);
    if (optHas(w, ['-U', '--unixsock', '--vsock', '-l', '--listen'])) return null;     // a socket path or a listener: an escape waits for it
    if (w.operands.length) out.push([w.operands[0], 'host']);
    for (const p of w.operands.slice(1)) if (!(tool === 'nc' ? /^(\d+(-\d+)?|[A-Za-z][\w-]*)$/ : /^\d+$/).test(p)) out.push([`a port the gate cannot read (${p.slice(0, 40)})`, 'bad']);
    add(optValues(w, tool === 'nc' ? ['-x'] : ['--proxy']), 'hostport');                // ncat -x is --hex-dump, a local file
    add(optValues(w, ['-g', '--g']).flatMap((v) => v.split(',')), 'host');               // source-routing hops
    return out;
  }
  if (tool === 'whatweb' || tool === 'wafw00f') {
    const w = walkOpts(args, OPT_SPECS[tool]);
    add(w.operands, 'url');
    add(optValues(w, tool === 'wafw00f' ? ['-p', '--proxy'] : ['--proxy']), 'hostport');   // whatweb -p names plugins
    return out;
  }
  if (tool === 'sslscan') { add(args.filter((t) => !t.startsWith('-')), 'hostport'); return out; }
  if (tool === 'sslyze') {
    const w = walkOpts(args, OPT_SPECS.sslyze);
    add(w.operands, 'sslyze');
    add(optValues(w, ['--https_tunnel']), 'hostport');
    return out;
  }
  if (tool === 'testssl.sh') {
    const w = walkOpts(args, OPT_SPECS['testssl.sh']);
    add(w.operands, 'url');
    add(optValues(w, ['--ip']).filter((v) => v !== 'one' && v !== 'proxy'), 'host');
    add(optValues(w, ['--proxy']).filter((v) => v !== 'auto'), 'hostport');
    return out;
  }
  if (tool === 'wfuzz') {
    const w = walkOpts(args, OPT_SPECS.wfuzz);
    add(w.operands.concat(optValues(w, ['-u'])), 'url');
    add(optValues(w, ['--ip']), 'hostport');
    add(optValues(w, ['-p']).map((v) => v.split(':')[0]), 'host');
    return out;
  }
  if (tool === 'dirb') {
    const w = walkOpts(args, OPT_SPECS.dirb);
    add(w.operands.slice(0, 1), 'url');                            // dirb <url> [wordlists] [options]
    add(optValues(w, ['-p']), 'hostport');
    return out;
  }
  if (tool === 'httpx') {
    for (const v of goValues(args, ['u', 'target']).flatMap((x) => x.split(','))) {
      if (/^as\d+$/i.test(v)) out.push(['an AS number (it stands for every prefix of the AS)', 'bad']);
      else if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(v)) out.push([v, 'host']);   // a network: the scope check needs all of it in scope
      else out.push([v, 'url']);
    }
    add(goValues(args, ['proxy', 'http-proxy']), 'hostport');
    add(goValues(args, ['r', 'resolvers']).flatMap((v) => v.split(',')).filter((v) => /^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(v)), 'hostport');
    return out;
  }
  if (tool === 'gobuster') {
    const { mode, w } = gobusterWalk(args);
    const vals = (short, long) => optValues(w, [short, long].filter(Boolean)).concat(goValues(args, [long.slice(2)]));
    // tftp -s/--server: the TFTP server (host[:port], port 69 by default) it sends read requests to
    if (mode === 'dns') { add(vals('-d', '--domain'), 'host'); add(vals('-r', '--resolver'), 'hostport'); }
    else if (mode === 'tftp') addRead(vals('-s', '--server'), 'hostport');
    else add(vals('-u', '--url'), 'url');
    add(vals('', '--proxy'), 'hostport');
    return out;
  }
  if (tool === 'ffuf') { add(goValues(args, ['u']), 'url'); add(goValues(args, ['x', 'replay-proxy']), 'hostport'); return out; }
  if (tool === 'feroxbuster') {
    const w = walkOpts(args, OPT_SPECS.feroxbuster);
    add(optValues(w, ['-u', '--url']), 'url');
    add(optValues(w, ['-p', '--proxy', '-P', '--replay-proxy', '--scope']), 'hostport');
    return out;
  }
  if (tool === 'dirbuster') { add(args.flatMap((t, i) => (t === '-u' && i + 1 < args.length ? [args[i + 1]] : [])), 'url'); return out; }
  // smbclient: -L HOST lists a host, else the service (//server/share, \\server\share) names it; -I is the address to use
  if (tool === 'smbclient') {
    const w = walkOpts(args, OPT_SPECS.smbclient), ips = optValues(w, ['-I', '--ip-address']), list = optValues(w, ['-L', '--list']);
    add(ips, 'host');
    if (list.length) { for (const v of list) sambaServer(v.replace(/^[\\/]+/, '').split(/[\\/]/)[0], 'smbclient', out, ips.length); return out; }
    if (w.operands.length) {
      const svc = w.operands[0].replace(/\//g, '\\');
      if (/^\\\\[^\\]/.test(svc)) sambaServer(svc.slice(2).split('\\')[0], 'smbclient', out, ips.length);
      else out.push([`a service the gate cannot read (${w.operands[0].slice(0, 40)})`, 'bad']);
    }
    return out;
  }
  // rpcclient: one server, a host or a binding string ([uuid@]ncacn_np:host[...], ncacn_ip_tcp:host[...]; ncalrpc is a local
  // socket), //host or \\host; -I is the address to use
  if (tool === 'rpcclient') {
    const w = walkOpts(args, OPT_SPECS.rpcclient), ips = optValues(w, ['-I', '--dest-ip']);
    add(ips, 'host');
    if (w.operands.length) {
      const raw = w.operands[0].replace(/^(\/\/|\\\\)/, ''), b = /^(?:[0-9a-f-]+@)?([A-Za-z_]\w*):(.*)$/i.exec(raw);
      if (b && !/^ncacn_(np|ip_tcp)$/i.test(b[1])) out.push([`an RPC binding the gate cannot scope (${b[1].slice(0, 20)})`, 'bad']);
      else sambaServer((b ? b[2] : raw).replace(/\[[\s\S]*$/, '').split(/[\\/]/)[0], 'rpcclient', out, ips.length);
    }
    return out;
  }
  // ldapsearch: every -H URI must name a host, and so must OpenLDAP 2.4's -h (it builds ldap://HOST:PORT from -h and -p; 2.5
  // and later refuse -h and -p, so the command fails without a connection). Without either the server comes from ldap.conf,
  // ./ldaprc or localhost, a URI with no host from DNS SRV records, ldapi:// is a local socket (ldapsearch(1), common.c)
  if (tool === 'ldapsearch') {
    const w = walkOpts(args, OPT_SPECS.ldapsearch), uris = optValues(w, ['-H']).flatMap((v) => v.split(/[\s,]+/)).filter(Boolean);
    addRead(optValues(w, ['-h']), 'hostport');
    if (!uris.length && !optHas(w, ['-h'])) out.push(['no -H or -h (the server comes from ldap.conf, ./ldaprc or localhost)', 'bad']);
    for (const u of uris) {
      const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^\/?#]*)/.exec(u);
      if (!m || !/^ldaps?$/i.test(m[1])) out.push([`an LDAP URI other than ldap:// or ldaps:// (${u.slice(0, 40)})`, 'bad']);
      else if (!m[2]) out.push([`an LDAP URI without a host (${u.slice(0, 40)}): DNS SRV records or ldap.conf pick the server`, 'bad']);
      else add([u], 'url');
    }
    return out;
  }
  // snmpwalk: the agent is the first operand, [udp:|tcp:]host[:port]; alias:, unix:, callback: and the other transports
  // reach a definition from snmp.conf, a local socket or another protocol. Every E in a -C value takes the word after the
  // option as the OID to end at (snmpwalk.c optProc: argv[optind++]), so -CE 10.10.10.5 gw walks the agent gw
  if (tool === 'snmpwalk') {
    const w = walkOpts(snmpEndOids(args), OPT_SPECS.snmpwalk);
    if (!w.operands.length) return [['no agent', 'bad']];
    const agent = w.operands[0], m = /^([A-Za-z]\w*):([\s\S]*)$/.exec(agent), tr = m && SNMP_TRANSPORTS.has(m[1].toLowerCase()) ? m[1].toLowerCase() : '';
    if (tr && tr !== 'udp' && tr !== 'tcp') out.push([`an SNMP transport other than udp or tcp (${tr}:)`, 'bad']);
    else add([tr ? m[2] : agent], 'hostport');
    return out;
  }
  // showmount and rpcinfo ask the runner itself without a host; rpcinfo -T local or unix does even with one, -a takes a
  // universal address (a.b.c.d.p1.p2), -b and -d never auto-run (reconEscape)
  if (tool === 'showmount') {
    const w = walkOpts(args, OPT_SPECS.showmount);
    if (!w.operands.length) return [['no host (showmount asks the runner itself)', 'bad']];
    add(w.operands.slice(0, 1), 'host');
    return out;
  }
  if (tool === 'rpcinfo') {
    const w = walkOpts(args, OPT_SPECS.rpcinfo);
    for (const v of optValues(w, ['-T'])) if (!/^(udp|tcp)$/i.test(v)) out.push([`rpcinfo -T ${v.slice(0, 20)} (only udp and tcp reach the host; local and unix are the runner's rpcbind)`, 'bad']);
    const uaddr = optValues(w, ['-a']);
    for (const v of uaddr) {
      const m = /^(\d{1,3}(?:\.\d{1,3}){3})\.\d{1,3}\.\d{1,3}$/.exec(v);
      if (m) out.push([m[1], 'host']); else out.push([`a universal address the gate cannot read (${v.slice(0, 40)})`, 'bad']);
    }
    if (!uaddr.length && !w.operands.length) out.push(["no host (rpcinfo asks the runner's own rpcbind)", 'bad']);
    if (!uaddr.length) add(w.operands.slice(0, 1), 'host');
    return out;
  }
  // whois asks the server -h (--host, --server) names, host[:port], and then connects to the host a referral in its reply
  // names (ReferralServer: whois://, rwhois://, % referto:), unless --no-recursion (getopt_long: exact, or a unique prefix
  // from --no-rec) keeps it to the -h server (whois.c handle_query, do_query). Without -h it picks a server itself
  // (/etc/whois.conf, WHOIS_SERVER, its table: whois.iana.org, whois.arin.net, ...) and follows their referrals; -I asks
  // whois.iana.org first
  if (tool === 'whois') {
    const w = walkOpts(args, OPT_SPECS.whois), servers = optValues(w, ['-h', '--host', '--server']);
    if (optHas(w, ['-I'])) out.push(['-I (whois asks whois.iana.org first and follows its referral)', 'bad']);
    if (!optHas(w, ['-h', '--host', '--server'])) out.push(["no -h (whois asks the registries' servers: whois.iana.org, whois.arin.net and the ones they refer to)", 'bad']);
    addRead(servers, 'hostport');
    if (servers.length && !optHas(w, ['--no-recursion'])) out.push(["a referral in the -h server's reply (whois connects to the host it names unless --no-recursion is given)", 'bad']);
    return out;
  }
  // nmap reads every operand as a target, unless -iL or -i names a file of targets; -sI's zombie, -b's FTP relay and
  // --dns-servers are hosts it sends packets to as well. rustscan scans its -a entries and hands nmap the words after --
  if (tool === 'nmap') { nmapTargets(args, out); return out; }
  if (tool === 'rustscan') {
    const own = args.includes('--') ? args.slice(0, args.indexOf('--')) : args;
    for (const e of rustscanEntries(own)) {
      const r = IP_RANGE.test(e) ? ipRanges(e) : null;
      if (r) out.push(r.length === 1 ? [r[0], 'range'] : [`a range the scope check cannot read (${e.slice(0, 40)})`, 'bad']);
      else if (!rustscanFileLike(e)) out.push([e, 'host']);
      else out.push([`a file name or an entry the gate cannot read (${e.slice(0, 40)})`, 'bad']);
    }
    if (args.includes('--')) nmapTargets(args.slice(args.indexOf('--') + 1), out);
    // --resolver (2.3 and later) names a file of DNS servers first, and only if no such file can be read a comma list of
    // addresses (address.rs get_resolver): only addresses are read here
    for (const v of pdLongValues(own, 'resolver').flatMap((x) => (x === null ? [''] : x.split(',')))) {
      out.push(/^\d{1,3}(\.\d{1,3}){3}$/.test(v) ? [v, 'host'] : [`a resolver the gate cannot read (${v.slice(0, 40)}): rustscan reads a file of DNS servers by that name`, 'bad']);
    }
    return out;
  }
  // fping -g START END pings every address between the two
  if (tool === 'fping') {
    const w = walkOpts(args, OPT_SPECS.fping), ops = w.operands;
    if (optHas(w, ['-g', '--generate']) && ops.length === 2 && ops.every((v) => ipToInt(v) !== null)) {
      out.push([ipToInt(ops[0]) <= ipToInt(ops[1]) ? `${ops[0]}-${ops[1]}` : `${ops[1]}-${ops[0]}`, 'range']);
    } else add(ops, 'host');
    return out;
  }
  // ping [hop ...] destination: the operands before the last are loose source-route hops the packets go to first (iputils
  // ping.c: rts->route), so every operand is a host
  if (tool === 'ping') { for (const v of walkOpts(args, OPT_SPECS.ping).operands) out.push(nmapTarget(v)); return out; }
  // traceroute host [packetlen], and the -g/--gateway hops (a list split at commas and blanks, clif.c CLIF_SEVERAL) its
  // probes are source-routed through
  if (tool === 'traceroute') {
    const w = walkOpts(args, OPT_SPECS.traceroute);
    if (w.operands.length) out.push(nmapTarget(w.operands[0]));
    addRead(optValues(w, ['-g', '--gateway']).flatMap((v) => v.split(/[\s,]+/)).filter(Boolean), 'host');
    return out;
  }
  // tracepath [-l pktlen] [-m hops] [-p port] destination: one operand, resolved with getaddrinfo (a name, or 8.8 for
  // 8.0.0.8); without -p, a /port after it is the port (tracepath.c: destination/port, backward compatibility)
  if (tool === 'tracepath') { addRead(walkOpts(args, OPT_SPECS.tracepath).operands.map((v) => v.split('/')[0]), 'host'); return out; }
  // nbtscan [-t ms] [-b bw] [-s sep] [-m n] range: one operand, read with inet_addr (8.8 is 8.0.0.8, 010 is 8, a name is no
  // range): an address, a.b.c.d/m (m 1 to 32) or a.b.c.d-N (the last octet up to N); only plain dotted-decimal forms are read
  if (tool === 'nbtscan') {
    const quad = (v) => ipToInt(v) !== null && !hostOf(v).bad;
    for (const v of walkOpts(args, OPT_SPECS.nbtscan).operands) {
      const net = /^([\d.]+)\/(\d{1,2})$/.exec(v), last = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$/.exec(v);
      if (expansionWhy(v)) out.push([expansionWhy(v), 'bad']);
      else if (quad(v) || (net && quad(net[1]))) out.push([v, 'host']);   // a mask outside 1 to 32 is out of scope
      else if (last && quad(last[1] + last[2]) && +last[2] <= +last[3] && +last[3] <= 255) out.push([`${last[1]}${last[2]}-${last[1]}${last[3]}`, 'range']);
      else out.push([`a range the gate cannot read (${v.slice(0, 40)}): nbtscan reads 8.8 as 8.0.0.8`, 'bad']);
    }
    return out;
  }
  // ike-scan scans every operand: an address or a name, a.b.c.d/nn, a.b.c.d-e.f.g.h (add_host_pattern; a.b.c.d:netmask is
  // blocked by the raw-text pass, which reads the netmask as an address)
  if (tool === 'ike-scan') { for (const v of longOnlyWalk(args, IKE_SHORT, IKE_LONG).operands) out.push(nmapTarget(v)); return out; }
  // onesixtyone [options] host [community]: the first operand is the host (an address or a.b.c.d/nn, read with
  // getaddrinfo AI_NUMERICHOST: 8.8 is 8.0.0.8), the second a community string; -i reads hosts from a file (reconEscape)
  if (tool === 'onesixtyone') {
    const w = walkOpts(args, OPT_SPECS.onesixtyone);
    if (!optHas(w, ['-i']) && w.operands.length) out.push(nmapTarget(w.operands[0]));
    return out;
  }
  // enum4linux and enum4linux-ng hand their host to smbclient, rpcclient, nmblookup and net, which resolve a name of one
  // label as a NetBIOS name (WINS or a broadcast)
  if (tool === 'enum4linux' || tool === 'enum4linux-ng') {
    for (const v of walkOpts(args, OPT_SPECS[tool]).operands) {
      if (!expansionWhy(v) && !v.includes('.') && !/^[\d:[]/.test(v) && v.toLowerCase() !== 'localhost') out.push([`a NetBIOS name (${v.slice(0, 40)}): ${tool} resolves it by WINS or a broadcast`, 'bad']);
      else out.push(nmapTarget(v));
    }
    return out;
  }
  // smbmap (impacket) connects to its -H host and asks --dc-ip, the KDC, for Kerberos tickets
  if (tool === 'smbmap') {
    const w = walkOpts(args, OPT_SPECS.smbmap);
    for (const v of optValues(w, ['-H'])) out.push(nmapTarget(v));
    addRead(optValues(w, ['--dc-ip']), 'host');
    return out;
  }
  if (tool === 'sqlmap') return sqlmapTargets(args);
  return null;
}
// sqlmap's target positions (lib/parse/cmdline.py): -u/--url (without a scheme sqlmap adds http://), a first word that looks
// like a URL (cmdline.py makes it --url=), -d's connection string DBMS://USER:PASSWORD@HOST:PORT/DB (one without @ names a
// local database file) and --safe-url (visited every --safe-freq requests). --proxy takes only a URL with a scheme, as
// --second-url and --csrf-url do to leave the target (a relative one resolves against it): the raw-text pass reads those
// hosts. sqlmap reads a one-dash word of three or more letters as the long option of that exact name (-dbs is --dbs, -url
// is --url), so -u and -d take a value only otherwise
const SQLMAP_UD_LONG = wordSet('data database dbms dbms-cred delay dns-domain dork dump-file dump-format dbs debug dependencies deprecations '
  + 'disable-coloring disable-hashing disable-json disable-multi disable-precon disable-stats doc-test drop-set-cookie dummy dump dump-all '
  + 'union-char union-cols union-from union-values url user-agent udf-inject unsafe-naming unstable update users');
const SQLMAP_TARGET_OPTS = [['url', 2], ['safe-url', 6]];
function sqlmapTargets(args) {
  const words = sqlmapWords(args), out = [];
  const take = (v, kind) => {
    if (v === null || v === undefined) return;
    if (expansionWhy(v)) out.push([expansionWhy(v), 'bad']);
    else if (kind !== 'dsn' || /^[^\/]*:\/\/[^\/]*@/.test(v)) out.push([v, 'url']);
  };
  if (words.length && /^(http|www\.|\w[\w.-]+\.\w{2,})/.test(words[0])) take(words[0], 'url');
  for (let i = 0; i < words.length; i++) {
    const t = words[i], next = i + 1 < words.length ? words[i + 1] : null;
    const short = /^-([ud])([\s\S]*)$/.exec(t);
    if (short && !(/^-\w{3,}/.test(t) && SQLMAP_UD_LONG.has(t.slice(1).split('=')[0]))) {
      take(short[2] !== '' ? short[2] : next, short[1] === 'u' ? 'url' : 'dsn');
      continue;
    }
    const m = /^(-{1,2})([A-Za-z][\w-]*)(?:=([\s\S]*))?$/.exec(t);
    if (!m) continue;
    const name = m[2].toLowerCase();
    for (const [opt, min] of SQLMAP_TARGET_OPTS) {
      if (m[1] === '-' ? name === opt : name.length >= min && opt.startsWith(name)) take(m[3] !== undefined ? m[3] : next, 'url');
    }
  }
  return out;
}
// snmpwalk's words without the ones -C takes as end OIDs (one word after the option for every E in its value)
function snmpEndOids(args) {
  const out = [];
  for (let k = 0; k < args.length; k++) {
    const t = args[k];
    out.push(t);
    if (t === '--') { out.push(...args.slice(k + 1)); break; }
    if (!/^-[^-]/.test(t)) continue;
    for (let p = 1; p < t.length; p++) {
      if (!OPT_SPECS.snmpwalk.short.includes(t[p])) continue;
      let v = t.slice(p + 1);
      if (!v && k + 1 < args.length) { v = args[++k]; out.push(v); }
      if (t[p] === 'C') k += (v.match(/E/g) || []).length;
      break;
    }
  }
  return out;
}
// ---- the DNS clients: the server each one asks ------------------------------------------------------------------------
// The names they look up stay with the raw-text pass (dig web01.lab asks the runner's resolver about web01.lab); the server
// a client is told to ask is a host position like a target: dig's @server words, host's word after the name, nslookup's
// word after the name or after -, dnsrecon -n (a comma list), dnsenum --dnsserver, fierce --dns-servers. Unlike a target,
// a command needs none of them (without one the runner's resolver answers). -> null, or [[value, kind]] like toolTargets
function dnsServers(program, args) {
  const tool = toolOf(program), out = [];
  const addRead = (vals) => { for (const v of vals) out.push(expansionWhy(v) ? [expansionWhy(v), 'bad'] : [v, 'host']); };
  if (tool === 'dig') addRead(digWalk(args).servers);
  else if (tool === 'host') addRead(hostWalk(args).servers);
  else if (tool === 'nslookup') addRead(nslookupWalk(args).servers);
  else if (tool === 'dnsrecon') addRead(optValues(walkOpts(args, OPT_SPECS.dnsrecon), ['-n', '--name_server']).flatMap((v) => v.split(',')));
  else if (tool === 'fierce') addRead(optValues(walkOpts(args, OPT_SPECS.fierce), ['--dns-servers']));
  // Getopt::Long's reading: one or two dashes, any case, a unique prefix from --dn, =value or the next word
  else if (tool === 'dnsenum') addRead(args.flatMap((t, i) => { const m = /^--?([A-Za-z][\w-]*)(?:=([\s\S]*))?$/.exec(t);
    return m && m[1].length >= 2 && 'dnsserver'.startsWith(m[1].toLowerCase()) ? [m[2] !== undefined ? m[2] : i + 1 < args.length ? args[i + 1] : ''] : []; }));
  else return null;
  return out;
}
// dig's words as dig.c reads them (preparse_args, dash_option, parse_args): leading -4 -6 -d -h -i -m -n -r -u -v in any
// number, then a letter that takes a value (b c f k p q t x y: the rest of the word or the next word), @server words,
// +options, and nothing after a word that starts with %. A value is no option: dig -q -r web01.lab still reads ~/.digrc
// (a local run). -> { servers, plus, batch (-f), norc (-r: ~/.digrc is not read) }
function digWalk(args) {
  const out = { servers: [], plus: [], batch: false, norc: false };
  for (let k = 0; k < args.length; k++) {
    const t = args[k];
    if (t.startsWith('%')) break;
    if (t.startsWith('@')) { out.servers.push(t.slice(1)); continue; }
    if (t.startsWith('+')) { out.plus.push(t.slice(1)); continue; }
    if (t.length < 2 || t[0] !== '-') continue;
    let p = 1;
    for (; p < t.length && '46dhimnruv'.includes(t[p]); p++) if (t[p] === 'r') out.norc = true;
    if (p < t.length && 'bcfkpqtxy'.includes(t[p])) {
      if (t[p] === 'f') out.batch = true;
      if (p + 1 === t.length) k++;                               // its value is the next word
    }
  }
  return out;
}
// a dig +option that makes dig ask the servers DNS answers name: +trace (the root and TLD servers down to the zone's) and
// +nssearch (every NS of the zone). plus_option: the text before =, a leading no turns it off, the first three letters
// pick the option as written (tra, nss), the rest compares in any case (+traCE; +TRACE is no option)
const digFollows = (opt) => {
  const cmd = opt.replace(/^=+/, '').split('=')[0];
  if (/^no/i.test(cmd)) return false;
  return (cmd.startsWith('tra') && cmd.length <= 5 && 'trace'.startsWith(cmd.toLowerCase()))
    || (cmd.startsWith('nss') && cmd.length <= 8 && 'nssearch'.startsWith(cmd.toLowerCase()));
};
// host's words as host.c reads them (isc_commandline_parse, POSIX getopt "46aAc:dilnm:p:rst:vVwCDN:R:TUW:": options end at
// the first operand or --): the option letters, the name and the server after it
function hostWalk(args) {
  const letters = [];
  let k = 0;
  for (; k < args.length; k++) {
    const t = args[k];
    if (t === '--') { k++; break; }
    if (t.length < 2 || t[0] !== '-') break;
    for (let p = 1; p < t.length; p++) {
      letters.push(t[p]);
      if ('cmptNRW'.includes(t[p])) { if (p + 1 === t.length) k++; break; }
    }
  }
  return { letters, servers: args.slice(k + 1, k + 2) };
}
// nslookup's words as nslookup.c reads them (parse_args): a word that starts with - and has more is an option (a value is
// attached with =), a lone - asks for interactive mode, the first other word is the name unless - came first, and a word
// after the name or after - is the server. Without a name nslookup is interactive and reads commands from stdin
function nslookupWalk(args) {
  let dash = false, name = null;
  const servers = [];
  for (const t of args) {
    if (t.startsWith('-')) { if (t === '-') dash = true; continue; }
    if (name === null && !dash) name = t; else servers.push(t);
  }
  return { interactive: name === null, servers };
}
// [value, kind] pairs (toolTargets, dnsServers) -> { hosts, bad }: the hosts they name, and the first one the check cannot read
function pairHosts(t) {
  const hosts = [];
  let bad = '';
  for (const [value, kind] of t) {
    if (kind === 'bad') { bad = bad || value; continue; }
    for (const s of targetHostStrings(value, kind)) {
      const h = (kind === 'host' && /\/\d{1,2}$/.test(s)) || kind === 'range' ? { host: s } : hostOf(s);
      if (h.bad) bad = bad || h.bad; else hosts.push(h.host);
    }
  }
  return { hosts, bad };
}
// one segment -> null (a program whose targets the gate does not read) or { hosts, bad }: the hosts its targets name, and
// the first target it cannot read; the same for the DNS server a client is told to ask
function segmentTargets(program, args) { const t = toolTargets(program, args); return t ? pairHosts(t) : null; }
function segmentServers(program, args) { const t = dnsServers(program, args); return t ? pairHosts(t) : null; }

// ---- what makes a read-only HTTP tool, curl, wget or netcat more than a read -------------------------------------------
const HTTP_TOOLS = new Set(['curl', 'wget', 'httpx', 'whatweb', 'wafw00f', 'gobuster', 'ffuf', 'feroxbuster', 'dirb', 'dirbuster', 'wfuzz',
  'nikto', 'testssl.sh', 'sslscan', 'sslyze']);
// a header that turns a GET into a write on frameworks that honour it
const METHOD_OVERRIDE = /x-(http-)?method(-override)?\s*:/i;
const isReadMethods = (v) => v !== null && v !== '' && v.split(',').every((m) => READ_METHOD.test(m.trim()));
// fed: something writes to the program's stdin (a pipe, a here-string, a heredoc, a < file other than /dev/null)
const stdinFed = (seg) => seg.pipedIn || seg.procSub || seg.words.some((w) => (w.redir === 'in' && pdFold(w.text) !== '/dev/null')
  || w.redir === 'herestr' || w.redir === 'heredoc' || w.redir === 'heredocBody');
// curl options whose value stays on the runner: the output format (-w) and the files it writes (-o, --stderr, -D)
const CURL_LOCAL = ['-w', '--write-out', '-o', '--output', '--stderr', '-D', '--dump-header'];
// the words of curl's that reach the wire: every word but the values of CURL_LOCAL (a line break in -w is only output)
const curlSent = (args) => { const w = walkOpts(args, OPT_SPECS.curl); return w.operands.concat(w.opts.flatMap(([n, v]) => (CURL_LOCAL.includes(n) ? [n] : [n, v ?? '']))); };
// curl --proto-redir: does the redirect set it leaves hold a scheme other than http, https, ftp or ftps. curl starts from
// those four (tool_getparam.c redir_protos) and reads the value left to right (tool_paramhlp.c proto2num): comma-separated
// names or all, case-insensitive, each after modifiers + (add, the default), - (remove), = (only this; the last modifier
// counts). Which other names are protocols depends on the build, so another name with + or = counts as widening, and so
// does a form curl refuses (another modifier, no value).
function curlProtoRedirWidens(value) {
  if (value === null) return true;
  const four = ['http', 'https', 'ftp', 'ftps'], set = new Set(four);
  let other = false;
  for (const token of value.split(',').filter(Boolean)) {
    const m = /^([=+-]*)([A-Za-z0-9][\s\S]*)$/.exec(token);
    if (!m) return true;
    const action = m[1] ? m[1][m[1].length - 1] : '+', name = m[2].toLowerCase();
    if (name === 'all') { if (action === '-') { set.clear(); other = false; } else { four.forEach((p) => set.add(p)); other = true; } }
    else if (four.includes(name)) { if (action === '-') set.delete(name); else { if (action === '=') { set.clear(); other = false; } set.add(name); } }
    else if (action === '=') { set.clear(); other = true; } else if (action === '+') other = true;
  }
  return other;
}
function toolEscape(program, args, seg) {
  const tool = toolOf(program);
  // sqlmap copies -H, --headers, --referer, --host and -A as given (a local request logger saw two header lines)
  if (tool === 'sqlmap' && args.some((t) => /[\r\n]/.test(t))) return 'sqlmap argument with a line break (CR or LF smuggles a header or a second request)';
  if (HTTP_TOOLS.has(tool)) {
    if ((tool === 'curl' ? curlSent(args) : args).some((t) => /[\r\n]/.test(t))) return `${program} argument with a line break (CR or LF smuggles a header or a second request)`;
    if (args.some((t) => METHOD_OVERRIDE.test(t))) return `${program} method-override header (X-HTTP-Method-Override, X-HTTP-Method, X-Method-Override turn a GET into a write)`;
  }
  if (tool === 'curl') {
    const w = walkOpts(args, OPT_SPECS.curl);
    if (optHas(w, ['--engine'])) return 'curl --engine loads an OpenSSL engine (a shared library)';
    if (optHas(w, ['--unix-socket', '--abstract-unix-socket'])) return 'curl --unix-socket talks to a local socket on the runner, not the target';
    if (optHas(w, ['--alt-svc'])) return 'curl --alt-svc connects to hosts from a cache file or named by the target';
    if (optHas(w, ['--location-trusted'])) return 'curl --location-trusted sends the credentials to any host a redirect names';
    if (optHas(w, ['-Q', '--quote', '--ftp-alternative-to-user'])) return 'curl -Q/--quote or --ftp-alternative-to-user sends raw FTP or SFTP commands (DELE, RMD, SITE)';
    if (optHas(w, ['-P', '--ftp-port'])) return 'curl -P/--ftp-port opens a port on the runner that the target connects back to (active FTP)';
    // a PROXY protocol header with this client address: the backend logs and authorizes the request as coming from it
    if (optHas(w, ['--haproxy-clientip'])) return 'curl --haproxy-clientip claims another client address in a PROXY protocol header (a spoofed source the backend trusts)';
    if (optValues(w, ['-H', '--header', '--proxy-header']).some((v) => v.startsWith('@')) || optValues(w, ['--url-query']).some((v) => /^[^=+]*@/.test(v)))
      return 'curl -H @file or --url-query @file (headers or query text from a file or stdin the gate cannot see)';
    if (optHas(w, ['--variable']) || args.some((t) => /^--expand-/i.test(t)) || optValues(w, ['--url']).some((v) => v.startsWith('@')))
      return 'curl --variable/--expand or --url @file (URLs, hosts or text from a file, stdin or the environment)';
    const urls = w.operands.concat(optValues(w, ['--url']));
    const scheme = (u) => (/^([A-Za-z][A-Za-z0-9+.-]*):\/{1,3}/.exec(u) || [])[1];
    if (urls.some((u) => (scheme(u) ? !/^(https?|ftps?)$/i.test(scheme(u)) : /^(dict|ldap|imap|smtp|pop3)\./i.test(u.replace(/^[^\/@]*@/, ''))))
      || optValues(w, ['--proto-default']).some((v) => !/^(https?|ftps?)$/i.test(v))
      || w.opts.some(([n, v]) => n === '--proto-redir' && curlProtoRedirWidens(v)))
      return 'curl URL with a scheme other than http, https, ftp or ftps (gopher, dict, telnet, file, smtp, ipfs ...), or --proto-default/--proto-redir';
  }
  if (tool === 'wget') {
    const w = walkOpts(args, OPT_SPECS.wget);
    if (optHas(w, ['--use-askpass']) || pdLong(args, ['use-askpass'])) return 'wget --use-askpass runs a program for the user name and password';
    if (pdLong(args, ['plugin', 'local-plugin', 'plugin-dirs'])) return 'wget2 --plugin/--local-plugin/--plugin-dirs loads a shared library';
    if (optHas(w, ['-i', '--input-file'])) return 'wget -i (URLs from a file or stdin the gate cannot see)';
    if (optHas(w, ['-b', '--background'])) return 'wget -b/--background detaches from the runner and keeps running after the command returns';
    if (optHas(w, ['--no-passive-ftp'])) return 'wget --no-passive-ftp opens a port on the runner that the target connects back to (active FTP)';
    if ((pdCluster(args, program, 'rmp') || optHas(w, ['-r', '-m', '-p', '--recursive', '--mirror', '--page-requisites']))
      && (pdCluster(args, program, 'H') || optHas(w, ['-H', '--span-hosts']))) return 'wget -r/-m/-p with -H/--span-hosts fetches from every host the pages link to';
  }
  if (tool === 'nc' || tool === 'ncat') {
    const w = walkOpts(args, OPT_SPECS[tool]);
    if (optHas(w, ['-U', '--unixsock', '--vsock'])) return 'netcat on a Unix or vsock socket talks to a local daemon on the runner, not the target (-U, --unixsock, --vsock)';
    const quiet = optHas(w, ['-z']) || (tool === 'nc' && optHas(w, ['-d'])) || (tool === 'ncat' && optHas(w, ['--recv-only']));
    if (optHas(w, ['--send-only']) || (!quiet && stdinFed(seg)))
      return 'netcat that sends what it reads from stdin to the target (a pipe, a here-string, a heredoc, a < file, --send-only)';
  }
  if (tool === 'httpx') {
    // Ubuntu's python3-httpx installs /usr/bin/httpx, a general HTTP client: a body, a write method or a download
    const py = (names) => args.some((t, i) => names.includes(t.replace(/=.*$/, '')) && (t.includes('=') || (i + 1 < args.length && !args[i + 1].startsWith('-'))));
    if (py(['-c', '--content', '-d', '--data', '-f', '--files', '-j', '--json', '--download'])
      || args.some((t, i) => /^(-m|--method)(=|$)/.test(t) && (t.includes('=') ? !READ_METHOD.test(t.slice(t.indexOf('=') + 1))
        : i + 1 < args.length && !args[i + 1].startsWith('-') && !READ_METHOD.test(args[i + 1]))))
      return `${program} with -m, -c, -d, -f, -j or --download (the Python httpx client: a write method, a body or a file)`;
    // Go's flag package sets a flag once per occurrence, in order, so the last -duc decides: -duc -duc=false checks for updates
    const taken = goTaken(args, HTTPX_BOOL);
    const duc = taken.filter(([n]) => n === 'duc' || n === 'disable-update-check').pop();
    if (!duc || /^(0|f|F|false|FALSE|False)$/.test(duc[1] ?? '')) {
      return `${program} without -duc checks for updates at api.pdtm.sh (traffic to a host the command does not name)`;
    }
    if (goOn(args, ['up', 'update'])) return `${program} -update replaces its own binary`;
    if (goOn(args, ['hc', 'health-check'])) return `${program} -health-check connects to scanme.sh`;
    if (goOn(args, ['pd', 'dashboard', 'pdu', 'dashboard-upload', 'aid', 'asset-id', 'aname', 'asset-name', 'tid', 'team-id', 'auth', 'ac', 'auth-config']))
      return `${program} -dashboard, -auth or -asset-* uploads results to cloud.projectdiscovery.io`;
    if (goOn(args, ['asn'])) return `${program} -asn asks a third-party ASN API`;
    if (goOn(args, ['tls-probe', 'csp-probe'])) return `${program} -tls-probe/-csp-probe probes the hosts named in the certificate or the CSP header`;
    if (goOn(args, ['pa', 'probe-all-ips']) || goValues(args, ['r', 'resolvers']).some((v) => !v.split(',').every((x) => /^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(x))))
      return `${program} -probe-all-ips or -resolvers that are not IP addresses (every IP of a name, DNS servers from a file)`;
    if (goOn(args, ['ss', 'screenshot', 'system-chrome', 'ho', 'headless-options', 'jsc', 'javascript-code']))
      return `${program} -screenshot runs a headless browser (it downloads Chromium and runs the page's JavaScript and given flags)`;
    if (goOn(args, ['hae', 'http-api-endpoint'])) return `${program} -http-api-endpoint opens a listening API socket on the runner`;
    if (args.some((t) => /^--?(rdb|result-db)[\w-]*(=|$)/.test(t))) return `${program} -result-db writes results to a database host from the environment or a config file`;
    if (goOn(args, ['rr', 'request', 'sf', 'secret-file', 'resume', 'l', 'list']) || (stdinFed(seg) && !goOn(args, ['no-stdin'])))
      return `${program} -request, -secret-file, -resume, -list or stdin (requests, secrets or targets from a file or stdin)`;
    if (goValues(args, ['x']).some((v) => !isReadMethods(v)) || goValues(args, ['body']).length)
      return `${program} -x with a method other than GET, HEAD, OPTIONS, TRACE or PROPFIND, or -body`;
    // the page classifier (runner.go dit.New) downloads its model from huggingface.co at startup; -favicon fetches the icon
    // URLs a page names, on any host (HandleFaviconHash)
    if (goOn(args, ['kb', 'knowledge-base', 'fep', 'filter-error-page']) || goValues(args, ['fpt', 'filter-page-type']).length)
      return `${program} -kb, -fpt or -fep downloads a page classifier model from huggingface.co`;
    if (goOn(args, ['favicon'])) return `${program} -favicon fetches the icon URLs the page names, on any host`;
    // a host name target is resolved through httpx's own resolvers, 1.1.1.1, 1.0.0.1, 8.8.8.8 and 8.8.4.4 after the system's
    // (fastdialer DefaultResolvers; retryabledns asks Cloudflare first); only -r replaces them, and -r is scope-checked
    const names = goValues(args, ['u', 'target']).flatMap((x) => x.split(',')).filter((v) => !/^(\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?|as\d+)$/i.test(v))
      .flatMap(urlHosts).filter((h) => !/^\d{1,3}(\.\d{1,3}){3}$/.test(h));
    if (names.length && !taken.some(([n]) => n === 'r' || n === 'resolvers'))
      return `${program} with a host name target and no -r asks 1.1.1.1 and 8.8.8.8 to resolve it (third-party resolvers; -r with in-scope resolvers keeps the lookups in the lab)`;
  }
  if (tool === 'ffuf') {
    if (goValues(args, ['X']).some((v) => !READ_METHOD.test(v))) return 'ffuf -X with a method other than GET, HEAD, OPTIONS, TRACE or PROPFIND (or a fuzz keyword)';
    if (goValues(args, ['d', 'data', 'data-ascii', 'data-binary']).length) return 'ffuf -d/-data sends a request body';
    if (args.some((t) => /^--?(pre|post)flight(-[\w-]+)?(=|$)/.test(t))) return 'ffuf -preflight/-postflight sends raw requests from a file before or after each request';
    if (goValues(args, ['request']).length) return 'ffuf -request (method, host, headers and body from a file)';
    const keys = ['FUZZ'].concat(goValues(args, ['w']).filter((v) => v.includes(':')).map((v) => v.slice(v.lastIndexOf(':') + 1)).filter(Boolean));
    if (goValues(args, ['u']).some((u) => fuzzedHost(u, (a) => keys.some((k) => a.includes(k))))) return 'ffuf -u with a fuzz keyword in the scheme or host part (the wordlist picks the host)';
  }
  if (tool === 'gobuster') {
    const { mode, w } = gobusterWalk(args);
    // tftp only sends read requests (gobustertftp ProcessWord: tftp Client.Receive, an RRQ per word)
    if (!['dir', 'vhost', 'fuzz', 'dns', 'tftp'].includes(mode)) return `gobuster ${mode.slice(0, 20) || '(no mode)'}: only dir, vhost, fuzz, dns and tftp read the target (s3 and gcs query third-party cloud storage)`;
    if (optValues(w, ['-m', '--method']).concat(goValues(args, ['method'])).some((v) => !READ_METHOD.test(v)) || optHas(w, ['-B', '--body']) || goValues(args, ['body']).length)
      return 'gobuster -m with a method other than GET, HEAD, OPTIONS, TRACE or PROPFIND, or -B/--body';
    if (mode === 'fuzz' && optValues(w, ['-u', '--url']).concat(goValues(args, ['url'])).some((u) => fuzzedHost(u, (a) => a.includes('FUZZ'))))
      return 'gobuster fuzz -u with FUZZ in the scheme or host part (the wordlist picks the host)';
  }
  if (tool === 'feroxbuster') {
    const w = walkOpts(args, OPT_SPECS.feroxbuster);
    if (optHas(w, ['-U', '--update'])) return 'feroxbuster --update replaces its own binary';
    if (!optHas(w, ['-q', '--quiet', '--silent'])) return 'feroxbuster without -q or --silent checks for updates at api.github.com';
    if (optValues(w, ['-m', '--methods']).some((v) => !READ_METHOD.test(v)) || optHas(w, ['--data', '--data-json', '--data-urlencoded']))
      return 'feroxbuster -m with a method other than GET, HEAD, OPTIONS, TRACE or PROPFIND, or --data';
    if (optHas(w, ['--burp', '--burp-replay'])) return 'feroxbuster --burp sends its traffic to a proxy at 127.0.0.1:8080';
    if (optHas(w, ['--request-file', '--stdin', '--resume-from'])) return 'feroxbuster --request-file, --stdin or --resume-from (host, method, body or targets from a file or stdin)';
    // it joins each word to the URL the WHATWG way, so a word \\host\x names another host: system wordlists only. A value is
    // a comma list of wordlists (parser.rs use_value_delimiter), and one that starts with http is downloaded (main.rs)
    if (optValues(w, ['-w', '--wordlist']).flatMap((v) => v.split(',')).some((p) => !/^\/usr\/share\/(wordlists|seclists|dirb|dirbuster|wfuzz)\//.test(p) || /(^|\/)\.\.(\/|$)/.test(p)))
      return 'feroxbuster wordlist outside /usr/share/wordlists, seclists, dirb, dirbuster or wfuzz (a word like \\\\host\\x reaches another host)';
  }
  if (tool === 'wfuzz') {
    const w = walkOpts(args, OPT_SPECS.wfuzz);
    if (optValues(w, ['-X']).some((v) => !READ_METHOD.test(v)) || optHas(w, ['-d'])) return 'wfuzz -X with a method other than GET, HEAD, OPTIONS, TRACE or PROPFIND (or a fuzz keyword), or -d';
    if (optHas(w, ['--prefilter']) || optValues(w, ['--slice', '--filter', '--field', '--efield']).some((v) => /:=|=\+|=-/.test(v)))
      return 'wfuzz --prefilter or a filter that assigns (:=, =+, =-) rewrites the request before it is sent';
    if (optHas(w, ['--AAA', '--script-args'])) return 'wfuzz --AAA or --script-args (discovery scripts follow links to other hosts)';
    const payloads = optValues(w, ['-z']).map((v) => v.split(',')[0].trim().toLowerCase());
    if (payloads.some((p) => !['file', 'list', 'range', 'hexrange', 'hexrand', 'permutation', 'names', 'buffer_overflow'].includes(p)))
      return 'wfuzz -z payload that searches a third-party service or reads requests, files or stdin the gate cannot see';
    const urls = w.operands.concat(optValues(w, ['-u']));
    if (urls.some((u) => !/^https?:\/\//i.test(u))) return 'wfuzz URL with a scheme other than http or https (gopher, dict ...) or a payload in its place';
    if (urls.some((u) => fuzzedHost(u, (a) => /FUZ\d*Z/.test(a)))) return 'wfuzz URL with a fuzz keyword in the host part (the wordlist picks the host)';
  }
  if (tool === 'whatweb') {
    const w = walkOpts(args, OPT_SPECS.whatweb);
    if (optValues(w, ['-p', '--plugins']).some((v) => !/^[+-]?[A-Za-z0-9_-]+(,[+-]?[A-Za-z0-9_-]+)*$/.test(v)))
      return 'whatweb -p/--plugins with a path (loads Ruby code from a file or a directory)';
    if (optHas(w, ['--custom-plugin'])) return 'whatweb --custom-plugin runs Ruby code';
    if (optValues(w, ['-g', '--grep']).some((v) => !/^[A-Za-z0-9 _.,:=-]+$/.test(v))) return 'whatweb -g/--grep with a quote, #, slash, bracket or backslash (the pattern is evaluated as Ruby)';
    if (w.opts.some(([n]) => /^--log-(el|mo)/.test(n))) return 'whatweb --log-elastic/--log-mongo sends the results to a database host';
    if (w.opts.some(([n]) => /^--url-(p|s)/.test(n))) return 'whatweb --url-prefix/--url-suffix/--url-pattern rewrites the targets';
    if (optHas(w, ['-i', '--input-file'])) return 'whatweb -i (targets from a file)';
  }
  if (tool === 'wafw00f') {
    const w = walkOpts(args, OPT_SPECS.wafw00f);
    if (optHas(w, ['-H', '--headers'])) return 'wafw00f -H/--headers (headers from a file the gate cannot see)';
    if (optHas(w, ['-i', '--input-file'])) return 'wafw00f -i (targets from a file)';
  }
  if (tool === 'nikto') return 'nikto sends write requests (PUT, DELETE, POST) and attack payloads by default; no form of it is read-only';
  if (tool === 'testssl.sh') {
    const w = walkOpts(args, OPT_SPECS['testssl.sh']);
    if (optHas(w, ['--phone-out'])) return `${program} --phone-out contacts the CRL, OCSP and pwnedkeys hosts the certificate names`;
    if (optHas(w, ['--mx', '--mx465', '--mx587'])) return `${program} --mx tests the mail servers of the domain (hosts from DNS)`;
    if (optValues(w, ['--proxy']).includes('auto')) return `${program} --proxy auto (a proxy from the environment)`;
    if (optHas(w, ['--openssl'])) return `${program} --openssl runs another openssl binary`;
    if (optHas(w, ['--file', '-iL'])) return `${program} --file (targets from a file)`;
  }
  if (tool === 'sslyze') {
    const w = walkOpts(args, OPT_SPECS.sslyze);
    if (optHas(w, ['--update_trust_stores'])) return 'sslyze --update_trust_stores downloads and replaces its trust stores';
    if (optHas(w, ['--targets_in'])) return 'sslyze --targets_in (targets from a file)';
  }
  if (tool === 'sslscan' && args.some((t) => /^--targets(=|$)/.test(t))) return 'sslscan --targets (targets from a file)';
  if (tool === 'dirb' && args.includes('-resume')) return 'dirb -resume resumes a saved session (its URL and options)';
  if (tool === 'dirbuster' && !args.includes('-H')) return 'dirbuster without -H starts the GUI, which checks for updates at sittinglittleduck.com';
  return '';
}
// a URL whose scheme or host part a fuzz keyword can replace: no literal http:// or https:// with a keyword-free host
const fuzzedHost = (u, keyed) => { const m = /^https?:\/\/([^\/]*)/i.exec(u); return !m || keyed(m[1]); };

// ---- the SMB, RPC, LDAP, SNMP and NFS clients, the scanners, arp and ss: what makes them more than a read ---------------
// smbclient's commands: every name in commands[] (source3/client/client.c, master; 4.19 lacks mkfifo), which process_tok
// matches exactly or by a unique prefix, case-insensitive (ren is rename, sc is scopy, WDEL is wdel), and the ones that
// only read or set a local option. Every other command waits: archive (levels 2 and 3 reset the archive bit after get),
// tar and tarmode (a and reset reset it), more (runs $PAGER), open (asks for write access), lock, unlock and logon, and the
// writes cancel chmod chown del deltree hardlink link md mkdir mkfifo mput posix_mkdir posix_open posix_rmdir posix_unlink
// print put rd rename reput rm rmdir scopy setea setmode symlink utimes wdel.
const SMB_COMMANDS = ('? .. allinfo altname archive backup blocksize cancel case_sensitive cd chmod chown close del deltree dir du echo exit get '
  + 'geteas getfacl hardlink help history iosize l lcd link listconnect lock logoff logon lowercase ls mask md mget mkdir mkfifo more mput newer '
  + 'notify open posix posix_encrypt posix_mkdir posix_open posix_rmdir posix_unlink posix_whoami print prompt put pwd q queue quit rd readlink '
  + 'recurse reget rename reput rm rmdir scopy setea setmode showacls showconnect stat symlink tar tarmode tcon tdis tid timeout translate '
  + 'unlock utimes volume vuid wdel').split(' ');
const SMB_READ = wordSet('? help allinfo altname cd .. dir ls l du get mget reget getfacl geteas stat readlink volume queue pwd notify showacls '
  + 'posix_whoami listconnect showconnect echo history prompt recurse mask lowercase lcd newer iosize timeout blocksize case_sensitive translate '
  + 'backup posix posix_encrypt exit quit q logoff tcon tdis tid vuid close');
// one smbclient command line -> the command it runs: the first token as next_token_talloc reads it (blanks split, double
// quotes join and go), resolved like process_tok; '' for an empty line, null when unknown or ambiguous (nothing runs then,
// and the gate waits all the same)
function smbCommand(line) {
  let i = 0, tok = '', q = false;
  while (i < line.length && ' \t\n\r'.includes(line[i])) i++;
  if (i >= line.length) return '';
  for (; i < line.length && (q || !' \t\n\r'.includes(line[i])); i++) if (line[i] === '"') q = !q; else tok += line[i];
  const t = tok.toLowerCase();
  if (SMB_COMMANDS.includes(t)) return t;
  const hits = SMB_COMMANDS.filter((c) => c.startsWith(t));
  return hits.length === 1 ? hits[0] : null;
}
// one smbclient command line -> its tokens, read the same way (get "my notes.txt" local.txt)
const smbTokens = (line) => [...String(line).matchAll(/(?:"[^"]*"?|[^\s"]+)+/g)].map((m) => m[0].replace(/"/g, ''));
// rpcclient's commands that only read (151 of the 258 names in the 4.19 and master tables, source3/rpcclient/cmd_*.c),
// matched exactly and case-insensitively like process_cmd. The others write (setuserinfo2, createdomuser, netsharedel,
// lsaaddacctrights, shutdowninit, change_trust_pw, dswriteaccountspn, ...), have side effects on the target (logonctrl,
// samlogon, rffpcnex and printercmp make it call back or connect out, eventlog_backuplog, fss_create_expose) or return
// secrets the way sqlmap --passwords does (querysecret, retrieveprivatedata, dsgetncchanges, and lsaquerytrustdominfo with
// info class 4 prints the trust password: cmd_lsarpc.c display_trust_dom_info_4); ntsvcs_hwprofflags sends action 0 (get).
const RPC_READ = wordSet('help ? list exit quit debuglevel debug sign seal packet schannel schannelsign timeout transport none lsaquery lookupsids '
  + 'lookupsids3 lookupsids_level lookupnames lookupnames4 lookupnames_level enumtrust enumprivs getdispname lsaenumsid lsaenumprivsaccount '
  + 'lsaenumacctrights lsalookupprivvalue lsaquerysecobj getusername dsroledominfo dscracknames dsgetdcinfo queryuser querygroup queryusergroups '
  + 'queryuseraliases querygroupmem queryaliasmem queryaliasinfo querydispinfo querydispinfo2 querydispinfo3 querydominfo enumdomusers enumdomgroups '
  + 'enumalsgroups enumdomains samlookupnames samlookuprids samquerysecobj getdompwinfo getusrdompwinfo lookupdomain getdispinfoidx enumdata enumdataex '
  + 'enumkey enumjobs getjob enumports enumdrivers enumprinters getdata getdataex getdriver getdriverdir getdriverpackagepath getprinter openprinter '
  + 'openprinter_ex getprintprocdir getform enumforms enumprocs enumprocdatatypes enummonitors getcoreprinterdrivers enumpermachineconnections '
  + 'winspool_asyncopenprinter winspool_asynccoreprinterdriverinstalled getanydcname getdcname dsr_getdcname dsr_getdcnameex dsr_getdcnameex2 '
  + 'dsr_getsitename gettrustrid dsr_enumtrustdom dsenumdomtrusts netrenumtrusteddomains netrenumtrusteddomainsex getdcsitecoverage srvinfo netshareenum '
  + 'netshareenumall netsharegetinfo netfileenum netremotetod netnamevalidate netfilegetsec netsessenum netdiskenum netconnenum dfsversion dfsgetinfo '
  + 'dfsenum dfsenumex echoaddone echodata sourcedata epmmap epmlookup wkssvc_wkstagetinfo wkssvc_getjoininformation wkssvc_enumeratecomputernames '
  + 'wkssvc_enumerateusers ntsvcs_getversion ntsvcs_validatedevinst ntsvcs_hwprofflags ntsvcs_hwprofinfo ntsvcs_getdevregprop ntsvcs_getdevlistsize '
  + 'ntsvcs_getdevlist eventlog_readlog eventlog_numrecord eventlog_oldestrecord eventlog_loginfo winreg_enumkey winreg_enumval querymultiplevalues '
  + 'querymultiplevalues2 fss_is_path_sup fss_get_sup_version fss_has_shadow_copy fss_get_mapping getinterfacelist clusapi_open_cluster '
  + 'clusapi_get_cluster_name clusapi_get_cluster_version clusapi_get_quorum_resource clusapi_create_enum clusapi_create_enumex clusapi_open_resource '
  + 'clusapi_get_resource_state clusapi_get_cluster_version2 fetch_properties fetch_attributes getpwuid uidtosid');
// one rpcclient command -> its name: the first word as poptParseArgvString reads it (blanks split; ' and " quote and go; a
// backslash escapes the next character, inside quotes only the quote)
function rpcCommand(cmd) {
  let i = 0, out = '', q = '';
  while (i < cmd.length && ' \t\n\v\f\r'.includes(cmd[i])) i++;
  for (; i < cmd.length; i++) {
    const c = cmd[i];
    if (q) { if (c === q) q = ''; else if (c === '\\' && i + 1 < cmd.length) { i++; if (cmd[i] !== q) out += '\\'; out += cmd[i]; } else out += c; continue; }
    if (' \t\n\v\f\r'.includes(c)) break;
    if (c === '"' || c === "'") q = c; else if (c === '\\') { if (i + 1 < cmd.length) out += cmd[++i]; } else out += c;
  }
  return out.toLowerCase();
}
// a getopt short-option cluster: does one of `letters` stand as an option in a one-dash word, before the first letter that
// takes a value (`values`, `optional`: the rest of the word, or the next word, is that value). Every word counts, a value
// that looks like an option too: stricter than getopt.
const clusterHas = (args, letters, values, optional = '') => args.some((t) => {
  if (!/^-[^-]/.test(t)) return false;
  for (let p = 1; p < t.length; p++) { if (letters.includes(t[p])) return true; if (values.includes(t[p]) || optional.includes(t[p])) return false; }
  return false;
});
// smbmap's argparse options (smbmap.py 1.10.x main()): the short letters that take a value (-r takes one optionally), the
// long names (1: a value, 2: two values, '+': values up to the next option, 0: none), unique prefixes allowed
const SMBMAP_SHORT_VALUE = 'HupsdPxgAF', SMBMAP_SHORT_FLAG = 'kvLqh';
const SMBMAP_LONG = { 'host-file': 1, username: 1, password: 1, prompt: 0, kerberos: 0, 'no-pass': 0, 'dc-ip': 1, version: 0, signing: 0, admin: 0,
  'no-banner': 0, 'no-color': 0, 'no-update': 0, timeout: 1, mode: 1, 'list-dir-timeout': 1, csv: 1, 'dir-only': 0, 'no-write-check': 0, depth: 1,
  exclude: '+', 'search-path': 1, 'search-timeout': 1, download: 1, upload: 2, delete: 1, skip: 0, help: 0 };
// does smbmap skip listing shares, and with it the write check: -v/--version, --signing or --download PATH, read the way
// argparse reads them (clusters such as -qv, unique prefixes such as --sig, =value). False whenever a word cannot be
// read that way (argparse then refuses to run, and the write check is required all the same).
function smbmapListsNoShares(args) {
  let skip = false;
  const value = (k) => (k < args.length && !(args[k].length > 1 && args[k].startsWith('-')) ? args[k] : null);
  for (let k = 0; k < args.length; k++) {
    const t = args[k];
    if (t.startsWith('--')) {
      const eq = t.indexOf('='), name = longName(eq < 0 ? t.slice(2) : t.slice(2, eq), SMBMAP_LONG), kind = name ? SMBMAP_LONG[name] : -1;
      if (kind === -1 || ((kind === 0 || kind === 2) && eq >= 0)) return false;
      if (kind === 0) { if (name === 'version' || name === 'signing') skip = true; continue; }
      if (kind === 1) {
        const v = eq >= 0 ? t.slice(eq + 1) : value(++k);
        if (v === null) return false;
        if (name === 'download' && v !== '') skip = true;
        continue;
      }
      if (kind === 2) { k += 2; continue; }
      if (eq < 0) while (value(k + 1) !== null) k++;
      continue;
    }
    if (t.length < 2 || !t.startsWith('-')) return false;
    for (let p = 1; p < t.length; p++) {
      const c = t[p];
      if (SMBMAP_SHORT_FLAG.includes(c)) { if (c === 'v') skip = true; continue; }
      if (SMBMAP_SHORT_VALUE.includes(c)) { if (p + 1 === t.length && value(++k) === null) return false; break; }
      if (c === 'r') { if (p + 1 === t.length && value(k + 1) !== null) k++; break; }
      return false;
    }
  }
  return skip;
}
function reconEscape(program, args, seg) {
  const tool = toolOf(program);
  if ((tool === 'smbclient' || tool === 'rpcclient') && optHas(walkOpts(args, OPT_SPECS[tool]), ['-R', '--name-resolve'])) {
    return `${tool} -R/--name-resolve picks how names resolve (wins and bcast reach hosts the command does not name)`;
  }
  // Kerberos asks a KDC that krb5.conf or the DNS SRV records of the realm name, never the command (-k, a --use-kerberos
  // other than off, --use-krb5-ccache; a local krb5.conf naming the KDC sent an AS-REQ there)
  if ((tool === 'smbclient' || tool === 'rpcclient') && (optHas(walkOpts(args, OPT_SPECS[tool]), ['-k', '--kerberos', '--use-krb5-ccache'])
    || walkOpts(args, OPT_SPECS[tool]).opts.some(([n, v]) => n === '--use-kerberos' && !/^(off|no|false|disabled)$/i.test(v || '')))) {
    return `${tool} with Kerberos (-k, --use-kerberos, --use-krb5-ccache) asks a KDC that krb5.conf or DNS SRV records name, a host the command does not name`;
  }
  if (tool === 'smbclient') {
    const w = walkOpts(args, OPT_SPECS.smbclient);
    if (optHas(w, ['-M', '--message'])) return 'smbclient -M/--message sends a WinPopup message to the host (its text from stdin)';
    if (optHas(w, ['-B', '--browse'])) return 'smbclient -B/--browse looks for servers by multicast DNS (hosts the command does not name)';
    // -T c backs a share up into a local tar file; x restores files onto the share, a resets their archive bits, F reads
    // the list of files from a local file (clitar.c tar_parse_args)
    if (optValues(w, ['-T', '--tar']).some((v) => !/^c[IXbgNnvr]*$/.test(v))) return 'smbclient -T/--tar other than a backup (x restores onto the share, a resets archive bits, F reads names from a file)';
    // the commands it runs: -c in every spelling (popt: -c v, -cv, -c=v, -Nc v, --command v, also an abbreviated --comm, which
    // popt refuses), here-strings and heredoc bodies; -c splits at ;, stdin at line breaks, the gate at both
    const cmds = optValues(w, ['-c']).concat(pdLongValues(args, 'command').filter((v) => v !== null),
      seg.words.filter((x) => x.redir === 'herestr' || x.redir === 'heredocBody').map((x) => x.text));
    for (const line of cmds.flatMap((c) => c.split(/[;\n]/))) {
      if (line.trimStart().startsWith('!')) return 'smbclient command that runs a local shell (!)';
      const name = smbCommand(line);
      if (name !== '' && !SMB_READ.has(name)) {
        return `smbclient command outside the read-only list (${(name || line.trim().split(/\s+/)[0]).slice(0, 30)}): it can change the share, reset archive bits, open files for writing, lock them or run a pager`;
      }
    }
  }
  if (tool === 'rpcclient') {
    const w = walkOpts(args, OPT_SPECS.rpcclient);
    const cmds = optValues(w, ['-c']).concat(pdLongValues(args, 'command').filter((v) => v !== null));
    for (const c of cmds.flatMap((x) => x.split(/[;\n]/))) {
      const name = rpcCommand(c);
      if (name && !RPC_READ.has(name)) return `rpcclient command outside the read-only list (${name.slice(0, 30)}): it can change the domain, a share or a service, or return secrets`;
    }
  }
  if (tool === 'smbmap') {
    // unless --no-write-check (or a unique prefix argparse takes, --no-w on), smbmap creates and deletes a directory, else a
    // file, named with 10 random letters on every share it lists (smbmap.py 1.10.8, 1047-1075). It lists shares unless
    // -v/--version, --signing or --download (or -x, -L, --upload, --delete, -F, which wait anyway) is given (line 1570)
    if (!args.some((t) => t.startsWith('--no-w') && 'no-write-check'.startsWith(t.slice(2))) && !smbmapListsNoShares(args)) {
      return 'smbmap without --no-write-check creates and deletes a directory on every share it lists (its write check)';
    }
    if (pdLetter(args, 'L') || pdLetter(args, 'F') || pdLong(args, ['mode'])) return 'smbmap -L, -F or --mode runs commands on the host (fsutil and net use, or PowerShell, over WMI or psexec)';
    if (pdLong(args, ['host-file'])) return 'smbmap --host-file (targets from a file)';
    if (clusterHas(args, 'k', SMBMAP_SHORT_VALUE, 'r') || pdLong(args, ['kerberos'])) return 'smbmap -k/--kerberos asks a KDC for tickets (the one --dc-ip names, or one DNS names, and the realms it refers to)';
  }
  if (tool === 'enum4linux' && pdLetter(args, 'A')) return 'enum4linux -A creates and removes a directory on every share it can map (its write check)';
  if (tool === 'enum4linux-ng' && optHas(walkOpts(args, OPT_SPECS['enum4linux-ng']), ['-K'])) {
    return 'enum4linux-ng -K authenticates with Kerberos (a KDC that krb5.conf or DNS SRV records name, a host the command does not name)';
  }
  if (tool === 'ldapsearch') {
    const w = walkOpts(args, OPT_SPECS.ldapsearch);
    if (optHas(w, ['-C'])) return 'ldapsearch -C follows referrals to any server the target names';
    if (optHas(w, ['-f'])) return 'ldapsearch -f reads search filters from a file or stdin the gate cannot see';
    // -o sets any ldap.conf option (common.c: ldap_pvt_conf_option); nettimeout and ldif_wrap (ldif-wrap) are its own
    if (optValues(w, ['-o']).some((v) => !/^(nettimeout|ldif_wrap)$/i.test(v.split('=')[0].replace(/-/g, '_')))) return 'ldapsearch -o with an ldap.conf option other than nettimeout or ldif_wrap';
    // without -x it binds with SASL unless -D names a DN and no SASL option is given (common.c tool_args): GSSAPI, -Y's or
    // the one the server offers first, asks a Kerberos KDC
    if (!optHas(w, ['-x']) && (optHas(w, ['-Y', '-U', '-R', '-X', '-O', '-Q', '-I']) || !optHas(w, ['-D']))) {
      return 'ldapsearch with a SASL bind (no -x): GSSAPI asks a Kerberos KDC that krb5.conf or DNS SRV records name (-x binds simply)';
    }
  }
  // snmpwalk -Y "token value" and --token=value set snmp.conf directives: includeFile, alias, defaultPort, clientaddr, ...
  if (tool === 'snmpwalk') {
    const w = walkOpts(args, OPT_SPECS.snmpwalk);
    if (optHas(w, ['-Y']) || w.opts.some(([n]) => n.startsWith('--') && !/^--(help|version)$/i.test(n))) return 'snmpwalk -Y or --name=value sets snmp.conf directives the gate cannot see (includeFile, alias, ...)';
  }
  if (tool === 'rpcinfo' && optHas(walkOpts(args, OPT_SPECS.rpcinfo), ['-b', '-d'])) return "rpcinfo -b broadcasts to the local network, -d deletes a registration from the runner's rpcbind";
  // the passive-source aggregators send the domain to third-party services, with API keys from a file the gate cannot see:
  // theHarvester's -b sources (search engines, crt.sh, Shodan, ...; api-keys.yaml), amass's data sources and public
  // resolvers (its config's keys), subfinder's passive sources (provider-config.yaml). None of them reads only the target
  if (tool === 'theharvester') return 'theHarvester sends the domain to third-party services (search engines, crt.sh, Shodan, ...) with API keys from a file the gate cannot see; no form of it is read-only';
  if (tool === 'amass') return 'amass sends the domain to third-party data sources and public DNS resolvers with API keys from a config the gate cannot see; no form of it is read-only';
  if (tool === 'subfinder') return 'subfinder sends the domain to third-party passive sources with API keys from a provider config the gate cannot see; no form of it is read-only';
  // dnsenum scrapes Google (-s/--scrap) and asks whois servers about the networks it finds (-w/--whois) only when told to;
  // --enum turns both on (dnsenum.pl 1.2.4: Getopt::Long, one or two dashes, any case, unique prefixes)
  if (tool === 'dnsenum' && (pdAbbrev(args, 'enum', 2, true) || pdAbbrev(args, 'scrap', 1, true) || pdAbbrev(args, 'whois', 1, true))) {
    return 'dnsenum --enum, -s/--scrap or -w/--whois asks Google and whois servers (third parties the command does not name)';
  }
  // dnsenum transfers the zone from every NS host the answer names (dnsenum:374 zonetransfer, unconditional) and sends its
  // reverse lookups to them; fierce transfers the zone from the SOA master and moves its resolver to the servers a referral
  // names (fierce.py zone_transfer, query), in every run
  if (tool === 'dnsenum') return 'dnsenum transfers the zone from every NS host DNS answers name and sends its reverse lookups to them; no form of it is read-only';
  if (tool === 'fierce') return 'fierce transfers the zone from the SOA master DNS answers name and follows referrals to the servers they name; no form of it is read-only';
  // dig -f reads lookups from a file or stdin, each with its own @server and +options; +trace and +nssearch ask the servers
  // DNS answers name (dighost.c followup_lookup); host -C asks every NS of the zone; nslookup without a name is interactive
  // and reads commands from stdin, where server and lserver move later lookups to any host (nslookup.c)
  if (tool === 'dig' && digWalk(args).batch) return 'dig -f reads lookups from a file or stdin, each with its own @server and +options (servers the gate cannot see)';
  if (tool === 'dig' && digWalk(args).plus.some(digFollows)) return 'dig +trace or +nssearch asks the servers DNS answers name (the root and TLD servers, every NS of the zone)';
  if (tool === 'host' && hostWalk(args).letters.includes('C')) return 'host -C asks every NS of the zone, at the addresses DNS answers name';
  if (tool === 'nslookup' && nslookupWalk(args).interactive) return 'nslookup without a name is interactive: it reads commands from stdin, and server or lserver moves later lookups to any host';
  // dnsrecon (cli.py): the standard enumeration asks every NS address the answer names about recursion and its BIND version
  // unless both checks are off; -a, -z, -t axfr and zonewalk transfer or walk the zone at the NS and SOA addresses; -s and
  // -t tld resolve names the command does not spell; -b, -y, -k, -w and -t bing, yand, crt ask third parties. -t is read in
  // any case, as a comma list, every value of it for the types that wait. argparse keeps the last -t and the last -r, and
  // dnsrecon skips an empty one (cli.py: if type_arg, if arguments.range): with neither it runs std (-t '', -t=, -r '')
  if (tool === 'dnsrecon') {
    const w = walkOpts(args, OPT_SPECS.dnsrecon), tv = optValues(w, ['-t', '--type']), rv = optValues(w, ['-r', '--range']);
    const types = tv.flatMap((v) => v.trim().toLowerCase().split(',')), unset = (vals) => !vals.length || vals[vals.length - 1] === '';
    if (optHas(w, ['-b', '-y', '-k', '-w']) || types.some((t) => ['bing', 'yand', 'crt'].includes(t))) {
      return 'dnsrecon -b, -y, -k, -w or -t bing, yand or crt asks Bing, Yandex, crt.sh or whois servers (third parties the command does not name)';
    }
    if (optHas(w, ['-a', '-z']) || types.some((t) => ['axfr', 'zonewalk'].includes(t))) return 'dnsrecon -a, -z or -t axfr or zonewalk transfers or walks the zone at the NS and SOA addresses DNS answers name';
    if (optHas(w, ['-s']) || types.includes('tld')) return 'dnsrecon -s or -t tld resolves names the command does not spell (the SPF record\'s include: domains and ranges, the domain under every TLD)';
    if ((types.includes('std') || (unset(tv) && unset(rv)))
      && !(optHas(w, ['--disable_check_recursion']) && optHas(w, ['--disable_check_bindversion']))) {
      return 'dnsrecon std (the default) asks every NS address DNS answers name about recursion and its BIND version, unless --disable_check_recursion and --disable_check_bindversion are both given';
    }
  }
  // traceroute -A looks up the AS of every hop at whois.radb.net, or $RA_SERVER (as_lookups.c)
  if (tool === 'traceroute' && optHas(walkOpts(args, OPT_SPECS.traceroute), ['-A', '--as-path-lookups'])) return 'traceroute -A/--as-path-lookups asks whois.radb.net (or $RA_SERVER) about every hop, a third party';
  if (tool === 'nbtscan' && clusterHas(args, 'f', 'tbsmf')) return 'nbtscan -f (targets from a file or stdin)';
  if (tool === 'onesixtyone' && clusterHas(args, 'i', 'ciopw')) return 'onesixtyone -i (targets from a file)';
  if (tool === 'onesixtyone' && clusterHas(args, 'c', 'ciopw')) return 'onesixtyone -c guesses community strings from a list (like nmap brute scripts)';
  if (tool === 'ike-scan') {
    const w = longOnlyWalk(args, IKE_SHORT, IKE_LONG);        // getopt_long_only: -sourceip, -readpkt and prefixes count too
    if (clusterHas(args, 'f', 'fsdrtBiblzmeapInygGOcLZECDSjk', 'oTP') || pdLong(args, ['file'])) return 'ike-scan -f/--file (targets from a file or stdin)';
    if (pdLong(args, ['sourceip']) || optHas(w, ['--sourceip'])) return 'ike-scan --sourceip spoofs the source address (the replies go to that host or to random ones)';
    if (optHas(w, ['--readpktfromfile'])) return 'ike-scan --readpktfromfile sends a packet read from a file the gate cannot see';
  }
  if (tool === 'fping' && (clusterHas(args, 'f', 'bBcCHiIkOpQrStxXf') || pdLong(args, ['file']))) return 'fping -f (targets from a file or stdin)';
  if (tool === 'arp' && (clusterHas(args, 'dsf', 'AHpit') || pdLong(args, ['delete', 'set', 'file']))) return "arp -d, -s or -f changes the runner's ARP cache";
  if (tool === 'ss' && (clusterHas(args, 'K', 'fADFN') || pdLong(args, ['kill']))) return 'ss -K/--kill closes sockets on the runner';
  // nmap scans what scripts find with --script-args newtargets (snmp-interfaces, a default script, adds the addresses it
  // reads), and reads script arguments from a file with --script-args-file
  if ((tool === 'nmap' || tool === 'rustscan') && (args.some((t) => /newtargets/i.test(t)) || args.some((t) => /^--?script-args-f/i.test(t)))) {
    return 'nmap --script-args newtargets or --script-args-file (hosts scripts discover, arguments from a file)';
  }
  // nmap's own words (rustscan hands it those after --): -D decoys (RND: random ones) and -S spoof the source address and
  // --spoof-mac the hardware address, so replies go to other hosts; --data and --data-string send the payload they are
  // given, to UDP services too (--data-length only pads); --ip-options can route through other hosts. getopt_long_only:
  // one dash and unique prefixes count
  // read through nmapWalk too: getopt_long_only takes -sp for --spoof-mac and -ip for --ip-options, and -nD is -n -D
  const nmapWords = tool === 'nmap' ? args : tool === 'rustscan' && args.includes('--') ? args.slice(args.indexOf('--') + 1) : [];
  if (nmapWords.some((t) => /^-[DS]/.test(t) || /^--?data(=|$)/.test(t)) || ['spoof-mac', 'ip-options'].some((n) => pdAbbrev(nmapWords, n, 3))
    || pdAbbrev(nmapWords, 'data-string', 6) || nmapWalk(nmapWords).opts.some(([n]) => ['-D', '-S', '--spoof-mac', '--data', '--data-string', '--ip-options'].includes(n)))
    return 'nmap -D, -S, --spoof-mac, --data, --data-string or --ip-options (spoofed sources, payloads it is given, routes through other hosts)';
  // the idle scan sends its probes to the target with the zombie's address as their source (idle_scan.cc), like -S
  if (nmapWalk(nmapWords).opts.some(([n]) => n === '--sI')) return "nmap -sI (the idle scan forges the zombie's address as the source of its probes)";
  // script arguments point default scripts at hosts the command does not name: upnp-info with override=false fetches the
  // LOCATION URL the target's SSDP reply names (upnp.lua), http-open-proxy makes an open proxy fetch proxy.url
  if (nmapWalk(nmapWords).opts.some(([n]) => n === '--script-args')) return 'nmap --script-args (script arguments point default scripts at hosts the command does not name: upnp-info override=false, proxy.url)';
  // masscan's option names ignore case, -, . and _ (main-conf.c EQUALS) and take =value, :value or the next word: it reads
  // options and targets from files (-c, --conf, --includefile, --resume), runs exploit checks (--heartbleed, --ticketbleed,
  // --vuln), sends the payloads and HTTP requests it is given (--hello-string, --hello-file, --nmap-payloads,
  // --pcap-payloads, --http-method, --http-payload, ...) and spoofs its source or gateway (--source-ip, --spoof-mac, --router-mac)
  if (tool === 'masscan') {
    const names = args.filter((t) => t.startsWith('--')).map((t) => t.slice(2).split(/[=:[]/)[0].replace(/[-._]/g, '').toLowerCase());
    if (args.some((t) => /^-c/.test(t)) || names.some((n) => ['conf', 'config', 'includefile', 'resume'].includes(n))) return 'masscan -c, --conf, --includefile or --resume (options or targets from a file)';
    // --http-user-agent (and its alias --http-useragent) only sets the User-Agent of its banner GET (SET_http_user_agent),
    // copied as given: a CR or LF in it would add header lines, so it waits then
    if (names.some((n) => /^(heartbleed|ticketbleed|vuln|hello|nmappayload|pcappayload)/.test(n) || (n.startsWith('http') && n !== 'httpuseragent'))
      || (names.includes('httpuseragent') && args.some((t) => /[\r\n]/.test(t)))) return 'masscan --heartbleed, --vuln, --hello-* or --http-* (exploit checks, payloads and requests it is given)';
    if (names.some((n) => /^(adapterip|sourceip|sourceaddress|spoof|srcip|adaptermac|sourcemac|router)/.test(n))) return 'masscan --source-ip, --spoof-mac or --router-mac spoofs its source or gateway (replies go elsewhere)';
    // --script loads and runs a Lua file (scripting.c: luaL_loadfile, lua_pcall); --nmap-service-probes reads the probes its
    // banner checks send from a file (nmapserviceprobes_read_file)
    if (names.includes('script')) return 'masscan --script runs a Lua file (code the gate cannot see)';
    if (names.some((n) => n.startsWith('nmapserviceprobe'))) return 'masscan --nmap-service-probes reads the probes it sends from a file the gate cannot see';
  }
  // rustscan -a reads an entry that is no address and does not resolve as a file of targets (address.rs): only addresses,
  // networks, ranges and dotted names that are no file name (hosts.txt, 10.10.10.5.txt) auto-run
  if (tool === 'rustscan') {
    const own = args.includes('--') ? args.slice(0, args.indexOf('--')) : args;
    if (rustscanEntries(own).some(rustscanFileLike)) return 'rustscan -a with a file name or an entry the gate cannot read (rustscan reads targets from a file it names)';
    // it appends the words after -- to its nmap command line and runs that line with sh -c (main.rs: command.join(" ");
    // scripts/mod.rs execute_script, 2.3 and later): sh reads them again, so a blank, a quote or a shell character in one
    // runs commands on the runner (-- ';' id runs id) or splits it into other words. Only plain words auto-run
    if (args.includes('--') && args.slice(args.indexOf('--') + 1).some((t) => !/^[A-Za-z0-9_.,:=+@%\/-]+$/.test(t))) {
      return 'rustscan runs the words after -- through sh -c (a blank, a quote or a shell character in them runs commands on the runner)';
    }
  }
  return '';
}
// rustscan's -a entries (-a v, -av, -a=v, -ga v, --addresses v, comma-separated), and whether one is a file to it
const rustscanEntries = (own) => own.flatMap((t, i) => { const m = /^-[gn]*a([\s\S]*)$/.exec(t); return !m ? [] : m[1] ? [m[1].replace(/^=/, '')] : i + 1 < own.length ? [own[i + 1]] : []; })
  .concat(pdLongValues(own, 'addresses').filter((v) => v !== null).map((v) => v.replace(/^=/, ''))).flatMap((v) => v.split(','));
const rustscanFileLike = (e) => !/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2}|-\d{1,3}(\.\d{1,3}){3})?$/.test(e)
  && !(/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(e) && !FILE_EXT.has(e.slice(e.lastIndexOf('.') + 1).toLowerCase()) && !/\.\d+$/.test(e));

// nmap's options (nmap.cc: getopt_long_only with "46Ab:D:d::e:Ffg:hIi:M:m:nO::o:P::p:qRrS:s::T:Vv::" and long_options[]):
// the short letters that take a value, those that take one only attached, and every long name (1: a value, 2: an optional
// one, only attached, 0: none). A one-dash word of two or more letters, or of one letter that is no short option, is a long
// name first, exact or a unique prefix (-sI zombie, -sp is --spoof-mac, -oA base), else short letters (-sV, -Pn, -p-, -T4,
// -nD RND); an ambiguous or unknown name makes nmap refuse to run; -- ends the options.
const NMAP_SHORT = { value: 'bDegiMmopST', optional: 'dOPsv', all: '46Ab:D:d::e:Ffg:hIi:M:m:nO::o:P::p:qRrS:s::T:Vv::'.replace(/:/g, '') };
const NMAP_LONG = Object.fromEntries([
  ...('datadir servicedb versiondb max-os-tries max-parallelism min-parallelism timing max-rtt-timeout min-rtt-timeout initial-rtt-timeout '
    + 'excludefile exclude max-hostgroup min-hostgroup scanflags host-timeout scan-delay max-scan-delay max-retries oA oN oM oG oS oH oX iL iR sI '
    + 'source-port nsock-engine proxies proxy data data-string data-length stylesheet mtu spoof-mac ttl version-intensity dns-servers port-ratio '
    + 'exclude-ports top-ports script script-args script-args-file script-help script-timeout ip-options min-rate max-rate stats-every route-dst '
    + 'resume').split(' ').map((n) => [n, 1]),
  ['debug', 2],
  ...('version verbose help iflist release-memory nogcc open defeat-rst-ratelimit defeat-icmp-ratelimit randomize-hosts discovery-ignore-rst '
    + 'osscan-limit osscan-guess fuzzy packet-trace version-trace send-eth send-ip no-stylesheet webxml rH vv ff privileged unprivileged '
    + 'append-output noninteractive thc badsum traceroute reason allports version-light version-all system-dns resolve-all unique log-errors '
    + 'deprecated-xml-osclass yoloscan script-trace script-updatedb adler32 disable-arp-ping').split(' ').map((n) => [n, 0]),
]);
// getopt_long_only's reading of a tool's words (nmap, ike-scan) -> { opts: [[name, value or null]], operands }; name is '-x'
// for a short letter, '--name' for a long name. short: { value, optional, all } letters; long: { name: 1 a value, 2 an
// optional one (only attached), 0 none }
function longOnlyWalk(args, short, longTable) {
  const opts = [], operands = [];
  const long = (given) => {                                       // the name, null when ambiguous, '' when none
    if (Object.prototype.hasOwnProperty.call(longTable, given)) return given;
    const hits = Object.keys(longTable).filter((n) => n.startsWith(given));
    return hits.length === 1 ? hits[0] : hits.length ? null : '';
  };
  for (let k = 0; k < args.length; k++) {
    const t = args[k];
    if (t === '--') { operands.push(...args.slice(k + 1)); break; }
    if (t.length < 2 || t[0] !== '-') { operands.push(t); continue; }
    const two = t[1] === '-', body = t.slice(two ? 2 : 1);
    if (two || body.length > 1 || !short.all.includes(body)) {
      const eq = body.indexOf('='), name = long(eq < 0 ? body : body.slice(0, eq));
      if (name) {
        let v = eq < 0 ? null : body.slice(eq + 1);
        if (v === null && longTable[name] === 1 && k + 1 < args.length) v = args[++k];
        opts.push(['--' + name, longTable[name] ? v : null]);
        continue;
      }
      if (two || name === null || !short.all.includes(body[0])) { opts.push([t, null]); continue; }
    }
    for (let p = 1; p < t.length; p++) {
      const c = t[p], rest = p + 1 < t.length ? t.slice(p + 1) : null;
      if (short.value.includes(c)) { opts.push(['-' + c, rest !== null ? rest : k + 1 < args.length ? args[++k] : null]); break; }
      if (short.optional.includes(c)) { opts.push(['-' + c, rest]); break; }
      opts.push(['-' + c, null]);
    }
  }
  return { opts, operands };
}
function nmapWalk(args) { return longOnlyWalk(args, NMAP_SHORT, NMAP_LONG); }
// one nmap operand -> a target value and kind: a network, a range (nmap's octet form 10.10.10.5-254, 10.10.10.*, or two
// addresses), a host (hostOf reads it); a mask on a name or a range cannot be read
function nmapTarget(v) {
  if (expansionWhy(v)) return [expansionWhy(v), 'bad'];
  if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(v)) return [v, 'host'];
  if ((/^[\d,*-]+(\.[\d,*-]+){3}$/.test(v) && /[-,*]/.test(v)) || IP_RANGE.test(v)) {
    const r = ipRanges(v);
    return r.length === 1 ? [r[0], 'range'] : [`a range the scope check cannot read (${v.slice(0, 40)})`, 'bad'];
  }
  if (v.includes('/')) return [`a network mask on a name or a range (${v.slice(0, 40)}): nmap scans the whole network around it`, 'bad'];
  return [v, 'host'];
}
function nmapTargets(args, out) {
  const w = nmapWalk(args);
  for (const [n, v] of w.opts) {
    if (n === '--iL' || n === '-i') out.push(['a target list file (-iL, -i): nmap reads its targets from the file instead', 'bad']);
    // -iR N scans N random internet hosts and ignores the operands (nmap.cc generate_random_ips); decide() blocks it too
    else if (n === '--iR') out.push(['random targets (-iR): nmap scans random internet hosts instead', 'bad']);
    else if (v !== null && (n === '--sI' || n === '-b')) out.push(expansionWhy(v) ? [expansionWhy(v), 'bad'] : [v, 'hostport']);   // zombie[:port], [user[:pass]@]server[:port]
    else if (v !== null && n === '--dns-servers') for (const s of v.split(',')) out.push(expansionWhy(s) ? [expansionWhy(s), 'bad'] : [s, 'host']);
  }
  // --proxies (--proxy) takes a chain of scheme://host:port URLs, each asked to relay to the next and the target: the raw-text
  // pass reads every URL's host in it (extractTargets), whatever the host looks like
  for (const v of w.operands) out.push(nmapTarget(v));
}

// every --script value in the raw text (nmap reads -script like --script), without the quotes around it ('default' is
// default); the words bash hands nmap give the rest
const rawScriptValues = (cmd) => [...cmd.matchAll(/(?:^|\s)--?script[=\s]+(["']?)([^"'\s]+)\1/gi)].map((m) => m[2]);

// The raw text cut into commands at line breaks, ; | and &, as the gate cut it before, but not inside quotes or after a
// backslash: bash splits nothing there (a quoted cookie "a=1; b=2", a user agent "(X11; Linux x86_64)", a query ?a=1&b=2).
// Nor does an & that belongs to a redirection: 2>&1, >&2, <&3 and &>file (shellSegments reads them the same way).
// A line break still cuts inside quotes, so a heredoc body reads as commands, stricter than bash.
function rawCommands(cmd) {
  const out = [];
  let cur = '', q = '';
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (c === '\r' || c === '\n') { out.push(cur); cur = ''; continue; }
    const esc = c === '\\' && q !== "'" && i + 1 < cmd.length && cmd[i + 1] !== '\n' && cmd[i + 1] !== '\r';
    if (esc) { cur += c + cmd[++i]; continue; }
    if (q) { if (c === (q === '"' ? '"' : "'")) q = ''; cur += c; continue; }
    const redirect = c === '&' && (cur.endsWith('>') || cur.endsWith('<') || (cmd[i + 1] === '>' && cmd[i - 1] !== '&'));
    if (c === "'") q = cur.endsWith('$') ? '$' : "'";              // $'...' takes backslash escapes, '...' none
    else if (c === '"') q = '"';
    else if ((c === ';' || c === '|' || c === '&') && !redirect) { out.push(cur); cur = ''; continue; }
    cur += c;
  }
  out.push(cur);
  return out.map((x) => x.trim()).filter(Boolean);
}

// ---- one segment writes a file, another loads it: settings, plugins and targets the gate never reads --------------------
// The runner starts every command in a fresh HOME and working directory, but within one command a segment can write a file
// that another one loads (curl -so ~/.curlrc ...; curl ...). These programs load settings, plugins, scripts or targets from
// HOME or the working directory: curl ~/.curlrc, wget ~/.wgetrc, dig ~/.digrc (not with -r), ffuf ~/.config/ffuf/ffufrc,
// httpx ~/.config/httpx/config.yaml, feroxbuster ./ferox-config.toml, whatweb ./whatweb.rb, wfuzz ~/.wfuzz, nmap ~/.nmap
// (scripts, script.db, probe files), rustscan ~/.rustscan.toml, snmpwalk ~/.snmp/snmp.conf, ldapsearch ./ldaprc and
// ~/.ldaprc, less and more ~/.lesskey; whatweb reads a target word that names a file as the page, and rustscan reads
// targets and resolvers from a file the word names (an -a entry that is no address or network, every --resolver value).
// Such a program waits when another segment writes a dotfile or a file in a dot folder, one of those names, the file one
// of those words names, or a file whose name the gate cannot tell (the server names it, a URL glob or a brace expansion
// does, awk writes it, sed reads its script from a file, smbclient fetches it after lcd). Names a program states count as
// written: tee's and the redirections', -o and the like, the w files of a sed script and sed -i's files and backups, nmap's
// output files (% expanded, -oA's three), smbclient get's local name, sort -o, uniq's OUTPUT, less -o, ldapsearch -t's
// directory. The write counts when it can land before the program loads: in a segment before it; in a
// segment after a lone & that ends the program's segment or one between them (the background list, a slow command and
// then the program, runs on while the commands after the & start); and, for nmap and rustscan, in a later member of the
// same pipe (the members start together; nmap opens nmap-service-probes when its service scan starts, after the port
// scan, and rustscan starts nmap after its own scan)
const STAGED_LATE = new Set(['nmap', 'rustscan']);
const STAGED_LOADERS = new Set(['curl', 'wget', 'dig', 'ffuf', 'httpx', 'feroxbuster', 'whatweb', 'wfuzz', 'nmap', 'rustscan', 'snmpwalk', 'ldapsearch', 'less', 'more']);
const STAGED_PATH = /(^|\/)\.[^./\s]|(^|\/)(whatweb\.rb|ferox-config\.toml|ldaprc)$/;
// the file curl -O and wget name after a URL: the last component of its path, as written and percent-decoded
const urlFileNames = (u) => {
  const rest = String(u).replace(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, '').replace(/[?#][\s\S]*$/, ''), path = rest.includes('/') ? rest.slice(rest.indexOf('/')) : '';
  let n = path.slice(path.lastIndexOf('/') + 1);
  const names = [n];
  for (let r = 0; r < 3; r++) n = pdPercentRound(n);
  return names.concat(n);
};
// whether a file written as p can be the file a program opens as the word w, relative to the working directory: the same
// path (./ and doubled slashes do not count: whatweb http://10.10.10.5 opens http:/10.10.10.5), or a path that is
// absolute, under HOME (~/, $HOME/: HOME may be the working directory) or above it (..) and ends in /w. A word that is
// itself absolute or above the working directory names no target the gate reads (whatweb and rustscan wait for it)
const pathKey = (p) => String(p).replace(/^(~|\$\{?HOME\}?)(?=\/|$)/, '/').replace(/\/{2,}/g, '/').replace(/(^|\/)(?:\.\/)+/g, '$1');
const sameFile = (p, w) => {
  const a = pathKey(p), b = pathKey(w), far = (x) => x.startsWith('/') || /(^|\/)\.\.(\/|$)/.test(x);
  return far(a) && !far(b) ? a.endsWith('/' + b) : a === b;
};
// the words whatweb and rustscan open a file by: whatweb's every word (a target that names a file is read as the page:
// target.rb File.exist?), rustscan's -a entries other than an address or a network (it reads a file only for an entry it
// cannot resolve: address.rs) and its --resolver values (read as a file of servers first, whatever they hold)
function stagedNames(tool, args) {
  if (tool === 'whatweb') return args.flatMap((t) => t.split(','));
  if (tool !== 'rustscan') return [];
  const own = args.includes('--') ? args.slice(0, args.indexOf('--')) : args;
  // an address or a network (a.b.c.d/nn with nn above 32 is out of scope) is never a file to it
  return rustscanEntries(own).filter((e) => ipToInt(e.split('/')[0]) === null).concat(pdLongValues(own, 'resolver').filter((v) => v !== null));
}
// nmap's output files: -oN -oG -oM -oS -oX (the old -o and -m), -oA X (X.nmap, X.gnmap, X.xml); - is stdout. nmap expands %
// in a name (output.cc logfilename): %H %M %S %T %R %m %d %y %Y %D %F become the time, any other %x becomes x (-oN %.curlrc
// writes .curlrc, ld%aprc writes ldaprc: a local run of nmap 7.94). -> [{ raw, names, dated }]; a dated name holds 0 for the time
const NMAP_OUT = new Set(['--oN', '--oG', '--oM', '--oS', '--oX', '--oA', '-o', '-m']);
function nmapOutputs(args) {
  const out = [];
  for (const [n, v] of nmapWalk(args).opts) {
    if (!NMAP_OUT.has(n) || v === null || v === '-') continue;
    let name = '', dated = false;
    for (let i = 0; i < v.length; i++) {
      if (v[i] !== '%') name += v[i];
      else if (++i < v.length) { if ('HMSTRmdyYDF'.includes(v[i])) { dated = true; name += '0'; } else name += v[i]; }
    }
    out.push({ raw: v, dated, names: n === '--oA' ? [`${name}.nmap`, `${name}.gnmap`, `${name}.xml`] : [name] });
  }
  return out;
}
// GNU getopt short clusters: the values one letter takes, where the letters in `takes` take the rest of the word or the
// next word (sort -uo FILE, -uoFILE; -to is -t with the value o); -- ends the options
const getoptValues = (args, takes, letter) => {
  const out = [];
  for (let k = 0; k < args.length; k++) {
    const t = args[k];
    if (t === '--') break;
    if (!/^-[^-]/.test(t)) continue;
    for (let p = 1; p < t.length; p++) {
      if (!takes.includes(t[p])) continue;
      const v = p + 1 < t.length ? t.slice(p + 1) : k + 1 < args.length ? args[++k] : null;
      if (t[p] === letter) out.push(v);
      break;
    }
  }
  return out;
};
const LESS_VALUE = 'bDhjkoOpPtTxyz#"';                            // less's options that take a value (opttbl.c)
// uniq [OPTION]... [INPUT [OUTPUT]] (getopt "-0123456789Dcdf:is:uw:z", in order): f s w, --skip-fields, --skip-chars and
// --check-chars take a value, +N before -- skips N characters (uniq.c); the operands are what is left
function uniqOperands(args) {
  const ops = [];
  let opts = true;
  for (let k = 0; k < args.length; k++) {
    const t = args[k];
    if (opts && t === '--') { opts = false; continue; }
    if (opts && t.startsWith('--')) {
      const name = t.slice(2).split('=')[0];
      if (!t.includes('=') && name && ['skip-fields', 'skip-chars', 'check-chars'].some((x) => x.startsWith(name))) k++;
      continue;
    }
    if (opts && /^-./.test(t)) { for (let p = 1; p < t.length; p++) if ('fsw'.includes(t[p])) { if (p + 1 === t.length) k++; break; } continue; }
    if (opts && /^\+\d+$/.test(t)) continue;
    ops.push(t);
  }
  return ops;
}
// wget's switches that keep the files of -r, -m and -p out of the host directory: -n's letters H and d (the rest of the word
// or the next word: -nH, -nHd, -qn H; main.c OPT__NO), --no-host-directories and --no-directories (and so any --no, as
// --no=H, which is a prefix of them), --host-directories or --directories with a value (=off), --delete-after (no_dirstruct)
const wgetFlat = (a) => a.flatMap((t, k) => {
  if (!/^-[^-]/.test(t)) return [];
  for (let p = 1; p < t.length; p++) {
    if (t[p] === 'n') return [p + 1 < t.length ? t.slice(p + 1) : a[k + 1] ?? ''];
    if (PD_VALUE_LETTERS.wget.includes(t[p])) return [];
  }
  return [];
}).some((v) => /[Hd]/.test(v))
  || pdLong(a, ['no-host-directories', 'no-directories', 'delete-after'])
  || a.some((t) => { const m = /^--([\w-]+)=([\s\S]*)$/.exec(t); return !!m && ['host-directories', 'directories'].some((x) => x.startsWith(m[1].toLowerCase())) && !/^(on|yes|1|true)$/i.test(m[2]); });
// one segment -> { paths, unknown, dated }: the files it writes as the program names them, why it writes one the gate cannot
// name ('' if none), and nmap's names with the time in them (they could match any word with digits)
function segmentWrites(s) {
  const tool = toolOf(s.program), a = s.args, paths = [], dated = [];
  let unknown = '';
  // bash expands {a,b} and {1..9} before the program runs: tee ~/{.curlrc,x} writes ~/.curlrc (a local run)
  const braced = s.seg.words.filter((w) => w.unqBrace).map((w) => w.text);
  const add = (raw, names = [raw]) => {
    if (raw && braced.some((b) => b.includes(raw))) unknown = `a name bash brace-expands (${String(raw).slice(0, 30)})`;
    else paths.push(...names);
  };
  for (const w of s.seg.words) if (w.redir === 'out') add(w.text);
  if (tool !== 'nmap') for (const cw of wordClasses(s.seg, new Set()).words) if (cw.kind === 'output file') add(cw.w.text);
  if (s.program === 'tee') for (const t of a) if (!/^-./.test(t)) add(t);
  const nmapWords = tool === 'nmap' ? a : tool === 'rustscan' && a.includes('--') ? a.slice(a.indexOf('--') + 1) : null;
  for (const o of nmapWords ? nmapOutputs(nmapWords) : []) { add(o.raw, o.names); if (o.dated) dated.push(...o.names); }
  if (tool === 'curl') {
    const urls = (toolTargets('curl', a) || []).filter(([, kind]) => kind === 'url').map(([u]) => u);
    const remote = pdCluster(a, 'curl', 'O') || pdLong(a, ['remote-name', 'remote-name-all']);
    if (remote) {
      for (const u of urls) add(u, urlFileNames(u));
      if (pdCluster(a, 'curl', 'J') || pdLong(a, ['remote-header-name'])) unknown = 'curl -J: the server names the file';
    }
    // curl expands {a,b} and [1-9] in a URL unless -g/--globoff: -O names every file after its URL, and #1 in -o stands for
    // the text the first glob matched (curl -o ~/#1 'http://10.10.10.5/{.curlrc}' writes ~/.curlrc, a local run)
    if (!a.includes('-g') && !a.includes('--globoff') && urls.some((u) => /[{[]/.test(u))
      && (remote || pdClusterValues(a, 'curl', 'o').concat(pdLongValues(curlLong(a), 'output')).some((v) => v !== null && /#\d/.test(v)))) {
      unknown = 'curl -O or -o #N with a URL glob: the glob names the file';
    }
  }
  if (tool === 'wget' && !pdLong(a, ['spider']) && !pdClusterValues(a, s.program, 'O').length && !pdLongValues(a, 'output-document').length) {
    // --restrict-file-names=lowercase or uppercase changes the case of every name (LDAPRC is saved as ldaprc)
    const urls = walkOpts(a, OPT_SPECS.wget).operands, cased = pdLong(a, ['restrict-file-names']);
    for (const u of urls) add(u, urlFileNames(u).flatMap((x) => (cased ? [x, x.toLowerCase(), x.toUpperCase()] : [x])));
    // -r, -m and -p save every file under a directory named after its host (10.10.10.5/.curlrc, also for ../.curlrc: a local
    // run of wget 1.21.4), where no loader looks; -nH and -nd keep them in the working directory under the server's names
    if ((pdCluster(a, s.program, 'rmp') || pdLong(a, ['recursive', 'mirror', 'page-requisites'])) && wgetFlat(a)) {
      unknown = 'wget -r, -m or -p with -nH, -nd or --delete-after: names the server gives';
    }
    // -x/--force-directories saves a file under its URL's path (wget 1.21.4, a local run: -x -nH http://h/.config/httpx/config.yaml
    // writes .config/httpx/config.yaml, httpx's settings file when the working directory is HOME); with the host directory
    // kept it lands under 10.10.10.5/, where no loader looks
    if ((pdCluster(a, s.program, 'x') || pdLong(a, ['force-directories'])) && wgetFlat(a)) unknown = 'wget -x with -nH: a path the URL names';
    if (pdLong(a, ['content-disposition', 'trust-server-names'])) unknown = 'wget --content-disposition or --trust-server-names: a name the server gives';
    // a wildcard in an FTP URL fetches every file of the listing it matches (globbing is on unless --no-glob)
    if (!a.includes('--no-glob') && urls.some((u) => /^ftps?:\/\/[^\/]*\/.*[*?[]/i.test(u))) unknown = 'wget FTP wildcard: names the server lists';
  }
  if (tool === 'smbclient') {
    const w = walkOpts(a, OPT_SPECS.smbclient), cmds = optValues(w, ['-c']).concat(pdLongValues(a, 'command').filter((v) => v !== null),
      s.seg.words.filter((x) => x.redir === 'herestr' || x.redir === 'heredocBody').map((x) => x.text));
    if (optHas(w, ['-T', '--tar'])) unknown = 'smbclient -T: a tar file the gate does not read';
    // get REMOTE [LOCAL] writes LOCAL, else REMOTE as typed (client.c cmd_get: lname = fname; - is stdout); lcd moves it,
    // lowercase toggles lowercasing it (do_get: strlower_m)
    let lcd = false, lower = false;
    for (const line of cmds.flatMap((c) => c.split(/[;\n]/))) {
      const cmd = smbCommand(line), tok = smbTokens(line), local = tok.length > 2 ? tok[2] : tok[1];
      if (cmd === 'lcd') lcd = true;
      else if (cmd === 'lowercase') lower = !lower;
      else if (cmd === 'mget' || cmd === 'tar') unknown = 'smbclient mget or tar: names on the share';
      else if ((cmd === 'get' || cmd === 'reget') && local !== undefined && local !== '-') {
        if (lcd) unknown = 'smbclient get after lcd: a file in another directory'; else add(local, lower ? [local, local.toLowerCase()] : [local]);
      }
    }
  }
  if (tool === 'smbmap' && pdLong(a, ['download'])) unknown = 'smbmap --download: a name on the share';
  if (s.program === 'awk' && a.some((t) => t.includes('>'))) unknown = 'awk print >: a file the program names';
  if (s.program === 'sed') for (const p of sedWrites(a)) add(p);
  // sort -o FILE (getopt "-bcCdfghik:mMno:rRsS:t:T:uVy:z": k o S t T y take a value) and --output FILE; uniq's OUTPUT (- is
  // stdout); less and more -o or -O FILE and --log-file or --LOG-FILE FILE
  if (s.program === 'sort') for (const v of getoptValues(a, 'kSoTty', 'o').concat(pdLongValues(a, 'output'))) if (v !== null) add(v);
  if (s.program === 'uniq') { const ops = uniqOperands(a); if (ops.length > 1 && ops[1] !== '-') add(ops[1]); }
  if (s.program === 'less' || s.program === 'more') {
    for (const v of getoptValues(a, LESS_VALUE, 'o').concat(getoptValues(a, LESS_VALUE, 'O'), pdLongValues(a, 'log-file'))) if (v !== null) add(v);
  }
  // ldapsearch -t writes every value to <dir>/ldapsearch-<attr>-XXXXXX (mkstemp), dir from -T, else TMPDIR or /tmp
  if (tool === 'ldapsearch') {
    const w = walkOpts(a, OPT_SPECS.ldapsearch), dirs = optValues(w, ['-T']), dir = dirs.length ? dirs[dirs.length - 1] : '/tmp';
    if (optHas(w, ['-t', '-T'])) add(dir, [`${dir}/ldapsearch-`]);
  }
  return { paths: paths.filter(Boolean), unknown, dated };
}
function stagedConfig(segs) {
  const writes = segs.map(segmentWrites);
  const n = segs.length, bgAt = new Array(n + 1).fill(n), pipeEnd = new Array(n).fill(0);
  for (let k = n - 1; k >= 0; k--) {
    bgAt[k] = segs[k].seg.bg ? k : bgAt[k + 1];                    // the first segment at or after k that a lone & ends
    pipeEnd[k] = k + 1 < n && segs[k + 1].seg.pipedIn ? pipeEnd[k + 1] : k;   // the last member of k's pipe
  }
  for (const [i, s] of segs.entries()) {
    const tool = toolOf(s.program);
    if (!STAGED_LOADERS.has(tool) || (tool === 'dig' && digWalk(s.args).norc)) continue;
    const named = stagedNames(tool, s.args);
    for (const [j, w] of writes.entries()) {
      if (!(j < i || (j > i && (bgAt[i] < j || (STAGED_LATE.has(tool) && j <= pipeEnd[i]))))) continue;   // lands after the load
      const hit = w.unknown || w.paths.find((p) => STAGED_PATH.test(p) || named.some((x) => sameFile(p, x))) || (named.length ? w.dated[0] : '');
      if (hit) return `${s.program} loads settings, plugins or targets from HOME or the working directory, and another part of the command writes one (${String(hit).slice(0, 50)})`;
    }
  }
  return '';
}

function classifyReadOnly(command) {
  const cmd = String(command || '').trim();
  if (!cmd) return { readOnly: false, reason: 'empty command' };
  if (MUTATING_PATTERNS.some((rx) => rx.test(cmd)) || rawSubcommandWrites(cmd)) return { readOnly: false, reason: 'command performs a write/active operation' };
  // the segments as bash reads them, each with its program and the words it gets: quoting hides no option from the checks
  // below ("--script=vuln", nc '-e', awk 'sys''tem('), which also run on the raw text and never relax it
  const segs = shellSegments(cmd).map((seg) => ({ seg, ...pdProgram(seg.words) }));
  // nmap NSE is passive only if EVERY script in EVERY list is default (a lone "default" prefix, or a second --script, must
  // not smuggle in vuln)
  const scripts = rawScriptValues(cmd).concat(segs.filter((s) => s.program === 'nmap' || s.program === 'rustscan').flatMap((s) => pdScriptValues(s.args)));
  if (scripts.some((v) => !v.split(',').map((s) => s.trim().toLowerCase()).every((s) => PASSIVE_NSE.has(s)))) {
    return { readOnly: false, reason: 'nmap NSE beyond default (active-recon tier or human)' };
  }
  // split into segments across line breaks, ; && || and pipes (a shell runs each line as its own command); every segment
  // must be a known read-only tool or local filter
  const segments = rawCommands(cmd);
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
  for (const s of segs) {                                         // the same, on the words bash hands each program
    if (!READONLY_TOOLS.has(s.program) && !FILTER_TOOLS.has(s.program)) {
      return { readOnly: false, reason: `"${s.program || '(empty)'}" is not on the read-only tool allowlist` };
    }
    const esc = execEscape(s.program, s.seg);
    if (esc) return { readOnly: false, reason: esc };
  }
  // every value curl, wget, netcat or an HTTP scanner reads as a target (operands, -u, proxies, --connect-to) must name a
  // host the scope check reads; decide() checks those hosts against the scope
  for (const s of segs) {
    const t = segmentTargets(s.program, s.args);
    if (t && t.bad) return { readOnly: false, reason: `${s.program} target the scope check cannot read: ${t.bad}` };
    if (t && !t.hosts.length) return { readOnly: false, reason: `${s.program} names no target host the gate can check` };
    const d = segmentServers(s.program, s.args);
    if (d && d.bad) return { readOnly: false, reason: `${s.program} server the scope check cannot read: ${d.bad}` };
  }
  // a program that loads settings, plugins or targets from HOME or the working directory, next to a segment that writes one
  const staged = stagedConfig(segs);
  if (staged) return { readOnly: false, reason: staged };
  // the runner's unprivileged user keeps local writes in its working directory: with sudo, output files land anywhere
  if (segs.some((s) => s.seg.words.slice(0, s.k).some((w) => !w.redir && w.text === 'sudo'))) {
    return { readOnly: false, reason: 'sudo runs the program as root (its output files and side effects can land anywhere)' };
  }
  return { readOnly: true, reason: 'passive recon (read-only tools only)' };
}

// ---- active-recon tier (opt-in) --------------------------------------------------------------
// A middle tier between passive recon and "needs a human": active but non-destructive scanning that
// a pentester runs constantly — nmap NSE default, version and banner, and sqlmap in enumerate-only mode at risk 1. Off
// unless LAB_AUTORUN_ACTIVE_RECON=true. Still fail-safe: anything outside these exact shapes returns false.
const SAFE_NSE = new Set(['default', 'version', 'banner']);      // script.db counts at PASSIVE_NSE: safe and discovery wait
const DANGER_NSE = /\b(vuln|exploit|brute|dos|intrusive|malware|fuzzer|external|backdoor)\b/i;
const SQLMAP_ENUM = /--(banner|current-user|current-db|hostname|is-dba|users|dbs|tables|columns|schema|count)\b|(^|\s)-b(\s|$)/i;
const SQLMAP_DANGER = /--(os-shell|os-pwn|os-cmd|sql-shell|sql-query|file-write|file-dest|file-read|reg-add|reg-del|reg-write|dump|dump-all|passwords|eval|udf-inject|priv-esc|crawl)\b/i;

// every --script value nmap gets, in the raw text and as words (args: the words after the program), default, version and
// banner only
function nmapSafeScripts(cmd, args) {
  const raw = rawScriptValues(cmd);
  if (!raw.length) return false;              // no --script => not this tier (plain nmap is passive tier)
  return raw.concat(args ? pdScriptValues(args) : [])
    .every((v) => !DANGER_NSE.test(v) && v.split(',').map((s) => s.trim().toLowerCase()).every((s) => SAFE_NSE.has(s)));
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

// sqlmap options that run or load code, reach hosts the command does not name, submit forms or read commands from a file or
// stdin (their help texts in lib/parse/cmdline.py), in every spelling sqlmapRisky reads; --proxy is its own option, not a
// prefix of --proxy-file
const SQLMAP_ESCAPES = [
  [['alert'], 'sqlmap --alert runs a program on the runner when it finds an injection'],
  [['tamper', 'preprocess', 'postprocess'], 'sqlmap --tamper, --preprocess or --postprocess loads Python scripts (a path loads any file)'],
  [['update'], 'sqlmap --update replaces its own code'],
  [['tor', 'check-tor', 'tor-port', 'tor-type', 'dns-domain', 'proxy-file'],
    'sqlmap --tor, --check-tor, --dns-domain or --proxy-file sends traffic to hosts the command does not name (Tor, check.torproject.org, interactsh, proxies from a file)'],
  [['forms'], 'sqlmap --forms submits every form it finds on the page'],
  [['second-req', 'shell', 'sqlmap-shell', 'wizard'], 'sqlmap --second-req, --shell or --wizard reads a request or commands from a file or stdin'],
  // misc.py cleanup(): stacked DROP TABLE sqlmapfile, sqlmapfilehex, sqlmapoutput and DROP FUNCTION for its UDFs; --batch
  // answers yes
  [['cleanup'], 'sqlmap --cleanup drops tables and functions from the target DBMS (DROP TABLE sqlmapoutput, DROP FUNCTION ...)'],
  // --check-internet fetches www.google.com/generate_204 (checks.py checkInternet); --dork asks DuckDuckGo and Bing
  // (utils/search.py), as -g does; --openapi and --openapi-base take their targets from the servers a fetched document
  // lists; --xxe registers with a public interactsh server (oast.fun, ...) unless --oob-server names one, and has the
  // target call it back
  [['check-internet', 'dork', 'openapi', 'openapi-base', 'openapi-tags', 'xxe', 'oob-server', 'oob-token'],
    'sqlmap --check-internet, --dork, --openapi or --xxe contacts hosts the command does not name (www.google.com, search engines, the servers an OpenAPI document lists, public interactsh servers)'],
  // --auth-refresh imports a Python file and calls its refresh() on a 401 (option.py _setAuthRefreshFunction); --safe-req
  // loads the request it repeats from a file
  [['auth-refresh'], 'sqlmap --auth-refresh loads and runs a Python file'],
  [['safe-req'], 'sqlmap --safe-req loads the request it repeats from a file the gate cannot see'],
];
const sqlmapWords = (words) => words.map((t) => t.replace(/^[‐–−—一 ﹣－]+/, (m) => '-'.repeat(m.length)));
function sqlmapEscape(words) {
  for (const t of sqlmapWords(words)) {
    const m = /^--?([A-Za-z][\w-]*)/.exec(t);
    if (!m || m[1].length < 2) continue;
    const x = m[1].toLowerCase(), hit = SQLMAP_ESCAPES.find(([names]) => names.some((d) => d === x || (d.startsWith(x) && x !== 'proxy') || x.startsWith(d + '-')));
    if (hit) return hit[1];
  }
  return '';
}
// --risk 2 and 3 add heavier time-based and OR-based payloads, and sqlmap's own help warns that the OR payloads can update
// every row of a table: the tier takes --risk only as 1, read in every spelling (--risk 1, --risk=1, --ris 1, -risk 1)
function sqlmapRiskAbove1(words) {
  const n = sqlmapWords(words);
  return n.some((t, i) => {
    const m = /^--?([A-Za-z][\w-]*)(?:=([\s\S]*))?$/.exec(t);
    if (!m || m[1].length < 2 || !'risk'.startsWith(m[1].toLowerCase())) return false;
    const v = m[2] !== undefined ? m[2] : n[i + 1];
    return v === undefined || !/^0*1$/.test(v.trim());
  });
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
  // the one command as bash reads it: its program picks the shape (a --script or --dbs word on another program is none),
  // the passive tier's escapes count here too (nmap --datadir, rustscan custom scripts), and quoting hides no option
  // ('-dump', "--script=vuln"); the raw-text checks stay and never relax this
  const segs = shellSegments(cmd);
  if (segs.length !== 1) return { ok: false, reason: 'not an allowed active-recon shape' };
  const { k, program, args } = pdProgram(segs[0].words);
  const esc = execEscape(program, segs[0]);
  if (esc) return { ok: false, reason: esc };
  // as in the passive tier: the runner's unprivileged user keeps local writes in its working directory, sudo does not
  if (segs[0].words.slice(0, k).some((w) => !w.redir && w.text === 'sudo')) {
    return { ok: false, reason: 'sudo runs the program as root (its output files and side effects can land anywhere)' };
  }
  // as in the passive tier: every host position (nmap's operands, -iL, -iR, sqlmap's URLs, --proxy, --safe-url) must name a
  // host the scope check reads
  const t = segmentTargets(program, args);
  const targetWhy = t && t.bad ? `${program} target the scope check cannot read: ${t.bad}` : t && !t.hosts.length ? `${program} names no target host the gate can check` : '';
  if ((program === 'nmap' || program === 'rustscan') && nmapSafeScripts(cmd, args)) {
    return targetWhy ? { ok: false, reason: targetWhy } : { ok: true, reason: 'nmap NSE, default, version and banner only' };
  }
  if (program === 'sqlmap' && (sqlmapRisky(cmd.split(/\s+/)) || sqlmapRisky(args))) return { ok: false, reason: 'sqlmap option that dumps, searches or reads files' };
  const sqlmapWhy = program === 'sqlmap' ? sqlmapEscape(cmd.split(/\s+/)) || sqlmapEscape(args) : '';
  if (sqlmapWhy) return { ok: false, reason: sqlmapWhy };
  if (program === 'sqlmap' && (sqlmapRiskAbove1(cmd.split(/\s+/)) || sqlmapRiskAbove1(args))) {
    return { ok: false, reason: 'sqlmap --risk 2 or 3 adds heavier and OR-based payloads (sqlmap warns they can update every row of a table)' };
  }
  if (targetWhy) return { ok: false, reason: targetWhy };
  if (program === 'sqlmap' && sqlmapEnumOnly(cmd)) return { ok: true, reason: 'sqlmap enumerate-only' };
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

// a network target (a.b.c.d/N): in scope only when all of it lies inside one allowlist entry and one engagement entry
// (an IP or a CIDR, N at least the entry's prefix length), excluded when any part of it is excluded
const parseNet = (s) => {
  const [ip, b] = String(s).trim().split('/'), n = ipToInt(ip || ''), bits = b === undefined ? 32 : /^\d{1,2}$/.test(b) ? Number(b) : -1;
  return n === null || bits < 0 || bits > 32 ? null : { n, bits };
};
const netMask = (bits) => (bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0);
const netIn = (t, e) => t.bits >= e.bits && ((t.n & netMask(e.bits)) >>> 0) === ((e.n & netMask(e.bits)) >>> 0);
const netMeets = (t, e) => { const b = Math.min(t.bits, e.bits); return ((t.n & netMask(b)) >>> 0) === ((e.n & netMask(b)) >>> 0); };
function netScopeWhy(net, cfg) {
  const t = parseNet(net), list = (l) => (l || []).map(parseNet).filter(Boolean);
  if (!t || !list(cfg.allowlist).some((e) => netIn(t, e))) return 'allowlist';
  if ((cfg.scopeIn || []).length && !list(cfg.scopeIn).some((e) => netIn(t, e))) return 'engagement';
  if (list(cfg.scopeOut).some((e) => netMeets(t, e))) return 'excluded';
  return '';
}
// a range (lo-hi, from ipRanges or fping -g START END) the same way: all of it inside one allowlist entry and one engagement
// entry (a single-IP entry admits only that address), excluded when it meets an excluded entry
function rangeScopeWhy(range, cfg) {
  const [lo, hi] = range.split('-').map(ipToInt);
  const span = (e) => { const n = parseNet(e); if (!n) return null; const a = (n.n & netMask(n.bits)) >>> 0; return [a, a + 2 ** (32 - n.bits) - 1]; };
  const list = (l) => (l || []).map(span).filter(Boolean);
  if (lo === null || hi === null || !list(cfg.allowlist).some(([a, b]) => a <= lo && hi <= b)) return 'allowlist';
  if ((cfg.scopeIn || []).length && !list(cfg.scopeIn).some(([a, b]) => a <= lo && hi <= b)) return 'engagement';
  if (list(cfg.scopeOut).some(([a, b]) => a <= hi && lo <= b)) return 'excluded';
  return '';
}
const hostScopeWhy = (h, cfg) => (h.includes('/') ? netScopeWhy(h, cfg) : IP_RANGE.test(h) ? rangeScopeWhy(h, cfg) : scopeWhy(h, cfg));

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

// The bash subset the gate needs -> [{ words: [{ text, redir, unqBrace }], pipedIn, procSub, bg }]. text is the argument the
// program gets; bg marks a segment that a lone & ends (the commands after it start while its list still runs). redir marks redirection targets: in, out, fd, herestr, heredoc (the delimiter) and heredocBody. It never
// fails: an unterminated quote runs to the end. $(...), ${...} and backticks are copied verbatim (they are unverifiable).
const PD_ANSI_C = new Map([['a', '\x07'], ['b', '\b'], ['e', '\x1b'], ['E', '\x1b'], ['f', '\f'], ['n', '\n'], ['r', '\r'], ['t', '\t'],
  ['v', '\v'], ['\\', '\\'], ["'", "'"], ['"', '"'], ['?', '?']]);
function shellSegments(command) {
  const s = String(command ?? '');
  const segs = [];
  let seg = { words: [], pipedIn: false, procSub: false, bg: false };
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
    seg = { words: [], pipedIn: piped, procSub: false, bg: false };
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
      seg.bg = true; endSeg(false); i++; continue;               // a lone &: what follows runs at the same time
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
// a segment's words -> the program's index, the program and the words it gets (redirections left out)
function pdProgram(words) {
  const k = pdProgramIndex(words);
  return { k, program: k < words.length ? words[k].text.replace(/^.*\//, '').toLowerCase() : '',
    args: words.slice(k + 1).filter((w) => !w.redir).map((w) => w.text) };
}
// every --script value nmap gets as a word: the next word, or the text after = (nmap reads -script like --script)
const pdScriptValues = (args) => args.flatMap((t, i) => (/^--?script$/i.test(t) ? args.slice(i + 1, i + 2)
  : /^--?script=/i.test(t) ? [t.slice(t.indexOf('=') + 1)] : []));

// Word classes. Local programs only read the runner's files and stdout. Options whose value is a local file make that
// value local; identity options (accounts, passwords, domains) make it ignored when it looks like one. A value that names
// a remote place (scheme, UNC path, host:/path, an in-scope host) is data wherever it stands.
const PD_LOCAL_PROGRAMS = FILTER_TOOLS;                           // without xargs, which runs programs
const PD_LOCAL_OPTS = new Map([
  ...['-o', '-O', '--output', '--output-file', '--output-document', '--output-dir', '-od', '-oN', '-oX', '-oG', '-oA', '-oS'].map((o) => [o, 'output file']),
  ...['-w', '--wordlist', '-iL', '-L', '-P', '-C', '--input-file', '--files-from'].map((o) => [o, 'wordlist or input file']),
  ...['-i', '-F', '-K', '--config'].map((o) => [o, 'key or input file'])]);
const PD_ID_OPTS = new Set(['-u', '-U', '--user', '--username', '-l', '--login', '-p', '--password', '--pass', '--hashes', '-hashes', '--domain', '-W', '--workgroup']);
// Per READONLY_TOOLS member (a test pins the list, so a tool that joins it gets reviewed): `none`, the letters of the shared
// tables that take no value in that tool (curl -L follows redirects, nmap -O detects the OS: the next word is not theirs),
// and the tool's own output, input and account options (masscan -oL, testssl.sh --jsonfile, smbmap -d). Letters differ
// between tools (curl -c is a cookie jar it writes, dnsrecon -c a CSV file), so these apply to their tool only.
const PD_OUT = 'output file', PD_IN = 'wordlist or input file', PD_KEY = 'key or input file', PD_ID = 'identity';
const pdTool = (none, kinds = {}) => ({ none, opts: new Map(Object.entries(kinds).flatMap(([kind, opts]) => opts.map((o) => [o, kind]))) });
const PD_TOOL_OPTS = {
  nmap: pdTool('OF'), rustscan: pdTool(''),
  masscan: pdTool('', { [PD_OUT]: ['-oL', '-oJ', '-oB', '-oU', '-oD', '--output-filename', '--pcap'], [PD_IN]: ['--readscan', '--includefile'], [PD_KEY]: ['-c', '--conf'] }),
  ping: pdTool(''), fping: pdTool(''), traceroute: pdTool(''), tracepath: pdTool(''), arp: pdTool(''), host: pdTool(''), dig: pdTool(''),
  nslookup: pdTool(''), whois: pdTool(''),
  dnsrecon: pdTool('w', { [PD_OUT]: ['-x', '--xml', '-c', '--csv', '-j', '--json', '--db'], [PD_IN]: ['-D', '--dictionary'] }),
  dnsenum: pdTool('w', { [PD_OUT]: ['--subfile'], [PD_IN]: ['-f', '--file'] }),
  fierce: pdTool('', { [PD_IN]: ['--subdomain-file', '--dns-file'] }),
  amass: pdTool('', { [PD_OUT]: ['-json', '-dir', '-log'], [PD_IN]: ['-df', '-nf', '-rf', '-blf', '-trf', '-ef', '-if', '-aw'], [PD_KEY]: ['-config'] }),
  subfinder: pdTool('', { [PD_OUT]: ['-output', '-oD', '-output-dir'], [PD_IN]: ['-dL', '-list', '-rL', '-rlist'], [PD_KEY]: ['-config', '-pc', '-provider-config'] }),
  theharvester: pdTool('p', { [PD_OUT]: ['-f', '--filename'] }),
  curl: pdTool('LiOpl', { [PD_OUT]: ['-c', '--cookie-jar', '-D', '--dump-header', '--trace', '--trace-ascii', '--stderr', '--libcurl', '--etag-save'] }),
  wget: pdTool('LFKp', { [PD_OUT]: ['-P', '--directory-prefix', '-a', '--append-output', '--save-cookies', '--warc-file', '--rejected-log'],
    [PD_KEY]: ['--load-cookies'], [PD_ID]: ['--http-user', '--http-password', '--http-passwd', '--ftp-user', '--ftp-password', '--ftp-passwd',
      '--proxy-user', '--proxy-password', '--proxy-passwd'] }),
  httpx: pdTool('', { [PD_OUT]: ['-output', '-srd', '-store-response-dir'], [PD_IN]: ['-l', '-list'], [PD_KEY]: ['-config'] }),
  whatweb: pdTool('', { [PD_OUT]: ['--log-brief', '--log-verbose', '--log-errors', '--log-xml', '--log-json', '--log-json-verbose',
    '--log-magictree', '--log-object', '--log-sql', '--log-sql-create'], [PD_KEY]: ['--cookie-jar'] }),
  wafw00f: pdTool('l', { [PD_KEY]: ['-H', '--headers'] }),
  sslscan: pdTool('', { [PD_OUT]: ['--xml'], [PD_IN]: ['--targets'] }),
  sslyze: pdTool('', { [PD_OUT]: ['--json_out'], [PD_IN]: ['--targets_in'] }),
  'testssl.sh': pdTool('UOLCFPWp', { [PD_OUT]: ['-oL', '--logfile', '-oj', '--jsonfile', '-oJ', '--jsonfile-pretty', '-oC', '--csvfile', '-oH',
    '--htmlfile', '-oa', '--outfile', '--outFile', '--outprefix'], [PD_IN]: ['--file'], [PD_ID]: ['--basicauth'] }),
  gobuster: pdTool('l'),
  ffuf: pdTool('', { [PD_OUT]: ['-debug-log'], [PD_IN]: ['-request'], [PD_KEY]: ['-config'] }),
  feroxbuster: pdTool('', { [PD_OUT]: ['--debug-log'], [PD_IN]: ['--resume-from'] }),
  dirb: pdTool('ilw', { [PD_IN]: ['-x'] }),
  dirbuster: pdTool('', { [PD_OUT]: ['-r'], [PD_IN]: ['-l'] }),
  wfuzz: pdTool('L', { [PD_OUT]: ['-f', '--dump-recipe'], [PD_KEY]: ['--recipe'] }),
  nikto: pdTool('', { [PD_OUT]: ['-output', '--output'], [PD_KEY]: ['-config'], [PD_ID]: ['-id', '--id'] }),
  enum4linux: pdTool('UPloi'),
  'enum4linux-ng': pdTool('UCPOL', { [PD_OUT]: ['-oJ', '-oY'], [PD_IN]: ['-s'] }),
  smbmap: pdTool('L', { [PD_OUT]: ['-g', '--csv'], [PD_IN]: ['--host-file'], [PD_ID]: ['-d'] }),
  smbclient: pdTool('', { [PD_KEY]: ['-A', '--authentication-file'] }),
  ldapsearch: pdTool('LuCW', { [PD_IN]: ['-f'], [PD_KEY]: ['-y'] }),
  rpcclient: pdTool('', { [PD_KEY]: ['-A', '--authentication-file'] }),
  rpcinfo: pdTool(''), showmount: pdTool(''), snmpwalk: pdTool(''),
  onesixtyone: pdTool('', { [PD_IN]: ['-c'] }),
  nbtscan: pdTool('', { [PD_IN]: ['-f'] }),
  'ike-scan': pdTool(''), netstat: pdTool(''), ss: pdTool(''), nc: pdTool(''),
  ncat: pdTool('', { [PD_OUT]: ['-x', '--hex-dump'] }),
};
PD_TOOL_OPTS.wget2 = PD_TOOL_OPTS.wget;
PD_TOOL_OPTS.testssl = PD_TOOL_OPTS['testssl.sh'];                // the Debian and Kali names of testssl.sh and httpx
PD_TOOL_OPTS['httpx-toolkit'] = PD_TOOL_OPTS.httpx;
const pdExclusion = (opt, program) => /^--(exclude|reject)/.test(opt) || opt === '--dont-scan'
  || ((program === 'wget' || program === 'wget2') && (opt === '-X' || opt === '-R'));
const pdOptionKind = (opt, program) => {
  const own = Object.prototype.hasOwnProperty.call(PD_TOOL_OPTS, program) ? PD_TOOL_OPTS[program] : null;
  if (own && own.opts.has(opt)) return own.opts.get(opt);
  if (own && /^-[A-Za-z]$/.test(opt) && own.none.includes(opt[1])) return '';
  return PD_LOCAL_OPTS.get(opt) || (pdExclusion(opt, program) ? 'exclusion' : PD_ID_OPTS.has(opt) ? 'identity' : '');
};
// a short-option cluster in a tool whose value letters are known (curl -sSLo FILE, wget -qO FILE): the position of the
// first letter that takes a value, or -1
const pdClusterAt = (t, program) => {
  let at = -1;
  pdClusterScan(t, program, (c, p) => { if (PD_VALUE_LETTERS[program].includes(c)) { at = p; return true; } return false; });
  return at;
};
const pdHostComponent = (t, hosts) => pdComponents(pdFold(t).replace(/\\/g, '/')).comps.some((c) => hosts.has(c));
const pdRemote = (t, hosts) => /:\/\/|^[\\/]{2}|^[^\s/\\:]+:\//.test(t) || pdHostComponent(t, hosts);
const pdIdentityLike = (t, hosts) => !t.includes('://') && !/^[\\/.~]/.test(t) && (t.match(/[\\/]/g) || []).length <= 1 && !pdHostComponent(t, hosts);
function wordClasses(segment, hosts) {
  const ws = segment.words, { k, program } = pdProgram(ws);
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
      const at = Object.prototype.hasOwnProperty.call(PD_VALUE_LETTERS, program) ? pdClusterAt(t, program) : -1;   // -sSLo file, -qO file
      const clusterKind = at > 0 ? pdOptionKind('-' + t[at], program) : '';
      if (clusterKind && at === t.length - 1) { pending = clusterKind; return words.push({ w, cls: 'ignored' }); }
      if (clusterKind) return words.push(value({ ...w, text: t.slice(at + 1) }, clusterKind));
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
  let cur = '', st = 0, at = [];                                  // at[u]: the character (index in ac) of cur's UTF-16 unit u
  for (let p = 0; p <= ac.length; p++) {
    if (p < ac.length && pdCompChar(ac[p])) {
      if (!cur) { st = p; at = []; }
      for (let q = 0; q < ac[p].length; q++) at.push(p);
      cur += ac[p];
      continue;
    }
    if (!cur) continue;
    // a host is blanked wherever it stands dot-aligned in a component: the whole component, its start (hr.lab.xml), its
    // end (_ldap._tcp.hr.lab, _dmarc.hr.lab) or between dots
    let atStart = false;
    for (const h of hosts) {
      for (let i = cur.indexOf(h); i >= 0; i = cur.indexOf(h, i + 1)) {
        const e = i + h.length;
        if ((i === 0 || cur[i - 1] === '.') && (e === cur.length || cur[e] === '.')) {
          spans.push([at[i], e === cur.length ? p : at[e]]);
          if (i === 0) atStart = true;
        }
      }
    }
    if (atStart && ac[st - 1] === '@') {                          // user@host, DOMAIN/user:pass@host: the user part too
      let b = st - 1;
      while (b > 0 && !/[\s='"]/.test(ac[b - 1]) && !(ac[b - 1] === '/' && ac[b - 2] === '/')) b--;
      spans.push([b, st]);
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
  'dnsrecon', 'dnsenum', 'fierce', 'amass', 'subfinder', 'theharvester', 'sslscan', 'sslyze', 'testssl.sh', 'testssl', 'gobuster',
  'enum4linux', 'enum4linux-ng', 'ldapsearch', 'rpcclient', 'rpcinfo', 'showmount', 'snmpwalk', 'onesixtyone', 'nbtscan',
  'ike-scan', 'netstat', 'ss', 'nc', 'ncat']);
// a one- or two-dash word abbreviating name to at least min letters (Getopt::Long and getopt_long_only accept these)
const pdAbbrev = (args, name, min, anyCase) => args.some((t) => {
  const m = /^--?([A-Za-z][\w-]*)/.exec(t);
  return !!m && m[1].length >= min && name.startsWith(anyCase ? m[1].toLowerCase() : m[1]);
});
// Options that load settings from a file the gate cannot see (wget -e robots=off is the one setting it reads): no auto-run
// with or without protected data. -> the option's label, or ''
function settingsFile(program, args) {
  if (program === 'curl' && (pdCluster(args, program, 'K') || pdLong(curlLong(args), ['config']))) return 'curl -K/--config';
  if (program === 'wget' || program === 'wget2') {
    const exec = pdClusterValues(args, program, 'e').concat(pdLongValues(args, 'execute'));      // -e v, -qe v, --exe=v
    if (pdLong(args, ['config']) || exec.some((v) => v === null || !/^robots\s*=\s*off$/i.test(v.trim()))) return 'wget --config/-e';
  }
  if ((program === 'ffuf' || program === 'httpx' || program === 'httpx-toolkit') && args.some((t) => /^--?config(=|$)/.test(t))) return `${program} -config`;
  if (program === 'nikto' && pdAbbrev(args, 'config', 2, true)) return 'nikto -config';
  if (program === 'wfuzz' && pdLong(args, ['recipe'])) return 'wfuzz --recipe';
  // smb.conf from another file or set option by option (name resolve order, wins server, include = another file); only the
  // protocol range an old server needs (--option='client min protocol=NT1') goes without a human. Samba matches parameter
  // names without regard to case and blanks.
  if (program === 'smbclient' || program === 'rpcclient') {
    const w = walkOpts(args, OPT_SPECS[program]), protocol = (v) => v !== null && /^client(ipc)?(min|max)protocol$/.test(v.split('=')[0].replace(/\s+/g, '').toLowerCase());
    if (optHas(w, ['-s', '--configfile']) || w.opts.some(([n, v]) => n === '--option' && !protocol(v))) return `${program} -s/--configfile or --option (other than the client protocol range)`;
  }
  // a lesskey file's #env section can set LESSOPEN, a program less runs on every file it shows (and on stdin with |-),
  // also when it writes to a pipe (less 590). -k may close a cluster (-Rk); more can be less
  if ((program === 'less' || program === 'more') && (args.some((t) => /^-[^-]*k/.test(t)) || pdLong(args, ['lesskey-file', 'lesskey-src', 'lesskey-content'])))
    return `${program} -k/--lesskey-src`;
  return '';
}
// program, its non-redirect words after the program, the segment's classified words, the in-scope hosts. Options that load
// settings from a file count as names read at run time: settingsFile(), nmap --datadir and --resume, rustscan
// --config-path and custom scripts.
function bulkReasons(program, args, classifiedWords, hosts) {
  const bulk = [], runtime = [];
  const settings = (label) => runtime.push(`${label} (settings the gate cannot see)`);
  if (program === 'wget' || program === 'wget2') {
    if (pdCluster(args, program, 'rmp') || pdLong(args, ['recursive', 'mirror', 'page-requisites'])) bulk.push('wget -r/-m/-p (recursion)');
    if (!args.includes('--no-glob') && args.some((t) => /^ftp:\/\//i.test(t) && /[*?[]/.test(t))) bulk.push('wget FTP wildcard');
    if (pdCluster(args, program, 'i') || pdLong(args, ['input-file'])) runtime.push('wget -i (URLs from a file)');
  }
  if (program === 'curl') {
    // every URL curl gets, with or without a scheme (an in-scope host names one), or after --url
    const urls = args.filter((t) => pdRemote(t, hosts)).concat(pdLongValues(args, 'url').filter((v) => v !== null));
    if (!args.includes('-g') && !args.includes('--globoff') && urls.some((u) => /[[\]{}]/.test(u))) bulk.push('curl URL glob ([...] or {...})');
    if (pdLong(args, ['variable', 'expand-']) || args.some((t) => /^--expand-/i.test(t))) runtime.push('curl --variable/--expand');
    if (pdLongValues(args, 'url').some((v) => v !== null && v.startsWith('@'))) runtime.push('curl --url @file');
  }
  if (program === 'httpx' || program === 'httpx-toolkit') {
    if (args.some((t) => /^--?(l|list|path|request|rr)(=|$)/.test(t))) runtime.push('httpx -l/-path/-request (names from a file)');
  }
  if ((program === 'whatweb' || program === 'wafw00f') && (pdLetter(args, 'i') || pdLong(args, ['input-file', 'input']))) {
    runtime.push(`${program} -i (URLs from a file)`);
  }
  if (program === 'nikto' && pdAbbrev(args, 'save', 2, true)) bulk.push('nikto -Save (keeps responses)');
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
  }
  if (program === 'wfuzz') {
    if (pdLetter(args, 'R')) bulk.push('wfuzz -R (recursion)');
    if (pdLong(args, ['field', 'efield'])) bulk.push('wfuzz --field/--efield (prints responses)');
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
    if (pdScriptValues(args).some((v) => v.split(',').some((x) => !PD_NSE_OK.has(x.trim().toLowerCase())))) bulk.push('nmap NSE beyond default, version and banner');
    if (args.some((t) => /^--?script-args/.test(t))) bulk.push('nmap --script-args');
    if (pdAbbrev(args, 'datadir', 5) || pdAbbrev(args, 'resume', 3)) settings('nmap --datadir/--resume');
  }
  if (program === 'rustscan') {
    const own = args.includes('--') ? args.slice(0, args.indexOf('--')) : args;            // after -- the words go to nmap
    if (pdLetter(own, 'c') || pdLong(own, ['config-path']) || pdLongValues(own, 'scripts').some((v) => v !== 'none' && v !== 'default')) {
      settings('rustscan --config-path/--scripts');
    }
  }
  const cfg = settingsFile(program, args);
  if (cfg) settings(cfg);
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
      const { args } = pdProgram(s.seg.words);
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
      // wget names the file it writes after the URL unless -O names it, and so does curl -O: a URL ending in a dotfile
      // (http://h/.wgetrc) writes that dotfile, into the working directory or wherever -P points
      const fromUrl = s.program === 'curl' ? pdCluster(args, 'curl', 'O') || pdLong(args, ['remote-name', 'remote-name-all'])
        : (s.program === 'wget' || s.program === 'wget2') && !pdClusterValues(args, s.program, 'O').length && !pdLongValues(args, 'output-document').length;
      if (fromUrl) {
        for (const u of args.filter((t) => !t.startsWith('-') && pdRemote(t, hosts))) {
          let name = u.replace(/[?#].*$/, '').replace(/\/+$/, '');
          name = name.slice(name.lastIndexOf('/') + 1);
          for (let round = 0; round < 3; round++) name = pdPercentRound(name);
          if (/^\.[^./\s]/.test(name)) runtime.push(`writes a dotfile that can change later commands (${name.slice(0, 30)})`);
        }
      }
      // the server names the file instead (curl -J with -O, wget --content-disposition or --trust-server-names follows the
      // header or the redirect): no URL shows that name, and it can be a dotfile too
      if (fromUrl && (s.program === 'curl' ? pdCluster(args, 'curl', 'J') || pdLong(args, ['remote-header-name'])
        : pdLong(args, ['content-disposition', 'trust-server-names']))) runtime.push('the server names the file it writes (it can be a dotfile)');
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
// A proposal longer than the manual-command limit ('Define task + target' in build_workflow.js) is blocked before any
// check reads it: extractTargets and the raw curl and netcat patterns take quadratic time in its length.
const CMD_MAX = 2000;
function decide(proposal, config) {
  const deny = config.deny || DEFAULT_DENY;
  const reasons = [];
  const command = (proposal && proposal.command ? String(proposal.command) : '').trim();
  const declared = proposal && proposal.target ? String(proposal.target).trim() : '';

  if (command.length > CMD_MAX) {
    const why = `command longer than ${CMD_MAX} characters (the limit for manual commands too)`;
    return { allowed: false, readOnly: false, readOnlyReason: why, activeRecon: false, activeReconReason: why, injectionSuspected: false,
      injectionHits: [], unverifiable: [], namesInScopeHost: false, autoRun: false, tier: null, requiresApproval: false, reasons: [why],
      prohibited: [], command, target: declared, mentioned: [], protectedData: [], dataReview: [], protectedEntries: asList(config.protectedData).length };
  }
  if (!command) reasons.push('empty command');

  // 1. the declared target must be in scope
  const declaredWhy = scopeWhy(declared, config);
  if (declaredWhy) {
    reasons.push(`declared target "${declared || '(none)'}" is ${SCOPE_WHY[declaredWhy]}`);
  }

  // 2. every host/IP mentioned in the command must be in scope (catches a command that quietly
  //    reaches a second, out-of-scope host even when the declared target is fine). Hosts are read from the raw text, from
  //    the words bash hands each program (quotes join: evilhost"."com is evilhost.com), and from the host positions of
  //    curl, wget, netcat and the HTTP scanners (an operand gw, curl -x gw:3128, whatweb exfil.sh)
  const segs = shellSegments(command).map((seg) => pdProgram(seg.words));
  const argWords = segs.flatMap((s) => s.args);
  // a network that stands only in a schemeless curl or wget URL is a host and a path (curl -s 10.10.10.5/10)
  const netInUrl = urlPathOnly(segs, NET_RX);
  const wordHosts = [...new Set([...argWords.flatMap((w) => extractTargets(w)), ...extractTargets(argWords.join(' ')),
    ...segs.flatMap((s) => uncWords(s.program, s.args).flatMap(uncHosts)),
    ...segs.flatMap((s) => (segmentTargets(s.program, s.args) || { hosts: [] }).hosts),
    ...segs.flatMap((s) => (segmentServers(s.program, s.args) || { hosts: [] }).hosts)])].filter((h) => !netInUrl(h));
  const mentioned = [...new Set([...extractTargets(command), ...wordHosts])].filter((h) => !netInUrl(h));
  const outOfScope = mentioned.filter((h) => hostScopeWhy(h, config));
  if (outOfScope.length) {
    const short = { allowlist: 'not in LAB_ALLOWLIST', engagement: 'outside the engagement scope', excluded: 'excluded by the engagement' };
    reasons.push(`command references out-of-scope host(s): ${outOfScope.map((h) => `${h} (${short[hostScopeWhy(h, config)]})`).join(', ')}`);
  }

  // 3. hard denylist, target-independent; the engagement's prohibited tools, its protected data and its time window
  const hit = deny.find((rx) => rx.test(command));
  if (hit) reasons.push(`command matches a denied pattern: ${hit}`);
  // nmap reads -iR in getopt_long_only's spellings too (--iR, --iR=5, a quoted '-iR'), in its own words and rustscan's after --
  const randomTargets = segs.some((s) => { const w = s.program === 'nmap' ? s.args : s.program === 'rustscan' && s.args.includes('--') ? s.args.slice(s.args.indexOf('--') + 1) : null;
    return !!w && nmapWalk(w).opts.some(([n]) => n === '--iR'); });
  if (/(^|\s)-iR\b/.test(command) || randomTargets) reasons.push('nmap -iR scans random internet hosts');
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
  // a network or range target cannot be checked against excluded host names (the gate does not resolve them)
  const netByName = mentioned.some((h) => (h.includes('/') || IP_RANGE.test(h)) && (config.scopeOut || []).some((e) => !parseNet(e)))
    ? ['network target while the engagement excludes host names'] : [];
  // a host name with a mask counts unless it stands only in a schemeless curl or wget URL (curl -s web01.lab/1)
  const maskInUrl = urlPathOnly(segs, MASK_RX), masked = [command, argWords.join(' ')].some((t) => [...t.matchAll(MASK_RX)].some((m) => !maskInUrl(m[0])));
  const unverifiable = [...new Set([...findUnverifiable(command), ...findUnverifiable(argWords.join(' ')), ...netByName])]
    .filter((why) => why !== MASK_WHY || masked);
  // the command must positively name a host in the words a program gets (a host in a comment names nothing), and every host
  // it names must be in scope - "no host found" is not a pass. A range names a host only through an address written out in
  // full in it (10.10.10.5-254 names 10.10.10.5): 10.10.10.* names none (an unquoted * is a glob bash may expand into local
  // file names, and to most tools it is no address at all)
  const namesInScopeHost = wordHosts.some((h) => !IP_RANGE.test(h)) && outOfScope.length === 0;
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
    protectedEntry, protectedCheck, shellSegments, nameMatch, PD_BULK_NONE, PD_TOOL_OPTS, READONLY_TOOLS };
}
