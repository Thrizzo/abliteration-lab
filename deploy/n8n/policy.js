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
// local filters allowed as pipe targets (they touch local stdout/files, never the target)
const FILTER_TOOLS = new Set([
  'grep', 'egrep', 'fgrep', 'awk', 'sed', 'cut', 'sort', 'uniq', 'head', 'tail', 'tee', 'tr',
  'wc', 'cat', 'less', 'more', 'jq', 'column', 'xargs', 'tr', 'rev', 'base64', 'cat',
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

function classifyReadOnly(command) {
  const cmd = String(command || '').trim();
  if (!cmd) return { readOnly: false, reason: 'empty command' };
  if (MUTATING_PATTERNS.some((rx) => rx.test(cmd))) return { readOnly: false, reason: 'command performs a write/active operation' };
  // nmap NSE is passive only if EVERY script in the list is safe/default (a lone "default" prefix must not smuggle in vuln)
  const scriptVal = (cmd.match(/--script[=\s]+("?)([^"\s]+)\1/i) || [])[2];
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
  const m = cmd.match(/--script[=\s]+("?)([^"\s]+)\1/i);
  if (!m) return false;                       // no --script => not this tier (plain nmap is passive tier)
  if (DANGER_NSE.test(m[2])) return false;
  return m[2].split(',').map((s) => s.trim().toLowerCase()).every((s) => SAFE_NSE.has(s));
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
// flags, and whether its auto-run tiers are on. LAB_ALLOWLIST and the LAB_AUTORUN_* variables stay the ceiling: a host
// has to be in LAB_ALLOWLIST AND in the engagement scope (when it lists any) AND not excluded, and a tier auto-runs only
// when both the variable and the engagement allow it. A run without an engagement (the web form) uses the ceiling alone.
// Mirrored for display and validation in app/engagement.py; this is the copy that decides.
const asList = (v) => (Array.isArray(v) ? v : []).map((s) => String(s ?? '').trim()).filter(Boolean).slice(0, 64);

function engagementConfig(eng, base) {
  const cfg = { allowlist: base.allowlist || [], autoRunReadOnly: base.autoRunReadOnly === true,
    autoRunActiveRecon: base.autoRunActiveRecon === true, now: base.now };
  if (!eng || typeof eng !== 'object' || Array.isArray(eng)) return cfg;
  return { ...cfg, scopeIn: asList(eng.scope_in), scopeOut: asList(eng.scope_out), prohibited: asList(eng.prohibited),
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

// ---- the gate --------------------------------------------------------------------------------
// proposal: { command, target, rationale }  (already parsed out of the abliterated model's text, or typed by the operator)
// config:   { allowlist: string[], deny?: RegExp[], scopeIn?, scopeOut?, prohibited?, window?, now?, autoRun* }
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

  // 3. hard denylist, target-independent; the engagement's prohibited tools and its time window
  const hit = deny.find((rx) => rx.test(command));
  if (hit) reasons.push(`command matches a denied pattern: ${hit}`);
  if (/(^|\s)-iR\b/.test(command)) reasons.push('nmap -iR scans random internet hosts');
  const banned = prohibitedHits(command, config.prohibited);
  if (banned.length) reasons.push(`prohibited by the rules of engagement: ${banned.join(', ')}`);
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
  // verify, carries no text aimed at the judge, and is in an enabled auto-run tier; everything else gates.
  // passive tier (LAB_AUTORUN_READONLY) and the opt-in active-recon tier (LAB_AUTORUN_ACTIVE_RECON) are independent.
  const passiveAuto = config.autoRunReadOnly === true && ro.readOnly;
  const activeAuto = config.autoRunActiveRecon === true && ar.ok;
  const autoRun = allowed && namesInScopeHost && unverifiable.length === 0 && !inj.suspected && (passiveAuto || activeAuto);
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
  };
}

// exported for the unit test; harmless inside an n8n Code node
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { decide, classifyReadOnly, classifyActiveRecon, detectInjection, findUnverifiable, targetInScope, extractTargets, inCidr, ipToInt,
    engagementConfig, scopeWhy, windowCheck, prohibitedHits, DEFAULT_DENY };
}
