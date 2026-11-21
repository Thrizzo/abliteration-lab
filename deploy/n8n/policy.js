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
      return true; // hostname match (exact; no wildcar­d on purpose)
    }
  }
  return false;
}

// ---- pull every host / IP a command string refers to -----------------------------------------
// Deliberately greedy: we would rather flag an out-of-scope token and block than miss one.
function extractTargets(command) {
  const found = new Set();
  const text = String(command || '');
  for (const m of text.matchAll(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g)) found.add(m[0]);
  // bare hostnames and URLs: scheme://host, or host:port, or dotted names
  for (const m of text.matchAll(/\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b/gi)) {
    const h = m[1].toLowerCase();
    if (!/^\d+\.\d+$/.test(h)) found.add(h); // skip version-like 1.2 fragments
  }
  return [...found];
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
  /\bnmap\b[^|;&]*--script(?!=?(safe|default)\b)/i, // nmap NSE other than safe/default
  /\b(curl|wget)\b[^|;&]*(-d\b|--data|-F\b|--form|-T\b|--upload-file|-X\s*(POST|PUT|DELETE|PATCH)|--request\s*(POST|PUT|DELETE|PATCH))/i,
  /\bsmbclient\b[^|;&]*-c\b[^|;&]*\b(put|mkdir|rmdir|del|rename|rm)\b/i,
  /\bnc\b(?![^|;&]*-z)[^|;&]*-[a-z]*l/i, // netcat listener (-l) that isn't a -z port check
];

function classifyReadOnly(command) {
  const cmd = String(command || '').trim();
  if (!cmd) return { readOnly: false, reason: 'empty command' };
  if (MUTATING_PATTERNS.some((rx) => rx.test(cmd))) return { readOnly: false, reason: 'command performs a write/active operation' };
  // split into segments across ; && || and pipes; every segment must be a known read-only tool or local filter
  const segments = cmd.split(/\||;|&&|\|\||&/).map((s) => s.trim()).filter(Boolean);
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

// ---- the gate --------------------------------------------------------------------------------
// proposal: { command, target, rationale }  (already parsed out of the abliterated model's text)
// config:   { allowlist: string[], deny?: RegExp[], requireApproval?: boolean }
function decide(proposal, config) {
  const allowlist = config.allowlist || [];
  const deny = config.deny || DEFAULT_DENY;
  const reasons = [];
  const command = (proposal && proposal.command ? String(proposal.command) : '').trim();
  const declared = proposal && proposal.target ? String(proposal.target).trim() : '';

  if (!command) reasons.push('empty command');

  // 1. the declared target must be in scope
  if (!targetInScope(declared, allowlist)) {
    reasons.push(`declared target "${declared || '(none)'}" is not in the allowlist`);
  }

  // 2. every host/IP mentioned in the command must be in scope (catches a command that quietly
  //    reaches a second, out-of-scope host even when the declared target is fine)
  const mentioned = extractTargets(command);
  const outOfScope = mentioned.filter((h) => !targetInScope(h, allowlist));
  if (outOfScope.length) {
    reasons.push(`command references out-of-scope host(s): ${outOfScope.join(', ')}`);
  }

  // 3. hard denylist, target-independent
  const hit = deny.find((rx) => rx.test(command));
  if (hit) reasons.push(`command matches a denied pattern: ${hit}`);

  const allowed = reasons.length === 0;
  const ro = classifyReadOnly(command);
  // auto-run only a command that passed every check AND is confidently read-only; everything else gates
  const autoRun = allowed && ro.readOnly && config.autoRunReadOnly === true;
  return {
    allowed,
    readOnly: ro.readOnly,
    readOnlyReason: ro.reason,
    autoRun,
    requiresApproval: allowed && !autoRun,
    reasons,
    command,
    target: declared,
    mentioned,
  };
}

// exported for the unit test; harmless inside an n8n Code node
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { decide, classifyReadOnly, targetInScope, extractTargets, inCidr, ipToInt, DEFAULT_DENY };
}
