/* Behaviour tests for the Code nodes inside workflows/pentest-copilot.json: runs each node's actual jsCode with mocked
 * n8n globals ($input, $json, $, $env), so an escaping slip that still parses but changes a regex is caught here, not in
 * a live run. Run: node deploy/n8n/workflow.test.js   (no deps, exit 1 on failure) */
const path = require('path');
const wf = require(path.join(__dirname, 'workflows', 'pentest-copilot.json'));

let failed = 0;
const ok = (name, cond, extra) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${name}`); if (!cond) { failed++; if (extra) console.log('    ', extra); } };
const node = (name) => wf.nodes.find((n) => n.name === name);

// run a Code node's jsCode; `nodesOut` feeds $('Other node').first().json
function run(name, { input = [], json = {}, nodesOut = {}, env = {} }) {
  const code = node(name).parameters.jsCode;
  const $input = { all: () => input.map((j) => ({ json: j })), first: () => ({ json: input[0] }) };
  const $ = (n) => ({ first: () => ({ json: nodesOut[n] }) });
  const $env = new Proxy(env, { get: (t, k) => t[k] });
  return new Function('$input', '$json', '$', '$env', code)($input, json, $, $env);
}

// every Code node parses
for (const n of wf.nodes.filter((n) => n.type === 'n8n-nodes-base.code')) {
  let parses = true;
  try { new Function('$input', '$json', '$', '$env', n.parameters.jsCode); } catch (e) { parses = false; }
  ok(`Code node parses: ${n.name}`, parses);
}

// ---- Build reference context: addresses from OTHER machines are neutralized, technique text survives ----
{
  const base = { task: 't', target: '10.10.11.42', allowlist: ['10.10.11.0/24'], scopeOk: true };
  const docs = [
    { document: { pageContent: 'Scan every TCP port first.\n```bash\nnmap -p- -T4 192.168.50.10\n```', metadata: { source: 'pwk', doc: 'pwk/a.md' } }, score: 0.61 },
    { document: { pageContent: 'The site redirects to lantern.htb; enumerate SMB on 10.10.11.42 with smbclient -N -L', metadata: { source: 'htb', doc: 'htb/b.md' } }, score: 0.7 },
  ];
  const out = run('Build reference context', { input: docs, nodesOut: { 'Scope gate': base } })[0].json;
  ok('references built from 2 docs', out.refCount === 2 && out.ragStatus === 'ok', out);
  ok('foreign IP neutralized', !out.references.includes('192.168.50.10') && out.references.includes('<other-host-ip>'), out.references);
  ok('lab host name neutralized', !out.references.includes('lantern.htb') && out.references.includes('<other-host>'), out.references);
  ok('technique text kept', out.references.includes('nmap -p- -T4') && out.references.includes('smbclient -N -L'));
  const ver = run('Build reference context', { input: [{ document: { pageContent: 'Apache 2.4.49, OpenSSH 7.2p2, Windows build 10.0.17763, odd 1.300.2.4', metadata: {} }, score: 0.5 }], nodesOut: { 'Scope gate': base } })[0].json.references;
  ok('common version formats untouched', ['2.4.49', '7.2p2', '10.0.17763', '1.300.2.4'].every((v) => ver.includes(v)), ver);
  // documented limitation: a four-part version with every part <= 255 is indistinguishable from an IPv4 and gets masked
  const four = run('Build reference context', { input: [{ document: { pageContent: 'build 7.2.2.1', metadata: {} }, score: 0.5 }], nodesOut: { 'Scope gate': base } })[0].json.references;
  ok('(limitation) 4-part all-octet version is masked like an address', four.includes('<other-host-ip>'), four);
  const none = run('Build reference context', { input: [{}], nodesOut: { 'Scope gate': base } })[0].json;
  ok('empty store -> no references, status "no matches"', none.refCount === 0 && none.ragStatus === 'no matches', none);
  const down = run('Build reference context', { input: [{ error: { message: 'connect ECONNREFUSED 127.0.0.1:6333' } }], nodesOut: { 'Scope gate': base } })[0].json;
  ok('store down -> copilot continues, status says why', down.refCount === 0 && /retrieval failed: connect ECONNREFUSED/.test(down.ragStatus), down);
  // measured in a live run: with the store down n8n passes the input item through unchanged (no error field)
  const passthru = run('Build reference context', { input: [base], nodesOut: { 'Scope gate': base } })[0].json;
  ok('store down (input passed through) -> status says retrieval failed, not "no matches"', passthru.refCount === 0 && /^retrieval failed/.test(passthru.ragStatus), passthru.ragStatus);
  ok('references are bounded', run('Build reference context', { input: Array.from({ length: 10 }, () => ({ document: { pageContent: 'x'.repeat(5000), metadata: {} }, score: 0.5 })), nodesOut: { 'Scope gate': base } })[0].json.references.length <= 3500 + 400);
}

// ---- Scope gate: fails closed when n8n blocks $env, reads the allowlist otherwise ----
{
  const blocked = new Proxy({}, { get: () => { throw new Error('access to env vars denied'); } });
  let msg = '';
  try { new Function('$input', '$json', '$', '$env', node('Scope gate').parameters.jsCode)({}, { target: '10.10.11.42' }, () => ({}), blocked); } catch (e) { msg = e.message; }
  ok('blocked $env -> actionable error, no guessed scope', /N8N_BLOCK_ENV_ACCESS_IN_NODE=false/.test(msg), msg);
  const inS = run('Scope gate', { json: { target: '10.10.11.42' }, env: { LAB_ALLOWLIST: '10.10.11.0/24' } })[0].json;
  const outS = run('Scope gate', { json: { target: '8.8.8.8' }, env: { LAB_ALLOWLIST: '10.10.11.0/24' } })[0].json;
  ok('scope gate: in / out of scope', inS.scopeOk === true && outS.scopeOk === false);
}

// ---- Parse proposal: JSON first, fenced block as fallback ----
{
  const scope = { target: '10.10.11.42', allowlist: ['10.10.11.0/24'] };
  const p1 = run('Parse proposal', { json: { text: 'Sure: {"command": "smbclient -N -L //10.10.11.42", "target": "10.10.11.42", "rationale": "list shares"}' }, nodesOut: { 'Define task + target': scope, 'Scope gate': scope } })[0].json;
  ok('parse JSON proposal', p1.proposal.command === 'smbclient -N -L //10.10.11.42' && p1.proposal.target === '10.10.11.42', p1.proposal);
  const p2 = run('Parse proposal', { json: { text: 'Run this:\n```bash\nnmap -sV 10.10.11.42\n```' }, nodesOut: { 'Define task + target': scope, 'Scope gate': scope } })[0].json;
  ok('parse fenced fallback', p2.proposal.command === 'nmap -sV 10.10.11.42', p2.proposal);
}

// ---- Apply judge decision: veto-only, runs the vetted command ----
{
  const pg = run('Policy gate', { json: { proposal: { command: 'nmap -sV 10.10.11.42', target: '10.10.11.42' }, allowlist: ['10.10.11.0/24'] }, env: { LAB_AUTORUN_READONLY: 'true' } })[0].json;
  const auth = run('Apply judge decision', { json: { text: 'AUTHORIZE\nfine' }, nodesOut: { 'Policy gate': pg }, env: { LAB_AUTORUN_READONLY: 'true' } })[0].json;
  const rej = run('Apply judge decision', { json: { text: 'REJECT\nnoisy' }, nodesOut: { 'Policy gate': pg }, env: { LAB_AUTORUN_READONLY: 'true' } })[0].json;
  const fuzzy = run('Apply judge decision', { json: { text: 'I think it is fine, AUTHORIZE maybe' }, nodesOut: { 'Policy gate': pg }, env: { LAB_AUTORUN_READONLY: 'true' } })[0].json;
  ok('AUTHORIZE -> allowed + auto-run (read-only)', auth.allowed === true && auth.autoRun === true);
  ok('REJECT -> blocked', rej.allowed === false);
  ok('ambiguous verdict -> not authorized', fuzzy.allowed === false);
}

// ---- model nodes: the judge runs without a thinking trace, the operator is left to the model's default ----
{
  const judge = node('Ollama: judge model (regular)').parameters.options;
  const operator = node('Ollama: abliterated model').parameters.options;
  ok('judge: think=false, temperature 0 (no minutes-long hidden trace on CPU)', judge.think === false && judge.temperature === 0, judge);
  ok('operator: think not forced', !('think' in operator), operator);
}

console.log(failed ? `\n${failed} test(s) FAILED` : '\nall workflow tests passed');
process.exit(failed ? 1 : 0);
