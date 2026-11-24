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

// ---- web form: two required fields that land in task / target ----
{
  const form = node('Copilot form');
  const fields = form.parameters.formFields.values;
  const f = (name) => fields.find((v) => v.fieldName === name);
  ok('form: Task and Target are required fields named task / target', f('task')?.requiredField === true && f('target')?.requiredField === true, fields);
  ok('form: published at /form/pentest-copilot', form.parameters.options.path === 'pentest-copilot');
  const set = node('Define task + target').parameters.assignments.assignments;
  ok('form input is trimmed into task / target', set.some((a) => a.name === 'task' && a.value.includes('$json.task')) && set.some((a) => a.name === 'target' && a.value.includes('$json.target')), set);
  ok('no manual trigger left (one way in)', !wf.nodes.some((n) => n.type === 'n8n-nodes-base.manualTrigger'));
}

// ---- graph: a blocked run can never reach approval or execution ----
{
  const kids = (n) => ((wf.connections[n] || {}).main || []).flat().map((c) => c.node);
  const reach = (from) => { const seen = new Set(); const stack = [from]; while (stack.length) { const n = stack.pop(); for (const k of kids(n)) if (!seen.has(k)) { seen.add(k); stack.push(k); } } return seen; };
  const danger = ['Auto-run (recon tier)?', 'Human approval', 'Execute on lab target (DISABLED)'];
  for (const b of ['Blocked (out of scope)', 'Blocked (policy)', 'Blocked (judge rejected)']) {
    const r = reach(b);
    ok(`${b} ends on the blocked page, never reaches approval/execute`, r.has('Result page: blocked') && danger.every((d) => !r.has(d)), [...r]);
  }
  // the only way into the authorized page is the true branch of Authorized?
  const into = (target) => Object.entries(wf.connections).flatMap(([src, c]) => (c.main || []).flatMap((outs, i) => outs.filter((o) => o.node === target).map(() => `${src}#${i}`)));
  ok('authorized page is fed only by Authorized? (true)', JSON.stringify(into('Result text (authorized)')) === JSON.stringify(['Authorized?#0']), into('Result text (authorized)'));
  ok('auto-run split is fed only by the authorized page', JSON.stringify(into('Auto-run (recon tier)?')) === JSON.stringify(['Result page: authorized#0']), into('Auto-run (recon tier)?'));
}

// ---- result page text: right verdict per path; form and model text escaped, command shown exactly ----
{
  const scopeBase = { task: 'Enumerate SMB', target: '10.10.11.42', allowlist: ['10.10.11.0/24'], scopeOk: true };
  const page = (name, json, nodesOut = {}) => run(name, { json, nodesOut })[0].json;
  const out = page('Result text (blocked)', { task: 'x', target: '8.8.8.8', allowlist: [], scopeOk: false, scopeReason: 'target "8.8.8.8" not in allowlist' });
  ok('page: out of scope', out.resultTitle === 'Blocked: target out of scope' && out.resultMessage.includes('not in allowlist') && !out.resultMessage.includes('References'), out);

  const evil = 'rm -rf / ; nmap -sV <other-host-ip> <script>alert(1)</script> && printf "a\\nb"';
  const pg = run('Policy gate', { json: { ...scopeBase, proposal: { command: evil, target: '10.10.11.42', rationale: '<img src=x onerror=alert(1)>' } }, env: { LAB_AUTORUN_READONLY: 'true' } })[0].json;
  const pol = page('Result text (blocked)', pg, { 'Build reference context': { ragStatus: 'no matches' } });
  ok('page: policy block', pol.resultTitle === 'Blocked by the policy gate', pol.resultTitle);
  ok('page: no model markup survives (script / img escaped)', !/<script|<img/i.test(pol.resultMessage) && pol.resultMessage.includes('&lt;script&gt;') && pol.resultMessage.includes('&lt;img src=x'), pol.resultMessage);
  ok('page: placeholder shown, not stripped', pol.resultMessage.includes('&lt;other-host-ip&gt;'));
  ok('page: literal backslash-n kept (doubled for n8n)', pol.resultMessage.includes('printf &quot;a\\\\nb&quot;'), pol.resultMessage);
  ok('page: retrieval status shown when retrieval ran', pol.resultMessage.includes('<b>References:</b> no matches'));

  const ok1 = run('Policy gate', { json: { ...scopeBase, proposal: { command: 'nmap -sV 10.10.11.42', target: '10.10.11.42', rationale: 'versions' } }, env: { LAB_AUTORUN_READONLY: 'true' } })[0].json;
  const judged = (text, cmdPg = ok1) => run('Apply judge decision', { json: { text }, nodesOut: { 'Policy gate': cmdPg }, env: { LAB_AUTORUN_READONLY: 'true' } })[0].json;
  const rej = page('Result text (blocked)', judged('REJECT\nnoisy'));
  ok('page: judge rejected', rej.resultTitle === 'Blocked: the judge rejected it' && rej.resultMessage.includes('judge rejected: REJECT'), rej.resultTitle);
  const auto = page('Result text (authorized)', judged('AUTHORIZE\nfine'));
  ok('page: authorized auto-run names the tier and that nothing ran', auto.resultTitle === 'Authorized: auto-run (passive tier)' && auto.resultMessage.includes('nothing ran'), auto.resultTitle);
  const hy = run('Policy gate', { json: { ...scopeBase, proposal: { command: 'hydra -l admin -P rockyou.txt ssh://10.10.11.42', target: '10.10.11.42', rationale: 'weak creds' } }, env: { LAB_AUTORUN_READONLY: 'true' } })[0].json;
  const appr = page('Result text (authorized)', judged('AUTHORIZE', hy));
  ok('page: authorized but not auto-run -> waiting for approval, with the reason', appr.resultTitle === 'Authorized: waiting for your approval' && appr.resultMessage.includes('not in an enabled auto-run tier'), appr);
  ok('page: carries the item through (Auto-run? still reads autoRun)', auto.autoRun === true && appr.autoRun === false && auto.policy && auto.policy.command === 'nmap -sV 10.10.11.42');
  const odd = page('Result text (authorized)', { ...ok1 });   // allowed by policy but never judged: must not read as authorized
  ok('page: an item that was not explicitly allowed is never titled authorized', odd.resultTitle === 'Blocked', odd.resultTitle);
}

console.log(failed ? `\n${failed} test(s) FAILED` : '\nall workflow tests passed');
process.exit(failed ? 1 : 0);
