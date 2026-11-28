/* Behaviour tests for the Code nodes inside workflows/pentest-copilot.json: runs each node's actual jsCode with mocked
 * n8n globals ($input, $json, $, $env), so an escaping slip that still parses but changes a regex is caught here, not in
 * a live run. Run: node deploy/n8n/workflow.test.js   (no deps, exit 1 on failure) */
const path = require('path');
const wf = require(path.join(__dirname, 'workflows', 'pentest-copilot.json'));

let failed = 0;
const ok = (name, cond, extra) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${name}`); if (!cond) { failed++; if (extra) console.log('    ', extra); } };
const node = (name) => wf.nodes.find((n) => n.name === name);

// run a Code node's jsCode; `nodesOut` feeds $('Other node').first().json
// `executed` lists the nodes that ran ($('X').isExecuted); left out, isExecuted is undefined, as in an older runner
function run(name, { input = [], json = {}, nodesOut = {}, env = {}, executed }) {
  const code = node(name).parameters.jsCode;
  const $input = { all: () => input.map((j) => ({ json: j })), first: () => ({ json: input[0] }) };
  const $ = (n) => ({ first: () => ({ json: nodesOut[n] }), isExecuted: executed ? executed.includes(n) : undefined });
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
  const prompt = { ...scope, operatorModel: 'glm-abl', operatorPrompt: 'TASK: ...', references: 'secret ref text' };
  const outs = { 'Define task + target': scope, 'Scope gate': scope, 'Build operator prompt': prompt };
  const p1 = run('Parse proposal', { json: { text: 'Sure: {"command": "smbclient -N -L //10.10.11.42", "target": "10.10.11.42", "rationale": "list shares"}' }, nodesOut: outs })[0].json;
  ok('parse JSON proposal', p1.proposal.command === 'smbclient -N -L //10.10.11.42' && p1.proposal.target === '10.10.11.42', p1.proposal);
  const p2 = run('Parse proposal', { json: { text: 'Run this:\n```bash\nnmap -sV 10.10.11.42\n```' }, nodesOut: outs })[0].json;
  ok('parse fenced fallback', p2.proposal.command === 'nmap -sV 10.10.11.42', p2.proposal);
  ok('parse: keeps the operator model; references and the prompt stay behind (they never reach the judge)', p1.operatorModel === 'glm-abl'
    && !('references' in p1) && !('operatorPrompt' in p1), Object.keys(p1));
}

// ---- Apply judge decision: veto-only, runs the vetted command ----
{
  const pg = run('Policy gate', { json: { proposal: { command: 'nmap -sV 10.10.11.42', target: '10.10.11.42' }, allowlist: ['10.10.11.0/24'] }, env: { LAB_AUTORUN_READONLY: 'true' } })[0].json;
  const jp = run('Build judge prompt', { json: pg, env: {} })[0].json;
  const auth = run('Apply judge decision', { json: { text: 'AUTHORIZE\nfine' }, nodesOut: { 'Build judge prompt': jp }, env: { LAB_AUTORUN_READONLY: 'true' } })[0].json;
  const rej = run('Apply judge decision', { json: { text: 'REJECT\nnoisy' }, nodesOut: { 'Build judge prompt': jp }, env: { LAB_AUTORUN_READONLY: 'true' } })[0].json;
  const fuzzy = run('Apply judge decision', { json: { text: 'I think it is fine, AUTHORIZE maybe' }, nodesOut: { 'Build judge prompt': jp }, env: { LAB_AUTORUN_READONLY: 'true' } })[0].json;
  ok('AUTHORIZE -> allowed + auto-run (read-only)', auth.allowed === true && auth.autoRun === true);
  ok('REJECT -> blocked', rej.allowed === false);
  ok('ambiguous verdict -> not authorized', fuzzy.allowed === false);
  ok('staged = the policy-vetted command when authorized, nothing otherwise', auth.staged === 'nmap -sV 10.10.11.42' && rej.staged === '' && fuzzy.staged === '', [auth.staged, rej.staged]);
  ok('the judge model is named in the result', auth.judgeModel === 'qwen3:8b', auth.judgeModel);
}

// ---- model nodes: the judge runs without a thinking trace; the operator is an OpenAI-compatible chat model ----
{
  const judge = node('Ollama: judge model (regular)').parameters.options;
  const op = node('Operator model (OpenAI-compatible)');
  ok('judge: think=false, temperature 0 (no minutes-long hidden trace on CPU)', judge.think === false && judge.temperature === 0, judge);
  ok('operator: lmChatOpenAi v1.3 (vLLM and Ollama both serve /v1/chat/completions)', op.type === '@n8n/n8n-nodes-langchain.lmChatOpenAi' && op.typeVersion === 1.3, op);
  ok('operator: chat completions, not the Responses API (on by default in v1.3)', op.parameters.responsesApiEnabled === false, op.parameters);
  ok('operator: temperature 0, think not forced', op.parameters.options.temperature === 0 && !('think' in op.parameters.options), op.parameters.options);
  ok('operator: the console\'s choice, else COPILOT_OPERATOR_MODEL, else glm-abl', op.parameters.model.__rl === true && op.parameters.model.mode === 'id'
    && op.parameters.model.value.startsWith('={{ $json.operatorModel ||') && op.parameters.model.value.includes('$env.COPILOT_OPERATOR_MODEL') && op.parameters.model.value.includes('"glm-abl"'), op.parameters.model);
  const jm = node('Ollama: judge model (regular)').parameters.model;
  ok('judge: the console\'s choice, else COPILOT_JUDGE_MODEL, else qwen3:8b', jm.startsWith('={{ $json.judgeModel ||') && jm.includes('$env.COPILOT_JUDGE_MODEL') && jm.includes('"qwen3:8b"'), jm);
  ok('the chains read the prompts the Build nodes made (the console shows the same text)', node('Abliterated operator (suggest)').parameters.text === '={{ $json.operatorPrompt }}'
    && node('Judge: authorize?').parameters.text === '={{ $json.judgePrompt }}');
  const into = (target, type) => Object.entries(wf.connections).flatMap(([src, c]) => (c[type] || []).flat().filter((o) => o.node === target).map(() => src));
  ok('operator model feeds the operator chain', JSON.stringify(into('Abliterated operator (suggest)', 'ai_languageModel')) === JSON.stringify(['Operator model (OpenAI-compatible)']));
}

// ---- console webhook: header secret, answers at once with the execution id, then the same pipeline ----
{
  const wh = node('Console webhook');
  ok('webhook: POST /webhook/copilot-run, header auth, answered by a Respond node', wh.type === 'n8n-nodes-base.webhook'
    && wh.parameters.httpMethod === 'POST' && wh.parameters.path === 'copilot-run' && wh.parameters.authentication === 'headerAuth'
    && wh.parameters.responseMode === 'responseNode' && !!wh.webhookId, wh);
  const rs = node('Respond: execution id');
  ok('respond: JSON with the execution id, 202', rs.parameters.respondWith === 'json' && rs.parameters.responseBody.includes('$execution.id')
    && rs.parameters.options.responseCode === 202, rs.parameters);
  ok('respond passes the request on (no enableResponseOutput)', !rs.parameters.enableResponseOutput);
  const kids = (n) => ((wf.connections[n] || {}).main || []).flat().map((c) => c.node);
  ok('webhook -> respond -> Define task + target', JSON.stringify(kids('Console webhook')) === JSON.stringify(['Respond: execution id'])
    && JSON.stringify(kids('Respond: execution id')) === JSON.stringify(['Define task + target']));
  // what the webhook node emits: headers (the X-Lab-Secret among them), params, query, body
  const hook = (body) => ({ headers: { 'x-lab-secret': 's3cret', host: 'n8n' }, params: {}, query: {}, body });
  const def = (json, executed) => run('Define task + target', { json, executed })[0].json;
  const c = def(hook({ task: '  Enumerate SMB ', target: ' 10.10.11.42 ', requested_by: 'x'.repeat(500) }), ['Console webhook', 'Respond: execution id']);
  ok('console runs read task / target from the body, trimmed', c.task === 'Enumerate SMB' && c.target === '10.10.11.42' && c.source === 'console', c);
  ok('requestedBy is bounded', c.requestedBy.length === 120, c.requestedBy.length);
  ok('the webhook headers (the shared secret) are not passed on', !JSON.stringify(c).includes('s3cret') && !('headers' in c) && !('body' in c), Object.keys(c));
  ok('console run without mode: copilot, no engagement, no model choice', c.mode === 'copilot' && c.engagement === null && c.operatorModel === '' && c.judgeModel === '', c);
  const f = def({ task: 'Enumerate SMB', target: '10.10.11.42', submittedAt: '2026-11-26T10:00:00Z', formMode: 'production' }, ['Copilot form']);
  ok('form runs read the two fields; source "form"', f.task === 'Enumerate SMB' && f.target === '10.10.11.42' && f.source === 'form' && f.requestedBy === '', f);
  const sneaky = def({ task: 'x', target: '10.10.11.42', mode: 'manual', command: 'id', engagement: { scope_in: ['8.8.8.8'] }, judge_model: 'glm-abl' }, ['Copilot form']);
  ok('a form run cannot choose manual mode, an engagement or models', sneaky.mode === 'copilot' && sneaky.manualCommand === '' && sneaky.engagement === null && sneaky.judgeModel === '', sneaky);
  ok('without isExecuted (older runner) the webhook is recognised by its shape', def(hook({ task: 't', target: '10.10.11.42' })).source === 'console'
    && def({ task: 't', target: '10.10.11.42' }).source === 'form');
  const m = def(hook({ target: '10.10.11.42', mode: 'manual', command: ' nmap -sV 10.10.11.42 ', operator_model: 'glm-abl', judge_model: 'qwen3:8b' }), ['Console webhook']);
  ok('manual mode: the command, a default task, the models', m.mode === 'manual' && m.manualCommand === 'nmap -sV 10.10.11.42' && m.task === 'Run the command the operator typed.'
    && m.operatorModel === 'glm-abl' && m.judgeModel === 'qwen3:8b', m);
  // a typed command over 2000 characters must reach the gate as too long, never as the prefix a plain cut leaves
  const longCmd = 'nmap -sV 10.10.11.42' + ' '.repeat(1985) + '; id';
  const lm = def(hook({ target: '10.10.11.42', mode: 'manual', command: longCmd }), ['Console webhook']);
  ok('manual mode: a command over 2000 characters goes on cut, marked, still over 2000', lm.manualCommand.length === 2004
    && lm.manualCommand.endsWith(' ...') && lm.manualCommand.startsWith('nmap -sV 10.10.11.42'), lm.manualCommand.length);
  const exact = 'curl -s http://10.10.11.42/?q=' + 'A'.repeat(1970);
  ok('manual mode: a command of exactly 2000 characters is passed whole', def(hook({ target: '10.10.11.42', mode: 'manual', command: exact }), ['Console webhook']).manualCommand === exact);
  {
    const env = { LAB_ALLOWLIST: '10.10.11.0/24', LAB_AUTORUN_READONLY: 'true' };
    const sg = run('Scope gate', { json: lm, env })[0].json;
    const lp = run('Manual proposal', { json: sg })[0].json;
    const lpol = run('Policy gate', { json: lp, env })[0].json.policy;
    ok('manual mode: the over-long command is blocked by the gate, not staged as its first 2000 characters', lpol.allowed === false && lpol.autoRun === false
      && lpol.reasons.join() === 'command longer than 2000 characters (the limit for manual commands too)', lpol.reasons);
  }
  ok('a model name that is not a plain name is dropped', def(hook({ task: 't', target: 'x', operator_model: 'glm abl; rm', judge_model: '../x' }), ['Console webhook']).operatorModel === ''
    && def(hook({ task: 't', target: 'x', judge_model: '../x' }), ['Console webhook']).judgeModel === '');
  const e = def(hook({ task: 't', target: '10.10.11.42', engagement: { name: 'n'.repeat(300), version: 3, scope_in: Array.from({ length: 80 }, (_, i) => `10.10.11.${i}`),
    scope_out: 'not a list', prohibited: ['hydra', ' ', 'p'.repeat(100)], roe: 'r'.repeat(9000), window_start: '2026-11-26T08:00:00Z', autorun_passive: 'yes', autorun_active: true } }), ['Console webhook']).engagement;
  ok('engagement: bounded and typed', e.name.length === 120 && e.version === 3 && e.scope_in.length === 64 && Array.isArray(e.scope_out) && e.scope_out.length === 0
    && e.prohibited.length === 2 && e.prohibited[1].length === 64 && e.roe.length === 8000 && e.window_start === '2026-11-26T08:00:00Z' && e.window_end === null
    && e.autorun_passive === false && e.autorun_active === true, e);
}

// ---- web form: two required fields that land in task / target ----
{
  const form = node('Copilot form');
  const fields = form.parameters.formFields.values;
  const f = (name) => fields.find((v) => v.fieldName === name);
  ok('form: Task and Target are required fields named task / target', f('task')?.requiredField === true && f('target')?.requiredField === true, fields);
  ok('form: published at /form/pentest-copilot', form.parameters.options.path === 'pentest-copilot');
  const d = run('Define task + target', { json: { task: '  Enumerate SMB \n', target: ' 10.10.11.42  ', submittedAt: 'now' }, executed: ['Copilot form'] })[0].json;
  ok('form input is trimmed into task / target', d.task === 'Enumerate SMB' && d.target === '10.10.11.42' && d.source === 'form', d);
  ok('no manual trigger (two ways in: the form and the console webhook)', !wf.nodes.some((n) => n.type === 'n8n-nodes-base.manualTrigger')
    && wf.nodes.filter((n) => /Trigger$|\.webhook$/.test(n.type)).map((n) => n.name).sort().join('|') === 'Console webhook|Copilot form');
}

// ---- graph: a blocked run can never reach approval or execution ----
{
  const kids = (n) => ((wf.connections[n] || {}).main || []).flat().map((c) => c.node);
  const reach = (from) => { const seen = new Set(); const stack = [from]; while (stack.length) { const n = stack.pop(); for (const k of kids(n)) if (!seen.has(k)) { seen.add(k); stack.push(k); } } return seen; };
  const danger = ['Auto-run (recon tier)?', 'Human approval', 'Execute on lab target (DISABLED)'];
  for (const b of ['Blocked (out of scope)', 'Blocked (policy)', 'Blocked (judge rejected)']) {
    const r = reach(b);
    ok(`${b} ends at the blocked result (page for form runs), never reaches approval/execute`,
      r.has('Result text (blocked)') && r.has('Result page: blocked') && danger.every((d) => !r.has(d)), [...r]);
  }
  // the only way into the authorized result is the true branch of Authorized?
  const into = (target) => Object.entries(wf.connections).flatMap(([src, c]) => (c.main || []).flatMap((outs, i) => outs.filter((o) => o.node === target).map(() => `${src}#${i}`)));
  ok('authorized result is fed only by Authorized? (true)', JSON.stringify(into('Result text (authorized)')) === JSON.stringify(['Authorized?#0']), into('Result text (authorized)'));
  ok('the form-run split is fed only by the authorized result', JSON.stringify(into('Form run? (authorized)')) === JSON.stringify(['Result text (authorized)#0']), into('Form run? (authorized)'));
  ok('auto-run split: the authorized page (form runs) or the false branch of Form run? (console runs), nothing else',
    JSON.stringify(into('Auto-run (recon tier)?').sort()) === JSON.stringify(['Form run? (authorized)#1', 'Result page: authorized#0']), into('Auto-run (recon tier)?'));
  for (const [pageNode, split] of [['Result page: authorized', 'Form run? (authorized)'], ['Result page: blocked', 'Form run? (blocked)']]) {
    const cond = node(split).parameters.conditions.conditions[0].leftValue;
    ok(`${pageNode}: only form runs (true branch of ${split}: source is not "console")`,
      JSON.stringify(into(pageNode)) === JSON.stringify([`${split}#0`]) && cond === '={{ $json.source !== "console" }}', [into(pageNode), cond]);
  }
  ok('blocked console runs end there: Form run? (blocked) has no false branch', ((wf.connections['Form run? (blocked)'] || {}).main || [])[1] === undefined
    || ((wf.connections['Form run? (blocked)'].main[1]) || []).length === 0);
}

// ---- "source" reaches the form-run splits through every Code node (else a console run would hit a form page) ----
{
  const env = { LAB_ALLOWLIST: '10.10.11.0/24', LAB_AUTORUN_READONLY: 'true' };
  const defined = { task: 'Enumerate SMB', target: '10.10.11.42', source: 'console', requestedBy: 'admin', mode: 'copilot', manualCommand: '',
    operatorModel: 'glm-abl', judgeModel: 'qwen3:8b', engagement: { name: 'ACME', version: 2, scope_in: ['10.10.11.0/28'] } };
  const scope = run('Scope gate', { json: defined, env })[0].json;
  const refs = run('Build reference context', { input: [{}], nodesOut: { 'Scope gate': scope } })[0].json;
  const prompt = run('Build operator prompt', { json: refs, env })[0].json;
  const parsed = run('Parse proposal', { json: { text: '{"command": "nmap -sV 10.10.11.42", "target": "10.10.11.42"}' }, nodesOut: { 'Define task + target': defined, 'Scope gate': scope, 'Build operator prompt': prompt } })[0].json;
  const pg = run('Policy gate', { json: parsed, env })[0].json;
  const jp = run('Build judge prompt', { json: pg, env })[0].json;
  const judged = run('Apply judge decision', { json: { text: 'AUTHORIZE' }, nodesOut: { 'Build judge prompt': jp }, env })[0].json;
  const result = run('Result text (authorized)', { json: judged, nodesOut: { 'Build reference context': refs } })[0].json;
  const blockedOut = run('Result text (blocked)', { json: run('Scope gate', { json: { ...defined, target: '8.8.8.8' }, env })[0].json })[0].json;
  const all = [scope, refs, prompt, parsed, pg, jp, judged, result, blockedOut];
  ok('source and requestedBy survive scope, retrieval, prompts, parse, policy, judge and result', all.every((j) => j.source === 'console' && j.requestedBy === 'admin'), all.map((j) => j.source));
  ok('mode, the models and the engagement survive to the result', [parsed, pg, jp, judged, result].every((j) => j.mode === 'copilot' && j.operatorModel === 'glm-abl'
    && j.engagement && j.engagement.version === 2) && judged.judgeModel === 'qwen3:8b', result);
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
  const judged = (text, cmdPg = ok1) => run('Apply judge decision', { json: { text }, nodesOut: { 'Build judge prompt': run('Build judge prompt', { json: cmdPg })[0].json }, env: { LAB_AUTORUN_READONLY: 'true' } })[0].json;
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

// ---- the engagement: scope gate, policy gate, prompts, re-check ----
{
  const env = { LAB_ALLOWLIST: '10.10.11.0/24,box.htb', LAB_AUTORUN_READONLY: 'true' };
  const E = { name: 'ACME internal', version: 4, scope_statement: 'Only the web tier.', scope_in: ['10.10.11.0/28', 'box.htb'], scope_out: ['10.10.11.1'],
    prohibited: ['hydra'], roe: 'No DoS. Stop on PII.', window_start: null, window_end: null, autorun_passive: true, autorun_active: false };
  const base = { task: 'Enumerate SMB', source: 'console', requestedBy: 'admin', mode: 'copilot', manualCommand: '', operatorModel: '', judgeModel: '' };
  const gate = (target, engagement = E) => run('Scope gate', { json: { ...base, target, engagement }, env })[0].json;
  ok('scope gate: inside LAB_ALLOWLIST and the engagement -> in scope', gate('10.10.11.5').scopeOk === true && gate('10.10.11.5').scopeBy === 'LAB_ALLOWLIST and the engagement scope');
  const narrow = gate('10.10.11.200');
  ok('scope gate: in LAB_ALLOWLIST, outside the engagement -> blocked before any model', narrow.scopeOk === false && narrow.scopeReason === 'target "10.10.11.200" is outside the engagement scope', narrow.scopeReason);
  ok('scope gate: an excluded target -> blocked', gate('10.10.11.1').scopeReason === 'target "10.10.11.1" is excluded by the engagement');
  ok('scope gate: the engagement cannot widen LAB_ALLOWLIST', gate('8.8.8.8', { ...E, scope_in: ['8.8.8.8'] }).scopeReason.includes('LAB_ALLOWLIST'));
  const closed = gate('10.10.11.5', { ...E, window_end: '2020-01-01T00:00:00Z' });
  ok('scope gate: outside the engagement window -> blocked', closed.scopeOk === false && closed.scopeReason.startsWith('outside the engagement window'), closed.scopeReason);
  ok('scope gate: no engagement -> LAB_ALLOWLIST alone', gate('10.10.11.200', null).scopeOk === true && gate('10.10.11.200', null).scopeBy === 'LAB_ALLOWLIST');
  const pageNarrow = run('Result text (blocked)', { json: narrow })[0].json.resultMessage;
  const pageCeil = run('Result text (blocked)', { json: gate('8.8.8.8') })[0].json.resultMessage;
  ok('result: an engagement block points at the console, a ceiling block at LAB_ALLOWLIST', pageNarrow.includes('engagement in the console') && pageCeil.includes('add it to LAB_ALLOWLIST'), [pageNarrow, pageCeil]);

  // the operator prompt carries the rules (and the references); the model is the console's choice or the environment's
  const refs = { ...gate('10.10.11.5'), references: '[ref 1 | htb | a.md | score 0.70]\nsmbclient -N -L //<other-host-ip>', refCount: 1, ragStatus: 'ok' };
  const op = run('Build operator prompt', { json: refs, env })[0].json;
  ok('operator prompt: task, target, rules of engagement, then references', /^TASK: Enumerate SMB\nTARGET \(authorized, in scope\): 10\.10\.11\.5\n\nRULES OF ENGAGEMENT[^\n]*\n<<<\nENGAGEMENT: ACME internal \(version 4\)\n/.test(op.operatorPrompt)
    && op.operatorPrompt.indexOf('RULES: No DoS') < op.operatorPrompt.indexOf('REFERENCE NOTES') && op.operatorPrompt.includes('PROHIBITED: hydra'), op.operatorPrompt);
  ok('operator model: COPILOT_OPERATOR_MODEL when the console chose none, glm-abl without it', op.operatorModel === 'glm-abl'
    && run('Build operator prompt', { json: refs, env: { COPILOT_OPERATOR_MODEL: 'glm-abl-run7' } })[0].json.operatorModel === 'glm-abl-run7'
    && run('Build operator prompt', { json: { ...refs, operatorModel: 'chosen' }, env: { COPILOT_OPERATOR_MODEL: 'x' } })[0].json.operatorModel === 'chosen');
  const long = run('Build operator prompt', { json: { ...refs, engagement: { ...E, roe: 'r'.repeat(9000) } }, env })[0].json.operatorPrompt;
  ok('operator prompt: the rules are cut at 4000 characters', long.includes(' ...\n>>>') && long.length < 4000 + 600, long.length);

  // policy gate with the engagement: prohibited tools, auto-run only when both allow it
  const pol = (command, engagement = E, e2 = env) => run('Policy gate', { json: { ...refs, engagement, proposal: { command, target: '10.10.11.5' } }, env: e2 })[0].json.policy;
  ok('policy: a prohibited tool is blocked with the reason', pol('hydra -l admin -P p.txt ssh://10.10.11.5').allowed === false
    && pol('hydra -l admin -P p.txt ssh://10.10.11.5').reasons.includes('prohibited by the rules of engagement: hydra'));
  ok('policy: an excluded host inside the command is blocked', pol('nmap -sV 10.10.11.5 10.10.11.1').allowed === false);
  ok('policy: auto-run needs LAB_AUTORUN_READONLY and the engagement', pol('nmap -sV 10.10.11.5').autoRun === true && pol('nmap -sV 10.10.11.5', { ...E, autorun_passive: false }).autoRun === false
    && pol('nmap -sV 10.10.11.5', E, { ...env, LAB_AUTORUN_READONLY: 'false' }).autoRun === false);

  // the judge: never an abliterated model, its prompt carries the rules and the vetted command
  const pgOk = run('Policy gate', { json: { ...refs, proposal: { command: 'nmap -sV 10.10.11.5', target: '10.10.11.5' } }, env })[0].json;
  const judgeFor = (judgeModel, operatorModel = 'glm-abl') => { try { return run('Build judge prompt', { json: { ...pgOk, judgeModel, operatorModel }, env })[0].json; } catch (e) { return { error: e.message }; } };
  for (const m of ['glm-abl', 'glm-edge-1.5b-chat-abl', 'glm-edge-1.5b-chat-abl:latest', 'qwen3-abliterated:8b', 'llama3-uncensored', 'same-as-op']) {
    ok(`judge refused: ${m}`, /refused: the judge must be a regular model/.test(judgeFor(m, m === 'same-as-op' ? 'same-as-op' : 'glm-abl').error || ''), judgeFor(m));
  }
  for (const m of ['qwen3:8b', 'llama3.1:8b', 'glm-edge-1.5b-chat-base', 'table-tennis', 'gpt-oss:20b']) ok(`judge allowed: ${m}`, judgeFor(m).judgeModel === m, judgeFor(m));
  ok('judge: COPILOT_JUDGE_MODEL, else qwen3:8b', judgeFor('').judgeModel === 'qwen3:8b'
    && run('Build judge prompt', { json: { ...pgOk, judgeModel: '' }, env: { ...env, COPILOT_JUDGE_MODEL: 'llama3.1:8b' } })[0].json.judgeModel === 'llama3.1:8b');
  const jprompt = judgeFor('qwen3:8b').judgePrompt;
  ok('judge prompt: task, target, the scope, rules, the vetted command, read-only and tier', /^TASK: Enumerate SMB\nTARGET: 10\.10\.11\.5\nSCOPE \(LAB_ALLOWLIST\): 10\.10\.11\.0\/24, box\.htb\nRULES OF ENGAGEMENT[^\n]*\n<<<\nENGAGEMENT: ACME internal/.test(jprompt)
    && jprompt.endsWith('>>>\nPROPOSED COMMAND (already passed the scope + denylist gate):\nnmap -sV 10.10.11.5\nread-only: true  tier: passive'), jprompt);
  ok('judge prompt: no references, no operator free text', !jprompt.includes('REFERENCE NOTES') && !jprompt.includes('smbclient'));
  const noEng = run('Build judge prompt', { json: { ...pgOk, engagement: null, judgeModel: 'qwen3:8b' }, env })[0].json.judgePrompt;
  ok('judge prompt: the scope even without an engagement (LAB_ALLOWLIST)', noEng.split('\n')[2] === 'SCOPE (LAB_ALLOWLIST): 10.10.11.0/24, box.htb'
    && !noEng.includes('RULES OF ENGAGEMENT'), noEng);

  // the re-check after the judge: a window that closed while the models worked blocks the run
  const jpClosed = { ...judgeFor('qwen3:8b'), engagement: { ...E, window_end: '2020-01-01T00:00:00Z' } };
  const late = run('Apply judge decision', { json: { text: 'AUTHORIZE' }, nodesOut: { 'Build judge prompt': jpClosed }, env })[0].json;
  ok('re-check: the window closed meanwhile -> blocked, nothing staged', late.allowed === false && late.staged === '' && late.reasons.some((r) => r.startsWith('outside the engagement window')), late.reasons);
}

// ---- protected data: bounded on the way in, enforced by the policy gate and its re-check, in both prompts, on the page ----
{
  const env = { LAB_ALLOWLIST: '10.10.11.0/24', LAB_AUTORUN_READONLY: 'true' };
  const E = { name: 'ACME data', version: 5, scope_in: ['10.10.11.0/28'], prohibited: ['hydra'], protected_data: ['customers.csv'],
    roe: 'Stop on PII.', autorun_passive: true, autorun_active: false };
  const hook = (engagement) => ({ headers: { 'x-lab-secret': 's3cret' }, params: {}, query: {}, body: { task: 'Enumerate the web root', target: '10.10.11.5', engagement } });
  const define = (engagement) => run('Define task + target', { json: hook(engagement), executed: ['Console webhook'] })[0].json;
  const pd = (v) => define({ ...E, protected_data: v }).engagement.protected_data;
  const many = pd(Array.from({ length: 80 }, (_, i) => `export${i}.csv`));
  ok('define: protected_data keeps 64 entries of at most 256 characters, drops blanks; a string is no list', many.length === 64 && many[63] === 'export63.csv'
    && pd(['p'.repeat(300)])[0].length === 256 && JSON.stringify(pd([' ', ' customers.csv ', '', null])) === '["customers.csv"]'
    && JSON.stringify(pd('customers.csv')) === '[]' && JSON.stringify(pd(undefined)) === '[]', many);

  // the policy gate reads the list the console sent; without it the same commands auto-run
  const scope = run('Scope gate', { json: define(E), env })[0].json;
  const policy = (command, engagement = scope.engagement) => run('Policy gate', { json: { ...scope, engagement, proposal: { command, target: '10.10.11.5' } }, env })[0].json;
  const noList = { ...scope.engagement, protected_data: [] };
  const measured = 'curl -s http://10.10.11.5/backup/customers.csv -o customers.csv';
  const blocked = policy(measured).policy;
  ok('policy: the measured download is blocked with the reason (it auto-runs without the list); 1 entry in force', blocked.allowed === false
    && JSON.stringify(blocked.reasons) === '["command names protected data: customers.csv"]' && JSON.stringify(blocked.protectedData) === '["customers.csv"]'
    && blocked.protectedEntries === 1 && policy(measured, noList).policy.autoRun === true, blocked);
  const bulk = policy('wget -r -np http://10.10.11.5/files/');
  ok('policy: a recursive wget is allowed but waits for a human, the bulk reason first (it auto-runs without the list)', bulk.policy.allowed === true
    && bulk.policy.autoRun === false && bulk.policy.dataReview[0].startsWith('bulk retrieval while data is protected')
    && policy('wget -r -np http://10.10.11.5/files/', noList).policy.autoRun === true, bulk.policy);
  const robots = policy('curl -s http://10.10.11.5/robots.txt').policy;
  ok('policy: a command that names no protected data still auto-runs', robots.autoRun === true && robots.dataReview.length === 0 && robots.protectedEntries === 1, robots);
  const unreadable = policy('curl -s http://10.10.11.5/robots.txt', define({ ...E, protected_data: ['p'.repeat(300)] }).engagement).policy;
  ok('policy: an entry kept at 256 characters is still too long for the gate: refused, so every command waits for a human', unreadable.allowed === true
    && unreadable.autoRun === false && /^cannot check for protected data: the entry "p{40}" cannot be read \(longer than 128 characters\)$/.test(unreadable.dataReview[0]), unreadable.dataReview);

  // the judge cannot lift the wait: AUTHORIZE stages the vetted command for a human, and the page says why (no judge model
  // is named here, so the node uses its default)
  const jp = run('Build judge prompt', { json: bulk, env })[0].json;
  const judged = run('Apply judge decision', { json: { text: 'AUTHORIZE' }, nodesOut: { 'Build judge prompt': jp }, env })[0].json;
  ok('judge: AUTHORIZE with a dataReview line -> allowed, no auto-run, the vetted command staged', judged.allowed === true && judged.autoRun === false
    && judged.staged === 'wget -r -np http://10.10.11.5/files/', judged);
  const page = run('Result text (authorized)', { json: judged })[0].json;
  ok('result: the waiting page lists the dataReview lines', page.resultTitle === 'Authorized: waiting for your approval'
    && bulk.policy.dataReview.length > 0 && bulk.policy.dataReview.every((r) => page.resultMessage.includes('\n- ' + r)), page.resultMessage);
  // the re-check runs the same gate: an item that passed without the list is blocked once the engagement carries it
  const jpLate = { ...run('Build judge prompt', { json: policy(measured, noList), env })[0].json, engagement: scope.engagement };
  const late = run('Apply judge decision', { json: { text: 'AUTHORIZE' }, nodesOut: { 'Build judge prompt': jpLate }, env })[0].json;
  ok('re-check: protected data blocks after the judge too, nothing staged', late.allowed === false && late.staged === ''
    && late.reasons.includes('command names protected data: customers.csv'), late.reasons);

  // both prompts carry the list after PROHIBITED and before RULES, cut at 1000 characters; an empty list adds nothing
  const prompts = (engagement) => {
    const item = { ...scope, engagement, references: '', refCount: 0 };
    const pg = run('Policy gate', { json: { ...item, proposal: { command: 'curl -s http://10.10.11.5/robots.txt', target: '10.10.11.5' } }, env })[0].json;
    return [run('Build operator prompt', { json: item, env })[0].json.operatorPrompt, run('Build judge prompt', { json: pg, env })[0].json.judgePrompt];
  };
  const listed = prompts(define({ ...E, protected_data: ['customers.csv', '/backup/'] }).engagement);
  ok('prompts: operator and judge read the list after PROHIBITED, before RULES', listed.every((p) => p.includes('\nPROHIBITED: hydra\nPROTECTED DATA (do not read, download or copy): customers.csv, /backup/\nRULES:')), listed);
  const without = { ...E };
  delete without.protected_data;
  ok('prompts: no line for an empty list, byte for byte the prompts of an engagement without the key', prompts(without).every((p) => !p.includes('PROTECTED DATA'))
    && JSON.stringify(prompts({ ...E, protected_data: [] })) === JSON.stringify(prompts(without)) && JSON.stringify(prompts({ ...E, protected_data: [' '] })) === JSON.stringify(prompts(without)));
  const label = 'PROTECTED DATA (do not read, download or copy): ';
  const value = (p) => (p.split('\n').find((l) => l.startsWith(label)) || '').slice(label.length);
  const capped = prompts({ ...E, protected_data: Array.from({ length: 70 }, (_, i) => 'x'.repeat(38) + String(i).padStart(3, '0')) });
  ok('prompts: 70 entries of 41 characters -> a value of 1004 characters ending in " ...", the rules still follow',
    capped.every((p) => value(p).length === 1004 && value(p).endsWith(' ...') && p.includes(' ...\nRULES: Stop on PII.')), capped.map((p) => value(p).length));
  // a scope statement as long as the console allows is cut to make room: the lines the gate enforces stay whole
  const statement = 'Only the web tier at 10.10.11.0/28, no production data. '.repeat(80).slice(0, 3990);
  const longScope = prompts(define({ ...E, scope_statement: statement, protected_data: ['customers.csv', '/backup/'] }).engagement);
  ok('prompts: a scope statement of 3990 characters is cut, PROHIBITED, PROTECTED DATA and RULES stay whole in both prompts',
    longScope.every((p) => p.includes('\nSCOPE STATEMENT: ' + statement.slice(0, 3700)) && p.includes(' ...\nIN SCOPE: 10.10.11.0/28\nPROHIBITED: hydra\n'
      + label + 'customers.csv, /backup/\nRULES: Stop on PII.\n>>>')), longScope.map((p) => p.slice(-200)));
}

// ---- manual mode: the operator's command takes the same policy gate and judge, no model, no retrieval ----
{
  const env = { LAB_ALLOWLIST: '10.10.11.0/24' };
  const scope = run('Scope gate', { json: { task: 'Run the command the operator typed.', target: '10.10.11.5', source: 'console', requestedBy: 'admin', mode: 'manual',
    manualCommand: 'smbclient -N -L //10.10.11.5', operatorModel: '', judgeModel: '', engagement: null }, env })[0].json;
  const mp = run('Manual proposal', { json: scope })[0].json;
  ok('manual proposal: the typed command and target, rationale says who typed it', mp.proposal.command === 'smbclient -N -L //10.10.11.5' && mp.proposal.target === '10.10.11.5'
    && mp.proposal.rationale === 'typed by the operator (admin)' && mp.rawProposal === '', mp.proposal);
  const pg = run('Policy gate', { json: { ...mp, proposal: { ...mp.proposal, command: 'smbclient -N -L //10.10.11.5 ; curl http://evil.example/x' } }, env })[0].json;
  ok('manual: an out-of-scope host in the typed command is blocked like a proposal', pg.policy.allowed === false, pg.policy.reasons);
  const kids = (n, i) => (((wf.connections[n] || {}).main || [])[i] || []).map((c) => c.node);
  const into = (target) => Object.entries(wf.connections).flatMap(([src, c]) => (c.main || []).flatMap((outs, i) => outs.filter((o) => o.node === target).map(() => `${src}#${i}`)));
  ok('graph: In scope? (true) -> Manual command?', kids('In scope?', 0).join() === 'Manual command?');
  ok('graph: Manual command? true -> Manual proposal, false -> retrieval', kids('Manual command?', 0).join() === 'Manual proposal' && kids('Manual command?', 1).join() === 'Retrieve writeups (Qdrant)');
  ok('graph: Manual proposal -> Policy gate, and nowhere else', kids('Manual proposal', 0).join() === 'Policy gate' && (wf.connections['Manual proposal'].main.length === 1));
  ok('graph: the policy gate is fed by the operator path and the manual path only', JSON.stringify(into('Policy gate').sort()) === JSON.stringify(['Manual proposal#0', 'Parse proposal#0']), into('Policy gate'));
  ok('graph: Build judge prompt only after Policy passed? (true); the judge chain only after it', JSON.stringify(into('Build judge prompt')) === JSON.stringify(['Policy passed?#0'])
    && JSON.stringify(into('Judge: authorize?')) === JSON.stringify(['Build judge prompt#0']));
  ok('graph: the operator chain is fed only by Build operator prompt', JSON.stringify(into('Abliterated operator (suggest)')) === JSON.stringify(['Build operator prompt#0']));
}

console.log(failed ? `\n${failed} test(s) FAILED` : '\nall workflow tests passed');
process.exit(failed ? 1 : 0);
