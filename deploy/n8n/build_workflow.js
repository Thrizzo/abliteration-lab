/* Generates deploy/n8n/workflows/pentest-copilot.json - the importable n8n workflow.
 *
 *   node deploy/n8n/build_workflow.js            # regenerate after editing policy.js or copilot/operator_contract.json
 *   node deploy/n8n/build_workflow.js --check    # exit 1 if the committed workflow is out of date (CI / tests)
 *
 * Privilege split: the ABLITERATED model only SUGGESTS (text, no tools) -> deterministic POLICY gate (the boundary:
 * scope, denylist, auto-run tier, unverifiable targets, injection aimed at the judge) -> a REGULAR "judge" model
 * AUTHORIZEs or REJECTs -> the runner executes the POLICY-VETTED command, never text the judge produced.
 * Read-only recon auto-runs (passive tier); NSE default/version/banner + sqlmap-enumerate (risk 1) only with the active tier; else a human.
 *
 * Two ways in: the web form, and a webhook the lab console calls (header secret). The webhook answers at once with the
 * execution id; the console then follows the run through n8n's API. Console runs end without the form's result pages.
 * The operator is an OpenAI-compatible chat model: glm-serve (vLLM) on GPU clusters, Ollama's /v1 API in dev.
 *
 * policy.js is embedded verbatim into the Code nodes (n8n Code nodes cannot require local files), and the prompts come
 * from copilot/operator_contract.json, shared with the Python side (QLoRA pairs, eval), so the two cannot drift.
 * Every generated Code node is parsed at build time: a quoting slip fails here, not inside n8n. */
const fs = require('fs');
const path = require('path');

const HERE = __dirname;
const OUT = path.join(HERE, 'workflows', 'pentest-copilot.json');
const POLICY = fs.readFileSync(path.join(HERE, 'policy.js'), 'utf8');
const C = JSON.parse(fs.readFileSync(path.join(HERE, '..', '..', 'copilot', 'operator_contract.json'), 'utf8'));

// The console's engagement (scope statement, rules, scope, exclusions, window, prohibited tools, protected data) as the
// operator and the judge read it. Mirrored in copilot/contract.py (engagement_text); copilot/tests/test_contract.py renders
// both. Two parts share 4000 characters (a cut ends in ' ...'): the head (name, scope statement, scope, exclusions,
// window), then the tail (prohibited tools, the first 1000 characters of the protected data, rules), which holds what the
// policy gate enforces. When both do not fit, the tail keeps at least min(its length, 2000) characters, so a long scope
// statement or long scope lists cannot push it out of both prompts: the head makes room, its scope statement cut first
// (to no less than 200 characters), then its end. The tail gets what is left and loses its end, as the whole text did
// before. Text that fits, a long rules text after a short head and a text with only one part read exactly as before.
const ENGAGEMENT_TEXT = `const ENGAGEMENT_HEADER = ${JSON.stringify(C.engagement_header)};
function engagementText(e) {
  if (!e || typeof e !== 'object' || Array.isArray(e)) return '';
  const s = (v) => (v === undefined || v === null ? '' : String(v).trim());
  const joined = (v) => (Array.isArray(v) ? v : []).map(s).filter(Boolean).join(', ');
  const cap = (v, n) => (v.length <= n ? v : v.slice(0, n) + ' ...');
  const lines = (pairs) => pairs.filter((p) => p[1]).map((p) => p[0] + ': ' + p[1]).join('\\n');
  const when = s(e.window_start) || s(e.window_end) ? (s(e.window_start) || 'open') + ' to ' + (s(e.window_end) || 'open') : '';
  const head = (statement) => lines([['ENGAGEMENT', s(e.name) && s(e.name) + (s(e.version) ? ' (version ' + s(e.version) + ')' : '')],
    ['SCOPE STATEMENT', statement], ['IN SCOPE', joined(e.scope_in)], ['OUT OF SCOPE', joined(e.scope_out)], ['WINDOW', when]]);
  const tail = lines([['PROHIBITED', joined(e.prohibited)], ['PROTECTED DATA (do not read, download or copy)', cap(joined(e.protected_data), 1000)],
    ['RULES', s(e.roe)]]);
  const statement = s(e.scope_statement);
  let h = head(statement);
  if (!h || !tail || h.length + 1 + tail.length <= 4000) return cap([h, tail].filter(Boolean).join('\\n'), 4000);
  const room = 4000 - 1 - Math.min(tail.length, 2000);           // the most the head may take
  if (h.length > room) {
    const keep = Math.max(200, statement.length - (h.length - room) - 4);
    if (keep + 4 < statement.length) h = head(statement.slice(0, keep) + ' ...');
    if (h.length > room) h = h.slice(0, room - 4) + ' ...';
  }
  return h + '\\n' + cap(tail, 4000 - 1 - h.length);
}`;
// A model name that marks an abliterated model ("glm-abl", "<slug>-abl" from the pipeline, "...-abliterated",
// "uncensored"): never the judge. Mirrored in app/copilot_runs.py (ABLITERATED).
const ABLITERATED = '/(^|[-_:./])abl($|[-_:./])|abliterat|uncensor/i';
const LABENV = `const labEnv = (k, d) => { let v; try { v = $env[k]; } catch (e) { throw new Error('n8n blocks $env in Code nodes (N8N_BLOCK_ENV_ACCESS_IN_NODE is not "false"). Set N8N_BLOCK_ENV_ACCESS_IN_NODE=false for this n8n (deploy/n8n/docker-compose.n8n.yml does) so the copilot can read ' + k + '. Failing closed instead of guessing a scope.'); } return (v === undefined || v === null || v === '') ? d : String(v); };`;
const nodes = [];
const connections = {};
const conn = (from, to, type = 'main', outIndex = 0) => {
  connections[from] = connections[from] || {};
  connections[from][type] = connections[from][type] || [];
  while (connections[from][type].length <= outIndex) connections[from][type].push([]);
  connections[from][type][outIndex].push({ node: to, type, index: 0 });
};
const add = (n) => { nodes.push(n); return n.name; };
const COL = 240; // x spacing between stages
const x = (c) => -680 + c * COL;
const boolIf = (name, col, expr) => add({
  name, type: 'n8n-nodes-base.if', typeVersion: 2.2, position: [x(col), 200],
  parameters: { conditions: { options: { caseSensitive: true, typeValidation: 'strict', version: 2 }, combinator: 'and',
    conditions: [{ id: 'c1', operator: { type: 'boolean', operation: 'true', singleValue: true }, leftValue: `={{ ${expr} }}`, rightValue: '' }] } },
});
const code = (name, col, js, row = 200) => add({ name, type: 'n8n-nodes-base.code', typeVersion: 2, position: [x(col), row], parameters: { jsCode: js } });
const ollama = (name, col, model, extra = {}) => add({ name, type: '@n8n/n8n-nodes-langchain.lmChatOllama', typeVersion: 1, position: [x(col), 440], parameters: { model, options: { temperature: 0, ...extra } } });
// OpenAI-compatible chat model: vLLM and Ollama both serve /v1/chat/completions. responsesApiEnabled must be false:
// it defaults to true in v1.3 and would call OpenAI's Responses API instead, which neither server needs to offer.
const openAiCompatible = (name, col, model, extra = {}) => add({ name, type: '@n8n/n8n-nodes-langchain.lmChatOpenAi', typeVersion: 1.3,
  position: [x(col), 440], parameters: { model: { __rl: true, mode: 'id', value: model }, responsesApiEnabled: false, options: { temperature: 0, ...extra } } });
const chain = (name, col, text, sys) => add({
  name, type: '@n8n/n8n-nodes-langchain.chainLlm', typeVersion: 1.6, position: [x(col), 200],
  parameters: { promptType: 'define', text, messages: { messageValues: [{ message: sys }] } },
});

// 0 input: a web form (Task + Target) --------------------------------------------------------
// Published: http://localhost:5678/form/pentest-copilot. In the editor, "Execute workflow" opens the same form as a test.
// Two separate fields on purpose: the scope gate checks one exact target, never a target guessed out of free text.
const FORM_PATH = 'pentest-copilot';
add({ name: 'Copilot form', type: 'n8n-nodes-base.formTrigger', typeVersion: 2.6, position: [x(0), 200], webhookId: 'b7e4c0de-7f3a-4c1e-9a52-3c0f1e2d4a11',
  parameters: {
    formTitle: 'Pentest lab copilot',
    formDescription: 'The abliterated model suggests one command for an in-scope lab target. The policy gate and a regular judge decide what happens to it. Nothing runs from this page.',
    formFields: { values: [
      { fieldLabel: 'Task', fieldName: 'task', fieldType: 'textarea', placeholder: 'Enumerate SMB on the box and suggest the next step.', requiredField: true },
      { fieldLabel: 'Target', fieldName: 'target', fieldType: 'text', placeholder: '10.10.10.5 or box.htb (must be in LAB_ALLOWLIST)', requiredField: true },
    ] },
    responseMode: 'lastNode',   // n8n switches to its multi-page flow on its own, because Form pages follow
    options: { path: FORM_PATH, buttonLabel: 'Ask the copilot', appendAttribution: false },
  } });
// 0b input: the lab console. POST with the shared secret in X-Lab-Secret (Header Auth credential):
//   {task, target, requested_by, mode: "copilot" | "manual", command (manual mode), operator_model, judge_model,
//    engagement: {name, version, scope_statement, roe, scope_in, scope_out, window_start, window_end, prohibited,
//                 protected_data, autorun_passive, autorun_active}}
// It answers at once with the execution id, then the same pipeline runs; the console follows it through n8n's API
// (GET /api/v1/executions/{id}?includeData=true) and can stop it (POST .../stop).
const WEBHOOK_PATH = 'copilot-run';
add({ name: 'Console webhook', type: 'n8n-nodes-base.webhook', typeVersion: 2.2, position: [x(0), 0], webhookId: 'c0de7a1e-5e11-4b6a-9d2c-7f3e8a9b0c55',
  parameters: { httpMethod: 'POST', path: WEBHOOK_PATH, authentication: 'headerAuth', responseMode: 'responseNode', options: {} } });
add({ name: 'Respond: execution id', type: 'n8n-nodes-base.respondToWebhook', typeVersion: 1.5, position: [x(0) + 120, 0],
  parameters: { respondWith: 'json', responseBody: '={{ { "execution_id": $execution.id } }}', options: { responseCode: 202 } } });
conn('Console webhook', 'Respond: execution id');
// Everything that arrives is bounded and typed here (and the webhook's headers, the secret included, stay behind). Form
// runs have the web form's two fields and nothing else: copilot mode, no engagement, the models from the environment.
// Protected-data entries keep 256 characters, twice what the policy gate reads: a longer entry stays too long, so the
// gate refuses it (every command then waits for a human) instead of enforcing a cut-off name that misses the listed one.
code('Define task + target', 1, `
const body = $json.body && typeof $json.body === 'object' && !Array.isArray($json.body) ? $json.body : null;
let ran; try { ran = $('Console webhook').isExecuted; } catch (e) { ran = undefined; }
const fromConsole = ran === true || (ran === undefined && !!($json.headers && body));
const src = fromConsole ? (body || {}) : $json;
const str = (v, n) => String(v ?? '').trim().slice(0, n);
const list = (v, n) => (Array.isArray(v) ? v : []).map((x) => str(x, n)).filter(Boolean).slice(0, 64);
const model = (v) => (/^[A-Za-z0-9][\\w.:\\/-]{0,127}$/.test(String(v ?? '')) ? String(v) : '');
const mode = fromConsole && src.mode === 'manual' ? 'manual' : 'copilot';
const e = fromConsole && src.engagement && typeof src.engagement === 'object' && !Array.isArray(src.engagement) ? src.engagement : null;
const engagement = e ? { name: str(e.name, 120), version: Number.isInteger(e.version) ? e.version : null,
  scope_statement: str(e.scope_statement, 4000), roe: str(e.roe, 8000), scope_in: list(e.scope_in, 253), scope_out: list(e.scope_out, 253),
  prohibited: list(e.prohibited, 64), protected_data: list(e.protected_data, 256),
  window_start: str(e.window_start, 40) || null, window_end: str(e.window_end, 40) || null,
  autorun_passive: e.autorun_passive === true, autorun_active: e.autorun_active === true } : null;
const task = str(src.task, 2000) || (mode === 'manual' ? 'Run the command the operator typed.' : '');
// a typed command over the gate's 2000-character limit goes on cut, with ' ...' after the cut: the gate still sees more than
// 2000 characters and blocks it. A plain cut would stage a prefix the operator never typed (the gate trims what the cut
// leaves, so 'nmap ... <spaces>; id' would arrive as 'nmap ...').
const typed = (v) => { const c = String(v ?? '').trim(); return c.length > 2000 ? c.slice(0, 2000) + ' ...' : c; };
return [{ json: { task, target: str(src.target, 253), source: fromConsole ? 'console' : 'form', requestedBy: fromConsole ? str(src.requested_by, 120) : '',
  mode, manualCommand: mode === 'manual' ? typed(src.command) : '', operatorModel: fromConsole ? model(src.operator_model) : '',
  judgeModel: fromConsole ? model(src.judge_model) : '', engagement } }];`);
conn('Copilot form', 'Define task + target');
conn('Respond: execution id', 'Define task + target');

// 1 scope gate: LAB_ALLOWLIST (the ceiling) and the engagement's scope, exclusions and window ------------------------
code('Scope gate', 2, `${POLICY}
${LABENV}
const ALLOWLIST = labEnv('LAB_ALLOWLIST', '10.10.10.0/24,192.168.56.0/24,127.0.0.1').split(',').map(s=>s.trim()).filter(Boolean);
const cfg = engagementConfig($json.engagement, { allowlist: ALLOWLIST });
const why = scopeWhy($json.target, cfg);
const win = windowCheck(cfg.window);
const scopeOk = !why && win.open;
const scopeReason = why ? \`target "\${$json.target}" is \${SCOPE_WHY[why]}\` : (win.open ? 'in scope' : win.reason);
return [{ json: { ...$json, allowlist: ALLOWLIST, scopeOk, scopeReason,
  scopeBy: (cfg.scopeIn || []).length ? 'LAB_ALLOWLIST and the engagement scope' : 'LAB_ALLOWLIST' } }];`);
conn('Define task + target', 'Scope gate');
boolIf('In scope?', 3, '$json.scopeOk');
conn('Scope gate', 'In scope?');

// 1a manual mode: the operator typed the command. No retrieval, no abliterated model: straight to the policy gate and
// the judge, which treat it exactly like a proposal.
boolIf('Manual command?', 4, '$json.mode === "manual"');
conn('In scope?', 'Manual command?', 'main', 0);
code('Manual proposal', 9, `
const j = $json;
return [{ json: { ...j, proposal: { command: j.manualCommand, target: j.target, rationale: 'typed by the operator' + (j.requestedBy ? ' (' + j.requestedBy + ')' : '') }, rawProposal: '' } }];`, -40);
conn('Manual command?', 'Manual proposal', 'main', 0);

// 1b retrieval: past writeups from Qdrant (RAG). Background DATA for the operator only; never reaches the judge. ---
add({
  name: 'Retrieve writeups (Qdrant)', type: '@n8n/n8n-nodes-langchain.vectorStoreQdrant', typeVersion: 1.4, position: [x(5), 200],
  alwaysOutputData: true, onError: 'continueRegularOutput',     // empty or unreachable store -> copilot still runs, without references
  parameters: { mode: 'load', qdrantCollection: { __rl: true, value: 'writeups', mode: 'id' },
    prompt: '={{ $json.task + " " + $json.target }}', topK: 4, includeDocumentMetadata: true, options: {} },
});
add({ name: 'Embeddings: Ollama', type: '@n8n/n8n-nodes-langchain.embeddingsOllama', typeVersion: 1, position: [x(5), 440],
  parameters: { model: 'nomic-embed-text' } });
conn('Manual command?', 'Retrieve writeups (Qdrant)', 'main', 1);
conn('Embeddings: Ollama', 'Retrieve writeups (Qdrant)', 'ai_embedding');
code('Build reference context', 6, `
// Retrieved chunks are DATA from past writeups: bounded, labelled with their source, handed to the abliterated
// operator as background only. They are dropped after the operator, so they never reach the judge.
const base = $('Scope gate').first().json;
const MAX_TOTAL = 3500, MAX_EACH = 1200;
// Addresses and host names in past writeups belong to OTHER machines, and a small model copies them verbatim (measured:
// with a reference note in context the operator proposed 'nmap -p- -T4 192.168.50.10', the note's IP, not the target).
// Replace them before the operator sees the text: the technique survives, the wrong address does not.
// Mirrored in copilot/contract.py (neutral); both are checked against copilot/tests/fixtures/neutral_vectors.json.
const neutral = (t) => String(t)
  .replace(/<IP_\\d+>/g, '<other-host-ip>')            // scrubbed engagement notes carry <IP_n>/<HOST_n> placeholders
  .replace(/<HOST_\\d+>/g, '<other-host>')
  .replace(/(?<![\\w.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\w.]*\\d)/g, (m) => (m.split('.').every((o) => Number(o) <= 255) ? '<other-host-ip>' : m))
  .replace(/\\b(?:[a-z0-9-]+\\.)+(?:htb|thm|vl|local|lab|lan|internal|corp|offsec)\\b/gi, '<other-host>');
const items = $input.all().map(i => i.json || {});
const err = items.find(j => j.error);
let used = 0; const refs = [];
for (const j of items) {
  const doc = j.document; if (!doc || !doc.pageContent) continue;
  const md = doc.metadata || {};
  const text = neutral(doc.pageContent).slice(0, MAX_EACH);
  if (used + text.length > MAX_TOTAL) break;
  used += text.length;
  refs.push('[ref ' + (refs.length + 1) + ' | ' + (md.source || '?') + ' | ' + (md.doc || '') + ' | score ' + (typeof j.score === 'number' ? j.score.toFixed(2) : '?') + ']\\n' + text);
}
const errMsg = err ? String((err.error && err.error.message) || err.error).slice(0, 200) : '';
// with onError=continueRegularOutput n8n passes the INPUT item through untouched when the store is down; a real
// empty result is {} (alwaysOutputData). So an item that still carries the scope-gate fields means retrieval failed.
const passthrough = !err && items.some((j) => !j.document && (j.scopeOk !== undefined || j.task !== undefined));
return [{ json: { ...base, references: refs.join('\\n\\n'), refCount: refs.length,
  ragStatus: err ? 'retrieval failed: ' + errMsg : (refs.length ? 'ok' : (passthrough ? 'retrieval failed (store unreachable or misconfigured - see the Retrieve writeups node error); running without references' : 'no matches')) } }];`);
conn('Retrieve writeups (Qdrant)', 'Build reference context');

// 2 abliterated operator (suggest only; no tools) --------------------------------------------
// The prompt is built in a Code node, so the console can show exactly what went to the model. User message format
// mirrored in copilot/contract.py (operator_messages); copilot/tests/test_contract.py renders both.
code('Build operator prompt', 7, `${LABENV}
${ENGAGEMENT_TEXT}
const j = $json;
const rules = engagementText(j.engagement);
const operatorPrompt = 'TASK: ' + j.task + '\\nTARGET (authorized, in scope): ' + j.target
  + (rules ? '\\n\\n' + ENGAGEMENT_HEADER + '\\n<<<\\n' + rules + '\\n>>>' : '')
  + (j.refCount ? '\\n\\n' + ${JSON.stringify(C.reference_header)} + '\\n<<<\\n' + j.references + '\\n>>>' : '');
// the console's choice, else COPILOT_OPERATOR_MODEL (glm-serve serves glm-abl, which Promote points at a run)
return [{ json: { ...j, operatorModel: j.operatorModel || labEnv('COPILOT_OPERATOR_MODEL', 'glm-abl'), operatorPrompt } }];`);
conn('Build reference context', 'Build operator prompt');
openAiCompatible('Operator model (OpenAI-compatible)', 8, '={{ $json.operatorModel || $env.COPILOT_OPERATOR_MODEL || "glm-abl" }}');
chain('Abliterated operator (suggest)', 8, '={{ $json.operatorPrompt }}', C.operator_system);
conn('Build operator prompt', 'Abliterated operator (suggest)');
conn('Operator model (OpenAI-compatible)', 'Abliterated operator (suggest)', 'ai_languageModel');

// 3 parse proposal (abliterated output = data) -----------------------------------------------
// Based on the scope gate's item, not the prompt's: the references (and the prompt that carries them) stay behind and
// never reach the judge.
code('Parse proposal', 9, `
const raw = String($json.text ?? $json.output ?? $json.response ?? '');
let proposal = { command: '', target: $('Define task + target').first().json.target, rationale: '' };
const m = raw.match(/\\{[\\s\\S]*\\}/);
if (m) { try { const p = JSON.parse(m[0]); proposal = { command: String(p.command||''), target: String(p.target||proposal.target), rationale: String(p.rationale||'') }; } catch(e){} }
if (!proposal.command) { const line = (raw.match(/\`\`\`(?:bash|sh)?\\n([\\s\\S]*?)\`\`\`/)||[])[1] || raw.split('\\n').map(s=>s.trim()).find(Boolean) || ''; proposal.command = line.trim(); }
return [{ json: { ...$('Scope gate').first().json, operatorModel: $('Build operator prompt').first().json.operatorModel, proposal, rawProposal: raw } }];`);
conn('Abliterated operator (suggest)', 'Parse proposal');

// 4 policy gate (deterministic boundary): LAB_ALLOWLIST and LAB_AUTORUN_* narrowed by the engagement ----------------
const POLICY_CONFIG = `const policyConfig = (j) => engagementConfig(j.engagement, { allowlist: j.allowlist,
  autoRunReadOnly: labEnv('LAB_AUTORUN_READONLY', 'false') === 'true', autoRunActiveRecon: labEnv('LAB_AUTORUN_ACTIVE_RECON', 'false') === 'true' });`;
code('Policy gate', 10, `${POLICY}
${LABENV}
${POLICY_CONFIG}
const d = decide($json.proposal, policyConfig($json));
return [{ json: { ...$json, policy: d } }];`);
conn('Parse proposal', 'Policy gate');
conn('Manual proposal', 'Policy gate');
boolIf('Policy passed?', 11, '$json.policy.allowed');
conn('Policy gate', 'Policy passed?');

// 5 judge (regular model) authorizes or rejects ----------------------------------------------
// Its prompt is built in a Code node too (the console shows it), and that node refuses an abliterated judge: the model
// that can veto the operator must not be the operator. Mirrored in copilot/contract.py (judge_user).
code('Build judge prompt', 12, `${LABENV}
${ENGAGEMENT_TEXT}
const j = $json, pol = j.policy || {};
const operatorModel = j.operatorModel || labEnv('COPILOT_OPERATOR_MODEL', 'glm-abl');
const judgeModel = j.judgeModel || labEnv('COPILOT_JUDGE_MODEL', 'qwen3:8b');
if (${ABLITERATED}.test(judgeModel) || judgeModel === operatorModel) {
  throw new Error('judge model "' + judgeModel + '" refused: the judge must be a regular model, never the abliterated operator. Choose another judge in the console.');
}
const rules = engagementText(j.engagement);
// the scope always (LAB_ALLOWLIST, already enforced by the gates): the judge weighs the command against it and the rules
const scope = (Array.isArray(j.allowlist) ? j.allowlist : []).map((x) => String(x ?? '').trim()).filter(Boolean).join(', ');
const judgePrompt = 'TASK: ' + j.task + '\\nTARGET: ' + pol.target + (scope ? '\\nSCOPE (LAB_ALLOWLIST): ' + scope : '')
  + (rules ? '\\n' + ENGAGEMENT_HEADER + '\\n<<<\\n' + rules + '\\n>>>' : '')
  + '\\nPROPOSED COMMAND (already passed the scope + denylist gate):\\n' + pol.command + '\\nread-only: ' + (pol.readOnly ? 'true' : 'false') + '  tier: ' + (pol.tier || 'none');
return [{ json: { ...j, judgeModel, judgePrompt } }];`);
conn('Policy passed?', 'Build judge prompt', 'main', 0);
// think: false. Ollama switches thinking ON for thinking-capable models (qwen3) when a request leaves it unset, so every
// verdict would first generate a hidden reasoning trace: minutes per call on a CPU, and Qwen advises against greedy
// decoding (temperature 0) in thinking mode. A one-word veto needs no trace; on non-thinking models the flag is a no-op.
ollama('Ollama: judge model (regular)', 13, '={{ $json.judgeModel || $env.COPILOT_JUDGE_MODEL || "qwen3:8b" }}', { think: false });
chain('Judge: authorize?', 13, '={{ $json.judgePrompt }}', C.judge_system);
conn('Build judge prompt', 'Judge: authorize?');
conn('Ollama: judge model (regular)', 'Judge: authorize?', 'ai_languageModel');

// 6 apply judge verdict + final boundary re-check --------------------------------------------
// the re-check runs the same gate again (the engagement window may have closed while the models worked); "staged" is
// the command the Execute node would get: always the policy-vetted one, never text the judge produced
code('Apply judge decision', 14, `${POLICY}
${LABENV}
${POLICY_CONFIG}
const p = $('Build judge prompt').first().json;
const verdict = String($json.text ?? $json.output ?? '').trim();
const authorized = /^\\s*authorize\\b/i.test(verdict);
const recheck = decide(p.proposal || { command: p.policy.command, target: p.policy.target }, policyConfig(p));
const allowed = p.policy.allowed && recheck.allowed && authorized;
const autoRun = allowed && p.policy.autoRun && recheck.autoRun;
return [{ json: { ...p, judgeVerdict: verdict, judgeAuthorized: authorized, allowed, autoRun, tier: recheck.tier,
  staged: allowed ? p.policy.command : '',
  reasons: [ ...(p.policy.reasons||[]), ...(recheck.reasons||[]), ...(authorized?[]:['judge rejected: '+verdict]) ] } }];`);
conn('Judge: authorize?', 'Apply judge decision');
boolIf('Authorized?', 15, '$json.allowed');
conn('Apply judge decision', 'Authorized?');

// 7 result page: what the form shows ---------------------------------------------------------
// Everything from the form or a model is HTML-escaped here. n8n also sanitizes and sandboxes the page, but its sanitizer
// keeps links, images and iframes, and it would strip a "<other-host-ip>" placeholder out of a command: the page must
// show the exact command, and model text must never become markup. Blocked runs end on their own page; authorized runs
// show theirs and then continue to the auto-run split, so a blocked item can never reach Human approval or Execute.
const RESULT = `
const j = $json, pol = j.policy || {}, prop = j.proposal || {};
// n8n's completion page turns a literal backslash-n into a line break; doubling that backslash keeps it literal
const esc = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/\\\\(?=n)/g, '\\\\\\\\');
const cut = (s, n) => { s = String(s ?? ''); return s.length > n ? s.slice(0, n) + ' ...' : s; };
let rag = '';
try { rag = String($('Build reference context').first().json.ragStatus || ''); } catch (e) { rag = ''; }   // not run when blocked by scope
const reasons = [];
let title, next;
if (j.scopeOk === false) {
  title = 'Blocked: target out of scope';
  reasons.push(j.scopeReason || 'target not in LAB_ALLOWLIST');
  next = /LAB_ALLOWLIST/.test(j.scopeReason || 'LAB_ALLOWLIST') ? 'No model was called. If the target belongs to your lab, add it to LAB_ALLOWLIST.'
    : 'No model was called. The engagement in the console decides this: change its scope or window if the target belongs to it.';
} else if (j.judgeVerdict === undefined && pol.allowed === false) {
  title = 'Blocked by the policy gate';
  reasons.push(...(pol.reasons || []));
  next = 'Nothing runs, and the judge never saw it.';
} else if (j.judgeVerdict !== undefined && j.allowed !== true) {
  title = j.judgeAuthorized === false ? 'Blocked: the judge rejected it' : 'Blocked by the policy re-check';
  reasons.push(...(j.reasons || []));
  next = 'Nothing runs.';
} else if (j.allowed !== true) {          // fail-safe: anything not explicitly allowed is never shown as authorized
  title = 'Blocked';
  reasons.push(...(pol.reasons || []), ...(j.reasons || []));
  next = 'Nothing runs.';
} else if (j.autoRun === true) {
  title = 'Authorized: auto-run (' + (j.tier || 'recon') + ' tier)';
  next = 'Handed to the Execute node. It stays disabled until you set LAB_RUNNER_URL and enable it, so nothing ran.';
} else {
  title = 'Authorized: waiting for your approval';
  if (pol.injectionSuspected) reasons.push('text aimed at the judge: ' + (pol.injectionHits || []).join(', '));
  if ((pol.dataReview || []).length) reasons.push(...pol.dataReview);
  if ((pol.unverifiable || []).length) reasons.push('target the gate cannot verify: ' + pol.unverifiable.join('; '));
  if (pol.namesInScopeHost === false) reasons.push('the command names no in-scope host');
  if (!pol.readOnly) reasons.push('not in an enabled auto-run tier' + (pol.readOnlyReason ? ': ' + pol.readOnlyReason : ''));
  next = 'Parked at the Human approval node. Nothing runs until that run is resumed, and the Execute node is disabled.';
}
const cmd = pol.command || prop.command || '';
const L = ['<b>Target:</b> <code>' + esc(cut(j.target, 200)) + '</code>'];
if (j.task) L.push('<b>Task:</b> ' + esc(cut(j.task, 400)));
if (cmd) L.push('<b>Suggested command:</b> <code>' + esc(cut(cmd, 800)) + '</code>');
if (prop.rationale) L.push('<b>Operator rationale:</b> ' + esc(cut(prop.rationale, 400)));
if (j.judgeVerdict !== undefined) L.push('<b>Judge:</b> ' + (esc(cut(j.judgeVerdict, 300)) || '(empty answer)'));
if (reasons.length) L.push('<b>Reasons:</b>\\n' + reasons.slice(0, 8).map((r) => '- ' + esc(cut(r, 300))).join('\\n'));
if (rag) L.push('<b>References:</b> ' + esc(rag));
L.push('<b>Next:</b> ' + esc(next));
return [{ json: { ...j, resultTitle: title, resultMessage: L.join('\\n\\n') } }];`;
const resultPage = (name, col, row, webhookId) => add({ name, type: 'n8n-nodes-base.form', typeVersion: 2.5, position: [x(col), row], webhookId,
  parameters: { operation: 'completion', respondWith: 'text', completionTitle: '={{ $json.resultTitle }}', completionMessage: '={{ $json.resultMessage }}', options: {} } });

code('Result text (authorized)', 16, RESULT);
// form runs end on a result page; console runs have no page to show (the console renders the result itself)
const formRun = (name, col, row) => { boolIf(name, col, '$json.source !== "console"'); nodes[nodes.length - 1].position[1] = row; return name; };
formRun('Form run? (authorized)', 16.5, 200);
resultPage('Result page: authorized', 17, 200, '5d2f9a64-1b7e-4f0c-8e3a-6a9b0c1d2e33');
conn('Authorized?', 'Result text (authorized)', 'main', 0);
conn('Result text (authorized)', 'Form run? (authorized)');
conn('Form run? (authorized)', 'Result page: authorized', 'main', 0);

// 8 auto-run split + human approval + execute ------------------------------------------------
boolIf('Auto-run (recon tier)?', 18, '$json.autoRun');
conn('Result page: authorized', 'Auto-run (recon tier)?');
conn('Form run? (authorized)', 'Auto-run (recon tier)?', 'main', 1);
add({ name: 'Human approval', type: 'n8n-nodes-base.wait', typeVersion: 1.1, position: [x(19), 360], webhookId: 'pentest-approval', parameters: { resume: 'webhook', options: {} } });
conn('Auto-run (recon tier)?', 'Human approval', 'main', 1);
add({ name: 'Execute on lab target (DISABLED)', type: 'n8n-nodes-base.httpRequest', typeVersion: 4.2, position: [x(20), 200], disabled: true,
  parameters: { method: 'POST', url: '={{ $env.LAB_RUNNER_URL }}', sendBody: true, specifyBody: 'json',
    jsonBody: '={{ { "command": $json.policy.command, "target": $json.policy.target, "autoRun": $json.autoRun, "tier": $json.tier } }}', options: {} } });
conn('Auto-run (recon tier)?', 'Execute on lab target (DISABLED)', 'main', 0);
conn('Human approval', 'Execute on lab target (DISABLED)');

// blocked terminals: each ends on the blocked result page ---------------------------------------
code('Result text (blocked)', 16, RESULT, 640);
formRun('Form run? (blocked)', 16.5, 640);
resultPage('Result page: blocked', 17, 640, '9e1c7b20-4d5a-4a8f-b6c3-2f0e1d9a8b44');
conn('Result text (blocked)', 'Form run? (blocked)');
conn('Form run? (blocked)', 'Result page: blocked', 'main', 0);      // console runs end here (false branch: nothing)
[['In scope?', 'out of scope', 3], ['Policy passed?', 'policy', 11], ['Authorized?', 'judge rejected', 15]].forEach(([src, label, col]) => {
  const name = `Blocked (${label})`;
  add({ name, type: 'n8n-nodes-base.noOp', typeVersion: 1, position: [x(col), 640] });
  conn(src, name, 'main', 1);
  conn(name, 'Result text (blocked)');
});

// sticky notes --------------------------------------------------------------------------------
const notes = [
  [x(0) - 20, 40, 360, 120, '#2E86DE', '1 - Input (web form)\nTask + one Target. Once published: http://localhost:5678/form/' + FORM_PATH + '. In the editor, Execute workflow opens a test form.'],
  [x(0) - 20, -230, 360, 210, '#2E86DE', '1b - Input (lab console)\nPOST /webhook/' + WEBHOOK_PATH + ' with the X-Lab-Secret header (Header Auth credential): task, target, mode (copilot | manual + command), operator and judge model, and the engagement (scope, exclusions, window, prohibited tools, protected data, rules). Answers at once with the execution id; the console follows the run through the n8n API. Console runs skip the result pages.'],
  [x(2) - 20, 40, 220, 150, '#10AC84', '2 - Scope gate (code)\nTarget must be in LAB_ALLOWLIST (the ceiling) AND the engagement scope, not excluded, inside the engagement window - before any model runs.'],
  [x(4) - 20, -230, 460, 150, '#F79F1F', '2a - Manual command\nThe operator typed the command in the console: no retrieval, no abliterated model. It goes through the same policy gate and judge as a proposal.'],
  [x(5) - 20, 40, 460, 120, '#2E86DE', '2b - Retrieval (RAG)\nTop-4 chunks from past writeups (Qdrant, collection writeups) as bounded background for the operator only; their addresses are neutralized. Empty/unreachable store -> runs without references.'],
  [x(7) - 20, 40, 460, 150, '#8854D0', '3 - Abliterated operator\nBuild operator prompt (task, target, rules of engagement, references) -> the model the console chose (glm-serve). SUGGESTS ONLY: no tools, it can never run a command.'],
  [x(10) - 20, 560, 300, 290, '#10AC84', '4 - Policy gate (code)\nThe real boundary: scope (LAB_ALLOWLIST + engagement), denylist, the engagement\'s prohibited tools and window, auto-run tier (variable AND engagement), targets it cannot verify (placeholders, $VARS, -iL, integer/hex IPs, IPv6) and text aimed at the judge: those never auto-run and go to a human. Protected data: a command that names a listed file, folder, share or table is blocked; bulk retrieval and names read at run time wait for a human while the list has entries.'],
  [x(12) - 20, 40, 460, 190, '#EE5253', '5 - Judge (regular model)\nBuild judge prompt refuses an abliterated judge. AUTHORIZE or REJECT the vetted command against the rules of engagement. Veto-only: the runner always executes policy.command, so a judge talked into AUTHORIZE (measured: it happens) cannot widen scope.'],
  [x(16) - 20, 380, 440, 170, '#2E86DE', '6 - Result page (form)\nShows the suggestion, the policy decision, the judge verdict and the next step. Form and model text are HTML-escaped; n8n also sanitizes the page. Blocked runs end here; authorized runs continue to the auto-run split.'],
  [x(18) - 20, -70, 480, 150, '#F79F1F', '7 - Auto-run + Execute\nRecon that cleared every gate auto-runs (LAB_AUTORUN_READONLY; add LAB_AUTORUN_ACTIVE_RECON for NSE default/version/banner + sqlmap-enumerate at risk 1). Else -> Human approval (Wait). Execute DISABLED on import: set LAB_RUNNER_URL and enable it.'],
];
notes.forEach(([px, py, w, h, color, content], i) => add({ name: `note${i}`, type: 'n8n-nodes-base.stickyNote', typeVersion: 1, position: [px, py], parameters: { width: w, height: h, color, content } }));

for (const n of nodes.filter((n) => n.type === 'n8n-nodes-base.code')) {
  try { new Function('$input', '$json', '$', '$env', n.parameters.jsCode); }
  catch (e) { throw new Error(`generated Code node "${n.name}" does not parse: ${e.message}`); }
}
// saveExecutionProgress: n8n otherwise stores a run's node results only when it ends, and the console follows a run
// live through the executions API (one event per finished node)
const workflow = { name: 'Pentest lab copilot (RAG + abliterated suggests, regular judge authorizes, runner executes)', nodes, connections, settings: { executionOrder: 'v1', saveExecutionProgress: true }, active: false };
const json = JSON.stringify(workflow, null, 2) + '\n';

if (process.argv.includes('--check')) {
  const current = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8') : '';
  if (current !== json) {
    console.error(`${path.relative(process.cwd(), OUT)} is out of date with policy.js / copilot/operator_contract.json: run node deploy/n8n/build_workflow.js`);
    process.exit(1);
  }
  console.log('workflow is up to date');
} else {
  fs.writeFileSync(OUT, json);
  console.log('wrote', path.relative(process.cwd(), OUT), '-', nodes.length, 'nodes');
}
