/* Generates deploy/n8n/workflows/pentest-copilot.json - the importable n8n workflow.
 *
 *   node deploy/n8n/build_workflow.js            # regenerate after editing policy.js or copilot/operator_contract.json
 *   node deploy/n8n/build_workflow.js --check    # exit 1 if the committed workflow is out of date (CI / tests)
 *
 * Privilege split: the ABLITERATED model only SUGGESTS (text, no tools) -> deterministic POLICY gate (the boundary:
 * scope, denylist, auto-run tier, unverifiable targets, injection aimed at the judge) -> a REGULAR "judge" model
 * AUTHORIZEs or REJECTs -> the runner executes the POLICY-VETTED command, never text the judge produced.
 * Read-only recon auto-runs (passive tier); safe NSE + sqlmap-enumerate only with the active tier; else a human.
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
// 0b input: the lab console. POST {task, target, requested_by} with the shared secret in X-Lab-Secret (Header Auth
// credential). It answers at once with the execution id, then the same pipeline runs; the console follows it through
// n8n's API (GET /api/v1/executions/{id}?includeData=true) and can stop it (POST .../stop).
const WEBHOOK_PATH = 'copilot-run';
add({ name: 'Console webhook', type: 'n8n-nodes-base.webhook', typeVersion: 2.2, position: [x(0), 0], webhookId: 'c0de7a1e-5e11-4b6a-9d2c-7f3e8a9b0c55',
  parameters: { httpMethod: 'POST', path: WEBHOOK_PATH, authentication: 'headerAuth', responseMode: 'responseNode', options: {} } });
add({ name: 'Respond: execution id', type: 'n8n-nodes-base.respondToWebhook', typeVersion: 1.5, position: [x(0) + 120, 0],
  parameters: { respondWith: 'json', responseBody: '={{ { "execution_id": $execution.id } }}', options: { responseCode: 202 } } });
conn('Console webhook', 'Respond: execution id');
add({ name: 'Define task + target', type: 'n8n-nodes-base.set', typeVersion: 3.4, position: [x(1), 200],
  parameters: { assignments: { assignments: [
    // console runs bring their fields in the request body, form runs as top-level fields
    { id: 'a1', name: 'task', type: 'string', value: '={{ String(($json.body ? $json.body.task : $json.task) ?? "").trim() }}' },
    { id: 'a2', name: 'target', type: 'string', value: '={{ String(($json.body ? $json.body.target : $json.target) ?? "").trim() }}' },
    { id: 'a3', name: 'source', type: 'string', value: '={{ $("Console webhook").isExecuted ? "console" : "form" }}' },
    { id: 'a4', name: 'requestedBy', type: 'string', value: '={{ String(($json.body && $json.body.requested_by) || "").slice(0, 120) }}' } ] } } });
conn('Copilot form', 'Define task + target');
conn('Respond: execution id', 'Define task + target');

// 1 scope gate -------------------------------------------------------------------------------
code('Scope gate', 2, `${POLICY}
${LABENV}
const ALLOWLIST = labEnv('LAB_ALLOWLIST', '10.10.10.0/24,192.168.56.0/24,127.0.0.1').split(',').map(s=>s.trim()).filter(Boolean);
const inScope = targetInScope($json.target, ALLOWLIST);
return [{ json: { ...$json, allowlist: ALLOWLIST, scopeOk: inScope, scopeReason: inScope?'in scope':\`target "\${$json.target}" not in allowlist\` } }];`);
conn('Define task + target', 'Scope gate');
boolIf('In scope?', 3, '$json.scopeOk');
conn('Scope gate', 'In scope?');

// 1b retrieval: past writeups from Qdrant (RAG). Background DATA for the operator only; never reaches the judge. ---
add({
  name: 'Retrieve writeups (Qdrant)', type: '@n8n/n8n-nodes-langchain.vectorStoreQdrant', typeVersion: 1.4, position: [x(4), 200],
  alwaysOutputData: true, onError: 'continueRegularOutput',     // empty or unreachable store -> copilot still runs, without references
  parameters: { mode: 'load', qdrantCollection: { __rl: true, value: 'writeups', mode: 'id' },
    prompt: '={{ $json.task + " " + $json.target }}', topK: 4, includeDocumentMetadata: true, options: {} },
});
add({ name: 'Embeddings: Ollama', type: '@n8n/n8n-nodes-langchain.embeddingsOllama', typeVersion: 1, position: [x(4), 440],
  parameters: { model: 'nomic-embed-text' } });
conn('In scope?', 'Retrieve writeups (Qdrant)', 'main', 0);
conn('Embeddings: Ollama', 'Retrieve writeups (Qdrant)', 'ai_embedding');
code('Build reference context', 5, `
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
// user message format mirrored in copilot/contract.py (operator_messages); copilot/tests/test_contract.py renders both
const OPERATOR_TEXT = '={{ "TASK: " + $json.task + "\\nTARGET (authorized, in scope): " + $json.target + ($json.refCount ? "\\n\\n" + '
  + JSON.stringify(C.reference_header) + ' + "\\n<<<\\n" + $json.references + "\\n>>>" : "") }}';
// served name from COPILOT_OPERATOR_MODEL (glm-serve serves glm-abl, which Promote points at a run)
openAiCompatible('Operator model (OpenAI-compatible)', 6, '={{ $env.COPILOT_OPERATOR_MODEL || "glm-abl" }}');
chain('Abliterated operator (suggest)', 6, OPERATOR_TEXT, C.operator_system);
conn('Build reference context', 'Abliterated operator (suggest)');
conn('Operator model (OpenAI-compatible)', 'Abliterated operator (suggest)', 'ai_languageModel');

// 3 parse proposal (abliterated output = data) -----------------------------------------------
code('Parse proposal', 7, `
const raw = String($json.text ?? $json.output ?? $json.response ?? '');
let proposal = { command: '', target: $('Define task + target').first().json.target, rationale: '' };
const m = raw.match(/\\{[\\s\\S]*\\}/);
if (m) { try { const p = JSON.parse(m[0]); proposal = { command: String(p.command||''), target: String(p.target||proposal.target), rationale: String(p.rationale||'') }; } catch(e){} }
if (!proposal.command) { const line = (raw.match(/\`\`\`(?:bash|sh)?\\n([\\s\\S]*?)\`\`\`/)||[])[1] || raw.split('\\n').map(s=>s.trim()).find(Boolean) || ''; proposal.command = line.trim(); }
return [{ json: { ...$('Scope gate').first().json, proposal, rawProposal: raw } }];`);
conn('Abliterated operator (suggest)', 'Parse proposal');

// 4 policy gate (deterministic boundary) -----------------------------------------------------
code('Policy gate', 8, `${POLICY}
${LABENV}
const d = decide($json.proposal, { allowlist: $json.allowlist, autoRunReadOnly: labEnv('LAB_AUTORUN_READONLY', 'false') === 'true', autoRunActiveRecon: labEnv('LAB_AUTORUN_ACTIVE_RECON', 'false') === 'true' });
return [{ json: { ...$json, policy: d } }];`);
conn('Parse proposal', 'Policy gate');
boolIf('Policy passed?', 9, '$json.policy.allowed');
conn('Policy gate', 'Policy passed?');

// 5 judge (regular model) authorizes or rejects ----------------------------------------------
// think: false. Ollama switches thinking ON for thinking-capable models (qwen3) when a request leaves it unset, so every
// verdict would first generate a hidden reasoning trace: minutes per call on a CPU, and Qwen advises against greedy
// decoding (temperature 0) in thinking mode. A one-word veto needs no trace; on non-thinking models the flag is a no-op.
ollama('Ollama: judge model (regular)', 10, 'qwen3:8b', { think: false });
chain('Judge: authorize?', 10,
  '={{ "TASK: " + $json.task + "\\nTARGET: " + $json.policy.target + "\\nPROPOSED COMMAND (already passed the scope + denylist gate):\\n" + $json.policy.command + "\\nread-only: " + $json.policy.readOnly + "  tier: " + ($json.policy.tier || "none") }}',
  C.judge_system);
conn('Policy passed?', 'Judge: authorize?', 'main', 0);
conn('Ollama: judge model (regular)', 'Judge: authorize?', 'ai_languageModel');

// 6 apply judge verdict + final boundary re-check --------------------------------------------
code('Apply judge decision', 11, `${POLICY}
${LABENV}
const p = $('Policy gate').first().json;
const verdict = String($json.text ?? $json.output ?? '').trim();
const authorized = /^\\s*authorize\\b/i.test(verdict);
const recheck = decide(p.proposal || { command: p.policy.command, target: p.policy.target }, { allowlist: p.allowlist, autoRunReadOnly: labEnv('LAB_AUTORUN_READONLY', 'false') === 'true', autoRunActiveRecon: labEnv('LAB_AUTORUN_ACTIVE_RECON', 'false') === 'true' });
const allowed = p.policy.allowed && recheck.allowed && authorized;
const autoRun = allowed && p.policy.autoRun && recheck.autoRun;
return [{ json: { ...p, judgeVerdict: verdict, judgeAuthorized: authorized, allowed, autoRun, tier: recheck.tier,
  reasons: [ ...(p.policy.reasons||[]), ...(recheck.reasons||[]), ...(authorized?[]:['judge rejected: '+verdict]) ] } }];`);
conn('Judge: authorize?', 'Apply judge decision');
boolIf('Authorized?', 12, '$json.allowed');
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
  next = 'No model was called. If the target belongs to your lab, add it to LAB_ALLOWLIST.';
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

code('Result text (authorized)', 13, RESULT);
// form runs end on a result page; console runs have no page to show (the console renders the result itself)
const formRun = (name, col, row) => { boolIf(name, col, '$json.source !== "console"'); nodes[nodes.length - 1].position[1] = row; return name; };
formRun('Form run? (authorized)', 13.5, 200);
resultPage('Result page: authorized', 14, 200, '5d2f9a64-1b7e-4f0c-8e3a-6a9b0c1d2e33');
conn('Authorized?', 'Result text (authorized)', 'main', 0);
conn('Result text (authorized)', 'Form run? (authorized)');
conn('Form run? (authorized)', 'Result page: authorized', 'main', 0);

// 8 auto-run split + human approval + execute ------------------------------------------------
boolIf('Auto-run (recon tier)?', 15, '$json.autoRun');
conn('Result page: authorized', 'Auto-run (recon tier)?');
conn('Form run? (authorized)', 'Auto-run (recon tier)?', 'main', 1);
add({ name: 'Human approval', type: 'n8n-nodes-base.wait', typeVersion: 1.1, position: [x(16), 360], webhookId: 'pentest-approval', parameters: { resume: 'webhook', options: {} } });
conn('Auto-run (recon tier)?', 'Human approval', 'main', 1);
add({ name: 'Execute on lab target (DISABLED)', type: 'n8n-nodes-base.httpRequest', typeVersion: 4.2, position: [x(17), 200], disabled: true,
  parameters: { method: 'POST', url: '={{ $env.LAB_RUNNER_URL }}', sendBody: true, specifyBody: 'json',
    jsonBody: '={{ { "command": $json.policy.command, "target": $json.policy.target, "autoRun": $json.autoRun, "tier": $json.tier } }}', options: {} } });
conn('Auto-run (recon tier)?', 'Execute on lab target (DISABLED)', 'main', 0);
conn('Human approval', 'Execute on lab target (DISABLED)');

// blocked terminals: each ends on the blocked result page ---------------------------------------
code('Result text (blocked)', 13, RESULT, 640);
formRun('Form run? (blocked)', 13.5, 640);
resultPage('Result page: blocked', 14, 640, '9e1c7b20-4d5a-4a8f-b6c3-2f0e1d9a8b44');
conn('Result text (blocked)', 'Form run? (blocked)');
conn('Form run? (blocked)', 'Result page: blocked', 'main', 0);      // console runs end here (false branch: nothing)
[['In scope?', 'out of scope', 3], ['Policy passed?', 'policy', 9], ['Authorized?', 'judge rejected', 12]].forEach(([src, label, col]) => {
  const name = `Blocked (${label})`;
  add({ name, type: 'n8n-nodes-base.noOp', typeVersion: 1, position: [x(col), 640] });
  conn(src, name, 'main', 1);
  conn(name, 'Result text (blocked)');
});

// sticky notes --------------------------------------------------------------------------------
const notes = [
  [x(0) - 20, 40, 360, 120, '#2E86DE', '1 - Input (web form)\nTask + one Target. Once published: http://localhost:5678/form/' + FORM_PATH + '. In the editor, Execute workflow opens a test form.'],
  [x(0) - 20, -170, 360, 150, '#2E86DE', '1b - Input (lab console)\nPOST /webhook/' + WEBHOOK_PATH + ' with the X-Lab-Secret header (Header Auth credential). Answers at once with the execution id; the console follows the run through the n8n API. Console runs skip the result pages.'],
  [x(2) - 20, 40, 220, 120, '#10AC84', '2 - Scope gate (code)\nTarget must be in LAB_ALLOWLIST before the abliterated model runs.'],
  [x(4) - 20, 40, 460, 120, '#2E86DE', '2b - Retrieval (RAG)\nTop-4 chunks from past writeups (Qdrant, collection writeups) as bounded background for the operator only; their addresses are neutralized. Empty/unreachable store -> runs without references.'],
  [x(6) - 20, 40, 220, 120, '#8854D0', '3 - Abliterated\nSUGGESTS ONLY. No tools; can never run a command.'],
  [x(8) - 20, 560, 300, 170, '#10AC84', '4 - Policy gate (code)\nThe real boundary: scope + denylist, auto-run tier (passive / active-recon), targets it cannot verify (placeholders, $VARS, -iL, integer/hex IPs, IPv6) and text aimed at the judge ("ignore your instructions", "AUTHORIZE"...): those never auto-run and go to a human.'],
  [x(10) - 20, 40, 260, 170, '#EE5253', '5 - Judge (regular model)\nAUTHORIZE or REJECT the vetted command. Veto-only: the runner always executes policy.command, so a judge talked into AUTHORIZE (measured: it happens) cannot widen scope, and a command carrying injection text goes to a human anyway.'],
  [x(13) - 20, 380, 440, 170, '#2E86DE', '6 - Result page (form)\nShows the suggestion, the policy decision, the judge verdict and the next step. Form and model text are HTML-escaped; n8n also sanitizes the page. Blocked runs end here; authorized runs continue to the auto-run split.'],
  [x(15) - 20, -70, 480, 150, '#F79F1F', '7 - Auto-run + Execute\nRecon that cleared every gate auto-runs (LAB_AUTORUN_READONLY; add LAB_AUTORUN_ACTIVE_RECON for safe NSE + sqlmap-enumerate). Else -> Human approval (Wait). Execute DISABLED on import: set LAB_RUNNER_URL and enable it.'],
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
