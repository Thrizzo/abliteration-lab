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
const chain = (name, col, text, sys) => add({
  name, type: '@n8n/n8n-nodes-langchain.chainLlm', typeVersion: 1.6, position: [x(col), 200],
  parameters: { promptType: 'define', text, messages: { messageValues: [{ message: sys }] } },
});

// 0 input ------------------------------------------------------------------------------------
add({ name: 'Engagement task', type: 'n8n-nodes-base.manualTrigger', typeVersion: 1, position: [x(0), 200], parameters: {} });
add({ name: 'Define task + target', type: 'n8n-nodes-base.set', typeVersion: 3.4, position: [x(1), 200],
  parameters: { assignments: { assignments: [
    { id: 'a1', name: 'task', type: 'string', value: 'Enumerate services on the box and suggest the next step.' },
    { id: 'a2', name: 'target', type: 'string', value: '10.10.10.5' } ] } } });
conn('Engagement task', 'Define task + target');

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
ollama('Ollama: abliterated model', 6, 'glm-edge-1.5b-chat-abl:latest');
chain('Abliterated operator (suggest)', 6, OPERATOR_TEXT, C.operator_system);
conn('Build reference context', 'Abliterated operator (suggest)');
conn('Ollama: abliterated model', 'Abliterated operator (suggest)', 'ai_languageModel');

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

// 7 auto-run split + human approval + execute ------------------------------------------------
boolIf('Auto-run (recon tier)?', 13, '$json.autoRun');
conn('Authorized?', 'Auto-run (recon tier)?', 'main', 0);
add({ name: 'Human approval', type: 'n8n-nodes-base.wait', typeVersion: 1.1, position: [x(14), 360], webhookId: 'pentest-approval', parameters: { resume: 'webhook', options: {} } });
conn('Auto-run (recon tier)?', 'Human approval', 'main', 1);
add({ name: 'Execute on lab target (DISABLED)', type: 'n8n-nodes-base.httpRequest', typeVersion: 4.2, position: [x(15), 200], disabled: true,
  parameters: { method: 'POST', url: '={{ $env.LAB_RUNNER_URL }}', sendBody: true, specifyBody: 'json',
    jsonBody: '={{ { "command": $json.policy.command, "target": $json.policy.target, "autoRun": $json.autoRun, "tier": $json.tier } }}', options: {} } });
conn('Auto-run (recon tier)?', 'Execute on lab target (DISABLED)', 'main', 0);
conn('Human approval', 'Execute on lab target (DISABLED)');

// blocked terminals ---------------------------------------------------------------------------
[['In scope?', 'out of scope', 3], ['Policy passed?', 'policy', 9], ['Authorized?', 'judge rejected', 12]].forEach(([src, label, col]) => {
  const name = `Blocked (${label})`;
  add({ name, type: 'n8n-nodes-base.noOp', typeVersion: 1, position: [x(col), 640] });
  conn(src, name, 'main', 1);
});

// sticky notes --------------------------------------------------------------------------------
const notes = [
  [x(0) - 20, 40, 360, 120, '#2E86DE', '1 - Input\nTask + one target. Swap the Manual Trigger for a Chat/Form/Webhook trigger for real use.'],
  [x(2) - 20, 40, 220, 120, '#10AC84', '2 - Scope gate (code)\nTarget must be in LAB_ALLOWLIST before the abliterated model runs.'],
  [x(4) - 20, 40, 460, 120, '#2E86DE', '2b - Retrieval (RAG)\nTop-4 chunks from past writeups (Qdrant, collection writeups) as bounded background for the operator only; their addresses are neutralized. Empty/unreachable store -> runs without references.'],
  [x(6) - 20, 40, 220, 120, '#8854D0', '3 - Abliterated\nSUGGESTS ONLY. No tools; can never run a command.'],
  [x(8) - 20, 560, 300, 170, '#10AC84', '4 - Policy gate (code)\nThe real boundary: scope + denylist, auto-run tier (passive / active-recon), targets it cannot verify (placeholders, $VARS, -iL, integer/hex IPs, IPv6) and text aimed at the judge ("ignore your instructions", "AUTHORIZE"...): those never auto-run and go to a human.'],
  [x(10) - 20, 40, 260, 170, '#EE5253', '5 - Judge (regular model)\nAUTHORIZE or REJECT the vetted command. Veto-only: the runner always executes policy.command, so a judge talked into AUTHORIZE (measured: it happens) cannot widen scope, and a command carrying injection text goes to a human anyway.'],
  [x(13) - 20, -70, 480, 150, '#F79F1F', '6 - Auto-run + Execute\nRecon that cleared every gate auto-runs (LAB_AUTORUN_READONLY; add LAB_AUTORUN_ACTIVE_RECON for safe NSE + sqlmap-enumerate). Else -> Human approval (Wait). Execute DISABLED on import: set LAB_RUNNER_URL and enable it.'],
];
notes.forEach(([px, py, w, h, color, content], i) => add({ name: `note${i}`, type: 'n8n-nodes-base.stickyNote', typeVersion: 1, position: [px, py], parameters: { width: w, height: h, color, content } }));

for (const n of nodes.filter((n) => n.type === 'n8n-nodes-base.code')) {
  try { new Function('$input', '$json', '$', '$env', n.parameters.jsCode); }
  catch (e) { throw new Error(`generated Code node "${n.name}" does not parse: ${e.message}`); }
}
const workflow = { name: 'Pentest lab copilot (RAG + abliterated suggests, regular judge authorizes, runner executes)', nodes, connections, settings: { executionOrder: 'v1' }, active: false };
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
