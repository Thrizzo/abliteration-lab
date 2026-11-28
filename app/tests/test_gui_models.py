"""The console's model pickers and layer field (app/static/app.js), run in node with app.js's own functions.

- the judge picker: the judge vetoes the abliterated operator, so when its default is not on the copilot's Ollama (with
  -HostOllama: the owner's own Ollama for Windows, with whatever chat models it holds) the list shows the default as
  missing and keeps it chosen; it never quietly takes the first chat model there. A choice the browser kept wins when
  that Ollama has it. The operator picker keeps its plain behaviour;
- the judge's info line names a missing default judge with its "ollama pull", and only then;
- the copilot-model card: in the Kubernetes console it names glm-serve and offers to load a run (Promote); in the Docker
  stack or a plain console it names Ollama, which serves the runs step 2 imported, asks nothing of /api/serving and hides
  the Load row;
- the layer field reads "15 17", "15, 17" and "15 - 17" as the CLI's --layers does;
- a scan again in the same run starts its live view without the earlier pass's combinations; new directions (a measure
  that ends) end the earlier scan and its pause, so the layer choice never offers a recommendation of other directions,
  and a pause whose scan files are gone is not offered either; a refused or stopped call on a paused run keeps the pause
  and its Continue; an earlier call's error banner goes once the next call starts, while the steps it left unfinished
  stay failed.

    python -m unittest discover -s app/tests
"""
import json
import os
import re
import shutil
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
APP_JS = os.path.join(HERE, "..", "static", "app.js")
NODE = shutil.which("node")

SCRIPT = r"""
const src = require('fs').readFileSync(__APP_JS__, 'utf8').replace(/\r/g, '');
const grab = (start, end) => { const i = src.indexOf(start), j = src.indexOf(end, i); if (i < 0 || j < 0) throw new Error('app.js: ' + start); return src.slice(i, j + end.length); };
const line = (start) => grab(start, '\n');
const code = [line('const esc = '), line('const escA = '), line('const sameModel = '), grab('const parseLayers = ', 'return out; };'),
  grab('function cpFillSelect(', '\n  return missing;\n}'), grab('function cpJudgeInfo(', "\n    + (ex ? `not usable as judge: ${ex}` : '');\n}"),
  grab('function foldEvents(evs){', '\n  return ES;\n}'), grab('function stepState(key){', "\n  return 'pending';\n}")].join('\n');
const store = {};
const cpStore = { get: (k, d) => (k in store ? store[k] : d) };
const S = { ES: {}, run: null };
const f = new Function('cpStore', 'S', code + '; return { cpFillSelect, parseLayers, cpJudgeInfo, foldEvents, stepState };')(cpStore, S);
const fill = (role, list, def, kept) => {
  for (const k of Object.keys(store)) delete store[k];
  if (kept !== undefined) store['model.' + role] = kept;
  const sel = { innerHTML: '' };
  const missing = f.cpFillSelect(sel, role, list, def);
  const options = [...sel.innerHTML.matchAll(/<option value="([^"]*)"( selected)?>([^<]*)<\/option>/g)].map((m) => ({ value: m[1], selected: !!m[2], label: m[3] }));
  return { missing, values: options.map((o) => o.value), selected: options.filter((o) => o.selected).map((o) => o.value), labels: options.map((o) => o.label) };
};
const out = {
  listed: fill('judge', ['llama3.1:8b', 'qwen3:8b'], 'qwen3:8b'),
  missing: fill('judge', ['gemma3:12b', 'llama3.1:8b'], 'qwen3:8b'),
  missingKept: fill('judge', ['gemma3:12b', 'llama3.1:8b'], 'qwen3:8b', 'llama3.1:8b'),
  missingKeptGone: fill('judge', ['gemma3:12b', 'llama3.1:8b'], 'qwen3:8b', 'mistral:7b'),
  latest: fill('judge', ['gemma3:12b', 'qwen3:latest'], 'qwen3'),
  down: fill('judge', [], 'qwen3:8b'),
  operator: fill('operator', ['glm-abl-v2'], 'glm-abl'),
  layers: Object.fromEntries(['15 17', '15, 17', '15 - 17 19', '17,15,17', '15,,17', 'abc', '-1', '19-15', '5;6'].map((t) => [t, f.parseLayers(t)])),
  info: {
    missing: f.cpJudgeInfo({ default: 'qwen3:8b', excluded: [{ name: 'glm-abl', why: 'abliterated: never' }] }, true),
    present: f.cpJudgeInfo({ default: 'qwen3:8b', excluded: [] }, false),
    error: f.cpJudgeInfo({ default: '<b>x</b>', error: 'did not list <i>', excluded: [] }, true),
  },
};
const ev = (status, extra) => ({ t: 1, step: 'scan', status, ...extra });
const first = [ev('start', { layers: [1, 2] }), ev('layer', { layer: 1 }), ev('combo', { layers: [1, 2] }), ev('done', { top_combos: [[[1, 2], 0]] })];
const again = f.foldEvents([...first, ev('start', { layers: [1, 2, 3] }), ev('layer', { layer: 2 })]).scan;
const done = f.foldEvents(first).scan;
out.fold = { again: { status: again.status, layers: again.layers.length, combos: again.combos.length, planned: again.layers_planned },
             done: { status: done.status, layers: done.layers.length, combos: done.combos.length } };
// a run paused at the choice, then other calls on it from outside the console (CLI, or the API with run_id). scan: whether
// the run still has its scan files (rundata's "scan"), which the pipeline removes with new directions (drop_scan)
const E = (step, status, extra) => ({ t: 1, step, status, ...extra });
const call = [E('download', 'done', { cached: true })];
const paused = [...call, E('measure', 'start'), E('measure', 'done'), ...first, E('choose', 'waiting', { recommended: 1, recommended_layers: [1] })];
const refusal = E('error', 'error', { message: 'layer 99 does not exist' });
const state = (evs, meta, scan, choice) => {
  S.ES = f.foldEvents(evs); S.run = { meta, choice: choice || { layer: null }, scan: scan ? { layers: [] } : null };
  return { choose: f.stepState('choose'), scan: S.ES.scan ? S.ES.scan.status : null, measure: S.ES.measure ? S.ES.measure.status : null, error: !!S.ES._error };
};
out.pause = {
  paused: state(paused, { status: 'awaiting_choice' }, true),
  refused: state([...paused, ...call, refusal], { status: 'error' }, true),
  refusedThenOk: state([...paused, ...call, refusal, ...call, E('choose', 'done', { layer: 2, layers: [2], by: 'user' })], { status: 'running' }, true),
  remeasured: state([...paused, ...call, E('measure', 'start'), E('measure', 'done')], { status: 'done' }, false),
  remeasureStopped: state([...paused, ...call, E('measure', 'start'), E('error', 'stopped')], { status: 'stopped' }, true),
  rescanStopped: state([...paused, ...call, E('measure', 'start'), E('measure', 'done'), E('scan', 'start', { layers: [1, 2] }), E('scan', 'layer', { layer: 1 }), E('error', 'stopped')], { status: 'stopped' }, false),
  stoppedThenContinued: state([...paused, ...call, E('measure', 'start'), E('measure', 'done'), E('scan', 'start', { layers: [1, 2] }), E('scan', 'layer', { layer: 1 }), E('error', 'stopped'),
                               ...call, E('choose', 'done', { layer: 1, layers: [1], by: 'user' }), E('apply', 'start'), E('apply', 'done')], { status: 'done' }, false, { layer: 1 }),
  scanFilesGone: state(paused, { status: 'error' }, false),
};
console.log(JSON.stringify(out));
"""


@unittest.skipUnless(NODE, "node not installed")
class ModelPickers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        js = SCRIPT.replace("__APP_JS__", json.dumps(APP_JS))
        p = subprocess.run([NODE, "-e", js], capture_output=True, text=True, timeout=60)
        if p.returncode:
            raise AssertionError(p.stderr)
        cls.got = json.loads(p.stdout)

    def test_the_judges_default_when_the_ollama_has_it(self):
        g = self.got["listed"]
        self.assertEqual((g["missing"], g["values"], g["selected"]), (False, ["llama3.1:8b", "qwen3:8b"], ["qwen3:8b"]))
        self.assertEqual(g["labels"][1], "qwen3:8b (default)")
        g = self.got["latest"]                                   # "qwen3" and "qwen3:latest" are the same model
        self.assertEqual((g["missing"], g["selected"]), (False, ["qwen3:latest"]))

    def test_a_missing_default_judge_is_shown_and_kept_not_replaced(self):
        g = self.got["missing"]
        self.assertTrue(g["missing"])
        self.assertEqual(g["values"], ["qwen3:8b", "gemma3:12b", "llama3.1:8b"])
        self.assertEqual(g["selected"], ["qwen3:8b"])            # never the first chat model on that Ollama
        self.assertIn("not on this Ollama", g["labels"][0])
        g = self.got["missingKeptGone"]                          # a kept choice that Ollama no longer has: the default again
        self.assertEqual((g["missing"], g["selected"]), (True, ["qwen3:8b"]))

    def test_a_judge_chosen_on_purpose_stays_chosen(self):
        g = self.got["missingKept"]
        self.assertEqual((g["missing"], g["selected"]), (True, ["llama3.1:8b"]))
        self.assertEqual(g["values"][0], "qwen3:8b")             # the default is still listed, marked missing
        self.assertTrue(re.search(r"not on this Ollama", g["labels"][0]))

    def test_no_list_and_the_operator(self):
        g = self.got["down"]                                     # the Ollama did not answer: its error says so elsewhere
        self.assertEqual((g["missing"], g["values"], g["selected"]), (False, ["qwen3:8b"], ["qwen3:8b"]))
        g = self.got["operator"]                                 # the operator picker: what glm-serve serves
        self.assertEqual((g["missing"], g["values"], g["selected"]), (False, ["glm-abl-v2"], ["glm-abl-v2"]))

    def test_the_judges_info_line(self):
        g = self.got["info"]
        self.assertIn("qwen3:8b, the default judge, is not on the copilot's Ollama", g["missing"])
        self.assertIn("ollama pull qwen3:8b", g["missing"])
        self.assertIn("not usable as judge: glm-abl (abliterated)", g["missing"])
        self.assertEqual(g["present"], "")
        self.assertNotIn("<b>", g["error"])                       # names and errors from the Ollama stay text
        self.assertNotIn("<i>", g["error"])
        self.assertIn("did not list &lt;i&gt;", g["error"])

    def test_a_scan_again_starts_without_the_earlier_combinations(self):
        self.assertEqual(self.got["fold"]["done"], {"status": "done", "layers": 1, "combos": 1})
        self.assertEqual(self.got["fold"]["again"], {"status": "running", "layers": 1, "combos": 0, "planned": [1, 2, 3]})

    def test_new_directions_end_the_pause(self):
        g = self.got["pause"]
        self.assertEqual(g["paused"], {"choose": "waiting", "scan": "done", "measure": "done", "error": False})
        # a refused Continue keeps the pause and its Continue; the next call ends the banner
        self.assertEqual(g["refused"], {"choose": "waiting", "scan": "done", "measure": "done", "error": True})
        self.assertEqual(g["refusedThenOk"], {"choose": "done", "scan": "done", "measure": "done", "error": False})
        # new directions: no scan and no pause of the earlier ones (no Continue with layer 1)
        self.assertEqual(g["remeasured"], {"choose": "pending", "scan": None, "measure": "done", "error": False})
        # a measure stopped before its end changed nothing: the pause stands
        self.assertEqual(g["remeasureStopped"], {"choose": "waiting", "scan": "done", "measure": "error", "error": True})
        self.assertEqual(g["rescanStopped"], {"choose": "pending", "scan": "error", "measure": "done", "error": True})
        # a later call that does not scan again: the stopped scan stays failed, not "running"
        self.assertEqual(g["stoppedThenContinued"], {"choose": "done", "scan": "error", "measure": "done", "error": False})
        # the scan files gone (drop_scan without a later event, e.g. a layer range without layers): no pause offered
        self.assertEqual(g["scanFilesGone"]["choose"], "pending")

    def test_the_layer_field_reads_like_the_cli(self):
        self.assertEqual(self.got["layers"], {"15 17": [15, 17], "15, 17": [15, 17], "15 - 17 19": [15, 16, 17, 19], "17,15,17": [17, 15],
                                              "15,,17": [15, 17], "abc": None, "-1": None, "19-15": None, "5;6": None})


# app.js's cpModelsLoad on a stand-in page: the copilot-model card in the Kubernetes console (glm-serve, Promote) and in
# the Docker stack or a plain console (S.env.runner "local": Ollama serves the operator, there is no glm-serve to load a
# run into)
CARD = r"""
const src = require('fs').readFileSync(__APP_JS__, 'utf8').replace(/\r/g, '');
const grab = (start, end) => { const i = src.indexOf(start), j = src.indexOf(end, i); if (i < 0 || j < 0) throw new Error('app.js: ' + start); return src.slice(i, j + end.length); };
const line = (start) => grab(start, '\n');
const code = [line('const esc = '), line('const escA = '), line('const sameModel = '), line('const ABL_NAME = '),
  grab('function cpFillSelect(', '\n  return missing;\n}'), grab('function cpJudgeInfo(', "\n    + (ex ? `not usable as judge: ${ex}` : '');\n}"),
  grab('async function cpModelsLoad(fresh){', "$('#serveToggle').click(); };\n}")].join('\n');
const MODELS = { operator: { models: ['glm-edge-1.5b-chat-abl:latest', 'qwen3:8b'], default: 'glm-edge-1.5b-chat-abl:latest', error: null },
                 judge: { models: ['qwen3:8b'], excluded: [], default: 'qwen3:8b', error: null }, embeddings: { model: 'nomic-embed-text' } };
const SERVING = { current: { run_id: 'r1' }, candidates: [{ run_id: 'r1', model: 'glm', promotable: true, verdict: 'pass' }] };
const card = async (runner, models, stored) => {
  const els = {}, calls = [];
  const $ = (s) => (els[s] = els[s] || { innerHTML: '', textContent: '', style: {}, disabled: false });
  const api = async (path) => { calls.push(path); if (path.startsWith('/copilot/models')) return models; if (path === '/serving') return SERVING; throw new Error(path); };
  const S = { env: { runner }, stage: 'model' }, CP = {}, cpStore = { get: (k, d) => (stored && k === 'model.operator' ? stored : d) };
  const f = new Function('$', 'api', 'S', 'CP', 'cpStore', 'layerText', code + '; return cpModelsLoad;')($, api, S, CP, cpStore, (r) => String(r.layer));
  await f(false);
  const hidden = ['label[for=cpLoadRun]', '.cp-loadrow', '#cpLoadInfo'].filter((s) => els[s] && els[s].style.display === 'none');
  const sel = els['#cpOpModel'].innerHTML.match(/<option value="([^"]*)" selected>/);
  return { calls, role: els['#cpOpRole'] ? els['#cpOpRole'].textContent : null, info: els['#cpOpInfo'].innerHTML, hidden,
           options: (els['#cpOpModel'].innerHTML.match(/<option /g) || []).length, selected: sel ? sel[1] : null,
           load: els['#cpLoadRun'] ? els['#cpLoadRun'].innerHTML : null };
};
// the Docker stack's Ollama without the default operator: one run of another model, the judge, an embedding model left out
const OLLAMA = (models, excluded) => ({ ...MODELS, operator: { models, excluded, default: 'glm-edge-1.5b-chat-abl:latest', error: null } });
const EMB = [{ name: 'nomic-embed-text:latest', why: 'an embedding model, not a chat model' }];
(async () => {
  const out = {
    local: await card('local', MODELS),
    localDown: await card('local', { ...MODELS, operator: { models: [], default: 'glm-edge-1.5b-chat-abl:latest', error: 'glm-serve did not list its models: <refused>' } }),
    k8s: await card('k8s', MODELS),
    localOtherRun: await card('local', OLLAMA(['glm-edge-4b-chat-abl:latest', 'qwen3:8b'], EMB)),
    localNoRun: await card('local', OLLAMA(['qwen3:8b'], EMB)),
    localStored: await card('local', OLLAMA(['glm-edge-4b-chat-abl:latest', 'qwen3:8b'], EMB), 'qwen3:8b'),
    k8sOther: await card('k8s', OLLAMA(['glm-abl'], [])),
  };
  console.log(JSON.stringify(out));
})().catch((e) => { console.error(e && e.stack || e); process.exit(1); });
"""


@unittest.skipUnless(NODE, "node not installed")
class OperatorCard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        js = CARD.replace("__APP_JS__", json.dumps(APP_JS))
        p = subprocess.run([NODE, "-e", js], capture_output=True, text=True, timeout=60)
        if p.returncode:
            raise AssertionError(p.stderr)
        cls.got = json.loads(p.stdout)

    def test_the_docker_console_names_ollama_and_offers_no_load(self):
        g = self.got["local"]
        self.assertEqual(g["calls"], ["/copilot/models"])           # no glm-serve to ask what it serves
        self.assertIn("served by Ollama", g["role"])
        self.assertIn("step 2 imports each abliterated run", g["info"])
        self.assertNotIn("glm-serve", g["info"])
        self.assertEqual(g["hidden"], ["label[for=cpLoadRun]", ".cp-loadrow", "#cpLoadInfo"])
        self.assertEqual(g["options"], 2)                             # the picker lists what that Ollama holds

    def test_the_docker_console_shows_why_the_list_is_empty(self):
        g = self.got["localDown"]
        self.assertIn("did not list its models: &lt;refused&gt;", g["info"])   # the server's error, as text
        self.assertNotIn("<refused>", g["info"])

    def test_the_docker_console_flags_a_missing_default_and_picks_a_run(self):
        g = self.got["localOtherRun"]
        self.assertEqual(g["selected"], "glm-edge-4b-chat-abl:latest")     # the run that is there, not the judge
        self.assertEqual(g["options"], 3)                                   # the missing default stays visible, marked
        self.assertIn("glm-edge-1.5b-chat-abl:latest, the default copilot model, is not on this Ollama", g["info"])
        self.assertIn("glm-edge-4b-chat-abl:latest, an abliterated one, is chosen instead", g["info"])
        self.assertIn("nomic-embed-text:latest (embedding)", g["info"])    # left out, and why

    def test_the_docker_console_without_a_run_says_so(self):
        g = self.got["localNoRun"]
        self.assertIn("no abliterated model is there yet", g["info"])
        self.assertEqual(g["selected"], "glm-edge-1.5b-chat-abl:latest")   # never the judge as the "abliterated" model
        self.assertIn("GLM-5.x runs have none", g["info"])

    def test_an_earlier_choice_is_kept_and_said_so(self):
        g = self.got["localStored"]                                     # chosen in this browser before the first run
        self.assertEqual(g["selected"], "qwen3:8b")
        self.assertIn("qwen3:8b is your earlier choice; pick one of the abliterated runs", g["info"])
        self.assertNotIn("is chosen instead", g["info"])

    def test_the_kubernetes_console_lists_what_glm_serve_serves(self):
        g = self.got["k8sOther"]                                          # glm-serve serves one name: nothing to flag
        self.assertEqual((g["options"], g["selected"]), (1, "glm-abl"))
        self.assertNotIn("not on this Ollama", g["info"])

    def test_the_kubernetes_console_keeps_glm_serve_and_load(self):
        g = self.got["k8s"]
        self.assertEqual(g["calls"], ["/copilot/models", "/serving"])
        self.assertIsNone(g["role"])                                  # the page's own text: "served by glm-serve"
        self.assertIn("glm-serve serves run", g["info"])
        self.assertEqual(g["hidden"], [])
        self.assertIn('value="r1"', g["load"])


if __name__ == "__main__":
    unittest.main()
