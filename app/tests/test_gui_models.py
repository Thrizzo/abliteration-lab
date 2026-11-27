"""The console's model pickers and layer field (app/static/app.js), run in node with app.js's own functions.

- the judge picker: the judge vetoes the abliterated operator, so when its default is not on the copilot's Ollama (with
  -HostOllama: the owner's own Ollama for Windows, with whatever chat models it holds) the list shows the default as
  missing and keeps it chosen; it never quietly takes the first chat model there. A choice the browser kept wins when
  that Ollama has it. The operator picker keeps its plain behaviour;
- the layer field reads "15 17", "15, 17" and "15 - 17" as the CLI's --layers does.

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
  grab('function cpFillSelect(', '\n  return missing;\n}')].join('\n');
const store = {};
const cpStore = { get: (k, d) => (k in store ? store[k] : d) };
const f = new Function('cpStore', code + '; return { cpFillSelect, parseLayers };')(cpStore);
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

    def test_the_layer_field_reads_like_the_cli(self):
        self.assertEqual(self.got["layers"], {"15 17": [15, 17], "15, 17": [15, 17], "15 - 17 19": [15, 16, 17, 19], "17,15,17": [17, 15],
                                              "15,,17": [15, 17], "abc": None, "-1": None, "19-15": None, "5;6": None})


if __name__ == "__main__":
    unittest.main()
