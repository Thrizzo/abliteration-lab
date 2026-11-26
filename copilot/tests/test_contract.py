"""The Python contract must match what the n8n workflow sends. Run: python -m unittest discover -s copilot/tests -t .
Cross-language checks render the workflow's own expressions with node; they are skipped if node is not installed."""
import json
import os
import shutil
import subprocess
import unittest

from copilot.contract import engagement_text, judge_user, neutral, operator_messages, operator_user, parse_answer

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WF = os.path.join(ROOT, "deploy", "n8n", "workflows", "pentest-copilot.json")
VECTORS = os.path.join(os.path.dirname(__file__), "fixtures", "neutral_vectors.json")
NODE = shutil.which("node")


def node_eval(js):
    return subprocess.run([NODE, "-e", js], capture_output=True, text=True, check=True).stdout


class Neutralizer(unittest.TestCase):
    def test_vectors(self):
        for v in json.load(open(VECTORS, encoding="utf-8")):
            self.assertEqual(neutral(v["in"]), v["out"], v["in"])

    @unittest.skipUnless(NODE, "node not installed")
    def test_js_node_matches_python(self):
        # run the real "Build reference context" Code node on every vector and compare with neutral()
        js = f"""
const wf = require({json.dumps(WF)}); const vecs = require({json.dumps(VECTORS)});
const code = wf.nodes.find(n => n.name === 'Build reference context').parameters.jsCode;
const out = vecs.map(v => {{
  const items = [{{ json: {{ document: {{ pageContent: v.in, metadata: {{}} }}, score: 0.5 }} }}];
  const r = new Function('$input','$json','$','$env', code)({{ all: () => items }}, {{}}, () => ({{ first: () => ({{ json: {{}} }}) }}), {{}});
  return r[0].json.references.replace(/^\\[ref 1[^\\]]*\\]\\n/, '');
}});
console.log(JSON.stringify(out));"""
        js_out = json.loads(node_eval(js))
        for v, got in zip(json.load(open(VECTORS, encoding="utf-8")), js_out):
            self.assertEqual(got, neutral(v["in"]), v["in"])


ENGAGEMENTS = [None, {}, {"name": "ACME internal", "version": 4, "scope_statement": "Only the web tier.", "scope_in": ["10.10.11.0/28", "box.htb"],
                          "scope_out": ["10.10.11.1"], "window_start": "2026-11-26T08:00:00+01:00", "window_end": None,
                          "prohibited": ["hydra", "-T5"], "roe": "No DoS.\nStop on PII: report it, do not copy it."},
               {"name": "long", "roe": "r" * 9000}, {"scope_out": [" ", "10.10.11.9 "], "roe": "  "}]


class OperatorPrompt(unittest.TestCase):
    @unittest.skipUnless(NODE, "node not installed")
    def test_n8n_operator_prompt_matches_python(self):
        # run the real "Build operator prompt" Code node and compare with operator_messages()
        for refs in ("", "[ref 1 | htb | a.md | score 0.70]\nnmap -sV <other-host-ip>"):
            for eng in ENGAGEMENTS:
                js = f"""
const wf = require({json.dumps(WF)});
const code = wf.nodes.find(n => n.name === 'Build operator prompt').parameters.jsCode;
const op = wf.nodes.find(n => n.name === 'Abliterated operator (suggest)');
const $json = {{ task: 'Enumerate SMB', target: '10.10.11.42', refCount: {1 if refs else 0}, references: {json.dumps(refs)}, engagement: {json.dumps(eng)} }};
const out = new Function('$input','$json','$','$env', code)({{}}, $json, () => ({{}}), {{}})[0].json;
console.log(JSON.stringify({{ user: out.operatorPrompt, chain: op.parameters.text, system: op.parameters.messages.messageValues[0].message }}));"""
                got = json.loads(node_eval(js))
                sys_msg, user_msg = operator_messages("Enumerate SMB", "10.10.11.42", refs, eng)
                self.assertEqual(got["user"], user_msg["content"], eng)
                self.assertEqual(got["system"], sys_msg["content"])
                self.assertEqual(got["chain"], "={{ $json.operatorPrompt }}")

    @unittest.skipUnless(NODE, "node not installed")
    def test_n8n_judge_prompt_matches_python(self):
        for eng in ENGAGEMENTS:
            for read_only, tier, allow in ((True, "passive", ["10.10.11.0/24", " box.htb "]), (False, None, []), (True, None, None)):
                js = f"""
const wf = require({json.dumps(WF)});
const code = wf.nodes.find(n => n.name === 'Build judge prompt').parameters.jsCode;
const $json = {{ task: 'Enumerate SMB', judgeModel: 'qwen3:8b', engagement: {json.dumps(eng)}, allowlist: {json.dumps(allow)},
  policy: {{ target: '10.10.11.42', command: 'smbclient -N -L //10.10.11.42', readOnly: {json.dumps(read_only)}, tier: {json.dumps(tier)} }} }};
console.log(JSON.stringify(new Function('$input','$json','$','$env', code)({{}}, $json, () => ({{}}), {{}})[0].json.judgePrompt));"""
                got = json.loads(node_eval(js))
                self.assertEqual(got, judge_user("Enumerate SMB", "10.10.11.42", "smbclient -N -L //10.10.11.42", read_only, tier, eng, allow),
                                 (eng, allow))
                self.assertEqual("SCOPE (LAB_ALLOWLIST): 10.10.11.0/24, box.htb" in got, bool(allow))

    def test_engagement_text(self):
        self.assertEqual(engagement_text(None), "")
        self.assertEqual(engagement_text({"scope_out": [" "], "roe": " "}), "")
        t = engagement_text(ENGAGEMENTS[2])
        self.assertTrue(t.startswith("ENGAGEMENT: ACME internal (version 4)\nSCOPE STATEMENT: Only the web tier.\nIN SCOPE: 10.10.11.0/28, box.htb\n"), t)
        self.assertIn("\nWINDOW: 2026-11-26T08:00:00+01:00 to open\nPROHIBITED: hydra, -T5\nRULES: No DoS.", t)
        long = engagement_text(ENGAGEMENTS[3])
        self.assertEqual(len(long), 4000 + 4)
        self.assertTrue(long.endswith("r ..."))

    def test_user_message_shape(self):
        self.assertEqual(operator_user("T", "10.0.0.1"), "TASK: T\nTARGET (authorized, in scope): 10.0.0.1")
        self.assertIn("<<<\nX\n>>>", operator_user("T", "10.0.0.1", "X"))


class ParseAnswer(unittest.TestCase):
    def test_json(self):
        p, ok = parse_answer('Sure! {"command": "nmap -sV 10.0.0.1", "target": "10.0.0.1", "rationale": "x"}')
        self.assertTrue(ok)
        self.assertEqual(p["command"], "nmap -sV 10.0.0.1")

    def test_fenced_fallback(self):
        p, ok = parse_answer("Run:\n```bash\nnmap -sV 10.0.0.1\n```")
        self.assertFalse(ok)
        self.assertEqual(p["command"], "nmap -sV 10.0.0.1")


if __name__ == "__main__":
    unittest.main()
