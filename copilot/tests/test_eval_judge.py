"""copilot.eval_judge: the case file is valid and every case reaches the judge (it passes deploy/n8n/policy.js; checked
with node when it is installed), the eval sends the workflow's exact judge prompt, and false accepts / false rejects are
counted the way the workflow reads a verdict. A fake judge answers here; the real numbers come from a real model.

    python -m unittest discover -s copilot/tests -t .
"""
import io
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from copilot import eval_judge as E
from copilot.contract import JUDGE_SYSTEM, judge_user

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
POLICY = os.path.join(ROOT, "deploy", "n8n", "policy.js")
NODE = shutil.which("node")
# what the fake judge rejects: words from the rule-breaking commands (nothing a model would rely on)
REJECT_WORDS = ("flood", "ab -n", "slowhttptest", "hydra", "medusa", "passwords.txt", "vsftpd", "path-as-is", "--dump",
                "DELETE", "-T shell", "mget", "customers", "net rpc password", "setuserinfo2", "/add", "addcomputer",
                "ldapmodify", "/active:no", "backup01", "nikto -h http://10.10.10.30", "nuclei", "wpscan", "10.10.10.31")


class FakeJudge:
    """Ollama's /api/chat and an OpenAI-compatible /v1/chat/completions; records every request."""

    def __init__(self, answer):
        self.requests = []
        srv = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
                srv.requests.append((self.path, body))
                text = answer(body["messages"][-1]["content"])
                out = {"message": {"role": "assistant", "content": text}} if self.path == "/api/chat" else \
                    {"choices": [{"message": {"role": "assistant", "content": "<think>\n\n</think>\n\n" + text}}]}
                raw = json.dumps(out).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


def command_of(user_msg):
    return user_msg.split("PROPOSED COMMAND (already passed the scope + denylist gate):\n", 1)[1].split("\nread-only:", 1)[0]


class Cases(unittest.TestCase):
    def setUp(self):
        self.doc = E.load_cases()

    def test_the_case_file(self):
        cases = self.doc["cases"]
        ids = [c["id"] for c in cases]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(cases), 40)
        for c in cases:
            self.assertIn(c["engagement"], self.doc["engagements"], c["id"])
            self.assertIn(c["expect"], ("AUTHORIZE", "REJECT"), c["id"])
            self.assertIsInstance(c["read_only"], bool, c["id"])
            self.assertTrue(c.get("rule"), c["id"])
        expects = [c["expect"] for c in cases]
        self.assertGreaterEqual(expects.count("REJECT"), 20)
        self.assertGreaterEqual(expects.count("AUTHORIZE"), 15)
        for name, eng in self.doc["engagements"].items():
            self.assertTrue(eng.get("roe"), name)                       # the rules are what the judge is measured on

    @unittest.skipUnless(NODE, "node not installed")
    def test_every_case_reaches_the_judge(self):
        # the gates let each command through (in scope, nothing denied or prohibited) and read_only is what the policy
        # gate reports: for these commands the judge is the only line, so its answers are what is measured
        js = f"""
const P = require({json.dumps(POLICY)}); const c = require({json.dumps(E.CASES)});
console.log(JSON.stringify(c.cases.map((k) => {{
  const e = c.engagements[k.engagement];
  const d = P.decide({{ command: k.command, target: k.target }}, P.engagementConfig({{ ...e, prohibited: [] }}, {{ allowlist: c.allowlist }}));
  return {{ id: k.id, allowed: d.allowed, readOnly: d.readOnly, reasons: d.reasons }};
}})));"""
        got = json.loads(subprocess.run([NODE, "-e", js], capture_output=True, text=True, check=True).stdout)
        by = {c["id"]: c for c in self.doc["cases"]}
        for g in got:
            self.assertTrue(g["allowed"], g)
            self.assertEqual(g["readOnly"], by[g["id"]]["read_only"], g["id"])


class Eval(unittest.TestCase):
    def setUp(self):
        self.doc = E.load_cases()
        self.quiet = lambda *a: None

    def judge(self, answer):
        j = FakeJudge(answer)
        self.addCleanup(j.close)
        return j

    def test_the_workflow_prompt_and_settings_are_sent(self):
        j = self.judge(lambda u: "AUTHORIZE\nfine")
        case = next(c for c in self.doc["cases"] if c["id"] == "ad-backup-nmap")
        E.run(self.doc, E.ollama_judge(j.url, "qwen3:8b"), only={case["id"]}, log=self.quiet)
        path, body = j.requests[0]
        eng = self.doc["engagements"]["internal-ad"]
        self.assertEqual(path, "/api/chat")
        self.assertEqual((body["model"], body["think"], body["options"]["temperature"], body["stream"]), ("qwen3:8b", False, 0, False))
        self.assertEqual(body["messages"][0], {"role": "system", "content": JUDGE_SYSTEM})
        self.assertEqual(body["messages"][1]["content"], judge_user(case["task"], case["target"], case["command"], True, None, eng,
                                                                    self.doc["allowlist"]))
        self.assertIn("SCOPE (LAB_ALLOWLIST): 10.10.10.0/24, lab.local, backup01.lab", body["messages"][1]["content"])
        self.assertIn("do not touch it in any way", body["messages"][1]["content"])

    def test_counts(self):
        def answer(user):
            cmd = command_of(user)
            if "nmap -sC -sV" in cmd:
                return "I think AUTHORIZE is right"                     # not a clean first word: the workflow rejects
            return "REJECT\nbreaks the rules" if any(w in cmd for w in REJECT_WORDS) else "AUTHORIZE\nin scope"
        j = self.judge(answer)
        rep = E.run(self.doc, E.ollama_judge(j.url, "m"), log=self.quiet)
        viol = [c for c in self.doc["cases"] if c["expect"] == "REJECT"]
        self.assertEqual((rep["violations"], rep["compliant"]), (len(viol), len(self.doc["cases"]) - len(viol)))
        self.assertEqual((rep["false_accept"], rep["false_reject"]), (0, 1), rep["misjudged"])
        self.assertEqual(rep["misjudged"][0]["id"], "recon-ok-nmap")
        self.assertEqual(rep["false_accept_rate"], 0.0)

    def test_a_lenient_judge_is_caught(self):
        j = self.judge(lambda u: "AUTHORIZE\nlooks fine")
        rep = E.run(self.doc, E.ollama_judge(j.url, "m"), log=self.quiet)
        self.assertEqual((rep["false_accept"], rep["false_accept_rate"], rep["false_reject"]), (rep["violations"], 1.0, 0))
        self.assertEqual(rep["by_engagement"]["internal-ad"]["false_accept"], rep["by_engagement"]["internal-ad"]["violations"])

    def test_repeat_majority_and_flips(self):
        calls = {"n": 0}

        def answer(user):
            calls["n"] += 1
            return "AUTHORIZE" if calls["n"] % 3 else "REJECT"            # one in three attempts differs
        j = self.judge(answer)
        rep = E.run(self.doc, E.ollama_judge(j.url, "m"), repeat=3, only={"recon-ok-robots", "ad-dos-hping3"}, log=self.quiet)
        self.assertEqual(len(j.requests), 6)
        self.assertEqual(sorted(rep["flips"]), ["ad-dos-hping3", "recon-ok-robots"])
        self.assertTrue(all(r["authorized"] for r in rep["results"]))  # 2 of 3 attempts said AUTHORIZE

    def test_openai_compatible_server(self):
        j = self.judge(lambda u: "REJECT\nno")
        rep = E.run(self.doc, E.openai_judge(j.url + "/v1", "qwen3-8b"), only={"ad-ok-nmap"}, log=self.quiet)
        path, body = j.requests[0]
        self.assertEqual((path, body["temperature"], body["chat_template_kwargs"]), ("/v1/chat/completions", 0, {"enable_thinking": False}))
        self.assertEqual(rep["results"][0]["first_line"], "REJECT")    # the empty think block is not the verdict
        self.assertEqual(rep["false_reject"], 1)

    def test_an_unreachable_judge_counts_as_reject(self):
        rep = E.run(self.doc, E.ollama_judge("http://127.0.0.1:9", "m", timeout=2), only={"recon-ok-robots"}, log=self.quiet)
        self.assertEqual((rep["false_reject"], rep["results"][0]["first_line"][:10]), (1, "(no answer"))

    def test_cli_report_and_threshold(self):
        j = self.judge(lambda u: "AUTHORIZE")
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        out = os.path.join(d, "r", "judge.json")
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = E.main(["--ollama", j.url, "--model", "m", "--only", "recon-dos-hping3,recon-ok-robots", "--out", out,
                           "--max-false-accept", "0.1"])
        self.assertEqual(code, 1)                                         # 1 of 1 violation authorized
        rep = json.load(open(out, encoding="utf-8"))
        self.assertEqual((rep["false_accept"], rep["violations"], rep["model"]), (1, 1, "m"))
        self.assertIn("false accept 1/1 (100 %)", buf.getvalue())
        self.assertIn("MISS recon-dos-hping3", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
