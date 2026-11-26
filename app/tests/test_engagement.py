"""The copilot's engagement (app/engagement.py): validation, the LAB_ALLOWLIST ceiling, versions, audit, the payload a
run carries; the same scope read by n8n's policy gate (deploy/n8n/policy.js, run with node when it is installed); and
the HTTP layer: /api/engagement, /api/copilot/models, a run's payload, model checks.

    python -m unittest discover -s app/tests
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import engagement as EN  # noqa: E402
import k8sjobs  # noqa: E402
import copilot_runs as CR  # noqa: E402

POLICY = os.path.join(HERE, "..", "..", "deploy", "n8n", "policy.js")
NODE = shutil.which("node")
CEIL = "10.10.10.0/24,192.168.56.0/24,box.htb,127.0.0.1"


class HTTPError(Exception):
    def __init__(self, status, msg):
        super().__init__(f"{status} {msg}")
        self.status, self.msg = status, msg


GOOD = {"name": "ACME internal", "scope_statement": "Only the web tier.", "roe": "No DoS.\r\nStop on PII.",
        "scope_in": "10.10.10.0/28\n10.10.10.5/24, BOX.htb", "scope_out": ["10.10.10.1"], "prohibited": "hydra\n  -T5 \nHydra\nscript   brute",
        "window_start": "2026-11-26T08:00+01:00", "window_end": "2026-11-26T18:00:00Z", "autorun_passive": True, "autorun_active": False}


class Entries(unittest.TestCase):
    def test_scope_entries(self):
        self.assertEqual(EN.scope_entry(" 10.10.10.5 "), ("ip", "10.10.10.5"))
        self.assertEqual(EN.scope_entry("10.10.10.5/24"), ("net", "10.10.10.0/24"))       # host bits cleared, as the gate masks them
        self.assertEqual(EN.scope_entry("Box.HTB"), ("host", "box.htb"))
        for bad in ("", "*.htb", "2001:db8::1", "10.10.10.300", "10.10.10.0/33", "a b", "-bad.host", "host_name.htb", "10.10.10"):
            with self.assertRaises(ValueError, msg=bad):
                EN.scope_entry(bad)

    def test_within_the_ceiling(self):
        c = EN.parse_ceiling(CEIL + ",not valid!")
        self.assertEqual(len(c), 4)
        inside = ["10.10.10.5", "10.10.10.0/28", "10.10.10.0/24", "box.htb", "127.0.0.1", "127.0.0.1/32"]
        outside = ["10.10.11.5", "10.10.0.0/16", "other.htb", "127.0.0.2", "192.168.0.0/16"]
        for e in inside:
            self.assertTrue(EN.within(EN.scope_entry(e), c), e)
        for e in outside:
            self.assertFalse(EN.within(EN.scope_entry(e), c), e)


class Store(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.feed = CR.Feed()
        self.audit = k8sjobs.Audit(self.dir, feed=self.feed)
        self.e = EN.Engagements(self.dir, audit=self.audit, ceiling=CEIL, autorun={"passive": True, "active": False}, http_error=HTTPError)

    def bad(self, fields, part):
        with self.assertRaises(HTTPError, msg=part) as cm:
            self.e.validate(fields)
        self.assertEqual(cm.exception.status, 400)
        self.assertIn(part, cm.exception.msg)

    def test_validate_normalises(self):
        v = self.e.validate(GOOD)
        self.assertEqual(v["scope_in"], ["10.10.10.0/28", "10.10.10.0/24", "box.htb"])
        self.assertEqual(v["prohibited"], ["hydra", "-T5", "script brute"])               # trimmed, one space, no case duplicates
        self.assertEqual((v["window_start"], v["window_end"]), ("2026-11-26T08:00:00+01:00", "2026-11-26T18:00:00+00:00"))
        self.assertEqual(v["roe"], "No DoS.\nStop on PII.")
        self.assertEqual((v["autorun_passive"], v["autorun_active"], v["active"]), (True, False, True))

    def test_validate_refuses(self):
        self.bad({**GOOD, "scope_in": "10.10.0.0/16"}, "10.10.0.0/16 is outside LAB_ALLOWLIST")
        self.bad({**GOOD, "scope_in": "*.htb"}, "no wildcards")
        self.bad({**GOOD, "window_start": "2026-11-26T08:00"}, "give a time zone")
        self.bad({**GOOD, "window_start": "tomorrow"}, "not a date and time")
        self.bad({**GOOD, "window_end": "2026-11-26T06:00:00Z"}, "window_end: must be after window_start")
        self.bad({**GOOD, "prohibited": "x" * 65}, "longer than 64")
        self.bad({**GOOD, "roe": "x" * 8001}, "roe: at most 8000")
        self.bad({**GOOD, "name": "bell\x07"}, "control characters")
        self.bad({**GOOD, "autorun_passive": "yes"}, "autorun_passive: true or false")
        self.bad({**GOOD, "scope_out": [f"10.10.10.{i}" for i in range(65)]}, "at most 64 entries")
        self.bad([], "a JSON object")
        # every problem at once
        with self.assertRaises(HTTPError) as cm:
            self.e.validate({**GOOD, "scope_in": "8.8.8.8", "window_start": "x"})
        self.assertIn("8.8.8.8", cm.exception.msg)
        self.assertIn("window_start", cm.exception.msg)

    def test_scope_out_may_name_anything(self):
        # exclusions only narrow: an exclusion outside the ceiling is harmless
        self.assertEqual(self.e.validate({**GOOD, "scope_out": "8.8.8.8"})["scope_out"], ["8.8.8.8"])

    def test_without_a_known_ceiling_formats_are_still_checked(self):
        e = EN.Engagements(self.dir, http_error=HTTPError)
        self.assertEqual(e.validate({"scope_in": "10.20.0.0/16"})["scope_in"], ["10.20.0.0/16"])   # n8n's ceiling decides
        with self.assertRaises(HTTPError):
            e.validate({"scope_in": "10.20.0.0/40"})
        self.assertFalse(e.status()["ceiling"]["known"])

    def test_versions_audit_payload(self):
        self.assertIsNone(self.e.current())
        self.assertIsNone(self.e.payload())
        r1 = self.e.save(GOOD, {"user": "admin", "ip": "10.42.0.7"}, note="kickoff")
        self.assertEqual((r1["version"], r1["by"], r1["note"]), (1, "admin", "kickoff"))
        self.assertEqual(self.e.save(GOOD, {"user": "other"})["version"], 1)               # the same fields: no new version
        r2 = self.e.save({**GOOD, "scope_out": ["10.10.10.1", "10.10.10.2"]}, {"ip": "10.42.0.8"})
        self.assertEqual((r2["version"], r2["by"]), (2, "10.42.0.8"))
        self.assertEqual([v["version"] for v in self.e.versions()], [2, 1])
        self.assertEqual(self.e.get(1)["scope_out"], ["10.10.10.1"])
        with self.assertRaises(HTTPError):
            self.e.get(9)
        recs = [r for r in self.audit.recent(10) if r["stage"] == "engagement"]
        self.assertEqual(len(recs), 2)
        self.assertEqual((recs[0]["data"]["version"], recs[0]["data"]["changed"], recs[0]["who"]["ip"]), (2, ["scope_out"], "10.42.0.8"))
        self.assertEqual(recs[1]["message"], "engagement v1 saved: ACME internal")
        p = self.e.payload()
        self.assertEqual(sorted(p), sorted(["name", "version", "scope_statement", "roe", "scope_in", "scope_out", "window_start",
                                            "window_end", "prohibited", "autorun_passive", "autorun_active"]))
        self.assertEqual((p["version"], p["scope_out"]), (2, ["10.10.10.1", "10.10.10.2"]))
        self.e.save({**GOOD, "active": False}, {"user": "admin"})
        self.assertIsNone(self.e.payload())                                              # switched off: LAB_ALLOWLIST alone
        st = self.e.status()
        self.assertEqual((st["current"]["version"], st["ceiling"]["allowlist"], st["ceiling"]["autorun_passive"]), (3, CEIL, True))

    def test_hints_for_hosts_the_rules_put_off_limits(self):
        # measured: the judge authorized "nmap -sV backup01.lab" under "do not touch backup01.lab"; Out of scope is code
        f = {**GOOD, "roe": "Exploitation is allowed. The backup server backup01.lab holds production backups: do not touch it.",
             "scope_statement": "The lab, 10.10.10.0/24. Its database server 10.10.10.31 is not a target."}
        self.assertEqual([h["host"] for h in EN.rule_hints(f)], ["backup01.lab", "10.10.10.31"])
        self.assertIn("do not touch it", EN.rule_hints(f)[0]["sentence"])
        self.assertEqual(EN.rule_hints({**f, "scope_out": "backup01.lab\n10.10.10.16/28"}), [])     # excluded already (a CIDR covers .31)
        self.assertEqual(EN.rule_hints({"scope_statement": "Only the web tier, 10.10.10.0/28.", "roe": "Test 10.10.10.5 first."}), [])
        rec = self.e.save({**f, "scope_in": "10.10.10.0/24"}, {"user": "admin"})
        self.assertEqual([h["host"] for h in rec["hints"]], ["backup01.lab", "10.10.10.31"])
        self.assertNotIn("hints", self.e.get(rec["version"]))                                  # worked out, not stored
        self.assertEqual([h["host"] for h in self.e.status()["hints"]], ["backup01.lab", "10.10.10.31"])

    @unittest.skipUnless(NODE, "node not installed")
    def test_n8n_reads_the_saved_scope_as_intended(self):
        # what the console saved, put through the real policy gate: inside the engagement, excluded, outside
        self.e.save({**GOOD, "window_start": "", "window_end": ""}, {"user": "admin"})
        js = f"""
const P = require({json.dumps(POLICY)});
const eng = {json.dumps(self.e.payload())};
const cfg = P.engagementConfig(eng, {{ allowlist: {json.dumps(CEIL.split(","))}, autoRunReadOnly: true }});
const out = {{}};
for (const h of ['10.10.10.5', '10.10.10.1', '10.10.10.200', 'box.htb', '192.168.56.7', '8.8.8.8']) out[h] = P.scopeWhy(h, cfg);
out.hydra = P.decide({{ command: '/usr/bin/hydra -l a ssh://10.10.10.5', target: '10.10.10.5' }}, cfg).reasons;
out.autorun = cfg.autoRunReadOnly;
console.log(JSON.stringify(out));"""
        got = json.loads(subprocess.run([NODE, "-e", js], capture_output=True, text=True, check=True).stdout)
        self.assertEqual({h: got[h] for h in ("10.10.10.5", "10.10.10.1", "10.10.10.200", "box.htb", "192.168.56.7", "8.8.8.8")},
                         {"10.10.10.5": "", "10.10.10.1": "excluded", "10.10.10.200": "", "box.htb": "", "192.168.56.7": "engagement",
                          "8.8.8.8": "allowlist"})                 # 10.10.10.200: inside 10.10.10.0/24, which the scope lists
        self.assertIn("prohibited by the rules of engagement: hydra", got["hydra"])
        self.assertTrue(got["autorun"])


try:
    import fastapi  # noqa: F401
    HAVE_FASTAPI = True
except ImportError:
    HAVE_FASTAPI = False


@unittest.skipUnless(HAVE_FASTAPI, "the console's dependencies are not installed here")
class TestEngagementHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from http.server import ThreadingHTTPServer
        import threading
        import model_standin
        from test_server_control import TestControlHTTP, call
        TestControlHTTP.setUpClass()
        cls.s, cls.call = TestControlHTTP.server, staticmethod(call)
        cls.standin = ThreadingHTTPServer(("127.0.0.1", 0), model_standin.H)
        threading.Thread(target=cls.standin.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.standin.shutdown()
        cls.standin.server_close()

    def setUp(self):
        from test_copilot_runs import FakeN8n
        from test_server_control import keep_server_state
        keep_server_state(self.s, self.addCleanup)                    # the server module is shared with later test classes
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        secrets = os.path.join(self.tmp, "secrets")
        os.makedirs(secrets)
        for name, value in (("webhook-secret", "s3cret"), ("n8n-api-key", "k3y")):
            with open(os.path.join(secrets, name), "w") as f:
                f.write(value)
        self.n8n = FakeN8n("s3cret", "k3y")
        self.addCleanup(self.n8n.close)
        s, url = self.s, f"http://127.0.0.1:{self.standin.server_address[1]}"
        s.copilot.base, s.copilot.secrets_dir = self.n8n.url, secrets
        s.copilot_models.operator_url = s.copilot_models.judge_url = url
        s.copilot_models._cache = (0.0, None)
        s.model_chat.base = url
        s.engagements = EN.Engagements(self.tmp, audit=s.audit, ceiling=CEIL, http_error=s.HTTPException)
        with open(os.path.join(HERE, "fixtures", "n8n_execution_manual.json"), encoding="utf-8") as f:
            self.n8n.plan = [json.load(f)]

    def test_save_read_versions(self):
        st, body = self.call(self.s.app, "POST", "/api/engagement", {"x-lab-user": "admin"}, {**GOOD, "note": "kickoff"})
        self.assertEqual(st, 200, body)
        self.assertEqual((body["version"], body["by"], body["note"]), (1, "admin", "kickoff"))
        st, body = self.call(self.s.app, "POST", "/api/engagement", {}, {**GOOD, "scope_in": "10.99.0.0/16"})
        self.assertEqual(st, 400)
        self.assertIn("outside LAB_ALLOWLIST", body["detail"])
        st, body = self.call(self.s.app, "GET", "/api/engagement")
        self.assertEqual((body["current"]["version"], body["ceiling"]["known"], [v["version"] for v in body["versions"]]), (1, True, [1]))
        self.assertEqual(self.call(self.s.app, "GET", "/api/engagement/versions/1")[1]["name"], "ACME internal")
        self.assertEqual(self.call(self.s.app, "GET", "/api/engagement/versions/7")[0], 404)
        self.assertEqual(self.call(self.s.app, "POST", "/api/engagement", {"origin": "https://evil.example"}, GOOD)[0], 403)

    def test_models_and_a_manual_run_with_the_engagement(self):
        st, models = self.call(self.s.app, "GET", "/api/copilot/models")
        self.assertEqual((st, models["operator"]["models"], models["judge"]["models"]), (200, ["glm-abl"], ["qwen3:8b"]))
        self.call(self.s.app, "POST", "/api/engagement", {"x-lab-user": "admin"}, GOOD)
        st, out = self.call(self.s.app, "POST", "/api/copilot/run", {"x-lab-user": "admin"},
                            {"target": "10.10.10.5", "mode": "manual", "command": "nmap -p 445 --open 10.10.10.5", "judge_model": "qwen3:8b"})
        self.assertEqual(st, 200, out)
        hook = next(c for c in self.n8n.calls if c[1] == "/webhook/copilot-run")[3]
        self.assertEqual((hook["mode"], hook["command"], hook["operator_model"], hook["judge_model"]),
                         ("manual", "nmap -p 445 --open 10.10.10.5", "glm-abl", "qwen3:8b"))
        self.assertEqual((hook["engagement"]["version"], hook["engagement"]["scope_in"]), (1, ["10.10.10.0/28", "10.10.10.0/24", "box.htb"]))
        # let the run's follower finish against this fake n8n: left running, it would keep polling after the fake is gone
        # and later write its "n8n's execution API kept failing" error into the shared feed, under another test
        for _ in range(100):
            if self.s.copilot.get(out["id"])["status"] not in ("running", "waiting"):
                break
            time.sleep(0.1)
        self.assertEqual(self.s.copilot.get(out["id"])["status"], "done")

    def test_refusals_before_n8n_is_asked(self):
        for body, part in (({"task": "t", "target": "10.10.10.5", "judge_model": "glm-abl:latest"}, "refused"),
                           ({"task": "t", "target": "10.10.10.5", "judge_model": "llama3.1:8b"}, "has no model"),
                           ({"task": "t", "target": "10.10.10.5", "operator_model": "nope"}, "glm-serve has no model"),
                           ({"target": "10.10.10.5", "mode": "manual", "command": "a\nb"}, "one line")):
            st, out = self.call(self.s.app, "POST", "/api/copilot/run", {}, body)
            self.assertEqual(st, 400, (body, out))
            self.assertIn(part, out["detail"], body)
        self.assertEqual(self.call(self.s.app, "POST", "/api/copilot/run", {}, {"target": "10.10.10.5", "mode": "shell"})[0], 422)
        self.assertEqual([c for c in self.n8n.calls if c[1] == "/webhook/copilot-run"], [])
        st, out = self.call(self.s.app, "POST", "/api/model/chat", {}, {"prompt": "hi", "model": "not-served"})
        self.assertEqual(st, 400)
        self.assertIn("glm-serve has no model", out["detail"])


if __name__ == "__main__":
    unittest.main()
