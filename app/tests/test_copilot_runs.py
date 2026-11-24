"""The console's copilot runs, live feed and free prompts (app/copilot_runs.py).

n8n's side is replayed from real executions of the workflow on n8n 2.48.7 (tests/fixtures/n8n_execution_*.json:
authorized, waiting for approval, blocked by policy, out of scope, operator unreachable; the webhook secret redacted).
Free prompts go to the model stand-in (app/tests/model_standin.py). Standard library only.

    python -m unittest discover -s app/tests
"""
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import copilot_runs as CR  # noqa: E402
import k8sjobs  # noqa: E402
import model_standin  # noqa: E402


def fixture(name):
    with open(os.path.join(HERE, "fixtures", f"n8n_execution_{name}.json"), encoding="utf-8") as f:
        return json.load(f)


def partial(ex, n):
    """The execution as n8n reports it while running: only the first n finished nodes."""
    ex = json.loads(json.dumps(ex))
    rd = ex["data"]["resultData"]["runData"]
    keep = sorted(rd, key=lambda k: rd[k][0]["executionIndex"])[:n]
    ex["data"]["resultData"]["runData"] = {k: rd[k] for k in keep}
    ex["status"], ex["finished"] = "running", False
    ex["data"]["resultData"].pop("error", None)
    return ex


class HTTPError(Exception):
    def __init__(self, status, msg):
        super().__init__(f"{status} {msg}")
        self.status, self.msg = status, msg


def new_run(rid="1"):
    return {"id": rid, "task": "t", "target": "10.10.10.5", "who": {"user": "admin"}, "started": "", "status": "running",
            "n8n_status": "new", "events": [], "result": None, "_seen": set(), "_waiting_since": None}


class TestFeed(unittest.TestCase):
    def test_order_after_limit_and_source(self):
        f = CR.Feed(maxlen=5)
        for i in range(7):
            f.emit("copilot" if i % 2 else "model", "s", f"m{i}")
        page = f.since(0)
        self.assertEqual([e["message"] for e in page["events"]], ["m2", "m3", "m4", "m5", "m6"])   # bounded
        self.assertEqual(page["latest"], 7)
        self.assertEqual([e["message"] for e in f.since(5)["events"]], ["m5", "m6"])
        self.assertEqual([e["message"] for e in f.since(0, source="copilot")["events"]], ["m3", "m5"])
        two = f.since(0, limit=2)
        self.assertEqual((len(two["events"]), two["next"]), (2, 4))
        self.assertEqual(f.since(7)["next"], 7)
        self.assertEqual(set(page["events"][0]), {"seq", "ts", "source", "run_id", "stage", "level", "message", "data"})


class TestEventsFromRealExecutions(unittest.TestCase):
    def absorb(self, name):
        runs = CR.CopilotRuns("http://n8n", None, CR.Feed())
        run = new_run()
        ended = runs.absorb(run, fixture(name))
        return run, ended

    def stages(self, run):
        return [e["stage"] for e in run["events"]]

    def test_authorized_auto_run(self):
        run, ended = self.absorb("authorized")
        self.assertTrue(ended)
        self.assertEqual(run["status"], "done")
        self.assertEqual(self.stages(run)[:2], ["scope", "error"])        # no Qdrant on that n8n: retrieval failed, run continued
        self.assertEqual([s for s in self.stages(run) if s != "error"],
                         ["scope", "retrieval", "proposal", "policy", "judge", "result", "execute", "end"])
        warn = next(e for e in run["events"] if e["stage"] == "error")
        self.assertEqual(warn["level"], "warn")                               # tolerated: the run went on
        r = run["result"]
        self.assertEqual((r["title"], r["allowed"], r["autoRun"], r["command"]),
                         ("Authorized: auto-run (passive tier)", True, True, "nmap -sV -Pn 10.10.10.5"))
        self.assertIn("disabled: nothing ran", r["next"])
        self.assertIn("nothing ran", run["events"][-2]["message"])          # the Execute node is reported as disabled
        self.assertEqual(run["events"][-1]["message"], "copilot run 1 done: Authorized: auto-run (passive tier)")

    def test_waiting_for_approval(self):
        run, ended = self.absorb("waiting")
        self.assertFalse(ended)
        self.assertEqual(run["status"], "waiting")
        self.assertEqual(run["result"]["title"], "Authorized: waiting for your approval")
        self.assertIn("hydra", run["result"]["command"])
        approval = next(e for e in run["events"] if e["stage"] == "approval")
        self.assertIn("nothing runs until it is resumed", approval["message"])

    def test_blocked_by_policy(self):
        run, ended = self.absorb("policy")
        self.assertTrue(ended)
        pol = next(e for e in run["events"] if e["stage"] == "policy")
        self.assertEqual(pol["level"], "warn")
        self.assertTrue(pol["message"].startswith("policy: blocked"))
        self.assertNotIn("judge", self.stages(run))                        # the judge never saw it
        self.assertEqual(run["result"]["title"], "Blocked by the policy gate")
        self.assertFalse(run["result"]["allowed"])

    def test_out_of_scope_calls_no_model(self):
        run, _ = self.absorb("scope")
        self.assertEqual(self.stages(run), ["scope", "result", "end"])
        self.assertEqual(run["events"][0]["level"], "warn")
        self.assertIn("No model was called", run["result"]["next"])

    def test_operator_unreachable(self):
        run, ended = self.absorb("error")
        self.assertTrue(ended)
        self.assertEqual(run["status"], "error")
        errs = [e for e in run["events"] if e["stage"] == "error"]
        self.assertTrue(any(e["level"] == "error" and "Connection error" in e["message"] for e in errs), errs)
        self.assertIsNone(run["result"])

    def test_no_event_carries_the_webhook_headers(self):
        for name in ("authorized", "waiting", "policy", "scope", "error"):
            run, _ = self.absorb(name)
            dump = json.dumps(run["events"])
            self.assertNotIn("x-lab-secret", dump.lower(), name)
            self.assertNotIn("<redacted>", dump, name)
            self.assertNotIn("headers", dump, name)

    def test_progress_without_duplicates(self):
        runs, run, ex = CR.CopilotRuns("http://n8n", None, CR.Feed()), new_run(), fixture("authorized")
        seen = []
        for n in (3, 7, 7, 12, 20):
            self.assertFalse(runs.absorb(run, partial(ex, n)))
            seen.append(len(run["events"]))
        self.assertTrue(runs.absorb(run, ex))
        stages = [s for s in self.stages(run) if s != "error"]
        self.assertEqual(stages, ["scope", "retrieval", "proposal", "policy", "judge", "result", "execute", "end"])   # each once
        self.assertEqual(seen[1], seen[2])                                   # the same snapshot twice adds nothing


class FakeN8n:
    """Webhook + public executions API. Executions advance one snapshot per GET; stop cancels a waiting one."""

    def __init__(self, secret, api_key):
        self.secret, self.api_key = secret, api_key
        self.snapshots, self.calls, self.next_id = {}, [], 100
        self.plan = []
        srv = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj):
                raw = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                srv.calls.append(("POST", self.path, dict(self.headers), body))
                if self.path == "/webhook/copilot-run":
                    if self.headers.get("X-Lab-Secret") != srv.secret:
                        return self._send(403, {"message": "Authorization data is wrong!"})
                    srv.next_id += 1
                    eid = str(srv.next_id)
                    srv.snapshots[eid] = list(srv.plan)
                    return self._send(202, {"execution_id": eid})
                if self.path.endswith("/stop") and self.headers.get("X-N8N-API-KEY") == srv.api_key:
                    eid = self.path.split("/")[-2]
                    last = json.loads(json.dumps(srv.snapshots[eid][-1]))
                    last["status"] = "canceled"
                    srv.snapshots[eid] = [last]
                    return self._send(200, {"id": eid, "status": "canceled"})
                return self._send(404, {"message": "not found"})

            def do_GET(self):
                srv.calls.append(("GET", self.path, dict(self.headers), None))
                if self.headers.get("X-N8N-API-KEY") != srv.api_key:
                    return self._send(401, {"message": "unauthorized"})
                eid = self.path.split("/executions/")[1].split("?")[0]
                snaps = srv.snapshots[eid]
                snap = snaps.pop(0) if len(snaps) > 1 else snaps[0]
                return self._send(200, snap)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


class TestCopilotRuns(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.secrets = os.path.join(self.dir, "secrets")
        os.makedirs(self.secrets)
        for name, value in (("webhook-secret", "s3cret"), ("n8n-api-key", "k3y")):
            with open(os.path.join(self.secrets, name), "w") as f:
                f.write(value + "\n")
        self.n8n = FakeN8n("s3cret", "k3y")
        self.feed = CR.Feed()
        self.audit = k8sjobs.Audit(self.dir, feed=self.feed)
        self.runs = CR.CopilotRuns(self.n8n.url, self.secrets, self.feed, audit=self.audit, http_error=HTTPError, poll=0.01, waiting_poll=0.01)

    def tearDown(self):
        self.n8n.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def wait(self, rid, statuses, t=5):
        t0 = time.time()
        while time.time() - t0 < t:
            if self.runs.get(rid)["status"] in statuses:
                return self.runs.get(rid)
            time.sleep(0.01)
        self.fail(f"run {rid} stayed {self.runs.get(rid)['status']}")

    def test_run_followed_to_its_result_and_audited(self):
        ex = fixture("authorized")
        self.n8n.plan = [partial(ex, 3), partial(ex, 9), ex]
        out = self.runs.start("Enumerate services", "10.10.10.5", {"user": "admin", "ip": "10.42.0.7"})
        hook = next(c for c in self.n8n.calls if c[1] == "/webhook/copilot-run")
        self.assertEqual(hook[3], {"task": "Enumerate services", "target": "10.10.10.5", "requested_by": "admin"})
        run = self.wait(out["id"], ("done",))
        self.assertEqual(run["result"]["title"], "Authorized: auto-run (passive tier)")
        audit = [(r["stage"], r["who"].get("user")) for r in reversed(self.audit.recent(10))]
        self.assertEqual(audit, [("start", "admin"), ("end", "admin")])
        feed = [e["stage"] for e in self.feed.since(0)["events"] if e["source"] == "copilot"]
        self.assertEqual(feed[0], "start")
        self.assertEqual(feed[-1], "end")
        self.assertIn("result", feed)
        self.assertEqual(self.runs.status()["runs"][0]["title"], "Authorized: auto-run (passive tier)")

    def test_stop_a_waiting_run(self):
        self.n8n.plan = [fixture("waiting")]
        out = self.runs.start("brute force ssh", "10.10.10.5", {"user": "admin"})
        self.wait(out["id"], ("waiting",))
        self.runs.stop(out["id"], {"user": "admin"})
        stop = next(c for c in self.n8n.calls if c[1].endswith("/stop"))
        self.assertEqual({k.lower(): v for k, v in stop[2].items()}.get("x-n8n-api-key"), "k3y")
        self.assertEqual(self.wait(out["id"], ("canceled",))["status"], "canceled")
        self.assertEqual([r["stage"] for r in self.audit.recent(3)], ["end", "stop", "start"])
        with self.assertRaises(HTTPError) as e:
            self.runs.stop(out["id"], {})
        self.assertEqual(e.exception.status, 409)

    def test_not_connected_wrong_secret_and_bad_input(self):
        with self.assertRaises(HTTPError) as e:
            self.runs.start("t", "two words", {})
        self.assertEqual(e.exception.status, 400)
        with open(os.path.join(self.secrets, "webhook-secret"), "w") as f:
            f.write("rotated-elsewhere")                                   # read on every use: no restart needed
        with self.assertRaises(HTTPError) as e:
            self.runs.start("t", "10.10.10.5", {})
        self.assertEqual(e.exception.status, 502)
        self.assertIn("secret does not match", e.exception.msg)
        os.remove(os.path.join(self.secrets, "n8n-api-key"))
        st = self.runs.status()
        self.assertEqual((st["configured"], st["missing"]), (False, ["n8n-api-key"]))
        with self.assertRaises(HTTPError) as e:
            self.runs.start("t", "10.10.10.5", {})
        self.assertEqual(e.exception.status, 409)
        self.assertIn("connect_console.py", e.exception.msg)

    def test_unknown_run(self):
        with self.assertRaises(HTTPError) as e:
            self.runs.get("999")
        self.assertEqual(e.exception.status, 404)


class TestModelChat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), model_standin.H)
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.feed = CR.Feed()
        self.audit = k8sjobs.Audit(self.dir, feed=self.feed)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_streams_tokens_and_audits_prompt_and_answer(self):
        chat = CR.ModelChat(self.url, "glm-abl", self.feed, audit=self.audit)
        evs = list(chat.stream("hello model, how are you", 64, {"user": "admin"}))
        tokens = "".join(e["token"] for e in evs if "token" in e)
        self.assertEqual(tokens, "stand-in answer to: hello model, how are you")
        self.assertTrue(evs[-1]["done"])
        rec = self.audit.recent(1)[0]
        self.assertEqual((rec["source"], rec["stage"], rec["who"]["user"]), ("model", "prompt", "admin"))
        self.assertEqual(rec["data"]["prompt"], "hello model, how are you")
        self.assertEqual(rec["data"]["answer"], tokens)
        self.assertEqual(self.feed.since(0)["events"][-1]["stage"], "prompt")

    def test_max_tokens_limits_the_answer(self):
        chat = CR.ModelChat(self.url, "glm-abl", self.feed, audit=self.audit)
        self.assertEqual(len([e for e in chat.stream("one two three four five", 2) if "token" in e]), 2)

    def test_errors_are_reported_and_audited(self):
        for base, part in ((self.url + "/nope", "HTTP 404"), ("http://127.0.0.1:9", "not reachable")):
            evs = list(CR.ModelChat(base, "glm-abl", self.feed, audit=self.audit).stream("x", 8))
            self.assertIn(part, evs[-1]["error"])
            self.assertEqual(self.audit.recent(1)[0]["level"], "error")

    def test_a_closed_stream_is_still_audited(self):
        gen = CR.ModelChat(self.url, "glm-abl", self.feed, audit=self.audit).stream("hello there friend", 64)
        next(gen)
        gen.close()                                                          # the browser went away
        rec = self.audit.recent(1)[0]
        self.assertEqual(rec["data"]["error"], "the browser closed the stream")
        self.assertEqual(rec["data"]["answer"], "stand-in ")


class TestModelWatch(unittest.TestCase):
    def test_emits_only_changes(self):
        states = iter(["running", "running", "isolated", "isolated", "killed"])

        class Control:
            def status(self):
                return {"state": next(states), "replicas": 1, "ready": 1}
        feed = CR.Feed()
        w = CR.ModelWatch(Control(), feed)
        for _ in range(5):
            w.check()
        self.assertEqual([e["message"] for e in feed.since(0)["events"]],
                         ["model server running", "model server running -> isolated", "model server isolated -> killed"])
        self.assertEqual([e["level"] for e in feed.since(0)["events"]], ["info", "warn", "warn"])


if __name__ == "__main__":
    unittest.main()
