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
                         ["scope", "retrieval", "prompt", "proposal", "policy", "judge_prompt", "judge", "result", "execute", "end"])
        warn = next(e for e in run["events"] if e["stage"] == "error")
        self.assertEqual(warn["level"], "warn")                               # tolerated: the run went on
        r = run["result"]
        self.assertEqual((r["title"], r["allowed"], r["autoRun"], r["command"]),
                         ("Authorized: auto-run (passive tier)", True, True, "nmap -sV -Pn 10.10.10.5"))
        self.assertIn("disabled: nothing ran", r["next"])
        self.assertEqual((r["staged"], r["mode"], r["operator_model"], r["judge_model"], r["engagement"]),
                         ("nmap -sV -Pn 10.10.10.5", "copilot", "glm-abl", "qwen3:8b", None))
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
        self.assertNotIn("judge_prompt", self.stages(run))
        self.assertEqual(run["result"]["title"], "Blocked by the policy gate")
        self.assertFalse(run["result"]["allowed"])
        self.assertEqual(run["result"]["staged"], "")                      # nothing staged when blocked

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
        for name in ("authorized", "waiting", "policy", "scope", "error", "manual", "engagement_scope", "prohibited", "judge_refused"):
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
        self.assertEqual(stages, ["scope", "retrieval", "prompt", "proposal", "policy", "judge_prompt", "judge", "result", "execute", "end"])   # each once
        self.assertEqual(seen[1], seen[2])                                   # the same snapshot twice adds nothing


class TestEventsV2(unittest.TestCase):
    """Real executions of the workflow with the engagement, model choice, manual mode and the visible prompts."""
    absorb = TestEventsFromRealExecutions.absorb
    stages = TestEventsFromRealExecutions.stages

    def ev(self, run, stage):
        return next(e for e in run["events"] if e["stage"] == stage)

    def test_the_prompt_to_the_abliterated_model_and_its_answer(self):
        run, _ = self.absorb("prohibited")                                 # an engagement: its rules are in the prompt
        p = self.ev(run, "prompt")
        self.assertEqual(p["data"]["model"], "glm-abl")
        self.assertTrue(p["data"]["prompt"].startswith("TASK: brute force ssh\nTARGET (authorized, in scope): 10.10.10.5\n\nRULES OF ENGAGEMENT"))
        self.assertIn("PROHIBITED: hydra", p["data"]["prompt"])
        answer = self.ev(run, "proposal")
        self.assertIn('"command": "hydra', answer["data"]["raw"])          # the model's own answer, as it came back
        self.assertEqual(answer["data"]["model"], "glm-abl")

    def test_prohibited_by_the_engagement(self):
        run, ended = self.absorb("prohibited")
        pol = self.ev(run, "policy")
        self.assertEqual((pol["level"], pol["data"]["prohibited"]), ("warn", ["hydra"]))
        self.assertIn("prohibited by the rules of engagement: hydra", pol["data"]["reasons"])
        self.assertNotIn("judge_prompt", self.stages(run))
        self.assertEqual((run["result"]["engagement"], run["result"]["staged"]), ({"name": "ACME internal", "version": 3}, ""))

    def test_manual_mode(self):
        run, ended = self.absorb("manual")
        self.assertTrue(ended)
        self.assertEqual(self.stages(run), ["scope", "proposal", "policy", "judge_prompt", "judge", "result", "execute", "end"])
        prop = self.ev(run, "proposal")
        self.assertEqual((prop["data"]["manual"], prop["data"]["proposal"]["command"]), (True, "nmap -p 445 --open 10.10.10.5"))
        self.assertTrue(prop["message"].startswith("typed by the operator"))
        jp = self.ev(run, "judge_prompt")
        self.assertEqual(jp["data"]["model"], "qwen3:8b")
        self.assertIn("RULES OF ENGAGEMENT", jp["data"]["prompt"])
        self.assertTrue(jp["data"]["prompt"].endswith("PROPOSED COMMAND (already passed the scope + denylist gate):\nnmap -p 445 --open 10.10.10.5"
                                                      "\nread-only: true  tier: passive"))
        self.assertEqual(self.ev(run, "judge")["data"]["staged"], "nmap -p 445 --open 10.10.10.5")
        r = run["result"]
        self.assertEqual((r["mode"], r["staged"], r["engagement"]["version"]), ("manual", "nmap -p 445 --open 10.10.10.5", 3))

    def test_outside_the_engagement_scope(self):
        run, _ = self.absorb("engagement_scope")
        self.assertEqual(self.stages(run), ["scope", "result", "end"])
        self.assertEqual(self.ev(run, "scope")["data"]["reason"], 'target "10.10.10.100" is outside the engagement scope')
        self.assertIn("engagement decides this", run["result"]["next"])
        run, _ = self.absorb("scope")
        self.assertIn("add it to LAB_ALLOWLIST", run["result"]["next"])

    def test_an_abliterated_judge_fails_the_run(self):
        run, ended = self.absorb("judge_refused")
        self.assertTrue(ended)
        self.assertEqual(run["status"], "error")
        err = next(e for e in run["events"] if e["stage"] == "error" and e["level"] == "error")
        self.assertIn('judge model "glm-abl" refused', err["message"])
        self.assertNotIn("judge", self.stages(run))
        self.assertIsNone(run["result"])


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
        self.httpd.server_close()                 # refused from now on, instead of accepted and never answered


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
        out = self.runs.start("Enumerate services", "10.10.10.5", {"user": "admin", "ip": "10.42.0.7"}, operator_model="glm-abl",
                              judge_model="qwen3:8b", engagement={"name": "ACME", "version": 2, "scope_in": ["10.10.10.0/28"]})
        hook = next(c for c in self.n8n.calls if c[1] == "/webhook/copilot-run")
        self.assertEqual(hook[3], {"task": "Enumerate services", "target": "10.10.10.5", "requested_by": "admin", "mode": "copilot",
                                   "command": "", "operator_model": "glm-abl", "judge_model": "qwen3:8b",
                                   "engagement": {"name": "ACME", "version": 2, "scope_in": ["10.10.10.0/28"]}})
        start = self.audit.recent(1)[0]
        self.assertEqual((start["data"]["mode"], start["data"]["operator_model"], start["data"]["engagement"]),
                         ("copilot", "glm-abl", {"name": "ACME", "version": 2}))
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

    def test_records_come_before_the_status_that_shows_them(self):
        # Whoever sees a run ended must find its "end" in the audit and the feed. A stop is recorded before n8n answers,
        # since the follower can see the run canceled, and record its end, before that answer is back.
        seen, write = {}, self.audit.write

        def spy(source, stage, *a, **kw):
            if stage in ("stop", "end"):
                seen[stage] = self.runs.get(kw["run_id"])["status"]
            return write(source, stage, *a, **kw)

        self.audit.write = spy
        self.n8n.plan = [fixture("waiting")]
        rid = self.runs.start("brute force ssh", "10.10.10.5", {"user": "admin"})["id"]
        self.wait(rid, ("waiting",))
        self.runs.stop(rid, {"user": "admin"})
        self.wait(rid, ("canceled",))
        self.assertEqual(seen, {"stop": "waiting", "end": "waiting"})

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

    def test_manual_mode_and_its_checks(self):
        ex = fixture("manual")
        self.n8n.plan = [ex]
        out = self.runs.start("", "10.10.10.5", {"user": "admin"}, mode="manual", command="nmap -p 445 --open 10.10.10.5",
                              operator_model="glm-abl", judge_model="qwen3:8b")
        hook = next(c for c in self.n8n.calls if c[1] == "/webhook/copilot-run")
        self.assertEqual((hook[3]["mode"], hook[3]["command"], hook[3]["task"]), ("manual", "nmap -p 445 --open 10.10.10.5", ""))
        self.assertEqual((out["mode"], out["command"]), ("manual", "nmap -p 445 --open 10.10.10.5"))
        self.wait(out["id"], ("done",))
        start = next(r for r in reversed(self.audit.recent(10)) if r["stage"] == "start")
        self.assertIn("(manual): manual command nmap -p 445", start["message"])
        for kwargs, part in (({"mode": "manual"}, "command are both required"),
                             ({"mode": "manual", "command": "nmap 10.10.10.5\nrm -rf ~"}, "one line"),
                             ({"mode": "manual", "command": "x" * 2001}, "one line"),
                             ({"mode": "shell", "command": "id"}, "mode is one of"),
                             ({"judge_model": "glm-abl"}, "refused"),
                             ({"judge_model": "llama3-abliterated:8b"}, "refused"),
                             ({"operator_model": "same", "judge_model": "same"}, "refused")):
            with self.assertRaises(HTTPError, msg=kwargs) as e:
                self.runs.start("t", "10.10.10.5", {}, **kwargs)
            self.assertEqual(e.exception.status, 400, kwargs)
            self.assertIn(part, e.exception.msg, kwargs)
        with self.assertRaises(HTTPError) as e:
            self.runs.start("", "10.10.10.5", {})                              # copilot mode needs a task
        self.assertIn("task and target", e.exception.msg)

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


class TestCopilotModels(unittest.TestCase):
    """Operators from glm-serve's /v1/models, judges from the copilot Ollama's /api/tags (the model stand-in serves both)."""
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), model_standin.H)
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def models(self, op=None, judge=None):
        return CR.CopilotModels(self.url if op is None else op, self.url if judge is None else judge, http_error=HTTPError)

    def test_lists_without_abliterated_or_embedding_judges(self):
        m = self.models().list()
        self.assertEqual((m["operator"]["models"], m["operator"]["default"], m["operator"]["error"]), (["glm-abl"], "glm-abl", None))
        self.assertEqual((m["judge"]["models"], m["judge"]["default"]), (["qwen3:8b"], "qwen3:8b"))
        self.assertEqual({x["name"]: x["why"].split(":")[0] for x in m["judge"]["excluded"]},
                         {"glm-abl:latest": "abliterated", "nomic-embed-text:latest": "an embedding model, not a chat model"})

    def test_check(self):
        m = self.models()
        self.assertEqual(m.check(), ("glm-abl", "qwen3:8b"))                  # nothing chosen: the defaults
        self.assertEqual(m.check("glm-abl:latest", "qwen3:8b"), ("glm-abl:latest", "qwen3:8b"))
        for op, judge, part in (("glm-abl", "glm-abl:latest", "refused"), (None, "glm-edge-1.5b-chat-abl", "refused"),
                                ("qwen3:8b", "qwen3:8b", "refused"), (None, "llama3.1:8b", "has no model 'llama3.1:8b'"),
                                ("other", None, "glm-serve has no model 'other'"), ("rm -rf", None, "not a model name")):
            with self.assertRaises(HTTPError, msg=(op, judge)) as e:
                m.check(op, judge)
            self.assertEqual(e.exception.status, 400)
            self.assertIn(part, e.exception.msg, (op, judge))

    def test_servers_down(self):
        m = self.models("http://127.0.0.1:9", "http://127.0.0.1:9")
        lst = m.list()
        self.assertIn("did not list", lst["operator"]["error"])
        self.assertIn("did not list", lst["judge"]["error"])
        self.assertEqual(m.check("glm-abl", "llama3.1:8b"), ("glm-abl", "llama3.1:8b"))   # can't verify the list: n8n will tell
        with self.assertRaises(HTTPError):
            m.check("glm-abl", "glm-abl")                                     # the judge rule needs no server
        self.assertEqual(m.operator("anything"), "anything")
        m2 = self.models()
        self.assertEqual(m2.operator(""), "glm-abl")
        with self.assertRaises(HTTPError):
            m2.operator("not-served")

    def test_free_prompt_to_a_chosen_model(self):
        feed = CR.Feed()
        list(CR.ModelChat(self.url, "glm-abl", feed).stream("hello there", 16, model="glm-abl-run7"))
        mine = [r for r in model_standin.SEEN if r["path"].startswith("/v1/chat") and r["user"] == "hello there"]
        self.assertEqual(mine[-1]["model"], "glm-abl-run7")              # SEEN is shared by every stand-in in this process
        self.assertEqual(feed.since(0)["events"][-1]["data"]["model"], "glm-abl-run7")


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
