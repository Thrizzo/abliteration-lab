"""The console's HTTP layer for Kill / Isolate (app/server.py in Kubernetes mode) against the fake Kubernetes API:
cross-site requests are refused, the JSON body is required, who asked reaches the audit log.

Calls the ASGI app directly (no httpx needed). Skipped where the app's own dependencies (FastAPI) are missing; the
image has them, and CI runs these tests inside it.

    python -m unittest discover -s app/tests
"""
import asyncio
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

try:
    import fastapi  # noqa: F401
    HAVE_FASTAPI = True
except ImportError:
    HAVE_FASTAPI = False


def call(app, method, path, headers=None, body=None):
    """One HTTP request straight into the ASGI app: (status, decoded JSON or text)."""
    raw = json.dumps(body).encode() if isinstance(body, (dict, list)) else (body or b"")
    hdrs = {"host": "lab.example.internal", **({"content-type": "application/json"} if isinstance(body, (dict, list)) else {}),
            **{k.lower(): v for k, v in (headers or {}).items()}}
    msgs, state = [], {"sent": False}

    async def receive():
        # like a real server: the body once, then nothing until the client goes away (which it never does here)
        if not state["sent"]:
            state["sent"] = True
            return {"type": "http.request", "body": raw, "more_body": False}
        await asyncio.Event().wait()

    async def send(m):
        msgs.append(m)

    path, _, query = path.partition("?")
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "scheme": "http",
             "path": path, "raw_path": path.encode(), "query_string": query.encode(), "root_path": "",
             "headers": [(k.encode(), v.encode()) for k, v in hdrs.items()], "client": ("127.0.0.1", 50000),
             "server": ("127.0.0.1", 8787)}
    asyncio.run(app(scope, receive, send))
    status = next(m["status"] for m in msgs if m["type"] == "http.response.start")
    text = b"".join(m.get("body", b"") for m in msgs if m["type"] == "http.response.body").decode()
    try:
        return status, json.loads(text)
    except ValueError:
        return status, text


@unittest.skipUnless(HAVE_FASTAPI, "the console's dependencies are not installed here")
class TestControlHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project, cls.state = tempfile.mkdtemp(), tempfile.mkdtemp()
        settings = os.path.join(cls.project, "jobs.json")
        with open(settings, "w") as f:
            json.dump({"namespace": "lab", "image": "img:ci", "serving": {"mode": "ollama"}}, f)
        os.environ.update(ABL_RUNNER="k8s", LAB_JOBS_SETTINGS=settings, ABL_PROJECT=cls.project, LAB_STATE_DIR=cls.state)
        import k8sjobs
        import server
        import test_k8sjobs as T
        cls.server, cls.T, cls.k8sjobs = server, T, k8sjobs

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.project, ignore_errors=True)
        shutil.rmtree(cls.state, ignore_errors=True)

    def setUp(self):
        self.api = self.T.FakeAPI()
        self.addCleanup(self.api.close)
        fake = self.k8sjobs.K8s(base=self.api.url, token="t", namespace="lab")
        s = self.server
        s.pipeline.k8s = s.serving.k8s = s.control.k8s = fake
        s.control.copy = None
        self.api.serve_running()
        self.app = s.app

    def changes(self):
        return [r for r in self.api.requests if r["method"] != "GET"]

    def test_cross_site_requests_are_refused(self):
        for hdrs in ({"origin": "https://evil.example"}, {"sec-fetch-site": "cross-site"}, {"sec-fetch-site": "same-site"},
                     {"origin": "null"}):
            status, body = call(self.app, "POST", "/api/control/kill", hdrs, {})
            self.assertEqual(status, 403, hdrs)
            self.assertEqual(body["detail"], "cross-site request refused")
        status, _ = call(self.app, "POST", "/api/serving/rollback", {"origin": "https://evil.example"}, {})
        self.assertEqual(status, 403)
        self.assertEqual(self.changes(), [])                                      # nothing reached Kubernetes
        self.assertEqual(call(self.app, "GET", "/api/control", {"origin": "https://evil.example"})[0], 200)   # reads pass

    def test_same_origin_browser_request_works_and_records_who(self):
        status, body = call(self.app, "POST", "/api/control/isolate",
                            {"origin": "https://lab.example.internal", "sec-fetch-site": "same-origin",
                             "x-lab-user": "admin", "x-lab-peer": "10.42.0.7", "x-lab-forwarded-for": "192.168.1.20"},
                            {"reason": "suspicious output"})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["status"]["state"], "isolated")
        status, st = call(self.app, "GET", "/api/control")
        rec = st["audit"][0]
        self.assertEqual((rec["stage"], rec["who"]["user"], rec["who"]["ip"], rec["who"]["forwarded_for"]),
                         ("isolate", "admin", "10.42.0.7", "192.168.1.20"))
        self.assertEqual(rec["data"]["reason"], "suspicious output")
        self.assertEqual(call(self.app, "POST", "/api/control/release", {}, {})[1]["status"]["state"], "running")

    def test_body_is_required(self):
        for raw, ctype in ((b"", None), (b"", "application/x-www-form-urlencoded"), (b"{}", "text/plain")):
            status, _ = call(self.app, "POST", "/api/control/kill", {"content-type": ctype} if ctype else {}, raw)
            self.assertEqual(status, 422, (raw, ctype))
        self.assertEqual(self.changes(), [])

    def test_kill_through_http(self):
        status, body = call(self.app, "POST", "/api/control/kill", {}, {})
        self.assertEqual(status, 200)
        self.assertEqual(body["status"]["state"], "killed")
        self.assertEqual(call(self.app, "POST", "/api/control/explode", {}, {})[0], 404)

    def test_refused_promote_is_audited(self):
        status, _ = call(self.app, "POST", "/api/serving/promote", {"x-lab-user": "admin"}, {"run_id": "20990101_000000"})
        self.assertEqual(status, 404)
        rec = call(self.app, "GET", "/api/control")[1]["audit"][0]
        self.assertEqual((rec["source"], rec["stage"], rec["level"], rec["who"]["user"]), ("serving", "promote", "error", "admin"))


@unittest.skipUnless(HAVE_FASTAPI, "the console's dependencies are not installed here")
class TestCopilotHTTP(unittest.TestCase):
    """The feed, the copilot's status and a streamed free prompt through the real app (model: the stand-in)."""

    @classmethod
    def setUpClass(cls):
        TestControlHTTP.setUpClass()                                 # the same server module, in Kubernetes mode
        cls.server = TestControlHTTP.server
        import model_standin
        from http.server import ThreadingHTTPServer
        import threading
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), model_standin.H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_feed_copilot_status_and_free_prompt(self):
        s = self.server
        s.model_chat.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        st, body = call(s.app, "GET", "/api/copilot")
        self.assertEqual(st, 200)
        self.assertFalse(body["configured"])                         # no Secret mounted in this test
        self.assertIn("n8n-api-key", body["missing"])
        st, body = call(s.app, "POST", "/api/copilot/run", {}, {"task": "t", "target": "10.10.10.5"})
        self.assertEqual(st, 409)
        self.assertIn("connect_console.py", body["detail"])
        before = call(s.app, "GET", "/api/feed")[1]["latest"]
        st, text = call(s.app, "POST", "/api/model/chat", {"x-lab-user": "admin"}, {"prompt": "hello there", "max_tokens": 16})
        self.assertEqual(st, 200)
        lines = [json.loads(line) for line in text.strip().split("\n")]
        self.assertEqual("".join(x.get("token", "") for x in lines), "stand-in answer to: hello there")
        self.assertTrue(lines[-1]["done"])
        feed = call(s.app, "GET", f"/api/feed?after={before}")[1]["events"]
        self.assertEqual([(e["source"], e["stage"]) for e in feed], [("model", "prompt")])
        self.assertEqual(feed[0]["data"]["who"]["user"], "admin")
        self.assertEqual(call(s.app, "POST", "/api/model/chat", {}, {"prompt": ""})[0], 422)

if __name__ == "__main__":
    unittest.main()
