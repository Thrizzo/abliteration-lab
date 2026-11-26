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
import time
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


def keep_server_state(server, add_cleanup):
    """The HTTP test classes share one server module (imported once per process). Whatever a test points at its own
    fakes is put back afterwards, so no later test talks to them: a stopped fake still accepts connections and never
    answers, which cost the next model list two 5 s timeouts."""
    saved = [(obj, attr, getattr(obj, attr)) for obj, attrs in (
        (server, ("engagements",)),
        (server.copilot, ("base", "secrets_dir")),
        (server.copilot_models, ("operator_url", "judge_url", "_cache")),
        (server.model_chat, ("base",)),
        (server.knowledge, ("qdrant_url", "ollama_url")),
        (server.control, ("k8s", "copy")),
        (server.pipeline, ("k8s",)),
        (server.serving, ("k8s",)),
    ) for attr in attrs]

    def restore():
        for obj, attr, value in saved:
            setattr(obj, attr, value)
    add_cleanup(restore)


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
        keep_server_state(s, self.addCleanup)
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
        keep_server_state(cls.server, cls.addClassCleanup)
        import model_standin
        from http.server import ThreadingHTTPServer
        import threading
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), model_standin.H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

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

@unittest.skipUnless(HAVE_FASTAPI, "the console's dependencies are not installed here")
class TestKnowledgeHTTP(unittest.TestCase):
    """Uploads as the browser sends them: the file as the raw body, source and name in the query."""

    @classmethod
    def setUpClass(cls):
        TestControlHTTP.setUpClass()
        cls.server = TestControlHTTP.server
        keep_server_state(cls.server, cls.addClassCleanup)
        import model_standin
        import test_knowledge
        from http.server import ThreadingHTTPServer
        import threading
        cls.emb = ThreadingHTTPServer(("127.0.0.1", 0), model_standin.H)
        threading.Thread(target=cls.emb.serve_forever, daemon=True).start()
        cls.qdrant = test_knowledge.FakeQdrant()
        k = cls.server.knowledge
        k.qdrant_url, k.ollama_url = cls.qdrant.url, f"http://127.0.0.1:{cls.emb.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.emb.shutdown()
        cls.emb.server_close()
        cls.qdrant.close()

    def test_preview_upload_list_delete(self):
        app = self.server.app
        notes = b"# Notes\n\nadmin is jane.doe@client-corp.com\n"
        st, p = call(app, "POST", "/api/knowledge/preview?source=engagement&name=notes.md", {}, notes)
        self.assertEqual(st, 200, p)
        self.assertNotIn("jane.doe", p["scrubbed"])
        st, up = call(app, "POST", "/api/knowledge/upload?source=htb&name=Lame.md", {"x-lab-user": "admin"},
                      b"# Lame\n\nsmbclient -N -L //target\n")
        self.assertEqual((st, up["doc"]), (200, "htb/Lame.md"))
        for _ in range(200):
            d = [x for x in call(app, "GET", "/api/knowledge")[1]["docs"] if x["doc"] == "htb/Lame.md"]
            if d and d[0]["status"] == "indexed":
                break
            time.sleep(0.02)
        self.assertEqual(d[0]["chunks"], 1)
        st, out = call(app, "POST", "/api/knowledge/delete", {}, {"doc": "htb/Lame.md"})
        self.assertEqual((st, out["deleted"]), (200, True))
        self.assertEqual(self.qdrant.docs(), {})

    def test_refusals(self):
        app = self.server.app
        big = str(64 * 1024 * 1024)
        self.assertEqual(call(app, "POST", "/api/knowledge/upload?source=htb&name=x.md", {"content-length": big}, b"x")[0], 413)
        self.assertEqual(call(app, "POST", "/api/knowledge/upload", {}, b"x")[0], 422)                  # no source / name
        self.assertEqual(call(app, "POST", "/api/knowledge/upload?source=htb&name=x.md", {"origin": "https://evil.example"}, b"x")[0], 403)
        self.assertEqual(call(app, "POST", "/api/knowledge/delete", {}, {"doc": "../app/server.py"})[0], 400)

if __name__ == "__main__":
    unittest.main()
