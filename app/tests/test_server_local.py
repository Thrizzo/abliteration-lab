"""The console outside Kubernetes (the Docker stack, a plain install), in a process of its own: the other HTTP tests import
the server once per process, in Kubernetes mode. Findings of the Docker audit:
- the audit log: what the console records (here a free prompt) goes to workspace/audit/*.jsonl and to the log, as in
  Kubernetes, and outlives a restart; the live feed still gets it;
- one machine for the pipeline and Ollama: while a stage that loads the model runs, or the lab holds one on the GPU,
  copilot runs, free prompts, Compare and knowledge uploads wait (409, with the reason); a download or the notebook
  engine's setup holds none of them back; and the other way round, such a stage does not start while a copilot run, an
  upload being embedded or an open model stream still uses Ollama;
- the copilot's secrets: a file the console may not read is reported as such, not as missing;
- the operator list of an Ollama that holds every model of the stack: embedding models left out (and named), the
  abliterated runs first, and messages that name the model server, not glm-serve.

    python -m unittest discover -s app/tests
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, "..")
sys.path.insert(0, APP)
sys.path.insert(0, HERE)

import copilot_runs as CR  # noqa: E402

try:
    import fastapi  # noqa: F401
    HAVE_FASTAPI = True
except ImportError:
    HAVE_FASTAPI = False

LOCAL = r"""
import json, os, sys, threading
from http.server import ThreadingHTTPServer
sys.path.insert(0, __APP__); sys.path.insert(0, __TESTS__)
import model_standin
srv = ThreadingHTTPServer(("127.0.0.1", 0), model_standin.H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{srv.server_address[1]}"
os.environ.pop("ABL_RUNNER", None)
os.environ.update(ABL_PROJECT=__PROJECT__, GLM_SERVE_URL=url, GLM_SERVE_MODEL="glm-abl", RAG_OLLAMA_URL=url, OLLAMA_HOST=url)
import server
from test_server_control import call
out = {"runner": "k8s" if server.K8S else "local", "audit": type(server.audit).__name__,
       "audit_dir": server.audit.dir, "feed": server.audit.feed is server.FEED}

# a free prompt: streamed, audited into the workspace
status, body = call(server.app, "POST", "/api/model/chat", {"x-lab-user": "admin"}, {"prompt": "hello there", "max_tokens": 8})
out["chat"] = status
files = sorted(os.listdir(os.path.join(__PROJECT__, "audit"))) if os.path.isdir(os.path.join(__PROJECT__, "audit")) else []
recs = [json.loads(l) for f in files for l in open(os.path.join(__PROJECT__, "audit", f), encoding="utf-8")]
out["records"] = [(r["source"], r["data"].get("prompt"), (r.get("who") or {}).get("user")) for r in recs]
out["in_feed"] = [e["source"] for e in server.FEED.since(0)["events"]] if hasattr(server.FEED, "since") else None

# a measure stage running: everything that loads a model in Ollama waits; a download holds nothing back
class Running:
    def poll(self):
        return None
server.pipeline.proc, server.pipeline.stage = Running(), "measure"
held = {}
for path, body in (("/api/copilot/run", {"task": "enumerate", "target": "10.10.10.5"}),
                   ("/api/model/chat", {"prompt": "hi", "max_tokens": 8}),
                   ("/api/ollama/chat", {"model": "glm-abl", "prompt": "hi"}),
                   ("/api/knowledge/upload?source=htb&name=x.md", b"# x")):
    st, b = call(server.app, "POST", path, {}, body)
    held[path.split("?")[0]] = (st, b.get("detail", "") if isinstance(b, dict) else str(b))
out["measure"] = held
server.pipeline.stage = "download"
st, b = call(server.app, "POST", "/api/model/chat", {}, {"prompt": "hi", "max_tokens": 8})
out["download"] = st
server.pipeline.stage = "setup"                       # the notebook engine's setup loads no model
out["setup"] = call(server.app, "POST", "/api/model/chat", {}, {"prompt": "hi", "max_tokens": 8})[0]
server.pipeline.proc = None

# the lab holds a model on the GPU (step 2): Ollama would load beside it
class Lab:
    device = "cuda:0"
server.lab.hm = Lab()
st, b = call(server.app, "POST", "/api/ollama/chat", {}, {"model": "glm-abl", "prompt": "hi"})
out["lab"] = (st, b.get("detail", "") if isinstance(b, dict) else str(b))
Lab.device = "cpu"
out["lab_cpu"] = call(server.app, "POST", "/api/model/chat", {}, {"prompt": "hi", "max_tokens": 8})[0]
server.lab.hm = None

# the other way round: a GPU stage does not start while Ollama still works for the console
from fastapi import HTTPException
def start(stage):
    try:
        server.pipeline.start([sys.executable, "-c", "pass"], "abliterate", stage)
        server.pipeline.proc.wait()
        return "started"
    except HTTPException as e:
        return f"{e.status_code}: {e.detail}"
with server.copilot.lock:
    server.copilot.runs["r1"] = {"id": "r1", "status": "running"}
out["start_copilot"] = start("measure")
out["start_download"] = start("download")             # a download loads nothing: it may start
with server.copilot.lock:
    server.copilot.runs["r1"]["status"] = "waiting"   # parked at Human approval: past the judge
server._STREAMS["n"] = 1                              # a free prompt or Compare still streaming
out["start_stream"] = start("scan")
server._STREAMS["n"] = 0
with server.knowledge.lock:
    server.knowledge.jobs["htb/x.md"] = {"status": "ingesting"}
out["start_ingest"] = start("measure")
with server.knowledge.lock:
    server.knowledge.jobs.clear()
out["start_free"] = start("measure")
print("RESULT " + json.dumps(out))
"""


@unittest.skipUnless(HAVE_FASTAPI, "the console's dependencies are not installed here")
class LocalConsole(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project = tempfile.mkdtemp()
        script = (LOCAL.replace("__APP__", json.dumps(APP)).replace("__TESTS__", json.dumps(HERE))
                  .replace("__PROJECT__", json.dumps(cls.project)))
        env = {k: v for k, v in os.environ.items() if k not in ("ABL_RUNNER", "N8N_URL", "QDRANT_URL", "COPILOT_SECRETS_DIR")}
        p = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=120, env=env, cwd=HERE)
        line = next((ln for ln in p.stdout.splitlines() if ln.startswith("RESULT ")), None)
        if line is None:
            raise AssertionError(p.stdout[-2000:] + p.stderr[-4000:])
        cls.got = json.loads(line[7:])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.project, ignore_errors=True)

    def test_the_audit_log_is_kept_outside_kubernetes(self):
        g = self.got
        self.assertEqual((g["runner"], g["audit"], g["feed"]), ("local", "Audit", True))
        self.assertEqual(g["audit_dir"], os.path.join(self.project, "audit"))
        self.assertEqual(g["chat"], 200)
        self.assertIn(["model", "hello there", "admin"], g["records"])        # the prompt, and who asked (Caddy's header)

    def test_a_running_stage_holds_back_what_loads_ollama(self):
        for path, (status, detail) in self.got["measure"].items():
            self.assertEqual(status, 409, path)
            self.assertIn("measure stage is running", detail, path)
        self.assertIn("Compare", self.got["measure"]["/api/ollama/chat"][1])
        self.assertEqual(self.got["download"], 200)                           # a download leaves the GPU alone
        self.assertEqual(self.got["setup"], 200)                              # so does the notebook engine's setup

    def test_a_lab_model_on_the_gpu_holds_back_ollama_too(self):
        status, detail = self.got["lab"]
        self.assertEqual(status, 409)
        self.assertIn("the lab (step 2) holds a model on the GPU", detail)
        self.assertEqual(self.got["lab_cpu"], 200)                            # a lab model in the RAM does not

    def test_a_gpu_stage_waits_for_what_still_uses_ollama(self):
        g = self.got
        self.assertIn("409: Ollama is still busy with 1 copilot run", g["start_copilot"])
        self.assertEqual(g["start_download"], "started")
        self.assertIn("1 open model stream (a free prompt or Compare)", g["start_stream"])
        self.assertNotIn("copilot run", g["start_stream"])                    # a run waiting for approval is past its models
        self.assertIn("1 knowledge upload being embedded", g["start_ingest"])
        self.assertEqual(g["start_free"], "started")


class Secrets(unittest.TestCase):
    def test_an_unreadable_file_is_not_called_missing(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for name in ("webhook-secret", "n8n-api-key"):
            with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                f.write("s3cret")
        runs = CR.CopilotRuns("http://n8n:5678", d, CR.Feed())
        self.assertEqual(runs.missing(), [])
        real_open = open

        def no_read(path, *a, **kw):                     # what a 0600 file of another user gives (root reads it here)
            if os.path.basename(str(path)) == "n8n-api-key":
                raise PermissionError(13, "Permission denied", path)
            return real_open(path, *a, **kw)
        with mock.patch("builtins.open", no_read):
            missing = runs.missing()
        self.assertEqual(len(missing), 1)
        self.assertIn("n8n-api-key (in " + d, missing[0])
        self.assertIn("may not read it: chown it to that uid", missing[0])
        os.remove(os.path.join(d, "webhook-secret"))
        self.assertEqual(runs.missing(), ["webhook-secret"])                   # really missing: the name, as before


class OllamaOperators(unittest.TestCase):
    """The Docker stack's operator server is its Ollama: /v1/models lists everything, /api/tags says what is an embedding."""
    V1 = {"data": [{"id": i} for i in ("qwen3:8b", "nomic-embed-text:latest", "glm-edge-4b-chat-abl:latest", "deepseek-r1:8b",
                                       "mxbai-embed-large:latest", "glm-edge-4b-chat-base:latest")]}
    TAGS = {"models": [{"name": "qwen3:8b", "details": {"family": "qwen3"}},
                       {"name": "nomic-embed-text:latest", "details": {"family": "nomic-bert"}},
                       {"name": "glm-edge-4b-chat-abl:latest", "details": {"family": "glm"}},
                       {"name": "deepseek-r1:8b", "details": {"family": "qwen3"}},
                       {"name": "mxbai-embed-large:latest", "details": {"family": "bert"}},
                       {"name": "glm-edge-4b-chat-base:latest", "details": {"family": "glm"}}]}

    def models(self, tags=True, ollama=True):
        m = CR.CopilotModels("http://op", "http://judge", operator_default="glm-edge-1.5b-chat-abl:latest", operator_tags=tags,
                             operator_server="the model server (GLM_SERVE_URL)",
                             http_error=lambda status, msg: ValueError(f"{status}: {msg}"))

        def get(url):
            if url == "http://op/v1/models":
                return self.V1
            if url in ("http://judge/api/tags",) or (ollama and url == "http://op/api/tags"):
                return self.TAGS
            raise OSError("HTTP Error 404: Not Found")                    # vLLM has no /api/tags
        m._get = get
        return m

    def test_embeddings_left_out_and_runs_first(self):
        op = self.models().list()["operator"]
        self.assertEqual(op["models"], ["glm-edge-4b-chat-abl:latest", "deepseek-r1:8b", "glm-edge-4b-chat-base:latest", "qwen3:8b"])
        self.assertEqual([x["name"] for x in op["excluded"]], ["mxbai-embed-large:latest", "nomic-embed-text:latest"])
        with self.assertRaises(ValueError) as e:
            self.models().check("nomic-embed-text:latest", None)
        self.assertIn("the model server (GLM_SERVE_URL) has no model 'nomic-embed-text:latest'", str(e.exception))

    def test_a_server_without_tags_keeps_everything(self):
        op = self.models(ollama=False).list()["operator"]
        self.assertEqual(len(op["models"]), 6)
        self.assertEqual(op["excluded"], [])

    def test_kubernetes_asks_glm_serve_only_for_its_models(self):
        m = self.models(tags=False)
        op = m.list()["operator"]
        self.assertEqual(op["models"], sorted(i["id"] for i in self.V1["data"]))     # as before: sorted, nothing dropped
        self.assertEqual(op["excluded"], [])


if __name__ == "__main__":
    unittest.main()
