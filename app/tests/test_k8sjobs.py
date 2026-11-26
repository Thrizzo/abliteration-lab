"""JobPipeline, Serving and ModelControl (app/k8sjobs.py) against a fake Kubernetes API server.

    python -m unittest discover -s app/tests        (from the repository root; standard library only)
"""
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import k8sjobs  # noqa: E402

NS = "lab"


class HTTPError(Exception):
    def __init__(self, status, msg):
        super().__init__(f"{status} {msg}")
        self.status, self.msg = status, msg


class FakeAPI:
    """Just enough of the Kubernetes API: Jobs, their pods and logs, one Deployment (with its scale subresource), one
    ConfigMap and network policies. fail[(method, path)] = (status, message) makes that call fail."""

    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []
        self.jobs, self.pods, self.logs = {}, {}, {}
        self.deployment = {"spec": {"replicas": 0, "selector": {"matchLabels": {"app": "glm-serve"}}}, "status": {}}
        self.policies = {}
        self.fail = {}
        self.configmap = {"data": {"MODEL_PATH": "/workspace/serving/current"}}
        self.pod_plan = {}            # job name -> list of phases the new pod goes through
        self.log_plan = {}            # pod -> list of "connections", each a list of (ts, text); then the pod ends
        self.exit_codes = {}
        self.block = threading.Event()   # set to release a blocking log stream (stop test)
        self.blocking = set()            # pods whose log stream blocks; a plan's "block": True puts its pod here
        srv = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *a):
                pass

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n)) if n else None

            def _send(self, code, obj):
                raw = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def handle_one(self, method):
                u = urllib.parse.urlsplit(self.path)
                q = dict(urllib.parse.parse_qsl(u.query))
                body = self._body() if method in ("POST", "PATCH", "DELETE") else None
                with srv.lock:
                    srv.requests.append({"method": method, "path": u.path, "query": q, "body": body,
                                         "auth": self.headers.get("Authorization"), "ctype": self.headers.get("Content-Type")})
                code, obj = srv.route(method, u.path, q, body, self)
                if code is not None:
                    self._send(code, obj)

            def do_GET(self):
                self.handle_one("GET")

            def do_POST(self):
                self.handle_one("POST")

            def do_PATCH(self):
                self.handle_one("PATCH")

            def do_DELETE(self):
                self.handle_one("DELETE")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.block.set()
        self.httpd.shutdown()

    def add_pod(self, job, phases, exit_code=0, logs=None):
        name = job + "-pod"
        self.pods[name] = {"metadata": {"name": name, "labels": {"job-name": job}}, "status": {"phase": phases[0]}, "_phases": list(phases)}
        self.exit_codes[name] = exit_code
        self.log_plan[name] = logs if logs is not None else [[]]
        return name

    def add_server_pod(self, name="glm-serve-7d4f-x1"):
        self.pods[name] = {"metadata": {"name": name, "labels": {"app": "glm-serve", "lab-role": "glm-serve"}},
                           "status": {"phase": "Running"}, "_phases": ["Running"]}

    def serve_running(self):
        """glm-serve up, reachable: its policy as kubectl apply leaves it, one replica, one pod."""
        self.policies["glm-serve-allow"] = {
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "glm-serve-allow", "namespace": NS, "uid": "u-1", "resourceVersion": "42",
                         "creationTimestamp": "2026-11-24T10:00:00Z", "generation": 1, "managedFields": [{"manager": "kubectl"}],
                         "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}"}},
            "spec": {"podSelector": {"matchLabels": {"lab-role": "glm-serve"}}, "policyTypes": ["Ingress"],
                     "ingress": [{"from": [{"podSelector": {"matchLabels": {"lab-role": "console"}}}], "ports": [{"port": 8000}]}]}}
        self.deployment["spec"]["replicas"] = 1
        self.deployment["status"]["readyReplicas"] = 1
        self.add_server_pod()

    def route(self, method, path, q, body, h):
        base_jobs = f"/apis/batch/v1/namespaces/{NS}/jobs"
        base_pods = f"/api/v1/namespaces/{NS}/pods"
        base_pol = f"/apis/networking.k8s.io/v1/namespaces/{NS}/networkpolicies"
        with self.lock:
            if (method, path) in self.fail:
                status, msg = self.fail[(method, path)]
                return status, {"message": msg}
            if path == f"/apis/apps/v1/namespaces/{NS}/deployments/glm-serve" and method == "GET":
                return 200, self.deployment
            if path == f"/apis/apps/v1/namespaces/{NS}/deployments/glm-serve/scale" and method == "PATCH":
                n = body["spec"]["replicas"]
                self.deployment["spec"]["replicas"] = n
                self.deployment["status"]["readyReplicas"] = n          # instant readiness is enough here
                if n and not any(k.startswith("glm-serve-") for k in self.pods):
                    self.add_server_pod()
                return 200, {"spec": {"replicas": n}}
            if path == base_pol and method == "POST":
                name = body["metadata"]["name"]
                if name in self.policies:
                    return 409, {"message": f"networkpolicies \"{name}\" already exists"}
                self.policies[name] = {**body, "metadata": {**body["metadata"], "uid": "u-2", "resourceVersion": "9"}}
                return 201, self.policies[name]
            if path.startswith(base_pol + "/"):
                name = path.rsplit("/", 1)[1]
                if name not in self.policies:
                    return 404, {"message": f"networkpolicies \"{name}\" not found"}
                if method == "DELETE":
                    del self.policies[name]
                    return 200, {}
                return 200, self.policies[name]
            if path == f"/api/v1/namespaces/{NS}/configmaps/glm-serve" and method == "PATCH":
                self.configmap["data"].update(body.get("data") or {})
                return 200, self.configmap
            if path == base_jobs and method == "POST":
                name = body["metadata"]["name"]
                self.jobs[name] = {**body, "status": {"active": 1}}
                plan = self.pod_plan.pop(name, None) or self.pod_plan.pop("*", None) or {"phases": ["Running"], "logs": [[]]}
                pod = self.add_pod(name, plan["phases"], plan.get("exit", 0), plan.get("logs"))
                if plan.get("block"):    # with the pod, before the console can ask for its log: set later, the stream
                    self.blocking.add(pod)   # could already be over and the Job ended (a test then sees no running Job)
                return 201, body
            if path == base_jobs and method == "GET":
                return 200, {"items": list(self.jobs.values())}
            if path.startswith(base_jobs + "/"):
                name = path.rsplit("/", 1)[1]
                if name not in self.jobs:
                    return 404, {"message": f"jobs.batch \"{name}\" not found"}
                if method == "DELETE":
                    del self.jobs[name]
                    return 200, {}
                return 200, self.jobs[name]
            if path == base_pods and method == "GET":
                sel = q.get("labelSelector", "")
                k, _, v = sel.partition("=")
                items = []
                for name, p in list(self.pods.items()):
                    if p["metadata"]["labels"].get(k) == v:
                        items.append(self._report(name))
                return 200, {"items": items}
            if path.startswith(base_pods + "/"):
                rest = path[len(base_pods) + 1:]
                name, _, sub = rest.partition("/")
                if name not in self.pods:
                    return 404, {"message": f"pods \"{name}\" not found"}
                p = self.pods[name]
                if method == "DELETE":
                    del self.pods[name]
                    self.block.set()
                    return 200, {}
                if sub == "log":
                    conns = self.log_plan.get(name) or [[]]
                    lines = conns.pop(0) if conns else []
                    last_conn = not conns
                    blocking = name in self.blocking
                else:
                    return 200, self._report(name)
        # log stream: outside the lock, may block
        h.send_response(200)
        h.send_header("Content-Type", "text/plain")
        h.end_headers()
        for ts, text in lines:
            h.wfile.write(f"{ts} {text}\n".encode() if ts else f"{text}\n".encode())
            h.wfile.flush()
        if blocking:
            self.block.wait(10)
        with self.lock:
            if last_conn and name in self.pods:
                self.pods[name]["_phases"] = ["Succeeded"]
                self.pods[name]["status"]["phase"] = "Succeeded"
                self._maybe_finish(name)
        return None, None

    def _report(self, name):
        """A pod read: the current phase is reported, then the pod moves on to the next planned phase."""
        p = self.pods[name]
        p["status"]["phase"] = p["_phases"][0]
        self._maybe_finish(name)
        out = json.loads(json.dumps({key: val for key, val in p.items() if not key.startswith("_")}))
        if len(p["_phases"]) > 1:
            p["_phases"].pop(0)
        return out

    def _maybe_finish(self, name):
        p = self.pods[name]
        if p["status"]["phase"] in ("Succeeded", "Failed"):
            p["status"]["containerStatuses"] = [{"name": "pipeline", "state": {"terminated": {"exitCode": self.exit_codes.get(name, 0)}}}]
        elif p["status"]["phase"] == "Pending":
            p["status"]["containerStatuses"] = [{"name": "pipeline", "state": {"waiting": {"reason": "ImagePullBackOff", "message": "pulling"}}}]
        else:
            p["status"].pop("containerStatuses", None)


SETTINGS = {
    "namespace": NS, "image": "ghcr.io/thrizzo/redteam-llm-lab:latest", "imagePullPolicy": "IfNotPresent",
    "imagePullSecrets": ["ghcr"], "workspaceClaim": "workspace", "ttlSecondsAfterFinished": 3600,
    "env": {"OLLAMA_HOST": "http://glm-serve.lab.svc:8000"},
    "classes": {"light": {"resources": {"requests": {"cpu": "500m"}}},
                "cpu": {"resources": {"requests": {"cpu": "4"}}},
                "gpu": {"resources": {"limits": {"nvidia.com/gpu": 8}}, "nodeSelector": {"redteam-llm-lab/gpu-node": "true"},
                        "tolerations": [{"key": "redteam-llm-lab/gpu-node", "operator": "Exists", "effect": "NoSchedule"}],
                        "activeDeadlineSeconds": 172800}},
    "serving": {"mode": "vllm", "deployment": "glm-serve", "configmap": "glm-serve", "servedName": "glm-abl", "exclusiveGpu": True},
}
PY = ["/opt/venv/bin/python", "-u", "-m", "abliterate"]


def wait_done(pl, timeout=10):
    t = time.time()
    while pl.running():
        if time.time() - t > timeout:
            raise AssertionError("pipeline did not finish: " + "\n".join(pl.lines))
        time.sleep(0.02)


class Base(unittest.TestCase):
    def setUp(self):
        self.api = FakeAPI()
        self.project = tempfile.mkdtemp()
        self.k8s = k8sjobs.K8s(base=self.api.url, token="test-token", namespace=NS)
        self.settings = json.loads(json.dumps(SETTINGS))
        self.pl = k8sjobs.JobPipeline(self.project, "/app", self.settings, self.k8s, http_error=HTTPError)
        self.pl.poll = 0.01

    def tearDown(self):
        self.api.close()
        shutil.rmtree(self.project, ignore_errors=True)

    def posted_job(self):
        return next(r["body"] for r in self.api.requests if r["method"] == "POST")


class TestJobs(Base):
    def test_new_run_job_manifest(self):
        self.pl.start(PY + ["--stage", "scan", "--model", "THUDM/glm-edge-1.5b-chat"], "abliterate", "scan")
        wait_done(self.pl)
        j = self.posted_job()
        pod = j["spec"]["template"]["spec"]
        c = pod["containers"][0]
        labels = j["metadata"]["labels"]
        run_dir = self.pl.run_dir
        self.assertRegex(j["metadata"]["name"], r"^abl-scan-\d{8}-\d{6}$")
        self.assertRegex(run_dir, r"^runs/abliterate_\d{8}_\d{6}$")
        self.assertEqual(c["command"][-4:], ["--run-dir", run_dir, "--out-dir", run_dir + "/model"])
        self.assertEqual(labels["lab-stage"], "scan")
        self.assertEqual(labels["lab-run"], run_dir.split("abliterate_")[1])
        self.assertNotIn("lab-egress-internet", labels)
        self.assertNotIn("lab-egress-model", labels)
        env = {e["name"]: e.get("value") for e in c["env"]}
        self.assertEqual(env["HF_HUB_OFFLINE"], "1")
        self.assertEqual(env["ABL_PROJECT"], self.project)
        self.assertEqual(env["OLLAMA_HOST"], "http://glm-serve.lab.svc:8000")
        self.assertNotIn("HF_TOKEN", env)
        self.assertEqual(c["resources"], {"limits": {"nvidia.com/gpu": 8}})
        self.assertEqual(pod["nodeSelector"], {"redteam-llm-lab/gpu-node": "true"})
        self.assertEqual(j["spec"]["activeDeadlineSeconds"], 172800)
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertTrue(pod["securityContext"]["runAsNonRoot"])
        self.assertEqual(c["securityContext"]["capabilities"], {"drop": ["ALL"]})
        self.assertEqual(pod["volumes"][0]["persistentVolumeClaim"]["claimName"], "workspace")
        self.assertEqual(c["volumeMounts"][0]["mountPath"], self.project)
        self.assertEqual(c["workingDir"], self.project)
        self.assertEqual(pod["imagePullSecrets"], [{"name": "ghcr"}])
        self.assertEqual(j["spec"]["backoffLimit"], 0)
        self.assertTrue(all(r["auth"] == "Bearer test-token" for r in self.api.requests))

    def test_download_gets_internet_and_token_only_from_the_secret(self):
        self.pl.start(PY + ["--model", "x/y", "--stage", "download"], "abliterate", "download", env_extra={"HF_TOKEN": "hf_SECRET"})
        wait_done(self.pl)
        j = self.posted_job()
        self.assertEqual(j["metadata"]["labels"]["lab-egress-internet"], "true")
        tok = next(e for e in j["spec"]["template"]["spec"]["containers"][0]["env"] if e["name"] == "HF_TOKEN")
        self.assertEqual(tok, {"name": "HF_TOKEN", "valueFrom": {"secretKeyRef": {"name": "hf", "key": "token", "optional": True}}})
        self.assertNotIn("hf_SECRET", json.dumps(j))
        self.assertTrue(any("Secret 'hf'" in line for line in self.pl.lines))
        self.assertEqual(j["spec"]["template"]["spec"]["containers"][0]["resources"], {"requests": {"cpu": "500m"}})

    def test_model_server_egress_only_when_deploying(self):
        self.pl.start(PY + ["--stage", "deploy", "--run-dir", "runs/abliterate_1_1"], "abliterate", "deploy", "runs/abliterate_1_1")
        wait_done(self.pl)
        self.assertEqual(self.posted_job()["metadata"]["labels"].get("lab-egress-model"), "true")
        self.api.requests.clear()
        self.pl.start(PY + ["--stage", "continue", "--run-dir", "runs/abliterate_1_1", "--no-ollama"], "abliterate", "continue", "runs/abliterate_1_1")
        wait_done(self.pl)
        j = self.posted_job()
        self.assertNotIn("lab-egress-model", j["metadata"]["labels"])
        self.assertNotIn("--out-dir", j["spec"]["template"]["spec"]["containers"][0]["command"])   # resumed run: from run.json

    def test_log_lines_events_and_exit_code(self):
        ev = json.dumps({"t": 1, "step": "scan", "status": "progress", "layer": 3})
        self.api.pod_plan["*"] = {"phases": ["Running"], "exit": 0, "logs": [[
            ("2026-11-24T10:00:00.1Z", "10:00:00 run runs/abliterate_20261124_100000: model m stage scan"),
            ("2026-11-24T10:00:00.25Z", "EVENT " + ev),
            ("2026-11-24T10:00:01Z", "done"),
        ]]}
        st = self.pl.start(PY + ["--stage", "scan", "--model", "m"], "abliterate", "scan")
        self.assertTrue(st["running"])
        wait_done(self.pl)
        st = self.pl.status()
        self.assertEqual(st["exit_code"], 0)
        self.assertFalse(st["running"])
        self.assertEqual(st["current"], "scan · progress")
        self.assertEqual(self.pl.events_from(0)["events"][0]["layer"], 3)
        lines = self.pl.log(0)["lines"]
        self.assertIn("done", lines)
        self.assertEqual(lines[-1], "[app] process exited with code 0")
        self.assertFalse(any(line.startswith("2026-") for line in lines))            # timestamps stripped
        self.assertTrue(os.path.isfile(st["log_path"]) and "done" in open(st["log_path"]).read())

    def test_jobs_report_to_the_live_feed(self):
        import copilot_runs
        self.pl.feed = copilot_runs.Feed()
        self.api.pod_plan["*"] = {"phases": ["Running"], "exit": 3, "logs": [[
            ("2026-11-24T10:00:00.1Z", "10:00:00 run runs/abliterate_20261124_100000: model m stage scan"),
            ("2026-11-24T10:00:00.2Z", "EVENT " + json.dumps({"t": 1, "step": "data", "status": "done"})),
            ("2026-11-24T10:00:00.3Z", "EVENT " + json.dumps({"t": 2, "step": "scan", "status": "progress"})),
            ("2026-11-24T10:00:00.4Z", "EVENT " + json.dumps({"t": 3, "step": "error", "status": "error", "message": "CUDA OOM"})),
        ]]}
        self.pl.start(PY + ["--stage", "scan", "--model", "m"], "abliterate", "scan")
        wait_done(self.pl)
        evs = self.pl.feed.since(0)["events"]
        self.assertEqual([e["message"].split(": ", 1)[-1] if e["message"].startswith("Job") else e["message"] for e in evs],
                         ["stage scan started", "data: done", "error: CUDA OOM", "stage scan exited with code 3"])
        self.assertEqual({e["source"] for e in evs}, {"pipeline"})
        self.assertEqual([e["level"] for e in evs], ["info", "info", "error", "error"])
        self.assertEqual(evs[-1]["run_id"], self.pl.run_id_of(self.pl.run_dir))       # the run the Job was created for

    def test_reconnect_skips_lines_already_seen(self):
        self.api.pod_plan["*"] = {"phases": ["Running"], "exit": 3, "logs": [
            [("2026-11-24T10:00:00.1Z", "one"), ("2026-11-24T10:00:00.5Z", "two")],                  # API closes early
            [("2026-11-24T10:00:00.1Z", "one"), ("2026-11-24T10:00:00.5Z", "two"), ("2026-11-24T10:00:01.05Z", "three")],
        ]}
        self.pl.start(PY + ["--stage", "scan", "--model", "m"], "abliterate", "scan")
        wait_done(self.pl)
        body = [x for x in self.pl.lines if not x.startswith("[app]")]
        self.assertEqual(body, ["one", "two", "three"])
        self.assertEqual(self.pl.exit_code, 3)
        logs = [r for r in self.api.requests if r["path"].endswith("/log")]
        self.assertEqual(len(logs), 2)
        self.assertNotIn("sinceTime", logs[0]["query"])
        self.assertEqual(logs[1]["query"]["sinceTime"], "2026-11-24T10:00:00Z")
        self.assertEqual(logs[0]["query"]["timestamps"], "true")

    def test_pending_pod_reason_shown_once(self):
        self.api.pod_plan["*"] = {"phases": ["Pending", "Pending", "Pending", "Running"], "logs": [[("2026-11-24T10:00:00Z", "ok")]]}
        self.pl.start(PY + ["--stage", "scan", "--model", "m"], "abliterate", "scan")
        wait_done(self.pl)
        waits = [x for x in self.pl.lines if "waiting for pod" in x]
        self.assertEqual(len(waits), 1)
        self.assertIn("ImagePullBackOff", waits[0])

    def test_stop_deletes_job_and_pod(self):
        self.api.pod_plan["*"] = {"phases": ["Running"], "logs": [[("2026-11-24T10:00:00Z", "working")]], "block": True}
        self.pl.start(PY + ["--stage", "scan", "--model", "m"], "abliterate", "scan")
        pod = self.pl.job + "-pod"
        time.sleep(0.2)
        self.pl.stop()
        wait_done(self.pl)
        dels = [r for r in self.api.requests if r["method"] == "DELETE"]
        self.assertEqual(dels[0]["path"], f"/apis/batch/v1/namespaces/{NS}/jobs/{self.pl.job}")
        self.assertEqual(dels[0]["body"], {"propagationPolicy": "Background", "gracePeriodSeconds": 0})
        self.assertTrue(any(r["path"].endswith(f"/pods/{pod}") and r["body"] == {"gracePeriodSeconds": 0} for r in dels))
        self.assertFalse(self.pl.running())

    def test_conflict_while_running_and_wrong_engine(self):
        self.api.pod_plan["*"] = {"phases": ["Running"], "logs": [[("2026-11-24T10:00:00Z", "x")]], "block": True}
        self.pl.start(PY + ["--stage", "scan", "--model", "m"], "abliterate", "scan")
        with self.assertRaises(HTTPError) as e:
            self.pl.start(PY, "abliterate", "scan")
        self.assertEqual(e.exception.status, 409)
        self.api.block.set()
        wait_done(self.pl)
        with self.assertRaises(HTTPError) as e:
            self.pl.start(PY, "notebook", "scan")
        self.assertEqual(e.exception.status, 400)

    def test_gpu_stage_refused_while_the_model_server_runs(self):
        self.api.deployment = {"spec": {"replicas": 1}, "status": {"replicas": 1}}
        with self.assertRaises(HTTPError) as e:
            self.pl.start(PY + ["--stage", "scan", "--model", "m"], "abliterate", "scan")
        self.assertEqual(e.exception.status, 409)
        self.assertIn("GPU node busy", e.exception.msg)
        self.pl.start(PY + ["--model", "m", "--stage", "download"], "abliterate", "download")   # not a GPU stage
        wait_done(self.pl)
        self.settings["serving"]["exclusiveGpu"] = False
        self.pl.start(PY + ["--stage", "scan", "--model", "m"], "abliterate", "scan")         # second GPU node
        wait_done(self.pl)

    def test_attach_after_console_restart(self):
        self.api.jobs["abl-scan-20261124-100000"] = {"metadata": {"name": "abl-scan-20261124-100000", "labels": {
            "app": "lab-job", "lab-stage": "scan", "lab-run": "20261124_100000"}}, "status": {"active": 1, "startTime": "2026-11-24T10:00:00Z"}}
        self.api.add_pod("abl-scan-20261124-100000", ["Running"], 0, [[("2026-11-24T10:00:02Z", "still measuring")]])
        self.assertEqual(self.pl.attach(), "abl-scan-20261124-100000")
        wait_done(self.pl)
        st = self.pl.status()
        self.assertEqual((st["stage"], st["run_id"], st["exit_code"]), ("scan", "20261124_100000", 0))
        self.assertIn("still measuring", self.pl.lines)
        self.assertIn("re-attached", self.pl.lines[0])


class TestServing(Base):
    def make_run(self, rid, with_model=True, gguf=False, layer=7):
        d = os.path.join(self.project, "runs", f"abliterate_{rid}")
        out = os.path.join(d, "model")
        os.makedirs(out)
        if with_model:
            open(os.path.join(out, "config.json"), "w").write("{}")
        meta = {"model_repo": "zai-org/GLM-5.3", "status": "done", "layer": layer, "out_dir": out, "model_dir": "/workspace/models/glm-5.3"}
        if gguf:
            g = os.path.join(self.project, "gguf", f"glm-5.3-abl-abliterate_{rid}-q8_0.gguf")
            os.makedirs(os.path.dirname(g), exist_ok=True)
            open(g, "wb").write(b"GGUF")
            meta["gguf"] = {"abl": g}
        json.dump(meta, open(os.path.join(d, "run.json"), "w"))
        return out

    def test_vllm_promote_rollback(self):
        a, b = self.make_run("20261101_000000"), self.make_run("20261102_000000", layer=9)
        self.make_run("20261103_000000", with_model=False)
        self.api.pods["glm-serve-abc"] = {"metadata": {"name": "glm-serve-abc", "labels": {"app": "glm-serve"}}, "status": {"phase": "Running"}, "_phases": ["Running"]}
        sv = k8sjobs.Serving(self.project, self.settings, self.k8s, http_error=HTTPError)
        self.assertEqual([c["run_id"] for c in sv.candidates()], ["20261102_000000", "20261101_000000"])
        st = sv.promote("20261101_000000")
        self.assertEqual(self.api.configmap["data"]["MODEL_PATH"], a)
        patch = next(r for r in self.api.requests if r["method"] == "PATCH")
        self.assertEqual(patch["path"], f"/api/v1/namespaces/{NS}/configmaps/glm-serve")
        self.assertEqual(patch["body"], {"data": {"MODEL_PATH": a}})
        self.assertEqual(patch["ctype"], "application/merge-patch+json")
        self.assertEqual(st["current"]["run_id"], "20261101_000000")
        self.assertEqual(st["current"]["restarted"], 1)
        self.assertTrue(any(r["method"] == "DELETE" and r["path"].endswith("/pods/glm-serve-abc") for r in self.api.requests))
        sv.promote("20261102_000000")
        st = sv.rollback()
        self.assertEqual(st["current"]["run_id"], "20261101_000000")
        self.assertEqual(st["current"]["action"], "rollback")
        patches = [r["body"]["data"]["MODEL_PATH"] for r in self.api.requests if r["method"] == "PATCH"]
        self.assertEqual(patches, [a, b, a])
        self.assertEqual([h["run_id"] for h in st["history"]], ["20261101_000000", "20261102_000000", "20261101_000000"])

    def test_errors(self):
        sv = k8sjobs.Serving(self.project, self.settings, self.k8s, http_error=HTTPError)
        with self.assertRaises(HTTPError) as e:
            sv.promote("nope")
        self.assertEqual(e.exception.status, 404)
        with self.assertRaises(HTTPError) as e:
            sv.rollback()
        self.assertEqual(e.exception.status, 409)

    def test_ollama_mode_publishes_the_runs_gguf(self):
        self.settings["serving"]["mode"] = "ollama"
        calls, release = [], threading.Event()
        self.make_run("20261101_000000")                     # no GGUF: not promotable
        self.make_run("20261102_000000", gguf=True)

        def publish(*a):
            release.wait(5)                                  # hold the upload until the test has seen "busy"
            calls.append(a)
        sv = k8sjobs.Serving(self.project, self.settings, self.k8s, http_error=HTTPError, publish=publish)
        c = {x["run_id"]: x for x in sv.candidates()}
        self.assertFalse(c["20261101_000000"]["promotable"])
        self.assertIn("deploy stage", c["20261101_000000"]["why"])
        with self.assertRaises(HTTPError) as e:
            sv.promote("20261101_000000")
        self.assertEqual(e.exception.status, 409)
        st = sv.promote("20261102_000000")
        self.assertIn("publishing", st["busy"])
        with self.assertRaises(HTTPError) as e:               # one publish at a time
            sv.promote("20261102_000000")
        self.assertEqual(e.exception.status, 409)
        release.set()
        sv.worker.join(5)
        self.assertEqual(calls, [("glm-abl", c["20261102_000000"]["gguf"], "/workspace/models/glm-5.3")])
        st = sv.status()
        self.assertEqual((st["busy"], st["current"]["served_name"]), (None, "glm-abl"))
        self.assertFalse(any(r["method"] == "PATCH" for r in self.api.requests))        # no ConfigMap in this mode

    def test_ollama_publish_failure_is_reported(self):
        self.settings["serving"]["mode"] = "ollama"
        self.make_run("20261102_000000", gguf=True)

        def boom(*a):
            raise RuntimeError("glm-serve unreachable")
        sv = k8sjobs.Serving(self.project, self.settings, self.k8s, http_error=HTTPError, publish=boom)
        sv.promote("20261102_000000")
        sv.worker.join(5)
        st = sv.status()
        self.assertIn("glm-serve unreachable", st["error"])
        self.assertIsNone(st["busy"])
        self.assertIsNone(st["current"])


class TestControl(Base):
    WHO = {"user": "admin", "ip": "10.42.0.7", "forwarded_for": "192.168.1.20"}

    def setUp(self):
        super().setUp()
        self.state = tempfile.mkdtemp()
        self.audit = k8sjobs.Audit(self.project)
        self.ctl = self.control()

    def tearDown(self):
        shutil.rmtree(self.state, ignore_errors=True)
        super().tearDown()

    def control(self):
        return k8sjobs.ModelControl(self.settings, self.k8s, self.state, self.audit, http_error=HTTPError)

    def calls(self):
        return [(r["method"], r["path"].rsplit("/", 2)[-2] + "/" + r["path"].rsplit("/", 1)[-1]) for r in self.api.requests
                if r["method"] != "GET"]

    def test_states(self):
        self.assertEqual(self.ctl.status()["state"], "killed")                   # no policy, 0 replicas, no pods
        self.api.serve_running()
        st = self.ctl.status()
        self.assertEqual((st["state"], st["replicas"], st["ready"], st["policy"]), ("running", 1, 1, True))
        self.assertEqual([p["name"] for p in st["pods"]], ["glm-serve-7d4f-x1"])
        self.api.deployment["status"]["readyReplicas"] = 0
        self.assertEqual(self.ctl.status()["state"], "starting")
        del self.api.policies["glm-serve-allow"]
        self.assertEqual(self.ctl.status()["state"], "isolated")
        self.api.deployment["spec"]["replicas"] = 0
        self.assertEqual(self.ctl.status()["state"], "stopping")               # pods still there
        self.api.pods.clear()
        self.assertEqual(self.ctl.status()["state"], "killed")
        self.api.serve_running()
        self.api.deployment["spec"]["replicas"] = 0
        self.api.pods.clear()
        self.assertEqual(self.ctl.status()["state"], "stopped")                  # the GPU overlays' default: policy, 0 replicas

    def test_kill_cuts_first_then_scales_then_deletes_with_grace_0(self):
        self.api.serve_running()
        out = self.ctl.act("kill", self.WHO, "loops on every prompt")
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["status"]["state"], "killed")
        self.assertEqual(self.calls(), [("DELETE", "networkpolicies/glm-serve-allow"), ("PATCH", "glm-serve/scale"),
                                        ("DELETE", "pods/glm-serve-7d4f-x1")])
        delete_pod = next(r for r in self.api.requests if r["method"] == "DELETE" and "/pods/" in r["path"])
        self.assertEqual(delete_pod["body"], {"gracePeriodSeconds": 0})
        pods_query = next(r for r in self.api.requests if r["path"].endswith("/pods") and r["method"] == "GET")
        self.assertEqual(pods_query["query"]["labelSelector"], "app=glm-serve")    # the Deployment's own selector
        self.assertEqual([s["step"] for s in out["steps"]][-1], "check: no pods left")
        rec = self.audit.recent(1)[0]
        self.assertEqual((rec["source"], rec["stage"], rec["level"], rec["who"]["user"]), ("control", "kill", "info", "admin"))
        self.assertEqual(rec["data"]["reason"], "loops on every prompt")
        self.assertEqual(rec["data"]["state"], "killed")

    def test_kill_keeps_going_when_a_step_fails(self):
        self.api.serve_running()
        self.api.fail[("DELETE", f"/apis/networking.k8s.io/v1/namespaces/{NS}/networkpolicies/glm-serve-allow")] = (500, "etcd timeout")
        out = self.ctl.act("kill", self.WHO)
        self.assertFalse(out["ok"])
        self.assertEqual([s["ok"] for s in out["steps"]], [False, True, True, True])
        self.assertIn("etcd timeout", out["steps"][0]["error"])
        self.assertEqual(self.api.deployment["spec"]["replicas"], 0)                # still scaled down
        self.assertFalse(any(k.startswith("glm-serve-") for k in self.api.pods))     # and the pod is gone
        self.assertEqual(self.audit.recent(1)[0]["level"], "error")

    def test_isolate_and_release_recreate_the_same_policy(self):
        self.api.serve_running()
        original = json.loads(json.dumps(self.api.policies["glm-serve-allow"]))
        self.assertTrue(self.ctl.act("isolate", self.WHO)["ok"])
        self.assertNotIn("glm-serve-allow", self.api.policies)
        self.assertEqual(self.ctl.status()["state"], "isolated")
        self.assertEqual(self.api.deployment["spec"]["replicas"], 1)                 # the model keeps running
        self.assertTrue(self.ctl.act("release", self.WHO)["ok"])
        posted = next(r["body"] for r in self.api.requests if r["method"] == "POST")
        self.assertEqual(posted["spec"], original["spec"])
        self.assertEqual(posted["metadata"]["annotations"], original["metadata"]["annotations"])
        for k in ("uid", "resourceVersion", "creationTimestamp", "generation", "managedFields"):
            self.assertNotIn(k, posted["metadata"])
        self.assertEqual(self.ctl.status()["state"], "running")
        self.assertEqual([r["stage"] for r in self.audit.recent(5)], ["release", "isolate"])

    def test_copy_survives_a_console_restart_and_lives_outside_the_workspace(self):
        self.api.serve_running()
        self.ctl.act("isolate", self.WHO)
        self.assertTrue(os.path.isfile(os.path.join(self.state, "glm-serve-allow.json")))
        for r, _, files in os.walk(self.project):
            self.assertNotIn("glm-serve-allow.json", files)                       # never on the shared workspace
        self.assertTrue(self.control().act("release", self.WHO)["ok"])          # a new console process

    def test_release_without_a_copy_is_refused_and_audited(self):
        with self.assertRaises(HTTPError) as e:
            self.ctl.act("release", self.WHO)
        self.assertEqual(e.exception.status, 409)
        self.assertIn("re-apply the overlay", e.exception.msg)
        rec = self.audit.recent(1)[0]
        self.assertEqual((rec["stage"], rec["level"]), ("release", "error"))
        self.assertIn("refused", rec["message"])

    def test_a_tampered_copy_is_not_used(self):
        with open(os.path.join(self.state, "glm-serve-allow.json"), "w") as f:
            json.dump({"kind": "NetworkPolicy", "metadata": {"name": "glm-serve-allow"},
                       "spec": {"podSelector": {}, "ingress": [{}]}}, f)          # would open every pod in the namespace
        with self.assertRaises(HTTPError):
            self.control().act("release", self.WHO)
        self.assertNotIn("glm-serve-allow", self.api.policies)

    def test_snapshot_at_start_makes_release_work_after_a_manual_delete(self):
        self.api.serve_running()
        self.assertTrue(self.ctl.snapshot())
        del self.api.policies["glm-serve-allow"]                                  # kubectl delete, outside the console
        self.assertTrue(self.ctl.act("release", self.WHO)["ok"])
        self.assertIn("glm-serve-allow", self.api.policies)

    def test_start_after_kill(self):
        self.api.serve_running()
        self.ctl.act("kill", self.WHO)
        out = self.ctl.act("start", self.WHO)
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["status"]["state"], "running")
        self.assertIn("glm-serve-allow", self.api.policies)
        self.assertEqual(self.api.deployment["spec"]["replicas"], 1)

    def test_start_refused_while_a_gpu_job_runs(self):
        self.api.jobs["abl-scan-1"] = {"metadata": {"name": "abl-scan-1", "labels": {"app": "lab-job", "lab-stage": "scan"}},
                                       "status": {"active": 1}}
        with self.assertRaises(HTTPError) as e:
            self.ctl.act("start", self.WHO)
        self.assertEqual(e.exception.status, 409)
        self.assertIn("GPU node busy", e.exception.msg)
        self.assertEqual(self.api.deployment["spec"]["replicas"], 0)
        self.settings["serving"]["exclusiveGpu"] = False                             # a second GPU node
        self.api.serve_running()
        self.assertTrue(self.control().act("start", self.WHO)["ok"])

    def test_unknown_action(self):
        with self.assertRaises(HTTPError) as e:
            self.ctl.act("explode", self.WHO)
        self.assertEqual(e.exception.status, 404)


class TestAudit(unittest.TestCase):
    def test_daily_files_newest_first_and_stdout_copy(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        a = k8sjobs.Audit(d)
        os.makedirs(a.dir)
        with open(os.path.join(a.dir, "2026-11-23.jsonl"), "w") as f:
            f.write(json.dumps({"stage": "old"}) + "\nnot json\n")
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rec = a.write("control", "kill", "kill: done in 412 ms", who={"user": "admin"}, data={"ok": True})
        self.assertTrue(buf.getvalue().startswith("AUDIT {"))
        self.assertRegex(rec["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
        self.assertEqual(set(rec), {"ts", "source", "run_id", "stage", "level", "message", "data", "who"})
        self.assertEqual([r["stage"] for r in a.recent(10)], ["kill", "old"])


class TestHelpers(unittest.TestCase):
    def test_ts_key_orders_trimmed_nanoseconds(self):
        self.assertLess(k8sjobs.ts_key("2026-11-24T10:00:00.1Z"), k8sjobs.ts_key("2026-11-24T10:00:00.12Z"))
        self.assertLess(k8sjobs.ts_key("2026-11-24T10:00:00Z"), k8sjobs.ts_key("2026-11-24T10:00:00.000000001Z"))
        self.assertEqual(k8sjobs.ts_key("nonsense"), ("", ""))

    def test_settings_merge(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "jobs.json")
        json.dump({"image": "x:1", "serving": {"mode": "ollama"}}, open(p, "w"))
        s = k8sjobs.load_settings(p)
        self.assertEqual((s["image"], s["serving"]["mode"], s["serving"]["servedName"]), ("x:1", "ollama", "glm-abl"))
        shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
