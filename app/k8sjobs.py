"""Kubernetes runner for the lab console (ABL_RUNNER=k8s).

Every pipeline stage runs as a Job in the console's namespace instead of a child process. JobPipeline has the same
interface as server.Pipeline (start / stop / status / log / events_from / running), so the GUI does not change: the
Job's pod log is streamed into the same lines and EVENT records a child process would have produced. Jobs keep running
when the console restarts; on start the console re-attaches to a running one.

Serving promotes a finished run to glm-serve and rolls back to the previous one:
  vllm    ConfigMap glm-serve MODEL_PATH -> the run's own model folder, then the serving pod is restarted
  ollama  (dev overlay) the run's GGUF is published to glm-serve under one stable name (default glm-abl)

ModelControl is the kill switch for glm-serve: Kill, Isolate, Release, Start (design section 8). Audit appends every
action, with who asked, to workspace/audit/YYYY-MM-DD.jsonl and to the container log.

Standard library only: the Kubernetes API is called with the pod's ServiceAccount token. Settings come from
/etc/lab/jobs.json (ConfigMap lab-jobs), one per overlay.
"""
import json
import os
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
SETTINGS_PATH = "/etc/lab/jobs.json"          # LAB_JOBS_SETTINGS overrides it (read when the settings are loaded)

DEFAULT_SETTINGS = {
    "namespace": None,                 # default: the console's own namespace
    "image": "ghcr.io/thrizzo/redteam-llm-lab:latest",
    "imagePullPolicy": "IfNotPresent",
    "imagePullSecrets": [],
    "workspaceClaim": "workspace",
    "ttlSecondsAfterFinished": 86400,
    "env": {},
    "classes": {"light": {}, "cpu": {}, "gpu": {}},
    "serving": {"mode": "vllm", "deployment": "glm-serve", "configmap": "glm-serve", "servedName": "glm-abl",
                "exclusiveGpu": True},
}

# which resource class a stage needs: download is network-bound, apply (the weight edit) and deploy (GGUF) need CPU and
# disk, everything else loads the model into memory (GPU overlays: the 8-GPU node)
STAGE_CLASS = {"download": "light", "apply": "cpu", "deploy": "cpu"}
NEEDS_INTERNET = {"download", "all"}                      # Hugging Face: model + prompt datasets
NEEDS_MODEL_SERVER = {"deploy", "all", "continue"}        # GGUF upload to glm-serve (Ollama), unless --no-ollama


def stage_class(stage):
    return STAGE_CLASS.get(stage, "gpu")


def load_settings(path=None):
    path = path or os.environ.get("LAB_JOBS_SETTINGS") or SETTINGS_PATH
    s = json.loads(json.dumps(DEFAULT_SETTINGS))
    if os.path.isfile(path):
        user = json.load(open(path, encoding="utf-8"))
        for k, v in user.items():
            if isinstance(v, dict) and isinstance(s.get(k), dict):
                s[k].update(v)
            else:
                s[k] = v
    return s


def ts_key(ts):
    """Sortable key for an RFC3339Nano timestamp (the API trims trailing zeros, so plain string order is wrong)."""
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z", ts or "")
    return (m.group(1), (m.group(2) or "").ljust(9, "0")) if m else ("", "")


class K8sError(Exception):
    def __init__(self, status, message):
        super().__init__(f"Kubernetes API {status}: {message}")
        self.status, self.message = status, message


class K8s:
    """The few Kubernetes API calls the console makes. In a pod: the ServiceAccount's token and CA. In tests: a base URL."""

    def __init__(self, base=None, token=None, cafile=None, namespace=None, timeout=30):
        if base is None:
            base = "https://{}:{}".format(os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc"),
                                          os.environ.get("KUBERNETES_SERVICE_PORT", "443"))
        self.base, self._token, self.timeout = base.rstrip("/"), token, timeout
        if cafile is None and os.path.isfile(os.path.join(SA_DIR, "ca.crt")):
            cafile = os.path.join(SA_DIR, "ca.crt")
        self.ctx = ssl.create_default_context(cafile=cafile) if self.base.startswith("https") else None
        ns_file = os.path.join(SA_DIR, "namespace")
        self.namespace = namespace or (open(ns_file).read().strip() if os.path.isfile(ns_file) else "default")

    def token(self):
        # projected ServiceAccount tokens rotate: read the file on every call
        return self._token if self._token is not None else open(os.path.join(SA_DIR, "token")).read().strip()

    def _open(self, method, path, body=None, query=None, content_type="application/json", timeout=None):
        url = self.base + path + ("?" + urllib.parse.urlencode(query) if query else "")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", "Bearer " + self.token())
        req.add_header("Accept", "application/json, */*")
        if data is not None:
            req.add_header("Content-Type", content_type)
        try:
            return urllib.request.urlopen(req, context=self.ctx, timeout=timeout or self.timeout)
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            try:
                msg = json.loads(raw).get("message", raw)
            except ValueError:
                msg = raw
            raise K8sError(e.code, msg) from None

    def _json(self, method, path, body=None, query=None, content_type="application/json"):
        with self._open(method, path, body, query, content_type) as r:
            raw = r.read()
        return json.loads(raw) if raw else {}

    def get(self, path, **query):
        return self._json("GET", path, query=query or None)

    def post(self, path, body):
        return self._json("POST", path, body)

    def patch(self, path, body):
        return self._json("PATCH", path, body, content_type="application/merge-patch+json")

    def delete(self, path, body=None):
        return self._json("DELETE", path, body)

    def stream_lines(self, path, **query):
        """Yields decoded lines of a streaming response (pod logs with follow=true) until the server closes it."""
        with self._open("GET", path, query=query, timeout=3600) as r:
            for raw in r:
                yield raw.decode("utf-8", "replace").rstrip("\n")


class JobPipeline:
    """server.Pipeline's interface, backed by one Kubernetes Job per stage."""

    poll = 2.0                     # seconds between pod status checks (tests lower it)

    def __init__(self, project, code, settings, k8s, http_error=None, run_id_of=None):
        self.project, self.code, self.settings, self.k8s = project, code, settings, k8s
        self.ns = settings.get("namespace") or k8s.namespace
        self.http_error = http_error or (lambda status, msg: RuntimeError(f"{status}: {msg}"))
        self.run_id_of = run_id_of or (lambda d: os.path.basename(os.path.normpath(d)).replace("abliterate_", ""))
        self.lock = threading.Lock()
        self.proc = None                       # no child process; kept so callers that check it see None
        self.thread = None
        self.job = None
        self.feed = None                       # the console's live feed (copilot.Feed), when set
        self._reset()

    def _feed(self, message, level="info", data=None):
        if self.feed:
            run = self.run_id_of(self.run_dir) if self.run_dir else None
            self.feed.emit("pipeline", self.stage or "?", message, level, data, run_id=run)

    def _reset(self):
        self.lines, self.events = [], []
        self.stage = self.engine = self.started = self.exit_code = self.log_path = self.run_dir = None
        self._log_file = None

    # -------------------------------------------------------------------- start / stop
    def running(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self, cmd, engine, stage, run_dir=None, env_extra=None):
        """cmd: the pipeline's command line as the console built it (with --layer or --layers, --combine), unchanged as
        the Job's container command; a new run gets its folders appended."""
        if self.running():
            raise self.http_error(409, f"'{self.stage}' is still running")
        if engine != "abliterate":
            raise self.http_error(400, "only the abliterate engine runs as a Kubernetes Job")
        if stage_class(stage) == "gpu":
            self._check_gpu_free()
        cmd = [str(c) for c in cmd]
        if not run_dir:
            # a new run gets its folder now (the UI follows it by id) and its own model folder, kept for Promote/Rollback
            run_dir = "runs/abliterate_" + datetime.now().strftime("%Y%m%d_%H%M%S")
            cmd += ["--run-dir", run_dir, "--out-dir", run_dir + "/model"]
        notes = []
        if env_extra and env_extra.get("HF_TOKEN"):
            notes.append("[app] Kubernetes: the Hugging Face token comes from the Secret 'hf', not from the browser")
        name = f"abl-{stage}-{datetime.now():%Y%m%d-%H%M%S}"
        self.k8s.post(f"/apis/batch/v1/namespaces/{self.ns}/jobs", self.job_manifest(name, stage, cmd, run_dir))
        self._begin(name, stage, run_dir, notes + [f"[app] Kubernetes Job {name} created"])
        return self.status()

    def stop(self):
        if self.job and self.running():
            try:
                self.k8s.delete(f"/apis/batch/v1/namespaces/{self.ns}/jobs/{self.job}",
                                {"propagationPolicy": "Background", "gracePeriodSeconds": 0})
            except K8sError as e:
                if e.status != 404:
                    raise
            for pod in self._pods():
                try:
                    self.k8s.delete(f"/api/v1/namespaces/{self.ns}/pods/{pod['metadata']['name']}", {"gracePeriodSeconds": 0})
                except K8sError as e:
                    if e.status != 404:
                        raise
            self._line(f"[app] stopped: Job {self.job} deleted")
        return self.status()

    def attach(self):
        """After a console restart: follow a Job that is still running."""
        try:
            jobs = self.k8s.get(f"/apis/batch/v1/namespaces/{self.ns}/jobs", labelSelector="app=lab-job").get("items", [])
        except Exception:
            return None
        active = [j for j in jobs if (j.get("status") or {}).get("active")]
        if not active or self.running():
            return None
        j = max(active, key=lambda x: (x.get("status") or {}).get("startTime") or "")
        labels = j["metadata"].get("labels") or {}
        run = labels.get("lab-run")
        started = (j.get("status") or {}).get("startTime")
        t0 = datetime.strptime(started, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp() if started else None
        self._begin(j["metadata"]["name"], labels.get("lab-stage", "?"), f"runs/abliterate_{run}" if run and run != "none" else None,
                    [f"[app] re-attached to the running Kubernetes Job {j['metadata']['name']}"], started=t0)
        return j["metadata"]["name"]

    def _check_gpu_free(self):
        sv = self.settings.get("serving") or {}
        if sv.get("mode") != "vllm" or not sv.get("exclusiveGpu", True):
            return
        d = self.k8s.get(f"/apis/apps/v1/namespaces/{self.ns}/deployments/{sv.get('deployment', 'glm-serve')}")
        if (d.get("spec") or {}).get("replicas") or (d.get("status") or {}).get("replicas"):
            raise self.http_error(409, "GPU node busy: glm-serve is running. Stop it (Kill) before measuring or validating, "
                                       "or set serving.exclusiveGpu=false in lab-jobs when there is a second GPU node")

    # -------------------------------------------------------------------- the Job
    def job_manifest(self, name, stage, cmd, run_dir):
        s, cls = self.settings, stage_class(stage)
        c = (s.get("classes") or {}).get(cls) or {}
        labels = {"app": "lab-job", "lab-role": "job", "lab-stage": stage,
                  "lab-run": self.run_id_of(run_dir) if run_dir else "none"}
        if stage in NEEDS_INTERNET:
            labels["lab-egress-internet"] = "true"
        if stage in NEEDS_MODEL_SERVER and "--no-ollama" not in cmd:
            labels["lab-egress-model"] = "true"
        env = {"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1", "MPLBACKEND": "Agg",
               "HF_HUB_DISABLE_PROGRESS_BARS": "1", "PYTHONPATH": self.code, "ABL_PROJECT": self.project, **(s.get("env") or {})}
        if stage not in NEEDS_INTERNET:
            env.update({"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"})
        env_list = [{"name": k, "value": str(v)} for k, v in env.items()]
        if stage in NEEDS_INTERNET:
            env_list.append({"name": "HF_TOKEN", "valueFrom": {"secretKeyRef": {"name": "hf", "key": "token", "optional": True}}})
        container = {"name": "pipeline", "image": s["image"], "imagePullPolicy": s.get("imagePullPolicy", "IfNotPresent"),
                     "command": cmd, "workingDir": self.project, "env": env_list, "resources": c.get("resources") or {},
                     "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
                     "volumeMounts": [{"name": "workspace", "mountPath": self.project}]}
        pod = {"restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
               "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000,
                                   "fsGroupChangePolicy": "OnRootMismatch", "seccompProfile": {"type": "RuntimeDefault"}},
               "containers": [container],
               "volumes": [{"name": "workspace", "persistentVolumeClaim": {"claimName": s.get("workspaceClaim", "workspace")}}]}
        for k in ("nodeSelector", "tolerations", "runtimeClassName"):
            if c.get(k):
                pod[k] = c[k]
        if s.get("imagePullSecrets"):
            pod["imagePullSecrets"] = [{"name": n} for n in s["imagePullSecrets"]]
        spec = {"backoffLimit": 0, "ttlSecondsAfterFinished": s.get("ttlSecondsAfterFinished", 86400),
                "template": {"metadata": {"labels": labels}, "spec": pod}}
        if c.get("activeDeadlineSeconds"):
            spec["activeDeadlineSeconds"] = c["activeDeadlineSeconds"]
        return {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name, "namespace": self.ns, "labels": labels}, "spec": spec}

    # -------------------------------------------------------------------- following the pod
    def _begin(self, job, stage, run_dir, notes, started=None):
        self._reset()
        self.job, self.stage, self.engine, self.run_dir = job, stage, "abliterate", run_dir
        self.started = started or time.time()
        os.makedirs(os.path.join(self.project, "runs"), exist_ok=True)
        self.log_path = os.path.join(self.project, "runs", f"app_abliterate_{stage}_{datetime.now():%Y%m%d_%H%M%S}.log")
        self._log_file = open(self.log_path, "a", encoding="utf-8")
        for n in notes:
            self._line(n)
        self._feed(f"Job {job}: stage {stage} started", data={"job": job})
        self.thread = threading.Thread(target=self._pump, daemon=True)
        self.thread.start()

    def _line(self, line):
        """The same parsing as server.Pipeline._pump."""
        f = self._log_file
        if f:
            try:
                f.write(line + "\n")
                f.flush()
            except ValueError:                        # closed by the pump at the same moment (stop): the UI still gets it
                pass
        with self.lock:
            if line.startswith("EVENT "):
                try:
                    ev = json.loads(line[6:])
                    self.events.append(ev)
                except ValueError:
                    ev = None
                if isinstance(ev, dict) and ev.get("status") in ("done", "error") and ev.get("step"):
                    err = ev.get("status") == "error"
                    msg = f"{ev['step']}: " + (str(ev.get("message") or "failed")[:200] if err else "done")
                    self._feed(msg, "error" if err else "info")      # the feed has its own lock: no inversion
                if '"generations"' in line or '"baseline"' in line or '"separation_pct"' in line:
                    line = line[:160] + " …"
            elif not self.run_dir:
                m = re.search(r"run (runs[\\/]abliterate_\d+_\d+)", line)
                if m:
                    self.run_dir = m.group(1).replace("\\", "/")
            self.lines.append(line)

    def _pods(self):
        return self.k8s.get(f"/api/v1/namespaces/{self.ns}/pods", labelSelector=f"job-name={self.job}").get("items", [])

    def _pump(self):
        try:
            pod = self._wait_for_pod()
            if pod:
                self._stream(pod)
                self.exit_code = self._wait_exit(pod)
            elif self.exit_code is None:
                self.exit_code = -1
        except Exception as e:                      # noqa: BLE001 - the UI must always see the end of a run
            self._line(f"[app] lost track of Job {self.job}: {e}")
            if self.exit_code is None:
                self.exit_code = -1
        self._line(f"[app] process exited with code {self.exit_code}")
        self._feed(f"Job {self.job}: stage {self.stage} exited with code {self.exit_code}", "info" if self.exit_code == 0 else "error",
                   {"job": self.job, "exit_code": self.exit_code})
        if self._log_file:
            self._log_file.close()
            self._log_file = None

    def _wait_for_pod(self):
        said = None
        while True:
            pods = self._pods()
            if not pods:
                try:
                    job = self.k8s.get(f"/apis/batch/v1/namespaces/{self.ns}/jobs/{self.job}")
                except K8sError as e:
                    if e.status == 404:
                        self._line(f"[app] Job {self.job} is gone")
                        return None
                    raise
                if (job.get("status") or {}).get("failed"):
                    self._line(f"[app] Job {self.job} failed before its pod started")
                    return None
                time.sleep(self.poll)
                continue
            p = pods[0]
            phase = (p.get("status") or {}).get("phase")
            if phase in ("Running", "Succeeded", "Failed"):
                return p["metadata"]["name"]
            why = self._pending_reason(p)
            if why != said:
                self._line(f"[app] waiting for pod {p['metadata']['name']}: {why}")
                said = why
            time.sleep(self.poll)

    @staticmethod
    def _pending_reason(p):
        st = p.get("status") or {}
        for cs in st.get("containerStatuses") or []:
            w = (cs.get("state") or {}).get("waiting")
            if w:
                return f"{w.get('reason')}: {w.get('message', '')}".strip(": ")
        for c in st.get("conditions") or []:
            if c.get("status") == "False" and c.get("reason"):
                return f"{c['reason']}: {c.get('message', '')}".strip(": ")
        return st.get("phase") or "pending"

    def _stream(self, pod):
        last = None
        path = f"/api/v1/namespaces/{self.ns}/pods/{pod}/log"
        while True:
            q = {"container": "pipeline", "follow": "true", "timestamps": "true"}
            if last:
                q["sinceTime"] = last[0] + "Z"        # second precision on the API side; finer duplicates are skipped below
            try:
                for raw in self.k8s.stream_lines(path, **q):
                    ts, _, text = raw.partition(" ")
                    key = ts_key(ts)
                    if key == ("", ""):               # no timestamp: keep the whole line
                        text, key = raw, None
                    if key and last and key <= last:
                        continue
                    if key:
                        last = key
                    self._line(text)
            except (TimeoutError, OSError):           # a quiet stage outlasted the read timeout: reconnect below
                pass
            phase = self._phase(pod)
            if phase != "Running":                    # the stream ended because the container did
                return
            time.sleep(self.poll)                     # API-side timeout while it still runs: reconnect

    def _phase(self, pod):
        try:
            return (self.k8s.get(f"/api/v1/namespaces/{self.ns}/pods/{pod}").get("status") or {}).get("phase")
        except K8sError as e:
            if e.status == 404:
                return "Gone"
            raise

    def _wait_exit(self, pod):
        while True:
            try:
                p = self.k8s.get(f"/api/v1/namespaces/{self.ns}/pods/{pod}")
            except K8sError as e:
                if e.status == 404:
                    return -9                         # deleted (Stop)
                raise
            for cs in (p.get("status") or {}).get("containerStatuses") or []:
                term = (cs.get("state") or {}).get("terminated")
                if cs.get("name") == "pipeline" and term:
                    return term.get("exitCode", -1)
            time.sleep(self.poll)

    # -------------------------------------------------------------------- what the UI reads
    def status(self):
        running = self.running()
        last_ev = self.events[-1] if self.events else None
        return {"running": running, "engine": self.engine, "stage": self.stage, "started": self.started,
                "elapsed_s": round(time.time() - self.started) if self.started and running else None,
                "exit_code": self.exit_code, "log_path": self.log_path, "n_lines": len(self.lines), "n_events": len(self.events),
                "run_dir": self.run_dir, "run_id": self.run_id_of(self.run_dir) if self.run_dir else None,
                "current": (f"{last_ev['step']} · {last_ev['status']}" if last_ev else None),
                "runner": "k8s", "job": self.job}

    def log(self, start):
        with self.lock:
            return {"lines": self.lines[start:], "next": len(self.lines), "running": self.running()}

    def events_from(self, start):
        with self.lock:
            return {"events": self.events[start:], "next": len(self.events), "running": self.running(), "run_id": self.status()["run_id"]}


class Serving:
    """Which run's model glm-serve serves: Promote, Rollback, and the history of both (workspace/serving/history.json)."""

    def __init__(self, project, settings, k8s, http_error=None, publish=None):
        self.project, self.settings, self.k8s = project, settings, k8s
        self.sv = settings.get("serving") or {}
        self.mode = self.sv.get("mode", "vllm")
        self.ns = settings.get("namespace") or k8s.namespace
        self.http_error = http_error or (lambda status, msg: RuntimeError(f"{status}: {msg}"))
        self.publish = publish                # ollama mode: publish(name, gguf, model_dir), blocking
        self.history_path = os.path.join(project, "serving", "history.json")
        self.lock = threading.Lock()
        self.busy = self.error = None
        self.worker = None

    def history(self):
        try:
            return json.load(open(self.history_path, encoding="utf-8"))
        except (OSError, ValueError):
            return []

    def _append(self, entry):
        h = self.history() + [entry]
        os.makedirs(os.path.dirname(self.history_path), exist_ok=True)
        tmp = self.history_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(h, f, indent=2)
        os.replace(tmp, self.history_path)

    def candidates(self):
        out = []
        runs = os.path.join(self.project, "runs")
        for d in sorted(os.listdir(runs), reverse=True) if os.path.isdir(runs) else []:
            if not d.startswith("abliterate_"):
                continue
            try:
                meta = json.load(open(os.path.join(runs, d, "run.json"), encoding="utf-8"))
            except (OSError, ValueError):
                continue
            out_dir = meta.get("out_dir") or ""
            if not os.path.isfile(os.path.join(out_dir, "config.json")):
                continue                              # no edited model (yet)
            gguf = (meta.get("gguf") or {}).get("abl")
            val = None
            try:
                val = json.load(open(os.path.join(runs, d, "validation.json"), encoding="utf-8")).get("verdict")
            except (OSError, ValueError):
                pass
            if self.mode == "ollama":
                ok, why = bool(gguf and os.path.isfile(gguf)), "run the deploy stage first: it builds the GGUF Ollama serves"
            else:
                ok, why = True, ""
            # layers: all layers whose directions the edit removed (runs before several directions have "layer" only)
            out.append({"run_id": d.replace("abliterate_", ""), "model": meta.get("model_repo"), "layer": meta.get("layer"),
                        "layers": meta.get("layers"), "status": meta.get("status"), "verdict": val, "path": out_dir, "gguf": gguf, "model_dir": meta.get("model_dir"),
                        "promotable": ok, "why": "" if ok else why})
        return out

    def deployment(self):
        try:
            d = self.k8s.get(f"/apis/apps/v1/namespaces/{self.ns}/deployments/{self.sv.get('deployment', 'glm-serve')}")
            return {"replicas": (d.get("spec") or {}).get("replicas") or 0, "ready": (d.get("status") or {}).get("readyReplicas") or 0}
        except Exception as e:                      # noqa: BLE001
            return {"error": str(e)}

    def status(self):
        h = self.history()
        return {"mode": self.mode, "served_name": self.sv.get("servedName", "glm-abl") if self.mode == "ollama" else None,
                "current": h[-1] if h else None, "history": list(reversed(h[-20:])), "candidates": self.candidates(),
                "deployment": self.deployment(), "busy": self.busy, "error": self.error}

    def promote(self, run_id, action="promote", by=None):
        with self.lock:
            if self.busy:
                raise self.http_error(409, f"busy: {self.busy}")
            c = next((x for x in self.candidates() if x["run_id"] == run_id), None)
            if not c:
                raise self.http_error(404, f"run {run_id} has no edited model")
            if not c["promotable"]:
                raise self.http_error(409, c["why"])
            entry = {"run_id": run_id, "path": c["path"], "model": c["model"], "layer": c["layer"], "action": action,
                     "at": datetime.now().isoformat(timespec="seconds"), "by": by}
            if c.get("layers"):
                entry["layers"] = c["layers"]
            self.error = None
            if self.mode == "vllm":
                cm = self.sv.get("configmap", "glm-serve")
                self.k8s.patch(f"/api/v1/namespaces/{self.ns}/configmaps/{cm}", {"data": {"MODEL_PATH": c["path"]}})
                entry["restarted"] = self._restart()
                self._append(entry)
                return self.status()
            name = self.sv.get("servedName", "glm-abl")
            self.busy = f"publishing run {run_id} to glm-serve as {name}"
            entry.update(served_name=name, gguf=c["gguf"])
            self.worker = threading.Thread(target=self._publish, args=(entry, c), daemon=True)
            self.worker.start()
            return self.status()

    def _publish(self, entry, c):
        try:
            self.publish(entry["served_name"], c["gguf"], c["model_dir"])
            self._append(entry)
        except Exception as e:                      # noqa: BLE001
            self.error = f"publishing {entry['run_id']} failed: {e}"
        finally:
            self.busy = None

    def _restart(self):
        """New pod, new ConfigMap values: delete the serving pods; the Deployment recreates them (if it is scaled up)."""
        n = 0
        for p in self.k8s.get(f"/api/v1/namespaces/{self.ns}/pods", labelSelector=f"app={self.sv.get('deployment', 'glm-serve')}").get("items", []):
            self.k8s.delete(f"/api/v1/namespaces/{self.ns}/pods/{p['metadata']['name']}")
            n += 1
        return n

    def rollback(self, by=None):
        h = self.history()
        if not h:
            raise self.http_error(409, "nothing has been promoted yet")
        current = h[-1]["run_id"]
        prev = next((e for e in reversed(h[:-1]) if e["run_id"] != current), None)
        if not prev:
            raise self.http_error(409, "no earlier promoted run to go back to")
        return self.promote(prev["run_id"], action="rollback", by=by)


class Audit:
    """Append-only audit log: workspace/audit/YYYY-MM-DD.jsonl (UTC date), one JSON object per line, in the live feed's
    schema {ts, source, run_id, stage, level, message, data} plus who: the basic-auth user, and the peer address and
    X-Forwarded-For chain as the login proxy saw them. With one shared login, the address is the only "who".
    Every record is also printed to stdout: the container log keeps a copy the Jobs, which share the workspace, can't edit."""

    def __init__(self, project, feed=None):
        self.dir = os.path.join(project, "audit")
        self.lock = threading.Lock()
        self.feed = feed                        # every audit record also goes to the live feed

    def write(self, source, stage, message, level="info", data=None, who=None, run_id=None):
        now = datetime.now(timezone.utc)
        rec = {"ts": now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z", "source": source,
               "run_id": run_id, "stage": stage, "level": level, "message": message, "data": data or {}, "who": who or {}}
        line = json.dumps(rec, ensure_ascii=False, default=str)
        with self.lock:
            os.makedirs(self.dir, exist_ok=True)
            with open(os.path.join(self.dir, now.strftime("%Y-%m-%d") + ".jsonl"), "a", encoding="utf-8") as f:
                f.write(line + "\n")
        print("AUDIT " + line, flush=True)
        if self.feed:
            self.feed.emit(source, stage, message, level, {**(data or {}), "who": who or {}}, run_id=run_id, ts=rec["ts"])
        return rec

    def recent(self, n=30):
        """The newest n records, newest first."""
        out = []
        try:
            files = sorted((f for f in os.listdir(self.dir) if f.endswith(".jsonl")), reverse=True)
        except OSError:
            return out
        for fn in files:
            try:
                with open(os.path.join(self.dir, fn), encoding="utf-8") as f:
                    lines = f.read().splitlines()
            except OSError:
                continue
            for line in reversed(lines):
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
                if len(out) >= n:
                    return out
        return out


class Refused(Exception):
    """A precondition failed before the action changed anything (the API answers 409)."""


class ModelControl:
    """Kill, Isolate, Release and Start for the model server (design section 8).

    The network policy glm-serve-allow is the model server's only opening; default-deny stays. Isolate deletes it, and
    Release recreates it from the console's copy. That copy lives in the console pod (state_dir, an emptyDir), not on the
    workspace: the Jobs and, in dev, the model server can write the workspace, and Release creates whatever the copy says.
    Kill isolates, scales the Deployment to 0 and deletes its pods with gracePeriodSeconds 0. Start recreates the policy
    and scales back up. A failed step never stops the steps after it, and every action is audited with its steps, their
    timings and who asked."""

    ACTIONS = ("kill", "isolate", "release", "start")
    SERVER_FIELDS = ("resourceVersion", "uid", "creationTimestamp", "generation", "managedFields", "selfLink",
                     "deletionTimestamp", "deletionGracePeriodSeconds")

    def __init__(self, settings, k8s, state_dir, audit, http_error=None):
        self.settings, self.k8s, self.audit = settings, k8s, audit
        self.sv = settings.get("serving") or {}
        self.ns = settings.get("namespace") or k8s.namespace
        self.deploy = self.sv.get("deployment", "glm-serve")
        self.policy = self.sv.get("policy", "glm-serve-allow")
        self.replicas = int(self.sv.get("replicas", 1))
        self.copy_path = os.path.join(state_dir, f"{self.policy}.json")
        self.http_error = http_error or (lambda status, msg: RuntimeError(f"{status}: {msg}"))
        self.lock = threading.Lock()
        self.wait_gone_s = 5.0
        self.copy = self._load_copy()

    # -------------------------------------------------------------------- API paths
    def _policy_path(self, name=None):
        return f"/apis/networking.k8s.io/v1/namespaces/{self.ns}/networkpolicies" + (f"/{name}" if name else "")

    def _deploy_path(self, sub=""):
        return f"/apis/apps/v1/namespaces/{self.ns}/deployments/{self.deploy}{sub}"

    def _pods(self, selector):
        return self.k8s.get(f"/api/v1/namespaces/{self.ns}/pods", labelSelector=selector).get("items", [])

    def _selector(self, d=None):
        """The Deployment's own pod selector (never a guessed label)."""
        d = d if d is not None else self.k8s.get(self._deploy_path())
        ml = ((d.get("spec") or {}).get("selector") or {}).get("matchLabels") or {"app": self.deploy}
        return ",".join(f"{k}={v}" for k, v in sorted(ml.items()))

    # -------------------------------------------------------------------- the console's copy of the policy
    def _valid(self, pol):
        spec = pol.get("spec") if isinstance(pol, dict) else None
        if not (isinstance(spec, dict) and pol.get("kind") == "NetworkPolicy"
                and (pol.get("metadata") or {}).get("name") == self.policy
                and ((spec.get("podSelector") or {}).get("matchLabels"))):
            raise ValueError(f"not a copy of {self.policy} for a named set of pods")
        return pol

    def _load_copy(self):
        try:
            with open(self.copy_path, encoding="utf-8") as f:
                return self._valid(json.load(f))
        except (OSError, ValueError):
            return None

    def _save_copy(self, live):
        pol = json.loads(json.dumps(live))
        pol.setdefault("apiVersion", "networking.k8s.io/v1")
        pol.setdefault("kind", "NetworkPolicy")
        for k in self.SERVER_FIELDS:
            (pol.get("metadata") or {}).pop(k, None)
        pol.pop("status", None)
        self._valid(pol)
        os.makedirs(os.path.dirname(self.copy_path), exist_ok=True)
        tmp = self.copy_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(pol, f, indent=2)
        os.replace(tmp, self.copy_path)
        self.copy = pol

    def snapshot(self):
        """At console start: keep a copy of the policy while it exists, so Release works after a hand-made delete too."""
        try:
            self._save_copy(self.k8s.get(self._policy_path(self.policy)))
            return True
        except Exception:                           # noqa: BLE001  absent (isolated) or unreadable: keep what we have
            return False

    # -------------------------------------------------------------------- state
    def _policy_exists(self):
        try:
            self.k8s.get(self._policy_path(self.policy))
            return True
        except K8sError as e:
            if e.status == 404:
                return False
            raise

    def status(self):
        out = {"deployment": self.deploy, "policy_name": self.policy, "saved_copy": self.copy is not None}
        try:
            d = self.k8s.get(self._deploy_path())
            pods = self._pods(self._selector(d))
            policy = self._policy_exists()
        except Exception as e:                      # noqa: BLE001
            return {**out, "state": "unknown", "error": str(e)}
        replicas = (d.get("spec") or {}).get("replicas") or 0
        ready = (d.get("status") or {}).get("readyReplicas") or 0
        plist = [{"name": p["metadata"]["name"], "phase": (p.get("status") or {}).get("phase"),
                  "deleting": bool(p["metadata"].get("deletionTimestamp"))} for p in pods]
        if replicas == 0:
            state = "stopping" if plist else ("stopped" if policy else "killed")
        elif not policy:
            state = "isolated"
        else:
            state = "running" if ready else "starting"
        return {**out, "state": state, "replicas": replicas, "ready": ready, "pods": plist, "policy": policy}

    # -------------------------------------------------------------------- actions
    def act(self, action, who=None, reason=""):
        if action not in self.ACTIONS:
            raise self.http_error(404, f"unknown action {action!r}")
        with self.lock:                             # one action at a time; each takes well under a second
            t0 = time.monotonic()
            steps, refused = [], None
            try:
                getattr(self, "_" + action)(steps)
            except Refused as e:
                refused = str(e)
            total = round((time.monotonic() - t0) * 1000)
            ok = refused is None and all(s["ok"] for s in steps)
            st = self.status()
            failed = sum(not s["ok"] for s in steps)
            msg = (f"{action} refused: {refused}" if refused else
                   f"{action}: done in {total} ms" if ok else f"{action}: {failed} of {len(steps)} steps failed")
            rec = self.audit.write("control", action, msg, level="info" if ok else "error", who=who,
                                   data={"ok": ok, "reason": reason or "", "steps": steps, "total_ms": total,
                                         "state": st.get("state"), "refused": refused})
        if refused:
            raise self.http_error(409, refused)
        return {"ok": ok, "action": action, "message": msg, "steps": steps, "total_ms": total, "status": st, "audit": rec}

    def _step(self, steps, name, fn):
        t = time.monotonic()
        try:
            detail = fn()
            steps.append({"step": name, "ok": True, "ms": round((time.monotonic() - t) * 1000), "detail": detail})
        except Exception as e:                      # noqa: BLE001  keep going: the next step may still cut the model off
            steps.append({"step": name, "ok": False, "ms": round((time.monotonic() - t) * 1000), "error": str(e)})

    def _remove_policy(self):
        try:
            live = self.k8s.get(self._policy_path(self.policy))
        except K8sError as e:
            if e.status == 404:
                return "already gone"
            raise
        note = "copy kept for Release"
        try:
            self._save_copy(live)
        except (OSError, ValueError) as e:          # never let the copy hold up the cut
            note = f"no copy kept ({e}): Release needs the overlay re-applied"
        try:
            self.k8s.delete(self._policy_path(self.policy))
        except K8sError as e:
            if e.status != 404:
                raise
        return f"deleted, {note}"

    def _restore_policy(self):
        if self._policy_exists():
            return "already there"
        if not self.copy:
            raise RuntimeError(f"the console has no copy of {self.policy}: re-apply the overlay (kubectl apply -k ...)")
        try:
            self.k8s.post(self._policy_path(), json.loads(json.dumps(self.copy)))
        except K8sError as e:
            if e.status != 409:                     # created meanwhile
                raise
            return "already there"
        return "recreated from the console's copy"

    def _scale(self, n):
        self.k8s.patch(self._deploy_path("/scale"), {"spec": {"replicas": n}})
        return f"replicas {n}"

    def _delete_pods(self):
        names = []
        for p in self._pods(self._selector()):
            name = p["metadata"]["name"]
            try:
                self.k8s.delete(f"/api/v1/namespaces/{self.ns}/pods/{name}", {"gracePeriodSeconds": 0})
                names.append(name)
            except K8sError as e:
                if e.status != 404:
                    raise
        return f"{len(names)} pod(s) deleted" + (f": {', '.join(names)}" if names else "")

    def _wait_gone(self):
        t, sel = time.monotonic(), self._selector()
        while True:
            if not self._pods(sel):
                return f"no pods listed after {round((time.monotonic() - t) * 1000)} ms"
            if time.monotonic() - t > self.wait_gone_s:
                raise RuntimeError(f"pods still listed after {self.wait_gone_s:.0f} s")
            time.sleep(0.1)

    def _check_gpu_free(self):
        if self.sv.get("mode") != "vllm" or not self.sv.get("exclusiveGpu", True):
            return
        jobs = self.k8s.get(f"/apis/batch/v1/namespaces/{self.ns}/jobs", labelSelector="app=lab-job").get("items", [])
        busy = [j["metadata"]["name"] for j in jobs if (j.get("status") or {}).get("active")
                and stage_class((j["metadata"].get("labels") or {}).get("lab-stage")) == "gpu"]
        if busy:
            raise Refused(f"GPU node busy: Job {busy[0]} is using the GPUs. Stop it first, or set serving.exclusiveGpu=false "
                          "in lab-jobs when there is a second GPU node")

    def _kill(self, steps):
        self._step(steps, f"isolate: delete network policy {self.policy}", self._remove_policy)
        self._step(steps, f"scale {self.deploy} to 0", lambda: self._scale(0))
        self._step(steps, "delete its pods with gracePeriodSeconds 0", self._delete_pods)
        self._step(steps, "check: no pods left", self._wait_gone)

    def _isolate(self, steps):
        self._step(steps, f"delete network policy {self.policy}", self._remove_policy)

    def _release(self, steps):
        if not self.copy and not self._policy_exists():
            raise Refused(f"the console has no copy of {self.policy}: re-apply the overlay (kubectl apply -k ...)")
        self._step(steps, f"recreate network policy {self.policy}", self._restore_policy)

    def _start(self, steps):
        self._check_gpu_free()
        self._step(steps, f"recreate network policy {self.policy}", self._restore_policy)
        self._step(steps, f"scale {self.deploy} to {self.replicas}", lambda: self._scale(self.replicas))
