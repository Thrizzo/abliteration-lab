r"""Red Team LLM Lab - local app server (abliteration).

    .\.venv\Scripts\python.exe app\server.py --open                        (from the project folder)
    .\.venv\Scripts\python.exe app\server.py --project C:\path\to\Abliteration --port 8787

Serves the UI, lists models and runs, drives the abliterate package (or the notebook runner) as a subprocess with a
live log + event stream, writes the layer choice, hosts the lab (model-resident probing) and a few Ollama helpers."""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import rundata  # noqa: E402
import copilot_runs as CR  # noqa: E402
import engagement as EN  # noqa: E402
import knowledge as KN  # noqa: E402
from lab import Lab  # noqa: E402
from datasets import Datasets, FILES as DATA_FILES  # noqa: E402
from sbom import SbomJob  # noqa: E402
from abliterate import arch as ARCH  # noqa: E402
from abliterate import platform as PL  # noqa: E402

CODE = os.path.dirname(HERE)                                    # where abliterate/, run_pipeline.py live
PROJECT = os.path.abspath(os.environ.get("ABL_PROJECT") or CODE)   # where models/, runs/, data/ live
OLLAMA = PL.ollama_host()
# Kubernetes (deploy/k8s): every pipeline stage runs as a Job next to the console, on the shared workspace volume
K8S = os.environ.get("ABL_RUNNER") == "k8s"
NOTEBOOK_STAGES = {"setup": "1 · setup (torch, packages, llama.cpp)", "data": "3 · dataset audit + local copies",
                   "abl": "4 · measure, scan, choose, apply, validate", "apply": "4.6-4.8 · apply the chosen layer + validate",
                   "validate": "4.8 · validate the saved model", "ollama": "7 · GGUF, Ollama import, A/B test", "main": "2-4 + 7 · the whole pipeline"}
PRESETS = [
    {"repo": "THUDM/glm-edge-4b-chat", "family": "GLM-Edge", "size": "4.3B · 8.6 GB", "local_ok": True, "note": "the POC model: dense pre-norm, exact edit"},
    {"repo": "THUDM/glm-edge-1.5b-chat", "family": "GLM-Edge", "size": "1.5B · 3 GB", "local_ok": True, "note": "small and fast"},
    {"repo": "THUDM/GLM-4-9B-0414", "family": "GLM-4", "size": "9.4B · 19 GB", "local_ok": False, "note": "post-norm block: direction folded through the norm; 16 GB VRAM is too small for bf16 (device_map auto offloads to CPU, slow)"},
    {"repo": "THUDM/glm-4-9b-chat-hf", "family": "GLM-4", "size": "9.4B · 19 GB", "local_ok": False, "note": "post-norm block, same as above"},
    {"repo": "zai-org/GLM-4.5-Air", "family": "GLM-4.5 MoE", "size": "106B · 220 GB", "local_ok": False, "note": "MoE: every expert down_proj is edited; multi-GPU node"},
    {"repo": "zai-org/GLM-4.6", "family": "GLM-4.6 MoE", "size": "355B", "local_ok": False, "note": "MoE, multi-GPU cluster"},
    {"repo": "zai-org/GLM-5.2", "family": "GLM-5.2 MoE + DSA", "size": "744B · 1.5 TB bf16", "local_ok": False, "gguf": False, "note": "78 layers, 256 experts, DSA indexer untouched; cluster only"},
    {"repo": "zai-org/GLM-5.3", "family": "GLM-5.3 MoE + DSA", "size": "744B · 0.75 TB FP8", "local_ok": False, "gguf": False, "note": "same architecture as 5.2, in FP8 (block-scaled: edited and requantized per block); zai-org/GLM-5.3-BF16 is the bf16 copy"},
    {"repo": "zai-org/GLM-5.3-Flash", "family": "GLM-5.3-Flash MoE + mHC", "size": "321B · 0.33 TB FP8", "local_ok": False, "gguf": False, "note": "hybrid: 34 linear-attention (KDA) + 11 DSA layers, 4 residual streams (mHC), 288 experts; the vision encoder stays untouched; 8 × H100 or H200 (FP8-capable)"},
]

RUN_ID = re.compile(r"\d{8}_\d{6}")


def run_dir_of(run_id):
    if not run_id or not RUN_ID.fullmatch(run_id):
        raise HTTPException(400, "bad run_id")
    return os.path.join("runs", f"abliterate_{run_id}")


app = FastAPI(title="Red Team LLM Lab")


class SameOriginOnly:
    """CSRF: a browser sends the lab's basic-auth credentials with requests another site makes, so a page elsewhere could
    press Kill, Release or Promote. State-changing requests from another origin are refused; clients that send no
    Origin / Sec-Fetch-Site headers (curl, n8n) are unaffected. Plain ASGI, so streamed answers pass through untouched."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["method"] not in ("GET", "HEAD", "OPTIONS"):
            h = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or []}
            site, origin, host = h.get("sec-fetch-site"), h.get("origin"), h.get("host", "").lower()
            if (site and site not in ("same-origin", "none")) or (origin and urllib.parse.urlsplit(origin).netloc.lower() != host):
                body = b'{"detail":"cross-site request refused"}'
                await send({"type": "http.response.start", "status": 403,
                            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


app.add_middleware(SameOriginOnly)
lab = Lab(PROJECT)
datasets = Datasets(os.path.join(PROJECT, "data"))
sbom = SbomJob(PROJECT)


# ------------------------------------------------------------------------- pipeline subprocess
class Pipeline:
    def __init__(self):
        self.proc = None
        self.lines, self.events = [], []
        self.stage = self.engine = None
        self.started = None
        self.exit_code = None
        self.log_path = None
        self.run_dir = None
        self.lock = threading.Lock()

    def running(self):
        return bool(self.proc) and self.proc.poll() is None

    def start(self, cmd, engine, stage, run_dir=None, env_extra=None):
        if self.running():
            raise HTTPException(409, f"'{self.stage}' is still running")
        if stage not in ("download", "ollama", "deploy"):          # GPU stages: free the VRAM first
            if lab.hm is not None:
                lab.unload()
            try:
                for m in ollama_get("/api/ps")["models"]:
                    ollama_post("/api/generate", {"model": m["name"], "keep_alive": 0}, timeout=20)
            except Exception:
                pass
        os.makedirs(os.path.join(PROJECT, "runs"), exist_ok=True)
        self.log_path = os.path.join(PROJECT, "runs", f"app_{engine}_{stage}_{datetime.now():%Y%m%d_%H%M%S}.log")
        env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "MPLBACKEND": "Agg", "HF_HUB_DISABLE_PROGRESS_BARS": "1",
               "PYTHONPATH": CODE + os.pathsep + os.environ.get("PYTHONPATH", ""), **(env_extra or {})}
        self.lines, self.events, self.stage, self.engine, self.started, self.exit_code, self.run_dir = [], [], stage, engine, time.time(), None, run_dir
        self.proc = subprocess.Popen(cmd, cwd=PROJECT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, encoding="utf-8", errors="replace", bufsize=1)
        threading.Thread(target=self._pump, daemon=True).start()
        return self.status()

    def _pump(self):
        with open(self.log_path, "w", encoding="utf-8") as f:
            for line in self.proc.stdout:
                line = line.rstrip("\n")
                f.write(line + "\n"); f.flush()
                with self.lock:
                    if line.startswith("EVENT "):
                        try:
                            ev = json.loads(line[6:])
                            self.events.append(ev)
                            if ev.get("step") == "download" and ev.get("path"):
                                pass
                        except Exception:
                            pass
                        if '"generations"' in line or '"baseline"' in line or '"separation_pct"' in line:
                            line = line[:160] + " …"
                    elif line.startswith("run runs") or line[9:].startswith("run runs"):
                        m = re.search(r"run (runs[\\/]abliterate_\d+_\d+)", line)
                        if m:
                            self.run_dir = m.group(1).replace("\\", "/")
                    self.lines.append(line)
        self.exit_code = self.proc.wait()
        with self.lock:
            self.lines.append(f"[app] process exited with code {self.exit_code}")

    def stop(self):
        if self.running():
            self.proc.kill()
        return self.status()

    def status(self):
        running = self.running()
        last_ev = self.events[-1] if self.events else None
        return {"running": running, "engine": self.engine, "stage": self.stage, "started": self.started,
                "elapsed_s": round(time.time() - self.started) if self.started and running else None,
                "exit_code": self.exit_code, "log_path": self.log_path, "n_lines": len(self.lines), "n_events": len(self.events),
                "run_dir": self.run_dir, "run_id": rundata.run_id(self.run_dir) if self.run_dir else None,
                "current": (f"{last_ev['step']} · {last_ev['status']}" if last_ev else None)}

    def log(self, start):
        with self.lock:
            return {"lines": self.lines[start:], "next": len(self.lines), "running": self.running()}

    def events_from(self, start):
        with self.lock:
            return {"events": self.events[start:], "next": len(self.events), "running": self.running(), "run_id": self.status()["run_id"]}


def _ollama_publish(name, gguf, model_dir):
    """Serving in the dev overlay: one run's GGUF published to glm-serve (Ollama) under a stable name."""
    from abliterate import deploy as DP
    DP.ollama_create(name, gguf, DP.chat_template_text(model_dir), None, print)


if K8S:
    import k8sjobs  # noqa: E402
    _k8s_settings = k8sjobs.load_settings()
    _k8s = k8sjobs.K8s(namespace=_k8s_settings.get("namespace"))
    pipeline = k8sjobs.JobPipeline(PROJECT, CODE, _k8s_settings, _k8s, http_error=HTTPException, run_id_of=rundata.run_id)
    serving = k8sjobs.Serving(PROJECT, _k8s_settings, _k8s, http_error=HTTPException, publish=_ollama_publish)
    audit = k8sjobs.Audit(PROJECT)
    # the copy of glm-serve-allow that Release recreates stays in the console pod (an emptyDir), off the shared workspace
    control = k8sjobs.ModelControl(_k8s_settings, _k8s, os.environ.get("LAB_STATE_DIR", "/var/lib/lab"), audit,
                                   http_error=HTTPException)
else:
    pipeline = Pipeline()
    serving = audit = control = None

# the live feed: copilot runs, free prompts, the kill switch and Promote/Rollback (audit records), Jobs, model state
FEED = CR.Feed()
if K8S:
    audit.feed = FEED
    pipeline.feed = FEED
# copilot runs go through n8n (its webhook + API); the secrets come from the mounted Secret "copilot", read on use
copilot = CR.CopilotRuns(os.environ.get("N8N_URL"), os.environ.get("COPILOT_SECRETS_DIR", "/etc/lab/copilot"), FEED, audit=audit,
                         http_error=HTTPException)
# free prompts straight to the model server (OpenAI-compatible: vLLM, or Ollama's /v1 in dev)
model_chat = CR.ModelChat(os.environ.get("GLM_SERVE_URL"),
                          (_k8s_settings.get("serving") or {}).get("servedName", "glm-abl") if K8S else os.environ.get("GLM_SERVE_MODEL", "glm-abl"),
                          FEED, audit=audit)
# which models a copilot run may use: operators from glm-serve, judges from the copilot's Ollama (never abliterated)
copilot_models = CR.CopilotModels(os.environ.get("GLM_SERVE_URL"), os.environ.get("RAG_OLLAMA_URL"), operator_default=model_chat.model,
                                  judge_default=os.environ.get("COPILOT_JUDGE_MODEL") or "qwen3:8b", http_error=HTTPException)
# the copilot's engagement (scope statement, rules, scope, exclusions, window, prohibited tools): versioned under
# workspace/engagement/, audited. LAB_ALLOWLIST / LAB_AUTORUN_* are the ceiling n8n enforces (ConfigMap copilot-scope);
# the console reads the same values to check what the GUI saves.
engagements = EN.Engagements(PROJECT, audit=audit, feed=FEED, ceiling=os.environ.get("LAB_ALLOWLIST") or None,
                             autorun={k: os.environ[v] == "true" for k, v in (("passive", "LAB_AUTORUN_READONLY"),
                                                                         ("active", "LAB_AUTORUN_ACTIVE_RECON")) if v in os.environ},
                             http_error=HTTPException)
# knowledge uploads for the copilot's retrieval: embedded with the copilot's Ollama (RAG_OLLAMA_URL; in dev OLLAMA_HOST
# points at glm-serve instead) into the Qdrant collection n8n searches
knowledge = KN.Knowledge(PROJECT, os.environ.get("QDRANT_URL"), os.environ.get("RAG_COLLECTION", "writeups"),
                         os.environ.get("RAG_OLLAMA_URL") or os.environ.get("OLLAMA_HOST"),
                         os.environ.get("RAG_EMBED_MODEL", "nomic-embed-text"), FEED, audit=audit, http_error=HTTPException)
PY = PL.pipeline_python(PROJECT)


def save_layer(layer, run_dir=None):
    """Same file and schema as the notebook's 4.5 cell (used by the notebook engine's apply stage)."""
    info = {"layer_to_abliterate": int(layer), "model": "models/glm-edge-4b-chat",
            "saved": datetime.now().isoformat(timespec="seconds"), "source": "app", "run_dir": run_dir}
    scan = rundata.load(os.path.join(PROJECT, run_dir, "scan_results.json")) if run_dir else None
    if scan:
        s = next((x for x in scan if x["layer"] == int(layer)), None)
        info["refusals_in_scan"] = s["refusals"] if s else None
    with open(os.path.join(PROJECT, "abliteration_settings.json"), "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2)
    return info


# ------------------------------------------------------------------------- helpers
def ollama_get(path, timeout=3):
    with urllib.request.urlopen(f"{OLLAMA}{path}", timeout=timeout) as r:
        return json.loads(r.read())


def ollama_post(path, body, timeout=30):
    req = urllib.request.Request(f"{OLLAMA}{path}", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


_cuda = {"checked": False, "available": None, "torch": None, "dtype": None}


def cuda_available():
    """torch.cuda.is_available() computed once in a thread (importing torch costs ~2 s); None until known.
    Also records the dtype a run gets here by default (bfloat16 on a GPU, usually float32 on the CPU)."""
    if not _cuda["checked"]:
        _cuda["checked"] = True
        def probe():
            try:
                import torch
                from abliterate.hooks import resolve_device
                _cuda["dtype"] = resolve_device("cuda", "auto", log=lambda *a: None)[1]
                _cuda["available"], _cuda["torch"] = bool(torch.cuda.is_available()), torch.__version__
            except Exception as e:
                _cuda["available"], _cuda["torch"] = False, f"import failed: {e}"
        threading.Thread(target=probe, daemon=True).start()
    return _cuda["available"]


def gpu_info():
    out = PL.nvidia_smi()
    try:
        return {"name": out[0], "vram_used_gb": round(int(out[1]) / 1024, 1), "vram_total_gb": round(int(out[2]) / 1024, 1), "util": int(out[3])} if out else None
    except Exception:
        return None


def folder_size(path):
    total = 0
    for r, _, fs in os.walk(path):
        for f in fs:
            try:
                total += os.path.getsize(os.path.join(r, f))
            except OSError:
                pass
    return total


# ------------------------------------------------------------------------- API: environment, models
@app.get("/api/env")
def env():
    p = lambda *a: os.path.join(PROJECT, *a)
    disk = shutil.disk_usage(PROJECT)
    try:
        models = [m["name"] for m in ollama_get("/api/tags")["models"]]
        loaded = [{"name": m["name"], "vram_gb": round(m.get("size_vram", 0) / 1e9, 1)} for m in ollama_get("/api/ps")["models"]]
        oll = {"reachable": True, "models": models, "loaded": loaded}
    except Exception as e:
        oll = {"reachable": False, "error": str(e), "models": [], "loaded": []}
    return {"project": PROJECT, "code": CODE, "gpu": gpu_info(), "cuda": cuda_available(), "torch": _cuda["torch"], "dtype": _cuda["dtype"], "os": os.name,
            "notebook_engine": os.name == "nt", "disk_free_gb": round(disk.free / 1e9, 1), "python": PY, "ollama_host": OLLAMA,
            "venv": os.path.isfile(PY), "venv_gguf": os.path.isfile(PL.gguf_python(PROJECT)),
            "llama_cpp": os.path.isfile(os.path.join(PL.llama_cpp_dir(PROJECT), "convert_hf_to_gguf.py")), "data": os.path.isfile(p("data", "harmful_test.jsonl")),
            "ollama": oll, "notebook_stages": NOTEBOOK_STAGES, "settings": rundata.load(p("abliteration_settings.json"), {}),
            "runner": "k8s" if K8S else "local"}


@app.get("/api/models")
def models():
    out = []
    mdir = os.path.join(PROJECT, "models")
    if os.path.isdir(mdir):
        for slug in sorted(os.listdir(mdir)):
            d = os.path.join(mdir, slug)
            if not os.path.isdir(d):
                continue
            complete = os.path.isfile(os.path.join(d, "config.json")) and (os.path.isfile(os.path.join(d, "model.safetensors")) or os.path.isfile(os.path.join(d, "model.safetensors.index.json")))
            entry = {"slug": slug, "path": d, "size_gb": round(folder_size(d) / 1e9, 1), "complete": complete,
                     "copy_info": rundata.load(os.path.join(d, "local_copy.json"), {}),
                     "abliterated": os.path.isfile(os.path.join(PROJECT, "out", f"{slug}-abliterated", "config.json"))}
            if os.path.isfile(os.path.join(d, "config.json")):
                try:
                    entry["arch"] = ARCH.inspect(d)
                except Exception as e:
                    entry["arch_error"] = str(e)
            out.append(entry)
    return {"models": out, "presets": PRESETS}


class Download(BaseModel):
    repo: str
    hf_token: str | None = None


@app.post("/api/models/download")
def models_download(b: Download):
    cmd = [PY, "-u", "-m", "abliterate", "--model", b.repo, "--stage", "download"]
    return pipeline.start(cmd, "abliterate", "download", env_extra={"HF_TOKEN": b.hf_token} if b.hf_token else None)   # token via env, never argv


# ------------------------------------------------------------------------- API: runs
@app.get("/api/runs")
def runs():
    return rundata.list_runs(PROJECT)


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/api/runs/{rid}")
def run(rid):
    d = os.path.join(PROJECT, run_dir_of(rid))
    if not os.path.isdir(d):
        raise HTTPException(404, "run not found")
    return rundata.collect(PROJECT, d)


@app.get("/api/runs/{rid}/events")
def run_events(rid):
    p = os.path.join(PROJECT, run_dir_of(rid), "events.jsonl")
    if not os.path.isfile(p):
        return {"events": []}
    evs = []
    with open(p, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    evs.append(json.loads(line))
                except Exception:
                    pass
    return {"events": evs}


class Choice(BaseModel):
    layer: int


@app.post("/api/runs/{rid}/choose")
def choose(rid, c: Choice):
    return save_layer(c.layer, run_dir_of(rid))


@app.get("/api/runs/{rid}/file/{name}")
def run_file(rid, name):
    if not re.fullmatch(r"[\w.\-]+\.(png|json|log|jsonl)", name):
        raise HTTPException(400, "bad name")
    path = os.path.join(PROJECT, run_dir_of(rid), name)
    if not os.path.isfile(path):
        raise HTTPException(404)
    return FileResponse(path)


# ------------------------------------------------------------------------- API: pipeline
class Start(BaseModel):
    engine: str = "abliterate"          # abliterate | notebook
    stage: str = "all"
    model: str | None = None
    run_id: str | None = None
    layer: int | None = None
    layers: list[int] | None = None     # instead of layer: several layers whose directions are removed together (--layers)
    combine: int = 0                    # the scan also tests the best 2..combine layers together (--combine; 0: off)
    pause_at_choice: bool = False
    no_ollama: bool = False
    skip_verify: bool = False
    device_map: str = "cuda"            # cuda | cpu | auto; cuda falls back to cpu when no GPU is visible
    dtype: str = "auto"                 # bfloat16 on a GPU, float32 on the CPU
    n_train: int = 256
    n_test: int = 16
    batch: int = 16
    gen_batch: int = 4
    max_new_tokens: int = 64
    layer_range: str = "0.2-0.8"
    trust_remote_code: bool = False
    quantize: str = "q8_0"


@app.post("/api/pipeline/start")
def pipeline_start(s: Start):
    run_dir = run_dir_of(s.run_id) if s.run_id else None
    for name, val in (("layer_range", s.layer_range), ("quantize", s.quantize), ("dtype", s.dtype), ("device_map", s.device_map), ("model", s.model or "")):
        if not re.fullmatch(r"[\w.\-/:]*", val):
            raise HTTPException(400, f"bad {name}")
    if s.layers is not None:
        if s.layer is not None:
            raise HTTPException(400, "give layer or layers, not both")
        if not s.layers or len(s.layers) > 64 or any(not 0 <= x < 10000 for x in s.layers):
            raise HTTPException(400, "bad layers: one to 64 layer numbers (the pipeline checks them against the model)")
    if not 0 <= s.combine <= 16:
        raise HTTPException(400, "bad combine: 0 (off) to 16 layers")
    if s.engine == "notebook":
        if (s.layers and len(s.layers) > 1) or s.combine:
            raise HTTPException(400, "the notebook engine applies one layer; several layers need engine=abliterate")
        if s.layers:
            s.layer = s.layers[0]
        if os.name != "nt" or os.environ.get("ABL_NOTEBOOK_ENGINE") == "0":
            raise HTTPException(400, "the notebook engine (run_pipeline.py / TransformerLens) is Windows-only; use engine=abliterate")
        if s.stage not in NOTEBOOK_STAGES:
            raise HTTPException(400, f"unknown notebook stage {s.stage}")
        if s.stage in ("apply", "validate") and not run_dir:
            raise HTTPException(400, "apply/validate need a run_id")
        if s.layer is not None:
            save_layer(s.layer, run_dir)
        cmd = [PY, "-u", os.path.join(CODE, "run_pipeline.py"), s.stage] + (["--run-dir", run_dir] if run_dir else [])
        return pipeline.start(cmd, "notebook", s.stage, run_dir)
    if s.stage not in ("all", "download", "measure", "scan", "continue", "apply", "validate", "deploy"):
        raise HTTPException(400, f"unknown stage {s.stage}")
    if s.stage in ("continue", "apply", "validate", "deploy") and not run_dir:
        raise HTTPException(400, f"{s.stage} needs a run_id")
    if s.stage in ("all", "download", "measure", "scan") and not s.model:
        raise HTTPException(400, "model is required")
    cmd = [PY, "-u", "-m", "abliterate", "--stage", s.stage, "--device-map", s.device_map, "--dtype", s.dtype,
           "--n-train", str(s.n_train), "--n-test", str(s.n_test), "--batch", str(s.batch), "--gen-batch", str(s.gen_batch),
           "--max-new-tokens", str(s.max_new_tokens), "--layer-range", s.layer_range, "--quantize", s.quantize]
    if s.model:
        cmd += ["--model", s.model]
    if run_dir:
        cmd += ["--run-dir", run_dir]
    if s.layer is not None:
        cmd += ["--layer", str(s.layer)]
    if s.layers:
        cmd += ["--layers", ",".join(str(x) for x in s.layers)]
    if s.combine:
        cmd += ["--combine", str(s.combine)]
    for flag, on in (("--pause-at-choice", s.pause_at_choice), ("--no-ollama", s.no_ollama), ("--skip-verify", s.skip_verify), ("--trust-remote-code", s.trust_remote_code)):
        if on:
            cmd.append(flag)
    return pipeline.start(cmd, "abliterate", s.stage, run_dir)


# ------------------------------------------------------------------------- API: serving (Kubernetes only)
class Promote(BaseModel):
    run_id: str


def _serving():
    if not serving:
        raise HTTPException(404, "serving (Promote / Rollback) exists in the Kubernetes deployment only")
    return serving


@app.get("/api/serving")
def serving_status():
    return _serving().status()


def _who(request):
    """Who asked, as the login proxy (Caddy, same pod) passes it on: the app listens on 127.0.0.1 only, so these headers
    can't come from anyone else. One shared login: the address is the real "who"."""
    h = request.headers
    return {"user": h.get("x-lab-user") or None, "ip": h.get("x-lab-peer") or (request.client.host if request.client else None),
            "forwarded_for": h.get("x-lab-forwarded-for") or None}


def _audited(stage, message, who, fn, run_id=None):
    """Serving changes go into the audit log too, failed attempts included."""
    try:
        out = fn()
    except HTTPException as e:
        audit.write("serving", stage, f"{message} refused: {e.detail}", level="error", who=who, run_id=run_id)
        raise
    audit.write("serving", stage, message, who=who, run_id=run_id,
                data={"mode": out.get("mode"), "busy": out.get("busy")})
    return out


@app.post("/api/serving/promote")
def serving_promote(b: Promote, request: Request):
    run_dir_of(b.run_id)                                     # validates the id
    who = _who(request)
    return _audited("promote", f"promote run {b.run_id}", who, lambda: _serving().promote(b.run_id, by=who["user"]), b.run_id)


@app.post("/api/serving/rollback")
def serving_rollback(request: Request):
    who = _who(request)
    return _audited("rollback", "rollback", who, lambda: _serving().rollback(by=who["user"]))


# ------------------------------------------------------------------------- API: Kill / Isolate (Kubernetes only)
class Action(BaseModel):
    reason: str = ""                                         # optional, for the audit log


def _control():
    if not control:
        raise HTTPException(404, "Kill / Isolate exist in the Kubernetes deployment only")
    return control


@app.get("/api/control")
def control_status():
    return {**_control().status(), "audit": audit.recent(30)}


@app.post("/api/control/{action}")
def control_action(action: str, b: Action, request: Request):
    """kill | isolate | release | start. The JSON body is required (an empty cross-site form post can't trigger it)."""
    return _control().act(action, _who(request), b.reason[:500])


# ------------------------------------------------------------------------- API: live feed, copilot runs, free prompts
@app.get("/api/feed")
def feed_since(after: int = 0, source: str = "", limit: int = 200):
    """Everything after the last seq the browser saw (it polls). Model and form text is data: the browser escapes it."""
    return FEED.since(after, min(max(limit, 1), 500), source or None)


class CopilotRun(BaseModel):
    task: str = Field("", max_length=2000)              # copilot mode: required; manual mode: optional (why)
    target: str = Field(min_length=1, max_length=253)
    mode: str = Field("copilot", pattern="^(copilot|manual)$")
    command: str = Field("", max_length=2000)            # manual mode: the command the operator typed
    operator_model: str = Field("", max_length=128)
    judge_model: str = Field("", max_length=128)


@app.get("/api/copilot")
def copilot_status():
    return {**copilot.status(), "model": {"configured": bool(model_chat.base), "name": model_chat.model}}


@app.get("/api/copilot/models")
def copilot_model_list(fresh: bool = False):
    """The copilot's three models: operators (glm-serve), judges (the copilot's Ollama, abliterated and embedding models
    left out), and the embedding model retrieval searches with (fixed: RAG_EMBED_MODEL)."""
    return {**copilot_models.list(fresh), "embeddings": {"model": knowledge.embed_model}}


@app.post("/api/copilot/run")
def copilot_run(b: CopilotRun, request: Request):
    """Starts the n8n copilot with the chosen models and the active engagement: scope gate, retrieval, operator (copilot
    mode) or the typed command (manual mode), policy gate, judge. It stages a command; nothing executes."""
    op, judge = copilot_models.check(b.operator_model, b.judge_model)
    return copilot.start(b.task, b.target, _who(request), mode=b.mode, command=b.command, operator_model=op, judge_model=judge,
                         engagement=engagements.payload())


@app.get("/api/engagement")
def engagement_status():
    """The active engagement, its recent versions and the ceiling (LAB_ALLOWLIST, LAB_AUTORUN_*) as far as the console knows it."""
    return engagements.status()


@app.post("/api/engagement")
def engagement_save(request: Request, b: dict = Body(...)):
    """Saves a new version (validated; the same fields again change nothing). Audited with who saved it."""
    b = dict(b)
    note = b.pop("note", "")
    return engagements.save(b, _who(request), note)


@app.get("/api/engagement/versions/{version}")
def engagement_version(version: int):
    return engagements.get(version)


@app.get("/api/copilot/runs/{run_id}")
def copilot_get(run_id: str):
    return copilot.get(run_id)


@app.post("/api/copilot/runs/{run_id}/stop")
def copilot_stop(run_id: str, b: Action, request: Request):
    return copilot.stop(run_id, _who(request))


class Prompt(BaseModel):
    prompt: str = Field(min_length=1, max_length=20000)
    max_tokens: int = Field(512, ge=1, le=4096)
    model: str = Field("", max_length=128)              # one glm-serve lists; empty: the served model


@app.post("/api/model/chat")
def model_chat_stream(b: Prompt, request: Request):
    """A free prompt to the served model, streamed as NDJSON ({"token"} ..., then {"done"} or {"error"}), audited."""
    if not model_chat.base:
        raise HTTPException(404, "no model server configured (GLM_SERVE_URL)")
    who = _who(request)
    model = copilot_models.operator(b.model)
    return StreamingResponse((json.dumps(ev) + "\n" for ev in model_chat.stream(b.prompt, b.max_tokens, who, model)),
                             media_type="application/x-ndjson")


# ------------------------------------------------------------------------- API: knowledge uploads (retrieval)
async def _upload_body(request):
    """The raw request body (the file itself), refused past the 50 MB cap while it is still arriving."""
    cap = KN.MAX_BYTES
    n = request.headers.get("content-length")
    if n and n.isdigit() and int(n) > cap:
        raise HTTPException(413, f"larger than {cap // (1024 * 1024)} MB")
    buf = bytearray()
    async for part in request.stream():
        buf += part
        if len(buf) > cap:
            raise HTTPException(413, f"larger than {cap // (1024 * 1024)} MB")
    return bytes(buf)


@app.get("/api/knowledge")
def knowledge_list():
    return knowledge.list()


@app.post("/api/knowledge/preview")
async def knowledge_preview(request: Request, source: str, name: str):
    """What ingesting would do (redactions, chunks), without storing or embedding anything. Body: the file."""
    data = await _upload_body(request)
    return await run_in_threadpool(knowledge.preview, source, name, data)


@app.post("/api/knowledge/upload")
async def knowledge_upload(request: Request, source: str, name: str):
    """Stores the file under workspace/writeups/<source>/ and ingests it in the background. Body: the file."""
    data = await _upload_body(request)
    return await run_in_threadpool(knowledge.upload, source, name, data, _who(request))


class DocRef(BaseModel):
    doc: str = Field(min_length=1, max_length=400)


@app.post("/api/knowledge/delete")
def knowledge_delete(b: DocRef, request: Request):
    return knowledge.delete(b.doc, _who(request))


@app.post("/api/pipeline/stop")
def pipeline_stop():
    return pipeline.stop()


@app.get("/api/pipeline/status")
def pipeline_status():
    return pipeline.status()


@app.get("/api/pipeline/log")
def pipeline_log(start: int = 0):
    return pipeline.log(start)


@app.get("/api/pipeline/events")
def pipeline_events(start: int = 0):
    return pipeline.events_from(start)


# ------------------------------------------------------------------------- API: lab
@app.get("/api/lab/status")
def lab_status():
    return lab.status()


class LabLoad(BaseModel):
    run_id: str
    unload_ollama: bool = True


@app.post("/api/lab/load")
async def lab_load(b: LabLoad):
    if pipeline.running():
        raise HTTPException(409, "a pipeline stage is running; wait for it to finish")
    if b.unload_ollama:
        try:
            for m in ollama_get("/api/ps")["models"]:
                ollama_post("/api/generate", {"model": m["name"], "keep_alive": 0}, timeout=20)
        except Exception:
            pass
    return await run_in_threadpool(lab.load, run_dir_of(b.run_id))


@app.post("/api/lab/unload")
def lab_unload():
    return lab.unload()


from pydantic import Field  # noqa: E402


class Probe(BaseModel):
    prompt: str = Field(max_length=20000)


@app.post("/api/lab/probe")
async def lab_probe(p: Probe):
    try:
        return await run_in_threadpool(lab.probe, p.prompt)
    except RuntimeError as e:
        raise HTTPException(409, str(e))


class Try(BaseModel):
    layer: int
    prompts: list[str] = Field(max_length=16)
    max_new_tokens: int = 64


@app.post("/api/lab/try")
async def lab_try(t: Try):
    try:
        return await run_in_threadpool(lab.try_layer, t.layer, t.prompts[:8], min(t.max_new_tokens, 200))
    except RuntimeError as e:
        raise HTTPException(409, str(e))


# ------------------------------------------------------------------------- API: Ollama proxy (the browser never talks to Ollama directly)
@app.get("/api/ollama/tags")
def ollama_tags():
    try:
        return ollama_get("/api/tags")
    except Exception as e:
        raise HTTPException(502, f"Ollama not reachable at {OLLAMA}: {e}")


class ChatReq(BaseModel):
    model: str = Field(max_length=200)
    prompt: str = Field(max_length=20000)
    num_predict: int = 300


@app.post("/api/ollama/chat")
def ollama_chat_proxy(c: ChatReq):
    from fastapi.responses import StreamingResponse
    body = json.dumps({"model": c.model, "stream": True, "options": {"temperature": 0, "num_predict": min(max(c.num_predict, 16), 2048)},
                       "messages": [{"role": "user", "content": c.prompt}]}).encode()
    req = urllib.request.Request(f"{OLLAMA}/api/chat", data=body, headers={"Content-Type": "application/json"})
    try:
        upstream = urllib.request.urlopen(req, timeout=600)
    except Exception as e:
        raise HTTPException(502, f"Ollama error: {e}")

    def gen():
        with upstream:
            while True:
                chunk = upstream.read1(4096)     # whatever is available: tokens stream as they arrive
                if not chunk:
                    break
                yield chunk
    return StreamingResponse(gen(), media_type="application/x-ndjson")


@app.post("/api/ollama/unload")
def ollama_unload():
    done = []
    try:
        for m in ollama_get("/api/ps")["models"]:
            ollama_post("/api/generate", {"model": m["name"], "keep_alive": 0}, timeout=20)
            done.append(m["name"])
    except Exception:
        pass
    return {"unloaded": done}


# ------------------------------------------------------------------------- API: datasets
@app.get("/api/data")
def data_status():
    return datasets.status()


@app.get("/api/data/{fname}")
def data_rows(fname: str, q: str = "", offset: int = 0, limit: int = 50, source: str | None = None, regex: bool = False):
    if fname not in DATA_FILES:
        raise HTTPException(404, "unknown file")
    try:
        return datasets.search(fname, q, max(0, offset), min(max(1, limit), 500), source, regex)
    except re.error as e:
        raise HTTPException(400, f"bad regex: {e}")


class RowAdd(BaseModel):
    prompt: str | None = None
    source: str | None = None
    chosen: list | None = None
    rejected: list | None = None


@app.post("/api/data/{fname}/rows")
def data_add(fname: str, r: RowAdd):
    if fname not in DATA_FILES:
        raise HTTPException(404, "unknown file")
    body = {k: v for k, v in r.model_dump().items() if v is not None}
    if DATA_FILES[fname]["kind"] == "prompt" and not body.get("prompt"):
        raise HTTPException(400, "prompt required")
    return datasets.add(fname, body)


class RowEdit(BaseModel):
    prompt: str | None = None
    chosen: list | None = None
    rejected: list | None = None


@app.put("/api/data/{fname}/rows/{rid}")
def data_edit(fname: str, rid: str, r: RowEdit):
    try:
        return datasets.edit(fname, rid, {k: v for k, v in r.model_dump().items() if v is not None})
    except KeyError:
        raise HTTPException(404, "row not found")


class RowsRemove(BaseModel):
    ids: list[str]
    reason: str = ""


@app.post("/api/data/{fname}/remove")
def data_remove(fname: str, r: RowsRemove):
    if fname not in DATA_FILES:
        raise HTTPException(404, "unknown file")
    return datasets.remove(fname, r.ids, r.reason)


@app.get("/api/data/{fname}/removed")
def data_removed(fname: str):
    return datasets.removed_rows(fname)


class RowsRestore(BaseModel):
    ids: list[str]


@app.post("/api/data/{fname}/restore")
def data_restore(fname: str, r: RowsRestore):
    return datasets.restore(fname, r.ids)


# ------------------------------------------------------------------------- API: SBOM
@app.get("/api/sbom")
def sbom_status():
    return sbom.status()


@app.post("/api/sbom/generate")
def sbom_generate():
    return sbom.start()


@app.get("/api/sbom/file/{name}")
def sbom_file(name: str):
    if not re.fullmatch(r"(sbom|summary|vulnerabilities)-[\w\-]+\.(cdx\.)?json", name):
        raise HTTPException(400, "bad name")
    path = os.path.join(PROJECT, "sbom", name)
    if not os.path.isfile(path):
        raise HTTPException(404)
    return FileResponse(path, media_type="application/json", filename=name)


@app.on_event("startup")
def _startup():
    """Kubernetes: a Job that kept running while the console restarted is followed again."""
    if K8S:
        pipeline.attach()
        threading.Thread(target=control.snapshot, daemon=True).start()     # a copy of glm-serve-allow for Release
        threading.Thread(target=CR.ModelWatch(control, FEED).run, daemon=True).start()   # model state changes -> feed


@app.on_event("shutdown")
def _shutdown():
    """docker stop / pod termination: end the pipeline child cleanly instead of leaving it to SIGKILL.
    A Kubernetes Job is not a child: it keeps running and the next console re-attaches."""
    if pipeline.running() and getattr(pipeline, "proc", None):
        pipeline.proc.terminate()
        try:
            pipeline.proc.wait(timeout=30)
        except Exception:
            pipeline.proc.kill()


# ------------------------------------------------------------------------- static UI
STATIC = os.path.join(HERE, "static")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"), headers={"Cache-Control": "no-store"})


def main():
    global PROJECT, PY
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", default=PROJECT)
    ap.add_argument("--port", type=int, default=int(os.environ.get("ABL_PORT", "8787")))
    ap.add_argument("--host", default=os.environ.get("ABL_HOST", "127.0.0.1"), help="bind address; 0.0.0.0 only behind a reverse proxy with auth")
    ap.add_argument("--open", action="store_true", help="open the browser")
    a = ap.parse_args()
    PROJECT = os.path.abspath(a.project)
    os.makedirs(PROJECT, exist_ok=True)
    PY = PL.pipeline_python(PROJECT)
    lab.project = PROJECT
    datasets.dir = os.path.join(PROJECT, "data")
    sbom.project, sbom.dir = PROJECT, os.path.join(PROJECT, "sbom")
    # built at import time from ABL_PROJECT: without these, --project left engagement versions and uploads in the code folder
    engagements.dir = os.path.join(PROJECT, "engagement")
    knowledge.root = os.path.join(PROJECT, "writeups")
    import uvicorn
    print(f"Red Team LLM Lab: code {CODE}, project {PROJECT}, python {PY}, ollama {OLLAMA} -> http://{a.host}:{a.port}")
    if a.open:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://localhost:{a.port}")).start()
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
