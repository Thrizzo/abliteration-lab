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
import urllib.request
import webbrowser
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import rundata  # noqa: E402
from lab import Lab  # noqa: E402
from datasets import Datasets, FILES as DATA_FILES  # noqa: E402
from sbom import SbomJob  # noqa: E402
from abliterate import arch as ARCH  # noqa: E402
from abliterate import platform as PL  # noqa: E402

CODE = os.path.dirname(HERE)                                    # where abliterate/, run_pipeline.py live
PROJECT = os.path.abspath(os.environ.get("ABL_PROJECT") or CODE)   # where models/, runs/, data/ live
OLLAMA = PL.ollama_host()
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
    {"repo": "zai-org/GLM-5.2", "family": "GLM-5.2 MoE + DSA", "size": "744B · 1.5 TB bf16", "local_ok": False, "note": "the target: 78 layers, 256 experts, DSA indexer untouched; cluster only"},
    {"repo": "zai-org/GLM-5.3", "family": "GLM-5.3 MoE + DSA", "size": "744B", "local_ok": False, "note": "same architecture as 5.2"},
]

RUN_ID = re.compile(r"\d{8}_\d{6}")


def run_dir_of(run_id):
    if not run_id or not RUN_ID.fullmatch(run_id):
        raise HTTPException(400, "bad run_id")
    return os.path.join("runs", f"abliterate_{run_id}")


app = FastAPI(title="Red Team LLM Lab")
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


pipeline = Pipeline()
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
            "ollama": oll, "notebook_stages": NOTEBOOK_STAGES, "settings": rundata.load(p("abliteration_settings.json"), {})}


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
    if s.engine == "notebook":
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
    for flag, on in (("--pause-at-choice", s.pause_at_choice), ("--no-ollama", s.no_ollama), ("--skip-verify", s.skip_verify), ("--trust-remote-code", s.trust_remote_code)):
        if on:
            cmd.append(flag)
    return pipeline.start(cmd, "abliterate", s.stage, run_dir)


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


@app.on_event("shutdown")
def _shutdown():
    """docker stop / pod termination: end the pipeline child cleanly instead of leaving it to SIGKILL."""
    if pipeline.running():
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
    import uvicorn
    print(f"Red Team LLM Lab: code {CODE}, project {PROJECT}, python {PY}, ollama {OLLAMA} -> http://{a.host}:{a.port}")
    if a.open:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://localhost:{a.port}")).start()
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
