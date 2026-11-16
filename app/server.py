r"""Abliteration Lab - local app server.

    .\.venv\Scripts\python.exe -m app                       (from the project folder)
    .\.venv\Scripts\python.exe app\server.py --project C:\path\to\Abliteration --port 8787

Serves the UI, lists runs, drives run_pipeline.py as a subprocess with a live log, writes the layer choice,
hosts the lab (model-resident probing / try-a-layer) and a few Ollama helpers."""
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
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rundata  # noqa: E402
from lab import Lab  # noqa: E402

PROJECT = os.environ.get("ABL_PROJECT") or os.path.dirname(HERE)
OLLAMA = "http://localhost:11434"
STAGES = {"setup": "1 · setup (torch, packages, llama.cpp)", "data": "3 · dataset audit + local copies",
          "abl": "4 · measure, scan, choose, apply, validate", "apply": "4.6-4.8 · apply the chosen layer + validate",
          "validate": "4.8 · validate the saved model", "ollama": "7 · GGUF, Ollama import, A/B test",
          "main": "2-4 + 7 · the whole pipeline"}

app = FastAPI(title="Abliteration Lab")
lab = Lab(PROJECT)


# ------------------------------------------------------------------------- pipeline subprocess
class Pipeline:
    def __init__(self):
        self.proc = None
        self.lines = []
        self.stage = None
        self.started = None
        self.exit_code = None
        self.log_path = None
        self.lock = threading.Lock()

    def start(self, stage, run_dir=None, layer=None):
        if self.proc and self.proc.poll() is None:
            raise HTTPException(409, f"stage '{self.stage}' is still running")
        if stage not in STAGES:
            raise HTTPException(400, f"unknown stage {stage}")
        if lab.bridge is not None and stage in ("abl", "apply", "validate", "main"):
            lab.unload()
        if layer is not None:
            save_layer(layer, run_dir)
        py = os.path.join(PROJECT, ".venv", "Scripts", "python.exe")
        cmd = [py, "-u", os.path.join(PROJECT, "run_pipeline.py"), stage]
        if run_dir:
            cmd += ["--run-dir", run_dir]
        os.makedirs(os.path.join(PROJECT, "runs"), exist_ok=True)
        self.log_path = os.path.join(PROJECT, "runs", f"app_{stage}_{datetime.now():%Y%m%d_%H%M%S}.log")
        env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "MPLBACKEND": "Agg", "HF_HUB_DISABLE_PROGRESS_BARS": "1"}
        self.lines, self.stage, self.started, self.exit_code = [], stage, time.time(), None
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
                    self.lines.append(line)
        self.exit_code = self.proc.wait()
        with self.lock:
            self.lines.append(f"[app] process exited with code {self.exit_code}")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
        return self.status()

    def status(self):
        running = bool(self.proc) and self.proc.poll() is None
        cells = [l for l in self.lines if l.startswith("[runner] cell ") and ":" in l]
        return {"running": running, "stage": self.stage, "stage_label": STAGES.get(self.stage), "started": self.started,
                "elapsed_s": round(time.time() - self.started) if self.started and running else None,
                "exit_code": self.exit_code, "log_path": self.log_path, "n_lines": len(self.lines),
                "current_cell": cells[-1][len("[runner] "):] if cells else None}

    def log(self, start):
        with self.lock:
            return {"lines": self.lines[start:], "next": len(self.lines), "running": bool(self.proc) and self.proc.poll() is None}


pipeline = Pipeline()


def save_layer(layer, run_dir=None):
    """Same file and schema as the notebook's 4.5 cell."""
    info = {"layer_to_abliterate": int(layer), "model": "models/glm-edge-4b-chat",
            "saved": datetime.now().isoformat(timespec="seconds"), "source": "app", "run_dir": run_dir}
    scan = rundata.load(os.path.join(PROJECT, run_dir, "scan_results.json")) if run_dir else None
    if scan:
        s = next((x for x in scan if x["layer"] == int(layer)), None)
        info["refusals_in_scan"] = s["refusals"] if s else None
        info["test_prompts"] = len(s["generations"]) if s else None
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


def gpu_info():
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=name,memory.used,memory.total,utilization.gpu", "--format=csv,noheader,nounits"],
                             capture_output=True, text=True, timeout=10).stdout.strip().split(", ")
        return {"name": out[0], "vram_used_gb": round(int(out[1]) / 1024, 1), "vram_total_gb": round(int(out[2]) / 1024, 1), "util": int(out[3])}
    except Exception:
        return None


# ------------------------------------------------------------------------- API
@app.get("/api/env")
def env():
    p = lambda *a: os.path.join(PROJECT, *a)
    disk = shutil.disk_usage(PROJECT)
    try:
        models = [m["name"] for m in ollama_get("/api/tags")["models"]]
        loaded = [{"name": m["name"], "vram_gb": round(m.get("size_vram", 0) / 1e9, 1)} for m in ollama_get("/api/ps")["models"]]
        oll = {"reachable": True, "models": models, "loaded": loaded,
               "base": "glm-edge-base:latest" in models, "abl": "glm-edge-abl:latest" in models}
    except Exception as e:
        oll = {"reachable": False, "error": str(e), "models": [], "loaded": []}
    return {
        "project": PROJECT, "gpu": gpu_info(), "disk_free_gb": round(disk.free / 1e9, 1),
        "venv": os.path.isfile(p(".venv", "Scripts", "python.exe")), "venv_gguf": os.path.isfile(p(".venv-gguf", "Scripts", "python.exe")),
        "base_model": os.path.isfile(p("models", "glm-edge-4b-chat", "config.json")),
        "abl_model": os.path.isfile(p("glm-edge-4b-chat-abliterated", "config.json")),
        "gguf_base": os.path.isfile(p("glm-edge-4b-base-f16.gguf")), "gguf_abl": os.path.isfile(p("glm-edge-4b-abliterated-f16.gguf")),
        "data": os.path.isfile(p("data", "harmful_test.jsonl")), "ollama": oll, "stages": STAGES,
        "settings": rundata.load(p("abliteration_settings.json"), {}),
    }


@app.get("/api/runs")
def runs():
    return rundata.list_runs(PROJECT)


@app.get("/api/runs/{rid}")
def run(rid):
    d = os.path.join(PROJECT, "runs", f"abliterate_{rid}")
    if not os.path.isdir(d):
        raise HTTPException(404, "run not found")
    return rundata.collect(PROJECT, d)


class Choice(BaseModel):
    layer: int


@app.post("/api/runs/{rid}/choose")
def choose(rid, c: Choice):
    return save_layer(c.layer, os.path.join("runs", f"abliterate_{rid}"))


class Start(BaseModel):
    stage: str
    run_id: str | None = None
    layer: int | None = None


@app.post("/api/pipeline/start")
def pipeline_start(s: Start):
    run_dir = os.path.join("runs", f"abliterate_{s.run_id}") if s.run_id else None
    if s.stage in ("apply", "validate") and not run_dir:
        raise HTTPException(400, "apply/validate need a run_id")
    return pipeline.start(s.stage, run_dir, s.layer)


@app.post("/api/pipeline/stop")
def pipeline_stop():
    return pipeline.stop()


@app.get("/api/pipeline/status")
def pipeline_status():
    return pipeline.status()


@app.get("/api/pipeline/log")
def pipeline_log(start: int = 0):
    return pipeline.log(start)


@app.get("/api/lab/status")
def lab_status():
    return lab.status()


class LabLoad(BaseModel):
    run_id: str
    unload_ollama: bool = True


@app.post("/api/lab/load")
async def lab_load(b: LabLoad):
    if pipeline.status()["running"]:
        raise HTTPException(409, "a pipeline stage is running; wait for it to finish")
    if b.unload_ollama:
        for m in ("glm-edge-base", "glm-edge-abl"):
            try:
                ollama_post("/api/generate", {"model": m, "keep_alive": 0}, timeout=20)
            except Exception:
                pass
    return await run_in_threadpool(lab.load, os.path.join("runs", f"abliterate_{b.run_id}"))


@app.post("/api/lab/unload")
def lab_unload():
    return lab.unload()


class Probe(BaseModel):
    prompt: str


@app.post("/api/lab/probe")
async def lab_probe(p: Probe):
    try:
        return await run_in_threadpool(lab.probe, p.prompt)
    except RuntimeError as e:
        raise HTTPException(409, str(e))


class Try(BaseModel):
    layer: int
    prompts: list[str]
    max_new_tokens: int = 64


@app.post("/api/lab/try")
async def lab_try(t: Try):
    try:
        return await run_in_threadpool(lab.try_layer, t.layer, t.prompts[:8], min(t.max_new_tokens, 200))
    except RuntimeError as e:
        raise HTTPException(409, str(e))


@app.post("/api/ollama/unload")
def ollama_unload():
    done = []
    for m in ("glm-edge-base", "glm-edge-abl"):
        try:
            ollama_post("/api/generate", {"model": m, "keep_alive": 0}, timeout=20)
            done.append(m)
        except Exception:
            pass
    return {"unloaded": done}


@app.get("/api/runs/{rid}/file/{name}")
def run_file(rid, name):
    if not re.fullmatch(r"[\w.\-]+\.(png|json|log)", name):
        raise HTTPException(400, "bad name")
    path = os.path.join(PROJECT, "runs", f"abliterate_{rid}", name)
    if not os.path.isfile(path):
        raise HTTPException(404)
    return FileResponse(path)


# ------------------------------------------------------------------------- static UI
STATIC = os.path.join(HERE, "static")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"), headers={"Cache-Control": "no-store"})


def main():
    global PROJECT
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", default=PROJECT)
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--open", action="store_true", help="open the browser")
    a = ap.parse_args()
    PROJECT = os.path.abspath(a.project)
    lab.project = PROJECT
    if not os.path.isfile(os.path.join(PROJECT, "abliteration_pipeline.ipynb")):
        raise SystemExit(f"{PROJECT} has no abliteration_pipeline.ipynb - pass --project")
    import uvicorn
    print(f"Abliteration Lab: project {PROJECT} -> http://localhost:{a.port}")
    if a.open:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://localhost:{a.port}")).start()
    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
