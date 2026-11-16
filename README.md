# Abliteration Lab: GLM-family abliteration with a guided app

Abliteration (Arditi et al. 2024) measures the one residual-stream direction a chat model uses to decide "I am about to refuse"
and projects it out of the weights. This repository holds the original notebook, an architecture-aware pipeline for **every GLM
model** (GLM-Edge, GLM-4, GLM-4.xV, GLM-4.5/4.6 MoE, GLM-5 / 5.1 / 5.2 / 5.3 MoE+DSA, GLM-5-Next, legacy ChatGLM), and a local
web app that drives it with a step-by-step learning guide.

| Path | Purpose |
|---|---|
| `abliterate/` | The pipeline package. `arch.py` (family detection, which tensors write into the residual stream, post-norm / MoE / FP8 handling), `data.py` (prompt sets, refusal markers), `hooks.py` (plain PyTorch hooks on a HF model: measure, ablate, generate; works with `device_map=auto`), `edit.py` (shard-by-shard safetensors edit incl. per-expert / fused experts, biases, post-norm folding, FP8 block requantization), `validate.py` (six checks), `deploy.py` (GGUF, Ollama, A/B), `pipeline.py` (CLI, events). |
| `app/` | **Abliteration Lab** (FastAPI + vanilla JS): Abliterate (model download, Run, live guide with "under the hood" and "for GLM-5.x" notes per step), Lab (refusal meter per layer and token, try any layer live), A/B chat, System. |
| `abliteration_pipeline.ipynb` + `run_pipeline.py` | The original notebook (GLM-Edge only, TransformerLens) and its headless runner; kept as the reference implementation. Two fixes vs. the original: cell 1.1 accepts `CUDA UMD Version:`; cell 4.8 opens each safetensors file once. |
| `gui/` + `build_gui.py` | The earlier standalone walkthrough page built from a run folder. |

## Run the app

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip notebook ipywidgets
.\.venv\Scripts\python.exe run_pipeline.py setup                  # torch CUDA, packages, llama.cpp converter env
.\.venv\Scripts\python.exe -m pip install fastapi "uvicorn[standard]" -c constraints-torch.txt
start_app.bat                                                       # http://localhost:8787
```

In the app: pick a preset or paste a repo id → Download → Run. Options: pause at the layer choice, through Ollama, reload and validate,
device map `cuda` or `auto`. Each guide step shows what is happening, why it matters, what to look for, and expands to the math and the
GLM-5.x transfer notes.

## Run the pipeline headless

```powershell
.\.venv\Scripts\python.exe -m abliterate --model THUDM/glm-edge-4b-chat
.\.venv\Scripts\python.exe -m abliterate --model THUDM/glm-edge-4b-chat --pause-at-choice
.\.venv\Scripts\python.exe -m abliterate --run-dir runs\abliterate_<ts> --stage continue --layer 17
.\.venv\Scripts\python.exe -m abliterate --model zai-org/GLM-5.2 --device-map auto --skip-verify --no-ollama
```

Artifacts per run (`runs/abliterate_<ts>/`): `run.json`, `events.jsonl`, `arch.json`, `layer_analysis.json`, `baseline.json`,
`scan_results.json`, `apply.json`, `generations.json`, `validation.json`, `ollama_ab.json`, `refusal_dirs.pt`, `means.pt`.
Models: `models/<slug>/` (base copy), `out/<slug>-abliterated/`, `gguf/<slug>-{base,abl}-f16.gguf`, Ollama `<slug>-base` / `<slug>-abl`.

## What transfers to GLM-5.2 / 5.3

Verified on this machine: GLM-Edge-4B end to end (layer 16/17, 15/16 → 1/16 refusals, validation PASS, Ollama A/B 9/10 → 0/10),
and the sharded edit on a synthetic checkpoint with per-expert, fused-3D-expert, FP8 block-scaled and post-norm tensors.
GLM-5.2 (`GlmMoeDsaForCausalLM`, 78 layers, 3 dense + 75 MoE layers with 256 routed + 1 shared experts, bf16, 1.5 TB in 282 shards)
is covered by the same code paths: measurement and scan need the model loaded (`--device-map auto` on a multi-GPU node), the edit streams
shard by shard on any machine with the disk space, the DSA indexer is left untouched. Not run on real GLM-5 weights here (no hardware).

Outputs (ignored by git): `models/`, `out/`, `gguf/`, `runs/`, `data/`, `.venv*`, `llama.cpp/`.
