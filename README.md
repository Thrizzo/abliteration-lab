# Abliteration Lab: GLM-family abliteration with a guided app

Abliteration (Arditi et al. 2024) measures the one residual-stream direction a chat model uses to decide "I am about to refuse"
and projects it out of the weights. This repository holds the original notebook, an architecture-aware pipeline for **every GLM
model** (GLM-Edge, GLM-4, GLM-4.xV, GLM-4.5/4.6 MoE, GLM-5 / 5.1 / 5.2 / 5.3 MoE+DSA, GLM-5-Next, legacy ChatGLM), and a local
web app that drives it with a step-by-step learning guide.

| Path | Purpose |
|---|---|
| `abliterate/` | The pipeline package. `arch.py` (family detection, which tensors write into the residual stream, post-norm / MoE / FP8 handling), `data.py` (prompt sets, refusal markers), `hooks.py` (plain PyTorch hooks on a HF model: measure, ablate, generate; works with `device_map=auto`), `edit.py` (shard-by-shard safetensors edit incl. per-expert / fused experts, biases, post-norm folding, FP8 block requantization), `validate.py` (six checks), `deploy.py` (GGUF, Ollama, A/B), `pipeline.py` (CLI, events). |
| `app/` | **Abliteration Lab** (FastAPI + vanilla JS), one linear flow: **1 Model** (GLM presets or any repo id, downloaded on run) → **2 Abliterate** (one click, live step guide with plain / why / what-to-look-for text, "under the hood" and "for GLM-5.x" notes, optional pause at the layer choice) → **3 Compare** (before/after chat in Ollama; an expandable lab with the per-layer refusal meter and try-a-layer). Header tools: **datasets** (view / search / add / edit / remove rows of the harmful, harmless and DPO sets with an audit trail under `data/removed/` and `data/edits.jsonl`), **SBOM** (CycloneDX 1.5 of `.venv` + `.venv-gguf` with PyPI/OSV advisories, the project's own modules and their imports, Ollama, llama.cpp, driver, models, datasets), **log**. |
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

In the app: pick a model → Run (downloads if needed) → Compare. Options: pause at the layer choice, finish in Ollama, reload and validate,
device `cuda` or `auto`. Each guide step shows what is happening, why it matters, what to look for, and expands to the math and the
GLM-5.x transfer notes.

## Run it in Docker (Linux, Docker Desktop, Rancher Desktop)

Published image: `ghcr.io/thrizzo/abliteration-lab:latest` (built by `.github/workflows/docker-image.yml`); `docker compose pull app`
skips the local build. For Rancher Desktop with the containerd backend: `docker save ghcr.io/thrizzo/abliteration-lab:latest | nerdctl load`.

The image holds the pipeline, the app and the GGUF converter environment; models and runs live on a volume at `/workspace`.
Ollama runs as its own container and the app talks to it over the API (`OLLAMA_HOST`), so no Ollama CLI is needed in the image.
The host needs an NVIDIA driver and the NVIDIA container toolkit (Docker Desktop on Windows: WSL2 + a current driver, nothing else).

```bash
cp deploy/.env.example deploy/.env         # set WORKSPACE and CADDY_HASH (docker run --rm caddy:2 caddy hash-password --plaintext 'secret')
mkdir -p workspace                          # or whatever WORKSPACE points to
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.gpu.yml --env-file deploy/.env up -d --build
```

Open http://localhost:8080 (Caddy, basic auth; `BIND_ADDR=127.0.0.1` by default, use an SSH tunnel or VPN from other machines, or set up TLS
in the Caddyfile before opening it to a network). Leave the `docker-compose.gpu.yml` file out on hosts without GPU passthrough
(Rancher Desktop on Windows): the UI, datasets, SBOM and Compare work, measure/scan do not. Headless pipeline runs use the same image:

```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.gpu.yml --env-file deploy/.env run --rm app --model THUDM/glm-edge-4b-chat
```

The container starts as root only to hand the mounted workspace to its unprivileged user (uid 1000) and drops privileges at once;
on Kubernetes the pod runs as uid 1000 with `fsGroup: 1000` instead.

Environment knobs (all optional): `ABL_PROJECT` (workspace, default `/workspace`), `OLLAMA_HOST`, `ABL_HOST`/`ABL_PORT`, `ABL_GGUF_PY`, `ABL_LLAMA_CPP`, `HF_TOKEN`.
The same variables let the plain Windows/Linux install point at other locations (`abliterate/platform.py`).

**Rancher Desktop.** With the *moby* (dockerd) backend the compose files work as is (`docker compose`). With the *containerd* backend use
`nerdctl compose -f deploy/docker-compose.yml up -d --build` (or `nerdctl load` the published image). GPU passthrough into Rancher Desktop containers on Windows is not supported by
Rancher Desktop itself (it is on Docker Desktop); on a Linux host install the NVIDIA container toolkit and it works with either backend.

**Rancher / Kubernetes.** `deploy/k8s/abliteration.yaml` is a single-pod deployment (app + Ollama sharing the workspace), a PVC for the
workspace, a Service and an ingress-nginx Ingress with basic auth. Push the image to a registry the cluster can pull from, install the
NVIDIA device plugin (enable time-slicing if a node has one GPU, because both containers request `nvidia.com/gpu`), create the
`basic-auth` secret, set the host name, then `kubectl apply -f deploy/k8s/abliteration.yaml`.

Security: the app has no login of its own and can run subprocesses, edit datasets and write models. Only expose it through the proxy
(or an ingress) with authentication, never bind `0.0.0.0` on an open network.

## Run the pipeline headless

```powershell
.\.venv\Scripts\python.exe -m abliterate --model THUDM/glm-edge-4b-chat
.\.venv\Scripts\python.exe -m abliterate --model THUDM/glm-edge-4b-chat --pause-at-choice
.\.venv\Scripts\python.exe -m abliterate --run-dir runs\abliterate_<ts> --stage continue --layer 17
.\.venv\Scripts\python.exe -m abliterate --model zai-org/GLM-5.2 --device-map auto --skip-verify --no-ollama
```

Artifacts per run (`runs/abliterate_<ts>/`): `run.json`, `events.jsonl`, `arch.json`, `layer_analysis.json`, `baseline.json`,
`scan_results.json`, `apply.json`, `generations.json`, `validation.json`, `ollama_ab.json`, `refusal_dirs.pt`, `means.pt`.
Models: `models/<slug>/` (base copy), `out/<slug>-abliterated/`, `gguf/<slug>-{base,abl}-<type>.gguf`, Ollama `<slug>-base` / `<slug>-abl`.
`--quantize q8_0` (default), `f16` or `bf16` are written directly by the llama.cpp converter and imported as is; other quant types
(`q4_K_M` …) need Ollama's create-time quantization of an f16 file, which Ollama dropped in 0.40, so prefer the direct types.

## What transfers to GLM-5.2 / 5.3

Verified on this machine: GLM-Edge-4B (layer 16/17, 15/16 → 1/16 refusals, validation PASS, Ollama A/B 9/10 → 0/10) and GLM-Edge-1.5B
(layer 12, validation PASS, Ollama A/B 6/10 → 0/10) end to end,
and the sharded edit on a synthetic checkpoint with per-expert, fused-3D-expert, FP8 block-scaled and post-norm tensors.
GLM-5.2 (`GlmMoeDsaForCausalLM`, 78 layers, 3 dense + 75 MoE layers with 256 routed + 1 shared experts, bf16, 1.5 TB in 282 shards)
is covered by the same code paths: measurement and scan need the model loaded (`--device-map auto` on a multi-GPU node), the edit streams
shard by shard on any machine with the disk space, the DSA indexer is left untouched. Not run on real GLM-5 weights here (no hardware).

Outputs (ignored by git): `models/`, `out/`, `gguf/`, `runs/`, `data/`, `.venv*`, `llama.cpp/`.
