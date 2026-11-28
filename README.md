# Red Team LLM Lab

Abliteration of GLM chat models, plus a pentest-lab copilot in n8n that runs the abliterated model behind a
deterministic policy gate and a regular judge model.

Remove the refusal behaviour from GLM chat models, watch how it is done layer by layer, and compare the model before and
after. Built as a learning tool and as a proof of concept for the whole GLM family, from GLM-Edge-1.5B on a single
consumer GPU up to the GLM-5.x mixture-of-experts models on a cluster.

> **Use responsibly.** An abliterated model answers requests the original would refuse. Keep it local, do not publish the
> weights, and do not give it tool access without guardrails. The harmful prompts used for measurement come from a public
> research dataset (AdvBench) and are shown in the app.

---

## 1. What abliteration is

A chat model is trained to refuse harmful requests. Arditi et al. (2024, *Refusal in Language Models Is Mediated by a Single
Direction*) showed that this behaviour is surprisingly simple inside the network: at the moment the model decides how to
begin its answer, "I am about to refuse" is a **single direction** in its internal state. Harmful prompts push the state along
that direction; harmless prompts do not.

A transformer processes text as a stream of vectors (the *residual stream*, 3,072 numbers per token in GLM-Edge-4B, 6,144
in GLM-5.2) that every layer reads and adds to. Abliteration works on that stream:

1. **Measure.** Run a few hundred harmful and harmless prompts. At the last prompt token, average each layer's input vector
   per group and subtract: `r_L = normalize(mean_harmful − mean_harmless)`. One candidate direction per layer.
2. **Scan.** For each candidate, subtract its component from the residual stream at every layer while the model answers
   held-out harmful prompts (`x ← x − (x·r) r`, a temporary hook) and count refusals. Good layers drop refusals to zero
   while the answers stay coherent and in the original language.
3. **Choose.** The rule: fewest refusals, then the lowest share of Chinese characters (a sign of damage), then the earliest
   layer. You can override it (`--layer`, or "pause at the layer choice" in the app) after reading the answers.
4. **Apply.** Make it permanent by editing every weight matrix that *writes into* the residual stream so it can no longer
   produce `r`: the token embedding, every attention output projection and every MLP output projection, including each
   expert of a mixture-of-experts layer: `W′ = W − r rᵀ W`. Nothing else changes.
5. **Validate.** Reload both models from disk and run six checks: the original refuses (a warning if it barely does), the
   edited one refuses at most a quarter of the held-out prompts, harmless prompts are not refused more than before, the
   next-token distribution on harmless prompts barely moved (KL below 0.5 passes, above 2 fails), only the intended tensors
   differ, and the direction is gone from the saved weights (max |r·W′| below 0.05, typically 1e-3).

**Several directions.** Sometimes one layer's direction leaves a few refusals that another layer's direction catches.
`--layers 15,17,19` (or `--layers "15 17 19"`; ranges such as `15-19` work too) removes the directions of all of them at once. They are not parallel,
so the edit removes the subspace they span: a QR decomposition turns them into an orthonormal basis Q, and every writer
becomes `W′ = W − Q (Qᵀ W)`. Removing them one after the other would not do it: each step would put back part of the
directions removed before. `--combine 3` makes the scan also test the best 2 and the best 3 layers together (one more
generation pass each, saved in `scan.json`); the rule then recommends a combination only if it leaves strictly fewer
refusals than the best single layer and its answers are not mostly Chinese. In the app: "combine the best … layers" under
Advanced, and "combine with" next to the layer when the run pauses at the layer choice. The risk: every removed direction
takes more out of the residual stream, so harmless answers move too. Validate measures that as the KL on harmless
prompts, and checks max |Qᵀ·W′| instead of max |r·W′|. Take as few layers as needed; one layer is exactly the edit above.

Why it is interesting beyond "uncensoring": it is a clean, reproducible example of mechanistic interpretability. A behaviour
that looks like it would need fine-tuning turns out to be one vector, measurable in minutes and removable with linear
algebra, and the same procedure transfers unchanged from a 1.5B dense model to a 744B mixture-of-experts model.

---

## 2. What is in this repository

| Path | What it is |
|---|---|
| `abliterate/` | The pipeline for every GLM family: `arch.py` detects the block structure and which tensors write into the residual stream (post-norm blocks, MoE experts, FP8 block scales), `hooks.py` measures and ablates with plain PyTorch hooks (works with `device_map=auto` and on the CPU), `edit.py` edits safetensors shard by shard without loading the model, `validate.py` runs the six checks, `deploy.py` converts to GGUF and imports into Ollama over its HTTP API, `pipeline.py` is the CLI and writes `events.jsonl` for the app. |
| `app/` | **The abliteration app**, a local web app (FastAPI, vanilla JS). One flow: **Model → Abliterate → Compare** (a console connected to n8n adds a fourth step, **Pentest**: the copilot; the Kubernetes console always is), plus header panels for the **datasets** (view, search, edit, remove rows with an audit trail), the **SBOM** (CycloneDX of both Python environments, advisories, the project's own modules, Ollama, llama.cpp, driver, models, datasets) and the process **log**. |
| `deploy/` | `Dockerfile`, `docker-compose.yml` (+ `docker-compose.gpu.yml`), `Caddyfile` (basic auth), `.env.example`, `k8s/abliteration.yaml`. |
| `deploy/n8n/` | **Pentest lab copilot** in n8n: the abliterated model only suggests a command, a deterministic policy gate (scope, denylist, injection aimed at the judge) and a regular judge model decide, read-only recon auto-runs, everything else waits for a human. Retrieval over your writeups via Qdrant. See [deploy/n8n/README.md](deploy/n8n/README.md). |
| `copilot/` | Writeup tooling for the copilot: scrubbed ingestion into Qdrant (RAG), QLoRA training pairs and a trainer that only touches read-side matrices (the abliteration cannot be undone through the adapter), and an eval harness. See [copilot/README.md](copilot/README.md). |
| `.github/workflows/docker-image.yml` | Builds and publishes `ghcr.io/thrizzo/redteam-llm-lab`. |
| `abliteration_pipeline.ipynb`, `run_pipeline.py` | The original notebook (GLM-Edge only, TransformerLens) and its headless runner, kept as the reference implementation. Windows only. |
| `gui/`, `build_gui.py` | A standalone single-file walkthrough page built from a run folder. |

Supported models (`arch.py`): GLM-Edge (`glm`), GLM-4 0414 / glm-4-9b-chat-hf (`glm4`, post-norm block: the direction is folded
through the norm weight), GLM-4.1V / 4.5V / 4.6V text decoders, GLM-4.5 / 4.6 MoE (`glm4_moe`, `glm4_moe_lite`), GLM-5 / 5.1 /
5.2 / 5.3 (`glm_moe_dsa`, MoE + sparse attention; the DSA indexer is left untouched), GLM-5.3-Flash (`glm5_next`: hybrid
linear + sparse attention, MoE, four residual streams per token; see section 6). Legacy ChatGLM checkpoints (remote code:
ChatGLM2/3, glm-4-9b-chat) are recognised but refused: their code does not load with transformers 5 (it reads
`config.max_length`, which transformers 5 drops), so use `glm-4-9b-chat-hf`. Checkpoints may be bf16, fp16/fp32 or FP8 block-scaled (the blocks of `weight_block_size`, 128 × 128,
a last partial block included; a scale in another shard than its weight stays in the shard the index names). The vision models (GLM-4.xV, GLM-5.3-Flash)
load through `AutoModelForImageTextToText`; only their text decoder is measured and edited.

Verified end to end on an RTX 5080 (16 GB): GLM-Edge-4B (layer 16, 15/16 → 1/16 refusals, validation PASS, Ollama A/B
9/10 → 0/10) and GLM-Edge-1.5B (layer 12, PASS, 6/10 → 0/10), natively and inside the Docker stack. Without a GPU the
1.5B run gives the same result on the CPU (float32, layer 12, 9/16 → 0/16 refusals, validation PASS); the GGUF / Ollama
stage was not part of that CPU run. The sharded edit was also tested on a synthetic checkpoint with per-expert,
fused-expert, FP8 and post-norm tensors. GLM-5.x has not been run on real weights (no hardware here); its tensor layout was
read from the model repository. For GLM-5.3-Flash a tiny random model of its architecture (transformers' own implementation,
`abliterate/tests/test_glm5_next.py`) shows that the edit stays exact across the four residual streams: the edited model's
logits equal the unedited model's with the direction projected out of every stream.

---

## 3. Deploy with Docker (recommended)

**Requirements.** Docker Desktop (Windows/macOS) or Docker Engine on Linux; for GPU use an NVIDIA driver and, on Linux, the
NVIDIA Container Toolkit. Docker Desktop on Windows needs its WSL 2 backend, a current WSL (`wsl --update`) and a current
NVIDIA driver; Rancher Desktop gives containers no GPU on Windows ([below](#rancher-desktop)). No GPU, or a runtime that cannot
hand it to containers: the stack runs on the CPU, see [Without a GPU](#without-a-gpu). Disk: about 15 GB for the image and
20 GB with the other images; per 4B model about 25 GB in the workspace (base copy, edited copy, two GGUFs) plus the two GGUFs
again (8 to 9 GB) in Ollama's volume, and each further run of it one more GGUF (about 4 GB); step 4 adds about 6 GB (n8n,
Qdrant, the judge and the embedding model). Hundreds of GB for the large models.

Every command below runs in the repository's folder, in PowerShell as in bash:

```bash
git clone https://github.com/Thrizzo/redteam-llm-lab.git
cd redteam-llm-lab
cp deploy/.env.example deploy/.env
mkdir workspace
```

`cp` only the first time: it overwrites an existing `deploy/.env`. `WORKSPACE=../workspace` in `.env` is resolved from
`deploy/`, so it is the `workspace` folder just created. On Windows a folder outside *Documents* and OneDrive is faster and is
not uploaded: `WORKSPACE=D:/redteam-workspace`, with forward slashes and without double quotes (inside double quotes compose
turns `\r`, `\n`, `\t` of a path into control characters).

Set `CADDY_HASH` in `deploy/.env` to the hash this prints (it asks for the password twice), in single quotes:

```bash
docker run --rm -it caddy:2 caddy hash-password
```

`COMPOSE_FILE` in `deploy/.env` lists the compose files every command uses: the stack plus `docker-compose.gpu.yml` (NVIDIA
GPU). Without a GPU remove the second one there; step 4 adds a third ([Step 4](#step-4-the-pentest-copilot)). One list for
every command: a command that left a file out would recreate the containers without the GPU or step 4.

**Windows with Rancher Desktop installed too:** the GPU needs Docker Desktop's engine. The two cannot run at the same time
(quit one before starting the other), and the docker command must reach Docker Desktop: `docker context show` prints
`desktop-linux`. After `deploy/k8s/tests/rancher-dev.ps1`, which works with Rancher Desktop's engine, switch back with
`docker context use desktop-linux`.

Build the image and start the stack:

```bash
docker compose --env-file deploy/.env up -d --build
```

The first build takes about 15 minutes (the torch CUDA wheels alone are several GB); `ollama/ollama` and `caddy` are pulled.
Then check that the app sees the GPU (`True` and its name):

```bash
docker compose --env-file deploy/.env exec app python -c "import torch; print(torch.cuda.is_available(), torch.cuda.get_device_name(0) if torch.cuda.is_available() else '')"
```

Open **http://localhost:8080** and log in with the user and password from `.env`. The first run of a model downloads it from
Hugging Face into `workspace/models/`.

**Update** after `git pull`: the same `up -d --build`. The code is part of the image: without `--build` the stack keeps
running the old one. Only the layers from the code on are rebuilt, a minute or two unless `deploy/requirements.txt`
changed. The app restarts, which stops a running pipeline stage, so let it finish first. `docker compose --env-file
deploy/.env pull ollama caddy` (plus `n8n qdrant` with step 4) updates the other images. Stop the stack with `docker compose
--env-file deploy/.env stop` (or `down`); never `down -v`, which deletes Ollama's models, n8n's data and the Qdrant index.

**The published image** `ghcr.io/thrizzo/redteam-llm-lab:latest` is built from `main`: `docker compose --env-file
deploy/.env pull app` fetches it instead of a build, and replaces a local build of the same name, so a checkout of another
branch then runs `main`'s code. If the pull fails with `unauthorized`, the package does not exist yet or is private. Its
visibility is separate from the repository's: making the repository public does not make an already published package
public. The owner can open it up once on the package's page under *Package settings* → *Danger Zone* → *Change visibility*.
Otherwise log in first with a personal access token (classic) that has the `read:packages` scope: `docker login ghcr.io -u
<github user>` and paste the token at the password prompt (piping a literal token in with `echo` can leave it in the shell
history). Or build, as above.

What the stack does:

- **app**: the pipeline and the web app, reachable only through Caddy. Starts as root just long enough to hand the mounted
  workspace to its unprivileged user (uid 1000; on a Linux host, a folder that belongs to a user gives the app that user's
  uid instead, so the files stay theirs), then drops privileges.
- **ollama**: serves the base and abliterated models for the Compare stage; the app uploads GGUFs through Ollama's API, so no
  files need to be shared.
- **caddy**: basic auth on port 8080. `BIND_ADDR=127.0.0.1` (default) keeps it on this machine; use an SSH tunnel or VPN
  from elsewhere. If you open it to a network, give Caddy a hostname and publish 80/443 so it gets a TLS certificate (see
  the comments in `Caddyfile` and `docker-compose.yml`): basic auth over plain HTTP sends the password in the clear.

**How the models reach Ollama.** Nothing is shared with the Ollama container; `abliterate/deploy.py` talks to its HTTP API over the
compose network: the converter writes `gguf/<model>-{base,abl}-q8_0.gguf` into the workspace, the app hashes each file, checks
`HEAD /api/blobs/sha256:<digest>`, uploads it with `POST /api/blobs/...` if unknown (about 80 s for 3 GB), then calls
`POST /api/create` with the blob, the GLM chat template, stop tokens and temperature 0. Ollama stores the result as
`<model>-base` and `<model>-abl` in its own volume. Ollama 0.40+ no longer quantizes GGUF imports at create time, which is why
the converter writes q8_0 directly. The Compare stage streams through the app's `/api/ollama/chat` proxy, so the browser
never needs to reach Ollama.

Headless runs use the same image:

```bash
docker compose --env-file deploy/.env run --rm app --model THUDM/glm-edge-4b-chat
docker compose --env-file deploy/.env run --rm app --model zai-org/GLM-5.2 --device-map auto --skip-verify --no-ollama
```

`deploy/.env` knobs for the compose stack: `COMPOSE_FILE`, `WORKSPACE`, `OLLAMA_STORE`, `CADDY_USER`, `CADDY_HASH`,
`BIND_ADDR`, `HTTP_PORT`, `HF_TOKEN` (gated repos; passed to the pipeline through the environment, never written to run
files), `TORCH_FLAVOR` (the image's PyTorch build: `cu126` for GPUs older than Turing, see [Without a GPU](#without-a-gpu)),
and for step 4 `N8N_ENCRYPTION_KEY`, `N8N_PORT`, `COPILOT_OPERATOR_MODEL`, `LAB_ALLOWLIST`, `LAB_AUTORUN_*`. The image itself is
configured through environment variables that the native install, a custom `docker run` or the Kubernetes manifest can
override: `ABL_PROJECT` (workspace), `OLLAMA_HOST`, `ABL_HOST` / `ABL_PORT`, `ABL_PYTHON`, `ABL_GGUF_PY`, `ABL_LLAMA_CPP`
(see `abliterate/platform.py`); inside the compose stack they are fixed by the Dockerfile and compose file.

**Offline / air-gapped**: on a connected machine build or pull the image, then `docker save
ghcr.io/thrizzo/redteam-llm-lab:latest ollama/ollama:latest caddy:2 -o redteam-llm-lab-image.tar` (with step 4 also
`n8nio/n8n:2.48.7 qdrant/qdrant:v1.20.2`). On the target `docker load -i redteam-llm-lab-image.tar`, then `up -d` without
`--build` and without `pull`.

### Step 4: the pentest copilot

The stack above runs steps 1 to 3. Step 4 **Pentest** needs n8n and Qdrant, which the overlay
`deploy/n8n/docker-compose.n8n.yml` adds; the console shows the step once it reaches n8n.

1. Set `N8N_ENCRYPTION_KEY` in `deploy/.env` (any long random string; `.env.example` shows how to make one), once: with
   another key later n8n refuses to start. Without it compose stops with *required variable N8N_ENCRYPTION_KEY is missing a
   value*.
2. Add the overlay to `COMPOSE_FILE` in `deploy/.env`, so that every command from then on uses it:
   ```
   COMPOSE_FILE=deploy/docker-compose.yml;deploy/docker-compose.gpu.yml;deploy/n8n/docker-compose.n8n.yml
   ```
   and start the stack (this restarts the app: let a running pipeline stage finish first):
   ```bash
   docker compose --env-file deploy/.env up -d --build
   ```
   n8n listens on `127.0.0.1:5678` (`N8N_PORT` in `deploy/.env` moves it). *Bind for 127.0.0.1:5678 failed: port is
   already allocated* means another container holds the port, often an n8n of your own: `docker ps -a --filter
   publish=5678` names it. A Windows program on the port (a leftover `kubectl port-forward`, for one) gives *Ports are not
   available* instead, and `Get-NetTCPConnection -LocalPort 5678 -State Listen` names it. Stop it, or set `N8N_PORT=5679`.
3. Pull the judge and the embedding model into the stack's Ollama:
   ```bash
   docker compose --env-file deploy/.env exec ollama ollama pull qwen3:8b
   ```
   ```bash
   docker compose --env-file deploy/.env exec ollama ollama pull nomic-embed-text
   ```
4. Set up n8n and connect the console. This runs in a one-off app container: no Python on this machine, n8n reached inside
   the stack whatever `N8N_PORT` is, and the console's secrets written to the workspace wherever `WORKSPACE` points:
   ```bash
   docker compose --env-file deploy/.env run --rm --no-deps app python /app/deploy/n8n/connect_console.py --n8n http://n8n:5678 --email <your n8n login> --setup-owner --secrets-dir /workspace/.copilot --operator-url http://ollama:11434/v1 --ollama-url http://ollama:11434 --qdrant-url http://qdrant:6333
   ```
   It asks for a password and creates n8n's owner account with it (8 to 64 characters with a digit and a capital letter),
   the credentials and the workflow, and writes the console's webhook secret and n8n key to `<WORKSPACE>/.copilot`.
5. Reload http://localhost:8080: the header shows step 4 **Pentest**. The copilot model is one that Ollama holds: step 2
   imports every abliterated run of a model with a GGUF (GLM-Edge, GLM-4) as `<model>-abl`; GLM-5.x runs get no GGUF, so
   in this stack they cannot be the copilot model. `COPILOT_OPERATOR_MODEL` in `deploy/.env` sets the default.
   Details, writeups for retrieval, and the n8n form: [deploy/n8n/README.md](deploy/n8n/README.md#setup).

The pipeline and Ollama share the GPU here. While a stage that loads the model runs, the console holds back copilot runs,
free prompts, Compare and knowledge uploads (they would load Ollama's models beside it) and says so; runs from the n8n form
should wait as well. Everything the console does in step 4 also goes into `<WORKSPACE>/audit/` and the app's log
(`docker compose --env-file deploy/.env logs app`).

### Rancher Desktop

The image is a plain OCI image.

- *moby (dockerd) backend*: the commands above work unchanged (without the GPU file on Windows). Docker Desktop and Rancher
  Desktop cannot run at the same time; see [Windows with Rancher Desktop installed too](#3-deploy-with-docker-recommended).
- *containerd backend*: `nerdctl compose -f deploy/docker-compose.yml up -d` (and `nerdctl load -i redteam-llm-lab-image.tar`
  for the exported image).
- On **Windows** Rancher Desktop does not pass the GPU into containers, whatever driver the host has: remove
  `docker-compose.gpu.yml` from `COMPOSE_FILE` and the whole pipeline runs on the CPU (next section). On a Linux host with the NVIDIA
  Container Toolkit the GPU works with either backend.
- In **the full lab on Kubernetes** (below) Rancher Desktop's pods get no GPU either, but the copilot's judge and
  embeddings can run on Ollama for Windows, which uses it: `deploy/k8s/tests/rancher-dev.ps1 -HostOllama`, see
  [GPU: Ollama for Windows](deploy/k8s/README.md#gpu-ollama-for-windows).

### Without a GPU

Remove `deploy/docker-compose.gpu.yml` from `COMPOSE_FILE` in `deploy/.env` (`COMPOSE_FILE=deploy/docker-compose.yml`, plus
the n8n overlay for step 4); nothing else changes:

```bash
docker compose --env-file deploy/.env up -d --build
```

A GPU older than Turing (GTX 9xx/10xx, Titan V, Tesla P40/V100) is visible but too old for the image's PyTorch (cu128, kernels
for Turing and newer). The app says so in its banner and runs on the CPU. To use it, set `TORCH_FLAVOR=cu126` in
`deploy/.env` and build again (`up -d --build`); that build has no kernels for RTX 50xx cards.

When no CUDA GPU is visible the pipeline and the lab load the model onto the CPU instead of failing with *Found no NVIDIA
driver on your system*: `--device-map cuda` falls back to `cpu`, and `--dtype auto` becomes float32 (bf16 on processors with
AVX512-BF16 / AMX, where it is the faster of the two). The app says so in a banner and preselects `cpu` under *Advanced*;
Ollama runs the Compare stage on the CPU as well. The method and the checks are the same, it just takes longer and the
model has to fit into RAM:

| | GLM-Edge-1.5B | GLM-Edge-4B |
| --- | --- | --- |
| RAM while loaded, float32 | 7 GB (measured) | about 18 GB (estimated) |
| full run with the default settings, 4 cores without AVX-512, no Ollama stage | 35 min (measured) | roughly 2 hours (estimated) |

To shorten a CPU run lower *test prompts*, *max new tokens* or narrow the *layer range* (`--n-test 8 --max-new-tokens 32
--layer-range 0.3-0.7`): the scan generates `layers × test prompts × tokens` and is most of the run time. If a run stops
without an error message (exit code 137) the container ran out of memory. Docker Desktop and Rancher Desktop on Windows
run inside WSL 2, which gets half of the host's RAM by default: raise it with `memory=24GB` under `[wsl2]` in
`%UserProfile%\.wslconfig`, then `wsl --shutdown` and start the container runtime again.

### Kubernetes (Rancher, RKE2, k3s)

**The full lab** (console with login, n8n copilot, Qdrant, judge model, and a vLLM server for the abliterated GLM-5.x
with Kill / Isolate) has its own Kustomize manifests: [deploy/k8s/README.md](deploy/k8s/README.md), overlays `dev`
(no GPU), `onprem` and `cloud`. The single-pod manifest below runs only the abliteration app.

`deploy/k8s/abliteration.yaml` deploys one pod with the app and Ollama as two containers, each with its own
PersistentVolumeClaim (`workspace` 200 Gi for the app, `ollama` 100 Gi for Ollama's store; GGUFs reach Ollama over its API on
127.0.0.1 inside the pod, not through a shared volume), a Service, a NetworkPolicy and an ingress-nginx Ingress with basic auth.
Steps:

1. Install the NVIDIA device plugin or GPU Operator. Both containers request `nvidia.com/gpu: 1`; on a node with a single
   GPU enable time-slicing (commands in the manifest header) or the pod stays Pending.
2. `kubectl create namespace abliteration`, then the secrets: `htpasswd -c auth admin` →
   `kubectl -n abliteration create secret generic basic-auth --from-file=auth`, and optionally
   `kubectl -n abliteration create secret generic hf --from-literal=token=hf_...`.
3. Set the host name in the Ingress; on k3s / Rancher Desktop (Traefik instead of ingress-nginx) use the Traefik variant
   described in the manifest header.
4. `kubectl apply -f deploy/k8s/abliteration.yaml`.

What a cluster does and does not buy you: it schedules runs onto nodes with free GPUs, keeps the checkpoints on shared
storage and gives everyone the same URL. It does **not** let one run use more GPU memory than a single node has: measure and
scan run one PyTorch process (`device_map=auto` shards across the GPUs of *one* machine). The weight edit itself needs no
GPU at all.

### Native (Windows, the way it was developed)

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip notebook ipywidgets
.\.venv\Scripts\python.exe run_pipeline.py setup          # torch CUDA, packages, llama.cpp converter environment, SBOM
.\.venv\Scripts\python.exe -m pip install fastapi "uvicorn[standard]" -c constraints-torch.txt
start_app.bat                                              # http://localhost:8787
```

Ollama must be installed and running (`ollama serve`). The same environment variables as in Docker apply.

---

## 4. Using the app

1. **Model**: pick a GLM preset or paste any repo id. Cards show family, size, whether it is on disk and whether the edit is
   exact; models that need a multi-GPU node are marked.
2. **Abliterate**: press Run. The guide below the button walks through download → architecture → load → measure → scan →
   choose → apply → verify → validate → GGUF → Ollama, each step with *what happens*, *why it matters*, *what to look for*,
   and expandable *under the hood* (math, tensor names) and *for GLM-5.x* notes. Charts and answers appear live. Tick
   "pause at the layer choice" to pick the layer yourself after the scan, or several layers ("combine with"; see
   *Several directions* in section 1).
3. **Compare**: the same prompt goes to the original and the abliterated model in Ollama, refusal phrases highlighted. The
   "Explore" panel loads the base model into a lab: a per-layer **refusal meter** for any prompt (how strongly each layer's
   direction lights up, token by token) and **try a layer live** (ablate any layer with hooks and read the answers).
4. **Pentest** (once the console is connected to n8n, as the Kubernetes console always is): the copilot, with its models, the engagement (scope, rules of engagement,
   protected data), copilot runs, manual commands, direct prompts and the live feed. See
   [deploy/k8s/README.md](deploy/k8s/README.md#copilot-runs-free-prompts-live-feed).

Header buttons: **datasets** (the harmful and harmless sets, plus the DPO set if it was exported with the notebook: search,
edit, add, remove with audit trail and restore),
**SBOM** (generate and download the CycloneDX file), **log** (process output).

Every run leaves a folder `runs/abliterate_<timestamp>/` with `run.json`, `events.jsonl`, `arch.json`, `layer_analysis.json`,
`baseline.json`, `scan_results.json`, `scan.json` (with `--combine`), `apply.json`, `generations.json`, `validation.json`,
`ollama_ab.json`, `refusal_dirs.pt`, `means.pt`. `run.json` names the applied layer (`layer`) and, since several directions,
all of them (`layers`); the edited model's folder keeps the directions and their basis in `refusal_direction.pt`. Models: `models/<slug>/` (base copy with revision and hashes), `out/<slug>-abliterated/`,
`gguf/<slug>-{base,abl}-q8_0.gguf`, Ollama `<slug>-base` / `<slug>-abl`.

---

## 5. Command line

```bash
python -m abliterate --model THUDM/glm-edge-4b-chat                       # everything, ends with both models in Ollama
python -m abliterate --model THUDM/glm-edge-4b-chat --pause-at-choice     # stop after the scan
python -m abliterate --run-dir runs/abliterate_<ts> --stage continue --layer 17
python -m abliterate --run-dir runs/abliterate_<ts> --stage continue --layers 15,17,19   # several directions at once
python -m abliterate --model THUDM/glm-edge-4b-chat --combine 3           # the scan also tests the best 2 and 3 layers together
python -m abliterate --model zai-org/GLM-5.2 --device-map auto --skip-verify --no-ollama
python -m abliterate --model THUDM/glm-edge-1.5b-chat --device-map cpu    # no GPU (also the fallback when none is visible)
python -m abliterate --help
```

Options: `--n-train 256 --n-test 16 --batch 16 --gen-batch 4 --max-new-tokens 64 --layer-range 0.2-0.8
--dtype auto|bfloat16|float32 --device-map cuda|cpu|auto --quantize q8_0|f16|bf16 --trust-remote-code --hf-token`,
`--layer N` or `--layers A,B,...`, `--combine K` (default 0: off). Stages:
`all`, `download`, `measure`, `scan`, `continue`, `apply`, `validate`, `deploy`.

---

## 6. GLM-5.2 / 5.3 specifically

`GlmMoeDsaForCausalLM`: 78 layers, hidden size 6,144, layers 0–2 dense, 3–77 mixture-of-experts with 256 routed + 1 shared
expert (8 active per token), DSA sparse-attention indexers on every fourth layer. GLM-5.2 is a bf16 checkpoint of 1.5 TB in
282 shards; GLM-5.3 ships in FP8 (0.75 TB, 141 shards, 128 × 128 blocks: the edit keeps the layout and writes new per-block scales), `zai-org/GLM-5.3-BF16`
is its bf16 copy.
The pipeline edits one attention output and 257 expert outputs per sparse layer (19,615 tensors with the MTP layer), streams the
checkpoint shard by shard (about 5 GB of RAM at a time, disk-bound), and leaves routers, indexers and norms untouched.

Hardware reality: measure and scan need the model loaded, which means a node with about 1.5 TB of GPU memory in bf16 or an
FP8 copy on 8×H200; CPU offload on a 1.5+ TB RAM node works for the measurement in hours and for a reduced scan
(`--n-test 8 --layer-range 0.35-0.7`). Convert and serve the edited checkpoint with vLLM or SGLang for validation at that
scale. llama.cpp at the pinned commit converts GLM-5.x too (`glm-dsa`; its vocabulary checked with the real tokenizers
through the converter view), but serving such a GGUF with Ollama is untested here, and at 0.75 to 1.5 TB it is not how this
lab serves GLM-5: the GLM-5.x presets untick the Ollama finish.

Reasoning: the GLM-4.7, GLM-5.x and GLM-5.3-Flash chat templates open a reasoning block at the generation prompt
(`<|assistant|><think>`). Measure, scan, validate and the lab ask the template for its own prompt without reasoning
(`enable_thinking=False`: GLM-4.7 and GLM-5 then write `</think>`, GLM-5.2 `<think></think>`). The GLM-5.3 and
GLM-5.3-Flash templates have no such switch, so the block is closed empty there (`<think></think>`, what they write for
earlier turns without reasoning). The scan therefore judges the answer itself. Check the promoted model with reasoning on
as well.

**GLM-5.3-Flash** (`zai-org/GLM-5.3-Flash`, `Glm5NextForConditionalGeneration`, MIT): 321B parameters, 45 layers plus one
MTP layer, hidden size 4,096. 34 layers use linear attention (Kimi Delta Attention), 11 use DSA sparse attention; layers 0–2
are dense, the rest MoE with 288 routed + 1 shared expert (8 active). FP8 checkpoint of 328 GB in 62 shards
(`-BF16`: 120 shards). Two differences matter for abliteration:
- **Four residual streams per token** (manifold-constrained hyper-connections, mHC). Each block reads a weighted mix of the
  streams, and its output is added to every stream with a per-stream weight. The streams also mix with each other through
  a 4 × 4 matrix. Every write therefore still goes through the projections the edit changes, and the mixing never acts on
  the hidden dimension, so the edit stays exact. The hooks measure the streams' mean (the model's own readout before the
  final norm) and ablate in each stream.
- **The edit**: the embedding, all 46 `o_proj` (linear and sparse layers alike) and every `down_proj` (3 dense, 12,384
  experts, 43 shared): 12,477 matrices. Routers, indexers, the mHC weights and the vision encoder stay untouched. Text
  prompts are fully covered; image tokens keep their own component along the direction, which the edited layers cannot
  write any further.

Hardware: about 330 GB in FP8, so one node with 8 FP8-capable 80 GB GPUs (H100 or H200) runs measure and scan; on A100s
transformers dequantizes the checkpoint to bf16 (about 640 GB), which does not fit with activations. On FP8-capable GPUs
(compute capability 8.9 and newer) transformers keeps the weights in FP8 and runs them through the `finegrained-fp8` Triton
kernel from the Hub: the image has the `kernels` package and the C compiler Triton needs, and the download stage fetches the
kernel with the model, so the measure and scan Jobs, which have no internet, find it in the cache (a cache without it stops
such a run before the load, with what to do). Install the `flash-linear-attention` kernels
there; without them transformers runs its PyTorch reference code for the linear layers (correct, much slower). vLLM
v0.34.0 (the glm-serve pin) registers `Glm5NextForConditionalGeneration`. llama.cpp at the pinned commit converts it as
well (arch `glm5-next`; checked through the converter view with the real tokenizer and on a tiny model of the
architecture), but serving that GGUF with Ollama is untested, and the preset unticks the Ollama finish.

---

## 7. Security notes

- The app has no login of its own and can download models, run subprocesses, edit datasets and write files. Only expose it
  behind the provided proxy (or an Ingress) with authentication, on a trusted network or over TLS.
- Models are loaded from safetensors without remote code unless `--trust-remote-code` is passed (checkpoints that bring
  their own model class). The GGUF converter refuses model folders that contain code files.
- Datasets are local JSONL copies exported once from a pinned Hugging Face revision, with the revision and SHA-256 recorded in
  `data/manifest.json`; every edit and removal is logged. `ABL_HARMFUL_DATASET` / `ABL_HARMLESS_DATASET` select other
  sources (`org/name[@revision][#column]`), e.g. for licence reasons. Switching exports again, keeps the old copy under
  `data/replaced/`, and every run records what it measured on (`deploy/k8s/README.md`, "Running abliteration" and
  "Licences for internal company use").
- The SBOM panel lists all packages with licences and PyPI/OSV advisories; regenerate it after updating the environment.

## 8. Credits

Method: Arditi, Obeso, Syed, Paleka, Panickssery, Gurnee, Nanda, *Refusal in Language Models Is Mediated by a Single Direction*
(2024). Prompt sets (defaults, selectable): `mlabonne/harmful_behaviors` (AdvBench, Zou et al. 2023), `mlabonne/harmless_alpaca`
(Stanford Alpaca; for company use see "Licences for internal company use" in `deploy/k8s/README.md`).
Models: Zhipu AI / THUDM GLM family (check each model's licence before redistributing anything derived from it). Tooling:
Hugging Face transformers, llama.cpp, Ollama, Caddy.
