# Red Team LLM Lab on Kubernetes

Kustomize manifests for the full lab:
- the **console** (the lab app with a login);
- the **pipeline stages as Kubernetes Jobs**;
- **`glm-serve`**, the server for the abliterated model, with Promote / Rollback;
- the **n8n copilot**, Qdrant and the judge/embeddings model.

The design behind them is [docs/design/glm5-k8s-console.md](../../docs/design/glm5-k8s-console.md).

> `abliteration.yaml` in this folder is the older single-pod variant: the abliteration app plus Ollama, no copilot.

## Layout

```
base/                       shared manifests (do not apply directly)
  namespaces.yaml           lab, lab-copilot (Pod Security: baseline enforced, restricted warned)
  lab/                      console + login, its RBAC, glm-serve (vLLM, 8 GPUs, 0 replicas), workspace volume,
                            network policies, jobs.json (how stages run as Jobs)
  copilot/                  n8n, Qdrant, Ollama (judge, embeddings), network policies
components/gpu-node/        puts glm-serve on the labelled, tainted 8-GPU node
overlays/dev/               no GPU: glm-serve runs Ollama, stages run on the CPU (phase 0)
overlays/onprem/            your own GPU node (e.g. RKE2 + GPU Operator), node-local fast storage
overlays/cloud/             generic GPU cloud, shared (RWX) fast storage
overlays/ci/                CI: stub console, network / login / RBAC / Kill tests
overlays/ci-pipeline/       CI: the real console image, every stage as a Job on a tiny GLM, Promote / Rollback
tests/                      kind config, e2e.sh, pipeline-e2e.sh, make_tiny_glm.py
```

**`lab`** holds everything that touches the model weights: the console, the Jobs it starts, `glm-serve`, and the
**workspace** volume they share. A volume belongs to one namespace, and all of these read or write the same weights.

**`lab-copilot`** holds n8n, Qdrant and the judge/embeddings Ollama.

The network policies deny everything that isn't explicitly opened:

| Who | May reach |
| --- | --- |
| console | n8n, Qdrant, Ollama, the model server, the Kubernetes API |
| n8n | Qdrant, Ollama, the model server |
| download Jobs | Hugging Face (443) |
| deploy Jobs | the model server |
| scan / apply / validate Jobs, the model server | nothing |

## Prerequisites

- **Network policies:** a network plugin that enforces them. RKE2's default (Canal), Calico and Cilium do, and k3s
  enforces them with its built-in controller.
- **GPU overlays:** the NVIDIA GPU Operator (or device plugin), plus the 8-GPU node labelled and tainted:
  ```bash
  kubectl label node <gpu-node> redteam-llm-lab/gpu-node=true
  ```
  ```bash
  kubectl taint node <gpu-node> redteam-llm-lab/gpu-node=true:NoSchedule
  ```
- **The console image** `ghcr.io/thrizzo/redteam-llm-lab` is private:
  - **Normally:** create a pull secret with a GitHub token that has `read:packages` (below), or make the package public.
  - **Exception, dev on Rancher Desktop with the dockerd engine:** Kubernetes uses images Docker built on the same
    machine, so the image `docker compose ... up -d --build` built for the compose stack is used as is, with no pull
    secret.
  - **CPU-only image** (smaller, for clusters without GPUs):
    `docker build -f deploy/Dockerfile --build-arg TORCH_FLAVOR=cpu -t ghcr.io/thrizzo/redteam-llm-lab:latest .`
  - **Kubernetes in Rancher Desktop:** enable it in Preferences → Kubernetes. Its k3s ships Traefik, the base's ingress
    class.

## Rancher Desktop (Windows): set up and check with one script

`tests/rancher-dev.ps1` does the Deploy steps below for the `dev` overlay, then checks the result. From a PowerShell
window anywhere in the repository:

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\k8s\tests\rancher-dev.ps1
```

- **Without switches** it runs `-Setup`, then `-Check`:
  - **`-Setup`:**
    - builds the console image into Rancher Desktop's container engine (docker with dockerd, nerdctl with
      containerd: it picks the one Kubernetes uses);
    - creates the namespaces and Secrets;
    - applies the overlay and waits for every pod;
    - connects n8n with `connect_console.py`.
  - **`-Check`:**
    - the login;
    - `http://lab.localhost` through Traefik, including a 2 MB upload and the 50 MB limit;
    - allowed and blocked traffic from probe pods;
    - the console's access to the Kubernetes API;
    - Isolate / Release / Kill / Start with their audit entries;
    - the copilot's models;
    - a knowledge upload that a copilot run retrieves;
    - a free prompt.
  - **`-Pipeline`** (optional, a few minutes): a tiny random GLM through every stage as Jobs, then Promote.
  - **`-Teardown`:** deletes both namespaces with all their data, after asking.
  - **`-EvalJudge`** (optional, 10 to 30 minutes on a CPU): how reliably the judge model enforces rules of engagement
    written as text. It runs 49 labelled commands through the copilot's Ollama with the workflow's exact prompt
    (`copilot/eval_judge.py`, in the console pod) and reports false accepts and false rejects. The report goes to
    `workspace/eval/`; `-JudgeModel` picks another judge.
- **It asks for:**
  - a console password the first time (only its bcrypt hash is stored, in Secret `lab/basic-auth`);
  - an n8n login (a fresh n8n gets it as its owner account).

  Re-running is safe: the build uses its cache, existing Secrets are kept, and n8n is updated in place.
- **Needs:**
  - Rancher Desktop with Kubernetes and Traefik on;
  - Python 3 for the n8n step;
  - `kubectl` context `rancher-desktop` (`-Context`). The script uses that context even when another one is current.
- **Memory:** WSL gets half the host RAM by default. The stack is sized to start on 8 GB. The judge (`qwen3:8b`)
  together with a CPU abliteration of GLM-Edge-1.5B needs about 16 GB:
  - set `memory=16GB` under `[wsl2]` in `%UserProfile%\.wslconfig`;
  - restart Rancher Desktop.

  The judge (~5 GB) downloads in the background. Checks that need it are skipped until it is there.
- **Output:** `ok`, `FAIL` or `skip` per step, and `rancher-dev-<time>.log` in the current folder. The log holds no
  passwords or keys; paste it back when something fails.
- **CI:** the `k3s` job runs the same script under PowerShell 7 on k3s (k3d), unattended. Windows PowerShell 5.1 itself
  is not run in CI.

## Deploy

1. **Namespaces and secrets** (once). Keep the single quotes around the hash, in bash and in PowerShell:
   ```bash
   kubectl apply -f deploy/k8s/base/namespaces.yaml
   ```
   ```bash
   kubectl -n lab create secret generic basic-auth --from-literal=user=admin --from-literal=hash='<bcrypt hash>'
   ```
   ```bash
   kubectl -n lab-copilot create secret generic n8n --from-literal=encryption-key='<long random string, never change it>'
   ```
   ```bash
   kubectl -n lab create secret docker-registry ghcr --docker-server=ghcr.io --docker-username=<github user> --docker-password=<token with read:packages>
   ```
   - **The login hash:** the same format as `CADDY_HASH` in `deploy/.env`. You can reuse that, or make one with
     `docker run --rm caddy:2 caddy hash-password --plaintext '<password>'`.
   - **Optional, gated Hugging Face models:**
     `kubectl -n lab create secret generic hf --from-literal=token=<hf token>`. Only download Jobs receive it.
2. **Edit the overlay** (onprem / cloud): the values marked `EDIT` in `patches.yaml` (storage class, host name, ingress
   class) and in `jobs.json` if your node is not an 8-GPU node.
3. **Apply:**
   ```bash
   kubectl apply -k deploy/k8s/overlays/dev
   ```
   Use `overlays/onprem` or `overlays/cloud` on a GPU cluster.
4. **Open the console:** through the Ingress host (`dev`: http://lab.localhost), or without one:
   ```bash
   kubectl -n lab port-forward svc/console 8080:8080
   ```
   http://localhost:8080, user and password from step 1.
5. **Connect n8n** (not on the Ingress). One script sets up the copilot's credentials, the workflow, and the console's
   access ([Copilot](#copilot-runs-free-prompts-live-feed)):
   ```bash
   kubectl -n lab-copilot port-forward svc/n8n 5678:5678
   ```
   ```bash
   python deploy/n8n/connect_console.py --email <your n8n login> --apply-secret
   ```
   A fresh n8n needs `--setup-owner` as well. n8n's own UI is then at http://localhost:5678.

## Running abliteration

The console works as it does locally (Model → Abliterate → Compare), but every stage runs as a Kubernetes **Job** in
`lab`. Its log streams into the same GUI, and the header shows the Job.

- **What the Jobs get:**
  - the stage's resources and placement from ConfigMap `lab-jobs` (the overlay's `jobs.json`);
  - the workspace at `/workspace`;
  - no ServiceAccount token, and non-root.

  Only download Jobs may reach the internet: they fetch the model and the prompt datasets. Every other stage runs
  offline.
- **Prompt datasets, selectable per environment:** by default the harmful prompts come from `mlabonne/harmful_behaviors`
  (AdvBench) and the harmless ones from `mlabonne/harmless_alpaca`. Two variables in `jobs.json` choose other Hugging Face
  datasets. Each takes `org/name`, optionally with `@revision` and `#column`:

  ```json
  "env": { "ABL_HARMLESS_DATASET": "databricks/databricks-dolly-15k#instruction" }
  ```

  `ABL_HARMFUL_DATASET` works the same way. The next download Job exports the changed source to `data/` and pins the
  commit; a branch or tag is resolved to its commit. The previous copy, and the rows the dataset workbench removed from it,
  move to `data/replaced/`. Every run records the source, commit, column, row count, SHA-256 and whether the copy was
  edited (`run.json`, `data`). If the harmful dataset has no `test` split, the held-out prompts come from the end of its
  `train` split. The other stages are offline: one that finds a changed source tells you to run download first, and
  keeps the old copy. In Docker Compose, the same two variables go into `deploy/.env`.
- **Every run keeps its own edited model** in `runs/<run>/model`, so earlier runs stay available for Rollback.
- **Stop** deletes the Job. A console restart doesn't stop a Job; the new console re-attaches to it.
- **One GPU node:** in vLLM mode GPU stages (scan, validate, ...) are refused while `glm-serve` runs. Stop it first, or
  set `serving.exclusiveGpu` to `false` in `jobs.json` once you have a second GPU node.

## Serving: Promote and Rollback

The **serving** button in the console's header (Kubernetes only) lists the runs with an edited model.

- **Promote** makes one of them the copilot's model:
  - **vLLM (onprem / cloud):** ConfigMap `glm-serve` gets `MODEL_PATH=/workspace/runs/<run>/model`. A running
    `glm-serve` pod is restarted with it; a stopped one uses it on its next start.
  - **Ollama (dev):** the run's GGUF, built by its deploy stage, is published to `glm-serve` as `glm-abl`.
- **Rollback** returns to the run promoted before.
- **History:** every change is recorded in `/workspace/serving/history.json`.

Start the vLLM server with **Start** in the kill switch (next section), or by hand:

```bash
kubectl -n lab scale deploy/glm-serve --replicas=1
```

- **vLLM version:** pinned to `v0.34.0`, not verified with GLM-5.x. Smoke-test it on the GPU node first and adjust
  `VLLM_ARGS` (ConfigMap `glm-serve`).
- **Re-applying an overlay** resets `glm-serve` to its manifest replicas (0 on GPU overlays), and resets `MODEL_PATH`
  to its default. Promote again afterwards, or keep the overlay's ConfigMap value in sync.

## Kill switch

The console's header shows the model server's state (**model running**, **isolated**, **killed**, ...). Click it, or
**serving**, for the buttons. Each action takes well under a second.

| Button | What happens | The model afterwards |
| --- | --- | --- |
| **Kill** (asks first) | 1. delete `glm-serve-allow` (the cut)<br>2. scale `glm-serve` to 0<br>3. delete its pod with grace period 0<br>4. check no pod is left | gone; nothing restarts it |
| **Isolate** | delete `glm-serve-allow` | keeps running, GPU memory included; nothing reaches it, and it reaches nothing |
| **Release** | recreate `glm-serve-allow` from the console's copy | reachable again |
| **Start** | recreate the policy, scale to 1 | loading (GLM-5.3 takes minutes); refused while a GPU Job holds the only GPU node |

- **Steps:** Kill runs every step even when one fails, and shows each step's result and time.
- **Open connections:** depending on the network plugin, a response already streaming when you press Isolate can
  finish. Kill ends it.
- **The console's copy of the policy** is kept in the console pod (an `emptyDir`), not on the workspace. Jobs and, in
  dev, the model server can write the workspace, and Release creates whatever the copy says. A new console pod copies
  the policy when it starts; if the policy was already gone then, Release refuses: re-apply the overlay.
- **Audit:** every Kill, Isolate, Release and Start, and every Promote and Rollback, refused attempts included, goes to
  `/workspace/audit/YYYY-MM-DD.jsonl` with its steps, timings, reason and who asked. A copy goes to the console's
  container log, which Jobs can't change:
  ```bash
  kubectl -n lab logs deploy/console -c app | grep ^AUDIT
  ```
  "Who" is the login user (one shared account) and the address the login proxy saw. Behind an Ingress that address is
  the ingress controller's; the `X-Forwarded-For` chain it sent is recorded too.
- **Cross-site requests:** a browser sends the login along with requests that other web pages make. The console refuses
  POSTs from another origin, so a page elsewhere can't press Kill or Release.

**By hand,** when the console is down. These are the same calls its ServiceAccount may make:

| Action | Commands |
| --- | --- |
| Isolate (model keeps running, no traffic) | `kubectl -n lab delete networkpolicy glm-serve-allow` |
| Release | `kubectl apply -k deploy/k8s/overlays/<overlay>` (re-creates the policy; also resets replicas) |
| Kill | `kubectl -n lab delete networkpolicy glm-serve-allow`<br>`kubectl -n lab scale deploy/glm-serve --replicas=0`<br>`kubectl -n lab delete pod -l app=glm-serve --grace-period=0 --force` |

Network policies only ever allow traffic, so isolation removes the allow and `default-deny` stays.

## Copilot: runs, free prompts, live feed

The **copilot** button in the console's header opens the copilot panel.

**Connect n8n once.** The console starts runs through n8n's webhook and follows them through n8n's API. One script sets up
both sides:

```bash
kubectl -n lab-copilot port-forward svc/n8n 5678:5678
```
```bash
python deploy/n8n/connect_console.py --email <your n8n login> --apply-secret
```

- **What it sets up:**
  - the copilot's credentials: the operator (OpenAI-compatible, `glm-serve`), Ollama (judge, embeddings), Qdrant, and
    the webhook secret;
  - the workflow, imported and published;
  - an n8n API key that may only read and stop executions;
  - the Secret `copilot` in `lab` with the key and the webhook secret.
- **Login:** it asks for your n8n password. A temporary full-scope key does the setup and is deleted at the end.
- **No restart:** the console reads the Secret from a mounted file, so it is connected within a minute or two.
- **Re-running** updates everything in place and rotates the key and the secret.
- **Fresh n8n:** add `--setup-owner --password ...` to create the owner account.

**Which model the copilot uses.** The copilot is the n8n flow, and it uses three models: the *copilot model* (operator),
the *judge*, and the *embedding model* for retrieval. The **Models** card names all three. The *operator* is the
abliterated model that suggests: whatever `glm-serve` serves.
In vLLM mode that is the promoted run, as `glm-abl`. To change it, pick another run under **Load** in the **Models** card.
That is Promote, so it is audited and Rollback in **Serving** undoes it. The *judge* is a
regular model in the copilot's Ollama that can veto the operator (`qwen3:8b` by default). It reads only the vetted
command, the scope (`LAB_ALLOWLIST`, always) and the rules of engagement; the operator's free text never reaches it. The
embedding model (`nomic-embed-text`) only turns writeups into vectors for retrieval and writes no text. The **Models** card lists both
from the servers themselves; the choice is remembered per browser and sent with every run. The judge is never an
abliterated model: the list leaves out `glm-abl`, `*-abl`, `*abliterated*` and `uncensored` names and embedding models,
the console refuses such a judge (400), and n8n's "Build judge prompt" node refuses it again.

**Scope and rules of engagement.** The **Engagement** card holds what the client agreed to:
- **Fields:** a name, the scope statement, the rules of engagement (free text that the operator model and the judge
  both read), the in-scope IPv4 addresses, CIDRs or host names, exclusions, a time window, prohibited tools or flags
  (`hydra`, `-T5`; whole words, no patterns), and the auto-run tiers.
- **One active engagement, versioned:** every save is a new version under `workspace/engagement/`, with who saved it and
  a note, in the audit log. Earlier versions can be loaded and saved again. Switch it off with *active*, and runs use
  `LAB_ALLOWLIST` alone.
- **`LAB_ALLOWLIST` stays the ceiling.** A host must be in `LAB_ALLOWLIST` and in the engagement's scope, not excluded,
  inside the window. A tier auto-runs only if both its `LAB_AUTORUN_*` variable and the engagement allow it. The console
  refuses a scope entry outside the ceiling when it saves. n8n's scope gate and policy gate enforce all of it, again
  after the judge.
- **The ceiling has one place:** `base/copilot/copilot.env` (`LAB_ALLOWLIST`, `LAB_AUTORUN_READONLY`,
  `LAB_AUTORUN_ACTIVE_RECON`, `COPILOT_JUDGE_MODEL`). Kustomize turns it into `copilot-settings`, which n8n reads, and
  `copilot-scope`, which the console reads. Edit the file and apply the overlay again. Restart n8n and the console so
  they read it.

**Three ways to ask:**
- **Copilot:** a task and one target. The run goes through the scope gate, retrieval, the abliterated operator, the
  policy gate and the judge.
- **Manual command:** you type the command (one line). It skips retrieval and the operator model, and the same policy
  gate and judge check it.
- **Direct prompt:** straight to the chosen operator model, streamed and audited. There is no copilot, gate or judge,
  since nothing executes either way. **Use as command** takes the command out of the answer into Manual command, where
  the gates check it.

**The run as a flow.** Two lanes: the copilot's gates and judge, and the abliterated model.
- **Prompt and answer:** the prompt crosses to the model and the answer comes back. "Show the prompt" has the exact text
  the model got (rules of engagement and references included). "Show the raw answer" has what it sent back.
- **Each gate:** passed, blocked with every reason, still deciding, or not reached. The judge's exact prompt is one
  click away.
- **About to be executed:** the policy-vetted command, the only thing the Execute node would ever get. It comes with
  Copy and Edit as manual command. **Execute** is shown disabled: the workflow's Execute node is off, no runner is
  configured, and authorized runs park at Human approval in n8n.
- **Stop run** stops a run in n8n.

**Live feed:** everything as it happens, from every source:
- copilot runs, free prompts, engagement saves;
- pipeline Jobs and their steps;
- Kill / Isolate / Release / Start, Promote / Rollback;
- changes of the model server's state.

**Logged and kept:**
- **Audit:** every run's start (mode, models, engagement version), stop and end, every engagement save, and every free
  prompt with its answer (up to 2,000 characters), go to the audit log with who asked.
- **The run list** lives in the console's memory, so a console restart forgets it. n8n keeps the executions.
- **The webhook secret is in n8n's execution data**, as part of the request headers n8n stores for the webhook node.
  Only n8n's owner and the console's key can read executions, and both have the secret anyway. The console never shows
  that node's data.

## Knowledge uploads

The **knowledge** button in the console's header opens the writeups the copilot retrieves from. It appears once
`QDRANT_URL` is set (in the base, `qdrant.lab-copilot`).

- **Add a document:**
  - **Types:** md, txt, rst, html or pdf, up to 50 MB.
  - **Source:**
    - `htb` and `blog`: public writeups;
    - `engagement`: your client notes, scrubbed hard;
    - `pwk`: course material, used for retrieval only, never for training.
  - **Preview** shows what ingesting would do: the chunks, and for engagement notes the scrubber's redactions and the
    scrubbed text. Engagement notes can only be uploaded after a preview.
  - **Upload** stores the file under `/workspace/writeups/<source>/` and ingests it in the background. It is scrubbed,
    chunked, then embedded by the copilot's Ollama (`RAG_OLLAMA_URL`, `nomic-embed-text`: the model n8n searches with)
    into the `writeups` collection.
  - **Uploading a file again** replaces its chunks.
- **Documents:** each with its chunk count and status. **Delete** removes its vectors first, then the file; if the
  vector store can't be reached, nothing is removed.
- **PDF:** the text layer is read in a separate process that limits its own memory and CPU time, since PDFs from the
  internet are untrusted and the console also hosts the kill switch. A PDF without a text layer (scanned) is refused;
  OCR it first.
- **Trust:** uploaded text stays untrusted. The workflow hands it only to the operator, with addresses masked, never to
  the judge, and the policy gate stays the boundary.
- **Logged:** uploads, ingest results and deletes go to the audit log and the live feed.
- **Body size, 50 MB end to end:** the console's login (Caddy) accepts up to 50 MB, and the base Ingress sets
  `nginx.ingress.kubernetes.io/proxy-body-size: 50m` for ingress-nginx (its default is 1 MB). Traefik, the class the
  overlays use (Rancher Desktop's default), sets no body limit unless a buffering middleware adds one.
- **Without the GUI:** the same ingest for a whole folder is `python -m copilot.ingest --src /workspace/writeups`
  (copilot/README.md).

## Licences for internal company use

For running the lab inside a company, on its own hardware, for its own red team. This is a checklist, not legal
advice. Have legal confirm the points marked **check**.

| Part | Licence | What it means internally |
|---|---|---|
| Rancher Desktop, k3s, Traefik, Qdrant, Ollama, Caddy, llama.cpp, vLLM, PyTorch, transformers, FastAPI | Apache-2.0 / MIT / BSD | Free. |
| Docker Desktop | Paid subscription for companies with 250+ employees or $10M+ revenue | Not needed: the dev path uses Rancher Desktop, and Docker Engine on Linux is free. |
| n8n Community Edition, self-hosted | Sustainable Use License | Free for internal business use. Offering it to customers, or running it as a service for others, needs a commercial licence. |
| GLM-5.3 (target) | Modified MIT. Model-as-a-Service providers with more than $10B revenue need a security review by Z.AI before commercial use. | Internal red-team use is not MaaS. **Never offer the model, or the abliterated one, as an API to others** without that review. |
| GLM-Edge 1.5B / 4B (dev tests) | GLM-4 licence: commercial use after a free registration with Zhipu, plus a "Built with GLM-Edge" notice | **check.** Register, or test with `THUDM/GLM-4-9B-0414` (MIT) instead. |
| qwen3:8b (judge), nomic-embed-text (embeddings) | Apache-2.0 | Free. |
| `mlabonne/harmful_behaviors` (AdvBench) | MIT | Free. |
| `mlabonne/harmless_alpaca` (default harmless prompts) | Unclear: derived from Stanford Alpaca, whose data licence is disputed (CC BY-NC vs CC BY), and which contains OpenAI outputs | **check**, or select another source: `ABL_HARMLESS_DATASET=databricks/databricks-dolly-15k#instruction` (CC BY-SA 3.0, commercial use allowed). |
| PWK / OSCP course material | Licensed to the student personally | Upload with source `pwk` only into a personal instance, never into a shared company one. |

The real cost is GPU time for GLM-5.3, not licences. Each run also keeps its own edited model of 0.75 to 1.5 TB, so
delete old runs you no longer need for Rollback.

## Tested in CI

`.github/workflows/k8s-e2e.yml` runs on every push that touches `deploy/k8s`, `deploy/n8n`, `app`, `abliterate` or
`copilot`. Network policies are enforced in all three jobs: Calico on kind, and k3s's own controller.

- **`kind` (`tests/e2e.sh`):**
  - server-side dry run of every overlay;
  - allowed and blocked traffic;
  - login 401 / 200;
  - RBAC: what the console may and may not do;
  - Isolate / Release and Kill / Start, performed as the console's ServiceAccount, including how long it takes until the
    model's container is gone from the node.
- **`pipeline` (`tests/pipeline-e2e.sh`)** runs the n8n workflow's tests, builds the console image from the commit (CPU
  torch) and runs the unit tests inside it (`abliterate/tests`, `copilot/tests`, `app/tests`). Then it drives the console through its API on a tiny random GLM,
  saved by transformers v5 like newer checkpoints:
  - download, scan, apply, validate and deploy as Jobs;
  - each Job's network labels;
  - Promote;
  - a second run whose served model must differ;
  - Rollback to the first run's exact model;
  - Stop;
  - the kill switch through the login: cross-site and body-less POSTs refused, Isolate and Release, Kill timed until
    the container is gone from the node, Start, and the audit entries with the login user;
  - copilot runs through **real n8n**, with a model stand-in (`app/tests/model_standin.py`) as the operator, judge and
    embeddings. `connect_console.py` sets n8n up; then:
    - every branch arrives in the console, one event per stage: approval, policy block, judge reject, out of scope;
    - Stop cancels a waiting run;
    - the webhook refuses calls without the secret, and the console's n8n key can't list workflows;
    - a free prompt streams from `glm-serve`;
    - the feed and the audit log record all of it;
  - copilot v2 through the same n8n:
    - the model lists leave out abliterated and embedding judges, and an abliterated judge is refused;
    - an engagement entry outside `LAB_ALLOWLIST` is refused;
    - with an engagement saved, the rules of engagement reach the operator's and the judge's prompt. The stand-in
      confirms it received exactly the prompts the console shows;
    - a target inside `LAB_ALLOWLIST` but outside the engagement is blocked before any model runs;
    - a prohibited tool is blocked by the policy gate;
    - a manual command takes the gates without retrieval or the operator, and is staged;
    - switched off, `LAB_ALLOWLIST` applies alone again;
  - the prompt sets each run measured on (source, pinned commit, column) are recorded in `run.json`;
  - knowledge uploads into **real Qdrant**:
    - markdown and PDF are indexed, and a scanned PDF is refused;
    - the engagement preview shows its redactions;
    - a copilot run retrieves the uploads;
    - after delete, the store and the folder are empty and the next run finds nothing;
    - deletes outside the writeups folder are refused.
- **`k3s`:** Rancher Desktop's Kubernetes, k3s in k3d, with Traefik, local-path storage and k3s's own network policy
  controller. It runs `tests/rancher-dev.ps1 -Setup -Pipeline -Check` unattended under PowerShell 7, on the `ci-k3s`
  overlay: `dev`, with only the embedding model pulled.
  - PowerShell's parser checks the script first, and that it is plain ASCII as Windows PowerShell 5.1 needs.
  - The script then:
    - creates the Secrets;
    - connects n8n;
    - runs the pipeline on a tiny GLM;
    - checks the login and the Ingress through Traefik, including the 50 MB limit;
    - checks the network policies under k3s, the kill switch, a knowledge upload retrieved by a copilot run, and a
      free prompt.

Not covered by CI: GPUs, vLLM with real weights, GLM-5.x itself, Windows PowerShell 5.1 (the `k3s` job runs
PowerShell 7).
