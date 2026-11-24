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
4. **Open the console:** through the Ingress host, or without one:
   ```bash
   kubectl -n lab port-forward svc/console 8080:8080
   ```
   http://localhost:8080, user and password from step 1.
5. **Open n8n** (not on the Ingress):
   ```bash
   kubectl -n lab-copilot port-forward svc/n8n 5678:5678
   ```
   - **Credentials:**
     - Ollama `http://ollama.lab-copilot.svc:11434` (judge, embeddings);
     - Qdrant `http://qdrant.lab-copilot.svc:6333`;
     - the operator model at `http://glm-serve.lab.svc:8000`, model `glm-abl`. In dev that is an Ollama credential with
       that Base URL; on GPU overlays an OpenAI credential with Base URL `.../v1`.
   - **Workflow:** import `deploy/n8n/workflows/pentest-copilot.json` and publish it.

## Running abliteration

The console works as it does locally (Model → Abliterate → Compare), but every stage runs as a Kubernetes **Job** in
`lab`. Its log streams into the same GUI, and the header shows the Job.

- **What the Jobs get:**
  - the stage's resources and placement from ConfigMap `lab-jobs` (the overlay's `jobs.json`);
  - the workspace at `/workspace`;
  - no ServiceAccount token, and non-root.

  Only download Jobs may reach the internet: they fetch the model and the prompt datasets. Every other stage runs
  offline.
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

Start the vLLM server (the console buttons for Start / Kill / Isolate come in phase 4):

```bash
kubectl -n lab scale deploy/glm-serve --replicas=1
```

- **vLLM version:** pinned to `v0.34.0`, not verified with GLM-5.x. Smoke-test it on the GPU node first and adjust
  `VLLM_ARGS` (ConfigMap `glm-serve`).
- **Re-applying an overlay** resets `glm-serve` to its manifest replicas (0 on GPU overlays), and resets `MODEL_PATH`
  to its default. Promote again afterwards, or keep the overlay's ConfigMap value in sync.

**Kill / Isolate by hand.** These are the same calls the console's ServiceAccount is allowed:

| Action | Commands |
| --- | --- |
| Isolate (model keeps running, no traffic) | `kubectl -n lab delete networkpolicy glm-serve-allow` |
| Release | `kubectl apply -k deploy/k8s/overlays/<overlay>` (re-creates the policy; also resets replicas) |
| Kill | `kubectl -n lab delete networkpolicy glm-serve-allow`<br>`kubectl -n lab scale deploy/glm-serve --replicas=0`<br>`kubectl -n lab delete pod -l app=glm-serve --grace-period=0 --force` |

Network policies only ever allow traffic, so isolation removes the allow and `default-deny` stays.

## Tested in CI

`.github/workflows/k8s-e2e.yml` runs on every push that touches `deploy/k8s`, `app` or `abliterate`, each time on a
kind cluster with Calico.

- **`kind` (`tests/e2e.sh`):**
  - server-side dry run of every overlay;
  - allowed and blocked traffic;
  - login 401 / 200;
  - RBAC: what the console may and may not do;
  - Isolate / Release and Kill / Start, performed as the console's ServiceAccount, including how long it takes until the
    model's container is gone from the node.
- **`pipeline` (`tests/pipeline-e2e.sh`)** builds the console image from the commit (CPU torch) and first runs the unit
  tests inside it (`abliterate/tests`, `app/tests`). Then it drives the console through its API on a tiny random GLM,
  saved by transformers v5 like newer checkpoints:
  - download, scan, apply, validate and deploy as Jobs;
  - each Job's network labels;
  - Promote;
  - a second run whose served model must differ;
  - Rollback to the first run's exact model;
  - Stop.

Not covered by CI: GPUs, vLLM with real weights, GLM-5.x itself.
