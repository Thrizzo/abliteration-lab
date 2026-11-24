# Red Team LLM Lab on Kubernetes

Kustomize manifests for the full lab: the console (lab app), the n8n copilot, Qdrant, the judge/embeddings model, and
`glm-serve`, the server for the abliterated model. The design behind them is
[docs/design/glm5-k8s-console.md](../../docs/design/glm5-k8s-console.md).

> `abliteration.yaml` in this folder is the older single-pod variant: the abliteration app plus Ollama, no copilot.

## Layout

```
base/                       shared manifests (do not apply directly)
  namespaces.yaml           lab-control, lab-model (Pod Security: baseline enforced, restricted warned)
  control/                  console + login, n8n, Qdrant, Ollama (judge, embeddings), Ingress, network policies
  model/                    glm-serve (vLLM, 8 GPUs, 0 replicas), models volume, network policies, console RBAC
components/gpu-node/        puts glm-serve on the labelled, tainted 8-GPU node
overlays/dev/               no GPU: glm-serve runs Ollama with a small abliterated model (phase 0)
overlays/onprem/            your own GPU node (e.g. RKE2 + GPU Operator), node-local fast storage
overlays/cloud/             generic GPU cloud, shared (RWX) fast storage
overlays/ci/                the dev overlay for the CI test on kind (stub console, test-only secrets)
tests/                      kind config + e2e.sh (run by .github/workflows/k8s-e2e.yml)
```

**Namespaces:**
- **`lab-control`:** everything you talk to.
- **`lab-model`:** only the model server and, from phase 2, the abliteration Jobs.

The console's Kill/Isolate permissions are limited to `lab-model`. Network policies deny everything that isn't explicitly
opened:
- the console reaches n8n, Qdrant, Ollama and the model server;
- n8n reaches Qdrant, Ollama and the model server;
- the model server reaches nothing at all.

## Prerequisites

- **Network policies:** a network plugin that enforces them. RKE2's default (Canal) does, as do Calico and Cilium. k3s
  enforces them with its built-in controller.
- **GPU overlays:** the NVIDIA GPU Operator (or device plugin), plus the 8-GPU node labelled and tainted:
  ```bash
  kubectl label node <gpu-node> redteam-llm-lab/gpu-node=true
  kubectl taint node <gpu-node> redteam-llm-lab/gpu-node=true:NoSchedule
  ```
- **The console image:** `ghcr.io/thrizzo/redteam-llm-lab` is private. Create a pull secret with a GitHub token that has
  `read:packages` (below), or make the package public.
  - **Exception, dev on Rancher Desktop with the dockerd engine:** Kubernetes uses images built by Docker on the same
    machine, and the dev overlay doesn't force a pull. The image `docker compose ... up -d --build` built for the compose
    stack is used as is, with no pull secret.
  - **Kubernetes in Rancher Desktop:** enable it in Preferences → Kubernetes. Its k3s enforces network policies and ships
    Traefik, which is the base's ingress class.

## Deploy

1. **Namespaces and secrets** (once). Keep the single quotes around the hash, in bash and in PowerShell:
   ```bash
   kubectl apply -f deploy/k8s/base/namespaces.yaml
   ```
   ```bash
   kubectl -n lab-control create secret generic basic-auth --from-literal=user=admin --from-literal=hash='<bcrypt hash>'
   ```
   ```bash
   kubectl -n lab-control create secret generic n8n --from-literal=encryption-key='<long random string, never change it>'
   ```
   ```bash
   kubectl -n lab-control create secret docker-registry ghcr --docker-server=ghcr.io --docker-username=<github user> --docker-password=<token with read:packages>
   ```
   - **The login hash:** the bcrypt hash is the same format as `CADDY_HASH` in `deploy/.env`. You can reuse that, or make
     one with `docker run --rm caddy:2 caddy hash-password --plaintext '<password>'`.
   - **Optional, gated Hugging Face models:**
     `kubectl -n lab-control create secret generic hf --from-literal=token=<hf token>`.
2. **Edit the overlay** (onprem / cloud). The values marked `EDIT` in its `patches.yaml`: storage class, host name,
   ingress class (`kubectl get ingressclass`).
3. **Apply:**
   ```bash
   kubectl apply -k deploy/k8s/overlays/dev
   ```
   Use `overlays/onprem` or `overlays/cloud` on a GPU cluster.
4. **Open the console:** through the Ingress host, or without one:
   ```bash
   kubectl -n lab-control port-forward svc/console 8080:8080
   ```
   http://localhost:8080, user and password from step 1. The login is a Caddy sidecar in the console pod, so it is the
   same behind any ingress controller.
5. **Open n8n** (not on the Ingress):
   ```bash
   kubectl -n lab-control port-forward svc/n8n 5678:5678
   ```
   - **Credentials:**
     - Ollama `http://ollama.lab-control.svc:11434` (judge, embeddings);
     - Qdrant `http://qdrant.lab-control.svc:6333`;
     - the operator model at `http://glm-serve.lab-model.svc:8000`. In dev that is Ollama (an Ollama credential with that
       Base URL); on GPU overlays it is vLLM (an OpenAI credential with Base URL `.../v1`).
   - **Workflow:** import `deploy/n8n/workflows/pentest-copilot.json` and publish it.

## The model server (glm-serve)

- **GPU overlays:** glm-serve starts at **0 replicas**, because there is nothing to serve until weights are on the
  `models` volume. Phase 2 adds the download → measure → edit → evaluate Jobs and Promote. Until then a checkpoint you
  place at `/models/serving/current` is served with:
  ```bash
  kubectl -n lab-model scale deploy/glm-serve --replicas=1
  ```
- **vLLM version:** pinned to `v0.34.0`, not verified with GLM-5.x. Smoke-test it on the GPU node first, and adjust
  `VLLM_ARGS` (ConfigMap `glm-serve`) for your GPUs and GLM's reasoning output.
- **Re-applying an overlay resets glm-serve to its manifest replicas** (0 on GPU overlays). That fails safe, but start it
  again afterwards.

**Kill / Isolate by hand.** The console gets buttons for these in phase 4. These are the same calls, and its
ServiceAccount is allowed exactly these:

| Action | Commands |
| --- | --- |
| Isolate (model keeps running, no traffic) | `kubectl -n lab-model delete networkpolicy glm-serve-allow` |
| Release | `kubectl apply -k deploy/k8s/overlays/<overlay>` (re-creates the policy; also resets replicas) |
| Kill | `kubectl -n lab-model delete networkpolicy glm-serve-allow`<br>`kubectl -n lab-model scale deploy/glm-serve --replicas=0`<br>`kubectl -n lab-model delete pod -l app=glm-serve --grace-period=0 --force` |

Network policies only ever allow traffic, so isolation removes the allow and `default-deny` stays. Adding a "deny"
policy next to the allow would change nothing.

## Tested in CI

`.github/workflows/k8s-e2e.yml` runs `tests/e2e.sh` on a kind cluster with Calico on every push that touches `deploy/k8s`:
1. server-side dry run of the dev, onprem and cloud overlays, then the ci overlay rolls out;
2. traffic:
   - allowed: console → model server, console → n8n;
   - blocked: a stranger pod → model server / n8n / Qdrant; the model server → the internet / Qdrant;
3. login: 401 without or with a wrong password, 200 with the right one;
4. RBAC: the console may scale glm-serve, delete pods in `lab-model`, and delete or create the allow policy. It may not:
   - exec into pods;
   - read secrets;
   - touch other Deployments or `default-deny`;
   - act outside `lab-model`;
5. Isolate/Release and Kill/Start, performed as the console's ServiceAccount, including how long it takes until the model's
   container is gone from the node.

Not covered by CI: GPUs, vLLM with real weights, the real console image (CI uses a stub behind the real login).
