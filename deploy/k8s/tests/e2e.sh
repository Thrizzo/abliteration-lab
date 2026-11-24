#!/usr/bin/env bash
# End-to-end test of deploy/k8s on a kind cluster with Calico (network policies enforced).
# Run by .github/workflows/k8s-e2e.yml; locally: create the cluster as the workflow does, then run this script.
#
# What it proves, on a real API server and a real network plugin:
#   1. every overlay is accepted by the API server (server-side dry run), and the ci overlay comes up
#   2. network policies: the console may reach the model server and n8n, anything else may not; the model server
#      cannot reach the internet or other pods
#   3. the login: Caddy in the console pod answers 401 without or with a wrong password, 200 with the right one
#   4. RBAC: the console ServiceAccount may do exactly Kill / Isolate / Start on the model server and nothing else
#   5. Isolate (as the console): traffic stops, the model keeps running; Release brings it back
#   6. Kill (as the console): the model's container is gone within seconds and nothing restarts it; Start brings it back
set -uo pipefail
cd "$(dirname "$0")/../../.."
OVERLAY=deploy/k8s/overlays/ci
NODE=${KIND_NODE:-lab-control-plane}
CONSOLE=system:serviceaccount:lab:console
GLM=http://glm-serve.lab.svc:8000/
pass=0; fail=0
ok()    { echo "ok   $*"; pass=$((pass + 1)); }
bad()   { echo "FAIL $*"; fail=$((fail + 1)); }
check() { local name=$1; shift; if "$@"; then ok "$name"; else bad "$name"; fi; }
not()   { ! "$@"; }
as_console() { kubectl --as="$CONSOLE" "$@"; }
can()   { kubectl auth can-i "$@" --as="$CONSOLE" >/dev/null 2>&1; }
# an HTTP answer within 5 s from inside a probe pod (any status counts: this tests the network, not the app)
reach() { kubectl -n lab exec "$1" -- curl -s -o /dev/null -m 5 "$2"; }
eventually() { local i; for i in $(seq 1 20); do "$@" && return 0; sleep 1; done; return 1; }
# the model server's container on the node, from the container runtime's view (not the API's)
model_containers() { docker exec "$NODE" crictl ps -q --label io.kubernetes.pod.namespace=lab --label io.kubernetes.container.name=server | wc -l; }

echo "== 1. deploy"
kubectl apply -f deploy/k8s/base/namespaces.yaml
for o in dev onprem cloud ci-pipeline; do
  check "server-side dry run: $o" kubectl apply --dry-run=server -k "deploy/k8s/overlays/$o" -o name
done
kubectl apply -k "$OVERLAY"
for w in deploy/n8n deploy/ollama statefulset/qdrant; do
  check "rollout $w (lab-copilot)" kubectl -n lab-copilot rollout status "$w" --timeout=600s
done
for w in deploy/console deploy/glm-serve; do
  check "rollout $w (lab)" kubectl -n lab rollout status "$w" --timeout=600s
done

# probe pods: one the policies treat as the console, one they treat as a stranger
for p in console intruder; do
  kubectl -n lab run "probe-$p" --image=curlimages/curl:8.23.0 --restart=Never --labels="lab-role=$p" \
    --command -- sleep 3600 >/dev/null
done
kubectl -n lab wait --for=condition=Ready pod/probe-console pod/probe-intruder --timeout=180s >/dev/null

echo "== 2. network policies"
QDRANT_IP=$(kubectl -n lab-copilot get pod qdrant-0 -o jsonpath='{.status.podIP}')
check "console -> model server" eventually reach probe-console "$GLM"
check "console -> n8n" reach probe-console http://n8n.lab-copilot.svc:5678/healthz
check "stranger -/-> model server" not reach probe-intruder "$GLM"
check "stranger -/-> n8n" not reach probe-intruder http://n8n.lab-copilot.svc:5678/healthz
check "stranger -/-> qdrant" not reach probe-intruder "http://$QDRANT_IP:6333/"
# precondition, so a missing shell cannot pass the negative checks below
check "model server container has bash + timeout" kubectl -n lab exec deploy/glm-serve -- timeout 5 bash -c true
check "model server -/-> internet" not kubectl -n lab exec deploy/glm-serve -- timeout 5 bash -c '</dev/tcp/1.1.1.1/443'
check "model server -/-> qdrant" not kubectl -n lab exec deploy/glm-serve -- timeout 5 bash -c "</dev/tcp/$QDRANT_IP/6333"

echo "== 3. login (Caddy in the console pod)"
kubectl -n lab port-forward svc/console 18080:8080 >/dev/null 2>&1 &
PF=$!
eventually curl -s -o /dev/null http://127.0.0.1:18080/
code() { curl -s -o /dev/null -w '%{http_code}' "$@" http://127.0.0.1:18080/; }
check "no password -> 401" test "$(code)" = 401
check "wrong password -> 401" test "$(code -u ci:wrong)" = 401
check "right password -> 200" test "$(code -u ci:ci-only-password)" = 200
kill $PF 2>/dev/null

echo "== 4. RBAC of the console ServiceAccount"
check "may scale glm-serve" can patch deployments/glm-serve --subresource=scale -n lab
check "may delete pods in lab" can delete pods -n lab
check "may delete glm-serve-allow" can delete networkpolicies/glm-serve-allow -n lab
check "may create network policies in lab" can create networkpolicies -n lab
check "may create Jobs in lab" can create jobs.batch -n lab
check "may read pod logs in lab" can get pods --subresource=log -n lab
check "may patch the glm-serve ConfigMap (Promote)" can patch configmaps/glm-serve -n lab
check "may NOT patch other ConfigMaps" not can patch configmaps/lab-jobs -n lab
check "may NOT delete default-deny" not can delete networkpolicies/default-deny -n lab
check "may NOT exec into pods" not can create pods --subresource=exec -n lab
check "may NOT read secrets" not can get secrets -n lab
check "may NOT scale other deployments" not can patch deployments/other --subresource=scale -n lab
check "may NOT create deployments" not can create deployments -n lab
check "may NOT create Jobs in lab-copilot" not can create jobs.batch -n lab-copilot
check "may NOT delete pods in lab-copilot" not can delete pods -n lab-copilot
check "may NOT delete pods in kube-system" not can delete pods -n kube-system

echo "== 5. Isolate and Release (as the console)"
kubectl -n lab get networkpolicy glm-serve-allow -o json \
  | jq 'del(.metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .metadata.generation, .metadata.managedFields, .metadata.annotations)' \
  > /tmp/glm-serve-allow.json
check "isolate: delete glm-serve-allow" as_console -n lab delete networkpolicy glm-serve-allow
check "isolate: console can no longer reach the model" eventually not reach probe-console "$GLM"
check "isolate: model keeps running" test "$(model_containers)" = 1
check "release: re-create glm-serve-allow" as_console create -f /tmp/glm-serve-allow.json
check "release: console reaches the model again" eventually reach probe-console "$GLM"

echo "== 6. Kill and Start (as the console)"
t0=$(date +%s%N)
as_console -n lab delete networkpolicy glm-serve-allow >/dev/null
as_console -n lab scale deploy/glm-serve --replicas=0 >/dev/null
as_console -n lab delete pod -l app=glm-serve --grace-period=0 --force --wait=false >/dev/null 2>&1
until [ "$(model_containers)" = 0 ]; do
  [ $(( ($(date +%s%N) - t0) / 1000000 )) -gt 30000 ] && break
  sleep 0.2
done
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
check "kill: container gone from the node in ${ms} ms (< 10 s)" test "$ms" -lt 10000
sleep 15
check "kill: nothing restarted it" test "$(model_containers)" = 0
check "kill: Deployment stays at 0" test "$(kubectl -n lab get deploy glm-serve -o jsonpath='{.spec.replicas}')" = 0
check "start: re-create glm-serve-allow" as_console create -f /tmp/glm-serve-allow.json
check "start: scale to 1" as_console -n lab scale deploy/glm-serve --replicas=1
check "start: model ready" kubectl -n lab rollout status deploy/glm-serve --timeout=300s
check "start: console reaches the model" eventually reach probe-console "$GLM"

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
