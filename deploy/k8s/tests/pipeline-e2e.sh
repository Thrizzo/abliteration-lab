#!/usr/bin/env bash
# Phase-2 end-to-end test: the REAL console image (built from this commit, CPU torch, loaded into kind as
# ghcr.io/thrizzo/redteam-llm-lab:ci) runs every pipeline stage as a Kubernetes Job, driven through the same API the GUI
# uses, on a tiny random GLM (deploy/k8s/tests/make_tiny_glm.py). Then Promote and Rollback publish runs to glm-serve.
#
#   1. download / scan / apply / validate / deploy each run as a Job; the GUI's status, log and run endpoints follow them
#   2. Job hygiene: only the download Job may reach the internet, only deploy may reach the model server
#   3. every run keeps its own model folder and its own GGUF
#   4. Promote run 1, Promote run 2 (different layer: glm-serve's model changes), Rollback (run 1's model is back)
#   5. Stop deletes a running Job
#   6. the kill switch through the login: cross-site and body-less POSTs refused; Isolate cuts traffic while the
#      model runs, Release restores it; Kill removes the container from the node within seconds and nothing restarts
#      it; Start brings it back; every action is audited with the login user, on the workspace and in the log
#   7. copilot runs through REAL n8n (the model stand-in answers as operator, judge and embeddings): connect_console.py
#      sets n8n up and the console picks up its Secret without a restart; every branch (approval / policy / judge /
#      scope) arrives as one event per stage; Stop cancels a waiting run; the webhook needs the secret; the console's
#      n8n key can only read and stop executions; a free prompt streams from glm-serve; feed and audit record it all
set -uo pipefail
cd "$(dirname "$0")/../../.."
pass=0; fail=0
ok()    { echo "ok   $*"; pass=$((pass + 1)); }
bad()   { echo "FAIL $*"; fail=$((fail + 1)); }
check() { local name=$1; shift; if "$@"; then ok "$name"; else bad "$name"; fi; }
console() { kubectl -n lab exec deploy/console -c app -- "$@"; }
console_stdin() { kubectl -n lab exec -i deploy/console -c app -- "$@"; }
API() { curl -sS -u ci:ci-only-password -H 'Content-Type: application/json' "http://127.0.0.1:18080/api$1" "${@:2}"; }
# POST to the console API: true on HTTP 2xx, otherwise prints the status and the answer
post_ok() {
  local out code
  out=$(API "$1" -d "$2" -w '\n%{http_code}') || { echo "  POST $1 failed" >&2; return 1; }
  code=${out##*$'\n'}
  [ "${code:0:1}" = 2 ] || { echo "  POST $1 -> HTTP $code: ${out%$'\n'*}" >&2; return 1; }
}

# start a stage through the console; wait until it is no longer running; echo "<run_id> <exit_code>"
# a stage that fails prints the end of its log (stderr), so the CI log shows why
run_stage() {
  local body=$1 st i code
  st=$(API /pipeline/start -d "$body") || { echo "start failed: $st" >&2; echo "- -1"; return; }
  if ! jq -e .running >/dev/null <<<"$st"; then echo "start refused: $st" >&2; echo "- -1"; return; fi
  for i in $(seq 1 450); do
    st=$(API /pipeline/status)
    [ "$(jq -r .running <<<"$st")" = false ] && break
    sleep 2
  done
  code=$(jq -r .exit_code <<<"$st")
  if [ "$code" != 0 ]; then
    echo "  stage exited with $code; end of its log:" >&2
    API '/pipeline/log?start=0' | jq -r '.lines[-25:][]' | sed 's/^/  | /' >&2
  fi
  echo "$(jq -r .run_id <<<"$st") $code"
}
served_digest() { console curl -s http://glm-serve.lab.svc:8000/api/tags | jq -r '.models[] | select(.name == "glm-abl:latest") | .digest'; }
# wait until a promote / rollback has finished; false if it timed out or reported an error
serving_done() {
  local i st
  for i in $(seq 1 120); do
    st=$(API /serving)
    if [ "$(jq -r .busy <<<"$st")" = null ]; then
      [ "$(jq -r .error <<<"$st")" = null ] && return 0
      echo "  serving error: $(jq -r .error <<<"$st")" >&2; return 1
    fi
    sleep 2
  done
  echo "  serving still busy: $(jq -r .busy <<<"$st")" >&2; return 1
}

echo "== deploy (ci-pipeline overlay)"
kubectl apply -f deploy/k8s/base/namespaces.yaml >/dev/null
# the copilot's Ollama is replaced by the model stand-in in CI (overlays/ci-pipeline/standin.yaml); its code:
kubectl -n lab-copilot create configmap model-standin --from-file=app/tests/model_standin.py --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl apply -k deploy/k8s/overlays/ci-pipeline >/dev/null
check "rollout console" kubectl -n lab rollout status deploy/console --timeout=600s
check "rollout glm-serve" kubectl -n lab rollout status deploy/glm-serve --timeout=600s
kubectl -n lab port-forward svc/console 18080:8080 >/dev/null 2>&1 &
PF=$!
for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:18080/ && break; sleep 1; done
check "console runs in Kubernetes mode" test "$(API /env | jq -r .runner)" = k8s

echo "== tiny GLM (built inside the console pod; only GLM-Edge's config and tokenizer are downloaded)"
check "make tiny GLM" console_stdin /opt/venv/bin/python - /workspace/src/tiny-glm < deploy/k8s/tests/make_tiny_glm.py
SMALL='"device_map": "cpu", "dtype": "float32", "n_train": 8, "n_test": 2, "batch": 4, "gen_batch": 2, "max_new_tokens": 4, "layer_range": "0.25-0.75"'

echo "== 1. stages as Jobs"
read -r _ code < <(run_stage '{"engine": "abliterate", "stage": "download", "model": "/workspace/src/tiny-glm"}')
check "download Job exit 0" test "$code" = 0
check "download fetched the prompt datasets" console test -f /workspace/data/harmful_train.jsonl
read -r RUN1 code < <(run_stage "{\"engine\": \"abliterate\", \"stage\": \"scan\", \"model\": \"/workspace/src/tiny-glm\", $SMALL}")
check "scan Job exit 0 (run $RUN1)" test "$code" = 0
check "scan paused at the layer choice" test "$(API "/runs/$RUN1" | jq -r .meta.status)" = awaiting_choice
check "GUI log shows the Job's output" bash -c "curl -sS -u ci:ci-only-password 'http://127.0.0.1:18080/api/pipeline/log?start=0' | jq -e '[.lines[] | select(test(\"paused after the scan\"))] | length > 0' >/dev/null"
read -r _ code < <(run_stage "{\"engine\": \"abliterate\", \"stage\": \"apply\", \"run_id\": \"$RUN1\", \"layer\": 1}")
check "apply Job exit 0" test "$code" = 0
check "run 1 has its own model folder" console test -f "/workspace/runs/abliterate_$RUN1/model/config.json"
read -r _ code < <(run_stage "{\"engine\": \"abliterate\", \"stage\": \"validate\", \"run_id\": \"$RUN1\"}")
check "validate Job exit 0" test "$code" = 0
read -r _ code < <(run_stage "{\"engine\": \"abliterate\", \"stage\": \"deploy\", \"run_id\": \"$RUN1\"}")
check "deploy Job exit 0 (GGUF + import into glm-serve)" test "$code" = 0
check "run 1 has its own GGUF" console bash -c "ls /workspace/gguf/ | grep -q 'abl-abliterate_$RUN1'"
check "run 1 has its Ollama A/B report" console test -f "/workspace/runs/abliterate_$RUN1/ollama_ab.json"

echo "== 2. Job hygiene"
label() { kubectl -n lab get jobs -l "lab-stage=$1" -o jsonpath="{.items[0].metadata.labels['$2']}"; }
check "download Job: internet yes" test "$(label download lab-egress-internet)" = true
check "scan Job: no internet, no model server" test -z "$(label scan lab-egress-internet)$(label scan lab-egress-model)"
check "deploy Job: model server yes, internet no" test "$(label deploy lab-egress-model)/$(label deploy lab-egress-internet)" = "true/"
check "Jobs run without a ServiceAccount token" test "$(kubectl -n lab get jobs -l app=lab-job -o jsonpath='{.items[*].spec.template.spec.automountServiceAccountToken}' | tr ' ' '\n' | sort -u)" = false

echo "== 3/4. Promote, a second run, Rollback"
check "promote run 1 accepted" post_ok /serving/promote "{\"run_id\": \"$RUN1\"}"
check "promote run 1 finished without error" serving_done
check "serving reports run 1" test "$(API /serving | jq -r .current.run_id)" = "$RUN1"
D1=$(served_digest)
check "glm-serve serves glm-abl after promote" test -n "$D1"
read -r RUN2 code < <(run_stage "{\"engine\": \"abliterate\", \"stage\": \"scan\", \"model\": \"/workspace/src/tiny-glm\", $SMALL}")
check "second run scanned ($RUN2)" test "$code" = 0 -a "$RUN2" != "$RUN1"
read -r _ code < <(run_stage "{\"engine\": \"abliterate\", \"stage\": \"apply\", \"run_id\": \"$RUN2\", \"layer\": 2}")
check "second run applied (layer 2)" test "$code" = 0
read -r _ code < <(run_stage "{\"engine\": \"abliterate\", \"stage\": \"deploy\", \"run_id\": \"$RUN2\"}")
check "second run deployed" test "$code" = 0
check "run 1's model folder is still there" console test -f "/workspace/runs/abliterate_$RUN1/model/config.json"
check "promote run 2 accepted" post_ok /serving/promote "{\"run_id\": \"$RUN2\"}"
check "promote run 2 finished without error" serving_done
D2=$(served_digest)
check "glm-serve's model changed with run 2 (per-run GGUF)" test -n "$D2" -a -n "$D1" -a "$D2" != "$D1"
check "rollback accepted" post_ok /serving/rollback '{}'
check "rollback finished without error" serving_done
check "serving reports run 1 again" test "$(API /serving | jq -r .current.run_id)" = "$RUN1"
D3=$(served_digest)
check "glm-serve serves run 1's exact model again" test -n "$D3" -a "$D3" = "$D1"
check "history: promote, promote, rollback" test "$(API /serving | jq -r '[.history[].action] | reverse | join(",")')" = "promote,promote,rollback"

echo "== 5. Stop"
st=$(API /pipeline/start -d "{\"engine\": \"abliterate\", \"stage\": \"scan\", \"model\": \"/workspace/src/tiny-glm\", \"device_map\": \"cpu\", \"dtype\": \"float32\", \"n_train\": 64, \"n_test\": 16, \"max_new_tokens\": 64}")
JOB=$(jq -r .job <<<"$st")
sleep 5
API /pipeline/stop -d '{}' >/dev/null
for i in $(seq 1 60); do [ "$(API /pipeline/status | jq -r .running)" = false ] && break; sleep 1; done
check "stop: no longer running" test "$(API /pipeline/status | jq -r .running)" = false
check "stop: Job $JOB deleted" bash -c "! kubectl -n lab get job '$JOB' >/dev/null 2>&1"

echo "== 6. Kill switch (through the login, as the browser calls it)"
not()   { ! "$@"; }
eventually() { local i; for i in $(seq 1 20); do "$@" && return 0; sleep 1; done; return 1; }
state() { API /control | jq -r .state; }
# the model's container on the node, from the container runtime's view (not the API's)
model_containers() { docker exec lab-control-plane crictl ps -q --label io.kubernetes.pod.namespace=lab --label io.kubernetes.container.name=server | wc -l; }
reach_model() { console curl -s -o /dev/null -m 5 http://glm-serve.lab.svc:8000/api/tags; }
code_of() { curl -s -o /dev/null -w '%{http_code}' -u ci:ci-only-password "$@"; }
CTL=http://127.0.0.1:18080/api/control
check "model server running" test "$(state)" = running
check "cross-site POST refused (Origin)" test "$(code_of -H 'Origin: https://evil.example' -H 'Content-Type: application/json' -d '{}' $CTL/kill)" = 403
check "cross-site POST refused (Sec-Fetch-Site)" test "$(code_of -H 'Sec-Fetch-Site: cross-site' -H 'Content-Type: application/json' -d '{}' $CTL/kill)" = 403
check "POST without a JSON body refused" test "$(code_of -X POST $CTL/kill)" = 422
check "the model still runs after those" test "$(state)" = running
out=$(API /control/isolate -H 'Origin: http://127.0.0.1:18080' -d '{"reason": "ci: isolate"}')
check "isolate ok (same-origin browser request)" test "$(jq -r .ok <<<"$out")" = true
check "isolate: state isolated" test "$(state)" = isolated
check "isolate: the console can no longer reach the model" eventually not reach_model
check "isolate: the model keeps running" test "$(model_containers)" = 1
check "release ok" test "$(API /control/release -d '{}' | jq -r .ok)" = true
check "release: the console reaches the model again" eventually reach_model
t0=$(date +%s%N)
out=$(API /control/kill -d '{"reason": "ci: kill"}')
until [ "$(model_containers)" = 0 ]; do
  [ $(( ($(date +%s%N) - t0) / 1000000 )) -gt 30000 ] && break
  sleep 0.2
done
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
check "kill ok: $(jq -r .message <<<"$out")" test "$(jq -r .ok <<<"$out")" = true
check "kill: container gone from the node in ${ms} ms (< 10 s)" test "$ms" -lt 10000
sleep 10
check "kill: nothing restarted it" test "$(model_containers)" = 0
check "kill: state killed" test "$(state)" = killed
check "start ok" test "$(API /control/start -d '{}' | jq -r .ok)" = true
check "start: model ready" kubectl -n lab rollout status deploy/glm-serve --timeout=300s
check "start: the console reaches the model" eventually reach_model
check "audit: start, kill, release, isolate, each by user ci" test "$(API /control | jq -r '[.audit[] | select(.source == "control") | "\(.stage):\(.who.user)"] | .[0:4] | join(",")')" = "start:ci,kill:ci,release:ci,isolate:ci"
check "audit: the isolate reason is kept" test "$(API /control | jq -r '[.audit[] | select(.stage == "isolate")][0].data.reason')" = "ci: isolate"
check "audit: written to the workspace" console bash -c 'grep -q "\"stage\": \"kill\"" /workspace/audit/*.jsonl'
check "audit: copied to the console's container log" bash -c "kubectl -n lab logs deploy/console -c app | grep -q '^AUDIT .*\"stage\": \"kill\"'"

echo "== 7. Copilot runs through real n8n, free prompts, the live feed"
check "rollout n8n" kubectl -n lab-copilot rollout status deploy/n8n --timeout=600s
check "rollout the model stand-in (in place of the copilot's Ollama)" kubectl -n lab-copilot rollout status deploy/ollama --timeout=300s
kubectl -n lab-copilot port-forward svc/n8n 15678:5678 >/dev/null 2>&1 &
PF2=$!
for i in $(seq 1 120); do [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:15678/rest/settings)" = 200 ] && break; sleep 2; done
check "connect_console.py: owner, API keys, credentials, workflow published, console Secret" python3 deploy/n8n/connect_console.py \
  --n8n http://127.0.0.1:15678 --email ci@lab.test --password Ci-Only-Owner-Pass-1 --setup-owner \
  --operator-url http://ollama.lab-copilot.svc:11434/v1 --apply-secret
copilot_ready() { local i; for i in $(seq 1 120); do [ "$(API /copilot | jq -r .configured)" = true ] && return 0; sleep 2; done; return 1; }
check "the console picks up the Secret (no restart)" copilot_ready
# start a run through the console, wait until it reaches one of the given states, echo the run
copilot_run() {
  local task=$1 target=$2 st id i run s; shift 2
  st=$(API /copilot/run -d "$(jq -cn --arg t "$task" --arg g "$target" '{task: $t, target: $g}')")
  id=$(jq -r '.id // empty' <<<"$st")
  [ -n "$id" ] || { echo "  copilot run refused: $st" >&2; echo '{}'; return; }
  for i in $(seq 1 120); do
    run=$(API "/copilot/runs/$id")
    for s in "$@"; do [ "$(jq -r .status <<<"$run")" = "$s" ] && { echo "$run"; return; }; done
    sleep 1
  done
  echo "  run $id stayed $(jq -r .status <<<"$run")" >&2; echo "$run"
}
stages() { jq -r '[.events[].stage | select(. != "error")] | join(",")' <<<"$1"; }
R=$(copilot_run "Enumerate services on the box" 10.10.10.5 waiting done error)
check "run: authorized, parked at Human approval (auto-run is off)" test "$(jq -r '.status + " / " + .result.title' <<<"$R")" = "waiting / Authorized: waiting for your approval"
check "run: one event per stage ($(stages "$R"))" test "$(stages "$R")" = "start,scope,retrieval,proposal,policy,judge,result,approval"
check "run: the operator's proposal, as the console shows it" test "$(jq -r .result.command <<<"$R")" = "nmap -sV -Pn 10.10.10.5"
RID=$(jq -r .id <<<"$R")
check "stop the waiting run from the console" post_ok "/copilot/runs/$RID/stop" '{}'
run_status() { local i; for i in $(seq 1 30); do [ "$(API "/copilot/runs/$1" | jq -r .status)" = "$2" ] && return 0; sleep 1; done; return 1; }
check "the run is canceled in n8n" run_status "$RID" canceled
B=$(copilot_run "destroy the box" 10.10.10.5 done error)
check "run: rm -rf blocked by the policy gate; the judge never saw it" test "$(jq -r .result.title <<<"$B") / $(stages "$B")" = "Blocked by the policy gate / start,scope,retrieval,proposal,policy,result,end"
J=$(copilot_run "reject this scan" 10.10.10.5 done error)
check "run: blocked by the judge" test "$(jq -r .result.title <<<"$J")" = "Blocked: the judge rejected it"
O=$(copilot_run "Enumerate services" 8.8.8.8 done error)
check "run: out of scope, no model called" test "$(jq -r .result.title <<<"$O") / $(stages "$O")" = "Blocked: target out of scope / start,scope,result,end"
check "n8n refuses the webhook without the secret" test "$(console curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' http://n8n.lab-copilot.svc:5678/webhook/copilot-run)" = 403
check "the console's n8n key may not list workflows (execution scopes only)" test "$(console sh -c 'curl -s -o /dev/null -w "%{http_code}" -H "X-N8N-API-KEY: $(cat /etc/lab-copilot/n8n-api-key)" http://n8n.lab-copilot.svc:5678/api/v1/workflows')" = 403
P=$(curl -sS -N -u ci:ci-only-password -H 'Content-Type: application/json' -d '{"prompt": "Say hello.", "max_tokens": 8}' http://127.0.0.1:18080/api/model/chat)
check "free prompt streamed from glm-serve: $(tail -n 1 <<<"$P" | jq -c .)" test "$(tail -n 1 <<<"$P" | jq -r .done)" = true
check "feed: Jobs, the kill switch, Promote, copilot runs and model events" test "$(API '/feed?limit=500' | jq -r '[.events[].source] | unique | join(",")')" = "control,copilot,model,pipeline,serving"
check "audit: the copilot run's start and stop by user ci" test "$(API /control | jq -r --arg id "$RID" '[.audit[] | select(.source == "copilot" and .run_id == $id) | "\(.stage):\(.who.user)"] | sort | join(",")')" = "end:ci,start:ci,stop:ci"
check "audit: the free prompt and its answer" test "$(API /control | jq -r '[.audit[] | select(.source == "model" and .stage == "prompt")][0].data.prompt')" = "Say hello."
kill $PF2 2>/dev/null

kill $PF 2>/dev/null
echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
