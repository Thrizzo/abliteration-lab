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

kill $PF 2>/dev/null
echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
