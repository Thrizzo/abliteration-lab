"""Copilot runs, the live feed and free prompts for the lab console (app/copilot_runs.py; the copilot/ package is the
RAG and fine-tuning side).

Feed         one in-memory stream of events {seq, ts, source, run_id, stage, level, message, data} that the GUI polls:
             copilot runs, free prompts, the kill switch and Promote/Rollback (through the audit log), pipeline Jobs,
             the model server's state.
CopilotRuns  starts the n8n copilot through its webhook (shared secret, X-Lab-Secret), follows the execution through
             n8n's API (one event per finished node: scope, retrieval, the operator's prompt and answer, policy, the
             judge's prompt and verdict, the staged command, result) and can stop it. Two modes: copilot (the
             abliterated model proposes) and manual (the operator typed the command: same policy gate and judge).
             Each run carries the chosen models and the active engagement (app/engagement.py); a run whose policy
             gate does not report checking all of its protected data (a workflow older than the console) is stopped.
             Nothing here executes a command: the console shows the staged command, and the Execute node is disabled.
CopilotModels the models a run can use: operators from glm-serve (/v1/models), judges from the copilot's Ollama
             (/api/tags) without abliterated or embedding models. The judge vetoes the abliterated operator, so it is
             never an abliterated model (n8n refuses one too).
ModelChat    free prompts straight to the model server's OpenAI-compatible API (glm-serve), streamed token by token.
             They skip the policy gate and the judge: this is model testing, and nothing can execute either way.

The webhook secret and the n8n API key are read from files (a mounted Secret, COPILOT_SECRETS_DIR) on every use, so
deploy/n8n/connect_console.py can set or rotate them without a console restart. Standard library only.
"""
import collections
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

WEBHOOK_PATH = "copilot-run"
SECRET_FILES = {"webhook-secret": "COPILOT_WEBHOOK_SECRET", "n8n-api-key": "N8N_API_KEY"}
FINAL = ("success", "error", "canceled", "crashed")
# a model name that marks an abliterated model ("glm-abl", "<slug>-abl" from the pipeline, "...-abliterated",
# "uncensored"): never the judge. Mirrors ABLITERATED in deploy/n8n/build_workflow.js.
ABLITERATED = re.compile(r"(^|[-_:./])abl($|[-_:./])|abliterat|uncensor", re.I)
MODEL_NAME = re.compile(r"[A-Za-z0-9][\w.:/-]{0,127}")       # what the workflow accepts as a model name
MODES = ("copilot", "manual")


def abliterated(name):
    return bool(ABLITERATED.search(str(name or "")))


def now_iso():
    t = datetime.now(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def cut(s, n):
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n] + " ..."


class Feed:
    """The live feed: a bounded, ordered stream. Readers ask for everything after the last seq they saw."""

    def __init__(self, maxlen=2000):
        self.lock = threading.Lock()
        self.events = collections.deque(maxlen=maxlen)
        self.seq = 0

    def emit(self, source, stage, message, level="info", data=None, run_id=None, ts=None):
        with self.lock:
            self.seq += 1
            ev = {"seq": self.seq, "ts": ts or now_iso(), "source": source, "run_id": run_id, "stage": stage, "level": level,
                  "message": message, "data": data or {}}
            self.events.append(ev)
        return ev

    def since(self, after=0, limit=200, source=None):
        with self.lock:
            evs = [e for e in self.events if e["seq"] > after and (not source or e["source"] == source)]
            latest = self.seq
        evs = evs[:limit]
        return {"events": evs, "next": evs[-1]["seq"] if evs else max(after, 0), "latest": latest}


# ------------------------------------------------------------------ n8n execution -> feed events
def _out(entry):
    try:
        return entry["data"]["main"][0][0]["json"] or {}
    except (KeyError, IndexError, TypeError):
        return {}


def result_card(j):
    """What the console shows at the end of a run, from the workflow's result node (the console escapes it). "staged" is
    the command the Execute node would get: the policy-vetted one, only when every gate passed."""
    pol, prop = j.get("policy") or {}, j.get("proposal") or {}
    allowed, auto = j.get("allowed") is True, j.get("autoRun") is True
    reasons = []
    review = list(pol.get("dataReview") or []) if allowed and not auto else []     # why it waits while data is protected
    for r in ([j.get("scopeReason")] if j.get("scopeOk") is False else []) + list(pol.get("reasons") or []) + list(j.get("reasons") or []) \
            + review:
        if r and r not in reasons:
            reasons.append(r)
    if allowed and auto:
        nxt = "Handed to the Execute node, which is disabled: nothing ran."
    elif allowed:
        nxt = "Parked at Human approval in n8n. Nothing runs until it is resumed, and the Execute node is disabled."
    elif j.get("scopeOk") is False:
        nxt = ("No model was called. If the target belongs to your lab, add it to LAB_ALLOWLIST."
               if "LAB_ALLOWLIST" in str(j.get("scopeReason") or "LAB_ALLOWLIST") else
               "No model was called. The engagement decides this: change its scope or window if the target belongs to it.")
    else:
        nxt = "Nothing runs."
    eng = j.get("engagement") if isinstance(j.get("engagement"), dict) else None
    return {"title": j.get("resultTitle") or ("Authorized" if allowed else "Blocked"), "allowed": allowed, "autoRun": auto,
            "tier": j.get("tier") or pol.get("tier"), "target": cut(j.get("target"), 200), "task": cut(j.get("task"), 400),
            "command": cut(pol.get("command") or prop.get("command"), 800), "rationale": cut(prop.get("rationale"), 400),
            "judge": cut(j.get("judgeVerdict"), 300) if "judgeVerdict" in j else None,
            "staged": cut(j.get("staged") or (pol.get("command") if allowed else ""), 2000) if allowed else "",
            "mode": j.get("mode") or "copilot", "operator_model": j.get("operatorModel") or None, "judge_model": j.get("judgeModel") or None,
            "engagement": {"name": cut(eng.get("name"), 120), "version": eng.get("version")} if eng else None,
            "reasons": [cut(r, 300) for r in reasons[:8]], "next": nxt}


def node_event(name, entry):
    """(stage, message, level, data) for a finished node the operator cares about, else None. Never the webhook's
    own output: it carries the request headers, the shared secret included."""
    j = _out(entry)
    if name == "Scope gate":
        ok = j.get("scopeOk") is True
        return "scope", (f"in scope: {cut(j.get('target'), 120)} ({j.get('scopeBy') or 'LAB_ALLOWLIST'})" if ok
                         else cut(j.get("scopeReason") or "out of scope", 200)), \
            "info" if ok else "warn", {"target": cut(j.get("target"), 200), "scopeOk": ok, "scopeBy": j.get("scopeBy"),
                                       "reason": cut(j.get("scopeReason"), 300)}
    if name == "Build reference context":
        st, n = str(j.get("ragStatus") or ""), j.get("refCount") or 0
        return "retrieval", cut(st, 200) + (f" ({n} references)" if n else ""), "warn" if st.startswith("retrieval failed") else "info", \
            {"ragStatus": cut(st, 300), "refCount": n}
    if name == "Build operator prompt":
        prompt, model = str(j.get("operatorPrompt") or ""), j.get("operatorModel") or "glm-abl"
        return "prompt", f"prompt to the abliterated model {cut(model, 80)} ({len(prompt)} characters)", "info", \
            {"model": cut(model, 128), "prompt": cut(prompt, 12000), "refCount": j.get("refCount") or 0}
    if name == "Parse proposal":
        prop = j.get("proposal") or {}
        cmd = prop.get("command")
        return "proposal", (f"operator proposes: {cut(cmd, 300)}" if cmd else "the operator gave no command"), "info", \
            {"proposal": {k: cut(prop.get(k), 800) for k in ("command", "target", "rationale")}, "raw": cut(j.get("rawProposal"), 4000),
             "model": cut(j.get("operatorModel"), 128)}
    if name == "Manual proposal":
        prop = j.get("proposal") or {}
        return "proposal", f"typed by the operator: {cut(prop.get('command'), 300)}", "info", \
            {"proposal": {k: cut(prop.get(k), 800) for k in ("command", "target", "rationale")}, "manual": True}
    if name == "Policy gate":
        pol = j.get("policy") or {}
        if pol.get("allowed"):
            if pol.get("autoRun"):
                how = f"auto-run tier {pol.get('tier')}"
            elif pol.get("injectionSuspected"):
                how = "needs a human: text aimed at the judge"
            elif pol.get("dataReview"):
                how = "needs a human: " + cut(pol["dataReview"][0], 160) + \
                    (f" (+{len(pol['dataReview']) - 1} more)" if len(pol["dataReview"]) > 1 else "")
            elif pol.get("unverifiable"):
                how = "needs a human: a target the gate cannot verify (" + "; ".join(cut(u, 60) for u in pol["unverifiable"][:2]) + ")"
            elif pol.get("namesInScopeHost") is False:
                how = "needs a human: the command names no in-scope host"
            elif pol.get("readOnly") or pol.get("activeRecon"):
                how = "needs a human: auto-run is off for this tier (LAB_AUTORUN_* or the engagement)"
            else:
                how = "needs a human: " + cut(pol.get("readOnlyReason") or "not read-only", 160)
            msg, level = f"policy: passed ({how})", "info"
        else:
            msg, level = "policy: blocked - " + "; ".join(cut(r, 160) for r in (pol.get("reasons") or [])[:3]), "warn"
        return "policy", msg, level, {k: pol.get(k) for k in ("allowed", "autoRun", "tier", "readOnly", "injectionSuspected", "unverifiable")} | \
            {"reasons": [cut(r, 300) for r in (pol.get("reasons") or [])[:8]], "prohibited": pol.get("prohibited") or [],
             "command": cut(pol.get("command"), 2000), "protectedData": pol.get("protectedData") or [],
             "dataReview": [cut(r, 300) for r in (pol.get("dataReview") or [])[:6]],
             # entries the gate checked; an older workflow leaves it out (CopilotRuns.absorb stops such a run)
             "protectedEntries": pol.get("protectedEntries")}
    if name == "Build judge prompt":
        prompt, model = str(j.get("judgePrompt") or ""), j.get("judgeModel") or "qwen3:8b"
        return "judge_prompt", f"prompt to the judge {cut(model, 80)} ({len(prompt)} characters)", "info", \
            {"model": cut(model, 128), "prompt": cut(prompt, 12000)}
    if name == "Apply judge decision":
        verdict = str(j.get("judgeVerdict") or "").strip()
        first = verdict.splitlines()[0] if verdict else "(empty answer)"
        return "judge", f"judge: {cut(first, 160)} -> " + ("authorized" if j.get("allowed") else "blocked"), \
            "info" if j.get("allowed") else "warn", {"verdict": cut(verdict, 500), "authorized": j.get("judgeAuthorized") is True,
                                                     "allowed": j.get("allowed") is True, "autoRun": j.get("autoRun") is True,
                                                     "staged": cut(j.get("staged"), 2000), "model": cut(j.get("judgeModel"), 128),
                                                     "reasons": [cut(r, 300) for r in (j.get("reasons") or [])[:8]]}
    if name in ("Result text (authorized)", "Result text (blocked)"):
        card = result_card(j)
        return "result", card["title"], "info" if card["allowed"] else "warn", card
    if name == "Human approval" and entry.get("executionStatus") == "waiting":
        return "approval", "parked at Human approval: nothing runs until it is resumed in n8n, and the Execute node is disabled", \
            "warn", {}
    if name.startswith("Execute on lab target"):
        return "execute", "the Execute node is disabled: nothing ran", "info", {}
    return None


def _same_model(a, b):
    """Ollama lists "qwen3:8b" and "glm-abl:latest"; "glm-abl" means the latter."""
    norm = lambda n: str(n or "")[:-7] if str(n or "").endswith(":latest") else str(n or "")
    return norm(a) == norm(b)


class CopilotModels:
    """Which models a run may use. Operators: what glm-serve serves (vLLM: the promoted run as glm-abl; Ollama in dev:
    every model it holds). Judges: the copilot's Ollama, minus embedding models and anything abliterated."""

    def __init__(self, operator_url, judge_url, operator_default="glm-abl", judge_default="qwen3:8b", http_error=None,
                 timeout=5, cache_s=10.0):
        self.operator_url, self.judge_url = (operator_url or "").rstrip("/"), (judge_url or "").rstrip("/")
        self.operator_default, self.judge_default = operator_default, judge_default
        self.http_error = http_error or (lambda status, msg: RuntimeError(f"{status}: {msg}"))
        self.timeout, self.cache_s = timeout, cache_s
        self._cache = (0.0, None)
        self.lock = threading.Lock()

    def _get(self, url):
        with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=self.timeout) as r:
            return json.loads(r.read() or b"{}")

    def _operators(self):
        if not self.operator_url:
            return [], "no model server configured (GLM_SERVE_URL)"
        try:
            data = self._get(self.operator_url + "/v1/models").get("data") or []
            return sorted({str(m.get("id")) for m in data if isinstance(m, dict) and m.get("id")}), None
        except (OSError, ValueError, AttributeError) as e:
            return [], f"glm-serve did not list its models: {cut(e, 200)}"

    def _judges(self):
        if not self.judge_url:
            return [], [], "no copilot Ollama configured (RAG_OLLAMA_URL)"
        try:
            tags = self._get(self.judge_url + "/api/tags").get("models") or []
        except (OSError, ValueError, AttributeError) as e:
            return [], [], f"the copilot's Ollama did not list its models: {cut(e, 200)}"
        ok, excluded = [], []
        for m in tags:
            name = str((m or {}).get("name") or "")
            family = str(((m or {}).get("details") or {}).get("family") or "").lower()
            if not name:
                continue
            if "embed" in name.lower() or family in ("bert", "nomic-bert"):
                excluded.append({"name": name, "why": "an embedding model, not a chat model"})
            elif abliterated(name):
                excluded.append({"name": name, "why": "abliterated: the judge must be a regular model"})
            else:
                ok.append(name)
        return sorted(ok), excluded, None

    def list(self, fresh=False):
        with self.lock:
            at, cached = self._cache
            if cached and not fresh and time.time() - at < self.cache_s:
                return cached
        ops, op_err = self._operators()
        judges, excluded, j_err = self._judges()
        out = {"operator": {"models": ops, "default": self.operator_default, "error": op_err},
               "judge": {"models": judges, "excluded": excluded, "default": self.judge_default, "error": j_err}}
        with self.lock:
            self._cache = (time.time(), out)
        return out

    def operator(self, name=None):
        """The model a free prompt goes to: one glm-serve lists (when it can be asked), else http_error(400)."""
        op = str(name or "").strip() or self.operator_default
        if not MODEL_NAME.fullmatch(op):
            raise self.http_error(400, f"model {cut(op, 80)!r} is not a model name")
        lists = self.list()["operator"]
        if name and not lists["error"] and not any(_same_model(op, a) for a in lists["models"]):
            raise self.http_error(400, f"glm-serve has no model {op!r} (it has: {', '.join(lists['models']) or 'none'})")
        return op

    def check(self, operator_model=None, judge_model=None):
        """(operator, judge) for a run: the defaults when none was chosen; http_error(400) for a judge that is
        abliterated or the operator itself, a name that is not a plain model name, or a choice the servers don't list
        (when they could be asked)."""
        op = str(operator_model or "").strip() or self.operator_default
        judge = str(judge_model or "").strip() or self.judge_default
        for role, name in (("operator", op), ("judge", judge)):
            if not MODEL_NAME.fullmatch(name):
                raise self.http_error(400, f"{role} model {cut(name, 80)!r} is not a model name")
        if abliterated(judge) or _same_model(judge, op):
            raise self.http_error(400, f"judge model {judge!r} refused: the judge vetoes the abliterated operator, so it must be a "
                                       f"regular model and not the operator itself")
        lists = self.list()
        for role, name, chosen in (("operator", op, operator_model), ("judge", judge, judge_model)):
            avail = lists[role]["models"]
            if chosen and not lists[role]["error"] and not any(_same_model(name, a) for a in avail):
                where = "glm-serve" if role == "operator" else "the copilot's Ollama"
                raise self.http_error(400, f"{where} has no model {name!r} (it has: {', '.join(avail) or 'none'})")
        return op, judge


class CopilotRuns:
    """Runs of the n8n copilot started from the console, followed live, stoppable."""

    def __init__(self, n8n_url, secrets_dir, feed, audit=None, http_error=None, poll=1.0, waiting_poll=10.0, keep=50):
        self.base = (n8n_url or "").rstrip("/")
        self.secrets_dir, self.feed, self.audit = secrets_dir, feed, audit
        self.http_error = http_error or (lambda status, msg: RuntimeError(f"{status}: {msg}"))
        self.poll, self.waiting_poll, self.keep = poll, waiting_poll, keep
        self.max_failures = 30                 # consecutive failed polls before a run is given up on
        self.max_waiting_s = 6 * 3600          # a run parked at Human approval is followed this long
        self.lock = threading.Lock()
        self.runs = collections.OrderedDict()  # execution id -> run, newest last

    # ---------------------------------------------------------------- configuration
    def secret(self, name):
        try:
            with open(os.path.join(self.secrets_dir or "", name), encoding="utf-8") as f:
                v = f.read().strip()
        except OSError:
            v = ""
        return v or os.environ.get(SECRET_FILES[name], "")

    def missing(self):
        return ([] if self.base else ["N8N_URL"]) + [n for n in SECRET_FILES if not self.secret(n)]

    # ---------------------------------------------------------------- HTTP
    def _http(self, method, path, body=None, headers=None, timeout=30):
        req = urllib.request.Request(self.base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json", "Accept": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            return e.code, cut(e.read().decode("utf-8", "replace"), 300)

    def _api(self, method, path, body=None):
        return self._http(method, "/api/v1" + path, body, {"X-N8N-API-KEY": self.secret("n8n-api-key")})

    # ---------------------------------------------------------------- runs
    def _emit(self, run, stage, message, level="info", data=None):
        ev = self.feed.emit("copilot", stage, message, level, data, run_id=run["id"])
        with self.lock:
            run["events"].append(ev)
        return ev

    def _audit(self, run, stage, message, who, level="info", data=None):
        if self.audit:
            rec = self.audit.write("copilot", stage, message, level=level, who=who, run_id=run["id"], data=data)
            with self.lock:
                run["events"].append({**rec, "seq": None})
        else:
            self._emit(run, stage, message, level, data)

    def start(self, task, target, who=None, mode="copilot", command=None, operator_model=None, judge_model=None, engagement=None):
        """mode copilot: the abliterated model proposes for the task; mode manual: the operator's command goes straight to
        the policy gate and the judge. operator_model / judge_model come checked from CopilotModels; engagement is the
        active one (app/engagement.py) or None."""
        task, target, command = str(task or "").strip(), str(target or "").strip(), str(command or "").strip()
        if mode not in MODES:
            raise self.http_error(400, f"mode is one of: {', '.join(MODES)}")
        if not target or (mode == "copilot" and not task) or (mode == "manual" and not command):
            raise self.http_error(400, "task and target are both required" if mode == "copilot" else "target and command are both required")
        if len(task) > 2000 or len(target) > 253 or any(c.isspace() for c in target):
            raise self.http_error(400, "the task is at most 2000 characters; the target is one host, address or range without spaces")
        if len(command) > 2000 or any(ord(c) < 32 or ord(c) == 127 for c in command):
            raise self.http_error(400, "the command is one line of at most 2000 characters (chain with && if you must)")
        if judge_model and (abliterated(judge_model) or (operator_model and judge_model == operator_model)):
            raise self.http_error(400, f"judge model {judge_model!r} refused: the judge must be a regular model, not the operator")
        missing = self.missing()
        if missing:
            raise self.http_error(409, "the copilot is not connected yet (missing: " + ", ".join(missing)
                                  + "). Run deploy/n8n/connect_console.py once; see deploy/k8s/README.md")
        who = who or {}
        body = {"task": task, "target": target, "requested_by": who.get("user") or "", "mode": mode,
                "command": command if mode == "manual" else "", "operator_model": operator_model or "",
                "judge_model": judge_model or "", "engagement": engagement}
        try:
            st, resp = self._http("POST", f"/webhook/{WEBHOOK_PATH}", body, {"X-Lab-Secret": self.secret("webhook-secret")})
        except OSError as e:
            raise self.http_error(502, f"n8n is not reachable: {e}")
        eid = resp.get("execution_id") if isinstance(resp, dict) else None
        if st not in (200, 202) or not eid:
            hint = " (the webhook secret does not match: re-run connect_console.py)" if st in (401, 403) else \
                " (is the workflow published?)" if st == 404 else ""
            raise self.http_error(502, f"n8n answered {st}{hint}: {cut(resp, 200)}")
        eng = None
        if isinstance(engagement, dict):
            pd = engagement.get("protected_data")
            # how many protected_data entries the run sent: its policy event must report as many (absorb)
            eng = {"name": cut(engagement.get("name"), 120), "version": engagement.get("version"),
                   "protected_data": len(pd) if isinstance(pd, list) else 0}
        run = {"id": str(eid), "task": cut(task, 2000), "target": target, "who": who, "started": now_iso(), "status": "running",
               "mode": mode, "command": cut(command, 2000) if mode == "manual" else None, "operator_model": operator_model,
               "judge_model": judge_model, "engagement": eng,
               "n8n_status": "new", "events": [], "result": None, "_seen": set(), "_waiting_since": None}
        with self.lock:
            self.runs[run["id"]] = run
            while len(self.runs) > self.keep:
                self.runs.popitem(last=False)
        what = f"manual command {cut(command, 120)}" if mode == "manual" else cut(task, 120)
        self._audit(run, "start", f"copilot run {run['id']} ({mode}): {what} -> {target}", who,
                    data={"task": cut(task, 2000), "target": target, "mode": mode, "command": run["command"],
                          "operator_model": operator_model, "judge_model": judge_model, "engagement": eng})
        threading.Thread(target=self._follow, args=(run,), daemon=True).start()
        return self.summary(run)

    def _follow(self, run):
        failures = 0
        while True:
            try:
                st, ex = self._api("GET", f"/executions/{run['id']}?includeData=true")
            except OSError as e:
                st, ex = 0, str(e)
            if st == 200 and isinstance(ex, dict):
                failures = 0
                if self.absorb(run, ex):
                    return
            else:
                failures += 1
                if failures >= self.max_failures:
                    self._emit(run, "error", f"n8n's execution API kept failing ({st}): {cut(ex, 200)}", "error")
                    with self.lock:                  # the event first: whoever sees the run end also finds why
                        run["status"] = "lost"
                    return
            waiting = run["status"] == "waiting"
            if waiting and time.time() - run["_waiting_since"] > self.max_waiting_s:
                self._emit(run, "approval", "no longer followed (waited too long); its state is in n8n", "warn")
                return
            time.sleep(self.waiting_poll if waiting else self.poll)

    def absorb(self, run, ex):
        """New events from one execution snapshot; True once the run has ended."""
        rd = ((ex.get("data") or {}).get("resultData") or {})
        run_data = rd.get("runData") or {}
        status = ex.get("status") or "running"
        last = rd.get("lastNodeExecuted")
        for name in sorted(run_data, key=lambda n: (run_data[n][0] or {}).get("executionIndex", 0)):
            for i, entry in enumerate(run_data[name]):
                key = f"{name}#{i}#{entry.get('executionStatus')}"
                if key in run["_seen"] or entry.get("executionStatus") in ("running", None) and not entry.get("data"):
                    continue
                run["_seen"].add(key)
                err = entry.get("error")
                if err or entry.get("executionStatus") == "error":
                    fatal = status == "error" and name == last
                    msg = (err or {}).get("message") if isinstance(err, dict) else err
                    self._emit(run, "error", f"{name}: {cut(msg or 'failed', 300)}", "error" if fatal else "warn")
                    continue
                ev = node_event(name, entry)
                if ev:
                    stage, message, level, data = ev
                    if stage == "result":
                        with self.lock:
                            run["result"] = data
                    self._emit(run, stage, message, level, data)
                    if stage == "policy":
                        self._enforced(run, data, status)
        with self.lock:
            prev, run["n8n_status"] = run["n8n_status"], status
        if status == "waiting":
            if prev != "waiting":
                with self.lock:
                    run["status"], run["_waiting_since"] = "waiting", time.time()
            return False
        if status in FINAL:
            if status == "error" and rd.get("error") and not any(e["stage"] == "error" and e["level"] == "error" for e in run["events"]):
                self._emit(run, "error", cut((rd.get("error") or {}).get("message") or "the run failed", 300), "error")
            final = {"success": "done"}.get(status, status)
            res = run["result"] or {}
            self._audit(run, "end", f"copilot run {run['id']} {final}" + (f": {res.get('title')}" if res.get("title") else ""),
                        run["who"], level="info" if status in ("success", "canceled") else "error",
                        data={"status": status, "title": res.get("title"), "command": res.get("command"), "allowed": res.get("allowed")})
            with self.lock:                          # after the record: whoever sees the run ended finds its "end" logged
                run["status"] = final
            return True
        with self.lock:
            run["status"] = "running"
        return False

    def _enforced(self, run, data, status):
        """A workflow older than the console drops protected_data without a word, and its gate passes what the list
        names. The policy event reports how many entries the gate checked: a run that sent another number is stopped,
        with the Stop button's n8n call. False when it was not enforced."""
        sent = (run.get("engagement") or {}).get("protected_data") or 0
        got = data.get("protectedEntries")
        if not sent or got == sent:
            return True
        self._audit(run, "error", f"Protected data is not enforced by this workflow (it reported {got or 0} of {sent} entries): "
                                  "re-import deploy/n8n/workflows/pentest-copilot.json", {"user": "console"}, level="error",
                    data={"sent": sent, "reported": got})
        if status not in FINAL:                     # an execution that has already ended has nothing left to stop
            try:
                self.stop(run["id"], {"user": "console"})
            except Exception:                       # noqa: BLE001  409: it ended meanwhile; stop() audits every other failure
                pass
        return False

    def stop(self, run_id, who=None):
        run = self.runs.get(str(run_id))
        if not run:
            raise self.http_error(404, f"no copilot run {run_id} in this console")
        if run["status"] not in ("running", "waiting"):
            raise self.http_error(409, f"run {run_id} has already ended ({run['status']})")
        # Recorded before n8n answers: the follower can see the run canceled, and log its "end", before this call returns.
        self._audit(run, "stop", f"copilot run {run['id']}: stop requested", who or {})
        try:
            st, body = self._api("POST", f"/executions/{run['id']}/stop", {})
        except OSError as e:
            self._audit(run, "stop", f"copilot run {run['id']}: not stopped, n8n is not reachable", who or {}, level="error")
            raise self.http_error(502, f"n8n is not reachable: {e}")
        if st not in (200, 201):
            self._audit(run, "stop", f"copilot run {run['id']}: not stopped, n8n refused ({st})", who or {}, level="error")
            raise self.http_error(502, f"n8n refused to stop it ({st}): {cut(body, 200)}")
        return self.summary(run)

    # ---------------------------------------------------------------- views
    def summary(self, run):
        with self.lock:
            return {"id": run["id"], "task": cut(run["task"], 200), "target": run["target"], "status": run["status"],
                    "started": run["started"], "who": run["who"], "title": (run["result"] or {}).get("title"),
                    "mode": run.get("mode", "copilot"), "command": cut(run.get("command"), 200) if run.get("command") else None}

    def get(self, run_id):
        run = self.runs.get(str(run_id))
        if not run:
            raise self.http_error(404, f"no copilot run {run_id} in this console")
        with self.lock:
            return {**{k: v for k, v in run.items() if not k.startswith("_")}, "events": list(run["events"])}

    def status(self):
        missing = self.missing()
        with self.lock:
            runs = list(reversed(self.runs.values()))
        return {"configured": not missing, "missing": missing, "n8n": self.base or None, "runs": [self.summary(r) for r in runs]}


class ModelChat:
    """Free prompts to the model server's OpenAI-compatible API (vLLM, or Ollama's /v1 in dev), streamed."""

    def __init__(self, base_url, model, feed, audit=None, timeout=600):
        self.base = (base_url or "").rstrip("/")
        self.model, self.feed, self.audit, self.timeout = model, feed, audit, timeout

    def stream(self, prompt, max_tokens=512, who=None, model=None):
        """Yields {"token": ...} per piece, then {"done": true, ...}, or {"error": ...}. Audited in every case, a
        browser that closes the stream early included. model: one glm-serve lists (checked by the caller)."""
        t0, pieces, err = time.time(), [], None
        model = model or self.model
        body = {"model": model, "messages": [{"role": "user", "content": prompt}], "stream": True,
                "max_tokens": int(max_tokens), "temperature": 0}
        req = urllib.request.Request(self.base + "/v1/chat/completions", data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "Accept": "text/event-stream"})
        try:
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    for raw in r:
                        line = raw.decode("utf-8", "replace").strip()
                        if not line.startswith("data:"):
                            continue
                        data = line[5:].strip()
                        if data == "[DONE]":
                            break
                        try:
                            obj = json.loads(data)
                        except ValueError:
                            continue
                        if obj.get("error"):
                            e = obj["error"]
                            err = (e.get("message") if isinstance(e, dict) else str(e)) or "the model server reported an error"
                            break
                        delta = (((obj.get("choices") or [{}])[0]).get("delta") or {}).get("content")
                        if delta:
                            pieces.append(delta)
                            yield {"token": delta}
            except urllib.error.HTTPError as e:
                err = f"HTTP {e.code}: {cut(e.read().decode('utf-8', 'replace'), 300)}"
            except OSError as e:
                err = f"the model server is not reachable: {e}"
            ms = round((time.time() - t0) * 1000)
            yield ({"error": err, "tokens": len(pieces), "ms": ms} if err else {"done": True, "tokens": len(pieces), "ms": ms})
        except GeneratorExit:
            err = err or "the browser closed the stream"
            raise
        finally:
            self._log(prompt, "".join(pieces), len(pieces), round((time.time() - t0) * 1000), err, who, model)

    def _log(self, prompt, answer, n, ms, err, who, model=None):
        model = model or self.model
        msg = f"free prompt to {model}: " + (f"failed after {n} pieces: {cut(err, 160)}" if err else f"{n} pieces in {ms} ms")
        data = {"prompt": cut(prompt, 2000), "answer": cut(answer, 2000), "pieces": n, "ms": ms, "model": model, "error": err}
        if self.audit:
            self.audit.write("model", "prompt", msg, level="error" if err else "info", who=who or {}, data=data)
        else:
            self.feed.emit("model", "prompt", msg, "error" if err else "info", data)


class ModelWatch:
    """The model server's state into the feed when it changes (running, isolated, killed, ...)."""

    def __init__(self, control, feed, every=5.0):
        self.control, self.feed, self.every = control, feed, every
        self.state = None

    def check(self):
        try:
            st = self.control.status()
        except Exception:                           # noqa: BLE001  the next check will tell
            return None
        state = st.get("state")
        if state and state != self.state:
            msg = f"model server {state}" if self.state is None else f"model server {self.state} -> {state}"
            self.feed.emit("model", "state", msg, "warn" if state in ("isolated", "killed", "stopping", "unknown") else "info",
                           {"state": state, "replicas": st.get("replicas"), "ready": st.get("ready")})
            self.state = state
        return state

    def run(self):
        while True:
            self.check()
            time.sleep(self.every)
