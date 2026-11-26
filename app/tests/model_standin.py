"""Deterministic stand-in for the copilot's models, for end-to-end tests on machines without GPUs (CI, kind).

One process answers both APIs the copilot uses:
  OpenAI   GET /v1/models, POST /v1/chat/completions (stream or not)   the operator (glm-serve), free prompts
  Ollama   POST /api/chat (stream or not), /api/embed, /api/embeddings, GET /api/tags, /api/version, POST /api/show
                                                                      the judge and the embeddings

The operator's proposal depends on words in the TASK, so a test can walk every branch of the workflow:
  (default)  nmap -sV -Pn <target>            read-only: passes policy and judge, auto-run tier
  "brute"    hydra ... ssh://<target>          not read-only: authorized, parked at Human approval (execution waits)
  "destroy"  rm -rf / --no-preserve-root       blocked by the policy gate
  "reject"   nmap -sV -Pn <target>            the judge answers REJECT
  "slow"     the operator answers after 4 s (to watch a run while it is still running)
A chat request without a TARGET line (a free prompt) gets "stand-in answer to: <prompt>".
GET /_seen lists the last model requests (path, model, last user message), so a test can check which model the copilot
asked and what the prompt said (e.g. that the rules of engagement reached the operator and the judge).

    python app/tests/model_standin.py [PORT]      (default 11434; standard library only)

Used by the console's unit tests (imported) and by the Kubernetes e2e test, which runs it in place of the copilot's
Ollama (deploy/k8s/tests/pipeline-e2e.sh).
"""
import collections
import json
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DIM = 768                                     # nomic-embed-text
SEEN = collections.deque(maxlen=200)          # model requests, newest last: GET /_seen


def text_of(messages):
    out = []
    for m in messages or []:
        c = m.get("content")
        if isinstance(c, list):                   # OpenAI content parts
            c = " ".join(p.get("text", "") for p in c if isinstance(p, dict))
        out.append(str(c or ""))
    return "\n".join(out)


def last_user(messages):
    for m in reversed(messages or []):
        if m.get("role") in ("user", "human"):
            c = m.get("content")
            return " ".join(p.get("text", "") for p in c if isinstance(p, dict)) if isinstance(c, list) else str(c or "")
    return ""


def operator_answer(messages):
    user = last_user(messages)
    task = (re.search(r"TASK:\s*(.*)", user) or [None, ""])[1].lower()
    m = re.search(r"TARGET[^:\n]*:\s*(\S+)", user)
    if not m:                                     # a free prompt, not a copilot run
        return f"stand-in answer to: {user.strip()[:80]}"
    target = m.group(1)
    if "slow" in task:
        time.sleep(4)
    if "destroy" in task:
        cmd = "rm -rf / --no-preserve-root"
    elif "brute" in task:
        cmd = f"hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://{target}"
    else:
        cmd = f"nmap -sV -Pn {target}"
    return json.dumps({"command": cmd, "target": target, "rationale": "stand-in operator"})


def judge_answer(messages):
    # only the TASK line decides: the judge's system prompt itself names both verdicts
    task = (re.search(r"TASK:\s*(.*)", last_user(messages)) or [None, ""])[1].lower()
    return "REJECT\nstand-in judge: rejected" if "reject" in task else "AUTHORIZE\nstand-in judge: in scope"


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):
        sys.stdout.write("%s %s\n" % (self.command, self.path))
        sys.stdout.flush()

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw) if raw else {}
        except ValueError:
            return {}

    def _json(self, obj, code=200):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _stream(self, ctype, chunks):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for c in chunks:
            data = c.encode()
            self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")

    def do_GET(self):
        if self.path.startswith("/v1/models"):
            return self._json({"object": "list", "data": [{"id": "glm-abl", "object": "model", "owned_by": "stand-in"}]})
        if self.path.startswith("/api/tags"):
            return self._json({"models": [{"name": n, "model": n, "size": 1, "digest": "0" * 64} for n in
                                          ("glm-abl:latest", "qwen3:8b", "nomic-embed-text:latest")]})
        if self.path.startswith("/api/version"):
            return self._json({"version": "0.0.0-standin"})
        if self.path in ("/", "/healthz"):
            return self._json({"ok": True})
        if self.path.startswith("/_seen"):
            return self._json({"requests": list(SEEN)})
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        b = self._body()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if self.path.startswith(("/v1/chat/completions", "/api/chat", "/api/generate")):
            msgs = b.get("messages") or [{"role": "user", "content": b.get("prompt", "")}]
            SEEN.append({"path": self.path, "model": b.get("model"), "user": last_user(msgs)[:4000]})
        if self.path.startswith("/v1/chat/completions"):
            answer = operator_answer(b.get("messages"))
            model, cid = b.get("model", "glm-abl"), "chatcmpl-standin"
            if b.get("stream"):
                words = re.findall(r"\S+\s*", answer) or [answer]
                limit = b.get("max_tokens") or b.get("max_completion_tokens")
                if limit:
                    words = words[:int(limit)]
                chunks = [f"data: {json.dumps({'id': cid, 'object': 'chat.completion.chunk', 'created': int(time.time()), 'model': model, 'choices': [{'index': 0, 'delta': {'content': w}, 'finish_reason': None}]})}\n\n" for w in words]
                chunks.append(f"data: {json.dumps({'id': cid, 'object': 'chat.completion.chunk', 'created': int(time.time()), 'model': model, 'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]})}\n\n")
                chunks.append("data: [DONE]\n\n")
                return self._stream("text/event-stream", chunks)
            return self._json({"id": cid, "object": "chat.completion", "created": int(time.time()), "model": model,
                               "choices": [{"index": 0, "message": {"role": "assistant", "content": answer}, "finish_reason": "stop"}],
                               "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}})
        if self.path.startswith("/api/chat") or self.path.startswith("/api/generate"):
            msgs = b.get("messages") or [{"role": "user", "content": b.get("prompt", "")}]
            answer = judge_answer(msgs)
            model = b.get("model", "qwen3:8b")
            final = {"model": model, "created_at": now, "done": True, "done_reason": "stop", "total_duration": 1,
                     "load_duration": 1, "prompt_eval_count": 1, "prompt_eval_duration": 1, "eval_count": 1, "eval_duration": 1}
            key = "message" if self.path.startswith("/api/chat") else "response"
            if b.get("stream", True):
                lines = [json.dumps({"model": model, "created_at": now, key: ({"role": "assistant", "content": answer} if key == "message" else answer), "done": False}) + "\n",
                         json.dumps({**final, key: ({"role": "assistant", "content": ""} if key == "message" else "")}) + "\n"]
                return self._stream("application/x-ndjson", lines)
            return self._json({**final, key: ({"role": "assistant", "content": answer} if key == "message" else answer)})
        if self.path.startswith("/api/embed"):
            inp = b.get("input")
            n = len(inp) if isinstance(inp, list) else 1
            vec = [0.01] * DIM
            if self.path.startswith("/api/embeddings"):
                return self._json({"embedding": vec})
            return self._json({"model": b.get("model", "nomic-embed-text"), "embeddings": [vec] * n})
        if self.path.startswith("/api/show"):
            return self._json({"modelfile": "", "parameters": "", "template": "{{ .Prompt }}", "details": {"family": "stand-in"}})
        return self._json({"error": "not found"}, 404)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 11434
    print(f"model stand-in on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
