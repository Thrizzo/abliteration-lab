r"""Score the copilot operator on held-out pairs (eval.jsonl from copilot.pairs) - so "does RAG / QLoRA help?" is a
measurement, not a feeling.

    # transformers backend (any HF folder: base-abliterated vs fine-tuned merged)
    python -m copilot.eval_operator --data /workspace/finetune/pairs --hf /workspace/out/glm-edge-4b-chat-abliterated
    python -m copilot.eval_operator --data /workspace/finetune/pairs --hf /workspace/finetune/run1/merged
    # Ollama backend (what n8n actually calls)
    python -m copilot.eval_operator --data ... --ollama http://ollama:11434 --model glm-edge-4b-chat-abl-ft
    # with retrieval, exactly as the n8n workflow builds it (Qdrant top-4, addresses neutralized, bounded)
    python -m copilot.eval_operator --data ... --hf ... --rag --qdrant http://qdrant:6333 --embed-ollama http://ollama:11434

Metrics (per pair, then averaged):
  json_ok          the answer is the single-line JSON the n8n Parse node expects
  target_ok        the proposed "target" equals the prompt's TARGET
  hits_target      the command itself contains TARGET (over pairs whose reference command does)
  placeholder      the command contains a <...> placeholder (copied from references or scrubbed text) - never auto-runs
  tool_match       same first token as the reference command
  exact            same command as the reference (whitespace-normalized)
  policy_allowed   deploy/n8n/policy.js would let it through to the judge (allowlist = TARGET; needs node)
  policy_autorun   ... and would auto-run it (passive tier)
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

from .contract import neutral, operator_messages, parse_answer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_JS = os.path.join(ROOT, "deploy", "n8n", "policy.js")
RX_USER = re.compile(r"^TASK: (?P<task>.*?)\nTARGET \(authorized, in scope\): (?P<target>[^\n]+)", re.S)


def load(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


class HF:
    def __init__(self, path, max_new):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(path)
        cuda = torch.cuda.is_available()
        dtype = torch.bfloat16 if cuda or torch.ops.mkldnn._is_mkldnn_bf16_supported() else torch.float32
        self.model = AutoModelForCausalLM.from_pretrained(path, dtype=dtype).to("cuda" if cuda else "cpu").eval()
        self.max_new = max_new

    def __call__(self, messages):
        with self.torch.no_grad():
            enc = self.tok.apply_chat_template(messages, add_generation_prompt=True, return_tensors="pt", return_dict=True).to(self.model.device)
            out = self.model.generate(**enc, max_new_tokens=self.max_new, do_sample=False)
        return self.tok.decode(out[0, enc["input_ids"].shape[1]:], skip_special_tokens=True).strip()


class OllamaChat:
    def __init__(self, host, model, max_new):
        self.host, self.model, self.max_new = host.rstrip("/"), model, max_new

    def __call__(self, messages):
        from .ingest import _req
        body = {"model": self.model, "messages": messages, "stream": False, "options": {"temperature": 0, "num_predict": self.max_new}}
        return _req("POST", f"{self.host}/api/chat", body, timeout=600)["message"]["content"].strip()


def references_for(query, args):
    """Same as the n8n retrieval + Build reference context nodes: top-k from Qdrant, neutralized, bounded."""
    from .ingest import Ollama, _req
    vec = Ollama(args.embed_ollama, args.embed_model).embed([query])[0]
    res = _req("POST", f"{args.qdrant.rstrip('/')}/collections/{args.collection}/points/query",
               {"query": vec, "limit": args.top_k, "with_payload": ["metadata", "content"], "with_vector": False})
    refs, used = [], 0
    for p in res["result"]["points"]:
        md, text = p["payload"].get("metadata") or {}, neutral(p["payload"].get("content", ""))[:1200]
        if used + len(text) > 3500:
            break
        used += len(text)
        refs.append(f"[ref {len(refs) + 1} | {md.get('source', '?')} | {md.get('doc', '')} | score {p['score']:.2f}]\n{text}")
    return "\n\n".join(refs)


def policy_check(rows):
    """Runs deploy/n8n/policy.js decide() over all proposals (allowlist = the pair's TARGET)."""
    node = shutil.which("node")
    if not node or not os.path.isfile(POLICY_JS):
        return None
    js = ("const {decide}=require(process.argv[1]);const rows=JSON.parse(require('fs').readFileSync(0,'utf8'));"
          "console.log(JSON.stringify(rows.map(r=>{const d=decide({command:r.command,target:r.target},"
          "{allowlist:[r.allow],autoRunReadOnly:true});return {allowed:d.allowed,autoRun:d.autoRun};})))")
    out = subprocess.run([node, "-e", js, POLICY_JS], input=json.dumps(rows), capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def norm(c):
    return re.sub(r"\s+", " ", c.strip())


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True, help="folder with eval.jsonl (or a .jsonl file)")
    be = ap.add_mutually_exclusive_group(required=True)
    be.add_argument("--hf", help="HF model folder")
    be.add_argument("--ollama", help="Ollama base URL")
    ap.add_argument("--model", help="Ollama model name (with --ollama)")
    ap.add_argument("--max-new", type=int, default=160)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--rag", action="store_true", help="add retrieved references like the n8n workflow does")
    ap.add_argument("--qdrant", default=os.environ.get("QDRANT_URL", "http://localhost:6333"))
    ap.add_argument("--collection", default=os.environ.get("RAG_COLLECTION", "writeups"))
    ap.add_argument("--embed-ollama", default=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    ap.add_argument("--embed-model", default=os.environ.get("RAG_EMBED_MODEL", "nomic-embed-text"))
    ap.add_argument("--top-k", type=int, default=4)
    ap.add_argument("--out", help="write per-pair results (jsonl) here")
    args = ap.parse_args(argv)

    path = args.data if args.data.endswith(".jsonl") else os.path.join(args.data, "eval.jsonl")
    pairs = load(path)[: args.limit or None]
    if not pairs:
        raise SystemExit(f"no pairs in {path}")
    gen = HF(args.hf, args.max_new) if args.hf else OllamaChat(args.ollama, args.model, args.max_new)
    label = args.hf or f"{args.ollama} {args.model}"
    results = []
    t0 = time.time()
    for p in pairs:
        m = RX_USER.match(p["messages"][1]["content"])
        task, target = m.group("task"), m.group("target").strip()
        gold = json.loads(p["messages"][2]["content"])
        refs = references_for(f"{task} {target}", args) if args.rag else ""
        raw = gen(operator_messages(task, target, refs))
        prop, ok = parse_answer(raw)
        cmd = prop["command"]
        results.append({"doc": p["meta"]["doc"], "target": target, "gold": gold["command"], "command": cmd, "raw": raw[:400],
                        "json_ok": ok, "target_ok": prop["target"].strip() == target,
                        "gold_hits": target in gold["command"], "hits_target": target in cmd,
                        "placeholder": bool(re.search(r"<[A-Za-z][\w-]{0,40}>", cmd)),
                        "tool_match": (cmd.split() or [""])[0] == (gold["command"].split() or [""])[0],
                        "exact": norm(cmd) == norm(gold["command"]), "refs": bool(refs)})
    pol = policy_check([{"command": r["command"], "target": r["target"], "allow": r["target"]} for r in results])
    if pol:
        for r, d in zip(results, pol):
            r["policy_allowed"], r["policy_autorun"] = d["allowed"], d["autoRun"]

    def rate(key, rows):
        rows = [r for r in rows if key in r]
        return f"{sum(bool(r[key]) for r in rows)}/{len(rows)}" if rows else "n/a"
    network = [r for r in results if r["gold_hits"]]
    summary = {"model": label, "rag": args.rag, "pairs": len(results), "seconds": round(time.time() - t0),
               "json_ok": rate("json_ok", results), "target_ok": rate("target_ok", results),
               "hits_target": rate("hits_target", network), "placeholder": rate("placeholder", results),
               "tool_match": rate("tool_match", results), "exact": rate("exact", results),
               "policy_allowed": rate("policy_allowed", results), "policy_autorun": rate("policy_autorun", results)}
    print(json.dumps(summary))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
