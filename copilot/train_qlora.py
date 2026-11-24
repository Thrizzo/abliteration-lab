r"""QLoRA fine-tuning of the copilot's operator on pairs from copilot.pairs - on the matrices that READ the residual stream
only, so the abliteration cannot be undone through the adapter.

    pip install -r copilot/requirements-finetune.txt          # peft (+ bitsandbytes for 4-bit on CUDA)
    python -m copilot.pairs --src /workspace/writeups --out /workspace/finetune/pairs
    # Option B (default): train the ABLITERATED model - safe by construction (see below), merge, check, import to Ollama
    python -m copilot.train_qlora --model /workspace/out/glm-edge-4b-chat-abliterated --data /workspace/finetune/pairs \
        --out /workspace/finetune/run1 --merge --to-ollama glm-edge-4b-chat-abl-ft
    # Option A: train the BASE model, merge, then run the abliterate pipeline on the merged folder (abliteration last)

Why read-side only. Abliteration made every matrix that WRITES into the residual stream - token embedding, attention
output, MLP/expert output (abliterate.arch.classify: embed / attn_out / mlp_out) - unable to produce the refusal direction
r (r^T W = 0). A LoRA on those matrices adds dW that can write r again. A LoRA on the read side (q/k/v, gate/up) only
changes what the orthogonalized writers receive; whatever they receive, they still cannot write r. So the target modules
are derived from the same classifier the edit used, and after merging every write-side tensor is checked to be
bit-identical to the input model (the run fails otherwise). Exact for pre-norm families such as GLM-Edge; for post-norm
GLM-4 the edit is folded through the norm. A LoRA could still learn a *new* refusal along another direction if the data
taught refusals; writeups do not, and the eval (copilot.eval_operator) is where you would see it.

4-bit (QLoRA proper) needs CUDA + bitsandbytes; without them this trains a bf16/fp32 LoRA (fine for small models and the
smoke test, slow on CPU). Merging always reloads the base in bf16, never from the 4-bit copy.
"""
import argparse
import glob
import json
import math
import os
import random
import shutil
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from abliterate.arch import EXCLUDE, classify  # noqa: E402

WRITE_KINDS = ("embed", "attn_out", "mlp_out")
KEEP_FILES = (".json", ".jinja", ".txt", ".model", ".tiktoken", ".py")


def read_side_targets(model):
    """Full names of the Linear layers that may get a LoRA: everything that is not a residual-stream writer, not the
    LM head, not a vision/router/indexer module."""
    import torch.nn as nn
    targets, writers = [], []
    for name, mod in model.named_modules():
        if not isinstance(mod, nn.Linear) and type(mod).__name__ not in ("Linear4bit", "Linear8bitLt"):
            continue
        if name.endswith("lm_head") or EXCLUDE.search(name + "."):
            continue
        (writers if classify(name + ".weight") in WRITE_KINDS else targets).append(name)
    return targets, writers


def load_pairs(path, tok, max_len):
    """Tokenizes chat pairs; loss only on the assistant answer (prompt tokens are -100)."""
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            msgs = json.loads(line)["messages"]
            prompt = tok.apply_chat_template(msgs[:-1], add_generation_prompt=True, tokenize=True, return_dict=True)["input_ids"]
            answer = tok(msgs[-1]["content"], add_special_tokens=False)["input_ids"] + ([tok.eos_token_id] if tok.eos_token_id is not None else [])
            ids = (prompt + answer)[-max_len:]
            labels = ([-100] * len(prompt) + answer)[-max_len:]
            if any(l != -100 for l in labels):
                rows.append((ids, labels))
    return rows


def batches(rows, size, pad_id, shuffle, seed):
    import torch
    order = list(range(len(rows)))
    if shuffle:
        random.Random(seed).shuffle(order)
    for i in range(0, len(order), size):
        chunk = [rows[j] for j in order[i:i + size]]
        n = max(len(ids) for ids, _ in chunk)
        ids = torch.full((len(chunk), n), pad_id)
        lab = torch.full((len(chunk), n), -100)
        att = torch.zeros((len(chunk), n), dtype=torch.long)
        for k, (a, b) in enumerate(chunk):                # left padding, like the pipeline's tokenizer
            ids[k, n - len(a):] = torch.tensor(a)
            lab[k, n - len(b):] = torch.tensor(b)
            att[k, n - len(a):] = 1
        yield ids, att, lab


def eval_loss(model, rows, args, pad_id, device):
    import torch
    if not rows:
        return None
    model.eval()
    tot, n = 0.0, 0
    with torch.no_grad():
        for ids, att, lab in batches(rows, args.batch, pad_id, False, 0):
            out = model(input_ids=ids.to(device), attention_mask=att.to(device), labels=lab.to(device))
            tot += out.loss.item() * ids.shape[0]
            n += ids.shape[0]
    model.train()
    return tot / max(1, n)


def tensors_of(folder):
    from safetensors import safe_open
    out = {}
    for f in sorted(glob.glob(os.path.join(folder, "*.safetensors"))):
        with safe_open(f, "pt") as h:
            for k in h.keys():
                out[k] = (f, k)
    return out


def verify_write_side_unchanged(src, merged, log):
    """Every residual-stream writer of the merged model must be bit-identical to the input model."""
    import torch
    from safetensors import safe_open
    a, b = tensors_of(src), tensors_of(merged)
    checked, changed = 0, []
    handles = {}
    get = lambda f: handles.setdefault(f, safe_open(f, "pt"))
    for k in a:
        if classify(k) not in WRITE_KINDS:
            continue
        if k not in b:
            changed.append(k + " (missing)")
            continue
        ta, tb = get(a[k][0]).get_tensor(k), get(b[k][0]).get_tensor(k)
        checked += 1
        if ta.shape != tb.shape or ta.dtype != tb.dtype or not torch.equal(ta, tb):
            changed.append(k)
    log(f"verify: {checked} write-side tensors compared, {len(changed)} changed")
    return checked, changed


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True, help="HF folder to train (abliterated = Option B, base = Option A)")
    ap.add_argument("--data", required=True, help="folder with train.jsonl / eval.jsonl from copilot.pairs")
    ap.add_argument("--out", required=True)
    ap.add_argument("--epochs", type=float, default=2.0)
    ap.add_argument("--max-steps", type=int, default=0, help="stop after N optimizer steps (smoke tests)")
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--alpha", type=int, default=32)
    ap.add_argument("--dropout", type=float, default=0.05)
    ap.add_argument("--batch", type=int, default=4)
    ap.add_argument("--grad-accum", type=int, default=4)
    ap.add_argument("--max-len", type=int, default=1024)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--4bit", dest="four_bit", choices=("auto", "on", "off"), default="auto",
                    help="QLoRA 4-bit base (needs CUDA + bitsandbytes); auto = on when available")
    ap.add_argument("--merge", action="store_true", help="merge the adapter into a bf16 copy and verify the write side")
    ap.add_argument("--to-ollama", metavar="NAME", help="after --merge: convert to GGUF q8_0 and import into Ollama as NAME")
    ap.add_argument("--project", default=os.environ.get("ABL_PROJECT", os.getcwd()), help="lab project (for the GGUF converter)")
    args = ap.parse_args(argv)

    import torch
    from peft import LoraConfig, PeftModel, get_peft_model
    from transformers import AutoModelForCausalLM, AutoTokenizer

    os.makedirs(args.out, exist_ok=True)
    log_f = open(os.path.join(args.out, "train.log"), "a", encoding="utf-8")

    def log(msg):
        line = f"{time.strftime('%H:%M:%S')} {msg}"
        print(line, flush=True)
        log_f.write(line + "\n")
        log_f.flush()

    torch.manual_seed(args.seed)
    cuda = torch.cuda.is_available()
    device = "cuda" if cuda else "cpu"
    four_bit = args.four_bit == "on" or (args.four_bit == "auto" and cuda)
    if four_bit:
        try:
            import bitsandbytes  # noqa: F401
        except ImportError:
            if args.four_bit == "on":
                raise SystemExit("--4bit on needs bitsandbytes (pip install -r copilot/requirements-finetune.txt) and CUDA")
            four_bit = False
    tok = AutoTokenizer.from_pretrained(args.model)
    tok.padding_side = "left"
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    dtype = torch.bfloat16 if (cuda or (hasattr(torch.ops, "mkldnn") and torch.ops.mkldnn._is_mkldnn_bf16_supported())) else torch.float32
    if four_bit:
        from peft import prepare_model_for_kbit_training
        from transformers import BitsAndBytesConfig
        q = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.bfloat16)
        model = AutoModelForCausalLM.from_pretrained(args.model, quantization_config=q, device_map={"": 0})
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    else:
        model = AutoModelForCausalLM.from_pretrained(args.model, dtype=dtype).to(device)
        model.gradient_checkpointing_enable()
        model.enable_input_require_grads()
    targets, writers = read_side_targets(model)
    log(f"model {args.model} | {'4-bit QLoRA' if four_bit else str(dtype).replace('torch.', '') + ' LoRA'} on {device}")
    log(f"LoRA targets: {len(targets)} read-side Linear layers (e.g. {sorted({t.rsplit('.', 1)[-1] for t in targets})}); "
        f"excluded {len(writers)} residual writers ({sorted({w.rsplit('.', 1)[-1] for w in writers})}) and lm_head")
    if not targets:
        raise SystemExit("no read-side Linear layers found - unknown architecture, refusing to guess")
    model = get_peft_model(model, LoraConfig(r=args.rank, lora_alpha=args.alpha, lora_dropout=args.dropout,
                                             target_modules=targets, bias="none", task_type="CAUSAL_LM"))
    lora_on_writers = [n for n, _ in model.named_modules() if n.endswith("lora_A") and classify(n.replace("base_model.model.", "").rsplit(".lora_A", 1)[0] + ".weight") in WRITE_KINDS]
    assert not lora_on_writers, f"LoRA attached to residual writers: {lora_on_writers[:3]}"
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    log(f"trainable parameters: {trainable:,}")

    train = load_pairs(os.path.join(args.data, "train.jsonl"), tok, args.max_len)
    evalr = load_pairs(os.path.join(args.data, "eval.jsonl"), tok, args.max_len) if os.path.isfile(os.path.join(args.data, "eval.jsonl")) else []
    log(f"pairs: {len(train)} train, {len(evalr)} eval (max_len {args.max_len})")
    if not train:
        raise SystemExit("no training pairs - run python -m copilot.pairs first")
    steps_per_epoch = math.ceil(len(train) / args.batch / args.grad_accum)
    total = args.max_steps or max(1, int(steps_per_epoch * args.epochs))
    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=args.lr, weight_decay=0.0)
    sched = torch.optim.lr_scheduler.LambdaLR(opt, lambda s: min(1.0, (s + 1) / max(1, total // 10)) * max(0.0, 1 - s / total))
    pad_id = tok.pad_token_id
    history = {"eval_loss_before": eval_loss(model, evalr, args, pad_id, device)}
    log(f"eval loss before: {history['eval_loss_before']}")
    model.train()
    step, micro, t0, losses = 0, 0, time.time(), []
    epoch = 0
    while step < total:
        for ids, att, lab in batches(train, args.batch, pad_id, True, args.seed + epoch):
            loss = model(input_ids=ids.to(device), attention_mask=att.to(device), labels=lab.to(device)).loss / args.grad_accum
            loss.backward()
            losses.append(loss.item() * args.grad_accum)
            micro += 1
            if micro % args.grad_accum == 0:
                torch.nn.utils.clip_grad_norm_([p for p in model.parameters() if p.requires_grad], 1.0)
                opt.step(); sched.step(); opt.zero_grad()
                step += 1
                log(f"step {step}/{total} loss {sum(losses[-args.grad_accum:]) / args.grad_accum:.4f} ({time.time() - t0:.0f}s)")
                if step >= total:
                    break
        epoch += 1
    history["eval_loss_after"] = eval_loss(model, evalr, args, pad_id, device)
    log(f"eval loss after: {history['eval_loss_after']}")
    adapter_dir = os.path.join(args.out, "adapter")
    model.save_pretrained(adapter_dir)
    tok.save_pretrained(adapter_dir)
    meta = {"model": args.model, "four_bit": four_bit, "targets": len(targets), "excluded_writers": len(writers),
            "steps": step, "train_pairs": len(train), "eval_pairs": len(evalr), **history, "args": vars(args)}

    if args.merge:
        del model
        merged_dir = os.path.join(args.out, "merged")
        base = AutoModelForCausalLM.from_pretrained(args.model, dtype=torch.bfloat16)   # never merge into the 4-bit copy
        merged = PeftModel.from_pretrained(base, adapter_dir).merge_and_unload()
        merged.save_pretrained(merged_dir, safe_serialization=True)
        for fn in os.listdir(args.model):                   # tokenizer, chat template, generation config
            if fn.endswith(KEEP_FILES) and not fn.startswith("model.safetensors") and not os.path.exists(os.path.join(merged_dir, fn)):
                shutil.copyfile(os.path.join(args.model, fn), os.path.join(merged_dir, fn))
        checked, changed = verify_write_side_unchanged(args.model, merged_dir, log)
        meta.update(merged=merged_dir, write_side_checked=checked, write_side_changed=changed)
        if changed:
            json.dump(meta, open(os.path.join(args.out, "run.json"), "w"), indent=2)
            raise SystemExit(f"write-side tensors changed after merge ({changed[:3]}...): the abliteration may be undone - not using this model")
        log(f"merged model: {merged_dir} (all {checked} residual writers bit-identical to the input)")
        if args.to_ollama:
            from abliterate import deploy as DP
            gguf = os.path.join(args.project, "gguf", f"{args.to_ollama}-q8_0.gguf")
            DP.convert_gguf(args.project, merged_dir, gguf, log, outtype="q8_0")
            tpl = "".join(open(os.path.join(merged_dir, fn), encoding="utf-8").read()
                          for fn in ("chat_template.jinja", "tokenizer_config.json") if os.path.isfile(os.path.join(merged_dir, fn)))
            DP.ollama_create(args.to_ollama, gguf, tpl, None, log)
            meta["ollama"] = args.to_ollama
            log(f"ollama: imported as {args.to_ollama} - set it in the n8n operator node, then run copilot.eval_operator")
    json.dump(meta, open(os.path.join(args.out, "run.json"), "w"), indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
