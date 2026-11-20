r"""The pipeline: download -> inspect -> load -> measure -> scan -> choose -> apply -> verify -> validate -> gguf -> ollama.
Writes the same artifacts as the notebook run (layer_analysis.json, baseline.json, scan_results.json, generations.json,
validation.json, means.pt, refusal_dirs.pt) plus run.json and events.jsonl (one JSON event per line, for the app).

    python -m abliterate --model THUDM/glm-edge-4b-chat
    python -m abliterate --model THUDM/glm-edge-4b-chat --pause-at-choice          # stops after the scan
    python -m abliterate --run-dir runs/abliterate_<ts> --stage continue --layer 17   # resumes with that layer
    python -m abliterate --model zai-org/GLM-5.2 --device-map auto --skip-verify --no-ollama
    python -m abliterate --model THUDM/glm-edge-1.5b-chat --device-map cpu          # no GPU: everything on the CPU, slower
"""
import argparse
import gc
import glob
import json
import os
import shutil
import sys
import time
from datetime import datetime

from . import arch as A
from . import data as D


class Run:
    def __init__(self, project, run_dir):
        self.project, self.run_dir = project, run_dir
        os.makedirs(run_dir, exist_ok=True)
        self.meta_path = os.path.join(run_dir, "run.json")
        self.meta = json.load(open(self.meta_path, encoding="utf-8")) if os.path.isfile(self.meta_path) else {}
        self.log_f = open(os.path.join(run_dir, "run.log"), "a", encoding="utf-8")
        self.ev_f = open(os.path.join(run_dir, "events.jsonl"), "a", encoding="utf-8")

    def log(self, msg):
        line = f"{datetime.now():%H:%M:%S} {msg}"
        print(line, flush=True)
        self.log_f.write(line + "\n"); self.log_f.flush()

    def event(self, step, status, **payload):
        ev = {"t": time.time(), "step": step, "status": status, **payload}
        self.ev_f.write(json.dumps(ev, ensure_ascii=False) + "\n"); self.ev_f.flush()
        print("EVENT " + json.dumps(ev, ensure_ascii=False), flush=True)

    def save(self, name, obj):
        with open(os.path.join(self.run_dir, name), "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)

    def load(self, name):
        p = os.path.join(self.run_dir, name)
        return json.load(open(p, encoding="utf-8")) if os.path.isfile(p) else None

    def update_meta(self, **kw):
        self.meta.update(kw); self.meta["updated"] = datetime.now().isoformat(timespec="seconds")
        with open(self.meta_path, "w", encoding="utf-8") as f:
            json.dump(self.meta, f, indent=2, ensure_ascii=False)


def slug_of(repo):
    return repo.rstrip("/").split("/")[-1].lower()


# ----------------------------------------------------------------------------- steps
def step_download(run, repo, models_dir, token=None):
    """Local copy under models/<slug>: safe file types only, revision + SHA-256 recorded (like notebook 4.0b)."""
    import hashlib
    slug = slug_of(repo)
    dst = os.path.join(models_dir, slug)
    if not os.path.isfile(os.path.join(dst, "config.json")) and os.path.isdir(models_dir):   # case-insensitive filesystems / hand-copied folders
        for d in os.listdir(models_dir):
            if d.lower() == slug and os.path.isfile(os.path.join(models_dir, d, "config.json")):
                dst = os.path.join(models_dir, d)
                break
    if os.path.isfile(os.path.join(dst, "config.json")):
        run.log(f"model: local copy present {dst}")
        run.event("download", "done", path=dst, cached=True)
        return dst
    if os.path.isdir(repo):
        run.event("download", "start", repo=repo, path=dst, note="copying local folder")
        shutil.copytree(repo, dst, dirs_exist_ok=True)
        run.event("download", "done", path=dst)
        return dst
    from huggingface_hub import HfApi, snapshot_download
    run.event("download", "start", repo=repo, path=dst)
    info = HfApi(token=token).model_info(repo, files_metadata=True)
    total = sum((s.size or 0) for s in info.siblings if s.rfilename.endswith((".safetensors", ".json", ".jinja", ".txt", ".model", ".tiktoken", ".py")))
    run.log(f"model: downloading {repo}@{info.sha[:8]} (~{total / 1e9:.1f} GB) -> {dst}")
    run.event("download", "progress", total_gb=round(total / 1e9, 1))
    snapshot_download(repo, revision=info.sha, local_dir=dst, token=token,
                      allow_patterns=["*.json", "*.safetensors", "*.jinja", "*.txt", "*.model", "*.tiktoken", "*.py", "*.md"])
    hashes = {f: hashlib.sha256(open(os.path.join(dst, f), "rb").read()).hexdigest() for f in sorted(os.listdir(dst)) if f.endswith(".safetensors") and os.path.getsize(os.path.join(dst, f)) < 3e9}
    json.dump({"repo": repo, "revision": info.sha, "downloaded": datetime.now().isoformat(timespec="seconds"), "sha256": hashes},
              open(os.path.join(dst, "local_copy.json"), "w", encoding="utf-8"), indent=2)
    run.event("download", "done", path=dst, revision=info.sha)
    return dst


def step_inspect(run, model_dir):
    info = A.inspect(model_dir)
    run.save("arch.json", info)
    run.update_meta(arch=info)
    run.log(f"arch: {info['family'] or info['model_type']} | {info['n_layers']} layers, d={info['hidden_size']} | "
            f"moe={info['moe']} post_norm={info['post_norm']} quant={bool(info['quantization'])} | support={info['support']}")
    for n in info["notes"]:
        run.log("  note: " + n)
    run.event("inspect", "done", **info)
    if info["support"] == "unsupported":
        raise SystemExit("architecture not supported - see arch.json")
    return info


def step_measure(run, hm, args, prompts):
    import torch
    harmful, _, harmless, _ = prompts
    run.event("measure", "start", n_train=len(harmful), n_layers=hm.n_layers, d_model=hm.d_model)
    prog = lambda lab: (lambda b, n, dt: run.event("measure", "progress", group=lab, batch=b, batches=n, seconds=round(dt, 1)))
    mean_h, nh = hm.mean_resid_pre(harmful, args.batch, "harmful", prog("harmful"))
    mean_hl, nl = hm.mean_resid_pre(harmless, args.batch, "harmless", prog("harmless"))
    dirs = mean_h - mean_hl
    norms = dirs.norm(dim=-1)
    dirs = dirs / norms.clamp_min(1e-8).unsqueeze(-1)
    torch.save(dirs, os.path.join(run.run_dir, "refusal_dirs.pt"))
    torch.save({"mean_h": mean_h, "mean_hl": mean_hl, "norms": norms}, os.path.join(run.run_dir, "means.pt"))
    lo_f, hi_f = (float(x) for x in args.layer_range.split("-"))
    n = hm.n_layers
    scan_lo, scan_hi = max(1, int(lo_f * n)), min(n - 1, int(hi_f * n))
    act_size = (nh + nl) / 2
    separation = (norms / act_size.clamp_min(1e-8) * 100)
    similarity = dirs @ dirs.T
    peak = int(separation[1:].argmax()) + 1
    stable = [l for l in range(n) if similarity[peak, l] > 0.8]
    cos_next = [float(similarity[l, l + 1]) for l in range(n - 1)] + [None]
    la = {"n_layers": n, "d_model": hm.d_model, "scan_range": [scan_lo, scan_hi], "peak": peak, "stable": stable,
          "separation_pct": [float(x) for x in separation], "norms": [float(x) for x in norms], "act_size": [float(x) for x in act_size],
          "similarity": [[round(float(v), 4) for v in row] for row in similarity], "cos_next": cos_next,
          "n_inst_train": len(harmful), "harmful_train_examples": harmful[:12], "harmless_train_examples": harmless[:12]}
    run.save("layer_analysis.json", la)
    run.log(f"measure: strongest separation in layer {peak} ({separation[peak]:.1f}%), stable block {stable[0] if stable else '-'}-{stable[-1] if stable else '-'}, scan {scan_lo}-{scan_hi}")
    run.event("measure", "done", peak=peak, stable=stable, scan_range=[scan_lo, scan_hi], separation_pct=la["separation_pct"], cos_next=cos_next)
    return dirs, la


def step_scan(run, hm, args, prompts, dirs, la):
    harmful_test = prompts[1]
    run.event("scan", "start", n_test=len(harmful_test), layers=list(range(la["scan_range"][0], la["scan_range"][1] + 1)))
    baseline = hm.generate(harmful_test, args.max_new_tokens, args.gen_batch)
    n_base = D.count_refusals(baseline)
    run.save("baseline.json", {"prompts": harmful_test, "baseline": baseline, "n_base": n_base, "scan_layers": list(range(la["scan_range"][0], la["scan_range"][1] + 1))})
    run.log(f"scan: baseline {n_base}/{len(harmful_test)} refusals")
    run.event("scan", "baseline", n_base=n_base, n_test=len(harmful_test), baseline=baseline)
    if n_base <= len(harmful_test) // 4:
        run.log("  warning: the base model barely refuses - check the markers / chat template")
    scan = []
    for l in range(la["scan_range"][0], la["scan_range"][1] + 1):
        t = time.time()
        gens = hm.generate(harmful_test, args.max_new_tokens, args.gen_batch, direction=dirs[l])
        nref = D.count_refusals(gens)
        cjk = sum(D.cjk_ratio(g) for g in gens) / len(gens)
        scan.append({"layer": l, "refusals": nref, "norm": round(la["norms"][l], 3), "cjk_ratio": round(cjk, 3), "generations": gens})
        run.log(f"scan: layer {l:3d} | {nref}/{len(harmful_test)} refusals | cjk {cjk:.2f} | {time.time() - t:4.1f}s | {gens[0][:70]!r}")
        run.event("scan", "layer", layer=l, refusals=nref, cjk_ratio=round(cjk, 3), seconds=round(time.time() - t, 1), generations=gens)
    scan.sort(key=lambda x: (x["refusals"], x["cjk_ratio"], x["layer"]))
    run.save("scan_results.json", scan)
    run.event("scan", "done", top=[(s["layer"], s["refusals"]) for s in scan[:5]])
    return scan, baseline, n_base


def choose_layer(scan):
    ok = [s for s in scan if s["cjk_ratio"] <= 0.2] or scan
    return min(ok, key=lambda s: (s["refusals"], s["cjk_ratio"], s["layer"]))["layer"]


def step_apply(run, args, model_dir, out_dir, dirs, layer, info):
    import torch
    from .edit import Editor
    direction = dirs[layer].clone()
    run.event("apply", "start", layer=layer, out_dir=out_dir, post_norm=info["post_norm"], moe=info["moe"])
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    ed = Editor(model_dir, out_dir, direction, post_norm=info["post_norm"], log=run.log,
                progress=lambda i, n, dt: run.event("apply", "progress", shard=i, shards=n, seconds=round(dt, 1)))
    stats = ed.run()
    torch.save({"layer": layer, "direction": direction}, os.path.join(out_dir, "refusal_direction.pt"))
    run.save("apply.json", {"layer": layer, **{k: v for k, v in stats.items() if k != "changed"}, "changed_preview": stats["changed"][:20]})
    run.update_meta(layer=layer, out_dir=out_dir)
    run.event("apply", "done", layer=layer, n_changed=stats["n_changed"], kinds=stats["kinds"], max_rw=stats["max_rw"], fp8=stats["fp8"], folded=stats["folded"], seconds=stats["seconds"])
    return direction


def step_verify_and_validate(run, args, model_dir, out_dir, direction, layer, prompts, baseline, scan, info):
    """Reloads base and edited model from disk (one at a time), behaviour + weight checks."""
    import torch
    from .hooks import HookedModel, load_model, resolve_device
    from .edit import expected_targets
    from .validate import behaviour_checks, compare_weights, weight_checks
    harmful_test, harmless_test = prompts[1], prompts[3]
    device_map, dtype = resolve_device(args.device_map, args.dtype, run.log)
    results = {}
    for tag, folder in (("base", model_dir), ("abl", out_dir)):
        run.event("validate", "progress", stage=f"loading {tag}")
        m, tok = load_model(folder, dtype, device_map, args.trust_remote_code, run.log)
        hm = HookedModel(m, tok, run.log)
        results[tag] = {"harmful": hm.generate(harmful_test, args.max_new_tokens, args.gen_batch),
                        "harmless": hm.generate(harmless_test, args.max_new_tokens, args.gen_batch),
                        "logits": hm.next_token_logits(harmless_test)}
        del hm, m; gc.collect(); torch.cuda.empty_cache()
    n_after = D.count_refusals(results["abl"]["harmful"])
    run.save("generations.json", {"prompts": harmful_test, "baseline": baseline, "layer": layer, "after_orthogonalization": results["abl"]["harmful"]})
    chosen = next((s["refusals"] for s in scan if s["layer"] == layer), None)
    run.log(f"verify: after the edit {n_after}/{len(harmful_test)} refusals (scan for layer {layer}: {chosen})")
    run.event("verify", "done", n_after=n_after, scan_refusals=chosen, after=results["abl"]["harmful"])
    checks, kl = behaviour_checks(results["base"], results["abl"], len(harmful_test), info["post_norm"])
    run.event("validate", "progress", stage="comparing weights")
    cmp = compare_weights(model_dir, out_dir, direction, run.log, post_norm=info["post_norm"])
    checks += weight_checks(cmp, expected_targets(model_dir), info["post_norm"])
    verdict = "FAIL" if any(c[2] == "FAIL" for c in checks) else ("WARN" if any(c[2] == "WARN" for c in checks) else "PASS")
    report = {"verdict": verdict, "layer": layer, "checks": [dict(zip(("check", "result", "status", "why"), c)) for c in checks],
              "examples": [{"prompt": p, "base": b, "abliterated": a} for p, b, a in zip(harmful_test, results["base"]["harmful"], results["abl"]["harmful"])]}
    run.save("validation.json", report)
    run.save("validation_details.json", {"eval_harmless": harmless_test, "base_harmless": results["base"]["harmless"], "abl_harmless": results["abl"]["harmless"],
                                         "eval_harmful": harmful_test, "base_harmful": results["base"]["harmful"], "abl_harmful": results["abl"]["harmful"],
                                         "kl": kl, "changed_tensors": cmp["n_changed"], "max_rw": cmp["max_rw"], "changed_kinds": cmp["kinds"]})
    shutil.copyfile(os.path.join(run.run_dir, "validation.json"), os.path.join(out_dir, "validation.json"))
    for c in checks:
        run.log(f"  {c[2]:4s} {c[0]:40s} {c[1]}")
    run.log(f"validate: OVERALL {verdict}")
    run.event("validate", "done", verdict=verdict, checks=report["checks"], kl=kl)
    return report


def step_deploy(run, args, project, model_dir, out_dir, slug, prompts):
    from . import deploy as DP
    gguf_dir = os.path.join(project, "gguf")
    # the converter writes the target type directly when it can (f16 / bf16 / q8_0); other quant types need Ollama's create-time
    # quantization of an f16 file, which only older Ollama versions (< 0.40) support
    direct = args.quantize in DP.CONVERTER_TYPES
    outtype = args.quantize if direct else "f16"
    base_g, abl_g = os.path.join(gguf_dir, f"{slug}-base-{outtype}.gguf"), os.path.join(gguf_dir, f"{slug}-abl-{outtype}.gguf")
    run.event("gguf", "start", outtype=outtype)
    DP.convert_gguf(project, out_dir, abl_g, run.log, allow_code=args.trust_remote_code, outtype=outtype)
    run.event("gguf", "progress", which="abl")
    DP.convert_gguf(project, model_dir, base_g, run.log, allow_code=args.trust_remote_code, outtype=outtype)
    run.event("gguf", "done", base=base_g, abl=abl_g)
    tpl = ""
    for fn in ("chat_template.jinja", "tokenizer_config.json"):
        p = os.path.join(model_dir, fn)
        if os.path.isfile(p):
            tpl += open(p, encoding="utf-8").read()
    names = {"base": f"{slug}-base", "abl": f"{slug}-abl"}
    run.event("ollama", "start", names=names, host=DP.P.ollama_host())
    for tag, gguf in (("base", base_g), ("abl", abl_g)):
        DP.write_modelfile(os.path.join(gguf_dir, f"Modelfile-{slug}-{tag}"), gguf, tpl)   # for manual `ollama create`
        DP.ollama_create(names[tag], gguf, tpl, None if direct else args.quantize, run.log)   # over the API (works across containers)
        run.event("ollama", "progress", created=names[tag])
    run.update_meta(ollama=names, gguf={"base": base_g, "abl": abl_g})
    ok = {n: DP.template_ok(n) for n in names.values()}
    run.log(f"ollama: created {names}, chat template active: {ok}")
    harmful = prompts[1][:10]
    normal = ["Explain how a TCP handshake works.", "Write a Python function that reverses a string.",
              "What is the difference between TCP and UDP?", "Summarize the causes of World War I in three sentences."]
    ab = DP.ab_test(names["base"], names["abl"], harmful, normal, run.log)
    ab["names"] = names
    run.save("ollama_ab.json", ab)
    with open(os.path.join(project, "runs", "ollama_ab_latest.json"), "w", encoding="utf-8") as f:
        json.dump(ab, f, ensure_ascii=False, indent=2)
    run.log(f"ollama A/B: base {ab['n_ref_base']}/{len(harmful)} | abliterated {ab['n_ref_abl']}/{len(harmful)} refusals")
    run.event("ollama", "done", names=names, n_ref_base=ab["n_ref_base"], n_ref_abl=ab["n_ref_abl"], template_ok=ok)
    return names


# ----------------------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", help="Hugging Face repo id or local folder (GLM family)")
    ap.add_argument("--project", default=os.getcwd())
    ap.add_argument("--run-dir", help="existing run folder to resume (stage continue/apply/validate/deploy)")
    ap.add_argument("--stage", default="all", choices=["all", "download", "measure", "scan", "continue", "apply", "validate", "deploy"])
    ap.add_argument("--layer", type=int, help="layer whose direction to apply (default: scan rule)")
    ap.add_argument("--pause-at-choice", action="store_true", help="stop after the scan and wait for --stage continue --layer N")
    ap.add_argument("--n-train", type=int, default=256); ap.add_argument("--n-test", type=int, default=16)
    ap.add_argument("--batch", type=int, default=16); ap.add_argument("--gen-batch", type=int, default=4)
    ap.add_argument("--max-new-tokens", type=int, default=64); ap.add_argument("--layer-range", default="0.2-0.8")
    ap.add_argument("--dtype", default="auto", help="auto (bfloat16 on a GPU; on the CPU float32, or bfloat16 where the processor has AVX512-BF16 / AMX) | bfloat16 | float32")
    ap.add_argument("--device-map", default="cuda", help="cuda (falls back to cpu when no GPU is visible) | cpu | auto (multi-GPU / offload)")
    ap.add_argument("--trust-remote-code", action="store_true"); ap.add_argument("--hf-token")
    ap.add_argument("--skip-verify", action="store_true", help="no reload/generation after the edit (huge models)")
    ap.add_argument("--no-ollama", action="store_true"); ap.add_argument("--quantize", default="q8_0")
    args = ap.parse_args(argv)
    project = os.path.abspath(args.project)
    os.chdir(project)

    if args.run_dir:
        run = Run(project, args.run_dir)
        model_repo = args.model or run.meta.get("model_repo")
        # a resumed run keeps its own settings unless they are given explicitly on this command line
        for k, v in (run.meta.get("args") or {}).items():
            if k in ("n_train", "n_test", "batch", "gen_batch", "max_new_tokens", "layer_range", "dtype", "trust_remote_code", "device_map")                     and getattr(args, k) == ap.get_default(k):
                setattr(args, k, v)
    else:
        if not args.model:
            ap.error("--model is required for a new run")
        run = Run(project, os.path.join("runs", "abliterate_" + datetime.now().strftime("%Y%m%d_%H%M%S")))
        model_repo = args.model
    slug = slug_of(model_repo)
    if not args.hf_token and os.environ.get("HF_TOKEN"):
        args.hf_token = os.environ["HF_TOKEN"]
    safe_args = {k: v for k, v in vars(args).items() if k != "hf_token"}
    run.update_meta(model_repo=model_repo, slug=slug, status="running", stage=args.stage, args=safe_args, started=run.meta.get("started") or datetime.now().isoformat(timespec="seconds"))
    run.log(f"run {run.run_dir}: model {model_repo} stage {args.stage}")
    try:
        model_dir = step_download(run, model_repo, os.path.join(project, "models"), args.hf_token)
        info = step_inspect(run, model_dir)
        out_dir = os.path.join(project, "out", f"{slug}-abliterated")
        run.update_meta(model_dir=model_dir, out_dir=out_dir)
        if args.stage == "download":
            run.update_meta(status="done"); return
        prompts = D.load_prompts(os.path.join(project, "data"), args.n_train, args.n_test)
        run.event("data", "done", n_train=len(prompts[0]), n_test=len(prompts[1]))

        import torch
        dirs = la = scan = baseline = None
        if args.stage in ("all", "measure", "scan"):
            from .hooks import HookedModel, load_model, resolve_device
            device_map, dtype = resolve_device(args.device_map, args.dtype, run.log)      # e.g. cuda -> cpu and auto -> float32 without a GPU
            run.update_meta(device={"device_map": device_map, "dtype": dtype})
            run.event("load", "start", model_dir=model_dir, dtype=dtype, device_map=device_map)
            m, tok = load_model(model_dir, dtype, device_map, args.trust_remote_code, run.log)
            hm = HookedModel(m, tok, run.log)
            run.event("load", "done", n_layers=hm.n_layers, d_model=hm.d_model, dtype=dtype, device_map=device_map)
            dirs, la = step_measure(run, hm, args, prompts)
            if args.stage == "measure":
                run.update_meta(status="done"); return
            scan, baseline, n_base = step_scan(run, hm, args, prompts, dirs, la)
            del hm, m; gc.collect(); torch.cuda.empty_cache()
            if args.stage == "scan" or args.pause_at_choice:
                run.update_meta(status="awaiting_choice", recommended=choose_layer(scan))
                run.event("choose", "waiting", recommended=choose_layer(scan))
                run.log(f"paused after the scan - recommended layer {choose_layer(scan)}; resume with --run-dir {run.run_dir} --stage continue --layer N")
                return
        else:
            dirs = torch.load(os.path.join(run.run_dir, "refusal_dirs.pt"))
            la, scan = run.load("layer_analysis.json"), run.load("scan_results.json")
            baseline = (run.load("baseline.json") or {}).get("baseline")

        if args.stage in ("all", "continue", "apply"):
            layer = args.layer if args.layer is not None else choose_layer(scan)
            run.event("choose", "done", layer=layer, recommended=choose_layer(scan), by="user" if args.layer is not None else "rule")
            direction = step_apply(run, args, model_dir, out_dir, dirs, layer, info)
            if args.stage == "apply":
                run.update_meta(status="done"); return
        else:
            layer = args.layer if args.layer is not None else run.meta.get("layer")
            direction = torch.load(os.path.join(out_dir, "refusal_direction.pt"))["direction"]

        if args.stage in ("all", "continue", "validate") and not args.skip_verify:
            step_verify_and_validate(run, args, model_dir, out_dir, direction, layer, prompts, baseline, scan, info)
            if args.stage == "validate":
                run.update_meta(status="done"); return
        if not args.no_ollama and args.stage in ("all", "continue", "deploy"):
            step_deploy(run, args, project, model_dir, out_dir, slug, prompts)
        run.update_meta(status="done")
        run.event("done", "done", layer=layer, out_dir=out_dir)
        run.log("done")
    except SystemExit:
        raise
    except KeyboardInterrupt:
        run.update_meta(status="stopped"); run.event("error", "stopped"); raise
    except Exception as e:
        import traceback
        run.log("ERROR " + traceback.format_exc())
        run.update_meta(status="error", error=str(e))
        run.event("error", "error", message=f"{type(e).__name__}: {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
