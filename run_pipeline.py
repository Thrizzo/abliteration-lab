r"""
run_pipeline.py - runs the code cells of abliteration_pipeline.ipynb non-interactively, in stages.

The notebook stays the single source of truth: this script extracts its code cells and executes
them 1:1 in one shared namespace (like a kernel would). Small hooks replace the interactive bits
(the ipywidgets layer picker in 4.5, matplotlib windows) and save extra data for the HTML GUI.

Usage (from the project folder, with the .venv python):
    .\.venv\Scripts\python.exe run_pipeline.py setup       # section 1: torch CUDA, packages, llama.cpp, SBOM
    .\.venv\Scripts\python.exe run_pipeline.py main        # sections 2, 3 (without the DPO audit), 4 and 7
    .\.venv\Scripts\python.exe run_pipeline.py validate --run-dir runs/abliterate_<ts>   # 4.8 only, into that run folder
    .\.venv\Scripts\python.exe run_pipeline.py apply --run-dir runs/abliterate_<ts>      # 4.6-4.8 with the layer in abliteration_settings.json
    .\.venv\Scripts\python.exe run_pipeline.py ollama      # section 7 only (re-uses data/harmful_test.jsonl)
    .\.venv\Scripts\python.exe run_pipeline.py --cells 20,22,24,26,30   # any cells by index
Sections 5 (benchmarks) and 6 (DPO) are not part of any stage.
"""
import argparse, glob, hashlib, json, os, subprocess, sys, time, traceback
from datetime import datetime

NOTEBOOK = "abliteration_pipeline.ipynb"
# (cell index, expected start of the cell) - the tag guards against a renumbered notebook
CELLS = {
    3: "# 1.1", 6: "# 1.2", 8: "# 1.3", 11: "# 1.4", 13: "# 1.5", 15: "# 1.6",
    20: "# 2.0", 22: "import contextlib", 24: "# Constants", 26: "# Functions for data",
    28: "# Training callback", 30: "# Environment check",
    34: "# 3.3", 37: "# 3.4", 40: "# 3.5", 50: "# 3.8a", 53: "# 3.8b", 56: "# 3.8c", 59: "# 3.8d",
    62: "# 4.0", 64: "# 4.0b", 67: "# 4.1", 70: "# 4.2", 73: "# 4.3", 76: "# 4.4", 79: "# 4.4b",
    81: "# 4.5", 85: "# 4.6", 88: "# 4.7", 90: "# 4.8",
    115: "# 7.1", 118: "# 7.2", 120: "# 7.3", 123: "# 7.4", 126: "# 7.5",
}
HELPERS = [20, 22, 24, 26, 28, 30]
STAGES = {
    "setup":  [3, 6, 8, 11, 13, 15],
    "data":   HELPERS + [34, 37, 40, 50, 53, 56, 59],
    "abl":    HELPERS + [62, 64, 67, 70, 73, 76, 79, 81, 85, 88, 90],
    "ollama": HELPERS + [115, 118, 120, 123, 126],
}
STAGES["validate"] = HELPERS + [62, 64, 67, 90]
STAGES["apply"] = HELPERS + [62, 64, 67, 85, 88, 90]      # re-apply a (new) chosen layer from a finished scan
STAGES["main"] = STAGES["data"] + STAGES["abl"][len(HELPERS):] + STAGES["ollama"][len(HELPERS):]

HF_SNAPSHOT = os.path.expandvars(r"%USERPROFILE%\.cache\huggingface\hub\models--THUDM--glm-edge-4b-chat\snapshots")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 22), b""):
            h.update(b)
    return h.hexdigest()


def jdump(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    print(f"[runner] written: {path}")


# ----------------------------------------------------------------------------- hooks
def before(idx, ns):
    if idx == 64:   # 4.0b: use the Hugging Face cache copy instead of downloading 8.6 GB again
        A = ns["A"]
        if not os.path.isfile(os.path.join(A.model, "config.json")) and os.path.isdir(HF_SNAPSHOT):
            snaps = [d for d in os.listdir(HF_SNAPSHOT) if os.path.isfile(os.path.join(HF_SNAPSHOT, d, "config.json"))]
            if snaps:
                A.model_repo = os.path.join(HF_SNAPSHOT, snaps[0])
                ns["_snapshot_rev"] = snaps[0]
                print(f"[runner] 4.0b: copying the base model from the HF cache (revision {snaps[0]})")
    if idx in (73, 79):   # charts: no window, save as PNG into the run folder
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        run_dir = ns["A"].run_dir
        def _show(*a, **k):
            path = os.path.join(run_dir, f"figure_{'4.3' if idx == 73 else '4.4b'}.png")
            plt.savefig(path, dpi=110, bbox_inches="tight"); plt.close("all")
            print(f"[runner] chart saved: {path}")
        plt.show = _show
    if idx == 85 and "scan" not in ns and RUN_DIR:   # apply stage: restore measure/scan state from the run folder
        import torch
        ns["refusal_dirs"] = torch.load(os.path.join(RUN_DIR, "refusal_dirs.pt"))
        ns["scan"] = json.load(open(os.path.join(RUN_DIR, "scan_results.json"), encoding="utf-8"))
        bl = json.load(open(os.path.join(RUN_DIR, "baseline.json"), encoding="utf-8"))
        ns["baseline"], ns["n_base"] = bl["baseline"], bl["n_base"]
        ns["scan_by_layer"] = {s_["layer"]: s_ for s_ in ns["scan"]}
        ns["RECOMMENDED"] = min(ns["scan"], key=lambda x: (x["refusals"], x["cjk_ratio"], x["layer"]))["layer"]
        ns["SETTINGS_FILE"] = "abliteration_settings.json"
        def load_saved_layer():
            try:
                return int(json.load(open("abliteration_settings.json", encoding="utf-8"))["layer_to_abliterate"])
            except Exception:
                return None
        ns["load_saved_layer"] = load_saved_layer
        print(f"[runner] 4.6: scan state restored from {RUN_DIR}; layer from abliteration_settings.json = {load_saved_layer()}")
    if idx == 120:   # 7.3: remove the two old Ollama models if they are the same blob (the earlier mix-up)
        ollama = ns["find_exe"]("ollama", [r"%LOCALAPPDATA%\Programs\Ollama\ollama.exe"])
        if ollama:
            ids = {}
            out = subprocess.run([ollama, "list"], capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ("glm-edge-base:latest", "glm-edge-abl:latest"):
                    ids[parts[0]] = parts[1]
            if len(ids) == 2 and len(set(ids.values())) == 1:
                print(f"[runner] 7.3: glm-edge-base and glm-edge-abl share blob {ids.popitem()[1]} -> removing both before re-import")
                subprocess.run([ollama, "rm", "glm-edge-base", "glm-edge-abl"], check=False)
    if idx == 123 and "harmful_test" not in ns:   # 7.4 standalone: load the held-out prompts from data/
        A_cfg = ns.get("A")
        n = getattr(A_cfg, "n_inst_test", 16) if A_cfg else 16
        if os.path.isfile("data/harmful_test.jsonl"):
            ns["harmful_test"] = ns["load_lines"]("data/harmful_test.jsonl")[:n]
            print(f"[runner] 7.4: harmful_test loaded from data/harmful_test.jsonl ({len(ns['harmful_test'])})")


RUN_DIR = None   # --run-dir: reuse an existing runs/abliterate_* folder (validate stage)


def after(idx, ns):
    if idx == 62 and RUN_DIR:
        fresh = ns["A"].run_dir                      # 4.0 already created a new folder + run.log
        ns["A"].run_dir = RUN_DIR
        ns["setup_logging"](RUN_DIR, ns["A"].debug)  # closes the handler on the fresh folder
        if os.path.isdir(fresh) and os.listdir(fresh) == ["run.log"]:
            import shutil
            shutil.rmtree(fresh, ignore_errors=True)
        print(f"[runner] using existing run folder {RUN_DIR}")
    if idx == 64:   # record revision + SHA-256 like the download branch does
        A = ns["A"]; info = os.path.join(A.model, "local_copy.json")
        if not os.path.isfile(info) and ns.get("_snapshot_rev"):
            hashes = {f: sha256(os.path.join(A.model, f)) for f in sorted(os.listdir(A.model)) if f.endswith(".safetensors")}
            jdump(info, {"repo": "THUDM/glm-edge-4b-chat", "revision": ns["_snapshot_rev"], "source": "local HF cache copy",
                         "downloaded": datetime.now().isoformat(timespec="seconds"), "sha256": hashes})
    if idx == 70:
        import torch
        A = ns["A"]
        torch.save({"mean_h": ns["mean_h"], "mean_hl": ns["mean_hl"], "norms": ns["norms"]}, os.path.join(A.run_dir, "means.pt"))
    if idx == 73:
        A = ns["A"]
        jdump(os.path.join(A.run_dir, "layer_analysis.json"), {
            "n_layers": int(ns["n_layers"]), "d_model": int(ns["bridge"].cfg.d_model),
            "scan_range": [int(ns["scan_lo"]), int(ns["scan_hi"])], "peak": int(ns["peak"]), "stable": [int(x) for x in ns["stable"]],
            "separation_pct": [float(x) for x in ns["separation"]], "norms": [float(x) for x in ns["norms"]],
            "act_size": [float(x) for x in ns["act_size"]],
            "similarity": [[round(float(v), 4) for v in row] for row in ns["similarity"]],
            "cos_next": [None if x != x else float(x) for x in ns["cos_next"]],
            "n_inst_train": int(A.n_inst_train), "harmful_train_examples": ns["harmful_train"][:12],
            "harmless_train_examples": ns["harmless_train"][:12]})
    if idx == 76:
        A = ns["A"]
        jdump(os.path.join(A.run_dir, "baseline.json"), {"prompts": ns["harmful_test"], "baseline": ns["baseline"],
                                                           "n_base": int(ns["n_base"]), "scan_layers": ns["scan_layers"]})
    if idx == 81:   # 4.5: the choice. Rule: fewest refusals, then fewest Chinese characters, then the earlier layer
        scan = ns["scan"]
        ok = [s for s in scan if s["cjk_ratio"] <= 0.2] or scan
        chosen = min(ok, key=lambda s: (s["refusals"], s["cjk_ratio"], s["layer"]))["layer"]
        print(f"\n[runner] 4.5: choosing layer {chosen} (recommended by the scan: {ns['RECOMMENDED']})")
        ns["show_layer"](chosen)
        ns["save_layer"](chosen)
    if idx == 90:
        A = ns["A"]
        jdump(os.path.join(A.run_dir, "validation_details.json"), {
            "eval_harmless": ns["eval_harmless"], "base_harmless": ns["base_s"], "abl_harmless": ns["abl_s"],
            "eval_harmful": ns["eval_harmful"], "base_harmful": ns["base_h"], "abl_harmful": ns["abl_h"],
            "kl": float(ns["kl"]), "changed_tensors": int(len(ns["changed"])), "max_rw": float(ns["max_rw"])})
    if idx == 123:
        jdump(os.path.join("runs", "ollama_ab_latest.json"), {"harmful": ns["test_harmful"], "normal": ns["test_normal"],
                                                               "results": ns["results"], "time": datetime.now().isoformat(timespec="seconds")})


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", nargs="?", choices=list(STAGES), default=None)
    ap.add_argument("--cells", help="comma-separated cell indices (overrides the stage)")
    ap.add_argument("--run-dir", help="reuse this runs/abliterate_* folder (for the validate stage)")
    args = ap.parse_args()
    global RUN_DIR
    RUN_DIR = args.run_dir
    cells = [int(x) for x in args.cells.split(",")] if args.cells else STAGES[args.stage or "main"]

    nb = json.load(open(NOTEBOOK, encoding="utf-8"))
    ns = {"__name__": "__main__", "__file__": os.path.abspath(NOTEBOOK)}
    t_all = time.time()
    print(f"[runner] {datetime.now():%Y-%m-%d %H:%M:%S} stage={args.stage or 'custom'} cells={cells} python={sys.executable}")
    for idx in cells:
        src = "".join(nb["cells"][idx]["source"])
        tag = CELLS.get(idx)
        if tag and not src.lstrip().startswith(tag):
            raise SystemExit(f"[runner] cell {idx} does not start with {tag!r} - the notebook was reordered; check CELLS.")
        head = src.strip().splitlines()[0][:90]
        print(f"\n{'=' * 100}\n[runner] cell {idx}: {head}\n{'=' * 100}", flush=True)
        t = time.time()
        try:
            before(idx, ns)
            exec(compile(src, f"<cell {idx}>", "exec"), ns)
            after(idx, ns)
        except SystemExit as e:
            print(f"[runner] cell {idx} called SystemExit({e}) - stopping."); raise
        except BaseException:
            print(f"\n[runner] cell {idx} FAILED after {time.time() - t:.0f}s:\n{traceback.format_exc()}")
            raise SystemExit(1)
        print(f"[runner] cell {idx} ok in {time.time() - t:.0f}s", flush=True)
    print(f"\n[runner] stage {args.stage or 'custom'} finished in {(time.time() - t_all) / 60:.1f} min")


if __name__ == "__main__":
    main()
