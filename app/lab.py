"""The lab: keeps a base model resident (plain HF model + hooks, any GLM family) so the UI can
- probe any prompt: how strongly does each layer's refusal direction light up at the last token?
- try any layer live: answer prompts with that layer's direction removed (hooks), next to the untouched answer."""
import gc
import json
import os
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))          # project root: abliterate/ package
from abliterate.data import REFUSAL_MARKERS, cjk_ratio, is_refusal  # noqa: E402


class Lab:
    def __init__(self, project):
        self.project = project
        self.lock = threading.Lock()
        self.hm = None
        self.model_dir = self.run_dir = None
        self.dirs = self.mean_h = self.mean_hl = None
        self.loaded_at = None
        self.baseline_cache = {}
        self.busy = None

    @property
    def bridge(self):           # kept for the server's "is something resident" checks
        return self.hm

    def status(self):
        import torch
        st = {"loaded": self.hm is not None, "run_dir": self.run_dir, "model_dir": self.model_dir,
              "n_layers": self.hm.n_layers if self.hm else None, "d_model": self.hm.d_model if self.hm else None,
              "busy": self.busy, "loaded_at": self.loaded_at}
        if torch.cuda.is_available():
            free, total = torch.cuda.mem_get_info()
            st["vram_free_gb"], st["vram_total_gb"] = round(free / 1e9, 1), round(total / 1e9, 1)
        return st

    def load(self, run_dir):
        import torch
        from abliterate.hooks import HookedModel, load_model
        with self.lock:
            self.busy = "loading"
            try:
                rd = os.path.join(self.project, run_dir)
                meta = json.load(open(os.path.join(rd, "run.json"), encoding="utf-8")) if os.path.isfile(os.path.join(rd, "run.json")) else {}
                model_dir = meta.get("model_dir") or os.path.join(self.project, "models", "glm-edge-4b-chat")
                if self.hm is None or self.model_dir != model_dir:
                    self.hm = None; gc.collect(); torch.cuda.empty_cache()
                    trc = bool((meta.get("args") or {}).get("trust_remote_code"))
                    m, tok = load_model(model_dir, "bfloat16", "cuda", trc)
                    self.hm = HookedModel(m, tok)
                    self.model_dir, self.loaded_at = model_dir, time.strftime("%H:%M:%S")
                dirs = torch.load(os.path.join(rd, "refusal_dirs.pt"))
                means = torch.load(os.path.join(rd, "means.pt"))
                self.dirs, self.mean_h, self.mean_hl = dirs.float(), means["mean_h"].float(), means["mean_hl"].float()
                self.run_dir = run_dir
                self.baseline_cache = {}
            finally:
                self.busy = None
        return self.status()

    def unload(self):
        import torch
        with self.lock:
            self.hm = None; self.model_dir = None
            gc.collect(); torch.cuda.empty_cache()
        return self.status()

    def probe(self, prompt):
        import torch
        if self.hm is None:
            raise RuntimeError("model not loaded")
        with self.lock:
            self.busy = "probing"
            try:
                acts, ids = self.hm.resid_pre_all(prompt)        # [L, seq, d]
                n = self.hm.n_layers
                layers, traces = [], {}
                for l in range(n):
                    act, r = acts[l], self.dirs[l]
                    proj = float(act[-1] @ r)
                    ref_h, ref_hl = float(self.mean_h[l] @ r), float(self.mean_hl[l] @ r)
                    span = ref_h - ref_hl
                    layers.append({"layer": l, "proj": round(proj, 3), "ref_harmful": round(ref_h, 3), "ref_harmless": round(ref_hl, 3),
                                   "score": round((proj - ref_hl) / span if abs(span) > 1e-6 else 0.0, 3),
                                   "cos": round(float(act[-1] @ r / (act[-1].norm() + 1e-6)), 4)})
                    traces[l] = [round(float(x), 3) for x in (act @ r)]
                toks = self.hm.tok.convert_ids_to_tokens(ids)
                top = sorted(range(n), key=lambda l: -layers[l]["score"])[:3]
                return {"prompt": prompt, "tokens": [t.replace("Ġ", " ").replace("▁", " ") for t in toks], "layers": layers,
                        "traces": {str(l): traces[l] for l in top}, "top_layers": top,
                        "refusal_like": sum(1 for x in layers if x["score"] > 0.5) / n}
            finally:
                self.busy = None
                gc.collect(); torch.cuda.empty_cache()

    def try_layer(self, layer, prompts, max_new_tokens=64, batch_size=4):
        if self.hm is None:
            raise RuntimeError("model not loaded")
        with self.lock:
            self.busy = f"generating (layer {layer})"
            try:
                todo = [p for p in prompts if (p, max_new_tokens) not in self.baseline_cache]
                if todo:
                    for p, o in zip(todo, self.hm.generate(todo, max_new_tokens, batch_size)):
                        self.baseline_cache[(p, max_new_tokens)] = o
                abl = self.hm.generate(prompts, max_new_tokens, batch_size, direction=self.dirs[layer])
                base = [self.baseline_cache[(p, max_new_tokens)] for p in prompts]
                return {"layer": layer, "prompts": prompts, "baseline": base, "ablated": abl,
                        "n_base": sum(is_refusal(t) for t in base), "n_abl": sum(is_refusal(t) for t in abl),
                        "cjk": [round(cjk_ratio(t), 3) for t in abl]}
            finally:
                self.busy = None
