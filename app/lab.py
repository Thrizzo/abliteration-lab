"""The lab: keeps the base model resident (TransformerLens bridge) so the UI can
- probe any prompt: how strongly does each layer's refusal direction light up at the last token?
- try any layer live: answer prompts with that layer's direction removed (hooks), next to the untouched answer.

The model code is the notebook's own: the helper cells are exec'd 1:1 (same trick as run_pipeline.py)."""
import gc
import json
import os
import threading
import time

NOTEBOOK = "abliteration_pipeline.ipynb"
HELPER_CELLS = [22, 24, 26]          # logging/helpers, refusal markers, data/activation/hook functions


class Lab:
    def __init__(self, project):
        self.project = project
        self.lock = threading.Lock()
        self.ns = None
        self.bridge = self.tokenizer = self.eos = None
        self.run_dir = None
        self.dirs = self.mean_h = self.mean_hl = None
        self.n_layers = self.d_model = None
        self.loaded_at = None
        self.baseline_cache = {}
        self.busy = None

    # ------------------------------------------------------------------ state
    def status(self):
        import torch
        st = {"loaded": self.bridge is not None, "run_dir": self.run_dir, "n_layers": self.n_layers, "d_model": self.d_model,
              "busy": self.busy, "loaded_at": self.loaded_at}
        if torch.cuda.is_available():
            free, total = torch.cuda.mem_get_info()
            st["vram_free_gb"] = round(free / 1e9, 1)
            st["vram_total_gb"] = round(total / 1e9, 1)
        return st

    def _helpers(self):
        if self.ns is None:
            nb = json.load(open(os.path.join(self.project, NOTEBOOK), encoding="utf-8"))
            ns = {"__name__": "lab"}
            for i in HELPER_CELLS:
                exec(compile("".join(nb["cells"][i]["source"]), f"<cell {i}>", "exec"), ns)
            self.ns = ns
        return self.ns

    # ------------------------------------------------------------------ load / unload
    def load(self, run_dir):
        import torch
        from transformers import AutoTokenizer
        from transformer_lens.model_bridge import TransformerBridge
        with self.lock:
            self.busy = "loading"
            try:
                ns = self._helpers()
                rd = os.path.join(self.project, run_dir)
                dirs = torch.load(os.path.join(rd, "refusal_dirs.pt"))
                means = torch.load(os.path.join(rd, "means.pt"))
                if self.bridge is None:
                    model_dir = os.path.join(self.project, "models", "glm-edge-4b-chat")
                    torch.set_grad_enabled(False)
                    tok = AutoTokenizer.from_pretrained(model_dir)
                    tok.padding_side = "left"
                    if tok.pad_token is None:
                        tok.pad_token = tok.eos_token
                    self.bridge = TransformerBridge.boot_transformers(model_dir, tokenizer=tok, device="cuda", dtype=torch.bfloat16)
                    self.tokenizer = tok
                    gen_cfg = getattr(self.bridge.original_model, "generation_config", None)
                    self.eos = getattr(gen_cfg, "eos_token_id", None) or tok.eos_token_id
                    self.n_layers, self.d_model = self.bridge.cfg.n_layers, self.bridge.cfg.d_model
                    self.loaded_at = time.strftime("%H:%M:%S")
                self.dirs, self.mean_h, self.mean_hl = dirs.float(), means["mean_h"].float(), means["mean_hl"].float()
                self.run_dir = run_dir
                self.baseline_cache = {}
            finally:
                self.busy = None
        return self.status()

    def unload(self):
        import torch
        with self.lock:
            self.bridge = self.tokenizer = None
            gc.collect()
            torch.cuda.empty_cache()
        return self.status()

    # ------------------------------------------------------------------ probe: refusal meter
    def probe(self, prompt):
        """For one prompt: projection of the last-token residual onto every layer's own direction,
        scaled between the harmless mean (0) and the harmful mean (1); plus the per-token trace at the peak layer."""
        import torch
        if self.bridge is None:
            raise RuntimeError("model not loaded")
        ns = self._helpers()
        with self.lock:
            self.busy = "probing"
            try:
                ids, mask = ns["tokenize_instructions"](self.tokenizer, [prompt])
                names = {f"blocks.{l}.hook_resid_pre" for l in range(self.n_layers)}
                _, cache = self.bridge.run_with_cache(ids.to("cuda"), attention_mask=mask.to("cuda"), names_filter=lambda n: n in names)
                layers = []
                traces = {}
                for l in range(self.n_layers):
                    act = cache[f"blocks.{l}.hook_resid_pre"][0].float().cpu()       # [seq, d_model]
                    r = self.dirs[l]
                    proj = float(act[-1] @ r)
                    ref_h, ref_hl = float(self.mean_h[l] @ r), float(self.mean_hl[l] @ r)
                    span = ref_h - ref_hl
                    score = (proj - ref_hl) / span if abs(span) > 1e-6 else 0.0
                    layers.append({"layer": l, "proj": round(proj, 3), "ref_harmful": round(ref_h, 3), "ref_harmless": round(ref_hl, 3),
                                   "score": round(score, 3), "cos": round(float(act[-1] @ r / (act[-1].norm() + 1e-6)), 4)})
                    traces[l] = [round(float(x), 3) for x in (act @ r)]
                del cache
                toks = self.tokenizer.convert_ids_to_tokens(ids[0].tolist())
                # per-token trace for the three most informative layers (highest scaled score)
                top = sorted(range(self.n_layers), key=lambda l: -layers[l]["score"])[:3]
                return {"prompt": prompt, "tokens": [t.replace("Ġ", " ").replace("▁", " ") for t in toks], "layers": layers,
                        "traces": {str(l): traces[l] for l in top}, "top_layers": top,
                        "refusal_like": sum(1 for x in layers if x["score"] > 0.5) / self.n_layers}
            finally:
                self.busy = None
                gc.collect(); torch.cuda.empty_cache()

    # ------------------------------------------------------------------ try a layer live
    def try_layer(self, layer, prompts, max_new_tokens=64, batch_size=4):
        import torch
        if self.bridge is None:
            raise RuntimeError("model not loaded")
        ns = self._helpers()
        with self.lock:
            self.busy = f"generating (layer {layer})"
            try:
                todo = [p for p in prompts if (p, max_new_tokens) not in self.baseline_cache]
                if todo:
                    outs = ns["get_generations"](self.bridge, self.tokenizer, todo, [], max_new_tokens, batch_size, "cuda", self.eos)
                    for p, o in zip(todo, outs):
                        self.baseline_cache[(p, max_new_tokens)] = o
                hooks = ns["ablation_hooks"](self.bridge, self.dirs[layer])
                abl = ns["get_generations"](self.bridge, self.tokenizer, prompts, hooks, max_new_tokens, batch_size, "cuda", self.eos)
                base = [self.baseline_cache[(p, max_new_tokens)] for p in prompts]
                return {"layer": layer, "prompts": prompts, "baseline": base, "ablated": abl,
                        "n_base": sum(ns["is_refusal"](t) for t in base), "n_abl": sum(ns["is_refusal"](t) for t in abl),
                        "cjk": [round(ns["cjk_ratio"](t), 3) for t in abl]}
            finally:
                self.busy = None
                gc.collect(); torch.cuda.empty_cache()
