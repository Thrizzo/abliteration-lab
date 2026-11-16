"""The permanent edit: W' = W - r r^T W for every matrix that writes into the residual stream, applied
shard by shard on the safetensors files (never loads the whole model). Handles:
- token embedding rows, attention output projections, every MLP output projection
  (dense MLP, per-expert tensors `experts.E.down_proj`, fused `experts.down_proj` [E, d, f], `w2_weight`)
- biases on those projections
- post-norm blocks (GLM-4 / 4V): the direction is folded through the RMSNorm weight g -> r~ = norm(g * r)
- FP8 block-scaled weights (`weight_scale_inv`, DeepSeek-style): dequantize per block, edit, requantize
"""
import glob
import json
import os
import shutil
import time

import torch
from safetensors import safe_open
from safetensors.torch import save_file

from .arch import classify, post_norm_name

FP8_MAX = 448.0
KEEP_FILES = (".json", ".jinja", ".txt", ".model", ".tiktoken", ".md")


def orth_rows(Wf, r):              # [V, d]: each row is a residual-space vector
    return Wf - torch.outer(Wf @ r, r)


def orth_out(Wf, r):               # [d, in] or [E, d, in]: the output dimension is the residual space
    if Wf.dim() == 3:
        return Wf - r[None, :, None] * torch.einsum("d,edi->ei", r, Wf)[:, None, :]
    return Wf - torch.outer(r, r @ Wf)


def residual_component(Wf, r, kind):
    """max |r . W| after the edit (should be ~0 up to rounding)."""
    if kind == "embed":
        return (Wf @ r).abs().max().item()
    if Wf.dim() == 3:
        return torch.einsum("d,edi->ei", r, Wf).abs().max().item()
    if Wf.dim() == 1:
        return abs(float(Wf @ r))
    return (r @ Wf).abs().max().item()


def expand_scale(scale, shape):
    """Broadcast a block/row/tensor scale to the weight's shape (block size inferred per dim)."""
    s = scale.float()
    if s.dim() == 0:
        return s.expand(shape)
    for dim in range(s.dim()):
        if s.shape[dim] != shape[dim]:
            rep = -(-shape[dim] // s.shape[dim])
            s = s.repeat_interleave(rep, dim=dim).narrow(dim, 0, shape[dim])
    return s


def requantize(Wf, scale_shape):
    """Per-block absmax requantization to float8_e4m3fn with the same scale layout as before."""
    shape = Wf.shape
    blocks = [-(-shape[i] // scale_shape[i]) if i < len(scale_shape) and scale_shape[i] > 0 else shape[i] for i in range(len(shape))]
    # pad to block multiples, reshape into blocks, absmax per block
    pad = [b * s - n for n, b, s in zip(shape, blocks, scale_shape)]
    Wp = torch.nn.functional.pad(Wf, [v for p in reversed(pad) for v in (0, p)])
    if Wf.dim() == 2:
        v = Wp.reshape(scale_shape[0], blocks[0], scale_shape[1], blocks[1])
        amax = v.abs().amax(dim=(1, 3))
    else:
        v = Wp.reshape(scale_shape[0], blocks[0], scale_shape[1], blocks[1], scale_shape[2], blocks[2])
        amax = v.abs().amax(dim=(1, 3, 5))
    scale = (amax / FP8_MAX).clamp_min(1e-12)
    q = (Wf / expand_scale(scale, shape)).clamp(-FP8_MAX, FP8_MAX).to(torch.float8_e4m3fn)
    return q, scale


class Editor:
    def __init__(self, src_dir, dst_dir, direction, post_norm=False, log=print, progress=None):
        self.src, self.dst, self.log, self.progress = src_dir, dst_dir, log, progress
        self.r = direction.float().cpu()
        self.r = self.r / self.r.norm()
        self.post_norm = post_norm
        idx_path = os.path.join(src_dir, "model.safetensors.index.json")
        if os.path.isfile(idx_path):
            self.index = json.load(open(idx_path, encoding="utf-8"))
            self.weight_map = self.index["weight_map"]
        else:
            self.index = None
            self.weight_map = None
        self.shards = sorted(set(self.weight_map.values())) if self.weight_map else ["model.safetensors"]
        self._norm_cache = {}
        self.stats = {"changed": [], "max_rw": 0.0, "kinds": {}, "fp8": 0, "bias": 0, "folded": 0}

    # -------------------------------------------------------------- helpers
    def _tensor(self, name):
        shard = self.weight_map[name] if self.weight_map else "model.safetensors"
        with safe_open(os.path.join(self.src, shard), "pt") as f:
            return f.get_tensor(name)

    def _direction_for(self, name, kind):
        """r, or the post-norm-folded r~ for attn/mlp outputs in post-norm families."""
        if kind == "embed" or not self.post_norm:
            return self.r
        pn = post_norm_name(name, kind)
        if pn is None or (self.weight_map is not None and pn not in self.weight_map):
            return self.r
        if pn not in self._norm_cache:
            g = self._tensor(pn).float()
            rt = g * self.r
            self._norm_cache[pn] = rt / rt.norm()
            self.stats["folded"] += 1
        return self._norm_cache[pn]

    def _edit(self, name, W, kind, scale=None):
        r = self._direction_for(name, kind)
        if W.dtype == torch.float8_e4m3fn or W.dtype == torch.float8_e5m2:
            if scale is None:
                raise RuntimeError(f"{name}: fp8 tensor without a scale tensor")
            Wf = W.float() * expand_scale(scale, W.shape)
            Wf = orth_rows(Wf, r) if kind == "embed" else orth_out(Wf, r)
            q, new_scale = requantize(Wf, tuple(scale.shape))
            self.stats["fp8"] += 1
            check = residual_component(q.float() * expand_scale(new_scale, W.shape), r, kind)
            return q, new_scale.to(scale.dtype), check
        Wf = W.float()
        if W.dim() == 1:                       # bias
            out = Wf - (Wf @ r) * r
            self.stats["bias"] += 1
        else:
            out = orth_rows(Wf, r) if kind == "embed" else orth_out(Wf, r)
        out = out.to(W.dtype)
        return out, None, residual_component(out.float(), r, kind)

    # -------------------------------------------------------------- run
    def run(self):
        os.makedirs(self.dst, exist_ok=True)
        t0 = time.time()
        for si, shard in enumerate(self.shards):
            t = time.time()
            tensors, scales_done = {}, set()
            with safe_open(os.path.join(self.src, shard), "pt") as f:
                keys = list(f.keys())
                meta = f.metadata() or {"format": "pt"}
                for k in keys:
                    if k in tensors:
                        continue
                    kind = classify(k)
                    if kind in ("embed", "attn_out", "mlp_out"):
                        W = f.get_tensor(k)
                        scale_name = next((s for s in (k + "_scale_inv", k.replace(".weight", ".weight_scale_inv"), k + "_scale", k.replace(".weight", ".weight_scale"))
                                           if s != k and (s in keys or (self.weight_map and s in self.weight_map))), None)
                        scale = (f.get_tensor(scale_name) if scale_name in keys else self._tensor(scale_name)) if scale_name else None
                        out, new_scale, check = self._edit(k, W, kind, scale)
                        tensors[k] = out.contiguous()
                        if new_scale is not None:
                            tensors[scale_name] = new_scale.contiguous()
                            scales_done.add(scale_name)
                        self.stats["changed"].append(k)
                        self.stats["kinds"][kind] = self.stats["kinds"].get(kind, 0) + 1
                        self.stats["max_rw"] = max(self.stats["max_rw"], check)
                    elif kind == "scale" and k in scales_done:
                        continue
                    else:
                        tensors[k] = f.get_tensor(k)
            save_file(tensors, os.path.join(self.dst, shard), metadata=meta)
            del tensors
            if self.progress:
                self.progress(si + 1, len(self.shards), time.time() - t)
            self.log(f"edit: shard {si + 1}/{len(self.shards)} {shard} ({time.time() - t:.0f}s, changed so far {len(self.stats['changed'])})")
        # index + config/tokenizer files
        if self.index is not None:
            with open(os.path.join(self.dst, "model.safetensors.index.json"), "w", encoding="utf-8") as fh:
                json.dump(self.index, fh, indent=2)
        for fn in os.listdir(self.src):
            p = os.path.join(self.src, fn)
            if os.path.isfile(p) and (fn.endswith(KEEP_FILES) or fn.endswith(".py")) and fn != "model.safetensors.index.json" and fn != "local_copy.json":
                shutil.copyfile(p, os.path.join(self.dst, fn))
        self.stats["seconds"] = round(time.time() - t0)
        self.stats["n_changed"] = len(self.stats["changed"])
        self.log(f"edit: {self.stats['n_changed']} tensors changed {self.stats['kinds']}, fp8 {self.stats['fp8']}, "
                 f"folded through post-norm {self.stats['folded']}, max |r.W'| = {self.stats['max_rw']:.2e}, {self.stats['seconds']}s")
        return self.stats


def expected_targets(src_dir):
    """All tensor names the edit should touch (from the index), for the validation step."""
    idx_path = os.path.join(src_dir, "model.safetensors.index.json")
    if os.path.isfile(idx_path):
        names = json.load(open(idx_path, encoding="utf-8"))["weight_map"].keys()
    else:
        with safe_open(os.path.join(src_dir, "model.safetensors"), "pt") as f:
            names = list(f.keys())
    return sorted(n for n in names if classify(n) in ("embed", "attn_out", "mlp_out"))
