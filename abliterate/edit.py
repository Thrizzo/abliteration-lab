"""The permanent edit: W' = W - Q Q^T W for every matrix that writes into the residual stream, applied
shard by shard on the safetensors files (never loads the whole model). Q is an orthonormal basis of what is removed:
one layer's unit direction r (W' = W - r r^T W), or the subspace spanned by the directions of several layers (basis).
Handles:
- token embedding rows, attention output projections, every MLP output projection
  (dense MLP, per-expert tensors `experts.E.down_proj`, fused `experts.down_proj` [E, d, f], `w2_weight`)
- biases on those projections
- post-norm blocks (GLM-4 / 4V): the direction is folded through the RMSNorm weight g -> r~ = norm(g * r);
  with several directions every basis vector is folded and the result orthonormalized again (fold)
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
DEPENDENT = 1e-3            # basis: a direction whose part outside the others' span is shorter than this (relative) is dropped


def basis(directions, log=print, names=None):
    """The orthonormal basis Q [d, k] that the edit and the ablation remove, from one unit direction [d] or from the unit
    directions of several layers [k, d] (one per row). Returns (Q in float32, the indices of the directions kept).
    One direction: r / |r| in float32, as the single-layer edit always computed it, so one layer gives exactly the old
    edit and ablation. Several: QR in float64 of the matrix whose columns are the directions. Q spans the same subspace,
    but its columns are orthogonal: removing non-orthogonal directions one after the other would put back part of the
    ones removed before. A direction that is (nearly) a combination of the others (|R_ii| < 1e-3 max |R_jj|) adds only
    rounding noise: it is dropped with a log line and the QR repeated without it. names: what the log calls each one."""
    D = torch.as_tensor(directions).detach().to("cpu")
    if D.dim() == 1 or D.shape[0] == 1:
        r = D.reshape(-1).float()
        return (r / r.norm())[:, None], [0]
    X = D.double()
    X = X / X.norm(dim=-1, keepdim=True).clamp_min(1e-300)
    keep = list(range(X.shape[0]))
    while True:
        Q, R = torch.linalg.qr(X[keep].T)
        diag = R.diagonal().abs()
        weak = [i for i in range(len(diag)) if diag[i] < DEPENDENT * diag.max()]
        if not weak:
            return Q.float(), keep
        i = weak[0]
        log(f"basis: {names[keep[i]] if names else f'direction {keep[i]}'} is (nearly) a combination of the others "
            f"(|R_ii| = {float(diag[i]):.1e}): dropped, {len(keep) - 1} directions left")
        keep.pop(i)


def fold(Q, g, log=print):
    """For a post-norm block (its projection's output y goes through RMSNorm with weight g, then into the residual
    stream): the basis that y must lose so that the block's output has no component in span(Q).
    For any vector q: q . (g * y / rms(y)) = (g * q) . y / rms(y). The output is therefore free of every q in span(Q)
    exactly when y is orthogonal to g * q for every q in span(Q), that is to the span of g * q_1 ... g * q_k. Folding
    every basis vector and orthonormalizing again (the folded vectors are no longer orthonormal) gives a basis of
    exactly that span, so this is the exact generalisation of one direction's r~ = normalize(g * r); for k = 1 it is
    computed as before. What the edit cannot keep is the rest of the output: rms(y) changes, so the remaining components
    are scaled per token."""
    if Q.shape[1] == 1:
        rt = g * Q[:, 0]
        return (rt / rt.norm())[:, None]
    return basis((g.double()[:, None] * Q.double()).T, log)[0]


def _vec(Q):
    """The unit vector r of a one-column basis (or of a plain vector): the k = 1 formulas are the single-direction ones."""
    return Q.reshape(-1) if Q.dim() == 1 or Q.shape[1] == 1 else None


def orth_rows(Wf, Q):              # [V, d]: each row is a residual-space vector
    """W - (W Q) Q^T: every row loses its component in span(Q). Q: [d, k] with orthonormal columns, or a unit vector."""
    r = _vec(Q)
    if r is not None:
        return Wf - torch.outer(Wf @ r, r)
    return Wf - (Wf @ Q) @ Q.T


def orth_out(Wf, Q):               # [d, in] or [E, d, in]: the output dimension is the residual space
    """W - Q (Q^T W): no output of W keeps a component in span(Q); [E, d, in] per expert."""
    r = _vec(Q)
    if r is not None:
        if Wf.dim() == 3:
            return Wf - r[None, :, None] * torch.einsum("d,edi->ei", r, Wf)[:, None, :]
        return Wf - torch.outer(r, r @ Wf)
    if Wf.dim() == 3:
        return Wf - torch.einsum("dk,eki->edi", Q, torch.einsum("dk,edi->eki", Q, Wf))
    return Wf - Q @ (Q.T @ Wf)


def orth_vec(b, Q):                # a bias [d] of an output projection
    """b - Q (Q^T b)."""
    r = _vec(Q)
    if r is not None:
        return b - (b @ r) * r
    return b - Q @ (Q.T @ b)


def residual_component(Wf, Q, kind):
    """max |Q^T W| after the edit (should be ~0 up to rounding): the largest component that a row (embedding), an output
    column or a bias keeps along any basis vector. k = 1: max |r . W|."""
    r = _vec(Q)
    if r is not None:
        if kind == "embed":
            return (Wf @ r).abs().max().item()
        if Wf.dim() == 3:
            return torch.einsum("d,edi->ei", r, Wf).abs().max().item()
        if Wf.dim() == 1:
            return abs(float(Wf @ r))
        return (r @ Wf).abs().max().item()
    if kind == "embed" or Wf.dim() == 1:
        return (Wf @ Q).abs().max().item()
    if Wf.dim() == 3:
        return torch.einsum("dk,edi->eki", Q, Wf).abs().max().item()
    return (Q.T @ Wf).abs().max().item()


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
    def __init__(self, src_dir, dst_dir, direction, post_norm=False, log=print, progress=None, names=None):
        """direction: one unit direction [d], or the unit directions of several layers [k, d]. The editor builds the
        orthonormal basis Q [d, k] itself (basis; names label the directions in its log); kept: the rows it used."""
        self.src, self.dst, self.log, self.progress = src_dir, dst_dir, log, progress
        self.Q, self.kept = basis(direction, log, names)
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
        self.stats = {"changed": [], "max_rw": 0.0, "kinds": {}, "fp8": 0, "bias": 0, "folded": 0, "directions": self.Q.shape[1]}

    # -------------------------------------------------------------- helpers
    def _tensor(self, name):
        shard = self.weight_map[name] if self.weight_map else "model.safetensors"
        with safe_open(os.path.join(self.src, shard), "pt") as f:
            return f.get_tensor(name)

    def _basis_for(self, name, kind):
        """Q, or the post-norm-folded basis (fold; one direction: r~) for attn/mlp outputs in post-norm families."""
        if kind == "embed" or not self.post_norm:
            return self.Q
        pn = post_norm_name(name, kind)
        if pn is None or (self.weight_map is not None and pn not in self.weight_map):
            return self.Q
        if pn not in self._norm_cache:
            self._norm_cache[pn] = fold(self.Q, self._tensor(pn).float(), self.log)
            self.stats["folded"] += 1
        return self._norm_cache[pn]

    def _edit(self, name, W, kind, scale=None):
        Q = self._basis_for(name, kind)
        if W.dtype == torch.float8_e4m3fn or W.dtype == torch.float8_e5m2:
            if scale is None:
                raise RuntimeError(f"{name}: fp8 tensor without a scale tensor")
            Wf = W.float() * expand_scale(scale, W.shape)
            Wf = orth_rows(Wf, Q) if kind == "embed" else orth_out(Wf, Q)
            q, new_scale = requantize(Wf, tuple(scale.shape))
            self.stats["fp8"] += 1
            check = residual_component(q.float() * expand_scale(new_scale, W.shape), Q, kind)
            return q, new_scale.to(scale.dtype), check
        Wf = W.float()
        if W.dim() == 1:                       # bias
            out = orth_vec(Wf, Q)
            self.stats["bias"] += 1
        else:
            out = orth_rows(Wf, Q) if kind == "embed" else orth_out(Wf, Q)
        out = out.to(W.dtype)
        return out, None, residual_component(out.float(), Q, kind)

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
        k = self.Q.shape[1]
        self.log(f"edit: {self.stats['n_changed']} tensors changed {self.stats['kinds']}, fp8 {self.stats['fp8']}, "
                 f"folded through post-norm {self.stats['folded']}, "
                 + (f"max |r.W'| = {self.stats['max_rw']:.2e}" if k == 1 else f"{k} directions, max |Q^T W'| = {self.stats['max_rw']:.2e}")
                 + f", {self.stats['seconds']}s")
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
