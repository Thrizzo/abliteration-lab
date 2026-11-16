"""Architecture inspection: which GLM family is this, where are the layers, which tensors write into the
residual stream, is the edit exact (pre-norm) or folded through a post-norm, is it MoE / FP8 / remote code."""
import glob
import json
import os
import re

# tensor-name classification (works on safetensors names without loading the model)
RX_EMBED = re.compile(r"(^|\.)(embed_tokens|word_embeddings)\.weight$")
RX_ATTN_OUT = re.compile(r"\.(self_attn|self_attention|attn|linear_attn|attention)\.(o_proj|dense|out_proj)\.(weight|bias)$")
RX_MLP_OUT = re.compile(r"\.mlp\.(.*\.)?(down_proj|dense_4h_to_h|w2_weight)(\.weight|\.bias)?$")
RX_SCALE = re.compile(r"(_scale_inv|_scale|\.weight_scale_inv|\.weight_scale)$")
RX_LAYER = re.compile(r"\.layers\.(\d+)\.")
EXCLUDE = re.compile(r"(^|\.)(visual|vision|vision_tower|vision_model|audio|image_encoder|indexer|gate\.|router)")

FAMILY = {
    "glm": {"name": "GLM-Edge", "post_norm": False, "moe": False},
    "glm4": {"name": "GLM-4 (0414 / 9B-hf)", "post_norm": True, "moe": False},
    "glm4v": {"name": "GLM-4.1V / 4V (text decoder)", "post_norm": True, "moe": False, "text_config": True},
    "glm46v": {"name": "GLM-4.6V (text decoder)", "post_norm": False, "moe": True, "text_config": True},
    "glm4_moe": {"name": "GLM-4.5 / 4.6 MoE", "post_norm": False, "moe": True},
    "glm4_moe_lite": {"name": "GLM-4.x MoE Lite", "post_norm": False, "moe": True},
    "glm4v_moe": {"name": "GLM-4.5V (text decoder)", "post_norm": False, "moe": True, "text_config": True},
    "glm_moe_dsa": {"name": "GLM-5 / 5.1 / 5.2 / 5.3 (MoE + DSA)", "post_norm": False, "moe": True},
    "glm5_next": {"name": "GLM-5-Next (hybrid linear / indexed attention, MoE)", "post_norm": False, "moe": True, "text_config": True},
    "chatglm": {"name": "ChatGLM (legacy remote code: ChatGLM2/3, glm-4-9b-chat)", "post_norm": False, "moe": False, "remote_code": True},
}


def classify(name, shape=None):
    """'embed' | 'attn_out' | 'mlp_out' | 'scale' | None  (plus whether it is a bias)."""
    if EXCLUDE.search(name):
        return None
    if RX_SCALE.search(name):
        base = RX_SCALE.sub("", name)
        return "scale" if (RX_ATTN_OUT.search(base + ".weight") or RX_MLP_OUT.search(base) or RX_MLP_OUT.search(base + ".weight")) else None
    if RX_EMBED.search(name):
        return "embed"
    if RX_ATTN_OUT.search(name):
        return "attn_out"
    if RX_MLP_OUT.search(name):
        return "mlp_out"
    return None


def layer_index(name):
    m = RX_LAYER.search(name)
    return int(m.group(1)) if m else None


def post_norm_name(name, kind):
    """For post-norm families: the RMSNorm weight that sits between this projection and the residual add."""
    prefix = name[:RX_LAYER.search(name).end()] if RX_LAYER.search(name) else None
    if prefix is None:
        return None
    return prefix + ("post_self_attn_layernorm.weight" if kind == "attn_out" else "post_mlp_layernorm.weight")


def inspect(model_dir):
    """Reads config.json (+ safetensors index) and returns a support assessment dict."""
    cfg = json.load(open(os.path.join(model_dir, "config.json"), encoding="utf-8"))
    mt = cfg.get("model_type", "")
    text = cfg.get("text_config") or cfg
    fam = FAMILY.get(mt)
    if fam is None and "chatglm" in mt.lower():
        fam = FAMILY["chatglm"]
    if fam is None and mt == "":
        fam = FAMILY["chatglm"] if "ChatGLM" in "".join(cfg.get("architectures", [])) else None
    q = cfg.get("quantization_config") or {}
    moe = {
        "n_routed_experts": text.get("n_routed_experts") or text.get("num_experts") or text.get("num_local_experts"),
        "n_shared_experts": text.get("n_shared_experts"),
        "num_experts_per_tok": text.get("num_experts_per_tok"),
        "first_k_dense_replace": text.get("first_k_dense_replace"),
        "mlp_layer_types": text.get("mlp_layer_types"),
    }
    is_moe = bool(moe["n_routed_experts"])
    size_bytes = None
    idx_path = os.path.join(model_dir, "model.safetensors.index.json")
    tensor_kinds = {}
    if os.path.isfile(idx_path):
        idx = json.load(open(idx_path, encoding="utf-8"))
        size_bytes = (idx.get("metadata") or {}).get("total_size")
        for n in idx["weight_map"]:
            k = classify(n)
            if k:
                tensor_kinds[k] = tensor_kinds.get(k, 0) + 1
    elif os.path.isfile(os.path.join(model_dir, "model.safetensors")):
        size_bytes = os.path.getsize(os.path.join(model_dir, "model.safetensors"))
    code_files = [f for f in os.listdir(model_dir) if f.endswith(".py")]
    needs_remote = bool(cfg.get("auto_map")) or (fam is not None and fam.get("remote_code"))
    notes, level = [], "exact"
    if fam is None:
        level = "unsupported"
        notes.append(f"model_type '{mt}' is not a known GLM family; the generic tensor patterns may still apply, check tensor_kinds")
    else:
        if fam["post_norm"]:
            level = "folded"
            notes.append("post-norm block (RMSNorm between projection and residual add): the direction is folded through the norm weight, so the edit is exact only up to the per-token RMS scaling")
        if is_moe:
            notes.append(f"MoE: {moe['n_routed_experts']} routed + {moe['n_shared_experts'] or 0} shared experts per sparse layer; every expert's down_proj is edited")
        if mt == "glm_moe_dsa":
            notes.append("DSA indexer modules do not write into the residual stream and are left untouched")
        if mt == "glm5_next":
            notes.append("hybrid: linear-attention layers also write through an o_proj and are edited")
        if q:
            fmt = q.get("fmt") or q.get("quant_method")
            notes.append(f"quantized checkpoint ({fmt}, block {q.get('weight_block_size')}): FP8 block-scaled tensors are dequantized, edited and requantized per block")
            if level == "exact":
                level = "requantized"
        if needs_remote:
            notes.append("legacy remote-code checkpoint: loading needs --trust-remote-code (the .py files in the folder run)")
    params_b = round(size_bytes / (1 if q else 2) / 1e9, 1) if size_bytes else None
    return {
        "model_type": mt, "architectures": cfg.get("architectures"), "family": fam["name"] if fam else None,
        "n_layers": text.get("num_hidden_layers"), "hidden_size": text.get("hidden_size"),
        "post_norm": bool(fam and fam["post_norm"]), "moe": is_moe, "moe_info": moe if is_moe else None,
        "quantization": q or None, "params_b": params_b, "size_gb": round(size_bytes / 1e9, 1) if size_bytes else None,
        "tensor_kinds": tensor_kinds, "code_files": code_files, "needs_remote_code": needs_remote,
        "text_config_nested": "text_config" in cfg, "support": level, "notes": notes,
        "fits_16gb_bf16": (size_bytes or 0) <= 15e9 and not q,
    }


# ------------------------------------------------------------------ live model structure (for hooks)
def find_layers(model):
    """The decoder layer ModuleList (text decoder for multimodal models)."""
    import torch.nn as nn
    cands = []
    for name, mod in model.named_modules():
        if isinstance(mod, nn.ModuleList) and len(mod) > 0 and name.endswith("layers") and not EXCLUDE.search(name + "."):
            cls = type(mod[0]).__name__
            if "DecoderLayer" in cls or "GLMBlock" in cls or "Block" in cls:
                cands.append((name, mod))
    if not cands:
        raise RuntimeError("could not find the decoder layers")
    cands.sort(key=lambda x: -len(x[1]))
    return cands[0]


def find_embedding(model):
    for name, mod in model.named_modules():
        if RX_EMBED.search(name + ".weight") and hasattr(mod, "weight"):
            return name, mod
    return model.get_input_embeddings()
