"""Builds a tiny, randomly initialised GLM checkpoint for pipeline tests: GLM-Edge's config, tokenizer and chat template
on a 4-layer, 64-wide model (~20 M parameters, almost all of them in the embeddings). Its answers are noise; the point
is that every pipeline stage (download, scan, apply, validate, deploy) runs end to end in seconds on a CPU.

    python make_tiny_glm.py OUT_DIR [REFERENCE]

REFERENCE is a local GLM-Edge folder or a Hugging Face repo (default THUDM/glm-edge-1.5b-chat); only its config and
tokenizer files are read, never its weights.
"""
import os
import shutil
import sys

import torch
from transformers import AutoConfig, AutoModelForCausalLM, AutoTokenizer

out = sys.argv[1]
ref = sys.argv[2] if len(sys.argv) > 2 else "THUDM/glm-edge-1.5b-chat"
if not os.path.isdir(ref):
    from huggingface_hub import snapshot_download
    ref = snapshot_download(ref, allow_patterns=["*.json", "*.jinja", "*.txt", "*.model", "*.tiktoken"])

cfg = AutoConfig.from_pretrained(ref)
for key, value in dict(num_hidden_layers=4, hidden_size=64, intermediate_size=128, num_attention_heads=4,
                       num_key_value_heads=2, head_dim=16).items():
    setattr(cfg, key, value)
torch.manual_seed(0)
model = AutoModelForCausalLM.from_config(cfg, dtype=torch.float32)
os.makedirs(out, exist_ok=True)
model.save_pretrained(out, safe_serialization=True)
AutoTokenizer.from_pretrained(ref).save_pretrained(out)
for name in ("chat_template.jinja", "generation_config.json"):
    if os.path.isfile(os.path.join(ref, name)) and not os.path.isfile(os.path.join(out, name)):
        shutil.copy(os.path.join(ref, name), out)
print(f"tiny GLM: {sum(p.numel() for p in model.parameters()) / 1e6:.1f} M parameters, "
      f"{cfg.num_hidden_layers} layers, model_type {cfg.model_type} -> {out}")
