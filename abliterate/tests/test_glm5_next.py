"""GLM-5.3-Flash (model_type glm5_next): hybrid linear (KDA) + DSA attention, MoE, a vision encoder, and four residual
streams per token (manifold-constrained hyper-connections, mHC). A tiny random model of that architecture, built from
transformers' own implementation, checks:
- which tensors of the real checkpoint count as writers into the residual stream;
- the hooks: one measurement per layer (the mean of the streams), ablation in every stream;
- that the weight edit is exact: the edited model's logits equal the unedited model's with the direction projected out
  of every stream (inference-time ablation), and no stream of the edited model carries the direction;
- the loader picks AutoModelForImageTextToText for the families transformers registers only there;
- a reasoning block opened by the chat template at the generation prompt is closed empty."""
import json
import os
import tempfile
import unittest

import torch

from abliterate import arch
from abliterate.edit import Editor
from abliterate.hooks import HookedModel, auto_class, opens_think

try:
    from transformers import Glm5NextConfig, Glm5NextForConditionalGeneration
except ImportError:                                     # transformers without glm5_next (added for GLM-5.3-Flash)
    Glm5NextConfig = Glm5NextForConditionalGeneration = None

D = 64
QUIET = lambda *a, **k: None                            # noqa: E731

# names from zai-org/GLM-5.3-Flash's model.safetensors.index.json (revision 46a050b) and what the edit makes of them
FLASH_NAMES = {
    "model.language_model.embed_tokens.weight": "embed",
    "model.language_model.layers.0.self_attn.o_proj.weight": "attn_out",            # KDA (linear attention), bf16
    "model.language_model.layers.3.self_attn.o_proj.weight": "attn_out",            # DSA layer, FP8
    "model.language_model.layers.3.self_attn.o_proj.weight_scale_inv": "scale",
    "model.language_model.layers.0.mlp.down_proj.weight": "mlp_out",                # dense layers 0-2
    "model.language_model.layers.0.mlp.down_proj.weight_scale_inv": "scale",
    "model.language_model.layers.7.mlp.experts.287.down_proj.weight": "mlp_out",
    "model.language_model.layers.7.mlp.experts.287.down_proj.weight_scale_inv": "scale",
    "model.language_model.layers.7.mlp.shared_experts.down_proj.weight": "mlp_out",
    "model.language_model.layers.45.self_attn.o_proj.weight": "attn_out",           # the MTP layer, edited alike
    # readers and everything else stay as they are
    "model.language_model.layers.0.hc_attn_fn": None,                               # mHC: computes the stream weights
    "model.language_model.layers.0.hc_ffn_base": None,
    "model.language_model.layers.0.self_attn.q_proj.weight": None,
    "model.language_model.layers.0.self_attn.g_b_proj.weight": None,
    "model.language_model.layers.0.self_attn.o_norm.weight": None,
    "model.language_model.layers.0.self_attn.A_log": None,
    "model.language_model.layers.3.self_attn.indexer.wq_b.weight": None,
    "model.language_model.layers.3.self_attn.kv_b_proj.weight": None,
    "model.language_model.layers.7.mlp.gate.weight": None,
    "model.language_model.layers.7.mlp.gate.e_score_correction_bias": None,
    "model.language_model.layers.7.mlp.experts.0.gate_proj.weight": None,
    "model.language_model.layers.45.eh_proj.weight": None,
    "model.visual.merger.down_proj.weight": None,                                   # the vision encoder is not edited
    "model.visual.blocks.0.attn.proj.weight": None,
    "lm_head.weight": None,
    "model.language_model.norm.weight": None,
}


class FlashNames(unittest.TestCase):
    def test_residual_writers(self):
        for name, kind in FLASH_NAMES.items():
            with self.subTest(name=name):
                self.assertEqual(arch.classify(name), kind)


def tiny_model(seed=0):
    torch.manual_seed(seed)
    text = dict(vocab_size=96, hidden_size=D, intermediate_size=96, moe_intermediate_size=32, num_hidden_layers=4,
                num_attention_heads=2, num_key_value_heads=2, n_shared_experts=1, n_routed_experts=4, num_experts_per_tok=2,
                kv_lora_rank=16, q_lora_rank=24, qk_rope_head_dim=0, qk_nope_head_dim=16, v_head_dim=16,
                index_topk=8, index_head_dim=16, index_n_heads=2, index_kpool=4,
                layer_types=["linear_attention", "linear_attention", "linear_attention", "indexed_attention"],
                mlp_layer_types=["dense", "sparse", "sparse", "sparse"],
                linear_attn_config={"num_heads": 2, "head_dim": 16, "short_conv_kernel_size": 4},
                hc_mult=4, mhc=True, pad_token_id=0, eos_token_id=1, tie_word_embeddings=False, max_position_embeddings=256)
    vision = dict(depth=1, hidden_size=32, num_heads=2, intermediate_size=64, out_hidden_size=D, projection_intermediate_size=64,
                  image_size=28, patch_size=14)
    cfg = Glm5NextConfig(text_config=text, vision_config=vision, tie_word_embeddings=False, image_token_id=95, video_token_id=94,
                         image_start_token_id=93, image_end_token_id=92, video_start_token_id=91, video_end_token_id=90)
    model = Glm5NextForConditionalGeneration(cfg).to(torch.float32).eval()
    with torch.no_grad():                               # deterministic, finite and not degenerate (some tensors start empty)
        for name, p in model.named_parameters():
            if p.dim() == 1 and name.endswith("norm.weight"):
                p.fill_(1.0)
            elif name.endswith(".scale"):               # mHC: the scales of the pre / post / comb weights
                p.uniform_(0.5, 1.5)
            else:
                p.normal_(0.0, 0.08)
    return model


class Tok:
    """Just enough tokenizer for HookedModel; a template without a reasoning block unless `think_tpl`."""
    eos_token_id, pad_token_id = 1, 0

    def __init__(self, think_tpl=False):
        self.think_tpl, self.seen = think_tpl, None

    def _render(self, conv):
        return "<|user|>" + conv[-1]["content"] + "<|assistant|>" + ("<think>" if self.think_tpl else "")

    def apply_chat_template(self, convs, add_generation_prompt=True, tokenize=True, **kw):
        if convs and isinstance(convs[0], dict):
            convs = [convs]
            single = True
        else:
            single = False
        texts = [self._render(c) for c in convs]
        if not tokenize:
            return texts[0] if single else texts
        self.seen = ("tokenized", texts)
        n = max(len(t) for t in texts)
        ids = torch.tensor([[0] * (n - len(t)) + [2 + ord(ch) % 80 for ch in t] for t in texts])
        return {"input_ids": ids, "attention_mask": (ids != 0).long()}

    def __call__(self, texts, padding=True, return_tensors="pt", add_special_tokens=True):
        self.seen = ("text", list(texts), add_special_tokens)
        n = max(len(t) for t in texts)
        ids = torch.tensor([[0] * (n - len(t)) + [2 + ord(ch) % 80 for ch in t] for t in texts])
        return {"input_ids": ids, "attention_mask": (ids != 0).long()}


@unittest.skipIf(Glm5NextConfig is None, "transformers without glm5_next")
class TinyFlash(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = tiny_model()
        cls.hm = HookedModel(cls.model, Tok(), log=QUIET)
        g = torch.Generator().manual_seed(1)
        cls.ids = torch.randint(2, 90, (2, 9), generator=g)
        cls.mask = torch.ones_like(cls.ids)
        r = torch.randn(D, generator=g)
        cls.r = r / r.norm()

    def logits(self, model):
        with torch.no_grad():
            return model(input_ids=self.ids, attention_mask=self.mask, use_cache=False).logits

    def layer_outputs(self, model):
        outs = []
        hm = HookedModel(model, Tok(), log=QUIET)
        handles = [l.register_forward_hook(lambda m, a, o: outs.append(o[0] if isinstance(o, tuple) else o)) for l in hm.layers]
        try:
            self.logits(model)
        finally:
            for h in handles:
                h.remove()
        return outs

    def test_structure(self):
        self.assertEqual(self.hm.n_layers, 4)
        self.assertEqual(self.hm.d_model, D)
        self.assertEqual(self.hm.streams, 4)
        outs = self.layer_outputs(self.model)
        self.assertEqual(tuple(outs[0].shape), (2, 9, 4, D))       # [batch, seq, streams, d]: why the hooks need the mean

    def test_measure_takes_the_mean_of_the_streams(self):
        captured = []
        handles = [l.register_forward_pre_hook(lambda m, a, k: captured.append((a[0] if a else k["hidden_states"]).detach().clone()),
                                               with_kwargs=True) for l in self.hm.layers]
        try:
            self.logits(self.model)
        finally:
            for h in handles:
                h.remove()
        hm = HookedModel(self.model, Tok(), log=QUIET)
        hm.encode = lambda prompts: (self.ids[:len(prompts)], self.mask[:len(prompts)])
        mean, norms = hm.mean_resid_pre(["a", "b"], batch_size=2)
        self.assertEqual(tuple(mean.shape), (4, D))
        want = torch.stack([c[:, -1].mean(dim=1).mean(dim=0) for c in captured])
        torch.testing.assert_close(mean, want, rtol=1e-5, atol=1e-6)
        all_layers, _ = hm.resid_pre_all("a")
        self.assertEqual(tuple(all_layers.shape), (4, 9, D))

    def test_ablation_clears_every_stream(self):
        outs = []
        with self.hm.ablated(self.r):                   # registered after the ablation's hooks, so these see their result
            handles = [l.register_forward_hook(lambda m, a, o: outs.append(o[0])) for l in self.hm.layers]
            try:
                self.logits(self.model)
            finally:
                for h in handles:
                    h.remove()
        self.assertEqual(len(outs), 4)
        for o in outs:
            self.assertEqual(tuple(o.shape), (2, 9, 4, D))
            self.assertLess((o @ self.r).abs().max().item(), 1e-5)

    def test_weight_edit_equals_ablation(self):
        with self.hm.ablated(self.r):
            want = self.logits(self.model)
        base = self.logits(self.model)
        self.assertGreater((base - want).abs().max().item(), 1e-3)  # the direction matters: the comparison is not vacuous
        with tempfile.TemporaryDirectory() as d:
            src, dst = os.path.join(d, "src"), os.path.join(d, "dst")
            self.model.save_pretrained(src)
            kinds = {}
            for n in _names(src):
                k = arch.classify(n)
                if k:
                    kinds[k] = kinds.get(k, 0) + 1
            self.assertEqual((kinds.get("embed"), kinds.get("attn_out")), (1, 4))
            self.assertGreaterEqual(kinds.get("mlp_out", 0), 1 + 3 + 3)   # dense + shared + experts (fused or one per expert)
            Editor(src, dst, self.r.clone(), post_norm=False, log=QUIET).run()
            edited = Glm5NextForConditionalGeneration.from_pretrained(dst, dtype=torch.float32).eval()
        got = self.logits(edited)
        torch.testing.assert_close(got, want, rtol=1e-4, atol=1e-4)
        for o in self.layer_outputs(edited):            # without any hook: no stream carries the direction
            self.assertLess((o @ self.r).abs().max().item(), 1e-4)


def _names(folder):
    """Tensor names of a saved checkpoint (sharded or one file)."""
    idx = os.path.join(folder, "model.safetensors.index.json")
    if os.path.isfile(idx):
        with open(idx, encoding="utf-8") as f:
            return list(json.load(f)["weight_map"])
    from safetensors import safe_open
    with safe_open(os.path.join(folder, "model.safetensors"), "pt") as f:
        return list(f.keys())


class Loader(unittest.TestCase):
    def test_auto_class(self):
        import transformers
        with tempfile.TemporaryDirectory() as d:
            for mt, remote, want in (("glm5_next", False, "AutoModelForImageTextToText"), ("glm4v_moe", False, "AutoModelForImageTextToText"),
                                     ("glm", False, "AutoModelForCausalLM"), ("glm_moe_dsa", False, "AutoModelForCausalLM"),
                                     ("glm5_next", True, "AutoModelForCausalLM"), ("", False, "AutoModelForCausalLM")):
                with self.subTest(model_type=mt, remote=remote):
                    with open(os.path.join(d, "config.json"), "w") as f:
                        json.dump({"model_type": mt}, f)
                    self.assertIs(auto_class(d, remote), getattr(transformers, want))


class ReasoningBlock(unittest.TestCase):
    """GLM-5.3 and GLM-5.3-Flash end the generation prompt with '<|assistant|><think>'."""

    class _Model(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.model = torch.nn.Module()
            self.model.layers = torch.nn.ModuleList([type("FakeDecoderLayer", (torch.nn.Module,), {})()])
            self.p = torch.nn.Parameter(torch.zeros(1))
            self.config = type("C", (), {"hidden_size": 8})()

    def test_closed_empty(self):
        tok = Tok(think_tpl=True)
        hm = HookedModel(self._Model(), tok, log=QUIET)
        self.assertTrue(hm.close_think)
        hm.encode(["hi"])
        self.assertEqual(tok.seen, ("text", ["<|user|>hi<|assistant|><think></think>"], False))

    def test_kept_with_think(self):
        tok = Tok(think_tpl=True)
        hm = HookedModel(self._Model(), tok, log=QUIET, think=True)
        self.assertFalse(hm.close_think)
        hm.encode(["hi"])
        self.assertEqual(tok.seen[0], "tokenized")

    def test_other_templates_unchanged(self):
        tok = Tok(think_tpl=False)
        hm = HookedModel(self._Model(), tok, log=QUIET)
        self.assertFalse(hm.close_think)
        hm.encode(["hi"])
        self.assertEqual(tok.seen, ("tokenized", ["<|user|>hi<|assistant|>"]))

    def test_opens_think(self):
        self.assertTrue(opens_think("<|assistant|><think>"))
        self.assertTrue(opens_think("<|assistant|><think>\n"))
        self.assertFalse(opens_think("<|assistant|><think></think>"))
        self.assertFalse(opens_think("<|assistant|>"))


if __name__ == "__main__":
    unittest.main()
