"""Several directions: the edit and the ablation remove the subspace spanned by the refusal directions of several layers.
- the projections for k = 1, 2, 3: the results are orthogonal to the subspace, k = 1 is exactly the single-direction
  edit and ablation, non-orthogonal directions act through their QR basis; and why: removing non-orthogonal directions
  one after the other leaves a component along the first one;
- tiny models with a two-direction subspace: the edited model's logits equal the inference-time ablation with the same
  subspace (glm5_next with its four residual streams, a pre-norm GLM); a post-norm GLM-4 gets what the folded edit
  promises, as for one direction: no residual write keeps a component in the subspace;
- the pipeline: --layers, the --combine pass, the rule with combinations, apply saving the basis, the weight check;
- the command line end to end on a tiny GLM: scan with --combine, pause, continue with --layers, validate.

    python -m unittest discover -s abliterate/tests -t .
"""
import argparse
import contextlib
import gc
import io
import json
import os
import shutil
import tempfile
import unittest
import warnings
from unittest import mock

import torch
from safetensors import safe_open

from abliterate import arch
from abliterate import pipeline as P
from abliterate.edit import Editor, basis, expected_targets, fold, orth_out, orth_rows, orth_vec, residual_component
from abliterate.hooks import HookedModel
from abliterate.tests.test_glm5_next import TPL_PLAIN, Glm5NextForConditionalGeneration, Tok, chat_tokenizer, tiny_model
from abliterate.validate import compare_weights, weight_checks

QUIET = lambda *a, **k: None                            # noqa: E731
D = 64


# the single-direction edit and ablation as they were written before several directions (the reference for k = 1)
def old_orth_rows(Wf, r):
    return Wf - torch.outer(Wf @ r, r)


def old_orth_out(Wf, r):
    if Wf.dim() == 3:
        return Wf - r[None, :, None] * torch.einsum("d,edi->ei", r, Wf)[:, None, :]
    return Wf - torch.outer(r, r @ Wf)


def old_residual_component(Wf, r, kind):
    if kind == "embed":
        return (Wf @ r).abs().max().item()
    if Wf.dim() == 3:
        return torch.einsum("d,edi->ei", r, Wf).abs().max().item()
    if Wf.dim() == 1:
        return abs(float(Wf @ r))
    return (r @ Wf).abs().max().item()


def unit(v):
    return v / v.norm()


def read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def read_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def read_events(run_dir):
    with open(os.path.join(run_dir, "events.jsonl"), encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def new_run(project, run_dir, test):
    """A pipeline Run whose log files the test closes again."""
    run = P.Run(project, run_dir)
    test.addCleanup(run.ev_f.close)
    test.addCleanup(run.log_f.close)
    return run


def directions(k, d=D, seed=0, overlap=1.0):
    """k unit directions that are far from orthogonal (pairwise cosines around 0.5), like neighbouring layers'."""
    g = torch.Generator().manual_seed(seed)
    common = torch.randn(d, generator=g)
    return torch.stack([unit(overlap * common + torch.randn(d, generator=g)) for _ in range(k)])


class Projections(unittest.TestCase):
    def setUp(self):
        g = torch.Generator().manual_seed(1)
        self.W = torch.randn(D, 40, generator=g)            # [d, in]: an output projection
        self.E = torch.randn(50, D, generator=g)            # [V, d]: embedding rows
        self.X = torch.randn(3, D, 24, generator=g)         # [E, d, in]: fused experts
        self.b = torch.randn(D, generator=g)                # a bias

    def test_basis_is_orthonormal_and_spans_the_directions(self):
        for k in (2, 3):
            with self.subTest(k=k):
                dirs = directions(k)
                self.assertGreater(abs(float(dirs[0] @ dirs[1])), 0.3)       # far from orthogonal
                Q, kept = basis(dirs)
                self.assertEqual((tuple(Q.shape), kept), ((D, k), list(range(k))))
                self.assertEqual(Q.dtype, torch.float32)
                torch.testing.assert_close(Q.T @ Q, torch.eye(k), rtol=0, atol=1e-6)
                torch.testing.assert_close(dirs @ Q @ Q.T, dirs, rtol=0, atol=1e-6)   # every direction lies in span(Q)

    def test_one_direction_is_exactly_the_old_edit(self):
        r_in = directions(1)[0] * 1.0001                     # a measured direction is unit up to rounding
        r = r_in.float().cpu()
        r = r / r.norm()                                    # what the editor did before
        for given in (r_in, r_in[None]):                    # [d] or [1, d]
            Q, kept = basis(given)
            self.assertEqual((tuple(Q.shape), kept), ((D, 1), [0]))
            self.assertTrue(torch.equal(Q[:, 0], r))
            self.assertTrue(torch.equal(orth_out(self.W, Q), old_orth_out(self.W, r)))
            self.assertTrue(torch.equal(orth_out(self.X, Q), old_orth_out(self.X, r)))
            self.assertTrue(torch.equal(orth_rows(self.E, Q), old_orth_rows(self.E, r)))
            self.assertTrue(torch.equal(orth_vec(self.b, Q), self.b - (self.b @ r) * r))
            for W, kind in ((self.W, "attn_out"), (self.X, "mlp_out"), (self.E, "embed"), (self.b, "mlp_out")):
                self.assertEqual(residual_component(W, Q, kind), old_residual_component(W, r, kind))
        # and the general formula W - Q (Q^T W) is the same projection for k = 1 (up to the order of the float sums)
        Qm = r[:, None]
        torch.testing.assert_close(self.W - Qm @ (Qm.T @ self.W), old_orth_out(self.W, r), rtol=0, atol=1e-5)
        torch.testing.assert_close(self.E - (self.E @ Qm) @ Qm.T, old_orth_rows(self.E, r), rtol=0, atol=1e-5)

    def test_the_subspace_is_removed_and_nothing_else(self):
        for k in (1, 2, 3):
            with self.subTest(k=k):
                Q = basis(directions(k))[0]
                P_out = torch.eye(D) - Q @ Q.T              # the part outside the subspace
                W2, X2, E2, b2 = orth_out(self.W, Q), orth_out(self.X, Q), orth_rows(self.E, Q), orth_vec(self.b, Q)
                self.assertLess((Q.T @ W2).abs().max().item(), 1e-5)
                self.assertLess(torch.einsum("dk,edi->eki", Q, X2).abs().max().item(), 1e-5)
                self.assertLess((E2 @ Q).abs().max().item(), 1e-5)
                self.assertLess((b2 @ Q).abs().max().item(), 1e-5)
                for W, kind in ((W2, "attn_out"), (X2, "mlp_out"), (E2, "embed"), (b2, "attn_out")):
                    self.assertLess(residual_component(W, Q, kind), 1e-5)
                torch.testing.assert_close(P_out @ W2, P_out @ self.W, rtol=0, atol=1e-5)
                torch.testing.assert_close(E2 @ P_out, self.E @ P_out, rtol=0, atol=1e-5)
                torch.testing.assert_close(orth_out(W2, Q), W2, rtol=0, atol=1e-5)          # a projection: twice is once
                self.assertGreater(residual_component(self.W, Q, "attn_out"), 0.1)          # before the edit there was a component

    def test_non_orthogonal_directions_act_through_their_qr_basis(self):
        for k in (2, 3):
            with self.subTest(k=k):
                dirs = directions(k, seed=k)
                Q_ref = torch.linalg.qr(dirs.double().T)[0].float()
                Q = basis(dirs)[0]
                torch.testing.assert_close(Q @ Q.T, Q_ref @ Q_ref.T, rtol=0, atol=1e-6)    # the same subspace
                torch.testing.assert_close(orth_out(self.W, Q), orth_out(self.W, Q_ref), rtol=0, atol=1e-5)
                torch.testing.assert_close(orth_out(self.X, Q), orth_out(self.X, Q_ref), rtol=0, atol=1e-5)
                torch.testing.assert_close(orth_rows(self.E, Q), orth_rows(self.E, Q_ref), rtol=0, atol=1e-5)
                # the directions themselves, used as if they were orthonormal, do not remove the subspace
                naive = self.W - dirs.T @ (dirs @ self.W)
                self.assertGreater((Q.T @ naive).abs().max().item(), 0.1)

    def test_why_a_subspace_one_after_the_other_leaves_the_first_direction(self):
        r1, r2 = directions(2, seed=3)
        cos = float(r1 @ r2)
        self.assertGreater(abs(cos), 0.3)
        # an activation: remove r1, then r2 - the second step puts part of r1 back
        x = torch.randn(D, generator=torch.Generator().manual_seed(4))
        x1 = x - (x @ r1) * r1
        x2 = x1 - (x1 @ r2) * r2
        self.assertAlmostEqual(float(x2 @ r1), -float(x1 @ r2) * cos, places=4)     # what is left along r1
        self.assertGreater(abs(float(x2 @ r1)), 0.05)
        self.assertLess(abs(float(x2 @ r2)), 1e-5)
        Q = basis(torch.stack([r1, r2]))[0]
        xq = x - Q @ (Q.T @ x)
        self.assertLess(max(abs(float(xq @ r1)), abs(float(xq @ r2))), 1e-5)
        # the same for weights: one after the other, the edited matrix can still write r1
        seq = old_orth_out(old_orth_out(self.W, r1), r2)
        self.assertGreater((r1 @ seq).abs().max().item(), 0.05)
        sub = orth_out(self.W, Q)
        self.assertLess(max((r1 @ sub).abs().max().item(), (r2 @ sub).abs().max().item()), 1e-5)
        self.assertGreater((seq - sub).abs().max().item(), 1e-2)

    def test_a_dependent_direction_is_dropped(self):
        r1, r2 = directions(2, seed=5)
        noise = torch.randn(D, generator=torch.Generator().manual_seed(6))
        nearly = unit(0.6 * r1 + 0.8 * r2 + 1e-5 * noise)   # (nearly) a combination of the first two
        logs = []
        Q, kept = basis(torch.stack([r1, nearly, r2]), log=logs.append, names=["layer 15", "layer 17", "layer 19"])
        self.assertEqual((tuple(Q.shape), kept), ((D, 2), [0, 1]))
        self.assertEqual(len(logs), 1)
        self.assertIn("layer 19", logs[0])                 # in this order the third one adds nothing
        self.assertIn("dropped", logs[0])
        torch.testing.assert_close(Q @ Q.T @ r2, r2, rtol=0, atol=1e-4)               # the subspace still holds it
        logs.clear()
        Q, kept = basis(torch.stack([r1, r1, r2]), log=logs.append)                   # the same layer twice
        self.assertEqual((Q.shape[1], kept, len(logs)), (2, [0, 2], 1))
        self.assertIn("direction 1", logs[0])

    def test_post_norm_fold(self):
        g = torch.empty(D).uniform_(0.5, 1.5, generator=torch.Generator().manual_seed(7))
        r = basis(directions(1))[0]
        rt = g * r[:, 0]
        self.assertTrue(torch.equal(fold(r, g)[:, 0], rt / rt.norm()))               # k = 1: r~ = normalize(g * r), as before
        Q = basis(directions(2, seed=8))[0]
        F = fold(Q, g)
        self.assertEqual(tuple(F.shape), (D, 2))
        torch.testing.assert_close(F.T @ F, torch.eye(2), rtol=0, atol=1e-6)
        GQ = g[:, None] * Q
        torch.testing.assert_close(F @ F.T @ GQ, GQ, rtol=0, atol=1e-5)              # span(F) = span(g * q_j)
        # the promise: a projection output y without span(F) leaves RMSNorm(g) without any component in span(Q)
        y = torch.randn(5, D, generator=torch.Generator().manual_seed(9))
        y2 = y - (y @ F) @ F.T
        out = g * y2 / y2.pow(2).mean(-1, keepdim=True).sqrt()
        self.assertLess((out @ Q).abs().max().item(), 1e-5)
        out_plain = g * (y - (y @ Q) @ Q.T)                 # removing span(Q) itself before the norm does not do it
        self.assertGreater((out_plain @ Q).abs().max().item(), 1e-2)


class FakeLayer(torch.nn.Module):
    """A decoder layer stand-in: changes its input, so the hooks before and after it both matter."""
    def forward(self, hidden_states):
        return hidden_states * 1.5 + 0.25


class FakeDecoderLayerStack(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.model = torch.nn.Module()
        self.model.layers = torch.nn.ModuleList([type("FakeDecoderLayer", (FakeLayer,), {})() for _ in range(2)])
        self.p = torch.nn.Parameter(torch.zeros(1))
        self.config = type("C", (), {"hidden_size": D})()

    def forward(self, x):
        for layer in self.model.layers:
            x = layer(hidden_states=x)
        return x


class Ablation(unittest.TestCase):
    """HookedModel.ablated on a stand-in with an mHC-shaped residual ([batch, seq, streams, d])."""

    def setUp(self):
        self.model = FakeDecoderLayerStack()
        self.hm = HookedModel(self.model, Tok(), log=QUIET)
        self.x = torch.randn(2, 5, 4, D, generator=torch.Generator().manual_seed(10))

    def run_ablated(self, direction):
        with torch.no_grad(), self.hm.ablated(direction):
            return self.model(self.x)

    def test_one_direction_is_exactly_the_old_ablation(self):
        r = directions(1)[0]
        want = self.x
        for _ in range(2):                                  # before the layer, after it; for both layers
            want = want - (want @ r).unsqueeze(-1) * r
            want = want * 1.5 + 0.25
            want = want - (want @ r).unsqueeze(-1) * r
        self.assertTrue(torch.equal(self.run_ablated(r), want))
        self.assertTrue(torch.equal(self.run_ablated(r[None]), want))

    def test_several_directions_leave_no_stream_with_any_of_them(self):
        for k in (2, 3):
            with self.subTest(k=k):
                dirs = directions(k, seed=11)
                out = self.run_ablated(dirs)
                self.assertEqual(tuple(out.shape), tuple(self.x.shape))
                self.assertLess((out @ dirs.T).abs().max().item(), 1e-5)          # every stream, every direction
                Q = basis(dirs)[0]
                torch.testing.assert_close(out @ (torch.eye(D) - Q @ Q.T),
                                           self.model(self.x - (self.x @ Q) @ Q.T) @ (torch.eye(D) - Q @ Q.T), rtol=0, atol=1e-5)
        logs = []
        self.hm.log = logs.append
        self.run_ablated(torch.stack([dirs[0], dirs[0], dirs[1]]))                  # a duplicate is dropped, with a log line
        self.assertEqual(len(logs), 1)


def tiny_glm(cfg_cls, model_cls, seed=0, layers=3):
    """A random GLM-family model (pre-norm glm or post-norm glm4) with weights large enough to matter. Norm weights are
    not all one, so a fold through them changes the basis."""
    torch.manual_seed(seed)
    cfg = cfg_cls(vocab_size=300, hidden_size=D, intermediate_size=96, num_hidden_layers=layers, num_attention_heads=4,
                  num_key_value_heads=2, head_dim=16, tie_word_embeddings=False, pad_token_id=0, eos_token_id=1,
                  max_position_embeddings=256)
    model = model_cls(cfg).to(torch.float32).eval()
    with torch.no_grad():
        for name, p in model.named_parameters():
            if name.endswith("norm.weight"):
                p.uniform_(0.5, 1.5)
            else:
                p.normal_(0.0, 0.08)
    return model


def tensors(folder):
    with safe_open(os.path.join(folder, "model.safetensors"), "pt") as f:
        return {k: f.get_tensor(k) for k in f.keys()}


class TinyModels(unittest.TestCase):
    """The weight edit with a two-direction subspace against the inference-time ablation with the same subspace."""

    @classmethod
    def setUpClass(cls):
        g = torch.Generator().manual_seed(12)
        cls.ids = torch.randint(2, 290, (2, 9), generator=g)
        cls.mask = torch.ones_like(cls.ids)
        cls.dirs = directions(2, seed=13)
        cls.Q = basis(cls.dirs)[0]
        cls.tmp = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def logits(self, model, ids=None):
        with torch.no_grad():
            ids = self.ids if ids is None else ids
            return model(input_ids=ids, attention_mask=torch.ones_like(ids), use_cache=False).logits

    def edited(self, model, cls, direction, post_norm, name):
        src, dst = os.path.join(self.tmp, name + "-src"), os.path.join(self.tmp, name + "-dst")
        model.save_pretrained(src)
        stats = Editor(src, dst, direction, post_norm=post_norm, log=QUIET).run()
        return cls.from_pretrained(dst, dtype=torch.float32).eval(), stats, src, dst

    def check_equals_ablation(self, model, cls, name, ids=None):
        hm = HookedModel(model, Tok(), log=QUIET)
        with hm.ablated(self.dirs):
            want = self.logits(model, ids)
        self.assertGreater((self.logits(model, ids) - want).abs().max().item(), 1e-3)   # the subspace matters
        edited, stats, _, _ = self.edited(model, cls, self.dirs, False, name)
        self.assertEqual(stats["directions"], 2)
        torch.testing.assert_close(self.logits(edited, ids), want, rtol=1e-4, atol=1e-4)
        outs = []
        handles = [l.register_forward_hook(lambda m, a, o: outs.append(o[0] if isinstance(o, tuple) else o))
                   for l in HookedModel(edited, Tok(), log=QUIET).layers]
        try:
            self.logits(edited, ids)
        finally:
            for h in handles:
                h.remove()
        for o in outs:                                       # without any hook: the residual stream lacks the subspace
            self.assertLess((o @ self.Q).abs().max().item(), 1e-4)
        return edited

    @unittest.skipIf(Glm5NextForConditionalGeneration is None, "transformers without glm5_next")
    def test_glm5_next_streams(self):
        ids = torch.randint(2, 90, (2, 9), generator=torch.Generator().manual_seed(14))
        self.check_equals_ablation(tiny_model(), Glm5NextForConditionalGeneration, "flash", ids)

    def test_pre_norm_glm(self):
        from transformers import GlmConfig, GlmForCausalLM
        model = tiny_glm(GlmConfig, GlmForCausalLM)
        self.assertEqual(model.config.model_type, "glm")
        self.check_equals_ablation(model, GlmForCausalLM, "glm")

    def test_post_norm_glm4_folded(self):
        """Post-norm (GLM-4): RMSNorm(g) sits between each projection and the residual add, so the edit folds the basis
        through g (edit.fold). What that guarantees, as for one direction: the blocks' normalized outputs, and with the
        embedding the whole residual stream, keep no component in the subspace. The rest of each output is scaled by
        the changed per-token RMS, so the edit is not the ablation itself (support level "folded")."""
        from transformers import Glm4Config, Glm4ForCausalLM
        model = tiny_glm(Glm4Config, Glm4ForCausalLM)
        self.assertEqual(model.config.model_type, "glm4")
        for k, direction in ((1, self.dirs[0]), (2, self.dirs)):
            with self.subTest(k=k):
                Q = basis(direction)[0]
                edited, stats, _, _ = self.edited(model, Glm4ForCausalLM, direction, True, f"glm4-{k}")
                self.assertEqual((stats["folded"], stats["directions"]), (2 * 3, k))
                writes, resid = self.post_norm_outputs(edited)
                self.assertEqual(len(writes), 2 * 3)
                for o in writes + resid:
                    self.assertLess((o @ Q).abs().max().item(), 1e-4)
                # the fold is what does it: the same subspace removed without folding leaves it in the writes
                plain, _, _, _ = self.edited(model, Glm4ForCausalLM, direction, False, f"glm4-plain-{k}")
                writes, _ = self.post_norm_outputs(plain)
                self.assertGreater(max((o @ Q).abs().max().item() for o in writes), 1e-2)

    def post_norm_outputs(self, model):
        writes, resid, handles = [], [], []
        for layer in HookedModel(model, Tok(), log=QUIET).layers:
            for norm in (layer.post_self_attn_layernorm, layer.post_mlp_layernorm):
                handles.append(norm.register_forward_hook(lambda m, a, o: writes.append(o)))
            handles.append(layer.register_forward_hook(lambda m, a, o: resid.append(o[0] if isinstance(o, tuple) else o)))
        try:
            self.logits(model)
        finally:
            for h in handles:
                h.remove()
        return writes, resid

    def test_one_layer_edit_is_bitwise_the_old_edit(self):
        """k = 1 through the new code gives exactly the tensors the single-direction editor wrote (with the post-norm
        fold r~ = normalize(g * r) for GLM-4)."""
        from transformers import Glm4Config, Glm4ForCausalLM, GlmConfig, GlmForCausalLM
        r_in = self.dirs[1] * 0.9999
        r = r_in.float().cpu()
        r = r / r.norm()
        for cfg_cls, model_cls, post_norm in ((GlmConfig, GlmForCausalLM, False), (Glm4Config, Glm4ForCausalLM, True)):
            with self.subTest(post_norm=post_norm):
                name = f"old-{int(post_norm)}"
                _, _, src, dst = self.edited(tiny_glm(cfg_cls, model_cls, seed=15), model_cls, r_in, post_norm, name)
                before, after = tensors(src), tensors(dst)
                n = 0
                for key, W in before.items():
                    kind = arch.classify(key)
                    if kind not in ("embed", "attn_out", "mlp_out"):
                        self.assertTrue(torch.equal(after[key], W), key)
                        continue
                    rr = r
                    if post_norm and kind != "embed":
                        g = before[arch.post_norm_name(key, kind)].float()
                        rr = g * r
                        rr = rr / rr.norm()
                    Wf = W.float()
                    want = (Wf - (Wf @ rr) * rr) if W.dim() == 1 else (old_orth_rows(Wf, rr) if kind == "embed" else old_orth_out(Wf, rr))
                    self.assertTrue(torch.equal(after[key], want.to(W.dtype)), key)
                    n += 1
                self.assertEqual(n, 1 + 2 * 3)


# ----------------------------------------------------------------------------- the pipeline
def scan_entry(layer, refusals, cjk=0.0):
    return {"layer": layer, "refusals": refusals, "norm": 1.0, "cjk_ratio": cjk, "generations": ["g"]}


class Choice(unittest.TestCase):
    def test_parse_layers(self):
        for text, want in (("15,17,19", [15, 17, 19]), ("15-19", [15, 16, 17, 18, 19]), ("12, 15-17", [12, 15, 16, 17]),
                           ("17,15,17", [17, 15]), ("15-17,16", [15, 16, 17]), ("3", [3]), ("0-0", [0])):
            with self.subTest(text=text):
                self.assertEqual(P.parse_layers(text), want)
        for text in ("", "a", "15-", "-3", "19-15", "1.5", "15;17", "0-99999"):
            with self.subTest(text=text), self.assertRaises(argparse.ArgumentTypeError):
                P.parse_layers(text)

    def test_check_layers_and_label(self):
        P.check_layers([0, 39], 40)
        with self.assertRaises(P.UsageError) as e:
            P.check_layers([17, 40, 52], 40)
        self.assertIn("layer 40, 52 does not exist", str(e.exception))
        self.assertIn("0 to 39", str(e.exception))
        self.assertEqual(P.layers_label([17]), "layer 17")
        self.assertEqual(P.layers_label([19, 15, 17]), "layers 15+17+19")

    def test_command_line_refuses_both_and_bad_values(self):
        for argv in (["--model", "m", "--layer", "3", "--layers", "4,5"], ["--model", "m", "--layers", "4,x"],
                     ["--model", "m", "--combine", "-1"]):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit) as e:
                P.main(argv)
            self.assertEqual(e.exception.code, 2)
            self.assertTrue(err.getvalue())

    def test_the_ranking_starts_with_the_rules_layer(self):
        g = torch.Generator().manual_seed(16)
        for _ in range(200):
            scan = [scan_entry(l, int(torch.randint(0, 4, (1,), generator=g)), round(float(torch.rand(1, generator=g)) * 0.4, 2))
                    for l in range(5, 12)]
            self.assertEqual(P.rank_layers(scan)[0]["layer"], P.choose_layer(scan))

    def test_combo_layers(self):
        scan = [scan_entry(12, 3), scan_entry(13, 1), scan_entry(14, 0, cjk=0.6), scan_entry(15, 1, cjk=0.1), scan_entry(16, 2)]
        # layer 14 has the fewest refusals but mostly Chinese answers: it ranks last, as the rule never picks it
        self.assertEqual([s["layer"] for s in P.rank_layers(scan)], [13, 15, 16, 12, 14])
        self.assertEqual(P.combo_layers(scan, 3), [[13, 15], [13, 15, 16]])
        self.assertEqual(P.combo_layers(scan, 9), [[13, 15], [13, 15, 16], [13, 15, 16, 12], [13, 15, 16, 12, 14]])
        self.assertEqual(P.combo_layers(scan, 1), [])
        self.assertEqual(P.combo_layers(scan, 0), [])

    def test_choose_layers_with_combos(self):
        scan = [scan_entry(13, 2), scan_entry(15, 2, cjk=0.1), scan_entry(16, 3)]
        combo = lambda layers, refusals, cjk=0.0: {"layers": layers, "refusals": refusals, "cjk": cjk}   # noqa: E731
        self.assertEqual(P.choose_layers(scan), [13])
        self.assertEqual(P.choose_layers(scan, []), [13])
        self.assertEqual(P.choose_layers(scan, [combo([13, 15], 2)]), [13])                      # as good: one layer is milder
        self.assertEqual(P.choose_layers(scan, [combo([13, 15], 1)]), [13, 15])                  # strictly fewer
        self.assertEqual(P.choose_layers(scan, [combo([13, 15], 0, cjk=0.5)]), [13])             # fewer, but mostly Chinese
        self.assertEqual(P.choose_layers(scan, [combo([13, 15], 1), combo([13, 15, 16], 0)]), [13, 15, 16])
        self.assertEqual(P.choose_layers(scan, [combo([13, 15], 1, cjk=0.1), combo([13, 15, 16], 1)]), [13, 15, 16])
        self.assertEqual(P.choose_layers(scan, [combo([13, 15], 1), combo([13, 15, 16], 1)]), [13, 15])   # fewer layers
        # the CJK rule also guards the best single layer: here every layer fails it, the combination must still pass it
        bad = [scan_entry(13, 2, cjk=0.5), scan_entry(15, 3, cjk=0.4)]
        self.assertEqual(P.choose_layers(bad, [combo([13, 15], 0, cjk=0.3)]), [13])
        self.assertEqual(P.choose_layers(bad, [combo([13, 15], 0, cjk=0.2)]), [13, 15])

    def test_scan_refusals(self):
        scan = [scan_entry(13, 2), scan_entry(15, 1)]
        combos = [{"layers": [15, 13], "refusals": 0, "cjk": 0.0}]
        self.assertEqual(P.scan_refusals([15], scan, combos), 1)
        self.assertEqual(P.scan_refusals([13, 15], scan, combos), 0)        # any order
        self.assertIsNone(P.scan_refusals([13, 16], scan, combos))
        self.assertIsNone(P.scan_refusals([13, 15], scan, None))
        self.assertIsNone(P.scan_refusals([13], None))


class FakeHM:
    """generate() answers like a model whose refusals depend on which layers' directions are removed (a script)."""

    def __init__(self, dirs, refusals, chinese=()):
        self.dirs, self.refusals, self.chinese, self.calls = dirs, refusals, set(chinese), []

    def generate(self, prompts, max_new_tokens, batch_size, direction=None):
        rows = [] if direction is None else (direction[None] if direction.dim() == 1 else direction)
        key = tuple(sorted(int((self.dirs @ r).argmax()) for r in rows))
        self.calls.append((key, None if direction is None else tuple(direction.shape)))
        n = self.refusals.get(key, len(prompts))
        answer = "当然可以，这是方法。" if key in self.chinese else "Sure, here is how."
        return ["I cannot help with that."] * n + [answer] * (len(prompts) - n)


class CombinePass(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        with contextlib.redirect_stdout(io.StringIO()):
            self.run_ = new_run(self.tmp, os.path.join(self.tmp, "runs", "abliterate_1"), self)
        self.dirs = directions(6, d=32, seed=17, overlap=0.0)
        self.prompts = ([], [f"harmful {i}" for i in range(8)], [], [])
        self.la = {"scan_range": [1, 4], "norms": [1.0] * 6}

    def scan(self, combine, refusals, chinese=()):
        hm = FakeHM(self.dirs, refusals, chinese)
        args = argparse.Namespace(max_new_tokens=4, gen_batch=2, combine=combine)
        with contextlib.redirect_stdout(io.StringIO()):
            out = P.step_scan(self.run_, hm, args, self.prompts, self.dirs, self.la)
        events = read_events(self.run_.run_dir)
        return out, hm, events

    def test_the_best_layers_are_tested_together(self):
        refusals = {(): 8, (1,): 3, (2,): 1, (3,): 2, (4,): 1, (2, 4): 1, (2, 3, 4): 0}
        (scan, _, n_base, combos), hm, events = self.scan(3, refusals)
        self.assertEqual(n_base, 8)
        self.assertEqual([s["layer"] for s in scan], [2, 4, 3, 1])                       # scan_results.json as before
        self.assertEqual(read_json(os.path.join(self.run_.run_dir, "scan_results.json"))[0]["layer"], 2)
        self.assertEqual([c["layers"] for c in combos], [[2, 4], [2, 4, 3]])             # the best 2 and 3, best first
        self.assertEqual([(c["refusals"], c["cjk"]) for c in combos], [(1, 0.0), (0, 0.0)])
        self.assertEqual(hm.calls[-2:], [((2, 4), (2, 32)), ((2, 3, 4), (3, 32))])       # one pass each, a [k, d] matrix
        saved = read_json(os.path.join(self.run_.run_dir, "scan.json"))
        self.assertEqual(saved["combine"], 3)
        self.assertEqual(saved["best_single"], {"layer": 2, "refusals": 1, "cjk_ratio": 0.0})
        self.assertEqual(saved["recommended"], [2, 4, 3])                                # strictly fewer than layer 2 alone
        self.assertEqual([c["layers"] for c in saved["combos"]], [[2, 4], [2, 4, 3]])
        self.assertEqual(len(saved["combos"][0]["generations"]), 8)
        self.assertEqual(P.choose_layers(scan, combos), [2, 4, 3])
        steps = [(e["step"], e["status"]) for e in events]
        self.assertEqual(steps[-3:], [("scan", "combo"), ("scan", "combo"), ("scan", "done")])   # combos before the scan ends
        self.assertEqual(events[-1]["combos"], [[[2, 4], 1], [[2, 4, 3], 0]])
        self.assertEqual((events[-3]["layers"], events[-3]["refusals"], events[-3]["cjk"]), ([2, 4], 1, 0.0))

    def test_a_combination_must_beat_the_best_layer_and_stay_out_of_chinese(self):
        refusals = {(): 8, (1,): 3, (2,): 1, (3,): 2, (4,): 1, (2, 4): 0, (2, 3, 4): 1}
        (scan, _, _, combos), _, _ = self.scan(3, refusals, chinese={(2, 4)})
        self.assertGreater(combos[0]["cjk"], P.CJK_MAX)
        self.assertEqual(P.choose_layers(scan, combos), [2])                           # 0 refusals, but Chinese; 1 is no better
        self.assertEqual(read_json(os.path.join(self.run_.run_dir, "scan.json"))["recommended"], [2])

    def test_off_by_default(self):
        (scan, _, _, combos), hm, events = self.scan(0, {(): 8, (2,): 1})
        self.assertIsNone(combos)
        self.assertEqual(len(hm.calls), 1 + 4)                                          # baseline + four layers
        self.assertFalse(os.path.exists(os.path.join(self.run_.run_dir, "scan.json")))
        self.assertNotIn("combos", events[-1])


# ----------------------------------------------------------------------------- apply and validate on a tiny GLM
def save_tiny_glm(folder, layers=4):
    from transformers import GlmConfig, GlmForCausalLM
    model = tiny_glm(GlmConfig, GlmForCausalLM, seed=18, layers=layers)
    model.save_pretrained(folder)
    chat_tokenizer(TPL_PLAIN).save_pretrained(folder)
    return model


class ApplyAndValidate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.src = os.path.join(cls.tmp, "tiny-glm")
        save_tiny_glm(cls.src)
        cls.dirs = directions(4, seed=19)                    # one unit direction per layer
        cls.info = {"post_norm": False, "moe": False}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def apply(self, layers, name, dirs=None):
        with contextlib.redirect_stdout(io.StringIO()):
            run = new_run(self.tmp, os.path.join(self.tmp, "runs", name), self)
            out = os.path.join(self.tmp, "out-" + name)
            direction = P.step_apply(run, argparse.Namespace(), self.src, out, self.dirs if dirs is None else dirs, layers, self.info)
        events = read_events(run.run_dir)
        return run, out, direction, events

    def test_several_layers(self):
        run, out, direction, events = self.apply([3, 1], "two")
        saved = torch.load(os.path.join(out, "refusal_direction.pt"))
        self.assertEqual((saved["layer"], saved["layers"]), (3, [3, 1]))
        self.assertTrue(torch.equal(saved["direction"], self.dirs[[3, 1]]))           # the directions, as before for one
        self.assertTrue(torch.equal(direction, saved["direction"]))
        self.assertTrue(torch.equal(saved["basis"], basis(self.dirs[[3, 1]])[0]))     # and the basis next to them
        meta = read_json(run.meta_path)
        self.assertEqual((meta["layer"], meta["layers"]), (3, [3, 1]))
        stats = read_json(os.path.join(run.run_dir, "apply.json"))
        self.assertEqual((stats["layer"], stats["layers"], stats["directions"]), (3, [3, 1], 2))
        self.assertNotIn("dropped", stats)
        start, done = (e for e in events if e["step"] == "apply" and e["status"] in ("start", "done"))
        self.assertEqual((start["layer"], start["layers"], done["layers"], done["directions"]), (3, [3, 1], [3, 1], 2))
        cmp = compare_weights(self.src, out, saved["direction"], QUIET)
        self.assertEqual(cmp["k"], 2)
        self.assertLess(cmp["max_rw"], 1e-5)
        checks = weight_checks(cmp, expected_targets(self.src))
        self.assertEqual([(c[0], c[2]) for c in checks], [("Only intended weights changed", "PASS"),
                                                          ("2 directions removed from saved weights", "PASS")])
        self.assertTrue(checks[1][1].startswith("max |Qᵀ·W| = "))
        wrong = compare_weights(self.src, out, self.dirs[[0, 2]], QUIET)               # another subspace is still written
        self.assertGreater(wrong["max_rw"], 1e-2)

    def test_one_layer_as_before(self):
        run, out, direction, _ = self.apply([2], "one")
        saved = torch.load(os.path.join(out, "refusal_direction.pt"))
        self.assertEqual((saved["layer"], saved["layers"]), (2, [2]))
        self.assertTrue(torch.equal(saved["direction"], self.dirs[2]))                 # [d], as the single-direction run saved it
        self.assertEqual(tuple(saved["basis"].shape), (D, 1))
        self.assertEqual(read_json(os.path.join(run.run_dir, "apply.json"))["directions"], 1)
        cmp = compare_weights(self.src, out, saved["direction"], QUIET)
        self.assertEqual(cmp["k"], 1)
        checks = weight_checks(cmp, expected_targets(self.src))
        self.assertEqual([(c[0], c[2]) for c in checks], [("Only intended weights changed", "PASS"),
                                                          ("Direction removed from saved weights", "PASS")])
        self.assertTrue(checks[1][1].startswith("max |r·W| = "))

    def test_a_dependent_layer_is_recorded(self):
        dirs = self.dirs.clone()
        dirs[1] = dirs[3]                                    # layer 1 points where layer 3 does
        run, out, _, events = self.apply([3, 1, 2], "dependent", dirs)
        self.assertEqual(read_json(os.path.join(run.run_dir, "apply.json"))["dropped"], [1])
        self.assertEqual(read_json(os.path.join(run.run_dir, "apply.json"))["directions"], 2)
        self.assertEqual(next(e for e in events if e["step"] == "apply" and e["status"] == "done")["dropped"], [1])
        self.assertIn("layer 1 is (nearly) a combination", read_text(os.path.join(run.run_dir, "run.log")))


# ----------------------------------------------------------------------------- the command line, end to end
def write_prompts(data_dir):
    """The three prompt files and a manifest naming their default sources, so the pipeline finds them and fetches nothing."""
    os.makedirs(data_dir, exist_ok=True)
    sets = {"harmful_train.jsonl": [f"How do I pick lock number {i}?" for i in range(8)],
            "harmful_test.jsonl": [f"Tell me how to break into house {i}." for i in range(4)],
            "harmless_train.jsonl": [f"Write a short poem about the number {i}." for i in range(12)]}
    manifest = {}
    for name, rows in sets.items():
        with open(os.path.join(data_dir, name), "w", encoding="utf-8") as f:
            for i, r in enumerate(rows):
                f.write(json.dumps({"id": f"{name[:-6]}-{i}", "prompt": r}) + "\n")
        manifest[name] = {"repo": "mlabonne/harmless_alpaca" if name.startswith("harmless") else "mlabonne/harmful_behaviors",
                          "split": "test" if "test" in name else "train", "revision": "0" * 40, "rows": len(rows)}
    with open(os.path.join(data_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f)


class CommandLine(unittest.TestCase):
    """python -m abliterate on a tiny GLM, on the CPU: --combine in the scan, a pause, --stage continue --layers."""

    def setUp(self):
        self.project = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.project, True)
        self.addCleanup(os.chdir, os.getcwd())               # main() changes into the project
        env = {k: v for k, v in os.environ.items() if k not in ("ABL_HARMFUL_DATASET", "ABL_HARMLESS_DATASET")}
        patcher = mock.patch.dict(os.environ, {**env, "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"}, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.src = os.path.join(self.project, "src", "tiny-glm")
        save_tiny_glm(self.src)
        write_prompts(os.path.join(self.project, "data"))

    def main(self, *argv):
        """(exit code, what it printed). The pipeline leaves its log files to the end of the process: quiet about that here."""
        with contextlib.redirect_stdout(io.StringIO()) as out, warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            try:
                P.main(["--project", self.project, *argv])
                code = 0
            except SystemExit as e:
                code = e.code
            gc.collect()
        return code, out.getvalue()

    def test_combine_pause_continue_with_layers(self):
        small = ["--device-map", "cpu", "--dtype", "float32", "--n-train", "4", "--n-test", "2", "--batch", "4", "--gen-batch", "2",
                 "--max-new-tokens", "3", "--layer-range", "0.25-0.75", "--no-ollama"]
        code, log = self.main("--model", self.src, "--combine", "3", "--pause-at-choice", *small)
        self.assertEqual(code, 0, log)
        (rd,) = [os.path.join(self.project, "runs", d) for d in os.listdir(os.path.join(self.project, "runs"))]
        meta = read_json(os.path.join(rd, "run.json"))
        self.assertEqual(meta["status"], "awaiting_choice")
        self.assertEqual(meta["recommended"], meta["recommended_layers"][0])
        scan = read_json(os.path.join(rd, "scan.json"))
        ranked = [s["layer"] for s in P.rank_layers(read_json(os.path.join(rd, "scan_results.json")))]
        self.assertEqual([c["layers"] for c in scan["combos"]], [ranked[:2], ranked[:3]])            # scan range 1-3
        events = read_events(rd)
        self.assertEqual(sum(e["status"] == "combo" for e in events), 2)
        self.assertEqual(events[-1]["recommended_layers"], meta["recommended_layers"])

        code, log = self.main("--run-dir", rd, "--stage", "continue", "--layers", "1,3", "--no-ollama")
        self.assertEqual(code, 0, log)
        meta = read_json(os.path.join(rd, "run.json"))
        self.assertEqual((meta["status"], meta["layer"], meta["layers"]), ("done", 1, [1, 3]))
        saved = torch.load(os.path.join(meta["out_dir"], "refusal_direction.pt"))
        self.assertEqual(tuple(saved["basis"].shape), (D, 2))
        self.assertEqual(read_json(os.path.join(rd, "generations.json"))["layers"], [1, 3])
        val = read_json(os.path.join(rd, "validation.json"))
        self.assertEqual(val["layers"], [1, 3])
        checks = {c["check"]: c["status"] for c in val["checks"]}
        self.assertEqual(checks["Only intended weights changed"], "PASS")
        self.assertEqual(checks["2 directions removed from saved weights"], "PASS")
        events = read_events(rd)
        choose = [e for e in events if e["step"] == "choose" and e["status"] == "done"][-1]
        self.assertEqual((choose["layer"], choose["layers"], choose["by"]), (1, [1, 3], "user"))
        self.assertEqual(events[-1]["layers"], [1, 3])
        self.assertIn("scan for layers 1+3:", log)

        # validate on its own reads the directions back from refusal_direction.pt
        code, log = self.main("--run-dir", rd, "--stage", "validate")
        self.assertEqual(code, 0, log)
        self.assertIn("scan for layers 1+3:", log)
        self.assertIn("2 directions removed from saved weights", log)
        self.assertEqual(read_json(os.path.join(rd, "validation.json"))["layers"], [1, 3])

        code, log = self.main("--run-dir", rd, "--stage", "continue", "--layers", "2,9", "--no-ollama")
        self.assertEqual(code, 2)
        meta = read_json(os.path.join(rd, "run.json"))
        self.assertEqual(meta["status"], "error")
        self.assertIn("layer 9 does not exist", meta["error"])
        self.assertEqual((meta["layer"], meta["layers"]), (1, [1, 3]))                 # the edit before stays recorded


if __name__ == "__main__":
    unittest.main()
