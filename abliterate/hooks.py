"""Measuring and ablating the residual stream with plain PyTorch hooks on a Hugging Face model.
No TransformerLens: works with device_map="auto" sharding, MoE blocks and multimodal text decoders, and on the CPU."""
import contextlib
import gc
import glob
import json
import os
import time

import torch

from .arch import find_layers


def _hs_from_args(args, kwargs):
    if args:
        return args[0], True
    return kwargs.get("hidden_states"), False


def _one_stream(x):
    """A residual vector per token. Models with manifold-constrained hyper-connections (mHC, GLM-5.3-Flash) carry
    hc_mult parallel streams between layers: x is [..., streams, d] there (x[:, -1] of a [batch, seq, streams, d] layer
    input). Their readout before the final norm is the unweighted mean of the streams, so the mean is what is measured."""
    return x.mean(dim=-2) if x.dim() >= 3 else x


def opens_think(text):
    """Reasoning templates (GLM-4.7, GLM-5.x) open a reasoning block at the generation prompt ('<|assistant|><think>')."""
    return text.rstrip().endswith("<think>")


class HookedModel:
    def __init__(self, model, tokenizer, log=print, think=False):
        self.model, self.tok, self.log = model, tokenizer, log
        self.layers_name, self.layers = find_layers(model)
        self.n_layers = len(self.layers)
        text_cfg = getattr(model.config, "text_config", None) or model.config
        self.d_model = model.config.hidden_size if hasattr(model.config, "hidden_size") else text_cfg.hidden_size
        self.streams = int(getattr(text_cfg, "hc_mult", 1) or 1)          # mHC models only (glm5_next): 4 in GLM-5.3-Flash
        self.device = next(model.parameters()).device
        gen_cfg = getattr(model, "generation_config", None)
        self.eos = getattr(gen_cfg, "eos_token_id", None) or tokenizer.eos_token_id
        # Measure, scan and validate look at the answer itself, not at reasoning. A template with a reasoning switch is asked
        # for its own prompt without reasoning (enable_thinking=False, when that ends the prompt with a closed block:
        # GLM-4.7, GLM-4.7-Flash and GLM-5 write '<|assistant|></think>', GLM-5.2 '<think></think>', GLM-4.5 / 4.6 add
        # '/nothink' and '<think></think>' where the model would otherwise open the block itself). The GLM-5.3 templates
        # have no switch and always open the block: there it is closed empty ('<think></think>', what they write for
        # earlier turns without reasoning). think=True keeps every template's default.
        self.chat_kwargs, self.close_think = {}, False
        if not think:
            try:
                def probe(**kw):
                    t = self.tok.apply_chat_template([{"role": "user", "content": "hi"}], add_generation_prompt=True, tokenize=False, **kw)
                    return t if isinstance(t, str) else ""
                default, off = probe(), probe(enable_thinking=False)
                if off != default and off.rstrip().endswith("</think>"):
                    self.chat_kwargs = {"enable_thinking": False}
                elif opens_think(default):
                    self.close_think = True
            except Exception:
                pass
        log(f"hooks: {self.layers_name} ({self.n_layers} layers), d_model={self.d_model}, first device {self.device}"
            + (f", {self.streams} residual streams (mHC: measured as their mean, ablated in each)" if self.streams > 1 else "")
            + (", reasoning off (the template's enable_thinking=False)" if self.chat_kwargs else "")
            + (", reasoning block closed at the prompt (<think></think>)" if self.close_think else ""))

    # ------------------------------------------------------------ tokenization (left padding, chat template)
    def encode(self, prompts):
        convs = [[{"role": "user", "content": p}] for p in prompts]
        if self.close_think:
            texts = [t + "</think>" if opens_think(t) else t
                     for t in self.tok.apply_chat_template(convs, add_generation_prompt=True, tokenize=False)]
            enc = self.tok(texts, padding=True, return_tensors="pt", add_special_tokens=False)   # the template wrote them
        else:
            enc = self.tok.apply_chat_template(convs, add_generation_prompt=True, padding=True, return_tensors="pt", return_dict=True,
                                               **self.chat_kwargs)
        return enc["input_ids"].to(self.device), enc["attention_mask"].to(self.device)

    # ------------------------------------------------------------ measurement: resid_pre at the last token
    @torch.no_grad()
    def mean_resid_pre(self, prompts, batch_size, label="", progress=None, per_token=False):
        """Mean of each layer's input hidden state at the last token -> [n_layers, d_model] float32 (CPU).
        Also returns the mean activation norm per layer (for the 'separation %' chart)."""
        total = torch.zeros(self.n_layers, self.d_model, dtype=torch.float32)
        norm_total = torch.zeros(self.n_layers, dtype=torch.float32)
        captured = {}

        def make_hook(li):
            def hook(mod, args, kwargs):
                hs, _ = _hs_from_args(args, kwargs)
                # a copy also on the CPU, where .float().cpu() is a view; mHC streams: their mean
                captured[li] = _one_stream(hs[:, -1].detach().to("cpu", torch.float32, copy=True))
            return hook

        handles = [l.register_forward_pre_hook(make_hook(i), with_kwargs=True) for i, l in enumerate(self.layers)]
        try:
            n_batches = (len(prompts) + batch_size - 1) // batch_size
            for b, i in enumerate(range(0, len(prompts), batch_size)):
                t = time.time()
                ids, mask = self.encode(prompts[i:i + batch_size])
                self.model(input_ids=ids, attention_mask=mask, use_cache=False)
                for li in range(self.n_layers):
                    total[li] += captured[li].sum(0)
                    norm_total[li] += captured[li].norm(dim=-1).sum()
                captured.clear()
                if progress:
                    progress(b + 1, n_batches, time.time() - t)
                gc.collect(); torch.cuda.empty_cache()
        finally:
            for h in handles:
                h.remove()
        mean = total / len(prompts)
        if not torch.isfinite(mean).all():
            raise RuntimeError(f"NaN/Inf in the {label} activations")
        return mean, norm_total / len(prompts)

    # ------------------------------------------------------------ one prompt, all layers, all tokens (lab probe)
    @torch.no_grad()
    def resid_pre_all(self, prompt):
        """[n_layers, seq, d_model] float32 CPU + token ids."""
        captured = {}

        def make_hook(li):
            def hook(mod, args, kwargs):
                hs, _ = _hs_from_args(args, kwargs)
                captured[li] = _one_stream(hs[0].detach().to("cpu", torch.float32, copy=True))
            return hook

        handles = [l.register_forward_pre_hook(make_hook(i), with_kwargs=True) for i, l in enumerate(self.layers)]
        try:
            ids, mask = self.encode([prompt])
            self.model(input_ids=ids, attention_mask=mask, use_cache=False)
        finally:
            for h in handles:
                h.remove()
        return torch.stack([captured[i] for i in range(self.n_layers)]), ids[0].tolist()

    # ------------------------------------------------------------ inference-time ablation
    @contextlib.contextmanager
    def ablated(self, direction):
        """Removes `direction` from the residual stream at every layer input and output (and from the
        attention-block output where no post-norm sits in between). Hooks are removed on exit.
        With mHC streams ([..., streams, d]) the projection acts on each stream: the streams only mix with each other
        and take in block outputs scaled per stream, so nothing puts the direction back."""
        if direction is None:
            yield
            return
        cache = {}

        def d_for(t):
            key = (t.device, t.dtype)
            if key not in cache:
                cache[key] = direction.to(t.device, t.dtype)
            return cache[key]

        def proj_out(t):
            d = d_for(t)
            return t - (t @ d).unsqueeze(-1) * d

        def pre(mod, args, kwargs):
            hs, positional = _hs_from_args(args, kwargs)
            if hs is None:
                return None
            hs = proj_out(hs)
            if positional:
                return (hs, *args[1:]), kwargs
            kwargs = dict(kwargs); kwargs["hidden_states"] = hs
            return args, kwargs

        def post(mod, args, out):
            if isinstance(out, tuple):
                return (proj_out(out[0]), *out[1:])
            return proj_out(out)

        handles = []
        for l in self.layers:
            handles.append(l.register_forward_pre_hook(pre, with_kwargs=True))
            handles.append(l.register_forward_hook(post))
            attn = getattr(l, "self_attn", None) or getattr(l, "self_attention", None) or getattr(l, "linear_attn", None)
            if attn is not None and not hasattr(l, "post_self_attn_layernorm"):
                handles.append(attn.register_forward_hook(post))
        try:
            yield
        finally:
            for h in handles:
                h.remove()

    @torch.no_grad()
    def generate(self, prompts, max_new_tokens, batch_size, direction=None):
        outs = []
        with self.ablated(direction):
            for i in range(0, len(prompts), batch_size):
                ids, mask = self.encode(prompts[i:i + batch_size])
                toks = self.model.generate(input_ids=ids, attention_mask=mask, max_new_tokens=max_new_tokens, do_sample=False,
                                           eos_token_id=self.eos, pad_token_id=self.tok.pad_token_id)
                outs += self.tok.batch_decode(toks[:, ids.shape[1]:], skip_special_tokens=True)
                gc.collect(); torch.cuda.empty_cache()
        return outs

    @torch.no_grad()
    def next_token_logits(self, prompts, batch_size=8):
        out = []
        for i in range(0, len(prompts), batch_size):
            ids, mask = self.encode(prompts[i:i + batch_size])
            out.append(self.model(input_ids=ids, attention_mask=mask, use_cache=False).logits[:, -1, :].to("cpu", torch.float32, copy=True))
        return torch.cat(out)


def cpu_bf16_fast():
    """True on processors with AVX512-BF16 / AMX: there bf16 is faster than float32 and needs half the RAM.
    Everywhere else bf16 matmuls take a generic path that is several times slower than float32."""
    try:
        return bool(torch.ops.mkldnn._is_mkldnn_bf16_supported())
    except Exception:
        return False


def resolve_device(device_map="cuda", dtype="auto", log=print):
    """What the model is really loaded on: (device_map, dtype name).
    'cuda' without a visible CUDA GPU becomes 'cpu'. dtype 'auto' is bfloat16 on a GPU; on the CPU it is float32 unless the
    processor has a fast bf16 path. An explicit dtype is kept as given."""
    has_cuda = torch.cuda.is_available()
    if device_map == "cuda" and not has_cuda:
        log("no CUDA GPU is visible to this process: running on the CPU instead (works, but measure and scan take much longer)")
        device_map = "cpu"
    on_cpu = device_map == "cpu" or (device_map == "auto" and not has_cuda)
    if dtype == "auto":
        dtype = "bfloat16" if not on_cpu or cpu_bf16_fast() else "float32"
    return device_map, dtype


def _ram_check(model_dir, dtype, log):
    """CPU runs die without a message when the model does not fit (the kernel kills the process, exit code 137): say so first."""
    try:
        with open("/proc/meminfo", encoding="ascii") as f:
            avail = next(int(line.split()[1]) for line in f if line.startswith("MemAvailable:")) / 1e6      # kB -> GB
        cfg = json.load(open(os.path.join(model_dir, "config.json"), encoding="utf-8"))
        src = getattr(torch, str(cfg.get("dtype") or cfg.get("torch_dtype") or "bfloat16"), torch.bfloat16).itemsize
        on_disk = sum(os.path.getsize(p) for p in glob.glob(os.path.join(model_dir, "*.safetensors"))) / 1e9
    except Exception:
        return                                                    # no /proc (Windows, macOS) or an unusual folder: nothing to say
    need = on_disk * getattr(torch, dtype).itemsize / src
    if need > 0.9 * avail:
        log(f"WARNING: the model needs about {need:.0f} GB of RAM in {dtype} but only {avail:.0f} GB are free. If the run stops without "
            f"an error (exit code 137) it ran out of memory: give the container / WSL VM more RAM or use a smaller model")


def auto_class(model_dir, trust_remote_code=False):
    """AutoModelForCausalLM, or AutoModelForImageTextToText for the families transformers registers only there: the GLM
    vision models (glm4v, glm4v_moe, glm46v, glm5_next = GLM-5.3-Flash). Their text-only forward and generate work alike.
    Remote code decides only for a checkpoint that brings its own causal-LM class (auto_map) or a model_type transformers
    does not know: a "trust remote code" left ticked from a ChatGLM model must not break a GLM-5.3-Flash run."""
    import transformers
    from transformers.models.auto import modeling_auto as ma
    try:
        with open(os.path.join(model_dir, "config.json"), encoding="utf-8") as f:
            cfg = json.load(f)
        mt, auto_map = cfg.get("model_type", "") or "", cfg.get("auto_map") or {}
    except (OSError, ValueError, AttributeError):
        mt, auto_map = "", {}
    causal, i2t = mt in ma.MODEL_FOR_CAUSAL_LM_MAPPING_NAMES, mt in ma.MODEL_FOR_IMAGE_TEXT_TO_TEXT_MAPPING_NAMES
    if trust_remote_code and ("AutoModelForCausalLM" in auto_map or not (causal or i2t)):
        return transformers.AutoModelForCausalLM
    if i2t and not causal:
        return transformers.AutoModelForImageTextToText
    return transformers.AutoModelForCausalLM


def load_model(model_dir, dtype="auto", device_map="cuda", trust_remote_code=False, log=print):
    """The model (see auto_class) + tokenizer with left padding. device_map='auto' shards over all GPUs (+ CPU offload);
    'cuda' falls back to 'cpu' when no GPU is visible (see resolve_device)."""
    from transformers import AutoTokenizer
    device_map, dtype = resolve_device(device_map, dtype, log)
    if device_map == "cpu" or not torch.cuda.is_available():
        _ram_check(model_dir, dtype, log)
    tok = AutoTokenizer.from_pretrained(model_dir, trust_remote_code=trust_remote_code)
    tok.padding_side = "left"
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    kw = {"dtype": getattr(torch, dtype), "trust_remote_code": trust_remote_code}
    Auto = auto_class(model_dir, trust_remote_code)
    if device_map == "auto":
        kw["device_map"] = "auto"
        model = Auto.from_pretrained(model_dir, **kw)
    else:
        model = Auto.from_pretrained(model_dir, **kw).to(device_map)
    model.eval()
    log(f"model loaded: {type(model).__name__}, dtype {dtype}, device_map {device_map}")
    return model, tok
