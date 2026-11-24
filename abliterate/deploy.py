"""GGUF conversion (llama.cpp converter in its own environment), Ollama import over the HTTP API (works when Ollama is
another container: the GGUF is uploaded as a blob, no CLI needed), A/B test over the API."""
import contextlib
import hashlib
import http.client
import io
import json
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from . import platform as P
from .data import count_refusals, is_refusal

GLM_EDGE_TEMPLATE = ('{{- range .Messages }}{{- if eq .Role "system" }}<|system|>\n{{ .Content }}'
                     '{{- else if eq .Role "user" }}<|user|>\n{{ .Content }}'
                     '{{- else if eq .Role "assistant" }}<|assistant|>\n{{ .Content }}{{- end }}{{- end }}<|assistant|>\n')
GLM4_TEMPLATE = '[gMASK]<sop>' + GLM_EDGE_TEMPLATE
STOPS = ["<|user|>", "<|observation|>", "<|endoftext|>"]


def check_model_folder(path):
    """The converter loads tokenizers with trust_remote_code=True: refuse folders with code or auto_map."""
    risky = [f for r, _, fs in os.walk(path) for f in fs if os.path.splitext(f)[1].lower() in {".py", ".pkl", ".pickle", ".bin", ".ckpt", ".so", ".dll", ".exe"}]
    try:
        auto_map = json.load(open(os.path.join(path, "tokenizer_config.json"), encoding="utf-8")).get("auto_map")
    except Exception:
        auto_map = None
    return not risky and not auto_map, risky, auto_map


CONVERTER_TYPES = ("f16", "bf16", "q8_0")     # what convert_hf_to_gguf.py can write directly; k-quants need llama-quantize

# loader bookkeeping transformers v5 writes into tokenizer_config.json; 4.x would hand it to the tokenizer as settings
_V5_LOADER_KEYS = ("backend", "is_local", "local_files_only")


def v4_tokenizer_config(cfg):
    """tokenizer_config.json as transformers 4.x reads it, or None if it needs no change. llama.cpp pins transformers 4.x
    for its converter, and v5 saves this file differently: PreTrainedTokenizerFast is called TokenizersBackend, and
    additional_special_tokens became a list in extra_special_tokens, where 4.x expects a dict."""
    out = {k: v for k, v in cfg.items() if k not in _V5_LOADER_KEYS}
    if out.get("tokenizer_class") == "TokenizersBackend":
        out["tokenizer_class"] = "PreTrainedTokenizerFast"
    extra = out.get("extra_special_tokens")
    if isinstance(extra, list):
        del out["extra_special_tokens"]
        add = list(out.get("additional_special_tokens") or [])
        out["additional_special_tokens"] = add + [t for t in extra if t not in add]
    return None if out == cfg else out


def _link(src, dst):
    """symlink; a hard link where symlinks need a privilege (Windows); a copy only as the last resort"""
    try:
        os.symlink(os.path.abspath(src), dst)
    except OSError:
        try:
            os.link(src, dst)
        except OSError:
            shutil.copyfile(src, dst)


def glm_context_config(cfg):
    """config.json with seq_length for an HF-format GLM (GlmForCausalLM: GLM-Edge, GLM-4-9B-hf), or None. The converter
    writes seq_length as the model's context length and falls back to the hidden size without it: 2048 for GLM-Edge 1.5B,
    whose trained context is 8192. Ollama caps the context at that value."""
    if "GlmForCausalLM" in (cfg.get("architectures") or []) and "seq_length" not in cfg and cfg.get("max_position_embeddings"):
        return {**cfg, "seq_length": cfg["max_position_embeddings"]}
    return None


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def converter_fixes(folder):
    """{file name: content} the converter should read instead of the folder's own file, and why."""
    fixes, why = {}, []
    tok = _read_json(os.path.join(folder, "tokenizer_config.json"))
    if tok is not None and (v4 := v4_tokenizer_config(tok)) is not None:
        fixes["tokenizer_config.json"] = v4
        why.append("tokenizer saved by transformers v5")
    cfg = _read_json(os.path.join(folder, "config.json"))
    if cfg is not None and (fixed := glm_context_config(cfg)) is not None:
        fixes["config.json"] = fixed
        why.append(f"context length {fixed['seq_length']} from max_position_embeddings")
    return fixes, why


@contextlib.contextmanager
def converter_view(folder, workdir, log=print):
    """The model folder as the converter reads it correctly. If it needs fixes (converter_fixes), the converter gets a
    temporary view in workdir: links to the folder's files, plus the fixed files. The folder itself is never changed."""
    fixes, why = converter_fixes(folder)
    if not fixes:
        yield folder
        return
    parent = tempfile.mkdtemp(prefix=".convert-", dir=workdir)
    view = os.path.join(parent, os.path.basename(os.path.normpath(folder)))     # the converter names the model after it
    try:
        os.makedirs(view)
        for fn in os.listdir(folder):
            src = os.path.join(folder, fn)
            if fn not in fixes and os.path.isfile(src):
                _link(src, os.path.join(view, fn))
        for fn, content in fixes.items():
            with open(os.path.join(view, fn), "w", encoding="utf-8") as f:
                json.dump(content, f, ensure_ascii=False, indent=2)
        log(f"gguf: the converter reads adjusted copies of {', '.join(sorted(fixes))} ({'; '.join(why)})")
        yield view
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def convert_gguf(project, folder, outfile, log=print, force=False, allow_code=False, outtype="f16"):
    py, conv = P.gguf_python(project), os.path.join(P.llama_cpp_dir(project), "convert_hf_to_gguf.py")
    if not (os.path.isfile(py) and os.path.isfile(conv)):
        raise RuntimeError(f"converter environment missing ({py} / {conv}): run notebook cell 1.5, run_pipeline.py setup, or set ABL_GGUF_PY / ABL_LLAMA_CPP")
    if os.path.isfile(outfile) and not force:
        log(f"gguf: {outfile} exists - skipping")
        return outfile
    ok, risky, auto_map = check_model_folder(folder)
    if not ok and not allow_code:
        raise RuntimeError(f"{folder} contains code files {risky} / auto_map {auto_map}; pass --allow-code to convert anyway")
    os.makedirs(os.path.dirname(outfile) or ".", exist_ok=True)
    env = {**os.environ, "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    with converter_view(folder, os.path.dirname(os.path.abspath(outfile)), log) as src:
        r = subprocess.run([py, conv, src, "--outtype", outtype, "--outfile", outfile], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", env=env)
    tail = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()[-6:]
    for line in tail:
        log("  " + line)
    if r.returncode != 0:
        if os.path.isfile(outfile):
            os.remove(outfile)
        raise RuntimeError(f"converter failed (exit {r.returncode}): {tail[-1] if tail else ''}")
    log(f"gguf: {outfile} ({os.path.getsize(outfile) / 1e9:.1f} GB)")
    return outfile


def chat_template_text(model_dir):
    """The model's chat template: chat_template.jinja (newer saves), or the chat_template entry of tokenizer_config.json
    (older ones; of a list of named templates, "default"). Only the template, never the rest of tokenizer_config.json:
    GLM-Edge lists [gMASK] among its special tokens there, which would pick the GLM-4 template for it."""
    p = os.path.join(model_dir or "", "chat_template.jinja")
    if os.path.isfile(p):
        with open(p, encoding="utf-8") as f:
            return f.read()
    try:
        with open(os.path.join(model_dir or "", "tokenizer_config.json"), encoding="utf-8") as f:
            ct = json.load(f).get("chat_template")
    except (OSError, ValueError, AttributeError):
        return ""
    if isinstance(ct, list):
        ct = next((t.get("template") for t in ct if isinstance(t, dict) and t.get("name") == "default"), None)
    return ct if isinstance(ct, str) else ""


def template_for(chat_template_text):
    return GLM4_TEMPLATE if "[gMASK]" in (chat_template_text or "") else GLM_EDGE_TEMPLATE


def write_modelfile(path, gguf, chat_template_text):
    """Kept for people who want to `ollama create` by hand; the pipeline itself uses the API."""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"FROM {os.path.abspath(gguf)}\n\nTEMPLATE \"\"\"{template_for(chat_template_text)}\"\"\"\n\n"
                + "".join(f'PARAMETER stop "{s}"\n' for s in STOPS) + "PARAMETER temperature 0\n")
    return path


# ------------------------------------------------------------------ Ollama HTTP API
def _url(path):
    return P.ollama_host() + path


def api_get(path, timeout=10):
    with urllib.request.urlopen(_url(path), timeout=timeout) as r:
        return json.loads(r.read())


def api_post(path, body, timeout=600, stream=False):
    req = urllib.request.Request(_url(path), data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        # keep Ollama's reason ({"error": ...}) in the message; callers still get an HTTPError whose body they can read
        detail = e.read()[:500]
        raise urllib.error.HTTPError(e.url, e.code, f"{e.reason}: {detail.decode(errors='replace').strip()}", e.headers,
                                     io.BytesIO(detail)) from None
    if stream:
        return r
    with r:
        return json.loads(r.read())


def _sha256(path, log=None):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 24), b""):
            h.update(b)
    return h.hexdigest()


def upload_blob(path, log=print):
    """Pushes a file into Ollama's blob store (idempotent: skipped if the digest exists). Returns 'sha256:<digest>'."""
    digest = "sha256:" + _sha256(path)
    u = urllib.parse.urlparse(P.ollama_host())
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=3600)
    conn.request("HEAD", f"/api/blobs/{digest}")
    resp = conn.getresponse(); resp.read()
    if resp.status == 200:
        log(f"ollama: blob {digest[:19]}… already present")
        conn.close()
        return digest
    size = os.path.getsize(path)
    log(f"ollama: uploading {os.path.basename(path)} ({size / 1e9:.1f} GB) as {digest[:19]}…")
    with open(path, "rb") as f:
        conn.request("POST", f"/api/blobs/{digest}", body=f, headers={"Content-Length": str(size), "Content-Type": "application/octet-stream"})
        resp = conn.getresponse(); body = resp.read()
    conn.close()
    if resp.status not in (200, 201):
        raise RuntimeError(f"blob upload failed: HTTP {resp.status} {body[:200]!r}")
    return digest


def ollama_create(name, gguf, chat_template_text, quantize=None, log=print):
    """Creates a model from a GGUF through the API: upload the file as a blob, then /api/create with template + stops.
    `quantize` asks Ollama to quantize at create time; newer Ollama versions (>= 0.40) refuse that for GGUF imports,
    so the pipeline converts to the target type with llama.cpp instead and passes quantize=None."""
    digest = upload_blob(gguf, log)
    body = {"model": name, "files": {os.path.basename(gguf): digest}, "template": template_for(chat_template_text),
            "parameters": {"stop": STOPS, "temperature": 0}, "stream": True}
    if quantize:
        body["quantize"] = quantize
    try:
        r = api_post("/api/create", body, timeout=3600, stream=True)
    except urllib.error.HTTPError as e:
        msg = e.read()[:300].decode(errors="replace")
        if quantize and e.code == 400 and "quantiz" in msg:
            raise RuntimeError(f"this Ollama ({api_get('/api/version').get('version')}) does not quantize GGUF imports; "
                               f"convert with --quantize q8_0|f16|bf16 (done by llama.cpp) instead: {msg}")
        raise RuntimeError(f"ollama create {name}: HTTP {e.code} {msg}")
    last = ""
    with r:
        for line in r:
            try:
                st = json.loads(line).get("status", "")
            except Exception:
                continue
            if st and st != last and not st.startswith("quantizing") and "copying" not in st:
                log("  " + st[:120])
            last = st
            if st.startswith("error") or "error" in json.loads(line):
                raise RuntimeError(f"ollama create {name}: {line.decode(errors='replace')[:200]}")
    if last != "success":
        raise RuntimeError(f"ollama create {name} ended with status {last!r}")
    return name


def ollama_chat(model, prompt, num_predict=160):
    out = api_post("/api/chat", {"model": model, "stream": False, "options": {"temperature": 0, "num_predict": num_predict},
                                 "messages": [{"role": "user", "content": prompt}]}, timeout=600)
    return out["message"]["content"]


def ab_test(base_name, abl_name, harmful, normal, log=print):
    results = {"base": [], "abl": []}
    for label, prompts in (("harmful", harmful), ("normal", normal)):
        for p in prompts:
            a, b = ollama_chat(base_name, p), ollama_chat(abl_name, p)
            results["base"].append(a); results["abl"].append(b)
            log(f"  [{label}] {p[:60]!r}: base {'REFUSAL' if is_refusal(a) else 'answers'} | abl {'REFUSAL' if is_refusal(b) else 'answers'}")
    n = len(harmful)
    return {"harmful": harmful, "normal": normal, "results": results,
            "n_ref_base": count_refusals(results["base"][:n]), "n_ref_abl": count_refusals(results["abl"][:n])}


def template_ok(name):
    try:
        tpl = api_post("/api/show", {"model": name}, timeout=30).get("template", "")
    except Exception:
        return False
    return "<|user|>" in tpl and "<|assistant|>" in tpl


def unload_all(log=print):
    try:
        for m in api_get("/api/ps")["models"]:
            api_post("/api/generate", {"model": m["name"], "keep_alive": 0}, timeout=30)
    except Exception:
        pass
