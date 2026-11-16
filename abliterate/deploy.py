"""GGUF conversion (llama.cpp converter in its own environment), Ollama import over the HTTP API (works when Ollama is
another container: the GGUF is uploaded as a blob, no CLI needed), A/B test over the API."""
import hashlib
import http.client
import json
import os
import subprocess
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


def convert_gguf(project, folder, outfile, log=print, force=False, allow_code=False):
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
    r = subprocess.run([py, conv, folder, "--outtype", "f16", "--outfile", outfile], capture_output=True, text=True,
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
    r = urllib.request.urlopen(req, timeout=timeout)
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


def ollama_create(name, gguf, chat_template_text, quantize="q8_0", log=print):
    """Creates a model from a GGUF through the API: upload the file as a blob, then /api/create with template + stops."""
    digest = upload_blob(gguf, log)
    body = {"model": name, "files": {os.path.basename(gguf): digest}, "template": template_for(chat_template_text),
            "parameters": {"stop": STOPS, "temperature": 0}, "stream": True}
    if quantize:
        body["quantize"] = quantize
    r = api_post("/api/create", body, timeout=3600, stream=True)
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
