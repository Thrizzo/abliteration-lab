"""GGUF conversion (llama.cpp converter in .venv-gguf), Ollama Modelfiles / import, A/B test over the Ollama API."""
import json
import os
import subprocess
import urllib.request

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
    py = os.path.join(project, ".venv-gguf", "Scripts", "python.exe")
    conv = os.path.join(project, "llama.cpp", "convert_hf_to_gguf.py")
    if not (os.path.isfile(py) and os.path.isfile(conv)):
        raise RuntimeError("converter environment missing (.venv-gguf / llama.cpp): run notebook cell 1.5 or run_pipeline.py setup")
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


def write_modelfile(path, gguf, chat_template_text):
    tpl = GLM4_TEMPLATE if "[gMASK]" in (chat_template_text or "") else GLM_EDGE_TEMPLATE
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"FROM {os.path.abspath(gguf)}\n\nTEMPLATE \"\"\"{tpl}\"\"\"\n\n" + "".join(f'PARAMETER stop "{s}"\n' for s in STOPS) + "PARAMETER temperature 0\n")
    return path


def ollama_exe():
    import shutil
    return shutil.which("ollama") or os.path.expandvars(r"%LOCALAPPDATA%\Programs\Ollama\ollama.exe")


def ollama_create(name, modelfile, quantize="q8_0", log=print):
    cmd = [ollama_exe(), "create", name, "-f", modelfile] + (["--quantize", quantize] if quantize else [])
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = (r.stdout + r.stderr).replace("\r", "\n")
    lines = [l for l in out.splitlines() if l.strip() and "copying file" not in l and "quantizing" not in l]
    for l in lines[-4:]:
        log("  " + l.strip()[:120])
    if r.returncode != 0:
        raise RuntimeError(f"ollama create {name} failed: {lines[-1] if lines else r.returncode}")
    return name


def ollama_chat(model, prompt, num_predict=160, host="http://localhost:11434"):
    body = json.dumps({"model": model, "stream": False, "options": {"temperature": 0, "num_predict": num_predict},
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request(f"{host}/api/chat", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read())["message"]["content"]


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
    r = subprocess.run([ollama_exe(), "show", name, "--template"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    return "<|user|>" in r.stdout and "<|assistant|>" in r.stdout
