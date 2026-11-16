"""Where things live on this machine: interpreters, the GGUF converter, Ollama, the GPU.
Everything can be overridden by environment variables so the same code runs on Windows, Linux and inside Docker:

    ABL_PROJECT     project folder (models/, out/, gguf/, runs/, data/ live here)          default: the code folder
    ABL_PYTHON      interpreter that runs the pipeline subprocesses                        default: sys.executable
    ABL_GGUF_PY     interpreter of the llama.cpp converter environment                     default: <project>/.venv-gguf
    ABL_LLAMA_CPP   llama.cpp checkout (convert_hf_to_gguf.py)                              default: <project>/llama.cpp
    OLLAMA_HOST     Ollama API base URL                                                     default: http://localhost:11434
    ABL_HOST / ABL_PORT   bind address of the app server                                    default: 127.0.0.1 / 8787
"""
import os
import shutil
import subprocess
import sys

IS_WINDOWS = os.name == "nt"


def venv_python(venv_dir):
    return os.path.join(venv_dir, "Scripts", "python.exe") if IS_WINDOWS else os.path.join(venv_dir, "bin", "python")


def pipeline_python(project):
    """The interpreter for pipeline subprocesses: explicit override, else the running one, else the project's .venv."""
    if os.environ.get("ABL_PYTHON"):
        return os.environ["ABL_PYTHON"]
    cand = venv_python(os.path.join(project, ".venv"))
    if sys.executable and os.path.isfile(sys.executable) and (sys.prefix != sys.base_prefix or not os.path.isfile(cand)):
        return sys.executable
    return cand


def gguf_python(project):
    return os.environ.get("ABL_GGUF_PY") or venv_python(os.path.join(project, ".venv-gguf"))


def llama_cpp_dir(project):
    return os.environ.get("ABL_LLAMA_CPP") or os.path.join(project, "llama.cpp")


def ollama_host():
    h = os.environ.get("OLLAMA_HOST", "").strip() or "http://localhost:11434"
    if not h.startswith("http"):
        h = "http://" + h
    return h.rstrip("/")


def ollama_exe():
    """The Ollama CLI if present (optional: the pipeline talks to the API; the CLI is only a fallback)."""
    p = shutil.which("ollama")
    if p:
        return p
    if IS_WINDOWS:
        cand = os.path.expandvars(r"%LOCALAPPDATA%\Programs\Ollama\ollama.exe")
        if os.path.isfile(cand):
            return cand
    return None


def nvidia_smi(query="name,memory.used,memory.total,utilization.gpu"):
    """GPU facts via nvidia-smi (available inside containers started with --gpus); None if absent."""
    exe = shutil.which("nvidia-smi") or (r"C:\Windows\System32\nvidia-smi.exe" if IS_WINDOWS else "/usr/bin/nvidia-smi")
    try:
        out = subprocess.run([exe, f"--query-gpu={query}", "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=10).stdout.strip()
        return out.splitlines()[0].split(", ") if out else None
    except Exception:
        return None


def driver_cuda_version():
    try:
        out = subprocess.run([shutil.which("nvidia-smi") or "nvidia-smi"], capture_output=True, text=True, timeout=30).stdout
    except Exception:
        return None
    import re
    m = re.search(r"CUDA (?:UMD )?Version:\s*([\d.]+)", out)
    return m.group(1) if m else None
