# Red Team LLM Lab - app + pipeline in one image. GPU via the NVIDIA container runtime (--gpus all / nvidia.com/gpu).
# The torch cu128 wheels bundle the CUDA libraries, so a plain Python base image is enough; the host driver is injected at run time.
# Pin the base by digest for fully reproducible builds: FROM python:3.12-slim-bookworm@sha256:<digest>
FROM python:3.12-slim-bookworm AS base
ENV PYTHONUNBUFFERED=1 PYTHONUTF8=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 LC_ALL=C.UTF-8 PIP_NO_CACHE_DIR=1 DEBIAN_FRONTEND=noninteractive \
    NVIDIA_VISIBLE_DEVICES=all NVIDIA_DRIVER_CAPABILITIES=compute,utility
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates && rm -rf /var/lib/apt/lists/*

# ---- converter environment: llama.cpp's convert_hf_to_gguf.py needs an older transformers, so it gets its own venv.
#      LLAMA_CPP_REF is a full commit SHA or tag; changing it busts the cache deliberately.
FROM base AS gguf
ARG LLAMA_CPP_REF=c7518dbec59281c430ca5278ab4e60eadbc88b13
RUN git init -q /opt/llama.cpp && cd /opt/llama.cpp \
 && git fetch -q --depth 1 https://github.com/ggml-org/llama.cpp "${LLAMA_CPP_REF}" && git checkout -q FETCH_HEAD \
 && echo "${LLAMA_CPP_REF}" > REV \
 && python -m venv /opt/venv-gguf \
 && /opt/venv-gguf/bin/pip install --quiet "pip==26.3" \
 && /opt/venv-gguf/bin/pip install -r requirements/requirements-convert_hf_to_gguf.txt \
 && /opt/venv-gguf/bin/pip install --upgrade "requests>=2.33.0" \
 && rm -rf .git ggml src examples tools tests docs models media ci scripts common include cmake vendor \
 && /opt/venv-gguf/bin/python -c "import sys; sys.path.insert(0, '/opt/llama.cpp/gguf-py'); import gguf, torch, transformers; print('converter env ok', transformers.__version__)"

# ---- main environment
FROM base AS app
COPY deploy/requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --quiet "pip==26.3" \
 && /opt/venv/bin/pip install -r /tmp/requirements.txt
COPY --from=gguf /opt/llama.cpp /opt/llama.cpp
COPY --from=gguf /opt/venv-gguf /opt/venv-gguf
RUN /opt/venv-gguf/bin/python /opt/llama.cpp/convert_hf_to_gguf.py --help >/dev/null && echo "converter ok"

WORKDIR /app
COPY abliterate /app/abliterate
COPY app /app/app
COPY copilot /app/copilot
COPY abliteration_pipeline.ipynb run_pipeline.py build_gui.py README.md /app/
COPY deploy/entrypoint.sh /app/deploy/entrypoint.sh
RUN chmod +x /app/deploy/entrypoint.sh && mkdir -p /workspace && useradd -m -u 1000 abl && chown -R abl:abl /app /workspace

# project data (models/, out/, gguf/, runs/, data/, sbom/) lives on a volume at /workspace.
# The container starts as root only to hand the mounted workspace to uid 1000, then drops privileges (entrypoint.sh).
ENV ABL_PROJECT=/workspace ABL_PYTHON=/opt/venv/bin/python ABL_GGUF_PY=/opt/venv-gguf/bin/python ABL_LLAMA_CPP=/opt/llama.cpp \
    PYTHONPATH=/app ABL_HOST=0.0.0.0 ABL_PORT=8787 OLLAMA_HOST=http://ollama:11434 HF_HOME=/workspace/.hf
EXPOSE 8787
VOLUME ["/workspace"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD curl -fsS http://127.0.0.1:8787/healthz >/dev/null || exit 1
ENTRYPOINT ["/app/deploy/entrypoint.sh"]
CMD ["serve"]
