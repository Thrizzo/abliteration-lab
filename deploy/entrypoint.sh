#!/bin/sh
# serve (default) -> the app server; anything else -> the pipeline CLI, e.g.
#   docker compose run --rm app --model THUDM/glm-edge-4b-chat --no-ollama
set -e
mkdir -p "$ABL_PROJECT" 2>/dev/null || true
cd "$ABL_PROJECT"
if [ "$1" = "serve" ]; then
  exec /opt/venv/bin/python /app/app/server.py --project "$ABL_PROJECT" --host "${ABL_HOST:-0.0.0.0}" --port "${ABL_PORT:-8787}"
fi
exec /opt/venv/bin/python -m abliterate --project "$ABL_PROJECT" "$@"
