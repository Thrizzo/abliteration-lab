#!/bin/sh
# serve (default) -> the app server; options -> the pipeline CLI; anything else -> run as a command.
#   docker compose run --rm app --model THUDM/glm-edge-4b-chat --no-ollama
#   docker compose run --rm app sh
set -e
ABL_PROJECT="${ABL_PROJECT:-/workspace}"
mkdir -p "$ABL_PROJECT" 2>/dev/null || true
# the workspace is a bind mount / PVC: when started as root, hand it to the app user and drop privileges
if [ "$(id -u)" = "0" ]; then
  chown abl:abl "$ABL_PROJECT" 2>/dev/null || true
  exec setpriv --reuid=abl --regid=abl --init-groups "$0" "$@"
fi
if [ ! -w "$ABL_PROJECT" ]; then
  echo "ERROR: $ABL_PROJECT is not writable by uid $(id -u). chown it to the app user (uid 1000) or start the container as root (it drops privileges itself)." >&2
  exit 1
fi
cd "$ABL_PROJECT"
case "${1:-serve}" in
  serve) shift; exec /opt/venv/bin/python /app/app/server.py --project "$ABL_PROJECT" --host "${ABL_HOST:-0.0.0.0}" --port "${ABL_PORT:-8787}" "$@" ;;
  -*)    exec /opt/venv/bin/python -m abliterate --project "$ABL_PROJECT" "$@" ;;
  *)     exec "$@" ;;
esac
