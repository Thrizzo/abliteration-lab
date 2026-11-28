#!/bin/sh
# serve (default) -> the app server; options -> the pipeline CLI; anything else -> run as a command.
#   docker compose run --rm app --model THUDM/glm-edge-4b-chat --no-ollama
#   docker compose run --rm app sh
set -e
ABL_PROJECT="${ABL_PROJECT:-/workspace}"
mkdir -p "$ABL_PROJECT" 2>/dev/null || true
# the workspace is a bind mount / PVC. Started as root, the container runs as the app user abl and drops privileges:
#  - a folder that belongs to a host user (a bind mount on a Linux host): abl takes that user's uid and gid, so the files
#    stay theirs on the host, and files they write there (writeups, the copilot's secrets) are readable here;
#  - otherwise (Docker Desktop shares Windows folders as root, a new volume): the folder is handed to abl (uid 1000).
if [ "$(id -u)" = "0" ]; then
  owner="$(stat -c %u "$ABL_PROJECT" 2>/dev/null || echo 0)"
  group="$(stat -c %g "$ABL_PROJECT" 2>/dev/null || echo 0)"
  adopted=""
  if [ "$owner" != "0" ] && [ "$owner" != "$(id -u abl)" ]; then
    if [ "$group" != "0" ] && [ "$group" != "$(id -g abl)" ]; then
      groupmod -o -g "$group" abl 2>/dev/null || true
    fi
    if usermod -o -u "$owner" abl 2>/dev/null; then
      adopted=1
    else
      echo "WARNING: could not give the app user uid $owner (the owner of $ABL_PROJECT): handing the folder to uid $(id -u abl)" >&2
    fi
  fi
  if [ -z "$adopted" ]; then
    chown abl:abl "$ABL_PROJECT" 2>/dev/null || true
  fi
  # HOME: Triton's and other caches go to ~, and root's home is not abl's to write
  HOME=/home/abl
  export HOME
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
