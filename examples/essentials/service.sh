#!/bin/sh
# A detached service, published to the host and shown in `kern ps`.
# `-p` forwards a host port to the box through a rootless forwarder.
set -eu
kern="${KERN:-kern}"; port="${PORT:-8080}"
trap '"$kern" stop web >/dev/null 2>&1 || true' EXIT
fetch() { if command -v curl >/dev/null 2>&1; then curl -fsS --max-time 2 "$1" 2>/dev/null
          else wget -qO- -T 2 "$1" 2>/dev/null; fi; }
echo "==> kern box web --image python:alpine -d -p $port:8000 -- python3 -m http.server"
"$kern" box web --image python:alpine -d -p "$port:8000" -- \
  sh -c 'mkdir -p /www && echo "<h1>hello from kern</h1>" > /www/index.html && cd /www && exec python3 -m http.server 8000'
i=0; while [ "$i" -lt 25 ]; do body="$(fetch "http://localhost:$port")" && break; i=$((i+1)); sleep 1; done
echo "==> curl http://localhost:$port  ->  ${body:-(did not come up)}"
echo "==> kern ps:"; "$kern" ps
echo "==> stopping (trap on exit) — no daemon."
