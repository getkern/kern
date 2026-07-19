#!/bin/sh
# Run a web service in an isolated box and reach it from the host.
#
# The box serves a page on its own port; `-p` publishes it to localhost through
# a rootless forwarder. The box is detached, so `kern ps` shows the published
# port while it runs.
set -eu
kern="${KERN:-kern}"
port="${PORT:-8080}"

# Always tidy up, even if a step fails.
trap '"$kern" stop web >/dev/null 2>&1 || true' EXIT

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsS --max-time 2 "$1" 2>/dev/null
  else wget -qO- -T 2 "$1" 2>/dev/null; fi
}

echo "==> starting a web server, published on localhost:$port"
"$kern" box web --image python:alpine -d -p "$port:8000" -- \
  sh -c 'mkdir -p /www && echo "<h1>hello from kern</h1>" > /www/index.html && cd /www && exec python3 -m http.server 8000'

echo "==> waiting for it to answer, then fetching http://localhost:$port :"
i=0
while [ "$i" -lt 25 ]; do
  if body="$(fetch "http://localhost:$port")"; then
    printf '    %s\n' "$body"
    break
  fi
  i=$((i + 1)); sleep 1
done
[ "$i" -lt 25 ] || { echo "    (did not come up in time)"; exit 1; }

echo
echo "==> kern ps (note the PORTS column):"
"$kern" ps

echo
echo "==> stopping (via trap on exit) - nothing left running, no daemon."
