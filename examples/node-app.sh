#!/bin/sh
# Develop and run a Node.js service WITHOUT installing node/npm on your host.
#
# Two phases, on purpose:
#   1. INSTALL (--net):   pull a dependency from the npm registry into node_modules, which lives on
#                         your host via a bind mount (-v). This is the only step that touches the network.
#   2. SERVE (no --net):  a SEPARATE, network-isolated box runs the app against the already-installed
#                         dependency and publishes its port to localhost (-p). No outbound access.
#
# The split is the point: fetch deps once with the network on, then run the app sealed off. Your host
# never gets node, npm, or node_modules in its PATH - it all stays in the throwaway boxes and the
# bind-mounted app dir.
set -eu
kern="${KERN:-kern}"
port="${PORT:-8080}"
name=node_demo

# A throwaway app directory on the host. node_modules will be written here by the install box.
app="$(mktemp -d)"
# Always clean up: stop the detached server, then delete the app dir (incl. node_modules).
trap '"$kern" stop "$name" >/dev/null 2>&1 || true; rm -rf "$app"' EXIT

cat > "$app/package.json" <<'EOF'
{
  "name": "kern-node-demo",
  "version": "1.0.0",
  "private": true,
  "dependencies": { "ms": "^2.1.3" }
}
EOF

# A tiny HTTP service that USES the installed dependency (`ms` formats a duration).
cat > "$app/app.js" <<'EOF'
const http = require('http');
const ms = require('ms'); // the dependency fetched in the install phase
http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('hello from a kern node box - uptime ' + ms(Math.round(process.uptime() * 1000), { long: true }) + '\n');
}).listen(8000, () => console.log('listening on 8000'));
EOF

echo "==> 1. INSTALL phase (--net on): npm install the dependency into a host-side node_modules:"
"$kern" box node_install --image node:alpine --net \
  -v "$app:/app" -w /app -- \
  sh -c 'npm install --no-audit --no-fund >/dev/null 2>&1 && echo "   installed: $(ls node_modules)"'

echo
echo "==> 2. SERVE phase (NO --net): run the app in an isolated box, published on localhost:$port:"
# The server box has no network access; it only reuses the node_modules from phase 1 (bound in at /app).
"$kern" box "$name" --image node:alpine -d \
  -v "$app:/app" -w /app -p "$port:8000" -- \
  node app.js

echo "==> waiting for it to answer, then fetching http://localhost:$port :"
fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsS --max-time 2 "$1" 2>/dev/null
  else wget -qO- -T 2 "$1" 2>/dev/null; fi
}
i=0
while [ "$i" -lt 25 ]; do
  if body="$(fetch "http://localhost:$port")"; then printf '    %s\n' "$body"; break; fi
  i=$((i + 1)); sleep 1
done
[ "$i" -lt 25 ] || { echo "    (did not come up in time)"; exit 1; }

echo
echo "==> kern ps (the detached server, with its published port):"
"$kern" ps

echo
echo "==> your host stayed clean:"
command -v node >/dev/null 2>&1 && echo "   (host has node)" || echo "   host has NO node - it all lived in the boxes"
echo "done - server stopped and app dir removed on exit (trap), no daemon left behind."
