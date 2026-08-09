#!/bin/sh
# Publish a box's port to the host and keep the service healthy - without a daemon:
#   -p [ip:]host:box   publish a port (binds 127.0.0.1 by default; 0.0.0.0 only if you ask for it)
#   --restart          restart the box if it exits non-zero (on-failure policy)
#   --health-cmd       probe the box periodically; `kern ps` shows HEALTH
#
# Real-life: run a web service / API on a box, reachable from the host, self-healing - no daemon.
set -eu
kern="${KERN:-kern}"
name=web

echo "==> starting a detached HTTP service: host 8080 -> box 80, with restart + health-check:"
"$kern" box "$name" --image alpine -d \
  -p 8080:80 --restart \
  --health-cmd 'wget -qO- localhost:80 >/dev/null' --health-interval 3 \
  -- sh -c 'while true; do printf "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello from kern\n" | nc -lp 80; done'

echo
echo "==> waiting for the health check to go green..."
# Poll the state, do not guess the duration. A fixed `sleep 4` was both slower than necessary here
# and too short on a loaded ARM board: the wrong number in both directions, which is what a fixed
# wait always is. Ten tries at 200 ms, then give up loudly rather than pretend.
i=0
while [ $i -lt 10 ]; do
  "$kern" ps 2>/dev/null | grep -q "healthy" && break
  sleep 0.2; i=$((i + 1))
done
[ $i -lt 10 ] || echo "    (still not healthy after 2s - continuing so you can see what ps reports)"
echo "==> kern ps - note the PORTS (127.0.0.1:8080->80) and HEALTH (healthy) columns:"
"$kern" ps

echo
echo "==> reach the box service from the HOST, over the published port:"
if command -v curl >/dev/null 2>&1; then
  curl -s http://127.0.0.1:8080/ || true
else
  wget -qO- http://127.0.0.1:8080/ || true
fi

echo
echo "==> the port binds 127.0.0.1 by DEFAULT (not exposed to the network). To expose on purpose:"
echo "      kern box $name -d -p 0.0.0.0:8080:80 ...   # binds all interfaces, prints a warning"

echo
echo "==> tear down:"
"$kern" stop "$name" >/dev/null
echo "done - port released, no daemon left behind."
