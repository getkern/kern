#!/bin/sh
# Bring up a richer `kern compose` stack - a cache with a health check + a web front-end that
# waits for that health - then reach it from the host and tear it all down.
#
#   kern compose <file>          bring the stack up, in dependency + HEALTH order
#   kern compose <file> down     stop every box and remove the stack's shared pod
#
# `kern compose` topologically sorts by dependency, starts each box detached, and for a
# `depends_healthy` edge it BLOCKS the dependent box until the dependency's --health-cmd passes.
# A multi-service stack gets a shared pod network automatically (name resolution + one loopback).
set -eu
kern="${KERN:-kern}"
here="$(dirname "$0")"
stack="$here/compose-webstack.toml"
port="${PORT:-8088}"

cleanup() {
  "$kern" compose "$stack" down >/dev/null 2>&1 || true
  "$kern" gc >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "==> bringing up the stack (cache must go HEALTHY before web starts):"
"$kern" compose "$stack"

echo
echo "==> kern ps - note the HEALTH column on 'cache' and the published PORT on 'web':"
"$kern" ps | sed 's/^/   /'

echo
echo "==> reach the web front-end from the HOST on 127.0.0.1:$port:"
fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsS --max-time 2 "$1" 2>/dev/null
  else wget -qO- -T 2 "$1" 2>/dev/null; fi
}
i=0
while [ "$i" -lt 25 ]; do
  if body="$(fetch "http://127.0.0.1:$port/")"; then
    printf '   %s\n' "$body"
    break
  fi
  i=$((i + 1)); sleep 1
done
[ "$i" -lt 25 ] || echo "   (web did not answer in time)"

echo
echo "==> tearing the stack down (stops both boxes + removes the shared pod):"
"$kern" compose "$stack" down

echo
echo "==> done - cleanup trap also runs a final compose down + kern gc, both idempotent."
