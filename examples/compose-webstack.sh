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

# Mirror kern's own precondition (the same check `multi-uid.sh` narrates): the official redis and nginx images drops privilege
# in its entrypoint, which needs a subordinate uid RANGE, which needs the setuid `newuidmap` /
# `newgidmap` helpers plus an /etc/subuid allocation. Without them kern warns and falls back to a
# single-uid map, where that entrypoint fails on its own `chown` - not a kern defect and not
# something this example can show, so it says which piece is missing and stops.
if ! command -v newuidmap >/dev/null 2>&1 ||
   ! grep -q "^$(id -un):" /etc/subuid 2>/dev/null; then
    echo "SKIPPED: no uid RANGE available on this host (need the uidmap package and an"
    echo "         /etc/subuid entry for $(id -un)). the official redis and nginx images cannot drop privilege without it."
    exit 0
fi

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
