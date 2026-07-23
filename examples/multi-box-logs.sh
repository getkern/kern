#!/bin/sh
# Daemonless `compose logs -f`: follow the live output of a whole fleet at once, each line prefixed
# with its box name, merged into one stream. Just `kern logs --tail 0 -f` per box in the background
# plus a prefix. Every follow returns on its own when its box exits (Ctrl-C also ends them all).
#
# Real-life: watching several services on one board interleave in real time while you debug, with no
# daemon aggregating logs for you.
set -eu
kern="${KERN:-kern}"
img="${IMG:-alpine}"
pfx="mlog$$"

cleanup() {
  for n in web api worker; do "$kern" stop "${pfx}-$n" >/dev/null 2>&1 || true; done
  "$kern" gc >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> launch 3 services, each logging on its own cadence:"
"$kern" box "${pfx}-web" --image "$img" -d -- \
  sh -c 'i=0; while [ $i -lt 6 ]; do echo "GET / 200"; i=$((i+1)); sleep 1; done' >/dev/null
"$kern" box "${pfx}-api" --image "$img" -d -- \
  sh -c 'i=0; while [ $i -lt 6 ]; do echo "SELECT users -> ok"; i=$((i+1)); sleep 1; done' >/dev/null
"$kern" box "${pfx}-worker" --image "$img" -d -- \
  sh -c 'i=0; while [ $i -lt 6 ]; do echo "job $i done"; i=$((i+1)); sleep 1; done' >/dev/null
sleep 1

echo
echo "==> follow ALL three live, each line tagged with its box (a daemonless 'compose logs -f'):"
for n in web api worker; do
  "$kern" logs "${pfx}-$n" --tail 0 -f 2>/dev/null | sed "s/^/[$n] /" &
done
wait
echo "==> all boxes exited; every follow returned on its own."
