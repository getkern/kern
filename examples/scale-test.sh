#!/bin/sh
# Stress the runtime and drive it entirely from `kern ps -q`: spawn N isolated boxes fast, count them
# via `ps -q`, sample a slice with `--filter`/`--format`, then tear the whole set down with a single
# `kern stop $(kern ps -q ...)`. kern starts a box in ~2 ms rootless, so this is a burst of hundreds of
# sandboxes with no dockerd in the path and nothing left behind.
#
# Real-life: a load/chaos test, or a burst of per-task sandboxes (CI shards, fuzz workers) brought up
# and reaped as a set. Bump N to push it - hundreds are fine on a laptop.
set -eu
kern="${KERN:-kern}"
img="${IMG:-alpine}"
pfx="scale$$"
N="${N:-30}"

cleanup() {
  "$kern" ps -q 2>/dev/null | grep "$pfx" | while read -r n; do
    "$kern" stop "$n" >/dev/null 2>&1 || true
  done
  "$kern" gc >/dev/null 2>&1 || true
}
trap cleanup EXIT

count() { "$kern" ps -q 2>/dev/null | grep -c "$pfx" || true; }

echo "==> spawning $N isolated boxes concurrently:"
i=1
while [ "$i" -le "$N" ]; do
  "$kern" box "${pfx}-$i" --image "$img" -d -- sh -c 'while true; do sleep 5; done' >/dev/null &
  i=$((i + 1))
done
wait
sleep 1
echo "    live boxes (ps -q | grep | wc): $(count) / $N"

echo
echo "==> sample a slice with ps --filter + --format (first 3):"
"$kern" ps --filter "name=$pfx" --format '{{.Names}}\t{{.Status}}\tup {{.RunningFor}}' \
  | grep "$pfx" | sort -V | head -3 | sed 's/^/    /'

echo
echo "==> tear the whole set down with one command substitution:"
ids="$("$kern" ps -q | grep "$pfx" || true)"
before="$(count)"
# shellcheck disable=SC2086
[ -n "$ids" ] && "$kern" stop $ids >/dev/null
echo "    stopped $before boxes; remaining matching '$pfx': $(count)"
