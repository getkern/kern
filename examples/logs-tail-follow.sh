#!/bin/sh
# `kern logs --tail N` and `kern logs -f`: read a box's captured output like `tail`.
#
#   --tail N     -> only the last N lines. kern seeks a bounded window near the END of the log, so a
#                   huge long-running log costs O(lines shown), not O(file size) - safe on GB-size logs.
#   -f/--follow  -> stream new appends live until the box exits (a `tail -f` for boxes). Ctrl-C ends the
#                   follow without touching the box. Combine with `--tail` to print a little backlog
#                   first; `--tail 0 -f` follows ONLY new output.
#
# Real-life: peek at the tail of a long training/build job without slurping the whole log; live-follow
# a detached service while debugging; `--tail 0 -f` as a clean "from here on" stream.
set -eu
kern="${KERN:-kern}"
img="${IMG:-alpine}"
b="logsdemo$$"

cleanup() {
  "$kern" stop "$b" >/dev/null 2>&1 || true
  "$kern" gc >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> a detached box that writes 100000 lines fast, then a few slow ticks:"
"$kern" box "$b" --image "$img" -d -- sh -c '
  i=0; while [ $i -lt 100000 ]; do echo "bulk line $i"; i=$((i+1)); done
  j=0; while [ $j -lt 6 ]; do echo "slow tick $j"; j=$((j+1)); sleep 1; done
' >/dev/null
sleep 2

echo
echo "==> logs --tail 3 : just the last 3 lines of a 100k+ line log (bounded read, no full slurp):"
"$kern" logs "$b" --tail 3

echo
echo "==> logs --tail 0 -f : skip the backlog, then follow ONLY new appends until the box exits:"
"$kern" logs "$b" --tail 0 -f
echo "==> box exited; the follow returned on its own (the box left the registry, no Ctrl-C needed)."
