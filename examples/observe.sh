#!/bin/sh
# Observe running boxes — daemonless. A detached box's output is captured to a log, and its
# memory/CPU are read straight from its cgroup. No background service.
#
#   kern logs <name>   replay captured stdout/stderr (works after the box exits, too)
#   kern stats [--json]  one-shot memory + CPU per box
#   kern top           live, auto-refreshing view (Ctrl-C to exit) — try it interactively
set -eu
kern="${KERN:-kern}"

echo "==> start a detached box that prints and then works:"
"$kern" box worker --image alpine -d -- \
  sh -c 'echo "worker started"; i=0; while [ $i -lt 30 ]; do echo "tick $i"; i=$((i+1)); sleep 1; done'
sleep 2

echo
echo "==> kern logs worker (captured output):"
"$kern" logs worker

echo
echo "==> kern stats --json (memory + CPU from the cgroup):"
"$kern" stats --json

echo
echo "==> 'kern top' gives a live view (run it in your terminal). Stopping the box:"
"$kern" stop worker

echo "==> logs survive after exit:"
"$kern" logs worker | tail -1
