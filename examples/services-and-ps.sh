#!/bin/sh
# Long-running boxes without a daemon: start detached, list, stop.
#
# `-d` forks a tiny supervisor that registers the box under $XDG_RUNTIME_DIR/kern/instances/.
# `kern ps` reads that directory and prunes dead entries as it goes — no background service.
set -eu
kern="${KERN:-kern}"

echo "starting two detached boxes..."
"$kern" box web --image alpine -d -- /bin/sh -c 'while true; do sleep 1; done'
"$kern" box cache --image alpine -d -- /bin/sh -c 'while true; do sleep 1; done'

sleep 1
echo
echo "kern ps:"
"$kern" ps

echo
echo "kern ps --json (machine-readable):"
"$kern" ps --json

echo
echo "stopping them..."
"$kern" stop web
"$kern" stop cache

sleep 1
echo "after stop, kern ps:"
"$kern" ps
