#!/bin/sh
# Long-running boxes without a daemon: start detached, list, stop.
#
# `-d` forks a tiny supervisor that registers the box under $XDG_RUNTIME_DIR/kern/instances/.
# `kern ps` reads that directory and prunes dead entries as it goes - no background service.
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2


echo "starting two detached boxes..."
"$kern" box web --image alpine -d -- /bin/sh -c 'while true; do sleep 1; done'
"$kern" box cache --image alpine -d -- /bin/sh -c 'while true; do sleep 1; done'

# Il box e' gia' avviato quando `-d` ritorna (misurato: 20 su 20 con `exec` e `logs` subito dopo).
# Si aspetta la CONDIZIONE, non un tempo: qui e' istantaneo, e su una board lenta regge lo stesso,
# mentre un `sleep 1` fisso era il numero sbagliato in entrambe le direzioni.
i=0; while [ $i -lt 25 ] && [ -z "$("$kern" ps -q 2>/dev/null)" ]; do sleep 0.04; i=$((i+1)); done
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

# Condizione, non orologio: appena i box compaiono si prosegue. Un `sleep 1` fisso costava un
# secondo qui e poteva non bastare su una board lenta.
i=0; while [ $i -lt 25 ] && [ -z "$("$kern" ps -q 2>/dev/null)" ]; do sleep 0.04; i=$((i+1)); done
echo "after stop, kern ps:"
"$kern" ps
