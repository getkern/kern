#!/bin/sh
# Getting data in and out of a box, and stepping into a running one.
#
#   -v src:dst[:ro]   bind a host path in (the only sanctioned way across the boundary)
#   --env / --workdir set environment + working dir
#   kern exec         run a command inside an already-running box (joins its namespaces)
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2


work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/in" "$work/out"
echo "payload-from-host" > "$work/in/data.txt"

echo "==> read a host file (ro) and write a result back (rw):"
"$kern" box job --image alpine \
  -v "$work/in:/in:ro" \
  -v "$work/out:/out" \
  -e RUN_ID=42 -w /out \
  -- /bin/sh -c 'echo "read: $(cat /in/data.txt) (run $RUN_ID) @ $(pwd)" > result.txt; cat result.txt'

echo "==> host now sees the box's output:"
cat "$work/out/result.txt"

echo
echo "==> step into a running box with kern exec:"
"$kern" box live --image alpine -d -- /bin/sh -c 'while true; do sleep 1; done'
# Il box e' gia' avviato quando `-d` ritorna (misurato: 20 su 20 con `exec` e `logs` subito dopo).
# Si aspetta la CONDIZIONE, non un tempo: qui e' istantaneo, e su una board lenta regge lo stesso,
# mentre un `sleep 1` fisso era il numero sbagliato in entrambe le direzioni.
i=0; while [ $i -lt 25 ] && [ -z "$("$kern" ps -q 2>/dev/null)" ]; do sleep 0.04; i=$((i+1)); done
"$kern" exec live -- /bin/sh -c 'echo "inside box $(hostname); processes: $(ls -d /proc/[0-9]* | wc -l)"'
"$kern" stop live
