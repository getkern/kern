#!/bin/sh
# Live observability without a daemon: per-box resource use and full box detail, read straight from
# the kernel (cgroups + the registry), no background service.
#
#   kern stats [--json] [name...]   one-shot memory + CPU per box (all, or just the named ones)
#   kern top                        live auto-refreshing monitor in a terminal; a one-shot
#                                   host+box SNAPSHOT when its output is piped (as here)
#   kern inspect <name> [--json]    full detail for one box - identity + resources
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2


echo "==> start two detached boxes doing a little work:"
"$kern" box api    --image alpine -d -- /bin/sh -c 'while true; do :; done'
"$kern" box worker --image alpine -d -- /bin/sh -c 'while true; do sleep 1; done'
# Il box e' gia' avviato quando `-d` ritorna (misurato: 20 su 20 con `exec` e `logs` subito dopo).
# Si aspetta la CONDIZIONE, non un tempo: qui e' istantaneo, e su una board lenta regge lo stesso,
# mentre un `sleep 1` fisso era il numero sbagliato in entrambe le direzioni.
i=0; while [ $i -lt 25 ] && [ -z "$("$kern" ps -q 2>/dev/null)" ]; do sleep 0.04; i=$((i+1)); done

echo
echo "==> kern stats - memory + CPU per box, sampled from each box's cgroup:"
"$kern" stats

echo
echo "==> kern stats --json (machine-readable, one object per box):"
"$kern" stats --json

echo
echo "==> narrow to a single box by name:"
"$kern" stats worker

echo
echo "==> kern top - interactive TUI in a terminal; piped (like now) it prints a one-shot"
echo "    host + box snapshot, so it's safe in a script. Run 'kern top' yourself for the live view:"
"$kern" top | head -20

echo
echo "==> kern inspect - full detail for one box (identity + resources). Pipe the JSON form"
echo "    into any tool; here we just show it:"
"$kern" inspect api --json

echo
echo "==> cleanup:"
"$kern" stop api
"$kern" stop worker
