#!/bin/sh
# Bring up a multi-box stack from a TOML file, in dependency order.
#
# `kern compose` reads stack.toml, topologically sorts by `depends_on` (rejecting cycles and
# unknown deps), and starts each box detached. Track them with `kern ps`, tear down with
# `kern stop`.
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2

here="$(dirname "$0")"

echo "composing the stack (db -> api -> web):"
"$kern" compose "$here/stack.toml"

# Condizione, non orologio: appena i box compaiono si prosegue. Un `sleep 1` fisso costava un
# secondo qui e poteva non bastare su una board lenta.
i=0; while [ $i -lt 25 ] && [ -z "$("$kern" ps -q 2>/dev/null)" ]; do sleep 0.04; i=$((i+1)); done
echo
echo "running boxes:"
"$kern" ps

echo
echo "tearing down:"
# Box names are scoped to the PROJECT (`<project>-<hash>-<service>`), so two stacks
# with a `db` can coexist. That means a bare `kern stop db` no longer finds it: tear the stack down
# with the verb that knows the project, which also removes the shared pod.
"$kern" compose "$here/stack.toml" down
