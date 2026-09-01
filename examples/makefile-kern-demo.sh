#!/bin/sh
# Runnable demo for Makefile.kern: `make lint/test/build` where each target executes in a kern box,
# so a machine with only kern installed (no compiler, no linter) can still build and test a project.
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2

here="$(cd "$(dirname "$0")" && pwd)"

# A throwaway stand-in project. Point make at your own repo instead.
proj="$(mktemp -d)"
trap 'rm -rf "$proj"' EXIT
echo "int main(void){return 0;}" > "$proj/main.c"

echo "==> running lint, test, and build - each hermetically in its own box:"
# CURDIR (and thus the repo bind) is wherever make is invoked, so run make from the project dir.
# KERN is passed through so the Makefile honors $KERN if you overrode it.
( cd "$proj" && make -f "$here/Makefile.kern" KERN="$kern" all )

echo
echo "==> artifact produced by the 'build' target (written to ./dist inside the box):"
cat "$proj/dist/artifact.txt"
echo "(the boxes are gone; only ./dist persisted, because it was an explicit writable bind)"
