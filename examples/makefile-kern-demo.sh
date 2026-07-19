#!/bin/sh
# Runnable demo for Makefile.kern: `make lint/test/build` where each target executes in a kern box,
# so a machine with only kern installed (no compiler, no linter) can still build and test a project.
set -eu
kern="${KERN:-kern}"
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
