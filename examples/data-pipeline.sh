#!/bin/sh
# A real per-job data pipeline: read-only input in, results out, processing isolated.
# The job can't modify your source data (mounted :ro) and can only write to the output dir.
# Run one per job/file/tenant - each in its own throwaway box.
#
# Real-life: batch transforms, log crunching, per-tenant processing, an edge sensor pipeline.
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
printf 'banana\napple\ncherry\napple\n' > "$work/in/fruit.txt"
printf 'alice,30\nbob,25\n'             > "$work/in/people.csv"

echo "==> processing $(ls "$work/in" | wc -l) input files, each transform isolated:"
"$kern" box pipeline --image alpine \
  -v "$work/in:/in:ro" -v "$work/out:/out" -w /in -- \
  sh -c 'sort -u fruit.txt > /out/fruit.sorted; cut -d, -f1 people.csv > /out/names.txt; echo "transformed."'

echo "==> outputs on your host (input dir was read-only and untouched):"
for f in "$work/out"/*; do echo "  --- $(basename "$f") ---"; sed 's/^/    /' "$f"; done
