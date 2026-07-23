#!/bin/sh
# Incident triage on a huge log WITHOUT reading the whole thing. A job emits a massive log then fails;
# `kern logs --tail N` seeks a bounded window near EOF (cost O(lines shown), not O(file size)), so you
# pull just the error tail off a huge log instantly, and `kern ps` snapshots box state for the report.
# The bounded read is what makes this safe on logs that would choke a naive `cat | tail`.
#
# Real-life: an SRE grabbing the crash tail + a state snapshot off a long-running training/build/ETL
# box on a device where slurping the whole log into memory is not an option.
set -eu
kern="${KERN:-kern}"
img="${IMG:-alpine}"
job="triage$$"

cleanup() {
  "$kern" stop "$job" >/dev/null 2>&1 || true
  "$kern" gc >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> a job that logs ~200k lines, then fails with an error tail:"
"$kern" box "$job" --image "$img" -d -- sh -c '
  i=0; while [ $i -lt 200000 ]; do echo "INFO step $i ok"; i=$((i+1)); done
  echo "ERROR: out of widgets at step 200000"
  echo "ERROR: aborting run"
  exit 1
' >/dev/null
# Wait for the job to finish (it will fail and self-clean from the registry).
while "$kern" ps -q | grep -q "$job"; do sleep 1; done

echo
echo "==> pull ONLY the last 4 lines off the ~200k-line log (bounded seek, no full slurp):"
"$kern" logs "$job" --tail 4 | sed 's/^/    /'

echo
echo "==> compact incident snapshot:"
running="$("$kern" ps -q | grep -c "$job" || true)"
echo "    box '$job' still running: $running  (0 = it crashed and self-cleaned from the registry)"
echo "==> triage done: error tail extracted from a huge log in O(lines shown), never O(file size)."
