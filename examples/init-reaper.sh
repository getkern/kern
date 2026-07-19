#!/bin/sh
# --init: give the box a real PID 1 that reaps zombies (and forwards SIGTERM/SIGINT).
#
# When a process's parent exits, its children are re-parented to PID 1. If those children then
# exit, PID 1 must `wait()` on them or they linger as <defunct> "zombie" entries in the process
# table. A plain shell run as the box's PID 1 does NOT reap re-parented grandchildren - so a
# workload that spawns short-lived orphans (a supervisor, a job runner, anything that forks) piles
# up zombies. `--init` inserts kern's tiny reaping init as PID 1: it adopts the orphans, reaps them
# immediately, and forwards signals to your command. (This is the classic "why --init" problem,
# same as Docker's --init / tini.)
#
# The payload below spawns a batch of orphaned children, waits for them to exit, then counts how
# many are stuck in the zombie state (Z) inside the box. Rootless, non-invasive, self-cleaning.
set -eu
kern="${KERN:-kern}"
img="${IMG:-alpine}"

# Shared workload: spawn 20 orphans, each backgrounded inside a subshell that exits at once so the
# child is re-parented to PID 1; then give them a moment to exit and count zombies via /proc.
payload='
  i=0
  while [ $i -lt 20 ]; do ( /bin/true & ) ; i=$((i + 1)); done
  sleep 1
  z=0
  for s in /proc/[0-9]*/status; do
    grep -q "^State:.*Z (zombie)" "$s" 2>/dev/null && z=$((z + 1))
  done
  echo "   zombies still in the process table: $z"
'

echo "── 1. WITHOUT --init: the shell is PID 1 and does not reap re-parented orphans"
"$kern" box reap-off --image "$img" -- sh -c "$payload"
echo "   (expect a nonzero count - the orphans exited but nobody wait()ed on them)"

echo
echo "── 2. WITH --init: kern's reaping init is PID 1 and adopts + reaps the orphans"
"$kern" box reap-on --image "$img" --init -- sh -c "$payload"
echo "   (expect 0 - every orphan was reaped as soon as it exited) ✓"

echo
echo "done - use --init for any box whose workload forks child processes (supervisors, job"
echo "runners, test harnesses). Both boxes were rootless and are already gone."
