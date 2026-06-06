#!/bin/sh
# Getting data in and out of a box, and stepping into a running one.
#
#   -v src:dst[:ro]   bind a host path in (the only sanctioned way across the boundary)
#   --env / --workdir set environment + working dir
#   kern exec         run a command inside an already-running box (joins its namespaces)
set -eu
kern="${KERN:-kern}"

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
sleep 1
"$kern" exec live -- /bin/sh -c 'echo "inside box $(hostname); processes: $(ls -d /proc/[0-9]* | wc -l)"'
"$kern" stop live
