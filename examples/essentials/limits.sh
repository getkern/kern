#!/bin/sh
# Run a box under hard CPU / memory caps (cgroup v2).
# The kernel enforces them where the controllers are delegated (a normal systemd
# user session). If a cap can't be applied, kern says so plainly rather than
# pretending it's in force.
set -eu
kern="${KERN:-kern}"
echo '==> kern box worker --image alpine --memory 256m --cpus 1 -- <work>'
"$kern" box worker --image alpine --memory 256m --cpus 1 -- \
  sh -c 'echo "running under a 256 MB / 1-core cap"; i=0; while [ $i -lt 200000 ]; do i=$((i+1)); done; echo "did some work, stayed within the cap"'
echo "The cap rode along with the box; no daemon, nothing left behind."
