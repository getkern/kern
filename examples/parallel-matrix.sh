#!/bin/sh
# Run the same command across a matrix of base images, all at once. kern fans out isolated
# boxes with no daemon and no lock contention (200 in ~0.07s in BENCHMARKS.md), so a test
# matrix finishes in the time of its slowest single box - not the sum.
#
# Without kern: a daemon serializes this (Docker ~3 runs/s), or you script chroots by hand.
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2


# What to check on each image (here: distro id + which shell it ships).
CHECK='if [ -r /etc/os-release ]; then . /etc/os-release; fi; echo "${ID:-minimal} - sh=$(readlink -f "$(command -v sh)")"'

pids=""
for img in alpine:3.19 alpine:3.18 debian:stable-slim ubuntu:24.04 busybox; do
  out="/tmp/kern-matrix-$$-$(echo "$img" | tr ':/' '--')"
  ( "$kern" box "m-$(echo "$img" | tr ':/' '--')" --image "$img" -- sh -c "$CHECK" >"$out" 2>/dev/null ) &
  pids="$pids $!"
done
wait $pids

echo "matrix results:"
for f in /tmp/kern-matrix-$$-*; do printf '  '; cat "$f"; rm -f "$f"; done
