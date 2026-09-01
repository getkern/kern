#!/bin/sh
# Head-to-head: the same isolated `/bin/true`, kern vs `docker run`. Run it yourself.
# kern starts in single-digit ms with no daemon; `docker run` pays a daemon round-trip.
# (Warm both first; numbers vary by machine - see BENCHMARKS.md for the full table.)
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2

N=20

bench() { # $1=label  $2..=command
  label="$1"; shift
  "$@" >/dev/null 2>&1 || true   # warm
  start=$(date +%s%N)
  i=0; while [ "$i" -lt "$N" ]; do "$@" >/dev/null 2>&1 || true; i=$((i+1)); done
  end=$(date +%s%N)
  awk "BEGIN{printf \"%-26s %6.1f ms/run\n\", \"$label\", ($end-$start)/1e6/$N}"
}

echo "==> $N runs each (warm):"
bench "kern box --image alpine" "$kern" box cmp --image alpine -- /bin/true

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  docker pull -q alpine >/dev/null 2>&1 || true
  bench "docker run --rm alpine" docker run --rm alpine /bin/true
else
  echo "docker run --rm alpine     (skipped - docker not available)"
fi

echo
echo "kern: no daemon, ~670 KB binary. docker: dockerd + containerd (~186 MB RSS) always resident."
