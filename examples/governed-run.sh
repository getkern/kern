#!/bin/sh
# Govern *resources* (CPU + memory), with or without a sandbox:
#   kern run --memory M --cpus N -- CMD    run a HOST command under cgroup caps - no namespaces, no
#                                          seccomp, no overlay; the leanest path (a capped exec).
#   kern box --memory M --cpus N           the same hard caps on a sandboxed box; a workload over the
#                                          memory limit is OOM-killed by the kernel.
#
# Real-life: cap a flaky build, a memory-hungry job, or a noisy neighbour - first-party governance.
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2


echo "==> kern run: a host command under a 256 MB / 0.5-core quota (governor only, no sandbox):"
"$kern" run --memory 256M --cpus 0.5 -- sh -c 'echo "running under a governed slice"; echo "cpus visible: $(nproc)"'

echo
echo "==> a hard memory cap is kernel-enforced. Inside a box with a 256 MB cap, allocate ~400 MB:"
echo "    (expected: killed at the cap by the kernel - the limit holds)"
if "$kern" box capped --image alpine --memory 256M -- \
     sh -c 'a=$(yes | head -c 400000000); echo "allocated ${#a} bytes (cap did NOT hold)"'; then
  echo "  note: no systemd-user cgroup here, so the cap is best-effort - see SECURITY.md"
else
  echo "  -> killed at the cap (exit $?), as expected: the 256 MB limit was enforced."
fi
echo "done."

# Fail-closed variant: add `--require-limits` and the box REFUSES to start unless the memory/pids caps
# are actually enforced (read back from the cgroup) - no silent best-effort fallback on a host that
# doesn't delegate cgroup v2. Use it when an unenforced cap must be a hard error, not a warning.
