#!/bin/sh
# The two verbs, side by side, because the names collide with Docker's and the collision is
# backwards. In Docker there is ONE verb and it isolates: `docker run` starts a container. In kern
# there are two, and the one spelled `run` is the one that does NOT isolate:
#
#   kern box   wraps a process in a full slice: image, namespaces, pivoted root, seccomp, cgroups.
#              This is what `docker run` does. It is the verb you want 90% of the time.
#   kern run   caps a process YOU launch, on the host, with no image and no sandbox. Docker has no
#              equivalent. It is the verb for "cap this build, this ffmpeg, this test run".
#
# Reading that is not the same as seeing it, so this script prints what each verb actually hands the
# workload: its uid, its hostname, what it thinks pid 1 is, and whether your home directory is
# reachable. Run it and the difference stops being an argument about names.
#
# The practical rule, and the reason the script exists: if the thing you are running might misbehave,
# `kern box`. `kern run` is for code you already trust and only want to keep within a resource
# budget. `kern run` will not stop a program from reading your files, because it was never asked to.
set -eu

KERN="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$KERN" || echo "$KERN")" "$("$KERN" --version 2>&1 | head -1)" >&2

command -v "$KERN" >/dev/null 2>&1 || { echo "kern not on PATH (set KERN=./target/release/kern)"; exit 1; }

# One probe, run three ways. `/proc/1/comm` rather than `ps`, so it reads the same under busybox
# inside the box as under procps on the host; HOME is passed in as $1 so the box cannot expand it to
# its own root and quietly compare a different path than the other two lines.
probe='printf "  uid=%-5s hostname=%-14s pid1=%-8s home reachable=%s\n" \
  "$(id -u)" "$(hostname)" "$(cat /proc/1/comm 2>/dev/null || echo ?)" \
  "$(test -d "$1" && echo YES || echo no)"'

echo
echo "1. the command bare, no kern at all"
sh -c "$probe" _ "$HOME"

echo
echo "2. kern run: a cap on that same host process. Same uid, same hostname, same pid 1, and your"
echo "   files are still right there. Nothing was isolated, and nothing claimed to be."
"$KERN" run --memory 256m --cpus 0.5 -- sh -c "$probe" _ "$HOME"

echo
echo "3. kern box: a real slice. Root inside its own user namespace, its own hostname, its own pid 1,"
echo "   and your home directory is simply not in the filesystem it can see."
"$KERN" box rvb --image alpine --memory 256m -- sh -c "$probe" _ "$HOME"

echo
echo "4. and what you get when you reach for the wrong one, which is the common mistake:"
echo "   \$ kern run --read-only --network none -- ./untrusted"
"$KERN" run --read-only --network none -- ./untrusted 2>&1 | sed 's/^/   /' || true

echo
echo "Both verbs take the same resource tokens, which is the point: one vcpu:heavy governs a bare"
echo "process and an isolated box alike. What differs is whether anything is isolated at all."
