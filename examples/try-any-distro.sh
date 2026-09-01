#!/bin/sh
# Try a command on several Linux distros - instantly, throwaway, no VM, no install.
# Each box pulls the image once (cached after), runs in a writable overlay, and vanishes.
# Without kern this means either a daemon (Docker) or hand-built chroots/VMs.
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2


for img in alpine:3.19 debian:stable-slim ubuntu:24.04; do
  printf '%-22s ' "$img:"
  "$kern" box "try-$(echo "$img" | tr ':/' '--')" --image "$img" -- \
    sh -c '. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME"'
done

echo
echo "Nothing was installed on your host; every box was discarded on exit."
