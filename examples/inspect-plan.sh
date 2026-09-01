#!/bin/sh
# Audit the isolation BEFORE running anything.
#
# `kern box <name> --plan` prints the exact, ordered mount sequence the sandbox would perform -
# no privileges, nothing executed. Useful for review, docs, and CI policy checks.
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2


"$kern" box web --plan

# The mount ordering (pivot before the read-only remount) is enforced by a typestate in the
# code: writing it the wrong way around is a *compile* error, not a latent sandbox-escape bug.
