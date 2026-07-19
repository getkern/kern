#!/bin/sh
# Audit the isolation BEFORE running anything.
#
# `kern box <name> --plan` prints the exact, ordered mount sequence the sandbox would perform -
# no privileges, nothing executed. Useful for review, docs, and CI policy checks.
set -eu
kern="${KERN:-kern}"

"$kern" box web --plan

# The mount ordering (pivot before the read-only remount) is enforced by a typestate in the
# code: writing it the wrong way around is a *compile* error, not a latent sandbox-escape bug.
