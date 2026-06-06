#!/bin/sh
# Bring up a multi-box stack from a TOML file, in dependency order.
#
# `kern compose` reads stack.toml, topologically sorts by `depends_on` (rejecting cycles and
# unknown deps), and starts each box detached. Track them with `kern ps`, tear down with
# `kern stop`.
set -eu
kern="${KERN:-kern}"
here="$(dirname "$0")"

echo "composing the stack (db -> api -> web):"
"$kern" compose "$here/stack.toml"

sleep 1
echo
echo "running boxes:"
"$kern" ps

echo
echo "tearing down:"
for b in web api db; do "$kern" stop "$b"; done
