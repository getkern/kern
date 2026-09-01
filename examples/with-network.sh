#!/bin/sh
# Networking is OFF by default (isolated, loopback-only). Opt in with --net to share the host
# network namespace - outbound connectivity for build/fetch steps. kern copies the host's
# resolv.conf into the box so DNS resolves out of the box.
#
# Trade-off: --net means NO network isolation (host localhost + abstract sockets are reachable).
# Use it for trusted work, not untrusted code. See SECURITY.md.
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2


echo "==> default (no --net): the box is isolated, outbound fails:"
"$kern" box offline --image alpine -- \
  sh -c 'wget -q -T3 -O- https://example.com >/dev/null 2>&1 && echo "reachable" || echo "no network (expected)"'

echo
echo "==> with --net: DNS + outbound work (install a package, fetch a URL):"
"$kern" box online --image alpine --net -- \
  sh -c 'apk add --no-cache curl >/dev/null 2>&1 && curl -fsS https://example.com | grep -o "<title>.*</title>"'
