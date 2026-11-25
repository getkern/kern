#!/bin/sh
# A box's network is Docker's by default: a NAT of its own, with outbound (DNS, fetch, install)
# and no reach into the host's loopback-only services. `--network none` leaves the box loopback
# only, which is what untrusted code should get. `--net` (`--network host`) shares the host's own
# network namespace.
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


echo "==> default: a NAT of the box's own, DNS + outbound work (install a package, fetch a URL):"
"$kern" box online --image alpine -- \
  sh -c 'apk add --no-cache curl >/dev/null 2>&1 && curl -fsS https://example.com | grep -o "<title>.*</title>"'

echo
echo "==> --network none: the box is isolated, outbound fails:"
"$kern" box offline --image alpine --network none -- \
  sh -c 'wget -q -T3 -O- https://example.com >/dev/null 2>&1 && echo "reachable" || echo "no network (expected)"'
