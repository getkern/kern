#!/bin/sh
# `--tun` exposes `/dev/net/tun` inside the box, so a userspace VPN / tunnel tool (WireGuard-go,
# openvpn, tun2socks, ...) can create a TUN interface in the box's OWN network namespace. Without
# --tun the device node is absent, so those tools can't run.
#
# This example is deliberately MINIMAL and HONEST: it proves the device is present with --tun and
# absent without it. It does NOT stand up a real VPN (that needs an external peer + keys, out of
# scope for a self-contained, non-invasive example). `--tun` takes no argument.
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2


cleanup() { "$kern" gc >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

echo "==> WITHOUT --tun: /dev/net/tun does not exist in the box (userspace VPNs can't start):"
"$kern" box notun --image alpine -- \
  sh -c 'if [ -c /dev/net/tun ]; then echo "present (unexpected)"; else echo "absent (expected)"; fi'

echo
echo "==> WITH --tun: the box sees the TUN char device it needs:"
"$kern" box withtun --image alpine --tun -- \
  sh -c 'echo "--- device node ---"; \
         ls -l /dev/net/tun; \
         [ -c /dev/net/tun ] && echo "OK: /dev/net/tun is a character device the VPN tool will open"'

echo
echo "==> the box has its OWN network namespace, so a tunnel it creates is private to the box."
echo "    A real userspace VPN then does the rest, e.g. inside a --tun box:"
echo "      apk add wireguard-tools wireguard-go   # (needs egress: add --net or a pod w/ pasta)"
echo "      wg-quick up wg0                         # opens /dev/net/tun, creates the TUN iface"
echo
echo "done - --tun only PROVISIONS the device; the workload owns the tunnel."
