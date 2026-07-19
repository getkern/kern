#!/bin/sh
# `--add-host NAME:IP` adds a custom /etc/hosts entry inside the box (repeatable). The IP may be the
# special keyword `host-gateway`, which kern resolves to the host's reachable address:
#   * with --net  (box shares the host network):  host-gateway -> 127.0.0.1
#   * default     (isolated box with egress):     host-gateway -> the host's primary IPv4
#     (the source address the host's default route would use).
#
# This is the standard way to point a box's client at a service running on the host, by a stable
# name, without hard-coding an IP.
#
#   --add-host db:10.0.0.5           map an arbitrary name to a fixed IP
#   --add-host host.internal:host-gateway   name the host itself
set -eu
kern="${KERN:-kern}"

cleanup() { "$kern" gc >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

echo "==> add a custom name -> IP entry; verify it lands in the box's /etc/hosts and resolves:"
"$kern" box withhost --image alpine \
  --add-host db.internal:10.0.0.5 \
  --add-host cache.internal:10.0.0.6 -- \
  sh -c 'echo "--- /etc/hosts (custom entries) ---"; \
         grep internal /etc/hosts; \
         echo "--- getent resolves the name ---"; \
         getent hosts db.internal'

echo
echo "==> host-gateway names the HOST from inside an isolated box (resolved to the host IPv4):"
# NOTE: resolution always works; REACHING a host service additionally requires the box to have a
# route to the host (e.g. --net, or a pod with pasta egress). Here we just show the resolution.
"$kern" box gw --image alpine \
  --add-host host.internal:host-gateway -- \
  sh -c 'echo "--- host.internal -> host primary IPv4 ---"; \
         grep host.internal /etc/hosts'

echo
echo "==> with --net the box shares the host network, so host-gateway resolves to loopback:"
"$kern" box gwnet --image alpine --net \
  --add-host host.internal:host-gateway -- \
  sh -c 'grep host.internal /etc/hosts'

echo
echo "done - custom names and the host-gateway keyword are just /etc/hosts entries in the box."
