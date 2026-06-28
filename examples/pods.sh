#!/bin/sh
# A POD is a set of boxes that share ONE network namespace — like a Kubernetes pod. Members reach
# each other over `localhost` AND by NAME, on 127.0.0.1. There is no daemon: `kern pod create`
# spawns a tiny holder process that owns the shared user+net namespace, and each
# `kern box --pod <name>` setns()es into it.
#
#   kern pod create <name> [--no-outbound]   create the pod (holder + shared /etc/hosts)
#   kern box <box> --pod <name> ...          join a box to the pod
#   kern pod ls                              list pods (members, up/dead)
#   kern pod rm <name>                       tear the pod down
#
# Peer-by-name is AUTOMATIC: joining a box appends "127.0.0.1  <box>" to the pod's shared
# /etc/hosts, so every member resolves every other member by name (no --add-host needed).
# Because all members SHARE one loopback, two services in a pod must use DIFFERENT ports
# (exactly like containers in a k8s pod).
#
# Outbound (internet egress) needs `pasta`/`passt` installed; --no-outbound keeps the pod
# loopback-only regardless. Intra-pod networking works either way.
set -eu
kern="${KERN:-kern}"
pod=demo-pod

cleanup() {
  "$kern" stop server client >/dev/null 2>&1 || true
  "$kern" pod rm "$pod" >/dev/null 2>&1 || true
  "$kern" gc >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "==> create a loopback-only pod (no internet egress, intra-pod networking stays on):"
"$kern" pod create "$pod" --no-outbound

echo
echo "==> join 'server': a detached box in the pod, serving HTTP on :8080:"
"$kern" box server --pod "$pod" --image alpine -d -- \
  sh -c 'while true; do printf "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello from the pod\n" | nc -lp 8080; done'
sleep 1

echo
echo "==> kern pod ls — the pod now has members:"
"$kern" pod ls

echo
echo "==> join 'client' to the same pod and reach the peer BY NAME over the shared loopback:"
"$kern" box client --pod "$pod" --image alpine -- \
  sh -c 'echo "--- resolving peer names via the shared /etc/hosts ---"; \
         grep -E "server|localhost" /etc/hosts; \
         echo "--- fetch http://server:8080/ (peer by name) ---"; \
         wget -qO- http://server:8080/ ; \
         echo "--- same service via localhost:8080 (one shared netns) ---"; \
         wget -qO- http://localhost:8080/'

echo
echo "==> the pod is isolated from the internet (--no-outbound): outbound fails, as intended:"
"$kern" box client --pod "$pod" --image alpine -- \
  sh -c 'wget -q -T3 -O- https://example.com >/dev/null 2>&1 && echo "reachable (unexpected)" || echo "no egress (expected for --no-outbound)"'

echo
echo "==> tear down (handled by the cleanup trap): kern pod rm + stop members."
# For internet egress from inside a pod, install `pasta`/`passt` and drop --no-outbound:
#   kern pod create $pod            # attaches a NAT'd egress + DNS when pasta is present
