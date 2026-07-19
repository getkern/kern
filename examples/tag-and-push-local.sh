#!/bin/sh
# Tag an image and push it to a registry - self-contained, via a local `registry:2` in a kern box.
#
#   kern tag  <src> <dst>                  give a cached image a second name
#   kern push <local-ref> [as <remote-ref>]  publish a cached image to a registry
#
# We run a throwaway Docker registry (`registry:2`) as a detached kern box, published on
# 127.0.0.1:5000. kern (like Docker) treats a LOOPBACK registry - localhost / 127.* / ::1 - as
# insecure-OK and talks plain HTTP to it automatically: there is no --tls/--insecure flag to pass,
# and none exists. (A non-loopback registry is always HTTPS + TLS-pinned, and a private one needs
# `kern login` first.) The registry's storage lives in the box's ephemeral overlay, so tearing the
# box down reclaims all pushed data.
set -eu
kern="${KERN:-kern}"
reg=127.0.0.1:5000
remote="$reg/demo/alpine:v1"

trap '"$kern" stop local-registry >/dev/null 2>&1 || true' EXIT

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsS --max-time 2 "$1" 2>/dev/null
  else wget -qO- -T 2 "$1" 2>/dev/null; fi
}

echo "==> starting a local registry (registry:2) as a detached box, published on $reg:"
"$kern" box local-registry --image registry:2 -d -p 127.0.0.1:5000:5000

echo "==> waiting for the registry to answer on http://$reg/v2/ ..."
i=0
while [ "$i" -lt 25 ]; do
  if fetch "http://$reg/v2/" >/dev/null; then break; fi
  i=$((i + 1)); sleep 1
done
[ "$i" -lt 25 ] || { echo "    (registry did not come up in time)"; exit 1; }
echo "    registry is up."

echo
echo "==> make sure we have a source image cached, then TAG it for the local registry:"
"$kern" pull alpine
"$kern" tag alpine "$remote"

echo
echo "==> PUSH it (plain HTTP to loopback - no TLS flag needed):"
"$kern" push "$remote"

echo
echo "==> drop the local copy of that ref, then PULL it back FROM the registry to prove the round-trip:"
"$kern" rmi "$remote" >/dev/null 2>&1 || true
back="$(mktemp -d)"
"$kern" pull "$remote" --dest "$back/rootfs"
echo "    pulled-back rootfs contents:"
ls "$back/rootfs" | tr '\n' ' '; echo

echo
echo "==> cleanup: stop the registry box (its data was ephemeral) and drop cached refs:"
"$kern" stop local-registry >/dev/null 2>&1 || true
"$kern" rmi "$remote" >/dev/null 2>&1 || true
rm -rf "$back"
"$kern" gc >/dev/null 2>&1 || true
echo "done - registry gone, no data left, no daemon."
