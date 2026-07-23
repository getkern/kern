#!/bin/sh
# `--pull missing|never|always`: control exactly when kern is allowed to touch a registry.
#
#   missing (default) - pull once if absent, then reuse forever (fast cold-start, no redundant fetch).
#   never             - air-gapped / reproducible: FAIL CLOSED if the image is not already cached,
#                       never reach the network. Locked-down CI agents, edge boxes, offline builds.
#   always            - force a fresh pull on redeploy AND swap it in atomically: a box already
#                       running on the old image keeps running, undisturbed, while new boxes get the
#                       new one. Zero-downtime image refresh, no daemon, no orchestrator.
#
# Real-life: a build farm that must never hit a registry mid-pipeline (never); a `:latest` redeploy on
# a long-lived service you cannot afford to kill (always); everyday reuse without re-pulling (missing).
set -eu
kern="${KERN:-kern}"
img="${IMG:-alpine}"
live="pullpol-live-$$"

cleanup() {
  "$kern" stop "$live" >/dev/null 2>&1 || true
  "$kern" gc >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> [missing] default policy: pull once if absent, then reuse the cache (no second fetch):"
"$kern" box --image "$img" --pull missing -- echo "    missing: ran"
"$kern" box --image "$img" --pull missing -- echo "    missing: ran again, served from cache"

echo
echo "==> [never] air-gapped determinism:"
echo "    a) an image that is NOT cached fails closed, with zero network:"
if "$kern" box --image "no-such-image-$$:latest" --pull never -- true 2>/dev/null; then
  echo "    UNEXPECTED: --pull never should have refused" >&2
  exit 1
fi
echo "    -> refused (non-zero exit), the registry was never contacted"
echo "    b) the already-cached image runs fully offline, no pull:"
"$kern" box --image "$img" --pull never -- echo "    never: ran offline from cache"

echo
echo "==> [always] zero-downtime refresh: a LIVE box survives an atomic cache swap"
"$kern" box "$live" --image "$img" -d -- \
  sh -c 'i=0; while true; do echo "live heartbeat $i"; i=$((i+1)); sleep 1; done' >/dev/null
sleep 2
echo "    box '$live' is live on the current image; now force a fresh pull of the same tag:"
"$kern" box --image "$img" --pull always -- echo "    always: fresh image pulled + atomically swapped in"
sleep 1
if "$kern" ps -q | grep -q "$live"; then
  echo "    -> the live box is STILL running across the swap"
  echo "       (overlayfs pinned its lower dir at mount time; the rename was invisible to it)"
else
  echo "    -> the live box unexpectedly disappeared across the swap" >&2
  exit 1
fi
echo "    new boxes now get the freshly-pulled image; the retired rootfs is left for 'kern gc'."
