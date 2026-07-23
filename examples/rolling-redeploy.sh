#!/bin/sh
# Zero-downtime rolling redeploy of a service fleet, daemonless. `--pull always` refreshes the image
# with an ATOMIC cache swap: boxes already running on the old rootfs are undisturbed (overlayfs pins
# the lower dir at mount time), so you bring up new instances on the fresh image and retire the old
# ones one at a time, with the fleet never dropping below its target size. No orchestrator, no root.
#
# Real-life: pushing a new `:latest` to a fleet of edge services on a Pi/Jetson with no k8s, where a
# restart-in-place would drop live connections.
set -eu
kern="${KERN:-kern}"
img="${IMG:-alpine}"
svc="rolldemo$$"

cleanup() {
  "$kern" ps -q 2>/dev/null | grep "$svc" | while read -r n; do
    "$kern" stop "$n" >/dev/null 2>&1 || true
  done
  "$kern" gc >/dev/null 2>&1 || true
}
trap cleanup EXIT

count() { "$kern" ps -q 2>/dev/null | grep -c "$svc" || true; }

echo "==> deploy v1: 3 long-lived service instances:"
for i in 1 2 3; do
  "$kern" box "${svc}-old-$i" --image "$img" -d -- sh -c 'while true; do sleep 2; done' >/dev/null
done
sleep 1
echo "    running instances: $(count)"

echo
echo "==> refresh the image in place (--pull always, atomic swap):"
echo "    the 3 live instances keep serving on their pinned rootfs THROUGHOUT."
"$kern" box --image "$img" --pull always -- true
echo "    still running during swap: $(count)  (never dropped)"

echo
echo "==> bring up v2: 3 new instances on the freshly-pulled image (overlap = zero downtime):"
for i in 1 2 3; do
  "$kern" box "${svc}-new-$i" --image "$img" -d -- sh -c 'while true; do sleep 2; done' >/dev/null
done
sleep 1
echo "    instances during overlap (old + new): $(count)"

echo
echo "==> retire v1 one at a time; the fleet stays above target the whole roll:"
for i in 1 2 3; do
  "$kern" stop "${svc}-old-$i" >/dev/null
  echo "    retired old-$i  ->  running now: $(count)"
done

echo
echo "==> roll complete: 3 instances, all on the new image, never a downtime window:"
"$kern" ps --filter "name=${svc}-new" --format '    {{.Names}}  {{.Status}}  up {{.RunningFor}}' | sort
