#!/bin/sh
# --bind-rootfs: bind the rootfs directory straight in, instead of stacking an overlay on it.
#
# By DEFAULT a box roots on an overlayfs: your rootfs is the read-only lower layer and the box's
# writes land in a private upper layer that is discarded on exit (copy-on-write, nothing touches
# the source). That's the safe, isolated default.
#
# On some kernels the overlayfs mount itself is slow — notably Android/edge kernels (e.g. the ones
# under some single-board computers) where creating the overlay dominates box start-up. For those,
# --bind-rootfs binds the rootfs DIRECTORY directly as the box root and skips the overlay.
#
# The honest trade (verified in the code — see SECURITY.md / the box docs):
#   • faster start where overlayfs is the bottleneck (no overlay mount to set up).
#   • the rootfs is MUTABLE and SHARED, not copy-on-write: the box writes straight into your
#     source directory, and two boxes on the same dir see each other's writes. Nothing is
#     discarded on exit.
#   • it is writable-only: kern REJECTS `--bind-rootfs --read-only` (a read-only bind remount is
#     denied on the very kernels where the bind helps), and REJECTS `--bind-rootfs --image`
#     (a pulled --image must stay an immutable, shareable overlay). So it needs a real --rootfs dir.
#
# This example pulls a tiny image into a throwaway directory, uses it as a bind rootfs, and shows
# that a write inside the box lands in the host directory (i.e. NOT copy-on-write). Fully rootless,
# self-cleaning.
set -eu
kern="${KERN:-kern}"
img="${IMG:-alpine}"

work="$(mktemp -d)"
rootfs="$work/rootfs"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM

echo "==> materialising a rootfs directory (pulling $img into $rootfs):"
"$kern" pull "$img" --dest "$rootfs" >/dev/null
echo "   done."

echo
echo "── 1. the guard rails (both are refused — bind mode is writable-only, needs a --rootfs dir):"
set +e
"$kern" box br-ro --rootfs "$rootfs" --bind-rootfs --read-only -- true 2>&1 | sed 's/^/   /'
"$kern" box br-img --image "$img" --bind-rootfs -- true 2>&1 | sed 's/^/   /'
set -e

echo
echo "── 2. a box on the bind rootfs writes STRAIGHT INTO the host directory (not copy-on-write):"
"$kern" box br-write --rootfs "$rootfs" --bind-rootfs -- \
  sh -c 'echo "written from inside the box" > /marker.txt; echo "   wrote /marker.txt inside the box"'
if [ -f "$rootfs/marker.txt" ]; then
  echo "   host sees $rootfs/marker.txt -> \"$(cat "$rootfs/marker.txt")\""
  echo "   => the write persisted in the source dir: bind rootfs is SHARED, not COW."
else
  echo "   (marker not found on host — unexpected for a bind rootfs)"
fi

echo
echo "── 3. contrast: the DEFAULT overlay root discards the box's writes (source stays pristine):"
"$kern" box br-overlay --rootfs "$rootfs" -- \
  sh -c 'echo x > /ephemeral.txt; echo "   wrote /ephemeral.txt inside an OVERLAY box"'
if [ -f "$rootfs/ephemeral.txt" ]; then
  echo "   host sees /ephemeral.txt (unexpected — overlay should have discarded it)"
else
  echo "   host does NOT see /ephemeral.txt — the overlay upper was discarded on exit ✓"
fi

echo
echo "done — bind-rootfs = fast + shared/mutable; overlay (default) = isolated + copy-on-write."
echo "Everything here lived in a temp dir and is now removed."
