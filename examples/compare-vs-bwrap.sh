#!/bin/sh
# kern vs bubblewrap. Both are fast, rootless, daemonless sandboxes — but bwrap is a *primitive*:
# you bring your own root filesystem and assemble flags. kern pulls an OCI image, runs it in a
# writable overlay, and gives you lifecycle (ps/exec/logs/stop) on top.
set -eu
kern="${KERN:-kern}"

echo "==> kern: name an image, get an isolated writable box — one line:"
"$kern" box demo --image alpine -- sh -c 'echo "  $(. /etc/os-release; echo $PRETTY_NAME), uid=$(id -u)"'

echo
if command -v bwrap >/dev/null 2>&1; then
  echo "==> bwrap: you must first provide a root filesystem, then spell out the isolation:"
  echo "    (no image pull, no overlay, no ps/exec/logs — those are kern's job)"
  rootfs="$(mktemp -d)"; trap 'rm -rf "$rootfs"' EXIT
  # bwrap needs an existing rootfs; borrow the host's /usr+/bin just to run busybox/echo.
  bwrap --unshare-all --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib \
        --ro-bind /lib64 /lib64 --proc /proc --dev /dev \
        sh -c 'echo "  ran under bwrap, uid=$(id -u) — but I had to hand it a rootfs + 6 flags"' \
    2>/dev/null || echo "  (bwrap run skipped)"
else
  echo "==> bwrap not installed — kern needs no such primitive, it is the whole tool."
fi

echo
echo "Same speed class (see BENCHMARKS.md); kern adds images, overlay, and lifecycle."
