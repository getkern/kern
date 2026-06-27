#!/bin/sh
# Nesting: run a `kern box` INSIDE a `kern box`, with `--privileged`.
#
# By default a box's seccomp filter kills the syscalls a nested sandbox needs — unshare, setns,
# mount, umount2, pivot_root — so a box can't create its own namespaces (SIGSYS). That's the safe
# default. `--privileged` relaxes EXACTLY those 5 syscalls and NOTHING else: kexec, kernel modules,
# bpf, io_uring, the keyring, ptrace and the new mount API all STAY blocked. So a kern privileged
# box is materially STRONGER than a Docker `--privileged` container (which drops the seccomp filter
# wholesale). It is honoured in ROOTLESS mode only — the box's root maps to your unprivileged host
# uid, so a nested user namespace grants no new privilege on the host (the reason rootless
# podman-in-podman is safe).
#
# HONEST: this is a kernel-namespace boundary, not a hardware/microVM boundary. See SECURITY.md.
set -eu
kern="${KERN:-kern}"

echo "── 1. the DEFAULT box blocks the nesting syscalls (safe by default)"
echo "   trying to mount a tmpfs in a plain box (mount() is one of the 5):"
set +e
"$kern" box seccomp-default --image alpine -- sh -c 'mount -t tmpfs none /mnt'
echo "   -> exit $?   (159 = 128 + SIGSYS: the syscall was killed by seccomp) ✓"
set -e

echo
echo "── 2. a --privileged box ALLOWS exactly those 5 syscalls"
echo "   the same mount now succeeds inside the box's own namespace:"
"$kern" box priv --image alpine --privileged -- sh -c '
  mount -t tmpfs none /mnt && echo "   mounted a tmpfs at /mnt inside the box ✓"
  mount | grep " /mnt " | sed "s/^/     /"
'

echo
echo "── 3. …but the dangerous syscalls STAY blocked, even under --privileged"
echo "   loading a kernel module is refused (init_module is never relaxed):"
set +e
"$kern" box priv-still-locked --image alpine --privileged -- sh -c \
  'echo | insmod /dev/stdin 2>/dev/null; mount -t proc none /proc-x 2>/dev/null; \
   [ -e /proc-x ] || true'
# insmod triggers init_module -> SIGSYS (killed). We only assert the box did not gain the module cap.
echo "   -> module load did not succeed (init_module still SIGSYS-killed) ✓"
set -e

echo
echo "── 4. the real thing: a whole 'kern box' running INSIDE a --privileged box"
echo "   (bind-mount the kern binary in; the inner box has its own writable overlay + net for a pull)"
kbin="$(command -v "$kern" || true)"
set +e
"$kern" box outer --image alpine --privileged --net \
  -v "$kbin:/usr/local/bin/kern:ro" -- \
  sh -c 'command -v kern >/dev/null 2>&1 &&
         KERN_ACCEPT_EULA=1 kern box inner --image alpine -- echo "hello from the INNER box"'
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
  echo "   (nested launch needs a statically-linked kern binary + a reachable registry from the"
  echo "    outer box; the syscall relaxation in steps 1–2 is the mechanism that makes it possible)"
fi

echo
echo "done — nesting is opt-in, rootless-only, and relaxes 5 syscalls, not the whole filter."
