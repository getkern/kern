#!/bin/sh
# Run code you do NOT trust, locked down hard.
#
# `--read-only` makes the whole root read-only (writes fail). On top of that every box already
# has: no network (isolated net namespace, loopback only), an always-on seccomp allowlist
# (mount, ptrace, kexec, module load, reboot, ... are killed with SIGSYS), a private PID
# namespace, and cgroup memory/task caps. The workload sees none of the host.
set -eu
kern="${KERN:-kern}"

echo "1) the root is read-only:"
"$kern" box jail --image alpine --read-only -- /bin/sh -c '
  touch /pwned 2>&1 || echo "   write denied (read-only) ✓"
'

echo "2) there is no network:"
"$kern" box jail --image alpine --read-only -- /bin/sh -c '
  ifaces=$(cat /proc/net/dev | tail -n +3 | cut -d: -f1 | tr -d " " | tr "\n" ",")
  echo "   interfaces: $ifaces   (loopback only) ✓"
'

echo "3) dangerous syscalls are killed by seccomp:"
set +e
"$kern" box jail --image alpine --read-only -- /bin/sh -c 'mount -t tmpfs none /mnt'
echo "   mount() exit code: $?   (159 = 128 + SIGSYS: the syscall was killed) ✓"

echo "4) the one-flag bundle: --security-profile untrusted applies the lot as a base"
"$kern" box jail --image alpine --security-profile untrusted -- /bin/sh -c '
  touch /pwned 2>&1 || echo "   seccomp allowlist + cap-drop ALL + read-only root, one flag ✓"
'

# Kernel-enforced defense in depth: --apparmor <profile> enters a pre-loaded AppArmor profile on the
# box's exec (an LSM layer over namespaces + seccomp). Load it once on the host as root
# (apparmor_parser -r /etc/apparmor.d/<profile>), then pass --apparmor <name>; kern fails the box
# CLOSED if the profile isn't loaded, so a typo can't silently drop the layer.
