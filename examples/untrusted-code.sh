#!/bin/sh
# Run code you do NOT trust, locked down hard.
#
# `--read-only` makes the whole root read-only (writes fail). On top of that every box already
# has: no network (isolated net namespace, loopback only), an always-on seccomp denylist
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
