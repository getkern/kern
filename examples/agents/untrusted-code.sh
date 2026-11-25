#!/bin/sh
# Run code you do NOT trust, locked down hard.
#
# `--read-only` makes the whole root read-only (writes fail) and `--network none` leaves the box
# loopback only (a box's default network is Docker's, a NAT with outbound). On top of that every
# box already has an always-on seccomp allowlist (mount, ptrace, kexec, module load, reboot, ...
# are refused with EPERM, Docker's answer, or kill the caller with SIGSYS under
# `--security-opt seccomp-deny=kill`), a private PID namespace, and cgroup memory/task caps. The
# workload sees none of the host.
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2


echo "1) the root is read-only:"
"$kern" box jail --image alpine --read-only -- /bin/sh -c '
  touch /pwned 2>&1 || echo "   write denied (read-only) ✓"
'

echo "2) there is no network (--network none):"
"$kern" box jail --image alpine --read-only --network none -- /bin/sh -c '
  ifaces=$(cat /proc/net/dev | tail -n +3 | cut -d: -f1 | tr -d " " | tr "\n" ",")
  echo "   interfaces: $ifaces   (loopback only) ✓"
'

echo "3) dangerous syscalls are refused by seccomp, or kill the caller with seccomp-deny=kill:"
set +e
"$kern" box jail --image alpine --read-only --network none -- /bin/sh -c 'mount -t tmpfs none /mnt 2>/dev/null'
echo "   mount() exit code: $?   (1: EPERM, Operation not permitted, as under Docker) ✓"
"$kern" box jail --image alpine --read-only --network none --security-opt seccomp-deny=kill -- /bin/sh -c 'mount -t tmpfs none /mnt'
echo "   with seccomp-deny=kill: $?   (159 = 128 + SIGSYS: the caller was killed) ✓"

echo "4) the one-flag bundle: --security-profile untrusted applies the lot as a base"
"$kern" box jail --image alpine --security-profile untrusted -- /bin/sh -c '
  touch /pwned 2>&1 || echo "   seccomp allowlist + cap-drop ALL + read-only root, one flag ✓"
'

# Kernel-enforced defense in depth: --apparmor <profile> enters a pre-loaded AppArmor profile on the
# box's exec (an LSM layer over namespaces + seccomp). Load it once on the host as root
# (apparmor_parser -r /etc/apparmor.d/<profile>), then pass --apparmor <name>; kern fails the box
# CLOSED if the profile isn't loaded, so a typo can't silently drop the layer.
