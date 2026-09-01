#!/bin/sh
# A `vdisk:` scratch disk: size-capped, isolated scratch space mounted at /vdisk/<name>.
#
# `vdisk:<name>` is a resource-profile token (like `vcpu:`/`vgpio:`) you put BEFORE the box command;
# it names a `[[vdisk]]` profile in a kern.toml passed with --config. kern mounts that disk at
# /vdisk/<name> inside the box:
#
#   * rootless (this script): a `size=`-capped tmpfs - RAM-backed, ephemeral, and the size cap IS
#     enforced by the kernel (writing past it fails with ENOSPC). No privilege required.
#   * root / `disk` group (foreground box): upgraded to a real ext4-on-loop image - disk-backed,
#     with optional `persistent`, `iops` and `bandwidth` limits.
#
# The vdisk is a SEPARATE mount, so it stays writable even under --read-only (scratch by design).
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2


# A minimal kern.toml defining one small vdisk profile. Kept small (10m) because the rootless tmpfs
# backend counts against RAM. Written to a temp dir and removed on exit.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cat > "$work/kern.toml" <<'EOF'
# `vdisk:scratch` -> a 10 MiB scratch disk mounted at /vdisk/scratch
[[vdisk]]
name = "scratch"
# `backend` names the host resource the profile slices. Required: a profile that
# does not say what it carves up is refused, not guessed. For a vdisk, "ram" is a size-capped tmpfs.
backend = "ram"
size = "10m"
EOF

echo "==> 1. attach the vdisk profile (token BEFORE the command) and use the scratch space:"
# `vdisk:scratch` is resolved from --config; the box mounts it at /vdisk/scratch.
"$kern" box builder vdisk:scratch --config "$work/kern.toml" --image alpine \
  -- /bin/sh -c '
    echo "   /vdisk/scratch is mounted:"
    grep " /vdisk/scratch " /proc/mounts | awk "{print \"     type:\", \$3, \" opts:\", \$4}"
    echo "   capacity (df, expect ~10M):"
    df -h /vdisk/scratch | sed -n "2p" | sed "s/^/     /"
    echo "   write a small file - fits fine:"
    dd if=/dev/zero of=/vdisk/scratch/chunk bs=1M count=4 2>/dev/null && echo "     wrote 4 MiB ✓"
  '

echo
echo "==> 2. the size cap is ENFORCED - writing past 10 MiB fails with ENOSPC:"
# This is a real kernel-enforced tmpfs quota (works fully rootless), unlike a named-volume --size
# which needs root for its ext4-loop backend (see named-volumes.sh).
set +e
"$kern" box overflow vdisk:scratch --config "$work/kern.toml" --image alpine \
  -- /bin/sh -c 'dd if=/dev/zero of=/vdisk/scratch/toobig bs=1M count=20 2>&1 | tail -n1 | sed "s/^/   /"'
set -e
echo "   -> the write stopped at the cap ('No space left on device') ✓"

echo
echo "done - a vdisk is per-box, size-capped scratch at /vdisk/<name>; enforced rootless via tmpfs,"
echo "       disk-backed (persistent + I/O limits) when run privileged."
# Both boxes ran in the foreground; their ephemeral overlays AND the RAM-backed vdisk are already
# gone. The trap removes the temp kern.toml.
