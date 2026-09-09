#!/bin/sh
# The six runtime-parity changes, asserted on whatever host this runs on.
#
# NO IMAGE AND NO NETWORK: the rootfs is built from the host's own busybox, so this runs on a board,
# a VPS or a WSL install without pulling anything. That also makes it the right fixture for the
# `/etc` cases: the rootfs ships no `/etc` at all, so anything found there was put there by kern.
#
# usage: sh verify-parity.sh /path/to/kern
# exit 0 = every case passed, 1 = at least one failed, 2 = could not build the fixture.
set -u
KERN=${1:-kern}
command -v "$KERN" >/dev/null 2>&1 || [ -x "$KERN" ] || { echo "SKIP: $KERN not executable"; exit 2; }
BB=$(command -v busybox) || { echo "SKIP: busybox is needed to build the fixture"; exit 2; }

FAIL=0
ok()   { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
note() { printf '  note  %s\n' "$1"; }

D=$(mktemp -d) || exit 2
XDG=$D/xdg
RF=$D/rootfs
mkdir -p "$XDG" "$RF/bin" "$RF/proc" "$RF/dev" "$RF/tmp"
cp "$BB" "$RF/bin/busybox"
for l in $(ldd "$BB" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*'); do
    [ -e "$l" ] && { mkdir -p "$RF$(dirname "$l")"; cp "$l" "$RF$l" 2>/dev/null; }
done
# EVERY APPLET IS SYMLINKED, not just `sh`. Ubuntu's busybox is built with the standalone shell, so
# `cat` and `grep` resolve to applets without a link and the fixture worked there by accident; on
# Debian's build they do not, and the cases read `sh: cat: not found` as a kern failure. The harness
# must not depend on which way a distro compiled busybox.
for a in sh cat grep test true; do ln -sf busybox "$RF/bin/$a"; done
# `KERN_QUIET=1` because this harness uses a temp `XDG_RUNTIME_DIR`, which on a host whose user
# manager lives elsewhere makes kern warn that caps are not delegated. The warning is CORRECT and is
# about the fixture, not about what is being asserted, and without silencing it every assertion reads
# the warning text instead of the command's output.
B() { XDG_RUNTIME_DIR=$XDG KERN_QUIET=1 "$KERN" box "$@" 2>&1; }

echo "host:   $(uname -srm)"
echo "distro: $( . /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || echo unknown )"
echo "kern:   $("$KERN" --version 2>&1 | head -1)"
echo

# A box must start at all before any of this means anything.
if ! B smoke --rootfs "$RF" -- /bin/busybox true >/dev/null 2>&1; then
    echo "SKIP: no box starts on this host; the parity cases cannot be read"
    B smoke2 --rootfs "$RF" -- /bin/busybox true 2>&1 | head -3 | sed 's/^/       /'
    rm -rf "$D"; exit 2
fi

out=$(B ptsprobe --rootfs "$RF" -- /bin/busybox sh -c 'test -c /dev/ptmx && grep -c " /dev/pts devpts " /proc/self/mounts')
printf '%s' "$out" | grep -q '^1$' \
    && ok "devpts + /dev/ptmx in a DETACHED box (issue #8)" \
    || bad "no devpts in a detached box (got '$(printf '%s' "$out" | tr '\n' '|')')"

out=$(B mqprobe --rootfs "$RF" -- /bin/busybox sh -c 'grep -c " /dev/mqueue mqueue " /proc/self/mounts')
printf '%s' "$out" | grep -q '^1$' \
    && ok "/dev/mqueue mounted, as runc provides" \
    || bad "no /dev/mqueue (got '$(printf '%s' "$out" | tr '\n' '|')')"

out=$(B artifact --rootfs "$RF" -- /bin/busybox sh -c '
    for p in /dev/pts /dev/mqueue; do
        [ -d "$p" ] || continue
        grep -q " $p " /proc/self/mounts || { echo "BARE:$p"; exit 0; }
    done; echo CLEAN')
printf '%s' "$out" | grep -q CLEAN \
    && ok "no mountpoint exists without its mount" \
    || bad "a mountpoint exists without its mount ($out)"

out=$(B hostsprobe --rootfs "$RF" -- /bin/busybox sh -c 'cat /etc/hosts')
printf '%s' "$out" | grep -q localhost && printf '%s' "$out" | grep -q hostsprobe \
    && ok "/etc/hosts seeded: localhost and the box's own name" \
    || bad "/etc/hosts missing or does not answer ('$(printf '%s' "$out" | tr '\n' '|')')"

out=$(B hostnameprobe --rootfs "$RF" -- /bin/busybox sh -c 'cat /etc/hostname' | tr -d '\n')
[ "$out" = "hostnameprobe" ] \
    && ok "/etc/hostname names the box" \
    || bad "/etc/hostname is '$out'"

# The pod records. A host with no pod support says so instead of failing.
if XDG_RUNTIME_DIR=$XDG "$KERN" pod create vpx >/dev/null 2>&1; then
    PD=$XDG/kern/pods/vpx
    HB=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
    if [ -s "$PD/boot" ] && [ "$(cat "$PD/boot")" = "$HB" ]; then
        ok "a pod records the boot it belongs to"
    elif [ -s "$PD/boot" ] && [ "$(cat "$PD/boot")" = "unavailable" ]; then
        # RECORDING the sentinel is right; TRUSTING it is not, and this case used to bless both.
        # A reviewer varied only this file against a live stranger whose pid:starttime matched and
        # found `unavailable` was the one unknown state that authorised a kill. So the assertion is
        # no longer "the sentinel was written" but "and it refuses", which is the half that matters.
        ok "boot_id unreadable here; the pod recorded the sentinel, which now REFUSES rather than trusts"
    else
        bad "pod boot record missing or wrong ('$(cat "$PD/boot" 2>/dev/null)')"
    fi
    if [ -s "$PD/pasta.pid" ]; then
        if grep -qE '^[0-9]+:[0-9]+$' "$PD/pasta.id" 2>/dev/null; then
            ok "and its pasta by pid:starttime"
        else
            bad "pasta running but pasta.id missing/malformed ('$(cat "$PD/pasta.id" 2>/dev/null)')"
        fi
    else
        note "no pasta on this host, so there is no pasta identity to assert"
    fi
    XDG_RUNTIME_DIR=$XDG "$KERN" pod rm vpx >/dev/null 2>&1
else
    note "pod create does not work here, so the pod records are not asserted"
fi

rm -rf "$D"
echo
[ "$FAIL" -eq 0 ] && { echo "  every case passed"; exit 0; }
echo "  $FAIL case(s) failed"; exit 1
