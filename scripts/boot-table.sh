#!/bin/sh
# The reviewer's six-row table: a live stranger whose `pid:starttime` matches `pasta.id` exactly,
# with ONLY the `boot` file varying. Every unknown state must be conservative.
#
# The stranger is a sacrificial `sleep`, so a kill costs nothing and the result is unambiguous:
# either the process is still there afterwards or it is not.
set -u
KERN=${1:-target/release/kern}
XDG=$(mktemp -d)/xdg
mkdir -p "$XDG/kern/pods"
FAIL=0

row() {
    label=$1
    action=$2   # what the file should be set to, or DELETE
    expect=$3   # SURVIVE or KILL

    dir=$XDG/kern/pods/bt
    rm -rf "$dir"; mkdir -p "$dir"

    sleep 120 &
    victim=$!
    st=$(sed 's/.*) //' "/proc/$victim/stat" 2>/dev/null | awk '{print $20}')
    [ -n "$st" ] || { echo "  ?? could not read the stranger's start time"; kill -9 "$victim" 2>/dev/null; return; }

    # A record that WOULD authorise: the pid is named and the start time matches exactly.
    printf '%s\n' "$victim" > "$dir/pasta.pid"
    printf '%s:%s\n' "$victim" "$st" > "$dir/pasta.id"
    printf '999999\n' > "$dir/holder"
    if [ "$action" = "DELETE" ]; then rm -f "$dir/boot"; else printf '%s' "$action" > "$dir/boot"; fi

    XDG_RUNTIME_DIR=$XDG "$KERN" pod rm bt >/dev/null 2>&1
    sleep 0.4
    if [ -d "/proc/$victim" ] && [ "$(sed 's/.*) //' "/proc/$victim/stat" 2>/dev/null | awk '{print $1}')" != "Z" ]; then
        got=SURVIVE
    else
        got=KILL
    fi
    kill -9 "$victim" 2>/dev/null; wait "$victim" 2>/dev/null

    if [ "$got" = "$expect" ]; then
        printf '  ok    %-34s -> %s\n' "$label" "$got"
    else
        printf '  FAIL  %-34s -> %s (expected %s)\n' "$label" "$got" "$expect"
        FAIL=$((FAIL + 1))
    fi
}

HB=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
echo "boot record table, stranger with a MATCHING pid:starttime"
echo
# The one row that must kill: same boot, identity matches. Without it the table proves only that
# kern never kills, which is not the property under test.
row "boot = this boot_id"        "$HB"          KILL
row "boot = a different boot_id" "00000000-0000-0000-0000-000000000000" SURVIVE
row "boot = empty"               ""             SURVIVE
row "boot = 'x'"                 "x"            SURVIVE
row "boot = 'unknown'"           "unknown"      SURVIVE
# ABSENCE IS THE ONE UNKNOWN THAT MUST NOT BE CONSERVATIVE. No record means a dir written before the
# record existed, so `pod_boot` answers `Attributable` and the identity check decides on its own.
# Refusing instead would leak the pasta of every pod created before this release, which is the harm
# the record exists to prevent, inflicted by the record.
#
# A DISAGREEMENT ABOUT THIS ROW WAS TRACED AND CLOSED, and it is recorded because the wrong version
# of it was nearly committed as corroboration. An external reviewer reported SURVIVE here while this
# harness measured KILL. The cause was their harness: it took the boot value as a string with no
# unlink branch, so the sentinel `__RM__` they passed meaning "delete" was written into the record as
# six literal characters. That is an unrecognised value, which SURVIVEs correctly, exactly as `x` and
# `unknown` do. Absence was never tested on their side.
#
# Confirmed independently before the cause was known: eight fixture combinations (holder present or
# absent, trailing newline or not) across two binaries all answered KILL. `boot-equiv.sh` then showed
# absence and this-boot agreeing 12 times out of 12 on both. There was no behaviour difference to
# explain.
row "boot file deleted (legacy)"  DELETE         KILL
row "boot = 'unavailable'"       "unavailable"  SURVIVE

rm -rf "$(dirname "$XDG")"
echo
[ "$FAIL" -eq 0 ] && { echo "  every row behaved"; exit 0; }
echo "  $FAIL row(s) wrong"; exit 1
