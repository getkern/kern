#!/bin/sh
# Two inputs that map to the SAME internal state must decide identically.
#
# `boot` absent and `boot` equal to this boot both answer `Attributable`: absence means a dir written
# before the record existed, and neither is a reason to refuse. So the two rows must agree on every
# run. An external reviewer measured them DIFFERING on WSL2 (absent -> survived, current -> killed),
# which is either non-determinism or a fixture that varied more than the one file. This runs both
# rows N times and reports the split.
set -u
KERN=${1:-target/release/kern}
N=${2:-10}
HB=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
BASE=$(mktemp -d)
SEQ=0

one() { # $1 = DELETE | a boot id value ; echoes SURVIVE or KILL
    # `$$` plus a counter, not `$RANDOM`: dash does not define it, and under `set -u` every row
    # died before running kern. The comparison then read two EMPTY results as agreement, which is
    # the false green this whole exercise is about.
    SEQ=$((SEQ + 1))
    XDG=$BASE/x$$_$SEQ
    dir=$XDG/kern/pods/eq
    mkdir -p "$dir"
    sleep 60 &
    v=$!
    st=$(sed 's/.*) //' "/proc/$v/stat" 2>/dev/null | awk '{print $20}')
    if [ -z "$st" ]; then kill -9 "$v" 2>/dev/null; echo "NOSTAT"; return; fi
    printf '%s\n' "$v" > "$dir/pasta.pid"
    printf '%s:%s\n' "$v" "$st" > "$dir/pasta.id"
    printf '999999\n' > "$dir/holder"
    [ "$1" = "DELETE" ] || printf '%s' "$1" > "$dir/boot"
    XDG_RUNTIME_DIR=$XDG "$KERN" pod rm eq >/dev/null 2>&1
    sleep 0.35
    if [ -d "/proc/$v" ] && [ "$(sed 's/.*) //' "/proc/$v/stat" 2>/dev/null | awk '{print $1}')" != "Z" ]; then
        r=SURVIVE
    else
        r=KILL
    fi
    kill -9 "$v" 2>/dev/null; wait "$v" 2>/dev/null
    rm -rf "$XDG"
    echo "$r"
}

echo "each row $N times, only the \`boot\` file varies"
for spec in "absent:DELETE" "this boot:$HB"; do
    label=${spec%%:*}; val=${spec#*:}
    s=0; k=0; o=0
    i=0
    while [ "$i" -lt "$N" ]; do
        case $(one "$val") in
            SURVIVE) s=$((s + 1)) ;;
            KILL)    k=$((k + 1)) ;;
            *)       o=$((o + 1)) ;;
        esac
        i=$((i + 1))
    done
    printf '  %-12s SURVIVE=%-3d KILL=%-3d other=%d\n' "$label" "$s" "$k" "$o"
    # A row that never ran cannot agree with anything. Without this the two states "agree" at 0/0.
    if [ "$o" -gt 0 ] || [ $((s + k)) -eq 0 ]; then
        echo "  the '$label' row did not produce a decision $o time(s); nothing is being compared"
        rm -rf "$BASE"; exit 2
    fi
    eval "res_$(echo "$label" | tr ' ' '_')=\"$s/$k\""
done
rm -rf "$BASE"
echo
if [ "$res_absent" = "$res_this_boot" ]; then
    echo "  the two states agree, as the code says they must"
    exit 0
fi
echo "  THEY DIFFER: absent=$res_absent this_boot=$res_this_boot (SURVIVE/KILL)"
exit 1
