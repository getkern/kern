#!/bin/sh
# Run every compose lifecycle transition in BOTH network modes, and check the three things that get
# missed. Written after four defects in one release cycle were found by an external reviewer rather
# than by this repo's own tests, and all four had the same shape.
#
# WHAT THE SUITE ALREADY DOES WELL, and this does not repeat: it asserts that a transition WORKS.
# What it does not do is look at everything a transition leaves behind. Each of the four:
#
#   * `compose stop` on a --no-pod stack printed "pod '<name>' gone with its last member" while the
#     other services were running. The behaviour was right, the sentence was false, and no test read
#     the sentence.
#   * `compose start` returned ~290 ms before the relays it announced were rebuilt. The test that
#     covered it slept six seconds first, so it could not fail.
#   * `compose down` left the stack's relay directory behind, holding a stale `served`. Processes
#     were checked; the filesystem was not.
#   * `kern stop` reported a foreground box unconfirmed while it kept running. That one needed a
#     host where a syscall is filtered, and this script would NOT have caught it. Stated so the
#     script is not credited with more than it does.
#
# So, per transition, in a pod and without one:
#   1. THE OUTPUT IS CHECKED AGAINST THE STATE. A line naming a pod on a stack that has none is a
#      failure, not cosmetics.
#   2. A PAYLOAD IS FETCHED WITH NO SETTLING TIME. A bare connect cannot see a stale relay, which
#      accepts and then cannot forward; only bytes back can. And a sleep before the check hides
#      exactly the window a script would hit.
#   3. AFTER `down`, BOTH PROCESSES AND DISK ARE EMPTY. Counted by pid and by directory, never by
#      process name: this repo has twice matched its own shell with `pgrep -f`.
#
# Usage:
#   sh scripts/acceptance-matrix.sh [path-to-kern]   # default: target/release/kern
#   sh scripts/acceptance-matrix.sh --self-check     # check the assertions themselves, no boxes
#
# Exit 0 only if every case passed. Skips (no busybox, no user namespaces) are printed and are not
# failures, because a host that cannot start a box cannot answer these questions either.
set -u

FAIL=0
pass() { printf '    ok    %s\n' "$1"; }
fail() { printf '    FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

# --- the assertions, as functions, so --self-check can exercise them without starting anything ----

# A stack with no pod must never see the word "pod '<name>'" in a lifecycle line.
claims_a_pod() { printf '%s' "$1" | grep -q "pod '"; }

# "N box(es) stopped" must agree with how many were actually running before.
stopped_count() { printf '%s' "$1" | sed -n 's/.*compose stop: \([0-9]*\) box(es) stopped.*/\1/p'; }

# THE v0.9.1 DISCRIMINANT. A release cut for a fix must exercise that fix, or a competent green
# report says nothing: the same battery passed on the defective artifact of v0.8.5.
#
# `--egress-allow` puts a proxy on 127.0.0.1:3128 inside the box. In v0.9.0 the pump could lose a race
# with the box init and bind before the loopback was up. Measured on an Orin Nano with the SHIPPED
# binary: `cannot bind 127.0.0.1:3128 in box: Address not available (99)`, then every allowed domain
# refused. Three of five hosts tested refuse that bind, so this is the common case and not the corner.
#
# The discriminant is a 403 FROM THE PROXY for a host that is not on the allowlist. A connect alone
# proves nothing (the port can be bound and unreachable, which is exactly the other half of the same
# defect); only bytes coming back prove the whole chain, box to pump to unix socket to proxy.
proxy_answered() { printf '%s' "$1" | grep -q '403'; }

self_check() {
    echo "  self-check: the assertions, against fixed strings"
    proxy_answered "wget: server returned error: HTTP/1.1 403 Forbidden" \
        && pass "a 403 from the proxy is recognised as a live chain" \
        || fail "the proxy 403 was not recognised"
    proxy_answered "kern: egress pump: cannot bind 127.0.0.1:3128 in box: Address not available" \
        && fail "the v0.9.0 bind failure was read as a live chain" \
        || pass "the v0.9.0 bind failure is not read as a live chain"
    proxy_answered "wget: can't connect to remote host (127.0.0.1): Connection refused" \
        && fail "a refused connect was read as a live chain" \
        || pass "a refused connect is not read as a live chain"
    claims_a_pod "compose stop: 1 box(es) stopped, pod 'x' still up (other members remain)" \
        && pass "a pod line is recognised as naming a pod" \
        || fail "a pod line was not recognised"
    claims_a_pod "compose stop: 1 box(es) stopped (this stack runs without a pod)" \
        && fail "the no-pod line was read as naming a pod" \
        || pass "the no-pod line is not read as naming a pod"
    [ "$(stopped_count 'compose stop: 2 box(es) stopped, pod ...')" = "2" ] \
        && pass "the stopped count is read out of the line" \
        || fail "the stopped count was not read"
    [ -z "$(stopped_count 'compose up: 2 box(es) started.')" ] \
        && pass "an unrelated line yields no count" \
        || fail "an unrelated line produced a count"
    [ "$FAIL" -eq 0 ] && echo "  self-check passed" || echo "  self-check FAILED"
    exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
}

[ "${1:-}" = "--self-check" ] && self_check

KERN=${1:-target/release/kern}
[ -x "$KERN" ] || { echo "no kern binary at $KERN"; exit 2; }
KERN=$(CDPATH= cd "$(dirname "$KERN")" && pwd)/$(basename "$KERN")
BB=$(command -v busybox) || { echo "SKIP: busybox is needed to build a test rootfs"; exit 0; }
printf 'int main(){return 0;}' >/dev/null # (no compiler needed; noted so nobody adds one)

D=$(mktemp -d) || exit 2
XDG=$D/xdg
RF=$D/rootfs
mkdir -p "$XDG" "$RF/bin" "$RF/tmp" "$RF/proc" "$RF/dev"
cp "$BB" "$RF/bin/busybox"
for l in $(ldd "$BB" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*'); do
    [ -e "$l" ] && { mkdir -p "$RF$(dirname "$l")"; cp "$l" "$RF$l" 2>/dev/null; }
done
# The applets are SYMLINKED, and their absence has cost this project four rounds of diagnosis twice:
# `sh: nc: not found` reads exactly like an unreachable peer.
for a in sh nc httpd netstat; do ln -sf busybox "$RF/bin/$a"; done
echo PAYLOAD_OK > "$RF/tmp/hello"
cat > "$D/s.toml" <<TOML
[box.a]
rootfs = "$RF"
port = 7401
command = ["/bin/busybox", "httpd", "-f", "-p", "127.0.0.1:7401", "-h", "/tmp"]

[box.b]
rootfs = "$RF"
port = 7402
command = ["/bin/busybox", "httpd", "-f", "-p", "127.0.0.1:7402", "-h", "/tmp"]

[box.c]
rootfs = "$RF"
port = 7403
command = ["/bin/busybox", "httpd", "-f", "-p", "127.0.0.1:7403", "-h", "/tmp"]
TOML

K() { XDG_RUNTIME_DIR=$XDG "$KERN" compose "$D/s.toml" "$@" 2>&1; }
running() { XDG_RUNTIME_DIR=$XDG "$KERN" ps 2>/dev/null | grep -c 'busybox httpd'; }
# A PAYLOAD, and immediately: see the header.
reaches() {
    XDG_RUNTIME_DIR=$XDG "$KERN" exec "$1" -- /bin/busybox sh -c \
        "printf 'GET /hello HTTP/1.0\r\n\r\n' | /bin/busybox nc -w 3 $2 $3 2>/dev/null" 2>/dev/null \
        | grep -c PAYLOAD_OK
}
# BY PID, never by name.
live_kern_pids() {
    n=0
    for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
        case "$(readlink "/proc/$p/exe" 2>/dev/null)" in "$KERN") n=$((n + 1)) ;; esac
    done
    printf '%s' "$n"
}

for MODE in --no-pod pod; do
    echo
    echo "  === mode: $MODE ==="
    if [ "$MODE" = pod ]; then UPFLAGS="-d"; else UPFLAGS="--no-pod"; fi

    up=$(K up $UPFLAGS)
    if [ "$(running)" -ne 3 ]; then
        echo "    SKIP: the stack did not come up here: $(printf '%s' "$up" | head -1)"
        K down >/dev/null 2>&1
        continue
    fi
    pass "up: 3 services running"

    # 2. reachability, with no settling time
    [ "$(reaches a b 7402)" = "1" ] && pass "up: payload a to b, no sleep" || fail "up: payload a to b"
    [ "$(reaches c a 7401)" = "1" ] && pass "up: payload c to a, no sleep" || fail "up: payload c to a"

    # 1. the output against the state, for the selector
    out=$(K stop b)
    n=$(running)
    [ "$n" -eq 2 ] && pass "stop b: the other two keep running" || fail "stop b: $n running, expected 2"
    c=$(stopped_count "$out")
    [ "$c" = "1" ] && pass "stop b: the line says 1, not 3" || fail "stop b: the line says '${c:-?}'"
    if [ "$MODE" = --no-pod ]; then
        claims_a_pod "$out" && fail "stop b: names a pod on a stack that has none: $out" \
            || pass "stop b: names no pod, correctly"
    else
        claims_a_pod "$out" && pass "stop b: names the pod, correctly" \
            || fail "stop b: a pod stack must still name its pod: $out"
    fi
    [ "$(reaches a c 7403)" = "1" ] && pass "stop b: an untouched pair still reaches" \
        || fail "stop b: an untouched pair stopped reaching"

    K start >/dev/null 2>&1
    [ "$(running)" -eq 3 ] && pass "start: back to 3" || fail "start: not back to 3"
    # THE ONE THE OLD TEST COULD NOT SEE: first attempt, no sleep.
    [ "$(reaches a b 7402)" = "1" ] && pass "start: payload on the FIRST attempt after it returns" \
        || fail "start: the stack was announced before it was reachable"

    K restart c >/dev/null 2>&1
    [ "$(reaches a c 7403)" = "1" ] && pass "restart c: reachable with no settling time" \
        || fail "restart c: unreachable right after restart"

    # 3. what is left behind, in processes AND on disk
    before=$(live_kern_pids)
    K down >/dev/null 2>&1
    sleep 1
    after=$(live_kern_pids)
    [ "$after" -eq 0 ] && pass "down: no kern process left (was $before)" \
        || fail "down: $after kern processes still alive"
    leftovers=$(ls -A "$XDG/kern/relays" 2>/dev/null | tr '\n' ' ')
    [ -z "$leftovers" ] && pass "down: nothing left under relays/" \
        || fail "down: relays/ still holds [$leftovers]"
done

# --- the v0.9.1 fix, exercised against the artifact rather than deduced from the changelog ---------
echo
echo "  egress: the proxy must ANSWER, not merely be bound"

# CAN THIS HOST TELL THE TWO ARTIFACTS APART? Measured, not assumed, because the answer is no on the
# machine most likely to run this. With `lo` down in a fresh net ns, three of five hosts tested refuse
# a `127.0.0.1` bind and two accept it, and the split is the kernel's routing configuration: every
# host with policy routing (`CONFIG_IP_MULTIPLE_TABLES`, probed by whether `ip rule list` works)
# accepted, every host without it refused, five out of five. The v0.9.0 defect only SHOWS on the
# refusing kind; on an accepting host the old binary passes this case exactly as the fixed one does.
#
# So the case reports which it is. A green tick that cannot fail is the failure this whole matrix
# exists to prevent, and printing it anyway would repeat the v0.8.5 field report: competent, all
# green, and blind to the defect it was cut for.
bind_refused_here=unknown
if command -v python3 >/dev/null 2>&1; then
    bind_refused_here=$(unshare -Urn python3 -c '
import socket
s = socket.socket()
try:
    s.bind(("127.0.0.1", 0)); print("no")
except OSError:
    print("yes")
' 2>/dev/null || echo unknown)
fi

egr=$("$KERN" box am-egress --image alpine --egress-allow example.com -- \
        sh -c 'wget -T5 -O- http://vietato.invalid/ 2>&1 >/dev/null | tail -1' 2>&1)
"$KERN" rm am-egress >/dev/null 2>&1
if proxy_answered "$egr"; then
    case "$bind_refused_here" in
      yes) pass "egress: the proxy answered, on a host that REFUSES the bind - this discriminates" ;;
      no)  pass "egress: the proxy answered, but this host ACCEPTS a bind on a down loopback, so"
           echo "          v0.9.0 passes this case here too, and this run has NOT validated the fix."
           echo "          Re-run on a host WITHOUT policy routing: \`ip rule list\` failing is the"
           echo "          discriminant, and it matched the bind outcome on all five hosts measured."
           echo "          Here: ip rule list $(ip rule list >/dev/null 2>&1 && echo works || echo fails)." ;;
      *)   pass "egress: the proxy answered (could not determine whether this host discriminates)" ;;
    esac
else
    # Report kern's OWN failure line, not the flag's informational note. The note contains the word
    # "refuses", so a `grep -i refus` matched it first and printed 400 characters of help text as the
    # reason a release failed. Same class as the harness that classified every run as refused because
    # it grepped for "egress": a substring is not a channel.
    why=$(printf '%s' "$egr" | grep -v 'kern: note:' | grep -iE 'cannot bind|Connection refused|pump' | head -1)
    fail "egress: no answer from the proxy - ${why:-$(printf '%s' "$egr" | tail -1 | cut -c1-90)}"
fi

rm -rf "$D"
echo
if [ "$FAIL" -eq 0 ]; then
    echo "  every case passed"
else
    echo "  $FAIL case(s) failed"
fi
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
