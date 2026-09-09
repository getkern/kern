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
# A case that cannot run here says so and is NOT counted as a pass. It was used before it was
# defined: the `exec -it` case calls it when `script(1)` is absent, which on a host without that
# binary would have died with "skip: not found" instead of reporting the reason.
skip() { printf '    skip  %s\n' "$1"; }

# --- the assertions, as functions, so --self-check can exercise them without starting anything ----

# A stack with no pod must never see the word "pod '<name>'" in a lifecycle line.
claims_a_pod() { printf '%s' "$1" | grep -q "pod '"; }

# "N box(es) stopped" must agree with how many were actually running before.
#
# `[0-9][0-9]*`, not `[0-9]*`, because the starred form matches the EMPTY string, so a formatting
# regression that dropped the number ("compose stop:  box(es) stopped") matched the line and
# extracted "".
#
# TIGHTER, NOT A FIX, and measured rather than assumed: both forms yield "" for that input (the
# starred one because it substitutes to nothing, this one because it does not match), so every
# assertion in this file behaves identically before and after. The count check fails either way,
# which is the correct outcome for a malformed line. The change is worth keeping because the two
# forms mean different things to the next reader, and a future caller that distinguishes "no match"
# from "matched, empty capture" would inherit the wrong one. Stated so nobody credits it with a
# behaviour change it does not have.
stopped_count() { printf '%s' "$1" | sed -n 's/.*compose stop: \([0-9][0-9]*\) box(es) stopped.*/\1/p'; }

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

# The member count out of `kern pod ls`'s table: the first row whose second field is all digits, so
# the `POD  BOXES  STATUS` header (second field `BOXES`) and the empty-table sentence both yield
# nothing rather than a number.
pod_member_count() { printf '%s' "$1" | awk '$2 ~ /^[0-9]+$/ { print $2; exit }'; }

# A compose bring-up line must say WHICH network the stack got, not only that services can find each
# other. Both halves count as stating it: having egress and not having it are both answers. The line
# that says neither is the one this checks against, because it is what shipped.
states_outbound() { printf '%s' "$1" | grep -qiE 'outbound|loopback-only'; }

# THE TWO LINES MUST NOT CONTRADICT EACH OTHER. `pod create` reports why pasta refused; the compose
# summary reports the pod's state. In v0.9.2 the second was a bool, and every false printed "install
# passt", so a user whose pasta WAS installed and refused to start read an instruction to install it
# two lines under kern's own correct sentence (#6). True when the output says both.
contradicts_install() {
    printf '%s' "$1" | grep -q 'pasta IS installed' \
        && printf '%s' "$1" | grep -q 'install `passt`'
}

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
    # THIS CORPUS CONTAINED NO FAILING-SYSTEM OUTPUT AT ALL, which an external reviewer read out of
    # the file: every string above is a success line or a crafted near-miss, so the predicates were
    # only ever exercised against a program that works. `claims_a_pod` asks whether the text NAMES a
    # pod, and an error naming the pod answers yes. Pinned here as the predicate's DOCUMENTED limit,
    # so nobody rebuilds a positive assertion on it: `compose` is captured with `2>&1`, so
    # "failed to create pod 'x'" used to satisfy "a pod is created". The one-service case reads
    # `pod ls` for that now, and these two cases are why.
    claims_a_pod "error: failed to create pod 'stack': permission denied" \
        && pass "an error naming a pod matches: this is a NAMING test, never a success test" \
        || fail "the predicate stopped matching an error that names a pod"
    claims_a_pod "compose up: pod 'stack' already exists" \
        && pass "the already-exists error matches too, and must not be read as creation" \
        || fail "the predicate stopped matching the already-exists error"
    [ "$(stopped_count 'compose stop: 2 box(es) stopped, pod ...')" = "2" ] \
        && pass "the stopped count is read out of the line" \
        || fail "the stopped count was not read"
    [ -z "$(stopped_count 'compose up: 2 box(es) started.')" ] \
        && pass "an unrelated line yields no count" \
        || fail "an unrelated line produced a count"
    [ "$(pod_member_count "$(printf 'POD    BOXES  STATUS\nstack-1    3  up\n')")" = "3" ] \
        && pass "the pod member count is read out of the table" \
        || fail "the pod member count was not read"
    [ -z "$(pod_member_count 'no pods - create one with kern pod create name')" ] \
        && pass "an empty pod table yields no count" \
        || fail "an empty pod table produced a count"
    states_outbound "pod x: services reach each other by name + outbound to the internet (pasta)." \
        && pass "an outbound line is recognised as stating the network" \
        || fail "the outbound line was not recognised"
    states_outbound "pod x: loopback-only - services reach each other; NO outbound (install passt for egress)." \
        && pass "a loopback-only line is recognised as stating the network" \
        || fail "the loopback-only line was not recognised"
    # THE NEGATIVE CONTROL, and the whole reason this assertion exists: the line that SHIPPED named
    # the pod and reported name resolution while saying nothing about egress, so a stack with no
    # internet and a stack with internet printed the same sentence. If this string ever passes
    # `states_outbound`, the assertion has stopped discriminating and every green tick below it is
    # worth nothing.
    states_outbound "pod x: services reach each other by name. tear down with kern compose f down." \
        && fail "the pre-fix silent line was read as stating the network" \
        || pass "the pre-fix silent line is not read as stating the network"
    # The v0.9.2 output that shipped, verbatim in shape: correct create line, wrong summary.
    contradicts_install "$(printf 'network: loopback-only; pasta IS installed but did not start: x\npod p: loopback-only; NO outbound (install `passt`/`pasta` for egress).\n')" \
        && pass "the contradiction between the two lines is recognised" \
        || fail "the contradiction was not recognised"
    contradicts_install "$(printf 'network: loopback-only; pasta IS installed but did not start: x\npod p: loopback-only; pasta is installed but is not running for this pod.\n')" \
        && fail "the fixed pair was read as contradicting" \
        || pass "the fixed pair is not read as contradicting"
    contradicts_install "$(printf 'network: loopback-only; NO outbound (install `passt`/`pasta` for egress)\npod p: loopback-only; NO outbound (install `passt`/`pasta` for egress).\n')" \
        && fail "a genuinely-absent pasta was read as contradicting" \
        || pass "a genuinely-absent pasta is not read as contradicting"
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
# `cat` and `grep` are here for the parity cases at the end. They were NOT here first, and the
# distro lab is what found it: Ubuntu's busybox is built with the standalone shell, so those two
# resolve to applets with no link and the cases passed on this machine by accident. On Debian 13,
# Fedora 44 and Rocky 10 the same cases read `sh: cat: not found` and reported it as a kern failure.
for a in sh nc httpd netstat cat grep; do ln -sf busybox "$RF/bin/$a"; done
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

# --- ONE SERVICE IS A STACK TOO -------------------------------------------------------------------
# Every case above runs THREE services, and so did every other compose test in this repo: the single
# `services:` in `sandbox_run.rs` points at an unreachable registry and never starts a box. So the
# one-service path had no coverage anywhere, and it shipped for the whole 0.9 line with NO NETWORK AT
# ALL. The auto-pod was gated on `boxes.len() >= 2`, because a pod's OTHER job is letting services
# find each other and one service has nobody to find. But the pod is also the only thing that
# attaches `pasta`, so a lone service got no pod, no NAT and no `/etc/resolv.conf`. It reads as a DNS
# fault and is not one: measured with the reporter's file, `curl http://1.1.1.1` failed in 0 ms.
# Filed as issue #5 by a user whose compose file had exactly one service, which is the first thing
# anyone writes.
#
# EGRESS ITSELF IS NOT ASSERTED HERE, and the omission is deliberate rather than an oversight: it
# needs `pasta` installed and a route off the host, and this script is built to run where neither is
# guaranteed. What IS asserted is the structure egress hangs off - a pod exists, and the bring-up line
# says which network the operator got - because those hold on any host that can start a box at all. A
# case that silently skips on most hosts is the green tick this matrix exists to prevent.
echo
echo "  one service: a stack of one must still get a pod"
cat > "$D/one.toml" <<TOML
[box.solo]
rootfs = "$RF"
port = 7404
command = ["/bin/busybox", "httpd", "-f", "-p", "127.0.0.1:7404", "-h", "/tmp"]
TOML
K1() { XDG_RUNTIME_DIR=$XDG "$KERN" compose "$D/one.toml" "$@" 2>&1; }
up1=$(K1 up -d)
if [ "$(running)" -ne 1 ]; then
    echo "    SKIP: the one-service stack did not come up here: $(printf '%s' "$up1" | head -1)"
else
    # THE POD MUST EXIST, and this used to ask the OUTPUT whether it did. `K1` folds stderr in
    # (`2>&1`), so `error: failed to create pod 'solo': ...` NAMES a pod, satisfied `claims_a_pod`,
    # and passed as "a pod is created". Not hypothetical for this case: #5's shape is a stack that
    # comes up with its box running and NO pod, so the `running` guard above does not exclude it,
    # and the line reporting that failure is exactly the line that names the pod.
    #
    # `claims_a_pod` is still right for the NEGATIVE usage above ("a stack with no pod must never
    # name one"), where any mention is the defect. It is the positive direction that cannot be
    # answered by the sentence.
    #
    # A keyword blacklist on the output would be the same mistake one level down: on an SELinux host
    # the SUCCESSFUL line contains "Permission denied" (pasta refused, the pod itself is fine), so
    # "does it look like an error" cannot decide this either. The pod is in `pod ls` or it is not.
    pods=$(XDG_RUNTIME_DIR=$XDG "$KERN" pod ls 2>/dev/null)
    n=$(pod_member_count "$pods")
    [ -n "$n" ] \
        && pass "one service: a pod is created (issue #5)" \
        || fail "one service: NO pod in pod ls, so no egress: $(printf '%s' "$up1" | tail -1)"
    states_outbound "$up1" \
        && pass "one service: the bring-up line states the network it got" \
        || fail "one service: the bring-up line says nothing about outbound: $(printf '%s' "$up1" | tail -1)"
    # `kern ps` and `kern pod ls` are two readers of one number and they disagreed: `pod ls` counted
    # lines in the pod's shared `hosts` file, and a compose member writes TWO of them (the qualified
    # `<pod>-<service>` and the bare alias) while a `kern box --pod` member writes one. Measured on
    # v0.9.1: 1, 2 and 3 services read 2, 4 and 6. Checked against the SERVICE COUNT, not against
    # `kern ps`, so a future change that breaks both readers the same way still fails here.
    [ "${n:-0}" = "1" ] \
        && pass "pod ls: 1 member for 1 running service" \
        || fail "pod ls: says '${n:-?}' for 1 running service"
fi
K1 down >/dev/null 2>&1
sleep 1
[ "$(live_kern_pids)" -eq 0 ] \
    && pass "one service: down leaves no kern process" \
    || fail "one service: down left $(live_kern_pids) kern process(es) alive"

# --- A WARNING A READER CAN DO NOTHING WITH IS NOISE ----------------------------------------------
# `stdin_open:` and `tty:` both printed "ignored (unsupported)", matched on the KEY rather than the
# value, so `tty: false` warned about nothing and a working daemon was told a feature was missing
# (getkern#7). A compose service is always detached, and a detached box has non-tty stdin at EOF, so
# `tty:` changes nothing kern can act on and a terminal is available through `kern exec -it` anyway.
#
# Asserted HERE and not in a Rust test because `warn` writes to stderr, which the compose crate's
# own tests cannot capture. The message text is unit-tested; its ABSENCE has to be read off a real
# run.
echo
echo "  compose: a key kern cannot act on must not produce an alarm"
cat > "$D/tty.toml" <<TOML
[box.q]
rootfs = "$RF"
command = ["/bin/busybox", "true"]
TOML
cat > "$D/tty.yml" <<YML
services:
  q:
    image: x
    tty: true
    stdin_open: false
YML
outq=$(XDG_RUNTIME_DIR=$XDG "$KERN" compose "$D/tty.yml" config 2>&1)
printf '%s' "$outq" | grep -qE "'tty:'|'stdin_open:'" \
    && fail "tty:/stdin_open: false still warn: $(printf '%s' "$outq" | grep -E "tty|stdin" | head -1)" \
    || pass "tty: true and stdin_open: false say nothing, because nothing is wrong"
# THE OTHER HALF, so this is not just an assertion that kern went quiet everywhere: the one key
# with a real consequence must still speak, and must name the service and the remedy.
cat > "$D/tty2.yml" <<YML
services:
  q:
    image: x
    stdin_open: true
YML
outq2=$(XDG_RUNTIME_DIR=$XDG "$KERN" compose "$D/tty2.yml" config 2>&1)
printf '%s' "$outq2" | grep -q "kern exec -it q" \
    && pass "stdin_open: true still states the difference and names the remedy" \
    || fail "stdin_open: true went silent too, so the noise fix silenced the signal"
# THE REMEDY MUST ANSWER THE KEY THAT WAS WRITTEN. `exec -it` answers `tty:`, and for a while it
# was the only thing offered, so a reader who wrote `stdin_open: true` alone got a PTY they had
# not asked for and nothing about stdin. Both halves are checked here because this file and the
# unit test read the same sentence: change one corpus and the other drifts.
printf '%s' "$outq2" | grep -q "as a file, an argument, or an environment variable" \
    && pass "and it says how to get input in, which is what stdin_open was asking for" \
    || fail "the note offers only the tty remedy for a stdin key"
printf '%s' "$outq2" | grep -q 'unsupported' \
    && fail "the stdin_open note still calls it unsupported" \
    || pass "and it is not phrased as a missing feature"

# THE REMEDY THE NOTE RECOMMENDS MUST WORK. `kern exec -it` is what that sentence sends people to,
# and a warning that recommends something broken is worse than the warning it replaced. The box
# under test is DETACHED, so its own stdin is /dev/null: the point is that `exec -it` allocates a
# PTY independently of that. `script` supplies the controlling terminal, without which the test
# cannot discriminate (measured: over `ssh -tt` both spellings report a TTY, because ssh already
# allocated one).
if ! command -v script >/dev/null 2>&1; then
    skip "no script(1) here, so a controlling terminal cannot be supplied to test exec -it"
else
    XDG_RUNTIME_DIR=$XDG "$KERN" box ttyprobe --rootfs "$RF" -d -- \
        /bin/busybox sh -c 'while true; do /bin/busybox sleep 5; done' >/dev/null 2>&1
    sleep 1
    noit=$(XDG_RUNTIME_DIR=$XDG "$KERN" exec ttyprobe -- \
        /bin/busybox sh -c 'test -t 0 && echo TTY || echo NOTTY' 2>/dev/null | tr -d '\r')
    isit=$(script -qec "XDG_RUNTIME_DIR=$XDG $KERN exec -it ttyprobe -- /bin/busybox sh -c 'test -t 0 && echo TTY || echo NOTTY'" /dev/null 2>/dev/null | tr -d '\r' | grep -oE '^(TTY|NOTTY)' | head -1)
    [ "$isit" = "TTY" ] \
        && pass "exec -it gives a real PTY in a detached box, so the note's remedy works" \
        || fail "exec -it did not give a PTY ('$isit'): the stdin_open note recommends a broken command"
    # The negative control, so the case is not passing on an ambient terminal: without -it the
    # same box must report no TTY.
    printf '%s' "$noit" | grep -q NOTTY \
        && pass "and without -it it is not a TTY, so the flag is what did it" \
        || fail "exec without -it also reported a TTY ('$noit'): this case cannot discriminate"
    XDG_RUNTIME_DIR=$XDG "$KERN" stop ttyprobe >/dev/null 2>&1
fi

# --- A REFUSING PASTA MUST BE REPORTED ONCE, NOT CONTRADICTED -------------------------------------
# v0.9.2 gave the compose summary its own opinion of the pod's network, derived from a BOOL. Every
# false printed "install `passt`/`pasta`", so a Fedora user whose pasta was installed and refused to
# start (SELinux, most likely) read that instruction two lines under kern's own correct "pasta IS
# installed but did not start: netns dir open: Permission denied". Reported as #6 within hours.
#
# The stub is a `pasta` that EXISTS and exits non-zero, which is the reporter's shape exactly: on
# PATH, so "not installed" is false, and refusing, so no NAT. It does not need a host where pasta
# genuinely fails, which is the only way this case could run anywhere.
echo
echo "  a refusing pasta: the summary must not tell you to install what is installed"
mkdir -p "$D/stub"
printf '#!/bin/sh\necho "netns dir open: Permission denied, exiting" >&2\nexit 1\n' > "$D/stub/pasta"
chmod +x "$D/stub/pasta"
out6=$(PATH="$D/stub:$PATH" XDG_RUNTIME_DIR=$XDG "$KERN" compose "$D/one.toml" up -d 2>&1)
# THE RETRY HAPPENED AND SAID SO. A pasta refused on the netns-directory open is retried once with
# `--no-netns-quit`, which straces show is the only open that flag removes. This stub refuses BOTH
# times, which is the case that must still report honestly: both reasons, not the second one alone,
# because the first names the operation a policy refused and the second would hide it.
if printf '%s' "$out6" | grep -q 'netns dir open'; then
    printf '%s' "$out6" | grep -q 'retried without the netns watch' \
        && pass "a netns-dir refusal is retried without the watch, and both reasons are reported" \
        || fail "the netns-dir refusal was not retried, or the retry swallowed the first reason"
else
    echo "    SKIP: the stub's refusal did not reach the reported reason"
fi
if [ "$(running)" -ne 1 ]; then
    echo "    SKIP: the stack did not come up under a refusing pasta: $(printf '%s' "$out6" | head -1)"
else
    contradicts_install "$out6" \
        && fail "the summary said to install a pasta that IS installed (#6)" \
        || pass "a refusing pasta is reported once, consistently (#6)"
    states_outbound "$out6" \
        && pass "a refusing pasta still states the network the stack got" \
        || fail "a refusing pasta left the network unstated"
fi
PATH="$D/stub:$PATH" XDG_RUNTIME_DIR=$XDG "$KERN" compose "$D/one.toml" down >/dev/null 2>&1
sleep 1

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

# ---------------------------------------------------------------------------------------------
# The "accepted but NOT enforced here" notice must follow the CGROUP, not the code path.
#
# The defect this replaces: the check read `/proc/self/cgroup`, which on the systemd-scope tier is
# the SUPERVISOR, parked in a sibling leaf of the box. Walking up from there never reaches the box's
# own leaf, so both notices fired over a box capped exactly as asked. Reported on WSL2 and reproduced
# on a Raspberry Pi 5 and a Jetson.
#
# ASSERTED ON BEHAVIOUR, not on the cgroup's numbers. An earlier version of this check compared
# `memory.max` against the requested byte count, and kern rounds a cap DOWN to a page (correctly), so
# `--memory 1000000` lands at 999424 and an equality test fails a correct binary. A 400 MB load
# against a 256 MB ceiling dying with 137 is the same claim without a number in it.
#
# MATCHED ON THE NOTICE CLASS, not per flag. Where no cgroup is delegated, kern emits ONE combined
# message covering memory and pids together, and there is no `--pids-limit accepted but NOT enforced`
# line at all; a per-flag matcher read that as silence and failed a correct binary. If you are here
# because you changed the wording of either notice, this is the matcher that reads it.
am_mem=$("$KERN" box am-cap --image alpine --memory 256m --pids-limit 8 -- \
           sh -c 'dd if=/dev/zero of=/dev/shm/f bs=1M count=400 2>/dev/null' 2>/dev/null)
am_oom=$?
am_notice=$("$KERN" box am-cap2 --image alpine --memory 256m --pids-limit 8 -- /bin/true 2>&1 |
              grep -cE "NOT enforced|could not be enforced")
"$KERN" rm am-cap am-cap2 >/dev/null 2>&1
if [ "$am_oom" -eq 137 ]; then
    if [ "$am_notice" -eq 0 ]; then
        pass "caps: a 400M load over a 256m ceiling was KILLED and kern reported no unenforced cap"
    else
        fail "caps: the ceiling KILLED the load and kern still reported a cap as unenforced"
    fi
else
    if [ "$am_notice" -gt 0 ]; then
        pass "caps: no ceiling bit here (exit $am_oom) and kern says so - correct on an undelegated host"
    else
        fail "caps: a 400M load survived a 256m cap and kern said nothing"
    fi
fi

# --- WHAT EVERY CONTAINER RUNTIME PROVIDES, AND KERN DID NOT --------------------------------------
# Five fixes whose common property is that each REVERTS INVISIBLY: none of them breaks another test
# when it regresses, and all of them would ship green. That is the whole reason they are here rather
# than only in unit tests - a gated devpts, a size-based hosts predicate or a mountpoint left behind
# by a failed mount are silent everywhere except inside a workload.
#
# `$RF` ships NO `/etc` at all (see its construction: bin, tmp, proc, dev), which is what makes it
# the right fixture: anything found under `/etc` here was put there by kern.
echo
echo "  what a container runtime provides"
# `KERN_QUIET=1`: this matrix runs under a TEMP `XDG_RUNTIME_DIR`, and on a host whose user manager
# lives at `/run/user/<uid>` that makes kern warn, correctly, that caps are not delegated to it. The
# warning is about the fixture and not about what these cases assert, and captured into `$out` it
# becomes the value every one of them reads. Found on three distros at once, for the same reason as
# the applet links above.
B() { XDG_RUNTIME_DIR=$XDG KERN_QUIET=1 "$KERN" box "$@" 2>&1; }

# devpts, in a DETACHED box. The gate this replaces was `--ssh || -it`, so the case has to be a box
# that asks for neither; under `-it` it passed before the fix too.
out=$(B ptsprobe --rootfs "$RF" -- /bin/busybox sh -c 'test -c /dev/ptmx && grep -c " /dev/pts devpts " /proc/self/mounts')
printf '%s' "$out" | grep -q '^1$' \
    && pass "a detached box has a devpts instance and a /dev/ptmx, so an in-box forkpty(3) can work" \
    || fail "no devpts in a detached box (got '$out'): issue #8 is back"

# /dev/mqueue. POSIX message queues resolve names under this mount and the C library cannot emulate
# it, so its absence is not a degraded mode, it is every mq_* call failing.
out=$(B mqprobe --rootfs "$RF" -- /bin/busybox sh -c 'grep -c " /dev/mqueue mqueue " /proc/self/mounts')
printf '%s' "$out" | grep -q '^1$' \
    && pass "and a /dev/mqueue mount, as runc provides" \
    || fail "no /dev/mqueue (got '$out')"

# THE ARTIFACT RULE, from the other side: a mountpoint must never exist without its mount. A bare
# directory at either path is the state a failed best-effort mount used to leave, and the state that
# defers the failure to the workload instead of reporting it here.
out=$(B artifact --rootfs "$RF" -- /bin/busybox sh -c '
    for p in /dev/pts /dev/mqueue; do
        [ -d "$p" ] || continue
        grep -q " $p " /proc/self/mounts || { echo "BARE:$p"; exit 0; }
    done; echo CLEAN')
if printf '%s' "$out" | grep -q CLEAN; then
    # THIS CASE DOES NOT DISCRIMINATE ON A HOST WHERE THE MOUNTS SUCCEED, and saying so is the point.
    # The artifact rule only fires when a best-effort mount is ATTEMPTED AND FAILS; where both take,
    # a binary that leaves residue and one that does not are indistinguishable here. Verified: the
    # pre-fix binary passes this case too, while failing the six around it. The branch itself is
    # covered by a unit test that mounts a filesystem type the kernel does not have
    # (`a_mount_that_does_not_take_leaves_no_mountpoint_behind`); this case guards the invariant on
    # the success path and would catch a mountpoint created without its mount.
    pass "no mountpoint exists without its mount, though on a host where both mounts SUCCEED"
    printf '          this case cannot tell the fix from its absence: the failure branch is\n'
    printf '          covered by a unit test, not here.\n'
else
    fail "a mountpoint exists without its mount ($out)"
fi

# /etc/hosts, seeded because the image ships none. The predicate is what the file ANSWERS, so the
# assertion is resolution-shaped: both localhost lines AND the box's own name.
out=$(B hostsprobe --rootfs "$RF" -- /bin/busybox sh -c 'cat /etc/hosts')
printf '%s' "$out" | grep -q 'localhost' && printf '%s' "$out" | grep -q 'hostsprobe' \
    && pass "/etc/hosts is seeded, so localhost and the box's own name resolve" \
    || fail "/etc/hosts missing or does not answer (got '$(printf '%s' "$out" | tr '\n' '|')')"

# /etc/hostname, which an image fills with the name of the machine that BUILT it.
out=$(B hostnameprobe --rootfs "$RF" -- /bin/busybox sh -c 'cat /etc/hostname')
[ "$(printf '%s' "$out" | tr -d '\n')" = "hostnameprobe" ] \
    && pass "/etc/hostname names the box, not the image's build host" \
    || fail "/etc/hostname is '$out', not the box name"

# THE POD'S OWN IDENTITY RECORDS. Cheap, and it catches the failure that matters: the file quietly
# not being written, which leaves teardown on the weaker fallback with nothing reporting it.
if XDG_RUNTIME_DIR=$XDG "$KERN" pod create amx >/dev/null 2>&1; then
    PD=$XDG/kern/pods/amx
    if [ -s "$PD/boot" ] && [ "$(cat "$PD/boot")" = "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)" ]; then
        pass "a pod records the boot it belongs to, so a dir surviving a reboot reaps nothing"
    else
        fail "the pod's boot record is missing or is not this boot"
    fi
    if [ -s "$PD/pasta.pid" ]; then
        # Only meaningful where pasta actually started; a loopback-only pod has no pasta to identify.
        if printf '%s' "$(cat "$PD/pasta.id" 2>/dev/null)" | grep -qE '^[0-9]+:[0-9]+$'; then
            pass "and its pasta by pid:starttime, so a recycled pid is not signalled"
        else
            fail "pasta is running but pasta.id is missing or malformed ('$(cat "$PD/pasta.id" 2>/dev/null)')"
        fi
    else
        skip "no pasta for this pod, so there is no identity record to assert"
    fi
    XDG_RUNTIME_DIR=$XDG "$KERN" pod rm amx >/dev/null 2>&1
else
    skip "pod create failed here, so the pod identity records cannot be asserted"
fi

rm -rf "$D"
echo
if [ "$FAIL" -eq 0 ]; then
    echo "  every case passed"
else
    echo "  $FAIL case(s) failed"
fi
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
