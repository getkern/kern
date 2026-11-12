#!/bin/sh
# EVERYTHING CI WILL SAY, SAID HERE FIRST, IN ABOUT TEN SECONDS.
#
# WHY THIS EXISTS, measured. The local checks were never the expensive part: the whole fast set
# below costs ~9 s, while ONE round of CI costs ~6.5 minutes. One session spent five red rounds -
# about 33 minutes of waiting - finding one defect per push, and not one of them needed a runner to
# be found. The cost is not running checks, it is learning about a defect from CI.
#
#   sh scripts/pre-push.sh          fast set + both bindings, ~45 s: run it as often as you like
#   sh scripts/pre-push.sh --full   + the integration suite, ~75 s: run it before a push
#
# The fast set grew from ~9 s to ~45 s when the binding suites were added, and that is a trade made
# with a number: they were absent, a binding change went green here and red on CI in two jobs, and
# one CI round costs ~9 minutes of waiting. 36 seconds against 9 minutes.
#
# BARE EXIT CODES, never a pipe: a gate whose status is swallowed by `| tee` reports success it did
# not earn.

set -u
cd "$(dirname "$0")/.." || exit 2
FULL=0
[ "${1:-}" = "--full" ] && FULL=1
fail=0

# INTEGER ARITHMETIC, NOT `%f`, and the reason is not pedantry. The first version handed printf a
# string like `1234e-3` for a `%5.1f`, which dash renders `1.2s` and bash under an Italian locale
# renders `1,2s`: a gate whose output changes with the operator's language. The decimal is built from
# whole milliseconds here, so every shell and every locale print the same characters.
elapsed() { printf '%d.%01d' "$(( $1 / 1000 ))" "$(( ($1 % 1000) / 100 ))"; }

step() {
    name=$1; shift
    t0=$(date +%s%N)
    if "$@" >/tmp/prepush.log 2>&1; then
        printf '  \033[32mok\033[0m   %-38s %5ss\n' "$name" "$(elapsed "$(( ($(date +%s%N)-t0)/1000000 ))")"
    else
        printf '  \033[31mFAIL\033[0m %-38s %5ss\n' "$name" "$(elapsed "$(( ($(date +%s%N)-t0)/1000000 ))")"
        sed 's/^/       /' /tmp/prepush.log | tail -25
        fail=1
    fi
}

# THE ORDER IS CHEAPEST-FIRST so the fastest thing that can be wrong says so first.
step "fmt"                     cargo fmt --all --check
# EVERY CRATE, NOT JUST THE BINARY. `-p getkern --bin kern` ran 717 tests and the workspace has
# 1199: the 482 it never saw are the parsers - kern-compose, kern-oci, kern-common, kern-isolation -
# and CI runs `cargo test --all`, so this file's promise to say what CI will say did not hold for
# any of them. Measured warm: 2.1s for the binary alone, 12.3s for the workspace. Ten seconds
# against the 6.5 minutes of the CI round they prevent is the trade this whole file argues for.
# `--lib --bins` keeps the integration suite out; it is what `--full` adds.
step "unit tests"              cargo test -q --workspace --lib --bins
# The runner executes as an ordinary user inside a cgroup it cannot write. A developer shell sits in
# its own delegated scope, so every assertion that assumes "a process may enter its own cgroup"
# passes here and fails there. This runs the unit tests in THAT shape. STILL JUST THE BINARY: the
# shape being reproduced is a cgroup one, and the crates above do not touch a cgroup.
step "unit tests, CI host shape" sh scripts/as-ci-host.sh cargo test -q -p getkern --bin kern
# THE LABEL SAID `-D warnings` AND THE COMMAND DID NOT SET IT. Measured: a `bool_assert_comparison`
# in a new test printed as a WARNING here and this script exited 0 and said "green: this is what CI
# will say"; run #863 then failed clippy on both x86 and aarch64, because the CI job exports
# `RUSTFLAGS: -D warnings` and this did not. `gate.sh` says why in its own header - a
# clippy that passes is not evidence - and this file, whose entire promise is to say what CI will
# say, was the one place the flag was missing. The flags now match CI exactly, `--all-features` and
# the debug profile included: a different profile is a different cache and can be a different lint.
step "clippy -D warnings"      env RUSTFLAGS="-D warnings" cargo clippy --all-targets --all-features
for g in no-ai-slop stale-numbers docker-vocabulary md-links flat-continuation \
         test-env-lock progress-is-tty-gated injection-declared registry-classified \
         tracked-paths-sane readme-blocks-complete og-card-matches-readme; do
    step "$g" python3 "scripts/$g.py"
done
# NO SEPARATE EM-DASH STEP, and the reason is the whole point of this file. The first version had
# one, spelled `grep --include="*.md"`, and it was WEAKER than the gate it paraphrased: `no-ai-slop`
# scans every tracked file for that character, not just markdown. So this script passed itself green
# while carrying an em-dash in this very line, and CI - which runs the real gate - went red. A fast
# script that RESTATES a check will drift below it and hand out false greens; it must CALL it. Every
# step above is the same script CI runs, by name.
#
# IT READS WHAT GIT TRACKS, so `git add` your new files before trusting a green from it. An
# untracked file is invisible to these gates and to CI alike, right up to the commit that adds
# it. Verified both ways: an em-dash in a staged `.sh` and in a tracked `.rs` each turn this red.

# THE BINDINGS, AND IN THE CONDITION CI HAS, because this file promised "everything CI will say" and
# said nothing at all about them. MEASURED: a change to the Python and Node bindings went green here
# and RED on CI in both `python binding (3.9)` and `(3.12)`, on a test that constructed a `Sandbox`
# directly - the constructor verifies a kern binary, and a runner has none while this machine has one
# on `$PATH`. So the gap was not only "the suite was not run", it was "it would have passed anyway
# here": a check that runs in the wrong condition does not check anything.
#
# `env -u KERN_BIN PATH=/usr/bin:/bin` is that condition, spelled once. It makes the integration tests
# SKIP, exactly as they do on CI, and leaves the several hundred unit tests that caught this. The full
# suites with a real kern are still worth running by hand; what belongs in a pre-push gate is the
# shape CI will actually see.
bindings_python() {
    [ -d bindings/python/tests ] || return 0
    ( cd bindings/python && env -u KERN_BIN PATH=/usr/bin:/bin python3 -m pytest -q ) || return 1
}
# EVERY test file, by glob: a gate that names one file leaves the next one out without a word, and CI
# runs no Node binding suite at all, so this is the only place they run.
bindings_node() {
    ls bindings/node/test/*.test.js >/dev/null 2>&1 || return 0
    command -v node >/dev/null || return 0
    ( cd bindings/node && env -u KERN_BIN node --test test/*.test.js ) || return 1
}
step "python binding, CI shape" bindings_python
step "node binding"            bindings_node

if [ "$FULL" -eq 1 ]; then
    step "integration suite" cargo test -q -p getkern
fi

# THE GPU CLAIM SUITE, WHICH WAS NOT IN THIS GATE AND SHOULD HAVE BEEN.
#
# MEASURED on 2026-11-10: this file printed green while `pentest-gpu-claims.sh` was RED, and the
# only reason it was caught is that it was run by hand. A7 had been pinned to `--gpus [0-9]+` and
# the flag had moved to docker's grammar, where a bare number is a count; the suite went red on the
# commit that corrected `kern doctor`, which is the gate working, and nothing here was listening.
# A discipline that depends on remembering to run something is not a gate.
#
# IT SAYS WHY IT DID NOT RUN, which is the whole point of putting it here rather than leaving it
# out. It needs a C compiler for the raw-ioctl probe and a GPU to have anything to claim about, and
# a host with neither is not a failure; a host with neither that stays SILENT is, because the next
# reader cannot tell "passed" from "never ran". `warm cache reports a check that never ran` is the
# same class and this project has paid for it before.
# WHY THE REASON IS DECIDED OUT HERE AND NOT INSIDE THE STEP. `step` sends the command's stdout to
# a log and prints `ok` on a zero exit, so a skip printed from inside the function was swallowed and
# the terminal read `ok`: a skip that looks like a pass, which is the exact thing this step exists
# to stop. Measured on the first version of it.
gpu_claims_skip_reason() {
    if ! command -v cc >/dev/null && ! command -v gcc >/dev/null; then
        echo "no C compiler for the ioctl probe"
        return 0
    fi
    if [ ! -d /sys/class/drm ] || [ -z "$(ls /sys/class/drm 2>/dev/null)" ]; then
        echo "no DRM card on this host"
        return 0
    fi
    return 1
}

gpu_claims() {
    # THE BINARY IS BUILT HERE AND PASSED AS AN ARGUMENT. The suite reads `kern doctor`, so it
    # needs the binary this gate is about to vouch for; a stale one would have it checking a claim
    # nobody is pushing, which this project has paid for three times. The first version of this
    # step set `KERN_BIN` and the suite ignored it, so it silently read whatever was in
    # `target/release` and reported green on a tree where the claim had been sabotaged.
    cargo build -q 2>/dev/null || return 1
    sh pentest/pentest-gpu-claims.sh "$PWD/target/debug/kern" > /tmp/prepush-gpu.log 2>&1
    rc=$?
    if [ "$rc" -ne 0 ] || grep -q "  FAIL " /tmp/prepush-gpu.log; then
        tail -30 /tmp/prepush-gpu.log
        return 1
    fi
    return 0
}
if gpu_skip=$(gpu_claims_skip_reason); then
    printf '  \033[33mskip\033[0m %-38s %s\n' "gpu claims" "$gpu_skip"
else
    step "gpu claims" gpu_claims
fi

# THE OTHER HALF: what a grant DOES, not what kern says about it. `pentest-gpu-grant.sh` hands
# cards to real boxes, runs a kernel on them, and checks that a box which named nothing got
# nothing and that nothing is left behind. It needs a real card and says so when there is none;
# `gpu claims` only needs a DRM node of any vendor, which is why the two conditions differ.
gpu_grant_skip_reason() {
    [ -e /dev/nvidia0 ] || { echo "no /dev/nvidia0: a grant has nothing to hand over"; return 0; }
    "$PWD/target/debug/kern" images 2>/dev/null | grep -q "kern-sandbox" \
        || { echo "the probe image is not pulled (kern-sandbox)"; return 0; }
    return 1
}
gpu_grant() {
    cargo build -q 2>/dev/null || return 1
    sh pentest/pentest-gpu-grant.sh "$PWD/target/debug/kern" > /tmp/prepush-grant.log 2>&1
    rc=$?
    if [ "$rc" -ne 0 ] || grep -q "  FAIL " /tmp/prepush-grant.log; then
        tail -30 /tmp/prepush-grant.log
        return 1
    fi
    return 0
}
if [ "$FULL" -eq 1 ]; then
    if grant_skip=$(gpu_grant_skip_reason); then
        printf '  \033[33mskip\033[0m %-38s %s\n' "gpu grant" "$grant_skip"
    else
        step "gpu grant" gpu_grant
    fi
fi

# WHAT CI ACTUALLY SAID, read rather than predicted. Everything above is this host answering about
# itself, and the sentence below used to claim it spoke for the runner. It did not: CI was red on
# `main` for four commits while this file printed green, once because a test asked whether a user
# namespace was ALLOWED when the runner allows it and refuses its uid map, and once because a push
# skipped this gate entirely. A prediction cannot catch either. Reading can.
echo
sh "$(dirname "$0")/ci-status.sh" || true

echo
if [ "$fail" -eq 0 ]; then
    [ "$FULL" -eq 1 ] && echo "green HERE, and the ci-status line above is what the runner says." \
                      || echo "green on the fast set. Before pushing: sh scripts/pre-push.sh --full"
    exit 0
fi
echo "RED. Fix it here; a CI round costs ~6.5 minutes and says the same thing."
exit 1
