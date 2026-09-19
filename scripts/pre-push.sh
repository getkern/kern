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
         tracked-paths-sane readme-blocks-complete; do
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
bindings_node() {
    [ -f bindings/node/test/sandbox.test.js ] || return 0
    command -v node >/dev/null || return 0
    ( cd bindings/node && env -u KERN_BIN node --test test/sandbox.test.js ) || return 1
}
step "python binding, CI shape" bindings_python
step "node binding"            bindings_node

if [ "$FULL" -eq 1 ]; then
    step "integration suite" cargo test -q -p getkern
fi

echo
if [ "$fail" -eq 0 ]; then
    [ "$FULL" -eq 1 ] && echo "green: this is what CI will say." \
                      || echo "green on the fast set. Before pushing: sh scripts/pre-push.sh --full"
    exit 0
fi
echo "RED. Fix it here; a CI round costs ~6.5 minutes and says the same thing."
exit 1
