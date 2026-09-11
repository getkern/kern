#!/bin/sh
# The gates CI runs, with the flags CI runs them with. Run this, not the individual commands.
#
# It exists because a `cargo clippy` that passes is not evidence: without `RUSTFLAGS=-D warnings` a
# lint is a warning and the exit code is 0, and the same tree fails CI. That happened here twice on a
# release branch, in the same hour, from typing the command by hand and dropping the flag. The flag is
# not optional and this file is the only place it has to be remembered.
#
# It also pins the toolchain question: CI uses whatever `stable` is on the day, so a local toolchain
# one release behind is the WEAKER gate. `rustup update stable` before trusting a green run.
set -eu
cd "$(dirname "$0")/.."
# STAGE FIRST. Several of these gates read TRACKED files (`git ls-files`, `git grep`), so a file you
# have just written is invisible to them until it is added. This script failed CI on the very commit
# that introduced it, for a marker inside itself, after passing by hand while still untracked.
untracked=$(git ls-files --others --exclude-standard | head -5)
if [ -n "$untracked" ]; then
    echo "  note: untracked files are INVISIBLE to the doc gates. git add them first:"
    printf '        %s\n' $untracked
fi
RUSTFLAGS="-D warnings"
export RUSTFLAGS
fail=0
step() {
    printf '  %-34s ' "$1"
    shift
    if "$@" >/tmp/gate.$$ 2>&1; then
        echo ok
    else
        echo FAILED
        tail -12 /tmp/gate.$$ | sed 's/^/      /'
        fail=1
    fi
    rm -f /tmp/gate.$$
}
echo "rust  (RUSTFLAGS=$RUSTFLAGS, $(cargo clippy --version))"
step "cargo fmt --check" cargo fmt --all --check
step "cargo clippy" cargo clippy --all-targets --all-features
step "cargo test" env -u KERN_BIN cargo test --all
# AARCH64 IS SHIPPED AND WAS NEVER BUILT HERE. `libc::c_char` is `i8` on x86_64 and `u8` on aarch64,
# so `[0i8; 256]` handed to `gethostname` compiled clean on this machine, passed every gate, and did
# not compile AT ALL on the board target. CI caught it; a release cut before CI would have published
# the x86 asset and no ARM one, which is exactly how v0.9.31 went out broken. A type check is
# seconds and covers the whole class.
#
# IT RUNS CLIPPY, NOT `check`, because CI runs clippy under `-D warnings` and the difference is not
# academic: the first repair of the `c_char` bug compiled cleanly on both targets and then failed
# aarch64 anyway, on `clippy::unnecessary_cast` - the cast that is real on x86_64 is a no-op on the
# port where the type already matches. A gate that runs a weaker check than CI is a gate that lets
# the same class through twice.
#
# THE TARGET IS `-gnu`, BECAUSE THAT IS WHAT CI USES: its aarch64 job runs on a native
# `ubuntu-24.04-arm` runner with the host's default toolchain. Checking `-musl` instead reports
# `unnecessary_cast` on the RLIMIT table, which is correct on musl (the type is already `c_int`) and
# wrong as a gate, since it fires on code that is green on `main` and in CI. A gate aimed at a
# target nobody builds manufactures its own failures.
if rustup target list --installed 2>/dev/null | grep -q aarch64-unknown-linux-gnu; then
    step "cargo clippy (aarch64)" cargo clippy --target aarch64-unknown-linux-gnu --all-targets
else
    printf '  %-34s %s\n' "cargo clippy (aarch64)" \
        "SKIP  target not installed: rustup target add aarch64-unknown-linux-gnu"
fi
echo "docs"
for g in flat-continuation gen-seccomp-allowlist injection-declared no-ai-slop \
         registry-classified stale-numbers test-count progress-is-tty-gated gates-selftest; do
    step "$g" python3 "scripts/$g.py"
done
# The compose corpus, and it is LAST among the doc gates because it is the slowest and the only one
# that needs an input this repository does not carry. It SKIPS with a reason when
# `KERN_COMPOSE_CORPUS` points at nothing, which is why it is here and not in `pentest/run-all.sh`,
# where a skip must block the stamp. It earned its place in one run: it caught three real compose
# files that the tree had started refusing, which the 1097 Rust tests did not and could not see.
step "compose-corpus" python3 "scripts/compose-corpus-gate.py"
echo "prose"
# The character is BUILT, never typed: this file is scanned by the same gate it runs, so a literal
# one here fails the build. It did, on the commit that added this script, because the check reads
# TRACKED files and the script was still untracked when it was run by hand.
EM=$(printf '\342\200\224')
printf 'a%sb\n' "$EM" > /tmp/emctl.$$
if ! grep -q "$EM" /tmp/emctl.$$; then
    echo "  em-dash          POSITIVE CONTROL FAILED: this grep cannot see an em-dash"
    fail=1
else
    n=$(git grep -l "$EM" | wc -l)
    printf '  %-34s ' "em-dash (control passed)"
    [ "$n" -eq 0 ] && echo ok || { echo "FAILED: $n files"; fail=1; }
fi
rm -f /tmp/emctl.$$
[ "$fail" -eq 0 ] && echo "every gate passed" || echo "$fail gate(s) failed"
exit "$fail"
