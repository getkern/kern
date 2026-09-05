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
echo "docs"
for g in flat-continuation gen-seccomp-allowlist injection-declared no-ai-slop \
         registry-classified stale-numbers test-count progress-is-tty-gated gates-selftest; do
    step "$g" python3 "scripts/$g.py"
done
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
