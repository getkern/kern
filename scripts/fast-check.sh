#!/bin/sh
# The pre-push check, sized to what the change touches: a minute, not the half hour of the full gate.
#
#     sh scripts/fast-check.sh                 # check what differs from origin/main
#     sh scripts/fast-check.sh some_test_name  # also run the integration tests whose name matches
#     sh scripts/fast-check.sh --push          # check, then push HEAD to main (fast-forward only)
#
# WHAT IT RUNS, and only when the diff calls for it:
#   - `cargo fmt --check` and, per touched crate, `clippy -D warnings` and its UNIT tests (`--lib`, `--bins` for the CLI);
#     the integration binaries (smoke, sandbox_run: ~2 min) only for a test name given as argument;
#   - the five documentation gates when a `.md` changed, the seccomp coverage gate when the seccomp
#     lists changed, a YAML parse and actionlint with shellcheck (as CI) when a workflow changed.
# The full suite, the batteries, `gates-selftest` and the pentest stay with CI and with
# `cut-release.sh`. WHY: on 2026-11-17 a release waited two hours on CI rounds; the owner's rule since
# is five minutes for a whole round (change, local check, push, control back), and CI is not waited on.
#
# `--push` pushes HEAD to `main` and returns. ONLY `main` exists on GitHub (owner, 2026-11-17): work
# lands there on every round, so the runner's own failures (a newer distro, AppArmor) surface at once
# instead of piling up on a side branch until release day. A push that is not a fast-forward is refused
# by git itself.
set -eu
cd "$(dirname "$0")/.."

push=0
filter=""
for a in "$@"; do
    case "$a" in
        --push) push=1 ;;
        *) filter="$a" ;;
    esac
done

die() { printf 'fast-check: %s\n' "$1" >&2; exit 1; }
ok() { printf '  ok  %s\n' "$1"; }
start=$(date +%s)

git fetch --quiet origin main 2>/dev/null || true
files=$( { git diff --name-only origin/main...HEAD 2>/dev/null; git diff --name-only HEAD; \
           git ls-files --others --exclude-standard; } | sort -u )
[ -n "$files" ] || { echo "fast-check: nothing differs from origin/main"; exit 0; }

has() { printf '%s\n' "$files" | grep -q "$1"; }

# Rust: format once, then lint and unit-test each touched crate.
if has '\.rs$\|Cargo\.toml$\|Cargo\.lock$'; then
    cargo fmt --all --check >/dev/null 2>&1 || die "cargo fmt --check (run: cargo fmt --all)"
    ok "fmt"
    for dir in $(printf '%s\n' "$files" | sed -n 's|^crates/\([^/]*\)/.*|\1|p' | sort -u); do
        [ -f "crates/$dir/Cargo.toml" ] || continue
        pkg=$(sed -n 's/^name = "\(.*\)"/\1/p' "crates/$dir/Cargo.toml" | head -1)
        RUSTFLAGS="${RUSTFLAGS:-} -D warnings" cargo clippy -q -p "$pkg" --all-targets -- -D warnings \
            >/tmp/fast-check-clippy.$$ 2>&1 || { tail -20 /tmp/fast-check-clippy.$$ >&2; die "clippy -p $pkg"; }
        ok "clippy -p $pkg"
        # Unit tests only: `--lib` for a library crate, `--bins` for the CLI (no lib target there).
        kind="--lib"
        [ -f "crates/$dir/src/lib.rs" ] || kind="--bins"
        cargo test -q -p "$pkg" "$kind" >/tmp/fast-check-test.$$ 2>&1 \
            || { tail -30 /tmp/fast-check-test.$$ >&2; die "cargo test -p $pkg $kind"; }
        ok "unit tests -p $pkg"
    done
    rm -f /tmp/fast-check-clippy.$$ /tmp/fast-check-test.$$
fi

# Integration tests, by name, when asked: the binary they run must be the one this tree builds.
if [ -n "$filter" ]; then
    cargo build -q --bin kern
    cargo test -q -p getkern --tests -- "$filter" >/tmp/fast-check-it.$$ 2>&1 \
        || { tail -30 /tmp/fast-check-it.$$ >&2; die "integration tests matching '$filter'"; }
    rm -f /tmp/fast-check-it.$$
    ok "integration tests matching '$filter'"
fi

if has '\.md$'; then
    for g in md-links docker-vocabulary flat-continuation no-ai-slop stale-numbers; do
        python3 "scripts/$g.py" >/dev/null 2>&1 || die "scripts/$g.py (run it for the detail)"
    done
    ok "documentation gates"
fi

if has 'seccomp'; then
    python3 scripts/gen-seccomp-allowlist.py --check >/dev/null 2>&1 \
        || die "scripts/gen-seccomp-allowlist.py --check"
    ok "seccomp lists"
fi

if has '^\.github/workflows/'; then
    for w in $(printf '%s\n' "$files" | grep '^\.github/workflows/.*\.yml$'); do
        [ -f "$w" ] || continue
        python3 -c "import sys, yaml; yaml.safe_load(open(sys.argv[1]))" "$w" 2>/dev/null \
            || die "$w does not parse as YAML"
    done
    ok "workflow YAML"
    # The CI's own `workflow syntax` job runs actionlint WITH shellcheck over every `run:` script;
    # a YAML parse alone missed two shellcheck infos that turned main red (2026-11-17). Same here,
    # through uvx, when it is installed.
    if command -v uvx >/dev/null 2>&1; then
        sc="$(uvx --from shellcheck-py sh -c 'command -v shellcheck' 2>/dev/null || true)"
        uvx --from actionlint-py actionlint ${sc:+-shellcheck "$sc"} >/tmp/fast-check-al.$$ 2>&1 \
            || { cat /tmp/fast-check-al.$$ >&2; rm -f /tmp/fast-check-al.$$; die "actionlint"; }
        rm -f /tmp/fast-check-al.$$
        ok "actionlint${sc:+ + shellcheck}"
    else
        printf '  --  actionlint skipped: no uvx here, CI runs it\n'
    fi
fi

printf 'fast-check: green in %ss\n' "$(( $(date +%s) - start ))"

if [ "$push" = 1 ]; then
    [ -z "$(git status --porcelain)" ] || die "uncommitted changes: commit first, then --push"
    git push --quiet origin HEAD:main
    printf 'pushed %s to main; CI runs there, nothing waits on it here\n' "$(git rev-parse --short HEAD)"
fi
