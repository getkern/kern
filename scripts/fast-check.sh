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
#   - every static gate CI runs (about 1.3 s), the Python binding's tests when it changed, the seccomp coverage gate when the seccomp
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
    # The registry-path chokepoint gate: milliseconds, and cut-release refused v0.51.1 on it.
    python3 scripts/registry-classified.py >/tmp/fast-check-reg.$$ 2>&1 \
        || { cat /tmp/fast-check-reg.$$ >&2; rm -f /tmp/fast-check-reg.$$; die "registry-classified"; }
    rm -f /tmp/fast-check-reg.$$
    ok "registry-classified"
fi

# Integration tests, by name, when asked: the binary they run must be the one this tree builds.
if [ -n "$filter" ]; then
    cargo build -q --bin kern
    cargo test -q -p getkern --tests -- "$filter" >/tmp/fast-check-it.$$ 2>&1 \
        || { tail -30 /tmp/fast-check-it.$$ >&2; die "integration tests matching '$filter'"; }
    rm -f /tmp/fast-check-it.$$
    ok "integration tests matching '$filter'"
fi

# EVERY STATIC GATE CI RUNS, ALWAYS: about 1.3 s together (measured 2026-11-20). They used to run here
# only when a `.md` changed, and v0.56.0 went red on main twice in one push for a gate this script
# never ran: `progress-is-tty-gated` (two `eprintln!` without `kern: ` in compose.rs). A gate that
# reads Rust runs on a Rust change, so "green here" has to mean "green in CI" for all of them.
for g in no-ai-slop stale-numbers docker-vocabulary md-links readme-blocks-complete \
         og-card-matches-readme flat-continuation test-env-lock progress-is-tty-gated injection-declared; do
    python3 "scripts/$g.py" >/tmp/fast-check-gate.$$ 2>&1 \
        || { cat /tmp/fast-check-gate.$$ >&2; rm -f /tmp/fast-check-gate.$$; die "scripts/$g.py"; }
done
python3 scripts/tracked-paths-sane.py --self-check >/tmp/fast-check-gate.$$ 2>&1 \
    && python3 scripts/tracked-paths-sane.py >>/tmp/fast-check-gate.$$ 2>&1 \
    || { cat /tmp/fast-check-gate.$$ >&2; rm -f /tmp/fast-check-gate.$$; die "scripts/tracked-paths-sane.py"; }
rm -f /tmp/fast-check-gate.$$
ok "the static gates CI runs (11)"

# THE BINDINGS' OWN TESTS, when a binding changed: CI runs the Python suite on every push, and on
# v0.56.0 one of its tests (ETXTBSY on a kern double rewritten while the first still ran) was red on
# main because nothing here ran it.
if has '^bindings/python/'; then
    (cd bindings/python && python3 -m pytest -q -p no:cacheprovider tests/ >/tmp/fast-check-py.$$ 2>&1) \
        || { tail -30 /tmp/fast-check-py.$$ >&2; rm -f /tmp/fast-check-py.$$; die "python binding tests (bindings/python: pytest tests/)"; }
    rm -f /tmp/fast-check-py.$$
    ok "python binding tests"
fi
if has '^bindings/node/'; then
    node --check bindings/node/index.js >/dev/null 2>&1 || die "node --check bindings/node/index.js"
    ok "node binding parses"
fi

# Every gate's self-test case must still find the text it sabotages (milliseconds, writes nothing):
# the full gates-selftest takes minutes, and a moved anchor turned CI red twice.
python3 scripts/gates-selftest.py --anchors >/tmp/fast-check-anchors.$$ 2>&1 \
    || { cat /tmp/fast-check-anchors.$$ >&2; rm -f /tmp/fast-check-anchors.$$; die "gates-selftest --anchors"; }
rm -f /tmp/fast-check-anchors.$$
ok "gates-selftest anchors"

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
    # NO AUTOMATIC JOB ON AN ARM64 MAC. On 2026-11-18 GitHub assigned no arm64 macOS runner for 15
    # minutes, three times, and cancelled the job: a red X on main with nothing wrong in the code.
    # `-intel` labels were assigned every time. The one exception is the probe that exists to ask
    # what an arm64 runner can do, and it only runs by hand.
    arm=$(grep -nE '^[[:space:]]*runs-on:[[:space:]]*macos-' .github/workflows/*.yml \
        | grep -v -- '-intel' | grep -v '^\.github/workflows/macos-vm-probe\.yml:' || true)
    [ -z "$arm" ] || die "a workflow job on an arm64 macOS runner (use macos-15-intel): $arm"
    ok "macOS jobs on Intel runners"
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
