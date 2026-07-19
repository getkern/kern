#!/bin/sh
# Compile a small Rust program in a throwaway toolchain box, then run the extracted binary in a
# separate minimal box. The build is GOVERNED with hard CPU + memory caps.
#
#   1. BUILD:  a `rust` box compiles your source (bound in at /src) with rustc, writing the binary to an
#              /out volume you keep on the host. The box is capped with --memory and --cpus, so a heavy
#              build can't run away with your machine - a memory-hungry compile is OOM-killed at the cap.
#   2. RUN:    a minimal `debian:stable-slim` box (no Rust toolchain) executes the extracted binary.
#
# The build needs no network: there are no crate dependencies, so rustc works fully offline. Your host
# never gets a Rust toolchain.
#
# NOTE on the run box: a default rustc build dynamically links glibc, so we run it on a slim *glibc*
# base (debian). That keeps the example honest - no musl/static claims we didn't ask rustc for.
set -eu
kern="${KERN:-kern}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/src" "$work/out"

cat > "$work/src/main.rs" <<'EOF'
fn main() {
    let n: u64 = (1..=20).product(); // 20!
    println!("hello from a Rust binary built in a governed kern box - 20! = {}", n);
}
EOF

echo "==> 1. BUILD: compile with rustc inside a rust box, capped at 512M RAM / 1 core:"
# --memory / --cpus are hard cgroup caps on the build box (see governed-run.sh). A build that exceeds
# the memory cap is OOM-killed by the kernel - governed builds, no runaway toolchain.
"$kern" box rust_build --image rust --memory 512M --cpus 1.0 \
  -v "$work/src:/src:ro" -v "$work/out:/out" -w /src -- \
  sh -c 'rustc -O main.rs -o /out/app && echo "   built /out/app ($(wc -c < /out/app) bytes)"'

echo
echo "==> 2. RUN: execute the extracted binary in a minimal debian box (no Rust toolchain):"
"$kern" box rust_run --image debian:stable-slim \
  -v "$work/out:/out:ro" -- \
  /out/app

echo
echo "==> your host never had a Rust toolchain:"
command -v rustc >/dev/null 2>&1 && echo "   (host has rustc)" || echo "   host has NO rustc - the compiler stayed in the box"
echo "done - artifact and sources removed on exit (trap)."
