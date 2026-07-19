#!/bin/sh
# Build a static Go binary in a throwaway toolchain box, then PROVE it's self-contained by running it
# in a different, minimal box that has no Go and a different base image.
#
#   1. BUILD:  a `golang` box compiles your source (bound in at /src) with CGO disabled, writing a
#              fully static binary to an /out volume you keep on the host. No Go on your host.
#   2. RUN:    a plain `alpine` box (musl, no Go, no glibc) executes that same binary. It runs because
#              the binary carries everything it needs - that's what "static" buys you.
#
# The build needs no network: there are no module dependencies and GOTOOLCHAIN=local forbids fetching a
# toolchain, so the whole thing works offline.
set -eu
kern="${KERN:-kern}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/src" "$work/out"

cat > "$work/src/go.mod" <<'EOF'
module kerndemo

go 1.21
EOF

cat > "$work/src/main.go" <<'EOF'
package main

import (
	"fmt"
	"runtime"
)

func main() {
	fmt.Printf("hello from a static Go binary (%s/%s), built in a disposable kern box\n",
		runtime.GOOS, runtime.GOARCH)
}
EOF

echo "==> 1. BUILD: compile a static binary inside a golang box (no Go on your host):"
"$kern" box go_build --image golang:alpine \
  -v "$work/src:/src:ro" -v "$work/out:/out" -w /src \
  -e CGO_ENABLED=0 -e GOTOOLCHAIN=local -- \
  sh -c 'go build -o /out/app . && echo "   built /out/app ($(wc -c < /out/app) bytes)"'

echo
echo "==> 2. RUN: execute that binary in a minimal alpine box - no Go, different libc base:"
"$kern" box go_run --image alpine \
  -v "$work/out:/out:ro" -- \
  sh -c '/out/app; printf "   ldd says: "; ldd /out/app 2>&1 | head -1'

echo
echo "==> your host never had a Go toolchain:"
command -v go >/dev/null 2>&1 && echo "   (host has go)" || echo "   host has NO go - the compiler stayed in the box"
echo "done - artifact and sources removed on exit (trap)."
