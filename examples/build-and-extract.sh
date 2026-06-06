#!/bin/sh
# Compile in a clean, throwaway toolchain — your host never gets the compiler.
# The image (with --net) installs gcc, builds your source bound in at /src, and writes the
# artifact to a volume you keep. The toolchain disappears with the box.
#
# Without kern: install gcc on your host (pollutes it), or run a daemon-backed container.
set -eu
kern="${KERN:-kern}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cat > "$work/hello.c" <<'EOF'
#include <stdio.h>
int main(void){ puts("built inside a disposable kern box"); return 0; }
EOF
mkdir -p "$work/out"

echo "==> building in alpine (gcc installed only inside the box):"
"$kern" box builder --image alpine --net \
  -v "$work:/src:ro" -v "$work/out:/out" -w /src -- \
  sh -c 'apk add --no-cache gcc musl-dev >/dev/null && cc -O2 -static hello.c -o /out/hello && echo "compiled."'

echo "==> the artifact is on your host; run it (host has no gcc):"
chmod +x "$work/out/hello"
"$work/out/hello"
command -v cc >/dev/null 2>&1 && echo "(host has cc)" || echo "(host has NO cc — the toolchain stayed in the box)"
