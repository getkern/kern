#!/bin/sh
# Multi-stage build: compile in a fat "builder" stage, ship only the binary in a slim final stage.
#
# kern's builder supports multi-stage Dockerfiles:
#   FROM <image> AS <name>        name a stage
#   COPY --from=<stage> <src> <dst>   pull an artifact out of an earlier stage
# Each stage builds through the same single-stage path; only the LAST stage becomes your tag,
# the intermediate builder stage is dropped — so its toolchain never ends up in the final image.
set -eu
kern="${KERN:-kern}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cat > "$work/hello.c" <<'EOF'
#include <stdio.h>
int main(void){ puts("hello from a statically-linked multi-stage build"); return 0; }
EOF

cat > "$work/Dockerfile" <<'EOF'
# ---- stage 1: builder (has the compiler) ----
FROM alpine:3.19 AS builder
RUN apk add --no-cache gcc musl-dev
COPY hello.c /hello.c
RUN cc -static -O2 /hello.c -o /hello

# ---- stage 2: final (no compiler, just the binary) ----
FROM alpine:3.19
COPY --from=builder /hello /usr/local/bin/hello
CMD ["/usr/local/bin/hello"]
EOF

echo "==> building the multi-stage image 'slim-app:1':"
"$kern" build -t slim-app:1 "$work"

echo
echo "==> run it (the final image's CMD runs the copied binary):"
"$kern" box slim-run --image slim-app:1

echo
echo "==> prove the final image is slim — it has the binary but NOT the build toolchain:"
"$kern" box slim-check --image slim-app:1 -- /bin/sh -c '
  ls -l /usr/local/bin/hello
  command -v cc  >/dev/null 2>&1 && echo "cc  present (unexpected)" || echo "cc  absent  — compiler stayed in the builder stage"
  command -v gcc >/dev/null 2>&1 && echo "gcc present (unexpected)" || echo "gcc absent  — build tools not shipped"
'

echo
echo "==> images list — only the final 'slim-app' tag remains (the builder stage was dropped):"
"$kern" images | sed -n '1p;/slim-app/p'

echo
echo "==> cleanup:"
"$kern" rmi slim-app:1 >/dev/null 2>&1 || true
"$kern" gc >/dev/null 2>&1 || true
echo "done — final image removed, builder stage never persisted, temp files gone."
