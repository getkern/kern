#!/bin/sh
# ETL where the dependency is installed ONCE (network-on), snapshotted into an
# image, and the transform then runs network-OFF over data bound in from the host.
#
# The pattern:
#   1. SETUP  — `kern build` bakes a tool into an image. A build's RUN steps get
#               network (to `apk add` / `pip install`), so this is the one online
#               step. The result is a cached image = the snapshot.
#   2. PROCESS — run that image with NO `--net`, mounting the data :ro. The
#               transform uses the baked-in tool with zero network access, which
#               we prove by having it try (and fail) to reach the internet.
#
# Why: pin and cache your toolchain once, then run the actual data processing in
# a locked-down, offline box — reproducible, and it can't phone home.
set -eu
kern="${KERN:-kern}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/data"

img="kern_etl_demo:1"

# Input data the transform will crunch. jq (the baked tool) is NOT in the alpine
# base — it only exists because the build step installed it.
cat > "$work/data/events.json" <<'EOF'
[ {"user":"amy","amount":12}, {"user":"bo","amount":7}, {"user":"amy","amount":5} ]
EOF

# ---- 1. SETUP: install the dep once, network-on, into an image snapshot -------
cat > "$work/Dockerfile" <<'EOF'
FROM alpine:3.19
# RUN steps have network during a build — this is the ONE online step.
RUN apk add --no-cache jq
EOF

echo "==> 1. building the toolchain snapshot ($img) — apk add runs online:"
if ! "$kern" build -t "$img" "$work"; then
  echo "  build failed (no network to pull alpine / fetch jq?) — cannot continue." >&2
  exit 0
fi

# ---- 2. PROCESS: transform offline over bound-in data -------------------------
echo
echo "==> 2. transform in a box with NO --net (data mounted :ro):"
"$kern" box etl-run --image "$img" \
  --memory 128m --cpus 1 --timeout 30 \
  -v "$work/data:/data:ro" -- \
  sh -c '
    # Prove there is no network here — this MUST fail (default-off, no --net).
    if wget -q -T 3 -O /dev/null https://example.com 2>/dev/null; then
      echo "  UNEXPECTED: network reachable in the process step" >&2; exit 1
    fi
    echo "  network check: offline (expected)"
    # The real work: aggregate total amount per user with the baked-in jq.
    echo "  jq version: $(jq --version)"
    echo "  totals per user:"
    jq -r "group_by(.user)[] | \"    \(.[0].user): \([.[].amount] | add)\"" /data/events.json
  '

echo
echo "==> cleanup: drop the snapshot image and reclaim its layers:"
"$kern" rmi "$img" >/dev/null 2>&1 || true
"$kern" gc >/dev/null 2>&1 || true
echo "done — deps were fetched once online; the transform ran fully offline."
