#!/bin/sh
# Run your project's tests in a clean, isolated box - on your laptop or on the device itself
# (edge CI). Bind the repo read-only, build/test with network, get a pass/fail exit code. No
# daemon to install on the build agent; works rootless on x86 and ARM alike.
#
# Real-life: pre-commit checks, per-PR sandboxes, building/testing directly on a Jetson/Pi.
set -eu
kern="${KERN:-kern}"

repo="$(mktemp -d)"
trap 'rm -rf "$repo"' EXIT
# A stand-in project: a script + its test. Point `-v` at your real repo instead.
cat > "$repo/build.sh" <<'EOF'
#!/bin/sh
echo "[ci] building..."; echo 'echo ok' > app.sh; chmod +x app.sh
echo "[ci] testing..."; [ "$(sh app.sh)" = "ok" ] || { echo "[ci] FAIL"; exit 1; }
echo "[ci] PASS"
EOF

echo "==> running CI in an isolated box (repo bound read-only, scratch is throwaway):"
if "$kern" box ci --image alpine -v "$repo:/src:ro" -w /tmp -- \
     sh -c 'cp /src/build.sh . && sh build.sh'; then
  echo "==> CI exit code: 0 (green) - propagated from the box"
else
  echo "==> CI failed (non-zero exit propagated) - your pipeline would stop here"
fi
