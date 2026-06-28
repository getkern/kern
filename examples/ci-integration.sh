#!/bin/sh
# Reproduce your CI locally: the exact steps from examples/github-actions.yml, run on your laptop.
#
# The whole point of running CI in a kern box is that "works in CI" and "works on my machine" become
# the same isolated sandbox — same image, same read-only repo mount, same memory cap, same exit-code
# gate. When CI goes red, run this to reproduce it without pushing.
set -eu
kern="${KERN:-kern}"

# Use the current repo if run from inside one, else a throwaway stand-in project.
if root="$(git rev-parse --show-toplevel 2>/dev/null)" && [ -f "$root/ci/build.sh" ]; then
  cleanup=:
else
  root="$(mktemp -d)"; cleanup="rm -rf '$root'"
  mkdir -p "$root/ci"
  cat > "$root/ci/build.sh" <<'EOF'
#!/bin/sh
echo "[ci] building..."; echo 'echo ok' > /tmp/app.sh
echo "[ci] testing...";  [ "$(sh /tmp/app.sh)" = "ok" ] || { echo "[ci] FAIL"; exit 1; }
echo "[ci] PASS"
EOF
fi
trap "$cleanup" EXIT

echo "==> running the CI job in a kern box (same as github-actions.yml):"
# --read-only + :ro: the build can read the repo but not mutate it or the host. -m caps memory.
# No --net: hermetic build with no network. Exit code propagates so a failure stops you here too.
if "$kern" box ci --image alpine --read-only \
     -v "$root:/src:ro" -w /src -m 512m -- \
     sh -c 'sh ci/build.sh'; then
  echo "==> local CI green (exit 0) — CI will pass too"
else
  echo "==> local CI failed (exit $?) — same failure CI would report"
fi
