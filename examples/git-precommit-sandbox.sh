#!/bin/sh
# A git pre-commit hook that runs your linters/tests in a clean, isolated kern box.
#
# Why: a pre-commit run executes project code (test suites, lint plugins, git hooks pulled in with a
# dependency). On your bare machine that code has your whole home directory. Run it in a box instead:
# the repo is bound READ-ONLY, there is no network and no host access, and the box's exit code gates
# the commit - non-zero means git aborts. A malicious test or hook can fail the commit but can't
# touch your machine.
#
# kern has no built-in git integration (it's a sandbox runtime, not a hook manager) - the "hook" is
# just a two-line shell snippet that calls `kern box`. It's printed below, then demoed for real.
set -eu
kern="${KERN:-kern}"

# ---------------------------------------------------------------------------
# The hook itself. Copy this into .git/hooks/pre-commit (chmod +x) in a real repo:
#
#   #!/bin/sh
#   root="$(git rev-parse --show-toplevel)"
#   kern box precommit --image alpine --read-only -v "$root:/src:ro" -w /src -- \
#     sh -c './ci/check.sh'          # <- your lint+test entrypoint; its exit code gates the commit
#
# --read-only + :ro binding: the checks can read the repo but cannot modify it or your host.
# No --net: the checks cannot reach the network. Exit code propagates out as the hook's exit code.
# ---------------------------------------------------------------------------

# --- Runnable demo of exactly what that hook does, on a throwaway repo ---
repo="$(mktemp -d)"
trap 'rm -rf "$repo"' EXIT
# A stand-in project with a check script. Point the hook at your real repo instead.
cat > "$repo/check.sh" <<'EOF'
#!/bin/sh
echo "[check] linting..."; grep -rq "TODO-BLOCKER" . && { echo "[check] found blocker marker"; exit 1; }
echo "[check] testing...";  [ "$(echo hi)" = "hi" ] || exit 1
echo "[check] all green"
EOF

run_hook() {
  # Mirrors the hook body above: repo bound read-only, no network, exit code returned.
  "$kern" box precommit --image alpine --read-only -v "$repo:/src:ro" -w /src -- \
    sh -c 'sh check.sh'
}

echo "==> commit #1: clean tree - checks pass, commit would be ALLOWED:"
if run_hook; then echo "   hook exit 0 -> git proceeds with the commit"; fi

echo
echo "==> commit #2: someone left a blocker in the code - checks fail, commit is BLOCKED:"
echo "// TODO-BLOCKER do not ship" > "$repo/oops.c"
if run_hook; then
  echo "   (unexpected) hook passed"
else
  echo "   hook exit $? -> git aborts the commit (nothing was committed)"
fi
