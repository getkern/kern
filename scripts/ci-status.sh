#!/bin/sh
# What CI ACTUALLY said about the commits already on `main`.
#
# WHY THIS EXISTS. The gate next door ends by printing "green: this is what CI will say", and for
# four commits in a row that sentence was false: CI was red on `main` and nobody looked. The gate
# cannot reproduce every host shape - the runner refuses a rootless uid map, so a box that starts
# here does not start there - and it also cannot catch a push that skipped it. Both failures look
# identical from the terminal: a local green and a red repository.
#
# So this does not predict CI. It READS it, which is the one thing a prediction can never do.
#
# BEST EFFORT AND NEVER FATAL. It needs a credential and a network, and a contributor who has
# neither must not be blocked by a check about somebody else's runner. It prints what it found and
# exits 0 either way; the gate prints the verdict beside its own.
set -eu
REPO=${KERN_CI_REPO:-getkern/kern}
tok=$(printf 'protocol=https\nhost=github.com\n\n' | git credential fill 2>/dev/null | sed -n 's/^password=//p') || tok=""
[ -n "$tok" ] || { echo "ci-status: no stored credential, skipping (this checks the REMOTE, not this tree)"; exit 0; }
body=$(curl -s --max-time 20 -H "Authorization: Bearer $tok" \
  "https://api.github.com/repos/$REPO/actions/workflows/ci.yml/runs?branch=main&per_page=5" 2>/dev/null) || body=""
[ -n "$body" ] || { echo "ci-status: could not reach GitHub, skipping"; exit 0; }
tmp=$(mktemp)
printf '%s' "$body" > "$tmp"
python3 - "$tmp" <<'PY'
import json, sys
try:
    runs = json.load(open(sys.argv[1])).get("workflow_runs", [])
except Exception:
    print("ci-status: unreadable answer, skipping")
    sys.exit(0)
if not runs:
    print("ci-status: no runs found, skipping")
    sys.exit(0)
head = runs[0]
state = head.get("conclusion") or head.get("status")
first = head["head_commit"]["message"].splitlines()[0][:48]
sha = head["head_sha"][:8]
print(f"ci-status: main is {state} at {sha} ({first})")
bad = [r for r in runs if r.get("conclusion") == "failure"]
if bad:
    print(f"ci-status: {len(bad)} of the last {len(runs)} runs on main FAILED:")
    for r in bad:
        msg = r["head_commit"]["message"].splitlines()[0][:52]
        print(f"    {r['head_sha'][:8]}  {msg}")
    print("    A local green does not make those green. Read one: Actions -> CI -> the red run.")
PY
rm -f "$tmp"
