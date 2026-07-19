#!/bin/sh
# Supply-chain check in a box: vet a third-party dependency before you trust it.
#
# The threat is install-time code execution - an npm/pip package whose postinstall (or setup.py)
# runs arbitrary code the moment you install it, reading your ~/.ssh keys or ~/.npmrc token and
# phoning them home. kern lets you split the job into two boxes so that never touches your machine:
#
#   1. FETCH box  - has network (to reach the registry) but NO host mounts and NO secrets, and
#                   downloads with lifecycle scripts DISABLED (`--ignore-scripts`). Nothing runs yet.
#   2. RUN box    - has NO network (isolated netns, loopback only) and no host secrets, then EXECUTES
#                   the package's lifecycle scripts. They run, but with the wire cut they cannot
#                   exfiltrate anything, and there are no host files to steal.
#
# HONEST LIMITATION: kern's network is all-or-nothing per box (`--net` = share host net; default =
# none). There is no built-in per-host egress allowlist/firewall. The two-box split above is exactly
# how you get "fetch is allowed to reach the registry, execution is allowed to reach nothing."
set -eu
kern="${KERN:-kern}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A stand-in "untrusted package" with a hostile postinstall. Swap in a real name to vet.
mkdir -p "$work/suspicious-pkg"
cat > "$work/suspicious-pkg/package.json" <<'JSON'
{
  "name": "suspicious-pkg",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "echo '[pkg] postinstall running'; echo '[pkg] reading host secrets...'; (cat /root/.ssh/id_rsa /root/.npmrc 2>&1 | head -1 || true); echo '[pkg] phoning home...'; (wget -qT2 -O- https://example.com >/dev/null 2>&1 && echo '[pkg] EXFIL OK' || echo '[pkg] no network - cannot exfiltrate')"
  }
}
JSON

echo "==> 1) FETCH: download a real dependency in a networked box, scripts DISABLED, no host mounts:"
# --net gives registry access; -m caps memory; --ignore-scripts means nothing executes on install.
# The download lands in our own scratch dir ($work), bound writable - NOT any host secret path.
"$kern" box dep-fetch --image node:alpine --net -m 512m \
  -v "$work:/audit" -w /audit -- \
  sh -c 'npm install --ignore-scripts --no-audit --no-fund is-number 2>&1 | tail -2; echo "   fetched, and nothing has run yet"'

echo
echo "==> 2) RUN: execute the untrusted lifecycle script in a box with NO network and no secrets:"
# No --net here. The postinstall runs, tries to read keys + phone home, and fails at both.
"$kern" box dep-run --image node:alpine \
  -v "$work:/audit" -w /audit/suspicious-pkg -- \
  sh -c 'npm run postinstall 2>&1'

echo
echo "Verdict: the package's install code ran fully sandboxed - no host files, no egress."
echo "Both boxes were thrown away; the only artifacts live in a temp dir that is now deleted."
