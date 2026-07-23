#!/bin/sh
# A fully air-gapped, reproducible CI run. Seed the base image ONCE, then every pipeline step runs
# with `--pull never`: if a step's image isn't already cached, kern FAILS CLOSED instead of reaching a
# registry. No surprise pulls, no network exfil from build steps, the same base bytes every run.
#
# Real-life: a supply-chain-hardened build agent (SLSA-style), a regulated or offline environment, or
# any CI where "the build silently pulled something new mid-pipeline" is unacceptable.
set -eu
kern="${KERN:-kern}"
img="${IMG:-alpine}"
work="$(mktemp -d)"
trap 'rm -rf "$work"; "$kern" gc >/dev/null 2>&1 || true' EXIT

echo "==> [seed] pull the base image ONCE (the only network step), then go air-gapped:"
"$kern" box --image "$img" --pull missing -- true >/dev/null
echo "    base '$img' is cached."

echo
echo "==> [guardrail] prove the air-gap: an UN-seeded image is refused, never pulled:"
if "$kern" box --image "unseeded-$$:latest" --pull never -- true 2>/dev/null; then
  echo "    UNEXPECTED: --pull never should have refused an un-seeded image" >&2
  exit 1
fi
echo "    -> refused (fail closed). A build step can't smuggle in an unpinned image."

echo
echo "==> [pipeline] every step is --pull never (cached base) AND network-off (kern's default):"
echo "    build:"
"$kern" box ci-build --image "$img" --pull never -v "$work:/out" -w /out -- \
  sh -c 'echo compiled > artifact.txt; echo "      -> produced /out/artifact.txt"'
echo "    test:"
"$kern" box ci-test --image "$img" --pull never -v "$work:/out:ro" -- \
  sh -c '[ "$(cat /out/artifact.txt)" = compiled ] && echo "      -> tests green"'
echo "    package:"
"$kern" box ci-package --image "$img" --pull never -v "$work:/out" -w /out -- \
  sh -c 'tar czf release.tgz artifact.txt && echo "      -> release.tgz built offline"'

echo
echo "==> air-gapped CI complete: 3 steps, cached base, zero network, deterministic. Artifacts:"
ls -1 "$work" | sed 's/^/    /'
