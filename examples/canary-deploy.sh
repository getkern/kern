#!/bin/sh
# Canary deploy that keeps the old version on failure, daemonless. Refresh the image (`--pull always`,
# atomic swap), run ONE canary box on it, then gate on the canary's own health verdict read back with
# `kern logs --tail`. If unhealthy, the existing 'prod' instance is never touched. Uses all three new
# knobs together: `--pull always`, `kern ps` (poll for completion), `kern logs --tail` (read verdict).
#
# Real-life: gate a risky :latest on a real workload's health check before it reaches prod traffic, on
# a box with no service mesh or orchestrator.
set -eu
kern="${KERN:-kern}"
img="${IMG:-alpine}"
svc="canary$$"

cleanup() {
  "$kern" stop "${svc}-prod" >/dev/null 2>&1 || true
  "$kern" gc >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> prod stays up the whole time:"
"$kern" box "${svc}-prod" --image "$img" -d -- sh -c 'while true; do sleep 2; done' >/dev/null
sleep 1
"$kern" ps --filter "name=${svc}-prod" --format '    prod: {{.Names}} {{.Status}}'

echo
echo "==> refresh the image (--pull always), then run a canary that self-tests:"
"$kern" box --image "$img" --pull always -- true >/dev/null 2>&1 || true
# The canary runs the new image's smoke test and records a verdict line. Flip OK->FAIL to see a reject.
"$kern" box "${svc}-canary" --image "$img" -d -- \
  sh -c 'echo "canary: warming up"; sleep 1; echo "canary: healthcheck OK"' >/dev/null
# Poll ps until the canary finishes, then read its verdict from the log tail.
while "$kern" ps -q | grep -q "${svc}-canary"; do sleep 1; done
if "$kern" logs "${svc}-canary" --tail 1 | grep -q OK; then
  verdict=healthy
else
  verdict=unhealthy
fi
echo "    canary verdict (from logs --tail): $verdict"

echo
if [ "$verdict" = healthy ]; then
  echo "==> healthy -> safe to roll the fleet (hand off to rolling-redeploy.sh)."
else
  echo "==> UNHEALTHY -> fleet left on the known-good image; canary discarded, no traffic risk."
fi
"$kern" ps --filter "name=${svc}-prod" --format '    prod still serving: {{.Names}} {{.Status}}'
