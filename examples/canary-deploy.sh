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
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2

img="${IMG:-alpine}"
svc="canary$$"

cleanup() {
  "$kern" stop "${svc}-prod" >/dev/null 2>&1 || true
  "$kern" gc >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> prod stays up the whole time:"
"$kern" box "${svc}-prod" --image "$img" -d -- sh -c 'while true; do sleep 2; done' >/dev/null
# Il box e' gia' avviato quando `-d` ritorna (misurato: 20 su 20 con `exec` e `logs` subito dopo).
# Si aspetta la CONDIZIONE, non un tempo: qui e' istantaneo, e su una board lenta regge lo stesso,
# mentre un `sleep 1` fisso era il numero sbagliato in entrambe le direzioni.
i=0; while [ $i -lt 25 ] && [ -z "$("$kern" ps -q 2>/dev/null)" ]; do sleep 0.04; i=$((i+1)); done
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
