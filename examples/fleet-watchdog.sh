#!/bin/sh
# A daemonless supervisor you can read at a glance: keep a service alive with nothing but `kern ps` and
# `kern logs`. The loop polls `ps --filter name= status=running`; when the service is gone (it
# crashed), it captures the crash tail with `logs --tail`, prints it, and restarts the box. No daemon,
# no root - the same pattern scales to a whole fleet.
#
# Real-life: a roll-your-own healer when `--restart on-failure` / systemd handoff isn't the right fit,
# or when you want custom crash-reporting to run between restarts.
set -eu
kern="${KERN:-kern}"
img="${IMG:-alpine}"
svc="watch$$"
restarts=0

cleanup() {
  "$kern" stop "$svc" >/dev/null 2>&1 || true
  "$kern" gc >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The "service": announces itself, works briefly, then crashes (exit 1) to exercise the healer.
start() {
  "$kern" gc >/dev/null 2>&1 || true
  "$kern" box "$svc" --image "$img" -d -- \
    sh -c 'echo "service up"; sleep 2; echo "FATAL: simulated crash"; exit 1' >/dev/null
}

alive() { "$kern" ps --filter "name=$svc" --filter status=running -q | grep -q "$svc"; }

echo "==> starting the service under a ps+logs watchdog (will heal 2 crashes, then stop):"
start
while [ "$restarts" -lt 2 ]; do
  sleep 1
  if alive; then
    continue
  fi
  restarts=$((restarts + 1))
  echo "    [watchdog] '$svc' is DOWN - last log line before it died:"
  "$kern" logs "$svc" --tail 1 2>/dev/null | sed 's/^/        /' || true
  echo "    [watchdog] restart #$restarts"
  start
done
sleep 1
echo "==> healed $restarts crashes with only 'kern ps' + 'kern logs' + a shell loop. No daemon."
