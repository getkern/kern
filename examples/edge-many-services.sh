#!/bin/sh
# On a RAM-constrained board (Jetson, Pi, …) the daemon is the tax that hurts: dockerd +
# containerd sit at ~186 MB RSS before you run anything. kern has NO daemon - each box is one
# short-lived process at a few MB. So you can fit many isolated services on a small device.
#
# Real-life: edge gateways, multi-tenant micro-services, a fleet of agents on an 8 GB Jetson.
set -eu
kern="${KERN:-kern}"

echo "==> starting 5 isolated detached services (no daemon):"
for n in collector ingest api metrics watchdog; do
  "$kern" box "$n" --image alpine -d -- sh -c 'while true; do sleep 5; done'
done
sleep 1

echo
echo "==> kern ps:"; "$kern" ps
echo
echo "==> per-box memory (kern stats) - total footprint is a few MB, not 186 MB of daemon:"
"$kern" stats

echo
echo "==> tear down:"
for n in collector ingest api metrics watchdog; do "$kern" stop "$n" >/dev/null; done
echo "done - 0 resident memory left behind (no daemon to keep running)."
