#!/bin/sh
# A daemonless "cron-like" pattern: run a short job in a FRESH, capped box on an interval.
#
# HONEST: kern has NO built-in scheduler. This is just the shell pattern - a loop that starts a
# throwaway box each tick. Each run is fully isolated (its own overlay + namespaces) and resource
# capped, and leaves nothing behind (a foreground box removes itself when its command exits). For
# REAL scheduling, drive this same one-shot `kern box ...` line from the host's cron or a
# systemd timer; kern supplies the isolation, the host supplies the clock.
#
#   kern box <name> --image alpine --memory 64m --cpus 0.5 -- <job>   one isolated, capped run
#
# (`--restart always` keeps a service ALIVE by respawning it on exit - that's supervision, not
#  interval scheduling; a job that should run "every N seconds and then stop" wants this loop.)
set -eu
kern="${KERN:-kern}"

interval="${INTERVAL:-2}"   # seconds between runs (kept short for the demo)
runs="${RUNS:-3}"           # number of iterations to show

cleanup() {
  "$kern" stop nightly-report >/dev/null 2>&1 || true
  "$kern" gc >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "==> running a capped one-shot job every ${interval}s, ${runs} times."
echo "    each iteration is a fresh box (64m RAM, 0.5 CPU) that cleans itself up on exit."
echo

i=1
while [ "$i" -le "$runs" ]; do
  echo "--- tick $i/$runs at $(date -u +%H:%M:%S) UTC ---"
  # A fresh, capped, isolated box for this tick. Foreground: it runs the job and is gone after.
  # The box name is reused each tick precisely BECAUSE the previous run removed itself.
  "$kern" box nightly-report --image alpine --memory 64m --cpus 0.5 -- \
    sh -c 'echo "  job running as $(id -un) in an isolated box; uptime slice:"; \
           echo "  $(cat /proc/loadavg)"; \
           echo "  (this box exists only for the duration of this command)"'
  i=$((i + 1))
  [ "$i" -le "$runs" ] && sleep "$interval"
done

echo
echo "==> done - no box, no daemon, no scheduler left running."
echo "    To run this for real on a schedule, add ONE line to the host's crontab, e.g.:"
echo "      */5 * * * *  kern box nightly-report --image alpine --memory 64m --cpus 0.5 -- <job>"
