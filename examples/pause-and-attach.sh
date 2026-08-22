#!/bin/sh
# Freeze a box's processes and reconnect to a detached box's output - no daemon involved.
#
#   kern pause <name>     freeze EVERY process in the box atomically (cgroup v2 freezer)
#   kern unpause <name>   thaw it again  (aliases: freeze/unfreeze, resume)
#   kern attach <name>    stream a detached box's captured output live (Ctrl-C detaches, box lives)
#
# `pause` uses the kernel cgroup freezer (`cgroup.freeze`), so the freeze is real and atomic - the
# box makes zero progress while frozen. `attach` follows the box's log file, so it only works on a
# DETACHED (`-d`) box, which is the one that logs to a file.
set -eu
kern="${KERN:-kern}"

# Ticks five times a second, not once. The demonstration needs a HANDFUL of ticks, not a handful
# of seconds: at 1 Hz this example spent 8 of its 10 seconds asleep, which is a long time to ask of
# someone reading it for the first time.
echo "==> start a detached box that ticks 5x a second and records each tick:"
"$kern" box ticker --image alpine -d -- \
  /bin/sh -c 'i=0; while true; do i=$((i+1)); echo "tick $i"; sleep 0.2; done'
sleep 1

echo
echo "==> it has been running ~1s, so a few ticks are in the log:"
"$kern" logs ticker | tail -2
before="$("$kern" logs ticker | wc -l)"

echo
echo "==> freeze it with kern pause - every process in the box stops dead:"
# `pause` is the cgroup-v2 freezer, so it needs the box to have a cgroup of its own. Where no
# systemd user manager is reachable kern refuses it by name instead of pretending, and this example
# has nothing left to show - so it SKIPS with that reason rather than dying half-read. Any OTHER
# pause failure is still a failure: only the documented unsupported case is classified as a skip.
if ! pause_err="$("$kern" pause ticker 2>&1)"; then
    case "$pause_err" in
        *"no dedicated cgroup"*)
            echo "    $pause_err"
            echo
            echo "SKIPPED: this host has no delegated cgroup, so the freezer is unavailable."
            echo "         Everything above ran; \`kern doctor\` explains the delegation state."
            "$kern" stop ticker >/dev/null 2>&1 || true
            exit 0
            ;;
        *) echo "$pause_err" >&2; exit 1 ;;
    esac
fi
# A full second is FIVE ticks' worth at this rate: if the freeze leaked even one, the count moves.
sleep 1

after_pause="$("$kern" logs ticker | wc -l)"
echo "    log lines before pause: $before   after 1s frozen (5 ticks' worth): $after_pause  (unchanged = truly frozen)"

echo
echo "==> thaw it with kern unpause - it resumes exactly where it left off:"
"$kern" unpause ticker
sleep 1
echo "    ticks resume:"
"$kern" logs ticker | tail -2

echo
echo "==> reconnect to its live output with kern attach (Ctrl-C detaches; the box keeps running)."
echo "    Interactive by design, so here we follow it for ~2s and then detach:"
# `attach` follows the log until you Ctrl-C; bound it with `timeout` in a non-interactive script.
timeout 2 "$kern" attach ticker || true

echo
echo "==> cleanup:"
"$kern" stop ticker
