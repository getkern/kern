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

echo "==> start a detached box that ticks once a second and records each tick:"
"$kern" box ticker --image alpine -d -- \
  /bin/sh -c 'i=0; while true; do i=$((i+1)); echo "tick $i"; sleep 1; done'
sleep 3

echo
echo "==> it has been running ~3s, so a few ticks are in the log:"
"$kern" logs ticker | tail -2
before="$("$kern" logs ticker | wc -l)"

echo
echo "==> freeze it with kern pause - every process in the box stops dead:"
"$kern" pause ticker
sleep 3   # 3 real seconds pass, but the frozen box produces no new ticks

after_pause="$("$kern" logs ticker | wc -l)"
echo "    log lines before pause: $before   after 3s frozen: $after_pause  (unchanged = truly frozen)"

echo
echo "==> thaw it with kern unpause - it resumes exactly where it left off:"
"$kern" unpause ticker
sleep 2
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
