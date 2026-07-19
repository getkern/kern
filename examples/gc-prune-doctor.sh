#!/bin/sh
# Housekeeping for a daemonless runtime: check the host, then reclaim what dead boxes leave behind.
#
#   kern doctor          preflight - will boxes even run on THIS host, and which optional
#                        features (user namespaces, cgroup delegation, netns, ...) are available?
#   kern prune           delete the leftover log / health / registry files of boxes that are no
#                        longer running (kern has no daemon reaping them for you)
#   kern gc              prune + sweep orphaned build layers; `kern gc --images` ALSO wipes the
#                        pulled-image cache (you'd re-pull on next use - not run here, to stay
#                        non-invasive to your image cache)
set -eu
kern="${KERN:-kern}"

echo "==> kern doctor - is this host able to run boxes, and what's available?"
# Exit status is non-zero if the host can't run boxes at all; keep going either way so the rest
# of the tour still demonstrates prune/gc.
"$kern" doctor || echo "(doctor reported problems above)"

echo
echo "==> create and stop a box so there's some dead-box residue to clean up:"
"$kern" box scratch --image alpine -d -- /bin/sh -c 'echo hi; while true; do sleep 1; done'
sleep 1
"$kern" stop scratch
sleep 1

echo
echo "==> kern prune - reap the log/health/registry files left by boxes no longer running:"
"$kern" prune

echo
echo "==> kern gc - prune again, plus sweep any orphaned build layers. Idempotent, so a second"
echo "    run right after should report nothing left to do:"
"$kern" gc

echo
echo "==> note: 'kern gc --images' additionally clears the pulled-image cache (frees disk, but you"
echo "    re-pull on next use). Not run here so we don't disturb your cached images. To try it:"
echo "        kern gc --images"

echo
echo "==> done - nothing left to clean up."
