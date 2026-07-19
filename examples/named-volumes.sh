#!/bin/sh
# A NAMED volume: persistent storage referenced by name, shared across boxes.
#
#   kern volume create <name> [--size N]   create a named volume (optionally record a quota)
#   -v <name>:/dest[:ro]                    mount it in a box (auto-created on first use, Docker-style)
#   kern volume ls | inspect | rm           manage them
#
# Unlike a `-v /host/path:/dest` bind (see mounts-and-exec.sh) a named volume is kern-managed storage
# under ~/.local/share/kern/volumes/<name>/ - you never pick a host path. It OUTLIVES the box, so
# box A can write data that box B reads later. Fully rootless: the volume is a directory kern
# bind-mounts.
set -eu
kern="${KERN:-kern}"

vol="kern_example_data"

# Start clean in case a previous run left it behind.
"$kern" volume rm "$vol" >/dev/null 2>&1 || true

echo "==> 1. create a named volume with a recorded quota:"
# --size accepts binary units (16m, 2g, ...). See the note in step 4 on when the quota is ENFORCED.
"$kern" volume create "$vol" --size 16m
"$kern" volume inspect "$vol" | sed 's/^/   /'

echo
echo "==> 2. box A WRITES into the volume (mounted at /work):"
"$kern" box writer --image alpine \
  -v "$vol:/work" \
  -- /bin/sh -c 'echo "hello from box A at $(date -u +%H:%M:%S)" > /work/message.txt; echo "   wrote /work/message.txt"'

echo
echo "==> 3. box B - a SEPARATE box - READS it back (persistence across boxes):"
"$kern" box reader --image alpine \
  -v "$vol:/work:ro" \
  -- /bin/sh -c 'echo "   box B sees: $(cat /work/message.txt)"'

echo
echo "==> 4. the --size quota:"
# HONEST: a named-volume quota is a real, enforced ext4-loop disk quota ONLY when kern can build the
# loop image - a plain foreground box run as root or in the `disk` group. Rootless (this script), kern
# mounts the plain data directory and tells you the quota is NOT enforced. `kern volume inspect`
# reports the recorded cap either way. For an ENFORCED size cap that works fully rootless, use a
# `vdisk:` scratch disk instead - see vdisk-scratch.sh (a size-capped tmpfs).
"$kern" volume inspect "$vol" | grep -i quota | sed 's/^/   /'
echo "   (rootless: recorded but not enforced; root/disk-group upgrades it to an ext4-loop quota)"

echo
echo "==> cleanup:"
# The boxes ran in the foreground and are already gone; remove the volume (refused while a box still
# mounts it - Docker's behaviour).
"$kern" volume rm "$vol"
echo "done - named volumes are kern-managed, persist across boxes, and are removed explicitly."
