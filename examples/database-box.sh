#!/bin/sh
# A stateful DATA SERVICE that survives its box: run redis detached on a NAMED VOLUME,
# write a key, throw the box away, start a NEW box on the SAME volume, read the key back.
#
#   kern box <name> --image redis -d -p H:B -v <vol>:/data --uid-range   detached redis + persistence
#   kern exec <name> -- redis-cli ...                                     talk to it (no host client needed)
#   kern volume create|inspect|rm                                        manage the named volume
#
# WHY --uid-range: the official redis image's entrypoint drops privilege to the `redis` service
# user (uid 999) via gosu. A single-uid box can't map that uid, so the drop fails. --uid-range
# maps a subordinate uid range so the entrypoint works. It needs the `uidmap` helpers
# (newuidmap/newgidmap) installed - standard on desktop Linux; on a host without them kern warns
# and falls back to single-uid (where this recipe's redis would not start).
#
# WHY the data survives: redis persists to /data/dump.rdb, and /data is a kern-managed NAMED
# volume that OUTLIVES any box. Box B mounts the very same volume and redis loads the RDB on boot.
set -eu
kern="${KERN:-kern}"

vol="kern_redis_data"
port="${PORT:-6379}"

cleanup() {
  "$kern" stop dbA dbB >/dev/null 2>&1 || true
  "$kern" volume rm "$vol" >/dev/null 2>&1 || true
  "$kern" gc >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Start from a clean slate in case a previous run left the volume behind.
"$kern" volume rm "$vol" >/dev/null 2>&1 || true

echo "==> 1. create a named volume for the database's /data:"
"$kern" volume create "$vol" --size 64m
"$kern" volume inspect "$vol" | sed 's/^/   /'

echo
echo "==> 2. start redis (box 'dbA') detached, published on 127.0.0.1:$port, data on the volume:"
"$kern" box dbA --image redis -d --uid-range \
  -p "$port:6379" -v "$vol:/data" \
  -- redis-server --dir /data --appendonly no

echo "==> waiting for redis to answer PING..."
i=0
while [ "$i" -lt 25 ]; do
  if "$kern" exec dbA -- redis-cli PING 2>/dev/null | grep -q PONG; then break; fi
  i=$((i + 1)); sleep 1
done
[ "$i" -lt 25 ] || { echo "   redis did not come up"; exit 1; }
echo "   redis is up (see the PORTS column):"
"$kern" ps | sed 's/^/   /'

echo
echo "==> 3. write a key, then force a synchronous save to /data/dump.rdb:"
"$kern" exec dbA -- redis-cli SET kern:greeting "hello from a box that no longer exists" >/dev/null
"$kern" exec dbA -- redis-cli SAVE >/dev/null
echo "   wrote kern:greeting and flushed the RDB to the volume."

echo
echo "==> 4. STOP and discard box dbA entirely (the container is gone; only the volume remains):"
"$kern" stop dbA >/dev/null

echo
echo "==> 5. start a BRAND-NEW box 'dbB' on the SAME volume and read the key back:"
"$kern" box dbB --image redis -d --uid-range \
  -p "$port:6379" -v "$vol:/data" \
  -- redis-server --dir /data --appendonly no
i=0
while [ "$i" -lt 25 ]; do
  if "$kern" exec dbB -- redis-cli PING 2>/dev/null | grep -q PONG; then break; fi
  i=$((i + 1)); sleep 1
done
[ "$i" -lt 25 ] || { echo "   redis did not come up"; exit 1; }
value="$("$kern" exec dbB -- redis-cli GET kern:greeting)"
printf '   dbB reads back: %s\n' "$value"
echo "   -> the data survived the box: persistence lives in the named volume, not the container."

echo
echo "==> cleanup (via trap): stop dbB, remove the volume, kern gc."
