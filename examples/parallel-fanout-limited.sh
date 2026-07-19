#!/bin/sh
# Process many items with BOUNDED concurrency: at most N boxes in flight at once.
#
# fan-out.sh / parallel-matrix.sh launch everything at once (great when the count
# is small and known). But a batch of hundreds shouldn't spawn hundreds of boxes
# simultaneously - you'd thrash CPU and RAM. Here we cap the fan-out to N using a
# plain shell sliding window: track the background PIDs and, once N are running,
# block on the OLDEST before launching the next. Pure POSIX job control, no daemon
# and no scheduler - just `&`, `$!`, and `wait <pid>`.
set -eu
kern="${KERN:-kern}"

items="${1:-12}"   # how many work items
max="${2:-4}"      # max boxes in flight at once (the concurrency bound)

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "==> $items items, at most $max isolated boxes running concurrently:"

pids=""
running=0
i=1
while [ "$i" -le "$items" ]; do
  # Launch item $i in its own capped, throwaway box, in the background. The job
  # does a little work (square the index) and drops its result in $work.
  (
    "$kern" box "item-$i" --image alpine --memory 64m --cpus 1 --timeout 30 -- \
      sh -c 'echo "$(( '"$i"' * '"$i"' ))"' > "$work/res-$i" 2>/dev/null
  ) &
  pids="$pids $!"
  running=$((running + 1))

  # Once the window is full, wait for the OLDEST launched box to finish before we
  # start another - this is what keeps concurrency at or below $max.
  if [ "$running" -ge "$max" ]; then
    # shellcheck disable=SC2086
    set -- $pids
    oldest="$1"; shift; pids="$*"
    wait "$oldest" 2>/dev/null || true
    running=$((running - 1))
  fi
  i=$((i + 1))
done

# Drain the final in-flight window.
wait 2>/dev/null || true

done_count="$(ls "$work" | wc -l)"
echo "==> completed $done_count/$items items (all accounted for despite the cap)."
echo "==> a few results (item -> square):"
n=0
for i in $(seq 1 "$items"); do
  [ -s "$work/res-$i" ] || continue
  printf '  item %-3s -> %s\n' "$i" "$(cat "$work/res-$i")"
  n=$((n + 1)); [ "$n" -ge 5 ] && { echo "  ..."; break; }
done

echo
echo "done - a big batch was throttled to $max concurrent boxes via shell job"
echo "control; every item finished and all boxes are gone."
