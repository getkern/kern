#!/bin/sh
# Per-task sandboxing at scale: run many isolated jobs in parallel.
#
# Because a box has no daemon and starts in milliseconds, you can give EACH unit of work its own
# throwaway sandbox — untrusted user submissions, fuzz cases, build matrix shards — with an
# ordinary shell loop. Here: 50 jobs, isolated, in parallel, with their results collected.
set -eu
kern="${KERN:-kern}"
n="${1:-50}"

echo "running $n isolated jobs (parallel)..."
start=$(date +%s)
seq 1 "$n" | xargs -P"$(nproc)" -I{} \
  "$kern" box "job{}" --image alpine -- /bin/sh -c 'echo "job {} on $(hostname): $(( {} * {} ))"' \
  | sort -t' ' -k2 -n | head -5
echo "... (first 5 shown)"
echo "done $n jobs in $(( $(date +%s) - start ))s — each in its own sandbox."
