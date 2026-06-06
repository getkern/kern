#!/bin/sh
# A quick tour of a day's work in kern — a throwaway tool, your code in a clean
# image, governed resources, untrusted code held at arm's length, and a
# background service. Each one isolated, daemonless, and gone when it's done.
set -eu
kern="${KERN:-kern}"
ms() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }
step() { echo; echo "── $1"; }

step "1. a tool from a clean image — nothing installed on your host"
t=$(date +%s%N)
"$kern" box tool --image alpine -- sh -c '. /etc/os-release; echo "   hello from $PRETTY_NAME"'
echo "   the box started, ran, and vanished in $(ms "$t") ms"

step "2. run against your own code, in that clean image"
work=$(mktemp -d); printf 'echo "   build ok"; echo "   tests: 3 passed"\n' > "$work/ci.sh"
"$kern" box ci --image alpine -v "$work:/src" -w /src -- sh ci.sh
echo "   your files stayed yours; the toolchain was the box's, not your host's"
rm -rf "$work"

step "3. governed resources — a box capped to 256 MB / 1 core"
"$kern" box worker --image alpine --memory 256m --cpus 1 -- sh -c 'echo "   working within the cap"'

step "4. untrusted code, held at arm's length — no network, read-only root"
"$kern" box sketchy --image alpine --read-only --network none -- sh -c '
  wget -q -T 2 -O- http://example.com >/dev/null 2>&1 && echo "   network: reachable (unexpected)" || echo "   network:        blocked"
  ( echo x > /nope ) 2>/dev/null && echo "   root fs: writable (unexpected)"       || echo "   root filesystem: read-only"
'

step "5. a background service, then cleaned up — no daemon"
"$kern" box svc --image alpine -d -- sh -c 'while true; do sleep 5; done' >/dev/null
"$kern" ps
"$kern" stop svc >/dev/null

step "done"
echo "No daemon is running. Nothing was installed on your host. Every box was"
echo "isolated, and they're all already gone."
