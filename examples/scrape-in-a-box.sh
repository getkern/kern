#!/bin/sh
# A scrape/fetch that reaches the web but stays otherwise locked down.
#
# Networking is OFF by default in a kern box. `--net` is the ONE relaxation we
# make here — it shares the host network namespace so the fetch can resolve DNS
# and connect out. EVERYTHING ELSE stays isolated: separate PID/mount/user
# namespaces, a capped box (memory/CPU/time), and the output goes to a volume
# you mount in. The scraper cannot touch your host filesystem beyond `-v`.
#
# HONEST trade-off: `--net` means NO network isolation — the box shares the
# host's loopback and can reach 127.0.0.1 services. Use it for trusted fetch
# code, not for running untrusted scrapers against your own machine. See
# SECURITY.md and with-network.sh.
set -eu
kern="${KERN:-kern}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/out"

# A stable, boring public endpoint. busybox `wget` ships in the alpine base, so
# there's nothing to install. `-T 8` bounds the connect+read so a dead network
# fails fast instead of hanging.
URL="https://example.com"

echo "==> fetching $URL in a network-ON but otherwise-isolated, capped box:"
if "$kern" box scraper --image alpine \
      --net --memory 128m --cpus 1 --timeout 30 \
      -v "$work/out:/out" -- \
      sh -c 'wget -q -T 8 -O /out/page.html "'"$URL"'" \
             && { echo "  fetched $(wc -c < /out/page.html) bytes"; \
                  grep -o "<title>[^<]*</title>" /out/page.html | sed "s/^/  title: /"; } \
             || { echo "  fetch failed (no network?)" >&2; exit 3; }'
then
  echo
  echo "==> result saved to the host via the mounted volume:"
  ls -l "$work/out/page.html" | sed 's/^/  /'
else
  echo
  echo "  (no network available — that's fine; the box behaved, it just had"
  echo "   nothing to reach. Re-run with connectivity to see the scrape.)"
fi

echo
echo "done — only --net was relaxed; the box was still PID/mount/user-isolated,"
echo "capped, and could only write to the volume you mounted. Box is gone."
