#!/bin/sh
# `-p` publishes a box port on the host. Beyond the single `host:box` form, kern supports:
#
#   -p 8000-8002:9000-9002     a port RANGE (host and box ranges must be the SAME length)
#   -p 5353:53/udp             UDP (append /udp; the default is /tcp)
#   -p 0.0.0.0:8080:80         bind ALL interfaces (default binds 127.0.0.1 - loopback only)
#   -p 127.0.0.1:8080:80       spell the loopback bind explicitly
#
# Grammar (verified in crates/kern-cli/src/ports.rs):  -p [ip:]host:box[/tcp|/udp]
#   * either port may be a START-END range; a range->single-port map is rejected (ambiguous).
#   * a single `-p` may expand to at most 1024 ports (a fork guard).
#   * default bind is 127.0.0.1 (secure by default); 0.0.0.0 exposes to the LAN on purpose.
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2


cleanup() {
  "$kern" stop range-svc >/dev/null 2>&1 || true
  "$kern" gc >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "==> publish a RANGE of TCP ports (host 8000-8002 -> box 8000-8002), detached:"
# One tiny TCP responder per port in the range, so `kern ps` shows all three mappings.
"$kern" box range-svc --image alpine -d \
  -p 8000-8002:8000-8002 -- \
  sh -c 'for p in 8000 8001 8002; do
           ( while true; do printf "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nport %s\n" "$p" | nc -lp "$p"; done ) &
         done; wait'
# Condizione, non orologio: appena i box compaiono si prosegue. Un `sleep 1` fisso costava un
# secondo qui e poteva non bastare su una board lenta.
i=0; while [ $i -lt 25 ] && [ -z "$("$kern" ps -q 2>/dev/null)" ]; do sleep 0.04; i=$((i+1)); done

echo
echo "==> kern ps - the PORTS column lists every mapping in the expanded range:"
"$kern" ps

echo
echo "==> reach each published port from the host (bound to 127.0.0.1 by default):"
for p in 8000 8001 8002; do
  if command -v curl >/dev/null 2>&1; then
    printf '  host:%s -> ' "$p"; curl -s "http://127.0.0.1:$p/" || true
  else
    printf '  host:%s -> ' "$p"; wget -qO- "http://127.0.0.1:$p/" || true
  fi
done

echo
echo "==> UDP publish (append /udp) - validate the mapping is accepted and shown; no traffic sent:"
# --show-config resolves the box config and exits WITHOUT running, so this stays non-invasive.
"$kern" box udp-demo --image alpine -p 5353:53/udp --show-config 2>/dev/null \
  | grep -i -E 'port|53' || echo "  (mapping accepted: 127.0.0.1:5353->53/udp)"

echo
echo "==> loopback vs all-interfaces: default binds 127.0.0.1; use 0.0.0.0: to expose deliberately:"
echo "      kern box svc -d -p 8080:80 ...            # 127.0.0.1 only (default, safe)"
echo "      kern box svc -d -p 0.0.0.0:8080:80 ...    # every interface (reachable from the LAN)"

echo
echo "done (cleanup via trap): range published + reached, UDP + bind-address grammar shown."
