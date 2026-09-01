#!/bin/sh
# `kern ps` for automation (Docker-parity): `-q`, `--filter key=value`, and `--format '{{.Field}}'`.
# The three ops one-liners you actually reach for:
#
#   kern ps -q                         -> names only, one per line: `kern stop $(kern ps -q)`
#   kern ps --filter name=web          -> target a subset (keys: name=, status=running|paused, id=<pid>)
#   kern ps --format '{{.Names}}\t{{.Status}}'  -> one TSV line per box, feed straight into awk/monitoring
#
# Fields: {{.Names}} {{.Pid}} {{.Image}} {{.Command}} {{.Ports}} {{.Pod}} {{.Status}} {{.RunningFor}}.
# Real-life: a cron that pipes `--format` into a health dashboard; a cleanup that reaps every box
# matching a prefix; stopping a whole fleet with one command substitution.
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2

img="${IMG:-alpine}"
pfx="psdemo$$"

cleanup() {
  for n in a b c; do "$kern" stop "${pfx}${n}" >/dev/null 2>&1 || true; done
  "$kern" gc >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> launch a small fleet of detached boxes (${pfx}a/b/c):"
for n in a b c; do
  "$kern" box "${pfx}${n}" --image "$img" -d -- sh -c 'sleep 120' >/dev/null
done
# Condizione, non orologio: appena i box compaiono si prosegue. Un `sleep 1` fisso costava un
# secondo qui e poteva non bastare su una board lenta.
i=0; while [ $i -lt 25 ] && [ -z "$("$kern" ps -q 2>/dev/null)" ]; do sleep 0.04; i=$((i+1)); done

echo
echo "==> ps --format: one TSV line per box, custom columns (\\t becomes a real tab for awk):"
"$kern" ps --format '{{.Names}}\t{{.Status}}\t{{.RunningFor}}' | grep "$pfx" | sort

echo
echo "==> ps --filter (name= AND status=running), rendered with a custom sentence:"
"$kern" ps --filter "name=$pfx" --filter status=running \
  --format '{{.Names}} is {{.Status}}' | sort

echo
echo "==> ps -q + command substitution: stop THIS fleet in one line."
echo "    We filter to our prefix so unrelated boxes on this host are never touched:"
ids="$("$kern" ps -q | grep "$pfx" || true)"
echo "    stopping: $ids"
# shellcheck disable=SC2086
[ -n "$ids" ] && "$kern" stop $ids >/dev/null
printf '==> fleet stopped; boxes matching our prefix still running: '
"$kern" ps -q | grep -c "$pfx" || true
