#!/bin/sh
# A fresh, isolated sandbox for every request.
#
# A box starts in a few milliseconds, so you can spin up a brand-new one per
# call instead of reusing a long-lived process - the pattern behind function /
# serverless runtimes. Each request runs untrusted input in its own box, with
# its own namespaces, and leaves nothing behind.
set -eu
kern="${KERN:-kern}"

# Handle one request: pipe the payload into a fresh box that runs a "handler"
# and prints a reply. `$(hostname)` inside the box is the box's own name, so you
# can see each request gets a different, isolated box.
handle() {
  n="$1"; payload="$2"
  printf '%s' "$payload" | "$kern" box "req-$$-$n" --image alpine -- \
    sh -c 'read -r req; echo "handled: $req   (box=$(hostname))"'
}

i=0
for payload in '{"n":1}' '{"user":"amy"}' '{"n":3}'; do
  i=$((i + 1))
  printf 'request   %s\n' "$payload"
  printf 'response  %s\n\n' "$(handle "$i" "$payload")"
done

echo "Each request ran in its own fresh box - different name, no shared state."
