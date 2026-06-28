#!/bin/sh
# Deliver secrets into a box WITHOUT baking them into the image or the environment.
#
#   --secret NAME=-        read the value from kern's stdin (never hits argv / the process table)
#   --secret SRC[:NAME]    read a host file (NAME defaults to the file's basename)
#   --secret NAME=value    inline literal — convenient, but visible in `ps` and recorded in the
#                          systemd journal, so prefer the stdin or file forms for real secrets
#
# Each secret is read on the HOST, before the box's namespaces exist, then written to a RAM-backed
# tmpfs at /run/secrets/<name> (mode 0400) INSIDE the box. It therefore never lands in the image's
# writable overlay and is gone the instant the box exits. This is the sanctioned alternative to
# `-e API_KEY=...` (which leaks into the child's environment and `/proc/<pid>/environ`).
set -eu
kern="${KERN:-kern}"

# A host secret file (chmod 600 — a world-writable secret source is refused, group/world-readable
# is warned about). Cleaned up on exit.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf 'super-secret-db-password\n' > "$work/db.pass"
chmod 600 "$work/db.pass"

echo "==> 1. deliver two secrets: one from a FILE, one from STDIN (argv-free):"
# The file form names the in-box file explicitly (":db_password"); the value piped on stdin becomes
# /run/secrets/api_token. The box reads them, then proves the mode and the backing filesystem.
printf '%s' 'tok_live_abc123' | "$kern" box vault --image alpine \
  --secret "$work/db.pass:db_password" \
  --secret api_token=- \
  -- /bin/sh -c '
    echo "   /run/secrets contains: $(ls /run/secrets | tr "\n" " ")"
    echo "   db_password = $(cat /run/secrets/db_password)"
    echo "   api_token   = $(cat /run/secrets/api_token)"
    echo
    echo "   permissions (expect -r-------- / 0400, owner read-only):"
    ls -l /run/secrets/db_password | sed "s/^/     /"
    echo "   mode = $(stat -c %a /run/secrets/db_password)"
    echo
    echo "   backing filesystem (expect tmpfs = RAM, NOT the image overlay):"
    grep " /run/secrets " /proc/mounts | awk "{print \"     type:\", \$3, \" opts:\", \$4}"
  '

echo
echo "==> 2. the secret is EPHEMERAL — a second box (no --secret) sees nothing:"
# Nothing was written to the image, so a fresh box from the same image has an empty (or absent)
# /run/secrets. Proof the secret lived only in RAM for the first box's lifetime.
"$kern" box plain --image alpine -- /bin/sh -c '
  if [ -d /run/secrets ] && [ -n "$(ls -A /run/secrets 2>/dev/null)" ]; then
    echo "   unexpected: /run/secrets still has content"
  else
    echo "   /run/secrets is empty / absent — the secret never touched the image ✓"
  fi
'

echo
echo "done — secrets ride in on a 0400 tmpfs, stay out of argv/env/overlay, and vanish on exit."
# Both boxes ran in the foreground and their ephemeral overlays are already gone; only the temp
# secret file remains, and the trap above removes it.
