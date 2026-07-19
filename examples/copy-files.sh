#!/bin/sh
# Move single files across the sandbox boundary with `kern cp` - the `docker cp` analogue.
#
#   kern cp <hostsrc> <box>:<dst>    copy a host file INTO a running box
#   kern cp <box>:<src> <hostdst>    copy a file OUT of a running box
#
# Exactly one side must be `<box>:<path>` (a running box name). `kern cp` moves single regular
# FILES only (not directories, FIFOs, devices) and the box-side open is resolved *inside the box's
# root* (openat2 RESOLVE_IN_ROOT), so a symlink planted in the image can't redirect the copy to a
# host path outside the box. A directory destination takes the source basename, `docker cp`-style.
set -eu
kern="${KERN:-kern}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
echo "hello-from-host" > "$work/from-host.txt"

echo "==> start a detached box to copy against:"
"$kern" box files --image alpine -d -- /bin/sh -c 'while true; do sleep 1; done'
sleep 1

echo
echo "==> copy a host file INTO the box (host -> box:/tmp):"
"$kern" cp "$work/from-host.txt" files:/tmp/from-host.txt

echo "==> the box can now read it:"
"$kern" exec files -- /bin/sh -c 'cat /tmp/from-host.txt'

echo
echo "==> have the box produce a file, then copy it OUT (box -> host):"
"$kern" exec files -- /bin/sh -c 'echo "computed-in-box: $(date +%s)" > /tmp/result.txt'
"$kern" cp files:/tmp/result.txt "$work/result.txt"
echo "==> host now has it:"
cat "$work/result.txt"

echo
echo "==> the copy stays confined. Plant a symlink in the box aimed at an absolute path,"
echo "    then copy it out - it resolves inside the BOX root, so we get the box's own file,"
echo "    never the host's /etc/passwd:"
"$kern" exec files -- /bin/sh -c 'ln -sf /etc/hostname /tmp/escape'
"$kern" cp files:/tmp/escape "$work/escape.txt"
echo "    copied (box-side target): $(cat "$work/escape.txt")   <- box hostname, not a host file"

echo
echo "==> cleanup:"
"$kern" stop files
