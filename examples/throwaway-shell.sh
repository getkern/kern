#!/bin/sh
# An ephemeral, writable shell in an image - like `docker run --rm -it`, but no daemon.
#
# Install packages, scribble files, break things: it all lands in a private overlay that's
# thrown away when the shell exits. The cached image stays pristine for the next run.
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2


# Non-interactive demo of a throwaway session (swap the `-c '...'` for nothing to get a real
# interactive shell when run from a terminal):
"$kern" box scratch --image alpine -- /bin/sh -c '
  echo "before: /tmp has $(ls /tmp | wc -l) entries"
  echo "scribbling..."; for i in 1 2 3; do echo "line $i" >> /tmp/notes; done
  echo "after:  /tmp/notes ="; cat /tmp/notes
  echo "(this whole filesystem is discarded when the box exits)"
'

# Proof the image is untouched: a fresh box does not see the previous writes.
"$kern" box scratch --image alpine -- /bin/sh -c '
  test -f /tmp/notes && echo "LEAKED" || echo "fresh box: /tmp/notes is gone ✓"
'
