#!/bin/sh
# Who runs inside the box? - single-uid (default), a full sub-uid RANGE, and dropping to a
# specific non-root uid with --user.
#
# kern is rootless: the box's root (uid 0) always maps to YOUR unprivileged host uid - the box
# gains no privilege on the host. By DEFAULT only that one id is mapped ("single-uid": fastest,
# smallest attack surface). Two flags change the mapping:
#
#   --uid-range        map a whole subordinate uid/gid RANGE (~65k ids) into the box, so a
#                      workload can use ids other than 0 - apt/dpkg, an image that runs as
#                      www-data/postgres, or a `chown` to a service uid.
#   --user UID[:GID]   drop to this uid/gid inside the box before the command runs (like Docker's
#                      -u / USER). A non-root --user needs the range mapping, so kern turns it on
#                      for you automatically.
#
# --uid-range (and therefore a non-root --user) needs the shadow helpers `newuidmap`/`newgidmap`
# AND a subordinate-id allocation for you in /etc/subuid + /etc/subgid. If either is absent, kern
# prints a warning and FALLS BACK to the single-uid map - the box still runs, but a drop to a
# non-zero uid will fail. This script detects that up front and degrades honestly.
set -eu
kern="${KERN:-kern}"
img="${IMG:-alpine}"

# Mirror kern's own precondition check so we can narrate what to expect (not a security decision -
# kern makes the real call itself and falls back gracefully either way).
have_range=no
if command -v newuidmap >/dev/null 2>&1 &&
   [ -f /etc/subuid ] && grep -q "^$(id -un):" /etc/subuid 2>/dev/null; then
  have_range=yes
fi
echo "==> host has newuidmap + an /etc/subuid range for $(id -un)? ...  $have_range"
echo

echo "── 1. DEFAULT box: single-uid map - box root (uid 0) == your host uid"
"$kern" box mu-single --image "$img" -- id
echo "   (uid=0 inside, but it's YOUR unprivileged uid on the host - no privilege gained)"

echo
echo "── 2. --uid-range: a whole subordinate id range is mapped in"
echo "   Proof: chown a file to a NON-zero uid inside the box. Only the range makes uid 100 exist."
echo "   • single-uid box (expected: chown fails - uid 100 isn't mapped):"
set +e
"$kern" box mu-nomap --image "$img" -- \
  sh -c ': > /tmp/f && chown 100:100 /tmp/f && echo "     chowned to 100 (unexpected here)" \
         || echo "     chown 100 refused - only uid 0 is mapped, as expected"'
echo "   • --uid-range box (expected: chown succeeds - uid 100 is in the mapped range):"
"$kern" box mu-range --image "$img" --uid-range -- \
  sh -c ': > /tmp/f && chown 100:100 /tmp/f && stat -c "     owner uid=%u gid=%g - the range mapped it" /tmp/f \
         || echo "     chown 100 failed (no subuid range on this host - see the note below)"'
set -e

echo
echo "── 3. --user 1000: run the workload as a specific non-root uid"
echo "   (kern auto-enables the range mapping so uid 1000 exists inside the box)"
if [ "$have_range" = yes ]; then
  "$kern" box mu-user --image "$img" --user 1000 -- id
  echo "   -> the command ran as uid=1000, not root ✓"
else
  echo "   Skipped: no newuidmap + /etc/subuid on this host, so a drop to uid 1000 can't be mapped."
  echo "   kern would warn and the setuid would fail. To enable it:"
  echo "     - install the shadow 'newuidmap'/'newgidmap' helpers (uidmap package), and"
  echo "     - add a range, e.g.:  echo \"$(id -un):100000:65536\" | sudo tee -a /etc/subuid /etc/subgid"
  echo "   The single-uid boxes above still ran fully - only the non-root drop needs the range."
fi

echo
echo "done - every box was rootless; boxes and any files they wrote are discarded on exit."
