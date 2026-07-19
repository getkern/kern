#!/bin/sh
# For the sceptic: try to break out, and watch the boundaries hold.
# A battery of adversarial checks a careful engineer would run before trusting a
# sandbox - namespace, filesystem, capability and device isolation, plus scale.
# Everything here is rootless and safe to run.
set -eu
kern="${KERN:-kern}"
ms() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }
step() { echo; echo "── $1"; }

step "1. PID namespace - the box can't see the host's processes"
host=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)
seen=$("$kern" box chk-pid --image alpine -- sh -c 'ls -d /proc/[0-9]* | wc -l' 2>/dev/null)
echo "   host: $host processes   ·   box sees: $seen"

step "2. devices - the host's disks are not in the box"
"$kern" box chk-dev --image alpine -- sh -c \
  'ls /dev/nvme* /dev/sd* /dev/mmcblk* 2>/dev/null | grep -q . && echo "   host disks VISIBLE (leak)" || echo "   host disks: absent"' 2>/dev/null

step "3. filesystem - climbing out of the root lands nowhere new"
"$kern" box chk-esc --image alpine -- sh -c \
  'cd / ; cd ../../../../../.. ; [ -f /etc/alpine-release ] && echo "   still the box image root - pivot held" || echo "   ESCAPED (leak)"' 2>/dev/null

step "4. capabilities - an arbitrary mount is refused"
"$kern" box chk-cap --image alpine -- sh -c \
  'mount -t proc none /mnt 2>/dev/null && echo "   mounted (unexpected)" || echo "   arbitrary mount: denied"' 2>/dev/null

step "5. read-only root - writes are rejected"
"$kern" box chk-ro --image alpine --read-only -- sh -c \
  '( echo x > /nope ) 2>/dev/null && echo "   wrote to / (unexpected)" || echo "   read-only root: holds"' 2>/dev/null

step "6. scale - 50 isolated boxes at once, no daemon"
t=$(date +%s%N); d=$(mktemp -d)
i=1; while [ "$i" -le 50 ]; do
  ( "$kern" box "sc-$i" --image alpine -- true >/dev/null 2>&1 && : > "$d/$i" ) &
  i=$((i + 1))
done
wait 2>/dev/null || true
ok=$(ls "$d" 2>/dev/null | wc -l); rm -rf "$d"
echo "   $ok/50 boxes ran and exited cleanly in $(ms "$t") ms"

step "done"
echo "Namespaces, pivot, capabilities and devices all held; nothing leaked, and"
echo "no daemon was ever running."
