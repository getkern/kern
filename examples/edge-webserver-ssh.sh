#!/bin/sh
# A web server on a headless board: published to the LAN, with ssh into the box.
#
# This is the shape that works, and the two things people get wrong on a board are both here.
#
#   1. BUILD with --net, SERVE without it. A box's default network is an isolated namespace with no
#      route out, so `apk add` needs `--net` (which shares the HOST network). But `-p` cannot be
#      combined with `--net`, and not as a technicality: with a shared network the box has no port of
#      its own, so kern would be forwarding to whichever HOST process holds that number. So: one box
#      with --net and NO ports to build the image, then a second box with -p and no --net to serve it.
#
#   2. Lingering. A detached box lives in a systemd scope under `user@<uid>.service`. Without
#      lingering, systemd stops that service when your last ssh session ends and the box dies with it,
#      taking its published port and its `kern logs` along. `kern doctor` tells you; the fix is one
#      command, once per machine.
#
# Measured end to end on a Raspberry Pi 5 (aarch64, kernel 6.6, rootless) on 2026-08-01: the page was
# fetched from a different machine over the LAN with no session open on the Pi, and `ssh` landed in a
# box that saw 8 processes where the host had 154 and could not see the host's SD card.
set -eu
kern="${KERN:-kern}"
img="${IMG:-web-ssh:demo}"
name="${NAME:-edgeweb}"
webport="${WEBPORT:-8080}"
sshport="${SSHPORT:-2222}"

cleanup() { $kern stop "$name" >/dev/null 2>&1 || true; $kern rm "$name" >/dev/null 2>&1 || true; }

echo "== 0. will a detached box survive your logout here?"
if [ -n "${USER:-$(id -un)}" ] && [ ! -e "/var/lib/systemd/linger/${USER:-$(id -un)}" ]; then
  echo "   systemd lingering is OFF. A detached box would die when this session ends."
  echo "   Fix once:  sudo loginctl enable-linger ${USER:-$(id -un)}"
  echo "   (continuing anyway - the box will work until you log out)"
else
  echo "   lingering on (or no user systemd): a detached box outlives this session."
fi

echo
echo "== 1. build the image: --net for outbound, NO published ports"
$kern stop imgbuild >/dev/null 2>&1 || true
$kern rm imgbuild >/dev/null 2>&1 || true
$kern box imgbuild --net --image alpine --detach -- sh -c '
  apk add --no-cache busybox-extras openssh >/dev/null 2>&1
  ssh-keygen -A >/dev/null 2>&1
  mkdir -p /srv
  printf "<!doctype html>\n<h1>Served from inside a kern box</h1>\n" > /srv/index.html
  sleep 600'
echo "   installing busybox-extras + openssh ..."
i=0
while [ "$i" -lt 60 ]; do
  if $kern exec imgbuild -- test -f /srv/index.html >/dev/null 2>&1; then break; fi
  i=$((i + 1)); sleep 1
done
$kern commit imgbuild "$img"
$kern stop imgbuild >/dev/null 2>&1 || true
$kern rm imgbuild >/dev/null 2>&1 || true

echo
echo "== 2. serve it: isolated network, port published to the LAN, ssh on loopback"
cleanup
# 0.0.0.0 for the web port because the point is to reach it from another machine; kern warns about
# that on purpose. --ssh always binds 127.0.0.1: a shell is not something to put on the LAN by
# default. The caps are here to show they are enforced, not because a busybox httpd needs them.
$kern box "$name" \
  -p "0.0.0.0:${webport}:9090" \
  --ssh "$sshport" \
  --memory 128m --cpus 0.5 \
  --image "$img" --detach \
  -- busybox-extras httpd -f -p 9090 -h /srv

echo
echo "== 3. what kern says is published, and what the kernel says is bound"
$kern ps
command -v ss >/dev/null 2>&1 && ss -ltn | grep -E ":${webport} |:${sshport} " || true

echo
echo "== 4. fetch it"
curl -fsS --max-time 5 "http://127.0.0.1:${webport}/" || echo "   (no curl, or nothing answered)"
ip=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -n "${ip:-}" ] && echo "   from another machine:  curl http://${ip}:${webport}/"

echo
echo "== 5. ssh into the box (needs newuidmap + /etc/subuid for sshd's privsep; kern warns if absent)"
echo "   the command kern printed above is the one to use; inside you will find:"
echo "     - hostname '$name', not this host's"
echo "     - a handful of processes, not this host's"
echo "     - /sys/fs/cgroup/memory.max = 134217728, the 128m cap"
echo "     - no /dev/mmcblk0, /dev/sda or any host disk"
echo
echo "   stop it with:  $kern stop $name"
