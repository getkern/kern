#!/bin/sh
# build-wsl-rootfs.sh - build kern's pre-baked WSL distro rootfs FROM ANY LINUX HOST (no root, no Alpine).
# Produces dist/kern-wsl-rootfs.tar.gz: a minimal Alpine + curl + ca-certificates + the kern musl binary,
# ready for `wsl --import kern <dir> kern-wsl-rootfs.tar.gz`. This is the plug-and-play one-shot payload.
set -eu

# apk triggers (busybox symlinks, ca-cert bundle) need chroot → root. We have no sudo, so re-exec ourselves
# inside a user namespace (`unshare -r`): uid 0 in-ns gives CAP_SYS_CHROOT + working chown. Same primitive
# kern box uses. -m adds a mount ns; network is untouched so curl still works.
if [ -z "${KERN_ROOTFS_INNS:-}" ]; then
    export KERN_ROOTFS_INNS=1
    exec unshare -rm sh "$0" "$@"
fi

# The distro's files get the modes a system has, whatever umask the builder's shell had: MEASURED,
# a rootfs built under umask 002 shipped `/` at 775, and kern (rightly) refuses a marker below a
# directory a group can write.
umask 022

ALPINE_VER="${ALPINE_VER:-3.20}"
ARCH="${ARCH:-x86_64}"
KERN_BIN="${KERN_BIN:-./target/x86_64-unknown-linux-musl/release/kern}"
OUT="${OUT:-./kern-wsl-rootfs.tar.gz}"
CDN="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VER}"

[ -f "$KERN_BIN" ] || { echo "kern binary not found: $KERN_BIN"; exit 1; }

WORK="$(mktemp -d)"
ROOT="$WORK/rootfs"
mkdir -p "$ROOT"
trap 'rm -rf "$WORK"' EXIT

echo "== fetching apk.static (${ALPINE_VER}/${ARCH}) =="
APK_APK="$(curl -fsSL "$CDN/main/$ARCH/" | grep -oE 'apk-tools-static-[0-9][^"]*\.apk' | head -1)"
[ -n "$APK_APK" ] || { echo "could not find apk-tools-static in the index"; exit 1; }
curl -fsSL -o "$WORK/apk.apk" "$CDN/main/$ARCH/$APK_APK"
tar -xzf "$WORK/apk.apk" -C "$WORK" sbin/apk.static
APK="$WORK/sbin/apk.static"

echo "== bootstrapping rootfs (alpine-base + curl + ca-certificates + passt) =="
# passt gives a pod its outbound network (pasta). MEASURED on 2026-11-18 on a real stack run from
# kern.exe: the distro shipped without it, so every pod was loopback-only and a service calling an
# external API failed; `passt` is in Alpine's community repository (3.20: 2024.11.21-r0).
# apk exits non-zero for cosmetic "updating directory permissions" warnings (harmless in-userns); the
# triggers (busybox symlinks, ca bundle) still run. Don't let set -e abort on those - verify below instead.
"$APK" --arch "$ARCH" \
  -X "$CDN/main" -X "$CDN/community" \
  -U --allow-untrusted --root "$ROOT" --initdb \
  add alpine-base curl ca-certificates shadow-uidmap passt || echo "apk: non-fatal warnings, continuing"

# The apk call above tolerates its cosmetic warnings, so check what must be there instead of its
# exit code: a distro without pasta gives every pod no network, and nothing would say why.
for need in usr/bin/pasta usr/bin/newuidmap usr/bin/curl; do
  [ -x "$ROOT/$need" ] || { echo "rootfs is missing /$need"; exit 1; }
done

echo "== installing kern =="
install -Dm755 "$KERN_BIN" "$ROOT/usr/local/bin/kern"

echo "== the user kern runs as, and its uid/gid subrange =="
# kern does NOT run boxes as root here. Started as root (the distro's login, and what kern.exe runs),
# it places itself in a cgroup subtree it delegates to this user and becomes the user before
# anything else (crates/kern-cli/src/wslentry.rs). MEASURED on 2026-11-18: with kern as root, a box's
# uid 0 was this distro's uid 0, and an escape held every capability, /mnt/c read-write and the other
# distributions' disks. The marker names the user; it must be a root-owned file only root can write,
# which a file made here is (this script runs as uid 0 of its own user namespace, packed numerically).
printf 'kern:x:1000:1000:kern:/home/kern:/bin/sh\n' >> "$ROOT/etc/passwd"
printf 'kern:x:1000:\n' >> "$ROOT/etc/group"
printf 'kern:!::0:::::\n' >> "$ROOT/etc/shadow"
mkdir -p "$ROOT/home/kern"
mkdir -p "$ROOT/etc/kern"
chmod 755 "$ROOT/etc/kern"
printf 'kern\n' > "$ROOT/etc/kern/wsl-user"
chmod 644 "$ROOT/etc/kern/wsl-user"
# A fresh distro has nothing to migrate.
: > "$ROOT/etc/kern/wsl-migrated"
chmod 644 "$ROOT/etc/kern/wsl-migrated"
# NO WAY BACK TO ROOT FROM THE USER. MEASURED in the test round: root's password field was EMPTY, and
# busybox `su` is setuid (bbsuid). `su` refused the empty answer there, but nothing in the rootfs
# should rest on that: root's password is locked (`wsl -u root` needs none), and `su` loses its
# setuid bit, since the user kern never needs it.
sed -i 's/^root:[^:]*:/root:*:/' "$ROOT/etc/shadow"
[ -e "$ROOT/bin/bbsuid" ] && chmod u-s "$ROOT/bin/bbsuid"
# `shadow-uidmap` gives setuid `newuidmap`/`newgidmap`; the subuid/subgid allocation lets kern map a
# whole uid RANGE into a box (box uid 1.. -> 100000..) instead of the weaker single-uid fallback. The
# user's range is the one root had, so an image cache moved from root keeps its owners; root gets the
# next one, for an operator who runs kern as root on purpose (KERN_WSL_AS_ROOT=1).
printf 'kern:100000:65536\nroot:165536:65536\n' > "$ROOT/etc/subuid"
printf 'kern:100000:65536\nroot:165536:65536\n' > "$ROOT/etc/subgid"
# apk couldn't set the setuid bit inside our build userns (the "chown: Invalid argument" above), so set
# it explicitly - newuidmap/newgidmap must be setuid-root to map a uid range for an ordinary user.
chmod 4755 "$ROOT/usr/bin/newuidmap" "$ROOT/usr/bin/newgidmap" 2>/dev/null || true

echo "== apk repositories, so \`apk add\` works INSIDE the shipped distro =="
# The -X flags above configure THAT ONE apk.static invocation and write nothing into the rootfs, so
# --initdb leaves the distro with a working apk binary and no repositories. Every later `apk add`
# then fails with "no such package" even though the network is fine. Measured on the published
# 0.6.32 distro: /etc/apk/repositories was absent, `apk add python3 py3-pip` (the exact command
# install.ps1 prints at the end of a successful install, for anyone who wants the SDKs) failed, and
# so did the openssh-client that `kern box --ssh` needs on the host side. Writing this file made
# 24171 packages resolvable and both commands work.
mkdir -p "$ROOT/etc/apk"
printf '%s/main\n%s/community\n' "$CDN" "$CDN" > "$ROOT/etc/apk/repositories"

echo "== resolv.conf + wsl.conf =="
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > "$ROOT/etc/resolv.conf"
cat > "$ROOT/etc/wsl.conf" <<'EOF'
[boot]
systemd=false
[user]
default=root
[interop]
appendWindowsPath=false
EOF

chmod 755 "$ROOT" "$ROOT/etc" "$ROOT/home" 2>/dev/null || true
echo "== packing $OUT =="
mkdir -p "$(dirname "$OUT")"
( cd "$ROOT" && tar --numeric-owner -czf "$OUT" . )
echo "== done =="
ls -lh "$OUT" | awk '{print $5, $9}'
