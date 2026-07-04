#!/bin/sh
# build-wsl-rootfs.sh — build kern's pre-baked WSL distro rootfs FROM ANY LINUX HOST (no root, no Alpine).
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

echo "== bootstrapping rootfs (alpine-base + curl + ca-certificates) =="
# apk exits non-zero for cosmetic "updating directory permissions" warnings (harmless in-userns); the
# triggers (busybox symlinks, ca bundle) still run. Don't let set -e abort on those — verify below instead.
"$APK" --arch "$ARCH" \
  -X "$CDN/main" -X "$CDN/community" \
  -U --allow-untrusted --root "$ROOT" --initdb \
  add alpine-base curl ca-certificates shadow-uidmap || echo "apk: non-fatal warnings, continuing"

echo "== installing kern =="
install -Dm755 "$KERN_BIN" "$ROOT/usr/local/bin/kern"

echo "== uid/gid subrange for multi-uid box isolation =="
# `shadow-uidmap` gives setuid `newuidmap`/`newgidmap`; the subuid/subgid allocation lets kern map a
# whole uid RANGE into a box (in-box root → host root, 1..65535 → 100000..) instead of the weaker
# single-uid fallback. kern runs as root in WSL, so allocate the range to root. Without this kern warns
# "--uid-range unavailable" and every box/build/compose drops to a single-uid map.
printf 'root:100000:65536\n' > "$ROOT/etc/subuid"
printf 'root:100000:65536\n' > "$ROOT/etc/subgid"
# apk couldn't set the setuid bit inside our build userns (the "chown: Invalid argument" above), so set
# it explicitly — newuidmap/newgidmap must be setuid-root to map a uid range. (kern also runs them as
# root in WSL, but keep them correct for any path.)
chmod 4755 "$ROOT/usr/bin/newuidmap" "$ROOT/usr/bin/newgidmap" 2>/dev/null || true

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

echo "== packing $OUT =="
mkdir -p "$(dirname "$OUT")"
( cd "$ROOT" && tar --numeric-owner -czf "$OUT" . )
echo "== done =="
ls -lh "$OUT" | awk '{print $5, $9}'
