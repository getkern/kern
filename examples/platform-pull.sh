#!/bin/sh
# Pull a SPECIFIC CPU architecture from a multi-arch image with `kern pull --platform`.
#
#   kern pull <image> [--dest <dir>] [--platform os/arch]
#     --platform     pick one arch from a multi-arch index, e.g. linux/amd64 or linux/arm64
#                    (default: this host's arch)
#
# A foreign-arch pull works fine for inspection / export / pushing elsewhere - kern prints a note
# that it won't run natively here without a qemu-user + binfmt handler. This is non-invasive:
# we only download, look at the rootfs ELF header, and delete it. Nothing is installed or run.
set -eu
kern="${KERN:-kern}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Report the machine type of a rootfs by reading the ELF header of its busybox binary.
# Prefer `file(1)` if present; otherwise decode ELF e_machine (byte 18): 62 = x86-64, 183 = aarch64.
arch_of() {
  bin="$1/bin/busybox"
  [ -e "$bin" ] || bin="$(find "$1/bin" -type f 2>/dev/null | head -n1)"
  [ -n "$bin" ] && [ -e "$bin" ] || { echo "(no binary found)"; return; }
  if command -v file >/dev/null 2>&1; then
    file -b "$bin" | cut -d, -f1-2
  else
    m="$(od -An -tu1 -j18 -N1 "$bin" | tr -d ' ')"
    case "$m" in
      62)  echo "ELF x86-64 (amd64)" ;;
      183) echo "ELF aarch64 (arm64)" ;;
      *)   echo "ELF e_machine=$m" ;;
    esac
  fi
}

echo "==> pulling alpine for linux/amd64:"
"$kern" pull alpine --platform linux/amd64 --dest "$work/amd64"

echo
echo "==> pulling the SAME image for linux/arm64:"
"$kern" pull alpine --platform linux/arm64 --dest "$work/arm64"

echo
echo "==> the extracted rootfs actually differs by architecture:"
printf '    linux/amd64 rootfs -> %s\n' "$(arch_of "$work/amd64")"
printf '    linux/arm64 rootfs -> %s\n' "$(arch_of "$work/arm64")"

echo
echo "==> host arch (what a plain 'kern pull alpine' would fetch):  $(uname -m)"
echo "    The arch that doesn't match your host won't run natively without qemu-user + binfmt."

echo
echo "==> cleanup: both rootfs dirs are under the temp dir, removed on exit."
echo "done - two architectures pulled, inspected by ELF header, nothing installed."
