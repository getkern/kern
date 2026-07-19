#!/bin/sh
# kern installer - downloads the latest prebuilt static binary for this platform.
#
#   curl -fsSL https://getkern.dev/install.sh | sh
#
# Honors:
#   KERN_INSTALL_DIR   where to install (default: ~/.local/bin, or /usr/local/bin as root)
#   KERN_VERSION       a specific tag, e.g. v0.3.0 (default: latest)
# No dependencies beyond a POSIX shell, curl (or wget), tar, and sha256sum (optional, for
# integrity verification). Linux only - kern is a Linux sandbox.
set -eu

REPO="getkern/kern"
RED='\033[0;31m'; GRN='\033[0;32m'; DIM='\033[2m'; ZZ='\033[0m'
err() { printf "${RED}error${ZZ}: %s\n" "$1" >&2; exit 1; }
info() { printf "${GRN}==>${ZZ} %s\n" "$1"; }

# --- platform detection ---
os="$(uname -s)"
[ "$os" = "Linux" ] || err "kern is Linux-only (detected $os)."
case "$(uname -m)" in
  x86_64 | amd64) arch="x86_64-unknown-linux-musl" ;;
  aarch64 | arm64) arch="aarch64-unknown-linux-musl" ;;
  *) err "unsupported architecture: $(uname -m) (x86_64 and aarch64 are published)." ;;
esac

# --- downloader ---
if command -v curl >/dev/null 2>&1; then
  dl() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  dl() { wget -qO "$2" "$1"; }
else
  err "need curl or wget to download."
fi

ver="${KERN_VERSION:-latest}"
asset="kern-${arch}.tar.gz"
if [ "$ver" = "latest" ]; then
  base="https://github.com/${REPO}/releases/latest/download"
else
  base="https://github.com/${REPO}/releases/download/${ver}"
fi

# --- install dir ---
if [ -n "${KERN_INSTALL_DIR:-}" ]; then
  bindir="$KERN_INSTALL_DIR"
elif [ "$(id -u)" = "0" ]; then
  bindir="/usr/local/bin"
else
  bindir="$HOME/.local/bin"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

info "downloading ${asset} (${ver})"
dl "${base}/${asset}" "${tmp}/${asset}" || err "download failed - is ${ver} published for ${arch}?"

# --- integrity (best-effort: verify if the checksum asset and sha256sum are both available) ---
if command -v sha256sum >/dev/null 2>&1 && dl "${base}/${asset}.sha256" "${tmp}/${asset}.sha256" 2>/dev/null; then
  want="$(awk '{print $1}' "${tmp}/${asset}.sha256")"
  got="$(sha256sum "${tmp}/${asset}" | awk '{print $1}')"
  [ "$want" = "$got" ] || err "checksum mismatch (expected $want, got $got)."
  info "checksum verified"
else
  printf "${DIM}    (skipping checksum verification)${ZZ}\n"
fi

info "installing to ${bindir}"
mkdir -p "$bindir"
tar -C "$tmp" -xzf "${tmp}/${asset}"
install -m755 "${tmp}/kern" "${bindir}/kern"

info "installed $("${bindir}/kern" --version)"
case ":${PATH}:" in
  *":${bindir}:"*) ;;
  *) printf "${DIM}    ${bindir} is not on your PATH - add:  export PATH=\"${bindir}:\$PATH\"${ZZ}\n" ;;
esac
