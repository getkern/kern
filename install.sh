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
# The IPv4 retry is not paranoia: inside a WSL2 distro whose curl is built against c-ares (Alpine's
# is), an AAAA lookup against the WSL NAT resolver can go unanswered while the A record resolves
# perfectly. curl then reports "Could not resolve host" for a name that `getent hosts` resolves a
# second later, which reads as a broken installer rather than a broken lookup. Measured on Windows 10
# 22H2: the same URL fails plain and returns 200 with --ipv4. One retry, and it says why.
if command -v curl >/dev/null 2>&1; then
  dl() {
    curl -fsSL "$1" -o "$2" && return 0
    echo "  download failed, retrying over IPv4 only (some WSL/musl resolvers stall on AAAA)" >&2
    curl -fsSL --ipv4 "$1" -o "$2"
  }
elif command -v wget >/dev/null 2>&1; then
  dl() {
    wget -qO "$2" "$1" && return 0
    echo "  download failed, retrying over IPv4 only (some WSL/musl resolvers stall on AAAA)" >&2
    wget -qO "$2" -4 "$1"
  }
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
  *":${bindir}:"*)
    # On PATH is not the same as FIRST on PATH. An older kern in /usr/local/bin keeps winning, so
    # `kern --version` reports the old one and the install looks like it did nothing. Say which file
    # actually answers, and only when it is not the one just written.
    winner=$(command -v kern 2>/dev/null || true)
    if [ -n "$winner" ] && [ "$winner" != "${bindir}/kern" ]; then
      printf "${DIM}    note: \`kern\` still resolves to ${winner} ($("$winner" --version 2>/dev/null || echo 'unknown version')) - it comes earlier on your PATH${ZZ}\n"
      printf "${DIM}    to use the one just installed: export PATH=\"${bindir}:\$PATH\"  (or remove ${winner})${ZZ}\n"
    fi
    ;;
  *) printf "${DIM}    ${bindir} is not on your PATH - add:  export PATH=\"${bindir}:\$PATH\"${ZZ}\n" ;;
esac
# Optional Docker drop-in: invoked as `docker` / `docker-compose`, kern rewrites the argv (no daemon,
# no docker.sock). NOT created automatically - a `docker` symlink would SHADOW a real Docker install.
# Opt in deliberately (typically on a box with no Docker):
printf "${DIM}    docker drop-in (optional, shadows any real Docker): ln -s \"${bindir}/kern\" \"${bindir}/docker\"${ZZ}\n"
