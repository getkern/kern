#!/bin/sh
# The colour codes ARE the printf format, on purpose, everywhere below.
# shellcheck disable=SC2059
# kern installer - downloads the latest prebuilt static binary for this platform.
#
#   curl -fsSL https://getkern.dev/install.sh | sh
#
# Honors:
#   KERN_INSTALL_DIR   where to install (default: ~/.local/bin, or /usr/local/bin as root)
#   KERN_VERSION       a specific tag, e.g. v0.3.0 (default: latest)
#   KERN_RELEASE_URL   a mirror holding that release's files (with KERN_VERSION); signatures still checked
#   KERN_VM            macOS only: the Lima VM's name (default: kern)
#   KERN_LIMA_ARGS     macOS only: extra `limactl start` flags for a new VM, e.g. "--vm-type qemu"
# No dependencies beyond a POSIX shell, curl (or wget), tar, and sha256sum (optional, for
# integrity verification). kern is a Linux sandbox: on macOS this script sets up a small Lima VM
# and installs kern inside it (kern_macos below).
set -eu

REPO="getkern/kern"
RED='\033[0;31m'; GRN='\033[0;32m'; DIM='\033[2m'; ZZ='\033[0m'
err() { printf "${RED}error${ZZ}: %s\n" "$1" >&2; exit 1; }
info() { printf "${GRN}==>${ZZ} %s\n" "$1"; }

# --- macOS: kern in a small Lima VM ---
# macOS has no namespaces and no cgroups, so there is nothing there for kern to build a box out of;
# it runs in a Linux VM. This sets one up with Lima, without Docker and without containerd inside it,
# installs kern there through the Linux path of this same script, and puts a `kern` command on the
# Mac that starts the VM when it is stopped and runs kern in it, in the current directory. The rest
# of this file is the Linux install and is not reached on a Mac.
#
# Checked against Lima 2.3.0's own source (cmd/limactl): `start` takes --tty, --name, --containerd
# (user, system, user+system, none), --mount-writable and --vm-type; `shell` quotes every argument
# with shellescape before the guest shell sees it, so `kern box ... -- echo "two words"` arrives as
# two words, and --workdir cds into that directory or exits 1. The default template is Ubuntu, whose
# kernel.apparmor_restrict_unprivileged_userns=1 stops rootless boxes: the profile kern carries is
# installed in the VM, the step the Linux path only prints.
kern_macos() {
  vm="${KERN_VM:-kern}"
  command -v curl >/dev/null 2>&1 || err "curl is required."
  # Lima from Homebrew if it is there, else the latest Lima release, verified, in ~/.kern/lima.
  PATH="$HOME/.kern/lima/bin:$PATH"
  export PATH
  if ! command -v limactl >/dev/null 2>&1; then
    if command -v brew >/dev/null 2>&1; then
      info "installing Lima (brew install lima)"
      brew install lima || err "brew install lima failed."
    else
      case "$(uname -m)" in
        arm64) larch="arm64" ;;
        x86_64) larch="x86_64" ;;
        *) err "unsupported Mac architecture: $(uname -m)." ;;
      esac
      ltag="$(curl -fsSL https://api.github.com/repos/lima-vm/lima/releases/latest |
        sed -n 's/.*"tag_name": *"\(v[^"]*\)".*/\1/p' | head -n 1)"
      [ -n "$ltag" ] || err "could not find the latest Lima release."
      lfile="lima-${ltag#v}-Darwin-${larch}.tar.gz"
      lurl="https://github.com/lima-vm/lima/releases/download/${ltag}"
      ltmp="$(mktemp -d)"
      info "installing Lima ${ltag} into ~/.kern/lima"
      curl -fsSL -o "${ltmp}/${lfile}" "${lurl}/${lfile}" || err "Lima download failed: ${lurl}/${lfile}"
      curl -fsSL -o "${ltmp}/SHA256SUMS" "${lurl}/SHA256SUMS" || err "Lima checksum download failed."
      lwant="$(awk -v f="$lfile" '$2 == f { print $1 }' "${ltmp}/SHA256SUMS")"
      lgot="$(shasum -a 256 "${ltmp}/${lfile}" | awk '{ print $1 }')"
      { [ -n "$lwant" ] && [ "$lwant" = "$lgot" ]; } ||
        err "Lima checksum mismatch (expected ${lwant:-none}, got ${lgot})."
      mkdir -p "$HOME/.kern/lima"
      tar -xzf "${ltmp}/${lfile}" -C "$HOME/.kern/lima" || err "could not unpack Lima into ~/.kern/lima."
      rm -rf "$ltmp"
    fi
  fi
  command -v limactl >/dev/null 2>&1 || err "limactl is not on PATH after installing Lima."

  # The VM: created once, started when it is stopped.
  if limactl list -q 2>/dev/null | grep -qx "$vm"; then
    if [ "$(limactl list --format '{{.Status}}' "$vm" 2>/dev/null)" != "Running" ]; then
      info "starting the Lima VM '${vm}'"
      limactl start --tty=false "$vm" || err "could not start the Lima VM '${vm}'."
    fi
  else
    # SAID BEFORE IT STARTS: the first run downloads Ubuntu's cloud image, 931 MiB measured on an
    # Apple Silicon Mac (3.5 min at 4.4 MiB/s), and a reader who is not told waits on a bar.
    info "creating the Lima VM '${vm}': Ubuntu, no Docker, no containerd (about 1 GB to download and a few minutes, once)"
    # `template:default` since Lima 2.0, which warns at `template://default` ("should be written");
    # a Lima from before 2.0, as an older Homebrew can have, knows only the old spelling.
    lmaj="$(limactl --version 2>/dev/null | sed -n 's/.*version \([0-9][0-9]*\).*/\1/p')"
    if [ "${lmaj:-0}" -ge 2 ]; then ltpl="template:default"; else ltpl="template://default"; fi
    # KERN_LIMA_ARGS is split into flags on purpose, e.g. "--vm-type qemu".
    # shellcheck disable=SC2086
    limactl start --tty=false --name="$vm" --containerd=none --mount-writable \
      ${KERN_LIMA_ARGS:-} "$ltpl" || err "could not create the Lima VM '${vm}'."
  fi

  # kern inside the VM, through this script's Linux path, as root so it lands in /usr/local/bin:
  # on PATH in every shell, interactive or not, and named by the AppArmor profile kern carries.
  info "installing kern inside the VM"
  # shellcheck disable=SC2016
  # KERN_INSTALL_FROM_MAC: the AppArmor step below is done here, so the Linux path must not tell
  # the reader to run it by hand (it did, in the middle of a Mac install that then did it itself).
  limactl shell "$vm" sh -c 'curl -fsSL "$1" | sudo env KERN_VERSION="$2" KERN_INSTALL_FROM_MAC=1 sh' \
    sh "https://raw.githubusercontent.com/${REPO}/main/install.sh" "${KERN_VERSION:-latest}" ||
    err "installing kern inside the VM failed."
  # shellcheck disable=SC2016
  limactl shell "$vm" sh -c '
    if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" = "1" ]; then
      /usr/local/bin/kern doctor --apparmor-profile | sudo tee /etc/apparmor.d/kern >/dev/null &&
        sudo apparmor_parser -r /etc/apparmor.d/kern
    fi' || err "installing the AppArmor profile inside the VM failed."
  # THE UID RANGE HELPERS: Lima's Ubuntu image gives the user an /etc/subuid range but ships no
  # newuidmap, so every box ran with a single-uid map and an image that chowns to a service user
  # failed at start. MEASURED on the Mac: nginx `chown(.., 101) failed (22: Invalid argument)`, redis
  # `chown: .: Invalid argument`; with `uidmap` installed both start.
  # shellcheck disable=SC2016
  limactl shell "$vm" sh -c '
    command -v newuidmap >/dev/null 2>&1 || ! command -v apt-get >/dev/null 2>&1 ||
      sudo apt-get install -y -q uidmap >/dev/null 2>&1' ||
    err "installing uidmap inside the VM failed (kern still runs, with a single-uid map)."

  # The `kern` command on the Mac.
  shimdir="$HOME/.local/bin"
  mkdir -p "$shimdir"
  # The shim's own `$` must reach the file unexpanded: single quotes on purpose.
  # shellcheck disable=SC2016
  {
    printf '%s\n' '#!/bin/sh'
    printf '%s\n' "# kern on macOS: runs kern inside the Lima VM '${vm}' (set up by kern's install.sh), starting"
    printf '%s\n' "# the VM when it is stopped. Under your home the current directory is the same path in the VM,"
    printf '%s\n' "# mounted writable; elsewhere kern runs in the VM's home."
    printf '%s\n' "# Remove: rm ~/.local/bin/kern && limactl delete --force ${vm}"
    printf '%s\n' 'PATH="$HOME/.kern/lima/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"'
    printf "vm='%s'\n" "$vm"
    printf '%s\n' 'if [ "$(limactl list --format "{{.Status}}" "$vm" 2>/dev/null)" != "Running" ]; then'
    printf '%s\n' '  limactl start --tty=false "$vm" >/dev/null 2>&1 ||'
    printf '%s\n' '    { echo "kern: could not start the Lima VM $vm (run: limactl start $vm)" >&2; exit 125; }'
    printf '%s\n' 'fi'
    printf '%s\n' 'case "$PWD" in'
    printf '%s\n' '  "$HOME" | "$HOME"/*) exec limactl shell --workdir "$PWD" "$vm" /usr/local/bin/kern "$@" ;;'
    printf '%s\n' '  *) exec limactl shell "$vm" /usr/local/bin/kern "$@" ;;'
    printf '%s\n' 'esac'
  } > "${shimdir}/kern"
  chmod 755 "${shimdir}/kern"
  info "installed $("${shimdir}/kern" --version) in the Lima VM '${vm}', called through ${shimdir}/kern"
  case ":${PATH}:" in
    *":${shimdir}:"*) ;;
    *)
      # shellcheck disable=SC2016
      line='export PATH="$HOME/.local/bin:$PATH"'
      if ! grep -qsxF "$line" "$HOME/.zshrc"; then
        printf '%s\n' "$line" >> "$HOME/.zshrc"
      fi
      printf "${DIM}    added ~/.local/bin to PATH in ~/.zshrc: open a new terminal, or run: %s${ZZ}\n" "$line"
      ;;
  esac
  printf "${DIM}    try: kern box --rm --image alpine -- echo hello${ZZ}\n"
}

# --- platform detection ---
os="$(uname -s)"
# Darwin runs kern_macos above: kern in a Lima VM, and a `kern` command on the Mac.
case "$os" in
  Linux) ;;
  Darwin)
    kern_macos
    exit 0
    ;;
  *) err "kern is Linux-only (detected $os)." ;;
esac
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
if [ -n "${KERN_RELEASE_URL:-}" ]; then
  # A MIRROR (an internal server, an offline copy): the files of ONE release, so the version has to be
  # named. The signature check below is the same, so a mirror cannot hand over a file the release
  # keys did not sign.
  [ "$ver" != latest ] || err "KERN_RELEASE_URL names a mirror: set KERN_VERSION too (the release it holds)."
  base="${KERN_RELEASE_URL%/}"
elif [ "$ver" = "latest" ]; then
  base="https://github.com/${REPO}/releases/latest/download"
else
  # A release's tag is `v<version>`: KERN_VERSION may be given with or without the `v`.
  base="https://github.com/${REPO}/releases/download/v${ver#v}"
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

# --- signature (when minisign is installed) ---
# The checksum above only proves the download matches the file next to it, on the same server. The
# signature proves the tarball is a release: made with one of the two keys below, the ones
# `kern self-update` trusts, and naming this file and this machine in its signed comment. Without
# minisign it is said and skipped, as the checksum is without sha256sum.
KERN_RELEASE_KEYS="RWSuYG/qtD8AV5p5IzIqfRuCwh5eJlT7ed5+7lVKrgILE1qvIpPGv+Ej RWRLQt2lFPXXsC0g2+1SPfSmOdjpxJ/f+t5DU+xPOaRNjElnisOR0Uo3"
# EVERY RELEASE FROM 0.51.2 ON IS SIGNED, so one without a signature is refused rather than
# installed: a missing `.minisig` is what a tampered release would look like, and the release
# workflow keeps a release a draft until it is signed. An older release, pinned with KERN_VERSION,
# predates the signatures and is installed with the line saying so.
signed_era=1
case "$ver" in
  latest) ;;
  *)
    v="${ver#v}"
    maj="${v%%.*}"; rest="${v#*.}"; min="${rest%%.*}"; pat="${rest#*.}"; pat="${pat%%[!0-9]*}"
    if [ "$maj" -eq 0 ] 2>/dev/null && { [ "$min" -lt 51 ] || { [ "$min" -eq 51 ] && [ "${pat:-0}" -lt 2 ]; }; }; then
      signed_era=""
    fi
    ;;
esac
if dl "${base}/${asset}.minisig" "${tmp}/${asset}.minisig" 2>/dev/null; then
  if command -v minisign >/dev/null 2>&1; then
    signed=""
    for key in $KERN_RELEASE_KEYS; do
      if minisign -V -q -P "$key" -m "${tmp}/${asset}" -x "${tmp}/${asset}.minisig" >/dev/null 2>&1; then
        signed="$key"
        break
      fi
    done
    [ -n "$signed" ] || err "the signature of ${asset} does not check out with the kern release keys - not installing."
    comment="$(sed -n 's/^trusted comment: //p' "${tmp}/${asset}.minisig")"
    # Each field on its own: one pattern for both needed TWO spaces between them (the first match
    # consumes the one space there is), and refused every release.
    case " $comment " in
      *" target=${arch} "*) ;;
      *) err "the signature of ${asset} is valid but names another machine (${comment}) - not installing." ;;
    esac
    case " $comment " in
      *" file=${asset} "*) ;;
      *) err "the signature of ${asset} is valid but names another file (${comment}) - not installing." ;;
    esac
    # THE VERSION TOO: a validly signed OLDER release served in place of the one asked for is a
    # downgrade. Pinned: it must be that version. Latest: it must be the version the (now verified)
    # binary reports.
    signed_ver="$(printf '%s\n' "$comment" | tr ' ' '\n' | sed -n 's/^version=//p')"
    if [ "$ver" = latest ]; then
      tar -C "$tmp" -xzf "${tmp}/${asset}" kern
      want_ver="$("${tmp}/kern" --version 2>/dev/null | awk '{print $2}')"
      want_ver="${want_ver#v}"
    else
      want_ver="${ver#v}"
    fi
    [ -n "$signed_ver" ] && [ "$signed_ver" = "$want_ver" ] \
      || err "the signature of ${asset} is valid but names version ${signed_ver:-none}, not ${want_ver:-unknown} - not installing."
    info "signature verified (${signed_ver})"
  elif [ -n "${KERN_RELEASE_URL:-}" ]; then
    # A mirror is trusted only through the signature: it is not github.com over HTTPS.
    err "${asset} came from the mirror ${base} and minisign is not installed to check its signature. A mirror is trusted only through the signatures: install minisign, or install from github.com."
  else
    printf "${DIM}    (signature not checked: install minisign to check it)${ZZ}\n"
  fi
elif [ -n "$signed_era" ]; then
  err "${asset} has no signature (${asset}.minisig), and every release from 0.51.2 on is signed - not installing. If the network dropped, run this again."
else
  printf "${DIM}    (this release predates signatures: none to check)${ZZ}\n"
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
# THE ONE HOST POLICY THAT MAKES THE NEXT COMMAND FAIL, said HERE rather than left for the reader to
# discover from a syscall name. Ubuntu 23.10+ ships `kernel.apparmor_restrict_unprivileged_userns=1`,
# which grants the user namespace and refuses its rootless id map, so no box starts at all. MEASURED
# on a stock Ubuntu 24.04.4 cloud image: install succeeds, and the first command in the README fails.
# The installer cannot fix it (the remedies need root, and this script may be piped into a plain sh),
# but a reader who is told before trying loses a minute instead of an evening.
if [ -z "${KERN_INSTALL_FROM_MAC:-}" ] &&
  [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" = "1" ]; then
  printf "\n${DIM}    note: this host restricts unprivileged user namespaces (Ubuntu 23.10+ default),${ZZ}\n"
  printf "${DIM}    which lets the namespace be created and refuses its uid map - no box can start yet.${ZZ}\n"
  printf "${DIM}    install the profile kern carries, which keeps the restriction on for everything else:${ZZ}\n"
  printf "      ${bindir}/kern doctor --apparmor-profile | sudo tee /etc/apparmor.d/kern >/dev/null && sudo apparmor_parser -r /etc/apparmor.d/kern\n"
  printf "${DIM}    then \`${bindir}/kern doctor\` should say ready. Full explanation: \`kern doctor\`.${ZZ}\n\n"
fi
# THE SELINUX POLICY THAT TAKES THE INTERNET AWAY FROM EVERY STACK, fixed here where it is MEASURED to
# apply and nowhere else. On openSUSE Leap 16 (enforcing, passt-selinux 2025-04) pasta is refused every
# namespace of an unconfined process, with no AVC logged, so no compose service and no one-off box
# reaches the internet; Fedora 45, also enforcing, lets the same call through. kern labelled as a
# container runtime, the type rootless podman runs as, gets through. So: only on an enforcing host with
# pasta, only when kern's own probe says SELinux is why pasta was refused (exit 3), and kept only if the
# probe then succeeds; otherwise the previous label is put back. The label is on this file: a filesystem
# relabel resets it, and running this installer again sets it again.
if [ "$(cat /sys/fs/selinux/enforce 2>/dev/null || echo 0)" = "1" ] && command -v pasta >/dev/null 2>&1; then
  probe=0
  "${bindir}/kern" __pasta-probe 2>"${tmp}/probe.err" || probe=$?
  if [ "$probe" = "3" ]; then
    old="$(stat -c %C "${bindir}/kern" 2>/dev/null || true)"
    if chcon -t container_runtime_exec_t "${bindir}/kern" 2>"${tmp}/chcon.err"; then
      again=0
      "${bindir}/kern" __pasta-probe 2>/dev/null || again=$?
      if [ "$again" = "0" ]; then
        info "SELinux refused pasta a box's namespaces here; kern is now labelled container_runtime_exec_t"
        printf "${DIM}    (the type rootless podman runs as), and stacks and one-offs reach the internet.${ZZ}\n"
        # A chcon label is undone by any restorecon (MEASURED). The rule that survives one is root's: a
        # file-context rule, then `restorecon -F`, which a plain restorecon leaves alone (MEASURED, for a
        # path under /home). A path under /usr/local is written as its /usr equivalent, which is what
        # semanage itself demands there ("conflicts with equivalency rule '/usr/local /usr'").
        spec="$(realpath "${bindir}/kern" 2>/dev/null || echo "${bindir}/kern")"
        case "$spec" in /usr/local/*) spec="/usr/${spec#/usr/local/}" ;; esac
        # Found where the SELinux tools live, not only on PATH: a PATH without /usr/sbin (an `env PATH=`
        # under sudo) hid semanage and sent a root install down the user branch (MEASURED).
        sel_tool() {
          command -v "$1" 2>/dev/null && return 0
          for d in /usr/sbin /sbin; do
            if [ -x "$d/$1" ]; then echo "$d/$1"; return 0; fi
          done
          return 1
        }
        semanage_bin="$(sel_tool semanage || true)"
        restorecon_bin="$(sel_tool restorecon || true)"
        if [ "$(id -u)" = "0" ] && [ -n "$semanage_bin" ] && [ -n "$restorecon_bin" ]; then
          if { "$semanage_bin" fcontext -a -t container_runtime_exec_t "$spec" 2>/dev/null ||
               "$semanage_bin" fcontext -m -t container_runtime_exec_t "$spec" 2>/dev/null; } &&
             "$restorecon_bin" -F "${bindir}/kern" 2>/dev/null &&
             stat -c %C "${bindir}/kern" 2>/dev/null | grep -q ':container_runtime_exec_t:'; then
            printf "${DIM}    kept by a file-context rule for ${spec}, so a relabel leaves it in place.${ZZ}\n"
          else
            chcon -t container_runtime_exec_t "${bindir}/kern" 2>/dev/null || true
            printf "${DIM}    a relabel resets it (the file-context rule could not be added); running this${ZZ}\n"
            printf "${DIM}    installer again sets it again, and \`kern doctor\` says when it is gone.${ZZ}\n"
          fi
        else
          printf "${DIM}    a relabel resets it; to keep it across one, as root:${ZZ}\n"
          printf "      sudo semanage fcontext -a -t container_runtime_exec_t '%s' && sudo restorecon -F '%s'\n" "$spec" "${bindir}/kern"
          printf "${DIM}    (or run this installer again; \`kern doctor\` says when it is gone).${ZZ}\n"
        fi
      else
        if [ -n "$old" ]; then chcon "$old" "${bindir}/kern" 2>/dev/null || true; fi
        printf "\n${DIM}    note: SELinux refuses pasta a box's namespaces here, and labelling kern as a container${ZZ}\n"
        printf "${DIM}    runtime did not change it, so the label was put back. Stacks and one-offs have no${ZZ}\n"
        printf "${DIM}    internet; \`${bindir}/kern doctor\` shows pasta's own words.${ZZ}\n\n"
      fi
    else
      printf "\n${DIM}    note: SELinux refuses pasta a box's namespaces here, so stacks and one-offs have no${ZZ}\n"
      printf "${DIM}    internet. The fix is to label kern as a container runtime, and this host does not${ZZ}\n"
      printf "${DIM}    define that type yet: install container-selinux (podman brings it), then run this${ZZ}\n"
      printf "${DIM}    installer again. chcon said: %s${ZZ}\n\n" "$(head -c 200 "${tmp}/chcon.err")"
    fi
  fi
fi
