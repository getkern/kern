# Installing kern

One static binary and no daemon. Its only Rust dependency is `libc`, and a box built from a
`--rootfs` needs nothing else on the host. The image path is the exception and is stated as one:
`kern pull` and `--image` shell out to the system `curl` and `tar` rather than linking a TLS stack
and a decompressor, which is most of why the release binary is 1.59 MB (a from-source build is
~2 MB; the size optimization is release-only). `kern doctor` reports whether both
are present. This page is the long form of the [README](../README.md).

Every release ships static binaries for `x86_64` and `aarch64`, each with a `.sha256` next to it, and
the tag they were built from is GPG-signed and timestamped ([provenance/](../provenance/)). Building
from source stays supported and needs a Rust toolchain. Either way the host needs a Linux kernel with
unprivileged user namespaces and cgroup v2.

**🐧 Linux & ARM boards** (Raspberry Pi · Jetson · Arduino UNO Q), on `x86-64` or `aarch64`:

```sh
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
```

The script detects the architecture, downloads the matching `.tar.gz` from the latest release,
**verifies its SHA256 and refuses to install on a mismatch**, and puts `kern` in `~/.local/bin`
(`/usr/local/bin` as root; `KERN_INSTALL_DIR` overrides, `KERN_VERSION=vX.Y.Z` pins a release). To do
it by hand, or on a host where piping a script into a shell is not acceptable:

```sh
curl -fsSLO https://github.com/getkern/kern/releases/latest/download/kern-x86_64-unknown-linux-musl.tar.gz{,.sha256}
sha256sum -c kern-x86_64-unknown-linux-musl.tar.gz.sha256
tar xzf kern-x86_64-unknown-linux-musl.tar.gz && install -Dm755 kern ~/.local/bin/kern
```

Or build it yourself:

```sh
cargo install --git https://github.com/getkern/kern getkern --locked
```

`--locked` builds against the committed `Cargo.lock`, so you get the dependency versions the tree was
tested with.

**🪟 Windows.** kern runs inside **WSL2**, a real Linux kernel. Install a WSL2 distro, add a Rust
toolchain, and run the same `cargo install --git … getkern --locked` inside it.

kern runs inside **WSL2**, a real Linux kernel, so the isolation (namespaces + seccomp) and `--cpus`
cap work for real, `--memory` included: measured on a stock WSL2 kernel (6.18), a 128m box reads back
`memory.max = 134217728`. Where a host does not delegate the `memory` controller (a stock Raspberry Pi
OS, and older WSL2 kernels), kern **warns** and shows the one-line fix rather than pretending, see
[Requirements and limitations](#requirements-and-limitations). On a native Linux host `--memory` is enforced
out of the box. The installer ensures the WSL2 engine (self-elevating for the one reboot it may need, then
resuming on its own), imports kern's **own** pre-baked distro (a tiny Alpine + kern, no Ubuntu, no
manual steps), drops the `kern.exe` shim on your PATH, and verifies end-to-end. Every download is
sha256-checked. After it finishes: `kern box dev --image alpine -it -- sh`. Honest caveat: kern runs
*inside* the WSL2 kernel, so it doesn't shed the VM weight native Linux does; the win is "no Docker
Desktop", not "no VM".

**Where the milliseconds go on Windows.** The figures at the top of this page are Linux hosts. A command
typed on the Windows side spawns `wsl.exe` to cross into the distro, once per command, and that crossing
is not kern's work but it dwarfs kern's work. Measured on two Windows 11 hosts: **6.5 and 7.0 ms per box**
typed inside the distro, against **70.5 ms** per command through `kern.exe`. So run kern
inside the distro; use the bridge for the occasional command from a PowerShell you are already in, not for
a loop that starts hundreds of boxes. Your project can live on `C:` either way, that made no measurable
difference to box startup.
[Benchmarks](../BENCHMARKS.md#windows-where-the-milliseconds-go) has the table, the variance, and what was
not measured.

**If your antivirus deletes `kern.exe`.** Some products remove an unsigned executable from
`%LOCALAPPDATA%` on sight; kern is not signed. The Linux side is untouched and still works, and the
installer also writes a `kern.cmd` companion that takes over automatically (`PATHEXT` resolves `.EXE`
before `.CMD`, so it is inert until the exe is gone), which keeps `kern` working in a new terminal.

It is a safety net, not a replacement, because `cmd.exe` is now in the path the exe was not: it does not
translate Windows paths (write `-v /mnt/c/data:/data`), it re-parses arguments so `%VAR%`, `!`, `^`, `&`
and `|` are consumed before kern sees them, Ctrl-C on an interactive box asks "Terminate batch job (Y/N)?"
first, and it is not an executable, so the Python and Node SDKs run **from Windows** cannot spawn it. To
get the exe back, allow the folder the installer names in your antivirus and re-run the installer.
Throughout, `wsl -d kern -- kern ...` and the SDKs run inside the distro are unaffected.

**From source** (the route that needs no trust in a published artifact):

```sh
cargo install --git https://github.com/getkern/kern getkern --locked
```

`--locked` builds against the committed `Cargo.lock`, so you get the dependency versions the tree
was tested with. This is the one route that does need a Rust toolchain.

**📦 Offline / air-gapped** (a board or locked-down server with no internet). kern is a single
static binary (~2 MB from a source build; 1.59 MB x86_64 / 1.31 MB aarch64 in the size-optimized
release build), so copying that one file *is* the install:

```sh
scp kern pi@raspberrypi:~/          # then:  ssh pi@raspberrypi kern box dev --image alpine -- sh
```

No daemon, no package, nothing to install on the target, which is why it runs where Docker can't
(see [EDGE.md](../EDGE.md)).

### Uninstall

`kern uninstall` is a **dry run by default**: it lists every path kern created, with sizes, and marks
which of them are data you made rather than a cache it can refetch. Nothing is removed until you add
`--yes`.

```sh
kern uninstall                 # show what would go, remove nothing
kern uninstall --yes           # do it
kern uninstall --keep-images   # keep the image cache, remove the rest
```

It refuses while boxes are running, and it only touches paths kern owns: the image cache, named
volumes, your `kern.toml`, the runtime state, units written by `--restart`, and the binary itself when
it sits where an installer put it. A `[[disk]]` you pointed somewhere is your data in your location and
is left alone.

On **Windows** the state lives in kern's WSL2 distro, so removal happens from PowerShell:

```powershell
irm https://raw.githubusercontent.com/getkern/kern/main/uninstall.ps1 | iex   # dry run
```

That prints what it found; the command it echoes performs it. It unregisters the `kern` distro, removes
the `kern.exe` shim, and takes its entry back out of your PATH. Your other WSL distros are not touched.


## Requirements and limitations


kern trades breadth for a small, honest core. What it needs, and what it deliberately does not do:

**Requires:**
- A **Linux kernel** with **unprivileged user namespaces** + **cgroup v2**. On Windows it runs under
  WSL2; there is no native macOS/Windows port ([Roadmap](../ROADMAP.md)).
- Hard `--memory`/`--cpus`/`--pids-limit` caps need a **delegated cgroup** (a systemd user manager, or root);
  without one they degrade to best-effort and kern says so. Pass `--require-limits` (`KERN_REQUIRE_LIMITS`)
  to refuse to start instead of running uncapped, or `--allow-uncapped` (`KERN_ALLOW_UNCAPPED`) to accept
  it silently in a nested CI. Microsoft's default WSL2 kernel and a stock
  Raspberry Pi OS, and WSL2 kernels older than the current one) don't delegate the `memory` controller,
  so `--memory` is accepted-but-unenforced there (same as Docker/Podman) until you enable it. A current
  WSL2 kernel does enforce it, measured. To enable it where it is missing: on **WSL**, add `cgroup_enable=memory cgroup_memory=1` to
  `kernelCommandLine` under `[wsl2]` in `%UserProfile%\.wslconfig`, then `wsl --shutdown`; on **Raspberry
  Pi OS**, add `cgroup_enable=memory cgroup_memory=1` to `/boot/firmware/cmdline.txt`, then reboot.
- `newuidmap` + `/etc/subuid` for a full uid range (`--uid-range`, `--ssh`); a single-uid box works
  without them.

**Deliberately not here:**
- **Not a microVM, not for hostile multi-tenancy.** A kernel vulnerability isn't contained: kern is a
  kernel-boundary sandbox for your own or semi-trusted code. When to reach for a microVM (Firecracker)
  or gVisor instead is spelled out in [What kern is not](../README.md#what-kern-is-not)
  and the [threat model](../SECURITY.md).
- **No overlay / software-defined networking** (a box gets an isolated netns, or the host's; a pod
  shares one) and no Docker plugin ecosystem.
- **`kern exec` caps** are inherited only where kern can join the box's cgroup (root, or a delegated
  `kern.slice`); on a rootless per-box-scope host the exec'd command runs outside the box's
  `--memory`/`--pids-limit` (namespaces + seccomp still isolate it), and kern warns.
- **GPU** slices are on the [Roadmap](../ROADMAP.md), not shipped.

## Platforms


**Linux, multi-architecture.** kern builds to a static (musl) binary for **`linux-x86_64`** and
**`linux-aarch64`**: one file per arch (~2.0 MB x86_64 / ~1.6 MB aarch64 from a source build; the
size-optimized release build is 1.59 MB / 1.31 MB), no Rust deps beyond `libc` (the pull path shells
out to system `curl`/`tar`). No prebuilt binaries are published yet; every target builds from source.

| Platform | Arch | Status |
|---|---|---|
| x86_64 Linux | x86_64 | ✅ primary + automated CI |
| aarch64 Linux (generic) | aarch64 | ✅ automated CI (native runner) |
| **Windows 10/11 (via WSL2)** | x86_64 | ✅ CI-built shim + distro (`install.ps1`) |
| NVIDIA Jetson (L4T) | aarch64 | ✅ manually validated (board) |
| Raspberry Pi 5 | aarch64 | ✅ manually validated |
| Arduino UNO Q (Android kernel, Debian userland) | aarch64 | ✅ manually validated |

kern needs a **Linux kernel** with **unprivileged user namespaces** + **cgroup v2**, and a **Linux
userland**. The kernel *flavor* doesn't matter: kern runs even on an *Android kernel* with a Linux
userland (the Arduino UNO Q). **On Windows, WSL2 *is* that Linux kernel**, and the one-line PowerShell
installer sets up WSL2 and drops in a pre-baked kern distro, so isolation, `--cpus` and `--memory` are
all enforced for real (measured on a stock 6.18 WSL2 kernel: a 128m box reads back `memory.max =
134217728`). Honest
caveat: you're inside the WSL2 VM, so it's "no Docker Desktop", not "no VM". kern does **not** run on stock Android-the-OS (Bionic, SELinux, userns off). Daemonless is a big
win on RAM-constrained boards (0 resident vs ~160 MB), see **[EDGE.md](../EDGE.md)**. ARM CI is tracked
in the issues.
