# Installing kern

One static binary, no daemon. Its only Rust dependency is `libc`, and a box built from a `--rootfs`
needs nothing else on the host. The image path is the exception and is stated as one: `kern pull` and
`--image` shell out to the system `curl` and `tar` rather than linking a TLS stack and a
decompressor. `kern doctor` reports whether both are present.

**Every host needs a Linux kernel with unprivileged user namespaces and cgroup v2.** Every release
ships static binaries for `x86_64` and `aarch64`, each with a `.sha256` beside it, and the tag they
were built from is GPG-signed and timestamped ([provenance/](../provenance/)).

## Linux and ARM boards

On `x86_64` or `aarch64`, including Raspberry Pi, Jetson and the Arduino UNO Q:

```sh
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
```

The script detects the architecture, downloads the matching `.tar.gz` from the latest release,
**verifies its SHA256 and refuses to install on a mismatch**, and puts `kern` in `~/.local/bin`
(`/usr/local/bin` as root; `KERN_INSTALL_DIR` overrides, `KERN_VERSION=vX.Y.Z` pins a release).

By hand, or where piping a script into a shell is not acceptable:

```sh
curl -fsSLO https://github.com/getkern/kern/releases/latest/download/kern-x86_64-unknown-linux-musl.tar.gz{,.sha256}
sha256sum -c kern-x86_64-unknown-linux-musl.tar.gz.sha256
tar xzf kern-x86_64-unknown-linux-musl.tar.gz && install -Dm755 kern ~/.local/bin/kern
```

From source, the route that needs no trust in a published artifact and the one that needs a Rust
toolchain. `--locked` builds against the committed `Cargo.lock`, so you get the dependency versions
the tree was tested with:

```sh
cargo install --git https://github.com/getkern/kern getkern --locked
```

**Offline or air-gapped.** kern is a single static binary, so copying that one file *is* the
install. No daemon, no package, nothing on the target, which is why it runs where Docker cannot:

```sh
scp kern pi@raspberrypi:~/          # then:  ssh pi@raspberrypi kern box dev --image alpine -- sh
```

## Windows

kern runs inside **WSL2**, which is a real Linux kernel, so the isolation and the caps work for real:
measured on a stock WSL2 kernel (6.18), a 128m box reads back `memory.max = 134217728`. The one-line
installer sets up the WSL2 engine (self-elevating for the one reboot it may need), imports kern's own
pre-baked distro, drops a `kern.exe` shim on your PATH and verifies end to end. Every download is
sha256-checked. Then: `kern box dev --image alpine -it -- sh`.

**Run kern inside the distro.** A command typed on the Windows side spawns `wsl.exe` to cross into
it, once per command, and that crossing dwarfs kern's own work: measured on two Windows 11 hosts,
**6.5 and 7.0 ms per box** inside the distro against **70.5 ms** through `kern.exe`. Use the bridge
for the occasional command from a PowerShell you are already in, not for a loop. Your project can
live on `C:` either way, which made no measurable difference.

**If your antivirus deletes `kern.exe`.** Some products remove an unsigned executable from
`%LOCALAPPDATA%` on sight, and kern is not signed. The installer also writes a `kern.cmd` companion
that takes over automatically, which keeps `kern` working in a new terminal. It is a safety net and
not a replacement: `cmd.exe` does not translate Windows paths, it re-parses arguments so `%VAR%`,
`!`, `^`, `&` and `|` are consumed before kern sees them, and it is not an executable, so the SDKs
run from Windows cannot spawn it. To get the exe back, allow the folder the installer names and
re-run it. `wsl -d kern -- kern ...` and the SDKs run inside the distro are unaffected throughout.

## macOS

There is no native port and there will not be one: macOS has no namespaces and no cgroups, so there
is nothing for kern to build a box out of. kern does run **inside a Linux VM on a Mac**, and there it
is the ordinary Linux kern.

**Start by running the installer on the Mac. It will refuse, and the refusal is the instructions.**

```sh
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
```

It looks for a Linux VM you already have (colima, Lima, OrbStack, Docker Desktop) before telling you
to install anything, and prints the route for the one it finds. Nothing is downloaded on a Mac: the
check happens before the first byte.

**If it names a VM you already run, use that one.** A second VM buys nothing:

```sh
colima ssh                                              # colima, or: limactl shell <instance>
docker run --rm -it --privileged --tmpfs /run ubuntu    # OrbStack / Docker Desktop
# then, inside: curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
```

`--privileged` is not decoration: a box mounts its own `/proc`, which Docker's default masking
refuses. On a Mac that privilege is inside Docker's own Linux VM, which is already the boundary
against macOS; on a Linux host it is privilege on the real machine, so that recipe is a way to TRY
kern rather than the way to run it there.

**If it finds none, install one, and the guest matters more than the VM.** colima is the smallest
thing that works and not the most capable: its default Ubuntu guest gives you a kern whose resource
caps do not bite. A Fedora guest has neither problem, on the evidence of a user's own `kern doctor`
in [issue #5](https://github.com/getkern/kern/issues/5).

```sh
brew install colima
colima start
colima ssh            # from here on you are on Linux, not macOS
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
```

**Verified** on a MacBook with Apple Silicon, colima 0.10.3, guest Ubuntu 24.04.4 aarch64: kern
installs, a box starts and runs, and the Python SDK drives it. That run found two things every Mac
following these steps will meet.

**1. The first box fails on AppArmor.** Ubuntu 23.10 and newer restrict unprivileged user
namespaces, and `kern doctor` lists it first with the same fix. The value is reset by a VM restart;
make it stick only if you accept relaxing a kernel protection inside the VM (the Mac is untouched
either way):

```sh
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/99-kern.conf
```

**2. DNS may be broken in the guest while IP works.** If `curl` cannot resolve a name but
`ping 1.1.1.1` answers, `/etc/resolv.conf` is a dangling symlink to an inactive `systemd-resolved`:

```sh
sudo rm -f /etc/resolv.conf && sudo sh -c 'echo "nameserver 1.1.1.1" > /etc/resolv.conf'
```

**What holds there, and what does not.** The isolation is the real one: namespaces, the pivoted
root, the seccomp allowlist, Landlock. The **resource caps are not enforced** on a default colima
guest, and kern says so at every box start rather than pretending. Getting them back is a property
of the guest and the mechanism is **delegation of the `memory` controller, not privilege**: measured
in a guest of colima's exact shape, a 200 MiB write under `--memory 32m` survived **as uid 0**. On a
colima guest specifically, no `cgroup.subtree_control` write fixes it either, because an
`colima ssh` session lands in `/system.slice/ssh.service` which the user cannot write and colima
creates no `user@<uid>.service`. `--require-limits` (`KERN_REQUIRE_LIMITS=1`) turns that into a
refusal to start instead of a box that only looks capped. Two more warnings are worth clearing
before real work: `sudo apt install uidmap` for official images that chown to a service user, and
`sudo apt install passt` for outbound networking from a pod. Full notes:
[FAQ](FAQ.md#does-it-run-on-macos).

**No GPU and no GPIO** are reachable from a Linux guest on a Mac. Apple's
`VZVirtioGraphicsDeviceConfiguration` gives that guest a display, not a compute device, which is the
same reason Docker Desktop has no GPU for containers. It is not a gap in kern and no VM setting
changes it. As on Windows, run kern **inside** the VM: crossing from the macOS side costs more per
command than the box does. No macOS figure is published here because none has been measured.

## Uninstall

`kern uninstall` is a **dry run by default**: it lists every path kern created, with sizes, and
marks which are data you made rather than a cache it can refetch. Nothing is removed until `--yes`.

```sh
kern uninstall                 # show what would go, remove nothing
kern uninstall --yes           # do it
kern uninstall --keep-images   # keep the image cache, remove the rest
```

It refuses while boxes are running, and touches only paths kern owns: the image cache, named
volumes, your `kern.toml`, the runtime state, units written by `--restart`, and the binary itself
when it sits where an installer put it. A `[[disk]]` you pointed somewhere is your data in your
location and is left alone.

On **Windows** the state lives in kern's WSL2 distro, so removal happens from PowerShell. This
prints what it found; the command it echoes performs it. It unregisters the `kern` distro, removes
the shim and takes its PATH entry back out. Your other WSL distros are untouched:

```powershell
irm https://raw.githubusercontent.com/getkern/kern/main/uninstall.ps1 | iex   # dry run
```

## Requirements and limitations

kern trades breadth for a small, honest core.

**On Ubuntu 23.10 and newer, one root command before the first box.** That release began shipping
`kernel.apparmor_restrict_unprivileged_userns=1`, which allows the namespace and refuses its
rootless uid map, so **no box starts at all** until it is dealt with. kern says so by name and
`kern doctor` lists it first. Two ways, and they are not equivalent:

```sh
# NARROW: teach AppArmor about kern, leaving the restriction on for every other program.
kern doctor --apparmor-profile | sudo tee /etc/apparmor.d/kern >/dev/null
sudo apparmor_parser -r /etc/apparmor.d/kern
```

```sh
# BROAD: lift the restriction machine-wide until reboot. Works everywhere, protects nothing.
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

The profile attaches **by path** and covers the four places kern normally lives (`/usr/bin`,
`/usr/local/bin`, `~/.local/bin`, `~/.cargo/bin`); a binary you moved elsewhere needs that path
added. `apparmor_parser -r` is not optional: AppArmor attaches at `exec`, so a kern already running
cannot see a profile loaded afterwards. **Both need root once**, and that is a real limit rather
than an inconvenience: on such a host, a user who cannot get root even once cannot run a box.

**Hard caps need a delegated cgroup** (a systemd user manager, or root); without one they degrade to
best-effort and kern says so. `--require-limits` (`KERN_REQUIRE_LIMITS`) refuses to start instead,
`--allow-uncapped` (`KERN_ALLOW_UNCAPPED`) accepts it silently in a nested CI. A stock Raspberry Pi
OS and WSL2 kernels older than the current one do not delegate the `memory` controller, so
`--memory` is accepted-but-unenforced there, the same as Docker and Podman. To enable it: on **WSL**
add `cgroup_enable=memory cgroup_memory=1` to `kernelCommandLine` under `[wsl2]` in
`%UserProfile%\.wslconfig`, then `wsl --shutdown`; on **Raspberry Pi OS** add the same to
`/boot/firmware/cmdline.txt`, then reboot.

**`newuidmap` + `/etc/subuid`** are needed for a full uid range (`--uid-range`, `--ssh`); a
single-uid box works without them.

**Deliberately not here:**

- **Not a microVM, not for hostile multi-tenancy.** A kernel vulnerability is not contained: this is
  a kernel-boundary sandbox for your own or semi-trusted code. When to reach for a microVM or gVisor
  instead is in [What kern is not](../README.md#what-kern-is-not) and the
  [threat model](../SECURITY.md).
- **No overlay or software-defined networking** (a box gets an isolated netns, or the host's; a pod
  shares one) and no Docker plugin ecosystem.
- **`kern exec` caps** are inherited only where kern can join the box's cgroup (root, or a delegated
  `kern.slice`); on a rootless per-box-scope host the exec'd command runs outside the box's caps,
  namespaces and seccomp still isolating it, and kern warns.
- **GPU slices** are on the [Roadmap](../ROADMAP.md), not shipped.

## Platforms

| Platform | Arch | Status |
|---|---|---|
| x86_64 Linux | x86_64 | primary, automated CI |
| aarch64 Linux (generic) | aarch64 | automated CI, native runner |
| **Windows 10/11 via WSL2** | x86_64 | CI-built shim and distro (`install.ps1`) |
| NVIDIA Jetson (L4T) | aarch64 | manually validated on the board |
| Raspberry Pi 5 | aarch64 | manually validated |
| Arduino UNO Q (Android kernel, Debian userland) | aarch64 | manually validated |
| macOS, **inside a Linux VM** | aarch64 | verified by hand on colima; Lima, OrbStack and UTM are the same shape, untested. Caps not enforced on a default guest ([notes](FAQ.md#does-it-run-on-macos)) |
| **Inside a container** (Docker, a k8s pod) | x86_64 | automated CI with `--privileged`: a 64m box inside `docker run --privileged`, red if the cap does not bite and red if `doctor` and the box disagree. How far below `--privileged` it still runs is [not measured](../ROADMAP.md) |

The kernel *flavor* does not matter: kern runs even on an **Android kernel** with a Linux userland
(the Arduino UNO Q). It does **not** run on stock Android-the-OS (Bionic, SELinux, userns off).
