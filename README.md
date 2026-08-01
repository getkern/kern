<div align="center">

<img src="assets/brand/kern-logo.png" width="260" alt="kern">

# kern: a rootless container sandbox and virtual-resource runtime

**A fast, rootless sandbox and virtual resource runtime for any workload, including untrusted and AI-generated code.**

**A real, kernel-enforced container in 3.4 ms, out of one 1.83 MB binary with no daemon.**

<p align="center">
  <img src="assets/kern-demo.gif" width="720" alt="Terminal: 'kern box app --image alpine -- echo hello from a real container' prints the greeting, then reports that kern started in 3.4 ms against docker run's 291 ms. A real OCI image, rootless, a 1.83 MB binary, no daemon, on an Intel i7-14700KF, Linux 7.0.">
</p>

<sub>**0 RAM at rest** · no daemon, no socket, nothing to start · one static binary, `libc` the only dependency</sub>

**Runs everywhere Linux does: bare Linux, Windows (via WSL2), and ARM boards** (Raspberry Pi, NVIDIA
Jetson, Arduino UNO Q), where a ~160 MB Docker daemon is a poor fit (on the Pi 5 tested here, no engine
was installed at all).

[![CI](https://github.com/getkern/kern/actions/workflows/ci.yml/badge.svg)](https://github.com/getkern/kern/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%C2%B7%20Windows%20(WSL2)%20%C2%B7%20ARM%20boards-informational.svg)](#platforms)
[![Release](https://img.shields.io/github/v/release/getkern/kern?label=release&color=brightgreen)](https://github.com/getkern/kern/releases/latest)

[Quickstart](#quickstart) · [When to use it, and when not](#when-to-use-kern-and-when-not) · [Embed it](#embed-it) · [How it works](#how-it-works) · [Benchmarks](BENCHMARKS.md) · [Security](SECURITY.md) · [Config](docs/CONFIG.md)

**🐧 Linux & ARM boards**
```sh
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
```
**🪟 Windows (via WSL2)**
```powershell
irm https://raw.githubusercontent.com/getkern/kern/main/install.ps1 | iex
```
then `kern box dev --image alpine -- sh`

Isolation is the first resource kern manages this way, not the only one: the same model also slices CPU
(`vcpu:`), memory, disk (`vdisk:`) and devices (`vgpio:`) per process, with or without a full box. The
container is one case of a smaller idea, and it is why there are two verbs. Embed it from Python, Node or

<p align="center">
  <img src="assets/demo.svg" width="780" alt="Terminal demo: a kern.toml defines reusable vcpu/vdisk/vgpio (device) profiles; 'kern box train --image alpine vcpu:heavy vdisk:scratch' attaches a 4-vCPU, 8 GB, 2 GB-scratch rootless isolated slice in a few ms (docker run takes ~289 ms); 'kern run vcpu:heavy -- ffmpeg' caps a heavy transcode with no sandbox; 'kern box iot --image alpine vgpio:sensor' exposes only /dev/i2c-1 and nothing else; piping a request into 'kern box fn --image python' runs it in a fresh isolated box per request (serverless style); 'kern compose stack.toml up' brings up a multi-box stack; 'kern top' is the live TUI for boxes, profiles and volumes: CPU, memory, disk and devices, sliced per box, in one ~1.8 MB static binary, no daemon.">
</p>

<sub>Demo timings on an Intel i7-14700KF (20-core / 28-thread x86_64, Linux 7.0, systemd-user, cgroup delegated): the timings in it are <i>capped</i> box starts, the `vcpu:heavy vdisk:scratch` slice the demo attaches, which is why they differ from the uncapped figure above; each is a full <code>kern box</code> lifecycle (fork, isolate, run, tear down), not kern's own setup phase in isolation, and the <a href="#performance">Performance</a> table was measured on the same machine on the same night. Your hardware and cgroup delegation differ, so measure your own: <code>kern bench --rootfs &lt;dir&gt;</code>. See <a href="BENCHMARKS.md">Benchmarks</a> for methodology, the capped-vs-uncapped split, and on-device board numbers.</sub>

</div>

---

kern runs Linux workloads in real, kernel-enforced sandboxes: user + PID + mount + network +
UTS + IPC namespaces, an overlay or read-only root pivoted in, an always-on seccomp filter, and
cgroup limits. It pulls OCI images, builds them, runs them, and gets out of the way. **No background
daemon, one short-lived process per box, started in single-digit milliseconds.**

It's built around one idea, *virtual resources*, exposed as **two verbs**: `box` wraps a process
in a full isolated slice; `run` caps a resource on a process you launch yourself. Isolation is just
the first resource; the same model virtualizes **CPU (`vcpu:`), memory, disk (`vdisk:`) and GPIO
devices (`vgpio:`)** today, with GPU on the roadmap. On the `box` side that's a full daemonless
container UX (OCI pull **and build**, overlay, volumes, secrets, in-box SSH, `cp`/`pause`/`attach`,
`ps`/`exec`/`logs`, compose, health, `tag`/`push`, `save`/`load`) in ~1.8 MB.

```sh
kern box dev --image alpine -- sh        # a throwaway, isolated Alpine shell, in a few ms
```

…or embed it, a fresh isolated box per call, for untrusted or agent-generated code (cloud-code-interpreter
territory, but *local* and ~1.8 MB: no cloud, no account, no VM):

```python
import kern_sandbox as kern                     # pip install kern-sandbox
r = kern.run_code("print(sum(range(100)))")   # network OFF, hard caps, a timeout the binding enforces
print(r.stdout, r.success)                     # → a fresh, discarded-after box
```

That call measures **16 ms** end to end on the x86_64 desktop (median of 60, after warm-up), and the
subtraction is worth publishing rather than a summary of it: **~8.4 ms** is CPython starting at all
(`python3 -c pass` on the host, same machine), **~3.4 ms** is the box, and the remaining **~4.3 ms** is
the binding's own work, which is not attributed further. So the interpreter is about half of it, not
"nearly all" - the shape this figure used to be described with.

## What you'd use it for

One move under all of these: a fresh, isolated, resource-capped box in single-digit milliseconds, wherever you would
otherwise reach for a container, a cloud sandbox, or root.

- **Development:** one command, in a real box, in milliseconds, then gone. A service, a database or a
  clean per-language build box starts, runs, and is thrown away with your host untouched
  and nothing left resident ([docker-shim.sh](examples/docker-shim.sh) · [compose-declared-ports.sh](examples/compose-declared-ports.sh) · [familiar-commands.sh](examples/familiar-commands.sh) · [database-box.sh](examples/database-box.sh)).
- **AI agents:** run each model-generated tool call in a fresh, network-off box, sandbox faults come back
  as data, not crashes ([warm-kernel.py](examples/warm-kernel.py) · [kern-mcp for Claude Desktop / Cursor](examples/mcp-code-interpreter.md) · [agent-tool-runner.py](examples/agent-tool-runner.py)).
- **CI:** run each step in a capped, daemonless box, no Docker-in-Docker ([ci-in-a-box.sh](examples/ci-in-a-box.sh)).
- **Edge / ARM:** one 1.8 MB binary on a Pi 5 / Jetson where a Docker daemon does not fit ([edge-many-services.sh](examples/edge-many-services.sh)).
- **Device access / IoT:** hand a workload *exactly* the device nodes you name (an I2C or SPI bus, a GPIO chip, a sensor) and nothing else, deny-by-default. The closest thing is CDI (the Container Device Interface), but that's a JSON spec you register with a supporting engine; kern's is a line of TOML, engine included, and it works on a bare `kern run` too ([device-isolation.sh](examples/device-isolation.sh)).
- **Untrusted or customer code:** execute it isolated and resource-capped, on your own machine, no cloud ([code-interpreter.py](examples/code-interpreter.py)).
- **Serverless / functions:** a fresh, throwaway box per request, so one call's crash or timeout stays contained to its own box ([per-request-workers.py](examples/per-request-workers.py)).
- **Data & batch:** ETL, scraping, per-file fan-out, each input in its own capped box ([data-pipeline.sh](examples/data-pipeline.sh) · [batch-process.sh](examples/batch-process.sh)).
- **Build and run OCI images:** `kern build` / `kern box`, speaks Docker formats, no daemon.

## kern vs Docker vs Podman

|  | **kern** | Docker | Podman |
|---|---|---|---|
| Daemon | **no** | yes (`dockerd` + `containerd`) | no |
| Rootless | **yes** | opt-in (rootless mode) | yes |
| Cold start (a bare box) | **2.1 ms** | ~294 ms | ~281 ms |
| Cold start (from an OCI image) | **3.4 ms** | ~294 ms | ~281 ms |
| Footprint | **one 1.83 MB static binary** | 154 to 160 MB daemon stack, resident with zero containers | multi-binary install |
| OCI images (pull / build) | **yes** | yes | yes |
| Resource caps without a full box | **yes (`kern run`)** | no | no |

Startup numbers are from a labeled [benchmark](BENCHMARKS.md) on one machine, measure your own. kern
covers a *smaller* surface than Docker (no overlay networks, no swarm) and spends it on a fast, rootless
core: single-digit-millisecond starts from one ~1.8 MB binary, no daemon. It is a **kernel-boundary**
sandbox for your own or semi-trusted code; for actively hostile multi-tenant code, a microVM is the
right tool, and [SECURITY.md](SECURITY.md) says exactly where the line is.

**What that trade costs, stated here rather than discovered later.** A `kern compose` stack is one
pod: no network segmentation between services, no `deploy.replicas`, nothing on `docker.sock`.
See [when NOT to use kern](#when-to-use-kern-and-when-not).

**"So it's a reimplementation of Docker?"** No, and the dependency list is the shortest proof: kern is
~58,000 lines of Rust with **one** external crate (`libc`), no vendored code and no Docker source. What
it shares with other runtimes are *published standards*, the [OCI image spec](https://github.com/opencontainers/image-spec)
and the [Compose Specification](https://compose-spec.io), the same way two browsers share HTML. Reading
a format is interoperability, not lineage. The architecture goes the other way on purpose: Docker runs a
container through a daemon and several binaries, kern runs one through a single static binary with
nothing resident between calls. And the `docker`-syntax shim is deliberately partial and says so: it
translates what maps, **refuses** what would change behaviour, and never silently ignores a flag
([Docker compatibility](#docker-compatibility)).

## Why kern

- ⚡ **Daemonless & tiny.** No `dockerd`-style service. A ~1.8 MB static binary, **one Rust dependency**
  (`libc`); it shells out to the system's `curl`/`tar` only to *pull* images (running a box needs
  neither). A cold start faster than a daemon round-trip; **0.35 MB** of real memory per extra box
  (PSS at 50 live boxes) vs an always-on daemon that measured 154 MB idle and 160 MB after an
  afternoon's use here (`dockerd` + `containerd`, zero containers running either time). `kern ps` reads state straight from the kernel.
- 👤 **Rootless by default.** Unprivileged user namespaces: your uid maps to root *inside* the box,
  and only there. Single-uid is the default and is `libc`-pure (no helper, smallest id surface);
  `--uid-range` opts into a full sub-id range (`apt`, `www-data`-style drops) via the standard
  `newuidmap` + `/etc/subuid`. kern says plainly that path is not helper-free. No host privilege
  is gained either way.
- 🧱 **Correct by construction.** The mount sequence is a **typestate**: remounting the root read-only
  *before* pivoting into it doesn't compile, so a class of sandbox-escape bug is unrepresentable, not
  just untested. `--plan` prints the exact isolation sequence without running anything.
- 🔍 **Honest about its boundaries.** Filesystem / process / namespace isolation is a real kernel
  boundary, the right tool for your own or semi-trusted code (CI, dev, edge, your agents' code).
  For actively hostile multi-tenant code, reach for a microVM. [SECURITY.md](SECURITY.md) says
  exactly when to use which, and marks every guarantee that is cooperative or opt-in.

## The model: two verbs

| Verb | Question it answers | What it does | Status |
|------|--------------------|--------------|--------|
| **`kern box`** | *"Isolate this workload, and slice its resources."* | Its own namespaces, overlay/read-only fs, private process tree, seccomp (**the container**), **plus** the same resource slices (`--memory`, `--cpus`, `vcpu:`, `vdisk:`, `vgpio:`). | ✅ works now |
| **`kern run`** | *"Just slice resources, no sandbox."* | Run a command against a CPU / memory quota with no isolation: the lean governor on its own. (A **GPU slice** is on the roadmap.) | ✅ works now |

**Both take resource slices;** the difference is the sandbox. `box` = isolation **+** slices; `run` =
slices **without** the sandbox. They compose (`run` inside `box`). Both ship today.

## Virtual resources

One model: a box gets *only* what you slice for it; a bare `run` adds the same caps to a process that
otherwise still sees the host. Every shipping cap is a real cgroup v2 or kernel control; devices are
deny-by-default. GPU slices are on the [Roadmap](#roadmap).

| Resource | Flag / profile | What the box gets | Enforcement |
|---|---|---|---|
| **CPU** | `--cpus` · `--cpuset-cpus` · `--nice` · `vcpu:` | Fractional CPU-time quota, core pinning, priority | cgroup `cpu.max` / `cpuset`, hard |
| **Memory** | `--memory` · `--memory-swap-max` | Hard RAM ceiling (+ swap allowance) | cgroup `memory.max`, hard¹ |
| **Disk** | `vdisk:` · `--size` (named volumes) | Size-capped scratch at `/vdisk/<name>` | rootless: a **RAM-backed tmpfs** (counts against the box's memory cap); privileged: ext4-on-loop quota on real disk |
| **Devices** | `vgpio:` | *Only* the named GPIO/I²C/SPI/LED nodes, nothing else | fresh `/dev` + fd-pinned bind + capability deny-list (raw-mem/disk/kvm refused) |
| **PIDs** | `--pids-limit` | Fork-bomb ceiling | cgroup `pids.max`, hard |
| **Block I/O** | `--io-weight` | I/O bandwidth weight | cgroup `io` |
| **GPU** | *(roadmap)* | Not shipped | see [Roadmap](#roadmap) |

¹ Where the `memory` controller is not delegated to a non-root user's scope, kern warns and shows the one-line
`.wslconfig` fix; enforced natively on Linux.

**How to check a cap, and how not to.** `free`, `top` and `htop` inside a box report the **host's** memory,
not the box's, because the kernel does not namespace `/proc/meminfo`. That is true of every container
runtime without a `/proc` shim, and it makes a cap that *is* enforced look absent. The distinction that
matters in practice: a runtime that sizes itself from the **cgroup** (a modern JVM, Go's memory limit, most
container-aware tooling) gets the right number; one that reads `/proc/meminfo` gets the host's. Read the
cgroup, or hit the ceiling and watch the kernel do it:

```sh
kern box check --image alpine --memory 256m -- cat /sys/fs/cgroup/memory.max   # 268435456
kern box oom   --image alpine --memory 256m -- \
  sh -c 'dd if=/dev/zero of=/dev/shm/x bs=1M count=512' ; echo "exit=$?"       # exit=137, OOM-killed
```

The cap binds on every host tested. On the Arduino UNO Q the BOX exits 143 rather than 137, and the
reason is measurable rather than a platform quirk: the workload itself is SIGKILLed by the cgroup
(`dd` exits **137** there, captured to a file before the shell dies), and the box's own init is
terminated afterwards, which is the 143. Android's `lmkd` is **not running** on that board, so it is
the cgroup doing the killing, not a host-level low-memory killer. `memory.max` reads back 33554432
throughout.

`cpu.max` reads the same way: `50000 100000` is half a core, `200000 100000` is two.

`--pids-limit` counts **every task in the box**, not just the ones your workload forks, so the forks
available to you are the limit minus whatever is already there. That baseline is not a fixed number: it
depends on whether the command is a shell or an exec'd binary, and on whether the box is detached. On the
box measured here it was 2, so `--pids-limit 30` allowed 28 forks before the kernel returned `EAGAIN`
(`can't fork: Resource temporarily unavailable`). It is a fork-bomb ceiling, not an exact budget for your
own processes. Profiles (`vcpu:`/`vdisk:`/`vgpio:`) are reusable presets in
`~/.config/kern/kern.toml`, see [docs/CONFIG.md](docs/CONFIG.md). Author them with `kern probe` (list the
host resources you can slice), `kern examples` (print a sample `kern.toml`), and `kern validate` (check one).

### Profiles

Name a slice once, attach it by name, and stop repeating flags. Profiles live in
`~/.config/kern/kern.toml`, so nothing has to be passed on the command line:

```sh
kern config add vcpu:slim --cpus 0.5 --memory 256m       # or edit the file by hand
kern box app --image alpine vcpu:slim -- ./app           # no flag: the profile is just there
kern run vcpu:slim -- ./train.sh                         # the same slice, no sandbox
```

What that wrote, and what a hand-written one looks like:

```toml
[[vcpu]]
name    = "slim"
backend = "host"     # the host resource being sliced: "host" is the whole CPU, so no [[cpu]] block
cpus    = 0.5
memory  = "256 MB"

[[vgpio]]
name    = "sensor"   # the interesting one: exactly one device node, everything else denied
backend = "host"
i2c     = ["/dev/i2c-1"]
```

Profile tokens go BEFORE the `--`: `vcpu:` · `vdisk:` · `vgpio:`. Use `--config ./kern.toml` only to
point at a per-project file instead of the default, or export `KERN_CONFIG` to make that the file every
command reads and writes. The full schema, every field, the 7-layer precedence and `extends` are in
**[docs/CONFIG.md](docs/CONFIG.md)**; a runnable walk-through is
[resource-profiles.sh](examples/resource-profiles.sh).

## What you can do in one line

### An isolated container, zero setup

No daemon, no root: one ~1.8 MB binary.

```sh
kern box try --image alpine -- sh
```

### Exactly one device, nothing else

Deny-by-default: only the peripheral you name crosses the boundary.

```sh
kern box iot --image alpine vgpio:sensor -- ./read.py   # only /dev/i2c-1 crosses in
```

### A fresh sandbox per request

Serverless-style, on your own machine: one throwaway box per call.

```sh
echo "$payload" | kern box fn --image python -- handler.py
```

### Where a Docker daemon is too heavy

The same box on a Pi or an Android-kernel board: just copy the one binary.

```sh
scp kern pi:  &&  ssh pi 'kern box edge --image alpine -- ./agent'
```

### Build, tag, push, all daemonless

```sh
kern build -t app:1 . && kern tag app:1 registry.example/app:1 && kern push registry.example/app:1
```

## Features

Daemonless, rootless, and complete: the full container UX plus resource slices, in one binary.
For every flag and command, run `kern --help`: it is generated from the parser, so it cannot
drift from what the binary accepts the way a hand-kept list in here would.

- **Run anything, isolated**: OCI images from any registry (v2 auth, multi-arch, gzip **+ zstd**) or a `--rootfs`; CoW overlay (image immutable, scratch discarded) or `--read-only`; `-it` TTY; `--init` PID-1 reaper.
- **Governed slices**: hard cgroup v2 caps on any `box`/`run`: `--memory` · `--cpus` · `--cpuset-cpus` · `--memory-swap-max` · `--pids-limit` · `--io-weight` · `--nice`. `kern run` is the governor with no sandbox.
- **Data & devices**: `-v` volumes (symlink-safe) · named volumes with a `--size` quota · network volumes (`nfs`/`smb`/`sshfs`) · `--secret` → `/run/secrets` (RAM, `0400`) · `vdisk:` scratch · `vgpio:` device passthrough (deny-by-default) · `--tmpfs`.
- **Network & identity**: isolated by default; `--network host` for outbound; **`--egress-allow d1,d2`** (⚠️ experimental) restricts outbound to an allowlist of domains via a kern-run filtering proxy (an agent can `pip install` but can't exfiltrate to an arbitrary domain), with honest known gaps documented in [docs/EGRESS.md](docs/EGRESS.md); `-p` rootless publish (loopback unless you ask); in-box `--ssh`; `--pod` shared-net pods (`--no-outbound`); `--tun`; `--user`.
- **Least privilege**: 13 dangerous caps always dropped (`--cap-add`/`--cap-drop`); an always-on **seccomp** denylist (kexec, modules, ptrace, mount API, `setns`, …) that also kills wrong-arch + x86_64 x32-ABI aliases; opt-in **Landlock** (LSM) write-allowlist (`--landlock-rw <path>`): the box root is read+exec and writes are confined to the paths you name, a kernel-enforced second boundary the workload can't lift.
- **Lifecycle, no daemon**: `--restart` + `--health-cmd`; `cp`/`pause`/`attach`/`exec`/`rename`/`update`/`wait`/`diff`/`events`; `ps`/`top`/`stats`/`logs`/`inspect`/`prune`/`gc`/`history`/`recover`; `compose` (reads `docker-compose.yml` too); reusable `[[vcpu]]`/`[[vgpio]]`/`[[vdisk]]` profiles; `kern doctor`.


**Built-in hardening.** User+PID+net+UTS+IPC+mount namespaces, self-pivot root, `nosuid,nodev` box
root, always-on seccomp, least-privilege caps, hard cgroup caps (via `systemd-run` where present);
every pulled blob sha256-verified and every layer vetted in-process (no `..`/absolute/device escapes,
decompression- & inode-bomb caps) before an isolated no-follow merge. Where a guarantee is cooperative
or opt-in (vGPIO/vDisk trust scope, network volumes), [SECURITY.md](SECURITY.md) says so.

## Install

**🐧 Linux & ARM boards** (Raspberry Pi · Jetson · Arduino UNO Q). One line; auto-detects `x86-64` / `aarch64`:

```sh
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
```

Served from **github.com** (read the script first if you like). It downloads the release binary for
your arch and verifies the sha256 before installing. No Rust toolchain required. (`getkern.dev/install.sh`
is a short alias.)

**🪟 Windows.** One line in PowerShell (no Docker Desktop, no Ubuntu):

```powershell
irm https://raw.githubusercontent.com/getkern/kern/main/install.ps1 | iex
```

kern runs inside **WSL2**, a real Linux kernel, so the isolation (namespaces + seccomp) and `--cpus`
cap work for real, `--memory` included: measured on a stock WSL2 kernel (6.18), a 128m box reads back
`memory.max = 134217728`. Where a host does not delegate the `memory` controller (a stock Raspberry Pi
OS, and older WSL2 kernels), kern **warns** and shows the one-line fix rather than pretending, see
[Requirements & limitations](#requirements--limitations). On a native Linux host `--memory` is enforced
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
[Benchmarks](BENCHMARKS.md#windows-where-the-milliseconds-go) has the table, the variance, and what was
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

**📦 Offline / air-gapped** (a board or locked-down server with no internet). kern is a single
~1.8 MB static binary, so copying that one file *is* the install:

```sh
scp kern pi@raspberrypi:~/          # then:  ssh pi@raspberrypi kern box dev --image alpine -- sh
```

No daemon, no package, nothing to install on the target, which is why it runs where Docker can't
(see [EDGE.md](EDGE.md)).

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


## Quickstart

### Start here

A sandboxed shell from any OCI image. The image stays read-only; your writes go to a scratch overlay that vanishes on exit.

```sh
kern box dev --image alpine -it -- sh
```

That box starts in **3.4 ms**, not the 2.1 ms of a bare rootfs box: an OCI image gets a rootless
uid-range mapping so an official image can drop privilege in its entrypoint, and that costs two
setuid helpers (0.9 ms, run concurrently, unavoidable without `CAP_SETUID`; measured as 3.4 against
2.4 with `--no-uid-range`). Measure it yourself
with `kern bench --image alpine`, or drop it with `--no-uid-range` if your workload stays root.

### Cap what it can use

Hard memory + CPU limits (cgroup v2). `kern run` is the leanest path: a quota on a host command, no sandbox.

```sh
kern run --memory 256M --cpus 0.5 -- ./crunch-numbers
kern box build --image alpine --memory 512M --cpus 1.5 -v "$PWD:/src" -w /src --net -- make
```

### Run it as a service

Detached, a published port, restarts if it dies, health-checked, without a daemon.

```sh
kern box svc --image alpine -d -p 8080:80 --restart \
  --health-cmd 'wget -qO- localhost:80' -- httpd -f
```

### See & control what's running

```sh
kern ps                   # running boxes, with PORTS + HEALTH
kern top                  # live TUI: boxes, CPU/RAM, profiles
kern exec svc -it -- sh   # shell into a running box
kern logs svc -f          # its output, followed live (--tail N for the last N)
kern diff svc             # files changed vs the image (C = changed, D = deleted)
kern update svc --memory 1g   # retune caps live; rename/wait/events too
kern stop svc             # stop it   (kern stop --all for everything)
```

### Hand it a secret

Never baked into the image or env; delivered on a pipe, readable only inside the box. The network is
isolated by default, so `--egress-allow` opens exactly the one host it may reach (and `wget` is
Alpine's busybox built-in, no extra install):

```sh
printf "$DB_TOKEN" | kern box job --image alpine --secret TOKEN=- --cap-drop ALL \
  --egress-allow api.example.com \
  -- sh -c 'wget -qO- --header="Authorization: Bearer $(cat /run/secrets/TOKEN)" https://api.example.com/v1/me'
```

### Before you rely on it

```sh
kern doctor               # will boxes even run on this host? preflight it
kern compose stack.toml   # bring up a stack in dependency order (TOML or compose.yml)
```

## Build & publish images

kern builds OCI images from a Dockerfile **without a daemon**: each `RUN` is a real `kern box`, each
step a content-addressed layer, reused on an unchanged rebuild.

```sh
kern build -t app:1 -f Dockerfile .          # FROM RUN COPY ADD ENV WORKDIR USER CMD ENTRYPOINT SHELL …
kern build -t app:1 --build-arg VER=9 .       # build args; multi-stage (FROM … AS b; COPY --from=b)
kern save app:1 -o app.tar                    # export a docker-load-compatible image tar …
kern load -i app.tar                          # … and import one (docker save format)
kern tag app:1 registry.example/app:1         # give a cached image a second name
kern commit devbox warmenv:1                  # snapshot a running box's fs into a reusable image
kern login registry.example                   # (private) creds stored 0600
kern push registry.example/app:1              # publish as a single-layer OCI image
```

**Warm start (`kern commit`).** Bake an expensive one-time setup (`apt`/`pip` installs, a warmed cache,
compiled artifacts) into a local image once, then start the next box from it instantly. It reads the
box's kernel-merged overlay through `/proc/<pid1>/root`, so whiteouts are already resolved, and skips
every nested mount, so a `-v` volume or a secret is never baked into the image. It's `docker commit`,
daemonless. A filesystem snapshot, not live memory: processes restart fresh (write state to disk if you
need it back).

kern parses **real-world Dockerfiles** as-is (comments inside `\` continuations, `SHELL`, BuildKit
`RUN --mount`/`ADD <url>` with `--checksum`/`--chmod`, `COPY <<heredoc`, `FROM scratch`, `# escape`
and BOM) and honours **`.dockerignore`** (also `.kernignore`), so a `COPY . /app` won't bake your
`.git`, `.env` or secrets into the image. **Multi-stage** builds run each stage in its own box and
confine `COPY --from=<stage>` to that stage's filesystem (a hostile source path or symlink can't read
the host). Layers pull as gzip **or zstd**. `push` normalizes ownership and strips setuid/setgid, so an
untrusted base can't smuggle a privilege-bit into what you publish. (`build`/`push` are the newest
surface, see [Project status](#project-status).)

## Embed it

Run a sandboxed command straight from your program: a fresh isolated box per call (untrusted code,
agent tools, per-request workers), and a structured result back, including rich mime-typed results
(charts, tables, the last expression) the way a Jupyter cell returns them, but local and daemonless.

```python
from kern_sandbox import Sandbox              # pip install kern-sandbox
with Sandbox(memory_mb=512, network=False) as s:
    print(s.run_code("print(6 * 7)").stdout)  # 42
```

```js
import { withSandbox } from "kern-sandbox";   // npm install kern-sandbox
await withSandbox({ memory: "512m", network: false }, async (s) => {
  console.log((await s.runCode("print(6*7)")).stdout);   // 42
});
```

```rust
use kern_isolation::Sandbox;                  // the crate the CLI itself uses
let out = Sandbox::builder().memory_max(512 << 20).build()?.run("echo", &["hi"])?;
```

Pure standard library on both sides, no transitive dependencies: the bindings shell out to the same
`kern` binary you already have. Full API, limits, file transfer and the rich-result shape:
**[Python](bindings/python/README.md)** · **[Node](bindings/node/README.md)** ·
[agent-code-interpreter.py](examples/agent-code-interpreter.py).

## Platforms

**Linux, multi-architecture.** Prebuilt static (musl) binaries for **`linux-x86_64`** and
**`linux-aarch64`**: one ~1.8 MB file, no Rust deps beyond `libc` (the pull path shells out to system
`curl`/`tar`).

| Platform | Arch | Status |
|---|---|---|
| x86_64 Linux | x86_64 | ✅ primary + automated CI |
| **Windows 10/11 (via WSL2)** | x86_64 | ✅ CI-built shim + distro (`install.ps1`) |
| NVIDIA Jetson (L4T) | aarch64 | ✅ manually validated |
| Raspberry Pi 5 | aarch64 | ✅ manually validated |
| Arduino UNO Q (Android kernel, Debian userland) | aarch64 | ✅ manually validated |

kern needs a **Linux kernel** with **unprivileged user namespaces** + **cgroup v2**, and a **Linux
userland**. The kernel *flavor* doesn't matter: kern runs even on an *Android kernel* with a Linux
userland (the Arduino UNO Q). **On Windows, WSL2 *is* that Linux kernel**, and the one-line PowerShell
installer sets up WSL2 and drops in a pre-baked kern distro, so isolation, `--cpus` and `--memory` are
all enforced for real (measured on a stock 6.18 WSL2 kernel: a 128m box reads back `memory.max =
134217728`). Honest
caveat: you're inside the WSL2 VM, so it's "no Docker Desktop", not "no VM". kern does **not** run on stock Android-the-OS (Bionic, SELinux, userns off). Daemonless is a big
win on RAM-constrained boards (0 resident vs ~160 MB), see **[EDGE.md](EDGE.md)**. ARM CI is tracked
in the issues.

## Docker compatibility

kern speaks Docker's **formats**, so your existing images and stacks just work, but it does **not**
reimplement the Docker Engine API. It's a lightweight alternative, not a drop-in clone.

| From your Docker setup | kern |
|------------------------|------|
| **OCI images** (Docker Hub, GHCR, quay, Harbor, self-hosted) | ✅ pull & run: multi-arch, `WWW-Authenticate` v2 auth, gzip **+ zstd** |
| **`docker-compose.yml`** | ✅ `kern compose <file> [up\|down\|stop\|start\|restart\|ps\|logs\|build\|pull\|config]` reads real-world files as-is: `depends_on` (+ `service_healthy`/`_completed` conditions), `healthcheck`, `deploy.resources.limits`, `ulimits`, `sysctls`, `labels`, `extra_hosts`, `init`, `stop_signal`/`stop_grace_period`, YAML **anchors/merge** (`<<: *x`), **`extends`**, `x-` extension fields, the project **`.env`**, `${VAR:-default}` and bare `$VAR` interpolation, network **aliases**. Multiple files merge (`-f base.yml -f override.yml`), plus `-p`/`--env-file`/`--profile`. `up` **reconciles**: a service still matching the file is left running, a changed one is recreated |
| **Dockerfile** `build` | ✅ `kern build`: all common instructions, **multi-stage**, `COPY --from=…` (a build stage **or** an external image), **COPY globs** (`*.txt`, `src/*`, `[ab].conf`), BuildKit **heredocs**, `ADD <url>` (+ `--checksum`/`--chmod`), `COPY --chmod` (recursive, Docker-parity), `FROM scratch`, `SHELL`, `# escape`/BOM, `--build-arg`, a **whole-build cache**, and honours **`.dockerignore`**. Daemonless: each `RUN` is a real box. The cache is keyed on the whole Dockerfile + context, NOT per layer as Docker's is: an identical build is reused (2040 ms to 24 in one measurement), and changing any instruction re-runs from the first, including steps before the edit |
| **`.dockerignore`** (also **`.kernignore`**) | ✅ excluded from the build context: keeps `.git`/secrets out of the image (last-match-wins, `!` re-include, `**`) |
| **`docker save` / `load` archives** | ✅ `kern save` / `kern load`: export/import an image tar, `docker load`-compatible |
| **`tag` / `push`** to a registry | ✅ `kern tag` / `kern push` |
| **Image management** (`docker images` / `rmi` / `search`) | ✅ `kern images` (list cached), `kern rmi` (remove, frees unshared layers), `kern search` (Docker Hub) |
| **`docker commit`** (container → image) | ✅ `kern commit <box> <image>`: snapshots the box's filesystem to a reusable image (warm start); skips volumes/secrets |
| **Docker Engine API** / `docker.sock` | ❌: tools that attach to the socket (Docker Desktop, some IDE/CI plugins) won't connect |
| **Swarm** (multi-host orchestration) | ❌ and there is no workaround: clustering, service replicas and rolling updates across machines are out of scope for a single-host, daemonless runtime. `kern compose` is one machine, one pod. |

**One stack, one network namespace.** The services of a `kern compose` stack share a
single network namespace, like the containers of a Kubernetes pod: they reach each
other by service name on `127.0.0.1`, with no bridge, no IPAM and no DNS server.
That is what makes a stack start in milliseconds, and it has one consequence worth
knowing before you choose kern: **two services cannot both listen on the same
container port**, even when their published ports differ. Two apps that both default
to `:3000` is the common case, so kern refuses it *before* starting anything and names
both services. The same applies to `net.*` sysctls, which belong to the namespace and
therefore to the whole stack.

Declare the port each service listens on and the conflict goes away:

```yaml
services:
  api:    { image: node:20-slim, port: 3000 }
  admin:  { image: node:20-slim, port: 3100 }
```

kern passes it as `PORT`, which most images read, and reserves it for that service, so
peers keep using the name (`http://admin:3100`) with nothing remapped at run time.
Docker's own `expose:` says the same thing and is honoured identically, so a stack that
already uses it needs no edit.

Three spellings, one space: `ports:` (published), `port:` (declared and passed as
`PORT`), `expose:` (declared only). A service that publishes nothing is visible to the
check only if it declares something. Every edge case is decided rather than left to chance
(a conflicting `PORT=` is refused by name, a range in `ports:` is expanded and checked
port by port, a range in `expose:` is never silently expanded, `--no-pod` lifts the
constraint entirely): [compose-declared-ports.sh](examples/compose-declared-ports.sh) runs
through them.

One deliberate asymmetry: a malformed entry in *your* kern profile is refused with its
line number, while the same entry in someone else's `docker-compose.yml` is warned about
and skipped. Failing a whole stack over one line of documentation is the wrong trade for a
file kern did not write; for a file you did, a typo should be named at once.

`kern compose <file> config` prints what kern understood, reservations included, and
refuses exactly what `up` would refuse: a dry run that disagreed with the bring-up would
be worse than no dry run.

### Starting a stack at boot

kern is daemonless, so after a reboot PID 1 starts, not kern. `kern compose <file> systemd` prints a
unit on stdout and installs nothing: where it belongs is a decision about your machine.

```console
$ kern compose stack.yml systemd > ~/.config/systemd/user/kern-shop.service
$ systemctl --user daemon-reload && systemctl --user enable --now kern-shop.service
$ loginctl enable-linger $USER        # or the unit stops when you log out
```

**It does not supervise.** The unit brings the stack up and tears it down; a service that dies an
hour later is not restarted, and the generated unit says so in its own comments rather than letting
you assume otherwise. Walk-through: [compose-systemd-unit.sh](examples/compose-systemd-unit.sh).

### Everyday `docker` commands

Most container-lifecycle verbs you type daily have a 1:1 `kern` equivalent (same name where it makes sense):

| `docker …` | `kern …` | Notes |
|---|---|---|
| `run` / `create` | `box` | one verb; `-d` detaches, `-it` for a PTY |
| `exec` | `exec` | joins the box's namespaces |
| `ps` | `ps` | `-q`, `--filter name=/status=/id=`, `--format '{{.Field}}'`, `--json` |
| `logs` | `logs` | `--tail N`, `-f`/`--follow` (bounded read, cheap on GB-size logs) |
| `stop` / `kill` | `stop` / `kill` | SIGKILL the box's process group |
| `pause` / `unpause` | `pause` / `unpause` | cgroup v2 freezer |
| `attach` | `attach` | Ctrl-C detaches, box keeps running |
| `cp` | `cp` | host↔box, symlinks can't escape the box root |
| `inspect` | `inspect` | `--json` |
| `stats` | `stats` | per-box CPU / memory |
| `top` (box processes) | `exec <box> ps` | plus `kern top`, the live TUI for every box |
| `rename` | `rename` | in place, pid unchanged |
| `update` | `update` | live cgroup caps, no restart (needs a delegated cgroup) |
| `wait` | `wait` | prints the exit code (`137` after `stop`) |
| `diff` | `diff` | overlay-upper changes: `C` changed/added, `D` deleted |
| `events` | `events` | poll-based stream (`start`/`die`/`rename`); daemonless, best-effort |
| `commit` | `commit` | box → reusable image (warm start) |
| `start` (resume a *stopped* container) | *(none)* | a box can run **as long as you want** (detach with `-d --restart` for a DB or server that stays up for days) and its **volumes persist on disk**; what's not supported is *resuming* a box you already stopped - you launch a fresh one that re-attaches the same volume |

Multi-service stacks **are** supported: `kern compose` reads your `docker-compose.yml` and brings the
services up in a pod, with `depends_on` ordering and healthchecks, daemonless. What needs a daemon
does not exist here: `swarm` / `service` / `stack`, `docker.sock`, and anything that attaches to it.

## When to use kern (and when not)

**✅ Use kern when you want:**

- a **fast, daemonless sandbox** for your own or **agent/LLM-generated** code (fresh box per call, embeddable from Rust/Python);
- **CI / build** boxes, or a throwaway dev environment, without a background daemon;
- containers on **edge / ARM** boards where a Docker daemon is too heavy or absent (Pi, Jetson, Android-kernel);
- **resource slices** beyond containers: `vcpu:` / `vdisk:` / `vgpio:` (GPU on the roadmap).

**❌ Do NOT use kern when you need:** (reach for the tool named after each)

- a hard boundary against **actively hostile multi-tenant** code → a **microVM** (Firecracker) or gVisor. kern's FS/PID/namespace/cgroup isolation is a real kernel boundary for *your own or semi-trusted* code, not a VM;
- the **Docker Engine API / Docker Desktop** workflow, or a true CLI drop-in → **Docker / Podman**;
- **network isolation between the services of one stack**, or `deploy.replicas` → Docker Compose or
  Kubernetes. A `kern compose` stack is one pod on one machine: services share a namespace and reach
  each other by name, which is what makes it start in milliseconds and is also its ceiling;
- **Kubernetes CRI** integration → containerd / CRI-O;
- a **low-level OCI runtime** to slot *under* containerd/podman (the runc layer) → **crun**, **youki** (also Rust), or runc. kern isn't a runc-replacement; it's the *whole* daemonless UX (pull, build, run, compose) in one binary, not a runtime another engine drives.

kern states every boundary that is cooperative or opt-in plainly in **[SECURITY.md](SECURITY.md)**; being honest about the edges is the point. You do not have to take any of it on trust: the four
adversarial suites in **[pentest/](pentest/)** assert those boundaries against the kernel rather than
against kern's own reporting, and `sh pentest/run-with-local-registry.sh ./target/release/kern
pentest/pentest-ports.sh` runs them with no registry account and no network.

## How it works

```text
   kern  ·  one static binary, no daemon        box · run · compose · exec · pull · top …
     │
     ▼
   runtime  (kern-isolation)
     ├─ namespaces   user · pid · net · mnt · uts · ipc
     ├─ rootfs       OCI overlay → pivot_root   (typestate: Mounted → OldRootReady → ReadOnly)
     ├─ devices      fresh /dev · vgpio passthrough · -v volumes (symlink-safe)
     ├─ cgroups v2   MemoryMax · CPUQuota · TasksMax
     ├─ seccomp      always-on denylist (+ wrong-arch / x32)
     └─ supervisor   fork → PID 1 → reap → exec / stats / stop
     │
     ▼
   images  (kern-oci)   registry v2 · sha256 per blob · in-process tar vetting
```

A `kern box` is one short-lived process tree: no daemon, no shared state.

1. **Namespaces.** `unshare` into a fresh user + PID + UTS + IPC namespace (and, by default, an
   isolated loopback-only net namespace; `--net` shares the host's, opt-in, flagged in the status
   panel). A single-uid map makes your uid root *inside* the box only; `--uid-range` opts into a full
   sub-id range.
2. **Root filesystem.** An **overlay** by default (image = read-only lower, a private upper takes
   writes); `--read-only` remounts it read-only *after* a self-pivot (`pivot_root(".", ".")`), which
   works even where a bind remount-RO is denied (some Android-kernel boards). Nothing is written into
   the rootfs, so many boxes share one read-only rootfs concurrently. (`--bind-rootfs` swaps the
   overlay for a direct bind: faster on a slow overlayfs, at the cost of a mutable shared source.)
3. **Devices, volumes & secrets.** A fresh `/dev` with the safe nodes (`+ /dev/net/tun` on `--tun`);
   `-v` volumes bound in with targets resolved **symlink-safely**, confined to the new root; secrets
   on a RAM `/run/secrets` (`0400`); `vdisk:`/`vgpio:` mounting exactly their declared disk/peripherals.
4. **Lockdown.** A clean env (no host secrets leak in), capabilities stripped to least-privilege, an
   optional `--user` drop, an always-on **seccomp** denylist (incl. wrong-arch + x32), and cgroup caps:

`kern box <name> --plan` prints the exact sequence for your invocation, without running it: that
output is generated from the code, so it cannot drift the way a description here would.
See **[ARCHITECTURE.md](ARCHITECTURE.md)** for the design and **[SECURITY.md](SECURITY.md)** for
where each boundary is real, cooperative, or opt-in.

## Performance

One isolated `/bin/true`, warm image cache, one box per run. The x86_64 row below was measured on an
**Intel i7-14700KF (20-core / 28-thread), Linux 7.0, NVMe, systemd-user** desktop, which is the same
machine the hero and demo numbers come from, in one sitting against the runtimes installed there
(exact per-runtime commands in **[BENCHMARKS.md](BENCHMARKS.md)**). Your numbers vary with hardware,
kernel and load, so measure your own with `kern bench --rootfs <dir>`; board rows are from on-device
runs.

### A working day, not a cold start

Cold start is quoted everywhere because it is easy to measure, but nobody notices 300 ms once. What a
developer feels is the twentieth `exec` of the afternoon. Same machine, same images, real commands,
timed with the shell:

| what you actually type | kern | docker | podman |
|---|---:|---:|---:|
| a throwaway box (`run … true`) | **3.4 ms** | 290.8 ms | 290.5 ms |
| `exec` into a running service | **0.79 ms** | 43.3 ms | 148.6 ms |
| list what is running (`ps`) | **0.30 ms** | 8.2 ms | 13.5 ms |
| read logs | **0.35 ms** | 8.2 ms | 37.5 ms |
| stop a service (`--init` handles SIGTERM) | **2.4 ms** | ~300 ms | |
| bring a 2-service stack up | **185 ms** | 301 ms | |

> Reproduce any row with `time`, on both sides. No script of ours is involved.

**One row needs a caveat we would rather state than be caught on.** Stopping a service whose init does
*not* handle SIGTERM takes 10 s on Docker and Podman, and 2.7 ms on kern. That is **not** Docker being
slow: a PID-namespace init discards signals it has no handler for, so the container genuinely cannot
die of SIGTERM, and waiting the full grace before `SIGKILL` is the correct, documented behaviour. kern
reads `/proc/<pid>/status` first and skips a wait that provably cannot end. The honest comparison is
the row above, with an init that *does* handle the signal: 2.4 ms against ~300, for the same reason every
other row is fast, not because of a container that ignores signals.

| host | kernel | **kern** | bubblewrap | runc | docker |
|---|---|---:|---:|---:|---:|
| x86_64 desktop | v7.0 | **2.2 ms** | 3.0 ms | 13.2 ms | 294.4 ms |
| Raspberry Pi 5 | v6.6-rpi | **11.8 ms** † | not installed | not installed | not installed |
| Jetson Orin Nano | v5.15-tegra | **12.5 ms** † | 5.6 ms | 32 ms ‡ | 472 ms ‡ |
| Arduino UNO Q | **v6.16 Android** | **91.5 ms** † | 15.0 ms | 76 ms ‡ | 858 ms ‡ |

kern and bubblewrap were measured together on 2026-07-30, three repeats each, median of medians, on an
idle host. ‡ = runc and docker are carried over from the earlier round and were **not** re-measured that
night. On the **Pi 5, kern is the only runtime present at all**: docker, podman, runc, crun, bwrap,
nerdctl, lxc and systemd-nspawn are all absent, checked one by one. One ~1.8 MB static binary just works
where the others are each a setup step (Docker alone is a ~160 MB daemon stack). That reach, not a
latency crown, is what the boards are here to show.

† **The kern column enforces resource caps and the bubblewrap column does not, because bubblewrap has no
caps to enforce.** `memory.max` was read back as 268435456 inside the box on every host in the table. The
boards give kern no delegated cgroup slice, so the only way to make a limit bite there is a systemd
transient scope, and that scope is the entire difference: `systemd-run --user --scope /bin/true` alone
costs 9.4 ms on the Pi, 9.0 on the Jetson and 59.9 on the Arduino, against gaps of 9.2, 9.3 and 58.2 ms
between kern's capped and uncapped runs on those same boards. The arithmetic closes to within 1.7 ms
everywhere, which is why the boards' figures are a fallback path rather than the engine.

**The toll is avoidable, and that is the point.** An SSH login sits under the SYSTEM systemd manager
while kern's delegated `kern.slice` lives under the USER manager, and cgroup v2 will not migrate a
process across that boundary. Enter the user manager's tree once and every box after it takes the
direct path, caps still enforced:

```sh
systemd-run --user --scope bash     # pay it once, then run kern inside that shell
```

| board | as an SSH login | inside one scope | + `--bind-rootfs` |
|---|---:|---:|---:|
| Raspberry Pi 5 | 11.8 ms | **3.0** | **2.8** |
| Jetson Orin Nano | 12.5 ms | **4.6** | **4.2** |
| Arduino UNO Q | 91.5 ms | **35.5** | **11.3** |

All four columns come from ONE sitting per board, so they compare with each other; the small drift
against the table above (11.7 vs 11.9 on the Pi) is two rounds an hour apart, not a change.

Eight times faster on the Arduino, four on the Pi. `kern doctor` measures the toll on your host and
prints that command. It also settles the bubblewrap comparison on the boards: kern *enforcing a memory
limit* is **4.2 ms against bubblewrap's 5.6** on the Jetson and **11.3 against 15.0** on the Arduino,
while bubblewrap enforces nothing.

At the same level of work, from the same round:

| board | kern, cgroup off | bubblewrap | |
|---|---:|---:|---|
| x86_64 desktop | **2.2 ms** | 2.9 ms | kern |
| Jetson Orin Nano, `--bind-rootfs` | **3.5 ms** | 5.6 ms | kern |
| Arduino UNO Q, `--bind-rootfs` | **9.6 ms** | 15.0 ms | kern |
| Raspberry Pi 5, `--bind-rootfs` | **2.3 ms** | not installed | |

`--bind-rootfs` is the like-for-like flag because bubblewrap binds rather than overlays; comparing kern's
default overlay against it compares two mount strategies, not two runtimes. It is worth reaching for only
on the Arduino, whose Android kernel spends **22.4 ms** in the overlay mount alone against ~0.1 ms on
x86: it takes that board from 91.7 ms to 69.2 with caps enforced, and from 33.5 to 9.6 with the cgroup
off. Elsewhere it is worth a few tenths. Every row in the first table is the default path, so the boards
are compared with each other rather than each with its own best flag.

Wherever kern can take its **direct** cgroup path it does not pay the scope toll at all: 2.6 ms on x86
with the cap enforced, against 4.2 ms for `systemd-run --user --scope /bin/true` on that same machine,
which is the round trip kern is avoiding. **3.4 ms inside WSL2** with the cap enforced, re-measured on
2026-07-31; `systemd-run` does not exist there at all, so the direct path was already the only one.

kern is the fastest sandbox on the desktop at **2.2 ms**, ahead of bubblewrap at 3.0 by 0.8 ms, and the top tier is
all within a few ms: nobody wins single-shot latency outright. The real gap is to the **engines**,
**~132x faster** on that same bare-rootfs path and **~86x** on the `--image` path that also maps a uid
range, against podman at 290.5 ms and Docker at 290.8, which round-trip a daemon every run. Beyond
one start: **451 boxes/s**, **0.35 MB** of real memory per additional box (PSS at 50 live boxes; the
RSS a monitor shows is 4.6 MB because two processes share one static binary's pages), **0 resident**
where Docker keeps 154 to 160 MB with zero containers running. Where the time goes, phase by phase: **[BENCHMARKS.md](BENCHMARKS.md)**.

Reproduce with **[`examples/benchmark.py`](examples/benchmark.py)** (auto-detects the runtimes you
have). kern does *less* than Docker (no overlay networks yet, see [Roadmap](#roadmap)); this compares
the run path.

## Real-world examples

Runnable, live-verified scripts in **[examples/](examples/)**:

| Scenario | Example |
|---|---|
| **A guided tour**: a tool, your code, resource caps, untrusted code, a service | [showcase.sh](examples/showcase.sh) |
| **Try to break out**: an adversarial isolation battery + 50 boxes at once | [hardening.sh](examples/hardening.sh) |
| Safely vet an untrusted `curl … sh` install script (no net, no host access) | [safe-install-script.sh](examples/safe-install-script.sh) |
| Per-job pipeline: read-only input → isolated processing → output | [data-pipeline.sh](examples/data-pipeline.sh) |
| Build/test a repo in a clean box (laptop or on-device) | [ci-in-a-box.sh](examples/ci-in-a-box.sh) |
| Many isolated services on a small board (a fraction of a MB each vs a ~160 MB daemon) | [edge-many-services.sh](examples/edge-many-services.sh) |
| Head-to-head timing: kern vs `docker run` | [compare-vs-docker.sh](examples/compare-vs-docker.sh) |

…plus governed runs, port-published services, compose stacks and more, see
**[examples/README.md](examples/README.md)**.

## Requirements & limitations

kern trades breadth for a small, honest core. What it needs, and what it deliberately does not do:

**Requires:**
- A **Linux kernel** with **unprivileged user namespaces** + **cgroup v2**. On Windows it runs under
  WSL2; there is no native macOS/Windows port ([Roadmap](#roadmap)).
- Hard `--memory`/`--cpus`/`--pids` caps need a **delegated cgroup** (a systemd user manager, or root);
  without one they degrade to best-effort and kern says so. Microsoft's default WSL2 kernel and a stock
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
  or gVisor instead is spelled out in [When to use kern (and when not)](#when-to-use-kern-and-when-not)
  and the [threat model](SECURITY.md).
- **No overlay / software-defined networking** (a box gets an isolated netns, or the host's; a pod
  shares one) and no Docker plugin ecosystem.
- **`kern exec` caps** are inherited only where kern can join the box's cgroup (root, or a delegated
  `kern.slice`); on a rootless per-box-scope host the exec'd command runs outside the box's
  `--memory`/`--pids` (namespaces + seccomp still isolate it), and kern warns.
- **GPU** slices are on the [Roadmap](#roadmap), not shipped.

## Project status

**0.6.31.** Everything in [Features](#features) works today and is tested (691 Rust, 65 Python and 54
Node tests; clippy-clean, `cargo-deny`-clean, adversarially reviewed slice by slice); the isolation is
real. kern trades Docker's breadth (overlay networks, a plugin ecosystem) for a small, fast core that
starts in single-digit milliseconds from one **~1.8 MB** binary. Versioned under semver: each release is the official
build of that version, and pre-1.0 means only that the CLI and config *surface* can still change between
minor versions, always called out in [CHANGELOG.md](CHANGELOG.md).

What kern knows it does not know, or does not do yet, is written down in
[OPEN_ITEMS.md](OPEN_ITEMS.md) rather than left for you to discover: a gap in a startup measurement
we have not attributed, why the seccomp filter is still a denylist, which fleet limit is a guard rail
instead of a boundary. Declared debt is cheaper than silent debt.

**Recently:** 0.6.31 fixes a stall on published ports that anyone serving HTTP would have hit.
`kern box -p` pumps bytes in userspace and neither side set `TCP_NODELAY`, so a response written as
headers-then-body waited on the peer's 40 ms delayed-ACK timer, and only on a REUSED connection: the
normal mode for HTTP/1.1, gRPC, Postgres and Redis. Measured with nginx on one keep-alive connection,
**59 requests/s before and 12,479 after**, with p99 going from a pinned 42.0 ms to 0.27. Before that,
0.6.30 was a correctness release: an OCI whiteout that could not be applied was reported as applied,
image content is now deleted by a no-follow tree walk, directory modes are changed by descriptor
rather than by name, a cache entry counts as complete only when its rootfs is there too, an absent
exit code from a box is no longer read as success by the Python and Node bindings, and no `unwrap`,
`expect` or `panic!` is left in production code. Full per-release detail in **[CHANGELOG.md](CHANGELOG.md)**.

**Deliberately not here yet:** the headline **GPU slices** (on the [Roadmap](#roadmap)) and Docker-style
overlay networking.

## Roadmap

kern starts as a small, fast sandbox/OCI runtime and grows deliberately: the resources it governs are
driven by what proves useful. These are directions under consideration, **not commitments or dates**,
and some may never ship if they would change what kern is. Recently shipped work is under
[Project status](#project-status), not here.

- **GPU slices.** A workload gets a *slice* of a GPU, not the whole device. Not shipped, and this
  README will describe it when it is, not before. Nothing here touches a GPU today.
- **More governed resources.** The same profile model could extend to other cgroup or kernel-real
  resources (I/O bandwidth, network shaping) as they prove useful.
- **Snapshot / warm-start (CRIU).** Same-host checkpoint and restore of a *warm* box for subsecond
  restarts. Feasible but gated: rootless CRIU needs a capability and suspending the seccomp filter, so it
  would be an explicit opt-in mode, not the default, and only for same-host, non-GPU boxes. Not committed.
- **macOS.** No native port, and it is a non-goal: a daemonless kernel + cgroup sandbox has no macOS
  equivalent. The only path considered is a thin shim over a Linux VM, the same shape as WSL2.
- **1.0, freeze:** CLI + config under semver, threat model + architecture finalised.

**In progress**

- **Per-stack supervisor.** Today `up` catches a service that dies at startup; one that dies an hour
  later is not detected. Under measurement on a Pi before it gets built.

**Deliberately out, not missing**

- Network segmentation between services, `deploy.replicas`, `docker.sock` / Engine API,
  `--privileged`. These follow from rootless + daemonless + one pod as the unit of isolation, not
  from missing work.

> A stack is one pod. Within that model kern is complete: what is listed above as out is a
> consequence of the model, not a gap in it.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design.

## Security

kern isolates with Linux **namespaces + seccomp + a self-pivoted root** (a copy-on-write overlay by
default: the image stays immutable, writes land in a private upper discarded on exit, and `--read-only`
locks the whole root), a kernel-level boundary, deny-by-default on devices, with the host's sysfs/procfs
masked, and an opt-in **Landlock** (LSM) layer on top (plus an experimental egress allowlist). That's
strong for first-party and noisy-neighbour workloads. For **adversarial, multi-tenant untrusted code** where you want a
hardware-virtualization boundary, a microVM/VM adds a layer kern doesn't: a deliberate trade for
single-digit-millisecond starts and a ~1.8 MB footprint.

The full threat model, per-feature notes, and the honest *"kern vs a microVM, when to use what"*
guidance live in [SECURITY.md](SECURITY.md). Found a vulnerability? Report it **privately** via GitHub
Security Advisories ("Report a vulnerability" on the repo); please don't open a public issue.

## Contributing

Issues and PRs welcome, see [CONTRIBUTING.md](CONTRIBUTING.md). Contributions are covered by a
lightweight [CLA](CLA.md); the project follows a [Code of Conduct](CODE_OF_CONDUCT.md). Security
reports: follow [SECURITY.md](SECURITY.md) (don't open a public issue).

## License

[Apache-2.0](LICENSE), permissive, with an explicit patent grant. See [NOTICE](NOTICE). The dependency
tree is deliberately tiny (`libc` only on the Rust side; standard-library-only on the Python side) and
copyleft-free; `cargo deny check licenses` is clean.

**Trademark.** The *code* is free under [Apache-2.0](LICENSE): fork it, embed it, run it, no strings.
The licence itself grants no rights to the project's names or logo (§6), so please don't use "kern"
for a fork, a modified build, or a competing product or service without permission, see
[TRADEMARK.md](TRADEMARK.md). Open code, protected name, the same split Rust and Firefox use.
