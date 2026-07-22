<div align="center">

# kern

**A fast, lightweight sandbox & virtual resource manager for AI agents and untrusted code.**

Run untrusted or agent-generated code in a real, kernel-enforced box that starts in **~2 ms**, from one
**~1.6 MB** rootless binary with no daemon. Embed it from Python, Node or Rust, or run it from the CLI.

Isolation is just the first resource kern manages this way: the same model also slices CPU (`vcpu:`),
memory, disk (`vdisk:`) and devices (`vgpio:`) per process, with or without a full box. The container is
one case of a smaller idea.

**Runs everywhere Linux does: bare Linux, Windows (via WSL2), and ARM boards** (Raspberry Pi, NVIDIA
Jetson, Arduino UNO Q), where a 186 MB Docker daemon is a poor fit (on the Pi 5 tested here, no engine
was installed at all).

**~2 ms** cold start (vs **~308 ms** `docker run`) · **~1.6 MB** static binary · **0 RAM at rest** · **rootless**

[![CI](https://github.com/getkern/kern/actions/workflows/ci.yml/badge.svg)](https://github.com/getkern/kern/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%C2%B7%20Windows%20(WSL2)%20%C2%B7%20ARM%20boards-informational.svg)](#platforms)
[![Release](https://img.shields.io/github/v/release/getkern/kern?label=release&color=brightgreen)](https://github.com/getkern/kern/releases/latest)

<p align="center">
  <img src="assets/demo.svg" width="780" alt="Terminal demo: a kern.toml defines reusable vcpu/vdisk/vgpio (device) profiles; 'kern box train --image alpine vcpu:heavy vdisk:scratch' attaches a 4-vCPU, 2 GB, 8 GB-scratch rootless isolated slice in a few ms (docker run takes ~308 ms); 'kern run vcpu:heavy -- ffmpeg' caps a heavy transcode with no sandbox; 'kern box iot --image alpine vgpio:sensor' exposes only /dev/i2c-1 and nothing else; piping a request into 'kern box fn --image python' runs it in a fresh isolated box per request (serverless style); 'kern compose stack.toml up' brings up a multi-box stack; 'kern top' is the live TUI for boxes, profiles and volumes: CPU, memory, disk and devices, sliced per box, in one ~1.6 MB static binary, no daemon.">
</p>

<sub>Demo timings on an Intel i7-14700KF (28-core x86_64, Linux 7.0, systemd-user, cgroup delegated): the <b>~2.7 ms</b> is a <i>capped</i> box start (the `vcpu:heavy vdisk:scratch` slice), a bare box is <b>~2 ms</b>; a full <code>kern box</code> lifecycle (fork, isolate, run, tear down), not just kern's ~1.24 ms of setup. Your hardware and cgroup delegation differ: see <a href="BENCHMARKS.md">Benchmarks</a> for the labeled table, methodology, and on-device board numbers.</sub>

[Install](#install) · [Quickstart](#quickstart) · [Docker compat](#docker-compatibility) · [When to use](#when-to-use-kern-and-when-not) · [Embed (Rust / Python / Node)](#embed-it) · [How it works](#how-it-works) · [Config &amp; profiles](docs/CONFIG.md) · [Benchmarks](BENCHMARKS.md) · [Security](SECURITY.md)

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
`ps`/`exec`/`logs`, compose, health, `tag`/`push`, `save`/`load`) in ~1.6 MB.

```sh
kern box dev --image alpine -- sh        # a throwaway, isolated Alpine shell, in a few ms
```

…or embed it, a fresh isolated box per call, for untrusted or agent-generated code (cloud-code-interpreter
territory, but *local* and ~1.6 MB: no cloud, no account, no VM):

```python
import kern_sandbox as kern                     # pip install kern-sandbox
r = kern.run_code("print(sum(range(100)))")   # network OFF, hard caps, a timeout the binding enforces
print(r.stdout, r.success)                     # → a fresh, discarded-after box
```

## kern vs Docker vs Podman

|  | Docker | Podman | **kern** |
|---|---|---|---|
| Daemon | yes (`dockerd` + `containerd`) | no | **no** |
| Rootless | partial | yes | **yes** |
| Cold start (a bare box) | ~308 ms | ~155 ms | **~2 ms** |
| Footprint | ~186 MB daemon stack | multi-package install | **one 1.6 MB static binary** |
| OCI images (pull / build) | yes | yes | **yes** |
| Resource caps without a full box | no | no | **yes (`kern run`)** |

Startup numbers are from a labeled [benchmark](BENCHMARKS.md) on one machine, measure your own. kern
deliberately does *less* than Docker (no overlay networks, no swarm): a small, fast, honest core. It is a
**kernel-boundary** sandbox for your own or semi-trusted code; for actively hostile multi-tenant code, a
microVM is the right tool, and [SECURITY.md](SECURITY.md) says exactly where the line is.

## What you'd use it for

- **AI agents:** run each model-generated tool call in a fresh, network-off box, sandbox faults come back
  as data, not crashes ([warm-kernel.py](examples/warm-kernel.py) · [kern-mcp for Claude Desktop / Cursor](examples/mcp-code-interpreter.md) · [agent-tool-runner.py](examples/agent-tool-runner.py)).
- **CI:** run each step in a capped, daemonless box, no Docker-in-Docker ([ci-in-a-box.sh](examples/ci-in-a-box.sh)).
- **Edge / ARM:** one 1.6 MB binary on a Pi 5 / Jetson where a Docker daemon does not fit ([edge-many-services.sh](examples/edge-many-services.sh)).
- **Untrusted or customer code:** execute it isolated and resource-capped, on your own machine, no cloud ([code-interpreter.py](examples/code-interpreter.py)).
- **Build and run OCI images:** `kern build` / `kern box`, speaks Docker formats, no daemon.

## Why kern

- ⚡ **Daemonless & tiny.** No `dockerd`-style service. A ~1.6 MB static binary, **one Rust dependency**
  (`libc`); it shells out to the system's `curl`/`tar` only to *pull* images (running a box needs
  neither). Cold start **~2 ms** vs ~308 ms for `docker run`; **~7 MB** RSS per box vs an always-on
  ~186 MB daemon (`dockerd` + `containerd`). `kern ps` reads state straight from the kernel.
- 👤 **Rootless by default.** Unprivileged user namespaces: your uid maps to root *inside* the box,
  and only there. Single-uid is the default and is `libc`-pure (no helper, smallest id surface);
  `--uid-range` opts into a full sub-id range (`apt`, `www-data`-style drops) via the standard
  `newuidmap` + `/etc/subuid`. We state plainly that path is not helper-free. No host privilege
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

One model: a box (or a bare `run`) gets *only* the resources you slice for it. Every cap is a real
cgroup v2 or kernel control; devices are deny-by-default. GPU slices are on the [Roadmap](#roadmap).

| Resource | Flag / profile | What the box gets | Enforcement |
|---|---|---|---|
| **CPU** | `--cpus` · `--cpuset-cpus` · `--nice` · `vcpu:` | Fractional CPU-time quota, core pinning, priority | cgroup `cpu.max` / `cpuset`, hard |
| **Memory** | `--memory` · `--memory-swap-max` | Hard RAM ceiling (+ swap allowance) | cgroup `memory.max`, hard¹ |
| **Disk** | `vdisk:` · `--size` (named volumes) | Size-capped scratch at `/vdisk/<name>` | tmpfs charged to the box cgroup (rootless), or ext4-on-loop quota (privileged) |
| **Devices** | `vgpio:` | *Only* the named GPIO/I²C/SPI/LED nodes, nothing else | fresh `/dev` + fd-pinned bind + capability deny-list (raw-mem/disk/kvm refused) |
| **PIDs** | `--pids-limit` | Fork-bomb ceiling | cgroup `pids.max`, hard |
| **Block I/O** | `--io-weight` | I/O bandwidth weight | cgroup `io` |
| **GPU** | *(roadmap)* | A *slice* of a GPU (VRAM cap, then time-slice) | 🚧 cooperative governor, first-party / noisy-neighbour, **not** a hard boundary |

¹ On the default WSL2 kernel the `memory` controller isn't delegated: kern warns and shows the one-line
`.wslconfig` fix; enforced natively on Linux. Profiles (`vcpu:`/`vdisk:`/`vgpio:`) are reusable presets in
`~/.config/kern/kern.toml`, see [docs/CONFIG.md](docs/CONFIG.md). Author them with `kern probe` (list the
host resources you can slice), `kern examples` (print a sample `kern.toml`), and `kern validate` (check one).

## What you can do in one line

### An isolated container, zero setup

No daemon, no root: one ~1.6 MB binary.

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

- **Run anything, isolated**: OCI images from any registry (v2 auth, multi-arch, gzip **+ zstd**) or a `--rootfs`; CoW overlay (image immutable, scratch discarded) or `--read-only`; `-it` TTY; `--init` PID-1 reaper.
- **Governed slices**: hard cgroup v2 caps on any `box`/`run`: `--memory` · `--cpus` · `--cpuset-cpus` · `--memory-swap-max` · `--pids-limit` · `--io-weight` · `--nice`. `kern run` is the governor with no sandbox.
- **Data & devices**: `-v` volumes (symlink-safe) · named volumes with a `--size` quota · network volumes (`nfs`/`smb`/`sshfs`) · `--secret` → `/run/secrets` (RAM, `0400`) · `vdisk:` scratch · `vgpio:` device passthrough (deny-by-default) · `--tmpfs`.
- **Network & identity**: isolated by default; `--network host` for outbound; **`--egress-allow d1,d2`** (⚠️ experimental) restricts outbound to an allowlist of domains via a kern-run filtering proxy (an agent can `pip install` but can't exfiltrate to an arbitrary domain), with honest known gaps documented in [docs/EGRESS.md](docs/EGRESS.md); `-p` rootless publish (loopback unless you ask); in-box `--ssh`; `--pod` shared-net pods (`--no-outbound`); `--tun`; `--user`.
- **Least privilege**: 13 dangerous caps always dropped (`--cap-add`/`--cap-drop`); an always-on **seccomp** denylist (kexec, modules, ptrace, mount API, `setns`, …) that also kills wrong-arch + x86_64 x32-ABI aliases; opt-in **Landlock** (LSM) write-allowlist (`--landlock-rw <path>`): the box root is read+exec and writes are confined to the paths you name, a kernel-enforced second boundary the workload can't lift.
- **Lifecycle, no daemon**: `--restart` + `--health-cmd`; `cp`/`pause`/`attach`/`exec`; `ps`/`top`/`stats`/`logs`/`inspect`/`prune`/`gc`/`history`/`recover`; `compose` (reads `docker-compose.yml` too); reusable `[[vcpu]]`/`[[vgpio]]`/`[[vdisk]]` profiles; `kern doctor`.

<details>
<summary><b>Every flag &amp; command, grouped</b></summary>

**Run anything, isolated**

- **OCI images, any registry**: `--image alpine` pulls (registry v2, multi-arch → your arch,
  gzip **and zstd** layers) and runs. Docker Hub, GHCR, GitLab, quay, Harbor, self-hosted, via the
  standard `WWW-Authenticate` challenge (Bearer or Basic). `kern login` stores creds `0600` and
  passes them to `curl` off-argv. Or bring a rootfs with `--rootfs`. Pull a foreign arch with
  `kern pull --platform os/arch`, then run it.
- **Governed slices**: `kern run` caps a command with **no sandbox**; `--memory` / `--cpus` /
  `--cpuset-cpus` (pin) / `--memory-swap-max` / `--pids-limit` / `--io-weight` / `--nice` set hard
  cgroup v2 caps on any `box` or `run` (kern warns if a controller isn't delegated).
- **Writable by default**: a copy-on-write overlay; the image stays immutable, scratch is discarded
  on exit. `--read-only` for a read-only root. **Interactive TTY** with `-it` (raw mode, resize-aware).
- **`--init`**: a built-in PID-1 reaper (no zombies, forwards SIGTERM) without bundling `tini`.

**Data & devices across the boundary**

- **Volumes, full**: `-v src:dst[:ro]` (symlink-safe) · **named volumes** (`kern volume` CRUD, with
  a per-volume `--size` quota) · **network volumes** (`nfs://` / `smb://` / `sshfs://`) mounted
  rootless via FUSE/GVFS.
- **Secrets**: `--secret NAME=value` / `NAME=-` (stdin) / `SRC[:NAME]` (file) → `/run/secrets/NAME`
  (mode `0400`) on a RAM tmpfs, never in the image or env.
- **vDisk** (`vdisk:`): a size-capped scratch at `/vdisk/<name>`: RAM tmpfs rootless, or an
  ext4-on-loop image (persistent, real quota) when privileged.
- **vGPIO** (`vgpio:`): expose *only* the listed GPIO/I²C/SPI/LED peripherals into a box
  (deny-by-default for the rest), for edge/IoT.
- **`--tmpfs PATH[:size]`**: a fresh `nosuid,nodev` tmpfs (refused over hardened mounts).

**Networking & identity**

- **Modes**: isolated loopback-only by default (`--network none`); `--network host` (= `--net`)
  for outbound; `--hostname`; **`--tun`** exposes `/dev/net/tun` for WireGuard / userspace VPNs.
- **Port publishing**: `-p [ip:]host:box` from a rootless forwarder; binds `127.0.0.1` by default,
  `0.0.0.0` only if you ask.
- **In-box SSH**: `--ssh 2222` runs a throwaway `sshd` (auto keypair or `--ssh-key`), published.
- **Pods**: `kern pod create` + `--pod <name>`: a shared-network pod where boxes reach each other
  by name (`--no-outbound` to deny internet egress).
- **`--user UID[:GID]`**: drop to a specific uid/gid (fails closed if unmapped).

**Least privilege, configurable**

- **Capabilities**: 13 dangerous caps always dropped; `--cap-drop CAP`/`ALL` drops more,
  `--cap-add CAP` keeps one (still bounded by userns + seccomp).
- **Seccomp**: an always-on denylist (kexec, kernel modules, ptrace, the mount API, `setns`,
  `syslog`, …); wrong-arch **and x86_64 x32-ABI** syscalls are killed, closing the alias bypass.
- **`--privileged`**: opt-in, relaxes seccomp for a **nested `kern box`** (docker-in-docker): re-allows
  exactly `unshare`/`setns`/`mount`/`umount2`/`pivot_root`, keeps kexec/modules/bpf/io_uring/keyring
  blocked (stronger than Docker's `--privileged`), **rootless-only**. See [SECURITY.md](SECURITY.md).

**Lifecycle & operations, no daemon**

- **Stay-up & health**: `--restart` supervises a detached box; `--health-cmd` +
  `--health-interval`/`-retries`/`-start-period`/`-timeout`/`-action` probe it; `kern ps` shows
  **HEALTH** + **PORTS**.
- **Box ops**: `kern cp` (symlink-confined, CVE-2019-14271-safe), `pause`/`unpause` (freezer),
  `attach` (live output), `exec` (join a running box).
- **Observe & manage**: `-d` detached; `ps` / `top` (TUI) / `stats` / `logs` / `inspect` /
  `stop` / `kill` / `killall` / `prune` / `gc` / `history` / `recover`.
- **Compose**: `kern compose stack.toml` (or a `docker-compose.yml`) brings up a multi-box stack
  in dependency order; `kern up`/`down` for the file in this dir.
- **Diagnostics**: `kern doctor` (will boxes run here?), `info`, `bench`, shell `completions`.
- **Resource profiles**: reusable `[[vcpu]]` / `[[vgpio]]` / `[[vdisk]]` in `~/.config/kern/kern.toml`,
  attached by prefix (`kern run vcpu:heavy vgpio:leds -- ./train.sh`); managed with `kern config`.

</details>

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
cap work for real. **One honest exception:** `--memory` needs the cgroup v2 *memory* controller, which
Microsoft's default WSL2 kernel doesn't enable; kern **warns** and points you to the one-time fix
(`kernelCommandLine = cgroup_enable=memory cgroup_memory=1` under `[wsl2]` in `%UserProfile%\.wslconfig`,
then `wsl --shutdown`). Same limit as Docker/Podman on WSL; on a native Linux host `--memory` is
enforced out of the box. The installer ensures the WSL2 engine (self-elevating for the one reboot it may need, then
resuming on its own), imports kern's **own** pre-baked distro (a tiny Alpine + kern, no Ubuntu, no
manual steps), drops the `kern.exe` shim on your PATH, and verifies end-to-end. Every download is
sha256-checked. After it finishes: `kern box dev --image alpine -it -- sh`. Honest caveat: kern runs
*inside* the WSL2 kernel, so it doesn't shed the VM weight native Linux does; the win is "no Docker
Desktop", not "no VM".

**📦 Offline / air-gapped** (a board or locked-down server with no internet). kern is a single
~1.6 MB static binary, so copying that one file *is* the install:

```sh
scp kern pi@raspberrypi:~/          # then:  ssh pi@raspberrypi kern box dev --image alpine -- sh
```

No daemon, no package, nothing to install on the target, which is why it runs where Docker can't
(see [EDGE.md](EDGE.md)).

<details>
<summary>Download + verify by hand, or build from source</summary>

```sh
# Straight from GitHub Releases, check the checksum yourself (aarch64: swap x86_64 → aarch64):
curl -fsSL https://github.com/getkern/kern/releases/latest/download/kern-x86_64-unknown-linux-musl.tar.gz \
  | tar xz && install -m 755 kern ~/.local/bin/kern   # a matching .tar.gz.sha256 ships next to it

# Or build it:
git clone https://github.com/getkern/kern && cd kern && cargo build --release
```

</details>

## Quickstart

### Start here

A sandboxed shell from any OCI image. The image stays read-only; your writes go to a scratch overlay that vanishes on exit.

```sh
kern box dev --image alpine -it -- sh
```

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
kern logs svc             # its output
kern stop svc             # stop it   (kern stop --all for everything)
```

### Hand it a secret

Never baked into the image or env; delivered on a pipe, readable only inside the box.

```sh
printf "$DB_TOKEN" | kern box job --image alpine --secret TOKEN=- --cap-drop ALL \
  -- sh -c 'curl -H "Authorization: Bearer $(cat /run/secrets/TOKEN)" https://api/…'
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
agent tools, per-request workers), a structured result back, including rich mime-typed results
(charts, tables, the last expression) the way a Jupyter cell returns them, but local and daemonless.

**Rust**, the `kern-isolation` crate:

```rust
use kern_isolation::Sandbox;

let out = Sandbox::builder()
    .rootfs("/var/lib/kern/rootfs/alpine")
    .no_network()                    // isolated loopback-only netns
    .memory_limit_bytes(256 << 20)   // cgroup cap
    .timeout_ms(5_000)               // SIGKILL a runaway
    .build()?
    .run("python3", &["handler.py"])?;

assert!(out.success());              // + out.stdout / .stderr / .exit_code / .wall_ms
```

**Python**, the `kern_sandbox` package on PyPI ([`pip install kern-sandbox`](https://pypi.org/project/kern-sandbox/)), for running semi-trusted or agent-generated code with fast local isolation:

```python
import kern_sandbox as kern     # kernel-boundary isolation, not a microVM

# one-shot: throwaway box, network OFF, hard caps, a mandatory timeout the binding enforces
r = kern.run_code("print(sum(range(100)))")
print(r.stdout, r.success)

# restrict the network to an allowlist: an agent can pip-install but cannot exfiltrate elsewhere
r = kern.run_code("import urllib.request as u; ...",
                  egress_allow=["pypi.org", "files.pythonhosted.org"])

# rich results, the "code interpreter" pattern (no Jupyter kernel): the last expression, any
# display(), and every matplotlib figure are auto-captured as mime-typed result.results
with kern.Sandbox(setup="pip install matplotlib pandas", timeout_s=60) as s:
    r = s.run_code("import matplotlib; matplotlib.use('Agg')\n"
                   "import matplotlib.pyplot as plt; plt.plot([1, 4, 9])")
    png = next((x.png for x in r.results if x.png), None)   # chart PNG bytes, no savefig; send to the model
    r = s.run_code("import pandas as pd; pd.DataFrame({'a': [1, 2]})")
    r.results[0].html                      # the DataFrame as an HTML table (also .text)
```

**Node / TypeScript**, the `kern-sandbox` package on npm ([`npm install kern-sandbox`](https://www.npmjs.com/package/kern-sandbox)), the same model for
the other half of the agent ecosystem (LangChain JS, the Vercel AI SDK), with types in the box:

```js
import { runCode, withSandbox } from "kern-sandbox";

// one-shot: throwaway box, network OFF, hard caps, a timeout the binding enforces
const r = await runCode("print(sum(range(100)))");
console.log(r.stdout, r.success);

// a session: files persist across calls; run agent-generated JS or Python
await withSandbox({ memoryMb: 512, timeoutS: 30 }, async (s) => {
  await s.writeFile("data.csv", csvBytes);
  const out = await s.runCode("import pandas as pd; print(pd.read_csv('data.csv').shape)");
});
```

**Warm kernel (sub-millisecond cells).** For a REPL/notebook or an agent's tool loop, open a persistent
warm interpreter with `Sandbox.kernel()` (Python and Node): in-memory state persists across cells and the
per-cell cost drops from a full interpreter boot (about 10 ms) to sub-millisecond (about 300x, 25k
cells/s), with the same rich results, still network-off and resource-capped.

**MCP server for Claude Desktop / Cursor / Windsurf.** The Python package also ships **`kern-mcp`**, a
dependency-free MCP stdio server that hands any MCP client a local, **network-off** code interpreter
backed by kern: `run_code` (python/bash/node), `write_file`, `read_file`, `list_files`, with charts
returned as image blocks. Point your client at the `kern-mcp` command (from
[`pip install kern-sandbox`](https://pypi.org/project/kern-sandbox/)); set `KERN_MCP_KERNEL=1` to route
`run_code` through the warm kernel. See [bindings/python](bindings/python).

Safe by default: every relaxing argument (`network`, extra `mounts`) says so, and the binding owns
the timeout, so a `timeout` fault is a fact, not a guess. Both bindings use the installed `kern` (`PATH`
or `KERN_BIN`); see [bindings/python](bindings/python) ([PyPI](https://pypi.org/project/kern-sandbox/)),
[bindings/node](bindings/node) ([npm](https://www.npmjs.com/package/kern-sandbox)), and the
`kern-isolation` crate (git/path, not yet crates.io).

## Platforms

**Linux, multi-architecture.** Prebuilt static (musl) binaries for **`linux-x86_64`** and
**`linux-aarch64`**: one ~1.6 MB file, no Rust deps beyond `libc` (the pull path shells out to system
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
installer sets up WSL2 and drops in a pre-baked kern distro, so isolation and `--cpus` are enforced
for real (`--memory` needs `cgroup_enable=memory` in the WSL kernel, which the default doesn't set;
kern warns and shows the one-line `.wslconfig` fix; enforced natively on real Linux). Honest caveat:
you're inside the WSL2 VM, so it's "no Docker Desktop", not "no VM". kern does **not** run on stock Android-the-OS (Bionic, SELinux, userns off). Daemonless is a big
win on RAM-constrained boards (0 resident vs ~186 MB), see **[EDGE.md](EDGE.md)**. ARM CI is tracked
in the issues.

## Docker compatibility

kern speaks Docker's **formats**, so your existing images and stacks just work, but it does **not**
reimplement the Docker Engine API. It's a lightweight alternative, not a drop-in clone.

| From your Docker setup | kern |
|------------------------|------|
| **OCI images** (Docker Hub, GHCR, quay, Harbor, self-hosted) | ✅ pull & run: multi-arch, `WWW-Authenticate` v2 auth, gzip **+ zstd** |
| **`docker-compose.yml`** | ✅ `kern compose` reads real-world files as-is: `depends_on` (+ `service_healthy`/`_completed` conditions), `healthcheck`, `deploy.resources.limits`, YAML **anchors/merge** (`<<: *x`), **`extends`**, `${VAR:-default}` interpolation, network **aliases** |
| **Dockerfile** `build` | ✅ `kern build`: all common instructions, **multi-stage**, `COPY --from=…` (a build stage **or** an external image), **COPY globs** (`*.txt`, `src/*`, `[ab].conf`), BuildKit **heredocs**, `ADD <url>` (+ `--checksum`/`--chmod`), `COPY --chmod` (recursive, Docker-parity), `FROM scratch`, `SHELL`, `# escape`/BOM, `--build-arg`, layer cache, and honours **`.dockerignore`**. Daemonless: each `RUN` is a real box |
| **`.dockerignore`** (also **`.kernignore`**) | ✅ excluded from the build context: keeps `.git`/secrets out of the image (last-match-wins, `!` re-include, `**`) |
| **`docker save` / `load` archives** | ✅ `kern save` / `kern load`: export/import an image tar, `docker load`-compatible |
| **`tag` / `push`** to a registry | ✅ `kern tag` / `kern push` |
| **Image management** (`docker images` / `rmi` / `search`) | ✅ `kern images` (list cached), `kern rmi` (remove, frees unshared layers), `kern search` (Docker Hub) |
| **`docker commit`** (container → image) | ✅ `kern commit <box> <image>`: snapshots the box's filesystem to a reusable image (warm start); skips volumes/secrets |
| **Docker Engine API** / `docker.sock` | ❌: tools that attach to the socket (Docker Desktop, some IDE/CI plugins) won't connect |
| **Swarm** | ❌: use `compose` / `--pod` |

## When to use kern (and when not)

**✅ Use kern when you want:**

- a **fast, daemonless sandbox** for your own or **agent/LLM-generated** code (fresh box per call, embeddable from Rust/Python);
- **CI / build** boxes, or a throwaway dev environment, without a background daemon;
- containers on **edge / ARM** boards where a Docker daemon is too heavy or absent (Pi, Jetson, Android-kernel);
- **resource slices** beyond containers: `vcpu:` / `vdisk:` / `vgpio:` (GPU on the roadmap).

**🔀 Reach for something else when you need:**

- a hard boundary against **actively hostile multi-tenant** code → a **microVM** (Firecracker) or gVisor. kern's FS/PID/namespace/cgroup isolation is a real kernel boundary for *your own or semi-trusted* code, not a VM;
- the **Docker Engine API / Docker Desktop** workflow, or a true CLI drop-in → **Docker / Podman**;
- **Kubernetes CRI** integration → containerd / CRI-O;
- a **low-level OCI runtime** to slot *under* containerd/podman (the runc layer) → **crun**, **youki** (also Rust), or runc. kern isn't a runc-replacement; it's the *whole* daemonless UX (pull, build, run, compose) in one binary, not a runtime another engine drives.

kern states every boundary that is cooperative or opt-in plainly in **[SECURITY.md](SECURITY.md)**; being honest about the edges is the point.

## How it works

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
   hard `MemoryMax`/`CPUQuota`/`TasksMax` when a systemd user manager is present.

The whole mount sequence flows through a **typestate** (`Rootfs<Mounted> → OldRootReady → ReadOnly`):
the read-only remount is only reachable *after* the pivot, so getting the order wrong is a compile
error. The same sequence drives `--plan`.

OCI images pull with `curl` + `tar` (registry v2, `WWW-Authenticate` auth, multi-arch, gzip/zstd),
each blob **sha256-verified**, each layer **vetted in-process from its raw tar headers** (absolute/`..`
paths, device nodes, escaping hardlink/symlink targets, decompression- & inode-bomb caps) before it
extracts into isolated staging and merges no-follow, closed by *parsing* the layer, not by trusting
the host tar, so it holds on GNU tar and BusyBox tar alike. Every layer is HTTPS-fetched and sha256-verified; credentials
travel off-argv. See [ARCHITECTURE.md](ARCHITECTURE.md).

## Performance

One isolated `/bin/true`, warm image cache, one box per run. The x86_64 comparison is the **28-core,
Linux 6.17, NVMe, systemd-user** host in **[BENCHMARKS.md](BENCHMARKS.md)** (exact per-runtime commands
there). kern's figure is informally reproduced on a second machine, an **Intel i7-14700KF**, same class, where a P-core-pinned
`/bin/true` box lands in the low-single-digit-ms range (an E-core is slightly higher). Your
numbers vary with hardware and load; board rows are from on-device runs.

| host | kernel | **kern** | bubblewrap | crun | runc | podman | docker |
|---|---|---:|---:|---:|---:|---:|---:|
| x86_64 desktop | v6.17 | **1.9 ms** | 2.6 ms | 5.2 ms | 12.2 ms | 155 ms | 308 ms |
| Jetson Orin Nano | v5.15-tegra | **3.6 ms** | 5.6 ms | ✗ | 32 ms | ✗ | 472 ms |
| Raspberry Pi 5 | v6.6-rpi | **2.1 ms** | ✗ | ✗ | ✗ | ✗ | ✗ |
| Arduino UNO Q | **v6.16 Android** | **9.9 ms** † | 14.9 ms | ✗ | 76 ms | ✗ | 858 ms |

✗ = not installed on the boards tested. On the **Pi 5, kern is the only runtime
present at all**: one ~1.6 MB static binary just works where the others are each a setup step (Docker
alone is a ~186 MB daemon stack).

kern is the fastest sandbox here at **~1.9 ms** (ahead of bubblewrap). Its *own* box setup is **~1 ms**
(the `KERN_TIMING` phases: `unshare` + overlay + `/dev` + pivot + seccomp, each sub-ms); the rest is
process start + teardown. Adding a hard cgroup cap costs about **+1 ms** when the cgroup is already
delegated (a systemd user session writes `memory.max` directly, **~2.7 ms** total, this is the common
desktop case and what the demo shows). Where kern must create the delegated scope itself it shells out
to `systemd-run`, which brings it to **~5.5 ms**, but **most of that is external `systemd-run` + D-Bus
scope creation, not kern** (`systemd-run --user --scope -- true` alone is ~4 ms); `KERN_NO_SCOPE` opts
out (back to ~1.9 ms, best-effort in-process cgroup). The
top tier is all within a few ms: *nobody* wins single-shot latency outright. The real gap is to the
**engines**: **~80-160× faster** than podman (~155 ms) / Docker (~308 ms), which round-trip a daemon every run, yet
kern alone ships a full daemonless container UX in ~1.6 MB. Beyond one start: **~500 boxes/s**, **~7 MB**
RSS/box, **0 resident** (Docker keeps ~186 MB resident before you run anything).

† On the Arduino's Android kernel an overlayfs *mount* is ~31 ms (a kernel quirk, sub-ms elsewhere),
so the default overlay box is ~33 ms there; `--bind-rootfs` starts in **9.9 ms, ahead of bubblewrap**.

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
| Many isolated services on a small board (few MB vs a 186 MB daemon) | [edge-many-services.sh](examples/edge-many-services.sh) |
| Head-to-head timing: kern vs `docker run` | [compare-vs-docker.sh](examples/compare-vs-docker.sh) |

…plus governed runs, port-published services, compose stacks and more, see
**[examples/README.md](examples/README.md)**.

## Project status

**0.6.9, a daemonless container + resource runtime that does less than Docker, on purpose.**
Everything in [Features](#features) works today and is tested (479 Rust, 61 Python and 50 Node tests; clippy-clean and
Node, clippy-clean, `cargo-deny`-clean, adversarially reviewed slice by slice); the isolation is real. It
deliberately skips a lot Docker has (overlay networks, a plugin ecosystem): the point is a small, fast,
honest core. The CLI and config surface are **not frozen until 1.0**.

**Recent work (0.6.9):** a **warm kernel** for the Python + Node bindings (`Sandbox.kernel()`, a
persistent interpreter that makes the code-interpreter path sub-millisecond) and an **MCP server**
(`kern-mcp`) for Claude Desktop / Cursor, plus a box-start rate in `kern top`. Before that (0.6.7 / 0.6.8):
`kern commit` warm-start snapshots, an `--egress-allow` domain allowlist and an `--landlock-rw`
write-allowlist, fleet budgets, and the bindings gaining resource profiles, egress control, live output
streaming, rich mime-typed results and workspace snapshot/restore. Earlier: local image **build** +
**`tag`**/**`push`**, **zstd** layers, **`--init`**, **`--platform`**, pods, and a Dockerfile/compose
parser verified against a real `docker build` differential. Per-release detail in
**[CHANGELOG.md](CHANGELOG.md)**.

**Deliberately not here yet:** the headline **GPU slices** (on the [Roadmap](#roadmap)) and Docker-style
overlay networking.

## Roadmap

kern starts as a small, fast sandbox/OCI runtime and grows deliberately; the set of resources it
governs is driven by what proves useful.

- **Shipped:** build + tag + push, zstd layers, `--init`, `--platform`, pods, `kern commit`,
  `--egress-allow`, `--landlock-rw`, fleet budgets, and the Python + Node bindings; ongoing polish +
  broader (ARM) CI and edge/I/O ergonomics.
- **Windows, via WSL2 (shipped, one line: see [Install](#install)).** kern runs on Windows inside WSL2
  (a real Linux kernel) so hard caps (`--memory`/`--cpus`) are real there, verified. A `kern.exe` shim
  and a pre-baked kern WSL2 distro (Alpine + kern, no Ubuntu, no manual steps) install with a single
  `irm … | iex` that self-elevates, imports the distro and drops the shim on PATH. Both the shim and the
  distro are **built by the release CI from tagged source and sha256-signed**; the installer verifies
  every download, so it's the same trust level as the Linux binaries, not a hand-uploaded exe. Honest caveat: kern runs *inside* the WSL2
  kernel, so it doesn't shed the VM weight native Linux does; the win is "no Docker Desktop", not "no VM".
- **GPU slices.** A workload gets a *slice* of a GPU, not the whole device. It lands incrementally,
  each stage useful on its own and each opt-in (`--no-gpu` stays the default): first **safe access +
  visibility** (device passthrough, driver-gated, sysfs/procfs masked; per-box VRAM + utilisation in
  `kern stats`), then a **cooperative per-box VRAM cap** via a userspace driver shim (NVIDIA/CUDA
  first, honest trust model: for first-party / noisy-neighbour isolation, *not* a hard boundary
  against a hostile tenant), then **time-sliced compute** + AMD (HIP) / Vulkan. A cross-vendor GPU
  merge pool stays an optional plugin, not core.
- **1.0, freeze:** CLI + config under semver, threat model + architecture finalised.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design.

## Security

kern isolates with Linux **namespaces + seccomp + a read-only userns root**, a kernel-level boundary,
deny-by-default on devices, with the host's sysfs/procfs masked, and an opt-in **Landlock** (LSM) layer
on top (plus an experimental egress allowlist). That's strong for first-party and noisy-neighbour workloads. For **adversarial, multi-tenant untrusted code** where you want a
hardware-virtualization boundary, a microVM/VM adds a layer kern doesn't: a deliberate trade for
~2 ms starts and a ~1.6 MB footprint.

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
But **"kern" is a trademark** of the project: please don't use the name for a fork, a
modified build, or a competing product/service without permission, see [TRADEMARK.md](TRADEMARK.md).
Open code, protected name, the same split Rust and Firefox use.
