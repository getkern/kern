<div align="center">

# kern

**A fast, lightweight sandbox & virtual resource manager.**

Run untrusted or agent-generated code in a real, kernel-enforced sandbox that starts in **~1.9 ms** —
a single **~1.5 MB** rootless binary, **no daemon**. **Runs everywhere Linux does: bare Linux,
Windows (via WSL2), and ARM boards** — Raspberry Pi, NVIDIA Jetson, Arduino UNO Q — where Docker won't
even install. Embed it from Python or Rust, or drive it from the CLI.

**~1.9 ms** cold start (vs **~300 ms** `docker run`) · **~1.5 MB** static binary · **0 RAM at rest** · **rootless**

[![CI](https://github.com/getkern/kern/actions/workflows/ci.yml/badge.svg)](https://github.com/getkern/kern/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%C2%B7%20Windows%20(WSL2)%20%C2%B7%20ARM%20boards-informational.svg)](#platforms)
[![Release](https://img.shields.io/github/v/release/getkern/kern?label=release&color=brightgreen)](https://github.com/getkern/kern/releases/latest)

<p align="center">
  <img src="assets/demo.svg" width="780" alt="Terminal demo: a kern.toml defines reusable vcpu/vdisk/vgpio (device) profiles; 'kern box train --image alpine vcpu:heavy vdisk:scratch' attaches a 4-vCPU, 2 GB, 8 GB-scratch rootless isolated slice in a few ms (docker run takes ~300 ms); 'kern run vcpu:heavy -- ffmpeg' caps a heavy transcode with no sandbox; 'kern box iot --image alpine vgpio:sensor' exposes only /dev/i2c-1 and nothing else; piping a request into 'kern box fn --image python' runs it in a fresh isolated box per request (serverless style); 'kern compose stack.toml up' brings up a multi-box stack; 'kern top' is the live TUI for boxes, profiles and volumes — CPU, memory, disk and devices, sliced per box, in one ~1.5 MB static binary, no daemon.">
</p>

[Install](#install) · [Quickstart](#quickstart) · [Docker compat](#docker-compatibility) · [When to use](#when-to-use-kern-and-when-not) · [Embed (Rust / Python)](#embed-it) · [How it works](#how-it-works) · [Benchmarks](BENCHMARKS.md) · [Security](SECURITY.md)

</div>

---

kern runs Linux workloads in real, kernel-enforced sandboxes — user + PID + mount + network +
UTS + IPC namespaces, an overlay or read-only root pivoted in, an always-on seccomp filter, and
cgroup limits. It pulls OCI images, builds them, runs them, and gets out of the way: **no background
daemon, one short-lived process per box, started in single-digit milliseconds.**

It's built around one idea — *virtual resources*. A container is the first resource kern manages
(isolation); the same model extends to **CPU, memory, disk (`vdisk:`) and GPIO (`vgpio:`)** slices
today, and to GPU slices on the roadmap. A full daemonless container UX — OCI pull **and build**,
overlay, volumes, secrets, in-box SSH, `cp`/`pause`/`attach`, `ps`/`exec`/`logs`, compose, health,
`tag`/`push` — in ~1.5 MB.

```sh
kern box dev --image alpine -- sh        # a throwaway, isolated Alpine shell — in a few ms
```

…or embed it — a fresh, isolated box per call, for untrusted or agent-generated code (E2B/Firecracker
territory, but *local* and ~1.5 MB — no cloud, no account, no VM):

```python
import kern_sandbox as kern
r = kern.run_code("print(sum(range(100)))")   # network OFF, hard caps, a timeout the binding enforces
print(r.stdout, r.success)                     # → a fresh 1.9 ms box, discarded after
```

## Why kern

- **Daemonless & tiny.** No `dockerd`-style service. A ~1.5 MB static binary, **one Rust dependency**
  (`libc`) — it shells out to the system's `curl`/`tar` only to *pull* images (running a box needs
  neither). Cold start **~1.9 ms** vs ~300 ms for `docker run`; **~7 MB** RSS per box vs an always-on
  ~186 MB daemon (`dockerd` + `containerd`). `kern ps` reads state straight from the kernel.
- **Rootless by default.** Unprivileged user namespaces — your uid maps to root *inside* the box,
  and only there. Single-uid is the default and is `libc`-pure (no helper, smallest id surface);
  `--uid-range` opts into a full sub-id range (`apt`, `www-data`-style drops) via the standard
  `newuidmap` + `/etc/subuid` — we state plainly that path is not helper-free. No host privilege
  is gained either way.
- **Correct by construction.** The mount sequence is a **typestate**: remounting the root read-only
  *before* pivoting into it doesn't compile — a class of sandbox-escape bug is unrepresentable, not
  just untested. `--plan` prints the exact isolation sequence without running anything.
- **Honest about its boundaries.** Filesystem / process / namespace isolation is a real kernel
  boundary — the right tool for your own or semi-trusted code (CI, dev, edge, your agents' code).
  For actively hostile multi-tenant code, reach for a microVM. [SECURITY.md](SECURITY.md) says
  exactly when to use which, and marks every guarantee that is cooperative or opt-in.

## The model: two verbs

| Verb | Question it answers | What it does | Status |
|------|--------------------|--------------|--------|
| **`kern box`** | *"Isolate this workload — and slice its resources."* | Its own namespaces, overlay/read-only fs, private process tree, seccomp — **the container** — **plus** the same resource slices (`--memory`, `--cpus`, `vcpu:`, `vdisk:`, `vgpio:`). | ✅ works now |
| **`kern run`** | *"Just slice resources — no sandbox."* | Run a command against a CPU / memory quota with no isolation — the lean governor on its own. (A **GPU slice** is on the roadmap.) | ✅ works now |

**Both take resource slices** — the difference is the sandbox. `box` = isolation **+** slices; `run` =
slices **without** the sandbox. They compose — `run` inside `box`. Both ship today.

## What you can do in one line

```sh
# an isolated OCI container, zero setup — no daemon, no root, one ~1.5 MB binary
kern box try --image alpine -- sh

# give a container exactly one device — deny-by-default for everything else
kern box iot --image alpine vgpio:sensor -- ./read.py     # only /dev/i2c-1 crosses in

# a fresh, isolated sandbox per request — serverless-style, on your own machine
echo "$payload" | kern box fn --image python -- handler.py

# the same box on a Pi or an Android-kernel board where Docker isn't installed
scp kern pi:  &&  ssh pi 'kern box edge --image alpine -- ./agent'

# build a multi-stage image, tag it, push it — all daemonless
kern build -t app:1 . && kern tag app:1 registry.example/app:1 && kern push registry.example/app:1
```

## Features

Daemonless, rootless, and complete — the full container UX plus resource slices, in one binary:

- **Run anything, isolated** — OCI images from any registry (v2 auth, multi-arch, gzip **+ zstd**) or a `--rootfs`; CoW overlay (image immutable, scratch discarded) or `--read-only`; `-it` TTY; `--init` PID-1 reaper.
- **Governed slices** — hard cgroup-v2 caps on any `box`/`run`: `--memory` · `--cpus` · `--cpuset-cpus` · `--memory-swap-max` · `--pids-limit` · `--io-weight` · `--nice`. `kern run` is the governor with no sandbox.
- **Data & devices** — `-v` volumes (symlink-safe) · named volumes with a `--size` quota · network volumes (`nfs`/`smb`/`sshfs`) · `--secret` → `/run/secrets` (RAM, `0400`) · `vdisk:` scratch · `vgpio:` device passthrough (deny-by-default) · `--tmpfs`.
- **Network & identity** — isolated by default; `--network host` for outbound; `-p` rootless publish (loopback unless you ask); in-box `--ssh`; `--pod` shared-net pods (`--no-outbound`); `--tun`; `--user`.
- **Least privilege** — 13 dangerous caps always dropped (`--cap-add`/`--cap-drop`); an always-on **seccomp** denylist (kexec, modules, ptrace, mount API, `setns`, …) that also kills wrong-arch + x86_64 x32-ABI aliases.
- **Lifecycle, no daemon** — `--restart` + `--health-cmd`; `cp`/`pause`/`attach`/`exec`; `ps`/`top`/`stats`/`logs`/`inspect`/`prune`/`gc`/`history`/`recover`; `compose` (reads `docker-compose.yml` too); reusable `[[vcpu]]`/`[[vgpio]]`/`[[vdisk]]` profiles; `kern doctor`.

<details>
<summary><b>Every flag &amp; command, grouped</b></summary>

**Run anything, isolated**

- **OCI images, any registry** — `--image alpine` pulls (registry v2, multi-arch → your arch,
  gzip **and zstd** layers) and runs. Docker Hub, GHCR, GitLab, quay, Harbor, self-hosted — via the
  standard `WWW-Authenticate` challenge (Bearer or Basic). `kern login` stores creds `0600` and
  passes them to `curl` off-argv. Or bring a rootfs with `--rootfs`. Pull a foreign arch with
  `kern pull --platform os/arch`, then run it.
- **Governed slices** — `kern run` caps a command with **no sandbox**; `--memory` / `--cpus` /
  `--cpuset-cpus` (pin) / `--memory-swap-max` / `--pids-limit` / `--io-weight` / `--nice` set hard
  cgroup-v2 caps on any `box` or `run` (kern warns if a controller isn't delegated).
- **Writable by default** — a copy-on-write overlay; the image stays immutable, scratch is discarded
  on exit. `--read-only` for a read-only root. **Interactive TTY** with `-it` (raw mode, resize-aware).
- **`--init`** — a built-in PID-1 reaper (no zombies, forwards SIGTERM) without bundling `tini`.

**Data & devices across the boundary**

- **Volumes, full** — `-v src:dst[:ro]` (symlink-safe) · **named volumes** (`kern volume` CRUD, with
  a per-volume `--size` quota) · **network volumes** (`nfs://` / `smb://` / `sshfs://`) mounted
  rootless via FUSE/GVFS.
- **Secrets** — `--secret NAME=value` / `NAME=-` (stdin) / `SRC[:NAME]` (file) → `/run/secrets/NAME`
  (mode `0400`) on a RAM tmpfs, never in the image or env.
- **vDisk** (`vdisk:`) — a size-capped scratch at `/vdisk/<name>`: RAM tmpfs rootless, or an
  ext4-on-loop image (persistent, real quota) when privileged.
- **vGPIO** (`vgpio:`) — expose *only* the listed GPIO/I2C/SPI/LED peripherals into a box
  (deny-by-default for the rest) — for edge/IoT.
- **`--tmpfs PATH[:size]`** — a fresh `nosuid,nodev` tmpfs (refused over hardened mounts).

**Networking & identity**

- **Modes** — isolated loopback-only by default (`--network none`); `--network host` (= `--net`)
  for outbound; `--hostname`; **`--tun`** exposes `/dev/net/tun` for WireGuard / userspace VPNs.
- **Port publishing** — `-p [ip:]host:box` from a rootless forwarder; binds `127.0.0.1` by default,
  `0.0.0.0` only if you ask.
- **In-box SSH** — `--ssh 2222` runs a throwaway `sshd` (auto keypair or `--ssh-key`), published.
- **Pods** — `kern pod create` + `--pod <name>`: a shared-network pod where boxes reach each other
  by name (`--no-outbound` to deny internet egress).
- **`--user UID[:GID]`** — drop to a specific uid/gid (fails closed if unmapped).

**Least privilege, configurable**

- **Capabilities** — 13 dangerous caps always dropped; `--cap-drop CAP`/`ALL` drops more,
  `--cap-add CAP` keeps one (still bounded by userns + seccomp).
- **Seccomp** — an always-on denylist (kexec, kernel modules, ptrace, the mount API, `setns`,
  `syslog`, …); wrong-arch **and x86_64 x32-ABI** syscalls are killed, closing the alias bypass.
- **`--privileged`** — opt-in, relaxes seccomp for a **nested `kern box`** (docker-in-docker): re-allows
  exactly `unshare`/`setns`/`mount`/`umount2`/`pivot_root`, keeps kexec/modules/bpf/io_uring/keyring
  blocked (stronger than Docker's `--privileged`), **rootless-only**. See [SECURITY.md](SECURITY.md).

**Lifecycle & operations, no daemon**

- **Stay-up & health** — `--restart` supervises a detached box; `--health-cmd` +
  `--health-interval`/`-retries`/`-start-period`/`-timeout`/`-action` probe it; `kern ps` shows
  **HEALTH** + **PORTS**.
- **Box ops** — `kern cp` (symlink-confined, CVE-2019-14271-safe), `pause`/`unpause` (freezer),
  `attach` (live output), `exec` (join a running box).
- **Observe & manage** — `-d` detached; `ps` / `top` (TUI) / `stats` / `logs` / `inspect` /
  `stop` / `kill` / `killall` / `prune` / `gc` / `history` / `recover`.
- **Compose** — `kern compose stack.toml` (or a `docker-compose.yml`) brings up a multi-box stack
  in dependency order; `kern up`/`down` for the file in this dir.
- **Diagnostics** — `kern doctor` (will boxes run here?), `info`, `bench`, shell `completions`.
- **Resource profiles** — reusable `[[vcpu]]` / `[[vgpio]]` / `[[vdisk]]` in `~/.config/kern/kern.toml`,
  attached by prefix (`kern run vcpu:heavy vgpio:leds -- ./train.sh`); managed with `kern config`.

</details>

**Built-in hardening** — user+PID+net+UTS+IPC+mount namespaces, self-pivot root, `nosuid,nodev` box
root, always-on seccomp, least-privilege caps, hard cgroup caps (via `systemd-run` where present);
every pulled blob sha256-verified and every layer vetted in-process (no `..`/absolute/device escapes,
decompression- & inode-bomb caps) before an isolated no-follow merge. Where a guarantee is cooperative
or opt-in (the GPU cap, vGPIO/vdisk trust scope, network volumes), [SECURITY.md](SECURITY.md) says so.

## Install

**🐧 Linux & ARM boards** (Raspberry Pi · Jetson · Arduino UNO Q) — one line; auto-detects `x86-64` / `aarch64`:

```sh
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
```

Served from **github.com** (read the script first if you like). It downloads the release binary for
your arch and verifies the sha256 before installing. No Rust toolchain required. (`getkern.dev/install.sh`
is a short alias. On macOS, run it inside a Linux VM.)

**🪟 Windows** — one line in PowerShell (no Docker Desktop, no Ubuntu):

```powershell
irm https://raw.githubusercontent.com/getkern/kern/main/install.ps1 | iex
```

kern runs inside **WSL2** — a real Linux kernel — so hard caps (`--memory`/`--cpus`) are enforced for
real. The installer ensures the WSL2 engine (self-elevating for the one reboot it may need, then
resuming on its own), imports kern's **own** pre-baked distro (a tiny Alpine + kern — no Ubuntu, no
manual steps), drops the `kern.exe` shim on your PATH, and verifies end-to-end. Every download is
sha256-checked. After it finishes: `kern box dev --image alpine -it -- sh`. Honest caveat: kern runs
*inside* the WSL2 kernel, so it doesn't shed the VM weight native Linux does — the win is "no Docker
Desktop", not "no VM".

**📦 Offline / air-gapped** (a board or locked-down server with no internet) — kern is a single
~1.5 MB static binary, so copying that one file *is* the install:

```sh
scp kern pi@raspberrypi:~/          # then:  ssh pi@raspberrypi kern box dev --image alpine -- sh
```

No daemon, no package, nothing to install on the target — which is why it runs where Docker can't
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

```sh
# Run a real OCI image in a writable overlay (image immutable; scratch discarded). -it = a PTY.
kern box dev --image alpine -it -- sh

# Cap the slice: hard memory + CPU (cgroup v2), a bind mount, an env, host net for the build.
kern box build --image alpine --memory 512M --cpus 1.5 \
  -v "$PWD:/src" -w /src -e CI=1 --net -- sh -c 'apk add --no-cache make && make'

# Governor only, no sandbox — a CPU + memory quota on a host command (the leanest path).
kern run --memory 256M --cpus 0.5 -- ./crunch-numbers

# Detached service: publish a port, keep it up, health-check it — without a daemon.
kern box svc --image alpine -d -p 8080:80 --restart \
  --health-cmd 'wget -qO- localhost:80' --health-interval 5 -- httpd -f
kern ps                       # running boxes, with PORTS + HEALTH
kern top                      # interactive TUI (tabs, live mem/CPU)
kern exec svc -it -- sh       # shell into a running box
kern cp svc:/etc/app.conf .   # copy a file out (symlink-confined)
kern logs svc ; kern stop svc # its output ; stop it (or: kern stop --all)

# Deliver a secret (never in image or env) and drop to least-privilege.
printf "$DB_TOKEN" | kern box job --image alpine --secret TOKEN=- --cap-drop ALL \
  -- sh -c 'curl -H "Authorization: Bearer $(cat /run/secrets/TOKEN)" https://api/…'

kern doctor                   # will boxes even run on this host? preflight it.
kern compose stack.toml       # bring up a small stack in dependency order (TOML or compose.yml)
```

## Build & publish images

kern builds OCI images from a Dockerfile **without a daemon** — each `RUN` is a real `kern box`, each
step a content-addressed layer, reused on an unchanged rebuild.

```sh
kern build -t app:1 -f Dockerfile .          # FROM / RUN / COPY / WORKDIR / ENV / CMD / ENTRYPOINT …
kern build -t app:1 --build-arg VER=9 .       # build args; multi-stage (FROM … AS b; COPY --from=b)
kern tag app:1 registry.example/app:1         # give a cached image a second name
kern login registry.example                   # (private) — creds stored 0600
kern push registry.example/app:1              # publish as a single-layer OCI image
```

**Multi-stage** builds run each stage in its own box and confine `COPY --from=<stage>` to that stage's
filesystem (a hostile source path or symlink can't read the host). Layers pull as gzip **or zstd**.
`push` normalizes ownership and strips setuid/setgid, so an untrusted base can't smuggle a
privilege-bit into what you publish. (`build`/`push` are the newest surface — see
[Project status](#project-status).)

## Embed it

Run a sandboxed command straight from your program — a fresh isolated box per call (untrusted code,
agent tools, per-request workers), structured result back.

**Rust** — the `kern-isolation` crate:

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

**Python** — the `kern_sandbox` package, built for *"run this untrusted / agent-generated code safely"*:

```python
import kern_sandbox as kern

# one-shot: throwaway box, network OFF, hard caps, a mandatory timeout the binding enforces
r = kern.run_code("print(sum(range(100)))")
print(r.stdout, r.success)

# a session: files persist across calls; deps installed once in the ONLY network-on step
with kern.Sandbox(image="python:3.12-slim", setup="pip install pandas",
                  memory_mb=512, cpus=1.0, timeout_s=30) as s:
    s.write_file("data.csv", csv_bytes)
    out = s.run_code("import pandas as pd; print(pd.read_csv('data.csv').describe())")
    print(out.stdout)          # network-off, capped, isolated; a fault is a typed SandboxFault
```

Safe by default — every relaxing argument (`network=True`, extra `mounts`) says so, and the binding owns
the timeout, so a `timeout` fault is a fact, not a guess. Both use the installed `kern` (`PATH` or
`KERN_BIN`) — see [bindings/python](bindings/python) and the `kern-isolation` crate (git/path, not yet
crates.io).

## Platforms

**Linux, multi-architecture.** Prebuilt static (musl) binaries for **`linux-x86_64`** and
**`linux-aarch64`** — one ~1.5 MB file, no Rust deps beyond `libc` (the pull path shells out to system
`curl`/`tar`).

| Platform | Arch | Status |
|---|---|---|
| x86_64 Linux | x86_64 | ✅ primary + automated CI |
| **Windows 10/11 (via WSL2)** | x86_64 | ✅ CI-built shim + distro (`install.ps1`) |
| NVIDIA Jetson (L4T) | aarch64 | ✅ manually validated |
| Raspberry Pi 5 | aarch64 | ✅ manually validated |
| Arduino UNO Q (Android kernel, Debian userland) | aarch64 | ✅ manually validated |

kern needs a **Linux kernel** with **unprivileged user namespaces** + **cgroups v2**, and a **Linux
userland**. The kernel *flavor* doesn't matter — kern runs even on an *Android kernel* with a Linux
userland (the Arduino UNO Q). **On Windows, WSL2 *is* that Linux kernel** — the one-line PowerShell
installer sets up WSL2 and drops in a pre-baked kern distro, so hard caps (`--memory`/`--cpus`) are
enforced for real (the honest caveat: you're inside the WSL2 VM, so it's "no Docker Desktop", not "no
VM"). kern does **not** run on stock Android-the-OS (Bionic, SELinux, userns off). Daemonless is a big
win on RAM-constrained boards (0 resident vs ~186 MB) — see **[EDGE.md](EDGE.md)**. ARM CI is tracked
in the issues.

## Docker compatibility

kern speaks Docker's **formats**, so your existing images and stacks just work — but it does **not**
reimplement the Docker Engine API. It's a lightweight alternative, not a drop-in clone.

| From your Docker setup | kern |
|------------------------|------|
| **OCI images** (Docker Hub, GHCR, quay, Harbor, self-hosted) | ✅ pull & run — multi-arch, `WWW-Authenticate` v2 auth, gzip **+ zstd** |
| **`docker-compose.yml`** | ✅ `kern compose` reads it — `depends_on`, `healthcheck`, `deploy.resources.limits` |
| **Dockerfile** `build` | ✅ `kern build` — all common instructions, **multi-stage**, `COPY --from=…` (a build stage **or** an external image), BuildKit **heredocs**, `--build-arg`, layer cache. Daemonless: each `RUN` is a real box |
| **`tag` / `push`** to a registry | ✅ `kern tag` / `kern push` |
| **Docker Engine API** / `docker.sock` | ❌ — tools that attach to the socket (Docker Desktop, some IDE/CI plugins) won't connect |
| **Swarm** | ❌ — use `compose` / `--pod` |

## When to use kern (and when not)

**Use kern when you want:**

- a **fast, daemonless sandbox** for your own or **agent/LLM-generated** code (fresh box per call, embeddable from Rust/Python);
- **CI / build** boxes, or a throwaway dev environment, without a background daemon;
- containers on **edge / ARM** boards where Docker won't even install (Pi, Jetson, Android-kernel);
- **resource slices** beyond containers — `vcpu:` / `vdisk:` / `vgpio:` (GPU on the roadmap).

**Reach for something else when you need:**

- a hard boundary against **actively hostile multi-tenant** code → a **microVM** (Firecracker) or gVisor. kern's FS/PID/namespace/cgroup isolation is a real kernel boundary for *your own or semi-trusted* code, not a VM;
- the **Docker Engine API / Docker Desktop** workflow, or a true CLI drop-in → **Docker / Podman**;
- **Kubernetes CRI** integration → containerd / CRI-O.

kern states every boundary that is cooperative or opt-in plainly in **[SECURITY.md](SECURITY.md)** — being honest about the edges is the point.

## How it works

A `kern box` is one short-lived process tree — no daemon, no shared state:

1. **Namespaces.** `unshare` into a fresh user + PID + UTS + IPC namespace (and, by default, an
   isolated loopback-only net namespace; `--net` shares the host's — opt-in, flagged in the status
   panel). A single-UID map makes your uid root *inside* the box only; `--uid-range` opts into a full
   sub-id range.
2. **Root filesystem.** An **overlay** by default (image = read-only lower, a private upper takes
   writes); `--read-only` remounts it read-only *after* a self-pivot (`pivot_root(".", ".")`), which
   works even where a bind remount-RO is denied (some Android-kernel boards). Nothing is written into
   the rootfs, so many boxes share one read-only rootfs concurrently. (`--bind-rootfs` swaps the
   overlay for a direct bind — faster on a slow overlayfs, at the cost of a mutable shared source.)
3. **Devices, volumes & secrets.** A fresh `/dev` with the safe nodes (`+ /dev/net/tun` on `--tun`);
   `-v` volumes bound in with targets resolved **symlink-safely**, confined to the new root; secrets
   on a RAM `/run/secrets` (`0400`); `vdisk:`/`vgpio:` mounting exactly their declared disk/peripherals.
4. **Lockdown.** A clean env (no host secrets leak in), capabilities stripped to least-privilege, an
   optional `--user` drop, an always-on **seccomp** denylist (incl. wrong-arch + x32), and cgroup caps
   — hard `MemoryMax`/`CPUQuota`/`TasksMax` when a systemd user manager is present.

The whole mount sequence flows through a **typestate** (`Rootfs<Mounted> → OldRootReady → ReadOnly`):
the read-only remount is only reachable *after* the pivot, so getting the order wrong is a compile
error. The same sequence drives `--plan`.

OCI images pull with `curl` + `tar` (registry v2, `WWW-Authenticate` auth, multi-arch, gzip/zstd),
each blob **sha256-verified**, each layer **vetted in-process from its raw tar headers** (absolute/`..`
paths, device nodes, escaping hardlink/symlink targets, decompression- & inode-bomb caps) before it
extracts into isolated staging and merges no-follow — closed by *parsing* the layer, not by trusting
the host tar, so it holds on GNU tar and BusyBox tar alike. Every request is TLS-pinned; credentials
travel off-argv. See [ARCHITECTURE.md](ARCHITECTURE.md).

## Performance

One isolated `/bin/true`, warm image cache, one box per run. The x86_64 row is **re-measured on an
Intel i7-14700KF, Linux 6.17**, pinned to a P-core to isolate the hybrid P/E-core scheduler (an
`/bin/true` box that lands on an E-core runs ~2.1 ms — same class): median of 200 (kern) / 20 (engines)
sequential runs. kern here: **median 1.7 ms, avg 1.9 ms, best 1.6 ms** (~1.9 ms unpinned/typical). Your
numbers vary with hardware and load. Board rows are from on-device runs; full method in
**[BENCHMARKS.md](BENCHMARKS.md)**.

| host | kernel | **kern** | bubblewrap | crun | runc | podman | docker |
|---|---|---:|---:|---:|---:|---:|---:|
| x86_64 desktop | 6.17 | **1.9 ms** | 3.2 ms | 5.2 ms\* | 16 ms | ~300 ms | ~307 ms |
| Jetson Orin Nano | 5.15-tegra | **3.6 ms** | 5.6 ms | ✗ | 32 ms | ✗ | 472 ms |
| Raspberry Pi 5 | 6.6-rpi | **2.1 ms** | ✗ | ✗ | ✗ | ✗ | ✗ |
| Arduino UNO Q | **6.16 Android** | **9.9 ms** † | 14.9 ms | ✗ | 76 ms | ✗ | 858 ms |

✗ = not installed (nor readily installable) on that board · \* crun not installed on this host, figure
from BENCHMARKS.md. On the **Pi 5, kern is the only runtime present at all** — one ~1.5 MB static binary
just works where the others are each a setup step (Docker alone is a ~186 MB daemon stack).

kern is the fastest sandbox here at **~1.9 ms** (ahead of bubblewrap). Its *own* box setup is **~1 ms**
(the `KERN_TIMING` phases — `unshare` + overlay + `/dev` + pivot + seccomp, each sub-ms); the rest is
process start + teardown. Adding a hard cgroup cap (the row above doesn't) brings it to **~6 ms** — but
**~4 ms of that is external `systemd-run` + D-Bus scope creation, not kern** (`systemd-run --user --scope
-- true` alone is ~4 ms), opt-out with `KERN_NO_SCOPE` (back to ~1.9 ms, best-effort in-process cgroup). The
top tier is all within a few ms — *nobody* wins single-shot latency outright. The real gap is to the
**engines**: **~120–150× faster** than podman/Docker (~300 ms), which round-trip a daemon every run — yet
kern alone ships a full daemonless container UX in ~1.5 MB. Beyond one start: **~500 boxes/s**, **~7 MB**
RSS/box, **0 resident** (Docker keeps ~186 MB resident before you run anything).

† On the Arduino's Android kernel an overlayfs *mount* is ~31 ms (a kernel quirk — sub-ms elsewhere),
so the default overlay box is ~34 ms there; `--bind-rootfs` starts in **9.9 ms, ahead of bubblewrap**.

Reproduce with **[`examples/benchmark.py`](examples/benchmark.py)** (auto-detects the runtimes you
have). kern does *less* than Docker (no overlay networks yet — see [Roadmap](#roadmap)); this compares
the run path.

## Real-world examples

Runnable, live-verified scripts in **[examples/](examples/)**:

| Scenario | Example |
|---|---|
| **A guided tour** — a tool, your code, resource caps, untrusted code, a service | [showcase.sh](examples/showcase.sh) |
| **Try to break out** — an adversarial isolation battery + 50 boxes at once | [hardening.sh](examples/hardening.sh) |
| Safely vet an untrusted `curl … sh` install script (no net, no host access) | [safe-install-script.sh](examples/safe-install-script.sh) |
| Per-job pipeline: read-only input → isolated processing → output | [data-pipeline.sh](examples/data-pipeline.sh) |
| Build/test a repo in a clean box (laptop or on-device) | [ci-in-a-box.sh](examples/ci-in-a-box.sh) |
| Many isolated services on a small board (few MB vs a 186 MB daemon) | [edge-many-services.sh](examples/edge-many-services.sh) |
| Head-to-head timing: kern vs `docker run` | [compare-vs-docker.sh](examples/compare-vs-docker.sh) |

…plus governed runs, port-published services, compose stacks and more — see
**[examples/README.md](examples/README.md)**.

## Project status

**0.6.3 — a daemonless container + resource runtime that does less than Docker, on purpose.**
Everything in [Features](#features) works today and is tested (**419 tests**, clippy-clean,
`cargo-deny`-clean, security-audited slice by slice); the isolation is real. It deliberately skips a
lot Docker has (overlay networks, a plugin ecosystem) — the point is a small, fast, honest core. The
CLI and config surface are **not frozen until 1.0**.

**New since 0.5:** local image **build** (multi-stage, `--build-arg`, cached layers), **`tag`** +
**`push`** to any registry, **zstd** layer pull, **`--init`** PID-1 reaper, **`--platform`** select,
pods (`--pod` / `--no-outbound`), and the **Python** binding. `build`/`push` are the newest, deepest
surface — audited (COPY-from confinement, setuid/opaque hardening) and, where a rootless-overlay
kernel can't persist an opaque dir, they **fail closed** to a safe path rather than leak.

**New in 0.6.3:** a guided, *"impossible to get wrong"* profile editor in `kern top` (pick the devices
the host actually exposes; every typed field validated live against the same rule the save uses), and a
**capability-based device deny-list** for `vgpio:` — a `/dev` node that grants raw memory/storage or
host control (mem, disks, VFIO/DMA, kvm, HID injection, the console, …) is refused by kernel identity,
and each bound device is fd-pinned to close a check→mount race. Verified on all four boards, including
GPU-compute passthrough on the Jetson.

**Deliberately not here yet:** the headline **GPU slices** (on the [Roadmap](#roadmap)) and Docker-style
overlay networking.

## Roadmap

kern starts as a small, fast sandbox/OCI runtime and grows deliberately — the set of resources it
governs is driven by what proves useful.

- **Shipped:** build + tag + push, zstd layers, `--init`, `--platform`, pods, the Python binding;
  ongoing polish + broader (ARM) CI and edge/I/O ergonomics.
- **Windows, via WSL2 (shipped — one line: see [Install](#install)).** kern runs on Windows inside WSL2
  — a real Linux kernel — so hard caps (`--memory`/`--cpus`) are real there, verified. A `kern.exe` shim
  and a pre-baked kern WSL2 distro (Alpine + kern, no Ubuntu, no manual steps) install with a single
  `irm … | iex` that self-elevates, imports the distro and drops the shim on PATH. Both the shim and the
  distro are **built by the release CI from tagged source and sha256-signed** — the installer verifies
  every download, so it's the same trust level as the Linux binaries, not a hand-uploaded exe. Honest
  caveat: kern runs *inside* the WSL2 kernel, so it doesn't shed the VM weight native Linux does — the
  win is "no Docker Desktop", not "no VM".
- **GPU slices.** A workload gets a *slice* of a GPU, not the whole device. It lands incrementally,
  each stage useful on its own and each opt-in (`--no-gpu` stays the default): first **safe access +
  visibility** (device passthrough, driver-gated, sysfs/procfs masked; per-box VRAM + utilisation in
  `kern stats`), then a **cooperative per-box VRAM cap** via a userspace driver shim (NVIDIA/CUDA
  first — honest trust model: for first-party / noisy-neighbour isolation, *not* a hard boundary
  against a hostile tenant), then **time-sliced compute** + AMD (HIP) / Vulkan. A cross-vendor GPU
  merge pool stays an optional plugin, not core.
- **1.0 — freeze:** CLI + config under semver, threat model + architecture finalised.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design.

## Security

kern isolates with Linux **namespaces + seccomp + a read-only userns root** — a kernel-level boundary,
deny-by-default on devices, with the host's sysfs/procfs masked. That's strong for first-party and
noisy-neighbour workloads. For **adversarial, multi-tenant untrusted code** where you want a
hardware-virtualization boundary, a microVM/VM adds a layer kern doesn't — a deliberate trade for
~1.9 ms starts and a ~1.5 MB footprint.

The full threat model, per-feature notes, and the honest *"kern vs a microVM — when to use what"*
guidance live in [SECURITY.md](SECURITY.md). Found a vulnerability? Report it **privately** via GitHub
Security Advisories ("Report a vulnerability" on the repo) — please don't open a public issue.

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Contributions are covered by a
lightweight [CLA](CLA.md); the project follows a [Code of Conduct](CODE_OF_CONDUCT.md). Security
reports: follow [SECURITY.md](SECURITY.md) (don't open a public issue).

## License

[Apache-2.0](LICENSE) — permissive, with an explicit patent grant. See [NOTICE](NOTICE). The dependency
tree is deliberately tiny (`libc` only on the Rust side; standard-library-only on the Python side) and
copyleft-free — `cargo deny check licenses` is clean.

**kern** and **getkern** are trademarks of the project: the *code* is yours to use under Apache-2.0, but
please don't ship a fork or a competing service under the name.
