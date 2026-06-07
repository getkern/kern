<div align="center">

# kern

**A fast, lightweight sandbox & virtual resource manager.**

Give any workload its own governed slice of the machine — process, filesystem, network, devices,
CPU and memory — kernel-enforced, with no daemon and a ~1 MB binary.

[![CI](https://github.com/getkern/kern/actions/workflows/ci.yml/badge.svg)](https://github.com/getkern/kern/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/platform-linux%20x86__64%20%7C%20aarch64-informational.svg)](#install)
[![Release](https://img.shields.io/github/v/release/getkern/kern?label=release&color=brightgreen)](https://github.com/getkern/kern/releases/latest)
[![Status: feature-complete sandbox](https://img.shields.io/badge/status-feature--complete%20sandbox-brightgreen.svg)](#project-status)

<p align="center">
  <img src="assets/demo.svg" width="780" alt="Terminal demo: a kern.toml defines reusable vcpu/vdisk/vgpio (device) profiles; 'kern box train --image alpine vcpu:heavy vdisk:scratch' attaches a 4-vCPU, 2 GB, 8 GB-scratch rootless isolated slice in 5.5 ms (docker run takes ~308 ms); 'kern run vcpu:heavy -- ffmpeg' caps a heavy transcode with no sandbox; 'kern box iot --image alpine vgpio:sensor' exposes only /dev/i2c-1 and nothing else; piping a request into 'kern box fn --image python' runs it in a fresh isolated box per request (serverless style); 'kern compose stack.toml up' brings up a multi-box stack; 'kern top' is the live TUI for boxes, profiles and volumes — CPU, memory, disk and devices, sliced per box, in one ~1 MB static binary, no daemon.">
</p>

[Install](#install) · [Quickstart](#quickstart) · [How it works](#how-it-works) · [Benchmarks](BENCHMARKS.md) · [Edge/ARM](EDGE.md) · [Security](SECURITY.md) · [Roadmap](#roadmap)

</div>

---

kern runs Linux workloads in real, kernel-enforced sandboxes — user + PID + mount + network +
UTS + IPC namespaces, an overlay or read-only root pivoted in, an always-on seccomp filter, and
cgroup limits. It pulls OCI images, runs them, and gets out of the way: **no background daemon,
one short-lived process per box, started in single-digit milliseconds.**

It's built around one idea — *virtual resources*. A container is the first resource kern
manages (isolation); the same model extends to **CPU, memory, disk (`vdisk:`) and GPIO (`vgpio:`)**
slices today, and to GPU slices on the roadmap. A full daemonless container UX — OCI pull, overlay,
volumes, secrets, in-box SSH, `cp`/`pause`/`attach`, `ps`/`exec`/`logs`, compose, health — in ~1 MB.

```sh
kern box dev --image alpine -- sh        # a throwaway, isolated Alpine shell — in ~5.5 ms
```

## Why kern

- **Daemonless.** No `dockerd`-style background service. `kern ps` reads state straight from the
  kernel and the runtime directory, pruning dead boxes as it goes.
- **Tiny & fast.** A ~1 MB static binary, **one Rust dependency** (`libc`) — it shells out to
  the system's `curl`/`tar` only to pull OCI images (running a box needs neither). Cold start
  ~1.9–5.5 ms vs ~308 ms for `docker run`; ~7 MB RSS per box vs an always-on ~186 MB daemon
  (`dockerd` + `containerd`).
- **Rootless by default.** Unprivileged user namespaces — your uid maps to root *inside* the box,
  and only that. **Single-uid is the default and is `libc`-pure** (no helper, fastest, smallest id
  surface) — it covers most boxes. Workloads that need a full uid range (`apt install`, daemons
  that drop to `www-data` like Apache) use **`--uid-range`, which relies on the standard system
  helper `newuidmap` + `/etc/subuid`** — we state it plainly: that path is not helper-free. No
  privilege is gained on the host either way.
- **Correct by construction.** The mount sequence is a **typestate**: remounting the root
  read-only *before* pivoting into it doesn't compile — a whole class of sandbox-escape bug is
  unrepresentable, not just untested.
- **Honest about its boundaries.** Filesystem / process / namespace isolation is a real kernel
  boundary — the right tool for your own or semi-trusted code (CI, dev, edge, your agents' code).
  For actively hostile multi-tenant code, reach for a microVM; [SECURITY.md](SECURITY.md) says
  exactly when to use which, and where a guarantee is cooperative or opt-in.

## The model: two verbs

kern gives a workload a governed slice of the machine through two composable verbs.

| Verb | Question it answers | What it does | Status |
|------|--------------------|--------------|--------|
| **`kern box`** | *"Isolate this workload."* | Its own namespaces, an overlay/read-only filesystem, a private process tree, seccomp. **The container.** | ✅ works now |
| **`kern run`** | *"Give this workload a governed slice of resources."* | Run a command against a quota of CPU / memory — no sandbox, just the governor. (A **GPU slice** is on the roadmap.) | ✅ works now |

`box` is about *isolation* (a boundary); `run` is about *resource governance* (a slice). They
compose — `run` inside `box`. Both ship today.

## Five one-liners

Each is a single command — rootless, no daemon, nothing pre-installed. The *combination* is
what's awkward to get anywhere else:

```sh
# 1. an isolated OCI container, zero setup — no daemon, no root, one ~1 MB binary
kern box try --image alpine -- sh

# 2. give a container exactly one device — deny-by-default for everything else
kern box iot --image alpine vgpio:sensor -- ./read.py     # only /dev/i2c-1 crosses in

# 3. a fresh, isolated sandbox per request — serverless-style, on your own machine
echo "$payload" | kern box fn --image python -- handler.py

# 4. the same box on a Pi or an Android-kernel board where Docker isn't installed
scp kern pi:  &&  ssh pi 'kern box edge --image alpine -- ./agent'

# 5. print the exact isolation sequence before running anything
kern box audit --image alpine --plan
```

## Features

**Run anything, isolated:**

- **Run OCI images** — `kern box <name> --image alpine -- sh` pulls it (registry v2, multi-arch →
  your arch) and runs it. Works with **any registry** — Docker Hub, GHCR, GitLab, quay, Harbor,
  self-hosted — via the standard `WWW-Authenticate` challenge (Bearer token or HTTP Basic). Or bring
  your own rootfs with `--rootfs`. **`kern login <registry>`** authenticates private-image pulls;
  credentials are stored `0600` and passed to `curl` off-argv (never in a process's argv).
- **Governed resource slices** — `kern run` runs a command against a CPU + memory quota with **no
  sandbox** (the leanest path); `--memory` / `--cpus` / `--cpuset-cpus` (pin) / `--memory-swap-max`
  / `--pids-limit` set tunable hard caps on any `box` or `run` (cgroup v2), kernel-enforced where
  the controllers are delegated (a systemd user session; kern warns if it can't apply a cap).
- **Writable by default** — a copy-on-write overlay; the image stays immutable, scratch is
  discarded on exit. `--read-only` for a read-only root.
- **Interactive TTY** — `kern box … -it` / `kern exec … -it` allocate a real PTY (raw mode,
  window-resize aware) for shells, REPLs and full-screen TUIs.

**Data & devices crossing the boundary:**

- **Volumes, full** — `-v src:dst[:ro]` binds host paths (symlink-safe); **named volumes**
  (`-v data:/work`, auto-created, managed with `kern volume create/ls/rm/inspect/prune`) with an
  optional **per-volume quota** (`--size`); and **network volumes** (`-v nfs://…` / `smb://` /
  `sshfs://`) mounted rootless via FUSE/GVFS. How volumes, vdisks and disks fit together —
  [docs/STORAGE.md](docs/STORAGE.md).
- **Secrets** — `--secret NAME=value` / `NAME=-` (stdin) / `SRC[:NAME]` (file) delivers a value as
  `/run/secrets/NAME` (mode `0400`) on a RAM tmpfs — never in the image or the workload's env.
- **vDisk** (`vdisk:` profiles) — a size-capped scratch volume at `/vdisk/<name>`: a RAM tmpfs
  rootless, or a disk-backed **ext4-on-loop** image (persistent + real disk quota) when privileged.
- **vGPIO** (`vgpio:` profiles) — expose *only* the listed GPIO/I2C/SPI/LED peripherals into a box
  (deny-by-default holds for everything else) — for edge/IoT workloads.
- **`--tmpfs PATH[:size]`** — a fresh `nosuid,nodev` tmpfs in the box (refused over hardened mounts).

**Networking & identity:**

- **Network modes** — isolated (loopback-only) by default (or `--network none` to say so
  explicitly); `--network host` (= `--net`) shares the host network for outbound build/fetch;
  `--hostname` sets the UTS name; **`--tun`** exposes
  `/dev/net/tun` for WireGuard / userspace VPNs.
- **Port publishing** — `-p [ip:]host:box` exposes a box's port from a rootless forwarder; binds
  **`127.0.0.1` by default** (loopback-safe), `0.0.0.0` only if you ask.
- **In-box SSH** — `kern box --ssh 2222 …` runs a throwaway `sshd` inside the box (auto-generated
  keypair or `--ssh-key`) and publishes it, for a ready-to-`ssh` workspace.
- **`--user UID[:GID]`** — drop the workload to a specific uid/gid (fails closed if it can't be mapped).

**Least privilege, configurable:**

- **Capabilities** — 13 dangerous caps are always dropped; `--cap-drop CAP`/`ALL` drops more and
  `--cap-add CAP` keeps one (a re-added cap is still bounded by the box's userns + seccomp).
- **Seccomp** — an always-on denylist (kexec, kernel modules, ptrace, the mount API, `setns`,
  `syslog`, …); wrong-arch **and x86_64 x32-ABI** syscalls are killed, closing the alias bypass.

**Lifecycle & operations, no daemon:**

- **Stay-up & health** — `--restart` supervises a detached box; `--health-cmd` +
  `--health-interval`/`--health-retries`/`--health-start-period`/`--health-timeout` probe it, and
  `kern ps` shows **HEALTH** + **PORTS**.
- **Box ops** — `kern cp <box>:<src> <dst>` (symlink-confined, CVE-2019-14271-safe), `kern pause`/
  `unpause` (cgroup freezer), `kern attach` (live output), `kern exec` (join a running box).
- **Observe & manage** — `-d` detached; `kern ps` / `top` (TUI) / `stats` / `logs` / `inspect` /
  `stop` / `kill` / `killall` / `prune` / `gc`.
- **Diagnostics** — **`kern doctor`** preflights the host (will boxes run here? which optional
  features are available?), `kern info` snapshots the runtime, `kern bench` times box start latency,
  `kern history` / `kern recover` audit and reconcile.
- **Shell completions** — `kern completions <bash|zsh|fish>`.
- **Compose** — `kern compose stack.toml` brings up a multi-box stack in dependency order (each
  `[box.NAME]` table mirrors the CLI — [docs/CONFIG.md](docs/CONFIG.md)).
- **Resource profiles** — define reusable `[[vcpu]]` / `[[vgpio]]` / `[[vdisk]]` profiles in
  `~/.config/kern/kern.toml`, attach by prefix (`kern run vcpu:heavy vgpio:leds -- ./train.sh`).
  Manage with `kern config [edit|setup|probe|clear]` / `validate` / `examples`. Resource-centric
  schema, forward-compatible with the full runtime.

**Built-in hardening:**

- **Readable, honest output** — a foreground box prints an aligned status panel (command, what's
  isolated vs open, resource caps) with an **actionable warning** for deliberately-open choices
  (`--net`, `--bind-rootfs`); tables share the styling (semantic colour — green `healthy` / red
  `unhealthy`), untrusted fields are escape-stripped, and output is **silent when piped**.
- **Hardened isolation** — user + PID + net + UTS + IPC + mount namespaces, self-pivot root,
  `nosuid,nodev` box root, always-on seccomp, least-privilege capabilities, cgroup memory/PID/CPU/IO
  caps (hard via `systemd-run` where present).
- **Hardened OCI pull** — every blob sha256-verified; layers vetted (no `..`/absolute/device
  escapes, decompression-bomb cap) and merged from isolated staging with no-follow semantics.
- **Correct by construction** — the mount sequence is a typestate (read-only-before-pivot doesn't
  compile); **`--plan`** prints the exact isolation sequence without running anything.

Where a guarantee is cooperative or opt-in (the GPU cap, the vGPIO/vdisk trust scope, network
volumes), [SECURITY.md](SECURITY.md) says so plainly.

## Platforms

**Linux, multi-architecture.** Prebuilt static (musl) binaries for **`linux-x86_64`** and
**`linux-aarch64`**; one ~1 MB file, no Rust dependencies beyond `libc` (the OCI-pull path
shells out to the system's `curl`/`tar`).

| Platform | Arch | Status |
|---|---|---|
| x86_64 Linux | x86_64 | ✅ primary + automated CI |
| NVIDIA Jetson (L4T) | aarch64 | ✅ manually validated |
| Raspberry Pi 5 | aarch64 | ✅ manually validated |
| Arduino UNO Q (Android kernel, Debian userland) | aarch64 | ✅ manually validated |

Needs a **Linux kernel** with **unprivileged user namespaces** + **cgroups v2**, and a **Linux
userland** (glibc/musl, a shell). The kernel flavor doesn't matter — kern runs even on an
*Android kernel* as long as the userland is Linux (the Arduino UNO Q is an Android-kernel board
with a Debian userland). It does **not** run on stock Android-the-OS (Bionic userland, SELinux,
userns usually disabled). The daemonless design is a big win on RAM-constrained boards (0 resident
vs ~186 MB for a daemon) — see **[EDGE.md](EDGE.md)**. Automated ARM CI is tracked in the issues.

> **Speed (one isolated `/bin/true`, 28-core x86_64):** bare box **~1.9 ms** (fastest here, ahead of
> `bubblewrap`; with a cgroup cap **~5.5 ms** ties `crun`, ~2× `runc`), vs **~155 ms `podman`** /
> **~308 ms `docker`** — and **200 boxes in parallel in ~0.07 s**. Full multi-runtime table (kern /
> crun / runc / bubblewrap / podman / Docker) in
> **[BENCHMARKS.md](BENCHMARKS.md)**.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
```

The script lives in this repo (read it first if you like) and is served from **github.com** — not a
domain you've never seen. It downloads the checksum-verified release binary for your arch
(`linux-x86_64` / `linux-aarch64`) and verifies the sha256 before installing. No Rust toolchain
required. (`getkern.dev/install.sh` is a short alias for the same script.)

<details>
<summary>Prefer to download + verify by hand?</summary>

```sh
# Grab the binary straight from GitHub Releases and check the checksum yourself:
curl -fsSL https://github.com/getkern/kern/releases/latest/download/kern-x86_64-unknown-linux-musl.tar.gz \
  | tar xz && install -m 755 kern ~/.local/bin/kern   # aarch64: swap x86_64 → aarch64
# each release ships a matching .tar.gz.sha256 next to it
```

</details>

<details>
<summary>Build from source</summary>

```sh
git clone https://github.com/getkern/kern
cd kern
cargo build --release
./target/release/kern --help
```

</details>

## Quickstart

```sh
# Run a real OCI image in a writable overlay (the image stays immutable; scratch is discarded).
kern box dev --image alpine -it -- sh        # -it = interactive PTY (raw mode, resize-aware)

# Cap the slice: hard memory + CPU limits (cgroup v2), enforced by the kernel.
kern box build --image alpine --memory 512M --cpus 1.5 \
  -v "$PWD:/src" -w /src -e CI=1 --net -- sh -c 'apk add --no-cache make && make'

# Governor only, no sandbox — give a host command a CPU + memory quota (the leanest path).
kern run --memory 256M --cpus 0.5 -- ./crunch-numbers

# Read-only input + a writable output dir — the sanctioned way data crosses the boundary.
kern box job --image alpine -v /data:/in:ro -v "$PWD/out:/out" -- /in/run.sh

# Detached service: publish a port, keep it up, health-check it — without a daemon.
kern box svc --image alpine -d -p 8080:80 --restart \
  --health-cmd 'wget -qO- localhost:80' --health-interval 5 -- httpd -f
kern ps                       # running boxes, with PORTS + HEALTH columns
kern top                      # interactive task manager (TUI: tabs, live mem/CPU)
kern exec svc -it -- sh       # shell into a running box (joins its namespaces)
kern cp svc:/etc/app.conf .   # copy a file out (symlink-confined, CVE-2019-14271-safe)
kern logs svc                 # its captured output
kern stop svc                 # or: kern stop a b c   ·   kern stop --all

# Deliver a secret (never in the image or env) and drop caps to least-privilege.
printf "$DB_TOKEN" | kern box job --image alpine --secret TOKEN=- --cap-drop ALL \
  -- sh -c 'curl -H "Authorization: Bearer $(cat /run/secrets/TOKEN)" https://api/…'

# An SSH-able workspace: throwaway sshd inside the box, published on :2222.
kern box dev --image ubuntu:22.04 -d --ssh 2222   # then: ssh -p 2222 root@127.0.0.1

# Will boxes even run on this host? Preflight it.
kern doctor

# Bring up a small stack in dependency order (TOML, no external runtime).
kern compose stack.toml
```

| Command | What it does |
|---------|--------------|
| `box <name> (--image <ref> \| --rootfs <dir>) [-- cmd]` | Run a command in a sandbox |
| `run [--memory <size>] [--cpus <n>] -- cmd` | Run a command under a CPU/memory quota — no sandbox |
| `box … --memory` / `--cpus` / `--cpuset-cpus` / `--pids-limit` | Hard cgroup memory / CPU / task caps |
| `box … -it` · `exec <name> -it` | Allocate an interactive PTY (shells, REPLs, TUIs) |
| `box … -p [ip:]host:box` · `--ssh <port>` | Publish a box port · run an in-box sshd |
| `box … --secret NAME=val` · `--tmpfs /path` | Deliver a secret (`/run/secrets`) · fresh tmpfs |
| `box … -v name:/dst` · `--tun` · `--hostname` · `--user` | Named/network volumes · TUN · UTS name · uid |
| `box … --cap-add/--cap-drop` · `--network host\|none` | Configure capabilities · network mode |
| `box … -d [--restart] [--health-cmd <cmd> …]` | Detach, restart-on-failure, health-check |
| `cp <box>:<src> <dst>` · `pause`/`unpause` · `attach` | Copy files · freeze/thaw · live output |
| `ps` · `top` · `stats` · `logs` · `inspect` · `stop`/`kill` `[--all]` | Observe & control (PORTS/HEALTH in `ps`) |
| `exec <name> [-- cmd]` | Run a command inside a running box |
| `search` · `pull` · `build` · `images` · `login`/`logout` | Search · pull · build (Dockerfile subset) · list images · registry auth |
| `volume <create\|ls\|rm\|inspect\|prune>` | Manage named volumes |
| `doctor` · `info` · `bench` · `history` · `recover` · `gc` | Preflight · runtime info · benchmark · ops |
| `config [edit\|setup\|probe\|clear]` · `validate` · `examples` | Manage `kern.toml` resource profiles |
| `compose <file>` · `completions <shell>` | Bring up a stack · shell completions |
| `pod create/ls/rm` · `box … --pod <name>` | Shared-network pod — boxes reach each other by name |
| `box <name> --plan` | Print the exact isolation sequence without running it |

## Embed it (Rust)

Beyond the CLI, kern ships an embeddable Rust API — run a sandboxed command straight from your
program and get structured output back. Spin a fresh isolated box per call (untrusted code, agent
tools, per-request workers):

```rust
use kern_isolation::Sandbox;

let out = Sandbox::builder()
    .rootfs("/var/lib/kern/rootfs/alpine")
    .no_network()                    // isolated loopback-only netns
    .memory_limit_bytes(256 << 20)   // cgroup cap
    .timeout_ms(5_000)               // SIGKILL a runaway
    .build()?
    .run("python3", &["handler.py"])?;

assert!(out.success());               // + out.stdout / .stderr / .exit_code / .wall_ms
```

It applies the same `kern.toml` profiles as the CLI
(`.config("kern.toml").profile("vcpu:small")`) and surfaces non-fatal advisories via
`.warnings()`. The `kern-isolation` crate drives the installed `kern` binary under the hood (it
needs `kern` on `PATH` or `KERN_BIN`); it lives in this repo — depend on it by git or path, not yet
from crates.io.

## Real-world examples

Runnable, live-verified scripts in **[examples/](examples/)**:

| Scenario | Example |
|---|---|
| **A guided tour** — a tool, your code, resource caps, untrusted code, a service | [showcase.sh](examples/showcase.sh) |
| **Try to break out** — an adversarial isolation battery + 50 boxes at once | [hardening.sh](examples/hardening.sh) |
| Publish a box port to the host, kept up + health-checked (`-p` · `--restart` · `--health-cmd`) | [serve-with-port.sh](examples/serve-with-port.sh) |
| Govern CPU + memory — `kern run` (no sandbox) and `--memory`/`--cpus` caps | [governed-run.sh](examples/governed-run.sh) |
| Vet an untrusted `curl \| sh` script safely (no net, no host access) | [safe-install-script.sh](examples/safe-install-script.sh) |
| Per-job data pipeline: read-only input → isolated processing → output | [data-pipeline.sh](examples/data-pipeline.sh) |
| Build/test a repo in a clean box (laptop or on-device) | [ci-in-a-box.sh](examples/ci-in-a-box.sh) |
| Compile in a disposable toolchain — host keeps no compiler | [build-and-extract.sh](examples/build-and-extract.sh) |
| Try a command on Alpine + Debian + Ubuntu instantly, throwaway | [try-any-distro.sh](examples/try-any-distro.sh) |
| Many isolated services on a small board (few MB vs a 186 MB daemon) | [edge-many-services.sh](examples/edge-many-services.sh) |
| Run one command across a matrix of images, all at once | [parallel-matrix.sh](examples/parallel-matrix.sh) |
| Head-to-head timing: kern vs `docker run` | [compare-vs-docker.sh](examples/compare-vs-docker.sh) |

…plus throwaway shells, detached services, compose stacks and more — see
**[examples/README.md](examples/README.md)**.

## How it works

A `kern box` is set up in a single short-lived process tree — no daemon, no shared state:

1. **Namespaces.** `unshare` into a fresh user + PID + UTS + IPC namespace (and, by default, an
   isolated loopback-only network namespace; `--net` shares the host's instead — so the box can
   then reach host services on `127.0.0.1` and the host's abstract sockets: opt-in, flagged in the
   status panel). A single-UID map
   makes your uid root *inside* the box only (`--uid-range` opts into a full sub-id range for
   `apt`/`www-data`-style workloads).
2. **Root filesystem.** An **overlay** by default (the OCI image / rootfs is the read-only lower; a
   private upper takes writes, so the image stays immutable); `--read-only` remounts that overlay
   read-only after the pivot — which works even where a bind remount-RO is denied (e.g. some
   Android-kernel boards). The pivot is a self-pivot (`pivot_root(".", ".")`), so nothing is
   written into the rootfs — many boxes can share one read-only rootfs concurrently. (`--bind-rootfs`
   swaps the overlay for a direct bind — faster on kernels with a slow overlayfs, at the cost of a
   mutable, shared source; see [BENCHMARKS.md](BENCHMARKS.md).)
3. **Devices, volumes & secrets.** A fresh `/dev` with the safe nodes (`null`/`zero`/`full`/`random`/
   `urandom`, plus `/dev/net/tun` on `--tun`); `-v` host paths / named / network volumes bound in
   with targets resolved **symlink-safely**, confined to the new root; `--secret` values written to a
   RAM-backed `/run/secrets` (mode `0400`), and `vdisk:`/`vgpio:` profiles mounting exactly their
   declared disk/peripherals.
4. **Lockdown.** A clean environment (no host secrets leak in), **capabilities** stripped to a
   least-privilege set (13 dangerous caps dropped from the bounding set, adjustable per box with
   `--cap-add`/`--cap-drop`), an optional drop to `--user`, an always-on **seccomp** denylist (kexec,
   kernel modules, ptrace, the mount API, `setns`, `syslog`, wrong-arch **and x32** syscalls), and
   best-effort cgroup caps — upgraded to hard `MemoryMax` / `CPUQuota` / `TasksMax` when a systemd
   user manager is available, or your `--memory` / `--cpus` / `--pids-limit` values.

The whole mount sequence flows through a **typestate** (`Rootfs<Mounted> → OldRootReady →
ReadOnly`): the read-only remount is only reachable *after* the pivot, so getting the order wrong
is a compile error. The same sequence drives `--plan`, which prints it without privileges.

OCI images are pulled with `curl` + `tar` (registry v2, `WWW-Authenticate` challenge auth for any
registry, multi-arch selection), each blob **sha256-verified**, and each layer **vetted in-process
from its raw tar headers** (absolute / `..` paths, device nodes, escaping hardlink/symlink targets,
decompression- and inode-bomb caps) before it extracts into isolated staging and merges with
no-follow semantics — the extraction escape classes are closed by *parsing* the layer, not by
trusting the host tar's version or text output, so the guarantee holds on GNU tar and on an edge
board's BusyBox tar alike. Every request is TLS-pinned (`--proto =https`, https-only redirects);
credentials travel to `curl` off-argv.

## Performance

One isolated `/bin/true`, 28-core x86_64, warm cache — time per run measured as total ÷ 200
sequential runs (a per-call timer would dominate at sub-ms scale). Your numbers will vary:

| runtime | cold start | what it does at that price |
|---|---:|---|
| **kern** `--rootfs` | **1.9 ms** | overlay + self-pivot + seccomp |
| bubblewrap | 2.6 ms | a sandbox *primitive* — no images, caps, lifecycle |
| crun | 5.2 ms | OCI runtime (C): bundle + cgroup |
| runc | 12.2 ms | OCI runtime (Go): bundle + cgroup |
| podman (rootless) | 155 ms | daemonless engine: `conmon` + full OCI stack per run |
| **docker run --rm** | 308 ms | client → daemon round-trip |

kern leads **both** honest tiers: it's the fastest sandbox here at **1.9 ms** (ahead of
bubblewrap), and when it *adds* a hard cgroup cap — the row above doesn't — that full path is
**~5.5 ms**, which **ties `crun`** (the fastest OCI runtime) and is **~2× `runc`**. The top
tier is all within a couple ms — *nobody* "wins" single-shot latency outright (that's why we don't
claim "fastest in the world"). The real gap is to the **engines**: kern is **~80–160× faster** than
`podman` (~155 ms) and Docker (~308 ms), which fork `conmon` / round-trip a daemon every run — yet
kern is the only one shipping a full daemonless container UX (OCI pull, overlay, `ps`/`exec`/`logs`,
compose) in ~1 MB.

**Same binary, every board — nothing to set up.** kern is *one* ~1 MB static aarch64 binary you
`scp` and run: no daemon, no package, no Rust runtime deps (it shells out to the system's
`curl`/`tar` only for image pull). The same `kern box` runs on a desktop, a
Jetson, a Raspberry Pi 5, and an **Android-kernel** board — fastest on all four (cold start,
isolated `/bin/true`):

| host | kernel | **kern** | bubblewrap | crun | runc | podman | docker |
|---|---|---:|---:|---:|---:|---:|---:|
| x86_64 desktop | 6.17 | **1.9 ms** | 2.6 ms | 5.2 ms | 12.2 ms | 155 ms | 308 ms |
| Jetson Orin Nano | 5.15-tegra | **3.6 ms** | 5.6 ms | ✗ | 32 ms | ✗ | 472 ms |
| Raspberry Pi 5 | 6.6-rpi | **2.1 ms** | ✗ | ✗ | ✗ | ✗ | ✗ |
| Arduino UNO Q | **6.16 Android** | **9.9 ms** † | 14.9 ms | ✗ | 76 ms | ✗ | 858 ms |

✗ = not installed (nor readily installable) on that board. The standout is the **Raspberry Pi 5:
`kern` is the only runtime present at all** — bubblewrap, crun, runc, podman and Docker are *none of
them there*, while one ~1 MB static binary just works. That's the point: kern is a single binary
you copy and run; the others are each a setup step (Docker alone pulls in a ~186 MB daemon stack).
They aren't *impossible* on a Pi — they're just work kern doesn't ask of you.

† On the Arduino's Android kernel an overlayfs *mount* is ~31 ms (a kernel quirk — it's sub-ms
everywhere else), so kern's default overlay box is 34 ms there; `--bind-rootfs` swaps the overlay
for a direct bind and kern starts in **9.9 ms, ahead of bubblewrap**.

Beyond a single start, kern does **542 boxes/s** sequentially and **200 in parallel in ~0.07 s**,
at **~7 MB** RSS per box and **no resident daemon** (Docker keeps ~186 MB resident before you run
anything). It does *less* than Docker (no registry push or overlay networks — see
[Roadmap](#roadmap)); this compares the run path. Reproduce this table on your machine with
**[`examples/benchmark.py`](examples/benchmark.py)** (auto-detects the runtimes you have). Full
method + caveats in **[BENCHMARKS.md](BENCHMARKS.md)**.

## Project status

**0.5.7 — a feature-complete sandbox & resource runtime.** Everything in [Features](#features) works
today and is tested (214 tests, clippy-clean, `cargo-deny`-clean, security-audited slice by slice);
the isolation is real. The CLI and config surface are **not frozen until 1.0**.

**Deliberately not here:** image **registry push**, and the headline **GPU slices**, which land in
stages from 0.9 — see [Roadmap](#roadmap). (kern *does* build a local image from a Dockerfile
subset with **`kern build`**; only pushing to a registry is out.) ARM is manual-validated, not yet
in CI ([Platforms](#platforms)).

## Roadmap

kern starts as a small, fast sandbox/OCI runtime and grows deliberately. The set of resources it
governs is driven by what proves useful, not a fixed list.

### Shipped in 0.5.7 ✅

kern grew from a fast sandbox/OCI runtime into a **feature-complete daemonless container +
resource runtime** — everything in [Features](#features) landed and is tested/audited:

- ✅ **Full volume system** — bind, named (`kern volume` CRUD + quota), and network (`nfs`/`smb`/`sshfs`).
- ✅ **Secrets** (`--secret`) and an **in-box SSH** workspace (`--ssh`).
- ✅ **Network & identity** — `--network host|none`, `--hostname`, `--tun`, `--user`.
- ✅ **Resources** — `--cpuset-cpus`, `--memory-swap-max`, `--pids-limit`, `--tmpfs`; `vdisk:` / `vgpio:` slices.
- ✅ **Configurable least-privilege** — `--cap-add`/`--cap-drop`, seccomp x32-ABI kill.
- ✅ **Box ops** — `cp` (symlink-confined), `pause`/`unpause`, `attach`, advanced health probes.
- ✅ **Operations** — `doctor`, `info`, `bench`, `history`, `recover`, `gc`, `kill`/`killall`, completions,
  registry `login`/`logout`, `config` management, resource profiles (`kern.toml`).

### Later

- **0.6/0.7 — polish + broader CI** (ARM in CI, not just manual validation) and more edge/I/O ergonomics.

**GPU — shipped in stages, not one big bang.** The headline (a workload gets a *slice* of a GPU,
not the whole device) is too much for a single release, so it lands incrementally — each stage
useful on its own, each opt-in (`--no-gpu` stays the default):

- **0.9 — GPU access + telemetry.** A box can safely use the host GPU (device passthrough,
  driver-version gated, sysfs/procfs masked) and `kern stats` shows per-box VRAM + utilisation.
  Visibility and safe sharing first — no virtualization yet.
- **0.10 — VRAM cap (cooperative).** A per-box VRAM ceiling via a userspace driver shim
  (`LD_LIBRARY_PATH`), NVIDIA/CUDA first. Honest trust model: a **cooperative** governor for
  first-party / noisy-neighbour isolation, *not* a hard boundary against a hostile tenant.
- **0.11 — compute slice + more vendors.** Time-sliced compute (token bucket) behind a single
  governed-driver proxy, plus AMD (HIP) and Vulkan backends; AMD/Intel can take a harder cap.
- The cross-vendor **GPU merge pool** stays a separate optional plugin, not core.

- **1.0 — freeze.** CLI + config frozen under semver, threat model and architecture finalised.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design.

## Contributing

Issues and PRs are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Contributions are covered by
a lightweight [CLA](CLA.md), and the project follows a [Code of Conduct](CODE_OF_CONDUCT.md).

Security reports: please follow [SECURITY.md](SECURITY.md) (do not open a public issue).

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).
