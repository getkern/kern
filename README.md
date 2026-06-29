<div align="center">

# kern

**A fast, lightweight sandbox & virtual resource manager.**

Give any workload its own governed slice of the machine — process, filesystem, network,
CPU and memory — kernel-enforced, with no daemon and a ~690 KB binary.

[![CI](https://github.com/getkern/kern/actions/workflows/ci.yml/badge.svg)](https://github.com/getkern/kern/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/platform-linux%20x86__64%20%7C%20aarch64-informational.svg)](#install)
[![Status: 0.4](https://img.shields.io/badge/status-0.4%20%E2%80%94%20early%20but%20it%20runs-green.svg)](#project-status)

[Install](#install) · [Quickstart](#quickstart) · [How it works](#how-it-works) · [Benchmarks](BENCHMARKS.md) · [Edge/ARM](EDGE.md) · [Security](SECURITY.md) · [Roadmap](#roadmap)

</div>

---

kern runs Linux workloads in real, kernel-enforced sandboxes — user + PID + mount + network +
UTS + IPC namespaces, an overlay or read-only root pivoted in, an always-on seccomp filter, and
cgroup limits. It pulls OCI images, runs them, and gets out of the way: **no background daemon,
one short-lived process per box, started in single-digit milliseconds.**

It's built around one idea — *virtual resources*. A container is the first resource kern
manages (isolation); the roadmap extends the same model to compute, starting with GPU slices.

```sh
kern box dev --image alpine -- sh        # a throwaway, isolated Alpine shell — in ~5.5 ms
```

## Why kern

- **Daemonless.** No `dockerd`-style background service. `kern ps` reads state straight from the
  kernel and the runtime directory, pruning dead boxes as it goes.
- **Tiny & fast.** A ~690 KB static binary, **one Rust dependency** (`libc`) — it shells out to
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
  boundary. Where a guarantee is cooperative or opt-in, [SECURITY.md](SECURITY.md) says so.

## The model: two verbs

kern gives a workload a governed slice of the machine through two composable verbs.

| Verb | Question it answers | What it does | Status |
|------|--------------------|--------------|--------|
| **`kern box`** | *"Isolate this workload."* | Its own namespaces, an overlay/read-only filesystem, a private process tree, seccomp. **The container.** | ✅ works now |
| **`kern run`** | *"Give this workload a governed slice of resources."* | Run a command against a quota of CPU / memory — no sandbox, just the governor. (A **GPU slice** is on the roadmap.) | ✅ new in 0.4 |

`box` is about *isolation* (a boundary); `run` is about *resource governance* (a slice). They
compose — `run` inside `box`. Both ship today.

## Features (shipping in 0.4)

- **Run OCI images** — `kern box <name> --image alpine -- sh` pulls from Docker Hub (registry v2,
  anonymous auth, multi-arch → your arch) and runs it. Or bring your own rootfs with `--rootfs`.
- **Governed resource slices** *(new in 0.4)* — `kern run` runs a command against a CPU + memory
  quota with **no sandbox** (the leanest path); `--memory <size>` / `--cpus <n>` set tunable hard
  caps on any `box` or `run` (cgroup v2: `memory.max`, `cpu.max`), replacing the old fixed 512 MiB.
- **Interactive TTY** *(new in 0.4)* — `kern box … -it` / `kern exec … -it` allocate a real PTY
  (raw mode, window-resize aware) for shells, REPLs and full-screen TUIs.
- **Port publishing** *(new in 0.4)* — `-p [ip:]host:box` exposes a box's listening port from a
  rootless forwarder; binds **`127.0.0.1` by default** (loopback-safe), `0.0.0.0` only if you ask.
- **Stay-up & health** *(new in 0.4)* — `--restart` supervises and restarts a detached box on
  failure; `--health-cmd` / `--health-interval` probe it, and `kern ps` shows **HEALTH** + **PORTS**.
- **Find & manage images** — `kern search <query>` searches Docker Hub; `kern images` lists what's
  pulled into the local cache (size + age); `kern pull <ref>` fetches without running.
- **Writable by default** — a copy-on-write overlay; the image stays immutable, scratch is
  discarded on exit. `--read-only` for a read-only root.
- **Volumes** — `-v src:dst[:ro]` binds host paths in (symlink-safe target resolution).
- **Env & workdir** — `--env K=V` (repeatable) and `--workdir <dir>`.
- **Networking** — isolated (loopback-only) by default; `--net` opts into host networking +
  DNS for outbound build/fetch steps.
- **Exec into a running box** — `kern exec <name> -- sh` joins its namespaces.
- **Lifecycle, no daemon** — `-d` detached, `kern ps` / `top` / `stats` / `logs` / `stop`.
- **Compose** — `kern compose stack.toml` brings up a multi-box stack in dependency order.
- **Readable, honest output** *(new in 0.4)* — a foreground box prints an aligned status panel
  (command, what's isolated vs open, resource caps) with an **actionable warning** for the
  deliberately-open choices (`--net`, `--bind-rootfs`); `ps`/`stats`/`images`/`search` share the
  same styling (dim header, semantic colour — green `healthy` / red `unhealthy`). Colour is
  meaning, untrusted fields are escape-stripped, and it's **silent when piped** so scripts stay clean.
- **Hardened isolation** — user + PID + net + UTS + IPC + mount namespaces, self-pivot root,
  always-on seccomp denylist (now also blocks `syslog`, closing a `dmesg` kernel-log leak),
  **least-privilege capabilities** (13 dangerous caps dropped from the bounding set), and cgroup
  memory/PID/CPU caps (hard caps via `systemd-run` where present).
- **Hardened OCI pull** — every blob sha256-verified; layers vetted (no `..`/absolute/device
  escapes, decompression-bomb cap) and merged from isolated staging.
- **`--plan`** — print the exact isolation sequence without running anything.

## Platforms

**Linux, multi-architecture.** Prebuilt static (musl) binaries for **`linux-x86_64`** and
**`linux-aarch64`**; one ~690 KB file, no Rust dependencies beyond `libc` (the OCI-pull path
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
kern logs svc                 # its captured output
kern stop svc                 # or: kern stop a b c   ·   kern stop --all

# Bring up a small stack in dependency order (TOML, no external runtime).
kern compose stack.toml
```

| Command | What it does |
|---------|--------------|
| `box <name> (--image <ref> \| --rootfs <dir>) [-- cmd]` | Run a command in a sandbox |
| `run [--memory <size>] [--cpus <n>] -- cmd` | Run a command under a CPU/memory quota — no sandbox |
| `box … --memory <size>` / `--cpus <n>` | Hard cgroup memory / CPU caps on a box |
| `box … -it` · `exec <name> -it` | Allocate an interactive PTY (shells, REPLs, TUIs) |
| `box … -p [ip:]host:box` | Publish a box port (loopback by default) |
| `box … -d [--restart] [--health-cmd <cmd>]` | Detach, restart-on-failure, health-check |
| `box … -v src:dst[:ro]` / `-e K=V` / `-w <dir>` / `--net` | Volumes · env · workdir · host network |
| `ps` · `top` · `stats` · `logs <name>` · `stop <name>… \| --all` | Observe & control (PORTS/HEALTH in `ps`) |
| `exec <name> [-- cmd]` | Run a command inside a running box |
| `search <query>` | Search Docker Hub for images |
| `pull <image>` / `images` | Download an OCI image · list pulled (cached) images |
| `compose <file>` | Bring up a stack in dependency order |
| `box <name> --plan` | Print the exact isolation sequence without running it |

## Real-world examples

Runnable, live-verified scripts in **[examples/](examples/)**:

| Scenario | Example |
|---|---|
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
3. **Devices & volumes.** A fresh `/dev` with the safe nodes (`null`/`zero`/`full`/`random`/
   `urandom`); `-v` host paths bound in with the target resolved **symlink-safely**, confined to
   the new root.
4. **Lockdown.** A clean environment (no host secrets leak in), **capabilities** stripped to a
   least-privilege set (13 dangerous caps dropped from the bounding set, so they can't be regained),
   an always-on **seccomp** denylist (kexec, kernel modules, ptrace, the mount API, `setns`,
   `syslog`, …), and best-effort cgroup caps — upgraded to hard `MemoryMax` / `CPUQuota` /
   `TasksMax` when a systemd user manager is available, or your `--memory` / `--cpus` values.

The whole mount sequence flows through a **typestate** (`Rootfs<Mounted> → OldRootReady →
ReadOnly`): the read-only remount is only reachable *after* the pivot, so getting the order wrong
is a compile error. The same sequence drives `--plan`, which prints it without privileges.

OCI images are pulled with `curl` + GNU `tar` (registry v2, anonymous Docker Hub auth, multi-arch
selection), each blob **sha256-verified**, each layer vetted (absolute / `..` paths, device
nodes, a decompression-bomb cap) and merged from isolated staging with no-follow semantics — so a
hostile image can't escape extraction.

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
compose) in ~690 KB.

**Same binary, every board — nothing to set up.** kern is *one* ~690 KB static aarch64 binary you
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
them there*, while one ~690 KB static binary just works. That's the point: kern is a single binary
you copy and run; the others are each a setup step (Docker alone pulls in a ~186 MB daemon stack).
They aren't *impossible* on a Pi — they're just work kern doesn't ask of you.

† On the Arduino's Android kernel an overlayfs *mount* is ~31 ms (a kernel quirk — it's sub-ms
everywhere else), so kern's default overlay box is 34 ms there; `--bind-rootfs` swaps the overlay
for a direct bind and kern starts in **9.9 ms, ahead of bubblewrap**.

Beyond a single start, kern does **542 boxes/s** sequentially and **200 in parallel in ~0.07 s**,
at **~7 MB** RSS per box and **no resident daemon** (Docker keeps ~186 MB resident before you run
anything). It does *less* than Docker (no build, registry push, or overlay networks — see
[Roadmap](#roadmap)); this compares the run path. Reproduce this table on your machine with
**[`examples/benchmark.py`](examples/benchmark.py)** (auto-detects the runtimes you have). Full
method + caveats in **[BENCHMARKS.md](BENCHMARKS.md)**.

## Project status

**0.4 — early, but it genuinely runs.** Everything in [Features](#features-shipping-in-04) works
today and is tested (74 tests, clippy-clean, `cargo-deny`-clean); the isolation is real. The CLI
and config surface are **not frozen until 1.0**.

**Not yet (on the roadmap):** declarative TOML profiles, image **build**, ARM in CI, and the
headline **GPU slices** — see [Roadmap](#roadmap). ARM is manual-validated, not yet in CI
([Platforms](#platforms)).

## Roadmap

kern starts as a small, fast sandbox/OCI runtime and grows deliberately. The set of resources it
governs is driven by what proves useful, not a fixed list.

### Shipped in 0.4.0 ✅

The verb that makes kern a *resource manager*, plus the highest-value gaps from the Docker
comparison — all landed:

- ✅ **`kern run`** — give a workload a **governed slice of CPU + memory** without a full sandbox
  (the resource-governor verb; composes inside `kern box`).
- ✅ **Tunable caps** — `--memory` / `--cpus` per box or run (was a fixed 512 MiB / 512 tasks).
- ✅ **Interactive TTY** (`-it`) — real PTY allocation for shells, REPLs and TUIs.
- ✅ **Port publishing** (`-p [ip:]host:box`) — reach a box's listening port; loopback by default.
- ✅ **Quality of life** — `--restart` on failure, `--health-cmd` checks, `ps` PORTS/HEALTH columns.
- ✅ **Hardening** — least-privilege capability drop + `syslog` seccomp block (see [SECURITY.md](SECURITY.md)).

### Later

- **0.5 — declarative TOML profiles.** A named profile (image + CPU/memory + volumes + env + net)
  in config, usable by **both** verbs: `kern run <profile>` *and* `kern box <profile>`. One
  reusable definition instead of a long command line; the box-level resource fields apply too.
- **0.5** — plus polish, more examples, broader CI (ARM in CI, not just manual validation).

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
