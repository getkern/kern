<div align="center">

# kern

**A fast, lightweight sandbox & virtual resource manager.**

Give any workload its own governed slice of the machine — process, filesystem, network,
CPU and memory — kernel-enforced, with no daemon and a ~640 KB binary.

[![CI](https://github.com/getkern/kern/actions/workflows/ci.yml/badge.svg)](https://github.com/getkern/kern/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/platform-linux%20x86__64%20%7C%20aarch64-informational.svg)](#install)
[![Status: 0.3](https://img.shields.io/badge/status-0.3%20%E2%80%94%20early%20but%20it%20runs-green.svg)](#project-status)

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
- **Tiny & fast.** A ~640 KB static binary, one dependency (`libc`). Cold start ~1.9–5.5 ms vs
  ~308 ms for `docker run`; ~7 MB RSS per box vs an always-on ~186 MB daemon (`dockerd` +
  `containerd`).
- **Rootless by default.** Unprivileged user namespaces — your uid maps to root *inside* the box,
  and only that (single-uid: fastest, smallest id surface). Add `--uid-range` for a full sub-id
  range (needs `newuidmap` + `/etc/subuid`) so `apt install` and daemons that drop to `www-data`
  (e.g. Apache) work. No privilege gained on the host either way.
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
| **`kern run`** | *"Give this workload a governed slice of resources."* | Run a command against a quota of CPU / memory — and, on the roadmap, a **GPU slice**. The resource governor. | 🔜 roadmap |

`box` is about *isolation* (a boundary); `run` is about *resource governance* (a slice). They
compose — `run` inside `box`. Everything below is `box`, which is what ships today.

## Features (shipping in 0.3)

- **Run OCI images** — `kern box <name> --image alpine -- sh` pulls from Docker Hub (registry v2,
  anonymous auth, multi-arch → your arch) and runs it. Or bring your own rootfs with `--rootfs`.
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
- **Hardened isolation** — user + PID + net + UTS + IPC + mount namespaces, self-pivot root,
  always-on seccomp denylist, cgroup memory/PID caps (hard caps via `systemd-run` where present).
- **Hardened OCI pull** — every blob sha256-verified; layers vetted (no `..`/absolute/device
  escapes, decompression-bomb cap) and merged from isolated staging.
- **`--plan`** — print the exact isolation sequence without running anything.

## Platforms

**Linux, multi-architecture.** Prebuilt static (musl) binaries for **`linux-x86_64`** and
**`linux-aarch64`**; one ~640 KB file, no runtime dependencies beyond `libc`.

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
> `bubblewrap`; with a cgroup cap **~5.5 ms** ties `crun`, ~2× `runc`), vs **~249 ms `podman`** /
> **~308 ms `docker`** — and **200 boxes in parallel in ~0.07 s**. Full multi-runtime table (kern /
> crun / runc / bubblewrap / podman / Docker) in
> **[BENCHMARKS.md](BENCHMARKS.md)**.

## Install

```sh
curl -fsSL https://getkern.dev/install.sh | sh
```

Downloads a checksum-verified static binary for your platform (`linux-x86_64` / `linux-aarch64`),
published on every tagged release. No Rust toolchain required.

<details>
<summary>Other ways to install (no custom domain needed)</summary>

```sh
# The same installer, served straight from the repo:
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh

# Or grab a binary directly from the latest GitHub Release:
curl -fsSL https://github.com/getkern/kern/releases/latest/download/kern-x86_64-unknown-linux-musl.tar.gz \
  | tar xz && install -m 755 kern ~/.local/bin/kern   # (aarch64: swap x86_64 → aarch64)
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
kern box dev --image alpine -- sh

# Bind your code in, set env + workdir, build with network access.
kern box build --image alpine \
  -v "$PWD:/src" -w /src -e CI=1 --net -- sh -c 'apk add --no-cache make && make'

# Read-only input + a writable output dir — the sanctioned way data crosses the boundary.
kern box job --image alpine -v /data:/in:ro -v "$PWD/out:/out" -- /in/run.sh

# Detached services, observed and controlled — without a daemon.
kern box svc --image alpine -d -- httpd -f
kern ps                       # list running boxes
kern top                      # interactive task manager (TUI: tabs, live mem/CPU)
kern exec svc -- sh           # shell into a running box (joins its namespaces)
kern logs svc                 # its captured output
kern stop svc                 # or: kern stop a b c   ·   kern stop --all

# Bring up a small stack in dependency order (TOML, no external runtime).
kern compose stack.toml
```

| Command | What it does |
|---------|--------------|
| `box <name> (--image <ref> \| --rootfs <dir>) [-- cmd]` | Run a command in a sandbox |
| `box … -v src:dst[:ro]` / `-e K=V` / `-w <dir>` / `--net` | Volumes · env · workdir · host network |
| `box … -d` · `ps` · `top` · `stats` · `logs <name>` · `stop <name>… \| --all` | Detach, observe, control |
| `exec <name> [-- cmd]` | Run a command inside a running box |
| `search <query>` | Search Docker Hub for images |
| `pull <image>` / `images` | Download an OCI image · list pulled (cached) images |
| `compose <file>` | Bring up a stack in dependency order |
| `box <name> --plan` | Print the exact isolation sequence without running it |

## Real-world examples

Runnable, live-verified scripts in **[examples/](examples/)**:

| Scenario | Example |
|---|---|
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
   isolated loopback-only network namespace; `--net` shares the host's instead). A single-UID map
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
4. **Lockdown.** A clean environment (no host secrets leak in), an always-on **seccomp** denylist
   (kexec, kernel modules, ptrace, the mount API, `setns`, …), and best-effort cgroup caps —
   upgraded to hard `MemoryMax` / `TasksMax` when a systemd user manager is available.

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
| podman (rootless) | 249 ms | daemonless engine: `conmon` + full OCI stack per run |
| **docker run --rm** | 308 ms | client → daemon round-trip |

kern leads **both** honest tiers: it's the fastest sandbox here at **1.9 ms** (ahead of
bubblewrap), and when it *adds* a hard cgroup cap — the row above doesn't — that full path is
**~5.5 ms**, which **ties `crun`** (the fastest OCI runtime) and is **~2× `runc`**. The top
tier is all within a couple ms — *nobody* "wins" single-shot latency outright (that's why we don't
claim "fastest in the world"). The real gap is to the **engines**: kern is **~35–110× faster** than
`podman` and Docker, which fork `conmon` / round-trip a daemon every run — yet kern is the only one
shipping a full daemonless container UX (OCI pull, overlay, `ps`/`exec`/`logs`, compose) in ~640 KB.

**Same binary, every board — nothing to set up.** kern is *one* ~640 KB static aarch64 binary you
`scp` and run: no daemon, no package, no dependency. The same `kern box` runs on a desktop, a
Jetson, a Raspberry Pi 5, and an **Android-kernel** board — fastest on all four (cold start,
isolated `/bin/true`):

| host | kernel | **kern** | bubblewrap | docker |
|---|---|---:|---:|---:|
| x86_64 desktop | 6.17 | **1.9 ms** | 2.6 ms | 308 ms |
| Jetson Orin Nano | 5.15-tegra | **3.1 ms** | 5.6 ms | 477 ms |
| Raspberry Pi 5 | 6.6-rpi | **2.0 ms** | — ‡ | — ‡ |
| Arduino UNO Q | **6.16 Android** | **9.9 ms** † | 14.9 ms | 868 ms |

‡ On the Pi, kern was the **only** container runtime present — and that's the point: it's a single
binary you copy and run, while the others must be installed first (Docker pulls in a ~186 MB daemon
stack). They aren't *impossible* on a Pi, they're just a setup step kern doesn't need; drop the
binary on a fresh board and you have containers.

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

**0.3 — early, but it genuinely runs.** Everything in [Features](#features-shipping-in-03) works
today and is tested (58 tests, clippy-clean, `cargo-deny`-clean); the isolation is real. The CLI
and config surface are **not frozen until 1.0**.

**Not yet (on the roadmap):** `kern run` resource quotas (CPU/memory), tunable `--memory`/`--cpus`,
interactive PTY (`-it`), port publishing (`-p`), image build, and the headline **GPU slices** —
see [Roadmap](#roadmap). ARM is manual-validated, not yet in CI ([Platforms](#platforms)).

## Roadmap

kern starts as a small, fast sandbox/OCI runtime and grows deliberately. The set of resources it
governs is driven by what proves useful, not a fixed list.

### Coming in 0.4.0

The verb that makes kern a *resource manager*, plus the highest-value gaps from the Docker
comparison. Planned, not frozen — see [BENCHMARKS.md](BENCHMARKS.md) for where 0.3 already wins.

- **`kern run`** — give a workload a **governed slice of CPU + memory** without a full sandbox
  (the resource-governor verb; composes inside `kern box`).
- **Tunable caps** — `--memory` / `--cpus` per box (today the cap is a fixed 512 MiB / 512 tasks).
- **Interactive TTY** (`-it`) — proper PTY allocation for shells and REPLs.
- **Port publishing** (`-p host:box`) — reach a box's listening port (today `--net` is host-only).
- **Quality of life** — restart-on-failure, a health check, friendlier `ps`/`logs` output.

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
