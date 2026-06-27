# Benchmarks

Measured on one machine — 28-core x86_64, Linux 6.17, NVMe, systemd-user — against the runtimes
installed there: **Docker 29.1.3** (daemon up), **Podman 4.9.3** (rootless), **crun 1.28**,
**runc 1.3.3** (rootless), **bubblewrap 0.9**. The workload is `/bin/true` in Alpine with the
**image/rootfs already local**, so this measures *runtime overhead*, not download time. All ran the
same Alpine rootfs (Docker/Podman via their image store; kern/bwrap/crun/runc via the same exported
rootfs directory). This is a 0.x project — treat these as "fast class", not a guarantee.

**Reproduce it yourself.** The three performance tables below — cold start, throughput, and
concurrency — are all produced by one script, [`examples/benchmark.py`](examples/benchmark.py)
(stdlib only, no dependencies). It auto-detects whatever runtimes are installed, pulls the Alpine
rootfs once, and prints the same numbers on your machine:

```sh
python3 examples/benchmark.py                      # cold-start + throughput (200 runs) + concurrency (200 parallel)
KERN=./target/release/kern python3 examples/benchmark.py --runs 500 --conc 100
```

(The remaining sections — real-image, footprint, resource caps — are measured by hand with the
commands shown inline; only those depend on a specific image or a systemd-user manager.)

> **TL;DR.** kern is in the **fastest tier** — it leads the no-cgroup-cap sandboxes (ahead of
> `bubblewrap`), and with a hard cgroup cap it **ties `crun`** (the fastest OCI runtime) and is
> **~2× `runc`** — while being the only one of them that ships a complete daemonless container UX
> (OCI pull, overlay, `ps`/`exec`/`logs`/`top`, compose) in a **~1.5 MB** binary. Against the real
> engines it's **~80–160× faster to start** (`podman` ~155 ms, Docker ~308 ms) and carries no
> resident daemon. It is *not* "the fastest in the world" — the top tier is within a couple ms,
> i.e. noise; the honest claim is **top-tier speed + a full runtime in a tiny daemonless binary**.

## Cold start — one isolated `/bin/true` (time per run = total ÷ 200 sequential runs)

> Reproduce: `python3 examples/benchmark.py` (the per-runtime `median (min–max)` line).

| Runtime | Cold start | What it does at that price |
|---|---:|---|
| **kern** `box --rootfs` | **1.9 ms** | overlay + self-pivot + seccomp |
| bubblewrap | 2.6 ms | a sandbox *primitive* — no images, caps, or lifecycle |
| crun | 5.2 ms | OCI runtime (C): bundle + cgroup setup |
| runc (rootless) | 12.2 ms | OCI runtime (Go): bundle + cgroup (high run-to-run variance) |
| podman (rootless) | 155 ms | daemonless engine: forks `conmon` + the full OCI stack per run |
| **docker run --rm** | 308 ms | client → daemon round-trip |

kern's bare box adds **no** cgroup cap (like bubblewrap); when it *does* add a hard cap the full
path is **~5.5 ms** — see the two-tier note below.

(Measured as total ÷ N over 200 runs, not a per-call timer — at sub-ms scale the timer's own
fork/exec would otherwise dominate. Latency and the throughput numbers below are the same data.)

Two honest tiers. **No cgroup cap** (lightest): kern's bare box leads at **1.9 ms**, ahead of
bubblewrap (2.6 ms) — both skip the cgroup. **With a cgroup cap** (what a real container wants):
kern at **5.5 ms ties `crun`** (5.2 ms — the fastest OCI runtime) and is **~2× faster than
`runc`** (12.2 ms). The physical floor for `unshare`+`exec` is ~1–2 ms, so everyone in the top
tier sits within a couple ms of each other and of each other's run-to-run noise — nobody "wins"
single-shot latency outright. The real gap is to the **engines**: `podman` (~155 ms) and Docker
(~308 ms) fork `conmon` / round-trip a daemon every run, so kern is **~80–160× faster** than the
tools people actually compare it to — while shipping the same UX (OCI pull, overlay,
`ps`/`exec`/`logs`, compose) in ~1.5 MB with no resident daemon.

### Real image, not `/bin/true`

Starting a container of a **real ~30 MB app image** (`ubuntu/apache2`, Apache pre-installed),
same image both sides, warm cache:

| Runtime | Cold start |
|---|---:|
| **kern** `box --image ubuntu/apache2` | **~7 ms** |
| `docker run --rm ubuntu/apache2` | **~320 ms** |

**~40× faster on the image you'd actually serve**, with no resident daemon. (Once the image is
local, a kern box of it is up in single-digit ms; the only slow step is one-time work *inside* the
box like `apt install`, which is the workload, not the runtime.)

> Reproduce (both sides warm — pull once first):
> ```sh
> kern pull ubuntu/apache2 && docker pull ubuntu/apache2
> time kern box web --image ubuntu/apache2 -- true        # KERN_SCOPE=1 to skip the cgroup scope
> time docker run --rm ubuntu/apache2 true
> ```

## Throughput — 200 sequential starts

> Reproduce: `python3 examples/benchmark.py` (the `throughput` column — same data as cold start, `1000 ÷ ms`).

| Runtime | Throughput |
|---|---:|
| **kern** `--rootfs` | **542 runs/s** |
| bubblewrap | 387 runs/s |
| crun | 193 runs/s |
| runc | 82 runs/s |
| **docker run --rm** | **3.2 runs/s** |

kern is **~1.4× bubblewrap, ~2.8× crun, ~6.6× runc**, and **~170× Docker** (which pays a daemon
round-trip per run: 200 runs took ~62 s vs kern's **0.37 s**).

## Concurrency — 200 isolated starts in parallel (wall-clock, all 200/200 succeeded)

> Reproduce: `python3 examples/benchmark.py` (the `Concurrency` block; `--conc 200` is the default).

| Runtime | Wall-clock |
|---|---:|
| **kern** `--rootfs` | **0.07 s** |
| bubblewrap | 0.15 s |
| **docker run --rm** | 18.74 s |

This is where a daemonless, lock-free design shows: kern fans out 200 concurrent boxes in 70 ms —
**~2× bubblewrap** and **~267× Docker**. (kern's overlay path was earlier verified at 30/30 and
many-sharing-one-rootfs at 12/12 — see the test suite.)

## Runs everywhere — the same static binary, on boards where the engines can't

The point isn't a single-shot latency crown — the top tier is noise. It's that **one ~1.5 MB
static aarch64 binary** runs the *same* `kern box` on a desktop, an NVIDIA Jetson, a Raspberry Pi 5,
and an **Android-kernel** board — including hardware where Docker/Podman aren't installed (or
installable) at all. Measured with [`examples/benchmark.py`](examples/benchmark.py) (bare box, time
per run = total ÷ N):

| host | kernel | **kern** | bubblewrap | crun | runc | podman | docker |
|---|---|---:|---:|---:|---:|---:|---:|
| x86_64 desktop | 6.17 | **1.9 ms** | 2.6 ms | 5.2 ms | 12.2 ms | 155 ms | 308 ms |
| Jetson Orin Nano | 5.15-tegra | **3.6 ms** | 5.6 ms | ✗ | 32 ms | ✗ | 472 ms |
| Raspberry Pi 5 | 6.6-rpi | **2.1 ms** | ✗ | ✗ | ✗ | ✗ | ✗ |
| Arduino UNO Q | **6.16 Android** | **9.9 ms** † | 14.9 ms | ✗ | 76 ms | ✗ | 858 ms |

✗ = **not installed (nor readily installable) on that board.** The standout row is the **Raspberry
Pi 5: `kern` is the ONLY runtime that runs at all** — bubblewrap, crun, runc, podman and Docker are
*none of them present*, while one ~1.5 MB static binary just works. That reach — not a single-shot
latency crown — is the differentiator. (Jetson/Arduino had bubblewrap, runc and Docker; crun and
podman weren't installed there either.)

† `--bind-rootfs` on the Arduino; its default overlay path is ~33 ms there (the Android-kernel
overlayfs pathology, see below).

kern is **first on every board** — and the one place it took work is itself the most interesting.
Profiled with `KERN_TIMING=1`, kern's *default* (overlay) startup on the Arduino breaks down as:
overlay mount **~22.8 ms**, everything else (unshare, /dev, pivot, proc, seccomp) **~1.9 ms**
combined. The overlay *mount syscall itself* is the whole gap: on this Android-derived 6.16 kernel
an overlayfs mount takes ~31 ms (vs ~8 ms for a plain bind) — yet only **104 µs on x86** and ~1 ms
on the Pi/Jetson. It's a property of that kernel's overlayfs, not of kern; kern uses an overlay so
the rootfs/image stays immutable and shareable, which is sub-millisecond on every normal kernel and
the reason kern wins outright on the other three boards. For exactly this case, **`--bind-rootfs`**
swaps the overlay for a direct bind — kern then starts in **9.9 ms, beating bubblewrap (14.9 ms)**
while still doing more than it (seccomp, a real `/dev`, lifecycle); the trade-off is a mutable,
shared source, so it's opt-in. Net: one ~1.5 MB binary (one Rust dep, `libc`; system `curl`/`tar` for
OCI pull), no daemon, no per-distro
packaging, **fastest on all four kernels** — and the only runtime present at all on the Pi and the
only one that ships OCI images + caps + `ps`/`exec`/`logs`/compose. That reach is the differentiator.

## Footprint

| | |
|---|---:|
| **kern** binary (the whole thing) | **~1.5 MB** static, stripped (one **Rust** dep, `libc`; OCI pull shells out to system `curl`/`tar`) — musl x86_64 ~1.5 MB, aarch64 ~1.3 MB (release profile: `opt-level=z` + LTO + `panic=abort` + strip) |
| kern resident memory at rest | **0** — no daemon |
| kern RSS per box (setup) | ~7 MB |
| bubblewrap binary | 70 KB (launcher only) |
| runc binary | ~10 MB |
| **Docker** resident | **~186 MB RSS** always on (`dockerd` ~121 MB + `containerd` ~65 MB) |

kern is **~15× smaller than runc** and needs no bundle scaffolding; bwrap is smaller still but is
only a launcher (no images/caps/lifecycle). Docker keeps ~186 MB resident before you run anything.

> Reproduce: `ls -l $(command -v kern)` (binary); `ps -o rss= -C dockerd -C containerd` (Docker
> resident, sum the KB); the per-box RSS is the box pid1's RSS while a box is up.

## Resource caps (where systemd-user is present)

The `--image` path runs inside a transient `systemd-run --user --scope` with `MemoryMax=512M`,
`MemorySwapMax=0`, `TasksMax=512` (verified enforced in the kernel cgroup):

| Test inside the box | Result |
|---|---|
| allocate ~100 MB | runs fine |
| allocate ~700 MB | **OOM-killed** (hard total cap; no swap escape) |
| fork bomb | capped at 512 tasks |

Without a systemd user manager, a best-effort cgroup v2 path applies where the hierarchy is
delegated, else caps are skipped (documented in [SECURITY.md](SECURITY.md)).

> Reproduce (needs systemd-user): start a box with a cap and try to exceed it —
> ```sh
> kern box mem --image alpine --memory 512M -- sh -c 'tr -dc 0 </dev/zero | head -c 700M | wc -c'
> ```
> the allocation is OOM-killed (exit 137); `--memory 100M` with `head -c 100M` runs fine.

## Method

The cold-start, throughput and concurrency tables all come from one self-contained script —
run it and you get the same three tables for whatever runtimes you have installed:

```sh
python3 examples/benchmark.py                 # auto-detect runtimes; 200 runs + 200 parallel
KERN=./target/release/kern python3 examples/benchmark.py --runs 500 --conc 100
```

It warms each runtime once, then reports latency as **total ÷ N** over N sequential runs (at
sub-ms scale a per-call timer's own fork/exec would dominate), throughput as `1000 ÷ ms`, and
concurrency as the wall-clock to fan out `--conc` starts at once. Under the hood it runs exactly
these per-runtime commands (kern with `KERN_SCOPE=1` to skip the cgroup scope, like bwrap):

```sh
kern box b --rootfs $ROOTFS -- /bin/busybox true         # KERN_SCOPE=1 = no cgroup scope
bwrap --unshare-all --bind $ROOTFS / --proc /proc --dev /dev /bin/busybox true
crun run --bundle $BUNDLE b                               # bundle pre-built (runc spec --rootless)
runc run --bundle $BUNDLE b
podman run --rm --network none alpine /bin/true
docker run --rm alpine /bin/true
```

## Honest caveats

- One machine, warm cache, `/bin/true` — a microbenchmark of *startup overhead*, not a workload.
- **kern ties `crun` and is ~2× `runc` as measured** — but the whole top tier hits the same ~1–2 ms
  `unshare`+`exec` floor, so single-shot "wins" are mostly run-to-run noise. The honest claim is
  "fastest tier, complete UX, tiny, daemonless", not "fastest of all".
- The comparison isn't perfectly apples-to-apples: runc's per-run number **excludes** the
  bundle/`config.json` setup it requires up front, whereas kern's `--image` ~7 ms **includes** the
  whole image-overlay + cgroup-cap path.
- Docker does far more (build, networking, volumes, swarm, a huge ecosystem); this compares the
  *cost of starting an isolated process*, where kern's daemonless design wins decisively.
- kern is early (0.x); these numbers are about speed/footprint, not maturity.
