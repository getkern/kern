# Benchmarks

Measured on one machine, 20-core / 28-thread x86_64, Linux 6.17, NVMe, systemd-user, against the runtimes
installed there: **Docker 29.1.3** (daemon up), **Podman 4.9.3** (rootless), **crun 1.28**,
**runc 1.3.3** (rootless), **bubblewrap 0.9**. The workload is `/bin/true` in Alpine with the
**image/rootfs already local**, so this measures *runtime overhead*, not download time. All ran the
same Alpine rootfs (Docker/Podman via their image store; kern/bwrap/crun/runc via the same exported
rootfs directory). This is a 0.x project, treat these as "fast class", not a guarantee.

> **Two numbers, and which one you get depends on whether the box is capped.**
>
> **The box you actually run is capped, and it is twice as fast as it was**: plain `kern box`, no
> environment set, **0.3.0 takes 4.92 ms and v0.6.21 takes 2.45 ms** on this machine today. 0.3.0
> re-execs itself through `systemd-run` for every box (11 `execve` of it per start); v0.6.21 caps
> directly in its own delegated slice and calls it zero times, while the cap still bites (200 MiB
> under `--memory 32m` still exits 137).
>
> **The table below measures an UNCAPPED box**, which is what makes it comparable to bubblewrap, and
> there kern went the other way: 0.3.0 reports **1.7 ms** against v0.6.21's **2.2 ms**, each with the
> benchmark script of its own era, bubblewrap steady at 2.8 and 2.7 as the control. Part of that 0.5
> ms is visible in `KERN_TIMING` and `strace`: v0.6.21 issues **thirteen more `mount` calls**, putting
> `/dev/null` over `/proc/kcore`, `kallsyms`, `kmsg`, `keys`, `latency_stats`, `timer_list`,
> `sched_debug` and `scsi`, remounting `sysrq-trigger`, `irq`, `bus`, `fs` and `asound` read-only, and
> mounting a cgroup2 view, which together close a container escape through `core_pattern`; the seccomp
> filter grew from 79 to 170 us for the same reason. That accounts for about 185 us of it. The rest is
> not attributed, and is recorded as such in [OPEN_ITEMS.md](OPEN_ITEMS.md) rather than explained away.
>
> The single most expensive thing left is not kern's: `unshare(CLONE_NEWNET)` costs **430 us** here
> (503 us for the namespace step with it, 74 us with `--net`), which is 17% of a box start and is the
> price of network isolation.
>
> Measure your own: `kern bench --rootfs <dir>`.

**Reproduce it yourself.** The three performance tables below, cold start, throughput, and
concurrency, are all produced by one script, [`examples/benchmark.py`](examples/benchmark.py)
(stdlib only, no dependencies). It auto-detects whatever runtimes are installed, pulls the Alpine
rootfs once, and prints the same numbers on your machine:

```sh
python3 examples/benchmark.py                      # cold-start + throughput (200 runs) + concurrency (200 parallel)
KERN=./target/release/kern python3 examples/benchmark.py --runs 500 --conc 100
```

(The remaining sections, real-image, footprint, resource caps, are measured by hand with the
commands shown inline; only those depend on a specific image or a systemd-user manager.)

> **TL;DR.** kern is in the **fastest tier**: it leads the no-cgroup-cap sandboxes (ahead of
> `bubblewrap`), and a hard cgroup cap now costs 0.25 ms rather than a `systemd-run` round trip: while being the only one of them that ships a complete daemonless container UX
> (OCI pull, overlay, `ps`/`exec`/`logs`/`top`, compose) in a **~1.8 MB** binary. Against the real
> engines it's **~125× faster to start** (`podman` ~288 ms, Docker ~289 ms) and carries no
> resident daemon. It is *not* "the fastest in the world", the top tier is within a couple ms,
> i.e. noise; the honest claim is **top-tier speed + a full runtime in a tiny daemonless binary**.

## Cold start, one isolated `/bin/true` (time per run = total ÷ 200 sequential runs)

> Reproduce: `python3 examples/benchmark.py` (the per-runtime `median (min-max)` line).

| Runtime | Cold start | What it does at that price |
|---|---:|---|
| **kern** `box --rootfs` | **2.2 ms** | overlay + self-pivot + seccomp |
| **kern** `box --image` | **3.3 ms** | the same, plus the rootless uid-range mapping: two setuid helpers (`newuidmap`/`newgidmap`), ~1.1 ms, run concurrently. A range cannot be written to `/proc/<pid>/uid_map` without `CAP_SETUID`, which a rootless process does not have, so the helpers are not avoidable. It is what lets an official image drop privilege in its entrypoint (postgres, nginx) instead of failing. Opt out with `--no-uid-range`. |
| bubblewrap | 2.9 ms | a sandbox *primitive*, no images, caps, or lifecycle |
| crun | 5.2 ms (June; not installed on the machine re-measured here) | OCI runtime (C): bundle + cgroup setup |
| runc (rootless) | 13.8 ms | OCI runtime (Go): bundle + cgroup (high run-to-run variance) |
| podman (rootless) | 287.5 ms | daemonless engine: forks `conmon` + the full OCI stack per run |
| **docker run --rm** | 289.2 ms | client → daemon round-trip |

kern's bare box adds **no** cgroup cap (like bubblewrap). Adding one used to cost a `systemd-run`
round trip and put the capped path at ~5.5 ms; since 0.6.15 kern caps directly in its own delegated
slice and **the cap costs 0.25 ms**: 2.20 ms uncapped, **2.45 ms with caps on**, 2.49 ms with an
explicit `--memory 512m`. The cap still bites (200 MiB under `--memory 32m` exits 137).

(Measured as total / N over 200 runs, not a per-call timer, at sub-ms scale the timer's own
fork/exec would otherwise dominate. Latency and the throughput numbers below are the same data.)

The two-tier split this section used to describe is gone, and that is the point: you no longer
choose between a fast box and a capped one. kern capped (2.45 ms) is faster than the fastest OCI
runtime measured here uncapped, and the physical floor for `unshare`+`exec` is ~1-2 ms, so the top
tier sits within a couple ms of itself and of its own run-to-run noise. Nobody "wins"
single-shot latency outright. The real gap is to the **engines**: `podman` (~288 ms) and Docker
(~289 ms) fork `conmon` / round-trip a daemon every run, so kern is **~125x faster** than the
engines while shipping the container UX they ship.

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

> Reproduce (both sides warm, pull once first):
> ```sh
> kern pull ubuntu/apache2 && docker pull ubuntu/apache2
> time kern box web --image ubuntu/apache2 -- true        # KERN_NO_SCOPE=1 to skip the cgroup scope
> time docker run --rm ubuntu/apache2 true
> ```

## Throughput, 200 sequential starts

> Reproduce: `python3 examples/benchmark.py` (the `throughput` column, same data as cold start, `1000 ÷ ms`).

| Runtime | Throughput |
|---|---:|
| **kern** `--rootfs` | **542 runs/s** |
| bubblewrap | 387 runs/s |
| crun | 193 runs/s |
| runc | 82 runs/s |
| **docker run --rm** | **3.2 runs/s** |

kern is **~1.4× bubblewrap, ~2.8× crun, ~6.6× runc**, and **~170× Docker** (which pays a daemon
round-trip per run: 200 runs took ~62 s vs kern's **0.37 s**).

## Concurrency, 200 isolated starts in parallel (wall-clock, all 200/200 succeeded)

> Reproduce: `python3 examples/benchmark.py` (the `Concurrency` block; `--conc 200` is the default).

| Runtime | Wall-clock |
|---|---:|
| **kern** `--rootfs` | **0.07 s** |
| bubblewrap | 0.15 s |
| **docker run --rm** | 18.74 s |

This is where a daemonless, lock-free design shows: kern fans out 200 concurrent boxes in 70 ms,
**~2× bubblewrap** and **~267× Docker**. (kern's overlay path was earlier verified at 30/30 and
many-sharing-one-rootfs at 12/12, see the test suite.)

## Runs everywhere, the same static binary, on boards where the engines can't

**These numbers were re-measured on 2026-07-30 and they moved, upward, on every board.** The earlier
table read 2.1 ms on the Pi 5, 3.6 on the Jetson and 9.9 on the Arduino. Re-running it found 11.8, 13.1
and 91.2 on the same hardware. The figures below are the new ones, because a number that does not
reproduce is not a benchmark.

It is **not a regression in kern**, which was the first thing checked: v0.6.9, v0.6.20, v0.6.24 and
v0.6.25 were each benched on the Pi 5 that evening and produced 13.9, 12.0, 11.9 and 11.7 ms. Every
version measures the same today, and the newest is the fastest of the four.

What changed is the boards. All three now have the **memory controller delegated** to the user slice,
which they did not before: on the Pi 5 it had to be turned on with `cgroup_enable=memory` and a reboot,
precisely because `--memory` was accepted and not enforced. Enforcing a cap costs what enforcing a cap
costs. The old figures were taken on hardware that could not enforce one.

Measured with `kern bench --rootfs <dir>` against a warm page cache and after 20 warm-up boxes, the
command the README tells you to run:

| host | kernel | **kern** | bubblewrap | runc | docker |
|---|---|---:|---:|---:|---:|
| x86_64 desktop | v7.0 | **2.2 ms** | 2.9 ms | 13.8 ms | 289.2 ms |
| Raspberry Pi 5 | v6.6-rpi | **11.8 ms** | ✗ | ✗ | ✗ |
| Jetson Orin Nano | v5.15-tegra | **13.1 ms** | 5.5 ms | 32 ms † | 472 ms † |
| Arduino UNO Q | **v6.16 Android** | **91.2 ms** | 14.6 ms | 76 ms † | 858 ms † |

✗ = **not installed (nor readily installable) on that board.** † carried over from the earlier session:
only kern and bubblewrap were re-measured on 2026-07-30.

**bubblewrap is now faster than kern on the two boards where both are installed**, which the earlier
table had the other way round. Said plainly because it is the kind of thing a reader finds in a minute:
bubblewrap does less. It is a sandbox primitive with no images, no caps, no lifecycle and no cgroup work,
and cgroup work is exactly what those boards started charging for.

The claim that survives is the one that was always the point, and it is a reach claim rather than a
latency one: on the **Raspberry Pi 5** kern is the ONLY runtime that runs at all. bubblewrap, crun, runc,
podman and Docker are none of them present, and one static binary copied over just works. On a desktop
kern is in the top tier; on these boards it is the thing that is there.

### Where the milliseconds go, and why they are not waste

Chased down on the Pi 5 the same evening, because a number you cannot explain is a number you cannot
defend.

kern's own instrumented phases sum to about **2 ms** (unshare + idmap 579 us, seccomp 233, overlay 185,
`/dev` 137, pivot 128, the rest smaller) and the box itself lives 2.5 ms. Starting the binary is not the
problem either: `kern --version` takes **481 us** there, faster than `/bin/true` at 519.

The rest is one thing. On that board a box goes through a **systemd transient scope**, and
`systemd-run --user --scope /bin/true` on its own costs **13.7 ms**, against a full `kern box` at 14.3 ms.
The scope is essentially the whole measurement.

It is not overhead that can be dropped. Setting `KERN_NO_SCOPE=1` takes the box from 15.5 ms to 4.1 ms,
and in the same breath `--memory 256m` leaves `memory.max` at `max`, `--pids-limit 30` leaves `pids.max`
at `max`, and a workload 3x over its RAM cap exits 0 instead of 137. On a host with no delegated slice to
write to, **the scope is the enforcement**. The 13.7 ms buys a cap that actually bites, and trading a
kernel boundary for milliseconds is the one trade this project will not make.

That is also why these figures moved: the boards now have the memory controller delegated, so they now
pay for enforcement they previously could not perform.

`KERN_NO_SCOPE=1` remains available for callers that want the speed and accept best-effort caps, and
since this release it **says so** rather than accepting a cap it will not enforce.

## Footprint

| | |
|---|---:|
| **kern** binary (the whole thing) | **~1.8 MB** static, stripped (one **Rust** dep, `libc`; OCI pull shells out to system `curl`/`tar`), musl x86_64 ~1.8 MB, aarch64 ~1.3 MB (release profile: `opt-level=z` + LTO + `panic=abort` + strip) |
| kern resident memory at rest | **0**: no daemon |
| kern RSS per box (setup) | ~7 MB |
| bubblewrap binary | 70 KB (launcher only) |
| runc binary | ~10 MB |
| **Docker** resident | **~186 MB RSS** always on (`dockerd` ~121 MB + `containerd` ~65 MB) |

kern is **~6× smaller than runc** (1.8 MB vs ~10 MB) and needs no bundle scaffolding; bwrap is
smaller still but is only a launcher (no images/caps/lifecycle). Docker keeps ~186 MB resident
before you run anything.

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

> Reproduce (needs systemd-user): start a box with a cap and try to exceed it,
> ```sh
> kern box mem --image alpine --memory 512M -- sh -c 'tr -dc 0 </dev/zero | head -c 700M | wc -c'
> ```
> the allocation is OOM-killed (exit 137); `--memory 100M` with `head -c 100M` runs fine.

## Method

Not every figure quoted in the README lives here, on purpose. The day-to-day operations table
(`exec`, `ps`, `logs`, bringing a stack up) is measured differently, by typing the commands and
timing them with the shell, so it lives next to that claim in
[README.md § A working day, not a cold start](README.md#a-working-day-not-a-cold-start) with its own
reproduction line. Copying those numbers into this file would give each of them two homes, and two
homes is how a number drifts.

The cold-start, throughput and concurrency tables all come from one self-contained script,
run it and you get the same three tables for whatever runtimes you have installed:

```sh
python3 examples/benchmark.py                 # auto-detect runtimes; 200 runs + 200 parallel
KERN=./target/release/kern python3 examples/benchmark.py --runs 500 --conc 100
```

It warms each runtime once, then reports latency as **total ÷ N** over N sequential runs (at
sub-ms scale a per-call timer's own fork/exec would dominate), throughput as `1000 ÷ ms`, and
concurrency as the wall-clock to fan out `--conc` starts at once. Under the hood it runs exactly
these per-runtime commands (kern with `KERN_NO_SCOPE=1` to skip the cgroup scope, like bwrap):

```sh
kern box b --rootfs $ROOTFS -- /bin/busybox true         # KERN_NO_SCOPE=1 = no cgroup scope
bwrap --unshare-all --bind $ROOTFS / --proc /proc --dev /dev /bin/busybox true
crun run --bundle $BUNDLE b                               # bundle pre-built (runc spec --rootless)
runc run --bundle $BUNDLE b
podman run --rm --network none alpine /bin/true
docker run --rm alpine /bin/true
```

## Honest caveats

- One machine, warm cache, `/bin/true`, a microbenchmark of *startup overhead*, not a workload.
- **kern ties `crun` and is ~2× `runc` as measured**: but the whole top tier hits the same ~1-2 ms
  `unshare`+`exec` floor, so single-shot "wins" are mostly run-to-run noise. The honest claim is
  "fastest tier, complete UX, tiny, daemonless", not "fastest of all".
- The comparison isn't perfectly apples-to-apples: runc's per-run number **excludes** the
  bundle/`config.json` setup it requires up front, whereas kern's `--image` ~7 ms **includes** the
  whole image-overlay + cgroup-cap path.
- Docker does far more (build, networking, volumes, swarm, a huge ecosystem); this compares the
  *cost of starting an isolated process*, where kern's daemonless design wins decisively.
- kern is early (0.x); these numbers are about speed/footprint, not maturity.
