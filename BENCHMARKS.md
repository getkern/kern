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
| bubblewrap | 3.0 ms | a sandbox *primitive*, no images, caps, or lifecycle |
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
| x86_64 desktop | v7.0 | **2.2 ms** | 3.0 ms | 13.8 ms | 289.2 ms |
| Raspberry Pi 5 | v6.6-rpi | **11.8 ms** | ✗ | ✗ | ✗ |
| Jetson Orin Nano | v5.15-tegra | **13.1 ms** | 5.5 ms | 32 ms † | 472 ms † |
| Arduino UNO Q | **v6.16 Android** | **93.2 ms** | 14.4 ms | 76 ms † | 858 ms † |

✗ = **not installed (nor readily installable) on that board.** † carried over from the earlier session:
only kern and bubblewrap were re-measured on 2026-07-30.

**On the two boards where both are installed, bubblewrap's number is now lower than kern's**, which the
earlier table had the other way round. Said plainly, because it is the kind of thing a reader finds in a
minute. But the two columns are not the same work, and the like-for-like measurement says the opposite.

bubblewrap is a sandbox primitive: no images, no lifecycle, and **no resource caps at all**, so it never
does cgroup work. kern's board figures include enforcing caps through a systemd transient scope, which is
what those boards started charging for. Measured on the x86 desktop where every tool is installed and kern
can use its direct cgroup path, 40 runs each after a warm-up:

| | ms per box | what it does at that price |
|---|---:|---|
| **kern**, memory cap ENFORCED | **2.6** | `memory.max` reads 268435456, verified in the same run |
| kern, cgroup off | 2.8 | same isolation, no cap |
| bubblewrap | 3.1 | no cap, and no way to ask for one (same series as the two rows above) |

**kern enforcing a memory limit is faster than bubblewrap enforcing nothing.**

The board gap is not the engine, and a third kernel settles it. Inside WSL2 there is no `systemd-run` at
all, so the scope is not even possible, and a box there costs **4.2 ms with the cap enforced**
(`memory.max` read back as 268435456 in the same run). Setting `KERN_NO_SCOPE=1` changes nothing there,
5.1 ms, because the direct path was already the one in use.

| where | ms per box | caps enforced | path |
|---|---:|---|---|
| x86_64 desktop | **2.6** | yes | direct |
| WSL2 | **4.2** | yes | direct, no systemd present at all |
| Raspberry Pi 5 | **17.1** | yes | systemd transient scope |
| Raspberry Pi 5, cgroup off | 3.7 | **no** | none |
| Jetson Orin Nano, cgroup off | 5.5 | **no** | none |
| Arduino UNO Q, cgroup off, `--bind-rootfs` | 12.4 | **no** | none |

And against bubblewrap at the same level of work, which is the only comparison that means anything since
bubblewrap has no caps to enforce:

| board | kern, cgroup off | bubblewrap | |
|---|---:|---:|---|
| Jetson Orin Nano | **5.5 ms** | 6.0 ms | kern |
| Arduino UNO Q, `--bind-rootfs` | **12.4 ms** | 14.4 ms | kern |
| x86_64 desktop, kern's caps ON | **2.6 ms** | 3.1 ms | kern, while doing more |

`--bind-rootfs` matters on the Arduino and nowhere else: `KERN_TIMING=1` puts **22.4 ms** in the overlay
mount alone on that Android kernel, against ~0.1 ms on x86. It takes that board from 93.2 ms to **65.4**
with caps enforced, and to 12.4 with the cgroup off. Every board row above is the DEFAULT path, so the
boards are compared with each other rather than each with its own best flag. bubblewrap binds rather than overlays, so
comparing kern's default overlay to it there compares two different mount strategies, not two runtimes.
With the same strategy kern is ahead.

### Why a headless board pays it, and what to do about it

Chased to the bottom the same night, because "the boards are slower" is not an explanation.

kern reaches its fast path by finding the systemd user manager's delegated slice. Rootless, that lives
under `/user.slice/user-<uid>.slice/user@<uid>.service/`. **An SSH session does not live there**: it is
placed in `/user.slice/user-<uid>.slice/session-N.scope` by the SYSTEM manager, a different delegation
domain, and a process there cannot write into the user manager's tree. So every box from an SSH shell
falls back to a per-box transient scope.

The size of that, measured on a Pi 5 with one binary at one moment:

| how kern was launched | ms per box | caps enforced |
|---|---:|---|
| from an SSH session | **13.8** | yes |
| from inside the systemd user manager | **3.5** | yes |

Same binary, same board, same image, `memory.max` reading 268435456 in both. **A 4x difference decided
purely by where the calling shell sits.**

It is not a bug kern can route around, and trying was instructive: making it locate the slice by
constructed path instead of by walking its own ancestors does let it *find* one, and then the box refuses
to start, because finding a delegated cgroup you are not inside is not the same as being able to use it.
kern's fail-closed check catches that and refuses rather than running an uncapped box, which is the
behaviour you want and the reason the attempt was caught in minutes rather than shipped.

**So if you run boxes on a headless board and care about the milliseconds, launch kern from a systemd
user service rather than straight from an SSH shell.** `systemd-run --user`, or a small unit, is enough,
and it is 4x. If you are on a desktop session the fast path is already what you get.

So: **wherever kern can take the direct cgroup path, a box costs 2.6 to 4.2 ms with limits enforced.** The
boards' 12 to 15 ms is the `systemd-run` round trip in full, which kern falls back to because it obtains
no delegated slice there. That is a fallback, not the engine, and making the direct path reachable on such
a host is the obvious next thing to try: it would put those boards back near 4 ms without giving up a
single cap.

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

## Windows: where the milliseconds go

Every figure above is a Linux host. On Windows kern runs inside its own WSL2 distro, and a command
typed on the Windows side crosses the VM boundary by spawning `wsl.exe` **once per command**. That
crossing is not kern's work and it dwarfs kern's work, so the honest reading is that Windows has two
different performance stories depending on where you type.

Two Windows 11 hosts, because one of them cannot measure the row that matters most. 20 boxes of the same
cached image per sample, `kern box --image alpine` against a warm cache:

| where you type | ms per box | processes added per command | host |
|---|---:|---|---|
| inside the distro (`wsl -d kern`, then `kern ...`) | **6.5** and **7.0** | none | both |
| Windows, via `kern.exe` | **70.5** | 1 (`wsl.exe`) | B |
| Windows, via the `kern.cmd` fallback | **~330-500** | 2 (`cmd.exe`, then `wsl.exe`) | A |

**Host A** runs Malwarebytes with real-time scanning, which deletes or blocks the unsigned `kern.exe`
within seconds of every download: the exe row cannot be measured there at all, which is precisely why the
fallback exists. **Host B** runs only Defender, the exe survives, and it supplies that row. The inside-WSL
figure is the one both hosts produce, and they agree: **6.5** and **7.0** ms.

So the Windows-side crossing costs about **63 ms per command** with the exe, on the host where it could be
measured. The fallback row is several times that, but it is a different host as well as a second process,
so the gap is not the price of the batch wrapper alone.

The comparable Linux figure is the **3.3 ms** OCI-image row above, not the 2.2 ms prepared-rootfs one. The
inside-WSL numbers are 20 boxes in 0.13 s, one series each, timed in the distro with `time` around the
whole loop so the shell's 10 ms resolution lands on the total rather than on each box: single samples, not
distributions.

The fallback row read 507 ms then 330 ms on two runs, so read it as "a few hundred", not as a figure. It
is timed from PowerShell, where each box is a separate Windows command and an antivirus scans every
process creation, both of which are in the number.

Two things this table does *not* say. It is silent on the normal `kern.exe` bridge, which adds one
process instead of two: on the machine above the antivirus deleted the unsigned exe within seconds of
every download, five times, so the row could not be measured there and is not guessed here.

And the WSL2 9p bridge did not show up in box startup, which was worth checking rather than assuming.
The same 20-box loop run with the working directory on `/mnt/c` took the same 0.13 s as from `~` inside the
distro: kern reads its image cache inside the distro's own filesystem, so where the shell happens to be
standing costs nothing.

Read that narrowly, because it is one comparison and the mechanism is specific. What was measured is the
**working directory** on 9p. A `-v` mount whose source is under `/mnt/c`, or an image cache relocated
there, crosses 9p on every read and would not behave the same: that case was not measured and nothing here
says it is free. An earlier draft of this section asserted the opposite of the measurement, which is why
the scope is spelled out.

So: on Windows, run kern inside the distro, where a box costs 6.5 ms. The bridge is for the occasional
command from a PowerShell you are already in, not for a loop that starts hundreds of boxes. The
`kern.cmd` row exists because an antivirus removing the exe should not leave you with nothing; it
preserves the *function*, not the speed.

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
