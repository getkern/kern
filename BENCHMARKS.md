# Benchmarks

Re-measured 2026-08-01 at **kern 0.6.30** on one machine: Intel i7-14700KF, 28 threads, **Linux
7.0.0**, NVMe, systemd-user with `cpu memory pids` delegated.

**The CPU governor does not move these numbers, and that is measured on both sides rather than
argued.** The machine runs `intel_pstate`, where `powersave` is dynamic scaling to turbo under load
and not a low-frequency mode. Sampling every core every 50 ms during box starts, the core running
kern sits at a median of **5501 MHz under `powersave` and 5505 under `performance`**, against a
5500 MHz ceiling: it is at full turbo either way. Running the identical benchmark under both:

| | `powersave` | `performance` |
|---|---:|---:|
| `box --rootfs` uncapped | 2.22 ms | 2.22 ms |
| `box --rootfs` capped | 2.30 ms | 2.44 ms |
| `box --image` | 3.46 ms | 3.44 ms |

The differences are inside the run-to-run spread, which is 0.02 to 0.09 ms over five independent
batches of 200. Quote the frequency a machine reaches, not the name of its governor: a reader whose
CPU does not reach its ceiling has a real reason to expect different numbers, and the governor name
alone never told them that. Against the runtimes installed on
it: **Docker 29.1.3** (daemon up), **Podman 4.9.3** (rootless), **runc 1.3.3** (rootless),
**bubblewrap 0.9**. `crun` is NOT installed here; its row below is from June and says so. The workload is `/bin/true` in Alpine with the
**image/rootfs already local**, so this measures *runtime overhead*, not download time. All ran the
same Alpine rootfs (Docker/Podman via their image store; kern/bwrap/crun/runc via the same exported
rootfs directory). This is a 0.x project, treat these as "fast class", not a guarantee.

> **Two numbers, and which one you get depends on whether the box is capped.**
>
> Recorded when **v0.6.21** was current, and kept as the record it is rather than restated as though it
> were today's measurement.
>
> **The box you actually run is capped, and it was twice as fast as it had been**: plain `kern box`, no
> environment set, **0.3.0 took 4.92 ms and v0.6.21 took 2.45 ms** on this machine. 0.3.0 re-execs itself
> through `systemd-run` for every box (11 `execve` of it per start); v0.6.21 caps directly in its own
> delegated slice **where that slice is reachable** and calls it zero times, while the cap still bites
> (200 MiB under `--memory 32m` still exits 137). Where it is not reachable, notably from an SSH session
> or on the ARM boards, the `systemd-run` path is still what runs and still costs what it costs, which is
> the subject of [Why a headless board pays it](#why-a-headless-board-pays-it-and-what-to-do-about-it).
>
> **The table below measures an UNCAPPED box**, which is what makes it comparable to bubblewrap, and
> there kern went the other way: 0.3.0 reported **1.7 ms** against v0.6.21's **2.2 ms**, each with the
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
> `bubblewrap`), and a hard cgroup cap costs **0.19 ms** rather than a `systemd-run` round trip: while being the only one of them that ships a complete daemonless container UX
> (OCI pull, overlay, `ps`/`exec`/`logs`/`top`, compose) in a **~1.8 MB** binary. Against the real
> engines it's **~120× faster to start** (2.44 ms against Docker's 292.5 and `podman`'s 289.0, the
> table below; ~81× if you compare the `--image` path's 3.61 ms, which does more) and carries no
> resident daemon. It is *not* "the fastest in the world", the top tier is within a couple ms,
> i.e. noise; the honest claim is **top-tier speed + a full runtime in a tiny daemonless binary**.

## Cold start, one isolated `/bin/true` (time per run = total ÷ 200 sequential runs)

> Reproduce: `python3 examples/benchmark.py` (the per-runtime `median (min-max)` line).

| Runtime | Cold start | What it does at that price |
|---|---:|---|
| **kern** `box --rootfs`, uncapped | **2.44 ms** | overlay + self-pivot + seccomp. Uncapped is what makes it comparable to bubblewrap |
| **kern** `box --rootfs`, capped (the default) | **2.63 ms** | the same, plus a real cgroup cap: +0.19 ms |
| **kern** `box --bind-rootfs` | 2.49 ms | no overlay, the source is shared and mutable |
| **kern** `box --image` | **3.61 ms** (2.65 with `--no-uid-range`) | the same, plus the rootless uid-range mapping: two setuid helpers (`newuidmap`/`newgidmap`), ~1.1 ms, run concurrently. A range cannot be written to `/proc/<pid>/uid_map` without `CAP_SETUID`, which a rootless process does not have, so the helpers are not avoidable. It is what lets an official image drop privilege in its entrypoint (postgres, nginx) instead of failing. Opt out with `--no-uid-range`. |
| bubblewrap | 2.8 ms | a sandbox *primitive*, no images, caps, or lifecycle |
| crun | 5.2 ms (June; not installed on the machine re-measured here) | OCI runtime (C): bundle + cgroup setup |
| runc (rootless) | 14.6 ms | OCI runtime (Go): bundle + cgroup (high run-to-run variance) |
| podman (rootless) | 289.0 ms | daemonless engine: forks `conmon` + the full OCI stack per run |
| **docker run --rm** | 292.5 ms | client → daemon round-trip |

kern's bare box adds **no** cgroup cap (like bubblewrap). Adding one used to cost a `systemd-run`
round trip and put the capped path at ~5.5 ms; since 0.6.15 kern can cap directly in its own delegated
slice, and **there the cap costs 0.19 ms**: 2.44 ms uncapped, **2.63 ms with caps on**, both measured
today over 200 runs x 5 batches. Adding `--memory 64m --cpus 1 --pids-limit 64` on the `--image` path
costs 0.52 ms (3.61 to 4.13). The cap still bites (200 MiB under `--memory 32m` exits 137; on the Arduino UNO Q's Android kernel the same write is stopped with 143/SIGTERM rather than 137/SIGKILL, with `memory.max` read back as 33554432 either way).

⚠️ **"There" is doing work in that sentence.** The direct slice is reachable only when kern runs inside
the systemd user manager's tree, which a desktop session gives you and an **SSH session does not**: a
login session is placed under the SYSTEM manager, in a different delegation domain. Where the direct path
is out of reach kern falls back to a per-box transient scope, and that costs **9.4 ms** rather than
0.25 on a Raspberry Pi 5. Same binary, same caps enforced either way. This paragraph used to state the
0.25 ms as though it held everywhere; it holds where the path is reachable.
[Why a headless board pays it](#why-a-headless-board-pays-it-and-what-to-do-about-it) has the numbers and
the one-line way to get the fast path back.

(Measured as total / N over 200 runs, not a per-call timer, at sub-ms scale the timer's own
fork/exec would otherwise dominate. Latency and the throughput numbers below are the same data.)

The two-tier split this section used to describe is gone, and that is the point: you no longer
choose between a fast box and a capped one. kern capped (2.45 ms) is faster than the fastest OCI
runtime measured here uncapped, and the physical floor for `unshare`+`exec` is ~1-2 ms, so the top
tier sits within a couple ms of itself and of its own run-to-run noise. Nobody "wins"
single-shot latency outright. The real gap is to the **engines**: `podman` (~288 ms) and Docker
(~292 ms) fork `conmon` / round-trip a daemon every run, so kern is **~120x faster** than the
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
| **kern** `--rootfs` (uncapped) | **410 runs/s** |
| bubblewrap | 357 runs/s |
| runc | 68 runs/s |
| podman (rootless) | 3.5 runs/s |
| **docker run --rm** | **3.4 runs/s** |

kern is **~1.1× bubblewrap** and **~6× runc**, and **~120× Docker**, which pays a daemon round-trip
per run.

These are `1000 / ms` applied to the cold-start table above, and that is now literally true. It was
not before: this table used to read 542, 387 and 82 runs/s, which imply 1.85, 2.58 and 12.2 ms, none
of which are the numbers printed one section up. Three of its five rows came from an earlier, faster
session while the sentence above them claimed "same data as cold start". Both tables now come from
one run of `examples/benchmark.py` on 2026-08-01.

## Concurrency, 200 isolated starts in parallel (wall-clock, all 200/200 succeeded)

> Reproduce: `python3 examples/benchmark.py` (the `Concurrency` block; `--conc 200` is the default).

| Runtime | Wall-clock |
|---|---:|
| **kern** `--rootfs` | **0.10 s** |
| bubblewrap | 0.15 s |
| runc | 0.31 s |
| **docker run --rm** | 16.21 s |
| podman (rootless) | 41.93 s |

This is where a daemonless, lock-free design shows: kern fans out 200 concurrent boxes in 100 ms,
**~1.5× bubblewrap** (0.15 s) and **~162× Docker** (16.21 s). Every runtime completed 200/200.

**It keeps scaling past the point the table stops.** Measured in the same session:

| kern boxes at once | wall-clock | succeeded | rate |
|---:|---:|---:|---:|
| 200 | 0.10 s | 200/200 | 1970 box/s |
| 500 | 0.31 s | 500/500 | 1613 box/s |
| 1000 | 0.61 s | 1000/1000 | 1640 box/s |

A thousand simultaneous kernel-isolated boxes in 0.61 s, none refused, on a 28-core desktop. The rate
is flat from 500 to 1000, so the limit at this size is the machine rather than anything serialising
inside kern. (The overlay path was earlier verified at 30/30 and many-sharing-one-rootfs at 12/12,
see the test suite.)

## Runs everywhere, the same static binary, on boards where the engines can't

**Re-measured twice on 2026-07-30.** The table shipped before that day read 2.1 ms on the Pi 5, 3.6 on
the Jetson and 9.9 on the Arduino. A first re-run found 11.8, 13.1 and 91.2. A second round late the same
night, after a defect was found in the benchmark command itself (below), produced the figures here. A
number that does not reproduce is not a benchmark, so what follows is one round, taken end to end in a
single sitting, with nothing carried in from the others except where a row says so.

**The benchmark command had a defect, and it mattered on exactly one board.** `kern bench --bind-rootfs`
accepted the flag and dropped it, so every "bind" figure ever quoted from `kern bench` was an overlay
figure under a bind label. On the Arduino UNO Q, whose Android kernel spends 22.4 ms in the overlay mount
alone against ~0.1 ms on x86, that is the difference between 33.5 ms and 9.6. Fixed, with a test that
asserts the parsed command rather than the exit code, since the old code also exited 0.

It is **not a regression in kern**, which was the first thing checked: v0.6.9, v0.6.20, v0.6.24 and
v0.6.25 were each benched on the Pi 5 that evening and produced 13.9, 12.0, 11.9 and 11.7 ms. The newest
is the fastest of the four. Those four are comparable with EACH OTHER and not with the tables below: they
were taken in one sitting before the boards were reset. What they establish is the ordering across
versions, which is the only thing a regression check needs.

What changed is the boards. All three now have the **memory controller delegated** to the user slice,
which they did not before: on the Pi 5 it had to be turned on with `cgroup_enable=memory` and a reboot,
precisely because `--memory` was accepted and not enforced. Enforcing a cap costs what enforcing a cap
costs. The old figures were taken on hardware that could not enforce one.

Measured with `kern bench --rootfs <dir>`, the command the README tells you to run, three repeats per
cell against a warm page cache on an idle host, median of medians. Every kern row had `memory.max` read
back as 268435456 from inside a box in the same session:

| host | kernel | **kern** | bubblewrap | runc | docker |
|---|---|---:|---:|---:|---:|
| x86_64 desktop | v7.0 | **2.6 ms** | 2.9 ms | 13.8 ms † | 292.9 ms † |
| Raspberry Pi 5 | v6.6-rpi | **11.8 ms** | ✗ | ✗ | ✗ |
| Jetson Orin Nano | v5.15-tegra | **12.5 ms** | 5.6 ms | 32 ms † | 472 ms † |
| Arduino UNO Q | **v6.16 Android** | **91.5 ms** | 15.0 ms | 76 ms † | 858 ms † |

✗ = **not installed on that board**, checked one binary at a time: on the Pi 5, docker, podman, runc,
crun, bwrap, nerdctl, lxc-start and systemd-nspawn are all absent. † carried over from an earlier
session: only kern and bubblewrap were measured in this round.

**On the two boards where both are installed, bubblewrap's number is lower than kern's.** Said plainly,
because it is the kind of thing a reader finds in a minute. The two columns are not the same work, and
the like-for-like measurement says the opposite.

bubblewrap is a sandbox primitive: no images, no lifecycle, and **no resource caps at all**, so it never
does cgroup work. kern's board figures include enforcing caps through a systemd transient scope, which is
what those boards started charging for.

### The scope is the whole gap, and the arithmetic closes

Not an explanation offered, one measured. `systemd-run --user --scope /bin/true` was timed on its own,
20 runs, beside kern's capped and uncapped box on the same host in the same session:

| host | kern, caps ON | kern, cgroup off | difference | `systemd-run --scope` alone |
|---|---:|---:|---:|---:|
| x86_64 desktop | 2.6 | 2.3 | 0.3 | 4.2 (**not paid**: direct path) |
| Raspberry Pi 5 | 11.8 | 2.7 | 9.2 | 9.4 |
| Jetson Orin Nano | 12.5 | 4.1 | 9.3 | 9.0 |
| Arduino UNO Q | 91.5 | 33.5 | 58.2 | 59.9 |

⚠️ **`kern doctor` reports a SMALLER number for the same board, and the two are not the same quantity.**
This column times `systemd-run --user --scope /bin/true` on its own: 59.9 ms on the Arduino. doctor
times the same command but reports it as a FLOOR ("at least 39 ms"), because a box does not merely
create the scope, it re-execs kern inside it. Reconcile against the DIFFERENCE column, never against
doctor's floor: 58.2 measured here against 59.9 standalone is what closes.

On all three boards the difference and the standalone scope agree to within 1.7 ms. The x86 row is the
control and it is the interesting one: the scope costs 4.2 ms there too, and kern does not pay it,
because it caps directly in its own delegated slice for 0.3 ms instead.

WSL2 is the third kernel that settles it: there is no `systemd-run` at all, so the scope is not even
possible, and a box costs **3.4 ms with the cap enforced** (3.0 with `KERN_NO_SCOPE=1`, which changes
nothing there because the direct path was already the only one). Re-measured on 2026-07-31 on the same
Windows 11 host, with `memory.max` read back as 268435456 and 200 MiB under `--memory 32m` exiting 137
in the same run. The 4.2 ms this table used to quote was an earlier round; the newer figure is faster
and it is the one that reproduces.

### The toll is avoidable, and that is the headline

The scope is paid because an SSH login sits under the SYSTEM systemd manager while kern's delegated
`kern.slice` lives under the USER manager, and cgroup v2 refuses to migrate a process across that
boundary. Verified on the UNO Q rather than assumed: creating a cgroup under `kern.slice` succeeds,
writing `memory.max` into it succeeds, writing the pid into `cgroup.procs` is **refused**, because the
common ancestor `user-<uid>.slice` is not the user's to write. So kern's per-box fallback is correct.

What it is not is unavoidable. Enter the user manager's tree ONCE and every box after it takes the
direct path, with the caps still enforced (`memory.max` read back as 268435456 in every cell below):

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

Eight times faster on the Arduino, four on the Pi, all with caps live. `kern doctor` now measures the
toll on the host in front of you and prints that command, rather than leaving it to be discovered.

**And it settles the bubblewrap comparison on the boards, not just on x86.** kern *enforcing a memory
limit* against bubblewrap enforcing nothing: **4.2 ms vs 5.6** on the Jetson, **11.3 vs 15.0** on the
Arduino. kern is ahead on every host where both are installed, while doing strictly more.

### Why the Arduino is still the slowest, chased to the bottom

Its remaining cost is one thing: **`mount -t overlay` takes 22 ms on that Android kernel**, against
~0.1 ms on x86. Everything else in a box there sums to about 7 ms. The 22 ms is a FIXED cost, which is
what makes it interesting:

- identical with a 517-file lowerdir and with an **empty** one, so it is not the image;
- identical with everything on ext4 and with everything on tmpfs, so it is not the storage;
- five consecutive mounts inside one namespace landed within **0.4 ms** of each other;
- `overlay` is already in `/proc/modules`, so it is not an autoload;
- a **tmpfs** mount in the same namespace costs 6.1 ms against overlay's 28.2, so it is not `mount()`
  in general.

A cost that ignores both the content and the backing store is not work being done. kern cannot make
that kernel faster. `--bind-rootfs` skips the mount entirely and is why the Arduino column above drops
from 35.5 to 11.3, but it binds the source directly: mutable and shared between boxes, where the
overlay root is per-box and leaves the source untouched. That is a trade to make deliberately, so
`kern doctor` states it instead of choosing for you.

### At the same level of work

bubblewrap binds rather than overlays, so `--bind-rootfs` is the like-for-like flag: comparing kern's
default overlay against it compares two mount strategies, not two runtimes.

| board | kern, cgroup off, `--bind-rootfs` | bubblewrap | |
|---|---:|---:|---|
| x86_64 desktop | **2.2 ms** | 2.9 ms | kern |
| Raspberry Pi 5 | **2.3 ms** | not installed | |
| Jetson Orin Nano | **3.5 ms** | 5.6 ms | kern |
| Arduino UNO Q | **9.6 ms** | 15.0 ms | kern |

**kern is ahead of bubblewrap on every host where both are installed, at the same level of work.** And on
x86, where kern reaches its direct cgroup path, kern *enforcing a memory limit* is 2.6 ms against
bubblewrap's 2.9 enforcing nothing.

`--bind-rootfs` is worth reaching for only on the Arduino: it takes that board from 91.7 ms to 69.2 with
caps enforced and from 33.5 to 9.6 with the cgroup off, against a few tenths of a millisecond everywhere
else. Every row in the first table is the DEFAULT path, so the boards are compared with each other rather
than each with its own best flag.

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
`systemd-run --user --scope /bin/true` on its own costs **9.4 ms**, against a full `kern box` at 11.9 ms.
The scope is essentially the whole measurement.

It is not overhead that can be dropped. Setting `KERN_NO_SCOPE=1` takes the box from 11.9 ms to 2.7 ms,
and in the same breath `--memory 256m` leaves `memory.max` at `max`, `--pids-limit 30` leaves `pids.max`
at `max`, and a workload 3x over its RAM cap exits 0 instead of 137. On a host with no delegated slice to
write to, **the scope is the enforcement**. The 9.4 ms buys a cap that actually bites, and trading a
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

The comparable Linux figure is the **3.6 ms** OCI-image row above, not the 2.2 ms prepared-rootfs one. The
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

## What a published port costs, on a real application

`kern box -p H:B` forks a process that copies bytes both ways in userspace, so every byte of every
request crosses it. Measured with **nginx**, not `/bin/true`, both against the same image: once behind
`-p` on an isolated netns, and once over `--net` where nginx binds the host port directly and there is
no pump at all. The difference is the pump.

| kept-alive connections | through `-p` | direct (`--net`) |
|---:|---:|---:|
| 1 | 12,479 req/s | 12,037 |
| 4 | 19,605 | 17,019 |
| 16 | 19,425 | 17,185 |
| 32 | 18,364 | 17,623 |

| | through `-p` | direct |
|---|---:|---:|
| p99, 1 connection | 0.27 ms | 0.19 ms |
| bandwidth, 32 MiB body | 1195 MB/s | 1250 MB/s |
| a FRESH connection per request, 16 conc. | 10,085 req/s | 10,113 |

Publishing is therefore close to free on this machine: within noise on request rate, 4% on bandwidth,
and 0.08 ms of p99. A fresh connection per request costs the same either way, because there the cost
is the TCP handshake and nginx's own accept path, not the pump.

⚠️ **These are the numbers after a 0.6.30 fix, and before it they were not close to free.** Neither
side of the pump set `TCP_NODELAY`, so a response written as headers-then-body waited on the peer's
40 ms delayed-ACK timer, and only on a REUSED connection. The same nginx measured **59 req/s on one
keep-alive connection with p99 pinned at 42.0 ms**, while opening a fresh connection per request gave
2614/s. Bandwidth was unaffected throughout, 1195 MB/s, which is exactly why it went unnoticed: a
benchmark that downloads one large file through a published port sees nothing wrong.

## What a published port costs at scale, and on a protocol that is not HTTP

The forwarder forks **one process per accepted connection**, which each `setns` into the box. Nobody
had measured what that costs when the connections are real and many, so:

**Connections held open at once** (nginx behind `-p`, each client keeps its connection):

| held open | forwarder processes | RSS | PSS | per connection |
|---:|---:|---:|---:|---:|
| 0 | 3 | 6.1 MB | 1.7 MB | |
| 200 | 203 | 266.9 MB | 11.9 MB | **52.9 kB** PSS |
| 500 | 503 | 658.3 MB | 27.2 MB | 52.3 kB |
| 1000 | 1003 | 1310.7 MB | 52.6 MB | 52.2 kB |

Read the PSS column. RSS says 1336 kB per connection and that is the same double-counting as the
per-box row above: every child is the same static binary, so its pages are charged to each of them.
The marginal cost of one more open connection is **52 kB and one PID**. Closing them all returns
exactly to 3 processes and 1.7 MB, with nothing left behind.

The ceiling is the PID limit rather than memory: `RLIMIT_NPROC` is 115,919 on this host, so the
design runs out of processes long before it runs out of RAM. A service expecting six-figure
simultaneous connections wants `--net` or a pod, not `-p`.

**Connections opened and closed as fast as possible** (one request each, then closed):

| opened at once | completed | wall | rate | p99 |
|---:|---:|---:|---:|---:|
| 100 | 100/100 | 0.02 s | 4940 conn/s | 1.45 ms |
| 500 | 500/500 | 0.09 s | 5393 conn/s | 1.46 ms |
| 1000 | 1000/1000 | 0.19 s | 5277 conn/s | 1.72 ms |
| 2000 | 2000/2000 | 0.37 s | 5352 conn/s | 1.76 ms |

Nothing was refused and the rate is flat, so the fork per connection is not the bottleneck at this
size. Sampling every 5 ms during 300 of these never caught more than one extra process alive: the
children finish faster than they can be counted.

**Redis, which is the shape HTTP is not**: strict request/response on one persistent connection,
3000 SET+GET round trips.

| | ops/s | p50 | p99 |
|---|---:|---:|---:|
| behind `-p` | 71,606 | 0.027 ms | 0.03 ms |
| direct, `--net` | 124,992 | 0.016 ms | 0.02 ms |

The pump costs about **11 us per round trip**, which on a protocol this fast is 43% of throughput. It
is invisible on HTTP, where a request costs far more than 11 us, and it is the reason to reach for a
pod or `--net` when the workload is a chatty database rather than a web server.

## `kern run` costs 4.9 ms and `kern box` costs 3.6, which looks backwards

`run` does LESS than `box`, no namespaces, no overlay, no seccomp, and measures slower. Both figures
are real, and the asymmetry is structural rather than a defect. Measured 2026-08-01, 200 runs x 3:

| | ms/run | what the cap does |
|---|---:|---|
| `kern run -- /bin/true` | 4.70 | still capped: `memory.max` 512 MiB, `pids.max` 512 |
| `kern run --memory 64m` | 4.88 | |
| `kern run --cpus 1` | 5.78 | a `CPUQuota` property costs ~0.9 ms more than a memory one |
| `kern run --memory 64m` with `KERN_NO_SCOPE=1` | **0.91** | `memory.max` reads `max`: no cap at all |
| `/bin/true` with no kern | 0.29 | the floor: fork + exec |

The ~4 ms is the `systemd-run --user --scope` round trip, and `box` stopped paying it in 0.6.15 while
`run` cannot. `box` leaves a supervisor process alive for the box's lifetime, so it can create the
cgroup directly under kern's delegated slice and remove it from that supervisor's `Drop`. `run`
**`exec()`s in place**: the kern process becomes the workload, so nothing of kern remains to do the
removal, and a directly created cgroup would be orphaned once per invocation, forever. The scope's
`--collect` is what reaps it.

So the 4 ms buys the cap, and this is what it buys:

```console
$ kern run --memory 64m -- python3 -c "b=bytearray(200*1024*1024)"
Killed                                        # exit 137
$ KERN_NO_SCOPE=1 kern run --memory 64m -- python3 -c "b=bytearray(200*1024*1024)"
kern: warning: requested resource cap(s) could not be enforced
                                              # exit 0, 200 MiB allocated
```

`KERN_NO_SCOPE=1` is 5x faster and removes the cap entirely; it says so on stderr rather than letting
you find out later. Use it where you want `run` as a plain launcher and are capping some other way.

## Where a box start actually goes

`KERN_TIMING=1` instruments both the parent and the box side. One `kern box --image alpine:3.19`,
2026-08-01, this machine:

| phase | cost |
|---|---:|
| `pivot+mount_proc` | 523 us |
| `seccomp` | 185 us |
| `proc-mask` (the thirteen mounts that close the `core_pattern` escape) | 173 us |
| `parent:image+command` | 153 us |
| `rootfs(overlay)` | 112 us |
| `parent:setup->spawn` | 101 us |
| `dev` | 97 us |
| `unshare+private` | 92 us |
| `parent:config+volumes` | 74 us |
| `parent:claim` | 62 us |
| `cgroup-view` | 49 us |
| `parent:teardown` | 48 us |
| `parent:name-check` | 27 us |
| `volumes` | 2 us |

The single largest item is the pivot and the `/proc` mount, and the two hardening phases that follow
it, `seccomp` and `proc-mask`, cost 358 us together. That is the price of the boundary, and it is
listed here rather than folded into a total so it can be argued with.

⚠️ These are ABSOLUTE phase durations. `OPEN_ITEMS.md` quotes smaller figures for some of the same
names (`proc-mask` 66 us, `seccomp` +60 us), and those are DELTAS, what the feature added when it
landed. The two are different measurements of different things and must not be subtracted from each
other.

## Footprint

| | |
|---|---:|
| **kern** binary (the whole thing) | **~1.8 MB** static, stripped (one **Rust** dep, `libc`; OCI pull shells out to system `curl`/`tar`), musl x86_64 1.83 MB, aarch64 1.50 MB (release profile: `opt-level=z` + LTO + `panic=abort` + strip) |
| kern resident memory at rest | **0**: no daemon |
| kern memory per box, marginal | **0.35 MB** (PSS, at 50 live boxes) |
| kern memory per box, one box alone | 1.65 MB PSS / 4.6 MB RSS |
| bubblewrap binary | 70 KB (launcher only) |
| runc binary | ~10 MB |
| **Docker** resident | **154 to 160 MB RSS** always on with zero containers running (`dockerd` + `containerd`, both readings 2026-08-01: 154 idle, 160 after an afternoon of use. It was ~186 MB when this row was first written, so it moves with the Docker version AND with how much the daemon has done since it started, which is why it is quoted as a range) |

kern is **~6× smaller than runc** (1.8 MB vs ~10 MB) and needs no bundle scaffolding; bwrap is
smaller still but is only a launcher (no images/caps/lifecycle). Docker keeps 154 to 160 MB resident
before you run anything; kern keeps **zero**, which `ps -eo rss,args | grep kern` shows directly when
no box is up.

> Reproduce: `ls -l $(command -v kern)` (binary); `ps -o rss= -C dockerd -C containerd` (Docker
> resident, sum the KB); for the per-box cost, sum `Pss` from `/proc/<pid>/smaps_rollup` over kern's
> own processes for that box.
>
> **This row said "~7 MB RSS per box" and RSS was the wrong measure.** kern runs two processes per
> box and both are the same static binary, so summing their RSS counts the shared pages twice. PSS
> divides shared pages by the number of sharers, which is what "how much more memory does one more
> box cost" actually means. Measured today: one box alone is 4.6 MB RSS but **1.65 MB PSS**, and with
> 50 boxes up at once the total PSS is 17.5 MB, so the marginal box costs **0.35 MB**. The old figure
> overstated the footprint by a factor of twenty at density, in the direction that flatters nobody:
> the density argument this project makes was being undersold by its own benchmark file.
>
> The two per-architecture sizes are the PUBLISHED artifacts, unpacked from the release tarballs
> (1,913,824 and 1,577,448 bytes at v0.6.30), not a local build: a local `cargo build --release`
> here produces 1,783,048 bytes, and quoting that would understate what anyone actually downloads.

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
