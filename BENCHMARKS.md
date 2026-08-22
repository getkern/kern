# Benchmarks

Measured 2026-08-01 on one machine: Intel i7-14700KF, 28 threads, **Linux 7.0.0**, NVMe,
systemd-user with `cpu memory pids` delegated. Against **Docker 29.1.3** (daemon up), **Podman
4.9.3** (rootless), **runc 1.3.3** (rootless), **bubblewrap 0.9**. `crun` is not installed here; its
row says so. The workload is `/bin/true` in Alpine with the image already local, so this measures
runtime overhead, not download time. All ran the same Alpine rootfs. This is a 0.x project: read
these as "fast class", not as a guarantee.

The CPU governor does not move these numbers, and that is measured on both sides. Sampling every core
every 50 ms during box starts, the core running kern sits at a median of **5501 MHz under `powersave`
and 5505 under `performance`**, against a 5500 MHz ceiling. Running the identical benchmark under
both gives 2.22 / 2.22 ms uncapped, 2.30 / 2.44 capped, 3.46 / 3.44 from an image, all inside the
run-to-run spread of 0.02 to 0.09 ms. Quote the frequency a machine reaches, not the name of its
governor: a reader whose CPU does not reach its ceiling has a real reason to expect different numbers.

**Reproduce it yourself.** The cold-start, throughput and concurrency tables come from one script,
[`examples/benchmark.py`](examples/benchmark.py), stdlib only. It auto-detects the runtimes you have,
pulls the Alpine rootfs once, and prints the same tables:

```sh
python3 examples/benchmark.py                      # 200 sequential runs + 200 in parallel
KERN=./target/release/kern python3 examples/benchmark.py --runs 500 --conc 100
```

The remaining sections are measured by hand with the commands shown inline.

**Measuring it by hand: do not pay for your own instrument.** A shell loop that calls `date` around
each run charges the measurement for its own forks. Two `date` calls cost **1.26 ms** on this
machine, which turned a 0.93 ms `exec` into 1.6 and a 3.5 ms image start into 4.3 - a "regression"
that vanished when the same loop was run against a build from before the change under test and
measured exactly the same inflated number. Use the script above, or bash's `$EPOCHREALTIME` around a
batch of 100 and divide. The concurrency row is sensitive to what ran BEFORE it, too: measured
immediately after 200 parallel podman containers it reads 0.25 s against 0.09 on a quiet machine.

## Cold start, one isolated `/bin/true`

Time per run, total divided by 200 sequential runs.

| Runtime | Cold start | What it does at that price |
|---|---:|---|
| **kern** `box --rootfs`, uncapped | **2.44 ms** | overlay + self-pivot + seccomp. Uncapped is what makes it comparable to bubblewrap |
| **kern** `box --rootfs`, capped (the default) | **2.63 ms** | the same, plus a real cgroup cap: +0.19 ms |
| **kern** `box --bind-rootfs` | 2.49 ms | no overlay, the source is shared and mutable |
| **kern** `box --image` | **3.61 ms** (2.65 with `--no-uid-range`) | the same, plus the rootless uid-range mapping: two setuid helpers, ~1.1 ms, run concurrently. A range cannot be written to `/proc/<pid>/uid_map` without `CAP_SETUID`, so they are not avoidable. It is what lets an official image drop privilege in its entrypoint (postgres, nginx) instead of failing |
| bubblewrap | 2.8 ms | a sandbox *primitive*: no images, caps, or lifecycle |
| crun | 5.2 ms (June; not installed on the machine re-measured here) | OCI runtime (C): bundle + cgroup setup |
| runc (rootless) | 14.6 ms | OCI runtime (Go): bundle + cgroup, high run-to-run variance |
| podman (rootless) | 289.0 ms | daemonless engine: forks `conmon` + the full OCI stack per run |
| **docker run --rm** | 292.5 ms | client to daemon round-trip |

**A cgroup cap costs 0.19 ms**, not a `systemd-run` round trip, because kern caps
directly in its own delegated slice. On the `--image` path `--memory 64m --cpus 1 --pids-limit 64`
costs 0.52 ms. The cap bites: 200 MiB under `--memory 32m` exits 137.

⚠️ **The direct slice is reachable only when kern runs inside the systemd user manager's tree**, which
a desktop session gives you and an **SSH session does not**: a login is placed under the SYSTEM
manager, a different delegation domain. Where the direct path is out of reach kern falls back to a
per-box transient scope, which costs **9.4 ms** on a Raspberry Pi 5. Same binary, same caps enforced
either way. [The toll is avoidable](#the-toll-is-avoidable) has the one-line fix.

Nobody wins single-shot latency outright: the physical floor for `unshare` + `exec` is 1 to 2 ms, so
the top tier sits within a couple of ms of itself and of its own noise. The real gap is to the
**engines**, which fork `conmon` or round-trip a daemon every run.

Throughput is the same data as `1000 / ms`: kern 410 runs/s, bubblewrap 357, runc 68, podman 3.5,
docker 3.4.

### Real image, not `/bin/true`

A real ~30 MB app image (`ubuntu/apache2`), same image both sides, warm cache: **kern ~7 ms against
`docker run` ~320 ms**. Once the image is local, a kern box of it is up in single-digit ms.

```sh
kern pull ubuntu/apache2 && docker pull ubuntu/apache2
time kern box web --image ubuntu/apache2 -- true
time docker run --rm ubuntu/apache2 true
```

## Concurrency, 200 isolated starts in parallel

Wall-clock, all 200/200 succeeded on every runtime.

| Runtime | Wall-clock |
|---|---:|
| **kern** `--rootfs` | **0.10 s** |
| bubblewrap | 0.15 s |
| runc | 0.31 s |
| **docker run --rm** | 16.21 s |
| podman (rootless) | 41.93 s |

It keeps scaling past where the table stops, measured in the same session:

| kern boxes at once | wall-clock | succeeded | rate |
|---:|---:|---:|---:|
| 200 | 0.10 s | 200/200 | 1970 box/s |
| 500 | 0.31 s | 500/500 | 1613 box/s |
| 1000 | 0.61 s | 1000/1000 | 1640 box/s |

A thousand simultaneous kernel-isolated boxes in 0.61 s, none refused, on a 28-core desktop. The rate
is flat from 500 to 1000, so the limit at this size is the machine rather than anything serialising
inside kern.

## Boards: the same static binary where the engines are not installed

Measured 2026-07-30 with `kern bench --rootfs <dir>`, three repeats per cell against a warm page
cache on an idle host, median of medians. Every kern row had `memory.max` read back as 268435456 from
inside a box in the same session.

| host | kernel | **kern** | bubblewrap | runc | docker |
|---|---|---:|---:|---:|---:|
| x86_64 desktop | v7.0 | **2.6 ms** | 2.9 ms | 13.8 ms † | 292.9 ms † |
| Raspberry Pi 5 | v6.6-rpi | **11.8 ms** | ✗ | ✗ | ✗ |
| Jetson Orin Nano | v5.15-tegra | **12.5 ms** | 5.6 ms | 32 ms † | 472 ms † |
| Arduino UNO Q | **v6.16 Android** | **91.5 ms** | 15.0 ms | 76 ms † | 858 ms † |

✗ = not installed on that board, checked one binary at a time: on the Pi 5, docker, podman, runc,
crun, bwrap, nerdctl, lxc-start and systemd-nspawn are all absent. † carried over from an earlier
session; only kern and bubblewrap were measured in this round.

**On the two boards where both are installed, bubblewrap's number is lower than kern's in this
table.** Said plainly, because it is the kind of thing a reader finds in a minute. The two columns
are not the same work: bubblewrap is a sandbox primitive with no images, no lifecycle and no
resource caps at all, so it never does cgroup work, while kern's board figures include enforcing
caps through a systemd transient scope. Measured at the same level of work, kern is ahead on every
host where both are installed, and ahead even while enforcing a cap bubblewrap does not:
[At the same level of work](#at-the-same-level-of-work), below.

### The scope is the whole gap, and the arithmetic closes

`systemd-run --user --scope /bin/true` timed on its own, 20 runs, beside kern's capped and uncapped
box on the same host in the same session:

| host | kern, caps ON | kern, cgroup off | difference | `systemd-run --scope` alone |
|---|---:|---:|---:|---:|
| x86_64 desktop | 2.6 | 2.3 | 0.3 | 4.2 (**not paid**: direct path) |
| Raspberry Pi 5 | 11.8 | 2.7 | 9.2 | 9.4 |
| Jetson Orin Nano | 12.5 | 4.1 | 9.3 | 9.0 |
| Arduino UNO Q | 91.5 | 33.5 | 58.2 | 59.9 |

On all three boards the difference and the standalone scope agree to within 1.7 ms. The x86 row is
the control: the scope costs 4.2 ms there too, and kern does not pay it because it caps directly for
0.3 ms. WSL2 is the third kernel that settles it: there is no `systemd-run` at all, and a box costs
**3.4 ms with the cap enforced**.

⚠️ `kern doctor` reports a smaller number for the same board and it is not the same quantity: doctor
reports a FLOOR, because a box does not merely create the scope, it re-execs kern inside it.
Reconcile against the DIFFERENCE column, never against doctor's floor.

### The toll is avoidable

The scope is paid because an SSH login sits under the SYSTEM systemd manager while kern's delegated
`kern.slice` lives under the USER manager, and cgroup v2 refuses to migrate a process across that
boundary. Verified on the UNO Q rather than assumed: creating a cgroup under `kern.slice` succeeds,
writing `memory.max` into it succeeds, writing the pid into `cgroup.procs` is **refused**.

Enter the user manager's tree once and every box after it takes the direct path, caps still enforced
(`memory.max` read back as 268435456 in every cell):

```sh
systemd-run --user --scope bash     # pay it once, then run kern inside that shell
```

| board | as an SSH login | inside one scope | + `--bind-rootfs` |
|---|---:|---:|---:|
| Raspberry Pi 5 | 11.8 ms | **3.0** | **2.8** |
| Jetson Orin Nano | 12.5 ms | **4.6** | **4.2** |
| Arduino UNO Q | 91.5 ms | **35.5** | **11.3** |

Eight times faster on the Arduino, four on the Pi, all with caps live. `kern doctor` measures the
toll on the host in front of you and prints that command.

It also settles the bubblewrap comparison on the boards: kern *enforcing a memory limit* against
bubblewrap enforcing nothing is **4.2 ms vs 5.6** on the Jetson and **11.3 vs 15.0** on the Arduino.

### Why the Arduino is still the slowest

One thing: **`mount -t overlay` takes 22 ms on that Android kernel**, against ~0.1 ms on x86.
Everything else in a box there sums to about 7 ms. The 22 ms is fixed, which is what makes it
interesting: identical with a 517-file lowerdir and with an empty one, identical on ext4 and on
tmpfs, five consecutive mounts within 0.4 ms of each other, `overlay` already in `/proc/modules`, and
a tmpfs mount in the same namespace costs 6.1 ms against overlay's 28.2. A cost that ignores both the
content and the backing store is not work being done, and kern cannot make that kernel faster.
`--bind-rootfs` skips the mount, at the price of binding the source directly: mutable and shared
between boxes. `kern doctor` states the trade instead of choosing for you.

### At the same level of work

bubblewrap binds rather than overlays, so `--bind-rootfs` is the like-for-like flag.

| board | kern, cgroup off, `--bind-rootfs` | bubblewrap |
|---|---:|---:|
| x86_64 desktop | **2.2 ms** | 2.9 ms |
| Raspberry Pi 5 | **2.3 ms** | not installed |
| Jetson Orin Nano | **3.5 ms** | 5.6 ms |
| Arduino UNO Q | **9.6 ms** | 15.0 ms |

**kern is ahead of bubblewrap on every host where both are installed, at the same level of work.**

The claim that survives is a reach claim rather than a latency one: on the Raspberry Pi 5 kern is the
only runtime that runs at all, and one static binary copied over just works.

## Windows: where the milliseconds go

On Windows kern runs inside its own WSL2 distro, and a command typed on the Windows side spawns
`wsl.exe` once per command. That crossing is not kern's work and it dwarfs kern's work. Two Windows
11 hosts, 20 boxes of the same cached image per sample:

| where you type | ms per box | processes added per command | host |
|---|---:|---|---|
| inside the distro (`wsl -d kern`, then `kern ...`) | **6.5** and **7.0** | none | both |
| Windows, via `kern.exe` | **70.5** | 1 (`wsl.exe`) | B |
| Windows, via the `kern.cmd` fallback | **~330-500** | 2 (`cmd.exe`, then `wsl.exe`) | A |

Host A runs Malwarebytes, which deletes the unsigned `kern.exe` within seconds of every download, so
the exe row cannot be measured there at all, which is why the fallback exists. Host B runs only
Defender and supplies that row. The inside-WSL figure is the one both hosts produce and they agree.

So the crossing costs about **63 ms per command**. Read the fallback row as "a few hundred", not as a
figure: it is a different host as well as a second process. The comparable Linux figure is the 3.4 ms
OCI-image row, not the 2.2 ms prepared-rootfs one.

The 9p bridge did not show up in box startup, which was worth checking rather than assuming: the same
20-box loop with the working directory on `/mnt/c` took the same 0.13 s as from `~`, because kern
reads its image cache inside the distro's own filesystem. Read that narrowly. A `-v` mount whose
source is under `/mnt/c`, or a relocated image cache, crosses 9p on every read and was not measured.

**On Windows, run kern inside the distro.** The bridge is for the occasional command from a
PowerShell you are already in, not for a loop that starts hundreds of boxes.

## What a published port costs

`kern box -p H:B` forks a process that copies bytes both ways in userspace, so every byte of every
request crosses it. Measured with **nginx**, once behind `-p` on an isolated netns and once over
`--net` where nginx binds the host port directly and there is no pump at all.

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

Publishing is close to free on this machine: within noise on request rate, 4% on bandwidth, 0.08 ms
of p99.

⚠️ **These are the numbers after the `TCP_NODELAY` fix below, and before it they were not close to free.** Neither
side of the pump set `TCP_NODELAY`, so a response written as headers-then-body waited on the peer's
40 ms delayed-ACK timer, and only on a REUSED connection: 59 req/s on one keep-alive connection with
p99 pinned at 42.0 ms. Bandwidth was unaffected throughout, which is exactly why it went unnoticed. A
benchmark that downloads one large file through a published port sees nothing wrong.

### At scale, and on a protocol that is not HTTP

The forwarder forks one process per accepted connection, each of which `setns` into the box.

| held open | forwarder processes | RSS | PSS | per connection |
|---:|---:|---:|---:|---:|
| 0 | 3 | 6.1 MB | 1.7 MB | |
| 200 | 203 | 266.9 MB | 11.9 MB | **52.9 kB** PSS |
| 500 | 503 | 658.3 MB | 27.2 MB | 52.3 kB |
| 1000 | 1003 | 1310.7 MB | 52.6 MB | 52.2 kB |

Read the PSS column: every child is the same static binary, so RSS charges its pages to each of them.
The marginal cost of one more open connection is **52 kB and one PID**, and closing them all returns
exactly to 3 processes and 1.7 MB. The ceiling is the PID limit rather than memory (`RLIMIT_NPROC` is
115,919 here), so a service expecting six-figure simultaneous connections wants `--net` or a pod.

Opened and closed as fast as possible, nothing was refused and the rate is flat: 100 in 0.02 s,
500 in 0.09, 1000 in 0.19, 2000 in 0.37, about 5300 conn/s throughout, p99 from 1.45 to 1.76 ms.

**Redis**, strict request/response on one persistent connection, 3000 SET+GET round trips: 71,606
ops/s behind `-p` against 124,992 direct. The pump costs about **11 us per round trip**, which on a
protocol this fast is 43% of throughput. It is invisible on HTTP, and it is the reason to reach for a
pod or `--net` when the workload is a chatty database rather than a web server.

## `kern run` costs 4.9 ms and `kern box` costs 3.6, which looks backwards

`run` does less than `box` and measures slower. Both figures are real, and the asymmetry is
structural. Measured 2026-08-01, 200 runs x 3:

| | ms/run | what the cap does |
|---|---:|---|
| `kern run -- /bin/true` | 4.70 | still capped: `memory.max` 512 MiB, `pids.max` 512 |
| `kern run --memory 64m` | 4.88 | |
| `kern run --cpus 1` | 5.78 | a `CPUQuota` property costs ~0.9 ms more than a memory one |
| `kern run --memory 64m` with `KERN_NO_SCOPE=1` | **0.91** | `memory.max` reads `max`: no cap at all |
| `/bin/true` with no kern | 0.29 | the floor: fork + exec |

The ~4 ms is the `systemd-run --user --scope` round trip. `box` no longer pays it and `run`
cannot: `box` leaves a supervisor alive for the box's lifetime, so it can create the cgroup directly
and remove it from that supervisor's `Drop`, while `run` **`exec()`s in place**, so nothing of kern
remains to do the removal and a directly created cgroup would be orphaned once per invocation,
forever. The scope's `--collect` is what reaps it.

`KERN_NO_SCOPE=1` is 5x faster and removes the cap entirely. It says so on stderr rather than letting
you find out later.

## A working day, not a cold start

Nobody notices 300 ms once. What a developer feels is the twentieth `exec` of the afternoon. Same
machine, same images, real commands, timed with the shell.

| what you actually type | kern | docker | podman |
|---|---:|---:|---:|
| a throwaway box (`box --image … true`) | **~3.6 ms** | ~290 ms | ~290 ms |
| `exec` into a running service | **0.79 ms** | 43.3 ms | 148.6 ms |
| list what is running (`ps`) | **0.30 ms** | 8.2 ms | 13.5 ms |
| read logs | **0.35 ms** | 8.2 ms | 37.5 ms |
| stop a service (init handles SIGTERM) | **4.6 ms** | 126.8 ms | 199.7 ms |
| stop nginx (the same image on all three) | **48.5 ms** | 187.2 ms | 256.9 ms |
| bring a 2-service stack up | **188 ms** | 292 ms | 1022 ms |
| stop that stack | **77 ms** | 263 ms | 496 ms |
| take it down (stop + remove) | **68.8 ms** | 402.3 ms | 515.5 ms |

Reproduce any row with `time`, on both sides. No script of ours is involved.

The `take it down` row is `compose down` on a RUNNING stack, so it includes stopping both services;
run against an already-stopped one it is 9 ms on kern, which is the removal alone and not a fair
column. Podman's compose cells need `podman.socket` enabled - without it `podman compose` fails
without starting anything and "measures" 28.7 ms, which is what a cell reads when nothing ran.

**The stop rows need two caveats, and both cut against the headline.**

FIRST, an init that does *not* handle SIGTERM: 10 165 ms on Docker, 10 203 ms on Podman, 5.1 ms on
kern. That is **not** Docker being slow. A PID-namespace init discards signals it has no handler for,
so the container genuinely cannot die of SIGTERM, and waiting the full grace before `SIGKILL` is
correct, documented behaviour. kern reads `SigCgt` from `/proc/<pid>/status` first and skips a wait
that provably cannot end. Publishing that as a 2000x win would be dishonest, which is why the table
measures an init that *does* handle the signal.

SECOND, the two runtimes do not signal the same set of processes. Docker and Podman send the stop
signal to PID 1 only; kern also signals the box's process group, so a shell blocked in `sleep 0.5`
wakes at once instead of when its child happens to finish. On that shape of workload the same table
row reads 4.9 ms against 346.7 and 364.5 - a 70x that is mostly the sleeping child, not the runtime.
The rows above therefore use an init that handles SIGTERM in a handler and returns immediately (a
static C binary, `signal(SIGTERM)` + `pause()`, the same binary bind-mounted into all three), which
is the comparison where only the runtime differs.

The `stop nginx` row is the one closest to what a developer actually types, and it is the least
flattering: most of those 48.5 ms are nginx's own shutdown, identical on all three.

## Where a box start actually goes

`KERN_TIMING=1` instruments both the parent and the box side. One `kern box --image alpine:3.19`:

| phase | cost |
|---|---:|
| `pivot+mount_proc` | 523 us |
| `seccomp` | 185 us |
| `proc-mask` (the fourteen mounts that close the `core_pattern` escape) | 173 us |
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

The largest item is the pivot and the `/proc` mount, and the two hardening phases that follow it,
`seccomp` and `proc-mask`, cost 358 us together. That is the price of the boundary, listed rather
than folded into a total so it can be argued with. `unshare(CLONE_NEWNET)` on its own costs **430
us**, 17% of a box start, and is the price of network isolation.

⚠️ These are ABSOLUTE phase durations. `OPEN_ITEMS.md` quotes smaller figures for some of the same
names, and those are DELTAS: what the feature added when it landed. They must not be subtracted from
each other.

## Footprint

| | |
|---|---:|
| **kern** binary | **~2.0 MB** x86_64, **~1.57 MB** aarch64 from a plain `cargo build --release` (the size-optimized release build is **1.59 MB / 1.31 MB**), static and stripped, one Rust dependency (`libc`); OCI pull shells out to the system `curl`/`tar` |
| kern resident memory at rest | **0**: no daemon |
| kern memory per box, marginal | **0.35 MB** PSS, at 50 live boxes |
| kern memory per box, one box alone | 1.65 MB PSS / 4.6 MB RSS |
| bubblewrap binary | 70 KB (launcher only) |
| runc binary | ~10 MB |
| **Docker** resident | **154 to 160 MB RSS** with zero containers running (`dockerd` + `containerd`; it moves with the version and with how much the daemon has done, which is why it is a range) |

PSS rather than RSS is the honest measure here: kern runs two processes per box and both are the same
static binary, so summing their RSS counts the shared pages twice. The two per-architecture sizes are
from the stripped `--release` build (`cargo build --release --target …-musl`), which reproduces
byte-for-byte, not a debug build, which is larger and would overstate the footprint.

```sh
ls -l $(command -v kern)                      # the binary
ps -o rss= -C dockerd -C containerd           # Docker resident, sum the KB
```

## Resource caps

A box caps directly in kern's delegated `kern.slice` inside the systemd user-manager tree, else inside
a transient `systemd-run --user --scope`, with `MemoryMax=512M`, `MemorySwapMax=0`, `TasksMax=512`,
verified enforced in the kernel cgroup: ~100 MB allocates fine, ~700 MB is OOM-killed with no swap
escape, a fork bomb is capped at 512 tasks. Without a systemd user manager, a best-effort cgroup v2
path applies where the hierarchy is delegated, else caps are skipped (documented in
[SECURITY.md](SECURITY.md)); `--require-limits` refuses to start rather than run uncapped there, and
`--allow-uncapped` accepts it silently.

```sh
kern box mem --image alpine --memory 512M -- sh -c 'tr -dc 0 </dev/zero | head -c 700M | wc -c'
```

## Method

The cold-start, throughput and concurrency tables all come from one self-contained script. It warms
each runtime once, then reports latency as **total divided by N** over N sequential runs (at sub-ms
scale a per-call timer's own fork/exec would dominate), throughput as `1000 / ms`, and concurrency as
the wall-clock to fan out `--conc` starts at once. Under the hood:

```sh
kern box b --rootfs $ROOTFS -- /bin/busybox true         # KERN_NO_SCOPE=1 = no cgroup scope
bwrap --unshare-all --bind $ROOTFS / --proc /proc --dev /dev /bin/busybox true
crun run --bundle $BUNDLE b                               # bundle pre-built
runc run --bundle $BUNDLE b
podman run --rm --network none alpine /bin/true
docker run --rm alpine /bin/true
```

The day-to-day operations table is measured differently, by typing the commands and timing them with
the shell, so it lives next to that claim with its own reproduction line rather than being copied
here. Two homes is how a number drifts.

## Honest caveats

- One machine, warm cache, `/bin/true`: a microbenchmark of *startup overhead*, not a workload.
- **kern ties `crun` and is about 2x `runc` as measured**, but the whole top tier hits the same 1 to
  2 ms `unshare`+`exec` floor, so single-shot wins are mostly run-to-run noise. The honest claim is
  "fastest tier, complete UX, tiny, daemonless", not "fastest of all".
- Not perfectly apples-to-apples: runc's per-run number **excludes** the bundle setup it requires up
  front, whereas kern's `--image` figure **includes** the whole image-overlay + cgroup-cap path.
- Docker does far more (build, networking, volumes, swarm, an ecosystem). This compares the cost of
  starting an isolated process.
- kern is early (0.x). These numbers are about speed and footprint, not maturity.
