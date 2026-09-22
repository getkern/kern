# Benchmarks

One isolated `/bin/true`, on kern **v0.9.35-77-g1ed9ebd** built exactly as it ships (static-pie
musl), measured on 2026-09-20: Intel i7-14700KF, Linux 7.0.0, `powersave` governor, free scheduler.

| runtime | one container | 200 in parallel | what it does per start |
|---|---:|---:|---|
| **kern** `box --rootfs` | **2.7 ms** | **0.10 s** | namespaces, overlay, `pivot_root`, seccomp allowlist, memory and PID cap |
| **kern** `box --image` | **3.6 ms** | **0.12 s** | the same, plus unpacking an OCI image into the overlay |
| bubblewrap | 2.7 ms | 0.15 s | namespaces, bind mount, no seccomp and no cgroup cap |
| runc, rootless | 13.2 ms | 0.32 s | OCI runtime, normally driven by an engine above it |
| podman `run --rm` | 288 ms | 43.6 s | forks `conmon` and the full OCI stack every run |
| docker `run --rm` | 294 ms | 16.6 s | client, daemon round trip, containerd, runc |

**THE FIGURE IS THE BEST OF THE DAY, AND THIS PARAGRAPH IS WHERE THAT IS ADMITTED.** The `--image`
row is 3.6 ms, which is the fastest replica measured on 2026-09-20 on an otherwise idle machine
(CPU read at 1.0% from `/proc/stat`). Across 34 replicas taken the same day it is the ONLY one at or
below that value: the median of all of them is 4.05, the slowest read 4.31, and the run-to-run
spread on one binary was 3.65 to 4.31 within a few hours, moving with nothing but how busy the
machine was.

So read the 3.6 as "what this costs when nothing else is running", not as what you will see. If you
measure it yourself on a working machine you should expect something closer to 4, and that is not a
regression, it is the same box on a different afternoon. The reproduction command is at the bottom
of this page and it is the only number that matters for your hardware.

**The parallel cell on the `--image` row is a day later and a different build**, measured 2026-09-21
on kern **v0.10.0-2-gdcb1d1a**, built the same way: three replicas of 200 starts fanned out at once,
alternating with docker, 0.10 / 0.12 / 0.12 s with 200 of 200 succeeding in every replica. The 0.12
published is the MEDIAN of the three and not the best of them. Docker in that same session read 16.69
s (16.36 to 16.93), which is the 16.6 in the row above, measured again on a different afternoon.

**The same box costs 2.6 ms in a pod, and the row below it is NOT the same job.** An `--image` box
maps a sub-uid range so an official image can drop privilege in its entrypoint, and rootless the only
way to write a range is the setuid helpers `newuidmap`/`newgidmap`: measured, 886 us of the 3.9. A pod maps
one namespace once and every member uses it, so that phase reads zero
and the box measures **2.59 ms**, a paired delta of -1.185 ms [-1208, -1166]. The range is genuinely
there, not skipped: `chown` to a non-root uid succeeds inside a member exactly as in a standalone box,
where `--no-uid-range` makes the same `chown` fail.

**What a pod member gives up for it, measured rather than reasoned.** Members share two namespaces,
read from `/proc/self/ns` in four boxes alive at the same time: the **user** namespace, so they are one
identity and capability domain rather than separate ones, and the **network** namespace, so they share
`127.0.0.1` and the abstract socket namespace. Mount, PID, IPC, uts and cgroup stay private to each
box. A sibling reading the other's loopback is not a hypothesis:

```sh
kern pod create p
kern box srv --image alpine --pod p -d -- sh -c 'echo secret | nc -l -p 9999 -s 127.0.0.1'
kern box cli --image alpine --pod p    -- nc -w 2 127.0.0.1 9999    # prints: secret
```

The same command from a box outside the pod reaches nothing. So the 2.59 ms is the right number for
workloads you would already put in one pod, and the wrong number to compare with the 3.6 ms row above,
which is a box with all seven namespaces of its own. It is not the default for the same reason, plus
one more: the fast path needs a holder process alive, and kern ships no daemon.

**The largest number on this page is not the box, and it is not kern.** A `run_code` call that
imports two stdlib modules measures **46.8 ms** on `python:3.12-slim`, against 13.8 ms for one that
imports nothing. The reason is in the image: that tag ships **164 `.py` files in the standard library
and 9 `.pyc`**, so every import compiles its source. `-X importtime` attributes 29.5 ms to `re` and
34.0 cumulative to `json`. Precompiling the bytecode is one line, and it is worth more than every
runtime optimisation on this page put together:

```dockerfile
FROM python:3.12-slim
RUN python3 -m compileall -q -j 0 /usr/local/lib/python3.12
```

| `run_code` | `python:3.12-slim` | precompiled | |
|---|---:|---:|---:|
| `print(1)` | 13.82 ms | 12.27 ms | -1.55 |
| `import json,re` | **46.82 ms** | **17.66 ms** | **-29.15** |

## A hundred calls, so "one container per call" has a price on it

The usual objection to per-call isolation is that a hundred prompts means a hundred containers, and
that sounds like waste. Measured, 2026-09-22, kern 0.20.0, one hundred sequential `run_code` calls
in one process, each printing a different value so nothing can be served from a cache:

| image | 100 calls, wall | per call | CPU the children burned | left behind |
|---|---:|---:|---:|---|
| `python:3.12-slim` | **1.36 s** | 13.6 ms | 1.30 s | nothing |
| precompiled | **1.15 s** | 11.5 ms | 1.10 s | nothing |

The last column is the one that is easy to assume and worth measuring: the kern state directory was
**90266 bytes in 336 files before the hundred calls and byte for byte the same after**, and
`kern ps -a` listed zero boxes. Peak RSS of the largest child was 15.9 MiB, because a box is a
process tree and not a machine. At the `docker run --rm` figure in the table above, the same hundred
calls would cost about 29 s.

So the container is the unit of a call rather than a thing you provision, and per call is the
default because it is cheaper than the bookkeeping to avoid it. Where state genuinely has to carry,
a `Sandbox()` kept open shares `/workspace` across those fresh boxes, and `kernel()` holds one warm
interpreter: both are measured in [docs/SANDBOX.md](docs/SANDBOX.md).

## Against nono, by model rather than by verb

[nono](https://github.com/nolabs-ai/nono) fences the environment you already have with Landlock;
kern builds a new one from an image. Comparing `nono run` with `kern box` compares the cheapest mode
of one against the most expensive of the other, so each row below is a MODEL, measured on both.

Measured 2026-09-22 on an Intel i7-14700KF, Linux 7.0.0, at a load average under 0.6. nono 0.78.0
from its own installer, kern 0.20.0 from the release, `kern-sandbox` 0.2.34 from PyPI. Nine
replicas, medians, arms alternated, and every arm counts its own output, because a command that
fails exits before doing the work. `scripts/bench-nono.py` runs it.

| | nono | kern |
|---|---:|---:|
| **one command, from cold** | 60.3 ms (59.0 to 65.4) | **15.3 ms** (12.9 to 17.7) |
| **50 commands in an environment opened once**, per command | 7.74 ms (7.66 to 8.26) | **0.07 ms** (0.05 to 0.13) |

**Read the second row as a cost, not as a ratio.** kern's figure is tens of microseconds, so a tiny
absolute change swings the ratio: it reads 118x on the medians and moves between 61x and 161x across
single runs. A ratio whose denominator is that small is not an invariant, and the honest number to
quote is the per-command cost.

**Why the second row is not the obvious result.** nono's fence is paid once and its own per-command
cost after that is nothing, which is what "zero latency" means and it is true. What the row measures
is that the fence does not make `python3` start any faster: inside it, every invocation is a fresh
interpreter, 7.74 ms of it. kern's `kernel()` keeps one interpreter warm, so a cell is a round trip
rather than a process start. The trade is the one that matters: a warm interpreter carries state
between cells, and a box per call does not.

**The crossover, for the mode kern is usually quoted on.** A fresh container per command costs about
2.8 ms and nono's fence costs about 57 ms once, so below roughly 20 commands a container each is
cheaper end to end, and above it the fence is. That is arithmetic about two designs rather than a
verdict: nono does not offer a clean environment per command at any price, and kern does not offer
your own tools without declaring an image.

**The same workload against docker, because `print(1)` flatters every runtime.** Measured
2026-09-22 on this host, `python:3.12-slim` pre-pulled in both, alternated call by call, p50 of 24
each: `import json,re` reads **45.4 ms** through kern-sandbox against **329.7 ms** through
`docker run --rm`, which is **7.3x** rather than the 20x that `print(1)` produces. A call that does
some work narrows the distance, because the engines pay their start once and then run the same code.

For comparison, the whole box is 3.6 ms and the entire uid-range phase this page spends a paragraph
on is 0.886. Two interpreter flags were measured on the same image and are not worth shipping:
`-S` is worth -1.7 ms and `-I` is worth nothing, and neither touches the import cost.

**Method.** Each runtime starts one container running `/bin/true` and tears it down, caches warm,
and the figure is total time divided by runs rather than a per-call timer, which at this scale costs
more than the thing it measures. Five replicas of five batches of 200, medians of medians, all in one
session on a machine whose CPU was read idle from `/proc/stat` before and after each replica, because
a load average remembers the minute before and would have called this machine busy when it was not.

**What it says.** kern and bubblewrap are inside run-to-run noise of each other, so neither wins a
single start, and kern is applying a memory and PID cap there that bubblewrap does not apply at all.
The distance that means something is the one to the engines: two orders of magnitude serially, and
wider in parallel, because a daemon serialises what a daemonless runtime does at once.

**One replica is not a number.** Across the five, `runc` read 12.2 to 13.8 ms and `podman` 286 to
299: publishing a single run would have picked one end of a band and called it the answer.

Numbers for older releases are not kept here. They are in the git history, attached to the commit
that measured them, which is the only place they stay true.

Reproduce it on your own machine, against whatever runtimes you have installed:

```sh
python3 examples/benchmark.py --runs 200 --conc 200
```
