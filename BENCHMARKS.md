# Benchmarks

One isolated `/bin/true`, on kern **v0.9.35-77-g1ed9ebd** built exactly as it ships (static-pie
musl), measured on 2026-09-20: Intel i7-14700KF, Linux 7.0.0, `powersave` governor, free scheduler.

| runtime | one container | 200 in parallel | what it does per start |
|---|---:|---:|---|
| **kern** `box --rootfs` | **2.7 ms** | **0.10 s** | namespaces, overlay, `pivot_root`, seccomp allowlist, memory and PID cap |
| **kern** `box --image` | **3.9 ms** | | the same, plus unpacking an OCI image into the overlay |
| bubblewrap | 2.7 ms | 0.15 s | namespaces, bind mount, no seccomp and no cgroup cap |
| runc, rootless | 13.2 ms | 0.32 s | OCI runtime, normally driven by an engine above it |
| podman `run --rm` | 288 ms | 43.6 s | forks `conmon` and the full OCI stack every run |
| docker `run --rm` | 294 ms | 16.6 s | client, daemon round trip, containerd, runc |

**The band, not the friendliest end of it.** The `--image` row is the median of eight measurements
taken today across two different harnesses, a Python loop and a bare shell loop, which read 3.79 to
4.06 ms. The shell loop reads HIGHER than the Python one, so the harness is not inflating it. An
earlier draft of this table published 3.8, the low end, which is the error this file exists to stop.

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
workloads you would already put in one pod, and the wrong number to compare with the 3.9 ms row above,
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

For comparison, the whole box is 3.9 ms and the entire uid-range phase this page spends a paragraph
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
