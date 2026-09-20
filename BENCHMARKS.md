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

**The same box costs 2.6 ms in a pod, and the reason is one syscall nobody repeats.** An
`--image` box maps a sub-uid range so an official image can drop privilege in its entrypoint, and
rootless the only way to write a range is the setuid helpers `newuidmap`/`newgidmap`. Measured, that
phase is 886 us of the 3.9. A pod created with `--uid-range` owns one mapped namespace and every
member inherits it, so the phase reads **zero** and the box measures **2.59 ms**, paired delta
-1.185 ms [-1208, -1166]. The range is fully there: `chown` to a non-root uid works inside a member
exactly as in a standalone box, which is the test that separates this from `--no-uid-range`, where
the same `chown` fails. One command, before the burst:

```sh
kern pod create fast --uid-range
kern box job --image alpine --pod fast -- ./work
```

It is not the default because it needs a holder process to stay alive, and kern ships no daemon.

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
