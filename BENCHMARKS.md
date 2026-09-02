# Benchmarks

One isolated `/bin/true`, x86_64 desktop, kernel 7.0.0, static musl binary, 200 runs per batch.
Reproduce with `python3 examples/benchmark.py`; your numbers will differ with CPU, kernel and
filesystem.

| runtime | cold start | 200 in parallel |
|---|---:|---:|
| **kern** `box --rootfs` | **2.7 ms** | **0.11 s** |
| bubblewrap | 2.7 ms | 0.14 s |
| runc (rootless) | 14.0 ms | 0.28 s |
| podman `run --rm` | 288.9 ms | 45.4 s |
| docker `run --rm` | 294.6 ms | 16.5 s |

kern and bubblewrap sit inside each other's noise and nobody wins single-shot latency outright; the
gap that matters is to the engines. kern's figure includes an overlay, a real cgroup cap and a
registry entry, none of which bubblewrap does. `box --image` is 3.5 ms, of which 1 ms is the
rootless uid-range mapping: two setuid helpers kern does not control.

The claim that survives is reach rather than milliseconds. On a Raspberry Pi 5, docker, podman,
runc, crun, bwrap, nerdctl, lxc-start and systemd-nspawn were all absent, checked one at a time;
kern ran there as the same static binary, copied over.
