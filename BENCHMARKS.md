# Benchmarks

One isolated `/bin/true`, x86_64 desktop, kernel 7.0.0, static musl binary, 200 runs per batch.
Reproduce with `python3 examples/benchmark.py`; your numbers will differ with CPU, kernel and
filesystem.

| runtime | cold start | 200 in parallel |
|---|---:|---:|
| **kern** `box --rootfs` | **2.7 ms** | **0.10 s** |
| bubblewrap | 3.0 ms | 0.18 s |
| runc (rootless) | 14.2 ms | 0.32 s |
| podman `run --rm` | 288.1 ms | 43.7 s |
| docker `run --rm` | 295.9 ms | 16.8 s |

The bubblewrap column is namespace-matched, or it is not a comparison: `kern box` always makes a
network namespace, so bwrap is given `--unshare-user --unshare-pid --unshare-ipc --unshare-uts
--unshare-net --bind <rootfs> / --proc /proc --dev /dev`.

kern leads bubblewrap by 0.3 ms and the two ranges do not overlap (2.6 to 2.7 against 2.9 to 3.0),
which is a real margin and a small one. Both columns run WITHOUT a cgroup cap, which is what makes
them the same job; kern is still installing a seccomp filter and writing a registry entry that bwrap
does not, and the default `kern box` adds the cap on top. The gap that matters is to the engines.
`box --image` is 3.5 ms, of which 1 ms is the rootless uid-range mapping: two setuid helpers kern
does not control.

The claim that survives is reach rather than milliseconds. On a Raspberry Pi 5, docker, podman,
runc, crun, bwrap, nerdctl, lxc-start and systemd-nspawn were all absent, checked one at a time;
kern ran there as the same static binary, copied over.

## aarch64

Same `/bin/true`, `--bind-rootfs` in both kern columns, medians of 12 alternating batches of 30.

| board | kern `KERN_NO_SCOPE=1` | kern default | bubblewrap |
|---|---:|---:|---:|
| Jetson Orin Nano | **4.6 ms** | 14.9 ms | 5.8 ms |
| Arduino UNO Q | **11.6 ms** | 60.3 ms | 14.9 ms |

At equal work kern is 21% faster than bubblewrap on both boards. The default is slower because it
spends a `systemd-run --user --scope` per box (10 ms on the Jetson, 49 ms on the UNO Q) to get a
cgroup cap bubblewrap never applies. Measured over SSH, where the login cgroup sits outside
`user@<uid>.service` and a `memory.max` write into kern's delegated slice is denied, so the scope
is the only way to cap there at all.
