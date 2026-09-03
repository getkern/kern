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

## kern against bubblewrap, settled

The table above is one session. This is the same question asked 23 times, because the answer moved
with how it was asked and the size of the margin was never stable enough to quote.

**23 replicas, 92,000 box starts, on a machine measured idle** (0.9% CPU busy, read from `/proc/stat`
over two seconds rather than from a load average that carries a minute of history). kern was faster in
**457 of 460 batches**, and not one bootstrap interval touched zero. The direction never moved. What
moved is the size:

| scheduler | kern | bubblewrap | margin |
|---|---:|---:|---:|
| free | **2.5 ms** | 2.75 ms | +9.2% |
| pinned to one core | **1.85 ms** | 2.0 ms | +6.6% |

Both runtimes drop about 0.7 ms with the core pinned, because the cache stays warm, and the margin
compresses with them: **part of what looks like a code difference is scheduling.** These two rows are
kern's DEFAULT, cgroup cap and all, which is not the same job as the namespace-matched table above and
is why the numbers differ from it. Reproduce with `sh scripts/bench-idle.sh 4`.

**Three variables each moved the answer by more than the answer**, which is why the script fixes all
three rather than documenting them:

- **The binary.** The shipped static-pie musl build starts a box in 2.372 ms; the glibc build
  `cargo build --release` produces on a normal distro reads 2.585, 9% slower, because it pays `ld.so`
  twice. Releases ship musl, so measuring the glibc build measures a binary nobody downloads.
- **The flags.** `KERN_NO_SCOPE=1` was once added to "level the field" and makes kern **0.22 ms
  SLOWER**, so it levels nothing.
- **The order.** Batches alternate and the starting runtime flips between replicas. Measured in
  sequence instead, bubblewrap alone read 3.0 one day and 2.7 the next: three times the margin.

The same binary reads **2.372, 2.490, 2.711 and 2.789 ms** depending on which of these you pick: a
spread of 0.4 ms, wider than any margin discussed here. A number without its binary, its flags and its
alternation stated is not a measurement.

The idle gate is part of the script and it refuses to conclude above 12% CPU busy. Its first version
used the load average and was wrong twice over: that number remembers the previous run, so running the
script twice in a row refused the second time. Its second version compared with `awk` under an Italian
locale, where `printf "%.1f"` emits a comma, so `12,5` parsed as 12 and the comparison was between
STRINGS: it rejected an idle machine at 5.9% and accepted a saturated one. Every `awk` in it is
`LC_ALL=C` now, and a gate that fails toward ACCEPTING is the wrong direction for a gate whose whole
job is to refuse.

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
