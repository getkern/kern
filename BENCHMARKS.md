# Benchmarks

One isolated `/bin/true`, x86_64 desktop, kernel 7.0.0, static musl binary, 200 runs per batch.
Reproduce with `python3 examples/benchmark.py`; your numbers will differ with CPU, kernel and
filesystem.

| runtime | cold start | 200 in parallel |
|---|---:|---:|
| **kern** `box --rootfs` | **2.5 ms** | **0.11 s** |
| bubblewrap | 2.5 ms | 0.13 s |
| runc (rootless) | 13.1 ms | 0.29 s |
| podman `run --rm` | 296.6 ms | 43.1 s |
| docker `run --rm` | 287.7 ms | 16.7 s |

The bubblewrap column is namespace-matched, or it is not a comparison: `kern box` always makes a
network namespace, so bwrap is given `--unshare-user --unshare-pid --unshare-ipc --unshare-uts
--unshare-net --bind <rootfs> / --proc /proc --dev /dev`.

**This table cannot separate kern from bubblewrap, and says so rather than pretending.** Measured one
runtime after the other, which is what this script does, both read 2.5 ms: the difference between them
is smaller than the drift between two batches taken minutes apart. Separating them takes ALTERNATING
batches, which is the section below. Both columns here run WITHOUT a cgroup cap, which is what makes
them the same job; the default `kern box` adds the cap on top. The gap this table DOES establish is
the one to the engines, two orders of magnitude away, and no measurement subtlety is needed to see it.
`box --image` is 3.4 ms (median of 7 batches of 100), which is the ~3.5 ms quoted on the front page:
that figure is rounded up, so it errs against kern rather than for it. About 1 ms of it is the
rootless uid-range mapping, two setuid helpers kern does not control.

Stopping a service whose init handles SIGTERM: kern 2.3 ms, docker 162 ms, podman 194 ms (medians,
same host, same day). The previous figures here read 310 and 380 ms for docker and podman, which
OVERSTATED both: they are corrected downward against kern's own comparison, because a number that
flatters is the one nobody re-checks. Measured with `trap "exit 0" TERM` as PID 1. Without a handler
the same command takes docker and podman about 10.2 s each, because PID 1 ignores a signal it has no
handler for and both wait out a 10 s grace period before SIGKILL.

The claim that survives is reach rather than milliseconds. On a Raspberry Pi 5, docker, podman,
runc, crun, bwrap, nerdctl, lxc-start and systemd-nspawn were all absent, checked one at a time;
kern ran there as the same static binary, copied over.

## kern against bubblewrap, settled

The table above is one session. This is the same question asked 23 times, because the answer moved
with how it was asked and the size of the margin was never stable enough to quote.

**35 replicas, 116,000 box starts, on a machine measured idle** (CPU busy read from `/proc/stat` over
two seconds, not from a load average that carries a minute of history). **The direction has never once
flipped**: kern led in 457 of 460 batches over the first 23, and in **238 of 240** over the twelve most
recent.

The four most recent were run against the **binary attached to the release**, downloaded and
checksummed, rather than a local build, and that turned out to matter:

| scheduler | kern | bubblewrap | margin |
|---|---:|---:|---:|
| free | **2.35 ms** | 2.60 ms | +9.6% |
| pinned to one core | **1.76 ms** | 1.89 ms | +7.3% |

**Which binary is a variable, and it was hiding inside the spread.** The four replicas before these
read +5.3, +5.1, +6.7 and +5.2 free, on a `cargo build --release --target ...-musl` that was two days
old. The shipped binary is built with `build-std` and `panic=immediate-abort`, is faster in absolute
terms (2.35 against 2.41) and leaves bubblewrap unchanged, so the margin widens. Both are honest
numbers about different binaries, and only one of them is the binary anyone downloads. That is the
same lesson as musl-versus-glibc, one level further in, and it is why this section names the artifact.

Earlier sessions on local builds read between +5% and +11%. The claim quoted elsewhere in this
repository is **about 9%**, measured on the release artifact, and the range is stated rather than
hidden.

Both runtimes get roughly 0.6 ms faster with the core pinned, because the cache stays warm, and the
margin compresses with them: **part of what looks like a code difference is scheduling.** These rows
are kern's DEFAULT, cgroup cap and all, which is not the same job as the namespace-matched table above
and is why the numbers differ from it. Reproduce with `sh scripts/bench-idle.sh 4`.

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
