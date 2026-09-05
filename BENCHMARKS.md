# Benchmarks

One isolated `/bin/true`, x86_64 desktop, kernel 7.0.0, static musl binary, 200 runs per batch.
Reproduce with `python3 examples/benchmark.py`; your numbers will differ with CPU, kernel and
filesystem.

| runtime | cold start | 200 in parallel |
|---|---:|---:|
| **kern** `box --rootfs` | **2.5 ms** | **0.11 s** |

<sub>2.5 ms is the round figure this file publishes and it sits inside the spread, not at its centre:
today the same binary read 2.496 in one harness and 2.561 in the other, and 1.96 with the core
pinned. The protocol below is what makes a single number mean anything.</sub>

### v0.9.1 costs 0.10 ms against v0.9.0, on purpose

Measured after the fact rather than assumed, both binaries built the way the release is built
(nightly, `-Z build-std`, `panic=immediate-abort`), and measured twice, in two harnesses, because a
number that moves a published figure should not rest on one.

`scripts/bench-idle.sh`, the harness this file documents, run on each binary in turn on the same idle
machine minutes apart:

| | free scheduler | pinned | margin over bubblewrap |
|---|---:|---:|---|
| v0.9.0 | **2.407 ms** | 1.780 ms | +13.3% and +10.6%, 20/20 and 20/20 |
| v0.9.1 | **2.561 ms** | 1.964 ms | +8.2% and +2.6% |

A second harness, 30 alternating batches of 40 with the order flipping every batch, agrees on the
direction and reads a smaller gap: 2.496 ms against 2.385, **+0.111 ms, with v0.9.1 faster in 1 of 30
paired batches**. Fifteen would be a tie. An earlier run of the same harness at 14 batches said
+0.101 and 0 of 14.

So the gap is between 0.10 and 0.18 ms depending on how it is measured, and it is not variance in
either. The 2.4 ms this file used to quote is still v0.9.0's number; it is not v0.9.1's.

**No compiler flag takes it back, and that is the confirmation rather than the disappointment.**
`Cargo.toml` justifies `opt-level = "z"` by asserting that this start is syscall-bound rather than
CPU-bound. Tested directly: a third binary built with the release configuration PLUS
`-C target-cpu=native`, on the i7-14700KF it was built for, run in the same harness in the same
session as the other two.

| | free | pinned |
|---|---:|---:|
| v0.9.1, `target-cpu=native` | 2.563 ms | 1.955 ms |
| v0.9.1, the portable release build | 2.572 ms | 1.983 ms |
| v0.9.0 | 2.449 ms | 1.799 ms |

The most aggressive codegen this machine can produce buys 0.009 ms free and 0.028 pinned, which is
inside the run-to-run drift: v0.9.0 itself read 2.407 in one run and 2.449 in the next. The
assertion in `Cargo.toml` now has a measurement under it: the cost is a syscall, and no compiler
removes a syscall.

### Where the 0.10 ms goes, after two wrong answers

**The first answer was wrong and the second answer was wronger, and both were published before they
were checked.** Recorded here rather than quietly replaced, because the way each failed is the useful
part.

FIRST: `strace` showed one extra `mkdir` and `rmdir` against v0.9.0, the supervisor's sibling cgroup,
and cgroup costs measured on this host made the arithmetic fit. That story was right and the
arithmetic that supported it was not: the numbers came from a Python harness and were measuring
Python. In C, on the same host:

| | |
|---|---:|
| `mkdir` of a cgroup | 90.5 us |
| `rmdir` | 12.6 us |
| moving a process in (`cgroup.procs`) | 19.4 us, FLAT from a 0 MB child to a 256 MB one |
| `open()` of `cgroup.procs` | 4.1 us |

The migration is cheap and does not scale with the child's footprint, so re-charging is not the
mechanism. The `mkdir` is what costs.

SECOND: a variant was built to test whether the leaf was the cost, it saved 0.008 ms, and that was
written up as "the leaf is not the cost". **The variant never ran.** A refactor removed the branch
that disabled the leaf, so the experiment measured the shipped code against itself. `strace -e mkdir`
would have shown it in one command and was not run until afterwards, when it printed one `-sup`
`mkdir` in both arms.

WITH THE EXPERIMENT ACTUALLY ENABLED, verified first by that same `strace` printing 0 against 1:

| | median |
|---|---:|
| sibling leaf (shipped) | 2.498 ms |
| supervisor stays where it already is | **2.331 ms** |
| v0.9.0 | 2.405 ms |

The variant saves **0.167 ms and wins 20 of 20 paired batches**, and it is faster than v0.9.0 by
0.074 ms while keeping both properties the leaf exists for: the OOM message survives, and
`memory.max` inside the box reads 134217728 for `--memory 128M`.

So the cost IS the leaf, the first story was right, and the measurement that seemed to refute it was
not a measurement. This is not shipped: it changes the code that decides who dies in an OOM, it has
been validated on one host and one posture, and a variant that looks free is exactly the kind that
needs the other postures before it is believed.


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
