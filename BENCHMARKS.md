# Benchmarks

One isolated `/bin/true`, x86_64 desktop, kernel 7.0.0, static musl binary, 200 runs per batch.
Reproduce with `python3 examples/benchmark.py`; your numbers will differ with CPU, kernel and
filesystem.

**Check what `docker` is on your machine before you compare against it.** kern used to ship an
optional drop-in that made `~/.local/bin/docker` a symlink to `kern`, and a benchmark that shells out
to `docker` then measured kern against itself and reported it as the competitor. MEASURED here on
2026-09-14: `docker run --rm alpine true` read 4.2 ms, which was not Docker being fast, it was kern
answering to Docker's name, next to a real podman at 285 ms in the same run. **That drop-in was
removed on 2026-09-19** - kern does not answer to another tool's name - but a symlink somebody
already made does not disappear with it, and `docker` can be other things too. `readlink -f $(command
-v docker)` settles it in one line, `docker --version` settles it in another, and `examples/benchmark.py`
now asks both before it measures anything.

| runtime | cold start | 200 in parallel |
|---|---:|---:|
| **kern** `box --rootfs` | **2.5 ms** | **0.11 s** |

<sub>2.5 ms is the round figure this file publishes and it sits inside the spread, not at its centre:
today the same binary read 2.496 in one harness and 2.561 in the other, and 1.96 with the core
pinned. The protocol below is what makes a single number mean anything.</sub>

### v0.9.1 is 0.05 ms FASTER than v0.9.0, after two wrong answers about why it was slower

The OOM fix in this release parks kern's supervisor outside the cgroup that carries
`memory.oom.group = 1`, so the process that reports a kill is not killed by it. The first cut did
that by creating a sibling cgroup per box, and cost 0.10 ms.

| | median | |
|---|---:|---|
| v0.9.0 | 2.346 ms | |
| v0.9.1, first cut | 2.464 ms | the sibling leaf, created on every box |
| **v0.9.1, shipped** | **2.300 ms** | the leaf only where it is needed |

Faster than the first cut in 24 of 24 paired batches, and faster than v0.9.0 in 21 of 24.

Those are the paired harness. `bench-idle.sh`, which is what the published figure quotes, reads the
shipped v0.9.1 at **2.411 and 2.398 ms** free and **1.780 and 1.810** pinned, ahead of bubblewrap by
8.6% to 11.7% and faster in 20 of 20 in all four replicas. **That bubblewrap margin has not held**: it
came out the other way on 2026-09-19 and back to a few percent on 2026-09-20, so read
"no margin to quote" below before quoting any margin from this paragraph. **The published number stays 2.4 ms**: the
release is measurably faster than v0.9.0 and the margin is smaller than the rounding, so moving the
headline to 2.3 would be quoting the friendlier of two harnesses.

**The leaf is needed on exactly one path.** `child` is freshly created, so the supervisor cannot
already be inside it; the only cgroup that can take the supervisor down with the workload is its own.
That happens when a scope or managed unit arms `origin` with `oom.group = 1`, which the code does when
`prepare_delegated_scope` did not manage to move kern into a leaf of its own. Everywhere else the
supervisor is already outside the blast radius and the leaf is pure cost.

Correctness re-checked in both layouts on four hosts and four systemd versions (249, 252, 255, 257):
the OOM message survives, `memory.max` and `pids.max` inside the box read the caps exactly, a wide cap
still lets the same workload finish, and `--egress-allow` still gets a 403 from its proxy.

### How the 0.10 ms was mis-attributed, twice

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
not a measurement. It IS shipped, after the other postures said so: four hosts, four systemd versions, and the leaf kept
on the one path where the supervisor's own cgroup is the one being armed. The table at the top of this
file is the result.


## kern against bubblewrap: no margin to quote, and the 2026-09-19 deficit did not reproduce

The table above is one session. This is the same question asked 33 times, because the answer moved
with how it was asked and the size of the margin has never been stable enough to quote.

**EVERY ROW IN THIS SECTION IS AT MATCHED WORK.** A bubblewrap invocation without the `--unshare-*`
flags keeps the host's network namespace, PID table, IPC, UTS and cgroup, so it is not the same job as
a box start and it is not raced against one here. A reader who drops those flags will measure a
bubblewrap that is about 0.23 ms faster than a box start and will be measuring a different job. The
namespace-matched invocation, to paste:

```
bwrap --unshare-user --unshare-pid --unshare-ipc --unshare-uts --unshare-net --unshare-cgroup \
      --ro-bind <rootfs> / --proc /proc --dev /dev --die-with-parent /bin/busybox true
```

Even matched on namespaces, kern's default still does MORE per start: an overlay instead of a bind, a
cgroup v2 memory and pids cap written and read back, a seccomp allowlist, and a lifecycle record. The
`--bind-rootfs` rows drop the overlay, which is as close as the two get to identical work.

### 2026-09-20, the shipped binary, sample-by-sample alternation

`v0.9.35-60-g1034dd0` built with the release recipe, bubblewrap 0.9.0, machine at 1.2 to 2.0% CPU busy
read from `/proc/stat`, `powersave` governor. n=400 per cell, paired, alternated every sample, 95%
intervals by bootstrap. Two fixtures are shown because they disagree and the disagreement is the point:
one is the invocation above, the other is the rootfs, argv and flags `bench-idle.sh` itself uses. That
second one differs in three ways, and each was measured on its own before being accepted: it omits
`--unshare-cgroup` (worth -4.6 us, interval spanning zero), omits `--die-with-parent` (worth 26.3 us,
in bubblewrap's favour) and binds read-write instead of read-only (17.4 us, spanning zero). About
0.03 ms in total, which is smaller than the rows it appears in but is not nothing, so it is named here
rather than folded in.

| scheduler | kern variant | fixture | bubblewrap | kern | margin |
|---|---|---|---:|---:|---:|
| free | default | this file's | 2.877 ms | **2.686 ms** | +6.4% |
| free | default | `bench-idle.sh`'s | 2.776 ms | **2.638 ms** | +5.0% |
| pinned to one core | default | this file's | 2.265 ms | **2.196 ms** | +3.8% |
| pinned to one core | default | `bench-idle.sh`'s | 2.184 ms | 2.159 ms | **indistinguishable** |
| free | `--bind-rootfs` | this file's | 2.797 ms | **2.411 ms** | +13.4% |
| pinned to one core | `--bind-rootfs` | this file's | 2.225 ms | **2.051 ms** | +7.8% |

`bench-idle.sh` itself, which batches instead of alternating every sample, was run ten times the same
day: free scheduler +0.3% to +3.1%, pinned to one core -3.7% to +0.2%, with six of the ten intervals
containing zero.

**So: on the free scheduler kern leads by roughly 5 to 6%, and pinned to one core the two are
indistinguishable to within a few percent that depends on the harness.** That is a smaller and less
stable margin than the 9% this repository used to quote, and it is not a deficit either.

### What was published here on 2026-09-19, and why it is still here

That day the same question came out the other way, and the measurement stays in the file because
deleting a result that has since moved is how a benchmark section becomes marketing:

| scheduler | kern | bubblewrap | margin |
|---|---:|---:|---:|
| free | 3.11 ms | **2.87 ms** | -7.7% |
| pinned to five cores | 2.41 ms | **2.26 ms** | -6.0% |
| pinned to one core | 2.53 ms | **2.24 ms** | -11.4% |

Not one interval touched zero, and the direction held across both start orders. Five explanations were
tested that day and every one failed: not a kern regression, not the cgroup cap (`KERN_NO_SCOPE=1`
makes kern 150 us SLOWER), not a bubblewrap update (both `.deb` builds were extracted and raced, 6.8 us
apart with the interval spanning zero), not the CPU clock, not the pinning width.

**Two changes landed between that run and this one, and together they are the size of the gap that
disappeared:** `d54162e` moved the CPU topology off the overlay upper onto a tmpfs (+148.7 us) and
`1034dd0` replaced a ten-deep absolute path per CPU with `mkdirat` from a directory fd (+10.6 us).
About 0.16 ms, against a deficit of 0.15 to 0.29 ms. That is consistent, not proven: nothing was held
fixed across the two dates except the machine.

### What is still not understood

`bench-idle.sh` puts kern 1 to 4% behind on its pinned replicas where sample-by-sample alternation on
**its own fixture** finds no difference at all. Batching against alternation was tested directly on the
same two commands and moved the answer by 0.025 ms without changing its sign, so it does not account
for all of it. Until it does, the pinned rows carry a harness-dependent residual of a few percent and
the honest summary is the one above: no single margin to quote, in either direction.

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

At equal work kern is 21% faster than bubblewrap on both boards. That is aarch64, measured on
2026-09-02 and not re-run since, so it neither confirms nor contradicts the x86 rows above: it is a
different machine class, and on x86 the same question has since read anywhere from -11% to +13%. The default is slower because it
spends a `systemd-run --user --scope` per box (10 ms on the Jetson, 49 ms on the UNO Q) to get a
cgroup cap bubblewrap never applies. Measured over SSH, where the login cgroup sits outside
`user@<uid>.service` and a `memory.max` write into kern's delegated slice is denied, so the scope
is the only way to cap there at all.
