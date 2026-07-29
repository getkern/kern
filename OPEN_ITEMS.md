# Open items

Things kern knows it does not know, or does not do yet, written down on purpose. Declared debt is
cheaper than silent debt: everything here has a shape, a way to settle it, and a reason it has not
been settled. If you hit one of these, you are not the first, and nothing here is a surprise to us.

## 315 us of a bare box start are not attributed

`kern bench --rootfs` reports **2.4 ms** on the machine BENCHMARKS.md describes. In the UNCAPPED
configuration (the one comparable to bubblewrap, selected with `KERN_NO_SCOPE`) v0.6.21 measures
2.2 ms where 0.3.0 measured 1.7 ms on the same machine, each with the benchmark script of its own
era, bubblewrap steady at 2.8 and 2.7 as the control.

Of that ~500 us gap, **~185 us is attributed and named**: `proc-mask` 66 us (thirteen `mount` calls
that hide `/proc/kcore`, `kallsyms`, `kmsg`, `keys`, `latency_stats`, `timer_list`, `sched_debug`,
`scsi` and remount five more read-only), `cgroup-view` 39 us, seccomp +60 us, `dev` +20 us. Together
they close a container escape through `core_pattern`, so that part is a price with something bought
for it.

**The remaining ~315 us has no measured cause.** We are not offering one. A plausible story written
as a fact is how this project once shipped a `/dev/shm` leak that did not exist.

Already excluded, by measurement:

- **registry size**: 2.56, 2.57 and 2.63 ms with 0, 50 and 250 live entries.
- **the `KERN_SCOPE` to `KERN_NO_SCOPE` rename** between the two benchmark scripts: 2.81 vs 2.84 ms.
- **the benchmark's own batch budget**, which shortens slow runtimes: docker measures 290.3 ms over
  12 runs and 292.4 ms over 200.

How to settle it: bisect the releases between 2026-06-06 and now in the uncapped configuration, ten
or so builds, measuring each with the script of its own era and bubblewrap as the control.

Why it has not been done: the configuration it would explain is the synthetic one. **In the
configuration a user actually runs, with cgroup caps on, the same span went from 4.92 ms to 2.45 ms**,
because 0.3.0 re-exec'd through `systemd-run` eleven times per box and current kern caps directly.
Attributing a slowdown in a path we ourselves document as unrepresentative is not where the next hour
belongs.

What made the question askable at all: `KERN_TIMING` now instruments the PARENT process, which had
none, so half of a box start used to be invisible. That is also how `unshare(CLONE_NEWNET)` turned
out to cost 430 us, 17% of a start and the largest single item in it.

## Landlock is gated on the kernel ABI

`--landlock-rw` needs Landlock ABI 2+. On an older kernel kern says so and continues without it
rather than pretending the restriction is in place. There is no userspace fallback that would be
honest to call equivalent.

## The seccomp filter is a denylist

kern denies a named set of syscalls rather than allowing a named set. An allowlist is the stronger
shape and is where this should end up; the reason it has not moved is that a wrong allowlist breaks
working images silently, and the migration needs a corpus of real workloads to validate against
before it can be trusted. The denylist is enforced always, cannot be turned off, and the escape
vectors it covers are tested.

## `KERN_MAX_CONCURRENT` is best-effort

The fleet concurrency gate counts live boxes and then starts one, so two launches racing can both
pass. `KERN_FLEET_MEMORY_MAX` and `KERN_FLEET_PIDS_MAX` are real cgroup limits and do not have this
property. The concurrency count is a guard rail, not a boundary, and is documented as one.

## The `--memory not enforced` warning is gated on the request

`cgroup.rs` warns when `--memory` was ASKED FOR and cannot be applied, not when a cap would be
applicable and this box ended up without one. A box that takes the default 512 MiB on a host where
the memory controller is not delegated gets no warning. The correct predicate
(`memory_cap_enforceable()`) already exists; wiring the warning to it needs a host with
`cgroup_enable=memory` removed to verify against, which is a physical board rather than a code
change.
