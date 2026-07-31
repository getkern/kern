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

## The Python and Node SDK test suites leave two boxes each behind

Measured 2026-07-29 against this build, from a clean slate (zero `kern` processes): `pytest` in
`bindings/python` ends 61/61 green and leaves **2** `pysbx-*` boxes running; `node --test` in
`bindings/node` ends 50/50 green and leaves **2** `jssbx-*`. They carry the SDK's 24 h `--timeout`
backstop, so they do expire on their own, but until then `kern ps` does not list them and
`kern stop --all` answers "no running boxes to stop" while four of them are alive.

What it is NOT, each ruled out by measurement rather than by reading: a registry defect (a plain
detached box is listed and stopped correctly), the orphan-on-launcher-death bug (a box whose
launcher is SIGKILLed stays registered and `stop --all` ends it), and `KERN_NO_SCOPE=1`, which the
SDK sets on every sandbox and which on its own leaves a box perfectly visible and stoppable. The
`Kernel.__exit__` path closes stdin, waits 3 s and calls `_kill()` on timeout, and `_kill()` runs
`kern stop <name>` before SIGKILLing the group, so on paper it should clean up.

The mechanism is therefore somewhere in the binding's own lifecycle and is NOT isolated yet. It
lives in `bindings/`, which ships as the separately versioned `kern-sandbox` package rather than in
the kern binary, so it is written down here instead of being fixed in a hurry the afternoon of a
release: a change to a lifecycle whose failure mode is not understood is how a leak becomes a kill
of something that should have lived.

## Binary size: measured 2026-07-31, deliberately NOT applied

Published: **1893344 B x86_64 (1.81 MB)**, **1577448 B aarch64 (1.50 MB)**. Growth since v0.6.22 is
**+2.9%** over six releases, which is not a problem and was the thing worth checking first.

The release profile is already at its limit (`opt-level="z"`, `lto="fat"`, `codegen-units=1`,
`panic="abort"`, `strip=true`). Two negative results, recorded so nobody spends an evening on them again:

- **`-C force-unwind-tables=no` alone changes nothing.** Byte-identical output, identical `.text`,
  identical `.eh_frame` (186980 B). The tables come from the precompiled std for the musl target;
  no flag on our own code reaches them. This is why `build-std` is the only real lever.
- **`opt-level="s"` is 11.5% WORSE than `"z"`** (2110432 vs 1893344, `.text` 1.72 vs 1.43 MB).
  The existing choice was right; now there is a number instead of a comment.

What does work, rebuilding the standard library on nightly:

| variant | x86_64 | aarch64 | panic messages |
|---|---|---|---|
| published | 1.81 MB | 1.50 MB | intact |
| `-Z build-std` | 1.40 MB (-22.8%) | not measured | **intact** |
| `+ -Cpanic=immediate-abort -Cforce-unwind-tables=no` | 1.22 MB (-32.6%) | 1.00 MB (-33.4%) | **gone** |

`.eh_frame` drops from 186980 B to **144 B**; `.text` falls 23%. The smallest x86_64 build passes
**13/13** of `kern-verify.sh` and is marginally faster (2.3 ms median against 2.5).

**Decision: `immediate-abort` never, `build-std` only after launch, and only if the cost is accepted.**

- A panic then prints nothing at all: no file, no line. The 34 production `unwrap`s are safe *by
  construction*, and "by construction" is exactly the class of claim that turned out false five times
  in one day (`-n5`, `--json=1`, the `rm -rf` comment, flags "verified by reading"). The day the 35th
  is wrong, "file and line" versus "it died" is ten minutes versus a week.
- `cargo test` cannot run under that profile: its harness catches panics to report failures, so the
  shipped binary would stop being the tested one where panics are concerned.
- nightly in CI is a new way to break that does not exist today, across 8 assets on 4 targets. And a
  contributor on stable could no longer build the published binary, which on an Apache-2.0 project
  soliciting contributions costs more than 400 KB.
- aarch64 was cross-compiled only, never executed on the Pi 5, Jetson or UNO Q.

## `kern ps` prints the mapping recorded at start, not a live probe

A published port is now a fact at box **start**: the forwarder binds its host socket before `kern box`
prints "started", and a bind that fails refuses the box instead of leaving a mapping nothing serves.
What `kern ps` prints afterwards is still the mapping stored in the registry, not an answer to "is
anything listening on that port right now".

In practice the two now agree. A forwarder is a child of the box's supervisor and is torn down with it,
so a live box implies live forwarders. The gap that remains is a forwarder that dies on its own, killed
by hand or by the OOM killer, while its box keeps running: `kern ps` would still show the mapping.

How to settle it: record the forwarder PIDs in the registry entry and have `ps` check them, one
`kill(pid, 0)` per published port. It was not done with the rest because the honest check is "does the
forwarder still exist", not "does something listen": probing the port would report the mapping as
healthy when an unrelated process grabbed it after the forwarder died, which is a worse answer than no
answer at all.

## `--ssh` needs `newuidmap`, and three of our four boards do not have it

`--ssh` forks an sshd inside the box, and sshd's privilege separation needs more than one uid in the
box's user namespace. kern's default single-uid map does not provide that, so `--ssh` requires the
`--uid-range` path: the setuid `newuidmap`/`newgidmap` helpers plus an `/etc/subuid` + `/etc/subgid`
allocation for the caller.

Measured 2026-07-31: present on an Ubuntu x86_64 desktop, **absent on a stock Raspberry Pi OS, on the
Arduino UNO Q and on the Jetson Orin Nano**. kern detects it and warns before the box starts ("--ssh
needs a uid range … so sshd will refuse the login"), which is the honest behaviour and not a defect,
but it means the flag most likely to be reached for on a headless board is the one least likely to
work there. The failure a user then sees from the client is
`kex_exchange_identification: Connection closed by remote host`, which says nothing about uid maps.

`kern doctor` already reports the ingredient (`--uid-range / --user / --ssh: newuidmap + /etc/subuid
present`), so the environment fact is covered. What is not: the warning kern prints at box start does
not name the fix, and the failure the client then sees is
`kex_exchange_identification: Connection closed by remote host`, which says nothing about uid maps.

How to settle it: (1) put the fix in the warning itself (`apt install uidmap`, and the `/etc/subuid`
line if that is what is missing), so the message is actionable on the board where it fires; (2) look at
whether a two-uid map is enough for sshd's privilege separation, which would drop the `newuidmap`
dependency entirely. Neither is started. Installing `uidmap` on a Raspberry Pi 5 on 2026-08-01 was
enough to make `--ssh` work there with no other change.
