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

## Whether a survivable denial helps an attacker map the filter is unresolved

Five denied syscalls return `ENOSYS` rather than killing the caller, so that software probing for an
optional fast path falls back instead of dying (`SECURITY.md` has the set and the measurement). That
choice is a deliberate compatibility trade, and it has a part we have measured and a part we have not.

Measured: the errno leaks nothing. A denied `io_uring_setup` and syscall number 998, which exists on
no kernel, are both `-1 ENOSYS` from inside the box, so a prober cannot tell "the filter refused this"
from "this kernel has no such call". Also measured: the enumeration cost is asymmetric. A permitted
syscall runs and returns its own errno, so the permitted set was always cheap to map; `ENOSYS` moves
five calls out of the "costs a process per probe" bucket, while the 24 in the kill set stay in it.

Not measured, and stated as unknown rather than argued away: whether a cheaper map of the filter is
worth anything to an attacker who already has code execution inside the box. Mapping is not bypassing,
and we have no evidence either way. If it turns out to matter, the lever is to move the five to
`SIGSYS` and lose the fallback behaviour, which is a compatibility decision, not a hard one.

## The integration tests used fixed box names, and it was not a kern defect

Recorded because the diagnosis took a wrong turn first. Two integration tests failed once during a
loaded session, `box_run_hardening_uts_net_seccomp` with "loopback present" and
`many_boxes_share_one_bind_rootfs_concurrently`, and nine consecutive full runs afterwards were green,
which is the worst shape a failure can have: it looks like an isolation regression and cannot be
reproduced on demand.

Reproduced deliberately by running four instances of the test binary at once: **40 of 40 executions
failed**. The cause was in the tests. Every box name was a fixed literal (`t`, `isobox`, `c0`..`c11`,
`cgexec`) and the registry those names live in is per-USER, not per-test-process, so two runs collide
and kern correctly refuses the second with `a box named 'c0' is already starting or running`. Any
other process on the machine starting a box called `t` would have done the same.

kern behaved correctly throughout. What was broken was that the tests could not say so: `kern_out`
retried five times and then returned an empty stdout, and the next assertion reported a missing
loopback for a box that had never started. That mislabelling was the real defect, and it is fixed
independently of the names: the helper now fails with the exit status and the box's own stderr, and
the 12-box concurrency test collects each failure's reason instead of counting successes.

After both fixes, locally: 60 parallel executions with zero failures, and three consecutive full
suites at 691 tests green.

**The fix is NOT in the tree, and that is the honest part of this entry.** Pushed twice, `0eb338b`
and `923c987`, and GitHub's CI went red both times on the `test` step with nothing but
`Process completed with exit code 101`. The job log needs admin rights on the repository to download,
so the failure could not be read, and three attempts to reproduce the runner's conditions locally all
came back green: the full suite under an `LD_PRELOAD` that makes `unshare(2)` return `EPERM`, which is
what AppArmor does to the runner and what `userns_plausible()` probes for, passes 691 tests with zero
failures. So the cause is something the simulation does not capture.

`crates/kern-cli/tests/sandbox_run.rs` is therefore back at the last green revision and main is green.
The defect it addressed is real and reproducible on demand (four concurrent runs of the binary, 40 of
40 red), it just does not bite CI, which runs the suite once on a host where these tests skip. Redo it
with the job log in hand: the two halves are unique per-process box names and a `kern_out` that fails
with the box's own stderr instead of returning an empty stdout for the next assertion to mislabel.

## The Python SDK pays a 3.2 ms floor that is CPython's, not kern's

`kern_sandbox.run_code` latencies land on three discrete values, 15.8, 31.5 and 64 ms, and a natural
distribution does not do that. Measured over 200 calls, `python:3.12-slim`, 2026-08-01: 188 at 15-16
ms, 10 at 31-32, 2 at 64.

The cause is `subprocess.Popen.wait(timeout=...)` in CPython's standard library, which does not block
on `waitpid`: it polls with an exponential backoff, from `subprocess.py` directly,

    delay = 0.0005                          # 500 us
    delay = min(delay * 2, remaining, .05)
    time.sleep(delay)

so its wake-ups fall at **0.5, 1.5, 3.5, 7.5, 15.5, 31.5, 63.5 ms**. Those are the observed clusters
to the decimal. `bindings/python/kern_sandbox/__init__.py` calls it at line 899 to enforce its own
deadline, which is what selects the polling branch.

Three measurements separate whose cost it is, all on the same host, image and workload:

| | p50 | shape |
|---|---:|---|
| `kern box --image python:3.12-slim -- python3 -c print(1)`, no binding | 12.28 ms | smooth, 10 to 15 |
| the same through the **Node** binding, which does not use CPython | 13.22 ms | smooth, 11 to 17 |
| the same through the **Python** binding | 15.79 ms | quantised: 15.5 / 31.5 / 64 |

So the box is not quantised and neither is Node. The real work is 12.28 ms and the first useful poll
lands at 15.5, which makes **3.2 ms per call, 26%, pure sleep**, plus a tail that doubles when the
process finishes just after a check.

The shape of the fix, not applied and deliberately not applied before a release: the two reader
threads already reach EOF when the box closes its pipes, which is exactly when it exits, so joining
them with the deadline and then calling `proc.wait()` with NO timeout uses the blocking `waitpid`
path and never polls. The deadline stays enforceable by a watchdog that tears the box down, which is
what labels a `timeout` fault today. It is a change to a lifecycle whose other failure mode is still
open two entries above, so it wants its own release and its own measurement, not the eve of one.

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

## The Python and Node SDK test suites leave boxes behind

Re-measured 2026-08-01 at kern-sandbox 0.1.12, each run from a clean slate (zero `kern box`
processes): `pytest` in `bindings/python` ends 65/65 green and leaves **2** `pysbx-*` boxes running;
`node --test` in `bindings/node` ends 54/54 green and leaves **5** `jssbx-*`. The Node side was 2 when
this was first written on 2026-07-29, so the cost tracks the number of execution tests rather than
being fixed. They carry the SDK's 24 h `--timeout` backstop, so they do expire on their own, but until
then `kern ps` does not list them and `kern stop --all` answers "no running boxes to stop" while seven
of them are alive.

**It is confined to the test suites. Normal SDK usage does not leak**, and that was measured rather
than assumed: against the published 0.1.12 in a clean venv, ten sequential `run()`, ten sequential
`run_code()`, sixteen concurrent `run()` and sixteen concurrent `run_code()` each leave **zero** boxes
behind. So the mechanism is in what the suites do (timeout and kill paths, most likely) and not in the
per-call lifecycle a user exercises.

A retraction belongs here, because the wrong version of this section was published first. Commit
`2728c08` claimed the concurrency regression tests added in 0.1.12 left 53 boxes of their own and made
them reap what they start. That attribution was wrong: it came from a count taken WITHOUT clearing the
manual 40-thread and 30-call reproduction runs done minutes earlier, so those boxes were counted as
the suites'. Measured properly, from a clean slate and with the reaping removed, the full Python suite
leaves 2 with the new test and 2 without it, and the Node suite leaves 5 either way. The tests
contribute nothing, and the reaping code has been removed rather than left in place justified by a
story that does not hold.

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

## The Python and Node SDK test suites leave boxes behind

Re-measured 2026-08-01 at kern-sandbox 0.1.12, from a clean slate (zero `kern box` processes):
`pytest` in `bindings/python` ends 65/65 green and leaves **2** `pysbx-*` boxes running; `node --test`
in `bindings/node` ends 54/54 green and leaves **5** `jssbx-*`. The Node side was 2 when this was
first written on 2026-07-29 and is 5 now, so it tracks the number of execution tests rather than
being a fixed cost. They carry the SDK's 24 h `--timeout` backstop, so they do expire on their own,
but until then `kern ps` does not list them and `kern stop --all` answers "no running boxes to stop"
while seven of them are alive.

It scales with the CALLS, not with the suites: the concurrency regression tests added in 0.1.12 fire
24 and 16 calls, and left **60** boxes behind before they were made to reap what they start. Those
two tests now kill, by pid difference, only the boxes they themselves created, which is a workaround
inside a test for a defect in the product and is marked as one: when the lifecycle bug below is
settled, that code goes.

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
