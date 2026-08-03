# Open items

Things kern knows it does not know, or does not do yet, written down on purpose. Declared debt is
cheaper than silent debt: everything here has a shape, a way to settle it, and a reason it has not
been settled. If you hit one of these, you are not the first, and nothing here is a surprise to us.

## kern does not see an installed `pasta` on WSL2, and reports it as not installed

On WSL2, with `passt` installed from apk and `/usr/bin/pasta` present, and a shell `PATH` that
contains `/usr/bin`, `kern pod create` printed the NOT-INSTALLED branch: "NO outbound (install
`passt`/`pasta` for egress)". Measured 2026-08-03 with the 0.6.34 binary, which tells that branch
apart from "installed but did not start", so the failing step is `which_pasta`, not pasta itself.

`which_pasta` reads `PATH`, joins `pasta` onto each entry and takes the first that `is_file()`. On
Linux with the same code and pasta in `/usr/bin`, it finds it. What is different under WSL is not
known, and guessing at it is what this file exists to prevent. The pod itself is unaffected: it comes
up loopback-only, which is also what the message says, so the consequence is a wrong CAUSE rather
than a wrong outcome.

Two measurement traps were hit while chasing it, and both are worth knowing before the next attempt.
`command -v` kept reporting `/usr/bin/pasta` after `apk del passt` had removed it, because the shell
caches command lookups; the file was gone and `ls` said so. And an earlier round appeared to show the
same symptom on a distro built from the fixed rootfs, but that image carried a kern built BEFORE the
branch existed, so its single message could not have said anything else.

## `stopping_a_box_leaves_no_timeout_watchdog_behind` fails about once in thirteen full runs

Measured 2026-08-03: one failure in 13 `cargo test --all` runs. The same test passes 10 times out of
10 run alone, and 6 out of 6 with six CPU spinners loading the machine, so neither isolation nor CPU
contention reproduces it. Eight further full-suite runs after the first failure were all green, and
the cause is therefore **not attributed**. A plausible story would be that the test's 5 s budget
(50 polls, 100 ms apart) is too tight while 703 tests are starting and tearing down boxes in
parallel, but that is a guess and this file exists to keep guesses out of the record.

What is measured, and points away from the product: the behaviour under test is the `--timeout`
watchdog fix from 0.6.32, verified then on the published binary (0 survivors of 6 where 0.6.31 left
6), and verified again on 2026-08-03 with the 0.6.34 binary over 8 consecutive runs, delta 0. The
test counts by a name unique to the test process, so a parallel test's box cannot be miscounted.

Operationally: if CI reddens on this test alone, re-run the job before reading anything into it, and
if it reddens twice in a row that is new information worth chasing. Settling it properly needs the
failing run to report how many processes were left and whether they exited a moment later, which the
assertion does not currently capture.

## The test suite leaves empty temp dirs behind

Every `cargo test --all` leaves a few empty directories in `/tmp`: `kern-cgcap-<pid>`,
`kern-help-test-<pid>`, `kern-it-cmp-<pid>`, `kern-it-xdg-wdog-<pid>`. Measured after six runs on
2026-08-03: 23 directories, 600 KB, all empty. It is test-only debris, invisible to anyone using
kern.

One of the five was a different thing and is fixed. `kern-oci-wh-perm-<pid>` did not merely survive
the test, it survived `rm -rf` from a shell: `cannot remove .../stg/dir/.wh.victim: Permission
denied`. That test deliberately sets a staging directory to mode 0555 and puts a whiteout marker
inside it, and an entry cannot be unlinked from a directory with no write bit. It already restored
the mode on the OTHER directory it locks, with a comment saying why, and simply did not do the same
for this one, so all four of its `remove_dir_all` calls failed behind a `let _ =`. One line, and the
test now leaves nothing.

What remains is the plain kind: `help_and_parser_agree.rs` builds its sandbox in a helper called once
per assertion and never removes it, and the others remove theirs on every exit path yet a directory
is still there afterwards, which is not yet explained. Not chased on 2026-08-03 because the first
lives in a helper shared by every assertion in that file, and rewriting shared test infrastructure
hours before a release trades a real regression risk for a few empty inodes.

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

Nine denied syscalls, in five families, return `ENOSYS` rather than killing the caller, so that software probing for an
optional fast path falls back instead of dying (`SECURITY.md` has the set and the measurement). That
choice is a deliberate compatibility trade, and it has a part we have measured and a part we have not.

Measured: the errno leaks nothing. A denied `io_uring_setup` and syscall number 998, which exists on
no kernel, are both `-1 ENOSYS` from inside the box, so a prober cannot tell "the filter refused this"
from "this kernel has no such call". Also measured: the enumeration cost is asymmetric. A permitted
syscall runs and returns its own errno, so the permitted set was always cheap to map; `ENOSYS` moves
nine calls out of the "costs a process per probe" bucket, while the 24 in the kill set stay in it.

Not measured, and stated as unknown rather than argued away: whether a cheaper map of the filter is
worth anything to an attacker who already has code execution inside the box. Mapping is not bypassing,
and we have no evidence either way. If it turns out to matter, the lever is to move the nine to
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

## RESOLVED: the Python SDK paid a 3.2 ms floor that was CPython's, not kern's

`kern_sandbox.run_code` latencies landed on three discrete values, 15.8, 31.5 and 64 ms, and a
natural distribution does not do that. Measured over 200 calls, `python:3.12-slim`, 2026-08-01: 188
at 15-16 ms, 10 at 31-32, 2 at 64.

The cause was `subprocess.Popen.wait(timeout=...)` in CPython's standard library, which does not
block on `waitpid`: it polls with an exponential backoff, from `subprocess.py` directly,

    delay = 0.0005                          # 500 us
    delay = min(delay * 2, remaining, .05)
    time.sleep(delay)

so its wake-ups fall at **0.5, 1.5, 3.5, 7.5, 15.5, 31.5, 63.5 ms**. Those were the observed clusters
to the decimal. The binding called it to enforce its own deadline, which is what selected the polling
branch.

Three measurements separated whose cost it was, all on the same host, image and workload:

| | p50 | shape |
|---|---:|---|
| `kern box --image python:3.12-slim -- python3 -c print(1)`, no binding | 12.28 ms | smooth, 10 to 15 |
| the same through the **Node** binding, which does not use CPython | 13.22 ms | smooth, 11 to 17 |
| the same through the **Python** binding | 15.79 ms | quantised: 15.5 / 31.5 / 64 |

Fixed in kern-sandbox **0.1.13**: the wait is a `poll(2)` on a pidfd, which becomes readable the
instant the box exits, so the deadline is enforced by the kernel instead of by a sleep loop, with a
fallback to the old polling wait wherever `pidfd_open` is unavailable. Re-measured over 200 calls:
p50 15.75 to 13.91, p90 31.86 to 16.16, p99 64.03 to 34.34, floor 15.61 to 11.74, and the three
clusters are replaced by a continuous distribution. The bare-box call, which the same rounding had
pinned to the 7.5 ms wake-up, measures 4.03.

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

## RESOLVED, and what was published about it was wrong

This section said the SDK test suites leave **boxes** behind: 2 `pysbx-*` after the Python suite and
5 `jssbx-*` after the Node one, invisible to `kern ps`, alive for 24 h on the SDK's `--timeout`
backstop. The count was right and the diagnosis was not, in the way that matters: **they were not
boxes**. One survivor was finally examined instead of counted, and it was `kern` itself at 884 KB
RSS, 0% CPU, one thread, asleep in `hrtimer_nanosleep`, with no children, the HOST's pid/user/mount
namespaces, and a cgroup inherited from whatever launched it. The box really was gone, and `kern ps`
was right to show nothing.

What survived was the `--timeout` **watchdog**, so the defect was in the kern binary and not in the
bindings at all. `--timeout N` forks that watchdog in the host namespace, before the box's
`unshare(CLONE_NEWPID)`, so that it can signal the box's ns-init. It then slept `N` out, and the only
thing that stopped it early was the supervisor's own cancellation on a normal exit. Kill the
supervisor before it reaches that line and the watchdog was orphaned for the remainder of the
deadline: 86405 s for an SDK box, so a day per box. `kern stop` on its own is a race, since it
SIGKILLs pid 1 and then sweeps the supervisor's process group, and it leaked 0 of 6 trials;
SIGKILLing the supervisor directly, which is exactly what both bindings do straight after `kern
stop`, leaked 6 of 6.

Fixed in kern **0.6.32**: the watchdog now waits on a pidfd for the box's exit with the deadline only
as a cap, so it leaves the moment there is nothing left to guard, whatever killed the supervisor and
whether or not anyone got to cancel it. Pinned by `stopping_a_box_leaves_no_timeout_watchdog_behind`,
which fails against the previous binary. Both suites now finish from a clean slate with **zero** kern
processes alive: 69 Python, 56 Node.

The earlier retraction stands and is kept. Commit `2728c08` had claimed the 0.1.12 concurrency tests
left 53 boxes of their own, from a count taken without clearing a manual reproduction run minutes
earlier. That makes two wrong readings of one phenomenon, and both came from counting processes
rather than opening one up.

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
