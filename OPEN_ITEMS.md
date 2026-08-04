# Open items

What kern does not do yet, or does not know. Each entry says what it costs you and what would
settle it. Resolved items live in [CHANGELOG.md](CHANGELOG.md), not here.

## The seccomp filter is a denylist

kern denies a named set of syscalls instead of allowing a named set. An allowlist is the stronger
shape and is where this should end up; a wrong allowlist breaks working images silently, so the
migration needs a corpus of real workloads to validate against first. Two of the rules match a
syscall number, and a third reads `clone`'s flags out of the register they arrive in and refuses
only the namespace-creating ones, since `clone` cannot be denied by number without taking `fork`
with it. The filter is always on and cannot be turned off.

## Whether a survivable denial helps an attacker is not known

Ten denied syscalls return `ENOSYS` instead of killing the caller, so software probing for an
optional fast path falls back rather than dying. [SECURITY.md](SECURITY.md) has the set.

Measured: the errno leaks nothing, because a denied `io_uring_setup` and a syscall number no kernel
implements are both `-1 ENOSYS` from inside the box. Not measured: whether a cheaper map of the
filter is worth anything to an attacker who already has code execution in the box. Mapping is not
bypassing, and there is no evidence either way. If it turns out to matter, the lever is to move
those ten to `SIGSYS` and lose the fallback behaviour.

## Landlock is gated on the kernel ABI

`--landlock-rw` needs Landlock ABI 2+. On an older kernel kern says so and continues without it
rather than pretending the restriction is in place. None of the three ARM boards tested ships it.

## `--ssh` needs `newuidmap`, and a fresh board does not ship it

sshd's privilege separation needs more than one uid in the box's user namespace, so `--ssh`
requires the `--uid-range` path: the setuid `newuidmap`/`newgidmap` helpers plus an `/etc/subuid`
and `/etc/subgid` allocation. Measured absent on a stock Raspberry Pi OS, on the Arduino UNO Q and
on the Jetson Orin Nano. kern warns before the box starts, but the warning does not name the fix,
and the failure the client then sees (`kex_exchange_identification: Connection closed by remote
host`) says nothing about uid maps. Installing `uidmap` was enough to make it work on a Pi 5.

## `pasta` refuses to start on WSL2

A pod there comes up loopback-only, and kern reports why: `Couldn't open user namespace
/proc/<pid>/ns/user: Permission denied`. Running as uid 0 inside the distro is not enough. Why that
permission is refused there and granted on every Linux host tested is not established. The
consequence is bounded: services still reach each other by name, only egress is missing.

## The `--memory not enforced` warning is gated on the request

The warning fires when `--memory` was asked for and cannot be applied, not when a box ends up with
no cap at all. A box taking the default 512 MiB on a host that does not delegate the memory
controller gets no warning. `--pids-limit` is gated the same way and for the same reason: warning
about the default on every box start on such a host would be noise that trains the reader to ignore
the line. The correct predicate (`memory_cap_enforceable()`) already exists; wiring the warning to
it needs a host with `cgroup_enable=memory` removed to verify against.

## `KERN_MAX_CONCURRENT` is best-effort

The fleet gate counts live boxes and then starts one, so two launches racing can both pass.
`KERN_FLEET_MEMORY_MAX` and `KERN_FLEET_PIDS_MAX` are real cgroup limits and do not have this
property. The concurrency count is a guard rail, not a boundary.

## `kern ps` prints the mapping recorded at start, not a live probe

A published port is a fact at box start: the forwarder binds its host socket before `kern box`
prints "started", and a bind that fails refuses the box rather than leaving a mapping nothing
serves. What `ps` prints afterwards is the registry entry. A forwarder is a child of the box's
supervisor and dies with it, so the gap is narrow: a forwarder killed by hand or by the OOM killer
while its box keeps running would still show.

## 315 us of a bare box start are not attributed

In the UNCAPPED configuration (`KERN_NO_SCOPE`, the one comparable to bubblewrap) a bare start grew
about 500 us since 0.3.0, with bubblewrap steady as the control. Roughly 185 us of that is named:
`proc-mask` 66 us, `cgroup-view` 39, seccomp 60, `dev` 20, and together they close a container
escape through `core_pattern`. **The remaining 315 us has no measured cause, and no story is
offered for it.** Registry size, a benchmark rename and the benchmark's batch budget are each
excluded by measurement. It has not been bisected because that configuration is the synthetic one:
with cgroup caps on, which is what users run, the same span went from 4.92 ms to 2.45 ms.

## Binary size is not being reduced

Read from the checksum-verified v0.6.37 release artifacts: **1926112 B x86_64 (1.84 MB)** and
**1642984 B aarch64 (1.57 MB)**. The release profile is already at its limit.

The x86_64 figure has not moved in three releases. The aarch64 one gained exactly 65536 B, one
64 KiB segment, and the cause is the build environment rather than the code: cross-built here with
`aarch64-linux-gnu-gcc` this same source is 1642984 B, the number a local build has produced since
before the previous release, when the published artifact was 1577448. Same code, local unchanged,
published up by the whole gap. WHICH change in the release environment closed it is not established,
and an earlier version of this entry asserted the reverse of what is now measured, so no story is
offered for it here.

Rebuilding the standard library on nightly reaches 1.40 MB, and adding `-Cpanic=immediate-abort`
reaches 1.22 MB. Deliberately not applied: under that flag a panic prints no file and no line,
`cargo test` cannot run under the profile so the shipped binary would stop being the tested one,
and a contributor on stable could no longer build the published binary.
