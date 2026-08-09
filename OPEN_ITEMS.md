# Open items

What kern does not do yet, or does not know. Each entry says what it costs you and what would
settle it. Resolved items live in [CHANGELOG.md](CHANGELOG.md), not here.

## The default seccomp filter is a denylist

kern's **default** filter denies a named set of syscalls instead of allowing a named set. The
stronger allowlist shape exists now behind `KERN_SECCOMP=allowlist` (moby's default allow set minus
kern's 34, deny-by-default with `ENOSYS`), but stays **off by default**: a wrong allowlist breaks
working images silently, so flipping the default is gated on validating against a corpus of real
workloads first. `KERN_SECCOMP=allowlist-audit` is the measurement for that gate - it runs the box
under the allowlist's deny surface as `SECCOMP_RET_LOG` (log-and-run instead of `ENOSYS`), so
`scripts/seccomp-audit.py` records exactly which syscalls a workload uses outside the allow set.

The allowlist denies no syscall whose absence forces a fallback to a **less-safe** variant: every
modern/hardened call moby allows - `openat2`, `faccessat2`, `statx`, `close_range`, `pidfd_open` and
the rest - is in the allow set, so the one denied modern call, `clone3`, degrades only to `clone`,
which the filter itself flag-checks (verified: no other safe/unsafe pair has the modern half denied).

The filter matches by syscall number; its one exception reads `clone`'s flags out of the register
they arrive in and refuses only the namespace-creating ones, since `clone` cannot be denied by number
without taking `fork` with it. It is always on and cannot be turned off - the two opt-in values above
make it STRICTER, never absent.

## The default capability drop keeps some caps Docker drops

kern drops 14 dangerous caps by default; Docker's default keeps a smaller set, so kern still keeps a
few Docker drops - `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_MKNOD`. They are held only
over the box's own user namespace, and the escape syscalls they would unlock (the mount API, `bpf`,
`ptrace`) are seccomp-killed, so the marginal risk is small. The one clean tightening already taken is
`CAP_SYS_PTRACE`: its syscalls were already killed, so dropping it costs nothing and closes a
`/proc/<pid>/mem` read. Dropping the rest toward Docker's set is deferred, not because it is wrong but
because it needs validation that it does not break a real workload - the `KERN_SECCOMP=allowlist-audit`
harness plus a compose corpus is that validation, and it has to run first. `--cap-drop` already lets
an operator take any of them today.

## No custom per-box seccomp profile from a file

Docker takes `--security-opt seccomp=<profile.json>`; kern does not. A box picks between the shipped
denylist and the opt-in allowlist (`KERN_SECCOMP=allowlist`), not an arbitrary profile. This is a
deliberate hold, not an oversight: an arbitrary OCI profile is a general parser (the full JSON:
`defaultAction`, `defaultErrnoRet`, `archMap`, per-syscall `action` and per-argument `args` with
`index`/`value`/`op`) plus a compiler from that to cBPF - which is what `libseccomp` exists to do,
because it is hard and easy to get subtly wrong. A bug there does not crash, it silently permits a
syscall the profile meant to deny. It earns its own validated effort - a pinned parser and an
exhaustive `filter classifies every rule as intended` proof, the same bar the allowlist met - not a
rushed add. Until then, `--cap-drop` narrows the capability set per box today, and
`KERN_SECCOMP=allowlist` is the stricter posture; neither needs a hand-written profile.

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
on the Jetson Orin Nano. kern warns before the box starts and names the fix (install `uidmap` + add a
subuid allocation, or use `kern exec`), but it cannot install the helper for you, and the failure the
ssh CLIENT then prints (`kex_exchange_identification: Connection closed by remote host`) says nothing
about uid maps. Installing `uidmap` was enough to make it work on a Pi 5.

## `pasta` refuses to start on WSL2

A pod there comes up loopback-only, and kern reports why: `Couldn't open user namespace
/proc/<pid>/ns/user: Permission denied`. Running as uid 0 inside the distro is not enough. Why that
permission is refused there and granted on every Linux host tested is not established. The
consequence is bounded: services still reach each other by name, only egress is missing.

## A host that delegates `memory` but not `pids` says nothing about the task ceiling

The uncapped-host notice is driven by `memory_cap_enforceable()`, so it covers the case that
actually occurs: a kernel booted without `cgroup_enable=memory` delegates neither. A host that
delegates `memory` and withholds `pids` alone would take the default `TasksMax=512` silently. Not
observed on any host tested, and no predicate for it exists yet; it is written here rather than
guessed at, because the fix is a second controller check and the cost of getting it wrong is a
warning that fires on healthy hosts.

## `KERN_MAX_CONCURRENT` is a guard rail, not a resource boundary

The count-and-claim runs under the claims-dir `flock` - the ceiling is read while the lock is held,
before the claim is written - so the earlier TOCTOU is closed and a racing burst can no longer
overshoot `N`. What remains is scope, by design: it bounds the NUMBER of live boxes a cooperating
starter admits (a caller can unset it), not their resource use, whereas `KERN_FLEET_MEMORY_MAX` and
`KERN_FLEET_PIDS_MAX` are real cgroup limits. The concurrency count is a guard rail, not a boundary.

## `kern ps` prints the mapping recorded at start, not a live probe

A published port is a fact at box start: the forwarder binds its host socket before `kern box`
prints "started", and a bind that fails refuses the box rather than leaving a mapping nothing
serves. What `ps` prints afterwards is the registry entry. A forwarder is a child of the box's
supervisor and dies with it, so the gap is narrow: a forwarder killed by hand or by the OOM killer
while its box keeps running would still show.

## 315 us of a bare box start are not attributed

In the UNCAPPED configuration (`KERN_NO_SCOPE`, the one comparable to bubblewrap) a bare start has
grown about 500 us over the project's history, with bubblewrap steady as the control. Roughly 185 us
of that is named:
`proc-mask` 66 us, `cgroup-view` 39, seccomp 60, `dev` 20, and together they close a container
escape through `core_pattern`. **The remaining 315 us has no measured cause, and no story is
offered for it.** Registry size, a benchmark rename and the benchmark's batch budget are each
excluded by measurement. It has not been bisected because that configuration is the synthetic one:
with cgroup caps on, which is what users run, the same span went from 4.92 ms to 2.45 ms.

## The release binary trades panic diagnostics for size

The published Linux binaries are built with a pinned nightly, `-Zbuild-std=std,panic_abort` and
`-Cpanic=immediate-abort`, reaching **1575480 B x86_64 (1.58 MB)** and **1312824 B aarch64 (1.31 MB)** -
a ~750 KB `.tar.gz` download. Two clean rebuilds are byte-identical and the stripped binary embeds no
build path, so it reproduces across machines with the pinned toolchain. A plain stable
`cargo build --release` still yields a working ~2.0 MB binary; the nightly is only the release-artifact
size optimization.

The honest cost, kept in view: under `immediate-abort` a panic prints no file and no line, so a bug
that can only reach a panic aborts with a bare `SIGABRT` and no diagnostic. kern's production code is
panic-free (audited, and no abort surfaced across the extreme + four-kernel cross-platform suites), but
"audited" is not "proven", so this is a real tradeoff, not a free win. Two consequences kept in view:
the source stays 100% stable Rust so `cargo test` runs on the SAME source the release ships (a
contributor on stable reproduces a standard, panic-message binary), and the pinned nightly needs a
deliberate bump + re-validation when it moves.
