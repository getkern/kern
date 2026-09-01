# Roadmap and known gaps

One file, because they are one question: what kern does not do. The first half is what may come and
the second is what is missing or unmeasured today, and neither is a commitment or a date. Recently
shipped work is under [Status](README.md#status); resolved items are in
[CHANGELOG.md](CHANGELOG.md), not here.

## Directions under consideration

Not commitments, and some may never ship if they would change what kern is.

- **GPU slices.** A workload gets a *slice* of a GPU, not the whole device. Not shipped, and the
  README will describe it when it is, not before.

  The judgement ships ahead of the capability, deliberately. `kern doctor` detects each GPU from
  sysfs and prints the tier a cap on it would have: `TIER-HW` where a MIG or SR-IOV partition is
  present, enforced by the device rather than by the tenant, with kern saying plainly that it read
  the partition's presence and has not measured the VRAM split; `TIER-SOFT` everywhere else. A cooperative quota on consumer hardware is
  bypassed by any tenant that talks to the device without going through the vendor library, so it is
  worth density and fairness and nothing else, and kern says so before it can cap anything. That
  detection is read-only: it reads, classifies and prints, and touches no driver.
- **More governed resources.** I/O bandwidth and IOPS caps already ship (`vdisk:` `--bandwidth` /
  `--iops`, box `--io-weight` → cgroup `io.max`/`io.weight`), and hold a box to the requested rate
  exactly where the host grants both: the `io` controller delegated to the box's cgroup (systemd
  often does not by default), and the ext4-on-loop vdisk backend (a real root, foreground box). A
  rootless box without those falls back and the caps are reported unapplied rather than pretended.
  Widening where they bind, and other kernel-real knobs like network shaping, as they prove useful.
- **Snapshot / warm-start (CRIU).** Same-host checkpoint and restore of a *warm* box for subsecond
  restarts. Feasible but gated: rootless CRIU needs a capability and suspending the seccomp filter, so it
  would be an explicit opt-in mode, not the default, and only for same-host, non-GPU boxes. Not committed.
- **macOS.** No native port, and it is a non-goal: a daemonless kernel + cgroup sandbox has no macOS
  equivalent. That is not the same as "kern does not work on a Mac": inside a Linux VM the Mac already
  runs the ordinary Linux kern, verified on Apple Silicon with an Ubuntu 24.04 guest, and
  [docs/INSTALL.md](docs/INSTALL.md) has the two obstacles and the caveat about caps.
  What is under consideration is only the convenience half, a thin shim so `kern` can be typed on the
  macOS side instead of inside the VM, the same shape as `kern.exe` on Windows. Nothing about it would
  reach a GPU: Apple exposes no compute device to a Linux guest, which is why Docker Desktop has no GPU
  for containers either.

**In progress**

- **Stack-level watcher.** A service with a `restart:` policy is already restarted when it dies
  mid-run by its own per-service supervisor (`on-failure` on a non-zero exit, `always`/`unless-stopped`
  on any exit, for the stack's lifetime). What is not there yet is a watcher over the whole member
  *set* that survives an individual supervisor being killed and re-applies policy across the stack;
  lower priority now that the common case is covered.

**Deliberately out, not missing**

- Network segmentation between services, `deploy.replicas`, `docker.sock` / Engine API, and the compose
  `privileged:` service key. These follow from rootless + daemonless + one pod as the unit of isolation,
  not from missing work. (The CLI `kern box --privileged` exists, and relaxes exactly five syscalls for
  nesting; see [SECURITY.md](SECURITY.md).)

> A stack is one pod. Within that model kern is complete: what is listed above as out is a
> consequence of the model, not a gap in it.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design.

## Known gaps, and what would settle them

What kern does not do yet, or does not know. Each entry says what it costs you and what would settle
it.

### No custom per-box seccomp profile from a file

Docker takes `--security-opt seccomp=<profile.json>`; kern does not. A box picks between the shipped
allowlist and the opt-out denylist (`KERN_SECCOMP=denylist`), not an arbitrary profile. This is a
deliberate hold, not an oversight: an arbitrary OCI profile is a general parser (the full JSON:
`defaultAction`, `defaultErrnoRet`, `archMap`, per-syscall `action` and per-argument `args` with
`index`/`value`/`op`) plus a compiler from that to cBPF - which is what `libseccomp` exists to do,
because it is hard and easy to get subtly wrong. A bug there does not crash, it silently permits a
syscall the profile meant to deny. It earns its own validated effort - a pinned parser and an
exhaustive `filter classifies every rule as intended` proof, the same bar the allowlist met - not a
rushed add. Until then, `--cap-drop` narrows the capability set per box today, and the shipped
allowlist - the default posture, not something you opt into - is already the stricter of the two
filters (`KERN_SECCOMP=denylist` opts *down* to the wider set); neither needs a hand-written profile.

### Whether a survivable denial helps an attacker is not known

Eleven denied syscalls return `ENOSYS` instead of killing the caller, so software probing for an
optional fast path falls back rather than dying. [SECURITY.md](SECURITY.md) has the set.

Measured: the errno leaks nothing, because a denied `io_uring_setup` and a syscall number no kernel
implements are both `-1 ENOSYS` from inside the box. Not measured: whether a cheaper map of the
filter is worth anything to an attacker who already has code execution in the box. Mapping is not
bypassing, and there is no evidence either way. If it turns out to matter, one lever is to move those
eleven to `SIGSYS` and lose the fallback behaviour.

A second lever breaks that binary trade: `SECCOMP_RET_USER_NOTIF` on the survivable-denial set. Those
syscalls would return a notification to a per-box listener that answers by policy - `ENOSYS` for the
honest fast-path probe (the fallback survives), while the errno is generated by policy rather than
read off the filter's structure (so a map is no longer deducible), and every attempt becomes a
loggable event instead of a silent `ENOSYS`. Feasible here: the kernel is well past the 5.9 that
`SECCOMP_FILTER_FLAG_NEW_LISTENER` + `SECCOMP_IOCTL_NOTIF_ADDFD` need, and a filter installed with the
new-listener flag returns the notify fd. It is **not shipped, by decision rather than omission**: it
earns its own validated effort, the same bar the allowlist met, because two things it introduces are
sharp: (1) a listener is a process outside the box, in tension with daemonless, so it has to be the
box's OWN parent, bound to the box lifecycle, never a global supervisor; and (2) the notify fd is a
boundary that must fail CLOSED - a listener-less `USER_NOTIF` filter blocks the workload on its own
syscalls (verified: a probe with such a filter hangs on its first `write`), so if the listener dies
the box must be reaped, not left running unmediated. Scoped to the eleven `ENOSYS` numbers, gated on
kernel >= 5.9 with a fall-back to today's `ENOSYS` filter on older edge kernels, it is a designed
path rather than something to add in a hurry before a tag.

### Landlock is gated on the kernel, and the flag is fail-closed

`--landlock-rw` needs the Landlock LSM. Where the kernel does not have it, a box that passes the flag
is REFUSED rather than run unconfined, so the flag means the same thing on every host and joins
`--require-limits` and `--apparmor` in the enforce-or-do-not-run family. Boxes that do not pass it are
unaffected. The open part is availability, not behaviour: measured absent on all three ARM boards
(Raspberry Pi OS 6.6 reports `capability` as its only LSM, Jetson 5.15-tegra, Arduino UNO Q 6.16), so
on the edge hardware kern is aimed at, a script that hard-codes the flag will not run until the kernel
ships `CONFIG_SECURITY_LANDLOCK=y`. `kern doctor` reports the ABI, and gating on it is the way to keep
one script working across a mixed fleet.

### `--ssh` needs `newuidmap`, and a fresh board does not ship it

sshd's privilege separation needs more than one uid in the box's user namespace, so `--ssh`
requires the `--uid-range` path: the setuid `newuidmap`/`newgidmap` helpers plus an `/etc/subuid`
and `/etc/subgid` allocation. Measured absent on a stock Raspberry Pi OS, on the Arduino UNO Q and
on the Jetson Orin Nano. kern warns before the box starts and names the fix (install `uidmap` + add a
subuid allocation, or use `kern exec`), but it cannot install the helper for you, and the failure the
ssh CLIENT then prints (`kex_exchange_identification: Connection closed by remote host`) says nothing
about uid maps. Installing `uidmap` was enough to make it work on a Pi 5.

### `pasta` refuses to start on WSL2

A pod there comes up loopback-only, and kern reports why: `Couldn't open user namespace
/proc/<pid>/ns/user: Permission denied`. Running as uid 0 inside the distro is not enough. Why that
permission is refused there and granted on every Linux host tested is not established. The
consequence is bounded: services still reach each other by name, only egress is missing.

### A host that delegates `memory` but not `pids` says nothing about the task ceiling

The uncapped-host notice is driven by `memory_cap_enforceable()`, so it covers the case that
actually occurs: a kernel booted without `cgroup_enable=memory` delegates neither. A host that
delegates `memory` and withholds `pids` alone would take the default `TasksMax=512` silently. Not
observed on any host tested, and no predicate for it exists yet; it is written here rather than
guessed at, because the fix is a second controller check and the cost of getting it wrong is a
warning that fires on healthy hosts.

### `KERN_MAX_CONCURRENT` is a guard rail, not a resource boundary

The count-and-claim runs under the claims-dir `flock` - the ceiling is read while the lock is held,
before the claim is written - so the earlier TOCTOU is closed and a racing burst can no longer
overshoot `N`. What remains is scope, by design: it bounds the NUMBER of live boxes a cooperating
starter admits (a caller can unset it), not their resource use, whereas `KERN_FLEET_MEMORY_MAX` and
`KERN_FLEET_PIDS_MAX` are real cgroup limits. The concurrency count is a guard rail, not a boundary.

### `kern ps` prints the mapping recorded at start, not a live probe

A published port is a fact at box start: the forwarder binds its host socket before `kern box`
prints "started", and a bind that fails refuses the box rather than leaving a mapping nothing
serves. What `ps` prints afterwards is the registry entry. A forwarder is a child of the box's
supervisor and dies with it, so the gap is narrow: a forwarder killed by hand or by the OOM killer
while its box keeps running would still show.

### The release binary trades panic diagnostics for size

The published Linux binaries are built with a pinned nightly, `-Zbuild-std=std,panic_abort`,
`-Zbuild-std-features=optimize_for_size` and `-Cpanic=immediate-abort`. `optimize_for_size` builds
std with core's size-first code paths and was worth a further ~5%, latency-neutral on the same
alternating 200-round measurement the panic flag got.

An x86_64 size reproduces ACROSS MACHINES: this desktop's build of a tagged commit matches the byte
count inside the published tarball, so the stripped binary embeds nothing machine-specific and the
number can be re-measured anywhere with the pinned toolchain. An aarch64 one cannot, because a native
build in CI and a cross build here are different link jobs (cross needs `rust-lld`), so an aarch64
size is only ever quoted from the release build. A plain stable `cargo build --release` still yields
a working, larger binary; the nightly is only the release-artifact size optimization.

The honest cost, kept in view: under `immediate-abort` a panic prints no file and no line, so a bug
that can only reach a panic aborts with a bare `SIGABRT` and no diagnostic. kern's production code is
panic-free (audited, and no abort surfaced across the extreme and four-kernel cross-platform suites),
but "audited" is not "proven", so this is a real tradeoff and not a free win. Two consequences: the
source stays 100% stable Rust, so `cargo test` runs on the SAME source the release ships and a
contributor on stable reproduces a standard, panic-message binary; and the pinned nightly needs a
deliberate bump plus re-validation when it moves.
