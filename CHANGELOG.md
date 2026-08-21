# Changelog

**CLI stability.** As of v0.7.0 the command surface is stable: the verbs, their flags, and the
`--json` output shapes change incompatibly only on a **minor bump** (`0.8.0`+, since kern is `0.x`),
never on a patch, and only after a deprecation entry here at least one release earlier. `--json`
output is additive: new fields may appear, so consumers must **ignore unknown fields**; removing or
renaming one is the breaking change the minor-bump rule covers. A `cli_surface_is_frozen` test
snapshots the surface and fails the build on any undocumented change. The project is still pre-release
in the sense that binaries are not published yet (build from source) and internal config-file keys may
still evolve, but scripts and SDKs written against the CLI can rely on it. Build from source with
`cargo install --git https://github.com/getkern/kern getkern --locked`. What follows is the current
state of the tree; full detail is in the git history.

## Current

### Security

- **`--landlock-rw` is now fail-closed** (behaviour change, and the only one to a flag's meaning in
  this release). On a kernel without the Landlock LSM it used to warn and start the box with no path
  allowlist; it now refuses to start. kern already had an enforce-or-do-not-run family
  (`--require-limits` for cgroup caps, `--apparmor` for the LSM profile) and this was the one member
  that degraded, so the same script confined writes on a laptop and confined nothing on a board. The
  refusal names the flag, both reasons the LSM can be absent (not built in, or switched off with
  `lsm=`), and the way out. **Boxes that do not pass the flag are unaffected.** The cost is deliberate:
  a script that hard-codes `--landlock-rw` across a mixed fleet now fails on the boards rather than
  running unconfined there, and `kern doctor` reports the ABI so it can be gated. Verified on a
  Raspberry Pi 5 whose only LSM is `capability` (refused, message names the flag; without the flag the
  box starts) and on a Landlock ABI v8 host (write inside the allowlist succeeds, write outside is
  denied).
- The default seccomp filter is now a deny-by-default **allowlist** (moby's own default filter minus
  kern's 35 escape syscalls), not the wider denylist: a syscall outside the vetted set returns
  `ENOSYS`, and the escape vectors still hard-kill (`mount`/`unshare`/a namespace-flagged `clone`
  all SIGSYS, verified on a default box). This is Docker's own default posture minus 34, so it is at
  least as compatible while being strictly narrower - the whole future syscall surface is closed by
  default rather than reached. The wider denylist is the opt-out via `KERN_SECCOMP=denylist`;
  `--security-profile untrusted` is unchanged (allowlist + `--cap-drop ALL` + `--read-only`), and an
  `exec` reproduces the box's own recorded filter. Validated: a default box runs common workloads
  (shell, `ls`, `cat`, `id`) and 436 unit tests pass.
- Registry-posture forgery closed: every host-path input (`-v`, `--secret`, `--env-file`, `--rootfs`,
  build context and `-f`, `kern cp` in both directions, `save -o`) refuses any source that resolves
  onto the trust-bearing runtime dirs, by `(device, inode)` identity as well as path. The default is
  inverted: everything under the runtime dir is refused except the box-data `logs/` and `scratch/`.
- `socket(AF_VSOCK, …)` refused with `EAFNOSUPPORT` in both seccomp modes.
- The bounding-set drop is verified with `PR_CAPBSET_READ`, and under `--cap-drop ALL` every set
  (`CapEff`/`CapPrm`/`CapInh`/`CapAmb`/`CapBnd`) is read back all-zero from `/proc/self/status` -
  ambient included, since it survives `execve` and `NO_NEW_PRIVS` does not clear it.
- `CAP_SYS_PTRACE` dropped by default (16 caps), closing the **cross-UID** `/proc/<pid>/mem` read.
  (A same-uid sibling read inside one box is standard Linux and not a boundary; a host or peer-box
  pid is not visible in the box's pid namespace, so its memory is unreachable regardless.)
- `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` dropped by default too, converging kern's default capability
  set onto Docker's/Podman's. They are re-kept CONDITIONALLY: `NET_ADMIN` for `--tun` (the box brings
  its own tunnel interface up; kern brings `lo` up before the drop, so loopback is unaffected) and
  `SYS_ADMIN` for `--privileged` (in-namespace `mount`), or either via `--cap-add`. `kern exec` stays
  strict and re-keeps neither, staying no more privileged than the box's PID 1. Their escape syscalls
  (the mount API, `bpf`) are seccomp-killed on a non-privileged box regardless, so this is
  defense-in-depth, not a boundary change.
- The seccomp mode is recorded and reproduced by `kern exec` and the health probe, not re-derived
  from the caller's env; an absent or corrupt record makes `exec` fail-loud.
- `KERN_MAX_CONCURRENT` enforced atomically under a `flock`, closing the fleet-cap TOCTOU.
- A SIGKILL'd detached supervisor's box is reaped via `cgroup.kill`.
- An inherited caller fd no longer leaks into the box: `shed_inherited_fds` before `execvp`
  (CVE-2016-9962 class).
- A pulled layer's setuid/setgid bit is stripped at extraction.
- OCI supply-chain hardening: a digest-pinned pull (`img@sha256:<hex>`) is content-addressed - the
  fetched manifest and the selected arch sub-manifest are sha256-verified, so a compromised registry
  cannot serve different bytes under a pin. The tar vetter also rejects a hardlink whose target
  descends an escaping symlink (a host-inode disclosure/corruption class), and an aggregate layer-count
  cap bounds a resource-exhaustion manifest.

### Fixed

- **`--stop-timeout`'s help says when the grace is skipped.** The flag read "Seconds the workload
  gets to exit on its own before the SIGKILL (default 10)", which promises a wait kern deliberately
  does not take when the box's init has no handler for the signal: a namespace PID 1 DISCARDS a
  signal it has no handler for, so the workload cannot die of it and the grace is a guaranteed wait
  for an event that can never happen (Docker and Podman sit it out anyway, measured at 10 278 and
  10 287 ms against kern's 21.9). The behaviour is unchanged and was already in BENCHMARKS.md and
  docs/DOCKER-COMPAT.md; what was missing is the one line a surprised reader looks at first. An
  external audit read `trap "" TERM` stopping in 4 ms as a defect, comparing it against the 3009 ms
  this project had published for `trap "sleep 60" TERM` - a handler that CATCHES the signal and never
  returns, which does spend the whole grace. Both numbers were right; the flag's own help did not say
  so. The two shapes are now an end-to-end test each, side by side, rather than prose.
- **An orphaned box is recoverable on the systemd-scope path too**, not only on the direct one. kern
  reaps a box whose supervisor was killed by remembering that box's own cgroup, and the path is
  recorded only when it names a `kern-box-*` dir - deliberately, because on the scope path a box's
  cgroup can be a scope kern did NOT create (`kern doctor` suggests `systemd-run --user --scope bash`
  to pay the scope cost once, and every box in that shell shares the shell's scope, so recording it
  would let a later reap `cgroup.kill` the user's whole session). The transient scope kern asks
  systemd for is now NAMED `kern-box-<pid>.scope`, which settles ownership by construction: an
  ambient scope is `run-*` and stays unrecorded. MEASURED on an Arduino UNO Q (aarch64, rootless,
  user systemd) before: SIGKILL a box's supervisor and the box vanished from `kern ps` while four of
  its processes kept running, with `kern stop` answering "no running box". After: `kern ps` shows it
  `orphaned`, `kern stop` reports "reaped via cgroup.kill", and no process is left. The recorded
  cgroup also lets the reaper hold engage there, so that board's exit codes went from 7 correct out
  of 10 under a bulk stop to 30 out of 30. The `.scope` suffix keeps the start-time orphan sweep off
  the dir (it reads the last `-` field as a pid, which never parses), and `stop` no longer rmdirs a
  cgroup that is a systemd unit - `--collect` removes it with the unit.
- **`kern wait` answers for a box that has already exited**, from the same exit record `kern ps -a`
  reads, for as long as `ps -a` still lists it (an hour). It used to refuse - "kern keeps no stopped
  boxes" - which was an inconsistency in kern's own surface rather than ephemerality: `ps -a` listed
  that box WITH its code while `wait` declined to print the same number, so a script that stopped a
  service could not ask how it had exited. Docker answers immediately there too. A box that is still
  running is unaffected: `wait` blocks until it exits, as before. Outside the window, and for an
  interactive `-it` box that never had a supervisor to record a code, `wait` still fails and says
  which case it is.
- **`--stop-timeout` is honoured in full, not rounded down to whole seconds.** `stop` waits the time
  LEFT until a deadline shared by the whole stack, and that remainder was truncated to seconds, so a
  box asked for 3 s got 2. Measured: a workload that flushes for 2.5 s under `--stop-timeout 3` was
  SIGKILLed at 2019 ms and recorded 137, where Docker's `stop -t 3` let the same workload finish in
  2799 ms and exit 5. kern now finishes it in 2526 ms with exit 5. A workload that exits at once
  still returns in ~16 ms, and one whose handler never finishes now consumes the whole 3 s rather
  than two thirds of it.
- **`kern stop` records the workload's own exit code, not a blanket 137.** A service that traps the
  stop signal and shuts down cleanly was reported as `exited (137)` - killed - by `kern ps -a` and
  `kern wait`, because the 137 was written when a stop was always a SIGKILL and the graceful phase
  arrived later without it following. Now the init's real status is read from its unreaped zombie and
  recorded, and 137 is kept for the case where it is the truth: an init that ignores the signal and is
  SIGKILLed. Measured against Docker on the same four-service stack (nginx, redis, and two shells that
  trap and exit 0 and 3): both runtimes now report 0, 0, 0 and 3, where kern previously reported 137
  four times. Reading that status is a race against whoever reaps the init - correct in 15 runs out of
  20 on its own - so `stop` holds the box's own reaper with SIGSTOP for the microseconds it takes,
  which makes it 30 out of 30. The hold is taken before any signal goes out (the group signal would
  otherwise kill the reaper first), released by a `Drop` on every path, and only ever applied to a
  process the box owns - never the user's systemd manager, which inherits an orphaned init, and never
  a FOREGROUND box's own process, which would print `Stopped` in the user's terminal. It is also
  taken only for a box with a dedicated cgroup, the case where a `stop` killed mid-hold is
  recoverable: `kern ps` then shows the box ORPHANED and the next `kern stop` reaps its cgroup whole.
  A box without one keeps the unguarded read rather than risking a stopped runner nothing can clear. Cost measured:
  none. A single stop is 16.20 ms against a 16.23 ms baseline and `stop --all` of 50 boxes is 110 ms
  against 119 ms, because consolidating the `/proc` readers onto one `stat_field` (reading `stat`
  rather than the much more expensive `status`) paid for the two extra signals.
- `kern gc` reaps orphaned box cgroups wherever a box was created, not only under kern.slice. A box
  that the OOM killer or a SIGKILL takes down leaves its `kern-box-*` cgroup dir behind (the RAII Drop
  that removes it cannot run on SIGKILL), and gc looked in one place while `apply_limits` creates in
  two: kern.slice on the direct path, the CALLER'S own cgroup on every other path. Measured on WSL2 as
  uid 0, where no kern.slice exists and boxes land at the cgroup root: three OOM-killed boxes left
  three dirs, a later box start did not reap them, and gc reported "nothing to prune" with them in
  place. After the fix the same sequence reports "reaped 3 orphaned box cgroups" and leaves none, while
  a live box's cgroup is untouched.
- kern no longer calls a box uncapped when the kernel is capping it. The uncapped notice and the
  `--require-limits` refusal keyed off "kern wrote no cap of its own", which is not the same question:
  on the systemd-scope path the scope carries `MemoryMax`/`TasksMax` and the backstops bind without
  kern writing a byte. Measured on a Raspberry Pi 5 over ssh, the box ran with `memory.max` 67108864,
  `memory.oom.group` 1 and `pids.max` 512 and was OOM-killed as a whole three times out of three
  (`dmesg`: `Memory cgroup out of memory`, three processes at once), while kern printed the notice and
  `--require-limits` refused to start. Both now ask the kernel what is in force: a memory ceiling that
  bounds the request anywhere up the tree, and a task ceiling at the box's own level (an ancestor's
  `pids.max` is shared with the session, so it does not count). The direct-path refusal is deliberately
  unchanged, since there the box's own cgroup is the sole enforcer by design. Verified both ways: on
  the Pi the notice is gone, `--require-limits` starts, and a 300 MB write is still killed 137; on a
  host with no delegation the notice and the refusal both still fire.
- A detached box's captured log is size-capped (two-file 32 MiB ring, zero-copy `splice`), so a
  runaway writer can't fill the session tmpfs.
- An OOM kills the whole box (`memory.oom.group = 1`), not one process.
- `kern ps`/`gc` under fd exhaustion no longer prunes or mis-reaps a live box (three-state liveness).
- A SIGKILL'd/OOM'd detached supervisor no longer leaves an unreachable "ghost": liveness reads
  `cgroup.events` `populated`; an orphan is visible (`--filter status=orphaned`) and reaped
  identity-safe against pid reuse.
- systemd detection probes the user manager's own control socket (`$XDG_RUNTIME_DIR/systemd/private`,
  what `systemd-run --user` actually connects to), so kern attempts the scope only where the manager is
  provably up: a dir-only host, or one with a reachable D-Bus bus but no user manager, no longer fails
  every box (it would connect and then die past kern's irreversible re-exec).
- A non-UTF-8 argument fails validation instead of panicking.
- The instance record is written atomically (temp + `rename`).
- `kern doctor` write-probes the real cap target; an unenforceable cap warns instead of running
  silently uncapped; `--pids-limit 1` is refused at parse; a second `vcpu:` profile warns.
- `volume ls --json` no longer lists names not on disk or misdirects a delete (display vs exact
  syscall form, `usable` flag); `kern <verb> --help` filters to the verb on a real terminal.
- `kern compose` anchors a service's relative `env_file`/`-v`/`rootfs` paths to the compose file's
  own directory, not the caller's working directory, so a stack runs the same from anywhere.
- Compose `restart: always`/`unless-stopped` is honoured on a pod member instead of being degraded to
  on-failure: kern's per-service supervisor keeps it up on ANY exit (including a clean 0) for the
  stack's lifetime. A standalone box's `always`/`unless-stopped` still takes the systemd path.
- A privileged port (`-p` below 1024) reports the real cause - a missing `CAP_NET_BIND_SERVICE`, or
  the address already in use - instead of a generic bind failure.
- A `--user`/image `USER` that cannot be mapped names the actual fix (install `newuidmap`/`newgidmap`
  + a `/etc/subuid`/`/etc/subgid` allocation, or use `--uid-range`) instead of blaming `--user`.
- A kern-TOML key (`health_cmd:`, `health_interval:`, `depends_healthy:`, `depends_completed:`, ...)
  written into a `docker-compose.yml` names the docker-compose equivalent (a `healthcheck:` block, or
  `depends_on: {SERVICE: {condition: service_healthy}}`) instead of a dead-end "unsupported", so a
  file that mixed the two spellings gets the fix rather than a silently missing health gate.
- The `kern-sandbox` SDKs decide `startup_failed` from an unforgeable channel: kern writes a "box
  started" byte to a caller-supplied `KERN_STARTED_FD` (CLOEXEC, so it never reaches the workload)
  only on the started path, so a workload can no longer forge the startup-failure marker on its own
  stderr to make the SDK raise. An older kern without the signal falls back to the stderr heuristic,
  which only ever over-reports a failure, never masks a real one.

### Added

- A CI gate fails, naming the syscall, when a new kernel `__NR_*` is neither allowed, denied, nor on
  the reviewed list (x86_64 + aarch64).
- `--require-limits` (or `KERN_REQUIRE_LIMITS`): refuse to start with a non-zero exit unless the
  memory and pids caps (including their defaults) are actually enforced, read back from the cgroup
  (the OOM / fork-bomb backstop), instead of running best-effort UNCAPPED. cpu/cpuset stay
  best-effort, as on the systemd-scope path (a QoS knob with no OOM/fork-bomb role). `--allow-uncapped`
  (`KERN_ALLOW_UNCAPPED`) is the explicit inverse: accept uncapped silently on a host with no cgroup
  delegation (nested CI). The two are mutually exclusive; the default is unchanged (warn once per
  host, run uncapped).
- `kern doctor` is more actionable: the multi-uid check names the commands to run (install the
  `newuidmap`/`newgidmap` helpers, then the `/etc/subuid`/`/etc/subgid` allocation line for your user,
  numeric-uid fallback when `$USER` is unset), not hardcoded to `apt`, and a new check reports whether
  `pasta` is present for pod/box outbound networking. kern uses these when present and never writes
  `/etc/subuid` or ships `pasta` itself.
- `--security-profile <untrusted>`: an opt-in bundle (seccomp allowlist + `--cap-drop ALL` +
  `--read-only`) for running code nobody has read, applied as a base that explicit flags and env
  override (`--cap-add X`, `KERN_SECCOMP=...`). `--cap-add ALL` and `--privileged` are refused under it
  (both would negate a constituent - all capabilities back, or a relaxed seccomp filter - leaving a box
  labelled untrusted that is not); a SET-but-unrecognised `KERN_SECCOMP` is a usage error, never a
  silent downgrade to the default filter. Closed set; prints its resolved constituents so the macro
  is visible. It does NOT touch Landlock (a write-allowlist needs
  the workload's real paths; build it from an audit run) and does NOT set `--require-limits` (which
  would break a cgroup-less host). The default is unchanged. It is a CLI/SDK flag; a compose service
  sets the same posture through its individual keys and `KERN_SECCOMP`, not a `[box.NAME]` macro key.
- The `kern-sandbox` SDKs (Python and Node) reach CLI parity for the above: `security_profile`
  /`securityProfile` maps to `--security-profile`, and `require_limits`/`requireLimits` to
  `--require-limits`. `security_profile="untrusted"` composes with the writable `-v` workspace (the
  root goes read-only, a bound mount stays writable). Note `require_limits` is the fail-closed gate,
  distinct from the pre-existing `enforce_limits` (which only picks the scope vs best-effort cap path)
  and mutually exclusive with the `KERN_ALLOW_UNCAPPED` env the SDK forwards.
- `kern ps -a`/`--all` lists recently-exited boxes (from their `waitexit` breadcrumbs), and
  `kern wait` resolves a box that has already exited, not only a live one.
- `--user` (and compose `user:`) accepts a NAME, resolved against the image's own
  `/etc/passwd`/`/etc/group`; the image's declared `USER` is honoured the same way. It fails closed
  on a host without `newuidmap` rather than silently running as in-box root.
- A compose `shm_size:` is recognised and left intentionally cgroup-bounded: `/dev/shm` is charged to
  the box memory cgroup (`mem_limit` / `--memory`), not pinned to a fixed size, so there is no 64 MB
  `/dev/shm` footgun to size around.
- `--apparmor <profile>` (CLI + the `kern-sandbox` Python/Node SDKs): enter a pre-loaded AppArmor
  (LSM) profile on the box's exec, layered over namespaces + seccomp (Docker's `--security-opt
  apparmor=`). A missing or unloadable profile fails the box CLOSED; `kern exec` re-enters the box's
  recorded profile so an exec is no less confined than the workload; a box whose posture predates this
  recording is refused rather than exec'd unconfined. kern applies no default profile.
- The Linux release build produces a size-optimized binary with a pinned-nightly `build-std` +
  `-Cpanic=immediate-abort` (~22% smaller than a plain stable `--release`, which a from-source
  `cargo install` still yields), reproducible byte-for-byte with the pinned toolchain. The source
  stays 100% stable Rust, so `cargo test` runs on the same source a release would ship. The exact
  sizes and the panic-diagnostics tradeoff this buys are in [OPEN_ITEMS.md](OPEN_ITEMS.md).
