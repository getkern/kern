# Changelog

This project is a work in progress: the CLI and config surface may change at any time. Build from
source with `cargo install --git https://github.com/getkern/kern getkern --locked`. What follows is
the current state of the tree; full detail is in the git history.

## Current

### Security

- Registry-posture forgery closed: every host-path input (`-v`, `--secret`, `--env-file`, `--rootfs`,
  build context and `-f`, `kern cp` in both directions, `save -o`) refuses any source that resolves
  onto the trust-bearing runtime dirs, by `(device, inode)` identity as well as path. The default is
  inverted: everything under the runtime dir is refused except the box-data `logs/` and `scratch/`.
- `socket(AF_VSOCK, …)` refused with `EAFNOSUPPORT` in both seccomp modes.
- The bounding-set drop is verified with `PR_CAPBSET_READ`, failing closed if any cap survives.
- `CAP_SYS_PTRACE` dropped by default (14 caps), closing the `/proc/<pid>/mem` cross-process read.
- The seccomp mode is recorded and reproduced by `kern exec` and the health probe, not re-derived
  from the caller's env; an absent or corrupt record makes `exec` fail-loud.
- `KERN_MAX_CONCURRENT` enforced atomically under a `flock`, closing the fleet-cap TOCTOU.
- A SIGKILL'd detached supervisor's box is reaped via `cgroup.kill`.
- An inherited caller fd no longer leaks into the box: `shed_inherited_fds` before `execvp`
  (CVE-2016-9962 class).
- A pulled layer's setuid/setgid bit is stripped at extraction.

### Fixed

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
- A privileged port (`-p` below 1024) reports the real cause - a missing `CAP_NET_BIND_SERVICE`, or
  the address already in use - instead of a generic bind failure.
- A `--user`/image `USER` that cannot be mapped names the actual fix (install `newuidmap`/`newgidmap`
  + a `/etc/subuid`/`/etc/subgid` allocation, or use `--uid-range`) instead of blaming `--user`.

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
  silent downgrade to the default denylist. Closed set; prints its resolved constituents so the macro
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
