# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to SemVer.
Pre-1.0: the CLI and config surface are NOT frozen; minor versions may break them.

## [Unreleased] — 0.4 (in progress)

### Added
- **`--memory`/`-m` and `--cpus` per box** — tunable resource caps (previously a fixed 512 MiB /
  uncapped CPU). `--memory 512m|1g|<bytes>` sets a hard memory ceiling (the box is OOM-killed at the
  limit); `--cpus 1.5` caps CPU to 1½ cores (K8s semantics, clamped to the host's CPU count). Both
  the transient systemd scope and the best-effort in-namespace cgroup honor them; the CPU cap is
  best-effort where the cgroup CPU controller isn't delegated (e.g. some Android kernels).

## [0.3.3] — contextual hint for box-not-running errors

### Fixed
- **`stop`/`exec`/`logs` on a box that isn't running now show the right hint** ("run `kern ps` to
  see running boxes") instead of the generic sandbox-setup hint ("needs unprivileged user
  namespaces and a valid --rootfs directory"), which was misleading for a simple lookup miss. New
  `Error::NotRunning` variant separates a lookup miss from a sandbox-setup failure.

## [0.3.2] — `kern stop` takes multiple names + `--all`

### Added
- **`kern stop <name>...`** now stops **every** name given (previously it stopped only the first and
  silently ignored the rest), and **`kern stop --all`** stops every running box. A requested name
  that isn't running is reported on stderr instead of being silently dropped.

## [0.3.1] — `--uid-range` fallback hardening

### Fixed
- **`--uid-range` now degrades gracefully when `newuidmap`/`newgidmap` are present but fail at
  runtime** (the helper isn't setuid-root, or there's no matching `/etc/subgid` allocation —
  common on CI runners and minimal hosts). Previously this aborted the box; now, since the process
  is already in a fresh user namespace, it falls back to the safe single-uid map (box uid 0 →
  caller) with a clear notice — mirroring how an *absent* helper already degraded. A `box`
  therefore always starts, with or without a usable subordinate-id range. The single-uid map write
  is now shared by the default and the fallback paths.

## [0.3.0] — Real sandbox execution

### Added
- **`kern box <name> (--image <ref>|--rootfs <dir>) [-- cmd...]` runs a command in a real
  sandbox**: a fresh user + PID + net + UTS + IPC + mount namespace (single-UID map, no host
  privilege gained), an overlay root `pivot_root`-ed in (writable by default; `--read-only`
  remounts it read-only), a private `/proc`, then `exec`. Exit code propagated. Defaults to
  `/bin/sh`.
- `kern-isolation`: `RealMounts` (the libc `MountOps` impl) + `run_in_sandbox`. The real path and
  the `--plan` recorder flow through the **same** `Rootfs` typestate, so the read-only-after-pivot
  ordering is compile-enforced for real execution too.
- **`kern box -d` (detached)** + **`kern ps [--json]`**: a detached box forks a supervisor that
  registers itself under `$XDG_RUNTIME_DIR/kern/instances/`; `kern ps` lists running boxes and
  **prunes dead entries on read** — observability with no daemon. Survives a corrupt registry
  file (skipped, not a crash).
- **OCI pull**: `kern pull <image>` and `kern box <name> --image <ref> -- <cmd>` download an OCI
  image (registry v2, anonymous Docker Hub auth, multi-arch manifest/index → this host's arch)
  via `curl` + GNU `tar`, extract layers and apply whiteouts (with the symlink-escape guard),
  into a local rootfs (cached for re-runs). Verified: `kern box web --image alpine` pulls Alpine
  and runs it sandboxed (read-only root, isolated net/UTS, uid 0-in-ns).
- **Pull hardening (adversarial images)**: each layer is vetted **before extraction** (absolute
  paths, `..` traversal, device nodes, 2 GiB decompression-bomb cap), then extracted into an
  **isolated staging dir** and merged with **no-follow** semantics — a symlink planted by an
  earlier layer cannot be traversed by a later layer's writes (cross-layer escape closed
  structurally). Whiteouts (incl. opaque dirs) are applied during the merge under the guard.
- **`kern compose <file>`**: a minimal TOML orchestrator (no external crate). `[box.NAME]` tables
  with `image`/`rootfs`, `command`, `depends_on`; boxes start detached in dependency order
  (cycles + unknown deps are reported). Track the stack with `kern ps`.
- **Writable boxes (overlayfs)**: a box defaults to a writable root — the image/rootfs is the
  read-only lower, a private upper takes writes (the image stays immutable, scratch is removed on
  exit). `--read-only` remounts that overlay read-only (incl. `/dev`), so the box has no writable
  surface. (Overlay is used for both modes; a bind remount-RO is denied on some kernels.)
- **`kern stop <name>`**: stop running box(es) — SIGKILL the supervisor's process group (tears
  down the box's PID namespace), drop the registry entry, remove the writable scratch.
- **Observability (`kern top` / `kern stats` / `kern logs`)**: daemonless live + point-in-time
  views, read straight from each box's cgroup and a per-box log. `kern top` auto-refreshes
  (uptime, memory, CPU% from `cpu.stat` deltas); `kern stats [--json]` is a one-shot table/JSON of
  memory + cumulative CPU; `kern logs <name>` replays a detached box's captured stdout/stderr
  (the supervisor now tees stdio to `$XDG_RUNTIME_DIR/kern/logs/<name>-<pid>.log`, readable
  post-mortem). All three reuse the same registry, so they need no daemon and prune dead boxes.
- **Volumes (`-v src:dst[:ro]`, repeatable)**: bind a host directory or file into the box — the
  sanctioned way data crosses the boundary. Source fds are captured *before* pivot and bound in
  *after*, so the target always resolves inside the box; `:ro` is enforced (a remount-read-only
  bind). A writable volume stays writable even under a `--read-only` root.
- **`kern exec <name> [--env K=V] [--workdir <dir>] [-- cmd]`**: run a command inside an
  already-running box by joining its user → mount → ipc → uts → (net) → pid namespaces (then
  forking into the pid namespace). The exec'd process gets the box's seccomp filter for parity
  and the exit code is propagated. Must be the same user that started the box.
- **`--env K=V` / `-e` (repeatable) and `--workdir <dir>` / `-w`** for `kern box` (and `kern
  exec`): layer environment on top of the clean base env, and `chdir` into a working directory.
- **`--net` (opt-in networking)**: share the host network namespace so the box has outbound
  connectivity (the default stays isolated, loopback-only). The host's `/etc/resolv.conf` is
  copied into the box's writable layer so DNS resolves out of the box. Trade-off: `--net` means
  **no network isolation** — see SECURITY.md.
- **Prebuilt binaries + `install.sh`**: a release workflow builds static (musl) `linux-x86_64`
  and `linux-aarch64` binaries with SHA256SUMS on each version tag; `curl -fsSL
  https://getkern.dev/install.sh | sh` downloads the right one (checksum-verified) — no Rust
  toolchain needed.
- **uid/gid range mapping**: when `newuidmap`/`newgidmap` and an `/etc/subuid`+`/etc/subgid`
  allocation are present, the box maps a full id range (box uid 0 → caller; box ids 1..N →
  subordinate ids) instead of a single uid — so `apt install` (which `chown`s to other uids) and
  daemons that drop to a non-root user (e.g. **Apache → `www-data`**) work. Falls back to the
  dependency-free single-uid map when the helpers/subids aren't available. No host privilege
  gained either way. Verified: real `apt install apache2` + `apache2` serving on Ubuntu in a box.

### Fixed
- **`cmd > /dev/null` now works inside a box.** The `/dev` tmpfs was mounted with the default
  sticky, world-writable mode (1777); with `fs.protected_regular` (≥1, default on most distros)
  an `O_CREAT` open of a device node the box doesn't own in a sticky world-writable directory is
  rejected with `EACCES` — breaking the near-universal redirect. `/dev` is now mounted `mode=755`
  (owned by the box's root), and device nodes are bound by their real host path *before* pivot
  (a post-pivot `/proc/self/fd` bind left them read-only). The hostile-`/dev`-symlink guard is
  preserved (a symlinked `/dev` is replaced with a real directory first; a normal `/dev` is
  untouched). Regression test added.
- **Concurrent boxes sharing one bind rootfs.** Several `--read-only` / `--rootfs` boxes started
  in parallel off the *same* rootfs raced on a `.old_root` put-old directory created/removed in
  that shared directory (and it couldn't be created on a read-only source). The pivot is now a
  **self-pivot** (`pivot_root(".", ".")` + `umount2(".", MNT_DETACH)`, the runc approach) that
  needs no put-old subdirectory, so nothing is written to the rootfs. 12 boxes sharing one bind
  rootfs now start 12/12 (was ~9/20); overlay boxes were already unaffected. Regression test added.
- **`-v` volume targets are resolved symlink-safe.** A volume's in-box target path is now resolved
  with an `openat(O_NOFOLLOW)` component walk confined to the new root, so a hostile image that
  ships a symlink at the mount point can't redirect the bind (and a host write) through it — the
  bind is refused instead. Regression test added.
- **Unknown `box`/`exec` flags are now rejected, not ignored.** A typo'd `--read-only` no longer
  silently runs a *writable* box — an unrecognized flag is a usage error.
- Audit hardening: closed an fd leak on an error path in the volume-target walk; reject a NUL byte
  in a `-v` target early; documented that `--net` also exposes host abstract-namespace UNIX sockets.

### Security (audit hardening)
- **pull integrity**: every blob is verified to hash to its `sha256:` digest before use
  (compromised/MITM registry + corrupt-download defense, beyond TLS).
- **registry**: a box's kernel start-time is recorded and checked, so a reused pid can't be
  mistaken for a live box (no false "running", no `stop` signalling an unrelated process).
- **seccomp**: denylist extended to the new mount API (`open_tree`/`move_mount`/`fsopen`/
  `fsconfig`/`fsmount`) and `unshare` (nested-userns escape) and `process_vm_readv`/`writev`
  (ptrace-equivalents) — closing gaps that contradicted the "blocks further mount/namespace
  manipulation" claim.
- **pull**: hardlink entries whose target escapes the rootfs (absolute / `..`) are now rejected.
- **image cache**: gated on a completion sentinel (no more "non-empty dir = valid" → no partial/
  poisoned rootfs); cache dir created mode `0700` under `~/.cache` (not a predictable `/tmp` path).
- **registry**: a pid that now belongs to another user (`EPERM`) is treated as gone — `kern stop`
  won't signal an unrelated process group via pid reuse.
- **sandbox**: a failed old-root unmount is now fatal (a leftover `/.old_root` would expose the
  host filesystem) rather than best-effort.

### Security
- **`search`/`images` strip terminal escapes from untrusted registry data.** A Docker Hub repo
  description/name (anyone can publish one) or a crafted cached image ref could carry ANSI/OSC
  escape sequences; printed raw they spoof the terminal (cursor/title/clipboard). The table path now
  strips control chars and `--json` escapes them as `\u00XX` (valid JSON, no injection).
- **`kern search` HTTP is bounded + HTTPS-pinned**: the Hub request caps the response
  (`--max-filesize`, no OOM from a huge body), pins the request **and every redirect** to HTTPS
  (`--proto`/`--proto-redir`, no `file://`/SSRF via a hostile redirect), and limits redirect count.
- **`kern top` restores the terminal on a fatal signal**: `SIGHUP` (SSH disconnect) / `SIGTERM` /
  `SIGINT`/`SIGQUIT` while the TUI is in raw mode + the alternate screen now runs an
  async-signal-safe handler (`tcsetattr` + reset escapes) before re-raising — no stranded terminal.
- **Full namespace isolation**: user + PID + **network** (only loopback) + **UTS** (hostname =
  box name) + **IPC** + mount. Verified live: host sees 528 procs, the box sees ~3; only `lo`
  in the box's network namespace.
- **Always-on seccomp denylist**: kexec, kernel-module (un)loading, ptrace, reboot, swap,
  further mount/`pivot_root`/`setns` are killed with SIGSYS; a wrong-arch syscall is killed too.
- **cgroup caps (memory 512 MiB + tasks 512)**: when a systemd user manager is present, `kern
  box` re-execs inside a transient `systemd-run --user --scope` (verified: `TasksMax=512`,
  `MemoryMax=512M`, **`MemorySwapMax=0`** so the memory cap is a HARD total — a workload over
  512 MiB is OOM-killed instead of silently swapping); otherwise a best-effort cgroup v2 path
  applies where delegated, degrading gracefully (no orphan cgroup) elsewhere.

- **`examples/`**: runnable, live-verified use-cases — run an image, throwaway shell, untrusted
  code (read-only + seccomp + no net), detached services + `ps`/`stop`, a `compose` stack, and
  per-task fan-out.

- **Minimal `/dev`**: a box gets `null`/`zero`/`full`/`random`/`urandom` on a fresh **tmpfs**
  `/dev` set up **after** pivot — host device fds are captured pre-pivot and bound in via
  `/proc/self/fd`, so a hostile rootfs with a symlinked `/dev` can't redirect writes to the host,
  and the image's own `/dev` is never mutated. (No `/dev/tty` — avoids TIOCSTI injection; never
  `/dev/mem`/disks; userns can't `mknod`.)
- **pull**: a non-`sha256:` (unverifiable) digest is now **refused**, not silently accepted.
- **Clean environment**: the box starts with a small, sane env (`PATH`/`HOME`/`TERM`/`HOSTNAME`),
  not the host's — host secrets/tokens and kern internals (`KERN_SCOPE`) no longer leak in.
- **Concurrent pulls** of the same image are serialized with a per-image `flock` (with a
  double-checked sentinel), so parallel `kern box --image X` from a cold cache all succeed.

- **`BENCHMARKS.md`**: measured multi-runtime comparison (vs Docker / runc / bubblewrap) — bare
  box ~3 ms, full `--image` ~7 ms, ~100× faster to start than `docker run` (and ~267× under
  parallelism), footprint, and resource-cap results.

### Added
- **`kern --help` now shows the `KERN` wordmark + colour** — a cyan/bold ASCII logo, bold section
  headers, cyan verbs, dim notes. Colour is emitted **only** when stdout is a TTY and `NO_COLOR`
  is unset, so piped output and scripts (and `kern --version`) stay plain. Dependency-free (a tiny
  `ui` module of raw escape strings); no EULA/demo banners — the public build stays clean.
- **`kern top` is now an interactive task-manager TUI** (when stdout is a TTY) — an htop-style
  full-screen view with tabs (**Overview** · **Boxes**), live refresh, and keyboard nav (`Tab`/
  `←→`/`1`/`2` to switch, `q`/`Esc`/`Ctrl-C` to quit). Boxes-only (the public build has no GPU/
  vCPU to monitor). Pure `libc` termios + ANSI, **no curses/ratatui dependency**; the terminal is
  put in raw mode + the alternate screen and **restored on drop** (clean teardown even on Ctrl-C
  or panic). Piped/non-TTY falls back to a one-shot table. New `registry::tasks` reads the box
  cgroup `pids.current` for the **PIDS** column.
- **`kern search <query>`** — search Docker Hub for images (name, stars, official flag,
  description), the same registry `kern pull` uses. Backed by a new `kern-oci` HTTP/JSON path
  (`net` + `json` modules, shared with `pull` so there's one curl wrapper and one string-scanner).
- **`kern images [--json]`** — list the images pulled into the local cache, by their *original*
  ref (recovered from the pull sentinel), with on-disk size and age — like `docker images`.

### Changed
- **`--bind-rootfs` — a fast path for kernels with a slow overlayfs.** The default still overlays
  the rootfs (immutable, shareable, sub-millisecond on normal kernels). But some Android-derived
  kernels mount an overlay in ~31 ms (vs ~8 ms for a bind; the syscall is 104 µs on x86). On an
  Arduino UNO Q this made the default box (34 ms) lose to bubblewrap (15 ms); with `--bind-rootfs`
  kern binds the rootfs directly and starts in **9.9 ms — faster than bubblewrap** — while still
  doing more (seccomp, real `/dev`, lifecycle). Trade-off (hence opt-in, `--rootfs`-only, not with
  `--read-only`): the source is mutable and shared. A hidden `KERN_TIMING=1` prints per-phase
  startup µs and found the bottleneck. Bind mode is hardened to stay within that trade-off and not
  exceed it: the root bind is **non-recursive** (`MS_BIND`, not `MS_REC`) so host filesystems
  mounted *under* the rootfs dir aren't leaked into the box, and bind mode does **not** inject
  `/etc/resolv.conf` (the overlay path writes it to a private scratch; a host-side write into the
  user's rootfs could follow a symlink and clobber a file outside it — so a bind-mode box uses the
  resolv.conf its rootfs already ships).
- **Single-uid map is now the default; `--uid-range` is opt-in** (faster *and* more isolated).
  Previously every box with an `/etc/subuid` allocation auto-mapped a 65k sub-uid range, which
  costs two `newuidmap`/`newgidmap` subprocesses at start and enlarges the namespace's id surface.
  The default is now the dependency-free single-uid map (box uid 0 = caller, nothing else) — a bare
  box cold-starts in **~2.5 ms (beats bubblewrap, ties rootless runc, ~145× faster than Docker)**.
  Pass `--uid-range` for workloads that need multiple uids inside the box (`apt`/`dpkg`, daemons
  that drop to `www-data`); if requested but unavailable it warns and falls back to single-uid.
- **Security: id-map helpers resolved by trusted absolute path only.** `newuidmap`/`newgidmap` are
  now located in `/usr/bin`,`/bin`,`/usr/sbin`,`/sbin` instead of via `$PATH`, so a writable PATH
  entry (e.g. `~/.local/bin`) can't shadow the system binary and feed a bogus uid mapping. The
  `/etc/subuid` lookup matches the login **name** first (numeric-uid row only as fallback, as
  shadow does), and the helper handshake is EINTR-safe and **fails closed** — any error in helper
  resolution, subuid parsing, the pid handshake, or the final verdict aborts rather than running a
  partially-mapped box. No privilege can be gained either way (the setuid helpers re-validate the
  allocation in the kernel).
- **Pull progress feedback**: `kern pull` and a cold `kern box --image` now report each step to
  stderr — `resolving`, layer count, per-layer `K/N` with a **live download progress bar** (curl
  `-#`), `verifying + extracting`, and a `✓ pulled` summary — so a download never looks frozen. A
  warm cache stays silent (no noise). The `box --image` path also prints a one-time
  "not cached — pulling once" notice so it's clear why there's a wait.
- **Compose progress**: `kern compose` now reports the resolved start order up front
  (`→ bringing up N box(es) in order: a → b → c`) and a `[i/N] starting '<name>'  <source> (after …)`
  line per box, so a multi-box stack (and any cold image pulls inside it) shows live progress
  instead of going quiet until the final summary.
- **Clearer "command not found" in a box**: a failed `execvp` now reports
  `cannot start '<cmd>' in box: <err>` with a hint (use a full path; a dynamically-linked binary
  needs its loader/libraries in the rootfs) instead of a bare `execvp failed: … (os error 2)`.
  Applies to both foreground (inline) and detached boxes (visible via `kern logs <name>`).
- **Truthful detached start (`kern box -d`)**: a readiness pipe (`FD_CLOEXEC` write end, closed by
  the box's successful `execvp` → EOF) makes the launcher print `started` only once the box is
  actually up, and `box '<name>' exited before starting — run \`kern logs <name>\`` (exit 1) if it
  dies first. No sleep, no poll — the only added latency is the box's real start time (~4 ms; ~7 ms
  with the systemd cgroup scope), the same a foreground box already pays. `compose` inherits this:
  a dependent box now starts only after its dependency is genuinely running.
- **Overlay scratch on tmpfs**: the writable upper/work layer now lives under `$XDG_RUNTIME_DIR`
  (tmpfs) instead of the disk cache — `box --image` cold-start dropped from ~25–32 ms to ~6 ms,
  and the writable layer is ephemeral and counts against the box's memory cap.
- `MountOps` is now fallible (`Result`), so the recorder and the real syscall path share one
  ordered, error-checked op log. First real dependency: `libc` (the single kernel boundary).
- Missing required arguments now produce a clear `usage:` error instead of a misleading
  "not implemented" (e.g. `kern pull` with no image, `kern box NAME` with no rootfs/image).

### Not yet (roadmap)
- `kern run` resource quotas (CPU/memory), tunable `--memory`/`--cpus`, interactive PTY (`-it`),
  port publishing (`-p`), image build, and GPU slices. See the README roadmap.

## [0.2.0] — Sandbox hardening

### Added
- `kern-isolation`: **mount-ordering typestate** `Rootfs<Mounted>` → `create_old_root()` →
  `Rootfs<OldRootReady>` → `into_readonly()`. Remounting the root read-only before pivoting in
  is now a **compile error**, not a sandbox-escape bug.
- `kern-isolation`: `MountMode` enum (overlay / bind / tmpfs) driving the initial root mount.
- `kern-cli`: `SandboxCtx` step sequence wired to the typestate.
- `kern box <name> --plan` — print the ordered isolation sequence (mount → pivot → read-only).
  Privilege-free; uses the validated `BoxName` newtype (rejects path traversal).

### Changed
- `overlay_ro_sequence` is now driven through the typestate; the characterization golden is
  **byte-identical** (the refactor changed no observable behaviour).

### Security
- `BoxName` hardened to a conservative charset (`[A-Za-z0-9_.-]`, no leading `-` or `.`, max 64
  chars). Blocks path traversal, NUL, whitespace, control characters, shell metacharacters and
  argument-injection by construction. Fuzzed with 40+ hostile inputs: zero crashes/panics.

## [0.1.0] — Foundation

### Added
- Workspace foundation: `kern-cli` (binary `kern`), `kern-common`, `kern-oci`, `kern-isolation`.
- Module-based CLI (no `include!()`): command parsing/dispatch + `--no-gpu` global flag.
- `kern-oci`: whiteout path-safety helper with a symlink-escape regression test.
- `kern-isolation`: the `MountOps` characterization seam (refactor-safety net).
- Project docs: README, SECURITY, ARCHITECTURE, CONTRIBUTING, CLA, CODE_OF_CONDUCT.
- CI: build + test + clippy + fmt + cargo-audit + cargo-deny on x86 (skip-graceful for HW).

[0.3.0]: https://github.com/getkern/kern/commits/main
[0.2.0]: https://github.com/getkern/kern/releases/tag/v0.2.0
[0.1.0]: https://github.com/getkern/kern/releases/tag/v0.1.0
