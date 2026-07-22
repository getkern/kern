# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to SemVer.
Pre-1.0: the CLI and config surface are NOT frozen; minor versions may change them.

**Deprecation policy (pre-1.0).** "Not frozen" does not mean "breaks without warning". When a
flag or config key changes:

- **Same meaning, new name** → the old name keeps working as a **deprecated alias** that prints a
  one-line warning to stderr, for **at least 2 minor releases** before it is removed. Your scripts
  keep running; you get a heads-up to update them.
- **Different meaning** → the old name is **rejected with an error** that explains the change and
  names the replacement (never silently reinterpreted, which would corrupt behaviour). Example:
  `--memory-swap` (Docker's mem+swap *total*) is refused with a pointer to `--memory-swap-max`
  (the cgroup v2 swap *allowance*), the two mean different things, so aliasing would lie.

Removals and deprecations are always listed under **Deprecated** / **Removed** here first.

## [0.6.11], 2026-07-22

A stricter, unambiguous resource-profile schema.

### Changed
- **`backend` is now REQUIRED on every `[[vcpu]]`/`[[vgpio]]`/`[[vdisk]]` profile** (breaking,
  pre-1.0). A profile must name the host resource it slices: a declared `[[cpu]]`/`[[gpio]]`/`[[disk]]`
  id, or a reserved keyword . **`host`** (the whole host CPU, or the host's own device nodes) or
  **`ram`** (a RAM-backed vdisk). This removes an ambiguity where a backend-less profile, or a typo in
  a backend, silently attached to a default/RAM resource. A missing or dangling backend is now
  rejected with a clear, actionable error at `kern validate`, at `kern box`/`kern run` attach time, at
  `kern config add`, and in the `kern top` form (which offers `host`/`ram` first). Migration: add
  `backend = "host"` (vcpu/vgpio) or `backend = "ram"` (vdisk) to a bare profile, or name a declared
  physical block. See `kern examples`.

## [0.6.10], 2026-07-22

A resource-isolation fix for `kern exec`.

### Fixed
- **`kern exec` now inherits the box's `--memory`/`--pids` caps.** An exec'd command joins the box's
  cgroup before entering its namespaces (the same "cap before fork" order the box's own PID 1 uses),
  so a fork bomb or memory hog run via `kern exec` is bounded by the box's limits, like `docker
  exec`. Previously it stayed in the launcher's cgroup and could exceed them. On the rootless
  per-box-scope path (e.g. an SSH login session on an edge board) the kernel won't let `kern exec`
  migrate into the box's transient scope; there it can't be enforced, so kern now warns when the box
  has explicit caps instead of leaking it silently. Namespaces + seccomp isolate the exec'd command
  either way. See [SECURITY.md](SECURITY.md).

## [0.6.9], 2026-07-21

A small CLI addition plus a big step for the language bindings (shipped separately as `kern-sandbox`
0.1.7 on PyPI + npm): a persistent warm interpreter that turns the code-interpreter path sub-millisecond.

### Added
- **`kern top` now shows a box-start rate.** The Boxes tab surfaces a per-second box-start rate with a
  sparkline, mirroring the existing runs rate, read from the daemonless mmap counter (offset 16). It is
  reader-side only: zero cost on the box-start hot path.

### Bindings (`kern-sandbox` 0.1.7, on PyPI + npm)
- **Warm kernel (`Sandbox.kernel()` / `Kernel`), Python and Node.** One persistent, warm Python
  interpreter in a long-lived box: cells run in a single resident process, so in-memory state persists
  across cells and the per-cell cost drops from a full CPython boot (about 10 ms) to sub-millisecond
  (about 300x, 25k cells/s). It captures the same rich mime-typed results as `run_code`, tears the box
  down on a per-cell timeout, caps oversize replies (a host-memory guard), and isolates the control
  channel on private fds so raw writes, C extensions and subprocess output are captured rather than
  corrupting the protocol (a raw `os.fork()` no longer spawns rogue clones). Trade: call-fast, not
  call-isolated (one process, one box, still network-off and resource-capped).
- **MCP kernel mode (`KERN_MCP_KERNEL=1`).** Routes the MCP server's Python `run_code` through a warm
  kernel, still network-off, respawning transparently on a timeout.

## [0.6.8], 2026-07-20

Coherence and agent-DX release: the 0.6.7 isolation features are now visible in `kern top`/`inspect`
and reachable from the language bindings, with live streaming and a workspace checkpoint.

### Added
- **`kern inspect` and `kern top` now surface the 0.6.7 isolation policies.** `inspect` shows the
  configured `mem-cap`/`pids-cap`, plus `landlock`, `egress` and `pod` when set (and the same fields in
  `--json`); the Boxes tab in `kern top` flags an egress/landlock box with a cyan badge, and the Overview
  shows a fleet-budget line when `KERN_FLEET_*` is in force. A box's requested caps and policies are
  recorded in its registry entry so they can be read back.
- **`--egress-allow` and `--landlock-rw` are now listed in the box help.**
- **Language bindings (Python + Node) gained the runtime features:** `profiles=["vcpu:…","vgpio:…",
  "vdisk:…"]` (attach a kern.toml resource profile, strictly validated), `egress_allow=[domains]` (a
  domain allowlist for the untrusted run box, mutually exclusive with full network), `on_stdout`/
  `on_stderr` live output callbacks (best-effort, the full capped output is still captured), and
  `snapshot`/`restore` of the workspace (a portable `.tar.gz` filesystem checkpoint, not a memory
  snapshot). `run_code` also accepts `language="node"`.

### Changed
- The Python binding no longer injects a `KERN_ACCEPT_EULA` variable (the public build has no EULA gate);
  the vestigial passthrough was removed from the bindings, examples and tests.

### Security
- **Snapshot `restore` is hardened against a hostile archive:** absolute paths, `..` traversal, symlink/
  device/hardlink members, a trailing-slash that could make a stat follow a planted symlink, a member
  size past the archive, a non-octal or negative size, and a bad ustar checksum are all refused; writes
  use `O_NOFOLLOW` with a symlink-rejecting parent descent. The Node hand-rolled tar reader is **opt-in**
  behind `KERN_SANDBOX_SNAPSHOT=1` (fail-closed) while it matures; the Python path uses the stdlib
  `tarfile`. The `egress_allow` and `profiles` values are strictly validated so a binding argument can
  never smuggle a CLI flag.

## [0.6.7], 2026-07-19

Agent and fleet sprint: run LLM/agent-generated code and dense per-request workloads with a real
egress boundary, a write-allowlist, warm-start snapshots, and honest fleet budgets.

### Added
- **`--egress-allow d1,d2,…` restricts a box's outbound traffic to a domain allowlist.** The box runs
  in an isolated network namespace and reaches the internet only through a kern-run filtering proxy
  that permits exactly the listed domains (ports 80/443). An agent can `pip install` from the index
  you allow but cannot exfiltrate to an arbitrary host. SSRF-guarded: a domain that resolves to any
  non-public address (loopback, RFC1918, link-local, CGNAT, reserved) is refused, and the request head
  is checked for smuggling. One inherent gap stays documented, not hidden: a domain sharing a CDN IP +
  SNI with an allowed one can be reached. Threat model and gaps in [docs/EGRESS.md](docs/EGRESS.md).
- **`--landlock-rw <path>` confines a box's writes with the Landlock LSM.** The box root is read+exec
  and writes are allowed only under the paths you name, a kernel-enforced second boundary the workload
  can't lift, fail-safe on symlinks.
- **`kern commit <box> <image>` snapshots a running box into a reusable image (warm start).** Bake an
  expensive one-time setup (`apt`/`pip`, a warmed cache) once, then start from it in milliseconds. A
  filesystem snapshot, not live memory: volumes and secrets are skipped, never baked in. It is
  `docker commit`, daemonless.
- **Fleet budgets.** `KERN_MAX_CONCURRENT` is a cooperative admission cap (best-effort, may overshoot
  under a parallel burst); `KERN_FLEET_MEMORY_MAX` / `KERN_FLEET_PIDS_MAX` place a REAL summed cap on
  `kern.slice` when boxes share it (root/direct-cap path), and warn + no-op on rootless per-box scopes
  where a summed cap can't be enforced. Scope stated honestly in [docs/CONFIG.md](docs/CONFIG.md).
- **`kern pod --uid-range`** maps a pod's members through a subuid range.
- **Node / TypeScript `kern-sandbox` binding**, 1:1 with the Python one, for embedding a fresh isolated
  box per call from JS/TS agents.

### Changed
- **A box now reads its own resource caps from inside.** Its cgroup namespace gets a read-only view of
  its own cgroup, so a JVM, .NET or Node runtime sees its real `--memory` limit (`memory.max`) by
  default instead of the host's, and **`/dev/shm` is a real tmpfs** so Postgres, Python `multiprocessing`
  and Chromium run out of the box.

### Security
- Egress path hardened end to end: resolved-IP vetting (whole name refused if any record is non-public),
  IPv4-mapped-IPv6 canonicalization, CGNAT / `240/4` / reserved ranges refused, bare-LF request-smuggling
  rejection, userinfo stripped from the authority, and slowloris / idle-relay bounds on the proxy.
- `kern commit` snapshots under an RAII cgroup freeze (TOCTOU-safe), with an async-signal-safe thaw so
  an interrupted commit never leaves a box frozen.

### Housekeeping
- Prose and CLI output swept free of em-dashes for brand consistency; crate `description` fields tidied.

## [0.6.5], 2026-07-18

### Added
- **`COPY`/`ADD` expand `*`, `?` and `[…]` globs against the build context** (Docker parity, verified
  against `docker build`): `COPY *.txt /app/`, `COPY src/* /app/`, `COPY [ab].conf /etc/` now copy each
  match into the destination directory; an unmatched glob is a clear error. Previously a glob source was
  taken literally and failed with "No such file". (A build-context *symlink* matched by a glob is still
  resolved/confined rather than preserved verbatim, kern's stricter no-leak copy behaviour.)

### Changed
- **Resource-profile keys are now spelled exactly like their CLI flags (BREAKING, see Rejected below).**
  `[[vcpu]]`: `vcpus` → `cpus` (CPU-time quota), `cpus` → `cpuset` (core pinning), `priority` → `nice`;
  `[[cpu]]`: `vcpus` → `cores`. The field in a profile now matches the flag you'd pass 1:1, removing a
  config-vs-flag inversion footgun. A `kern.toml` written for ≤ 0.6.4 must rename these keys (the old
  names are refused with a pointer, not silently reinterpreted, see **Rejected**).
- **`--memory` now warns, once and clearly, when the kernel can't enforce it.** On kernels that don't
  delegate the cgroup v2 `memory` controller, Microsoft's default WSL2 kernel, or Raspberry Pi OS
  without `cgroup_enable=memory`, a `memory.max` write is accepted but never bites, so the box would
  silently run uncapped. kern now detects the missing controller (env-independent) and prints an
  actionable heads-up (how to enable it on WSL, and that Docker/Podman hit the same limit there),
  instead of implying the cap is in force. The box still runs and stays fully isolated (namespaces +
  seccomp are unaffected); only the RAM cap is skipped. No change on a normal host, where the cap is
  enforced as before.

### Fixed
- **Pod holder no longer hangs a piped `compose up` / `pod create`.** The `__pod-holder` daemon inherited
  the caller's stderr and, being long-lived, held it open for the pod's whole life, so `kern compose up
  2>&1 | …`, `$(kern pod create …)`, or a CI log pipe never saw EOF and appeared to hang. The holder now
  redirects stdout + stderr to `/dev/null` once it prints `pod-ready`, and the parent's readiness wait is
  bounded (a wedged holder can't hang `pod create`).
- **`kern push` packs an owner-safe tar on a BusyBox host.** GNU tar takes `--owner=0`/`--group=0`;
  BusyBox tar rejects them, so pushing from Alpine or WSL errored. kern now detects the tar flavour and
  packs root-owned layers either way.
- **`kern box` now works out-of-the-box INSIDE a Docker/Podman container (CI runners).** The box
  overlay scratch defaults to `/run/user/<uid>`/`/tmp`, which inside a container sit on the
  container's own overlayfs, and the kernel rejects a nested-overlay upperdir with a bare
  `EINVAL`. kern now probes the scratch candidates and skips any that live on overlayfs, falling
  back to `/dev/shm` (a real tmpfs even in Docker; size-capped, announced on stderr). If every
  candidate is overlayfs the mount error is now actionable, "set `XDG_RUNTIME_DIR` to a tmpfs/disk
  path, or in Docker add `--tmpfs /run`", instead of `Invalid argument`.
- **`COPY <dir> <dest>/` now copies the directory's CONTENTS into `<dest>`, matching Docker** (verified
  against `docker build`), instead of nesting them under `<dest>/<dirname>/`. A directory source always
  has its contents copied (`COPY d /target/` → `/target/f1`, never `/target/d/f1`); a file copied into a
  directory still keeps its basename. Previously `COPY . /app/` (and any `COPY dir /existing-dir/`)
  wrongly nested the whole tree one level deep.
- **`COPY --chmod=<octal>` is now honoured for a context `COPY` and a `COPY --from`**, not only for
  `ADD <url>` / `COPY <<heredoc`. The mode is applied recursively to every copied file and directory
  (matching Docker); without `--chmod` the source mode is still preserved. Previously a
  `COPY --chmod=755 app /app` silently kept the source's mode (e.g. 0644). `--chmod` is now part of a
  cached layer's key, so two builds that differ only in `--chmod` no longer share a layer.
- **Windows `install.ps1`: the in-place update now actually runs** (was always falling back to a
  cache-wiping re-import). `wsl -- wslpath` eats backslashes in a Windows path, so the swap target
  resolved empty; the path is now passed with forward slashes.

### Security
- **Dangerous character devices are refused at bind time**, mirroring the resolver's fixed-identity deny
  on the pinned fd: raw memory (major 1: mem/kmem/port/kmsg), generic SCSI (major 21), and the stable
  misc majors `/dev/kvm` (10:232) and `/dev/net/tun` (10:200). If host root swaps a vetted char node for
  a dangerous one between the parent's resolve and the child's bind, the pinned-fd re-check still refuses
  it. Legitimate `vgpio:` devices (gpiochip, i2c, spi) are unaffected.

### Rejected (not aliased)
- **The pre-0.6.5 resource-profile key names are refused with a clear error, not silently reinterpreted.**
  Under the new scheme a bare `cpus` means the *quota* where it used to mean the *pinset*, so aliasing
  would change behaviour silently. Per the deprecation policy above, `[[vcpu]]` `vcpus`/`priority` and
  `[[cpu]]` `vcpus` are rejected with a message naming the replacement. Update `kern.toml`: `[[vcpu]]`
  `vcpus`→`cpus`, `cpus`→`cpuset`, `priority`→`nice`; `[[cpu]]` `vcpus`→`cores`.

## [0.6.4], 2026-07-15

### Added
- **`kern build` parses real-world Dockerfiles.** Comments inside `\` line-continuations, the `SHELL`
  instruction, BuildKit flags (`RUN --mount=…`, `FROM --platform=…`, `COPY/ADD --chown/--chmod/--link/
  --checksum`), the `# escape=` directive, a leading BOM, automatic `TARGETARCH`/`TARGETOS` build args,
  multi-name `ARG`, `FROM scratch`, and blank lines inside a continuation now parse instead of erroring.
- **`ADD <url>` and `COPY <<heredoc`.** `ADD` from an HTTPS URL (HTTPS-only, `--checksum` verified,
  `--chmod` honoured so a fetched binary is executable) and heredoc `COPY <<FILE … FILE` (the
  write-a-file-inline pattern) are supported, matching the common "download a static binary" recipe.
- **`.dockerignore` + `.kernignore`.** Build-context filtering with faithful Docker semantics:
  last-match-wins, `!` re-include, `*` non-recursive vs `**`, a filtered copy that does not follow
  symlinks out of the context, and a canonical context root (fail-closed, never fail-open).
- **Compose: real-world YAML.** Anchors/aliases/merge keys (`<<: *x`), the anchor forms real stacks use
  (Airflow/Sentry/Penpot), block scalars (`|`/`>`), multi-line & following-line flow, multi-line quoted
  scalars, same-file `extends`, `networks.*.aliases`, and mixed list/map `environment` salvage (which
  makes some engines panic). Real-world compose files now parse essentially 100%.

### Fixed
- **Windows `install.ps1` updates in place and keeps the image cache.** The updater no longer
  `wsl --unregister`s the distro (which wiped every cached image on each update); it swaps the binary
  in place and only falls back to a re-import, with a warning, if that is not possible.
- **`kern.toml` multi-line TOML arrays** (as `kern setup` writes them) now parse.
- The RAM-backed (tmpfs) vdisk scratch warning now says it is **EPHEMERAL**, not merely that it
  "counts against RAM".

## [0.6.3], 2026-07-13

### Added
- **Guided, "impossible to get wrong" profile forms in `kern top`.** Creating a vcpu/vgpio/vdisk
  profile now picks from what the host actually exposes instead of typing `/dev/` paths: detected
  devices are checkbox lists, absent kinds are read-only "none on this host" notes, `backend` is a
  single-select radio of the configured `[[gpio]]`/`[[cpu]]`/`[[disk]]` ids, and every typed field
  (numbers, sizes, names, the `extra` /dev path) is validated live with a three-state ✓ / "keep
  typing" indicator, a plain-language help line explains each field.
- **One validation rule shared by live-typing, save and load.** `config::field_state` is derived from
  the save authority (`profile_line` / `validate_profile_name`), so a value that types cleanly always
  saves and vice-versa, no per-field char-class list to drift, no dead-ends.
- **Whole-profile validation at save.** A `backend`/`extends` that references no configured
  `[[gpio]]`/`[[cpu]]`/`[[disk]]`/profile is refused before the write, with a clear message.

### Security
- **Capability-based `/dev` deny-list for vGPIO passthrough.** Refuses, by kernel IDENTITY
  (major/minor) where fixed and by name/path otherwise, every node that grants host control or raw
  memory/storage: block devices; mem/kmem/port/kmsg/oldmem; sg\*/nvme\* char storage controllers,
  bsg, dm/loop/btrfs control; VFIO (incl. the 6.x cdev); kvm/vhost\*/vbox\*; uinput/uhid/hidraw\*/
  hiddev\*; watchdog\*/mtd\*/nvram; net/tun, ppp; fuse/udmabuf; mei\*; dax\*; the privileged DRM
  `card*` modeset node; console/virtual-consoles/vcs\*/cuse. Render-only GPU (`renderD*`), rtc and
  serial ttys stay allowed. A specific USB device (`/dev/bus/usb/<bus>/<dev>`) is a scoped passthrough;
  the whole bus is refused.
- **fd-pinned device binds close the check→mount TOCTOU.** The runtime walks `/dev/…` one hop at a
  time (`openat(O_PATH|O_NOFOLLOW)`), pins the exact inode and binds from `/proc/self/fd`, so a name
  swapped at any depth between the resolver's check and the mount can't redirect it.
- **`extra` is a validated `/dev` path** (not free text); `i2c` entries are validated at save; the
  resolver still canonicalizes and re-checks every path under `/dev/` at launch.

### Fixed
- The `leds` picker drops netdev/keyboard-LED noise (`enp5s0-0::lan`, `input3::capslock`) and keeps
  real board LEDs. `midi` and `display` now actually detect devices (`display` offers the allowed
  `renderD*` GPU node) instead of always showing "none detected".
- `save_named_block` is fail-closed: it refuses to write a `kern.toml` that would not re-parse.

## [0.6.2], 2026-07-12

### Added
- **Nested boxes, `kern box --privileged`.** A full `kern box` can now run *inside* another
  (docker-in-docker style). The always-on seccomp filter blocks namespace + mount syscalls by
  default; `--privileged` re-allows **exactly five**: `unshare`/`setns`/`mount`/`umount2`/
  `pivot_root`, so a nested box can create its own namespaces and rootfs. Everything else stays
  blocked (kexec, modules, `bpf`, `io_uring`, keyring, `ptrace`, the new mount API), so it is
  materially stronger than a Docker `--privileged` container (which drops seccomp wholesale). It is
  **rootless-only**: honoured only when the box's root maps to an unprivileged host uid, decided by
  reading the effective `/proc/self/uid_map` after the namespace is set up (so a `--pod` box is
  judged by its holder's map, not the caller's euid), and refused outright as real root. Documented
  in [SECURITY.md](SECURITY.md); validated on x86_64 + aarch64 (incl. an Android-kernel board).
- **`kern build`: BuildKit `RUN` heredocs**: `RUN <<EOF … EOF` (the body runs as a shell script),
  `RUN <interp> <<EOF` (body fed on the command's stdin), `<<-EOF` tab-dedent, and `<<'EOF'` quoted
  delimiters. Unterminated / stacked / `COPY` heredocs error clearly (never a silent mis-parse).
- **`kern build`: `COPY --from=<external-image>`**: copy files straight out of an external image
  (`COPY --from=nginx:alpine /etc/nginx/nginx.conf /`), not just an earlier build stage. A build stage
  always wins over a same-named image; the image is pulled with the full hardening and its files are
  copied through the same confined (`openat2 RESOLVE_IN_ROOT`, no-follow, `..`-reject) path as a stage.
- **`kern compose`: Docker v3 `deploy.resources.limits`** (`memory`/`cpus`/`pids`) are now honoured as
  hard caps, where rootless Docker ignores them without cgroup v2+systemd, kern enforces them. A
  `limits:` block that maps nothing (a typo) warns instead of silently running uncapped.
- **`kern compose`: multi-line arrays** (`command = [\n …\n]`) in a native TOML stack now parse.

### Fixed
- **Multi-stage builds** failed at the first stage's `RUN` with a fork-safety refusal, the build's
  transcript recorder held a background thread, so `COPY --from`'s merged-view `fork()` saw a
  multi-threaded process. The recorder is now a child process; the build stays single-threaded.
- **`redis:latest` (Redis 8) and other io_uring-probing images** were SIGSYS-killed mid-startup and
  now run, see Security below.
- Clearer parse errors: an unterminated quoted compose value and an unterminated `RUN` heredoc now
  report the offending line instead of failing later with a confusing downstream error.
- Dropped a dead `KERN_ACCEPT_EULA` passthrough and its stale comments from the embedding SDK, the
  public build has no EULA gate (and never claimed one in docs).

### Security
- **seccomp: deny-but-degrade for probe-and-fallback syscalls.** `io_uring`, `userfaultfd`,
  `perf_event_open`, the keyring family and `syslog(2)` now return `ENOSYS` instead of a `SIGSYS`
  kill. They are still fully DENIED, the syscall never runs, so the isolation is identical, but
  software that merely probes an optional fast-path (e.g. Redis 8's io_uring) now falls back cleanly
  instead of dying. Real escape vectors (kexec, kernel modules, the mount API, `bpf`, `ptrace`, the
  nesting set) still hard-KILL. The two sets are asserted disjoint.

## [0.6.1], 2026-07-08

**docker-compose YAML compatibility**, **image registry `push`**, and a split-out, fuzzed compose
parser, each built dev → test → clean-code → security-audit (multi-agent, adversarially verified).

### Added
- **docker-compose YAML support**: `kern compose` now reads a `docker-compose.yml` (not only the
  native kern TOML stack): services, `image`/`build`, `command`/`entrypoint`, `environment`/
  `env_file`, `ports`, `volumes`, `depends_on` (incl. `condition: service_healthy` /
  `service_completed_successfully`), `healthcheck`, `secrets`, resource/cap/hardening keys. The
  parser is hand-rolled and **dependency-free**; the unmappable long tail **degrades with a warning**
  rather than silently mis-converting. Structural YAML we don't support (anchors/aliases →
  billion-laughs, tab indent, block scalars, multi-doc, tags) is **refused up front** with a precise
  line.
- **full `${VAR}` interpolation modifier set**: Docker's `${VAR:-default}` / `${VAR-default}`,
  `${VAR:+replace}` / `${VAR+replace}`, and `${VAR:?msg}` / `${VAR?msg}`, with the `:` meaning
  "treat empty like unset". Previously only `${VAR:-default}` (unset-only) was handled, so an
  `:+` replacement or an empty-value default silently produced the wrong string. Verified identical
  to `docker compose` on the same file.
- **nested `${VAR}` interpolation**: `${A:-${B:-default}}` now resolves the inner expression first,
  then the outer (Docker parity), via a balanced-brace scan; previously the whole thing passed through
  verbatim. Depth-capped (16) so an adversarial `${${${…}}}` can't drive unbounded recursion
  (fuzzed: 800k+ runs, terminates).
- **compose `tmpfs` with options**: Docker's `- /scratch:size=10M,mode=1770,uid=1000` was forwarded
  whole to `--tmpfs`, which took the entire option string as the size and **aborted the service**.
  Now the `size=` option is kept (`--tmpfs /scratch:10M`) and the rest is dropped with a warning.
- **compose `profiles`**: a `profiles:`-tagged service was warn-and-ignored but **still started**,
  a service meant to be OFF ran on a plain `up`. Now it is inactive unless one of its profiles is
  enabled via `COMPOSE_PROFILES` (Docker semantics; `*` enables all), and a `depends_on` toward a
  dropped profiled service is pruned rather than failing the topo sort.
- **`kern push`**: publish a cached image (rootfs + config) to an OCI registry v2 (schema-2
  manifest), `docker pull`-compatible. WRITE-scoped auth via `kern login`; all requests HTTPS-pinned.
  Verified end-to-end against a local `registry:2`: push → pull-back reproduces an identical rootfs
  (byte-for-byte file set) that boots a box.
- **`kern-compose` crate**: the compose parser is now its own CLI-free library crate, **fuzzed in
  isolation** (`fuzz/compose_yaml`, property: parse never panics + a parse is always
  topo-orderable-or-cycle). `toml_lite` (the shared quoted-string/bool/array/comment scanners) moved
  to `kern-common`.

### Security
- **Python binding: workload env goes via a private `--env-file`, not argv**: `Sandbox(env={...})`
  passed each value as `--env K=V` on the `kern box` argv, visible in `ps` / `/proc/<pid>/cmdline` to
  any local user (a credential leak for a component whose job is running untrusted code beside secrets).
  The env is now written to a `0600` file in the binding's own `0700` workspace and passed as
  `--env-file`; a newline/NUL in a key or value is rejected. Verified: env still reaches the box, the
  value no longer appears in any `kern`/box process argv.
- **`kern run --` honors end-of-options for profile tokens**: `kern run -- vcpu:heavy prog` peeled
  `vcpu:heavy` as a `[[vcpu]]` profile despite the `--`, replacing the pinned program with its own first
  argument (a `--`-contract violation, and divergent from the `box` path). `run` now preserves the
  leading `--` so the profile-peeler treats everything after it as the literal command. No escape (run
  is unsandboxed and execs argv directly), but the arg-parsing confusion is fixed.
- **seccomp: deny io_uring and the kernel keyring**: `io_uring_setup/enter/register` (a large,
  historically bug-rich async-I/O surface behind real container-escape CVEs) and
  `add_key/request_key/keyctl` are now in the always-on box denylist, matching Docker's default
  profile / gVisor. A sandboxed workload never needs them. A regression test pins the critical set.
- **box `--ssh`: disable TCP/tunnel forwarding**: the throwaway sshd now sets `AllowTcpForwarding no`,
  `PermitTunnel no`, `GatewayPorts no`, so a login can't port-forward out of the box (it already binds
  loopback-only inside the box netns, uses pubkey-only auth, and modern ciphers).
- **`--secret NAME=value` warning is honest about persistence**: the inline form is not only visible
  in `ps` (ephemeral) but recorded in the systemd journal on the cgroup-scope re-exec, where it
  outlives the box. The warning now says so and steers to `NAME=-` (stdin) or a file, which never hit
  argv.
- **push: refuse a cross-host upload redirect**: an untrusted registry answering the blob-upload
  `POST` with an absolute `Location:` on another host could exfiltrate the auth token / `kern login`
  credentials and the private layer to that host (CVE-2020-15157 class). The Location is now required
  to be the **same host and port** as the registry; an HTTPS→http downgrade, a loopback→internal-IP
  bounce (SSRF), or a same-host **different-port** bounce (a distinct internal service) is rejected.
- **compose warnings sanitize terminal control characters**: a warning interpolates untrusted compose
  text (service names, keys, values, paths); a hostile file could embed ANSI escapes / cursor moves /
  carriage returns in, say, an unknown field name and inject them into your terminal (spoofed or hidden
  output) when the parser warned about it. All warnings now escape control chars to `\xNN`
  (centralized in `warn`, so every call is covered). Build-context and bind-source `../` traversal were
  already refused; service names that look like flags (`--privileged`) were already rejected.
- **OCI: reject a tar link/dir header with a non-zero size (extractor-desync escape)**: a hostile
  layer could set a false `size` on a symlink/hardlink/directory header (which carry no data). The
  in-process vetter skipped `size` bytes trusting the lie, but a non-GNU `tar` (**BusyBox**, on the
  musl/edge boards kern targets) reads those bytes as the NEXT header, so an escaping symlink
  (`esc → /etc/shadow`) hidden in the "data" slipped past the escape guard and was extracted. The
  vetter now rejects a non-zero size on typeflags `1`/`2`/`5`, so it and every extractor agree on where
  each header ends. (**Critical**; found in a hacker-mode audit.)
- **OCI push: don't send credentials to a same-parent-domain sibling auth realm**: the push
  credential-leak fix covered the blob-upload redirect but not the auth challenge: `realm_host_trusted`
  trusted **any** subdomain of the registry's parent domain, so on shared hosting a hostile
  `registry.acme.com` could point its token realm at an attacker-controlled `attacker.acme.com` and
  harvest the long-lived write password. Trust is now the exact host or a **hardcoded** known
  registry↔auth pair (Docker Hub), never a generic parent-domain rule. (**High**.)
- **cpuset huge-range memory-exhaustion DoS**: `cpuset: 0-999999999` (accepted by the format check)
  expanded to a ~8 GB `Vec` before the per-index bound ran. The range is now clamped to `CPU_SETSIZE`
  before expansion. (**High**.)
- **compose parser panic-hardening**: an untrusted `healthcheck.interval` with a huge digit-run
  (`6000000000000000h`) no longer overflow-panics (debug) or wraps to a nonsense value (release);
  `parse_duration_secs` uses checked arithmetic and falls back to the box default. An anchor/alias is
  now refused in **every** position, value (`k: *a`), list-item (`- *a`), inline collection (`[*a]`,
  `{k: *a}`), and inline **map key** (`{&a k: v}`), where it previously reached the box as the literal
  `*a`. The guard is defined by construction (a `&`/`*` that starts a token outside quotes, not a
  hand-kept opener list) and a 50k-case property test proves it against an independent oracle. `${A${B}}`
  no longer leaks a stray `}`, and `${VAR}` inside a comment no longer raises a spurious unset-var warning.

### Fixed
- **`kern <cmd> --help` shows the help**: every subcommand (`box`, `run`, `pull`, `push`, `compose`,
  `exec`, …) rejected `--help`/`-h` as an "unknown flag" error; only the first-position `kern --help`
  worked. The universal `<tool> <cmd> --help` habit now prints the full reference instead of an error.
  A `--help` after `--` (part of the box/run command) is still passed through to the workload.
- **compose `entrypoint` + `command` composition**: a **shell-form** entrypoint (`entrypoint: /x`)
  now ignores `command` (Docker semantics) instead of appending it as shell positional params (which
  silently dropped the command); an **exec-form** (list) entrypoint still composes `entrypoint ++
  command`.
- **push: pushed layers are root-owned (0:0)**: the layer tar previously carried the invoking
  user's UID/GID (e.g. `1000`), so a pulled image had host-UID-owned files. Now normalized to `0:0`
  with `--owner=0 --group=0`, matching real Docker layers. Verified: push → pull-back yields
  root-owned files and stays `docker pull`-compatible.
- **compose list-form env host pass-through**: a `environment: [- API_KEY]` entry with no `=` is
  Docker's host pass-through (inherit `API_KEY` from the host env). The bare `API_KEY` was forwarded
  to the box's `--env K=V` parser, which rejected it and **aborted the whole service**. Now: present
  in the host → `API_KEY=<value>`; absent → omitted (Docker semantics), never a malformed `--env`.
- **compose long-form volumes**: a `volumes: [{type: bind, source: S, target: T, read_only: true}]`
  entry was forwarded to the box's `-v` as the raw `{…}` and **aborted the service**. Now reconstructed
  to `S:T[:ro]` (verified: the bind mounts and `read_only` is kernel-enforced). An anonymous/tmpfs
  long-form (no `source`) is warned-and-skipped, not forwarded as a malformed `-v`.
- **compose `healthcheck.timeout` / `start_period` durations**: these map to `--health-{timeout,
  start-period}`, which take integer **seconds**, but Docker writes them as durations (`30s`, `1m30s`,
  `0s`). The raw string was forwarded verbatim, so a standard `timeout: 30s` aborted the box
  (`usage: --health-start-period <seconds>`). They now convert through the same `parse_duration_secs`
  as `interval`; `start_period: 0s` (no grace) correctly reaches the box as `0`. (Found by an extreme
  vs-Docker test.)

### Changed
- `kern_common::toml_lite::strip_comment` is now **escape-aware** (a `\"` no longer closes a string,
  so a `#` after it stays in the value). This is a **bug-fix** bundled with the `toml_lite` move, it
  affects both the compose parser and the `kern.toml` profile loader, and only changes output for the
  rare line with an escaped quote before an unquoted-looking `#` (previously that value was truncated).

## [0.5.7], 2026-07-03

**The full 0.5 launch.** kern grows from a fast sandbox/OCI runtime into a **feature-complete
daemonless container + resource runtime**: the entire private feature set minus GPU/intelligence.
Every slice was built dev → test → clean-code → security-audit → perf; no stubs ship. 214 tests,
clippy/`cargo-deny`-clean, security-audited. (Image registry **push** and GPU slices are
deliberately out, see the README roadmap.)

### Added
- **Full volume system**: `-v src:dst[:ro]` bind mounts (symlink-safe), **named volumes**
  (`-v data:/work`, auto-created; `kern volume create/ls/rm/inspect/prune`) with an optional
  **per-volume quota** (`--size`, ext4-on-loop when privileged / honest fallback otherwise), and
  **network volumes** (`nfs://`/`smb://`/`sshfs://`) mounted rootless via FUSE/GVFS.
- **`--secret NAME=value` / `NAME=-` / `SRC[:NAME]`**: deliver a secret as `/run/secrets/NAME`
  (mode `0400`) on a RAM tmpfs; never in the image, argv (stdin form), or the workload's env.
- **`--ssh <port>` / `--ssh-key`**: a throwaway `sshd` inside the box (auto-generated ed25519 keypair
  or your pubkey), published on the host port, a ready-to-`ssh` workspace.
- **Networking & identity**: `--network host|none` (unifies `--net`), `--hostname`, **`--tun`**
  (`/dev/net/tun` for WireGuard/VPN), `--user UID[:GID]` (drops privilege, fails closed if unmapped).
- **`--pids-limit`, `--tmpfs PATH[:size]`**: fork-bomb cap and a fresh `nosuid,nodev` box tmpfs.
- **`--cap-add` / `--cap-drop CAP|ALL`**: configure capabilities on the always-dropped baseline.
- **Box operations**: **`kern cp <box>:<src> <dst>`** (symlink-confined via `openat2 RESOLVE_IN_ROOT`,
  CVE-2019-14271-safe), **`kern pause`/`unpause`** (cgroup freezer), **`kern attach`** (live output).
- **Advanced health**: `--health-retries` / `--health-start-period` / `--health-timeout`, and
  **`--health-action <restart|stop|none>`** (act when a box turns unhealthy, `restart` implies the
  on-failure policy; `stop` tears the box down).
- **`--timeout <sec>`**: auto-stop a box after N seconds (foreground, `-it`, and detached). The
  watchdog runs in the host namespace so it can reliably terminate the box's PID-namespace init.
- **`--env-file <file>`** (repeatable, `K=V` lines, `#` comments), layered under `--env` (explicit
  wins); **`--nice <n>`** (-20..19); **`--io-weight <n>`** (cgroup v2 `io.weight`, best-effort);
  **`--config <path>`** (a specific `kern.toml` for `vcpu:`/`vgpio:`/`vdisk:` profile tokens);
  **`--show-config`** (print the resolved configuration and exit, a dry run); **`-q`/`--quiet`**
  (suppress the foreground status panel).
- **`vdisk:` / `vgpio:` profiles**: a size-capped disk at `/vdisk/<name>` (tmpfs / ext4-loop, with
  `--iops`/`--bandwidth` → `io.max`) and per-peripheral GPIO/I2C/SPI/LED passthrough (deny-by-default).
- **Operations**: `kern doctor` (host preflight), `info`, `bench`, `history`, `recover`, `gc`,
  `kill`/`killall`, `completions <bash|zsh|fish>`; registry **`login`/`logout`** (private-image pulls,
  credentials `0600`, passed to `curl` off-argv); `config [edit|setup|probe|clear]`.
- **Any-registry image pulls**: auth now follows the standard registry-v2 `WWW-Authenticate`
  challenge (Bearer token or HTTP Basic), so `--image ghcr.io/…`, GitLab, quay, Harbor and
  self-hosted registries work, not just Docker Hub. Every request is TLS-pinned (`--proto =https`,
  https-only redirects, `--` URL terminator); credentials go to the token endpoint / registry
  off-argv via a `curl -K` STDIN config.
- **`--image` now honors the image's OCI config**: `Entrypoint`/`Cmd`/`Env`/`WorkingDir`/`User` are
  applied as defaults, so `kern box --image redis` runs the image's real entrypoint (like
  `docker run`), not a bare shell, with the image's env and workdir. Explicit flags always win:
  `-- CMD` replaces `Cmd` (kept under `Entrypoint`, docker-style), `--env`/`--env-file` override the
  image env, `--workdir`/`--user` override theirs. The (sha256-verified) config blob is cached
  alongside the rootfs so a cache hit reapplies it without re-pulling.
- **`--restart always` / `--restart unless-stopped`**: a persistent, reboot-surviving box **without a
  kern daemon**: kern writes a `systemd --user` unit (`~/.config/systemd/user/kern-<name>.service`),
  enables it, and turns on linger, so systemd, already running, restarts the box on any exit and
  brings it back at boot. Resource caps (`--memory`/`--memory-swap-max`/`--cpus`/`--pids-limit`) are
  enforced by the unit's own service cgroup. The box still shows in `kern ps`/`logs`/`exec`; `kern
  stop` (and `stop --all`) disable and remove the unit so it neither restarts nor returns at reboot.
  `--restart` also now takes a **policy** (`no` | `on-failure` | `always` | `unless-stopped`, Docker
  names); bare `--restart` stays `on-failure` (kern's in-process supervisor, unchanged). Command args
  are systemd-quoted and control-char-rejected so the unit can't be injected into.
- **`kern pod`**: shared-network **pods** for multi-service stacks: boxes in a pod reach each other
  **by name** on `127.0.0.1` (like a Kubernetes pod). `kern pod create <name>` spawns a holder that
  owns the pod's user+net namespace; `kern box <n> --pod <name>` joins it (its own mount/pid/uts/ipc
  ns stay private, only user+net are shared, so pod members are co-trusted) and is registered in a
  shared `/etc/hosts` mapping every member → `127.0.0.1`. Publish a pod service to the host with `-p`
  on its box. `kern pod ls` / `kern pod rm`. Daemonless; pod join is ~6 ms (a `setns`, cheaper than a
  fresh box) and a reused holder PID is rejected via its net-ns inode identity. **Outbound**: if
  `pasta`/`passt` is installed, `kern pod create` attaches it to the pod (rootless userspace NAT) so
  pod services also reach the internet, with DNS wired up automatically, no config; if it isn't, the
  pod is loopback-only (inter-service only) and says so. The dependency is **optional** (kern needs
  nothing extra to run, pasta only unlocks outbound). **`kern compose <file>` auto-pods**: a
  multi-service stack is put in a pod named after the file, so services reach each other **by name
  with zero config** (`--no-pod` opts out); `kern compose <file> down` stops the stack and removes the
  pod. `compose up` of a 2-service stack (pod + NAT + both boxes) is ~38 ms.
- **`kern build`**: build a local image from a **Dockerfile subset**, daemonless
  (curl/tar/cp): `kern build -t <name> [-f Dockerfile] [--build-arg K=V] [<context>]`. `RUN` executes
  inside a real `kern box` (host net, full userns/seccomp/cap isolation); `COPY`/`ADD` copy from the
  context; `ENV`/`WORKDIR`/`USER`/`CMD`/`ENTRYPOINT`/`EXPOSE`/`ARG`/`LABEL` accumulate into the image
  config. Builds are **layered**: the base is a shared read-only overlay lower and only the *diff* is
  stored (KB, not a full base copy), so a build's time and disk are independent of the base size, and
  a rebuilt/derived image is prune-safe (the base is re-resolved by ref). Where unprivileged overlay
  isn't available it transparently falls back to a flat copy build (`KERN_BUILD_FLAT=1` forces it).
  The result lands in the image cache so `kern box --image <name>` runs it with **no pull** (it reuses
  the OCI-config sidecar).
  Supported instructions are honoured with Docker semantics (ENTRYPOINT resets the base CMD; RUN/CMD/
  ENTRYPOINT are left for the shell, only ARG/ENV substitute); unsupported ones (multi-stage,
  `VOLUME`/`HEALTHCHECK`/`ADD <url>`/`COPY --from`) are **rejected with a clear error**, never
  silently ignored. COPY/WORKDIR destinations are `..`- and symlink-escape-proof (can't write outside
  the image rootfs). Consecutive `RUN` steps are **batched into one box** (each still in its own
  `/bin/sh -c`, `&&`-chained for fail-fast + per-RUN cwd reset) and build boxes skip the transient
  systemd scope, so a 10-`RUN` build is ~25 ms instead of ~160 ms, and build time is independent of
  the base image size. Builds are **layer-cached** (Docker-style): every unit (a RUN batch, a COPY, a
  WORKDIR) is a content-addressed layer keyed by everything before it + its own inputs (a COPY folds
  in the copied file contents), so an unchanged rebuild reuses cached layers and re-runs nothing,
  and a code change reuses the expensive dependency layers before it. An unchanged rebuild is ~13 ms
  and the cache is shared across images.
- **`--cpuset-cpus <list>`** (on `box` and `run`), pin a box to specific CPUs (`0-3`, `0,2,4`).
  Applied via **`sched_setaffinity`** (the workload inherits the affinity across `exec`), so it
  **works rootless with no cgroup `cpuset` delegation**: which is frequently unavailable on a user
  session even when `cpu`/`memory` are. On hosts where the `cpuset` controller *is* delegated, the
  cgroup `cpuset.cpus` / systemd `AllowedCPUs` write also applies as the harder, unwidenable path.
  The list is structurally validated (`N` or `N-M`, `N<=M`, no empty tokens) so a typo can't
  silently yield an unpinned box and nothing arbitrary reaches the kernel file. (Cooperative for the
  trust model, a hostile workload could widen its own affinity; `--memory`/`--cpus` are the hard,
  cgroup-enforced governance.)
- **`--memory-swap-max <size>`** (on `box` and `run`), swap allowance, mapped 1:1 to cgroup v2
  `memory.swap.max` (a *separate* limit from `--memory`; default `0` = swap off). This is the
  honest v2-native knob, **not** Docker's combined mem+swap total. Accepts an explicit `0` (swap off).
- **`kern run --config <kern.toml>`**: a specific config for `run`'s profile tokens (`vcpu:`/…),
  matching `kern box --config` so the two verbs share one profile surface.
- **I/O limits are feedback-first**: a `--iops`/`--bandwidth`/`--io-weight` request that the host's
  cgroup `io` controller isn't delegated to enforce now prints a clear "not enforced" note instead of
  silently doing nothing.
- **`kern inspect <name> [--json]`**: full detail for one running box (pid/pid1, rootfs, command,
  uptime, ports, health, and live mem/cpu/tasks). Untrusted fields are escape-scrubbed.
- **`kern prune`**: garbage-collect the leftover log/health sidecars of boxes that are no longer
  running; reports what it reclaimed (or "nothing to prune"). Live boxes are never touched.
- **Frozen TOML box schema** ([docs/CONFIG.md](docs/CONFIG.md)), `[box.NAME]` tables mirror the
  full `kern box` CLI (was only `image`/`rootfs`/`command`/`depends_on`): `memory`/`cpus`/`cpuset`/
  `swap_max`/`pids_limit`/`io_weight`/`nice`/`timeout`, `workdir`/`read_only`/`uid_range`/
  `bind_rootfs`/`hostname`/`user`/`tmpfs`, `net`/`tun`/`ports`/`ssh`/`ssh_key`,
  `env`/`env_file`/`secrets`, `cap_add`/`cap_drop`, and the full
  `restart`/`timeout`/`health_*` supervision set. One rule, **TOML mirrors the CLI**: so the same
  table is what a future `--profile` will reuse; the key names and array-vs-table shape (including
  the remaining reserved keys for later slices) are frozen from 0.5.0. Unknown keys are still
  rejected with the offending line.

### Security
Each feature slice was adversarially audited; highlights:
- **seccomp x32-ABI kill**: on x86_64, x32 syscalls (which share the x86_64 arch token) are killed,
  closing the classic bypass where the x32 alias of a denied syscall slipped past a number-only denylist.
- **`kern cp` is symlink-confined**: the in-box path resolves under `openat2(RESOLVE_IN_ROOT |
  RESOLVE_NO_MAGICLINKS)` on `/proc/<pid1>/root`, so a hostile image can't redirect a copy to a host
  file (the CVE-2019-14271 class). Regular files only, size-capped.
- **`--user` fails closed**: if the requested uid can't be mapped, the box refuses to start rather
  than silently running as in-box root.
- **`--user` + `--cap-drop ALL` compose correctly**: the capability drop is now split around the
  user switch (drop the *bounding* set → `setgid`/`setuid` → clear the *effective* set), so the
  canonical hardened profile (`--user 1000 --cap-drop ALL --read-only …`, e.g. for running untrusted
  code) no longer fails with a spurious "gid isn't mapped" from `CAP_SETGID` being dropped too early.
- **In-box PTYs**: the box now mounts a private `devpts` at `/dev/pts` (+ a `/dev/ptmx`
  multiplexer, `nosuid,noexec,newinstance`), so programs *inside* the box can allocate a controlling
  terminal. Interactive `ssh` into an `--ssh` box (and `screen`/`tmux`/`script`) work instead of
  failing "PTY allocation request failed". (`kern box -it` was unaffected, it uses a host PTY.)
- **Box root is `nosuid,nodev`**; `--secret` never touches the image/argv/env; registry credentials
  are `0600` and passed to `curl` via stdin config, never `/proc/<pid>/cmdline`.
- **Device access is deny-by-default** and covered by an adversarial test: a box's `/dev` is a fresh
  tmpfs with only a safe allowlist (`null/zero/full/random/urandom`); a raw disk / `/dev/mem` is
  absent and a fabricated device node is inert (userns `SB_I_NODEV`). See SECURITY.md.

### Rejected (not aliased)
- **`--memory-swap`**: refused with an error pointing to `--memory-swap-max` (different meaning on
  cgroup v2; silently aliasing it would lie). Per the deprecation policy above.

### Fixed
- **Duplicate box names are refused.** Starting a box whose name is already held by a *running* box
  now errors (`a box named '<n>' is already running`) instead of silently stacking a second box that
  made `stop`/`logs`/`exec` ambiguous. A repeated `kern compose … up` no longer accumulates
  duplicate services. A stopped box's name is immediately reusable.
- **Pod teardown no longer leaks its NAT daemon.** `pasta`/`passt` re-execs into an ISA-optimised
  variant (`pasta.avx2`, …), so the identity check that guards against PID reuse never matched and
  the outbound daemon survived every `kern pod rm` / `kern compose … down`. It is now matched by
  process-name family and reliably reaped.
- **Concurrent `kern pod create <same-name>` can no longer orphan a holder.** The mkdir loser used to
  reclaim the winner's still-initialising pod directory and spawn a second namespace holder; it now
  detects the in-progress claim (with a bounded wait so a slow host can't race the marker) and backs
  off, so exactly one holder is ever created.
- **A `[[vcpu]]` `extends` cycle no longer crashes kern.** A `kern.toml` where a profile extends
  itself (directly or through a chain) sent `resolve_vcpu` into unbounded recursion and aborted the
  process with a stack overflow; cycles are now detected and reported (`[[vcpu]] 'extends' cycle: a
  -> b -> a`).
- **`KERN_CONFIG` is now honoured.** The documented `KERN_CONFIG` environment variable (an explicit
  `kern.toml` path, overridden only by `--config`) was ignored, the default location was always
  used. It now works, and a missing/malformed file named that way is a clear error, not a silent
  fallback.
- **`--secret NAME=value` now warns that the inline value is visible in `ps`.** The value sits in the
  process's argv, so for a detached box it stayed readable in `/proc/<pid>/cmdline` for the box's
  whole lifetime; the warning steers to the non-leaking forms (`NAME=-` stdin, or a `SRC:NAME` file),
  which were already leak-free.
- **`kern stats <name>...` now filters to the named boxes** (Docker-parity) instead of silently
  ignoring the argument and printing every box; a requested name that isn't running is reported.
- **A paused box now shows as `paused`** in `kern ps` (HEALTH) and `kern top` (STATUS), previously a
  frozen box (`kern pause`) looked identical to a running one, even though the freeze was real.
- **A `-p` host port already in use now fails fast with a clear error** ("cannot publish host port
  N: …, already in use") instead of the box printing "✔ started" while its forwarder silently
  failed to bind (its error was swallowed for detached boxes). The port is pre-flighted before the
  box starts.
- **`--memory` / `--cpus` now warn honestly when the host can't enforce them.** On a rootless host
  whose user slice lacks a delegated `memory`/`cpu` controller (e.g. some Raspberry Pi setups), the
  cap was silently ignored, the box looked capped but wasn't. kern now checks the *effective* limit
  up the whole cgroup tree (so it never false-warns on a host where the systemd scope is the real
  enforcer) and prints a one-line "not enforced" note only when nothing in the chain caps it.
- **A non-root `--user` now actually works in the default (overlay) box.** Previously any
  `--user <non-zero-uid>` failed with `execvp: Permission denied`: overlayfs presents the merged
  root's mode as the private upper dir's, which was `0700`, so a dropped, capability-less uid
  couldn't even traverse `/`. The box root is now `0755` (a normal root fs) when a non-root `--user`
  is requested, still private on the host (its `0700` parent scratch dir is unchanged), so only the
  in-box view changes. Default boxes (running as the box's root) are untouched. For a `--bind-rootfs`
  tree you still control the perms; the exec-failure hint now names the uid/rootfs cause instead of
  the misleading "command must exist … loader" message.

## [0.4.0], 2026-06-28

The resource-governor verb (`kern run`), tunable CPU/memory caps, interactive PTY, port
publishing, restart/health supervision, and a defense-in-depth hardening pass (least-privilege
capabilities, loopback-by-default ports, a `syslog` seccomp block) from an adversarial pentest.

### Added
- **`kern box` status panel**: a foreground box now prints an aligned, colour-coded posture summary
  (cmd · fs · net · seccomp/caps/userns guard · limits · mounts; `-it` adds an exit hint) with an
  **actionable warning block** for
  the deliberately-open choices (`--net`, `--bind-rootfs`), each with a one-line fix. Colour is
  semantic (green = isolated, yellow = open-but-chosen), the seccomp count is read live (never
  drifts), untrusted fields (image ref, command) are **stripped of terminal-escape sequences**
  before display (no ANSI/title/cursor spoofing), and it degrades cleanly: ASCII glyphs when the
  locale isn't UTF-8, width from
  `TIOCGWINSZ`/`$COLUMNS`, **plain when `NO_COLOR`** is set. Printed to **stderr only when stderr is
  a TTY**, so pipes, scripts and `kern logs` stay clean; a detached box prints a one-line
  `✔ started <name>` with the next-step commands instead.
- **Unified table styling**: `kern ps`/`stats`/`images`/`search` now share the panel's visual
  standard on a TTY: a **dim header**, **bold-cyan NAME**, **semantic colour** for status (green
  `healthy` / red `unhealthy` in `ps`, a green ✓ for an official image in `search`), and `ps`
  truncates a long `COMMAND` to the terminal width with a dynamically-sized `PORTS` column so the
  table never wraps. All of it is **gated to a TTY**: piped/`NO_COLOR` output stays plain and
  full-width for scripts, and column alignment is computed on the uncoloured cells.
- **`kern box … -p [ip:]host:box` (port publishing)**: reach a service inside an isolated box from
  the host. A rootless userspace TCP forwarder is forked **before** the sandbox `unshare` (so it
  stays in the host network namespace, binding the host port); per connection it forks a
  single-threaded connector that joins the box's user+net namespaces (as `kern exec` does) and
  connects to the box's `127.0.0.1:<box>`. The optional bind IP **defaults to `127.0.0.1`**
  (loopback-only); pass `-p 0.0.0.0:H:B` to expose on all interfaces (a warning is printed).
  Repeatable; foreground + detached; torn down when the box exits.
- **`kern box -d --restart`**: restart a detached box if it exits non-zero (on-failure policy),
  up to a cap (10) with a 1 s backoff so a box that crashes on every start eventually gives up.
  Each attempt runs in a fresh child (the sandbox `unshare` mutates its caller, so it can't be
  re-run in place).
- **`kern box -d --health-cmd <cmd> [--health-interval N]`**: a sidecar process probes the box
  (`/bin/sh -c <cmd>` via `kern exec`, exit 0 = healthy) every N seconds (default 30) and records
  `healthy`/`unhealthy` for `kern ps`. It follows `--restart`s (re-reads the box's PID 1 each round).
- **`kern ps` shows `HEALTH` and `PORTS` columns** (and the same fields in `--json`): the current
  health status and the published `-p` mappings (e.g. `8080->80, 127.0.0.1:443->443`). The `PORTS`
  column sizes to its widest value and, on a TTY, `COMMAND` is truncated to the terminal width so a
  long command never wraps the table (like `docker ps`); piped output prints the full command.
- **`kern box … -it` and `kern exec … -it` (interactive PTY)**: allocate a pseudo-terminal so a
  box (or a command exec'd into a running box) runs a real interactive shell/REPL: it gets a
  controlling tty (`isatty` true), the host terminal goes raw, the window size is copied in and
  `SIGWINCH` resizes are forwarded, and the exit code propagates. `box -it` is foreground only
  (rejects `-d`). The byte pump is single-threaded by design, the sandbox fork must run in a
  single-threaded process, so there's no fork-in-thread hazard. (`exec -it` shares the same
  PTY plumbing as `box -it` via a common `adopt_controlling_tty` helper.)
- **`kern run [--memory M] [--cpus N] [--] <cmd...>`**: the resource-governor verb: run a command
  under cgroup CPU/memory caps **without** a sandbox (no namespaces/seccomp). It `exec`s the command
  (no fork) so it's the leanest path, a transient capped cgroup + `exec`, and propagates the
  command's exit code. `--cpus` is clamped once to the host's physical CPU count (consistent across
  the systemd scope and the in-namespace cgroup).
- **`--memory`/`-m` and `--cpus` per box**: tunable resource caps (previously a fixed 512 MiB /
  uncapped CPU). `--memory 512m|1g|<bytes>` sets a hard memory ceiling (the box is OOM-killed at the
  limit); `--cpus 1.5` caps CPU to 1½ cores (K8s semantics, clamped to the host's CPU count). Both
  the transient systemd scope and the best-effort in-namespace cgroup honor them; the CPU cap is
  best-effort where the cgroup CPU controller isn't delegated (e.g. some Android kernels).

### Security (defense-in-depth, from an adversarial pentest of the box)
- **`-p` binds `127.0.0.1` by default** (was `0.0.0.0`), a published service is no longer
  accidentally exposed to the LAN. Use `-p 0.0.0.0:H:B` to bind all interfaces deliberately (a
  warning is printed when you do). `kern ps` now shows the bind address per mapping.
- **Least-privilege capabilities**: the box drops never-needed dangerous caps (SYS_MODULE,
  SYS_RAWIO, SYS_BOOT, SYS_TIME, SYSLOG, MAC_ADMIN/OVERRIDE, AUDIT_CONTROL/READ, WAKE_ALARM,
  PERFMON, BPF, SYS_PACCT) from its effective/permitted/inheritable **and** bounding sets just
  before exec, so neither the workload nor a setuid/file-cap binary can wield them. Workload caps
  (CHOWN, DAC_*, SETUID/SETGID, NET_BIND/RAW/ADMIN, SYS_CHROOT, MKNOD, …) are kept, `apk`/`apt`,
  `chown`, and privilege-drop still work. (These caps are namespaced, i.e. already grant no host
  power; this shrinks the surface against cap-gated kernel bugs.) Pentest confirmed the box blocks
  mount/pivot/setns/unshare (seccomp), device/kernel-memory access, the classic container escapes
  (core_pattern, cgroup release_agent CVE-2022-0492, sysrq), fork-bomb (pids cap), and cross-box
  FS/PID/net access.

### Fixed
- **A box's loopback (`lo`) is now brought up** in its isolated network namespace, so `127.0.0.1`
  works inside the box (a fresh net ns leaves `lo` DOWN). `--net` boxes keep the host's loopback.

### Changed
- **Release profile is now `opt-level = "z"` (size-optimised).** The new 0.4 features grew the
  binary; since kern's cold start is syscall-bound (`unshare`/`mount`/`exec`), not CPU-bound, size
  codegen shrinks it ~14% (musl x86_64 804 → **688 KB**, glibc **594 KB**) with **no** latency cost
 , measured a hair faster (better I-cache). There is no hot CPU path to slow down.

## [0.3.3], contextual hint for box-not-running errors

### Fixed
- **`stop`/`exec`/`logs` on a box that isn't running now show the right hint** ("run `kern ps` to
  see running boxes") instead of the generic sandbox-setup hint ("needs unprivileged user
  namespaces and a valid --rootfs directory"), which was misleading for a simple lookup miss. New
  `Error::NotRunning` variant separates a lookup miss from a sandbox-setup failure.

## [0.3.2], `kern stop` takes multiple names + `--all`

### Added
- **`kern stop <name>...`** now stops **every** name given (previously it stopped only the first and
  silently ignored the rest), and **`kern stop --all`** stops every running box. A requested name
  that isn't running is reported on stderr instead of being silently dropped.

## [0.3.1], `--uid-range` fallback hardening

### Fixed
- **`--uid-range` now degrades gracefully when `newuidmap`/`newgidmap` are present but fail at
  runtime** (the helper isn't setuid-root, or there's no matching `/etc/subgid` allocation,
  common on CI runners and minimal hosts). Previously this aborted the box; now, since the process
  is already in a fresh user namespace, it falls back to the safe single-uid map (box uid 0 →
  caller) with a clear notice, mirroring how an *absent* helper already degraded. A `box`
  therefore always starts, with or without a usable subordinate-id range. The single-uid map write
  is now shared by the default and the fallback paths.

## [0.3.0], Real sandbox execution

### Added
- **`kern box <name> (--image <ref>|--rootfs <dir>) [-- cmd...]` runs a command in a real
  sandbox**: a fresh user + PID + net + UTS + IPC + mount namespace (single-uid map, no host
  privilege gained), an overlay root `pivot_root`-ed in (writable by default; `--read-only`
  remounts it read-only), a private `/proc`, then `exec`. Exit code propagated. Defaults to
  `/bin/sh`.
- `kern-isolation`: `RealMounts` (the libc `MountOps` impl) + `run_in_sandbox`. The real path and
  the `--plan` recorder flow through the **same** `Rootfs` typestate, so the read-only-after-pivot
  ordering is compile-enforced for real execution too.
- **`kern box -d` (detached)** + **`kern ps [--json]`**: a detached box forks a supervisor that
  registers itself under `$XDG_RUNTIME_DIR/kern/instances/`; `kern ps` lists running boxes and
  **prunes dead entries on read**: observability with no daemon. Survives a corrupt registry
  file (skipped, not a crash).
- **OCI pull**: `kern pull <image>` and `kern box <name> --image <ref> -- <cmd>` download an OCI
  image (registry v2, anonymous Docker Hub auth, multi-arch manifest/index → this host's arch)
  via `curl` + GNU `tar`, extract layers and apply whiteouts (with the symlink-escape guard),
  into a local rootfs (cached for re-runs). Verified: `kern box web --image alpine` pulls Alpine
  and runs it sandboxed (read-only root, isolated net/UTS, uid 0-in-ns).
- **Pull hardening (adversarial images)**: each layer is vetted **before extraction** (absolute
  paths, `..` traversal, device nodes, 2 GiB decompression-bomb cap), then extracted into an
  **isolated staging dir** and merged with **no-follow** semantics, a symlink planted by an
  earlier layer cannot be traversed by a later layer's writes (cross-layer escape closed
  structurally). Whiteouts (incl. opaque dirs) are applied during the merge under the guard.
- **`kern compose <file>`**: a minimal TOML orchestrator (no external crate). `[box.NAME]` tables
  with `image`/`rootfs`, `command`, `depends_on`; boxes start detached in dependency order
  (cycles + unknown deps are reported). Track the stack with `kern ps`.
- **Writable boxes (overlayfs)**: a box defaults to a writable root, the image/rootfs is the
  read-only lower, a private upper takes writes (the image stays immutable, scratch is removed on
  exit). `--read-only` remounts that overlay read-only (incl. `/dev`), so the box has no writable
  surface. (Overlay is used for both modes; a bind remount-RO is denied on some kernels.)
- **`kern stop <name>`**: stop running box(es), SIGKILL the supervisor's process group (tears
  down the box's PID namespace), drop the registry entry, remove the writable scratch.
- **Observability (`kern top` / `kern stats` / `kern logs`)**: daemonless live + point-in-time
  views, read straight from each box's cgroup and a per-box log. `kern top` auto-refreshes
  (uptime, memory, CPU% from `cpu.stat` deltas); `kern stats [--json]` is a one-shot table/JSON of
  memory + cumulative CPU; `kern logs <name>` replays a detached box's captured stdout/stderr
  (the supervisor now tees stdio to `$XDG_RUNTIME_DIR/kern/logs/<name>-<pid>.log`, readable
  post-mortem). All three reuse the same registry, so they need no daemon and prune dead boxes.
- **Volumes (`-v src:dst[:ro]`, repeatable)**: bind a host directory or file into the box, the
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
  **no network isolation**: see SECURITY.md.
- **Prebuilt binaries + `install.sh`**: a release workflow builds static (musl) `linux-x86_64`
  and `linux-aarch64` binaries with SHA256SUMS on each version tag; `curl -fsSL
  https://getkern.dev/install.sh | sh` downloads the right one (checksum-verified), no Rust
  toolchain needed.
- **uid/gid range mapping**: when `newuidmap`/`newgidmap` and an `/etc/subuid`+`/etc/subgid`
  allocation are present, the box maps a full id range (box uid 0 → caller; box ids 1..N →
  subordinate ids) instead of a single uid, so `apt install` (which `chown`s to other uids) and
  daemons that drop to a non-root user (e.g. **Apache → `www-data`**) work. Falls back to the
  dependency-free single-uid map when the helpers/subids aren't available. No host privilege
  gained either way. Verified: real `apt install apache2` + `apache2` serving on Ubuntu in a box.

### Fixed
- **`cmd > /dev/null` now works inside a box.** The `/dev` tmpfs was mounted with the default
  sticky, world-writable mode (1777); with `fs.protected_regular` (≥1, default on most distros)
  an `O_CREAT` open of a device node the box doesn't own in a sticky world-writable directory is
  rejected with `EACCES`, breaking the near-universal redirect. `/dev` is now mounted `mode=755`
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
  ships a symlink at the mount point can't redirect the bind (and a host write) through it, the
  bind is refused instead. Regression test added.
- **Unknown `box`/`exec` flags are now rejected, not ignored.** A typo'd `--read-only` no longer
  silently runs a *writable* box, an unrecognized flag is a usage error.
- Audit hardening: closed an fd leak on an error path in the volume-target walk; reject a NUL byte
  in a `-v` target early; documented that `--net` also exposes host abstract-namespace UNIX sockets.

### Security (audit hardening)
- **pull integrity**: every blob is verified to hash to its `sha256:` digest before use
  (compromised/MITM registry + corrupt-download defense, beyond TLS).
- **registry**: a box's kernel start-time is recorded and checked, so a reused pid can't be
  mistaken for a live box (no false "running", no `stop` signalling an unrelated process).
- **seccomp**: denylist extended to the new mount API (`open_tree`/`move_mount`/`fsopen`/
  `fsconfig`/`fsmount`) and `unshare` (nested-userns escape) and `process_vm_readv`/`writev`
  (ptrace-equivalents), closing gaps that contradicted the "blocks further mount/namespace
  manipulation" claim.
- **pull**: hardlink entries whose target escapes the rootfs (absolute / `..`) are now rejected.
- **image cache**: gated on a completion sentinel (no more "non-empty dir = valid" → no partial/
  poisoned rootfs); cache dir created mode `0700` under `~/.cache` (not a predictable `/tmp` path).
- **registry**: a pid that now belongs to another user (`EPERM`) is treated as gone, `kern stop`
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
  async-signal-safe handler (`tcsetattr` + reset escapes) before re-raising, no stranded terminal.
- **Full namespace isolation**: user + PID + **network** (only loopback) + **UTS** (hostname =
  box name) + **IPC** + mount. Verified live: host sees 528 procs, the box sees ~3; only `lo`
  in the box's network namespace.
- **Always-on seccomp denylist**: kexec, kernel-module (un)loading, ptrace, reboot, swap,
  further mount/`pivot_root`/`setns` are killed with SIGSYS; a wrong-arch syscall is killed too.
- **cgroup caps (memory 512 MiB + tasks 512)**: when a systemd user manager is present, `kern
  box` re-execs inside a transient `systemd-run --user --scope` (verified: `TasksMax=512`,
  `MemoryMax=512M`, **`MemorySwapMax=0`** so the memory cap is a HARD total, a workload over
  512 MiB is OOM-killed instead of silently swapping); otherwise a best-effort cgroup v2 path
  applies where delegated, degrading gracefully (no orphan cgroup) elsewhere.

- **`examples/`**: runnable, live-verified use-cases, run an image, throwaway shell, untrusted
  code (read-only + seccomp + no net), detached services + `ps`/`stop`, a `compose` stack, and
  per-task fan-out.

- **Minimal `/dev`**: a box gets `null`/`zero`/`full`/`random`/`urandom` on a fresh **tmpfs**
  `/dev` set up **after** pivot, host device fds are captured pre-pivot and bound in via
  `/proc/self/fd`, so a hostile rootfs with a symlinked `/dev` can't redirect writes to the host,
  and the image's own `/dev` is never mutated. (No `/dev/tty`, avoids TIOCSTI injection; never
  `/dev/mem`/disks; userns can't `mknod`.)
- **pull**: a non-`sha256:` (unverifiable) digest is now **refused**, not silently accepted.
- **Clean environment**: the box starts with a small, sane env (`PATH`/`HOME`/`TERM`/`HOSTNAME`),
  not the host's, host secrets/tokens and kern internals (`KERN_SCOPE`) no longer leak in.
- **Concurrent pulls** of the same image are serialized with a per-image `flock` (with a
  double-checked sentinel), so parallel `kern box --image X` from a cold cache all succeed.

- **`BENCHMARKS.md`**: measured multi-runtime comparison (vs Docker / runc / bubblewrap), bare
  box ~3 ms, full `--image` ~7 ms, ~100× faster to start than `docker run` (and ~267× under
  parallelism), footprint, and resource-cap results.

### Added
- **`kern --help` now shows the `KERN` wordmark + colour**: a cyan/bold ASCII logo, bold section
  headers, cyan verbs, dim notes. Colour is emitted **only** when stdout is a TTY and `NO_COLOR`
  is unset, so piped output and scripts (and `kern --version`) stay plain. Dependency-free (a tiny
  `ui` module of raw escape strings); no EULA/demo banners, the public build stays clean.
- **`kern top` is now an interactive task-manager TUI** (when stdout is a TTY), an htop-style
  full-screen view with tabs (**Overview** · **Boxes**), live refresh, and keyboard nav (`Tab`/
  `←→`/`1`/`2` to switch, `q`/`Esc`/`Ctrl-C` to quit). Boxes-only (the public build has no GPU/
  vCPU to monitor). Pure `libc` termios + ANSI, **no curses/ratatui dependency**; the terminal is
  put in raw mode + the alternate screen and **restored on drop** (clean teardown even on Ctrl-C
  or panic). Piped/non-TTY falls back to a one-shot table. New `registry::tasks` reads the box
  cgroup `pids.current` for the **PIDS** column.
- **`kern search <query>`**: search Docker Hub for images (name, stars, official flag,
  description), the same registry `kern pull` uses. Backed by a new `kern-oci` HTTP/JSON path
  (`net` + `json` modules, shared with `pull` so there's one curl wrapper and one string-scanner).
- **`kern images [--json]`**: list the images pulled into the local cache, by their *original*
  ref (recovered from the pull sentinel), with on-disk size and age, like `docker images`.

### Changed
- **`--bind-rootfs`, a fast path for kernels with a slow overlayfs.** The default still overlays
  the rootfs (immutable, shareable, sub-millisecond on normal kernels). But some Android-derived
  kernels mount an overlay in ~31 ms (vs ~8 ms for a bind; the syscall is 104 µs on x86). On an
  Arduino UNO Q this made the default box (34 ms) lose to bubblewrap (15 ms); with `--bind-rootfs`
  kern binds the rootfs directly and starts in **9.9 ms, faster than bubblewrap**: while still
  doing more (seccomp, real `/dev`, lifecycle). Trade-off (hence opt-in, `--rootfs`-only, not with
  `--read-only`): the source is mutable and shared. A hidden `KERN_TIMING=1` prints per-phase
  startup µs and found the bottleneck. Bind mode is hardened to stay within that trade-off and not
  exceed it: the root bind is **non-recursive** (`MS_BIND`, not `MS_REC`) so host filesystems
  mounted *under* the rootfs dir aren't leaked into the box, and bind mode does **not** inject
  `/etc/resolv.conf` (the overlay path writes it to a private scratch; a host-side write into the
  user's rootfs could follow a symlink and clobber a file outside it, so a bind-mode box uses the
  resolv.conf its rootfs already ships).
- **Single-uid map is now the default; `--uid-range` is opt-in** (faster *and* more isolated).
  Previously every box with an `/etc/subuid` allocation auto-mapped a 65k sub-uid range, which
  costs two `newuidmap`/`newgidmap` subprocesses at start and enlarges the namespace's id surface.
  The default is now the dependency-free single-uid map (box uid 0 = caller, nothing else), a bare
  box cold-starts in **~2.5 ms (beats bubblewrap, ties rootless runc, ~145× faster than Docker)**.
  Pass `--uid-range` for workloads that need multiple uids inside the box (`apt`/`dpkg`, daemons
  that drop to `www-data`); if requested but unavailable it warns and falls back to single-uid.
- **Security: id-map helpers resolved by trusted absolute path only.** `newuidmap`/`newgidmap` are
  now located in `/usr/bin`,`/bin`,`/usr/sbin`,`/sbin` instead of via `$PATH`, so a writable PATH
  entry (e.g. `~/.local/bin`) can't shadow the system binary and feed a bogus uid mapping. The
  `/etc/subuid` lookup matches the login **name** first (numeric-uid row only as fallback, as
  shadow does), and the helper handshake is EINTR-safe and **fails closed**: any error in helper
  resolution, subuid parsing, the pid handshake, or the final verdict aborts rather than running a
  partially-mapped box. No privilege can be gained either way (the setuid helpers re-validate the
  allocation in the kernel).
- **Pull progress feedback**: `kern pull` and a cold `kern box --image` now report each step to
  stderr, `resolving`, layer count, per-layer `K/N` with a **live download progress bar** (curl
  `-#`), `verifying + extracting`, and a `✓ pulled` summary, so a download never looks frozen. A
  warm cache stays silent (no noise). The `box --image` path also prints a one-time
  "not cached, pulling once" notice so it's clear why there's a wait.
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
  actually up, and `box '<name>' exited before starting, run \`kern logs <name>\`` (exit 1) if it
  dies first. No sleep, no poll, the only added latency is the box's real start time (~4 ms; ~7 ms
  with the systemd cgroup scope), the same a foreground box already pays. `compose` inherits this:
  a dependent box now starts only after its dependency is genuinely running.
- **Overlay scratch on tmpfs**: the writable upper/work layer now lives under `$XDG_RUNTIME_DIR`
  (tmpfs) instead of the disk cache, `box --image` cold-start dropped from ~25-32 ms to ~6 ms,
  and the writable layer is ephemeral and counts against the box's memory cap.
- `MountOps` is now fallible (`Result`), so the recorder and the real syscall path share one
  ordered, error-checked op log. First real dependency: `libc` (the single kernel boundary).
- Missing required arguments now produce a clear `usage:` error instead of a misleading
  "not implemented" (e.g. `kern pull` with no image, `kern box NAME` with no rootfs/image).

### Not yet (roadmap)
- `kern run` resource quotas (CPU/memory), tunable `--memory`/`--cpus`, interactive PTY (`-it`),
  port publishing (`-p`), image build, and GPU slices. See the README roadmap.

## [0.2.0], Sandbox hardening

### Added
- `kern-isolation`: **mount-ordering typestate** `Rootfs<Mounted>` → `create_old_root()` →
  `Rootfs<OldRootReady>` → `into_readonly()`. Remounting the root read-only before pivoting in
  is now a **compile error**, not a sandbox-escape bug.
- `kern-isolation`: `MountMode` enum (overlay / bind / tmpfs) driving the initial root mount.
- `kern-cli`: `SandboxCtx` step sequence wired to the typestate.
- `kern box <name> --plan`, print the ordered isolation sequence (mount → pivot → read-only).
  Privilege-free; uses the validated `BoxName` newtype (rejects path traversal).

### Changed
- `overlay_ro_sequence` is now driven through the typestate; the characterization golden is
  **byte-identical** (the refactor changed no observable behaviour).

### Security
- `BoxName` hardened to a conservative charset (`[A-Za-z0-9_.-]`, no leading `-` or `.`, max 64
  chars). Blocks path traversal, NUL, whitespace, control characters, shell metacharacters and
  argument-injection by construction. Fuzzed with 40+ hostile inputs: zero crashes/panics.

## [0.1.0], Foundation

### Added
- Workspace foundation: `kern-cli` (binary `kern`), `kern-common`, `kern-oci`, `kern-isolation`.
- Module-based CLI (no `include!()`): command parsing/dispatch + `--no-gpu` global flag.
- `kern-oci`: whiteout path-safety helper with a symlink-escape regression test.
- `kern-isolation`: the `MountOps` characterization seam (refactor-safety net).
- Project docs: README, SECURITY, ARCHITECTURE, CONTRIBUTING, CLA, CODE_OF_CONDUCT.
- CI: build + test + clippy + fmt + cargo-audit + cargo-deny on x86 (skip-graceful for HW).

[0.6.5]: https://github.com/getkern/kern/releases/tag/v0.6.5
[0.6.4]: https://github.com/getkern/kern/releases/tag/v0.6.4
[0.6.3]: https://github.com/getkern/kern/releases/tag/v0.6.3
[0.6.2]: https://github.com/getkern/kern/releases/tag/v0.6.2
[0.5.7]: https://github.com/getkern/kern/releases/tag/v0.5.7
[0.3.3]: https://github.com/getkern/kern/releases/tag/v0.3.3
[0.3.2]: https://github.com/getkern/kern/releases/tag/v0.3.2
[0.3.1]: https://github.com/getkern/kern/releases/tag/v0.3.1
[0.4.0]: https://github.com/getkern/kern/releases/tag/v0.4.0
[0.3.0]: https://github.com/getkern/kern/releases/tag/v0.3.0
[0.2.0]: https://github.com/getkern/kern/releases/tag/v0.2.0
[0.1.0]: https://github.com/getkern/kern/releases/tag/v0.1.0
