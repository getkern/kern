# Security Policy

kern runs untrusted images inside a sandbox and (optionally, from 0.9) interposes on the GPU
driver. It *will* receive security reports — here is the model and how to report.

## Reporting a vulnerability

**Please do not open a public issue for security bugs.** Report privately via GitHub Security
Advisories ("Report a vulnerability" on the repo) or email the maintainer listed on the GitHub
profile. You'll get an acknowledgement and a coordinated-disclosure timeline.

## Threat model

**In scope — kernel-enforced isolation must hold:**
- A malicious OCI image / `--rootfs` must not read or write host files outside the rootfs
  (path traversal, cross-layer symlink escape, whiteout-through-symlink, tar traversal).
- A box must not see or affect host processes, mounts, or other boxes (PID/mount/net ns).
- Resource limits (cgroups: memory/pids) must hold; fork bombs / OOM must be contained.
- seccomp must block the dangerous syscall set unconditionally.

**Explicitly OUT of scope (cooperative, by design — not a boundary):**
- **The GPU VRAM cap (0.9+) is cooperative.** It governs honest workloads via the public
  driver API; an adversarial app bypasses it (absolute-path `dlopen`, static link, raw
  ioctls). On consumer NVIDIA there is no userspace hard cap; a kernel-enforced cap exists
  only on AMD/Intel via the `dmem` cgroup controller. Do not treat the GPU cap as a security
  boundary or a multi-tenant billing mechanism on consumer NVIDIA.

## Current status (0.4 — honest)

What is **enforced now** by `kern box`:
- user + PID + network (loopback-only) + UTS + IPC + mount namespaces;
- `pivot_root` into the rootfs (the default root is a writable overlay whose scratch is discarded
  on exit; `--read-only` remounts the root **read-only** — and the mount ordering, read-only only
  *after* the pivot, is compile-enforced by a typestate);
- **least-privilege capabilities**: 13 never-needed dangerous caps (module load, raw I/O,
  `SYS_TIME`, `SYSLOG`, `BPF`, `PERFMON`, MAC/audit admin, `SYS_BOOT`, …) are dropped from the
  effective/permitted/inheritable **and** the bounding set just before exec, so neither the
  workload nor a setuid/file-capability binary can wield them (they're namespaced anyway — this
  shrinks the surface against cap-gated kernel bugs). `--cap-drop CAP` / `--cap-drop ALL` drops more;
  `--cap-add CAP` keeps one that would otherwise be dropped (add wins). Even a re-added cap (e.g.
  `--cap-add SYS_ADMIN`) is held only over the box's **own** user namespace and the always-on seccomp
  denylist still blocks the escape syscalls it would otherwise unlock — so `--cap-add` cannot breach
  the host, and an unknown cap name is a hard error (a typo can't silently leave a cap in place);
- always-on **seccomp** denylist (~25 syscalls: kexec(+`_file_load`) / module load-unload /
  ptrace + `process_vm_readv`/`writev` / reboot / swap / the classic **and** new mount API /
  `pivot_root` / `setns` / `unshare` / `bpf` / `perf_event_open` / `userfaultfd` / `syslog`),
  wrong-arch syscalls killed, and on x86_64 every **x32-ABI** syscall (the `__X32_SYSCALL_BIT`
  variant, which shares the x86_64 arch token) is killed too — closing the classic bypass where the
  x32 alias of a denied syscall number would otherwise slip past a number-only denylist;
- **device access is deny-by-default**: the box's `/dev` is a fresh box-owned `tmpfs` that
  *shadows* the image's `/dev`, with only a minimal safe allowlist bound in from the host
  (`null`, `zero`, `full`, `random`, `urandom`). A raw disk, `/dev/mem`, or any other node is
  therefore simply **absent** — and a device node the box *does* fabricate is **inert**: a filesystem
  mounted inside an unprivileged user namespace is flagged `SB_I_NODEV`, so a `mknod`'d node can't be
  opened to reach any host device (on kernels < 5.11 `mknod` itself is refused `EPERM`; on newer ones
  it succeeds but the node is un-openable — same outcome). The box root, `/dev`, and every extra
  mount also carry `MS_NODEV`, so this holds without relying on the implicit userns behaviour. The
  boundary is the namespace + the allowlist, so no eBPF device-cgroup filter is needed (and none would
  load unprivileged); GPIO device nodes (via a `vgpio:` profile) are added to this allowlist
  explicitly today, and GPU nodes will be at 0.9 — never by opening `/dev` up.

Resource caps (memory + tasks): when a systemd **user** manager is present, `kern box` re-execs
inside a transient `systemd-run --user --scope` with `MemoryMax`/`TasksMax`, so fork-bomb / OOM
are cgroup-enforced. Without it, a best-effort cgroup v2 path applies where the hierarchy is
delegated, else it is skipped gracefully — so on a host with **neither** systemd-user nor a
delegated cgroup, containment is not guaranteed.

- **`--pids-limit N`** sets the box's `pids.max` (and the scope's `TasksMax`) — a fork-bomb ceiling.
  Default 512. Like the memory cap, it's cgroup-enforced where a scope / delegated hierarchy exists.
- **`--user UID[:GID]`** drops the workload to a uid/gid *after* all privileged setup and the
  capability drop, just before seccomp (`setgroups`→`setgid`→`setuid`). Only ids **mapped into the
  box's user namespace** work, so a non-root `--user` implies the uid/gid-range mapping (like
  `--ssh`). It **fails closed**: if the requested id can't be mapped (e.g. a host without
  `newuidmap`/`newgidmap`), the box **refuses to start** rather than silently running the workload as
  in-box root — dropping privilege never grants it. It reduces privilege inside the box; it is not
  itself a trust boundary (the box is already contained by the namespace/seccomp/cap-drop). Note a
  non-root `--user` **sheds all capabilities**, including any `--cap-add` (the `setuid` clears them,
  and kern doesn't raise the ambient set) — pair `--cap-add` with the box's default root-in-userns
  user if the workload needs the cap.
- **`--tmpfs PATH[:size]`** mounts a fresh `NOSUID,NODEV` tmpfs at PATH in the box. Mounting one over
  the sandbox's own hardened `/proc`, `/sys` or `/dev` is **refused** (it would unmask them); the size
  is a real cap (`ENOSPC` past it) but counts against RAM, so pair a large tmpfs with `--memory`.
- **`--hostname NAME`** sets the box's UTS hostname (validated to a DNS-label charset). Cosmetic /
  scoping only — the box has its own UTS namespace, so it can't affect the host's hostname.

Opt-in flags that **relax** isolation (off by default — you ask for them):
- **`--net`** (= **`--network host`**) shares the **host network namespace** instead of the isolated
  loopback-only one (`--network none`, the default). The box gains outbound connectivity, but there is
  then **no network isolation**: it can reach host `localhost` services, the host's networks, **and
  every abstract-namespace UNIX socket** (those live in the network namespace, not the filesystem —
  e.g. X11, some D-Bus/runtime sockets), and bind host-visible addresses. Use it for trusted
  build/fetch steps, not for untrusted code.
- **`--tun`** binds `/dev/net/tun` into the box so a WireGuard / userspace-VPN workload can create a
  tunnel. The box retains `CAP_NET_ADMIN`, but a **child user namespace's** capabilities are not
  effective over a namespace owned by the initial user namespace — so even combined with
  `--network host` (box in the *host* netns) a `--tun` box **cannot reconfigure the host's
  interfaces** (`TUNSETIFF` / interface config on the host netns returns `EPERM`). With the default
  isolated netns it manages only its own tunnel. The always-on seccomp denylist is what keeps holding
  `CAP_NET_ADMIN`/`CAP_SYS_ADMIN` in the box's userns safe (the escape syscalls are blocked).
- **`-v src:dst`** binds a host path into the box. A writable volume is a hole through the
  sandbox by design — the box can modify those host files (use `:ro` for read-only). `kern`
  rejects a non-existent source and resolves it to an absolute, symlink-free path first.
- **`kern exec`** joins a running box's namespaces; it is restricted to the user who started the
  box (joining its user namespace requires being that namespace's owner). The exec'd process gets
  the same always-on **seccomp** filter (**fail-closed** — it won't run if the filter can't install)
  and the same always-dropped **dangerous-cap baseline**. A box's *custom* `--cap-drop`/`--user` are
  not reapplied on exec (they aren't recorded per box), so an `exec` runs at the box's baseline, not
  its tightened profile — the host boundary still holds (namespaced caps + seccomp block every escape
  syscall regardless).
- **`kern cp <box>:<src> <dst>` / `<src> <box>:<dst>`** copies a single file in or out of a running
  box. The in-box path is resolved with `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` against the
  box's root (`/proc/<pid1>/root`), so **every symlink and `..` is reinterpreted as if that root were
  `/`** — a hostile image cannot plant a symlink (absolute, `../..`, or a chain) that makes the copy
  read or write a **host** file outside the box (the CVE-2019-14271 class). kern never executes
  anything inside the box to do the copy. Restricted to your own boxes (`/proc/<pid1>/root` needs
  same-uid ptrace access, and the box is found via your registry). Copies **regular files only**
  (a box-planted FIFO/socket/device is refused, opened `O_NONBLOCK` so it can't hang the copy) with a
  4 GiB size cap, so a hostile image can't stall or OOM your `cp`. (Writing *into* the box still follows
  a final in-box symlink — but confined to the box, which the box could already write itself.)
- **`kern pause` / `kern unpause`** freeze / thaw a box via its cgroup v2 freezer (`cgroup.freeze`) —
  it writes only the box's *own* dedicated cgroup, and refuses (rather than freezing the session) when
  the box has no dedicated cgroup. **`kern attach`** streams a detached box's log live and is
  read-only (a detached box has no stdin); Ctrl-C detaches without stopping the box.
- **`-p [ip:]host:box`** publishes a box port on the host via a rootless forwarder. It **binds
  `127.0.0.1` by default** (reachable only from the host); `-p 0.0.0.0:H:B` binds all interfaces
  and exposes the box's service to the LAN — a deliberate, warned-about choice. The forwarder runs
  in the host network namespace (it has to, to bind the host port); the box itself stays in its own
  isolated network namespace.

OCI pull (`kern pull` / `--image`):
- **Integrity**: each blob is verified to hash to its `sha256:` digest (via `sha256sum`) before
  use — defends against a compromised/MITM registry and corrupt downloads, beyond TLS.
- **Layer vetting**: absolute paths, `..` traversal, device nodes, hardlink targets that escape
  the rootfs, and a 2 GiB decompression-bomb cap are all rejected before anything is written.
- **Isolated-staging, no-follow merge**: each layer extracts into a fresh staging dir, then
  merges into the rootfs refusing to traverse any symlink — the cross-layer escape class is
  closed structurally (not by trusting tar). The guard is a lexical check, which is sound here
  because extraction is single-threaded (no concurrency across the image's own layers) and the
  cache/scratch dirs are created **mode 0700 and owned by the user**, so no other local user can
  race a symlink into the paths. Whiteouts (incl. opaque dirs) are applied under the same guard.
- **Registry credentials** (`kern login`/`logout`, for private images): stored in an owner-only
  (`0600`) file under `~/.config/kern/`, base64-encoded (obfuscation — the `0600` mode is the real
  protection, not the encoding). The password is read from the terminal **with echo off** (or piped
  stdin), never taken as a flag. When kern authenticates a pull, the credential is handed to `curl`
  via a `-K -` **stdin config**, *not* a `--user` argument — so it never appears in `/proc/<pid>/cmdline`
  where another same-uid process could read it; control characters are stripped so a crafted credential
  can't inject a curl directive. `kern` does not **push** images to a registry (it pulls, builds
  locally, and runs) — use a dedicated builder for registry push.

## vGPIO device passthrough (opt-in, honest scope)

A `vgpio:` profile **deliberately widens** the box's device surface — it bind-mounts the profile's
listed peripherals (`/dev/i2c-*`, `/dev/spi*`, `/dev/gpiochip*`, camera/audio, and `/sys` dirs for
pwm/adc/1-wire/leds) into the box. Only the listed devices are exposed; deny-by-default still holds
for everything else, and the source paths are canonicalized and re-checked to stay under `/dev/`
(no symlink escape to a host file). Two honest limitations, by design:

- **GPIO is chip-granular, not per-line.** Requesting any `pins` binds every `/dev/gpiochipN`, and a
  gpiochip character device exposes *all* of that controller's lines via ioctl. `pins = [17]` does
  **not** restrict the box to line 17 — the kernel has no per-line mount boundary. The pin list is
  cooperative metadata (`KERN_VGPIO_PINS`), not a security boundary.
- **`--read-only` keeps a vGPIO box's `/sys` writable.** LED brightness / PWM control *are* writes,
  so the box-owned `/sys` tmpfs and the bound sysfs attribute dirs stay writable even under
  `--read-only` (the root filesystem is still read-only). This is intentional.

Grant a `vgpio:` profile only to workloads you'd trust with that hardware.

## vDisk (size-capped scratch volume)

A `vdisk:` profile mounts a size-capped volume at `/vdisk/<name>`. Rootless it is a **RAM-backed
`tmpfs`** — the `size` is a real quota (a write past it fails `ENOSPC`), but it counts against RAM:
pair a large vdisk with `--memory` so a box that fills its vdisk can't drive the host to OOM (kern
warns for vdisks ≥ 1 GiB). The mount is created inside a fresh box-owned `/vdisk` tmpfs
(symlink-neutralized), so a hostile image shipping `/vdisk` as a symlink can't redirect it. Under
`--read-only` the vdisk stays writable by design (it's scratch). A **disk-backed ext4-on-loop**
backend (persistent, real disk quota) is used instead when kern runs privileged (root / `disk`
group, plain foreground box) — the loop device is configured `LO_FLAGS_AUTOCLEAR` and any setup
failure unwinds immediately, so a half-built vdisk can't leak a loop device or a stray mount; on
any failure it falls back to tmpfs. `iops`/`bandwidth` I/O limits are recognised but not yet applied
(a cgroup-io increment) — reported, never silently dropped.

## Secrets (`--secret`)

`--secret` delivers a value into the box as `/run/secrets/<name>` (mode **0400**) without it ever
landing in the image or the workload's environment:

- Three forms — `NAME=value` (inline; note it's visible in the host's `ps`, so prefer a file/stdin
  for real secrets), `NAME=-` (read from kern's **stdin**, never in `argv`), and `SRC[:NAME]` (a host
  **file**; a world-writable source is refused, a group/world-readable one is warned). The name is
  charset-validated to a single path component (no `/`, no `..`), and duplicate names are rejected.
- The bytes are read **on the host, before the fork**; inside the box they're written to a **RAM-backed
  `tmpfs`** (`NOSUID|NODEV`) mounted at `/run/secrets`, so a secret never touches the persisted overlay
  upper and is gone when the box exits. A hostile image shipping `/run/secrets` as a symlink is
  neutralised (the symlink is removed before the mount) and each file is created `O_EXCL | O_NOFOLLOW`
  inside the box-owned tmpfs, so the write can't be redirected out.

## SSH (`--ssh`)

`--ssh PORT` runs a throwaway `sshd` **inside** the box and publishes it on host `PORT` (→ box `:22`)
via the ordinary rootless port-forwarder; `ssh`/`scp`/`sftp` then reach the box. It's for interactive
box access, not a hardened bastion — grant it only to workloads you'd trust with a shell in the box.

- **Keys never touch the image.** Without `--ssh-key`, kern generates a throwaway ed25519 keypair in
  the owner-only runtime dir and prints the ready-to-paste `ssh -i … root@127.0.0.1`; `--ssh-key FILE`
  authorizes your own public key instead. The host key, `authorized_keys`, and config live on the
  box's `/run` tmpfs (off the image), which is remounted read-only after setup. sshd is **pubkey-only**
  (`PasswordAuthentication no`, `UsePAM no`), binds `127.0.0.1:22` inside the box's own network
  namespace, and is a child of the box's PID 1 so it dies with the box.
- **Needs a group mapping.** sshd's privilege separation calls `setgroups`, which a single-uid user
  namespace forbids (`/proc/self/setgroups=deny`). So `--ssh` **implies the uid/gid-range mapping**
  (like `--uid-range`, via `newgidmap`) — with it, group ops succeed and login works with no in-box
  shim. On a host without `newuidmap`, the box falls back to single-uid and relies on a tiny
  `setgroups`/`initgroups` stub compiled in-box (only if a C compiler is present); otherwise SSH
  login won't complete and kern says so. The image must ship `openssh-server` (`sshd` + `ssh-keygen`).
- **Honest scope:** the forked sshd — and the shells it spawns per session — run **without** the box's
  seccomp filter **and with the pre-drop capability set** (they're forked before both `drop_dangerous_caps`
  and the seccomp install). Those caps are namespaced (checked against the initial user namespace for
  host-global effects, so largely inert against the host), but the SSH subtree is strictly more
  privileged than the box's main workload. The namespace / pivot / read-only-root / cgroup isolation
  still holds. `--ssh` is an *interactive-trust* grant — treat it like handing out a shell in the box.
- **`--ssh` runs the image's own binaries.** Standing up sshd executes the image's `ssh-keygen`, `sshd`,
  and (best-effort, only if present) `cc` to build the `setgroups` shim — all inside the already-pivoted
  box, as the box uid, but pre-seccomp/pre-cap-drop. A hostile image could ship a malicious `sshd`/`cc`;
  the exposure is the same interactive-trust surface you opted into (nothing runs host-side, and the
  shim/config live on a box-owned `/run` tmpfs remounted read-only after setup, so the workload can't
  swap them later).
- The uid/gid-range mapping trades a little of the single-uid map's extra isolation for a working sshd —
  a deliberate, documented choice scoped to `--ssh`.
- **`--ssh` logs in as (namespaced) root, even with `--user`.** sshd is forked before the `--user`
  drop and its config is `PermitRootLogin yes`, so an ssh session is box-root regardless of a
  `--user` set for the main workload. That root is your own unprivileged uid mapped to 0 inside the
  box's userns — no host privilege — but a `--user`-restricted box is still reachable as root over
  its SSH port. Grant `--ssh` to workloads you'd trust with a root shell in the box.
- **`--ssh` + `--net` puts the box sshd on the *host* loopback.** With the isolated network (default)
  the sshd is reachable only via the `-p` forwarder on `127.0.0.1:<port>`. Under `--network host` it
  binds `127.0.0.1:22` in the host network namespace directly — key-gated, but combine the two only
  when you intend host-loopback SSH reachability.

## Volumes

- **Named volumes** (`-v name:/dest`) are directories under `~/.local/share/kern/volumes`,
  auto-created and bind-mounted. The name is charset-validated (single component) and the resolved
  path is canonicalized and confined under the volumes dir, so a planted symlink can't redirect the
  bind outside it.
- **Per-volume quota** (`kern volume create <name> --size N`) records a size limit. When the box
  runs privileged (root / `disk` group, plain foreground) the volume is backed by the ext4-on-loop
  disk (a real, disk-backed quota); otherwise it falls back to a plain directory and kern **says the
  quota isn't enforced** — never a silent drop. The requested size is clamped to a 64 TiB ceiling at
  create time (and re-clamped when read back), so a hand-edited `meta.json` can't drive a multi-EB
  `mkfs`. The enforced (ext4 image) and unenforced (plain `data/` dir) backends are distinct on-disk
  locations; the first privileged mount **seeds** the fresh image from `data/` so upgrading a volume
  to the enforced backend doesn't hide files already written to it.
- **Network volumes** (`-v nfs://…`, `smb://`, `sshfs://`) mount rootless via FUSE/GVFS
  (`sshfs`/`gio`) into a per-box staging dir, then bind in. The host/path are strictly validated
  (no shell metacharacters, control chars, or a leading `-` that a tool would read as an option) —
  everything is spawned via argv, never a shell. A mount that can't reach its server is killed after
  25 s rather than hanging the launch, and the mount is unmounted when the box exits (its handle also
  cleans up on any error path). `sshfs` uses `StrictHostKeyChecking=accept-new` (trust-on-first-use)
  — an active MITM at *first* contact could impersonate the server; pin the host key beforehand for
  untrusted networks. Network volumes require a plain foreground box for now (not `-d`/`-it`).

## Supervision (`--timeout`, `--health-action`)

- The auto-stop and health-action watchdogs run **host-side**, never inside the box. Each is forked
  **before** the box's `unshare(CLONE_NEWPID)`, so it sits in the host (ancestor) pid namespace — the
  only position from which it can reliably signal the box's ns-init. An in-box process can't reach
  them: the foreground `--timeout` pipe is `FD_CLOEXEC` (severed at the workload's `execvp`, so the
  box never holds it), and the target pid comes from the trusted `fork()` return / the host-only
  registry (`$XDG_RUNTIME_DIR/kern/instances`, `0700`, not bind-mounted into the box) — never from
  anything the box can write. So an untrusted workload **cannot forge a pid to make the host signal an
  arbitrary process**.
- The foreground `--timeout` watchdog pins its target with a **`pidfd`** taken while the box is still
  alive, so the delayed SIGTERM/SIGKILL can never land on a reused pid (on a kernel too old for
  `pidfd`, < 5.3, it falls back to `kill(pid)`). The detached `--timeout` stopper re-checks the box is
  the **same instance** (name + supervisor pid, and `kern ps` already validates the pid's start-time)
  before tearing it down.
- Known, bounded limitation: `--health-action restart` re-reads the box's PID 1 from the registry and
  `SIGKILL`s it; during a restart gap that pid could in principle be reused by **another process of
  the same user** before the kill lands. The window is sub-quantum and **not attacker-targetable** (an
  unprivileged kill only reaches same-uid processes, and an in-box workload can't create host-ns
  processes to steer the reuse) — consistent with the cooperative, first-party trust model for the
  resource governor. It is not a cross-tenant boundary.

## Registry authentication (`kern login`, image pulls)

- Auth follows the standard registry-v2 `WWW-Authenticate` challenge, so any compliant registry
  works (Docker Hub, GHCR, GitLab, quay, Harbor, self-hosted) — anonymously, or with `kern login`
  credentials for private repos.
- **Every** request is TLS-pinned: `--proto =https` (and `--proto-redir =https` on the redirect-
  following ones), a bounded `--max-redirs`, and a `--` URL terminator — a hostile registry can't
  downgrade a manifest/blob/token fetch to `http://`/`file://` or smuggle a `-`-leading URL into a
  flag.
- **Credentials never touch argv.** `login` stores them `0600` (dir `0700`); on a pull they're fed
  to `curl` via a `-K` STDIN config (Basic) or used only to fetch a short-lived Bearer token — so no
  same-uid process can read the password from `/proc/<pid>/cmdline`. A crafted credential can't
  inject a curl directive (control chars stripped, quotes/backslashes escaped).
- **Realm pinning (CVE-2020-15157 class).** For a Bearer challenge, the stored password is sent to
  the advertised token `realm` **only if the realm host is the registry host or a subdomain of its
  parent domain** (e.g. `registry-1.docker.io` ↔ `auth.docker.io`). A registry that points its auth
  realm at a foreign host gets an **anonymous** token instead (with a warning), so a compromised or
  impersonated registry can't harvest the credentials the Bearer flow is meant to keep away from it.
  The realm host is parsed **exactly as curl dials it** — userinfo (`user:pass@host`) and `:port`
  stripped, case-folded — so a `realm="https://trusted:0@evil.com/…"` (curl connects to `evil.com`)
  can't masquerade as trusted; and a common multi-label public suffix (`co.uk`, `com.au`, …) is never
  treated as a trustable parent domain, so two unrelated `*.co.uk` registries can't cross-trust.
- The short-lived Bearer token (not the stored secret) does travel in an `Authorization` header;
  this is an accepted, standard trade-off.

## Hardening posture

- Zero vendor-binary modification; the GPU shim uses only the public driver API and is
  disable-able with `--no-gpu`.
- GNU tar >= 1.27 enforced for layer extraction; tar layers validated before extraction
  (no `..`, no absolute paths, size caps); escaping symlinks sanitized.
- Always-on seccomp blocks the dangerous syscall set regardless of flags.

## Supported versions

Pre-1.0: only the latest 0.x is supported. Security fixes land on `main`.
