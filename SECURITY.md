# Security Policy

kern runs untrusted images inside a sandbox. It *will* receive security reports; here is the model
and how to report.

## Reporting a vulnerability

**Please do not open a public issue for security bugs.** Report privately via GitHub Security
Advisories ("Report a vulnerability" on the repo) or email hello@getkern.dev. You will get an
acknowledgement and a coordinated-disclosure timeline.

## Threat model

**In scope. Kernel-enforced isolation must hold:**

- A malicious OCI image or `--rootfs` must not read or write host files outside the rootfs (path
  traversal, cross-layer symlink escape, whiteout-through-symlink, tar traversal).
- A box must not see or affect host processes, mounts, or other boxes.
- Resource limits must hold: fork bombs and OOM must be contained.
- seccomp must block the dangerous syscall set unconditionally.

**Out of scope, by design.** GPU limits are not shipped, so there is nothing here to trust or to
attack yet. When they land, expect a cooperative governor for honest workloads rather than a
boundary, and expect this file to say so with the bypasses named.

**An unprivileged user namespace is itself kernel attack surface.** kern's isolation is *built on*
one, and userns has historically been a fertile source of kernel privilege-escalation CVEs. Running
untrusted code in a box hands that code the in-kernel namespace surface to probe.

## kern or a microVM

kern isolates with namespaces, seccomp and a pivoted root: millisecond start, one small binary, no
VM, no daemon. That boundary is real and its attack surface is the host **kernel**, so a kernel
privilege-escalation bug is an escape.

- **Reach for kern** when the code is yours or semi-trusted and you want speed, density and
  simplicity: CI jobs, build steps, dev sandboxes, your own agent's tool-calls under your
  supervision.
- **Reach for a microVM** (Firecracker, Kata) or gVisor when you run actively hostile, multi-tenant
  code from strangers sharing one host, and a hardware-virtualization boundary is worth the startup
  cost. That is not where kern competes.

## What is enforced now

- **Namespaces**: user, PID, network (loopback-only), UTS, IPC and mount.
- **`pivot_root`** into the rootfs. The default root is a writable overlay whose scratch is discarded
  on exit; `--read-only` remounts it read-only, and the ordering (read-only only *after* the pivot)
  is compile-enforced by a typestate.
- **Least-privilege capabilities**: 13 never-needed dangerous caps (module load, raw I/O, `SYS_TIME`,
  `SYSLOG`, `BPF`, `PERFMON`, MAC and audit admin, `SYS_BOOT`, and more) are dropped from the
  effective, permitted, inheritable **and bounding** sets just before exec, so no setuid or
  file-capability binary in the image can wield them. `--cap-drop CAP` / `--cap-drop ALL` drops more;
  `--cap-add CAP` keeps one that would otherwise go (add wins), and an unknown cap name is a hard
  error so a typo cannot silently leave a cap in place. Even a re-added `CAP_SYS_ADMIN` is held only
  over the box's own user namespace, and the always-on filter still blocks the escape syscalls it
  would unlock, so `--cap-add` cannot breach the host.
- **Always-on seccomp**, **34 syscalls denied**: 24 that hard-kill plus the 10 that return `ENOSYS`,
  split described below; a rootless `--privileged` box denies 5 fewer. Do not take the number from
  this file, ask the binary: `kern box <name> --image <ref> --show-config` prints
  `seccomp_denied_syscalls` from the live lists. The set is kexec (+`_file_load`), module
  load/unload, `ptrace` + `process_vm_readv`/`writev`, reboot, swap, the classic **and** new mount
  API including the whole reconfiguration family (`mount_setattr`, `fspick`,
  `fsopen`/`fsconfig`/`fsmount`, `open_tree`/`move_mount`), so a box cannot re-mount its own root
  writable, plus `pivot_root`, `setns`, `unshare`, `bpf`, `clone3`, io_uring's three, `userfaultfd`,
  `perf_event_open`, the keyring's three and `syslog`. Wrong-arch syscalls are killed, and on x86_64
  so is every **x32-ABI** syscall, closing the classic bypass where the x32 alias of a denied number
  slips past a number-only denylist.
- **`clone(2)` is filtered on its ARGUMENTS**, and it is the only rule of that shape. Denying
  `unshare` and `setns` does not stop a workload making a namespace, because `clone` takes the same
  `CLONE_NEW*` flags, and a process that creates a nested user namespace is handed a full capability
  set by the kernel, bounding set included. `clone` cannot simply be denied by number, since `fork`,
  `vfork`, `posix_spawn` and `pthread_create` are all `clone` with no namespace bit, so the filter
  reads the flags out of the register they arrive in and kills only the seven `CLONE_NEW*` bits.
  `clone3` puts the same flags in a struct behind a pointer, which BPF **cannot dereference**, so it
  is refused wholesale with `ENOSYS`, the answer Docker and podman give for the same reason. Closed
  in 0.6.34, verified on six platforms.
- **Device access is deny-by-default**: the box's `/dev` is a fresh box-owned tmpfs shadowing the
  image's, with only `null`, `zero`, `full`, `random` and `urandom` bound in. Any other node is simply
  **absent**, and one the box fabricates is **inert**: a filesystem mounted in an unprivileged user
  namespace is flagged `SB_I_NODEV`, so a `mknod`'d node cannot be opened to reach a host device (on
  kernels below 5.11 `mknod` itself returns `EPERM`; same outcome). The root, `/dev` and every extra
  mount also carry `MS_NODEV`, so this holds without relying on the implicit userns behaviour.
- **Landlock write-allowlist** (`--landlock-rw <path>`, opt-in, needs Linux 5.13+): a kernel LSM
  confines the box's writes to the named paths while the root stays read+exec, with symlinks opened
  `O_NOFOLLOW`. **A real boundary**, verified: a box with `--landlock-rw /tmp` writes `/tmp` and is
  denied `/etc` and `/root`. Where the kernel lacks it, the box still runs with the namespace,
  seccomp and cgroup boundary.
- **Egress allowlist** (`--egress-allow`, opt-in, foreground): the box reaches the internet only
  through a kern-run filtering proxy. **SSRF-guarded**: a domain resolving to any non-public address
  is refused at connect time even if allow-listed. Honest residual: a domain sharing a CDN IP and SNI
  with an allowed one can be reached, so this is an application-layer allowlist for a semi-trusted
  workload, **not a hard exfiltration boundary**. Full model in [docs/EGRESS.md](docs/EGRESS.md).

### What a denied syscall returns

The filter has two verdicts. Real escape vectors (kexec, module load/unload, the mount API, `bpf`,
`ptrace`, `setns`/`unshare`/`pivot_root`) **hard-kill** the caller with `SIGSYS`. Ten, in six
families that software merely probes for an optional fast path (io_uring's three, `userfaultfd`,
`perf_event_open`, the keyring's three, `syslog`, and `clone3`), return **`ENOSYS`**. They are
equally denied; the difference is only what the caller sees, and it is the difference between Redis
falling back to its epoll path and Redis dying. The two sets are asserted disjoint by a test.

The obvious objection is that a survivable denial is easier to enumerate than a fatal one. Measured
from inside a box on x86_64, kernel 7.0:

| syscall probed inside the box | result |
|---|---|
| `io_uring_setup` (denied, degrade set) | `-1 ENOSYS`, process survives |
| syscall number 998 (exists on no kernel) | `-1 ENOSYS`, process survives |
| `kexec_load`, `bpf` (denied, kill set) | killed by `SIGSYS` |
| the same calls with no kern filter (control) | a *different* errno, never `ENOSYS` |

So the errno discloses nothing: a filtered call is byte-identical to one this kernel does not
implement. What is cheap to enumerate is the **permitted** set, and it always was, since a permitted
syscall runs and returns its own errno. `ENOSYS` moves ten calls from "costs the prober a process"
to "free"; the 24 in the kill set still cost one each. Whether mapping a filter helps an attacker who
already has code execution in the box is a separate and open question, written down as unresolved in
[OPEN_ITEMS.md](OPEN_ITEMS.md) rather than argued either way here.

### Read-only and cgroup-mask integrity

Two independent layers. The always-on filter blocks the mount-reconfiguration family, so a box cannot
re-mount its root writable; the default capability drop removes `CAP_SYS_ADMIN`, so it cannot
`umount` the cgroup masks to reach the host hierarchy. A box explicitly granted `CAP_SYS_ADMIN` or
run with `--no-seccomp` waives one layer by choice. A third hardening, locking the mounts with
`MNT_LOCKED` so the guarantees hold even in those opt-in configurations, is deferred rather than
shipped untested: it reorders capability-sensitive setup that must be verified on real namespaces.

### Nested boxes (`--privileged`)

By default a full `kern box` cannot run inside another; it gets `SIGSYS`. `--privileged` relaxes
**exactly five** syscalls, `unshare`, `setns`, `mount`, `umount2` and `pivot_root`, so a nested box
can create its own namespaces and rootfs. Everything else stays blocked, so a `--privileged` kern box
is materially stronger than a Docker `--privileged` container, which drops the filter wholesale. It
also skips `/proc` masking, because the kernel refuses a nested `/proc` mount under the locked masks.

**Rootless-only, and gated on the effective mapping rather than the caller's euid:** it is honoured
only when the box's root maps to an unprivileged host uid, decided by reading `/proc/self/uid_map`
after the namespace is set up, and refused outright as real root, where a relaxed `mount` could reach
the host-global `/proc/sys` knobs. Rootless, those knobs stay unwritable regardless: a `--privileged`
box can read `/proc/sys` but not write it, verified against `core_pattern`.

## Resource caps

With a systemd **user** manager present, `kern box` runs inside a transient `systemd-run --user
--scope` with `MemoryMax`/`TasksMax`, so fork bombs and OOM are cgroup-enforced. Without it, a
best-effort cgroup v2 path applies where the hierarchy is delegated, else it is skipped gracefully:
on a host with **neither**, containment is not guaranteed. `--pids-limit N` sets `pids.max`, default
512, on the same terms.

**`kern exec` and the box's caps.** An exec'd command joins the box's cgroup, and so inherits its
caps, **only where the box sits in a delegated cgroup kern can write**. On the rootless per-box-scope
path (an SSH login on an edge board, whose shell is a sibling scope) the kernel will not let `kern
exec` migrate into the box's transient scope, so an exec'd command runs **outside** the box's caps.
kern warns when the box has explicit caps rather than leak it silently. The box's own workload is
always capped, and namespaces plus seccomp isolate the exec'd command regardless. Each exec does not
get its own capped scope on purpose: that would grant every exec the box's full limit, so N execs
could use N times the box's memory.

## Flags that change the posture

- **`--user UID[:GID]`** drops the workload after all privileged setup and the capability drop. Only
  ids mapped into the box's user namespace work, so a non-root `--user` implies the uid/gid-range
  mapping. It **fails closed**: if the id cannot be mapped the box refuses to start rather than
  silently running as in-box root. Note it **sheds all capabilities**, including any `--cap-add`.
- **`--tmpfs PATH[:size]`** mounts a fresh `NOSUID,NODEV` tmpfs. Mounting one over the sandbox's own
  hardened `/proc`, `/sys` or `/dev` is **refused**. The size is a real cap but counts against RAM.
- **`--net`** (`--network host`) shares the host network namespace: there is then **no network
  isolation**. The box can reach host `localhost` services, the host's networks, and **every
  abstract-namespace UNIX socket** (X11, some D-Bus sockets), and can bind host-visible addresses.
- **`--tun`** binds `/dev/net/tun` in. The box holds `CAP_NET_ADMIN`, but a child user namespace's
  capabilities are not effective over a namespace owned by the initial one, so even with
  `--network host` it **cannot reconfigure the host's interfaces** (`EPERM`).
- **`-v src:dst`** binds a host path in. A writable volume is a hole through the sandbox by design;
  use `:ro`. kern rejects a non-existent source and resolves it to an absolute, symlink-free path.
  The bind is **non-recursive**, because a recursive one would clone host submounts that a `:ro`
  volume could then leave writable.
- **`-p [ip:]host:box`** binds **`127.0.0.1` by default**. `-p 0.0.0.0:H:B` exposes the service to
  the LAN, a deliberate and warned-about choice. The forwarder runs in the host network namespace,
  the box stays in its own.
- **`kern exec`** is restricted to the user who started the box. The exec'd process gets the same
  always-on seccomp filter, **fail-closed**, and the same dropped-cap baseline. A box's custom
  `--cap-drop`/`--user` are not reapplied, since they are not recorded per box, so an exec runs at the
  baseline rather than the tightened profile. The host boundary still holds.
- **`kern cp`** resolves the in-box path with `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`, so
  every symlink and `..` is reinterpreted as if the box root were `/`: a hostile image cannot plant a
  link that makes the copy touch a host file (the CVE-2019-14271 class). Nothing is executed inside
  the box to do it. Regular files only, opened `O_NONBLOCK` so a planted FIFO cannot hang the copy,
  with a 4 GiB cap.
- **`kern pause`/`unpause`** write only the box's own cgroup and refuse when it has none.
  **`kern attach`** is read-only.

## OCI pull, build and push

- **Integrity**: every blob is verified against its `sha256:` digest before use, which defends
  against a compromised or MITM registry beyond TLS. The check runs **before** both the vetter and
  the extractor and both read the same verified file, so any disagreement between them can only be
  interpretive, never a difference in bytes.
- **Layer vetting, in-process.** Absolute and `..` paths, device nodes, escaping hardlink and
  symlink targets, a 2 GiB decompression-bomb cap and an entry-count cap are rejected before anything
  is written. The decision reads the **raw tar headers** at fixed offsets, not `tar -tv`'s
  locale-dependent text, which a member name containing ` -> ` could otherwise desync. Because the
  vetter and `tar -xzf` are two parsers, the principle is **fail closed wherever they could
  disagree**: a path set from two sources (GNU `L`/`K` *and* PAX `path=`), a PAX global override, a
  GNU sparse or multivolume member, a base-256 size too large for a `u64`, and any unknown typeflag
  are all refused. The scan requires an all-zero tail, capped so a zero flood cannot make the check
  itself a DoS. A legitimate image built with an exotic-but-safe construct is refused rather than
  extracted. The byte-level parser is fuzzed.
- **Isolated staging, no-follow merge**: each layer extracts into a fresh staging dir, then merges
  into the rootfs refusing to traverse any symlink, so the cross-layer escape class is closed
  structurally rather than by trusting tar. Whiteouts, including opaque dirs, are applied under the
  same guard, and the cache and scratch dirs are mode 0700 and user-owned.
- **Image file modes are preserved as-is**, so an image's `/tmp` keeps its sticky `1777`. Stated
  plainly: an image shipping a world-writable system dir leaves it world-writable **inside the box**.
  It is contained, being the box's own rootfs on a 0700 host scratch, never the host, and a setuid
  bit there is inert because the box root is `MS_NOSUID`.
- **`push`** packs the rootfs with ownership normalized to uid/gid 0 and setuid/setgid bits stripped,
  so an untrusted base cannot smuggle a privilege bit into what you publish.

## Registry authentication

- Auth follows the standard registry-v2 challenge, so any compliant registry works, anonymously or
  with `kern login`.
- **Every request is TLS-pinned**: `--proto =https`, `--proto-redir =https` where redirects are
  followed, a bounded `--max-redirs` and a `--` URL terminator, so a hostile registry cannot
  downgrade a fetch to `http://` or `file://` or smuggle a `-`-leading URL into a flag.
- **Credentials never touch argv.** They are stored `0600` in a `0700` dir, base64-encoded for
  obfuscation only (the mode is the protection), read from the terminal with echo off, and fed to
  `curl` through a `-K -` **stdin config**, so no same-uid process can read them from
  `/proc/<pid>/cmdline`. Control characters are stripped so a crafted credential cannot inject a curl
  directive.
- **Realm pinning (CVE-2020-15157 class).** For a Bearer challenge the stored password goes to the
  advertised token realm **only if that host is the registry host or a subdomain of its parent
  domain**; otherwise the token is fetched anonymously, with a warning. The realm host is parsed
  exactly as curl dials it, userinfo and port stripped, so `realm="https://trusted:0@evil.com/"`
  cannot masquerade as trusted, and a multi-label public suffix (`co.uk`) is never a trustable
  parent. A cross-host redirect during upload is refused.

## vGPIO device passthrough (opt-in)

A `vgpio:` profile **deliberately widens** the box's device surface: it binds the listed peripherals
(`/dev/i2c-*`, `/dev/spi*`, `/dev/gpiochip*`, camera and audio, and `/sys` dirs for pwm, adc, 1-wire
and leds) into the box. Only the listed devices are exposed, deny-by-default still holds for
everything else, and the source paths are canonicalized and re-checked to stay under `/dev/`. Two
honest limitations:

- **GPIO is chip-granular, not per-line.** Requesting any `pins` binds every `/dev/gpiochipN`, and
  that character device exposes *all* of the controller's lines via ioctl. `pins = [17]` does **not**
  restrict the box to line 17; the kernel has no per-line mount boundary. The pin list is cooperative
  metadata, not a security boundary.
- **`--read-only` keeps a vGPIO box's `/sys` writable**, because LED and PWM control are writes. The
  root filesystem is still read-only.

Grant a `vgpio:` profile only to workloads you would trust with that hardware.

## vDisk

A `vdisk:` profile mounts a size-capped volume at `/vdisk/<name>`. Rootless it is a RAM-backed
tmpfs: the size is a real quota (`ENOSPC` past it) but it counts against RAM, so pair a large vdisk
with `--memory`; kern warns at 1 GiB and above. The mount is created inside a fresh box-owned
`/vdisk` tmpfs with symlinks neutralized, so a hostile image shipping `/vdisk` as a symlink cannot
redirect it. A disk-backed ext4-on-loop backend is used instead when kern runs privileged, configured
`LO_FLAGS_AUTOCLEAR` and unwound immediately on any setup failure so a half-built vdisk cannot leak a
loop device or a stray mount. `iops` and `bandwidth` limits are recognised but not yet applied, and
are reported rather than silently dropped.

## Secrets (`--secret`)

`--secret` delivers a value as `/run/secrets/<name>`, mode **0400**, without it landing in the image
or the environment. Three forms: `NAME=value` (inline, and **visible in the host's `ps`**, so prefer
a file or stdin for real secrets), `NAME=-` (read from kern's stdin, never in argv), and `SRC[:NAME]`
(a host file; a world-writable source is refused and a group-readable one warned). The name is
validated to a single path component and duplicates are rejected.

The bytes are read on the host **before the fork**; inside the box they are written to a RAM-backed
tmpfs, so a secret never touches the persisted overlay upper and is gone when the box exits. A
hostile image shipping `/run/secrets` as a symlink is neutralised, and each file is created
`O_EXCL | O_NOFOLLOW` inside the box-owned tmpfs so the write cannot be redirected out.

## SSH (`--ssh`)

`--ssh PORT` runs a throwaway `sshd` **inside** the box and publishes it via the ordinary rootless
forwarder. It is for interactive box access, not a hardened bastion.

- **Keys never touch the image.** Without `--ssh-key`, kern generates a throwaway ed25519 keypair
  in the owner-only runtime dir. The host key, `authorized_keys` and config live on the box's `/run`
  tmpfs, remounted read-only after setup. sshd is **pubkey-only** and dies with the box's PID 1.
- **Needs a group mapping**, because sshd's privilege separation calls `setgroups`, which a
  single-uid user namespace forbids. So `--ssh` implies the uid/gid-range mapping via `newgidmap`;
  without `newuidmap` login will not complete and kern says so. The image must ship `openssh-server`.
- **Honest scope: the forked sshd, and the shells it spawns, run WITHOUT the box's seccomp filter and
  with the pre-drop capability set**, because they are forked before both steps. Those caps are
  namespaced and largely inert against the host, but the SSH subtree is strictly more privileged than
  the box's main workload. Standing sshd up also **runs the image's own binaries** pre-seccomp, so a
  hostile image could ship a malicious one: that is the interactive-trust surface you opted into.
- **It logs in as (namespaced) root even with `--user`**, since sshd is forked before the drop. That
  root is your own uid mapped to 0 in the box with no host privilege, but a `--user`-restricted box
  is still reachable as root over SSH. With `--net` the sshd binds the **host** loopback directly.

## Volumes

- **Named volumes** live under `~/.local/share/kern/volumes`. The name is charset-validated to a
  single component and the resolved path is canonicalized and confined under the volumes dir, so a
  planted symlink cannot redirect the bind.
- **Per-volume quota** is a real disk-backed quota only when the box runs privileged (ext4-on-loop);
  otherwise it falls back to a plain directory and kern **says the quota is not enforced**, never
  silently drops it. The size is clamped to a 64 TiB ceiling at create time and again when read back,
  so a hand-edited `meta.json` cannot drive a multi-exabyte `mkfs`. The first privileged mount seeds
  the fresh image from the unenforced backend, so upgrading does not hide files already written.
- **Network volumes** (`nfs://`, `smb://`, `sshfs://`) mount rootless via FUSE. Host and path are
  strictly validated (no shell metacharacters, control characters, or a leading `-` a tool would read
  as an option) and everything is spawned via argv, never a shell. A mount that cannot reach its
  server is killed after 25 s, and unmounted when the box exits. `sshfs` uses
  `StrictHostKeyChecking=accept-new`, so an active MITM at *first* contact could impersonate the
  server; pin the host key beforehand on untrusted networks.

## Supervision (`--timeout`, `--health-action`)

The watchdogs run **host-side**, never inside the box, and each is forked **before** the box's
`unshare(CLONE_NEWPID)`, the only position from which it can reliably signal the box's ns-init. An
in-box process cannot reach them: the foreground `--timeout` pipe is `FD_CLOEXEC`, severed at the
workload's exec, and the target pid comes from the trusted `fork()` return or the host-only registry,
never from anything the box can write. So an untrusted workload **cannot forge a pid to make the host
signal an arbitrary process**. The foreground watchdog pins its target with a **pidfd** taken while
the box is alive, so a delayed signal cannot land on a reused pid.

Known, bounded limitation: `--health-action restart` re-reads PID 1 from the registry and `SIGKILL`s
it, and during a restart gap that pid could in principle be reused by another process **of the same
user** before the kill lands. The window is sub-quantum and not attacker-targetable, since an
unprivileged kill only reaches same-uid processes and an in-box workload cannot create host-namespace
processes to steer the reuse. It is not a cross-tenant boundary.

## Check it yourself

The claims above are asserted by four adversarial suites in [pentest/](pentest/), which ask the
kernel what is true rather than asking kern to report on itself: that a published port cannot tunnel
into a host service, that `--ssh` does not hand out the host's shell, that `kern exec` does not
escape the box, that a box cannot raise its own `memory.max` and sees no cgroup above its own, that a
device not granted does not cross, and that a SIGKILLed supervisor does not leave a host port held.

```sh
cargo build --release
sh pentest/run-with-local-registry.sh ./target/release/kern pentest/pentest-ports.sh
```

That wrapper serves the test image from your own loopback, so nothing here needs a registry account
or a network. Exit status is 0 only if every asserted property held; a host that cannot answer a
question reports `SKIP` with the reason and never counts it as a pass. Measured results, and what is
deliberately not wired into CI, are in [pentest/README.md](pentest/README.md).

## Supported versions

Pre-1.0: only the latest 0.x is supported. Security fixes land on `main`.
