# Security Policy
kern runs untrusted images inside a sandbox. It *will* receive security reports; here is the model
and how to report.

## Reporting a vulnerability
**Please do not open a public issue for security bugs.** Report privately via GitHub Security
Advisories ("Report a vulnerability" on the repo) or email hello@getkern.dev. You will get an
acknowledgement and a coordinated-disclosure timeline.

## Threat model
The structured view - assets, entry points, and the two trust levels (a kernel-enforced boundary
versus a cooperative governor) as tables - is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). This
section is the summary; the rest of this file is the per-mechanism detail behind it.

**In scope. Kernel-enforced isolation must hold:**

- A malicious OCI image or `--rootfs` must not read or write host files outside the rootfs (path
  traversal, cross-layer symlink escape, whiteout-through-symlink, tar traversal).

- A box must not see or affect host processes, mounts, or other boxes.

- A box must not read or write kern's own runtime registry (a peer box's ssh host keys, secrets, and
  recorded capability/seccomp posture) through any host-path input: `-v`, `--secret`, `--env-file`,
  `--rootfs`, the `kern build` context/`-f` Dockerfile, or `kern cp`/`kern save -o`.

- Resource limits must hold: fork bombs and OOM must be contained.

- seccomp must block the dangerous syscall set unconditionally.

**Out of scope, by design: the GPU.** No GPU limit ships, so there is no cap here to attack. What
ships is the verdict about one, and the verdict is that a VRAM cap in userspace is a quota and not a
boundary.

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
  cost.

## What is enforced now
- **Namespaces**: user, PID, network (loopback-only), UTS, IPC and mount.

- **`pivot_root`** into the rootfs. The default root is a writable overlay whose scratch is discarded on exit; `--read-only` remounts it read-only. The overlay `lowerdir` is the image cache, shared read-only across boxes, and every write lands in a per-box ephemeral upper.

- **Least-privilege capabilities**: 16 never-needed dangerous caps (module load, raw I/O,
  `SYS_TIME`, `SYSLOG`, `BPF`, `PERFMON`, MAC and audit admin, `SYS_BOOT`, `SYS_PTRACE`, `NET_ADMIN`
  and `SYS_ADMIN`, the same default set Docker and Podman drop) are dropped from the effective,
  permitted, inheritable, **ambient and bounding** sets just before exec, so no setuid or file-
  capability binary in the image can wield them. Dropping `SYS_PTRACE` closes the **cross-UID**
  `/proc/<pid>/mem` read in a multi-uid box (its syscall is seccomp-killed anyway); a **same-uid**
  sibling read inside one box stays possible and is not a boundary, a box being one trust domain,
  and host or peer-box memory is unreachable regardless because those pids are not in the box's pid
  namespace.

- **Always-on seccomp, allowlist by default**: the shipped default is moby's own default filter
  minus kern's 35 (deny-by-default, the long tail returning `ENOSYS`); the wider denylist is the
  opt-out via `KERN_SECCOMP=denylist`.

- **`clone(2)` is filtered on its ARGUMENTS**, and it is the only rule of that shape.

- **`socket(AF_VSOCK, …)` is refused** with `EAFNOSUPPORT`, in BOTH the denylist and the allowlist.

- **Device access is deny-by-default**: the box's `/dev` is a fresh box-owned tmpfs shadowing the
  image's, with only `null`, `zero`, `full`, `random` and `urandom` bound in.

- **Landlock write-allowlist** (`--landlock-rw <path>`, opt-in, needs Linux 5.13+): a kernel LSM
  confines the box's writes to the named paths while the root stays read+exec, with symlinks opened
  `O_NOFOLLOW`.

**Measured on four hosts**, each with a positive control, so a host that cannot run the command at
all is never read as a pass: enforced on this desktop (Linux 7.0, ABI 8, unprivileged) and on an
Ubuntu 24.04 VPS as root (kernel 6.8, ABI 4, where a write outside the grant is denied at uid 0
exactly as for a normal user); **refused**, on both `box` and `run`, on a Raspberry Pi 5 whose only
LSM is `capability` and on a Jetson Orin Nano (5.15-tegra, systemd 249). On the two that refuse, the
same command runs without the flag, so the refusal is the flag's and not the host's.

**Two limits of a write allowlist, measured rather than assumed**, because "writes stay in the
folder" is true of bytes and not of everything: - **A FIFO inside the grant is a channel out.** A
named pipe in the granted directory, with a reader running outside the confinement, carries data
past the boundary: the write is inside the grant and Landlock permits it exactly as documented.
Verified on this desktop, the string arrives outside.

- **Egress allowlist** (`--egress-allow`, opt-in, foreground): the box reaches the internet only
  through a kern-run filtering proxy.

### What a denied syscall returns
The filter has two verdicts. Real escape vectors (kexec, module load/unload, the mount API, `bpf`,
`ptrace`, `setns`/`unshare`/`pivot_root`) **hard-kill** the caller with `SIGSYS`.

The obvious objection is that a survivable denial is easier to enumerate than a fatal one. Measured
inside a box on x86_64, kernel 7.0:

| syscall probed inside the box | result |
|---|---|
| `io_uring_setup` (denied, degrade set) | `-1 ENOSYS`, process survives |
| syscall number 998 (exists on no kernel) | `-1 ENOSYS`, process survives |
| `kexec_load`, `bpf` (denied, kill set) | killed by `SIGSYS` |
| the same calls with no kern filter (control) | a *different* errno, never `ENOSYS` |
So the errno discloses nothing: a filtered call is byte-identical to one this kernel does not
implement. What is cheap to enumerate is the **permitted** set, and always was, since a permitted
syscall runs and returns its own errno.

### Read-only and cgroup-mask integrity
Two independent layers, and neither is the default cap drop - which does **not** remove
`CAP_SYS_ADMIN` (that cap is kept, held only over the box's own user namespace). First, the always-
on filter **kills** the mount API - `mount`, `umount2`, `pivot_root`, `setns` and the whole
reconfiguration family - so a box cannot re-mount its root writable OR `umount` the cgroup masks to
reach the host hierarchy, whatever caps it holds.

### Nested boxes (`--privileged`)
By default a full `kern box` cannot run inside another; it gets `SIGSYS`. `--privileged` relaxes
**exactly five** syscalls, `unshare`, `setns`, `mount`, `umount2` and `pivot_root`, so a nested box
can create its own namespaces and rootfs.

**Rootless-only, and gated on the effective mapping rather than the caller's euid:** it is honoured
only when the box's root maps to an unprivileged host uid, decided by reading `/proc/self/uid_map`
after the namespace is set up, and refused outright as real root, where a relaxed `mount` could
reach the host-global `/proc/sys` knobs. Rootless, those knobs stay unwritable regardless: a
`--privileged` box can read `/proc/sys` but not write it, verified against `core_pattern`.

### Pods share three namespaces, and one of them is the identity domain
A pod exists so its members can reach each other by name, and that is a boundary decision, not a
networking convenience. Read from `/proc/self/ns` in four boxes that are alive AT THE SAME TIME, the
shared set is:

| namespace | in a pod | standalone |
|---|---|---|
| **user** | **shared** | private |
| **network** | **shared** | private |
| mount, PID, IPC, uts, cgroup | private | private |
Four boxes at once, rather than four in a row, because a namespace inode is freed when its last
member exits and the kernel reuses the number. An earlier version of this table said `uts` was
shared too, read off boxes that had run one after another: with all four alive it is private, and
the runs that said otherwise were comparing an inode a dead box had handed back.

The user namespace is the one to weigh. Members are one identity and capability domain rather than
separate ones: root in one member and root in another are the same mapped authority, and a
capability held over that namespace is held over it by all of them.

The shared network namespace is a route. Members share `127.0.0.1` and the abstract socket
namespace, which is exactly what makes a pod useful and also means a listener on loopback in one
member is reachable from another.

```sh
kern pod create p
kern box srv --image alpine --pod p -d -- sh -c 'echo secret | nc -l -p 9999 -s 127.0.0.1'
kern box cli --image alpine --pod p    -- nc -w 2 127.0.0.1 9999    # prints: secret
```
The same command from a box outside the pod reaches nothing.

**So: put workloads in one pod when you would have put them in one trust boundary anyway**, which is
what a compose stack is. Do not reach for a pod to make a box start faster, even though it does
([BENCHMARKS.md](BENCHMARKS.md) measures 2.59 ms against 3.89): the millisecond is real and so is
the shared identity domain that buys it.

A pod maps a sub-uid range into its shared user namespace by default, the same default a standalone
`--image` box has, because the mapping costs nothing per member once the holder has done it. `--no-
uid-range` asks for the single-uid map instead: tighter, and the same trade the flag makes on a
standalone box.

## Resource caps
Inside the systemd **user** manager's tree, `kern box` caps directly in its delegated `kern.slice`;
where that is out of reach it falls back to a transient `systemd-run --user --scope` with
`MemoryMax`/`TasksMax`. Either way fork bombs and OOM are cgroup-enforced, verified by read-back.

**`--require-limits` makes the uncapped fallback fatal.** With it (or `KERN_REQUIRE_LIMITS`) a box
refuses to start, non-zero, unless the memory and pids caps are actually in force, **read back from
the cgroup** rather than merely written: the OOM / fork-bomb backstop, never a box that runs
believing it is capped when it is not. cpu/cpuset stay best-effort, as they carry no containment
role.

**`kern exec` and the box's caps.** An exec'd command inherits them **only where the box sits in a
delegated cgroup kern can write**. On the rootless per-box-scope path (an SSH login on an edge
board, whose shell is a sibling scope) the kernel will not let it migrate into the box's transient
scope, so the exec'd command runs **outside** the box's caps; kern warns rather than leak that
silently.

## Delivering an environment, and who can read it
`--env-file` exists so a secret does not have to travel in `argv`, where the process table shows it
to every local user for as long as the box lives. That is the whole of what it buys, and the
boundary is worth stating exactly, because a caller who reads more into it will be wrong in the
direction that costs them.

**Against another user on the host**, the file's mode is the guard, and the Python binding's
LangChain policy goes further: it puts the environment in an anonymous `memfd` and passes the
descriptor, so there is no name on any filesystem to open, and a `kill -9` of the caller leaves
nothing behind (a named temp file cleaned by a finalizer does, since finalizers do not run on a
kill).

**Against another process of the SAME user, it is not a boundary.** kern does not close descriptors
it did not open, so an inherited one stays in its table for the life of the box: `/proc/<kern-
pid>/fd/N` is readable by anything running as you. Measured with a sampler over a whole session
rather than a single look at a running one, which is how a first and sloppier probe of ours reported
the opposite.

So: better than `argv` in every case, better than a named file after the process dies, and the same
as either while it lives. Closing an inherited descriptor once the environment is parsed would
shrink that window to the parse itself; until that lands, this is a documented limit and not a
defence, and a host where other local processes are hostile is not one to hand a secret to through
any of these paths.

## Flags that change the posture
- **`--security-profile untrusted`** is an opt-in bundle for code nobody has read: the seccomp
  **allowlist** (deny-by-default, the same posture the default now installs), **`--cap-drop ALL`**,
  and **`--read-only`** root, applied as a BASE that explicit flags still override.

- **`--apparmor <profile>`** enters a pre-loaded AppArmor (LSM) profile on the box's `exec`,
  layering kernel-enforced file/capability confinement over namespaces + seccomp - Docker's
  `--security-opt apparmor=`.

- **`--user UID[:GID]` (or a name)** drops the workload after all privileged setup and the
  capability drop.

- **`--tmpfs PATH[:size]`** mounts a fresh `NOSUID,NODEV` tmpfs.

- **`--net`** (`--network host`) shares the host network namespace: there is then **no network
  isolation**.

- **`--tun`** binds `/dev/net/tun` in. The box holds `CAP_NET_ADMIN`, but a child user namespace's capabilities are not effective over a namespace owned by the initial one, so even with `--network host` it **cannot reconfigure the host's interfaces** (`EPERM`).

- **`-v src:dst`** binds a host path in. A writable volume is a hole through the sandbox by design; use `:ro`.

- **`-p [ip:]host:box`** binds **`0.0.0.0` by default**, which is every interface, which is the LAN.

- **`kern exec`** is restricted to the user who started the box.

- **`kern cp`** resolves the in-box path with `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`, so
  every symlink and `..` is reinterpreted as if the box root were `/`: a hostile image cannot plant
  a link that makes the copy touch a host file (the CVE-2019-14271 class).

- **`kern pause`/`unpause`** write only the box's own cgroup and refuse when it has none.

- **What kern RENDERS is sanitised; what the WORKLOAD wrote is not.** Two different questions, and
  the answer differs on purpose.

## OCI pull, build and push
- **Integrity**: every blob is verified against its `sha256:` digest before use, which defends
  against a compromised or MITM registry beyond TLS.

- **Layer vetting, in-process.** Absolute and `..` paths, device nodes, escaping hardlink and
  symlink targets, a 2 GiB decompression-bomb cap and an entry-count cap are rejected before
  anything is written.

- **Isolated staging, no-follow merge**: each layer extracts into a fresh staging dir, then merges
  into the rootfs refusing to traverse any symlink, so the cross-layer escape class is closed
  structurally rather than by trusting tar.

- **Image file modes are preserved as-is**, so an image's `/tmp` keeps its sticky `1777`.

- **`push`** packs the rootfs with ownership normalized to uid/gid 0 and setuid/setgid bits
  stripped, so an untrusted base cannot smuggle a privilege bit into what you publish.

## Registry authentication
- Auth follows the standard registry-v2 challenge, so any compliant registry works, anonymously or
  with `kern login`.

- **Every request is TLS-pinned**: `--proto =https`, `--proto-redir =https` where redirects are
  followed, a bounded `--max-redirs` and a `--` URL terminator, so a hostile registry cannot
  downgrade a fetch to `http://` or `file://` or smuggle a `-`-leading URL into a flag.

- **Credentials never touch argv.** They are stored `0600` in a `0700` dir, base64-encoded for
  obfuscation only (the mode is the protection), read from the terminal with echo off, and fed to
  `curl` through a `-K -` **stdin config**, so no same-uid process can read them from
  `/proc/<pid>/cmdline`.

- **Realm pinning (CVE-2020-15157 class).** For a Bearer challenge the stored password goes to the
  advertised token realm **only if that host is the registry host or a subdomain of its parent
  domain**; otherwise the token is fetched anonymously, with a warning.

## vGPIO device passthrough (opt-in)
A `vgpio:` profile **deliberately widens** the box's device surface: it binds the listed peripherals
(`/dev/i2c-*`, `/dev/spi*`, `/dev/gpiochip*`, camera and audio, and `/sys` dirs for pwm, adc, 1-wire
and leds) into the box. Only the listed devices are exposed, deny-by-default still holds for
everything else, and the source paths are canonicalized and re-checked to stay under `/dev/`.

- **GPIO is chip-granular, not per-line.** Requesting any `pins` binds every `/dev/gpiochipN`, and
  that character device exposes *all* of the controller's lines via ioctl. The pin list is
  cooperative metadata, not a security boundary.

- **`--read-only` keeps a vGPIO box's `/sys` writable**, because LED and PWM control are writes.

Grant a `vgpio:` profile only to workloads you would trust with that hardware.

## GPU: no cap ships, and why one in userspace would not be a boundary
**No GPU limit ships, so there is no cap here to attack.** What ships is a read-only verdict: `kern
doctor` reads sysfs and reports what a VRAM cap on each device would be worth. `TIER-HW` where a MIG
or SR-IOV partition is present, which the device enforces rather than the tenant, though kern reads
its presence and **has not measured the VRAM split**; `TIER-SOFT` for everything else, which on
consumer hardware is a cooperative quota, NOT a boundary against malicious code.

The reason a userspace cap cannot be a boundary is that the workload does not have to go through it:
measured on an RTX 5060 Ti, a process linking only libc reached the driver with a raw ioctl and was
answered, on two distinct driver ABIs. The full argument, the four other measured bypasses, the
scope it does and does not cover, and **two named blind spots** in kern's own detection are in
[docs/GPU-CLAIMS.md](docs/GPU-CLAIMS.md), and [`pentest/pentest-gpu-claims.sh`](pentest/pentest-gpu-
claims.sh) runs them.

**What to do with a hostile GPU tenant.** Give it a MIG instance or an SR-IOV virtual function, or
give it the whole device. A cooperative quota is the right tool for packing several of your own
models onto one card, and the wrong tool for containing someone else's.

## vDisk
A `vdisk:` profile mounts a size-capped volume at `/vdisk/<name>`. Rootless it is a RAM-backed
tmpfs: the size is a real quota (`ENOSPC` past it) but it counts against RAM, so pair a large vdisk
with `--memory`; kern warns at 1 GiB and above.

## Secrets (`--secret`)
`--secret` delivers a value as `/run/secrets/<name>`, mode **0400**, without it landing in the image
or the environment. Three forms: `NAME=value` (inline, and **visible in the host's `ps`**, so prefer
a file or stdin for real secrets), `NAME=-` (read from kern's stdin, never in argv), and
`SRC[:NAME]` (a host file; a world-writable source is refused and a group-readable one warned).

The bytes are read on the host **before the fork**; inside the box they are written to a RAM-backed
tmpfs, so a secret never touches the persisted overlay upper and is gone when the box exits. A
hostile image shipping `/run/secrets` as a symlink is neutralised, and each file is created `O_EXCL
| O_NOFOLLOW` inside the box-owned tmpfs so the write cannot be redirected out.

## SSH (`--ssh`)
`--ssh PORT` runs a throwaway `sshd` **inside** the box and publishes it via the ordinary rootless
forwarder. It is for interactive box access, not a hardened bastion.

- **Keys never touch the image.** Without `--ssh-key`, kern generates a throwaway ed25519 keypair in
  the owner-only runtime dir.

- **Needs a group mapping**, because sshd's privilege separation calls `setgroups`, which a single-
  uid user namespace forbids.

- **Honest scope: the forked sshd, and the shells it spawns, run WITHOUT the box's seccomp filter
  and with the pre-drop capability set**, because they are forked before both steps.

- **It logs in as (namespaced) root even with `--user`**, since sshd is forked before the drop.

## Volumes
- **Named volumes** live under `~/.local/share/kern/volumes`.

- **Per-volume quota** is real only when the box runs privileged (ext4-on-loop); otherwise it falls
  back to a plain directory and kern **says the quota is not enforced**, never silently drops it.

- **Network volumes** (`nfs://`, `smb://`, `sshfs://`) mount rootless via FUSE.

## Supervision (`--timeout`, `--health-action`)
The watchdogs run **host-side**, forked **before** the box's `unshare(CLONE_NEWPID)`, the only
position from which they can reliably signal the box's ns-init. An in-box process cannot reach them:
the foreground `--timeout` pipe is `FD_CLOEXEC`, severed at the workload's exec, and the target pid
comes from the trusted `fork()` return or the host-only registry, never from anything the box can
write.

Known, bounded limitation: `--health-action restart` re-reads PID 1 from the registry and `SIGKILL`s
it, and during a restart gap that pid could in principle be reused by another process **of the same
user** before the kill lands. The window is sub-quantum and not attacker-targetable, since an
unprivileged kill only reaches same-uid processes and an in-box workload cannot create host-
namespace processes to steer the reuse. It is not a cross-tenant boundary.

## Check it yourself
The claims above are asserted by five adversarial suites in [pentest/](pentest/), which ask the
kernel what is true rather than asking kern to report on itself: that a published port cannot tunnel
into a host service, that `--ssh` does not hand out the host's shell, that `kern exec` does not
escape the box, that a box cannot raise its own `memory.max` and sees no cgroup above its own, that
a device not granted does not cross, and that a SIGKILLed supervisor does not leave a host port
held.

The fifth is the GPU claim suite, and it is the one that attacks a claim rather than a mechanism: it
reads what `kern doctor` says about each card, then runs T1 to T9 against the host's own driver and
fails if the two disagree.

```sh
sh pentest/pentest-gpu-claims.sh ./target/release/kern
```
```sh
cargo build --release
sh pentest/run-with-local-registry.sh ./target/release/kern pentest/pentest-ports.sh
```
That wrapper serves the test image from your own loopback, so nothing here needs a registry account
or a network. Exit status is 0 only if every asserted property held; a host that cannot answer a
question reports `SKIP` with the reason and never counts it as a pass.

## What's supported
The code on `main` is what's supported; security fixes land there.
