//! Real-syscall sandbox execution (Linux).
//!
//! ONE RULE THAT EVERY FORKED CHILD IN THIS FILE OBEYS, STATED HERE BECAUSE THREE PLACES OBEY IT AND
//! NONE OF THEM SAID IT: **between `fork` and `exec`, nothing may allocate, take a lock, or format a
//! string.** A child of `fork` inherits the address space of a process that may have had other
//! threads, and the allocator's lock can have been copied while another thread held it; that thread
//! does not exist in the child, so it will never release it and the first allocation hangs forever.
//! Diagnostics on those paths are therefore `libc::write(2, …)` over a `const` byte literal, and file
//! reads fill a caller-owned stack buffer instead of building a `String`. The three places are the
//! box-start child's fail-closed refusal, the `kern exec` child, and the OOM reporter; a fourth
//! should read this line rather than rediscover it.
//!
//! [`RealMounts`] performs the mount/pivot/remount ops the [`crate::Rootfs`] typestate issues;
//! [`run_in_sandbox`] sets up an unprivileged user namespace + PID namespace, builds the root
//! through that same typestate, mounts a fresh `/proc`, remounts the root read-only (last -
//! enforced by the typestate), and `exec`s the command. The parent waits and returns the exit
//! code. This is the privileged counterpart of the `Recorder`-driven `--plan`: same sequence,
//! real kernel.
//!
//! Identity mapping: by default the caller's euid maps to root *inside* the namespace and nothing
//! else (a single-uid map - fastest, and the smallest attack surface). With `--uid-range`
//! (`SandboxSpec::uid_range`), and when `newuidmap`/`newgidmap` + an `/etc/subuid`/`/etc/subgid`
//! allocation are present, box ids 1..N additionally map to the caller's subordinate-id range (so
//! `apt`/`dpkg` and daemons that drop to non-root users work). Either way no host privilege is
//! gained. Linux-only.

use crate::{Error, MountMode, MountOps, PortMap, Rootfs};
use std::convert::Infallible;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

/// The one message for "this host won't let an unprivileged user namespace be created" - reused by
/// every unshare site (box + pod) so they can't drift. Callers requiring a `&str` (the pod
/// `eprintln`) use it directly; the sandbox path wraps it in [`Error::Unsupported`].
const USERNS_UNAVAILABLE: &str =
    "unprivileged user namespaces are unavailable (kernel.unprivileged_userns_clone=0 or an AppArmor restriction)";

/// Why a subordinate-uid range is on, which is what decides whether an UNAVAILABLE range is worth a
/// line on stderr. An unmet explicit request must be reported: the caller asked for something they
/// did not get. A per-image default must NOT be, because the fallback single-uid map is exactly what
/// the box did before the default existed, so the warning would fire on every image box on every
/// host without `newuidmap` (all three of our boards) while reporting a request nobody made.
/// `kern doctor` reports the missing helper once, as the environment capability it is.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum UidRange {
    /// Single-uid self-map: only the caller's id exists inside the box.
    #[default]
    Off,
    /// Turned on by kern for an `--image` box, since official images drop privilege in their
    /// entrypoint. Falls back to the single-uid map silently.
    ImageDefault,
    /// Asked for by `--uid-range`, `--ssh`, or a non-root `--user`. An unmet request is reported.
    Requested,
}

impl UidRange {
    /// True when a range should be attempted at all.
    pub fn is_on(self) -> bool {
        self != Self::Off
    }

    /// Wire form for `KERN_POD_UID_RANGE`, read back by the pod holder in the child process.
    pub fn as_env(self) -> &'static str {
        match self {
            Self::Off => "",
            Self::ImageDefault => "default",
            Self::Requested => "requested",
        }
    }

    /// Inverse of [`Self::as_env`]. An unset variable is `Off`; anything else that is not the
    /// literal `default` counts as `Requested`, so a holder from an older kern (which wrote `1`)
    /// keeps its warning rather than losing it.
    pub fn from_env(v: Option<&str>) -> Self {
        match v {
            None | Some("") => Self::Off,
            Some("default") => Self::ImageDefault,
            Some(_) => Self::Requested,
        }
    }
}

/// What to run, and how to provide its root filesystem.
/// One secret to expose at `/run/secrets/<name>` inside the box.
///
/// THE MODE IS PART OF THE SECRET, not a constant, and the two callers need different ones. The
/// Compose Specification is explicit that a service secret defaults to "world-readable permissions
/// (mode `0444`)" and that a `mode:` in the file overrides it; kern wrote every secret 0400 into a
/// 0700 directory, which no workload running as a non-root user can read. MEASURED on Docker's own
/// `nginx-golang-postgres` sample, whose `db` declares `user: postgres`: the entrypoint died with
/// `/run/secrets/db-password: Permission denied` on every start, so the database never came up and
/// the `service_healthy` gate its backend waits on timed out after 120 s.
///
/// `kern box --secret` keeps 0400 when no mode is given: that surface is kern's own, and a default
/// nobody asked to widen stays where it was. The compose driver passes the specification's default
/// explicitly, so the widening is visible at the call site that owes it.
#[derive(Clone, Debug)]
pub struct Secret {
    /// The file name under `/run/secrets`. A single path component, validated by the caller.
    pub name: String,
    /// The secret's bytes, read on the host before the fork.
    pub bytes: Vec<u8>,
    /// The file mode to create it with. The write bit is dropped whatever is asked for, per the
    /// specification: "The writable bit must be ignored if set."
    pub mode: libc::mode_t,
}

pub struct SandboxSpec {
    /// New-root path the box pivots into. For `Overlay` (what the CLI builds) it's the empty
    /// merge point; `Bind`/`Tmpfs` (the `--plan` recorder + tests) name the rootfs directly.
    pub root: String,
    /// How the root is mounted.
    pub mode: MountMode,
    /// `Overlay` only: the read-only lower (image) + writable upper + work dirs.
    pub overlay: Option<OverlayDirs>,
    /// Remount the root read-only after pivot. With an overlay root this remounts the merged
    /// overlay RO (works in a user namespace even where a bind remount-RO is denied, e.g. some
    /// Android-kernel boards). Default boxes leave this false - the upper is the writable surface.
    pub read_only: bool,
    /// `--landlock-rw <path>` (repeatable): apply a Landlock (LSM) write-allowlist. When non-empty the
    /// box root is read+exec only and writes are permitted ONLY under these paths (plus the box scratch
    /// dirs), enforced by the kernel and unliftable by the workload. Empty = no Landlock (namespaces +
    /// seccomp only). FAIL-CLOSED when non-empty: a kernel without Landlock, or a ruleset that cannot
    /// be built or enforced, REFUSES the box rather than degrading to a no-op, so the flag means the
    /// same thing on every host. Leave it empty to run without the LSM.
    pub landlock_rw: Vec<String>,
    /// `--apparmor <profile>`: a pre-loaded AppArmor (LSM) profile the box enters on the coming exec
    /// (Docker's `--security-opt apparmor=`), layering kernel-enforced file/capability confinement over
    /// namespaces + seccomp. `None` = no transition (the box keeps kern's own profile, usually
    /// unconfined). The profile must be loaded on the host (root, once); a missing/unloadable profile
    /// fails the box CLOSED rather than running it unconfined.
    pub apparmor: Option<String>,
    /// argv of the command to run inside the sandbox (must be non-empty).
    pub command: Vec<String>,
    /// Hostname to set inside the (isolated) UTS namespace.
    pub hostname: String,
    /// Host paths bind-mounted into the box (`-v src:dst[:ro]`) - the only way data crosses the
    /// sandbox boundary. Bound before pivot (host source reachable), target resolved symlink-safe.
    pub volumes: Vec<Volume>,
    /// Extra environment for the workload (`--env K=V`), applied on top of the clean base env.
    pub env: Vec<(String, String)>,
    /// Working directory to `chdir` into before exec (`--workdir`). `None` → `/`.
    pub workdir: Option<String>,
    /// Share the host network namespace instead of an isolated (loopback-only) one (`--net`).
    /// Opt-in: gives the box outbound networking at the cost of network isolation.
    pub share_net: bool,
    /// `--ip <addr>` (repeatable): extra IPv4 addresses `lo` answers on inside the box's network
    /// namespace, each as a `/32`.
    ///
    /// EXISTS FOR `ipv4_address:`. A compose file that pins a service to an address under
    /// `networks:` is naming what its peers connect to, and a kern stack has no user-defined subnet
    /// to allocate from, so the literal address existed NOWHERE: a peer that hard-coded it got no
    /// route at all, and kern could only warn. Added by [`add_loopback_alias`] before the capability
    /// drop, because the box itself must not be able to reconfigure its network afterwards.
    ///
    /// NOT A SUBNET AND NOT A ROUTE. Each address is claimed as a `/32` on the loopback, so it
    /// answers inside the namespace and changes nothing about how the box reaches the world.
    pub net_ips: Vec<std::net::Ipv4Addr>,
    /// `--pod <name>`: JOIN this pod holder's user + net namespace instead of creating a fresh one,
    /// so every box in the pod shares one loopback network (they reach each other on `127.0.0.1`,
    /// resolved by name via a shared `/etc/hosts`). The value is the holder process's PID; the box
    /// still gets its own mount/pid/uts/ipc namespaces. Pod members are co-trusted (they share the
    /// pod's user+net ns) - the pod is the network trust unit, like a Kubernetes pod.
    pub pod_holder: Option<i32>,
    /// `--pod-bridge <ip>/<prefix>`: join the pod through its BRIDGE instead of sharing its network
    /// namespace, taking this address on it.
    ///
    /// THE DIFFERENCE IS THE LOOPBACK. Sharing one namespace is what makes a kern stack fast, and it
    /// is also the one thing it does that Docker does not: every service sees the same `127.0.0.1`,
    /// so a port a service binds there is reachable by every peer. On the bridge each member keeps
    /// its own loopback and reaches its peers by address, which is Docker's arrangement, at the cost
    /// of one `veth` per service. The wiring kern had for a private loopback cost a TCP relay per
    /// ORDERED PAIR PER PORT instead: measured on six services, 170-183 ms to bring up against
    /// 247-352 ms, and 56 processes against 122.
    pub pod_bridge: Option<BridgeAttach>,
    /// Map a subordinate uid/gid *range* into the box (`--uid-range`) instead of just the caller.
    /// Opt-in because it (a) costs two `newuidmap`/`newgidmap` subprocesses at start and (b) maps
    /// 65k extra ids into the namespace; the default single-uid map is both faster and more
    /// isolated. Needed only for workloads that use multiple uids inside the box (`apt`/`dpkg`,
    /// daemons that drop to `www-data`, …).
    pub uid_range: UidRange,
    /// Hard memory ceiling in bytes for the box's cgroup (`--memory`). `None` → the default cap.
    pub memory_max: Option<u64>,
    /// `--shm-size` in bytes: an explicit cap for `/dev/shm`. `None` derives one from `memory_max`
    /// (see `shm_size_for`), which is the number the cgroup already enforces.
    pub shm_max: Option<u64>,
    /// Swap allowance in bytes (`--memory-swap-max` → `memory.swap.max`). `None` → `0` (swap off, so
    /// `memory_max` is a hard total). This is the v2 swap limit, NOT a combined mem+swap total.
    pub memory_swap_max: Option<u64>,
    /// CPU pinning list (`--cpuset-cpus`, e.g. `"0-3"` / `"0,2,4"`). `None` → no pinning. Applied via
    /// `sched_setaffinity` (rootless, no cgroup delegation needed) AND, where the `cpuset` controller
    /// is delegated, the cgroup `cpuset.cpus` write for the harder path.
    pub cpuset: Option<String>,
    /// CPU cap in cores (`--cpus`, K8s semantics: 1.5 = 1½ cores). `None` → uncapped. Best-effort:
    /// silently skipped where the cgroup CPU controller isn't delegated (e.g. some Android kernels).
    pub cpus: Option<f64>,
    /// `-it`: a PTY slave fd (opened by the CLI on the host) for the box to use as its controlling
    /// terminal. When set, the box child `setsid`s, makes the slave its controlling tty, and dup2s
    /// it onto stdin/out/err. `None` → the box inherits kern's stdio. The parent pumps the matching
    /// master (see `run_in_sandbox_with`'s `tty_master`).
    pub tty_slave: Option<i32>,
    /// `-it`: the CHILD end of a `socketpair` on which the box hands its own PTY master back to the
    /// CLI. `None` keeps the pre-existing behaviour, where the box uses the host slave in
    /// `tty_slave` and its terminal has no name inside the box. See [`crate::ptybox`].
    pub pty_sock: Option<i32>,
    /// `-it`: the PARENT end of that same `socketpair`, which the CLI reads the box's master from
    /// inside `on_started`. Held here rather than passed separately so the two ends cannot drift
    /// apart: one of them is useless without the other.
    pub pty_sock_parent: Option<i32>,
    /// vGPIO device nodes (host `/dev/*` paths) to expose in the box's `/dev` - from a `vgpio:`
    /// profile. Bound before pivot like the base device allowlist.
    pub vgpio_devs: Vec<String>,
    /// vGPIO sysfs directories (host `/sys/*` paths) to expose in the box's `/sys` (pwm/adc/1-wire/
    /// leds). Bound before pivot.
    pub vgpio_sysfs: Vec<String>,
    /// vDisk profiles to mount at `/vdisk/<name>` in the box (from `vdisk:` profiles).
    pub vdisks: Vec<VdiskMount>,
    /// Secrets to expose as `/run/secrets/<name>` (mode 0400), from `--secret`. The bytes were read
    /// on the host before the fork; the box writes them into a RAM-backed tmpfs so they never touch
    /// the persisted overlay upper and are gone when the box exits.
    pub secrets: Vec<Secret>,
    /// `--ssh`: stand up an in-box `sshd` (authorized to the given public key). `None` → no SSH. The
    /// caller also wires a `-p HOST:22` forwarder; sshd is forked just before the box execs PID 1.
    pub ssh: Option<crate::ssh::SshSetup>,
    /// `--tun`: expose `/dev/net/tun` in the box's `/dev` (WireGuard / userspace VPN). The box owns
    /// its network namespace, so it can create the tunnel; the node is bound like the base allowlist.
    pub tun: bool,
    /// `--init`: run a minimal built-in init (kern itself, no external tini) as box PID 1. It forks the
    /// workload, reaps ALL reparented orphans (no zombies), forwards SIGTERM/SIGINT to the workload, and
    /// exits with its status. Off by default (PID 1 execs the command directly), so the common path is
    /// byte-for-byte unchanged.
    pub init: bool,
    /// `--tmpfs PATH[:opts]`: extra fresh tmpfs mounts inside the box. Blocked over hardened mounts.
    pub tmpfs: Vec<TmpfsMount>,
    /// `--user UID[:GID]`: drop to this uid/gid just before exec (after all privileged setup). `None`
    /// → keep the namespace root. Only ids mapped into the box's userns work (see `--uid-range`).
    pub run_as: Option<(u32, u32)>,
    /// The supplementary groups the workload's user belongs to, resolved by the CALLER from the
    /// image's own `/etc/group` (see `image_supplementary_gids`). Empty means "clear the set", which
    /// is what a box with no image-declared user gets and what an explicit `--user UID:GID` gets.
    ///
    /// RESOLVED OUTSIDE, APPLIED HERE, because the resolution reads a file in the image rootfs and
    /// this code runs after the pivot with no allocation budget and no message path.
    pub extra_gids: Vec<u32>,
    /// `--pids-limit N`: the box's `pids.max` (task ceiling). `None` → the default. Fork-bomb cap.
    pub pids_max: Option<u64>,
    /// `--cap-add`/`--cap-drop` policy on top of the always-dropped dangerous caps. Default drops
    /// exactly the dangerous set.
    pub caps: CapSpec,
    /// cgroup v2 `io.max` lines (`MAJ:MIN riops=… wbps=…`) for a vdisk's `--iops`/`--bandwidth`.
    /// Written into the box's cgroup best-effort (needs the `io` controller delegated).
    pub io_max: Vec<String>,
    /// cgroup v2 `io.weight` (`--io-weight`, 1..=10000): relative I/O priority for the box. `None`
    /// leaves the default. Best-effort like `io_max` (needs the `io` controller delegated).
    pub io_weight: Option<u64>,
    /// `--memory-reservation <size>` → cgroup v2 `memory.low`: a SOFT floor, not a cap. The kernel
    /// reclaims from this box only after it has reclaimed from cgroups that are over their own low
    /// watermark, so it protects a working set under pressure without ever killing anything.
    ///
    /// This is Docker's `mem_reservation`, and the distinction from `--memory` is the whole point of
    /// having both: `memory.max` kills, `memory.low` prioritises. A file that sets only the
    /// reservation asked to be protected, not to be capped.
    pub memory_low: Option<u64>,
    /// `--cpu-weight <n>` (1..=10000) → cgroup v2 `cpu.weight`: RELATIVE share of CPU under
    /// contention, the counterpart of `io_weight` for the cpu controller. Orthogonal to `cpus`, which
    /// is an absolute ceiling: a box may have both a ceiling and a share.
    pub cpu_weight: Option<u64>,
    /// `--add-host NAME:IP`: extra `/etc/hosts` entries appended inside the box (`host-gateway` is
    /// already resolved to a concrete address by the caller). Empty for none.
    pub extra_hosts: Vec<(String, String)>,
    /// `--dns IP` (repeatable): the box's resolvers, written as `nameserver` lines in
    /// `/etc/resolv.conf`. Empty means kern does not touch that file at all, which is the behaviour
    /// every box had before this existed: the image's own file (usually absent, or empty on the
    /// debian family) is left exactly as it is.
    ///
    /// The values are already validated as IP literals by the CLI, so this layer does no parsing.
    pub dns: Vec<String>,
    /// `--dns-search DOMAIN` (repeatable): the `search` line of `/etc/resolv.conf`.
    pub dns_search: Vec<String>,
    /// `--dns-option OPT` (repeatable): the `options` line of `/etc/resolv.conf` (e.g. `ndots:2`).
    pub dns_options: Vec<String>,
    /// `--ulimit NAME=SOFT[:HARD]` (repeatable), resolved to `(RLIMIT_*, soft, hard)` by the CLI so
    /// this layer does no string work. Applied with `setrlimit(2)` before privileges are dropped:
    /// LOWERING a limit always succeeds, RAISING a hard limit needs `CAP_SYS_RESOURCE` in the INIT
    /// user namespace, which a rootless box does not have - so a raise fails loudly rather than
    /// leaving the workload with a silently different limit than it asked for.
    pub ulimits: Vec<(i32, u64, u64)>,
    /// `--sysctl KEY=VALUE` (repeatable). Written to `/proc/sys/<key with '.' → '/'>` AFTER the fresh
    /// procfs is mounted and BEFORE privileges are dropped. Only NAMESPACED knobs are writable (the
    /// box owns its uts/ipc, and its net ns when it has one); a host-global knob is owned by the init
    /// user namespace and the kernel refuses the write - reported as a hard error, never ignored.
    pub sysctls: Vec<(String, String)>,
    /// `--privileged`: relax the always-on seccomp filter to ALLOW the namespace + classic-mount
    /// syscalls (`unshare`/`setns`/`mount`/`umount2`/`pivot_root`) so a *nested* `kern box` (or
    /// docker-in-docker-style workload) can start. Honoured ONLY in rootless mode - when the box's
    /// root maps to an UNPRIVILEGED host uid (caller is non-root), a nested userns grants no new
    /// host privilege (the reason rootless podman-in-podman is safe). As real host root (euid 0) the
    /// request is IGNORED (no relaxation): relaxing `mount` there would re-open the core_pattern /
    /// host-privilege class. Every other dangerous syscall (kexec, modules, bpf, io_uring, keyring,
    /// ptrace, the NEW mount API) stays blocked even here - stronger than Docker's `--privileged`.
    pub privileged: bool,
    /// `--require-limits` (or `KERN_REQUIRE_LIMITS`): make an unenforceable OOM/fork-bomb backstop FATAL
    /// instead of a warning. By default a box on a host that cannot delegate a cgroup runs UNCAPPED with
    /// a loud notice (best-effort is a legitimate configuration). With this set, "the cap binds or the
    /// box does not start": if `apply_limits` cannot put BOTH the memory AND the pids cap (their
    /// read-back-verified defaults included) in force, the box is refused with a non-zero exit. Scope is
    /// deliberately memory + pids (the OOM and fork-bomb backstops): `cpu`/`cpuset` stay best-effort,
    /// exactly as on the systemd-scope path, because they carry no default and no OOM/fork-bomb role -
    /// refusing a box for an unenforceable cpu quota would be a regression versus the scope path, which
    /// only warns. See `apply_limits`'s `require_all` gate.
    ///
    /// Caveat on the EFFECTIVE ceiling: the box's own cgroup is written the exact requested value and
    /// read back, so `--require-limits` proves the cap is IN FORCE, not that it equals the request. A
    /// stricter ancestor (cgroup v2 takes the minimum up the tree) can make the effective ceiling LOWER
    /// than asked - the box still never exceeds what it requested, so the backstop holds; it is just
    /// tighter, never looser.
    ///
    /// Second caveat, on a LYING environment: the guarantee is "written AND read back a non-`max`
    /// value", not "the kernel will OOM-kill". Inside a container that exposes a writable `memory.max`
    /// without actually delegating the controller (the write is accepted and the read-back shows the
    /// value, yet nothing enforces it), the gate passes. Proving real enforcement needs a trial
    /// allocation, too costly for box start. On a genuine host the read-back is the enforcement; a
    /// nested runtime that fakes the interface is out of scope. `kern doctor` (`memory_cap_state`)
    /// write-probes and reports the honest state for that case.
    pub require_limits: bool,
    /// `--allow-uncapped` (or `KERN_ALLOW_UNCAPPED`): explicitly accept running UNCAPPED where a cgroup
    /// cannot be delegated, silencing the best-effort "runs UNCAPPED" notice. For nested CI and known
    /// cgroup-less hosts where the notice is expected noise. It does NOT change whether the box runs
    /// (best-effort already runs) and does NOT silence the outer-enforcer FORGERY warning (a security
    /// signal, not a user preference). Mutually exclusive with `require_limits` (a contradiction).
    pub allow_uncapped: bool,
    /// The seccomp filter this box runs (denylist vs opt-in allowlist), resolved ONCE by the launcher
    /// via [`crate::SeccompFilter::from_env`]. Carried here so PID 1 installs it, and recorded in the
    /// instance registry so `kern exec` reproduces the SAME filter instead of re-reading the
    /// environment - which would let an exec into an allowlist box fall back to the wider denylist.
    pub seccomp_mode: crate::SeccompFilter,
}

/// One `--tmpfs` mount, fully resolved by the CLI so this layer parses nothing.
///
/// A STRUCT AND NOT A `(path, size)` TUPLE any more: the pair carried exactly one setting, so every
/// other option a compose file writes (`mode=`, `noexec`, `ro`) had nowhere to travel and was
/// reported as "recognised but not applied". Widening the tuple would have made the meaning of the
/// second and third element positional, which is how a call site comes to swap them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TmpfsMount {
    /// Absolute, `.`/`..`-free mount point inside the box.
    pub path: String,
    /// tmpfs `size=` value (`"64m"`), or empty for the kernel default (half of RAM).
    pub size: String,
    /// tmpfs `mode=` value (`"1777"`, `"0755"`), or empty for kern's `1777` default.
    pub mode: String,
    /// tmpfs `uid=` value, or empty for the mounting identity.
    ///
    /// APPLIED, WITH A FALL-BACK. A tmpfs in a user namespace accepts only an id that namespace
    /// MAPS: without `--uid-range` a box maps exactly one, so `uid=10001` would make `mount(2)`
    /// fail with `EINVAL` and the box would lose the mount entirely. A file asking for an ownership
    /// kern cannot give must not cost it the directory, so the mount is retried without the two and
    /// the reader is told which happened.
    pub uid: String,
    /// tmpfs `gid=` value, or empty. See [`Self::uid`].
    pub gid: String,
    /// `MS_NOEXEC`: no execution from this mount.
    pub noexec: bool,
    /// `MS_RDONLY`: the mount is read-only.
    pub read_only: bool,
}

/// A resolved vDisk to mount in the box at `/vdisk/<name>`. When `host_dir` is set, the host prepared
/// an ext4-on-loop mount (privileged path) that is bind-mounted in; otherwise a `size=`-capped
/// `tmpfs` is mounted (rootless fallback - RAM-backed, ephemeral).
pub struct VdiskMount {
    pub name: String,
    pub size: Option<u64>,
    pub host_dir: Option<String>,
}

/// overlayfs directories. `lower` is the read-only image; `upper`/`work` are the writable layer.
pub struct OverlayDirs {
    pub lower: String,
    pub upper: String,
    pub work: String,
}

/// A host directory or file bind-mounted into the box.
pub struct Volume {
    /// Absolute host path to expose.
    pub source: String,
    /// Absolute path inside the box where it appears.
    pub target: String,
    /// Mount it read-only (`:ro`).
    pub read_only: bool,
}

/// A [`MountOps`] that performs the real Linux mount syscalls.
pub struct RealMounts;

/// `mkdir -p` for a path INSIDE the box: walk the separators and `mkdir` each prefix, ignoring an
/// already-exists. libc and a stack buffer, no heap and no panic, because this runs in the child
/// between `fork` and `exec` where an allocation is a hazard.
///
/// Best-effort ON PURPOSE. It reports nothing: the caller's `chdir` is the check that decides, and it
/// names the real reason (a read-only root, a permission denial, a component that is a file). Bounded
/// by `PATH_MAX`; a longer path is left untouched so the `chdir` fails and says so, rather than a
/// truncated `mkdir` silently creating a directory nobody asked for.
fn mkdir_p(path: &str) {
    const MAX: usize = 4096;
    let b = path.as_bytes();
    if b.is_empty() || b.len() >= MAX {
        return;
    }
    let mut buf = [0u8; MAX];
    buf[..b.len()].copy_from_slice(b);
    // Each separator terminates a parent that has to exist first; index 0 is skipped so a leading
    // `/` is not mistaken for an empty path.
    for i in 1..b.len() {
        if b[i] == b'/' {
            buf[i] = 0;
            // SAFETY: `buf` is NUL-terminated at `i` and outlives the call; `mkdir` only reads it.
            unsafe { libc::mkdir(buf.as_ptr().cast(), 0o755) };
            buf[i] = b'/';
        }
    }
    buf[b.len()] = 0;
    // SAFETY: same as above, terminated at `b.len()`, which the length guard keeps in bounds.
    unsafe { libc::mkdir(buf.as_ptr().cast(), 0o755) };
}

fn cstr(s: &str) -> Result<CString, Error> {
    CString::new(s).map_err(|_| {
        Error::Syscall(
            "cstring",
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL byte in path"),
        )
    })
}

impl MountOps for RealMounts {
    fn mount(&mut self, _src: &str, dst: &str, _fstype: &str, flags: u64) -> Result<(), Error> {
        let dst_c = cstr(dst)?;
        // For the bind root we mount the directory onto itself so it becomes a mount point
        // (pivot_root requires the new root to be one). Other fstypes mount a fresh filesystem.
        // Deliberately NON-recursive (`MS_BIND`, not `MS_BIND | MS_REC`): if the operator's
        // `--rootfs` dir has host filesystems mounted *underneath* it (a NAS share, an external
        // disk, a stray `/proc`), a recursive bind would clone those submounts into the box and
        // leak them. A plain bind exposes the directory tree only; submounts are left behind.
        let r = if flags & crate::MS_BIND != 0 {
            unsafe {
                libc::mount(
                    dst_c.as_ptr(),
                    dst_c.as_ptr(),
                    ptr::null(),
                    libc::MS_BIND as libc::c_ulong,
                    ptr::null(),
                )
            }
        } else {
            let fs_c = cstr(_fstype)?;
            unsafe {
                libc::mount(
                    fs_c.as_ptr(),
                    dst_c.as_ptr(),
                    fs_c.as_ptr(),
                    flags as libc::c_ulong,
                    ptr::null(),
                )
            }
        };
        if r != 0 {
            return Err(Error::last("mount"));
        }
        Ok(())
    }

    fn pivot(&mut self, new_root: &str, _old_root: &str) -> Result<(), Error> {
        // Self-pivot (runc-style): chdir into the new root, then `pivot_root(".", ".")`, which
        // stacks the old root *on top of* the new root at "/". This needs NO put_old subdirectory,
        // so we never `mkdir`/`rmdir` a `.old_root` inside the rootfs. That matters because a
        // a shared read-only lower (several boxes off one rootfs/image) would otherwise race on
        // creating/removing `.old_root` in it (and it fails outright on a read-only source).
        // `_old_root` is unused by the syscall but kept in the recorded plan for readability.
        let new_c = cstr(new_root)?;
        if unsafe { libc::chdir(new_c.as_ptr()) } != 0 {
            return Err(Error::last("chdir(new_root)"));
        }
        let dot = cstr(".")?;
        let r = unsafe { libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), dot.as_ptr()) };
        if r != 0 {
            return Err(Error::last("pivot_root"));
        }
        Ok(())
    }

    fn remount_ro(&mut self, target: &str) -> Result<(), Error> {
        let t = cstr(target)?;
        let r = unsafe {
            libc::mount(
                ptr::null(),
                t.as_ptr(),
                ptr::null(),
                (libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY) as libc::c_ulong,
                ptr::null(),
            )
        };
        if r != 0 {
            return Err(Error::last("remount_ro"));
        }
        Ok(())
    }
}

/// Make every mount in this namespace private, so our changes don't propagate to the host.
fn make_private() -> Result<(), Error> {
    let root = cstr("/")?;
    let r = unsafe {
        libc::mount(
            ptr::null(),
            root.as_ptr(),
            ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            ptr::null(),
        )
    };
    if r != 0 {
        return Err(Error::last("mount(MS_PRIVATE)"));
    }
    Ok(())
}

/// Mount an overlayfs at `merged` (read-only `lower` image + writable `upper`/`work`). The
/// kernel holds references to the dirs, so the box's root stays writable; changes land in
/// `upper` and the image is untouched.
fn mount_overlay(lower: &str, upper: &str, work: &str, merged: &str) -> Result<(), Error> {
    let ty = cstr("overlay")?;
    let merged_c = cstr(merged)?;
    let opts = cstr(&format!("lowerdir={lower},upperdir={upper},workdir={work}"))?;
    // `NODEV|NOSUID` on the box root: a device node on the rootfs is inert and a setuid binary can't
    // elevate. Both are already assured (userns superblocks are `SB_I_NODEV`; the workload runs under
    // `NO_NEW_PRIVS` + the bounding-set cap drop), so this is defense-in-depth that doesn't rely on
    // that implicit kernel behaviour. Device nodes the box legitimately uses live on the separate
    // `/dev` tmpfs, not here.
    let hardening = (libc::MS_NODEV | libc::MS_NOSUID) as libc::c_ulong;
    let r = unsafe {
        libc::mount(
            ty.as_ptr(),
            merged_c.as_ptr(),
            ty.as_ptr(),
            hardening,
            opts.as_ptr() as *const libc::c_void,
        )
    };
    if r != 0 {
        let e = std::io::Error::last_os_error();
        // kern inside a Docker/Podman container: the scratch dir (default `/run/user/<uid>` or
        // `/tmp`) sits on the CONTAINER's overlayfs rootfs, and the kernel refuses an overlayfs
        // upperdir that itself lives on overlayfs with a bare EINVAL ("not supported as upperdir"
        // only in dmesg). Turn that into an actionable message instead of "Invalid argument".
        if e.raw_os_error() == Some(libc::EINVAL) && fs_is_overlayfs(upper) {
            return Err(Error::Unsupported(
                "mount(overlay): the box scratch dir is on an overlayfs filesystem - the kernel \
                 rejects nested-overlay upperdirs (typical when kern runs INSIDE a Docker/CI \
                 container). Point XDG_RUNTIME_DIR at a tmpfs/disk path, or in Docker add \
                 `--tmpfs /run`",
            ));
        }
        return Err(Error::Syscall("mount(overlay)", e));
    }
    Ok(())
}

/// Whether `path` (or its deepest existing ancestor) lives on an overlayfs - the one filesystem the
/// kernel refuses as an overlay UPPER layer. Used only to turn a bare `EINVAL` into a clear error.
fn fs_is_overlayfs(path: &str) -> bool {
    const OVERLAYFS_SUPER_MAGIC: i64 = 0x794c7630;
    let mut p = std::path::Path::new(path);
    loop {
        if let Ok(c) = cstr(&p.to_string_lossy()) {
            let mut st: libc::statfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::statfs(c.as_ptr(), &mut st) } == 0 {
                return st.f_type as i64 == OVERLAYFS_SUPER_MAGIC;
            }
        }
        match p.parent() {
            Some(parent) => p = parent,
            None => return false,
        }
    }
}

/// Mount a fresh procfs for the new PID namespace (so `ps` etc. see only sandbox processes).
/// Target is the **cwd-relative** `proc` (cwd is the new root right after the self-pivot), NOT
/// `/proc`: before the old root is detached, "/" still resolves through the stacked old root, so
/// an absolute target would land in the old root. It must also run BEFORE the detach - mounting a
/// fresh procfs requires an existing fully-visible proc instance, which the old root still
/// provides; after `MNT_DETACH` that instance is gone and the mount is refused (EPERM).
fn mount_proc() -> Result<(), Error> {
    let proc_dir = cstr("proc")?;
    unsafe { libc::mkdir(proc_dir.as_ptr(), 0o555) }; // best-effort if the rootfs lacks /proc
    let fstype = cstr("proc")?;
    let r = unsafe {
        libc::mount(
            fstype.as_ptr(),
            proc_dir.as_ptr(),
            fstype.as_ptr(),
            0,
            ptr::null(),
        )
    };
    if r != 0 {
        return Err(Error::last("mount(proc)"));
    }
    Ok(())
}

/// Read-only bind a procfs path onto itself: writes fail (EROFS) but reads still work. Used to lock
/// down the host-global, NON-namespaced knobs under `/proc` that a container must never write.
fn ro_bind_ro(path: &str) -> Result<(), Error> {
    let c = cstr(path)?;
    if unsafe {
        libc::mount(
            c.as_ptr(),
            c.as_ptr(),
            ptr::null(),
            libc::MS_BIND,
            ptr::null(),
        )
    } != 0
    {
        return Err(Error::last("mount(bind proc)"));
    }
    if unsafe {
        libc::mount(
            ptr::null(),
            c.as_ptr(),
            ptr::null(),
            libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY,
            ptr::null(),
        )
    } != 0
    {
        return Err(Error::last("remount(ro proc)"));
    }
    Ok(())
}

/// Mask a procfs file by bind-mounting `/dev/null` over it - reads return empty, writes go nowhere.
/// Used for kernel-memory / info-leak files (`/proc/kcore`, `/proc/kallsyms`, …).
fn null_over(path: &str) -> Result<(), Error> {
    let src = cstr("/dev/null")?;
    let dst = cstr(path)?;
    if unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            ptr::null(),
            libc::MS_BIND,
            ptr::null(),
        )
    } != 0
    {
        return Err(Error::last("mount(mask proc)"));
    }
    Ok(())
}

/// Mount the box's OWN cgroup v2 hierarchy READ-ONLY at `/sys/fs/cgroup`, exactly like Docker/runc
/// (`cgroupns=private` + a `cgroup2` mount). Combined with the `CLONE_NEWCGROUP` the child unshared,
/// the box sees ONLY its own cgroup as the root of the hierarchy: memory-aware runtimes (the JVM,
/// .NET, Node) then read the real `memory.max` and size their heap to the cap instead of the host's
/// RAM, while the host tree and sibling boxes stay invisible.
///
/// `MS_RDONLY` is load-bearing security, not cosmetic: the box may READ its limits but can never write
/// `cgroup.procs` (no self-migration out of the cap) or edit a `*.max` file, so exposing the cgroup
/// buys the runtimes correctness without handing the workload a lever on its own limits. `NOSUID`,
/// `NODEV`, `NOEXEC` harden the mount. Only `/sys/fs/cgroup` is mounted - the rest of `/sys` is left
/// absent, so the host sysfs stays masked (kern's deny-by-default `/sys` property is unchanged).
///
/// Best-effort throughout: a kernel without cgroup namespaces, a host that refuses the `cgroup2` mount,
/// or a `--privileged` nested box where `mount_too_revealing` bites, simply leaves the box without a
/// cgroup view (kern's prior behaviour) - it never fails the box.
fn mount_cgroup() {
    // Create the mountpoint on the (still-writable) box root WITHOUT mounting a full sysfs, so `/sys`
    // otherwise stays empty and the host sysfs is never revealed. Neutralize a hostile image symlink at
    // `/sys/fs/cgroup` first (same guard as `/dev`), so the mount can't be redirected elsewhere.
    for d in ["/sys", "/sys/fs", "/sys/fs/cgroup"] {
        if let Ok(c) = cstr(d) {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::lstat(c.as_ptr(), &mut st) } == 0
                && (st.st_mode & libc::S_IFMT) == libc::S_IFLNK
            {
                unsafe { libc::unlink(c.as_ptr()) };
            }
            unsafe { libc::mkdir(c.as_ptr(), 0o755) };
        }
    }
    if let (Ok(ty), Ok(tgt)) = (cstr("cgroup2"), cstr("/sys/fs/cgroup")) {
        unsafe {
            libc::mount(
                ty.as_ptr(),
                tgt.as_ptr(),
                ty.as_ptr(),
                (libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC)
                    as libc::c_ulong,
                ptr::null(),
            );
        }
    }
}

/// Neutralize the host-global procfs surface - the runc "readonlyPaths" + "maskedPaths" set. These
/// files/dirs are NOT namespaced, so on a kernel where the box's root maps to a privileged host uid
/// (kern run as root, in WSL, under `sudo`, or in CI), an in-box write reaches the HOST. The escape
/// that motivated this: `/proc/sys/kernel/core_pattern` → set it to `|/evil` and the kernel runs your
/// program as ROOT on the host at the next core dump. `/proc/sys` read-only is therefore the HARD
/// requirement (fail-closed); the rest are best-effort (present on all mainstream kernels).
fn mask_proc_paths() -> Result<(), Error> {
    ro_bind_ro("/proc/sys")?; // core_pattern, kernel.modprobe, … - every host-global sysctl. FATAL.
    for p in [
        "/proc/sysrq-trigger",
        "/proc/irq",
        "/proc/bus",
        "/proc/fs",
        "/proc/asound",
    ] {
        let _ = ro_bind_ro(p);
    }
    for p in [
        "/proc/kcore",
        "/proc/kallsyms",
        "/proc/kmsg",
        "/proc/keys",
        "/proc/latency_stats",
        "/proc/timer_list",
        "/proc/sched_debug",
        "/proc/scsi",
    ] {
        let _ = null_over(p);
    }
    Ok(())
}

/// Detach the old root, which the self-pivot left stacked at "." (== the new root's "/"). Must run
/// IMMEDIATELY after the pivot, before any absolute-path mount: until the old root is detached,
/// "/" resolves through it. Resolution of "." starts at the new root and moves up the stack, so
/// this unmounts the old (host) root. A failed unmount is FATAL - a leftover old root would keep
/// the whole host filesystem visible inside the box.
fn detach_old_root() -> Result<(), Error> {
    let dot = cstr(".")?;
    if unsafe { libc::umount2(dot.as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err(Error::last("umount2(old_root)"));
    }
    // Anchor at the now-clean new root.
    let root = cstr("/")?;
    if unsafe { libc::chdir(root.as_ptr()) } != 0 {
        return Err(Error::last("chdir(/)"));
    }
    Ok(())
}

/// `exec` the command, replacing this process. Returns only on failure.
/// Transition the NEXT `exec()` of this process into a pre-loaded AppArmor profile (`--apparmor`).
/// Writes `exec <profile>` to `/proc/self/attr/apparmor/exec` (older kernels: `/proc/self/attr/exec`),
/// the exact interface `aa_change_onexec()` uses; the profile applies when `execvp` runs. FAIL-CLOSED:
/// a profile that is not loaded (or AppArmor disabled) returns `Err`, and the caller refuses to exec the
/// workload rather than run it unconfined - kern never silently drops a confinement the user asked for.
/// The profile must be loaded on the host (root, once), exactly like Docker's `--security-opt apparmor=`.
fn apply_apparmor_onexec(profile: &str) -> Result<(), Error> {
    use std::io::Write;
    let payload = format!("exec {profile}");
    let mut last = String::from("no AppArmor interface (/proc/self/attr/apparmor/exec)");
    for path in ["/proc/self/attr/apparmor/exec", "/proc/self/attr/exec"] {
        match std::fs::OpenOptions::new().write(true).open(path) {
            Ok(mut f) => {
                return f.write_all(payload.as_bytes()).map_err(|e| {
                    Error::Spec(format!(
                        "--apparmor {profile}: could not enter the profile (is it loaded on the host? \
                         `sudo apparmor_parser -r <profile>`): {e}"
                    ))
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => last = format!("cannot open {path}: {e}"),
        }
    }
    Err(Error::Spec(format!(
        "--apparmor {profile}: {last} - AppArmor is not available on this kernel"
    )))
}

/// The pre-exec gate descriptor, passed by the launcher in `KERN_GATE_FD`.
///
/// 🔴 RESOLVE THIS BEFORE `set_clean_env`, AND NEVER AFTER. `set_clean_env` calls `clearenv()` to
/// wipe the inherited host environment before the workload runs - its own docstring names "kern
/// internals like `KERN_SCOPE`" as things it deliberately removes, and `KERN_GATE_FD` is one of
/// those. Read at the gate itself (line ~760, long past the wipe at ~1055) it answered `None` on
/// every box, so the gate never engaged and the workload ran while the peer network was still being
/// built. MEASURED: `DBG child: gate_fd=None env=Err(NotPresent)` in the box log while the launcher
/// had just printed `fd=3`. The value is therefore captured at the top of `child_setup_and_exec` and
/// threaded down as an argument, which also makes the dependency visible in the signature instead of
/// hidden in an environment read.
///
/// An ENVIRONMENT VARIABLE and not a fixed number, because the box's setup opens and closes
/// descriptors and a hard-coded fd would collide with whatever landed there. The launcher creates the
/// pipe, marks the WRITE end `CLOEXEC` so no other child of the launcher (the health checker, a relay
/// half, the timeout watchdog) can hold it open and keep the gate from closing on launcher death, and
/// passes the READ end's number here.
///
/// `None` when unset, unparseable or negative: a box with no gate execs immediately, which is every
/// path that does not go through a multi-box bring-up. Parsing failure reads as "no gate" rather than
/// as an error, because a box that cannot find its gate must not hang forever waiting on a descriptor
/// nobody holds - the failure direction is toward running, and the launcher that set the variable is
/// the one that would have released it anyway.
fn gate_fd() -> Option<libc::c_int> {
    let raw = std::env::var("KERN_GATE_FD").ok()?;
    let fd: libc::c_int = raw.trim().parse().ok()?;
    (fd >= 0).then_some(fd)
}

/// The byte a gated box writes on the readiness pipe once it is fully set up and about to wait.
///
/// A DISTINCT VALUE and not "any byte", because the pipe already carries a meaning per shape: EOF is
/// "the workload exec'd" and a byte was "setup failed" (`b"x"`). A third state needs a third symbol,
/// not an overload of the second, or a launcher would report a prepared box as a failed one.
pub const READY_PREPARED: u8 = b'P';

fn exec(argv: &[CString], ready_fd: Option<libc::c_int>, gate: Option<libc::c_int>) -> Error {
    // FAIL-CLOSED setup-window choke point (TOCTOU): every workload exec funnels through here, and here
    // refuses to hand control over unless a seccomp filter is provably in force in THIS process. All
    // real paths install it just above their exec (`child_setup_and_exec`, the built-in init's workload
    // child, and the `kern exec` path). This catches a FUTURE exec added through indirection or aliasing
    // that the lexical `no_untrusted_exec_before_the_seccomp_filter` source guard - one stack frame -
    // cannot see. One `Acquire` load on a path that already forks+execs is free; the cost of being wrong
    // is a workload running unfiltered. Panic-free: it returns fail-closed, the caller reports and exits.
    if !crate::seccomp::is_installed() {
        return Error::Unsupported(
            "refusing to exec the workload: no seccomp filter is installed in this process \
             (setup-window guard)",
        );
    }
    // THE PRE-EXEC GATE, AND IT IS THE LAST THING BEFORE `execvp` ON PURPOSE.
    //
    // WHAT IT BUYS. A compose stack under `--no-pod` builds its peer relays only once every box has
    // a PID 1, because a relay binds inside one box's namespace and forwards into another's. The
    // workload therefore used to run BEFORE the network it was written against existed, and two
    // independent failures followed, both measured: a service that connects at t=0 and does not
    // retry (Quarkus, and every client written against Docker, where the network is up before the
    // process is) got ECONNREFUSED and died; and a stack whose `depends_on: condition:
    // service_healthy` gate blocked `up` never reached the relay block at all, so the relay it was
    // waiting for was never built. Deadlock by construction, not a race.
    //
    // With the gate, box setup runs to completion and stops here. The launcher builds every relay
    // against namespaces that exist but hold no workload, then releases. No workload ever observes a
    // partially built network. That is the invariant, and it is the only reason this costs anything.
    //
    // WHY HERE AND NOT EARLIER. Above this line the process is already fully confined: root pivoted,
    // capabilities dropped, Landlock attached, seccomp installed and PROVEN installed by the check
    // immediately above. A gated box is therefore a fully-confined PID 1 blocked in one `read`, and
    // release is one `execvp`. Gating earlier would park a process in a weaker posture and call it
    // prepared. `read` and `execvp` are in every allowlist this project ships, so the gate cannot be
    // the thing a filter refuses.
    //
    // THE CHILD CANNOT REPORT ITS OWN DEATH HERE. It has a pivoted root and no path to a host file,
    // so a box that is never released leaves its record through the supervisor, which sees the exit
    // and knows the release never happened. Nothing is written from this side.
    //
    // EOF IS REFUSAL, NOT RELEASE, AND THE DIRECTION IS THE WHOLE POINT.
    //
    // The launcher closing its write end without sending a byte means it died, or it decided the
    // stack cannot come up (a relay that could not be built for a plan or namespace reason). In both
    // cases the network this workload was gated on does not exist and never will. Releasing on EOF
    // would start every prepared box of a stack that just failed to build its edges, which is the
    // silent partial state this gate exists to make impossible. PDEATHSIG does not cover it either:
    // under compose the box's parent is the `kern box` launcher, which detaches, not the `up` process
    // that owns the gate.
    //
    // So: one byte = release, anything else = refuse and let the caller report it. `EINTR` is retried
    // because a signal arriving mid-wait is not an answer. A read error other than `EINTR` is treated
    // as EOF for the same reason it is refused: the channel that was going to carry the release is
    // gone.
    //
    // NO TIMEOUT. The gate waits for an event, not for a duration. A launcher that is alive and
    // wedged leaves a box visible as prepared, which `kern stop` can end; a duration here would
    // reintroduce exactly the arbitrary wait this design removes.
    if let Some(fd) = gate {
        // ANNOUNCE PREPARED BEFORE BLOCKING, or the launcher waits for an exec that waits for the
        // launcher. `kern box -d` returns when the readiness pipe reaches EOF, and EOF means the
        // workload exec'd; under the gate the workload cannot exec until the launcher releases it,
        // so the two waits close a cycle: compose waits for the launcher, the launcher waits for the
        // exec, the exec waits for the gate, the gate is written by compose. MEASURED as a four-way
        // wait that hung two runs in three.
        //
        // The byte is written to the READINESS pipe, not to the gate pipe, because the launcher is
        // already blocked reading that one. EOF keeps its meaning for every ungated box, and the
        // failure byte keeps its meaning for both, so nothing that exists today changes.
        if let Some(rfd) = ready_fd {
            let b = [READY_PREPARED];
            loop {
                // SAFETY: one byte from a live local buffer to a descriptor this process inherited.
                let n = unsafe { libc::write(rfd, b.as_ptr().cast::<libc::c_void>(), 1) };
                if n == 1 {
                    break;
                }
                // SAFETY: `__errno_location` is always valid for the calling thread.
                let err = unsafe { *libc::__errno_location() };
                if err != libc::EINTR {
                    // The launcher is gone. The gate below will read EOF and refuse, which is the
                    // same outcome, so there is nothing to report from here.
                    break;
                }
            }
        }
        let mut byte = [0u8; 1];
        let released = loop {
            // SAFETY: `fd` is a raw descriptor this process inherited and owns for the duration of
            // this call; the buffer is a live local of exactly the length passed.
            let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast::<libc::c_void>(), 1) };
            if n == 1 {
                break true;
            }
            if n == 0 {
                break false;
            }
            // SAFETY: `__errno_location` is always valid for the calling thread.
            let err = unsafe { *libc::__errno_location() };
            if err != libc::EINTR {
                break false;
            }
        };
        // SAFETY: closing a descriptor this process owns, exactly once.
        unsafe { libc::close(fd) };
        // NOTHING TO REMOVE FROM THE ENVIRONMENT HERE: `set_clean_env` wiped the whole inherited
        // environment hundreds of lines above, `KERN_GATE_FD` with it, so the workload never sees the
        // name and never sees a number that is no longer open. That wipe is also why this descriptor
        // arrives as an argument rather than as an environment read.
        if !released {
            return Error::Unsupported(
                "never released: the launcher closed the pre-exec gate without releasing this box \
                 (the stack failed to build its peer network, or `up` died) - the workload did not run",
            );
        }
    }
    let mut ptrs: Vec<*const c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(ptr::null());
    unsafe { libc::execvp(ptrs[0], ptrs.as_ptr()) };
    Error::last("execvp")
}

/// Child path (PID 1 in the new PID namespace): own mount namespace, build the root through the
/// typestate, mount /proc, drop the old root, remount read-only LAST, then exec. Never returns
/// Per-phase wall-clock for box setup, gated on the `KERN_TIMING` env var (off → zero cost beyond
/// one `getenv`). Set `KERN_TIMING=1` to print `kern-timing: <phase>: <µs>` to stderr - a cheap
/// profiler for where startup goes on a given kernel/SoC (overlay vs dev binds vs seccomp).
pub struct PhaseTimer {
    on: bool,
    last: libc::timespec,
}

impl Default for PhaseTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl PhaseTimer {
    pub fn new() -> Self {
        let on = crate::cgroup::env_flag("KERN_TIMING");
        let mut last = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if on {
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut last) };
        }
        Self { on, last }
    }

    pub fn mark(&mut self, label: &str) {
        if !self.on {
            return;
        }
        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
        let us =
            (now.tv_sec - self.last.tv_sec) * 1_000_000 + (now.tv_nsec - self.last.tv_nsec) / 1000;
        eprintln!("kern-timing: {label}: {us} us");
        self.last = now;
    }
}

/// `Ok` - on success `exec` (or the built-in init) replaces/owns the process; otherwise it returns the
/// error. `ready_fd` (the readiness pipe's write end) is threaded through so that with `--init`, PID 1
/// can close its own copy after forking the workload (so the launcher still gets EOF = "box up"), and
/// the forked workload can write the failure byte if its own exec fails.
/// Whether the box's root (inner uid 0) maps to an UNPRIVILEGED host uid, read from the now-established
/// `/proc/self/uid_map`. This is the PROPERTY that `--privileged` nesting depends on - a box whose root
/// maps to host root must never get the relaxed seccomp (a relaxed `mount` there re-opens the host). We
/// read the map rather than trust the caller's euid because `--pod` joins a holder's user namespace, so
/// the mapping is the holder's, not a function of our euid. Each map line is `inside outside count`;
/// the entry covering inside-uid 0 tells us the host uid box-root becomes. Fails CLOSED: if the map is
/// unreadable, malformed, or has no entry for inside-0, return `false` (treat as privileged, don't relax).
fn box_root_is_unprivileged() -> bool {
    match std::fs::read_to_string("/proc/self/uid_map") {
        Ok(m) => uid_map_root_is_unprivileged(&m),
        Err(_) => false, // can't read the map → cannot confirm → fail closed
    }
}

/// Pure parser behind [`box_root_is_unprivileged`] (unit-testable). Given the contents of a
/// `uid_map` (`inside outside count` per line), return `true` IFF the entry covering inside-uid 0
/// maps it to a NON-zero (unprivileged) host uid. Fails CLOSED (`false`) if inside-0 is unmapped or
/// no line is well-formed - so `--privileged` never relaxes seccomp on a map it doesn't understand.
fn uid_map_root_is_unprivileged(map: &str) -> bool {
    for line in map.lines() {
        let f: Vec<u64> = line
            .split_whitespace()
            .filter_map(|t| t.parse().ok())
            .collect();
        if let [inside, outside, count] = f[..] {
            if inside == 0 && count >= 1 {
                // `outside` is an id in the PARENT user namespace, not guaranteed a host uid. That's
                // safe here: only real root can construct a userns mapping any id to host uid 0, and
                // real root is refused `--privileged` up front - so a non-root caller can never reach
                // a chain where inner-0 resolves to host root. We also fail toward OVER-refusal (a
                // one-level-deep `0 0 1` is refused, never wrongly allowed).
                return outside != 0;
            }
        }
    }
    false
}

fn child_setup_and_exec(
    spec: &SandboxSpec,
    argv: &[CString],
    ready_fd: Option<i32>,
    allow_nesting: bool,
) -> Result<Infallible, Error> {
    // FIRST STATEMENT, AND THE POSITION IS THE POINT: `set_clean_env` below calls `clearenv()`, so
    // every environment read after it answers `None` for a kern-internal name. See `gate_fd`.
    let gate = gate_fd();
    let mut t = PhaseTimer::new();
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        // NAME THE CAUSE, NOT THE SYSCALL. Reaching here without the capability to unshare a mount
        // namespace means this process sits in a user namespace whose id map was never applied: the
        // namespace was granted and the map refused, which is precisely what Ubuntu 23.10+ ships by
        // default (`kernel.apparmor_restrict_unprivileged_userns=1`).
        //
        // MEASURED on a stock Ubuntu 24.04.4 cloud image: `kern box t1 --image alpine -- echo ok`
        // printed `unshare(CLONE_NEWNS) failed: Operation not permitted` and a hint that named four
        // possible causes and told the reader to run `kern doctor`. `doctor` then diagnosed it
        // exactly and handed over the two remedies. The information existed the whole time, one
        // sysctl read away, and was not at the place where the reader was standing. That is the
        // first command in the README, on the distribution most readers run.
        if std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .is_ok_and(|v| v.trim() == "1")
        {
            return Err(Error::Unsupported(
                "unprivileged user namespaces are restricted here - this host allows the namespace \
                 and refuses its rootless uid map (Ubuntu 23.10+ ships \
                 kernel.apparmor_restrict_unprivileged_userns=1), so no box can start. \
                 `kern doctor` prints the AppArmor profile to install; \
                 `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` lifts it for the \
                 whole machine until reboot",
            ));
        }
        return Err(Error::last("unshare(CLONE_NEWNS)"));
    }
    // Own cgroup namespace: make the box's OWN cgroup the root of the `cgroup2` hierarchy it mounts
    // below (see `mount_cgroup`), so memory-aware runtimes (the JVM, .NET, Node) read the real
    // `memory.max` and size their heap to the cap instead of the host's RAM - without it they assume
    // host RAM and get OOM-killed under load despite the cap - while the host tree and sibling boxes
    // stay invisible. The process is already IN its box cgroup here (the supervisor moved into it via
    // `apply_limits` before the fork), so the namespace root is exactly that cgroup. Best-effort: a
    // kernel without cgroup namespaces just leaves the box without a cgroup view (prior behaviour).
    // SECURITY: capture whether the unshare succeeded. If it FAILED (no cgroupns), we must NOT mount a
    // fresh `cgroup2` below: without our own cgroup-ns root it would expose the WHOLE host cgroup tree
    // (every sibling box + systemd unit) read-only. Gate the mount on this.
    let cgroupns_ok = unsafe { libc::unshare(libc::CLONE_NEWCGROUP) } == 0;
    set_hostname(&spec.hostname);
    make_private()?;
    t.mark("unshare+private");

    let mut ops = RealMounts;
    // Build the new root (typestate). Overlay sets up the merge directly; bind/tmpfs go through
    // the recordable seam.
    let mounted = match spec.mode {
        MountMode::Overlay => {
            let o = spec
                .overlay
                .as_ref()
                .ok_or(Error::Unsupported("overlay mode without overlay dirs"))?;
            mount_overlay(&o.lower, &o.upper, &o.work, &spec.root)?;
            Rootfs::premounted(&spec.root)
        }
        MountMode::Bind | MountMode::Tmpfs => Rootfs::mount(&mut ops, spec.mode, &spec.root)?,
    };
    t.mark("rootfs(overlay)");
    // Set up `<root>/dev` and bind `-v` volumes BEFORE pivot, while the host source paths are
    // reachable. Device nodes must be bound by real host path to stay writable from the user
    // namespace; volume targets are resolved symlink-safely, confined to the new root.
    // devpts is mounted in EVERY box, not only where kern itself needs a PTY (`--ssh`, `-it`).
    //
    // It used to be gated on `spec.ssh.is_some() || spec.tty_slave.is_some()`, to save one
    // mount+mkdir+symlink per box, under the reasoning that "the overwhelming common case (agent
    // code-exec, CI, `sh -c`) never opens a PTY". That reasoning confuses two different questions:
    // whether the BOX's own stdio is a terminal, and whether a process INSIDE the box may allocate
    // one. `-i`/`-t` answer the first; devpts answers the second, and docker mounts it in every
    // container for exactly that reason.
    //
    // The gap it left is not exotic. Reported as #8 by a user running Paseo, an agent daemon whose
    // terminal manager calls `forkpty(3)`: the call failed with "out of pty devices" in a detached
    // box while succeeding under `-it`, so a whole class of workloads (agent runners, web terminals,
    // anything spawning `script`/`tmux`/an sshd of its own) could not run. Measured on x86_64 before
    // this change, so it was never about the reporter's aarch64 host.
    //
    // The saving was real but small, and it bought a wrong answer. `--tmpfs /dev/pts` stays refused:
    // a caller must not be able to shadow the hardened `/dev`, so kern owns this mount rather than
    // leaving users to improvise one.
    let needs_pts = true;
    // THE BOX'S OWN SLAVE WINS WHEN THERE IS ONE. `spec.tty_slave` is the host pty the CLI opened
    // before the fork; it works, but its device does not exist under the box's `/dev`, so
    // `ttyname()` cannot name it and `tty(1)` prints "not a tty" on every musl image. When
    // `setup_dev` managed to build a pair from the box's own devpts and hand the master back, that
    // one is used instead and the terminal has a name. See [`crate::ptybox`].
    let box_slave = setup_dev(
        &spec.root,
        spec.tun,
        needs_pts,
        spec.tty_slave,
        shm_size_for(spec.shm_max, spec.memory_max),
        spec.pty_sock,
    )?;
    // The host slave is now dead weight in this process: the workload is about to get the box's
    // one. Closing it here rather than leaking it into the exec keeps the box from holding an fd on
    // a terminal it does not use, which `/proc/1/fd` would otherwise show.
    if box_slave.is_some() {
        if let Some(host) = spec.tty_slave {
            unsafe { libc::close(host) };
        }
    }
    // Whichever way it went, this process is done with the channel.
    if let Some(sock) = spec.pty_sock {
        unsafe { libc::close(sock) };
    }
    setup_vgpio(&spec.root, &spec.vgpio_devs, &spec.vgpio_sysfs)?;
    t.mark("dev");
    setup_volumes(&spec.root, &spec.volumes)?;
    setup_vdisk(&spec.root, &spec.vdisks)?;
    setup_tmpfs(&spec.root, &spec.tmpfs)?;
    // `--ssh` needs a box-owned tmpfs over ALL of `/run` (so `/run/sshd` is namespace-root-owned for
    // sshd's privsep check). Mount it once here, up front, so secrets write `/run/secrets` INTO it
    // rather than under a `/run` that sshd will later shadow. Without `--ssh`, secrets mount their own
    // narrow `/run/secrets` tmpfs (keeps the image's `/run` otherwise intact).
    let run_tmpfs = spec.ssh.is_some();
    if run_tmpfs {
        make_box_tmpfs(&spec.root, "run")?;
    }
    setup_secrets(&spec.root, &spec.secrets, run_tmpfs)?;
    setup_cpu_topology(&spec.root, spec.cpuset.as_deref());
    setup_etc_identity(&spec.root, &spec.hostname);
    setup_extra_hosts(&spec.root, &spec.extra_hosts);
    // AFTER the hosts files, because the two are independent and this one only fires when asked.
    setup_resolv_conf(&spec.root, &spec.dns, &spec.dns_search, &spec.dns_options);
    t.mark("volumes");
    // Self-pivot into the new root. The old root is left stacked at "/"; mount a fresh `proc`
    // (cwd-relative, while the old root still provides the visible proc instance the kernel
    // requires), THEN detach the old root.
    let staged = mounted.create_old_root(&mut ops)?;
    mount_proc()?;
    detach_old_root()?;
    t.mark("pivot+mount_proc");
    // Lock down the non-namespaced host-global procfs knobs (core_pattern, sysrq, kernel info) now that
    // `/proc` resolves to the fresh procfs - closes the classic core_pattern escape for a root-mapped box.
    //
    // SKIP for a `--privileged` (nesting) box: the ro-bind/`/dev/null` masks are LOCKED submounts, and
    // the kernel's `mount_too_revealing` check then refuses a NESTED box's fresh `/proc` mount (EPERM) -
    // it would "reveal" what the outer masks hide. Presenting a fully-visible `/proc` (exactly what
    // Docker `--privileged` does) is what lets docker-in-docker-style nesting work. Safe here because
    // `allow_nesting` is rootless-only: the host-global sysctls under `/proc/sys` are owned by the INIT
    // user namespace and a rootless box (even as box-root) lacks the CAP_SYS_ADMIN there to write them -
    // so the mask was defense-in-depth for the ROOT-mapped case, which `--privileged` already refuses.
    // The nested box, unless itself `--privileged`, re-applies its own masks normally.
    // `--sysctl`: written HERE, in the only correct window - after the fresh procfs is mounted and
    // while `/proc/sys` is still writable, but BEFORE `mask_proc_paths` remounts it read-only. The
    // ordering is a property, not an accident: the operator's values are applied, and then the knobs
    // are sealed, so the workload itself can never change what it was pinned to (Docker leaves
    // namespaced knobs writable from inside the container).
    apply_sysctls(&spec.sysctls)?;
    if !spec.sysctls.is_empty() {
        t.mark("sysctl");
    }
    if !allow_nesting {
        mask_proc_paths()?;
    }
    t.mark("proc-mask");
    // Give the box a read-only view of its OWN cgroup at `/sys/fs/cgroup` (see `mount_cgroup`), so
    // memory-aware runtimes read the real cap. After the `/proc` masks so their mount ordering matches
    // the rest of the hardened set; before the optional read-only root remount below, while the root is
    // still writable for the mountpoint mkdir. ONLY when we own a cgroup namespace (else a fresh cgroup2
    // mount would reveal the whole host cgroup tree instead of just this box's leaf).
    if cgroupns_ok {
        mount_cgroup();
    }
    t.mark("cgroup-view");
    // Optional read-only remount LAST - the typestate makes any other order a compile error.
    // Overlay leaves the root writable (writes land in the upper layer). Volume submounts keep
    // their own flags, so a writable `-v` stays writable even under a read-only root. `MS_REMOUNT`
    // only affects the named mount, so the separate `/dev` tmpfs is remounted read-only too -
    // otherwise `--read-only` would leave `/dev` writable. (Device nodes keep working: they're
    // their own bind mounts and writes go through the driver, not the tmpfs.)
    if spec.read_only {
        let _ro = staged.into_readonly(&mut ops)?;
        remount_dev_ro()?;
    }

    // Replace the inherited host environment with a clean, minimal one - the host's env (secrets,
    // tokens, SSH/agent sockets, kern internals like KERN_SCOPE) must NOT leak into the workload -
    // then layer the user's `--env` on top.
    set_clean_env(&spec.hostname, &spec.env)?;

    // Honor `--workdir`: chdir into it, CREATING it first if the image does not have it.
    //
    // Docker does the same, and the compose idiom depends on it: `working_dir: /app` with the code
    // bind-mounted there is the standard shape, and plenty of images (python:alpine among them) ship
    // no `/app`. Refusing was a real compatibility gap, found by bringing up a three-service stack
    // where the second service died on `chdir(workdir) failed: No such file or directory`.
    //
    // Created inside the box's own rootfs, after the pivot, so this cannot touch a host path. Mode
    // 0755 matches Docker's. A creation failure is NOT fatal on its own: a read-only root legitimately
    // refuses it, and the chdir below is the check that decides - it reports the real reason either way.
    if let Some(wd) = &spec.workdir {
        let c = cstr(wd)?;
        // Create it only for an ABSOLUTE path, as Docker requires ("it needs to be an absolute
        // path"). Without this guard the creation above turns a typo into a silent success: `-w app`
        // instead of `-w /app` used to fail, and would now quietly mkdir `app` relative to the box's
        // root and run there. A relative workdir still reaches `chdir` and fails there if it does not
        // exist, so the behaviour for an existing relative path is unchanged.
        if wd.starts_with('/') && unsafe { libc::access(c.as_ptr(), libc::F_OK) } != 0 {
            mkdir_p(wd);
        }
        if unsafe { libc::chdir(c.as_ptr()) } != 0 {
            return Err(Error::last("chdir(workdir)"));
        }
    }

    // Bring the box's own loopback up so 127.0.0.1 works inside an isolated net namespace (a fresh
    // net ns has `lo` present but DOWN). Skipped when `--net` shares the host's already-up loopback,
    // and for a `--pod` box whose shared loopback the pod holder already brought up.
    if !spec.share_net && spec.pod_holder.is_none() {
        bring_loopback_up();
    }
    // `--ip`: the addresses a compose file pinned to this service. Done for a POD MEMBER TOO, which
    // is why it is not inside the branch above: the holder brought the shared `lo` UP, but an address
    // belongs to the service that declared it and every member adds its own to the namespace they
    // share. Best-effort and per address, so one that cannot be claimed does not cost the others.
    for ip in &spec.net_ips {
        add_loopback_alias(*ip);
    }

    // `--ssh`: stand up the in-box sshd (mounts /run tmpfs, writes keys/config, forks sshd). Done
    // here - after loopback (sshd binds 127.0.0.1) and pivot (privileged mounts), before seccomp
    // (the filter would block the mounts, and the forked sshd must predate the filter).
    if let Some(ssh) = &spec.ssh {
        crate::ssh::setup(ssh);
    }

    // `-it`: adopt the PTY slave as the controlling terminal (done before seccomp - these are setup
    // syscalls, not the workload's). The slave fd was opened on the host and inherited across the
    // unshare/pivot (it's just an fd).
    if let Some(slave) = box_slave.or(spec.tty_slave) {
        adopt_controlling_tty(slave);
    }

    // Pin to `--cpuset-cpus` via CPU affinity. This is the rootless-portable path: unlike the
    // cgroup `cpuset` controller (frequently NOT delegated to a user session), `sched_setaffinity`
    // needs no privilege and no delegation, and the affinity is inherited across the exec - so the
    // box command actually runs pinned even where the cgroup write is skipped. Done before seccomp
    // (a setup syscall).
    set_cpu_affinity(spec.cpuset.as_deref());

    // `--ulimit`: applied while we still hold capabilities (a hard-limit RAISE needs them) and before
    // seccomp, which would otherwise have to allow `setrlimit`.
    apply_ulimits(&spec.ulimits)?;
    if !spec.ulimits.is_empty() {
        t.mark("ulimit");
    }

    // `--apparmor <profile>`: request the onexec transition into a pre-loaded AppArmor profile. Done
    // HERE, while the process is still inner-root and DUMPABLE, and BEFORE the `--user` setuid below: a
    // setuid privilege-drop clears the dumpable flag, which flips `/proc/self/attr/*` to root-owned 0600
    // (`task_dump_owner`), so a non-root `--user` - or an image's own `USER`, which `run_as` folds in -
    // could no longer open the attr file to write the transition (EACCES) and the box would fail to
    // start with a misleading "AppArmor is not available on this kernel" though the profile IS loaded.
    // The onexec label lives in the task security context and survives setuid/cap-drop/seccomp and the
    // `--init` reaper's fork, so requesting it first is safe and is the profile the eventual execve
    // transitions into. Also before the seccomp install and the init/non-init split. FAIL-CLOSED: a
    // profile that won't arm refuses the box rather than running it unconfined.
    if let Some(profile) = &spec.apparmor {
        apply_apparmor_onexec(profile)?;
        t.mark("apparmor");
    }
    // Least-privilege, in three ordered steps so `--user` + `--cap-drop ALL` (the canonical hardened
    // profile) composes correctly. All run after privileged setup (mount/pivot/loopback), so they
    // only affect the workload.
    let cap_mask = cap_drop_mask(&spec.caps, spec.tun, spec.privileged);
    // 1. Bounding set - needs effective `CAP_SETPCAP` (still present here); stops a file-cap binary
    //    re-adding a dropped cap. Dropping a cap from the *bounding* set does NOT block using it from
    //    the effective set, so the `setuid`/`setgid` below still work even under `--cap-drop ALL`.
    drop_cap_bounding(cap_mask)?;
    // 2. `--user UID[:GID]`: drop to the workload's uid/gid - needs `CAP_SETUID`/`CAP_SETGID` in the
    //    *effective* set, which are still present (we haven't cleared effective yet). setgid before
    //    setuid (once uid is non-root you can't change gid); setuid to a non-root uid then sheds the
    //    effective caps itself. Only mapped ids succeed; a failure fails closed (refuses to exec).
    if let Some((uid, gid)) = spec.run_as {
        set_user(uid, gid, &spec.extra_gids)?;
    }
    // 3. Clear the dropped caps from effective/permitted/inheritable. For a non-root `--user` step 2
    //    already emptied them; this covers a root box and is otherwise a harmless no-op. Fatal on a
    //    real failure (see `clear_caps_from_sets`): the box must not run holding caps it dropped.
    clear_caps_from_sets(cap_mask)?;

    // Landlock (LSM) write-allowlist, applied BEFORE seccomp (whose filter would otherwise block the
    // `landlock_*` syscalls). Defense-in-depth over the mount namespace: the box root is read+exec and
    // writes are confined to `--landlock-rw` paths + the box scratch dirs, enforced by the kernel and
    // unliftable by the workload.
    //
    // FAIL-CLOSED, on BOTH failure shapes. A ruleset that could not be built or enforced was always
    // fatal; a kernel with no Landlock at all used to warn and run the box unconfined, which made this
    // the only "enforce or do not run" flag in the CLI that did not. `--require-limits` refuses when the
    // cgroup caps cannot bind and `--apparmor` refuses when the profile cannot be entered; a flag whose
    // entire purpose is to confine writes must refuse for the same reason, or an operator who wrote it
    // into a script gets a box that silently has no path allowlist on exactly the hosts where they were
    // least sure of the kernel. The cost is stated and deliberate: a script that passes this flag and
    // runs on a board without `CONFIG_SECURITY_LANDLOCK` now fails instead of degrading, so the operator
    // decides (drop the flag, or gate it on `kern doctor`) rather than kern deciding for them.
    if !spec.landlock_rw.is_empty() {
        // `?` carries the "a ruleset that WAS available failed" case with the syscall's own message;
        // `false` is the one shape that needs a message written here, because the kernel returned no
        // error at all - there is simply no LSM to ask.
        if !crate::landlock::apply_rw_allowlist(&spec.landlock_rw)? {
            return Err(Error::Unsupported(
                "--landlock-rw was requested but this kernel has no Landlock (not built in, or \
                 switched off at boot with `lsm=`), so the path write-allowlist cannot be enforced: \
                 refusing to start rather than running a box that asked to be confined and would \
                 not be. `kern doctor` reports the Landlock ABI on this host. Drop --landlock-rw to \
                 run with namespaces, seccomp and cgroups, which is the default posture and does \
                 not depend on this LSM.",
            ));
        }
        t.mark("landlock");
    }
    // Install the seccomp filter LAST - after all setup syscalls (mount/pivot) are done, so it
    // only constrains the workload. Then exec (or hand off to the built-in init). `allow_nesting`
    // (a rootless `--privileged` box) leaves the namespace + classic-mount syscalls allowed so a
    // nested `kern box` can start; everything else stays blocked.
    crate::seccomp::install(spec.seccomp_mode, allow_nesting)?;
    t.mark("seccomp");
    // SECURITY (CVE-2016-9962 class): shed every inherited fd `>= 3` before handing control to the
    // workload, keeping ONLY the readiness pipe (`ready_fd`, whose CLOEXEC close on a successful
    // `execvp` signals the launcher). kern marks every descriptor IT opens `CLOEXEC`, but a descriptor
    // inherited from kern's CALLER - an SDK process that spawns boxes while holding a socket or a host
    // file open, a CI runner, a supervisor - is not kern's to mark, and would otherwise pass straight
    // into the workload as a live handle to a host object OUTSIDE the box's rootfs. Done here, before
    // the init/non-init split, so it also covers the `--init` reaper PID 1 (which does not itself
    // `exec` and would otherwise keep the caller's fds readable via `/proc/1/fd`). The pty slave, if
    // any, was already dup'd onto 0/1/2 and its high fd closed by `adopt_controlling_tty` above.
    // THE PRE-EXEC GATE DESCRIPTOR IS THE SECOND EXCEPTION, and leaving it out silently broke the
    // gate: `shed_inherited_fds` closes every inherited fd >= 3, so the gate's read end was closed
    // here and the `read` below returned EBADF, which the gate reads as EOF, which is REFUSAL. A box
    // that should have waited refused instead, and the reason was four hundred lines away from the
    // symptom. It is listed rather than ranged because the exception must be as narrow as the
    // readiness pipe's: exactly one descriptor, named, and closed by the gate itself before `execvp`.
    // TWO SHAPES, AND THE FAST ONE IS THE DEFAULT. `shed_inherited_fds` closes the two ranges around
    // the kept descriptor with `close_range(2)`: two syscalls. `shed_inherited_fds_keeping` cannot do
    // that for an arbitrary set and falls back to 1021 individual `close()` calls.
    //
    // MEASURED, and this is why the branch exists rather than the list always: routing every box
    // through the list form cost **+207 us on box start p50** (2903 against a 2696 baseline, n=300,
    // same binary, alternated) - eight times the 25 us that was set as the stop-and-look line before
    // the number was taken. A gate exists only for a multi-box `--no-pod` stack, so a box that has
    // none must not pay for one.
    match gate {
        None => shed_inherited_fds(ready_fd.unwrap_or(-1)),
        Some(g) => shed_inherited_fds_keeping(&[ready_fd.unwrap_or(-1), g]),
    }
    // THE LAST THING PID 1 DOES BEFORE THE WORKLOAD, and until this mark existed it was invisible.
    // `box lifetime` minus the marked phases left a residue of about 670 us that did not move with the
    // image, the rootfs, the workload's linkage or the network namespace - constant across four
    // configurations, and therefore structural rather than a property of what was being run. A block
    // that size with no marker is the largest thing in this file nobody can attribute, and the fd shed
    // walks `/proc/self/fd`, so it is the first candidate the residue has to be split against.
    t.mark("shed-fds");
    if spec.init {
        // `--init`: this PID-1 process forks the workload and becomes a reaping init. Never returns.
        run_init(spec, argv, ready_fd, gate)
    } else {
        // Default: PID 1 IS the workload - exec directly, byte-for-byte the original path.
        Err(exec(argv, ready_fd, gate))
    }
}

/// Built-in init (`--init`): kern PID 1 forks the workload, then loops reaping EVERY child (the direct
/// workload plus any orphan reparented to PID 1 - the zombie-reaping guarantee), forwarding SIGTERM and
/// SIGINT to the workload, and finally `_exit`s with the workload's own status. Raw libc only, never
/// unwinds. `ready_fd` is the readiness pipe write end: PID 1 closes its own copy right after the fork
/// so the launcher still sees EOF when the workload execs; the workload child writes the failure byte
/// if ITS exec fails (so a detached box reports "exited before starting" instead of hanging).
/// `gate` is threaded rather than re-read from the environment for the reason in [`gate_fd`]: by the
/// time `--init` forks its workload child, `clearenv` has already run.
fn run_init(
    spec: &SandboxSpec,
    argv: &[CString],
    ready_fd: Option<i32>,
    gate: Option<libc::c_int>,
) -> ! {
    // The forwarding signal handler needs the workload pid; a static is the only way to reach it.
    static CHILD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
    extern "C" fn forward(sig: libc::c_int) {
        // Async-signal-safe: `kill` is on the AS-safe list. Forward to the workload only (pid > 0).
        let pid = CHILD.load(std::sync::atomic::Ordering::SeqCst);
        if pid > 0 {
            unsafe { libc::kill(pid, sig) };
        }
    }

    let child = unsafe { libc::fork() };
    if child < 0 {
        if let Some(fd) = ready_fd {
            let _ = unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
        }
        eprintln!("kern: --init: fork failed");
        unsafe { libc::_exit(125) }; // setup failure: the box could not start its workload
    }
    if child == 0 {
        // WORKLOAD child: inherits the CLOEXEC ready_fd - a successful exec closes it (→ launcher EOF).
        // On exec failure, write the byte HERE (this is not PID 1, so the parent's byte-write below
        // won't fire for us) so the launcher learns it failed, then report and exit.
        // `exec` only ever returns on failure (its type is `-> Error`).
        let e = exec(argv, ready_fd, gate);
        if let Some(fd) = ready_fd {
            let _ = unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
        }
        report_exec_failure(spec, &e);
        // Always an `execvp` failure here (`exec` only returns on failure): 126 (EACCES) / 127 (not
        // found), never 125 - a 125 setup failure cannot reach this WORKLOAD child.
        unsafe { libc::_exit(box_start_exit_code(&e)) };
    }

    // PID 1 (init). Close our own copy of the ready fd NOW, so the workload's exec is the last holder
    // of the write end → the launcher reads EOF exactly when the box is up (not when PID 1 exits).
    if let Some(fd) = ready_fd {
        unsafe { libc::close(fd) };
    }
    // Publish the child pid, THEN install the forwarders - so an early signal can't `kill(0)` the
    // whole group. `SA_RESTART` is deliberately OFF so `waitpid` returns EINTR and we can re-loop.
    CHILD.store(child, std::sync::atomic::Ordering::SeqCst);
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = forward as extern "C" fn(libc::c_int) as usize;
        sa.sa_flags = 0; // no SA_RESTART
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }
    // Reap loop: wait for ANY child. The workload's status is what we exit with; every other reaped
    // pid is a reparented orphan (the zombie-reaping guarantee). EINTR = a forwarded signal → re-loop.
    let mut child_status = 0i32;
    let mut child_reaped = false;
    loop {
        let mut status = 0i32;
        let r = unsafe { libc::waitpid(-1, &mut status, 0) };
        if r < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue; // interrupted by a forwarded signal - keep reaping
            }
            break; // ECHILD (all children gone) or an unexpected error
        }
        if r == child {
            child_status = status;
            child_reaped = true;
        }
    }
    // Exit with the workload's decoded status (128+signo if it was killed); if we somehow never saw it,
    // don't decode uninitialized status - fail with 1.
    unsafe {
        libc::_exit(if child_reaped {
            wait_code(child_status)
        } else {
            1
        })
    };
}

/// The `_exit` code for a box that could not run its workload, aligned with Docker's convention so the
/// caller (and an SDK relaying the code) can tell a kern/setup failure apart from the workload's own
/// command failure:
/// - **125**: kern could not START the box - any setup step failed (mount, uid map, seccomp, AppArmor,
///   cgroup). This is NOT a "command not found"; the operator must look at the sandbox, not their argv.
/// - **126**: the command was FOUND but the kernel refused to exec it (`EACCES`: not executable, or an
///   LSM transition denied).
/// - **127**: the command was not found (`ENOENT` and friends).
///
/// Only an `execvp` error is the workload's own command; every other `Error` is kern's setup, so it
/// maps to 125. Matches `child_setup_and_exec`, whose non-init tail is exactly `Err(exec(argv))`.
fn box_start_exit_code(e: &Error) -> i32 {
    match e {
        Error::Syscall("execvp", io) if io.raw_os_error() == Some(libc::EACCES) => 126,
        Error::Syscall("execvp", _) => 127,
        _ => 125,
    }
}

/// Print the actionable "cannot start the box command" diagnostic for a failed `execvp` (command not
/// found, missing loader, or a dropped-uid permission error), or a generic setup-failure line for any
/// other error. Shared by the direct-exec path and the `--init` workload child so both give the same
/// hint. Does not exit - the caller `_exit`s.
fn report_exec_failure(spec: &SandboxSpec, e: &Error) {
    if let Error::Syscall("execvp", io) = e {
        let cmd = spec.command.first().map(String::as_str).unwrap_or("?");
        // A permission-denied exec while dropped to a non-root `--user` is almost always the uid, not a
        // missing command: in a rootless box the overlay rootfs is owned by the box's root uid and a
        // dropped uid can't traverse/exec it. Name the real cause.
        let dropped = matches!(spec.run_as, Some((u, _)) if u != 0);
        if io.kind() == std::io::ErrorKind::PermissionDenied && dropped {
            let uid = spec.run_as.map(|(u, _)| u).unwrap_or(0);
            // With BOTH --user and --apparmor an EACCES is ambiguous - the dropped uid can't traverse
            // the rootfs, OR the profile refused the transition. Name the uid (the more common cause of
            // the two) but point at the profile too, so a box with both flags does not mis-attribute.
            let aa = spec
                .apparmor
                .as_deref()
                .map(|p| {
                    format!(
                        "\n      (or the AppArmor profile '{p}' refused the exec - is it loaded on the host?)"
                    )
                })
                .unwrap_or_default();
            eprintln!(
                "kern: cannot start '{cmd}' as uid {uid} in box: {io}\n\
                 hint: a rootless box's rootfs is owned by the box's root uid, so a \
                 non-root --user often can't exec it - drop --user (runs as the box's \
                 root) or provide a rootfs owned by uid {uid}{aa}"
            );
        } else if io.kind() == std::io::ErrorKind::PermissionDenied && spec.apparmor.is_some() {
            // EACCES with a profile requested is the LSM refusing the transition - almost always the
            // profile is not (or no longer) loaded on the host. Name it, don't blame the command.
            let profile = spec.apparmor.as_deref().unwrap_or("?");
            eprintln!(
                "kern: cannot start '{cmd}' in box: {io}\n\
                 hint: the AppArmor profile '{profile}' would not admit the exec - is it loaded on \
                 the host? (`apparmor_parser -r <profile>` loads it; `-R` removes it)"
            );
        } else {
            eprintln!(
                "kern: cannot start '{cmd}' in box: {io}\n\
                 hint: the command must exist inside the box (try a full path like \
                 /bin/sh) and, if dynamically linked, its libraries/loader must be \
                 present in the rootfs"
            );
        }
    } else if matches!(e, Error::Spec(_)) {
        // A `Spec` error is BY CONSTRUCTION the one kind of setup failure that already named the
        // field, the reason and what to change, so the generic hint under it would contradict it:
        // it asserts the failure is "a host capability rather than a wrong command" and points at
        // `kern doctor`, and a spec refusal is the opposite of both - the host is fine and doctor
        // cannot see the value that was refused. Branching on the VARIANT and not on the wording,
        // because here the type is still in hand (the CLI has only the rendered string by the time
        // it decides, and keys the same suppression off the message).
        eprintln!("kern: sandbox setup failed: {e}");
    } else {
        // AND IT CARRIES ITS OWN REMEDY, because nothing downstream can add one. This branch runs in
        // the FORKED CHILD, which `_exit`s on the next line, so the error never reaches the CLI's hint
        // function and no match arm there can ever help it. An outside reviewer measured exactly that:
        // `kern: sandbox setup failed: mount(overlay) failed: Invalid argument (os error 22)`, with no
        // hint line under it, while every neighbouring branch in this function carries one.
        //
        // The text is [`crate::SETUP_FAILURE_HINT`] and not a copy: the CLI prints the same class of
        // failure for everything that fails BEFORE the fork, and two wordings for one condition drift.
        eprintln!(
            "kern: sandbox setup failed: {e}\nhint: {}",
            crate::SETUP_FAILURE_HINT
        );
    }
}

/// `--user`: drop to `uid`/`gid` for the workload. Order matters - `setgroups` (clear supplementary
/// groups) then `setgid` then `setuid`, because once the uid is non-root you can no longer change
/// gid. Only ids mapped into the box's user namespace succeed (see `--uid-range`).
///
/// **Fails CLOSED**: if a non-root target `setgid`/`setuid` fails (the id isn't mapped - e.g. a host
/// without `newuidmap`/`newgidmap` fell back to the single-uid map), return `Err` so the box
/// **refuses to exec** rather than silently running the workload as in-box root. Dropping privilege
/// must never *grant* it. `--user 0` (explicitly root) is a successful no-op.
fn set_user(uid: u32, gid: u32, extra_gids: &[u32]) -> Result<(), Error> {
    unsafe {
        if extra_gids.is_empty() {
            // Best-effort: setgroups may be EPERM under `/proc/self/setgroups=deny` (single-uid box);
            // the single mapped group is already the whole set, so a failure here is harmless.
            libc::setgroups(0, std::ptr::null());
        } else {
            // THE IMAGE'S OWN GROUP MEMBERSHIPS, resolved by the caller from the image's `/etc/group`
            // exactly as Docker and podman resolve them, and granted here because clearing them
            // breaks images that rely on one.
            //
            // MEASURED on Elastic's official three-node compose file: its `setup` service writes the
            // certificates `root:root` mode 640, `kibana` is `kibana:x:1000:1000` in the image's
            // passwd and a MEMBER of group 0 in its `/etc/group` (`root:x:0:kibana`), and podman
            // gives it `groups=1000,0`. kern cleared the set, so kibana ran with group 1000 only and
            // died with `FATAL Error: EACCES: permission denied, open 'config/certs/ca/ca.crt'` -
            // while the three Elasticsearch nodes, whose image declares `1000:0` outright, were
            // green. This is not a grant kern invents: a supplementary gid is only usable inside the
            // box's own gid map, so it can reach nothing the box could not already reach.
            let gids: Vec<libc::gid_t> = extra_gids.iter().map(|g| *g as libc::gid_t).collect();
            if libc::setgroups(gids.len(), gids.as_ptr()) != 0 {
                // NOT FATAL, BUT NAMED. A single-uid box has `/proc/self/setgroups` set to `deny`,
                // where this cannot succeed and the box is still perfectly usable for images that do
                // not depend on a group. Silence would leave the reader with the EACCES above and
                // nothing pointing at its cause.
                let e = std::io::Error::last_os_error();
                let list = extra_gids
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                eprintln!(
                    "kern: warning: could not give the workload the group(s) its image puts it in \
                     ({list}): {e}. A file readable only through one of those groups will fail with \
                     EACCES; `--uid-range` maps a range of gids and lets this succeed."
                );
            }
        }
        if libc::setgid(gid as libc::gid_t) != 0 && gid != 0 {
            return Err(Error::Unsupported(
                "cannot drop to the target gid - it isn't mapped into the box (needed by --user or the \
                 image's own USER; add newuidmap/newgidmap + an /etc/subgid allocation, or use --uid-range)",
            ));
        }
        if libc::setuid(uid as libc::uid_t) != 0 && uid != 0 {
            return Err(Error::Unsupported(
                "cannot drop to the target uid - it isn't mapped into the box (needed by --user or the \
                 image's own USER; add newuidmap/newgidmap + an /etc/subuid allocation, or use --uid-range)",
            ));
        }
        // PUT `dumpable` BACK, BECAUSE THE KERNEL JUST CLEARED IT AND THE `execve` BELOW WILL SET IT
        // ANYWAY.
        //
        // A credential change clears `PR_SET_DUMPABLE`, and a process that is not dumpable has its
        // `/proc/<pid>/ns/*` refused with EACCES - to EVERY caller, including the uid that owns it.
        // MEASURED, same uid in both arms and nothing but this flag between them: `open
        // /proc/<pid>/ns/user` answers OK at `dumpable=1` and `Permission denied` at `dumpable=0`.
        //
        // WHAT IT BROKE. kern's peer relay enters a box by opening exactly those two files, and it
        // does so while every box is still HELD AT ITS PRE-EXEC GATE - which is the whole
        // correctness argument for the gate: no workload has run, so no workload can observe a
        // half-built network. Between this `setuid` and the workload's `execve` the box is therefore
        // unreadable, and a stack whose `networks:` segregate died with
        // `peer relay: ... errno 13` for every service that runs as a non-root user. On the neutral
        // corpus that was the ONLY image-only file kern wires with relays, so it was the whole
        // runnable sample of that wiring.
        //
        // WHY RESTORING IT GIVES NOTHING AWAY. `execve` recomputes `dumpable` from the new
        // credentials, so the only interval this changes is the one between here and that exec, and
        // in that interval the only code running is kern's own box setup. The classic reason to
        // leave a uid-changed process undumpable is a setuid `execve` afterwards; kern arms
        // `PR_SET_NO_NEW_PRIVS` before the workload runs (seccomp requires it), which makes the
        // setuid bit inert process-wide - the same reasoning already recorded for the `nosuid`
        // remount being defence in depth rather than load-bearing.
        //
        // NOT FATAL: a box that cannot be entered by a relay is still a box that runs. The relay
        // says so itself, by name, and that message is the one that used to blame a bind.
        libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
    }
    Ok(())
}

/// Pin the workload to the CPUs named in `--cpuset-cpus` (`"0-3"`, `"0,2,4"`) with
/// `sched_setaffinity`. Portable and rootless - needs neither a delegated `cpuset` cgroup nor any
/// capability - and inherited across `exec`. Best-effort: a parse or syscall failure leaves the box
/// unpinned rather than failing it. Cooperative for this trust model (a hostile workload could widen
/// its own affinity; `--memory`/`--cpus` are the hard, cgroup-enforced governance). Complements the
/// cgroup `cpuset.cpus` write, which stays authoritative on hosts where that controller IS delegated.
pub fn set_cpu_affinity(cpuset: Option<&str>) {
    let Some(list) = cpuset else { return };
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe { libc::CPU_ZERO(&mut set) };
    let mut any = false;
    for cpu in expand_cpu_list(list) {
        if cpu < libc::CPU_SETSIZE as usize {
            unsafe { libc::CPU_SET(cpu, &mut set) };
            any = true;
        }
    }
    if any
        && unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) } != 0
    {
        // Best-effort (it needs no privilege, so this is rare - every requested CPU offline, or a
        // restrictive outer affinity mask). WARN instead of dropping `--cpuset-cpus` silently, so a
        // workload that did NOT get pinned is visible rather than quietly running across all CPUs -
        // the same "best-effort caps announce themselves" rule the `--memory` notice follows.
        eprintln!(
            "kern: warning: --cpuset-cpus '{list}' could not be applied ({}); the workload runs \
             without CPU pinning",
            std::io::Error::last_os_error()
        );
    }
}

/// Expand a validated cpuset list (`"0-3,5"`) into CPU indices. The CLI already restricts the string
/// to `N` / `N-M` tokens (`is_cpu_list`), so a malformed token here simply contributes nothing.
///
/// SECURITY: a CPU index past `CPU_SETSIZE` can never be set in a `cpu_set_t`, so we CLAMP each range
/// to it BEFORE expanding. Without this a hostile `cpuset: 0-999999999` (which `is_cpu_list` accepts -
/// it only checks the `u32` format, not the magnitude) would `extend(0..=999999999)` and allocate a
/// ~8 GB `Vec` before the per-element bound in the caller ever ran - a memory-exhaustion DoS. (Found
/// in a hacker-mode audit.)
fn expand_cpu_list(s: &str) -> Vec<usize> {
    const MAX: usize = libc::CPU_SETSIZE as usize;
    let mut out = Vec::new();
    for tok in s.split(',') {
        match tok.split_once('-') {
            Some((a, b)) => {
                if let (Ok(lo), Ok(hi)) = (a.parse::<usize>(), b.parse::<usize>()) {
                    // Clamp the upper bound: indices >= CPU_SETSIZE are unsettable, so expanding to them
                    // only wastes memory. `lo > MAX` yields an empty range (lo..=MAX-1 skipped).
                    let hi = hi.min(MAX.saturating_sub(1));
                    if lo <= hi {
                        out.extend(lo..=hi);
                    }
                }
            }
            None => {
                if let Ok(c) = tok.parse::<usize>() {
                    if c < MAX {
                        out.push(c);
                    }
                }
            }
        }
    }
    out
}

/// Open the volume SOURCE - an absolute, already-canonical host path - SYMLINK-FREE via an
/// `openat(O_NOFOLLOW)` component walk from `/`, returning an `O_PATH` fd. `parse_volumes`
/// canonicalized and registry-guarded this path as a STRING, but the kernel would RE-RESOLVE that
/// string at `mount()` time and FOLLOW a symlink swapped into an intermediate component between the
/// check (in the parent) and the bind (here, post-fork) - the CVE-2021-30465 symlink-exchange race.
/// Resolving it ourselves with `O_NOFOLLOW` and mounting from the pinned fd makes a swap FAIL the walk,
/// never redirect it: the bind is either the checked inode or an error. Symmetric with the target side.
fn open_source_nofollow(src: &str) -> Result<libc::c_int, Error> {
    let mut dir = unsafe {
        libc::open(
            cstr("/")?.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if dir < 0 {
        return Err(Error::last("open(/)"));
    }
    for comp in src.split('/').filter(|c| !c.is_empty()) {
        // A canonical path has no `.`/`..`; refuse them anyway so a tampered string can't climb.
        if comp == "." || comp == ".." {
            unsafe { libc::close(dir) };
            return Err(Error::Unsupported(
                "volume source must be canonical (no '.'/'..')",
            ));
        }
        let c = match cstr(comp) {
            Ok(c) => c,
            Err(e) => {
                unsafe { libc::close(dir) };
                return Err(e);
            }
        };
        let next = unsafe {
            libc::openat(
                dir,
                c.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        unsafe { libc::close(dir) };
        if next < 0 {
            // A component that is now a symlink (swapped in after the check) lands here as ELOOP/ENOTDIR.
            return Err(Error::last("openat(volume source, O_NOFOLLOW)"));
        }
        dir = next;
    }
    Ok(dir)
}

/// The `size=` to mount `/dev/shm` with, in bytes, or `None` to leave it unsized.
///
/// `--shm-size` when the operator gave one. Otherwise the box's own `--memory` cap, which is the one
/// number that is already true: the tmpfs is charged to that cgroup, so a box can never actually hold
/// more shm than that, and saying so out loud costs nothing while an unsized mount reports half the
/// HOST's RAM. Deliberately NOT Docker's fixed 64 MB default, which is the footgun the previous comment
/// here was avoiding: it is what breaks Postgres under load, and it has no relationship to the box.
/// An uncapped box keeps the previous behaviour, because there is no honest number to use.
const fn shm_size_for(explicit: Option<u64>, memory_max: Option<u64>) -> Option<u64> {
    match explicit {
        Some(n) => Some(n),
        None => memory_max,
    }
}

/// The per-mount flags currently in force on the filesystem `fd` refers to, as `MS_*` bits.
///
/// Needed because a bind REMOUNT **sets** the per-mount flags rather than adding to them, and a user
/// namespace refuses one that would clear a flag the kernel locked (`nosuid`, `nodev`, `noexec`, the
/// atime policy and `rdonly` are locked on any mount a userns inherited). So "add nosuid" has to be
/// spelled "everything already in force, plus nosuid", or the remount fails with `EPERM` on exactly the
/// mounts that most need it. `statvfs`'s `ST_*` bits are the readable form of those flags.
fn current_mount_flags(fd: libc::c_int) -> libc::c_ulong {
    // `fstatfs64` and not `fstatvfs`: glibc implements the latter by PARSING `/proc/self/mounts` to
    // fill `f_flag`, which is both slower and a second source of truth for something the kernel answers
    // directly. This is the syscall, it reports THIS mount's own flags, and it works on the `O_PATH` fd
    // this is called with. The `64` suffix is not optional: plain `statfs` carries no `f_flags` field on
    // the glibc targets, while `statfs64` has it on glibc AND musl, which is what the release builds use.
    let mut st: libc::statfs64 = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs64(fd, &mut st) } != 0 {
        // Unreadable: claim nothing. The caller ORs in what it wants, and a remount that then tries to
        // clear a locked flag fails - which is the safe direction, because this path is best-effort.
        return 0;
    }
    let f = st.f_flags as libc::c_ulong;
    // The kernel reports these bits in `f_flags` with the SAME numeric values as the `MS_*` mount
    // flags, so one constant serves both sides. (The `ST_*` spellings are not used: musl does not
    // define all of them, and the release builds are musl.)
    //
    // The list is explicit rather than a bulk copy of `f_flags`, and that is load-bearing: `f_flags`
    // also carries `ST_VALID` (0x20), which is numerically `MS_REMOUNT`. Passing the raw word through
    // would smuggle a flag nobody asked for into the very syscall this feeds.
    let mut ms: libc::c_ulong = 0;
    for bit in [
        libc::MS_RDONLY,
        libc::MS_NOSUID,
        libc::MS_NODEV,
        libc::MS_NOEXEC,
        libc::MS_SYNCHRONOUS,
        libc::MS_MANDLOCK,
        libc::MS_NOATIME,
        libc::MS_NODIRATIME,
        libc::MS_RELATIME,
    ] {
        let b = bit as libc::c_ulong;
        if f & b != 0 {
            ms |= b;
        }
    }
    ms
}

/// Bind each `-v` host path into the new root BEFORE pivot (while the host source is reachable at
/// its real path). BOTH ends are resolved **symlink-free** via an `openat(O_NOFOLLOW)` component walk
/// and the bind runs fd-to-fd through `/proc/self/fd/<n>` - so neither a hostile image's symlink at the
/// mount point NOR a symlink swapped into the source path between check and mount can redirect the bind
/// onto a host path. Every volume is then remounted with `nosuid`, and a `:ro` one also read-only.
///
/// `nosuid` here is DEFENCE IN DEPTH and is deliberately best-effort, which is a correction of an
/// earlier belief in this file. The reasoning that made it load-bearing (that under `--uid-range` a
/// setuid-root file on a volume lets an in-box uid become box-root) is wrong for a kern box: kern arms
/// `PR_SET_NO_NEW_PRIVS` before the workload runs, because seccomp requires it, and no-new-privs makes
/// the setuid bit inert process-wide no matter how the filesystem is mounted. Measured: `NoNewPrivs: 1`
/// in every reachable configuration, and a setuid-root binary on a `-v` volume executed by an in-box
/// uid 1000 under `--uid-range` returns euid 1000 with the remount removed as well as with it.
///
/// So a failed `nosuid` remount is never fatal. Making it fatal would refuse to start a box for a
/// property something else already guarantees, on exactly the kernels that reject bind remounts
/// outright (Android-derived board kernels, as the `:ro` path below records). A `:ro` volume is
/// different and still fatal: read-only is a contract the caller asked for, and nothing else provides
/// it.
/// Decode the four escapes the kernel writes into a `mountinfo` path field (`\040` space, `\011`
/// tab, `\012` newline, `\134` backslash). Anything else is copied through byte for byte.
fn unescape_mountinfo(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            let oct = &s[i + 1..i + 4];
            match u8::from_str_radix(oct, 8) {
                Ok(v) if oct.bytes().all(|c| c.is_ascii_digit()) => {
                    out.push(v as char);
                    i += 4;
                    continue;
                }
                _ => {}
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// The mount points sitting strictly UNDER `src` in this mount namespace, at most `max` of them.
///
/// Used ONLY to explain a bind the kernel already refused, never to refuse one ourselves, and that
/// split is measured rather than assumed. The kernel's rule in `__do_loopback` is
/// `has_locked_children`, not "has children": a mount inherited when the user namespace was created
/// carries `MNT_LOCKED` and makes a non-recursive bind fail with EINVAL, while a mount made INSIDE
/// the namespace afterwards does not. Probed on this host in a fresh user+mount namespace: binding
/// `/tmp` (one inherited submount) returned EINVAL, and binding a directory whose child tmpfs was
/// mounted in the same namespace returned 0. `MNT_LOCKED` does not appear in `mountinfo`, and kern's
/// own `/proc`, `/dev` and devpts under the box root are exactly the second kind, so a pre-mount
/// refusal keyed on this evidence would refuse binds that work.
///
/// Because the explanation is gated on evidence that is read back at failure time and not on the
/// errno, a kernel that starts reporting something other than EINVAL does not turn the message into
/// a false claim: no submounts found means the raw syscall error is reported unchanged.
///
/// THE ROOT CASE IS UNREACHABLE HERE, and it is worth writing down because the first question a
/// reader asks is "and if kern runs as root, where the copies are not locked?". A box's namespaces
/// are created with `CLONE_NEWUSER` unconditionally (`ns_flags` in `run_in_sandbox_with`, with no
/// branch that omits it), and its mount namespace is unshared inside that new user namespace, so
/// the mounts copied into it are always locked: `copy_mnt_ns` locks the copies whenever the new
/// mount namespace's user namespace differs from the old one's. There is no kern box whose
/// inherited mounts are unlocked, whatever the caller's uid.
fn submounts_under(src: &str, max: usize) -> (Vec<String>, usize) {
    let Ok(body) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return (Vec::new(), 0);
    };
    submounts_in(&body, src, max)
}

/// The parsing half of [`submounts_under`], split out so a test can hand it a `mountinfo` body.
/// Returns the first `max` mount points strictly under `src` and how many there are in total.
///
/// DISTINCT mount points, counted and listed once each, because two filesystems can be stacked on
/// one path and the operator acts on the path. Measured: binding `/proc` on this host reported
/// `/proc/sys/fs/binfmt_misc` twice, since `mountinfo` carries a line for the autofs and one for the
/// filesystem mounted over it.
pub(crate) fn submounts_in(body: &str, src: &str, max: usize) -> (Vec<String>, usize) {
    let prefix = if src.ends_with('/') {
        src.to_string()
    } else {
        format!("{src}/")
    };
    let mut seen: Vec<String> = Vec::new();
    for line in body.lines() {
        // Field 5 (1-based) is the mount point; it is escaped but never contains a bare space.
        let Some(mp) = line.split(' ').nth(4) else {
            continue;
        };
        let mp = unescape_mountinfo(mp);
        if !mp.starts_with(&prefix) || seen.contains(&mp) {
            continue;
        }
        seen.push(mp);
    }
    let total = seen.len();
    seen.truncate(max);
    (seen, total)
}

fn setup_volumes(root: &str, vols: &[Volume]) -> Result<(), Error> {
    if vols.is_empty() {
        return Ok(());
    }
    let rc = cstr(root)?;
    let root_fd = unsafe {
        libc::open(
            rc.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(Error::last("open(root)"));
    }
    let mut result = Ok(());
    for v in vols {
        // Resolve and PIN the source symlink-free (race-close the check->mount window, see
        // `open_source_nofollow`). `fstat` on the pinned fd gives the type without re-touching the path.
        let src_fd = match open_source_nofollow(&v.source) {
            Ok(fd) => fd,
            Err(e) => {
                result = Err(e);
                break;
            }
        };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(src_fd, &mut st) } != 0 {
            unsafe { libc::close(src_fd) };
            result = Err(Error::Syscall(
                "fstat(volume source)",
                std::io::Error::last_os_error(),
            ));
            break;
        }
        let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        let tgt_fd = match open_in_root(root_fd, &v.target, is_dir) {
            Ok(fd) => fd,
            Err(e) => {
                unsafe { libc::close(src_fd) };
                result = Err(e);
                break;
            }
        };
        // Both ends addressed by their pinned fd (a decimal fd can never contain a NUL, so these
        // cannot fail - returned as an error, not asserted, since box mount-setup has no message path).
        let src = cstr(&format!("/proc/self/fd/{src_fd}"))?;
        let tgt = cstr(&format!("/proc/self/fd/{tgt_fd}"))?;
        // Deliberately NON-recursive (`MS_BIND`, not `MS_BIND | MS_REC`) - same rationale as the bind
        // root above: if the operator's volume source has host filesystems mounted *underneath* it
        // (a NAS share, an external disk, another program's socket dir), a recursive bind would put
        // those filesystems INSIDE the box. They belong to whoever mounted them, and the box asked
        // for a directory, not for everything that happens to be mounted under it. That is the
        // reason, and it does not expire.
        //
        // DOCKER DOES THE OPPOSITE, measured rather than assumed: with a tmpfs mounted at
        // `/tmp/kern-sub` on the host, `docker run -v /tmp:/x` shows two mount lines under `/x` and
        // `/x/kern-sub` is a mount point INSIDE the container (Docker 29.6.2, aarch64). So this is a
        // deliberate difference and not an oversight: kern hands the box the directory tree it asked
        // for, and nothing else that happens to be mounted under it.
        //
        // The `:ro` argument is NOT the reason, and saying so out loud is the point of this
        // paragraph. This comment used to lead with "the RO remount is per-mount, so a recursive
        // bind would leave the cloned submounts writable under a `:ro` volume". True on the mount
        // API kern uses, and an outside reviewer pointed out that it stops being true the moment
        // anyone reaches for `mount_setattr(MOUNT_ATTR_RDONLY, AT_RECURSIVE)`, which has covered
        // submounts since 5.12. An argument with an expiry date is the wrong one to build a refusal
        // on, and the wrong one to put in the operator's error message.
        let r = unsafe {
            libc::mount(
                src.as_ptr(),
                tgt.as_ptr(),
                ptr::null(),
                libc::MS_BIND as libc::c_ulong,
                ptr::null(),
            )
        };
        unsafe {
            libc::close(tgt_fd);
            libc::close(src_fd);
        }
        if r != 0 {
            let os = std::io::Error::last_os_error();
            // Say WHY, when the evidence for a why is there. A bare "Invalid argument" on a `-v` is
            // unactionable: the operator sees a path that exists, is readable, and still cannot be
            // mounted. See `submounts_under` for why this reads the evidence after the failure
            // instead of refusing before the syscall.
            let (named, total) = submounts_under(&v.source, 3);
            result = Err(if total == 0 {
                Error::Syscall("mount(volume bind)", os)
            } else {
                let subject = if total == 1 {
                    format!("1 path under {} has a filesystem mounted on it", v.source)
                } else {
                    format!(
                        "{total} paths under {} have a filesystem mounted on them",
                        v.source
                    )
                };
                let more = if total > named.len() {
                    format!(", and {} more", total - named.len())
                } else {
                    String::new()
                };
                Error::Spec(format!(
                    "mount(volume bind) failed for -v {}:{}: {os}. {subject} ({}{more}). kern binds a volume NON-recursively, because a recursive bind would put those filesystems INSIDE the box, and they belong to whatever mounted them rather than to this workload. The kernel then refuses a non-recursive bind of a source holding mounts inherited from outside the box. Bind a subdirectory that has none, or unmount them on the host.",
                    v.source,
                    v.target,
                    named.join(", "),
                ))
            });
            break;
        }
        {
            // Lock the per-mount flags ON the bind. A FIRST bind ignores them - they take an
            // `MS_REMOUNT` - so without this pass a `-v` volume honours a setuid binary sitting on it
            // and a `:ro` volume is writable. ONE remount and not two: `nosuid` and `rdonly` are flags
            // of the same syscall, and setting them separately would leave a window where the volume is
            // bound with neither, plus a second chance to fail.
            //
            // Re-resolve the target (it now points *into* the bind mount). The pre-bind fd refers to
            // the underlying dir, which can't be remounted.
            let ro_fd = match open_in_root(root_fd, &v.target, is_dir) {
                Ok(fd) => fd,
                Err(e) => {
                    result = Err(e);
                    break;
                }
            };
            // Everything already in force, plus what we are adding. See `current_mount_flags`: a bind
            // remount SETS flags, and a userns refuses one that clears a locked one.
            let mut flags = current_mount_flags(ro_fd)
                | (libc::MS_REMOUNT | libc::MS_BIND | libc::MS_NOSUID) as libc::c_ulong;
            if v.read_only {
                flags |= libc::MS_RDONLY as libc::c_ulong;
            }
            let ro_tgt = cstr(&format!("/proc/self/fd/{ro_fd}"))?; // decimal fd, but stated not asserted
            let r2 = unsafe {
                libc::mount(
                    ptr::null(),
                    ro_tgt.as_ptr(),
                    ptr::null(),
                    flags,
                    ptr::null(),
                )
            };
            unsafe { libc::close(ro_fd) };
            // Losing `nosuid` is not worth refusing to start for: `PR_SET_NO_NEW_PRIVS` already makes
            // the setuid bit inert in this box (see this function's doc), so the remount is depth and
            // not the guard. Losing `:ro` IS fatal - nothing else provides it.
            if r2 != 0 && v.read_only {
                let e = std::io::Error::last_os_error();
                result = Err(if e.raw_os_error() == Some(libc::EPERM) {
                    // EPERM on a bind remount-RO has more than one cause: the kernel may not support
                    // it at all (common on Android-kernel boards, where the root `--read-only` path
                    // sidesteps it by remounting the *overlay*, not a bind), OR a mount policy -
                    // e.g. SELinux, always on under an Android kernel - refused it. Don't assert one
                    // cause; list the alternatives so the message isn't misleading when it's a policy.
                    Error::Unsupported(
                        "read-only bind mount (:ro) failed with EPERM - this kernel may not support a \
                         bind remount-RO (common on Android-kernel boards), or a mount policy (e.g. \
                         SELinux) refused it. Alternatives: use --read-only for the box root \
                         (overlay-based, works on Android), or drop ':ro' to mount read-write. On a \
                         hardened/SELinux kernel, check your mount policy.",
                    )
                } else {
                    Error::Syscall("remount_ro(volume)", e)
                });
                break;
            }
        }
    }
    unsafe { libc::close(root_fd) };
    result
}

/// Resolve (creating as needed) `target` strictly *within* `root_fd`, refusing to traverse any
/// symlink (`O_NOFOLLOW` per component) - so the path can never escape the new root. Returns an
/// `O_PATH` fd to the final component (a directory, or a freshly-created empty file when
/// `is_dir` is false), suitable as a bind-mount target via `/proc/self/fd`.
fn open_in_root(root_fd: libc::c_int, target: &str, is_dir: bool) -> Result<libc::c_int, Error> {
    let comps: Vec<&str> = target.split('/').filter(|c| !c.is_empty()).collect();
    if comps.is_empty() {
        return Err(Error::Unsupported("volume target must not be the root"));
    }
    let mut dir = unsafe { libc::dup(root_fd) };
    if dir < 0 {
        return Err(Error::last("dup(root)"));
    }
    for (i, comp) in comps.iter().enumerate() {
        // Reject `.`/`..` so the target can't climb out of the new root: `O_NOFOLLOW` stops
        // symlinks, but `..` is a real directory and `openat` would walk it upward.
        if *comp == "." || *comp == ".." {
            unsafe { libc::close(dir) };
            return Err(Error::Unsupported(
                "volume target must not contain '.' or '..'",
            ));
        }
        let c = match cstr(comp) {
            Ok(c) => c,
            Err(e) => {
                unsafe { libc::close(dir) };
                return Err(e);
            }
        };
        let last = i == comps.len() - 1;
        if last && !is_dir {
            // Final component of a file volume: ensure it exists (no-follow), then return an
            // O_PATH fd. (O_PATH ignores O_CREAT, so the create is a separate open.)
            let cf = unsafe {
                libc::openat(
                    dir,
                    c.as_ptr(),
                    libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    0o644,
                )
            };
            if cf >= 0 {
                unsafe { libc::close(cf) };
            }
            let f = unsafe {
                libc::openat(
                    dir,
                    c.as_ptr(),
                    libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            unsafe { libc::close(dir) };
            if f < 0 {
                return Err(Error::last("openat(volume file target)"));
            }
            return Ok(f);
        }
        // Directory component: ensure it exists, then descend without following a symlink.
        unsafe { libc::mkdirat(dir, c.as_ptr(), 0o755) };
        let next = unsafe {
            libc::openat(
                dir,
                c.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        unsafe { libc::close(dir) };
        if next < 0 {
            // A symlink (or non-directory) on the path → refuse rather than escape the root.
            return Err(Error::last("openat(volume target component)"));
        }
        dir = next;
    }
    Ok(dir)
}

/// Wipe the inherited environment, set a small sane base, then layer the user's `--env` on top.
///
/// FAIL-CLOSED on the wipe: `clearenv` removes the INHERITED host environment (secrets, tokens,
/// `SSH_AUTH_SOCK`, kern internals like `KERN_SCOPE`) before the workload's minimal env is layered on.
/// If it could not clear, the box must NOT exec with the host env still visible - that is a silent
/// leak of host credentials into an untrusted workload. On the shipped musl target `clearenv` cannot
/// fail; the check pins the invariant and fails closed on any port whose libc behaves differently.
fn set_clean_env(hostname: &str, extra: &[(String, String)]) -> Result<(), Error> {
    if unsafe { libc::clearenv() } != 0 {
        return Err(Error::last("clearenv"));
    }
    set_env(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    set_env("HOME", "/root");
    set_env("TERM", "xterm");
    // ASK THE KERNEL WHEN THE CALLER DID NOT SAY. `exec_in_box` passes an empty name - it did not
    // create the namespace and does not know what was put in it - so every `kern exec` and every
    // health probe ran with `HOSTNAME=` while `hostname` printed the box's name correctly. Docker
    // sets it, and a check that reads it (Airflow's scheduler probe passes `"$${HOSTNAME}"` to
    // `airflow jobs check`) is comparing against an empty string. Reading it back from the UTS
    // namespace we are already in cannot drift from whatever actually set it.
    // `c_char` IS NOT THE SAME TYPE ON EVERY ARCHITECTURE, and this line is where it bit twice. It
    // is `i8` on x86_64 and `u8` on aarch64, so `[0i8; 256]` compiled here and did not compile at
    // all on the board targets; naming the libc type fixed that and then a per-byte `as u8` became
    // a no-op cast on aarch64, which `-D warnings` rejects in turn. Both are the same mistake:
    // hand-rolling what `CStr` already does portably. It reads the NUL-terminated buffer the kernel
    // just wrote, on every port, with no cast to be wrong about.
    let mut buf = [0 as libc::c_char; 256];
    let live = if hostname.is_empty()
        && unsafe { libc::gethostname(buf.as_mut_ptr(), buf.len() - 1) } == 0
    {
        // SAFE: `gethostname` returned 0, and `buf.len() - 1` left the final byte as the NUL it was
        // initialised to, so the buffer is NUL-terminated within its own bounds either way.
        unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    } else {
        String::new()
    };
    set_env(
        "HOSTNAME",
        if hostname.is_empty() { &live } else { hostname },
    );
    for (k, v) in extra {
        set_env(k, v);
    }
    Ok(())
}

fn set_env(key: &str, val: &str) {
    if let (Ok(k), Ok(v)) = (cstr(key), cstr(val)) {
        unsafe { libc::setenv(k.as_ptr(), v.as_ptr(), 1) };
    }
}

/// The safe host device nodes a sandbox needs. Deliberately NOT `/dev/tty` (a controlling
/// terminal enables TIOCSTI-style injection on unhardened kernels) and never `/dev/mem`, disks…
const DEV_NODES: [&str; 5] = ["null", "zero", "full", "random", "urandom"];

/// Create a mountpoint, mount `fstype` on it with the standard hardening, and REMOVE THE DIRECTORY
/// AGAIN if the mount does not take. Returns whether it took.
///
/// THE ARTIFACT RULE, IN ONE PLACE. A best-effort mount that leaves its mountpoint behind produces a
/// path that EXISTS and answers nothing: the failure then surfaces deep inside the workload, at the
/// `mq_open` or the `forkpty`, instead of at the one place that knew the mount did not happen. That
/// is the same shape as an `/etc/hosts` that exists and resolves no `localhost`, and the same shape
/// that made issue #8 appear at `forkpty(3)` rather than at box setup. The rule for every
/// best-effort mount here: the box sees the ARTIFACT of success, never the residue of an attempt.
///
/// EXTRACTED SO THE FAILURE BRANCH CAN BE TESTED WITHOUT A FAULT SWITCH. The alternative considered
/// and rejected was an env-gated failure injector in this path: it is new surface in box setup whose
/// only purpose is testability, and its shape ("a variable makes a mount not happen") invites
/// extension to mounts that ARE load-bearing. A function that takes the filesystem type by name is
/// testable by passing a type the kernel does not have, which is what the unit test does.
///
/// `rmdir`, not a recursive delete: the directory was created empty one syscall earlier and nothing
/// can have populated it, so recursion would only add a way to remove something else if the path
/// were ever wrong.
fn mount_or_leave_nothing(path: &str, fstype: &str) -> bool {
    let (Ok(p), Ok(ty)) = (cstr(path), cstr(fstype)) else {
        return false;
    };
    if unsafe { libc::mkdir(p.as_ptr(), 0o755) } != 0 {
        return false;
    }
    let ok = unsafe {
        libc::mount(
            ty.as_ptr(),
            p.as_ptr(),
            ty.as_ptr(),
            (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
            ptr::null(),
        )
    } == 0;
    if !ok {
        unsafe { libc::rmdir(p.as_ptr()) };
    }
    ok
}

/// Populate `<root>/dev` BEFORE pivot, while the host's `/dev` is still reachable at its real
/// path. A device node bound from the host's devtmpfs is only *writable* from an unprivileged
/// user namespace when bound by its real path (a post-pivot bind via `/proc/self/fd` leaves
/// `/dev/null` read-only - the workload can't `> /dev/null`), so the bind must happen here.
///
/// Symlink-safe: if the image ships `/dev` as a *symlink* (a hostile image pointing it at a host
/// path), it is removed first and replaced with a real directory, so the tmpfs mount and the
/// device binds all resolve to a directory we own *inside* the new root - never through the
/// symlink. For a normal (already-a-directory) `/dev` nothing is mutated: the tmpfs simply
/// shadows it, so the image/rootfs is left untouched.
/// Returns the PTY slave allocated from the BOX's own devpts, when `pty_sock` asked for one and the
/// box could produce it. `None` means the caller keeps whatever terminal it already had, which is
/// the pre-existing HOST pty: the terminal is a convenience and must never fail a box over it.
///
/// See [`crate::ptybox`] for why a box-owned slave is the difference between `tty(1)` working and
/// printing "not a tty" on every musl image.
fn setup_dev(
    root: &str,
    tun: bool,
    needs_pts: bool,
    tty_slave: Option<i32>,
    shm_size: Option<u64>,
    pty_sock: Option<i32>,
) -> Result<Option<i32>, Error> {
    let mut box_slave: Option<i32> = None;
    let dev_path = format!("{root}/dev");
    let dp = cstr(&dev_path)?;
    // Neutralize a hostile `/dev` symlink before any path resolves through it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(dp.as_ptr(), &mut st) } == 0
        && (st.st_mode & libc::S_IFMT) == libc::S_IFLNK
    {
        unsafe { libc::unlink(dp.as_ptr()) };
    }
    unsafe { libc::mkdir(dp.as_ptr(), 0o755) }; // EEXIST is fine for a normal /dev directory
                                                // A fresh tmpfs so device nodes live on a filesystem we own and the image's /dev is shadowed.
                                                // `mode=755` is essential: the tmpfs default root mode is 1777 (sticky + world-writable), and
                                                // with `fs.protected_regular` (≥1, default on most distros) an O_CREAT open of a node we don't
                                                // own in a sticky world-writable dir is rejected with EACCES - that breaks the universal
                                                // `cmd > /dev/null` redirect. A non-sticky 0755 /dev (owned by the box's root) avoids it.
    let ty = cstr("tmpfs")?;
    let opts = cstr("mode=755")?;
    // `MS_NOSUID`: a workload must never gain privilege via a setuid binary it drops on the box-owned
    // /dev tmpfs. (No `MS_NODEV` - /dev is exactly where the bind-mounted device nodes below must work;
    // this matches runc/Docker, which mount /dev `nosuid,mode=755` and deliberately NOT `nodev`.)
    if unsafe {
        libc::mount(
            ty.as_ptr(),
            dp.as_ptr(),
            ty.as_ptr(),
            libc::MS_NOSUID as libc::c_ulong,
            opts.as_ptr() as *const libc::c_void,
        )
    } != 0
    {
        return Err(Error::last("mount(/dev tmpfs)"));
    }
    // `/dev/tty` IS ABSENT ON PURPOSE, AND ABSENT IS NOT THE SAME AS CREATABLE.
    //
    // The device stays out for the reason on `DEV_NODES`, and that reason was re-measured rather than
    // taken on trust before this line was written. A box started WITHOUT `-it` from a shell that has a
    // terminal INHERITS the launcher's controlling terminal: measured under a real pty, the launcher
    // reads `tty_nr=34816` (`/dev/pts/0`) and the box's workload reads the SAME 34816. So a `/dev/tty`
    // inside the box would open the operator's own terminal, and `TIOCSTI` on it injects into the
    // shell the operator is typing at. The exclusion is load-bearing and is not being relaxed.
    //
    // What IS wrong is what happens next. `/dev` is a tmpfs the box's root owns, so `> /dev/tty`
    // CREATES a regular file: a program that writes a prompt there gets no error and the operator sees
    // nothing, and a later reader opens the file instead of failing. Reported by an outside reviewer
    // and reproduced here, `-rw-rw-r-- 2 bytes` where the host has `crw-rw-rw- 5, 0`. That is the
    // silent-success shape this codebase refuses everywhere else.
    //
    // A DIRECTORY is the answer that needs no device. `open(O_WRONLY)` on it is `EISDIR` whether or not
    // `O_CREAT` is passed, so a redirect fails loudly, `open(O_RDONLY)` succeeds but every `read` is
    // `EISDIR`, and `stat` reports something that is honestly not a character device. Nothing that
    // works today breaks: today the path does not exist, so the only behaviours are "silently created"
    // and `ENOENT`, and both become a hard error naming the path.
    //
    // Best-effort like the binds below: on a host where the `mkdir` fails, the box keeps exactly the
    // behaviour it had before this line.
    if let Ok(t) = cstr(&format!("{root}/dev/tty")) {
        unsafe { libc::mkdir(t.as_ptr(), 0o000) };
    }
    // Bind each node best-effort: a host that lacks one (or refuses the bind) just leaves that
    // node absent rather than failing the whole box. The tmpfs above is the load-bearing step.
    for node in DEV_NODES {
        let target = format!("{root}/dev/{node}");
        let src = format!("/dev/{node}");
        if let (Ok(t), Ok(s)) = (cstr(&target), cstr(&src)) {
            let f = unsafe {
                libc::open(
                    t.as_ptr(),
                    libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    0o666,
                )
            };
            if f >= 0 {
                unsafe { libc::close(f) };
            }
            unsafe {
                libc::mount(
                    s.as_ptr(),
                    t.as_ptr(),
                    ptr::null(),
                    libc::MS_BIND as libc::c_ulong,
                    ptr::null(),
                )
            };
        }
    }
    // `/dev/shm`: POSIX shared memory as a SEPARATE tmpfs, exactly like Docker/runc. Postgres' dynamic
    // shared memory, Python `multiprocessing`, Chromium and many runtimes open `/dev/shm/...`; without
    // this mount they fail "No such file or directory". `mode=1777` (sticky + world-writable) is the
    // standard shm mode so an unprivileged workload creates its OWN segments (which it then owns, so
    // `fs.protected_regular` doesn't bite). `MS_NOSUID|MS_NODEV`: shm never hosts a setuid binary or a
    // device node. The tmpfs is charged to the box's memory cgroup, so `--memory` bounds it and there is
    // no separate `--shm-size` footgun (Docker's 64 MB default is what breaks Postgres under load).
    // MEASURED, not assumed: on 5.15-tegra a `--memory 32m` box admits ~30 MB into an UNSIZED (3.7 GB,
    // half of host RAM) `/dev/shm` before ENOSPC, so the charge, not the tmpfs size, is the bound.
    // Best-effort: a host/kernel that refuses it just leaves the box without `/dev/shm` (prior behaviour).
    {
        let shmdir = format!("{root}/dev/shm");
        if let Ok(sd) = cstr(&shmdir) {
            unsafe { libc::mkdir(sd.as_ptr(), 0o1777) };
            // `size=` when we have one to give. The charge to the memory cgroup remains the real bound,
            // and that has not changed; what changes is what the box is TOLD. An unsized tmpfs reports
            // half the HOST's RAM through `statvfs`, so it both leaks a host fact into the box and lies
            // to every workload that sizes a buffer from the filesystem it is about to write - Postgres'
            // dynamic shared memory, Chromium, and a PyTorch DataLoader all do exactly that. A box under
            // `--memory 256m` was being told it had gigabytes.
            let opts = match shm_size {
                Some(n) => format!("mode=1777,size={n}"),
                None => "mode=1777".to_string(),
            };
            if let (Ok(ty), Ok(o)) = (cstr("tmpfs"), cstr(&opts)) {
                unsafe {
                    libc::mount(
                        ty.as_ptr(),
                        sd.as_ptr(),
                        ty.as_ptr(),
                        (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
                        o.as_ptr() as *const libc::c_void,
                    )
                };
            }
        }
    }
    // `-it`: bind the controlling-PTY SLAVE onto `/dev/console` (like runc/Docker), for the case
    // where the box could NOT build its own terminal and kept the host one.
    //
    // THIS USED TO BE THE WHOLE FIX, AND IT ONLY EVER WORKED UNDER ONE C LIBRARY. The host slave's
    // device is absent from the box's private devpts, so `ttyname()` has to find it some other way.
    // glibc's falls back to SCANNING `/dev` and finds this bind; musl's is a `readlink` of
    // `/proc/self/fd/0` plus a `stat`, with no fallback, so it returned ENOENT and `tty(1)` printed
    // "not a tty" on every alpine box while a Debian one looked correct. Measured on kern
    // 0.9.32-review.14, same box, two probes:
    //
    //     musl    ttyname_r FAILED rc=2      /proc/self/fd/0 -> /dev/pts/2, absent in the box
    //     glibc   ttyname_r = /dev/console   found by the scan
    //
    // The pair now comes from the box's OWN devpts (see [`crate::ptybox`]), which both libraries
    // resolve, and this bind is what is left for a box that could not make one. Kept rather than
    // removed for exactly that case. Best-effort: a failure never breaks the box.
    if let Some(slave) = tty_slave {
        let mut buf = [0u8; 256];
        if let Ok(link) = cstr(&format!("/proc/self/fd/{slave}")) {
            let n =
                unsafe { libc::readlink(link.as_ptr(), buf.as_mut_ptr().cast(), buf.len() - 1) };
            if n > 0 {
                let src = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
                let target = format!("{root}/dev/console");
                if let (Ok(t), Ok(s)) = (cstr(&target), cstr(&src)) {
                    let f = unsafe {
                        libc::open(
                            t.as_ptr(),
                            libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                            0o600,
                        )
                    };
                    if f >= 0 {
                        unsafe { libc::close(f) };
                    }
                    unsafe {
                        libc::mount(
                            s.as_ptr(),
                            t.as_ptr(),
                            ptr::null(),
                            libc::MS_BIND as libc::c_ulong,
                            ptr::null(),
                        )
                    };
                }
            }
        }
    }
    // `/dev/mqueue`: POSIX message queues as their own filesystem, exactly like Docker/runc mount it.
    // `mq_open(3)` resolves names under this mount, so without it every POSIX-mqueue call fails
    // ENOENT/ENOSYS rather than working - it is not a fallback the C library can emulate. Nothing
    // host-global is exposed: the mount is scoped to the box's IPC namespace, which kern already
    // unshares, so the queues a box creates are invisible to the host and to sibling boxes and die
    // with the namespace.
    //
    // NOSUID|NODEV|NOEXEC for the same reason as `/dev/shm`: a filesystem the workload can create
    // files in must never host a setuid binary, a device node, or an executable page. Best-effort - a
    // kernel built without CONFIG_POSIX_MQUEUE, or one that refuses the mount, leaves the box without
    // `/dev/mqueue` (the behaviour before this existed) instead of failing the box.
    // THE DIRECTORY IS REMOVED WHEN THE MOUNT FAILS, and that is not tidiness. A best-effort mount
    // that leaves its mountpoint behind produces a path that EXISTS and answers nothing: `mq_open`
    // then fails deep inside the workload instead of at the one place that knows the mount did not
    // happen. It is the same shape as an `/etc/hosts` that exists and resolves no `localhost`, and
    // the same shape that made #8 surface at `forkpty(3)` rather than at box setup. `devpts` above
    // already keys its `/dev/ptmx` symlink on the mount result, so its artifact is honest too: the
    // rule for every best-effort mount here is that the box must see the ARTIFACT of success, never
    // the residue of an attempt.
    mount_or_leave_nothing(&format!("{root}/dev/mqueue"), "mqueue");
    // Standard `/dev` symlinks into procfs - `/dev/fd`, `/dev/std{in,out,err}` - exactly as Docker/runc
    // provide them. Bash/shell process substitution (`<(...)` → `/dev/fd/63`) and many entrypoints
    // (e.g. postgres `initdb`) need them; without `/dev/fd` they fail "No such file or directory". They
    // resolve through the box's own `/proc` (mounted for its PID namespace), so they're safe and correct.
    for (link, tgt) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        if let (Ok(l), Ok(t)) = (cstr(&format!("{root}/dev/{link}")), cstr(tgt)) {
            unsafe { libc::symlink(t.as_ptr(), l.as_ptr()) };
        }
    }
    // devpts: a PRIVATE pty instance at `/dev/pts` + a `/dev/ptmx` multiplexer, so programs INSIDE
    // the box can allocate a controlling terminal - most importantly the in-box sshd for `--ssh`
    // (interactive `ssh box` otherwise fails "PTY allocation request failed"), plus screen/tmux/script.
    // A user namespace is allowed to mount devpts. `newinstance` = a pty namespace private to this box;
    // `ptmxmode=0666` lets the unprivileged workload open the multiplexer. NOSUID|NOEXEC harden it; no
    // `gid=` (group 5 isn't mapped in a single-uid box, which would EINVAL the mount). Best-effort - a
    // host/kernel that refuses it just leaves the box without in-box PTYs (kern's own `-it` uses a HOST
    // pty and is unaffected).
    // Stood up for EVERY box, on the same reasoning as `/dev/shm` a few lines above: what the
    // workload may open is not what kern was asked for. kern's own `-it` uses a HOST pty and never
    // needed this; the caller who does is the process INSIDE the box. Measured cost of doing it
    // unconditionally, 40 alternated runs per binary on one host: +0.03 ms median on a bare box,
    // +1.1%. See the `needs_pts` binding for what that saving used to buy.
    if needs_pts {
        let ptsdir = format!("{root}/dev/pts");
        if let Ok(pd) = cstr(&ptsdir) {
            unsafe { libc::mkdir(pd.as_ptr(), 0o755) };
            if let (Ok(ty), Ok(opts)) = (cstr("devpts"), cstr("newinstance,ptmxmode=0666")) {
                let ok = unsafe {
                    libc::mount(
                        ty.as_ptr(),
                        pd.as_ptr(),
                        ty.as_ptr(),
                        (libc::MS_NOSUID | libc::MS_NOEXEC) as libc::c_ulong,
                        opts.as_ptr() as *const libc::c_void,
                    )
                } == 0;
                // `/dev/ptmx` → `pts/ptmx`: `openpty()`/sshd open `/dev/ptmx` to get a new pty pair.
                if ok {
                    if let (Ok(px), Ok(tgt)) = (cstr(&format!("{root}/dev/ptmx")), cstr("pts/ptmx"))
                    {
                        unsafe { libc::symlink(tgt.as_ptr(), px.as_ptr()) };
                    }
                    // THE BOX'S OWN TERMINAL, and this is the earliest moment one can exist: the
                    // mount above is what makes `/dev/ptmx` mean anything here. Allocated now,
                    // pre-pivot, so the slave's path is `<root>/dev/pts/N` and becomes `/dev/pts/N`
                    // the moment the box takes that root - a path that RESOLVES inside the box.
                    //
                    // The host pair the CLI opened stays exactly where it is until the master
                    // reaches it. Only when both halves of the handover succeed does the caller
                    // switch, so a failure anywhere here is the old behaviour and not a broken box.
                    if let Some(sock) = pty_sock {
                        box_slave = crate::ptybox::hand_over_pair(&format!("{root}/dev"), sock);
                    }
                }
            }
        }
    }
    // `--tun`: bind `/dev/net/tun` into the box (WireGuard / userspace VPN). The box owns its network
    // namespace, so a workload can create the tunnel interface; the `/dev/net` dir is created on the
    // box-owned `/dev` tmpfs so the bind can't be redirected by a hostile image symlink. Best-effort:
    // a host without the `tun` module simply leaves the node absent.
    if tun {
        let netdir = format!("{root}/dev/net");
        if let Ok(nd) = cstr(&netdir) {
            unsafe { libc::mkdir(nd.as_ptr(), 0o755) };
        }
        let target = format!("{root}/dev/net/tun");
        if let (Ok(t), Ok(s)) = (cstr(&target), cstr("/dev/net/tun")) {
            let f = unsafe {
                libc::open(
                    t.as_ptr(),
                    libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    0o666,
                )
            };
            if f >= 0 {
                unsafe { libc::close(f) };
            }
            unsafe {
                libc::mount(
                    s.as_ptr(),
                    t.as_ptr(),
                    ptr::null(),
                    libc::MS_BIND as libc::c_ulong,
                    ptr::null(),
                )
            };
        }
    }
    Ok(box_slave)
}

/// Expose a `vgpio:` profile's host devices in the box. Device nodes are bound into the box's own
/// `/dev` tmpfs (created by `setup_dev` - box-owned, so binding into it can't be redirected by a
/// hostile image symlink). If the profile needs sysfs peripherals (pwm/adc/1-wire/leds), a fresh
/// box-owned `/sys` tmpfs is created (shadowing any image `/sys`, deny-by-default) and only the
/// requested directories are bound in. Runs BEFORE pivot while the host sources are reachable.
/// Best-effort per entry: a device absent on this host is simply skipped.
fn setup_vgpio(root: &str, devs: &[String], sysfs: &[String]) -> Result<(), Error> {
    for dev in devs {
        if let Some(rel) = dev.strip_prefix("/dev/") {
            bind_into(root, "dev", rel, dev, false);
        }
    }
    if sysfs.is_empty() {
        return Ok(());
    }
    make_box_tmpfs(root, "sys")?;
    for s in sysfs {
        if let Some(rel) = s.strip_prefix("/sys/") {
            bind_into(root, "sys", rel, s, true);
        }
    }
    Ok(())
}

/// If `path` is a symlink, remove it - so a hostile image can't redirect a mkdir/mount we're about to
/// perform on it (used pre-pivot, where paths still resolve through the host root). Best-effort.
fn unlink_if_symlink(path: &str) {
    if let Ok(p) = cstr(path) {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::lstat(p.as_ptr(), &mut st) } == 0
            && (st.st_mode & libc::S_IFMT) == libc::S_IFLNK
        {
            unsafe { libc::unlink(p.as_ptr()) };
        }
    }
}

/// Create a fresh box-owned tmpfs at `<root>/<leaf>`, neutralising a hostile symlink first (mirrors
/// `setup_dev`'s `/dev` handling). Used for `/sys` when a vGPIO profile needs sysfs peripherals, and
/// for the wide `/run` tmpfs the `--ssh` path needs. `NOSUID|NODEV`: a box tmpfs never hosts a setuid
/// binary or a device node (parity with the vdisk/secrets mounts).
fn make_box_tmpfs(root: &str, leaf: &str) -> Result<(), Error> {
    let path = format!("{root}/{leaf}");
    let p = cstr(&path)?;
    unlink_if_symlink(&path);
    unsafe { libc::mkdir(p.as_ptr(), 0o755) };
    let ty = cstr("tmpfs")?;
    let opts = cstr("mode=755")?;
    if unsafe {
        libc::mount(
            ty.as_ptr(),
            p.as_ptr(),
            ty.as_ptr(),
            (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
            opts.as_ptr() as *const libc::c_void,
        )
    } != 0
    {
        return Err(Error::last("mount(vgpio /sys tmpfs)"));
    }
    Ok(())
}

/// Open a `/dev/...` device node by walking the path ONE component at a time from `/dev`, each hop an
/// `openat(O_PATH|O_NOFOLLOW)`. A plain `open(path, O_NOFOLLOW)` only guards the FINAL component - an
/// intermediate symlink is still followed - so a component swapped to a symlink at any depth could
/// redirect the bind. Walking each hop with `O_NOFOLLOW` closes that TOCTOU *by construction* (not by
/// trusting a pre-canonicalized string): every hop is atomic against its parent fd, `..` is refused,
/// and the walk can't leave `/dev`. Returns the pinned leaf fd (the caller fstat-checks it and binds
/// from `/proc/self/fd`), or `None` if the path is absent / a component was swapped to a symlink.
fn open_dev_pinned(src: &str) -> Option<i32> {
    let rest = src.strip_prefix("/dev/")?;
    let dev = cstr("/dev").ok()?;
    let mut cur = unsafe {
        libc::open(
            dev.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if cur < 0 {
        return None;
    }
    let comps: Vec<&str> = rest
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    for (i, comp) in comps.iter().enumerate() {
        if *comp == ".." {
            unsafe { libc::close(cur) };
            return None; // never traverse out of /dev
        }
        let last = i + 1 == comps.len();
        let mut flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        if !last {
            flags |= libc::O_DIRECTORY; // every non-final hop must be a real directory
        }
        let Ok(c) = cstr(comp) else {
            unsafe { libc::close(cur) };
            return None;
        };
        let next = unsafe { libc::openat(cur, c.as_ptr(), flags) };
        unsafe { libc::close(cur) };
        if next < 0 {
            return None; // absent, or a component swapped to a symlink (O_NOFOLLOW → ELOOP)
        }
        cur = next;
    }
    Some(cur)
}

/// Bind host `src` onto `<root>/<base>/<rel>`, creating the parent chain and leaf target inside the
/// box-owned `<base>` tmpfs (so target creation can't be redirected by a hostile symlink). `is_dir`
/// selects a recursive directory bind vs a device-node file bind. Best-effort; a `..`/empty
/// component in `rel` is refused (defence-in-depth - sources are already sanitised).
fn bind_into(root: &str, base: &str, rel: &str, src: &str, is_dir: bool) {
    let comps: Vec<&str> = rel.split('/').collect();
    if comps.iter().any(|c| *c == ".." || c.is_empty()) {
        return;
    }
    // mkdir -p the parents under <root>/<base>.
    let mut cur = format!("{root}/{base}");
    for c in &comps[..comps.len() - 1] {
        cur.push('/');
        cur.push_str(c);
        if let Ok(cp) = cstr(&cur) {
            unsafe { libc::mkdir(cp.as_ptr(), 0o755) };
        }
    }
    let target = format!("{root}/{base}/{rel}");
    let (Ok(t), Ok(s)) = (cstr(&target), cstr(src)) else {
        return;
    };
    if is_dir {
        unsafe { libc::mkdir(t.as_ptr(), 0o755) };
        unsafe {
            libc::mount(
                s.as_ptr(),
                t.as_ptr(),
                ptr::null(),
                (libc::MS_BIND | libc::MS_REC) as libc::c_ulong,
                ptr::null(),
            )
        };
    } else {
        // Create the target node inside the box-owned tmpfs (O_NOFOLLOW: a hostile image symlink at
        // the target can't redirect where we create it).
        let f = unsafe {
            libc::open(
                t.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o666,
            )
        };
        if f >= 0 {
            unsafe { libc::close(f) };
        }
        // TOCTOU-safe SOURCE: walk `/dev/...` one hop at a time (open_dev_pinned) so the fd PINS the
        // exact inode with NO intermediate symlink followed at any depth, then bind FROM the fd via
        // /proc/self/fd - a component swapped between the resolver's check and this mount can't redirect
        // us. Re-check on the pinned fd that it's neither a BLOCK device (a host disk) nor a dangerous
        // raw CHAR node.
        let sfd = match open_dev_pinned(src) {
            Some(fd) => fd,
            None => return, // absent, escapes /dev, or a component was swapped to a symlink → skip
        };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let fstat_ok = unsafe { libc::fstat(sfd, &mut st) } == 0;
        let mode = st.st_mode & libc::S_IFMT;
        let is_block = mode == libc::S_IFBLK;
        // Mirror the resolver's `is_dangerous_dev` FIXED-identity deny at BIND time: raw memory (major
        // 1, minors mem/kmem/port/kmsg = {1,2,4,11,12}), generic SCSI (major 21), and the stable misc
        // majors `/dev/kvm` (10:232) and `/dev/net/tun` (10:200). If host root swapped a vetted char
        // node for a dangerous one between the parent's resolve and this child's bind, the pinned-fd
        // re-check still refuses it - so this gate matches its claim, not just block nodes. (Only the
        // stable major:minor identities can be re-checked here; name/dynamic-major nodes rely on the
        // resolve-time check + no-symlink-follow pin. Legit vgpio devices - gpiochip, i2c 89, spi - are
        // unaffected.)
        let is_dangerous_char = mode == libc::S_IFCHR && {
            let maj = libc::major(st.st_rdev);
            let min = libc::minor(st.st_rdev);
            (maj == 1 && matches!(min, 1 | 2 | 4 | 11 | 12))
                || maj == 21
                || (maj == 10 && matches!(min, 232 | 200))
        };
        if fstat_ok && !is_block && !is_dangerous_char {
            if let Ok(fdpath) = cstr(&format!("/proc/self/fd/{sfd}")) {
                unsafe {
                    libc::mount(
                        fdpath.as_ptr(),
                        t.as_ptr(),
                        ptr::null(),
                        libc::MS_BIND as libc::c_ulong,
                        ptr::null(),
                    )
                };
            }
        }
        unsafe { libc::close(sfd) };
    }
}

/// Mount each `vdisk:` profile at `/vdisk/<name>` in the box. A privileged ext4-on-loop mount, when
/// the host prepared one (`host_dir`), is bind-mounted in; otherwise a `size=`-capped `tmpfs` is
/// mounted (rootless - RAM-backed, ephemeral). Runs before pivot. The mount is a *separate* mount,
/// so a vdisk stays writable even under `--read-only` (a vdisk is scratch space by design).
/// Best-effort per entry.
fn setup_vdisk(root: &str, vdisks: &[VdiskMount]) -> Result<(), Error> {
    if vdisks.is_empty() {
        return Ok(());
    }
    // A fresh box-owned `/vdisk` tmpfs (symlink-neutralized) so every per-disk mkdir/mount target is
    // created inside a filesystem we own - a hostile image shipping `/vdisk` (or `/vdisk/<name>`) as
    // a symlink can't redirect a vdisk mount to a host path. Mirrors `setup_dev`'s `/dev` handling.
    make_box_tmpfs(root, "vdisk")?;
    for vd in vdisks {
        // The name is a single path component (validated at the CLI); guard defensively.
        if vd.name.is_empty() || vd.name.contains('/') || vd.name.contains("..") {
            continue;
        }
        let Ok(t) = cstr(&format!("{root}/vdisk/{}", vd.name)) else {
            continue;
        };
        unsafe { libc::mkdir(t.as_ptr(), 0o755) };
        // A vdisk is untrusted scratch: never honour a device node or setuid binary living on it.
        let hardening = (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong;
        match &vd.host_dir {
            // Privileged ext4-loop mount prepared on the host → bind it in, then remount to LOCK
            // nosuid/nodev on the bind (a first bind ignores those flags - they need MS_REMOUNT).
            Some(src) => {
                if let Ok(s) = cstr(src) {
                    unsafe {
                        libc::mount(
                            s.as_ptr(),
                            t.as_ptr(),
                            ptr::null(),
                            (libc::MS_BIND | libc::MS_REC) as libc::c_ulong,
                            ptr::null(),
                        );
                        libc::mount(
                            ptr::null(),
                            t.as_ptr(),
                            ptr::null(),
                            (libc::MS_REMOUNT | libc::MS_BIND) as libc::c_ulong | hardening,
                            ptr::null(),
                        );
                    }
                }
            }
            // Rootless: a size-capped tmpfs.
            None => {
                let opts = match vd.size {
                    Some(n) => format!("size={n},mode=0755"),
                    None => "mode=0755".to_string(),
                };
                let ty = cstr("tmpfs")?;
                if let Ok(o) = cstr(&opts) {
                    unsafe {
                        libc::mount(
                            ty.as_ptr(),
                            t.as_ptr(),
                            ty.as_ptr(),
                            hardening,
                            o.as_ptr() as *const libc::c_void,
                        )
                    };
                }
            }
        }
    }
    Ok(())
}

/// Mount each `--tmpfs PATH[:size]` as a fresh tmpfs inside the box (pre-pivot, `<root>/PATH`).
/// `NOSUID|NODEV` - a scratch tmpfs never hosts a device node or setuid binary. The CLI already
/// blocked the hardened mounts (`/proc`, `/sys`, `/dev`) and validated the path/size. Best-effort per
/// entry; the mountpoint's parents are created on the way in.
fn setup_tmpfs(root: &str, entries: &[TmpfsMount]) -> Result<(), Error> {
    for m in entries {
        let path = &m.path;
        // Defence-in-depth: the CLI guarantees an absolute, `..`-free path, but re-check before it
        // becomes a host-resolved (pre-pivot) mount target.
        if !path.starts_with('/') || path.split('/').any(|c| c == "..") {
            continue;
        }
        let full = format!("{root}{path}");
        // mkdir -p the target chain inside the new root - pre-pivot, so paths resolve through the
        // HOST root. Neutralize a symlink at EACH component first: a hostile image shipping an
        // intermediate dir (or the leaf) as a symlink could otherwise redirect the mkdir/mount out of
        // the rootfs. Same discipline as `setup_dev`/`setup_secrets`.
        let mut cur = root.to_string();
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            cur.push('/');
            cur.push_str(comp);
            unlink_if_symlink(&cur);
            if let Ok(c) = cstr(&cur) {
                unsafe { libc::mkdir(c.as_ptr(), 0o755) };
            }
        }
        // MODE IS THE CALLER'S, SIZE IS THE CALLER'S, THE HARDENING IS NOT.
        //
        // `mode=1777` stays the DEFAULT because that is what a scratch `/tmp` has to be, and it is
        // what every box got before this was configurable. A file that writes `mode=0755` (a
        // Postgres socket directory, in the corpus this came from) gets 0755, because that is a
        // property of the directory and not of the confinement.
        //
        // `MS_NOSUID | MS_NODEV` ARE NOT NEGOTIABLE and are OR-ed in unconditionally. A `suid` or
        // `dev` token in a compose file is a request for kern to be less confining than it is, and
        // the flag parser names it as recognised-and-never-applied rather than acting on it. That
        // is the same treatment `privileged: true` gets, and for the same reason: the alternative is
        // a runtime whose isolation is decided by the file it is handed.
        //
        // `MS_NOEXEC` and `MS_RDONLY` ARE the caller's: neither weakens the box (both only remove
        // capability from the mount), and `noexec` on `/tmp` is a hardening measure real files ask
        // for.
        let mut opts = String::with_capacity(48);
        if !m.size.is_empty() {
            opts.push_str("size=");
            opts.push_str(&m.size);
            opts.push(',');
        }
        opts.push_str("mode=");
        opts.push_str(if m.mode.is_empty() { "1777" } else { &m.mode });
        // `uid=`/`gid=` LAST, so the retry below can cut them off by truncating the string rather
        // than rebuilding it. Kept out of the string entirely when the file named neither.
        let without_ids = opts.len();
        if !m.uid.is_empty() {
            opts.push_str(",uid=");
            opts.push_str(&m.uid);
        }
        if !m.gid.is_empty() {
            opts.push_str(",gid=");
            opts.push_str(&m.gid);
        }
        let mut hardening = (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong;
        if m.noexec {
            hardening |= libc::MS_NOEXEC as libc::c_ulong;
        }
        if m.read_only {
            hardening |= libc::MS_RDONLY as libc::c_ulong;
        }
        let Ok(t) = cstr(&full) else { continue };
        let Ok(ty) = cstr("tmpfs") else { continue };
        let mounted = match cstr(&opts) {
            Ok(o) => {
                // SAFETY: three NUL-terminated strings that outlive the call, and a flag word built
                // from libc constants.
                unsafe {
                    libc::mount(
                        ty.as_ptr(),
                        t.as_ptr(),
                        ty.as_ptr(),
                        hardening,
                        o.as_ptr() as *const libc::c_void,
                    ) == 0
                }
            }
            Err(_) => false,
        };
        // THE RETRY EXISTS BECAUSE THE FALL-BACK MUST NOT BE THE MISSING MOUNT. A tmpfs in a user
        // namespace takes only an id that namespace MAPS, and a box without `--uid-range` maps
        // exactly one: `uid=10001` from a real compose file then fails the mount with `EINVAL` and
        // the workload finds no directory at all. Asking for an ownership kern cannot give must
        // cost the ownership, not the mount.
        if !mounted && opts.len() > without_ids {
            opts.truncate(without_ids);
            let retried = match cstr(&opts) {
                // SAFETY: as above, with the shortened option string.
                Ok(o) => unsafe {
                    libc::mount(
                        ty.as_ptr(),
                        t.as_ptr(),
                        ty.as_ptr(),
                        hardening,
                        o.as_ptr() as *const libc::c_void,
                    ) == 0
                },
                Err(_) => false,
            };
            if retried {
                eprintln!(
                    "kern: note: --tmpfs '{}': uid=/gid= were refused by the kernel (a user \
                     namespace accepts only the ids it maps; `--uid-range` maps more), so the mount \
                     is there and owned by the box's own identity",
                    m.path
                );
            }
        }
    }
    Ok(())
}

/// Append `--add-host NAME:IP` entries to the box's `/etc/hosts` (Docker parity). Best-effort,
/// pre-pivot, writing into the box's OWN root (an overlay copy-up, not the shared image). The path is
/// resolved with [`open_in_root`], which refuses a symlink at EVERY component (not just the final one)
/// and rejects `.`/`..` - so a hostile image shipping `/etc` OR `/etc/hosts` as a symlink can't redirect
/// the append out of the box root (this runs pre-pivot, where a naive open would resolve through the
/// HOST root). Content is guarded too: an entry whose name or IP carries whitespace/control is skipped,
/// so a crafted value can't inject extra `/etc/hosts` lines.
/// Give a box the `/etc/hosts` that every container runtime provides.
///
/// Images do not ship one (`python:3.12-slim` and the whole debian family do not): docker writes it
/// at run time, and kern only did so for pod members, whose `/etc/hosts` is the pod's shared file
/// bind-mounted over this path. A standalone box got nothing, so glibc went `files` then `dns`,
/// found no file, and a box without outbound has no DNS either. Measured before this existed:
/// `getaddrinfo("localhost")` failed with `EAI_AGAIN` in a plain box. That breaks anything talking
/// to itself by name (a daemon serving a UI on a port, a health check hitting `http://localhost`)
/// and anything resolving its OWN hostname at startup, which the JVM, Postgres and RabbitMQ do.
///
/// Seeds an ABSENT-or-EMPTY file only, which leaves the two working cases untouched: an image that
/// ships its own, and the pod bind, whose file already carries these two localhost lines plus every
/// peer's name. `setup_extra_hosts` appends after this, so `--add-host` entries land under the
/// seeds instead of into an empty file.
/// The three `/sys/devices/system/cpu` files a modern allocator reads before it will run.
///
/// WITHOUT THEM, WIDELY-USED IMAGES ABORT BEFORE THEIR FIRST INSTRUCTION. A kern box mounts no
/// `sysfs` at all (measured: no `/sys` line in the box's `/proc/mounts`), and recent tcmalloc calls
/// `NumPossibleCPUs` at startup, finds nothing to read, and fails a `CHECK`. MEASURED on the
/// official `mongo:latest` image, which is one of the most common services in any compose file:
///
/// ```text
/// tcmalloc/internal/sysinfo.cc:123] CHECK in NumPossibleCPUsNoCache: cpus.has_value() (false)
/// ```
///
/// The experiment that made this a fact rather than a guess: the same image, same box, with a
/// directory holding these three files bind-mounted at that path, got PAST the abort and failed on
/// something else entirely (MongoDB refusing kernel 6.19+, which is MongoDB's own limit and happens
/// under Docker too). One variable, two outcomes.
///
/// PLAIN FILES, NOT A `sysfs`, AND NOT THE HOST'S. Docker mounts the host's real `/sys` read-only,
/// which hands a container the whole machine's topology; kern writes three files into the box's own
/// root, so nothing about the host is exposed beyond the CPU RANGE the box is allowed to run on.
/// When `--cpuset-cpus` names a set, that set is what the box is told - which is MORE truthful than
/// Docker, where a capped container still reads the host's full list and sizes its thread pools for
/// CPUs it will never get.
///
/// DELIBERATELY THREE FILES AND NOTHING ELSE. This is not an emulated `sysfs` and must not grow into
/// one: every addition is another host fact leaving the machine. If an image needs more than the CPU
/// range, it needs a real `sysfs`, and that is a different decision from this one.
///
/// Best-effort in every branch, like its neighbours: a box that cannot be given these still starts,
/// exactly as it did before they existed.
fn setup_cpu_topology(root: &str, cpuset: Option<&str>) {
    // The range the box may run on. A `--cpuset-cpus` is already validated as a CPU list by the CLI;
    // without one, the host's own `possible` line is the truthful answer, and `0` is the floor for a
    // host that will not say (a machine always has at least one CPU, and an EMPTY file is what the
    // allocator already cannot parse).
    let range = match cpuset {
        Some(c) if !c.trim().is_empty() => c.trim().to_string(),
        _ => std::fs::read_to_string("/sys/devices/system/cpu/possible")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "0".to_string()),
    };
    // A value that travels into a file an allocator parses: digits, `-` and `,` only. Anything else
    // would be a range nothing can read, which is the state this function exists to leave behind.
    if !range
        .bytes()
        .all(|b| b.is_ascii_digit() || b == b'-' || b == b',')
    {
        return;
    }
    let dir = format!("{root}/sys/devices/system/cpu");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    for f in ["possible", "present", "online"] {
        let _ = std::fs::write(format!("{dir}/{f}"), format!("{range}\n"));
    }
}

/// Write the two `/etc` files a container runtime owns: `/etc/hosts` and `/etc/hostname`.
///
/// WHY BOTH IN ONE FUNCTION, AND WHY NOT `open_in_root`
///     Both files live in the same directory, so the symlink-safe descent to `etc` is walked ONCE
///     and each file is then opened with a single `openat` from that directory fd. The earlier shape
///     called `open_in_root` per file, which returns an `O_PATH` fd (what a bind-mount TARGET needs)
///     and therefore forced a reopen through `/proc/self/fd/<n>` to get something writable: a full
///     path resolution per file, for a plain write that never needed one. Two root opens, two
///     descents and two `/proc` resolutions became one descent and two `openat`s.
///
/// THE GUARANTEE IS UNCHANGED
///     `O_NOFOLLOW` on `etc` (with `O_DIRECTORY`) and on each final component, from a fd rooted at
///     the box root, is exactly what the per-component walk enforced: a symlinked `/etc`, `/etc/hosts`
///     or `/etc/hostname` is refused rather than followed out of the box root. `..` cannot appear
///     because the components are literals here, not caller input.
///
/// `/etc/hosts` IS SEEDED, `/etc/hostname` IS OVERWRITTEN
///     Images ship neither a useful hosts file nor a correct hostname. `python:3.12-slim` and the
///     debian family carry NO `/etc/hosts` at all, so glibc went `files` then `dns`, found no file,
///     and a box without outbound has no DNS either: measured before this existed,
///     `getaddrinfo("localhost")` failed with `EAI_AGAIN`, which breaks anything that talks to itself
///     by name (a daemon serving a UI on a port, a health check on `http://localhost`) and anything
///     resolving its OWN hostname at startup, which the JVM, Postgres and RabbitMQ do. Hosts is
///     seeded only when ABSENT-OR-EMPTY, which leaves untouched an image that ships its own and the
///     pod bind, whose shared file already carries these lines plus every peer name.
///     `/etc/hostname` is different: the file an image ships is a fact about the machine that BUILT
///     the image (`debuerreotype` on the debian family), never about this box, and `HOSTNAME` and
///     `uname -n` were already correct, so the file was the only one of the three that disagreed.
///     It is truncated and rewritten. Safe on every rootfs kern accepts: `--rootfs` is overlayed,
///     verified by removing a file inside a box and finding the host directory untouched.
///
/// Best-effort in every branch: no failure here fails the box, and `setup_extra_hosts` appends
/// `--add-host` entries after this, so they land under the seeds instead of into an empty file.
fn setup_etc_identity(root: &str, hostname: &str) {
    /// The two lines every runtime seeds, byte-identical to what the pod's shared file carries so a
    /// standalone box and a pod member cannot disagree about `localhost`.
    ///
    /// `localhost` IS ON THE IPv4 LINE ONLY, which is podman's spelling and NOT Docker's. A
    /// deliberate deviation, and the one place in this file where matching Docker would be the wrong
    /// thing to do.
    ///
    /// MEASURED, three runtimes, one image (`python:3.12-alpine`, an IPv4-only listener, the check
    /// `wget -O- http://localhost:5000/` that real compose files are full of):
    ///
    /// * podman: hosts file reads `::1 ip6-localhost ip6-loopback`, `wget` returns 0.
    /// * Docker 29.6.2: hosts file reads `::1 localhost ip6-localhost ip6-loopback`, the container's
    ///   `disable_ipv6` is `0` and `lo` HAS `::1` - and `wget http://localhost:5000/` FAILS while
    ///   `http://127.0.0.1:5000/` returns 0. Docker has the defect too.
    /// * kern before this: same as Docker, for the same reason.
    ///
    /// A previous version of this comment explained the difference by saying a Docker container has
    /// IPv6 switched off, so its `::1` is demoted by musl's address sorting. That explanation is
    /// WRONG, and the Docker measurement above is what killed it: IPv6 is on there and the check
    /// fails anyway. What is actually true is smaller and does not need a theory about Docker: with
    /// both records present musl prefers `::1`, busybox's `wget` uses the first address only, and an
    /// IPv4-only listener is then unreachable by name. podman avoids it by not claiming the name for
    /// `::1`, and kern does the same. The IPv6 loopback keeps its own names, which is what anything
    /// asking for IPv6 by name uses.
    const LOCALHOST_SEED: &[u8] = b"127.0.0.1\tlocalhost\n::1\tip6-localhost ip6-loopback\n";
    /// Prefix of the box's own entry. Split from the name so neither has to be copied to be written.
    const SELF_PREFIX: &[u8] = b"127.0.0.1\t";
    /// What an `/etc/hosts` must already contain for kern to leave it alone.
    const LOCALHOST: &[u8] = b"localhost";

    let h = hostname.trim();
    let name_ok = !h.is_empty() && !h.chars().any(|c| c.is_whitespace() || c.is_control());

    let Ok(rc) = cstr(root) else {
        return;
    };
    let root_fd = unsafe {
        libc::open(
            rc.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return;
    }
    // Descend into `etc` once. `mkdirat` first so a rootfs without one still works; `O_NOFOLLOW`
    // refuses a symlinked `/etc` rather than following it out of the box root.
    let Ok(etc) = cstr("etc") else {
        unsafe { libc::close(root_fd) };
        return;
    };
    unsafe { libc::mkdirat(root_fd, etc.as_ptr(), 0o755) };
    // Open `etc` as a REAL directory fd, not `O_PATH`. `openat(2)` accepts an `O_PATH` descriptor as
    // its `dirfd`, which is what `root_fd` is, so the descent needs no `/proc/self/fd` round trip:
    // an earlier shape took the `O_PATH` fd here and reopened it by name through procfs to get
    // something usable as a `dirfd`, and that reopen is a full path resolution. Measured with
    // `KERN_TIMING=1`, 60 alternated runs per binary: the `volumes` phase went 2 -> 72 us with the
    // procfs reopen in place, against 24 us for the two mounts this change also added, so the
    // resolution cost three times what the mounts did. `O_NOFOLLOW` still refuses a symlinked `/etc`.
    let dir_fd = unsafe {
        libc::openat(
            root_fd,
            etc.as_ptr(),
            libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    unsafe { libc::close(root_fd) };
    if dir_fd < 0 {
        return;
    }

    // --- /etc/hosts: append the seeds unless the file ALREADY RESOLVES `localhost` ----------------
    //
    // The predicate is "does this file answer the question", not "is this file empty". Size zero was
    // the first cut and it is the same mistake this project has made twice before on the sibling
    // file: `resolv.conf` was once gated on `exists()`, which debian satisfies with an EMPTY file,
    // and then on non-empty, which a comments-only file satisfies while naming no nameserver. An
    // `/etc/hosts` carrying nothing but comments exists, is non-empty, and still leaves
    // `getaddrinfo("localhost")` failing. So the file is read and the seeds are appended unless a
    // `localhost` entry is already there.
    //
    // O_APPEND, not O_TRUNC: whatever an image put there is kept and the seeds go under it, which is
    // also what makes this safe against the pod bind. That shared file always carries `localhost`,
    // so it is matched and skipped; if it somehow did not, appending would still not destroy the
    // peer names it exists to carry.
    if let Ok(f) = cstr("hosts") {
        let fd = unsafe {
            libc::openat(
                dir_fd,
                f.as_ptr(),
                libc::O_CREAT | libc::O_RDWR | libc::O_APPEND | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o644,
            )
        };
        if fd >= 0 {
            // A bounded read: an /etc/hosts that answers for `localhost` states it in the first few
            // lines, and a box must not be able to make kern read an unbounded file at setup.
            let mut buf = [0u8; 4096];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            let head = if n > 0 {
                #[allow(clippy::cast_sign_loss)] // n > 0 is checked
                &buf[..n as usize]
            } else {
                &buf[..0]
            };
            let resolves_localhost = head
                .windows(LOCALHOST.len())
                .any(|w| w.eq_ignore_ascii_case(LOCALHOST));
            if !resolves_localhost {
                // `writev` over borrowed slices: the two constant halves are `'static` and the name
                // is borrowed from the caller, so the file is written with ZERO heap allocation and
                // ONE syscall. The earlier shape built a `String` per box to concatenate three
                // fragments that never needed to be contiguous.
                let mut iov = [libc::iovec {
                    iov_base: ptr::null_mut(),
                    iov_len: 0,
                }; 4];
                let mut n = 0usize;
                let mut push = |b: &[u8]| {
                    iov[n] = libc::iovec {
                        iov_base: b.as_ptr() as *mut libc::c_void,
                        iov_len: b.len(),
                    };
                    n += 1;
                };
                push(LOCALHOST_SEED);
                if name_ok {
                    push(SELF_PREFIX);
                    push(h.as_bytes());
                    push(b"\n");
                }
                unsafe { libc::writev(fd, iov.as_ptr(), n as libc::c_int) };
            }
            unsafe { libc::close(fd) };
        }
    }

    // --- /etc/hostname: always the box's own name ------------------------------------------------
    if name_ok {
        if let Ok(f) = cstr("hostname") {
            let fd = unsafe {
                libc::openat(
                    dir_fd,
                    f.as_ptr(),
                    libc::O_CREAT
                        | libc::O_WRONLY
                        | libc::O_TRUNC
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW,
                    0o644,
                )
            };
            if fd >= 0 {
                // Same reason as the hosts write above: two borrowed fragments, one syscall, no
                // allocation. `h` is a slice of the caller's `hostname`, never copied.
                let iov = [
                    libc::iovec {
                        iov_base: h.as_ptr() as *mut libc::c_void,
                        iov_len: h.len(),
                    },
                    libc::iovec {
                        iov_base: b"\n".as_ptr() as *mut libc::c_void,
                        iov_len: 1,
                    },
                ];
                unsafe { libc::writev(fd, iov.as_ptr(), 2) };
                unsafe { libc::close(fd) };
            }
        }
    }
    unsafe { libc::close(dir_fd) };
}

fn setup_extra_hosts(root: &str, hosts: &[(String, String)]) {
    if hosts.is_empty() {
        return;
    }
    let clean = |s: &str| !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control());
    let mut block = String::from("\n# kern --add-host\n");
    for (name, ip) in hosts {
        if clean(name) && clean(ip) {
            block.push_str(&format!("{ip}\t{name}\n"));
        }
    }
    let Ok(rc) = cstr(root) else {
        return;
    };
    let root_fd = unsafe {
        libc::open(
            rc.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return;
    }
    // Symlink-safe walk to the real `/etc/hosts` (created if absent); returns an O_PATH fd.
    let path_fd = open_in_root(root_fd, "etc/hosts", false);
    unsafe { libc::close(root_fd) };
    let Ok(path_fd) = path_fd else {
        return; // a symlinked /etc or /etc/hosts (or a bad component) - refuse rather than escape
    };
    // O_PATH can't be written; reopen the SAME inode via /proc/self/fd for the append (no re-resolution
    // of the box path, so the symlink guard above still holds).
    let ok_reopen = cstr(&format!("/proc/self/fd/{path_fd}")).map(|proc_path| unsafe {
        libc::open(
            proc_path.as_ptr(),
            libc::O_WRONLY | libc::O_APPEND | libc::O_CLOEXEC,
        )
    });
    unsafe { libc::close(path_fd) };
    if let Ok(wfd) = ok_reopen {
        if wfd >= 0 {
            unsafe {
                libc::write(wfd, block.as_ptr().cast(), block.len());
                libc::close(wfd);
            }
        }
    }
}

/// Write the box's `/etc/resolv.conf` from `--dns` / `--dns-search` / `--dns-option`.
///
/// SILENT WHEN NOTHING WAS ASKED, and that is the whole compatibility contract. A box with no DNS
/// flags is byte-identical to every box kern has ever started: the image's own file is left alone,
/// including the EMPTY one the debian family ships. Only an explicit request makes kern take
/// ownership of the file, so this cannot change the behaviour of any existing stack.
///
/// O_TRUNC, NOT APPEND, and the asymmetry with `/etc/hosts` is deliberate. Hosts is additive: the
/// image's entries and kern's seeds and the pod's peers all coexist, and appending is how they do.
/// A resolver list is not additive: `resolv.conf` is read top-down with at most `MAXNS` (3) servers
/// honoured by glibc, so appending kern's servers under an image's would leave the image's in front
/// and the requested ones unused past the third line. A caller who names their resolvers means those
/// resolvers.
///
/// SYMLINK-SAFE BY THE SAME WALK AS `setup_extra_hosts`. `open_in_root` refuses a symlinked `/etc`
/// or `/etc/resolv.conf`, so a hostile image cannot redirect this write out of the box root; the
/// writable reopen goes through `/proc/self/fd` on the pinned inode rather than re-resolving the
/// path, so nothing can be swapped between the check and the write.
///
/// INJECTION IS REFUSED PER VALUE, not per file. `resolv.conf` is line-oriented, so a value carrying
/// a newline would write a directive the caller did not ask for; a value carrying whitespace would
/// split into two fields. Both are dropped here, and the CLI already refuses a `--dns` that is not
/// an IP literal, so this is the second of two independent gates rather than the only one.
///
/// Best-effort in every branch, like its two neighbours: DNS that could not be written must not stop
/// a box that may not need to resolve anything.
fn setup_resolv_conf(root: &str, dns: &[String], search: &[String], options: &[String]) {
    if dns.is_empty() && search.is_empty() && options.is_empty() {
        return;
    }
    /// A value that may be written into a line-oriented file: no whitespace (which includes the
    /// newline that would forge a directive) and no control characters.
    fn clean(s: &str) -> bool {
        !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control())
    }
    let mut body = String::new();
    for ip in dns.iter().filter(|v| clean(v)) {
        body.push_str("nameserver ");
        body.push_str(ip);
        body.push('\n');
    }
    let mut push_line = |head: &str, values: &[String]| {
        let mut wrote_head = false;
        for v in values.iter().filter(|v| clean(v)) {
            if !wrote_head {
                body.push_str(head);
                wrote_head = true;
            }
            body.push(' ');
            body.push_str(v);
        }
        if wrote_head {
            body.push('\n');
        }
    };
    push_line("search", search);
    push_line("options", options);
    // Every value was rejected: writing an EMPTY resolv.conf would be worse than writing none, since
    // an empty file makes glibc fall back to 127.0.0.1 rather than to the image's own configuration.
    if body.is_empty() {
        return;
    }
    let Ok(rc) = cstr(root) else {
        return;
    };
    let root_fd = unsafe {
        libc::open(
            rc.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return;
    }
    let path_fd = open_in_root(root_fd, "etc/resolv.conf", false);
    unsafe { libc::close(root_fd) };
    let Ok(path_fd) = path_fd else {
        return; // a symlinked /etc or /etc/resolv.conf - refuse rather than escape the box root
    };
    // SAFETY: `proc_path` is a live `CString` for the duration of the call, and the descriptor it
    // names is the one `open_in_root` just pinned - so this reopen does NOT re-resolve the box path
    // and the symlink guard above still holds.
    let ok_reopen = cstr(&format!("/proc/self/fd/{path_fd}")).map(|proc_path| unsafe {
        libc::open(
            proc_path.as_ptr(),
            libc::O_WRONLY | libc::O_TRUNC | libc::O_CLOEXEC,
        )
    });
    unsafe { libc::close(path_fd) };
    if let Ok(wfd) = ok_reopen {
        if wfd >= 0 {
            // SAFETY: `body` is a live local `String` and `body.len()` is its exact byte length; the
            // descriptor is the one opened immediately above and is closed exactly once, here.
            unsafe {
                libc::write(wfd, body.as_ptr().cast(), body.len());
                libc::close(wfd);
            }
        }
    }
}

/// Expose `--secret` values as `/run/secrets/<name>` (mode 0400) inside the box. The bytes were read
/// on the host before the fork; here we mount a fresh, box-owned, RAM-backed `tmpfs` at
/// `/run/secrets` (so a secret never lands in the persisted overlay upper) and write each file. Runs
/// before pivot. A hostile image shipping `/run/secrets` as a symlink is neutralised, and each file
/// is created `O_NOFOLLOW | O_EXCL` inside the tmpfs we own - the write can't be redirected out.
fn setup_secrets(root: &str, secrets: &[Secret], run_tmpfs: bool) -> Result<(), Error> {
    if secrets.is_empty() {
        return Ok(());
    }
    // INVARIANT (do not break): the HOST runtime dir `$XDG_RUNTIME_DIR/kern` (registry, health, and
    // exit sidecars) is NEVER mounted into a box - it isn't in the new root after pivot, so a workload
    // can't read or forge it. `kern compose`'s `depends_completed` trusts that a box CANNOT write
    // another service's `exit/<…>` sidecar. If a future feature needs in-box supervision state, mount
    // a NARROW box-owned path (like `/run/secrets` below), never bind the host `kern` runtime tree.
    //
    // `/run` may not exist in a minimal rootfs; create the chain. When a wide `/run` tmpfs is already
    // mounted (the `--ssh` path), `/run/secrets` is just a subdir on it - still RAM-backed and off the
    // overlay upper. Otherwise mount a narrow box-owned tmpfs on `/run/secrets` (0700, NOSUID|NODEV)
    // so the rest of the image's `/run` is left intact.
    //
    // This runs pre-pivot, so paths still resolve through the HOST root: a hostile image shipping
    // `/run` (or `/run/secrets`) as a symlink would redirect these mkdir/mount calls. Neutralize a
    // symlink at BOTH components before touching them - same discipline as `setup_dev`/`make_box_tmpfs`
    // (the `--ssh` path already got a fresh `/run` via `make_box_tmpfs`, so this is a no-op there).
    unlink_if_symlink(&format!("{root}/run"));
    if let Ok(runp) = cstr(&format!("{root}/run")) {
        unsafe { libc::mkdir(runp.as_ptr(), 0o755) };
    }
    let dir = format!("{root}/run/secrets");
    let dp = cstr(&dir)?;
    unlink_if_symlink(&dir);
    unsafe { libc::mkdir(dp.as_ptr(), 0o755) };
    if !run_tmpfs {
        let ty = cstr("tmpfs")?;
        // 0755, NOT 0700. The directory has to be TRAVERSABLE by whatever user the workload runs as,
        // or a per-file mode decides nothing: MEASURED on Docker's own `nginx-golang-postgres`
        // sample, whose `db` service declares `user: postgres` - the entrypoint died with
        // `/run/secrets/db-password: Permission denied` on every start. The files inside carry the
        // permission decision; the directory only has to let a reader reach them, which is exactly
        // what Docker's `/run/secrets` does.
        let opts = cstr("mode=0755")?;
        let hardening = (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong;
        if unsafe {
            libc::mount(
                ty.as_ptr(),
                dp.as_ptr(),
                ty.as_ptr(),
                hardening,
                opts.as_ptr() as *const libc::c_void,
            )
        } != 0
        {
            return Err(Error::last("mount(/run/secrets tmpfs)"));
        }
    }
    for Secret { name, bytes, mode } in secrets {
        // Name is a validated single component at the CLI; guard defensively before it hits a path.
        if name.is_empty() || name.contains('/') || name.contains("..") {
            continue;
        }
        let path = format!("{dir}/{name}");
        let cp = match cstr(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // O_EXCL: the tmpfs is freshly ours, so a pre-existing entry would be an anomaly; O_NOFOLLOW:
        // never traverse a symlink out of the tmpfs. The MODE comes from the caller: see [`Secret`].
        //
        // `open`'s mode argument is masked by the umask, which a caller's environment sets and this
        // process inherits, so a 0444 asked for could arrive as 0440. `fchmod` after the fact is not
        // masked and is the only way to land the mode that was requested.
        let fd = unsafe {
            libc::open(
                cp.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                *mode,
            )
        };
        if fd >= 0 {
            // The write bit is dropped whatever the caller asked for: the Compose Specification says
            // "the writable bit must be ignored if set", and a writable secret is one a workload can
            // silently replace for anything else that reads it later.
            unsafe { libc::fchmod(fd, *mode & 0o555) };
        }
        if fd < 0 {
            // The tmpfs is freshly box-owned, so this shouldn't happen - but never let a secret go
            // missing *silently* (an app would fall back to a weaker default). Say so.
            eprintln!(
                "kern: warning: could not materialise secret '{name}' at /run/secrets ({})",
                std::io::Error::last_os_error()
            );
            continue;
        }
        let mut off = 0usize;
        while off < bytes.len() {
            let n = unsafe {
                libc::write(
                    fd,
                    bytes[off..].as_ptr() as *const libc::c_void,
                    bytes.len() - off,
                )
            };
            if n <= 0 {
                break;
            }
            off += n as usize;
        }
        unsafe { libc::close(fd) };
    }
    Ok(())
}

/// Remount the box's `/dev` tmpfs read-only - for `--read-only` boxes, so `/dev` isn't a writable
/// hole in an otherwise read-only root. It's our own tmpfs (created in this user namespace), so
/// the remount is permitted. Blocks creating/renaming entries in `/dev`; the bound device nodes
/// stay usable (separate mounts; their writes go through the device driver, not the tmpfs).
fn remount_dev_ro() -> Result<(), Error> {
    let dev = cstr("/dev")?;
    let r = unsafe {
        libc::mount(
            ptr::null(),
            dev.as_ptr(),
            ptr::null(),
            (libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong,
            ptr::null(),
        )
    };
    if r != 0 {
        return Err(Error::last("remount_ro(/dev)"));
    }
    Ok(())
}

/// Set the sandbox hostname (in the new UTS namespace). Best-effort: a failure here doesn't
/// weaken isolation, so it isn't fatal.
fn set_hostname(name: &str) {
    // Truncate to HOST_NAME_MAX on a char boundary (BoxName is ASCII in practice, but don't slice
    // through a multi-byte sequence regardless).
    let end = (0..=name.len().min(64))
        .rev()
        .find(|&i| name.is_char_boundary(i))
        .unwrap_or(0);
    let trimmed = &name.as_bytes()[..end];
    unsafe { libc::sethostname(trimmed.as_ptr() as *const c_char, trimmed.len()) };
}

/// Subordinate id ranges to map into the box (box ids 1..count → these), plus the trusted
/// absolute paths of the helpers that will apply them.
struct IdRange {
    newuidmap: std::path::PathBuf,
    newgidmap: std::path::PathBuf,
    sub_uid: u32,
    uid_count: u32,
    sub_gid: u32,
    gid_count: u32,
}

/// Resolve a setuid id-map helper by **absolute trusted path only** - deliberately NOT via `$PATH`.
/// `newuidmap`/`newgidmap` are security-sensitive (they write our uid map with privilege); resolving
/// them through `$PATH` would let a writable entry like `~/.local/bin` shadow the real system binary
/// and feed us a bogus mapping. Only the standard system bin dirs are trusted.
pub fn trusted_helper(bin: &str) -> Option<std::path::PathBuf> {
    ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        .iter()
        .map(|d| std::path::Path::new(d).join(bin))
        .find(|p| p.is_file())
}

/// The login name for `uid` (for matching `/etc/subuid` rows), or `None`.
pub fn username(uid: u32) -> Option<String> {
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) }
        .to_str()
        .ok()
        .map(str::to_string)
}

/// `(start, count)` from a `name:start:count` (or `id:start:count`) row in `/etc/subuid` or
/// `/etc/subgid`, with `count > 1`. A row matching the login **name** wins (returned immediately);
/// a numeric-uid row is only used as a fallback - mirroring how shadow's `newuidmap` resolves the
/// allocation, so a stray numeric row never shadows the user's named one.
pub fn sub_range(file: &str, name: Option<&str>, id: u32) -> Option<(u32, u32)> {
    let content = std::fs::read_to_string(file).ok()?;
    let mut numeric: Option<(u32, u32)> = None;
    for line in content.lines() {
        let mut f = line.split(':');
        let Some(who) = f.next() else { continue };
        let by_name = name == Some(who);
        let by_id = who.parse::<u32>() == Ok(id);
        if !by_name && !by_id {
            continue;
        }
        if let (Some(s), Some(c)) = (f.next(), f.next()) {
            if let (Ok(start), Ok(count)) = (s.trim().parse(), c.trim().parse::<u32>()) {
                if count > 1 {
                    if by_name {
                        return Some((start, count)); // a named row takes precedence
                    }
                    numeric.get_or_insert((start, count));
                }
            }
        }
    }
    numeric
}

/// Decide whether a ranged uid/gid map is possible: needs both `newuidmap`/`newgidmap` and a
/// subordinate-id allocation for the caller. `None` → use the single-uid fallback.
fn detect_id_range(euid: u32, egid: u32) -> Option<IdRange> {
    let newuidmap = trusted_helper("newuidmap")?;
    let newgidmap = trusted_helper("newgidmap")?;
    let name = username(euid);
    let (sub_uid, uid_count) = sub_range("/etc/subuid", name.as_deref(), euid)?;
    let (sub_gid, gid_count) = sub_range("/etc/subgid", name.as_deref(), egid)?;
    Some(IdRange {
        newuidmap,
        newgidmap,
        sub_uid,
        uid_count,
        sub_gid,
        gid_count,
    })
}

/// `newuidmap`/`newgidmap PID 0 own 1 1 sub count` - map box id 0 → caller, box ids 1.. → the
/// subordinate range. `bin` is a trusted absolute path. Returns whether the helper exited 0.
/// Start one id-map helper WITHOUT waiting for it. The caller waits, so the two helpers overlap.
fn spawn_idmap(
    bin: &std::path::Path,
    pid: i32,
    own: u32,
    sub: u32,
    count: u32,
) -> Option<std::process::Child> {
    std::process::Command::new(bin)
        .args([
            pid.to_string(),
            "0".to_string(),
            own.to_string(),
            "1".to_string(),
            "1".to_string(),
            sub.to_string(),
            count.to_string(),
        ])
        .spawn()
        .ok()
}

// A CONCURRENT USER NAMESPACE THAT MEASURED WORSE, recorded so the next person does not rebuild it.
//
// THE IDEA. The ranged id map is the most expensive step of a box start (914 us in-program against
// 21 us for the single-uid map). It cannot be overlapped in place, because `newuidmap` writes the
// `uid_map` of a process that is ALREADY unshared, and between that unshare and the map being
// written the process has no mapped uid and so cannot touch the filesystem at all. The way around
// that ordering is a CARRIER child: it unshares the user namespace and blocks, kern stays in the
// host namespace with its real uid, points the two setuid helpers at the carrier's pid, and does the
// cgroup, the ports and the image while they run; then `setns`es into the mapped namespace and
// unshares the remaining four. The `setns` is legal for the same reason the `--pod` path's is, and
// it was verified: the resulting `uid_map` and `gid_map` inside the box were byte-identical.
//
// IT WORKED AND IT WAS SLOWER. Implemented in full, the phase it targets fell from 914 us to 2 us -
// the helpers really did finish during the setup - and the whole box start got 66 us SLOWER
// (CI95 [+29, +112], 250 paired samples). The cost had moved, not gone: a new `parent:userns-start`
// mark put it at 986 us, MORE than the 914 it was hiding.
//
// WHY, so the next attempt starts from the reason and not from the idea. The preparation step
// blocked three times, and none of the three is the setuid helpers:
//   * it reads the carrier's readiness byte, which is a scheduling round trip;
//   * it `waitpid`s the carrier after opening its namespace, another round trip;
//   * and `std::process::Command::spawn` is `posix_spawn`, which every libc implements with
//     `CLONE_VFORK`: THE PARENT IS SUSPENDED UNTIL THE CHILD EXECS. Two spawns in sequence mean kern
//     pays both exec latencies synchronously, which is most of what the overlap was supposed to hide.
//
// A shape that could still win has to remove all three: a thin helper forked once, early, that owns
// the carrier AND both spawns and reports a verdict kern reads later. That is a third process and
// three more handshakes on the path that establishes the box'"'"'s user namespace, and there is no
// measurement yet saying it wins. It is not attempted here for the reason this comment exists: on
// this path a change that is slower in the program is a regression whatever the idea says.

// A SECOND SHAPE OF THE SAME OVERLAP, ALSO MEASURED, ALSO NOT SHIPPED. Read this with the note
// above it: together they bound the idea, so the next attempt starts from the boundary and not from
// scratch.
//
// The first attempt failed because kern drove the carrier itself and blocked three times, the worst
// being `posix_spawn`: every libc implements it with `CLONE_VFORK`, so the caller is suspended until
// the child execs, and two spawns put both exec latencies back on the critical path. The second
// attempt removed all three by giving a thin `prep` helper the carrier AND both spawns, leaving kern
// one `fork` before it could continue. That part WORKED and was measured: `parent:userns-start` cost
// 77 us against the 986 us the first shape cost, and the id map phase fell from 914 us to 3 us.
//
// THE TOTAL DID NOT MOVE AT ALL: 3853.2 us against 3853.2 us, difference -1.8 us with a 95% interval
// of [-44.6, +43.9] over 300 paired samples. Not a loss this time - a wash.
//
// THE REASON IS AN INEQUALITY, and it is what makes this worth writing down. Overlapping only pays
// while there is work to overlap WITH. Inside `run_in_sandbox_with` there is about 226 us of it (the
// ports and the cgroup); the helper chain is about 985 us end to end, and the extra process adds a
// round trip of its own. 226 us of hiding minus that round trip is zero.
//
// WHAT WOULD CHANGE THE ANSWER, stated as a condition rather than as a plan: an overlap window wider
// than the chain. The only place one exists is the CLI's own phases before the sandbox call - about
// 487 us of name check, config, claim and image resolution - which would put the total window near
// 713 us and predict roughly 0.6 ms. Starting there crosses the `KERN_SCOPE` re-exec: kern re-execs
// itself under `systemd-run` on the scope path, destructors do not run across `execve`, and the
// prepared processes would be left holding a namespace with nobody to release them. Any third
// attempt has to solve THAT first, and the gain has to be weighed against putting user-namespace
// lifetime state in the CLI, on the path that establishes the box'"'"'s security boundary.

/// Apply BOTH id maps, overlapping the two setuid helpers instead of running them back to back.
///
/// They used to run in sequence, so a box paid two full spawn + exec + wait cycles one after the
/// other. MEASURED: that is about 2 ms of a ~4 ms image-box start, the single largest cost in the
/// whole sequence and pure latency rather than work. The two helpers write DIFFERENT files
/// (`/proc/<pid>/uid_map` and `/proc/<pid>/gid_map`) for the same target, read different files
/// (`/etc/subuid`, `/etc/subgid`) and share no mutable state, so nothing orders one before the
/// other. `newgidmap` is itself the privileged writer, so there is no `setgroups` sequencing to
/// respect either.
///
/// BOTH are waited even when the first fails: a spawned child that is never reaped becomes a zombie
/// held by the supervisor for as long as the box lives.
fn run_both_idmaps(r: &IdRange, pid: i32, euid: u32, egid: u32) -> bool {
    let a = spawn_idmap(&r.newuidmap, pid, euid, r.sub_uid, r.uid_count);
    let b = spawn_idmap(&r.newgidmap, pid, egid, r.sub_gid, r.gid_count);
    let wait = |c: Option<std::process::Child>| {
        c.map(|mut c| c.wait().map(|s| s.success()).unwrap_or(false))
            .unwrap_or(false)
    };
    let ok_a = wait(a);
    let ok_b = wait(b);
    ok_a && ok_b
}

/// Unshare `ns_flags` (incl. the user ns), then set a *ranged* uid/gid map. Because an
/// unprivileged process can only self-map a single id, the actual mapping is applied by a helper
/// child that stays in the HOST user namespace (where the setuid `newuidmap`/`newgidmap` work) and
/// targets us by pid, synchronized over pipes. Leaves `setgroups` allowed (newgidmap is the
/// privileged writer), so the box can use supplementary groups.
///
/// # A restructuring that MEASURED WORSE, so that nobody repeats it
///
/// The obvious cut here is the middle process: kern forks one helper, which then forks `newuidmap`
/// and `newgidmap` itself, so three forks stand between the `unshare` and a mapped namespace. Forking
/// the two setuid helpers DIRECTLY from kern, each waiting on its own gate and `execve`-ing, removes
/// one process and one scheduling hop, and the result comes back as an exit status instead of a byte
/// on a pipe. It is simpler and it is faster on a bench that isolates the dance: 0.83 ms against
/// 0.68 ms over 40 rounds, and still faster with a 256 MB parent (8.4 ms against 3.6 ms), which was
/// the first explanation tried for why the real program disagrees, and which the bench refuted.
///
/// IN KERN IT IS CONSISTENTLY SLOWER. Two binaries built from the same tree, alternated in one
/// session, 32 paired batches of 30 `box --image` runs each: 3.482 ms with the middle process against
/// 3.747 ms without it, and the direct form won 1 batch out of 32. The reason is not known. What is
/// known is that a change which is slower in the program is a regression whatever a bench says, and
/// that the bench did not model whatever decides it here.
///
/// `pt` splits the two halves for the profiler, and the split is the reason it exists: this function
/// was the single most expensive step in a box start (about 1.27 ms of 3.63 ms on the `--image` path)
/// behind ONE label, so "the unshare" and "two setuid helpers" could not be told apart. Both arms of
/// the caller now emit the same pair, `parent:unshare(ns)` and `parent:idmap`, so one profile answers
/// which of the two a given host is paying for. `None` from the `--pod` path, which has no timer.
fn apply_userns_range(
    ns_flags: libc::c_int,
    euid: u32,
    egid: u32,
    r: &IdRange,
    pt: Option<&mut PhaseTimer>,
) -> Result<(), Error> {
    let mut p2h = [0 as libc::c_int; 2]; // parent → helper: "I've unshared, map me"
    let mut h2p = [0 as libc::c_int; 2]; // helper → parent: '1' mapped / '0' failed
    if unsafe { libc::pipe(p2h.as_mut_ptr()) } != 0 || unsafe { libc::pipe(h2p.as_mut_ptr()) } != 0
    {
        return Err(Error::last("pipe"));
    }
    let helper = unsafe { libc::fork() };
    if helper < 0 {
        return Err(Error::last("fork(idmap helper)"));
    }
    if helper == 0 {
        // Helper - still in the host user namespace, so the setuid map helpers have privilege.
        unsafe {
            libc::close(p2h[1]);
            libc::close(h2p[0]);
        }
        let ppid = unsafe { libc::getppid() };
        let mut b = [0u8; 1];
        let _ = unsafe { libc::read(p2h[0], b.as_mut_ptr() as *mut libc::c_void, 1) };
        let ok = run_both_idmaps(r, ppid, euid, egid);
        let msg: &[u8] = if ok { b"1" } else { b"0" };
        let _ = unsafe { libc::write(h2p[1], msg.as_ptr() as *const libc::c_void, 1) };
        unsafe { libc::_exit(0) };
    }
    unsafe {
        libc::close(p2h[0]);
        libc::close(h2p[1]);
    }
    let unshared = unsafe { libc::unshare(ns_flags) };
    if unshared != 0 {
        let e = std::io::Error::last_os_error();
        unsafe {
            libc::close(p2h[1]);
            libc::close(h2p[0]);
            libc::waitpid(helper, ptr::null_mut(), 0);
        }
        if e.raw_os_error() == Some(libc::EPERM) {
            return Err(Error::Unsupported(USERNS_UNAVAILABLE));
        }
        return Err(Error::Syscall("unshare(namespaces)", e));
    }
    // The namespaces exist; everything after this point is the two setuid helpers and the handshake.
    if let Some(p) = pt {
        p.mark("parent:unshare(ns)");
    }
    let _ = unsafe { libc::write(p2h[1], b"x".as_ptr() as *const libc::c_void, 1) };
    // Wait for the helper's verdict. Retry on EINTR so a stray signal can't be misread as a
    // mapping failure (which would, correctly but needlessly, abort the box).
    let mut got = [0u8; 1];
    let n = loop {
        let r = unsafe { libc::read(h2p[0], got.as_mut_ptr() as *mut libc::c_void, 1) };
        if r < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        break r;
    };
    unsafe {
        libc::close(p2h[1]);
        libc::close(h2p[0]);
        libc::waitpid(helper, ptr::null_mut(), 0);
    }
    if n != 1 || got[0] != b'1' {
        // newuidmap/newgidmap are present (detect_id_range found them + a sub-id allocation) but
        // couldn't actually apply the range here - typically the helper isn't setuid-root, or there
        // is no matching /etc/subgid row. We're already in a fresh, still-unmapped user namespace, so
        // fall back to the safe single-uid self-map (identical to the no-range default) instead of
        // aborting the box - mirroring how an *absent* helper already degrades gracefully. (If a
        // partial map already populated uid_map, the self-map write fails and that unrecoverable
        // half-mapped state is surfaced as the error.)
        eprintln!(
            "kern: --uid-range mapping via newuidmap/newgidmap failed (helper present but not usable here) - using single-uid map"
        );
        return write_single_uid_map(euid, egid);
    }
    Ok(())
}

/// Is a subordinate id RANGE usable on this host (a `newuidmap`/`newgidmap` pair plus an
/// `/etc/subuid` allocation)? The precondition for [`with_id_mapped_userns`], asked separately so a
/// caller can decide what it is going to do BEFORE it forks - the layer unpack has to choose its
/// `tar` flags in the parent and must not answer that question a second time in the child.
/// Run `f` as uid 0 of a user namespace carrying kern's SUBORDINATE ID RANGE, and return its status.
///
/// WHY THIS EXISTS. Layers are extracted on the host, as the caller's uid, which cannot `chown` to
/// anything else - so extraction passes `--no-same-owner` and every file in an image ends up owned by
/// the caller. Inside a box that is uid 0, so an image that `chown`s a directory to a NON-ROOT user
/// and then runs as that user cannot write to its own directory. MEASURED on three real stacks:
/// Prometheus dies with `mkdir data/: permission denied`, Kibana with `EACCES` on its uuid file, and
/// Logstash the same way; all three run as a non-root user the image created.
///
/// The box already maps a full range (box uid 1..N → the caller's `/etc/subuid` allocation), so the
/// ownership those images want IS representable on disk. It is only lost because `tar` runs outside
/// the namespace where the range exists. Inside this one, uid 0 holds `CAP_CHOWN` over every mapped
/// id, so `tar` can restore it - and `CAP_DAC_OVERRIDE`, which is what makes the resulting files
/// REMOVABLE again (an unprivileged caller cannot unlink inside a directory a subuid owns).
///
/// The closure is told whether it got a RANGE or a single-uid map, read back from the installed map
/// rather than from what was asked for. Without a range there is exactly one id to own anything, and
/// a caller told otherwise would try to create ownership that cannot exist.
///
/// `Err` when no user namespace could be mapped at all. The closure is NOT run in that case, so a
/// caller that has a degraded path can take it - ask [`single_threaded`] first if it must keep the
/// closure.
///
/// FORK-SAFETY: refused in a multi-threaded process, for [`crate::single_threaded`]'s reason - the
/// child runs Rust code between the fork and its `_exit`, and a lock held by another thread at fork
/// time is held forever in the child.
pub fn id_range_available() -> bool {
    let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
    detect_id_range(euid, egid).is_some()
}

pub fn with_id_mapped_userns<F: FnOnce(bool) -> i32>(f: F) -> Result<i32, Error> {
    let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let range = detect_id_range(euid, egid);
    if !single_threaded() {
        return Err(Error::Unsupported(
            "id-mapped work: refusing to fork in a multi-threaded process (fork-safety)",
        ));
    }
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(Error::last("fork(id-mapped)"));
    }
    if child == 0 {
        // CHILD. A failure to become ns-root must not run `f` at all: it would run with the caller's
        // own identity and no capabilities, which is neither of the two states `f` is written for.
        let mapped = match &range {
            // `apply_userns_range` unshares AND maps, and degrades to the single-uid map itself when
            // the helpers turn out to be unusable here.
            Some(r) => apply_userns_range(libc::CLONE_NEWUSER, euid, egid, r, None).is_ok(),
            None => {
                let unshared = unsafe { libc::unshare(libc::CLONE_NEWUSER) } == 0;
                unshared && write_single_uid_map(euid, egid).is_ok()
            }
        };
        if !mapped {
            unsafe { libc::_exit(121) };
        }
        // The map is in place but this process still carries its old ids; become uid 0 OF THE
        // NAMESPACE, which is where the capabilities over the mapped range live.
        if unsafe { libc::setresgid(0, 0, 0) } != 0 || unsafe { libc::setresuid(0, 0, 0) } != 0 {
            unsafe { libc::_exit(122) };
        }
        // WHICH MAP WE ACTUALLY GOT, READ BACK rather than assumed. `apply_userns_range` degrades to
        // a single-uid map on its own when the helpers are present but unusable, and a caller told
        // "you have a range" when it does not would extract an image whose ownership cannot exist.
        let code = f(uid_map_is_ranged());
        unsafe { libc::_exit(code) };
    }
    let mut st = 0;
    if unsafe { libc::waitpid(child, &mut st, 0) } < 0 {
        return Err(Error::last("waitpid(id-mapped)"));
    }
    let code = if libc::WIFEXITED(st) {
        libc::WEXITSTATUS(st)
    } else {
        // Killed by a signal: not an exit code, and reporting one would let 0 mean success.
        return Err(Error::Unsupported("id-mapped work was killed by a signal"));
    };
    match code {
        121 => Err(Error::Unsupported(
            "id-mapped work: could not map a user namespace",
        )),
        122 => Err(Error::Unsupported(
            "id-mapped work: could not become root of the mapped namespace",
        )),
        c => Ok(c),
    }
}

/// Does THIS process's uid map cover more than the single self-mapped id?
///
/// Read from `/proc/self/uid_map` and not deduced from what was requested: the range helpers can be
/// present and still fail (not setuid, no `/etc/subgid` row), and the mapper degrades to a single-uid
/// map when they do. The only honest answer to "can a file be owned by a non-root box user here" is
/// the map the kernel actually installed.
fn uid_map_is_ranged() -> bool {
    std::fs::read_to_string("/proc/self/uid_map").is_ok_and(|s| map_text_is_ranged(&s))
}

/// The parse half of [`uid_map_is_ranged`], split from the read so it can be asserted.
///
/// A `uid_map` row is `<in-ns start> <host start> <count>`, and the question is whether any row maps
/// MORE THAN ONE id: with a single row of count 1 there is exactly one identity in the namespace, so
/// no file can belong to anyone else and a caller told otherwise would try to create ownership that
/// cannot exist. A file kern cannot parse answers `false`, which is the conservative direction: it
/// keeps `--no-same-owner`, which is what every host did before any of this.
fn map_text_is_ranged(text: &str) -> bool {
    text.lines().any(|l| {
        l.split_whitespace()
            .nth(2)
            .and_then(|c| c.parse::<u64>().ok())
            .is_some_and(|count| count > 1)
    })
}

/// Whether this process is single-threaded, the precondition [`with_id_mapped_userns`] enforces.
///
/// Read from `/proc/self/status` rather than remembered: a caller cannot know what a library it
/// links has spawned, and a wrong answer here is a deadlock in a forked child.
pub fn single_threaded() -> bool {
    std::fs::read_to_string("/proc/self/status").is_ok_and(|s| {
        s.lines()
            .find_map(|l| l.strip_prefix("Threads:"))
            .and_then(|v| v.trim().parse::<u32>().ok())
            == Some(1)
    })
}

/// Write the dependency-free single-uid identity map (box uid/gid 0 → caller) for the CURRENT,
/// already-unshared user namespace: deny `setgroups` first (the kernel requires this before an
/// unprivileged `gid_map`), then the one-row uid/gid maps. Shared by the no-range default and the
/// `--uid-range` fallback for when the id-mapping helpers can't apply a range.
fn write_single_uid_map(euid: u32, egid: u32) -> Result<(), Error> {
    if let Err(e) = std::fs::write("/proc/self/setgroups", b"deny") {
        // Denying setgroups is the kernel's prerequisite for an unprivileged `gid_map`. Ubuntu's
        // `apparmor_restrict_unprivileged_userns` policy can let a userns be created (full caps, empty
        // maps) yet still refuse *this* write with EACCES (the AppArmor mediation) or EPERM (a plain
        // kernel denial) - the environment permits the namespace but not a rootless id map, so a box
        // genuinely can't run here. Report it as unsupported (and name user namespaces) so foreground
        // and detached fail identically and the skip-graceful tests skip either way, rather than
        // leaking a bare "setgroups: Permission denied".
        if matches!(e.raw_os_error(), Some(libc::EACCES | libc::EPERM)) {
            return Err(Error::Unsupported(
                "unprivileged user namespaces are restricted here - an AppArmor \
                 apparmor_restrict_unprivileged_userns policy allows the namespace but blocks \
                 denying setgroups for the rootless uid map",
            ));
        }
        return Err(Error::Syscall("setgroups", e));
    }
    std::fs::write("/proc/self/uid_map", format!("0 {euid} 1"))
        .map_err(|e| Error::Syscall("uid_map", e))?;
    std::fs::write("/proc/self/gid_map", format!("0 {egid} 1"))
        .map_err(|e| Error::Syscall("gid_map", e))?;
    Ok(())
}

/// Run `spec.command` inside a fresh user + PID + mount namespace sandbox. Returns the child's
/// exit code. Requires unprivileged user namespaces.
pub fn run_in_sandbox(spec: &SandboxSpec) -> Result<i32, Error> {
    run_in_sandbox_with(spec, None, |_| None, None, &[], false)
}

/// Owns the readiness-pipe write end and *fails closed*: if dropped while still armed (i.e. before
/// the box took it over or the parent disarmed it), it writes one failure byte and closes the fd,
/// so a waiting launcher learns the box never started. [`disarm`](ReadyGuard::disarm) hands the raw
/// fd to whoever will now own the signalling (the box child on success, or nobody in the parent).
struct ReadyGuard(Option<i32>);

impl ReadyGuard {
    fn disarm(&mut self) -> Option<i32> {
        self.0.take()
    }
}

impl Drop for ReadyGuard {
    fn drop(&mut self) {
        if let Some(fd) = self.0 {
            unsafe {
                libc::write(fd, b"x".as_ptr().cast(), 1);
                libc::close(fd);
            }
        }
    }
}

/// Like [`run_in_sandbox`], but invokes `on_started` in the parent with the box's PID-1 pid (in
/// the host pid namespace) right after the fork - so a supervisor can record it for `kern exec`
/// to join the box's namespaces later.
///
/// `ready_fd`, if set, is the write end of a readiness pipe: it is closed automatically when the
/// box's command `execvp`s (`FD_CLOEXEC`), so a waiting reader gets EOF = "the box is up", and one
/// byte is written to it first if setup/exec fails - letting a detached launcher report a truthful
/// "started" / "failed to start" with zero polling. The parent closes its own copy after the fork.
///
/// The fd is wrapped in a [`ReadyGuard`] so that *any* early error (a failed `unshare`,
/// `uid_map`, or uid-range mapping - all of which return before the box is even forked) signals
/// failure on drop. Without this, an error before the fork would close the pipe cleanly and the
/// launcher would misread the EOF as a successful start.
///
/// `die_with_parent` is set ONLY for a FOREGROUND box (a plain `kern box`, not `-d`/`-it`/managed):
/// this supervisor arms `PR_SET_PDEATHSIG(SIGKILL)` relative to its launcher and the box's PID 1
/// arms it relative to this supervisor, so a hard kill of the launcher (SIGKILL/OOM - where no
/// cleanup can run) cascades launcher → supervisor → pidns-init instead of orphaning the box until
/// the `--timeout` backstop fires. It MUST stay false for a detached box, whose launcher exits right
/// after forking the supervisor (arming would kill the box instantly).
/// `on_started` is called with PID 1 as soon as the box exists, and MAY RETURN A REPLACEMENT PTY
/// MASTER. That return is the seam between the two crates: the box allocates its own terminal from
/// its own devpts (so `ttyname()` can name it), sends the master back over `spec.pty_sock`, and only
/// the CLI knows what to do with it - retarget `SIGWINCH`, copy the window size. So the CLI receives
/// it inside this callback and hands it back here, where the pump lives. `None` keeps `tty_master`,
/// which is the host pty and the behaviour before [`crate::ptybox`] existed.
pub fn run_in_sandbox_with<F: FnOnce(i32) -> Option<i32>>(
    spec: &SandboxSpec,
    ready_fd: Option<i32>,
    on_started: F,
    tty_master: Option<i32>,
    ports: &[PortMap],
    die_with_parent: bool,
) -> Result<i32, Error> {
    // Armed until the box child takes ownership (post-fork) or the parent disarms it: a drop on
    // any error path before then writes the failure byte, so a pre-fork failure is never reported
    // as "started".
    let mut ready = ReadyGuard(ready_fd);
    if spec.command.is_empty() {
        return Err(Error::Unsupported("no command given to run in the sandbox"));
    }
    // FOREGROUND box: die with the launcher. Arm `PR_SET_PDEATHSIG(SIGKILL)` so that if the process
    // that launched this `kern` (our parent) is hard-killed - SIGKILL/OOM, where no exit path or
    // Drop can run `kern stop` - this supervisor is torn down too, rather than being reparented and
    // keeping the box alive until the `--timeout` backstop. PDEATHSIG is per parent *thread*; the
    // fork below already requires this process to be single-threaded, so it fires on the launcher's
    // real death. Skipped for `-d`/`-it`/managed (see `die_with_parent`).
    if die_with_parent {
        // Capture the launcher BEFORE arming, then re-check: PDEATHSIG only fires on a *future*
        // parent death, so if the launcher already exited (its child `kern` reparented) between our
        // spawn and this prctl, the signal would never come - detect the reparent and refuse to
        // start, leaving no orphaned box.
        let launcher = unsafe { libc::getppid() };
        unsafe {
            libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0,
                0,
                0,
            );
        }
        if unsafe { libc::getppid() } != launcher {
            return Err(Error::Unsupported("launcher exited before the box started"));
        }
    }
    // Build argv CStrings before fork (the child stays allocation-light).
    let argv: Vec<CString> = spec
        .command
        .iter()
        .map(|s| cstr(s))
        .collect::<Result<_, _>>()?;

    // `-p` forwarders: fork them NOW, BEFORE the cgroup join and the `unshare`, so they stay in the
    // host network + user namespace (and out of the box's cgroup). Each BINDS its host socket here
    // and reports the outcome, so a port we cannot publish fails the box instead of leaving `kern ps`
    // showing a mapping nothing serves; each then blocks until we send it the box's PID 1 after the
    // fork below. (Empty `ports` → no forwarders.) The returned set is RAII: every error return
    // between here and the box's start tears the bound ports down.
    // The spawn-side timer starts HERE, before the ports and the cgroup, so that everything between
    // this point and the box's fork is inside the profile. A step that is not marked is a step whose
    // cost is attributed to whatever is marked next, which is how a 986 us block sat unnoticed in
    // front of `parent:limits+cgroup` during the concurrent-namespace attempt documented above.
    let mut pt_spawn = PhaseTimer::new();

    let forwarders = crate::ports::fork_forwarders(ports)
        .map_err(|(hp, why)| Error::Spec(format!("cannot publish host port {hp}: {why}")))?;

    // STARTED HERE RATHER THAN AFTER `apply_limits`, because everything `apply_limits` does was
    // invisible to this profiler and it is not small. `box lifetime` minus every marked phase left
    // about 670 us unattributed, CONSTANT across four configurations - image or host rootfs, dynamic
    // or static workload, with or without a network namespace - so it was structural and not a
    // property of the workload. Three candidates were measured and eliminated before this one: the
    // fd shed is 3 us, the pid namespace is 27 us (anchored externally against bubblewrap with and
    // without `--unshare-pid`), and the dynamic loader is not it either, since a statically linked
    // busybox leaves the same residue. What remained unmarked was the cgroup and scope setup.

    // Best-effort cgroup v2 cap (memory + PIDs) BEFORE namespacing, so the forked workload
    // inherits it. Degrades gracefully where the hierarchy isn't delegated. The returned guard owns
    // the cgroup dir and removes it on drop; we bind it to `_cg` so it lives until this function
    // returns - which is AFTER the `waitpid` below, when the box (and its PID-namespace descendants)
    // are dead and the cgroup is empty, so the `rmdir` in `Drop` succeeds. Without this the scope-less
    // fast path (no systemd `--collect`) would leak one cgroup dir per box.
    let cg = crate::cgroup::apply_limits(
        true, // allow_direct: `kern box` has a supervisor to hold the RAII guard and vacate on the direct path
        crate::cgroup::Leaf::Box(&spec.hostname),
        spec.memory_max,
        spec.memory_swap_max,
        spec.cpuset.as_deref(),
        spec.cpus,
        spec.pids_max,
        &spec.io_max,
        spec.io_weight,
        spec.memory_low,
        spec.cpu_weight,
        spec.require_limits, // demand BOTH memory and pids bind, not just one
        true, // supervisor_forks_workload: `kern box` forks PID 1, which joins the capped cgroup itself
    );

    // The BOX's cgroup, for the two readers below. ONE expression, bound once and shared, because the
    // human-readable warning and the machine-readable enforcement byte answer the same question and
    // must not be able to disagree. They did: the byte took this directory and the warning read
    // `/proc/self/cgroup`, which is the supervisor's uncapped SIBLING leaf on the scope tier, so both
    // Raspberry Pi 5 and Jetson reported "--memory accepted but NOT enforced here" over a box whose
    // leaf held exactly the requested `memory.max` and `pids.max`. `None` where the sibling layout was
    // not built: the supervisor is then inside the capped cgroup and the self-read is correct.
    let box_cg = cg
        .as_ref()
        .filter(|g| g.supervisor_is_outside())
        .map(crate::cgroup::CgroupGuard::box_dir);

    // Under a systemd scope the caps were handed to `systemd-run` as `MemoryMax=`/`CPUQuota=`/
    // `TasksMax=` and nothing re-checked them: systemd accepts a property the kernel cannot honour
    // and reports nothing. Verify the EFFECTIVE chain at the box's own cgroup. Found on an Arduino
    // UNO Q's Android kernel, whose `cpu` controller exposes only `cpu.weight` and no `cpu.max`,
    // turning `--cpus` into a share with no message at all.
    // NOT gated on `KERN_SCOPE` any more. The gate assumed the scope tier was the only one that could
    // accept a cap without enforcing it, and the opt-out path (`KERN_NO_SCOPE`) disproved that: it
    // warned from before the box existed because nothing here would. Now the check runs on EVERY box
    // path, always against the box's own cgroup, so there is one place that answers this question and
    // it is the one that can.
    crate::cgroup::warn_unenforced_caps(box_cg, spec.memory_max, spec.cpus, spec.pids_max);

    // Record whether the memory cap actually binds, for the `KERN_STARTED_FD` enforcement byte. HERE is
    // the one correct point: the box's cgroup exists with its caps written and the box has not yet
    // forked, so the value-aware check sees exactly the ceiling the box will run under. Read once by the
    // box_run teardown that writes the started byte. All paths.
    //
    // The BOX's directory is passed explicitly rather than read from `/proc/self/cgroup`. The supervisor
    // is no longer inside the capped cgroup on the direct path (it sits in a sibling leaf so a whole-box
    // OOM cannot take it), so self-reading would answer for that uncapped leaf and report every box as
    // unenforced. Where the layout could not be built the supervisor is still inside and `None` restores
    // the self-read, which is the same answer as before.
    crate::cgroup::record_memory_cap_signal(spec.memory_max, box_cg);

    // FAIL-CLOSED on the direct fast path. When we DELIBERATELY skipped the per-box systemd scope
    // (`took_direct_cap_path()` - the SAME canonical predicate `reexec` used, so they can't diverge), the
    // box's OWN cgroup is the sole enforcer. `apply_limits` returns `None` iff a MANDATORY cap didn't bite
    // (memory + pids ALWAYS carry a default cap, verified per-dimension inside apply_limits) - so a `None`
    // here means we'd run with a missing OOM/fork-bomb backstop. REFUSE. No `caps_requested` gate: the
    // default memory/pids caps are mandatory, so a default box (no flags) must also be refused if they
    // didn't take. Hosts with no user systemd never took the direct path → best-effort, no refusal; the
    // scope path sets `KERN_SCOPE` so `took_direct_cap_path()` is false there and a `None` is fine.
    // Both checks below only matter when NO cap was applied; when `cg` is `Some` neither the (env + systemd
    // stat) `took_direct_cap_path()` nor the (cgroup-walking) `env_claims_enforcer_but_none_real()` runs.
    if cg.is_none() {
        // `cg.is_none()` says KERN wrote no cap of its own. It does NOT say the box is uncapped, and
        // conflating the two was a measured defect: on the systemd-scope path the SCOPE carries
        // `MemoryMax`/`TasksMax`, so the backstops bind without kern writing a byte. On a Raspberry Pi 5
        // over ssh the box ran with `memory.max` 67108864, `memory.oom.group` 1 and `pids.max` 512, was
        // OOM-killed as a whole 3 times out of 3 (`dmesg`: `Memory cgroup out of memory`), and kern
        // still printed the uncapped notice while `--require-limits` refused to start - on a host where
        // the caps demonstrably worked. So ask the kernel what is in force before refusing or warning.
        // Deliberately NOT applied to the direct-path refusal below: there the box's own cgroup is the
        // sole enforcer by design, and accepting an ancestor's ceiling would loosen a fail-closed rule.
        let caps_already_bound = crate::cgroup::mandatory_caps_in_force(spec.memory_max);
        // `--require-limits`: the caller asked for "enforce or do not run". A missing cap is fatal on
        // ANY path (best-effort included), BEFORE the warn-and-run fall-through below, so a workload
        // that depends on the ceiling never starts believing it is capped when it is not.
        if spec.require_limits && !caps_already_bound {
            return Err(Error::Unsupported(
                "requested resource cap(s) could not be enforced here and --require-limits \
                 (KERN_REQUIRE_LIMITS) is set: refusing to start. Ways out: run inside a systemd user \
                 scope, or on a host that delegates the cgroup v2 memory/pids controllers (`kern \
                 doctor` shows the state; on WSL2 or a Raspberry Pi add `cgroup_enable=memory` to the \
                 kernel command line); or, to accept uncapped operation, drop --require-limits and pass \
                 --allow-uncapped in its place (the two are mutually exclusive, not additive).",
            ));
        }
        if crate::cgroup::took_direct_cap_path() {
            return Err(Error::Unsupported(
                "resource caps could not be enforced on the direct cgroup path (kern.slice delegation \
                 raced, was garbage-collected, or is partial); refusing to start an uncapped box",
            ));
        }
        // SECURITY: never run SILENTLY uncapped because of a (possibly forged) outer-enforcer env var. A
        // caller can set `KERN_MANAGED`/`KERN_SCOPE`/`KERN_BUILD_STEP` to skip the fail-closed above, but if
        // no real cgroup cap is actually in force (verified against the cgroup, not the env claim), warn
        // loudly. (Warn, not refuse, so a legit first-party best-effort build step isn't broken; the direct
        // path already hard-refuses. Mutually exclusive with the refusal: that needs NO outer-enforcer env.)
        if crate::cgroup::env_claims_enforcer_but_none_real() {
            eprintln!(
                "kern: warning: an outer-enforcer env var (KERN_SCOPE/KERN_MANAGED/KERN_BUILD_STEP) is set \
                 but NO cgroup cap is in force - the box runs UNCAPPED. If kern did not set that variable, a \
                 caller may be bypassing the resource limits."
            );
        } else if !spec.allow_uncapped
            && !caps_already_bound
            && !crate::cgroup::env_flag("KERN_QUIET")
            && crate::cgroup::memory_cap_enforceable()
        {
            // KERN_QUIET drops this human-readable notice for embedders (the MCP server) that read the
            // uncapped verdict off the machine signal instead; it does NOT change the allow/refuse
            // behaviour (that stays on `--allow-uncapped`/`--require-limits`), only the prose.
            // The box did NOT take the direct kern.slice path, no outer enforcer claims to cap it, and
            // `apply_limits` could not put a cap in force here. `memory_cap_enforceable()` is TRUE, so the
            // once-per-process "controller absent from this tree" notice in `reexec_in_scope_if_possible`
            // did NOT fire: the controller IS in the tree, but kern could not place the box in a cgroup
            // that carries the cap. The usual cause is that the direct kern.slice path was declined
            // because no systemd user manager was found - and that check is `$XDG_RUNTIME_DIR/systemd`, so
            // a WRONG or unset `XDG_RUNTIME_DIR` silently disables it (this is how the case was first hit:
            // pointing `XDG_RUNTIME_DIR` at a scratch subdir), as does a genuinely systemd-less host.
            //
            // NOT gated on an EXPLICIT `--memory`/`--pids-limit`/`--cpus`: memory and pids ALWAYS carry a
            // DEFAULT cap (the OOM / fork-bomb backstop), so a plain `kern box` with no cap flags is
            // equally UNCAPPED here and equally silent - the exact gap Grok flagged (a default Redis on a
            // best-effort host with no backstop). Accepting a cap - default or requested - and enforcing
            // nothing is the one thing this codebase does not do quietly. Warn (not refuse): the direct
            // path already hard-refuses, and a best-effort host is a legitimate configuration.
            // The middle clause is MEASURED per host rather than fixed prose: the fixed version named
            // `XDG_RUNTIME_DIR` and `/run/user/$(id -u)` on every host, which on a colima guest with no
            // user manager at all sends the reader to set a variable that changes nothing.
            eprintln!(
                "kern: warning: resource caps could not be enforced here (memory + pids, INCLUDING their \
                 defaults) - the box runs UNCAPPED, with no OOM / fork-bomb backstop. kern could not place \
                 it in a delegated cgroup: {}. `kern doctor` shows the delegation state; \
                 `--require-limits` refuses to start uncapped, `--allow-uncapped` silences this.",
                crate::cgroup::missing_manager_clause()
            );
        }
    }
    // Held for RAII: its Drop removes the box's cgroup dirs after waitpid (see CgroupGuard). Named
    // rather than `_`-prefixed because the forked child below reads it to join the capped cgroup: the
    // supervisor is no longer in that cgroup, so the workload is not placed there by inheritance.
    let cg = cg;
    pt_spawn.mark("parent:limits+cgroup");

    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    // `--pod`: JOIN the pod holder's existing user + net namespace (created by `kern pod create`)
    // instead of unsharing our own - so every box in the pod shares one loopback network. We start
    // in the host user ns, where we are privileged over our descendant holder, so we can `setns`
    // into it; then we unshare only pid/uts/ipc (mount is unshared in the child). No uid map - the
    // holder already mapped the pod user ns. This branch is fully separate from the normal one, so a
    // non-pod box is byte-for-byte unaffected.
    // Set in the non-pod branch below when a uid range was wanted and could not be built. Read once,
    // at the two exit points, and only when the box also failed: see `hint_missing_uid_range`.
    let mut range_unmet = false;
    if let Some(holder) = spec.pod_holder {
        let open_ns = |kind: &str| -> i32 {
            let p = format!("/proc/{holder}/ns/{kind}\0");
            unsafe {
                libc::open(
                    p.as_ptr() as *const libc::c_char,
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            }
        };
        let (user, net) = (open_ns("user"), open_ns("net"));
        if user < 0 || net < 0 {
            return Err(Error::Unsupported(
                "pod holder is gone (create the pod first with `kern pod create`)",
            ));
        }
        if unsafe { libc::setns(user, libc::CLONE_NEWUSER) } != 0 {
            let e = std::io::Error::last_os_error();
            return Err(Error::Syscall("setns(pod user)", e));
        }
        // TWO WAYS TO BE IN A POD, and they differ in exactly one namespace. Sharing the holder's
        // network namespace is the default and the fast one. With `--pod-bridge` the member unshares
        // its OWN network namespace and reaches its peers over the pod's bridge, which is what gives
        // it a `127.0.0.1` no peer can reach.
        match &spec.pod_bridge {
            None => {
                if unsafe { libc::setns(net, libc::CLONE_NEWNET) } != 0 {
                    let e = std::io::Error::last_os_error();
                    return Err(Error::Syscall("setns(pod net)", e));
                }
            }
            Some(at) => {
                if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                    let e = std::io::Error::last_os_error();
                    return Err(Error::Syscall("unshare(net) for the pod bridge", e));
                }
                // The member's OWN loopback, brought up before the bridge end arrives so a workload
                // that binds `127.0.0.1` finds it there whatever the bridge does.
                bring_loopback_up();
                attach_to_pod_bridge(holder, at)?;
            }
        }
        unsafe {
            libc::close(user);
            libc::close(net);
        }
        let rest = libc::CLONE_NEWPID | libc::CLONE_NEWUTS | libc::CLONE_NEWIPC;
        if unsafe { libc::unshare(rest) } != 0 {
            return Err(Error::Syscall(
                "unshare(pid+uts+ipc)",
                std::io::Error::last_os_error(),
            ));
        }
    } else {
        // Full namespace set: user + PID + UTS (hostname) + IPC, and - unless `--net` shares the host
        // network - an isolated (loopback-only) network namespace. The mount namespace is unshared in
        // the child (so its pivot doesn't touch the parent). With CLONE_NEWPID the *next* fork
        // becomes PID 1.
        let mut ns_flags =
            libc::CLONE_NEWUSER | libc::CLONE_NEWPID | libc::CLONE_NEWUTS | libc::CLONE_NEWIPC;
        if !spec.share_net {
            ns_flags |= libc::CLONE_NEWNET;
        }
        // Map the user namespace. The DEFAULT is the dependency-free single-uid identity map (box uid
        // 0 = caller) - no subprocess, one extra id in the namespace: the fastest and most isolated
        // option. `--uid-range` opts into a FULL subordinate range (box uid 0 → caller, uids 1..N →
        // the caller's `/etc/subuid` range) so software that drops to or `chown`s *other* uids works
        // (`apt`/`dpkg`, daemons that drop to `www-data`, …); it needs the setuid `newuidmap`/
        // `newgidmap` helpers and costs two subprocesses at start.
        let range = if spec.uid_range.is_on() {
            let r = detect_id_range(euid, egid);
            if r.is_none() && spec.uid_range == UidRange::Requested {
                // Requested but unavailable - don't silently behave as if mapped: tell the user, then
                // fall through to the safe single-uid map (apt-style workloads just lack extra uids).
                // A per-image default stays quiet here; see [`UidRange`].
                eprintln!(
                    "kern: --uid-range requested but unavailable (need newuidmap/newgidmap + an /etc/subuid+/etc/subgid allocation) - using single-uid map"
                );
            }
            r
        } else {
            None
        };
        // THE LAST UNMEASURED STEP ON THE RANGED PATH, and it sat inside `parent:unshare(ns)` where
        // it was indistinguishable from the namespace syscall itself. `detect_id_range` stats up to
        // four directories per helper, resolves the login name and reads `/etc/subuid` and
        // `/etc/subgid`; none of that is obviously free, and the difference between the ranged and
        // single-map arms of `parent:unshare(ns)` (about 100 us) had to be attributed to either this
        // or the helper fork, with no way to tell which.
        pt_spawn.mark("parent:id-range-detect");
        // Wanted and not buildable. Recorded for the ONE moment it is information rather than
        // noise: a non-zero exit, at the two returns below. `Requested` is deliberately excluded,
        // because it was already reported above, and saying the same thing twice about one
        // situation is how a message stops being read. Assigned here because the `match` below
        // consumes `range`, and declared outside this branch because a `--pod` box takes the other
        // one and never builds a range at all.
        range_unmet = spec.uid_range == UidRange::ImageDefault && range.is_none();
        match range {
            Some(range) => {
                // TWO MARKS, NOT ONE, and the same two on both arms. The ranged branch used to have no
                // mark at all, so a `KERN_TIMING` run of the `--image` path attributed about a
                // millisecond to nothing; then it had one, and the one hid which half was paying. The
                // inner `parent:unshare(ns)` is emitted by `apply_userns_range` itself, so the
                // difference between the two arms is exactly the id map and nothing else.
                apply_userns_range(ns_flags, euid, egid, &range, Some(&mut pt_spawn))?;
                pt_spawn.mark("parent:idmap");
            }
            None => {
                if unsafe { libc::unshare(ns_flags) } != 0 {
                    let e = std::io::Error::last_os_error();
                    if e.raw_os_error() == Some(libc::EPERM) {
                        return Err(Error::Unsupported(USERNS_UNAVAILABLE));
                    }
                    return Err(Error::Syscall("unshare(namespaces)", e));
                }
                pt_spawn.mark("parent:unshare(ns)");
                write_single_uid_map(euid, egid)?;
                pt_spawn.mark("parent:idmap");
            }
        }
    }

    // `--privileged` relaxes the seccomp filter so a NESTED box can create its own namespaces - but
    // ONLY when the box's root actually maps to an UNPRIVILEGED host uid. Decide from the EFFECTIVE
    // userns uid_map now that it is established (the single-uid / `--uid-range` map written above, OR
    // the holder's map we joined via `--pod` setns) - NOT from the caller's euid. In pod mode the
    // mapping is the holder's, so an euid-only proxy could relax a box whose root maps to host root;
    // reading the actual map closes that. Fails CLOSED on anything it can't confirm. (The CLI also
    // refuses `--privileged` as real root up front; this is the authoritative, property-based gate.)
    let allow_nesting = spec.privileged && box_root_is_unprivileged();

    // THE WORKLOAD'S CGROUP IS DECIDED BEFORE THE FORK, because that is the only place it can be used
    // to avoid a migration: `clone3(CLONE_INTO_CGROUP)` creates the child already inside, and the
    // `cgroup.procs` write below is what costs 5 to 20 ms on an idle machine (see `fork_into_cgroup`).
    // `None` means "the supervisor stays in the capped cgroup", where the child inherits it and there
    // is nothing to place.
    //
    // The binding is read again IN THE CHILD after the fork. That is sound and copies nothing: the
    // child is a copy-on-write duplicate of this address space, so `cg_target` names the same path
    // there, and `born_in_cgroup` carries the same value the parent computed.
    // Opened as a DESCRIPTOR, like the `kern exec` path, so both placements go through one API and
    // neither can be handed a path that stops naming anything after a namespace change. Nothing
    // crosses a `setns` here, so this is the same thing the path did; it is uniform on purpose.
    //
    // FAIL-CLOSED when the directory exists but cannot be opened: `cg_target` is `Some` only when a
    // cap was created and the supervisor stayed outside it, so a `None` here means the cap is real and
    // unreachable, and the child's placement below must refuse rather than run the box uncapped.
    let cg_target = cg
        .as_ref()
        .filter(|g| g.supervisor_is_outside())
        .map(|g| g.box_dir());
    let cg_ref = match cg_target.map(crate::cgroup::CgroupRef::open) {
        None => None,
        Some(Some(r)) => Some(r),
        Some(None) => {
            return Err(Error::Unsupported(
                "cannot open the box's cgroup to place it (the box would run without its caps)",
            ))
        }
    };
    let (pid, born_in_cgroup) = crate::cgroup::fork_into_cgroup(cg_ref.as_ref());
    if pid < 0 {
        return Err(Error::last("fork"));
    }
    if pid == 0 {
        // JOIN THE CAPPED CGROUP, FIRST, because nothing below is worth doing in a box that would run
        // without its memory ceiling and fork-bomb guard.
        //
        // The supervisor deliberately stays OUTSIDE that cgroup (see `apply_limits`): it carries
        // `memory.oom.group = 1`, so a process inside it is killed with the box and cannot report why the
        // box died. That means the workload is no longer placed there by inheritance and has to write
        // itself in. Done here, before any namespace or mount work, so a box that cannot be capped is
        // refused having changed nothing.
        //
        // FAIL-CLOSED: a failed write means this box has no cap of its own. `_exit(126)` rather than
        // continue, matching the fail-closed refusals in `apply_limits`, and one byte on the readiness fd
        // first so the launcher reports a start failure instead of waiting.
        //
        // SKIPPED ENTIRELY WHEN THE CHILD WAS BORN IN THE CGROUP. `born_in_cgroup` is true only when
        // `clone3(CLONE_INTO_CGROUP)` returned success, and the kernel places the task before the
        // syscall returns, so there is no window in which this process is outside `dir`. The
        // fail-closed property is unchanged: on every path where the kernel would not do it, the
        // write below still runs and still refuses.
        if let Some(cgr) = cg_ref.as_ref() {
            if !born_in_cgroup && !crate::cgroup::join_box_cgroup(cgr) {
                // AND SAY SO, because refusing in silence is its own defect. Measured by forcing
                // `EACCES` on the `cgroup.procs` open: the box exited 126 with ZERO bytes on either
                // stream, so a host that cannot delegate a cgroup answered `kern box --memory 64m`
                // with a bare 126 and nothing that named the cause. The safe branch was taken and
                // told nobody, which is the same defect as the silent unsafe branch read backwards.
                //
                // A literal through `write(2)` and not `eprintln!`: this is a forked child, and the
                // allocator's lock can have been copied held from a thread that no longer exists
                // here. Async-signal-safe or nothing.
                const MSG: &[u8] = b"kern: refusing to start: the box could not be placed in its \
                    own cgroup, so its --memory/--pids caps would not apply (cgroup delegation \
                    unavailable or not writable here)\n";
                unsafe { libc::write(2, MSG.as_ptr().cast(), MSG.len()) };
                if let Some(fd) = ready_fd {
                    let b = [1u8];
                    unsafe { libc::write(fd, b.as_ptr().cast(), 1) };
                }
                unsafe { libc::_exit(126) };
            }
            // Closed here, in the child, for the same reason as on the exec path: everything below is
            // namespace and mount setup, and it must not carry a descriptor onto `/sys/fs/cgroup`.
            cgr.close();
        }
        // CHILD (box PID 1): set up and exec. Take the readiness fd from the guard (this process
        // now owns the signalling) and mark it close-on-exec - a successful `execvp` then closes
        // it, so the waiting launcher reads EOF = "the box is up". On any error below we write one
        // byte first, so it learns it failed. (The guard is disarmed; the child never unwinds -
        // it always exec()s or `_exit`s - so its Drop never runs here.)
        //
        // FOREGROUND box: complete the death cascade. Arm `PR_SET_PDEATHSIG(SIGKILL)` relative to
        // the supervisor (our parent) FIRST, so if the supervisor is hard-killed - e.g. because ITS
        // launcher died and its own PDEATHSIG fired above - this pidns init dies too, and killing
        // PID 1 tears down the box's whole namespace. It survives the workload's (non-setuid)
        // execve; on the `--init` path PID 1 never execs and stays armed. Only for a foreground box:
        // a detached box's supervisor is its persistent owner, and teardown there stays with the
        // existing supervise/`kern stop` path, unchanged.
        //
        // Two honest bounds on this hop. (a) It is COOPERATIVE for a hostile PID 1: the box's own init
        // could `prctl(PR_SET_PDEATHSIG, 0)` to clear it (prctl isn't seccomp-blocked) or a setuid
        // entrypoint clears it on execve - that only drops the anti-orphan guarantee back to the
        // `--timeout` backstop (an availability property, not an isolation boundary). (b) Unlike the
        // supervisor leg we do NOT re-check `getppid()` after arming: this child is already PID 1 of
        // its new pid namespace (CLONE_NEWPID was unshared above), so `getppid()` reads 0 regardless of
        // the host-side supervisor's fate - a supervisor death in the fork→prctl microsecond window
        // simply falls through to the `--timeout` backstop, exactly as before this fix.
        if die_with_parent {
            unsafe {
                libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0,
                    0,
                    0,
                );
            }
        }
        let ready_fd = ready.disarm();
        if let Some(fd) = ready_fd {
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        match child_setup_and_exec(spec, &argv, ready_fd, allow_nesting) {
            Ok(never) => match never {},
            Err(e) => {
                if let Some(fd) = ready_fd {
                    let _ = unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
                }
                // `e` is EITHER a failed `execvp` (command not found/not executable - the common,
                // confusing case) OR a setup failure (mount, uid map, seccomp, AppArmor: the box could
                // not be built). `box_start_exit_code` maps the first to 126/127 and the second to 125
                // (Docker's "container failed to start"), so a setup failure is no longer mis-reported as
                // a "command not found" (127) the operator would chase in their own argv.
                report_exec_failure(spec, &e);
                unsafe { libc::_exit(box_start_exit_code(&e)) };
            }
        }
    }

    // PARENT (supervisor): the box was forked and now owns readiness signalling, so disarm our
    // guard and just drop our copy of the fd - the launcher then sees EOF exactly when the box
    // exec()s (or the failure byte if the box's own setup fails), not before.
    if let Some(fd) = ready.disarm() {
        unsafe { libc::close(fd) };
    }
    // Report PID 1 (for `kern exec`) and start the `-p` forwarders now that the box's net ns exists.
    let box_master = on_started(pid);
    forwarders.activate(pid);
    // `-it`: hand the terminal to the box. Drop our copy of the slave so the master sees EOF when
    // the box exits, then pump host stdio <-> master until then. Single-threaded by design - the
    // fork above must run in a single-threaded process (the child does non-async-signal-safe setup),
    // so we never spawn a pump thread.
    if let Some(master) = tty_master {
        if let Some(slave) = spec.tty_slave {
            unsafe { libc::close(slave) };
        }
        // PUMP THE BOX'S OWN MASTER WHEN THERE IS ONE. The host pair still exists and is still
        // valid; it is simply not the terminal the box took. Pumping the host master here would
        // move bytes to nobody, so the choice has to be made on the same fact the box made it on.
        let master = box_master.unwrap_or(master);
        let code = pty_pump_and_wait(master, pid);
        hint_missing_uid_range(range_unmet, code);
        return Ok(code); // `forwarders` drops here and stops them
    }
    // Whatever signal reaches this process, what it exits with must be the BOX's verdict rather than
    // its own death. A FOREGROUND box is the user's own process and nothing else would carry their
    // signal inwards, so it forwards; behind a supervisor the box is signalled directly and a forward
    // would be a second delivery, so it only survives. Same discriminant as the PDEATHSIG above.
    if die_with_parent {
        forward_signals_to_the_box(pid);
    } else {
        keep_waiting_through_signals();
    }
    // Reap the box (EINTR-robust, so a signal can't return early and drop the cgroup guard on a
    // still-live box → EBUSY leak).
    let mut status = 0i32;
    let rc = reap_retry_eintr(pid, &mut status);
    // `forwarders` drops on every return below, stopping them after the box is reaped.
    if rc < 0 {
        return Err(Error::last("waitpid"));
    }
    let code = wait_code(status);
    // LATCH THE OOM VERDICT HERE, the one point where it can still be read: the box is reaped, so its
    // counter is final, and `cg`'s `Drop` (which removes that directory) has not run yet. The caller
    // decides what to print only after this function returns, by which time the directory is gone -
    // measured, and the reason a first attempt that read the path later reported nothing at all.
    // Only on a SIGKILL exit, so the ordinary path reads no files.
    if code == 128 + libc::SIGKILL {
        if let Some(dir) = crate::cgroup::this_box_cgroup_dir() {
            crate::cgroup::latch_box_oom(dir);
        }
    }
    hint_missing_uid_range(range_unmet, code);
    Ok(code)
}

/// Say why an official image may have just failed, at the one moment that is information.
///
/// The `--image` path maps a uid RANGE by default, because an official image drops privilege in its
/// entrypoint and needs more than one id to do it. Where `newuidmap`/`newgidmap` or an `/etc/subuid`
/// allocation is missing the range cannot be built, and kern falls back to the safe single-uid map.
/// That fallback is silent on purpose: most images do not care, and a line on every box start on
/// such a host is noise that trains a reader to ignore stderr. This project already carries one
/// defect of exactly that shape, in the `--memory` warning gated on the request rather than the
/// outcome, so the fix here is deliberately not "warn earlier".
///
/// nginx does care. Measured with `nginx:alpine`: `chown nginx:nginx /tmp` succeeds with the range
/// and fails with `chown: /tmp: Invalid argument` without it, which is what its entrypoint runs
/// before starting. The image then dies on an error naming neither the uid range nor kern, and the
/// reader has nothing to search for.
///
/// So the line is emitted on the single combination where it carries information: the range was
/// wanted, could not be built, AND the box exited non-zero. It is worded as a possibility because it
/// is one - a workload is free to fail for its own reasons, and nothing here can tell the two apart.
/// A zero exit says the box did not need the range, which is the common case and stays silent.
/// The decision, split from the printing so the gating is testable without capturing stderr. Both
/// halves of the condition matter and each is a separate defect if dropped: without `range_unmet`
/// the note fires on every failing box, which is noise; without `code != 0` it fires on every box on
/// a host with no `newuidmap`, which is the noise the silent fallback exists to avoid.
#[inline]
const fn should_hint_uid_range(range_unmet: bool, code: i32) -> bool {
    range_unmet && code != 0
}

#[inline]
fn hint_missing_uid_range(range_unmet: bool, code: i32) {
    if !should_hint_uid_range(range_unmet, code) {
        return;
    }
    eprintln!(
        "kern: note: this box ran with a single-uid map because a uid range was unavailable (needs \
         newuidmap/newgidmap and an /etc/subuid+/etc/subgid allocation). An image that chowns or \
         drops privilege in its entrypoint fails that way, with an error of its own that does not \
         mention it. Install `uidmap` (Debian/Ubuntu) or `shadow-uidmap` (Alpine), or pass \
         --no-uid-range to say the single-uid map is what you want."
    );
}

/// Pump the host's stdin/stdout against a PTY `master` while the box (`pid`) runs, returning its
/// exit code. Single-threaded poll loop: host stdin → master, master → host stdout. A master EOF
/// (the box closed its slave) ends it; then we reap the box. The host terminal's raw mode + window
/// size are the CLI's responsibility (set before this call, restored after).
/// `-it`: adopt the PTY `slave` as the controlling terminal - a new session (so we may claim a
/// controlling tty), make the slave it, then dup it onto stdio. Shared by the `box` child and the
/// `exec` child so both get an identical interactive terminal.
fn adopt_controlling_tty(slave: i32) {
    unsafe {
        libc::setsid();
        libc::ioctl(slave, libc::TIOCSCTTY, 0);
        libc::dup2(slave, 0);
        libc::dup2(slave, 1);
        libc::dup2(slave, 2);
        if slave > 2 {
            libc::close(slave);
        }
    }
}

fn pty_pump_and_wait(master: i32, pid: i32) -> i32 {
    let mut buf = [0u8; 16384];
    let mut stdin_fd = 0i32; // set to -1 (ignored by poll) once host stdin hits EOF
    loop {
        let mut fds = [
            libc::pollfd {
                fd: stdin_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: master,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue; // SIGWINCH/SIGCHLD etc. - re-poll
            }
            break;
        }
        // master → host stdout first, so the box's final output is drained before we notice EOF.
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let r = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
            if r <= 0 {
                break; // box closed its slave
            }
            write_all(1, &buf[..r as usize]);
        }
        // host stdin → master
        if stdin_fd >= 0 && fds[0].revents & libc::POLLIN != 0 {
            let r = unsafe { libc::read(stdin_fd, buf.as_mut_ptr().cast(), buf.len()) };
            if r <= 0 {
                stdin_fd = -1; // host stdin EOF: stop forwarding, keep relaying box output
            } else {
                write_all(master, &buf[..r as usize]);
            }
        }
        if fds[0].revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            stdin_fd = -1;
        }
    }
    let mut status = 0i32;
    reap_retry_eintr(pid, &mut status);
    wait_code(status)
}

/// Write all of `data` to `fd`, retrying short and `EINTR` writes; best-effort (a closed peer
/// simply ends the transfer).
fn write_all(fd: i32, mut data: &[u8]) {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if n <= 0 {
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        data = &data[n as usize..];
    }
}

/// Defense-in-depth (least privilege): strip capabilities the box never legitimately needs from
/// the workload's effective/permitted/inheritable sets AND its bounding set, so neither the
/// workload nor a setuid/file-cap binary inside it can ever wield them. These are namespaced (they
/// grant no power over host-owned resources - verified) and several are already seccomp-blocked;
/// dropping them shrinks the attack surface against kernel bugs reachable only with the cap.
/// KEPT (so apt/apk, chown, and privilege-drop to non-root keep working): CHOWN, DAC_*, FOWNER,
/// FSETID, KILL, SETUID, SETGID, SETPCAP, NET_BIND_SERVICE, NET_RAW, SYS_CHROOT, MKNOD, SETFCAP,
/// IPC_*, SYS_NICE/RESOURCE, … Best-effort; an unknown cap number on an older kernel just fails
/// harmlessly.
/// `NET_ADMIN` (12) and `SYS_ADMIN` (21) are dropped too - this converges kern's default onto the
/// Docker/Podman default set - but CONDITIONALLY (see [`cap_drop_mask`]): `NET_ADMIN` is KEPT for
/// `--tun` (the box brings its own tunnel interface up; kern itself brings `lo` up BEFORE the drop, so
/// loopback is unaffected either way), and `SYS_ADMIN` for `--privileged` (in-namespace `mount`), and
/// either via `--cap-add`. Held only over the box's own user namespace regardless, and the escape
/// syscalls they would unlock (the mount API, `bpf`, `ptrace`) are seccomp-killed, so the drop closes a
/// residual against kernel bugs reachable only with the cap, not a live boundary hole.
/// The default set of never-needed dangerous caps kern always drops (kernel-stable numbers, used
/// directly so we don't depend on newer libc constants). NET_ADMIN and SYS_ADMIN are listed here so
/// the default drops them; the two condition flags re-KEEP them in [`cap_drop_mask`].
/// `CAP_NET_ADMIN` (network interface / routing / netfilter admin) and `CAP_SYS_ADMIN` (the broad
/// mount/sethostname/keyctl cap) - the two conditionally-kept caps. Named once here because each number
/// appears in BOTH [`DEFAULT_DROP`] (the default drops them) AND [`cap_drop_mask`] (a flag re-keeps
/// them); a literal in two places is the derived-condition trap this codebase keeps closing.
const CAP_NET_ADMIN: u32 = 12;
const CAP_SYS_ADMIN: u32 = 21;

const DEFAULT_DROP: &[u32] = &[
    CAP_NET_ADMIN, // (12) network admin. KEPT for `--tun` (the box needs it to bring its tunnel
    //     interface up) or `--cap-add NET_ADMIN`. kern brings the box's `lo` up itself, before the
    //     drop, so 127.0.0.1 works without it. Docker's default drops it; kern now matches, closing the
    //     gap against Podman (which also drops it).
    16, // SYS_MODULE     load kernel modules
    17, // SYS_RAWIO      raw I/O ports, /dev/mem, ioperm
    19, // SYS_PTRACE     the `ptrace`/`process_vm_*` syscalls are already seccomp-killed, but the cap
    //     ALSO bypasses the ptrace-access UID check on `/proc/<pid>/mem`, so dropping it closes a
    //     CROSS-UID read (one uid reading a different uid's memory in a multi-uid box). A SAME-uid
    //     sibling read stays possible - that is standard Linux and not a sandbox boundary, since a box
    //     is one trust domain; a host or peer-box process's memory is unreachable regardless, its pid
    //     not being in the box's pid namespace. Docker drops it by default; a debugger needs the killed
    //     `ptrace` syscall regardless, so this removes no capability a box could actually use.
    20,            // SYS_PACCT      process accounting
    CAP_SYS_ADMIN, // (21) the broadest cap (mount, sethostname, keyctl, …). KEPT for `--privileged` (a
    //     nested runtime / in-namespace `mount` needs it) or `--cap-add SYS_ADMIN` (e.g. a workload that
    //     calls `sethostname` itself; kern applies `--hostname` before the drop). Its escape syscalls
    //     (the mount API) are seccomp-killed on a non-privileged box regardless, so the drop is
    //     defense-in-depth, matching Docker's/Podman's default which also drops it.
    22, // SYS_BOOT       reboot / kexec_load
    25, // SYS_TIME       set system / RTC clock
    30, // AUDIT_CONTROL
    32, // MAC_OVERRIDE   bypass MAC (SELinux/AppArmor)
    33, // MAC_ADMIN
    34, // SYSLOG         syslog(2) / kernel pointers
    35, // WAKE_ALARM
    37, // AUDIT_READ
    38, // PERFMON        perf_event_open
    39, // BPF            load BPF programs
];

/// `--cap-add`/`--cap-drop` policy layered on top of the always-dropped [`DEFAULT_DROP`] set. Cap
/// numbers (not names) - the CLI resolves names and rejects unknown ones before the fork. Default
/// (`Default::default()`) drops exactly the dangerous set. All cap numbers are < 64 (the current
/// `CAP_LAST_CAP` is 40), so a single `u64` bitmask covers the whole set.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct CapSpec {
    /// `--cap-drop ALL`: drop every capability up to `CAP_LAST_CAP` (minus `adds`).
    pub drop_all: bool,
    /// Extra caps to drop beyond the default dangerous set.
    pub drops: Vec<u32>,
    /// Caps to KEEP - removed from the computed drop set (so `--cap-add` wins over a drop).
    pub adds: Vec<u32>,
}

/// The bitmask (bit N = cap N) of the dangerous caps kern ALWAYS drops from a box's bounding set
/// ([`DEFAULT_DROP`]). `kern top` reads a box's `CapBnd` and, if it intersects this mask, knows the box
/// re-added a normally-dropped cap via `--cap-add` - i.e. it is LESS confined than the default. A
/// rootless box's `CapEff` is full-but-namespaced (not a signal), so the bounding set is what matters.
pub fn default_dropped_cap_mask() -> u64 {
    DEFAULT_DROP.iter().fold(0u64, |m, &c| m | (1u64 << c))
}

/// The kernel's `CAP_LAST_CAP`, read from procfs (so a newer kernel's caps are covered by
/// `--cap-drop ALL`); falls back to 40 (`CAP_CHECKPOINT_RESTORE`) where the file is unreadable.
fn cap_last_cap() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n < 64) // our bitmask is 64-bit; guard against a pathological value
        .unwrap_or(40)
}

/// The capability drop set as a u64 bitmask (every cap number is < 64): always the dangerous
/// [`DEFAULT_DROP`] set, plus whatever `--cap-drop` adds (or *everything* for `--cap-drop ALL`),
/// minus whatever `--cap-add` keeps, minus the two CONDITIONAL keeps: `NET_ADMIN` (12) for `--tun`
/// and `SYS_ADMIN` (21) for `--privileged`. The conditional keeps are applied LAST so they win over a
/// contradictory explicit `--cap-drop` (the same "a keep wins over a drop" rule `--cap-add` follows),
/// which is what keeps `--tun`/`--privileged` from silently losing the cap the feature needs even under
/// `--cap-drop ALL`.
fn cap_drop_mask(spec: &CapSpec, tun: bool, privileged: bool) -> u64 {
    let mut mask: u64 = if spec.drop_all {
        let last = cap_last_cap();
        // bits 0..=last
        if last >= 63 {
            u64::MAX
        } else {
            (1u64 << (last + 1)) - 1
        }
    } else {
        DEFAULT_DROP.iter().fold(0u64, |m, &c| m | (1u64 << c))
    };
    for &c in &spec.drops {
        if c < 64 {
            mask |= 1u64 << c;
        }
    }
    // `--cap-add` wins: keep these even if the default set / ALL would drop them.
    for &c in &spec.adds {
        if c < 64 {
            mask &= !(1u64 << c);
        }
    }
    // `--tun` KEEPS CAP_NET_ADMIN: the box brings its own tunnel interface up in its netns. kern's own
    // `lo` is already up before the drop, so loopback never depended on this. Applied last so the tunnel
    // is never left without the cap it needs, even under `--cap-drop ALL`.
    if tun {
        mask &= !(1u64 << CAP_NET_ADMIN);
    }
    // `--privileged` KEEPS CAP_SYS_ADMIN: its seccomp relaxation lets a nested runtime / in-box `mount`
    // run, and those need the cap in the box's OWN user namespace. A non-privileged box has the mount
    // API seccomp-killed, so the cap is inert there and the drop costs it nothing.
    if privileged {
        mask &= !(1u64 << CAP_SYS_ADMIN);
    }
    mask
}

/// Drop the masked capabilities from the **bounding** set (`PR_CAPBSET_DROP`), so a file-cap binary
/// can't re-add them later. Needs `CAP_SETPCAP` in the *effective* set, so it must run BEFORE the
/// effective set is cleared and BEFORE any `setuid` to a non-root user (which sheds effective caps).
fn drop_cap_bounding(mask: u64) -> Result<(), Error> {
    // Drop each requested capability from the bounding set and, in the SAME pass, confirm it actually
    // went - measuring the OUTCOME per cap, not deducing it from a return code (capability bits are
    // independent, so dropping one never disturbs another's verdict):
    //   * `PR_CAPBSET_DROP` failing with EINVAL means the cap is past CAP_LAST_CAP (a `--cap-drop <N>`
    //     beyond the kernel's range) - nothing to drop, not a per-call failure; any OTHER error (EPERM =
    //     missing CAP_SETPCAP) fails closed at once.
    //   * `PR_CAPBSET_READ` then reads the cap back: 1 = still present (a leak), 0 = gone, <0/EINVAL = no
    //     such cap, never in `CapBnd`. A cap that EXISTS and reads back PRESENT means the drop silently
    //     failed and we refuse a weaker boundary than `--cap-drop` promised.
    // The per-cap `prctl` probe (a handful of microsecond calls over exactly the dropped caps) replaces
    // reading and parsing the ~1 KiB `/proc/self/status` on the box hot path; `read_cap_bnd` survives as
    // the unit test's whole-mask cross-check.
    let mut leaked = 0u64;
    for c in 0..64u32 {
        if mask & (1u64 << c) == 0 {
            continue;
        }
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, c as libc::c_ulong, 0, 0, 0) } != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EINVAL) {
                return Err(Error::Syscall("prctl(PR_CAPBSET_DROP)", e));
            }
        }
        if unsafe { libc::prctl(libc::PR_CAPBSET_READ, c as libc::c_ulong, 0, 0, 0) } == 1 {
            leaked |= 1u64 << c;
        }
    }
    if leaked != 0 {
        return Err(Error::Spec(format!(
            "capability bounding-set drop did not take: caps {leaked:#018x} still present in CapBnd \
             after PR_CAPBSET_DROP (refusing a weaker boundary than --cap-drop asked)"
        )));
    }
    Ok(())
}

/// The process bounding capability set (`CapBnd`) from `/proc/self/status`, as a u64 bitmask. The box
/// hot path now VERIFIES the `PR_CAPBSET_DROP` sweep per-cap with `PR_CAPBSET_READ` (no `/proc` parse),
/// so this whole-mask reader survives only as the cross-check the unit test asserts against - hence
/// `#[cfg(test)]`, to keep it out of the production binary rather than leave it dead there.
#[cfg(test)]
fn read_cap_bnd() -> Result<u64, Error> {
    let s = std::fs::read_to_string("/proc/self/status")
        .map_err(|e| Error::Syscall("read /proc/self/status", e))?;
    let hex = s
        .lines()
        .find_map(|l| l.strip_prefix("CapBnd:"))
        .map(str::trim)
        .ok_or_else(|| Error::Spec("no CapBnd line in /proc/self/status".into()))?;
    u64::from_str_radix(hex, 16)
        .map_err(|_| Error::Spec(format!("unparsable CapBnd value '{hex}'")))
}

/// Apply `--ulimit` resource limits with `setrlimit(2)`.
///
/// FAIL-CLOSED FOR A LIMIT THAT BINDS, CLAMPED-AND-SAID FOR ONE THAT DOES NOT.
///
/// A workload that asked to be CONFINED and silently got a wider bound is a correctness bug: it
/// surfaces later as a fork bomb that was supposed to be capped. Lowering either bound always
/// succeeds rootless, so a refusal there is a real failure and stays one.
///
/// RAISING is the opposite ask and it is the common one in compose files: `memlock: -1` and
/// `nofile: 65536` are Elasticsearch's standard block, present in thousands of stacks. The kernel
/// refuses that rootless - a hard bound goes up only with `CAP_SYS_RESOURCE` in the INIT user
/// namespace - and refusing to start cost the whole service. MEASURED: `--ulimit memlock=-1:-1`
/// (OpenCTI's Elasticsearch, verbatim) failed with EPERM on a host whose hard limit is 4085088, and
/// the box never ran. Docker on the same rootless host cannot grant it either; the difference is
/// that kern was turning "you get less headroom" into "you get nothing".
///
/// So a refused RAISE is retried at the highest value this box can have - its inherited hard bound -
/// and the difference is NAMED. Nothing is confined more loosely than asked: the clamp can only
/// lower what was requested.
/// The `--ulimit` names, the `RLIMIT_*` each resolves to, the `ulimit` flag that reads the same bound
/// in a shell (verified against `help ulimit`, not guessed), and the UNIT `setrlimit` counts in
/// (`getrlimit(2)`; empty where the value is a bare number, as for `nice` and `rtprio`).
///
/// ONE table, read in BOTH directions, and it lives at this layer rather than in the CLI because
/// this is where the failures are. The clamp warning below used to say `--ulimit resource 8`: the
/// operator wrote `memlock`, compose wrote `memlock`, and the only place the number appeared was
/// kern's own diagnostic. Naming it needs the reverse lookup here, and a second copy of the table in
/// two crates is how the two spellings drift.
///
/// The unit column is not decoration. `--ulimit memlock=-1` on this host clamps to 4183130112, while
/// the `ulimit -l` the message sends the operator to prints 4085088: the same limit in KILOBYTES.
/// A number offered for comparison against a command that scales it differently is a wrong number.
// THE CAST IS REAL ON ONE LIBC AND A NO-OP ON ANOTHER, so exactly one of them is always going to
// call it unnecessary. `RLIMIT_*` is `u32` under glibc and already `c_int` under musl: dropping the
// cast stops the build on glibc, keeping it makes clippy fail the musl target under `-D warnings`,
// and the release SHIPS musl. CI lints the gnu target, so this divergence was invisible there and
// showed up the first time the shipped target was linted: 17 errors, on code that is correct.
// One allow, on the one table where the platform types meet, is the whole fix.
#[allow(clippy::unnecessary_cast)]
pub const ULIMITS: &[(&str, i32, char, &str)] = &[
    ("core", libc::RLIMIT_CORE as i32, 'c', "bytes"),
    ("cpu", libc::RLIMIT_CPU as i32, 't', "seconds"),
    ("data", libc::RLIMIT_DATA as i32, 'd', "bytes"),
    ("fsize", libc::RLIMIT_FSIZE as i32, 'f', "bytes"),
    ("locks", libc::RLIMIT_LOCKS as i32, 'x', "locks"),
    ("memlock", libc::RLIMIT_MEMLOCK as i32, 'l', "bytes"),
    ("msgqueue", libc::RLIMIT_MSGQUEUE as i32, 'q', "bytes"),
    ("nice", libc::RLIMIT_NICE as i32, 'e', ""),
    ("nofile", libc::RLIMIT_NOFILE as i32, 'n', "descriptors"),
    ("nproc", libc::RLIMIT_NPROC as i32, 'u', "processes"),
    ("rss", libc::RLIMIT_RSS as i32, 'm', "bytes"),
    ("rtprio", libc::RLIMIT_RTPRIO as i32, 'r', ""),
    ("rttime", libc::RLIMIT_RTTIME as i32, 'R', "microseconds"),
    ("sigpending", libc::RLIMIT_SIGPENDING as i32, 'i', "signals"),
    ("stack", libc::RLIMIT_STACK as i32, 's', "bytes"),
];

/// The name a `RLIMIT_*` number was written as, the `ulimit` flag that reads it in a shell, and the
/// unit its value is counted in.
pub fn ulimit_named(resource: i32) -> Option<(&'static str, char, &'static str)> {
    ULIMITS
        .iter()
        .find(|(_, r, _, _)| *r == resource)
        .map(|(n, _, f, u)| (*n, *f, *u))
}

/// An rlimit value as the operator wrote it: `RLIM_INFINITY` is `unlimited`, not 18446744073709551615.
fn rlim_text(v: libc::rlim_t) -> String {
    if v == libc::RLIM_INFINITY {
        "unlimited".to_string()
    } else {
        v.to_string()
    }
}

fn apply_ulimits(limits: &[(i32, u64, u64)]) -> Result<(), Error> {
    for &(resource, soft, hard) in limits {
        let rl = libc::rlimit {
            rlim_cur: soft as libc::rlim_t,
            rlim_max: hard as libc::rlim_t,
        };
        // SAFETY: `resource` is one of the RLIMIT_* constants (the CLI resolves the name against a
        // fixed table and rejects anything else), and `rl` is a fully initialised `rlimit` we own.
        if unsafe { libc::setrlimit(resource as _, &rl) } == 0 {
            continue;
        }
        let e = std::io::Error::last_os_error();
        // The inherited bounds, which are the ceiling a rootless box cannot pass.
        let mut cur = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: same constant, and `cur` is a live `rlimit` this call fills in.
        let have = unsafe { libc::getrlimit(resource as _, &mut cur) } == 0;
        let raising = have && hard as libc::rlim_t > cur.rlim_max;
        if e.raw_os_error() == Some(libc::EPERM) && raising {
            let clamped = libc::rlimit {
                rlim_cur: (soft as libc::rlim_t).min(cur.rlim_max),
                rlim_max: cur.rlim_max,
            };
            // SAFETY: as above; `clamped` is derived from values the kernel just reported.
            if unsafe { libc::setrlimit(resource as _, &clamped) } == 0 {
                // NAME THE LIMIT AND WHERE IT LIVES. An operator reading this has one decision to
                // make - accept the headroom or change the host - and the warning has to carry
                // enough to make it: which limit (by the name they typed, not the RLIMIT_ number),
                // what the ceiling actually is, and the three places that ceiling is set. kern
                // cannot raise it from inside, so the remedy is never anything kern can do.
                let named = ulimit_named(resource);
                let label = match named {
                    Some((n, _, _)) => format!("--ulimit {n}"),
                    None => format!("--ulimit resource {resource}"),
                };
                // The unit belongs to the numbers, not to the remedy: `ulimit -l` prints kilobytes
                // for the same bound `setrlimit` counts in bytes, so the ceiling is pointed at by
                // NAME and the operator reads its value from the host in the host's own units.
                let unit = match named {
                    Some((_, _, u)) if !u.is_empty() => format!(" {u}"),
                    _ => String::new(),
                };
                let where_to_change = match named {
                    Some((n, f, _)) => format!(
                        " If the service really needs more, the ceiling is the HOST's own {n} \
                         limit: `ulimit -{f}` in the shell that starts kern, a `{n}` line in \
                         /etc/security/limits.conf, or Limit{}= in its systemd unit.",
                        n.to_ascii_uppercase()
                    ),
                    None => String::new(),
                };
                // MEMLOCK IS NOT LIKE THE OTHERS, and a clamped `memlock: -1` is the single most
                // common one in the wild (Elasticsearch, OpenSearch and everything derived from
                // their compose files ship it). `mlockall` charges the whole RESERVED address space,
                // not the resident set, so a JVM that reserves more than this ceiling cannot lock at
                // all and `bootstrap.memory_lock: true` then refuses to start rather than running
                // with less. MEASURED in a box with this exact ceiling: 8 GiB of PROT_NONE
                // reservation made `mlockall` return ENOMEM, 1 GiB returned 0, and Elastic's own
                // three-node compose file died with "memory locking requested ... but memory is not
                // locked". Saying only "less headroom" would describe that as a degradation when it
                // is a refusal.
                // Same platform split as `ULIMITS`: `RLIMIT_MEMLOCK` is `u32` under glibc and
                // `c_int` under musl, so the cast is required on one and redundant on the other.
                #[allow(clippy::unnecessary_cast)]
                let is_memlock = resource == libc::RLIMIT_MEMLOCK as i32;
                let locking = if is_memlock && hard as libc::rlim_t == libc::RLIM_INFINITY {
                    " A process that calls `mlockall` counts its whole reserved address space \
                     against this, not the memory it is using, so a workload that REQUIRES memory \
                     locking (Elasticsearch's `bootstrap.memory_lock`) refuses to start here rather \
                     than running with less."
                } else {
                    ""
                };
                eprintln!(
                    "kern: warning: {label}: asked for soft {} / hard {}, applied soft {} / hard \
                     {}{unit} - a rootless box cannot raise a hard limit (that needs \
                     CAP_SYS_RESOURCE in the initial user namespace), so it keeps the one it \
                     inherited. The workload runs with less headroom than the file asked \
                     for.{locking}{where_to_change}",
                    rlim_text(soft as libc::rlim_t),
                    rlim_text(hard as libc::rlim_t),
                    rlim_text(clamped.rlim_cur),
                    rlim_text(clamped.rlim_max)
                );
                continue;
            }
        }
        let hint = if e.raw_os_error() == Some(libc::EPERM) {
            " (raising a HARD limit needs CAP_SYS_RESOURCE in the initial user namespace - a \
             rootless box can only LOWER its inherited limits)"
        } else {
            ""
        };
        // Same reason as the warning above: the operator typed a name, so the failure says the name.
        let label = match ulimit_named(resource) {
            Some((n, _, _)) => n.to_string(),
            None => format!("resource {resource}"),
        };
        return Err(Error::Spec(format!(
            "--ulimit {label}: setrlimit(soft {}, hard {}) failed: {e}{hint}",
            rlim_text(soft as libc::rlim_t),
            rlim_text(hard as libc::rlim_t)
        )));
    }
    Ok(())
}

/// Apply `--sysctl KEY=VALUE` by writing `/proc/sys/<key with '.' → '/'>`.
///
/// FAIL-CLOSED, like Docker: a container that asked for `net.core.somaxconn=1024` and silently ran
/// with the host default has different behaviour under load than it asked for. Only NAMESPACED knobs
/// are writable from inside (the box owns its uts/ipc namespaces, and its net namespace when it has
/// one); a host-global knob belongs to the init user namespace and the kernel returns EPERM/EACCES,
/// which is reported with that distinction so the operator knows it is a namespace-ownership issue
/// and not a typo.
///
/// The key is validated as a *relative* `a.b.c` path before it is joined: a key containing `/`, `..`
/// or a leading separator could otherwise be steered outside `/proc/sys` and turn a config field into
/// an arbitrary-file write.
fn apply_sysctls(sysctls: &[(String, String)]) -> Result<(), Error> {
    for (key, value) in sysctls {
        if key.is_empty()
            || key.contains('/')
            || key
                .split('.')
                .any(|seg| seg.is_empty() || seg == "." || seg == "..")
        {
            return Err(Error::Spec(format!(
                "--sysctl '{key}': invalid key (expected dotted form like net.core.somaxconn, with no \
                 '/' or empty/'..' segments)"
            )));
        }
        let mut path = String::with_capacity("/proc/sys/".len() + key.len());
        path.push_str("/proc/sys/");
        for (i, seg) in key.split('.').enumerate() {
            if i > 0 {
                path.push('/');
            }
            path.push_str(seg);
        }
        if let Err(e) = std::fs::write(&path, value.as_bytes()) {
            let why = match e.kind() {
                std::io::ErrorKind::NotFound => {
                    " (no such knob on this kernel, or it is not visible in this namespace)"
                }
                std::io::ErrorKind::PermissionDenied => {
                    " (not a namespaced knob, or this namespace is not owned by the box's user \
                     namespace - a rootless box can only set knobs it owns; `net.*` needs its own \
                     network namespace, e.g. a pod or --network)"
                }
                _ => "",
            };
            return Err(Error::Spec(format!(
                "--sysctl {key}={value}: writing {path} failed: {e}{why}"
            )));
        }
    }
    Ok(())
}

/// Clear the masked capabilities from the live effective/permitted/inheritable sets (the workload
/// won't hold them after exec). For a non-root `--user`, `setuid` has already emptied these; this
/// still matters for a root box and is a harmless no-op otherwise.
fn clear_caps_from_sets(mask: u64) -> Result<(), Error> {
    let lo = (mask & 0xffff_ffff) as u32;
    let hi = (mask >> 32) as u32;
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut hdr = CapHeader {
        version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // FAIL CLOSED on either syscall: this is what actually strips the dangerous caps from the
    // workload's effective/permitted/inheritable sets. Swallowing an error left the workload holding
    // caps the box promised to drop. `capget` failing (an unreadable cap header) means we cannot know
    // what to clear; `capset` clears bits ONLY (an all-subset write, which is always permitted), so a
    // failure there is a genuine anomaly, not a policy refusal - either way the box must not run
    // pretending the caps are gone.
    unsafe {
        if libc::syscall(libc::SYS_capget, &mut hdr as *mut _, data.as_mut_ptr()) != 0 {
            return Err(Error::last("capget"));
        }
        data[0].effective &= !lo;
        data[0].permitted &= !lo;
        data[0].inheritable &= !lo;
        data[1].effective &= !hi;
        data[1].permitted &= !hi;
        data[1].inheritable &= !hi;
        if libc::syscall(libc::SYS_capset, &hdr as *const _, data.as_ptr()) != 0 {
            return Err(Error::last("capset"));
        }
    }
    Ok(())
}

/// Drop capabilities for the workload: always the dangerous [`DEFAULT_DROP`] set, plus `--cap-drop`
/// (or *everything* for `--cap-drop ALL`), minus `--cap-add`. Clears the effective/permitted/
/// inheritable sets AND the bounding set. Used where NO `--user` switch follows (e.g. `kern exec`);
/// the box workload path splits this around `set_user` (bounding drop → setuid → effective clear) so
/// that `--cap-drop ALL` doesn't strip `CAP_SETUID`/`SETGID` before the user switch needs them.
/// `tun`/`privileged` are passed FALSE here on purpose: `kern exec` reproduces the box's explicit
/// `--cap-add`/`--cap-drop` (via `spec`) but NOT the implicit `--tun`/`--privileged` keeps, staying
/// MORE constrained than the box's PID 1 - the same deliberate "exec stays strict" axis as nesting.
fn drop_dangerous_caps(spec: &CapSpec) -> Result<(), Error> {
    let mask = cap_drop_mask(spec, false, false);
    drop_cap_bounding(mask)?;
    clear_caps_from_sets(mask)?;
    Ok(())
}

/// The same shed, keeping SEVERAL descriptors instead of one.
///
/// The egress pump needs two: the pipe it reads the box pid from, and the pipe it answers its
/// readiness on. Keeping only one of them would either leave it unable to be told which box to join,
/// or unable to report that it is listening, and the second failure is silent by construction: the
/// reader would wait on a pipe whose only writer had been closed underneath it.
///
/// `keep` is expected to be tiny (two entries today), so the linear scan per fd costs nothing next to
/// the syscalls; correctness here is worth more than one `close_range` call. Best-effort like the
/// single-fd version: closing an unopened fd is a harmless EBADF.
pub fn shed_inherited_fds_keeping(keep: &[i32]) {
    for fd in 3..1024 {
        if !keep.contains(&fd) {
            unsafe { libc::close(fd) };
        }
    }
}

/// After `fork()`, close every inherited fd `>= 3` except `keep` (pass `-1` to keep none). Two callers
/// need it: a long-lived helper child (a `-p` forwarder, a health-checker) sheds the parent's fds -
/// most importantly a detached box's readiness-pipe write end, whose lingering copy would stop the
/// launcher from ever seeing EOF and hang `kern box -d`; and the box workload / `kern exec` path sheds
/// them for ISOLATION, so a descriptor kern's caller left open (an SDK's socket, a host file) does not
/// pass through `execvp` into the box as a handle to a host object outside the rootfs (CVE-2016-9962).
///
/// One `close_range(2)` syscall replaces the old ~1021-iteration `close()` loop; to preserve `keep`
/// we close the two ranges around it. Falls back to the per-fd loop on a kernel without close_range
/// (< 5.9 → ENOSYS). Best-effort throughout: closing an unopened fd is a harmless EBADF.
pub fn shed_inherited_fds(keep: i32) {
    let close_range = |lo: u32, hi: u32| -> i64 {
        unsafe {
            libc::syscall(
                libc::SYS_close_range,
                lo as libc::c_uint,
                hi as libc::c_uint,
                0,
            )
        }
    };
    const HI: u32 = u32::MAX; // "up to the highest fd"
    let ok = if keep < 3 {
        close_range(3, HI) == 0
    } else {
        let k = keep as u32;
        close_range(3, k - 1) == 0 && close_range(k + 1, HI) == 0
    };
    if !ok {
        for fd in 3..1024 {
            if fd != keep {
                unsafe { libc::close(fd) };
            }
        }
    }
}

/// Does `pid1` share OUR `kind` namespace? Compared by the `(dev, ino)` identity of
/// `/proc/<pid>/ns/<kind>`: `stat` follows the ns link to the nsfs inode, which IS the kernel's
/// namespace identity (the number `readlink` renders as `net:[…]`).
///
/// Fails CLOSED, and the closed direction is `false` = "treat it as separate and try to join". A
/// wrong `true` would SKIP a namespace and run the command outside part of the box's isolation, so
/// anything unreadable is left for `setns` to refuse; a wrong `false` only costs the `EPERM` that
/// this predicate exists to avoid.
fn shares_our_namespace(pid1: i32, kind: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    let id =
        |p: &str| -> Option<(u64, u64)> { std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino())) };
    match (
        id(&format!("/proc/self/ns/{kind}")),
        id(&format!("/proc/{pid1}/ns/{kind}")),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Bring the loopback interface (`lo`) up in the current network namespace via `SIOCSIFFLAGS`, so
/// `127.0.0.1` works inside an otherwise-isolated box. Best-effort (a fresh net ns owned by our
/// user namespace grants CAP_NET_ADMIN, so this normally succeeds; failures leave `lo` down).
///
/// IDEMPOTENT, and that is load-bearing rather than incidental: two processes reach for this on the
/// same net ns. The box's own init calls it during setup, and the egress pump calls it after joining
/// the ns from outside, because the pump is handed the box's pid the instant `clone` returns and
/// cannot wait for an init that is still pivoting its root. Whoever arrives second reads the flag,
/// finds it set and returns: ONE ioctl, and no write at all. (A first draft of this comment said the
/// second caller "re-raises a no-op", which describes a simpler implementation than the one here.)
///
/// Returns whether `lo` carries `IFF_UP` on the way out, `true` included for a loopback something
/// else had already raised.
///
/// `IFF_UP` is the flag and `127.0.0.1` is an address, and a caller about to `bind` needs the second.
/// They are not the same thing, so this was measured rather than assumed. In a fresh net ns:
///
///   before  IFF_UP=0  SIOCGIFADDR=-1 EADDRNOTAVAIL   (no address at all)
///   after   IFF_UP=1  SIOCGIFADDR=0  127.0.0.1
///
/// The kernel assigns the loopback address when the interface comes up, so raising the flag is what
/// makes the address exist and the flag IS the thing to report. If that ever stops being true on some
/// kernel, this function is where it breaks, and `SIOCGIFADDR` after the set is the stronger check.
pub fn bring_loopback_up() -> bool {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return false;
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        ifr.ifr_name[0] = b'l' as libc::c_char;
        ifr.ifr_name[1] = b'o' as libc::c_char;
        // `ioctl`'s request arg is `c_ulong` on x86_64 but `c_int` on aarch64 - `as _` casts the
        // SIOC* constant to whatever this target expects, so this compiles on every arch.
        let mut up = false;
        if libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) == 0 {
            if ifr.ifr_ifru.ifru_flags & libc::IFF_UP as i16 != 0 {
                up = true; // already up: someone else won the race, which is a success for us
            } else {
                ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
                up = libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) == 0;
            }
        }
        libc::close(sock);
        up
    }
}

/// The interface alias label kern gives one extra loopback address: `lo:` + the address in hex.
///
/// DERIVED FROM THE ADDRESS AND NOT FROM A COUNTER, and that is the whole reason this is a function.
/// `SIOCSIFADDR` sets the address OF A LABEL, so two boxes in one pod both writing `lo:0` would have
/// the second replace the first's address rather than add to it, and the first service would quietly
/// lose the address the file gave it. Keyed by the address, a repeated call is idempotent and two
/// different addresses cannot collide. Eight hex digits keep the label at 11 characters, inside the
/// kernel's 15-character limit for every possible address, which a decimal label is not.
#[must_use]
pub fn loopback_alias_label(ip: std::net::Ipv4Addr) -> String {
    let o = ip.octets();
    format!("lo:{:02x}{:02x}{:02x}{:02x}", o[0], o[1], o[2], o[3])
}

/// Give `lo` an extra address in the current network namespace, as a `/32`.
///
/// WHY A BOX NEEDS ONE. A compose file that writes `ipv4_address:` under a service's `networks:` is
/// naming the address its peers connect to, and a kern stack has no user-defined subnet to allocate
/// from, so the literal address existed NOWHERE and a peer that hard-coded it got no route. Every
/// address in `127.0.0.0/8` is local on `lo` without configuration, which is why the per-service
/// aliases need none; an address outside it has to be added.
///
/// `ioctl` AND NOT NETLINK, matching [`bring_loopback_up`]: the same `AF_INET` socket, two calls,
/// no message construction and no dependency. Measured in a rootless `unshare -rn`: `SIOCSIFADDR`
/// followed by `SIOCSIFNETMASK` on a per-address label gives `172.20.0.5/32 scope global`, a second
/// identical call returns 0 again, and a listener on `0.0.0.0` answers on it.
///
/// CALLED BEFORE THE CAPABILITY DROP, because it needs `CAP_NET_ADMIN` and kern takes that away from
/// the box: measured from inside a running box, `ip addr add` answers `RTNETLINK answers: Operation
/// not permitted` with bit 12 clear in `CapEff`. The box gets the address and still cannot
/// reconfigure the network afterwards, which is the posture kern wants.
/// Write an interface name into an `ifreq`, bounded by the array the kernel reads.
fn ifr_name(ifr: &mut libc::ifreq, name: &str) {
    for (i, b) in name.bytes().enumerate() {
        if i + 1 >= ifr.ifr_name.len() {
            break;
        }
        ifr.ifr_name[i] = b as libc::c_char;
    }
}

/// One `SIOCSIFADDR`-family call: an interface name and one IPv4 value.
///
/// ONE DEFINITION FOR THE ADDRESS AND THE MASK, and for the loopback alias and the bridge member
/// alike. The byte-order line is the whole reason: `octets()` is already network order and
/// `from_ne_bytes` keeps that layout, so a `to_be()` here would write the address backwards on a
/// little-endian machine. Written once, it can only be wrong once.
fn iface_set_ipv4_field(
    sock: libc::c_int,
    name: &str,
    request: libc::c_ulong,
    addr: std::net::Ipv4Addr,
) -> bool {
    // SAFETY: an `ifreq` filled in full before the ioctl reads it.
    unsafe {
        let mut ifr: libc::ifreq = std::mem::zeroed();
        ifr_name(&mut ifr, name);
        let sin = std::ptr::addr_of_mut!(ifr.ifr_ifru.ifru_addr).cast::<libc::sockaddr_in>();
        (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
        (*sin).sin_port = 0;
        (*sin).sin_addr.s_addr = u32::from_ne_bytes(addr.octets());
        libc::ioctl(sock, request as _, &ifr) == 0
    }
}

/// Give an interface an IPv4 address and netmask in the current network namespace.
pub fn iface_set_ipv4(name: &str, ip: std::net::Ipv4Addr, mask: std::net::Ipv4Addr) -> bool {
    // SAFETY: a datagram socket opened only to carry the ioctls, closed on every path.
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return false;
        }
        let ok = iface_set_ipv4_field(sock, name, libc::SIOCSIFADDR, ip)
            && iface_set_ipv4_field(sock, name, libc::SIOCSIFNETMASK, mask);
        libc::close(sock);
        ok
    }
}

/// Raise `IFF_UP` on an interface in the current network namespace. Idempotent.
pub fn iface_up(name: &str) -> bool {
    // SAFETY: an `ifreq` read back before it is written, on a socket closed on every path.
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return false;
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        ifr_name(&mut ifr, name);
        let mut ok = false;
        if libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) == 0 {
            if ifr.ifr_ifru.ifru_flags & libc::IFF_UP as i16 != 0 {
                ok = true;
            } else {
                ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
                ok = libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) == 0;
            }
        }
        libc::close(sock);
        ok
    }
}

/// Rename an interface (it must be down), so a `veth` end created with a unique name in the holder's
/// namespace becomes the ordinary `eth0` inside the box.
///
/// UNIQUE ON CREATION, ORDINARY AFTER THE MOVE. Both ends are created in the HOLDER's namespace,
/// where every member's ends live at once, so a member cannot create `eth0` there without colliding
/// with the next member. The name only has to be ordinary on the far side, which is after the move.
pub fn iface_rename(old: &str, new: &str) -> bool {
    // SAFETY: both names are written into the fixed-size arrays the ioctl reads.
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return false;
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        ifr_name(&mut ifr, old);
        let np = std::ptr::addr_of_mut!(ifr.ifr_ifru.ifru_newname).cast::<libc::c_char>();
        for (i, b) in new.bytes().enumerate() {
            if i + 1 >= libc::IFNAMSIZ {
                break;
            }
            *np.add(i) = b as libc::c_char;
        }
        let ok = libc::ioctl(sock, libc::SIOCSIFNAME as _, &ifr) == 0;
        libc::close(sock);
        ok
    }
}

pub fn add_loopback_alias(ip: std::net::Ipv4Addr) -> bool {
    let label = loopback_alias_label(ip);
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return false;
        }
        let set = |request: libc::c_ulong, addr: std::net::Ipv4Addr| -> bool {
            iface_set_ipv4_field(sock, &label, request, addr)
        };
        // VERIFIED AND RETRIED, BECAUSE A CONCURRENT ADD LOSES ONE. Two boxes joining the same pod
        // add their addresses to the same `lo` at the same time, and the legacy label interface
        // drops one of them: MEASURED with two `kern box --pod` started in parallel, where only the
        // later address survived, while the identical pair added one after the other both stuck.
        // The check is a `bind` rather than a read-back ioctl because binding is the thing the
        // caller actually needs to be true, and an address that cannot be bound is not there
        // whatever a query says.
        let mut ok = false;
        for _ in 0..ATTEMPTS {
            if set(libc::SIOCSIFADDR, ip)
                && set(
                    libc::SIOCSIFNETMASK,
                    std::net::Ipv4Addr::new(255, 255, 255, 255),
                )
                && ipv4_is_local(sock, ip)
            {
                ok = true;
                break;
            }
            // Short enough that a whole retry budget is invisible next to a box start, long enough
            // that the racing process gets to finish rather than being fought for the same slot.
            std::thread::sleep(std::time::Duration::from_millis(RETRY_MS));
        }
        libc::close(sock);
        ok
    }
}

/// How many times [`add_loopback_alias`] re-adds an address it cannot bind afterwards.
const ATTEMPTS: usize = 12;
/// The pause between those attempts.
const RETRY_MS: u64 = 5;

/// Can this address be bound in the current network namespace?
///
/// The direct question the caller has: `bind` succeeds on a local address and fails with
/// `EADDRNOTAVAIL` on one the namespace does not hold. Port 0 so the kernel picks an ephemeral one
/// and nothing is claimed; the socket is closed immediately.
fn ipv4_is_local(_probe: libc::c_int, ip: std::net::Ipv4Addr) -> bool {
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if s < 0 {
            return false;
        }
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = 0;
        sa.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
        let r = libc::bind(
            s,
            std::ptr::addr_of!(sa).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        libc::close(s);
        r == 0
    }
}

/// The bridge interface a pod holder builds, and the one its members attach to.
pub const POD_BRIDGE: &str = "kbr0";

/// A member's place on the pod bridge: the address it takes and the size of the network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeAttach {
    /// The address this box answers on, reachable from every other member.
    pub ip: std::net::Ipv4Addr,
    /// Prefix length of the pod's network, so the member knows which peers are directly connected.
    pub prefix: u8,
}

/// Split `10.89.0.0/24` into the address a bridge takes (`.1`) and its netmask.
///
/// THE GATEWAY IS THE FIRST HOST ADDRESS, which is the convention every reader expects and the one
/// Docker uses for its own bridges. Members start at `.2`, the same place kern's loopback aliases
/// start, for the same reason: `.0` is the network and `.1` is where the bridge sits.
#[must_use]
pub fn pod_bridge_parts(cidr: &str) -> Option<(std::net::Ipv4Addr, std::net::Ipv4Addr, u8)> {
    let (net, prefix) = cidr.split_once('/')?;
    let net: std::net::Ipv4Addr = net.trim().parse().ok()?;
    let prefix: u8 = prefix.trim().parse().ok()?;
    // A /31 or /32 holds no bridge and two members; anything wider than /8 is not a mistake this
    // should silently accept either.
    if !(8..=30).contains(&prefix) {
        return None;
    }
    // LOOPBACK IS NOT A NETWORK A BRIDGE CAN CARRY, and accepting it built a pod in which nothing
    // worked and nothing said so. MEASURED: `pod create --bridge 127.0.0.0/8` succeeded, two members
    // joined with `--pod-bridge 127.0.0.5/8` and `127.0.0.6/8` started and got those addresses on
    // `eth0`, and then the first could not reach the second at all (`nc` rc=1) and the peer's NAME
    // did not resolve. The kernel routes 127/8 to `lo` inside each namespace, so the packets never
    // crossed the bridge. A pod that comes up and silently isolates every member is the exact shape
    // the holder's fail-closed check above exists to prevent; the check could not see it because the
    // bridge itself was built without error.
    if net.is_loopback() {
        return None;
    }
    let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
    let base = u32::from_be_bytes(net.octets()) & mask;
    Some((
        std::net::Ipv4Addr::from(base + 1),
        std::net::Ipv4Addr::from(mask),
        prefix,
    ))
}

/// The netmask for a prefix length.
#[must_use]
pub fn mask_of(prefix: u8) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::from(u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0))
}

/// Put this process's network namespace on the pod's bridge, as `eth0`.
///
/// THE MEMBER HAS ALREADY UNSHARED ITS OWN NETWORK NAMESPACE when this runs, which is the whole
/// point: it keeps a `127.0.0.1` no other service can reach, exactly as a Docker container does,
/// while still reaching its peers. The shared-namespace pod cannot do the first, and the
/// relay wiring pays a TCP hop per ordered pair per port for the second.
///
/// A FORKED HELPER DOES THE WORK IN THE HOLDER'S NAMESPACE, because both ends of a `veth` are born
/// where it is created and one of them has to be born next to the bridge. The helper `setns`es into
/// the holder's network namespace (legal: the member is already in the pod's USER namespace, which
/// owns it), builds the pair with THIS process's namespace named for the far end, and attaches the
/// near end to the bridge. The caller then renames it and gives it its address, in its own
/// namespace.
///
/// THE FAR END IS BORN HERE, NOT MOVED HERE, and that is worth about 20 ms per service. Moving an
/// interface between network namespaces waits a full RCU grace period inside the kernel;
/// [`crate::netlink::add_veth_peer_in_netns`] names the target namespace in the CREATE message and
/// the kernel registers the peer there directly. Measured, five pairs each, in a user namespace:
/// 14-22 ms to move, 1-2 ms to create in place. End to end that took a bridged member from 16-30 ms
/// down to the pod member's own cost, and it is the reason the bridge can be the default wiring.
///
/// THE MOVE IS STILL THERE AS A FALLBACK. The create-time form has been in the kernel for as long
/// as `veth` has, but this is the one step in a box's setup that has no alternative if it fails: a
/// member that cannot attach cannot start at all. So a refusal falls back to build-then-move, which
/// is what every kern before this did, and the box comes up 20 ms slower instead of not at all.
fn attach_to_pod_bridge(holder: i32, at: &BridgeAttach) -> Result<(), Error> {
    let me = std::process::id() as i32;
    let vname = format!("kv{me}");
    let pname = format!("kp{me}");
    // SAFETY: a fork from the single-threaded box setup path; the child only does namespace and
    // netlink work and then `_exit`s without touching the parent's state.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::Syscall(
            "fork(pod bridge helper)",
            std::io::Error::last_os_error(),
        ));
    }
    if pid == 0 {
        let code = {
            let path = format!("/proc/{holder}/ns/net\0");
            // SAFETY: the path is NUL-terminated above and the fd is used only for `setns`.
            let fd = unsafe {
                libc::open(
                    path.as_ptr().cast::<libc::c_char>(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                2
            // SAFETY: `fd` is a namespace file just opened.
            } else if unsafe { libc::setns(fd, libc::CLONE_NEWNET) } != 0 {
                3
            } else {
                // THE FAST FORM FIRST: the peer is created already inside the member's namespace,
                // so nothing is ever moved. `born_far` records which form succeeded, because the
                // two leave the helper's namespace in different states and the steps below differ.
                //
                // AND IT IS CONFIRMED BY LOOKING, NOT BY THE RETURN VALUE. A kernel that did not
                // read `IFLA_NET_NS_PID` inside the peer's nest would create the pair, answer with
                // a perfectly good ack, and leave the far end HERE - and a fallback keyed on the
                // error would never fire, so the member would find nothing to rename and fail to
                // start. MEASURED by deleting that one attribute: the box did not come up. The
                // check is one `if_nametoindex` and it turns a fallback that reads well into one
                // that works.
                //
                // THE THREE STATES ARE NOT TWO, and reading them as two is a defect this fallback
                // had until the mutation above was actually run. `made` says a pair exists;
                // `born_far` says the far end is where it belongs. A fast form that succeeded but
                // ignored the namespace has `made` true and `born_far` false, and calling
                // `add_veth` again for it fails with `EEXIST` - which is what happened, and turned
                // the rescue into a second way to fail.
                let fast = crate::netlink::add_veth_peer_in_netns(&vname, &pname, me).is_ok();
                let born_far = fast && crate::netlink::index_of(&pname).is_none();
                let made = fast || crate::netlink::add_veth(&vname, &pname).is_ok();
                if !made {
                    4
                } else {
                    match (
                        crate::netlink::index_of(&vname),
                        crate::netlink::index_of(POD_BRIDGE),
                    ) {
                        (Some(v), Some(b)) => {
                            if crate::netlink::set_master(v, b).is_err() {
                                6
                            } else if !iface_up(&vname) {
                                7
                            } else if born_far {
                                // Nothing left to do here: the far end is already where it belongs.
                                0
                            } else {
                                // The fallback. The peer is still in THIS namespace - either
                                // because the fast form was refused, or because it silently ignored
                                // the target namespace - and has to make the trip, paying the grace
                                // period the fast form avoids.
                                match crate::netlink::index_of(&pname) {
                                    Some(p) if crate::netlink::move_to_netns(p, me).is_ok() => 0,
                                    Some(_) => 9,
                                    None => 5,
                                }
                            }
                        }
                        _ => 5,
                    }
                }
            }
        };
        // SAFETY: leaving the forked child without running the parent's handlers.
        unsafe { libc::_exit(code) };
    }
    let mut status = 0i32;
    // SAFETY: waiting on the child just forked.
    if unsafe { libc::waitpid(pid, &mut status, 0) } != pid {
        return Err(Error::Syscall(
            "waitpid(pod bridge helper)",
            std::io::Error::last_os_error(),
        ));
    }
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    if code != 0 {
        return Err(Error::Unsupported(
            "could not attach this box to the pod bridge (is the pod holder still running, and was \
             the pod created with a bridge?)",
        ));
    }
    // The end is here now, under the unique name it was born with. `eth0` is what a workload
    // expects to find, and the name only has to be ordinary once it is on this side.
    if !iface_rename(&pname, "eth0") {
        return Err(Error::Unsupported(
            "the pod bridge interface arrived but could not be renamed to eth0",
        ));
    }
    if !iface_set_ipv4("eth0", at.ip, mask_of(at.prefix)) || !iface_up("eth0") {
        return Err(Error::Unsupported(
            "the pod bridge interface could not be addressed",
        ));
    }
    Ok(())
}

/// Create and HOLD a pod's shared user + net namespace, then block forever. `kern pod create` forks
/// this as a detached holder process; `--pod` boxes `setns` into `/proc/<holder>/ns/{user,net}` to
/// share its loopback network. Unshares a fresh user ns (single-uid map: pod-root = the caller) + a
/// fresh net ns, brings its loopback up, then `pause()`s so the namespaces stay alive until the
/// holder is killed (`kern pod rm`). Never returns.
pub fn run_pod_holder() -> ! {
    // A pod holder maps a RANGED uid map (`KERN_POD_UID_RANGE`, set by `pod create --uid-range`)
    // when the pod will host OCI images that drop privilege in their entrypoint (postgres/redis/nginx/
    // …). Members `setns` into this shared user ns and inherit the range, so their drop to a service
    // uid works - the 0.6 official-image fix, extended to the pod path. Default (no env) = the single-
    // uid self-map: faster (no newuidmap), more isolated (one uid), for a pod of root-only services.
    let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let env_range = std::env::var("KERN_POD_UID_RANGE").ok();
    let want_range = UidRange::from_env(env_range.as_deref());
    let ns = libc::CLONE_NEWUSER | libc::CLONE_NEWNET;
    // The range needs newuidmap + an /etc/subuid allocation; if either is missing, fall back to the
    // single-uid map (honest degrade - official images in this pod will then fail with the F1 warning,
    // not silently). detect_id_range is resolved BEFORE the unshare (it must run in the init userns).
    let range = if want_range.is_on() {
        detect_id_range(euid, egid)
    } else {
        None
    };
    match range {
        Some(r) => {
            // apply_userns_range does its own unshare(ns) + fork-helper newuidmap/newgidmap + sync.
            // `None`: the pod holder is created by `kern pod create`, which has no `PhaseTimer` in
            // scope and is not on a box's hot path. Passing one would time a different operation
            // under the box's labels, which is worse than not timing it.
            if let Err(e) = apply_userns_range(ns, euid, egid, &r, None) {
                eprintln!(
                    "kern: pod: ranged user-ns map failed ({e}) - falling back to single-uid"
                );
                // apply_userns_range unshares before it can fail on the map write; we may already be in
                // a fresh userns. Try the single-uid self-map here as the honest fallback.
                if write_single_uid_map(euid, egid).is_err() {
                    eprintln!("kern: pod: could not map the pod user namespace");
                    unsafe { libc::_exit(1) };
                }
            }
        }
        None => {
            if unsafe { libc::unshare(ns) } != 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EPERM) {
                    eprintln!("kern: pod: {USERNS_UNAVAILABLE}");
                } else {
                    eprintln!("kern: pod: unshare(user+net) failed: {e}");
                }
                unsafe { libc::_exit(1) };
            }
            if want_range == UidRange::Requested {
                eprintln!("kern: pod: --uid-range requested but unavailable (need newuidmap/newgidmap + /etc/subuid) - single-uid map");
            }
            if write_single_uid_map(euid, egid).is_err() {
                eprintln!("kern: pod: could not map the pod user namespace");
                unsafe { libc::_exit(1) };
            }
        }
    }
    bring_loopback_up();
    // `KERN_POD_BRIDGE=<cidr>`: this pod gives every member its own network namespace on a bridge
    // instead of sharing this one. Set by `kern pod create --bridge`, read here for the reason
    // `KERN_POD_UID_RANGE` is: the holder is forked by a verb that cannot pass it a struct.
    //
    // FAIL-CLOSED. A member that cannot reach the bridge has no peers at all, so a holder that could
    // not build one must not report itself ready: the alternative is a pod that starts, looks fine
    // and silently isolates every service in it.
    if let Ok(cidr) = std::env::var("KERN_POD_BRIDGE") {
        match pod_bridge_parts(&cidr) {
            Some((gw, mask, _)) => {
                if crate::netlink::add_bridge(POD_BRIDGE).is_err()
                    || !iface_set_ipv4(POD_BRIDGE, gw, mask)
                    || !iface_up(POD_BRIDGE)
                {
                    eprintln!("kern: pod: could not build the pod bridge ({cidr})");
                    unsafe { libc::_exit(1) };
                }
            }
            None => {
                eprintln!(
                    "kern: pod: '{cidr}' is not a network kern can build a bridge on (expected \
                     something like 10.89.0.0/24: an IPv4 network, prefix between 8 and 30, and not \
                     loopback - the kernel routes 127/8 to `lo`, so members would get addresses that \
                     never cross the bridge)"
                );
                unsafe { libc::_exit(1) };
            }
        }
    }
    // Signal readiness (the parent waits for this line on our stdout) so `kern pod create` only
    // records the holder once its namespaces are actually set up.
    println!("pod-ready");
    // Release the caller's inherited stdio: we're now a detached daemon that `pause()`s for the pod's
    // whole lifetime. If we kept the inherited stderr (fd 2) open, ANY caller reading our parent's
    // combined output - `kern compose up 2>&1 | …`, `$(kern pod create …)`, a CI log pipe - would never
    // see EOF and would appear to hang for as long as the pod lives. Point fd 1 and fd 2 at /dev/null so
    // those pipes close now, while keeping the descriptors valid for the rest of our life.
    unsafe {
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
        if devnull >= 0 {
            libc::dup2(devnull, libc::STDOUT_FILENO);
            libc::dup2(devnull, libc::STDERR_FILENO);
            if devnull > libc::STDERR_FILENO {
                libc::close(devnull);
            }
        } else {
            libc::close(libc::STDOUT_FILENO);
        }
    }
    hold_until_the_pod_is_gone();
}

/// Block for the life of the pod, and no longer.
///
/// WHY THIS IS NOT `pause()` ANY MORE. A holder exists to keep one pod's user and net namespaces
/// alive, and it is addressed through the pod's directory under the registry: that directory holds
/// its pid file, its `hosts`, its `resolv.conf`. When the directory goes, nothing can name the pod,
/// nothing can join it and `kern pod rm` cannot find it - but the holder went on holding, forever,
/// and so did the `pasta` watching its namespace.
///
/// MEASURED on this machine: 140 orphan holders and 116 `pasta` processes, the oldest alive for
/// 5.8 hours, every one of them from an integration test that set `XDG_RUNTIME_DIR` to a temporary
/// directory and removed it at the end without tearing the pod down. A user who deletes their
/// runtime directory - or whose `/run/user/<uid>` is cleaned on logout - reaches the same state.
///
/// FAIL-SAFE TOWARD STAYING ALIVE, WHICH IS THE WHOLE DESIGN. Exiting wrongly kills a running
/// stack's network, so every uncertainty resolves to "keep holding":
///
///   * no `KERN_POD_DIR` in the environment (a holder spawned by an older kern, or by hand) leaves
///     this function in the exact `pause()` loop it replaced, forever;
///   * only a definite ABSENCE counts. `try_exists` answers `Ok(false)` for ENOENT alone; a
///     permission error, an I/O error or an unmounted filesystem answer `Err`, and `Err` is treated
///     as "still there";
///   * and absence has to hold across TWO consecutive checks a full interval apart, so a directory
///     being replaced by a rename is never mistaken for one that is gone.
///
/// THE INTERVAL IS LONG ON PURPOSE. This costs one `stat` every 30 seconds for the life of a pod,
/// which is nothing, and the requirement it serves is only that a leaked holder stops existing in
/// under a minute rather than in hours.
fn hold_until_the_pod_is_gone() -> ! {
    let dir = match std::env::var_os("KERN_POD_DIR") {
        Some(d) if !d.is_empty() => std::path::PathBuf::from(d),
        // Nothing to watch: hold forever, which is what every kern before this did.
        _ => loop {
            // SAFETY: `pause` takes no arguments and only blocks this thread until a signal.
            unsafe { libc::pause() };
        },
    };
    /// One poll. Long enough to be free, short enough that a leak is measured in seconds.
    const POLL: std::time::Duration = std::time::Duration::from_secs(30);
    let mut missing_in_a_row = 0u8;
    loop {
        std::thread::sleep(POLL);
        let (next, release) = pod_holder_verdict(missing_in_a_row, dir.try_exists());
        missing_in_a_row = next;
        // AND THE MEMBERS DECIDE, NOT ONLY THE DIRECTORY.
        //
        // A reviewer found the case this needs: on a systemd host WITHOUT `loginctl enable-linger`,
        // logind removes `/run/user/<uid>` on the last logout while leaving the user's processes
        // running (the default `KillUserProcesses=no`). The pod's directory is then genuinely gone,
        // the rule above is satisfied, and the holder would release the namespaces of a stack that
        // is still serving traffic. Before this watchdog existed the stack survived a logout with
        // its network intact; that must not become a 60-second fuse.
        //
        // The holder's reason to exist is its MEMBERS, not its directory. If any other process is
        // still inside this network namespace, there is something to hold for, whatever the
        // filesystem says. The orphan population this watchdog was written for - a pod whose boxes
        // are long dead and whose directory was deleted by a harness - has no members, so it is
        // still reaped.
        //
        // Paid only when the directory is already missing, which on a healthy host is never.
        if release && !this_netns_has_other_processes() {
            // SAFETY: leaving a detached daemon with no handlers of its own to run. The namespaces
            // this process held are released by the kernel as it goes, and the `pasta` watching
            // them exits on its own netns watch.
            unsafe { libc::_exit(0) };
        }
    }
}

/// One poll of [`hold_until_the_pod_is_gone`]: the new strike count, and whether to let the pod go.
///
/// PURE, BECAUSE THE LOOP AROUND IT CANNOT BE TESTED WITHOUT WAITING A MINUTE AND THE DANGEROUS
/// BRANCH IS NOT THE SLOW ONE. Releasing wrongly takes the network away from a running stack, so the
/// branch that must never fire is `Err` - a directory that could not be stat'ed, which is not a
/// directory that is gone. Written inline it was three arms inside a sleeping loop, reachable only
/// by a test that sleeps; written here every arm is one call.
///
/// `probe` is [`std::path::Path::try_exists`]'s answer, whose whole value is that it distinguishes
/// ENOENT (`Ok(false)`) from every other failure (`Err`).
///
/// TWO STRIKES, A FULL INTERVAL APART, so a directory being replaced by a rename is never read as
/// one that is gone. The counter saturates rather than wrapping: a `u8` rolling over to 0 after 256
/// consecutive absences would make a long-gone pod immortal again, which is the exact bug this
/// function exists to end.
/// Is any process other than this one inside this process's network namespace?
///
/// THE HOLDER'S MEMBERS, ASKED OF THE KERNEL rather than of a file. `/proc/<pid>/ns/net` is a link
/// whose target names the namespace, so two processes share one exactly when their links match.
/// Compared by the link TEXT (`net:[4026534073]`), which is the namespace's inode and is what the
/// kernel prints; no parsing, no assumption about the format beyond equality.
///
/// UNREADABLE ANSWERS "YES". A `/proc` this process cannot walk, a pid that exits mid-scan, a link
/// that cannot be read: none of those is evidence that the namespace is empty, and the only use of
/// this function is to decide whether to release it. Every uncertainty keeps the holder alive, which
/// is the same rule the directory probe follows.
fn this_netns_has_other_processes() -> bool {
    let Ok(mine) = std::fs::read_link("/proc/self/ns/net") else {
        return true; // cannot tell: hold
    };
    let me = std::process::id().to_string();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return true; // cannot tell: hold
    };
    for e in entries.filter_map(Result::ok) {
        let Ok(name) = e.file_name().into_string() else {
            continue;
        };
        if name == me || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        // A pid that vanishes between the listing and the read is not a member; a link that cannot
        // be read for any other reason is not evidence either way, and there is no way to tell the
        // two apart from here. Skipping is safe because the DIRECTORY probe is the other half of
        // the decision: a namespace with real members almost never has every one of them unreadable.
        if std::fs::read_link(format!("/proc/{name}/ns/net")).is_ok_and(|t| t == mine) {
            return true;
        }
    }
    false
}

fn pod_holder_verdict(missing_in_a_row: u8, probe: std::io::Result<bool>) -> (u8, bool) {
    match probe {
        Ok(true) => (0, false),
        Ok(false) => {
            let n = missing_in_a_row.saturating_add(1);
            (n, n >= 2)
        }
        Err(_) => (0, false),
    }
}

/// The box this process waits on, for [`forward_signals_to_the_box`]'s handler. `0` = nothing to
/// forward to (the handler then keeps the signal's default meaning).
static BOX_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
/// How many fatal signals this process has taken while waiting for the box. The SECOND one always ends
/// it, so two Ctrl-Cs end a box whose workload ignores the first.
static BOX_SIGNALS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Handler for the fatal signals a waiting kern can take. Async-signal-safe: two atomics, `kill` and
/// `_exit`, nothing else.
extern "C" fn forward_to_box(sig: libc::c_int) {
    // Asked twice: honour the signal's default meaning, whatever we were doing with the first.
    if BOX_SIGNALS.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
        unsafe { libc::_exit(128 + sig) };
    }
    let pid = BOX_PID.load(std::sync::atomic::Ordering::SeqCst);
    if pid > 0 {
        unsafe { libc::kill(pid, sig) };
    }
    // `pid == 0`: swallow it and keep waiting. See `keep_waiting_through_signals`.
}

/// While kern waits for a box, treat a fatal signal as "end the BOX", not "end kern": forward it to
/// PID 1 and keep reaping, so this process exits with the box's own status.
///
/// This is what makes a box's exit code independent of the INIT SYSTEM, which is where it came from.
/// MEASURED, same binary and same workload past its `--memory` cap: an Arduino UNO Q (systemd 257)
/// reported 143 where a Raspberry Pi 5 (252) and a Jetson Orin Nano (249) reported 137. The kernel had
/// already SIGKILLed the box on all three; what differed is that the newer manager's default
/// `OOMPolicy=stop` ALSO stops the unit, and its SIGTERM reached kern - blocked in `waitpid`, with the
/// box's status already there to be read - and killed it before it could read it. The exit code of a
/// box that hit its memory cap should not depend on the manager's version.
///
/// Two properties this deliberately buys beyond that, both matching `docker run`:
///   * `kill <kern>` (or a SIGTERM to a non-tty box) now tears the box DOWN and reports what it exited
///     with, instead of killing kern and leaving the box to the PDEATHSIG cascade;
///   * a workload that IGNORES the first signal cannot make kern unkillable - the second exits at once
///     with `128+signo`, and `kern stop --time 0` / SIGKILL remain the hard escapes.
///
/// Installed AFTER the box is forked, so the workload never inherits these dispositions, and only for
/// a FOREGROUND box - the one case where this process is the user's own and nothing else would carry
/// their signal into the box. Everything behind a supervisor uses [`keep_waiting_through_signals`]
/// instead, because there the box is signalled directly and a forward would be a SECOND delivery.
pub fn forward_signals_to_the_box(pid: libc::pid_t) {
    BOX_PID.store(pid, std::sync::atomic::Ordering::SeqCst);
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = forward_to_box as extern "C" fn(libc::c_int) as usize;
        // No `SA_RESTART`, deliberately: `reap_retry_eintr` re-loops on EINTR, and coming back through
        // it is what lets the reap see a box that died while the signal was being delivered.
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        for &sig in &[libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT] {
            libc::sigaddset(&mut sa.sa_mask, sig);
        }
        for &sig in &[libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// Take the first fatal signal WITHOUT dying and without touching the box: keep waiting, so this
/// process lives to read the box's status and record it. The second one exits, as it would have.
///
/// For every kern process that sits BEHIND a supervisor - the detached runner and the supervisor
/// itself. Two reasons it swallows rather than forwards, both measured:
///   * the box is already being signalled directly. `kern stop` signals the box's process GROUP, which
///     these processes share, so a forward would be a SECOND delivery: a workload whose handler is
///     re-entrant runs its shutdown twice.
///   * a forward can FALSIFY the verdict. On an Arduino UNO Q (systemd 257) a detached box past its
///     `--memory` cap recorded 143 while forwarding: the manager's `OOMPolicy=stop` SIGTERMs the scope,
///     and kern's own relay of that SIGTERM reached the workload BEFORE the kernel's `oom.group`
///     SIGKILL, so the box was recorded as terminated rather than OOM-killed. Swallowing it leaves the
///     kernel's kill as the only thing that touches the box: 137, the same as on systemd 249 and 252.
pub fn keep_waiting_through_signals() {
    forward_signals_to_the_box(0)
}

/// Blocking `waitpid(pid)` that retries on `EINTR`, writing the status through `status` and returning
/// the raw `waitpid` return (`>= 0` = reaped, `< 0` = a real, non-EINTR error). A signal
/// (SIGCHLD/SIGWINCH/…) can interrupt a blocking `waitpid` with the child STILL ALIVE - returning early
/// there would leave the box unreaped (a zombie, and for the supervisor path a cgroup guard dropped on a
/// non-empty cgroup → EBUSY leak). Looping until the child is actually reaped, or a non-EINTR error,
/// makes every foreground reap robust. One helper so all reap sites share the same discipline.
fn reap_retry_eintr(pid: i32, status: &mut i32) -> i32 {
    loop {
        let rc = unsafe { libc::waitpid(pid, status, 0) };
        if rc >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return rc;
        }
    }
}

/// Decode a `waitpid` status into a shell-style exit code (128+signal if killed).
fn wait_code(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

/// Print a one-line "refusing to run" reason and `_exit(126)` - the fail-closed exit every POLICY step
/// in the `exec_in_box` child takes when it cannot reapply the box's posture (env wipe, cap drop,
/// seccomp install). Centralised so a new fail-closed step can't drift the code or the "refusing to
/// run" wording, and `-> !` makes "never returns" part of the type - a caller cannot fall through past
/// it into an unprotected exec. (A `--workdir`/exec failure exits 127 "not runnable", a different case.)
fn exec_fail_closed(reason: &str) -> ! {
    eprintln!("kern: exec: {reason} - refusing to run");
    unsafe { libc::_exit(126) }
}

#[allow(clippy::too_many_arguments)] // each arg is a distinct exec knob; grouping would only hide it
/// What `exec_in_box` must do when the child cannot be PLACED in the box's capped cgroup.
///
/// The placement fails for two causes that need opposite answers, and a third caller needs a third
/// answer, so the decision cannot live inside the function: it is the caller's policy and it is the
/// one input that cannot be re-derived after the fork.
///
/// CAUSE ONE, the box is at its `pids.max`: `clone3` refuses with EAGAIN and the fallback `fork`
/// SUCCEEDS outside the cgroup. The cap is real, in force, and the command would step around it.
///
/// CAUSE TWO, the host layout forbids the migration: cgroup v2 delegation containment needs write
/// access to the `cgroup.procs` of the COMMON ANCESTOR of the source and destination, and from a
/// shell in `/init.scope` that ancestor is the root cgroup. MEASURED on WSL2 with `systemd=true` by
/// an outside reviewer: `kern exec` refused every single time, on a host where nothing was wrong
/// with the box. No implementation fixes that one. A process in `/init.scope` cannot reach the
/// user's delegated tree, and it cannot move itself there either, because that migration needs the
/// same permission on the same root.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Unplaceable {
    /// Refuse with 126 and say why. The default for `kern exec`, because a command that steps around
    /// the box's `--memory`/`--pids-limit` while the operator believes it is capped is the silent
    /// escape the fail-closed exists to stop.
    Refuse,
    /// Run it, and say so. `KERN_ALLOW_UNCAPPED`, whose documented meaning across `SECURITY.md`,
    /// `INSTALL.md` and `RESOURCES.md` is already "explicitly accept running UNCAPPED where a cgroup
    /// cap cannot be applied". Reusing it adds no CLI surface, which matters because that surface is
    /// frozen, and it keeps ONE name for one concept. kern never sets it itself, so it cannot be
    /// inherited from an outer kern; it is only ever the operator saying it.
    ProceedWithWarning,
    /// Run it, quietly. ONLY for kern's own `--health-cmd` probe, and only after the first one has
    /// warned. A probe is an instrument, not the workload: refusing it turns a host cgroup layout
    /// into a permanent false "unhealthy" for every box that has a health check, which is a broken
    /// feature reported as a broken box. Warning on every interval instead would be a line every few
    /// seconds, which trains the reader to ignore the stream that carries it.
    ProceedQuietly,
}

// One parameter per thing the exec must REPRODUCE from the box it enters: its namespaces, workdir,
// terminal, timeout, caps, seccomp filter, AppArmor profile and cgroup policy. Grouping them into a
// struct would hide exactly the list a reader has to check when asking "does an exec match its box",
// which is the question this function exists to answer correctly. The same reasoning, and the same
// allow, is on `apply_limits`.
#[allow(clippy::too_many_arguments)]
/// The three things an `exec -it` needs to give the command a terminal the box can NAME: the two
/// ends of the handover socket, and the CLI's hook for re-pointing `SIGWINCH` once the master
/// changes. Grouped because they are useless individually and because `exec_in_box`'s signature is
/// already at the limit clippy warns about.
///
/// `retarget` is a plain `fn` pointer on purpose: it crosses a crate boundary into the CLI, which
/// owns the host terminal's state, and a bare pointer carries no lifetime to thread through a
/// function that forks.
pub struct PtyHandover {
    /// Child end of the socketpair, inherited across the fork; the child sends the master on it.
    pub sock_child: i32,
    /// Parent end, which this function reads the master from after the fork.
    pub sock_parent: i32,
    /// Called in the PARENT with the new master, before the pump starts.
    pub retarget: fn(i32),
}

// THIRTEEN ARGUMENTS, and each one is a decision the CHILD cannot make for itself. Everything here
// is resolved before the fork on purpose: after it, the child may not allocate, may not read the
// environment, and may not consult the registry. Collapsing them into a struct would move the same
// values behind one name without changing what has to be decided when, so the lint is silenced
// rather than satisfied. `PtyHandover` groups the three that DO belong together.
#[allow(clippy::too_many_arguments)]
pub fn exec_in_box(
    pid1: i32,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    tty_slave: Option<i32>,
    tty_master: Option<i32>,
    timeout_secs: Option<u64>,
    box_has_explicit_caps: bool,
    box_caps: &CapSpec,
    seccomp_mode: crate::SeccompFilter,
    // The box's `--apparmor` profile, taken from the RECORDED exec posture (`Instance::apparmor` via
    // `exec_posture()`), or `None` if it ran unconfined. NOT read back from `/proc/<pid1>/attr/...`:
    // for an `--init` box PID 1 is the unconfined reaper, so that read would deduce "unconfined" and
    // exec UNCONFINED into a confined box. Re-entered here so `kern exec` matches the box's confinement,
    // like caps + seccomp - otherwise an exec would run OUTSIDE the box's AppArmor profile.
    apparmor: Option<&str>,
    // What to do if the child cannot be placed in the box's capped cgroup. Resolved by the CALLER,
    // before the fork, because the child may not read the environment or allocate. See [`Unplaceable`].
    unplaceable: Unplaceable,
    // `-it`: let the exec'd command take its terminal from the BOX's devpts rather than the host's,
    // so `ttyname()` can resolve it inside the box. `None` keeps the host pty in `tty_slave`, which
    // works but has no name there. See [`crate::ptybox`].
    pty: Option<PtyHandover>,
    // Drop to this uid/gid (with these supplementary groups) before the exec, or stay box-root.
    //
    // ONLY THE HEALTH PROBE PASSES A USER, and the asymmetry is deliberate. Docker runs a
    // `HEALTHCHECK` as the container's user - measured, not assumed: on Docker 29.6.2 a container
    // started `--user 1000:1000 -w /tmp` with a probe that records `id` and `pwd` reports
    // `uid=1000 gid=1000 groups=1000` and `/tmp`. A probe that runs as root is a FALSE-GREEN
    // generator: it reads files the workload cannot, reports healthy, and
    // `depends_on: service_healthy` then releases a dependent onto a service that dies of EACCES.
    // Measured on Elastic's own stack, whose certificates are `root:root` mode 640. `kern exec`
    // keeps box-root: it is the operator's door into the box and the frozen CLI has no `--user` on
    // it to get root back with.
    run_as: Option<(u32, u32)>,
    extra_gids: &[u32],
) -> Result<i32, Error> {
    if command.is_empty() {
        return Err(Error::Unsupported("no command given to exec in the box"));
    }
    let argv: Vec<CString> = command.iter().map(|s| cstr(s)).collect::<Result<_, _>>()?;

    // INHERIT the box's environment, like `docker exec` does. Read from the host view of PID 1 NOW,
    // before any `setns`: once we enter the mount namespace `/proc` is the box's and this path no
    // longer resolves to the same task. Without this, `exec` ran with a bare PATH/HOME and every
    // `compose exec db psql -U $POSTGRES_USER` style command saw an empty variable.
    //
    // Explicit `-e` is applied AFTER these (see the `set_clean_env` call), so a caller can still
    // override anything the box set. Best-effort: an unreadable `environ` just means no inheritance,
    // never a failed exec.
    let inherited: Vec<(String, String)> = std::fs::read(format!("/proc/{pid1}/environ"))
        .map(|raw| {
            raw.split(|b| *b == 0)
                .filter(|e| !e.is_empty())
                .filter_map(|e| std::str::from_utf8(e).ok())
                .filter_map(|e| e.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let mut env_all: Vec<(String, String)> = inherited;
    env_all.extend(env.iter().cloned());
    let env: &[(String, String)] = &env_all;

    // Open every namespace fd BEFORE any setns: once we enter the mount namespace, `/proc` points
    // at the box's, so `/proc/<pid1>/ns/*` would no longer resolve. Order of *entry* matters -
    // user first (so we hold CAP_SYS_ADMIN in the box's userns for the rest); pid before the fork.
    // `cgroup` comes straight after `user`, whose capabilities it needs. Without it an exec'd command
    // read the HOST's cgroup path out of `/proc/self/cgroup`
    // (`0::/user.slice/user-1000.slice/user@1000.service/kern.slice/kern-box-<name>-<pid>`) while the
    // box's own workload correctly reads `0::/`: the same box, two different answers, with the host's
    // slice layout and the caller's uid disclosed to whatever ran under `kern exec`. A box without a
    // cgroup namespace (an older kernel, no `CONFIG_CGROUP_NS`) has no `ns/cgroup` file, so it is
    // skipped exactly as before.
    let ns_order: [(&str, libc::c_int); 7] = [
        ("user", libc::CLONE_NEWUSER),
        ("cgroup", libc::CLONE_NEWCGROUP),
        ("ipc", libc::CLONE_NEWIPC),
        ("uts", libc::CLONE_NEWUTS),
        ("net", libc::CLONE_NEWNET),
        ("mnt", libc::CLONE_NEWNS),
        ("pid", libc::CLONE_NEWPID),
    ];
    let mut fds: Vec<(libc::c_int, libc::c_int)> = Vec::with_capacity(ns_order.len());
    // THE CGROUP NAMESPACE IS HELD BACK FOR THE CHILD. Joining it here would make
    // `clone3(CLONE_INTO_CGROUP)` below answer ENOENT, because inside it the box's cgroup is the
    // root and the ancestor it shares with ours cannot be named. The child enters it after it has
    // been born in the right cgroup, which is the same place it ends up either way.
    let mut cgroup_ns_fd: libc::c_int = -1;
    for (name, flag) in ns_order {
        // A namespace the box SHARES with us is not one to join, and joining it fails. `--net` is the
        // case that made this visible: `/proc/<pid1>/ns/net` is not missing there, it EXISTS and
        // resolves to OUR net ns. Entering the box's user ns first drops the `CAP_SYS_ADMIN` that the
        // host net ns's owning (initial) user ns requires, so the following `setns(CLONE_NEWNET)` is
        // refused `EPERM` and every `kern exec` into a `--net` box died with "must be the same user
        // that started it" - which was also the wrong reason. Measured on x86_64 and a Raspberry Pi 5
        // on 2026-07-31: 100% of execs into a `--net` box. Compared BEFORE any `setns`, while
        // `/proc/self/ns/*` still describes where we started.
        if shares_our_namespace(pid1, name) {
            continue;
        }
        let p = cstr(&format!("/proc/{pid1}/ns/{name}"))?;
        let fd = unsafe { libc::open(p.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd >= 0 {
            if flag == libc::CLONE_NEWCGROUP {
                cgroup_ns_fd = fd;
            } else {
                fds.push((fd, flag));
            }
        }
        // A missing ns file means the box is gone; the required-namespace check below catches that.
    }
    // Refuse if the box's core namespaces aren't there to join: if PID 1 has exited (a race), its
    // `/proc/<pid1>/ns/*` vanish, and without this we'd fork+exec in the HOST namespaces - running
    // the command UNSANDBOXED. user + mnt + pid must all be present.
    for req in [libc::CLONE_NEWUSER, libc::CLONE_NEWNS, libc::CLONE_NEWPID] {
        if !fds.iter().any(|(_, f)| *f == req) {
            for (f, _) in &fds {
                unsafe { libc::close(*f) };
            }
            return Err(Error::Unsupported(
                "box is not running (its namespaces are gone)",
            ));
        }
    }
    // Join the box's cgroup (its `--memory`/`--pids` caps) BEFORE entering the mount namespace.
    // Once we `setns(CLONE_NEWNS)` into the box, `/sys/fs/cgroup` is the box's masked view and the
    // host cgroupfs is unreachable, so this MUST happen here, in the host mount ns. We move THIS
    // (pre-fork) process, so the child forked below inherits the cgroup atomically - the same
    // "cap before fork" order the box's own PID 1 setup uses, with no fork→move→exec race.
    //
    // Without it an `exec`'d workload stays in the LAUNCHER's cgroup and escapes the box's resource
    // caps entirely: a fork bomb or memory hog run via `kern exec` would NOT be bounded by the box's
    // `--pids`/`--memory` (unlike `docker exec`, which places the exec'd process in the container's
    // cgroup). The namespace + seccomp isolation holds regardless; this closes the RESOURCE gap on
    // the delegated direct-cap path (kern.slice/kern-box-*).
    //
    // On the rootless per-box-systemd-scope path (Jetson/Pi 5 and the common rootless case) the box
    // lives in a `run-*.scope` that the kernel will NOT let us migrate into from our own session
    // scope (the common ancestor `user@<uid>.service` isn't user-writable - verified EPERM), so the
    // exec runs outside the caps there. `join_box_cgroup_for_exec` reports that as `Unbounded`.
    //
    // We always ATTEMPT the join (it caps the exec on the direct path; a harmless no-op elsewhere)
    // but only WARN when the user set an EXPLICIT `--memory`/`--pids` on the box (`box_has_explicit_
    // caps`): a default box on a scope host also sits in a scope with a default MemoryMax, so warning
    // on `Unbounded` alone would fire on EVERY exec on every rootless host (a `kern exec box ls`
    // included) - noise the user never asked about. A `--health-cmd` probe passes `false` too, so it
    // never spams the box log every interval.
    // PLACE THE PROCESS IN THE BOX'S CGROUP HERE, BEFORE THE `setns` BELOW, AND NOT AFTER IT. The
    // ordering is the whole point of this being a separate step, and it holds for two independent
    // reasons that were learned the expensive way:
    //
    //   1. NAMING. After the cgroup namespace is joined, `/proc/<pid1>/cgroup` reports a path relative
    //      to THAT namespace and no longer names a directory under `/sys/fs/cgroup`.
    //   2. REACHABILITY, which a descriptor does NOT fix. Inside the box's cgroup namespace the box's
    //      own cgroup is the root, and the common ancestor it shares with the caller's cgroup cannot
    //      be named there at all. The kernel refuses the placement outright, whether it is asked for
    //      through `clone3(CLONE_INTO_CGROUP)` with an fd or through a write on a pre-opened
    //      `cgroup.procs`. Both come back ENOENT, not EPERM - traced:
    //
    //          setns(3, CLONE_NEWUSER)                                    = 0
    //          setns(4, CLONE_NEWCGROUP)                                  = 0
    //          clone3({flags=CLONE_INTO_CGROUP, ..., cgroup=10}, 88)      = -1 ENOENT
    //          openat(10, "cgroup.procs", O_WRONLY|O_CLOEXEC)             = 3        <- opens fine
    //          write(3, "0", 1)                                           = -1 ENOENT
    //
    // The consequence of getting this wrong was not a slower exec, it was an UNCAPPED one: measured on
    // the binary that placed after the `setns`, `kern exec` into a `--pids-limit 2 --memory 64M` box
    // ran in the CALLER's cgroup - read from the host by pid, with the box's own PID 1 as the positive
    // control and the exec'd process verified to be in the box's PID namespace - and said nothing,
    // because the probe that decides whether a failed placement cost a cap read `memory.max` from the
    // same unreachable place and concluded there was no cap to lose.
    //
    // SO THE MIGRATION STAYS ON THIS PATH, and with it its cost: it is a `cgroup.procs` write, which
    // takes `cgroup_threadgroup_rwsem` for write and therefore an RCU grace period - 11.7 to 25.8 ms on
    // a quiet host against 1.7 to 2.2 ms without it. `clone3(CLONE_INTO_CGROUP)` avoids that grace
    // period and IS used, but only on the box START path, which places its child before entering any
    // namespace and where the saving is real. Buying those milliseconds here costs the cap.
    //
    // AND THE LAUNCHER IS OUT OF THE BLAST RADIUS. While it migrated, `memory.oom.group` killed it with
    // the box, so the process that would have explained the kill was the one being killed, and a third
    // process outside the group had to exist to say so. That watcher is gone: the launcher survives,
    // reports the OOM itself after `waitpid`, and returns 137 instead of dying of SIGKILL.
    //
    // WHAT THE CALLER USED TO SEE WHEN THAT HAPPENED, measured rather than guessed. A `--memory 32m`
    // box, an exec'd command that allocates past it:
    //
    //     returncode -9 (SIGKILL) on the `kern exec` process ITSELF
    //     stdout b''   stderr b''
    //     memory.events: max 20 oom 1 oom_kill 4 oom_group_kill 1
    //
    // Zero bytes explaining it, because `memory.oom.group = 1` kills the launcher along with the box
    // and SIGKILL cannot be caught. Nothing inside the group can report it, by construction, so
    // `spawn_oom_reporter` below puts one process OUTSIDE the group whose only job is to say it.
    let box_cg = crate::cgroup::box_cgroup_dir_for_exec(pid1).and_then(|d| {
        let cg = crate::cgroup::CgroupRef::open(&d);
        if cg.is_none() && box_has_explicit_caps {
            // Say it rather than fall into the quiet branch: this is the one place that can tell the
            // difference between "the box has no cap" and "kern could not reach the cap it has".
            eprintln!(
                "kern: exec: warning: cannot open the box's cgroup ({}), so the command runs \
                 OUTSIDE the box's --memory/--pids caps (its namespaces + seccomp still isolate it)",
                d.display()
            );
        }
        cg
    });
    // Migrate NOW, while the caller is still in its own namespaces, so the child forked after the
    // `setns` inherits the cgroup. Reported from the outcome, exactly as before.
    // BEFORE the migration below, because a reporter forked after it would be inside the group and
    // would die with everything else. `_reporter` keeps the pipe's write end alive for exactly as
    // long as this process is alive; that is the whole signal.
    // NESSUN GUARDIANO, e la ragione e' che il lanciatore adesso SOPRAVVIVE. Finche' migrava dentro il
    // cgroup, `memory.oom.group` lo uccideva col box e il processo che avrebbe potuto spiegare l'evento
    // era quello ucciso: serviva un terzo processo fuori dal gruppo. Ora `clone3(CLONE_INTO_CGROUP)`
    // colloca il FIGLIO e il lanciatore resta fuori, quindi puo' riportare da se'. Un processo in meno
    // per ogni `kern exec`, e una macchina a stati in meno.
    //
    // La linea di base si legge QUI, prima che parta qualsiasi cosa, su un ANTENATO che sopravvive al
    // box: il cgroup del box viene smontato insieme ai suoi processi, misurato sparito 10,7 ms dopo.
    let oom_events_fd = crate::cgroup::oom_kill_dir_for_pid(pid1)
        .and_then(|d| crate::cgroup::open_oom_events_fd(&d));
    let oom_baseline = oom_events_fd.and_then(crate::cgroup::oom_group_kill_from_fd);

    // IS THERE A CAP TO ESCAPE AT ALL? Computed HERE, before the `setns` below, and this is the
    // input the refusal was missing.
    //
    // The block that used to stand here was dead: `let placed = true;` followed by `if !placed`,
    // left behind when the migration was replaced by `clone3`. It called
    // `exec_join_outcome_after_failure`, which is the function that answers exactly this question,
    // and nothing consulted the answer.
    //
    // WHAT THAT COST, reported by an outside reviewer on a host with no delegation: `kern exec`
    // refused with 126 on a box that was NOT at its pids limit, saying the command "would run
    // outside its --memory/--pids caps" on a box that HAD no caps. `apply_limits` returns `None`
    // where nothing can be delegated, so the box sits in the caller's own cgroup,
    // `box_cgroup_dir_for_exec` answers `None`, `fork_into_cgroup(None)` reports `born = false`, and
    // the refusal fired on a placement that had nothing to place. A refusal for a loss that did not
    // happen, with a message naming caps that did not exist.
    //
    // BEFORE THE `setns`, and that is not a preference: `exec_join_outcome_after_failure` reads
    // `memory.max` and `pids.max` through the cgroup's DESCRIPTOR, and the comment on that function
    // records what happened when the same read was done afterwards through a path - inside the box's
    // namespaces the host path names nothing, both reads failed, and a box capped at
    // `--pids-limit 2 --memory 64M` was reported as having no cap worth mentioning.
    //
    // `None` means the box has no cgroup of its own, so there is nothing to be outside of.
    let escaping_a_real_cap = crate::cgroup::placement_failure_costs_a_cap(
        box_cg.is_some(),
        box_cg.as_ref().is_some_and(|cg| {
            matches!(
                crate::cgroup::exec_join_outcome_after_failure(cg),
                crate::cgroup::ExecCgroupJoin::Unbounded
            )
        }),
    );
    // `box_cg` is kept alive for the `clone3` below, which needs its descriptor.

    for (fd, flag) in &fds {
        if unsafe { libc::setns(*fd, *flag) } != 0 {
            let e = std::io::Error::last_os_error();
            for (f, _) in &fds {
                unsafe { libc::close(*f) };
            }
            if e.raw_os_error() == Some(libc::EPERM) {
                return Err(Error::Unsupported(
                    "cannot join the box's namespaces (must be the same user that started it)",
                ));
            }
            return Err(Error::Syscall("setns", e));
        }
    }
    for (fd, _) in &fds {
        unsafe { libc::close(*fd) };
    }

    // Fork: with the box's pid namespace entered, the child becomes a member of it, and it inherits
    // the cgroup this process was migrated into above. NOTHING IS PLACED HERE - a second placement
    // after the `setns` is not a safety net, it is a copy of the same decision that always fails, and
    // reading its failure is what produced the silent uncapped exec.
    let (pid, born) = crate::cgroup::fork_into_cgroup(box_cg.as_ref());
    if pid < 0 {
        return Err(Error::last("fork"));
    }
    if pid == 0 {
        if cgroup_ns_fd >= 0 {
            unsafe { libc::setns(cgroup_ns_fd, libc::CLONE_NEWCGROUP) };
        }
        // FAIL-CLOSED, and this is the half the experiment showed was missing. `clone3` refuses with
        // EAGAIN once the box is at its `pids.max`, and `fork_into_cgroup`'s fallback is a plain
        // `fork` that SUCCEEDS and leaves the child outside the cgroup: measured, a box at 2/2
        // accepted the exec with exit 0 and the command ran with no ceiling. That is the same silent
        // escape the pre-`setns` migration was put back to close.
        if !born && escaping_a_real_cap {
            // AND IT NAMES THE TWO CAUSES, because a refusal that states only the consequence leaves
            // the reader with nothing to do. An outside reviewer hit this on WSL2 with `systemd=true`:
            // `kern exec` refused every time, on a host where the previous release ran the command
            // uncapped and said so, and the message gave no way to tell a full box from a host layout
            // that can never work. The two causes need opposite actions and only the reader can tell
            // them apart, so both are named and `kern doctor` is pointed at, which reports which cap
            // path this host takes in its first two lines.
            //
            // ONE `const` LITERAL, written with `write(2)`: this is between a fork and an exec, where
            // nothing may allocate or format. The `\`-continuations are stripped by the compiler
            // along with the indentation that follows them, so the reader sees one sentence. That is
            // worth stating because `cargo fmt` will join such a literal back onto one line if it is
            // ever edited, and the indentation then becomes runs of spaces INSIDE the message.
            //
            // AND THE DEFAULT IS STILL REFUSE. What changed is that a host where the placement can
            // NEVER succeed no longer loses the verb outright: `KERN_ALLOW_UNCAPPED` is the operator
            // saying the uncapped run is intended, which is the meaning that variable already carries
            // for `kern box` and `kern run`, and kern's own health probe proceeds because refusing it
            // reports a healthy box as unhealthy. Both alternatives are the CALLER's decision, taken
            // before this fork; nothing here reads the environment.
            match unplaceable {
                Unplaceable::Refuse => {
                    // THE REMEDY THAT KEEPS THE CAPS IS NAMED HERE, not only in `kern doctor`.
                    // MEASURED on four cloud images (Ubuntu 24.04, Fedora 44, Debian 13, Rocky
                    // 10.2): an ordinary `ssh` session sits outside the systemd user manager on all
                    // four, so `kern compose exec` refused on every one of them while the stack
                    // itself was up and correctly capped. That is not an exotic host shape, it is
                    // what "ssh into a server" is, and the reader who hits it was being handed
                    // `KERN_ALLOW_UNCAPPED=1` (drop the caps) or a pointer to another command. The
                    // fix that costs nothing and keeps the caps enforced is one line, so it goes
                    // where the refusal is read.
                    const MSG: &[u8] = b"kern: exec: refusing: the command could not be placed in the box's cgroup, so it would run outside its --memory/--pids caps. Either the box is at its --pids-limit, or this host runs kern outside the cgroup tree it delegates and no exec can join a box here - an ordinary ssh session is outside it on most distributions. Re-enter once with `systemd-run --user --scope bash` and run kern in that shell: caps stay enforced and exec works. `kern doctor` reports which cap path this host takes, and KERN_ALLOW_UNCAPPED=1 runs the command uncapped instead.\n";
                    unsafe { libc::write(2, MSG.as_ptr().cast(), MSG.len()) };
                    unsafe { libc::_exit(126) };
                }
                Unplaceable::ProceedWithWarning => {
                    const MSG: &[u8] = b"kern: exec: KERN_ALLOW_UNCAPPED is set, so the command runs OUTSIDE the box's --memory/--pids caps. The box's namespaces, seccomp filter and AppArmor profile still apply to it; only the resource ceiling does not.\n";
                    unsafe { libc::write(2, MSG.as_ptr().cast(), MSG.len()) };
                }
                Unplaceable::ProceedQuietly => {}
            }
        }
        // For a `--health-timeout` probe: become a **session leader** (`setsid`) so this grandchild is
        // a new process-group/session leader inside the box's pid namespace whose host-visible id is
        // `pid` - the probe and everything it forks then live in that group, so the parent can
        // `kill(-pid)` the whole subtree on timeout. Also arm `PR_SET_PDEATHSIG(SIGKILL)` so if the
        // waiting stub dies for any reason the probe is torn down too. Skip under a tty (the terminal
        // pump owns the session).
        if tty_slave.is_none() && timeout_secs.is_some() {
            unsafe {
                libc::setsid();
                libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0,
                    0,
                    0,
                );
            }
        }
        // Fail CLOSED on the env wipe: an exec that ran with this caller's host environment still set
        // would leak host secrets/tokens into the box, the same leak `set_clean_env` exists to prevent.
        if set_clean_env("", env).is_err() {
            exec_fail_closed("could not sanitise the environment");
        }
        // `-it`: adopt the PTY slave as the controlling terminal (before seccomp - a setup syscall).
        //
        // THE BOX'S OWN DEVPTS IS ALREADY OURS HERE: `setns` put this child in the box's mount
        // namespace, so `/dev/ptmx` is the box's multiplexer and a pair opened from it lands at
        // `/dev/pts/N` - a path that RESOLVES for the command about to run. The host slave in
        // `tty_slave` is the fallback and stays exactly as it was if any of this fails.
        // `/dev` and not `<root>/dev`: `setns` already put this child in the box's mount namespace,
        // so the box's devpts IS `/dev/pts` here. Same handover as the box start path, same code.
        let box_slave = pty
            .as_ref()
            .and_then(|h| crate::ptybox::hand_over_pair("/dev", h.sock_child));
        if let Some(h) = pty.as_ref() {
            unsafe { libc::close(h.sock_child) };
        }
        if let Some(slave) = box_slave.or(tty_slave) {
            adopt_controlling_tty(slave);
        }
        // Parity with a box's own workload: reapply the box's OWN capability spec, so an `exec`'d
        // command is no MORE privileged than the box's PID 1 (which ran `drop_dangerous_caps` with the
        // same spec + seccomp before its own exec). `box_caps` is rebuilt by the caller from the
        // registry (`--cap-drop ALL` / `--cap-drop CAP` / `--cap-add CAP`); an older box with no
        // recorded spec passes `CapSpec::default()`, the dangerous baseline this used unconditionally
        // before. A `--cap-add` the box kept is preserved so exec matches PID 1 rather than being
        // stricter (harmless if it were, but this is the faithful reconstruction).
        // Fail CLOSED if the box's cap drop cannot be reapplied: an `exec` that kept the dangerous
        // baseline while the box's PID 1 dropped it would be a silent privilege gap in the box.
        if drop_dangerous_caps(box_caps).is_err() {
            exec_fail_closed("could not drop capabilities");
        }
        // THE IDENTITY, THEN THE DIRECTORY, and both AFTER the capability drop: dropping the
        // BOUNDING set needs `CAP_SETPCAP`, which a non-root uid no longer has. Measured by doing it
        // the other way round first: with the drop before it, every probe on a `--user` box failed
        // closed at "could not drop capabilities" and the box reported unhealthy. `CAP_SETUID` and
        // `CAP_SETGID` are not in the dangerous mask, so they are still here.
        //
        // FAIL CLOSED. Running the probe as root is exactly the false green this exists to remove.
        if let Some((uid, gid)) = run_as {
            if set_user(uid, gid, extra_gids).is_err() {
                exec_fail_closed("could not drop to the box's own user");
            }
        }
        // Honor `--workdir` - fatal if it can't be entered (consistent with `kern box -w`, so a
        // typo'd dir is an error, not a silent run in `/`).
        if let Some(wd) = workdir {
            let entered = cstr(wd).is_ok_and(|c| unsafe { libc::chdir(c.as_ptr()) } == 0);
            if !entered {
                eprintln!("kern: exec: cannot enter workdir {wd}");
                unsafe { libc::_exit(127) };
            }
        }
        // Fail CLOSED if seccomp can't install - never run the exec'd command unfiltered (the box's
        // PID 1 fails closed on this same call; `exec` must match, not fall through unprotected).
        // `seccomp_mode` is the box's OWN recorded filter (denylist vs allowlist), so the exec'd
        // command runs under the SAME posture as PID 1 - not one re-derived from this caller's
        // environment (a box on the deny-by-default allowlist must not be entered by an exec that
        // fell back to the wider denylist). Nesting stays STRICT (`allow_nesting=false`) regardless of
        // the box's `--privileged`: an exec being MORE constrained than PID 1 is always safe, whereas
        // relaxing it would be the dangerous direction, so this axis is deliberately not reproduced.
        // `--apparmor` parity: if the box's PID 1 entered an AppArmor profile, the exec'd command must
        // re-enter it too - otherwise `kern exec` (like a lax `docker exec`) would run OUTSIDE the box's
        // LSM confinement. Applied BEFORE seccomp, the same order PID 1 used. Fail-closed: a profile
        // that won't re-enter refuses the exec rather than running it unconfined.
        if let Some(profile) = apparmor {
            if apply_apparmor_onexec(profile).is_err() {
                exec_fail_closed("could not re-enter the box's AppArmor profile");
            }
        }
        if crate::seccomp::install(seccomp_mode, false).is_err() {
            exec_fail_closed("seccomp filter could not be installed");
        }
        // SECURITY (CVE-2016-9962 class): same fd shed as the box workload path - a descriptor this
        // caller left open (an SDK holding a socket, a host file) must not pass through `setns` + this
        // `execvp` into the box. No readiness pipe on the exec path, so keep none; the pty slave was
        // already dup'd onto 0/1/2 and its high fd closed by `adopt_controlling_tty` above.
        shed_inherited_fds(-1);
        // `kern exec` has no readiness pipe and no gate: nothing to announce, nothing to wait for.
        let err = exec(&argv, None, None);
        // `execve` returned, so it FAILED. ENOENT & friends = "command not found" (127). EACCES = the
        // kernel FOUND it but refused to run it (126, the POSIX code for "found but not executable") -
        // and with `--apparmor` in play that is almost always the LSM refusing the profile transition
        // because the profile was UNLOADED on the host after the box started (`apparmor_parser -R`),
        // NOT the user's command. Name that cause and fail closed rather than mimic "not found", so the
        // operator looks at the sandbox, not at their argv.
        let eacces =
            matches!(&err, Error::Syscall(_, io) if io.raw_os_error() == Some(libc::EACCES));
        if eacces && apparmor.is_some() {
            exec_fail_closed(
                "exec refused (EACCES): the box's AppArmor profile would not admit it (was the \
                 profile unloaded on the host?), or the target is not executable",
            );
        }
        eprintln!("kern: exec failed: {err}");
        unsafe { libc::_exit(if eacces { 126 } else { 127 }) };
    }
    // `-it` parent: drop our copy of the slave so the master sees EOF when the exec'd process exits,
    // then pump host stdio <-> master until then (single-threaded, like the box path).
    if let Some(master) = tty_master {
        if let Some(slave) = tty_slave {
            unsafe { libc::close(slave) };
        }
        // THE BOX'S MASTER, IF THE CHILD BUILT ONE. `recv_fd` answers `None` on EOF, so a child that
        // never reached the allocation (or could not) costs one read and leaves the host pty pumping,
        // which is exactly what happened before this existed.
        let mut master = master;
        if let Some(h) = pty.as_ref() {
            unsafe { libc::close(h.sock_child) };
            if let Some(m) = crate::ptybox::recv_fd(h.sock_parent) {
                // Size and SIGWINCH follow the terminal actually in use; the CLI owns that state.
                (h.retarget)(m);
                unsafe { libc::close(master) };
                master = m;
            }
        }
        let code = pty_pump_and_wait(master, pid);
        if let Some(h) = pty.as_ref() {
            unsafe { libc::close(h.sock_parent) };
        }
        return Ok(code);
    }
    // No terminal on this call, so the handover channel is pure cost: close both ends rather than
    // let a `--health-cmd` probe accumulate two descriptors per interval.
    if let Some(h) = pty.as_ref() {
        unsafe {
            libc::close(h.sock_child);
            libc::close(h.sock_parent);
        }
    }
    let mut status = 0i32;
    match timeout_secs {
        // `--health-timeout`: poll, and on expiry SIGKILL the whole probe group (the in-box grandchild
        // and anything it spawned), then reap - so a hung probe can't leak a live process into the box
        // every interval. Returns 124 (the `timeout(1)` convention) on expiry.
        Some(secs) if secs > 0 => {
            let mut waited_ms = 0u64;
            loop {
                let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if r == pid {
                    return Ok(wait_code(status));
                }
                if r < 0 {
                    return Err(Error::last("waitpid"));
                }
                if waited_ms >= secs * 1000 {
                    // Kill the probe's whole session/group (the grandchild made itself the leader), so
                    // a probe that forked helpers is fully torn down - not just its top process; then
                    // reap the grandchild. `kill(-pid)` is the load-bearing one; the direct `kill(pid)`
                    // covers the (skipped-setsid) edge.
                    unsafe { libc::kill(-pid, libc::SIGKILL) };
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                    reap_retry_eintr(pid, &mut status); // reap the killed probe (EINTR-robust, no zombie)
                    return Ok(124);
                }
                unsafe { libc::usleep(100_000) }; // 100 ms
                waited_ms += 100;
            }
        }
        _ => {
            if reap_retry_eintr(pid, &mut status) < 0 {
                return Err(Error::last("waitpid"));
            }
            let code = wait_code(status);
            // SIGKILL E IL CONTATORE SALITO: il comando e' stato ucciso col box. Da solo `128 + SIGKILL`
            // non dice niente, perche' SIGKILL ha molti mittenti; l'incremento di `oom_group_kill` sul
            // cgroup ANTENATO e' cio' che lo attribuisce.
            //
            // ⛔ L'attesa e' necessaria e non e' cautela: il contatore atterra DOPO che il processo e'
            // morto. Misurato, un solo campione preso all'istante della morte riportava l'OOM in 3 corse
            // su 10. A passi di 2 ms fino a 400: sono 200x il massimo osservato (2 ms), e questo tempo lo
            // paga solo un comando GIA' ucciso, mai uno sano.
            if code == 128 + libc::SIGKILL {
                if let (Some(fd), Some(base)) = (oom_events_fd, oom_baseline) {
                    let mut fired = false;
                    let mut waited = 0;
                    while !fired && waited <= 400 {
                        fired =
                            crate::cgroup::oom_group_kill_from_fd(fd).is_some_and(|now| now > base);
                        if fired {
                            break;
                        }
                        let ts = libc::timespec {
                            tv_sec: 0,
                            tv_nsec: 2_000_000,
                        };
                        unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
                        waited += 2;
                    }
                    if fired {
                        eprintln!(
                            "kern: exec: this command was killed with its box by the kernel's OOM \
                             killer, against the box's memory cap (memory.oom.group kills the whole \
                             box, the exec'd command included). Raise it with `--memory <size>`."
                        );
                    }
                }
            }
            if let Some(fd) = oom_events_fd {
                unsafe { libc::close(fd) };
            }
            Ok(code)
        }
    }
}

#[cfg(test)]
mod ready_guard_tests {
    use super::ReadyGuard;

    /// Read the read end (the write end is already closed in these tests, so this won't block).
    /// Returns bytes read: 0 = EOF = "started", >0 = a failure byte was written = "failed".
    fn drain(rd: i32) -> usize {
        let mut buf = [0u8; 4];
        let n = unsafe { libc::read(rd, buf.as_mut_ptr().cast(), buf.len()) };
        unsafe { libc::close(rd) };
        n.max(0) as usize
    }

    fn pipe() -> (i32, i32) {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        (fds[0], fds[1])
    }

    #[test]
    fn armed_guard_signals_failure_on_drop() {
        // HIGH-bug regression: an error path that drops the guard while armed (e.g. a pre-fork
        // `unshare`/`uid_map` failure) MUST write a failure byte, not present a clean EOF.
        let (rd, wr) = pipe();
        drop(ReadyGuard(Some(wr)));
        assert_eq!(drain(rd), 1, "armed drop must write a failure byte");
    }

    #[test]
    fn disarmed_guard_is_silent() {
        // Success path: the box child / parent disarm the guard, so dropping it writes nothing -
        // the read end then sees EOF only once the real fd owner closes it.
        let (rd, wr) = pipe();
        let mut g = ReadyGuard(Some(wr));
        let fd = g.disarm();
        drop(g);
        if let Some(fd) = fd {
            unsafe { libc::close(fd) };
        }
        assert_eq!(drain(rd), 0, "disarmed drop must be silent (EOF)");
    }
}

#[cfg(test)]
mod shed_tests {
    use super::shed_inherited_fds;

    /// SECURITY (CVE-2016-9962 class): `shed_inherited_fds` must close every inherited fd `>= 3` except
    /// the one to keep, so a descriptor kern's caller left open does not pass through `execvp` into the
    /// box. Exercised in a FORKED child: the function closes the WHOLE process's fds, which would nuke
    /// the test harness's own descriptors if run inline. The child reports which fds survived through a
    /// pipe whose write end is the fd we ask to keep.
    #[test]
    fn shed_closes_inherited_fds_except_keep() {
        let mut report = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(report.as_mut_ptr()) }, 0, "pipe");
        let (rd, wr) = (report[0], report[1]);

        // Two "leaked" descriptors that shed must close, both `>= 3`.
        let leak_a = unsafe { libc::dup(0) };
        let leak_b = unsafe { libc::dup(0) };
        assert!(leak_a >= 3 && leak_b >= 3, "dups must land at fd >= 3");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            // CHILD: shed everything >= 3 except the report pipe write end, then report.
            shed_inherited_fds(wr);
            let is_open =
                |fd: i32| -> u8 { (unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1) as u8 };
            let out = [is_open(leak_a), is_open(leak_b), is_open(wr), is_open(1)];
            unsafe {
                libc::write(wr, out.as_ptr().cast(), out.len());
                libc::_exit(0);
            }
        }
        // PARENT: read the child's four verdict bytes.
        unsafe { libc::close(wr) };
        let mut buf = [9u8; 4];
        let n = unsafe { libc::read(rd, buf.as_mut_ptr().cast(), buf.len()) };
        unsafe {
            libc::close(rd);
            libc::close(leak_a);
            libc::close(leak_b);
            let mut st = 0i32;
            libc::waitpid(pid, &mut st, 0);
        }
        assert_eq!(n, 4, "child must report four bytes");
        assert_eq!(buf[0], 0, "a leaked inherited fd must be CLOSED by shed");
        assert_eq!(
            buf[1], 0,
            "every leaked inherited fd must be CLOSED by shed"
        );
        assert_eq!(
            buf[2], 1,
            "the kept fd must stay OPEN (it carries the readiness signal)"
        );
        assert_eq!(buf[3], 1, "stdio (fd 1) must be untouched");
    }
}

#[cfg(test)]
mod setup_window_sequence_tests {
    /// SECURITY (TOCTOU / setup-window regression): the seccomp filter and the capability drop are the
    /// LAST setup steps before the workload's `execvp`, so nothing untrusted runs in the window between
    /// entering the user namespace and the filter being in force. A hand grep proved that once; this
    /// makes it a permanent guard. A future edit that forks or execs a process in the setup window -
    /// before `crate::seccomp::install(...)` - FAILS the build instead of silently opening the window
    /// (the exact gap a reviewer flagged as having no automated cancello).
    ///
    /// The test reads its own source and asserts no process-launching token appears inside
    /// `child_setup_and_exec` BEFORE the install call: the CALL SYNTAX (with a `(`) for the ways a
    /// new/foreign program starts (`execvp(`/`execve(`/`execv(`/`posix_spawn(`/`Command::new(`/
    /// `.spawn(`) or a new task forks (`libc::fork(`/`libc::clone(`/`run_init(`). `//` line comments
    /// are stripped first, so prose that merely NAMES a syscall (the apparmor comment mentions "the
    /// eventual execve") cannot trip the scan - only real call syntax does. `aa_change_onexec`/
    /// `apply_apparmor_onexec` only ARM a transition that fires at the eventual execve, launching
    /// nothing, and by their spelling match none of the tokens anyway.
    #[test]
    fn no_untrusted_exec_before_the_seccomp_filter() {
        const SRC: &str = include_str!("real.rs");
        let fn_start = SRC
            .find("fn child_setup_and_exec")
            .expect("child_setup_and_exec must exist");
        let after_fn = &SRC[fn_start..];
        // The FIRST seccomp install after the function signature is the barrier (line ~990); the test
        // module's own token list sits far below it, so it is never scanned.
        let install = after_fn
            .find("crate::seccomp::install(")
            .expect("child_setup_and_exec must install the seccomp filter");
        // Strip `//` line comments so prose naming a syscall cannot false-positive; scan only code.
        let setup_window: String = after_fn[..install]
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        for tok in [
            "execvp(",
            "execve(",
            "execv(",
            "posix_spawn(",
            "Command::new(",
            ".spawn(",
            "libc::fork(",
            "libc::clone(",
            "run_init(",
        ] {
            assert!(
                !setup_window.contains(tok),
                "'{tok}' appears in child_setup_and_exec BEFORE seccomp::install: the setup window \
                 must run no untrusted code before the filter and cap drop are in force (TOCTOU guard)"
            );
        }
        // Guard against a barrier matched too early: the workload's own exec (`exec(argv)`) must exist
        // AFTER the install, confirming `install` is the true last-lockdown-before-exec barrier.
        assert!(
            after_fn[install..].contains("exec(argv)"),
            "exec(argv) must come AFTER seccomp::install in child_setup_and_exec"
        );
    }
}

#[cfg(test)]
mod pdeathsig_cascade_tests {
    // Reproduces the OS mechanism the orphan-on-launcher-death fix relies on: a "box PID 1" (G)
    // that arms `PR_SET_PDEATHSIG(SIGKILL)` relative to its "supervisor" (A) is SIGKILLed the moment
    // A dies - the same relationship `run_in_sandbox_with` wires between the box's pidns-init and its
    // supervisor when `die_with_parent` is set. Deterministic (kernel-guaranteed pdeathsig delivery),
    // no namespaces/root needed, so it runs anywhere. The whole scenario runs inside a dedicated
    // observer child so the subreaper mode + `waitpid(-1)` can't disturb the cargo test harness.
    #[test]
    fn armed_grandchild_is_sigkilled_when_its_parent_dies() {
        unsafe {
            let outer = libc::fork();
            assert!(outer >= 0, "fork(observer) failed");
            if outer == 0 {
                // ── Observer (isolated process) ──
                // Anti-hang: if the cascade DOESN'T fire, G would `pause()` forever and our
                // `waitpid` would block - SIGALRM turns that into a visible non-zero exit instead.
                libc::alarm(10);
                // Become a subreaper so a grandchild orphaned by A's death reparents to US, letting
                // us reap it and observe HOW it died (rather than losing it to init).
                libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
                let mut sync = [0i32; 2];
                if libc::pipe(sync.as_mut_ptr()) != 0 {
                    libc::_exit(10);
                }
                let (sr, sw) = (sync[0], sync[1]);
                let a = libc::fork();
                if a < 0 {
                    libc::_exit(11);
                }
                if a == 0 {
                    // ── A: the "supervisor" ──
                    let g = libc::fork();
                    if g < 0 {
                        libc::_exit(12);
                    }
                    if g == 0 {
                        // ── G: the "box PID 1" - arm the death cascade, then block forever ──
                        libc::close(sr);
                        libc::prctl(
                            libc::PR_SET_PDEATHSIG,
                            libc::SIGKILL as libc::c_ulong,
                            0,
                            0,
                            0,
                        );
                        // Tell A we've armed it BEFORE A exits - closes the pdeathsig race (a parent
                        // that dies before the child arms would never trigger the signal).
                        let one = [1u8; 1];
                        let _ = libc::write(sw, one.as_ptr().cast(), 1);
                        libc::close(sw);
                        loop {
                            libc::pause();
                        }
                    }
                    // A: wait until G has armed pdeathsig, then die to trigger it.
                    libc::close(sw);
                    let mut b = [0u8; 1];
                    while libc::read(sr, b.as_mut_ptr().cast(), 1) < 0 {}
                    libc::_exit(0);
                }
                libc::close(sr);
                libc::close(sw);
                // Reap both descendants: A (clean exit 0) and G (SIGKILL, reparented to us).
                let (mut got_kill, mut got_exit0) = (false, false);
                loop {
                    let mut st = 0i32;
                    let r = libc::waitpid(-1, &mut st, 0);
                    if r <= 0 {
                        break; // ECHILD: everyone reaped
                    }
                    if libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == libc::SIGKILL {
                        got_kill = true;
                    } else if libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0 {
                        got_exit0 = true;
                    }
                }
                libc::_exit(if got_kill && got_exit0 { 0 } else { 20 });
            }
            // ── Test process ── reap ONLY our observer by pid (no `waitpid(-1)` here, so we never
            // steal a sibling test's child).
            let mut st = 0i32;
            let r = libc::waitpid(outer, &mut st, 0);
            assert_eq!(r, outer, "waitpid(observer) failed");
            assert!(
                libc::WIFEXITED(st),
                "observer was signaled (e.g. SIGALRM timeout) - cascade never fired (status {st})"
            );
            assert_eq!(
                libc::WEXITSTATUS(st),
                0,
                "PDEATHSIG cascade broken: the armed grandchild was NOT SIGKILLed when its parent died"
            );
        }
    }
}

/// The `--uid-range` + official-image gap (0.6): images whose entrypoint drops privilege
/// (postgres/redis/mysql/nginx `setpriv`/`gosu` to a service uid) failed to start. ROOT CAUSE (found
/// by ~45 tests, after ruling out idmapped mounts - impossible rootless, EPERM: mount_setattr(IDMAP)
/// needs CAP_SYS_ADMIN in the init userns where the image fs lives - and fuse-overlayfs - slow,
/// user-space): the box's `/` was mode 0700 (from the own-only overlay upper), so ANY dropped non-root
/// uid hit EACCES on the FIRST path component `/`, before ownership ever mattered. FIX (two surgical
/// changes): (1) the box root is 0755 when privilege may be dropped (`--user` non-root OR `--uid-range`),
/// a normal rootfs mode, safe because the HOST scratch dir stays 0700 and isolation is the namespace,
/// not the root's mode; (2) `/dev/fd` + `/dev/std{in,out,err}` symlinks into procfs (bash process
/// substitution / postgres initdb need them). Verified live: redis, nginx, postgres all reach
/// "ready to accept connections" under `--uid-range`.
/// The pod holder learns WHY its range was asked for through an env var, because it decides in a
/// forked child, after the parent is gone. That crossing must survive a kern upgrade in both
/// directions: a holder started by an older kern wrote a bare `1`, which has to keep warning rather
/// than fall silent, since back then only an explicit `--uid-range` could set it at all.
#[cfg(test)]
mod uid_range_env_roundtrip {
    use super::UidRange;

    #[test]
    fn every_variant_survives_the_env_crossing() {
        for v in [UidRange::Off, UidRange::ImageDefault, UidRange::Requested] {
            let wire = v.as_env();
            let back = UidRange::from_env(if wire.is_empty() { None } else { Some(wire) });
            assert_eq!(back, v, "{v:?} did not survive as {wire:?}");
        }
    }

    #[test]
    fn an_older_holders_bare_1_still_warns() {
        // Pre-enum kern set `1` only for an explicit `--uid-range`, so it must read as Requested,
        // never as the silent per-image default.
        assert_eq!(UidRange::from_env(Some("1")), UidRange::Requested);
        // An unset or empty variable is simply off.
        assert_eq!(UidRange::from_env(None), UidRange::Off);
        assert_eq!(UidRange::from_env(Some("")), UidRange::Off);
        assert!(!UidRange::Off.is_on());
        assert!(UidRange::ImageDefault.is_on() && UidRange::Requested.is_on());
    }
}

#[cfg(test)]
mod uid_range_root_traversable {
    use std::os::unix::fs::PermissionsExt;

    // The fix is a mode on the overlay upper (→ the box root). Assert the exact rule the box path uses:
    // root becomes world-traversable (0755) iff a non-root --user is set, OR --uid-range is on, OR the
    // box is a POD MEMBER (it joins a shared user ns that may map a range, and its image may drop
    // privilege - the box's own uid_range flag is false there, so pod membership must count too).
    fn root_should_be_traversable(user_non_root: bool, uid_range: bool, pod_member: bool) -> bool {
        user_non_root || uid_range || pod_member
    }

    #[test]
    fn root_is_traversable_when_privilege_may_be_dropped() {
        assert!(
            root_should_be_traversable(false, true, false),
            "--uid-range → 0755 (entrypoint may drop)"
        );
        assert!(
            root_should_be_traversable(true, false, false),
            "--user non-root → 0755"
        );
        assert!(
            root_should_be_traversable(false, false, true),
            "pod member → 0755 (shared range userns, image may drop, e.g. postgres/redis)"
        );
        assert!(root_should_be_traversable(true, true, true));
        assert!(
            !root_should_be_traversable(false, false, false),
            "plain root box stays own-only 0700"
        );
    }

    #[test]
    fn mode_0755_is_world_traversable() {
        // The property that was missing: other-execute on the root so a dropped uid can enter `/`.
        let perms = std::fs::Permissions::from_mode(0o755);
        assert_eq!(
            perms.mode() & 0o001,
            0o001,
            "0755 must have other-execute (traversal)"
        );
        assert_eq!(
            std::fs::Permissions::from_mode(0o700).mode() & 0o001,
            0,
            "0700 blocks other - the bug"
        );
    }
}

#[cfg(test)]
mod cpuset_expand_tests {
    use super::expand_cpu_list;

    /// REGRESSION (HIGH, hacker-mode audit): a huge cpuset range must NOT allocate a giant Vec. Indices
    /// past CPU_SETSIZE are unsettable, so the range is clamped before expansion - `0-999999999` yields
    /// at most CPU_SETSIZE entries, not a billion (which would be ~8 GB → memory-exhaustion DoS).
    #[test]
    fn huge_cpuset_range_is_clamped_not_exploded() {
        let max = libc::CPU_SETSIZE as usize;
        let v = expand_cpu_list("0-999999999");
        assert!(v.len() <= max, "expanded {} entries, cap is {max}", v.len());
        assert_eq!(v.first(), Some(&0));
        assert_eq!(v.last(), Some(&(max - 1)));
        // A bare index past the cap contributes nothing.
        assert!(expand_cpu_list("999999999").is_empty());
        // Normal small lists are unaffected.
        assert_eq!(expand_cpu_list("0-3,5"), vec![0, 1, 2, 3, 5]);
    }
}

#[cfg(test)]
mod add_host_tests {
    use super::*;

    #[test]
    fn a_mount_that_does_not_take_leaves_no_mountpoint_behind() {
        // The artifact rule, on the branch that only fires when a mount fails. No fault switch is
        // needed: a filesystem type the kernel does not have fails for a real kernel reason, on a
        // real path, and unprivileged it fails regardless of type - either way the assertion is the
        // same one, that nothing is left to be mistaken for a successful mount.
        let base = std::env::temp_dir().join(format!("kern-mountrule-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let Ok(()) = std::fs::create_dir_all(&base) else {
            return;
        };

        let bogus = base.join("nosuch");
        let took = mount_or_leave_nothing(&bogus.to_string_lossy(), "nosuchfs-kern-test");
        assert!(
            !took,
            "a filesystem type the kernel does not have cannot mount"
        );
        assert!(
            !bogus.exists(),
            "a mount that did not take must leave NO directory: an empty mountpoint is a path that \
             exists and answers nothing, which is the failure this rule removes"
        );

        // The mountpoint is not created when the mkdir itself cannot succeed, so a pre-existing
        // path is never adopted and never removed. `rmdir` must not reach something kern did not
        // make one syscall earlier.
        let taken = base.join("taken");
        let Ok(()) = std::fs::create_dir_all(&taken) else {
            let _ = std::fs::remove_dir_all(&base);
            return;
        };
        let _ = std::fs::write(taken.join("keep"), b"x");
        assert!(!mount_or_leave_nothing(
            &taken.to_string_lossy(),
            "nosuchfs-kern-test"
        ));
        assert!(
            taken.join("keep").exists(),
            "an existing directory is neither mounted over nor removed"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn etc_identity_seeds_hosts_and_rewrites_hostname() {
        let tmp = std::env::temp_dir().join(format!("kern-etcid-a-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let Ok(()) = std::fs::create_dir_all(tmp.join("etc")) else {
            return;
        };
        // The shape an image actually ships: no hosts file at all, and a hostname naming the
        // machine that BUILT the image (debian images carry `debuerreotype`).
        let _ = std::fs::write(tmp.join("etc/hostname"), "debuerreotype\n");
        let root = tmp.to_string_lossy().into_owned();

        setup_etc_identity(&root, "boxname");

        let hosts = std::fs::read_to_string(tmp.join("etc/hosts")).unwrap_or_default();
        assert!(
            hosts.contains("127.0.0.1\tlocalhost"),
            "the localhost seed is written: {hosts:?}"
        );
        // `localhost` MUST NOT ALSO NAME `::1`. With a working IPv6 loopback, musl prefers `::1`
        // and busybox `wget` uses the first address only, so `wget http://localhost:PORT` against
        // an IPv4-only listener - the most common health check spelling there is - was refused in
        // a kern box and returned 0 under podman. The IPv6 loopback keeps its own names.
        assert!(
            hosts.contains("::1\tip6-localhost") && !hosts.contains("::1\tlocalhost"),
            "the IPv6 line must not claim the name `localhost`: {hosts:?}"
        );
        assert!(
            hosts.contains("127.0.0.1\tboxname"),
            "the box resolves its own name: {hosts:?}"
        );
        let hn = std::fs::read_to_string(tmp.join("etc/hostname")).unwrap_or_default();
        assert_eq!(
            hn, "boxname\n",
            "the image's build-host name is replaced, not appended to"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn etc_identity_leaves_a_populated_hosts_alone() {
        let tmp = std::env::temp_dir().join(format!("kern-etcid-b-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let Ok(()) = std::fs::create_dir_all(tmp.join("etc")) else {
            return;
        };
        // Alpine ships one; so does the pod bind, which arrives as a non-empty file over this path.
        let shipped = "127.0.0.1\tlocalhost localhost.localdomain\n";
        let _ = std::fs::write(tmp.join("etc/hosts"), shipped);
        let root = tmp.to_string_lossy().into_owned();

        setup_etc_identity(&root, "boxname");

        let hosts = std::fs::read_to_string(tmp.join("etc/hosts")).unwrap_or_default();
        assert_eq!(
            hosts, shipped,
            "a non-empty hosts file is never rewritten, so a pod's shared file is not duplicated"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn etc_identity_seeds_a_file_that_exists_but_answers_nothing() {
        // The third instance of a predicate this project has got wrong twice on `resolv.conf`:
        // `exists()` was satisfied by debian's EMPTY file, non-empty is satisfied by a file that
        // names nothing. An `/etc/hosts` of pure comments is non-empty and still leaves
        // `getaddrinfo("localhost")` failing, so the test is what the file ANSWERS, not its size.
        let tmp = std::env::temp_dir().join(format!("kern-etcid-d-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let Ok(()) = std::fs::create_dir_all(tmp.join("etc")) else {
            return;
        };
        let comments = "# written by the build\n# do not edit\n";
        let _ = std::fs::write(tmp.join("etc/hosts"), comments);

        setup_etc_identity(&tmp.to_string_lossy(), "boxname");

        let out = std::fs::read_to_string(tmp.join("etc/hosts")).unwrap_or_default();
        assert!(
            out.starts_with(comments),
            "what the image wrote is kept, the seeds go under it: {out:?}"
        );
        assert!(
            out.contains("127.0.0.1\tlocalhost") && out.contains("127.0.0.1\tboxname"),
            "a file that resolved nothing is seeded: {out:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn etc_identity_refuses_a_symlinked_etc_and_a_symlinked_target() {
        let tmp = std::env::temp_dir().join(format!("kern-etcid-c-{}", std::process::id()));
        let out = std::env::temp_dir().join(format!("kern-etcid-c-out-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir_all(&out);
        let Ok(()) = std::fs::create_dir_all(&out) else {
            return;
        };
        let Ok(()) = std::fs::create_dir_all(&tmp) else {
            return;
        };

        // 1. `/etc` itself is a symlink out of the root: the descent must refuse it.
        if std::os::unix::fs::symlink(&out, tmp.join("etc")).is_ok() {
            setup_etc_identity(&tmp.to_string_lossy(), "boxname");
            assert!(
                !out.join("hosts").exists() && !out.join("hostname").exists(),
                "a symlinked /etc must not be followed out of the box root"
            );
            let _ = std::fs::remove_file(tmp.join("etc"));
        }

        // 2. `/etc` is real but `/etc/hosts` points outside: the final component must refuse too.
        let Ok(()) = std::fs::create_dir_all(tmp.join("etc")) else {
            return;
        };
        if std::os::unix::fs::symlink(out.join("pwned"), tmp.join("etc/hosts")).is_ok() {
            setup_etc_identity(&tmp.to_string_lossy(), "boxname");
            assert!(
                !out.join("pwned").exists(),
                "a symlinked /etc/hosts must not be followed out of the box root"
            );
        }
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn extra_hosts_writes_clean_entries_and_refuses_injection() {
        let tmp = std::env::temp_dir().join(format!("kern-addhost-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("etc")).unwrap();
        std::fs::write(tmp.join("etc/hosts"), "127.0.0.1 localhost\n").unwrap();
        let root = tmp.to_string_lossy().into_owned();

        setup_extra_hosts(
            &root,
            &[
                ("db.local".into(), "10.0.0.5".into()), // clean → written
                // a newline in the IP must NOT inject a second hosts line
                ("good".into(), "1.2.3.4\n6.6.6.6 evil.injected".into()),
                // whitespace/newline in the name → skipped
                ("bad\n7.7.7.7 sneaky".into(), "9.9.9.9".into()),
                ("".into(), "1.1.1.1".into()), // empty name → skipped
            ],
        );

        let out = std::fs::read_to_string(tmp.join("etc/hosts")).unwrap();
        assert!(out.contains("10.0.0.5\tdb.local"), "clean entry is written");
        assert!(
            out.contains("127.0.0.1 localhost"),
            "existing entries preserved"
        );
        assert!(
            !out.contains("evil.injected") && !out.contains("sneaky"),
            "no injected /etc/hosts line: {out:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn extra_hosts_refuses_a_symlinked_etc_and_cannot_escape_the_box_root() {
        // A hostile image shipping `/etc` as a symlink must NOT let the append escape the box root
        // (open_in_root refuses a symlink at every component). Runs pre-pivot, so a naive open would
        // resolve through the host root - this is the exact escape the audit flagged.
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir().join(format!("kern-etcsym-{}", std::process::id()));
        let root = base.join("boxroot");
        let victim = base.join("victim"); // OUTSIDE the box root
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&victim).unwrap();
        // box root's `etc` is a symlink to the victim dir
        symlink(&victim, root.join("etc")).unwrap();

        setup_extra_hosts(&root.to_string_lossy(), &[("db".into(), "1.2.3.4".into())]);

        assert!(
            !victim.join("hosts").exists(),
            "a symlinked /etc must not let the append escape to the victim dir"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}

#[cfg(test)]
mod cap_mask_tests {
    use super::*;

    #[test]
    fn default_dropped_mask_covers_the_dangerous_set_only() {
        let m = default_dropped_cap_mask();
        // Every DEFAULT_DROP cap is set: NET_ADMIN(12), SYS_MODULE(16), SYS_RAWIO(17), SYS_PTRACE(19),
        // SYS_ADMIN(21), SYS_BOOT(22), PERFMON(38), BPF(39). NET_ADMIN and SYS_ADMIN are in the default
        // set now (converged onto Docker's/Podman's default); the two condition flags re-keep them.
        for c in [
            12u32, 16, 17, 19, 20, 21, 22, 25, 30, 32, 33, 34, 35, 37, 38, 39,
        ] {
            assert!(m & (1u64 << c) != 0, "cap {c} must be in the dropped mask");
        }
        // Kept caps are NOT in the mask (so a default box never false-flags): CHOWN(0), SETUID(7),
        // MKNOD(27). (SYS_PTRACE(19), NET_ADMIN(12) and SYS_ADMIN(21) are now dropped by default.)
        for c in [0u32, 7, 27] {
            assert!(
                m & (1u64 << c) == 0,
                "kept cap {c} must NOT be in the dropped mask"
            );
        }
        // The mask is exactly the default drop of an unmodified spec (the bounding set kern imposes).
        assert_eq!(m, cap_drop_mask(&CapSpec::default(), false, false));
    }

    #[test]
    fn tun_keeps_net_admin_and_privileged_keeps_sys_admin() {
        // The two CONDITIONAL keeps, verified against the default spec. Bit 12 = CAP_NET_ADMIN, bit 21 =
        // CAP_SYS_ADMIN. Default (no flag) drops BOTH; `--tun` keeps NET_ADMIN; `--privileged` keeps
        // SYS_ADMIN; each keep touches ONLY its own cap (no cross-leak).
        let d = CapSpec::default();
        let base = cap_drop_mask(&d, false, false);
        assert!(base & (1u64 << 12) != 0, "default drops NET_ADMIN");
        assert!(base & (1u64 << 21) != 0, "default drops SYS_ADMIN");

        let tun = cap_drop_mask(&d, true, false);
        assert!(tun & (1u64 << 12) == 0, "--tun keeps NET_ADMIN");
        assert!(tun & (1u64 << 21) != 0, "--tun does NOT keep SYS_ADMIN");

        let priv_ = cap_drop_mask(&d, false, true);
        assert!(priv_ & (1u64 << 21) == 0, "--privileged keeps SYS_ADMIN");
        assert!(
            priv_ & (1u64 << 12) != 0,
            "--privileged does NOT keep NET_ADMIN"
        );

        // A conditional keep wins over a contradictory explicit `--cap-drop` (same "keep wins" rule as
        // `--cap-add`), so `--tun`/`--privileged` never silently lose the cap the feature needs - even
        // under `--cap-drop ALL`. SECURITY-CRITICAL: under `--cap-drop ALL` (what `--security-profile
        // untrusted` installs) a single feature flag re-keeps ONLY its own cap - the whole rest of the
        // 64-bit space stays dropped, so `untrusted --tun` is one cap over an isolated netns, not a hole.
        let drop_all = CapSpec {
            drop_all: true,
            ..Default::default()
        };
        // Diff against the pure ALL mask (no flags): the XOR is EXACTLY the feature's bit and nothing
        // else - the precise "no cross-leak, no extra cap" property. (count_zeros on the full u64 would
        // count the always-zero high bits above CAP_LAST_CAP, so it is the wrong tool here.)
        let base_all = cap_drop_mask(&drop_all, false, false);
        let all_tun = cap_drop_mask(&drop_all, true, false);
        assert_eq!(
            base_all ^ all_tun,
            1u64 << 12,
            "under ALL, --tun un-drops EXACTLY NET_ADMIN (bit 12), nothing else: {all_tun:#x}"
        );
        assert!(
            all_tun & (1u64 << 21) != 0,
            "SYS_ADMIN stays dropped under ALL+--tun"
        );
        let all_priv = cap_drop_mask(&drop_all, false, true);
        assert_eq!(
            base_all ^ all_priv,
            1u64 << 21,
            "under ALL, --privileged un-drops EXACTLY SYS_ADMIN (bit 21), nothing else: {all_priv:#x}"
        );
        assert!(
            all_priv & (1u64 << 12) != 0,
            "NET_ADMIN stays dropped under ALL+--privileged"
        );
        // Both flags under ALL un-drop exactly the two feature caps, nothing more.
        assert_eq!(
            base_all ^ cap_drop_mask(&drop_all, true, true),
            (1u64 << 12) | (1u64 << 21)
        );
        // `--cap-add` still works for a box that is neither --tun nor --privileged.
        let add_na = CapSpec {
            adds: vec![12],
            ..Default::default()
        };
        assert!(cap_drop_mask(&add_na, false, false) & (1u64 << 12) == 0);
    }

    #[test]
    fn cap_add_puts_a_dropped_cap_back_so_top_can_flag_it() {
        // `--cap-add SYS_MODULE` removes cap 16 from the drop set → the box's bounding set KEEPS it →
        // its CapBnd then intersects default_dropped_cap_mask(), which is how `kern top` flags caps:+.
        let spec = CapSpec {
            adds: vec![16],
            ..Default::default()
        };
        let dropped = cap_drop_mask(&spec, false, false);
        assert!(
            dropped & (1u64 << 16) == 0,
            "--cap-add SYS_MODULE must NOT drop cap 16"
        );
        // The bounding set = full minus the drop set; cap 16 survives and would be flagged.
        assert!(default_dropped_cap_mask() & (1u64 << 16) != 0);
    }

    #[test]
    fn read_cap_bnd_parses_the_real_bounding_set() {
        // `drop_cap_bounding` VERIFIES its own result by re-reading CapBnd instead of trusting the
        // per-call errno. That verification is only as good as the parse: the test process has a full
        // bounding set, so the value must be non-zero and cover the low caps that always exist.
        let bnd = read_cap_bnd().expect("/proc/self/status always has a CapBnd line on Linux");
        assert!(bnd != 0, "the test runner's bounding set is not empty");
        // CAP_CHOWN(0) and CAP_DAC_OVERRIDE(1) exist on every kernel this runs on.
        assert!(
            bnd & 0b11 == 0b11,
            "low caps present in the runner's CapBnd"
        );
    }
}

#[cfg(test)]
mod nesting_gate_tests {
    use super::uid_map_root_is_unprivileged;

    /// `--privileged` nesting is gated on the EFFECTIVE box-root mapping, not the caller's euid - so a
    /// `--pod` box that joins a holder's userns is judged by the holder's real map. This is the parser
    /// behind that gate; it MUST refuse (fail closed) whenever box-root could reach host root.
    #[test]
    fn nesting_gate_reads_the_effective_map_and_fails_closed() {
        // Rootless: inner 0 → host 1000 (single-uid) or a subuid → UNPRIVILEGED → nesting allowed.
        assert!(uid_map_root_is_unprivileged("0 1000 1"));
        assert!(uid_map_root_is_unprivileged("0 100000 65536")); // --uid-range: 0 → a subuid
        assert!(uid_map_root_is_unprivileged("0 1000 1\n1 100000 65535")); // multi-row, 0 first

        // DANGEROUS: inner 0 → host 0 (a root-mapped box, e.g. a root-created pod holder). MUST refuse,
        // even though a caller euid check might have said "non-root". This is the whole point of the fix.
        assert!(!uid_map_root_is_unprivileged("0 0 1"));
        assert!(!uid_map_root_is_unprivileged("0 0 4294967295"));

        // Fail closed on anything we can't understand: inner-0 unmapped, empty, or malformed.
        assert!(!uid_map_root_is_unprivileged("1 100000 65536")); // inside-0 not covered
        assert!(!uid_map_root_is_unprivileged(""));
        assert!(!uid_map_root_is_unprivileged("garbage\nnot a map"));
        assert!(!uid_map_root_is_unprivileged("0 0")); // truncated line
    }
}

#[cfg(test)]
mod open_dev_pinned_tests {
    use super::open_dev_pinned;

    #[test]
    fn walks_dev_safely_and_refuses_traversal_and_symlinks() {
        // A real char device opens; the returned fd is valid.
        let fd = open_dev_pinned("/dev/null").expect("/dev/null opens");
        assert!(fd >= 0);
        unsafe { libc::close(fd) };
        // Absent node → None (fail-safe skip).
        assert!(open_dev_pinned("/dev/kern-nope-xyz-123").is_none());
        // `..` mid-path → refused, never traverses out of /dev.
        assert!(open_dev_pinned("/dev/../etc/passwd").is_none());
        // Not under /dev → refused outright.
        assert!(open_dev_pinned("/etc/passwd").is_none());
        // An INTERMEDIATE symlink is not followed: /dev/fd is a symlink to /proc/self/fd, so walking
        // `/dev/fd/0` must refuse at the `fd` hop (O_NOFOLLOW|O_DIRECTORY → ENOTDIR) rather than escape
        // to /proc. This is the by-construction closure of the deep-symlink TOCTOU.
        if std::fs::symlink_metadata("/dev/fd")
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            assert!(
                open_dev_pinned("/dev/fd/0").is_none(),
                "an intermediate symlink under /dev must not be followed"
            );
        }
    }
}

/// The uid-range note has two halves to its condition and each is a separate defect if dropped, so
/// the truth table is asserted rather than read.
///
/// It exists because an official image that `chown`s in its entrypoint dies on a host without
/// `newuidmap`, with an error of its own that names neither the uid range nor kern. Measured with
/// `nginx:alpine`: `chown nginx:nginx /tmp` succeeds with the range and returns
/// `chown: /tmp: Invalid argument` without it.
///
/// It is NOT emitted when the range was simply not wanted (`--no-uid-range`, or a `--rootfs` box),
/// which is the caller's own decision, and not when the box exited 0, which says the range was not
/// needed. Those two exclusions are the whole reason the fallback can stay silent everywhere else.
#[cfg(test)]
mod uid_range_hint_fires_only_when_it_is_information {
    use super::should_hint_uid_range;

    #[test]
    fn the_truth_table_is_exactly_one_of_four() {
        // The only combination that carries information: wanted, unavailable, and the box failed.
        assert!(
            should_hint_uid_range(true, 1),
            "unmet range + failure must speak"
        );
        assert!(
            should_hint_uid_range(true, 137),
            "any non-zero code, not just 1"
        );
        assert!(
            should_hint_uid_range(true, -1),
            "a signal-derived negative code is still a failure"
        );

        // Silent everywhere else, and each of these is a different reason.
        assert!(
            !should_hint_uid_range(true, 0),
            "the box succeeded, so it never needed the range: saying so would be noise on every \
             box start on a host without newuidmap, which is what the silent fallback avoids"
        );
        assert!(
            !should_hint_uid_range(false, 1),
            "the range was mapped or never wanted: this failure is the workload's own"
        );
        assert!(!should_hint_uid_range(false, 0), "nothing happened");
    }

    /// Both exit paths of `run_in_sandbox_with` must call it: the PTY path (`-it`) returns early and
    /// is easy to forget, which is this project's `derived-condition-duplicated` shape. Asserted on
    /// the source because the two returns cannot be funnelled into one without restructuring a
    /// function that forks.
    #[test]
    fn every_exit_path_of_the_sandbox_reports_it() {
        let src = include_str!("real.rs");
        // Split so the needle does NOT appear verbatim in this file: `include_str!` pulls in this
        // test too, and the first version counted its own search string as a third call site. It
        // then "passed" when a real call was deleted, which is a test that measures itself.
        let needle = concat!("hint_missing_uid_range", "(range_unmet, code);");
        let calls = src.matches(needle).count();
        assert_eq!(
            calls, 2,
            "run_in_sandbox_with has two returns that carry an exit code, the PTY one and the \
             waitpid one, and both must report. Found {calls} call sites."
        );
    }
}

#[cfg(test)]
mod box_start_exit_code_is_docker_aligned {
    use super::box_start_exit_code;
    use crate::Error;

    #[test]
    fn a_setup_failure_is_125_not_a_command_error() {
        // A setup failure (mount, uid map, seccomp, AppArmor, cgroup) means the BOX could not start:
        // Docker's 125, NOT a "command not found" (127) the operator would chase in their own argv.
        // This is the Grok #5 / deferred FIX-5 class - an unloaded `--apparmor` used to exit 127.
        assert_eq!(
            box_start_exit_code(&Error::Spec("--apparmor: profile not loaded".into())),
            125
        );
        assert_eq!(box_start_exit_code(&Error::Unsupported("no userns")), 125);
        assert_eq!(
            box_start_exit_code(&Error::Syscall(
                "mount",
                std::io::Error::from_raw_os_error(libc::EPERM)
            )),
            125,
            "a NON-execvp syscall failure is kern's setup, not the workload's command"
        );
    }

    #[test]
    fn the_workloads_own_command_failure_keeps_126_or_127() {
        // Only an `execvp` error is the workload's own command.
        assert_eq!(
            box_start_exit_code(&Error::Syscall(
                "execvp",
                std::io::Error::from_raw_os_error(libc::ENOENT)
            )),
            127,
            "ENOENT = command not found"
        );
        assert_eq!(
            box_start_exit_code(&Error::Syscall(
                "execvp",
                std::io::Error::from_raw_os_error(libc::EACCES)
            )),
            126,
            "EACCES = found but not executable (or an LSM transition denied)"
        );
        assert_eq!(
            box_start_exit_code(&Error::Syscall(
                "execvp",
                std::io::Error::from_raw_os_error(libc::ELOOP)
            )),
            127,
            "any other execvp errno falls back to not-found (127)"
        );
    }

    /// Both box-start error `_exit`s must route through the helper, not a hardcoded `_exit(127)` (the
    /// exact regression Grok #5 named). Asserted on the source, like the uid-hint call-site count,
    /// because the two exits live in forked children that cannot be funnelled into one.
    #[test]
    fn both_box_start_error_exits_use_the_helper_not_a_hardcoded_127() {
        let src = include_str!("real.rs");
        // Built via concat so the needle is not present verbatim in this test (else `include_str!`
        // counts its own search string, a test that measures itself).
        let needle = concat!("_exit(box_start_exit_code", "(&e))");
        assert_eq!(
            src.matches(needle).count(),
            2,
            "the run_init workload child and the direct box path must both use box_start_exit_code"
        );
    }
}

#[cfg(test)]
mod shm_and_mount_flag_gates {
    use super::*;

    #[test]
    fn shm_size_prefers_the_explicit_cap_and_falls_back_to_the_memory_one() {
        // An operator's `--shm-size` wins outright.
        assert_eq!(
            shm_size_for(Some(16 << 20), Some(256 << 20)),
            Some(16 << 20)
        );
        // Otherwise the memory cap, which is the number the cgroup already enforces: an unsized
        // `/dev/shm` reports half the HOST's RAM, which both leaks a host fact and misleads every
        // workload that sizes a buffer from `statvfs`.
        assert_eq!(shm_size_for(None, Some(256 << 20)), Some(256 << 20));
        // Nothing enforced anywhere means no honest number exists, so nothing is claimed.
        assert_eq!(shm_size_for(None, None), None);
        // Deliberately NOT Docker's fixed 64 MB: the fallback tracks the box, not a constant.
        assert_eq!(shm_size_for(None, Some(2 << 30)), Some(2 << 30));
    }

    #[test]
    fn the_mount_flag_map_never_smuggles_ms_remount() {
        // `statfs.f_flags` carries ST_VALID (0x20), which is numerically MS_REMOUNT. Copying the raw
        // word into a remount would add a flag nobody asked for, to the very syscall this feeds. The
        // guard is that the mapping is an explicit allowlist of bits, so assert the bit is not in it.
        const ST_VALID: libc::c_ulong = 0x0020;
        assert_eq!(
            ST_VALID,
            libc::MS_REMOUNT as libc::c_ulong,
            "the premise of this test: the two constants collide"
        );
        let mapped: libc::c_ulong = [
            libc::MS_RDONLY,
            libc::MS_NOSUID,
            libc::MS_NODEV,
            libc::MS_NOEXEC,
            libc::MS_SYNCHRONOUS,
            libc::MS_MANDLOCK,
            libc::MS_NOATIME,
            libc::MS_NODIRATIME,
            libc::MS_RELATIME,
        ]
        .iter()
        .fold(0, |a, b| a | *b as libc::c_ulong);
        assert_eq!(
            mapped & ST_VALID,
            0,
            "the preserved-flag set must not contain MS_REMOUNT/ST_VALID"
        );
    }

    #[test]
    fn current_mount_flags_reads_the_kernel_and_discriminates() {
        // A positive control for the reader itself: `/proc` is `nosuid,nodev,noexec` on every Linux
        // this runs on, and `/` is not, so a reader that returned a constant would fail one of the two.
        let open = |p: &str| -> libc::c_int {
            let c = cstr(p).expect("a literal path has no NUL");
            unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) }
        };
        let proc_fd = open("/proc");
        if proc_fd < 0 {
            return; // no /proc (a stripped container): the check has nothing to read, so it says nothing
        }
        let f = current_mount_flags(proc_fd);
        unsafe { libc::close(proc_fd) };
        assert_ne!(
            f & libc::MS_NOSUID as libc::c_ulong,
            0,
            "/proc is mounted nosuid; a reader that missed it would let a remount CLEAR the flag"
        );
        let root_fd = open("/");
        if root_fd >= 0 {
            let rf = current_mount_flags(root_fd);
            unsafe { libc::close(root_fd) };
            assert_ne!(f, rf, "the reader must discriminate: / and /proc differ");
        }
    }
}

#[cfg(test)]
mod loopback_tests {
    use super::*;

    /// Raise `lo` with our OWN ioctl, so the test can tell "this host refuses" from "the code did not
    /// work". Deliberately a second implementation rather than a call to the function under test: if
    /// this succeeds where `bring_loopback_up` failed, the failure is the code's and the test says so;
    /// if this fails too, the host cannot grant CAP_NET_ADMIN over a fresh net ns and there is nothing
    /// to measure, so the test skips with a reason instead of reporting a defect that is not there.
    fn raise_lo_directly() -> bool {
        unsafe {
            let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if s < 0 {
                return false;
            }
            let mut ifr: libc::ifreq = std::mem::zeroed();
            ifr.ifr_name[0] = b'l' as libc::c_char;
            ifr.ifr_name[1] = b'o' as libc::c_char;
            let ok = libc::ioctl(s, libc::SIOCGIFFLAGS as _, &mut ifr) == 0 && {
                ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
                libc::ioctl(s, libc::SIOCSIFFLAGS as _, &ifr) == 0
            };
            libc::close(s);
            ok
        }
    }

    /// Read `lo`'s IFF_UP in the CURRENT net namespace, independently of the function under test:
    /// `bring_loopback_up` must not be the instrument that reports on `bring_loopback_up`.
    fn lo_is_up() -> bool {
        unsafe {
            let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if s < 0 {
                return false;
            }
            let mut ifr: libc::ifreq = std::mem::zeroed();
            ifr.ifr_name[0] = b'l' as libc::c_char;
            ifr.ifr_name[1] = b'o' as libc::c_char;
            let ok = libc::ioctl(s, libc::SIOCGIFFLAGS as _, &mut ifr) == 0;
            let up = ok && ifr.ifr_ifru.ifru_flags & libc::IFF_UP as i16 != 0;
            libc::close(s);
            up
        }
    }

    /// The egress pump serves `127.0.0.1` in a net ns it joined from OUTSIDE, and it is handed the
    /// box's pid while the box's init is still setting up, so it cannot assume the init has raised
    /// `lo` yet. This pins the property the pump now relies on, in a REDUCED system: a fresh net ns,
    /// where `lo` is present, DOWN and address-less.
    ///
    /// What it asserts is `connect`, NOT `bind`, and that choice is the point. Whether a down loopback
    /// refuses the bind turns out to be kernel-dependent: measured with one C probe, 6.12.8+ fails it
    /// with EADDRNOTAVAIL while 7.0.0 accepts it and lets `listen` succeed too. Only the far side
    /// agrees across both, failing with ENETUNREACH either way. So this test pins the property that
    /// holds everywhere, and a successful bind is asserted here as NOT evidence of reachability -
    /// which is exactly why the pump treats a loopback it cannot raise as fatal rather than binding
    /// and reporting itself ready.
    ///
    /// The DOWN-and-unreachable state asserted first is this test's positive control. It proves the
    /// environment can still produce the failure the fix exists for, so a `bring_loopback_up` that
    /// did nothing would be caught here rather than passing on a loopback something else had raised.
    ///
    /// Runs entirely in a FORKED child: `unshare` moves the calling process, and cargo's test harness
    /// is multi-threaded, so doing this in-process would drag every other test into a new namespace.
    /// A host without unprivileged user namespaces cannot make the precondition, so it SKIPS rather
    /// than fails, and says which.
    #[test]
    fn a_down_lo_is_unreachable_on_every_kernel_and_bring_loopback_up_fixes_it_idempotently() {
        const SKIP: i32 = 99;
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            let rc = (|| -> i32 {
                if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
                    return SKIP; // no unprivileged userns here; nothing to measure
                }
                // POSITIVE CONTROL: the precondition the fix addresses is really present.
                if lo_is_up() {
                    return 10; // a fresh net ns with lo already up would invalidate the test
                }
                // On THIS kernel, does serving succeed while the loopback is down? 7.0 says yes and
                // 6.12 says no, and the fix must hold either way, so a refused bind is not a failure
                // of the test: it is the other kernel, and the reachability check below is skipped
                // because there is no listener to be unreachable. Everything after the fix still runs.
                let down_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).ok();
                let addr = match down_listener.as_ref().map(|l| l.local_addr()) {
                    Some(Ok(a)) => Some(a),
                    Some(Err(_)) => return 12,
                    None => None, // the bind was refused: this kernel fails earlier, nothing to probe
                };
                // Where the bind DID succeed, connecting to that same listening port must not: this is
                // the failure the box's workload would hit while the pump reported itself ready, and it
                // is the reason readiness cannot be defined as "bound".
                if let Some(a) = addr {
                    if std::net::TcpStream::connect(a).is_ok() {
                        return 13;
                    }
                }
                // THE FIX. A `false` here is not automatically a defect: this function is documented
                // best-effort, and a host that will not grant CAP_NET_ADMIN over a fresh net ns cannot
                // raise `lo` no matter what the code does. GitHub's runners are such a host - AppArmor
                // restricts the user namespace - and asserting success there turned this test red for
                // an environment rather than for a regression.
                //
                // So the environment is separated from the code with an INDEPENDENT attempt: the test
                // raises the flag itself, with its own ioctl, and only calls the failure a defect if
                // its own attempt would have worked. Same discriminant as the positive control above,
                // pointed the other way.
                if !bring_loopback_up() {
                    return if raise_lo_directly() { 14 } else { SKIP };
                }
                if !lo_is_up() {
                    return 15; // measured independently of the return value above
                }
                if let Some(a) = addr {
                    if std::net::TcpStream::connect(a).is_err() {
                        return 16; // the same port must now be reachable
                    }
                } else if std::net::TcpListener::bind(("127.0.0.1", 0)).is_err() {
                    return 16; // the kernel that refused the bind must now accept it
                }
                // IDEMPOTENT: the box's init calls this too, and either order must be a success.
                if !bring_loopback_up() || !lo_is_up() {
                    return 17;
                }
                0
            })();
            unsafe { libc::_exit(rc) };
        }
        let mut st = 0i32;
        assert!(unsafe { libc::waitpid(pid, &mut st, 0) } == pid, "waitpid");
        let code = (st >> 8) & 0xff;
        if code == SKIP {
            eprintln!(
                "skipped: this host cannot raise `lo` in a fresh net ns (no unprivileged user \
                 namespace, or no CAP_NET_ADMIN over it - GitHub runners restrict this via AppArmor)"
            );
            return;
        }
        assert_eq!(
            code, 0,
            "fresh-netns loopback check failed at step {code} (10..13 = the control itself broke, \
             14..17 = bring_loopback_up did not raise lo, or was not idempotent)"
        );
    }
}

#[cfg(test)]
mod cpu_topology_tests {
    use super::setup_cpu_topology;

    /// THE THREE FILES A MODERN ALLOCATOR READS, AND THE BOX'S OWN CPU SET IN THEM.
    ///
    /// A kern box mounts no `sysfs`, and recent tcmalloc fails a `CHECK` at startup when it cannot
    /// read the possible-CPU list: measured on the official `mongo:latest` image, which aborted
    /// before its first instruction. The experiment that made it a fact: the same image and box with
    /// these three files present got past the abort and failed on MongoDB's own kernel-version check.
    ///
    /// WITH A CPUSET, THE BOX IS TOLD ITS OWN SET, which is more truthful than Docker: there a capped
    /// container still reads the host's full list and sizes its thread pools for CPUs it will never
    /// be scheduled on.
    ///
    /// A VALUE THAT IS NOT A CPU LIST WRITES NOTHING. The files are parsed by an allocator, and a
    /// malformed range is the state this function exists to leave behind, not one to create.
    #[test]
    fn the_cpu_topology_reports_the_boxs_own_set_and_refuses_anything_that_is_not_a_range() {
        let root = std::env::temp_dir().join(format!("kern-cputop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::create_dir_all(&root);
        let read = |f: &str| -> Option<String> {
            std::fs::read_to_string(root.join("sys/devices/system/cpu").join(f)).ok()
        };

        // An explicit cpuset is what the box is told, in all three files.
        setup_cpu_topology(&root.to_string_lossy(), Some("0-1"));
        for f in ["possible", "present", "online"] {
            assert_eq!(read(f).as_deref(), Some("0-1\n"), "{f}");
        }

        // A list form, not just a range.
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::create_dir_all(&root);
        setup_cpu_topology(&root.to_string_lossy(), Some("0,2,4"));
        assert_eq!(read("possible").as_deref(), Some("0,2,4\n"));

        // Anything that is not a CPU list writes NOTHING rather than a file nothing can parse.
        for bad in ["0-1; rm -rf /", "all", "0-1\n0-2", "0 1"] {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::create_dir_all(&root);
            setup_cpu_topology(&root.to_string_lossy(), Some(bad));
            assert!(read("possible").is_none(), "must refuse {bad:?}");
        }

        // No cpuset: the host's own range, which is what an uncapped box may really run on. The
        // value is whatever this machine says, so the assertion is on the SHAPE, not the number.
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::create_dir_all(&root);
        setup_cpu_topology(&root.to_string_lossy(), None);
        let got = read("possible").unwrap_or_default();
        assert!(
            !got.trim().is_empty()
                && got
                    .trim()
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b'-' || b == b','),
            "an uncapped box still needs a readable range, got {got:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod loopback_alias_tests {
    use super::loopback_alias_label;
    use std::net::Ipv4Addr;

    /// THE LABEL IS KEYED BY THE ADDRESS, AND A COUNTER WOULD LOSE AN ADDRESS.
    ///
    /// `SIOCSIFADDR` sets the address OF A LABEL. Two boxes in one pod both writing `lo:0` would
    /// have the second REPLACE the first's address rather than add to it, and the first service
    /// would silently lose the address its file gave it. Keyed by the address, a repeat is
    /// idempotent and two addresses cannot collide.
    ///
    /// THE LENGTH IS THE OTHER HALF. An interface name is at most 15 characters, and a decimal
    /// label (`lo:255.255.255.255`) is 18. Hex is always 11.
    #[test]
    fn a_loopback_alias_label_is_unique_per_address_and_always_fits() {
        assert_eq!(
            loopback_alias_label(Ipv4Addr::new(172, 20, 0, 5)),
            "lo:ac140005"
        );
        assert_eq!(
            loopback_alias_label(Ipv4Addr::new(10, 5, 0, 100)),
            "lo:0a050064"
        );
        // The widest possible address still fits inside the kernel's 15-character limit.
        let widest = loopback_alias_label(Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(widest, "lo:ffffffff");
        assert!(widest.len() <= 15, "{widest} is {} chars", widest.len());
        // Two different addresses never share a label, including ones that differ only in an octet
        // a decimal rendering would run together (`1.2.3.4` vs `12.3.4` is not a thing here, but
        // `1.20.3.4` and `1.2.03.4` would be if the label were built by joining decimals).
        assert_ne!(
            loopback_alias_label(Ipv4Addr::new(1, 20, 3, 4)),
            loopback_alias_label(Ipv4Addr::new(12, 0, 3, 4))
        );
        // And the same address twice is the same label, which is what makes a repeat idempotent.
        assert_eq!(
            loopback_alias_label(Ipv4Addr::new(192, 168, 1, 1)),
            loopback_alias_label(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    /// THE ADD IS RETRIED, AND THAT IS A DECISION RATHER THAN A HABIT.
    ///
    /// Two boxes joining the same pod add their addresses to the same `lo` at the same time and the
    /// legacy label interface DROPS ONE: measured with two `kern box --pod` started in parallel,
    /// where only the later address survived, against the identical pair added one after the other,
    /// where both stuck. With the retry, three boxes started in parallel all keep their address, and
    /// a two-service compose stack reached the literal address three runs out of three.
    ///
    /// PINNED HERE BECAUSE NO UNIT TEST REACHES IT. Reproducing the race needs a private network
    /// namespace and two processes racing inside it, which a unit test in this crate cannot stand
    /// up; the evidence is the end-to-end runs above. What this asserts is that the retry is still
    /// there, so removing it is a deliberate act and not a silent one.
    // THE LINT IS EXACTLY WRONG HERE. `assertions_on_constants` exists to catch an assertion that
    // can never fail and therefore tests nothing. This one tests nothing about a RUN and everything
    // about a DECISION: it fails at the moment someone edits the constant, which is the only moment
    // that matters, and it fails with the reason the constant exists.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn the_alias_add_still_retries_because_a_concurrent_add_loses_one() {
        assert!(
            super::ATTEMPTS > 1,
            "a single attempt loses an address when two boxes join a pod at once"
        );
        // Long enough to outlast a racing add, short enough to be invisible next to a box start:
        // the whole budget is under a tenth of a second.
        assert!(super::ATTEMPTS as u64 * super::RETRY_MS <= 100);
    }
}

#[cfg(test)]
mod id_map_tests {
    use super::*;

    /// WHETHER OWNERSHIP CAN EXIST AT ALL, and the answer decides how a layer is unpacked.
    ///
    /// With a single-uid map there is exactly one identity in the namespace, so no file can belong to
    /// anyone else and `tar` must be told `--no-same-owner`. With a range, an image's uid 1000 lands
    /// on the caller's subuid base and a service that runs as that user can write its own directories
    /// (measured on `kibana:7.16.1`: `EACCES` before, writable after). A wrong answer here is either
    /// an extraction that fails on every chown, or one that silently keeps the old flattening.
    #[test]
    fn a_map_is_ranged_only_when_some_row_covers_more_than_one_id() {
        // The single-uid map kern writes when no subordinate range is available.
        assert!(!map_text_is_ranged("         0       1000          1\n"));
        // The ranged map a box gets: the second row is what makes it a range.
        assert!(map_text_is_ranged(
            "         0       1000          1\n         1     100000      65536\n"
        ));
        // A range on the FIRST row counts too: the shape is not fixed.
        assert!(map_text_is_ranged("0 100000 65536\n"));

        // AN UNPARSEABLE OR EMPTY MAP IS NOT A RANGE. That is the conservative direction: it keeps
        // `--no-same-owner`, which is what every host did before any of this. Reading it as a range
        // would make every layer fail on a chown that cannot succeed.
        assert!(!map_text_is_ranged(""));
        assert!(!map_text_is_ranged("garbage\n"));
        assert!(
            !map_text_is_ranged("0 1000\n"),
            "a row with no count column"
        );
        assert!(
            !map_text_is_ranged("0 1000 x\n"),
            "a count that is not a number"
        );
        // Count zero maps nothing and is not a range either.
        assert!(!map_text_is_ranged("0 1000 0\n"));
    }
}

#[cfg(test)]
mod pod_holder_watchdog_tests {
    use super::pod_holder_verdict;

    /// A HOLDER LETS ITS POD GO ONLY ON A DEFINITE, REPEATED ABSENCE.
    ///
    /// The holder keeps a pod's user and net namespaces alive. Releasing them while the pod is
    /// running takes the network away from every service in it, so the failure this guards is not
    /// "leaks a process" but "kills a live stack", and the arms are asserted one at a time.
    ///
    /// MEASURED end to end on the real thing, once, by hand: a pod created, its directory removed
    /// underneath it, and the holder gone within 70 seconds - two polls of 30. That measurement is
    /// not repeated in the suite, because a minute of sleeping per run buys nothing this function
    /// does not decide.
    #[test]
    fn a_pod_holder_releases_only_on_a_repeated_definite_absence() {
        let enoent = || Ok(false);
        let present = || Ok(true);
        let unreadable = || Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));

        // ONE absence is not enough: a directory can be replaced by a rename.
        assert_eq!(pod_holder_verdict(0, enoent()), (1, false));
        // TWO in a row is.
        assert_eq!(pod_holder_verdict(1, enoent()), (2, true));

        // THE DANGEROUS ARM. An unreadable directory is not a missing one, and it must reset the
        // count rather than advance it: a permission or I/O error on a live pod's directory would
        // otherwise be two strikes away from killing the stack.
        assert_eq!(pod_holder_verdict(1, unreadable()), (0, false));
        assert_eq!(pod_holder_verdict(0, unreadable()), (0, false));

        // And a directory that is there resets the count too, so an absence followed by a return
        // does not carry a strike forward.
        assert_eq!(pod_holder_verdict(1, present()), (0, false));
        assert_eq!(pod_holder_verdict(0, present()), (0, false));

        // THE COUNTER SATURATES. Wrapping would make a pod that has been gone for 256 polls look
        // freshly absent and immortal again, which is the bug this whole function exists to end.
        assert_eq!(pod_holder_verdict(u8::MAX, enoent()), (u8::MAX, true));
    }

    /// A NAMESPACE WITH MEMBERS IS NOT AN EMPTY ONE, AND THE HOLDER ASKS BEFORE IT RELEASES.
    ///
    /// THE CASE THIS EXISTS FOR, found in review: on a systemd host without `loginctl
    /// enable-linger`, logind removes `/run/user/<uid>` on the last logout while leaving the user's
    /// processes running. The pod's directory is then genuinely gone and the directory rule alone
    /// would release the namespaces of a stack that is still serving. Before the watchdog, a logout
    /// left such a stack with its network intact; that must not become a sixty-second fuse.
    ///
    /// BOTH DIRECTIONS, because either one alone is satisfied by a constant: a namespace holding
    /// only this process must answer false, or the orphan population the watchdog was written for is
    /// never reaped; a namespace holding one more must answer true, or the logout case is still
    /// live. Run in a child that unshares its own network namespace, because the test binary's own
    /// namespace is the machine's and shares it with everything.
    #[test]
    fn a_holder_sees_whether_anything_else_is_in_its_network_namespace() {
        // SAFETY: fork in a test binary; the child only unshares, forks, reads /proc and exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            let code = || -> i32 {
                // SAFETY: unshare on the freshly forked child.
                if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
                    return 10; // no unprivileged user namespaces on this host
                }
                let _ = std::fs::write("/proc/self/setgroups", b"deny");
                let _ = std::fs::write("/proc/self/uid_map", b"0 0 1");
                // ALONE: this process is the only one in the namespace it just made.
                if super::this_netns_has_other_processes() {
                    return 11;
                }
                // SAFETY: fork from the same single-threaded child; the grandchild stays in this
                // network namespace and sleeps until it is killed.
                let member = unsafe { libc::fork() };
                if member < 0 {
                    return 12;
                }
                if member == 0 {
                    // SAFETY: the grandchild waits to be killed and touches nothing shared.
                    unsafe {
                        libc::sleep(30);
                        libc::_exit(0);
                    }
                }
                // NOT ALONE any more, and the answer must change.
                let answer = super::this_netns_has_other_processes();
                // SAFETY: the grandchild is this process's own child.
                unsafe {
                    libc::kill(member, libc::SIGKILL);
                    let mut st = 0i32;
                    libc::waitpid(member, &mut st, 0);
                }
                i32::from(!answer) * 13
            }();
            // SAFETY: exiting the forked child without running the parent's atexit handlers.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0i32;
        // SAFETY: waiting on the child just forked.
        assert!(
            unsafe { libc::waitpid(pid, &mut status, 0) } == pid,
            "waitpid"
        );
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        if code == 10 {
            eprintln!("skipping: this host does not allow unprivileged user namespaces");
            return;
        }
        assert_ne!(
            code, 11,
            "a namespace holding only this process must answer FALSE, or a pod whose boxes are all \
             gone is never reaped and the watchdog does nothing"
        );
        assert_ne!(
            code, 13,
            "a namespace holding one more process must answer TRUE, or a logout that removes the \
             runtime directory releases the network of a stack that is still serving"
        );
        assert_eq!(code, 0, "the probe failed for another reason (12 = fork)");
    }
}
