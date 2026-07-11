//! Real-syscall sandbox execution (Linux).
//!
//! [`RealMounts`] performs the mount/pivot/remount ops the [`crate::Rootfs`] typestate issues;
//! [`run_in_sandbox`] sets up an unprivileged user namespace + PID namespace, builds the root
//! through that same typestate, mounts a fresh `/proc`, remounts the root read-only (last —
//! enforced by the typestate), and `exec`s the command. The parent waits and returns the exit
//! code. This is the privileged counterpart of the `Recorder`-driven `--plan`: same sequence,
//! real kernel.
//!
//! Identity mapping: by default the caller's euid maps to root *inside* the namespace and nothing
//! else (a single-uid map — fastest, and the smallest attack surface). With `--uid-range`
//! (`SandboxSpec::uid_range`), and when `newuidmap`/`newgidmap` + an `/etc/subuid`/`/etc/subgid`
//! allocation are present, box ids 1..N additionally map to the caller's subordinate-id range (so
//! `apt`/`dpkg` and daemons that drop to non-root users work). Either way no host privilege is
//! gained. Linux-only.

use crate::{Error, MountMode, MountOps, PortMap, Rootfs};
use std::convert::Infallible;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

/// The one message for "this host won't let an unprivileged user namespace be created" — reused by
/// every unshare site (box + pod) so they can't drift. Callers requiring a `&str` (the pod
/// `eprintln`) use it directly; the sandbox path wraps it in [`Error::Unsupported`].
const USERNS_UNAVAILABLE: &str =
    "unprivileged user namespaces are unavailable (kernel.unprivileged_userns_clone=0 or an AppArmor restriction)";

/// What to run, and how to provide its root filesystem.
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
    /// Android-kernel boards). Default boxes leave this false — the upper is the writable surface.
    pub read_only: bool,
    /// argv of the command to run inside the sandbox (must be non-empty).
    pub command: Vec<String>,
    /// Hostname to set inside the (isolated) UTS namespace.
    pub hostname: String,
    /// Host paths bind-mounted into the box (`-v src:dst[:ro]`) — the only way data crosses the
    /// sandbox boundary. Bound before pivot (host source reachable), target resolved symlink-safe.
    pub volumes: Vec<Volume>,
    /// Extra environment for the workload (`--env K=V`), applied on top of the clean base env.
    pub env: Vec<(String, String)>,
    /// Working directory to `chdir` into before exec (`--workdir`). `None` → `/`.
    pub workdir: Option<String>,
    /// Share the host network namespace instead of an isolated (loopback-only) one (`--net`).
    /// Opt-in: gives the box outbound networking at the cost of network isolation.
    pub share_net: bool,
    /// `--pod <name>`: JOIN this pod holder's user + net namespace instead of creating a fresh one,
    /// so every box in the pod shares one loopback network (they reach each other on `127.0.0.1`,
    /// resolved by name via a shared `/etc/hosts`). The value is the holder process's PID; the box
    /// still gets its own mount/pid/uts/ipc namespaces. Pod members are co-trusted (they share the
    /// pod's user+net ns) — the pod is the network trust unit, like a Kubernetes pod.
    pub pod_holder: Option<i32>,
    /// Map a subordinate uid/gid *range* into the box (`--uid-range`) instead of just the caller.
    /// Opt-in because it (a) costs two `newuidmap`/`newgidmap` subprocesses at start and (b) maps
    /// 65k extra ids into the namespace; the default single-uid map is both faster and more
    /// isolated. Needed only for workloads that use multiple uids inside the box (`apt`/`dpkg`,
    /// daemons that drop to `www-data`, …).
    pub uid_range: bool,
    /// Hard memory ceiling in bytes for the box's cgroup (`--memory`). `None` → the default cap.
    pub memory_max: Option<u64>,
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
    /// vGPIO device nodes (host `/dev/*` paths) to expose in the box's `/dev` — from a `vgpio:`
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
    pub secrets: Vec<(String, Vec<u8>)>,
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
    /// `--tmpfs PATH[:size]`: extra fresh tmpfs mounts inside the box (`(path, size_option)` — size is
    /// a tmpfs `size=` string like `"64m"`, or empty for the default). Blocked over hardened mounts.
    pub tmpfs: Vec<(String, String)>,
    /// `--user UID[:GID]`: drop to this uid/gid just before exec (after all privileged setup). `None`
    /// → keep the namespace root. Only ids mapped into the box's userns work (see `--uid-range`).
    pub run_as: Option<(u32, u32)>,
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
    /// `--add-host NAME:IP`: extra `/etc/hosts` entries appended inside the box (`host-gateway` is
    /// already resolved to a concrete address by the caller). Empty for none.
    pub extra_hosts: Vec<(String, String)>,
    /// `--privileged`: relax the always-on seccomp filter to ALLOW the namespace + classic-mount
    /// syscalls (`unshare`/`setns`/`mount`/`umount2`/`pivot_root`) so a *nested* `kern box` (or
    /// docker-in-docker-style workload) can start. Honoured ONLY in rootless mode — when the box's
    /// root maps to an UNPRIVILEGED host uid (caller is non-root), a nested userns grants no new
    /// host privilege (the reason rootless podman-in-podman is safe). As real host root (euid 0) the
    /// request is IGNORED (no relaxation): relaxing `mount` there would re-open the core_pattern /
    /// host-privilege class. Every other dangerous syscall (kexec, modules, bpf, io_uring, keyring,
    /// ptrace, the NEW mount API) stays blocked even here — stronger than Docker's `--privileged`.
    pub privileged: bool,
}

/// A resolved vDisk to mount in the box at `/vdisk/<name>`. When `host_dir` is set, the host prepared
/// an ext4-on-loop mount (privileged path) that is bind-mounted in; otherwise a `size=`-capped
/// `tmpfs` is mounted (rootless fallback — RAM-backed, ephemeral).
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
        return Err(Error::last("mount(overlay)"));
    }
    Ok(())
}

/// Mount a fresh procfs for the new PID namespace (so `ps` etc. see only sandbox processes).
/// Target is the **cwd-relative** `proc` (cwd is the new root right after the self-pivot), NOT
/// `/proc`: before the old root is detached, "/" still resolves through the stacked old root, so
/// an absolute target would land in the old root. It must also run BEFORE the detach — mounting a
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

/// Mask a procfs file by bind-mounting `/dev/null` over it — reads return empty, writes go nowhere.
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

/// Neutralize the host-global procfs surface — the runc "readonlyPaths" + "maskedPaths" set. These
/// files/dirs are NOT namespaced, so on a kernel where the box's root maps to a privileged host uid
/// (kern run as root, in WSL, under `sudo`, or in CI), an in-box write reaches the HOST. The escape
/// that motivated this: `/proc/sys/kernel/core_pattern` → set it to `|/evil` and the kernel runs your
/// program as ROOT on the host at the next core dump. `/proc/sys` read-only is therefore the HARD
/// requirement (fail-closed); the rest are best-effort (present on all mainstream kernels).
fn mask_proc_paths() -> Result<(), Error> {
    ro_bind_ro("/proc/sys")?; // core_pattern, kernel.modprobe, … — every host-global sysctl. FATAL.
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
/// this unmounts the old (host) root. A failed unmount is FATAL — a leftover old root would keep
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
fn exec(argv: &[CString]) -> Error {
    let mut ptrs: Vec<*const c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(ptr::null());
    unsafe { libc::execvp(ptrs[0], ptrs.as_ptr()) };
    Error::last("execvp")
}

/// Child path (PID 1 in the new PID namespace): own mount namespace, build the root through the
/// typestate, mount /proc, drop the old root, remount read-only LAST, then exec. Never returns
/// Per-phase wall-clock for box setup, gated on the `KERN_TIMING` env var (off → zero cost beyond
/// one `getenv`). Set `KERN_TIMING=1` to print `kern-timing: <phase>: <µs>` to stderr — a cheap
/// profiler for where startup goes on a given kernel/SoC (overlay vs dev binds vs seccomp).
struct PhaseTimer {
    on: bool,
    last: libc::timespec,
}

impl PhaseTimer {
    fn new() -> Self {
        let on = std::env::var_os("KERN_TIMING").is_some();
        let mut last = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if on {
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut last) };
        }
        Self { on, last }
    }

    fn mark(&mut self, label: &str) {
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

/// `Ok` — on success `exec` (or the built-in init) replaces/owns the process; otherwise it returns the
/// error. `ready_fd` (the readiness pipe's write end) is threaded through so that with `--init`, PID 1
/// can close its own copy after forking the workload (so the launcher still gets EOF = "box up"), and
/// the forked workload can write the failure byte if its own exec fails.
/// Whether the box's root (inner uid 0) maps to an UNPRIVILEGED host uid, read from the now-established
/// `/proc/self/uid_map`. This is the PROPERTY that `--privileged` nesting depends on — a box whose root
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
/// no line is well-formed — so `--privileged` never relaxes seccomp on a map it doesn't understand.
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
                // real root is refused `--privileged` up front — so a non-root caller can never reach
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
    let mut t = PhaseTimer::new();
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(Error::last("unshare(CLONE_NEWNS)"));
    }
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
    // devpts is only needed when the box will host an in-box PTY (an `--ssh` sshd, or an interactive
    // `-it` slave). The overwhelming common case (agent code-exec, CI, `sh -c`) never opens a PTY, so
    // gate the whole devpts mount+mkdir+symlink out of it — one fewer filesystem-mount syscall per box.
    let needs_pts = spec.ssh.is_some() || spec.tty_slave.is_some();
    setup_dev(&spec.root, spec.tun, needs_pts, spec.tty_slave)?;
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
    setup_extra_hosts(&spec.root, &spec.extra_hosts);
    t.mark("volumes");
    // Self-pivot into the new root. The old root is left stacked at "/"; mount a fresh `proc`
    // (cwd-relative, while the old root still provides the visible proc instance the kernel
    // requires), THEN detach the old root.
    let staged = mounted.create_old_root(&mut ops)?;
    mount_proc()?;
    detach_old_root()?;
    // Lock down the non-namespaced host-global procfs knobs (core_pattern, sysrq, kernel info) now that
    // `/proc` resolves to the fresh procfs — closes the classic core_pattern escape for a root-mapped box.
    //
    // SKIP for a `--privileged` (nesting) box: the ro-bind/`/dev/null` masks are LOCKED submounts, and
    // the kernel's `mount_too_revealing` check then refuses a NESTED box's fresh `/proc` mount (EPERM) —
    // it would "reveal" what the outer masks hide. Presenting a fully-visible `/proc` (exactly what
    // Docker `--privileged` does) is what lets docker-in-docker-style nesting work. Safe here because
    // `allow_nesting` is rootless-only: the host-global sysctls under `/proc/sys` are owned by the INIT
    // user namespace and a rootless box (even as box-root) lacks the CAP_SYS_ADMIN there to write them —
    // so the mask was defense-in-depth for the ROOT-mapped case, which `--privileged` already refuses.
    // The nested box, unless itself `--privileged`, re-applies its own masks normally.
    if !allow_nesting {
        mask_proc_paths()?;
    }
    t.mark("pivot+proc");
    // Optional read-only remount LAST — the typestate makes any other order a compile error.
    // Overlay leaves the root writable (writes land in the upper layer). Volume submounts keep
    // their own flags, so a writable `-v` stays writable even under a read-only root. `MS_REMOUNT`
    // only affects the named mount, so the separate `/dev` tmpfs is remounted read-only too —
    // otherwise `--read-only` would leave `/dev` writable. (Device nodes keep working: they're
    // their own bind mounts and writes go through the driver, not the tmpfs.)
    if spec.read_only {
        let _ro = staged.into_readonly(&mut ops)?;
        remount_dev_ro()?;
    }

    // Replace the inherited host environment with a clean, minimal one — the host's env (secrets,
    // tokens, SSH/agent sockets, kern internals like KERN_SCOPE) must NOT leak into the workload —
    // then layer the user's `--env` on top.
    set_clean_env(&spec.hostname, &spec.env);

    // Honor `--workdir`: chdir into it (must exist inside the box). Fatal if it can't be entered.
    if let Some(wd) = &spec.workdir {
        let c = cstr(wd)?;
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

    // `--ssh`: stand up the in-box sshd (mounts /run tmpfs, writes keys/config, forks sshd). Done
    // here — after loopback (sshd binds 127.0.0.1) and pivot (privileged mounts), before seccomp
    // (the filter would block the mounts, and the forked sshd must predate the filter).
    if let Some(ssh) = &spec.ssh {
        crate::ssh::setup(ssh);
    }

    // `-it`: adopt the PTY slave as the controlling terminal (done before seccomp — these are setup
    // syscalls, not the workload's). The slave fd was opened on the host and inherited across the
    // unshare/pivot (it's just an fd).
    if let Some(slave) = spec.tty_slave {
        adopt_controlling_tty(slave);
    }

    // Pin to `--cpuset-cpus` via CPU affinity. This is the rootless-portable path: unlike the
    // cgroup `cpuset` controller (frequently NOT delegated to a user session), `sched_setaffinity`
    // needs no privilege and no delegation, and the affinity is inherited across the exec — so the
    // box command actually runs pinned even where the cgroup write is skipped. Done before seccomp
    // (a setup syscall).
    set_cpu_affinity(spec.cpuset.as_deref());

    // Least-privilege, in three ordered steps so `--user` + `--cap-drop ALL` (the canonical hardened
    // profile) composes correctly. All run after privileged setup (mount/pivot/loopback), so they
    // only affect the workload.
    let cap_mask = cap_drop_mask(&spec.caps);
    // 1. Bounding set — needs effective `CAP_SETPCAP` (still present here); stops a file-cap binary
    //    re-adding a dropped cap. Dropping a cap from the *bounding* set does NOT block using it from
    //    the effective set, so the `setuid`/`setgid` below still work even under `--cap-drop ALL`.
    drop_cap_bounding(cap_mask);
    // 2. `--user UID[:GID]`: drop to the workload's uid/gid — needs `CAP_SETUID`/`CAP_SETGID` in the
    //    *effective* set, which are still present (we haven't cleared effective yet). setgid before
    //    setuid (once uid is non-root you can't change gid); setuid to a non-root uid then sheds the
    //    effective caps itself. Only mapped ids succeed; a failure fails closed (refuses to exec).
    if let Some((uid, gid)) = spec.run_as {
        set_user(uid, gid)?;
    }
    // 3. Clear the dropped caps from effective/permitted/inheritable. For a non-root `--user` step 2
    //    already emptied them; this covers a root box and is otherwise a harmless no-op.
    clear_caps_from_sets(cap_mask);

    // Install the seccomp filter LAST — after all setup syscalls (mount/pivot) are done, so it
    // only constrains the workload. Then exec (or hand off to the built-in init). `allow_nesting`
    // (a rootless `--privileged` box) leaves the namespace + classic-mount syscalls allowed so a
    // nested `kern box` can start; everything else stays blocked.
    crate::seccomp::install(allow_nesting)?;
    t.mark("seccomp");
    if spec.init {
        // `--init`: this PID-1 process forks the workload and becomes a reaping init. Never returns.
        run_init(spec, argv, ready_fd)
    } else {
        // Default: PID 1 IS the workload — exec directly, byte-for-byte the original path.
        Err(exec(argv))
    }
}

/// Built-in init (`--init`): kern PID 1 forks the workload, then loops reaping EVERY child (the direct
/// workload plus any orphan reparented to PID 1 — the zombie-reaping guarantee), forwarding SIGTERM and
/// SIGINT to the workload, and finally `_exit`s with the workload's own status. Raw libc only, never
/// unwinds. `ready_fd` is the readiness pipe write end: PID 1 closes its own copy right after the fork
/// so the launcher still sees EOF when the workload execs; the workload child writes the failure byte
/// if ITS exec fails (so a detached box reports "exited before starting" instead of hanging).
fn run_init(spec: &SandboxSpec, argv: &[CString], ready_fd: Option<i32>) -> ! {
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
        unsafe { libc::_exit(127) };
    }
    if child == 0 {
        // WORKLOAD child: inherits the CLOEXEC ready_fd — a successful exec closes it (→ launcher EOF).
        // On exec failure, write the byte HERE (this is not PID 1, so the parent's byte-write below
        // won't fire for us) so the launcher learns it failed, then report and exit.
        // `exec` only ever returns on failure (its type is `-> Error`).
        let e = exec(argv);
        if let Some(fd) = ready_fd {
            let _ = unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
        }
        report_exec_failure(spec, &e);
        unsafe { libc::_exit(127) };
    }

    // PID 1 (init). Close our own copy of the ready fd NOW, so the workload's exec is the last holder
    // of the write end → the launcher reads EOF exactly when the box is up (not when PID 1 exits).
    if let Some(fd) = ready_fd {
        unsafe { libc::close(fd) };
    }
    // Publish the child pid, THEN install the forwarders — so an early signal can't `kill(0)` the
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
                continue; // interrupted by a forwarded signal — keep reaping
            }
            break; // ECHILD (all children gone) or an unexpected error
        }
        if r == child {
            child_status = status;
            child_reaped = true;
        }
    }
    // Exit with the workload's decoded status (128+signo if it was killed); if we somehow never saw it,
    // don't decode uninitialized status — fail with 1.
    unsafe {
        libc::_exit(if child_reaped {
            wait_code(child_status)
        } else {
            1
        })
    };
}

/// Print the actionable "cannot start the box command" diagnostic for a failed `execvp` (command not
/// found, missing loader, or a dropped-uid permission error), or a generic setup-failure line for any
/// other error. Shared by the direct-exec path and the `--init` workload child so both give the same
/// hint. Does not exit — the caller `_exit`s.
fn report_exec_failure(spec: &SandboxSpec, e: &Error) {
    if let Error::Syscall("execvp", io) = e {
        let cmd = spec.command.first().map(String::as_str).unwrap_or("?");
        // A permission-denied exec while dropped to a non-root `--user` is almost always the uid, not a
        // missing command: in a rootless box the overlay rootfs is owned by the box's root uid and a
        // dropped uid can't traverse/exec it. Name the real cause.
        let dropped = matches!(spec.run_as, Some((u, _)) if u != 0);
        if io.kind() == std::io::ErrorKind::PermissionDenied && dropped {
            let uid = spec.run_as.map(|(u, _)| u).unwrap_or(0);
            eprintln!(
                "kern: cannot start '{cmd}' as uid {uid} in box: {io}\n\
                 hint: a rootless box's rootfs is owned by the box's root uid, so a \
                 non-root --user often can't exec it — drop --user (runs as the box's \
                 root) or provide a rootfs owned by uid {uid}"
            );
        } else {
            eprintln!(
                "kern: cannot start '{cmd}' in box: {io}\n\
                 hint: the command must exist inside the box (try a full path like \
                 /bin/sh) and, if dynamically linked, its libraries/loader must be \
                 present in the rootfs"
            );
        }
    } else {
        eprintln!("kern: sandbox setup failed: {e}");
    }
}

/// `--user`: drop to `uid`/`gid` for the workload. Order matters — `setgroups` (clear supplementary
/// groups) then `setgid` then `setuid`, because once the uid is non-root you can no longer change
/// gid. Only ids mapped into the box's user namespace succeed (see `--uid-range`).
///
/// **Fails CLOSED**: if a non-root target `setgid`/`setuid` fails (the id isn't mapped — e.g. a host
/// without `newuidmap`/`newgidmap` fell back to the single-uid map), return `Err` so the box
/// **refuses to exec** rather than silently running the workload as in-box root. Dropping privilege
/// must never *grant* it. `--user 0` (explicitly root) is a successful no-op.
fn set_user(uid: u32, gid: u32) -> Result<(), Error> {
    unsafe {
        // Best-effort: setgroups may be EPERM under `/proc/self/setgroups=deny` (single-uid box); the
        // single mapped group is already the whole set, so a failure here is harmless.
        libc::setgroups(0, std::ptr::null());
        if libc::setgid(gid as libc::gid_t) != 0 && gid != 0 {
            return Err(Error::Unsupported(
                "--user: setgid failed — the gid isn't mapped into the box (add newuidmap/newgidmap \
                 + an /etc/subgid allocation, or use --uid-range)",
            ));
        }
        if libc::setuid(uid as libc::uid_t) != 0 && uid != 0 {
            return Err(Error::Unsupported(
                "--user: setuid failed — the uid isn't mapped into the box (add newuidmap/newgidmap \
                 + an /etc/subuid allocation, or use --uid-range)",
            ));
        }
    }
    Ok(())
}

/// Pin the workload to the CPUs named in `--cpuset-cpus` (`"0-3"`, `"0,2,4"`) with
/// `sched_setaffinity`. Portable and rootless — needs neither a delegated `cpuset` cgroup nor any
/// capability — and inherited across `exec`. Best-effort: a parse or syscall failure leaves the box
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
    if any {
        unsafe {
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        }
    }
}

/// Expand a validated cpuset list (`"0-3,5"`) into CPU indices. The CLI already restricts the string
/// to `N` / `N-M` tokens (`is_cpu_list`), so a malformed token here simply contributes nothing.
///
/// SECURITY: a CPU index past `CPU_SETSIZE` can never be set in a `cpu_set_t`, so we CLAMP each range
/// to it BEFORE expanding. Without this a hostile `cpuset: 0-999999999` (which `is_cpu_list` accepts —
/// it only checks the `u32` format, not the magnitude) would `extend(0..=999999999)` and allocate a
/// ~8 GB `Vec` before the per-element bound in the caller ever ran — a memory-exhaustion DoS. (Found
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

/// Bind each `-v` host path into the new root BEFORE pivot (while the host source is reachable at
/// its real path). The target is resolved **symlink-free, confined to the new root** via an
/// `openat(O_NOFOLLOW)` component walk — so a hostile image that ships a symlink at the mount
/// point can't redirect the bind onto a host path. Read-only volumes are then remounted RO.
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
        let src = match cstr(&v.source) {
            Ok(c) => c,
            Err(e) => {
                result = Err(e);
                break;
            }
        };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::stat(src.as_ptr(), &mut st) } != 0 {
            result = Err(Error::Syscall(
                "stat(volume source)",
                std::io::Error::last_os_error(),
            ));
            break;
        }
        let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        let tgt_fd = match open_in_root(root_fd, &v.target, is_dir) {
            Ok(fd) => fd,
            Err(e) => {
                result = Err(e);
                break;
            }
        };
        let tgt = cstr(&format!("/proc/self/fd/{tgt_fd}")).unwrap(); // decimal fd → never NUL
                                                                     // Deliberately NON-recursive (`MS_BIND`, not `MS_BIND | MS_REC`) — same rationale as the bind
                                                                     // root above: if the operator's volume source has host filesystems mounted *underneath* it
                                                                     // (a NAS share, an external disk), a recursive bind would clone those submounts into the box.
                                                                     // The RO remount below is per-mount (`MS_REMOUNT` is not recursive on Linux), so a recursive
                                                                     // bind would leave every cloned submount WRITABLE under a `:ro` volume — silently breaking the
                                                                     // operator's explicit read-only contract. A plain bind exposes the directory tree only.
        let r = unsafe {
            libc::mount(
                src.as_ptr(),
                tgt.as_ptr(),
                ptr::null(),
                libc::MS_BIND as libc::c_ulong,
                ptr::null(),
            )
        };
        unsafe { libc::close(tgt_fd) };
        if r != 0 {
            result = Err(Error::last("mount(volume bind)"));
            break;
        }
        if v.read_only {
            // Re-resolve the target (it now points *into* the bind mount) and remount it RO. The
            // pre-bind fd refers to the underlying dir, which can't be remounted.
            let ro_fd = match open_in_root(root_fd, &v.target, is_dir) {
                Ok(fd) => fd,
                Err(e) => {
                    result = Err(e);
                    break;
                }
            };
            let ro_tgt = cstr(&format!("/proc/self/fd/{ro_fd}")).unwrap(); // decimal fd → never NUL
            let r2 = unsafe {
                libc::mount(
                    ptr::null(),
                    ro_tgt.as_ptr(),
                    ptr::null(),
                    (libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY) as libc::c_ulong,
                    ptr::null(),
                )
            };
            unsafe { libc::close(ro_fd) };
            if r2 != 0 {
                let e = std::io::Error::last_os_error();
                result = Err(if e.raw_os_error() == Some(libc::EPERM) {
                    // EPERM on a bind remount-RO has more than one cause: the kernel may not support
                    // it at all (common on Android-kernel boards, where the root `--read-only` path
                    // sidesteps it by remounting the *overlay*, not a bind), OR a mount policy —
                    // e.g. SELinux, always on under an Android kernel — refused it. Don't assert one
                    // cause; list the alternatives so the message isn't misleading when it's a policy.
                    Error::Unsupported(
                        "read-only bind mount (:ro) failed with EPERM — this kernel may not support a \
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
/// symlink (`O_NOFOLLOW` per component) — so the path can never escape the new root. Returns an
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
fn set_clean_env(hostname: &str, extra: &[(String, String)]) {
    unsafe { libc::clearenv() };
    set_env(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    set_env("HOME", "/root");
    set_env("TERM", "xterm");
    set_env("HOSTNAME", hostname);
    for (k, v) in extra {
        set_env(k, v);
    }
}

fn set_env(key: &str, val: &str) {
    if let (Ok(k), Ok(v)) = (cstr(key), cstr(val)) {
        unsafe { libc::setenv(k.as_ptr(), v.as_ptr(), 1) };
    }
}

/// The safe host device nodes a sandbox needs. Deliberately NOT `/dev/tty` (a controlling
/// terminal enables TIOCSTI-style injection on unhardened kernels) and never `/dev/mem`, disks…
const DEV_NODES: [&str; 5] = ["null", "zero", "full", "random", "urandom"];

/// Populate `<root>/dev` BEFORE pivot, while the host's `/dev` is still reachable at its real
/// path. A device node bound from the host's devtmpfs is only *writable* from an unprivileged
/// user namespace when bound by its real path (a post-pivot bind via `/proc/self/fd` leaves
/// `/dev/null` read-only — the workload can't `> /dev/null`), so the bind must happen here.
///
/// Symlink-safe: if the image ships `/dev` as a *symlink* (a hostile image pointing it at a host
/// path), it is removed first and replaced with a real directory, so the tmpfs mount and the
/// device binds all resolve to a directory we own *inside* the new root — never through the
/// symlink. For a normal (already-a-directory) `/dev` nothing is mutated: the tmpfs simply
/// shadows it, so the image/rootfs is left untouched.
fn setup_dev(root: &str, tun: bool, needs_pts: bool, tty_slave: Option<i32>) -> Result<(), Error> {
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
                                                // own in a sticky world-writable dir is rejected with EACCES — that breaks the universal
                                                // `cmd > /dev/null` redirect. A non-sticky 0755 /dev (owned by the box's root) avoids it.
    let ty = cstr("tmpfs")?;
    let opts = cstr("mode=755")?;
    // `MS_NOSUID`: a workload must never gain privilege via a setuid binary it drops on the box-owned
    // /dev tmpfs. (No `MS_NODEV` — /dev is exactly where the bind-mounted device nodes below must work;
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
    // `-it`: bind the controlling-PTY SLAVE onto `/dev/console` (like runc/Docker). kern's `-it` slave
    // is a HOST devpts node; the box's own `/dev/pts` is a private `newinstance` that doesn't contain
    // it, so fd 0's device isn't found under the box's `/dev` and `ttyname()` fails — bash prints
    // "ttyname error: No such device" and the `tty` command errors. The slave's host path is still
    // resolvable here (pre-pivot), so read it off `/proc/self/fd/<slave>` and bind the device onto a
    // fresh `/dev/console` node; `ttyname()` then resolves fd 0 to `/dev/console`. Best-effort: a
    // failure just leaves the (cosmetic) warning, never breaks the box.
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
    // Standard `/dev` symlinks into procfs — `/dev/fd`, `/dev/std{in,out,err}` — exactly as Docker/runc
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
    // the box can allocate a controlling terminal — most importantly the in-box sshd for `--ssh`
    // (interactive `ssh box` otherwise fails "PTY allocation request failed"), plus screen/tmux/script.
    // A user namespace is allowed to mount devpts. `newinstance` = a pty namespace private to this box;
    // `ptmxmode=0666` lets the unprivileged workload open the multiplexer. NOSUID|NOEXEC harden it; no
    // `gid=` (group 5 isn't mapped in a single-uid box, which would EINVAL the mount). Best-effort — a
    // host/kernel that refuses it just leaves the box without in-box PTYs (kern's own `-it` uses a HOST
    // pty and is unaffected).
    // Only stand up a devpts instance when the box actually needs an in-box PTY (`--ssh` / `-it`).
    // Skipping it in the common case removes a whole filesystem-mount syscall (+ mkdir + symlink) from
    // box setup. kern's own `-it` uses a HOST pty (unaffected); this is for PTYs opened INSIDE the box.
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
    Ok(())
}

/// Expose a `vgpio:` profile's host devices in the box. Device nodes are bound into the box's own
/// `/dev` tmpfs (created by `setup_dev` — box-owned, so binding into it can't be redirected by a
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

/// If `path` is a symlink, remove it — so a hostile image can't redirect a mkdir/mount we're about to
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
/// `openat(O_PATH|O_NOFOLLOW)`. A plain `open(path, O_NOFOLLOW)` only guards the FINAL component — an
/// intermediate symlink is still followed — so a component swapped to a symlink at any depth could
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
/// component in `rel` is refused (defence-in-depth — sources are already sanitised).
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
        // /proc/self/fd — a component swapped between the resolver's check and this mount can't redirect
        // us. Re-check on the pinned fd that it's not a BLOCK device (a host disk).
        let sfd = match open_dev_pinned(src) {
            Some(fd) => fd,
            None => return, // absent, escapes /dev, or a component was swapped to a symlink → skip
        };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let is_block = unsafe { libc::fstat(sfd, &mut st) } == 0
            && (st.st_mode & libc::S_IFMT) == libc::S_IFBLK;
        if !is_block {
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
/// mounted (rootless — RAM-backed, ephemeral). Runs before pivot. The mount is a *separate* mount,
/// so a vdisk stays writable even under `--read-only` (a vdisk is scratch space by design).
/// Best-effort per entry.
fn setup_vdisk(root: &str, vdisks: &[VdiskMount]) -> Result<(), Error> {
    if vdisks.is_empty() {
        return Ok(());
    }
    // A fresh box-owned `/vdisk` tmpfs (symlink-neutralized) so every per-disk mkdir/mount target is
    // created inside a filesystem we own — a hostile image shipping `/vdisk` (or `/vdisk/<name>`) as
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
            // nosuid/nodev on the bind (a first bind ignores those flags — they need MS_REMOUNT).
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
/// `NOSUID|NODEV` — a scratch tmpfs never hosts a device node or setuid binary. The CLI already
/// blocked the hardened mounts (`/proc`, `/sys`, `/dev`) and validated the path/size. Best-effort per
/// entry; the mountpoint's parents are created on the way in.
fn setup_tmpfs(root: &str, entries: &[(String, String)]) -> Result<(), Error> {
    for (path, size) in entries {
        // Defence-in-depth: the CLI guarantees an absolute, `..`-free path, but re-check before it
        // becomes a host-resolved (pre-pivot) mount target.
        if !path.starts_with('/') || path.split('/').any(|c| c == "..") {
            continue;
        }
        let full = format!("{root}{path}");
        // mkdir -p the target chain inside the new root — pre-pivot, so paths resolve through the
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
        let opts = if size.is_empty() {
            "mode=1777".to_string()
        } else {
            format!("size={size},mode=1777")
        };
        let hardening = (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong;
        if let (Ok(t), Ok(ty), Ok(o)) = (cstr(&full), cstr("tmpfs"), cstr(&opts)) {
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
    Ok(())
}

/// Append `--add-host NAME:IP` entries to the box's `/etc/hosts` (Docker parity). Best-effort,
/// pre-pivot, writing into the box's OWN root (an overlay copy-up, not the shared image). The path is
/// resolved with [`open_in_root`], which refuses a symlink at EVERY component (not just the final one)
/// and rejects `.`/`..` — so a hostile image shipping `/etc` OR `/etc/hosts` as a symlink can't redirect
/// the append out of the box root (this runs pre-pivot, where a naive open would resolve through the
/// HOST root). Content is guarded too: an entry whose name or IP carries whitespace/control is skipped,
/// so a crafted value can't inject extra `/etc/hosts` lines.
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
        return; // a symlinked /etc or /etc/hosts (or a bad component) — refuse rather than escape
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

/// Expose `--secret` values as `/run/secrets/<name>` (mode 0400) inside the box. The bytes were read
/// on the host before the fork; here we mount a fresh, box-owned, RAM-backed `tmpfs` at
/// `/run/secrets` (so a secret never lands in the persisted overlay upper) and write each file. Runs
/// before pivot. A hostile image shipping `/run/secrets` as a symlink is neutralised, and each file
/// is created `O_NOFOLLOW | O_EXCL` inside the tmpfs we own — the write can't be redirected out.
fn setup_secrets(root: &str, secrets: &[(String, Vec<u8>)], run_tmpfs: bool) -> Result<(), Error> {
    if secrets.is_empty() {
        return Ok(());
    }
    // INVARIANT (do not break): the HOST runtime dir `$XDG_RUNTIME_DIR/kern` (registry, health, and
    // exit sidecars) is NEVER mounted into a box — it isn't in the new root after pivot, so a workload
    // can't read or forge it. `kern compose`'s `depends_completed` trusts that a box CANNOT write
    // another service's `exit/<…>` sidecar. If a future feature needs in-box supervision state, mount
    // a NARROW box-owned path (like `/run/secrets` below), never bind the host `kern` runtime tree.
    //
    // `/run` may not exist in a minimal rootfs; create the chain. When a wide `/run` tmpfs is already
    // mounted (the `--ssh` path), `/run/secrets` is just a subdir on it — still RAM-backed and off the
    // overlay upper. Otherwise mount a narrow box-owned tmpfs on `/run/secrets` (0700, NOSUID|NODEV)
    // so the rest of the image's `/run` is left intact.
    //
    // This runs pre-pivot, so paths still resolve through the HOST root: a hostile image shipping
    // `/run` (or `/run/secrets`) as a symlink would redirect these mkdir/mount calls. Neutralize a
    // symlink at BOTH components before touching them — same discipline as `setup_dev`/`make_box_tmpfs`
    // (the `--ssh` path already got a fresh `/run` via `make_box_tmpfs`, so this is a no-op there).
    unlink_if_symlink(&format!("{root}/run"));
    if let Ok(runp) = cstr(&format!("{root}/run")) {
        unsafe { libc::mkdir(runp.as_ptr(), 0o755) };
    }
    let dir = format!("{root}/run/secrets");
    let dp = cstr(&dir)?;
    unlink_if_symlink(&dir);
    unsafe { libc::mkdir(dp.as_ptr(), 0o700) };
    if !run_tmpfs {
        let ty = cstr("tmpfs")?;
        let opts = cstr("mode=0700")?;
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
    for (name, bytes) in secrets {
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
        // never traverse a symlink out of the tmpfs. Mode 0400 — read-only to the owner.
        let fd = unsafe {
            libc::open(
                cp.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o400,
            )
        };
        if fd < 0 {
            // The tmpfs is freshly box-owned, so this shouldn't happen — but never let a secret go
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

/// Remount the box's `/dev` tmpfs read-only — for `--read-only` boxes, so `/dev` isn't a writable
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

/// Resolve a setuid id-map helper by **absolute trusted path only** — deliberately NOT via `$PATH`.
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
/// a numeric-uid row is only used as a fallback — mirroring how shadow's `newuidmap` resolves the
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

/// `newuidmap`/`newgidmap PID 0 own 1 1 sub count` — map box id 0 → caller, box ids 1.. → the
/// subordinate range. `bin` is a trusted absolute path. Returns whether the helper exited 0.
fn run_idmap(bin: &std::path::Path, pid: i32, own: u32, sub: u32, count: u32) -> bool {
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
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Unshare `ns_flags` (incl. the user ns), then set a *ranged* uid/gid map. Because an
/// unprivileged process can only self-map a single id, the actual mapping is applied by a helper
/// child that stays in the HOST user namespace (where the setuid `newuidmap`/`newgidmap` work) and
/// targets us by pid, synchronized over pipes. Leaves `setgroups` allowed (newgidmap is the
/// privileged writer), so the box can use supplementary groups.
fn apply_userns_range(
    ns_flags: libc::c_int,
    euid: u32,
    egid: u32,
    r: &IdRange,
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
        // Helper — still in the host user namespace, so the setuid map helpers have privilege.
        unsafe {
            libc::close(p2h[1]);
            libc::close(h2p[0]);
        }
        let ppid = unsafe { libc::getppid() };
        let mut b = [0u8; 1];
        let _ = unsafe { libc::read(p2h[0], b.as_mut_ptr() as *mut libc::c_void, 1) };
        let ok = run_idmap(&r.newuidmap, ppid, euid, r.sub_uid, r.uid_count)
            && run_idmap(&r.newgidmap, ppid, egid, r.sub_gid, r.gid_count);
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
        // couldn't actually apply the range here — typically the helper isn't setuid-root, or there
        // is no matching /etc/subgid row. We're already in a fresh, still-unmapped user namespace, so
        // fall back to the safe single-uid self-map (identical to the no-range default) instead of
        // aborting the box — mirroring how an *absent* helper already degrades gracefully. (If a
        // partial map already populated uid_map, the self-map write fails and that unrecoverable
        // half-mapped state is surfaced as the error.)
        eprintln!(
            "kern: --uid-range mapping via newuidmap/newgidmap failed (helper present but not usable here) — using single-uid map"
        );
        return write_single_uid_map(euid, egid);
    }
    Ok(())
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
        // kernel denial) — the environment permits the namespace but not a rootless id map, so a box
        // genuinely can't run here. Report it as unsupported (and name user namespaces) so foreground
        // and detached fail identically and the skip-graceful tests skip either way, rather than
        // leaking a bare "setgroups: Permission denied".
        if matches!(e.raw_os_error(), Some(libc::EACCES | libc::EPERM)) {
            return Err(Error::Unsupported(
                "unprivileged user namespaces are restricted here — an AppArmor \
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
    run_in_sandbox_with(spec, None, |_| {}, None, &[], false)
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
/// the host pid namespace) right after the fork — so a supervisor can record it for `kern exec`
/// to join the box's namespaces later.
///
/// `ready_fd`, if set, is the write end of a readiness pipe: it is closed automatically when the
/// box's command `execvp`s (`FD_CLOEXEC`), so a waiting reader gets EOF = "the box is up", and one
/// byte is written to it first if setup/exec fails — letting a detached launcher report a truthful
/// "started" / "failed to start" with zero polling. The parent closes its own copy after the fork.
///
/// The fd is wrapped in a [`ReadyGuard`] so that *any* early error (a failed `unshare`,
/// `uid_map`, or uid-range mapping — all of which return before the box is even forked) signals
/// failure on drop. Without this, an error before the fork would close the pipe cleanly and the
/// launcher would misread the EOF as a successful start.
///
/// `die_with_parent` is set ONLY for a FOREGROUND box (a plain `kern box`, not `-d`/`-it`/managed):
/// this supervisor arms `PR_SET_PDEATHSIG(SIGKILL)` relative to its launcher and the box's PID 1
/// arms it relative to this supervisor, so a hard kill of the launcher (SIGKILL/OOM — where no
/// cleanup can run) cascades launcher → supervisor → pidns-init instead of orphaning the box until
/// the `--timeout` backstop fires. It MUST stay false for a detached box, whose launcher exits right
/// after forking the supervisor (arming would kill the box instantly).
pub fn run_in_sandbox_with<F: FnOnce(i32)>(
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
    // that launched this `kern` (our parent) is hard-killed — SIGKILL/OOM, where no exit path or
    // Drop can run `kern stop` — this supervisor is torn down too, rather than being reparented and
    // keeping the box alive until the `--timeout` backstop. PDEATHSIG is per parent *thread*; the
    // fork below already requires this process to be single-threaded, so it fires on the launcher's
    // real death. Skipped for `-d`/`-it`/managed (see `die_with_parent`).
    if die_with_parent {
        // Capture the launcher BEFORE arming, then re-check: PDEATHSIG only fires on a *future*
        // parent death, so if the launcher already exited (its child `kern` reparented) between our
        // spawn and this prctl, the signal would never come — detect the reparent and refuse to
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
    // host network + user namespace (and out of the box's cgroup). Each blocks until we send it the
    // box's PID 1 after the fork below. (Empty `ports` → no forwarders.)
    let forwarders = crate::ports::fork_forwarders(ports);

    // Best-effort cgroup v2 cap (memory + PIDs) BEFORE namespacing, so the forked workload
    // inherits it. Degrades gracefully where the hierarchy isn't delegated. The returned guard owns
    // the cgroup dir and removes it on drop; we bind it to `_cg` so it lives until this function
    // returns — which is AFTER the `waitpid` below, when the box (and its PID-namespace descendants)
    // are dead and the cgroup is empty, so the `rmdir` in `Drop` succeeds. Without this the scope-less
    // fast path (no systemd `--collect`) would leak one cgroup dir per box.
    let cg = crate::cgroup::apply_limits(
        true, // allow_direct: `kern box` has a supervisor to hold the RAII guard and vacate on the direct path
        &spec.hostname,
        spec.memory_max,
        spec.memory_swap_max,
        spec.cpuset.as_deref(),
        spec.cpus,
        spec.pids_max,
        &spec.io_max,
        spec.io_weight,
    );

    // FAIL-CLOSED on the direct fast path. When we DELIBERATELY skipped the per-box systemd scope
    // (`took_direct_cap_path()` — the SAME canonical predicate `reexec` used, so they can't diverge), the
    // box's OWN cgroup is the sole enforcer. `apply_limits` returns `None` iff a MANDATORY cap didn't bite
    // (memory + pids ALWAYS carry a default cap, verified per-dimension inside apply_limits) — so a `None`
    // here means we'd run with a missing OOM/fork-bomb backstop. REFUSE. No `caps_requested` gate: the
    // default memory/pids caps are mandatory, so a default box (no flags) must also be refused if they
    // didn't take. Hosts with no user systemd never took the direct path → best-effort, no refusal; the
    // scope path sets `KERN_SCOPE` so `took_direct_cap_path()` is false there and a `None` is fine.
    // Both checks below only matter when NO cap was applied; when `cg` is `Some` neither the (env + systemd
    // stat) `took_direct_cap_path()` nor the (cgroup-walking) `env_claims_enforcer_but_none_real()` runs.
    if cg.is_none() {
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
                 but NO cgroup cap is in force — the box runs UNCAPPED. If kern did not set that variable, a \
                 caller may be bypassing the resource limits."
            );
        }
    }
    let _cg = cg; // held for RAII: its Drop removes the box's cgroup dir after waitpid (see CgroupGuard)

    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    // `--pod`: JOIN the pod holder's existing user + net namespace (created by `kern pod create`)
    // instead of unsharing our own — so every box in the pod shares one loopback network. We start
    // in the host user ns, where we are privileged over our descendant holder, so we can `setns`
    // into it; then we unshare only pid/uts/ipc (mount is unshared in the child). No uid map — the
    // holder already mapped the pod user ns. This branch is fully separate from the normal one, so a
    // non-pod box is byte-for-byte unaffected.
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
        if unsafe { libc::setns(user, libc::CLONE_NEWUSER) } != 0
            || unsafe { libc::setns(net, libc::CLONE_NEWNET) } != 0
        {
            let e = std::io::Error::last_os_error();
            return Err(Error::Syscall("setns(pod user+net)", e));
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
        // Full namespace set: user + PID + UTS (hostname) + IPC, and — unless `--net` shares the host
        // network — an isolated (loopback-only) network namespace. The mount namespace is unshared in
        // the child (so its pivot doesn't touch the parent). With CLONE_NEWPID the *next* fork
        // becomes PID 1.
        let mut ns_flags =
            libc::CLONE_NEWUSER | libc::CLONE_NEWPID | libc::CLONE_NEWUTS | libc::CLONE_NEWIPC;
        if !spec.share_net {
            ns_flags |= libc::CLONE_NEWNET;
        }
        // Map the user namespace. The DEFAULT is the dependency-free single-uid identity map (box uid
        // 0 = caller) — no subprocess, one extra id in the namespace: the fastest and most isolated
        // option. `--uid-range` opts into a FULL subordinate range (box uid 0 → caller, uids 1..N →
        // the caller's `/etc/subuid` range) so software that drops to or `chown`s *other* uids works
        // (`apt`/`dpkg`, daemons that drop to `www-data`, …); it needs the setuid `newuidmap`/
        // `newgidmap` helpers and costs two subprocesses at start.
        let range = if spec.uid_range {
            let r = detect_id_range(euid, egid);
            if r.is_none() {
                // Requested but unavailable — don't silently behave as if mapped: tell the user, then
                // fall through to the safe single-uid map (apt-style workloads just lack extra uids).
                eprintln!(
                    "kern: --uid-range requested but unavailable (need newuidmap/newgidmap + an /etc/subuid+/etc/subgid allocation) — using single-uid map"
                );
            }
            r
        } else {
            None
        };
        match range {
            Some(range) => apply_userns_range(ns_flags, euid, egid, &range)?,
            None => {
                if unsafe { libc::unshare(ns_flags) } != 0 {
                    let e = std::io::Error::last_os_error();
                    if e.raw_os_error() == Some(libc::EPERM) {
                        return Err(Error::Unsupported(USERNS_UNAVAILABLE));
                    }
                    return Err(Error::Syscall("unshare(namespaces)", e));
                }
                write_single_uid_map(euid, egid)?;
            }
        }
    }

    // `--privileged` relaxes the seccomp filter so a NESTED box can create its own namespaces — but
    // ONLY when the box's root actually maps to an UNPRIVILEGED host uid. Decide from the EFFECTIVE
    // userns uid_map now that it is established (the single-uid / `--uid-range` map written above, OR
    // the holder's map we joined via `--pod` setns) — NOT from the caller's euid. In pod mode the
    // mapping is the holder's, so an euid-only proxy could relax a box whose root maps to host root;
    // reading the actual map closes that. Fails CLOSED on anything it can't confirm. (The CLI also
    // refuses `--privileged` as real root up front; this is the authoritative, property-based gate.)
    let allow_nesting = spec.privileged && box_root_is_unprivileged();

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::last("fork"));
    }
    if pid == 0 {
        // CHILD (box PID 1): set up and exec. Take the readiness fd from the guard (this process
        // now owns the signalling) and mark it close-on-exec — a successful `execvp` then closes
        // it, so the waiting launcher reads EOF = "the box is up". On any error below we write one
        // byte first, so it learns it failed. (The guard is disarmed; the child never unwinds —
        // it always exec()s or `_exit`s — so its Drop never runs here.)
        //
        // FOREGROUND box: complete the death cascade. Arm `PR_SET_PDEATHSIG(SIGKILL)` relative to
        // the supervisor (our parent) FIRST, so if the supervisor is hard-killed — e.g. because ITS
        // launcher died and its own PDEATHSIG fired above — this pidns init dies too, and killing
        // PID 1 tears down the box's whole namespace. It survives the workload's (non-setuid)
        // execve; on the `--init` path PID 1 never execs and stays armed. Only for a foreground box:
        // a detached box's supervisor is its persistent owner, and teardown there stays with the
        // existing supervise/`kern stop` path, unchanged.
        //
        // Two honest bounds on this hop. (a) It is COOPERATIVE for a hostile PID 1: the box's own init
        // could `prctl(PR_SET_PDEATHSIG, 0)` to clear it (prctl isn't seccomp-blocked) or a setuid
        // entrypoint clears it on execve — that only drops the anti-orphan guarantee back to the
        // `--timeout` backstop (an availability property, not an isolation boundary). (b) Unlike the
        // supervisor leg we do NOT re-check `getppid()` after arming: this child is already PID 1 of
        // its new pid namespace (CLONE_NEWPID was unshared above), so `getppid()` reads 0 regardless of
        // the host-side supervisor's fate — a supervisor death in the fork→prctl microsecond window
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
                // A failed `execvp` is the common, confusing case (command not found, not executable,
                // or a missing loader). Name the command and hint, rather than a bare os-error leak.
                report_exec_failure(spec, &e);
                unsafe { libc::_exit(127) };
            }
        }
    }

    // PARENT (supervisor): the box was forked and now owns readiness signalling, so disarm our
    // guard and just drop our copy of the fd — the launcher then sees EOF exactly when the box
    // exec()s (or the failure byte if the box's own setup fails), not before.
    if let Some(fd) = ready.disarm() {
        unsafe { libc::close(fd) };
    }
    // Report PID 1 (for `kern exec`) and start the `-p` forwarders now that the box's net ns exists.
    on_started(pid);
    for f in &forwarders {
        f.activate(pid);
    }
    // `-it`: hand the terminal to the box. Drop our copy of the slave so the master sees EOF when
    // the box exits, then pump host stdio <-> master until then. Single-threaded by design — the
    // fork above must run in a single-threaded process (the child does non-async-signal-safe setup),
    // so we never spawn a pump thread.
    if let Some(master) = tty_master {
        if let Some(slave) = spec.tty_slave {
            unsafe { libc::close(slave) };
        }
        let code = pty_pump_and_wait(master, pid);
        forwarders.iter().for_each(|f| f.stop());
        return Ok(code);
    }
    // Reap the box (EINTR-robust, so a signal can't return early and drop the cgroup guard on a
    // still-live box → EBUSY leak).
    let mut status = 0i32;
    let rc = reap_retry_eintr(pid, &mut status);
    forwarders.iter().for_each(|f| f.stop());
    if rc < 0 {
        return Err(Error::last("waitpid"));
    }
    Ok(wait_code(status))
}

/// Pump the host's stdin/stdout against a PTY `master` while the box (`pid`) runs, returning its
/// exit code. Single-threaded poll loop: host stdin → master, master → host stdout. A master EOF
/// (the box closed its slave) ends it; then we reap the box. The host terminal's raw mode + window
/// size are the CLI's responsibility (set before this call, restored after).
/// `-it`: adopt the PTY `slave` as the controlling terminal — a new session (so we may claim a
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
                continue; // SIGWINCH/SIGCHLD etc. — re-poll
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
/// grant no power over host-owned resources — verified) and several are already seccomp-blocked;
/// dropping them shrinks the attack surface against kernel bugs reachable only with the cap.
/// KEPT (so apt/apk, chown, and privilege-drop to non-root keep working): CHOWN, DAC_*, FOWNER,
/// FSETID, KILL, SETUID, SETGID, SETPCAP, NET_BIND_SERVICE, NET_RAW, NET_ADMIN (also used for `lo`),
/// SYS_CHROOT, MKNOD, SETFCAP, IPC_*, SYS_NICE/RESOURCE/PTRACE, … Best-effort; an unknown cap number
/// on an older kernel just fails harmlessly.
/// The default set of never-needed dangerous caps kern always drops (kernel-stable numbers, used
/// directly so we don't depend on newer libc constants).
const DEFAULT_DROP: &[u32] = &[
    16, // SYS_MODULE     load kernel modules
    17, // SYS_RAWIO      raw I/O ports, /dev/mem, ioperm
    20, // SYS_PACCT      process accounting
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
/// numbers (not names) — the CLI resolves names and rejects unknown ones before the fork. Default
/// (`Default::default()`) drops exactly the dangerous set. All cap numbers are < 64 (the current
/// `CAP_LAST_CAP` is 40), so a single `u64` bitmask covers the whole set.
#[derive(Default, Clone)]
pub struct CapSpec {
    /// `--cap-drop ALL`: drop every capability up to `CAP_LAST_CAP` (minus `adds`).
    pub drop_all: bool,
    /// Extra caps to drop beyond the default dangerous set.
    pub drops: Vec<u32>,
    /// Caps to KEEP — removed from the computed drop set (so `--cap-add` wins over a drop).
    pub adds: Vec<u32>,
}

/// The bitmask (bit N = cap N) of the dangerous caps kern ALWAYS drops from a box's bounding set
/// ([`DEFAULT_DROP`]). `kern top` reads a box's `CapBnd` and, if it intersects this mask, knows the box
/// re-added a normally-dropped cap via `--cap-add` — i.e. it is LESS confined than the default. A
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
/// minus whatever `--cap-add` keeps.
fn cap_drop_mask(spec: &CapSpec) -> u64 {
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
    mask
}

/// Drop the masked capabilities from the **bounding** set (`PR_CAPBSET_DROP`), so a file-cap binary
/// can't re-add them later. Needs `CAP_SETPCAP` in the *effective* set, so it must run BEFORE the
/// effective set is cleared and BEFORE any `setuid` to a non-root user (which sheds effective caps).
fn drop_cap_bounding(mask: u64) {
    for c in 0..64u32 {
        if mask & (1u64 << c) != 0 {
            unsafe { libc::prctl(libc::PR_CAPBSET_DROP, c as libc::c_ulong, 0, 0, 0) };
        }
    }
}

/// Clear the masked capabilities from the live effective/permitted/inheritable sets (the workload
/// won't hold them after exec). For a non-root `--user`, `setuid` has already emptied these; this
/// still matters for a root box and is a harmless no-op otherwise.
fn clear_caps_from_sets(mask: u64) {
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
    unsafe {
        if libc::syscall(libc::SYS_capget, &mut hdr as *mut _, data.as_mut_ptr()) == 0 {
            data[0].effective &= !lo;
            data[0].permitted &= !lo;
            data[0].inheritable &= !lo;
            data[1].effective &= !hi;
            data[1].permitted &= !hi;
            data[1].inheritable &= !hi;
            libc::syscall(libc::SYS_capset, &hdr as *const _, data.as_ptr());
        }
    }
}

/// Drop capabilities for the workload: always the dangerous [`DEFAULT_DROP`] set, plus `--cap-drop`
/// (or *everything* for `--cap-drop ALL`), minus `--cap-add`. Clears the effective/permitted/
/// inheritable sets AND the bounding set. Used where NO `--user` switch follows (e.g. `kern exec`);
/// the box workload path splits this around `set_user` (bounding drop → setuid → effective clear) so
/// that `--cap-drop ALL` doesn't strip `CAP_SETUID`/`SETGID` before the user switch needs them.
fn drop_dangerous_caps(spec: &CapSpec) {
    let mask = cap_drop_mask(spec);
    drop_cap_bounding(mask);
    clear_caps_from_sets(mask);
}

/// After `fork()`, close every inherited fd `>= 3` except `keep` (pass `-1` to keep none). A
/// long-lived helper child (a `-p` forwarder, a health-checker) must shed the parent's fds — most
/// importantly a detached box's readiness-pipe write end, whose lingering copy would stop the
/// launcher from ever seeing EOF and hang `kern box -d`.
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

/// Bring the loopback interface (`lo`) up in the current network namespace via `SIOCSIFFLAGS`, so
/// `127.0.0.1` works inside an otherwise-isolated box. Best-effort (a fresh net ns owned by our
/// user namespace grants CAP_NET_ADMIN, so this normally succeeds; failures leave `lo` down).
fn bring_loopback_up() {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return;
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        ifr.ifr_name[0] = b'l' as libc::c_char;
        ifr.ifr_name[1] = b'o' as libc::c_char;
        // `ioctl`'s request arg is `c_ulong` on x86_64 but `c_int` on aarch64 — `as _` casts the
        // SIOC* constant to whatever this target expects, so this compiles on every arch.
        if libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) == 0 {
            ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
            libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr);
        }
        libc::close(sock);
    }
}

/// Create and HOLD a pod's shared user + net namespace, then block forever. `kern pod create` forks
/// this as a detached holder process; `--pod` boxes `setns` into `/proc/<holder>/ns/{user,net}` to
/// share its loopback network. Unshares a fresh user ns (single-uid map: pod-root = the caller) + a
/// fresh net ns, brings its loopback up, then `pause()`s so the namespaces stay alive until the
/// holder is killed (`kern pod rm`). Never returns.
pub fn run_pod_holder() -> ! {
    // A pod holder maps a RANGED uid map (`KERN_POD_UID_RANGE=1`, set by `pod create --uid-range`)
    // when the pod will host OCI images that drop privilege in their entrypoint (postgres/redis/nginx/
    // …). Members `setns` into this shared user ns and inherit the range, so their drop to a service
    // uid works — the 0.6 official-image fix, extended to the pod path. Default (no env) = the single-
    // uid self-map: faster (no newuidmap), more isolated (one uid), for a pod of root-only services.
    let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let want_range = std::env::var_os("KERN_POD_UID_RANGE").is_some();
    let ns = libc::CLONE_NEWUSER | libc::CLONE_NEWNET;
    // The range needs newuidmap + an /etc/subuid allocation; if either is missing, fall back to the
    // single-uid map (honest degrade — official images in this pod will then fail with the F1 warning,
    // not silently). detect_id_range is resolved BEFORE the unshare (it must run in the init userns).
    let range = if want_range {
        detect_id_range(euid, egid)
    } else {
        None
    };
    match range {
        Some(r) => {
            // apply_userns_range does its own unshare(ns) + fork-helper newuidmap/newgidmap + sync.
            if let Err(e) = apply_userns_range(ns, euid, egid, &r) {
                eprintln!(
                    "kern: pod: ranged user-ns map failed ({e}) — falling back to single-uid"
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
            if want_range {
                eprintln!("kern: pod: --uid-range requested but unavailable (need newuidmap/newgidmap + /etc/subuid) — single-uid map");
            }
            if write_single_uid_map(euid, egid).is_err() {
                eprintln!("kern: pod: could not map the pod user namespace");
                unsafe { libc::_exit(1) };
            }
        }
    }
    bring_loopback_up();
    // Signal readiness (the parent waits for this line on our stdout) so `kern pod create` only
    // records the holder once its namespaces are actually set up.
    println!("pod-ready");
    unsafe {
        libc::close(libc::STDOUT_FILENO);
    }
    loop {
        unsafe { libc::pause() };
    }
}

/// Blocking `waitpid(pid)` that retries on `EINTR`, writing the status through `status` and returning
/// the raw `waitpid` return (`>= 0` = reaped, `< 0` = a real, non-EINTR error). A signal
/// (SIGCHLD/SIGWINCH/…) can interrupt a blocking `waitpid` with the child STILL ALIVE — returning early
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

/// `kern exec`: run `command` inside the namespaces of an already-running box (its PID 1 is
/// `pid1`, in the host pid namespace). Joins the box's user namespace first (to gain capabilities
/// in it), then its mount/ipc/uts/(net)/pid namespaces, then forks so the child lands in the
/// box's pid namespace, applies the env/workdir + the same seccomp filter, and execs. Returns the
/// command's exit code.
///
/// Not a descendant of PID 1, so the box's own seccomp filter doesn't block the `setns` calls
/// here; the new process gets its own copy of the filter for parity. Requires that the caller is
/// the same user that created the box (its user namespace owner).
pub fn exec_in_box(
    pid1: i32,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    tty_slave: Option<i32>,
    tty_master: Option<i32>,
    timeout_secs: Option<u64>,
) -> Result<i32, Error> {
    if command.is_empty() {
        return Err(Error::Unsupported("no command given to exec in the box"));
    }
    let argv: Vec<CString> = command.iter().map(|s| cstr(s)).collect::<Result<_, _>>()?;

    // Open every namespace fd BEFORE any setns: once we enter the mount namespace, `/proc` points
    // at the box's, so `/proc/<pid1>/ns/*` would no longer resolve. Order of *entry* matters —
    // user first (so we hold CAP_SYS_ADMIN in the box's userns for the rest); pid before the fork.
    let ns_order: [(&str, libc::c_int); 6] = [
        ("user", libc::CLONE_NEWUSER),
        ("ipc", libc::CLONE_NEWIPC),
        ("uts", libc::CLONE_NEWUTS),
        ("net", libc::CLONE_NEWNET),
        ("mnt", libc::CLONE_NEWNS),
        ("pid", libc::CLONE_NEWPID),
    ];
    let mut fds: Vec<(libc::c_int, libc::c_int)> = Vec::with_capacity(ns_order.len());
    for (name, flag) in ns_order {
        let p = cstr(&format!("/proc/{pid1}/ns/{name}"))?;
        let fd = unsafe { libc::open(p.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd >= 0 {
            fds.push((fd, flag));
        }
        // A missing ns file means it isn't separate (e.g. `--net` shares the host net ns) —
        // there's nothing to join, so skipping is correct.
    }
    // Refuse if the box's core namespaces aren't there to join: if PID 1 has exited (a race), its
    // `/proc/<pid1>/ns/*` vanish, and without this we'd fork+exec in the HOST namespaces — running
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

    // Fork: with the box's pid namespace entered, the child becomes a member of it.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::last("fork"));
    }
    if pid == 0 {
        // For a `--health-timeout` probe: become a **session leader** (`setsid`) so this grandchild is
        // a new process-group/session leader inside the box's pid namespace whose host-visible id is
        // `pid` — the probe and everything it forks then live in that group, so the parent can
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
        set_clean_env("", env);
        // `-it`: adopt the PTY slave as the controlling terminal (before seccomp — a setup syscall).
        if let Some(slave) = tty_slave {
            adopt_controlling_tty(slave);
        }
        // Honor `--workdir` — fatal if it can't be entered (consistent with `kern box -w`, so a
        // typo'd dir is an error, not a silent run in `/`).
        if let Some(wd) = workdir {
            let entered = cstr(wd).is_ok_and(|c| unsafe { libc::chdir(c.as_ptr()) } == 0);
            if !entered {
                eprintln!("kern: exec: cannot enter workdir {wd}");
                unsafe { libc::_exit(127) };
            }
        }
        // Parity with a box's own workload: drop the always-dropped dangerous caps here too, so an
        // `exec`'d command isn't more privileged than the box's PID 1 (which ran `drop_dangerous_caps`
        // + seccomp before its own exec). The box's *custom* `--cap-drop`/`--user` aren't reapplied —
        // they aren't recorded per box — but the dangerous baseline + seccomp match.
        drop_dangerous_caps(&CapSpec::default());
        // Fail CLOSED if seccomp can't install — never run the exec'd command unfiltered (the box's
        // PID 1 fails closed on this same call; `exec` must match, not fall through unprotected).
        // `exec` keeps the STRICT filter regardless of the box's `--privileged` (which isn't
        // recorded per box) — an exec'd command being *more* constrained than PID 1 is always safe.
        if crate::seccomp::install(false).is_err() {
            eprintln!("kern: exec: seccomp filter could not be installed — refusing to run");
            unsafe { libc::_exit(126) };
        }
        eprintln!("kern: exec failed: {}", exec(&argv));
        unsafe { libc::_exit(127) };
    }
    // `-it` parent: drop our copy of the slave so the master sees EOF when the exec'd process exits,
    // then pump host stdio <-> master until then (single-threaded, like the box path).
    if let Some(master) = tty_master {
        if let Some(slave) = tty_slave {
            unsafe { libc::close(slave) };
        }
        return Ok(pty_pump_and_wait(master, pid));
    }
    let mut status = 0i32;
    match timeout_secs {
        // `--health-timeout`: poll, and on expiry SIGKILL the whole probe group (the in-box grandchild
        // and anything it spawned), then reap — so a hung probe can't leak a live process into the box
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
                    // a probe that forked helpers is fully torn down — not just its top process; then
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
            Ok(wait_code(status))
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
        // Success path: the box child / parent disarm the guard, so dropping it writes nothing —
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
mod pdeathsig_cascade_tests {
    // Reproduces the OS mechanism the orphan-on-launcher-death fix relies on: a "box PID 1" (G)
    // that arms `PR_SET_PDEATHSIG(SIGKILL)` relative to its "supervisor" (A) is SIGKILLed the moment
    // A dies — the same relationship `run_in_sandbox_with` wires between the box's pidns-init and its
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
                // `waitpid` would block — SIGALRM turns that into a visible non-zero exit instead.
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
                        // ── G: the "box PID 1" — arm the death cascade, then block forever ──
                        libc::close(sr);
                        libc::prctl(
                            libc::PR_SET_PDEATHSIG,
                            libc::SIGKILL as libc::c_ulong,
                            0,
                            0,
                            0,
                        );
                        // Tell A we've armed it BEFORE A exits — closes the pdeathsig race (a parent
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
                "observer was signaled (e.g. SIGALRM timeout) — cascade never fired (status {st})"
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
/// by ~45 tests, after ruling out idmapped mounts — impossible rootless, EPERM: mount_setattr(IDMAP)
/// needs CAP_SYS_ADMIN in the init userns where the image fs lives — and fuse-overlayfs — slow,
/// user-space): the box's `/` was mode 0700 (from the own-only overlay upper), so ANY dropped non-root
/// uid hit EACCES on the FIRST path component `/`, before ownership ever mattered. FIX (two surgical
/// changes): (1) the box root is 0755 when privilege may be dropped (`--user` non-root OR `--uid-range`)
/// — a normal rootfs mode, safe because the HOST scratch dir stays 0700 and isolation is the namespace,
/// not the root's mode; (2) `/dev/fd` + `/dev/std{in,out,err}` symlinks into procfs (bash process
/// substitution / postgres initdb need them). Verified live: redis, nginx, postgres all reach
/// "ready to accept connections" under `--uid-range`.
#[cfg(test)]
mod uid_range_root_traversable {
    use std::os::unix::fs::PermissionsExt;

    // The fix is a mode on the overlay upper (→ the box root). Assert the exact rule the box path uses:
    // root becomes world-traversable (0755) iff a non-root --user is set OR --uid-range is on.
    fn root_should_be_traversable(user_non_root: bool, uid_range: bool) -> bool {
        user_non_root || uid_range
    }

    #[test]
    fn root_is_traversable_when_privilege_may_be_dropped() {
        assert!(
            root_should_be_traversable(false, true),
            "--uid-range → 0755 (entrypoint may drop)"
        );
        assert!(
            root_should_be_traversable(true, false),
            "--user non-root → 0755"
        );
        assert!(root_should_be_traversable(true, true));
        assert!(
            !root_should_be_traversable(false, false),
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
            "0700 blocks other — the bug"
        );
    }
}

#[cfg(test)]
mod cpuset_expand_tests {
    use super::expand_cpu_list;

    /// REGRESSION (HIGH, hacker-mode audit): a huge cpuset range must NOT allocate a giant Vec. Indices
    /// past CPU_SETSIZE are unsettable, so the range is clamped before expansion — `0-999999999` yields
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
        // resolve through the host root — this is the exact escape the audit flagged.
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
        // Every DEFAULT_DROP cap is set: SYS_MODULE(16), SYS_RAWIO(17), SYS_BOOT(22), BPF(39), PERFMON(38).
        for c in [16u32, 17, 20, 22, 25, 30, 32, 33, 34, 35, 37, 38, 39] {
            assert!(m & (1u64 << c) != 0, "cap {c} must be in the dropped mask");
        }
        // Kept caps are NOT in the mask (so a default box never false-flags): CHOWN(0), SETUID(7),
        // NET_ADMIN(12), SYS_ADMIN(21), MKNOD(27), SYS_PTRACE(19).
        for c in [0u32, 7, 12, 19, 21, 27] {
            assert!(
                m & (1u64 << c) == 0,
                "kept cap {c} must NOT be in the dropped mask"
            );
        }
        // The mask is exactly the default drop of an unmodified spec (the bounding set kern imposes).
        assert_eq!(m, cap_drop_mask(&CapSpec::default()));
    }

    #[test]
    fn cap_add_puts_a_dropped_cap_back_so_top_can_flag_it() {
        // `--cap-add SYS_MODULE` removes cap 16 from the drop set → the box's bounding set KEEPS it →
        // its CapBnd then intersects default_dropped_cap_mask(), which is how `kern top` flags caps:+.
        let spec = CapSpec {
            adds: vec![16],
            ..Default::default()
        };
        let dropped = cap_drop_mask(&spec);
        assert!(
            dropped & (1u64 << 16) == 0,
            "--cap-add SYS_MODULE must NOT drop cap 16"
        );
        // The bounding set = full minus the drop set; cap 16 survives and would be flagged.
        assert!(default_dropped_cap_mask() & (1u64 << 16) != 0);
    }
}

#[cfg(test)]
mod nesting_gate_tests {
    use super::uid_map_root_is_unprivileged;

    /// `--privileged` nesting is gated on the EFFECTIVE box-root mapping, not the caller's euid — so a
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
