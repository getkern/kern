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

use crate::{Error, MountMode, MountOps, Rootfs};
use std::convert::Infallible;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

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
    /// Map a subordinate uid/gid *range* into the box (`--uid-range`) instead of just the caller.
    /// Opt-in because it (a) costs two `newuidmap`/`newgidmap` subprocesses at start and (b) maps
    /// 65k extra ids into the namespace; the default single-uid map is both faster and more
    /// isolated. Needed only for workloads that use multiple uids inside the box (`apt`/`dpkg`,
    /// daemons that drop to `www-data`, …).
    pub uid_range: bool,
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
    let r = unsafe {
        libc::mount(
            ty.as_ptr(),
            merged_c.as_ptr(),
            ty.as_ptr(),
            0,
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

/// `Ok` — on success `exec` replaces the process; otherwise it returns the error.
fn child_setup_and_exec(spec: &SandboxSpec, argv: &[CString]) -> Result<Infallible, Error> {
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
    setup_dev(&spec.root)?;
    t.mark("dev");
    setup_volumes(&spec.root, &spec.volumes)?;
    t.mark("volumes");
    // Self-pivot into the new root. The old root is left stacked at "/"; mount a fresh `proc`
    // (cwd-relative, while the old root still provides the visible proc instance the kernel
    // requires), THEN detach the old root.
    let staged = mounted.create_old_root(&mut ops)?;
    mount_proc()?;
    detach_old_root()?;
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

    // Install the seccomp filter LAST — after all setup syscalls (mount/pivot) are done, so it
    // only constrains the workload. Then exec.
    crate::seccomp::install()?;
    t.mark("seccomp");
    Err(exec(argv))
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
        let r = unsafe {
            libc::mount(
                src.as_ptr(),
                tgt.as_ptr(),
                ptr::null(),
                (libc::MS_BIND | libc::MS_REC) as libc::c_ulong,
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
                result = Err(Error::last("remount_ro(volume)"));
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
fn setup_dev(root: &str) -> Result<(), Error> {
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
    if unsafe {
        libc::mount(
            ty.as_ptr(),
            dp.as_ptr(),
            ty.as_ptr(),
            0,
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
fn trusted_helper(bin: &str) -> Option<std::path::PathBuf> {
    ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        .iter()
        .map(|d| std::path::Path::new(d).join(bin))
        .find(|p| p.is_file())
}

/// The login name for `uid` (for matching `/etc/subuid` rows), or `None`.
fn username(uid: u32) -> Option<String> {
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
fn sub_range(file: &str, name: Option<&str>, id: u32) -> Option<(u32, u32)> {
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
            return Err(Error::Unsupported(
                "unprivileged user namespaces are unavailable (kernel.unprivileged_userns_clone=0 or an AppArmor restriction)",
            ));
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
        return Err(Error::Unsupported(
            "newuidmap/newgidmap failed to map the user namespace (check /etc/subuid and /etc/subgid)",
        ));
    }
    Ok(())
}

/// Run `spec.command` inside a fresh user + PID + mount namespace sandbox. Returns the child's
/// exit code. Requires unprivileged user namespaces.
pub fn run_in_sandbox(spec: &SandboxSpec) -> Result<i32, Error> {
    run_in_sandbox_with(spec, None, |_| {})
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
pub fn run_in_sandbox_with<F: FnOnce(i32)>(
    spec: &SandboxSpec,
    ready_fd: Option<i32>,
    on_started: F,
) -> Result<i32, Error> {
    // Armed until the box child takes ownership (post-fork) or the parent disarms it: a drop on
    // any error path before then writes the failure byte, so a pre-fork failure is never reported
    // as "started".
    let mut ready = ReadyGuard(ready_fd);
    if spec.command.is_empty() {
        return Err(Error::Unsupported("no command given to run in the sandbox"));
    }
    // Build argv CStrings before fork (the child stays allocation-light).
    let argv: Vec<CString> = spec
        .command
        .iter()
        .map(|s| cstr(s))
        .collect::<Result<_, _>>()?;

    // Best-effort cgroup v2 cap (memory + PIDs) BEFORE namespacing, so the forked workload
    // inherits it. Degrades gracefully where the hierarchy isn't delegated.
    let _cg = crate::cgroup::apply_limits(&spec.hostname);

    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    // Full namespace set: user + PID + UTS (hostname) + IPC, and — unless `--net` shares the host
    // network — an isolated (loopback-only) network namespace. The mount namespace is unshared in
    // the child (so its pivot doesn't touch the parent). With CLONE_NEWPID the *next* fork becomes
    // PID 1.
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
            // fall through to the safe single-uid map (apt-style workloads just won't have extra uids).
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
                    return Err(Error::Unsupported(
                        "unprivileged user namespaces are unavailable (kernel.unprivileged_userns_clone=0 or an AppArmor restriction)",
                    ));
                }
                return Err(Error::Syscall("unshare(namespaces)", e));
            }
            std::fs::write("/proc/self/setgroups", b"deny")
                .map_err(|e| Error::Syscall("setgroups", e))?;
            std::fs::write("/proc/self/uid_map", format!("0 {euid} 1"))
                .map_err(|e| Error::Syscall("uid_map", e))?;
            std::fs::write("/proc/self/gid_map", format!("0 {egid} 1"))
                .map_err(|e| Error::Syscall("gid_map", e))?;
        }
    }

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
        let ready_fd = ready.disarm();
        if let Some(fd) = ready_fd {
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        match child_setup_and_exec(spec, &argv) {
            Ok(never) => match never {},
            Err(e) => {
                if let Some(fd) = ready_fd {
                    let _ = unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
                }
                // A failed `execvp` is the common, confusing case (command not found, not
                // executable, or — for a dynamic binary in a bare rootfs — a missing loader,
                // which the kernel also reports as ENOENT). Name the command and hint, rather
                // than leaking a bare `execvp failed: ... (os error 2)`.
                if let Error::Syscall("execvp", io) = &e {
                    let cmd = spec.command.first().map(String::as_str).unwrap_or("?");
                    eprintln!(
                        "kern: cannot start '{cmd}' in box: {io}\n\
                         hint: the command must exist inside the box (try a full path like \
                         /bin/sh) and, if dynamically linked, its libraries/loader must be \
                         present in the rootfs"
                    );
                } else {
                    eprintln!("kern: sandbox setup failed: {e}");
                }
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
    // Report PID 1 (for `kern exec`), then wait for the sandbox.
    on_started(pid);
    let mut status = 0i32;
    if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        return Err(Error::last("waitpid"));
    }
    Ok(wait_code(status))
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
        set_clean_env("", env);
        // Honor `--workdir` — fatal if it can't be entered (consistent with `kern box -w`, so a
        // typo'd dir is an error, not a silent run in `/`).
        if let Some(wd) = workdir {
            let entered = cstr(wd).is_ok_and(|c| unsafe { libc::chdir(c.as_ptr()) } == 0);
            if !entered {
                eprintln!("kern: exec: cannot enter workdir {wd}");
                unsafe { libc::_exit(127) };
            }
        }
        let _ = crate::seccomp::install();
        eprintln!("kern: exec failed: {}", exec(&argv));
        unsafe { libc::_exit(127) };
    }
    let mut status = 0i32;
    if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        return Err(Error::last("waitpid"));
    }
    Ok(wait_code(status))
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
