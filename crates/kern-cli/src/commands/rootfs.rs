//! The box's filesystem: staging a rootfs, the overlay under it, and the scratch that holds both.
//!
//! A SUPPORT module. Every verb that materialises a filesystem uses these - `build` for its stage
//! chain and COPY globs, `start` for the box's own root, `system` for the sweepers - so they sit
//! here and the parent re-exports them, rather than next to one verb with the others reaching
//! sideways.
//!
//! Contents: the confined copiers (`openat2`-rooted, depth-bounded), the merged-view extractor and
//! its whiteout handling, the COPY glob expansion, the overlay capability probes, and the scratch
//! lifecycle including the orphan sweep.

use super::*;

/// Remove a box's writable scratch tree (best-effort), with a ranged fallback for subuid-owned files.
pub(crate) fn cleanup_scratch(scratch: Option<&std::path::Path>) {
    if let Some(s) = scratch {
        if std::fs::remove_dir_all(s).is_ok() || !s.exists() {
            return;
        }
        // remove_dir_all failed and the dir is still there: a `--uid-range` box (or a pod member) can
        // leave files owned by SUBORDINATE uids (an image that dropped to e.g. uid 472 → host subuid
        // 100471) that we - as the plain host user, outside any userns - can't unlink (they sit under
        // subuid-owned dirs). Retry inside a `newuidmap`-mapped user namespace where those subuids map
        // back to ns-root, so the remove succeeds. This is what `podman unshare rm` does for the same
        // reason. Best-effort: if the range isn't available, we've already tried the plain remove.
        //
        // TOCTOU (the ranged remove is PRIVILEGED - subuids map to ns-root - and descends a tree a box
        // wrote): a box process surviving teardown could plant a symlink mid-descent to steer the
        // recursive remove outside the scratch tree. Two layers close it: (1) `remove_dir_all` is
        // no-follow at every level (openat+O_NOFOLLOW since Rust 1.26; our MSRV is 1.82, so guaranteed,
        // not toolchain-luck); (2) BEFORE removing, we re-open the target under kern's scratch-root with
        // `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` - a kernel-level check that no component is a
        // symlink or escapes the root. If that open is refused, we do NOT run the ranged remove.
        if !scratch_path_is_confined(s) {
            return;
        }
        remove_dir_all_ranged(s);
    }
}

/// True iff `dir` opens cleanly under kern's scratch-root with `openat2(RESOLVE_BENEATH |
/// RESOLVE_NO_SYMLINKS)` - i.e. every path component stays beneath the root and none is a symlink.
/// Kernel-enforced (Linux 5.6+ for openat2 / 5.3 for the resolve flags); if openat2 is unavailable the
/// no-follow `remove_dir_all` + the canonicalized parent check are the fallback confinement.
pub(crate) fn scratch_path_is_confined(dir: &std::path::Path) -> bool {
    const SYS_OPENAT2: libc::c_long = 437;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let root = scratch_dir();
    let Ok(root_c) = std::ffi::CString::new(root.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    let root_fd = unsafe {
        libc::open(
            root_c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return false;
    }
    // The path RELATIVE to the scratch root (RESOLVE_BENEATH interprets it from root_fd).
    let rel = dir.strip_prefix(&root).unwrap_or(dir);
    let Ok(rel_c) = std::ffi::CString::new(rel.as_os_str().as_encoded_bytes()) else {
        unsafe { libc::close(root_fd) };
        return false;
    };
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,
    };
    let fd = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            root_fd,
            rel_c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    unsafe { libc::close(root_fd) };
    if fd >= 0 {
        unsafe { libc::close(fd as libc::c_int) };
        true // confined: no symlink component, stays beneath the scratch root
    } else {
        // ENOSYS (no openat2) → fall back to the no-follow remove + canonical-parent check (still safe
        // on our MSRV); any other error (ELOOP/EXDEV = a symlink/escape component) → refuse.
        std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS)
    }
}

/// Remove `dir` from inside a user namespace mapped to the caller's full subordinate range, so files
/// owned by subordinate uids (left by a `--uid-range` / pod box whose workload dropped privilege) are
/// unlinkable (they appear owned by ns-root under the map). Forks a child that unshares a user ns and
/// blocks; the parent maps it with `newuidmap`/`newgidmap`; the child then `remove_dir_all`s as ns-root.
pub(crate) fn remove_dir_all_ranged(dir: &std::path::Path) {
    let (uid, gid) = (unsafe { libc::getuid() }, unsafe { libc::getgid() });
    // Resolve the range + trusted helpers via the ONE authoritative kern-isolation impl (same as the
    // box-start path), so cleanup can't drift; no allocation → give up.
    let name = kern_isolation::username(uid);
    let (Some(newuidmap), Some(newgidmap)) = (
        kern_isolation::trusted_helper("newuidmap"),
        kern_isolation::trusted_helper("newgidmap"),
    ) else {
        return;
    };
    let (Some((sub_uid, uc)), Some((sub_gid, gc))) = (
        kern_isolation::sub_range("/etc/subuid", name.as_deref(), uid),
        kern_isolation::sub_range("/etc/subgid", name.as_deref(), gid),
    ) else {
        return;
    };
    let mut c2p = [0i32; 2];
    let mut p2c = [0i32; 2];
    if unsafe { libc::pipe(c2p.as_mut_ptr()) } != 0 || unsafe { libc::pipe(p2c.as_mut_ptr()) } != 0
    {
        return;
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return;
    }
    if pid == 0 {
        unsafe {
            libc::close(c2p[0]);
            libc::close(p2c[1])
        };
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
            unsafe { libc::_exit(1) };
        }
        let _ = unsafe { libc::write(c2p[1], b"1".as_ptr().cast(), 1) };
        let mut b = [0u8; 1];
        let _ = unsafe { libc::read(p2c[0], b.as_mut_ptr().cast(), 1) };
        // ns-root over the whole range now: the subuid-owned files map to ids we own here → removable.
        let _ = std::fs::remove_dir_all(dir);
        unsafe { libc::_exit(0) };
    }
    unsafe {
        libc::close(c2p[1]);
        libc::close(p2c[0])
    };
    let mut b = [0u8; 1];
    let _ = unsafe { libc::read(c2p[0], b.as_mut_ptr().cast(), 1) };
    let map = |bin: &std::path::Path, own: u32, sub: u32, count: u32| {
        let _ = std::process::Command::new(bin)
            .args([
                pid.to_string(),
                "0".into(),
                own.to_string(),
                "1".into(),
                "1".into(),
                sub.to_string(),
                count.to_string(),
            ])
            .status();
    };
    map(&newuidmap, uid, sub_uid, uc);
    map(&newgidmap, gid, sub_gid, gc);
    let _ = unsafe { libc::write(p2c[1], b"1".as_ptr().cast(), 1) };
    let mut st = 0;
    crate::eintr::waitpid(pid, &mut st, 0);
}

/// Sweep orphaned overlay scratch: `<scratch>/<name>-<pid>/` dirs whose box is no longer live.
/// Returns `(dirs_removed, bytes_freed)`. Shared by `recover` (its whole job) and `gc` (folded in so
/// `gc` is the ONE full local cleanup - previously only `recover` reclaimed scratch, and it was easy
/// to miss, so crashed-box overlay dirs quietly piled up).
pub(crate) fn sweep_orphan_scratch() -> (u32, u64) {
    // `registry::list()` already prunes entries whose process is dead on read; call it to get the
    // set of *live* boxes and to trigger that cleanup.
    let live = registry::list();
    let live_scratch: std::collections::HashSet<String> =
        live.iter().map(|b| b.rootfs.clone()).collect();
    let mut recovered = 0u32;
    let mut freed = 0u64;
    let scratch = scratch_dir();
    if let Ok(entries) = std::fs::read_dir(&scratch) {
        for e in entries.flatten() {
            let path = e.path();
            let merged = path.join("merged");
            // A live box's `rootfs` is its `.../merged` dir; if none matches, this scratch is orphaned.
            if !live_scratch.contains(&merged.to_string_lossy().into_owned()) && path.is_dir() {
                freed += dir_size(&path);
                // Use the chmod-then-remove force cleaner: an overlay leaves a mode-000 `work/work`
                // dir that plain `remove_dir_all` can't traverse (Permission denied) - the bug that made
                // recover a silent no-op while orphans piled up. `gc`/`prune` already use this helper.
                remove_build_tree(&path);
                if !path.exists() {
                    recovered += 1;
                }
            }
        }
    }
    (recovered, freed)
}

/// The mount points inside a box's mount namespace, box-root-relative (e.g. `/proc`, `/dev`, `/dev/shm`,
/// `/sys/fs/cgroup`, and every `-v` volume / workspace / secret), EXCLUDING the root `/` itself. Read
/// from `/proc/<pid1>/mountinfo` (field 5 is the mount point). Used by `commit` to skip everything that
/// is not the image's own filesystem. `mountinfo` octal-escapes space/tab/newline/backslash in the path.
pub(crate) fn box_mount_points(pid1: i32) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    let Ok(body) = std::fs::read_to_string(format!("/proc/{pid1}/mountinfo")) else {
        return set;
    };
    for line in body.lines() {
        // Fields up to the optional-fields marker are fixed; the mount point is field 5 (index 4).
        if let Some(mp) = line.split_whitespace().nth(4) {
            let unescaped = unescape_mountinfo(mp);
            if unescaped != "/" {
                set.insert(unescaped);
            }
        }
    }
    set
}

/// Decode `mountinfo`'s octal escapes (`\040` space, `\011` tab, `\012` newline, `\134` backslash).
pub(crate) fn unescape_mountinfo(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let code = (b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0');
            out.push(code as char);
            i += 4;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

/// Recursively copy a box's merged rootfs at `src_root` into `dst_root`, skipping the box-root-relative
/// paths in `skip` (its nested mounts: pseudo-fs, bind volumes, secrets). The overlay is read through
/// `/proc/<pid1>/root`, so the kernel has already resolved whiteouts/opaque dirs; a plain recursive copy
/// captures the merged view. Symlinks are copied verbatim (NEVER followed), directories are recreated
/// with their mode, regular files are copied with their permission bits; devices / fifos / sockets are
/// skipped (not image content). Descent is via `read_dir`, so a symlinked directory is copied as a link
/// and never traversed into: a box-planted symlink cannot steer the copy outside the box root.
pub(crate) fn copy_rootfs_snapshot(
    src_root: &std::path::Path,
    dst_root: &std::path::Path,
    skip: &std::collections::HashSet<String>,
) -> Result<(), Error> {
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    std::fs::create_dir_all(dst_root).map_err(|e| Error::Sandbox(format!("commit mkdir: {e}")))?;
    // Each frame: (source dir, destination dir, box-root-relative path of the source dir).
    let mut stack = vec![(
        src_root.to_path_buf(),
        dst_root.to_path_buf(),
        "/".to_string(),
    )];
    while let Some((sdir, ddir, rel)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&sdir) else {
            continue;
        };
        for ent in entries.flatten() {
            let name = ent.file_name();
            let child_rel = if rel == "/" {
                format!("/{}", name.to_string_lossy())
            } else {
                format!("{rel}/{}", name.to_string_lossy())
            };
            if skip.contains(&child_rel) {
                continue; // a nested mount: proc/sys/dev/shm, a -v volume, workspace, or a secret
            }
            let sp = ent.path();
            let dp = ddir.join(&name);
            let Ok(md) = std::fs::symlink_metadata(&sp) else {
                continue;
            };
            let ft = md.file_type();
            let mode = md.mode() & 0o7777;
            if ft.is_symlink() {
                if let Ok(target) = std::fs::read_link(&sp) {
                    let _ = symlink(&target, &dp);
                }
            } else if ft.is_dir() {
                let _ = std::fs::create_dir(&dp);
                let _ = std::fs::set_permissions(&dp, std::fs::Permissions::from_mode(mode));
                stack.push((sp, dp, child_rel));
            } else if ft.is_file() && std::fs::copy(&sp, &dp).is_ok() {
                let _ = std::fs::set_permissions(&dp, std::fs::Permissions::from_mode(mode));
            }
        }
    }
    Ok(())
}

/// Copy from an image's KERNEL-MERGED overlay view into `out_dir`, honouring overlay opaque/whiteout
/// semantics so a file DELETED in an upper layer (`rm -rf dir && mkdir dir` → an OPAQUE directory, or a
/// per-file `.wh.` whiteout) can never resurface. This is the ONE correct reader for a ≥2-layer image:
/// a hand-rolled top-first / bottom-up `cp -a` of the RAW layer dirs ignores the opaque xattr and leaks
/// the deleted file (a real confidentiality bug - a secret `rm`'d in a build step reappearing in a
/// `COPY --from` or a pushed image). Letting the KERNEL present the merged view is the only way that
/// honours opaque + whiteout + redirect_dir + metacopy - the kernel is the authority, not our code.
///
/// HOW (no box, no `newuidmap`, no pseudo-fs, no external `cp`/`tar`): open an fd on `out_dir` (the copy
/// DESTINATION) FIRST - on the host, before any namespace work - then fork a child that
///   1. `unshare(CLONE_NEWUSER | CLONE_NEWNS)` and writes a SINGLE-UID self map (`0 <euid> 1`) - this
///      alone grants CAP_SYS_ADMIN *inside the new userns*, enough to mount an overlay, WITHOUT the
///      setuid `newuidmap` helper (that's only needed to map a *range* of subuids). No `/etc/subuid`.
///   2. mounts the `chain` as a READ-ONLY overlay (`MS_RDONLY|MS_NODEV|MS_NOSUID`) on a private temp
///      mountpoint. No `/proc`, `/dev`, `/sys` is mounted - so the merged view contains ONLY the image's
///      files (the disk-filling `/proc/<pid>` copy of a box-based approach is not even representable).
///   3. resolves every source path with `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` rooted at the
///      mount - so the untrusted `src_rel` is confined BY CONSTRUCTION: a `..` is kernel-clamped to the
///      mount root, and an in-image symlink with an absolute target (`/app -> /etc`) resolves inside the
///      IMAGE's `/etc`, never the host's. (Both `..`-escape and in-image-absolute-symlink-escape were
///      verified to read host files with a naive `cp`; `RESOLVE_IN_ROOT` closes both - `cp`'s
///      `--no-dereference` only guards the FINAL component, not parent components, so it is NOT enough.)
///   4. copies with an in-process recursive copier (regular files via `copy_file_range` + read/write
///      fallback, directories recursively, symlinks verbatim) into the pre-opened `out_fd` - no external
///      binary, so it works even on a `scratch`/distroless image. `src_rel = None` copies the whole
///      rootfs (push squash); `Some(p)` copies that one path by basename (a `COPY --from`).
///
/// On `_exit` the child's mount+user namespaces die, unmounting the overlay BY CONSTRUCTION (no umount
/// bookkeeping, no leaked mount holding deleted lower files). Only called for a ≥2-layer chain (where
/// cross-layer opaque is possible); a single-layer/flat image is already merged and copied directly.
pub(crate) fn merged_view_extract(
    chain: &[String],
    src_rel: Option<&str>,
    out_dir: &std::path::Path,
) -> Result<(), Error> {
    // `chain` is ALREADY top-first (the caller split `resolve_image`'s `top:…:base` on ':'), and
    // overlayfs `lowerdir=` shadows left-to-right (leftmost wins) - so we join it AS-IS (no reverse).
    // Getting this order wrong silently defeats the opaque (base would shadow top), re-leaking the
    // deleted file. The RO mount needs only lowerdir. The opts CString outlives the fork.
    let lower = chain.join(":"); // top:…:base, order-preserving
    let opts = cstring(&format!("lowerdir={lower}"))?;
    // Defence-in-depth (the kernel `openat2(RESOLVE_IN_ROOT)` already confines every component): reject a
    // `..` path COMPONENT up front with a clear error. `None` = whole-rootfs push.
    if let Some(p) = src_rel {
        if p.trim_start_matches('/').split('/').any(|c| c == "..") {
            return Err(Error::Build(format!(
                "COPY --from source '{p}' contains a '..' component (refused)"
            )));
        }
    }
    // Open the DESTINATION as an fd on the host, BEFORE any namespace work. It stays valid in the child
    // (an fd isn't re-resolved), giving it a handle to the out dir to copy INTO without ever naming a
    // host path - the only host object reachable from the confined child.
    let out_fd = {
        use std::os::unix::io::IntoRawFd;
        std::fs::File::open(out_dir)
            .map_err(|e| Error::Oci(format!("merged-view: open out dir: {e}")))?
            .into_raw_fd()
    };
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    // FORK SAFETY: the child allocates (the copier uses `format!`/`CString`), which is only safe after
    // `fork()` when no OTHER thread could hold the allocator lock - i.e. the process is single-threaded.
    // `kern build`/`push` run on a synchronous single-threaded `main` (background threads live only in the
    // run/box paths), so this holds today. Enforce it as a HARD runtime check (not a debug_assert, which
    // vanishes in release - the fork-safety it guards would then be unprotected exactly in production): a
    // future worker-pool/pre-fork thread gets a clean error here instead of a rare malloc deadlock.
    if !single_threaded() {
        unsafe { libc::close(out_fd) };
        return Err(Error::Oci(
            "merged-view: refusing to fork in a multi-threaded process (fork-safety)".into(),
        ));
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe { libc::close(out_fd) };
        return Err(Error::Oci("merged-view: fork failed".into()));
    }
    if pid == 0 {
        // ---- CHILD: sets up the ns/mount and copies; never returns (always `_exit`). ----
        merged_view_child(&opts, out_fd, src_rel, euid, egid);
    }
    // ---- PARENT: close our copy of the out fd, reap the child, map its exit code to a precise error. ----
    unsafe { libc::close(out_fd) };
    let mut status = 0i32;
    if crate::eintr::waitpid(pid, &mut status, 0) < 0 {
        return Err(Error::Oci("merged-view: waitpid failed".into()));
    }
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        return Ok(());
    }
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    // 107 = openat2 ENOSYS (kernel < 5.6); 108 = the source path doesn't exist in the MERGED view (e.g.
    // an opaque dir correctly hid it); 120 = the tree is nested past MERGED_COPY_MAX_DEPTH. Each gets a
    // precise message; everything else is a generic extract failure with the stage code for diagnosis.
    match code {
        107 => Err(Error::Oci(
            "reading the image's merged view needs openat2 (Linux 5.6+); this kernel is older"
                .into(),
        )),
        108 => Err(Error::Build(
            "COPY --from source does not exist in the stage's final filesystem".into(),
        )),
        120 => Err(Error::Build(
            "COPY --from source tree is nested too deeply (refused)".into(),
        )),
        _ => Err(Error::Oci(format!(
            "reading the image's merged overlay view failed (extract stage {code})"
        ))),
    }
}

/// The forked child of [`merged_view_extract`]. Sets up the namespaces + RO overlay mount, opens the
/// merged view as a dirfd, resolves the source path CONFINED to it via `openat2(RESOLVE_IN_ROOT)`, then
/// copies it into the pre-opened `out_fd` with an in-process recursive copier - NO chroot, NO `/proc`,
/// NO external `cp`/`tar` (so it works even on a `scratch`/distroless image with no binaries). Each
/// failure `_exit`s a distinct code so the parent can pinpoint the stage.
///
/// The child is the only thread in this process after fork (a `kern build` is single-threaded here), so
/// the copier may allocate; the map-writing that precedes it stays allocation-free out of habit and to
/// keep it robust if that ever changes.
pub(crate) fn merged_view_child(
    opts: &std::ffi::CStr,
    out_fd: libc::c_int,
    src_rel: Option<&str>,
    euid: libc::uid_t,
    egid: libc::gid_t,
) -> ! {
    unsafe {
        // 1. New user + mount namespace.
        if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
            libc::_exit(101);
        }
        // Single-uid self map: `deny` setgroups (required before writing gid_map unprivileged), then
        // `0 <euid> 1` / `0 <egid> 1`. Grants CAP_SYS_ADMIN in the new userns with no `newuidmap` helper.
        if !write_proc_self(b"/proc/self/setgroups\0", b"deny")
            || !write_proc_self_map(b"/proc/self/uid_map\0", euid)
            || !write_proc_self_map(b"/proc/self/gid_map\0", egid)
        {
            libc::_exit(102);
        }
        // Make our mount namespace private so the overlay mount can't propagate back to the host.
        if libc::mount(
            c"none".as_ptr(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        ) != 0
        {
            libc::_exit(103);
        }
        // 2. Mount the merged view RO on a private mountpoint (relative to CWD at fork time).
        let mnt = c".kern-merged";
        libc::mkdir(mnt.as_ptr(), 0o700);
        if libc::mount(
            c"overlay".as_ptr(),
            mnt.as_ptr(),
            c"overlay".as_ptr(),
            (libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID) as libc::c_ulong,
            opts.as_ptr() as *const libc::c_void,
        ) != 0
        {
            libc::_exit(104);
        }
        // 3. Open the merged view as a dirfd - the ROOT for all confined source resolution.
        let root_fd = libc::open(mnt.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        if root_fd < 0 {
            libc::_exit(105);
        }
        // 4. Copy. `None` = whole rootfs (push): copy the root dir itself INTO out_fd. `Some(p)` = a
        // single COPY --from path, resolved confined and copied by basename into out_fd.
        let code = match src_rel {
            None => copy_confined_tree(root_fd, ".", out_fd, None, 0),
            Some(p) => {
                let rel = p.trim_start_matches('/');
                // The basename becomes the destination entry name (Docker's `COPY --from x/y .` → `./y`).
                let name = std::path::Path::new(rel)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned());
                copy_confined_tree(root_fd, rel, out_fd, name.as_deref(), 0)
            }
        };
        libc::_exit(code);
    }
}

/// Recursively copy `src_rel` (resolved CONFINED under `root_fd` via `openat2(RESOLVE_IN_ROOT)`) into
/// `dst_fd`. `dst_name` is the destination entry name (COPY --from: the source's basename); `None` means
/// copy the CONTENTS of a directory `src_rel` into `dst_fd` (the whole-rootfs push case, `src_rel="."`).
/// Returns 0 on success or a small non-zero code identifying the failing operation. Preserves regular
/// files (via `copy_file_range` with a read/write fallback), directories (recursive), and symlinks
/// (verbatim, never dereferenced - matching `cp -a`); best-effort mode/owner/mtime; device/fifo are
/// skipped gracefully (rootless can't `mknod`, and they don't appear in a COPY --from binary/tree).
/// Maximum directory nesting the copier will descend. A hostile ≥2-layer image can author an arbitrarily
/// deep tree (`a/a/a/…`); without a cap the recursion would overflow the child's native stack (SIGSEGV,
/// an uncontrolled abort). This bound is far above any real image's depth, so it only ever trips on an
/// adversarial tree, where it returns a clean error code instead of crashing.
pub(crate) const MERGED_COPY_MAX_DEPTH: u32 = 256;

pub(crate) unsafe fn copy_confined_tree(
    root_fd: libc::c_int,
    src_rel: &str,
    dst_fd: libc::c_int,
    dst_name: Option<&str>,
    depth: u32,
) -> i32 {
    if depth > MERGED_COPY_MAX_DEPTH {
        return 120; // too deep - refuse rather than overflow the stack (parent surfaces a clean error)
    }
    // Resolve the source CONFINED to root_fd: `openat2(RESOLVE_IN_ROOT)` clamps `..` to root_fd and
    // reinterprets absolute in-image symlinks relative to it; `RESOLVE_NO_MAGICLINKS` blocks /proc-style
    // magic-link escapes. First open O_PATH|O_NOFOLLOW to classify the entry WITHOUT following a final
    // symlink; then reopen readable with a SECOND openat2 (files/dirs) - reopening an O_PATH fd readable
    // needs /proc (absent here), so a fresh confined openat2 is the clean way.
    let sfd = openat2_in_root(root_fd, src_rel, libc::O_PATH | libc::O_NOFOLLOW);
    if sfd < 0 {
        // The adapter returns `-errno`. ENOSYS → kernel < 5.6 (no openat2): 107 (parent maps to a precise
        // hint). ENOENT / RESOLVE refusal → 108 (a confined "no such file" - e.g. an opaque dir correctly
        // hid the source).
        return if sfd == -libc::ENOSYS { 107 } else { 108 };
    }
    let mut st: libc::stat = std::mem::zeroed();
    if libc::fstatat(sfd, c"".as_ptr(), &mut st, libc::AT_EMPTY_PATH) != 0 {
        libc::close(sfd);
        return 109;
    }
    match st.st_mode & libc::S_IFMT {
        // Read the symlink target straight off the O_PATH classify fd (AT_EMPTY_PATH) - confined by the
        // same openat2 that opened it, so no bare `readlinkat(root_fd, path)` re-resolution is needed.
        libc::S_IFLNK => {
            let rc = copy_one_symlink(sfd, dst_fd, dst_name);
            libc::close(sfd);
            rc
        }
        libc::S_IFDIR => {
            libc::close(sfd); // reopened readable inside copy_one_dir via a fresh confined openat2
            copy_one_dir(root_fd, src_rel, dst_fd, dst_name, &st, depth)
        }
        libc::S_IFREG => {
            libc::close(sfd);
            copy_one_file(root_fd, src_rel, dst_fd, dst_name, &st)
        }
        _ => {
            libc::close(sfd);
            0 // device/fifo/socket: skip (rootless can't recreate; absent in a COPY --from tree)
        }
    }
}

/// Thin `c_int`-returning adapter over the shared [`crate::openat2::openat2_in_root`] confinement
/// primitive, for the post-fork copier which speaks raw fds + numeric exit codes (not `io::Result`).
/// Returns the fd, or `-errno` so the caller can distinguish `ENOSYS` (pre-5.6 kernel) from `ENOENT`.
pub(crate) fn openat2_in_root(root_fd: libc::c_int, path: &str, flags: libc::c_int) -> libc::c_int {
    match crate::openat2::openat2_in_root(root_fd, path, flags, 0) {
        Ok(fd) => fd,
        Err(e) => -e.raw_os_error().unwrap_or(libc::EINVAL),
    }
}

/// Copy a symlink SOURCE verbatim (read its target off the already-confined O_PATH `src_fd`, recreate
/// with `symlinkat`). Never dereferenced - identical to `cp -a`, and reads nothing at the target. Reading
/// via `readlinkat(src_fd, "", AT_EMPTY_PATH)` keeps confinement BY CONSTRUCTION: `src_fd` came from
/// `openat2(RESOLVE_IN_ROOT)`, so there is no bare path re-resolution that could follow a symlinked parent.
pub(crate) unsafe fn copy_one_symlink(
    src_fd: libc::c_int,
    dst_fd: libc::c_int,
    dst_name: Option<&str>,
) -> i32 {
    let Some(name) = dst_name else { return 0 }; // a symlink has no "contents" to splat into a dir
    let mut buf = [0u8; libc::PATH_MAX as usize];
    let n = libc::readlinkat(
        src_fd,
        c"".as_ptr(),
        buf.as_mut_ptr() as *mut libc::c_char,
        buf.len() - 1,
    );
    if n < 0 {
        return 110;
    }
    buf[n as usize] = 0;
    let Ok(name_c) = std::ffi::CString::new(name) else {
        return 111;
    };
    if libc::symlinkat(buf.as_ptr() as *const libc::c_char, dst_fd, name_c.as_ptr()) != 0 {
        return 112;
    }
    0
}

/// Copy a directory: create it in `dst_fd` (or reuse `dst_fd` when `dst_name` is `None` - the whole-
/// rootfs push copies contents in place), then recurse. The source is reopened readable via a fresh
/// confined `openat2` (O_DIRECTORY); each child recurses via its path under the merged root, so every
/// component stays confined by `RESOLVE_IN_ROOT`.
pub(crate) unsafe fn copy_one_dir(
    root_fd: libc::c_int,
    src_rel: &str,
    dst_fd: libc::c_int,
    dst_name: Option<&str>,
    st: &libc::stat,
    depth: u32,
) -> i32 {
    // Destination dir fd: a freshly-created subdir, or `dst_fd` itself (contents-in-place).
    let child_dst = match dst_name {
        Some(name) => {
            let Ok(name_c) = std::ffi::CString::new(name) else {
                return 111;
            };
            libc::mkdirat(dst_fd, name_c.as_ptr(), st.st_mode & 0o7777);
            let fd = libc::openat(
                dst_fd,
                name_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            );
            if fd < 0 {
                return 113;
            }
            fd
        }
        None => libc::dup(dst_fd),
    };
    // Reopen the source dir readable (confined). `.` resolves to the merged root itself for the push case.
    let src_read = openat2_in_root(root_fd, src_rel, libc::O_RDONLY | libc::O_DIRECTORY);
    if src_read < 0 {
        libc::close(child_dst);
        return 114;
    }
    let dirp = libc::fdopendir(src_read);
    if dirp.is_null() {
        libc::close(src_read);
        libc::close(child_dst);
        return 115;
    }
    let mut rc = 0;
    loop {
        let ent = libc::readdir(dirp);
        if ent.is_null() {
            break;
        }
        let name_ptr = (*ent).d_name.as_ptr();
        // Skip "." and "..".
        let b0 = *name_ptr as u8;
        let b1 = *name_ptr.add(1) as u8;
        if b0 == b'.' && (b1 == 0 || (b1 == b'.' && *name_ptr.add(2) as u8 == 0)) {
            continue;
        }
        let name_bytes = std::ffi::CStr::from_ptr(name_ptr).to_bytes();
        let Ok(child_name) = std::str::from_utf8(name_bytes) else {
            rc = 116;
            break;
        };
        // Child path under the merged root: `src_rel/child` (or just `child` when src_rel is ".").
        let child_rel = if src_rel == "." {
            child_name.to_string()
        } else {
            format!("{src_rel}/{child_name}")
        };
        let child_rc =
            copy_confined_tree(root_fd, &child_rel, child_dst, Some(child_name), depth + 1);
        if child_rc != 0 {
            rc = child_rc;
            break;
        }
    }
    libc::closedir(dirp); // also closes src_read
                          // Best-effort preserve dir mode/owner AFTER populating, so it isn't undone.
    if let Some(name) = dst_name {
        if let Ok(name_c) = std::ffi::CString::new(name) {
            libc::fchmodat(dst_fd, name_c.as_ptr(), st.st_mode & 0o7777, 0);
            libc::fchownat(
                dst_fd,
                name_c.as_ptr(),
                st.st_uid,
                st.st_gid,
                libc::AT_SYMLINK_NOFOLLOW,
            );
        }
    }
    libc::close(child_dst);
    rc
}

/// Copy a regular file: reopen the source readable (confined), create the dest, copy bytes with
/// `copy_file_range` (reflink/fast path) falling back to read/write, then preserve owner/mtime.
pub(crate) unsafe fn copy_one_file(
    root_fd: libc::c_int,
    src_rel: &str,
    dst_fd: libc::c_int,
    dst_name: Option<&str>,
    st: &libc::stat,
) -> i32 {
    let Some(name) = dst_name else { return 0 };
    let Ok(name_c) = std::ffi::CString::new(name) else {
        return 111;
    };
    let rfd = openat2_in_root(root_fd, src_rel, libc::O_RDONLY | libc::O_NOFOLLOW);
    if rfd < 0 {
        return 117;
    }
    let dfd = libc::openat(
        dst_fd,
        name_c.as_ptr(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW,
        (st.st_mode & 0o7777) as libc::c_uint,
    );
    if dfd < 0 {
        libc::close(rfd);
        return 118;
    }
    // copy_file_range (kernel reflink/fast copy); fall back to read/write on ENOSYS/EXDEV/short copy.
    let mut remaining = st.st_size as usize;
    let mut ok = true;
    while remaining > 0 {
        let n = libc::copy_file_range(
            rfd,
            std::ptr::null_mut(),
            dfd,
            std::ptr::null_mut(),
            remaining,
            0,
        );
        if n > 0 {
            remaining -= n as usize;
        } else if n == 0 {
            break; // EOF
        } else {
            ok = false;
            break;
        }
    }
    if !ok {
        // read/write fallback from the start.
        libc::lseek(rfd, 0, libc::SEEK_SET);
        libc::ftruncate(dfd, 0);
        let mut buf = [0u8; 1 << 16];
        loop {
            let r = libc::read(rfd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
            if r < 0 {
                libc::close(rfd);
                libc::close(dfd);
                return 119;
            }
            if r == 0 {
                break;
            }
            let mut off = 0isize;
            while off < r {
                let w = libc::write(
                    dfd,
                    buf.as_ptr().offset(off) as *const libc::c_void,
                    (r - off) as usize,
                );
                if w <= 0 {
                    libc::close(rfd);
                    libc::close(dfd);
                    return 119;
                }
                off += w;
            }
        }
    }
    // Carry `user.*` xattrs (application metadata, harmless) - best-effort, BEFORE owner/mtime. We do
    // NOT carry `security.capability`: file-capabilities are a privilege channel exactly like setuid, and
    // the source image is UNTRUSTED (a hostile `COPY --from`/push base could ship `/bin/sh` with
    // `cap_setuid+ep` → escalation in the copied/published image, and file-caps bypass the box's
    // MS_NOSUID unlike setuid). kern's model grants no file-caps at runtime, so dropping them removes an
    // injection vector without losing anything usable - the same call kern makes for setuid (stripped at
    // push). `system.*`/`trusted.*` are skipped too (need privilege, not ours to propagate).
    copy_xattrs(rfd, dfd);
    // Preserve owner + mtime best-effort (mode was set at create time).
    libc::fchown(dfd, st.st_uid, st.st_gid);
    let times = [
        libc::timespec {
            tv_sec: st.st_atime,
            tv_nsec: st.st_atime_nsec,
        },
        libc::timespec {
            tv_sec: st.st_mtime,
            tv_nsec: st.st_mtime_nsec,
        },
    ];
    libc::futimens(dfd, times.as_ptr());
    libc::close(rfd);
    libc::close(dfd);
    0
}

/// `CString` from a `&str`, mapping interior-NUL to an OCI error (a path/opt with a NUL is invalid).
pub(crate) fn cstring(s: &str) -> Result<std::ffi::CString, Error> {
    std::ffi::CString::new(s).map_err(|_| Error::Oci("merged-view: NUL in path".into()))
}

/// `true` if this process has exactly one thread - read from `/proc/self/stat`'s `num_threads` field.
/// Guards the fork-safety invariant of [`merged_view_extract`] via a HARD runtime check (it returns an
/// error if false - NOT a debug_assert, which would vanish in release where the guard matters most).
/// Best effort: if `/proc` is unreadable we assume single-threaded (don't refuse a legitimate run).
pub(crate) fn single_threaded() -> bool {
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
        return true;
    };
    // Fields after the (possibly space/paren-bearing) comm are space-separated; num_threads is field 20
    // (1-indexed), i.e. the 18th field AFTER the closing ')'. Parse from the last ')' to avoid comm spaces.
    let Some(rest) = stat.rsplit_once(')').map(|(_, r)| r.trim_start()) else {
        return true;
    };
    rest.split_whitespace()
        .nth(17) // state(1) … num_threads is the 18th token after comm
        .and_then(|n| n.parse::<i64>().ok())
        .map(|n| n <= 1)
        .unwrap_or(true)
}

/// Rewrite each service's RELATIVE bind-mount source to an absolute path under the compose file's
/// directory (Docker's rule), so kern's `-v` - which wants an absolute path or a named volume -
/// accepts the common `./dir:/dst` / `.:/app` compose form. A source that is already absolute (`/…`),
/// or a bare NAME (a named volume, no `/` and no leading `.`), is left untouched. The resolved path is
/// CONFINED under the compose dir (canonicalize + starts_with, same traversal guard as a build
/// context) so a `../../../etc:/x` can't escape the project tree.
pub(crate) fn resolve_relative_binds(
    boxes: &mut [crate::compose::ComposeBox],
    file: &str,
) -> Result<(), Error> {
    let base = std::fs::canonicalize(compose_dir(file))
        .map_err(|e| Error::Compose(format!("resolving compose dir: {e}")))?;

    for b in boxes.iter_mut() {
        for v in b.volumes.iter_mut() {
            // Split `src:dst[:opts]`. The source is the first segment; dst/opts follow.
            let (src, rest) = match v.split_once(':') {
                Some((s, r)) => (s, r),
                None => continue, // malformed spec - let `kern box` report it precisely
            };
            // Classify the source. A leading `/` is absolute (left as-is). A bare NAME with no `/` is a
            // named volume (left as-is; the box validates it). ANYTHING ELSE containing `/` is a
            // relative PATH and must be confined - not just the `./`/`../` forms: a source like
            // `foo/../../../etc` is relative but doesn't start with `./`, and the old check let it skip
            // the guard (the box's name-validator caught it as a backstop, but defense-in-depth wants
            // the compose layer to confine every relative path itself). (Hacker-mode audit, MEDIUM.)
            // `.` and `..` are relative PATHS with no slash in them, so the "no slash means named
            // volume" rule sent the single most common bind in existence (`.:/app`, mount the project
            // root) to the volume-name validator, which refused it. Docker resolves both against the
            // project directory. Anything else without a slash really is a named volume.
            let is_dot = src == "." || src == "..";
            if !is_dot && (src.starts_with('/') || !src.contains('/')) {
                continue;
            }
            // Docker CREATES a missing relative bind source. Refusing broke the most ordinary
            // workflow there is: clone a repo whose compose file says `./data:/var/lib/mysql`, and
            // `up` failed because `./data` does not exist yet. We create it too, but SAY SO - Docker
            // creating directories silently is how a typo'd path becomes an empty mount nobody
            // notices. Only under the compose directory, and only for a path that is relative, so the
            // traversal guard below still decides what is allowed.
            let target = base.join(src);
            // Containment is checked LEXICALLY first, BEFORE creating anything: `canonicalize` needs
            // the path to exist, so a `../x` source would otherwise have its directory created and
            // only then be refused - a filesystem side effect outside the project, caused by the very
            // input we are about to reject.
            // Walk the components keeping a depth counter: a `..` at depth 0 would step above the
            // project, so `try_fold` short-circuits to `None` and that IS the escape.
            let escapes = src
                .split('/')
                .try_fold(0i32, |depth, seg| match seg {
                    "" | "." => Some(depth),
                    ".." => (depth > 0).then_some(depth - 1),
                    _ => Some(depth + 1),
                })
                .is_none();
            if escapes {
                return Err(Error::Compose(format!(
                    "service '{}': bind source '{src}' escapes the compose directory (refused)",
                    b.name
                )));
            }
            if !target.exists() {
                std::fs::create_dir_all(&target).map_err(|e| {
                    Error::Compose(format!(
                        "service '{}': bind source '{src}' does not exist and could not be created: {e}",
                        b.name
                    ))
                })?;
                eprintln!(
                    "kern compose: service '{}': created missing bind source '{src}'",
                    b.name
                );
            }
            let abs = std::fs::canonicalize(&target).map_err(|e| {
                Error::Compose(format!("service '{}': bind source '{src}': {e}", b.name))
            })?;
            if !abs.starts_with(&base) {
                return Err(Error::Compose(format!(
                    "service '{}': bind source '{src}' escapes the compose directory (refused)",
                    b.name
                )));
            }
            *v = format!("{}:{rest}", abs.to_string_lossy());
        }
        // Compose `secrets:` map to `--secret <file>:<name>`; `<file>` came from a top-level `file: ./x`
        // and is relative → resolve against the compose dir, same traversal guard as a bind.
        for s in b.secrets.iter_mut() {
            let Some((file, nm)) = s.split_once(':') else {
                continue;
            };
            if file.starts_with('/') {
                continue; // already absolute
            }
            let abs = std::fs::canonicalize(base.join(file)).map_err(|e| {
                Error::Compose(format!("service '{}': secret file '{file}': {e}", b.name))
            })?;
            if !abs.starts_with(&base) {
                return Err(Error::Compose(format!(
                    "service '{}': secret file '{file}' escapes the compose directory (refused)",
                    b.name
                )));
            }
            *s = format!("{}:{nm}", abs.to_string_lossy());
        }
    }
    Ok(())
}

/// Walk a squashed rootfs and honour any OCI whiteout marker that survived the merge: `.wh.<name>`
/// deletes its sibling `<name>` (and itself), `.wh..wh..opq` clears its directory's contents. In
/// kern's model the chain has none (see the invariant at the call site), so this is a no-op belt -
/// but if a future layer format leaves whiteouts, this keeps a deleted file from being republished.
/// Best-effort, non-following (never descends a symlink), depth-first.
pub(crate) fn strip_whiteout_markers(root: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        let ft = match e.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if name == ".wh..wh..opq" {
            // Opaque dir marker: drop it (its "hide everything below" is already reflected in the
            // merged view we squashed; the marker itself must not ship).
            let _ = std::fs::remove_file(e.path());
            continue;
        }
        if let Some(victim) = name.strip_prefix(".wh.") {
            // Whiteout: remove the shadowed sibling (if it somehow got copied) and the marker.
            if !victim.is_empty() && !victim.contains('/') {
                let sib = root.join(victim);
                if sib.is_dir() {
                    let _ = std::fs::remove_dir_all(&sib);
                } else {
                    let _ = std::fs::remove_file(&sib);
                }
            }
            let _ = std::fs::remove_file(e.path());
            continue;
        }
        // Recurse into real subdirectories (not symlinks - no-follow).
        if ft.is_dir() {
            strip_whiteout_markers(&e.path());
        }
    }
}

pub(crate) fn own_only_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// Apply a Dockerfile `--chmod=<octal>` to a file the build just CREATED (an ADD-url download or a
/// COPY-heredoc body), so `ADD --chmod=755 <url> /bin/tool` lands executable (the download-and-run
/// pattern) - curl/`std::fs::write` create it 0644 otherwise. `None` = no flag, leave the mode as-is.
/// The octal is parsed leniently (`755`, `0755`, `0o755`); a non-octal mode is a clear error.
pub(crate) fn apply_chmod(path: &std::path::Path, mode: Option<&str>) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let Some(mode) = mode else { return Ok(()) };
    let cleaned = mode.trim().trim_start_matches("0o");
    let bits = u32::from_str_radix(cleaned, 8).map_err(|_| {
        Error::Sandbox(format!(
            "--chmod: invalid mode '{mode}' (use an octal mode like 755 or 0644)"
        ))
    })?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits))
        .map_err(|e| Error::Sandbox(format!("--chmod {mode}: {e}")))
}

/// Apply a context/`--from` COPY's `--chmod=<octal>` to everything just copied at `target`: the file,
/// or a directory AND its whole subtree - Docker's `--chmod` is recursive. `None` = no flag, leave the
/// copied modes as-is. Symlinks are SKIPPED (never chmod THROUGH a symlink - the same no-follow
/// invariant the `cp -a`/`copy_dir_filtered` copy upholds, so a `leak -> /host` in the context can't be
/// used to chmod a host file). Directories are chmod'd AFTER their children so a restrictive mode
/// (e.g. 0644) on the dir can't block our own descent.
pub(crate) fn apply_chmod_tree(target: &std::path::Path, mode: Option<&str>) -> Result<(), Error> {
    let Some(mode) = mode else { return Ok(()) };
    let cleaned = mode.trim().trim_start_matches("0o");
    let bits = u32::from_str_radix(cleaned, 8).map_err(|_| {
        Error::Sandbox(format!(
            "--chmod: invalid mode '{mode}' (use an octal mode like 755 or 0644)"
        ))
    })?;
    chmod_tree_bits(target, bits);
    Ok(())
}

pub(crate) fn chmod_tree_bits(path: &std::path::Path, bits: u32) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(md) = std::fs::symlink_metadata(path) else {
        return;
    };
    if md.file_type().is_symlink() {
        return; // never follow/chmod a symlink
    }
    if md.is_dir() {
        if let Ok(rd) = std::fs::read_dir(path) {
            for e in rd.flatten() {
                chmod_tree_bits(&e.path(), bits);
            }
        }
    }
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits));
}

/// Max bytes of the overlay `lowerdir=` chain - the mount-options buffer is ~one page (4 KiB); this
/// leaves headroom for `upperdir=`/`workdir=` so a long build/image chain fails with our clear error
/// instead of a cryptic kernel `EINVAL`.
pub(crate) const MAX_LOWERDIR_BYTES: usize = 3500;

/// The persistent overlay upper dir under a `kern build` work/`--overlay-upper` root - the ONE place
/// this layout convention lives, shared by [`build_run`] (writes COPY/WORKDIR here) and [`build_spec`]
/// (mounts it as the RUN box's overlay upperdir) so the two can't silently desync.
pub(crate) fn build_upper_dir(overlay_root: &std::path::Path) -> PathBuf {
    overlay_root.join("upper")
}

/// Remove a build work tree. overlayfs leaves its workdir's inner `work/` at mode `000`, which a
/// plain `remove_dir_all` can't traverse (→ a leaked `.build-*` dir on disk). We own every entry, so
/// chmod each directory back to `0700` before recursing, then remove.
pub(crate) fn remove_build_tree(path: &std::path::Path) {
    fn chmod_dirs(p: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    chmod_dirs(&e.path());
                }
            }
        }
    }
    chmod_dirs(path);
    let _ = std::fs::remove_dir_all(path);
}

/// Probe whether an unprivileged overlay with a persistent upper actually mounts on this kernel (a
/// tiny `true`-box over `base_lower`). Decides layered-vs-flat build up front. Best-effort; any
/// failure → `false` → the flat copy path.
/// `true` if this kernel HONOURS an overlay opaque directory in a rootless (single-uid userns) mount -
/// i.e. after `rm -rf dir && mkdir dir` on a dir that lives in a lower layer, the lower's files are
/// hidden from the merged view. Tested once, in-process (fork + `unshare(CLONE_NEWUSER|NEWNS)` +
/// single-uid self-map + a throwaway 2-dir overlay), so it needs no `newuidmap` and mirrors exactly what
/// a build layer does. Returns `true` on a modern kernel (a sub-ms check); `false` on a kernel that
/// silently omits the opaque (measured: tegra 5.15) - where the caller must NOT build layered, or a
/// deleted file would leak into a `COPY --from`/push. Best-effort: if the probe itself can't run
/// (no unpriv userns at all - but then `probe_overlay` already said no), we return `false` (fail-closed).
pub(crate) fn probe_opaque_honored() -> bool {
    let tmp = cache_dir().join(format!(".opaque-probe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    // lower/dir/secret + empty upper/work + a merge target. If mkdir fails we can't probe → fail-closed.
    let mk = |p: &std::path::Path| std::fs::create_dir_all(p).is_ok();
    if !(mk(&tmp.join("lower/dir"))
        && mk(&tmp.join("up"))
        && mk(&tmp.join("wk"))
        && mk(&tmp.join("mg")))
    {
        remove_build_tree(&tmp);
        return false;
    }
    if std::fs::write(tmp.join("lower/dir/secret"), b"x").is_err() {
        remove_build_tree(&tmp);
        return false;
    }
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };
    // The child does the ns/mount/rm and _exits 0 iff the opaque IS honoured (secret hidden). Any failure
    // (mount error, opaque not honoured, secret still visible) → non-zero → fail-closed.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        remove_build_tree(&tmp);
        return false;
    }
    if pid == 0 {
        unsafe { probe_opaque_child(&tmp, euid, egid) };
    }
    let mut status = 0i32;
    let waited = crate::eintr::waitpid(pid, &mut status, 0);
    remove_build_tree(&tmp);
    waited == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

pub(crate) fn probe_overlay(
    self_exe: &std::path::Path,
    base_lower: &str,
    work: &std::path::Path,
) -> bool {
    let probe = work.join(".probe");
    let ok = std::process::Command::new(self_exe)
        .env("KERN_BUILD_STEP", "1") // no transient scope for the throwaway probe box
        .arg("box")
        .arg(format!("_probe-{}", std::process::id()))
        .arg("--overlay-lower")
        .arg(base_lower)
        .arg("--overlay-upper")
        .arg(&probe)
        .arg("--quiet")
        .arg("--")
        .arg("true")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    remove_build_tree(&probe); // the probe leaves a mode-000 overlay workdir too
    ok
}

/// Does the filesystem holding `dir` support copy-on-write clones?
///
/// `Some(true)` a clone succeeded, `Some(false)` the filesystem refused it, `None` the probe could
/// not run and nothing may be concluded from that.
///
/// ## Why this is worth knowing
///
/// [`copy_tree`] passes `--reflink=auto`, which makes the flat build's base copy nearly free on
/// btrfs, xfs and bcachefs and a FULL BYTE COPY everywhere else - silently, because `auto` is
/// defined to fall back without complaining. That single property decides whether a flat build of a
/// 2 GB base costs milliseconds or minutes, and nothing anywhere said which one the operator was
/// getting. A field report measured 2m49s and 1.9 GB re-copied per build and could not tell whether
/// it was a property of kern or of their host; it is neither, it is the filesystem.
///
/// ## Why `cp` and not the `FICLONE` ioctl
///
/// The ioctl would avoid a process spawn, and its request number would have to be written out here
/// as a literal because it is not exposed by every version of the `libc` crate. Probing with the
/// SAME tool `copy_tree` actually uses answers the question that matters - "will the copy this code
/// is about to run be cheap" - instead of a related one, and it cannot drift from it. The cost is
/// one spawn on a path that is either `doctor` or a build already measured in seconds.
pub(crate) fn supports_reflink(dir: &std::path::Path) -> Option<bool> {
    let stamp = format!(".kern-reflink-{}", std::process::id());
    let src = dir.join(format!("{stamp}.src"));
    let dst = dir.join(format!("{stamp}.dst"));
    // A one-byte file: a clone is a metadata operation, so the size decides nothing, and the smaller
    // the file the less a fallback copy could cost if `cp` ignored `always`.
    if std::fs::write(&src, b"k").is_err() {
        return None; // cannot write here at all: the probe measured nothing
    }
    let _ = std::fs::remove_file(&dst); // a leftover would make `cp` refuse for the wrong reason
    let out = std::process::Command::new("cp")
        .arg("--reflink=always")
        .arg("--")
        .arg(&src)
        .arg(&dst)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
    match out {
        Ok(st) => Some(st.success()),
        // `cp` is missing or could not be spawned. `copy_tree` would fail for the same reason and
        // says so; here there is simply no answer.
        Err(_) => None,
    }
}

/// `cp -a src/. dst` - copy the CONTENTS of `src` into the existing `dst`, preserving symlinks,
/// modes and timestamps (used to make a mutable copy of the pulled base rootfs).
pub(crate) fn copy_tree(src: &std::path::Path, dst: &std::path::Path) -> Result<(), Error> {
    std::fs::create_dir_all(dst).map_err(|e| Error::Sandbox(format!("build rootfs: {e}")))?;
    let ok = std::process::Command::new("cp")
        .arg("-a")
        .arg("--reflink=auto") // copy-on-write clone on btrfs/xfs (near-free); plain copy elsewhere
        .arg("--") // paths are absolute, but stop cp treating any of them as a flag
        .arg(format!("{}/.", src.display()))
        .arg(dst)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(Error::Sandbox(
            "copying the base rootfs failed (is `cp` available?)".into(),
        ))
    }
}

/// Whether a COPY/ADD source token carries a glob metacharacter Docker expands (`*`, `?`, `[`).
pub(crate) fn has_glob_meta(s: &str) -> bool {
    s.bytes().any(|b| b == b'*' || b == b'?' || b == b'[')
}

/// `filepath.Match`-style match of ONE path component (never spans `/`, like Docker's COPY glob):
/// `*` = any run, `?` = one char, `[set]`/`[!set]` = a class (with `a-z` ranges). Patterns are short.
pub(crate) fn glob_match_component(pat: &[u8], name: &[u8]) -> bool {
    if pat.is_empty() {
        return name.is_empty();
    }
    match pat[0] {
        b'*' => {
            glob_match_component(&pat[1..], name)
                || (!name.is_empty() && glob_match_component(pat, &name[1..]))
        }
        b'?' => !name.is_empty() && glob_match_component(&pat[1..], &name[1..]),
        b'[' => {
            if name.is_empty() {
                return false;
            }
            let neg = pat.get(1) == Some(&b'!');
            let mut i = if neg { 2 } else { 1 };
            let start = i;
            let mut hit = false;
            while i < pat.len() && (pat[i] != b']' || i == start) {
                if i + 2 < pat.len() && pat[i + 1] == b'-' && pat[i + 2] != b']' {
                    if name[0] >= pat[i] && name[0] <= pat[i + 2] {
                        hit = true;
                    }
                    i += 3;
                } else {
                    if pat[i] == name[0] {
                        hit = true;
                    }
                    i += 1;
                }
            }
            if i >= pat.len() {
                return false; // unterminated class → no match
            }
            (hit != neg) && glob_match_component(&pat[i + 1..], &name[1..])
        }
        c => !name.is_empty() && name[0] == c && glob_match_component(&pat[1..], &name[1..]),
    }
}

/// Expand a COPY source pattern (context-relative, `/`-separated) into matching relative paths, one
/// component at a time (Docker matches `filepath.Match` per component). A component with no glob meta
/// is taken literally. Sorted; empty if nothing matched.
pub(crate) fn glob_expand_ctx(ctx: &std::path::Path, pattern: &str) -> Vec<String> {
    let comps: Vec<&str> = pattern
        .trim_start_matches("./")
        .split('/')
        .filter(|c| !c.is_empty())
        .collect();
    let mut cur = vec![String::new()];
    for comp in comps {
        let mut next = Vec::new();
        for base in &cur {
            let base_dir = if base.is_empty() {
                ctx.to_path_buf()
            } else {
                ctx.join(base)
            };
            if has_glob_meta(comp) {
                if let Ok(rd) = std::fs::read_dir(&base_dir) {
                    for e in rd.flatten() {
                        let nm = e.file_name();
                        let nm = nm.to_string_lossy();
                        if glob_match_component(comp.as_bytes(), nm.as_bytes()) {
                            next.push(if base.is_empty() {
                                nm.into_owned()
                            } else {
                                format!("{base}/{nm}")
                            });
                        }
                    }
                }
            } else {
                let cand = if base.is_empty() {
                    comp.to_string()
                } else {
                    format!("{base}/{comp}")
                };
                if ctx.join(&cand).symlink_metadata().is_ok() {
                    next.push(cand);
                }
            }
        }
        cur = next;
    }
    cur.sort();
    cur
}

/// Expand any glob sources in a context COPY/ADD `srcs` list against `ctx`; literal sources pass
/// through unchanged. Errors if a glob matches nothing (Docker: "no source files were specified").
pub(crate) fn expand_copy_srcs(
    ctx: &std::path::Path,
    srcs: &[String],
) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    for s in srcs {
        if has_glob_meta(s) {
            let m = glob_expand_ctx(ctx, s);
            if m.is_empty() {
                return Err(Error::Sandbox(format!("COPY: no source files match '{s}'")));
            }
            out.extend(m);
        } else {
            out.push(s.clone());
        }
    }
    Ok(out)
}

/// Copy `src_rel` (relative to the build context) into the build `rootfs` at `dst`, refusing to
/// escape the context (source) or traverse a symlinked component of the image (destination). A
/// relative `dst` (e.g. `COPY x .`) resolves against the current `workdir` (Docker semantics).
/// Drop the `.` and empty segments a path join creates, leaving `..` ALONE.
///
/// `..` is deliberately kept: `sanitize_rootfs_rel` refuses it, and resolving it here would quietly
/// turn a rejected escape into an accepted write.
pub(crate) fn collapse_dot_segments(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        out.push('/');
        out.push_str(seg);
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

pub(crate) fn copy_into_rootfs(
    ctx: &std::path::Path,
    src_rel: &str,
    rootfs: &std::path::Path,
    dst: &str,
    workdir: Option<&str>,
    chain: &[String],
    chmod: Option<&str>,
) -> Result<(), Error> {
    // Source must resolve to a real path INSIDE the context (no `../`, no symlink pointing out).
    let src = std::fs::canonicalize(ctx.join(src_rel))
        .map_err(|e| Error::Sandbox(format!("COPY source '{src_rel}': {e}")))?;
    if !src.starts_with(ctx) {
        return Err(Error::Sandbox(format!(
            "COPY source '{src_rel}' escapes the build context"
        )));
    }
    // A relative destination is taken against the current WORKDIR (default `/`).
    let dst_abs = if dst.starts_with('/') {
        dst.to_string()
    } else {
        format!("{}/{}", workdir.unwrap_or("/").trim_end_matches('/'), dst)
    };
    // Then the `.` segments that join just created are dropped. `WORKDIR /app` + `COPY . .` builds
    // `/app/.`, and `cp` fails trying to create a directory literally named `.` - which broke the
    // single most common shape an application Dockerfile has. `COPY . /app` and `COPY main.py .`
    // both worked, which is why it survived: only a DIRECTORY source with a relative dot
    // destination under a non-root WORKDIR hits it.
    let dst_abs = collapse_dot_segments(&dst_abs);
    // Destination resolution (Docker semantics, verified against `docker build`):
    //   - a FILE into a directory dest keeps its basename → `dst/<file>`.
    //   - a DIRECTORY source has its CONTENTS copied into dest (`COPY dir /d/` → `/d/<contents>`,
    //     NEVER `/d/dir`); the `cp -a src/.` below fills `dst` directly, so a dir targets `dst` itself.
    //   - a FILE to a non-dir dest is a rename → `dst`.
    // `rootfs` is this unit's fresh (empty) layer, so a dir that exists only in a LOWER layer is found
    // via `chain` (the cached-layer build); the flat build passes an empty chain.
    let dst_clean = dst_abs.trim_start_matches('/');
    let dst_is_dir =
        dst.ends_with('/') || rootfs.join(dst_clean).is_dir() || chain_has_dir(chain, dst_clean);
    let target_rel = if dst_is_dir && !src.is_dir() {
        let base = src
            .file_name()
            .ok_or(Error::Sandbox("COPY source has no file name".into()))?;
        format!(
            "{}/{}",
            dst_clean.trim_end_matches('/'),
            base.to_string_lossy()
        )
    } else {
        dst_clean.trim_end_matches('/').to_string()
    };
    // Reject `..` (and re-strip any leading `/` the dir-branch reintroduced): a `..` component is a
    // real directory, so `whiteout_dir_symlink_free` (symlinks only) waves it through, and
    // `rootfs.join(..)` / `cp` would then escape the rootfs to write anywhere on the host.
    let target_rel = sanitize_rootfs_rel(dst, &target_rel)?;
    // No symlinked component in the target's parent may lead out of the rootfs (image could plant
    // `dst -> /host`). Then create the parents as REAL dirs and copy.
    let parent_rel = std::path::Path::new(&target_rel)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !kern_oci::whiteout_dir_symlink_free(&rootfs.to_string_lossy(), &parent_rel) {
        return Err(Error::Sandbox(format!(
            "COPY dest '{dst}' crosses a symlink in the image"
        )));
    }
    let target = rootfs.join(&target_rel);
    if let Some(p) = target.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    // If the target itself is an existing symlink, unlink it so we don't copy THROUGH it out of the
    // rootfs (COPY overwrites the name, following Docker).
    if let Ok(m) = std::fs::symlink_metadata(&target) {
        if m.file_type().is_symlink() {
            let _ = std::fs::remove_file(&target);
        }
    }
    // When the build context carries a `.dockerignore`/`.kernignore`, a directory COPY must skip the
    // excluded paths (so `COPY . /app` doesn't bake `.git`/secrets). The filter needs re-include
    // (`!`) and last-match-wins semantics that `cp`/`tar --exclude` can't express, so a directory copy
    // with an ignore file present goes through a no-follow Rust walk instead of `cp -a`. With NO ignore
    // file (the common case) the fast `cp -a` path below is unchanged.
    if src.is_dir() {
        if let Some(ig) = crate::dockerignore::DockerIgnore::load(ctx) {
            let _ = std::fs::create_dir_all(&target);
            // Match ignore paths relative to the CANONICAL context root: `src` is already canonicalized,
            // so a symlinked context path (e.g. `/tmp` -> `/private/tmp`, or a symlinked project dir)
            // would otherwise make `strip_prefix` fail and silently disable filtering - a fail-OPEN
            // that would leak the very secrets the ignore file exists to keep out. Falls back to raw
            // `ctx` only if canonicalize fails (then the walk fails CLOSED on any un-strippable entry).
            let ctx_root = std::fs::canonicalize(ctx).unwrap_or_else(|_| ctx.to_path_buf());
            copy_dir_filtered(&src, &target, &ctx_root, &ig)
                .map_err(|e| Error::Sandbox(format!("COPY '{src_rel}' → '{dst}': {e}")))?;
            return apply_chmod_tree(&target, chmod);
        }
    }
    let arg = if src.is_dir() {
        let _ = std::fs::create_dir_all(&target);
        format!("{}/.", src.display())
    } else {
        src.to_string_lossy().into_owned()
    };
    // SECURITY INVARIANT (do not break): `cp -a` implies `--no-dereference` - it PRESERVES symlinks in
    // the copied tree rather than following them. This is load-bearing for the build-context confinement
    // (the "duale-di-Z2" note in `resolve_builds`): the COPY source root is confined by canonicalize +
    // starts_with, and because the recursive descent here does NOT follow inner symlinks, a symlink
    // buried in the context lands in the image verbatim (dangling in the pivoted rootfs) and its host
    // target is never read at build time. If this `cp -a` is ever replaced (e.g. a Rust `walkdir` copy
    // for portability), that replacement MUST be no-follow too, or a `leak -> /host/secret` inside a
    // build context would leak the host file into the image. Verified live: it does not, today.
    let ok = std::process::Command::new("cp")
        .arg("-a")
        .arg("--") // src/target are absolute, but never let cp parse them as flags
        .arg(&arg)
        .arg(&target)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        apply_chmod_tree(&target, chmod)
    } else {
        Err(Error::Sandbox(format!("COPY '{src_rel}' → '{dst}' failed")))
    }
}

/// Recursively copy directory `src` into `target`, SKIPPING paths the context's ignore rules exclude
/// (matched relative to `ctx`, the context root). NO-FOLLOW - the same confinement invariant as the
/// `cp -a` path: a symlink is recreated as a symlink, never traversed, so a `leak -> /host/secret` in
/// the context lands dangling in the image and its host target is never read. File MODE is preserved
/// (an executable script stays executable). Non-regular entries (fifo/socket/device - which don't
/// belong in a build context) are skipped.
pub(crate) fn copy_dir_filtered(
    src: &std::path::Path,
    target: &std::path::Path,
    ctx: &std::path::Path,
    ig: &crate::dockerignore::DockerIgnore,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let md = std::fs::symlink_metadata(&path)?;
        let ft = md.file_type();
        // The path RELATIVE TO THE CONTEXT ROOT drives ignore matching (dockerignore is context-
        // relative). If it can't be made relative (shouldn't happen - `src` and `ctx` are both
        // canonical), fail CLOSED (skip) rather than copy an un-vetted file.
        let Ok(rel) = path.strip_prefix(ctx) else {
            continue;
        };
        let rel = rel.to_string_lossy().replace('\\', "/");
        let dest = target.join(entry.file_name());
        if ft.is_dir() {
            // Prune a wholly-excluded subtree only when no `!` rule could re-include a descendant.
            if ig.can_prune_dir(&rel) {
                continue;
            }
            std::fs::create_dir_all(&dest)?;
            copy_dir_filtered(&path, &dest, ctx, ig)?;
        } else if ig.excluded(&rel) {
            continue;
        } else if ft.is_symlink() {
            // Recreate the symlink verbatim - NEVER follow it (a `leak -> /host/secret` in the context
            // must land dangling, its target never read at build time).
            let link = std::fs::read_link(&path)?;
            let _ = std::fs::remove_file(&dest);
            std::os::unix::fs::symlink(&link, &dest)?;
        } else if ft.is_file() {
            // Unlink any pre-existing dest first, so a symlink planted at that path (e.g. by the base
            // image) can't make `fs::copy` write THROUGH it out of the rootfs - stricter than `cp -a`.
            let _ = std::fs::remove_file(&dest);
            std::fs::copy(&path, &dest)?;
            std::fs::set_permissions(
                &dest,
                std::fs::Permissions::from_mode(md.permissions().mode()),
            )?;
        }
    }
    Ok(())
}

/// Turn an in-image path into a rootfs-relative one that CANNOT escape: strip leading `/`, then
/// reject any `..` component. `..` is a real directory, so the symlink-only
/// [`kern_oci::whiteout_dir_symlink_free`] guard doesn't catch it; without this a `COPY`/`WORKDIR`
/// dest of `../../etc/…` would let `cp`/`create_dir_all` write outside the rootfs onto the host.
pub(crate) fn sanitize_rootfs_rel(orig: &str, rel: &str) -> Result<String, Error> {
    let rel = rel.trim_start_matches('/');
    if std::path::Path::new(rel)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Error::Build(format!(
            "'{orig}' escapes the image rootfs (`..`)"
        )));
    }
    Ok(rel.to_string())
}

/// `mkdir -p` a workdir inside the rootfs, refusing a `..` escape or a symlinked component that
/// leads out.
pub(crate) fn mkdir_in_rootfs(rootfs: &std::path::Path, dir: &str) -> Result<(), Error> {
    let rel = sanitize_rootfs_rel(dir, dir)?;
    if !kern_oci::whiteout_dir_symlink_free(&rootfs.to_string_lossy(), &rel) {
        return Err(Error::Sandbox(format!(
            "WORKDIR '{dir}' crosses a symlink in the image"
        )));
    }
    let _ = std::fs::create_dir_all(rootfs.join(&rel));
    Ok(())
}

/// What [`seed_resolv_conf`] did, and therefore what [`restore_resolv_conf`] has to undo.
///
/// PRESENCE WAS THE WHOLE ANSWER, AND PRESENCE IS NOT THE QUESTION. This used to be a `bool`: true
/// when the file had been created, false otherwise, and false also meant "the base had one, leave
/// it". Two different situations behind one value is what made the defect below possible.
pub(crate) enum SeededResolv {
    /// Nothing was written: the base already names a server, or the host had nothing to copy.
    Untouched,
    /// Created where the base had no file at all: delete it before the image is finalized, but only
    /// if it still holds `written`.
    Created { written: Vec<u8> },
    /// Overwrote a file that named no server: put `original` back, but only if the file still holds
    /// `written`.
    ///
    /// The bytes and not "truncate to empty": an empty file and a file of comments are both
    /// serverless and neither may be turned into the other. The image keeps what it shipped.
    Replaced { written: Vec<u8>, original: Vec<u8> },
}

/// Does this `resolv.conf` name a server a resolver could actually use?
///
/// A `nameserver` line with a value. Comments, `search`, `options`, blank lines and an empty file all
/// answer no, because none of them tells a resolver where to ask.
fn names_a_server(content: &[u8]) -> bool {
    content.split(|b| *b == b'\n').any(|line| {
        let line = std::str::from_utf8(line).unwrap_or("");
        let line = line.trim();
        // `;` is a comment in resolv.conf as well as `#`.
        if line.starts_with('#') || line.starts_with(';') {
            return false;
        }
        let mut parts = line.split_whitespace();
        parts.next() == Some("nameserver") && parts.next().is_some_and(|v| !v.is_empty())
    })
}

/// Seed `/etc/resolv.conf` in the build rootfs from the host so RUN steps can resolve DNS over the
/// shared network namespace.
///
/// ## The defect this replaced
///
/// The test was `dst.exists()`, and Debian- and Ubuntu-based images SHIP AN EMPTY
/// `/etc/resolv.conf`. An empty file exists, so kern left it alone, and the build sandbox got a
/// resolver with nowhere to ask. Alpine ships no such file, so Alpine was created and worked - which
/// made the failure look like a network fault instead of a file-contents one.
///
/// Measured on this host, one Dockerfile, one variable:
///
/// ```text
/// FROM ubuntu:24.04, flat path  ->  wc -c < /etc/resolv.conf = 0, DNS KO
/// FROM alpine:latest, same host ->  943 bytes, DNS OK
/// ```
///
/// It bites only on the FLAT build path, which is why it took a field report to surface: where
/// unprivileged overlay works, the RUN step is a box whose overlay UPPER gets a resolv.conf written
/// into it, shadowing the base's empty one. WSL2 has no unprivileged overlay, so every build there
/// takes the flat path and every Debian-based build loses DNS. `apt-get`, `pip` and `dotnet restore`
/// all die, which is most real-world images.
///
/// ## Why it does not simply overwrite
///
/// Docker bind-mounts the daemon's resolv.conf over the image's for the duration of a build, so it
/// always wins. kern seeds only where the base names NO server, which fixes the broken case and
/// leaves a base that ships a working resolver saying what its author meant. Stated because it is a
/// deliberate divergence and not an oversight.
///
/// The host's own file is copied as-is: the build box shares the host network namespace, so a
/// loopback stub resolver (`nameserver 127.0.0.53`, systemd-resolved) is the same loopback in there.
pub(crate) fn seed_resolv_conf(rootfs: &std::path::Path) -> SeededResolv {
    let dst = rootfs.join("etc/resolv.conf");
    let existing = std::fs::read(&dst).ok();
    if existing.as_deref().is_some_and(names_a_server) {
        return SeededResolv::Untouched; // the base names a server: its author's choice stands
    }
    let Ok(host) = std::fs::read("/etc/resolv.conf") else {
        return SeededResolv::Untouched; // nothing to copy from
    };
    // A host file that names no server either would replace one useless file with another, and the
    // restore afterwards would then be pure churn. Say nothing happened, because nothing useful can.
    if !names_a_server(&host) {
        return SeededResolv::Untouched;
    }
    if std::fs::create_dir_all(rootfs.join("etc")).is_err() || std::fs::write(&dst, &host).is_err()
    {
        return SeededResolv::Untouched;
    }
    match existing {
        Some(original) => SeededResolv::Replaced {
            written: host,
            original,
        },
        None => SeededResolv::Created { written: host },
    }
}

/// Undo [`seed_resolv_conf`], so the host's DNS servers are not baked into the image.
///
/// The restore is EXACT and not a delete. The code this replaced only ever deleted, which was right
/// for the one case it handled (a file it had created) and would silently drop a base image's own
/// file in the case it did not handle. An image that shipped an empty `/etc/resolv.conf` gets an
/// empty `/etc/resolv.conf` back, byte for byte.
///
/// ## It only undoes what is still ITS OWN
///
/// A build step may write `/etc/resolv.conf` deliberately - `RUN echo 'nameserver 1.1.1.1' >
/// /etc/resolv.conf` is the workaround a field report used to get DNS at all, and it is a legitimate
/// thing for a Dockerfile to do on its own account. Undoing unconditionally deleted that file from
/// the finished image: the step ran, the write succeeded, and the result was silently discarded.
/// Measured: a base built with `nameserver 203.0.113.9` came back with no file, and a build FROM it
/// then saw the host's resolver.
///
/// So the seed is undone only while the file still holds the bytes the seed put there. It is the
/// same rule the VRAM reaper uses on a slot it means to reclaim: read, then act only if the value is
/// still the one that was read. Anything else in the file belongs to the image.
pub(crate) fn restore_resolv_conf(rootfs: &std::path::Path, seeded: &SeededResolv) {
    let dst = rootfs.join("etc/resolv.conf");
    let (written, original) = match seeded {
        SeededResolv::Untouched => return,
        SeededResolv::Created { written } => (written, None),
        SeededResolv::Replaced { written, original } => (written, Some(original)),
    };
    // A read failure means the file is gone or unreadable, and either way there is nothing of ours
    // left to take back.
    let Ok(now) = std::fs::read(&dst) else {
        return;
    };
    if now != *written {
        return; // a build step owns this file now
    }
    match original {
        Some(bytes) => {
            let _ = std::fs::write(&dst, bytes);
        }
        None => {
            let _ = std::fs::remove_file(&dst);
        }
    }
}

/// Per-box writable overlay scratch (upper/work) - placed on **tmpfs** where possible
/// (`$XDG_RUNTIME_DIR` → `/run/user/<uid>`, both tmpfs), else `/tmp`. tmpfs makes the create /
/// overlay-mount / cleanup RAM-fast and keeps the writable layer ephemeral; its pages count
/// against the box's memory cap. Created mode 0700 by the caller.
pub(crate) fn scratch_dir() -> PathBuf {
    crate::registry::assert_registry_child("scratch"); // classification chokepoint (see registry.rs)
    let uid = unsafe { libc::getuid() };
    // The scratch holds each box's overlay upper/work - and the kernel refuses an overlay UPPER
    // that itself lives on overlayfs. On a normal host `/run/user/<uid>` (tmpfs) or `/tmp` is fine;
    // when kern runs INSIDE a Docker/CI container BOTH sit on the container's overlay rootfs, so
    // probe the candidates and take the first non-overlay one. `/dev/shm` is a real tmpfs even
    // inside Docker (size-capped - last resort, announced on stderr so an ENOSPC later isn't a
    // mystery). If everything is overlayfs, fall through to /tmp and let the mount fail with the
    // actionable nested-overlay error from kern-isolation.
    //
    // `$XDG_RUNTIME_DIR` still wins when it works - it is the documented override - but it is now a
    // CANDIDATE rather than an unconditional answer, the same shape `registry::runtime_subdir` has
    // always had. The reason is measured, on WSL2 (2026-08-29): a distro with WSLg exports
    // `XDG_RUNTIME_DIR=/mnt/wslg/runtime-dir`, the SAME path for every uid, and `kern/scratch` under
    // it is created 0700 by whichever user starts a box first. The other user then gets
    // `overlay scratch: Permission denied` - and root, who passes every permission check, gets
    // something worse: it writes into a dir owned by a uid that is not mapped inside the box's user
    // namespace and the failure surfaces later as `mount(overlay) failed: Permission denied`. Both
    // directions were reproduced by simply changing which user ran first. So a candidate must be
    // ours, not merely writable, and refusing a foreign-owned `kern-<uid>` dir also closes the
    // pre-created-directory trap on world-writable `/tmp` and `/dev/shm`.
    let mut cands: Vec<(PathBuf, PathBuf, &str)> = Vec::new();
    if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR") {
        let base = PathBuf::from(&x);
        cands.push((base.join("kern/scratch"), base, "xdg"));
    }
    let run = PathBuf::from(format!("/run/user/{uid}"));
    if run.is_dir() {
        cands.push((run.join("kern/scratch"), run, "run"));
    }
    let tmp = PathBuf::from(format!("/tmp/kern-{uid}/scratch"));
    cands.push((tmp.clone(), PathBuf::from("/tmp"), "tmp"));
    cands.push((
        PathBuf::from(format!("/dev/shm/kern-{uid}/scratch")),
        PathBuf::from("/dev/shm"),
        "shm",
    ));
    for (cand, base, kind) in &cands {
        if fs_magic_of(cand) == Some(OVERLAYFS_SUPER_MAGIC) {
            continue;
        }
        if !scratch_base_usable(base, cand) {
            if *kind == "xdg" && !kern_common::env_flag("KERN_QUIET") {
                static ONCE: std::sync::Once = std::sync::Once::new();
                ONCE.call_once(|| {
                    eprintln!(
                        "kern: note: $XDG_RUNTIME_DIR ({}) holds a `kern` dir this user does not \
                         own - putting box scratch under /run/user/<uid> or /tmp instead",
                        base.display()
                    );
                });
            }
            continue;
        }
        if *kind == "shm" && !kern_common::env_flag("KERN_QUIET") {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| {
                eprintln!(
                    "kern: note: /run and /tmp are on overlayfs (container?) - using the \
                     size-capped /dev/shm for box scratch; set XDG_RUNTIME_DIR to a tmpfs/disk \
                     path for full capacity"
                );
            });
        }
        return cand.clone();
    }
    tmp
}

/// Can this user put a box's writable layer at `cand`? The leaf is created on demand, so the
/// question is asked of the deepest ancestor that EXISTS: it must be writable, and - unless it is
/// `base`, the system directory kern did not create - it must be OURS. Ownership is the half that
/// permissions alone cannot answer, because root passes `access(2)` on every directory and then the
/// overlay mount fails inside the box's user namespace instead. Read-only, so probing leaves nothing
/// behind.
pub(crate) fn scratch_base_usable(base: &std::path::Path, cand: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let uid = unsafe { libc::getuid() };
    let mut p = cand;
    loop {
        if let Ok(md) = std::fs::symlink_metadata(p) {
            if !md.is_dir() {
                return false; // a file (or a symlink) where a directory belongs is not ours to use
            }
            if p != base && md.uid() != uid {
                return false;
            }
            let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
                return false;
            };
            // SAFETY: `c` is a live NUL-terminated path and `access` only reads it.
            return unsafe { libc::access(c.as_ptr(), libc::W_OK | libc::X_OK) == 0 };
        }
        match p.parent() {
            Some(up) => p = up,
            None => return false,
        }
    }
}

pub(crate) const OVERLAYFS_SUPER_MAGIC: i64 = 0x794c7630;

/// Remove the overlay scratch behind a box, derived from its merge path
/// (`<cache>/scratch/<name>-<pid>/merged`).
pub(crate) fn cleanup_box_scratch(rootfs: &str) {
    let p = std::path::Path::new(rootfs);
    if p.file_name().is_none_or(|n| n != "merged") {
        return;
    }
    let Some(scratch) = p.parent() else { return };
    // CONFINEMENT (the ranged fallback below runs a privileged newuidmap'd remove_dir_all, so the path
    // must be provably ours): require `scratch`'s parent to be kern's own scratch root - not a weak
    // `.contains("/scratch/")` (which `/tmp/scratch/../../etc` would pass). Canonicalize both sides so
    // no `..`/symlink in the registry-derived rootfs can steer the remove outside kern's scratch tree.
    let root = scratch_dir();
    let canon_root = std::fs::canonicalize(&root).unwrap_or(root);
    let parent_ok = scratch.parent().is_some_and(|par| {
        std::fs::canonicalize(par)
            .map(|c| c == canon_root)
            .unwrap_or(false)
    });
    if !parent_ok {
        return;
    }
    // Route through cleanup_scratch's ranged fallback: a `--uid-range`/pod box whose image dropped
    // privilege leaves subordinate-uid-owned files (e.g. grafana's /var/lib/grafana owned by subuid
    // 100471) that a plain remove_dir_all can't unlink from the host - the fallback retries inside a
    // newuidmap'd user ns where they're removable.
    cleanup_scratch(Some(scratch));
}

#[cfg(test)]
mod resolv_tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "kern-resolv-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::create_dir_all(d.join("etc"));
        d
    }

    /// AN EMPTY FILE NAMES NO SERVER, and that was the whole defect.
    ///
    /// Every Debian and Ubuntu image ships an empty `/etc/resolv.conf`. The old test was
    /// `dst.exists()`, so kern read presence as configuration and left the build sandbox with a
    /// resolver that had nowhere to ask. The forms below are the ones a real file takes.
    #[test]
    fn only_a_nameserver_line_counts_as_naming_a_server() {
        assert!(names_a_server(b"nameserver 1.1.1.1\n"));
        assert!(names_a_server(b"search example.com\nnameserver 8.8.8.8\n"));
        assert!(names_a_server(b"  nameserver   127.0.0.53  \n"));
        assert!(names_a_server(b"nameserver 1.1.1.1")); // no trailing newline

        // The shapes that look configured and are not.
        assert!(!names_a_server(b""), "an empty file is what Debian ships");
        assert!(!names_a_server(b"\n\n  \n"));
        assert!(
            !names_a_server(b"# nameserver 1.1.1.1\n"),
            "a comment is not a server"
        );
        assert!(
            !names_a_server(b"; nameserver 1.1.1.1\n"),
            "`;` comments too"
        );
        assert!(!names_a_server(b"search example.com\noptions edns0\n"));
        assert!(
            !names_a_server(b"nameserver\n"),
            "the directive with no value"
        );
        assert!(!names_a_server(b"nameserver   \n"));
        assert!(
            !names_a_server(b"nameservers 1.1.1.1\n"),
            "a different directive"
        );
        // Not UTF-8: must answer no rather than panic. A layer can contain anything.
        assert!(!names_a_server(&[0xff, 0xfe, 0x00, 0x01]));
    }

    /// THE THREE OUTCOMES, AND THE RESTORE IS EXACT.
    ///
    /// The old code returned a bool and only ever deleted. Deleting is right for a file it created
    /// and wrong for one it overwrote: an image that shipped an empty `/etc/resolv.conf` would have
    /// come out without the file at all.
    #[test]
    fn seeding_is_undone_exactly_and_never_bakes_host_dns_into_the_image() {
        // The host must name a server for any seeding to happen at all; where it does not, this
        // whole case is inapplicable and says so rather than asserting the wrong thing.
        let host = std::fs::read("/etc/resolv.conf").unwrap_or_default();
        if !names_a_server(&host) {
            eprintln!(
                "SKIP: this host's /etc/resolv.conf names no server, so nothing can be seeded"
            );
            return;
        }

        // 1. The base ships no file: created, then removed.
        let d = scratch("created");
        let seeded = seed_resolv_conf(&d);
        assert!(
            matches!(seeded, SeededResolv::Created { .. }),
            "an absent file must be created"
        );
        assert!(names_a_server(
            &std::fs::read(d.join("etc/resolv.conf")).unwrap_or_default()
        ));
        restore_resolv_conf(&d, &seeded);
        assert!(
            !d.join("etc/resolv.conf").exists(),
            "a file kern created must not survive into the image"
        );

        // 2. The base ships an EMPTY file: replaced, then restored to empty. The reported case.
        let d = scratch("empty");
        let _ = std::fs::write(d.join("etc/resolv.conf"), b"");
        let seeded = seed_resolv_conf(&d);
        assert!(
            matches!(seeded, SeededResolv::Replaced { .. }),
            "an empty file must be seeded over"
        );
        assert!(
            names_a_server(&std::fs::read(d.join("etc/resolv.conf")).unwrap_or_default()),
            "the build sandbox must have a resolver during RUN"
        );
        restore_resolv_conf(&d, &seeded);
        assert_eq!(
            std::fs::read(d.join("etc/resolv.conf")).unwrap_or_else(|_| b"MISSING".to_vec()),
            b"".to_vec(),
            "the image gets its empty file back, not a deletion and not the host's servers"
        );

        // 3. A file of comments only: same treatment, restored byte for byte.
        let d = scratch("comments");
        let original = b"# nothing here\n; nor here\n".to_vec();
        let _ = std::fs::write(d.join("etc/resolv.conf"), &original);
        let seeded = seed_resolv_conf(&d);
        assert!(matches!(seeded, SeededResolv::Replaced { .. }));
        restore_resolv_conf(&d, &seeded);
        assert_eq!(
            std::fs::read(d.join("etc/resolv.conf")).unwrap_or_default(),
            original,
            "an empty file and a file of comments are both serverless and are not interchangeable"
        );

        // 3b. A BUILD STEP OVERWROTE IT. The undo must not fire: `RUN echo 'nameserver 1.1.1.1' >
        //     /etc/resolv.conf` is a legitimate thing for a Dockerfile to do, and it is the exact
        //     workaround a field report used to get DNS at all. Deleting it afterwards discarded a
        //     write that had already succeeded. Measured before this was fixed: a base built with
        //     `nameserver 203.0.113.9` came out with no file, and a build FROM it saw the host's
        //     resolver instead.
        let d = scratch("stepwrote");
        let _ = std::fs::write(d.join("etc/resolv.conf"), b"");
        let seeded = seed_resolv_conf(&d);
        assert!(matches!(seeded, SeededResolv::Replaced { .. }));
        let theirs = b"nameserver 203.0.113.9\n".to_vec();
        let _ = std::fs::write(d.join("etc/resolv.conf"), &theirs);
        restore_resolv_conf(&d, &seeded);
        assert_eq!(
            std::fs::read(d.join("etc/resolv.conf")).unwrap_or_default(),
            theirs,
            "a file a build step wrote belongs to the image, not to the seed"
        );

        // 3c. The same on a file kern CREATED: the delete must not fire either.
        let d = scratch("createdthenwritten");
        let seeded = seed_resolv_conf(&d);
        assert!(matches!(seeded, SeededResolv::Created { .. }));
        let _ = std::fs::write(d.join("etc/resolv.conf"), &theirs);
        restore_resolv_conf(&d, &seeded);
        assert_eq!(
            std::fs::read(d.join("etc/resolv.conf")).unwrap_or_default(),
            theirs,
            "the undo deletes only a file that still holds what the seed put there"
        );

        // 4. The base names a server: untouched, and still untouched after the restore.
        let d = scratch("own");
        let own = b"nameserver 203.0.113.9\n".to_vec();
        let _ = std::fs::write(d.join("etc/resolv.conf"), &own);
        let seeded = seed_resolv_conf(&d);
        assert!(
            matches!(seeded, SeededResolv::Untouched),
            "a base that names a server keeps what its author meant"
        );
        restore_resolv_conf(&d, &seeded);
        assert_eq!(
            std::fs::read(d.join("etc/resolv.conf")).unwrap_or_default(),
            own
        );

        for t in [
            "created",
            "empty",
            "comments",
            "own",
            "stepwrote",
            "createdthenwritten",
        ] {
            let _ = std::fs::remove_dir_all(
                std::env::temp_dir().join(format!("kern-resolv-{t}-{}", std::process::id())),
            );
        }
    }
}

#[cfg(test)]
mod reflink_tests {
    use super::*;

    /// THE PROBE ANSWERS ABOUT A REAL FILESYSTEM, AND CLEANS UP AFTER ITSELF.
    ///
    /// It decides whether the flat build's base copy is a clone or a full re-read of the whole base
    /// image, which on a 2 GB base is the difference between milliseconds and minutes. A probe that
    /// left files behind would litter the image cache it runs in, and one that answered from the
    /// filesystem's NAME rather than from an attempted clone would be wrong on the cases that
    /// matter: a filesystem can be btrfs and still refuse a clone across subvolumes.
    #[test]
    fn the_reflink_probe_answers_and_leaves_nothing_behind() {
        let dir = std::env::temp_dir().join(format!("kern-reflink-t-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let before: Vec<_> = std::fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name())
            .collect();

        // The answer is a property of THIS host and cannot be asserted either way; that it IS an
        // answer, and not a crash or a hang, is what this checks. Both values are legitimate.
        let answer = supports_reflink(&dir);
        assert!(
            matches!(answer, Some(true) | Some(false) | None),
            "the probe must return a verdict or an honest None"
        );

        let after: Vec<_> = std::fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(
            before.len(),
            after.len(),
            "the probe left files behind: {after:?}"
        );

        // A directory that cannot be written to yields None, never a verdict invented from a failed
        // measurement - the same rule the overlay probe follows.
        let missing = dir.join("no-such-subdir");
        assert_eq!(
            supports_reflink(&missing),
            None,
            "an unwritable location measured nothing, so it must not claim an answer"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
