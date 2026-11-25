//! Landlock: an unprivileged, path-based LSM applied as defense-in-depth over the box's namespaces and
//! seccomp filter. `--landlock-rw <path>` turns the box into a WRITE-allowlist: the workload may read and
//! execute anywhere in the box, but may only WRITE under the listed paths (plus the box's own scratch
//! dirs `/dev`, `/tmp`, `/run`, `/proc`). The kernel enforces it and the workload CANNOT lift it (it
//! survives across `execve` and can only be tightened, never relaxed): a real second boundary that a
//! mount-namespace-escape bug alone would not defeat.
//!
//! It is ABI-negotiated: `landlock_create_ruleset(NULL, 0, VERSION)` reports the kernel's Landlock ABI,
//! and we only ask the kernel to govern the access rights that ABI knows (asking for an unknown right is
//! `EINVAL`). On a kernel without Landlock the whole thing degrades to a no-op (the box still has its
//! namespaces + seccomp) rather than failing the box.
//!
//! All three Landlock syscalls are issued raw (no libc wrapper is guaranteed), with the arch-correct
//! numbers from `libc::SYS_landlock_*`. Applied on the box's PID-1 thread just before `execve` (after
//! `no_new_privs`, before seccomp), so it covers the workload and every descendant.
//!
//! What Landlock does NOT cover (by design, stated so it is never assumed):
//!  * A file DESCRIPTOR already open for write before `restrict_self` keeps its access (Landlock governs
//!    path resolution, not open fds). kern applies the ruleset on PID 1 before `execve` while no workload
//!    code has run, so the workload never gets a pre-opened writable fd to a denied path.
//!  * It is a WRITE allowlist, not a read confinement: the box root stays readable/executable everywhere
//!    (programs need their libs/config). For read confinement use the mount namespace (`-v`, RO remounts).
//!  * `rename`/link ACROSS directories (`LANDLOCK_ACCESS_FS_REFER`) is DENIED by default on ABI >= 2 (we
//!    do not grant REFER), so a workload can't move a file out of an allowlisted subtree into a denied
//!    one. On ABI 1 REFER does not exist and the kernel governs cross-dir rename differently; kern's real
//!    write boundary on such kernels is the combination below, not Landlock alone.
//!  * Landlock does not stop a new `mount`/`pivot_root`/`umount2` that could re-expose a path; those are
//!    blocked by kern's always-on SECCOMP filter, not by Landlock. The two are defense-in-depth TOGETHER:
//!    seccomp closes the mount vector, Landlock the path-write vector. Neither alone is the whole story.

use crate::Error;
use std::ffi::CString;

// `landlock_create_ruleset` flag: report the supported ABI version instead of creating a ruleset.
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
// `landlock_add_rule` rule type: a rule on a filesystem hierarchy.
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

// Filesystem access-right bits (`LANDLOCK_ACCESS_FS_*`), grouped by the ABI that introduced them.
const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_REMOVE_DIR: u64 = 1 << 4;
const FS_REMOVE_FILE: u64 = 1 << 5;
const FS_MAKE_CHAR: u64 = 1 << 6;
const FS_MAKE_DIR: u64 = 1 << 7;
const FS_MAKE_REG: u64 = 1 << 8;
const FS_MAKE_SOCK: u64 = 1 << 9;
const FS_MAKE_FIFO: u64 = 1 << 10;
const FS_MAKE_BLOCK: u64 = 1 << 11;
const FS_MAKE_SYM: u64 = 1 << 12;
const FS_REFER: u64 = 1 << 13; // ABI 2+
const FS_TRUNCATE: u64 = 1 << 14; // ABI 3+
const FS_IOCTL_DEV: u64 = 1 << 15; // ABI 5+

/// Read+exec+list: what the box root grants, so programs run and read their libs/config anywhere while
/// writes stay confined to the granted subtrees.
const READ_EXEC: u64 = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR;

/// The access rights that are meaningful on a NON-directory. The kernel rejects a `path_beneath` rule
/// whose `allowed_access` carries a directory-only right (`*_DIR`, `MAKE_*`, `REFER`) when the rule's
/// fd is a file or a device node: `landlock_add_rule` returns `EINVAL` and the whole ruleset is lost.
///
/// This is not hypothetical. Every path kern granted before was a directory, so the mask was never
/// needed and its absence was a latent defect on BOTH paths: `kern box --landlock-rw /etc/hosts` fails
/// the same way. Masking here fixes it once, for every caller, rather than forbidding files at the
/// call sites - a per-file grant is a legitimate and precise thing to want.
const FILE_RIGHTS: u64 = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV;

/// The box's own scratch/device directories, always writable under Landlock so a locked-down box still
/// functions (`cmd > /dev/null`, temp files, `/proc/self/*`), independent of the user's `--landlock-rw`.
///
/// These are safe to grant WHOLESALE only because they are the box's own: inside a box `/dev` is the
/// small device set kern mounts, `/tmp` and `/run` are fresh tmpfs that die with the box, and `/proc`
/// is masked. None of them is the host's.
const AUTO_RW: &[&str] = &["/dev", "/tmp", "/run", "/proc"];

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

unsafe fn create_ruleset(attr: *const RulesetAttr, size: usize, flags: u32) -> i64 {
    libc::syscall(
        libc::SYS_landlock_create_ruleset,
        attr,
        size,
        flags as libc::c_ulong,
    )
}

unsafe fn add_rule(ruleset_fd: i32, attr: *const PathBeneathAttr) -> i64 {
    libc::syscall(
        libc::SYS_landlock_add_rule,
        ruleset_fd,
        LANDLOCK_RULE_PATH_BENEATH as libc::c_ulong,
        attr,
        0 as libc::c_ulong,
    )
}

unsafe fn restrict_self(ruleset_fd: i32) -> i64 {
    libc::syscall(
        libc::SYS_landlock_restrict_self,
        ruleset_fd,
        0 as libc::c_ulong,
    )
}

/// The kernel's Landlock ABI version (>= 1), or `None` if Landlock is unavailable (old kernel, or
/// disabled at boot).
pub fn abi_version() -> Option<i32> {
    let v = unsafe { create_ruleset(std::ptr::null(), 0, LANDLOCK_CREATE_RULESET_VERSION) };
    if v >= 1 {
        Some(v as i32)
    } else {
        None
    }
}

/// The full set of filesystem access rights the given ABI can govern. Asking the kernel to handle a
/// right it doesn't know is `EINVAL`, so this masks by ABI: v1 is the base set, and REFER/TRUNCATE/
/// IOCTL_DEV are added as later ABIs introduce them.
fn handled_for_abi(abi: i32) -> u64 {
    let mut h = FS_EXECUTE
        | FS_WRITE_FILE
        | FS_READ_FILE
        | FS_READ_DIR
        | FS_REMOVE_DIR
        | FS_REMOVE_FILE
        | FS_MAKE_CHAR
        | FS_MAKE_DIR
        | FS_MAKE_REG
        | FS_MAKE_SOCK
        | FS_MAKE_FIFO
        | FS_MAKE_BLOCK
        | FS_MAKE_SYM;
    if abi >= 2 {
        h |= FS_REFER;
    }
    if abi >= 3 {
        h |= FS_TRUNCATE;
    }
    if abi >= 5 {
        h |= FS_IOCTL_DEV;
    }
    h
}

/// Add a `path_beneath` rule granting `access` on the subtree at `path`. Best-effort per path: a path
/// that doesn't exist in the box is skipped (it can't be a target for the workload anyway), never fatal.
///
/// Symlink safety (why a symlinked `--landlock-rw` path cannot WIDEN the allowlist):
///  * `O_NOFOLLOW` refuses a path whose FINAL component is a symlink, so `--landlock-rw /app` where the
///    image ships `/app -> /` fails the open and is skipped. The box then runs WITHOUT that grant, i.e.
///    a STRICTER allowlist, never write-anywhere. A hostile image can only tighten, never loosen.
///  * An INTERMEDIATE symlink (`/app/data` with `/app -> /etc`) is resolved to the real inode
///    (`/etc/data`), and Landlock binds the rule to that inode. The kernel resolves the workload's own
///    `/app/data` to the SAME inode at write time, so enforcement matches the grant exactly: the writable
///    subtree is precisely the path the operator named (by its resolved identity), never a broader one.
///  * The rule is bound at open time on pid1 BEFORE `execve`, while no workload runs, so there is no
///    TOCTOU between resolving the path and enforcing the ruleset.
///
/// Hence `RESOLVE_NO_SYMLINKS` is deliberately NOT used: it would reject legitimate symlinked dirs (a
/// common `/var/run -> /run`) for no security gain, since symlinks here are already fail-safe.
///
/// Returns whether a rule was actually added. A caller that must not silently lose a grant reads this
/// instead of stat-ing the path itself: the answer is derived from the very fd the rule is bound to, so
/// there is no window in which the checked path and the granted path could be different objects. A
/// separate `stat` before the call cannot give that guarantee, because `O_NOFOLLOW` rejects a path that
/// BECAME a symlink but accepts one swapped for a different real directory (`mv good away && mv evil
/// good`), and the grant would then bind to the attacker's inode while the check had passed on the
/// operator's.
fn add_path(ruleset_fd: i32, path: &str, access: u64) -> Result<bool, Error> {
    let c = CString::new(path).map_err(|_| Error::Unsupported("landlock path has a NUL"))?;
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Ok(false); // absent path (or a symlink final component) → nothing to grant, and never a target
    }
    // Directory-only rights on a non-directory are `EINVAL`, which loses the ENTIRE ruleset, not just
    // this rule. `fstat` is valid on an `O_PATH` fd, so ask the kernel what this inode is and drop the
    // rights it cannot carry. A failed `fstat` takes the conservative branch (mask to the file set):
    // the grant can only end up NARROWER than asked, never wider.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let is_dir =
        unsafe { libc::fstat(fd, &mut st) } == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
    let access = if is_dir { access } else { access & FILE_RIGHTS };
    let attr = PathBeneathAttr {
        allowed_access: access,
        parent_fd: fd,
    };
    let r = unsafe { add_rule(ruleset_fd, &attr) };
    unsafe { libc::close(fd) };
    if r != 0 {
        return Err(Error::last("landlock_add_rule"));
    }
    Ok(true)
}

/// Apply a Landlock write-allowlist to the current thread (and, via `execve`, the workload): the box
/// root is read+exec, and full access is granted only under `rw` (plus the box scratch dirs). Returns
/// `Ok(true)` when enforced, `Ok(false)` when Landlock is unavailable on this kernel, and `Err` on a
/// real failure to build or enforce a ruleset that WAS available.
///
/// This function reports; it does not decide. Both `Ok(false)` and `Err` are refusals at the call site
/// in `real.rs` (a box that asked to be confined does not run unconfined), and the distinction is kept
/// here because the two need different messages: one names a missing LSM the operator can check with
/// `kern doctor`, the other names the syscall that failed.
pub fn apply_rw_allowlist(rw: &[String]) -> Result<bool, Error> {
    // `strict_user: false` - a box path that cannot be granted is SKIPPED, and that silence is the
    // documented fail-safe: the box keeps its namespaces, seccomp and read-only root, and an image that
    // ships `/app -> /` can only ever make the allowlist NARROWER. Unchanged from before.
    apply_rw_allowlist_with(rw, AUTO_RW, false)
}

/// Build and enforce the ruleset: `READ_EXEC` on `/`, full access under `auto` and under `rw`.
///
/// `auto` and `strict_user` are parameters because their correct values depend on whether the caller
/// has a mount namespace (see [`AUTO_RW`]). A box always has one; the host-side entry point that had
/// none went with `kern limit` in 0.57.0, and the parameters keep the rule stated where it applies.
///
/// `strict_user` decides what a user path that could not be granted MEANS. With a namespace it is
/// fail-safe silence (the allowlist narrows, everything else still confines); without one it is the
/// confinement itself going missing, so it becomes an error naming the path. The `auto` set is never
/// strict on either path: `/tmp` legitimately does not exist in a minimal box, and a missing
/// `/dev/full` on the host is not something the operator asked for.
fn apply_rw_allowlist_with(rw: &[String], auto: &[&str], strict_user: bool) -> Result<bool, Error> {
    let Some(abi) = abi_version() else {
        return Ok(false);
    };
    let handled = handled_for_abi(abi);
    let attr = RulesetAttr {
        handled_access_fs: handled,
    };
    let ruleset_fd = unsafe { create_ruleset(&attr, std::mem::size_of::<RulesetAttr>(), 0) };
    if ruleset_fd < 0 {
        return Err(Error::last("landlock_create_ruleset"));
    }
    let ruleset_fd = ruleset_fd as i32;

    // Every rule is added on the ONE ruleset fd, and each path is opened exactly once inside
    // `add_path`, which then stats and binds that same fd. Nothing here re-resolves a path it has
    // already checked, so no rule can end up bound to a different object than the one that was
    // inspected.
    // Close the ruleset on the way out of an error. Every call site below returns immediately after
    // calling it, so it runs at most once per invocation; it must stay that way, because a second call
    // would close an fd number the kernel may already have handed to something else.
    let close_and = |e: Error| {
        unsafe { libc::close(ruleset_fd) };
        e
    };

    // The box root: readable + executable everywhere (programs run, read libs/config), but no write.
    add_path(ruleset_fd, "/", READ_EXEC & handled).map_err(close_and)?;
    // The scratch/device dirs: full access, best-effort on both paths (see the doc note above).
    for p in auto {
        add_path(ruleset_fd, p, handled).map_err(close_and)?;
    }
    // The operator's own paths: same call, but under `strict_user` a skip is refused rather than
    // ignored, and the refusal is decided by the return of the call that would have bound the rule.
    for p in rw {
        let granted = add_path(ruleset_fd, p, handled).map_err(close_and)?;
        if !granted && strict_user {
            return Err(close_and(Error::Spec(format!(
                "--landlock-rw '{p}': the path could not be opened to bind the grant (it must exist, \
                 and its final component must not be a symlink - Landlock opens it O_NOFOLLOW). \
                 Refusing rather than running with that path silently ungranted."
            ))));
        }
    }

    // Landlock requires no_new_privs; kern already sets it for seccomp, but ensure it (idempotent) so
    // this module is correct on its own.
    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    let r = unsafe { restrict_self(ruleset_fd) };
    unsafe { libc::close(ruleset_fd) };
    if r != 0 {
        return Err(Error::last("landlock_restrict_self"));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handled_rights_grow_monotonically_with_abi() {
        // Each ABI is a superset of the previous (never drops a right), and later rights only appear at
        // their introducing ABI, so an old kernel is never asked to handle a right it would EINVAL on.
        let v1 = handled_for_abi(1);
        let v2 = handled_for_abi(2);
        let v3 = handled_for_abi(3);
        let v5 = handled_for_abi(5);
        assert_eq!(v1 & FS_REFER, 0, "REFER is ABI 2+, absent at v1");
        assert_eq!(v2 & FS_REFER, FS_REFER);
        assert_eq!(v2 & FS_TRUNCATE, 0, "TRUNCATE is ABI 3+, absent at v2");
        assert_eq!(v3 & FS_TRUNCATE, FS_TRUNCATE);
        assert_eq!(v3 & FS_IOCTL_DEV, 0, "IOCTL_DEV is ABI 5+, absent at v3");
        assert_eq!(v5 & FS_IOCTL_DEV, FS_IOCTL_DEV);
        assert_eq!(v1 & v2, v1, "v2 is a superset of v1");
        assert_eq!(v2 & v3, v2, "v3 is a superset of v2");
    }

    #[test]
    fn read_exec_has_no_write_rights() {
        // The box-root grant must never include a write/create/remove right, or the allowlist leaks.
        let writes = FS_WRITE_FILE
            | FS_REMOVE_DIR
            | FS_REMOVE_FILE
            | FS_MAKE_REG
            | FS_MAKE_DIR
            | FS_TRUNCATE;
        assert_eq!(READ_EXEC & writes, 0);
        assert_eq!(READ_EXEC, FS_EXECUTE | FS_READ_FILE | FS_READ_DIR);
    }
}
