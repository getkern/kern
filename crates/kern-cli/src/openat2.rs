//! The ONE `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` confinement primitive, shared by every
//! caller that resolves an UNTRUSTED path against a trusted root (currently `kern cp`'s in-box path in
//! [`crate::boxcp`] and the merged-view copier in `commands`). Consolidated so the security boundary has
//! a single definition — two hand-rolled copies could drift, and this is exactly the kind of call where
//! a silent divergence (a missing `RESOLVE_*` flag) reopens an escape.
//!
//! `RESOLVE_IN_ROOT` reinterprets every absolute symlink and `..` as if `root_fd` were `/`, so a hostile
//! image cannot plant a symlink or a `..` chain that reads/writes a **host** file outside the root — the
//! class of bug behind CVE-2019-14271 (`docker cp` following a container symlink out to the host).
//! `RESOLVE_NO_MAGICLINKS` refuses to traverse `/proc`-style magic links during resolution.

use std::os::unix::io::RawFd;

// `struct open_how` + `openat2` (`<linux/openat2.h>`, Linux 5.6+). `openat2` is nr 437 on every
// current arch.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
const SYS_OPENAT2: libc::c_long = 437;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_IN_ROOT: u64 = 0x10;

/// Open `path` (interpreted relative to `root_fd` as its own `/`) with symlink/`..` escape confined to
/// that root. `extra_flags` adds `O_RDONLY|O_PATH|O_NOFOLLOW|O_CREAT|…`; `mode` applies on create.
/// `O_CLOEXEC` is always set. Returns the fd or an `io::Error` (e.g. `ENOENT` when the path doesn't
/// exist in the root, `ENOSYS` on a pre-5.6 kernel — the caller maps these as it needs).
pub fn openat2_in_root(
    root_fd: RawFd,
    path: &str,
    extra_flags: i32,
    mode: u32,
) -> std::io::Result<RawFd> {
    // Strip the leading `/` — with RESOLVE_IN_ROOT the path is already rooted at `root_fd`.
    let rel = path.trim_start_matches('/');
    let c =
        std::ffi::CString::new(rel).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let how = OpenHow {
        flags: (libc::O_CLOEXEC | extra_flags) as u64,
        mode: mode as u64,
        resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
    };
    let fd = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            root_fd,
            c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(fd as RawFd)
    }
}
