//! The ONE `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` confinement primitive, shared by every
//! caller that resolves an UNTRUSTED path against a trusted root (currently `kern cp`'s in-box path in
//! [`crate::boxcp`], `kern exec -u` reading a running box's account files, and the merged-view copier
//! in `commands`). Consolidated so the security boundary has
//! a single definition - two hand-rolled copies could drift, and this is exactly the kind of call where
//! a silent divergence (a missing `RESOLVE_*` flag) reopens an escape.
//!
//! `RESOLVE_IN_ROOT` reinterprets every absolute symlink and `..` as if `root_fd` were `/`, so a hostile
//! image cannot plant a symlink or a `..` chain that reads/writes a **host** file outside the root - the
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
/// exist in the root, `ENOSYS` on a pre-5.6 kernel - the caller maps these as it needs).
pub fn openat2_in_root(
    root_fd: RawFd,
    path: &str,
    extra_flags: i32,
    mode: u32,
) -> std::io::Result<RawFd> {
    // Strip the leading `/` - with RESOLVE_IN_ROOT the path is already rooted at `root_fd`.
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

/// Open `/proc/<pid1>/root` as an `O_PATH` dirfd: a running box's root, for confined resolution with
/// [`openat2_in_root`]. Owned, so every return path closes it.
pub(crate) fn box_root_fd(pid1: i32) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    // A decimal pid can never contain a NUL, so this cannot fail - stated as an error rather than
    // asserted, because `panic = "abort"` turns a wrong assumption here into a dead process.
    let Ok(p) = std::ffi::CString::new(format!("/proc/{pid1}/root")) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "box root path contained a NUL",
        ));
    };
    let fd = unsafe {
        libc::open(
            p.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: `fd` was just returned by `open` and nothing else holds it.
        Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
    }
}

/// The flags to open a file the box's (or an image's) own content controls. `O_NONBLOCK` is for a FIFO
/// planted at the path: opening one for reading would otherwise wait for a writer that party controls.
/// It changes nothing for a regular file.
pub(crate) const READ_UNTRUSTED: i32 = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY;

/// Open the file at `path` under `root` for `access` (`O_RDONLY` or `O_RDWR`), but only if it is a
/// REGULAR file: `Ok(None)` when there is no such file, `InvalidData` when there is one of another
/// type, any other error as the kernel gave it.
///
/// CLASSIFIED BEFORE IT IS OPENED. The first open is `O_PATH`, which calls no driver's `open` and
/// waits for no writer, so a device node or a FIFO at the path is refused on its type without this
/// process ever opening it as one. The reopen goes through that descriptor (`/proc/self/fd/<n>`), so
/// it is the inode that was classified whatever the path names by then. `O_CREAT` is never passed: a
/// file the box does not have is not one this creates.
pub(crate) fn open_regular_in_root(
    root: std::os::fd::BorrowedFd<'_>,
    path: &str,
    access: i32,
) -> std::io::Result<Option<std::fs::File>> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let classified = match openat2_in_root(root.as_raw_fd(), path, libc::O_PATH, 0) {
        // SAFETY: `fd` was just returned by `openat2` and nothing else holds it.
        Ok(fd) => unsafe { std::fs::File::from_raw_fd(fd) },
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => {
            return Ok(None)
        }
        Err(e) => return Err(e),
    };
    if !classified.metadata()?.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    let Ok(reopen) = std::ffi::CString::new(format!("/proc/self/fd/{}", classified.as_raw_fd()))
    else {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    };
    let fd = unsafe {
        libc::open(
            reopen.as_ptr(),
            access | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by `open` and nothing else holds it.
    Ok(Some(unsafe { std::fs::File::from_raw_fd(fd) }))
}

/// The text of the file at `path` under `root`, opened with [`open_regular_in_root`]: `Ok(None)` when
/// there is no such file, an error when there is one this cannot use (see [`read_regular`]) or the
/// resolution itself failed. The difference is the point: `kern exec -u` reporting "no such user" for
/// a passwd it could not READ (an `openat2` this kernel does not have, a FIFO, 9 MiB of it) would send
/// the reader looking for an account instead of at the cause.
pub(crate) fn read_regular_in_root(
    root: std::os::fd::BorrowedFd<'_>,
    path: &str,
    max: u64,
) -> std::io::Result<Option<String>> {
    match open_regular_in_root(root, path, libc::O_RDONLY)? {
        Some(file) => read_regular(&file, max).map(Some),
        None => Ok(None),
    }
}

/// The text of `file` if it is a REGULAR file of at most `max` bytes and UTF-8, else an
/// `InvalidData` error saying which of the three it is not.
///
/// The type is checked on the OPEN descriptor, so a swap after the check reads nothing new, and the
/// read stops at `max + 1` bytes whatever the size said, because a file can grow between `fstat` and
/// `read`. Read from the current offset, which is the start for a file just opened.
pub(crate) fn read_regular(file: &std::fs::File, max: u64) -> std::io::Result<String> {
    let bytes = read_regular_bytes(file, max)?;
    String::from_utf8(bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "not UTF-8".to_string()))
}

/// The BYTES of `file` under the same two rules, for a record that is not text.
///
/// Split out of [`read_regular`] rather than written beside it: the kept-box record
/// ([`crate::keepbox`]) holds an argv, and an argument is not required to be UTF-8, so it needs the
/// regular-file check and the bound without the decode. There was a third bounded reader in that
/// module that had neither check, and a FIFO planted at the record's name hung `kern ps -a` for
/// ever (measured, `timeout 10` returned 124).
pub(crate) fn read_regular_bytes(file: &std::fs::File, max: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let unusable = |why: String| std::io::Error::new(std::io::ErrorKind::InvalidData, why);
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(unusable("not a regular file".to_string()));
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max || meta.len() > max {
        return Err(unusable(format!("larger than {max} bytes")));
    }
    Ok(bytes)
}
