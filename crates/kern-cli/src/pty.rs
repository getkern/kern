//! Host-side PTY support for `-it`. Allocates a pseudo-terminal, puts the host terminal in raw
//! mode (the caller restores it), copies the window size in, and propagates `SIGWINCH`. The byte
//! pump and the box wait live in `kern_isolation` (it owns the box pid); this module owns only the
//! host-terminal state. Dependency-free: just `libc` + the standard `posix_openpt` dance.

use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, Ordering};

/// A PTY pair. The `slave` becomes the box's controlling terminal; the `master` stays in kern.
pub struct Pty {
    pub master: RawFd,
    pub slave: RawFd,
}

/// Open a new PTY pair (`posix_openpt` + `grantpt` + `unlockpt` + `ptsname_r` + open). No libutil
/// dependency. On any failure the master is closed so no fd leaks.
pub fn open() -> io::Result<Pty> {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if master < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::grantpt(master) != 0 || libc::unlockpt(master) != 0 {
            let e = io::Error::last_os_error();
            libc::close(master);
            return Err(e);
        }
        let mut name = [0 as libc::c_char; 256];
        if libc::ptsname_r(master, name.as_mut_ptr(), name.len()) != 0 {
            let e = io::Error::last_os_error();
            libc::close(master);
            return Err(e);
        }
        let slave = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        if slave < 0 {
            let e = io::Error::last_os_error();
            libc::close(master);
            return Err(e);
        }
        // Close-on-exec the master: the box child inherits it across fork, and without this it would
        // survive the box's `execvp` - leaving the workload holding its own terminal's master end (a
        // confused-deputy that could steal bytes from the pump). The parent's pump never execs, so
        // CLOEXEC doesn't affect it. (The slave is dup2'd onto the box's stdio, which stays open.)
        libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC);
        Ok(Pty { master, slave })
    }
}

/// Is `fd` a terminal?
fn is_tty(fd: RawFd) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

/// Put the terminal at `fd` into raw mode, returning the previous settings for [`restore`].
pub(crate) fn make_raw(fd: RawFd) -> io::Result<libc::termios> {
    unsafe {
        let mut prev: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut prev) != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = prev;
        libc::cfmakeraw(&mut raw);
        if libc::tcsetattr(fd, libc::TCSANOW, &raw) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(prev)
    }
}

/// Restore terminal settings previously saved by [`make_raw`]. Best-effort.
pub fn restore(fd: RawFd, prev: &libc::termios) {
    unsafe {
        libc::tcsetattr(fd, libc::TCSANOW, prev);
    }
}

/// Put the host's stdin (fd 0) into raw mode and start forwarding window resizes to the PTY
/// `master` - but ONLY when our stdin is itself a terminal. When kern's input is piped, stdin isn't
/// a tty: the box still gets its PTY, we just leave our own stdin alone. Returns the saved terminal
/// settings to hand back to [`restore`] (or `None` when there was nothing to raw). Shared by
/// `box -it` and `exec -it`. With no terminal on stdin, the size comes from `KERN_TTY_SIZE` /
/// `KERN_TTY_SIZE_FILE` (see `piped_size_setup`).
pub fn raw_with_resize(master: RawFd) -> Option<libc::termios> {
    if !is_tty(0) {
        piped_size_setup(master);
        return None;
    }
    copy_winsize(0, master);
    install_winch(master);
    make_raw(0).ok()
}

/// Copy the window size from `from` (the host tty) to `to` (the PTY master). Best-effort.
pub(crate) fn copy_winsize(from: RawFd, to: RawFd) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(from, libc::TIOCGWINSZ, &mut ws) == 0 {
            libc::ioctl(to, libc::TIOCSWINSZ, &ws);
        }
    }
}

/// PTY master fd the `SIGWINCH` handler resizes (set by [`install_winch`]).
static WINCH_MASTER: AtomicI32 = AtomicI32::new(-1);

/// Async-signal-safe `SIGWINCH` handler: re-read the host window size and push it to the master.
/// Only `ioctl` (async-signal-safe) is called.
extern "C" fn on_winch(_sig: libc::c_int) {
    let m = WINCH_MASTER.load(Ordering::Relaxed);
    if m >= 0 {
        unsafe {
            let mut ws: libc::winsize = std::mem::zeroed();
            if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) == 0 {
                libc::ioctl(m, libc::TIOCSWINSZ, &ws);
            }
        }
    }
}

/// Point `SIGWINCH` at a DIFFERENT master, and push the current size onto it once.
///
/// The box may build its own terminal from its own devpts and hand that master back after the fork
/// (see `kern_isolation::ptybox`), which leaves the size handling aimed at the host pair the CLI
/// opened first. Without this the interactive box would start at whatever size the new master
/// defaulted to and would never learn about a resize: the handler would keep writing to a terminal
/// nobody is reading.
///
/// Safe to call when `install_winch` has not run: the store is what the handler reads, and the
/// initial `ioctl` pair is the same one the handler performs.
pub fn retarget_resize(master: RawFd) {
    WINCH_MASTER.store(master, Ordering::Relaxed);
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) == 0 {
            libc::ioctl(master, libc::TIOCSWINSZ, &ws);
            return;
        }
    }
    // No terminal on stdin: the size the caller declared, if it declared one (see `piped_size_setup`).
    apply_piped_size(master);
}

/// Forward host terminal resizes to the PTY `master`. No `SA_RESTART`, so the resize also wakes the
/// pump's `poll()` (it re-polls on `EINTR`).
fn install_winch(master: RawFd) {
    WINCH_MASTER.store(master, Ordering::Relaxed);
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_winch as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut());
    }
}

// ---- the size of a box terminal whose kern has no terminal of its own ----------------------------
//
// `-it` with stdin a PIPE still gives the box a pty (an SDK drives it through pipes: Node has no
// openpty), but kern learns the window size from TIOCGWINSZ on fd 0, and a pipe has none: the box sat
// at the kernel's 0x0 and `stty size` answered "0 0". Two variables say it instead, read only when
// stdin is not a terminal, so a terminal's behaviour does not change:
//
//   KERN_TTY_SIZE=COLSxROWS        the size, once.
//   KERN_TTY_SIZE_FILE=<path>      a file holding COLSxROWS, read at start and on every SIGWINCH: the
//                                  caller rewrites it (atomically, by rename) and signals kern.
//
// THE FILE IS READ IN THE SIGNAL HANDLER, with openat/read/close only. All three are on POSIX's
// async-signal-safe list (signal-safety(7)), the parse touches only a stack buffer, and the name below
// is leaked once before the handler is installed. A flag polled by the pump would need a hook in
// `kern_isolation`'s pump loop for the same effect.
//
// THROUGH A DESCRIPTOR ON ITS DIRECTORY, opened before any namespace is entered: `kern exec` pumps
// from inside the box's mount namespace, where the caller's path names another file or none (MEASURED:
// by path, `exec -it` stayed at "0 0" while `box -it` resized). The directory and not the file, because
// the caller replaces the file by rename. Close-on-exec, so no workload inherits it.

/// `KERN_TTY_SIZE`, packed `cols << 16 | rows`; 0 when unset.
static PIPED_SIZE: AtomicU32 = AtomicU32::new(0);
/// `O_PATH` descriptor on `KERN_TTY_SIZE_FILE`'s directory; -1 when unset.
static SIZE_DIR: AtomicI32 = AtomicI32::new(-1);
/// `KERN_TTY_SIZE_FILE`'s last component, NUL-terminated, leaked for the life of the process.
static SIZE_NAME: AtomicPtr<libc::c_char> = AtomicPtr::new(std::ptr::null_mut());

/// `COLSxROWS` (trailing whitespace allowed), each 1..=65535. No allocation: the signal handler calls it.
pub(crate) fn parse_size(raw: &[u8]) -> Option<(u16, u16)> {
    let mut end = raw.len();
    while end > 0 && raw[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let raw = &raw[..end];
    let x = raw.iter().position(|b| *b == b'x')?;
    let num = |part: &[u8]| -> Option<u16> {
        if part.is_empty() || part.len() > 5 {
            return None;
        }
        let mut v: u32 = 0;
        for b in part {
            if !b.is_ascii_digit() {
                return None;
            }
            v = v * 10 + u32::from(b - b'0');
        }
        u16::try_from(v).ok().filter(|v| *v > 0)
    };
    Some((num(&raw[..x])?, num(&raw[x + 1..])?))
}

/// The size in `KERN_TTY_SIZE_FILE`, or `None` when unset, unreadable or malformed.
/// Async-signal-safe: open, read and close on a stack buffer.
fn read_size_file() -> Option<(u16, u16)> {
    let name = SIZE_NAME.load(Ordering::Acquire);
    let dir = SIZE_DIR.load(Ordering::Acquire);
    if name.is_null() || dir < 0 {
        return None;
    }
    let mut buf = [0u8; 32];
    // SAFETY: `name` is a NUL-terminated string leaked by `piped_size_setup` and never freed.
    let n = unsafe {
        let fd = libc::openat(
            dir,
            name,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NONBLOCK,
        );
        if fd < 0 {
            return None;
        }
        let n = libc::read(fd, buf.as_mut_ptr().cast(), buf.len());
        libc::close(fd);
        n
    };
    let n = usize::try_from(n).ok()?;
    parse_size(buf.get(..n)?)
}

/// Set `master` to the declared size: the file when it answers, else `KERN_TTY_SIZE`.
fn apply_piped_size(master: RawFd) {
    let size = read_size_file().or_else(|| {
        let packed = PIPED_SIZE.load(Ordering::Relaxed);
        (packed != 0).then_some(((packed >> 16) as u16, (packed & 0xffff) as u16))
    });
    if let Some((cols, rows)) = size {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &ws) };
    }
}

/// `SIGWINCH` with no terminal on stdin: re-read `KERN_TTY_SIZE_FILE` and push it to the master.
extern "C" fn on_winch_piped(_sig: libc::c_int) {
    // SAFETY: errno is thread-local; saved and restored so the interrupted code never sees ours.
    let saved = unsafe { *libc::__errno_location() };
    let m = WINCH_MASTER.load(Ordering::Relaxed);
    if m >= 0 {
        apply_piped_size(m);
    }
    unsafe { *libc::__errno_location() = saved };
}

/// Read `KERN_TTY_SIZE` / `KERN_TTY_SIZE_FILE` (stdin is not a terminal), size `master`, and when a
/// file is named, re-read it on `SIGWINCH`. A malformed value is reported and ignored.
fn piped_size_setup(master: RawFd) {
    if let Some(v) = crate::global_env("KERN_TTY_SIZE") {
        use std::os::unix::ffi::OsStrExt;
        match parse_size(v.as_bytes()) {
            Some((c, r)) => PIPED_SIZE.store(u32::from(c) << 16 | u32::from(r), Ordering::Relaxed),
            None => eprintln!("kern: warning: KERN_TTY_SIZE={v:?} is not COLSxROWS; ignored"),
        }
    }
    let mut watch_file = false;
    if let Some(v) = crate::global_env("KERN_TTY_SIZE_FILE").filter(|v| !v.is_empty()) {
        match open_size_file_dir(std::path::Path::new(&v)) {
            Ok((dir, name)) => {
                SIZE_NAME.store(name.into_raw(), Ordering::Release);
                SIZE_DIR.store(dir, Ordering::Release);
                watch_file = true;
            }
            Err(e) => eprintln!("kern: warning: KERN_TTY_SIZE_FILE={v:?}: {e}; ignored"),
        }
    }
    WINCH_MASTER.store(master, Ordering::Relaxed);
    apply_piped_size(master);
    if watch_file {
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_winch_piped as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = 0;
            libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut());
        }
    }
}

/// An `O_PATH` close-on-exec descriptor on `path`'s directory, and its last component.
fn open_size_file_dir(path: &std::path::Path) -> io::Result<(RawFd, std::ffi::CString)> {
    use std::os::unix::ffi::OsStrExt;
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidInput, what.to_string());
    let name = path.file_name().ok_or_else(|| bad("names no file"))?;
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => std::path::Path::new("."),
    };
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| bad("contains a NUL byte"))?;
    let cdir = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| bad("contains a NUL byte"))?;
    let fd = unsafe {
        libc::open(
            cdir.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fd, name))
}

#[cfg(test)]
mod tests {
    use super::parse_size;

    #[test]
    fn a_declared_size_is_cols_x_rows_and_nothing_else() {
        assert_eq!(parse_size(b"100x30"), Some((100, 30)));
        assert_eq!(parse_size(b"120x40\n"), Some((120, 40)));
        assert_eq!(parse_size(b"65535x1"), Some((65535, 1)));
        for bad in [
            &b""[..],
            b"x",
            b"100",
            b"100x",
            b"x30",
            b"0x30",
            b"100x0",
            b"65536x1",
            b"-1x2",
            b"1 x2",
            b"100x30x2",
            b"100X30",
            b"999999x1",
        ] {
            assert_eq!(parse_size(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
    }
}
