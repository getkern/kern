//! Host-side PTY support for `-it`. Allocates a pseudo-terminal, puts the host terminal in raw
//! mode (the caller restores it), copies the window size in, and propagates `SIGWINCH`. The byte
//! pump and the box wait live in `kern_isolation` (it owns the box pid); this module owns only the
//! host-terminal state. Dependency-free: just `libc` + the standard `posix_openpt` dance.

use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};

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
fn make_raw(fd: RawFd) -> io::Result<libc::termios> {
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
/// `box -it` and `exec -it`.
pub fn raw_with_resize(master: RawFd) -> Option<libc::termios> {
    if !is_tty(0) {
        return None;
    }
    copy_winsize(0, master);
    install_winch(master);
    make_raw(0).ok()
}

/// Copy the window size from `from` (the host tty) to `to` (the PTY master). Best-effort.
fn copy_winsize(from: RawFd, to: RawFd) {
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
