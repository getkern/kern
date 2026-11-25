//! A process pinned by a pidfd: what a box's supervisor waits on for its log pump to finish, at
//! the exit itself rather than on a timer. Where there is none (a kernel before 5.3, or a process
//! already gone), the caller keeps a timer.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// A pidfd for one process. It pins the process it was opened on, so a pid reused afterwards is
/// never the one waited for; a caller that opened it AFTER the pid could have been reused checks
/// the identity (start time) it already trusts, as `registry::pair_alive` does.
pub(crate) struct PidFd(OwnedFd);

impl PidFd {
    /// `None` without `pidfd_open` or for a pid that is not a live process.
    pub(crate) fn open(pid: i32) -> Option<Self> {
        if pid <= 0 {
            return None;
        }
        // SAFETY: `pidfd_open(pid, 0)` takes two integers and returns a new descriptor or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        let fd = RawFd::try_from(fd).ok().filter(|f| *f >= 0)?;
        // SAFETY: a descriptor the kernel just returned to this process, owned by nothing else.
        Some(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    pub(crate) fn raw(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    /// Block until the process exits or `ms` milliseconds pass. `true` only when it was seen to
    /// exit; an error answers `false`.
    pub(crate) fn wait_exit(&self, ms: i32) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.raw(),
            events: libc::POLLIN,
            revents: 0,
        };
        // Restarted on a signal against the deadline, so a signal cannot shorten the wait.
        let n = crate::eintr::poll(std::slice::from_mut(&mut pfd), ms);
        n > 0 && pfd.revents & libc::POLLIN != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pidfd of a child is readable once the child exits, not before; a pid that is no process
    /// opens none.
    #[test]
    fn a_pidfd_wakes_at_the_exit_and_not_before() {
        let Ok(mut child) = std::process::Command::new("sleep").arg("0.15").spawn() else {
            eprintln!("skip: no `sleep` here");
            return;
        };
        let Ok(pid) = i32::try_from(child.id()) else {
            return;
        };
        let Some(p) = PidFd::open(pid) else {
            let _ = child.wait();
            eprintln!("skip: pidfd_open unsupported on this kernel");
            return;
        };
        assert!(!p.wait_exit(10), "the child is still running");
        let t = std::time::Instant::now();
        assert!(p.wait_exit(5000), "the exit must wake the wait");
        assert!(t.elapsed() < std::time::Duration::from_secs(2));
        let _ = child.wait();
        assert!(PidFd::open(0).is_none() && PidFd::open(-1).is_none());
    }
}
