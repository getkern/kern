//! Restart-on-`EINTR` wrappers for the two blocking syscalls kern makes directly.
//!
//! `waitpid` and `poll` both return -1 with `EINTR` when a signal is delivered while they block.
//! kern installs a handler for almost nothing, which is why this looked unreachable and stayed
//! unwrapped for so long - but kern does not run alone. A `SIGWINCH` from a resized terminal reaches
//! `kern top`, a profiler's `SIGPROF` reaches anything run under one, and a shell's job-control
//! signals reach a foreground box. Every call site read -1 as a real outcome: an interrupted
//! `waitpid` left `status` at whatever it was initialised to and the caller decoded that as the
//! child's exit, and an interrupted `poll` was indistinguishable from "the timeout expired, there is
//! nothing to read".
//!
//! `poll` is the one with a trap in it. Retrying with the ORIGINAL timeout restarts the clock, so a
//! steady drip of signals extends a 10 s bound without limit - the bug the naive fix introduces
//! while appearing to fix this one. The remaining time is recomputed from a monotonic deadline
//! instead, which is what a bounded wait was always supposed to mean.

/// `waitpid(2)`, restarted on `EINTR`.
///
/// Same signature and return value as `libc::waitpid`, minus the spurious -1. `status` is only
/// written by a call that actually reaped, so a caller may still decode it exactly as before.
pub(crate) fn waitpid(
    pid: libc::pid_t,
    status: &mut libc::c_int,
    options: libc::c_int,
) -> libc::pid_t {
    loop {
        let r = unsafe { libc::waitpid(pid, status, options) };
        if r == -1 && errno() == libc::EINTR {
            continue;
        }
        return r;
    }
}

/// Reap a child whose exit status nobody reads, restarted on `EINTR`.
///
/// Separate from [`waitpid`] because the callers that discard the status passed a null pointer, and
/// a `&mut` that is documented as "may be null" is a worse interface than two functions.
pub(crate) fn reap(pid: libc::pid_t) {
    let mut ignored = 0;
    let _ = waitpid(pid, &mut ignored, 0);
}

/// `poll(2)`, restarted on `EINTR` against a monotonic deadline.
///
/// `timeout_ms` keeps `poll`'s own meaning: negative blocks forever, 0 returns at once. A restart
/// after a signal gets the time that is LEFT, never a fresh full timeout, so the wall-clock bound a
/// caller asked for is the bound it gets no matter how many signals arrive.
pub(crate) fn poll(fds: &mut [libc::pollfd], timeout_ms: libc::c_int) -> libc::c_int {
    let nfds = fds.len() as libc::nfds_t;
    // An infinite or zero timeout needs no deadline arithmetic: `poll` already means the right
    // thing on a restart, since there is no budget to run down.
    if timeout_ms <= 0 {
        loop {
            let r = unsafe { libc::poll(fds.as_mut_ptr(), nfds, timeout_ms) };
            if r == -1 && errno() == libc::EINTR {
                continue;
            }
            return r;
        }
    }
    let deadline = monotonic_ms().saturating_add(timeout_ms as u64);
    loop {
        let now = monotonic_ms();
        // Deadline already passed while handling a signal: report the timeout the caller asked
        // for rather than issuing a `poll` that would block for a fresh full interval.
        if now >= deadline {
            return 0;
        }
        let left = (deadline - now).min(libc::c_int::MAX as u64) as libc::c_int;
        let r = unsafe { libc::poll(fds.as_mut_ptr(), nfds, left) };
        if r == -1 && errno() == libc::EINTR {
            continue;
        }
        return r;
    }
}

fn errno() -> libc::c_int {
    // `__errno_location` is glibc/musl's thread-local errno. `std::io::Error::last_os_error()`
    // would allocate nothing either, but it is the raw value that is wanted here and this keeps
    // the two wrappers symmetrical.
    unsafe { *libc::__errno_location() }
}

fn monotonic_ms() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // CLOCK_MONOTONIC cannot step backwards or be adjusted by NTP, so a deadline built from it
    // survives a clock change mid-wait. CLOCK_REALTIME would not.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64) * 1000 + (ts.tv_nsec as u64) / 1_000_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waitpid_reaps_a_real_child() {
        // The control: the wrapper must still behave like `waitpid` when no signal interferes.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe { libc::_exit(7) };
        }
        let mut st = -1;
        assert_eq!(waitpid(pid, &mut st, 0), pid);
        assert!(libc::WIFEXITED(st), "child did not exit normally");
        assert_eq!(libc::WEXITSTATUS(st), 7);
    }

    #[test]
    fn poll_honours_its_deadline() {
        // A pipe nobody writes to: `poll` can only come back by timing out. The assertion is on the
        // ELAPSED time, not on the return value, because the return value was already right before
        // this module existed - it is the restarted clock that this has to rule out.
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let mut pfd = [libc::pollfd {
            fd: fds[0],
            events: libc::POLLIN,
            revents: 0,
        }];
        let t0 = monotonic_ms();
        assert_eq!(poll(&mut pfd, 120), 0, "expected a timeout, not readiness");
        let dt = monotonic_ms() - t0;
        assert!(
            dt >= 110,
            "returned after {dt} ms, before the 120 ms asked for"
        );
        assert!(dt < 2000, "took {dt} ms for a 120 ms timeout");
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    #[test]
    fn poll_reports_a_readable_fd() {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { libc::write(fds[1], b"x".as_ptr().cast(), 1) }, 1);
        let mut pfd = [libc::pollfd {
            fd: fds[0],
            events: libc::POLLIN,
            revents: 0,
        }];
        assert_eq!(poll(&mut pfd, 1000), 1);
        assert_ne!(pfd[0].revents & libc::POLLIN, 0);
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    #[test]
    fn zero_timeout_returns_at_once() {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let mut pfd = [libc::pollfd {
            fd: fds[0],
            events: libc::POLLIN,
            revents: 0,
        }];
        let t0 = monotonic_ms();
        assert_eq!(poll(&mut pfd, 0), 0);
        assert!(monotonic_ms() - t0 < 1000, "a 0 ms poll blocked");
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
}
