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

/// `read(2)`, restarted on `EINTR`.
///
/// The third blocking syscall kern makes directly, added when `compose watch` began reading an
/// inotify fd: a signal delivered while that read blocks returns -1/`EINTR`, and a caller that reads
/// -1 as "no events" would silently stop rebuilding after the first `SIGWINCH`. The same class the
/// module header describes, in a third place.
///
/// Returns the byte count, or -1 with `errno` set for a real failure. `EAGAIN` is NOT retried: on a
/// non-blocking fd it means "nothing to read", which is an answer rather than an interruption, and
/// looping on it would spin.
///
/// # Safety
///
/// `buf` must point to at least `len` writable bytes for the duration of the call. The signature is
/// `unsafe`-free because every caller in this tree passes a stack buffer it owns; the pointer pair is
/// the shape `read(2)` takes.
pub(crate) fn read(fd: libc::c_int, buf: *mut libc::c_void, len: usize) -> isize {
    loop {
        // SAFETY: the caller's contract above - `buf` is `len` writable bytes it owns.
        let r = unsafe { libc::read(fd, buf, len) };
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
    // `waitpid(-1, ..)` does NOT mean "this child", it means "any child". A caller that passed a
    // failed `fork()`'s -1 through would reap whatever exits first, which on the foreground box path
    // is plausibly the box's own PID 1 that another wait is about to collect: an exit code lost or
    // attributed to the wrong process, the exact class this module exists to close.
    debug_assert!(pid > 0, "reap() takes a specific child, never a wait-any");
    if pid <= 0 {
        return;
    }
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
    // No usable clock: fall back to the plain restart with the original timeout. That can stretch
    // the bound under a signal storm, but it is a HONEST degradation, where trusting a bogus
    // deadline would return an instant phantom timeout the caller reads as "nothing to read" - a
    // wrong value returned silently, in the module whose whole point is to stop doing that.
    let Some(start) = monotonic_ms() else {
        loop {
            let r = unsafe { libc::poll(fds.as_mut_ptr(), nfds, timeout_ms) };
            if r == -1 && errno() == libc::EINTR {
                continue;
            }
            return r;
        }
    };
    let deadline = start.saturating_add(timeout_ms as u64);
    loop {
        let Some(now) = monotonic_ms() else {
            let r = unsafe { libc::poll(fds.as_mut_ptr(), nfds, timeout_ms) };
            if r == -1 && errno() == libc::EINTR {
                continue;
            }
            return r;
        };
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

fn monotonic_ms() -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // CLOCK_MONOTONIC cannot step backwards or be adjusted by NTP, so a deadline built from it
    // survives a clock change mid-wait. CLOCK_REALTIME would not.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return None;
    }
    Some((ts.tv_sec as u64) * 1000 + (ts.tv_nsec as u64) / 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_ms() -> u64 {
        monotonic_ms().expect("CLOCK_MONOTONIC")
    }

    extern "C" fn noop(_: libc::c_int) {}

    /// Install a SIGUSR1 handler with `SA_RESTART` explicitly OFF, and hammer the CALLING thread
    /// with it from a helper thread. Both halves are load-bearing: a signal whose default action is
    /// "ignore" (SIGWINCH, SIGCHLD, SIGURG) never interrupts a syscall at all, because the kernel
    /// only unblocks one when it has a handler to run, and `SA_RESTART` would make the kernel
    /// restart the syscall itself so EINTR never reaches userspace. Getting either wrong yields a
    /// test that passes against completely unwrapped code, which is what the first attempt did.
    fn under_signal_storm<T>(body: impl FnOnce() -> T) -> T {
        // Serialised, and the handler is never restored. Rust runs tests in parallel threads of ONE
        // process, so a concurrent storm test that reset SIGUSR1 to SIG_DFL made this one's next
        // signal kill the whole test binary (signal 10). The disposition is process-wide state:
        // two tests cannot own it at once, and handing it back is what breaks the other.
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = noop as extern "C" fn(libc::c_int) as libc::sighandler_t;
            sa.sa_flags = 0; // NOT SA_RESTART: this is what makes EINTR observable
            libc::sigemptyset(&mut sa.sa_mask);
            assert_eq!(libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut()), 0);
        }
        // pthread_kill, not kill(getpid()): a process-directed signal may be taken by ANY thread
        // that has it unblocked, including the sender, and would then never interrupt our poll.
        let target = unsafe { libc::pthread_self() };
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let s2 = stop.clone();
        let t = std::thread::spawn(move || {
            while !s2.load(std::sync::atomic::Ordering::Relaxed) {
                unsafe { libc::pthread_kill(target, libc::SIGUSR1) };
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });
        let out = body();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = t.join();
        out
    }

    /// THE test of this module: the only one that fails against either wrong implementation.
    ///
    /// No retry at all -> `poll` returns -1 on the first signal and the `assert_eq!(.., 0)` fails.
    /// Retry with the ORIGINAL timeout -> the clock restarts on every signal, so with one signal
    /// every 10 ms against a 300 ms budget the call never returns and the upper bound fails.
    /// Only the monotonic deadline lands inside the window.
    #[test]
    fn poll_deadline_survives_a_signal_storm() {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let mut pfd = [libc::pollfd {
            fd: fds[0],
            events: libc::POLLIN,
            revents: 0,
        }];
        let (rc, dt) = under_signal_storm(|| {
            let t0 = now_ms();
            let rc = poll(&mut pfd, 300);
            (rc, now_ms() - t0)
        });
        assert_eq!(rc, 0, "poll returned {rc}: EINTR leaked to the caller");
        assert!(
            dt >= 280,
            "returned after {dt} ms, short of the 300 ms budget"
        );
        assert!(
            dt < 900,
            "took {dt} ms for a 300 ms budget: the timeout is being restarted per signal"
        );
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    /// Same storm against `waitpid`. Unwrapped, this returns -1 with `status` untouched and the
    /// caller decodes the initialiser as the child's exit code.
    #[test]
    fn waitpid_survives_a_signal_storm() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // Nothing may be added between fork() and _exit(): this process is multi-threaded, so
            // anything that allocates or takes a lock another thread held at fork time can deadlock.
            unsafe {
                libc::usleep(250_000);
                libc::_exit(9)
            };
        }
        let mut st = -1;
        let r = under_signal_storm(|| {
            let mut st2 = -1;
            let r = waitpid(pid, &mut st2, 0);
            st = st2;
            r
        });
        assert_eq!(r, pid, "waitpid returned {r}: EINTR leaked to the caller");
        assert!(libc::WIFEXITED(st), "status {st} was never written");
        assert_eq!(libc::WEXITSTATUS(st), 9);
    }

    #[test]
    fn waitpid_reaps_a_real_child() {
        // The control: unchanged behaviour when no signal interferes. See the note above about the
        // fork/_exit window - nothing may be inserted there.
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
        // A control, not a proof: with no signals this passes against unwrapped code too.
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let mut pfd = [libc::pollfd {
            fd: fds[0],
            events: libc::POLLIN,
            revents: 0,
        }];
        let t0 = now_ms();
        assert_eq!(poll(&mut pfd, 120), 0, "expected a timeout, not readiness");
        let dt = now_ms() - t0;
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
        let t0 = now_ms();
        assert_eq!(poll(&mut pfd, 0), 0);
        assert!(now_ms() - t0 < 1000, "a 0 ms poll blocked");
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
}
