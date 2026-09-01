//! Keeping a box alive, and taking it down: the parts that outlive one verb.
//!
//! A SUPPORT module. `start` arms the timeout and the health checker, `inspect` stops and freezes,
//! `system` reaps what is left, `compose` reads a health state to decide a dependency, and all of
//! them need the same primitives, so they live here and the parent re-exports them.
//!
//! Contents: the detached fork and its stop path, the foreground timeout watchdog, the graceful kill
//! (TERM, grace, KILL) with its zombie-aware exit reading, the health checker and its config, the
//! freeze guard that thaws on a fatal signal, and the reaper that keeps a supervisor from collecting
//! zombies.

use super::*;

/// Fork a health-checker for a detached box: every `interval` s it runs `health_cmd` (via
/// `/bin/sh -c`) inside the box and records `healthy`/`unhealthy` in the registry health sidecar
/// (shown by `kern ps`). It re-reads the box's PID 1 each round, so it follows `--restart`s.
/// Returns the checker's pid.
pub(crate) fn spawn_health_checker(name: String, pid: i32, hc: OwnedHealth) -> Option<i32> {
    // `Option`, not a bare pid, for the reason `fork_detached` spells out: this returned -1 on a
    // failed fork and the teardown passed it to `kill`.
    let child = unsafe { libc::fork() };
    if child > 0 {
        return Some(child);
    }
    if child < 0 {
        return None;
    }
    // CHILD: die with the launcher. Without this a SIGKILL'd parent (which skips every teardown,
    // including `stop_health_checker`) left this loop probing a box that no longer exists, forever -
    // measured: one orphan per SIGKILL, and the box itself does not leak because it already carries
    // the same link. The box's PDEATHSIG is set for exactly this reason; the checker had no such
    // guard because it only ever ran under a supervisor that stopped it explicitly.
    //
    // The prctl has a well-known race: if the parent dies between the `fork` and here, the signal has
    // already been delivered to nobody. Re-reading `getppid` after arming closes it - a changed
    // parent means we were reparented, so there is nothing left to probe for.
    //
    // Safe on BOTH launch paths: `box_run`'s only scope re-exec happens before either fork site, so
    // this process's parent keeps its pid for as long as the box lives.
    let launcher = unsafe { libc::getppid() };
    arm_pdeathsig();
    if unsafe { libc::getppid() } != launcher {
        unsafe { libc::_exit(0) };
    }
    // Shed inherited fds (the detached box's readiness pipe would otherwise hang `box -d`), then
    // quiet stdio so probe output doesn't land in the box log.
    kern_isolation::shed_inherited_fds(-1);
    detach_stdio(None);
    registry::set_health(&name, pid, "starting");
    let probe = ["/bin/sh".to_string(), "-c".to_string(), hc.cmd];
    let mut elapsed = 0u64; // seconds since the checker started
    let mut fails = 0u32; // consecutive failures
    let mut acted = false; // acted on the *current* unhealthy episode (reset when healthy again)
    let mut first = true;
    loop {
        // The FIRST probe runs after a short fixed delay, NOT after a full `interval`: a dependent box
        // gated on `service_healthy` should start as soon as the dependency is actually ready, not wait
        // a whole interval for the first check. A service that boots in 50 ms was being held ~1 s just
        // because `interval: 1s` slept before the first probe - a needless bottleneck in a `depends_on:
        // condition: service_healthy` stack. Subsequent probes use the real interval.
        if first {
            unsafe { libc::usleep(100_000) }; // 100 ms - let the process exec before the first probe
            first = false;
        } else {
            unsafe { libc::sleep(hc.interval as libc::c_uint) };
            elapsed = elapsed.saturating_add(hc.interval);
        }
        // The box may have been `kern rename`d since we started: resolve its CURRENT name by pid so we
        // follow the rename instead of writing health under (and looking up) the stale original name.
        // `name_for_pid` is a readdir + filename match (no per-entry file reads), far cheaper than a
        // `list()`. Then `find(cur)` opens ONLY this box's entry - a full `list()` per interval per
        // checker would be O(N²) steady-state across N checkers.
        let cur = registry::name_for_pid(pid).unwrap_or_else(|| name.clone());
        let entry = registry::find(&cur);
        let pid1 = entry.as_ref().map(|b| b.pid1).unwrap_or(0);
        let status = if pid1 > 0 {
            // Probe under the box's RECORDED seccomp mode, read from the same entry as `pid1`, so the
            // probe's filter matches PID 1 by construction - not by the assumption that the checker's
            // environment still equals the box's creation environment.
            let mode = entry.as_ref().map(|b| b.seccomp_mode).unwrap_or_default();
            let ok = run_probe(pid1, &probe, hc.timeout, mode);
            if ok {
                fails = 0;
                acted = false;
                "healthy"
            } else {
                fails = fails.saturating_add(1);
                // During the start-period grace, a failure keeps the box "starting" (Docker
                // semantics - a slow-booting service isn't flapped to unhealthy). After it, a box is
                // "unhealthy" only once `retries` checks have failed in a row; until then hold
                // "starting" so a single blip doesn't trip an orchestrator.
                if elapsed <= hc.start_period || fails < hc.retries {
                    "starting"
                } else {
                    "unhealthy"
                }
            }
        } else {
            "starting"
        };
        registry::set_health(&cur, pid, status);
        // `--health-action`: when the box first turns unhealthy, act once (not every interval).
        if status == "unhealthy" && !acted {
            acted = true;
            match hc.action {
                HealthAction::None => {}
                // Restart: kill box PID 1 so the supervisor's on-failure policy re-runs it. Signal
                // via a pidfd taken now, so a pid recycled during a restart gap can't be the victim
                // (the registry-supplied `pid1` could be stale between the box exiting and the
                // supervisor re-registering the new one). Falls back to `kill` on kernels < 5.3.
                HealthAction::Restart => {
                    if pid1 > 0 {
                        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid1, 0) as i32 };
                        unsafe { signal_box(pidfd, pid1, libc::SIGKILL) };
                        if pidfd >= 0 {
                            unsafe { libc::close(pidfd) };
                        }
                    }
                }
                // Stop: tear the whole box down (a detached stopper that has escaped this checker's
                // process group, so the group-kill can't cut its own cleanup short), then exit - the
                // box is going away, so there's nothing left to check.
                HealthAction::Stop => {
                    spawn_detached_stop(name.clone());
                    unsafe { libc::_exit(0) };
                }
            }
        }
    }
}

/// Fork a child that has left the caller's process group (`setsid`), with inherited fds shed and
/// stdio detached - the common prologue of the detached stop/timeout helpers. Returns the child pid
/// to the parent and `None` to the child (which then runs its body and `_exit`s). Escaping the group
/// matters because these children call `stop()`, which group-kills the box; an in-group caller would
/// otherwise be cut down mid-cleanup.
pub(crate) enum Forked {
    /// The parent, holding the child's pid. Always `> 0`.
    Parent(i32),
    /// The child: run the body and `_exit`.
    Child,
    /// `fork` failed. Nothing was created, so there is nothing to run and nothing to signal.
    Failed,
}

pub(crate) fn fork_detached() -> Forked {
    // THREE STATES, NOT TWO, AND THE THIRD IS THE WHOLE POINT. This returned `Option<i32>` with
    // `child != 0` deciding, so a FAILED fork (-1) came back as `Some(-1)` and the caller handed that
    // to `libc::kill`. `kill(-1, sig)` signals EVERY process the caller may signal, which for a normal
    // user is their entire session, and the trigger is precisely the moment a fork fails: `EAGAIN`
    // under `RLIMIT_NPROC` or memory pressure, i.e. a host already running many boxes.
    //
    // `Option` could not express it: `None` already means "you are the child, run the body", so
    // reporting failure that way would have made the PARENT run the watchdog and never return.
    let child = unsafe { libc::fork() };
    if child > 0 {
        return Forked::Parent(child);
    }
    if child < 0 {
        return Forked::Failed;
    }
    unsafe { libc::setsid() };
    kern_isolation::shed_inherited_fds(-1);
    detach_stdio(None);
    Forked::Child
}

/// Signal a helper this module forked, and never anything else.
///
/// A guard on the pid, not on the caller's discipline: `kill(0, sig)` hits the caller's whole process
/// group and `kill(-1, sig)` hits every process the user owns, so a pid that is not strictly positive
/// is never a pid to signal. Returns whether the signal was delivered.
pub(crate) fn signal_helper(pid: i32, sig: libc::c_int) -> bool {
    if pid <= 0 {
        return false;
    }
    unsafe { libc::kill(pid, sig) == 0 }
}

pub(crate) fn spawn_detached_stop(name: String) {
    match fork_detached() {
        // The parent is done, and a failed fork means the stop simply does not happen here: this is a
        // best-effort helper, and the alternative (running the body in the caller) would block it.
        Forked::Parent(_) | Forked::Failed => return,
        Forked::Child => {}
    }
    let _ = stop(std::slice::from_ref(&name), false);
    unsafe { libc::_exit(0) };
}

/// Fork a watchdog for a **foreground** `--timeout N`, returning `(watchdog_pid, write_fd)`. The
/// watchdog is created in the caller's (host) pid namespace - it MUST be forked before the box's
/// `unshare(CLONE_NEWPID)`, so it is an *ancestor* of the box and can therefore signal the box's
/// ns-init (a same-namespace member cannot). It blocks reading the box's PID 1 from the returned
/// pipe (written by `on_started`); once it has it, it waits for that box to EXIT with `secs` as a
/// cap, and only if the cap is reached does it SIGTERM and - after a 2 s grace - SIGKILL the box's
/// PID 1, tearing down the whole namespace. If the pipe closes before a pid arrives (the box never
/// started and the caller cancels), the read returns 0 and the watchdog just exits.
///
/// Waiting for the exit rather than sleeping the deadline out is what stops this process outliving
/// the box it guards: see `wait_for_box_exit`.
/// Returns `None` if the pipe/fork failed (the box simply runs without a timeout).
pub(crate) fn spawn_foreground_timeout(secs: u64) -> Option<(i32, i32)> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return None;
    }
    let (rd, wr) = (fds[0], fds[1]);
    let child = unsafe { libc::fork() };
    if child < 0 {
        unsafe {
            libc::close(rd);
            libc::close(wr);
        }
        return None;
    }
    if child > 0 {
        // Parent keeps the write end. Mark it close-on-exec so the box's exec'd command doesn't
        // inherit a live host pipe fd (the parent's own `on_started` write is unaffected - CLOEXEC
        // only fires on exec).
        unsafe {
            libc::close(rd);
            libc::fcntl(wr, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        return Some((child, wr));
    }
    // CHILD (host-ns watchdog): escape our parent's group/session, drop the write end, quiet stdio.
    unsafe {
        libc::setsid();
        libc::close(wr);
    }
    kern_isolation::shed_inherited_fds(rd);
    detach_stdio(None);
    let mut buf = [0u8; 4];
    let mut got = 0usize;
    while got < buf.len() {
        let n = unsafe { libc::read(rd, buf[got..].as_mut_ptr().cast(), buf.len() - got) };
        if n <= 0 {
            unsafe { libc::_exit(0) }; // pipe closed before a pid arrived - box already gone
        }
        got += n as usize;
    }
    let pid1 = i32::from_ne_bytes(buf);
    // Pin the target with a pidfd taken NOW, while the box is still alive: a pidfd refers to that
    // exact process for its whole life, so the delayed signals below can never land on a reused pid
    // (if the box exits during the sleep, the signal just fails with ESRCH). Fall back to plain
    // `kill(pid1)` only on a kernel too old for pidfd (< 5.3) - the target boards are 5.15+.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid1, 0) as i32 };
    unsafe {
        // WAIT FOR THE BOX TO EXIT, with `secs` as a CAP - do not sleep `secs` out. A pidfd becomes
        // readable the instant the process it pins terminates, so the common case (the box finishes
        // early) wakes us at once and we exit with nothing to enforce.
        //
        // This used to be a bare `sleep(secs)`, and `cancel_foreground_timeout` was the only thing
        // that stopped it: the supervisor closes our pipe, SIGKILLs us and reaps us when the box
        // exits normally. That covers a normal exit and NOTHING else. `kern stop` kills the
        // supervisor, so the supervisor never runs its own cleanup, and this watchdog was left
        // sleeping out the remainder of the deadline: 884 KB and a pid, for 24 h with the SDK's
        // 86405 s default. Measured: `kern box difftest --timeout 300` then `kern stop difftest`
        // reported success and left this process behind for the remaining 298 seconds, and running
        // the two SDK teardown tests repeatedly accumulated 14 of them.
        //
        // Waiting on the pidfd fixes every one of those paths at once, because it keys on the fact
        // that actually matters (the box is gone) instead of on the supervisor's cooperation.
        //
        // Note it deliberately does NOT key on our pipe reaching EOF. The supervisor dying is not
        // the same event as the box dying: SIGKILL the supervisor and the box's pid 1 is orphaned
        // but keeps running, and enforcing the deadline on exactly that box is this watchdog's
        // reason to exist. The pidfd stays readable-on-exit whoever dies first, so the safety net
        // is kept while the leak goes away.
        if wait_for_box_exit(pidfd, secs.saturating_mul(1000)) {
            libc::_exit(0); // the box is already gone: nothing to signal, nothing to leave behind
        }
        signal_box(pidfd, pid1, libc::SIGTERM);
        // Same again for the grace period: a box that dies on the SIGTERM must not hold us here for
        // the full 2 s, and one that ignores it gets exactly the 2 s it used to get.
        wait_for_box_exit(pidfd, 2000);
        signal_box(pidfd, pid1, libc::SIGKILL);
        libc::_exit(0);
    }
}

/// CLOCK_MONOTONIC in milliseconds, or `None` if the clock cannot be read.
///
/// SAFETY: async-signal-safe (`clock_gettime` is on the POSIX list), so it is callable from the
/// post-fork watchdog child, which must not touch the allocator or any libc lock.
pub(crate) unsafe fn monotonic_ms() -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) != 0 {
        return None;
    }
    Some((ts.tv_sec as u64).saturating_mul(1000) + (ts.tv_nsec as u64) / 1_000_000)
}

/// Block until the process pinned by `pidfd` exits, or until `ms` milliseconds have passed.
/// Returns true **only** when it was observed to exit.
///
/// Every failure mode degrades to "sleep the deadline out and report no exit", which is precisely
/// the behaviour this replaces, so the caller's SIGTERM/SIGKILL can never fire EARLY on a live box:
///
///   * no pidfd at all (kernel < 5.3, or `pidfd_open` refused) -> sleep, exactly as before;
///   * the clock cannot be read -> sleep, rather than loop on an unbounded deadline;
///   * `POLLERR`/`POLLNVAL` (an fd we cannot wait on) -> sleep out what is left of the deadline;
///   * `EINTR` -> retry, bounded by the absolute deadline, so a signal cannot shorten it.
///
/// SAFETY: async-signal-safe - `poll`, `clock_gettime` and `sleep` only, no allocation.
pub(crate) unsafe fn wait_for_box_exit(pidfd: i32, ms: u64) -> bool {
    // `sleep` takes whole seconds: round UP, so a sub-second deadline is never truncated to zero.
    let sleep_out = |left: u64| {
        if left > 0 {
            libc::sleep(left.div_ceil(1000) as libc::c_uint);
        }
    };
    if pidfd < 0 {
        sleep_out(ms);
        return false;
    }
    let Some(start) = monotonic_ms() else {
        sleep_out(ms);
        return false;
    };
    let deadline = start.saturating_add(ms);
    let mut pfd = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let Some(now) = monotonic_ms() else {
            sleep_out(ms);
            return false;
        };
        if now >= deadline {
            return false;
        }
        let left = deadline - now;
        // poll(2) takes an `int` of milliseconds. A deadline past ~24.8 days would overflow it, so
        // it is waited out in chunks rather than clamped to -1, which would mean "forever" and would
        // silently disarm the timeout.
        let chunk = if left > i32::MAX as u64 {
            i32::MAX
        } else {
            left as i32
        };
        pfd.revents = 0;
        let r = libc::poll(&mut pfd, 1, chunk);
        if r > 0 {
            if pfd.revents & libc::POLLIN != 0 {
                return true; // the pidfd fired: the box has terminated
            }
            // An fd we cannot wait on. Serve out the rest of the deadline the old way instead of
            // returning false immediately, which would SIGTERM a box that still has time left.
            let rest = monotonic_ms().map_or(0, |n| deadline.saturating_sub(n));
            sleep_out(rest);
            return false;
        }
        // r == 0: this chunk expired, the loop re-checks the deadline.
        // r < 0: EINTR or another error; the deadline check at the top bounds the retry.
    }
}

/// Send `sig` to the box's BOX PID 1: via its `pidfd` when we have one (reuse-proof), else plain
/// `kill`.
///
/// THE FALLBACK REFUSES A NON-POSITIVE PID, and that is not defensive padding. A box is registered
/// with `pid1: 0` and re-registered once its init exists, so between those two writes the recorded
/// value is 0 - and `kill(0, sig)` does not mean "nobody", it means the CALLER'S ENTIRE PROCESS
/// GROUP. A `kern stop` landing in that window would have signalled the stopper's own shell, and
/// with `SIGKILL` at the teardown site there is no second chance. `init_catches_signal` returns
/// `true` for `pid1 <= 0`, so the graceful arm is taken rather than skipped, which is what makes the
/// window reachable rather than theoretical.
///
/// SAFETY: async-signal-safe - an integer comparison and raw syscalls, called from the post-fork
/// watchdog child.
pub(crate) unsafe fn signal_box(pidfd: i32, pid1: i32, sig: i32) {
    if pidfd >= 0 {
        libc::syscall(libc::SYS_pidfd_send_signal, pidfd, sig, 0, 0);
    } else if pid1 > 0 {
        libc::kill(pid1, sig);
    }
}

/// Tear a box down for `kern stop`: SIGKILL its **PID-namespace init** (`pid1`) directly, then sweep
/// the supervisor's process group. Returns whether the box was **confirmed** gone.
///
/// The kernel destroys the *entire* pid namespace the instant its PID 1 dies, so no workload - not
/// even a `while True: pass` that ignores SIGTERM - can survive, and `setsid` can't dodge it (it moves
/// the session/process group, not the pid namespace). Signalling `pid1` is also what makes this reach
/// a **foreground** box: its init is not in the caller's process group, so the historical `kill(-pid)`
/// alone missed it (there's no group whose id is a non-leader supervisor's pid → a harmless ESRCH).
/// We keep the group sweep too: for a **detached** box (supervisor `setsid`-ed, pgid == pid) it reaps
/// the supervisor and any stray helpers exactly as before, and it's the only reachable target for an
/// old registry entry that never recorded `pid1`.
///
/// The pidfd is taken while the box is still alive, so both the signal and the exit-confirmation are
/// reuse-proof: a `pidfd` polls readable precisely when its process terminates (even before it's
/// reaped), which side-steps the zombie window a bare `kill(pid, 0)` probe would trip on.
/// Docker's shutdown contract: send `stop_signal` first, give the workload
/// `grace_ms` to exit on its own, then SIGKILL whatever is left.
///
/// MILLISECONDS, not seconds. What reaches here is the time LEFT until a deadline shared by the
/// whole stack, and rounding that down to a whole second threw away up to 999 ms of a grace the
/// caller asked for: MEASURED, `--stop-timeout 3` gave a 2.5 s flush only 2019 ms and SIGKILLed it
/// (Docker's `stop -t 3` let the same workload finish in 2799 ms and exit 5).
///
/// This is not politeness. A hard SIGKILL means redis loses everything since its last save and
/// postgres does crash recovery on the NEXT start, on every single `stop`. The graceful phase is what
/// lets a stateful service flush and close. `grace_ms == 0` keeps the old behaviour (straight to
/// SIGKILL) for callers that want the box gone now.
///
/// The wait is a bounded poll on the pidfd, so a workload that exits immediately costs one syscall,
/// not the whole grace. A workload that IGNORES the signal costs exactly `grace_ms` and then dies:
/// the kernel tears down the pid namespace with its PID 1, so nothing survives the SIGKILL.
/// Can `sig` actually terminate this box's init, or would the grace period be a guaranteed wait for
/// nothing?
///
/// A PID-namespace init is special: the kernel DISCARDS any signal it has no handler for, so the
/// default "terminate" action does not apply to it. A box whose command is an ordinary program that
/// installs no handler (`sleep`, and most binaries) therefore cannot be stopped by SIGTERM at all,
/// and the graceful phase becomes a full wait for an event that can never happen.
///
/// MEASURED: `kern stop` on a `sleep` box took 9013 ms, against 2 ms before the graceful phase
/// existed, because it always waited the whole 10 s and only then sent SIGKILL. A box whose init
/// DOES trap the signal (a shell with `trap`, or any real service) is unaffected and still gets its
/// full grace.
///
/// `SigCgt` in `/proc/<pid>/status` is the caught-signal mask, one bit per signal, signal `n` at bit
/// `n-1`. Unreadable, unparsable, or absent means we do NOT know: assume it IS caught, so an unknown
/// stays on the patient path rather than being killed early. Guessing wrong in that direction costs
/// a wait; guessing wrong the other way would cut a real shutdown short.
pub(crate) fn init_catches_signal(pid1: i32, sig: i32) -> bool {
    if pid1 <= 0 || !(1..=64).contains(&sig) {
        return true;
    }
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid1}/status")) else {
        return true;
    };
    let Some(mask) = status
        .lines()
        .find_map(|l| l.strip_prefix("SigCgt:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
    else {
        return true;
    };
    mask & (1u64 << (sig - 1)) != 0
}

/// The `/proc/<pid>/stat` line, or `None` if the process is gone (or was never a pid).
pub(crate) fn proc_stat(pid: i32) -> Option<String> {
    if pid <= 0 {
        return None;
    }
    std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()
}

/// A pid's single-letter run state (`R`, `S`, `T`, `Z`, ...), or `None` if it is gone.
pub(crate) fn proc_state(pid: i32) -> Option<char> {
    let stat = proc_stat(pid)?;
    registry::stat_field(&stat, 3)?.chars().next()
}

/// A pid's parent, or `None` when it cannot be read (already reaped, or a process we may not look
/// at).
pub(crate) fn parent_of(pid: i32) -> Option<i32> {
    let stat = proc_stat(pid)?;
    registry::stat_field(&stat, 4)?.parse().ok()
}

/// The exit status of a **zombie we are not the parent of**, decoded the way `waitpid(2)` reports it.
///
/// `stop` needs the box init's real exit code and cannot `wait4` for it: that init's parent is the
/// supervisor, not us. Field 52 of `/proc/<pid>/stat` (`exit_code`, since Linux 3.5) carries exactly
/// the status `waitpid` would return, and it is populated for the whole zombie window - between the
/// init's death and the supervisor reaping it.
///
/// The window is NARROW and it is a real race: the init's parent is woken by the same event our
/// pidfd poll waits on, and reading this unguarded was right in 15 runs out of 20. `ReaperHold` is
/// what makes the window ours; this function only reads what is there.
///
/// Anything unexpected - not a zombie yet, unreadable, a status that is neither an exit nor a
/// signal - returns `None`, so the caller falls back instead of recording a guess.
pub(crate) fn zombie_exit_code(pid: i32) -> Option<i32> {
    let stat = proc_stat(pid)?;
    if registry::stat_field(&stat, 3) != Some("Z") {
        return None;
    }
    let status: i32 = registry::stat_field(&stat, 52)?.parse().ok()?;
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Some(128 + libc::WTERMSIG(status))
    } else {
        None
    }
}

/// Hold the box init's REAPER still, so the init's exit status survives long enough to be read.
///
/// MEASURED: without this, `kern stop` on a workload that traps the signal and exits 7 recorded the
/// real code in 15 runs out of 20 and fell back to 137 in the other 5. The init's parent is woken by
/// the very event our pidfd poll waits on, and when it reaps first the status is gone from /proc
/// before we can read it. A 75%-correct exit code is a worse contract than a consistently wrong one,
/// so the race is removed rather than won: SIGSTOP cannot be caught, and a stopped parent cannot
/// `wait4`.
///
/// TAKE IT BEFORE SIGNALLING. `stop` signals the box's process GROUP, which the runner is in, and a
/// dead runner is not a reaper we can hold - the init reparents to the user's systemd, which reaps
/// it at once. Held first, the runner takes that signal as PENDING (SIGSTOP wins) and dies from it
/// the moment we let go, so the end state is the same as if it had never been held.
///
/// The init itself is never stopped - it is a different process - so its shutdown handler runs
/// normally and the grace means what it says.
///
/// ONLY the box's RUNNER is ever held - the intermediate the supervisor forks, which no shell has a
/// job for. Two other things can be an init's parent and neither may be touched. The user's systemd
/// manager inherits an orphaned init, and trusting `PPid` blindly would SIGSTOP the process manager
/// of the whole session. A FOREGROUND box's parent is the user's own `kern box` process: stopping it
/// would print `Stopped` in their terminal for the length of the grace, and a `stop` interrupted mid
/// hold would leave that box frozen and looking alive - a worse outcome than the exit code this
/// buys, and a foreground box reports its code directly to its caller anyway. Both cases fall back
/// to the unguarded read.
///
/// The release is a `Drop`, which a SIGKILL of `kern stop` itself skips, so the caller takes this
/// hold only for a box whose dedicated cgroup makes that survivable - see the call site. VERIFIED in
/// both directions: with a cgroup, `kern stop` killed mid-grace leaves the box ORPHANED in `kern ps`
/// and the next `kern stop` reaps it whole ("reaped via cgroup.kill", no stopped process and no
/// stray left); with no cgroup and no hold, the runner dies with the group and the init reparents
/// and reaps itself, which is the behaviour that existed before this type and is left intact.
pub(crate) struct ReaperHold(pub(crate) Option<i32>);

impl ReaperHold {
    /// Hold this box's reaper, or hold nothing when it is not ours to hold.
    ///
    /// Returning before the target is ACTUALLY stopped would lose the race it exists to remove:
    /// `kill` only queues the signal, and the group SIGTERM that follows is number 15 against
    /// SIGSTOP's 19 - the kernel delivers the lower-numbered one first, so a reaper still running
    /// with both pending dies instead of stopping. MEASURED at 25 correct out of 30 without this
    /// wait, and 30 out of 30 with it. The wait is a few tens of microseconds (the target is blocked
    /// in `wait4`, so it stops as soon as it is scheduled) and bounded, because a hold that never
    /// lands must not turn a stop into a hang.
    pub(crate) fn new(supervisor: i32, pid1: i32) -> Self {
        let Some(reaper) = parent_of(pid1) else {
            return Self(None);
        };
        if reaper <= 1 || parent_of(reaper) != Some(supervisor) {
            return Self(None);
        }
        if unsafe { libc::kill(reaper, libc::SIGSTOP) } != 0 {
            return Self(None);
        }
        let held = Self(Some(reaper));
        for _ in 0..200 {
            match proc_state(reaper) {
                Some('T') => break,
                // Gone while we waited: nothing to hold, and nothing to release.
                None => return Self(None),
                _ => {
                    unsafe { libc::usleep(50) };
                }
            }
        }
        // Re-check the relationship now that the target cannot run: between reading `PPid` and the
        // signal landing, that pid could have died and been reused by an unrelated process of this
        // user, and the check above would have cleared a process we then stopped. It is a narrow
        // window and the damage would be small (a stop-and-continue), but it is closed for free -
        // a reused pid is no longer the init's parent, and dropping `held` here resumes it at once.
        if parent_of(pid1) != Some(reaper) {
            return Self(None);
        }
        held
    }
}

impl Drop for ReaperHold {
    /// Let it go, on every path. It resumes into whatever arrived while it was stopped - `stop`
    /// signals the box's process group, which it is in - so it finishes exactly as it would have
    /// without the hold. A reaper left stopped would never tear its cgroup, forwarders and scratch
    /// dir down, so this is a `Drop` and not a call at the end of the happy path.
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            unsafe { libc::kill(pid, libc::SIGCONT) };
        }
    }
}

/// What a teardown did, and the box's real exit code when it could be observed.
///
/// `stop` is the box's LAST owner: its group signal kills the supervisor, which therefore never
/// reaches the `set_box_exit` it writes on a normal exit. Whatever this carries is the only exit code
/// the box will ever have. A flat `bool` here is what made every clean `kern stop` record `exit 137`:
/// the constant was written when the teardown was ALWAYS a SIGKILL, and it did not follow the
/// graceful phase in.
///
/// The distinction is deliberately NOT "which branch ran" but "what did we read". A box can reach
/// any branch already dead - `stop` signals the group before it gets here - so branch identity is a
/// bad witness, while the unreaped status is the fact itself: it reads 137 exactly when the init
/// really was SIGKILLed, and 7 when the workload trapped the signal and exited 7.
pub(crate) enum Teardown {
    /// The box is gone. `Some(code)` is the init's real status, read from its unreaped zombie;
    /// `None` means we tore it down without ever observing one.
    Gone(Option<i32>),
    /// The signal went out, the box was not confirmed gone in time.
    Unconfirmed,
}

impl Teardown {
    /// Whether the box is confirmed gone.
    pub(crate) fn confirmed(&self) -> bool {
        matches!(self, Teardown::Gone(_))
    }

    /// The code to record for `kern wait` / `kern ps -a`. A teardown whose status we could not read
    /// falls back to 137, the historical value, rather than inventing a `0` nobody measured.
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Teardown::Gone(Some(code)) => *code,
            _ => 137,
        }
    }
}

/// How long `stop` may still wait on THIS box: its own `--stop-timeout`, minus the time already
/// spent since the signal went out, in MILLISECONDS.
///
/// Every box is signalled in phase 1, so a box's grace runs from THERE, not from the moment the
/// teardown loop reaches it. That is what keeps a stack converging - an N-service stop costs
/// max(grace), never the sum - and it is also why the remainder must be measured per box rather than
/// against one deadline shared by the stack: a shared `max(grace)` hands every member the LONGEST
/// grace configured anywhere in the file. MEASURED on a two-service stack, one asking 4 s and one
/// asking 1 s, both hanging in their handler: the 1 s service was killed at 5154 ms. Its own
/// `stop_grace_period` is an upper bound, and it was exceeded five times over. With this it is
/// killed as soon as its own second is spent, and the stack still finishes in max(grace).
///
/// Milliseconds, not seconds: rounding the remainder down to a whole second silently spent up to
/// 999 ms of a grace the caller asked for (`--stop-timeout 3` gave a 2.5 s flush only 2019 ms and
/// SIGKILLed it mid-write, where Docker's `stop -t 3` let it finish in 2799 ms and exit 5).
///
/// A box configured with no grace at all gets zero, which is the straight-to-SIGKILL path.
///
/// The bound this gives is one-sided, and deliberately so: a member is never SIGKILLed BEFORE its own
/// grace, and can be killed later than it if a longer-grace member is torn down first, because the
/// loop is sequential. Killing it exactly on its own second regardless of order would need concurrent
/// waits; the stack total is max(grace) either way, and erring late costs a wait where erring early
/// would cut a real shutdown short.
pub(crate) fn remaining_grace_ms(own_grace_secs: u64, since_signal: std::time::Duration) -> u64 {
    let own = own_grace_secs.saturating_mul(1000);
    let spent = u64::try_from(since_signal.as_millis()).unwrap_or(u64::MAX);
    own.saturating_sub(spent)
}

pub(crate) fn kill_box_graceful(pid: i32, pid1: i32, stop_signal: i32, grace_ms: u64) -> Teardown {
    // The init may ALREADY be gone: `stop` signals the supervisor's process group before it reaches
    // here, and a box init that sits in that group takes that signal too, so it can be an unreaped
    // zombie on arrival. Read its status now, while /proc still has it. Without this the graceful
    // phase is skipped for a reason that looks right and is not: a zombie's `SigCgt` is cleared, so
    // `init_catches_signal` reports "cannot catch it" for a workload that caught it and exited 7.
    let already = zombie_exit_code(pid1);
    let pidfd = if pid1 > 0 {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid1, 0) as i32 };
        // Skip the graceful phase entirely when the init provably cannot receive the signal: see
        // `init_catches_signal`. This is the difference between `kern stop` returning in 2 ms and in
        // 9 s for the most ordinary box there is. Already dead is the same case: nothing to wait for.
        let graceful = grace_ms > 0 && already.is_none() && init_catches_signal(pid1, stop_signal);
        if graceful {
            // Graceful phase: the configured signal to the box init, and to the supervisor's group so
            // a foreground box's helpers hear it too.
            unsafe { signal_box(fd, pid1, stop_signal) };
            if pid > 1 {
                unsafe { libc::kill(-pid, stop_signal) };
            }
            if fd >= 0 {
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // Exited within the grace: nothing left to kill, and we say so without the SIGKILL.
                let ms = grace_ms.min(i32::MAX as u64) as i32;
                if crate::eintr::poll(std::slice::from_mut(&mut pfd), ms) > 0 {
                    unsafe { libc::close(fd) };
                    // Read the status HERE, first thing, while the reaper is still held: once it is
                    // released and reaps, the box's real exit code is gone for good.
                    return Teardown::Gone(zombie_exit_code(pid1));
                }
            }
        }
        unsafe { signal_box(fd, pid1, libc::SIGKILL) };
        fd
    } else {
        if grace_ms > 0 && pid > 1 {
            unsafe { libc::kill(-pid, stop_signal) };
            std::thread::sleep(std::time::Duration::from_millis(grace_ms.min(60_000)));
        }
        -1
    };
    // Never let a corrupt/degenerate `pid <= 1` turn the group sweep into `kill(-1)` (SIGKILL every
    // process the user owns) or `kill(0)` (our own group): it's only meaningful for a real supervisor.
    if pid > 1 {
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
    if pidfd >= 0 {
        // Wait (bounded) for the init to actually exit - POLLIN fires on termination.
        let mut pfd = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = crate::eintr::poll(std::slice::from_mut(&mut pfd), 1000);
        unsafe { libc::close(pidfd) };
        if ready > 0 {
            // Read it again now that it is definitely dead: our SIGKILL leaves a status of 137, and
            // an init that had already exited on its own leaves the code it chose. `already` wins -
            // it was read before we signalled, so it cannot be our own SIGKILL overwriting a real
            // exit code (a zombie's status is fixed, but the pre-signal read needs no reasoning).
            Teardown::Gone(already.or_else(|| zombie_exit_code(pid1)))
        } else {
            Teardown::Unconfirmed
        }
    } else {
        // No pidfd (pid1 unrecorded, or a kernel < 5.3): best-effort probe on the recorded pids. The
        // signal still went out via `signal_box`/the group sweep; we just can't confirm as precisely.
        let probe = if pid1 > 0 { pid1 } else { pid };
        for _ in 0..100 {
            if unsafe { libc::kill(probe, 0) } != 0 {
                return Teardown::Gone(already); // ESRCH - the target is gone
            }
            unsafe { libc::usleep(10_000) };
        }
        Teardown::Unconfirmed
    }
}

/// Hand the box's PID 1 to a foreground `--timeout` watchdog over its pipe (from `on_started`, in the
/// host-ns parent). No-op when no timeout is armed.
pub(crate) fn feed_timeout_pid(wd: Option<(i32, i32)>, pid1: i32) {
    if let Some((_, wfd)) = wd {
        let p = pid1.to_ne_bytes();
        unsafe { libc::write(wfd, p.as_ptr().cast(), p.len()) };
    }
}

/// Cancel a foreground `--timeout` watchdog once the box has exited: close our pipe end (so a
/// still-blocked watchdog reads EOF and gives up), then SIGKILL and reap it. Reaping before we return
/// means the watchdog's pid can't be reused, and closing/killing a still-sleeping one stops it before
/// it can signal. No-op when no timeout is armed.
/// Stop a health checker and drop the status it published.
///
/// SIGTERM rather than SIGKILL: the checker is a plain loop with no state to flush, but a terminated
/// child still has to be reaped or the launcher leaves a zombie, and `--restart` boxes start and
/// stop often enough for that to accumulate. `clear_health` then removes the sidecar so `kern ps`
/// does not report the health of a box that is gone.
///
/// ONE FUNCTION FOR BOTH LAUNCH PATHS. The detached path had this inline and the foreground path had
/// no checker at all; giving the foreground path its own copy of the teardown is how the two drift.
/// `key_pid` is the pid the registry entry is keyed by (the supervisor's when detached, the
/// launcher's in the foreground), which is what `set_health` wrote under.
pub(crate) fn stop_health_checker(checker: Option<i32>, name: &str, key_pid: i32) {
    let Some(hp) = checker else {
        return;
    };
    if !signal_helper(hp, libc::SIGTERM) {
        return;
    }
    crate::eintr::reap(hp);
    registry::clear_health(name, key_pid);
}

pub(crate) fn cancel_foreground_timeout(wd: Option<(i32, i32)>) {
    if let Some((wd_pid, wfd)) = wd {
        unsafe { libc::close(wfd) };
        if signal_helper(wd_pid, libc::SIGKILL) {
            crate::eintr::reap(wd_pid);
        }
    }
}

/// Fork a watchdog for a **detached** `--timeout N`: after N seconds it stops the box by name (the
/// same teardown as `kern stop`, so the registry/scratch are cleaned up and a `--restart` policy
/// can't resurrect it). It first checks the box is still the same instance (name + supervisor pid),
/// so a box that already exited on its own isn't "stopped" a second time. Returns its pid so the
/// supervisor can cancel it once the box exits normally.
pub(crate) fn spawn_timeout_stop(name: String, sup_pid: i32, secs: u64) -> Option<i32> {
    match fork_detached() {
        Forked::Parent(child) => return Some(child),
        // No watchdog was created, so the caller has nothing to cancel and nothing to signal.
        Forked::Failed => return None,
        Forked::Child => {}
    }
    // Wait for the SUPERVISOR to exit, with `secs` as a cap, rather than sleeping `secs` out.
    //
    // This is the detached twin of the foreground watchdog above, and it kept the bare `sleep` that
    // one shed: `kern box x -d --timeout N` followed by `kern stop x` left this process asleep for
    // the remainder of N, reparented to init, 884 KB and a pid per stopped box. Measured on this
    // tree before the change: `--timeout 20`, stop after one second, and the process was still
    // there at t=15 s and gone at t=20, exactly the deadline. `strace` showed it going straight
    // from `setsid` to `clock_nanosleep(25s)`, with no `pidfd_open` anywhere.
    //
    // Keying on the supervisor loses nothing here, unlike in the foreground watchdog, and the guard
    // below is why: this one only ever acts `if registry::pair_alive(&name, sup_pid)`, so a dead
    // supervisor already meant "do nothing". Waiting on its exit reaches that same decision without
    // holding a process for the deadline. The pidfd also pins that exact supervisor, so a pid
    // recycled during the wait cannot make the pair-probe match a different box.
    //
    // The pidfd is opened AFTER `fork_detached`, never before: that helper runs `close_range(3, ..)`
    // in the child, which would close an fd taken by the parent.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, sup_pid, 0) as i32 };
    let supervisor_gone = unsafe { wait_for_box_exit(pidfd, secs.saturating_mul(1000)) };
    if pidfd >= 0 {
        unsafe { libc::close(pidfd) };
    }
    if supervisor_gone {
        unsafe { libc::_exit(0) }; // nothing left to stop, and the pair-probe would say so too
    }
    // Exact (name,pid)-PAIR probe: a by-name `find` would test the pid against whichever same-name
    // entry readdir yields first - a duplicate entry (fail-open unclaimed start / pre-claim kern)
    // could shadow the tracked box and the timeout would silently never fire.
    if registry::pair_alive(&name, sup_pid) {
        let _ = stop(std::slice::from_ref(&name), false);
    }
    unsafe { libc::_exit(0) };
}

/// Run one health probe inside the box and report whether it succeeded (exit 0). Forks a child that
/// `exec_in_box`es the probe (so the checker itself stays on the host); `timeout` > 0 is enforced
/// inside `exec_in_box`, which SIGKILLs the whole in-box probe group on expiry (→ non-zero) so a hung
/// check neither stalls the checker nor leaks a live process into the box each interval.
pub(crate) fn run_probe(
    pid1: i32,
    probe: &[String],
    timeout: u64,
    seccomp_mode: kern_isolation::SeccompFilter,
) -> bool {
    let to = (timeout > 0).then_some(timeout);
    let probe_pid = unsafe { libc::fork() };
    if probe_pid == 0 {
        // A health probe never warns about the scope-path cap gap (it runs every interval). It keeps
        // the dangerous BASELINE drop (`CapSpec::default()`), unchanged from before this parameter
        // existed: a probe is not `kern exec`, and matching it to a box's `--cap-drop ALL` could break
        // a check that needs a baseline cap. Reapplying the box's own spec to the probe is a separate,
        // separately-validated follow-up; this increment fixes the `kern exec` contract only.
        //
        // The seccomp mode is the box's RECORDED mode (read from its registry entry by the caller), so
        // the probe installs the SAME filter as PID 1 by construction - not by assuming the checker's
        // environment still equals the box's creation environment.
        let code = exec_in_box(
            pid1,
            probe,
            &[],
            None,
            None,
            None,
            to,
            false,
            &kern_isolation::CapSpec::default(),
            seccomp_mode,
            // A health probe is kern's OWN command (the `--health-cmd`), run to decide liveness, not
            // the workload proper: keep it at the baseline (no box AppArmor), consistent with its
            // baseline caps above, so a confining profile can't wedge the very check kern uses to
            // decide health. Caveat, stated plainly: the probe target is a binary in the box's
            // workload-writable rootfs, so a workload that overwrites it gets one AppArmor-unconfined
            // (still seccomp- and namespace-confined) run per interval. A deliberate, documented
            // tradeoff, the same one taken for the probe's baseline caps; applying the profile here is
            // the separately-tracked follow-up.
            None,
        )
        .unwrap_or(1);
        unsafe { libc::_exit(code) };
    }
    if probe_pid <= 0 {
        return false;
    }
    let mut st = 0i32;
    if crate::eintr::waitpid(probe_pid, &mut st, 0) <= 0 {
        return false;
    }
    libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0
}

/// The on-failure restart contract for one box: whether to retry at all, and how many times.
/// Grouped so the supervisor keeps a readable signature as the contract grows.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Restart {
    /// `--restart` (on-failure). `false` = run once, never retry.
    pub(crate) on_failure: bool,
    /// Docker `always`/`unless-stopped` on a POD MEMBER: restart on ANY exit (including 0), uncapped,
    /// via THIS in-process supervisor (it dies with the stack). A STANDALONE always/unless-stopped box
    /// takes the systemd path instead; a pod member cannot, as it needs the pod holder's namespace.
    pub(crate) always: bool,
    /// `--restart-max` / compose `on-failure:N`. 0 = kern's built-in cap. Not applied when `always`.
    pub(crate) max: u32,
}

/// What to do when a box's health check turns it "unhealthy" (`--health-action`).
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum HealthAction {
    /// Record the status only (Docker's default) - an orchestrator decides what to do.
    None,
    /// Kill the box so the supervisor restarts it (implies the on-failure restart policy).
    Restart,
    /// Stop the box entirely (no restart).
    Stop,
}

/// Parse `--health-action <restart|stop|none>` (default `none`).
pub(crate) fn parse_health_action(s: Option<&str>) -> Result<HealthAction, Error> {
    match s {
        None | Some("none") => Ok(HealthAction::None),
        Some("restart") => Ok(HealthAction::Restart),
        Some("stop") => Ok(HealthAction::Stop),
        Some(o) => Err(Error::Sandbox(format!(
            "invalid --health-action '{o}' (expected restart, stop or none)"
        ))),
    }
}

/// The health-check policy for a detached box (`--health-*`).
pub(crate) struct HealthConfig<'a> {
    pub(crate) cmd: Option<&'a str>,
    pub(crate) interval: u64,
    pub(crate) retries: u32,
    pub(crate) start_period: u64,
    pub(crate) timeout: u64,
    pub(crate) action: HealthAction,
}

impl HealthConfig<'_> {
    /// The same policy, owned, for a checker that outlives `box_run`'s borrowed args.
    ///
    /// ONE CONVERSION FOR BOTH LAUNCH PATHS. Each used to build `OwnedHealth` field by field at its
    /// own call site, from different sources, which is how a flag comes to mean one thing detached
    /// and another in the foreground. `cmd` is taken separately because the caller has already
    /// matched on it to decide there is a checker to start at all.
    pub(crate) fn owned(&self, cmd: &str) -> OwnedHealth {
        OwnedHealth {
            cmd: cmd.to_string(),
            interval: self.interval,
            retries: self.retries,
            start_period: self.start_period,
            timeout: self.timeout,
            action: self.action,
        }
    }
}

/// Owned health policy handed to the forked checker (it outlives `box_run`'s borrowed args).
pub(crate) struct OwnedHealth {
    pub(crate) cmd: String,
    pub(crate) interval: u64,
    pub(crate) retries: u32,
    pub(crate) start_period: u64,
    pub(crate) timeout: u64,
    pub(crate) action: HealthAction,
}

/// Arm `PR_SET_PDEATHSIG(SIGKILL)`: SIGKILL this process when its parent dies - the die-with-parent
/// link for a foreground box. Survives a non-setuid `execve`.
pub(crate) fn arm_pdeathsig() {
    unsafe {
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL as libc::c_ulong,
            0,
            0,
            0,
        );
    }
}

/// `waitpid` a child to completion, retrying on `EINTR`; returns the raw status (0 on a wait error, so
/// a caller reading it as "exited 0" degrades safe).
pub(crate) fn reap(child: libc::pid_t) -> libc::c_int {
    let mut status: libc::c_int = 0;
    loop {
        let w = unsafe { libc::waitpid(child, &mut status, 0) };
        if w < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break;
    }
    status
}

/// The write-end fd of the freeze file, published for the signal handler while a commit holds a box
/// frozen. `-1` when no commit is freezing. A signal that would kill the commit process (and so skip the
/// `FreezeGuard::drop` thaw) is caught, the box is thawed via this fd with an async-signal-safe raw
/// `write`, and the signal is re-raised with its default disposition.
pub(crate) static FREEZE_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// Async-signal-safe: thaw the frozen box (raw `write` of "0") then re-raise `sig` so the process still
/// dies as the signal intends. Installed with `SA_RESETHAND`, so the disposition is already reset to
/// `SIG_DFL` on entry and the re-raise takes the default action. Only `write` and `raise` are used here,
/// both on POSIX's async-signal-safe list (`signal()` is NOT guaranteed to be, so it is avoided).
pub(crate) extern "C" fn thaw_on_fatal_signal(sig: i32) {
    let fd = FREEZE_FD.load(std::sync::atomic::Ordering::SeqCst);
    if fd >= 0 {
        unsafe { libc::write(fd, b"0".as_ptr() as *const libc::c_void, 1) };
    }
    unsafe { libc::raise(sig) };
}

/// RAII cgroup-freezer guard: freezes a box's cgroup on construction and thaws it on drop. Used by
/// `commit` to stop the workload for the duration of the rootfs snapshot (a frozen cgroup runs no task,
/// so no file can be swapped mid-copy). `thaw_path` is `Some` ONLY when this guard is the one that
/// transitioned the cgroup 0 -> 1; if the box has no dedicated cgroup, the write fails, or the box was
/// ALREADY frozen (the user ran `kern pause`), it is `None` and drop leaves the freeze state untouched,
/// so committing a paused box never silently un-pauses it.
///
/// Drop alone is NOT a sufficient safety net: SIGINT (Ctrl-C), SIGTERM, `process::exit`, and
/// `panic = "abort"` all skip destructors, which would leave the box frozen forever. So while WE hold the
/// freeze, SIGINT/SIGTERM/SIGHUP are trapped by [`thaw_on_fatal_signal`] (which thaws and re-raises), and
/// `kern stop`/`kern unpause` thaw a box they find frozen, giving a recovery path even for SIGKILL/OOM
/// that no handler can catch. The freeze is never a state you can only leave if a destructor ran.
pub(crate) struct FreezeGuard {
    pub(crate) thaw_path: Option<std::path::PathBuf>,
    pub(crate) freeze_fd: i32,
    pub(crate) old_handlers: Vec<(i32, libc::sigaction)>,
}

impl FreezeGuard {
    const TRAP: [i32; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

    pub(crate) fn freeze(box_pid: i32) -> FreezeGuard {
        let none = || FreezeGuard {
            thaw_path: None,
            freeze_fd: -1,
            old_handlers: Vec::new(),
        };
        let Some(cg) = registry::box_cgroup(box_pid) else {
            return none();
        };
        let freeze = cg.join("cgroup.freeze");
        // Preserve a pre-existing freeze: if the box is already paused, snapshot under it and do NOT thaw
        // on drop (that would un-pause a box the user deliberately paused). NOTE: `cgroup.freeze` has no
        // compare-and-swap, so a `kern pause` racing in the window between this read and our write below
        // could be undone by our drop-thaw. The window is tiny (a pause landing during an active commit)
        // and the consequence is a resumed box, not a security boundary crossing; a lossless fix isn't
        // possible with a plain cgroup file, so this is a documented known window rather than a guarantee.
        let already_frozen = std::fs::read_to_string(&freeze)
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
        if already_frozen {
            return none();
        }
        if std::fs::write(&freeze, "1").is_err() {
            return none();
        }
        // The freeze is asynchronous; wait (bounded) until the cgroup reports `frozen 1` so the snapshot
        // starts only once every task is actually stopped. If it never settles within the budget, warn
        // and proceed rather than block commit forever, so the operator knows the TOCTOU protection did
        // not fully engage for this snapshot.
        let events = cg.join("cgroup.events");
        let mut settled = false;
        for _ in 0..200 {
            match std::fs::read_to_string(&events) {
                Ok(s) if s.lines().any(|l| l.trim() == "frozen 1") => {
                    settled = true;
                    break;
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(5)),
            }
        }
        if !settled {
            eprintln!(
                "kern: warning: box did not report 'frozen' within 1s; the commit snapshot proceeds \
                 WITHOUT the freeze, so a concurrent write could race it"
            );
        }
        // Arm the signal-safe thaw: publish an fd to the freeze file and trap the interactive/kill signals
        // that would otherwise skip Drop and strand the box frozen.
        let mut freeze_fd = -1;
        let mut old_handlers = Vec::new();
        let cpath = std::ffi::CString::new(freeze.as_os_str().as_encoded_bytes()).ok();
        if let Some(cp) = cpath {
            freeze_fd = unsafe { libc::open(cp.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
            if freeze_fd >= 0 {
                FREEZE_FD.store(freeze_fd, std::sync::atomic::Ordering::SeqCst);
                for &sig in &Self::TRAP {
                    unsafe {
                        let mut new: libc::sigaction = std::mem::zeroed();
                        new.sa_sigaction = thaw_on_fatal_signal as extern "C" fn(libc::c_int)
                            as libc::sighandler_t;
                        libc::sigemptyset(&mut new.sa_mask);
                        // SA_RESETHAND: the kernel resets the handler to SIG_DFL before invoking it, so the
                        // handler's re-raise dies by default action without any (non-async-signal-safe)
                        // signal() call. Restore-via-sigaction on Drop covers the normal path.
                        new.sa_flags = libc::SA_RESETHAND;
                        let mut old: libc::sigaction = std::mem::zeroed();
                        if libc::sigaction(sig, &new, &mut old) == 0 {
                            old_handlers.push((sig, old));
                        }
                    }
                }
            }
        }
        FreezeGuard {
            thaw_path: Some(freeze),
            freeze_fd,
            old_handlers,
        }
    }
}

impl Drop for FreezeGuard {
    fn drop(&mut self) {
        // Restore the original signal handlers and stop publishing the fd BEFORE the normal thaw.
        for (sig, old) in &self.old_handlers {
            unsafe { libc::sigaction(*sig, old, std::ptr::null_mut()) };
        }
        if self.freeze_fd >= 0 {
            FREEZE_FD.store(-1, std::sync::atomic::Ordering::SeqCst);
        }
        if let Some(p) = &self.thaw_path {
            let _ = std::fs::write(p, "0");
        }
        if self.freeze_fd >= 0 {
            unsafe { libc::close(self.freeze_fd) };
        }
    }
}

/// A running box's current health status by NAME (`healthy`/`unhealthy`/`starting`/empty). The
/// sidecar is keyed `name-pid`, so resolve the pid via the registry first; a box that has already
/// left the registry reads as empty (which the caller treats as "not yet healthy").
pub(crate) fn current_health(name: &str) -> String {
    registry::find(name)
        .map(|i| registry::health_of(name, i.pid))
        .unwrap_or_default()
}
