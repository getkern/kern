//! In kern's WSL distro, the user kern becomes never holds root's terminal.
//!
//! WHY. kern started from a root shell gives root up (`wslentry`), and before this the process that
//! did so kept root's terminal: descriptors 0-2 on it, and root's session, with that terminal as its
//! controlling one. A process of the same uid (one that left a box) may trace a process of its own
//! uid, and a traced kern could `ioctl(TIOCSTI)` into root's terminal, which accepts it there because
//! it is kern's controlling terminal: input typed into root's shell, so root.
//!
//! WHAT. The model of `sudo`'s `use_pty`. When any of 0-2 is a terminal, a new pseudo-terminal is
//! opened and the process forks:
//!
//! * the CHILD makes a session of its own with the new terminal as its controlling one, puts the
//!   new terminal where each of 0-2 had a terminal (pipes and files stay as they are), closes every
//!   other inherited descriptor, PROVES no descriptor and no `/dev/tty` reaches the old terminal,
//!   and only then goes on to give root up;
//! * the PARENT stays root, outside the user's cgroup subtree, and relays: root's terminal in raw
//!   mode to the new one, the new one's output back, window resizes, and the signals a terminal or
//!   a caller sends it; it exits with the child's status. Root's processes are out of the user's
//!   reach: the user can neither trace nor signal them.
//!
//! With no terminal among 0-2 there is nothing to relay: the inherited descriptors above 2 are
//! closed and kern goes on in the same process. A terminal that cannot be made is a refusal, never
//! root's terminal handed over.
//!
//! Ctrl-Z does not suspend kern started this way: the child's process group has no parent in its
//! session, so the kernel discards the terminal's stop signals for it.

use std::os::fd::RawFd;

/// The relay's input buffer bound: past it, root's terminal is not read until the child drains.
const PENDING_CAP: usize = 64 * 1024;

/// The longest the relay goes on copying output once the child has exited: what is left in the
/// terminal is shown, and a descendant that kept the terminal cannot hold the relay open.
const DRAIN_MS: u128 = 1000;

/// Which of descriptors 0-2 are terminals.
fn terminals() -> [bool; 3] {
    // SAFETY: isatty takes a plain integer.
    [0, 1, 2].map(|fd| unsafe { libc::isatty(fd) } == 1)
}

/// The descriptor the relay writes the child's output to: the first terminal among 1, 2, 0.
fn output_fd(tty: [bool; 3]) -> Option<RawFd> {
    [1, 2, 0].into_iter().find(|fd| tty[*fd as usize])
}

/// The process exit for a child's wait status: its code, or 128 + the signal that ended it.
fn exit_code(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

/// The signals the relay takes through its signalfd.
const RELAYED: [libc::c_int; 9] = [
    libc::SIGCHLD,
    libc::SIGWINCH,
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGTSTP,
    libc::SIGCONT,
    libc::SIGPIPE,
];

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// The device number of the terminal at `fd`, `None` when it cannot be read.
fn rdev_of(fd: RawFd) -> Option<libc::dev_t> {
    // SAFETY: `st` is a plain struct fstat fills.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        (libc::fstat(fd, &mut st) == 0).then_some(st.st_rdev)
    }
}

/// Called as root, before the identity changes. Returns in the process that goes on to give root
/// up; when a relay is needed, the parent never returns (it relays and exits with the child's
/// status). `Err` when the terminal could not be handed off: the caller refuses.
pub(crate) fn hand_off_terminal() -> Result<(), String> {
    let tty = terminals();
    let Some(output) = output_fd(tty) else {
        kern_isolation::shed_inherited_fds(-1);
        return Ok(());
    };
    let input = tty[0].then_some(0);
    let pty = crate::pty::open().map_err(|e| format!("cannot open a terminal of its own: {e}"))?;
    // The new terminal starts as root's is now: the same settings and size.
    // SAFETY: `t` is a plain struct tcgetattr fills; every call takes plain integers or it.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(output, &mut t) == 0 {
            libc::tcsetattr(pty.slave, libc::TCSANOW, &t);
        }
    }
    crate::pty::copy_winsize(output, pty.master);
    let slave_rdev = rdev_of(pty.slave).ok_or("cannot read its own terminal")?;

    // The signals are blocked BEFORE the fork, so a child that ends at once is still seen; the child
    // gives the mask back right away.
    // SAFETY: the sigset_t values are plain structs the sig* calls fill.
    let (mut set, mut old): (libc::sigset_t, libc::sigset_t) = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        for s in RELAYED {
            libc::sigaddset(&mut set, s);
        }
        if libc::sigprocmask(libc::SIG_BLOCK, &set, &mut old) != 0 {
            return Err(format!("sigprocmask: {}", std::io::Error::last_os_error()));
        }
    }
    // SAFETY: `set` is initialised above.
    let sfd = unsafe { libc::signalfd(-1, &set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
    if sfd < 0 {
        return Err(format!("signalfd: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: the process is single-threaded here: this runs first thing in `main`.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if child > 0 {
        relay(Relay {
            child,
            master: pty.master,
            slave: pty.slave,
            sfd,
            input,
            output,
        })
    }
    // THE CHILD.
    // SAFETY: plain descriptor and signal calls on values set above.
    unsafe {
        libc::sigprocmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        libc::close(sfd);
        libc::close(pty.master);
        if libc::setsid() < 0 {
            return Err(format!("setsid: {}", std::io::Error::last_os_error()));
        }
        if libc::ioctl(pty.slave, libc::TIOCSCTTY, 0) != 0 {
            return Err(format!(
                "cannot take its own terminal: {}",
                std::io::Error::last_os_error()
            ));
        }
        for fd in 0..3 {
            if tty[fd as usize] && libc::dup2(pty.slave, fd) < 0 {
                return Err(format!("dup2: {}", std::io::Error::last_os_error()));
            }
        }
        if pty.slave > 2 {
            libc::close(pty.slave);
        }
    }
    kern_isolation::shed_inherited_fds(-1);
    // PROVED, not assumed: every terminal among 0-2 and the controlling terminal are the new one.
    for fd in 0..3 {
        // SAFETY: isatty takes a plain integer.
        if unsafe { libc::isatty(fd) } == 1 && rdev_of(fd) != Some(slave_rdev) {
            return Err(format!("descriptor {fd} still reaches root's terminal"));
        }
    }
    // The controlling terminal is `tty_nr` in `/proc/self/stat` (`fstat` of an opened `/dev/tty`
    // answers `/dev/tty`'s own 5:0, MEASURED: it refused every start).
    let ctty = std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|s| ctty_nr(&s));
    if ctty != Some(slave_rdev as u64) {
        return Err("its controlling terminal is not its own".to_string());
    }
    Ok(())
}

/// The controlling terminal's device number, field 7 (`tty_nr`) of a `/proc/<pid>/stat` text. The
/// command name (field 2) may hold spaces and parentheses, so the fields are counted after the last `)`.
fn ctty_nr(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace()
        .nth(4)?
        .parse::<i64>()
        .ok()
        .map(|n| n as u64)
}

struct Relay {
    child: libc::pid_t,
    master: RawFd,
    slave: RawFd,
    sfd: RawFd,
    input: Option<RawFd>,
    output: RawFd,
}

/// Write all of `buf` to the (blocking) terminal `fd`. `false` when the terminal is gone.
fn write_all(fd: RawFd, mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        // SAFETY: `buf` is a live slice.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n > 0 {
            buf = &buf[n as usize..];
            continue;
        }
        match errno() {
            libc::EINTR => {}
            libc::EAGAIN => {
                let mut p = libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: one live pollfd.
                unsafe { libc::poll(&mut p, 1, 100) };
            }
            _ => return false,
        }
    }
    true
}

/// Send `sig` where a terminal would: the new terminal's foreground process group, else the child's.
fn forward(r: &Relay, sig: libc::c_int) {
    let mut pgrp: libc::pid_t = 0;
    // SAFETY: TIOCGPGRP writes one pid_t.
    let ok = unsafe { libc::ioctl(r.master, libc::TIOCGPGRP, &mut pgrp) } == 0 && pgrp > 0;
    // SAFETY: kill takes plain integers.
    unsafe {
        if !ok || libc::kill(-pgrp, sig) != 0 {
            libc::kill(-r.child, sig);
        }
    }
}

/// The child's status once it has ended, `None` while it runs.
fn reaped(child: libc::pid_t) -> Option<libc::c_int> {
    let mut st: libc::c_int = 0;
    loop {
        // SAFETY: `st` is a live int.
        let got = unsafe { libc::waitpid(child, &mut st, libc::WNOHANG) };
        if got == child {
            return Some(st);
        }
        if got < 0 && errno() == libc::EINTR {
            continue;
        }
        if got < 0 {
            // Not our child any more (cannot happen): stop relaying with a failure.
            return Some(1 << 8);
        }
        return None;
    }
}

fn relay(r: Relay) -> ! {
    // SAFETY: plain descriptor calls.
    unsafe {
        libc::close(r.slave);
        let fl = libc::fcntl(r.master, libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(r.master, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }
    let saved = r.input.and_then(|fd| crate::pty::make_raw(fd).ok());
    let mut pending: Vec<u8> = Vec::new();
    let mut reading_input = r.input.is_some();
    let mut master_open = true;
    let mut output_open = true;
    let mut status: Option<libc::c_int> = None;
    let mut buf = [0u8; 16 * 1024];
    while status.is_none() {
        let mut fds: Vec<libc::pollfd> = vec![libc::pollfd {
            fd: r.sfd,
            events: libc::POLLIN,
            revents: 0,
        }];
        let input_at = match r.input {
            Some(fd) if reading_input && pending.len() < PENDING_CAP => {
                fds.push(libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                });
                Some(fds.len() - 1)
            }
            _ => None,
        };
        let master_at = if master_open {
            let out = if pending.is_empty() { 0 } else { libc::POLLOUT };
            fds.push(libc::pollfd {
                fd: r.master,
                events: libc::POLLIN | out,
                revents: 0,
            });
            Some(fds.len() - 1)
        } else {
            None
        };
        // SAFETY: `fds` is a live vector of pollfd.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            break;
        }
        if fds[0].revents & libc::POLLIN != 0 {
            loop {
                // SAFETY: a zeroed signalfd_siginfo is a valid buffer for one record.
                let mut si: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
                let size = std::mem::size_of::<libc::signalfd_siginfo>();
                // SAFETY: `si` is `size` bytes.
                let got = unsafe {
                    libc::read(r.sfd, (&mut si as *mut libc::signalfd_siginfo).cast(), size)
                };
                if got != size as isize {
                    break;
                }
                match si.ssi_signo as libc::c_int {
                    libc::SIGCHLD => status = status.or_else(|| reaped(r.child)),
                    libc::SIGWINCH => crate::pty::copy_winsize(r.output, r.master),
                    s @ (libc::SIGINT | libc::SIGQUIT | libc::SIGTERM | libc::SIGHUP) => {
                        forward(&r, s)
                    }
                    // A stop at root's terminal would leave kern running behind a stopped relay.
                    _ => {}
                }
            }
        }
        if let Some(i) = input_at {
            if fds[i].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                if let Some(fd) = r.input {
                    // SAFETY: `buf` is a live buffer.
                    let got = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                    if got > 0 {
                        pending.extend_from_slice(&buf[..got as usize]);
                    } else if got == 0 || !matches!(errno(), libc::EINTR | libc::EAGAIN) {
                        // Root's terminal is gone: the child's terminal hangs up as well.
                        reading_input = false;
                        forward(&r, libc::SIGHUP);
                    }
                }
            }
        }
        if let Some(i) = master_at {
            let ev = fds[i].revents;
            if ev & libc::POLLOUT != 0 && !pending.is_empty() {
                // SAFETY: `pending` is a live vector.
                let w = unsafe { libc::write(r.master, pending.as_ptr().cast(), pending.len()) };
                if w > 0 {
                    pending.drain(..w as usize);
                }
            }
            if ev & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                // SAFETY: `buf` is a live buffer.
                let got = unsafe { libc::read(r.master, buf.as_mut_ptr().cast(), buf.len()) };
                if got > 0 {
                    if output_open {
                        output_open = write_all(r.output, &buf[..got as usize]);
                    }
                } else if got == 0 || !matches!(errno(), libc::EINTR | libc::EAGAIN) {
                    // Every holder of the new terminal closed it (EIO): only the child's end is left.
                    master_open = false;
                }
            }
        }
        if !master_open && status.is_none() {
            // Nothing more to relay: wait for the child, still forwarding signals.
            status = wait_forwarding(&r);
        }
    }
    let started = std::time::Instant::now();
    while master_open && output_open && started.elapsed().as_millis() < DRAIN_MS {
        let mut p = libc::pollfd {
            fd: r.master,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live pollfd.
        if unsafe { libc::poll(&mut p, 1, 50) } <= 0 {
            break;
        }
        // SAFETY: `buf` is a live buffer.
        let got = unsafe { libc::read(r.master, buf.as_mut_ptr().cast(), buf.len()) };
        if got <= 0 {
            break;
        }
        output_open = write_all(r.output, &buf[..got as usize]);
    }
    if let (Some(fd), Some(t)) = (r.input, saved.as_ref()) {
        crate::pty::restore(fd, t);
    }
    let st = status.unwrap_or(1 << 8);
    if libc::WIFSIGNALED(st) {
        // Ended by a signal: end the same way, so root's shell sees what the child saw.
        let sig = libc::WTERMSIG(st);
        // SAFETY: plain signal calls on an integer signal number.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            let mut one: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut one);
            libc::sigaddset(&mut one, sig);
            libc::sigprocmask(libc::SIG_UNBLOCK, &one, std::ptr::null_mut());
            libc::kill(libc::getpid(), sig);
        }
    }
    std::process::exit(exit_code(st))
}

/// Wait for the child with nothing left to relay, forwarding the signals that arrive meanwhile.
fn wait_forwarding(r: &Relay) -> Option<libc::c_int> {
    loop {
        if let Some(st) = reaped(r.child) {
            return Some(st);
        }
        let mut p = libc::pollfd {
            fd: r.sfd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live pollfd.
        unsafe { libc::poll(&mut p, 1, -1) };
        loop {
            // SAFETY: a zeroed signalfd_siginfo is a valid buffer for one record.
            let mut si: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
            let size = std::mem::size_of::<libc::signalfd_siginfo>();
            // SAFETY: `si` is `size` bytes.
            let got =
                unsafe { libc::read(r.sfd, (&mut si as *mut libc::signalfd_siginfo).cast(), size) };
            if got != size as isize {
                break;
            }
            let s = si.ssi_signo as libc::c_int;
            if matches!(
                s,
                libc::SIGINT | libc::SIGQUIT | libc::SIGTERM | libc::SIGHUP
            ) {
                forward(r, s);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_controlling_terminal_is_field_seven_counted_after_the_last_parenthesis() {
        let stat = "1478 (k (x) ern) S 1477 1478 1477 34816 1478 4194560 0 0";
        assert_eq!(ctty_nr(stat), Some(34816));
        assert_eq!(ctty_nr("1 (init) S 0 1 1 0 -1"), Some(0));
        assert_eq!(ctty_nr("garbage"), None);
    }

    #[test]
    fn output_goes_to_the_first_terminal_among_stdout_stderr_stdin() {
        assert_eq!(output_fd([true, true, true]), Some(1));
        assert_eq!(output_fd([true, false, true]), Some(2));
        assert_eq!(output_fd([true, false, false]), Some(0));
        assert_eq!(output_fd([false, false, false]), None);
    }

    #[test]
    fn the_relay_exits_with_the_childs_code_or_128_plus_its_signal() {
        assert_eq!(exit_code(0), 0);
        assert_eq!(exit_code(3 << 8), 3);
        assert_eq!(exit_code(libc::SIGINT), 128 + libc::SIGINT);
        assert_eq!(exit_code(libc::SIGKILL), 128 + libc::SIGKILL);
    }
}
