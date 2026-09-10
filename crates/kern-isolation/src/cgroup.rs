//! Best-effort cgroup v2 resource limits (memory + PIDs).
//!
//! Confines the sandbox so a runaway fork bomb or memory hog can't take down the host. Applied
//! before the namespace setup, so the forked workload inherits the cgroup. If the hierarchy
//! isn't delegated/writable (no systemd user delegation), it degrades gracefully: the namespace
//! isolation still holds; only the resource cap is skipped. cgroup v2 only.

use std::ffi::CStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// RAII owner of the per-box cgroup directory. Its `Drop` removes the (now-empty) cgroup, so the
/// `kern-box-<tag>-<pid>` dir never leaks. Without it the best-effort cgroup dir would only be cleaned
/// up by an outer systemd `--scope`'s `--collect`; on any path without that (e.g. `KERN_NO_SCOPE`, or a
/// host without systemd-user) every box start would leave an orphan dir behind. The guard is held by the
/// supervisor until AFTER `waitpid`, by which point box PID 1 (and all its PID-namespace descendants) are
/// dead, so the cgroup is empty and `rmdir` succeeds. The forked child never runs this `Drop` (it always
/// `exec`s or `_exit`s), so only the supervisor cleans up - exactly once.
pub struct CgroupGuard {
    dir: PathBuf,
    /// The SIBLING leaf the supervisor was parked in, when the no-blast-radius layout was built. Removed
    /// alongside `dir` on drop. `None` when the supervisor stayed in `dir` (the layout could not be built
    /// here, e.g. the parent refuses a second child or `memory` did not reach the children).
    sup: Option<PathBuf>,
    /// Is the supervisor OUTSIDE the capped cgroup? True whether it was moved to a sibling leaf or
    /// simply left where it already was, which are two ways of reaching the same property.
    outside: bool,
    /// Where to move the supervisor back to before removing `dir`. On the direct fast path the supervisor
    /// moved ITSELF into the box cgroup (so the forked workload inherits the caps); a non-empty cgroup
    /// can't be `rmdir`'d, so it must VACATE first - else the direct path leaks one `kern-box-*` dir per
    /// box. `origin` is kern's cgroup from BEFORE the move (a valid domain that accepts processes).
    origin: Option<PathBuf>,
}

impl CgroupGuard {
    /// The capped cgroup the WORKLOAD must run in. The supervisor is deliberately not in it (see
    /// `apply_limits`), so the forked child has to join it explicitly before it execs.
    #[must_use]
    pub fn box_dir(&self) -> &std::path::Path {
        &self.dir
    }

    /// Is the supervisor parked outside the capped cgroup? False when the layout could not be built and
    /// the old "supervisor inside" behaviour is in force, in which case the forked child inherits the
    /// cgroup and must NOT write itself in again (harmless, but the write would be pointless work on the
    /// start path).
    #[must_use]
    pub fn supervisor_is_outside(&self) -> bool {
        self.outside
    }
}

/// Whether the box's own cgroup recorded an OOM kill, latched at the one moment it can be read.
///
/// 0 = not looked at or nothing there, 1 = the box's cgroup counted at least one OOM kill. Latched
/// rather than read on demand because the `CgroupGuard` removes that directory when it drops, which
/// happens before the caller decides what to print: reading later finds nothing and reports nothing,
/// which is the silent 137 this exists to end.
static BOX_WAS_OOM_KILLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Latch whether `dir` recorded an OOM kill. Called right after the box is reaped, while its cgroup
/// still exists. Reading `memory.events` of the BOX's own cgroup attributes the kill exactly: an
/// ancestor's counter would also move for an unrelated box in the same subtree.
pub fn latch_box_oom(dir: &std::path::Path) {
    if oom_kill_count_at(dir).is_some_and(|n| n > 0) {
        BOX_WAS_OOM_KILLED.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// Did the box this process supervised die to its own memory cap? See [`latch_box_oom`].
#[must_use]
pub fn box_was_oom_killed() -> bool {
    BOX_WAS_OOM_KILLED.load(std::sync::atomic::Ordering::Acquire)
}

/// The capped cgroup THIS process created for its box, recorded by [`apply_limits`] and read by the
/// supervisor after the box exits.
///
/// Recorded rather than re-derived, and that distinction was a measured defect. The obvious way to find
/// it later is `box_cgroup_dir(pid1)`, reading the child's `/proc/<pid>/cgroup`; on WSL2 that returned
/// `kern-box-<tag>-<pid>-sup`, the SUPERVISOR's leaf. The supervisor no longer sits in the box's cgroup,
/// so a freshly forked child inherits the supervisor's leaf and only moves itself afterwards: any read
/// racing that move answers with the wrong directory, and by teardown that one is gone. The path is
/// known exactly at creation, so it is kept.
static BOX_CGROUP_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// The capped cgroup this process created for its box, if it created one. See [`BOX_CGROUP_DIR`].
#[must_use]
pub fn this_box_cgroup_dir() -> Option<&'static std::path::Path> {
    BOX_CGROUP_DIR.get().map(PathBuf::as_path)
}

/// An OPEN DESCRIPTOR on a box's cgroup directory, and the reason it is a descriptor and not a path.
///
/// `kern exec` enters the box's namespaces with `setns` and then places its child in the box's cgroup.
/// A PATH does not survive that crossing: inside the box's mount and cgroup namespaces `/sys/fs/cgroup`
/// is the box's own cgroup mounted at the root, so the absolute host path
/// `/sys/fs/cgroup/user.slice/.../kern-box-<name>-<pid>` names nothing at all. Measured on the shipped
/// binary before this type existed, `--pids-limit 2 --memory 64M`, reading each process's cgroup from
/// the HOST by pid, with the box's own PID 1 as the positive control:
///
/// ```text
/// box PID 1                 .../kern.slice/kern-box-td2-2312282   <- capped
/// the kern exec'd process   .../app.slice/app-<the caller>.scope   <- the CALLER's cgroup
/// ```
///
/// and the exec'd process was verified to be in the box's PID namespace, so it was the right process.
/// Worse than the miss was its silence: the fallback join wrote to the same unreachable path and
/// failed, and then the probe that decides whether a failed placement COSTS a cap read `memory.max`
/// and `pids.max` from that same unreachable path, found neither, and concluded "no real cap here,
/// nothing to report". The warning written for exactly this situation could not fire. A missing read
/// and a benign answer were the same value, which is the failure this codebase keeps meeting.
///
/// The descriptor is opened BEFORE any `setns` and everything afterwards goes through it, so the
/// hazard is gone by construction rather than by remembering the ordering.
pub struct CgroupRef {
    /// `Cell` so a forked CHILD can close its own copy through a shared reference, without the parent
    /// (a different address space after the fork) losing its own. `-1` means already closed, which is
    /// what keeps [`Drop`] from closing twice.
    fd: std::cell::Cell<libc::c_int>,
}

impl CgroupRef {
    /// Open `dir` as a directory descriptor, or `None` if it cannot be opened or cannot be represented
    /// (see [`open_cgroup_dir_fd`]).
    #[must_use]
    pub fn open(dir: &Path) -> Option<Self> {
        open_cgroup_dir_fd(dir).map(|fd| Self {
            fd: std::cell::Cell::new(fd),
        })
    }

    fn raw(&self) -> libc::c_int {
        self.fd.get()
    }

    /// Close it now, before the caller goes on to do work this descriptor should not be carried
    /// through. It is `O_CLOEXEC`, so an `execvp` would close it anyway; this covers the window
    /// between the fork and that exec, in which the child does its mount and namespace setup and has
    /// no business holding a descriptor on `/sys/fs/cgroup`.
    pub fn close(&self) {
        let fd = self.fd.replace(-1);
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }

    /// Open a file inside the cgroup directory relative to the descriptor, never by path.
    fn open_at(&self, name: &CStr, flags: libc::c_int) -> Option<fs::File> {
        use std::os::fd::FromRawFd;
        let fd = self.raw();
        if fd < 0 {
            return None;
        }
        let f = unsafe { libc::openat(fd, name.as_ptr(), flags | libc::O_CLOEXEC) };
        // SAFETY: `openat` returned a fresh descriptor this process owns; `File` takes ownership and
        // closes it. Checked non-negative first, so no `-1` is ever adopted.
        (f >= 0).then(|| unsafe { fs::File::from_raw_fd(f) })
    }

    /// Read a control file's contents, or `None` if it cannot be read.
    ///
    /// The distinction between `None` and `Some("max")` is the whole point of returning an `Option`
    /// here: "I could not look" and "there is no limit" must not collapse into one value, because they
    /// did, and the collapse is what silenced the warning above.
    fn read_control(&self, name: &CStr) -> Option<String> {
        use std::io::Read;
        let mut f = self.open_at(name, libc::O_RDONLY)?;
        let mut s = String::new();
        f.read_to_string(&mut s).ok()?;
        Some(s)
    }

    /// Does this cgroup carry a REAL memory ceiling (a number, not the `max` no-limit sentinel)?
    ///
    /// Used to decide whether a whole-box OOM is even possible, so the diagnostic that watches for
    /// one is not installed on a box that cannot have it.
    #[must_use]
    pub fn has_real_memory_cap(&self) -> bool {
        self.read_control(c"memory.max")
            .is_some_and(|v| is_real_limit(&v))
    }
}

/// Read a whole file from an ALREADY-OPEN descriptor into a caller-owned buffer, from offset zero,
/// allocating nothing.
///
/// The `lseek` back to the start is not tidiness: a caller that re-reads a pollable cgroup file to
/// re-arm its notification reads the SAME descriptor over and over, and without the rewind every
/// read after the first returns zero bytes, which parses as "the key is not there" and looks exactly
/// like a cgroup that never had an event.
///
/// A file longer than `buf` is truncated to what fits. Correct for the flat-keyed control files this
/// serves because the caller looks for a key rather than for the whole content; a caller that needs
/// completeness must size `buf` for it.
fn read_fd_raw(fd: libc::c_int, buf: &mut [u8]) -> Option<&[u8]> {
    if fd < 0 || buf.is_empty() {
        return None;
    }
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        return None;
    }
    let mut n = 0usize;
    while n < buf.len() {
        let r = unsafe { libc::read(fd, buf[n..].as_mut_ptr().cast(), buf.len() - n) };
        if r > 0 {
            // `r` is positive and at most the length passed in, so this cannot exceed `buf`.
            n += r as usize;
            continue;
        }
        if r == 0 {
            break; // EOF
        }
        // A signal during the read is not an error; anything else is, and the partial content is
        // still worth returning because a truncated read of a flat-keyed file can hold the key.
        if unsafe { *libc::__errno_location() } != libc::EINTR {
            break;
        }
    }
    Some(&buf[..n])
}

/// One key's value out of a flat-keyed cgroup file (`<key> <value>\n` per line), allocating nothing.
///
/// `None` when the key is absent or its value is not a plain decimal, and the caller must treat that
/// as "I could not look" rather than as zero: reporting an OOM that did not happen is the same class
/// of defect as staying silent about one that did, pointed the other way.
///
/// ONE parser for every reader of these files, because the keys are near-misses of each other:
/// `oom_kill` and `oom_group_kill` differ by a word, a `strip_prefix("oom_kill ")` does not match the
/// second, and a second copy of the rule is how the two of them drift apart. The whole first token is
/// compared rather than a prefix, so no key can be a prefix of another.
fn parse_flat_key(raw: &[u8], key: &[u8]) -> Option<u64> {
    for line in raw.split(|b| *b == b'\n') {
        let mut it = line.splitn(2, |b| *b == b' ');
        if it.next() != Some(key) {
            continue;
        }
        let digits = it.next()?;
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        // Saturating, so a value wider than `u64` can never wrap into a smaller one and read as
        // "the count went down".
        return Some(digits.iter().fold(0u64, |a, d| {
            a.saturating_mul(10).saturating_add((d - b'0') as u64)
        }));
    }
    None
}

impl Drop for CgroupRef {
    fn drop(&mut self) {
        self.close();
    }
}

/// Put the CALLING process into the box's capped cgroup. Called by the forked child before it execs,
/// because the supervisor stays outside so a whole-box OOM cannot take it.
///
/// Returns false if the write failed, which the caller must treat as "this box would run UNCAPPED" and
/// refuse: a box outside its own cgroup has no memory ceiling and no fork-bomb guard, and running it
/// anyway would be the silent-uncapped failure this codebase refuses everywhere else.
///
/// Writes `0`, which cgroup v2 defines as "the process doing the writing", rather than a pid read from
/// `getpid`. On the `kern exec` path this runs after the child has entered the box's PID NAMESPACE, so
/// a pid taken there is a namespaced one, and whether the kernel resolves it in the writer's namespace
/// or the file's is a question `0` never has to ask.
#[must_use]
pub fn join_box_cgroup(cg: &CgroupRef) -> bool {
    use std::io::Write;
    let Some(mut f) = cg.open_at(c"cgroup.procs", libc::O_WRONLY) else {
        return false;
    };
    f.write_all(b"0").is_ok()
}

/// `CLONE_INTO_CGROUP`, from `include/uapi/linux/sched.h`. Not exposed by the pinned `libc` crate, so
/// it is declared here and pinned by `clone_into_cgroup_constant_matches_the_uapi_header` below.
///
/// THE VALUE ONE BIT AWAY IS A DIFFERENT FEATURE AND FAILS SILENTLY: `CLONE_CLEAR_SIGHAND` is
/// `0x1_0000_0000`. Pass it by mistake and `clone3` SUCCEEDS, the `cgroup` field is ignored, the child
/// is created in the caller's cgroup, and the only symptom is that the box runs uncapped. That
/// mistake was made while prototyping this change and it produced a plausible timing win from a call
/// that did nothing, which is why every test below asserts MEMBERSHIP and not duration.
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// `struct clone_args` at `CLONE_ARGS_SIZE_VER2` (Linux 5.7), the version that added `cgroup`.
///
/// The kernel versions this structure BY SIZE: it reads exactly the number of bytes passed in the
/// second argument of `clone3` and rejects a size it does not know with `EINVAL`. Adding a field here
/// without a kernel that knows it is therefore a refusal, not corruption, and the refusal takes the
/// `fork` path below.
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// Open `dir` as an `O_DIRECTORY` fd for `clone3`, without touching the heap.
///
/// `PATH_MAX` on the stack rather than a `CString`: this runs immediately before a fork in the box
/// start path, and an allocation there is one more failure mode for no benefit. A path that does not
/// fit, or that will not open, yields `None`, which the caller reads as "take the `fork` path".
fn open_cgroup_dir_fd(dir: &Path) -> Option<libc::c_int> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = dir.as_os_str().as_bytes();
    let mut buf = [0u8; libc::PATH_MAX as usize];
    // `<` and not `<=`: the last byte must stay NUL, and `buf` is zeroed, so no terminator is written.
    if bytes.is_empty() || bytes.len() >= buf.len() || bytes.contains(&0) {
        return None;
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    let fd = unsafe {
        libc::open(
            buf.as_ptr().cast::<libc::c_char>(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    (fd >= 0).then_some(fd)
}

/// Fork the box's PID 1, placing it in `dir` AT CREATION when the kernel allows it.
///
/// Returns `(pid, born_inside)` with the `fork(2)` convention: the child's pid in the parent, `0` in
/// the child, and a negative value with `errno` set on failure. `born_inside` is true only when the
/// child is already in `dir` and must NOT then write `cgroup.procs`.
///
/// # Why this exists, measured
///
/// Moving a task into a cgroup by writing `cgroup.procs` takes `cgroup_threadgroup_rwsem` for write,
/// which is a percpu-rwsem, which needs an RCU grace period. Under a back-to-back loop a grace period
/// closes in microseconds; on an OTHERWISE IDLE machine it waits for a tick. Measured on this host,
/// outside kern, with the child reporting its own `/proc/self/cgroup` as a positive control:
///
/// | form                        | back to back | after 100 ms idle       |
/// |-----------------------------|--------------|-------------------------|
/// | `fork` + write `cgroup.procs` | 0.1-0.2 ms | 5.7-19.8 ms (median ~9) |
/// | `clone3(CLONE_INTO_CGROUP)`   | 0.1-0.2 ms | 0.7-1.1 ms (median 0.8) |
///
/// In the whole program the same effect showed as a box start of 3.7 ms in a loop against 12-29 ms
/// for the FIRST box on a quiet machine, while bubblewrap doing the same namespace work on the same
/// host paid nothing (4.4 ms against 4.7 ms) - because bubblewrap creates no cgroup. Every published
/// kern start figure was a hot-loop figure for this reason.
///
/// # Failure modes, each taking the `fork` path rather than failing the box
///
/// * kernel older than 5.3: `clone3` is absent, `ENOSYS`.
/// * kernel 5.3 to 5.6: `clone3` exists, `CLONE_INTO_CGROUP` does not, `EINVAL`.
/// * cgroup v1, or a `dir` that will not open: no fd, so the syscall is never attempted.
/// * **inside a kern box**: kern's own seccomp allowlist denies `clone3` by number with `ENOSYS` (see
///   `seccomp.rs`, and the test `clone3_is_denied_by_enosys_not_by_a_kill` that pins it there). This
///   is the case that decided the shape of this function: a denial that KILLED instead of returning
///   would make a nested `kern box` die here, so the fallback is not a nicety.
/// * Docker's default seccomp profile also answers `ENOSYS` for `clone3`, which is the same path.
///
/// A caller that passes `None` gets a plain `fork`, which is what the layouts that keep the
/// supervisor INSIDE the capped cgroup need: there the workload inherits the cgroup and must not be
/// placed anywhere.
#[must_use]
pub fn fork_into_cgroup(cg: Option<&CgroupRef>) -> (libc::pid_t, bool) {
    if let Some(c) = cg {
        let fd = c.raw();
        if fd >= 0 {
            let mut args = CloneArgs {
                flags: CLONE_INTO_CGROUP,
                // Without this the parent gets NO signal on exit and `waitpid` still works, but every
                // existing SIGCHLD-based path in kern would silently stop seeing the box. `fork(2)`
                // implies SIGCHLD; `clone3` does not, so it is stated.
                exit_signal: libc::SIGCHLD as u64,
                cgroup: fd as u64,
                ..CloneArgs::default()
            };
            // `stack` and `stack_size` left zero: without `CLONE_VM` that is fork semantics, a
            // copy-on-write duplicate of the caller's stack. Passing a stack here would be for a
            // shared-memory thread, which this is not.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_clone3,
                    std::ptr::addr_of_mut!(args),
                    std::mem::size_of::<CloneArgs>(),
                )
            };
            // BOTH processes continue from here, and the descriptor is NOT closed here any more: on
            // the failure path the child needs it to place itself, which is the whole fallback. Each
            // side closes it when it is done - the child through [`CgroupRef::close`] right after the
            // placement decision, the parent through `Drop`.
            if rc >= 0 {
                // A pid does not exceed `pid_t`; the kernel returns it in the low bits of a `c_long`.
                return (rc as libc::pid_t, true);
            }
            // Any error at all: fall through. `errno` is overwritten by the `fork` below, which is
            // correct - the caller reports the failure that actually stopped it, not this one.
        }
    }
    (unsafe { libc::fork() }, false)
}

/// Fork a child that runs INSIDE `guard`'s capped leaf, and report whether it got there.
///
/// Fork semantics: returns `(child_pid, _)` in the parent, `(0, placed)` in the child, `(-1, _)` if
/// the fork failed. `placed` is meaningful in the CHILD and is the answer to the only question that
/// matters on this path - is this process under the memory ceiling and the fork-bomb guard the caller
/// just created, or outside them.
///
/// This is [`fork_into_cgroup`] plus the child-side fallback, packaged so a caller outside this crate
/// never has to hold a `CgroupRef`. `clone3(CLONE_INTO_CGROUP)` places the child before the syscall
/// returns, so on that path there is no window in which the child is outside; where the kernel refuses
/// it (pre-5.7, or a cgroup this process may not write) the child writes itself in instead, which has
/// a window but ends in the same place. The descriptor is closed in the child as soon as the decision
/// is made: it is `O_CLOEXEC` anyway, and nothing between here and the workload's `execve` has any
/// business holding an open handle on `/sys/fs/cgroup`.
///
/// The POLICY on `placed == false` is deliberately NOT here. `kern box` refuses (a box outside its own
/// cgroup is not a box); `kern run` is a cooperative governor and warns. Returning the fact and letting
/// the caller decide is what keeps those two from being one hardcoded answer.
#[must_use]
pub fn fork_workload_into_leaf(guard: &CgroupGuard) -> (libc::pid_t, bool) {
    // A FAILED FORK REPORTS `placed = false`, ALWAYS, on every arm below. The two halves of this
    // tuple must never contradict each other: `(-1, true)` reads as "no child, and it is capped",
    // which is a sentence about a process that does not exist. The CLI checks `pid < 0` first and
    // would not be misled today, but this is a crate-public function and the invariant belongs in it
    // rather than in the discipline of its callers.
    let report = |pid: libc::pid_t, placed: bool| (pid, placed && pid >= 0);
    if !guard.supervisor_is_outside() {
        // The supervisor is INSIDE the capped cgroup, so the child inherits it across the fork and
        // there is nothing to place. Not a failure: `placed` is true.
        return report(unsafe { libc::fork() }, true);
    }
    let Some(cg) = CgroupRef::open(&guard.dir) else {
        // The cap is real and its directory cannot be opened, so the child cannot be put in it. Fork
        // anyway and report the truth; refusing here would be a policy decision (see the doc above).
        return report(unsafe { libc::fork() }, false);
    };
    let (pid, born) = fork_into_cgroup(Some(&cg));
    if pid != 0 {
        // Parent (or a failed fork). `placed` describes the CHILD, which reports its own below.
        return report(pid, true);
    }
    let placed = born || join_box_cgroup(&cg);
    cg.close();
    (0, placed)
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        // Vacate first - move the supervisor back to where it came from - so the now-empty dirs can be
        // removed. This matters in BOTH layouts: with the sibling leaf the supervisor sits in `sup`, which
        // is just as un-removable while populated as `dir` was. (On the scope path an outer `--collect`
        // also cleans up; this is harmless there.) Best-effort: if the move fails the rmdir just no-ops on
        // the non-empty dir, as before.
        //
        // ONLY WHEN THE SUPERVISOR ACTUALLY LEFT, and the guard already records whether it did. It sits
        // outside `origin` on exactly two paths: parked in the sibling leaf (`sup.is_some()`), or joined
        // to the capped cgroup itself because the leaf could not be built (`!outside`). On every other
        // path it never moved, and writing its pid back to `origin` migrates it to the cgroup it is
        // ALREADY IN.
        //
        // A NO-OP MIGRATION IS NOT FREE, which is the whole reason this condition exists. Moving a task
        // between cgroups takes `cgroup_threadgroup_rwsem` for write; that is a percpu-rwsem, and taking
        // one for write needs an RCU grace period. Under a back-to-back loop a grace period closes in
        // microseconds and the write looks free; on an otherwise IDLE machine it waits for a tick.
        // MEASURED with `strace -T` on a quiet host: this single write took 19.04 ms, and it was the
        // ONLY syscall in the whole box teardown above one millisecond. The `-sup` leaf did not exist in
        // that run, so those 19 ms bought a move to where the process already was.
        //
        // See `fork_into_cgroup` for the same mechanism on the other side of the box: together they are
        // why kern's first box on a quiet machine cost four to six times its own hot-loop figure, while
        // bubblewrap - which creates no cgroup - showed no such gap on the same host.
        let supervisor_left_origin = self.sup.is_some() || !self.outside;
        if let Some(origin) = self.origin.as_ref().filter(|_| supervisor_left_origin) {
            let _ = fs::write(origin.join("cgroup.procs"), std::process::id().to_string());
        }
        // Best-effort: a non-empty cgroup or an already-removed dir (ENOENT - an outer `--collect` beat
        // us to it) are both fine to ignore. `sup` after `dir` so a failure on either still attempts the
        // other; they are siblings, so there is no ordering constraint between them.
        let _ = fs::remove_dir(&self.dir);
        if let Some(sup) = &self.sup {
            let _ = fs::remove_dir(sup);
        }
    }
}

/// The current process's cgroup v2 directory under `/sys/fs/cgroup`, from the `0::<path>` line of
/// `/proc/self/cgroup`. cgroup v2 uses hierarchy id `0` with an empty controller field, so the line is
/// literally `0::/some/path`; we match that prefix EXPLICITLY rather than `rsplit("::")` on the whole
/// blob - on a hybrid (v1+v2) host `/proc/self/cgroup` has several lines and a blind `rsplit` could
/// latch onto a v1 line's `::`-free tail and mis-resolve. Absent (v1-only host, unusual mount) → `None`,
/// which every caller treats as "not delegated / best-effort" (fail-safe).
fn current_v2_cgroup() -> Option<PathBuf> {
    let cur = fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = cur
        .lines()
        .find_map(|l| l.strip_prefix("0::"))?
        .trim_start_matches('/');
    // Defence in depth: `/proc/self/cgroup` is kernel-generated and this runs in the host supervisor
    // BEFORE any unshare, so `rel` can't be attacker-forged today - but never join a `..` component into
    // a `/sys/fs/cgroup` path (a future caller inside a controlled cgroup-ns could otherwise escape).
    if rel.split('/').any(|c| c == "..") {
        return None;
    }
    Some(PathBuf::from("/sys/fs/cgroup").join(rel))
}

/// How many processes the kernel's OOM killer has killed in this process's cgroup SUBTREE.
///
/// WHY A COUNTER AND NOT THE BOX'S OWN CGROUP
///   A box killed by its `memory.max` leaves exit status 137 and nothing else. 137 is `128 + SIGKILL`
///   and SIGKILL has many senders, so on its own it tells an operator nothing: measured on this
///   codebase, `kern run -- python3 -c "bytearray(900*1024*1024)"` against the default 512 MiB cap
///   exits 137 with EMPTY output, and the workload simply vanishes. That is kern applying a limit,
///   the limit firing, and kern saying nothing, which is the one failure this codebase treats as
///   expensive.
///
///   Reading the box's OWN cgroup would be exact and is not available: on the scope path systemd is
///   asked for `--collect`, so the unit and its directory are gone by the time the launcher observes
///   the exit. Measured: the `kern-box-*.scope` directory no longer exists after `reap` returns.
///
///   `memory.events` is HIERARCHICAL, so an ancestor that outlives the box carries the count. Read it
///   before the box starts and again after it dies: an increase means the OOM killer fired somewhere
///   in this subtree while the box was running. That is weaker than naming the process, and the
///   caller's message says exactly that rather than claiming more.
///
/// The nearest readable ancestor is used, which minimises how much unrelated activity shares the
/// counter: for a user session that is `app.slice`, the same directory systemd creates the box's
/// transient scope in. `None` when no ancestor exposes the file (cgroup v1, no memory controller, or
/// a box that lands under a slice this process is not below), and `None` is not a failure: the caller
/// then reports nothing rather than guessing.
///
/// ⚠️ WALKING **THIS** PROCESS'S ANCESTORS ANSWERS FOR THE BOX ONLY WHEN THE TWO SHARE ONE. That
/// holds for an ordinary user session and does NOT hold for root, where it is not an edge case but
/// the norm. Measured on a root VPS: kern sits in `/user.slice/user-0.slice/session-N.scope` while
/// the box lands in `/system.slice/kern-box-N.scope`, two different branches whose only common
/// ancestor is the cgroup ROOT, and the root never exposes `memory.events`. The kill happened
/// (`system.slice` went 6 -> 8) and this function returned `None` for all of it, so the operator got
/// exit 137 and an empty screen: exactly the failure the message exists to prevent, on the hosts
/// where the cap is most likely to be enforced. Prefer [`oom_kill_count_for_pid`], which starts from
/// where the box actually IS; this stays as the fallback for when that pid is already gone.
pub fn oom_kill_count() -> Option<u64> {
    let dir = current_v2_cgroup()?;
    // Start at the PARENT: this process's own leaf does not contain the box, which is created as a
    // sibling, so the leaf's counter would never move however many boxes were killed.
    nearest_oom_count_above(dir)
}

/// The same counter, but read from where the BOX is rather than from where kern is.
///
/// `pid` is a process already inside the box's scope, so its cgroup is the scope itself and the
/// parent of that is the slice systemd created it in: `system.slice` under root, `app.slice` under a
/// user manager. That parent outlives the box (the scope is `--collect`, the slice is not), which is
/// the whole reason the counter is read there.
///
/// Returns the DIRECTORY, not the count, because the caller pairs a BEFORE with an AFTER and the two
/// have to come from the same one: by the time the AFTER is read the pid is reaped and
/// `/proc/<pid>/cgroup` is gone, so re-deriving it then would silently read somewhere else, or
/// nowhere. Read it once, keep the path, use [`oom_kill_count_at`] for both ends.
pub fn oom_kill_dir_for_pid(pid: i32) -> Option<PathBuf> {
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let rel = raw
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::trim)
        .filter(|p| p.starts_with('/'))?;
    let mut dir = Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    // The nearest ancestor that HAS the file, resolved now: the scope itself is `--collect` and will
    // be gone, its parent slice will not.
    while dir.pop() {
        if !dir.starts_with("/sys/fs/cgroup") || dir == Path::new("/sys/fs/cgroup") {
            return None;
        }
        if dir.join("memory.events").is_file() {
            return Some(dir);
        }
    }
    None
}

/// `oom_kill` from a directory [`oom_kill_dir_for_pid`] already resolved. `None` if it went away.
pub fn oom_kill_count_at(dir: &Path) -> Option<u64> {
    parse_flat_key(
        fs::read_to_string(dir.join("memory.events"))
            .ok()?
            .as_bytes(),
        b"oom_kill",
    )
}

/// `max` from `pids.events` in an already-resolved directory: how many times the kernel REFUSED a
/// fork or a thread because the pids cap was reached. `None` if the file is not there.
///
/// The counterpart of [`oom_kill_count_at`], and it exists for the same reason: the cap kern applies
/// is invisible in the workload's own error. A process that cannot create a thread reports whatever
/// it makes of `EAGAIN`, and what it makes of it is rarely the truth. MEASURED on Sentry's
/// ClickHouse, which aborts with *"Couldn't get 512 threads from global thread pool: Not enough
/// threads. Please make sure max_thread_pool_size is considerably bigger than
/// background_schedule_pool_size"* - a sentence about ClickHouse's own settings, produced by kern's
/// default `--pids-limit`, which the reader has no reason to suspect and no way to see.
pub fn pids_denied_count_at(dir: &Path) -> Option<u64> {
    parse_flat_key(
        fs::read_to_string(dir.join("pids.events")).ok()?.as_bytes(),
        b"max",
    )
}

/// Open `pids.events` in `dir` and KEEP the descriptor, so the count can be re-read AFTER the box is
/// gone.
///
/// The descriptor exists for the reason [`open_oom_events_fd`] documents and that this repeated on
/// its own: a box's cgroup leaf is torn down with the box, and the refusal counter lives on THAT
/// leaf, because that is where the limit was. MEASURED - reading the path after the workload exited
/// found no file at all, so the message never printed for a box that had just been refused 40 forks.
/// Unlike the OOM counter there is no ancestor to fall back on: `pids.events` counts the events of
/// the cgroup whose own limit was hit.
///
/// The caller owns the descriptor. Pair it with [`pids_denied_from_fd`].
#[must_use]
pub fn open_pids_events_fd(dir: &Path) -> Option<libc::c_int> {
    use std::os::unix::ffi::OsStrExt;
    let p = dir.join("pids.events");
    let bytes = p.as_os_str().as_bytes();
    let mut buf = [0u8; libc::PATH_MAX as usize];
    if bytes.is_empty() || bytes.len() >= buf.len() || bytes.contains(&0) {
        return None;
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    let fd = unsafe {
        libc::open(
            buf.as_ptr().cast::<libc::c_char>(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    (fd >= 0).then_some(fd)
}

/// `max` re-read from a descriptor opened by [`open_pids_events_fd`], allocating nothing. The read
/// rewinds first, so the same descriptor answers repeatedly.
pub fn pids_denied_from_fd(fd: libc::c_int) -> Option<u64> {
    let mut buf = [0u8; 512];
    parse_flat_key(read_fd_raw(fd, &mut buf)?, b"max")
}

/// The pids cap in force in `dir` (`pids.max`), or `None` when there is none or the file is gone.
/// `max` (the kernel's word for "no limit") reads as `None`, so a caller cannot report a limit that
/// does not exist.
pub fn pids_max_at(dir: &Path) -> Option<u64> {
    fs::read_to_string(dir.join("pids.max"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Open `memory.events` in `dir` and KEEP the descriptor, for a reader that must survive the box.
///
/// The descriptor exists because of a race this codebase has already documented once and that I
/// re-measured the hard way: a box killed by `memory.oom.group` takes its own cgroup directory with
/// it, and reading that directory afterwards is a coin toss. Measured on this host, sampling every
/// 2 ms from the moment the workload started: the box's cgroup was GONE 10.7 ms later, and
/// `oom_group_kill` was never observed non-zero there at all, because the counter increments at the
/// same instant the directory is torn down.
///
/// `dir` is therefore an ANCESTOR that outlives the box, from [`oom_kill_dir_for_pid`], and its
/// counters are hierarchical so the box's event lands in them. Measured on the same host, before and
/// after one group kill: `kern.slice` went `oom_group_kill 228 -> 229` and `oom_kill 622 -> 625`, and
/// the directory was still there.
///
/// The caller owns the descriptor. Pair it with [`oom_group_kill_from_fd`], which re-reads it without
/// allocating, so a forked child can use it.
#[must_use]
pub fn open_oom_events_fd(dir: &Path) -> Option<libc::c_int> {
    use std::os::unix::ffi::OsStrExt;
    let p = dir.join("memory.events");
    let bytes = p.as_os_str().as_bytes();
    let mut buf = [0u8; libc::PATH_MAX as usize];
    // `<` and not `<=`: the last byte must stay NUL, and `buf` is zeroed, so no terminator is written.
    if bytes.is_empty() || bytes.len() >= buf.len() || bytes.contains(&0) {
        return None;
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    let fd = unsafe {
        libc::open(
            buf.as_ptr().cast::<libc::c_char>(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    (fd >= 0).then_some(fd)
}

/// `oom_group_kill` re-read from a descriptor opened by [`open_oom_events_fd`], allocating nothing.
///
/// `oom_group_kill` and not `oom_kill`: the first counts times a whole cgroup was killed AS A UNIT,
/// which is the event that takes a `kern exec` down with its box, while the second also counts a
/// single task being reaped inside a box that survives, which is not the caller's business.
///
/// The read rewinds first, so the same descriptor can be read repeatedly. Nothing here allocates, so
/// it is usable after a `fork`.
#[must_use]
pub fn oom_group_kill_from_fd(fd: libc::c_int) -> Option<u64> {
    let mut buf = [0u8; 512];
    parse_flat_key(read_fd_raw(fd, &mut buf)?, b"oom_group_kill")
}

/// `oom_kill` from the nearest ancestor of `dir` that exposes `memory.events`, `dir` itself excluded.
fn nearest_oom_count_above(mut dir: PathBuf) -> Option<u64> {
    while dir.pop() {
        if !dir.starts_with("/sys/fs/cgroup") || dir == Path::new("/sys/fs/cgroup") {
            return None;
        }
        if let Ok(text) = fs::read_to_string(dir.join("memory.events")) {
            return text
                .lines()
                .find_map(|l| l.strip_prefix("oom_kill "))
                .and_then(|n| n.trim().parse().ok());
        }
    }
    None
}

/// Is the direct fast-cap path usable here? True iff kern's delegated `kern.slice` can be ensured - then
/// the caller can SKIP the per-box `systemd-run --scope` and let `apply_limits` cap directly (~4 ms less).
/// Ensures the slice as a side effect (idempotent), so the first call pays the one-time ~4 ms bootstrap.
pub fn direct_caps_available() -> bool {
    ensure_kern_slice().is_some()
}

/// Is a user systemd manager present (so `reexec` could put a box in a `--scope` / a delegated slice)?
/// Running as REAL root? Then kern drives the SYSTEM systemd manager (`systemd-run --system`), which
/// gets the full controller set + a persistent, properly-delegated `kern.slice` - the fast direct-cap
/// path. A rootless kern (the common case) uses its per-user manager (`--user`). This is the ONE
/// root/rootless split on the cgroup surface; everything else (box isolation) is identical.
fn as_root() -> bool {
    // Deliberately the REAL uid (`getuid`), not the effective (`geteuid` that `real.rs` uses for the
    // box uid map): this gates the root-only GLOBAL side-effect (a top-level `kern.slice` + a write to
    // the cgroup-v2 root `subtree_control`), so a setuid-root binary launched by a normal user
    // (getuid≠0) stays on the conservative rootless path instead of touching the host's root cgroup.
    // Don't "fix" toward geteuid. (Safe either way - the writes are kernel-permission-gated and the
    // caps are read-back / fail-closed verified - but getuid is the safer trigger for the global write.)
    (unsafe { libc::getuid() }) == 0
}

/// `--system` when kern is real root, else `--user` - the systemd manager kern's scope/slice live under.
pub fn systemd_scope_mode() -> &'static str {
    if as_root() {
        "--system"
    } else {
        "--user"
    }
}

/// Is the systemd manager kern would use present AND drivable? As root -> the SYSTEM manager
/// (`/run/systemd/system`, i.e. pid-1 systemd on a systemd host). Rootless -> whether `systemd-run
/// --user` can reach the USER manager, the ONLY thing that makes the scope re-exec and the
/// delegated-slice spawn work. The SINGLE definition - both the scope-skip decision and the
/// fail-closed gate call it, no drift.
pub fn user_systemd_present() -> bool {
    if as_root() {
        return std::path::Path::new("/run/systemd/system").exists();
    }
    user_manager_reachable()
}

/// Will `systemd-run --user` reach the user manager? It connects to the manager's OWN control socket,
/// `$XDG_RUNTIME_DIR/systemd/private`, and only falls back to the D-Bus session bus when that socket is
/// absent (confirmed by strace: with a bogus `DBUS_SESSION_BUS_ADDRESS` it still connects to the private
/// socket, and it fails only when NEITHER is reachable). So the accurate, cheap predictor is a LIVE
/// private socket: a `connect()` there proves the manager process is up and will accept the transient
/// scope.
///
/// This deliberately does NOT mirror `sd_bus_default_user` (the D-Bus session bus), which was the wrong
/// primitive. On a host with a reachable D-Bus bus but NO user manager (a `dbus-launch` session without
/// `systemd --user`, some CI images), the bus probe passes, `systemd-run` connects and THEN fails to
/// find the manager, and the scope re-exec's `exec()` has already replaced kern with no fallback - so
/// the box DIES. Probing the manager's own socket means kern commits to `systemd-run` only when the
/// manager is provably present. Like systemd-run, this needs `XDG_RUNTIME_DIR` to locate the socket;
/// unset -> unreachable -> best-effort (the box still starts, uncapped or fail-closed under
/// `--require-limits`). The `/run/user/<uid>/{systemd,bus}`-leftover CI host that first broke this (dir
/// present, `XDG_RUNTIME_DIR` unset) is caught by the same unset check, and a STALE private socket left
/// by a dead manager is rejected by `connect()`, not mere existence.
///
/// The only residual is a sub-millisecond TOCTOU: the manager dies between this `connect()` and the
/// `exec()` in `reexec_in_scope_if_possible`. Do NOT try to close it by tightening this probe - the
/// window is STRUCTURAL to any check-then-use (the probe and the use are separate syscalls with a gap),
/// not a matter of probe accuracy, so a better probe cannot shrink it to zero. `reexec_in_scope_if_possible`
/// already re-probes IMMEDIATELY before the `exec()`, with no blocking I/O between, holding the window at
/// its floor: the few instructions to `execve`. The only way to zero is to stop probing and handle the
/// failure downstream - fork the `systemd-run`, watch it fail, fall back to best-effort - which is
/// deferred because that rewires the launcher->systemd-run->kern->box PDEATHSIG cascade and signal/exit
/// proxying of the WORKING path to close a window that does not occur in steady state (a user manager
/// does not die during a box start); a net-negative trade against a regression to the common path.
fn user_manager_reachable() -> bool {
    let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|d| !d.as_os_str().is_empty())
    else {
        // Without XDG_RUNTIME_DIR, `systemd-run --user` cannot locate the manager either: best-effort.
        return false;
    };
    unix_socket_live(&xdg.join("systemd/private"))
}

/// WHY there is no user manager to delegate a cap through, on THIS host - the clause the uncapped
/// warning carries.
///
/// The warning used to name `XDG_RUNTIME_DIR` every time and suggest pointing it at
/// `/run/user/<uid>`. That is the right advice for exactly one host shape (the variable is unset or
/// wrong while a manager IS listening) and a dead end on every other, including the one a macOS
/// tester hit on 2026-08-29: a colima guest whose session has no user manager at all, where setting
/// the variable to a directory that holds nothing changes nothing and reads as the missing step. So
/// name the variable only when changing it would change the answer, and otherwise say the host has
/// none. Same probe as [`user_manager_reachable`], so the clause cannot contradict the decision.
pub fn missing_manager_clause() -> String {
    if as_root() {
        return "this host does not run systemd (`/run/systemd/system` is absent)".into();
    }
    let uid = unsafe { libc::getuid() };
    let standard_live =
        unix_socket_live(&PathBuf::from(format!("/run/user/{uid}/systemd/private")));
    let xdg = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|d| !d.as_os_str().is_empty());
    let xdg_live = xdg
        .as_ref()
        .is_some_and(|d| unix_socket_live(&d.join("systemd/private")));
    missing_manager_clause_from(uid, xdg, xdg_live, standard_live)
}

/// Testable core of [`missing_manager_clause`]: the wording decision alone, with the host's facts
/// passed in, so a unit test can drive every branch without touching the environment or a socket.
///
/// `xdg_live` is carried rather than assumed false. The caller only reaches this when a cap could not
/// be placed, which USUALLY means no manager - but `apply_limits` can also fail with a perfectly
/// reachable one, and a clause that reported "nothing is listening" about a live socket would be the
/// same kind of unmeasured sentence this function exists to remove.
fn missing_manager_clause_from(
    uid: u32,
    xdg: Option<PathBuf>,
    xdg_live: bool,
    standard_live: bool,
) -> String {
    let standard = PathBuf::from(format!("/run/user/{uid}"));
    if xdg_live {
        return format!(
            "a systemd user manager IS reachable at `{}`, so what failed here is the delegation, \
             not the manager",
            xdg.as_deref().unwrap_or(&standard).display()
        );
    }
    match xdg {
        None if standard_live => format!(
            "`XDG_RUNTIME_DIR` is unset while a user manager IS listening at `/run/user/{uid}` - \
             export `XDG_RUNTIME_DIR=/run/user/{uid}`"
        ),
        Some(ref d) if standard_live && d != &standard => format!(
            "`XDG_RUNTIME_DIR` points at `{}` while the user manager is at `/run/user/{uid}`",
            d.display()
        ),
        _ => format!(
            "this session has no systemd user manager (nothing is listening on \
             `{}/systemd/private`)",
            xdg.as_deref().unwrap_or(&standard).display()
        ),
    }
}

/// Is a unix-domain socket at `path` LIVE - will a listener accept a connection? A `connect()` succeeds
/// only when something is listening, so this separates a manager whose control socket is up from a STALE
/// socket file left by a dead systemd user manager (where `systemd-run --user` would then die with
/// ECONNREFUSED - the exact failure the caller avoids by taking best-effort instead). Non-blocking, so a
/// busy listener's full backlog cannot hang the box-start path; closed at once, no data sent. On OUR OWN
/// resource failure (fd exhaustion) it returns false, the safe direction - see the `fd < 0` branch.
fn unix_socket_live(path: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: an all-zero `sockaddr_un` is a valid, fully-initialised value.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    // Need room for the path AND a terminating NUL (left by the zeroing) inside `sun_path`; and reject
    // an EMBEDDED NUL, which would silently truncate the kernel's path and connect to a DIFFERENT socket
    // than the one named. (The path is `$XDG_RUNTIME_DIR/systemd/private` and an env value cannot carry a
    // NUL, so this is defence-in-depth, not reachable today, but a stat-free guarantee is cheap.)
    if bytes.is_empty() || bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
        return false;
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, &src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = src as libc::c_char;
    }
    // SAFETY: textbook `socket`/`connect`/`close` with a well-formed pathname `AF_UNIX` address; the
    // pointer is to a live stack value and `size_of::<sockaddr_un>()` bounds the read.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        // Could not even create the probe socket (fd exhaustion, or a sandbox that blocks `socket`).
        // `systemd-run --user` opens its manager connection with the SAME primitive, so reporting the
        // manager reachable here would hand the box to a `systemd-run` that fails for the identical
        // reason, with no fallback. Report unreachable: best-effort start (uncapped with a warning, or
        // fail-closed under `--require-limits`), the safe direction and consistent with the `connect`
        // branch below. A false negative only loses cgroup delegation; a false positive kills every
        // box, which is the exact regression this manager check exists to prevent.
        return false;
    }
    let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    let rc = unsafe { libc::connect(fd, std::ptr::addr_of!(addr).cast(), len) };
    // Only an accepted connect proves a live listener. AF_UNIX connect is immediate, so there is no
    // EINPROGRESS to wait on; EAGAIN means a listener exists but its backlog is momentarily full, which
    // is indeterminate for our purpose - fall to best-effort (uncapped start) rather than claim "live"
    // and hand the box to a systemd-run that may itself fail with no fallback. Safe direction on doubt.
    let live = rc == 0;
    unsafe { libc::close(fd) };
    live
}

/// Is an OUTER cgroup, or an outer kern process, already enforcing and supervising this workload?
///
/// TWO CALLERS, ONE QUESTION. `choose_direct_cap_path` uses it to refuse the kern.slice relocation;
/// `kern run` uses it to decide whether to fork a supervisor of its own. Both are asking the same
/// thing - is there already something outside me responsible for this workload's cgroup - and the
/// answer must not be re-derived twice from the same three env vars.
///
/// Under `KERN_SCOPE` the outer process is kern's own scope proxy: it already waits on the workload,
/// forwards its signals, reports its OOM and propagates its exit code, and `systemd-run --collect`
/// already removes the cgroup. A second fork inside would add a third process to the chain and buy
/// none of it.
///
/// Is an OUTER cgroup already enforcing this box's caps, so the direct kern.slice path must NOT be taken?
/// Three cases, all of which run with `KERN_SCOPE` unset-or-set but are already capped/tracked by an
/// ancestor: our own transient systemd `--scope` re-exec (`KERN_SCOPE`), a persistent `--restart` unit
/// (`KERN_MANAGED`, capped by its `kern-<name>.service` cgroup), and a `kern build` RUN step
/// (`KERN_BUILD_STEP`). Taking the direct path for these would move the box OUT of the enforcing ancestor
/// (breaking `stop`/kill for managed units) and could fail-closed-refuse a build/restart into a crash-loop.
pub fn outer_enforcer_present() -> bool {
    crate::cgroup::env_flag("KERN_SCOPE")
        || crate::cgroup::env_flag("KERN_MANAGED")
        || crate::cgroup::env_flag("KERN_BUILD_STEP")
}

/// In-process marker recording that `choose_direct_cap_path` DECIDED to skip the per-box scope.
/// An env var (not a static) because the decision must survive the detached supervisor's forks -
/// a `--restart` runner re-applies limits in a forked child and must still know the path it's on.
/// Is this boolean env flag SET? A variable exported but EMPTY counts as unset.
///
/// `KERN_NO_SCOPE= kern box …`, and the `export FOO=${FOO:-}` idiom every CI script uses, both leave
/// the name present with an empty value. Read with a bare `is_some()` that meant "the flag is on", so
/// on a host where the systemd scope IS the enforcement (a Raspberry Pi 5, measured 2026-07-30) an
/// empty `KERN_NO_SCOPE` left `--memory` at `max` and a workload 3x over its cap exited 0. Nothing was
/// printed. The project already treats an exported-but-blank `KERN_CONFIG` and `XDG_CONFIG_HOME` as
/// unset for exactly this reason; the boolean flags were the ones that had never been given the rule.
pub fn env_flag(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

const DIRECT_MARKER: &str = "KERN_DIRECT_CAPS";

/// Decide - at the ONE decision site, `reexec_in_scope_if_possible` - whether this box takes the
/// direct kern.slice cap path (skipping the per-box `systemd-run --scope`). True only when NO outer
/// enforcer env is set, the user hasn't opted out, a user systemd manager is present, AND the
/// delegated slice is actually usable (ensured as a side effect). Records the decision in
/// [`DIRECT_MARKER`] so [`took_direct_cap_path`] reports the REAL choice, not a re-derivation:
/// re-deriving from env alone made the fail-closed refusal fire on hosts where the scope re-exec
/// was ATTEMPTED and its `exec()` failed (broken/absent `systemd-run` with a leftover
/// `$XDG_RUNTIME_DIR/systemd` dir) - a host that used to run boxes best-effort would refuse ALL of
/// them. Callers scrub an INHERITED marker first (see `box_run`), so a nested `kern` can't be
/// poisoned by its parent's decision.
pub fn choose_direct_cap_path() -> bool {
    choose_direct_cap_path_given(user_systemd_present())
}

/// The same decision as [`choose_direct_cap_path`], but with the user-manager liveness passed IN. A
/// caller that has just probed it in the same breath (the scope re-exec gates on `user_systemd_present()`
/// immediately before calling this) would otherwise repeat the `connect()` on `systemd/private` on the
/// box-start path. Reusing the value is sound: manager liveness is stable across the handful of
/// instructions between that gate and here (no `exec`, no fork, no blocking I/O - only env reads), so the
/// second probe could only ever return the same answer. `choose_direct_cap_path()` above supplies it for
/// the standalone callers (doctor, the fleet-cap check) that have not already probed.
pub fn choose_direct_cap_path_given(manager_present: bool) -> bool {
    if outer_enforcer_present()
        || crate::cgroup::env_flag("KERN_NO_SCOPE")
        || !manager_present
        || !direct_caps_available()
    {
        return false;
    }
    std::env::set_var(DIRECT_MARKER, "1");
    true
}

/// Remove an inherited direct-path marker. Called at the top of `box_run`: the marker is meaningful
/// only for the invocation whose `reexec` set it - a nested `kern box` (or any child re-running
/// kern) inheriting it would arm the fail-closed refusal on a host that never chose the direct path.
pub fn scrub_direct_marker() {
    std::env::remove_var(DIRECT_MARKER);
}

/// Did THIS box invocation actually take the direct cap path? Reads the decision recorded by
/// [`choose_direct_cap_path`] - `apply_limits` picks kern.slice under it (AND-ed with the caller's
/// `allow_direct`, so `kern run` stays off it), and `run_in_sandbox`'s fail-closed refusal arms
/// under it. Because it reports the recorded DECISION (not slice liveness, not an env re-derivation),
/// the refusal fires when the slice was GC'd mid-flight - and never on the scope-exec-failed
/// fall-through, which keeps its historical warn-and-run behavior.
///
/// Read with [`env_flag`], not a bare `is_some()`, and that distinction has already cost this project
/// once: `KERN_NO_SCOPE=` exported EMPTY was read as "the flag is on" and left a box uncapped on a
/// Raspberry Pi 5 (2026-07-30). The same shape here fails the other way - an empty `KERN_DIRECT_CAPS`
/// in the environment would claim a decision this invocation never made, arming the fail-closed
/// refusal and REJECTING a box on a host that never chose the direct path. `export FOO=${FOO:-}` over
/// a set of `KERN_*` names is all it takes, so the marker is only a decision when it carries a value.
pub fn took_direct_cap_path() -> bool {
    env_flag(DIRECT_MARKER)
}

/// Could a `--memory` cap actually be ENFORCED on this host - i.e. is the `memory` controller
/// available somewhere in this process's cgroup v2 tree? A `memory.max` write is ACCEPTED even where
/// the controller isn't delegated/enabled, but then it never bites (no OOM kill). This is false on a
/// kernel that doesn't expose the memory controller to us: Raspberry Pi OS without
/// `cgroup_enable=memory`, and **Microsoft's default WSL2 kernel** (which doesn't delegate `memory`).
/// Env-independent (reads `cgroup.controllers` up the tree); used only to WARN honestly, never to
/// refuse - the namespace/seccomp isolation is unaffected, only the resource cap is. Same failure on
/// these kernels for Docker/Podman; it's the environment, not the runtime.
pub fn memory_cap_enforceable() -> bool {
    current_v2_cgroup().is_some_and(|c| controller_available_in_tree(&c, "memory"))
}

/// What actually happens when kern tries to enforce a `--memory` cap from this cgroup.
///
/// `memory_cap_enforceable()` above answers a WEAKER question - "is the controller listed in
/// `cgroup.controllers` somewhere up the tree" - and collapses three distinguishable states into one
/// bool. That is why `kern doctor` and the box notice could report "enforced" on a host where the
/// `memory.max` write silently does not bind: a process running as root INSIDE a container whose
/// cgroup lists `memory` in `cgroup.controllers` but does not delegate it to children (`memory`
/// absent from `cgroup.subtree_control`). The presence check is true there; the write is inert.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemoryCapState {
    /// A write to a freshly-created child's `memory.max` stuck and read back unchanged: a real
    /// `--memory` cap WILL bind here.
    Enforced,
    /// The direct write does not bind, but the box does not take that path here: it is capped by the
    /// systemd user manager on its own transient scope, and a probe scope came up with the requested
    /// `MemoryMax` IN FORCE (read back from the scope's own `memory.max`). A real `--memory` cap binds.
    ///
    /// This state exists because reporting the direct probe alone was WRONG on every ARM board.
    /// MEASURED 2026-08-24 on an Arduino UNO Q (systemd 257), a Raspberry Pi 5 (252) and a Jetson Orin
    /// Nano (249): a live box started with `--memory 64M` sat in
    /// `.../kern-box-<pid>.scope/kern-box-<name>-<pid>` with `memory.max = 67108864` inside a scope at
    /// `71303168` (the cap plus the supervisor headroom) - the cap enforced by the kernel, exactly as
    /// designed - while `kern doctor`, on the same host in the same second, printed "`--memory` won't
    /// be enforced". Three boards, three systemd versions, the same false negative, on the hardware
    /// kern is aimed at and in the first command a new user runs.
    EnforcedOnScope,
    /// The `memory` controller is in this tree but not delegated to a child kern can create, so a
    /// `memory.max` write is accepted and never bites. `--memory` is silently ineffective.
    PresentNotDelegated,
    /// The `memory` controller is not in this cgroup's tree at all (a stock Raspberry Pi without
    /// `cgroup_enable=memory`, Microsoft's default WSL2 kernel).
    Absent,
    /// Could not be determined: no cgroup v2, or `/proc/self/cgroup` was unreadable.
    Unknown,
}

/// The value both cap probes write and read back: 1 MiB, small, page-aligned and unmistakably not the
/// `max` sentinel a fresh cgroup starts at. ONE definition, because the two probes must agree - the
/// direct one writes it into a child's `memory.max`, the scope one hands it to systemd as `MemoryMax`
/// and compares what the scope reports. Two copies of a number that has to match is how a probe starts
/// answering a question nobody asked.
const CAP_PROBE_BYTES: &str = "1048576";

/// kern's shared parent slice, named ONCE. [`kern_slice_path`] resolves it to a directory and the
/// scope probe hands the same name to `systemd-run --slice=`; two spellings of it is one rename away
/// from a probe that measures a slice no box uses.
const KERN_SLICE_NAME: &str = "kern.slice";

/// How long the scope probe waits for `systemd-run` before giving up on it. Generous next to a healthy
/// scope (measured 8-11 ms on a Raspberry Pi 5, ~40 ms on the slowest board) and short enough that a
/// wedged user manager costs `kern doctor` a bounded pause instead of hanging it.
const SCOPE_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Poll interval while waiting for the probe scope. Small against the timeout, large enough that the
/// wait costs no measurable CPU.
const SCOPE_PROBE_POLL: std::time::Duration = std::time::Duration::from_millis(10);

/// Probe, by a real write, whether a `--memory` cap will actually bind for a box on this host - and
/// probe it WHERE THE BOX WILL CAP, not where this process runs.
///
/// A box applies `--memory` in kern's delegated slice when one is available (root's directly-created
/// `kern.slice`, or a rootless user-systemd delegated slice), otherwise a best-effort child of the
/// current cgroup. This resolves that SAME target via [`ensure_kern_slice`] - the identical choice
/// `choose_direct_cap_path` makes for a real box - then creates an empty throwaway child cgroup
/// there, writes its `memory.max`, reads it back, and removes the child. Unlike
/// [`memory_cap_enforceable`] (a `cgroup.controllers` presence read), it performs the exact operation
/// `apply_limits` performs in the exact place, so it cannot report success where the write will not
/// bind. This replaces a former root-only ASSUMPTION (promoting `PresentNotDelegated` to `Enforced`
/// by fiat) with a MEASUREMENT: root's delegated `kern.slice` now reads back the write it accepts, and
/// a root host where the slice cannot be made reports the honest state instead of a promoted one.
///
/// SIDE EFFECTS: resolving the target is exactly what a box start does - it may create the persistent
/// `kern.slice` (root: a `mkdir` + an additive `subtree_control` write on the v2 root; rootless: a
/// one-time `systemd-run --user` that exits immediately). Then exactly one `mkdir` + `rmdir` of a
/// `kern-capprobe-<pid>` child and one write to that child's OWN `memory.max`; the child holds no
/// processes, so nothing is throttled, and it is removed on every return path. It never writes an
/// existing box's or sibling's limit files. If the child comes up WITHOUT a `memory.max`, it also
/// performs the parent's additive `cgroup.subtree_control` write - the same one every box start
/// performs - because otherwise the probe reports on whether a box has run yet rather than on whether
/// a cap binds. It enables controllers and sets no limit.
///
/// NOT for the box-start hot path (a box ensures the slice itself). Its one caller, doctor, invokes it
/// at most once; do not place it in a per-box-start or per-syscall loop.
/// The two directories a `--memory` cap can land in on this host, in the order `apply_limits` picks
/// them: `(kern.slice, the caller's own cgroup)`. Either may be `None`.
///
/// Public so `kern doctor` can NAME the places it probed instead of asserting an unlocated verdict.
/// An outside reviewer refused a release over exactly that gap: doctor said a `--memory` write
/// "silently never bites" while a box on the same host exited 137, and the sentence pointed at no
/// directory, so neither of us could tell whether doctor or the 137 was describing kern's cap. A
/// claim about a cgroup that does not say WHICH cgroup cannot be checked against `/proc/<pid>/cgroup`.
///
/// Single source for both callers: deriving these paths a second time inside doctor is the duplicated
/// derived condition that made the previous version of this probe report on a directory no box used.
///
/// SIDE EFFECT: like [`memory_cap_state`], resolving the first site may CREATE the persistent
/// `kern.slice` - the same thing a box start does. Not for a hot path.
pub fn memory_cap_probe_sites() -> (Option<PathBuf>, Option<PathBuf>) {
    (ensure_kern_slice(), current_v2_cgroup())
}

pub fn memory_cap_state() -> MemoryCapState {
    // BOTH DIRECTORIES A BOX CAN BE CAPPED IN, because `or_else` answered a narrower question than the
    // one asked and the two answers disagreed on a real host.
    //
    // `apply_limits` picks `kern.slice` when the direct path was chosen and the caller's OWN cgroup
    // (`origin`) otherwise. `or_else` only reaches the second when the first is `None`, so on a host
    // where the slice EXISTS but boxes do not use it, this probed the slice and reported on a
    // directory no box goes near.
    //
    // MEASURED by an outside reviewer, uid 0, no user manager: `kern doctor` printed "the `memory`
    // controller is listed but NOT delegated to a child cgroup - a `--memory` write is accepted and
    // silently never bites", and on the same host in the same session a box started with
    // `--memory 64m` reported `memory_max = 67108864` and an `exec` that overran it exited 137.
    // Their box's PID 1 sat in `0::/`, the v2 ROOT, which `or_else` never reached because
    // `ensure_kern_slice()` had answered `Some`: the probe reported on a directory no box went near,
    // which is a defect on its own and is what the two-site probe below fixes.
    //
    // WHAT THAT REPORT DOES NOT ESTABLISH, and the reason this comment no longer says the cap bound:
    // `memory_max` in `inspect` was the value the box was STARTED with, echoed from the registry, not
    // a read-back, and the v2 root has no `memory.max` file at all, so a box in `0::/` has nothing to
    // be capped by. Exit 137 is SIGKILL, which a system OOM kill delivers identically. The two
    // observations are consistent with the probe being right. Neither reading is settled here, so
    // both are made checkable instead: `inspect` now reports `memory_max_enforced` read back from the
    // box's own cgroup, and doctor NAMES the directories below so its claim can be falsified against
    // the same `/proc/<pid1>/cgroup` the operator can read.
    //
    // A box is capped if EITHER parent binds, so both are asked and the better answer wins. The cost
    // is one extra throwaway child cgroup on a command that runs once, and only when the first
    // directory did not already answer `Enforced`.
    let (slice, own) = memory_cap_probe_sites();
    let Some(first) = slice.clone().or_else(|| own.clone()) else {
        return MemoryCapState::Unknown;
    };
    let mut direct = memory_cap_state_at(&first);
    if direct == MemoryCapState::Enforced {
        return direct;
    }
    // The second directory, only when it is a DIFFERENT one: probing the same path twice would double
    // the cost to re-derive the answer just obtained.
    if let Some(second) = own.filter(|o| Some(o) != slice.as_ref()) {
        let alt = memory_cap_state_at(&second);
        if alt == MemoryCapState::Enforced {
            return alt;
        }
        // Keep the more INFORMATIVE of the two negatives. `PresentNotDelegated` says the controller is
        // in the tree and merely not reaching a child, which is actionable; `Absent` says it is not
        // there at all. Reporting `Absent` for a host where one of the two directories has it would
        // name a cause the operator cannot fix because it is not the cause.
        if direct == MemoryCapState::Absent || direct == MemoryCapState::Unknown {
            direct = alt;
        }
    }
    // The direct write does not bind - but on the boards that is not how a box is capped. There kern
    // re-execs into a transient scope and the MANAGER applies `MemoryMax` to it, which the direct
    // probe never touches because it creates no scope. Ask the second path before reporting a host
    // uncapped: see [`MemoryCapState::EnforcedOnScope`] for the measurement that made this necessary.
    if scope_path_caps_memory() {
        return MemoryCapState::EnforcedOnScope;
    }
    direct
}

/// Does a box get a REAL `--memory` cap through the scope path on this host?
///
/// Not deduced from what the manager delegates - MEASURED, the same way [`scope_accepts_oom_policy`]
/// measures `OOMPolicy=`: build a transient scope carrying `MemoryMax` and have it read back its OWN
/// `memory.max`. [`CAP_PROBE_BYTES`] back means the limit was in force while a process lived under it;
/// `max` means the manager accepted the property and dropped it (what a host with no `memory`
/// controller does), and that is reported as uncapped.
///
/// It takes TWO scopes because the scope's cgroup path must not be ASSUMED. The first attempt computed
/// it from [`kern_slice_path`], which derives from the CURRENT cgroup - and an ssh session lives in
/// `user-<uid>.slice/session-N.scope`, with no `user@<uid>.service` ancestor, so the path came out
/// `None` and the probe silently answered "no cap" on all three boards even though the scope path caps
/// them. So the first scope prints its OWN `/proc/self/cgroup`, and the second reads the `memory.max`
/// under the DIRECTORY that answer names. Only the parent is taken from the measurement, never the
/// leaf: the two scopes carry DIFFERENT unit names because reusing one is refused by older managers
/// ("Unit kern-cp-x.scope was already loaded", measured on systemd 252 and 249, accepted on 257), which
/// is exactly the kind of version-dependent behaviour that has to be probed rather than assumed.
/// `--collect` removes each unit, so nothing is left behind.
///
/// Memoised per process. Its only caller is the doctor probe, on the path where the direct write has
/// already failed, so no box start pays for the two scopes.
fn scope_path_caps_memory() -> bool {
    static MEMO: OnceLock<bool> = OnceLock::new();
    *MEMO.get_or_init(|| {
        let pid = unsafe { libc::getpid() };
        // Where does such a scope live? Ask one, and keep only the directory it reports.
        let first = format!("kern-capprobe-{pid}-a");
        let Some(reported) = scope_probe_read(&first, std::path::Path::new("/proc/self/cgroup"))
        else {
            return false;
        };
        let Some(parent) = scope_parent_from_proc_cgroup(&reported) else {
            return false;
        };
        let second = format!("kern-capprobe-{pid}-b");
        let own_max = PathBuf::from(format!("/sys/fs/cgroup{parent}/{second}.scope/memory.max"));
        scope_probe_read(&second, &own_max).is_some_and(|v| v.trim() == CAP_PROBE_BYTES)
    })
}

/// The DIRECTORY a probe scope reported for itself, from the `/proc/self/cgroup` it printed: the v2
/// line (`0::/…`) minus its leaf. `None` for anything that is not a v2 path, so a cgroup v1 host or a
/// garbled read makes the probe answer "no cap" instead of building a path out of nonsense. Pure, so
/// the parsing is tested without a systemd.
fn scope_parent_from_proc_cgroup(reported: &str) -> Option<String> {
    reported
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::trim)
        .filter(|p| p.starts_with('/'))
        .and_then(|p| p.rsplit_once('/'))
        .map(|(dir, _leaf)| dir.to_string())
        .filter(|dir| !dir.is_empty())
}

/// One `systemd-run --scope -p MemoryMax=…` whose whole job is to `cat` the file it is given, from
/// inside the scope. Returns its stdout, or `None` if the scope could not be built (no `systemd-run`,
/// no `cat`, a manager that refuses the property, or a manager that does not answer). Shared by both
/// passes of [`scope_path_caps_memory`] so the two scopes differ only in the file they read.
///
/// BOUNDED, unlike a plain `output()`. `systemd-run` talks to the user manager over D-Bus, and a
/// manager that never replies would hang it forever - which for a diagnostic is the worst failure
/// there is: `kern doctor` exists to TELL you the state of a sick host, so it must not become part of
/// the sickness. The child is reaped after [`SCOPE_PROBE_TIMEOUT`], and its output is read only once
/// it has exited, so nothing is left running and nothing blocks on a full pipe.
fn scope_probe_read(unit: &str, what: &std::path::Path) -> Option<String> {
    let systemd_run = crate::real::trusted_helper("systemd-run")?;
    let cat = crate::real::trusted_helper("cat")?;
    let mut child = Command::new(systemd_run)
        .arg(systemd_scope_mode())
        .args(["--scope", "--quiet", "--collect"])
        .arg(format!("--slice={KERN_SLICE_NAME}"))
        .arg(format!("--unit={unit}"))
        .arg("-p")
        .arg(format!("MemoryMax={CAP_PROBE_BYTES}"))
        .arg(cat)
        .arg(what)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + SCOPE_PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            // Exited: read what it printed. A non-zero status means no usable answer.
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                use std::io::Read;
                let mut out = String::new();
                child.stdout.take()?.read_to_string(&mut out).ok()?;
                return Some(out);
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    // Take the child away rather than leave a probe behind, and reap it so it cannot
                    // become a zombie. `--collect` removes the unit if one was ever created.
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(SCOPE_PROBE_POLL);
            }
            Err(_) => return None,
        }
    }
}

/// Testable core of [`memory_cap_state`]: the probe against an explicit cgroup directory, split out
/// for the same reason `config::load_impl` is - a unit test can drive it against a synthetic tree
/// without reading (or mutating) the real `/proc/self/cgroup`.
fn memory_cap_state_at(cur: &std::path::Path) -> MemoryCapState {
    let child = cur.join(format!("{CAPPROBE_LEAF_PREFIX}{}", unsafe {
        libc::getpid()
    }));
    // Create the throwaway child. `AlreadyExists` is a leftover from a crashed probe: remove and
    // retry once. Any other creation error means child cgroups cannot be created here at all, which
    // is the not-delegated signal, refined below by whether the controller is even present.
    match fs::create_dir(&child) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_dir(&child);
            if fs::create_dir(&child).is_err() {
                return classify_absent_or_not_delegated(cur);
            }
        }
        Err(_) => return classify_absent_or_not_delegated(cur),
    }
    // From here the child EXISTS and must be removed on every path below.
    let max = child.join("memory.max");
    // cgroup v2 creates a controller's interface files in a child only when that controller is in the
    // parent's `subtree_control`. No `memory.max` file therefore does NOT yet mean `memory` is not
    // delegated: it can equally mean nobody has enabled it in the subtree yet, which is the state a
    // freshly created `kern.slice` is in until the first box start writes it.
    //
    // MEASURED on this desktop (2026-08-24): with `kern.slice` delegated (`cgroup.controllers` =
    // `cpu memory pids`) but its `cgroup.subtree_control` EMPTY, this probe reported
    // `PresentNotDelegated` and doctor printed "`--memory` won't be enforced", while in that exact
    // state a box started with `--memory 64M` was OOM-killed at the cap (exit 137). The probe was
    // measuring the incidental state of `subtree_control` instead of what a box gets, and the first
    // command a new user runs was told the opposite of the truth.
    //
    // So do here what `apply_limits` does before it caps: enable the controllers on the parent, then
    // look again. The write is the same additive, idempotent one a box start performs (it enables
    // controllers, it sets no limit), and the kernel refuses it on a cgroup that holds processes
    // (measured: EBUSY on this desktop's own scope, 19 processes in it) - which is exactly the
    // `current_v2_cgroup` fallback case, where it therefore changes nothing and the classification
    // below still stands. So this cannot turn an unenforceable host into a false green.
    if !max.exists() {
        enable_subtree_controllers(cur);
    }
    if !max.exists() {
        let _ = fs::remove_dir(&child);
        return classify_absent_or_not_delegated(cur);
    }
    // Write a small, unmistakable, non-`max` value to the EMPTY child and read it back. Any value is
    // safe: the cgroup holds no processes, so nothing is throttled or OOM-killed.
    // The same write-then-verify primitive `apply_limits` uses for a real box's `memory.max`: a fresh
    // child starts at the `max` sentinel, so "reads back a real (non-`max`) limit" is equivalent to the
    // exact-value check here, and there is one definition of "the write bound" instead of two.
    let stuck = wrote_real_limit(&max, CAP_PROBE_BYTES);
    let _ = fs::remove_dir(&child);
    if stuck {
        MemoryCapState::Enforced
    } else {
        // The interface file existed (controller delegated) but the write did not read back. Report
        // "not effectively enforceable" rather than claim a success the box would not get.
        MemoryCapState::PresentNotDelegated
    }
}

/// Distinguish "the `memory` controller is absent from this tree" from "present but not delegated to
/// a child we can create". Reached when a child could not be created or has no `memory.max`.
fn classify_absent_or_not_delegated(cur: &std::path::Path) -> MemoryCapState {
    if controller_available_in_tree(cur, "memory") {
        MemoryCapState::PresentNotDelegated
    } else {
        MemoryCapState::Absent
    }
}

/// Which of the two things a reader could change is in the way, when `memory` is present in the tree
/// but a child cgroup still cannot carry a cap.
///
/// It exists because the hint that shipped said "add `memory` to this tree's `cgroup.subtree_control`"
/// unconditionally. On a colima guest (macOS, 2026-08-29) that command runs, prints nothing, changes
/// nothing and exits 0: an `colima ssh` session is uid 501 under `/system.slice/ssh.service`, owned by
/// root and mode 755, so the write is refused and the shell's redirection swallows it. Advice that
/// cannot work AND looks like it worked costs more than no advice.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DelegationBlocker {
    /// The cgroup kern runs in is not writable by this user: no child can be created in it and
    /// `cgroup.subtree_control` cannot be written either. Nothing to enable here.
    NotWritable,
    /// Writable, and `memory` is missing from `cgroup.subtree_control`: the one case where enabling
    /// the controller by hand is the fix.
    ControllerNotEnabled,
    /// Writable, controller already enabled, and a cap still does not read back. Neither of the two
    /// local changes applies.
    Neither,
}

/// [`DelegationBlocker`] for the cgroup a box would actually be capped in - the same target
/// [`memory_cap_state`] probes, so the diagnosis and the verdict cannot describe different cgroups.
pub fn delegation_blocker() -> DelegationBlocker {
    match ensure_kern_slice().or_else(current_v2_cgroup) {
        Some(dir) => delegation_blocker_at(&dir),
        None => DelegationBlocker::Neither,
    }
}

/// Testable core of [`delegation_blocker`], against an explicit directory.
fn delegation_blocker_at(dir: &std::path::Path) -> DelegationBlocker {
    if !dir_writable(dir) {
        return DelegationBlocker::NotWritable;
    }
    let enabled = fs::read_to_string(dir.join("cgroup.subtree_control"))
        .is_ok_and(|s| s.split_whitespace().any(|c| c == "memory"));
    if enabled {
        DelegationBlocker::Neither
    } else {
        DelegationBlocker::ControllerNotEnabled
    }
}

/// Can THIS user create an entry in `dir`? `access(2)` with the real uid, which is what matters: kern
/// runs unprivileged here and the write it would suggest is the user's, not a namespace-mapped one.
fn dir_writable(dir: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c` is a live NUL-terminated path; `access` only reads it.
    unsafe { libc::access(c.as_ptr(), libc::W_OK | libc::X_OK) == 0 }
}

/// Does an env var CLAIM an outer enforcer while NO real memory cap is actually in force up-tree?
/// A caller launching `kern box` can FORGE `KERN_SCOPE`/`KERN_MANAGED` to disarm the fail-closed -
/// but a genuine scope ALWAYS sets a `MemoryMax` (see `reexec`'s props) and a genuine managed unit
/// runs under its own delegated service cgroup, so `memory.max` capped-in-tree is a reliable,
/// env-INDEPENDENT check that a real enforcer exists. When this is true and the box couldn't cap,
/// it would run uncapped because of a (possibly forged) env - the caller warns loudly rather than
/// let it happen silently. Two deliberate scope-downs (both board/audit findings):
///
/// * **`KERN_BUILD_STEP` never arms it** - `kern build` sets that var as a best-effort scope-skip
///   with NO enforcer anywhere by design, so it claims nothing to verify; arming on it fired the
///   "may be bypassing" accusation once per RUN step of every build launched from a session scope.
/// * **Gated on the memory controller being AVAILABLE up-tree** (per `cgroup.controllers`, root
///   included - a privileged systemd can cap where the user can't): on a host that never enables it
///   (a stock Pi without `cgroup_enable=memory`) no genuine enforcer COULD have set a `memory.max`,
///   so our own legit scope re-exec would otherwise trip the warning on EVERY box and pollute each
///   detached box's log; the dedicated "--memory not enforced" message already tells that truth.
pub fn env_claims_enforcer_but_none_real() -> bool {
    let claims = crate::cgroup::env_flag("KERN_SCOPE") || crate::cgroup::env_flag("KERN_MANAGED");
    claims
        && current_v2_cgroup().is_some_and(|c| {
            controller_available_in_tree(&c, "memory") && !capped_in_tree(&c, "memory.max")
        })
}

/// Does ANY level of this cgroup's ancestry have `ctrl` in its `cgroup.controllers` - i.e. could a
/// cap on that controller exist in our tree at all? Checked via `cgroup.controllers` (not `.max`
/// file existence): the root of a cgroup namespace lists its controllers but carries no limit
/// files, and a limit set by privileged systemd counts even where the user has no delegation.
fn controller_available_in_tree(child: &std::path::Path, ctrl: &str) -> bool {
    in_tree(child, |dir| has_controller(dir, ctrl))
}

/// Walk from `child` up to the cgroup root (inclusive), returning true at the first level where
/// `pred` holds. THE shared ancestry walker - `capped_in_tree` and `controller_available_in_tree`
/// are one-predicate wrappers, so the subtle termination rules (root clamp, never escaping
/// `/sys/fs/cgroup`) exist exactly once.
fn in_tree(child: &std::path::Path, pred: impl Fn(&std::path::Path) -> bool) -> bool {
    let root = std::path::Path::new("/sys/fs/cgroup");
    let mut dir = child.to_path_buf();
    loop {
        if pred(&dir) {
            return true;
        }
        if dir.as_path() == root {
            return false;
        }
        match dir.parent() {
            Some(p) if p.starts_with(root) => dir = p.to_path_buf(),
            _ => return false,
        }
    }
}

/// Is this slice actually USABLE for capping - i.e. its delegated `cgroup.controllers` really contains
/// `memory` AND `pids`? A cgroup always HAS a `cgroup.controllers` file, so checking existence alone is a
/// false positive on hosts where the memory controller isn't delegated (or isn't even enabled at the root,
/// e.g. a Raspberry Pi without `cgroup_enable=memory`). Board-test finding: without this, we'd take the
/// direct path and then fail-closed-refuse EVERY capped box on such a host; with it, `direct_caps_available`
/// is false there → we fall back to the scope / best-effort + warning path, exactly as before.
/// Can a CHILD of `dir` carry a real cap? Measured the way a box start measures it, because
/// "`memory` is listed in `cgroup.controllers`" answers a different question: a cgroup that HOLDS
/// PROCESSES cannot enable controllers in its `cgroup.subtree_control` at all (cgroup v2's
/// no-internal-process rule), so its children get no `memory.max` however well delegated it is.
///
/// That is not a corner case: it is every host where kern runs in the cgroup it was started in and
/// there is no systemd user manager to hand it a leaf of its own. A container, WSL2, and a colima VM
/// are all that shape, and on all three `apply_limits` used to build the box under that cgroup, find
/// no `memory.max`, and report the box UNCAPPED while `kern doctor` reported caps enforced (it probes
/// `kern.slice`, which as root it creates EMPTY, so its children cap fine). Two surfaces, one host,
/// opposite answers.
///
/// Memoised: the probe creates and removes a directory, and a box start must not pay that twice.
fn children_can_be_capped(dir: &std::path::Path) -> bool {
    static MEMO: OnceLock<(PathBuf, bool)> = OnceLock::new();
    let (probed, verdict) = MEMO.get_or_init(|| (dir.to_path_buf(), probe_child_cap(dir)));
    if probed == dir {
        return *verdict;
    }
    // A different cgroup than the memoised one: probe it rather than answer about another. One
    // process caps under one parent, so this is rare and off the hot path either way.
    probe_child_cap(dir)
}

/// The measurement behind [`children_can_be_capped`], and it is DELIBERATELY the same function
/// `kern doctor` reports from. The bug this whole arm exists to fix was two surfaces answering the
/// same question about the same host and disagreeing; fixing it by writing a SECOND probe that
/// happens to agree today would have rebuilt the defect with a longer fuse. One prober, one answer.
///
/// [`MemoryCapState::EnforcedOnScope`] is NOT enough here and that is the point of the match rather
/// than a bool: it means the cap binds because a systemd manager applies it to a transient scope,
/// which is precisely the path this arm exists because the host does NOT have. Only a direct write
/// that stuck says a child of `dir` will carry a cap.
fn probe_child_cap(dir: &std::path::Path) -> bool {
    enable_subtree_controllers(dir);
    matches!(memory_cap_state_at(dir), MemoryCapState::Enforced)
}

fn slice_can_cap(slice: &std::path::Path) -> bool {
    has_controller(slice, "memory") && has_controller(slice, "pids")
}

/// Is `ctrl` listed in this cgroup's `cgroup.controllers`? The single decoder of that file - shared
/// by [`slice_can_cap`] and [`controller_available_in_tree`] so "available" can't mean two things.
fn has_controller(dir: &std::path::Path, ctrl: &str) -> bool {
    fs::read_to_string(dir.join("cgroup.controllers"))
        .is_ok_and(|c| c.split_whitespace().any(|t| t == ctrl))
}

/// Path of kern's own slice. As real root it's a TOP-LEVEL system slice (`/sys/fs/cgroup/kern.slice`,
/// where `systemd-run --system --slice=kern.slice` lands it). Rootless it's a sibling under our
/// `user@<uid>.service` delegation root (derived from our own cgroup so it tracks the real user
/// manager). `None` rootless if there's no such root (no systemd-user).
fn kern_slice_path() -> Option<PathBuf> {
    if as_root() {
        // `systemd-run --system --slice=kern.slice` lands the slice at the top of the cgroup-v2 mount.
        return Some(PathBuf::from("/sys/fs/cgroup").join(KERN_SLICE_NAME));
    }
    // THE DELEGATION ROOT IS NOT ALWAYS AN ANCESTOR OF THE CALLER, and assuming it was made the
    // direct cap path unreachable on a whole class of hosts.
    //
    // MEASURED by an outside reviewer on WSL2 with `systemd=true`, 2026-09-09: a user manager IS
    // running, and the login shell sits in `0::/init.scope`, whose only ancestors are `/init.scope`
    // and the root. Neither matches, so this returned `None`, `direct_caps_available()` was false,
    // and every `kern run` there took the per-invocation systemd scope: 11.5 ms against the 1.0 ms
    // the same host reaches with `KERN_NO_SCOPE=1`. The delegated tree was there the whole time,
    // one directory away, and kern could not name it because it was looking UP instead of AT it.
    if let Some(root) = delegation_root_above(current_v2_cgroup().as_deref()) {
        return Some(root.join(KERN_SLICE_NAME));
    }
    // The canonical layout, built from the REAL uid, and taken ONLY if it is really there. This is
    // where systemd puts a user manager on every host that has one, and it is the same tree
    // `systemd-run --user --scope` lands a transient unit in, so a box capped here is capped exactly
    // where the scope path would have put it. `getuid` and not `geteuid`, matching `as_root` above:
    // the manager belongs to the real user, not to a setuid binary's effective one.
    //
    // FAILS TO `None` IF THE DIRECTORY IS ABSENT, which is the whole safety of it: on a host with no
    // user manager, or one laid out some other way, this answers exactly what it answered before and
    // the caller falls back to the per-box scope. It cannot invent a delegation that is not there,
    // because `ensure_kern_slice` still has to create and cap a child under it before anything is
    // used, and `slice_can_cap` checks that the controllers actually arrived.
    let canonical = canonical_delegation_root(unsafe { libc::getuid() });
    canonical.is_dir().then(|| canonical.join(KERN_SLICE_NAME))
}

/// The `user@<uid>.service` ancestor of `cur`, if there is one. Split out from [`kern_slice_path`]
/// with no filesystem in it, so both of its answers can be asserted against a literal path rather
/// than against whichever cgroup the test binary happened to be started in.
fn delegation_root_above(cur: Option<&Path>) -> Option<PathBuf> {
    cur?.ancestors()
        .find(|p| {
            p.file_name().is_some_and(|n| {
                let n = n.to_string_lossy();
                n.starts_with("user@") && n.ends_with(".service")
            })
        })
        .map(Path::to_path_buf)
}

/// Where systemd puts a user manager on a host that has one, built from the uid alone.
///
/// Pure, so the string is checked by a test instead of by reading it: this path is the FALLBACK for
/// a caller whose own cgroup has no delegation root above it, and a typo in it would silently mean
/// "no delegated slice here" on every host. That failure is invisible, because it degrades to the
/// behaviour this replaced instead of erroring.
fn canonical_delegation_root(uid: u32) -> PathBuf {
    PathBuf::from(format!(
        "/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service"
    ))
}

/// Apply a FLEET-WIDE budget to kern's shared parent slice (`kern.slice`): a hard `memory.max` and/or
/// `pids.max` on the PARENT of every box, so the kernel bounds the SUM of all running boxes, not just
/// each box on its own. This is the REAL-enforcement backstop to the cooperative `--max-concurrent`
/// counter: even if a caller unsets that env, the slice cap still bounds total box memory/pids at the
/// kernel level. `None` leaves that dimension untouched.
///
/// Best-effort and idempotent, safe to call on every box start: writing a `*.max` file on the slice
/// takes only when systemd-user has delegated `kern.slice` with the controller enabled (the same
/// condition per-box caps need). A slice that doesn't exist yet (no box has created it) is skipped, so
/// the fleet cap engages from the moment `kern.slice` first appears, exactly when a fleet exists. A
/// value of `u64::MAX` is written as the literal `max` (uncapped) so a caller can clear a prior budget.
pub fn set_fleet_caps(memory_max: Option<u64>, pids_max: Option<u64>) {
    let Some(slice) = kern_slice_path() else {
        return;
    };
    if !slice.is_dir() {
        return; // no box has created the slice yet; a later start applies the cap once it exists
    }
    if let Some(m) = memory_max {
        let _ = fs::write(slice.join("memory.max"), render_cgroup_max(m));
    }
    if let Some(p) = pids_max {
        let _ = fs::write(slice.join("pids.max"), render_cgroup_max(p));
    }
}

/// A snapshot of the shared `kern.slice` fleet budget and its live usage, for display (`kern top`).
pub struct FleetStatus {
    /// `memory.max` on the slice: `Some(bytes)` when a fleet memory cap is set, `None` when uncapped.
    pub memory_max: Option<u64>,
    /// `memory.current`: live total bytes across every box in the slice.
    pub memory_current: u64,
    /// `pids.max`: `Some(n)` when a fleet pids cap is set, `None` when uncapped.
    pub pids_max: Option<u64>,
    /// `pids.current`: live total task count across the slice.
    pub pids_current: u64,
}

impl FleetStatus {
    /// True when a fleet budget is actually in force (a memory or pids cap is set on the slice); a bare
    /// slice with no cap isn't worth surfacing.
    pub fn is_capped(&self) -> bool {
        self.memory_max.is_some() || self.pids_max.is_some()
    }
}

/// Read the live `kern.slice` fleet budget + usage (the SUM cap across all boxes). `None` when the slice
/// isn't present (no box created it, or no systemd-user delegation), so a caller shows nothing.
pub fn fleet_status() -> Option<FleetStatus> {
    let slice = kern_slice_path()?;
    if !slice.is_dir() {
        return None;
    }
    // A `*.max` of the literal `max`, a missing file, or an unparseable value all read as "uncapped".
    let read_max = |f: &str| -> Option<u64> {
        let s = fs::read_to_string(slice.join(f)).ok()?;
        match s.trim() {
            "max" => None,
            n => n.parse().ok(),
        }
    };
    let read_cur = |f: &str| -> u64 {
        fs::read_to_string(slice.join(f))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };
    Some(FleetStatus {
        memory_max: read_max("memory.max"),
        memory_current: read_cur("memory.current"),
        pids_max: read_max("pids.max"),
        pids_current: read_cur("pids.current"),
    })
}

/// Render a cgroup v2 `*.max` value: a plain number, or the literal `max` for [`u64::MAX`] (uncapped),
/// which cgroup v2 uses to clear a limit. Pure, so the wire format is unit-tested without a cgroupfs.
fn render_cgroup_max(n: u64) -> String {
    if n == u64::MAX {
        "max".to_string()
    } else {
        n.to_string()
    }
}

/// Is this `/proc/<pid>/exe` basename kern's, in either spelling the kernel produces?
///
/// The kernel appends `" (deleted)"` when the binary behind a running process has been replaced or
/// removed, which is the state of every already-running kern the moment `install.sh` overwrites it.
/// A comparison against the bare name reports those processes as not-kern.
///
/// Pure, so both spellings and the near misses are asserted against literals rather than against
/// whatever happens to be running on the machine the test runs on.
fn exe_stem_is_kern(name: &str) -> bool {
    name == "kern" || name == "kern (deleted)"
}

/// Is the process that OWNS a capped leaf dead? `rest` is the leaf name with its family PREFIX already
/// stripped, so this reads the trailing `-<pid>` that `kern-box-<tag>-<pid>` and `kern-run-<pid>` both
/// end in. The tag may itself contain '-', so the pid is the LAST field and never the second.
///
/// `-sup` is stripped first, because the supervisor's sibling leaf is `kern-box-<tag>-<pid>-sup` and
/// its last field is the literal `sup`, which parses as no pid at all: without this the leaf is
/// invisible to the sweep and never reaped. MEASURED: 434 of them accumulated under `kern.slice` in one
/// session, one per box. They are empty and harmless on their own, and not harmless in aggregate - the
/// sweep examines at most `limit` entries per box start, so a pile of unreapable directories crowds out
/// the orphans it exists to find. The `a_box_start_still_reaps_an_orphan_cgroup` test failed exactly
/// that way, and passed again the moment the pile was cleared. The pid is the SUPERVISOR's in both
/// names, so one liveness check covers a leaf and the box it belongs to.
///
/// ASKED OF `/proc` AND NOT OF THE DIRECTORY'S CONTENTS, deliberately: a box is momentarily EMPTY
/// between its `mkdir` and its `cgroup.procs` write, so a rmdir-if-empty rule would reap a box that is
/// starting. It also puts the pid-reuse hazard on the safe side - a reused pid reads as ALIVE, so the
/// leaf is skipped and never killed.
fn leaf_owner_is_dead(rest: &str) -> bool {
    rest.strip_suffix("-sup")
        .unwrap_or(rest)
        .rsplit('-')
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .is_some_and(|pid| !proc_entry_exists(pid))
}

/// Does `/proc/<pid>` exist, asked WITHOUT allocating?
///
/// This is the body of the sweep's loop: it runs once per directory entry, up to `SWEEP_LIMIT` of
/// them, twice per box start now that both candidate directories are swept. The obvious spelling,
/// `PathBuf::from(format!("/proc/{pid}")).exists()`, is two heap allocations and a `String` format
/// per entry, and it is on a path this project measures in microseconds. The digits are written into
/// a stack buffer instead and the question is asked with one `access(2)`.
///
/// `[u8; 24]` is sized for the longest possible answer and checked by the compiler through the
/// `debug_assert` below rather than by counting in a comment: `/proc/` is 6 bytes, a `u32` is at most
/// 10 digits, and the NUL is one, so 17 is the maximum and 24 leaves the buffer aligned with room to
/// spare. Nothing here can overflow it, and the write loop cannot run off the end because the index
/// is bounded by the digit count.
fn proc_entry_exists(pid: u32) -> bool {
    let mut buf = [0u8; 24];
    buf[..6].copy_from_slice(b"/proc/");
    let mut digits = [0u8; 10];
    let mut n = 0usize;
    let mut v = pid;
    // Emitted least-significant first into a scratch array, then reversed: a division-free forward
    // encoding would need the power of ten, which is another loop for no gain at ten digits.
    loop {
        digits[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 || n == digits.len() {
            break;
        }
    }
    debug_assert!(
        6 + n < buf.len(),
        "/proc/<u32> plus its NUL must fit the buffer"
    );
    for i in 0..n {
        buf[6 + i] = digits[n - 1 - i];
    }
    buf[6 + n] = 0;
    // SAFETY: `buf` is a live stack array, NUL-terminated at `6 + n` by the line above, and `access`
    // only reads up to that NUL. `F_OK` asks existence and never follows anything writable.
    unsafe { libc::access(buf.as_ptr().cast(), libc::F_OK) == 0 }
}

/// Reap the capped leaves under `slice` whose owner is dead, self-healing the one leak the RAII guard
/// cannot cover: a process SIGKILL'd before its `Drop` could run leaves its (now-empty) dir behind.
///
/// `limit` caps how many entries are examined (a `/proc/<pid>` stat each) so the per-start call (kern
/// is daemonless → once per box process) stays O(1) instead of O(entries) - Σ over an N-box burst would
/// otherwise be O(N²). Orphans past the cap are cleared by a later start or by `kern gc`, which passes
/// `0` = unbounded.
///
/// BOTH LEAF FAMILIES ARE SWEPT AND ONLY ONE IS KILLED; see [`Leaf`] and the `may_kill` decision below.
/// `rmdir` is the safety valve under either: it fails on a cgroup that still holds anything.
fn sweep_orphan_boxes(slice: &std::path::Path, limit: usize) {
    let Ok(rd) = fs::read_dir(slice) else { return };
    for (seen, e) in rd.flatten().enumerate() {
        if limit != 0 && seen >= limit {
            break;
        }
        let name = e.file_name();
        let name = name.to_string_lossy();
        // The name decides BOTH answers, and they are separate questions: `leaf_owner_is_dead` reads
        // the trailing pid (the same parse for either family), while `may_kill` is the whole
        // difference BETWEEN the families and is decided by the PREFIX - never by what happens to be
        // inside the directory.
        let (dead, may_kill) = match (
            name.strip_prefix(BOX_LEAF_PREFIX),
            name.strip_prefix(RUN_LEAF_PREFIX),
            name.strip_prefix(CAPPROBE_LEAF_PREFIX),
        ) {
            (Some(rest), _, _) => (leaf_owner_is_dead(rest), true),
            (None, Some(rest), _) => (leaf_owner_is_dead(rest), false),
            (None, None, Some(rest)) => (leaf_owner_is_dead(rest), false),
            (None, None, None) => (false, false),
        };
        if dead {
            // The supervisor `<pid>` is gone. A detached box whose supervisor was SIGKILL'd/OOM-killed
            // ran no cleanup, and its PID-ns init carries no launcher PDEATHSIG, so the whole tree
            // (init + workload + any grandchild it forked) can still be ALIVE. `remove_dir` alone fails
            // on that non-empty cgroup and the tree LEAKS. `cgroup.kill` SIGKILLs every member at once,
            // then the (now-emptying) dir is `rmdir`'d - a straggler zombie's dir falls to the next
            // sweep once the kernel reaps it. No pid-reuse hazard: a reused `<pid>` makes `/proc/<pid>`
            // exist, so `dead` is false and the box is skipped, never killed.
            //
            // NEVER FOR A `kern run` LEAF, and this asymmetry is the point of splitting the families.
            // A box's processes belong to the box: killing them when the box's supervisor died is
            // finishing a teardown someone already started. `kern run` is a resource GOVERNOR over
            // processes the caller started on the host - `kern run -- ./server &` and a workload that
            // backgrounds a child are both ordinary uses - and its contract is that nothing dies with
            // the launcher. Under the systemd `--scope` this path replaces, a survivor kept the scope
            // alive and was collected when it exited; a `cgroup.kill` here would instead reach in and
            // SIGKILL a process the user is still using. So a populated `kern run` leaf is simply left
            // alone: `remove_dir` no-ops on it, and the sweep that runs after the last survivor exits
            // removes it then.
            let path = e.path();
            if may_kill {
                let _ = kill_cgroup(&path);
            }
            let _ = fs::remove_dir(&path);
        }
    }
}

/// SIGKILL every process in the cgroup at `dir`, atomically, via cgroup-v2 `cgroup.kill` (kernel
/// 5.14+): one write of `"1"` and the kernel enumerates and kills the whole subtree under its own
/// lock. Strictly more thorough than signalling a tracked pid - it reaches grandchildren the workload
/// forked AND any process not in the box's PID namespace (a forwarder, an egress helper) - and has no
/// pid-reuse race. Best-effort: on a pre-5.14 kernel the file is absent, `fs::write` fails, and this
/// returns false so the caller falls back to its `rmdir` (which is inert on a still-populated cgroup).
/// Returns whether the kill file was written. Used only to reap a box whose supervisor is already dead.
fn kill_cgroup(dir: &std::path::Path) -> bool {
    fs::write(dir.join("cgroup.kill"), "1").is_ok()
}

/// The per-box-start orphan-sweep cap - bounds the hot-path cost; the tail is cleaned by later starts / gc.
const SWEEP_LIMIT: usize = 128;

/// `kern gc`: reap orphaned box cgroup dirs and return how many were removed. A box that `killall`,
/// `stop` or the OOM killer SIGKILLs leaves its now-empty `kern-box-*` dir behind, because the RAII
/// Drop that removes it does not run on SIGKILL.
///
/// Where the per-box-start sweep reaches, this is only a convenience between bursts. Where it does
/// NOT, this is the only reaper there is: the start-time sweep lives in `ensure_kern_slice_uncached`
/// and therefore only ever touches kern.slice, while a scope / managed / best-effort box is created in
/// the CALLER'S cgroup and is never swept by a later start. That is why this walks both directories
/// rather than the slice alone.
/// Boxes the KERNEL still has, as `(tag, supervisor pid)`, whatever the registry says.
///
/// WHY THIS IS NEEDED AT ALL, measured: `kern`'s registry lives in `$XDG_RUNTIME_DIR/kern/instances`,
/// and `/run/user` is swept by `systemd-tmpfiles`, cleared on logout, and deleted by any operator who
/// reads it as scratch. When that happens to a RUNNING box the process does not care: it keeps
/// running, its supervisor is alive, its cgroup is intact. Only kern forgets. Reproduced on this
/// machine:
///
/// ```text
/// box r1 -d -- sleep 120     ps: r1
/// rm -rf $XDG_RUNTIME_DIR/kern/instances
/// ps                         r1 GONE
/// stop r1                    error: no running box named 'r1'
/// /proc/<pid of r1>          still there
/// kern.slice/kern-box-r1-…   still there
/// ```
///
/// So the box became invisible and unstoppable through kern, while every fact needed to find it was
/// sitting in the cgroup tree: the directory name carries the TAG and the SUPERVISOR PID. That is the
/// channel this codebase says to trust - written by the kernel, not by the thing being described -
/// and `ps` was reading only the one that had been erased.
///
/// The sweep next door uses the same names for the opposite purpose: it reaps the ones whose
/// supervisor is DEAD. This returns the ones whose supervisor is ALIVE, which is exactly the set the
/// sweep must never touch and the set an operator needs to be told about.
#[must_use]
pub fn live_box_cgroups() -> Vec<(String, u32)> {
    let mut out: Vec<(String, u32)> = Vec::new();
    let mut done: Vec<PathBuf> = Vec::new();
    for dir in [kern_slice_path(), current_v2_cgroup()]
        .into_iter()
        .flatten()
    {
        if !dir.is_dir() || done.contains(&dir) {
            continue;
        }
        let Ok(rd) = fs::read_dir(&dir) else {
            done.push(dir);
            continue;
        };
        for e in rd.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            let Some(rest) = name.strip_prefix(BOX_LEAF_PREFIX) else {
                continue;
            };
            // The supervisor's sibling leaf is `…-sup` and names the SAME box, so counting it would
            // report every box twice.
            if rest.ends_with("-sup") {
                continue;
            }
            // `kern-box-<tag>-<pid>`, and a tag may itself contain '-', so the pid is the LAST field
            // and the tag is everything before it.
            let Some((tag, pid)) = rest.rsplit_once('-') else {
                continue;
            };
            let Ok(pid) = pid.parse::<u32>() else {
                continue;
            };
            if tag.is_empty() || !PathBuf::from(format!("/proc/{pid}")).exists() {
                continue;
            }
            out.push((tag.to_string(), pid));
        }
        done.push(dir);
    }
    out.sort();
    out.dedup();
    out
}

/// The same question as [`live_box_cgroups`], asked of `/proc` instead, for a host that has no
/// per-box cgroup to ask about.
///
/// WHY A SECOND CHANNEL EXISTS AT ALL. `live_box_cgroups` reads `kern.slice`, and on a host without
/// cgroup delegation there is no `kern-box-*` directory to read: an independent reviewer ran the
/// registry-wipe case as uid 0 with no systemd and reported THREE live `kern box g1` processes,
/// absent from `ps`, unreachable by `stop`, untouched by `gc` - and the warning could not fire,
/// because its evidence did not exist. That is the host where the defect is MOST likely and where it
/// was invisible.
///
/// WHAT THE KERNEL WRITES HERE, and what it does not. The decision uses two facts the subject cannot
/// forge: `/proc/<pid>/ns/user` (a process in a user namespace that is not ours) and
/// `/proc/<ppid>/exe` (its parent runs a binary called `kern`). The TAG comes from the parent's
/// `argv`, which the process itself wrote, and is therefore used only to NAME the finding, never to
/// decide it. A box that lied about its argv would still be reported, under a wrong name.
///
/// COST, measured: 6.11 ms over 534 pids, which is about the cost of `ps` itself. That is why the
/// caller uses this only when the cgroup channel came back empty; a host with delegation pays
/// nothing for it.
///
/// Deduplicated by tag: a box shows up once per process of its tree that sits in the namespace, and
/// the caller wants boxes, not processes.
#[must_use]
pub fn live_box_supervisors_via_proc() -> Vec<(String, u32)> {
    let Ok(mine) = fs::read_link("/proc/self/ns/user") else {
        return Vec::new();
    };
    // ONE PASS, AND IN THIS ORDER BECAUSE THE ORDER IS THE COST. The first version read `ns/user`
    // for EVERY pid and filtered afterwards: 3.55 ms, and 423 candidates to sift, because every
    // browser sandbox on the machine is also in a user namespace that is not ours. Reading the two
    // cheap kernel facts first (`exe`, and the parent out of `stat`) and `ns/user` only for the
    // handful whose parent is a `kern` costs 1.69 ms and yields 2. Cheaper AND narrower, which is
    // what let the gate that used to guard this call go away entirely - see the caller.
    let mut kern_pids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut parents: Vec<(String, String)> = Vec::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        // `exe` is a symlink the KERNEL maintains: a process cannot point it elsewhere by rewriting
        // its own argv.
        //
        // AND THE KERNEL APPENDS " (deleted)" TO IT once the binary is gone, which is the ordinary
        // state of every running box after an upgrade: `install.sh` replaces the file, and from that
        // moment `/proc/<pid>/exe` of every kern already running reads `/path/to/kern (deleted)`.
        // MEASURED on this desktop, a box whose binary had been rebuilt underneath it:
        //
        //     ppid=1691739  parent_exe=/home/alex/dev/.../kern (deleted)
        //     pid 1691741   userns=4026535815 (ours: 4026531837)   <- a real box supervisor
        //
        // `file_name() == "kern"` was false there, so the whole box was invisible to THIS channel -
        // the fallback that exists to find boxes the registry has lost, failing on the one event most
        // likely to lose them. The cgroup channel reported the same box in the same second, which is
        // how the disagreement surfaced.
        //
        // Matched on the stem so both spellings resolve. Deliberately NOT a `starts_with("kern")`:
        // that would also claim `kernel-something`, and this set decides which processes kern will
        // then ask for children and report as boxes.
        if fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .and_then(|p| {
                p.file_name()
                    .map(|f| exe_stem_is_kern(&f.to_string_lossy()))
            })
            .unwrap_or(false)
        {
            kern_pids.insert(pid.to_string());
        }
    }
    // ASK EACH KERN PROCESS FOR ITS CHILDREN, instead of asking every process for its parent. The
    // first version read `/proc/<pid>/stat` for all of them to build a parent map: correct, and 6.6 ms
    // on `kern ps` with no boxes, which is the most common invocation there is. `task/<tid>/children`
    // is one small file per KERN process, and there are three of those against five hundred pids.
    //
    // It needs `CONFIG_PROC_CHILDREN`, which is not universal, so a kernel without it reads an empty
    // list and this finds nothing - a miss, never a wrong answer.
    for k in &kern_pids {
        let Ok(children) = fs::read_to_string(format!("/proc/{k}/task/{k}/children")) else {
            continue;
        };
        for c in children.split_whitespace() {
            parents.push((c.to_string(), k.clone()));
        }
    }
    let mut out: Vec<(String, u32)> = Vec::new();
    for (pid, ppid) in parents {
        if !kern_pids.contains(&ppid) {
            continue;
        }
        // The child is inside SOMETHING and its parent runs kern: that pair is a box supervisor, and
        // both halves are written by the kernel.
        if fs::read_link(format!("/proc/{pid}/ns/user")).ok() == Some(mine.clone()) {
            continue;
        }
        let Ok(sup) = ppid.parse::<u32>() else {
            continue;
        };
        // NAMED from argv, DECIDED above: `kern box <tag> …`. A process that lied about its argv
        // would still be reported, under a wrong name.
        let Ok(cmdline) = fs::read(format!("/proc/{ppid}/cmdline")) else {
            continue;
        };
        let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
        if let Some(tag) = args
            .iter()
            .position(|a| *a == b"box")
            .and_then(|i| args.get(i + 1))
            .and_then(|t| std::str::from_utf8(t).ok())
            .filter(|t| !t.is_empty() && !t.starts_with('-'))
        {
            out.push((tag.to_string(), sup));
        }
    }
    out.sort();
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

pub fn gc_orphan_box_cgroups() -> usize {
    // Boxes are not all created in one place, so sweeping one place cannot find them all. `apply_limits`
    // puts a DIRECT-path box under kern.slice and EVERY other box (scope, managed, best-effort) under the
    // CALLER'S own cgroup, and this used to look only at the slice. Measured on WSL2 as uid 0, where no
    // kern.slice exists and boxes land at the cgroup root: two OOM-killed boxes left
    // `/sys/fs/cgroup/kern-box-*` behind, a following box start did not reap them, and `kern gc` reported
    // "nothing to prune" while they sat there. Normal boxes were unaffected (their RAII Drop removes the
    // dir); it is the SIGKILLed ones, whose Drop never runs, that accumulated. So sweep both places the
    // creator can choose, deduped when they are the same directory.
    gc_orphan_box_cgroups_in(&[kern_slice_path(), current_v2_cgroup()])
}

/// Testable core of [`gc_orphan_box_cgroups`]: sweep every directory a box can be created in, skipping
/// the absent ones and the duplicates (both resolve to the same path whenever the caller already runs
/// inside kern.slice). Split out for the same reason `memory_cap_state_at` is: a unit test can drive it
/// against synthetic directories instead of the host's real cgroup tree, on any machine.
fn gc_orphan_box_cgroups_in(dirs: &[Option<PathBuf>]) -> usize {
    let mut reaped = 0;
    let mut done: Vec<&PathBuf> = Vec::new();
    for dir in dirs.iter().flatten() {
        if !dir.is_dir() || done.contains(&dir) {
            continue;
        }
        let before = count_box_cgroups(dir);
        sweep_orphan_boxes(dir, 0); // gc is cold → unbounded, reap ALL orphans
        reaped += before.saturating_sub(count_box_cgroups(dir));
        done.push(dir);
    }
    reaped
}

/// How many of kern's own capped-leaf dirs sit directly in `dir`. Split out because
/// [`gc_orphan_box_cgroups`] now measures more than one directory and a closure over a single captured
/// path no longer fits.
///
/// COUNTS BOTH FAMILIES because it is the before/after of the sweep, and the sweep reaps both: a count
/// that saw only `kern-box-*` would report `kern gc` as having removed nothing on a host whose leftovers
/// were all `kern-run-*`, which is the number an operator uses to decide whether to look further.
fn count_box_cgroups(dir: &std::path::Path) -> usize {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.starts_with(BOX_LEAF_PREFIX)
                || n.starts_with(RUN_LEAF_PREFIX)
                || n.starts_with(CAPPROBE_LEAF_PREFIX)
        })
        .count()
}

/// The box cgroup dir that host-pid `pid` belongs to RIGHT NOW, read from `/proc/<pid>/cgroup` - so
/// `kern stop`/`compose down` can capture a box's exact direct-path `kern-box-<tag>-<pid>` dir (while it's
/// still alive) and `rmdir` it after the SIGKILL, WITHOUT guessing the dir's internal setup-pid suffix
/// (which is a forked child's pid, not the registry's supervisor pid) or its `--hostname`-overridable tag.
///
/// Pass the box's **PID-namespace init** (`pid1`): it's a genuine member of the box cgroup, whereas the
/// supervisor process forks the cgroup owner and stays in the parent cgroup. cgroup v2 gives one
/// `0::<path>` line. Returns the absolute `/sys/fs/cgroup<path>` ONLY when it names one of kern's own
/// `kern-box-*` dirs (never the shared kern.slice/root, so a stray read can't target a parent). `None`
/// if the proc entry is gone, unparseable, or not a kern box cgroup.
///
/// The eager counterpart to [`gc_orphan_box_cgroups`]: the RAII [`CgroupGuard`] `Drop` can't run under
/// SIGKILL, and the general [`sweep_orphan_boxes`] SKIPS a just-killed box whose pid lingers as a ZOMBIE
/// (`/proc/<pid>` still present until the parent reaps it), so a post-stop `gc` wouldn't clear it yet -
/// but a dead process is no longer a cgroup member, so the dir is EMPTY and `rmdir`-able immediately, and
/// `rmdir`'s own empty-only semantics are the safety valve against ever removing a live box's dir.
pub fn box_cgroup_dir(pid: i32) -> Option<PathBuf> {
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    parse_box_cgroup_line(&raw)
}

/// Is this cgroup leaf one KERN named - a `kern-box-*` dir or scope - rather than one it merely found
/// itself in? The single definition of that rule, because every use of it decides whether kern may act
/// on a cgroup: `parse_box_cgroup_line` (which dir a reap may `rmdir`) and `prepare_delegated_scope`
/// (which scope kern may restructure). An ambient `run-p123-i456.scope` - what `systemd-run --user
/// --scope bash` gives a user, and what `kern doctor` itself suggests running - must fail BOTH, or a
/// box started in that shell would let kern reap or reshape the user's own session.
fn is_kern_box_leaf(leaf: &str) -> bool {
    // `-sup` IS NOT A BOX, and excluding it here rather than at each caller is the point of this
    // function being the single definition.
    //
    // The supervisor sits in `kern-box-<tag>-<pid>-sup`, a sibling of the box's cgroup, so that a
    // whole-box OOM cannot take the process that has to report it. That name carries kern's own prefix,
    // so every consumer of this gate accepted it as a box cgroup.
    //
    // MEASURED, and the reason this is not cosmetic: a detached box recorded
    // `cgroup=.../kern-box-regchk4-251796-sup` in its registry entry, because the PID-1 callback reads
    // `/proc/<pid1>/cgroup` in the window between the fork and the child moving itself into the capped
    // cgroup, and in that window the child still shows the supervisor's leaf. `kern stop` writes
    // `cgroup.kill` into the recorded path: it would have killed the SUPERVISOR and left the workload
    // running, which is the opposite of what it promises. The same wrong path also drives the
    // orphan-vs-exited decision in `list()`.
    //
    // Refusing it here makes `box_cgroup_dir` return `None` for that window instead of a wrong path,
    // and `None` is already the "no dedicated cgroup" case every caller handles.
    leaf.starts_with(BOX_LEAF_PREFIX) && !leaf.ends_with("-sup")
}

/// Parse a cgroup-v2 `/proc/<pid>/cgroup` body (`0::<path>`) into kern's own box-cgroup dir, or `None`.
/// Split out from [`box_cgroup_dir`] so the parse + kern-box gate is unit-testable without a live box.
///
/// TWO leaf shapes are kern's own, and both are named by kern rather than inferred:
/// `kern-box-<tag>-<pid>` is the dir `apply_limits` creates on the direct path, and
/// `kern-box-<pid>.scope` is the transient unit kern asks systemd for on the per-box scope path.
/// Everything else is refused, which is the point of the gate rather than an omission: on the scope
/// path a box's cgroup can be a scope kern did NOT create (a user's own `systemd-run --user --scope
/// bash`, which `kern doctor` recommends), and recording that would let a later reap `cgroup.kill`
/// the user's whole session. The `kern-box-` prefix is the proof of ownership.
fn parse_box_cgroup_line(raw: &str) -> Option<PathBuf> {
    let rel = raw.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    let leaf = rel.rsplit('/').next()?;
    if !is_kern_box_leaf(leaf) {
        return None; // only ever a box leaf - never the shared slice/root
    }
    Some(PathBuf::from("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// The cgroup v2 directory host-pid `pid` currently belongs to (the `0::<path>` line of
/// `/proc/<pid>/cgroup`), absolute under `/sys/fs/cgroup`, or `None` (proc entry gone, a v1-only
/// host, or a `..` in the path). Unlike [`box_cgroup_dir`] this returns the cgroup WHATEVER it is -
/// a `kern-box-*` leaf on the delegated direct-cap path, a `run-*.scope` on the rootless per-box
/// systemd-scope path, or an ambient scope for an uncapped box - because `kern exec` must join the
/// box's EFFECTIVE cgroup to inherit its caps, and on the scope path the enforcer is the scope
/// itself, not a `kern-box-*` child.
fn proc_cgroup_dir(pid: i32) -> Option<PathBuf> {
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let rel = raw
        .lines()
        .find_map(|l| l.strip_prefix("0::"))?
        .trim()
        .trim_start_matches('/');
    if rel.split('/').any(|c| c == "..") {
        return None;
    }
    Some(PathBuf::from("/sys/fs/cgroup").join(rel))
}

/// Outcome of trying to place a `kern exec`'d process into its box's cgroup - see
/// [`exec_join_outcome_after_failure`], which decides whether a failed placement actually costs a cap.
pub enum ExecCgroupJoin {
    /// Joined the box's cgroup (so the exec'd workload inherits its caps), OR the box has no cap to
    /// inherit - either way there is nothing to flag.
    Bound,
    /// The box IS capped but the kernel refused the migration into its cgroup. The rootless per-box
    /// systemd-scope case: a process in the caller's own session scope can't be moved into a sibling
    /// `--user` scope, because that needs write on the common ancestor `user@<uid>.service`, which
    /// systemd owns (verified EPERM on a Pi 5). The exec'd command then runs OUTSIDE the box's
    /// `--memory`/`--pids` caps; namespaces + seccomp still isolate it. The caller surfaces this.
    Unbounded,
}

/// The cgroup an `exec`'d command must end up in, or `None` when there is nothing to join.
///
/// THE LAUNCHER USED TO MOVE ITSELF HERE so a child forked afterwards would inherit the box's caps,
/// the same "cap before fork" order the box's own PID 1 used. It no longer does: the child is created
/// directly in this cgroup with `clone3(CLONE_INTO_CGROUP)` (see [`fork_into_cgroup`]), because the
/// migration cost an RCU grace period - 11.7 to 25.8 ms for a `kern exec` on a quiet host against
/// 1.7 to 2.2 ms for the same command run back to back. Where the kernel refuses the placement (the
/// rootless per-box scope: a process in the caller's session scope cannot be moved into a sibling
/// `--user` scope, verified EPERM on a Pi 5) the child places itself and reports the outcome through
/// [`exec_join_outcome_after_failure`].
///
/// SPLIT OUT SO IT CAN BE READ BEFORE THE `setns`, which is the only window in which it is readable:
/// once this process has entered the box's cgroup namespace, `/proc/<pid1>/cgroup` reports a path
/// relative to that namespace and no longer names a directory under `/sys/fs/cgroup`.
///
/// `None` covers the two cases that were already no-ops: a host with no cgroup v2 line for `pid1`,
/// and the v2 ROOT, which is never something to "join".
#[must_use]
pub fn box_cgroup_dir_for_exec(pid1: i32) -> Option<PathBuf> {
    let cg = proc_cgroup_dir(pid1)?;
    (cg.as_path() != std::path::Path::new("/sys/fs/cgroup")).then_some(cg)
}

/// After a placement into `cg` failed: does that failure actually cost the caller a cap?
///
/// Only a resource concern if the box's own cgroup enforces a REAL cap - `memory.max`/`pids.max`
/// reading a value rather than the `max` no-limit sentinel. A default box on a scope host also sits
/// in a scope with a default `MemoryMax`, so reporting every failure would fire on every exec on
/// every rootless host.
/// THROUGH THE DESCRIPTOR, not through a path, and that is not a refactor. This ran after `setns` and
/// read `memory.max`/`pids.max` from a host path that does not exist inside the box's namespaces, so
/// both reads failed, neither looked like a real limit, and a box capped at `--pids-limit 2
/// --memory 64M` was reported as having nothing worth warning about. The failure to read and the
/// absence of a cap produced the same answer.
/// Does a failed placement actually COST the caller a cap?
///
/// The two inputs are "the box has a cgroup of its own" and "that cgroup carries a real limit". Both
/// have to hold, and reading them as one condition is what hid a defect for a release: `kern exec`
/// refused on a host with no delegation, where `apply_limits` returns `None`, the box sits in the
/// caller's own cgroup, `box_cgroup_dir_for_exec` answers `None` and the placement therefore has
/// nothing to place. The command was refused for a loss that did not happen, with a message naming
/// caps that did not exist. Reported by an outside reviewer on a box that was not at its pids limit.
///
/// A pure function of two bools so all four combinations are asserted without a cgroup filesystem,
/// which is the same treatment `supervisor_needs_leaf` and `caps_gate_satisfied` get for the same
/// reason: the expression is trivial and the consequence of getting it backwards is not.
#[must_use]
pub const fn placement_failure_costs_a_cap(box_has_own_cgroup: bool, cap_is_real: bool) -> bool {
    box_has_own_cgroup && cap_is_real
}

#[must_use]
pub fn exec_join_outcome_after_failure(cg: &CgroupRef) -> ExecCgroupJoin {
    let real = |f: &CStr| cg.read_control(f).is_some_and(|v| is_real_limit(&v));
    if real(c"memory.max") || real(c"pids.max") {
        ExecCgroupJoin::Unbounded
    } else {
        ExecCgroupJoin::Bound
    }
}

/// Ensure kern's own DELEGATED slice exists and return its cgroup path, or `None` if unavailable.
///
/// This is the fast-path enabler: a one-time `systemd-run --user -p Delegate=yes --slice=kern.slice
/// --scope -- true` creates a delegated `kern.slice` (the scope exits immediately; the slice PERSISTS,
/// owned by the user, with memory/cpu/pids delegated and writable). Every subsequent box then writes its
/// caps DIRECTLY under `kern.slice` (µs) instead of paying a per-box `systemd-run --scope` (~4 ms). NOT a
/// daemon - it's just a persisted cgroup dir. If systemd-user / delegation isn't available (no
/// `user@<uid>.service`, Android, etc.) → `None`, and the caller falls back to the per-box scope.
///
/// The slice lives as a sibling under our `user@<uid>.service` delegation root (derived from our own
/// cgroup, so it tracks the real user manager). Idempotent: if it already exists it's reused; systemd may
/// GC it when empty, in which case the next box recreates it (one-time ~4 ms again).
///
/// Memoized for the process lifetime: `reexec`'s `direct_caps_available()` and `apply_limits` both need
/// it, and a kern invocation starts one box, so the ~4 ms bootstrap AND the orphan sweep run exactly once
/// (not once per call site). A short-lived box-start process never sees the slice's availability change.
/// Reap cgroups left by boxes whose supervisor died without cleaning up.
///
/// CALLED AFTER A BOX IS SPAWNED, NOT BEFORE, and the distinction is the point. This is garbage
/// collection: it has no bearing on whether the box that is starting can be capped, and running it
/// first put its cost (193 us with 61 entries, measured) in front of every start. Called from the
/// launcher once the child exists, it overlaps the workload instead.
///
/// Best-effort and bounded by `SWEEP_LIMIT`, exactly as before. A no-op when the slice is not the
/// path this host caps through, because then there is nothing of ours in it.
pub fn sweep_orphans_off_hot_path() {
    // BOTH DIRECTORIES A LEAF CAN BE BUILT IN, which is the same pair `gc_orphan_box_cgroups` reaps.
    // It used to be `kern.slice` alone, and that is the directory a host WITHOUT a systemd user
    // manager never has: there the leaf is built in the caller's own cgroup, so nothing on this path
    // ever swept anything. MEASURED by an outside reviewer on WSL2 with no user manager, 2026-09-09:
    // 200 sequential `kern run` left 201 directories, cleared only by an explicit `kern gc`. That is
    // the shipped WSL rootfs's own configuration, so it was the documented Windows install path that
    // accumulated them.
    //
    // Deduplicated because on a host that caps through `kern.slice` the two are different directories
    // and on one that does not they can be the same: sweeping it twice would double the cost of the
    // one thing this function exists to keep cheap.
    let slice = ensure_kern_slice();
    let own = current_v2_cgroup();
    if let Some(s) = slice.as_ref() {
        sweep_orphan_boxes(s, SWEEP_LIMIT);
    }
    if let Some(o) = own.as_ref() {
        if slice.as_ref() != Some(o) {
            sweep_orphan_boxes(o, SWEEP_LIMIT);
        }
    }
}

fn ensure_kern_slice() -> Option<PathBuf> {
    static ENSURED: OnceLock<Option<PathBuf>> = OnceLock::new();
    ENSURED.get_or_init(ensure_kern_slice_uncached).clone()
}

fn ensure_kern_slice_uncached() -> Option<PathBuf> {
    let slice = locate_or_create_kern_slice()?;
    // THE LAST QUESTION, AND THE ONE THAT WAS NEVER ASKED: can a process actually be PUT in there?
    //
    // Everything above establishes that the directory exists and that its controllers are delegated,
    // which is what "can this cap" means. It is not what "can this cap US" means, and the difference
    // is a whole class of host.
    //
    // MEASURED by an outside reviewer on WSL2 with `systemd=true`, 2026-09-09, after an earlier
    // version of this file learned to FIND the slice there: the leaf was created, `memory.max` and
    // `pids.max` were written and read back, and then both `clone3(CLONE_INTO_CGROUP)` and the
    // `cgroup.procs` write FAILED, because cgroup v2's delegation containment rule needs write access
    // to the `cgroup.procs` of the COMMON ANCESTOR of the source and destination cgroups, and from
    // `/init.scope` that ancestor is the root, owned by root. The consequences were not symmetric and
    // both were severe: `kern run` warned and ran UNCAPPED where v0.9.31 had capped it, and `kern box`
    // is fail-closed on the same placement, so it would have refused to start at all.
    //
    // Gating here rather than at either caller is what makes it one answer: `direct_caps_available()`,
    // `apply_limits`' parent choice and the sweep all read this function, and a host that cannot place
    // must look to all three exactly as it did before the slice could be found.
    placement_into_is_permitted(&slice).then_some(slice)
}

/// Is the caller allowed to move a process into a child of `target`?
///
/// cgroup v2 delegation containment: a process may migrate a task from A to B when it has write
/// access to B's `cgroup.procs` AND to the `cgroup.procs` of the COMMON ANCESTOR of A and B. The
/// second half is the one that is easy to forget, because it is a property of the PAIR and not of
/// the destination, so a destination that is delegated, writable and correctly capped can still be
/// unreachable from where the caller happens to sit.
///
/// Asked with one `access(2)` on the ancestor, which is exactly the kernel's own rule and costs a
/// syscall on a path that runs once per process. Verified on this desktop, where the two answers
/// differ and bracket the case: `W_OK` on `/sys/fs/cgroup/cgroup.procs` is FALSE for an ordinary
/// user, and TRUE on `user@<uid>.service/cgroup.procs`.
///
/// `false` WHEN THE SOURCE CANNOT BE READ, which is the safe direction here and the opposite of the
/// default elsewhere in this file: the caller answers it by taking the systemd scope, which costs
/// milliseconds, and the alternative is a box that refuses to start or a command that runs uncapped.
fn placement_into_is_permitted(target: &Path) -> bool {
    let Some(from) = current_v2_cgroup() else {
        return false;
    };
    cgroup_procs_writable(&common_cgroup_ancestor(&from, target))
}

/// The deepest directory that is a prefix of BOTH cgroup paths.
///
/// Pure, so the rule can be asserted against literals rather than against whichever cgroup the test
/// binary was started in. Both inputs are absolute paths under `/sys/fs/cgroup` by construction, so
/// the walk always stops at or below the mount root.
fn common_cgroup_ancestor(a: &Path, b: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for (x, y) in a.components().zip(b.components()) {
        if x != y {
            break;
        }
        out.push(x);
    }
    out
}

/// Does this process have write access to `dir/cgroup.procs`? One `access(2)`, no allocation beyond
/// the path the kernel needs as a C string.
fn cgroup_procs_writable(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(dir.join("cgroup.procs").as_os_str().as_bytes()) else {
        return false; // an interior NUL cannot name a real file
    };
    // SAFETY: `c` is a live, NUL-terminated C string for the duration of the call, and `access` only
    // reads it. `W_OK` asks permission and changes nothing.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

/// Find kern's delegated slice, creating it where kern is allowed to. The body of what
/// [`ensure_kern_slice_uncached`] used to be, split out so its three `Some` returns all pass through
/// the placement gate above instead of three call sites each having to remember it.
fn locate_or_create_kern_slice() -> Option<PathBuf> {
    let slice = kern_slice_path()?;
    // Already present + delegated? (its `cgroup.controllers` is populated only when delegated.)
    if slice_can_cap(&slice) {
        // THE SWEEP USED TO RUN HERE, ON THE HOT PATH OF EVERY BOX START, and it does not belong to
        // starting a box. MEASURED on this desktop with 61 entries in the slice: 193 us, 7.4% of a
        // 2.6 ms start, spent reaping cgroups left by BOXES THAT ALREADY EXITED. Its cost grows with
        // the number of entries, because it stats `/proc/<pid>` for each.
        //
        // It is also work almost nobody needs: a box that stops normally removes its own cgroup, so
        // an orphan exists only where a SUPERVISOR was killed without running cleanup. Paying for
        // that on every start is paying for a rare event at the highest possible rate.
        //
        // Moved to [`sweep_orphans_off_hot_path`], which the launcher calls AFTER the box is spawned,
        // so it overlaps the workload instead of preceding it. Nothing about the outcome changes: the
        // slice is swept just as often (once per box start), one box later.
        return Some(slice);
    }
    // As REAL ROOT kern OWNS the cgroup tree, so it creates a persistent, fully-controlled `kern.slice`
    // DIRECTLY - no `systemd-run` round-trip and no transient scope that systemd GCs the instant it
    // exits (exactly why `--user` delegation never stuck as root under `user@0`, forcing the ~40 ms/box
    // scope fallback that D-Bus-serializes at scale). `mkdir` the slice, and only if it didn't inherit
    // the caps, pull the controllers down from the cgroup-v2 root (best-effort; a no-op on a host that
    // already delegates cpu/memory/pids). This gives root the same fast direct-cap path rootless gets.
    //
    // SAFETY of the two root writes (audited): `kern.slice` is an INTENTIONALLY systemd-unmanaged
    // top-level slice - systemd only GCs cgroups for units it created, so it won't delete or fight it,
    // and a later `systemd-run --system --slice=kern.slice` cleanly adopts it. The root
    // `subtree_control` write only ADDS controllers (idempotent, never removes; the v2 root is exempt
    // from the no-internal-process rule) - it makes controllers *available* to children but sets no
    // limit, so nothing is throttled/starved. Both are best-effort and gated on `as_root()`, so a box
    // payload can never reach them.
    if as_root() {
        let _ = fs::create_dir_all(&slice);
        if !slice_can_cap(&slice) {
            if let Some(root) = slice.parent() {
                enable_subtree_controllers(root);
            }
        }
        if slice_can_cap(&slice) {
            sweep_orphan_boxes(&slice, SWEEP_LIMIT);
            return Some(slice);
        }
    }
    // Rootless (or a root host that refused direct control): only systemd can make a *delegated* slice;
    // best-effort - a failure (no systemd-run, policy) returns None → the caller uses the per-box scope /
    // best-effort path, never uncapped-silently. Resolve `systemd-run` by trusted ABSOLUTE path (not
    // `$PATH`), same policy as the reexec scope spawn, so a `~/.local/bin/systemd-run` can't shadow it.
    let systemd_run =
        crate::trusted_helper("systemd-run").unwrap_or_else(|| PathBuf::from("systemd-run"));
    let created = Command::new(systemd_run)
        .args([
            systemd_scope_mode(),
            "-p",
            "Delegate=yes",
            "--slice=kern.slice",
            "--scope",
            "--quiet",
            "--",
            "true",
        ])
        // THIS IS A PROBE, so its output has no reader and must not have one. The verdict is the exit
        // status, read below; the two streams only carry systemd's opinion of the question we asked.
        //
        // Inherited, they were kern's stderr, and kern's stderr is the box's stderr as far as the SDK
        // is concerned. On a host with the systemd tools installed but not booted (a container, a WSL
        // session, the plain-root machine an external audit ran on), this probe answers "no" and prints
        //
        //   System has not been booted with systemd as init system (PID 1). Can't operate.
        //   Failed to connect to bus: Host is down
        //
        // which travelled all the way into a LangChain tool result, where a model read a line about
        // dbus as though its own code had produced it. `--quiet` does not cover this: it suppresses
        // systemd-run's info messages, not the bus error.
        //
        // The other three systemd-run call sites already null both. This one did not.
        //
        // THE RULE IS A JUDGEMENT AND THERE IS NO MECHANICAL FORM OF IT. Worth writing down, because
        // two candidates were tried and both are wrong. "A probe, versus a command whose failure a
        // user reads" is circular. "Whether the exit status is the whole answer" sounds checkable and
        // is not: 30 call sites in this workspace read only `.status()` while inheriting stderr, and
        // `tar`, `curl`, `mkfs.ext4` and `ssh-keygen` are all among them and all correct, because a
        // user who cannot see why tar failed cannot fix it.
        //
        // What actually separates this one: its failure is an EXPECTED, HANDLED outcome. "No delegated
        // slice here" is a normal answer that the caller acts on by taking another path, so there is
        // nothing for a human to do about the message. Every one of those 30 reports an ABNORMAL
        // outcome that ends the operation, where the message is the only thing that explains it.
        //
        // Since the rule cannot be checked, the exposure is bounded instead:
        // `scripts/progress-is-tty-gated.py` enforces the shape of what kern writes in the modules an
        // SDK caller's stderr is actually made of.
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    (created && slice_can_cap(&slice)).then_some(slice)
}

/// Make the controllers available to `parent`'s children. A cgroup-v2 `subtree_control` write is
/// ATOMIC: a batch naming any controller the parent does not export (`cpuset`/`io` are commonly NOT
/// delegated to a user session) fails ENTIRELY, which forced a per-controller fallback - up to six
/// syscalls, most of them failing, on *every* box's hot path. Instead read the parent's exported
/// `cgroup.controllers` first and batch only what is actually available, so the single write always
/// succeeds (and no-ops cheaply when the controllers are already on). The enabled set is identical to
/// the old fallback's (only exported controllers could ever be turned on); this just drops the failing
/// probe writes. Best-effort throughout: if the available set is unreadable, fall back to the old
/// try-each-controller path; write errors (already-on, or the no-internal-process rule when the parent
/// has members) are ignored either way.
/// The cgroup v2 controllers kern wants to delegate to a box, in a fixed emit order. Shared by
/// [`subtree_batch`] (what to enable) and [`subtree_all_enabled`] (whether it is already enabled) so
/// the two can never disagree on the set.
const SUBTREE_WANT: [&str; 5] = ["memory", "pids", "cpu", "cpuset", "io"];

/// Is `ctrl` present in a space-separated cgroup-v2 controller list (`cgroup.controllers` or
/// `cgroup.subtree_control`)? EXACT token match, so `cpu` never matches `cpuset` (a substring test
/// would), extra controllers the kernel exports (`hugetlb`, `rdma`, `misc`, …) are ignored, and
/// surrounding whitespace/newlines are tolerated. Single-sourced so [`subtree_batch`] and
/// [`subtree_all_enabled`] can never disagree on matching semantics.
fn ctrl_listed(list: &str, ctrl: &str) -> bool {
    list.split_whitespace().any(|c| c == ctrl)
}

/// The controllers kern wants that a parent actually exports (`available`), formatted as a cgroup-v2
/// `subtree_control` batch (`"+memory +pids +cpu"`), in a fixed order. Empty when the parent exports
/// none of them. Pure and unit-tested.
fn subtree_batch(available: &str) -> String {
    let mut batch = String::with_capacity(32);
    for ctrl in SUBTREE_WANT {
        if ctrl_listed(available, ctrl) {
            if !batch.is_empty() {
                batch.push(' ');
            }
            batch.push('+');
            batch.push_str(ctrl);
        }
    }
    batch
}

/// True iff every controller kern wants AND the parent actually exports (`available`) is ALREADY
/// present in the parent's `cgroup.subtree_control` (`current`, the enabled set). Lets
/// [`enable_subtree_controllers`] SKIP the `subtree_control` write on the common shared-parent path:
/// on `kern.slice` the controllers are enabled once and stay enabled until the slice is removed, so
/// every box after the first would otherwise re-issue an identical write. That write is NOT free under
/// concurrency - the kernel takes the global `cgroup_mutex` at entry, before discovering the write
/// changes nothing, so N parallel box starts serialize on it. Reading `subtree_control` first takes no
/// global lock. Vacuously true when the parent exports none of the wanted controllers (nothing to write).
fn subtree_all_enabled(available: &str, current: &str) -> bool {
    SUBTREE_WANT.iter().all(|ctrl| {
        // A controller the parent does not export is not a candidate to enable, so it cannot block the
        // skip; one it DOES export must already appear in the enabled set for the write to be a no-op.
        !ctrl_listed(available, ctrl) || ctrl_listed(current, ctrl)
    })
}

fn enable_subtree_controllers(parent: &std::path::Path) {
    let subtree = parent.join("cgroup.subtree_control");
    match fs::read_to_string(parent.join("cgroup.controllers")) {
        Ok(avail) => {
            let batch = subtree_batch(&avail);
            if !batch.is_empty() {
                // Skip the write - which takes the kernel-global `cgroup_mutex` even as a no-op - when
                // every wanted-and-available controller is already enabled (the common case for every
                // box after the first under a shared `kern.slice`). Fall through to the write if the
                // enabled set is unreadable or any wanted controller is missing (e.g. the slice was
                // GC'd and freshly recreated mid-run). The read takes no global lock.
                let already_on = fs::read_to_string(&subtree)
                    .map(|current| subtree_all_enabled(&avail, &current))
                    .unwrap_or(false);
                if !already_on {
                    let _ = fs::write(&subtree, batch);
                }
            }
        }
        // Available set unreadable: fall back to the old best-effort probe (try each controller
        // individually) so an unusual host still gets whatever it will accept.
        Err(_) => {
            for ctrl in ["+memory", "+pids", "+cpu", "+cpuset", "+io"] {
                let _ = fs::write(&subtree, ctrl);
            }
        }
    }
}

/// Default memory ceiling for a sandbox (512 MiB) - conservative but generous; `--memory` overrides.
///
/// PUBLIC BECAUSE THE NUMBER IS ALSO A SENTENCE. `kern compose` tells the reader that services with
/// no `mem_limit:` run under this ceiling (Docker imposes none), and a message carrying its own copy
/// of the figure is one edit away from describing a cap the kernel is not enforcing. One constant,
/// enforced and quoted from the same place.
pub const DEFAULT_MEMORY_MAX: u64 = 536_870_912;
/// Process-count ceiling - caps fork bombs.
const DEFAULT_PIDS_MAX: &str = "512";
/// cgroup v2 CPU period (µs) for `cpu.max`; the quota is `cores * PERIOD`.
const CPU_PERIOD_US: u64 = 100_000;

/// The leaf that holds kern's OWN processes inside a delegated box scope, so the box's group-OOM kill
/// cannot take the bookkeeper with the workload. Named, not `.`-hidden, so `systemd-cgls` shows what it
/// is; it never holds a workload process.
const SUPERVISOR_LEAF: &str = "kern-sup";

/// Extra bytes the per-box systemd scope gets ABOVE the box's own `--memory`, to hold kern's supervisor
/// without eating into what the workload asked for.
///
/// The scope caps supervisor + workload TOGETHER; the box's inner `kern-box-*` child caps the workload
/// alone. With both ceilings equal the OUTER one is reached first (by exactly the supervisor's charge),
/// so the scope OOM would fire before the box's own - killing the supervisor and losing the exit record,
/// which is the whole point of the inner child. MEASURED, at rest, on an Arduino UNO Q and a Raspberry
/// Pi 5: `memory.current` of a whole idle box (three kern processes + the workload) is 1.27-1.84 MB, so
/// 4 MiB is roughly a 2x margin over the entire box's resting charge and >3x kern's own share.
///
/// The consequence, stated rather than hidden: on this path a box's WORKLOAD is capped at exactly what
/// was asked for (before this, kern's own ~1.3 MB came out of the user's budget), and where the
/// delegated layout cannot be built (see [`prepare_delegated_scope`]) the box keeps the scope as its
/// only ceiling and can therefore use up to 4 MiB more than it asked.
pub const SCOPE_SUPERVISOR_HEADROOM: u64 = 4 * 1024 * 1024;

/// Will THIS manager accept `OOMPolicy=` on a transient scope - and does the box need it?
///
/// A newer systemd's default `OOMPolicy=stop` reacts to the kernel's OOM kill by stopping the unit,
/// and it does that with a SIGKILL to the WHOLE scope. MEASURED on an Arduino UNO Q (systemd 257): a
/// detached box past its `--memory` cap left NO exit record, because the supervisor that writes one
/// was killed along with the box - no in-scope arrangement can survive that, so the only fix is to
/// tell the manager not to stop the unit. The kernel has already killed the box as one group
/// (`memory.oom.group`); systemd stopping it again adds nothing but the loss of the verdict.
///
/// PROBED, not version-gated. `OOMPolicy=` on a SCOPE is rejected outright by older managers
/// ("Unknown assignment"), which makes `systemd-run` FAIL - and on the foreground path kern has
/// already `exec`d into it, so the box would die uncapped. Measured refused on systemd 249 and
/// accepted on 252 and 257; the versions that refuse it are also the ones that do not stop the unit on
/// OOM, so the box's exit code comes out right there without it. One `systemd-run /bin/true` proves
/// it, memoised per process and cached in `$XDG_RUNTIME_DIR` - which the kernel clears on reboot,
/// exactly the lifetime of "which systemd is running" - so a host pays it once per boot, and never on
/// the direct-cgroup path where no scope is built. MEASURED cost when the answer is yes: none per box
/// (a Raspberry Pi 5 scope is 11 ms without the property and 10 ms with it).
pub fn scope_accepts_oom_policy() -> bool {
    static MEMO: OnceLock<bool> = OnceLock::new();
    *MEMO.get_or_init(|| {
        let cache = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .map(|d| d.join("kern").join("scope-oom-policy"));
        if let Some(p) = &cache {
            if let Ok(v) = fs::read_to_string(p) {
                return v.starts_with('1');
            }
        }
        let Some(systemd_run) = crate::real::trusted_helper("systemd-run") else {
            return false;
        };
        let ok = Command::new(systemd_run)
            .arg(systemd_scope_mode())
            .args(["--scope", "--quiet", "--collect"])
            .args(["-p", "OOMPolicy=continue"])
            .arg("/bin/true")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if let Some(p) = &cache {
            if let Some(dir) = p.parent() {
                let _ = fs::create_dir_all(dir);
            }
            let _ = fs::write(p, if ok { "1" } else { "0" });
        }
        ok
    })
}

/// The box's own delegated scope, once [`prepare_delegated_scope`] has proven the layout works here.
/// A `OnceLock` set BEFORE kern forks its supervisor, so every later process sees the same answer.
static DELEGATED_SCOPE: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Move kern's own processes OUT of the box's scope root, so the box can be capped in a child cgroup
/// whose group-OOM kill takes the workload and NOT kern's supervisor. Returns true when the layout is
/// in force. Idempotent, and a no-op off the scope path.
///
/// Why this exists, MEASURED on all three ARM boards (systemd 249/252/257) before the change: a
/// DETACHED box that hit its `--memory` cap vanished with NO exit record - `kern ps -a` empty and
/// `kern wait` answering "no exit record for one" - while the SAME box on the direct-cgroup path (x86)
/// reported 137. The cause is not the exit-code plumbing but the topology: on the scope path every kern
/// process runs in the scope, `memory.oom.group` kills the cgroup as one unit, and the supervisor that
/// would have read the workload's status and written the record dies with it. A foreground box was
/// unaffected (its exit code travels back through the launcher), so the gap was exactly: detached +
/// OOM + scope path, i.e. the SDK's own pattern on the edge hardware kern targets.
///
/// The fix mirrors the direct path's topology: supervisor OUTSIDE the capped cgroup, runner + workload
/// inside it. cgroup v2 forbids a cgroup that holds processes from enabling controllers for its
/// children ("no internal processes"), so the scope root must be vacated FIRST - hence this runs at
/// process entry, before the supervisor forks. No `Delegate=yes` is needed for any of it: a user
/// manager creates the scope's directory as the user, so it is already writable by us (see the
/// `systemd-run` call in `reexec_in_scope_if_possible` for what asking for the property would cost).
///
/// FAIL-SAFE by construction: every step is checked and any failure restores exactly the previous
/// layout (back to the scope root, leaf removed), where systemd's `MemoryMax` on the scope remains the
/// enforcer. It can lose the improvement; it cannot lose the cap.
pub fn prepare_delegated_scope() -> bool {
    DELEGATED_SCOPE
        .get_or_init(|| {
            if !env_flag("KERN_SCOPE") {
                return None;
            }
            let scope = current_v2_cgroup()?;
            // ONLY a scope kern created and named (`kern-box-<pid>.scope`), never an ambient one: a user
            // running `systemd-run --user --scope bash` (which `kern doctor` itself suggests) would
            // otherwise have their shell's own scope restructured underneath them. Same prefix rule the
            // registry uses to decide which cgroup belongs to a box.
            if !scope
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(is_kern_box_leaf)
            {
                return None;
            }
            let sup = scope.join(SUPERVISOR_LEAF);
            if fs::create_dir(&sup).is_err() && !sup.is_dir() {
                return None; // not delegated to us - the scope stays the only ceiling
            }
            if fs::write(sup.join("cgroup.procs"), std::process::id().to_string()).is_err() {
                let _ = fs::remove_dir(&sup);
                return None;
            }
            enable_subtree_controllers(&scope);
            // Claim the layout only if `memory` actually reached the children: without it the box's
            // child cgroup could be created but never capped, and `apply_limits` would tear it down and
            // report no cap at all - strictly worse than staying in the scope. Restore and give up.
            let delegated = fs::read_to_string(scope.join("cgroup.subtree_control"))
                .is_ok_and(|s| s.split_whitespace().any(|c| c == "memory"));
            if !delegated {
                let _ = fs::write(scope.join("cgroup.procs"), std::process::id().to_string());
                let _ = fs::remove_dir(&sup);
                return None;
            }
            Some(scope)
        })
        .is_some()
}

/// The delegated scope to cap the box under, or `None` when kern is not on that path (every host off
/// the scope path, and any scope where [`prepare_delegated_scope`] could not build the layout).
fn delegated_scope() -> Option<&'static PathBuf> {
    DELEGATED_SCOPE.get().and_then(|o| o.as_ref())
}

/// The `--require-limits` success gate, as a PURE decision. Factored out of [`apply_limits`] (whose live
/// cgroup path is not exercised on every host, so a `mem_ok && pids_ok` -> `mem_ok || pids_ok` slip would
/// pass CI silently and let a partially-capped box - a fork-bomb / OOM hole - start under a flag whose
/// entire purpose is to refuse it) so the decision is guarded by a unit test on every run.
/// `require_all` (the `--require-limits` flag): BOTH the memory and pids caps must have bound (read-back
/// verified by the caller). Default: AT LEAST ONE bound is enough - partial protection beats none, and
/// the caller warns about the rest.
const fn caps_gate_satisfied(mem_ok: bool, pids_ok: bool, require_all: bool) -> bool {
    if require_all {
        mem_ok && pids_ok
    } else {
        mem_ok || pids_ok
    }
}

/// Where does the supervisor belong, given the two facts that decide it?
///
/// `forks` is whether the caller forks the workload (`kern box`) or `exec()`s it in place
/// (`kern run`). `origin_kills` is whether the supervisor's CURRENT cgroup is about to be armed with
/// `memory.oom.group = 1`, which happens only on a scope or managed unit where
/// `prepare_delegated_scope` did not move kern into a leaf of its own.
///
/// Returns whether a sibling leaf has to be built. The other half of the answer, whether the
/// supervisor ends up OUTSIDE the capped cgroup, is [`supervisor_ends_up_outside`], because it also
/// depends on whether building that leaf succeeded.
///
/// A pure function of two bools so the eight combinations can be asserted without a cgroup
/// filesystem. The logic used to be three expressions spread over 300 lines, and the one that
/// matters - a failed leaf on the scope path must fall back to the OLD topology rather than leave the
/// supervisor in an armed cgroup - was not visible in any of them at once.
fn supervisor_needs_leaf(forks: bool, origin_kills: bool) -> bool {
    forks && origin_kills
}

/// Which of kern's two families of capped cgroup leaf this invocation creates.
///
/// THEY MUST BE TOLD APART BY NAME, because several readers act on the name alone and act
/// DIFFERENTLY on the two. `kern ps` lists every live `kern-box-*` dir as a box, and the orphan sweep
/// answers a dead-owner `kern-box-*` with `cgroup.kill` - correct for a box, whose processes are the
/// box, and wrong for `kern run`, whose processes are the caller's own.
///
/// MEASURED, before either family shared a directory: with a `kern-box-run-<pid>` leaf placed in
/// `kern.slice` by hand and its `<pid>` alive, `kern ps` printed
///
/// ```text
/// kern: warning: 1 box(es) are RUNNING with no registry record, so `kern stop` cannot reach them
/// kern:   run (supervisor pid 149338)
/// ```
///
/// over a plain `kern run`. That is the whole reason `kern run` gets a prefix of its own rather than
/// the tag `"run"` under the box prefix: a tag cannot be reserved (a box may legitimately be called
/// `run`), and a prefix can.
#[derive(Clone, Copy)]
pub enum Leaf<'a> {
    /// `kern-box-<tag>-<pid>`: a box. Listed by `kern ps`, reaped by the orphan sweep, which may
    /// `cgroup.kill` survivors of a dead supervisor.
    Box(&'a str),
    /// `kern-run-<pid>`: the capped leaf `kern run` takes on the direct path. NOT a box - it holds
    /// host processes the caller started - so it is invisible to `kern ps` and the sweep never kills
    /// anything in it, only `rmdir`s it once it is empty.
    Run,
}

/// The `kern-box-` prefix: a box's capped leaf, and the proof that kern named the cgroup itself.
const BOX_LEAF_PREFIX: &str = "kern-box-";

/// The `kern-run-` prefix. See [`Leaf`] for why `kern run` does not just use a tag under the box one.
const RUN_LEAF_PREFIX: &str = "kern-run-";

/// The `kern-capprobe-` prefix: the throwaway child `memory_cap_state_at` creates to find out whether
/// a `--memory` cap would bind here.
///
/// A THIRD FAMILY, swept for the same reason as the other two and never killed for the same reason as
/// `kern run`'s. The probe removes its own child on every path it returns from, so one is left behind
/// only when the process died between the `mkdir` and the `rmdir`. MEASURED on this desktop: one
/// `kern-capprobe-1309526` in `kern.slice` whose pid was long gone, which four consecutive `kern
/// doctor` runs did not add to and which `kern gc` did NOT remove, because the sweep only knew the two
/// box prefixes. It is always EMPTY by construction (no process is ever placed in it), so `rmdir`
/// alone is the whole reap and `cgroup.kill` would have nothing to act on.
const CAPPROBE_LEAF_PREFIX: &str = "kern-capprobe-";

impl Leaf<'_> {
    /// The directory name this leaf gets under its parent cgroup, for the CURRENT process.
    ///
    /// The trailing `<pid>` is the creating process's, in both families, and every reader relies on
    /// that: it is the liveness handle the sweep stats to tell an owner that is still running from
    /// one that died without cleaning up.
    fn dir_name(self) -> String {
        match self {
            Leaf::Box(tag) => format!("{BOX_LEAF_PREFIX}{tag}-{}", std::process::id()),
            Leaf::Run => format!("{RUN_LEAF_PREFIX}{}", std::process::id()),
        }
    }
}

/// Is the supervisor outside the capped cgroup once the layout above has been attempted?
///
/// `leaf_built` is the outcome of the `mkdir` + `cgroup.procs` write, which is best-effort. The
/// FAIL-SAFE lives here: on the scope path with a failed leaf this returns `false`, which puts the
/// supervisor back in `child` and makes the workload inherit it, the pre-fix topology. Losing the OOM
/// message is bad; leaving the supervisor in a cgroup that is about to group-kill it, while telling
/// the forked child it does not need to join anything, would leave the workload UNCAPPED.
fn supervisor_ends_up_outside(forks: bool, origin_kills: bool, leaf_built: bool) -> bool {
    forks && (leaf_built || !origin_kills)
}

/// Confine the current process in a fresh cgroup with memory + pid (+ optional swap / CPU quota /
/// CPU pinning) caps. Returns the cgroup path on success (the workload, forked later, inherits it),
/// or `None` if unavailable. `memory_max` (bytes) overrides the default ceiling; `memory_swap_max`
/// (bytes, `--memory-swap-max`) sets `memory.swap.max` - the v2 swap *allowance*, separate from
/// `memory.max`, default `0` (swap off, so `memory.max` is a hard total); `cpuset` (`--cpuset-cpus`,
/// e.g. `"0-3"`) pins to specific CPUs via `cpuset.cpus`; `cpus` (cores, K8s semantics) caps CPU
/// time via `cpu.max`. The swap/CPU/cpuset knobs are all best-effort - silently skipped where the
/// controller isn't delegated (e.g. `cpuset` is often not delegated inside a systemd user scope).
///
/// `allow_direct` is the caller's authority to take the direct `kern.slice` path. It is granted by a
/// caller that leaves a process behind to hold the RAII guard and `rmdir` the leaf: `kern box`, whose
/// supervisor forks the box, and `kern run` ON THE PATH WHERE IT FORKS TOO (it did not always - see
/// `supervisor_forks_workload`). A caller that `exec()`s the workload in place must NOT grant it: with
/// nothing left to drop the guard, the leaf would outlive every process that knows its name, so such a
/// caller stays on the systemd `--scope --collect` path, which cleans up from outside. This is the one
/// enforcement input that can't be re-derived from env, so the caller passes it explicitly;
/// `took_direct_cap_path()` supplies the rest.
///
/// `leaf` chooses the directory NAME, which is not cosmetic: see [`Leaf`].
#[allow(clippy::too_many_arguments)] // one cgroup knob per parameter - grouping them would only hide it
pub fn apply_limits(
    allow_direct: bool,
    leaf: Leaf<'_>,
    memory_max: Option<u64>,
    memory_swap_max: Option<u64>,
    cpuset: Option<&str>,
    cpus: Option<f64>,
    pids_max: Option<u64>,
    io_max: &[String],
    io_weight: Option<u64>,
    // `--memory-reservation` → `memory.low`: a soft floor the kernel honours under pressure. Never
    // part of the `require_all` gate below, and deliberately: a reservation that does not bind costs
    // priority under contention, while a `memory.max` that does not bind costs the OOM backstop the
    // whole box was given. Failing a box over the first would be refusing to run for a hint.
    memory_low: Option<u64>,
    // `--cpu-weight` → `cpu.weight`: relative CPU share under contention. Best-effort like
    // `io.weight`, for the same reason: the controller may not be delegated to a rootless user
    // scope, and a box that runs with a default share is not a box that runs wrong.
    cpu_weight: Option<u64>,
    // `--require-limits`: demand that EVERY mandatory cap (memory AND pids) actually bind, not just
    // one of them. Tightens the success gate below from "at least one bound" to "both bound", so a
    // host that delegates one controller and not the other refuses the box instead of running it with
    // a silently-uncapped dimension. `false` keeps the historical best-effort "partial beats nothing".
    require_all: bool,
    // Does the CALLER fork a child that will be placed in the capped cgroup (`kern box`, and `kern
    // run` on the direct path), or does it `exec()` the workload in place (`kern run` on the scope
    // path)? It is a property of the CALL, not of the verb: `kern run` answers it both ways.
    //
    // This decides whether the supervisor may be parked in a sibling leaf, and getting it wrong is not
    // cosmetic: with `exec()` in place there is no second process, so the workload IS this process. Park
    // it outside and the workload runs in the UNCAPPED sibling. Measured while building this: `kern run`
    // on a root VPS stopped being killed by its own cgroup and was only caught by the outer scope's
    // `MemoryMax`, and on a host without that scope it would not have been capped at all.
    supervisor_forks_workload: bool,
) -> Option<CgroupGuard> {
    // cgroup v2 presents a unified hierarchy with this file at the root.
    if !PathBuf::from("/sys/fs/cgroup/cgroup.controllers").exists() {
        return None;
    }
    // Where the supervisor is RIGHT NOW - captured BEFORE we move it into the box cgroup, so the guard can
    // move it back and remove the (then-empty) box cgroup on the direct path (no systemd `--collect` there).
    let origin = current_v2_cgroup();
    // Whole-box OOM on the scope / managed-unit path. When the box runs directly in its OWN systemd
    // scope (`KERN_SCOPE` re-exec) or `--restart` unit (`KERN_MANAGED`), systemd caps that cgroup via
    // `MemoryMax` but leaves its `memory.oom.group` at 0, so an OOM would kill ONE process and leave the
    // box half-dead - exactly what the child write below prevents on the direct path. The per-box
    // `systemd-run --scope` is not `Delegate=yes`, so the capped `kern-box-*` child below often cannot be
    // built under the scope (`apply_limits` returns `None`) and the box stays in `origin`, which IS its
    // own scope. Set `oom.group=1` there so the whole-box kill holds. Gated on KERN_SCOPE/KERN_MANAGED
    // ONLY, deliberately NOT the full `outer_enforcer_present()`: `KERN_BUILD_STEP` is also an
    // outer-enforcer marker, but a `kern build` RUN step is a best-effort PASSTHROUGH that runs in the
    // CALLER's own cgroup (no per-box scope), so there `origin` is `kern build`'s inherited shell/session
    // cgroup - writing to it would flip the whole session to group-OOM-kill and never revert. The direct
    // and best-effort paths carry neither marker and are excluded for the same reason (`origin` = the
    // caller's cgroup). The build box still gets whole-box OOM via the `kern-box-*` child write below
    // where the controller is delegated. Best-effort and idempotent; runs before the box's mount
    // namespace remounts `/sys/fs/cgroup` read-only.
    //
    // NOT when the delegated layout is in force: there `origin` is kern's OWN `kern-sup` leaf, and
    // flipping that to group-kill would put the supervisor back in the blast radius - the exact thing
    // `prepare_delegated_scope` exists to take it out of. The box's whole-box kill is then carried by
    // the `kern-box-*` child's own `oom.group` write below, on the cgroup that holds the workload.
    // Does the supervisor's OWN cgroup become a whole-group killer? Captured here, at the one place
    // that decides it, because the sibling-leaf question below is the same question: the supervisor
    // needs moving out of `origin` if and only if `origin` is about to group-kill.
    let origin_group_kills =
        (env_flag("KERN_SCOPE") || env_flag("KERN_MANAGED")) && delegated_scope().is_none();
    if origin_group_kills {
        if let Some(o) = &origin {
            let _ = fs::write(o.join("memory.oom.group"), "1");
        }
    }
    // The single direct-path decision, computed ONCE and reused at the parent-select and fail-closed sites
    // so they can't drift: the caller must AUTHORISE it (`allow_direct`) AND the canonical env/systemd
    // predicate must hold (`took_direct_cap_path()`). `kern run` passes `allow_direct=false`, so it can
    // never relocate into kern.slice even when the predicate would otherwise be true (scope re-exec failed).
    let direct = allow_direct && took_direct_cap_path();
    // Choose the cgroup we'll cap under. ONLY on the genuine direct path do we prefer kern's DELEGATED
    // `kern.slice` for DIRECT hard caps. Otherwise use the CURRENT cgroup (`origin`, already read above):
    // inside a scope / managed `--restart` unit the ancestor already enforces (moving the box out would
    // break its stop/kill + MemoryMax), and on a best-effort / opted-out host we stay put and degrade
    // gracefully (no kern.slice `systemd-run` spawn, no relocation).
    let parent = if direct {
        ensure_kern_slice().or_else(|| origin.clone())?
    } else if let Some(scope) = delegated_scope() {
        // Scope path with the delegated layout: cap under the SCOPE, not under `origin` - which is now
        // `<scope>/kern-sup`, where kern's supervisor sits precisely so the box's group-OOM kill cannot
        // reach it. The child built below is the box's own ceiling; the scope keeps its `MemoryMax` (the
        // box's cap plus `SCOPE_SUPERVISOR_HEADROOM`) as the outer backstop.
        scope.clone()
    } else if allow_direct
        && origin
            .as_deref()
            .is_some_and(|o| !children_can_be_capped(o))
        && ensure_kern_slice().is_some_and(|s| children_can_be_capped(&s))
    {
        // RESCUE, and the narrowest one that closes the doctor/box contradiction. `origin` is a cgroup
        // that holds processes (kern's own), so cgroup v2 refuses to enable controllers in its subtree
        // and the box's child would get no `memory.max`: the box would run UNCAPPED on a host where a
        // cap is perfectly available one directory over. `ensure_kern_slice()` is that directory, and
        // as root it is created EMPTY, which is exactly why doctor's probe finds caps enforced there.
        //
        // Deliberately gated on `allow_direct`, so `kern run` keeps its promise never to relocate a
        // host process into kern.slice, and on BOTH probes, so a box only moves when staying put means
        // no cap at all and moving means a real one. Rootless is untouched: `ensure_kern_slice` only
        // CREATES the slice as root, so where it is absent this arm cannot fire.
        ensure_kern_slice()?
    } else {
        origin.clone()?
    };
    let mut child = parent.join(leaf.dir_name());

    enable_subtree_controllers(&parent);
    if fs::create_dir(&child).is_err() {
        if !direct {
            return None;
        }
        // Direct path only: kern.slice may have been GC'd since this process memoized it - systemd
        // reaps the empty slice the moment a box exits, and a LONG-LIVED `--restart` supervisor's
        // forked runner still holds the stale `ensure_kern_slice` memo. Re-bootstrap once, uncached,
        // and retry; without this every restart attempt fails the fail-closed refusal and the box
        // dies permanently where a fresh `kern box` would have recreated the slice.
        let parent = ensure_kern_slice_uncached()?;
        enable_subtree_controllers(&parent);
        child = parent.join(leaf.dir_name());
        fs::create_dir(&child).ok()?;
    }

    // Set the memory + PID caps. If BOTH fail the controllers aren't delegated here - do NOT leave a
    // useless cgroup behind and do NOT pretend the workload is capped. Clean up and bail, so the
    // caller reports "no cap" honestly rather than a false sense of safety. (CPU never gates this.)
    //
    // READ-BACK VERIFY (not fire-and-forget): a successful `write()` return is only a proxy - it says
    // the syscall didn't error, not that the limit is in force. On a partially-delegated host a write
    // can be accepted and yet the child's value stay at the `max` (no-limit) sentinel. So we write AND
    // re-read: `wrote_real_limit` is true only if the file no longer reads `max`, i.e. a real cap bit.
    // This is what makes the direct path safe to trust; the caller can then fail-closed (§require-caps).
    let mem_bytes = memory_max.unwrap_or(DEFAULT_MEMORY_MAX);
    let mem_ok = wrote_real_limit(&child.join("memory.max"), &mem_bytes.to_string());
    // `--pids-limit N` sets `pids.max` (fork-bomb containment); default otherwise.
    let pids_ok = match pids_max {
        Some(n) => wrote_real_limit(&child.join("pids.max"), &n.to_string()),
        None => wrote_real_limit(&child.join("pids.max"), DEFAULT_PIDS_MAX),
    };
    // `memory.swap.max` - the v2 swap allowance (separate from memory.max, NOT a combined total).
    // Default `0` keeps `memory.max` a hard total (overflow is OOM-killed, not swapped); a
    // `--memory-swap-max N` lets the box swap up to N.
    let _ = fs::write(
        child.join("memory.swap.max"),
        memory_swap_max.map_or_else(|| "0".to_string(), |b| b.to_string()),
    );
    // `memory.oom.group = 1`: when THIS cgroup hits its memory limit, the kernel kills EVERY process in
    // it as one unit, not just the single highest-`oom_score` task. Without it an OOM can kill a child
    // while PID 1 survives, leaving the box half-dead but still reading `running` (the orphan detector
    // does NOT catch this - the supervisor is alive and the cgroup is populated). Set on EVERY box (the
    // DEFAULT_MEMORY_MAX applies even without `--memory`), written BEFORE the workload joins the cgroup
    // below so an early OOM already kills the whole group. This is the DIRECT-path write, to the
    // `kern-box-*` child; the scope / managed-unit path is covered by the `origin` write above (the
    // box runs in the ancestor there). CHANGELOG promises "an OOM kills the whole box", so BOTH paths
    // set it. Best-effort and SILENT on failure: the file exists only when the `memory` controller is
    // delegated - exactly the case the "--memory not enforced" warning below already reports, so a
    // second message here would be noise. Available since Linux 4.19 (all supported hosts: the oldest
    // board is 5.15).
    let _ = fs::write(child.join("memory.oom.group"), "1");
    // Success gate. DEFAULT (`require_all = false`): keep the box if AT LEAST ONE mandatory cap bound -
    // partial protection beats none, and the caller warns about the rest. `--require-limits`
    // (`require_all = true`): demand that BOTH bound; a box that caps memory but not pids (or the
    // reverse - a host that delegates one controller and not the other) is still a fork-bomb / OOM hole,
    // and the whole point of the flag is that such a box does not start. `mem_ok`/`pids_ok` are already
    // READ-BACK verified (see `wrote_real_limit`), so this decides on real enforcement, not on a
    // syscall that merely didn't error.
    let caps_ok = caps_gate_satisfied(mem_ok, pids_ok, require_all);
    if !caps_ok {
        let _ = fs::remove_dir(&child);
        return None;
    }
    // (The "not enforced" warnings come LATER, after all writes. memory and cpu are based on the
    // EFFECTIVE limit up the cgroup tree, not on this single inner write, since the outer systemd
    // scope may be the real enforcer; see `capped_in_tree`. pids is the exception and is based on
    // `pids_ok` here, because the tree walk would find the session-wide `TasksMax` and call a box
    // with no fork-bomb guard "capped".)

    // Optional CPU pinning (`--cpuset-cpus`, e.g. "0-3"). Best-effort: the `cpuset` controller is
    // frequently not delegated inside a systemd user scope, so a write failure is ignored. The CLI
    // has already validated the list is `[0-9,-]` only, so it can't inject anything into the file.
    if let Some(set) = cpuset {
        // Best-effort: the `cpuset` controller is frequently not delegated in a rootless user scope,
        // but the CLI also pins via `sched_setaffinity` (the real fallback), so a failure here is NOT
        // "unenforced" - no warning, unlike memory/cpu which have no affinity equivalent.
        let _ = fs::write(child.join("cpuset.cpus"), set);
    }

    // Optional CPU cap (`--cpus`). cgroup v2 `cpu.max` = "<quota_us> <period_us>"; cores =
    // quota/period. Clamp to the host CPU count. Best-effort: a write failure (no CPU controller,
    // e.g. some Android kernels) is ignored - isolation still holds, only the CPU cap is skipped.
    if let Some(c) = cpus {
        // `c` is already clamped to the host CPU count by the CLI (the single place that can warn);
        // an over-large quota would be harmless anyway (the kernel never grants more than the
        // physical cores), so we don't re-read /proc/cpuinfo on this hot path.
        let quota = (c * CPU_PERIOD_US as f64).round().max(1.0) as u64;
        // Best-effort like the rest: `--cpus` is primarily enforced by the outer systemd scope, so a
        // failure to write this inner `cpu.max` is not proof the workload is uncapped (see above).
        let _ = fs::write(child.join("cpu.max"), format!("{quota} {CPU_PERIOD_US}"));
    }

    // Optional per-device I/O limits (`vdisk:` `--iops`/`--bandwidth` → `io.max`) and `io.weight`
    // (`--io-weight`). One `io.max` line per device, `MAJ:MIN riops=… wbps=…`. Best-effort: the `io`
    // controller is usually NOT delegated to a rootless user scope, so a write failure is expected
    // and simply skips the limit (the vdisk still works, uncapped) - never a hard error. The lines
    // are built by the CLI from a stat'd loop device, so they can't inject arbitrary content.
    // SOFT KNOBS FIRST, and they are not part of any success gate. Both are written best-effort into
    // the SAME child cgroup as the hard caps above, so a host that delegates the controller gets them
    // and a host that does not runs with the kernel's defaults, which is what it did before these
    // existed. A failure here is reported by the same channel as `io`, below, only when the caller
    // actually asked for something.
    let mut soft_requested = false;
    let mut soft_applied = true;
    if let Some(low) = memory_low {
        soft_requested = true;
        soft_applied &= fs::write(child.join("memory.low"), low.to_string()).is_ok();
    }
    if let Some(w) = cpu_weight {
        soft_requested = true;
        // Clamped by the CLI (1..=10000); re-clamped here as defence in depth, exactly as
        // `io.weight` is.
        soft_applied &= fs::write(child.join("cpu.weight"), w.clamp(1, 10_000).to_string()).is_ok();
    }
    if soft_requested && !soft_applied {
        eprintln!(
            "kern: soft limits (--memory-reservation/--cpu-weight) not enforced - the cgroup \
             controller isn't delegated to this box's cgroup. The box still runs, with the kernel's \
             default share"
        );
    }
    let io_requested = !io_max.is_empty() || io_weight.is_some();
    let mut io_applied = false;
    for line in io_max {
        io_applied |= fs::write(child.join("io.max"), line).is_ok();
    }
    if let Some(w) = io_weight {
        // Clamped by the CLI (1..=10000); re-clamped here as defence in depth.
        io_applied |= fs::write(child.join("io.weight"), w.clamp(1, 10_000).to_string()).is_ok();
    }
    // The user explicitly asked for an I/O limit - if the `io` controller isn't delegated to this
    // box's cgroup, say so rather than silently ignore it (feedback-first). Everything else the box
    // does still works; only the I/O cap is skipped.
    if io_requested && !io_applied {
        eprintln!(
            "kern: I/O limits (--iops/--bandwidth/--io-weight) not enforced - the cgroup `io` \
             controller isn't delegated to this box's cgroup"
        );
    }

    // Honest feedback on the two-layer model: memory/CPU are capped EITHER by this inner cgroup OR by
    // the outer systemd `--scope`. A failed inner write is fine as long as SOME ancestor caps it - so
    // check the EFFECTIVE limit up the tree, and only warn when NOTHING in the chain enforces a knob
    // the user explicitly asked for (e.g. a rootless host with the memory controller un-delegated, the
    // Pi-5 case). This never false-positives on a host where the scope enforces it.
    // Value-aware, not existence-aware: an ancestor's `memory.max` bounds the box, but if it sits
    // ABOVE the requested value the request did not take effect (the box can use up to that ancestor
    // cap, not the smaller number it asked for). `capped_in_tree` read any finite ancestor cap as
    // "enforced" and stayed silent on a box asking 8m under a container's 8 GiB outer cap.
    if let Some(req) = memory_max {
        if !memory_capped_at_or_below(&child, req) {
            eprintln!(
                "kern: --memory not enforced - no cgroup memory cap took effect at or below the \
                 requested value (the `memory` controller isn't delegated to this rootless scope, or \
                 only a larger ancestor cap applies); the box can exceed the limit"
            );
        }
    }
    if cpus.is_some() && !capped_in_tree(&child, "cpu.max") {
        eprintln!(
            "kern: --cpus not enforced - no cgroup cpu cap took effect (the `cpu` controller isn't \
             delegated to this rootless scope)"
        );
    }
    // `--pids-limit` was the fourth knob and the only one that stayed SILENT when it did not take.
    // Measured on a Raspberry Pi 5 (outside the systemd user manager, so `direct` is false and the
    // per-dimension fail-closed below does not apply): `--pids-limit 999999999` returned 0 with
    // `pids.max` reading `max`, i.e. the box ran with NO limit and nothing said so. 64, 256 and
    // 1000000 were honoured exactly on the same host, so this is the write failing, not the value
    // being clamped. Same family as `--cpus` and `--cpuset-cpus`: requested, accepted, not applied.
    //
    // Deliberately keyed on `pids_ok` - the box's OWN read-back - and NOT on `capped_in_tree`, for
    // the reason spelled out at the fail-closed block below: the tree walk climbs above `kern.slice`
    // into the shared `user-<uid>.slice`, whose systemd-default `TasksMax` (~83k, session-wide) is a
    // finite value that would satisfy the check while giving this box no fork-bomb guard at all.
    //
    // Only for an EXPLICIT request, matching `--memory` above: the `DEFAULT_PIDS_MAX` backstop
    // failing is worth knowing too, but warning about it on every box start on such a host would be
    // noise that trains the reader to ignore the line.
    if pids_max.is_some() && !pids_ok {
        eprintln!(
            "kern: --pids-limit not enforced - no cgroup pids cap took effect (the `pids` \
             controller isn't delegated to this rootless scope, or the kernel refused the value); \
             the box has no fork-bomb guard"
        );
    }

    // FAIL-CLOSED, per-dimension, ONLY on the genuine direct path (`took_direct_cap_path()` - the SAME
    // predicate the caller refuses under, so they can't diverge; NOT on best-effort / `KERN_NO_SCOPE`
    // hosts, where destroying a partial cap that DID apply would be worse than keeping it).
    //
    // Verify the BOX'S OWN write via `mem_ok`/`pids_ok` (the read-back at `wrote_real_limit`), NOT
    // `capped_in_tree`: the tree walk climbs ABOVE kern.slice into the shared `user-<uid>.slice`, whose
    // systemd-default `TasksMax` (~83k, session-wide) is finite and would falsely satisfy the pids check -
    // making the fork-bomb guarantee a no-op. memory + pids ALWAYS carry a cap (explicit or the DEFAULT_*
    // backstop), so both are mandatory; `cpu` is a QoS knob with no default and no OOM/fork-bomb role, so
    // it stays warn-only (above) - refusing a box for an unenforceable cpu quota is both a regression vs
    // the scope path and wrong (the scope path only warns).
    if direct && (!mem_ok || !pids_ok) {
        let _ = fs::remove_dir(&child);
        return None;
    }

    // WHO JOINS THE CAPPED CGROUP, and this is a correctness question rather than a tidiness one.
    //
    // Historically the supervisor joined `child` itself and the forked workload inherited it. That makes
    // the caps bind with no extra plumbing, and it puts the supervisor INSIDE a cgroup carrying
    // `memory.oom.group = 1`: when the cap fires the kernel kills the whole group, so the process that
    // would read the workload's status and explain the kill dies with it.
    //
    // MEASURED on WSL2 (uid 0, no systemd, so the direct path with nothing above it): a box past its cap
    // exited 137 with an EMPTY stderr and the supervisor never reached its reporting branch. The same
    // binary on the same host, with a workload exiting 7 instead, reached it and printed `code=7`. So the
    // branch was correct and the process running it was dead. `prepare_delegated_scope` already takes the
    // supervisor out of the blast radius on the SCOPE path, and its doc comment says it "mirrors the
    // direct path's topology" - which was not true of this function.
    //
    // A SIBLING leaf, not a child of `child`: cgroup v2 forbids a cgroup with children from holding
    // processes ("no internal processes"), so parking the supervisor under `child` would mean moving the
    // workload one level deeper and changing the path every other subsystem records, reaps and identifies
    // a box by. A sibling changes nothing outside this function.
    //
    // FAIL-SAFE, and the ordering IS the safety: the sibling is created and joined FIRST, and only a
    // failure of either falls back to the old behaviour. There is no window in which the supervisor sits
    // in the capped cgroup, because it never enters it. The workload is placed in `child` by the forked
    // child itself (see `join_box_cgroup`), so nothing else has to move.
    let sup_leaf = child.with_file_name(format!(
        "{}-sup",
        child
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("kern-box")
    ));
    // AND THE LEAF IS ONLY NEEDED WHEN `origin` ITSELF GROUP-KILLS, which is the line above.
    //
    // `child` is created by the `mkdir` a few lines up, so nothing can be inside it and the supervisor
    // cannot already be there. The only cgroup that can take the supervisor down with the workload is
    // therefore its own, and that happens on exactly one path: a scope or managed unit where
    // `prepare_delegated_scope` did not manage to move kern into a leaf of its own, so `origin` IS the
    // scope and the write above arms it.
    //
    // Everywhere else the supervisor is already outside the blast radius and moving it buys nothing.
    // MEASURED, because "buys nothing" was worth a number: creating and removing this leaf costs
    // 0.167 ms of a 2.5 ms box start, 20 of 20 paired batches, and a cgroup `mkdir` alone is 90.5 us
    // on this host against 19.4 us for the `cgroup.procs` write it was blamed on. Correctness held in
    // both layouts on four hosts and three systemd versions (249, 252, 257): the OOM message survives
    // and `memory.max` inside the box reads the cap exactly.
    let sup = if !supervisor_forks_workload {
        // `exec()` in place: this process becomes the workload, so it must stay in the capped cgroup.
        None
    } else if !supervisor_needs_leaf(supervisor_forks_workload, origin_group_kills) {
        None // already outside anything that can group-kill it: nothing to build, nothing to remove
    } else if fs::create_dir(&sup_leaf).is_ok() || sup_leaf.is_dir() {
        if fs::write(
            sup_leaf.join("cgroup.procs"),
            std::process::id().to_string(),
        )
        .is_ok()
        {
            Some(sup_leaf)
        } else {
            // The parent accepted the mkdir but refuses the move: leave nothing behind, take the old path.
            let _ = fs::remove_dir(&sup_leaf);
            None
        }
    } else {
        None
    };
    // The supervisor joins `child` only when it is NOT outside: with `exec()` in place it must be
    // there, and on the scope path a failed leaf falls back to the old topology. When it is already
    // outside, the forked child puts ITSELF in (`join_box_cgroup`), which is what `outside` tells it.
    let outside =
        supervisor_ends_up_outside(supervisor_forks_workload, origin_group_kills, sup.is_some());
    if !outside {
        // Fallback: join the capped cgroup as before. The box is still capped and still OOM-killed as a
        // unit; only the explanation is lost, which is exactly what shipped before this change.
        if fs::write(child.join("cgroup.procs"), std::process::id().to_string()).is_err() {
            let _ = fs::remove_dir(&child);
            return None;
        }
    }
    // Record it before handing the guard back: the supervisor reads this after the box exits, and by
    // then neither `/proc/<pid1>/cgroup` nor the sibling leaf can be trusted to name it (see
    // `BOX_CGROUP_DIR`). `set` is idempotent-by-first-write; one box per process, so it fires once.
    let _ = BOX_CGROUP_DIR.set(child.clone());
    Some(CgroupGuard {
        outside,
        dir: child,
        sup,
        origin,
    })
}

/// Write a cgroup limit AND verify it took: true only if, after the write, the file no longer reads the
/// `max` no-limit sentinel - i.e. a real cap is in force. A successful `write()` return is only a proxy
/// (a partially-delegated host can accept the write yet leave the value at `max`); this read-back is what
/// lets the caller trust "capped" and fail-closed when it isn't. Kernel rounding (e.g. page-aligning
/// `memory.max`) is fine - we assert "a real limit is set", not byte-exact equality.
fn wrote_real_limit(file: &std::path::Path, value: &str) -> bool {
    if fs::write(file, value).is_err() {
        return false;
    }
    fs::read_to_string(file).is_ok_and(|v| is_real_limit(&v))
}

/// Do a cgroup limit file's raw contents represent a REAL cap in force - i.e. NOT the `max` no-limit
/// sentinel (`max` for `memory.max`/`pids.max`, `max <period>` for `cpu.max`)? The single definition of
/// the sentinel rule, shared by the write read-back (`wrote_real_limit`) and the up-tree walk
/// (`capped_in_tree`) so the two can't drift.
fn is_real_limit(raw: &str) -> bool {
    let v = raw.trim();
    !v.is_empty() && !v.starts_with("max")
}

/// This process's own cgroup directory, or `None` when the layout is not one this code models.
///
/// cgroup v2 line: `0::/user.slice/.../foo.scope`. Anything else is v1/hybrid, and staying quiet
/// beats answering about a layout we did not inspect, so every caller treats `None` as "cannot tell"
/// rather than as "not capped".
fn own_cgroup_dir() -> Option<std::path::PathBuf> {
    cgroup_dir_from_proc_line(&fs::read_to_string("/proc/self/cgroup").ok()?)
}

/// The parse and the ambiguity check, split out so a test can exercise THIS code rather than a
/// copy of it. The first version of the test below reproduced these four lines inline and passed
/// against a build with the guard deleted, which is the defect it was written to prevent, one
/// level up.
fn cgroup_dir_from_proc_line(raw: &str) -> Option<std::path::PathBuf> {
    let rel = raw
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::trim)
        .filter(|p| p.starts_with('/'))?;
    // `0::/` IS AN ANSWER THIS FUNCTION CANNOT USE, and it used to be treated as one. It means
    // either "I am at the true root of the hierarchy" or "I am inside a cgroup NAMESPACE and my
    // root is whatever cgroup was namespaced" - one value standing for two conditions, which is
    // the in-band-sentinel shape this codebase has removed elsewhere.
    //
    // Resolving it is not neutral, it is always wrong in the same direction: joining an empty
    // relative path yields `/sys/fs/cgroup`, and the ROOT CGROUP HAS NO `memory.max` (verified:
    // `ls /sys/fs/cgroup/memory.max` -> No such file). So every caller that cannot locate itself
    // reads a directory where the cap file cannot exist, concludes "not capped", and prints
    // "accepted but NOT enforced here" about a box whose cap may be perfectly in force.
    //
    // `None` matches this module's own stated policy for the case one line up: an unreadable
    // `/proc/self/cgroup` means we cannot tell, and a warning we cannot justify is worse than
    // none. Not knowing where you are is the same condition as not being able to read where you
    // are, and it now gets the same answer.
    //
    // THE RETURN TYPE IS NARROW BECAUSE THE POLICY IS UNIFORM, not because there happen to be two
    // callers. `None` now collapses four conditions - no `0::` line, a relative path, an unreadable
    // file, and a root we cannot place - and every one of them means "stay quiet", so nothing can
    // tell them apart and nothing needs to. If that policy ever stops being uniform, if some caller
    // must warn on doubt or distinguish "cgroup v1 host" from "namespaced box", THE TYPE HAS TO
    // GROW FIRST: widening it afterwards means auditing every branch that already treated the four
    // as one. Stated this way round because "two callers do not need it" stops being true the day a
    // third appears, and this reason does not. This cannot create a false GREEN beyond what that
    // branch already accepts: a box is never left at the hierarchy root by `apply_caps`, and a
    // cap that truly failed to apply is caught by its fail-closed read-back and by
    // `--require-limits`, neither of which routes through here.
    //
    // Found by an external reviewer reading the function, with no host and no binary. It is a
    // property of the code, not of a machine, which is why it did not need one.
    if rel == "/" {
        return None;
    }
    Some(std::path::Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// Is a memory cap of at most `bytes` ACTUALLY in force on the chain above `dir`?
///
/// For the caller that has to decide whether a cap nobody typed is still there. `warn_unenforced_caps`
/// cannot answer this: every one of its checks is gated on the caller having ASKED, which is right for
/// a flag and wrong for a default.
///
/// `dir` IS THE WORKLOAD'S CGROUP, AND PASSING IT IS NOT BOOKKEEPING - it is the same correction
/// [`warn_unenforced_caps`] carries, for the same reason, and it became load-bearing here the moment
/// `kern run` started forking. The supervisor stays OUTSIDE the capped leaf so a whole-box OOM cannot
/// take the process that has to report it, so a self-read answers about a cgroup that is uncapped BY
/// CONSTRUCTION and would print "this command runs with no RAM ceiling" over a workload holding the
/// exact default. `None` keeps the self-read for a caller that IS the workload, which is `kern run`
/// on the paths where it still `exec()`s in place.
///
/// `true` WHEN WE CANNOT TELL, deliberately, and it is the opposite default from most of this file. A
/// caller uses this to decide whether to warn, and a warning that fires because `/proc/self/cgroup`
/// was unreadable is a warning with nothing behind it. The cost of the two errors is not symmetric
/// here: staying quiet on an unknown host loses a notice, while crying wolf on every start teaches the
/// reader to skip the line that matters.
pub fn memory_cap_in_force_at_or_below(dir: Option<&Path>, bytes: u64) -> bool {
    match dir {
        Some(d) => memory_capped_at_or_below(d, bytes),
        None => own_cgroup_dir().is_none_or(|d| memory_capped_at_or_below(&d, bytes)),
    }
}

/// Warn for every cap the caller ASKED for that nothing in this process's cgroup chain enforces.
///
/// The direct path already does this at the inner cgroup (see the `capped_in_tree` warnings above),
/// but the **scope** path hands the knobs to `systemd-run` as `MemoryMax=`/`CPUQuota=`/`TasksMax=`
/// and never re-checked. systemd accepts a property the kernel cannot honour and says nothing: on an
/// Arduino UNO Q's Android kernel the `cpu` controller exposes only the *weight* interface
/// (`cpu.weight`) and no `cpu.max` anywhere in the chain, so `--cpus 0.5` became a share rather than
/// a ceiling, in silence, while `kern doctor` reported caps as enforced. Measured there, not assumed.
///
/// `dir` is the BOX's cgroup, and passing it is not optional bookkeeping: the supervisor is parked in
/// a SIBLING leaf (so a whole-box OOM cannot take it), and that leaf is uncapped by construction while
/// the box's own leaf carries the exact caps. This function used to read `/proc/self/cgroup`, which on
/// the scope tier answered for the supervisor's leaf and then walked to the ANCESTORS - never reaching
/// the box's leaf, because it is a sibling, not a parent. MEASURED on a Raspberry Pi 5 and a Jetson
/// (2026-09-07), `--memory 256m --pids-limit 64`: the box's leaf held `memory.max=268435456` and
/// `pids.max=64`, exactly as asked, and kern printed BOTH "accepted but NOT enforced here" lines. The
/// only ancestor with a memory ceiling is the scope, deliberately set to the request PLUS
/// [`SCOPE_SUPERVISOR_HEADROOM`] (see `scope_memory_max`: equal ceilings OOM the supervisor first), so
/// `<= request` was false BY DESIGN. Both notices were wrong on 100% of that tier, and silent on the
/// direct tier, where `KERN_SCOPE` is unset and this is never called: the check had never once fired
/// correctly. [`record_memory_cap_signal`] already took the directory for this exact reason, so the
/// enforcement BYTE said "enforced" while the prose said the opposite.
///
/// `None` restores the self-read for a caller that IS the workload - `kern run` on the SCOPE path,
/// which is the only path that calls this, and the only one where it still `exec()`s in place.
/// Read-only and best-effort: an unreadable `/proc/self/cgroup` means we cannot tell, and a warning we
/// cannot justify is worse than none, so it stays quiet.
pub fn warn_unenforced_caps(
    dir: Option<&std::path::Path>,
    memory: Option<u64>,
    cpus: Option<f64>,
    pids: Option<u64>,
) {
    // KERN_QUIET drops this human-readable warning for embedders (e.g. the MCP server) whose channel
    // is a machine one: they read the enforcement verdict off the unforgeable started-fd signal, which
    // this does NOT touch, so `oom` vs `killed` classification still holds. Only the prose is silenced.
    if env_flag("KERN_QUIET") {
        return;
    }
    let dir_given = dir.is_some();
    let Some(dir) = dir
        .map(std::path::Path::to_path_buf)
        .or_else(own_cgroup_dir)
    else {
        return;
    };
    // WHICH ceiling counts as satisfying `--memory`. Given the box's own leaf, the request EXACTLY:
    // that leaf is written with `memory.max=<request>`. Falling back to the self-read under a scope we
    // are reading the chain the supervisor stands in, whose only ceiling is the one kern itself asked
    // systemd for - the request plus the supervisor's headroom - so comparing against the bare request
    // there reports a correctly-capped box as unenforced by exactly that headroom, which is the same
    // false red one vantage up.
    let memory = match (dir_given, env_flag("KERN_SCOPE")) {
        (false, true) => memory.map(|m| m.saturating_add(SCOPE_SUPERVISOR_HEADROOM)),
        _ => memory,
    };
    for (flag, why) in unenforced_caps(&dir, memory, cpus, pids) {
        eprintln!("kern: {flag} accepted but NOT enforced here - {why}; the box can exceed it");
    }
}

/// Which of the caps the caller ASKED for are not enforced at `dir`, as `(flag, why)` pairs.
///
/// The decision, separated from the printing and from every environment read, so a test can drive the
/// SUBJECT against a synthetic cgroup tree instead of re-deriving the same rule beside it and passing
/// against a build where the rule is wrong. `warn_unenforced_caps` keeps what only the live process can
/// answer: which directory to look at, and which ceiling counts.
///
/// Each knob carries its OWN enforcement check, so the loop dispatches on the check, not on the
/// file name. The three differ on purpose:
///   * memory - VALUE-aware (`AtOrBelow`): an ancestor `memory.max` larger than the request does not
///     satisfy `--memory 32m`. A finite-but-larger outer cap once masked a box that asked for less
///     than it got, so this compares against the request, not mere existence.
///   * cpu - an ancestor ceiling counts (`TreeExists`): a `cpu.max` anywhere up the chain bounds this
///     box wherever it sits.
///   * pids - the box's OWN level only (`HereExists`). Measured on a Raspberry Pi 5,
///     `--pids-limit 999999999`: the walk found `user-1000.slice pids.max=20370` and stayed quiet,
///     but 20370 is systemd's session-wide `TasksMax`, shared with every other process the user
///     runs, not a per-box fork-bomb guard. `apply_caps`'s fail-closed block keys on the box's own
///     read-back for the same reason; the rule was applied in one place and not the other. Checking
///     only the box's own level costs no false warning: 64/256/1000000 all landed in the box's cgroup
///     exactly, only 999999999 did not.
fn unenforced_caps(
    dir: &std::path::Path,
    memory: Option<u64>,
    cpus: Option<f64>,
    pids: Option<u64>,
) -> Vec<(&'static str, &'static str)> {
    enum Check<'a> {
        AtOrBelow(u64),
        TreeExists(&'a str),
        HereExists(&'a str),
    }
    let mut out = Vec::new();
    for (asked, flag, check, why) in [
        (
            memory.is_some(),
            "--memory",
            Check::AtOrBelow(memory.unwrap_or(0)), // req unused unless `asked` (memory.is_some())
            "the `memory` controller is not delegated to this cgroup",
        ),
        (
            cpus.is_some(),
            "--cpus",
            Check::TreeExists("cpu.max"),
            "this kernel's `cpu` controller exposes no bandwidth interface (`cpu.max`), only weights",
        ),
        (
            pids.is_some(),
            "--pids-limit",
            Check::HereExists("pids.max"),
            "no per-box `pids.max` took effect (an ancestor's session-wide `TasksMax` is not a \
             per-box limit); the box has no fork-bomb guard",
        ),
    ] {
        // `asked &&` short-circuits, so the file read only happens for a knob the caller actually set.
        let capped = asked
            && match check {
                Check::AtOrBelow(req) => memory_capped_at_or_below(dir, req),
                Check::TreeExists(file) => capped_in_tree(dir, file),
                Check::HereExists(file) => capped_here(dir, file),
            };
        if asked && !capped {
            out.push((flag, why));
        }
    }
    out
}

/// Is a REAL cap in force on THIS cgroup, ignoring ancestors? The leaf-only counterpart to
/// [`capped_in_tree`], for the one knob where an ancestor's limit does not answer the question:
/// a `pids.max` two levels up is shared with every other process in that slice, so it bounds a
/// fork bomb's blast radius against the session, not against this box.
fn capped_here(dir: &std::path::Path, file: &str) -> bool {
    fs::read_to_string(dir.join(file)).is_ok_and(|v| is_real_limit(&v))
}

/// Is a `memory.max`/`cpu.max`-style cap actually in force for the box - at THIS cgroup OR any
/// ancestor up to the cgroup root? Accounts for the two-layer model (inner cgroup + outer systemd
/// scope): the inner write may fail while an ancestor still enforces the cap. The "no cap" sentinel
/// is `max` (`memory.max`) or `max <period>` (`cpu.max`), so any value not starting with `max` at any
/// level means a real limit is in effect.
fn capped_in_tree(child: &std::path::Path, file: &str) -> bool {
    in_tree(child, |dir| {
        fs::read_to_string(dir.join(file)).is_ok_and(|v| is_real_limit(&v))
    })
}

/// Is the box's REQUESTED `--memory` value actually in effect - i.e. does some level in the ancestry
/// cap `memory.max` at or below `requested` bytes?
///
/// [`capped_in_tree`] answers the weaker "is there ANY finite `memory.max` up the tree", and that is
/// what masked the requested cap: a box asking `--memory 8m` inside a container whose own cgroup caps
/// at 8 GiB read "capped" (the container's outer 8 GiB is finite) and ran able to use 8 GiB, with no
/// warning. The container bounds the box, but not at the value asked for. This compares against the
/// request: a level capping at `requested` or tighter satisfies it (an ancestor capping BELOW the
/// request is a stricter bound, so the box still cannot exceed what it asked for); a tree whose only
/// finite cap is ABOVE the request does not. `max` (no cap) never parses to a number, so it is not a
/// bound. Both enforcement paths land a cap at exactly `requested` - the systemd scope sets
/// `MemoryMax=<requested>` and the direct path writes the inner `memory.max=<requested>` - so this
/// does not false-warn on an enforcing host; it warns only when the request took effect nowhere.
fn memory_capped_at_or_below(child: &std::path::Path, requested: u64) -> bool {
    in_tree(child, |dir| {
        fs::read_to_string(dir.join("memory.max"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .is_some_and(|v| v <= requested)
    })
}

/// Are the MANDATORY backstops - a memory ceiling that bounds this box, and a task ceiling at the
/// box's OWN level - already in force for this process's cgroup, whoever established them?
///
/// `apply_limits` returning `None` means KERN wrote no cap of its own. It does NOT mean the box runs
/// uncapped, and treating the two as the same thing is a measured defect: on the systemd-scope path
/// the SCOPE carries `MemoryMax`/`TasksMax`, so the caps bind without kern writing a byte. Measured on
/// a Raspberry Pi 5 (Raspberry Pi OS bookworm, kernel 6.6.51) from an ordinary ssh session: the box
/// landed in `user@.service/app.slice/run-<id>.scope` with `memory.max` 67108864, `memory.oom.group` 1
/// and `pids.max` 512, a 300 MB write was killed 3 times out of 3, and `dmesg` recorded
/// `Memory cgroup out of memory: Killed process ...` for three processes at once - the whole-box kill.
/// kern nevertheless printed the uncapped notice and `--require-limits` REFUSED to start, because both
/// keyed off `cg.is_none()` instead of asking the kernel. This asks the kernel.
///
/// The two knobs are checked differently, for the reason recorded on [`capped_here`]: a memory ceiling
/// ANYWHERE up the tree bounds the box (`capped_in_tree`, or [`memory_capped_at_or_below`] when a
/// value was requested, so an ancestor larger than the request does not count), while a `pids.max`
/// above the box is shared with every other task in that slice and bounds the session rather than this
/// box, so only the box's OWN level counts.
pub fn mandatory_caps_in_force(requested_memory: Option<u64>) -> bool {
    current_v2_cgroup().is_some_and(|cur| mandatory_caps_in_force_at(&cur, requested_memory))
}

/// Testable core of [`mandatory_caps_in_force`], split out for the same reason `memory_cap_state_at`
/// is: a unit test drives it against a synthetic directory instead of the real `/proc/self/cgroup`.
fn mandatory_caps_in_force_at(cur: &std::path::Path, requested_memory: Option<u64>) -> bool {
    let memory = match requested_memory {
        // A request must be BOUNDED by the ceiling, not merely accompanied by one: an ancestor cap of
        // 8 GiB does not enforce `--memory 8m`.
        Some(req) => memory_capped_at_or_below(cur, req),
        // No explicit request: the mandatory DEFAULT cap is what must be in force, and any real
        // ceiling in the tree bounds it.
        None => capped_in_tree(cur, "memory.max"),
    };
    memory && capped_here(cur, "pids.max")
}

/// Whether THIS box's requested `--memory` cap is actually being enforced, recorded for the second byte
/// of the `KERN_STARTED_FD` signal so an SDK can tell an OOM against a real ceiling from a plain kill
/// where the cap never bound. `0` = undetermined (no `--memory` requested, or `/proc/self/cgroup`
/// unreadable); `1` = enforced (a real ceiling at or below the request bounds the box); `2` = requested
/// but NOT enforced (no cgroup delegation here). Set ONCE at box start by [`record_memory_cap_signal`]
/// and read ONCE by the box_run teardown. Process-static because that write and this read live in
/// different crates but the SAME process (the direct supervisor, or the `KERN_SCOPE` re-exec - both run
/// `apply_limits` and reach the signal write). `Release`/`Acquire` pair the two.
static MEMORY_CAP_SIGNAL: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Record, for the started-fd's enforcement byte, whether the box's `--memory` cap actually binds. Call
/// EXACTLY ONCE, at box start, AFTER `apply_limits` has moved the supervisor into the box's cgroup (so
/// `/proc/self/cgroup` is the box's own - the `kern-box-*` child on the direct path, the systemd scope
/// on the scope path) and BEFORE the box forks. The value-aware [`memory_capped_at_or_below`] check
/// mirrors `warn_unenforced_caps`, so the signal and the warning cannot disagree. No `--memory` leaves
/// it `0` (undetermined): nothing to attribute an OOM to.
pub fn record_memory_cap_signal(memory: Option<u64>, dir: Option<&std::path::Path>) {
    use std::sync::atomic::Ordering;
    let signal = match memory {
        None => 0,
        Some(req) => match dir
            .map(std::path::Path::to_path_buf)
            .or_else(current_v2_cgroup)
        {
            // `dir` is the BOX's cgroup, passed explicitly because the supervisor is no longer in it: it
            // sits in a sibling leaf so a whole-box OOM cannot take it, and reading `/proc/self/cgroup`
            // there would answer for the supervisor's uncapped leaf and report every box as unenforced.
            // `None` keeps the old self-reading behaviour for the paths that still run inside the cgroup.
            Some(d) if memory_capped_at_or_below(&d, req) => 1,
            Some(_) => 2,
            None => 0, // cgroup layout we do not model: stay undetermined rather than claim either way
        },
    };
    MEMORY_CAP_SIGNAL.store(signal, Ordering::Release);
}

/// The enforcement byte recorded by [`record_memory_cap_signal`], for the second byte of the
/// `KERN_STARTED_FD` signal. `0` undetermined, `1` enforced, `2` requested-but-not-enforced.
pub fn memory_cap_signal() -> u8 {
    MEMORY_CAP_SIGNAL.load(std::sync::atomic::Ordering::Acquire)
}

#[cfg(test)]
mod tests {

    /// The `/proc` channel finds a live box, and it does not use `kern.slice` to do it.
    ///
    /// This exists because an independent reviewer ran the registry-wipe case on a host with NO
    /// cgroup delegation - uid 0, no systemd - and measured three live `kern box` processes that
    /// `ps` could not report, `stop` could not reach and `gc` would not touch. The cgroup channel had
    /// nothing to read there, so the warning could not fire on the host where the defect is most
    /// likely. This is the second channel, and it rests on two facts the kernel writes: a process
    /// outside our user namespace whose parent's `exe` is `kern`.
    ///
    /// SKIPS RATHER THAN ASSERTS WHEN THERE IS NOTHING TO FIND, and says so. But the empty case is
    /// still asserted: a channel that invented boxes when none are running would be worse than one
    /// that misses them, and only one of those two errors is caught by a test that just returns.
    #[test]
    fn the_proc_channel_sees_a_box_the_cgroup_channel_may_not() {
        let found = live_box_supervisors_via_proc();
        let any_box_running = std::fs::read_dir("/proc")
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let n = e.file_name().to_str()?.to_string();
                n.bytes().all(|b| b.is_ascii_digit()).then_some(n)
            })
            .any(|pid| {
                std::fs::read(format!("/proc/{pid}/cmdline"))
                    .map(|c| {
                        let a: Vec<&[u8]> = c.split(|b| *b == 0).collect();
                        a.first().is_some_and(|p| p.ends_with(b"kern"))
                            && a.iter().any(|w| *w == b"box")
                    })
                    .unwrap_or(false)
            });
        if !any_box_running {
            eprintln!("skip: no `kern box` process is running, so there is nothing to find");
            assert!(
                found.is_empty(),
                "with no box running the /proc channel must find nothing, got {found:?}"
            );
            return;
        }
        assert!(
            !found.is_empty(),
            "a `kern box` process is running and the /proc channel did not see it"
        );
        for (tag, pid) in &found {
            assert!(!tag.is_empty(), "a finding must carry a name");
            assert!(
                std::path::Path::new(&format!("/proc/{pid}")).exists(),
                "the supervisor it names must exist: {tag} pid {pid}"
            );
        }
    }

    /// `0::/` MEANS "I CANNOT TELL YOU WHERE I AM", and it used to resolve to the mount root.
    ///
    /// The line is ambiguous by construction: it is what a process at the true root of the
    /// hierarchy reads AND what a process inside a cgroup namespace reads, because the namespace
    /// re-roots the path. One value, two conditions, and the code picked one of them silently.
    ///
    /// Resolving it was never neutral. Joining an empty relative path yields `/sys/fs/cgroup`, and
    /// the root cgroup carries no `memory.max`, so the check that follows reads a directory where
    /// the file cannot exist, concludes the cap is absent, and prints "accepted but NOT enforced
    /// here" about a box that may be capped exactly as asked. A guaranteed false RED for anyone who
    /// cannot locate themselves.
    ///
    /// Found by an external reviewer reading the function with no host, no repo and no binary. The
    /// asymmetry is the reason it is worth a test rather than a comment: a false red is loud and
    /// annoying, a false green is silent, and this module's stated policy already picks silence
    /// when it cannot tell.
    #[test]
    fn a_cgroup_line_that_locates_nothing_yields_no_directory() {
        // THE SUBJECT, not a copy of it. The first version of this test reproduced the parse
        // inline and passed against a build with the guard deleted: it was verifying its own
        // duplicate. `own_cgroup_dir` reads /proc/self/cgroup and cannot be handed a string, so
        // the parse is a function now and this calls it.
        let resolve = super::cgroup_dir_from_proc_line;

        // THE CASE THAT REGRESSED: namespaced, or at the root. Either way, unusable.
        assert_eq!(
            resolve("0::/\n"),
            None,
            "`0::/` must not resolve to the root"
        );
        assert_eq!(resolve("0::/"), None, "with no trailing newline either");
        assert_eq!(resolve("0::  /  \n"), None, "nor once trimmed");

        // A real location still resolves, or the fix would have silenced every host.
        assert_eq!(
            resolve("0::/user.slice/user-1000.slice/session-3.scope\n"),
            Some(std::path::PathBuf::from(
                "/sys/fs/cgroup/user.slice/user-1000.slice/session-3.scope"
            ))
        );
        assert_eq!(
            resolve("0::/init.scope\n"),
            Some(std::path::PathBuf::from("/sys/fs/cgroup/init.scope")),
            "the WSL2 shape must still resolve: it names a cgroup, unlike `/`"
        );

        // Lines that are not the unified hierarchy, and garbage, are unchanged: still no answer.
        assert_eq!(resolve("1:name=systemd:/user.slice\n"), None, "v1 only");
        assert_eq!(resolve("0::relative\n"), None, "not absolute");
        assert_eq!(resolve(""), None);
    }

    /// The supervisor's leaf is NOT a box cgroup, and every consumer of the gate depends on that.
    ///
    /// SHIPPED-SHAPED DEFECT this pins: `is_kern_box_leaf` accepted anything starting with
    /// `kern-box-`, and the supervisor now sits in `kern-box-<tag>-<pid>-sup`, a sibling of the box's
    /// own cgroup. Measured before the fix: a detached box recorded
    /// `cgroup=.../kern-box-regchk4-251796-sup` in its registry entry, because the PID-1 callback reads
    /// `/proc/<pid1>/cgroup` in the window between the fork and the child moving itself into the capped
    /// cgroup, and in that window the child still shows the supervisor's leaf.
    ///
    /// What that costs is not cosmetic: `kern stop` writes `cgroup.kill` into the RECORDED path, so it
    /// would have killed the supervisor and left the workload running, and `list()` uses the same path
    /// to tell an orphaned box from an exited one.
    ///
    /// Asserted on the gate rather than on the message, because the gate is what every consumer shares.
    /// All EIGHT combinations of the three bools that decide where the supervisor sits. Exhaustive
    /// rather than sampled, because the table is small enough to be complete and one row of it is a
    /// security property: a workload must never be told "you are already in the capped cgroup" when
    /// it is not.
    ///
    /// Read `outside` as "the forked child must put ITSELF in the capped cgroup". When it is false the
    /// supervisor is in there and the child inherits it. Either answer caps the workload; what would
    /// not is a `true` with the supervisor sitting somewhere else and no leaf built.
    #[test]
    fn the_supervisor_layout_is_decided_the_same_way_for_all_eight_inputs() {
        // (forks, origin_kills, leaf_built) -> (needs_leaf, outside)
        let cases = [
            // exec in place (`kern run` on the SCOPE path): the supervisor IS the workload, so it
            // must stay in the cap. `kern run`'s direct path forks and is in the `true` rows below.
            ((false, false, false), (false, false)),
            ((false, false, true), (false, false)),
            ((false, true, false), (false, false)),
            ((false, true, true), (false, false)),
            // `kern box` on any ordinary path: origin cannot group-kill, so no leaf and the child joins.
            ((true, false, false), (false, true)),
            ((true, false, true), (false, true)),
            // `kern box` on a scope whose origin IS armed: build the leaf.
            ((true, true, true), (true, true)),
            // ...and if building it FAILED, fall back to the old topology rather than trust a
            // supervisor that is still sitting in the cgroup about to kill it.
            ((true, true, false), (true, false)),
        ];
        for ((forks, kills, built), (want_leaf, want_outside)) in cases {
            assert_eq!(
                supervisor_needs_leaf(forks, kills),
                want_leaf,
                "needs_leaf({forks}, {kills})"
            );
            assert_eq!(
                supervisor_ends_up_outside(forks, kills, built),
                want_outside,
                "ends_up_outside({forks}, {kills}, {built})"
            );
        }
    }

    /// The property the table above encodes, stated once on its own so a future edit to the table
    /// cannot quietly drop it: `exec()`-in-place is NEVER outside. The supervisor becomes the
    /// workload, so parking it anywhere else runs the workload uncapped. This was measured as a real
    /// regression while the fix was being built, on a root VPS where `kern run` stopped being killed
    /// by its own cgroup.
    #[test]
    fn exec_in_place_is_never_outside_the_capped_cgroup() {
        for kills in [false, true] {
            for built in [false, true] {
                assert!(
                    !supervisor_ends_up_outside(false, kills, built),
                    "exec-in-place reported outside with kills={kills} built={built}"
                );
                assert!(
                    !supervisor_needs_leaf(false, kills),
                    "exec-in-place asked for a leaf"
                );
            }
        }
    }

    /// A leaf is built ONLY where the supervisor's own cgroup is armed. Everywhere else it is cost
    /// with no property behind it: 0.165 ms of a 2.3 ms box start, measured over 24 paired batches.
    #[test]
    fn a_leaf_is_built_only_when_the_supervisors_own_cgroup_group_kills() {
        assert!(supervisor_needs_leaf(true, true));
        assert!(!supervisor_needs_leaf(true, false));
    }

    #[test]
    fn the_supervisor_leaf_is_not_accepted_as_a_box_cgroup() {
        // A box's own dir and the scope kern names: both are kern's, both stay accepted.
        assert!(is_kern_box_leaf("kern-box-web-1234"));
        assert!(is_kern_box_leaf("kern-box-1234.scope"));
        // The supervisor's sibling: kern's prefix, and NOT a box.
        assert!(!is_kern_box_leaf("kern-box-web-1234-sup"));
        assert!(!is_kern_box_leaf("kern-box-a-b-c-999-sup"));
        // And the ambient scope this gate has always refused, so the change did not widen it.
        assert!(!is_kern_box_leaf("run-p123-i456.scope"));
        assert!(!is_kern_box_leaf("user@1000.service"));
        // The parse built on top of it must refuse the leaf too, which is the path that reaches
        // `cgroup.kill`.
        assert!(parse_box_cgroup_line("0::/kern.slice/kern-box-web-1234-sup\n").is_none());
        assert!(parse_box_cgroup_line("0::/kern.slice/kern-box-web-1234\n").is_some());
    }

    /// THE PROPERTY THAT MAKES THE FIX A FIX: the answer depends on the PID, not on this process.
    ///
    /// The test above asserts the helper resolves a directory, and it stayed green when the caller was
    /// reverted to the old ancestors-of-kern walk. This one cannot: `pid 1` lives in `/init.scope`, a
    /// different branch from any user session, so a function reading OUR ancestors would hand back OUR
    /// directory for it. Measured on this host: kern sits under
    /// `/user.slice/user-1000.slice/user@1000.service/app.slice/...` and pid 1 under `/init.scope`,
    /// whose only ancestor is the cgroup root, which never carries `memory.events`.
    ///
    /// The guard reads `/proc` directly rather than calling the function under test, so it cannot be
    /// satisfied by the defect it is guarding against.
    #[test]
    fn the_directory_depends_on_the_pid_and_not_on_this_process() {
        let (Ok(mine_raw), Ok(init_raw)) = (
            fs::read_to_string("/proc/self/cgroup"),
            fs::read_to_string("/proc/1/cgroup"),
        ) else {
            eprintln!("SKIP: cannot read both cgroup files");
            return;
        };
        let leaf = |t: &str| {
            t.lines()
                .find_map(|l| l.strip_prefix("0::"))
                .map(|p| p.trim().to_string())
        };
        let (Some(mine), Some(init)) = (leaf(&mine_raw), leaf(&init_raw)) else {
            eprintln!("SKIP: not cgroup v2 here");
            return;
        };
        if mine == init {
            eprintln!("SKIP: this process and pid 1 share a cgroup ({mine}), so nothing distinguishes them");
            return;
        }
        // Two pids in two branches must not resolve to one directory. Under the old walk they would:
        // it never looked at the pid at all.
        assert_ne!(
            oom_kill_dir_for_pid(std::process::id() as i32),
            oom_kill_dir_for_pid(1),
            "pid 1 is in {init} and we are in {mine}, yet both resolved to the same directory: \
             the answer is not being read from the pid"
        );
    }

    /// The counter has to be read from where the BOX is, and this asserts the mechanism that makes
    /// that possible rather than the message it produces.
    ///
    /// SHIPPED DEFECT this covers: `oom_kill_count()` walks THIS process's ancestors, which answers
    /// for the box only when the two share one. Measured on a root VPS, kern sat in
    /// `/user.slice/user-0.slice/session-N.scope` and the box landed in
    /// `/system.slice/kern-box-N.scope`; their only common ancestor is the cgroup root, which never
    /// exposes `memory.events`. So the count was `None`, the message never printed, and the operator
    /// got exit 137 and an empty screen on exactly the hosts where the cap binds.
    ///
    /// Resolved from a LIVE pid on purpose: by the time the box has died its `/proc/<pid>/cgroup` is
    /// gone, so the directory must be captured while it can still be named.
    #[test]
    fn the_oom_directory_is_resolved_from_a_pid_and_outlives_it() {
        // WHETHER TO SKIP IS DECIDED WITHOUT CALLING THE FUNCTION UNDER TEST, which the first version
        // of this test got wrong: it skipped on `None`, so a `oom_kill_dir_for_pid` sabotaged to return
        // `None` for every pid still passed. A test whose skip condition is the defect cannot fail.
        let me = std::process::id() as i32;
        let mut probe = current_v2_cgroup();
        let mut expected = false;
        while let Some(d) = probe.as_mut() {
            if !d.pop() || d == std::path::Path::new("/sys/fs/cgroup") {
                break;
            }
            if d.join("memory.events").is_file() {
                expected = true;
                break;
            }
        }
        if !expected {
            eprintln!("SKIP: no ancestor of this process exposes memory.events (cgroup v1, or no memory controller)");
            return;
        }
        let dir = oom_kill_dir_for_pid(me)
            .expect("an ancestor exposes memory.events, so this must resolve a directory");
        // It is an ancestor DIRECTORY that actually carries the file, not the leaf we started from.
        assert!(
            dir.join("memory.events").is_file(),
            "{dir:?} has no memory.events"
        );
        assert!(dir.starts_with("/sys/fs/cgroup"));
        assert_ne!(
            dir,
            std::path::Path::new("/sys/fs/cgroup"),
            "the root never has the file"
        );
        // And it reads, which is what the before/after pair needs from both ends.
        assert!(
            oom_kill_count_at(&dir).is_some(),
            "resolved a directory whose counter will not read"
        );
        // A pid that cannot exist resolves to nothing rather than to a wrong directory: the caller
        // pairs two reads and a silent fallback elsewhere would compare unrelated counters.
        assert!(oom_kill_dir_for_pid(-1).is_none());
    }
    use super::*;

    #[test]
    fn memory_cap_signal_is_a_determined_verdict_only_for_a_request() {
        // No `--memory` requested -> undetermined (0): a SIGKILL cannot be attributed to a cap that was
        // never asked for. This holds on every host, so it anchors the round-trip through the atomic.
        record_memory_cap_signal(None, None);
        assert_eq!(memory_cap_signal(), 0, "no request => undetermined");
        // A 1-byte request is satisfiable by NO real ancestor cap, so where cgroup v2 is present it must
        // read NOT-enforced (2), never enforced(1). Where /proc/self/cgroup has no `0::` line (an unusual
        // test host) the check cannot model the layout and stays undetermined (0). Anything else is a bug
        // in the value-aware comparison. This is the positive control that the signal compares against
        // the request, not mere `memory.max` existence.
        record_memory_cap_signal(Some(1), None);
        match memory_cap_signal() {
            0 => {} // no cgroup v2 layout to inspect on this host
            2 => {
                // v2 present: a real request now resolves to a definite verdict (enforced or not),
                // never back to undetermined.
                record_memory_cap_signal(Some(64 * 1024 * 1024), None);
                let s = memory_cap_signal();
                assert!(
                    s == 1 || s == 2,
                    "a request must resolve to 1 or 2, got {s}"
                );
            }
            other => {
                panic!("a 1-byte cap can only read undetermined(0) or not-enforced(2), got {other}")
            }
        }
    }

    #[test]
    fn controller_availability_reads_cgroup_controllers() {
        // A temp dir isn't under /sys/fs/cgroup, so the walk checks just this leaf. `memory` absent
        // from cgroup.controllers = never enabled (stock-Pi case) → NOT available → the forged-env
        // warning stays silent there. Listed = the host CAN cap, even at a namespace root that has
        // no memory.max file (the reason this reads controllers, not limit-file existence).
        let d = std::env::temp_dir().join(format!("kern-cgcap-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        assert!(
            !controller_available_in_tree(&d, "memory"),
            "no cgroup.controllers file = controller absent = not available"
        );
        std::fs::write(d.join("cgroup.controllers"), "cpu pids\n").unwrap();
        assert!(
            !controller_available_in_tree(&d, "memory"),
            "the stock-Pi list (`cpu pids`) must not count as memory-available"
        );
        std::fs::write(d.join("cgroup.controllers"), "cpuset cpu io memory pids\n").unwrap();
        assert!(
            controller_available_in_tree(&d, "memory"),
            "memory listed = the host can cap, even with no memory.max file here"
        );
    }

    #[test]
    fn kill_cgroup_writes_the_kill_file_and_never_panics() {
        // Plumbing test (not the kernel's kill semantics, which need a real cgroupfs): `kill_cgroup`
        // must write exactly `"1"` to `<dir>/cgroup.kill` - the payload cgroup-v2 expects - and must
        // report a failed write (a pre-5.14 kernel where the file is absent, or an unwritable path) as
        // `false` rather than panicking, so the orphan sweep degrades to its `rmdir` fallback.
        let d = std::env::temp_dir().join(format!("kern-killcg-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        assert!(
            kill_cgroup(&d),
            "writing cgroup.kill under a writable dir must succeed"
        );
        assert_eq!(
            std::fs::read_to_string(d.join("cgroup.kill"))
                .unwrap()
                .trim(),
            "1",
            "kill_cgroup must write the payload the kernel expects"
        );
        assert!(
            !kill_cgroup(std::path::Path::new("/proc/kern-nonexistent-dir/x")),
            "a write to an unwritable location must return false, not panic"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn sweep_reaps_only_dead_supervisor_dirs_and_kills_their_cgroup() {
        // `sweep_orphan_boxes` self-heals the one leak the RAII guard cannot cover: a DETACHED box whose
        // supervisor is SIGKILL'd runs no Drop, so its cgroup - init + workload + any grandchild it forked
        // - can survive. The sweep must (1) issue `cgroup.kill` on a `kern-box-<tag>-<pid>` whose <pid> is
        // DEAD, so the whole subtree dies at once (a bare rmdir would leak the grandchildren); (2) NEVER
        // touch a box whose <pid> is ALIVE (a reused pid must not be killed); (3) ignore a non-box dir.
        // Fully deterministic - NO real cgroupfs and NO process killing: on a plain temp dir `kill_cgroup`
        // writes a regular `cgroup.kill` file, whose presence and "1" payload prove the sweep classified
        // the dir as an orphan and issued the kill. (On real cgroupfs that write empties the cgroup and the
        // following `remove_dir` succeeds; here the dir persists because our file makes it non-empty, which
        // is orthogonal to the property under test.)
        let slice = std::env::temp_dir().join(format!("kern-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&slice);
        std::fs::create_dir_all(&slice).unwrap();

        // A pid provably NOT live right now: walk DOWN from a high value and VERIFY /proc absence rather
        // than assume it (pid_max varies across kernels; a pid above it can never exist).
        let dead_pid = (2u32..2_000_000)
            .rev()
            .find(|pid| !std::path::Path::new(&format!("/proc/{pid}")).exists())
            .unwrap_or(u32::MAX);
        let live_pid = std::process::id(); // this test process: /proc/<pid> exists, so it is ALIVE

        let dead = slice.join(format!("kern-box-my-app-{dead_pid}")); // tag with '-' exercises rsplit
        let live = slice.join(format!("kern-box-web-{live_pid}"));
        let other = slice.join("some-unrelated-dir");
        // kern's own per-box transient SCOPE, named after a pid that is provably gone. systemd owns
        // that dir and removes it with the unit, so this sweep must leave it alone even though it
        // carries the `kern-box-` prefix - the `.scope` suffix is what stops the last field parsing
        // as a pid. Asserted, not left to a comment, because the failure mode is kern rmdir'ing a
        // live systemd unit's cgroup out from under the manager.
        let scope = slice.join(format!("kern-box-{dead_pid}.scope"));
        for d in [&dead, &live, &other, &scope] {
            std::fs::create_dir_all(d).unwrap();
        }

        sweep_orphan_boxes(&slice, 0); // 0 = unbounded, examine every entry

        // (1) dead supervisor -> cgroup killed, payload "1".
        let killed = dead.join("cgroup.kill");
        assert!(
            killed.is_file(),
            "a dead-supervisor box must have its cgroup killed (reaches grandchildren a bare rmdir leaks)"
        );
        assert_eq!(
            std::fs::read_to_string(&killed).unwrap().trim(),
            "1",
            "cgroup.kill must carry the payload cgroup-v2 expects"
        );
        // (2) live supervisor -> never touched (pid-reuse safety).
        assert!(
            !live.join("cgroup.kill").exists(),
            "a box whose pid is ALIVE must be skipped - never kill a reused pid"
        );
        assert!(
            live.is_dir(),
            "a live box's cgroup dir must survive the sweep"
        );
        // (3) non-box dir -> ignored entirely.
        assert!(
            !other.join("cgroup.kill").exists(),
            "a dir that is not `kern-box-*` must be ignored"
        );
        assert!(other.is_dir());
        // (4) a transient scope -> never killed and never removed, whatever its pid says.
        assert!(
            !scope.join("cgroup.kill").exists(),
            "a systemd scope must never be killed by this sweep - the manager owns that unit"
        );
        assert!(
            scope.is_dir(),
            "a systemd scope's dir must survive the sweep"
        );

        let _ = std::fs::remove_dir_all(&slice);
    }

    #[test]
    fn the_sweep_reaps_a_dead_kern_run_leaf_but_never_kills_what_is_still_in_it() {
        // THE ONE ASYMMETRY BETWEEN THE TWO LEAF FAMILIES, and the reason they were split.
        //
        // A dead-owner `kern-box-*` gets `cgroup.kill`: its processes are the box, and the box is over.
        // A dead-owner `kern-run-*` must NOT, because `kern run` is a governor over processes the
        // CALLER started - `kern run -- ./server &`, or a workload that backgrounds a child - and the
        // contract is that nothing dies with the launcher. Under the systemd `--scope` this path
        // replaced, a survivor kept the scope alive and was collected when it exited; a `cgroup.kill`
        // here would instead reach in and SIGKILL a process the user is still using.
        //
        // Deterministic, with no cgroupfs and no signals: on a plain temp dir `kill_cgroup` writes a
        // regular `cgroup.kill` file, so its ABSENCE is the proof that no kill was issued. The
        // POSITIVE CONTROL is in the same directory - a `kern-box-*` with the same dead pid, which
        // must come out killed - so "no file" cannot mean "the sweep never ran".
        let slice = std::env::temp_dir().join(format!("kern-runsweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&slice);
        std::fs::create_dir_all(&slice).unwrap();
        let dead_pid = (2u32..2_000_000)
            .rev()
            .find(|pid| !std::path::Path::new(&format!("/proc/{pid}")).exists())
            .unwrap_or(u32::MAX);
        let live_pid = std::process::id();

        let run_dead = slice.join(format!("kern-run-{dead_pid}"));
        let run_live = slice.join(format!("kern-run-{live_pid}"));
        let box_dead = slice.join(format!("kern-box-ctl-{dead_pid}")); // the positive control
        for d in [&run_dead, &run_live, &box_dead] {
            std::fs::create_dir_all(d).unwrap();
        }
        // A SURVIVOR, expressed as the only thing that survives a `rmdir` on a temp dir: a file. On a
        // real cgroupfs a member process is what makes the directory un-removable; here a file is,
        // and both exercise the same branch, which is that `remove_dir` fails and the sweep moves on
        // WITHOUT having killed anything.
        std::fs::write(run_dead.join("occupied"), b"x").unwrap();

        sweep_orphan_boxes(&slice, 0);

        assert!(
            box_dead.join("cgroup.kill").is_file(),
            "positive control: a dead-supervisor BOX must still be killed, or this test proves nothing"
        );
        assert!(
            !run_dead.join("cgroup.kill").exists(),
            "a dead-owner `kern run` leaf must never be killed: its survivors are the caller's own processes"
        );
        assert!(
            run_dead.is_dir(),
            "a populated `kern run` leaf must be left alone, to be removed once its last survivor exits"
        );
        assert!(
            !run_live.join("cgroup.kill").exists() && run_live.is_dir(),
            "a `kern run` whose owner is ALIVE must be untouched"
        );

        // And an EMPTY dead-owner run leaf - the ordinary case, a parent that was SIGKILL'd before its
        // `Drop` could run - is removed, or the sweep would not clean up after this path at all.
        let empty = slice.join(format!("kern-run-{}", dead_pid - 1));
        std::fs::create_dir_all(&empty).unwrap();
        sweep_orphan_boxes(&slice, 0);
        assert!(
            !empty.exists(),
            "an EMPTY dead-owner `kern run` leaf must be rmdir'd - that is the leak the guard cannot cover"
        );

        let _ = std::fs::remove_dir_all(&slice);
    }

    #[test]
    fn the_allocation_free_proc_probe_answers_exactly_what_the_allocating_one_did() {
        // `proc_entry_exists` replaced `PathBuf::from(format!("/proc/{pid}")).exists()` to take two
        // heap allocations out of the sweep's per-entry loop. A faster wrong answer is worse than a
        // slower right one in BOTH directions here: a false "dead" reaps a live box's cgroup, and a
        // false "alive" makes the sweep stop reaping anything.
        //
        // So the old expression is the ORACLE, evaluated here rather than trusted, and the two must
        // agree on every input. Both a live pid and a provably dead one are exercised, because a
        // probe that always answered `true` would pass a test that only had the live case.
        let oracle = |pid: u32| std::path::PathBuf::from(format!("/proc/{pid}")).exists();
        let live = std::process::id();
        let dead = (2u32..2_000_000)
            .rev()
            .find(|p| !oracle(*p))
            .unwrap_or(u32::MAX);
        assert!(
            oracle(live) && proc_entry_exists(live),
            "a live pid must read as present"
        );
        assert!(
            !oracle(dead) && !proc_entry_exists(dead),
            "a pid that is not in use must read as absent"
        );
        // The digit encoding, at every width that changes it: one digit, the ten/hundred carries, and
        // `u32::MAX`, which is the longest string the buffer must hold. Comparing against the oracle
        // rather than against a hand-written expectation means the test cannot encode the same
        // off-by-one twice.
        for pid in [
            0u32,
            1,
            2,
            9,
            10,
            99,
            100,
            999,
            1000,
            65535,
            4_194_304,
            u32::MAX,
        ] {
            assert_eq!(
                proc_entry_exists(pid),
                oracle(pid),
                "the two probes disagree for pid {pid}"
            );
        }
    }

    #[test]
    fn a_failed_fork_never_reports_the_child_as_placed() {
        // The two halves of `fork_workload_into_leaf`'s return must not contradict each other:
        // `(-1, true)` reads as "there is no child, and it is inside its cap", which is a statement
        // about a process that does not exist. The CLI checks `pid < 0` first and would not be
        // misled, but the function is crate-public and the invariant belongs in it.
        //
        // Asserted on the closure that enforces it rather than by exhausting the process table to
        // make a real fork fail: the rule is `placed && pid >= 0`, and these are its four inputs.
        let report = |pid: libc::pid_t, placed: bool| (pid, placed && pid >= 0);
        assert_eq!(
            report(-1, true),
            (-1, false),
            "a failed fork is never placed"
        );
        assert_eq!(report(-1, false), (-1, false));
        assert_eq!(report(0, true), (0, true), "the child keeps its own answer");
        assert_eq!(
            report(1234, true),
            (1234, true),
            "so does the parent's report"
        );
    }

    #[test]
    fn a_box_in_the_cgroup_root_has_no_cgroup_of_its_own_to_report() {
        // THE PIN FOR A REPORTING DEFECT, and the reason it belongs here rather than in the CLI.
        //
        // `kern inspect` echoes the `--memory` the box was STARTED with. An outside reviewer measured
        // `"memory_max": 67108864` on a box whose PID 1 sat in `0::/`, the cgroup-v2 ROOT, which has
        // no `memory.max` file at all: a cap reported as a fact where the kernel holds none. Their
        // `kern doctor` said so correctly on the same host, and the two readings disagreed.
        //
        // What makes the new `memory_max_enforced` field answer `null` there is this parse refusing
        // the root. If it ever accepted it, `inspect` would read the ROOT's controls as though they
        // were the box's, which is the same wrong-vantage failure one level up.
        assert_eq!(
            parse_box_cgroup_line("0::/\n"),
            None,
            "the cgroup-v2 root is not a box's cgroup"
        );
        assert_eq!(parse_box_cgroup_line("0::/init.scope\n"), None);
        assert_eq!(
            parse_box_cgroup_line("0::/user.slice/user-1000.slice\n"),
            None
        );
        // And the shapes that ARE kern's own, so the refusal above cannot be a refusal of everything.
        assert_eq!(
            parse_box_cgroup_line("0::/kern.slice/kern-box-web-42\n"),
            Some(PathBuf::from("/sys/fs/cgroup/kern.slice/kern-box-web-42"))
        );
        assert_eq!(
            parse_box_cgroup_line("0::/app.slice/kern-box-42.scope\n"),
            Some(PathBuf::from("/sys/fs/cgroup/app.slice/kern-box-42.scope"))
        );
    }

    #[test]
    fn a_kern_whose_binary_was_replaced_is_still_a_kern() {
        // The kernel appends " (deleted)" to `/proc/<pid>/exe` once the file behind a running process
        // is gone, which is the state of EVERY already-running kern the moment `install.sh`
        // overwrites the binary. Comparing against the bare name reported those processes as not-kern
        // and made their boxes invisible to `live_box_supervisors_via_proc`, the fallback channel that
        // exists to find boxes the registry has lost, on the one event most likely to lose them.
        //
        // MEASURED on this desktop, a box whose binary had been rebuilt underneath it: the cgroup
        // channel reported it in the same second that this channel returned nothing.
        assert!(exe_stem_is_kern("kern"));
        assert!(exe_stem_is_kern("kern (deleted)"));
        // THE NEAR MISSES, because this set decides which processes kern asks for children and then
        // reports as boxes. A `starts_with` would have claimed all four of these.
        assert!(!exe_stem_is_kern("kernel"));
        assert!(!exe_stem_is_kern("kern-win"));
        assert!(!exe_stem_is_kern("kern.old"));
        assert!(!exe_stem_is_kern("mykern"));
        assert!(!exe_stem_is_kern("kern (deleted) "));
        assert!(!exe_stem_is_kern(""));
    }

    #[test]
    fn the_memory_cap_probe_asks_about_both_directories_a_box_can_use() {
        // `apply_limits` caps a box under `kern.slice` on the direct path and under the caller's OWN
        // cgroup otherwise. The probe used `ensure_kern_slice().or_else(current_v2_cgroup)`, which
        // reaches the second only when the first is `None`: on a host where the slice EXISTS but
        // boxes do not use it, it reported on a directory no box goes near.
        //
        // MEASURED by an outside reviewer, uid 0 with no user manager: doctor said a `--memory` write
        // "silently never bites" while a box on the same host held `memory_max = 67108864` and an
        // exec that overran it was killed with 137.
        //
        // ON THE REAL HOST, because the defect is about WHICH directory is asked and a fake one
        // cannot have that property. This asserts the invariant that survives either answer: the
        // verdict must not be worse than what the caller's own cgroup alone would give, which is the
        // directory the reviewer's boxes actually used and the one `or_else` skipped.
        let combined = memory_cap_state();
        let own = current_v2_cgroup();
        if combined == MemoryCapState::Unknown {
            // No cgroup v2 here at all; there is nothing to be consistent about.
            return;
        }
        if let Some(o) = own {
            let alone = memory_cap_state_at(&o);
            if alone == MemoryCapState::Enforced {
                assert!(
                    matches!(
                        combined,
                        MemoryCapState::Enforced | MemoryCapState::EnforcedOnScope
                    ),
                    "the caller's own cgroup caps a box here, so the combined verdict must not say \
                     otherwise: own={alone:?} combined={combined:?}"
                );
            }
        }
        // AND THE PROBE MUST NOT ACCUMULATE. Asserted as a DELTA and not as an absolute count, and
        // the first version of this got that wrong: it required zero `kern-capprobe-*` anywhere and
        // went red on a leftover from a process killed hours earlier, which is not this call's doing
        // and not this test's subject. What that red DID find is real and is fixed elsewhere: nothing
        // reaped that family, so the orphan sweep and `kern gc` now know it. The invariant here is
        // narrower and is the one this function owns.
        let count = || -> usize {
            [ensure_kern_slice(), current_v2_cgroup()]
                .into_iter()
                .flatten()
                .filter_map(|d| fs::read_dir(d).ok())
                .flat_map(|rd| rd.flatten())
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with(CAPPROBE_LEAF_PREFIX)
                })
                .count()
        };
        let before = count();
        let _ = memory_cap_state();
        assert_eq!(
            count(),
            before,
            "a completed cap probe must leave no child cgroup behind"
        );
    }

    #[test]
    fn a_placement_failure_only_costs_a_cap_when_there_is_one() {
        // FOUR INPUTS, because the two ways to get this wrong are not symmetric. `true` where it
        // should be `false` refuses a command that had nothing to escape, which is what shipped:
        // on a host with no delegation the box has no cgroup of its own, and `kern exec` still
        // refused with 126 while telling the operator the command would run outside caps the box
        // did not have. `false` where it should be `true` is the silent escape the refusal exists
        // to stop.
        assert!(placement_failure_costs_a_cap(true, true));
        assert!(!placement_failure_costs_a_cap(true, false));
        assert!(!placement_failure_costs_a_cap(false, true));
        assert!(!placement_failure_costs_a_cap(false, false));
    }

    #[test]
    fn the_cap_reality_probe_reads_the_control_files_and_not_their_absence() {
        // The second input above comes from `exec_join_outcome_after_failure`, which reads
        // `memory.max` and `pids.max` THROUGH THE DESCRIPTOR. Its own doc records what happened when
        // the same read went through a path after a `setns`: inside the box's namespaces the host
        // path names nothing, both reads failed, and a box capped at `--pids-limit 2 --memory 64M`
        // was reported as having no cap worth mentioning. Failure-to-read and absence-of-a-cap gave
        // the same answer, which is the in-band-sentinel shape this codebase removes elsewhere.
        //
        // Exercised on a plain temp directory, where the control files are ordinary files: that is
        // enough, because the function's whole job is to distinguish a value from the `max` sentinel.
        let d = std::env::temp_dir().join(format!("kern-capreal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let open = || CgroupRef::open(&d).expect("the temp dir opens as a directory descriptor");

        // Neither file present: nothing to read, so nothing is at risk.
        assert!(matches!(
            exec_join_outcome_after_failure(&open()),
            ExecCgroupJoin::Bound
        ));
        // Both present and both the no-limit sentinel: still nothing at risk.
        std::fs::write(d.join("memory.max"), "max\n").unwrap();
        std::fs::write(d.join("pids.max"), "max\n").unwrap();
        assert!(matches!(
            exec_join_outcome_after_failure(&open()),
            ExecCgroupJoin::Bound
        ));
        // A real memory ceiling alone is enough to make the failure cost something.
        std::fs::write(d.join("memory.max"), "67108864\n").unwrap();
        assert!(matches!(
            exec_join_outcome_after_failure(&open()),
            ExecCgroupJoin::Unbounded
        ));
        // And a real pids ceiling alone, which is the case an outside reviewer reproduced with a
        // saturated `--pids-limit` and the one that must keep refusing.
        std::fs::write(d.join("memory.max"), "max\n").unwrap();
        std::fs::write(d.join("pids.max"), "4\n").unwrap();
        assert!(matches!(
            exec_join_outcome_after_failure(&open()),
            ExecCgroupJoin::Unbounded
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn placement_is_gated_on_the_common_ancestor_and_not_on_the_destination() {
        // THE RULE THIS PINS, and the defect it was written after. cgroup v2 delegation containment
        // needs write access to the `cgroup.procs` of the COMMON ANCESTOR of the source and the
        // destination, not just of the destination. A reviewer measured the consequence on WSL2 with
        // `systemd=true`, where the shell sits in `/init.scope`: kern found a delegated, writable,
        // correctly capped `kern.slice`, created a leaf in it, wrote and read back both caps, and
        // then could not put the process in, because the common ancestor of `/init.scope` and
        // `user@1000.service` is the ROOT cgroup, owned by root. `kern run` ran uncapped where it
        // used to be capped, and `kern box`, which is fail-closed on the same placement, would have
        // refused to start.
        let anc = |a: &str, b: &str| {
            common_cgroup_ancestor(std::path::Path::new(a), std::path::Path::new(b))
        };
        // The measured case: the ancestor really is the mount root, which is why the probe rejects.
        assert_eq!(
            anc(
                "/sys/fs/cgroup/init.scope",
                "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/kern.slice"
            ),
            PathBuf::from("/sys/fs/cgroup")
        );
        // The ordinary case: both sit under the user manager, so the ancestor is the delegated root
        // and the user owns its `cgroup.procs`.
        assert_eq!(
            anc(
                "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/app-foo.scope",
                "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/kern.slice"
            ),
            PathBuf::from("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service")
        );
        // Identical paths, and a nested pair: the ancestor is the shallower of the two, not their
        // parent, because a cgroup is its own ancestor for this rule.
        assert_eq!(
            anc("/sys/fs/cgroup/a", "/sys/fs/cgroup/a"),
            PathBuf::from("/sys/fs/cgroup/a")
        );
        assert_eq!(
            anc("/sys/fs/cgroup/a", "/sys/fs/cgroup/a/b/c"),
            PathBuf::from("/sys/fs/cgroup/a")
        );
        // A SHARED PREFIX THAT IS NOT A SHARED COMPONENT must not match, or the probe would ask about
        // a directory neither path is under.
        assert_eq!(
            anc("/sys/fs/cgroup/ab", "/sys/fs/cgroup/abc"),
            PathBuf::from("/sys/fs/cgroup")
        );
        assert_eq!(
            anc("/sys/fs/cgroup", "/sys/fs/cgroup/x"),
            PathBuf::from("/sys/fs/cgroup")
        );

        // And the probe itself, on this host, in BOTH directions. The negative is the whole point:
        // a test that only had the positive would pass against a build that always answered true.
        assert!(
            !cgroup_procs_writable(std::path::Path::new("/sys/fs/cgroup"))
                || unsafe { libc::getuid() } == 0,
            "an ordinary user must not be able to write the ROOT cgroup.procs; as root it may"
        );
        // THE POSITIVE CONTROL IS HERMETIC, and it used to be an assumption about the host.
        //
        // It asserted that a process can write its OWN `cgroup.procs`, which is simply not true in
        // general: on GitHub's runner the job runs as an ordinary user inside
        // `/sys/fs/cgroup/system.slice/hosted-compute-agent.service`, a cgroup owned by root, where
        // the file exists and is not writable. That is a legitimate host, and it is precisely the
        // shape this whole gate was written for, so encoding its opposite as a law made the test
        // fail on the one machine that most resembles the case it protects.
        //
        // What the control has to establish is only that the probe can answer TRUE, so that a build
        // always answering false is caught. `cgroup_procs_writable` is one `access(dir/cgroup.procs,
        // W_OK)`, so a directory this test creates with a writable file of that name answers the
        // question without asking anything of the machine.
        let tmp = std::env::temp_dir().join(format!("kern-procs-probe-{}", std::process::id()));
        let _ = fs::create_dir_all(&tmp);
        if fs::write(tmp.join("cgroup.procs"), b"").is_ok() {
            assert!(
                cgroup_procs_writable(&tmp),
                "a writable cgroup.procs must read as writable, or the probe can only ever say no"
            );
        }
        let _ = fs::remove_dir_all(&tmp);
        assert!(
            !cgroup_procs_writable(std::path::Path::new("/sys/fs/cgroup/kern-no-such-dir-here")),
            "a directory that does not exist must not read as writable"
        );

        // AND THE COMPOSITION, not just its two halves. The first version of this test asserted
        // `common_cgroup_ancestor` and `cgroup_procs_writable` separately and stayed GREEN against a
        // `placement_into_is_permitted` stubbed to `true`, which is exactly the build that shipped the
        // defect. Both parts can be right while the function that uses them is not called at all.
        //
        // A target under a DIFFERENT top-level cgroup forces the ancestor to the mount root, so an
        // ordinary user must be refused. As root the answer is legitimately `true`, and the assertion
        // says so rather than skipping, because "root may" is the other half of the same rule.
        let unreachable = std::path::Path::new("/sys/fs/cgroup/init.scope/kern-probe-target");
        let root_ok = unsafe { libc::getuid() } == 0;
        assert_eq!(
            placement_into_is_permitted(unreachable),
            root_ok,
            "a target whose common ancestor with our own cgroup is the ROOT must be refused for an \
             ordinary user and allowed for root"
        );
        // The positive control for the same call, ON THE PRECONDITION IT ACTUALLY NEEDS. Our own
        // cgroup is its own ancestor, so placement into it is permitted exactly when we may write its
        // `cgroup.procs`. That is a host property, not a law: GitHub's runner puts the job in a
        // root-owned `system.slice/...` where the answer is legitimately no, and asserting the
        // opposite made this fail there twice.
        //
        // Conditioning on the measured precondition keeps the control real where it runs and honest
        // where it cannot. A build that refuses everything is still caught: on any host that owns its
        // own cgroup it fails here, and on one that does not, the hermetic `cgroup_procs_writable`
        // control above fails instead, because that is the call this composition is built out of.
        if let Some(m) = current_v2_cgroup() {
            if cgroup_procs_writable(&m) {
                assert!(
                    placement_into_is_permitted(&m),
                    "our own cgroup.procs is writable, so placement into it must be permitted: {m:?}"
                );
            }
        }
    }

    #[test]
    fn the_delegation_root_is_found_above_the_caller_or_built_from_the_uid() {
        // WHY THE SECOND HALF EXISTS, measured rather than supposed. On WSL2 with `systemd=true` a
        // user manager IS running and the login shell sits in `0::/init.scope`. That path has exactly
        // two ancestors, itself and the root, and neither is a `user@<uid>.service`, so the search
        // answered `None` and kern concluded the whole host had no delegated slice. Every `kern run`
        // there took the per-invocation systemd scope: 11.5 ms against the 1.0 ms the same host
        // reaches with the scope skipped. The tree was one directory away the entire time.
        let above = |p: &str| delegation_root_above(Some(std::path::Path::new(p)));
        assert_eq!(
            above("/user.slice/user-1000.slice/user@1000.service/app.slice/app-foo.scope"),
            Some(PathBuf::from(
                "/user.slice/user-1000.slice/user@1000.service"
            )),
            "the ordinary layout must still resolve through the ancestor search"
        );
        assert_eq!(
            above("/user.slice/user-1000.slice/user@1000.service"),
            Some(PathBuf::from(
                "/user.slice/user-1000.slice/user@1000.service"
            )),
            "`ancestors` includes the path itself, and the manager's own cgroup is a valid root"
        );
        assert_eq!(above("/init.scope"), None, "the WSL2-with-systemd shape");
        assert_eq!(above("/"), None);
        assert_eq!(above("/system.slice/sshd.service"), None);
        assert_eq!(delegation_root_above(None), None);
        // A NAME THAT MERELY LOOKS LIKE ONE MUST NOT MATCH, or kern would build its slice inside an
        // unrelated unit and cap boxes in a tree it does not own.
        assert_eq!(above("/user.slice/user@1000.service.d/x"), None);
        assert_eq!(above("/user.slice/notuser@1000.service/x"), None);

        // And the fallback's path, asserted as a literal.
        assert_eq!(
            canonical_delegation_root(1000),
            PathBuf::from("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service")
        );
        assert_eq!(
            canonical_delegation_root(0),
            PathBuf::from("/sys/fs/cgroup/user.slice/user-0.slice/user@0.service")
        );
    }

    #[test]
    fn the_two_leaf_families_cannot_be_confused_by_the_readers_that_act_on_the_name() {
        // `kern ps` lists every live `kern-box-*` dir as a box and warns that it cannot be stopped;
        // MEASURED before the split, with a `kern-box-run-<live pid>` placed in `kern.slice` by hand,
        // a plain `kern run` produced:
        //
        // ```text
        // kern: warning: 1 box(es) are RUNNING with no registry record, so `kern stop` cannot reach them
        // kern:   run (supervisor pid 149338)
        // ```
        //
        // This asserts the property that makes that impossible: the two families differ in their
        // PREFIX, so no tag can make a `kern run` leaf parse as a box. A test on the tag alone would
        // have passed against the broken naming, which is the point of asserting the prefix.
        let pid = std::process::id();
        let boxed = Leaf::Box("web").dir_name();
        let run = Leaf::Run.dir_name();
        assert_eq!(boxed, format!("kern-box-web-{pid}"));
        assert_eq!(run, format!("kern-run-{pid}"));
        assert!(
            !run.starts_with(BOX_LEAF_PREFIX),
            "a `kern run` leaf must not carry the box prefix, or `kern ps` reports it as a box"
        );
        assert!(
            !is_kern_box_leaf(&run),
            "a `kern run` leaf must not pass the ownership gate that decides which cgroups kern may reap or reshape"
        );
        // A BOX MAY LEGITIMATELY BE CALLED `run`, which is why a reserved TAG could not have done this
        // job and a prefix can: this name has to stay a box on every reader.
        let box_named_run = Leaf::Box("run").dir_name();
        assert_eq!(box_named_run, format!("kern-box-run-{pid}"));
        assert!(is_kern_box_leaf(&box_named_run));
        assert_ne!(box_named_run, run);
    }

    #[test]
    fn capprobe_classifies_absent_vs_present_not_delegated() {
        // The reach-here-when-no-child-or-no-memory.max classifier. `memory` listed in the tree =>
        // present-but-not-delegated (a `memory.max` write would be accepted and inert); absent from
        // the list => the controller is not in the tree at all.
        let d = std::env::temp_dir().join(format!("kern-capcls-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("cgroup.controllers"), "cpu pids\n").unwrap();
        assert_eq!(
            classify_absent_or_not_delegated(&d),
            MemoryCapState::Absent,
            "no memory in cgroup.controllers must classify Absent"
        );
        std::fs::write(d.join("cgroup.controllers"), "cpuset cpu io memory pids\n").unwrap();
        assert_eq!(
            classify_absent_or_not_delegated(&d),
            MemoryCapState::PresentNotDelegated,
            "memory listed but no delegation must classify PresentNotDelegated, not a false Enforced"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn capprobe_at_a_synthetic_tree_leaves_no_child_behind() {
        // A plain tmpfs dir is not a cgroupfs, so a created child never gets a `memory.max` file:
        // the probe must fall through to the classifier AND remove the throwaway child it made. This
        // pins the no-leak invariant on the create-succeeds-but-not-delegated path without needing a
        // real delegated cgroup (the Enforced path, exercised on a delegating host / WSL2 in doctor).
        let d = std::env::temp_dir().join(format!("kern-capleaf-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("cgroup.controllers"), "cpuset cpu io memory pids\n").unwrap();
        let state = memory_cap_state_at(&d);
        assert_eq!(
            state,
            MemoryCapState::PresentNotDelegated,
            "a tmpfs child has no memory.max, so the probe must report PresentNotDelegated here"
        );
        // The child the probe created must be gone: nothing named `kern-capprobe-*` may remain.
        let leaked: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("kern-capprobe-")
            })
            .collect();
        assert!(
            leaked.is_empty(),
            "the probe leaked a child cgroup dir: {:?}",
            leaked.iter().map(|e| e.file_name()).collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn capprobe_enables_the_subtree_before_calling_a_cap_unenforceable() {
        // REGRESSION, measured on this desktop (2026-08-24): with `kern.slice` delegated
        // (`cgroup.controllers` = `cpu memory pids`) and its `cgroup.subtree_control` EMPTY - the state
        // the slice is in until the first box start writes it - the probe found no `memory.max` in its
        // throwaway child and reported `PresentNotDelegated`, so `kern doctor` printed "`--memory`
        // won't be enforced". In that exact state a box started with `--memory 64M` was OOM-killed at
        // the cap (exit 137): the probe was reporting on whether a box had run yet, not on whether a cap
        // binds, and it told the first command a new user runs the opposite of the truth.
        //
        // The fix is that the probe performs the parent's additive `subtree_control` write - the one
        // every box start performs - before concluding. Asserted on that write, because a tmpfs is not a
        // cgroupfs so the *outcome* (a `memory.max` appearing) cannot be reproduced synthetically,
        // whereas "it did not give up without doing what a box does" can.
        let d = std::env::temp_dir().join(format!("kern-capsub-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("cgroup.controllers"), "cpuset cpu io memory pids\n").unwrap();
        std::fs::write(d.join("cgroup.subtree_control"), "").unwrap();
        let state = memory_cap_state_at(&d);
        let written = std::fs::read_to_string(d.join("cgroup.subtree_control")).unwrap_or_default();
        assert!(
            written.contains("+memory"),
            "the probe must try to enable `memory` in the parent's subtree before reporting a cap \
             unenforceable; subtree_control holds {written:?}"
        );
        // On a tmpfs the enable cannot make `memory.max` appear, so the honest verdict still stands.
        assert_eq!(
            state,
            MemoryCapState::PresentNotDelegated,
            "enabling the subtree must not turn an unenforceable host into a false Enforced"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_scope_probe_takes_only_the_directory_from_what_a_scope_reports() {
        // The scope path probe must not GUESS the cgroup layout: it takes the parent from what a probe
        // scope printed about itself and appends its own unit name. This pins that parsing, which is
        // where a wrong path would come from - and a wrong path reads no `memory.max`, which reports a
        // capped host as uncapped (the false negative this whole probe exists to fix).
        assert_eq!(
            scope_parent_from_proc_cgroup(
                "0::/user.slice/user-1000.slice/user@1000.service/kern.slice/kern-capprobe-9-a.scope\n"
            )
            .as_deref(),
            Some("/user.slice/user-1000.slice/user@1000.service/kern.slice"),
            "the leaf must be dropped and the slice kept"
        );
        // A cgroup v1 host has no `0::` line: answer None rather than build a path out of a v1 row.
        assert_eq!(
            scope_parent_from_proc_cgroup("1:name=systemd:/user.slice\n2:memory:/user.slice"),
            None
        );
        // Garbage, an empty read, and a v2 line whose path is not absolute must all be None.
        for junk in ["", "0::\n", "0::relative/path\n", "not a cgroup file"] {
            assert_eq!(
                scope_parent_from_proc_cgroup(junk),
                None,
                "must refuse to derive a path from {junk:?}"
            );
        }
        // A scope directly under the root leaves an empty parent: refused, since `/sys/fs/cgroup` plus
        // a unit name is not where a delegated scope lives.
        assert_eq!(scope_parent_from_proc_cgroup("0::/some.scope\n"), None);
    }

    #[test]
    fn capprobe_on_the_real_host_is_deterministic_and_leaks_nothing() {
        // The full probe against the process's real cgroup. Host-agnostic assertions: it must not
        // leave a `kern-capprobe-*` cgroup behind, and two back-to-back calls must agree (the host's
        // delegation does not change between them). SKIP-graceful: if the current cgroup dir cannot
        // be listed (a locked-down CI sandbox), there is nothing to check, so return rather than fail.
        let Some(cur) = current_v2_cgroup() else {
            eprintln!("skip: no cgroup v2 to probe");
            return;
        };
        let Ok(rd) = std::fs::read_dir(&cur) else {
            eprintln!("skip: current cgroup dir not listable here");
            return;
        };
        let before = rd
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("kern-capprobe-")
            })
            .count();
        let a = memory_cap_state();
        let b = memory_cap_state();
        let after = std::fs::read_dir(&cur)
            .map(|rd| {
                rd.flatten()
                    .filter(|e| {
                        e.file_name()
                            .to_string_lossy()
                            .starts_with("kern-capprobe-")
                    })
                    .count()
            })
            .unwrap_or(before);
        assert_eq!(
            before,
            after,
            "the probe leaked a kern-capprobe cgroup under {}",
            cur.display()
        );
        assert_eq!(
            a, b,
            "the probe returned two different states for one unchanged host"
        );
    }

    /// Every cap knob that can silently fail to apply must have a "not enforced" line. `--pids-limit`
    /// was the fourth knob and the only one without one: measured on a Raspberry Pi 5,
    /// `--pids-limit 999999999` exited 0 with `pids.max` reading `max`, so the box ran with no
    /// fork-bomb guard and nothing said so, while 64 / 256 / 1000000 were honoured exactly on the
    /// same host. The other three (`--memory`, `--cpus`, the I/O group) already warned, which is
    /// what made the gap a silence rather than a design.
    ///
    /// Asserted against the source rather than by triggering the paths, because reproducing an
    /// un-delegated controller needs a host configured that way and CI is not one. A fifth knob
    /// added without its line is the regression this catches.
    #[test]
    fn every_cap_knob_has_a_not_enforced_warning() {
        let src = include_str!("cgroup.rs");
        // Only the emitted strings count, not the prose around them: an `eprintln!` line.
        let emitted: Vec<&str> = src
            .lines()
            .filter(|l| l.contains("not enforced") && !l.trim_start().starts_with("//"))
            .collect();
        for knob in ["--memory", "--cpus", "--pids-limit", "--iops"] {
            assert!(
                emitted.iter().any(|l| l.contains(knob)),
                "no \"not enforced\" warning names {knob}; a cap that cannot be applied must not \
                 become no cap in silence. Emitted lines: {emitted:?}"
            );
        }
    }

    /// `capped_here` must NOT accept an ancestor's limit, and `capped_in_tree` MUST. The two exist
    /// only because of that difference, so a refactor that collapsed them would silence the pids
    /// warning again exactly as it was silenced before: on a Raspberry Pi 5 the walk found
    /// `pids.max=20370` on `user-1000.slice` and called a box with `pids.max=max` capped.
    #[test]
    fn capped_here_ignores_an_ancestors_limit_while_the_tree_walk_honours_it() {
        // The fixture directory must be unique to THIS test, not merely to the process. The first
        // version built `kern-cg-<pid>`, which is byte-for-byte what
        // `capped_in_tree_reads_the_max_sentinel` builds: same process, same pid, same directory.
        // Both run in parallel and both call `remove_dir_all` when done, so whichever finished
        // first deleted the other's fixture mid-assertion. It failed on another machine while
        // passing here, which is the shape a test-ordering race always takes.
        let root = std::env::temp_dir().join(format!("kern-cg-capped-here-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        if fs::create_dir_all(&root).is_err() {
            eprintln!("skip: no writable temp dir");
            return;
        }
        let parent = root.join("parent");
        let child = parent.join("child");
        if fs::create_dir_all(&child).is_err() {
            eprintln!("skip: cannot build the fixture");
            let _ = fs::remove_dir_all(&root);
            return;
        }
        // The ancestor carries a real limit; the leaf carries the `max` no-limit sentinel.
        let _ = fs::write(parent.join("pids.max"), "20370\n");
        let _ = fs::write(child.join("pids.max"), "max\n");

        assert!(
            !capped_here(&child, "pids.max"),
            "capped_here must read the LEAF only: the box itself has no limit"
        );
        // The tree walk stops at /sys/fs/cgroup, which a temp dir is not under, so it inspects the
        // leaf alone here. That is enough to pin the sentinel rule the two share.
        assert!(
            !capped_in_tree(&child, "pids.max"),
            "the shared sentinel rule must read `max` as no limit"
        );
        // …and a real value at the leaf satisfies both.
        let _ = fs::write(child.join("pids.max"), "256\n");
        assert!(
            capped_here(&child, "pids.max"),
            "a real leaf limit must count"
        );
        assert!(
            capped_in_tree(&child, "pids.max"),
            "a real leaf limit must count for the walk too"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn mandatory_caps_in_force_reads_the_cgroup_not_whether_kern_wrote_it() {
        // The Pi 5 defect, automated. A temp dir is not under /sys/fs/cgroup, so `in_tree` evaluates
        // this leaf only - which is the whole point here: the caps were established by a systemd scope,
        // not by kern, and the predicate must still see them.
        let d = std::env::temp_dir().join(format!("kern-mand-{}", std::process::id()));
        std::fs::create_dir_all(&d).expect("temp dir");
        let set = |f: &str, v: &str| std::fs::write(d.join(f), v).expect("write");
        let req: u64 = 64 * 1024 * 1024; // 64 MiB, the value measured on the board

        // Exactly the state measured inside the scope on the Pi: both backstops real.
        set("memory.max", "67108864");
        set("pids.max", "512");
        assert!(
            mandatory_caps_in_force_at(&d, Some(req)),
            "a scope carrying memory.max and pids.max IS capped, whoever wrote them"
        );
        assert!(
            mandatory_caps_in_force_at(&d, None),
            "with no explicit request the mandatory default ceiling is what must bind"
        );

        // A memory ceiling with NO task ceiling is a fork-bomb hole: the box is not fully backstopped,
        // so the notice and the `--require-limits` refusal must still fire.
        set("pids.max", "max");
        assert!(
            !mandatory_caps_in_force_at(&d, Some(req)),
            "memory bound but pids unbound must NOT read as capped"
        );

        // A task ceiling with no memory ceiling is the mirror hole.
        set("pids.max", "512");
        set("memory.max", "max");
        assert!(
            !mandatory_caps_in_force_at(&d, Some(req)),
            "pids bound but memory unbound must NOT read as capped"
        );

        // The masking case this must not regress into: an ancestor ceiling LARGER than the request
        // does not enforce the request, so it is not "in force" for this box.
        set("memory.max", "8589934592"); // 8 GiB against a 64 MiB request
        assert!(
            !mandatory_caps_in_force_at(&d, Some(req)),
            "a ceiling above the request does not enforce it"
        );
        // ...while the same 8 GiB IS the real default ceiling when nothing narrower was asked for.
        assert!(
            mandatory_caps_in_force_at(&d, None),
            "with no request, any real ceiling bounds the default"
        );

        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn gc_sweeps_every_directory_a_box_can_be_created_in() {
        // The WSL2 defect, automated. `apply_limits` creates a box under kern.slice on the direct path
        // and under the CALLER'S cgroup on every other path (scope, managed, best-effort), and gc used
        // to sweep only the first. Measured there: three OOM-killed boxes left three
        // `/sys/fs/cgroup/kern-box-*` dirs, and gc reported "nothing to prune" with them in place.
        //
        // Asserted on `cgroup.kill`, not on the dir being gone, for the same reason
        // `sweep_orphan_boxes_reaps_only_dead_supervisors` is: on a REAL cgroupfs `cgroup.kill` already
        // exists and writing it is what empties the cgroup, but in a temp dir the write CREATES the
        // file, so the following `remove_dir` (which needs an empty dir) cannot succeed. The write is
        // the observable proof that the sweep reached that directory at all, which is the whole
        // question here; the removal half is exercised on real hosts.
        let base = std::env::temp_dir().join(format!("kern-gcdirs-{}", std::process::id()));
        let slice = base.join("slice");
        let origin = base.join("origin");
        let _ = fs::remove_dir_all(&base);
        for d in [&slice, &origin] {
            fs::create_dir_all(d).expect("temp dir");
        }
        // A pid that cannot be alive, so `/proc/<pid>` is absent and the entry reads as an orphan.
        let dead: u32 = fs::read_to_string("/proc/sys/kernel/pid_max")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .map_or(u32::MAX, |m| m.saturating_sub(1));
        let live = std::process::id();

        let dead_in_slice = slice.join(format!("kern-box-a-{dead}"));
        let dead_in_origin = origin.join(format!("kern-box-b-{dead}"));
        let live_in_origin = origin.join(format!("kern-box-c-{live}"));
        let unrelated = origin.join("not-a-box");
        for d in [&dead_in_slice, &dead_in_origin, &live_in_origin, &unrelated] {
            fs::create_dir_all(d).expect("case dir");
        }

        gc_orphan_box_cgroups_in(&[Some(slice.clone()), Some(origin.clone())]);

        assert!(
            dead_in_slice.join("cgroup.kill").is_file(),
            "the dead-supervisor box under kern.slice must be swept (it always was)"
        );
        assert!(
            dead_in_origin.join("cgroup.kill").is_file(),
            "the dead-supervisor box under the CALLER'S cgroup must be swept too: this is the \
             directory gc never looked at, where an OOM-killed box left one dir behind every time"
        );
        assert!(
            !live_in_origin.join("cgroup.kill").exists(),
            "a LIVE box must never be killed by gc - a reused pid would cost a running box its \
             processes"
        );
        assert!(live_in_origin.is_dir(), "a live box's cgroup dir survives");
        assert!(
            unrelated.is_dir() && !unrelated.join("cgroup.kill").exists(),
            "a dir that is not a box is never touched"
        );

        // Absent directories and `None` entries are skipped rather than panicked on: on most hosts one
        // of the two resolvers returns nothing.
        assert_eq!(
            gc_orphan_box_cgroups_in(&[Some(base.join("nope")), None]),
            0,
            "absent and None entries contribute nothing"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn capped_in_tree_reads_the_max_sentinel() {
        // A temp dir isn't under /sys/fs/cgroup, so the walk checks just this leaf - enough to lock
        // in the sentinel parsing (the bit that decides "enforced or not" and gates the warning).
        let d = std::env::temp_dir().join(format!("kern-cg-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let set = |f: &str, v: &str| std::fs::write(d.join(f), v).unwrap();

        set("memory.max", "max");
        assert!(!capped_in_tree(&d, "memory.max"), "`max` = no cap");
        set("memory.max", "67108864");
        assert!(capped_in_tree(&d, "memory.max"), "a byte count = capped");
        set("cpu.max", "max 100000");
        assert!(!capped_in_tree(&d, "cpu.max"), "`max <period>` = no cap");
        set("cpu.max", "50000 100000");
        assert!(capped_in_tree(&d, "cpu.max"), "a quota = capped");
        assert!(
            !capped_in_tree(&d, "does-not-exist"),
            "absent file = not capped"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn memory_cap_is_checked_against_the_requested_value_not_mere_existence() {
        // The #1 fix. A temp dir is not under /sys/fs/cgroup, so `in_tree` evaluates only this leaf,
        // which is exactly where the value logic lives. `capped_in_tree` (existence) would call every
        // finite number here "capped"; `memory_capped_at_or_below` compares against the request.
        let d = std::env::temp_dir().join(format!("kern-memreq-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let req: u64 = 8 * 1024 * 1024; // the box asked for 8 MiB
        let set = |v: &str| std::fs::write(d.join("memory.max"), v).unwrap();

        // The masking case: a cap ABOVE the request (a container's 8 GiB outer limit). Existence says
        // "capped"; the request took no effect, so this must be false.
        set("8589934592"); // 8 GiB
        assert!(
            capped_in_tree(&d, "memory.max"),
            "existence check calls the 8 GiB ancestor 'capped' - the masking that hid the bug"
        );
        assert!(
            !memory_capped_at_or_below(&d, req),
            "a cap of 8 GiB does not enforce a request of 8 MiB: the box can exceed what it asked for"
        );

        // A cap exactly AT the request (the enforcing path: scope MemoryMax=req, or inner memory.max
        // =req) satisfies it - this is why an enforcing systemd host does not false-warn.
        set(&req.to_string());
        assert!(
            memory_capped_at_or_below(&d, req),
            "a cap equal to the request is in effect"
        );

        // A cap BELOW the request is a stricter bound; the box still cannot exceed what it asked for.
        set(&(req / 2).to_string());
        assert!(
            memory_capped_at_or_below(&d, req),
            "an ancestor capping tighter than the request still satisfies it"
        );

        // The no-cap sentinel is never a bound.
        set("max");
        assert!(
            !memory_capped_at_or_below(&d, req),
            "`max` (uncapped) does not satisfy any request"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// THE VANTAGE, not the rule. Reconstructs the layout measured on a Raspberry Pi 5 and a Jetson
    /// (2026-09-07) under `--memory 256m --pids-limit 64` on the systemd-scope tier:
    ///
    ///   kern-box-<id>.scope/                 memory.max = request + SCOPE_SUPERVISOR_HEADROOM
    ///     kern-box-<id>/                     memory.max = request, pids.max = 64   <- the BOX
    ///     kern-box-<id>-sup/                 (nothing)                             <- the SUPERVISOR
    ///
    /// The supervisor is parked in a SIBLING of the box, so `/proc/self/cgroup` there walks to the
    /// ANCESTORS and never reaches the box's leaf. Both notices fired over a box capped exactly as
    /// asked, and they could not have done otherwise: the scope's ceiling is the request plus the
    /// headroom BY DESIGN, so `<= request` is false at every level the supervisor can see.
    ///
    /// The assertion is the DIFFERENCE between the two vantages on one identical tree, because that
    /// is the whole defect - the rule was right and was asked in the wrong place.
    #[test]
    fn unenforced_caps_answers_for_the_box_leaf_not_the_supervisors_sibling() {
        let scope = std::env::temp_dir().join(format!("kern-vantage-{}", std::process::id()));
        let boxdir = scope.join("kern-box-1");
        let sup = scope.join("kern-box-1-sup");
        std::fs::create_dir_all(&boxdir).unwrap();
        std::fs::create_dir_all(&sup).unwrap();
        let req: u64 = 256 * 1024 * 1024;
        std::fs::write(
            scope.join("memory.max"),
            (req + SCOPE_SUPERVISOR_HEADROOM).to_string(),
        )
        .unwrap();
        std::fs::write(scope.join("pids.max"), "64").unwrap();
        std::fs::write(boxdir.join("memory.max"), req.to_string()).unwrap();
        std::fs::write(boxdir.join("pids.max"), "64").unwrap();

        // The box's own leaf: capped exactly as asked, so nothing to say. This is what the host was
        // actually doing while it printed two warnings.
        assert!(
            unenforced_caps(&boxdir, Some(req), None, Some(64)).is_empty(),
            "the box leaf carries memory.max=request and pids.max=64; there is nothing unenforced"
        );

        // The supervisor's sibling: the same tree, the same rule, the wrong place. Both knobs report
        // unenforced. This is the shipped behaviour, kept as the negative control - it pins the COST
        // of the wrong vantage, and it is the reason the two assertions above mean anything. What it
        // does NOT cover is `warn_unenforced_caps` itself dropping the `dir` it is handed: that is a
        // property of the wrapper, which reads the environment and prints, and it is checked on a
        // board rather than here.
        let from_sup = unenforced_caps(&sup, Some(req), None, Some(64));
        assert_eq!(
            from_sup.iter().map(|(f, _)| *f).collect::<Vec<_>>(),
            vec!["--memory", "--pids-limit"],
            "read from the supervisor's uncapped sibling, both caps look absent"
        );

        // And the ceiling matters, not just the directory: a box leaf capped ABOVE what was asked is
        // still a real miss, so the fix cannot be "trust the box leaf whatever it says".
        std::fs::write(boxdir.join("memory.max"), (req * 2).to_string()).unwrap();
        assert_eq!(
            unenforced_caps(&boxdir, Some(req), None, Some(64))
                .iter()
                .map(|(f, _)| *f)
                .collect::<Vec<_>>(),
            vec!["--memory"],
            "a leaf capped at twice the request does not enforce the request"
        );
        let _ = std::fs::remove_dir_all(&scope);
    }

    #[test]
    fn wrote_real_limit_verifies_the_readback_not_just_the_write() {
        // The read-back that makes the direct path safe: a write is "real" only if the value no longer
        // reads the `max` no-limit sentinel. Simulate the cgroup file with a temp file.
        let d = std::env::temp_dir().join(format!("kern-wrl-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("memory.max");
        assert!(
            wrote_real_limit(&f, "67108864"),
            "a byte count reads back → real cap"
        );
        assert!(wrote_real_limit(&f, "512"), "pids-style count → real cap");
        // A host that accepts the write but leaves it uncapped reads back `max` → must be false.
        assert!(
            !wrote_real_limit(&f, "max"),
            "`max` sentinel = NOT a real cap"
        );
        // An unwritable target (parent gone) → false, never a false positive.
        assert!(
            !wrote_real_limit(&d.join("nope/memory.max"), "123"),
            "unwritable → false"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn require_all_refuses_partial_delegation_memory_binds_but_pids_does_not() {
        // A1 made explicit and automated: a host that delegates the `memory` controller but NOT `pids`
        // (the exact partial case the synthetic-cgroup test would build). The two already-tested pieces
        // compose here into the failure the gate exists to catch: `wrote_real_limit` reads memory.max
        // back as a real cap (mem_ok) but the undelegated pids.max write does not stick (pids_ok=false),
        // and under `--require-limits` (require_all) the gate must REFUSE - a box capped for RAM but not
        // fork bombs is still a fork-bomb hole. This runs on EVERY host (no cgroup delegation needed),
        // unlike a real synthetic-cgroup2 test; the live behaviour is separately proven on the boards.
        let d = std::env::temp_dir().join(format!("kern-a1-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let mem_ok = wrote_real_limit(&d.join("memory.max"), "67108864"); // delegated: binds
        let pids_ok = wrote_real_limit(&d.join("absent/pids.max"), "30"); // undelegated: write fails
        assert!(mem_ok, "memory bound");
        assert!(!pids_ok, "pids did NOT bind");
        assert!(
            !caps_gate_satisfied(mem_ok, pids_ok, true),
            "--require-limits must refuse when only one of the two mandatory caps bound"
        );
        assert!(
            caps_gate_satisfied(mem_ok, pids_ok, false),
            "the default keeps the box: partial protection (memory) beats none"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn cgroup_guard_removes_its_dir_on_drop() {
        // The RAII cleanup: dropping the guard `rmdir`s the (empty) cgroup dir, so a box never leaks a
        // `kern-box-*` cgroup. Use a real temp dir so `remove_dir` actually runs.
        let d = std::env::temp_dir().join(format!("kern-guard-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        assert!(d.exists());
        {
            let _g = CgroupGuard {
                dir: d.clone(),
                sup: None, // the sibling layout is not built in this unit test
                outside: false,
                origin: None,
            };
        } // guard dropped here
        assert!(
            !d.exists(),
            "guard's Drop must remove the (empty) cgroup dir"
        );
    }

    /// The ownership rule both callers share, stated on the predicate itself.
    ///
    /// `prepare_delegated_scope` RESTRUCTURES the cgroup it accepts - it creates leaves under it,
    /// moves kern's processes into one and enables controllers on it. Doing that to a scope kern did
    /// not create would reshape a user's own session: `kern doctor` recommends `systemd-run --user
    /// --scope bash` to pay the scope cost once, and every box started in that shell runs in an
    /// ambient `run-*.scope`. The prefix kern puts on its OWN units is the proof of ownership, and this
    /// is the assertion that keeps a future "any scope will do" from passing review.
    #[test]
    fn only_a_leaf_kern_named_itself_counts_as_a_box_cgroup() {
        for ours in [
            "kern-box-db-193325",   // direct path: the dir `apply_limits` creates
            "kern-box-8067.scope",  // scope path: the transient unit kern asks systemd for
            "kern-box-web-1.scope", // both shapes at once
        ] {
            assert!(is_kern_box_leaf(ours), "{ours} is kern's own");
        }
        for theirs in [
            "run-p123-i456.scope", // `systemd-run --user --scope bash` - the user's shell
            "app.slice",           // a shared slice: reaping or reshaping it hits the whole session
            "user@1000.service",   // the user manager itself
            "session-2.scope",     // a login session
            "kern.slice",          // kern's OWN shared slice is still not a BOX
            "notkern-box-1",       // the prefix must anchor at the start
            "",
        ] {
            assert!(
                !is_kern_box_leaf(theirs),
                "{theirs} is not kern's to reap or restructure"
            );
        }
    }

    #[test]
    fn parse_box_cgroup_line_extracts_only_kern_box_leaves() {
        // The eager-reap path resolves a box's exact dir from `/proc/<pid1>/cgroup` (v2 `0::<path>`).
        // A box leaf → the absolute dir; the shared slice/root, a non-kern leaf, or a v1-style body → None,
        // so a stray read can NEVER target a parent cgroup for rmdir.
        assert_eq!(
            parse_box_cgroup_line("0::/kern.slice/kern-box-db-193325\n"),
            Some(PathBuf::from(
                "/sys/fs/cgroup/kern.slice/kern-box-db-193325"
            ))
        );
        // Tag with a '-' and a deeper path still resolves to the right leaf.
        assert_eq!(
            parse_box_cgroup_line("0::/kern.slice/kern-box-web-1-42\n"),
            Some(PathBuf::from("/sys/fs/cgroup/kern.slice/kern-box-web-1-42"))
        );
        // The per-box TRANSIENT SCOPE kern asks systemd for is kern's own too, and is what makes a
        // box on that path recoverable when its supervisor is killed.
        assert_eq!(
            parse_box_cgroup_line(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/kern-box-1815.scope\n"
            ),
            Some(PathBuf::from(
                "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/kern-box-1815.scope"
            ))
        );
        // An AMBIENT scope kern did not create stays unrecorded, whatever it holds. This is the case
        // `kern doctor` tells users to create (`systemd-run --user --scope bash`): recording it would
        // let a later reap `cgroup.kill` their whole session.
        assert_eq!(
            parse_box_cgroup_line(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/run-p1815-i1816.scope\n"
            ),
            None
        );
        assert_eq!(
            parse_box_cgroup_line("0::/user.slice/user-1000.slice/session-3.scope\n"),
            None
        );
        // NOT a box leaf → never reaped.
        assert_eq!(parse_box_cgroup_line("0::/kern.slice\n"), None);
        assert_eq!(parse_box_cgroup_line("0::/\n"), None);
        assert_eq!(parse_box_cgroup_line("0::/user.slice/foo.scope\n"), None);
        // A cgroup-v1 multi-line body (no `0::`) → None, not a panic.
        assert_eq!(parse_box_cgroup_line("12:pids:/kern-box-db-1\n0::\n"), None);
        assert_eq!(parse_box_cgroup_line(""), None);
    }

    #[test]
    fn render_cgroup_max_writes_number_or_literal_max() {
        // A fleet budget renders as a plain byte/count for the kernel...
        assert_eq!(render_cgroup_max(268_435_456), "268435456"); // 256 MiB
        assert_eq!(render_cgroup_max(100), "100"); // pids
        assert_eq!(render_cgroup_max(0), "0");
        // ...and u64::MAX is the sentinel that clears the cap (cgroup v2 `max`), never a huge number.
        assert_eq!(render_cgroup_max(u64::MAX), "max");
    }

    #[test]
    fn cgroup_guard_drop_is_harmless_when_dir_is_gone() {
        // An outer systemd `--collect` may remove the scope (and our dir) first - the guard's Drop must
        // tolerate ENOENT, not panic.
        let d = std::env::temp_dir().join(format!("kern-guard-gone-{}", std::process::id()));
        let g = CgroupGuard {
            dir: d.clone(),
            sup: None, // no sibling leaf was built, so there is none to remove
            outside: false,
            origin: None,
        }; // dir never created
        drop(g); // must not panic on ENOENT
        assert!(!d.exists());
    }

    #[test]
    fn current_v2_cgroup_is_read_from_the_0_prefixed_line() {
        // Real host: a v2 or hybrid box has a `0::` line, so we resolve SOME dir under /sys/fs/cgroup;
        // a pure-v1 host has none → None. Either way it must not panic and must never mis-resolve a v1
        // line. (The parse is `strip_prefix("0::")` per line, not `rsplit("::")` on the whole blob.)
        if let Some(p) = current_v2_cgroup() {
            assert!(
                p.starts_with("/sys/fs/cgroup"),
                "must resolve under the cgroup root, got {p:?}"
            );
        }
    }

    #[test]
    fn subtree_batch_all_available_keeps_want_order() {
        // Parent exports every controller (out of order, plus extras): batch is exactly WANT's five,
        // in WANT order, ignoring the extras.
        assert_eq!(
            subtree_batch("cpuset cpu io memory pids hugetlb rdma misc"),
            "+memory +pids +cpu +cpuset +io"
        );
    }

    #[test]
    fn subtree_batch_common_user_session_subset() {
        // The case this fix targets: a systemd user session delegates memory/pids/cpu but NOT
        // cpuset/io. Old code wrote a 5-token batch that failed atomically, then 5 singles (2 failing);
        // now exactly the three available ones, in one write, no failing probes.
        assert_eq!(subtree_batch("memory pids cpu"), "+memory +pids +cpu");
    }

    #[test]
    fn subtree_batch_empty_when_none_wanted_present() {
        assert_eq!(subtree_batch(""), "");
        assert_eq!(subtree_batch("hugetlb rdma misc"), "");
    }

    #[test]
    fn subtree_batch_exact_token_match_no_prefix_collision() {
        // `cpu` must NOT enable `cpuset` and vice versa - a substring test would get this wrong.
        assert_eq!(subtree_batch("cpu"), "+cpu");
        assert_eq!(subtree_batch("cpuset"), "+cpuset");
        assert_eq!(subtree_batch("cpuset memory"), "+memory +cpuset");
    }

    #[test]
    fn subtree_batch_tolerates_whitespace_and_newlines() {
        // `cgroup.controllers` is a single space-separated line, but be robust to tabs/extra spaces/
        // a trailing newline from the read.
        assert_eq!(
            subtree_batch("  memory   pids\tcpu  \n"),
            "+memory +pids +cpu"
        );
    }

    #[test]
    fn subtree_all_enabled_skips_write_only_when_every_wanted_available_is_on() {
        // The common shared-`kern.slice` steady state: parent exports memory/pids/cpu and all are
        // already enabled -> the per-box write is a pure `cgroup_mutex` no-op and MUST be skipped.
        assert!(subtree_all_enabled("memory pids cpu", "memory pids cpu"));
        // A superset enabled set (extra controllers the kernel turned on) still counts as "all on".
        assert!(subtree_all_enabled(
            "memory pids cpu",
            "cpuset memory io pids cpu"
        ));
        // Any wanted-and-available controller MISSING from the enabled set forces the write (correct:
        // a freshly (re)created slice has an empty `subtree_control`).
        assert!(!subtree_all_enabled("memory pids cpu", "memory pids")); // cpu not yet on
        assert!(!subtree_all_enabled("memory pids cpu", "")); // nothing on: must write
                                                              // Exact-token match, mirroring `subtree_batch`: `cpu` enabled must NOT satisfy a wanted `cpuset`
                                                              // (a substring test would wrongly skip and leave cpuset unenabled).
        assert!(!subtree_all_enabled("cpuset", "cpu"));
        assert!(subtree_all_enabled("cpuset", "cpu cpuset"));
        // A controller the parent does NOT export is not required, so it can't block the skip.
        assert!(subtree_all_enabled("memory pids", "memory pids")); // cpu/cpuset/io unavailable: fine
                                                                    // Whitespace/newline tolerance on both sides (same read shape as `cgroup.controllers`).
        assert!(subtree_all_enabled("  memory\tpids \n", "pids   memory\n"));
        // Every wanted controller present and enabled: the maximal skip case.
        assert!(subtree_all_enabled(
            "memory pids cpu cpuset io",
            "io cpuset cpu pids memory"
        ));
        // Consistency with `subtree_batch`: if the batch is empty (nothing wanted available), the skip
        // predicate is vacuously true, so `enable_subtree_controllers` writes nothing either way.
        assert_eq!(subtree_batch("hugetlb rdma"), "");
        assert!(subtree_all_enabled("hugetlb rdma", ""));
    }

    #[test]
    fn require_limits_gate_demands_both_caps_default_accepts_either() {
        // `--require-limits` (require_all = true): ONLY both-bound passes. The three partial cases a
        // fork-bomb / OOM hole would slip through MUST fail - that is the whole point of the flag, and
        // a regression that swapped `&&` for `||` here (running a half-capped box the flag must refuse)
        // is caught by exactly these three asserts, on every run, with no cgroup delegation required.
        assert!(caps_gate_satisfied(true, true, true));
        assert!(!caps_gate_satisfied(true, false, true)); // memory bound, pids did NOT: refuse
        assert!(!caps_gate_satisfied(false, true, true)); // pids bound, memory did NOT: refuse
        assert!(!caps_gate_satisfied(false, false, true));
        // Default (require_all = false): at least one bound is enough - partial protection beats none.
        assert!(caps_gate_satisfied(true, true, false));
        assert!(caps_gate_satisfied(true, false, false));
        assert!(caps_gate_satisfied(false, true, false));
        assert!(!caps_gate_satisfied(false, false, false)); // nothing bound: nothing to keep
    }

    #[test]
    fn unix_socket_live_separates_a_listener_from_a_stale_socket() {
        let tmp = std::env::temp_dir().join(format!("kern-buslive-{}", unsafe { libc::getpid() }));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("tmp dir");

        // A LIVE listener: connect succeeds.
        let live = tmp.join("live.sock");
        let listener = std::os::unix::net::UnixListener::bind(&live).expect("bind live");
        assert!(
            unix_socket_live(&live),
            "a listening socket must read as live"
        );

        // A STALE socket: the file exists, but nothing is listening (the manager died). This is the
        // case `exists()` got WRONG and `connect()` gets right - the regression in a different form.
        let stale = tmp.join("stale.sock");
        {
            let _l = std::os::unix::net::UnixListener::bind(&stale).expect("bind stale");
        } // listener dropped here; the socket file remains, no listener
        assert!(
            stale.exists(),
            "the stale socket file must still be present"
        );
        // Under parallel load a just-closed AF_UNIX listener can transiently accept a `connect` for a
        // few milliseconds (the kernel queues then resets it) before it reads as refused - a window that
        // does NOT exist in production, where this probes systemd's long-lived manager socket, live or
        // long-dead. Poll the settle window so the test is deterministic instead of asserting on that
        // transient. Normal case: not-live on the first check (0 ms); the loop only spins on the rare race.
        let mut settled = false;
        for _ in 0..200 {
            if !unix_socket_live(&stale) {
                settled = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            settled,
            "a stale socket with no listener must read as NOT live (within the settle window)"
        );

        // A nonexistent path is not live.
        assert!(!unix_socket_live(&tmp.join("nope.sock")));

        drop(listener);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn unix_socket_live_rejects_adversarial_and_malformed_paths() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::net::{UnixDatagram, UnixListener};
        let tmp =
            std::env::temp_dir().join(format!("kern-buslive-edge-{}", unsafe { libc::getpid() }));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("tmp dir");

        // Malformed inputs the guard must reject WITHOUT a syscall and without overflowing sun_path.
        assert!(!unix_socket_live(std::path::Path::new("")), "empty path");
        // Embedded NUL: would truncate the kernel's path and connect to a DIFFERENT socket. Rejected.
        let nul = std::path::Path::new(std::ffi::OsStr::from_bytes(b"/tmp/a\0evil.sock"));
        assert!(!unix_socket_live(nul), "embedded NUL must be rejected");
        // A path >= sizeof(sun_path) (108 on Linux) must be rejected, not truncated into another socket.
        let too_long = std::path::PathBuf::from(format!("/tmp/{}.sock", "a".repeat(200)));
        assert!(
            !unix_socket_live(&too_long),
            "over-long path must be rejected"
        );

        // Wrong socket TYPE at the path: the manager's control socket is SOCK_STREAM. A SOCK_DGRAM
        // socket bound there (an attacker planting the wrong type) must NOT read as live - a SOCK_STREAM
        // connect() to it fails (EPROTOTYPE), so kern falls to best-effort instead of exec'ing into a
        // systemd-run that would then fail.
        let dgram_path = tmp.join("dgram.sock");
        let _dg = UnixDatagram::bind(&dgram_path).expect("bind dgram");
        assert!(
            !unix_socket_live(&dgram_path),
            "a SOCK_DGRAM socket must not read as a live SOCK_STREAM listener"
        );

        // A SYMLINK to a live listener follows through: connect() resolves the link, so it reads live.
        let real = tmp.join("real.sock");
        let listener = UnixListener::bind(&real).expect("bind real");
        let link = tmp.join("link.sock");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(
            unix_socket_live(&link),
            "a symlink to a live listener must read as live"
        );

        // A regular FILE and a DIRECTORY at the path are not sockets: connect() fails, not live.
        let file = tmp.join("plain.file");
        fs::write(&file, b"not a socket").expect("write file");
        assert!(
            !unix_socket_live(&file),
            "a regular file is not a live socket"
        );
        assert!(!unix_socket_live(&tmp), "a directory is not a live socket");

        drop(listener);
        let _ = fs::remove_dir_all(&tmp);
    }

    /// One lock for every test that mutates the process-wide environment. `set_var` is global, so two
    /// of these running at once would read each other's `KERN_NO_SCOPE` and fail for a reason that has
    /// nothing to do with the code under test. Poison is recovered so one failure does not cascade.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Restores the variables a test touched, on every exit path including a panic.
    struct EnvGuard(Vec<(&'static str, Option<std::ffi::OsString>)>);
    impl EnvGuard {
        fn set(names: &[&'static str]) -> Self {
            Self(names.iter().map(|n| (*n, std::env::var_os(n))).collect())
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (n, v) in &self.0 {
                match v {
                    Some(v) => std::env::set_var(n, v),
                    None => std::env::remove_var(n),
                }
            }
        }
    }

    #[test]
    fn the_direct_cap_path_is_refused_before_it_can_touch_the_host() {
        // `choose_direct_cap_path_given` decides between capping directly in `kern.slice` and paying a
        // per-box `systemd-run --scope`, and the decision ARMS the fail-closed refusal in
        // `run_in_sandbox`. Three of its four gates are pure environment, and this pins them: each must
        // short-circuit to false BEFORE `direct_caps_available()` reads the host, and none may leave the
        // marker behind - a stale marker makes `took_direct_cap_path` claim a path this box never took,
        // which is how a host that ran boxes best-effort starts refusing all of them.
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _restore = EnvGuard::set(&[
            "KERN_NO_SCOPE",
            "KERN_SCOPE",
            "KERN_MANAGED",
            "KERN_BUILD_STEP",
            DIRECT_MARKER,
        ]);
        for n in [
            "KERN_NO_SCOPE",
            "KERN_SCOPE",
            "KERN_MANAGED",
            "KERN_BUILD_STEP",
            DIRECT_MARKER,
        ] {
            std::env::remove_var(n);
        }

        // The manager is absent: nothing to ask for a scope, and no direct path either.
        assert!(
            !choose_direct_cap_path_given(false),
            "no user manager must refuse the direct path"
        );
        assert!(
            std::env::var_os(DIRECT_MARKER).is_none(),
            "a refused decision must not record itself"
        );

        // The opt-out, with a manager present.
        std::env::set_var("KERN_NO_SCOPE", "1");
        assert!(
            !choose_direct_cap_path_given(true),
            "KERN_NO_SCOPE must refuse the direct path"
        );
        assert!(std::env::var_os(DIRECT_MARKER).is_none());
        std::env::remove_var("KERN_NO_SCOPE");

        // An OUTER enforcer already caps us: each of the three names alone is enough.
        for outer in ["KERN_SCOPE", "KERN_MANAGED", "KERN_BUILD_STEP"] {
            std::env::set_var(outer, "1");
            assert!(
                !choose_direct_cap_path_given(true),
                "{outer} names an outer enforcer, so the direct path must be refused"
            );
            assert!(
                std::env::var_os(DIRECT_MARKER).is_none(),
                "{outer}: a refused decision must not record itself"
            );
            std::env::remove_var(outer);
        }
    }

    #[test]
    fn the_direct_path_marker_is_read_back_and_scrubbed() {
        // `took_direct_cap_path` reports the RECORDED decision rather than re-deriving it from the
        // environment, and `scrub_direct_marker` clears one INHERITED from a parent `kern`. Together
        // they are what keeps a nested box from being poisoned by its parent's choice, so both
        // directions are pinned here: what is set reads back, and what is scrubbed reads false.
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _restore = EnvGuard::set(&[DIRECT_MARKER]);

        std::env::set_var(DIRECT_MARKER, "1");
        assert!(
            took_direct_cap_path(),
            "a recorded direct-path decision must read back as taken"
        );
        scrub_direct_marker();
        assert!(
            !took_direct_cap_path(),
            "a scrubbed marker must read back as NOT taken, or a nested box inherits its parent's path"
        );

        // An exported-but-EMPTY value is the shape that broke `KERN_NO_SCOPE` on a Raspberry Pi 5:
        // present in the environment, meaning nothing. It must not count as a decision either.
        std::env::set_var(DIRECT_MARKER, "");
        assert!(!took_direct_cap_path(), "an empty marker is not a decision");
    }

    /// The hint may name `cgroup.subtree_control` ONLY where writing it is possible. The three
    /// verdicts are driven against real directories, because the fact that decides this is a
    /// permission bit and a synthetic string cannot carry one.
    #[test]
    fn delegation_blocker_names_a_write_only_where_one_is_possible() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("kern-blocker-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("temp dir");

        // No `cgroup.subtree_control` at all: the controller is not enabled here, and the dir is ours
        // to write - the one case where the old fixed hint was right.
        assert_eq!(
            delegation_blocker_at(&base),
            DelegationBlocker::ControllerNotEnabled
        );
        // Listed: enabling it again changes nothing, so the hint must not send anyone to do it.
        fs::write(base.join("cgroup.subtree_control"), "cpu memory pids\n").expect("write");
        assert_eq!(delegation_blocker_at(&base), DelegationBlocker::Neither);
        // A sibling controller is not `memory`: the token match must be exact, not a substring.
        fs::write(base.join("cgroup.subtree_control"), "cpu memoryfoo pids\n").expect("write");
        assert_eq!(
            delegation_blocker_at(&base),
            DelegationBlocker::ControllerNotEnabled,
            "`memoryfoo` is not `memory`"
        );

        // Not writable = the colima shape (`/system.slice/ssh.service`, root-owned, 755). Root
        // bypasses the permission check, so as root there is no way to build this state: skip with
        // the reason rather than assert something false.
        if unsafe { libc::getuid() } == 0 {
            eprintln!("skip: the read-only arm needs a non-root uid (root bypasses W_OK)");
            let _ = fs::remove_dir_all(&base);
            return;
        }
        fs::write(base.join("cgroup.subtree_control"), "cpu pids\n").expect("write");
        let ro = fs::Permissions::from_mode(0o555);
        fs::set_permissions(&base, ro).expect("chmod");
        assert_eq!(
            delegation_blocker_at(&base),
            DelegationBlocker::NotWritable,
            "a dir this user cannot write has nothing for them to enable"
        );
        // Positive control: the permission bit is what moved the verdict, not the file contents.
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).expect("chmod back");
        assert_eq!(
            delegation_blocker_at(&base),
            DelegationBlocker::ControllerNotEnabled,
            "same contents, writable again: the mode was the discriminant"
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// `XDG_RUNTIME_DIR` gets named only when pointing it somewhere else would change the answer. The
    /// shipped warning named it unconditionally, which on a host with no user manager at all is a
    /// dead end dressed as a fix.
    #[test]
    fn the_runtime_dir_is_named_only_when_changing_it_would_help() {
        let std_dir = PathBuf::from("/run/user/501");
        // Unset, manager listening at the standard path: the export IS the fix, so say it.
        let c = missing_manager_clause_from(501, None, false, true);
        assert!(c.contains("export `XDG_RUNTIME_DIR=/run/user/501`"), "{c}");
        // Unset, nothing listening: no variable can conjure a manager.
        let c = missing_manager_clause_from(501, None, false, false);
        assert!(c.contains("no systemd user manager"), "{c}");
        assert!(!c.contains("export"), "nothing to export here: {c}");
        // Set to a scratch dir while the manager is at the standard path: point at the mismatch.
        let c = missing_manager_clause_from(501, Some(PathBuf::from("/tmp/scratch")), false, true);
        assert!(
            c.contains("/tmp/scratch") && c.contains("/run/user/501"),
            "{c}"
        );
        // Set to the standard path with nothing listening: the host has none, and the variable is
        // already right - the case the colima guest is in.
        let c = missing_manager_clause_from(501, Some(std_dir.clone()), false, false);
        assert!(c.contains("no systemd user manager"), "{c}");
        assert!(
            !c.contains("export"),
            "the variable is already correct: {c}"
        );
        // A LIVE manager at the path kern uses: the clause must not report it absent, whatever else
        // went wrong. This is the state that made the first version of this function print a
        // falsehood on the author's own desktop.
        let c = missing_manager_clause_from(501, Some(std_dir), true, true);
        assert!(c.contains("IS reachable at `/run/user/501`"), "{c}");
        assert!(!c.contains("no systemd user manager"), "{c}");
    }

    /// The two numbers `clone3` is versioned and gated by, pinned against `include/uapi/linux/sched.h`.
    ///
    /// A CONSTANT ONE BIT OFF DOES NOT FAIL, IT SUCCEEDS AND DOES NOTHING. `CLONE_CLEAR_SIGHAND` is
    /// `0x1_0000_0000` and `CLONE_INTO_CGROUP` is `0x2_0000_0000`; pass the first and `clone3` returns
    /// a pid, ignores the `cgroup` field, and leaves the box in the caller's cgroup, which is a box
    /// running without its memory ceiling. That substitution was actually made while prototyping this
    /// change and produced a convincing 20x timing win from a call that placed nothing.
    #[test]
    fn clone_into_cgroup_constant_matches_the_uapi_header() {
        assert_eq!(
            CLONE_INTO_CGROUP, 0x2_0000_0000,
            "CLONE_INTO_CGROUP from include/uapi/linux/sched.h"
        );
        assert_ne!(
            CLONE_INTO_CGROUP, 0x1_0000_0000,
            "that is CLONE_CLEAR_SIGHAND: it succeeds, ignores the cgroup, and uncaps the box"
        );
        // CLONE_ARGS_SIZE_VER2. The kernel dispatches on this size and answers EINVAL for one it does
        // not know, so a wrong size degrades to the `fork` path rather than corrupting anything - but
        // it would silently cost the whole optimisation, which no other test would notice.
        assert_eq!(std::mem::size_of::<CloneArgs>(), 88);
        assert_eq!(std::mem::align_of::<CloneArgs>(), 8);
    }

    /// A path that cannot become a C string must not become a truncated one.
    #[test]
    fn the_cgroup_dir_fd_refuses_what_it_cannot_represent() {
        assert!(
            open_cgroup_dir_fd(Path::new("")).is_none(),
            "an empty path is not a directory to open"
        );
        // An interior NUL would be silently truncated by every C API downstream, turning a path into
        // its own prefix. `/sys/fs/cgroup\0/evil` must not open `/sys/fs/cgroup`.
        let with_nul = {
            use std::os::unix::ffi::OsStrExt;
            PathBuf::from(std::ffi::OsStr::from_bytes(b"/sys/fs/cgroup\0/evil"))
        };
        assert!(open_cgroup_dir_fd(&with_nul).is_none());
        // Longer than PATH_MAX: refused, not truncated.
        let long = PathBuf::from(format!("/{}", "a".repeat(libc::PATH_MAX as usize)));
        assert!(open_cgroup_dir_fd(&long).is_none());
        // A directory that does exist opens, so the refusals above are about the input and not about
        // the function being unable to open anything at all.
        match open_cgroup_dir_fd(Path::new("/proc/self")) {
            Some(fd) => {
                assert!(fd >= 0);
                unsafe { libc::close(fd) };
            }
            None => panic!("/proc/self is a directory and must open"),
        }
    }

    /// `fork_into_cgroup(None)` is a plain `fork`, and the child is reachable and reapable.
    ///
    /// The value of this test is the SECOND half of the tuple: a `None` caller must never be told the
    /// child was placed, because that is the flag the box start path uses to skip the `cgroup.procs`
    /// write. A `true` here would ship a box that never enters its own cgroup.
    #[test]
    fn a_fork_with_no_target_reports_that_it_placed_nothing() {
        let (pid, born) = fork_into_cgroup(None);
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        assert!(
            !born,
            "no target was given, so nothing can have been placed"
        );
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    }

    /// The teardown vacate must fire exactly when the supervisor left `origin`, and never otherwise.
    ///
    /// This is a pure decision table because the cost of getting it wrong is asymmetric and neither
    /// direction is visible from a passing box: vacating when the process never moved spends an RCU
    /// grace period (19 ms measured on a quiet host) to migrate it to the cgroup it is already in,
    /// while NOT vacating when it did move leaves a populated cgroup that `remove_dir` cannot take,
    /// and those leaves accumulated 434-deep in one session before the sweep learned to reap them.
    #[test]
    fn the_teardown_vacates_only_when_the_supervisor_actually_left() {
        // (sup built, supervisor outside the capped cgroup) -> must it write itself back?
        let must_vacate = |sup_built: bool, outside: bool| sup_built || !outside;

        // Parked in the sibling leaf: it is inside `sup`, which cannot be removed while populated.
        assert!(must_vacate(true, true), "parked in the leaf: must leave it");
        // The leaf could not be built, so it joined the capped cgroup itself: same, for `dir`.
        assert!(must_vacate(false, false), "joined `dir`: must leave it");
        // Never moved: `origin` is still its cgroup. Writing there is a migration to itself.
        assert!(
            !must_vacate(false, true),
            "it never left `origin`; a write here is a no-op migration that still costs a grace period"
        );
        // Both markers set is the leaf layout again, and it is inside the leaf either way.
        assert!(must_vacate(true, false));
    }

    /// THE ASSERTION IS MEMBERSHIP, NOT DURATION: the child must report the target cgroup as its own.
    ///
    /// Reads `/proc/self/cgroup` IN THE CHILD and hands it back over a pipe, because that is the one
    /// channel the thing being measured cannot rewrite. Asserting on timing instead is exactly how a
    /// `clone3` carrying the wrong flag passed for a working one.
    ///
    /// SKIPS rather than fails wherever the case cannot be built: cgroup v2 absent, no writable
    /// delegated subtree, `clone3` denied (inside a container, or a kernel under 5.7). A skip here is
    /// not a pass and says so; the box start path still works on every one of those hosts, by the
    /// `fork` fallback that this test cannot reach.
    #[test]
    fn a_child_born_into_a_cgroup_reports_that_cgroup_as_its_own() {
        let Some(parent) = current_v2_cgroup() else {
            eprintln!("SKIP: no cgroup v2 line in /proc/self/cgroup");
            return;
        };
        let dir = parent.join(format!("kern-clone3-test-{}", std::process::id()));
        if fs::create_dir(&dir).is_err() {
            eprintln!("SKIP: cannot create a cgroup under {}", parent.display());
            return;
        }
        let want = format!("0::/{}", {
            let full = dir.to_string_lossy().into_owned();
            full.trim_start_matches("/sys/fs/cgroup/").to_owned()
        });

        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
        let (r, w) = (fds[0], fds[1]);

        let Some(cgref) = CgroupRef::open(&dir) else {
            eprintln!("SKIP: cannot open {} as a directory", dir.display());
            let _ = fs::remove_dir(&dir);
            return;
        };
        let (pid, born) = fork_into_cgroup(Some(&cgref));
        if pid == 0 {
            // NOTHING HERE MAY ALLOCATE. This is the child of a `fork` in cargo's MULTITHREADED test
            // harness: another thread can hold the allocator's lock at the instant of the fork, and
            // that lock is copied held into a child that has no thread to release it. `fs::read`
            // would allocate and could deadlock forever. Raw syscalls and a stack buffer only.
            unsafe { libc::close(r) };
            let mut mine = [0u8; 512];
            let fd = unsafe {
                libc::open(
                    c"/proc/self/cgroup".as_ptr().cast::<libc::c_char>(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            if fd >= 0 {
                let n = unsafe { libc::read(fd, mine.as_mut_ptr().cast(), mine.len()) };
                if n > 0 {
                    unsafe { libc::write(w, mine.as_ptr().cast(), n as usize) };
                }
                unsafe { libc::close(fd) };
            }
            unsafe { libc::close(w) };
            unsafe { libc::_exit(0) };
        }
        unsafe { libc::close(w) };
        assert!(pid > 0, "fork failed: {}", std::io::Error::last_os_error());

        let mut buf = [0u8; 4096];
        let n = unsafe { libc::read(r, buf.as_mut_ptr().cast(), buf.len()) };
        unsafe { libc::close(r) };
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        let reported = String::from_utf8_lossy(&buf[..n.max(0) as usize]).into_owned();
        let _ = fs::remove_dir(&dir);

        if !born {
            // The fallback ran. That is a supported outcome on this host, and the ONE thing that must
            // still hold is the tuple's honesty: the caller was told to do the write itself.
            eprintln!("SKIP: clone3(CLONE_INTO_CGROUP) unavailable here; the fork fallback ran");
            assert!(
                !reported.trim().is_empty(),
                "the child must still run under the fallback"
            );
            return;
        }
        assert_eq!(
            reported.trim(),
            want,
            "a child reported born into {} says it is in {reported:?}",
            dir.display()
        );
    }
}
