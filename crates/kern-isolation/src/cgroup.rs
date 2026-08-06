//! Best-effort cgroup v2 resource limits (memory + PIDs).
//!
//! Confines the sandbox so a runaway fork bomb or memory hog can't take down the host. Applied
//! before the namespace setup, so the forked workload inherits the cgroup. If the hierarchy
//! isn't delegated/writable (no systemd user delegation), it degrades gracefully: the namespace
//! isolation still holds; only the resource cap is skipped. cgroup v2 only.

use std::fs;
use std::path::PathBuf;
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
    /// Where to move the supervisor back to before removing `dir`. On the direct fast path the supervisor
    /// moved ITSELF into the box cgroup (so the forked workload inherits the caps); a non-empty cgroup
    /// can't be `rmdir`'d, so it must VACATE first - else the direct path leaks one `kern-box-*` dir per
    /// box. `origin` is kern's cgroup from BEFORE the move (a valid domain that accepts processes).
    origin: Option<PathBuf>,
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        // Vacate the box cgroup first - move the supervisor back to where it came from - so the now-empty
        // dir can be removed. (On the scope path an outer `--collect` also cleans up; this is harmless
        // there.) Best-effort: if the move fails the rmdir just no-ops on the non-empty dir, as before.
        if let Some(origin) = &self.origin {
            let _ = fs::write(origin.join("cgroup.procs"), std::process::id().to_string());
        }
        // Best-effort: a non-empty cgroup or an already-removed dir (ENOENT - an outer `--collect` beat
        // us to it) are both fine to ignore.
        let _ = fs::remove_dir(&self.dir);
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

/// Is an OUTER cgroup already enforcing this box's caps, so the direct kern.slice path must NOT be taken?
/// Three cases, all of which run with `KERN_SCOPE` unset-or-set but are already capped/tracked by an
/// ancestor: our own transient systemd `--scope` re-exec (`KERN_SCOPE`), a persistent `--restart` unit
/// (`KERN_MANAGED`, capped by its `kern-<name>.service` cgroup), and a `kern build` RUN step
/// (`KERN_BUILD_STEP`). Taking the direct path for these would move the box OUT of the enforcing ancestor
/// (breaking `stop`/kill for managed units) and could fail-closed-refuse a build/restart into a crash-loop.
fn outer_enforcer_present() -> bool {
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
pub fn took_direct_cap_path() -> bool {
    std::env::var_os(DIRECT_MARKER).is_some()
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
    /// The `memory` controller is in this tree but not delegated to a child kern can create, so a
    /// `memory.max` write is accepted and never bites. `--memory` is silently ineffective.
    PresentNotDelegated,
    /// The `memory` controller is not in this cgroup's tree at all (a stock Raspberry Pi without
    /// `cgroup_enable=memory`, Microsoft's default WSL2 kernel).
    Absent,
    /// Could not be determined: no cgroup v2, or `/proc/self/cgroup` was unreadable.
    Unknown,
}

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
/// existing box's or sibling's limit files.
///
/// NOT for the box-start hot path (a box ensures the slice itself). Its one caller, doctor, invokes it
/// at most once; do not place it in a per-box-start or per-syscall loop.
pub fn memory_cap_state() -> MemoryCapState {
    let Some(target) = ensure_kern_slice().or_else(current_v2_cgroup) else {
        return MemoryCapState::Unknown;
    };
    memory_cap_state_at(&target)
}

/// Testable core of [`memory_cap_state`]: the probe against an explicit cgroup directory, split out
/// for the same reason `config::load_impl` is - a unit test can drive it against a synthetic tree
/// without reading (or mutating) the real `/proc/self/cgroup`.
fn memory_cap_state_at(cur: &std::path::Path) -> MemoryCapState {
    let child = cur.join(format!("kern-capprobe-{}", unsafe { libc::getpid() }));
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
    // parent's `subtree_control`. No `memory.max` file therefore means `memory` is not delegated here.
    if !max.exists() {
        let _ = fs::remove_dir(&child);
        return classify_absent_or_not_delegated(cur);
    }
    // Write a small, unmistakable, non-`max` value to the EMPTY child and read it back. Any value is
    // safe: the cgroup holds no processes, so nothing is throttled or OOM-killed.
    // The same write-then-verify primitive `apply_limits` uses for a real box's `memory.max`: a fresh
    // child starts at the `max` sentinel, so "reads back a real (non-`max`) limit" is equivalent to the
    // exact-value check here, and there is one definition of "the write bound" instead of two.
    const PROBE_BYTES: &str = "1048576"; // 1 MiB
    let stuck = wrote_real_limit(&max, PROBE_BYTES);
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
        return Some(PathBuf::from("/sys/fs/cgroup/kern.slice"));
    }
    let cur = current_v2_cgroup()?;
    let root = cur.ancestors().find(|p| {
        p.file_name().is_some_and(|n| {
            let n = n.to_string_lossy();
            n.starts_with("user@") && n.ends_with(".service")
        })
    })?;
    Some(root.join("kern.slice"))
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

/// Reap orphaned box cgroup dirs under kern.slice: a `kern-box-<tag>-<pid>` whose supervisor `<pid>` is
/// DEAD. Self-heals the one leak the RAII guard can't cover - a DETACHED box whose supervisor is
/// SIGKILL'd by `kern stop` never runs `Drop`, leaving its (now-empty) dir behind. RACE-SAFE: a LIVE box's
/// pid is alive (`/proc/<pid>` exists) → skipped, including one mid-creation; only dead-owner dirs are
/// `rmdir`'d, and `rmdir` itself fails on any still-populated cgroup. Cheap (one readdir + a stat/entry),
/// run once per box start when kern.slice is confirmed usable.
/// Reap dead-supervisor `kern-box-<tag>-<pid>` cgroup dirs under `slice`. `limit` caps how many entries
/// are examined (a `/proc/<pid>` stat each) so the PER-BOX-START call (kern is daemonless → once per box
/// process) stays O(1) instead of O(entries) - Σ over an N-box burst would otherwise be O(N²). Orphans
/// past the cap are cleared by a later start or by `kern gc` (which passes `0` = unbounded). The
/// `/proc/<pid>` check (not a bare rmdir-if-empty) is deliberate: a box is momentarily EMPTY between its
/// cgroup `mkdir` and the `cgroup.procs` write, so only a truly dead pid is reaped.
fn sweep_orphan_boxes(slice: &std::path::Path, limit: usize) {
    let Ok(rd) = fs::read_dir(slice) else { return };
    for (seen, e) in rd.flatten().enumerate() {
        if limit != 0 && seen >= limit {
            break;
        }
        let name = e.file_name();
        let name = name.to_string_lossy();
        // trailing `-<pid>` of `kern-box-<tag>-<pid>` (tag may contain '-', pid is always the last field).
        let dead = name
            .strip_prefix("kern-box-")
            .and_then(|s| s.rsplit('-').next())
            .and_then(|p| p.parse::<u32>().ok())
            .is_some_and(|pid| !PathBuf::from(format!("/proc/{pid}")).exists());
        if dead {
            // The supervisor `<pid>` is gone. A detached box whose supervisor was SIGKILL'd/OOM-killed
            // ran no cleanup, and its PID-ns init carries no launcher PDEATHSIG, so the whole tree
            // (init + workload + any grandchild it forked) can still be ALIVE. `remove_dir` alone fails
            // on that non-empty cgroup and the tree LEAKS. `cgroup.kill` SIGKILLs every member at once,
            // then the (now-emptying) dir is `rmdir`'d - a straggler zombie's dir falls to the next
            // sweep once the kernel reaps it. No pid-reuse hazard: a reused `<pid>` makes `/proc/<pid>`
            // exist, so `dead` is false and the box is skipped, never killed.
            let path = e.path();
            let _ = kill_cgroup(&path);
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

/// `kern gc`: reap orphaned box cgroup dirs under kern.slice and return how many were removed. A
/// direct-path box that `killall`/`stop` SIGKILLs leaves its now-empty `kern-box-*` cgroup dir behind
/// (the next box start's sweep clears it, but a user may `gc` between bursts). No-op when kern.slice
/// isn't in use (a rootless scope host never populates it).
pub fn gc_orphan_box_cgroups() -> usize {
    let Some(slice) = kern_slice_path() else {
        return 0;
    };
    if !slice.is_dir() {
        return 0;
    }
    let count = || {
        fs::read_dir(&slice)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("kern-box-"))
            .count()
    };
    let before = count();
    sweep_orphan_boxes(&slice, 0); // gc is cold → unbounded, reap ALL orphans
    before.saturating_sub(count())
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

/// Parse a cgroup-v2 `/proc/<pid>/cgroup` body (`0::<path>`) into kern's own box-cgroup dir, or `None`.
/// Split out from [`box_cgroup_dir`] so the parse + kern-box gate is unit-testable without a live box.
fn parse_box_cgroup_line(raw: &str) -> Option<PathBuf> {
    let rel = raw.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    let leaf = rel.rsplit('/').next()?;
    if !leaf.starts_with("kern-box-") {
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
/// [`join_box_cgroup_for_exec`].
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

/// Move THIS process into the cgroup that box PID 1 (`pid1`) lives in, so a child forked afterwards
/// (the `kern exec`'d command) inherits the box's memory/pids caps - the same "cap before fork"
/// order the box's own PID 1 uses. Side-effect-only (never creates/removes a cgroup, only ADDS this
/// pid), so it's safe against any target. On the delegated direct-cap path the target is the box's
/// `kern-box-*` cgroup and the write succeeds ([`ExecCgroupJoin::Bound`]); where the kernel forbids
/// the migration (rootless per-box scope) it returns [`ExecCgroupJoin::Unbounded`] IFF the box is
/// really capped, so the caller warns instead of silently running the command uncapped.
pub fn join_box_cgroup_for_exec(pid1: i32) -> ExecCgroupJoin {
    let Some(cg) = proc_cgroup_dir(pid1) else {
        return ExecCgroupJoin::Bound; // no v2 cgroup to speak of - nothing to inherit
    };
    if cg.as_path() == std::path::Path::new("/sys/fs/cgroup") {
        return ExecCgroupJoin::Bound; // the root - never "join" it
    }
    if fs::write(cg.join("cgroup.procs"), std::process::id().to_string()).is_ok() {
        return ExecCgroupJoin::Bound;
    }
    // Couldn't migrate in. Only a resource concern if the box's own cgroup enforces a real cap
    // (its `memory.max`/`pids.max` reads a value, not the `max` no-limit sentinel).
    let real = |f: &str| fs::read_to_string(cg.join(f)).is_ok_and(|v| is_real_limit(&v));
    if real("memory.max") || real("pids.max") {
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
fn ensure_kern_slice() -> Option<PathBuf> {
    static ENSURED: OnceLock<Option<PathBuf>> = OnceLock::new();
    ENSURED.get_or_init(ensure_kern_slice_uncached).clone()
}

fn ensure_kern_slice_uncached() -> Option<PathBuf> {
    let slice = kern_slice_path()?;
    // Already present + delegated? (its `cgroup.controllers` is populated only when delegated.)
    if slice_can_cap(&slice) {
        sweep_orphan_boxes(&slice, SWEEP_LIMIT); // reap dead-supervisor leftovers (bounded on the hot path)
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
const DEFAULT_MEMORY_MAX: u64 = 536_870_912;
/// Process-count ceiling - caps fork bombs.
const DEFAULT_PIDS_MAX: &str = "512";
/// cgroup v2 CPU period (µs) for `cpu.max`; the quota is `cores * PERIOD`.
const CPU_PERIOD_US: u64 = 100_000;

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

/// Confine the current process in a fresh cgroup with memory + pid (+ optional swap / CPU quota /
/// CPU pinning) caps. Returns the cgroup path on success (the workload, forked later, inherits it),
/// or `None` if unavailable. `memory_max` (bytes) overrides the default ceiling; `memory_swap_max`
/// (bytes, `--memory-swap-max`) sets `memory.swap.max` - the v2 swap *allowance*, separate from
/// `memory.max`, default `0` (swap off, so `memory.max` is a hard total); `cpuset` (`--cpuset-cpus`,
/// e.g. `"0-3"`) pins to specific CPUs via `cpuset.cpus`; `cpus` (cores, K8s semantics) caps CPU
/// time via `cpu.max`. The swap/CPU/cpuset knobs are all best-effort - silently skipped where the
/// controller isn't delegated (e.g. `cpuset` is often not delegated inside a systemd user scope).
///
/// `allow_direct` is the caller's authority to take the direct `kern.slice` path: `true` for `kern box`
/// (a supervisor holds the RAII guard and vacates the box cgroup before `rmdir`), `false` for `kern run`
/// (it `exec()`s IN PLACE - no supervisor to move back out - so it must stay on the systemd `--scope`
/// `--collect` path and NEVER relocate into `kern.slice`). This is the one enforcement input that can't be
/// re-derived from env, so the caller passes it explicitly; `took_direct_cap_path()` supplies the rest.
#[allow(clippy::too_many_arguments)] // one cgroup knob per parameter - grouping them would only hide it
pub fn apply_limits(
    allow_direct: bool,
    tag: &str,
    memory_max: Option<u64>,
    memory_swap_max: Option<u64>,
    cpuset: Option<&str>,
    cpus: Option<f64>,
    pids_max: Option<u64>,
    io_max: &[String],
    io_weight: Option<u64>,
    // `--require-limits`: demand that EVERY mandatory cap (memory AND pids) actually bind, not just
    // one of them. Tightens the success gate below from "at least one bound" to "both bound", so a
    // host that delegates one controller and not the other refuses the box instead of running it with
    // a silently-uncapped dimension. `false` keeps the historical best-effort "partial beats nothing".
    require_all: bool,
) -> Option<CgroupGuard> {
    // cgroup v2 presents a unified hierarchy with this file at the root.
    if !PathBuf::from("/sys/fs/cgroup/cgroup.controllers").exists() {
        return None;
    }
    // Where the supervisor is RIGHT NOW - captured BEFORE we move it into the box cgroup, so the guard can
    // move it back and remove the (then-empty) box cgroup on the direct path (no systemd `--collect` there).
    let origin = current_v2_cgroup();
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
    } else {
        origin.clone()?
    };
    let mut child = parent.join(format!("kern-box-{tag}-{}", std::process::id()));

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
        child = parent.join(format!("kern-box-{tag}-{}", std::process::id()));
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
    // below so an early OOM already kills the whole group. Best-effort and SILENT on failure: the file
    // exists only when the `memory` controller is delegated - exactly the case the "--memory not
    // enforced" warning below already reports, so a second message here would be noise, and kern makes
    // no doc promise of atomic OOM termination that a warning would need to defend. Available since
    // Linux 4.19 (all supported hosts: the oldest board is 5.15).
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

    // Join the cgroup - binds the limits to us (and our future forked workload).
    if fs::write(child.join("cgroup.procs"), std::process::id().to_string()).is_err() {
        let _ = fs::remove_dir(&child);
        return None;
    }
    Some(CgroupGuard { dir: child, origin })
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

/// Warn for every cap the caller ASKED for that nothing in this process's cgroup chain enforces.
///
/// The direct path already does this at the inner cgroup (see the `capped_in_tree` warnings above),
/// but the **scope** path hands the knobs to `systemd-run` as `MemoryMax=`/`CPUQuota=`/`TasksMax=`
/// and never re-checked. systemd accepts a property the kernel cannot honour and says nothing: on an
/// Arduino UNO Q's Android kernel the `cpu` controller exposes only the *weight* interface
/// (`cpu.weight`) and no `cpu.max` anywhere in the chain, so `--cpus 0.5` became a share rather than
/// a ceiling, in silence, while `kern doctor` reported caps as enforced. Measured there, not assumed.
///
/// Runs INSIDE the scope, so `/proc/self/cgroup` is the box's own chain and the answer is the
/// effective one. Read-only and best-effort: an unreadable `/proc/self/cgroup` means we cannot tell,
/// and a warning we cannot justify is worse than none, so it stays quiet.
pub fn warn_unenforced_caps(memory: Option<u64>, cpus: Option<f64>, pids: Option<u64>) {
    let Ok(raw) = fs::read_to_string("/proc/self/cgroup") else {
        return;
    };
    // cgroup v2 line: `0::/user.slice/.../foo.scope`. Anything else is v1/hybrid, which this check
    // does not model - staying quiet beats warning about a layout we did not inspect.
    let Some(rel) = raw
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::trim)
        .filter(|p| p.starts_with('/'))
    else {
        return;
    };
    let dir = std::path::Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    // Each knob carries its OWN enforcement check, so the loop dispatches on the check, not on the
    // file name. The three differ on purpose:
    //   * memory - VALUE-aware (`AtOrBelow`): an ancestor `memory.max` larger than the request does not
    //     satisfy `--memory 32m`. A finite-but-larger outer cap once masked a box that asked for less
    //     than it got, so this compares against the request, not mere existence.
    //   * cpu - an ancestor ceiling counts (`TreeExists`): a `cpu.max` anywhere up the chain bounds this
    //     box wherever it sits.
    //   * pids - the box's OWN level only (`HereExists`). Measured on a Raspberry Pi 5,
    //     `--pids-limit 999999999`: the walk found `user-1000.slice pids.max=20370` and stayed quiet,
    //     but 20370 is systemd's session-wide `TasksMax`, shared with every other process the user runs
    //     - not a per-box fork-bomb guard. `apply_caps`'s fail-closed block keys on the box's own
    //     read-back for the same reason; the rule was applied in one place and not the other. Checking
    //     only the box's own level costs no false warning: 64/256/1000000 all landed in the box's cgroup
    //     exactly, only 999999999 did not.
    enum Check<'a> {
        AtOrBelow(u64),
        TreeExists(&'a str),
        HereExists(&'a str),
    }
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
                Check::AtOrBelow(req) => memory_capped_at_or_below(&dir, req),
                Check::TreeExists(file) => capped_in_tree(&dir, file),
                Check::HereExists(file) => capped_here(&dir, file),
            };
        if asked && !capped {
            eprintln!("kern: {flag} accepted but NOT enforced here - {why}; the box can exceed it");
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
        for d in [&dead, &live, &other] {
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

        let _ = std::fs::remove_dir_all(&slice);
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
                origin: None,
            };
        } // guard dropped here
        assert!(
            !d.exists(),
            "guard's Drop must remove the (empty) cgroup dir"
        );
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
        assert!(
            !unix_socket_live(&stale),
            "a stale socket with no listener must read as NOT live"
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
}
