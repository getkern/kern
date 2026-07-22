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

/// Is the systemd manager kern would use actually present? As root → the SYSTEM manager (`/run/systemd/
/// system`, i.e. pid-1 systemd on a systemd host). Rootless → a `systemd` dir under `$XDG_RUNTIME_DIR`.
/// The SINGLE definition - both the scope-skip decision and the fail-closed gate call it, no drift.
pub fn user_systemd_present() -> bool {
    if as_root() {
        return std::path::Path::new("/run/systemd/system").exists();
    }
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(|d| std::path::Path::new(&d).join("systemd").exists())
        .unwrap_or(false)
}

/// Is an OUTER cgroup already enforcing this box's caps, so the direct kern.slice path must NOT be taken?
/// Three cases, all of which run with `KERN_SCOPE` unset-or-set but are already capped/tracked by an
/// ancestor: our own transient systemd `--scope` re-exec (`KERN_SCOPE`), a persistent `--restart` unit
/// (`KERN_MANAGED`, capped by its `kern-<name>.service` cgroup), and a `kern build` RUN step
/// (`KERN_BUILD_STEP`). Taking the direct path for these would move the box OUT of the enforcing ancestor
/// (breaking `stop`/kill for managed units) and could fail-closed-refuse a build/restart into a crash-loop.
fn outer_enforcer_present() -> bool {
    std::env::var_os("KERN_SCOPE").is_some()
        || std::env::var_os("KERN_MANAGED").is_some()
        || std::env::var_os("KERN_BUILD_STEP").is_some()
}

/// In-process marker recording that `choose_direct_cap_path` DECIDED to skip the per-box scope.
/// An env var (not a static) because the decision must survive the detached supervisor's forks -
/// a `--restart` runner re-applies limits in a forked child and must still know the path it's on.
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
    if outer_enforcer_present()
        || std::env::var_os("KERN_NO_SCOPE").is_some()
        || !user_systemd_present()
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
    let claims =
        std::env::var_os("KERN_SCOPE").is_some() || std::env::var_os("KERN_MANAGED").is_some();
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
            let _ = fs::remove_dir(e.path());
        }
    }
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

/// Make the controllers available to `parent`'s children. cgroup-v2 accepts several tokens in one
/// write, so try them all at once (1 syscall); only if that fails enable them one at a time - so an
/// unavailable controller (e.g. no `cpu` on some Android-derived kernels) can't block the others.
/// (Controllers may already be on, or be denied by the no-internal-process rule when the parent has
/// members - all best-effort either way.)
fn enable_subtree_controllers(parent: &std::path::Path) {
    let subtree = parent.join("cgroup.subtree_control");
    if fs::write(&subtree, "+memory +pids +cpu +cpuset +io").is_err() {
        for ctrl in ["+memory", "+pids", "+cpu", "+cpuset", "+io"] {
            let _ = fs::write(&subtree, ctrl);
        }
    }
}

/// Default memory ceiling for a sandbox (512 MiB) - conservative but generous; `--memory` overrides.
const DEFAULT_MEMORY_MAX: u64 = 536_870_912;
/// Process-count ceiling - caps fork bombs.
const DEFAULT_PIDS_MAX: &str = "512";
/// cgroup v2 CPU period (µs) for `cpu.max`; the quota is `cores * PERIOD`.
const CPU_PERIOD_US: u64 = 100_000;

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
    if !pids_ok && !mem_ok {
        let _ = fs::remove_dir(&child);
        return None;
    }
    // (A "not enforced" warning for memory/CPU comes LATER - after all writes - and is based on the
    // EFFECTIVE limit up the cgroup tree, not this single inner write, since the outer systemd scope
    // may be the real enforcer. See `capped_in_tree` below.)

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
    if memory_max.is_some() && !capped_in_tree(&child, "memory.max") {
        eprintln!(
            "kern: --memory not enforced - no cgroup memory cap took effect (the `memory` controller \
             isn't delegated to this rootless scope); the box can exceed the limit"
        );
    }
    if cpus.is_some() && !capped_in_tree(&child, "cpu.max") {
        eprintln!(
            "kern: --cpus not enforced - no cgroup cpu cap took effect (the `cpu` controller isn't \
             delegated to this rootless scope)"
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
}
