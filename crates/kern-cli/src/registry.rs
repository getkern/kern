//! Running-box registry.
//!
//! Each detached box writes one small `key=value` file under `$XDG_RUNTIME_DIR/kern/instances/`
//! (falling back to `/run/user/<uid>/kern/instances/`, then `/tmp/kern-<uid>/instances/`). The
//! "pid" is the supervisor process that lives for the box's lifetime. [`list`] reads the dir and
//! **prunes dead entries** as a side effect, so `kern ps` always reflects reality without a
//! daemon. The on-disk format is deliberately a flat `key=value` file - trivial to write from a
//! post-`fork` supervisor and to parse, no JSON dependency.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// One registered, running box.
#[derive(Clone)]
pub struct Instance {
    pub name: String,
    pub pid: i32,
    /// PID 1 inside the box (host pid-namespace numbering), for `kern exec` to join its
    /// namespaces. 0 until the supervisor learns it (or for an older registry entry).
    pub pid1: i32,
    pub rootfs: String,
    pub command: String,
    /// Unix start time (seconds).
    pub started: u64,
    /// The pid's kernel start-time (`/proc/<pid>/stat` field 22, clock ticks since boot). Pins
    /// the identity of the pid so a reused pid can't masquerade as a live box.
    pub starttime: u64,
    /// Published ports summary for `kern ps` (e.g. `8080->80, 127.0.0.1:443->443`); empty if none.
    pub ports: String,
    /// Comma-separated **named volumes** this box mounts (from `-v name:/dst`) - so `kern volume rm`
    /// can refuse to delete a volume still in use. Empty when none; absent in older entries.
    pub volumes: String,
    /// The **pod** (`--pod <name>`, e.g. a compose stack) this box belongs to - the grouping key for
    /// `kern ps`'s tree view and `kern stop <pod>`. Empty for a standalone box; absent in older entries.
    pub pod: String,
    /// The box's `--workdir`, so `kern exec` can start where the workload started instead of at `/`.
    /// Docker's `exec` inherits the container's WorkingDir and people rely on it: a compose service
    /// with `working_dir: /app` should not need `-w /app` typed again on every exec. Empty when the
    /// box has none; absent in older entries.
    pub workdir: String,
    /// The `--egress-allow` domain allowlist (comma-joined) governing this box's outbound traffic;
    /// empty when the box is fully isolated or shares the host network. Absent in older entries.
    pub egress: String,
    /// The `--landlock-rw` write-allowlist paths (comma-joined) confining the box's writes via the
    /// Landlock LSM; empty when no Landlock policy applies. Absent in older entries.
    pub landlock_rw: String,
    /// The box's requested `memory.max` cap in bytes (`--memory`); `None` when uncapped or absent in
    /// older entries. This is the REQUESTED cap recorded at start, not live usage.
    pub memory_max: Option<u64>,
    /// The box's requested `pids.max` cap (`--pids-limit`); `None` when uncapped or absent.
    pub pids_max: Option<u64>,
    /// `--stop-signal`: the signal `kern stop` sends BEFORE the SIGKILL, as a number (SIGTERM = 15).
    /// 0 or absent in an older entry means SIGTERM.
    pub stop_signal: i32,
    /// `--stop-timeout`: seconds the workload gets to exit on its own before the SIGKILL. 0 or absent
    /// keeps the historical behaviour (immediate SIGKILL).
    pub stop_grace: u64,
    /// Fingerprint of the compose definition this box was created from (`--def-hash`). `up`
    /// compares it against the current file to decide whether a running service is still what the
    /// file asks for; empty for a box created outside compose, or by an older kern.
    pub def_hash: String,
    /// `--label k=v` metadata (comma-joined `k=v` pairs), the compose `labels:` target. Purely
    /// descriptive - it changes nothing about how the box runs - but it is what `kern ps --filter
    /// label=` selects on and what `kern inspect` reports, so tooling can group a stack's boxes.
    /// Empty when none; absent in older entries (the decoder defaults it).
    pub labels: String,
    /// The box's `--cap-drop ALL`: every capability up to `CAP_LAST_CAP` is dropped from the bounding
    /// set. Recorded so `kern exec` reapplies the SAME drop the box's PID 1 got, instead of the
    /// always-dropped baseline. Only meaningful when [`cap_recorded`](Self::cap_recorded) is true.
    pub cap_drop_all: bool,
    /// Extra caps DROPPED beyond the dangerous baseline (`--cap-drop CAP`), as comma-joined cap
    /// numbers (e.g. `12,13`). Empty when none. Reapplied by `kern exec`.
    pub cap_drops: String,
    /// Caps KEPT that the baseline would drop (`--cap-add CAP`, add wins), as comma-joined cap
    /// numbers. Empty when none. Reapplied by `kern exec` so an exec is no MORE dropped than PID 1.
    pub cap_adds: String,
    /// The seccomp filter this box runs (denylist vs the opt-in allowlist). Recorded so `kern exec`
    /// reproduces the box's OWN posture instead of re-reading `KERN_SECCOMP` from the exec caller's
    /// environment - which could enter an allowlist box under the wider denylist. A record with no
    /// `seccompmode` line parses as [`SeccompFilter::Denylist`](kern_isolation::SeccompFilter): the
    /// allowlist did not exist for such a box, so this is provable, not a guess.
    pub seccomp_mode: kern_isolation::SeccompFilter,
    /// `--apparmor <profile>` the box entered on exec (empty = none). Part of the exec POSTURE, like
    /// `seccomp_mode`/`cap_*`: `kern exec` re-enters the RECORDED profile rather than deducing it from
    /// `/proc/<pid1>/attr/apparmor/current`, which reads UNCONFINED for an `--init` box (PID 1 is the
    /// reaper, which never execs into the profile) and would run the exec OUTSIDE the box's confinement.
    /// Absent line (older record) → empty → exec adds no transition, matching a box that ran unconfined.
    pub apparmor: String,
    /// Whether this record carries a capability profile at all (the `capdropall` line was present).
    /// `false` for a box created before the cap fields existed: `exec` cannot know whether that box
    /// dropped ALL caps or none, so it REFUSES rather than guess a baseline that could be more
    /// privileged than the box actually is. Derived at parse time; never serialised.
    pub cap_recorded: bool,
    /// Whether the record carried an `apparmor=` line (added after the cap fields, so an older record
    /// omits it). ABSENT means the box's AppArmor posture is UNKNOWABLE (it may have run under
    /// `--apparmor`), so `exec` REFUSES rather than re-enter nothing and run UNCONFINED, the same
    /// fail-closed as `cap_recorded`. PRESENT-but-empty means the box ran with no profile (exec adds no
    /// transition). Derived at parse time from the line's presence; never serialised.
    pub aa_recorded: bool,
    /// Whether the record carried a `seccompmode=` line. Mirrors `aa_recorded`/`cap_recorded`: ABSENT
    /// means the box predates seccomp-posture recording, so `exec` REFUSES rather than reproduce the
    /// weaker `Denylist` default a missing line parses to. Makes the exec gate MECHANICAL instead of
    /// relying on the field-order coincidence that a missing `seccompmode` also implies a missing
    /// `apparmor`. Derived at parse time from the line's presence; never serialised.
    pub seccomp_recorded: bool,
    /// Set when a posture field that IS present is malformed (`capdropall` not `0`/`1`, a non-numeric
    /// cap in `capdrops`/`capadds`, or an unrecognised `seccompmode`). `exec` refuses on a corrupt
    /// record rather than apply a partial posture that could be less restrictive than the box's.
    /// Derived at parse time; never serialised.
    pub posture_corrupt: bool,
    /// The box's DEDICATED cgroup v2 path (absolute, under `/sys/fs/cgroup`), recorded once PID 1 is
    /// known. EMPTY for a box with no dedicated cgroup (no systemd-user: its processes share kern's own
    /// session cgroup, which is ALWAYS populated, so it carries no orphan signal) and for older entries.
    /// This is the STABLE identity used to decide liveness WITHOUT a live pid - a cgroup path does not
    /// recycle the way a pid does - so a box whose supervisor died but whose cgroup is still populated is
    /// recognised as ORPHANED (reachable + reapable), not silently dropped while it still holds its port.
    pub cgroup: String,
    /// The recorded cgroup dir's `(st_dev, st_ino)` IDENTITY, captured together with [`cgroup`]. The
    /// path ALONE is not a safe reap target: its `kern-box-<name>-<pid>` leaf embeds a PID, and PIDs
    /// recycle, so a LATER box could come to occupy the exact same path after THIS box's supervisor
    /// died, and `cgroup.kill` on the path would then SIGKILL the wrong box (running under this box's
    /// stale `memory.max`). The kernel assigns each cgroup a unique inode that is NOT reused for the
    /// dir's lifetime; before trusting the path for either liveness OR a reap, kern re-`stat`s it and
    /// refuses if the identity differs (the path was recreated as a different cgroup, so this box is
    /// gone). `None` for a box with no dedicated cgroup or an older entry (the path is empty too, so
    /// liveness falls back to the supervisor pid). [Self::cgroup]
    pub cgroup_id: Option<(u64, u64)>,
    /// Derived at LOAD time (never serialised): the supervisor pid is dead, but the recorded [`cgroup`]
    /// is still populated - the box's PID 1 / `-p` forwarder outlived the supervisor. Such a box stays
    /// VISIBLE in `kern ps` (marked `orphaned`) and REAPABLE by `kern stop`/`gc` via `cgroup.kill`,
    /// instead of vanishing from the registry while it still holds a host port bound.
    /// [Self::cgroup]
    pub orphaned: bool,
}

impl Instance {
    /// The named volumes this box mounts. Sole decoder of the comma-separated `volumes` wire-format
    /// (empties filtered) - `volume rm`/`prune` ask through here rather than splitting the raw field,
    /// so the encoding lives in one place (paired with `commands::mounted_named_volumes`, the encoder).
    pub fn volume_names(&self) -> impl Iterator<Item = &str> {
        self.volumes.split(',').filter(|v| !v.is_empty())
    }

    /// The pid to resolve the box's DEDICATED cgroup from (for `pause`/`stats`/`update`/freeze).
    /// Use the box's in-box PID 1 (`pid1`, host-namespace numbering) - it always lives in the box's
    /// real cgroup on BOTH cap paths: the direct `kern.slice/kern-box-*` path (where the SUPERVISOR
    /// pid does NOT - it stays in the launcher's cgroup) and the systemd-scope re-exec path (where
    /// both do). Fall back to the supervisor `pid` when `pid1` isn't learned yet (0) or for an older
    /// registry entry, matching the pre-existing behaviour.
    pub fn cgroup_pid(&self) -> i32 {
        if self.pid1 > 0 {
            self.pid1
        } else {
            self.pid
        }
    }
}

/// The instances directory (one file per running box), created on demand.
pub fn dir() -> io::Result<PathBuf> {
    runtime_subdir("instances")
}

/// The logs directory (one `<name>-<pid>.log` per detached box), created on demand.
pub fn logs_dir() -> io::Result<PathBuf> {
    runtime_subdir("logs")
}

/// The SSH keys directory (`--ssh` stores a throwaway private key here so the user can `ssh -i` it).
/// On a tmpfs runtime dir it's cleared on logout; owner-only like the rest of the runtime tree.
pub fn ssh_dir() -> io::Result<PathBuf> {
    runtime_subdir("ssh")
}

/// The health directory - a sidecar `<name>-<pid>` per box with `--health-cmd`, holding its latest
/// status. Kept SEPARATE from `instances/` so `list()` never mistakes a status file for a box entry.
fn health_dir() -> io::Result<PathBuf> {
    runtime_subdir("health")
}

/// Record a box's latest health (`healthy`/`unhealthy`/`starting`); written by the health-checker.
pub fn set_health(name: &str, pid: i32, status: &str) {
    if let Ok(d) = health_dir() {
        let _ = fs::write(d.join(format!("{name}-{pid}")), status);
    }
}

/// A box's current health, or empty string if it has no health check.
pub fn health_of(name: &str, pid: i32) -> String {
    health_dir()
        .ok()
        .and_then(|d| fs::read_to_string(d.join(format!("{name}-{pid}"))).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Remove a box's health sidecar (on stop / de-register).
pub fn clear_health(name: &str, pid: i32) {
    if let Ok(d) = health_dir() {
        let _ = fs::remove_file(d.join(format!("{name}-{pid}")));
    }
}

/// The exit directory - a sidecar per box that has RUN TO COMPLETION, holding its `<code>` as decimal
/// text. Written by the detached supervisor when a box's main process exits for good (no `--restart`
/// left). Consumed by `kern compose`'s `depends_completed` (Docker's `service_completed_successfully`):
/// the box has left `list()`, and this tells us whether it finished cleanly (0) or failed.
///
/// The sidecar filename is an opaque compose-supplied KEY that encodes BOTH the stack AND the `up`
/// epoch: `<pod>-<token>-<name>` (adversarial review, rounds 1-2):
///  * **`<pod>`** namespaces by stack, so two different stacks that each contain a `db` never collide
///    on one `exit/db` - one stack could otherwise read the OTHER's `db` exit.
///  * **`<token>`** (a fresh per-`up` epoch) namespaces by RUN. This is the round-2 fix: with the
///    token only INSIDE the file, two concurrent `up`s of the same stack shared the filename, so one
///    `up`'s `clear`-before-spawn would DELETE the other's real completion - a healthy stack failing
///    because a peer `up` wiped its state, not fail-closed. With the token in the KEY, each run owns
///    its own files; a concurrent run's clear/write can't touch them. Isolation is structural.
///
/// Because a separate `down` invocation doesn't know the `up`'s token, it reaps each box's sidecar by
/// pod-prefix AND box-name-suffix (`<pod>-*-<name>`, see `clear_exit_matching`) - NOT a blind `<pod>-`
/// prefix, which would delete a concurrent same-stack run's in-flight files. Kept SEPARATE from
/// `instances/` so `list()` never mistakes it for a live box. The runtime dir is NOT in a box's mount
/// namespace (verified), so a workload can't forge another service's exit.
fn exit_dir() -> io::Result<PathBuf> {
    runtime_subdir("exit")
}

/// AUTHORITATIVE registry children: those whose records kern READS and ACTS ON for ANOTHER box, so a
/// forged record steers kern against a peer - plus `ssh/`, whose per-box host keys are a cross-box
/// SECRET. NONE may be bind-mounted into a box.
///  * `instances` / `claims` - forge a peer's capability/seccomp posture → its `kern exec` re-adds caps.
///  * `exit` - forge a compose completion → `depends_completed` releases a dependent early.
///  * `waitexit` - forge an exited-box record → the operator's `kern ps -a` shows arbitrary rows.
///  * `health` - forge a peer's health → `--health-action restart|stop` acts on that peer's process
///    (worse than display: kern signals a box on the attacker's word).
///  * `pods` - forge `holder`/`netns` → `kern box --pod` `setns`es into a victim's namespaces, or a
///    teardown SIGKILLs the victim pid recorded as the holder.
///  * `ssh` - reading a peer's generated sshd host key lets a box impersonate that peer's `--ssh` server.
///
/// [`trusted_state_dirs`] and [`guarded_identities`] are DERIVED from this ONE list, and
/// `every_registry_child_is_classified` fails the build on a registry child in neither this nor
/// [`BOX_DATA_DIRS`] - so a dir added here is protected by construction, closing the parallel-list drift
/// that let `waitexit/` ship mountable.
const AUTHORITATIVE_DIRS: [&str; 7] = [
    "instances",
    "claims",
    "exit",
    "waitexit",
    "health",
    "pods",
    "ssh",
];

/// Registry children that are OPAQUE box DATA kern never interprets: mounting one is access to a peer
/// box's own bytes - the same operator foot-gun as `-v /home/other`, not a forgeable control record.
/// `logs` is a box's captured output; `scratch` is its overlay upper/work. (`volumes/` is a SIBLING
/// tree under `$XDG_DATA_HOME`, not a registry child, and is mountable by design - the named-volume
/// mechanism itself; `runstats` is a single cosmetic counter FILE `kern top` only displays.)
///
/// One consequence worth stating: because `scratch/` holds a box's overlay UPPER, an operator who
/// mounts a peer's `scratch/` writable into another box AND `kern commit`s that peer while it runs lands
/// the mounted box's bytes in the PUBLISHED image. It stays a foot-gun (an operator `-v`, never in-box
/// code), but the effect leaves the box - a published artefact - so it is documented, not silent.
const BOX_DATA_DIRS: [&str; 2] = ["logs", "scratch"];

/// The classification CHOKEPOINT: every function that builds a `<runtime>/kern/<name>` path calls this,
/// so a registry-root child cannot be created without being in a class. A new unclassified `name` would
/// default to MOUNTABLE - the exact way `waitexit/` shipped as a hole - so it trips here in debug/test
/// builds (compiled out of release: zero cost). `runtime_subdir`, `pod::pods_root` and `scratch_dir` all
/// route through it even though they diverge on how they RESOLVE the path; the check is on the NAME, not
/// the resolution. A static gate (`scripts/registry-classified.py`) is the compile-time backstop for a
/// future constructor that forgets to call it.
pub(crate) fn assert_registry_child(name: &str) {
    debug_assert!(
        AUTHORITATIVE_DIRS.contains(&name) || BOX_DATA_DIRS.contains(&name),
        "unclassified registry child {name:?}: add it to AUTHORITATIVE_DIRS (kern reads and acts on it \
         for another box, or it is a cross-box secret) or BOX_DATA_DIRS (opaque box bytes)"
    );
}

/// The path of each AUTHORITATIVE child, asked of the function that OWNS it, never reconstructed: `pods/`
/// comes from `pod::pods_root` (its real resolver), the rest from `existing_runtime_subdir` (the
/// non-creating sibling of `runtime_subdir`, THEIR resolver's candidate list). Since the inverted guard
/// now refuses the whole root minus the box-data allowlist, the DIRECT mount of every authoritative dir
/// is caught by containment regardless of resolver; this exact path only feeds the dev/ino ALIAS check
/// ([`guarded_identities`]), where a reconstruction that missed a divergent resolver would let a `mount
/// --bind` of that dir slip through. A future divergent-resolver dir turned authoritative needs its real
/// resolver added here (its DIRECT mount is already safe).
fn authoritative_paths() -> impl Iterator<Item = PathBuf> {
    AUTHORITATIVE_DIRS.iter().filter_map(|leaf| match *leaf {
        "pods" => Some(crate::pod::pods_root()),
        // NON-creating (`existing_runtime_subdir`, not `runtime_subdir`): resolving the identity set must
        // not mkdir authoritative dirs (`ssh/`, `claims/`, …) that no box has needed yet. `pods_root`
        // already only joins.
        other => existing_runtime_subdir(other),
    })
}

/// The AUTHORITATIVE dir paths, DERIVED from [`AUTHORITATIVE_DIRS`], each canonicalized. The live guard
/// no longer enumerates these (it refuses the whole root minus the box-data allowlist - see
/// [`path_overlaps_trusted_state`]); this survives only so the anti-forgery TESTS can assert every
/// authoritative dir is still refused in every canonical/bind form.
#[cfg(test)]
pub fn trusted_state_dirs() -> Vec<PathBuf> {
    authoritative_paths()
        .filter_map(|d| fs::canonicalize(d).ok())
        .collect()
}

/// TEST-ONLY: CREATE every authoritative registry dir (`<root>/kern/<leaf>`). Production resolves the
/// identity set NON-creatingly ([`existing_runtime_subdir`]), so a test that needs these dirs present -
/// to canonicalize their forms or read their dev+ino - must materialize them explicitly rather than lean
/// on a side effect. `runtime_subdir("pods")` creates the same path `pod::pods_root` resolves to.
#[cfg(test)]
pub(crate) fn materialize_authoritative_dirs_for_test() {
    for leaf in AUTHORITATIVE_DIRS {
        let _ = runtime_subdir(leaf);
    }
}

/// The canonical registry ROOT `<runtime>/kern` (parent of `instances/`), or `None` if it does not
/// resolve. Canonicalized so the containment test below matches the canonicalized `-v` source.
fn registry_root() -> Option<PathBuf> {
    dir()
        .ok()
        .as_deref()
        .and_then(Path::parent)
        .and_then(|r| fs::canonicalize(r).ok())
}

/// The `(device, inode)` identity of each NON-mountable registry location a `mount --bind` alias could
/// smuggle in: the registry ROOT, every [`AUTHORITATIVE_DIRS`] child, and the `runstats` counter FILE.
/// A bind of one of these to `/elsewhere` gives `/elsewhere` a different canonical path but the SAME
/// dev+ino, which the PATH check in [`path_overlaps_trusted_state`] would miss and this catches - the
/// same identity approach as the vgpio device guard. BOX_DATA children are deliberately NOT here: a bind
/// alias of `logs/`/`scratch/` is as mountable as the dir itself.
fn guarded_identities() -> Vec<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let mut paths: Vec<PathBuf> = authoritative_paths().collect();
    if let Some(root) = registry_root() {
        paths.push(root);
    }
    paths.push(crate::runstats::path()); // the cosmetic counter FILE (still non-mountable)
    paths
        .iter()
        .filter_map(|p| fs::metadata(p).ok())
        .map(|m| (m.dev(), m.ino()))
        .collect()
}

/// Would bind-mounting `src` (already canonicalized) into a box expose registry state it must not
/// reach? INVERTED DEFAULT: anything resolving under the runtime registry root is refused UNLESS its
/// top-level child is an explicitly-mountable [`BOX_DATA_DIRS`] dir. So a child added tomorrow (as
/// `runstats` was) is non-mountable by OMISSION, not mountable by omission - the class the `waitexit/`
/// miss lived in, closed at the root instead of one dir at a time. Three shapes are refused:
///  * a source UNDER the root whose first component is not a box-data child (`instances/…`, `runstats`,
///    or any unclassified future child),
///  * the root itself OR an ANCESTOR that contains it (`-v $XDG_RUNTIME_DIR:/x` exposes it by traversal),
///  * a `mount --bind` ALIAS whose canonical path is elsewhere but whose dev/ino is the root or a
///    non-box-data child (identity, which the path check alone would wave through).
pub fn path_overlaps_trusted_state(src: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(root) = registry_root() else {
        return false;
    };
    if let Some(verdict) = mount_refused_by_path(src, &root) {
        return verdict;
    }
    // Not under the root by path. Only a `mount --bind` ALIAS remains (a different canonical path
    // carrying a registry dir's dev/ino). A bind alias shares the registry FILESYSTEM's device, so a
    // `src` on a DIFFERENT device CANNOT be one - short-circuit before building the identity set, which
    // otherwise `metadata`s ~9 registry dirs on EVERY normal `-v`/`--rootfs` (a `/home` source, on the
    // real disk not the runtime tmpfs, hits exactly this fall-through). `root` is resolved ONCE here and
    // in `mount_refused_by_path` above.
    let (Ok(sm), Ok(rm)) = (fs::metadata(src), fs::metadata(&root)) else {
        return false;
    };
    if sm.dev() != rm.dev() {
        return false;
    }
    guarded_identities().contains(&(sm.dev(), sm.ino()))
}

/// The PATH half of [`path_overlaps_trusted_state`], PURE so the inversion is unit-tested without a
/// filesystem. `Some(true)` = refuse, `Some(false)` = allow (a box-data child), `None` = no path
/// overlap, the caller falls through to the dev/ino identity check.
fn mount_refused_by_path(src: &Path, root: &Path) -> Option<bool> {
    if let Ok(rel) = src.strip_prefix(root) {
        // Under the root (or IS the root when `rel` is empty): mountable ONLY if the first component is
        // a box-data child. Empty `rel` -> no component -> refused (the root itself).
        return Some(
            !rel.components()
                .next()
                .and_then(|c| c.as_os_str().to_str())
                .is_some_and(|name| BOX_DATA_DIRS.contains(&name)),
        );
    }
    if root.starts_with(src) {
        return Some(true); // src is an ANCESTOR of the root - mounting it exposes the whole registry
    }
    None
}

/// Record a completed box's final exit code under compose's stack+run-scoped `key`
/// (`<pod>-<token>-<name>`). Best-effort.
pub fn set_exit(key: &str, code: i32) {
    if let Ok(d) = exit_dir() {
        let _ = fs::write(d.join(key), code.to_string());
    }
}

/// A completed box's recorded exit code for `key`, or `None` if it hasn't completed here or the
/// sidecar is malformed. The key already carries the run's token, so any file that exists for it
/// belongs to THIS run - no separate token check needed. `Some(0)` = finished successfully.
pub fn exit_of(key: &str) -> Option<i32> {
    exit_dir()
        .ok()
        .and_then(|d| fs::read_to_string(d.join(key)).ok())
        .and_then(|s| s.trim().parse().ok())
}

/// Remove a box's exit sidecar for the exact `key` - compose calls this BEFORE (re)launching the box.
/// Best-effort.
pub fn clear_exit(key: &str) {
    if let Ok(d) = exit_dir() {
        let _ = fs::remove_file(d.join(key));
    }
}

/// The `kern wait` exit directory - a `<pid>-<starttime>` sidecar holding a completed box's exit code
/// as decimal text. SEPARATE from compose's `exit/` (whose keys are `<pod>-<token>-<name>`). Keyed on
/// the supervisor pid AND its kernel start-time, NOT the name: (a) a `kern rename` never orphans the
/// record (it isn't name-derived), and (b) a recycled pid with a different start-time can't be read as
/// the old box. Written by EVERY detached supervisor and by `stop`/`kill`. Kept out of `instances/` so
/// `list()` never mistakes it for a live box.
fn waitexit_dir() -> io::Result<PathBuf> {
    runtime_subdir("waitexit")
}

/// Record a completed box's exit code for `kern wait`, keyed `<pid>-<starttime>`. Written by the
/// detached supervisor as its LAST act (before it unregisters) and by `stop`/`kill` (which SIGKILL the
/// supervisor before it can record its own). Best-effort.
pub fn set_box_exit(pid: i32, starttime: u64, code: i32, name: &str, pod: &str, command: &str) {
    if let Ok(d) = waitexit_dir() {
        // Multi-line so `kern ps -a` can render the box that exited (its name, pod, command), not only
        // the code `kern wait` needs. Line 1 stays the BARE code, so `box_exit` - and any pre-existing
        // bare-code sidecar from an older kern - still parses. The command is flattened to one line (the
        // record is line-delimited) and CAPPED: it is a display string, and an unbounded argv must not
        // set the sidecar's on-disk size - the dir is bounded by count, not by any single record.
        let command: String = command
            .chars()
            .filter(|c| *c != '\n' && *c != '\r')
            .take(512)
            .collect();
        let body = format!("{code}\n{name}\n{pod}\n{command}");
        let _ = fs::write(d.join(format!("{pid}-{starttime}")), body);
    }
}

/// A completed box's recorded exit code for `(pid, starttime)`, or `None` if it never completed here.
/// NON-consuming: several `kern wait` on the same box all read the same code (matching Docker); the
/// sidecar is reaped by `prune`/`gc` once the pid is dead, not on read.
pub fn box_exit(pid: i32, starttime: u64) -> Option<i32> {
    waitexit_dir()
        .ok()
        .and_then(|d| fs::read_to_string(d.join(format!("{pid}-{starttime}"))).ok())
        // Line 1 is the code (the record grew extra lines for `ps -a`); a bare-code sidecar is line 1
        // alone, so both formats read here.
        .and_then(|s| s.lines().next().and_then(|l| l.trim().parse().ok()))
}

/// Reap the `waitexit` sidecars of a stack's boxes on `compose down`: those whose recorded pod == `pod`
/// AND whose name is one of `names`. So `compose ps -a` is empty after a teardown (matching Docker),
/// while `compose stop` leaves the exited services visible. Scoped to the pod AND the caller's OWN
/// service names - the exact scoping `clear_exit_matching` uses for the compose `exit/` dir - so a
/// foreign box's record is never touched. Two residuals remain, both a lost diagnostic record and never
/// a misattribution, both the class `exit/` already accepts. FIRST, another run - CONCURRENT or a PRIOR
/// one not yet `gc`ed - that shares BOTH the pod name and a service name (two checkouts of the same
/// project reach this with no live overlap): a run token would not help, since `down` never learns the
/// `up`'s token, exactly as `exit/` reaps every token for a name rather than a specific one. SECOND, a
/// service RENAMED between `up` and `down`, whose old-name record is not in `names` and so is left for
/// the `WAITEXIT_SHOW_SECS` read-reap instead of being cleared here. Best-effort; returns the count.
pub fn clear_waitexit_pod(pod: &str, names: &[String]) -> usize {
    let Ok(d) = waitexit_dir() else { return 0 };
    let mut n = 0usize;
    if let Ok(rd) = fs::read_dir(&d) {
        for e in rd.flatten() {
            if waitexit_split(&e.file_name()).is_none() {
                continue; // not a `<pid>-<starttime>` sidecar
            }
            let Ok(body) = fs::read_to_string(e.path()) else {
                continue;
            };
            let (_, rec_name, rec_pod, _) = parse_waitexit_body(&body);
            if rec_pod == pod
                && names.iter().any(|s| s == rec_name)
                && fs::remove_file(e.path()).is_ok()
            {
                n += 1;
            }
        }
    }
    n
}

/// Decode a `waitexit` sidecar filename `<pid>-<starttime>` (both numeric) into its key, or `None` if
/// malformed. The SOLE parser of that grammar, so `sweep_waitexit_dead` (which reaps by it) and
/// `list_exited` (which lists by it) can never drift on what a valid sidecar name is - the same reason
/// [`entry_split`] is the sole decoder of the instances-tree key.
fn waitexit_split(name: &std::ffi::OsStr) -> Option<(i32, u64)> {
    let (pid, st) = name.to_str()?.split_once('-')?;
    Some((pid.parse().ok()?, st.parse().ok()?))
}

/// Decode a `waitexit` sidecar BODY `code\nname\npod\ncommand` into its fields - the SOLE body parser
/// (as [`waitexit_split`] is the sole NAME parser), so `clear_waitexit_pod` and `list_exited` never
/// drift on the line layout [`set_box_exit`] writes. `code` defaults to 0 for a legacy bare-code / short
/// record; `name`/`pod` are trimmed; `command` is returned RAW (it is scrubbed on human display and
/// `\u`-escaped in JSON, so it keeps its bytes here for JSON fidelity). `box_exit` does NOT use this: it
/// reads line 1 alone and needs `None` (not 0) when the code is unparseable, a distinct semantics.
fn parse_waitexit_body(body: &str) -> (i32, &str, &str, &str) {
    let mut lines = body.lines();
    let code = lines
        .next()
        .and_then(|l| l.trim().parse().ok())
        .unwrap_or(0);
    let name = lines.next().unwrap_or("").trim();
    let pod = lines.next().unwrap_or("").trim();
    let command = lines.next().unwrap_or("");
    (code, name, pod, command)
}

/// Sweep `wait` exit sidecars whose `(pid, starttime)` is no longer a live box - bounds the dir against
/// boxes that exited but were never `wait`ed on. Returns the count removed. Called from `prune` and
/// `gc`. A live box's sidecar is kept (via [`is_alive`], which also rejects a reused pid whose
/// start-time differs). Best-effort.
pub fn sweep_waitexit_dead() -> usize {
    let Ok(d) = waitexit_dir() else { return 0 };
    let mut n = 0usize;
    if let Ok(rd) = fs::read_dir(&d) {
        for e in rd.flatten() {
            // Reap unless that exact box is still alive; a malformed name is an orphan, also reaped.
            let dead = match waitexit_split(&e.file_name()) {
                Some((p, s)) => !is_alive(p, s),
                None => true,
            };
            if dead && fs::remove_file(e.path()).is_ok() {
                n += 1;
            }
        }
    }
    n
}

/// One box that has exited but whose `waitexit` sidecar `gc`/`prune` has not yet reaped - the data
/// behind `kern ps -a`. Reconstructed from the sidecar (`<pid>-<starttime>` → `code\nname\npod\n
/// command`) plus its mtime for "how long ago". kern keeps NO durable per-container object the way
/// podman's on-disk store does (a stopped container there survives until `podman rm`); this is a
/// transient breadcrumb, reaped on the next `gc`, so `ps -a` shows the RECENTLY exited, not history.
pub struct ExitedBox {
    pub name: String,
    pub pid: i32,
    /// The pid's kernel start-time, so `ps -a`'s live/exited dedup keys on the FULL `(pid, starttime)`
    /// identity - a fresh live box that recycles a within-window exited box's pid can't hide it.
    pub starttime: u64,
    pub code: i32,
    pub pod: String,
    pub command: String,
    /// Seconds since the box exited, from the sidecar's mtime.
    pub exited_ago: u64,
}

/// How long an exited box stays visible to `kern ps -a` before it is treated as history and reaped.
/// `ps -a` is "RECENTLY exited", not an unbounded log: a sidecar older than this is stale, so
/// `list_exited` removes it on read (below) - the same read-time self-heal `list()` does for a live
/// record whose box is gone. Bounds the dir for anyone who runs `ps -a`; `gc`/`prune` still reap the
/// rest. One hour is long enough to answer "what just died in my stack" and short enough to bound.
const WAITEXIT_SHOW_SECS: u64 = 3600;

/// Every exited box still holding a `waitexit` sidecar within the display window, NEWEST first. A
/// sidecar whose `(pid, starttime)` is somehow still alive is skipped - it is a live box, already in
/// [`list`], not an exited one. One older than [`WAITEXIT_SHOW_SECS`] is REAPED here (read-time
/// self-heal, mirroring `list()`), so `ps -a` shows the recent, not history. A bare-code sidecar from
/// an older kern has no name/pod/command; it still lists, named by its pid, rather than silently vanish.
pub fn list_exited() -> Vec<ExitedBox> {
    let Ok(d) = waitexit_dir() else {
        return Vec::new();
    };
    let now = now_unix();
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(&d) else {
        return out;
    };
    for e in rd.flatten() {
        let Some((pid, starttime)) = waitexit_split(&e.file_name()) else {
            continue;
        };
        if is_alive(pid, starttime) {
            continue;
        }
        // mtime BEFORE the body read: a stale record is reaped without paying to read it.
        let mtime = e
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(now, |dur| dur.as_secs());
        let ago = now.saturating_sub(mtime);
        if ago > WAITEXIT_SHOW_SECS {
            let _ = fs::remove_file(e.path()); // best-effort read-time reap of history
            continue;
        }
        let Ok(body) = fs::read_to_string(e.path()) else {
            continue;
        };
        let (code, name, pod, command) = parse_waitexit_body(&body);
        // name/pod come off DISK: scrub terminal-control bytes at the source so EVERY consumer (table,
        // `-q`, `--format`, `--json`) is safe, not just the ones that remembered. A no-op on a valid
        // `BoxName`; defence in depth if a legacy/forged record ever carried control bytes. (command is
        // scrubbed on human display and `\u`-escaped in JSON, so it stays raw here for JSON fidelity.)
        out.push(ExitedBox {
            name: if name.is_empty() {
                format!("(pid {pid})")
            } else {
                crate::ui::scrub(name)
            },
            pid,
            starttime,
            code,
            pod: crate::ui::scrub(pod),
            command: command.to_string(),
            exited_ago: ago,
        });
    }
    out.sort_by_key(|e| e.exited_ago);
    out
}

/// The LIVE box whose supervisor pid is `pid`, or `None`. The single anti-spoof scan behind
/// [`name_for_pid`] and [`current_caps`]: only an entry whose body `name=` AGREES with its filename AND
/// that is a live box is trusted, so a planted, inconsistent, or stale `<x>-<pid>` file can't steer a
/// box's identity. O(n) scan of the (small) instances dir. (`find_ref` is a DIFFERENT scan, keyed on
/// the body `pid=` and opening every entry, so it stays separate.)
fn live_by_pid(pid: i32) -> Option<Instance> {
    let d = dir().ok()?;
    for e in fs::read_dir(&d).ok()?.flatten() {
        let fname = e.file_name();
        let Some((name, p)) = entry_split(&fname) else {
            continue;
        };
        if p.parse::<i32>() != Ok(pid) {
            continue;
        }
        if let Some(inst) = load_live(&e.path()) {
            if inst.name == name {
                return Some(inst);
            }
        }
    }
    None
}

/// The CURRENT on-disk name of the live box whose supervisor pid is `pid`, or `None`. Long-lived
/// writers (the supervisor's restart re-register, the health checker, `update_caps`) call this so a
/// `kern rename` is honoured instead of resurrecting the box's ORIGINAL name.
pub fn name_for_pid(pid: i32) -> Option<String> {
    live_by_pid(pid).map(|inst| inst.name)
}

/// The `(memory_max, pids_max)` the LIVE box with `pid` currently records, or `None` if there is no
/// live entry for it. The registry record is the source of truth for a box's caps after a `kern
/// update` (which writes them here), so the in-process restart supervisor reads them back on each
/// (re)start to keep an updated limit in force instead of snapping to the box's original spec.
pub fn current_caps(pid: i32) -> Option<(Option<u64>, Option<u64>)> {
    live_by_pid(pid).map(|inst| (inst.memory_max, inst.pids_max))
}

/// Remove every exit sidecar whose filename starts with `prefix` (compose passes `<pod>-`). Used by
/// `compose down`, which - being a separate invocation - doesn't know the `up`'s token and so can't
/// name the exact per-run key. Reaping is scoped to BOTH ends - `<prefix>…<suffix>` - so `compose
/// down` clears `<pod>-<*any-token*>-<name>` only for the box `<name>` it is actually stopping. A
/// blind `<pod>-` prefix would ALSO delete `<pod>-<otherToken>-<name>` of a DIFFERENT run of the same
/// stack that is still in flight - re-opening, from the GC side, the exact cross-run deletion the
/// token-in-key fix closed for clear/write (adversarial review, final round). Anchoring the suffix to
/// the box name keeps GC safe: the only run that can own `<pod>-*-<name>` is the one whose `<name>`
/// box exists, and duplicate live box names are refused, so down can't wipe a concurrent run's box.
/// Best-effort.
pub fn clear_exit_matching(prefix: &str, suffix: &str) {
    if let Ok(d) = exit_dir() {
        if let Ok(entries) = fs::read_dir(&d) {
            for e in entries.flatten() {
                if exit_key_bracketed(&e.file_name().to_string_lossy(), prefix, suffix) {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
    }
}

/// Does `name` start with `prefix` AND end with `suffix`, with the two NOT overlapping? The length
/// guard is the subtle part: without it, `prefix` and `suffix` could match the same bytes on a short
/// filename (e.g. prefix `p-` and suffix `-p` both matching `-p-`), reaping a file that isn't really
/// `<prefix><token><suffix>`. Pure so it's unit-tested without touching the filesystem.
fn exit_key_bracketed(name: &str, prefix: &str, suffix: &str) -> bool {
    name.len() >= prefix.len() + suffix.len() && name.starts_with(prefix) && name.ends_with(suffix)
}

/// Create and return `<runtime>/kern/<leaf>`, with graceful fallbacks.
/// The ordered candidate paths for a registry subdir, WITHOUT touching disk: `$XDG_RUNTIME_DIR/kern/<leaf>`,
/// then `/run/user/<uid>/kern/<leaf>`, then the `/tmp/kern-<uid>/<leaf>` fallback. Shared by the CREATING
/// resolver ([`runtime_subdir`], which mkdir's the first it can) and the NON-creating one
/// ([`existing_runtime_subdir`], which returns the first that already exists), so the two can never drift
/// on where a dir lives - the resolver-divergence [`authoritative_paths`] warns about.
fn runtime_subdir_candidates(leaf: &str) -> Vec<PathBuf> {
    assert_registry_child(leaf);
    let uid = unsafe { libc::getuid() };
    let mut candidates = Vec::new();
    if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR") {
        candidates.push(PathBuf::from(x).join("kern").join(leaf));
    }
    candidates.push(PathBuf::from(format!("/run/user/{uid}/kern/{leaf}")));
    candidates.push(PathBuf::from(format!("/tmp/kern-{uid}/{leaf}")));
    candidates
}

fn runtime_subdir(leaf: &str) -> io::Result<PathBuf> {
    // Create every component we own as **0700**: `$XDG_RUNTIME_DIR`/`/run/user/<uid>` are already
    // owner-only, but the `/tmp/kern-<uid>` fallback lives under world-traversable `/tmp`, and this
    // tree can hold private material (the `--ssh` throwaway key). `DirBuilder` only sets the mode on
    // components it creates, so an existing (systemd-owned) runtime dir is left untouched.
    use std::os::unix::fs::DirBuilderExt;
    let mut last_err = io::Error::other("no writable runtime dir");
    for d in runtime_subdir_candidates(leaf) {
        match fs::DirBuilder::new().recursive(true).mode(0o700).create(&d) {
            Ok(()) => return Ok(d),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// The first already-EXISTING candidate for a registry subdir, or `None` - the non-creating sibling of
/// [`runtime_subdir`]. The identity check ([`guarded_identities`]) only STATs these dirs to fingerprint
/// them; it must not mkdir a dir that never existed (e.g. `ssh/` when no box used `--ssh`) merely to read
/// its dev/ino. A dir that does not exist cannot be a `mount --bind` alias source, so skipping it is safe.
fn existing_runtime_subdir(leaf: &str) -> Option<PathBuf> {
    runtime_subdir_candidates(leaf)
        .into_iter()
        .find(|d| d.exists())
}

/// The cgroup v2 directory of `pid` under `/sys/fs/cgroup`, from `/proc/<pid>/cgroup`.
fn cgroup_of(pid: i32) -> Option<PathBuf> {
    let s = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let rel = s.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    Some(PathBuf::from("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// Our own cgroup, resolved once. It never changes over the process's life, so caching it avoids
/// re-reading `/proc/self/cgroup` for every `box_cgroup` call (four per box per `top` frame).
fn own_cgroup() -> Option<&'static PathBuf> {
    static OWN: OnceLock<Option<PathBuf>> = OnceLock::new();
    OWN.get_or_init(|| cgroup_of(unsafe { libc::getpid() }))
        .as_ref()
}

/// The box's **dedicated** cgroup, or `None` if it doesn't have one. A box gets its own cgroup
/// only when it ran inside a `systemd-run --user --scope`; without one (no systemd-user) its
/// processes live in the shared session cgroup - the same one `kern` itself runs in - and
/// `memory.current` there reflects the whole session, not the box. We detect that by comparing
/// the box's cgroup to our own: if they match, the reading isn't box-specific, so we report none
/// rather than a misleading session-wide number.
pub fn box_cgroup(pid: i32) -> Option<PathBuf> {
    let cg = cgroup_of(pid)?;
    if own_cgroup() == Some(&cg) {
        return None;
    }
    Some(cg)
}

/// Resolve a box's dedicated cgroup PATH and its `(dev, ino)` IDENTITY from its PID 1, for recording in
/// the instance at start. Both come from ONE `box_cgroup_dir` resolve plus one `stat`, so the stored
/// path and the stored identity can never disagree. `box_cgroup_dir` (unlike [`box_cgroup`]) reads PID
/// 1's OWN `/proc/<pid1>/cgroup` and returns the `kern-box-*` leaf regardless of the CALLER's cgroup -
/// the box-start callback runs in the runner process, itself a member of that very cgroup, so a
/// caller-relative check would wrongly return None. `(String::new(), None)` when there is no dedicated
/// `kern-box-*` cgroup (no systemd-user): liveness then falls back to the supervisor pid, as before.
pub fn box_cgroup_record(pid1: i32) -> (String, Option<(u64, u64)>) {
    let Some(path) = kern_isolation::box_cgroup_dir(pid1) else {
        return (String::new(), None);
    };
    let s = path.to_string_lossy().into_owned();
    // Identity captured at the SAME instant as the path. A transient stat error here just yields no
    // identity (None) - liveness then falls back to the supervisor pid for this box, never reap-by-path.
    let id = match probe_cgroup(&s) {
        Probe::Id(id) => Some(id),
        Probe::Gone | Probe::Unknown => None,
    };
    (s, id)
}

/// All per-box cgroup stats from a **single** `box_cgroup` resolve - mem / cpu / tasks / frozen. The
/// `top` refresh reads these together per box, so this avoids re-resolving the cgroup (and re-reading
/// `/proc/<pid>/cgroup`) four separate times per box, per frame.
#[derive(Default)]
pub struct BoxStats {
    pub mem: Option<u64>,
    pub cpu_usec: Option<u64>,
    pub tasks: Option<u64>,
    pub paused: bool,
}

pub fn box_stats(pid: i32) -> BoxStats {
    let Some(cg) = box_cgroup(pid) else {
        return BoxStats::default();
    };
    let num = |f: &str| -> Option<u64> { fs::read_to_string(cg.join(f)).ok()?.trim().parse().ok() };
    let cpu_usec = fs::read_to_string(cg.join("cpu.stat")).ok().and_then(|s| {
        s.lines()
            .find_map(|l| l.strip_prefix("usage_usec "))
            .and_then(|v| v.trim().parse().ok())
    });
    let paused = fs::read_to_string(cg.join("cgroup.freeze"))
        .map(|s| s.trim() == "1")
        .unwrap_or(false);
    BoxStats {
        mem: num("memory.current"),
        cpu_usec,
        tasks: num("pids.current"),
        paused,
    }
}

/// Is this box frozen by `kern pause`? Reads its cgroup v2 `cgroup.freeze` ("1" = frozen). `false`
/// when the box has no dedicated cgroup or the file is unreadable - so `ps`/`top` can show "paused"
/// instead of a frozen box looking identical to a running one.
pub fn is_paused(pid: i32) -> bool {
    box_cgroup(pid)
        .and_then(|cg| fs::read_to_string(cg.join("cgroup.freeze")).ok())
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

/// A box's current memory usage (bytes), from its (dedicated) cgroup `memory.current`. `None` if
/// the box has no dedicated cgroup (see [`box_cgroup`]) - shown as `-` rather than a wrong number.
pub fn mem_bytes(pid: i32) -> Option<u64> {
    let cg = box_cgroup(pid)?;
    fs::read_to_string(cg.join("memory.current"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// A box's cumulative CPU time (microseconds), from its (dedicated) cgroup `cpu.stat`
/// `usage_usec`. `None` if the box has no dedicated cgroup.
pub fn cpu_usec(pid: i32) -> Option<u64> {
    let cg = box_cgroup(pid)?;
    fs::read_to_string(cg.join("cpu.stat"))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("usage_usec "))?
        .trim()
        .parse()
        .ok()
}

/// The number of tasks (processes/threads) in a box, from its (dedicated) cgroup `pids.current`.
/// `None` if the box has no dedicated cgroup.
pub fn tasks(pid: i32) -> Option<u64> {
    let cg = box_cgroup(pid)?;
    fs::read_to_string(cg.join("pids.current"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Current Unix time in seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Encode an entry to its `key=value` wire format (paired with [`parse`]). Extracted so the format is
/// round-trip unit-tested without touching the filesystem.
fn encode(inst: &Instance) -> String {
    format!(
        "name={}\npid={}\npid1={}\nrootfs={}\ncommand={}\nstarted={}\nstarttime={}\nports={}\nvolumes={}\npod={}\negress={}\nlandlock={}\nmemory_max={}\npids_max={}\nlabels={}\nstopsig={}\nstopgrace={}\ndefhash={}\nworkdir={}\ncapdropall={}\ncapdrops={}\ncapadds={}\nseccompmode={}\napparmor={}\ncgroup={}\ncgroupid={}\n",
        inst.name,
        inst.pid,
        inst.pid1,
        one_line(&inst.rootfs),
        one_line(&inst.command),
        inst.started,
        inst.starttime,
        one_line(&inst.ports),
        one_line(&inst.volumes),
        one_line(&inst.pod),
        one_line(&inst.egress),
        one_line(&inst.landlock_rw),
        inst.memory_max.map(|v| v.to_string()).unwrap_or_default(),
        inst.pids_max.map(|v| v.to_string()).unwrap_or_default(),
        one_line(&inst.labels),
        inst.stop_signal,
        inst.stop_grace,
        one_line(&inst.def_hash),
        one_line(&inst.workdir),
        u8::from(inst.cap_drop_all),
        one_line(&inst.cap_drops),
        one_line(&inst.cap_adds),
        inst.seccomp_mode.as_str(),
        one_line(&inst.apparmor),
        one_line(&inst.cgroup),
        // `<dev>:<ino>` of the recorded cgroup dir, or empty. Digits + one ':' - no `one_line` needed.
        inst.cgroup_id
            .map(|(d, i)| format!("{d}:{i}"))
            .unwrap_or_default(),
    )
}

/// Write the entry ATOMICALLY. Returns the file path (so the supervisor can remove it on exit).
///
/// A plain `fs::write` opens the final path `O_TRUNC` and then writes, so a `SIGKILL`/OOM/power loss
/// between the truncate and the last byte would leave a TRUNCATED record on disk. The posture lines
/// (`capdropall`/`capdrops`/`capadds`/`seccompmode`) are written LAST, so a truncated record can carry
/// `capdropall` without the drops that follow it - and a peer's `kern exec`, reading it, would
/// reconstruct a WEAKER capability/seccomp posture than the box actually ran. Stage the whole record in
/// a hidden, caller-pid-keyed temp and `rename` it over the final path instead: a same-directory rename
/// is atomic, so a reader sees either NO entry or the COMPLETE record, never a half-written one. The
/// temp's trailing `-<pid>.tmp` is not all-digits, so `list()`/`well_formed_entry` never take it for a box.
pub fn register(inst: &Instance) -> io::Result<PathBuf> {
    let d = dir()?;
    let path = d.join(format!("{}-{}", inst.name, inst.pid));
    let tmp = d.join(format!(
        ".{}-{}-{}.tmp",
        inst.name,
        inst.pid,
        std::process::id()
    ));
    fs::write(&tmp, encode(inst))?;
    if let Err(e) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp); // never leave a staged body behind
        return Err(e);
    }
    Ok(path)
}

/// Remove an entry (best-effort).
pub fn unregister(path: &Path) {
    let _ = fs::remove_file(path);
}

/// Read `entry`, transform its body with `f`, and swap the result back atomically through a hidden,
/// CALLER-pid-keyed temp (`.<tag>-<selfpid>-<pid>.tmp`). Keying the temp on the CALLING process means
/// two concurrent writers on the SAME box (e.g. `rename` racing `update`) never share a temp and so
/// never tear each other's write - a torn body would fail `parse` and make `load_live` unregister the
/// LIVE box. The temp's trailing `-` segment isn't all-digits, so `entry_split`/`well_formed_entry`
/// skip it and `list()` never mistakes it for a second box. No-op if `entry` is already gone.
/// Best-effort. `dir` is the instances directory (where `entry` lives).
/// Replace an entry's body atomically: stage the new text in a hidden temp beside it, then `rename`
/// it over the entry (same-directory rename, so the reader sees the old body or the new one, never a
/// half-written one).
///
/// FALLIBLE. It returned `()` and discarded both the write and the rename, which made "the body was
/// replaced" indistinguishable from "the body was not touched" - and the entry BODY is where the
/// box's displayed name and caps live, so a discarded failure means `kern ps` reports something the
/// caller believes it changed. A MISSING entry is not a failure: the box is gone, and there is
/// nothing to rewrite. An entry that exists and cannot be read is, because that is a rewrite that
/// did not happen.
///
/// The staged temp is removed when the rename fails, so a refused replace cannot leave litter in the
/// registry directory that a later run would have to reason about.
fn atomic_rewrite(
    dir: &Path,
    entry: &Path,
    pid: i32,
    tag: &str,
    f: impl FnOnce(&str) -> String,
) -> io::Result<()> {
    if !entry.exists() {
        return Ok(()); // the box is gone: nothing to rewrite, and that is not an error
    }
    let Some(body) = read_entry_capped(entry) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cannot read registry entry {}", entry.display()),
        ));
    };
    let tmp = dir.join(format!(".{tag}-{}-{pid}.tmp", std::process::id()));
    fs::write(&tmp, f(&body))?;
    // Re-check the target still exists right before the swap. A concurrent `rename` of THIS box could
    // have moved its entry away since the `exists()` at the top, and `fs::rename(tmp, entry)` to a
    // now-missing target would CREATE it - resurrecting the renamed-away entry as a DUPLICATE (two
    // files for one pid, so `list()`/`find()` see the box twice with divergent bodies). If it's gone,
    // honour the same "nothing to rewrite" contract as the entry-missing case above. This narrows the
    // window to a single syscall; the residual race degrades only to a benign last-writer-wins on the
    // body, never a duplicate.
    if !entry.exists() {
        let _ = fs::remove_file(&tmp);
        return Ok(());
    }
    if let Err(e) = fs::rename(&tmp, entry) {
        let _ = fs::remove_file(&tmp); // never leave a staged body behind
        return Err(e);
    }
    Ok(())
}

/// Rename a running box: move its `instances/<old>-<pid>` entry to `<new>-<pid>`, rewrite the `name=`
/// field, and move its log/health sidecars. `fs::rename` keeps EXACTLY ONE entry visible to a
/// concurrent `list()` throughout (never a double, never a gap); the `name=` fix is then swapped in
/// atomically through a hidden temp so a reader never sees a torn body. The live supervisor still
/// holds the OLD entry path for its final `unregister` - that becomes a harmless no-op and the renamed
/// entry is pruned by `list()` when the box exits, so nothing leaks. The caller has already validated
/// `new` and verified it is free. Best-effort on the sidecars (a box may have neither).
pub fn rename(old: &str, new: &str, pid: i32) -> io::Result<()> {
    let d = dir()?;
    let old_entry = d.join(format!("{old}-{pid}"));
    let new_entry = d.join(format!("{new}-{pid}"));
    // BODY FIRST, on the entry that still exists. The displayed name comes from the body's `name=`
    // field (`load_live` -> `parse`), not from the file name, so rewriting the file first and the body
    // second left a window whose failure was permanent AND silent: the file called `<new>-<pid>` with
    // a body still saying `<old>`, and `Ok` returned. Done in this order, a refused rewrite changes
    // nothing at all.
    atomic_rewrite(&d, &old_entry, pid, "rename", |body| {
        rewrite_name_field(body, new)
    })?;
    // Atomic: exactly one entry exists at every instant.
    if let Err(e) = fs::rename(&old_entry, &new_entry) {
        // The body now says `new` while the file is still `<old>-<pid>`. Put the body back so the
        // registry is exactly as it was before this call. Best-effort BECAUSE it is a recovery
        // attempt on a path that is already returning an error: if it fails too, the error below has
        // already told the caller the registry directory is not behaving.
        let _ = atomic_rewrite(&d, &old_entry, pid, "rename", |body| {
            rewrite_name_field(body, old)
        });
        return Err(e);
    }
    if let Ok(l) = logs_dir() {
        let _ = fs::rename(
            l.join(format!("{old}-{pid}.log")),
            l.join(format!("{new}-{pid}.log")),
        );
    }
    if let Ok(h) = health_dir() {
        let _ = fs::rename(
            h.join(format!("{old}-{pid}")),
            h.join(format!("{new}-{pid}")),
        );
    }
    Ok(())
}

/// Replace the `name=` line of a `key=value` registry body, preserving every other line verbatim.
/// Pure (filesystem-free), unit-tested alongside `encode`/`parse`.
fn rewrite_name_field(body: &str, new: &str) -> String {
    let mut out = String::with_capacity(body.len() + new.len());
    for line in body.lines() {
        if line.starts_with("name=") {
            out.push_str("name=");
            out.push_str(new);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// Sync a running box entry's recorded `memory_max`/`pids_max` after a live `kern update`, so
/// `ps`/`inspect` show the new caps. Only the given (`Some`) fields are rewritten; the rest is
/// preserved. Atomic body swap via a hidden temp (same discipline as [`rename`]). Best-effort.
pub fn update_caps(name: &str, pid: i32, memory_max: Option<u64>, pids_max: Option<u64>) {
    let Ok(d) = dir() else { return };
    // Target the box's CURRENT entry by pid: if a concurrent `rename` moved it since the caller
    // resolved the name, update the LIVE file (or skip if it's genuinely gone) instead of recreating
    // the old-name entry - which would duplicate the box under two names.
    let cur = name_for_pid(pid).unwrap_or_else(|| name.to_string());
    let entry = d.join(format!("{cur}-{pid}"));
    // Best-effort ON PURPOSE, and reported. The caller has already written the new cap into the
    // box's cgroup - the kernel is enforcing it - so failing `kern update` because the bookkeeping
    // could not follow would be the wrong trade. What is NOT acceptable is silence: `ps`/`inspect`
    // would then keep showing the previous cap with nothing to attribute the discrepancy to.
    if let Err(e) = atomic_rewrite(&d, &entry, pid, "update", |body| {
        rewrite_caps(body, memory_max, pids_max)
    }) {
        eprintln!(
            "kern: the new caps are enforced but could not be recorded for '{cur}': {e} -              `kern ps` and `kern inspect` will keep showing the previous values"
        );
    }
}

/// Rewrite only the `memory_max=`/`pids_max=` lines that have a `Some` replacement, preserving every
/// other line. Pure; unit-tested alongside `encode`/`parse`.
fn rewrite_caps(body: &str, memory_max: Option<u64>, pids_max: Option<u64>) -> String {
    let mut out = String::with_capacity(body.len() + 16);
    for line in body.lines() {
        match (memory_max, pids_max) {
            (Some(m), _) if line.starts_with("memory_max=") => {
                out.push_str("memory_max=");
                out.push_str(&m.to_string());
            }
            (_, Some(p)) if line.starts_with("pids_max=") => {
                out.push_str("pids_max=");
                out.push_str(&p.to_string());
            }
            _ => out.push_str(line),
        }
        out.push('\n');
    }
    out
}

/// A real entry is well under 1 KiB; only read a bounded prefix so a same-user process can't wedge
/// `list()` (which `kern ps`/`volume rm`/`stop` all call) with a multi-gigabyte junk file.
const MAX_ENTRY_BYTES: u64 = 64 * 1024;

/// Split a `<name>-<pid>` entry filename into `(name, pid-digits)`, or `None` (grammar check only: name
/// non-empty, pid non-empty all-ASCII-digits; no integer parse). The SOLE decoder of the on-disk key
/// grammar (paired with `register`'s `format!("{name}-{pid}")` encoder) - `entry_name`, `well_formed_entry`,
/// `find`'s pre-filter, and `name_for_pid` all go through it so they can't drift on what a valid entry is.
fn entry_split(fname: &std::ffi::OsStr) -> Option<(&str, &str)> {
    let (n, pid) = fname.to_str()?.rsplit_once('-')?;
    (!n.is_empty() && !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
        .then_some((n, pid))
}

/// The `<name>` of a well-formed `<name>-<pid>` entry filename, else `None`.
fn entry_name(fname: &std::ffi::OsStr) -> Option<&str> {
    entry_split(fname).map(|(n, _)| n)
}

/// Is this a well-formed registry filename (`<name>-<pid>`, pid all digits)? Skips anything else a
/// same-user process dropped in the dir, so junk files aren't parsed. NOTE: we deliberately do NOT
/// cap the *number* of entries - a cap could push a real box's entry out of view and let its
/// in-use volume be deleted (fail-open). Reading many small files stays O(n) but bounded per file.
fn well_formed_entry(name: &std::ffi::OsStr) -> bool {
    entry_name(name).is_some()
}

/// Read at most [`MAX_ENTRY_BYTES`] of a registry file (bounded against a huge planted file).
fn read_entry_capped(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut buf = String::new();
    fs::File::open(path)
        .ok()?
        .take(MAX_ENTRY_BYTES)
        .read_to_string(&mut buf)
        .ok()?;
    Some(buf)
}

/// All currently-running boxes, oldest first. Dead entries are pruned as a side effect.
pub fn list() -> Vec<Instance> {
    let mut out = Vec::new();
    let Ok(d) = dir() else {
        return out;
    };
    let Ok(entries) = fs::read_dir(&d) else {
        return out;
    };
    for e in entries.flatten() {
        // Ignore anything that isn't one of our `<name>-<pid>` files (planted junk), without deleting
        // it (it's in our own 0700 dir, but a foreign name isn't ours to prune).
        if !well_formed_entry(&e.file_name()) {
            continue;
        }
        if let Some(inst) = load_live(&e.path()) {
            out.push(inst);
        }
    }
    out.sort_by_key(|i| i.started);
    out
}

/// Outcome of probing the directory at a recorded cgroup path. THREE states, never two: the crux of the
/// fix is that "could not determine" (a transient error) must be distinguishable from "definitely gone",
/// or a `kern ps`/`gc` under fd exhaustion would prune/reap a LIVE box's record and recreate the ghost.
enum Probe {
    /// Resolved to a directory with this `(dev, ino)` identity.
    Id((u64, u64)),
    /// Definitively ABSENT (`ENOENT`/`ENOTDIR`): the cgroup is gone; the record is safe to reap.
    Gone,
    /// Could NOT be determined - a transient or unmodelled error (fd exhaustion `EMFILE`/`ENFILE`,
    /// kernel `ENOMEM`, a racing `ESTALE`, an unexpected errno). Not proof of absence: never prune or
    /// reap on this; the caller re-evaluates on the next pass, when the pressure has cleared.
    Unknown,
}

/// Probe the dir at `path` for its `(dev, ino)` identity, distinguishing "definitely gone" from "could
/// not tell". `fs::metadata` opens (and closes) one fd internally, so under fd exhaustion it fails with
/// `EMFILE` - which MUST read as [`Probe::Unknown`], not [`Probe::Gone`]. The kernel gives each cgroup a
/// unique inode not reused for the dir's lifetime, so the identity is a stable, non-recycling key.
fn probe_cgroup(path: &str) -> Probe {
    use std::os::unix::fs::MetadataExt;
    match fs::metadata(path) {
        Ok(m) => Probe::Id((m.dev(), m.ino())),
        Err(e) => match e.raw_os_error() {
            // The only errnos that PROVE the path is gone. Everything else (EMFILE/ENFILE/ENOMEM/
            // ESTALE/EACCES/ELOOP/…) is transient or unmodelled - do not decide on it.
            Some(libc::ENOENT) | Some(libc::ENOTDIR) => Probe::Gone,
            _ => Probe::Unknown,
        },
    }
}

/// The `(dev, ino)` identity of the dir at `path`, or `None` if it is gone / unreadable. Test-only thin
/// wrapper over [`probe_cgroup`] so unit tests can fabricate a record's recorded identity.
#[cfg(test)]
fn cgroup_identity(path: &str) -> Option<(u64, u64)> {
    match probe_cgroup(path) {
        Probe::Id(id) => Some(id),
        Probe::Gone | Probe::Unknown => None,
    }
}

/// Three-state liveness of a DEAD-supervisor box, resolved from its recorded cgroup:
///
///  * ORPHANED - the cgroup at the recorded path is still OURS (identity matches) AND still populated
///    (`cgroup.events` `populated 1`): the supervisor is gone but PID 1 / the `-p` forwarder live on.
///  * EXITED - the path is gone, empty (`populated 0`), or now a STRANGER's cgroup (identity mismatch),
///    or there is no recorded identity to check against: the record may be pruned.
///  * UNKNOWN - a TRANSIENT probe error (fd exhaustion, `ENOMEM`, `ESTALE`) left the state
///    undetermined: the caller must NOT prune or reap; re-evaluate next pass.
///
/// Identity is checked FIRST (never read a path we cannot confirm is our own cgroup - a recycled `<pid>`
/// leaf could hand it to another box), and a transient error at ANY step yields `Unknown` so pressure
/// never prunes a live record. `Unknown` is a transient RETURN value only - it is never written to the
/// record, so it self-resolves the moment the fds free up.
enum Liveness {
    Orphaned,
    Exited,
    Unknown,
}

fn cgroup_liveness(cgroup: &str, id: Option<(u64, u64)>) -> Liveness {
    // No recorded identity (older entry / no dedicated cgroup): the path carries no trustworthy orphan
    // signal, and the supervisor-pid liveness already ran and said dead. Fail closed - never reap-by-path.
    let Some(want) = id else {
        return Liveness::Exited;
    };
    if cgroup.is_empty() {
        return Liveness::Exited;
    }
    match probe_cgroup(cgroup) {
        Probe::Gone => Liveness::Exited,
        Probe::Unknown => Liveness::Unknown,
        Probe::Id(got) if got != want => Liveness::Exited, // a stranger owns our path ⇒ our box is gone
        Probe::Id(_) => {
            // Our cgroup. Is its subtree populated? A read error here is also transient ⇒ Unknown.
            match fs::read_to_string(Path::new(cgroup).join("cgroup.events")) {
                Ok(s) => {
                    let populated = s
                        .lines()
                        .find_map(|l| l.strip_prefix("populated "))
                        .map(|v| v.trim() == "1")
                        .unwrap_or(false);
                    if populated {
                        Liveness::Orphaned
                    } else {
                        Liveness::Exited
                    }
                }
                // The dir existed a moment ago; a racing removal makes the read `ENOENT` ⇒ gone.
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Liveness::Exited,
                Err(_) => Liveness::Unknown, // EMFILE/ENOMEM/… ⇒ do not decide
            }
        }
    }
}

/// Load the registry entry at `path`, resolving its liveness to one of THREE states (never two):
///
/// * supervisor pid alive → `running` (returned as-is).
/// * supervisor dead, recorded cgroup ours+populated → `orphaned` (returned with `orphaned = true`).
/// * supervisor dead, cgroup gone/empty/a stranger's, or unparseable → `exited` (record pruned, `None`).
///
/// A TRANSIENT probe error (fd exhaustion, `ENOMEM`, `ESTALE`) is the fourth outcome and the one that
/// must NOT prune: the record is kept UNMARKED (shown as running) and re-evaluated next pass. `is_alive`
/// itself is fd-free (`kill(pid, 0)`, and a failed `proc_starttime` read reads as alive), so only the
/// cgroup probe needed the transient/gone split. The middle state is the ghost fix: a box whose
/// SUPERVISOR was SIGKILL'd used to be pruned here while its PID 1 and `-p` forwarder still held the host
/// port, so `kern stop <name>` answered "no running box" and the port was unreclaimable. Now such a box
/// stays VISIBLE and REAPABLE. The single entry-loading rule - [`list`] and [`find`] both go through
/// here - so the capped read, the parse, the liveness gate and the prune can't drift between them.
fn load_live(path: &Path) -> Option<Instance> {
    let Some(inst) = read_entry_capped(path).and_then(|b| parse(&b)) else {
        // Unparseable/torn: a live box's body parses (it was written atomically), so this is not one.
        unregister(path);
        return None;
    };
    if is_alive(inst.pid, inst.starttime) {
        return Some(inst); // running: supervisor alive
    }
    match cgroup_liveness(&inst.cgroup, inst.cgroup_id) {
        // The supervisor is gone but the box's processes (PID 1, forwarder) live on in OUR cgroup.
        Liveness::Orphaned => Some(Instance {
            orphaned: true,
            ..inst
        }),
        // A transient probe error (fd exhaustion, ENOMEM, ESTALE): do NOT prune a record we could not
        // evaluate. Keep it unmarked and re-evaluate next pass - fail-safe in the non-destructive
        // direction. Under pressure a running-looking record is far less harmful than a dropped one.
        Liveness::Unknown => Some(inst),
        // Gone / empty / a stranger's cgroup: the box has exited, prune the stale record.
        Liveness::Exited => {
            unregister(path);
            None
        }
    }
}

/// Reap an ORPHANED box (supervisor dead, cgroup still populated): SIGKILL every process in its recorded
/// cgroup at once via cgroup-v2 `cgroup.kill`, which reaches the PID 1 AND the `-p` forwarder that the
/// dead supervisor left holding the host port - a per-pid walk would miss whichever the registry never
/// learned. Drops the registry entry when the box is confirmed dead or killed. Returns whether the kill
/// was ISSUED. On a TRANSIENT error (fd exhaustion, `ENOMEM`) it does NOT drop the record - a live box
/// might still be there - and returns `false` so the next `gc`/`stop` retries.
pub fn reap_orphan(inst: &Instance) -> bool {
    match kill_recorded_cgroup(inst) {
        // Killed our cgroup, or confirmed it is gone / a stranger's: either way our box is over, so drop
        // the record and free the name.
        ReapOutcome::Killed => {
            unregister_entry(inst);
            true
        }
        ReapOutcome::Gone => {
            unregister_entry(inst);
            false
        }
        // Could not determine (fd exhaustion / ENOMEM / ESTALE): leave the record for the next sweep.
        ReapOutcome::Unknown => false,
    }
}

/// Remove `inst`'s registry entry (`<name>-<pid>`). Best-effort - a box already gone is not an error.
fn unregister_entry(inst: &Instance) {
    if let Ok(d) = dir() {
        unregister(&d.join(format!("{}-{}", inst.name, inst.pid)));
    }
}

/// The outcome of an identity-checked cgroup reap. Mirrors [`Probe`]'s three states at the kill layer.
enum ReapOutcome {
    /// `cgroup.kill` was written to OUR cgroup.
    Killed,
    /// The cgroup is definitively gone, or a stranger occupies the path (identity mismatch): nothing of
    /// ours to kill, and the record may be dropped.
    Gone,
    /// A transient error left the state undetermined: do NOT kill and do NOT drop the record.
    Unknown,
}

/// SIGKILL the recorded cgroup's whole subtree via `cgroup.kill`, but ONLY the exact cgroup kern
/// recorded, and never on a transient error. The `kern-box-<name>-<pid>` path embeds a PID that
/// recycles, so between recording the path and reaping it a different box could have come to own it -
/// killing by path alone would SIGKILL the WRONG workload (running under this box's stale caps). The kill
/// is identity-safe AND TOCTOU-free by operating on a PINNED directory fd: open the path once, `fstat`
/// that fd against the recorded `(dev, ino)`, then `openat(dirfd, "cgroup.kill")` RELATIVE to the same fd
/// (which refers to the inode, not the path, so a concurrent swap of the path after the open cannot
/// redirect the write). Every errno is classified: `ENOENT`/`ENOTDIR` (and a missing `cgroup.kill`) prove
/// the cgroup is gone; an identity mismatch means a stranger owns the path; anything else
/// (`EMFILE`/`ENFILE`/`ENOMEM`/…) is [`ReapOutcome::Unknown`] - do not kill, do not drop the record.
fn kill_recorded_cgroup(inst: &Instance) -> ReapOutcome {
    let Some(want) = inst.cgroup_id else {
        return ReapOutcome::Gone; // no recorded identity ⇒ nothing to reap by cgroup
    };
    if inst.cgroup.is_empty() {
        return ReapOutcome::Gone;
    }
    let Ok(cpath) = std::ffi::CString::new(inst.cgroup.as_bytes()) else {
        return ReapOutcome::Gone; // an embedded NUL can never be a real cgroup path
    };
    // Pin the directory OBJECT. `O_PATH` is enough to `fstat` it and to anchor an `openat`, and never
    // executes anything in the dir. `O_CLOEXEC` so a concurrent fork can't leak the fd.
    let dirfd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_DIRECTORY | libc::O_PATH | libc::O_CLOEXEC,
        )
    };
    if dirfd < 0 {
        return match io::Error::last_os_error().raw_os_error() {
            Some(libc::ENOENT) | Some(libc::ENOTDIR) => ReapOutcome::Gone, // path gone ⇒ box gone
            _ => ReapOutcome::Unknown, // EMFILE/ENFILE/ENOMEM/… ⇒ retry next pass
        };
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(dirfd, &mut st) } != 0 {
        unsafe { libc::close(dirfd) };
        return ReapOutcome::Unknown; // couldn't confirm identity ⇒ don't kill
    }
    let outcome = if (st.st_dev as u64, st.st_ino as u64) == want {
        // Relative to the pinned dir - never re-resolves `inst.cgroup`.
        let kfd = unsafe { libc::openat(dirfd, c"cgroup.kill".as_ptr(), libc::O_WRONLY) };
        if kfd >= 0 {
            let wrote = unsafe { libc::write(kfd, b"1".as_ptr().cast(), 1) } == 1;
            unsafe { libc::close(kfd) };
            if wrote {
                ReapOutcome::Killed
            } else {
                ReapOutcome::Unknown // the write itself faulted (ENOMEM/EINTR) ⇒ retry
            }
        } else {
            match io::Error::last_os_error().raw_os_error() {
                // No `cgroup.kill` under our (identity-matched) dir ⇒ the cgroup is no longer a live
                // cgroup (kernel < 5.14, or the dir is mid-teardown) ⇒ treat as gone.
                Some(libc::ENOENT) => ReapOutcome::Gone,
                _ => ReapOutcome::Unknown,
            }
        }
    } else {
        ReapOutcome::Gone // a stranger occupies our path ⇒ our box is gone (must NOT kill it)
    };
    unsafe { libc::close(dirfd) };
    outcome
}

/// The LIVE box named `name`, or `None`. The targeted-lookup primitive: unlike [`list`], it opens and
/// `/proc`-stats ONLY the entry whose FILENAME (`<name>-<pid>`) matches `name` - every OTHER running box
/// costs nothing but its dirent. This is what keeps by-name commands (start name-check, `exec`, `stop`,
/// `attach`, health polls…) O(1) in file I/O regardless of how many boxes run: routing them through
/// `list()` made each call O(running boxes) (open + parse + `kill` + read `/proc/<pid>/stat` for EVERY
/// box) - measured super-linear (3 ms idle → 19 ms at 100 live boxes), and O(N²) for a per-box health
/// checker polling forever. Prunes a dead same-name entry as a side effect (name reusable after a crash),
/// never a live one.
pub fn find(name: &str) -> Option<Instance> {
    let d = dir().ok()?;
    for e in fs::read_dir(&d).ok()?.flatten() {
        // Match on the `<name>-<pid>` FILENAME (one grammar decoder, shared with `well_formed_entry`)
        // WITHOUT opening the file, so a non-matching box - the common case at scale - costs only its
        // dirent, never an open/`/proc` stat.
        let fname = e.file_name();
        if entry_name(&fname) != Some(name) {
            continue;
        }
        // A filename match - confirm it's actually a LIVE box named `name` (body `name=` is authoritative,
        // matching `list()`). Dead/unparseable → pruned by `load_live` so the name is reusable; a live box
        // whose body-name differs from its filename (shouldn't happen) is left alone, keep looking.
        match load_live(&e.path()) {
            Some(inst) if inst.name == name => return Some(inst),
            _ => {}
        }
    }
    None
}

/// Is the EXACT `<name>-<pid>` entry a live box? The targeted (name,pid)-PAIR probe for watchers
/// that track one specific instance (the detached `--timeout` watchdog, `attach`'s exit poll): a
/// by-name [`find`] would test the pid against whichever same-name entry readdir yields first, so a
/// duplicate entry (possible only from a fail-open unclaimed start or a pre-claim kern) could shadow
/// the tracked box - the watchdog would never fire / attach would report a live box as exited.
/// Opens exactly one file; never prunes.
pub fn pair_alive(name: &str, pid: i32) -> bool {
    let Ok(d) = dir() else { return false };
    read_entry_capped(&d.join(format!("{name}-{pid}")))
        .and_then(|b| parse(&b))
        .is_some_and(|i| i.name == name && i.pid == pid && is_alive(i.pid, i.starttime))
}

/// Is a LIVE box already named `name`? Thin wrapper over [`find`] - the box-start hot-path name-check.
pub fn name_taken(name: &str) -> bool {
    find(name).is_some()
}

/// Resolve a box by a user-supplied reference: its NAME, or - as a fallback - its supervisor PID as
/// shown in `kern ps` (Docker-style ref-or-name for the live commands: `stop`/`exec`/`logs`/…).
/// NAME WINS: a box literally named "79" resolves before a box whose pid is 79, so an all-digit box
/// name is never shadowed by a coincidental pid. The pid branch runs ONLY when the ref is a plain
/// positive integer AND is not a live box name, and scans the (small) registry once. Caveat: a pid is
/// a LIVE handle only - reused by the OS, changed by `--restart` - so the NAME stays the stable identity.
pub fn find_ref(x: &str) -> Option<Instance> {
    if let Some(inst) = find(x) {
        return Some(inst); // a live box named `x` - name wins
    }
    if let Some(inst) = find_service(x) {
        return Some(inst); // the SERVICE name `kern ps` prints inside a pod
    }
    let pid: i32 = x.parse().ok().filter(|&p| p > 0)?; // else it can't be a pid
    let d = dir().ok()?;
    for e in fs::read_dir(&d).ok()?.flatten() {
        if entry_name(&e.file_name()).is_none() {
            continue; // planted junk / non-entry filename
        }
        match load_live(&e.path()) {
            Some(inst) if inst.pid == pid => return Some(inst),
            _ => {}
        }
    }
    None
}

/// Resolve the SHORT service name a pod box is displayed under. A compose box is named
/// `<pod>-<token>-<service>`, and `kern ps` renders it in the pod's tree as just `<service>` - so the
/// name a person reads was not a name any verb accepted: `kern exec api` answered "no running box
/// named 'api'" while the box was right there on screen. `docker compose exec api` works, and the
/// display had already promised the short form.
///
/// Matched on the compose naming SHAPE, `<stack>-<token>-<service>` with a hex token, not on a bare
/// trailing `-<service>`: a standalone box called `my-api` must not answer to `api`, which is exactly
/// the guess this is meant to avoid. The `pod` field cannot be the test, because a single-service
/// stack creates no pod (nothing to share a netns with) yet still carries the prefixed name.
///
/// Only when the match is UNAMBIGUOUS: two stacks each running an `api` resolve to neither, because
/// picking one is worse than saying so. The exact-name and pid branches in [`find_ref`] run first, so
/// a box literally named `api` still wins over this.
fn find_service(service: &str) -> Option<Instance> {
    if service.is_empty() {
        return None;
    }
    let suffix = format!("-{service}");
    let d = dir().ok()?;
    let mut hit: Option<Instance> = None;
    for e in fs::read_dir(&d).ok()?.flatten() {
        if entry_name(&e.file_name()).is_none() {
            continue;
        }
        match load_live(&e.path()) {
            Some(inst) if is_compose_service(&inst.name, &suffix) => {
                if hit.is_some() {
                    return None; // ambiguous across stacks: refuse rather than pick
                }
                hit = Some(inst);
            }
            _ => {}
        }
    }
    hit
}

/// Does `name` have the compose shape `<stack>-<token>-<service>`, for this `-<service>` suffix, with
/// `<token>` a hex hash? The token is what separates a generated stack box from a hand-named one.
fn is_compose_service(name: &str, suffix: &str) -> bool {
    let Some(prefix) = name.strip_suffix(suffix) else {
        return false;
    };
    let Some((stack, token)) = prefix.rsplit_once('-') else {
        return false;
    };
    !stack.is_empty() && token.len() >= 8 && token.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The claims directory - one `<name>` file per IN-FLIGHT box start (see [`claim_name`]).
fn claims_dir() -> io::Result<PathBuf> {
    runtime_subdir("claims")
}

/// Take the claims-dir advisory lock (`flock`; the kernel releases it with the process, so it can't
/// leak). ALL claim mutation - take, stale takeover, prune - happens under it, so two starters that
/// both see the same stale claim can't both "take it over" (one would silently delete the other's
/// fresh claim). Held for a handful of syscalls; contention cost is microseconds against a ~3 ms
/// box start. Retries `EINTR`: a signal landing while blocked on a contended lock must not surface
/// as "no usable runtime dir" - the caller would fail-open UNCLAIMED, quietly disabling the very
/// race protection this lock exists for.
fn lock_claims(d: &Path) -> io::Result<fs::File> {
    use std::os::fd::AsRawFd;
    // `.lock` can never collide with a claim: names are `BoxName`-vetted (no leading '.').
    let f = fs::File::create(d.join(".lock"))?;
    while unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
    Ok(f)
}

/// `(pid, starttime)` from a claim body (`"<pid> <starttime>"`), or `None` if malformed.
fn parse_claim(body: &str) -> Option<(i32, u64)> {
    let mut it = body.split_whitespace();
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

/// A held start-claim on a box name. Dropping it (in the process that took it) releases the name.
/// A claim leaked by a crash is stale the moment its pid dies - the next same-name start takes it
/// over, and [`prune`] sweeps the rest.
pub struct NameClaim {
    path: PathBuf,
    owner: u32,
}

impl Drop for NameClaim {
    fn drop(&mut self) {
        // Only the claiming PROCESS releases: a forked child (the detached supervisor) inherits
        // this struct and must not free the name from under its parent.
        if std::process::id() == self.owner {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Atomically claim `name` for an in-flight box start - the other half of the start name-check.
/// [`name_taken`] sees a box only once it's REGISTERED, so two concurrent same-name starts could
/// both pass it and both come up (check-then-register TOCTOU). The claim closes that window:
///
/// * `Ok(Some(_))` - this process owns the name; hold the claim until the box is registered (the
///   registry entry is authoritative from then on), then drop it.
/// * `Ok(None)` - the name is taken: a LIVE process holds the claim (already starting), or a live
///   box is already REGISTERED under it. The registry re-check happens HERE, under the lock, so
///   name reservation is atomic-by-construction for every caller - a second start path that only
///   calls `claim_name` cannot silently reintroduce the race.
/// * `Err(_)` - no usable runtime dir. The registry itself is equally unavailable then, so callers
///   proceed unclaimed (fail-open, exactly like `name_taken`).
///
/// A claim is a `<pid> <starttime>` file judged by the registry's own [`is_alive`] rule, and the
/// whole check-and-take runs under the dir-wide flock - a stale claim (starter crashed before
/// registering) is taken over exactly once, never raced.
/// Uncapped convenience wrapper over [`claim_name_capped`], used by the claim tests to keep their
/// `Option<NameClaim>` shape. Production always goes through `claim_name_capped` (with the fleet max),
/// so this is `#[cfg(test)]` rather than a second live entry point that could drift from it.
#[cfg(test)]
pub fn claim_name(name: &str) -> io::Result<Option<NameClaim>> {
    match claim_name_capped(name, None)? {
        StartOutcome::Claimed(c) => Ok(Some(c)),
        StartOutcome::NameBusy | StartOutcome::FleetFull { .. } => Ok(None),
    }
}

/// The verdict of an atomic start attempt: got the name, the name is busy, or the FLEET ceiling is
/// already reached. Separate from `claim_name`'s `Option` so the fleet refusal carries its own numbers
/// for a precise message (and can never be confused with a name collision).
pub enum StartOutcome {
    Claimed(NameClaim),
    NameBusy,
    FleetFull { live: usize, max: usize },
}

/// [`claim_name`] plus a race-free fleet ceiling. The count-then-start check in `fleet_gate_and_budget`
/// is a pure TOCTOU: N starters at `max-1` all read the same count and all proceed, overshooting `max`
/// by the burst size before any registers. This does the ceiling check UNDER THE SAME claim-dir lock as
/// the name claim, so the two are one atomic step: a starter counts the boxes in flight (registered +
/// claimed-not-yet-registered) and, if that is already `max`, refuses BEFORE writing its own claim - so
/// the next starter, serialized on the lock, sees this one's claim and is refused in turn. `max = None`
/// is exactly `claim_name` (no counting, no extra `readdir`). Cooperative, not a security boundary: a
/// caller can unset the env; `KERN_FLEET_*` remains the kernel-enforced hard bound.
pub fn claim_name_capped(name: &str, max: Option<usize>) -> io::Result<StartOutcome> {
    let d = claims_dir()?;
    let _lock = lock_claims(&d)?;
    // Ceiling FIRST, still under the lock: this box has not claimed yet, so it is not in the count.
    if let Some(max) = max {
        let live = boxes_in_flight(&d);
        if live >= max {
            return Ok(StartOutcome::FleetFull { live, max });
        }
    }
    let path = d.join(name);
    if let Ok(body) = fs::read_to_string(&path) {
        if live_claim(&body) {
            return Ok(StartOutcome::NameBusy); // live claimant → name busy
        }
        // Dead claimant or malformed body → stale; fall through and take it over (we hold the lock).
    }
    // A box that REGISTERED before we locked is invisible to the claim file (its starter already
    // released the claim after registering) - the registry entry is authoritative from that point.
    if name_taken(name) {
        return Ok(StartOutcome::NameBusy);
    }
    let pid = std::process::id();
    fs::write(&path, format!("{pid} {}\n", proc_starttime(pid as i32)))?;
    Ok(StartOutcome::Claimed(NameClaim { path, owner: pid }))
}

/// Count the boxes in flight for the fleet ceiling, run UNDER the caller's claim-dir lock: LIVE
/// registrations ([`list`] already prunes dead ones) plus LIVE claims not yet registered, DEDUPED by
/// name (a box briefly holds both a claim and a registration). Self-healing by the same `is_alive`
/// rule used everywhere, so a crashed starter's slot frees itself and never permanently blocks the
/// fleet. `list` reads the INSTANCES dir and never takes the claims lock, so calling it here cannot
/// deadlock against the lock the caller holds.
fn boxes_in_flight(claims_d: &Path) -> usize {
    let mut names: std::collections::HashSet<String> = list().into_iter().map(|i| i.name).collect();
    if let Ok(rd) = fs::read_dir(claims_d) {
        for e in rd.flatten() {
            let fname = e.file_name();
            let n = fname.to_string_lossy();
            if n.starts_with('.') {
                continue; // the `.lock` file, never a claim
            }
            if fs::read_to_string(e.path()).is_ok_and(|b| live_claim(&b)) {
                names.insert(n.into_owned());
            }
        }
    }
    names.len()
}

/// Is this claim body a LIVE claimant's? The single staleness rule - [`claim_name`]'s takeover and
/// [`prune`]'s sweep both ask here, so they can never disagree on what counts as live (a divergence
/// would let prune delete a claim a racing starter still honors).
fn live_claim(body: &str) -> bool {
    parse_claim(body).is_some_and(|(p, t)| is_alive(p, t))
}

/// The set of named volumes any running box currently mounts (for `volume prune`'s in-use guard).
pub fn volumes_in_use() -> std::collections::HashSet<String> {
    list()
        .iter()
        .flat_map(|b| b.volume_names().map(str::to_string))
        .collect()
}

/// Is this our live box supervisor? It must exist (`kill(pid,0)==0`; `EPERM` = another user's
/// pid → gone) AND - when both start-times are known - its kernel start-time must match what we
/// recorded, so a reused pid (a different process that happens to have the same number) is seen as
/// gone. The start-time check is an ANTI-REUSE refinement layered on the existence proof, NOT a
/// second liveness test: if we recorded no start-time (`starttime == 0`) OR the live read comes back
/// empty (`proc_starttime` returns 0 - a transient `/proc` read failure: `open` hitting `EMFILE`
/// under heavy parallel fd pressure, a stat hiccup during namespace churn), we fall back to the
/// `kill(0)` proof rather than declaring a demonstrably-existing process dead. Pruning a live box's
/// entry on a momentary read failure is fail-DANGEROUS - it would drop a running box from `ps`/
/// `stop` and let `volume prune` delete a volume it still mounts. Pid-reuse is still caught whenever
/// the live read succeeds (the overwhelmingly common case).
fn is_alive(pid: i32, starttime: u64) -> bool {
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    let live = proc_starttime(pid);
    starttime == 0 || live == 0 || live == starttime
}

/// The fields of `/proc/<pid>/stat` *after* the `comm` field - i.e. the slice past the last `)`.
/// `comm` can contain spaces and parens, so this is the only safe split point; post-`)` tokens
/// start at field 3 (state), so field N is `nth(N - 3)`.
fn stat_after_comm(stat: &str) -> Option<&str> {
    stat.rfind(')').map(|rp| &stat[rp + 1..])
}

/// The sole child of `ppid` (a box supervisor forks exactly one child - PID 1 of the box), found
/// by scanning `/proc/*/stat` for a process whose parent is `ppid`. Fallback for `kern exec` when
/// the supervisor hadn't yet recorded PID 1. `None` if no such process exists.
pub fn child_of(ppid: i32) -> Option<i32> {
    let want = ppid.to_string();
    let entries = fs::read_dir("/proc").ok()?;
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        // Post-')' fields: state ppid ... → ppid is the 2nd token (field 4).
        if stat_after_comm(&stat).and_then(|s| s.split_whitespace().nth(1)) == Some(want.as_str()) {
            return Some(pid);
        }
    }
    None
}

/// A pid's start-time from `/proc/<pid>/stat` field 22 (clock ticks since boot), or 0.
pub fn proc_starttime(pid: i32) -> u64 {
    let Ok(s) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return 0;
    };
    // starttime is field 22 → the 20th post-')' token (index 19).
    stat_after_comm(&s)
        .and_then(|s| s.split_whitespace().nth(19))
        .and_then(|t| t.parse().ok())
        .unwrap_or(0)
}

/// Collapse newlines so one entry stays on its own lines.
fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

/// Garbage-collect leftovers from boxes that are no longer running. [`list`] already prunes dead
/// *instance* files on read, but a detached box's `logs/<name>-<pid>.log` and `health/<name>-<pid>`
/// sidecars outlive it - those accumulate. This removes any log/health file whose `<name>-<pid>`
/// key doesn't match a currently-live box, and returns `(files_removed, bytes_freed)` so the caller
/// can report it honestly. Live boxes are never touched.
pub fn prune() -> (usize, u64) {
    // `list()` also prunes dead/unparseable instance files as a side effect.
    let live: std::collections::HashSet<String> = list()
        .iter()
        .map(|i| format!("{}-{}", i.name, i.pid))
        .collect();
    let mut removed = 0usize;
    let mut freed = 0u64;
    let instances = dir().ok(); // for the concurrent-start re-check in the sweep
    let inst = instances.as_deref();
    sweep_orphans(logs_dir(), ".log", &live, inst, &mut removed, &mut freed);
    sweep_orphans(health_dir(), "", &live, inst, &mut removed, &mut freed);
    // `kern wait` exit sidecars of boxes whose supervisor is gone (dead-pid). Reaped here too, not
    // only in `gc`, so `prune` - the routine cleanup - bounds this dir (it would otherwise leak one
    // tiny file per never-waited detached box). A wait consumes its own sidecar within ~100 ms of the
    // box exiting, so a concurrent prune only ever costs an already-late wait its code, never a box.
    removed += sweep_waitexit_dead();
    // Claims whose starter is gone (a crash between claim and register leaves one behind). Swept
    // under the same dir-wide flock as `claim_name`, so a prune can never delete a claim that a
    // concurrent starter is (re)taking right now.
    if let Ok(d) = claims_dir() {
        if let Ok(_lock) = lock_claims(&d) {
            if let Ok(rd) = fs::read_dir(&d) {
                for e in rd.flatten() {
                    let fname = e.file_name();
                    let Some(f) = fname.to_str() else { continue };
                    if f.starts_with('.') {
                        continue; // `.lock` - never a claim (BoxName forbids a leading '.')
                    }
                    let live = fs::read_to_string(e.path()).is_ok_and(|b| live_claim(&b));
                    if !live {
                        let sz = e.metadata().map(|m| m.len()).unwrap_or(0);
                        if fs::remove_file(e.path()).is_ok() {
                            removed += 1;
                            freed += sz;
                        }
                    }
                }
            }
        }
    }
    (removed, freed)
}

/// Remove files in `target` whose name (minus `suffix`) is not a live-box key. `instances` is the
/// instances dir, used to spare a sidecar whose box registered after the live-set snapshot.
/// Best-effort.
fn sweep_orphans(
    target: io::Result<PathBuf>,
    suffix: &str,
    live: &std::collections::HashSet<String>,
    instances: Option<&Path>,
    removed: &mut usize,
    freed: &mut u64,
) {
    let Ok(d) = target else { return };
    let Ok(rd) = fs::read_dir(&d) else { return };
    for e in rd.flatten() {
        let fname = e.file_name();
        let Some(fname) = fname.to_str() else {
            continue;
        };
        // A log is `<key>.log`; a health sidecar is `<key>` (empty suffix). A file not matching the
        // expected suffix (e.g. a `.log` in the health dir) is skipped, not force-removed.
        let Some(key) = fname.strip_suffix(suffix) else {
            continue;
        };
        if suffix.is_empty() && fname.ends_with(".log") {
            continue; // defensive: never treat a stray `.log` as a health key
        }
        if live.contains(key) {
            continue;
        }
        // Re-check right before deleting: if the box's instance file exists NOW, a box registered
        // after our `list()` snapshot (a start racing this prune) - leave its sidecar alone. This is
        // exact and, unlike a time window, never delays reclaiming a genuinely-stopped box's log
        // (`kern stop` removes the instance file first, so its log is swept immediately).
        if instances.is_some_and(|i| i.join(key).exists()) {
            continue;
        }
        let sz = e.metadata().map(|m| m.len()).unwrap_or(0);
        if fs::remove_file(e.path()).is_ok() {
            *removed += 1;
            *freed += sz;
        }
    }
}

fn parse(body: &str) -> Option<Instance> {
    let (mut name, mut pid) = (None, None);
    let (mut rootfs, mut command, mut ports) = (String::new(), String::new(), String::new());
    let (mut pid1, mut started, mut starttime) = (0i32, 0u64, 0u64);
    let (mut volumes, mut pod) = (String::new(), String::new());
    let (mut egress, mut landlock_rw) = (String::new(), String::new());
    let (mut memory_max, mut pids_max) = (None, None);
    let mut labels = String::new();
    let (mut stop_signal, mut stop_grace) = (0i32, 0u64);
    let mut def_hash = String::new();
    let mut workdir = String::new();
    let mut cap_drop_all = false;
    let (mut cap_drops, mut cap_adds) = (String::new(), String::new());
    let mut apparmor = String::new();
    let mut cgroup = String::new();
    let mut cgroup_id: Option<(u64, u64)> = None;
    // Posture-record state, DERIVED from what the file actually contains (never a stored field):
    //   seccomp_mode  - the box's filter; absent line → Denylist (the allowlist did not exist for a
    //                   box that recorded no mode, so this is provable, not a guess).
    //   cap_recorded  - true once the `capdropall` line is seen; false for a pre-cap-fields box, whose
    //                   capability posture is UNKNOWABLE, so `exec` must refuse rather than guess.
    //   posture_corrupt - a posture field is PRESENT but malformed; `exec` refuses rather than apply a
    //                   partial posture that could be less restrictive than the box actually is.
    let mut seccomp_mode = kern_isolation::SeccompFilter::Denylist;
    let mut cap_recorded = false;
    let mut aa_recorded = false;
    let mut seccomp_recorded = false;
    let mut posture_corrupt = false;
    // Completeness: `encode` writes `capdropall`, `capdrops`, `capadds` together (one feature, one era),
    // so a record that has `capdropall` but is MISSING either list is TRUNCATED, and exec must refuse it
    // rather than reconstruct a posture from the half that survived (drops silently lost). `seccompmode`
    // is deliberately NOT required here: it was added later, so a box from before it legitimately omits
    // the line and runs the provable denylist default.
    let mut seen_capdrops = false;
    let mut seen_capadds = false;
    for line in body.lines() {
        // Skip a malformed line (e.g. a half-written record from a crash mid-write) rather than `?`-ing
        // out, which would evaporate the WHOLE entry and silently drop a live box from the registry.
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "name" => name = Some(v.to_string()),
            "pid" => pid = v.parse().ok(),
            "pid1" => pid1 = v.parse().unwrap_or(0),
            "rootfs" => rootfs = v.to_string(),
            "command" => command = v.to_string(),
            "started" => started = v.parse().unwrap_or(0),
            "starttime" => starttime = v.parse().unwrap_or(0),
            "ports" => ports = v.to_string(),
            "volumes" => volumes = v.to_string(),
            "pod" => pod = v.to_string(),
            "egress" => egress = v.to_string(),
            "landlock" => landlock_rw = v.to_string(),
            // empty string (uncapped) parses to None; a bad value is ignored, not fatal
            "memory_max" => memory_max = v.parse().ok(),
            "pids_max" => pids_max = v.parse().ok(),
            "labels" => labels = v.to_string(),
            "stopsig" => stop_signal = v.parse().unwrap_or(0),
            "stopgrace" => stop_grace = v.parse().unwrap_or(0),
            "defhash" => def_hash = v.to_string(),
            "workdir" => workdir = v.to_string(),
            // The presence of `capdropall` marks a box that DID record its capability posture. A
            // value other than `0`/`1` is corruption, not a default - flag it so `exec` refuses rather
            // than silently reading it as `false` (the LESS restrictive direction).
            "capdropall" => {
                cap_recorded = true;
                match v {
                    "0" => cap_drop_all = false,
                    "1" => cap_drop_all = true,
                    _ => posture_corrupt = true,
                }
            }
            // Store the raw list, but flag corruption: dropping a non-numeric token would make the box
            // LESS dropped (more privileged) on the `drops` side, so a bad token invalidates the record.
            "capdrops" => {
                seen_capdrops = true;
                cap_drops = v.to_string();
                if !cap_csv_valid(v) {
                    posture_corrupt = true;
                }
            }
            "capadds" => {
                seen_capadds = true;
                cap_adds = v.to_string();
                if !cap_csv_valid(v) {
                    posture_corrupt = true;
                }
            }
            // A PRESENT-but-unrecognised mode is corruption (refuse). An ABSENT line is a box from
            // before this field: it stays the default Denylist, which is what that box actually ran.
            "seccompmode" => {
                seccomp_recorded = true;
                match kern_isolation::SeccompFilter::parse(v) {
                    Some(m) => seccomp_mode = m,
                    None => posture_corrupt = true,
                }
            }
            // The AppArmor profile the box entered, or empty for none. Recorded so `kern exec` re-enters
            // the SAME profile. NOT part of the corrupt/refuse gate: an empty/absent value is a valid
            // "no profile" (the box ran unconfined), not a truncated posture.
            "apparmor" => {
                apparmor = v.to_string();
                aa_recorded = true;
            }
            // The box's dedicated cgroup path, recorded once PID 1 was known. Absent in an older entry
            // and empty for a box with no dedicated cgroup - both leave `cgroup` empty, which
            // `cgroup_populated` reads as "no orphan signal" (fall back to supervisor liveness).
            "cgroup" => cgroup = v.to_string(),
            // `<dev>:<ino>` identity of that cgroup dir. A malformed or absent value leaves `cgroup_id`
            // None; `cgroup_populated`/`reap_orphan` then refuse to trust the path (fail closed: an
            // orphan we cannot IDENTIFY is treated as gone rather than reaped by path alone).
            "cgroupid" => {
                cgroup_id = v
                    .split_once(':')
                    .and_then(|(d, i)| Some((d.trim().parse().ok()?, i.trim().parse().ok()?)))
            }
            _ => {}
        }
    }
    // A record with `capdropall` but missing `capdrops`/`capadds` is truncated (they are written as one
    // block): treat it as corrupt so `exec` refuses rather than reconstruct a posture from what survived.
    if cap_recorded && !(seen_capdrops && seen_capadds) {
        posture_corrupt = true;
    }
    Some(Instance {
        name: name?,
        pid: pid?,
        pid1,
        rootfs,
        command,
        started,
        starttime,
        ports,
        volumes,
        pod,
        workdir,
        egress,
        landlock_rw,
        labels,
        stop_signal,
        stop_grace,
        def_hash,
        memory_max,
        pids_max,
        cap_drop_all,
        cap_drops,
        cap_adds,
        seccomp_mode,
        apparmor,
        cap_recorded,
        aa_recorded,
        seccomp_recorded,
        posture_corrupt,
        cgroup,
        cgroup_id,
        // Never serialised: this is a LIVENESS verdict, derived by `load_live` after comparing the
        // supervisor pid against the recorded cgroup. A freshly parsed record carries no verdict yet.
        orphaned: false,
    })
}

/// A capability CSV field is well-formed iff every non-empty comma token parses as a `u32`. The empty
/// string (no caps) is valid. A malformed token must invalidate the whole record, not be silently
/// dropped: on the `--cap-drop` side a dropped token leaves the box LESS dropped (more privileged).
fn cap_csv_valid(s: &str) -> bool {
    s.split(',')
        .filter(|t| !t.is_empty())
        .all(|t| t.parse::<u32>().is_ok())
}

/// The box's capability spec as the three registry fields `(cap_drop_all, cap_drops_csv,
/// cap_adds_csv)` that [`encode`] serialises, so `kern exec` can rebuild the exact `CapSpec` the box's
/// PID 1 got and reapply it instead of the always-dropped baseline. Cap numbers are small ints
/// (`< CAP_LAST_CAP`), joined by commas; the empty string means none.
pub(crate) fn cap_fields(caps: &kern_isolation::CapSpec) -> (bool, String, String) {
    let csv = |v: &[u32]| v.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
    (caps.drop_all, csv(&caps.drops), csv(&caps.adds))
}

/// Rebuild the box's `CapSpec` from the three registry fields (the inverse of [`cap_fields`]), so
/// `kern exec` reapplies the box's OWN drop set - not the always-dropped baseline. An unparseable
/// cap number is dropped rather than errored: a corrupt field must never make an `exec` MORE
/// privileged, and the baseline is still applied under it. An older entry carries no such fields, so
/// `drop_all=false` with empty lists yields `CapSpec::default()` - exactly the pre-record behaviour.
fn cap_spec_from_fields(drop_all: bool, drops: &str, adds: &str) -> kern_isolation::CapSpec {
    let parse = |s: &str| {
        s.split(',')
            .filter(|t| !t.is_empty())
            .filter_map(|t| t.parse::<u32>().ok())
            .collect::<Vec<u32>>()
    };
    kern_isolation::CapSpec {
        drop_all,
        drops: parse(drops),
        adds: parse(adds),
    }
}

impl Instance {
    /// The capability spec and seccomp filter `kern exec` must REPRODUCE for this box, or a refusal.
    /// The gate lives WITH the reconstruction so a caller cannot rebuild a usable posture from a record
    /// that has none: a box predating the posture fields is unknowable (drop-ALL and default both parse
    /// to empty), and a malformed field can't be trusted - guessing either could enter the box MORE
    /// privileged than its PID 1, so both refuse, loudly, and restarting the box re-records. The
    /// `cap_recorded`/`posture_corrupt` flags are private detail of this check, not the caller's to test.
    pub(crate) fn exec_posture(
        &self,
    ) -> Result<
        (
            kern_isolation::CapSpec,
            kern_isolation::SeccompFilter,
            Option<String>,
        ),
        crate::error::Error,
    > {
        if !self.cap_recorded {
            return Err(crate::error::Error::Sandbox(format!(
                "box '{}' was created before its security profile was recorded; its exec profile \
                 cannot be reconstructed safely - restart the box to record it",
                self.name
            )));
        }
        if !self.aa_recorded {
            return Err(crate::error::Error::Sandbox(format!(
                "box '{}' predates AppArmor-posture recording; its exec profile cannot be reconstructed \
                 safely (the box may have started under `--apparmor`, and running the exec unconfined \
                 would breach the box's confinement) - restart the box to record it",
                self.name
            )));
        }
        if !self.seccomp_recorded {
            return Err(crate::error::Error::Sandbox(format!(
                "box '{}' predates seccomp-posture recording; its exec filter cannot be reconstructed \
                 safely (a missing `seccompmode` parses to the weaker denylist default, which could run \
                 the exec under a WIDER filter than the box's PID 1) - restart the box to record it",
                self.name
            )));
        }
        if self.posture_corrupt {
            return Err(crate::error::Error::Sandbox(format!(
                "box '{}' has a corrupt security-posture record; refusing to exec - restart the box",
                self.name
            )));
        }
        // Each posture dimension has its OWN `*_recorded` gate (cap/aa/seccomp): exec refuses a box that
        // predates ANY of them, WITHOUT relying on the field-order coincidence that a missing
        // `seccompmode` also implies a missing `apparmor`. A present-but-malformed field sets
        // `posture_corrupt`, refused above.
        Ok((
            cap_spec_from_fields(self.cap_drop_all, &self.cap_drops, &self.cap_adds),
            self.seccomp_mode,
            // Empty (no profile / older record) → None → `kern exec` adds no AppArmor transition, which
            // matches a box that ran unconfined. A recorded profile is re-entered so the exec is no less
            // confined than the box's workload - the reason this is a RECORD field, not read from /proc.
            (!self.apparmor.is_empty()).then(|| self.apparmor.clone()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every child of the registry root must be CLASSIFIED - `AUTHORITATIVE_DIRS` (kern reads and acts
    /// on it, or it is a cross-box secret; never mountable) or `BOX_DATA_DIRS` (opaque box data). A
    /// registry dir added by any code path fails here until someone classifies it, instead of shipping
    /// mountable-by-default the way `waitexit/` did. The registry root derives from the process-global
    /// `XDG_RUNTIME_DIR`, so this test holds `TEST_ENV_LOCK` while it materializes, resolves and counts:
    /// the env-setting tests flip that var, and a flip landing between materialize and the count would
    /// drop leaves that `canonicalize` can then no longer find, failing the 1:1 count spuriously.
    #[test]
    fn every_registry_child_is_classified() {
        let _env = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // The two classes must be disjoint - a dir cannot be both authoritative and opaque data.
        for a in AUTHORITATIVE_DIRS {
            assert!(!BOX_DATA_DIRS.contains(&a), "{a:?} is in BOTH classes");
        }
        // Materialize every authoritative child so the scan is meaningful and `trusted_state_dirs` can
        // canonicalize all of them (`runtime_subdir` creates `<root>/kern/<leaf>`, the same path
        // `pods_root` resolves to for `pods`).
        materialize_authoritative_dirs_for_test();
        let Ok(instances) = dir() else { return };
        let Some(root) = instances.parent() else {
            return;
        };
        let Ok(rd) = fs::read_dir(root) else { return };
        for e in rd.flatten() {
            if !e.path().is_dir() {
                continue; // registry children are directories; a stray file is not this test's concern
            }
            let raw = e.file_name();
            let name = raw.to_string_lossy();
            assert!(
                AUTHORITATIVE_DIRS.contains(&name.as_ref()) || BOX_DATA_DIRS.contains(&name.as_ref()),
                "unclassified registry child {name:?}: add it to AUTHORITATIVE_DIRS (kern reads and \
                 acts on it, or it holds a cross-box secret) or BOX_DATA_DIRS (opaque box data)"
            );
        }
        // `trusted_state_dirs` is DERIVED from `AUTHORITATIVE_DIRS` - one per entry, no parallel list.
        assert_eq!(trusted_state_dirs().len(), AUTHORITATIVE_DIRS.len());
    }

    #[test]
    fn exec_refuses_a_record_with_apparmor_but_no_seccompmode() {
        // The `seccomp_recorded` gate is MECHANICAL, not a side effect of the field-order invariant
        // (encode writes `seccompmode` before `apparmor`, so a real record cannot carry apparmor without
        // seccommode). A hand-built record with an apparmor line but NO seccommode line is refused BY THE
        // SECCOMP GATE - never silently run under the weaker denylist default a missing `seccompmode`
        // parses to, which could exec into a WIDER filter than the box's PID 1 installed.
        let inst =
            parse("name=b\npid=1\npid1=2\ncapdropall=1\ncapdrops=\ncapadds=\napparmor=kern-box\n")
                .expect("parse a record with apparmor but no seccommode line");
        assert!(inst.aa_recorded, "the apparmor line marks aa recorded");
        assert!(
            !inst.seccomp_recorded,
            "no seccompmode line means the seccomp posture is NOT recorded"
        );
        let err = inst
            .exec_posture()
            .expect_err("exec must refuse a record whose seccomp posture is unrecorded");
        assert!(
            format!("{err}").contains("seccomp-posture recording"),
            "the refusal must name the seccomp gate, got: {err}"
        );
    }

    #[test]
    fn apparmor_survives_the_record_round_trip_and_reaches_exec_posture() {
        // The `--apparmor` profile is part of the exec POSTURE: it must survive encode->parse and come
        // back out of `exec_posture`, so `kern exec` re-enters the SAME profile the box entered. This is
        // why it is a RECORD field and not read from `/proc/<pid1>` - the reaper of an `--init` box reads
        // `unconfined` there, and the exec would run OUTSIDE the box's confinement.
        let inst =
            parse("name=b\npid=1\npid1=2\ncapdropall=1\ncapdrops=\ncapadds=\nseccompmode=denylist\napparmor=kern-box\n")
                .expect("parse a record carrying an apparmor line");
        assert_eq!(inst.apparmor, "kern-box");
        let (_caps, _sec, aa) = inst.exec_posture().expect("posture reproduces");
        assert_eq!(
            aa.as_deref(),
            Some("kern-box"),
            "exec must re-enter the recorded profile"
        );
        assert_eq!(
            parse(&encode(&inst)).unwrap().apparmor,
            "kern-box",
            "the profile survives an encode->parse round trip"
        );
        // `apparmor=` PRESENT but empty = the box ran with NO profile → exec adds no transition, Ok(None).
        let none = parse(
            "name=b\npid=1\npid1=2\ncapdropall=1\ncapdrops=\ncapadds=\nseccompmode=denylist\napparmor=\n",
        )
        .expect("parse a record with an empty-but-present apparmor line");
        assert!(
            none.aa_recorded,
            "an `apparmor=` line, even empty, marks the posture recorded"
        );
        let (_c, _s, aa2) = none
            .exec_posture()
            .expect("posture for a recorded no-profile box");
        assert_eq!(aa2, None, "recorded-but-no-profile → no exec transition");

        // MISSING the apparmor line (older binary that predates recording) = the AppArmor posture is
        // UNKNOWABLE: the box MAY have started under `--apparmor`, so exec must REFUSE rather than run
        // unconfined - the same fail-closed as a missing cap profile (`cap_recorded`).
        let unrec = parse(
            "name=b\npid=1\npid1=2\ncapdropall=1\ncapdrops=\ncapadds=\nseccompmode=denylist\n",
        )
        .expect("parse a pre-apparmor record");
        assert!(!unrec.aa_recorded, "no apparmor line → not recorded");
        assert!(
            unrec.exec_posture().is_err(),
            "an unrecorded AppArmor posture must REFUSE the exec, not run it unconfined"
        );
    }

    #[test]
    fn cap_spec_survives_the_registry_field_round_trip() {
        use kern_isolation::CapSpec;
        // The pair `cap_fields` -> `cap_spec_from_fields` must be lossless, or `kern exec` reapplies
        // the WRONG drop set. Covers `--cap-drop ALL`, `--cap-add` (kept), a specific `--cap-drop`,
        // and the default (empty), which must reconstruct to `CapSpec::default()`.
        let cases = [
            CapSpec {
                drop_all: true,
                drops: vec![],
                adds: vec![10],
            },
            CapSpec {
                drop_all: false,
                drops: vec![0],
                adds: vec![],
            },
            CapSpec {
                drop_all: false,
                drops: vec![],
                adds: vec![],
            },
            CapSpec {
                drop_all: true,
                drops: vec![12, 13],
                adds: vec![21],
            },
        ];
        for c in &cases {
            let (da, dr, ad) = cap_fields(c);
            let back = cap_spec_from_fields(da, &dr, &ad);
            assert_eq!(back.drop_all, c.drop_all, "drop_all lost for {c:?}");
            assert_eq!(back.drops, c.drops, "drops lost for {c:?}");
            assert_eq!(back.adds, c.adds, "adds lost for {c:?}");
        }
        // The empty spec round-trips to the default (the pre-record `exec` behaviour for old boxes).
        let (da, dr, ad) = cap_fields(&CapSpec::default());
        let back = cap_spec_from_fields(da, &dr, &ad);
        assert_eq!(
            back,
            CapSpec::default(),
            "an empty spec must rebuild CapSpec::default()"
        );

        // A corrupt field must never make an exec MORE privileged: an unparseable cap number is
        // dropped, and the dangerous baseline still applies under whatever survives.
        let corrupt = cap_spec_from_fields(false, "12,notanum,13", "");
        assert_eq!(
            corrupt.drops,
            vec![12, 13],
            "a garbage cap number is skipped, not fatal"
        );
    }

    #[test]
    fn rewrite_name_field_swaps_only_the_name_line() {
        let body = "name=old\npid=7\nrootfs=/r\ncommand=sleep 1\n";
        assert_eq!(
            rewrite_name_field(body, "new"),
            "name=new\npid=7\nrootfs=/r\ncommand=sleep 1\n"
        );
        // a `name=` appearing mid-value (not at line start) is left untouched
        let b2 = "command=echo name=x\nname=a\n";
        assert_eq!(rewrite_name_field(b2, "b"), "command=echo name=x\nname=b\n");
    }

    #[test]
    fn rewrite_caps_touches_only_requested_lines() {
        let body = "name=a\nmemory_max=100\npids_max=200\n";
        assert_eq!(
            rewrite_caps(body, Some(50), Some(64)),
            "name=a\nmemory_max=50\npids_max=64\n"
        );
        // memory only: pids_max preserved
        assert_eq!(
            rewrite_caps(body, Some(50), None),
            "name=a\nmemory_max=50\npids_max=200\n"
        );
        // neither: body unchanged
        assert_eq!(rewrite_caps(body, None, None), body);
    }

    /// The short-name rule must recognise the compose SHAPE and nothing else. A hand-named box that
    /// merely ends the same way (`my-api`) must not answer to `api`, or `kern exec api` would act on a
    /// box the user never referred to. The `pod` field cannot be the test: a single-service stack
    /// creates no pod yet still carries the generated `<stack>-<token>-<service>` name.
    #[test]
    fn only_the_compose_name_shape_answers_to_a_short_service_name() {
        for good in [
            "dbg-d019a3a0-api",
            "kern-webstack2-c3598f51-api",
            "a-0123456789abcdef-api",
        ] {
            assert!(is_compose_service(good, "-api"), "{good} should match");
        }
        for bad in [
            "my-api",             // hand-named, no token
            "api",                // the bare name; the exact-name branch owns this
            "stack-zzzzzzzz-api", // token is not hex
            "stack-abc-api",      // token too short to be a hash
            "-d019a3a0-api",      // empty stack
            "dbg-d019a3a0-apix",  // different service
            "dbg-d019a3a0-web",   // different service
        ] {
            assert!(!is_compose_service(bad, "-api"), "{bad} should NOT match");
        }
    }

    /// The `workdir` field is what lets `kern exec` start where the workload started instead of at
    /// `/`. Two things must hold: it survives a round trip, and an entry written by an OLDER kern -
    /// which has no `workdir=` line at all - still loads, with an empty workdir rather than vanishing
    /// from the registry. A schema addition that drops live boxes on upgrade is worse than the gap it
    /// closes.
    #[test]
    fn workdir_roundtrips_and_an_entry_written_without_it_still_loads() {
        let inst = Instance {
            name: "wd".into(),
            pid: 11,
            pid1: 12,
            rootfs: "/r".into(),
            command: "sleep 1".into(),
            started: 1,
            starttime: 2,
            ports: String::new(),
            volumes: String::new(),
            pod: "stack".into(),
            workdir: "/app".into(),
            egress: String::new(),
            landlock_rw: String::new(),
            memory_max: None,
            pids_max: None,
            labels: String::new(),
            stop_signal: 0,
            stop_grace: 0,
            def_hash: String::new(),
            cap_drop_all: false,
            cap_drops: String::new(),
            cap_adds: String::new(),
            seccomp_mode: kern_isolation::SeccompFilter::Denylist,
            apparmor: String::new(),
            cap_recorded: true,
            aa_recorded: true,
            seccomp_recorded: true,
            posture_corrupt: false,
            cgroup: String::new(),
            cgroup_id: None,
            orphaned: false,
        };
        let wire = encode(&inst);
        assert!(wire.contains("workdir=/app\n"), "encoded: {wire}");
        assert_eq!(parse(&wire).expect("round trip").workdir, "/app");

        // A pre-0.6.25 entry: every other key present, no `workdir=` line.
        let older: String = wire
            .lines()
            .filter(|l| !l.starts_with("workdir="))
            .map(|l| format!("{l}\n"))
            .collect();
        let got = parse(&older).expect("an older entry must still load");
        assert_eq!(got.name, "wd", "the entry survived");
        assert_eq!(got.pod, "stack", "its other fields survived");
        assert_eq!(
            got.workdir, "",
            "a missing workdir reads as none, not as garbage"
        );
    }

    #[test]
    fn encode_parse_roundtrips_0_6_7_fields() {
        let inst = Instance {
            name: "rt".into(),
            pid: 7,
            pid1: 8,
            rootfs: "/r".into(),
            command: "sleep 1".into(),
            started: 1,
            starttime: 2,
            ports: String::new(),
            volumes: String::new(),
            pod: "stack".into(),
            workdir: String::new(),
            egress: "pypi.org,files.pythonhosted.org".into(),
            landlock_rw: "/tmp,/data".into(),
            memory_max: Some(134_217_728),
            pids_max: Some(64),
            labels: String::new(),
            stop_signal: 0,
            stop_grace: 0,
            def_hash: String::new(),
            cap_drop_all: true,
            cap_drops: "12,13".into(),
            cap_adds: "10".into(),
            seccomp_mode: kern_isolation::SeccompFilter::Allowlist,
            apparmor: String::new(),
            cap_recorded: true,
            aa_recorded: true,
            seccomp_recorded: true,
            posture_corrupt: false,
            cgroup: String::new(),
            cgroup_id: None,
            orphaned: false,
        };
        let got = parse(&encode(&inst)).expect("parse a well-formed entry");
        assert_eq!(got.pod, "stack");
        assert_eq!(got.egress, "pypi.org,files.pythonhosted.org");
        assert_eq!(got.landlock_rw, "/tmp,/data");
        assert_eq!(got.memory_max, Some(134_217_728));
        assert_eq!(got.pids_max, Some(64));
        // The box's capability spec round-trips: `exec` rebuilds it and must get the exact drop.
        assert!(
            got.cap_drop_all,
            "--cap-drop ALL must survive the round trip"
        );
        assert_eq!(got.cap_drops, "12,13", "extra dropped caps must survive");
        assert_eq!(got.cap_adds, "10", "kept (--cap-add) caps must survive");
        // The seccomp posture round-trips, so `exec` reproduces the box's filter (not a re-read env).
        assert_eq!(
            got.seccomp_mode,
            kern_isolation::SeccompFilter::Allowlist,
            "the seccomp mode must survive the round trip"
        );
        // A well-formed entry is recorded and not corrupt: `exec` proceeds.
        assert!(got.cap_recorded, "a written cap profile marks the record");
        assert!(!got.posture_corrupt, "a well-formed record is not corrupt");
        // an uncapped box round-trips to None (empty value), never Some(0)
        let uncapped = Instance {
            memory_max: None,
            pids_max: None,
            labels: String::new(),
            stop_signal: 0,
            stop_grace: 0,
            def_hash: String::new(),
            cap_drop_all: false,
            cap_drops: String::new(),
            cap_adds: String::new(),
            seccomp_mode: kern_isolation::SeccompFilter::Denylist,
            apparmor: String::new(),
            cap_recorded: true,
            aa_recorded: true,
            seccomp_recorded: true,
            posture_corrupt: false,
            ..inst.clone()
        };
        let got2 = parse(&encode(&uncapped)).expect("parse");
        assert_eq!(got2.memory_max, None);
        assert_eq!(got2.pids_max, None);
        // an OLD entry with none of the new keys still parses (backward compatible), fields default
        let legacy = "name=old\npid=3\npid1=0\nrootfs=/r\ncommand=sh\nstarted=1\nstarttime=2\nports=\nvolumes=\npod=\n";
        let g = parse(legacy).expect("legacy entry still parses");
        assert!(g.egress.is_empty() && g.landlock_rw.is_empty());
        assert_eq!(g.memory_max, None);
        assert_eq!(g.pids_max, None);
        // No cap keys in a legacy entry: `exec` must rebuild `CapSpec::default()` (the dangerous
        // baseline), which is exactly how it behaved before the fields existed - no behaviour change
        // for a box started by an older kern still running across the upgrade.
        assert!(
            !g.cap_drop_all && g.cap_drops.is_empty() && g.cap_adds.is_empty(),
            "a legacy entry must default its cap fields, not invent a drop set"
        );
        // a corrupt line (e.g. a truncated write) is SKIPPED, not fatal: the box stays in the registry
        let corrupt = "name=surv\npid=9\nthis-line-has-no-equals\npod=stack\n";
        let s = parse(corrupt).expect("a corrupt line must not evaporate the whole entry");
        assert_eq!(s.name, "surv");
        assert_eq!(s.pid, 9);
        assert_eq!(s.pod, "stack");
    }

    // Registry-mutating tests all share ONE process-wide instances dir AND one pid
    // (`std::process::id()`), so a pid-keyed `find_ref` in one test can observe a box another test
    // registered under the same pid. Serialize them through this lock so each runs without a
    // concurrent same-pid registration racing it. (No dir wipe: a stale entry from a prior run is
    // inert - its pid belongs to a now-dead process, so `is_alive` skips it - and a developer's real
    // running boxes have different pids and are never touched.)
    static REG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    /// Registry tests resolve the claims/instances dir through `runtime_subdir`, which READS
    /// `$XDG_RUNTIME_DIR`. Other modules' tests (e.g. `runstats`) repoint that var - process-global -
    /// under [`crate::TEST_ENV_LOCK`]. Holding only `REG_LOCK` left the two uncoordinated: a concurrent
    /// env flip mid-test split the 16-thread contention test across two runtime dirs, so each half took
    /// its own `.lock` and BOTH "won" (flaky `claim_name_one_winner_under_contention`). Hold BOTH locks,
    /// always env-then-reg (one consistent order → no deadlock, since no path takes them reversed).
    fn reg_guard() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        let env = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let reg = REG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        (env, reg)
    }

    #[test]
    fn well_formed_entry_accepts_our_files_rejects_junk() {
        use std::ffi::OsStr;
        // `<name>-<pid>` - names may contain `-` `.` `_`, pid is the trailing digits.
        assert!(well_formed_entry(OsStr::new("web-42")));
        assert!(well_formed_entry(OsStr::new("my-box-12345")));
        assert!(well_formed_entry(OsStr::new("app.v2-7")));
        // Junk a same-user process might drop in the dir.
        assert!(!well_formed_entry(OsStr::new("web")));
        assert!(!well_formed_entry(OsStr::new("web-")));
        assert!(!well_formed_entry(OsStr::new("web-abc")));
        assert!(!well_formed_entry(OsStr::new("-42")));
        assert!(!well_formed_entry(OsStr::new("evil.tmp")));
    }

    /// The recorded cgroup path is what lets `list()` tell an ORPHANED box (supervisor dead, cgroup
    /// still populated) from an exited one. It must survive a round trip, and an entry written by an
    /// OLDER kern - no `cgroup=` line - must still load with an empty path (read as "no orphan signal",
    /// so liveness falls back to the supervisor pid), never vanish from the registry.
    #[test]
    fn cgroup_field_roundtrips_and_an_older_entry_defaults_empty() {
        let body = "name=cg\npid=7\npid1=8\nrootfs=/r\ncommand=sh\nstarted=1\nstarttime=2\ncgroup=/sys/fs/cgroup/kern.slice/kern-box-cg-9\ncgroupid=42:1337\n";
        let got = parse(body).expect("parse");
        assert_eq!(got.cgroup, "/sys/fs/cgroup/kern.slice/kern-box-cg-9");
        assert_eq!(
            got.cgroup_id,
            Some((42, 1337)),
            "the (dev, ino) identity must parse"
        );
        assert!(
            !got.orphaned,
            "a freshly parsed record carries no liveness verdict"
        );
        let wire = encode(&got);
        assert!(
            wire.contains("cgroup=/sys/fs/cgroup/kern.slice/kern-box-cg-9\n"),
            "the cgroup field must survive the round trip; encoded: {wire}"
        );
        assert!(
            wire.contains("cgroupid=42:1337\n"),
            "the cgroup identity must survive the round trip; encoded: {wire}"
        );
        // An older entry (no cgroup/cgroupid lines) still loads, with empty path and no identity.
        let older = "name=old\npid=3\npid1=0\nrootfs=/r\ncommand=sh\nstarted=1\nstarttime=2\n";
        let g = parse(older).expect("an older entry must still load");
        assert_eq!(
            g.cgroup, "",
            "a missing cgroup line reads as empty, not garbage"
        );
        assert_eq!(g.cgroup_id, None, "a missing identity line reads as None");
        // A malformed identity must not panic and must read as None (fail closed: unidentifiable).
        let bad = "name=b\npid=3\npid1=0\nrootfs=/r\ncommand=sh\nstarted=1\nstarttime=2\ncgroupid=not:a:number\n";
        assert_eq!(
            parse(bad).expect("still parses").cgroup_id,
            None,
            "a malformed cgroupid must be None, not a partial parse"
        );
    }

    /// A detached box whose SUPERVISOR was SIGKILL'd but whose PID 1 / `-p` forwarder outlived it must
    /// stay VISIBLE and reapable, not vanish from the registry while it still holds a host port bound.
    /// `load_live` decides this from the RECORDED cgroup, so the state is FABRICATED deterministically -
    /// a dead supervisor pid plus a `cgroup.events` file - rather than by racing a real SIGKILL. When
    /// the cgroup later reads empty, the record is pruned (exited).
    #[test]
    fn an_orphaned_box_stays_visible_and_an_exited_one_is_pruned() {
        let _g = reg_guard();
        // A stand-in cgroup: `cgroup_populated` only reads `<dir>/cgroup.events`, so a plain file is
        // a faithful substitute for a real cgroup with a live process in it.
        let cg = std::env::temp_dir().join(format!("kern-orph-cg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&cg);
        fs::create_dir_all(&cg).expect("cg dir");
        fs::write(cg.join("cgroup.events"), "populated 1\nfrozen 0\n").expect("events");
        // The record must carry the dir's REAL (dev, ino): liveness now confirms identity, not just
        // the path, so a fabricated cgroup needs its true identity or it reads as a stranger's.
        let (dev, ino) = cgroup_identity(&cg.to_string_lossy()).expect("stat cg");
        // A supervisor pid that CANNOT be alive (above any kernel pid_max), so `is_alive` is false.
        let dead_pid: i32 = 0x3FFF_FFFF;
        let name = format!("orph-{}", std::process::id());
        let d = dir().expect("registry dir");
        let entry = d.join(format!("{name}-{dead_pid}"));
        let body = format!(
            "name={name}\npid={dead_pid}\npid1=0\nrootfs=/r\ncommand=sleep\nstarted=1\nstarttime=2\ncgroup={}\ncgroupid={dev}:{ino}\n",
            cg.display()
        );
        fs::write(&entry, &body).expect("write entry");
        // POPULATED cgroup + dead supervisor ⇒ orphaned, KEPT (not pruned).
        let got = find(&name).expect("an orphaned box must stay visible, not be pruned");
        assert!(
            got.orphaned,
            "dead supervisor + populated cgroup ⇒ orphaned"
        );
        assert_eq!(got.cgroup, cg.to_string_lossy());
        assert!(
            entry.exists(),
            "an orphaned entry must NOT be pruned from disk"
        );
        // Now the cgroup reads EMPTY ⇒ exited ⇒ `find` prunes the stale record.
        fs::write(cg.join("cgroup.events"), "populated 0\nfrozen 0\n").expect("events empty");
        assert!(
            find(&name).is_none(),
            "an empty-cgroup dead-supervisor box is exited and must be pruned"
        );
        assert!(
            !entry.exists(),
            "the exited record must be pruned from disk"
        );
        let _ = fs::remove_dir_all(&cg);
    }

    /// `probe_cgroup` must split "definitely gone" (`ENOENT`) from "resolved" - the errno classification
    /// that keeps a transient failure (fd exhaustion) from reading as absence and pruning a live record.
    /// The transient branch (`EMFILE`) is fabricated at the shell level (`ulimit -n`); here we pin the
    /// two deterministic ends and that a dead-supervisor box over an ABSENT cgroup reads as `Exited`.
    #[test]
    fn probe_cgroup_splits_gone_from_resolved() {
        // A path that cannot exist ⇒ Gone (never Unknown).
        assert!(
            matches!(
                probe_cgroup("/sys/fs/cgroup/kern.slice/kern-box-nope-does-not-exist-999999"),
                Probe::Gone
            ),
            "an absent cgroup path must classify as Gone"
        );
        // A real directory ⇒ Id with its (dev, ino).
        let tmp = std::env::temp_dir();
        assert!(
            matches!(probe_cgroup(&tmp.to_string_lossy()), Probe::Id(_)),
            "an existing directory must classify as Id"
        );
        // cgroup_liveness over a recorded-but-absent cgroup with an identity ⇒ Exited (prunable).
        assert!(matches!(
            cgroup_liveness(
                "/sys/fs/cgroup/kern.slice/kern-box-nope-x-999999",
                Some((1, 2))
            ),
            Liveness::Exited
        ));
        // No recorded identity ⇒ Exited (fail closed, never reap-by-path).
        assert!(matches!(
            cgroup_liveness("/some/path", None),
            Liveness::Exited
        ));
    }

    /// The PID-reuse collision the reviewer named: a box's `kern-box-<name>-<pid>` path is recreated -
    /// by a LATER box after a pid recycled the leaf - as a DIFFERENT cgroup (different inode). The stale
    /// record still points at that path, and the path IS populated (by the stranger's processes). Path
    /// alone would read the box as orphaned and `cgroup.kill` would SIGKILL the wrong box. The `(dev,
    /// ino)` identity closes it: a mismatched inode reads as exited (pruned, not reaped), and a direct
    /// `reap_orphan` refuses to kill. Fabricated deterministically - a populated dir plus a record whose
    /// recorded identity is DELIBERATELY wrong - rather than by racing a real pid recycle.
    #[test]
    fn a_recycled_cgroup_path_is_not_reaped_when_its_identity_changed() {
        let _g = reg_guard();
        let cg = std::env::temp_dir().join(format!("kern-orph-id-{}", std::process::id()));
        let _ = fs::remove_dir_all(&cg);
        fs::create_dir_all(&cg).expect("cg dir");
        // Populated, as a stranger's live cgroup would be.
        fs::write(cg.join("cgroup.events"), "populated 1\nfrozen 0\n").expect("events");
        let (dev, real_ino) = cgroup_identity(&cg.to_string_lossy()).expect("stat cg");
        // The record's recorded inode is DELIBERATELY wrong (what the ORIGINAL box's cgroup had).
        let stale_ino = real_ino.wrapping_add(1);
        let dead_pid: i32 = 0x3FFF_FFFE;
        let name = format!("orphid-{}", std::process::id());
        let d = dir().expect("registry dir");
        let entry = d.join(format!("{name}-{dead_pid}"));
        let body = format!(
            "name={name}\npid={dead_pid}\npid1=0\nrootfs=/r\ncommand=sleep\nstarted=1\nstarttime=2\ncgroup={}\ncgroupid={dev}:{stale_ino}\n",
            cg.display()
        );
        fs::write(&entry, &body).expect("write entry");
        // Populated path, but the identity no longer matches ⇒ this box is GONE, not orphaned ⇒ pruned.
        assert!(
            find(&name).is_none(),
            "a populated path with a changed identity must read as exited, never as this box orphaned"
        );
        // And a direct reap must REFUSE to kill (nothing of ours is there). Rebuild the instance and
        // call `reap_orphan`: it must return false and touch no `cgroup.kill` in the stranger's dir.
        fs::write(&entry, &body).expect("rewrite entry"); // `find` above pruned it; restore for the direct call
        let inst = parse(&body).expect("parse");
        assert_eq!(inst.cgroup_id, Some((dev, stale_ino)));
        assert!(
            !reap_orphan(&inst),
            "reap_orphan must NOT kill a cgroup whose identity differs from the record"
        );
        assert!(
            !cg.join("cgroup.kill").exists(),
            "the identity-mismatched reap must not have created/written cgroup.kill"
        );
        let _ = fs::remove_dir_all(&cg);
    }

    #[test]
    fn exit_key_bracketed_matches_pod_and_name_across_tokens() {
        // `compose down` reaps `<pod>-<*any token*>-<name>` for a box it stops. It must match every
        // token of THAT box, and NOT a different box of the same stack (the concurrent-run leak the
        // final review flagged).
        let p = "myapp-"; // pod prefix
        let s = "-migrate"; // -<name>
        assert!(exit_key_bracketed("myapp-tokenA-migrate", p, s));
        assert!(exit_key_bracketed("myapp-99-123456789-migrate", p, s)); // real token shape
                                                                         // A DIFFERENT box of the same stack must NOT match - this is the fix.
        assert!(!exit_key_bracketed("myapp-tokenA-other", p, s));
        // A different stack must not match.
        assert!(!exit_key_bracketed("otherapp-tokenA-migrate", p, s));
        // Length guard: prefix and suffix must not overlap on a too-short name.
        assert!(!exit_key_bracketed("myapp-migrate", "myapp-", "-migrate")); // no token between → too short to bracket
        assert!(!exit_key_bracketed("x", "myapp-", "-migrate"));
    }

    #[test]
    fn is_paused_false_when_no_cgroup() {
        // An impossible pid has no /proc/<pid>/cgroup → no box cgroup → not paused (safe default,
        // so a box whose freeze state can't be read never shows a spurious "paused").
        assert!(!is_paused(i32::MAX));
    }

    #[test]
    fn claim_name_excludes_second_starter_and_releases_on_drop() {
        let _g = reg_guard();
        let name = format!("clm-{}", std::process::id());
        let c1 = claim_name(&name).unwrap();
        assert!(c1.is_some(), "first claim must win");
        // While held, a second start of the same name is refused.
        assert!(claim_name(&name).unwrap().is_none());
        drop(c1);
        // Released → the name is claimable again (and the file is gone).
        let c2 = claim_name(&name).unwrap();
        assert!(c2.is_some(), "claim must be reusable after release");
    }

    #[test]
    fn find_ref_resolves_name_then_pid_name_wins() {
        let _g = reg_guard();
        let pid = std::process::id() as i32; // THIS process is alive → is_alive true
        let mk = |name: &str, p: i32| {
            register(&Instance {
                name: name.to_string(),
                pid: p,
                pid1: 0,
                rootfs: String::new(),
                command: String::new(),
                started: 1,
                starttime: proc_starttime(pid),
                ports: String::new(),
                volumes: String::new(),
                pod: String::new(),
                workdir: String::new(),
                egress: String::new(),
                landlock_rw: String::new(),
                memory_max: None,
                pids_max: None,
                labels: String::new(),
                stop_signal: 0,
                stop_grace: 0,
                def_hash: String::new(),
                cap_drop_all: false,
                cap_drops: String::new(),
                cap_adds: String::new(),
                seccomp_mode: kern_isolation::SeccompFilter::Denylist,
                apparmor: String::new(),
                cap_recorded: true,
                aa_recorded: true,
                seccomp_recorded: true,
                posture_corrupt: false,
                cgroup: String::new(),
                cgroup_id: None,
                orphaned: false,
            })
            .unwrap()
        };
        let uniq = format!("fr-{pid}");
        let p1 = mk(&uniq, pid);
        // by NAME: resolves to exactly our box (unique name - deterministic).
        assert_eq!(find_ref(&uniq).map(|i| i.name), Some(uniq.clone()));
        // by PID: a numeric ref resolves via the pid branch to a LIVE box with this pid. Under the
        // test harness every test shares THIS process's pid, so a concurrent test's box may be the one
        // returned - assert the resolved box carries the queried pid, not that it's our exact name.
        // (The name-resolution and name-wins properties below use unique names and stay exact.)
        assert_eq!(find_ref(&pid.to_string()).map(|i| i.pid), Some(pid));
        // an unknown name and a non-existent pid both miss.
        assert!(find_ref("no-such-box-xyz").is_none());
        assert!(find_ref("2147483647").is_none()); // i32::MAX - no such pid
                                                   // NAME WINS: a box literally named after a NUMBER resolves by that NAME (via `find`), never
                                                   // via the pid branch - so a numeric name can't be shadowed by a coincidental pid.
        let numname = format!("{}", pid.wrapping_add(1)); // a name that looks like a (different) pid
        let p2 = mk(&numname, pid);
        assert_eq!(find_ref(&numname).map(|i| i.name), Some(numname.clone()));
        unregister(&p1);
        unregister(&p2);
    }

    /// `rename` must be all-or-nothing: either the box answers to the new name, or nothing changed.
    ///
    /// The displayed name comes from the `name=` field INSIDE the entry body (`load_live` -> `parse`),
    /// not from the file name. `rename` renamed the FILE with `?` and rewrote the BODY with a
    /// discarded result, so a failed rewrite left the file called `<new>-<pid>` while the body still
    /// said `<old>` - and returned `Ok`. The user is told the rename worked and `kern ps` keeps
    /// showing the old name, with the two halves of the registry entry disagreeing about the box's
    /// identity.
    ///
    /// The failure is forced deterministically rather than waited for: `atomic_rewrite` stages through
    /// `.rename-<our-pid>-<box-pid>.tmp` in the registry directory, so pre-planting that path as a
    /// DIRECTORY makes its `fs::write` fail `EISDIR` on every filesystem.
    #[test]
    fn rename_is_all_or_nothing_when_the_body_cannot_be_rewritten() {
        let _g = reg_guard();
        let pid = std::process::id() as i32; // this process is alive, so the entry is "live"
        let old = format!("rn-old-{pid}");
        let new = format!("rn-new-{pid}");
        let path = register(&Instance {
            name: old.clone(),
            pid,
            pid1: 0,
            rootfs: String::new(),
            command: String::new(),
            started: 1,
            starttime: proc_starttime(pid),
            ports: String::new(),
            volumes: String::new(),
            pod: String::new(),
            workdir: String::new(),
            egress: String::new(),
            landlock_rw: String::new(),
            memory_max: None,
            pids_max: None,
            labels: String::new(),
            stop_signal: 0,
            stop_grace: 0,
            def_hash: String::new(),
            cap_drop_all: false,
            cap_drops: String::new(),
            cap_adds: String::new(),
            seccomp_mode: kern_isolation::SeccompFilter::Denylist,
            apparmor: String::new(),
            cap_recorded: true,
            aa_recorded: true,
            seccomp_recorded: true,
            posture_corrupt: false,
            cgroup: String::new(),
            cgroup_id: None,
            orphaned: false,
        })
        .expect("register the box under its original name");
        let d = dir().expect("registry dir");
        let blocker = d.join(format!(".rename-{}-{pid}.tmp", std::process::id()));
        std::fs::create_dir_all(&blocker).expect("plant the staging path as a directory");

        let outcome = rename(&old, &new, pid);
        let by_new = find_ref(&new).map(|i| i.name);
        let by_old = find_ref(&old).map(|i| i.name);

        let _ = std::fs::remove_dir_all(&blocker);
        unregister(&path);
        unregister(&d.join(format!("{new}-{pid}")));
        unregister(&d.join(format!("{old}-{pid}")));

        if outcome.is_ok() {
            assert_eq!(
                by_new.as_deref(),
                Some(new.as_str()),
                "rename reported success, so the box must answer to '{new}'"
            );
            assert!(
                by_old.is_none(),
                "rename reported success, so '{old}' must no longer resolve"
            );
        } else {
            assert_eq!(
                by_old.as_deref(),
                Some(old.as_str()),
                "rename failed, so the registry must be exactly as it was: the box still '{old}'"
            );
            assert!(
                by_new.is_none(),
                "rename failed, so '{new}' must not resolve to anything"
            );
        }
    }

    #[test]
    fn claim_name_refuses_a_live_registered_box() {
        let _g = reg_guard();
        // The registry re-check lives INSIDE claim_name (under its lock): a box that registered and
        // released its claim must still make a fresh claim fail - for EVERY caller, by construction.
        let name = format!("clm-reg-{}", std::process::id());
        let pid = std::process::id() as i32;
        let path = register(&Instance {
            name: name.clone(),
            pid,
            pid1: 0,
            rootfs: String::new(),
            command: String::new(),
            started: 1,
            starttime: proc_starttime(pid),
            ports: String::new(),
            volumes: String::new(),
            pod: String::new(),
            workdir: String::new(),
            egress: String::new(),
            landlock_rw: String::new(),
            memory_max: None,
            pids_max: None,
            labels: String::new(),
            stop_signal: 0,
            stop_grace: 0,
            def_hash: String::new(),
            cap_drop_all: false,
            cap_drops: String::new(),
            cap_adds: String::new(),
            seccomp_mode: kern_isolation::SeccompFilter::Denylist,
            apparmor: String::new(),
            cap_recorded: true,
            aa_recorded: true,
            seccomp_recorded: true,
            posture_corrupt: false,
            cgroup: String::new(),
            cgroup_id: None,
            orphaned: false,
        })
        .unwrap();
        let got = claim_name(&name).unwrap();
        unregister(&path);
        assert!(got.is_none(), "a live registered box must refuse the claim");
    }

    #[test]
    fn claim_name_takes_over_stale_and_malformed_claims() {
        let _g = reg_guard();
        // A claimant pid that can't exist (> kernel pid_max) → dead → stale → taken over.
        let name = format!("clm-stale-{}", std::process::id());
        let d = claims_dir().unwrap();
        fs::write(d.join(&name), "999999999 1\n").unwrap();
        assert!(claim_name(&name).unwrap().is_some());
        // A malformed body is treated as stale too (never wedges the name forever).
        let name2 = format!("clm-junk-{}", std::process::id());
        fs::write(d.join(&name2), "not a claim\n").unwrap();
        assert!(claim_name(&name2).unwrap().is_some());
    }

    #[test]
    fn claim_name_one_winner_under_contention() {
        let _g = reg_guard();
        // The E5 race: N concurrent starts of the SAME name - exactly one may win. Threads each
        // open their own lock fd (flock is per-open-file-description, so they do exclude each other).
        let name = format!("clm-race-{}", std::process::id());
        let wins: Vec<Option<NameClaim>> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..16)
                .map(|_| s.spawn(|| claim_name(&name).ok().flatten()))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(
            wins.iter().filter(|w| w.is_some()).count(),
            1,
            "exactly one of 16 concurrent same-name claims must win"
        );
    }

    #[test]
    fn claim_name_capped_enforces_the_fleet_ceiling_atomically() {
        let _g = reg_guard();
        // The ceiling is a GLOBAL count, so unique names do not isolate it the way the other claim
        // tests are isolated - point the runtime dir at a fresh temp so the count sees ONLY this test's
        // claims. `reg_guard` holds `TEST_ENV_LOCK`, so no other test flips `XDG_RUNTIME_DIR` meanwhile.
        let prev = std::env::var_os("XDG_RUNTIME_DIR");
        let tmp = std::env::temp_dir().join(format!("kern-fleet-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        std::env::set_var("XDG_RUNTIME_DIR", &tmp);

        // A binder that asserts the outcome is a live claim and hands back the guard (kept alive so its
        // claim keeps counting). Panicking here is a TEST assertion, not production code.
        let claim_ok = |name: &str, max: Option<usize>| -> NameClaim {
            match claim_name_capped(name, max).expect("runtime dir is writable") {
                StartOutcome::Claimed(c) => c,
                StartOutcome::NameBusy => panic!("'{name}' unexpectedly busy"),
                StartOutcome::FleetFull { live, max } => {
                    panic!("'{name}' refused: fleet {live}/{max:?}")
                }
            }
        };

        // max = 2: two claims fit, the third is refused with the exact numbers, and the refusal is
        // atomic with the count (the third could not have slipped in before the second's claim landed).
        let c1 = claim_ok("a", Some(2));
        let c2 = claim_ok("b", Some(2));
        match claim_name_capped("c", Some(2)).unwrap() {
            StartOutcome::FleetFull { live, max } => {
                assert_eq!((live, max), (2, 2), "third claim must see the full fleet");
            }
            _ => panic!("third claim over the ceiling must be FleetFull"),
        }
        // Releasing one frees exactly one slot (the count is self-healing on the claim file's removal).
        drop(c1);
        let c3 = claim_ok("c", Some(2));
        // An uncapped claim is never fleet-refused, whatever the count.
        let c4 = claim_ok("d", None);

        drop(c2);
        drop(c3);
        drop(c4);
        let _ = fs::remove_dir_all(&tmp);
        match prev {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    #[test]
    fn parse_reads_volumes_and_tolerates_older_entries() {
        let _g = reg_guard();
        // A full entry round-trips the volumes and pod fields.
        let full = "name=web\npid=42\npid1=7\nrootfs=/r\ncommand=sh\nstarted=1\nstarttime=2\nports=\nvolumes=data,cache\npod=myapp\n";
        let i = parse(full).unwrap();
        assert_eq!(i.name, "web");
        assert_eq!(i.volumes, "data,cache");
        assert_eq!(i.pod, "myapp");
        // An OLDER entry with no `volumes=`/`pod=` line still parses (fields default to empty) - the
        // wire format is append-only, so a box registered by a previous kern version is never dropped.
        let old = "name=web\npid=42\nrootfs=/r\ncommand=sh\nstarted=1\nstarttime=2\nports=\n";
        let oi = parse(old).unwrap();
        assert_eq!(oi.volumes, "");
        assert_eq!(oi.pod, "");
        // ...but its capability posture is UNKNOWABLE: no `capdropall` line means `exec` must refuse
        // rather than guess a baseline. The record still parses (the box stays visible to `ps`/`stop`);
        // only `exec` gates on `cap_recorded`. The seccomp mode defaults to the provable denylist.
        assert!(
            !oi.cap_recorded,
            "an entry with no cap fields must be marked unrecorded, so exec refuses"
        );
        assert!(!oi.posture_corrupt, "absent is not corrupt");
        assert_eq!(
            oi.seccomp_mode,
            kern_isolation::SeccompFilter::Denylist,
            "a box that recorded no mode ran the denylist (the allowlist did not exist for it)"
        );
    }

    #[test]
    fn a_malformed_posture_field_is_flagged_corrupt_never_silently_defaulted() {
        // The record is present (has `capdropall`) so it is NOT "absent", but each posture field is
        // malformed in turn. Each must set `posture_corrupt` so `exec` refuses - a garbage token must
        // never be dropped into a LESS restrictive posture (fewer drops, or a fallback filter mode).
        let base = "name=b\npid=1\nrootfs=/r\ncommand=sh\nstarted=1\nstarttime=2\n";
        // capdropall neither 0 nor 1
        let bad_all = parse(&format!("{base}capdropall=2\ncapdrops=\ncapadds=\n")).unwrap();
        assert!(
            bad_all.cap_recorded && bad_all.posture_corrupt,
            "capdropall=2"
        );
        // a non-numeric token in the DROP list (the dangerous side: dropping it → less dropped)
        let bad_drop = parse(&format!("{base}capdropall=0\ncapdrops=12,x,13\ncapadds=\n")).unwrap();
        assert!(bad_drop.posture_corrupt, "non-numeric cap in capdrops");
        // a non-numeric token in the ADD list
        let bad_add = parse(&format!("{base}capdropall=0\ncapdrops=\ncapadds=nope\n")).unwrap();
        assert!(bad_add.posture_corrupt, "non-numeric cap in capadds");
        // an unrecognised seccomp mode
        let bad_mode = parse(&format!(
            "{base}capdropall=0\ncapdrops=\ncapadds=\nseccompmode=wat\n"
        ))
        .unwrap();
        assert!(bad_mode.posture_corrupt, "unknown seccompmode token");
        // TRUNCATED after `capdropall`: the drops that follow were cut (a `SIGKILL` mid-write, or a
        // fabricated partial record). Reconstructing a posture from `capdropall` alone would silently
        // lose the drops, so a record with `capdropall` but MISSING `capdrops`/`capadds` is corrupt.
        let cut_after_all = parse(&format!("{base}capdropall=0\n")).unwrap();
        assert!(
            cut_after_all.cap_recorded && cut_after_all.posture_corrupt,
            "capdropall present but capdrops/capadds missing = truncated"
        );
        let cut_mid = parse(&format!("{base}capdropall=0\ncapdrops=12,13\n")).unwrap();
        assert!(
            cut_mid.posture_corrupt,
            "capdropall+capdrops present but capadds missing = truncated"
        );
        // A box from BEFORE `seccompmode` existed - capdropall+capdrops+capadds, no seccompmode line - is
        // NOT corrupt: the absent mode is the provable denylist default, and that box actually ran it.
        let old_box = parse(&format!("{base}capdropall=1\ncapdrops=12,13\ncapadds=10\n")).unwrap();
        assert!(
            old_box.cap_recorded && !old_box.posture_corrupt,
            "a pre-seccompmode box (all cap fields, no seccompmode) is valid"
        );
        assert_eq!(
            old_box.seccomp_mode,
            kern_isolation::SeccompFilter::Denylist
        );
        // a WELL-FORMED record with every posture field present is neither absent nor corrupt.
        let ok = parse(&format!(
            "{base}capdropall=1\ncapdrops=12,13\ncapadds=10\nseccompmode=allowlist\n"
        ))
        .unwrap();
        assert!(ok.cap_recorded && !ok.posture_corrupt);
        assert_eq!(ok.seccomp_mode, kern_isolation::SeccompFilter::Allowlist);
    }

    #[test]
    fn the_inverted_guard_refuses_by_default_and_allows_only_box_data() {
        // INVERTED DEFAULT (pure path half): under the registry root, refuse EVERYTHING except a
        // box-data child, so a new child (as `runstats` was) is non-mountable by omission. Also refuse
        // the root itself and any ancestor that drags it in; leave siblings and unrelated paths alone.
        let root = Path::new("/run/user/1000/kern");
        let refuse = |p: &str| mount_refused_by_path(Path::new(p), root);

        // authoritative dirs, a record inside one, an UNKNOWN future child, and the runstats FILE → all
        // refused by omission (none is a box-data child).
        assert_eq!(refuse("/run/user/1000/kern/instances"), Some(true));
        assert_eq!(refuse("/run/user/1000/kern/instances/victim-9"), Some(true));
        assert_eq!(refuse("/run/user/1000/kern/health"), Some(true));
        assert_eq!(refuse("/run/user/1000/kern/pods/shop/holder"), Some(true));
        assert_eq!(refuse("/run/user/1000/kern/runstats"), Some(true));
        assert_eq!(refuse("/run/user/1000/kern/some_future_child"), Some(true));
        // the root itself, and an ANCESTOR that contains it → refused.
        assert_eq!(refuse("/run/user/1000/kern"), Some(true));
        assert_eq!(refuse("/run/user/1000"), Some(true));
        assert_eq!(refuse("/run/user"), Some(true));
        // BOX_DATA children (and paths inside them) → ALLOWED.
        assert_eq!(refuse("/run/user/1000/kern/logs"), Some(false));
        assert_eq!(
            refuse("/run/user/1000/kern/scratch/box-1/upper"),
            Some(false)
        );
        // a SIBLING sharing a name prefix, and unrelated paths → no path overlap (identity check next).
        assert_eq!(refuse("/run/user/1000/kern-other"), None);
        assert_eq!(refuse("/tmp/project"), None);
    }
}
