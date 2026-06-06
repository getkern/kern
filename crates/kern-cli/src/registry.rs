//! Running-box registry.
//!
//! Each detached box writes one small `key=value` file under `$XDG_RUNTIME_DIR/kern/instances/`
//! (falling back to `/run/user/<uid>/kern/instances/`, then `/tmp/kern-<uid>/instances/`). The
//! "pid" is the supervisor process that lives for the box's lifetime. [`list`] reads the dir and
//! **prunes dead entries** as a side effect, so `kern ps` always reflects reality without a
//! daemon. The on-disk format is deliberately a flat `key=value` file — trivial to write from a
//! post-`fork` supervisor and to parse, no JSON dependency.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// One registered, running box.
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
    /// Comma-separated **named volumes** this box mounts (from `-v name:/dst`) — so `kern volume rm`
    /// can refuse to delete a volume still in use. Empty when none; absent in older entries.
    pub volumes: String,
}

impl Instance {
    /// The named volumes this box mounts. Sole decoder of the comma-separated `volumes` wire-format
    /// (empties filtered) — `volume rm`/`prune` ask through here rather than splitting the raw field,
    /// so the encoding lives in one place (paired with `commands::mounted_named_volumes`, the encoder).
    pub fn volume_names(&self) -> impl Iterator<Item = &str> {
        self.volumes.split(',').filter(|v| !v.is_empty())
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

/// The health directory — a sidecar `<name>-<pid>` per box with `--health-cmd`, holding its latest
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

/// Create and return `<runtime>/kern/<leaf>`, with graceful fallbacks.
fn runtime_subdir(leaf: &str) -> io::Result<PathBuf> {
    let uid = unsafe { libc::getuid() };
    let mut candidates = Vec::new();
    if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR") {
        candidates.push(PathBuf::from(x).join("kern").join(leaf));
    }
    candidates.push(PathBuf::from(format!("/run/user/{uid}/kern/{leaf}")));
    candidates.push(PathBuf::from(format!("/tmp/kern-{uid}/{leaf}")));
    // Create every component we own as **0700**: `$XDG_RUNTIME_DIR`/`/run/user/<uid>` are already
    // owner-only, but the `/tmp/kern-<uid>` fallback lives under world-traversable `/tmp`, and this
    // tree can hold private material (the `--ssh` throwaway key). `DirBuilder` only sets the mode on
    // components it creates, so an existing (systemd-owned) runtime dir is left untouched.
    use std::os::unix::fs::DirBuilderExt;
    let mut last_err = io::Error::other("no writable runtime dir");
    for d in candidates {
        match fs::DirBuilder::new().recursive(true).mode(0o700).create(&d) {
            Ok(()) => return Ok(d),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
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
/// processes live in the shared session cgroup — the same one `kern` itself runs in — and
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

/// All per-box cgroup stats from a **single** `box_cgroup` resolve — mem / cpu / tasks / frozen. The
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
/// when the box has no dedicated cgroup or the file is unreadable — so `ps`/`top` can show "paused"
/// instead of a frozen box looking identical to a running one.
pub fn is_paused(pid: i32) -> bool {
    box_cgroup(pid)
        .and_then(|cg| fs::read_to_string(cg.join("cgroup.freeze")).ok())
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

/// A box's current memory usage (bytes), from its (dedicated) cgroup `memory.current`. `None` if
/// the box has no dedicated cgroup (see [`box_cgroup`]) — shown as `-` rather than a wrong number.
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

/// Write the entry. Returns the file path (so the supervisor can remove it on exit).
pub fn register(inst: &Instance) -> io::Result<PathBuf> {
    let path = dir()?.join(format!("{}-{}", inst.name, inst.pid));
    let body = format!(
        "name={}\npid={}\npid1={}\nrootfs={}\ncommand={}\nstarted={}\nstarttime={}\nports={}\nvolumes={}\n",
        inst.name,
        inst.pid,
        inst.pid1,
        one_line(&inst.rootfs),
        one_line(&inst.command),
        inst.started,
        inst.starttime,
        one_line(&inst.ports),
        one_line(&inst.volumes),
    );
    fs::write(&path, body)?;
    Ok(path)
}

/// Remove an entry (best-effort).
pub fn unregister(path: &Path) {
    let _ = fs::remove_file(path);
}

/// A real entry is well under 1 KiB; only read a bounded prefix so a same-user process can't wedge
/// `list()` (which `kern ps`/`volume rm`/`stop` all call) with a multi-gigabyte junk file.
const MAX_ENTRY_BYTES: u64 = 64 * 1024;

/// Is this a well-formed registry filename (`<name>-<pid>`, pid all digits)? Skips anything else a
/// same-user process dropped in the dir, so junk files aren't parsed. NOTE: we deliberately do NOT
/// cap the *number* of entries — a cap could push a real box's entry out of view and let its
/// in-use volume be deleted (fail-open). Reading many small files stays O(n) but bounded per file.
fn well_formed_entry(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .and_then(|s| s.rsplit_once('-'))
        .is_some_and(|(n, pid)| {
            !n.is_empty() && !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit())
        })
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
        let path = e.path();
        let Some(body) = read_entry_capped(&path) else {
            continue;
        };
        match parse(&body) {
            Some(inst) if is_alive(inst.pid, inst.starttime) => out.push(inst),
            // Unparseable or dead → prune.
            _ => unregister(&path),
        }
    }
    out.sort_by_key(|i| i.started);
    out
}

/// The set of named volumes any running box currently mounts (for `volume prune`'s in-use guard).
pub fn volumes_in_use() -> std::collections::HashSet<String> {
    list()
        .iter()
        .flat_map(|b| b.volume_names().map(str::to_string))
        .collect()
}

/// Is this our live box supervisor? It must exist (`kill(pid,0)==0`; `EPERM` = another user's
/// pid → gone) AND its kernel start-time must match what we recorded — so a reused pid (a
/// different process that happens to have the same number) is correctly seen as gone.
fn is_alive(pid: i32, starttime: u64) -> bool {
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    starttime == 0 || proc_starttime(pid) == starttime
}

/// The fields of `/proc/<pid>/stat` *after* the `comm` field — i.e. the slice past the last `)`.
/// `comm` can contain spaces and parens, so this is the only safe split point; post-`)` tokens
/// start at field 3 (state), so field N is `nth(N - 3)`.
fn stat_after_comm(stat: &str) -> Option<&str> {
    stat.rfind(')').map(|rp| &stat[rp + 1..])
}

/// The sole child of `ppid` (a box supervisor forks exactly one child — PID 1 of the box), found
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
/// sidecars outlive it — those accumulate. This removes any log/health file whose `<name>-<pid>`
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
        // after our `list()` snapshot (a start racing this prune) — leave its sidecar alone. This is
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
    let mut volumes = String::new();
    for line in body.lines() {
        let (k, v) = line.split_once('=')?;
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
            _ => {}
        }
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_entry_accepts_our_files_rejects_junk() {
        use std::ffi::OsStr;
        // `<name>-<pid>` — names may contain `-` `.` `_`, pid is the trailing digits.
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

    #[test]
    fn is_paused_false_when_no_cgroup() {
        // An impossible pid has no /proc/<pid>/cgroup → no box cgroup → not paused (safe default,
        // so a box whose freeze state can't be read never shows a spurious "paused").
        assert!(!is_paused(i32::MAX));
    }

    #[test]
    fn parse_reads_volumes_and_tolerates_older_entries() {
        // A full entry round-trips the volumes field.
        let full = "name=web\npid=42\npid1=7\nrootfs=/r\ncommand=sh\nstarted=1\nstarttime=2\nports=\nvolumes=data,cache\n";
        let i = parse(full).unwrap();
        assert_eq!(i.name, "web");
        assert_eq!(i.volumes, "data,cache");
        // An OLDER entry with no `volumes=` line still parses (field defaults to empty).
        let old = "name=web\npid=42\nrootfs=/r\ncommand=sh\nstarted=1\nstarttime=2\nports=\n";
        assert_eq!(parse(old).unwrap().volumes, "");
    }
}
