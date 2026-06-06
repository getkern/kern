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
}

/// The instances directory (one file per running box), created on demand.
pub fn dir() -> io::Result<PathBuf> {
    runtime_subdir("instances")
}

/// The logs directory (one `<name>-<pid>.log` per detached box), created on demand.
pub fn logs_dir() -> io::Result<PathBuf> {
    runtime_subdir("logs")
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
    let mut last_err = io::Error::other("no writable runtime dir");
    for d in candidates {
        match fs::create_dir_all(&d) {
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

/// The box's **dedicated** cgroup, or `None` if it doesn't have one. A box gets its own cgroup
/// only when it ran inside a `systemd-run --user --scope`; without one (no systemd-user) its
/// processes live in the shared session cgroup — the same one `kern` itself runs in — and
/// `memory.current` there reflects the whole session, not the box. We detect that by comparing
/// the box's cgroup to our own: if they match, the reading isn't box-specific, so we report none
/// rather than a misleading session-wide number.
fn box_cgroup(pid: i32) -> Option<PathBuf> {
    let cg = cgroup_of(pid)?;
    if cgroup_of(unsafe { libc::getpid() }) == Some(cg.clone()) {
        return None;
    }
    Some(cg)
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
        "name={}\npid={}\npid1={}\nrootfs={}\ncommand={}\nstarted={}\nstarttime={}\nports={}\n",
        inst.name,
        inst.pid,
        inst.pid1,
        one_line(&inst.rootfs),
        one_line(&inst.command),
        inst.started,
        inst.starttime,
        one_line(&inst.ports),
    );
    fs::write(&path, body)?;
    Ok(path)
}

/// Remove an entry (best-effort).
pub fn unregister(path: &Path) {
    let _ = fs::remove_file(path);
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
        let path = e.path();
        let Ok(body) = fs::read_to_string(&path) else {
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

fn parse(body: &str) -> Option<Instance> {
    let (mut name, mut pid) = (None, None);
    let (mut rootfs, mut command, mut ports) = (String::new(), String::new(), String::new());
    let (mut pid1, mut started, mut starttime) = (0i32, 0u64, 0u64);
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
    })
}
