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
    /// Comma-separated **named volumes** this box mounts (from `-v name:/dst`) — so `kern volume rm`
    /// can refuse to delete a volume still in use. Empty when none; absent in older entries.
    pub volumes: String,
    /// The **pod** (`--pod <name>`, e.g. a compose stack) this box belongs to — the grouping key for
    /// `kern ps`'s tree view and `kern stop <pod>`. Empty for a standalone box; absent in older entries.
    pub pod: String,
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

/// The exit directory — a sidecar per box that has RUN TO COMPLETION, holding its `<code>` as decimal
/// text. Written by the detached supervisor when a box's main process exits for good (no `--restart`
/// left). Consumed by `kern compose`'s `depends_completed` (Docker's `service_completed_successfully`):
/// the box has left `list()`, and this tells us whether it finished cleanly (0) or failed.
///
/// The sidecar filename is an opaque compose-supplied KEY that encodes BOTH the stack AND the `up`
/// epoch: `<pod>-<token>-<name>` (adversarial review, rounds 1-2):
///  * **`<pod>`** namespaces by stack, so two different stacks that each contain a `db` never collide
///    on one `exit/db` — one stack could otherwise read the OTHER's `db` exit.
///  * **`<token>`** (a fresh per-`up` epoch) namespaces by RUN. This is the round-2 fix: with the
///    token only INSIDE the file, two concurrent `up`s of the same stack shared the filename, so one
///    `up`'s `clear`-before-spawn would DELETE the other's real completion — a healthy stack failing
///    because a peer `up` wiped its state, not fail-closed. With the token in the KEY, each run owns
///    its own files; a concurrent run's clear/write can't touch them. Isolation is structural.
///
/// Because a separate `down` invocation doesn't know the `up`'s token, it reaps each box's sidecar by
/// pod-prefix AND box-name-suffix (`<pod>-*-<name>`, see `clear_exit_matching`) — NOT a blind `<pod>-`
/// prefix, which would delete a concurrent same-stack run's in-flight files. Kept SEPARATE from
/// `instances/` so `list()` never mistakes it for a live box. The runtime dir is NOT in a box's mount
/// namespace (verified), so a workload can't forge another service's exit.
fn exit_dir() -> io::Result<PathBuf> {
    runtime_subdir("exit")
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
/// belongs to THIS run — no separate token check needed. `Some(0)` = finished successfully.
pub fn exit_of(key: &str) -> Option<i32> {
    exit_dir()
        .ok()
        .and_then(|d| fs::read_to_string(d.join(key)).ok())
        .and_then(|s| s.trim().parse().ok())
}

/// Remove a box's exit sidecar for the exact `key` — compose calls this BEFORE (re)launching the box.
/// Best-effort.
pub fn clear_exit(key: &str) {
    if let Ok(d) = exit_dir() {
        let _ = fs::remove_file(d.join(key));
    }
}

/// Remove every exit sidecar whose filename starts with `prefix` (compose passes `<pod>-`). Used by
/// `compose down`, which — being a separate invocation — doesn't know the `up`'s token and so can't
/// name the exact per-run key. Reaping is scoped to BOTH ends — `<prefix>…<suffix>` — so `compose
/// down` clears `<pod>-<*any-token*>-<name>` only for the box `<name>` it is actually stopping. A
/// blind `<pod>-` prefix would ALSO delete `<pod>-<otherToken>-<name>` of a DIFFERENT run of the same
/// stack that is still in flight — re-opening, from the GC side, the exact cross-run deletion the
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
        "name={}\npid={}\npid1={}\nrootfs={}\ncommand={}\nstarted={}\nstarttime={}\nports={}\nvolumes={}\npod={}\n",
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

/// The `<name>` of a well-formed `<name>-<pid>` entry filename (name non-empty, pid all digits), else
/// `None`. The SOLE decoder of the on-disk key grammar (paired with `register`'s `format!("{name}-{pid}")`
/// encoder) — so `well_formed_entry` and `find`'s filename pre-filter can't drift on what a valid entry
/// is (they had already diverged: one required a non-empty name, the other didn't).
fn entry_name(fname: &std::ffi::OsStr) -> Option<&str> {
    let (n, pid) = fname.to_str()?.rsplit_once('-')?;
    (!n.is_empty() && !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit())).then_some(n)
}

/// Is this a well-formed registry filename (`<name>-<pid>`, pid all digits)? Skips anything else a
/// same-user process dropped in the dir, so junk files aren't parsed. NOTE: we deliberately do NOT
/// cap the *number* of entries — a cap could push a real box's entry out of view and let its
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

/// Load the registry entry at `path` if it is a LIVE box, pruning a dead/unparseable one as a side
/// effect (never a live one). The single entry-loading rule — [`list`] and [`find`] both go through
/// here, so the capped read, the parse, the liveness gate and the prune can't drift between them.
fn load_live(path: &Path) -> Option<Instance> {
    match read_entry_capped(path).and_then(|b| parse(&b)) {
        Some(inst) if is_alive(inst.pid, inst.starttime) => Some(inst),
        _ => {
            unregister(path);
            None
        }
    }
}

/// The LIVE box named `name`, or `None`. The targeted-lookup primitive: unlike [`list`], it opens and
/// `/proc`-stats ONLY the entry whose FILENAME (`<name>-<pid>`) matches `name` — every OTHER running box
/// costs nothing but its dirent. This is what keeps by-name commands (start name-check, `exec`, `stop`,
/// `attach`, health polls…) O(1) in file I/O regardless of how many boxes run: routing them through
/// `list()` made each call O(running boxes) (open + parse + `kill` + read `/proc/<pid>/stat` for EVERY
/// box) — measured super-linear (3 ms idle → 19 ms at 100 live boxes), and O(N²) for a per-box health
/// checker polling forever. Prunes a dead same-name entry as a side effect (name reusable after a crash),
/// never a live one.
pub fn find(name: &str) -> Option<Instance> {
    let d = dir().ok()?;
    for e in fs::read_dir(&d).ok()?.flatten() {
        // Match on the `<name>-<pid>` FILENAME (one grammar decoder, shared with `well_formed_entry`)
        // WITHOUT opening the file, so a non-matching box — the common case at scale — costs only its
        // dirent, never an open/`/proc` stat.
        let fname = e.file_name();
        if entry_name(&fname) != Some(name) {
            continue;
        }
        // A filename match — confirm it's actually a LIVE box named `name` (body `name=` is authoritative,
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
/// the tracked box — the watchdog would never fire / attach would report a live box as exited.
/// Opens exactly one file; never prunes.
pub fn pair_alive(name: &str, pid: i32) -> bool {
    let Ok(d) = dir() else { return false };
    read_entry_capped(&d.join(format!("{name}-{pid}")))
        .and_then(|b| parse(&b))
        .is_some_and(|i| i.name == name && i.pid == pid && is_alive(i.pid, i.starttime))
}

/// Is a LIVE box already named `name`? Thin wrapper over [`find`] — the box-start hot-path name-check.
pub fn name_taken(name: &str) -> bool {
    find(name).is_some()
}

/// Resolve a box by a user-supplied reference: its NAME, or — as a fallback — its supervisor PID as
/// shown in `kern ps` (Docker-style ref-or-name for the live commands: `stop`/`exec`/`logs`/…).
/// NAME WINS: a box literally named "79" resolves before a box whose pid is 79, so an all-digit box
/// name is never shadowed by a coincidental pid. The pid branch runs ONLY when the ref is a plain
/// positive integer AND is not a live box name, and scans the (small) registry once. Caveat: a pid is
/// a LIVE handle only — reused by the OS, changed by `--restart` — so the NAME stays the stable identity.
pub fn find_ref(x: &str) -> Option<Instance> {
    if let Some(inst) = find(x) {
        return Some(inst); // a live box named `x` — name wins
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

/// The claims directory — one `<name>` file per IN-FLIGHT box start (see [`claim_name`]).
fn claims_dir() -> io::Result<PathBuf> {
    runtime_subdir("claims")
}

/// Take the claims-dir advisory lock (`flock`; the kernel releases it with the process, so it can't
/// leak). ALL claim mutation — take, stale takeover, prune — happens under it, so two starters that
/// both see the same stale claim can't both "take it over" (one would silently delete the other's
/// fresh claim). Held for a handful of syscalls; contention cost is microseconds against a ~3 ms
/// box start. Retries `EINTR`: a signal landing while blocked on a contended lock must not surface
/// as "no usable runtime dir" — the caller would fail-open UNCLAIMED, quietly disabling the very
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
/// A claim leaked by a crash is stale the moment its pid dies — the next same-name start takes it
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

/// Atomically claim `name` for an in-flight box start — the other half of the start name-check.
/// [`name_taken`] sees a box only once it's REGISTERED, so two concurrent same-name starts could
/// both pass it and both come up (check-then-register TOCTOU). The claim closes that window:
///
/// * `Ok(Some(_))` — this process owns the name; hold the claim until the box is registered (the
///   registry entry is authoritative from then on), then drop it.
/// * `Ok(None)` — the name is taken: a LIVE process holds the claim (already starting), or a live
///   box is already REGISTERED under it. The registry re-check happens HERE, under the lock, so
///   name reservation is atomic-by-construction for every caller — a second start path that only
///   calls `claim_name` cannot silently reintroduce the race.
/// * `Err(_)` — no usable runtime dir. The registry itself is equally unavailable then, so callers
///   proceed unclaimed (fail-open, exactly like `name_taken`).
///
/// A claim is a `<pid> <starttime>` file judged by the registry's own [`is_alive`] rule, and the
/// whole check-and-take runs under the dir-wide flock — a stale claim (starter crashed before
/// registering) is taken over exactly once, never raced.
pub fn claim_name(name: &str) -> io::Result<Option<NameClaim>> {
    let d = claims_dir()?;
    let _lock = lock_claims(&d)?;
    let path = d.join(name);
    if let Ok(body) = fs::read_to_string(&path) {
        if live_claim(&body) {
            return Ok(None); // live claimant → name busy
        }
        // Dead claimant or malformed body → stale; fall through and take it over (we hold the lock).
    }
    // A box that REGISTERED before we locked is invisible to the claim file (its starter already
    // released the claim after registering) — the registry entry is authoritative from that point.
    if name_taken(name) {
        return Ok(None);
    }
    let pid = std::process::id();
    fs::write(&path, format!("{pid} {}\n", proc_starttime(pid as i32)))?;
    Ok(Some(NameClaim { path, owner: pid }))
}

/// Is this claim body a LIVE claimant's? The single staleness rule — [`claim_name`]'s takeover and
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
/// pid → gone) AND — when both start-times are known — its kernel start-time must match what we
/// recorded, so a reused pid (a different process that happens to have the same number) is seen as
/// gone. The start-time check is an ANTI-REUSE refinement layered on the existence proof, NOT a
/// second liveness test: if we recorded no start-time (`starttime == 0`) OR the live read comes back
/// empty (`proc_starttime` returns 0 — a transient `/proc` read failure: `open` hitting `EMFILE`
/// under heavy parallel fd pressure, a stat hiccup during namespace churn), we fall back to the
/// `kill(0)` proof rather than declaring a demonstrably-existing process dead. Pruning a live box's
/// entry on a momentary read failure is fail-DANGEROUS — it would drop a running box from `ps`/
/// `stop` and let `volume prune` delete a volume it still mounts. Pid-reuse is still caught whenever
/// the live read succeeds (the overwhelmingly common case).
fn is_alive(pid: i32, starttime: u64) -> bool {
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    let live = proc_starttime(pid);
    starttime == 0 || live == 0 || live == starttime
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
                        continue; // `.lock` — never a claim (BoxName forbids a leading '.')
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
    let (mut volumes, mut pod) = (String::new(), String::new());
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
            "pod" => pod = v.to_string(),
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
        pod,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Registry-mutating tests all share ONE process-wide instances dir AND one pid
    // (`std::process::id()`), so a pid-keyed `find_ref` in one test can observe a box another test
    // registered under the same pid. Serialize them through this lock so each runs without a
    // concurrent same-pid registration racing it. (No dir wipe: a stale entry from a prior run is
    // inert — its pid belongs to a now-dead process, so `is_alive` skips it — and a developer's real
    // running boxes have different pids and are never touched.)
    static REG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn reg_guard() -> std::sync::MutexGuard<'static, ()> {
        REG_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

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
    fn exit_key_bracketed_matches_pod_and_name_across_tokens() {
        // `compose down` reaps `<pod>-<*any token*>-<name>` for a box it stops. It must match every
        // token of THAT box, and NOT a different box of the same stack (the concurrent-run leak the
        // final review flagged).
        let p = "myapp-"; // pod prefix
        let s = "-migrate"; // -<name>
        assert!(exit_key_bracketed("myapp-tokenA-migrate", p, s));
        assert!(exit_key_bracketed("myapp-99-123456789-migrate", p, s)); // real token shape
                                                                         // A DIFFERENT box of the same stack must NOT match — this is the fix.
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
            })
            .unwrap()
        };
        let uniq = format!("fr-{pid}");
        let p1 = mk(&uniq, pid);
        // by NAME: resolves to exactly our box (unique name — deterministic).
        assert_eq!(find_ref(&uniq).map(|i| i.name), Some(uniq.clone()));
        // by PID: a numeric ref resolves via the pid branch to a LIVE box with this pid. Under the
        // test harness every test shares THIS process's pid, so a concurrent test's box may be the one
        // returned — assert the resolved box carries the queried pid, not that it's our exact name.
        // (The name-resolution and name-wins properties below use unique names and stay exact.)
        assert_eq!(find_ref(&pid.to_string()).map(|i| i.pid), Some(pid));
        // an unknown name and a non-existent pid both miss.
        assert!(find_ref("no-such-box-xyz").is_none());
        assert!(find_ref("2147483647").is_none()); // i32::MAX — no such pid
                                                   // NAME WINS: a box literally named after a NUMBER resolves by that NAME (via `find`), never
                                                   // via the pid branch — so a numeric name can't be shadowed by a coincidental pid.
        let numname = format!("{}", pid.wrapping_add(1)); // a name that looks like a (different) pid
        let p2 = mk(&numname, pid);
        assert_eq!(find_ref(&numname).map(|i| i.name), Some(numname.clone()));
        unregister(&p1);
        unregister(&p2);
    }

    #[test]
    fn claim_name_refuses_a_live_registered_box() {
        let _g = reg_guard();
        // The registry re-check lives INSIDE claim_name (under its lock): a box that registered and
        // released its claim must still make a fresh claim fail — for EVERY caller, by construction.
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
        // The E5 race: N concurrent starts of the SAME name — exactly one may win. Threads each
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
    fn parse_reads_volumes_and_tolerates_older_entries() {
        let _g = reg_guard();
        // A full entry round-trips the volumes and pod fields.
        let full = "name=web\npid=42\npid1=7\nrootfs=/r\ncommand=sh\nstarted=1\nstarttime=2\nports=\nvolumes=data,cache\npod=myapp\n";
        let i = parse(full).unwrap();
        assert_eq!(i.name, "web");
        assert_eq!(i.volumes, "data,cache");
        assert_eq!(i.pod, "myapp");
        // An OLDER entry with no `volumes=`/`pod=` line still parses (fields default to empty) — the
        // wire format is append-only, so a box registered by a previous kern version is never dropped.
        let old = "name=web\npid=42\nrootfs=/r\ncommand=sh\nstarted=1\nstarttime=2\nports=\n";
        let oi = parse(old).unwrap();
        assert_eq!(oi.volumes, "");
        assert_eq!(oi.pod, "");
    }
}
