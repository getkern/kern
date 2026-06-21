//! Build history — a daemonless record of past `kern build` invocations, the kern analogue of Docker
//! Desktop's "Builds" panel (`docker buildx history`). Each `kern build` writes one flat `key=value`
//! record under `$XDG_DATA_HOME/kern/builds/<id>/meta` (persistent across reboot — unlike the runtime
//! box registry in [`crate::registry`], which lives on tmpfs and is deliberately wiped), plus an
//! optional `log` transcript of the build's step lines. `kern builds` lists them; `kern build
//! logs|inspect|rm|prune` manage them.
//!
//! No daemon and no lock: records are append-only and each build owns its own `<id>` directory, so
//! there is no shared-name uniqueness constraint (the box registry needs `flock` only because box
//! *names* must be unique; a build id can't collide — it embeds the pid). Free-text fields are
//! newline-collapsed on write so a crafted tag/path can't forge extra record lines.

use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

/// A build's outcome. Serialized to the record as a lowercase word; unknown/older values read back as
/// [`Status::Running`] (an in-flight or truncated record).
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum Status {
    /// Record pre-written at build start; overwritten on completion. If it survives as `running`, the
    /// build was killed mid-flight (SIGINT/SIGKILL) before it could finalize — shown as `interrupted`.
    #[default]
    Running,
    Ok,
    Warn,
    Failed,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Running => "running",
            Status::Ok => "ok",
            Status::Warn => "warn",
            Status::Failed => "failed",
        }
    }
    fn parse(s: &str) -> Status {
        match s {
            "ok" => Status::Ok,
            "warn" => Status::Warn,
            "failed" => Status::Failed,
            _ => Status::Running,
        }
    }
    /// Human label for `kern builds` / `inspect`. A lingering `running` record is a build that never
    /// finished, so it reads as `interrupted` rather than pretending it's still going.
    pub fn label(self) -> &'static str {
        match self {
            Status::Running => "interrupted",
            Status::Ok => "ok",
            Status::Warn => "warn",
            Status::Failed => "failed",
        }
    }

    /// Parse a `--status <s>` filter value (accepts the labels shown by `kern builds`). `None` for an
    /// unknown word so the caller can reject it with a usage error.
    pub fn from_label(s: &str) -> Option<Status> {
        match s {
            "ok" => Some(Status::Ok),
            "warn" => Some(Status::Warn),
            "failed" | "fail" => Some(Status::Failed),
            "running" | "interrupted" => Some(Status::Running),
            _ => None,
        }
    }
}

/// One past (or in-flight) build.
#[derive(Clone, Default, Debug)]
pub struct Record {
    /// `<started_unix>-<pid>` — a single safe path component (validated on every read).
    pub id: String,
    /// The `-t` tag the image was built under.
    pub tag: String,
    /// Dockerfile path used.
    pub dockerfile: String,
    /// Build context directory.
    pub context: String,
    /// Build start, Unix seconds.
    pub started: u64,
    /// Wall-clock build time in milliseconds (0 until finalized).
    pub duration_ms: u64,
    pub status: Status,
    /// Number of Dockerfile lint warnings (drives the `warn` status).
    pub warnings: u32,
    /// Resulting image size in bytes (0 if the build failed or size is unknown).
    pub size: u64,
    /// Failure message (empty on success).
    pub error: String,
}

/// Root directory holding all build records. Mirrors [`crate::volume::volumes_dir`] — persistent user
/// data under `$XDG_DATA_HOME/kern/builds` (fallback `~/.local/share/kern/builds`, then a `/tmp`
/// last resort), NOT the tmpfs runtime dir.
pub fn builds_dir() -> PathBuf {
    if let Some(x) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(x).join("kern").join("builds");
    }
    if let Some(h) = std::env::var_os("HOME") {
        return PathBuf::from(h).join(".local/share/kern/builds");
    }
    PathBuf::from(format!("/tmp/kern-builds-{}", unsafe { libc::getuid() }))
}

/// A build id (`<name>` of a `builds/<name>` dir) that is a safe single path component. Reuses the
/// shared resource-name rule so a crafted id can never climb out of `builds/` on `rm`/`inspect`.
pub fn valid_id(id: &str) -> bool {
    kern_common::valid_resource_name(id)
}

/// Mint the id for a build starting at `started` in process `pid`. Digits + one `-` → always a valid
/// single path component; the pid disambiguates concurrent builds in the same second.
pub fn new_id(started: u64, pid: u32) -> String {
    format!("{started}-{pid}")
}

/// Collapse newlines so one free-text field stays on its own record line (same guard as the box
/// registry's `one_line`) — a tag or path containing `\n` can't forge extra `key=value` lines.
fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

fn record_dir(id: &str) -> PathBuf {
    builds_dir().join(id)
}

/// Create `dir` (and parents) 0700 — build transcripts can contain whatever a `RUN` step printed
/// (potentially build-time secrets), so keep the tree owner-only, not umask-default.
fn mkdir_private(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// Open a record file for writing, 0600 and refusing to follow a symlink at the final component — the
/// single "private, no-symlink" open every record writer uses. `append` = append (create if absent)
/// vs create+truncate. O_NOFOLLOW means a planted `meta`/`log` symlink can't redirect the write.
fn open_private(path: &Path, append: bool) -> io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.mode(0o600).custom_flags(libc::O_NOFOLLOW).create(true);
    if append {
        o.append(true);
    } else {
        o.write(true).truncate(true);
    }
    o.open(path)
}

/// The transcript log path for build `id`.
pub fn log_path(id: &str) -> PathBuf {
    record_dir(id).join("log")
}

/// Write (or overwrite) the record's `meta` file. Called once at build start (status `running`) and
/// again at completion with the final status/duration/size.
pub fn write(rec: &Record) -> io::Result<()> {
    if !valid_id(&rec.id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid build id",
        ));
    }
    let dir = record_dir(&rec.id);
    mkdir_private(&dir)?;
    let mut body = String::new();
    // Append-only wire format: readers tolerate missing keys, so new fields never break old records.
    let _ = write!(
        body,
        "id={}\ntag={}\ndockerfile={}\ncontext={}\nstarted={}\nduration_ms={}\nstatus={}\nwarnings={}\nsize={}\nerror={}\n",
        rec.id,
        one_line(&rec.tag),
        one_line(&rec.dockerfile),
        one_line(&rec.context),
        rec.started,
        rec.duration_ms,
        rec.status.as_str(),
        rec.warnings,
        rec.size,
        one_line(&rec.error),
    );
    // Write a temp then rename over `meta` — the swap is atomic, so a crash mid-finalize can't leave a
    // truncated/0-byte record: the pre-written `running`/`interrupted` trace survives until the new meta
    // is complete. O_NOFOLLOW on the temp refuses writing THROUGH a planted symlink; `rename` onto `meta`
    // replaces a symlinked `meta` itself (never clobbers through it), so both writes stay confined.
    let tmp = dir.join("meta.tmp");
    open_private(&tmp, false)?.write_all(body.as_bytes())?;
    std::fs::rename(&tmp, dir.join("meta"))
}

/// A real record is tiny; bound the read so a planted giant `meta` can't wedge `list()`.
const MAX_META_BYTES: u64 = 64 * 1024;

fn parse(body: &str) -> Option<Record> {
    let mut r = Record::default();
    let mut have_id = false;
    for line in body.lines() {
        // Skip (don't abort on) a line without '=' — a blank line, a truncated tail from the read cap,
        // or stray junk must not discard an otherwise-valid record. Only a present, valid `id=` matters.
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "id" => {
                r.id = v.to_string();
                have_id = true;
            }
            "tag" => r.tag = v.to_string(),
            "dockerfile" => r.dockerfile = v.to_string(),
            "context" => r.context = v.to_string(),
            "started" => r.started = v.parse().unwrap_or(0),
            "duration_ms" => r.duration_ms = v.parse().unwrap_or(0),
            "status" => r.status = Status::parse(v),
            "warnings" => r.warnings = v.parse().unwrap_or(0),
            "size" => r.size = v.parse().unwrap_or(0),
            "error" => r.error = v.to_string(),
            _ => {}
        }
    }
    (have_id && valid_id(&r.id)).then_some(r)
}

/// Read one record by id, or `None` if absent/unreadable/malformed.
pub fn get(id: &str) -> Option<Record> {
    if !valid_id(id) {
        return None;
    }
    let body = read_capped(&record_dir(id).join("meta"))?;
    parse(&body)
}

fn read_capped(path: &Path) -> Option<String> {
    read_nofollow(path, MAX_META_BYTES)
}

/// Read at most `max` bytes of `path`, refusing to follow a symlink at the final component
/// (`O_NOFOLLOW`) — a planted `meta`/`log` symlink can't turn a record read into an arbitrary
/// file read. `from_utf8_lossy` so a binary file symlinked in still can't produce invalid UTF-8.
fn read_nofollow(path: &Path, max: u64) -> Option<String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?
        .take(max)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Read a build's captured transcript (symlink-refusing, capped), or `None` if absent/unreadable.
pub fn read_log(id: &str) -> Option<String> {
    if !valid_id(id) {
        return None;
    }
    read_nofollow(&log_path(id), MAX_LOG_BYTES)
}

/// All build records, newest first (by `started`, then id).
pub fn list() -> Vec<Record> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(builds_dir()) {
        for e in entries.flatten() {
            let Some(name) = e.file_name().to_str().map(String::from) else {
                continue;
            };
            if !valid_id(&name) {
                continue; // skip anything that isn't a well-formed record dir
            }
            if let Some(body) = read_capped(&e.path().join("meta")) {
                if let Some(r) = parse(&body) {
                    out.push(r);
                }
            }
        }
    }
    out.sort_by(|a, b| b.started.cmp(&a.started).then_with(|| b.id.cmp(&a.id)));
    out
}

/// The record ids (dir names) newest-first, WITHOUT opening any `meta`. An id is `<started_unix>-<pid>`
/// and `started` is a fixed-width 10-digit stamp for every real record, so a descending string sort is
/// newest-first — letting `query`/`prune` avoid the O(N) meta reads `list()` does when they only need
/// the newest few. (The full/filtered path still uses `list()`'s exact `started` sort.)
fn record_ids_newest_first() -> Vec<String> {
    let mut ids: Vec<String> = match std::fs::read_dir(builds_dir()) {
        Ok(rd) => rd
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .filter(|n| valid_id(n))
            .collect(),
        Err(_) => Vec::new(),
    };
    ids.sort_unstable_by(|a, b| b.cmp(a));
    ids
}

/// Records for a `kern builds` query, reading only what's needed. A bare `-n N` (no tag/status filter)
/// reads just the N newest `meta` files — not the whole history — since ids sort newest-first without a
/// read. Any tag/status filter must read all records (those fields live in the meta), so it falls back
/// to `list()`.
pub fn query(tag: Option<&str>, status: Option<Status>, limit: Option<usize>) -> Vec<Record> {
    if tag.is_none() && status.is_none() {
        if let Some(n) = limit {
            return record_ids_newest_first()
                .into_iter()
                .take(n)
                .filter_map(|id| get(&id))
                .collect();
        }
    }
    filter_builds(list(), tag, status, limit)
}

/// Apply the `kern builds` query to an already-newest-first list: keep records whose tag CONTAINS
/// `tag` (if given) and whose status equals `status` (if given), then cap to the `limit` newest. Pure,
/// so the filter/limit/status logic is unit-tested without the filesystem.
pub fn filter_builds(
    recs: Vec<Record>,
    tag: Option<&str>,
    status: Option<Status>,
    limit: Option<usize>,
) -> Vec<Record> {
    recs.into_iter()
        .filter(|r| tag.is_none_or(|t| r.tag.contains(t)))
        .filter(|r| status.is_none_or(|s| r.status == s))
        .take(limit.unwrap_or(usize::MAX))
        .collect()
}

/// Delete one build record (and its log). Returns whether it existed.
pub fn remove(id: &str) -> bool {
    if !valid_id(id) {
        return false;
    }
    let dir = record_dir(id);
    let existed = dir.is_dir();
    let _ = std::fs::remove_dir_all(&dir);
    existed
}

/// Keep the `keep` newest records, delete the rest. Returns how many were removed. Build records have
/// no liveness (a build is a past event), so retention is count-based, not "is it still running".
/// Uses the name-only newest-first order so pruning a large history doesn't open every `meta` first.
pub fn prune(keep: usize) -> usize {
    let mut removed = 0;
    for id in record_ids_newest_first().into_iter().skip(keep) {
        if remove(&id) {
            removed += 1;
        }
    }
    removed
}

// ── Transcript capture ────────────────────────────────────────────────────────────────────────────
//
// A build prints its step lines (and each RUN box's output) to stderr. To persist that for `kern build
// logs <id>` without threading a writer through every build function, [`Capture`] redirects this
// process's fd 2 into the build's `log` file for the build's lifetime, teed LIVE back to the real
// stderr so the user still sees the build. Child RUN boxes inherit the redirected fd 2, so their
// stderr is captured too. On drop, stderr is restored and the reader thread drains and exits. stdout
// (fd 1) is untouched, so `kern build ... | …` piping and the final `built '<tag>'` line are unchanged.

/// Cap the captured transcript so a pathological build can't grow an unbounded log.
const MAX_LOG_BYTES: u64 = 1024 * 1024;

/// RAII stderr→log tee. `start` returns `None` (build proceeds uncaptured) if the pipe/dup fails — a
/// logging problem must never fail a build.
pub struct Capture {
    saved_err: i32,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Capture {
    pub fn start(id: &str) -> Option<Capture> {
        if !valid_id(id) {
            return None;
        }
        let dir = record_dir(id);
        mkdir_private(&dir).ok()?;
        let mut logf = open_private(&dir.join("log"), false).ok()?;
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return None;
        }
        let (rd, wr) = (fds[0], fds[1]);
        let saved_err = unsafe { libc::dup(2) };
        if saved_err < 0 {
            unsafe {
                libc::close(rd);
                libc::close(wr);
            }
            return None;
        }
        // Point fd 2 at the pipe write end, then drop the spare write fd — now only fd 2 (and any child
        // that inherits it) holds the write end, so restoring fd 2 later yields a clean EOF.
        unsafe {
            libc::dup2(wr, 2);
            libc::close(wr);
        }
        let thread = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut written: u64 = 0;
            loop {
                let n = unsafe { libc::read(rd, buf.as_mut_ptr().cast(), buf.len()) };
                if n <= 0 {
                    break; // EOF (all write ends closed) or error
                }
                let n = n as usize;
                // Tee live to the real stderr so the build stays visible.
                unsafe { libc::write(saved_err, buf.as_ptr().cast(), n) };
                if written < MAX_LOG_BYTES {
                    let _ = logf.write_all(&buf[..n]);
                    written += n as u64;
                }
            }
            unsafe { libc::close(rd) };
        });
        Some(Capture {
            saved_err,
            thread: Some(thread),
        })
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        // Restore fd 2 → the last pipe-write ref is gone → the reader thread hits EOF and exits.
        unsafe { libc::dup2(self.saved_err, 2) };
        // Join BEFORE closing `saved_err`: the pipe may still hold up to a buffer of stderr the reader
        // must drain and tee to the terminal; closing first would make that final `write(saved_err,…)`
        // hit a closed fd (and, in theory, a reused one). Close only once the reader has finished.
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        unsafe { libc::close(self.saved_err) };
    }
}

/// Append one line to a build's `log` (used for the final summary line, written after capture ends).
pub fn append_log(id: &str, msg: &str) {
    if !valid_id(id) {
        return;
    }
    if let Ok(mut f) = open_private(&log_path(id), true) {
        let _ = writeln!(f, "{msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // XDG_DATA_HOME is process-global; the CRATE-WIDE lock serializes this against every other module's
    // env-mutating tests (e.g. `volume`), which also repoint XDG_DATA_HOME.
    use crate::TEST_ENV_LOCK as ENV_LOCK;

    fn with_tmp_home<T>(f: impl FnOnce() -> T) -> T {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-builds-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::env::set_var("XDG_DATA_HOME", &tmp);
        let out = f();
        std::env::remove_var("XDG_DATA_HOME");
        let _ = std::fs::remove_dir_all(&tmp);
        out
    }

    fn rec(id: &str, started: u64, status: Status) -> Record {
        Record {
            id: id.to_string(),
            tag: "app:latest".into(),
            dockerfile: "Dockerfile".into(),
            context: ".".into(),
            started,
            duration_ms: 1200,
            status,
            warnings: 0,
            size: 4096,
            error: String::new(),
        }
    }

    #[test]
    fn write_read_roundtrip_and_status() {
        with_tmp_home(|| {
            let mut r = rec("100-7", 100, Status::Warn);
            r.warnings = 3;
            write(&r).unwrap();
            let got = get("100-7").unwrap();
            assert_eq!(got.tag, "app:latest");
            assert_eq!(got.warnings, 3);
            assert_eq!(got.status, Status::Warn);
            assert_eq!(got.duration_ms, 1200);
        });
    }

    #[test]
    fn parse_tolerates_older_records_missing_fields() {
        // A record from a future/older kern with only the mandatory id still parses; new fields default.
        let r = parse("id=1-2\ntag=x\nstarted=5\n").unwrap();
        assert_eq!(r.id, "1-2");
        assert_eq!(r.tag, "x");
        assert_eq!(r.warnings, 0);
        assert_eq!(r.status, Status::Running); // absent status → running/interrupted
                                               // No id → rejected.
        assert!(parse("tag=x\nstarted=5\n").is_none());
    }

    #[test]
    fn one_line_blocks_field_injection() {
        with_tmp_home(|| {
            // A tag containing a newline + a forged field must NOT create a second record field.
            let mut r = rec("200-9", 200, Status::Ok);
            r.tag = "evil\nsize=999999999".into();
            write(&r).unwrap();
            let got = get("200-9").unwrap();
            assert_eq!(got.size, 4096, "injected size must not take effect");
            assert!(got.tag.contains("size=999999999")); // it stayed part of the (collapsed) tag
        });
    }

    #[test]
    fn list_is_newest_first_and_prune_keeps_n() {
        with_tmp_home(|| {
            for (id, t) in [("1-1", 1u64), ("2-1", 2), ("3-1", 3), ("4-1", 4)] {
                write(&rec(id, t, Status::Ok)).unwrap();
            }
            let all = list();
            assert_eq!(all.len(), 4);
            assert_eq!(all[0].id, "4-1", "newest first");
            assert_eq!(all[3].id, "1-1");
            let removed = prune(2);
            assert_eq!(removed, 2);
            let kept = list();
            assert_eq!(kept.len(), 2);
            assert_eq!(kept[0].id, "4-1");
            assert_eq!(kept[1].id, "3-1"); // the two oldest (1-1, 2-1) were pruned
        });
    }

    #[test]
    fn filter_builds_by_tag_status_and_limit() {
        let recs = vec![
            Record {
                tag: "web-api".into(),
                status: Status::Ok,
                ..rec("5-1", 5, Status::Ok)
            },
            Record {
                tag: "web-ui".into(),
                status: Status::Warn,
                ..rec("4-1", 4, Status::Warn)
            },
            Record {
                tag: "db".into(),
                status: Status::Failed,
                ..rec("3-1", 3, Status::Failed)
            },
            Record {
                tag: "web-cron".into(),
                status: Status::Ok,
                ..rec("2-1", 2, Status::Ok)
            },
        ];
        // tag substring
        let web = filter_builds(recs.clone(), Some("web"), None, None);
        assert_eq!(web.len(), 3);
        assert!(web.iter().all(|r| r.tag.contains("web")));
        // status
        let ok = filter_builds(recs.clone(), None, Some(Status::Ok), None);
        assert_eq!(
            ok.iter().map(|r| r.tag.as_str()).collect::<Vec<_>>(),
            vec!["web-api", "web-cron"]
        );
        // tag AND status AND limit (newest-first order preserved → first match kept)
        let one = filter_builds(recs.clone(), Some("web"), Some(Status::Ok), Some(1));
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].tag, "web-api");
        // limit alone
        assert_eq!(filter_builds(recs.clone(), None, None, Some(2)).len(), 2);
        // no filters → identity
        assert_eq!(filter_builds(recs.clone(), None, None, None).len(), 4);
        // status label parsing (incl. interrupted == running)
        assert_eq!(Status::from_label("failed"), Some(Status::Failed));
        assert_eq!(Status::from_label("interrupted"), Some(Status::Running));
        assert_eq!(Status::from_label("bogus"), None);
    }

    #[test]
    fn query_limit_only_reads_newest_n_without_full_scan() {
        with_tmp_home(|| {
            for (id, t) in [("100-1", 100u64), ("200-1", 200), ("300-1", 300)] {
                write(&rec(id, t, Status::Ok)).unwrap();
            }
            // `-n 2` fast path: newest two, correct order, via name sort (no meta of 100-1 needed).
            let got = query(None, None, Some(2));
            assert_eq!(
                got.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
                vec!["300-1", "200-1"]
            );
            // a tag filter still finds the right record (falls back to the full read path).
            write(&Record {
                tag: "special".into(),
                ..rec("50-1", 50, Status::Ok)
            })
            .unwrap();
            let f = query(Some("special"), None, None);
            assert_eq!(f.len(), 1);
            assert_eq!(f[0].id, "50-1");
        });
    }

    #[test]
    fn append_log_and_read_log_roundtrip() {
        with_tmp_home(|| {
            write(&rec("30-1", 30, Status::Ok)).unwrap();
            append_log("30-1", "line one");
            append_log("30-1", "line two");
            let log = read_log("30-1").unwrap();
            assert!(
                log.contains("line one") && log.contains("line two"),
                "{log:?}"
            );
            // a build with no log yet → None, not a panic.
            write(&rec("31-1", 31, Status::Ok)).unwrap();
            assert!(read_log("31-1").is_none());
        });
    }

    #[test]
    fn write_is_atomic_no_stray_meta_tmp_on_success() {
        with_tmp_home(|| {
            write(&rec("32-1", 32, Status::Ok)).unwrap();
            // rename consumed the temp; only `meta` remains.
            assert!(builds_dir().join("32-1").join("meta").is_file());
            assert!(!builds_dir().join("32-1").join("meta.tmp").exists());
            // a second write (the finalize) still lands atomically and parses.
            write(&rec("32-1", 32, Status::Failed)).unwrap();
            assert_eq!(get("32-1").unwrap().status, Status::Failed);
        });
    }

    #[test]
    fn symlinked_meta_and_log_are_refused() {
        with_tmp_home(|| {
            // meta → symlink to an outside file: get() must refuse (O_NOFOLLOW → open fails), so a
            // planted symlink can't turn a record read into an arbitrary-file read.
            let dir = builds_dir().join("9-9");
            std::fs::create_dir_all(&dir).unwrap();
            std::os::unix::fs::symlink("/etc/hostname", dir.join("meta")).unwrap();
            assert!(get("9-9").is_none(), "symlinked meta must be refused");
            // legit meta + symlinked log: read_log must refuse the log.
            let dir2 = builds_dir().join("8-8");
            std::fs::create_dir_all(&dir2).unwrap();
            std::fs::write(dir2.join("meta"), "id=8-8\ntag=x\nstarted=1\nstatus=ok\n").unwrap();
            std::os::unix::fs::symlink("/etc/hostname", dir2.join("log")).unwrap();
            assert!(read_log("8-8").is_none(), "symlinked log must be refused");
        });
    }

    #[test]
    fn giant_meta_is_capped_not_unbounded() {
        with_tmp_home(|| {
            let dir = builds_dir().join("7-7");
            std::fs::create_dir_all(&dir).unwrap();
            let mut body = String::from("id=7-7\ntag=big\nstarted=1\nstatus=ok\n");
            body.push_str(&"junk=x\n".repeat(200_000)); // ~1.4 MB — well over the 64 KiB read cap
            std::fs::write(dir.join("meta"), &body).unwrap();
            // The bounded read sees the leading real fields; no OOM/hang on a planted giant file.
            let r = get("7-7").unwrap();
            assert_eq!(r.tag, "big");
        });
    }

    #[test]
    fn invalid_id_is_rejected_everywhere() {
        with_tmp_home(|| {
            assert!(!valid_id("../etc"));
            assert!(!valid_id(".hidden"));
            assert!(valid_id("1720-42"));
            // remove/get on a traversing id do nothing / return None.
            assert!(!remove("../etc"));
            assert!(get("../../x").is_none());
            let bad = Record {
                id: "../escape".into(),
                ..rec("x", 1, Status::Ok)
            };
            assert!(write(&bad).is_err());
        });
    }
}
