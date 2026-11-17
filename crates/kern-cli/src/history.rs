//! The box history: one line of METADATA per finished box, so a box that is gone can still be asked
//! about.
//!
//! WHY IT EXISTS. An SDK or MCP call is a box that lives milliseconds, and once it ended nothing on
//! the CLI could say it had run: `kern ps -a` kept a record only for a box that was stopped or killed,
//! `kern logs` has nothing for a foreground box, and the exit code that did survive (`137`) did not
//! say whether the kernel's OOM killer, kern's own `--timeout` or a `kern stop` ended it. MEASURED on
//! 2026-11-14: a successful `run_code` left no trace at all, a timed-out one left `exit 137` and
//! nothing else.
//!
//! WHAT A LINE HOLDS, AND WHAT IT NEVER HOLDS. Time, box name, image, duration, exit code, outcome and
//! GPU selection: facts kern itself observed, from outside the box. Never the command's output, its
//! arguments or its environment, which can carry a secret; the box's own stdout is not a channel this
//! file is ever written from.
//!
//! WHERE, AND THE OPERATOR CHOOSES. `[kern] sandbox_history` in `kern.toml` (see [`Keep`]):
//!
//! * `memory`, the default: `$XDG_RUNTIME_DIR/kern/history/boxes.tsv`, beside the registry, on the
//!   runtime tmpfs, so a reboot clears it. Classified AUTHORITATIVE there: kern prints these lines as
//!   fact, so a box able to write the file would print rows of its choosing.
//! * `disk`: `$XDG_DATA_HOME/kern/history/boxes.tsv`, kept across reboots. Under the same root as the
//!   kept-box store, which the CLI and both SDKs already refuse as a mount source, for the same
//!   reason; a test holds that the location and the refusal agree.
//! * `off`: nothing new is recorded.
//!
//! One `O_APPEND` write per box (a line is far under `PIPE_BUF`, so concurrent boxes cannot
//! interleave), and past [`MAX_BYTES`] the file is renamed to `boxes.1.tsv` and a new one started:
//! the history is bounded at twice that, with no daemon to trim it.

use std::io::Write;
use std::path::PathBuf;

/// The size at which the current file is rotated when `[kern] sandbox_history_max_size` is unset:
/// about 18 000 lines (MEASURED on 2026-11-17: 18 799 lines in a rotated 1 MiB file).
const MAX_BYTES: u64 = 1 << 20;
const CURRENT: &str = "boxes.tsv";
const PREVIOUS: &str = "boxes.1.tsv";
/// The line format's version, first field of every line, so a later kern can read an older file.
const FORMAT: &str = "v1";

/// How a box ended, as kern observed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Exit code 0.
    Ok,
    /// The workload exited with this non-zero code on its own.
    Exit(i32),
    /// The kernel's OOM killer fired in the box's own cgroup.
    Oom,
    /// kern's own `--timeout` ended it.
    Timeout,
    /// A `kern stop` / `kern kill` ended it (the SDK's own deadline arrives this way).
    Stopped,
    /// Another signal ended the workload.
    Signal(u8),
    /// The box never started (kern's exit 125).
    NotStarted,
}

impl Outcome {
    /// The word a line carries and `kern sandbox history` prints.
    pub fn word(&self) -> String {
        match self {
            Outcome::Ok => "ok".into(),
            Outcome::Exit(c) => format!("exit-{c}"),
            Outcome::Oom => "oom".into(),
            Outcome::Timeout => "timeout".into(),
            Outcome::Stopped => "stopped".into(),
            Outcome::Signal(s) => format!("signal-{s}"),
            Outcome::NotStarted => "not-started".into(),
        }
    }

    fn parse(w: &str) -> Option<Outcome> {
        Some(match w {
            "ok" => Outcome::Ok,
            "oom" => Outcome::Oom,
            "timeout" => Outcome::Timeout,
            "stopped" => Outcome::Stopped,
            "not-started" => Outcome::NotStarted,
            _ => {
                if let Some(c) = w.strip_prefix("exit-") {
                    Outcome::Exit(c.parse().ok()?)
                } else {
                    Outcome::Signal(w.strip_prefix("signal-")?.parse().ok()?)
                }
            }
        })
    }

    /// Whether this is a failure an operator scanning the history wants to see.
    pub fn failed(&self) -> bool {
        !matches!(self, Outcome::Ok)
    }
}

/// Decide the outcome of a foreground box from what kern observed of it. ONE place, so the history
/// and anything later that reports an outcome cannot classify the same death two ways.
///
/// `signal` is the signal that ended the workload (0 if it exited), `oom` whether the box's own
/// cgroup saw an OOM kill, `timeout_s` the box's `--timeout` (0 for none) and `ran_ms` how long it
/// ran. A SIGKILL at or past the timeout is kern's watchdog: the watchdog is a separate process that
/// reports nothing back, and a 250 ms margin covers its own scheduling.
pub fn classify(code: i32, signal: u8, oom: bool, timeout_s: u64, ran_ms: u64) -> Outcome {
    if code == 125 {
        Outcome::NotStarted
    } else if oom {
        Outcome::Oom
    } else if signal == 9 && timeout_s > 0 && ran_ms + 250 >= timeout_s.saturating_mul(1000) {
        Outcome::Timeout
    } else if signal != 0 {
        Outcome::Signal(signal)
    } else if code == 0 {
        Outcome::Ok
    } else {
        Outcome::Exit(code)
    }
}

/// What kind of box a name is: see [`Entry::kind`].
pub fn kind_of(name: &str) -> &'static str {
    if name.starts_with("pysbx-") {
        "sandbox-py"
    } else if name.starts_with("jssbx-") {
        "sandbox-js"
    } else if name.starts_with("kern-sbx-") {
        "sandbox-resident"
    } else {
        "box"
    }
}

/// One finished box.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Unix time of the end, in milliseconds.
    pub ended_ms: u64,
    pub name: String,
    /// The image, or `-` for a `--rootfs` box.
    pub image: String,
    pub ran_ms: u64,
    pub code: i32,
    pub outcome: Outcome,
    /// The `--gpus` selection, or `-`.
    pub gpu: String,
}

impl Entry {
    /// What kind of box this was, from the names the SDKs give their boxes: `pysbx-` (Python and the
    /// MCP server, one box per call), `jssbx-` (Node), `kern-sbx-` (a resident box: a Kernel or a
    /// `persist` sandbox). Anything else is a box someone started.
    pub fn kind(&self) -> &'static str {
        kind_of(&self.name)
    }

    pub fn is_sandbox(&self) -> bool {
        self.kind() != "box"
    }

    /// The line this entry is stored as. Fields are tab-separated; a tab, CR or LF in a field (none
    /// can occur in a box name or an image reference kern accepted, but the line format must not
    /// depend on that) becomes a space.
    fn line(&self) -> String {
        let clean = |s: &str| -> String {
            let s: String = s
                .chars()
                .map(|c| {
                    if matches!(c, '\t' | '\n' | '\r') {
                        ' '
                    } else {
                        c
                    }
                })
                .take(256)
                .collect();
            if s.is_empty() {
                "-".to_string()
            } else {
                s
            }
        };
        format!(
            "{FORMAT}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            self.ended_ms,
            clean(&self.name),
            clean(&self.image),
            self.ran_ms,
            self.code,
            self.outcome.word(),
            clean(&self.gpu)
        )
    }

    fn parse(line: &str) -> Option<Entry> {
        let f: Vec<&str> = line.trim_end_matches('\n').split('\t').collect();
        if f.len() != 8 || f[0] != FORMAT {
            return None;
        }
        Some(Entry {
            ended_ms: f[1].parse().ok()?,
            name: f[2].to_string(),
            image: f[3].to_string(),
            ran_ms: f[4].parse().ok()?,
            code: f[5].parse().ok()?,
            outcome: Outcome::parse(f[6])?,
            gpu: f[7].to_string(),
        })
    }
}

/// Where the history is kept: `[kern] sandbox_history`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keep {
    /// The runtime tmpfs: kept until the machine reboots. The default.
    Memory,
    /// `$XDG_DATA_HOME/kern/history`: kept across reboots.
    Disk,
    /// Nothing new is recorded.
    Off,
}

impl Keep {
    pub const ALL: [Keep; 3] = [Keep::Memory, Keep::Disk, Keep::Off];

    /// The value `kern.toml` and `kern sandbox keep` spell it with.
    pub fn word(self) -> &'static str {
        match self {
            Keep::Memory => "memory",
            Keep::Disk => "disk",
            Keep::Off => "off",
        }
    }

    pub fn parse(w: &str) -> Option<Keep> {
        Keep::ALL.into_iter().find(|k| k.word() == w)
    }

    /// What the choice does, in the words every surface prints after [`Self::word`]: the CLI,
    /// `kern info`, the config error and both lines of `kern top` read it from here, so the
    /// sentence cannot be spelled four ways.
    pub fn meaning(self) -> &'static str {
        match self {
            Keep::Memory => "cleared at reboot",
            Keep::Disk => "kept across reboots",
            Keep::Off => "nothing new is recorded",
        }
    }

    /// The picker key for this choice in `kern top`: its word's first letter (`m`, `d`, `o`).
    pub fn key(self) -> u8 {
        self.word().as_bytes().first().copied().unwrap_or(b'?')
    }

    /// The choice a picker key names, if any.
    pub fn by_key(k: u8) -> Option<Keep> {
        Keep::ALL.into_iter().find(|x| x.key() == k)
    }
}

/// The configured [`Keep`], read from the active `kern.toml` and re-read only when that file
/// changed. NOT [`crate::config::load_cached`], which holds one answer for the life of a process:
/// `kern top` runs for hours and the choice is made from another process (`kern sandbox keep`) as
/// often as from its own key. A missing or unreadable file is the default.
pub fn keep() -> Keep {
    keep_state().0
}

/// [`keep`] and, when `kern.toml` does not parse, why: the default is then in force and the
/// sentences that name the place say so. One load answers both, memoised together.
fn keep_state() -> (Keep, Option<String>) {
    use std::sync::Mutex;
    type Key = (Option<PathBuf>, u64, Option<std::time::SystemTime>);
    type State = (Keep, Option<String>);
    static MEMO: Mutex<Option<(Key, State)>> = Mutex::new(None);
    let path = crate::config::active_path();
    let meta = path.as_ref().and_then(|p| std::fs::metadata(p).ok());
    let key: Key = (
        path,
        meta.as_ref().map_or(0, std::fs::Metadata::len),
        meta.and_then(|m| m.modified().ok()),
    );
    let mut guard = MEMO.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((k, v)) = guard.as_ref() {
        if *k == key {
            return v.clone();
        }
    }
    let v = match crate::config::load(None) {
        Ok(c) => (c.kern.sandbox_history.unwrap_or(Keep::Memory), None),
        Err(e) => (Keep::Memory, Some(e)),
    };
    *guard = Some((key, v.clone()));
    v
}

/// [`keep`] for the one read a box's end makes: no memo key to `stat`, because a box process
/// records once and the memo could never hit. NOT `load_cached`, whose answer is fixed for the
/// process: a detached box's supervisor lives as long as its box and must write where the setting
/// says NOW, and an SDK box loads no config before this anyway, so the cache saves no read.
///
/// Returns the rotation size too (`[kern] sandbox_history_max_size`, else [`MAX_BYTES`]): the same
/// load answers both, so a box's end reads `kern.toml` once.
fn keep_for_record() -> (Keep, u64) {
    let cfg = crate::config::load(None).ok();
    let k = cfg.as_ref().map(|c| &c.kern);
    (
        k.and_then(|k| k.sandbox_history).unwrap_or(Keep::Memory),
        max_bytes_of(k.and_then(|k| k.sandbox_history_max_size)),
    )
}

/// The rotation size a configured value means: the value, else [`MAX_BYTES`]. A value under the
/// floor the config reader enforces cannot reach here from a parsed file; it is floored anyway, so
/// no caller can make the history rotate on every line.
fn max_bytes_of(configured: Option<u64>) -> u64 {
    configured
        .unwrap_or(MAX_BYTES)
        .max(crate::config::HISTORY_MIN_BYTES)
}

/// The rotation size in force now, for the paths that rewrite the history outside a box's end
/// (`kern sandbox keep` moving rows). A `kern.toml` that does not parse means the default.
fn max_bytes() -> u64 {
    max_bytes_of(
        crate::config::load(None)
            .ok()
            .and_then(|c| c.kern.sandbox_history_max_size),
    )
}

fn memory_dir() -> std::io::Result<PathBuf> {
    crate::registry::runtime_subdir("history")
}

/// `$XDG_DATA_HOME/kern/history`, else `~/.local/share/kern/history`; `None` with neither set.
///
/// THE SAME ROOT AS THE KEPT-BOX STORE ([`crate::keepbox::data_root`], from the same resolver),
/// and that is the reason for the place: the CLI refuses that root and its ancestors as a mount source, and both SDKs refuse
/// `$XDG_DATA_HOME/kern`, so a box can neither read nor forge this history.
/// `the_disk_history_is_refused_as_a_mount_source` holds the agreement.
pub(crate) fn disk_dir_path() -> Option<PathBuf> {
    crate::keepbox::data_root().map(|r| r.join("history"))
}

/// [`disk_dir_path`], created private (`0700`) and checked to be a directory this user owns, so a
/// symlink or another user's directory planted there is refused rather than written through.
fn disk_dir() -> std::io::Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let d = disk_dir_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "neither XDG_DATA_HOME nor HOME is set",
        )
    })?;
    crate::commands::own_only_dir(&d)?;
    let m = std::fs::symlink_metadata(&d)?;
    // SAFETY: `getuid` has no preconditions and cannot fail.
    if !m.is_dir() || m.uid() != unsafe { libc::getuid() } {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{} is not a directory this user owns", d.display()),
        ));
    }
    Ok(d)
}

/// The directory `k` writes to, and the one `kern sandbox history` reads: `off` reads the memory
/// one, which holds what was recorded before (a switch to `off` moves the rows there, so they are
/// still readable and go at the next reboot). A disk directory that cannot be made falls back to
/// memory, so a box's line is kept somewhere rather than nowhere.
fn dir_of(k: Keep) -> std::io::Result<PathBuf> {
    match k {
        Keep::Disk => disk_dir().or_else(|_| memory_dir()),
        Keep::Memory | Keep::Off => memory_dir(),
    }
}

fn dir() -> std::io::Result<PathBuf> {
    dir_of(keep())
}

/// The file the history is written to now (for `off`, the one that holds what came before), for
/// display: what `kern top` names on every frame, so the disk path is COMPUTED and nothing is made
/// or checked on disk to name it.
pub fn current_file() -> Option<PathBuf> {
    match keep() {
        Keep::Disk => disk_dir_path(),
        Keep::Memory | Keep::Off => memory_dir().ok(),
    }
    .map(|d| d.join(CURRENT))
}

/// Append one entry, unless the history is `off`. Best-effort and silent: a box's result must
/// never depend on its history.
fn record(e: &Entry) {
    let (k, max) = keep_for_record();
    if k == Keep::Off {
        return;
    }
    let Ok(d) = dir_of(k) else {
        return;
    };
    record_in(&d, e, max);
}

/// What the OWNER of a box (its foreground launcher, or a detached box's supervisor) observed
/// when the box ended: everything its history line is written from.
pub struct Observed<'a> {
    pub code: i32,
    /// The signal that ended the workload, 0 if it exited.
    pub signal: u8,
    /// Whether its own cgroup OOM-killed it.
    pub oom: bool,
    /// `--timeout` in seconds, 0 for none.
    pub timeout_s: u64,
    pub ran_ms: u64,
    /// The image, empty for a `--rootfs` box (written `-`).
    pub image: &'a str,
    /// The `--gpus` selection, empty for none (written `-`).
    pub gpu: &'a str,
}

/// The owner's line for the box `name` it owned as `owner_pid`. THE ONE PLACE an owner writes one,
/// so the stop claim, the outcome and the field rules cannot differ between the foreground and the
/// detached path: if a `kern stop` already wrote the line this writes nothing, if a stop ended the
/// box and left the line to its owner the outcome is `stopped`, otherwise it is what was observed.
pub fn record_owner_end(name: &str, owner_pid: i32, o: &Observed) {
    let outcome = match crate::registry::owner_stop_claim(name, owner_pid) {
        crate::registry::StopClaim::AlreadyWritten => return,
        crate::registry::StopClaim::OwnerWrites => Outcome::Stopped,
        crate::registry::StopClaim::NotStopped => {
            classify(o.code, o.signal, o.oom, o.timeout_s, o.ran_ms)
        }
    };
    record(&Entry {
        ended_ms: now_ms(),
        name: name.to_string(),
        image: o.image.to_string(),
        ran_ms: o.ran_ms,
        code: o.code,
        outcome,
        gpu: o.gpu.to_string(),
    });
}

/// `kern stop`'s line for the box `b` it ended, written HERE unless the box's owner already wrote
/// it: one atomic claim decides, with no waiting (see `registry::owner_stop_claim`). A stop that
/// wins leaves the owner a `.done` mark, which an owner already gone never reads, so it is removed.
pub fn record_stopped(b: &crate::registry::Instance, code: i32) {
    if !crate::registry::claim_stop_record(&b.name, b.pid) {
        return;
    }
    if !crate::registry::pid_is_still(b.pid, b.starttime) {
        crate::registry::forget_stop_record(&b.name, b.pid);
    }
    record(&Entry {
        ended_ms: now_ms(),
        name: b.name.clone(),
        image: b.image.clone(),
        // From the kernel's start time of the box's init, to the tick, where the record has it;
        // else from the recorded start second.
        ran_ms: ran_ms_since_ticks(b.pid1_starttime).unwrap_or_else(|| {
            crate::registry::now_unix()
                .saturating_sub(b.started)
                .saturating_mul(1000)
        }),
        code,
        outcome: Outcome::Stopped,
        gpu: b.gpus.clone(),
    });
}

fn record_in(d: &std::path::Path, e: &Entry, max: u64) {
    use std::os::unix::fs::OpenOptionsExt;
    let cur = d.join(CURRENT);
    if std::fs::metadata(&cur).is_ok_and(|m| m.len() >= max) {
        // Two writers may both see the file full; the second rename moves a fresh, short file over
        // the previous one, which loses at most a handful of lines and never corrupts one.
        let _ = std::fs::rename(&cur, d.join(PREVIOUS));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&cur)
    {
        let _ = f.write_all(e.line().as_bytes());
    }
}

/// Every entry still held, oldest first.
pub fn read_all() -> Vec<Entry> {
    dir().map(|d| read_in(&d)).unwrap_or_default()
}

fn read_in(d: &std::path::Path) -> Vec<Entry> {
    let mut out = Vec::new();
    for f in [PREVIOUS, CURRENT] {
        if let Ok(text) = std::fs::read_to_string(d.join(f)) {
            out.extend(text.lines().filter_map(Entry::parse));
        }
    }
    out
}

/// The sandbox entries, newest first, re-read only when either file changed.
///
/// FOR `kern top`, which asks every second: the files hold up to about 37 000 lines at the default size and parsing them
/// on every frame would be work for an answer that rarely changes. The key is each file's size and
/// modification time, which an append always moves.
///
/// SHARED, NOT COPIED: an `Arc` over the cached list. `kern top` asks for it several times a frame
/// (the tab bar's count, the Overview, the tab, Enter), and a copy of 12 000 entries with three
/// strings each is about 36 000 allocations per call.
pub fn sandboxes_newest_first() -> std::sync::Arc<[Entry]> {
    use std::sync::{Arc, Mutex};
    type Key = (PathBuf, Vec<(u64, Option<std::time::SystemTime>)>);
    static CACHE: Mutex<Option<(Key, Arc<[Entry]>)>> = Mutex::new(None);
    let Ok(d) = dir() else {
        return Arc::from(Vec::new());
    };
    // THE DIRECTORY IS PART OF THE KEY: a switch between memory and disk changes where the rows
    // are, and two files that happen to share a size and a second must not answer for each other.
    let key: Key = (
        d.clone(),
        [PREVIOUS, CURRENT]
            .iter()
            .map(|f| {
                std::fs::metadata(d.join(f))
                    .map(|m| (m.len(), m.modified().ok()))
                    .unwrap_or((0, None))
            })
            .collect(),
    );
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((k, v)) = guard.as_ref() {
        if *k == key {
            return Arc::clone(v);
        }
    }
    let mut v: Vec<Entry> = read_in(&d).into_iter().filter(Entry::is_sandbox).collect();
    v.reverse();
    let v: Arc<[Entry]> = Arc::from(v);
    *guard = Some((key, Arc::clone(&v)));
    v
}

/// Write `entries` (oldest first) as the whole history of `d`, newest `max` bytes in the current
/// file and the `max` before them in the previous one, the bound [`record_in`] keeps. Each
/// file is written to a private temporary and renamed over, so a reader sees the old file or the
/// new one, never half of one.
fn write_whole(d: &std::path::Path, entries: &[Entry], max: u64) -> std::io::Result<()> {
    let lines: Vec<String> = entries.iter().map(Entry::line).collect();
    // From the newest end: the current file takes the lines that fit, the previous one the lines
    // before them that fit, and older ones go.
    let fit_before = |end: usize| -> usize {
        let mut start = end;
        let mut size = 0u64;
        while start > 0 && size + lines[start - 1].len() as u64 <= max {
            size += lines[start - 1].len() as u64;
            start -= 1;
        }
        start
    };
    let split = fit_before(lines.len());
    let start = fit_before(split);
    for (name, body) in [
        (PREVIOUS, lines[start..split].concat()),
        (CURRENT, lines[split..].concat()),
    ] {
        let target = d.join(name);
        if body.is_empty() {
            remove_if_present(&target)?;
        } else {
            crate::config::write_atomic(&target, &body)?;
        }
    }
    Ok(())
}

/// Remove `path`; one that is not there is already the state asked for.
fn remove_if_present(path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Remove both history files of `d`.
fn remove_in(d: &std::path::Path) -> std::io::Result<()> {
    for f in [PREVIOUS, CURRENT] {
        remove_if_present(&d.join(f))?;
    }
    Ok(())
}

/// How many lines `d` holds, counted as bytes rather than parsed: the sentences that name the
/// place say how many, and parsing up to 2 MiB to count it cost milliseconds per call.
fn held_in(d: &std::path::Path) -> usize {
    [PREVIOUS, CURRENT]
        .iter()
        .filter_map(|f| std::fs::read(d.join(f)).ok())
        .map(|b| b.iter().filter(|c| **c == b'\n').count())
        .sum()
}

/// Every place a history can be: memory, and the disk directory where it exists.
fn places() -> impl Iterator<Item = PathBuf> {
    [memory_dir().ok(), disk_dir_path().filter(|p| p.is_dir())]
        .into_iter()
        .flatten()
}

/// Move every row of `from` into `to`, merged by end time with what `to` already holds, and empty
/// `from`. Returns how many rows came across. The same directory is a no-op.
///
/// A box that ends DURING the move may append to `from` after it was read; that line stays there
/// and is read again if the history ever points back at `from`. The window is one read and two
/// renames long, and the alternative, a lock every box end would take, is a cost on the hot path
/// for a switch that happens once.
fn move_rows(from: &std::path::Path, to: &std::path::Path, max: u64) -> std::io::Result<usize> {
    if from == to {
        return Ok(0);
    }
    let moving = read_in(from);
    if moving.is_empty() {
        return Ok(0);
    }
    let mut all = read_in(to);
    all.extend(moving.iter().cloned());
    all.sort_by_key(|e| e.ended_ms);
    write_whole(to, &all, max)?;
    remove_in(from)?;
    Ok(moving.len())
}

/// Make `new` the history's place: write `[kern] sandbox_history` and move the rows already held to
/// where `new` keeps them (`off` keeps them in memory, readable until the next reboot). Returns how
/// many rows moved.
pub fn set_keep(new: Keep) -> Result<usize, String> {
    crate::config::set_kern_key("sandbox_history", Some(&format!("\"{}\"", new.word())))?;
    let Ok(to) = dir_of(new) else {
        return Ok(0);
    };
    // EVERY PLACE IS SWEPT, not only the previous setting's: a disk directory that could not be
    // made fell back to memory, so rows can sit in either. `move_rows` merges by end time and is a
    // no-op on the target itself, so the order does not matter.
    let mut moved = 0;
    let max = max_bytes();
    for from in places() {
        moved += move_rows(&from, &to, max).map_err(|e| format!("moving the history: {e}"))?;
    }
    Ok(moved)
}

/// Remove every row held, in memory and on disk. Returns how many there were.
pub fn clear() -> Result<usize, String> {
    let mut n = 0;
    for d in places() {
        n += held_in(&d);
        remove_in(&d).map_err(|e| format!("clearing {}: {e}", d.display()))?;
    }
    Ok(n)
}

/// "N rows moved with it", or nothing for none: the CLI and `kern top` say it the same way.
pub fn moved_line(n: usize) -> Option<String> {
    match n {
        0 => None,
        1 => Some("1 row moved with it".to_string()),
        n => Some(format!("{n} rows moved with it")),
    }
}

/// Where the history is and how many rows it holds, the sentence `kern info` and the CLI print:
/// `memory: cleared at reboot, 139 rows in /run/user/1000/kern/history/boxes.tsv`.
///
/// A `kern.toml` that does not parse is SAID, not absorbed: the history then sits where the default
/// puts it, and a reader who wrote `disk` with a typo elsewhere in the file must not be told
/// "memory" as if that were their choice.
pub fn keep_line() -> String {
    let (k, broken) = keep_state();
    let line = match dir_of(k) {
        Err(_) => format!("{}: {}, no directory to keep it in", k.word(), k.meaning()),
        Ok(d) => {
            let held = held_in(&d);
            let at = d.join(CURRENT);
            let fell_back = k == Keep::Disk && disk_dir_path().is_some_and(|p| !d.starts_with(p));
            match k {
                Keep::Off if held == 0 => "off: nothing is recorded".to_string(),
                Keep::Off => format!(
                    "off: {}; {held} rows from before stay in {} until reboot",
                    k.meaning(),
                    at.display()
                ),
                Keep::Disk if fell_back => format!(
                    "disk, but the disk directory could not be made: {held} rows in {}, {}",
                    at.display(),
                    Keep::Memory.meaning()
                ),
                Keep::Disk | Keep::Memory => {
                    format!(
                        "{}: {}, {held} rows in {}",
                        k.word(),
                        k.meaning(),
                        at.display()
                    )
                }
            }
        }
    };
    match broken {
        Some(e) => format!("{line} (the default: kern.toml does not parse, {e})"),
        None => line,
    }
}

/// The last hour of `rows` as one line: runs, the outcomes by count, and run-time p50/p99.
pub fn last_hour_line(rows: &[Entry]) -> String {
    let (n, by, p50, p99) = summary(rows, now_ms().saturating_sub(3_600_000));
    if n == 0 {
        return "no sandbox finished in the last hour".to_string();
    }
    let by: Vec<String> = by.iter().map(|(k, v)| format!("{k} {v}")).collect();
    format!(
        "last hour {n} runs: {}   ran p50 {} p99 {}",
        by.join(" · "),
        dur(p50),
        dur(p99)
    )
}

/// The end as a local date and time, and a duration, for the TUI, which prints the same columns.
pub fn ended_and_ran(e: &Entry) -> (String, String) {
    (local_datetime(e.ended_ms), dur(e.ran_ms))
}

/// How long ago a process started, in milliseconds, from its kernel start time in clock ticks since
/// boot (`/proc/<pid>/stat` field 22) and `/proc/uptime`: to the tick (10 ms at the usual 100 Hz),
/// where the recorded start second would round a 300 ms box to 0 or 1000. `None` for a zero start
/// time (never recorded) or an unreadable clock.
pub fn ran_ms_since_ticks(ticks: u64) -> Option<u64> {
    if ticks == 0 {
        return None;
    }
    // SAFETY: `sysconf` has no preconditions.
    let hz = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })
        .ok()
        .filter(|h| *h > 0)?;
    let up = std::fs::read_to_string("/proc/uptime").ok()?;
    let secs: f64 = up.split_whitespace().next()?.parse().ok()?;
    if !secs.is_finite() || secs < 0.0 {
        return None;
    }
    let now_ms = (secs * 1000.0) as u64;
    now_ms.checked_sub(ticks.checked_mul(1000)? / hz)
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `YYYY-MM-DD HH:MM:SS` of a Unix time in milliseconds, in the local zone: the shape Docker
/// Desktop's log list uses.
///
/// THE DATE IS PART OF IT because the history outlives the day: kept on disk it spans reboots, and
/// a column of bare `08:37:16` could not say which morning. Owner report 16/11, on a list of 1464
/// sandboxes going back days.
fn local_datetime(ms: u64) -> String {
    // 64-bit seconds, which is `time_t` on every target kern builds for (glibc and musl, x86_64 and
    // aarch64); the alias itself is deprecated in `libc` for musl, so it is not named here.
    let t = i64::try_from(ms / 1000).unwrap_or(0);
    // SAFETY: `localtime_r` reads `t` and writes only into `tm`, which lives on this stack frame.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r((&raw const t).cast(), &mut tm) }.is_null() {
        return "---------- --:--:--".into();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        i64::from(tm.tm_year) + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

/// `1.2s`, `340ms`, `3m05s`.
fn dur(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{}m{:02}s", ms / 60_000, (ms / 1000) % 60)
    }
}

/// What `kern sandbox` was asked to do.
#[derive(Debug, PartialEq, Eq)]
pub enum SandboxCmd {
    /// The sandboxes running now.
    Ls { json: bool },
    /// The last `n` finished ones (`all`: every box, not only the SDKs'), `failed` only.
    History {
        json: bool,
        n: usize,
        failed: bool,
        all: bool,
    },
    /// Counts, outcomes and run time over the held history.
    Stats { json: bool, all: bool },
    /// Where the history is kept; with a value, change it.
    Keep { to: Option<Keep> },
    /// Remove every row held.
    Clear,
}

/// `kern sandbox ls|history|stats`.
pub fn sandbox_cmd(cmd: &SandboxCmd) -> Result<(), crate::error::Error> {
    match cmd {
        SandboxCmd::Ls { json } => sandbox_ls(*json),
        SandboxCmd::History {
            json,
            n,
            failed,
            all,
        } => {
            let held = read_all();
            let rows: Vec<&Entry> = held
                .iter()
                .filter(|e| *all || e.is_sandbox())
                .filter(|e| !*failed || e.outcome.failed())
                .collect();
            let rows = &rows[rows.len().saturating_sub(*n)..];
            if *json {
                for e in rows {
                    println!("{}", entry_json(e));
                }
                return Ok(());
            }
            if rows.is_empty() {
                // NOT "NOTHING RECORDED" WHEN SOMETHING IS: without `--all` only the SDKs'
                // sandboxes are listed, and a history full of `kern box` rows used to answer "no
                // finished sandbox recorded yet" (104 rows held, reported against 6d93b85).
                let others = held
                    .iter()
                    .filter(|e| !*failed || e.outcome.failed())
                    .count();
                if !*all && others > 0 {
                    println!(
                        "no SDK sandbox {}recorded; {others} other box{} {}, see `kern sandbox history --all`",
                        if *failed { "failure " } else { "" },
                        if others == 1 { "" } else { "es" },
                        if others == 1 { "is" } else { "are" },
                    );
                } else {
                    println!(
                        "no finished sandbox recorded yet (kern records one line per box that ends)"
                    );
                }
                where_line();
                return Ok(());
            }
            println!(
                "{:<19} {:<24} {:<17} {:<26} {:>8}  {:<12} GPU",
                "ENDED", "NAME", "KIND", "IMAGE", "RAN", "OUTCOME"
            );
            for e in rows {
                println!(
                    "{:<19} {:<24} {:<17} {:<26} {:>8}  {:<12} {}",
                    local_datetime(e.ended_ms),
                    cut(&e.name, 24),
                    e.kind(),
                    cut(&e.image, 26),
                    dur(e.ran_ms),
                    e.outcome.word(),
                    e.gpu
                );
            }
            where_line();
            Ok(())
        }
        SandboxCmd::Stats { json, all } => sandbox_stats(*json, *all),
        SandboxCmd::Keep { to: None } => {
            println!("{}", keep_line());
            println!(
                "change it with: kern sandbox keep memory | disk | off   ([kern] sandbox_history in {})",
                config_name()
            );
            Ok(())
        }
        SandboxCmd::Keep { to: Some(k) } => {
            let moved = set_keep(*k).map_err(crate::error::Error::Config)?;
            println!("{}", keep_line());
            if let Some(m) = moved_line(moved) {
                println!("{m}");
            }
            Ok(())
        }
        SandboxCmd::Clear => {
            let n = clear().map_err(crate::error::Error::Config)?;
            println!("{n} rows removed; {}", keep_line());
            Ok(())
        }
    }
}

/// The `kern.toml` the setting is written to, for the sentence that names it.
fn config_name() -> String {
    crate::config::active_path().map_or_else(|| "kern.toml".into(), |p| p.display().to_string())
}

/// The closing line of a human `history` or `stats`: where these rows live and how to change it,
/// because the default clears them at reboot and a reader should not find that out from a reboot.
fn where_line() {
    let now = keep();
    let next: Vec<&str> = Keep::ALL
        .into_iter()
        .filter(|k| *k != now)
        .map(Keep::word)
        .collect();
    println!(
        "history {}   (kern sandbox keep {})",
        keep_line(),
        next.join(" | ")
    );
}

fn cut(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

fn entry_json(e: &Entry) -> String {
    use kern_common::json_str;
    format!(
        "{{\"ended_ms\":{},\"name\":{},\"kind\":{},\"image\":{},\"ran_ms\":{},\"exit_code\":{},\"outcome\":{},\"gpu\":{}}}",
        e.ended_ms,
        json_str(&e.name),
        json_str(e.kind()),
        json_str(&e.image),
        e.ran_ms,
        e.code,
        json_str(&e.outcome.word()),
        json_str(&e.gpu)
    )
}

fn sandbox_ls(json: bool) -> Result<(), crate::error::Error> {
    let now = crate::registry::now_unix();
    let live: Vec<crate::registry::Instance> = crate::registry::list()
        .into_iter()
        .filter(|b| kind_of(&b.name) != "box")
        .collect();
    let kind = kind_of;
    if json {
        for b in &live {
            println!(
                "{{\"name\":{},\"kind\":{},\"pid\":{},\"up_s\":{}}}",
                kern_common::json_str(&b.name),
                kern_common::json_str(kind(&b.name)),
                b.pid,
                now.saturating_sub(b.started)
            );
        }
        return Ok(());
    }
    if live.is_empty() {
        println!("no sandbox running");
        return Ok(());
    }
    println!("{:<32} {:<17} {:>8} {:>8}", "NAME", "KIND", "PID", "UP");
    for b in &live {
        println!(
            "{:<32} {:<17} {:>8} {:>8}",
            cut(&b.name, 32),
            kind(&b.name),
            b.pid,
            match now.saturating_sub(b.started) {
                0 => "<1s".to_string(),
                up => dur(up.saturating_mul(1000)),
            }
        );
    }
    Ok(())
}

/// The value at quantile `q` of sorted `v` (nearest rank).
fn quantile(v: &[u64], q: f64) -> u64 {
    if v.is_empty() {
        return 0;
    }
    let i = ((q * v.len() as f64).ceil() as usize).clamp(1, v.len()) - 1;
    v[i]
}

/// Counts per outcome and run-time quantiles, for the whole history and for the last hour.
fn summary(rows: &[Entry], since_ms: u64) -> (usize, Vec<(String, usize)>, u64, u64) {
    let rows: Vec<&Entry> = rows.iter().filter(|e| e.ended_ms >= since_ms).collect();
    let mut by: Vec<(String, usize)> = Vec::new();
    for e in &rows {
        let w = e.outcome.word();
        match by.iter_mut().find(|(k, _)| *k == w) {
            Some((_, n)) => *n += 1,
            None => by.push((w, 1)),
        }
    }
    by.sort_by_key(|x| std::cmp::Reverse(x.1));
    let mut ran: Vec<u64> = rows.iter().map(|e| e.ran_ms).collect();
    ran.sort_unstable();
    (rows.len(), by, quantile(&ran, 0.5), quantile(&ran, 0.99))
}

fn sandbox_stats(json: bool, all: bool) -> Result<(), crate::error::Error> {
    let rows: Vec<Entry> = read_all()
        .into_iter()
        .filter(|e| all || e.is_sandbox())
        .collect();
    let hour = now_ms().saturating_sub(3_600_000);
    let windows = [("last hour", hour), ("held", 0)];
    if json {
        let parts: Vec<String> = windows
            .iter()
            .map(|(label, since)| {
                let (n, by, p50, p99) = summary(&rows, *since);
                let by: Vec<String> = by
                    .iter()
                    .map(|(k, v)| format!("{}:{v}", kern_common::json_str(k)))
                    .collect();
                format!(
                    "{}:{{\"runs\":{n},\"outcomes\":{{{}}},\"p50_ms\":{p50},\"p99_ms\":{p99}}}",
                    kern_common::json_str(label),
                    by.join(",")
                )
            })
            .collect();
        println!("{{{}}}", parts.join(","));
        return Ok(());
    }
    for (label, since) in windows {
        let (n, by, p50, p99) = summary(&rows, since);
        let by: Vec<String> = by.iter().map(|(k, v)| format!("{k} {v}")).collect();
        println!(
            "{label:<10} {n:>6} runs   {}   ran p50 {} p99 {}",
            if by.is_empty() {
                "-".to_string()
            } else {
                by.join(" · ")
            },
            dur(p50),
            dur(p99)
        );
    }
    where_line();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, outcome: Outcome) -> Entry {
        Entry {
            ended_ms: 1,
            name: name.into(),
            image: "python:3.12-slim".into(),
            ran_ms: 12,
            code: 0,
            outcome,
            gpu: "-".into(),
        }
    }

    /// Every death is told apart by what kern OBSERVED, and the ones the exit code alone conflates
    /// (137 is OOM, timeout, stop and an `exit(137)` alike) are the reason this exists.
    #[test]
    fn the_outcome_names_what_ended_the_box() {
        assert_eq!(classify(0, 0, false, 0, 5), Outcome::Ok);
        assert_eq!(classify(3, 0, false, 0, 5), Outcome::Exit(3));
        assert_eq!(
            classify(137, 0, false, 0, 5),
            Outcome::Exit(137),
            "exit(137) by the code itself"
        );
        assert_eq!(classify(137, 9, true, 30, 5), Outcome::Oom);
        assert_eq!(classify(137, 9, false, 2, 2000), Outcome::Timeout);
        assert_eq!(
            classify(137, 9, false, 2, 900),
            Outcome::Signal(9),
            "killed BEFORE its timeout"
        );
        assert_eq!(classify(139, 11, false, 0, 5), Outcome::Signal(11));
        assert_eq!(classify(125, 0, false, 0, 1), Outcome::NotStarted);
    }

    /// The stats count outcomes over a window and take run-time quantiles by nearest rank.
    #[test]
    fn stats_count_outcomes_and_quantiles_over_a_window() {
        let mut rows: Vec<Entry> = (1..=100)
            .map(|i| {
                let mut e = entry(
                    "pysbx-x",
                    if i % 10 == 0 {
                        Outcome::Oom
                    } else {
                        Outcome::Ok
                    },
                );
                e.ran_ms = i;
                e.ended_ms = 1000 + i;
                e
            })
            .collect();
        rows.push(entry("old", Outcome::Timeout));
        let (n, by, p50, p99) = summary(&rows, 1000);
        assert_eq!(n, 100, "the entry ended before the window is not counted");
        assert_eq!(by, vec![("ok".to_string(), 90), ("oom".to_string(), 10)]);
        assert_eq!((p50, p99), (50, 99));
        assert_eq!(quantile(&[], 0.5), 0);
    }

    /// A line round-trips, a hostile field cannot add a line or a column, and the file rotates and is
    /// read across both halves in order.
    #[test]
    fn lines_round_trip_and_the_file_rotates() {
        let d = std::env::temp_dir().join(format!("kern-history-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let mut forged = entry("evil\tname\nv1\t9\tx", Outcome::Exit(3));
        forged.code = 3;
        record_in(&d, &forged, MAX_BYTES);
        record_in(&d, &entry("pysbx-0123456789ab", Outcome::Oom), MAX_BYTES);
        let got = read_in(&d);
        assert_eq!(got.len(), 2, "the forged newline added no line: {got:?}");
        assert_eq!(got[0].name, "evil name v1 9 x");
        assert_eq!(got[1].outcome, Outcome::Oom);
        assert_eq!(got[1].kind(), "sandbox-py");
        // Rotation: a full current file moves aside and both halves are read, oldest first.
        let pad = "x".repeat(MAX_BYTES as usize);
        std::fs::write(
            d.join(CURRENT),
            format!("{}{pad}\n", entry("old", Outcome::Ok).line()),
        )
        .unwrap();
        record_in(&d, &entry("new", Outcome::Ok), MAX_BYTES);
        let names: Vec<String> = read_in(&d).into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["old", "new"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A temporary XDG world: runtime, data and config dirs of its own, `KERN_CONFIG` unset, all
    /// restored on drop so a failing assertion leaves nothing pointing at a removed directory.
    struct World {
        base: PathBuf,
        prev: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    const VARS: [&str; 4] = [
        "XDG_RUNTIME_DIR",
        "XDG_DATA_HOME",
        "XDG_CONFIG_HOME",
        "KERN_CONFIG",
    ];

    impl World {
        fn new(tag: &str) -> World {
            let base = std::env::temp_dir().join(format!("kern-hist-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            for d in ["run", "data", "config"] {
                std::fs::create_dir_all(base.join(d)).unwrap();
            }
            let prev = VARS.iter().map(|v| (*v, crate::global_env(v))).collect();
            crate::set_global_env("XDG_RUNTIME_DIR", base.join("run"));
            crate::set_global_env("XDG_DATA_HOME", base.join("data"));
            crate::set_global_env("XDG_CONFIG_HOME", base.join("config"));
            crate::unset_global_env("KERN_CONFIG");
            World { base, prev }
        }
        fn toml(&self) -> String {
            std::fs::read_to_string(self.base.join("config/kern/kern.toml")).unwrap_or_default()
        }
    }

    impl Drop for World {
        fn drop(&mut self) {
            for (v, old) in &self.prev {
                match old {
                    Some(x) => crate::set_global_env(v, x),
                    None => crate::unset_global_env(v),
                }
            }
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    fn named(name: &str, ended_ms: u64) -> Entry {
        Entry {
            ended_ms,
            ..entry(name, Outcome::Ok)
        }
    }

    /// `[kern] sandbox_history_max_size` is the bound a box's end applies: with 4 KiB configured,
    /// two hundred finished boxes leave the current file under 4 KiB plus one line and the history
    /// at most two files, end to end through `record`, the path every box takes.
    #[test]
    fn the_configured_history_size_is_the_bound_a_box_end_keeps() {
        let _g = crate::env_guard();
        let w = World::new("maxsize");
        std::fs::create_dir_all(w.base.join("config/kern")).unwrap();
        std::fs::write(
            w.base.join("config/kern/kern.toml"),
            "[kern]\nsandbox_history_max_size = \"4k\"\n",
        )
        .unwrap();
        for i in 0..200 {
            record(&named("pysbx-0123456789ab", 1_000_000_000_000 + i));
        }
        let d = memory_dir().unwrap();
        let cur = std::fs::metadata(d.join(CURRENT)).unwrap().len();
        let prev = std::fs::metadata(d.join(PREVIOUS)).unwrap().len();
        let line = named("pysbx-0123456789ab", 1_000_000_000_000).line().len() as u64;
        assert!(cur <= 4096 + line, "current {cur} bytes");
        assert!(prev <= 4096 + line, "previous {prev} bytes");
        let kept = read_in(&d);
        assert!(kept.len() < 200, "rotation dropped the oldest");
        assert_eq!(
            kept.last().map(|e| e.ended_ms),
            Some(1_000_000_000_000 + 199),
            "the newest is kept"
        );
    }

    /// The key is validated where the file is read: the three words load, anything else is refused
    /// with the three named, and an absent key is the default, memory.
    #[test]
    fn the_history_setting_parses_its_three_values_and_refuses_the_rest() {
        for k in Keep::ALL {
            let cfg =
                crate::config::parse(&format!("[kern]\nsandbox_history = \"{}\"\n", k.word()))
                    .unwrap();
            assert_eq!(cfg.kern.sandbox_history, Some(k));
            assert_eq!(Keep::parse(k.word()), Some(k));
        }
        let err = crate::config::parse("[kern]\nsandbox_history = \"tmpfs\"\n").unwrap_err();
        assert!(
            err.contains("\"memory\"") && err.contains("\"disk\"") && err.contains("\"off\""),
            "{err}"
        );
        assert_eq!(
            crate::config::parse("[kern]\n")
                .unwrap()
                .kern
                .sandbox_history,
            None
        );
    }

    /// THE DISK HISTORY IS WHERE THE MOUNT REFUSAL ALREADY LOOKS. A box handed this directory could
    /// read what ran on the host and print rows of its choosing; the refusal covers it because it is
    /// derived from the same root, and this holds the two together.
    #[test]
    fn the_disk_history_is_refused_as_a_mount_source() {
        let _g = crate::env_guard();
        let w = World::new("mount");
        let d = disk_dir().expect("the disk dir is made");
        assert!(d.starts_with(w.base.join("data/kern")), "{}", d.display());
        let canon = std::fs::canonicalize(&d).unwrap();
        assert!(
            crate::registry::trusted_state_overlap(&canon).is_some(),
            "{} must be refused as a mount source",
            canon.display()
        );
        // Refused on the CLI path, with the data root's own reason and the right relation.
        let e = crate::commands::parse_volumes(&[format!("{}:/h", canon.display())])
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(
            e.contains("is inside kern's own state") && e.contains("sandbox history"),
            "{e}"
        );
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    /// The whole switch, through the functions the CLI and `kern top` call: the default is memory;
    /// `disk` writes the key, carries the rows across and makes the next box land on disk; `off`
    /// records nothing and brings the rows back to memory, where they stay readable; `clear` empties
    /// both places.
    #[test]
    fn switching_where_the_history_is_kept_moves_the_rows_and_the_next_line() {
        let _g = crate::env_guard();
        let w = World::new("switch");
        assert_eq!(keep(), Keep::Memory, "no kern.toml is the default");
        record(&named("pysbx-a", 1));
        record(&named("pysbx-b", 3));
        let mem = memory_dir().unwrap();
        assert_eq!(read_in(&mem).len(), 2);

        assert_eq!(set_keep(Keep::Disk), Ok(2));
        assert!(
            w.toml().contains("sandbox_history = \"disk\""),
            "{}",
            w.toml()
        );
        assert_eq!(keep(), Keep::Disk);
        assert!(read_in(&mem).is_empty(), "the rows left memory");
        record(&named("pysbx-c", 2));
        let disk = disk_dir().unwrap();
        let names: Vec<String> = read_all().into_iter().map(|e| e.name).collect();
        assert_eq!(
            names,
            ["pysbx-a", "pysbx-b", "pysbx-c"],
            "read from disk, in order"
        );
        assert!(read_in(&mem).is_empty(), "the new line went to disk");
        assert!(keep_line().starts_with("disk: kept across reboots, 3 rows in "));

        assert_eq!(set_keep(Keep::Off), Ok(3));
        assert!(w.toml().contains("sandbox_history = \"off\""));
        record(&named("pysbx-d", 9));
        assert_eq!(read_all().len(), 3, "off records nothing");
        assert!(read_in(&disk).is_empty(), "the rows left the disk");
        assert!(keep_line().starts_with("off: nothing new is recorded; 3 rows from before"));

        // The key is written in place, never twice.
        assert_eq!(
            w.toml().matches("sandbox_history").count(),
            1,
            "{}",
            w.toml()
        );

        assert_eq!(clear(), Ok(3));
        assert!(read_all().is_empty());
        assert_eq!(keep_line(), "off: nothing is recorded");

        // A file that does not parse leaves the default in force, and the line says why.
        std::fs::write(
            w.base.join("config/kern/kern.toml"),
            "[kern]\nsandbox_history = \"tmpfs\"\n",
        )
        .unwrap();
        assert_eq!(keep(), Keep::Memory);
        let l = keep_line();
        assert!(
            l.starts_with("memory: cleared at reboot") && l.contains("kern.toml does not parse"),
            "{l}"
        );
    }

    /// A move merges by end time and holds the bound a single file holds: the newest
    /// [`MAX_BYTES`] in the current file, the [`MAX_BYTES`] before them in the previous one.
    #[test]
    fn a_move_merges_by_time_and_keeps_the_bound() {
        let base = std::env::temp_dir().join(format!("kern-hist-move-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (a, b) = (base.join("a"), base.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        record_in(&a, &named("one", 1), MAX_BYTES);
        record_in(&a, &named("three", 3), MAX_BYTES);
        record_in(&b, &named("two", 2), MAX_BYTES);
        assert_eq!(move_rows(&a, &b, MAX_BYTES).unwrap(), 2);
        let names: Vec<String> = read_in(&b).into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["one", "two", "three"]);
        assert!(read_in(&a).is_empty());
        assert_eq!(
            move_rows(&b, &b, MAX_BYTES).unwrap(),
            0,
            "the same directory is a no-op"
        );

        // Past the bound: three files' worth of lines keep the newest two files' worth.
        // A fixed-width time, so every line is the same length and a file's worth is a count.
        let t0 = 1_000_000_000_000u64;
        let line = named("n", t0).line().len() as u64;
        let per_file = MAX_BYTES / line;
        let many: Vec<Entry> = (0..per_file * 3).map(|i| named("n", t0 + i)).collect();
        write_whole(&b, &many, MAX_BYTES).unwrap();
        let kept = read_in(&b);
        assert_eq!(kept.len() as u64, per_file * 2);
        assert_eq!(
            kept.first().map(|e| e.ended_ms),
            Some(t0 + per_file),
            "the oldest third dropped"
        );
        assert_eq!(
            kept.last().map(|e| e.ended_ms),
            Some(t0 + per_file * 3 - 1),
            "the newest kept"
        );
        assert!(std::fs::metadata(b.join(CURRENT)).unwrap().len() <= MAX_BYTES);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A start time in ticks becomes a run time to the tick: this process started moments ago, so
    /// its own start reads as a few seconds at most, and a zero start (never recorded) as nothing.
    #[test]
    fn a_start_in_clock_ticks_gives_the_run_time_to_the_tick() {
        let me = i32::try_from(std::process::id()).unwrap_or(0);
        let ticks = crate::registry::proc_starttime(me);
        let ran = ran_ms_since_ticks(ticks);
        assert!(
            ran.is_some_and(|ms| ms < 600_000),
            "this test process started {ran:?} ms ago"
        );
        assert_eq!(ran_ms_since_ticks(0), None);
    }

    /// An empty or relative XDG variable is unset, as the spec says and as both SDKs read it: the
    /// data root falls back to `$HOME/.local/share/kern` instead of a path relative to wherever kern
    /// was started.
    #[test]
    fn an_empty_or_relative_xdg_variable_is_unset() {
        let _g = crate::env_guard();
        let prev = (
            crate::global_env("XDG_DATA_HOME"),
            crate::global_env("HOME"),
        );
        crate::set_global_env("HOME", "/home/someone");
        for v in ["", "relative/dir"] {
            crate::set_global_env("XDG_DATA_HOME", v);
            assert_eq!(
                crate::keepbox::data_root(),
                Some(PathBuf::from("/home/someone/.local/share/kern")),
                "XDG_DATA_HOME={v:?}"
            );
            assert!(
                crate::volume::volumes_dir().is_absolute(),
                "XDG_DATA_HOME={v:?}"
            );
        }
        crate::set_global_env("XDG_DATA_HOME", "/x");
        assert_eq!(disk_dir_path(), Some(PathBuf::from("/x/kern/history")));
        for (k, v) in [("XDG_DATA_HOME", prev.0), ("HOME", prev.1)] {
            match v {
                Some(x) => crate::set_global_env(k, x),
                None => crate::unset_global_env(k),
            }
        }
    }
}
