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
//! WHERE. `$XDG_RUNTIME_DIR/kern/history/boxes.tsv`, beside the registry, and classified
//! AUTHORITATIVE there: kern prints these lines as fact, so a box able to write the file would print
//! rows of its choosing. One `O_APPEND` write per box (a line is far under `PIPE_BUF`, so concurrent
//! boxes cannot interleave), and past [`MAX_BYTES`] the file is renamed to `boxes.1.tsv` and a new
//! one started: the history is bounded at twice that, with no daemon to trim it.

use std::io::Write;
use std::path::PathBuf;

/// The size at which the current file is rotated: about 6000 lines.
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

fn dir() -> std::io::Result<PathBuf> {
    crate::registry::runtime_subdir("history")
}

/// Append one entry. Best-effort and silent: a box's result must never depend on its history.
pub fn record(e: &Entry) {
    let Ok(d) = dir() else {
        return;
    };
    record_in(&d, e);
}

fn record_in(d: &std::path::Path, e: &Entry) {
    use std::os::unix::fs::OpenOptionsExt;
    let cur = d.join(CURRENT);
    if std::fs::metadata(&cur).is_ok_and(|m| m.len() >= MAX_BYTES) {
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
/// FOR `kern top`, which asks every second: the files hold up to about 12 000 lines and parsing them
/// on every frame would be work for an answer that rarely changes. The key is each file's size and
/// modification time, which an append always moves.
pub fn sandboxes_newest_first() -> Vec<Entry> {
    use std::sync::Mutex;
    type Key = Vec<(u64, Option<std::time::SystemTime>)>;
    static CACHE: Mutex<Option<(Key, Vec<Entry>)>> = Mutex::new(None);
    let Ok(d) = dir() else {
        return Vec::new();
    };
    let key: Key = [PREVIOUS, CURRENT]
        .iter()
        .map(|f| {
            std::fs::metadata(d.join(f))
                .map(|m| (m.len(), m.modified().ok()))
                .unwrap_or((0, None))
        })
        .collect();
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((k, v)) = guard.as_ref() {
        if *k == key {
            return v.clone();
        }
    }
    let mut v: Vec<Entry> = read_in(&d).into_iter().filter(Entry::is_sandbox).collect();
    v.reverse();
    *guard = Some((key, v.clone()));
    v
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

/// `HH:MM:SS` and a duration, for the TUI, which prints the same columns.
pub fn ended_and_ran(e: &Entry) -> (String, String) {
    (hms(e.ended_ms), dur(e.ran_ms))
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `HH:MM:SS` of a Unix time in milliseconds, in the local zone.
fn hms(ms: u64) -> String {
    // 64-bit seconds, which is `time_t` on every target kern builds for (glibc and musl, x86_64 and
    // aarch64); the alias itself is deprecated in `libc` for musl, so it is not named here.
    let t = i64::try_from(ms / 1000).unwrap_or(0);
    // SAFETY: `localtime_r` reads `t` and writes only into `tm`, which lives on this stack frame.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r((&raw const t).cast(), &mut tm) }.is_null() {
        return "--:--:--".into();
    }
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
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
            let rows: Vec<Entry> = read_all()
                .into_iter()
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
                println!(
                    "no finished sandbox recorded yet (kern records one line per box that ends)"
                );
                return Ok(());
            }
            println!(
                "{:<9} {:<24} {:<17} {:<26} {:>8}  {:<12} GPU",
                "ENDED", "NAME", "KIND", "IMAGE", "RAN", "OUTCOME"
            );
            for e in rows {
                println!(
                    "{:<9} {:<24} {:<17} {:<26} {:>8}  {:<12} {}",
                    hms(e.ended_ms),
                    cut(&e.name, 24),
                    e.kind(),
                    cut(&e.image, 26),
                    dur(e.ran_ms),
                    e.outcome.word(),
                    e.gpu
                );
            }
            Ok(())
        }
        SandboxCmd::Stats { json, all } => sandbox_stats(*json, *all),
    }
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
        record_in(&d, &forged);
        record_in(&d, &entry("pysbx-0123456789ab", Outcome::Oom));
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
        record_in(&d, &entry("new", Outcome::Ok));
        let names: Vec<String> = read_in(&d).into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["old", "new"]);
        let _ = std::fs::remove_dir_all(&d);
    }
}
