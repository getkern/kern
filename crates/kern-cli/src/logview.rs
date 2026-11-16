//! The Logs tab of `kern top`: the output of every box in one stream, read incrementally.
//!
//! WHAT IT IS FOR. `kern logs <box>` and `kern compose logs` answer about one box or one stack.
//! The question this tab answers is the one a person asks first when something is wrong and they do
//! not yet know where: what is every box saying, right now and just before. Docker Desktop answers it
//! with a Logs view; this is kern's, in the terminal, with what that view lacks: a level read from
//! each line (and inherited by a stack trace's continuation lines), a filter by level and by source,
//! `a|b` alternatives in the search, the rate of lines, and a CSV export whose cells cannot run as
//! spreadsheet formulas.
//!
//! WHAT IT COSTS, AND WHEN. Nothing while the tab is not on screen: no watch, no read. On screen:
//!
//! - every log file is followed from an OFFSET, so a refresh reads only the bytes appended since the
//!   last one, never the file again; the time index beside it (`<log>.idx`, written by the log pump)
//!   is followed the same way;
//! - an inotify watch on the logs directory says WHICH file grew, so an idle host costs no reads at
//!   all; reads are grouped at most every [`PUMP_EVERY_MS`], so a box printing as fast as it can
//!   costs at most twenty frames a second, not one per write;
//! - at most [`READ_PER_PUMP`] bytes per file per refresh, so one runaway box cannot stall a frame;
//! - at most [`MAX_LINES`] lines are held, the oldest dropped first, and the first visit reads at most
//!   [`BACKLOG_TOTAL`] of history, newest files first.
//!
//! WHAT A LINE IS ALLOWED TO DO TO THE TERMINAL: nothing. A box's output is untrusted. Escape
//! sequences are removed whole (a CSI or OSC sequence, not just its ESC byte, or `[31m` would be left
//! in the text) and every other control character goes, before the line is stored, so neither the
//! screen nor the export can carry one.

use std::collections::{HashMap, VecDeque};
use std::io::Write as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::PathBuf;
use std::time::Instant;

use crate::ui::Palette;

/// Lines held in memory, all sources together. The oldest go first.
const MAX_LINES: usize = 50_000;

/// A line longer than this is cut (with `…`): a box that writes one 16 MiB line must not make a
/// frame copy 16 MiB. The export carries the same cut text.
const MAX_LINE_CHARS: usize = 4096;

/// Bytes without a newline after which they are taken as a line anyway, so a box that never prints
/// one cannot grow a buffer without bound.
const MAX_PARTIAL: usize = 64 * 1024;

/// History read from one file on the first visit, from its end.
const BACKLOG_PER_FILE: u64 = 64 * 1024;

/// History read from all files together on the first visit, the most recently written first.
const BACKLOG_TOTAL: u64 = 2 * 1024 * 1024;

/// Bytes read from one file in one refresh. The rest is read on the next one.
const READ_PER_PUMP: u64 = 256 * 1024;

/// How far a file may run ahead of what was read before the gap is SKIPPED rather than read: a
/// box writing faster than this between two refreshes is writing faster than anyone reads, and
/// only its newest lines are worth a frame. The gap is said in the stream, and `kern logs <box>`
/// still has it (within its rotation).
const CATCH_UP: u64 = 64 * 1024;

/// The shortest interval between two refreshes while lines keep arriving.
const PUMP_EVERY_MS: u64 = 50;

/// The interval while some box writes more than a refresh reads: four frames a second, which is
/// as fast as a flood can be watched. MEASURED before it: a box printing 290k lines a second held
/// `kern top` at 99 % of a core chasing every line.
const FLOOD_EVERY_MS: u64 = 250;

/// How often every file is checked when inotify is unavailable.
const POLL_FALLBACK_MS: u64 = 250;

/// The seconds the lines-per-second figure is averaged over.
const RATE_WINDOW_S: usize = 5;

/// How often the store figures (files, bytes, how full) are re-read while the tab is shown.
const STORE_EVERY_MS: u128 = 2000;

/// How full a store may get before it is said in yellow, and in red. The red one is where writes
/// are about to fail; the yellow one leaves room to act.
pub(crate) const FILL_WARN_PCT: u64 = 85;
pub(crate) const FILL_CRIT_PCT: u64 = 95;

/// Where the logs are and how much they take.
struct StoreStats {
    dir: String,
    files: usize,
    bytes: u64,
    /// Bytes of boxes that ended: what `kern prune` frees.
    ended: u64,
    /// How full its filesystem is, as `df` counts it (`commands::fs_fill`).
    fill: u64,
    fs_type: &'static str,
}

/// How bad a line says it is, read from its text.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum Level {
    Info = 0,
    Warn = 1,
    Error = 2,
}

impl Level {
    fn word(self) -> &'static str {
        match self {
            Level::Info => "all",
            Level::Warn => "warn+",
            Level::Error => "error",
        }
    }

    fn next_filter(self) -> Level {
        match self {
            Level::Info => Level::Warn,
            Level::Warn => Level::Error,
            Level::Error => Level::Info,
        }
    }
}

/// One line of one box's output, as stored.
struct Line {
    /// Arrival order across all sources; never reused, so the view can refer to a line by it.
    seq: u64,
    /// Unix nanoseconds of the time mark the line falls after, `0` when none was recorded.
    nanos: u64,
    src: u32,
    level: Level,
    text: Box<str>,
}

/// A line read but not yet numbered (the first visit sorts the backlog by time before numbering).
struct Fresh {
    nanos: u64,
    src: u32,
    level: Level,
    text: Box<str>,
}

/// One log file followed from an offset.
struct Tail {
    src: u32,
    path: PathBuf,
    /// The inode the offsets belong to: a rotation renames the file away and starts a new one, and
    /// an offset into the old file means nothing in the new.
    ino: u64,
    offset: u64,
    idx_offset: u64,
    /// `(log offset, unix nanos)` marks not yet behind the read position (plus the last one that
    /// is, which the next line may still fall after).
    marks: Vec<(u64, u64)>,
    /// Bytes after the last newline, and the file offset they start at.
    partial: Vec<u8>,
    partial_off: u64,
    last_nanos: u64,
    last_level: Level,
    /// First visit: read only the end of the file, and drop the first, cut, line.
    backlog: Option<u64>,
    /// Inside that cut first line, possibly across more than one read: drop until a newline.
    skipping: bool,
    /// The last read skipped a gap ([`CATCH_UP`]): this box is flooding.
    skipped: bool,
    /// Whether a gap may be skipped at all: yes for the screen, never for `kern logs --all`, whose
    /// reader asked for every line.
    catch_up: bool,
    dirty: bool,
}

/// What a key did on the Logs tab.
pub(crate) enum KeyOutcome {
    /// The tab used it; nothing else should.
    Consumed,
    /// Not a Logs key: tab switching, quit and help go on to the normal handler.
    Ignored,
    /// Show this text in the read-only overlay.
    Overlay(String),
}

/// The state of the Logs tab. Inert until [`LogView::set_active`] is called with `true`.
pub(crate) struct LogView {
    active: bool,
    loaded: bool,
    dir: Option<PathBuf>,
    ino_fd: i32,
    tails: Vec<Tail>,
    /// Log file name -> index in `tails`.
    by_name: HashMap<String, usize>,
    sources: Vec<String>,
    src_by_label: HashMap<String, u32>,
    lines: VecDeque<Line>,
    next_seq: u64,
    /// Seqs of the lines the filter lets through, oldest first.
    view: VecDeque<u64>,
    search: String,
    /// `search` split on `|`, lowercased ASCII, empty alternatives dropped.
    terms: Vec<Vec<u8>>,
    level: Level,
    only_src: Option<u32>,
    editing: bool,
    /// Index into `view`; meaningful when not following.
    sel: usize,
    follow: bool,
    pending: bool,
    /// The last refresh found a file further behind than it reads in one: pace at
    /// [`FLOOD_EVERY_MS`].
    flooded: bool,
    last_pump: Option<Instant>,
    /// Lines per second over the last [`RATE_WINDOW_S`] seconds: (second, count) buckets.
    rate: VecDeque<(u64, u64)>,
    store: Option<StoreStats>,
    store_at: Option<Instant>,
    /// Lines held per source, kept with the ring: the header counts the boxes that SAID something,
    /// not every log file found (a desktop held 40, most of them empty, of boxes long gone).
    held: Vec<u32>,
}

impl Default for LogView {
    fn default() -> Self {
        LogView {
            active: false,
            loaded: false,
            dir: None,
            ino_fd: -1,
            tails: Vec::new(),
            by_name: HashMap::new(),
            sources: Vec::new(),
            src_by_label: HashMap::new(),
            lines: VecDeque::new(),
            next_seq: 0,
            view: VecDeque::new(),
            search: String::new(),
            terms: Vec::new(),
            level: Level::Info,
            only_src: None,
            editing: false,
            sel: 0,
            follow: true,
            pending: false,
            flooded: false,
            last_pump: None,
            rate: VecDeque::new(),
            store: None,
            store_at: None,
            held: Vec::new(),
        }
    }
}

impl Drop for LogView {
    fn drop(&mut self) {
        self.unwatch();
    }
}

impl LogView {
    /// Turn following on when the tab is shown and off when it is left. The lines are kept, so
    /// coming back is instant; only what was written meanwhile is read.
    pub(crate) fn set_active(&mut self, on: bool) {
        if on == self.active {
            return;
        }
        self.active = on;
        if !on {
            self.unwatch();
            return;
        }
        if self.dir.is_none() {
            self.dir = crate::registry::logs_dir().ok();
        }
        self.watch();
        self.discover();
        self.refresh_store();
        if !self.loaded {
            self.loaded = true;
            self.first_load();
        } else {
            for t in &mut self.tails {
                t.dirty = true;
            }
            let _ = self.pump();
        }
    }

    /// The inotify descriptor for `poll`, while the tab is shown and no refresh is already owed.
    ///
    /// NOT WHILE ONE IS OWED: a box writing without pause raises an event per write, and polling
    /// the watch then woke the loop once per write to learn what it already knew. Left unread, the
    /// kernel merges a file's repeated events into one, read after the next refresh.
    pub(crate) fn fd(&self) -> Option<i32> {
        (self.active && self.ino_fd >= 0 && !self.pending).then_some(self.ino_fd)
    }

    /// How long `poll` may wait before [`LogView::due`] work exists, or `None` for no deadline.
    pub(crate) fn wait_ms(&self) -> Option<u64> {
        if !self.active {
            return None;
        }
        let every = if self.flooded && (self.pending || self.ino_fd < 0) {
            FLOOD_EVERY_MS
        } else if self.ino_fd < 0 {
            POLL_FALLBACK_MS
        } else if self.pending {
            PUMP_EVERY_MS
        } else {
            return None;
        };
        let since = self.last_pump.map_or(every, |t| {
            u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX)
        });
        Some(every.saturating_sub(since))
    }

    /// Whether a refresh is owed now.
    pub(crate) fn due(&self) -> bool {
        self.wait_ms() == Some(0)
    }

    /// Drain the inotify queue: mark the files that grew, add the new ones. The reading itself is
    /// left to [`LogView::pump`], at most every [`PUMP_EVERY_MS`].
    pub(crate) fn on_readable(&mut self) {
        if self.ino_fd < 0 {
            return;
        }
        let mut buf = [0u8; 8192];
        loop {
            // SAFETY: a descriptor this struct owns and a buffer of the length given.
            let n = unsafe { libc::read(self.ino_fd, buf.as_mut_ptr().cast(), buf.len()) };
            let Ok(n) = usize::try_from(n) else {
                break;
            };
            if n == 0 {
                break;
            }
            let Some(got) = buf.get(..n) else {
                break;
            };
            self.take_events(got);
        }
        self.pending = true;
    }

    /// Parse a run of `struct inotify_event` records. Read field by field from bytes: the buffer
    /// carries no alignment guarantee, and a record cut by the buffer's end is dropped.
    fn take_events(&mut self, mut b: &[u8]) {
        const HEAD: usize = 16;
        while b.len() >= HEAD {
            let field = |at: usize| -> u32 {
                let mut w = [0u8; 4];
                if let Some(s) = b.get(at..at + 4) {
                    w.copy_from_slice(s);
                }
                u32::from_ne_bytes(w)
            };
            let mask = field(4);
            let len = usize::try_from(field(12)).unwrap_or(usize::MAX);
            let Some(name) = b.get(HEAD..HEAD.saturating_add(len)) else {
                break;
            };
            b = b.get(HEAD.saturating_add(len)..).unwrap_or(&[]);
            if mask & libc::IN_Q_OVERFLOW != 0 {
                // Events were lost: every file may have grown.
                self.discover();
                for t in &mut self.tails {
                    t.dirty = true;
                }
                continue;
            }
            let end = name.iter().position(|c| *c == 0).unwrap_or(name.len());
            let Ok(name) = std::str::from_utf8(name.get(..end).unwrap_or(&[])) else {
                continue;
            };
            let log = name.strip_suffix(".idx").unwrap_or(name);
            if !log.ends_with(".log") {
                continue;
            }
            if mask & (libc::IN_DELETE | libc::IN_MOVED_FROM) != 0 && log == name {
                // Removed or rotated away: the next pump finds the new inode, or nothing.
                if let Some(t) = self.by_name.get(log).and_then(|i| self.tails.get_mut(*i)) {
                    t.dirty = true;
                }
                continue;
            }
            match self.by_name.get(log).copied() {
                Some(i) => {
                    if let Some(t) = self.tails.get_mut(i) {
                        t.dirty = true;
                    }
                }
                None => self.add_tail(log, None),
            }
        }
    }

    /// Read what every marked file appended, at most [`READ_PER_PUMP`] each. `true` when a line
    /// was read, so the caller draws a frame only when there is something new to draw.
    pub(crate) fn pump(&mut self) -> bool {
        self.last_pump = Some(Instant::now());
        if self
            .store_at
            .is_none_or(|t| t.elapsed().as_millis() >= STORE_EVERY_MS)
        {
            self.refresh_store();
        }
        self.pending = false;
        if self.ino_fd < 0 {
            // No watch: every file is a candidate, and new ones are found by listing.
            self.discover();
            for t in &mut self.tails {
                t.dirty = true;
            }
        }
        let mut fresh: Vec<Fresh> = Vec::new();
        let mut more = false;
        let mut skipped = false;
        for t in &mut self.tails {
            if !t.dirty {
                continue;
            }
            t.dirty = false;
            if read_tail(t, &mut fresh) {
                t.dirty = true;
                more = true;
            }
            skipped |= t.skipped;
        }
        self.flooded = more || skipped;
        if more {
            self.pending = true;
        }
        let got = !fresh.is_empty();
        for f in fresh {
            self.push(f, true);
        }
        got
    }

    /// The first visit: list the files, read the end of each (newest first, within
    /// [`BACKLOG_TOTAL`]), and order the result by time before it is numbered.
    fn first_load(&mut self) {
        let mut order: Vec<(i64, usize)> = self
            .tails
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let m = std::fs::metadata(&t.path).map_or(0, |m| m.mtime());
                (m, i)
            })
            .collect();
        order.sort_unstable_by_key(|o| std::cmp::Reverse(o.0));
        let mut budget = BACKLOG_TOTAL;
        for (_, i) in order {
            let Some(t) = self.tails.get_mut(i) else {
                continue;
            };
            let take = budget.min(BACKLOG_PER_FILE);
            budget = budget.saturating_sub(take);
            t.backlog = Some(take);
        }
        let mut fresh: Vec<Fresh> = Vec::new();
        for t in &mut self.tails {
            if read_tail(t, &mut fresh) {
                // Only the end was wanted; what lies between is not history anyone scrolled to.
                t.dirty = true;
            } else {
                t.dirty = false;
            }
        }
        fresh.sort_by_key(|f| f.nanos);
        for f in fresh {
            // History, not lines arriving now: kept out of the lines-per-second figure.
            self.push(f, false);
        }
        self.last_pump = Some(Instant::now());
    }

    /// List the logs directory and follow every log file not followed yet. A file found here is
    /// read from its start, unless the first visit gives it a backlog.
    fn discover(&mut self) {
        let Some(dir) = self.dir.clone() else {
            return;
        };
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return;
        };
        for e in rd.flatten() {
            let Some(name) = e.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if name.ends_with(".log") && !self.by_name.contains_key(&name) {
                self.add_tail(&name, if self.loaded { None } else { Some(0) });
            }
        }
    }

    fn add_tail(&mut self, file: &str, backlog: Option<u64>) {
        let Some(dir) = self.dir.as_ref() else {
            return;
        };
        let label = label_of(file);
        let src = match self.src_by_label.get(&label) {
            Some(s) => *s,
            None => {
                let s = u32::try_from(self.sources.len()).unwrap_or(u32::MAX);
                self.sources.push(label.clone());
                self.src_by_label.insert(label, s);
                s
            }
        };
        self.by_name.insert(file.to_string(), self.tails.len());
        self.tails.push(Tail {
            src,
            path: dir.join(file),
            ino: 0,
            offset: 0,
            idx_offset: 0,
            marks: Vec::new(),
            partial: Vec::new(),
            partial_off: 0,
            last_nanos: 0,
            last_level: Level::Info,
            backlog,
            skipping: false,
            skipped: false,
            catch_up: true,
            dirty: true,
        });
        self.pending = true;
    }

    /// Re-read where the logs are, how much they take, and how full their filesystem is.
    fn refresh_store(&mut self) {
        self.store_at = Some(Instant::now());
        let Some(dir) = self.dir.as_ref() else {
            return;
        };
        let (files, bytes, ended) = crate::registry::logs_store();
        let dir_s = dir.to_string_lossy().into_owned();
        let fill = crate::commands::fs_fill(&dir_s).map_or(0, |(pct, _)| pct);
        let fs_type = if is_tmpfs(dir) {
            "RAM (tmpfs), cleared at reboot"
        } else {
            "disk"
        };
        self.store = Some(StoreStats {
            dir: crate::ui::scrub(&dir_s),
            files,
            bytes,
            ended,
            fill,
            fs_type,
        });
    }

    /// Number a line, store it, and let it into the view if the filter does. `live`: the line was
    /// written just now and counts toward the rate (the first visit's history does not).
    fn push(&mut self, f: Fresh, live: bool) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        if live {
            let sec = u64::try_from(now_secs()).unwrap_or(0);
            match self.rate.back_mut() {
                Some((s, n)) if *s == sec => *n = n.saturating_add(1),
                _ => {
                    self.rate.push_back((sec, 1));
                    while self.rate.len() > RATE_WINDOW_S + 1 {
                        self.rate.pop_front();
                    }
                }
            }
        }
        let line = Line {
            seq,
            nanos: f.nanos,
            src: f.src,
            level: f.level,
            text: f.text,
        };
        let pass = self.passes(&line);
        let i = line.src as usize;
        if self.held.len() <= i {
            self.held.resize(i + 1, 0);
        }
        if let Some(n) = self.held.get_mut(i) {
            *n = n.saturating_add(1);
        }
        self.lines.push_back(line);
        if pass {
            self.view.push_back(seq);
        }
        while self.lines.len() > MAX_LINES {
            if let Some(old) = self.lines.pop_front() {
                if let Some(n) = self.held.get_mut(old.src as usize) {
                    *n = n.saturating_sub(1);
                }
                while self.view.front().is_some_and(|s| *s <= old.seq) {
                    self.view.pop_front();
                    self.sel = self.sel.saturating_sub(1);
                }
            }
        }
    }

    fn passes(&self, l: &Line) -> bool {
        l.level >= self.level
            && self.only_src.is_none_or(|s| s == l.src)
            && (self.terms.is_empty()
                || self
                    .terms
                    .iter()
                    .any(|t| contains_ascii_ci(l.text.as_bytes(), t)))
    }

    fn line_by_seq(&self, seq: u64) -> Option<&Line> {
        let front = self.lines.front()?.seq;
        let i = usize::try_from(seq.checked_sub(front)?).ok()?;
        self.lines.get(i)
    }

    /// Rebuild the view after the filter changed, keeping the selected line selected if it passes.
    fn refilter(&mut self) {
        let keep = self.view.get(self.sel).copied();
        self.view = self
            .lines
            .iter()
            .filter(|l| self.passes(l))
            .map(|l| l.seq)
            .collect();
        self.sel = match keep {
            Some(seq) => self.view.partition_point(|s| *s < seq),
            None => self.view.len().saturating_sub(1),
        }
        .min(self.view.len().saturating_sub(1));
    }

    fn set_search(&mut self, s: String) {
        self.terms = s
            .split('|')
            .map(|t| t.trim().to_ascii_lowercase().into_bytes())
            .filter(|t| !t.is_empty())
            .collect();
        self.search = s;
        self.refilter();
    }

    /// The selected line's index in `view`: the last one while following.
    fn cursor(&self) -> usize {
        if self.follow {
            self.view.len().saturating_sub(1)
        } else {
            self.sel.min(self.view.len().saturating_sub(1))
        }
    }

    /// Lines per second over the last full seconds of the window.
    fn per_second(&self) -> f64 {
        let now = u64::try_from(now_secs()).unwrap_or(0);
        let total: u64 = self
            .rate
            .iter()
            .filter(|(s, _)| *s < now && now.saturating_sub(*s) <= RATE_WINDOW_S as u64)
            .map(|(_, n)| *n)
            .sum();
        total as f64 / RATE_WINDOW_S as f64
    }

    /// A key on the Logs tab. `page` is the rows a screen shows.
    pub(crate) fn handle_key(&mut self, key: &[u8], page: usize) -> KeyOutcome {
        if self.editing {
            return self.edit_key(key);
        }
        let page = page.max(1);
        let last = self.view.len().saturating_sub(1);
        if key.len() >= 3 && key.first() == Some(&0x1b) && matches!(key.get(1), Some(b'[' | b'O')) {
            let cur = self.cursor();
            match key.get(2..).unwrap_or(&[]) {
                b"A" => {
                    self.follow = false;
                    self.sel = cur.saturating_sub(1);
                }
                b"B" => {
                    self.sel = cur.saturating_add(1).min(last);
                    self.follow = self.sel >= last;
                }
                b"5~" => {
                    self.follow = false;
                    self.sel = cur.saturating_sub(page);
                }
                b"6~" => {
                    self.sel = cur.saturating_add(page).min(last);
                    self.follow = self.sel >= last;
                }
                b"H" | b"1~" | b"7~" => {
                    self.follow = false;
                    self.sel = 0;
                }
                b"F" | b"4~" | b"8~" => {
                    self.follow = true;
                    self.sel = last;
                }
                // ← → switch tabs, as everywhere.
                _ => return KeyOutcome::Ignored,
            }
            return KeyOutcome::Consumed;
        }
        // vi keys, as everywhere else in `kern top`.
        match key {
            b"j" => return self.handle_key(b"\x1b[B", page),
            b"k" => return self.handle_key(b"\x1b[A", page),
            _ => {}
        }
        match key {
            // ESC UNDOES BEFORE IT QUITS. On every other tab a lone Esc leaves `kern top`; here a
            // reader who just filtered or scrolled expects it to undo that, and losing the session
            // to it was the first thing a test did. With nothing to undo it quits, as elsewhere.
            [0x1b] => {
                if self.search.is_empty()
                    && self.level == Level::Info
                    && self.only_src.is_none()
                    && self.follow
                {
                    return KeyOutcome::Ignored;
                }
                self.level = Level::Info;
                self.only_src = None;
                self.follow = true;
                self.set_search(String::new());
                KeyOutcome::Consumed
            }
            b"/" => {
                self.editing = true;
                KeyOutcome::Consumed
            }
            b"e" => {
                self.level = self.level.next_filter();
                self.refilter();
                KeyOutcome::Consumed
            }
            b"s" => {
                self.only_src = match self.only_src {
                    Some(_) => None,
                    None => self
                        .view
                        .get(self.cursor())
                        .and_then(|seq| self.line_by_seq(*seq))
                        .map(|l| l.src),
                };
                self.refilter();
                KeyOutcome::Consumed
            }
            b"f" => {
                self.follow = !self.follow;
                if !self.follow {
                    self.sel = last;
                }
                KeyOutcome::Consumed
            }
            b"c" => {
                self.held.clear();
                self.lines.clear();
                self.view.clear();
                self.sel = 0;
                self.follow = true;
                KeyOutcome::Consumed
            }
            b"x" => KeyOutcome::Overlay(match self.export_csv() {
                Ok((path, n)) => format!(
                    "logs exported\n\n  {n} line(s), the ones the filter shows, to\n  {}\n\n  \
                     columns: timestamp (UTC, the line's time mark), object (the box), message\n  \
                     a cell that starts with = + - @ is prefixed with ' so a spreadsheet does not \
                     run it as a formula\n  the file is readable by you only (0600): logs carry \
                     whatever the boxes printed",
                    crate::ui::scrub(&path.display().to_string())
                ),
                Err(e) => format!("logs NOT exported\n\n  {e}"),
            }),
            b"\r" | b"\n" => match self
                .view
                .get(self.cursor())
                .and_then(|s| self.line_by_seq(*s))
            {
                Some(l) => KeyOutcome::Overlay(format!(
                    "log line\n\n  time    {}\n  source  {}\n  level   {}\n\n{}",
                    local_stamp(l.nanos),
                    self.sources.get(l.src as usize).map_or("-", String::as_str),
                    match l.level {
                        Level::Info => "-",
                        Level::Warn => "warning",
                        Level::Error => "error",
                    },
                    wrap(&l.text, 100)
                )),
                None => KeyOutcome::Consumed,
            },
            _ => KeyOutcome::Ignored,
        }
    }

    fn edit_key(&mut self, key: &[u8]) -> KeyOutcome {
        match key {
            [0x1b] => {
                self.editing = false;
                self.set_search(String::new());
            }
            b"\r" | b"\n" => self.editing = false,
            [0x7f] | [0x08] => {
                let mut s = self.search.clone();
                s.pop();
                self.set_search(s);
            }
            k if k.first().is_some_and(|c| *c >= 0x20) && k.first() != Some(&0x7f) => {
                if let Ok(t) = std::str::from_utf8(k) {
                    let t: String = t.chars().filter(|c| !c.is_control()).collect();
                    if !t.is_empty() && self.search.chars().count() < 200 {
                        let mut s = self.search.clone();
                        s.push_str(&t);
                        self.set_search(s);
                    }
                }
            }
            _ => {}
        }
        KeyOutcome::Consumed
    }

    /// The tab's body, `body_rows` lines at most.
    pub(crate) fn render(&self, p: &Palette, width: usize, body_rows: usize) -> String {
        let (b, c, d, g, y, r, z) = (p.b, p.c, p.d, p.g, p.y, p.r, p.z);
        let mut s = String::new();
        let state = match (self.follow, self.flooded) {
            (true, false) => format!("{g}live{z}"),
            // Said, so a reader does not take the stream for every line written.
            (true, true) => format!("{y}live, skipping: a box writes faster than this shows{z}"),
            (false, _) => format!("{y}paused{z}"),
        };
        let mut filters: Vec<String> = Vec::new();
        if !self.search.is_empty() {
            filters.push(format!("search {c}{}{z}", crate::ui::scrub(&self.search)));
        }
        if self.level != Level::Info {
            filters.push(format!("level {c}{}{z}", self.level.word()));
        }
        if let Some(src) = self.only_src.and_then(|i| self.sources.get(i as usize)) {
            filters.push(format!("source {c}{src}{z}"));
        }
        let filters = if filters.is_empty() {
            String::new()
        } else {
            format!("   {d}·{z} {}", filters.join(&format!(" {d}·{z} ")))
        };
        s.push_str(&format!(
            "\n  {b}LOGS{z}  {state}  {d}{} shown of {} · {} box(es) · {:.1} lines/s read{z}{filters}\n",
            self.view.len(),
            self.lines.len(),
            self.held.iter().filter(|n| **n > 0).count(),
            self.per_second(),
        ));
        if self.editing {
            s.push_str(&format!(
                "  {b}search:{z} {}{b}█{z}  {d}(a|b matches either; case ignored){z}\n",
                crate::ui::scrub(&self.search)
            ));
        } else {
            s.push_str(&self.store_line(p, width));
        }
        // Sized by the boxes that have lines here, not by every log file found.
        let src_w = self
            .sources
            .iter()
            .enumerate()
            .filter(|(i, _)| self.held.get(*i).is_some_and(|n| *n > 0))
            .map(|(_, x)| x.chars().count())
            .max()
            .unwrap_or(6)
            .clamp(6, 24);
        s.push_str(&format!(
            "  {b}  {:<21} {:<src_w$} MESSAGE{z}\n",
            "TIME", "SOURCE"
        ));
        let rows = body_rows.saturating_sub(4).max(1);
        if self.view.is_empty() {
            let why = if self.lines.is_empty() {
                "no box has written anything yet; lines appear here as they are written"
            } else {
                "nothing passes the filter ([Esc] in search clears it, [e] cycles the level)"
            };
            s.push_str(&format!("  {d}{why}{z}\n"));
            return s;
        }
        let cur = self.cursor();
        let start = cur
            .saturating_add(1)
            .saturating_sub(rows)
            .min(self.view.len().saturating_sub(rows));
        let end = start.saturating_add(rows).min(self.view.len());
        let msg_w = width.saturating_sub(2 + 2 + 21 + 1 + src_w + 1).max(10);
        let colors: [&str; 5] = if c.is_empty() {
            ["", "", "", "", ""]
        } else {
            ["\x1b[36m", "\x1b[35m", "\x1b[34m", "\x1b[32m", "\x1b[33m"]
        };
        for i in start..end {
            let Some(l) = self.view.get(i).and_then(|seq| self.line_by_seq(*seq)) else {
                continue;
            };
            let mark = if i == cur && !self.follow {
                format!("{b}›{z} ")
            } else {
                "  ".to_string()
            };
            let src = self.sources.get(l.src as usize).map_or("-", String::as_str);
            let sc = colors
                .get(l.src as usize % colors.len())
                .copied()
                .unwrap_or("");
            let lc = match l.level {
                Level::Error => r,
                Level::Warn => y,
                Level::Info => "",
            };
            let text: String = l.text.chars().take(msg_w).collect();
            s.push_str(&format!(
                "  {mark}{d}{:<21}{z} {sc}{:<src_w$}{z} {lc}{text}{z}\n",
                local_stamp(l.nanos),
                trunc_chars(src, src_w),
            ));
        }
        let (above, below) = (start, self.view.len().saturating_sub(end));
        if above > 0 || below > 0 {
            s.push_str(&format!("  {d}… {above} above · {below} below{z}\n"));
        }
        s
    }

    /// Where the logs are, how much they take, and how full the store is, coloured by how close it
    /// is to the point where lines are dropped.
    fn store_line(&self, p: &Palette, width: usize) -> String {
        let (d, y, r, z) = (p.d, p.y, p.r, p.z);
        let Some(st) = self.store.as_ref() else {
            return "\n".to_string();
        };
        let pct = st.fill;
        let (col, warn) = if pct >= FILL_CRIT_PCT {
            (
                r,
                " FULL SOON: a box's output is dropped when it fills (its log says how much)",
            )
        } else if pct >= FILL_WARN_PCT {
            (y, " filling: output is dropped when it is full")
        } else {
            (d, "")
        };
        let ended = if st.ended > 0 {
            format!(
                ", {} of it from boxes that ended (`kern prune`)",
                human_bytes(st.ended)
            )
        } else {
            String::new()
        };
        // What matters first, so a narrow screen cuts the path and not the warning.
        let line = format!(
            "store {pct} % full{warn} · {} in {} file(s){ended} · {} · {}",
            human_bytes(st.bytes),
            st.files,
            st.fs_type,
            st.dir,
        );
        let line: String = line.chars().take(width.saturating_sub(4)).collect();
        format!("  {col}{line}{z}\n")
    }

    /// The tab's key line.
    pub(crate) fn footer(&self, p: &Palette) -> String {
        let (d, z) = (p.d, p.z);
        if self.editing {
            return format!(
                "{d}type to search   [{z}⏎{d}] keep   [{z}Esc{d}] clear   [{z}Backspace{d}] delete{z}"
            );
        }
        format!(
            "{d}[{z}/{d}]search [{z}e{d}]level [{z}s{d}]ource [{z}f{d}]ollow [{z}⏎{d}]line [{z}x{d}] CSV [{z}c{d}]lear   [{z}↑↓ PgUp/PgDn End{d}]   [{z}Tab{d}] next   [{z}q{d}] quit   [{z}?{d}] help{z}"
        )
    }

    /// Write the lines the filter shows as CSV, in the working directory (or the home directory
    /// when that is not writable), to a file only the user can read.
    fn export_csv(&self) -> Result<(PathBuf, usize), String> {
        let name = format!("kern-logs-{}.csv", file_stamp());
        let mut dirs: Vec<PathBuf> = Vec::new();
        if let Ok(cwd) = std::env::current_dir() {
            dirs.push(cwd);
        }
        if let Some(home) = crate::global_env("HOME") {
            dirs.push(PathBuf::from(home));
        }
        let mut last = String::from("no directory to write to");
        for dir in dirs {
            let path = dir.join(&name);
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path);
            let mut file = match file {
                Ok(f) => f,
                Err(e) => {
                    last = format!("{}: {e}", path.display());
                    continue;
                }
            };
            let mut out: Vec<u8> = Vec::with_capacity(self.view.len().saturating_mul(96));
            out.extend_from_slice(b"timestamp,object,message\n");
            let mut n = 0usize;
            for seq in &self.view {
                let Some(l) = self.line_by_seq(*seq) else {
                    continue;
                };
                let ts = if l.nanos == 0 {
                    String::new()
                } else {
                    crate::commands::boxlog::fmt_mark(l.nanos)
                };
                let src = self.sources.get(l.src as usize).map_or("", String::as_str);
                out.extend_from_slice(csv_cell(&ts).as_bytes());
                out.push(b',');
                out.extend_from_slice(csv_cell(src).as_bytes());
                out.push(b',');
                out.extend_from_slice(csv_cell(&l.text).as_bytes());
                out.push(b'\n');
                n += 1;
            }
            return match file.write_all(&out).and_then(|()| file.flush()) {
                Ok(()) => Ok((path, n)),
                Err(e) => {
                    let _ = std::fs::remove_file(&path);
                    Err(format!("{}: {e}", path.display()))
                }
            };
        }
        Err(last)
    }

    fn watch(&mut self) {
        if self.ino_fd >= 0 {
            return;
        }
        let Some(dir) = self.dir.as_ref() else {
            return;
        };
        let Ok(c) = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(dir.as_os_str()))
        else {
            return;
        };
        // SAFETY: no arguments but flags.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return;
        }
        let mask = libc::IN_MODIFY
            | libc::IN_CREATE
            | libc::IN_MOVED_TO
            | libc::IN_DELETE
            | libc::IN_MOVED_FROM;
        // SAFETY: a descriptor just made and a NUL-terminated path.
        if unsafe { libc::inotify_add_watch(fd, c.as_ptr(), mask) } < 0 {
            // SAFETY: closing the descriptor made above, owned by nothing else.
            unsafe { libc::close(fd) };
            return;
        }
        self.ino_fd = fd;
    }

    fn unwatch(&mut self) {
        if self.ino_fd >= 0 {
            // SAFETY: a descriptor this struct owns; closing it removes its watches.
            unsafe { libc::close(self.ino_fd) };
            self.ino_fd = -1;
        }
    }
}

/// `kern logs --all`: the output of every box in the log store in ONE stream, ordered by time,
/// each line prefixed `<box>  | ` as `compose logs` prefixes a service. With `-f` it stays on the
/// store, boxes started later included, until interrupted.
///
/// What the Logs tab of `kern top` shows, for a script: the same reading (offsets, the time index,
/// escape sequences and control characters removed) and none of the screen's shortcuts, so no gap
/// is skipped however fast a box writes. `tail` is per box, as `compose logs --tail` is per
/// service; `window` keeps a line the index cannot place in time, as `kern logs` does.
pub(crate) fn print_all(
    tail: Option<usize>,
    follow: bool,
    timestamps: bool,
    window: (Option<u64>, Option<u64>),
) -> Result<(), crate::error::Error> {
    let dir = crate::registry::logs_dir()
        .map_err(|e| crate::error::Error::Sandbox(format!("logs dir: {e}")))?;
    let mut all = AllLogs {
        dir,
        tails: Vec::new(),
        by_name: HashMap::new(),
        labels: Vec::new(),
        width: 0,
    };
    all.discover();
    let mut first: Vec<Fresh> = Vec::new();
    for t in &mut all.tails {
        let mut mine: Vec<Fresh> = Vec::new();
        while read_tail(t, &mut mine) {}
        if let Some(n) = tail {
            let cut = mine.len().saturating_sub(n);
            mine.drain(..cut);
        }
        first.extend(mine);
    }
    first.retain(|f| in_window(f.nanos, window));
    first.sort_by_key(|f| f.nanos);
    all.width = first
        .iter()
        .filter_map(|f| all.labels.get(f.src as usize))
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(0);
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    if all.emit(&mut out, &first, timestamps).is_err() {
        // The reader went away (`| head`): that is the end of the stream, not an error.
        return Ok(());
    }
    if out.flush().is_err() || !follow {
        return Ok(());
    }
    // FOLLOW: woken by the directory's inotify watch, or every second without one.
    let mut view = LogView::default();
    view.dir = Some(all.dir.clone());
    view.watch();
    loop {
        let mut pfd = libc::pollfd {
            fd: view.ino_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one pollfd on this frame; a `-1` descriptor is ignored by `poll`.
        unsafe { libc::poll(&mut pfd, 1, 1000) };
        if view.ino_fd >= 0 {
            let mut buf = [0u8; 8192];
            // SAFETY: a descriptor `view` owns and a buffer of the length given.
            while unsafe { libc::read(view.ino_fd, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
        }
        all.discover();
        let mut fresh: Vec<Fresh> = Vec::new();
        for t in &mut all.tails {
            while read_tail(t, &mut fresh) {}
        }
        fresh.retain(|f| in_window(f.nanos, window));
        for f in &fresh {
            if let Some(l) = all.labels.get(f.src as usize) {
                all.width = all.width.max(l.chars().count());
            }
        }
        if all.emit(&mut out, &fresh, timestamps).is_err() || out.flush().is_err() {
            return Ok(());
        }
    }
}

/// The files `kern logs --all` follows.
struct AllLogs {
    dir: PathBuf,
    tails: Vec<Tail>,
    by_name: HashMap<String, usize>,
    labels: Vec<String>,
    width: usize,
}

impl AllLogs {
    /// Follow every `*.log` in the store not followed yet, from its start.
    fn discover(&mut self) {
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let mut names: Vec<String> = rd
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .filter(|n| n.ends_with(".log") && !self.by_name.contains_key(n))
            .collect();
        names.sort();
        for name in names {
            let src = u32::try_from(self.labels.len()).unwrap_or(u32::MAX);
            self.labels.push(label_of(&name));
            self.by_name.insert(name.clone(), self.tails.len());
            self.tails.push(Tail {
                src,
                path: self.dir.join(&name),
                ino: 0,
                offset: 0,
                idx_offset: 0,
                marks: Vec::new(),
                partial: Vec::new(),
                partial_off: 0,
                last_nanos: 0,
                last_level: Level::Info,
                backlog: None,
                skipping: false,
                skipped: false,
                catch_up: false,
                dirty: true,
            });
        }
    }

    fn emit(
        &self,
        out: &mut impl std::io::Write,
        lines: &[Fresh],
        timestamps: bool,
    ) -> std::io::Result<()> {
        let w = self.width;
        for f in lines {
            let label = self.labels.get(f.src as usize).map_or("-", String::as_str);
            if timestamps {
                let ts = if f.nanos == 0 {
                    "-".to_string()
                } else {
                    crate::commands::boxlog::fmt_mark(f.nanos)
                };
                writeln!(out, "{label:<w$}  | {ts} {}", f.text)?;
            } else {
                writeln!(out, "{label:<w$}  | {}", f.text)?;
            }
        }
        Ok(())
    }
}

/// Inside `--since`/`--until`, or not placed in time at all (kept, as `kern logs` keeps it).
fn in_window(nanos: u64, (since, until): (Option<u64>, Option<u64>)) -> bool {
    nanos == 0 || (since.is_none_or(|s| nanos >= s) && until.is_none_or(|u| nanos <= u))
}

/// Read what `t` appended since the last call, at most [`READ_PER_PUMP`]. `true` when more remains.
fn read_tail(t: &mut Tail, out: &mut Vec<Fresh>) -> bool {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&t.path);
    let Ok(file) = file else {
        return false;
    };
    let Ok(meta) = file.metadata() else {
        return false;
    };
    let len = meta.len();
    if meta.ino() != t.ino || len < t.offset {
        // A new file at the same name (a rotation), or the same one cut shorter: start over.
        t.ino = meta.ino();
        t.offset = 0;
        t.idx_offset = 0;
        t.marks.clear();
        t.partial.clear();
        t.partial_off = 0;
        t.skipping = false;
    }
    if let Some(b) = t.backlog.take() {
        if t.offset == 0 && len > b {
            t.offset = len - b;
            t.partial_off = t.offset;
            t.skipping = true;
        }
    }
    read_marks_delta(t);
    t.skipped = false;
    if t.offset >= len {
        return false;
    }
    // FURTHER BEHIND THAN IS WORTH READING: skip to the newest `CATCH_UP` bytes, say so in the
    // stream, and drop the line the jump lands inside.
    if t.catch_up && len - t.offset > CATCH_UP && !t.skipping {
        let gap = len - CATCH_UP - t.offset;
        let at = t.offset;
        t.offset = len - CATCH_UP;
        t.partial.clear();
        t.partial_off = t.offset;
        t.skipping = true;
        t.skipped = true;
        out.push(Fresh {
            nanos: crate::commands::boxlog::mark_for(&t.marks, at).unwrap_or(t.last_nanos),
            src: t.src,
            level: Level::Info,
            text: format!(
                "… {} skipped here: this box writes faster than a screen can show (`kern logs` \
                 keeps them, within its rotation)",
                human_bytes(gap)
            )
            .into_boxed_str(),
        });
    }
    let want = (len - t.offset).min(READ_PER_PUMP);
    let Ok(want_usize) = usize::try_from(want) else {
        return false;
    };
    let mut data = vec![0u8; want_usize];
    let mut got = 0usize;
    while got < data.len() {
        let Some(rest) = data.get_mut(got..) else {
            break;
        };
        match file.read_at(rest, t.offset + got as u64) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    data.truncate(got);
    t.offset += got as u64;
    split_lines(t, &data, out);
    // Marks wholly behind the read position are spent, except the last one, which the next line
    // may still fall after.
    let keep_from = t
        .marks
        .partition_point(|(o, _)| *o <= t.partial_off)
        .saturating_sub(1);
    t.marks.drain(..keep_from);
    t.offset < len
}

/// Append the newly written `<log>.idx` records to `t.marks`.
fn read_marks_delta(t: &mut Tail) {
    let idx = crate::commands::boxlog::idx_path(&t.path);
    let Ok(f) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&idx)
    else {
        return;
    };
    let Ok(len) = f.metadata().map(|m| m.len()) else {
        return;
    };
    if len < t.idx_offset {
        // The index was compacted (rewritten coarser) or restarted: read it again.
        t.idx_offset = 0;
        t.marks.clear();
    }
    let rec = crate::commands::boxlog::MARK_LEN as u64;
    let whole = (len - t.idx_offset) / rec * rec;
    if whole == 0 {
        return;
    }
    let Ok(n) = usize::try_from(whole.min(1024 * rec)) else {
        return;
    };
    let mut buf = vec![0u8; n];
    let Ok(got) = f.read_at(&mut buf, t.idx_offset) else {
        return;
    };
    let got = got / crate::commands::boxlog::MARK_LEN * crate::commands::boxlog::MARK_LEN;
    for c in buf
        .get(..got)
        .unwrap_or(&[])
        .chunks_exact(crate::commands::boxlog::MARK_LEN)
    {
        let mut o = [0u8; 8];
        let mut w = [0u8; 8];
        o.copy_from_slice(c.get(..8).unwrap_or(&[0; 8]));
        w.copy_from_slice(c.get(8..16).unwrap_or(&[0; 8]));
        t.marks.push((u64::from_le_bytes(o), u64::from_le_bytes(w)));
    }
    t.idx_offset += got as u64;
}

/// Cut `data` (which follows `t.partial`) into lines.
fn split_lines(t: &mut Tail, data: &[u8], out: &mut Vec<Fresh>) {
    let mut rest = data;
    while let Some(nl) = rest.iter().position(|c| *c == b'\n') {
        let (head, tail) = rest.split_at(nl);
        rest = tail.get(1..).unwrap_or(&[]);
        let start = t.partial_off;
        let line_len = (t.partial.len() + head.len()) as u64;
        if t.skipping {
            t.skipping = false;
            t.partial.clear();
        } else if t.partial.is_empty() {
            emit(t, start, head, out);
        } else {
            let mut whole = std::mem::take(&mut t.partial);
            whole.extend_from_slice(head);
            emit(t, start, &whole, out);
        }
        t.partial_off = start + line_len + 1;
    }
    if !t.skipping {
        t.partial.extend_from_slice(rest);
    } else {
        // Still inside the cut first line: what was read is not a line's start.
        t.partial_off += rest.len() as u64;
    }
    if t.partial.len() > MAX_PARTIAL {
        let start = t.partial_off;
        let whole = std::mem::take(&mut t.partial);
        emit(t, start, &whole, out);
        t.partial_off = start + whole.len() as u64;
    }
}

/// One raw line at file offset `start`, cleaned, levelled and timed.
fn emit(t: &mut Tail, start: u64, raw: &[u8], out: &mut Vec<Fresh>) {
    let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
    let text = clean(raw);
    let level = match level_of(&text) {
        Some(l) => l,
        None if is_continuation(&text) => t.last_level,
        None => Level::Info,
    };
    t.last_level = level;
    let nanos = crate::commands::boxlog::mark_for(&t.marks, start).unwrap_or(t.last_nanos);
    t.last_nanos = nanos;
    out.push(Fresh {
        nanos,
        src: t.src,
        level,
        text: text.into_boxed_str(),
    });
}

/// The text of a raw line as it may be shown: UTF-8 (lossy), escape sequences removed WHOLE, tabs
/// as four spaces, every other control and direction-override character dropped, cut at
/// [`MAX_LINE_CHARS`].
fn clean(raw: &[u8]) -> String {
    // THE COMMON CASE, COPIED: a line of printable ASCII has nothing to remove or translate.
    // MEASURED 0.47 us a line through the general path below.
    if raw.iter().all(|c| (0x20..0x7f).contains(c)) {
        let cut = raw.get(..raw.len().min(MAX_LINE_CHARS)).unwrap_or(raw);
        let mut out = String::from_utf8_lossy(cut).into_owned();
        if raw.len() > MAX_LINE_CHARS {
            out.push('…');
        }
        return out;
    }
    let s = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(s.len().min(MAX_LINE_CHARS + 4));
    let mut it = s.chars().peekable();
    let mut n = 0usize;
    while let Some(ch) = it.next() {
        if ch == '\u{1b}' {
            match it.peek() {
                // CSI: parameters and intermediates up to a final byte in 0x40..=0x7e.
                Some('[') => {
                    it.next();
                    for c in it.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&c) {
                            break;
                        }
                    }
                }
                // OSC: up to BEL or ST (ESC \).
                Some(']') => {
                    it.next();
                    while let Some(c) = it.next() {
                        if c == '\u{7}' {
                            break;
                        }
                        if c == '\u{1b}' && it.peek() == Some(&'\\') {
                            it.next();
                            break;
                        }
                    }
                }
                // A two-byte escape.
                Some(_) => {
                    it.next();
                }
                None => {}
            }
            continue;
        }
        if ch == '\t' {
            out.push_str("    ");
            n += 4;
        } else if kern_common::is_terminal_unsafe(ch) {
            continue;
        } else {
            out.push(ch);
            n += 1;
        }
        if n >= MAX_LINE_CHARS {
            out.push('…');
            break;
        }
    }
    out
}

/// The level a line states, when it states one.
///
/// Read from the forms logs actually use: an upper-case word (`ERROR`, `WARN`, Postgres `FATAL:`,
/// Python `CRITICAL`), a lower-case one followed by a colon (`error:`), logfmt `level=error`, JSON
/// `"level":"error"`, and an exception or traceback header. A lower-case word alone is not enough:
/// "0 errors" is not an error.
///
/// ONE PASS OVER THE LINE, no allocation. The first version searched each of eighteen forms across
/// the whole line in turn: MEASURED 2.4 us a line, 78 % of the cost of reading a line, which under
/// a box printing 290k lines a second was a whole core. Here each position is looked at once, and
/// only the forms that can start with the byte found there are compared.
fn level_of(text: &str) -> Option<Level> {
    const HEAD: usize = 400;
    let b = text.as_bytes();
    let head = b.get(..b.len().min(HEAD)).unwrap_or(b);
    let mut low_buf = [0u8; HEAD];
    for (d, s) in low_buf.iter_mut().zip(head) {
        *d = s.to_ascii_lowercase();
    }
    let low = low_buf.get(..head.len()).unwrap_or(&[]);
    let (mut warn, mut exception, mut colon, mut caused) = (false, false, false, false);
    for (i, (&c, &l)) in head.iter().zip(low).enumerate() {
        let word = |w: &[u8]| word_at(head, i, w);
        let at = |w: &[u8]| low.get(i..).is_some_and(|r| r.starts_with(w));
        match c {
            b'E' if word(b"ERROR") || word(b"EMERG") => return Some(Level::Error),
            b'F' if word(b"FATAL") => return Some(Level::Error),
            b'P' if word(b"PANIC") => return Some(Level::Error),
            b'C' if word(b"CRITICAL") => return Some(Level::Error),
            b'A' if word(b"ALERT") => return Some(Level::Error),
            b'W' if word(b"WARN") || word(b"WARNING") => warn = true,
            _ => {}
        }
        match l {
            b'e' if at(b"error:") => return Some(Level::Error),
            b'e' if at(b"exception") => exception = true,
            b'f' if at(b"fatal:") => return Some(Level::Error),
            b'p' if at(b"panic:") => return Some(Level::Error),
            b'l' if at(b"level=error") || at(b"level=fatal") => return Some(Level::Error),
            b'l' if at(b"level=warn") => warn = true,
            b'"' if at(b"\"level\":\"error\"") || at(b"\"level\":\"fatal\"") => {
                return Some(Level::Error)
            }
            b'"' if at(b"\"level\":\"warn") => warn = true,
            b't' if at(b"traceback (most recent call last)") => return Some(Level::Error),
            b'w' if at(b"warning:") || at(b"warn:") => warn = true,
            b'c' if at(b"caused by") => caused = true,
            b':' => colon = true,
            _ => {}
        }
    }
    if exception && (caused || colon) {
        return Some(Level::Error);
    }
    warn.then_some(Level::Warn)
}

/// `w` at `i` in `hay` as a whole word (bounded by non-letters).
fn word_at(hay: &[u8], i: usize, w: &[u8]) -> bool {
    hay.get(i..).is_some_and(|r| r.starts_with(w))
        && (i == 0 || !hay.get(i - 1).is_some_and(u8::is_ascii_alphabetic))
        && !hay.get(i + w.len()).is_some_and(u8::is_ascii_alphabetic)
}

/// A line that continues the one before it: a stack frame, a `Caused by`, an elided frame count.
fn is_continuation(text: &str) -> bool {
    let t = text.trim_start();
    text.starts_with(' ')
        || t.starts_with("at ")
        || t.starts_with("Caused by")
        || (t.starts_with("...") && t.ends_with("more"))
}

/// `needle` (already lower-case ASCII) in `hay`, ignoring ASCII case. No allocation.
fn contains_ascii_ci(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if hay.len() < needle.len() {
        return false;
    }
    (0..=hay.len() - needle.len()).any(|i| {
        hay.get(i..i + needle.len()).is_some_and(|w| {
            w.iter()
                .zip(needle)
                .all(|(a, b)| a.to_ascii_lowercase() == *b)
        })
    })
}

/// The box a log file belongs to: `<box>-<pid>.log` -> `<box>`.
fn label_of(file: &str) -> String {
    let stem = file.strip_suffix(".log").unwrap_or(file);
    let name = match stem.rsplit_once('-') {
        Some((n, pid))
            if !n.is_empty() && !pid.is_empty() && pid.bytes().all(|c| c.is_ascii_digit()) =>
        {
            n
        }
        _ => stem,
    };
    crate::ui::scrub(name)
}

/// One CSV cell (RFC 4180): quoted when it holds a comma, a quote or a line break, quotes doubled.
/// A cell starting with `=`, `+`, `-` or `@` is prefixed with `'`, the OWASP guard against a
/// spreadsheet running a box's output as a formula.
fn csv_cell(v: &str) -> String {
    let guarded = if v.starts_with(['=', '+', '-', '@']) {
        format!("'{v}")
    } else {
        v.to_string()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

/// `YYYY-MM-DD HH:MM:SS.t` in the local zone, tenths because a time mark starts at 100 ms; `-` when
/// no mark was recorded.
fn local_stamp(nanos: u64) -> String {
    if nanos == 0 {
        return "-".to_string();
    }
    let Ok(t) = i64::try_from(nanos / 1_000_000_000) else {
        return "-".to_string();
    };
    // SAFETY: `localtime_r` reads `t` and writes only `tm`, on this stack frame.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r((&raw const t).cast(), &mut tm) }.is_null() {
        return "-".to_string();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{}",
        i64::from(tm.tm_year) + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        (nanos / 100_000_000) % 10
    )
}

/// `YYYYMMDD-HHMMSS` now, local, for the export's file name.
fn file_stamp() -> String {
    let t = now_secs();
    // SAFETY: as in `local_stamp`.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r((&raw const t).cast(), &mut tm) }.is_null() {
        return t.to_string();
    }
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        i64::from(tm.tm_year) + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

/// Whether `p` is on a tmpfs, that is in RAM.
fn is_tmpfs(p: &std::path::Path) -> bool {
    // TMPFS_MAGIC.
    kern_common::fs_magic(p) == Some(0x0102_1994)
}

/// `512 B`, `3.1 MiB`: a byte count for a person.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1024.0;
    let mut u = 0usize;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS.get(u).copied().unwrap_or("TiB"))
}

/// Seconds since the epoch, now.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

fn trunc_chars(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// `text` broken into lines of at most `w` characters, each indented two spaces.
fn wrap(text: &str, w: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    chars
        .chunks(w.max(1))
        .map(|c| format!("  {}", c.iter().collect::<String>()))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn tail_at(path: &Path) -> Tail {
        Tail {
            src: 0,
            path: path.to_path_buf(),
            ino: 0,
            offset: 0,
            idx_offset: 0,
            marks: Vec::new(),
            partial: Vec::new(),
            partial_off: 0,
            last_nanos: 0,
            last_level: Level::Info,
            backlog: None,
            skipping: false,
            skipped: false,
            catch_up: true,
            dirty: true,
        }
    }

    fn texts(v: &[Fresh]) -> Vec<String> {
        v.iter().map(|f| f.text.to_string()).collect()
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kern-logview-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::create_dir_all(&d);
        d
    }

    fn append(p: &Path, b: &[u8]) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .unwrap_or_else(|e| panic!("open {}: {e}", p.display()));
        f.write_all(b)
            .unwrap_or_else(|e| panic!("write {}: {e}", p.display()));
    }

    /// ONLY WHAT WAS APPENDED IS READ, AND A LINE CUT BY A READ IS JOINED, NOT SPLIT.
    #[test]
    fn a_tail_reads_only_new_bytes_and_joins_a_line_across_reads() {
        let d = tmpdir("tail");
        let p = d.join("web-123.log");
        append(&p, b"one\ntw");
        let mut t = tail_at(&p);
        let mut out = Vec::new();
        assert!(!read_tail(&mut t, &mut out));
        assert_eq!(texts(&out), ["one"]);
        out.clear();
        append(&p, b"o\nthree\n");
        read_tail(&mut t, &mut out);
        assert_eq!(
            texts(&out),
            ["two", "three"],
            "the cut line must come back whole"
        );
        out.clear();
        read_tail(&mut t, &mut out);
        assert!(out.is_empty(), "nothing new, nothing read");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A ROTATION STARTS OVER: a new file at the same name is read from its start.
    #[test]
    fn a_rotated_log_is_read_from_its_start() {
        let d = tmpdir("rot");
        let p = d.join("db-9.log");
        append(&p, b"old line\n");
        let mut t = tail_at(&p);
        let mut out = Vec::new();
        read_tail(&mut t, &mut out);
        std::fs::rename(&p, d.join("db-9.log.1")).unwrap_or_else(|e| panic!("rename: {e}"));
        // LONGER than the old one, so only the inode can tell the files apart: a shorter one would
        // be caught by the length check alone (the first version of this test was, and a sabotage
        // of the inode check went unnoticed).
        append(&p, b"new line one\nnew line two\n");
        out.clear();
        read_tail(&mut t, &mut out);
        assert_eq!(texts(&out), ["new line one", "new line two"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// THE FIRST VISIT READS THE END, AND THE LINE THE CUT FELL INSIDE IS DROPPED, NOT SHOWN HALF.
    #[test]
    fn a_backlog_starts_at_a_whole_line() {
        let d = tmpdir("back");
        let p = d.join("api-1.log");
        append(&p, b"aaaaaaaaaa\nbbbb\ncccc\n");
        let mut t = tail_at(&p);
        t.backlog = Some(8);
        let mut out = Vec::new();
        read_tail(&mut t, &mut out);
        assert_eq!(texts(&out), ["cccc"], "the cut `bb` must not appear");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A FILE FURTHER BEHIND THAN `CATCH_UP` IS SKIPPED TO ITS NEWEST BYTES, and the gap is said.
    #[test]
    fn a_flooding_file_is_skipped_to_its_newest_lines_and_the_gap_said() {
        let d = tmpdir("flood");
        let p = d.join("yes-1.log");
        append(&p, b"first\n");
        let mut t = tail_at(&p);
        let mut out = Vec::new();
        read_tail(&mut t, &mut out);
        let mut flood = Vec::new();
        for i in 0..100_000u32 {
            flood.extend_from_slice(format!("line {i:06}\n").as_bytes());
        }
        append(&p, &flood);
        out.clear();
        read_tail(&mut t, &mut out);
        let txt = texts(&out);
        assert!(
            txt.first().is_some_and(|l| l.contains("skipped")),
            "the gap must be said first: {:?}",
            txt.first()
        );
        assert_eq!(
            txt.last().map(String::as_str),
            Some("line 099999"),
            "the newest line is read"
        );
        let read: usize = txt.iter().skip(1).map(|l| l.len() + 1).sum();
        assert!(
            read as u64 <= CATCH_UP,
            "no more than CATCH_UP is read: {read}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// THE TIME OF A LINE IS THE MARK IT FALLS AFTER, read from the index beside the log.
    #[test]
    fn a_line_takes_the_time_of_the_mark_it_falls_after() {
        let d = tmpdir("marks");
        let p = d.join("w-5.log");
        append(&p, b"first\nsecond\n");
        let mut idx = Vec::new();
        for (o, n) in [(0u64, 1_000_000_000u64), (6, 2_000_000_000)] {
            idx.extend_from_slice(&o.to_le_bytes());
            idx.extend_from_slice(&n.to_le_bytes());
        }
        std::fs::write(crate::commands::boxlog::idx_path(&p), idx)
            .unwrap_or_else(|e| panic!("idx: {e}"));
        let mut t = tail_at(&p);
        let mut out = Vec::new();
        read_tail(&mut t, &mut out);
        let times: Vec<u64> = out.iter().map(|f| f.nanos).collect();
        assert_eq!(times, [1_000_000_000, 2_000_000_000]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// NOTHING A BOX PRINTS CAN MOVE THE CURSOR OR REPAINT: the sequence goes whole.
    #[test]
    fn escape_sequences_are_removed_whole_and_controls_dropped() {
        assert_eq!(clean(b"\x1b[31mred\x1b[0m ok"), "red ok");
        assert_eq!(clean(b"\x1b]0;title\x07after"), "after");
        assert_eq!(clean(b"\x1b]8;;http://x\x1b\\link"), "link");
        assert_eq!(clean(b"a\rb\x08c\x00d"), "abcd");
        assert_eq!(clean(b"\tat x"), "    at x");
        assert_eq!(clean("\u{202e}rtl".as_bytes()), "rtl");
        let long = vec![b'x'; MAX_LINE_CHARS * 2];
        assert_eq!(clean(&long).chars().count(), MAX_LINE_CHARS + 1);
    }

    /// THE LEVEL IS READ FROM THE FORMS LOGS USE, AND A STACK TRACE INHERITS IT.
    #[test]
    fn levels_are_read_and_a_stack_trace_inherits_its_level() {
        assert_eq!(level_of("2026 ERROR [x] boom"), Some(Level::Error));
        assert_eq!(
            level_of("UTC [57] FATAL:  password authentication failed"),
            Some(Level::Error)
        );
        assert_eq!(level_of("level=error msg=x"), Some(Level::Error));
        assert_eq!(
            level_of(r#"{"level":"error","msg":"x"}"#),
            Some(Level::Error)
        );
        assert_eq!(
            level_of("2026-03-26 16:31:56 WARN  [io.qua.config] key"),
            Some(Level::Warn)
        );
        assert_eq!(level_of("warning: deprecated"), Some(Level::Warn));
        assert_eq!(
            level_of("built with 0 errors"),
            None,
            "a lower-case word alone is not a level"
        );
        assert_eq!(
            level_of("TERRORS"),
            None,
            "a word inside another word is not a level"
        );
        let d = tmpdir("lvl");
        let p = d.join("kc-1.log");
        append(
            &p,
            b"ERROR boom\n\tat org.x.Y(Y.java:1)\nCaused by: z\n\t... 1 more\nall good\n",
        );
        let mut t = tail_at(&p);
        let mut out = Vec::new();
        read_tail(&mut t, &mut out);
        let lv: Vec<Level> = out.iter().map(|f| f.level).collect();
        assert_eq!(
            lv,
            [
                Level::Error,
                Level::Error,
                Level::Error,
                Level::Error,
                Level::Info
            ]
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// THE EXPORT IS RFC 4180, AND A CELL CANNOT RUN AS A FORMULA.
    #[test]
    fn csv_cells_are_quoted_and_guarded() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_cell("+1"), "'+1");
        assert_eq!(csv_cell("@cmd"), "'@cmd");
    }

    /// THE FILTER: levels, a source, and `a|b` alternatives, case ignored.
    #[test]
    fn the_filter_takes_level_source_and_alternatives() {
        let mut v = LogView::default();
        for (src, level, text) in [
            (0u32, Level::Info, "GET /health 200"),
            (1, Level::Error, "database is down"),
            (0, Level::Warn, "slow query"),
            (1, Level::Info, "Retrying connection"),
        ] {
            v.push(
                Fresh {
                    nanos: 1,
                    src,
                    level,
                    text: text.into(),
                },
                true,
            );
        }
        assert_eq!(v.view.len(), 4);
        v.level = Level::Warn;
        v.refilter();
        assert_eq!(v.view.len(), 2);
        v.level = Level::Info;
        v.set_search("DOWN|retrying".to_string());
        assert_eq!(v.view.len(), 2, "either alternative, case ignored");
        v.set_search(String::new());
        v.only_src = Some(0);
        v.refilter();
        assert_eq!(v.view.len(), 2);
    }

    /// ESC UNDOES A FILTER BEFORE IT QUITS: with a search or a level set it clears them and the
    /// tab keeps the key; with nothing set it is not the tab's, and `kern top` quits as elsewhere.
    #[test]
    fn esc_clears_the_filters_before_it_is_a_quit() {
        let mut v = LogView::default();
        v.set_search("x".to_string());
        v.level = Level::Warn;
        assert!(matches!(v.handle_key(&[0x1b], 10), KeyOutcome::Consumed));
        assert!(v.search.is_empty() && v.level == Level::Info);
        assert!(matches!(v.handle_key(&[0x1b], 10), KeyOutcome::Ignored));
        // While typing a search, every key is the search's, `q` included.
        assert!(matches!(v.handle_key(b"/", 10), KeyOutcome::Consumed));
        assert!(matches!(v.handle_key(b"q", 10), KeyOutcome::Consumed));
        assert_eq!(v.search, "q");
    }

    /// THE MEMORY IS BOUNDED: past the cap the oldest lines go, and the view with them.
    #[test]
    fn the_oldest_lines_leave_past_the_cap() {
        let mut v = LogView::default();
        for i in 0..(MAX_LINES + 10) {
            v.push(
                Fresh {
                    nanos: 1,
                    src: 0,
                    level: Level::Info,
                    text: format!("l{i}").into(),
                },
                false,
            );
        }
        assert_eq!(v.lines.len(), MAX_LINES);
        assert_eq!(v.view.len(), MAX_LINES);
        assert_eq!(
            v.lines.front().map(|l| l.text.to_string()),
            Some("l10".to_string())
        );
        assert!(v.view.iter().all(|s| v.line_by_seq(*s).is_some()));
        assert_eq!(
            v.held.first().copied(),
            Some(MAX_LINES as u32),
            "the per-box count follows the ring"
        );
    }

    /// Not a check: the cost of one line through the pipeline, printed (`--ignored --nocapture`).
    #[test]
    #[ignore]
    fn bench_line_cost() {
        let line = b"2026-03-26 16:32:08,251 WARN  [org.hibernate.engine.jdbc.spi.SqlExceptionHelper] (JPA Startup Thread) SQL Error: 0, SQLState: 28P01\n";
        let mut data = Vec::new();
        for _ in 0..200_000 {
            data.extend_from_slice(line);
        }
        let mut t = tail_at(Path::new("/nonexistent"));
        let mut out = Vec::with_capacity(200_000);
        let t0 = Instant::now();
        split_lines(&mut t, &data, &mut out);
        let el = t0.elapsed();
        eprintln!(
            "split+clean+level: {} lines in {:?} = {:.0} ns/line",
            out.len(),
            el,
            el.as_nanos() as f64 / out.len() as f64
        );
        let t0 = Instant::now();
        let mut n = 0;
        for f in &out {
            if level_of(&f.text).is_some() {
                n += 1;
            }
        }
        let el = t0.elapsed();
        eprintln!(
            "level_of alone: {:.0} ns/line ({n})",
            el.as_nanos() as f64 / out.len() as f64
        );
        let t0 = Instant::now();
        for _ in 0..200_000 {
            let _ = clean(line);
        }
        eprintln!(
            "clean alone: {:.0} ns/line",
            t0.elapsed().as_nanos() as f64 / 200_000.0
        );
        let mut v = LogView::default();
        let t0 = Instant::now();
        for f in out {
            v.push(f, true);
        }
        eprintln!(
            "push: {:.0} ns/line",
            t0.elapsed().as_nanos() as f64 / 200_000.0
        );
    }

    /// `kern logs --all` READS EVERY BOX AND ORDERS BY TIME, prefixing each line with its box.
    #[test]
    fn all_logs_are_merged_by_time_and_prefixed() {
        let d = tmpdir("all");
        let mark = |log: &Path, marks: &[(u64, u64)]| {
            let mut idx = Vec::new();
            for (o, n) in marks {
                idx.extend_from_slice(&o.to_le_bytes());
                idx.extend_from_slice(&n.to_le_bytes());
            }
            std::fs::write(crate::commands::boxlog::idx_path(log), idx)
                .unwrap_or_else(|e| panic!("idx: {e}"));
        };
        let a = d.join("web-1.log");
        let b = d.join("database-2.log");
        append(&a, b"a1\na2\n");
        append(&b, b"b1\n");
        mark(&a, &[(0, 10), (3, 30)]);
        mark(&b, &[(0, 20)]);
        let mut all = AllLogs {
            dir: d.clone(),
            tails: Vec::new(),
            by_name: HashMap::new(),
            labels: Vec::new(),
            width: 8,
        };
        all.discover();
        let mut fresh = Vec::new();
        for t in &mut all.tails {
            while read_tail(t, &mut fresh) {}
        }
        fresh.sort_by_key(|f| f.nanos);
        let mut out = Vec::new();
        all.emit(&mut out, &fresh, false)
            .unwrap_or_else(|e| panic!("emit: {e}"));
        let text = String::from_utf8_lossy(&out);
        assert_eq!(
            text.lines().collect::<Vec<_>>(),
            ["web       | a1", "database  | b1", "web       | a2"],
            "ordered by time across boxes, each line prefixed with its box"
        );
        // The window keeps a line the index cannot place, as `kern logs` does.
        assert!(in_window(0, (Some(5), Some(6))));
        assert!(in_window(20, (Some(10), Some(30))));
        assert!(!in_window(40, (Some(10), Some(30))));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_log_file_names_its_box() {
        assert_eq!(label_of("kcu-a-1-719914.log"), "kcu-a-1");
        assert_eq!(label_of("web-12.log"), "web");
        assert_eq!(label_of("noid.log"), "noid");
    }
}
