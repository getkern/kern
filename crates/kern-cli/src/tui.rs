//! `kern top` - a small, dependency-free task-manager TUI (alternate screen, tabs, live refresh,
//! keyboard nav; each data tab shows a live item count, e.g. `Boxes (3)`). Seven tabs: **Overview** (host CPU / RAM / load + the box aggregate), **Boxes** (the
//! per-box table - MEM/CPU/PIDS plus HEALTH and PORTS (parity with `kern ps`) - with lifecycle
//! actions: stop/pause/unpause/logs), **Runs** (aggregate `kern limit` throughput - rate/sec, avg
//! setup latency, peak, total + sparkline; a `⚡` on the tab marks live activity), **Builds** (`kern
//! build` history), **Profiles** (the reusable
//! specs you attach by prefix - vcpu/vgpio/vdisk; a vdisk *selects* one of the read-only physical
//! disks, and its `[[disk]]` is materialised from that choice, never hand-created) and **Storage** (the
//! concrete data layer - physical disks read-only + named volumes you create). Host stats come straight
//! from `/proc`. Pure `libc` termios + ANSI, no curses/ratatui dependency.
//!
//! A `?` from any tab opens a full-keymap help overlay (the footer always advertises it), so the whole
//! interface is discoverable without docs.
//!
//! Interaction is a small [`Mode`] state machine - `Nav` plus three modals (`Overlay` read-only pane,
//! `Form` input, `Confirm` for destructive actions). Profile edits are written **surgically** (see
//! [`crate::toml_surgery`]) so a single edit never rewrites the whole file and drop the user's other
//! sections.
//!
//! Robustness: the terminal is put in raw mode + the alternate screen on entry and **restored on
//! drop** (so a panic or early return still leaves a sane terminal). `ISIG` is disabled, so Ctrl-C
//! arrives as a byte we handle as "quit" - clean teardown, no stranded alt-screen.

use crate::commands::{fmt_uptime, human_bytes};
use crate::registry;
use crate::ui::Palette;
use std::collections::HashMap;
use std::io::Write;
use std::time::Instant;

const TABS: [&str; 9] = [
    "Overview",
    "Boxes",
    // `kern limit`'s, named after the verb. It was "Runs" while that verb was `kern run`; since
    // `kern run` starts a box, as `docker run` does, a "Runs" tab beside "Boxes" read as a second
    // kind of box. Every box, `run` or `box`, is on the Boxes tab.
    "Limits",
    "Images",
    "Builds",
    "Profiles",
    "Storage",
    "Sandboxes",
    "Logs",
];
/// How long the FIRST poll waits before the first periodic refresh, in milliseconds.
///
/// The opening frame cannot show a host CPU% because that figure is a delta and there is no
/// previous sample yet. This is how long the reader looks at a `0%` before the real one arrives.
/// It matches the gap `snapshot()` leaves between its own two samples on the piped path.
const FIRST_WAIT_MS: i32 = 120;

/// The steady refresh cadence in milliseconds, used from the second wait onward.
const STEADY_WAIT_MS: i32 = 1000;

const TAB_OVERVIEW: usize = 0;
const TAB_BOXES: usize = 1;
const TAB_RUNS: usize = 2;
const TAB_IMAGES: usize = 3;
const TAB_BUILDS: usize = 4;
const TAB_PROFILES: usize = 5;
const TAB_STORAGE: usize = 6;
/// The SDK and MCP sandboxes: the ones running and the ones that finished (see `history.rs`).
const TAB_SANDBOXES: usize = 7;
/// Every box's output in one stream: see [`crate::logview`].
const TAB_LOGS: usize = 8;

/// What the TUI is doing right now: plain navigation, or a modal layered over it.
enum Mode {
    Nav,
    /// A read-only text pane (box logs, profile/volume detail). Any key closes it.
    Overlay(String),
    /// A multi-field text form (volume create, profile new/edit).
    Form(Form),
    /// The "new profile" kind picker (Profiles tab `n`): choose vcpu / vgpio / vdisk / disk.
    PickKind,
    /// Where the sandbox history is kept (Sandboxes tab `m`): memory / disk / off, or clear it.
    PickHistory,
    /// A destructive action awaiting `y`/`n`.
    Confirm {
        prompt: String,
        action: Pending,
    },
}

/// A destructive action held until the user confirms it.
enum Pending {
    RemoveVolume(String),
    PruneVolumes,
    DeleteProfile(&'static str, String), // (section header, profile name)
    RemoveImage(String),                 // image ref (as shown in the Images tab)
    PruneImages,                         // reclaim orphaned build layers
    DeleteBuild(String),                 // build id
    StopBox(String),                     // box name, from the Boxes tab
    // THE BULK ACTIONS CARRY THEIR TARGETS, not just a count, and that is deliberate: the list is
    // re-read every tick, so an action that re-derived "everything" at confirm time could act on a
    // set the operator never saw. What was on screen when they pressed `D` is what gets deleted.
    RemoveAllImages(Vec<String>),
    DeleteAllBuilds(Vec<String>),
    RemoveAllVolumes(Vec<String>),
    StopAllBoxes(Vec<String>),
    ClearHistory, // every row of the sandbox history, in memory and on disk
}

/// A multi-field input form. `active` is the focused field; typing edits its value.
struct Form {
    title: String,
    fields: Vec<Field>,
    active: usize,
    submit: Submit,
    error: Option<String>,
    /// Whether the "Advanced" fold is expanded (advanced fields hidden until then).
    show_advanced: bool,
}

/// Indices of the fields currently on screen: every common field + the fold row, plus the advanced
/// fields only when the fold is open. Navigation and rendering both walk this list so a collapsed
/// advanced group is truly skipped (you can't Tab into a hidden field).
fn visible_fields(form: &Form) -> Vec<usize> {
    form.fields
        .iter()
        .enumerate()
        .filter(|(_, f)| f.divider || !f.advanced || form.show_advanced)
        .map(|(i, _)| i)
        .collect()
}

/// The fields the cursor can actually land on: visible ones minus the read-only "none on this host"
/// notes, so Tab/↑/↓ glide straight over hardware the machine doesn't have.
fn nav_fields(form: &Form) -> Vec<usize> {
    visible_fields(form)
        .into_iter()
        .filter(|&i| !form.fields[i].is_dead_info())
        .collect()
}

/// Canonicalize a pick option/value token for MATCHING (edit-seed dedup). Only i2c has an ambiguous
/// short form: a bus may be saved bare (`"1"`) or as `"i2c-1"` but the host scan lists `"/dev/i2c-1"`:
/// fold all three to the `/dev/` form so they compare equal. Everything else is returned unchanged.
/// Uses the resolver's `canon_i2c_bus` (SINGLE source of truth) so the form and the runtime can't
/// drift on what counts as the same bus.
fn canon_pick_token(label: &str, s: &str) -> String {
    if label == "i2c" {
        if let Some(p) = crate::config::canon_i2c_bus(s) {
            return p;
        }
    }
    s.to_string()
}

#[derive(Clone)]
struct Field {
    label: &'static str,
    /// Shown dim inside an empty field as a placeholder (text fields), or as the toggle's caption.
    hint: &'static str,
    value: String,
    /// A boolean switch (`[x]`/`[ ]`, Space flips) rather than free-text - for keys like `persistent`
    /// that are a bool, so a beginner never types "true"/"false". On = non-empty value; off = empty.
    toggle: bool,
    /// Checkbox options: the host devices DETECTED for this field. Non-empty ⇒ a "pick" field - the
    /// user toggles which are selected (←/→ to move, Space to check) instead of typing a `/dev/…`
    /// path, so a wrong path is impossible. `value` (what `apply_form` saves) stays in sync = the
    /// checked options, comma-joined. `cur` is the highlighted option.
    options: Vec<String>,
    sel: Vec<bool>,
    cur: usize,
    /// A rare/expert knob: hidden under the "Advanced" fold so a beginner sees only the common fields.
    advanced: bool,
    /// The "▸ Advanced" fold row itself (not an input) - Space/←→ expand or collapse the advanced group.
    divider: bool,
    /// A device kind the host DOESN'T have: while its value is empty it's a read-only "none on this
    /// host" note (nothing to type, skipped by navigation), so a beginner is never asked to invent a
    /// path for hardware that isn't there. If an edited profile pre-fills a value, it becomes editable
    /// so the setting is still visible and removable.
    info: bool,
    /// SINGLE-select pick (a radio group): a field that holds ONE value (e.g. `backend` = one GPIO id).
    /// Ticking an option clears the others, so the invalid multi-value state is unrepresentable.
    radio: bool,
}

impl Field {
    /// A free-text field with a dim placeholder.
    fn text(label: &'static str, hint: &'static str) -> Self {
        Field {
            label,
            hint,
            value: String::new(),
            toggle: false,
            options: Vec::new(),
            sel: Vec::new(),
            cur: 0,
            advanced: false,
            divider: false,
            info: false,
            radio: false,
        }
    }

    /// The "▸ Advanced" fold row that hides the rare fields until the user expands it.
    fn divider() -> Self {
        Field {
            divider: true,
            ..Field::text("", "")
        }
    }

    /// A read-only "this host has no such device" note (see `info`). `msg` shows dim after the label.
    fn info(label: &'static str, msg: &'static str) -> Self {
        Field {
            info: true,
            ..Field::text(label, msg)
        }
    }

    /// True while this is a dead "none on this host" note - no value, nothing to edit, skip in nav.
    fn is_dead_info(&self) -> bool {
        self.info && self.value.is_empty()
    }

    /// A boolean toggle (off by default). Space/`y`/`n` set it; any non-empty value reads as on.
    fn toggle(label: &'static str, hint: &'static str) -> Self {
        Field {
            toggle: true,
            ..Field::text(label, hint)
        }
    }

    /// A checkbox picker over detected devices - foolproof: you can only choose what exists.
    fn pick(label: &'static str, hint: &'static str, options: Vec<String>) -> Self {
        let n = options.len();
        Field {
            options,
            sel: vec![false; n],
            ..Field::text(label, hint)
        }
    }

    /// A SINGLE-select picker (radio group): holds one value. Ticking one option clears the rest, so a
    /// field that must be one value (e.g. `backend`) can't be put into an invalid multi-value state.
    fn radio(label: &'static str, hint: &'static str, options: Vec<String>) -> Self {
        Field {
            radio: true,
            ..Field::pick(label, hint, options)
        }
    }

    /// True for a checkbox picker (has detected device options).
    fn is_pick(&self) -> bool {
        !self.options.is_empty()
    }

    /// Re-derive `value` (comma-joined checked options) after a toggle, so `apply_form` sees it.
    fn sync_pick_value(&mut self) {
        self.value = self
            .options
            .iter()
            .zip(&self.sel)
            .filter(|(_, on)| **on)
            .map(|(o, _)| o.clone())
            .collect::<Vec<_>>()
            .join(",");
    }

    /// For an EDIT form: check the options that match a pre-filled comma/space `value`. A saved device
    /// that ISN'T detected on this host (e.g. a profile authored on a Pi, edited on a desktop) is kept
    /// as a checked extra option, so editing never silently drops it.
    ///
    /// Matching is done on a canonical form so an i2c bus saved bare (`"1"` or `"i2c-1"`) still matches
    /// the host-scanned `"/dev/i2c-1"` instead of appending a DUPLICATE checkbox for the same bus.
    fn seed_pick_selection(&mut self) {
        if !self.is_pick() {
            return;
        }
        let label = self.label;
        let want: Vec<String> = self
            .value
            .split([',', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| canon_pick_token(label, s))
            .collect();
        self.sel.fill(false);
        for tok in want {
            match self
                .options
                .iter()
                .position(|o| canon_pick_token(label, o) == tok)
            {
                Some(i) => self.sel[i] = true,
                None => {
                    self.options.push(tok);
                    self.sel.push(true);
                }
            }
        }
        self.sync_pick_value();
    }
}

/// What a submitted [`Form`] does.
enum Submit {
    CreateVolume,
    /// Rename and/or re-quota an existing named volume (Storage tab `e`).
    EditVolume {
        orig_name: String,
    },
    /// Write a `vcpu`/`vgpio`/`vdisk` profile back to `kern.toml` (all three go through one path).
    SaveProfile {
        section: &'static str,
        /// The name being edited (so a rename can rewrite the old block), or `None` for a new profile.
        orig_name: Option<String>,
    },
}

/// One row in the Profiles tab.
struct ProfRow {
    section: &'static str,
    name: String,
    summary: String,
}

/// A box row with its frame-to-frame CPU%.
struct Row {
    name: String,
    pid: i32,
    uptime: u64,
    mem: Option<u64>,
    cpu_pct: f64,
    tasks: Option<u64>,
    paused: bool,
    /// Health-check state (`healthy`/`unhealthy`/`starting`, empty if the box has no `--health-cmd`) -
    /// the same signal `kern ps` shows, so a compose stack's readiness is visible in the TUI too.
    health: String,
    /// Published-ports summary (e.g. `8080->80`), empty if none - parity with `kern ps`.
    ports: String,
    /// The pod (compose stack) this box belongs to, empty for a standalone box - drives the `kern ps`
    /// tree grouping in the Boxes tab.
    pod: String,
    /// How this box DEVIATES from the secure default - `net:host` and/or `root-mapped`, empty when
    /// fully isolated (the common case). Flags only the LESS-confined boxes, never a vanity badge.
    iso: String,
    /// Extra-confinement badge: `egress` and/or `landlock` (0.6.7 policies), empty when neither applies.
    /// Unlike `iso` (which flags LESS-confined boxes), this marks the MORE-confined ones.
    sec: String,
    /// The supervisor is dead and the box's PID 1 is not: `kern ps` calls this `orphaned`.
    ///
    /// CARRIED BECAUSE THE TWO VIEWS MUST NOT DISAGREE ABOUT ONE BOX. `ps` routes its column through
    /// `box_status`, which the CLI documents as the single source of truth and which answers
    /// `orphaned` before it answers anything else. This table asked `health_of` directly, which is a
    /// second definition of a box's state and had drifted: MEASURED by SIGKILLing three boxes'
    /// supervisors, `kern ps` printed `orphaned` and `kern top` printed `running` for the same three
    /// pids, in the same second. A dashboard that contradicts the list is worse than either alone,
    /// because the reader has no way to tell which one is lying.
    orphaned: bool,
    /// Processes the OOM killer ended in this box while it runs on (a child, under the per-process
    /// default), the count behind `inspect`'s `State.OOMKilled`; 0 for none.
    oom_kills: u64,
    /// Docker's `RestartCount`, the one `inspect` reports: a `--restart` box run again counts here.
    restarts: u32,
    /// How it reaches out: `nat`, `pod`, `host` or `none`; empty when its init could not be read
    /// (between two runs of a `--restart` box), which must not count as `none`. See [`net_kind`].
    net: &'static str,
    /// Between two runs of its `--restart` policy: systemd is about to start it again and no
    /// process runs now (`pid` is 0 and shown as `-`). `kern ps` lists it `restarting (code)`.
    restarting: bool,
    /// The code its last run exited with, while systemd holds it; `None` otherwise.
    last_code: Option<i32>,
}

/// Restores the terminal on drop: leave the alternate screen, show the cursor, re-enable line
/// wrap, and put `termios` back. Runs even on panic / early return.
struct TermGuard {
    orig: libc::termios,
    fd: i32,
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        ALT_SCREEN_TID.store(0, std::sync::atomic::Ordering::SeqCst);
        let mut out = std::io::stdout();
        let _ = out.write_all(b"\x1b[?7h\x1b[?1049l\x1b[?25h");
        let _ = out.flush();
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig) };
    }
}

/// Saved `(termios, fd)` for the signal handler to restore. `TermGuard::drop` covers a normal
/// return and a panic (unwind runs Drop), but a fatal signal - `SIGTERM` (`kill`), `SIGHUP` (an SSH
/// disconnect), `SIGINT`/`SIGQUIT` via `kill` - terminates WITHOUT unwinding, leaving the terminal
/// in raw mode + the alternate screen. The handler below restores it. Set once before the handlers
/// are installed; kern is single-threaded, so the handler's read is sound.
static mut RESTORE: Option<(libc::termios, libc::c_int)> = None;

/// Async-signal-safe: only `tcsetattr` + `write(2)` (both AS-safe), then re-raise with the default
/// disposition so the exit status still reflects the signal.
extern "C" fn restore_on_signal(sig: libc::c_int) {
    // SAFETY: RESTORE is written once before any handler can fire; single-threaded, no concurrent
    // writer. `addr_of` avoids forming a reference to the mutable static.
    unsafe {
        if let Some((t, fd)) = *std::ptr::addr_of!(RESTORE) {
            libc::tcsetattr(fd, libc::TCSANOW, &t);
            const RESET: &[u8] = b"\x1b[?7h\x1b[?1049l\x1b[?25h";
            libc::write(1, RESET.as_ptr().cast(), RESET.len());
        }
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// Install [`restore_on_signal`] for the signals that would otherwise kill us mid-TUI.
fn install_restore_handlers() {
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = restore_on_signal as *const () as libc::sighandler_t;
    unsafe {
        libc::sigemptyset(&mut sa.sa_mask);
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// Terminal size (cols, rows) via `TIOCGWINSZ`, defaulting to 80×24.
fn term_size() -> (usize, usize) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 {
        (ws.ws_col as usize, ws.ws_row.max(10) as usize)
    } else {
        (80, 24)
    }
}

/// An inotify fd watching the box registry dir for box create/remove/rename, or `-1` if unavailable.
/// `kern top` polls this alongside stdin, so a box lifecycle change (from ANY kern process) refreshes
/// the view INSTANTLY instead of on the next 1 s tick - the "no lag" property. Best-effort.
fn setup_registry_watch() -> i32 {
    use std::os::unix::ffi::OsStrExt;
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if fd < 0 {
        return -1;
    }
    if let Ok(dir) = crate::registry::dir() {
        let _ = std::fs::create_dir_all(&dir);
        if let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) {
            let mask = libc::IN_CREATE
                | libc::IN_DELETE
                | libc::IN_MOVED_TO
                | libc::IN_MOVED_FROM
                | libc::IN_CLOSE_WRITE;
            if unsafe { libc::inotify_add_watch(fd, c.as_ptr(), mask) } >= 0 {
                return fd;
            }
        }
    }
    unsafe { libc::close(fd) };
    -1
}

/// Split one `read` of the terminal into individual key events, keeping an escape sequence (the
/// arrows, Home/End, PgUp/PgDn) whole.
///
/// A sequence is `ESC` then `[` or `O`, then parameter bytes, then a final byte in `0x40..=0x7e`.
/// Anything else is one byte, one key. A lone `ESC`, or a sequence that arrived truncated, stays a
/// single event: that is exactly what a bare Escape keypress looks like, and treating it as the
/// start of something longer would swallow the key that closes a modal.
fn split_keys(buf: &[u8], out: &mut std::collections::VecDeque<Vec<u8>>) {
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == 0x1b && i + 1 < buf.len() && (buf[i + 1] == b'[' || buf[i + 1] == b'O') {
            let mut j = i + 2;
            while j < buf.len() && !(0x40..=0x7e).contains(&buf[j]) {
                j += 1;
            }
            let end = (j + 1).min(buf.len());
            out.push_back(buf[i..end].to_vec());
            i = end;
        } else {
            out.push_back(vec![buf[i]]);
            i += 1;
        }
    }
}

/// Run the interactive TUI. Returns when the user quits (`q`, `Esc`, or `Ctrl-C`).
pub fn run() -> Result<(), crate::error::Error> {
    let fd = 0; // stdin
    let mut orig: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut orig) } != 0 {
        return snapshot(); // not a real tty after all - one-shot fallback
    }
    // The screen refreshes for as long as it is open: its GPU rows read one running `nvidia-smi`.
    start_gpu_stream();
    let mut raw = orig;
    raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
    raw.c_iflag &= !(libc::IXON | libc::ICRNL);
    raw.c_cc[libc::VMIN] = 0;
    raw.c_cc[libc::VTIME] = 0;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
        return snapshot();
    }
    // Save the cooked termios for the signal handler, then install handlers (before the alt screen)
    // so a SIGHUP/SIGTERM mid-TUI still restores the terminal. `orig`/`fd` are `Copy`.
    unsafe { *std::ptr::addr_of_mut!(RESTORE) = Some((orig, fd)) };
    install_restore_handlers();
    let _guard = TermGuard { orig, fd };

    let mut out = std::io::stdout();
    let _ = out.write_all(b"\x1b[?1049h\x1b[?25l\x1b[2J"); // alt screen, hide cursor, clear
    let _ = out.flush();
    // Set AFTER the guard exists, so every path out of here clears it again.
    ALT_SCREEN_TID.store(this_tid(), std::sync::atomic::Ordering::SeqCst);

    let p = Palette::detect();
    let mut tab = 0usize;
    let mut sel = 0usize; // highlighted row on the active list tab
    let mut mode = Mode::Nav;
    let mut prev: HashMap<i32, (u64, Instant)> = HashMap::new();
    let mut prev_cpu: Option<(u64, u64)> = None;
    let mut prev_runs: Option<(u64, std::time::Instant)> = None;
    let mut runs_hist: Vec<f64> = Vec::new(); // reader-side sparkline ring for the Limits tab
    let mut prev_box: Option<(u64, std::time::Instant)> = None;
    let mut box_hist: Vec<f64> = Vec::new(); // reader-side sparkline ring for the box-start rate
                                             // Cleared by the first poll that times out; see the comment at that poll for why.
    let mut first_wait = true;

    // Live wake: an inotify watch on the box registry dir so a box created/removed by ANY kern
    // process shows up INSTANTLY, with zero poll lag. Best-effort - if inotify or the dir is
    // unavailable, the 1 s timer below still keeps the view fresh (just not sub-second on changes).
    let ino_fd = setup_registry_watch();

    // Key events already split off a read but not yet dispatched. A terminal hands us SEVERAL bytes
    // in one `read` whenever keys arrive faster than one loop turn: a held key repeating, a paste,
    // or any laggy link, which over ssh to a board is the normal case rather than the exception.
    // Acting on `buf[0]` and discarding the rest lost every key but the first, so a burst ending in
    // `q` never quit. They are queued here and dispatched one per turn instead.
    let mut keyq: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();

    // Measured once at the start, off this thread, so the first visit to Storage normally finds the
    // sizes already there; after that only while the tab is on screen.
    let mut sizer = VolumeSizer::default();
    sizer.kick();
    // The Logs tab: inert (no watch, no read) until the tab is shown.
    let mut logs = crate::logview::LogView::default();
    // When the last periodic refresh ran. The refresh is owed every `STEADY_WAIT_MS` whatever else
    // wakes the loop: the Logs tab wakes it up to twenty times a second, and a refresh that waited
    // for a quiet second would then never come.
    let mut last_refresh = Instant::now();
    // Set by a wake that has nothing new for the screen; the next turn skips the paint once.
    let mut skip_paint = false;
    let mut snap = refresh_full(
        &mut prev,
        &mut prev_cpu,
        &mut prev_runs,
        &mut runs_hist,
        &mut prev_box,
        &mut box_hist,
        tab,
    );
    loop {
        let (cols, term_rows) = term_size();
        let list_len = tab_list_len(
            tab,
            &snap.rows,
            &snap.profs,
            &snap.vols,
            &snap.builds,
            snap.builds_total,
            &snap.images,
            &snap.sbx,
        );
        if sel >= list_len {
            sel = list_len.saturating_sub(1);
        }

        // THE STORAGE TAB REPAIRS ITS OWN LIST, HERE, and this is the only place that can be
        // right. A tab change happens in four key handlers (`Tab`, `h`, `l`, the arrow escapes)
        // plus the mutating actions, and asking each of them to remember the walk is asking for
        // the one that forgets. This runs after `tab` has settled and before anything is drawn, so
        // the frame that first shows Storage already has real sizes: no empty column, no flash.
        //
        // It costs one `is_none()` scan of a list that is at most a few dozen long on every other
        // frame, and it cannot loop: after the walk every entry is `Some`.
        //
        // THE SIZES COME FROM A CHILD, NOT FROM THIS THREAD. Measuring is a recursive walk of every
        // volume: MEASURED on a desktop with 556 volumes, 60 ms on the first visit and again on
        // every 1 s refresh while the tab was shown (5.8 % of a core), on the thread that reads
        // keys. A child (`kern __volume-sizes`) measures now, its output is read when `poll` says
        // so, and every frame shows the latest sizes it has. Not a thread: this process runs
        // lifecycle actions in-process, and kern's fork paths assume one thread.
        if tab == TAB_STORAGE {
            sizer.want_fresh();
        }
        sizer.fill(&mut snap.vols);
        logs.set_active(tab == TAB_LOGS);
        // The same repair for the two count-only lists, and the condition is `total > 0` rather
        // than `!is_empty()`: an empty store leaves the vec legitimately empty, and testing the vec
        // alone would re-read the directory on every single frame of an empty tab.
        if tab == TAB_BUILDS
            && (snap.builds.is_empty()
                || builds_reach(
                    sel,
                    snap.builds.len(),
                    snap.builds_total,
                    term_rows.saturating_sub(17).max(1),
                ))
            && snap.builds_total > 0
        {
            snap.set_builds(builds_listing(crate::listing::Detail::Read));
        }
        if tab == TAB_IMAGES && snap.images.is_empty() && snap.images_total > 0 {
            snap.set_images(crate::commands::image_entries_with(
                crate::listing::Detail::Read,
            ));
        }
        // A wake that brought nothing to show (a log event whose read is still paced) draws no
        // frame: under a writing box those were most of the wakes.
        if std::mem::take(&mut skip_paint) {
            // Straight to the wait below.
        } else {
            let frame = render(
                &p,
                tab,
                &snap.rows,
                &snap.host,
                &snap.profs,
                &snap.vols,
                &snap.builds,
                snap.builds_total,
                &snap.images,
                snap.images_total,
                cols,
                term_rows,
                sel,
                &mode,
                &logs,
            );
            // The frame is already capped to `term_rows` by `render` itself - one place decides the
            // height, so this loop cannot disagree with it.
            // Clear each line to end-of-line (`\x1b[K`) so a shorter/blank line in the new frame wipes
            // any leftover text from the previous one (no residue, no flicker), then erase everything
            // below the frame (`\x1b[J`) in case the new frame has fewer lines.
            let painted = frame.replace('\n', "\x1b[K\n");
            let _ = out.write_all(b"\x1b[H"); // cursor home
            let _ = out.write_all(painted.as_bytes());
            let _ = out.write_all(b"\x1b[J");
            let _ = out.flush();
        }

        // Wait for a key, a registry change (inotify), or ~1 s (the CPU%/stats window). A registry
        // change wakes us instantly (no poll lag); the timer keeps stats fresh even when idle.
        // Queued keys are dispatched WITHOUT polling: they already arrived, and making the user's
        // second keystroke wait on a poll is what turned a burst into a frozen-looking TUI.
        if keyq.is_empty() {
            let mut pfds = [
                libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: ino_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                // The volume sizer's output while a measurement runs (see `VolumeSizer`).
                libc::pollfd {
                    fd: sizer.fd().unwrap_or(-1),
                    events: libc::POLLIN,
                    revents: 0,
                },
                // The Logs tab's watch on the logs directory, while the tab is shown.
                libc::pollfd {
                    fd: logs.fd().unwrap_or(-1),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // An absent descriptor (no inotify watch, no measurement running) is `-1`, which `poll`
            // ignores by definition: the slot reports nothing rather than a stale descriptor.
            let nfds = pfds.len();
            // THE FIRST WAIT IS SHORT, AND ONLY THE FIRST. Host CPU% is a DELTA: the opening
            // frame has no previous sample, so it necessarily reads 0% and stays wrong until the
            // second refresh. With a flat 1000 ms that is a full second of a screen showing zeros,
            // which is what the TUI felt slow for: measured, the first frame lands at 6 ms and the
            // first TRUE one at 1011 ms. 120 ms is the interval `snapshot()` already uses between
            // its two samples on the non-interactive path, so the two front ends agree on what a
            // usable CPU window costs, and it is short enough to read as instant.
            //
            // It is not kept short: a 120 ms cadence would re-walk `/proc` eight times a second
            // for a number that does not move that fast. After the first timeout this returns to
            // 1000 ms for the rest of the session.
            let period = if first_wait {
                FIRST_WAIT_MS
            } else {
                STEADY_WAIT_MS
            };
            let since = i32::try_from(last_refresh.elapsed().as_millis()).unwrap_or(i32::MAX);
            let refresh_in = period.saturating_sub(since).max(0);
            let timeout_ms = logs.wait_ms().map_or(refresh_in, |w| {
                refresh_in.min(i32::try_from(w).unwrap_or(i32::MAX))
            });
            if crate::eintr::poll(&mut pfds[..nfds], timeout_ms) <= 0 {
                let fresh_lines = logs.due() && logs.pump();
                if last_refresh.elapsed().as_millis() < u128::try_from(period).unwrap_or(0) {
                    // Nothing for the frame unless lines were read: no repaint for nothing.
                    skip_paint = !fresh_lines;
                    continue;
                }
                first_wait = false;
                last_refresh = Instant::now();
                snap = refresh_full(
                    &mut prev,
                    &mut prev_cpu,
                    &mut prev_runs,
                    &mut runs_hist,
                    &mut prev_box,
                    &mut box_hist,
                    tab,
                ); // timeout → periodic refresh (CPU% window)
                continue;
            }
            // A MEASUREMENT LANDED: the sizes reach the frame drawn next, without a key, and the
            // walk that produced them ran in another process.
            if pfds[2].revents != 0 {
                sizer.on_readable();
                if pfds[0].revents & libc::POLLIN == 0 && pfds[1].revents & libc::POLLIN == 0 {
                    continue;
                }
            }
            // LOG FILES GREW: note which, and read them when the pacing allows. A frame is drawn
            // only when lines were actually read, so a burst of writes costs one frame per
            // `PUMP_EVERY_MS`, not one per write.
            if pfds[3].revents != 0 {
                logs.on_readable();
                let fresh_lines = logs.due() && logs.pump();
                if pfds[0].revents & libc::POLLIN == 0 && pfds[1].revents & libc::POLLIN == 0 {
                    skip_paint = !fresh_lines;
                    continue;
                }
            }
            // A registry change woke us: drain the inotify queue and refresh NOW. If no key is also
            // pending, re-render and wait again - no 1 s lag on box appear/disappear.
            if ino_fd >= 0 && pfds[1].revents & libc::POLLIN != 0 {
                let mut ibuf = [0u8; 4096];
                while unsafe { libc::read(ino_fd, ibuf.as_mut_ptr().cast(), ibuf.len()) } > 0 {}
                snap = refresh_full(
                    &mut prev,
                    &mut prev_cpu,
                    &mut prev_runs,
                    &mut runs_hist,
                    &mut prev_box,
                    &mut box_hist,
                    tab,
                );
                if pfds[0].revents & libc::POLLIN == 0 {
                    continue;
                }
            }
            // 64, not 8: a paste or a fast repeat delivers more than eight bytes at once, and a
            // buffer that truncates them just moves the loss one layer down.
            let mut buf = [0u8; 64];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                continue;
            }
            split_keys(&buf[..n as usize], &mut keyq);
        }
        let Some(key_owned) = keyq.pop_front() else {
            continue;
        };
        let key = &key_owned[..];

        // Dispatch by mode. `mem::replace` takes ownership so a modal can transition cleanly back to
        // Nav; an edit that stays in the modal puts it back. `dirty` = the action changed on-disk
        // state (a box lifecycle op, a saved/deleted profile, a created/removed volume), so the lists
        // are re-read immediately; a pure navigation key just re-renders the existing snapshot.
        let mut dirty = false;
        match std::mem::replace(&mut mode, Mode::Nav) {
            // A read-only pane: any key closes it, quit still quits.
            Mode::Overlay(_) => {
                if is_quit(key) {
                    break;
                }
            }
            // Confirm a destructive action: `y` performs it, anything else cancels.
            Mode::Confirm { action, .. } => {
                if matches!(key.first(), Some(b'y' | b'Y')) {
                    // A destructive action that was refused must say so. `mode` was reset to `Nav` by
                    // the `replace` above, so setting the overlay here is what the other arms do too.
                    if let Some(err) = perform_pending(action) {
                        mode = Mode::Overlay(err);
                    }
                    dirty = true;
                }
            }
            // The Profiles "new" kind picker: a letter opens that form. `v` (vdisk) uses the disk-
            // selector form; the others are plain field forms.
            Mode::PickKind => match key.first() {
                Some(b'c') => mode = Mode::Form(new_profile_form("vcpu")),
                Some(b'g') => mode = Mode::Form(new_profile_form("vgpio")),
                Some(b'v') => mode = Mode::Form(new_profile_form("vdisk")),
                _ => {}
            },
            // The Sandboxes history picker: a letter is the choice, `c` asks before clearing, any
            // other key leaves everything as it was.
            Mode::PickHistory => {
                let pick = key.first().copied().and_then(crate::history::Keep::by_key);
                if let Some(k) = pick {
                    mode = Mode::Overlay(choose_history(k));
                    dirty = true;
                } else if key.first() == Some(&b'c') {
                    mode = Mode::Confirm {
                        prompt: "remove every finished-sandbox row, in memory and on disk?  (y/n)"
                            .into(),
                        action: Pending::ClearHistory,
                    };
                }
            }
            // A form: edit fields; Enter/Ctrl-S saves, Esc cancels.
            Mode::Form(form) => match handle_form_key(form, key) {
                FormOutcome::Stay(f) => mode = Mode::Form(f),
                FormOutcome::Cancel => {}
                FormOutcome::Submit(f) => match apply_form(&f) {
                    Ok(()) => dirty = true,
                    Err(e) => {
                        mode = Mode::Form(Form {
                            error: Some(e),
                            ..f
                        })
                    }
                },
            },
            // Normal navigation.
            Mode::Nav => {
                // THE LOGS TAB SEES THE KEY FIRST: while a search is typed it takes every key,
                // `q` included, and its own keys (`/ e s f x c`, the arrows) are not the other
                // tabs' (`s` stops a box on Boxes). What it does not use goes on as usual.
                if tab == TAB_LOGS {
                    let page = term_size().1.saturating_sub(16).max(1);
                    match logs.handle_key(key, page) {
                        crate::logview::KeyOutcome::Consumed => continue,
                        crate::logview::KeyOutcome::Overlay(text) => {
                            mode = Mode::Overlay(text);
                            continue;
                        }
                        crate::logview::KeyOutcome::Ignored => {}
                    }
                }
                if is_quit(key) {
                    break;
                }
                dirty = handle_nav(
                    key,
                    &mut tab,
                    &mut sel,
                    list_len,
                    &snap.rows,
                    &snap.profs,
                    &snap.vols,
                    &snap.builds,
                    &snap.images,
                    &snap.cfg,
                    &mut mode,
                );
            }
        }
        // A mutating action re-reads the lists at once (the stopped box vanishes, the new volume
        // appears) but leaves the CPU% baselines alone - re-sampling over the sub-second gap since
        // the last tick would show a spurious spike. The next tick restores a full ~1 s window.
        if dirty {
            let (rows, _) = collect_rows(&prev);
            snap.rows = rows;
            snap.cfg = crate::config::load(None).unwrap_or_default();
            snap.profs = profile_rows(&snap.cfg);
            snap.vols = crate::volume::entries_with(crate::volume::Sizes::Skip);
            // A volume created or removed changes what there is to measure.
            sizer.stale();
            // Also re-read the lists whose tabs now mutate (Images `d`/`p`, Builds `d`) so a deleted row
            // disappears on the very next frame, not on the ≤1 s periodic refresh (inotify watches the
            // box registry, not the image cache / build history).
            snap.set_builds(builds_listing(detail_policy(tab, TAB_BUILDS)));
            snap.set_images(crate::commands::image_entries_with(detail_policy(
                tab, TAB_IMAGES,
            )));
        }
    }
    Ok(()) // _guard restores the terminal on drop
}

/// `q` / `Q` / `Ctrl-C`, or a lone `Esc` (not the start of an arrow-key escape sequence).
fn is_quit(key: &[u8]) -> bool {
    matches!(key.first(), Some(b'q' | b'Q' | 0x03)) || key == [0x1b]
}

/// Number of selectable rows on the active tab (0 for Overview).
#[allow(clippy::too_many_arguments)]
fn tab_list_len(
    tab: usize,
    rows: &[Row],
    profs: &[ProfRow],
    vols: &[crate::volume::VolInfo],
    builds: &[crate::builds::Record],
    // The Builds tab selects over the whole store, of which `builds` is the part read so far: the
    // rest is read as the selection reaches it (`builds_reach`), so `End` lands on the oldest build.
    builds_total: usize,
    images: &[crate::commands::ImageEntry],
    sbx: &[crate::history::Entry],
) -> usize {
    match tab {
        TAB_SANDBOXES => sbx.len(),
        TAB_BOXES => rows.len(),
        TAB_IMAGES => images.len(),
        TAB_BUILDS => builds_total.max(builds.len()),
        TAB_PROFILES => profs.len(),
        TAB_STORAGE => vols.len(),
        _ => 0,
    }
}

/// Handle a key in normal navigation: tab switching, row selection, and the per-tab action keys.
#[allow(clippy::too_many_arguments)]
fn handle_nav(
    key: &[u8],
    tab: &mut usize,
    sel: &mut usize,
    list_len: usize,
    rows: &[Row],
    profs: &[ProfRow],
    vols: &[crate::volume::VolInfo],
    builds: &[crate::builds::Record],
    images: &[crate::commands::ImageEntry],
    cfg: &crate::config::KernConfig,
    mode: &mut Mode,
) -> bool {
    let down = |s: &mut usize| *s = s.saturating_add(1).min(list_len.saturating_sub(1));
    let up = |s: &mut usize| *s = s.saturating_sub(1);
    let switch = |t: &mut usize, s: &mut usize, nt: usize| {
        *t = nt;
        *s = 0;
    };
    // Arrow-key escape sequences: ↑↓ select, ←→ switch tab, PgUp/PgDn a page, Home/End the ends.
    // Pure navigation - never dirties data. A PAGE is the rows a list pane shows, so PgDn lands on
    // the first row that was not on screen; without it a 555-volume Storage tab took 554 presses.
    if key.len() >= 3 && key[0] == 0x1b && (key[1] == b'[' || key[1] == b'O') {
        let page = term_size().1.saturating_sub(17).max(1);
        match &key[2..] {
            b"A" => up(sel),
            b"B" => down(sel),
            b"C" => switch(tab, sel, (*tab + 1) % TABS.len()),
            b"D" => switch(tab, sel, (*tab + TABS.len() - 1) % TABS.len()),
            b"5~" => *sel = sel.saturating_sub(page),
            b"6~" => *sel = sel.saturating_add(page).min(list_len.saturating_sub(1)),
            b"H" | b"1~" | b"7~" => *sel = 0,
            b"F" | b"4~" | b"8~" => *sel = list_len.saturating_sub(1),
            _ => {}
        }
        return false;
    }
    // `?` opens the full-key help overlay from ANY tab - the discoverable safety net every good TUI
    // has (htop/k9s/lazydocker). The footer always advertises `?` so a first-time user knows it exists.
    if key[0] == b'?' {
        *mode = Mode::Overlay(help_text());
        return false;
    }
    match key[0] {
        b'\t' | b'l' => switch(tab, sel, (*tab + 1) % TABS.len()),
        b'h' => switch(tab, sel, (*tab + TABS.len() - 1) % TABS.len()),
        b'1' => switch(tab, sel, TAB_OVERVIEW),
        b'2' => switch(tab, sel, TAB_BOXES),
        b'3' => switch(tab, sel, TAB_RUNS),
        b'4' => switch(tab, sel, TAB_IMAGES),
        b'5' => switch(tab, sel, TAB_BUILDS),
        b'6' => switch(tab, sel, TAB_PROFILES),
        b'7' => switch(tab, sel, TAB_STORAGE),
        b'8' => switch(tab, sel, TAB_SANDBOXES),
        b'9' => switch(tab, sel, TAB_LOGS),
        b'j' => down(sel),
        // `k` IS UP. It was not bound here at all, so it fell through to the per-tab arms below,
        // where the Boxes tab read it as a lifecycle key and STOPPED the selected box. The help
        // overlay has always advertised "↑ ↓ / j k  select a row", so the product documented vi
        // navigation and delivered a destructive action on half of it: a user moving down the list
        // with `j` and back up with `k` killed whatever they had landed on. Reported from the field
        // as "the nav keys appear to work until they do a destructive change".
        //
        // Binding it here, beside `j`, is what makes the pair mean one thing. The per-tab arms below
        // are only reached for keys navigation does not claim.
        b'k' => up(sel),
        // Only the Boxes tab acts immediately (stop/pause/kill). Profiles/Storage keys just open a
        // modal, so the mutation (if any) happens later via Confirm/Form - nothing to refresh yet.
        _ if *tab == TAB_BOXES => return nav_boxes(key[0], *sel, rows, mode),
        _ if *tab == TAB_IMAGES => nav_images(key[0], *sel, images, mode),
        _ if *tab == TAB_BUILDS => nav_builds(key[0], *sel, builds, mode),
        _ if *tab == TAB_PROFILES => nav_profiles(key[0], *sel, profs, cfg, mode),
        _ if *tab == TAB_STORAGE => nav_storage(key[0], *sel, vols, mode),
        _ if *tab == TAB_SANDBOXES => nav_sandboxes(key[0], *sel, mode),
        _ => {}
    }
    false
}

/// Boxes-tab action keys: stop / pause / unpause the selected box, or open its logs. There is no
/// kill key: `k` is navigation, and the one lifecycle stop is `s`, behind a confirmation. The CLI
/// helpers are reused with muted stdio so their messages don't bleed into the alt-screen. Returns
/// `true` when a lifecycle op changed box state (so the caller re-reads the list), `false` for a
/// read-only action (opening logs) or an unbound key.
fn nav_boxes(k: u8, sel: usize, rows: &[Row], mode: &mut Mode) -> bool {
    let Some(name) = rows.get(sel).map(|r| r.name.clone()) else {
        return false;
    };
    // Every lifecycle key now reports its outcome. `quiet_io` redirects fd 1 and 2 to /dev/null so a
    // reused CLI helper's `println!` cannot corrupt the alt-screen - which ALSO sent its error message
    // there. A refused stop (the box exited a moment ago) or a refused pause (a host with no freezer
    // controller) left the user with an unchanged list, a key that appeared to do nothing, and no
    // reason for it. The result is carried out of the muted section and shown in the same overlay pane
    // the log view already uses.
    let outcome = match k {
        // STOPPING A RUNNING BOX ASKS FIRST, and it did not.
        //
        // The confirmation in this file was inversely proportional to the cost of the action:
        // deleting a PROFILE - a line of `kern.toml` that takes seconds to retype - opened a
        // `(y/n)` prompt, while stopping a running box, which is live work that no `n` can bring
        // back, executed on the keystroke. The prompt names the box, so a stale selection is
        // visible before it is acted on.
        //
        // `k` is gone from this arm: it is navigation now (see `handle_nav`). `s` is the stop key,
        // it is a mnemonic, and it is what the help has always listed first.
        b's' => {
            *mode = Mode::Confirm {
                prompt: format!("stop box {name}?  (y/n)"),
                action: Pending::StopBox(name.clone()),
            };
            return false;
        }
        // The Boxes tab's bulk action is STOP, not delete: a box is a running process, and the verb
        // that matches `s` is the one the CLI spells `kern stop --all`.
        b'S' => {
            let live: Vec<String> = rows.iter().map(|r| r.name.clone()).collect();
            if !live.is_empty() {
                *mode = Mode::Confirm {
                    prompt: format!("stop ALL {} running box(es)?  (y/n)", live.len()),
                    action: Pending::StopAllBoxes(live),
                };
            }
            // Like `s`: the prompt is the whole effect of the key, so there is nothing to refresh
            // until the confirmation runs.
            return false;
        }
        // Pause and unpause stay immediate: both are reversible by the other key, so a mistaken
        // press costs a keystroke rather than the work. Asking for every key would make the prompt
        // noise, and noise is how a confirmation stops being read.
        b'p' => quiet_io(|| crate::commands::pause(std::slice::from_ref(&name), false, true)),
        b'u' => quiet_io(|| crate::commands::pause(std::slice::from_ref(&name), false, false)),
        b'\r' | b'\n' => {
            *mode = Mode::Overlay(
                crate::commands::box_log_tail(&name).unwrap_or_else(|| "(no output yet)".into()),
            );
            return false;
        }
        _ => return false,
    };
    if let Err(e) = outcome {
        *mode = Mode::Overlay(format!("{name}: {e}"));
    }
    true
}

/// Profiles-tab action keys: new / edit / delete a `kern.toml` profile.
fn nav_profiles(
    k: u8,
    sel: usize,
    profs: &[ProfRow],
    cfg: &crate::config::KernConfig,
    mode: &mut Mode,
) {
    match k {
        // `n` opens the kind picker so any kind (incl. vdisk) is creatable from an empty list.
        b'n' => *mode = Mode::PickKind,
        b'e' | b'\r' | b'\n' => {
            if let Some(row) = profs.get(sel) {
                *mode = Mode::Form(edit_profile_form(row.section, &row.name, cfg));
            }
        }
        b'd' => {
            if let Some(row) = profs.get(sel) {
                *mode = Mode::Confirm {
                    prompt: format!("delete profile {}:{}?  (y/n)", row.section, row.name),
                    action: Pending::DeleteProfile(row.section, row.name.clone()),
                };
            }
        }
        _ => {}
    }
}

/// Storage-tab action keys: new / delete / inspect / prune named volumes (the persistent data layer).
fn nav_storage(k: u8, sel: usize, vols: &[crate::volume::VolInfo], mode: &mut Mode) {
    match k {
        b'n' => *mode = Mode::Form(new_volume_form()),
        b'e' => {
            if let Some(v) = vols.get(sel) {
                *mode = Mode::Form(edit_volume_form(v));
            }
        }
        b'd' => {
            if let Some(v) = vols.get(sel) {
                // PROMPT gets the scrubbed name (it is drawn on a terminal), ACTION gets the raw
                // one (it becomes a path). Handing the scrubbed name to the action deleted whatever
                // directory that string happened to name, which for a planted `a\nb` is the real
                // volume `ab`: a confirmed delete landing on a volume the operator never selected.
                *mode = Mode::Confirm {
                    prompt: format!("remove volume '{}' and its data?  (y/n)", v.name),
                    action: Pending::RemoveVolume(v.raw.clone()),
                };
            }
        }
        b'p' => {
            *mode = Mode::Confirm {
                prompt: "prune ALL unused volumes?  (y/n)".into(),
                action: Pending::PruneVolumes,
            };
        }
        // `p` reclaims the UNUSED ones; `D` removes every volume on the list, in use or not, and
        // takes the data with it. The prompt says "and their data" because a volume is the one thing
        // in this TUI whose deletion is not recoverable by pulling or rebuilding.
        b'D' => {
            if !vols.is_empty() {
                let names: Vec<String> = vols.iter().map(|v| v.raw.clone()).collect();
                *mode = Mode::Confirm {
                    prompt: format!(
                        "remove ALL {} volume(s) AND THEIR DATA?  this cannot be undone  (y/n)",
                        names.len()
                    ),
                    action: Pending::RemoveAllVolumes(names),
                };
            }
        }
        b'\r' | b'\n' => {
            if let Some(v) = vols.get(sel) {
                *mode = Mode::Overlay(volume_detail(v));
            }
        }
        _ => {}
    }
}

/// Images-tab action keys: delete the selected image (`d`), prune orphaned build layers (`p`), or open
/// a read-only detail overlay (`Enter`). Images are pulled/built elsewhere (no in-`top` "create"), so
/// the interactive surface is Delete + Prune + Read - the meaningful CRUD for a cache of artifacts.
fn nav_images(k: u8, sel: usize, images: &[crate::commands::ImageEntry], mode: &mut Mode) {
    match k {
        b'd' => {
            if let Some(img) = images.get(sel) {
                *mode = Mode::Confirm {
                    // the ref is untrusted (`.ok` content) → scrub escapes in the prompt; the action
                    // still carries the raw ref so `image_rm` resolves the real cache entry.
                    prompt: format!(
                        "remove image '{}' and its unshared layers?  (y/n)",
                        crate::ui::scrub(&img.name)
                    ),
                    action: Pending::RemoveImage(img.name.clone()),
                };
            }
        }
        // `D` deletes the WHOLE tab, `d` one row: the pair is deliberate, and the shift is the
        // friction. The prompt names the COUNT and what is lost, because "delete all?" tells an
        // operator nothing about the blast radius of the key they are about to press.
        b'D' => {
            if !images.is_empty() {
                let names: Vec<String> = images.iter().map(|i| i.name.clone()).collect();
                *mode = Mode::Confirm {
                    prompt: format!(
                        "delete ALL {} cached image(s)?  they must be pulled again  (y/n)",
                        names.len()
                    ),
                    action: Pending::RemoveAllImages(names),
                };
            }
        }
        b'p' => {
            *mode = Mode::Confirm {
                prompt: "prune orphaned build layers?  (y/n)".into(),
                action: Pending::PruneImages,
            };
        }
        b'\r' | b'\n' => {
            if let Some(img) = images.get(sel) {
                *mode = Mode::Overlay(image_detail(img));
            }
        }
        _ => {}
    }
}

/// Builds-tab action keys: delete the selected build record (`d`) or view its captured transcript
/// (`Enter`). Builds are immutable history created by `kern build` (no in-`top` create/edit), so the
/// interactive surface is Delete + Read-logs.
fn nav_builds(k: u8, sel: usize, builds: &[crate::builds::Record], mode: &mut Mode) {
    match k {
        b'd' => {
            if let Some(b) = builds.get(sel) {
                *mode = Mode::Confirm {
                    prompt: format!("delete build record '{}'?  (y/n)", b.id),
                    action: Pending::DeleteBuild(b.id.clone()),
                };
            }
        }
        b'D' => {
            if !builds.is_empty() {
                let ids: Vec<String> = builds.iter().map(|b| b.id.clone()).collect();
                *mode = Mode::Confirm {
                    prompt: format!(
                        "delete ALL {} build record(s)?  the images they built stay  (y/n)",
                        ids.len()
                    ),
                    action: Pending::DeleteAllBuilds(ids),
                };
            }
        }
        b'\r' | b'\n' => {
            if let Some(b) = builds.get(sel) {
                let body = crate::builds::read_log(&b.id)
                    .unwrap_or_else(|| "(no transcript captured for this build)".into());
                *mode = Mode::Overlay(format!("build {} - {}\n{}", b.id, b.tag, body));
            }
        }
        _ => {}
    }
}

/// A read-only detail block for one cached image (Images tab `Enter`). The ref is scrubbed of terminal
/// escapes - a `.ok` sentinel's content is untrusted.
fn image_detail(img: &crate::commands::ImageEntry) -> String {
    let now = registry::now_unix();
    // A dangling image (layers gone) shows that plainly instead of a misleading `0 B` size.
    let size = if img.dangling {
        "dangling (missing layers - would fail to run)".to_string()
    } else {
        human_bytes(img.size)
    };
    format!(
        "image {}\nsize     {}\npulled   {}\n\ndelete with `d` · reclaim layers with `p`",
        crate::ui::scrub(&img.name),
        size,
        fmt_uptime(now.saturating_sub(img.pulled)),
    )
}

/// Carry out a confirmed destructive action, muting the helper's stdio. Returns the failure text when
/// the action did NOT happen, for the caller to show.
///
/// Every arm used to discard its result while `quiet_io` sent the helper's own message to /dev/null,
/// so a refused `volume rm` (a volume still bound by a running box), a refused `image rm` (an image
/// still in use) or a failed profile delete left the item on screen after a `y` confirmation, with
/// nothing to explain why. A destructive action that did not happen is exactly the case a user needs
/// told.
fn perform_pending(action: Pending) -> Option<String> {
    match action {
        Pending::RemoveVolume(name) => quiet_io(|| crate::volume::run(&["rm".to_string(), name]))
            .err()
            .map(|e| e.to_string()),
        Pending::PruneVolumes => quiet_io(|| crate::volume::run(&["prune".to_string()]))
            .err()
            .map(|e| e.to_string()),
        Pending::DeleteProfile(section, name) => delete_profile(section, &name).err(),
        Pending::RemoveImage(name) => quiet_io(|| crate::commands::image_rm(&[name]))
            .err()
            .map(|e| e.to_string()),
        Pending::PruneImages => quiet_io(crate::commands::image_prune)
            .err()
            .map(|e| e.to_string()),
        // `remove` reports three outcomes: gone, never there, or could not be removed. Only the last
        // is a failure to show - "there was no such record" means the list was stale, and the refresh
        // that follows the confirmation already corrects it.
        Pending::DeleteBuild(id) => match crate::builds::remove(&id) {
            Ok(_) => None,
            Err(e) => Some(format!("build '{id}': {e}")),
        },
        // A refused stop is worth showing for the same reason as the others: the box stays on the
        // list after a `y`, and without the reason that reads as the key having done nothing.
        Pending::StopBox(name) => {
            quiet_io(|| crate::commands::stop(std::slice::from_ref(&name), false))
                .err()
                .map(|e| e.to_string())
        }
        // A BULK ACTION REPORTS EVERY FAILURE, not the first. Stopping at the first error leaves the
        // rest of the list untouched with no word about it, which reads as "the key did nothing" for
        // items that were never attempted. Each one is tried, and the summary names how many of how
        // many failed plus the first reason - enough to act on, short enough to fit the overlay.
        Pending::RemoveAllImages(names) => bulk(
            "image",
            names.len(),
            names.into_iter().map(|n| {
                quiet_io(|| crate::commands::image_rm(&[n]))
                    .err()
                    .map(|e| e.to_string())
            }),
        ),
        Pending::DeleteAllBuilds(ids) => bulk(
            "build",
            ids.len(),
            ids.into_iter()
                .map(|id| crate::builds::remove(&id).err().map(|e| e.to_string())),
        ),
        Pending::RemoveAllVolumes(names) => bulk(
            "volume",
            names.len(),
            names.into_iter().map(|n| {
                quiet_io(|| crate::volume::run(&["rm".to_string(), n]))
                    .err()
                    .map(|e| e.to_string())
            }),
        ),
        Pending::StopAllBoxes(names) => bulk(
            "box",
            names.len(),
            names.into_iter().map(|n| {
                quiet_io(|| crate::commands::stop(std::slice::from_ref(&n), false))
                    .err()
                    .map(|e| e.to_string())
            }),
        ),
        Pending::ClearHistory => crate::history::clear().err(),
    }
}

/// Apply a choice from the history picker, and say what it did: the place, the rows held, and
/// how many moved with the switch. A failure (a `kern.toml` that would not parse) says why.
fn choose_history(k: crate::history::Keep) -> String {
    match crate::history::set_keep(k) {
        Ok(moved) => format!(
            "sandbox history\n\n{}{}\n\nWritten to kern.toml as [kern] sandbox_history = \"{}\"; \
             `kern sandbox keep` reads and changes the same line.",
            crate::history::keep_line(),
            crate::history::moved_line(moved)
                .map(|m| format!("\n{m}"))
                .unwrap_or_default(),
            k.word()
        ),
        Err(e) => format!("sandbox history: not changed\n\n{e}"),
    }
}

/// Run a bulk destructive action to the end and summarise what failed.
///
/// `None` when every item succeeded, which is what the caller treats as "no overlay, just refresh".
/// Otherwise a line naming how many of how many failed and the FIRST reason: a list of twenty
/// identical permission errors is not more informative than one, and it does not fit the pane.
fn bulk(kind: &str, total: usize, results: impl Iterator<Item = Option<String>>) -> Option<String> {
    let mut failed = 0usize;
    let mut first: Option<String> = None;
    for e in results.flatten() {
        failed += 1;
        if first.is_none() {
            first = Some(e);
        }
    }
    match (failed, first) {
        (0, _) => None,
        (n, Some(e)) => Some(format!(
            "{n} of {total} {kind}(s) could not be removed: {e}"
        )),
        (n, None) => Some(format!("{n} of {total} {kind}(s) could not be removed")),
    }
}

/// The OS thread id that raised the alternate screen, 0 while it is down (cleared by
/// `TermGuard::drop`). It is the ONLY thing that licenses `quiet_io` to touch fd 1 and fd 2, which
/// are process-wide and not that function's to borrow. See `quiet_io` for what went wrong without it.
///
/// A bool would have said "an alt screen is up somewhere". What `quiet_io` has to know is "*I* am the
/// thread that put it up", because the descriptors it swaps belong to every thread in the process.
/// Only the TUI loop raises it, and that holds today by TOPOLOGY, not by construction: a caller added
/// on another thread would inherit exactly the defect the flag was introduced to remove. Carrying the
/// tid makes the precondition enforce itself in release and fail loudly in debug.
static ALT_SCREEN_TID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// This thread's kernel id. `gettid`, not `pthread_self`: it must survive a `fork`, where the child
/// is a new thread of a new process and its `pthread_t` may repeat the parent's.
fn this_tid() -> i32 {
    unsafe { libc::gettid() }
}

/// Run `f` with fd 1 and fd 2 redirected to `/dev/null`, then restored - so a reused CLI helper's
/// `println!`/`eprintln!` can't corrupt the alt-screen. Used for the lifecycle key actions.
///
/// THE REDIRECT ONLY HAPPENS WHILE THE ALT SCREEN IS UP, and that guard is load-bearing rather than
/// decorative. `dup2` onto 1 and 2 rewrites the file descriptor table of the whole PROCESS, not of
/// the calling thread, so every other thread's output lands in `/dev/null` for the duration. `kern
/// top` is single-threaded and there is nothing else printing, but the unit tests are not: libtest
/// runs them on parallel threads and prints the results from another one. The measured effect was
/// that this binary silently dropped up to a hundred lines of its own test report, INCLUDING the
/// `test result:` summary, while still exiting 0 - so a failure could have been reported into
/// `/dev/null`, and `scripts/test-count.py` had nothing to parse. Two overlapping calls could also
/// interleave save and restore and leave fd 1 on `/dev/null` for good.
///
/// Outside the alt screen there is no alt screen to protect, so the swap is pure damage: the helper's
/// own `println!` is then wanted output. The condition is exact rather than a test-mode sniff - the
/// key handlers that call this are only reachable from the interactive loop, which sets the flag.
fn quiet_io<T>(f: impl FnOnce() -> T) -> T {
    let owner = ALT_SCREEN_TID.load(std::sync::atomic::Ordering::SeqCst);
    if owner == 0 {
        return f();
    }
    let me = this_tid();
    debug_assert_eq!(
        owner, me,
        "quiet_io ran on a thread that did not raise the alt screen: the fd swap is process-wide, so \
         it would send THAT thread's output to /dev/null too"
    );
    if owner != me {
        return f();
    }
    let _ = std::io::stdout().flush();
    let (s1, s2) = unsafe { (libc::dup(1), libc::dup(2)) };
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY) };
    if null >= 0 {
        unsafe {
            libc::dup2(null, 1);
            libc::dup2(null, 2);
            libc::close(null);
        }
    }
    let out = f();
    let _ = std::io::stdout().flush();
    unsafe {
        if s1 >= 0 {
            libc::dup2(s1, 1);
            libc::close(s1);
        }
        if s2 >= 0 {
            libc::dup2(s2, 2);
            libc::close(s2);
        }
    }
    out
}

// ───────────────────────────── Profiles & Volumes: model ─────────────────────────────

/// Flatten the three editable profile kinds into display rows (name + a one-line summary).
fn profile_rows(cfg: &crate::config::KernConfig) -> Vec<ProfRow> {
    let mut out = Vec::new();
    for e in &cfg.vcpu {
        let mut parts = Vec::new();
        if let Some(q) = e.cpus {
            parts.push(format!("{} cores", trim_f(q)));
        }
        if let Some(c) = &e.cpuset {
            parts.push(format!("pin {c}"));
        }
        if let Some(m) = &e.memory {
            parts.push(m.clone());
        }
        if let Some(x) = &e.extends {
            parts.push(format!("extends {x}"));
        }
        out.push(ProfRow {
            section: "vcpu",
            name: e.name.clone(),
            summary: parts.join("  "),
        });
    }
    for e in &cfg.vgpio {
        let mut parts = Vec::new();
        if !e.backend.is_empty() {
            parts.push(e.backend.clone());
        }
        if !e.pins.is_empty() {
            let pins: Vec<String> = e.pins.iter().map(u32::to_string).collect();
            parts.push(format!("pins {}", pins.join(",")));
        }
        out.push(ProfRow {
            section: "vgpio",
            name: e.name.clone(),
            summary: parts.join("  "),
        });
    }
    // vdisk - a per-box scratch/disk profile (attached with `vdisk:name`).
    for e in &cfg.vdisk {
        let mut parts = Vec::new();
        parts.push(e.size.clone().unwrap_or_else(|| "uncapped".into()));
        if e.persistent {
            parts.push("persistent".into());
        }
        // Only surface a placement when a power user pinned one via a [[disk]] backend.
        if !e.backend.is_empty() {
            parts.push(format!("on {}", vdisk_location(cfg, e)));
        }
        out.push(ProfRow {
            section: "vdisk",
            name: e.name.clone(),
            summary: parts.join("  "),
        });
    }
    // Group by category (compute → device → storage) and sort by name within each - so the list is
    // predictable and grouped, not raw config-insertion order.
    out.sort_by(|a, b| {
        let rank = |s: &str| match s {
            "vcpu" => 0,
            "vgpio" => 1,
            "vdisk" => 2,
            _ => 3,
        };
        rank(a.section)
            .cmp(&rank(b.section))
            .then_with(|| a.name.cmp(&b.name))
    });
    out
}

/// The human location a vdisk sits on: the `[[disk]]` path its backend points at, else the raw backend.
fn vdisk_location(cfg: &crate::config::KernConfig, e: &crate::config::VDiskEntry) -> String {
    let want = e.backend.strip_prefix("disk:").unwrap_or(&e.backend);
    cfg.disk
        .iter()
        .find(|d| d.name == want)
        .map(|d| d.path.clone())
        .unwrap_or_else(|| e.backend.clone())
}

/// The list label for a profile row: `section:name`.
fn prof_label(r: &ProfRow) -> String {
    format!("{}:{}", r.section, r.name)
}

/// Format an `f64` core count without a trailing `.0` (`4.0` → `4`, `0.5` → `0.5`).
fn trim_f(v: f64) -> String {
    crate::ui::fmt_cpus(v)
}

/// The `backend` field for every profile kind - a SELECTION of the configured backends, never free text
/// (that's how `disk:0sfsf…` / `gpio:0sfsf…` were possible). vgpio→`[[gpio]]` ids, vcpu→`[[cpu]]` ids,
/// vdisk→`disk:<[[disk]] name>`. A single-select radio (a profile uses ONE backend). `backend` is
/// MANDATORY, so the reserved sentinel (`host` for vcpu/vgpio, `ram` for vdisk = the whole host, no
/// physical block needed) is ALWAYS offered first - the field is never an empty dead-end, and the save
/// (`validate_profile_refs`) refuses a profile that leaves it unset. One helper for all three kinds.
fn backend_field(kind: &str) -> Field {
    let cfg = crate::config::load(None).unwrap_or_default();
    let (sentinel, hint): (&str, &'static str) = match kind {
        "vdisk" => (
            crate::config::BACKEND_RAM,
            "required: pick a backend (ram = a RAM tmpfs, or a configured disk)",
        ),
        "vgpio" => (
            crate::config::BACKEND_HOST,
            "required: pick a backend (host = the host's own devices, or a configured id)",
        ),
        _ => (
            crate::config::BACKEND_HOST,
            "required: pick a backend (host = the whole host CPU, or a configured id)",
        ),
    };
    let mut ids: Vec<String> = vec![sentinel.to_string()];
    ids.extend(match kind {
        "vgpio" => cfg.gpio.iter().map(|g| g.id.clone()).collect::<Vec<_>>(),
        "vcpu" => cfg.cpu.iter().map(|c| c.id.clone()).collect::<Vec<_>>(),
        "vdisk" => cfg
            .disk
            .iter()
            .map(|d| format!("disk:{}", d.name))
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    });
    Field::radio("backend", hint, ids)
}

/// The editable fields for a compute/IO profile section (`vcpu`/`vgpio`) - used for new and edit.
/// (Storage kinds - vdisk, volume - have their own forms.)
fn section_fields(section: &str) -> Vec<Field> {
    // The common fields first (a beginner rarely scrolls past them), then the advanced ones. The form
    // scrolls, so every field of every kind is reachable - nothing is CLI-only.
    match section {
        "vcpu" => vec![
            Field::text("name", "e.g. heavy"),
            Field::text("cpus", "cores, e.g. 4 or 0.5 (= --cpus)"),
            Field::text("cpuset", "pin list, e.g. 0-3 (= --cpuset-cpus)"),
            Field::text("memory", "e.g. 512m, 2g (= --memory)"),
            Field::text("nice", "-20..19 (optional, = --nice)"),
            Field::text("numa", "NUMA node, e.g. 0 (optional)"),
            backend_field("vcpu"),
            Field::text("extends", "base profile (optional)"),
        ],
        "vgpio" => {
            // For-dummies: the beginner sees only NAME + the everyday devices, each as a checkbox
            // list of what THIS host actually exposes - so there's nothing to type and nothing to
            // guess: tick the device you want the box to reach, or leave it empty. Everything rare
            // (LEDs, CAN, PWM, backend, …) lives under the "Advanced" fold so the form stays short.
            //
            // `pick(label, plain-language what-is-this)` when the host HAS that device - you tick it,
            // you never type a path. When the host DOESN'T have it, there's nothing valid to type, so
            // it becomes a read-only "none detected on this host" note instead of an empty box that
            // invites garbage. Same mechanism on every host - only the detected contents differ.
            let mk = |label: &'static str, plain: &'static str| {
                let opts = present_devices(label);
                if opts.is_empty() {
                    Field::info(label, "none detected on this host")
                } else {
                    Field::pick(label, plain, opts)
                }
            };
            // The everyday devices, in plain language (no /dev/ jargon in the hint).
            let mut common = vec![Field::text("name", "a short name, e.g. sensors")];
            let mut absent = Vec::new(); // a common device the host lacks → a note under Advanced
            for (label, plain) in [
                ("i2c", "I²C bus - sensors, small displays"),
                ("spi", "SPI bus - displays, ADCs"),
                ("uart", "serial port"),
                ("camera", "camera"),
                ("audio", "sound card"),
                ("bluetooth", "Bluetooth adapter"),
            ] {
                let f = mk(label, plain);
                if f.is_pick() {
                    common.push(f); // present → show it up front, tick to allow
                } else {
                    absent.push(f); // not on this host → a "none here" note, out of the way
                }
            }
            // GPIO pins are line NUMBERS from YOUR wiring, so they're the one thing you legitimately
            // type - but only when the host actually has a GPIO controller. Check the modern chardev
            // (/dev/gpiochip*) AND the legacy sysfs interface (/sys/class/gpio), so a board that only
            // exposes sysfs-GPIO isn't wrongly told it has none. No GPIO at all ⇒ a "none here" note,
            // not an empty box inviting a guess.
            let has_gpio = !present_devices("pins").is_empty()
                || std::path::Path::new("/sys/class/gpio/export").exists();
            let mut advanced = absent;
            if has_gpio {
                common.push(Field::text("pins", "GPIO pins, e.g. 17 27"));
            } else {
                advanced.push(Field::info("pins", "no GPIO controller on this host"));
            }
            // The rare / expert knobs - hidden until the user opens "Advanced". Anything the host can
            // enumerate is a pick (net interfaces, LEDs, …); a device it lacks is a note; pwm follows
            // the same GPIO gate as pins; only the truly free-form escape (`extra`) stays typed.
            // NOTE: `net` is deliberately absent - a vgpio profile does NOT attach a network interface
            // (the resolver ignores it), so offering it would be a lie. Network access is the box's
            // own `--net`. If net-passthrough is ever wired in the resolver, add it back here.
            for (label, plain) in [
                ("leds", "on-board LEDs"),
                ("can", "CAN bus"),
                ("input", "input devices (keys, touch)"),
                ("midi", "MIDI ports"),
                ("display", "GPU render node (renderD)"),
            ] {
                advanced.push(mk(label, plain));
            }
            // A USB peripheral is passed by its FUNCTION, not as a raw bus node: a USB-serial adapter is
            // under 'serial' (ttyUSB), a webcam under 'camera' (video), a USB mic under 'sound card'.
            // Raw /dev/bus/usb passthrough is refused by the resolver (it reaches the WHOLE bus - BadUSB),
            // so a real usb pick would only ever be denied - an explanatory note instead of a lie.
            advanced.push(Field::info(
                "usb",
                "by function (serial/camera/audio) - or a specific /dev/bus/usb/B/D in 'extra'",
            ));
            // Number fields (pwm/adc/onewire are channel/line indices you'd type) only accept typing
            // when the host actually HAS that controller; otherwise there's nothing to type, so it's a
            // "none here" note - never an empty box asking you to guess. A gated helper keeps it uniform.
            let dir_has = |dir: &str, prefix: &str| {
                std::fs::read_dir(dir)
                    .map(|rd| {
                        rd.flatten().any(|e| {
                            e.file_name()
                                .to_str()
                                .is_some_and(|n| n.starts_with(prefix))
                        })
                    })
                    .unwrap_or(false)
            };
            let gated = |label: &'static str, hint: &'static str, present: bool| {
                if present {
                    Field::text(label, hint)
                } else {
                    Field::info(label, "none detected on this host")
                }
            };
            advanced.push(gated(
                "pwm",
                "PWM lines, e.g. 12 13",
                dir_has("/sys/class/pwm", "pwmchip"),
            ));
            advanced.push(gated(
                "adc",
                "ADC channels, e.g. 0 1",
                dir_has("/sys/bus/iio/devices", "iio:device"),
            ));
            advanced.push(gated(
                "onewire",
                "1-Wire line numbers",
                std::path::Path::new("/sys/bus/w1/devices").exists(),
            ));
            advanced.push(backend_field("vgpio"));
            advanced.push(Field::text("extra", "any other /dev path"));
            let mut v = common;
            v.push(Field::divider());
            for mut f in advanced {
                f.advanced = true;
                v.push(f);
            }
            v
        }
        "vdisk" => vec![
            Field::text("name", "e.g. scratch"),
            Field::text("size", "e.g. 2g"),
            Field::toggle("persistent", "survives box removal"),
            backend_field("vdisk"),
            Field::text("iops", "ops/s (optional)"),
            Field::text("bandwidth", "e.g. 100m (optional)"),
        ],
        _ => vec![Field::text("name", "")],
    }
}

/// A concrete, plain-language "what is this field and when would I use it" line for the focused field,
/// shown at the bottom of the form. This is the hand-holding: the user isn't expected to know what an
/// I²C bus or a PWM line is - the help says it, with an everyday example. `None` = no help (e.g. the
/// Advanced fold row). Kept short (≤ ~74 chars) so it never wraps an 80-column terminal.
fn field_help(section: &str, label: &str) -> Option<&'static str> {
    let h = match (section, label) {
        ("vgpio", "name") => "A label for this hardware set - attach with  vgpio:NAME",
        ("vgpio", "i2c") => "I²C bus for sensors & small displays. Tick the bus your part is on.",
        ("vgpio", "spi") => "SPI bus for displays, ADCs, radios. Tick the port your part uses.",
        ("vgpio", "uart") => "Serial port for GPS, modems, consoles. Tick the tty it's on.",
        ("vgpio", "camera") => "A camera. Tick it to let the box capture video.",
        ("vgpio", "audio") => "The sound card. Tick to let the box play or record audio.",
        ("vgpio", "bluetooth") => "The Bluetooth adapter. Tick to let the box use Bluetooth/BLE.",
        ("vgpio", "pins") => "Raw GPIO pin numbers (e.g. 17 27) for LEDs, buttons, relays.",
        ("vgpio", "leds") => "On-board LEDs you want the box to control.",
        ("vgpio", "can") => "CAN bus - vehicle & industrial networking.",
        ("vgpio", "input") => "Input devices - keys, touchscreen, joystick.",
        ("vgpio", "midi") => "MIDI ports for music gear.",
        ("vgpio", "display") => {
            "GPU render node (renderD) for compute/video; card modeset is refused."
        }
        ("vgpio", "pwm") => "PWM outputs (e.g. 12 13) for servos, dimming, fans.",
        ("vgpio", "adc") => "Analog inputs (ADC channels).",
        ("vgpio", "onewire") => "1-Wire lines, e.g. a DS18B20 temperature sensor.",
        ("vgpio", "backend") => {
            "The configured [[gpio]] backend (optional; run kern config setup to add one)."
        }
        ("vgpio", "extra") => "Any other /dev path to pass, only if you know it exists.",
        ("vcpu", "name") => "A label for this CPU/memory slice - attach with  vcpu:NAME",
        ("vcpu", "cpus") => {
            "How many cores the box may use, e.g. 4 - or 0.5 for half a core (= --cpus)."
        }
        ("vcpu", "cpuset") => {
            "Pin to specific cores, e.g. 0-3 (= --cpuset-cpus). Leave blank to let it float."
        }
        ("vcpu", "memory") => "Memory ceiling, e.g. 512m or 2g. The box is OOM-capped at this.",
        ("vdisk", "name") => "A label for this scratch disk - attach with  vdisk:NAME",
        ("vdisk", "size") => "Max size of the scratch disk, e.g. 2g. Writes past it fail.",
        ("vdisk", "persistent") => {
            "Keep the disk's data after the box is removed (default: wiped)."
        }
        _ => return None,
    };
    Some(h)
}

/// The ONE validation authority for a typed keystroke - the derived "char filter": a character is
/// accepted iff the resulting value isn't `field_state::Invalid`. `field_state` is itself derived from
/// the save parser (`profile_line` / `validate_profile_name`), so there is a SINGLE source of truth for
/// what any field may hold, shared by live-typing AND save; a per-field char-class list (which could
/// drift) no longer exists. A number field rejects a letter because the value would be `Invalid`; a
/// name rejects a space for the same reason; even `extra` rejects a non-`/dev/` string. The
/// printable-ASCII gate at the call site still blocks control / multibyte bytes for every field.
fn field_value_ok(label: &str, v: &str) -> bool {
    crate::config::field_state(label, v) != crate::config::FieldState::Invalid
}

/// Fields governed by `config::field_state` - the SINGLE rule shared with save - and given the live
/// three-state indicator. Numbers/ranges/sizes, the name/extends identifiers, AND the `extra` /dev-path
/// escape (all route through the same `field_state` dispatcher, so no field validates by a second,
/// drift-prone path). Only `backend` (a pick) isn't here.
fn validated_field(label: &str) -> bool {
    matches!(
        label,
        "pins"
            | "pwm"
            | "adc"
            | "onewire"
            | "numa"
            | "nice"
            | "cpus"
            | "cpuset"
            | "memory"
            | "size"
            | "bandwidth"
            | "iops"
            | "name"
            | "extends"
            | "extra"
    )
}

/// A blank form to create a new profile. `backend` is no longer pre-filled: it's now a picker of the
/// configured GPIO ids (or a "run kern config setup" note), and it's optional - the resolver binds the
/// gpiochips from `pins` regardless - so a beginner leaves it alone.
fn new_profile_form(section: &'static str) -> Form {
    let mut fields = section_fields(section);
    // `backend` is the only MANDATORY field besides the name, and it sits inside the Advanced fold,
    // BELOW every detected-device row - so the more hardware a host has, the further it is from the
    // top. Measured on the three ARM boards: a Pi 5 (no i2c nodes) puts it six rows down, a Jetson
    // (seven i2c buses, four spi ports, four uarts) far below that, on exactly the boards where a
    // vgpio profile is the point. Filling the visible form and pressing Enter answered with a
    // message written in TOML rather than in the form's own language.
    //
    // Pre-select the sentinel, as `kern config add` does: the value is still written EXPLICITLY into
    // the file (so the 0.6.11 rule that a profile never binds to an implicit default is intact), it
    // is still visible in the form, and it is still one keystroke to change. NEW forms only - an
    // EDIT must keep showing the profile's real state, including a backend that is missing.
    if let Some(f) = fields.iter_mut().find(|f| f.label == "backend") {
        if let Some(first) = f.sel.first_mut() {
            *first = true;
            f.sync_pick_value();
        }
    }
    Form {
        title: format!("new {section} profile"),
        fields,
        active: 0,
        submit: Submit::SaveProfile {
            section,
            orig_name: None,
        },
        error: None,
        show_advanced: false,
    }
}

/// A form pre-filled with EVERY set field of the existing profile (via `config::profile_pairs`), so an
/// edit shows and re-saves all of them - nothing is dropped or hidden.
fn edit_profile_form(section: &'static str, name: &str, cfg: &crate::config::KernConfig) -> Form {
    let mut fields = section_fields(section);
    set_field(&mut fields, "name", name.to_string());
    for (k, v) in crate::config::profile_pairs(cfg, section, name) {
        set_field(&mut fields, &k, v);
    }
    // If the profile already sets an advanced field, open the fold so the edit SHOWS it - nothing the
    // user configured stays hidden.
    let show_advanced = fields.iter().any(|f| f.advanced && !f.value.is_empty());
    Form {
        title: format!("edit {section}:{name}"),
        fields,
        active: 0,
        submit: Submit::SaveProfile {
            section,
            orig_name: Some(name.to_string()),
        },
        error: None,
        show_advanced,
    }
}

/// A form to create a named volume (name + optional quota).
fn new_volume_form() -> Form {
    Form {
        title: "new volume".into(),
        fields: vec![
            Field::text("name", "e.g. data"),
            Field::text("size", "optional quota, e.g. 2g (blank = unlimited)"),
        ],
        active: 0,
        submit: Submit::CreateVolume,
        error: None,
        show_advanced: false,
    }
}

/// An edit form for a named volume, pre-filled with its name and current quota (blank size = no quota).
fn edit_volume_form(v: &crate::volume::VolInfo) -> Form {
    let size = v.quota.map(bytes_to_size_str).unwrap_or_default();
    let mut fields = vec![
        Field::text("name", "volume name"),
        Field::text("size", "quota, e.g. 2g (blank = unlimited)"),
    ];
    // Same split: the editable field shows the scrubbed name, `orig_name` carries the raw one so the
    // rename finds the directory that is actually there.
    set_field(&mut fields, "name", v.name.clone());
    set_field(&mut fields, "size", size);
    Form {
        title: format!("edit volume:{}", v.name),
        fields,
        active: 0,
        submit: Submit::EditVolume {
            orig_name: v.raw.clone(),
        },
        error: None,
        show_advanced: false,
    }
}

/// Bytes → the shortest EXACT, re-parseable size string (`2147483648`→`2g`, `1`→`1`), so an edit form
/// pre-fills a value `config::size_to_bytes` can read straight back.
fn bytes_to_size_str(n: u64) -> String {
    const K: u64 = 1 << 10;
    for (unit, suffix) in [(K * K * K, 'g'), (K * K, 'm'), (K, 'k')] {
        if n >= unit && n % unit == 0 {
            return format!("{}{suffix}", n / unit);
        }
    }
    n.to_string()
}

/// Set a field's value by label (used to pre-fill edit forms). For a pick field, check the boxes that
/// match the pre-filled value so an edit shows the current selection.
fn set_field(fields: &mut [Field], label: &str, val: String) {
    if let Some(f) = fields.iter_mut().find(|f| f.label == label) {
        f.value = val;
        f.seed_pick_selection();
    }
}

/// The result of feeding a key to a form.
enum FormOutcome {
    Stay(Form),
    Cancel,
    Submit(Form),
}

/// Edit a form with one keypress: type into the active field, navigate fields, submit or cancel.
fn handle_form_key(mut form: Form, key: &[u8]) -> FormOutcome {
    // Arrow keys ↑/↓ move between VISIBLE fields; ←/→ move the highlighted checkbox inside a pick
    // field, or open/close the Advanced fold when it's focused.
    if key.len() >= 3 && key[0] == 0x1b && key[1] == b'[' {
        let vis = nav_fields(&form);
        let vpos = vis
            .iter()
            .position(|&i| i == form.active)
            .unwrap_or(0)
            .min(vis.len().saturating_sub(1));
        match key[2] {
            b'A' => form.active = vis[vpos.saturating_sub(1)],
            b'B' => form.active = vis[(vpos + 1).min(vis.len().saturating_sub(1))],
            b'C' => {
                let f = &mut form.fields[form.active];
                if f.divider {
                    form.show_advanced = true;
                } else if f.is_pick() {
                    f.cur = (f.cur + 1) % f.options.len();
                }
            }
            b'D' => {
                let f = &mut form.fields[form.active];
                if f.divider {
                    form.show_advanced = false;
                } else if f.is_pick() {
                    f.cur = (f.cur + f.options.len() - 1) % f.options.len();
                }
            }
            _ => {}
        }
        return FormOutcome::Stay(form);
    }
    // The Advanced fold row: Space toggles it; Enter still saves, Esc cancels, Tab moves on - but a
    // typed character never lands on it.
    if form.fields[form.active].divider {
        match key[0] {
            b' ' => {
                form.show_advanced = !form.show_advanced;
                return FormOutcome::Stay(form);
            }
            0x1b => return FormOutcome::Cancel,
            b'\r' | b'\n' | 0x13 => return FormOutcome::Submit(form),
            b'\t' => {
                let vis = nav_fields(&form);
                let vpos = vis.iter().position(|&i| i == form.active).unwrap_or(0);
                form.active = vis[(vpos + 1) % vis.len()];
                return FormOutcome::Stay(form);
            }
            _ => return FormOutcome::Stay(form),
        }
    }
    // A "none on this host" note never takes input - its value stays empty so it stays a note and a
    // wrong path can't be typed. (Enter/Tab/Esc still work; nav already skips it anyway.)
    if form.fields[form.active].is_dead_info()
        && !matches!(key[0], 0x1b | b'\t' | b'\r' | b'\n' | 0x13)
    {
        return FormOutcome::Stay(form);
    }
    // A pick field: Space checks/unchecks the highlighted option; typing never lands here.
    if form.fields[form.active].is_pick() && !matches!(key[0], 0x1b | b'\t' | b'\r' | b'\n' | 0x13)
    {
        let f = &mut form.fields[form.active];
        if key[0] == b' ' && f.cur < f.sel.len() {
            let now_on = !f.sel[f.cur];
            // A radio group holds ONE value: ticking one clears the others (invalid multi-value state
            // is unrepresentable). A plain pick toggles independently.
            if f.radio {
                f.sel.iter_mut().for_each(|s| *s = false);
            }
            f.sel[f.cur] = now_on;
            f.sync_pick_value();
        }
        form.error = None;
        return FormOutcome::Stay(form);
    }
    // A toggle field is driven by Space (flip) / `y` (on) / `n` (off); typing never lands in it.
    if form.fields[form.active].toggle && !matches!(key[0], 0x1b | b'\t' | b'\r' | b'\n' | 0x13) {
        let v = &mut form.fields[form.active].value;
        match key[0] {
            b' ' => {
                *v = if v.is_empty() {
                    "yes".into()
                } else {
                    String::new()
                }
            }
            b'y' | b'Y' | b'1' => *v = "yes".into(),
            b'n' | b'N' | b'0' | 0x7f | 0x08 => v.clear(),
            _ => {}
        }
        form.error = None;
        return FormOutcome::Stay(form);
    }
    match key[0] {
        0x1b => FormOutcome::Cancel, // lone Esc
        b'\t' => {
            let vis = nav_fields(&form);
            let vpos = vis.iter().position(|&i| i == form.active).unwrap_or(0);
            form.active = vis[(vpos + 1) % vis.len()];
            FormOutcome::Stay(form)
        }
        b'\r' | b'\n' | 0x13 => FormOutcome::Submit(form), // Enter / Ctrl-S
        0x7f | 0x08 => {
            form.fields[form.active].value.pop();
            form.error = None;
            FormOutcome::Stay(form)
        }
        _ => {
            // Append typed printable ASCII, but ONLY if the resulting value isn't Invalid per the
            // single `field_state` authority (shared with save). A letter can't land in a number field
            // and `pins` can't reach `44545454545` - both because the value would be Invalid - with no
            // separate char-class list to drift. The `0x20..0x7f` gate blocks control / multibyte bytes.
            let label = form.fields[form.active].label;
            let v = &mut form.fields[form.active].value;
            for &b in key {
                if !(0x20..0x7f).contains(&b) {
                    continue;
                }
                // Append then roll back on reject - no per-byte clone of the whole value, so pasting
                // n chars stays O(n·len) instead of O(n²) clones.
                v.push(b as char);
                if !field_value_ok(label, v) {
                    v.pop();
                }
            }
            form.error = None;
            FormOutcome::Stay(form)
        }
    }
}

/// Carry out a submitted form: create the volume, or write the profile back to `kern.toml`.
fn apply_form(form: &Form) -> Result<(), String> {
    match &form.submit {
        Submit::CreateVolume => {
            let name = form.fields[0].value.trim();
            if name.is_empty() {
                return Err("name is required".into());
            }
            let size = form.fields[1].value.trim();
            let mut args = vec!["create".to_string(), name.to_string()];
            if !size.is_empty() {
                args.push("--size".to_string());
                args.push(size.to_string());
            }
            let mut res = Ok(());
            quiet_io(|| res = crate::volume::run(&args));
            res.map_err(|e| e.to_string())
        }
        Submit::EditVolume { orig_name } => {
            let get = |l: &str| {
                form.fields
                    .iter()
                    .find(|f| f.label == l)
                    .map(|f| f.value.trim())
                    .unwrap_or("")
            };
            let name = get("name");
            if name.is_empty() {
                return Err("name is required".into());
            }
            let size_raw = get("size");
            // Blank size clears the quota; otherwise it must parse (and be > 0 - a 0-byte quota is
            // meaningless and is the mistake that produced the confusing `0 B` quota).
            let size = if size_raw.is_empty() {
                None
            } else {
                Some(
                    crate::config::size_to_bytes(size_raw)
                        .ok_or("size: e.g. 2g, 512m, 1g (or blank for none)")?,
                )
            };
            crate::volume::edit(orig_name, name, size).map_err(|e| e.to_string())
        }
        Submit::SaveProfile { section, orig_name } => {
            let (name, body) = form_to_body(&form.fields)?;
            // The fields this form controls; every OTHER key already in the block (numa, nice, an i2c
            // set via `kern config add`, …) is preserved by the merge.
            let managed: Vec<&str> = form
                .fields
                .iter()
                .map(|f| f.label)
                .filter(|l| *l != "name")
                .collect();
            crate::config::save_named_block(section, orig_name.as_deref(), &name, &managed, &body)
        }
    }
}

/// Turn a profile form's fields into (name, body lines) via the shared `config` schema - the
/// SAME validation + emission `kern config add` and the loader use, so the two paths can't diverge.
fn form_to_body(fields: &[Field]) -> Result<(String, Vec<String>), String> {
    let name = fields
        .iter()
        .find(|f| f.label == "name")
        .map(|f| f.value.trim())
        .unwrap_or("");
    let pairs: Vec<(&str, &str)> = fields
        .iter()
        .filter(|f| f.label != "name")
        .map(|f| (f.label, f.value.trim()))
        .collect();
    let body = crate::config::profile_block(name, &pairs)?;
    Ok((name.to_string(), body))
}

/// Remove a profile block from `kern.toml`, preserving the rest (shared with `kern config rm`).
fn delete_profile(section: &str, name: &str) -> Result<(), String> {
    crate::config::delete_named_block(section, name)
}

/// The detail text shown in the Volumes inspect overlay.
fn volume_detail(v: &crate::volume::VolInfo) -> String {
    let quota = v.quota.map_or_else(
        || "∞ (unlimited - grows until the disk is full)".to_string(),
        human_bytes,
    );
    format!(
        "volume '{}'\n\n  data used   {}\n  quota       {}\n  mount with  -v {}:/path[:ro]",
        v.name,
        // `-` until the sizer has measured this volume (a volume made a moment ago): an unmeasured
        // volume and an empty one are different facts, so never `0`.
        v.size.map_or_else(|| "-".to_string(), human_bytes),
        quota,
        v.name
    )
}

/// Snapshot the Boxes table once (used when stdout is not a TTY - e.g. piped).
///
/// EVERY RATE IN THIS PANE IS A DELTA, so a one-shot has to take the pair itself. The host CPU%
/// already did (two `/proc/stat` samples ~120 ms apart); the per-box CPU% and the box-start rate did
/// not, and both are wrong in the same direction - `collect_rows(&HashMap::new())` has no previous
/// sample, so it takes the `None => 0.0` arm for every box, and a `HostStats::default()` carries
/// `box_starts_total: 0`, which is the arm that prints a blank line instead of the rate.
///
/// MEASURED, both: a box pegging a full core read `0%` here across 24 consecutive snapshots while its
/// own cgroup `cpu.stat` and its workload's `/proc/<pid>/stat` ticks both said 100%, and the
/// interactive tab beside it said `100%` too. A wrong number is worse than an absent one on this
/// surface: piped `top` is what a script, CI, or an agent reads, and 0% is not obviously a
/// placeholder. The start-rate line matters for the same reader - an SDK firing ~ms boxes leaves the
/// live list empty, and that line is the only place its work shows up.
///
/// One sleep, not three: the first half of all three samples is taken before it.
pub fn snapshot() -> Result<(), crate::error::Error> {
    let p = Palette::detect();
    let (_, s1) = read_host(None);
    let prev_rows = sample_box_cpu();
    let (mut prev_box, mut box_hist) = (None, Vec::new());
    sample_rate(crate::runstats::box_total(), &mut prev_box, &mut box_hist);
    std::thread::sleep(std::time::Duration::from_millis(120));
    let (mut host, _) = read_host(s1);
    let bt = crate::runstats::box_total();
    (
        host.box_starts_per_sec,
        host.box_starts_peak,
        host.box_starts_spark,
    ) = sample_rate(bt, &mut prev_box, &mut box_hist);
    host.box_starts_total = bt;
    let mem_pct = host.mem_pct();
    println!(
        "host: CPU {:.0}%  RAM {} / {} ({:.0}%)  load {:.2} ({} cores)",
        host.cpu_pct,
        human_bytes(host.mem_used),
        human_bytes(host.mem_total),
        mem_pct,
        host.load1,
        host.cores
    );
    let (rows, _) = collect_rows(&prev_rows);
    print!("{}", boxes_table(&p, &rows, usize::MAX, usize::MAX, &host));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// `kern top --json [--tab LIST] [--stream [--interval S]]`: the same frames, for a program.
//
// ONE PRODUCER. Every frame is built by `refresh_full`, the function the screen draws from, with
// the same cost rule: the expensive records (images, builds, volume sizes) are read only for the
// tabs asked for, exactly as the screen reads them only for the tab on view. So `kern top` and its
// JSON cannot disagree about a box, which is the failure the `orphaned` field above records.
//
// THE CONTRACT IS VERSIONED. `schema` opens every frame and `kern version --json` reports it as
// `json_schema`, so a reader decides whether it can read a kern by a number, not by parsing a
// version string. A field is never renamed or retyped under the same schema; a new field may be
// added.
//
// WHAT A FRAME COSTS, MEASURED on this host (28 cores, 2 GPUs, 557 volumes, 8951 finished
// sandboxes): kern's own work is about 2 ms of CPU a frame. The GPUs come from one `nvidia-smi` kept
// running (`GpuStream`): 50 frames at 0.2 s went from 0.35 s of CPU to 0.11 s, and from six
// `nvidia-smi` to one; a single frame from 188 ms to about 150. Two lists were
// unbounded and are not any more: every finished sandbox in every frame was 1.4 MB a line, now the
// newest `LIST_CAP`; measuring every volume's size was 70 ms of CPU a frame, now at most once every
// `VOLUME_SIZES_EVERY` while streaming.

/// The shape `kern top --json` writes. `kern version --json` reports it.
pub(crate) const JSON_SCHEMA: u32 = 1;

/// The longest list a frame carries (builds, sandboxes): the newest, as the screen reads them at
/// first. The count of all of them is in `counts`.
const LIST_CAP: usize = 512;

/// How old a volume size may be before a stream measures it again.
const VOLUME_SIZES_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// A tab named as the tab bar names it, any case: its index. `None` for any other word.
/// `runs` is the tab's name before `kern limit` had that name, kept for a script written then.
pub(crate) fn json_tab(name: &str) -> Option<usize> {
    if name.eq_ignore_ascii_case("runs") {
        return Some(TAB_RUNS);
    }
    TABS.iter().position(|t| t.eq_ignore_ascii_case(name))
}

/// What the frames are built from from one to the next: the baselines every rate and CPU% is a
/// delta against, as the screen keeps them, and the volume sizes last measured.
#[derive(Default)]
struct JsonState {
    prev: HashMap<i32, (u64, Instant)>,
    prev_cpu: Option<(u64, u64)>,
    prev_runs: Option<(u64, Instant)>,
    runs_hist: Vec<f64>,
    prev_box: Option<(u64, Instant)>,
    box_hist: Vec<f64>,
    sizes: HashMap<String, Option<u64>>,
    sized_at: Option<Instant>,
}

impl JsonState {
    fn frame(&mut self, tabs: &[usize]) -> Snapshot {
        let mut s = refresh_full(
            &mut self.prev,
            &mut self.prev_cpu,
            &mut self.prev_runs,
            &mut self.runs_hist,
            &mut self.prev_box,
            &mut self.box_hist,
            TAB_OVERVIEW,
        );
        if tabs.contains(&TAB_IMAGES) {
            s.set_images(crate::commands::image_entries_with(
                crate::listing::Detail::Read,
            ));
        }
        if tabs.contains(&TAB_BUILDS) {
            s.set_builds(builds_listing(crate::listing::Detail::Read));
        }
        if tabs.contains(&TAB_STORAGE) {
            self.sized(&mut s.vols);
        }
        s
    }

    /// The volumes `refresh_full` listed, with sizes measured at most every `VOLUME_SIZES_EVERY`:
    /// a volume created since then reads `null` until the next measure.
    fn sized(&mut self, vols: &mut Vec<crate::volume::VolInfo>) {
        let stale = self
            .sized_at
            .is_none_or(|t| t.elapsed() >= VOLUME_SIZES_EVERY);
        if stale {
            *vols = crate::volume::entries_with(crate::volume::Sizes::Measure);
            self.sizes = vols.iter().map(|v| (v.raw.clone(), v.size)).collect();
            self.sized_at = Some(Instant::now());
            return;
        }
        for v in vols.iter_mut() {
            v.size = self.sizes.get(&v.raw).copied().flatten();
        }
    }
}

/// A float JSON can carry: a non-finite one (a rate before its first delta) is `null`.
fn put_f(o: &mut String, v: f64) {
    use std::fmt::Write as _;
    if v.is_finite() {
        let _ = write!(o, "{v:.2}");
    } else {
        o.push_str("null");
    }
}

fn put_opt<T: std::fmt::Display>(o: &mut String, v: Option<T>) {
    use std::fmt::Write as _;
    match v {
        Some(x) => {
            let _ = write!(o, "{x}");
        }
        None => o.push_str("null"),
    }
}

fn put_str(o: &mut String, v: &str) {
    o.push_str(&kern_common::json_str(v));
}

/// `"key":[item,item,...]`, each item written by `f`.
fn put_list<T>(
    o: &mut String,
    key: &str,
    items: impl IntoIterator<Item = T>,
    mut f: impl FnMut(&mut String, T),
) {
    o.push_str(",\"");
    o.push_str(key);
    o.push_str("\":[");
    for (i, it) in items.into_iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        f(o, it);
    }
    o.push(']');
}

/// One frame as one line of JSON, written into one buffer.
fn frame_json(s: &Snapshot, tabs: &[usize], ts_ms: u64) -> String {
    use std::fmt::Write as _;
    let h = &s.host;
    let mut o = String::with_capacity(1024 + s.rows.len() * 256);
    let _ = write!(o, "{{\"schema\":{JSON_SCHEMA},\"kern\":");
    put_str(&mut o, kern_common::VERSION);
    let _ = write!(o, ",\"ts_ms\":{ts_ms},\"tabs\":[");
    for (i, t) in tabs.iter().filter_map(|t| TABS.get(*t)).enumerate() {
        if i > 0 {
            o.push(',');
        }
        put_str(&mut o, &t.to_ascii_lowercase());
    }
    o.push_str("],\"host\":{\"cpu_pct\":");
    put_f(&mut o, h.cpu_pct);
    let _ = write!(o, ",\"cores\":{},\"load1\":", h.cores);
    put_f(&mut o, h.load1);
    let _ = write!(
        o,
        ",\"mem_used\":{},\"mem_total\":{},\"disk_used\":{},\"disk_total\":{},\"disk_fill_pct\":{},\"logs_used\":{},\"logs_total\":{},\"logs_fill_pct\":{}}}",
        h.mem_used, h.mem_total, h.disk_used, h.disk_total, h.disk_fill, h.logs_used, h.logs_total, h.logs_fill
    );
    o.push_str(",\"services\":{\"docker_api\":");
    put_str(&mut o, &h.docker_api);
    o.push_str(",\"https\":");
    put_str(&mut o, &h.https);
    o.push('}');
    put_list(&mut o, "gpus", &h.gpus, |o, g| {
        let _ = write!(o, "{{\"index\":{},\"name\":", g.index);
        put_str(o, &g.name);
        o.push_str(",\"bus\":");
        put_str(o, &g.bus);
        o.push_str(",\"mem_used_mib\":");
        put_opt(o, g.mem_used_mib);
        o.push_str(",\"mem_total_mib\":");
        put_opt(o, g.mem_total_mib);
        o.push_str(",\"util_pct\":");
        put_opt(o, g.util_pct);
        o.push_str(",\"temp_c\":");
        put_opt(o, g.temp_c);
        o.push_str(",\"power_w\":");
        match g.power_w {
            Some(w) => put_f(o, w),
            None => o.push_str("null"),
        }
        o.push('}');
    });
    let _ = write!(o, ",\"runs\":{{\"total\":{},\"per_sec\":", h.runs_total);
    put_f(&mut o, h.runs_per_sec);
    o.push_str(",\"peak_per_sec\":");
    put_f(&mut o, h.runs_peak);
    let _ = write!(o, ",\"avg_setup_us\":{}}}", h.runs_avg_us);
    let _ = write!(
        o,
        ",\"box_starts\":{{\"total\":{},\"per_sec\":",
        h.box_starts_total
    );
    put_f(&mut o, h.box_starts_per_sec);
    o.push_str(",\"peak_per_sec\":");
    put_f(&mut o, h.box_starts_peak);
    o.push('}');
    put_list(&mut o, "boxes", &s.rows, |o, r| {
        o.push_str("{\"name\":");
        put_str(o, &r.name);
        // `null` between two runs, never 0: a consumer that signals a row's pid must not be
        // handed one that `kill(2)` reads as "the whole process group".
        o.push_str(",\"pid\":");
        if r.restarting {
            o.push_str("null");
        } else {
            let _ = write!(o, "{}", r.pid);
        }
        let _ = write!(
            o,
            ",\"restarting\":{},\"uptime_s\":{},\"mem_bytes\":",
            r.restarting, r.uptime
        );
        put_opt(o, r.mem);
        o.push_str(",\"cpu_pct\":");
        put_f(o, r.cpu_pct);
        o.push_str(",\"tasks\":");
        put_opt(o, r.tasks);
        let _ = write!(
            o,
            ",\"paused\":{},\"orphaned\":{},\"health\":",
            r.paused, r.orphaned
        );
        put_str(o, &r.health);
        o.push_str(",\"ports\":");
        put_str(o, &r.ports);
        o.push_str(",\"pod\":");
        put_str(o, &r.pod);
        o.push_str(",\"isolation\":");
        put_str(o, &r.iso);
        o.push_str(",\"confinement\":");
        put_str(o, &r.sec);
        let _ = write!(
            o,
            ",\"oom_kills\":{},\"oom_killed\":{},\"restarts\":{},\"network\":",
            r.oom_kills,
            r.oom_kills > 0,
            r.restarts
        );
        put_str(o, r.net);
        o.push('}');
    });
    let _ = write!(
        o,
        ",\"counts\":{{\"boxes\":{},\"images\":{},\"builds\":{},\"profiles\":{},\"volumes\":{},\"sandboxes\":{}}}",
        s.rows.len(),
        s.images_total,
        s.builds_total,
        s.profs.len(),
        s.vols.len(),
        s.sbx.len()
    );
    if tabs.contains(&TAB_IMAGES) {
        // The shape of `kern images --json`, field names included.
        put_list(&mut o, "images", &s.images, |o, i| {
            o.push_str("{\"image\":");
            put_str(o, &i.name);
            let _ = write!(
                o,
                ",\"size_bytes\":{},\"pulled\":{},\"dangling\":{}}}",
                i.size, i.pulled, i.dangling
            );
        });
    }
    if tabs.contains(&TAB_BUILDS) {
        put_list(&mut o, "builds", s.builds.iter().take(LIST_CAP), |o, b| {
            o.push_str(&crate::commands::build_json(b));
        });
    }
    if tabs.contains(&TAB_PROFILES) {
        put_list(&mut o, "profiles", &s.profs, |o, p| {
            o.push_str("{\"section\":");
            put_str(o, p.section);
            o.push_str(",\"name\":");
            put_str(o, &p.name);
            o.push_str(",\"summary\":");
            put_str(o, &p.summary);
            o.push('}');
        });
    }
    if tabs.contains(&TAB_STORAGE) {
        put_list(&mut o, "volumes", &s.vols, |o, v| {
            o.push_str("{\"name\":");
            put_str(o, &v.raw);
            o.push_str(",\"size_bytes\":");
            put_opt(o, v.size);
            o.push_str(",\"quota_bytes\":");
            put_opt(o, v.quota);
            o.push('}');
        });
    }
    if tabs.contains(&TAB_SANDBOXES) {
        put_list(&mut o, "sandboxes", s.sbx.iter().take(LIST_CAP), |o, e| {
            o.push_str(&crate::history::entry_json(e));
        });
    }
    o.push('}');
    o
}

/// `kern top --json`: one frame, or with `stream` one frame a line every `interval` until the
/// reader goes away.
pub fn json(
    tabs: &[usize],
    stream: bool,
    interval: std::time::Duration,
) -> Result<(), crate::error::Error> {
    if tabs.contains(&TAB_LOGS) {
        return Err(crate::error::Error::Cli(
            "kern top --json --tab logs: the logs are a stream of their own, `kern logs --all -f` \
             (one line each, `box | ` first)"
                .to_string(),
        ));
    }
    let mut tabs: Vec<usize> = tabs.to_vec();
    if tabs.is_empty() {
        tabs = vec![TAB_OVERVIEW, TAB_BOXES];
    }
    tabs.sort_unstable();
    tabs.dedup();
    // ONE `nvidia-smi` for the whole run, single frame included: started now, its first reading
    // lands during the baseline's 120 ms instead of after them.
    start_gpu_stream();
    let mut st = JsonState::default();
    // THE FIRST FRAME IS A BASELINE, not a reading: host CPU% and every rate are deltas, and the
    // screen's first frame shows `0%` for the same reason. Sampled, then 120 ms, then reported,
    // which is what `snapshot` (the non-terminal `kern top`) does.
    GPU_WAIT.with(|w| w.set(false));
    let _ = st.frame(&tabs);
    GPU_WAIT.with(|w| w.set(true));
    std::thread::sleep(std::time::Duration::from_millis(120));
    let out = std::io::stdout();
    loop {
        let s = st.frame(&tabs);
        let line = frame_json(&s, &tabs, registry::unix_ms());
        let mut w = out.lock();
        // A reader that closed the pipe ends the stream; it is not an error of kern's.
        if writeln!(w, "{line}").and_then(|()| w.flush()).is_err() {
            return Ok(());
        }
        drop(w);
        if !stream {
            return Ok(());
        }
        std::thread::sleep(interval);
    }
}

/// The ONLY thing `collect_rows` wants from a previous frame: each box's `(cpu_usec, instant)`. Split
/// out so a one-shot snapshot can take the earlier half of the pair without paying for a whole
/// `collect_rows` - no health sidecars, no `/proc` isolation walk, no pod sort. Keyed on `pid` and
/// read through `cgroup_pid()` exactly as `collect_rows` does, because a key or a cgroup that
/// disagreed would silently miss every box and land back on the `0%` this exists to fix.
fn sample_box_cpu() -> HashMap<i32, (u64, Instant)> {
    let now = Instant::now();
    registry::list()
        .into_iter()
        .map(|b| {
            let usec = registry::box_stats(b.cgroup_pid()).cpu_usec.unwrap_or(0);
            (b.pid, (usec, now))
        })
        .collect()
}

/// Read the registry and compute each box's frame-to-frame CPU%, returning the rows and the new
/// `(cpu_usec, instant)` map for the next frame.
/// One frame's worth of data: the box rows + host stats + the `kern.toml` view (profiles) and the
/// on-disk volumes. Gathered on the 1 s tick (and refreshed after a mutating action) so pure
/// navigation keys re-render from this cache instead of re-scanning `/proc`, cgroups, `kern.toml`
/// and every volume dir on every keystroke.
struct Snapshot {
    rows: Vec<Row>,
    host: HostStats,
    cfg: crate::config::KernConfig,
    profs: Vec<ProfRow>,
    vols: Vec<crate::volume::VolInfo>,
    builds: Vec<crate::builds::Record>,
    /// Build records ON DISK, which is what the tab bar counts. Not `builds.len()`: that is the
    /// subset actually read, and it is empty on every tab but Builds.
    builds_total: usize,
    images: Vec<crate::commands::ImageEntry>,
    /// Cached images ON DISK, which is what the tab bar counts. See `builds_total`.
    images_total: usize,
    /// Finished sandboxes, newest first (cached by `history`, so cheap on every frame).
    sbx: std::sync::Arc<[crate::history::Entry]>,
}

impl Snapshot {
    /// Take a listing whole. The records and the total are two halves of one fact and drift
    /// silently if set apart: a caller that assigns only the records leaves the tab bar reporting
    /// the previous count, which is wrong in the one direction nobody checks (too high, so the
    /// list looks truncated rather than empty). Every site that replaces a list goes through one
    /// of these.
    fn set_builds(&mut self, listing: crate::listing::Listing<crate::builds::Record>) {
        self.builds = listing.records;
        self.builds_total = listing.total;
    }

    fn set_images(&mut self, listing: crate::listing::Listing<crate::commands::ImageEntry>) {
        self.images = listing.records;
        self.images_total = listing.total;
    }
}

/// One daemonless throughput lens: from a monotonic `total` and the prior `(total, instant)`, derive the
/// rate/sec since the last sample, push it onto a bounded reader-side sparkline ring, and return
/// `(rate_per_sec, session_peak, spark)`. Advances `prev` to now. Shared by the runs and box-start lenses.
fn sample_rate(
    total: u64,
    prev: &mut Option<(u64, Instant)>,
    hist: &mut Vec<f64>,
) -> (f64, f64, Vec<f64>) {
    const SPARK_N: usize = 48;
    let mut rate = 0.0;
    if let Some((pt, pi)) = *prev {
        let dt = pi.elapsed().as_secs_f64();
        if dt > 0.05 {
            rate = total.saturating_sub(pt) as f64 / dt;
        }
    }
    hist.push(rate);
    if hist.len() > SPARK_N {
        hist.remove(0);
    }
    let peak = hist.iter().copied().fold(0.0_f64, f64::max);
    *prev = Some((total, Instant::now()));
    (rate, peak, hist.clone())
}

// ONE PLACE DECIDES WHAT A FRAME PAYS FOR.
//
// The rule is [`crate::listing`]'s: a list's EXISTENCE is needed on every frame, because the tab
// bar prints its count; a list's CONTENTS are needed only on its own tab, and the contents are the
// expensive half. These two say whether the frame about to be drawn is the one that needs them.
//
// They are functions and not an inlined `tab == TAB_x` because each answer is consumed at four call
// sites, and four copies is four chances for one to disagree. The failure would be silent in both
// directions: a tab that shows `-` forever, or every other tab paying a recursive walk once a
// second.

/// Volume sizes, measured by a child process (`kern __volume-sizes`) so the recursive walk never
/// runs on the thread that draws and reads keys.
///
/// The latest measurement is kept and applied to every frame's list ([`VolumeSizer::fill`]); a
/// volume it has not seen yet shows `-`, which is "not measured", never `0`. A new measurement is
/// started at most every [`VolumeSizer::FRESH`] while the Storage tab is on screen, and at once
/// after a volume is created or removed.
#[derive(Default)]
struct VolumeSizer {
    child: Option<std::process::Child>,
    out: Vec<u8>,
    sizes: HashMap<String, u64>,
    measured: Option<Instant>,
}

impl VolumeSizer {
    /// How old a measurement may be while the Storage tab is shown. The walk is the expensive half
    /// of the tab, and a volume's size does not move in the second it took to look.
    const FRESH: std::time::Duration = std::time::Duration::from_secs(5);

    /// Start a measurement, unless one is running.
    fn kick(&mut self) {
        use std::os::fd::AsRawFd;
        if self.child.is_some() {
            return;
        }
        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        let child = std::process::Command::new(exe)
            .arg("__volume-sizes")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn();
        let Ok(child) = child else {
            return;
        };
        if let Some(o) = child.stdout.as_ref() {
            let fd = o.as_raw_fd();
            // SAFETY: a descriptor this process owns through `child`; only its flags change.
            unsafe {
                let fl = libc::fcntl(fd, libc::F_GETFL);
                if fl >= 0 {
                    libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
                }
            }
        }
        self.out.clear();
        self.child = Some(child);
    }

    /// Start one if the last is older than [`Self::FRESH`] or there is none.
    fn want_fresh(&mut self) {
        if self.measured.is_none_or(|t| t.elapsed() >= Self::FRESH) {
            self.kick();
        }
    }

    /// The last measurement no longer describes the volumes: measure again now.
    fn stale(&mut self) {
        self.measured = None;
        self.kick();
    }

    /// The running measurement's output, for `poll`.
    fn fd(&self) -> Option<i32> {
        use std::os::fd::AsRawFd;
        self.child
            .as_ref()
            .and_then(|c| c.stdout.as_ref())
            .map(AsRawFd::as_raw_fd)
    }

    /// Read what the child has written; at its end, take the sizes and reap it.
    fn on_readable(&mut self) {
        use std::io::Read as _;
        let Some(child) = self.child.as_mut() else {
            return;
        };
        let Some(stdout) = child.stdout.as_mut() else {
            return;
        };
        let mut buf = [0u8; 65536];
        loop {
            match stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => self.out.extend_from_slice(buf.get(..n).unwrap_or(&[])),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(_) => break,
            }
        }
        let ok = child.wait().is_ok_and(|st| st.success());
        self.child = None;
        if !ok {
            return;
        }
        let mut sizes = HashMap::new();
        let mut fields = self.out.split(|b| *b == 0);
        while let (Some(raw), Some(bytes)) = (fields.next(), fields.next()) {
            let (Ok(raw), Some(bytes)) = (
                std::str::from_utf8(raw),
                std::str::from_utf8(bytes)
                    .ok()
                    .and_then(|b| b.parse::<u64>().ok()),
            ) else {
                continue;
            };
            sizes.insert(raw.to_string(), bytes);
        }
        self.sizes = sizes;
        self.measured = Some(Instant::now());
    }

    /// Put the latest sizes on a freshly read list.
    fn fill(&self, vols: &mut [crate::volume::VolInfo]) {
        for v in vols {
            if v.size.is_none() {
                v.size = self.sizes.get(&v.raw).copied();
            }
        }
    }
}

impl Drop for VolumeSizer {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// The build records, from [`crate::builds::list_cached`] with this process's cache: a finished
/// record is read once per `kern top` session, not once a second.
fn builds_listing(
    detail: crate::listing::Detail,
) -> crate::listing::Listing<crate::builds::Record> {
    BUILD_RECORDS.with(|c| {
        crate::builds::list_cached(&mut c.borrow_mut(), detail, BUILDS_SHOWN.with(|n| n.get()))
    })
}

/// How many build records the session reads: one chunk to start, a chunk more each time the
/// selection comes within a page of the end of what is read ([`builds_reach`]).
const BUILDS_CHUNK: usize = 512;

thread_local! {
    static BUILD_RECORDS: std::cell::RefCell<crate::builds::RecordCache> =
        std::cell::RefCell::new(crate::builds::RecordCache::default());
    static BUILDS_SHOWN: std::cell::Cell<usize> = const { std::cell::Cell::new(BUILDS_CHUNK) };
}

/// The selection is near the end of the build records read so far and the store has more: read
/// the next chunk. `true` when it grew, so the caller re-reads the list.
fn builds_reach(sel: usize, read: usize, total: usize, page: usize) -> bool {
    let reach = sel.saturating_add(page.saturating_mul(2));
    if read >= total || reach < read {
        return false;
    }
    // Up to where the selection is plus two pages, in whole chunks, in ONE step: `End` on a long
    // history reads to the end at once rather than a chunk per frame.
    let want = reach
        .saturating_add(1)
        .div_ceil(BUILDS_CHUNK)
        .saturating_mul(BUILDS_CHUNK);
    BUILDS_SHOWN.with(|n| n.set(n.get().saturating_add(BUILDS_CHUNK).max(want)));
    true
}

/// Does the frame about to be drawn print the RECORDS of the list that `owner` owns?
///
/// `owner` is the tab that displays the list: `TAB_BUILDS` for build records (one `open` each, 921
/// on this host), `TAB_IMAGES` for cached images (one sentinel read each plus one sidecar per layer
/// reference, 889 on the same host). Both counts come free from the directory sweep either way.
fn detail_policy(tab: usize, owner: usize) -> crate::listing::Detail {
    if tab == owner {
        crate::listing::Detail::Read
    } else {
        crate::listing::Detail::Skip
    }
}

/// A full refresh: re-sample everything and advance the CPU% baselines (`prev`, `prev_cpu`) - used
/// on the 1 s tick, where the ~1 s delta gives a meaningful CPU percentage.
///
/// `tab` DECIDES THE COST OF THIS CALL, and this call is most of the cost of a frame. It is the tab
/// about to be drawn, and nothing here displays it: it is here only so the three expensive
/// collectors can be asked for the cheap half of their answer when the frame will not show the
/// expensive half. Measured on this host, per refresh, once a second:
///
/// - volumes: the recursive walk of 342 volume trees was 46085 `lstat` and 12684 `getdents64`,
///   69 ms of the 75 the first frame took. Storage tab only.
/// - builds: one `open` per record, 921 of them. Builds tab only.
/// - images: one sentinel read per image plus one sidecar per layer reference, 889 of them (364
///   distinct layers shared across 316 images). Images tab only.
///
/// Every tab still gets each list's COUNT for the tab bar, which falls out of the directory sweep
/// the collector makes anyway. Passing the policies in from outside was the earlier shape and it
/// put four copies of `tab == TAB_x` at four call sites; the policy lives in `*_policy` now and the
/// callers pass the one fact they actually have.
fn refresh_full(
    prev: &mut HashMap<i32, (u64, Instant)>,
    prev_cpu: &mut Option<(u64, u64)>,
    prev_runs: &mut Option<(u64, Instant)>,
    runs_hist: &mut Vec<f64>,
    prev_box: &mut Option<(u64, Instant)>,
    box_hist: &mut Vec<f64>,
    tab: usize,
) -> Snapshot {
    let (rows, seen) = collect_rows(prev);
    *prev = seen;
    let (mut host, cpu_now) = read_host(*prev_cpu);
    *prev_cpu = cpu_now;
    // Two daemonless throughput lenses from the same mmap counter, same reader-side rate+sparkline shape
    // (see `sample_rate`): `kern limit` invocations (offset 0, + an honest average setup latency), and box
    // STARTS (offset 16). The box lens is what makes an ephemeral agent firehose visible - the live list
    // can't show a ~ms box, the rate can. Neither is a live "peak concurrent" (that would need a reaper).
    let (rt, lat_sum_us) = crate::runstats::snapshot();
    (host.runs_per_sec, host.runs_peak, host.runs_spark) = sample_rate(rt, prev_runs, runs_hist);
    host.runs_total = rt;
    host.runs_avg_us = lat_sum_us.checked_div(rt).unwrap_or(0);
    let bt = crate::runstats::box_total();
    (
        host.box_starts_per_sec,
        host.box_starts_peak,
        host.box_starts_spark,
    ) = sample_rate(bt, prev_box, box_hist);
    host.box_starts_total = bt;
    let cfg = crate::config::load(None).unwrap_or_default();
    let profs = profile_rows(&cfg);
    // Never measured here: see `VolumeSizer`.
    let vols = crate::volume::entries_with(crate::volume::Sizes::Skip);
    let builds = builds_listing(detail_policy(tab, TAB_BUILDS));
    let images = crate::commands::image_entries_with(detail_policy(tab, TAB_IMAGES));
    Snapshot {
        rows,
        host,
        cfg,
        profs,
        vols,
        builds: builds.records,
        builds_total: builds.total,
        images: images.records,
        images_total: images.total,
        sbx: crate::history::sandboxes_newest_first(),
    }
}

/// A compact marker of how a running box DEVIATES from the secure default: `net:host` (it shares the
/// host network namespace instead of an isolated one) and/or `root-mapped` (its uid 0 maps to host uid
/// 0 - kern ran as root). Empty when the box is fully isolated, so the Boxes tab flags only the boxes
/// that are LESS confined than default (the always-on layers - seccomp, masked `/proc`, dropped caps -
/// are identical for every box, so a "secure" badge would be vanity). Read-only `/proc` introspection.
fn box_isolation(pid: i32, pod: &str) -> String {
    let mut flags = Vec::new();
    // Shared host netns? `kern top` runs in the host netns, so an equal namespace link means the box
    // was started with `--network host` (no isolated netns).
    let mut host_net = false;
    if let (Ok(bx), Ok(me)) = (
        std::fs::read_link(format!("/proc/{pid}/ns/net")),
        std::fs::read_link("/proc/self/ns/net"),
    ) {
        if bx == me {
            host_net = true;
            flags.push("net:host");
        }
    }
    // ITS OWN NAT, Docker's default since 0.57: the box reaches the internet, which is the one thing
    // a reader of this column most needs to tell apart from a `--network none` box (no flag, the
    // most isolated). Read off the box's own interfaces: anything but `lo` outside a pod (whose
    // network the POD column already names). One small `/proc` read.
    if !host_net && pod.is_empty() && has_interface_beyond_lo(pid) {
        flags.push("net:nat");
    }
    // Root-mapped: the first uid_map line is `inside outside count`; inside-0 → outside-0 means the box
    // root is host root (a rootless box maps 0 to the unprivileged user's uid instead).
    if let Ok(map) = std::fs::read_to_string(format!("/proc/{pid}/uid_map")) {
        let first: Vec<&str> = map
            .lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        if first.len() == 3 && first[0] == "0" && first[1] == "0" {
            flags.push("root-mapped");
        }
    }
    // Extra caps: a box whose BOUNDING set (`CapBnd`) contains a cap kern always drops by default
    // (DEFAULT_DROP - module load, raw I/O, BPF, …) kept one it would normally drop, so it is less
    // confined than default. That happens via `--cap-add`, or via `--tun` (keeps `NET_ADMIN`) or
    // `--privileged` (keeps `SYS_ADMIN`) - all correctly flagged here. The bounding set is the honest
    // signal: a rootless box's `CapEff` is full but namespaced (grants no host power) and would
    // false-positive; `CapBnd` reflects what kern actually kept.
    if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
        if let Some(bnd) = status.lines().find_map(|l| l.strip_prefix("CapBnd:")) {
            if let Ok(bits) = u64::from_str_radix(bnd.trim(), 16) {
                if bits & kern_isolation::default_dropped_cap_mask() != 0 {
                    flags.push("caps:+");
                }
            }
        }
    }
    // A GRANTED CARD IS A DEVICE GRANT, so it belongs with the flags above and not with the
    // more-confined badge: the box reaches real hardware through the host's driver, which is a
    // deviation from the isolated default in exactly the way `net:host` is.
    //
    // WHICH CARDS, NEVER HOW BUSY. NVML attributes nothing to a cgroup or a uid, so a per-box
    // utilisation number would be the host's figure wearing a box's name; this table would be
    // claiming an attribution the driver does not make. Ownership IS attributable, and it is the
    // question a reader of `kern top` is asking: who has the card.
    //
    // Read through the SAME function `kern inspect` uses, from the box's own `/dev`, so the two
    // views cannot disagree about one box. That disagreement has already happened in this file
    // once, over `orphaned`, and the comment on that field says what it cost.
    let gpus = crate::commands::inspect::gpu_nodes_of(Some(pid));
    let gpu_flag;
    if !gpus.is_empty() {
        let idx: Vec<&str> = gpus
            .split_whitespace()
            .filter_map(|n| n.strip_prefix("nvidia"))
            .collect();
        gpu_flag = format!("gpu:{}", idx.join(","));
        flags.push(&gpu_flag);
    }
    flags.join(" ")
}

/// One word for how the box whose init is `pid1` reaches out, off the flags [`box_isolation`] read: a
/// pod member with `net:host` is `host`. Empty when the init's network namespace cannot be read, which
/// [`box_isolation`] answers with no flag, the same as `none`.
fn net_kind(pid1: i32, pod: &str, iso: &str) -> &'static str {
    let has = |f: &str| iso.split_whitespace().any(|x| x == f);
    if pid1 <= 0 || std::fs::read_link(format!("/proc/{pid1}/ns/net")).is_err() {
        ""
    } else if has("net:host") {
        "host"
    } else if !pod.is_empty() {
        "pod"
    } else if has("net:nat") {
        "nat"
    } else {
        "none"
    }
}

/// Does the network namespace of `pid` have an interface other than `lo`?
fn has_interface_beyond_lo(pid: i32) -> bool {
    pid > 0
        && std::fs::read_to_string(format!("/proc/{pid}/net/dev")).is_ok_and(|t| {
            t.lines()
                .skip(2)
                .filter_map(|l| l.split(':').next())
                .any(|n| n.trim() != "lo")
        })
}

/// How long a unit's restart count and the services' state are reused: each read is a `systemctl`,
/// about 4 ms MEASURED, twice a frame's whole budget, and both change at a human pace.
const SYSTEMD_READ_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

/// systemd's `NRestarts` of the unit a `--restart always|unless-stopped` box runs under, 0 for a box
/// with none. A box without a unit costs one `stat` a frame; one with, a `systemctl show` every
/// [`SYSTEMD_READ_EVERY`].
fn unit_restarts(name: &str) -> u32 {
    static SEEN: std::sync::Mutex<Option<HashMap<String, (Instant, u32)>>> =
        std::sync::Mutex::new(None);
    if !crate::commands::has_managed_unit(name) {
        return 0;
    }
    let Ok(mut seen) = SEEN.lock() else {
        return 0;
    };
    let seen = seen.get_or_insert_with(HashMap::new);
    if let Some((at, n)) = seen.get(name) {
        if at.elapsed() < SYSTEMD_READ_EVERY {
            return *n;
        }
    }
    let n = crate::commands::managed_unit_runs(name).map_or(0, |u| u.restarts);
    seen.insert(name.to_string(), (Instant::now(), n));
    n
}

/// The Docker API socket and HTTPS as `kern info` says them, read every [`SYSTEMD_READ_EVERY`].
fn services() -> (String, String) {
    static SEEN: std::sync::Mutex<Option<(Instant, String, String)>> = std::sync::Mutex::new(None);
    let read = || {
        (
            crate::dockershim::socket_state().short(),
            crate::localtls::status_line(),
        )
    };
    let Ok(mut seen) = SEEN.lock() else {
        return read();
    };
    if let Some((at, api, https)) = seen.as_ref() {
        if at.elapsed() < SYSTEMD_READ_EVERY {
            return (api.clone(), https.clone());
        }
    }
    let (api, https) = read();
    *seen = Some((Instant::now(), api.clone(), https.clone()));
    (api, https)
}

fn collect_rows(prev: &HashMap<i32, (u64, Instant)>) -> (Vec<Row>, HashMap<i32, (u64, Instant)>) {
    let now_t = Instant::now();
    let now_u = registry::now_unix();
    let mut seen = HashMap::new();
    let mut rows = Vec::new();
    for b in registry::list() {
        // One cgroup resolve for all four readings (mem/cpu/tasks/frozen) instead of four.
        let st = registry::box_stats(b.cgroup_pid());
        let cpu_now = st.cpu_usec.unwrap_or(0);
        let cpu_pct = match prev.get(&b.pid) {
            Some((pu, t)) => {
                let dt = now_t.duration_since(*t).as_secs_f64().max(1e-6);
                (cpu_now.saturating_sub(*pu) as f64 / 1e6 / dt) * 100.0
            }
            None => 0.0,
        };
        seen.insert(b.pid, (cpu_now, now_t));
        let health = registry::health_of(&b.name, b.pid);
        // Introspect the box's INTERIOR init (`pid1`), not the host-side supervisor `pid` - the
        // supervisor lives in the host netns with the kernel's trivial uid_map, which would falsely flag
        // every box. `pid1 == 0` (unrecorded / old entry) → the /proc reads fail → no flag, no false
        // positive.
        let pid1 = b.live_pid1().unwrap_or(0);
        let iso = box_isolation(pid1, &b.pod);
        let net = net_kind(pid1, &b.pod, &iso);
        let mut sec = String::new();
        if !b.egress.is_empty() {
            sec.push_str("egress");
        }
        if !b.landlock_rw.is_empty() {
            if !sec.is_empty() {
                sec.push('+');
            }
            sec.push_str("landlock");
        }
        let oom_kills = crate::commands::inspect::box_oom_kills(&b);
        let restarts = crate::commands::inspect::box_restarts(&b, Some(unit_restarts(&b.name)));
        rows.push(Row {
            net,
            oom_kills,
            restarts,
            uptime: now_u.saturating_sub(b.started),
            mem: st.mem,
            tasks: st.tasks,
            paused: st.paused,
            cpu_pct,
            health,
            ports: b.ports,
            name: b.name,
            pid: b.pid,
            pod: b.pod,
            iso,
            sec,
            orphaned: b.orphaned,
            restarting: false,
            last_code: None,
        });
    }
    // A BOX BETWEEN TWO RUNS OF ITS `--restart` POLICY stays in the list, as `kern ps` and `docker
    // ps` keep a `Restarting (1)` row: MEASURED before, a crash-looping service blinked out of this
    // table for every gap, the one moment its row was the news. Asked of kern's units only (a
    // `readdir`), and of systemd only for a unit whose box is not in the registry now (about 3.4 ms).
    let live: std::collections::HashSet<String> = rows.iter().map(|r| r.name.clone()).collect();
    for name in crate::commands::managed_unit_names() {
        if live.contains(&name) {
            continue;
        }
        let Some(u) = crate::commands::managed_unit_runs(&name) else {
            continue;
        };
        if !u.restarting {
            continue;
        }
        rows.push(Row {
            name,
            pid: 0,
            uptime: 0,
            mem: None,
            cpu_pct: 0.0,
            tasks: None,
            paused: false,
            health: String::new(),
            ports: String::new(),
            pod: String::new(),
            iso: String::new(),
            sec: String::new(),
            orphaned: false,
            oom_kills: 0,
            restarts: u.restarts,
            net: "",
            restarting: true,
            last_code: u.last_code,
        });
    }
    // Group for the pod-tree view: standalone boxes first, then each pod's members contiguous (pods in
    // name order). A STABLE sort, so registry order is preserved within a group - and the selection
    // index stays valid (it just indexes this display order; actions still hit rows[sel]).
    rows.sort_by(|a, b| {
        (!a.pod.is_empty())
            .cmp(&!b.pod.is_empty())
            .then_with(|| a.pod.cmp(&b.pod))
    });
    (rows, seen)
}

/// A snapshot of host-wide resource use, shown in the Overview tab.
#[derive(Default)]
struct HostStats {
    mem_used: u64,
    mem_total: u64,
    disk_used: u64,
    disk_total: u64,
    /// The filesystem the box logs are on (`$XDG_RUNTIME_DIR`, a tmpfs in RAM on a desktop): a box's
    /// output is dropped when it is full, so its fill is watched like the disk's.
    logs_used: u64,
    logs_total: u64,
    /// Percent full as `df` counts it, which is what predicts ENOSPC (`commands::fs_fill`).
    disk_fill: u64,
    logs_fill: u64,
    cpu_pct: f64,
    cores: usize,
    load1: f64,
    /// Cumulative `kern limit` invocations (from the daemonless runstats mmap counter) + the derived
    /// rate/sec: fire-and-forget capped processes are too many to list, so they are counted instead.
    runs_total: u64,
    runs_per_sec: f64,
    /// Average per-run setup latency in microseconds (entry→exec, the honest "~1 ms"); 0 with no runs.
    runs_avg_us: u64,
    /// The highest runs/sec seen since `top` started (session peak throughput) and a reader-side ring of
    /// recent runs/sec samples for the Runs-tab sparkline - both derived from the monotonic total.
    runs_peak: f64,
    runs_spark: Vec<f64>,
    /// Cumulative box STARTS (daemonless runstats counter, offset 16) + derived rate/sec, session peak,
    /// and a reader-side sparkline. This is the lens the live Boxes list can't give for EPHEMERAL boxes:
    /// a `kern box` lives ~ms (below a 1 s refresh), so an agent firing hundreds/sec (via the SDK/MCP)
    /// is invisible in the list but shows here as a rate. Same daemonless mmap-counter shape as runs.
    box_starts_total: u64,
    box_starts_per_sec: f64,
    box_starts_peak: f64,
    box_starts_spark: Vec<f64>,
    /// The host's NVIDIA cards, one entry each (see [`host_gpus`]). Empty on a host with none.
    gpus: Vec<GpuStat>,
    /// The Docker API socket and HTTPS, in `kern info`'s words ([`services`]); empty when not read.
    docker_api: String,
    https: String,
}

/// One NVIDIA card as the Overview lists it. Every reading the driver may answer `N/A` for is an
/// `Option`, so a card that reports no power draw still gets its row.
#[derive(Clone, Debug, PartialEq)]
struct GpuStat {
    index: u32,
    name: String,
    /// `0000:01:00.0`, the bus as the driver's own `/proc/driver/nvidia/gpus` names it.
    bus: String,
    mem_used_mib: Option<u64>,
    mem_total_mib: Option<u64>,
    util_pct: Option<u32>,
    temp_c: Option<u32>,
    power_w: Option<f64>,
}

/// `nvidia-smi --query-gpu=index,name,pci.bus_id,memory.used,memory.total,utilization.gpu,
/// temperature.gpu,power.draw --format=csv,noheader,nounits`, one card per line. A line that does
/// not carry an index, a name and a bus is skipped; a reading the driver answered `[N/A]` for is
/// `None`.
fn parse_smi_gpus(text: &str) -> Vec<GpuStat> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split(',').map(str::trim).collect();
        if f.len() < 8 {
            continue;
        }
        let (Ok(index), name, raw_bus) = (f[0].parse::<u32>(), f[1], f[2]) else {
            continue;
        };
        // A JETSON'S GPU HAS NO PCI BUS, and its `nvidia-smi` answers `[N/A]` there and for every
        // reading: MEASURED on an Orin Nano, `0, Orin (nvgpu), [N/A], ...`. The line was skipped,
        // so `kern top` said `GPU none` on a host with a GPU. An empty bus is kept as empty.
        let bus = raw_bus.to_ascii_lowercase();
        let bus = bus
            .get(bus.len().saturating_sub(12)..)
            .unwrap_or(&bus)
            .to_string();
        let bus = if bus.len() == 12 && bus.contains(':') {
            bus
        } else {
            String::new()
        };
        if name.is_empty() {
            continue;
        }
        out.push(GpuStat {
            index,
            name: name.to_string(),
            bus,
            mem_used_mib: f[3].parse().ok(),
            mem_total_mib: f[4].parse().ok(),
            util_pct: f[5].parse().ok(),
            temp_c: f[6].parse().ok(),
            power_w: f[7].parse().ok(),
        });
    }
    out
}

/// The `/dev/nvidiaN` minor of the card on `bus`, from the driver's own record. A box holds a card
/// as that node, which is how [`overview`] counts the boxes on each card; the minor and the
/// nvidia-smi index are not guaranteed to agree, so the box count is keyed on the minor.
fn gpu_minor(bus: &str) -> Option<u32> {
    let info =
        std::fs::read_to_string(format!("/proc/driver/nvidia/gpus/{bus}/information")).ok()?;
    info.lines()
        .find_map(|l| l.strip_prefix("Device Minor:"))
        .and_then(|v| v.trim().parse().ok())
}

/// The host's NVIDIA cards, read with the driver's `nvidia-smi` at most once every two seconds.
///
/// `kern top` had no GPU line at all, so on a host with two cards and seven boxes using them the
/// one question a reader has (which card is full, which boxes hold it) was not on the screen. One
/// query costs about 20 ms (measured, five runs, on two RTX 5060 Ti), hence the cache; it runs
/// under `run_bounded`'s deadline, so a wedged driver cannot freeze the screen. A host without the
/// tool, or without NVIDIA cards, gets no section.
/// What `nvidia-smi` is asked, one card a line.
const SMI_QUERY: [&str; 2] = [
    "--query-gpu=index,name,pci.bus_id,memory.used,memory.total,utilization.gpu,temperature.gpu,power.draw",
    "--format=csv,noheader,nounits",
];

/// The cards' readings from ONE `nvidia-smi` left running (`-lms`), for the views that refresh
/// (the screen and `--json --stream`).
///
/// MEASURED on this host (2 GPUs): a reading from a fresh `nvidia-smi` costs about 44 ms of CPU,
/// almost all of it the driver library's start; from one already running, about 3 ms. The screen
/// asked a fresh one every 2 s, so its GPU rows were most of what `kern top` cost.
///
/// NO THREAD: the pipe is non-blocking and each refresh takes the lines that have arrived, the way
/// `VolumeSizer` reads its child. `kern top` stays single-threaded, which code that forks relies on.
/// The child gets `PDEATHSIG`, so it ends with kern however kern ends.
struct GpuStream {
    child: std::process::Child,
    out: std::process::ChildStdout,
    buf: Vec<u8>,
    cards: std::collections::BTreeMap<u32, GpuStat>,
    alive: bool,
}

thread_local! {
    static GPU_STREAM: std::cell::RefCell<Option<GpuStream>> = const { std::cell::RefCell::new(None) };
    /// Whether `host_gpus` waits for the stream's first reading. Off for `--json`'s baseline frame,
    /// which is never printed: the reading then arrives during the 120 ms that follow it.
    static GPU_WAIT: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// Start the running `nvidia-smi` for this process, once. A host with no `nvidia-smi` starts nothing.
pub(crate) fn start_gpu_stream() {
    GPU_STREAM.with(|g| {
        if g.borrow().is_none() {
            *g.borrow_mut() = GpuStream::spawn();
        }
    });
}

impl GpuStream {
    fn spawn() -> Option<Self> {
        let smi = smi_path()?;
        let mut args: Vec<&str> = SMI_QUERY.to_vec();
        args.extend(["-lms", "2000"]);
        Self::spawn_from(&smi, &args)
    }

    /// The reader over any program that prints `nvidia-smi`'s lines (the tests give it a fake one).
    fn spawn_from(program: &std::path::Path, args: &[&str]) -> Option<Self> {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new(program);
        cmd.args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        // SAFETY: prctl with integer arguments, async-signal-safe, in the child before exec.
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0,
                    0,
                    0,
                );
                Ok(())
            });
        }
        let mut child = cmd.spawn().ok()?;
        let Some(out) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        };
        let fd = out.as_raw_fd();
        // SAFETY: fcntl on the pipe this process just received.
        let nonblock = unsafe {
            let fl = libc::fcntl(fd, libc::F_GETFL);
            fl >= 0 && libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) == 0
        };
        if !nonblock {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        Some(Self {
            child,
            out,
            buf: Vec::with_capacity(1024),
            cards: std::collections::BTreeMap::new(),
            alive: true,
        })
    }

    /// The newest reading of every card, from what has arrived. `None` before the first line, and
    /// for good once `nvidia-smi` has ended (the caller then asks a fresh one, as before).
    fn poll(&mut self) -> Option<Vec<GpuStat>> {
        use std::io::Read;
        let mut chunk = [0u8; 4096];
        while self.alive {
            match self.out.read(&mut chunk) {
                Ok(0) => self.alive = false,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => self.alive = false,
            }
        }
        while let Some(nl) = self.buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=nl).collect();
            for g in parse_smi_gpus(&String::from_utf8_lossy(&line)) {
                self.cards.insert(g.index, g);
            }
        }
        // A line that never ends is not one: drop it rather than grow without bound.
        if self.buf.len() > 64 * 1024 {
            self.buf.clear();
        }
        if !self.alive || self.cards.is_empty() {
            return None;
        }
        Some(self.cards.values().cloned().collect())
    }
}

impl Drop for GpuStream {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Where `nvidia-smi` is. `/usr/sbin` IS WHERE A JETSON KEEPS IT, and it was not looked at:
/// measured on an Orin Nano. Then every directory on `PATH`, for a host that put it somewhere else.
fn smi_path() -> Option<std::path::PathBuf> {
    let fixed = [
        "/usr/bin/nvidia-smi",
        "/usr/sbin/nvidia-smi",
        "/usr/lib/wsl/lib/nvidia-smi",
        "/usr/local/bin/nvidia-smi",
    ]
    .map(std::path::PathBuf::from);
    let on_path = crate::global_env("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join("nvidia-smi"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    fixed.into_iter().chain(on_path).find(|p| p.is_file())
}

fn host_gpus() -> Vec<GpuStat> {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    // The running `nvidia-smi`, where this process started one: its newest reading, no process.
    // Its FIRST reading is waited for (up to 150 ms, the driver library's start) rather than paid
    // for twice by asking a fresh `nvidia-smi` beside it.
    let streamed = GPU_STREAM.with(|g| {
        let mut g = g.borrow_mut();
        let mut got = g.as_mut().and_then(GpuStream::poll);
        let mut waited = 0;
        let wait = GPU_WAIT.with(std::cell::Cell::get);
        while wait
            && got.is_none()
            && waited < 30
            && g.as_ref().is_some_and(|s| s.alive && s.cards.is_empty())
        {
            std::thread::sleep(std::time::Duration::from_millis(5));
            waited += 1;
            got = g.as_mut().and_then(GpuStream::poll);
        }
        if g.as_ref().is_some_and(|s| !s.alive) {
            *g = None;
        }
        got
    });
    if let Some(gpus) = streamed {
        return gpus
            .into_iter()
            .map(|g| tegra_readings(g, std::path::Path::new("/")))
            .collect();
    }
    // A stream that is starting and a caller that does not wait (the unprinted baseline): nothing
    // yet, and no second `nvidia-smi` beside the one that is about to answer.
    if !GPU_WAIT.with(std::cell::Cell::get) && GPU_STREAM.with(|g| g.borrow().is_some()) {
        return Vec::new();
    }
    static CACHE: Mutex<Option<(Instant, Vec<GpuStat>)>> = Mutex::new(None);
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, gpus)) = guard.as_ref() {
        if at.elapsed() < Duration::from_secs(2) {
            return gpus.clone();
        }
    }
    let gpus = smi_path()
        .and_then(|p| crate::gpu::run_bounded(&p, &SMI_QUERY))
        .map(|t| parse_smi_gpus(&t))
        .unwrap_or_default();
    let gpus = gpus
        .into_iter()
        .map(|g| tegra_readings(g, std::path::Path::new("/")))
        .collect::<Vec<_>>();
    *guard = Some((Instant::now(), gpus.clone()));
    gpus
}

/// An integrated (Tegra) GPU's readings from `/sys` under `root`, for what its `nvidia-smi` answers
/// `[N/A]`: the load (`<gpu>/load`, in thousandths) and the `gpu-thermal` zone (millidegrees). A
/// card with a PCI bus, or one whose readings are already there, is returned unchanged. Its memory
/// is the host's RAM (unified), which `gpu_rows` says rather than printing a dash.
fn tegra_readings(mut g: GpuStat, root: &std::path::Path) -> GpuStat {
    if !g.bus.is_empty() {
        return g;
    }
    if g.util_pct.is_none() {
        let platform = root.join("sys/devices/platform");
        let load = std::fs::read_dir(&platform)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".gpu"))
            .find_map(|e| std::fs::read_to_string(e.path().join("load")).ok())
            .and_then(|v| v.trim().parse::<u32>().ok());
        g.util_pct = load.map(|permille| (permille / 10).min(100));
    }
    if g.temp_c.is_none() {
        let zones = root.join("sys/class/thermal");
        g.temp_c = std::fs::read_dir(&zones)
            .into_iter()
            .flatten()
            .flatten()
            .find(|z| {
                std::fs::read_to_string(z.path().join("type"))
                    .is_ok_and(|t| t.trim() == "gpu-thermal")
            })
            .and_then(|z| std::fs::read_to_string(z.path().join("temp")).ok())
            .and_then(|v| v.trim().parse::<i64>().ok())
            .and_then(|mc| u32::try_from(mc / 1000).ok());
    }
    g
}

impl HostStats {
    /// RAM used as a percentage of total (0 when total is unknown).
    fn mem_pct(&self) -> f64 {
        if self.mem_total > 0 {
            self.mem_used as f64 / self.mem_total as f64 * 100.0
        } else {
            0.0
        }
    }
}

/// `(busy, total)` jiffies from `/proc/stat`'s aggregate `cpu ` line - CPU% is the delta of two.
fn host_cpu_sample() -> Option<(u64, u64)> {
    let s = std::fs::read_to_string("/proc/stat").ok()?;
    let mut it = s.lines().next()?.split_whitespace();
    if it.next()? != "cpu" {
        return None;
    }
    let v: Vec<u64> = it.filter_map(|t| t.parse().ok()).collect();
    if v.len() < 4 {
        return None;
    }
    let total: u64 = v.iter().sum();
    let idle = v[3] + v.get(4).copied().unwrap_or(0); // idle + iowait
    Some((total.saturating_sub(idle), total))
}

/// `(used, total)` host RAM in bytes, from `/proc/meminfo` (`used = total − available`).
fn host_mem() -> Option<(u64, u64)> {
    let s = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kb = |k: &str| {
        s.lines()
            .find_map(|l| l.strip_prefix(k))
            .and_then(|r| r.split_whitespace().next())
            .and_then(|n| n.parse::<u64>().ok())
    };
    let total = kb("MemTotal:")?;
    let avail = kb("MemAvailable:").or_else(|| kb("MemFree:"))?;
    Some((total.saturating_sub(avail) * 1024, total * 1024))
}

/// True for an on-board LED worth offering; false for the NOISE that dominates `/sys/class/leds` on a
/// desktop - a netdev LED (`<iface>` or `<iface>-<port>` before `::`, e.g. `enp5s0-0::lan`, a NIC PHY
/// light) or an input LED (`inputN::…`, a keyboard capslock light) - neither of which is a meaningful
/// device to pass into a sandbox. Real board LEDs (`led0`, `ACT`, `PWR`, `mmc0::…`) pass.
fn is_board_led(name: &str, nets: &[String]) -> bool {
    let head = name.split("::").next().unwrap_or(name);
    let is_input_led = head
        .strip_prefix("input")
        .is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit()));
    let is_netdev_led = nets
        .iter()
        .any(|iface| head == iface || head.strip_prefix(iface).is_some_and(|r| r.starts_with('-')));
    !is_input_led && !is_netdev_led
}

/// The host devices currently present for a vGPIO field `kind` - the options the new/edit form offers
/// as checkboxes, so a user PICKS from what actually exists instead of typing a `/dev/…` path (which
/// is easy to get wrong). Uniform for every host: the same probe runs everywhere, only the *contents*
/// differ - a Pi shows its i2c/gpio, a mini-PC its bluetooth/usb. Returns sorted; a busy desktop can
/// return many (e.g. 20 i2c DDC buses), so the form caps the visible count and keeps a manual field.
/// The shared, host-uniform probe: `section_fields` consumes it so every profile form picks devices
/// through one identical mechanism.
fn present_devices(kind: &str) -> Vec<String> {
    // Files under `dir` whose name starts with any of `prefixes`, mapped through `to_entry`.
    fn scan(dir: &str, prefixes: &[&str], to_entry: impl Fn(&str) -> String) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| prefixes.iter().any(|p| n.starts_with(p)))
            .map(|n| to_entry(&n))
            .collect();
        v.sort();
        v.dedup();
        v
    }
    let dev = |prefixes: &[&str]| scan("/dev", prefixes, |n| format!("/dev/{n}"));
    match kind {
        "i2c" => dev(&["i2c-"]),
        "pins" => dev(&["gpiochip"]), // pins are chip-granular → the gpiochip nodes
        "spi" => dev(&["spidev"]),
        "uart" => dev(&["ttyS", "ttyUSB", "ttyACM"]),
        "can" => dev(&["can"]),
        "camera" => dev(&["video"]),
        "input" => scan("/dev/input", &["event"], |n| format!("/dev/input/{n}")),
        "audio" => scan("/dev/snd", &["pcm", "controlC"], |n| {
            format!("/dev/snd/{n}")
        }),
        // On-board LED NAMES, but DROP the noise: `/sys/class/leds` on a desktop is dominated by
        // netdev LEDs (`enp5s0-0::lan` - a NIC PHY link light) and input LEDs (`input3::capslock` - a
        // keyboard light), which are meaningless to pass into a sandbox. A LED whose segment before
        // `::` is a present network interface, or is `inputN`, is filtered; real board LEDs (`led0`,
        // `ACT`, `PWR`, `mmc0::…`) remain.
        "leds" => {
            let nets = present_devices("net");
            scan("/sys/class/leds", &[""], |n| n.to_string())
                .into_iter()
                .filter(|n| is_board_led(n, &nets))
                .collect()
        }
        "bluetooth" => scan("/sys/class/bluetooth", &["hci"], |n| n.to_string()),
        "net" => scan("/sys/class/net", &[""], |n| n.to_string()), // interface NAMES (eth0, wlan0…)
        "midi" => scan("/dev/snd", &["midi"], |n| format!("/dev/snd/{n}")), // ALSA MIDI nodes
        // GPU: offer the RENDER node (renderD*, allowed for compute/video) - the privileged card*
        // modeset node is refused by the resolver, so it isn't offered.
        "display" => scan("/dev/dri", &["renderD"], |n| format!("/dev/dri/{n}")),
        _ => Vec::new(),
    }
}

/// `(used, total)` bytes on the filesystem that backs the kern data root - `statvfs("/")`, matching
/// `df` (used = blocks − free). This is the disk where images / volumes / vdisks physically live.
///
/// ONE IMPLEMENTATION, in [`crate::commands::fs_usage`]. This was a private copy here, and
/// `config setup` needed the same measurement to write a `[[disk]]` budget. Two copies of a `statvfs`
/// wrapper is how `kern top` and a generated config come to state different totals for the same
/// disk; the shared one also does its arithmetic checked, which this one did not.
fn host_disk() -> Option<(u64, u64)> {
    crate::commands::fs_usage("/")
}

/// The host's logical CPU count (per-CPU lines in `/proc/stat`), resolved once - the core count is
/// fixed for the process's life, so `top` needn't re-read `/proc/stat` for it every frame.
fn host_cores() -> usize {
    static CORES: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CORES.get_or_init(|| {
        std::fs::read_to_string("/proc/stat")
            .ok()
            .map(|s| {
                s.lines()
                    .filter(|l| {
                        l.starts_with("cpu") && l.as_bytes().get(3).is_some_and(u8::is_ascii_digit)
                    })
                    .count()
            })
            .filter(|&c| c > 0)
            .unwrap_or(1)
    })
}

/// 1-minute load average (read live) plus the cached logical CPU count.
fn host_load_cores() -> (f64, usize) {
    let load1 = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next().and_then(|t| t.parse().ok()))
        .unwrap_or(0.0);
    (load1, host_cores())
}

/// Read host stats. CPU% is computed against `prev_cpu` (the previous `/proc/stat` sample, returned
/// for the next frame); with no previous sample it reports 0.
fn read_host(prev_cpu: Option<(u64, u64)>) -> (HostStats, Option<(u64, u64)>) {
    let sample = host_cpu_sample();
    let cpu_pct = match (prev_cpu, sample) {
        (Some((pb, pt)), Some((b, t))) if t > pt => {
            (b.saturating_sub(pb) as f64 / (t - pt) as f64 * 100.0).clamp(0.0, 100.0)
        }
        _ => 0.0,
    };
    let (mem_used, mem_total) = host_mem().unwrap_or((0, 0));
    let (disk_used, disk_total) = host_disk().unwrap_or((0, 0));
    let logs_dir = crate::registry::logs_dir().ok();
    let (logs_used, logs_total) = logs_dir
        .as_ref()
        .and_then(|d| crate::commands::fs_usage(&d.to_string_lossy()))
        .unwrap_or((0, 0));
    let logs_fill = logs_dir
        .as_ref()
        .and_then(|d| crate::commands::fs_fill(&d.to_string_lossy()))
        .map_or(0, |(pct, _)| pct);
    let disk_fill = crate::commands::fs_fill("/").map_or(0, |(pct, _)| pct);
    let (load1, cores) = host_load_cores();
    let (docker_api, https) = services();
    (
        HostStats {
            mem_used,
            mem_total,
            disk_used,
            disk_total,
            logs_used,
            logs_total,
            disk_fill,
            logs_fill,
            cpu_pct,
            cores,
            load1,
            runs_total: 0,
            runs_per_sec: 0.0,
            runs_avg_us: 0,
            runs_peak: 0.0,
            runs_spark: Vec::new(),
            box_starts_total: 0,
            box_starts_per_sec: 0.0,
            box_starts_peak: 0.0,
            box_starts_spark: Vec::new(),
            gpus: host_gpus(),
            docker_api,
            https,
        },
        sample,
    )
}

/// Build a full frame for the active `tab` / `mode`.
#[allow(clippy::too_many_arguments)]
fn render(
    p: &Palette,
    tab: usize,
    rows: &[Row],
    host: &HostStats,
    profs: &[ProfRow],
    vols: &[crate::volume::VolInfo],
    builds: &[crate::builds::Record],
    // Records on disk. `builds` is the subset THIS frame read; see the tab bar.
    builds_total: usize,
    images: &[crate::commands::ImageEntry],
    // Cached images on disk, same relationship to `images` as `builds_total` to `builds`.
    images_total: usize,
    cols: usize,
    term_rows: usize,
    sel: usize,
    mode: &Mode,
    logs: &crate::logview::LogView,
) -> String {
    let (b, c, d, g, z) = (p.b, p.c, p.d, p.g, p.z);
    let width = cols.clamp(40, 120);
    // Rows left for DATA once everything else has taken its share. Counted, not estimated, because
    // estimating it wrong is what produced the flicker: the frame chrome is 7 lines (title 2 + tab
    // bar 1 + footer 4) and every list pane adds 5 of its own (a blank, its caption, a blank, the
    // column header, and the trailing "… N more"), so 12 lines are spoken for before the first row
    // of data. The old budget subtracted 9, which fit while a list was short and overflowed by
    // exactly 3 as soon as one filled the screen: measured, Images and Builds rendered 33 lines
    // into a 30-row terminal. Those 3 extra lines scroll the alternate screen, which carries the tab
    // bar off the top and makes every repaint start from a shifted origin. That is the flicker.
    let body_rows = term_rows.saturating_sub(12).max(1);
    let mut s = String::new();

    // Title bar - a live host header, always visible on every tab (CPU · RAM · Disk · Boxes),
    // refreshed each frame. The green figures are the "now"; the dim ones the total/context.
    s.push_str(&format!(
        "{b}{c} kern top{z}   {d}CPU{z} {g}{:>3.0}%{z} {d}/ {} cores{z}   {d}RAM{z} {g}{}{z}{d} / {}{z}   {d}Disk{z} {}{}{z}{d} / {}{z}{}   {d}Boxes{z} {g}{}{z}   {}\n\n",
        host.cpu_pct,
        host.cores,
        human_bytes(host.mem_used),
        human_bytes(host.mem_total),
        fill_colour(p, host.disk_fill),
        human_bytes(host.disk_used),
        human_bytes(host.disk_total),
        // THE LOG STORE ONLY WHEN IT IS FILLING: it is in RAM and small, and a full one drops box
        // output, so it earns a place in the header exactly when that is close.
        if host.logs_fill >= crate::logview::FILL_WARN_PCT {
            format!(
                "   {d}Logs{z} {}{}{z}{d} / {}{z}",
                fill_colour(p, host.logs_fill),
                human_bytes(host.logs_used),
                human_bytes(host.logs_total)
            )
        } else {
            String::new()
        },
        rows.len(),
        gpu_header(p, &host.gpus),
    ));

    // Tab bar - active tab inverted, each data tab showing a LIVE count of its rows so you can see how
    // many boxes/profiles/volumes exist without entering the tab. Overview is an aggregate → no count.
    // Each tab carries a live count - but 7 counted tabs (~87 cols) overflow a narrow/80-col
    // terminal: the bar wraps and shoves the later tabs (Images/Builds/…) off screen. If the full
    // bar won't fit `width`, drop the counts and render just the names so every tab stays visible.
    // `short`: a count of a thousand or more as `1.5k`. The step between every count in full and
    // none at all: with nine tabs a history of 1464 sandboxes and 11961 builds pushed a 100-column
    // bar over its width, and every count went for the sake of four digits.
    let label = |i: usize, compact: bool, short: bool| -> String {
        if compact {
            return TABS[i].to_string();
        }
        let n = |v: usize| -> String {
            if short {
                short_count(v)
            } else {
                v.to_string()
            }
        };
        match i {
            TAB_BOXES => format!("{} ({})", TABS[i], n(rows.len())),
            // The `_total`s, NOT `.len()`: these records are only read on their own tab, so the
            // vec is empty everywhere else while the store is not. The count is a property of the
            // store and must not change when the reader looks somewhere else.
            TAB_IMAGES => format!("{} ({})", TABS[i], n(images_total)),
            TAB_BUILDS => format!("{} ({})", TABS[i], n(builds_total)),
            TAB_PROFILES => format!("{} ({})", TABS[i], n(profs.len())),
            TAB_STORAGE => format!("{} ({})", TABS[i], n(vols.len())),
            // RUNNING sandboxes, as Boxes counts running boxes: the finished ones are a history,
            // and a count that only grows says nothing at a glance.
            // THE LIST'S LENGTH, the rule every other tab follows (Boxes its boxes, Storage its
            // volumes, Builds its records): here the finished sandboxes held, which is what the tab
            // scrolls. Always shown, `(0)` included, as the others are.
            TAB_SANDBOXES => format!(
                "{} ({})",
                TABS[i],
                n(crate::history::sandboxes_newest_first().len())
            ),
            // Runs are fire-and-forget (~1 ms) - there's no "current items" set like the other tabs,
            // so a cumulative count would mislead (it'd only grow). Show the LIVE rate while streaming
            // (that's the only meaningful "now"); nothing when idle. The cumulative total lives on the
            // tab body ("Total"), not here.
            TAB_RUNS if host.runs_per_sec > 0.5 => {
                format!(
                    "{} ({}/s) ⚡",
                    TABS[i],
                    human_count(host.runs_per_sec.round() as u64)
                )
            }
            _ => TABS[i].to_string(),
        }
    };
    // A rendered tab takes `label.len() + 3` visible cols (a space each side + a trailing separator);
    // the leading space adds one. Compact the whole bar if the full version won't fit.
    //
    // FOUR STEPS. Every count, then only the counts that are not `(0)`, then those with a large
    // number written short (`12.0k`), then none. With eight tabs the full bar is wider than 100
    // columns, and an all-or-nothing rule took every count away there to make room for an `(0)` that
    // says nothing; a `(0)` is the first thing to give up, four digits of a large count the second.
    let zero = |l: &str| l.ends_with(" (0)");
    let shown = |i: usize, step: usize| -> String {
        let full = label(i, false, step >= 2);
        match step {
            0 => full,
            1 | 2 if !zero(&full) => full,
            _ => label(i, true, false),
        }
    };
    // TIGHT: two spaces between two tabs instead of three, tried at each step BEFORE that step's
    // counts give way, so nine columns of spacing go before a number does. MEASURED: renaming the
    // third tab from "Runs" to "Limits" took a 100-column bar with `Images (1k)` and `Builds (12k)`
    // from 100 columns to 102, and both counts went for two letters.
    let bar_w = |step: usize, tight: bool| {
        1 + (0..TABS.len())
            .map(|i| shown(i, step).chars().count() + if tight { 2 } else { 3 })
            .sum::<usize>()
    };
    let (step, tight) = (0..3)
        .flat_map(|st| [(st, false), (st, true)])
        .find(|(st, t)| bar_w(*st, *t) <= width)
        .unwrap_or((3, false));
    let sep = if tight { "" } else { " " };
    s.push(' ');
    for i in 0..TABS.len() {
        let l = shown(i, step);
        if i == tab {
            s.push_str(&format!("{b}\x1b[7m {l} \x1b[27m{z}{sep}"));
        } else {
            s.push_str(&format!("{d} {l} {z}{sep}"));
        }
    }
    s.push('\n');
    s.push_str(&format!("{d}{}{z}\n", "─".repeat(width)));

    // Body + footer depend on the mode: a modal takes over the body area.
    let keys = match mode {
        Mode::Overlay(text) => {
            s.push_str(&text_pane(p, text, body_rows, width));
            format!("{d}[{z}any key{d}] back{z}")
        }
        Mode::Form(form) => {
            s.push_str(&form_pane(p, form, width, body_rows));
            format!("{d}[{z}Tab{d}/{z}↑↓{d}] field   [{z}⏎{d}] save   [{z}Esc{d}] cancel{z}")
        }
        Mode::PickKind => {
            s.push_str(&pick_pane(p));
            format!("{d}[{z}c{d}]vcpu  [{z}g{d}]vgpio  [{z}v{d}]vdisk   [{z}Esc{d}] cancel{z}")
        }
        Mode::PickHistory => {
            s.push_str(&history_pane(p, crate::history::keep()));
            // The keys from the choices themselves (`Keep::key`), as the pane and the handler.
            let keys: Vec<String> = crate::history::Keep::ALL
                .into_iter()
                .map(|k| {
                    let w = k.word();
                    format!("[{z}{}{d}]{}", &w[..1], &w[1..])
                })
                .collect();
            format!(
                "{d}{}  [{z}c{d}]lear   [{z}Esc{d}] cancel{z}",
                keys.join("  ")
            )
        }
        Mode::Confirm { prompt, .. } => {
            s.push_str(&confirm_pane(p, prompt));
            format!("{d}[{z}y{d}] yes   [{z}any other{d}] no{z}")
        }
        Mode::Nav => {
            match tab {
                TAB_BOXES => s.push_str(&boxes_table(p, rows, body_rows, sel, host)),
                TAB_RUNS => s.push_str(&runs_table(p, host)),
                TAB_IMAGES => s.push_str(&images_table(p, images, body_rows, sel)),
                TAB_BUILDS => s.push_str(&builds_table(p, builds, builds_total, body_rows, sel)),
                TAB_PROFILES => s.push_str(&profiles_table(p, profs, body_rows, sel)),
                TAB_STORAGE => s.push_str(&storage_table(p, vols, body_rows, sel)),
                TAB_SANDBOXES => s.push_str(&sandboxes_table(
                    p,
                    rows,
                    &crate::history::sandboxes_newest_first(),
                    body_rows,
                    sel,
                )),
                TAB_LOGS => s.push_str(&logs.render(p, width, body_rows)),
                _ => s.push_str(&overview(p, rows, host)),
            }
            if tab == TAB_LOGS {
                logs.footer(p)
            } else {
                nav_footer(p, tab, rows, profs, vols, builds, images)
            }
        }
    };
    s.push_str(&format!("\n{d}{}{z}\n  {keys}\n", "─".repeat(width)));
    // HARD CAP, at the boundary where the invariant belongs: `render` never returns more lines than
    // the screen has. The row budget above keeps every pane inside it at normal sizes, but a pane
    // with FIXED content (the Overview) cannot shrink below its own height, so a very small window
    // would still overflow. A frame past the last row scrolls the alternate screen: the tab bar
    // leaves through the top and each repaint lands a line lower, which is what the flicker was.
    // Losing the bottom of a pane in a 10-row window is a small, local, visible loss; a screen that
    // scrolls itself is a broken TUI. Capping here rather than at the paint site keeps ONE place
    // that decides the frame height, and lets a test hold it.
    let mut lines: Vec<&str> = s.lines().collect();
    lines.truncate(term_rows.max(1));
    lines.join("\n")
}

/// The `?` help overlay: the complete keymap + what each tab is for, in plain language. Rendered in the
/// read-only [`Mode::Overlay`] pane (any key closes it). First line is the bold title (see `text_pane`).
fn help_text() -> String {
    "kern top - keyboard help  (press any key to close)\n\
     \n\
     MOVE\n\
       Tab / → / l      next tab            ← / h      previous tab\n\
       1 2 3 4 5 6 7 8 9  jump to a tab    ↑ ↓ / j k  select a row\n\
       PgUp / PgDn      a page up / down    Home / End the first / last row\n\
       q  or  Ctrl-C    quit\n\
     \n\
     TABS - what each one shows\n\
       1 Overview   host CPU / RAM / load and the box totals\n\
       2 Boxes      every box, kern run or kern box (pods grouped): MEM, CPU%, PIDS, HEALTH,\n\
     \x20                PORTS; a --restart box between two runs is listed as restarting\n\
     \x20                (yellow net:host / root-mapped / caps:+ / gpu:N flags a box LESS\n\
     \x20                 isolated than default; gpu:N says WHICH cards, never how busy)\n\
       3 Limits     kern limit throughput: rate/sec, avg latency, peak, total (aggregate)\n\
       4 Images     cached OCI images: repository:tag, size, pulled age (like kern images)\n\
       5 Builds     build history: status, duration, size, age (like kern builds)\n\
       6 Profiles   reusable resource specs (vcpu / vgpio / vdisk) in kern.toml\n\
       7 Storage    physical disks (read-only) and your named volumes\n\
       8 Sandboxes  SDK and MCP sandboxes: running now, and the ones that finished with how\n\
     \x20                they ended; Enter shows one (its code and output: kern sandbox show)\n\
       9 Logs       every box's output in one stream, newest at the bottom, live\n\
     \n\
     LOGS tab\n\
       /  search (a|b matches either, case ignored; Esc clears)   e  level: all, warn+, error\n\
       s  only the selected line's box (s again: all)             f  follow / pause\n\
       Enter  the whole line     x  export what is shown as CSV     c  clear the view\n\
     \x20  a line's level is read from its text; a stack trace's lines take the level of the\n\
     \x20  line they continue. Read only while the tab is shown, and only what was appended.\n\
     \n\
     SANDBOXES tab\n\
       m  where the history is kept: memory (the default, cleared at reboot), disk (kept\n\
     \x20   across reboots) or off; c in the same menu clears it (asks first)\n\
     \n\
     BOXES tab - act on the selected box\n\
       s  stop (asks first)   S  stop ALL (asks first)\n\
       p  pause               u  unpause\n\
       Enter          view its logs (a box's own output)\n\
     \n\
     IMAGES tab\n\
       d  delete      D  delete ALL cached images       p  prune orphaned layers\n\
       Enter  detail\n\
     \n\
     BUILDS tab\n\
       d  delete      D  delete ALL build records       Enter  view the transcript\n\
     \n\
     PROFILES tab\n\
       n  new         e  edit         d  delete\n\
     \n\
     STORAGE tab\n\
       n  new         e  edit         d  delete        Enter  details\n\
       p  prune unused      D  remove ALL volumes and their data\n\
     \n\
     HEALTH colors:  green = healthy   red = unhealthy   dim = starting or no check\n\
     Destructive actions (stop / delete / prune) ask y / n first.\n\
     A SHIFTED key acts on the whole tab: its prompt names how many and what is lost."
        .to_string()
}

/// The per-tab footer hint bar in normal navigation.
fn nav_footer(
    p: &Palette,
    tab: usize,
    rows: &[Row],
    profs: &[ProfRow],
    vols: &[crate::volume::VolInfo],
    builds: &[crate::builds::Record],
    images: &[crate::commands::ImageEntry],
) -> String {
    let (d, z) = (p.d, p.z);
    // Every footer ends with a permanent `[?] help` - a first-time user doesn't know `?` exists until
    // it's shown, and `?` is where they find everything else. The hint to `?` is what discovers `?`.
    let help = format!("   [{z}?{d}] help{z}");
    match tab {
        TAB_BOXES if !rows.is_empty() => format!(
            "{d}[{z}↑↓ PgUp/PgDn{d}] select   [{z}s{d}]top [{z}S{d}]top-all [{z}p{d}]ause [{z}u{d}]npause [{z}⏎{d}]logs   [{z}Tab{d}] next   [{z}q{d}] quit{help}"
        ),
        TAB_IMAGES if !images.is_empty() => format!(
            "{d}[{z}↑↓ PgUp/PgDn{d}] select   [{z}d{d}]elete [{z}D{d}]elete-all [{z}p{d}]rune-layers [{z}⏎{d}]detail   [{z}Tab{d}] next   [{z}q{d}] quit{help}"
        ),
        TAB_BUILDS if !builds.is_empty() => format!(
            "{d}[{z}↑↓ PgUp/PgDn{d}] select   [{z}d{d}]elete [{z}D{d}]elete-all [{z}⏎{d}]logs   [{z}Tab{d}] next   [{z}q{d}] quit{help}"
        ),
        TAB_PROFILES => {
            let edit = if profs.is_empty() { "" } else { " [e]dit [d]elete" };
            format!("{d}[{z}↑↓ PgUp/PgDn{d}] select   [{z}n{d}]ew{edit}   [{z}Tab{d}] next   [{z}q{d}] quit{help}")
        }
        TAB_STORAGE => {
            let ops = if vols.is_empty() {
                ""
            } else {
                " [e]dit [d]elete [D]elete-all [⏎]info"
            };
            format!(
                "{d}[{z}↑↓ PgUp/PgDn{d}] select   [{z}n{d}]ew{ops} [{z}p{d}]rune   [{z}Tab{d}] next   [{z}q{d}] quit{help}"
            )
        }
        TAB_SANDBOXES => format!(
            "{d}[{z}↑↓ PgUp/PgDn{d}] select   [{z}⏎{d}]detail   [{z}m{d}] history: {z}{}{d}   [{z}Tab{d}] next   [{z}q{d}] quit{help}",
            crate::history::keep().word()
        ),
        _ => format!(
            "{d}[{z}q{d}] quit   [{z}Tab{d}/{z}←→{d}] switch tab   [{z}1{d}-{z}9{d}] jump{help}"
        ),
    }
}

/// A read-only text overlay: a bold first-line title, then the tail of the (sanitized) body clipped to
/// the pane. Terminal escapes in untrusted content (box logs) are stripped so they can't inject SGR /
/// move the cursor.
fn text_pane(p: &Palette, text: &str, body_rows: usize, width: usize) -> String {
    let (b, d, z) = (p.b, p.d, p.z);
    let mut lines = text.lines();
    let title = crate::ui::scrub(lines.next().unwrap_or("detail"));
    let body: Vec<&str> = lines.collect();
    let mut s = format!("\n  {b}{title}{z}\n");
    let take = body_rows.saturating_sub(2).max(1);
    let start = body.len().saturating_sub(take);
    if body.iter().all(|l| l.trim().is_empty()) && body.len() <= 1 {
        s.push_str(&format!("  {d}(no output yet){z}\n"));
    }
    for l in &body[start..] {
        let clean: String = crate::ui::scrub(l)
            .chars()
            .take(width.saturating_sub(2))
            .collect();
        s.push_str(&format!("  {clean}\n"));
    }
    s
}

/// The input-form pane: a title, a one-line hint, then one line per field. The **active** field lights
/// up (accent caret / label / brackets) and shows the text cursor `▏` **at the insertion point** - right
/// after what you've typed, or at the very start (before the dim placeholder) when the field is empty -
/// so it's obvious where your typing lands. When a kind has more fields than fit, the list **scrolls**
/// to keep the active field visible (`↑ N more` / `↓ N more`), so every field is reachable. Any
/// validation error shows in red.
fn form_pane(p: &Palette, form: &Form, width: usize, body_rows: usize) -> String {
    let (b, c, d, g, r, z) = (p.b, p.c, p.d, p.g, p.r, p.z);
    let mut s = format!("\n  {b}{}{z}\n", form.title);
    s.push_str(&format!(
        "  {d}{z}{c}↑↓{z}{d}/{z}{c}Tab{z}{d} move · {z}{c}Space{z}{d} tick a box · {z}{c}⏎{z}{d} save · {z}{c}Esc{z}{d} cancel{z}\n"
    ));
    // A one-line, plain-language explainer for the fiddly kinds so the user isn't left guessing.
    if let Submit::SaveProfile { section, .. } = &form.submit {
        let intro = match *section {
            "vgpio" => {
                Some("Give the box real hardware. Not doing hardware work? Leave it empty - that's fine.")
            }
            _ => None,
        };
        if let Some(t) = intro {
            s.push_str(&format!("  {d}{t}{z}\n"));
        }
    }
    s.push('\n');
    // Inner width of the value box (chars). Kept modest so the box hugs the text, not the whole screen.
    let boxw = width.saturating_sub(24).clamp(14, 30);
    // Scroll over the VISIBLE fields (a collapsed Advanced group is skipped) so the active one stays on
    // screen. Reserve rows for the title, hint, blank, the two "more" markers and the error line.
    let vis = visible_fields(form);
    let nvis = vis.len();
    let win = body_rows.saturating_sub(7).max(3).min(nvis.max(1));
    let vpos = vis.iter().position(|&i| i == form.active).unwrap_or(0);
    let vstart = vpos.saturating_sub(win - 1).min(nvis.saturating_sub(win));
    let vend = (vstart + win).min(nvis);
    if vstart > 0 {
        s.push_str(&format!("  {d}  ↑ {vstart} more{z}\n"));
    }
    for &i in &vis[vstart..vend] {
        let f = &form.fields[i];
        let active = i == form.active;
        let caret = if active {
            format!("{c}▸{z}")
        } else {
            " ".into()
        };
        let label = if active {
            format!("{c}{:<9}{z}", f.label)
        } else {
            format!("{b}{:<9}{z}", f.label)
        };
        // A "none on this host" note: dim label + dim message, no box. Nothing to type here, and the
        // cursor never lands on it - it's there only so you can SEE the machine has no such device.
        if f.is_dead_info() {
            s.push_str(&format!("    {d}{:<9}{z} {d}- {} -{z}\n", f.label, f.hint));
            continue;
        }
        // The Advanced fold row: a single toggle line that hides the rare knobs. Collapsed, it lists a
        // few of what's inside so the user knows there's more (and that they can ignore it).
        if f.divider {
            let n_adv = form.fields.iter().filter(|x| x.advanced).count();
            let cap = if form.show_advanced {
                "▾ Advanced - hide rare devices".to_string()
            } else {
                let names: Vec<&str> = form
                    .fields
                    .iter()
                    .filter(|x| x.advanced)
                    .map(|x| x.label)
                    .take(4)
                    .collect();
                let more = if n_adv > names.len() { ", …" } else { "" };
                format!("▸ Advanced - {n_adv} more: {}{more}", names.join(", "))
            };
            // No generic caret here - the ▸/▾ in the cap IS the pointer; accent colour shows focus.
            let styled = if active {
                format!(
                    "{c}{cap}   Space to {}{z}",
                    if form.show_advanced { "hide" } else { "open" }
                )
            } else {
                format!("{d}{cap}{z}")
            };
            s.push_str(&format!("\n    {styled}\n"));
            continue;
        }
        // A pick field renders detected devices as checkboxes - ←/→ highlight one, Space checks it.
        // No typing: the choices come from the host, so it's impossible to enter a wrong path.
        if f.is_pick() {
            let cap = if active {
                format!("{d}←/→ move · Space checks{z}")
            } else if f.value.is_empty() {
                format!("{d}{}{z}", f.hint)
            } else {
                format!("{g}{}{z}", f.value)
            };
            s.push_str(&format!("  {caret} {label} {cap}\n"));
            // Window the chips around the cursor and grow the window only while it FITS the terminal
            // width, so a busy host (20+ i2c buses) never overflows into an ugly wrap. `‹N`/`N›` show
            // how many are hidden on each side.
            let n_opt = f.options.len();
            let cw = |i: usize| f.options[i].chars().count() + 5; // "[ ]" + name + two spaces
            let budget = width.saturating_sub(11); // 7-space indent + the ‹N / N› counters
            let (mut lo, mut hi) = (f.cur, f.cur + 1);
            let mut used = cw(f.cur);
            loop {
                let grow_hi = hi < n_opt && used + cw(hi) <= budget;
                if grow_hi {
                    used += cw(hi);
                    hi += 1;
                }
                let grow_lo = lo > 0 && used + cw(lo - 1) <= budget;
                if grow_lo {
                    lo -= 1;
                    used += cw(lo);
                }
                if !grow_hi && !grow_lo {
                    break;
                }
            }
            let mut row = String::from("       ");
            if lo > 0 {
                row.push_str(&format!("{d}‹{lo}  {z}"));
            }
            // Radio (single-select) draws round `(•)` brackets; a multi-pick draws square `[✓]`.
            let (lb, rb, on) = if f.radio {
                ('(', ')', '•')
            } else {
                ('[', ']', '✓')
            };
            for i in lo..hi {
                let checked = f.sel.get(i).copied().unwrap_or(false);
                let mark = if checked {
                    format!("{g}{on}{z}")
                } else {
                    " ".to_string()
                };
                let name = &f.options[i];
                if active && i == f.cur {
                    row.push_str(&format!("{c}{lb}{z}{mark}{c}{rb}{z}{c}{name}{z}  "));
                } else {
                    row.push_str(&format!("{d}{lb}{z}{mark}{d}{rb}{z}{name}  "));
                }
            }
            if hi < n_opt {
                row.push_str(&format!("{d}{} ›{z}", n_opt - hi));
            }
            s.push_str(&row);
            s.push('\n');
            continue;
        }
        // A toggle renders as a checkbox `[x]`/`[ ]` with its hint as caption - no text box / cursor.
        if f.toggle {
            let on = !f.value.is_empty();
            let mark = if on {
                format!("{g}x{z}")
            } else {
                " ".to_string()
            };
            let (tlb, trb) = if active {
                (format!("{c}[{z}"), format!("{c}]{z}"))
            } else {
                (format!("{d}[{z}"), format!("{d}]{z}"))
            };
            let cap = if active {
                format!("{d}{}  ·  Space toggles{z}", f.hint)
            } else {
                format!("{d}{}{z}", f.hint)
            };
            s.push_str(&format!("  {caret} {label} {tlb}{mark}{trb} {cap}\n"));
            continue;
        }
        // Brackets light up (accent) on the active field so the eye lands on it.
        let (lb, rb) = if active {
            (format!("{c}[{z}"), format!("{c}]{z}"))
        } else {
            (format!("{d}[{z}"), format!("{d}]{z}"))
        };
        // Inner content, cursor placed at the insertion point (active field only).
        let inner = if active {
            let cur = format!("{c}▏{z}");
            if f.value.is_empty() {
                // Cursor FIRST, then the dim placeholder → "start typing right here".
                let ph: String = f.hint.chars().take(boxw.saturating_sub(1)).collect();
                let pad = boxw.saturating_sub(1 + ph.chars().count());
                format!("{cur}{d}{ph}{z}{:pad$}", "")
            } else {
                // Value, then the cursor right after it.
                let val: String = f.value.chars().take(boxw.saturating_sub(1)).collect();
                let pad = boxw.saturating_sub(1 + val.chars().count());
                format!("{g}{val}{z}{cur}{:pad$}", "")
            }
        } else if f.value.is_empty() {
            let ph: String = f.hint.chars().take(boxw).collect();
            format!("{d}{ph:<boxw$}{z}")
        } else {
            let val: String = f.value.chars().take(boxw).collect();
            format!("{g}{val:<boxw$}{z}")
        };
        // Three-state indicator on the ACTIVE numeric field: ✓ once the value is save-valid, a dim ‥
        // while it's still an incomplete-but-ok prefix (keep typing) - so "valid yet?" is never a guess.
        let status = if active && !f.value.is_empty() && validated_field(f.label) {
            match crate::config::field_state(f.label, &f.value) {
                crate::config::FieldState::Valid => format!("  {g}✓{z}"),
                crate::config::FieldState::Incomplete => format!("  {d}‥ keep typing{z}"),
                crate::config::FieldState::Invalid => format!("  {r}✗{z}"),
            }
        } else {
            String::new()
        };
        s.push_str(&format!("  {caret} {label} {lb}{inner}{rb}{status}\n"));
    }
    if vend < nvis {
        s.push_str(&format!("  {d}  ↓ {} more{z}\n", nvis - vend));
    }
    // Contextual help: what the FOCUSED field is and when you'd use it, with an everyday example - so
    // the user is guided to the right choice instead of guessing.
    if let Submit::SaveProfile { section, .. } = &form.submit {
        if let Some(h) = field_help(section, form.fields[form.active].label) {
            let h: String = h.chars().take(width.saturating_sub(6)).collect();
            s.push_str(&format!("\n  {c}❔{z} {d}{h}{z}\n"));
        }
    }
    if let Some(e) = &form.error {
        s.push_str(&format!("\n  {r}✗ {e}{z}\n"));
    }
    s
}

/// The confirm pane: a centred prompt for a destructive action.
fn confirm_pane(p: &Palette, prompt: &str) -> String {
    let (b, y, z) = (p.b, p.y, p.z);
    format!("\n\n  {y}⚠{z}  {b}{prompt}{z}\n")
}

/// Where the sandbox history is kept, as one line: the three choices with the current one marked,
/// what it means, how many sandboxes it holds and the file. The Sandboxes tab and the Overview both
/// print it, so the choice is visible where the history is read and not only behind `m`.
/// Reads no history file: the count is the cached list's, the path is computed.
fn history_choice_line(p: &Palette, held: usize) -> String {
    use crate::history::Keep;
    let (b, c, d, g, y, z) = (p.b, p.c, p.d, p.g, p.y, p.z);
    let now = crate::history::keep();
    let marks: Vec<String> = Keep::ALL
        .into_iter()
        .map(|k| {
            if k == now {
                let col = if k == Keep::Off { y } else { g };
                format!("{col}●{z} {b}{}{z}", k.word())
            } else {
                format!("{d}○ {}{z}", k.word())
            }
        })
        .collect();
    let what = now.meaning();
    let file = crate::history::current_file()
        .map(|f| format!(" in {}", f.display()))
        .unwrap_or_default();
    format!(
        "{}   {d}{what} · {held} finished sandboxes recorded{file} ·{z} {c}m{z}{d} to change{z}",
        marks.join("  ")
    )
}

/// The history picker: the three places, the current one marked, and what each means.
fn history_pane(p: &Palette, now: crate::history::Keep) -> String {
    use crate::history::Keep;
    let (b, c, d, g, z) = (p.b, p.c, p.d, p.g, p.z);
    let mut s = format!(
        "\n  {b}sandbox history{z}  {d}- one line per finished sandbox (never its output): where to keep it{z}\n\n"
    );
    for k in Keep::ALL {
        let key = char::from(k.key());
        let mark = if k == now {
            format!("{g}● now{z}")
        } else {
            "     ".to_string()
        };
        s.push_str(&format!(
            "    {b}[{c}{key}{b}]{z}  {b}{:<7}{z}{d}{:<32}{z} {mark}\n",
            k.word(),
            k.meaning()
        ));
    }
    s.push_str(&format!(
        "\n    {b}[{c}c{b}]{z}  {b}clear{z}  {d}remove every row held, in memory and on disk (asks first){z}\n\n  {d}{}{z}\n",
        crate::history::keep_line()
    ));
    s
}

/// The Profiles "new" kind picker: vcpu / vgpio / vdisk, each attachable to a box by prefix.
fn pick_pane(p: &Palette) -> String {
    let (b, c, d, z) = (p.b, p.c, p.d, p.z);
    let row = |key: &str, name: &str, what: &str| {
        format!("    {b}[{c}{key}{b}]{z}  {b}{name:<8}{z}{d}{what}{z}\n")
    };
    let mut s = format!("\n  {b}new profile{z}  {d}- pick a kind:{z}\n\n");
    s.push_str(&row("c", "vcpu", "CPU / memory limits for a box"));
    s.push_str(&row("g", "vgpio", "GPIO / I²C / SPI access for a box"));
    s.push_str(&row(
        "v",
        "vdisk",
        "a private, size-capped scratch disk for one box",
    ));
    s
}

/// The lead marker + name colour for a table row: the selected row gets a `›` caret and bold, so it
/// reads at a glance which row the lifecycle keys act on. (Reverse-video is avoided - an embedded
/// colour reset mid-row would cut it.) Shared by the Boxes / Profiles / Storage tables.
fn sel_marker(p: &Palette, selected: bool) -> (String, String) {
    if selected {
        (format!("{}›{} ", p.b, p.z), format!("{}{}", p.b, p.c))
    } else {
        ("  ".into(), p.c.to_string())
    }
}

/// The physical-disk one-liner for the Overview / Storage panes: the first two disks, then a
/// `(+N more)` tail when there are others. `None` when no disk was detected. The caller wraps it in
/// its own dim styling. Cached - disks are fixed hardware, so `top` scans `/sys/block` once, not
/// every frame.
fn disks_summary() -> Option<String> {
    static CACHE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            let disks = crate::commands::host_disks();
            if disks.is_empty() {
                return None;
            }
            let shown = disks
                .iter()
                .take(2)
                .cloned()
                .collect::<Vec<_>>()
                .join("   ");
            let more = disks.len().saturating_sub(2);
            Some(if more > 0 {
                format!("{shown}   (+{more} more)")
            } else {
                shown
            })
        })
        .clone()
}

/// The Profiles tab: the `kern.toml` vcpu / vgpio / vdisk profiles, `section:name` + a summary.
fn profiles_table(p: &Palette, profs: &[ProfRow], max_rows: usize, sel: usize) -> String {
    let (b, c, d, g, z) = (p.b, p.c, p.d, p.g, p.z);
    let mut s = format!(
        "\n  {d}reusable specs - attach to a box: {z}{c}kern box vcpu:heavy vgpio:leds vdisk:scratch …{z}\n"
    );
    // One titled sub-table per category, in a fixed order - an empty category still shows its header
    // + "none yet" so it's obvious the kind exists. `sel` is a flat index into `profs` (already sorted
    // by category then name), so the caret lands on the right row across sections; navigation is
    // unchanged. Headers are visual only - they don't consume a selection index.
    const CATS: [(&str, &str, &str); 3] = [
        ("vcpu", "vCPU", "CPU / memory slices"),
        ("vgpio", "vGPIO", "GPIO · I²C · device passthrough"),
        ("vdisk", "vDisk", "per-box scratch disks"),
    ];
    // A WINDOW OVER THE FLAT LIST, as every other pane has, and a budget that counts this pane's own
    // chrome. It had neither: a shared row budget that stopped drawing at the limit (so a profile
    // past it could be selected and never seen) and three section headers the frame budget did not
    // know about, so a long list cut the footer off the screen. The pane is allowed the five lines
    // of chrome every list pane is; beyond them it spends 2 on the caption, 6 on the three headers,
    // and at most 3 on a line for a section with nothing in the window. Hence `max_rows - 7`.
    let avail = max_rows.saturating_sub(7).max(1);
    let (wstart, wend) = list_window(profs.len(), avail, sel);
    for (section, title, desc) in CATS {
        s.push_str(&format!("\n  {b}{title}{z}  {d}- {desc}{z}\n"));
        let all: Vec<(usize, &ProfRow)> = profs
            .iter()
            .enumerate()
            .filter(|(_, r)| r.section == section)
            .collect();
        if all.is_empty() {
            s.push_str(&format!(
                "    {d}none yet - press {z}{g}n{z}{d} to add one{z}\n"
            ));
            continue;
        }
        let shown: Vec<&(usize, &ProfRow)> = all
            .iter()
            .filter(|(i, _)| (wstart..wend).contains(i))
            .collect();
        if shown.is_empty() {
            s.push_str(&format!(
                "    {d}… {} here, scroll to see them{z}\n",
                all.len()
            ));
            continue;
        }
        for (i, r) in shown {
            let (lead, col) = sel_marker(p, *i == sel);
            s.push_str(&format!(
                "  {lead}{col}{:<22}{z}  {d}{}{z}\n",
                trunc(&prof_label(r), 22),
                r.summary
            ));
        }
    }
    s.push_str(&list_marker(p, profs.len(), wstart, wend));
    s
}

/// The running boxes an SDK or the MCP server started, by the names they give them.
fn live_sandboxes(rows: &[Row]) -> Vec<&Row> {
    rows.iter()
        .filter(|r| crate::history::kind_of(&r.name) != "box")
        .collect()
}

/// Sandboxes finished in each of `buckets` equal slices of the last `window_s` seconds, oldest
/// first: the activity a list cannot show, because an SDK call lives milliseconds and is gone
/// between two frames. 30 slices of 2 s keep the LIVE title under 100 columns; 60 of 1 s did not.
fn ends_per_bucket(
    done: &[crate::history::Entry],
    now_ms: u64,
    window_s: u64,
    buckets: usize,
) -> Vec<f64> {
    let mut out = vec![0.0; buckets.max(1)];
    let window = window_s * 1000;
    let start = now_ms.saturating_sub(window);
    let width = (window / out.len() as u64).max(1);
    for e in done {
        if e.ended_ms < start || e.ended_ms > now_ms {
            continue;
        }
        let i = ((e.ended_ms - start) / width) as usize;
        let last = out.len() - 1;
        out[i.min(last)] += 1.0;
    }
    out
}

/// The Sandboxes tab, in two sections.
///
/// LIVE, at a FIXED height. An SDK call lives milliseconds, so the running list is usually empty or
/// one row, and a section whose height followed it made everything under it jump every second. Its
/// title carries what a list cannot: sandboxes finished per second over the last minute, read from
/// the history, so the activity is visible even when nothing lives long enough to be listed.
///
/// FINISHED, newest first, which is the list the selection moves over. The outcome is coloured by
/// what it means (ok, an exit or a stop, a kill the kernel or kern decided), and a row that ended in
/// the last three seconds carries a dot, so new work is seen arriving.
///
/// BUDGET. A list pane is allowed five lines of chrome (blank, caption, blank, header, marker). This
/// one spends six more, always the same six, so the finished list knows its rows: the history line,
/// the live title, the live rows ([`LIVE_ROWS`], blank-padded) and the finished title. The footer
/// test holds it.
fn sandboxes_table(
    p: &Palette,
    rows: &[Row],
    done: &[crate::history::Entry],
    max_rows: usize,
    sel: usize,
) -> String {
    sandboxes_table_at(p, rows, done, max_rows, sel, crate::history::now_ms())
}

/// [`sandboxes_table`] at a given time, so a test can hold "just now".
fn sandboxes_table_at(
    p: &Palette,
    rows: &[Row],
    done: &[crate::history::Entry],
    max_rows: usize,
    sel: usize,
    now: u64,
) -> String {
    const LIVE_ROWS: usize = 3;
    let (b, c, d, g, r, y, z) = (p.b, p.c, p.d, p.g, p.r, p.y, p.z);
    let mut s = format!(
        "\n  {d}code an SDK or the MCP server ran, live and finished · {z}{c}kern sandbox history{z}{d} on the CLI{z}\n"
    );
    // HISTORY, A LINE OF ITS OWN: where the finished ones are kept is a choice, and the default
    // clears them at reboot. A reader learns that here, with the other two choices beside it, rather
    // than from a reboot; `m` opens the picker.
    s.push_str(&format!(
        "  {b}HISTORY{z}  {}\n",
        history_choice_line(p, done.len())
    ));

    // LIVE.
    let live = live_sandboxes(rows);
    let per_s = ends_per_bucket(done, now, 60, 30);
    let last_min: f64 = per_s.iter().sum();
    let live_col = if live.is_empty() { d } else { g };
    s.push_str(&format!(
        "  {b}LIVE{z}  {live_col}{} running{z}   {d}finished, last minute{z} {c}{}{z}  {d}{}{z}\n",
        live.len(),
        spark(&per_s),
        last_min as u64
    ));
    for slot in 0..LIVE_ROWS {
        let last = slot + 1 == LIVE_ROWS;
        match live.get(slot) {
            Some(_) if last && live.len() > LIVE_ROWS => s.push_str(&format!(
                "    {d}… {} more running, all of them in the Boxes tab{z}\n",
                live.len() - slot
            )),
            Some(row) => s.push_str(&format!(
                "    {g}●{z} {:<26} {d}{:<17}{z} {:>8} {:>8}  {:>5.1}%\n",
                trunc(&row.name, 26),
                crate::history::kind_of(&row.name),
                fmt_uptime(row.uptime),
                row.mem.map_or_else(|| "-".to_string(), human_bytes),
                row.cpu_pct
            )),
            None if slot == 0 => s.push_str(&format!(
                "    {d}nothing running now (a Kernel or a persist sandbox stays here; a call is gone in ms){z}\n"
            )),
            None => s.push('\n'),
        }
    }

    // FINISHED.
    s.push_str(&format!(
        "\n  {b}FINISHED{z}  {d}{}{z}\n",
        crate::history::last_hour_line(done)
    ));
    s.push_str(&format!(
        // Four columns in, where a row's time starts: the selection marker and the fresh dot.
        "  {b}    {:<19} {:<26} {:<17} {:>8}  {:<12} {:<5}{z}\n",
        "ENDED", "NAME", "KIND", "RAN", "OUTCOME", "GPU"
    ));
    if done.is_empty() {
        s.push_str(&format!(
            "  {d}none yet: a line is kept for every sandbox that ends (never its output){z}\n"
        ));
        return s;
    }
    let max_rows = max_rows.saturating_sub(LIVE_ROWS + 3).max(1);
    let (wstart, wend) = list_window(done.len(), max_rows, sel);
    for (i, e) in done[wstart..wend]
        .iter()
        .enumerate()
        .map(|(k, e)| (k + wstart, e))
    {
        let (lead, col) = sel_marker(p, i == sel);
        let (ended, ran) = crate::history::ended_and_ran(e);
        let word = e.outcome.word();
        let oc = match e.outcome {
            crate::history::Outcome::Ok => g,
            crate::history::Outcome::Exit(_)
            | crate::history::Outcome::Stopped
            | crate::history::Outcome::NotStarted => y,
            _ => r,
        };
        let fresh = if now.saturating_sub(e.ended_ms) < 3000 {
            format!("{g}●{z}")
        } else {
            " ".to_string()
        };
        s.push_str(&format!(
            "  {lead}{fresh} {col}{ended:<19}{z} {col}{:<26}{z} {d}{:<17}{z} {ran:>8}  {oc}{word:<12}{z} {d}{}{z}\n",
            trunc(&e.name, 26),
            e.kind(),
            e.gpu
        ));
    }
    s.push_str(&list_marker(p, done.len(), wstart, wend));
    s
}

/// Sandboxes-tab keys: Enter shows the selected finished sandbox in full, `m` where the history
/// is kept.
fn nav_sandboxes(k: u8, sel: usize, mode: &mut Mode) {
    if k == b'm' {
        *mode = Mode::PickHistory;
        return;
    }
    if !matches!(k, b'\r' | b'\n') {
        return;
    }
    let done = crate::history::sandboxes_newest_first();
    let Some(e) = done.get(sel) else {
        return;
    };
    let (ended, ran) = crate::history::ended_and_ran(e);
    *mode = Mode::Overlay(format!(
        "sandbox {}\nkind     {}\nimage    {}\nended    {ended}\nran      {ran}\nexit     {}\noutcome  {}\ngpu      {}\n\n\
         Its code and output, when the SDK recorded them (`sandbox_transcripts`, on by default): \
         `kern sandbox show {}`. `kern sandbox history --json` has the same line for a script.",
        e.name,
        e.kind(),
        e.image,
        e.code,
        e.outcome.word(),
        e.gpu,
        e.name
    ));
}

/// The Storage tab - the concrete data layer: the read-only physical disks, then the named volumes
/// (persistent storage you mount with `-v`). Per-box vdisks are *specs*, so they live in Profiles.
fn storage_table(
    p: &Palette,
    vols: &[crate::volume::VolInfo],
    max_rows: usize,
    sel: usize,
) -> String {
    let (b, c, d, g, z) = (p.b, p.c, p.d, p.g, p.z);
    let mut s = String::new();
    let mut max_rows = max_rows;

    // Physical disks - read-only hardware; where volumes and vdisks physically live.
    //
    // THREE LINES THE FRAME BUDGET DOES NOT KNOW ABOUT, so they come out of this pane's rows. They
    // did not: with 555 volumes the list took every row the budget gave a list pane, the frame ran 3
    // lines past the screen, and `render`'s cap cut the bottom off, which is the footer with the
    // `[d]elete` key on it. MEASURED on this desktop; reported as "Storage has no footer".
    if let Some(summary) = disks_summary() {
        s.push_str(&format!(
            "\n  {b}DISKS{z} {d}(physical, read-only){z}\n    {d}{summary}{z}\n"
        ));
        max_rows = max_rows.saturating_sub(3).max(1);
    }

    s.push_str(&format!(
        "\n  {d}named volumes, persistent and shared: {z}{c}kern box -v NAME:/data …{z}  {d}(per-box vdisks are in Profiles){z}\n\n"
    ));
    s.push_str(&format!(
        "  {b}{:<24}  {:>10}  {:>10}{z}\n",
        "VOLUME", "SIZE", "QUOTA"
    ));
    if vols.is_empty() {
        s.push_str(&format!(
            "  {d}no volumes yet, press {z}{g}n{z}{d} to create one{z}\n"
        ));
        return s;
    }
    let (wstart, wend) = list_window(vols.len(), max_rows, sel);
    for (i, v) in vols[wstart..wend]
        .iter()
        .enumerate()
        .map(|(k, v)| (k + wstart, v))
    {
        let (lead, col) = sel_marker(p, i == sel);
        // No quota = UNLIMITED (the volume can grow until the disk is full). A bare `-` read as
        // "unset/error"; `∞` says "no cap" at a glance (the `?` help and the create form spell it out).
        // `kern_common::pad_visible` right-pads by COLUMN width (`∞` is 1 col / 3 bytes) - the colour is
        // applied AFTER padding so the zero-width codes don't count. Same helper as `kern volume ls`.
        let quota_plain = v.quota.map_or_else(|| "∞".to_string(), human_bytes);
        let padded = kern_common::pad_visible(&quota_plain, 10);
        let quota_cell = if v.quota.is_none() {
            padded.replace('∞', &format!("{d}∞{z}")) // colour the glyph, keep the pad
        } else {
            padded
        };
        s.push_str(&format!(
            "  {lead}{col}{:<24}{z}  {:>10}  {}\n",
            trunc(&v.name, 24),
            v.size.map_or_else(|| "-".to_string(), human_bytes),
            quota_cell
        ));
    }
    // Unconditional: the marker is empty when the whole list fits, so the caller has one code path
    // and cannot forget the guard.
    s.push_str(&list_marker(p, vols.len(), wstart, wend));
    s
}

/// Compact large counts (`1.2k`, `3.4M`) for the runs metric - thousands of runs shouldn't sprawl.
/// A count in the fewest characters, for a tab bar short of room: `1k`, `12k`, `2M`, rounded.
/// `human_count`'s `1.5k` is as long as the `1464` it replaces.
fn short_count(n: usize) -> String {
    if n < 1_000 {
        n.to_string()
    } else if n < 999_500 {
        format!("{}k", n.saturating_add(500) / 1_000)
    } else {
        format!("{}M", n.saturating_add(500_000) / 1_000_000)
    }
}

/// Green, yellow from [`crate::logview::FILL_WARN_PCT`], red from
/// [`crate::logview::FILL_CRIT_PCT`]: how a store's fill is coloured everywhere in `kern top`.
fn fill_colour(p: &Palette, pct: u64) -> &'static str {
    if pct >= crate::logview::FILL_CRIT_PCT {
        p.r
    } else if pct >= crate::logview::FILL_WARN_PCT {
        p.y
    } else {
        p.g
    }
}

/// The ALERTS block of the Overview: a store close to full, what fails when it is, and the command
/// that gives room back. Empty when nothing is close.
fn alerts(p: &Palette, host: &HostStats) -> String {
    let (b, z) = (p.b, p.z);
    let mut out = String::new();
    let disk = host.disk_fill;
    if disk >= crate::logview::FILL_WARN_PCT {
        let c = fill_colour(p, disk);
        out.push_str(&format!(
            "  {c}Disk {disk} % full{z}: images, volumes, builds and the sandbox history live here, \
             and a write that finds it full fails (a pull, a build, a volume write). \
             `kern gc` frees build layers and leftovers; `kern gc --images` the image cache\n"
        ));
    }
    let logs = host.logs_fill;
    if logs >= crate::logview::FILL_WARN_PCT {
        let c = fill_colour(p, logs);
        out.push_str(&format!(
            "  {c}Log store {logs} % full{z} ($XDG_RUNTIME_DIR, in RAM): when it is full a box's \
             output is DROPPED, never the box, and its log says how much was lost. `kern prune` \
             frees the logs of boxes that ended\n"
        ));
    }
    if out.is_empty() {
        return out;
    }
    format!("\n  {b}ALERTS{z}\n{out}")
}

fn human_count(n: u64) -> String {
    if n < 1_000 {
        n.to_string()
    } else if n < 1_000_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    }
}

/// The title bar's GPU figure, on every tab: how many cards and their memory, summed. `GPU none`
/// on a host without one, so the absence reads as a fact rather than as a figure that failed.
fn gpu_header(p: &Palette, gpus: &[GpuStat]) -> String {
    gpu_header_with(p, gpus, detected_cards())
}

/// The cards `kern doctor` sees (`gpu::detect`), counted ONCE per `kern top`: the header's fallback
/// when the per-card reader finds nothing it can read. MEASURED on WSL2 with an RTX 3060: doctor said
/// "a WSL2 GPU at /dev/dxg", `--gpus all` ran `nvidia-smi` in a box, and `top` said `GPU none`, because
/// on WSL there is no /dev/nvidia* and the driver's NVML is a glibc library the musl distro cannot load.
/// Two detections of one fact disagreed; the header now never contradicts doctor.
fn detected_cards() -> usize {
    static CARDS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    // WSL2 has no DRM card for its GPU: `card_count` counts the adapters behind /dev/dxg there, as
    // `kern info` does (two ioctls, no process), so the header agrees with info and doctor.
    *CARDS.get_or_init(crate::gpu::card_count)
}

fn gpu_header_with(p: &Palette, gpus: &[GpuStat], detected: usize) -> String {
    let (d, g, z) = (p.d, p.g, p.z);
    if gpus.is_empty() {
        if detected > 0 {
            return format!("{d}GPU{z} {g}{detected}{z} {d}· usage n/a{z}");
        }
        return format!("{d}GPU none{z}");
    }
    let used: u64 = gpus.iter().filter_map(|x| x.mem_used_mib).sum();
    let total: u64 = gpus.iter().filter_map(|x| x.mem_total_mib).sum();
    if total == 0 {
        return format!("{d}GPU{z} {g}{}{z}", gpus.len());
    }
    format!(
        "{d}GPU{z} {g}{}{z} {d}·{z} {g}{}{z}{d} / {}{z}",
        gpus.len(),
        human_bytes(used.saturating_mul(1 << 20)),
        human_bytes(total.saturating_mul(1 << 20))
    )
}

/// The `nvidiaN` nodes a row's `gpu:0,1` flag names (see `box_isolation`), space-separated.
fn gpu_nodes_from_flag(r: &Row) -> String {
    r.iso
        .split_whitespace()
        .find_map(|t| t.strip_prefix("gpu:"))
        .map(|list| {
            list.split(',')
                .filter(|n| !n.is_empty())
                .map(|n| format!("nvidia{n}"))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

/// A compose box's service name, `llm0` out of `aistack-e1c0723b-llm0`: what follows the stack's
/// 8-hex-digit hash. A name without that shape (a plain `kern box`) is returned whole. Measured: the
/// first version stripped the pod name, and a `--no-pod` stack has none, so the row printed every
/// box's full name.
fn service_of(name: &str) -> &str {
    let mut rest = name;
    while let Some((head, tail)) = rest.split_once('-') {
        if head.len() == 8
            && head
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && !tail.is_empty()
            && rest.len() < name.len()
        {
            return tail;
        }
        rest = tail;
    }
    name
}

/// The Overview's GPU rows. `nodes_of` answers a box's GPU nodes (`nvidia0 nvidia1`); production
/// reads them from the row's `gpu:N` flag, which the Boxes tab computed from the box's INTERIOR
/// init, so the two views cannot disagree. The first version asked `/proc/<pid>/root/dev` of the
/// host-side supervisor, whose `/dev` is the host's: MEASURED, every one of seven boxes counted on
/// both cards. A test passes its own.
fn gpu_rows(
    p: &Palette,
    rows: &[Row],
    gpus: &[GpuStat],
    nodes_of: impl Fn(&Row) -> String,
    minor_of: impl Fn(&str) -> Option<u32>,
) -> String {
    let (b, d, z) = (p.b, p.d, p.z);
    if gpus.is_empty() {
        return String::new();
    }
    let held: Vec<(String, &str)> = rows
        .iter()
        .map(|r| {
            // The service, not the box: see `service_of`.
            let short = service_of(&r.name);
            (nodes_of(r), short)
        })
        .collect();
    let mut s = String::new();
    for g in gpus {
        let node = minor_of(&g.bus).map(|m| format!("nvidia{m}"));
        let names: Vec<&str> = node.as_ref().map_or(Vec::new(), |n| {
            held.iter()
                .filter(|(h, _)| h.split_whitespace().any(|x| x == n))
                .map(|(_, name)| *name)
                .collect()
        });
        let mem = match (g.mem_used_mib, g.mem_total_mib) {
            (Some(u), Some(t)) => format!(
                "{} / {}",
                human_bytes(u.saturating_mul(1 << 20)),
                human_bytes(t.saturating_mul(1 << 20))
            ),
            // An integrated GPU's memory IS the host's RAM, which is the fact a dash would hide.
            _ if g.bus.is_empty() => "memory unified with RAM".to_string(),
            _ => "-".to_string(),
        };
        let mut extra = Vec::new();
        if let Some(u) = g.util_pct {
            extra.push(format!("{u} % busy"));
        }
        if let Some(t) = g.temp_c {
            extra.push(format!("{t} C"));
        }
        if let Some(w) = g.power_w {
            extra.push(format!("{w:.0} W"));
        }
        // NAMES, AND NOTHING WHEN NO BOX HOLDS THE CARD. A count ("3 boxes", "no box") answered a
        // question nobody asks of a card and read as noise; who holds it is the question.
        let held_by = if names.is_empty() {
            String::new()
        } else {
            format!(" · {}", names.join(", "))
        };
        let name = g.name.strip_prefix("NVIDIA ").unwrap_or(&g.name);
        // The bus without its domain, and nothing at all for a GPU that has none. `strip_prefix`
        // and not a slice: `&bus[5..]` panicked on the empty bus of a Jetson.
        if let Some(bus) = g
            .bus
            .strip_prefix("0000:")
            .or(Some(g.bus.as_str()))
            .filter(|b| !b.is_empty())
        {
            extra.push(bus.to_string());
        }
        s.push_str(&format!(
            "  {b}{:<16}{z}{name}  {mem}   {d}{}{held_by}{z}\n",
            format!("GPU {}", g.index),
            extra.join(" · ")
        ));
    }
    s
}

/// The Overview tab: host resources first (the machine kern runs on), then the box aggregate.
fn overview(p: &Palette, rows: &[Row], host: &HostStats) -> String {
    let (b, d, z) = (p.b, p.d, p.z);
    let mut s = String::from("\n");
    let row = |k: &str, v: String| format!("  {b}{:<16}{z}{v}\n", k);

    // Host - the machine kern is running on.
    let mem_pct = host.mem_pct();
    s.push_str(&format!("  {b}HOST{z}\n"));
    s.push_str(&row(
        "CPU",
        format!(
            "{:>4.0} %   {d}{} cores · load {:.2}{z}",
            host.cpu_pct, host.cores, host.load1
        ),
    ));
    s.push_str(&row(
        "RAM",
        format!(
            "{} / {}   {d}({:.0} %){z}",
            human_bytes(host.mem_used),
            human_bytes(host.mem_total),
            mem_pct
        ),
    ));
    // Physical disks - read-only hardware, the pool a `vdisk:` profile's image lives on.
    if let Some(summary) = disks_summary() {
        s.push_str(&row("Disks", format!("{d}{summary}{z}")));
    }
    // GPUs - one row per card: what it is, how full, and how many boxes hold it.
    s.push_str(&gpu_rows(
        p,
        rows,
        &host.gpus,
        gpu_nodes_from_flag,
        gpu_minor,
    ));
    // `kern limit` throughput lives on its own **Limits** tab (fire-and-forget capped processes) - Overview
    // stays the host + box picture. A one-line pointer only while runs actively stream (same > 0.5/s
    // threshold as the Runs-tab `⚡`, so the two never disagree), never a stale idle cumulative.
    if host.runs_per_sec > 0.5 {
        s.push_str(&row(
            "Limits",
            format!("{d}⚡ live - see the {z}{b}Limits{z}{d} tab{z}"),
        ));
    }

    // Boxes - the aggregate of what kern is running.
    let total_mem: u64 = rows.iter().filter_map(|r| r.mem).sum();
    // `pct()` normalises a stray `-0.0` (float rounding on an idle host) to a clean `0.0`.
    let total_cpu: f64 = pct(rows.iter().map(|r| r.cpu_pct).sum());
    let total_tasks: u64 = rows.iter().filter_map(|r| r.tasks).sum();
    let cap = if rows.iter().any(|r| r.mem.is_some()) {
        "yes (systemd cgroup scope)"
    } else {
        "no dedicated cgroup"
    };
    // A store close to full is said before anything else on the screen that is not the host.
    s.push_str(&alerts(p, host));
    s.push_str(&format!("\n  {b}BOXES{z}\n"));
    s.push_str(&row("Running", format!("{}", rows.len())));
    s.push_str(&row("Memory", human_bytes(total_mem)));
    s.push_str(&row("CPU", format!("{total_cpu:.1} %")));
    s.push_str(&row("Tasks", format!("{total_tasks}")));
    s.push_str(&row("Resource cap", format!("{d}{cap}{z}")));
    // HOW THE RUNNING BOXES REACH OUT, from the same `iso` flags the Boxes tab prints: the default is
    // a NAT of its own (Docker's), so the count a reader checks is the boxes that are not.
    if !rows.is_empty() {
        let parts: Vec<String> = ["nat", "pod", "host", "none", ""]
            .iter()
            .map(|w| (rows.iter().filter(|r| r.net == *w).count(), w))
            .filter(|(n, _)| *n > 0)
            .map(|(n, w)| format!("{n} {}", if w.is_empty() { "not read" } else { w }))
            .collect();
        s.push_str(&row("Network", parts.join(" · ")));
    }
    let oom_boxes = rows.iter().filter(|r| r.oom_kills > 0).count();
    if oom_boxes > 0 {
        let kills: u64 = rows.iter().map(|r| r.oom_kills).sum();
        s.push_str(&row(
            "OOM kills",
            format!(
                "{}{kills}{z} {d}in {oom_boxes} running box(es): a process ended, the box ran on{z}",
                p.y
            ),
        ));
    }
    // SANDBOXES: the ones running, and the last hour of the ones that finished; the tab has the rest.
    let done = crate::history::sandboxes_newest_first();
    s.push_str(&row(
        "Sandboxes",
        format!(
            "{} running   {d}{}{z}",
            live_sandboxes(rows).len(),
            crate::history::last_hour_line(&done)
        ),
    ));
    s.push_str(&row("Sandbox history", history_choice_line(p, done.len())));
    // Fleet budget: the SUM cap across all boxes on `kern.slice` (KERN_FLEET_MEMORY_MAX / _PIDS_MAX),
    // the real-enforcement backstop to the cooperative KERN_MAX_CONCURRENT counter. Shown only when a
    // budget is actually set (otherwise the slice usually doesn't even exist).
    if let Some(f) = kern_isolation::fleet_status().filter(|f| f.is_capped()) {
        let mem = match f.memory_max {
            Some(m) => format!("mem {}/{}", human_bytes(f.memory_current), human_bytes(m)),
            None => format!("mem {}", human_bytes(f.memory_current)),
        };
        let pids = match f.pids_max {
            Some(p) => format!("pids {}/{p}", f.pids_current),
            None => format!("pids {}", f.pids_current),
        };
        s.push_str(&row("Fleet cap", format!("{mem} · {pids}")));
    }
    // THE SERVICES a Docker client and a browser reach kern through, as `kern info` says them.
    if !host.docker_api.is_empty() || !host.https.is_empty() {
        s.push_str(&format!("\n  {b}SERVICES{z}\n"));
        if !host.docker_api.is_empty() {
            s.push_str(&row("Docker API", format!("{d}{}{z}", host.docker_api)));
        }
        if !host.https.is_empty() {
            s.push_str(&row("HTTPS", format!("{d}{}{z}", host.https)));
        }
    }
    if rows.is_empty() {
        s.push_str(&format!(
            "\n  {d}no running boxes - start one with `kern run -d <image>`{z}\n"
        ));
    }
    s
}

/// A tiny unicode-block sparkline of `samples`, scaled to their own max - a compact recent-shape glyph
/// for the Runs tab. An all-zero (idle) window renders as a flat baseline, never a panic.
fn spark(samples: &[f64]) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let max = samples.iter().copied().fold(0.0_f64, f64::max);
    if max <= 0.0 {
        return BARS[0].to_string().repeat(samples.len().max(1));
    }
    samples
        .iter()
        .map(|&v| {
            let idx = ((v / max) * (BARS.len() - 1) as f64).round() as usize;
            BARS[idx.min(BARS.len() - 1)]
        })
        .collect()
}

/// The Runs tab. `kern limit` is fire-and-forget (~1 ms, no sandbox, exec-in-place, not registered), so it
/// has NO per-row list - it's shown as **aggregate throughput**. Every figure here is really measured
/// from the daemonless mmap counter: the live rate, the honest average setup latency (entry→exec - this
/// IS the "~1 ms"), the session-peak rate, the cumulative total, and a recent-shape sparkline.
/// Deliberately NOT shown: "active / peak concurrent" - unmeasurable without a per-run reaper that would
/// defeat the whole point of a ~1 ms run, so we don't invent it.
fn runs_table(p: &Palette, host: &HostStats) -> String {
    let (b, c, d, g, z) = (p.b, p.c, p.d, p.g, p.z);
    let row = |k: &str, v: String| format!("  {b}{:<14}{z}{v}\n", k);
    let mut s = String::new();
    s.push_str(&format!(
        // NO FIGURE HERE. This said "gone in ~1 ms": a number with no machine and no method beside it,
        // in a panel that cannot carry either, and one that ages every time the runtime moves. What a
        // reader needs from this line is what a run IS. The measurements live in BENCHMARKS.md.
        "\n  {b}Limits{z}{d} = CPU/memory-capped commands - {z}{c}kern limit -- <cmd>{z}{d} - with {z}{b}no sandbox{z}{d}.{z}\n"
    ));
    s.push_str(&format!(
        "  {d}A limit is {z}{b}NOT a container{z}{d}: every box ({z}{c}kern run{z}{d}, {z}{c}kern box{z}{d}) is on the {z}{c}Boxes{z}{d} tab. These are too many to{z}\n"
    ));
    s.push_str(&format!(
        "  {d}list one-by-one, so this tab {z}{b}counts{z}{d} them as live throughput instead.{z}\n\n"
    ));

    if host.runs_total == 0 {
        s.push_str(&format!(
            "  {d}none yet - fire capped processes with {z}{c}kern limit -- <cmd>{z}\n"
        ));
        s.push_str(&format!(
            "  {d}e.g.  {z}{c}for i in $(seq 1000); do kern limit -- true; done{z}\n\n"
        ));
        s.push_str(&format!(
            "  {d}a limit is a CPU/mem-capped process with no sandbox: cgroup caps only, no namespaces.{z}\n"
        ));
        return s;
    }

    let rate = host.runs_per_sec.round().max(0.0) as u64;
    let per_min = (host.runs_per_sec * 60.0).round().max(0.0) as u64;
    // Live rate is green while streaming, dim when idle (0/s) - the number is the honest "now".
    let rate_col = if host.runs_per_sec > 0.5 { g } else { d };
    s.push_str(&row(
        "Speed",
        format!(
            "{rate_col}{} {d}/sec{z}   {d}({}/min){z}",
            human_count(rate),
            human_count(per_min)
        ),
    ));
    s.push_str(&row(
        "Avg latency",
        format!(
            "{:.1} {d}ms · kern setup overhead (entry→exec){z}",
            host.runs_avg_us as f64 / 1000.0
        ),
    ));
    s.push_str(&row(
        "Peak speed",
        format!(
            "{} {d}/sec · session max{z}",
            human_count(host.runs_peak.round().max(0.0) as u64)
        ),
    ));
    s.push_str(&row(
        "Total",
        format!("{} {d}so far this session{z}", human_count(host.runs_total)),
    ));

    // Recent-shape sparkline of runs/sec (the reader-side ring). When the whole window is idle, an
    // all-`▁` baseline rendered green looks like a growing bar next to "0 /s" (confusing) - so show a
    // green sparkline only when there's real recent activity, else a dim "idle" so a flat line never
    // reads as throughput.
    if host.runs_spark.len() >= 2 {
        if host.runs_spark.iter().any(|&v| v > 0.0) {
            s.push_str(&format!(
                "\n  {b}{:<14}{z}{g}{}{z}\n",
                "Recent",
                spark(&host.runs_spark)
            ));
        } else {
            s.push_str(&format!(
                "\n  {b}{:<14}{z}{d}idle - no runs in the last window{z}\n",
                "Recent"
            ));
        }
    }

    s.push_str(&format!(
        "\n  {d}runs = capped processes (CPU/mem cgroup, no sandbox), fire-and-forget - shown as{z}\n"
    ));
    s.push_str(&format!(
        "  {d}aggregate throughput, not a per-row list: at scale, the list is the wrong shape.{z}\n"
    ));
    s
}

/// The Images tab: cached OCI images (`repository` + `tag` split, size, pulled age) - a read-only
/// in-`top` mirror of `kern images`, sourced from the exact same [`crate::commands::image_entries`] so
/// the two never drift. `repository:tag` is split on the last `:` (unless that tail holds a `/`, i.e. a
/// `host:port/…` reference with no explicit tag → shown as `latest`).
/// The slice of a list to draw so the SELECTED row is on screen, and the line that says what is
/// hidden on either side of it.
///
/// 🔴 EVERY LIST PANE SLICED FROM ZERO. `images[..shown]` drew the first `max_rows` rows and nothing
/// else, forever: the selection could walk past the last drawn row, but the window never followed it,
/// so the cursor left the screen and the rest of the list was UNREACHABLE. Measured on a host with
/// 309 cached images: `kern top` showed 25 and `… 284 more`, and no key reached the 284. The form
/// two hundred lines up already scrolled correctly; the tables did not, and the whole difference was
/// this offset.
///
/// ONE line of chrome, not two, and that is a hard constraint rather than a taste: the frame budget
/// (`body_rows`) reserves exactly one row for the trailing marker, and a test asserts no tab renders
/// more lines than the terminal has - a frame one row too tall scrolls the alternate screen and
/// carries the tab bar off the top. So a single line reports BOTH directions instead of a marker
/// above and another below.
///
/// The window moves as little as it can: descending, the selection sits on the last visible row
/// rather than recentring, which keeps the list still under the eye instead of jumping half a page.
fn list_window(len: usize, max_rows: usize, sel: usize) -> (usize, usize) {
    if len <= max_rows {
        return (0, len);
    }
    let start = sel
        .saturating_sub(max_rows.saturating_sub(1))
        .min(len - max_rows);
    (start, start + max_rows)
}

/// The one-line position marker for a windowed list: what is above, what is below, or nothing at all
/// when the whole list fits.
fn list_marker(p: &Palette, len: usize, start: usize, end: usize) -> String {
    let (d, z) = (p.d, p.z);
    let (above, below) = (start, len.saturating_sub(end));
    match (above, below) {
        (0, 0) => String::new(),
        (0, b) => format!("  {d}… {b} more below{z}\n"),
        (a, 0) => format!("  {d}… {a} more above{z}\n"),
        (a, b) => format!(
            "  {d}… {a} above · {b} below  ({}-{} of {len}){z}\n",
            start + 1,
            end
        ),
    }
}

fn images_table(
    p: &Palette,
    images: &[crate::commands::ImageEntry],
    max_rows: usize,
    sel: usize,
) -> String {
    let (b, c, d, y, z) = (p.b, p.c, p.d, p.y, p.z);
    let cut = |s: &str, n: usize| -> String { s.chars().take(n).collect() };
    let mut s = format!("\n  {d}cached images - {z}{c}kern pull <image>{z}{d} · name order{z}\n\n");
    s.push_str(&format!(
        "  {b}{:<24} {:<14} {:>9}  PULLED{z}\n",
        "REPOSITORY", "TAG", "SIZE"
    ));
    if images.is_empty() {
        s.push_str(&format!(
            "  {d}no images yet - pull one with {z}{c}kern pull alpine{z}\n"
        ));
        return s;
    }
    let now = registry::now_unix();
    let (wstart, wend) = list_window(images.len(), max_rows, sel);
    for (i, img) in images[wstart..wend]
        .iter()
        .enumerate()
        .map(|(k, v)| (k + wstart, v))
    {
        let (lead, col) = sel_marker(p, i == sel);
        let (repo, tag) = match img.name.rsplit_once(':') {
            Some((r, t)) if !t.contains('/') => (r, t),
            _ => (img.name.as_str(), "latest"),
        };
        // A dangling image (layers gone) shows `dangling` in yellow, never a misleading `0 B`. The ref is
        // untrusted `.ok` content - scrub escapes before the raw alt-screen (as image_detail / the CLI do).
        let size = if img.dangling {
            format!("{y}{:>9}{z}", "dangling")
        } else {
            format!("{:>9}", human_bytes(img.size))
        };
        s.push_str(&format!(
            "  {lead}{col}{:<24}{z} {d}{:<14}{z} {size}  {d}{}{z}\n",
            cut(&crate::ui::scrub(repo), 24),
            cut(&crate::ui::scrub(tag), 14),
            fmt_uptime(now.saturating_sub(img.pulled)),
        ));
    }
    // Unconditional: the marker is empty when the whole list fits, so the caller has one code path
    // and cannot forget the guard.
    s.push_str(&list_marker(p, images.len(), wstart, wend));
    s
}

/// The Boxes tab: a per-box table, capped to `max_rows` so it never overflows the screen. `sel` is the
/// highlighted row (the target of the lifecycle keys), marked with a `›` and reverse-video.
/// The Builds tab: `kern build` history (newest first) - id, tag, coloured status (+ warning count),
/// duration, size, age. A read-only in-`top` mirror of `kern builds`.
fn builds_table(
    p: &Palette,
    builds: &[crate::builds::Record],
    // The whole store: `builds` is only the newest part read so far (see `builds_reach`), and the
    // marker below counts what is below on disk, not what happens to be in memory.
    total: usize,
    max_rows: usize,
    sel: usize,
) -> String {
    let (b, c, d, g, y, r, z) = (p.b, p.c, p.d, p.g, p.y, p.r, p.z);
    let cut = |s: &str, n: usize| -> String { s.chars().take(n).collect() };
    let mut s = String::new();
    s.push_str(&format!(
        "\n  {d}build history - {z}{c}kern build -t NAME .{z}{d} · newest first{z}\n\n"
    ));
    s.push_str(&format!(
        "  {b}{:<18} {:<16} {:<11} {:>8} {:>9}  CREATED{z}\n",
        "ID", "TAG", "STATUS", "TIME", "SIZE"
    ));
    if builds.is_empty() {
        s.push_str(&format!(
            "  {d}no builds yet - run {z}{g}kern build -t app .{z}\n"
        ));
        return s;
    }
    let now = registry::now_unix();
    let (wstart, wend) = list_window(builds.len(), max_rows, sel);
    for (i, bd) in builds[wstart..wend]
        .iter()
        .enumerate()
        .map(|(k, v)| (k + wstart, v))
    {
        let (lead, col) = sel_marker(p, i == sel);
        let (sc, label) = match bd.status {
            crate::builds::Status::Ok => (g, "ok".to_string()),
            crate::builds::Status::Warn => (y, format!("warn {}", bd.warnings)),
            crate::builds::Status::Failed => (r, "failed".to_string()),
            crate::builds::Status::Running => (d, "interrupted".to_string()),
        };
        let dur = if bd.duration_ms < 1000 {
            format!("{}ms", bd.duration_ms)
        } else {
            format!("{:.1}s", bd.duration_ms as f64 / 1000.0)
        };
        s.push_str(&format!(
            "  {lead}{col}{:<18}{z} {:<16} {sc}{:<11}{z} {:>8} {:>9}  {d}{}{z}\n",
            cut(&bd.id, 18),
            cut(&bd.tag, 16),
            label,
            dur,
            human_bytes(bd.size),
            fmt_uptime(now.saturating_sub(bd.started)),
        ));
    }
    // Unconditional: the marker is empty when the whole list fits, so the caller has one code path
    // and cannot forget the guard.
    s.push_str(&list_marker(p, total.max(builds.len()), wstart, wend));
    s
}

fn boxes_table(p: &Palette, rows: &[Row], max_rows: usize, sel: usize, host: &HostStats) -> String {
    let (b, c, d, g, y, z) = (p.b, p.c, p.d, p.g, p.y, p.z);
    // The caption every other list pane has and this one did not, though the row budget above
    // already reserves its three lines (blank, caption, blank) for EVERY pane: Boxes was spending
    // the slot on nothing. It carries the word `containers` because that is what someone arriving
    // from another runtime looks for, and a capability named only in this project's own vocabulary
    // is invisible to them - measured once already, when `host.docker.internal` existed and went
    // unfound for three weeks. The pane still costs exactly the 5 chrome lines the budget counts:
    // the start-rate line below takes the second blank's place when it is there.
    // It says `boxes` and not `running boxes` because a row here can be ORPHANED, and the guard
    // that catches a dashboard contradicting its own STATUS column reads the whole pane.
    let mut s =
        format!("\n  {d}boxes (containers) - {z}{c}kern run -d --name <name> <image>{z}{d} · pods grouped{z}\n");
    // Box-START rate. The live list below shows only boxes alive right NOW, but a `kern box` lives ~ms:
    // an agent firing hundreds/sec (via the SDK / kern-mcp) flickers past a 1 s refresh and never appears
    // in the list. This header counts STARTS as a rate + sparkline (same daemonless counter as the Runs
    // tab uses for `kern limit`), so the ephemeral firehose is visible even when the list is empty.
    if host.box_starts_total > 0 {
        let rate = host.box_starts_per_sec.round().max(0.0) as u64;
        let col = if host.box_starts_per_sec > 0.5 { g } else { d };
        s.push_str(&format!(
            "  {d}box starts {z}{col}{rate}{d}/sec{z}  {d}peak {z}{}{d}/s  total {z}{}{d}   recent {}{z}\n",
            host.box_starts_peak.round() as u64,
            host.box_starts_total,
            spark(&host.box_starts_spark)
        ));
    } else {
        s.push('\n');
    }
    // THE NAME COLUMN IS MEASURED, for the reason the comment further down already gives about pod
    // members and which applied one case over. A box with no pod has an empty `pod` field, so
    // `display_box_name` returns its WHOLE name and a fixed sixteen then cut it: a relay-wired
    // compose stack rendered as `psbug-749cf899-f`, `psbug-749cf899-s`, `psbug-749cf899-a` - three
    // services distinguished by one letter each, in the column whose job is to tell them apart.
    // Truncation is worse than overflow here: an overflowing table is ugly and an over-truncated one
    // is wrong.
    //
    // FLOORED AT 16 so a table of short names is exactly what it has always been, and CEILINGED at
    // 48 so one pathological name cannot push STATUS off a terminal.
    let nw = rows
        .iter()
        .map(|r| {
            crate::ui::display_box_name(&r.name, &r.pod).chars().count()
                + if r.pod.is_empty() { 0 } else { 3 } // the tree connector shares this cell
        })
        .chain(std::iter::once(16))
        .max()
        .unwrap_or(16)
        .min(48);
    s.push_str(&format!(
        "    {b}{:<nw$}  {:>7}  {:>8}  {:>8}  {:>5}  {:>4}  {:<9}  {:<14}  STATUS{z}\n",
        "NAME", "PID", "UPTIME", "MEM", "CPU%", "PIDS", "HEALTH", "PORTS"
    ));
    if rows.is_empty() {
        s.push_str(&format!("  {d}no running boxes{z}\n"));
        return s;
    }
    // The window starts wherever the selection is, so `i` stays the ABSOLUTE index into `rows`: the
    // pod grouping and the tree connectors below both look at neighbours by absolute position, and a
    // window-relative index would draw `└─` in the middle of a group.
    let (wstart, wend) = list_window(rows.len(), max_rows, sel);
    let mut prev_pod = "";
    for (i, r) in rows[wstart..wend]
        .iter()
        .enumerate()
        .map(|(k, r)| (k + wstart, r))
    {
        // Pod header when entering a new pod group - the `kern ps` tree view: standalone boxes are
        // flat, a pod's members sit under a `<pod> (pod · N boxes)` header, indented with ├─/└─.
        if !r.pod.is_empty() && r.pod != prev_pod {
            let n = rows.iter().filter(|x| x.pod == r.pod).count();
            let plural = if n == 1 { "box" } else { "boxes" };
            s.push_str(&format!(
                "  {b}{c}{}{z} {d}(pod · {n} {plural}){z}\n",
                r.pod
            ));
        }
        prev_pod = r.pod.as_str();
        // Tree connector inside the NAME cell for a pod member (└─ for the group's last member), so
        // every other column stays aligned. Empty for a standalone box.
        let connector = if r.pod.is_empty() {
            String::new()
        } else if i + 1 >= wend || rows[i + 1].pod != r.pod {
            "└─ ".to_string()
        } else {
            "├─ ".to_string()
        };
        // Strip the pod prefix, exactly as `kern ps` does: the registry keeps the full
        // project-scoped name, but a member shows the SERVICE name its compose file uses. Without
        // this, every member of a pod rendered as the same truncated project prefix
        // (`toptest-ac3b7` three times over) and the one column that tells them apart told you
        // nothing. Display only; a standalone box is printed whole.
        let shown = crate::ui::display_box_name(&r.name, &r.pod);
        let name_cell = format!(
            "{connector}{}",
            trunc(shown, nw.saturating_sub(connector.chars().count()))
        );

        let mem = r.mem.map_or("-".into(), human_bytes);
        let tasks = r.tasks.map_or("-".into(), |n| n.to_string());
        // ORPHANED WINS, exactly as it does in `box_status`. It is a lifecycle state and not a health
        // verdict, so in this table it belongs to STATUS rather than to HEALTH - `kern ps` has one
        // column and puts it there; here there are two, and putting it in the same place as `ps`
        // would have said a box with a healthcheck is unhealthy, which it is not.
        //
        // YELLOW, NOT RED: the box is running and reachable, and the thing that died is the process
        // that would have restarted it. Red would read as "the workload failed".
        // BETWEEN TWO RUNS FIRST: there is no process to be orphaned or paused. Yellow like
        // `orphaned`, a heads-up: the box is not up this instant and systemd is bringing it back.
        let mut status = if r.restarting {
            match r.last_code {
                Some(c) => format!("{y}restarting ({c}){z}"),
                None => format!("{y}restarting{z}"),
            }
        } else if r.orphaned {
            format!("{y}orphaned{z}")
        } else if r.paused {
            format!("{d}paused{z}")
        } else {
            format!("{g}running{z}")
        };
        // WHAT `ps` CANNOT SHOW IN A ROW: a child the OOM killer ended in a box that runs on (the
        // per-process default), and a `--restart` box run again, whose uptime alone reads as new.
        if r.oom_kills > 0 {
            status.push_str(&format!(" {y}oom:{}{z}", r.oom_kills));
        }
        if r.restarts > 0 {
            status.push_str(&format!(" {d}restarts:{}{z}", r.restarts));
        }
        // HEALTH colored like `kern ps`: green healthy, red unhealthy, dim starting/none.
        let health = match r.health.as_str() {
            "healthy" => format!("{g}{:<9}{z}", "healthy"),
            "unhealthy" => format!("{}{:<9}{z}", p.r, "unhealthy"),
            "starting" => format!("{d}{:<9}{z}", "starting"),
            _ => format!("{d}{:<9}{z}", "-"),
        };
        let ports = if r.ports.is_empty() {
            format!("{d}{:<14}{z}", "-")
        } else {
            format!("{:<14}", trunc(&r.ports, 14))
        };
        // Trailing flag only when the box is LESS isolated than default (net:host / root-mapped) - in
        // yellow so it reads as "heads-up", never a green all-clear badge.
        let iso = if r.iso.is_empty() {
            String::new()
        } else {
            format!("  {y}{}{z}", r.iso)
        };
        // Positive-confinement badge (egress/landlock, 0.6.7 policies), in cyan so it reads distinct
        // from the yellow `iso` heads-up: it marks the MORE-confined boxes, not a deviation.
        let sec = if r.sec.is_empty() {
            String::new()
        } else {
            format!("  {c}{}{z}", r.sec)
        };
        let (lead, name_col) = sel_marker(p, i == sel);
        s.push_str(&format!(
            "  {lead}{name_col}{:<nw$}{z}  {:>7}  {:>8}  {:>8}  {:>4.0}%  {:>4}  {health}  {ports}  {status}{iso}{sec}\n",
            name_cell,
            if r.restarting {
                "-".to_string()
            } else {
                r.pid.to_string()
            },
            fmt_uptime(r.uptime),
            mem,
            pct(r.cpu_pct),
            tasks
        ));
    }
    // Unconditional: the marker is empty when the whole list fits, so the caller has one code path
    // and cannot forget the guard.
    s.push_str(&list_marker(p, rows.len(), wstart, wend));
    s
}

/// Normalise a CPU% for display: clamp to ≥ 0 and collapse a signed zero (`-0.0`) to a clean `0.0`.
/// (`f64::max(-0.0, 0.0)` may keep the sign, which then prints as "-0" - an idle-host eyesore.)
fn pct(v: f64) -> f64 {
    let v = v.max(0.0);
    if v == 0.0 {
        0.0
    } else {
        v
    }
}

/// Truncate to `max` chars (char-safe).
fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The running `nvidia-smi` is read as it writes: a line split across two reads is kept until it
    /// ends, each card keeps its newest reading, and a reader that ended says so.
    #[test]
    fn the_gpu_stream_reads_lines_as_they_arrive_and_says_when_it_ended() {
        let script = "printf '0, Card A, 00000000:01:00.0, 100, 8192, 5, 40, 20.5\n1, Card B, 0000'; \
                      sleep 0.3; printf '0000:06:00.0, 7, 8192, 0, 30, 4.0\n0, Card A, 00000000:01:00.0, 200, 8192, 9, 41, 21.0\n'; \
                      sleep 0.3";
        let Some(mut st) = GpuStream::spawn_from(std::path::Path::new("/bin/sh"), &["-c", script])
        else {
            panic!("the fake nvidia-smi did not start");
        };
        let mut seen: Option<Vec<GpuStat>> = None;
        for _ in 0..100 {
            if let Some(v) = st.poll() {
                if v.len() == 2 && v.first().and_then(|g| g.mem_used_mib) == Some(200) {
                    seen = Some(v);
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let Some(cards) = seen else {
            panic!("never read both cards with card 0's newest reading");
        };
        assert_eq!(
            cards.iter().map(|g| g.index).collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(cards[1].bus, "0000:06:00.0", "the split line was joined");
        for _ in 0..100 {
            if st.poll().is_none() && !st.alive {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!st.alive, "the reader did not notice the program ended");
        assert_eq!(st.poll(), None);
    }

    /// The sparkline reader must be TOTAL on any `f64` slice: `kern top` derives it from the daemonless
    /// `runstats` mmap counter, and a corrupt page (a half-finished write, a truncated mmap - or, before
    /// the volume guard's inverted default made `runstats` non-mountable, a peer's forged bytes) must
    /// never panic an ADMIN command. The `max <= 0` guard and the `idx.min(BARS-1)` clamp are what make
    /// it total; this pins that a forged `count`/`latency` (all-zero, all-max, mixed) yields glyphs, not
    /// a `divide by zero` or an out-of-bounds index.
    #[test]
    fn spark_is_total_on_adversarial_input() {
        assert_eq!(spark(&[]).chars().count(), 1); // empty -> one baseline glyph, no panic
        assert_eq!(spark(&[0.0, 0.0, 0.0]), "▁▁▁"); // all zero -> `max <= 0` guard, no div-by-zero
        for s in [
            vec![f64::MAX, 0.0],
            vec![f64::MAX, f64::MAX],
            vec![1e300, 1.0, 0.0],
            vec![u64::MAX as f64, 1.0],
        ] {
            let out = spark(&s);
            assert_eq!(
                out.chars().count(),
                s.len(),
                "one glyph per sample, never a panic"
            );
            assert!(
                out.chars().all(|c| ('▁'..='█').contains(&c)),
                "every glyph is in range"
            );
        }
    }

    fn plain() -> Palette {
        Palette {
            b: "",
            c: "",
            d: "",
            g: "",
            y: "",
            r: "",
            z: "",
        }
    }

    /// `quiet_io` may take the PROCESS's stdout only while there is an alt screen to protect.
    ///
    /// It `dup2`s over fd 1 and fd 2, which belong to the process and not to the calling thread, so
    /// while it is inside `f` every other thread writes into `/dev/null`. This binary is the proof:
    /// libtest runs tests on parallel threads and prints from another one, and the tui tests calling
    /// through `quiet_io` were silently eating up to a hundred lines of the test report, the
    /// `test result:` summary among them, while the binary still exited 0. Measured before the fix:
    /// 6 runs out of 8 ended with no summary at all; after it, 0 out of 8.
    ///
    /// The negative half runs HERE, in the live multi-threaded harness, because that is the situation
    /// that was broken. The positive control runs in a forked child: with the flag set the redirect is
    /// real and process-wide, and performing it in this process would drop the harness's output again,
    /// which is precisely the defect being pinned.
    #[test]
    fn quiet_io_takes_the_process_stdout_only_under_the_alt_screen() {
        fn fd1() -> String {
            std::fs::read_link("/proc/self/fd/1")
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        }
        use std::sync::atomic::Ordering::SeqCst;
        assert_eq!(
            ALT_SCREEN_TID.load(SeqCst),
            0,
            "no test may leave the flag set"
        );
        let before = fd1();
        assert!(!before.is_empty(), "cannot read /proc/self/fd/1 to compare");
        assert_eq!(
            quiet_io(fd1),
            before,
            "quiet_io redirected the whole process's stdout with no alt screen up"
        );
        assert_eq!(fd1(), before, "fd 1 changed across a no-op quiet_io");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            // `this_tid()` in the child, not the inherited value: after a fork the child is a new
            // thread of a new process, and storing the parent's tid would make the owner check fail
            // for the wrong reason and hide whether the swap happens at all.
            ALT_SCREEN_TID.store(this_tid(), SeqCst);
            let inside = quiet_io(fd1);
            let ok = inside == "/dev/null" && fd1() == before;
            unsafe { libc::_exit(i32::from(!ok)) };
        }
        let mut st = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut st, 0) }, pid, "waitpid");
        assert!(
            libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
            "under the alt screen quiet_io must redirect fd 1 to /dev/null and put it back"
        );
    }

    /// A lifecycle key that FAILS must say so on screen.
    ///
    /// `nav_boxes` reuses the CLI helpers inside `quiet_io`, which redirects fd 1 and fd 2 to
    /// /dev/null so their `println!` cannot corrupt the alt-screen. That also swallowed their error
    /// message, and the `Result` itself was discarded - so a refused stop left an unchanged list, a
    /// key that appeared to do nothing, and no reason anywhere. The outcome is now carried out of the
    /// muted section and shown in the overlay pane the log view already uses.
    ///
    /// Driven with a box name that cannot exist, so `commands::pause` returns the "no running box"
    /// error without touching anything on this machine.
    ///
    /// DRIVEN WITH `p` AND NOT `s`, and it used to be `s`. Stopping a box now opens a confirmation
    /// instead of acting on the keystroke, so `s` no longer reaches this path at all: its failure is
    /// reported after the `y`, by `perform_pending`, which
    /// `a_refused_destructive_action_returns_its_reason` covers. `p` is the remaining key that acts
    /// immediately - deliberately, because pause is undone by `u` - so it is the one that still has
    /// to carry its own outcome to the screen.
    #[test]
    fn a_failed_lifecycle_key_is_reported_in_the_overlay() {
        let _g = crate::env_guard();
        let name = format!("tui-absent-{}-{}", std::process::id(), 0xC0FFEEu32);
        let rows = vec![row(&name, false)];
        let mut mode = Mode::Nav;

        let changed = nav_boxes(b'p', 0, &rows, &mut mode);

        assert!(
            changed,
            "a lifecycle key still counts as a state-changing action, so the caller re-reads the list"
        );
        match &mode {
            Mode::Overlay(text) => {
                assert!(
                    text.contains(&name),
                    "the overlay must name the box the action failed on: {text:?}"
                );
            }
            other => panic!(
                "a refused stop must be reported; the TUI stayed in {:?} with nothing on screen",
                std::mem::discriminant(other)
            ),
        }
    }

    /// The same contract for a CONFIRMED destructive action: `perform_pending` returns the failure
    /// text instead of discarding it, so the caller can show it. Driven with a volume name that
    /// cannot exist, which `volume rm` refuses without touching this machine's volume store.
    #[test]
    fn a_refused_destructive_action_returns_its_reason() {
        let _g = crate::env_guard();
        let name = format!("tui-novol-{}-{}", std::process::id(), 0xBADF00Du32);
        let outcome = perform_pending(Pending::RemoveVolume(name.clone()));
        let text = match outcome {
            Some(t) => t,
            None => panic!(
                "removing a volume that does not exist is refused, so perform_pending must return \
                 the reason rather than letting the confirmation look like it worked"
            ),
        };
        assert!(
            !text.is_empty(),
            "the returned failure text must carry the reason, not an empty string"
        );

        // AND THE SAME FOR A STOP, which reaches this function now instead of acting on the
        // keystroke. Without this arm the newest destructive action would be the only one whose
        // refusal could go unreported, which is the gap this whole contract exists to close.
        let boxname = format!("tui-nobox-{}-{}", std::process::id(), 0xDEADBEEFu32);
        let outcome = perform_pending(Pending::StopBox(boxname.clone()));
        match outcome {
            Some(t) => assert!(
                t.contains(&boxname) || !t.is_empty(),
                "the refusal must carry a reason: {t:?}"
            ),
            None => panic!(
                "stopping a box that does not exist is refused, so perform_pending must return the \
                 reason rather than letting the confirmation look like it worked"
            ),
        }
    }

    /// `kern top` AND `kern ps` MUST NOT DISAGREE ABOUT ONE BOX.
    ///
    /// A box whose SUPERVISOR was killed while its PID 1 lives is `orphaned`: still running, still
    /// holding its ports, and with nothing left to restart it. `kern ps` routes its column through
    /// `box_status`, which the CLI documents as the single source of truth and which answers
    /// `orphaned` ahead of everything else. This table asked `health_of` directly - a second
    /// definition of a box's state - and it had drifted: MEASURED by SIGKILLing three supervisors,
    /// `ps` printed `orphaned` and `top` printed `running` for the same three pids in the same
    /// second.
    ///
    /// THE CONTROLS ARE THE OTHER TWO STATES, because a table that printed `orphaned` for everything
    /// would pass an assertion that only looked for the word.
    /// A box between two runs of its `--restart` policy has a row with no process: `restarting`
    /// with its last code, and `-` where a pid would be (0 is no box's pid). Neither `running` nor
    /// `orphaned`, which would say a process exists.
    #[test]
    fn the_boxes_table_lists_a_box_between_runs_without_a_pid() {
        let _g = crate::env_guard();
        let p = Palette::plain();
        let host = HostStats::default();
        let mut gap = row("loop", false);
        gap.pid = 0;
        gap.restarting = true;
        gap.last_code = Some(1);
        gap.mem = None;
        gap.tasks = None;
        let out = boxes_table(&p, &[gap], 10, 0, &host);
        let line = out.lines().find(|l| l.contains("loop")).unwrap_or_default();
        assert!(line.contains("restarting (1)"), "{out}");
        assert!(
            !line.contains("running") && !line.contains("orphaned"),
            "{out}"
        );
        assert!(
            line.split_whitespace().skip_while(|w| *w != "loop").nth(1) == Some("-"),
            "the pid column of a box with no process: {line:?}"
        );
    }

    #[test]
    fn the_boxes_table_reports_an_orphaned_box_as_orphaned_and_not_as_running() {
        let _g = crate::env_guard();
        let p = Palette::plain();
        let host = HostStats::default();
        let mut orphan = row("gone", false);
        orphan.orphaned = true;
        let out = boxes_table(&p, &[orphan], 10, 0, &host);
        assert!(
            out.contains("orphaned"),
            "a box whose supervisor is dead must say so here, as `kern ps` does:\n{out}"
        );
        assert!(
            !out.contains("running"),
            "and it must not ALSO be called running: a dashboard that contradicts the list leaves \
             the reader no way to tell which one is lying:\n{out}"
        );
        // THE CONTROLS. An ordinary box is running; a paused one is paused; neither is orphaned.
        let live = boxes_table(&p, &[row("live", false)], 10, 0, &host);
        assert!(
            live.contains("running") && !live.contains("orphaned"),
            "the CONTROL failed: an ordinary box must still read as running:\n{live}"
        );
        let held = boxes_table(&p, &[row("held", true)], 10, 0, &host);
        assert!(
            held.contains("paused") && !held.contains("orphaned"),
            "the CONTROL failed: a paused box must still read as paused:\n{held}"
        );
    }

    /// The two counts `ps` cannot show in a row are in the status cell, and only when not zero.
    #[test]
    fn a_box_row_says_its_oom_kills_and_restarts() {
        let host = HostStats::default();
        let mut r = row("web", false);
        let quiet = boxes_table(&plain(), &[row("web", false)], 10, 0, &host);
        assert!(
            !quiet.contains("oom:") && !quiet.contains("restarts:"),
            "{quiet}"
        );
        r.oom_kills = 2;
        r.restarts = 3;
        let out = boxes_table(&plain(), &[r], 10, 0, &host);
        assert!(out.contains("running oom:2 restarts:3"), "{out}");
    }

    /// The Overview counts how the boxes reach out, one word per box and a box it could not read
    /// apart, says the OOM kills, and names the services in `kern info`'s words.
    #[test]
    fn the_overview_counts_networks_and_names_the_services() {
        let _g = crate::env_guard();
        let with = |n: &str, net: &'static str| {
            let mut r = row(n, false);
            r.net = net;
            r
        };
        let mut host_pod = with("d", "host");
        host_pod.oom_kills = 4;
        let (nat, none, pod, gap) = (
            with("a", "nat"),
            with("b", "none"),
            with("c", "pod"),
            with("e", ""),
        );
        let host = HostStats {
            docker_api: "listening on /run/x.sock".into(),
            https: "off".into(),
            ..HostStats::default()
        };
        let out = overview(&plain(), &[nat, none, pod, host_pod, gap], &host);
        assert!(
            out.contains("1 nat · 1 pod · 1 host · 1 none · 1 not read"),
            "{out}"
        );
        assert!(
            out.contains("OOM kills") && out.contains("4 in 1 running box"),
            "{out}"
        );
        assert!(
            out.contains("SERVICES") && out.contains("listening on /run/x.sock"),
            "{out}"
        );
        let empty = overview(&plain(), &[], &HostStats::default());
        assert!(
            !empty.contains("SERVICES") && !empty.contains("Network") && !empty.contains("OOM"),
            "{empty}"
        );
        assert!(empty.contains("kern run -d <image>"), "{empty}");
    }

    fn row(name: &str, paused: bool) -> Row {
        Row {
            name: name.into(),
            pid: 100,
            uptime: 5,
            mem: Some(1024 * 1024),
            cpu_pct: 1.0,
            tasks: Some(3),
            paused,
            health: String::new(),
            ports: String::new(),
            pod: String::new(),
            iso: String::new(),
            sec: String::new(),
            orphaned: false,
            oom_kills: 0,
            restarts: 0,
            net: "",
            restarting: false,
            last_code: None,
        }
    }

    /// A terminal delivers several bytes in ONE read whenever keys outrun the loop: a held key, a
    /// paste, or a laggy link (ssh to a board is the normal case, not the exception). Dispatching
    /// `buf[0]` and dropping the rest meant a burst ending in `q` never quit: measured, a batch of
    /// eight keys hung the TUI until it was killed 12 s later, one at a time it answered in 274 ms.
    ///
    /// The escape sequences are the reason this cannot be a plain per-byte loop: an arrow key is
    /// three bytes that mean ONE event, and splitting it would type a stray `[` into a form.
    #[test]
    fn a_burst_becomes_one_event_per_key_and_an_arrow_stays_whole() {
        let split = |b: &[u8]| {
            let mut q = std::collections::VecDeque::new();
            split_keys(b, &mut q);
            q.into_iter().collect::<Vec<_>>()
        };
        // The measured failure: eight keys in one read are eight events, and the last is `q`.
        let got = split(b"1234567q");
        assert_eq!(got.len(), 8, "a burst must not collapse to one event");
        assert_eq!(got[7], b"q".to_vec(), "the quit key must survive the burst");
        // An arrow is one event of three bytes, not three events.
        assert_eq!(split(b"\x1b[C"), vec![b"\x1b[C".to_vec()]);
        assert_eq!(
            split(b"\x1b[C\x1b[Dq"),
            vec![b"\x1b[C".to_vec(), b"\x1b[D".to_vec(), b"q".to_vec()]
        );
        // `ESC O P` (an F-key on some terminals) is the other sequence introducer.
        assert_eq!(split(b"\x1bOP"), vec![b"\x1bOP".to_vec()]);
        // A bare Escape is a key in its own right: it closes a modal, so it must NOT be held back
        // waiting for bytes that are never coming.
        assert_eq!(split(b"\x1b"), vec![b"\x1b".to_vec()]);
        assert_eq!(split(b"\x1bq"), vec![b"\x1b".to_vec(), b"q".to_vec()]);
        // A truncated sequence still yields one event rather than vanishing.
        assert_eq!(split(b"\x1b["), vec![b"\x1b[".to_vec()]);
        assert!(split(b"").is_empty());
    }

    /// A frame taller than the screen scrolls the alternate buffer: the tab bar leaves through the
    /// top and every repaint starts one line lower, which is seen as flicker. It was real, and the
    /// arithmetic that caused it is the kind that drifts silently, so the invariant is pinned here
    /// rather than in a comment.
    ///
    /// Measured before the fix, with a list long enough to fill the budget: Images and Builds
    /// rendered **33** lines into a **30**-row terminal, at every size, always over by exactly 3.
    #[test]
    fn no_tab_ever_renders_a_frame_taller_than_the_terminal() {
        // `render` reads the sandbox history, which lives under `XDG_RUNTIME_DIR`.
        let _g = crate::env_guard();
        // Far more rows than any budget: whichever pane is on screen, its list is the long case.
        let rows: Vec<Row> = (0..200).map(|i| row(&format!("box{i}"), false)).collect();
        let builds: Vec<crate::builds::Record> = (0..200)
            .map(|i| crate::builds::Record {
                id: format!("{i}"),
                tag: format!("t{i}"),
                ..Default::default()
            })
            .collect();
        let images: Vec<crate::commands::ImageEntry> = (0..200)
            .map(|i| crate::commands::ImageEntry {
                name: format!("img{i}"),
                size: 1024,
                pulled: 0,
                dangling: false,
                platform: None,
                stem: String::new(),
            })
            .collect();
        for term_rows in [10usize, 20, 24, 30, 40, 50, 80] {
            for tab in 0..TABS.len() {
                let frame = render(
                    &plain(),
                    tab,
                    &rows,
                    &HostStats::default(),
                    &[],
                    &[],
                    &builds,
                    builds.len(),
                    &images,
                    images.len(),
                    100,
                    term_rows,
                    0,
                    &Mode::Nav,
                    &crate::logview::LogView::default(),
                );
                let h = frame.lines().count();
                assert!(
                    h <= term_rows,
                    "tab {tab} rendered {h} lines into {term_rows} rows: the alt screen will scroll"
                );
            }
        }
    }

    /// THE FOOTER IS THE LAST LINE OF EVERY TAB, WITH EVERY LIST LONG. The test above holds the
    /// frame's HEIGHT, which `render` caps by cutting the bottom, so it passed while the cut removed
    /// the footer: MEASURED, Storage with 555 volumes lost its `[d]elete` line, because its DISKS
    /// section is three lines the frame budget did not know about. It also gave Storage no volumes.
    #[test]
    fn every_tab_ends_with_its_footer_whatever_its_lists_hold() {
        // `render` reads the sandbox history, which lives under `XDG_RUNTIME_DIR`.
        let _g = crate::env_guard();
        let rows: Vec<Row> = (0..200).map(|i| row(&format!("box{i}"), false)).collect();
        let vols: Vec<crate::volume::VolInfo> = (0..555)
            .map(|i| crate::volume::VolInfo {
                name: format!("vol{i}"),
                raw: format!("vol{i}"),
                size: Some(1024),
                quota: None,
            })
            .collect();
        let profs: Vec<ProfRow> = (0..200)
            .map(|i| ProfRow {
                section: "vcpu",
                name: format!("p{i}"),
                summary: String::new(),
            })
            .collect();
        let builds: Vec<crate::builds::Record> = (0..200)
            .map(|i| crate::builds::Record {
                id: format!("{i}"),
                tag: format!("t{i}"),
                ..Default::default()
            })
            .collect();
        let images: Vec<crate::commands::ImageEntry> = (0..200)
            .map(|i| crate::commands::ImageEntry {
                name: format!("img{i}"),
                size: 1024,
                pulled: 0,
                dangling: false,
                platform: None,
                stem: String::new(),
            })
            .collect();
        for term_rows in [24usize, 30, 40, 50, 80] {
            for tab in 0..TABS.len() {
                for sel in [0usize, 300, 554] {
                    let frame = render(
                        &plain(),
                        tab,
                        &rows,
                        &HostStats::default(),
                        &profs,
                        &vols,
                        &builds,
                        builds.len(),
                        &images,
                        images.len(),
                        100,
                        term_rows,
                        sel,
                        &Mode::Nav,
                        &crate::logview::LogView::default(),
                    );
                    let last = frame.lines().last().unwrap_or("");
                    assert!(
                        last.contains("help"),
                        "tab {tab}, {term_rows} rows, sel {sel}: the last line is not the footer: {last:?}"
                    );
                    // The Overview says where the sandbox history is kept, and how to change it.
                    if tab == TAB_OVERVIEW && term_rows >= 40 {
                        assert!(
                            frame.lines().any(|l| l.contains("Sandbox history")
                                && l.contains("○")
                                && l.contains("m to change")),
                            "{frame}"
                        );
                    }
                }
            }
        }
    }

    /// THE SANDBOXES TAB STAYS IN ITS BUDGET WITH A LONG HISTORY AND MANY RUNNING: the five lines
    /// every pane has, the rows it was given, and nothing more (a pane that overflows pushes the
    /// footer off the screen, as Storage and Profiles did). The selected row is on screen at the end
    /// of the list, a failure is named, and the running ones past three are sent to Boxes.
    #[test]
    fn the_sandboxes_tab_lists_the_finished_ones_within_its_rows() {
        let _g = crate::env_guard();
        let done: Vec<crate::history::Entry> = (0..300)
            .map(|i| crate::history::Entry {
                ended_ms: 1_000 + i,
                name: format!("pysbx-{i:012}"),
                image: "python:3.12-slim".into(),
                ran_ms: 40,
                code: if i == 299 { 137 } else { 0 },
                outcome: if i == 299 {
                    crate::history::Outcome::Oom
                } else {
                    crate::history::Outcome::Ok
                },
                gpu: "-".into(),
            })
            .collect();
        let live: Vec<Row> = (0..5)
            .map(|i| row(&format!("kern-sbx-k{i}"), false))
            .collect();
        for (max_rows, sel) in [(20usize, 0usize), (20, 299), (8, 150)] {
            let out = sandboxes_table(&plain(), &live, &done, max_rows, sel);
            let n = out.lines().count();
            assert!(n <= max_rows + 5, "{n} lines for {max_rows} rows:\n{out}");
            assert!(
                out.contains(&format!("pysbx-{sel:012}")),
                "the selected row is shown:\n{out}"
            );
            assert!(
                out.contains("3 more running, all of them in the Boxes tab"),
                "{out}"
            );
            assert!(out.contains("5 running"), "{out}");
        }
        let out = sandboxes_table(&plain(), &live, &done, 20, 299);
        assert!(
            out.lines()
                .any(|l| l.contains("pysbx-000000000299") && l.contains("oom")),
            "{out}"
        );
        let empty = sandboxes_table(&plain(), &[], &[], 20, 0);
        assert!(
            empty.contains("none yet") && empty.contains("0 running"),
            "{empty}"
        );
        // WHERE THE HISTORY IS KEPT is on the tab, all three choices with one marked, the count and
        // the key: a reader must not have to press `m` to learn the default clears at reboot.
        let hist = out
            .lines()
            .find(|l| l.contains("HISTORY"))
            .unwrap_or_default();
        let marked = ["● memory", "● disk", "● off"]
            .iter()
            .filter(|m| hist.contains(*m))
            .count();
        let open = ["○ memory", "○ disk", "○ off"]
            .iter()
            .filter(|m| hist.contains(*m))
            .count();
        assert!(
            marked == 1
                && open == 2
                && hist.contains("300 finished sandboxes recorded")
                && hist.contains("m to change"),
            "{out}"
        );
        // THE LIVE SECTION HAS ONE HEIGHT, whatever runs: the list under it must not jump.
        let h = |live: &[Row]| {
            sandboxes_table(&plain(), live, &done, 20, 0)
                .lines()
                .count()
        };
        assert_eq!(h(&[]), h(&live[..1]));
        assert_eq!(h(&[]), h(&live));
        // A row that ended a moment ago carries the dot and an old one does not; newest first, as
        // the tab receives the history.
        let mut newest: Vec<crate::history::Entry> = done.clone();
        newest.reverse();
        let now = newest[0].ended_ms + 500;
        let fresh = sandboxes_table_at(&plain(), &[], &newest, 20, 0, now);
        let line = |name: &str| {
            fresh
                .lines()
                .find(|l| l.contains(name))
                .unwrap_or("")
                .to_string()
        };
        assert!(line("pysbx-000000000299").contains('●'), "{fresh}");
        let old_one = sandboxes_table_at(&plain(), &[], &newest, 20, 0, now + 10_000);
        // The finished rows only: the HISTORY line marks the current choice with the same dot.
        assert!(
            !old_one
                .lines()
                .filter(|l| l.contains("pysbx-"))
                .any(|l| l.contains('●')),
            "nothing is fresh ten seconds later: {old_one}"
        );
        // The per-second activity counts the ends inside the last minute, and only those.
        assert_eq!(
            ends_per_bucket(&done, 200_000, 60, 30).iter().sum::<f64>(),
            0.0
        );
        let per = ends_per_bucket(&done, 1_300, 60, 30);
        assert_eq!((per.len(), per.iter().sum::<f64>()), (30, 300.0));
        // AND THE TITLE FITS 100 COLUMNS, which a 60-bar line did not.
        let title = fresh.lines().find(|l| l.contains("LIVE")).unwrap_or("");
        assert!(
            title.chars().count() <= 100,
            "{} cols: {title}",
            title.chars().count()
        );
    }

    #[test]
    fn boxes_tab_shows_egress_landlock_badge() {
        // A box carrying 0.6.7 confinement policies surfaces a `sec` badge in the Boxes tab, so the TUI
        // reflects egress/landlock rather than looking identical to an unconfined box.
        let mut r = row("guarded", false);
        r.sec = "egress+landlock".to_string();
        let out = boxes_table(&plain(), &[r], 10, usize::MAX, &HostStats::default());
        let line = out.lines().find(|l| l.contains("guarded")).unwrap();
        assert!(line.contains("egress+landlock"), "badge missing: {line}");
    }

    #[test]
    fn boxes_flag_only_reduced_isolation_never_a_secure_badge() {
        // A default (fully isolated) box carries NO isolation marker - no vanity "secure" badge.
        let out = boxes_table(
            &plain(),
            &[row("safe", false)],
            10,
            usize::MAX,
            &HostStats::default(),
        );
        let safe = out.lines().find(|l| l.contains("safe")).unwrap();
        assert!(
            !safe.contains("net:host") && !safe.contains("root-mapped"),
            "an isolated box shows no deviation flag: {safe}"
        );
        // A box that deviates (net:host / root-mapped / caps:+ / gpu:N) surfaces exactly that.
        let mut r = row("loose", false);
        r.iso = "net:host root-mapped caps:+".into();
        let out2 = boxes_table(&plain(), &[r], 10, usize::MAX, &HostStats::default());
        let loose = out2.lines().find(|l| l.contains("loose")).unwrap();
        assert!(
            loose.contains("net:host") && loose.contains("root-mapped") && loose.contains("caps:+"),
            "a less-confined box flags its deviations: {loose}"
        );
    }

    #[test]
    fn selected_row_gets_a_caret() {
        let rows = [row("web", false), row("db", false)];
        let out = boxes_table(&plain(), &rows, 10, 1, &HostStats::default()); // db selected
        let line = out.lines().find(|l| l.contains("db")).unwrap();
        assert!(line.contains('›'), "selected row should show the caret");
        let web = out.lines().find(|l| l.contains("web")).unwrap();
        assert!(!web.contains('›'), "unselected row must not show the caret");
    }

    #[test]
    fn boxes_table_shows_the_box_start_rate() {
        // The ephemeral-firehose lens: when boxes have STARTED (counter > 0) the header shows a rate +
        // total, even with an EMPTY live list (every box already flickered past). Absent when total is 0.
        let host = HostStats {
            box_starts_total: 1234,
            box_starts_per_sec: 87.0,
            box_starts_peak: 90.0,
            box_starts_spark: vec![10.0, 40.0, 87.0],
            ..HostStats::default()
        };
        let out = boxes_table(&plain(), &[], 10, usize::MAX, &host); // empty list, but starts happened
        assert!(out.contains("box starts"), "shows the start-rate header");
        assert!(
            out.contains("87") && out.contains("1234"),
            "shows rate/sec and cumulative total"
        );
        // absent when nothing has started
        let none = boxes_table(&plain(), &[], 10, usize::MAX, &HostStats::default());
        assert!(
            !none.contains("box starts"),
            "no rate header before any box has started"
        );
    }

    #[test]
    fn the_one_shot_snapshot_keeps_the_pair_every_rate_here_needs() {
        // THE GATE THAT ALWAYS RUNS. The end-to-end guard for this
        // (`a_piped_top_reports_a_real_cpu_percent_per_box`) needs busybox, a user namespace AND a
        // delegated per-box cgroup, and honestly SKIPS without them - which is most CI runners, the
        // one place nobody reads a skip line. So the rule is also asserted where it cannot skip: in
        // this file's own source.
        //
        // THE RULE: every number in this pane except MEM/PIDS/UPTIME is a DELTA between two samples.
        // `snapshot()` is the one caller with no previous frame to subtract, so it has to take both
        // halves itself. The two spellings below are precisely how it failed to: an empty map makes
        // `collect_rows` take its `None => 0.0` arm for every box, and a default `HostStats` carries
        // `box_starts_total: 0`, the arm that prints a blank line where the rate belongs.
        const SRC: &str = include_str!("tui.rs");
        let body = SRC
            .split_once("pub fn snapshot()")
            .expect("snapshot() is still in this file")
            .1;
        let body = &body[..body.find("\n}\n").expect("snapshot() has an end")];
        for bad in ["HashMap::new()", "HostStats::default()"] {
            assert!(
                !body.contains(bad),
                "`snapshot()` passes `{bad}`, which discards the earlier half of a delta and makes \
                 every box read 0% CPU (measured: 0% for a box the cgroup said was at 100%). Take \
                 the first sample before the sleep this function already does, as it does for the \
                 host CPU%."
            );
        }
        // The positive side, so deleting the samples rather than renaming them cannot pass either.
        assert!(
            body.contains("sample_box_cpu()") && body.contains("sample_rate("),
            "`snapshot()` no longer takes the earlier half of the per-box CPU and box-start samples"
        );
    }

    #[test]
    fn the_boxes_caption_costs_the_same_rows_with_or_without_the_start_rate() {
        // The frame budget (`body_rows = term_rows - 12`) reserves FIVE lines per list pane. Boxes
        // used two of them and now uses the caption as well, so the arithmetic is asserted rather
        // than trusted: the start-rate line, when present, takes the second blank's place instead of
        // adding a sixth line. Getting this wrong is the flicker the budget comment describes.
        let chrome = |host: &HostStats| -> usize {
            boxes_table(&plain(), &[], 10, usize::MAX, host)
                .lines()
                .count()
        };
        let busy = HostStats {
            box_starts_total: 12,
            box_starts_per_sec: 3.0,
            ..HostStats::default()
        };
        let idle = HostStats::default();
        assert_eq!(chrome(&busy), chrome(&idle), "same rows in both branches");
        let out = boxes_table(&plain(), &[], 10, usize::MAX, &idle);
        assert!(
            out.contains("boxes (containers)"),
            "the pane names what it lists, in the word a reader from another runtime searches for"
        );
        assert!(
            out.contains("kern run -d --name <name> <image>"),
            "and the command that makes one, as every other pane's caption does"
        );
    }

    #[test]
    fn boxes_table_shows_health_and_ports_like_ps() {
        // A box with a healthcheck + published port must surface both in the TUI, matching `kern ps`.
        let mut r = row("web", false);
        r.health = "healthy".into();
        r.ports = "8080->80".into();
        let out = boxes_table(&plain(), &[r], 10, 0, &HostStats::default());
        assert!(out.contains("HEALTH"), "header must include HEALTH");
        assert!(out.contains("PORTS"), "header must include PORTS");
        assert!(out.contains("healthy"), "row must show the health state");
        assert!(out.contains("8080->80"), "row must show the ports");
        // A box with no healthcheck / no ports shows a dim `-`, never an empty gap.
        let out2 = boxes_table(&plain(), &[row("db", false)], 10, 0, &HostStats::default());
        let dbrow = out2.lines().find(|l| l.contains("db")).unwrap();
        assert!(dbrow.contains('-'), "no-health/no-ports row shows a dash");
    }

    /// A STORE CLOSE TO FULL IS SAID, with what fails and the command that gives room back; under
    /// the threshold nothing is said at all.
    #[test]
    fn the_overview_alerts_on_a_disk_or_a_log_store_close_to_full() {
        let at = |disk: u64, logs: u64| HostStats {
            disk_fill: disk,
            logs_fill: logs,
            ..HostStats::default()
        };
        assert!(
            alerts(&plain(), &at(84, 84)).is_empty(),
            "under 85 % nothing is said"
        );
        let a = alerts(&plain(), &at(90, 10));
        assert!(a.contains("ALERTS") && a.contains("Disk 90 % full") && a.contains("kern gc"));
        assert!(!a.contains("Log store"));
        let a = alerts(&plain(), &at(10, 96));
        assert!(
            a.contains("Log store 96 % full") && a.contains("DROPPED") && a.contains("kern prune")
        );
        assert!(!a.contains("Disk "));
    }

    #[test]
    fn tab_bar_shows_live_counts() {
        // `render` reads the sandbox history, which lives under `XDG_RUNTIME_DIR` (or, kept on
        // disk, under `XDG_DATA_HOME`), so the test gets its own, EMPTY one. Reading the host's made
        // the outcome the host's: a desktop with 1464 finished sandboxes pushed the bar past 100
        // columns once a ninth tab was added, and the counts this test asserts went with it.
        let _g = crate::env_guard();
        struct World(
            Vec<(&'static str, Option<std::ffi::OsString>)>,
            std::path::PathBuf,
        );
        impl Drop for World {
            fn drop(&mut self) {
                for (v, old) in &self.0 {
                    match old {
                        Some(x) => crate::set_global_env(v, x),
                        None => crate::unset_global_env(v),
                    }
                }
                let _ = std::fs::remove_dir_all(&self.1);
            }
        }
        let base = std::env::temp_dir().join(format!("kern-tui-tabbar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let _world = World(
            [
                "XDG_RUNTIME_DIR",
                "XDG_DATA_HOME",
                "XDG_CONFIG_HOME",
                "KERN_CONFIG",
            ]
            .iter()
            .map(|v| (*v, crate::global_env(v)))
            .collect(),
            base.clone(),
        );
        for (v, d) in [
            ("XDG_RUNTIME_DIR", "run"),
            ("XDG_DATA_HOME", "data"),
            ("XDG_CONFIG_HOME", "config"),
        ] {
            let _ = std::fs::create_dir_all(base.join(d));
            crate::set_global_env(v, base.join(d));
        }
        crate::unset_global_env("KERN_CONFIG");
        // The tab bar shows a live count per data tab (Boxes/Profiles/Storage) so you see how many
        // items exist without entering - Overview (an aggregate) has no count.
        let host = HostStats {
            mem_used: 0,
            mem_total: 1,
            disk_used: 0,
            disk_total: 1,
            logs_used: 0,
            logs_total: 1,
            disk_fill: 0,
            logs_fill: 0,
            cpu_pct: 0.0,
            cores: 1,
            load1: 0.0,
            runs_total: 0,
            runs_per_sec: 0.0,
            runs_avg_us: 0,
            runs_peak: 0.0,
            runs_spark: Vec::new(),
            box_starts_total: 0,
            box_starts_per_sec: 0.0,
            box_starts_peak: 0.0,
            box_starts_spark: Vec::new(),
            gpus: Vec::new(),
            docker_api: String::new(),
            https: String::new(),
        };
        let boxes = [row("a", false), row("b", false), row("c", false)];
        // A wide terminal (100 columns, about the 97 the counted bar takes with its zeros dropped)
        // shows the live counts.
        let out = render(
            &plain(),
            TAB_BOXES,
            &boxes,
            &host,
            &[],
            &[],
            &[],
            // The Builds count is the STORE's total, deliberately not `builds.len()`: the records
            // are only read on the Builds tab, so on every other tab the slice is empty while the
            // count must still be right. Passing an empty slice with a non-zero total here is the
            // exact shape of a non-Builds frame, and it caught nothing only because it was added
            // after the wiring - it exists so a future refactor cannot quietly re-derive the count
            // from the slice and show `Builds (0)` on six tabs out of seven.
            7,
            &[],
            5,
            100,
            24,
            0,
            &Mode::Nav,
            &crate::logview::LogView::default(),
        );
        assert!(
            out.contains("Builds (7)"),
            "Builds count comes from the total, not the (empty) record slice: {out}"
        );
        assert!(
            out.contains("Images (5)"),
            "Images count comes from the total the same way: {out}"
        );
        // 3 boxes, 0 profiles, 0 volumes.
        assert!(
            out.contains("Boxes (3)"),
            "Boxes tab shows its count: {out}"
        );
        // AT 100 COLUMNS NINE COUNTED TABS DO NOT FIT, and the bar gives up the `(0)`s first,
        // keeping every count that says something: the three above.
        assert!(
            !out.contains("Profiles (0)"),
            "a zero count is the first to go"
        );
        // With the room, every count is there, the zeros and the Sandboxes one included.
        let wide = render(
            &plain(),
            TAB_BOXES,
            &boxes,
            &host,
            &[],
            &[],
            &[],
            // The Builds count is the STORE's total, deliberately not `builds.len()`: the records
            // are only read on the Builds tab, so on every other tab the slice is empty while the
            // count must still be right. Passing an empty slice with a non-zero total here is the
            // exact shape of a non-Builds frame, and it caught nothing only because it was added
            // after the wiring - it exists so a future refactor cannot quietly re-derive the count
            // from the slice and show `Builds (0)` on six tabs out of seven.
            7,
            &[],
            5,
            120,
            24,
            0,
            &Mode::Nav,
            &crate::logview::LogView::default(),
        );
        assert!(
            wide.contains("Profiles (0)"),
            "Profiles tab shows 0: {wide}"
        );
        assert!(wide.contains("Storage (0)"), "Storage tab shows 0");
        assert!(
            wide.contains("Sandboxes ("),
            "Sandboxes is counted like every list tab"
        );
        assert!(out.contains("Overview"), "Overview stays uncounted");
        assert!(
            !out.contains("Overview ("),
            "Overview must NOT carry a count"
        );

        // LARGE COUNTS ARE WRITTEN SHORT BEFORE THEY ARE DROPPED: 11961 builds and 1464 images
        // do not fit 100 columns in full, and `12k` and `1k` do.
        let large = render(
            &plain(),
            TAB_BOXES,
            &boxes,
            &host,
            &[],
            &[],
            &[],
            11_961,
            &[],
            1_464,
            100,
            24,
            0,
            &Mode::Nav,
            &crate::logview::LogView::default(),
        );
        // In full where the tight spacing makes room (it does at 100 columns), else written short.
        assert!(
            (large.contains("Builds (11961)") || large.contains("Builds (12k)"))
                && (large.contains("Images (1464)") || large.contains("Images (1k)")),
            "a large count is kept, not dropped: {large}"
        );
        // Where even the tight bar needs it, the large count is written short before it goes.
        let shorter = render(
            &plain(),
            TAB_BOXES,
            &boxes,
            &host,
            &[],
            &[],
            &[],
            11_961,
            &[],
            1_464,
            95,
            24,
            0,
            &Mode::Nav,
            &crate::logview::LogView::default(),
        );
        assert!(
            shorter.contains("Builds (12k)") && shorter.contains("Images (1k)"),
            "a large count is shortened, not dropped: {shorter}"
        );
        assert_eq!(short_count(999), "999");
        assert_eq!(short_count(1_464), "1k");
        assert_eq!(short_count(999_499), "999k");
        assert_eq!(short_count(999_500), "1M");

        // A narrow terminal drops the counts but keeps EVERY tab visible (the overflow bug: at 80
        // cols the counted bar would wrap and shove Images/Builds/… off screen).
        let narrow = render(
            &plain(),
            TAB_BOXES,
            &boxes,
            &host,
            &[],
            &[],
            &[],
            7,
            &[],
            0,
            80,
            24,
            0,
            &Mode::Nav,
            &crate::logview::LogView::default(),
        );
        assert!(!narrow.contains("Boxes (3)"), "narrow bar drops counts");
        for t in [
            "Overview", "Boxes", "Limits", "Images", "Builds", "Profiles", "Storage",
        ] {
            assert!(
                narrow.contains(t),
                "narrow bar keeps every tab: missing {t}"
            );
        }
    }

    #[test]
    fn storage_shows_infinity_for_unlimited_quota() {
        // A volume with no quota is UNLIMITED - show `∞`, not an ambiguous `-`. A capped one shows the
        // human size. (The bug: `-` read as "unset/error" instead of "no cap".)
        let vols = [
            crate::volume::VolInfo {
                name: "boundless".into(),
                raw: "boundless".into(),
                size: Some(11),
                quota: None,
            },
            crate::volume::VolInfo {
                name: "capped".into(),
                raw: "capped".into(),
                size: Some(0),
                quota: Some(2 * 1024 * 1024 * 1024),
            },
        ];
        let out = storage_table(&plain(), &vols, 10, 0);
        assert!(out.contains('∞'), "unlimited quota shows ∞: {out}");
        assert!(!out.contains(" - "), "no bare dash for the quota column");
        assert!(out.contains("2G"), "a capped quota shows its size");
    }

    /// Drive one key through `handle_nav` on the Boxes tab, returning the resulting mode and
    /// selection. The signature is long and every argument is a live list, so a helper keeps the
    /// cases below about the KEY rather than about the plumbing.
    /// A BOX NAME IS NEVER CUT DOWN TO A PREFIX EVERY ROW SHARES.
    ///
    /// The NAME cell was a fixed sixteen characters and the name was truncated into it. For a pod
    /// member that is harmless - the pod prefix is stripped first, so what is shown is the short
    /// service name - and the comment in `boxes_table` records exactly that fix. A box with NO pod
    /// has an empty `pod` field, so nothing is stripped and the full, project-scoped name met the
    /// cut: MEASURED on a relay-wired compose stack, three services rendered as
    /// `psbug-749cf899-f`, `psbug-749cf899-s` and `psbug-749cf899-a`, told apart by one letter in
    /// the column whose only job is to tell them apart.
    ///
    /// TRUNCATION IS WORSE THAN OVERFLOW HERE, which is why this asserts the name is WHOLE rather
    /// than that the table is narrow: an overflowing table is ugly, an over-truncated one is wrong,
    /// and the name is what `kern stop` takes.
    ///
    /// THE CONTROL IS THE SHORT-NAME CASE in the same assertion: a table of short names must still
    /// lay out at the old width, or this would pass on a renderer that simply padded everything to
    /// some new constant.
    #[test]
    fn the_boxes_table_never_truncates_a_name_into_a_shared_prefix() {
        let _g = crate::env_guard();
        let row = |name: &str, pod: &str, pid: i32| Row {
            name: name.to_string(),
            pid,
            uptime: 3,
            mem: Some(1024),
            cpu_pct: 0.0,
            tasks: Some(1),
            paused: false,
            health: String::new(),
            ports: String::new(),
            pod: pod.to_string(),
            iso: String::new(),
            sec: String::new(),
            orphaned: false,
            oom_kills: 0,
            restarts: 0,
            net: "",
            restarting: false,
            last_code: None,
        };
        let p = Palette::plain();
        let host = HostStats::default();
        // Three no-pod boxes whose names share the first fifteen characters, which is the shape a
        // relay-wired compose stack produces.
        let long = vec![
            row("psbug-749cf899-front", "", 101),
            row("psbug-749cf899-secret", "", 102),
            row("psbug-749cf899-api", "", 103),
        ];
        let out = boxes_table(&p, &long, 10, 0, &host);
        for whole in [
            "psbug-749cf899-front",
            "psbug-749cf899-secret",
            "psbug-749cf899-api",
        ] {
            assert!(
                out.contains(whole),
                "the table cut '{whole}' down to a prefix its neighbours share:\n{out}"
            );
        }
        // AND THE COLUMNS LINE UP. Anchored on the LAST column rather than on the pid: every field
        // between them is fixed-width, so if STATUS starts at one offset for every row then so does
        // everything before it. Searching for the pid digits instead was the first attempt and it
        // matched a digit inside the NAME (`psbug-749cf899-…`), which made the test fail on a table
        // that was correctly aligned.
        // CHARACTER OFFSETS AND NOT BYTE OFFSETS. The selection marker is `\u{203a}`, three bytes and
        // one column, so `str::find` reported the selected row two further right than the others and
        // failed a table that was correctly aligned. What a reader sees is columns, so columns are
        // what this counts.
        let offsets: Vec<usize> = out
            .lines()
            .filter(|l| l.contains("psbug-"))
            .filter_map(|l| l.find("running").map(|byte| l[..byte].chars().count()))
            .collect();
        assert_eq!(offsets.len(), 3, "three rows carry a status:\n{out}");
        assert!(
            offsets.iter().all(|o| *o == offsets[0]),
            "the STATUS column starts at {offsets:?}, which is not one column:\n{out}"
        );

        // THE CONTROL: short names keep the layout they have always had, sixteen wide.
        let short = vec![row("a", "", 201), row("b", "", 202)];
        let out = boxes_table(&p, &short, 10, 0, &host);
        let header = out
            .lines()
            .find(|l| l.contains("NAME"))
            .unwrap_or_default()
            .to_string();
        let name_at = header.find("NAME").unwrap_or(0);
        let pid_at = header.find("PID").unwrap_or(0);
        // 16 for the NAME cell, two spaces, then `PID` right-aligned in a seven-wide field, so its
        // `P` sits four in: 16 + 2 + 4. Written as the arithmetic rather than as `22` so a change to
        // any of the three is readable here instead of being a number nobody can check.
        assert_eq!(
            pid_at - name_at,
            16 + 2 + 4,
            "a table of short names must lay out exactly as it always has: {header:?}"
        );
    }

    fn press(key: &[u8], rows: &[Row], sel_in: usize) -> (Mode, usize, bool) {
        let mut tab = TAB_BOXES;
        let mut sel = sel_in;
        let mut mode = Mode::Nav;
        let dirty = handle_nav(
            key,
            &mut tab,
            &mut sel,
            rows.len(),
            rows,
            &[],
            &[],
            &[],
            &[],
            &crate::config::KernConfig::default(),
            &mut mode,
        );
        (mode, sel, dirty)
    }

    /// `k` MOVES THE SELECTION UP. IT DOES NOT ACT ON THE BOX.
    ///
    /// Reported from the field (getkern/kern#3): "the `hjkl` navigation half-works in top TUI mode
    /// but has conflicting keys on some screens (`k` kills the box!)". `j` was bound to `down` in
    /// the navigation match and `k` was bound to nothing, so it fell through to the Boxes tab's
    /// lifecycle keys and stopped the selected box.
    ///
    /// The pair is asserted together, because half of a vi pair working is exactly the shape that
    /// makes the other half a surprise.
    #[test]
    fn k_selects_up_and_never_acts_on_the_box() {
        let rows = [row("a", false), row("b", false), row("c", false)];

        // Down, then back up: the selection returns to where it started, and nothing was acted on.
        let (mode, sel, dirty) = press(b"j", &rows, 0);
        assert_eq!(sel, 1, "`j` moves down");
        assert!(matches!(mode, Mode::Nav), "`j` opens nothing");
        assert!(!dirty, "`j` changes no box state");

        let (mode, sel, dirty) = press(b"k", &rows, 1);
        assert_eq!(
            sel, 0,
            "`k` moves up, which is what the help has always promised"
        );
        assert!(
            matches!(mode, Mode::Nav),
            "`k` must not open a confirmation either: it is navigation, not an action"
        );
        assert!(
            !dirty,
            "`k` reported a state change, which means it acted on the box"
        );

        // At the top, `k` stays put rather than wrapping onto the last row, where a later action
        // key would land somewhere the user did not look at.
        let (_, sel, _) = press(b"k", &rows, 0);
        assert_eq!(sel, 0, "`k` at the top does not wrap");
    }

    /// STOPPING A BOX ASKS FIRST, and it did not.
    ///
    /// Deleting a profile - a line of `kern.toml` - already opened a `(y/n)` prompt, while stopping
    /// a running box executed on the keystroke. The confirmation was inversely proportional to the
    /// cost of the action.
    #[test]
    fn stopping_a_box_opens_a_confirmation_naming_it() {
        let rows = [row("alpha", false), row("beta", false)];
        let (mode, sel, dirty) = press(b"s", &rows, 1);
        assert_eq!(sel, 1, "the confirmation must not move the selection");
        assert!(
            !dirty,
            "nothing has happened yet, so the caller must not re-read the list"
        );
        match mode {
            Mode::Confirm { prompt, action } => {
                assert!(
                    prompt.contains("beta"),
                    "the prompt must name the box being stopped, got {prompt:?}"
                );
                assert!(
                    matches!(action, Pending::StopBox(ref n) if n == "beta"),
                    "the pending action must target the SELECTED box"
                );
            }
            Mode::Nav => panic!("`s` acted immediately instead of asking"),
            _ => panic!("`s` must open a confirmation, and opened something else"),
        }
    }

    /// THE HELP AND THE FOOTER MAY NOT PROMISE A KEY THE CODE DOES NOT HONOUR.
    ///
    /// This is the defect underneath the report rather than the keystroke itself: the help overlay
    /// listed `↑ ↓ / j k  select a row` AND `k  kill` at the same time, and the footer advertised
    /// `[k]ill`. The product documented vi navigation and delivered a destructive action on half of
    /// it. `k` was also not a kill: it called the same graceful `stop` as `s`, so the word was wrong
    /// twice over.
    ///
    /// Asserted against the real strings, so the two cannot drift apart again in silence.
    /// The drawn window FOLLOWS the selection, so every row of a long list is reachable.
    ///
    /// 🔴 EVERY LIST PANE SLICED FROM ZERO. `images[..max_rows]` drew the first screenful and nothing
    /// else: the selection walked past the last drawn row, the cursor left the screen, and the rest
    /// of the list could not be reached by any key. Measured on a host with 309 cached images -
    /// `kern top` showed 25 and `… 284 more`, forever.
    ///
    /// Asserted over the WHOLE range rather than at a few points, because the defect is precisely
    /// "some selections are not covered", and a spot check picks the ones that are.
    #[test]
    fn the_list_window_keeps_every_selection_on_screen() {
        for len in [1usize, 5, 25, 26, 309] {
            for max_rows in [1usize, 5, 25] {
                for sel in 0..len {
                    let (start, end) = list_window(len, max_rows, sel);
                    assert!(
                        start <= sel && sel < end,
                        "len={len} max_rows={max_rows} sel={sel}: window {start}..{end} hides the selection"
                    );
                    assert!(
                        end <= len,
                        "window {start}..{end} runs past the list of {len}"
                    );
                    assert!(
                        end - start <= max_rows,
                        "window {start}..{end} is taller than the {max_rows} rows available"
                    );
                    // The last row must be reachable: at the bottom the window ends AT the end.
                    if sel + 1 == len {
                        assert_eq!(end, len, "the last row is not reachable at sel={sel}");
                    }
                }
            }
        }
    }

    /// The marker names BOTH directions, and costs exactly one line.
    ///
    /// One line is a hard constraint, not a preference: the frame budget reserves a single row for
    /// it, and a second marker line would push a full tab one row past the terminal - which scrolls
    /// the alternate screen and carries the tab bar off the top. The invariant test next door
    /// catches that, so this one states WHY the marker is shaped this way.
    #[test]
    fn the_list_marker_is_one_line_and_names_both_directions() {
        let p = plain();
        assert_eq!(
            list_marker(&p, 10, 0, 10),
            "",
            "nothing hidden, nothing said"
        );
        let mid = list_marker(&p, 309, 76, 101);
        assert_eq!(
            mid.lines().count(),
            1,
            "the marker must fit one line: {mid:?}"
        );
        assert!(mid.contains("76"), "it must say what is above: {mid}");
        assert!(mid.contains("208"), "and what is below: {mid}");
        let top = list_marker(&p, 309, 0, 25);
        assert!(
            top.contains("284") && !top.contains("above"),
            "at the top only below: {top}"
        );
        let bottom = list_marker(&p, 309, 284, 309);
        assert!(
            bottom.contains("284") && !bottom.contains("below"),
            "at the bottom only above: {bottom}"
        );
    }

    /// A shifted key asks before acting on the whole tab, and its prompt carries the COUNT.
    ///
    /// The count is the point. "delete all?" tells an operator nothing about the blast radius of the
    /// key they are one keystroke from confirming; "delete ALL 309 cached image(s)?" does. Every bulk
    /// key is checked for both properties - that it ARMS a confirmation rather than acting, and that
    /// the prompt names how many.
    #[test]
    fn a_bulk_key_asks_first_and_its_prompt_names_how_many() {
        let imgs: Vec<crate::commands::ImageEntry> = (0..7)
            .map(|i| crate::commands::ImageEntry {
                name: format!("img{i}:latest"),
                size: 1,
                pulled: 0,
                dangling: false,
                platform: None,
                stem: String::new(),
            })
            .collect();
        let mut mode = Mode::Nav;
        nav_images(b'D', 0, &imgs, &mut mode);
        match &mode {
            Mode::Confirm { prompt, action } => {
                assert!(
                    prompt.contains('7'),
                    "the prompt must name the count: {prompt}"
                );
                assert!(
                    matches!(action, Pending::RemoveAllImages(v) if v.len() == 7),
                    "the action must carry the seven targets that were on screen"
                );
            }
            _ => panic!("`D` on Images must arm a confirmation, not act"),
        }

        // An empty tab has nothing to confirm: the key does nothing rather than prompting about zero.
        let mut mode = Mode::Nav;
        nav_images(b'D', 0, &[], &mut mode);
        assert!(
            matches!(mode, Mode::Nav),
            "`D` on an empty tab must not prompt"
        );

        // Boxes: the bulk verb is STOP, and it asks too.
        let rows = vec![row("a", false), row("b", false)];
        let mut mode = Mode::Nav;
        nav_boxes(b'S', 0, &rows, &mut mode);
        match &mode {
            Mode::Confirm { prompt, action } => {
                assert!(
                    prompt.contains('2'),
                    "the stop-all prompt names the count: {prompt}"
                );
                assert!(matches!(action, Pending::StopAllBoxes(v) if v.len() == 2));
            }
            _ => panic!("`S` on Boxes must arm a confirmation"),
        }
    }

    #[test]
    fn the_help_and_footer_describe_the_keys_that_actually_exist() {
        let help = help_text();
        assert!(
            help.contains("j k  select a row"),
            "the help must keep promising vi selection: {help}"
        );
        assert!(
            !help.contains("k  kill"),
            "the help must not also bind `k` to a destructive action"
        );
        assert!(
            help.contains("stop (asks first)"),
            "a destructive key that asks must say so where the user reads the keys"
        );
        // The residue of the same defect: the summary line at the bottom of the help still listed
        // `kill` among the destructive actions long after the key was gone, so the overlay named an
        // action the TUI does not have. The word may not appear at all: there is no kill here.
        assert!(
            !help.contains("kill"),
            "the help may not name a `kill` action the TUI does not offer: {help}"
        );

        let footer = nav_footer(&plain(), TAB_BOXES, &[row("x", false)], &[], &[], &[], &[]);
        assert!(
            !footer.contains("ill"),
            "the footer must not advertise a kill key that is neither bound nor a kill: {footer}"
        );
        assert!(
            footer.contains("top"),
            "the footer still offers stop: {footer}"
        );

        // AND THE PROMISE IS TRUE, not merely present: pressing what the help lists must select.
        // A text assertion alone would stay green if the binding were removed again.
        let rows = [row("a", false), row("b", false)];
        assert_eq!(press(b"j", &rows, 0).1, 1);
        assert_eq!(press(b"k", &rows, 1).1, 0);
    }

    /// THE SELECTION MARKER SITS ON THE SELECTED ROW, AND ON NO OTHER.
    ///
    /// A mutation sweep turned `sel_marker(p, i == sel)` into `i != sel` and all 920 tests stayed
    /// green: the marker would move onto every row EXCEPT the selected one, so a destructive key
    /// would act on a box the user is not looking at. That is the same failure the `k` binding had -
    /// an action landing somewhere the eye is not - reached from the rendering side instead.
    ///
    /// `plain()` has empty colour codes, so the marker is the only thing distinguishing the rows and
    /// the assertion cannot pass on a stray escape sequence.
    #[test]
    fn the_selection_marker_is_on_the_selected_row_and_no_other() {
        let prof = |n: &str| ProfRow {
            section: "vcpu",
            name: n.to_string(),
            summary: String::new(),
        };
        let rows = [prof("alpha"), prof("beta"), prof("gamma")];

        for sel in 0..rows.len() {
            let table = profiles_table(&plain(), &rows, 10, sel);
            // Only the PROFILE rows. The pane also renders section headers, a "none yet"
            // placeholder per empty kind, and a hint line that itself contains `vcpu:heavy` - so
            // filtering on the prefix would catch four lines and the count assertion below would
            // have failed for the wrong reason. Filter on the names this case created.
            let names = ["alpha", "beta", "gamma"];
            let lines: Vec<&str> = table
                .lines()
                .filter(|l| names.iter().any(|n| l.contains(n)))
                .collect();
            assert_eq!(
                lines.len(),
                rows.len(),
                "one line per profile, and the filter must not be catching the hint line: {table:?}"
            );
            for (i, line) in lines.iter().enumerate() {
                // `sel_marker` emits "› " for the selected row and two spaces for the others.
                let marked = line.contains('›');
                assert_eq!(
                    marked,
                    i == sel,
                    "sel={sel}: row {i} ({}) marked={marked}, which puts the cursor where the user \
                     is not looking",
                    lines[i].trim()
                );
            }
        }
    }

    #[test]
    fn question_mark_opens_help_and_footer_advertises_it() {
        // `?` from any tab opens the help overlay (discoverable safety net).
        let mut tab = TAB_BOXES;
        let mut sel = 0;
        let mut mode = Mode::Nav;
        handle_nav(
            b"?",
            &mut tab,
            &mut sel,
            0,
            &[],
            &[],
            &[],
            &[],
            &[],
            &crate::config::KernConfig::default(),
            &mut mode,
        );
        assert!(
            matches!(mode, Mode::Overlay(_)),
            "`?` must open the help overlay"
        );
        if let Mode::Overlay(t) = &mode {
            assert!(t.contains("keyboard help"), "overlay is the help text");
            assert!(
                t.contains("Overview") && t.contains("Boxes"),
                "help explains the tabs"
            );
        }
        // Every footer advertises `?` so a first-time user knows it exists.
        for t in [TAB_OVERVIEW, TAB_BOXES, TAB_PROFILES, TAB_STORAGE] {
            let f = nav_footer(&plain(), t, &[row("x", false)], &[], &[], &[], &[]);
            assert!(
                f.contains("?] help"),
                "footer for tab {t} must advertise [?] help"
            );
        }
    }

    #[test]
    fn out_of_range_selection_highlights_nothing() {
        let rows = [row("web", false)];
        let out = boxes_table(&plain(), &rows, 10, usize::MAX, &HostStats::default()); // snapshot mode
        assert!(!out.contains('›'));
    }

    #[test]
    fn negative_zero_cpu_renders_as_zero() {
        let mut rows = [row("web", false)];
        rows[0].cpu_pct = -0.0;
        let out = boxes_table(&plain(), &rows, 10, usize::MAX, &HostStats::default());
        assert!(out.contains("0%"), "cpu% should render 0");
        assert!(!out.contains("-0"), "a stray -0.0 must be normalised to 0");
    }

    #[test]
    fn text_pane_titles_strips_control_bytes_and_tails() {
        // First line is the (bold) title; the body is sanitized and tail-clipped to the pane.
        let text = "logs: web\nl1\nl2\x1b[2J\x07\nl3\nl4\nl5";
        let out = text_pane(&plain(), text, 5, 40); // take = 3 body lines
        assert!(out.contains("logs: web"), "title shown");
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\x07'));
        assert!(out.contains("l5"));
        assert!(!out.contains("l1"), "old lines beyond the tail are dropped");
    }

    /// A text field pre-filled with a value (test helper).
    fn tf(label: &'static str, value: &str) -> Field {
        let mut f = Field::text(label, "");
        f.value = value.into();
        f
    }

    #[test]
    fn form_body_serialises_and_validates() {
        let fields = vec![
            tf("name", "heavy"),
            tf("cpus", "4"),
            tf("cpuset", "0-3"),
            tf("memory", ""), // empty → skipped
            tf("nice", "10"),
        ];
        let (name, body) = form_to_body(&fields).unwrap();
        assert_eq!(name, "heavy");
        assert!(body.contains(&"name = \"heavy\"".to_string()));
        assert!(body.contains(&"cpus = 4".to_string()));
        assert!(body.contains(&"cpuset = \"0-3\"".to_string()));
        assert!(body.contains(&"nice = 10".to_string()));
        assert!(
            !body.iter().any(|l| l.starts_with("memory")),
            "empty field skipped"
        );

        // A bad number is rejected with a message, not silently written.
        let bad = vec![tf("name", "x"), tf("cpus", "abc")];
        assert!(form_to_body(&bad).is_err());

        // A missing name is rejected.
        let noname = vec![tf("name", "  ")];
        assert!(form_to_body(&noname).is_err());
    }

    #[test]
    fn persistent_is_a_toggle_not_free_text() {
        let _g = crate::env_guard();
        // Space flips it; typing letters never lands in it; on → `persistent = true`, off → omitted.
        let mut form = new_profile_form("vdisk");
        set_field(&mut form.fields, "name", "scratch".into()); // form_to_body needs a name
        let pi = form
            .fields
            .iter()
            .position(|f| f.label == "persistent")
            .unwrap();
        assert!(form.fields[pi].toggle, "persistent must be a toggle");
        form.active = pi;
        // A letter does NOT type into a toggle.
        form = match handle_form_key(form, b"x") {
            FormOutcome::Stay(f) => f,
            _ => panic!(),
        };
        assert_eq!(form.fields[pi].value, "", "typing must not fill a toggle");
        // Space turns it on.
        form = match handle_form_key(form, b" ") {
            FormOutcome::Stay(f) => f,
            _ => panic!(),
        };
        assert_eq!(form.fields[pi].value, "yes");
        let (_n, body) = form_to_body(&form.fields).unwrap();
        assert!(
            body.iter().any(|l| l == "persistent = true"),
            "on → persistent = true: {body:?}"
        );
        // Space again turns it off → the key is omitted (cleared).
        form = match handle_form_key(form, b" ") {
            FormOutcome::Stay(f) => f,
            _ => panic!(),
        };
        assert_eq!(form.fields[pi].value, "");
        let (_n, body2) = form_to_body(&form.fields).unwrap();
        assert!(!body2.iter().any(|l| l.starts_with("persistent")));
    }

    #[test]
    fn bytes_to_size_str_is_exact_and_reparseable() {
        // Pre-fill values for the volume-edit form must round-trip through config::size_to_bytes.
        for (bytes, want) in [
            (2 * 1024 * 1024 * 1024, "2g"),
            (512 * 1024 * 1024, "512m"),
            (4 * 1024, "4k"),
            (1, "1"),
            (0, "0"),
        ] {
            let s = bytes_to_size_str(bytes);
            assert_eq!(s, want);
            if bytes > 0 {
                assert_eq!(crate::config::size_to_bytes(&s), Some(bytes), "reparse {s}");
            }
        }
    }

    #[test]
    fn tui_form_and_config_add_emit_the_same_block() {
        // The Profiles form and `kern config add` must produce byte-identical kern.toml: both go
        // through config::profile_block. This pins that the two paths can never drift.
        let fields = vec![
            tf("name", "heavy"),
            tf("cpus", "4"),
            tf("cpuset", "0-3"),
            tf("memory", "512m"),
            tf("nice", "10"),
        ];
        let (_name, from_form) = form_to_body(&fields).unwrap();
        let from_cli = crate::config::profile_block(
            "heavy",
            &[
                ("cpus", "4"),
                ("cpuset", "0-3"),
                ("memory", "512m"),
                ("nice", "10"),
            ],
        )
        .unwrap();
        assert_eq!(from_form, from_cli);
    }

    #[test]
    fn edit_form_round_trips_every_field_losslessly() {
        let _g = crate::env_guard();
        // A profile hand-written with the full field set, loaded into the edit form and re-serialised,
        // must reproduce every field - no CLI-only / hand-edit-only field is dropped by an edit cycle.
        let raw = "\
[[vgpio]]
name = \"full\"
backend = \"gpio:0\"
pins = [17, 27]
pwm = [12]
i2c = [\"/dev/i2c-1\", \"/dev/i2c-2\"]
spi = [\"/dev/spidev0.0\"]
leds = [\"led0\"]
";
        let cfg = crate::config::parse(raw).unwrap();
        let form = edit_profile_form("vgpio", "full", &cfg);
        let (name, body) = form_to_body(&form.fields).unwrap();
        assert_eq!(name, "full");
        for expect in [
            "backend = \"gpio:0\"",
            "pins = [17, 27]",
            "pwm = [12]",
            "i2c = [\"/dev/i2c-1\", \"/dev/i2c-2\"]",
            "spi = [\"/dev/spidev0.0\"]",
            "leds = [\"led0\"]",
        ] {
            assert!(
                body.iter().any(|l| l == expect),
                "lost/changed on edit round-trip: {expect}\n got {body:?}"
            );
        }

        // Same for a vcpu carrying its advanced fields.
        let cfg2 = crate::config::parse(
            "[[vcpu]]\nname=\"h\"\ncpus=4\nnuma=1\nnice=-5\nextends=\"base\"\n",
        )
        .unwrap();
        let (_n, b2) = form_to_body(&edit_profile_form("vcpu", "h", &cfg2).fields).unwrap();
        for e in ["cpus = 4", "numa = 1", "nice = -5", "extends = \"base\""] {
            assert!(b2.iter().any(|l| l == e), "vcpu lost {e}: {b2:?}");
        }
    }

    #[test]
    fn active_field_cursor_sits_at_the_insertion_point() {
        let _g = crate::env_guard();
        let p = plain();
        let mut form = new_profile_form("vcpu");
        // Empty active field: cursor is immediately before the placeholder ("▏e.g. heavy").
        let out = form_pane(&p, &form, 80, 24);
        let name_line = out.lines().find(|l| l.contains("name")).unwrap();
        assert!(name_line.contains("▏"), "active field shows a cursor");
        let ci = name_line.find('▏').unwrap();
        let hi = name_line.find("e.g. heavy").unwrap();
        assert!(ci < hi, "cursor precedes the placeholder when empty");
        // Typed value: cursor sits right AFTER the value, not at the far right.
        form.fields[0].value = "heavy".into();
        let out2 = form_pane(&p, &form, 80, 24);
        let l2 = out2.lines().find(|l| l.contains("name")).unwrap();
        let vi = l2.find("heavy").unwrap();
        let cu = l2.find('▏').unwrap();
        assert!(
            cu > vi && cu <= vi + "heavy".len() + 1,
            "cursor follows the value"
        );
    }

    #[test]
    fn pick_field_space_checks_and_assembles_value() {
        // A pick field is driven ENTIRELY by the keyboard: →/← move the highlight, Space checks.
        // Typing must never land in it (the whole point is "impossible to enter a wrong path").
        let mut f = Field::pick(
            "i2c",
            "pick",
            vec![
                "/dev/i2c-0".into(),
                "/dev/i2c-1".into(),
                "/dev/i2c-2".into(),
            ],
        );
        assert!(f.is_pick());
        let mut form = Form {
            title: "t".into(),
            fields: vec![f.clone()],
            active: 0,
            submit: Submit::SaveProfile {
                section: "vgpio",
                orig_name: None,
            },
            error: None,
            show_advanced: false,
        };
        // Check option 0, move right twice, check option 2 → value is the two checked paths, in order.
        let feed = |form: Form, k: &[u8]| match handle_form_key(form, k) {
            FormOutcome::Stay(f) => f,
            _ => panic!("pick nav should stay in the form"),
        };
        form = feed(form, b" "); // check i2c-0
        form = feed(form, b"\x1b[C"); // →
        form = feed(form, b"\x1b[C"); // →  (now on i2c-2)
        form = feed(form, b" "); // check i2c-2
        assert_eq!(form.fields[0].value, "/dev/i2c-0,/dev/i2c-2");
        // A stray letter is ignored, not typed into the value.
        form = feed(form, b"x");
        assert_eq!(form.fields[0].value, "/dev/i2c-0,/dev/i2c-2");

        // The pane renders the checked boxes as `[✓]` and the device names (no free-text box).
        let pane = form_pane(&plain(), &form, 80, 24);
        assert!(
            pane.contains("[✓]"),
            "checked options render as ticks:\n{pane}"
        );
        assert!(
            pane.contains("/dev/i2c-0"),
            "device names are shown:\n{pane}"
        );

        // seed_pick_selection re-checks the boxes matching a pre-filled value (edit path).
        f.value = "/dev/i2c-1".into();
        f.seed_pick_selection();
        assert_eq!(f.sel, vec![false, true, false]);
        assert_eq!(f.value, "/dev/i2c-1");
    }

    #[test]
    fn i2c_bare_value_does_not_duplicate_a_detected_bus() {
        // A profile saved with a BARE i2c bus ("1", the form the CLI writes) must tick the detected
        // "/dev/i2c-1" instead of appending a second checkbox for the same physical bus.
        let mut f = Field::pick("i2c", "h", vec!["/dev/i2c-0".into(), "/dev/i2c-1".into()]);
        f.value = "1".into(); // bare form, as `kern config add ... i2c=1` stores it
        f.seed_pick_selection();
        assert_eq!(f.options.len(), 2, "no duplicate option was appended");
        assert_eq!(f.sel, vec![false, true], "the detected bus is ticked");
        assert_eq!(
            f.value, "/dev/i2c-1",
            "value canonicalizes to the /dev path"
        );
        // A bus NOT detected here is still kept (canonicalized) as a checked extra - lossless.
        let mut g = Field::pick("i2c", "h", vec!["/dev/i2c-0".into()]);
        g.value = "i2c-0, 9".into();
        g.seed_pick_selection();
        assert_eq!(g.options, vec!["/dev/i2c-0", "/dev/i2c-9"]);
        assert_eq!(g.sel, vec![true, true]);
    }

    #[test]
    fn vgpio_form_does_not_offer_net_a_field_the_resolver_ignores() {
        let _g = crate::env_guard();
        // `net` in a vgpio profile is inert (the resolver never attaches an interface), so the form
        // must not advertise it - offering a knob that does nothing is exactly the "misleading" trap.
        let form = new_profile_form("vgpio");
        assert!(
            !form.fields.iter().any(|f| f.label == "net"),
            "net must not be a vgpio form field"
        );
        assert!(
            field_help("vgpio", "net").is_none(),
            "no help entry for net"
        );
    }

    #[test]
    fn vgpio_form_hides_rare_fields_until_advanced_is_opened() {
        let _g = crate::env_guard();
        // A new vgpio form is short: the rare knob `backend` (pre-filled to gpio:0) lives under the
        // collapsed Advanced fold, so a beginner doesn't see it at all until they ask.
        let mut form = new_profile_form("vgpio");
        assert!(!form.show_advanced, "advanced starts collapsed");
        assert!(
            form.fields.iter().any(|f| f.divider),
            "there is an Advanced fold row"
        );
        let collapsed = form_pane(&plain(), &form, 80, 40);
        assert!(collapsed.contains("Advanced"), "the fold is advertised");
        assert!(
            collapsed.contains("Give the box real hardware"),
            "a plain-language explainer guides the user:\n{collapsed}"
        );
        assert!(
            !collapsed.contains("backend"),
            "a collapsed advanced field is hidden:\n{collapsed}"
        );
        // Focus the fold and press Space → it opens and the advanced fields appear.
        let div = form.fields.iter().position(|f| f.divider).unwrap();
        form.active = div;
        form = match handle_form_key(form, b" ") {
            FormOutcome::Stay(f) => f,
            _ => panic!("space on the fold should stay in the form"),
        };
        assert!(form.show_advanced, "Space opened the fold");
        let opened = form_pane(&plain(), &form, 80, 40);
        assert!(
            opened.contains("backend"),
            "advanced fields show once opened:\n{opened}"
        );
    }

    #[test]
    fn leds_picker_drops_netdev_and_input_noise_keeps_board_leds() {
        let nets = vec!["enp5s0".to_string(), "lo".to_string(), "wlp4s0".to_string()];
        // Noise: NIC PHY LEDs and keyboard LEDs - never a meaningful sandbox device.
        for noise in [
            "enp5s0-0::lan",
            "enp5s0::act",
            "wlp4s0-1::wlan",
            "input3::capslock",
        ] {
            assert!(!is_board_led(noise, &nets), "{noise} should be dropped");
        }
        // Real board LEDs - kept. 'logo' starts with 'lo' but isn't the 'lo' iface → kept.
        for led in ["led0", "ACT", "PWR", "mmc0::activity", "default-on", "logo"] {
            assert!(is_board_led(led, &nets), "{led} should be kept");
        }
    }

    #[test]
    fn every_profile_field_is_guarded_for_all_kinds() {
        let _g = crate::env_guard();
        // EXTREME, for all vprofiles: no field in ANY profile form is unguarded free text. Each field
        // is validated by the field_state authority (numbers / name / sizes), a picker/radio selection,
        // a boolean toggle, or a "none here / explanatory" note - with ONE documented exception, the
        // free-form `extra` /dev-path escape (guarded downstream by the resolver). If a new field is
        // added as free text, this fails.
        for kind in ["vcpu", "vgpio", "vdisk"] {
            for f in section_fields(kind) {
                if f.divider {
                    continue;
                }
                let guarded = f.is_pick()            // detected-device pick / backend radio
                    || f.toggle                       // a boolean
                    || f.info                         // a "none on this host" / explanatory note
                    || validated_field(f.label); // field_state governs it (numbers/name/size/extra path)
                assert!(
                    guarded,
                    "{kind} field {:?} is UNGUARDED free text - make it validated / a pick / a note",
                    f.label
                );
            }
        }
    }

    #[test]
    fn backend_is_a_selection_never_a_free_text_box() {
        let _g = crate::env_guard();
        // `backend` names a configured id (gpio/cpu/disk) - so for EVERY kind it must be a picker of
        // those ids (or a "none configured" note), never a free-text box where `disk:0sfsf…` could be
        // typed. Regression: vcpu/vdisk backend used to be free text.
        for kind in ["vgpio", "vcpu", "vdisk"] {
            let fields = section_fields(kind);
            let backend = fields.iter().find(|f| f.label == "backend").unwrap();
            assert!(
                backend.is_pick() || backend.info,
                "{kind} backend must be a picker or a note, not free text"
            );
        }
    }

    #[test]
    fn focused_field_gets_a_plain_language_help_line() {
        let _g = crate::env_guard();
        // Whatever field is focused, the form shows a concrete "what is this / when to use it" line at
        // the bottom - the user is guided, never left guessing what to enter.
        let mut form = new_profile_form("vgpio");
        // Focus the name field: help explains it's a label + how to attach it.
        assert_eq!(form.fields[0].label, "name");
        let pane = form_pane(&plain(), &form, 80, 40);
        assert!(
            pane.contains("❔") && pane.contains("vgpio:NAME"),
            "name field is explained:\n{pane}"
        );
        // Focus a pick (a detected bus) → its help + example shows.
        if let Some(i) = form.fields.iter().position(|f| f.is_pick()) {
            form.active = i;
            let label = form.fields[i].label;
            let pane = form_pane(&plain(), &form, 80, 40);
            let help = field_help("vgpio", label).unwrap();
            assert!(pane.contains(help), "help for {label} shows:\n{pane}");
        }
    }

    /// Type an arbitrary byte string into a field through the REAL key handler, returning the value it
    /// ended up holding (Enter keeps it, Esc stops early). Used by the extreme fuzz below.
    fn type_into(section: &'static str, label: &'static str, input: &[u8]) -> String {
        let mut form = Form {
            title: "t".into(),
            fields: vec![Field::text(label, "")],
            active: 0,
            submit: Submit::SaveProfile {
                section,
                orig_name: None,
            },
            error: None,
            show_advanced: false,
        };
        for &b in input {
            match handle_form_key(form, &[b]) {
                FormOutcome::Stay(f) | FormOutcome::Submit(f) => form = f,
                FormOutcome::Cancel => return String::new(), // Esc aborts - nothing typed
            }
        }
        form.fields.into_iter().next().unwrap().value
    }

    #[test]
    fn extreme_typing_never_reaches_an_invalid_or_unsavable_value() {
        // Hammer every typed numeric/size field with adversarial byte strings and assert two things:
        //  (1) the accumulated value is NEVER config::field_state == Invalid (the filter never lets a
        //      dead value stick), and
        //  (2) whenever it IS Valid, config::profile_line accepts it - no value can dead-end at save.
        use crate::config::{field_state, profile_line, FieldState};
        let fields: &[(&str, &str)] = &[
            ("vgpio", "pins"),
            ("vgpio", "pwm"),
            ("vgpio", "adc"),
            ("vgpio", "onewire"),
            ("vcpu", "numa"),
            ("vcpu", "nice"),
            ("vcpu", "cpus"),
            ("vcpu", "cpuset"),
            ("vcpu", "memory"),
            ("vdisk", "size"),
            ("vdisk", "bandwidth"),
            ("vdisk", "iops"),
            ("vgpio", "name"), // name/extends now route through field_state too (round-4 fix)
            ("vcpu", "extends"),
        ];
        let nines = "9".repeat(200);
        let inputs: &[&str] = &[
            "",
            "0",
            "1",
            "17 27",
            "0-3",
            "512m",
            "2g",
            "16t",
            "-20",
            "0.5",
            "1.5",
            "1.5g",
            ".5g",
            "44545454545",
            "999999999999999999999999999",
            "100",
            "-25",
            "1.2.3.4",
            "----",
            "0-0-0-0",
            "512mmm",
            "5m2",
            "abcdef",
            "0x1F",
            "  ",
            " 1 2 ",
            ",,,",
            "1,,2",
            "17,,27",
            "٠١٢",    // arabic-indic digits (multibyte)
            "１２３", // fullwidth digits (multibyte)
            "1e9",
            "nan",
            "inf",
            "-0",
            "00",
            "1 2 3 4 5",
            &nines,
            "g",
            "m",
            ".",
            "-.-",
            "\t\n\r",
            "1\0",
            "２0",
            "0-",
            "-",
            "2ggg",
            "999t",     // overflows when multiplied
            "-lead",    // name: leading dash (unfixable)
            ".hidden",  // name: leading dot
            "a..b",     // name: traversal
            "a/b",      // name: slash (never allowed)
            "a:b",      // name: colon
            "My_Box-2", // name: valid identifier
        ];
        for &(section, label) in fields {
            for input in inputs {
                let v = type_into(section, label, input.as_bytes());
                assert_ne!(
                    field_state(label, &v),
                    FieldState::Invalid,
                    "typing {input:?} into {section}:{label} left an INVALID value {v:?}"
                );
                if !v.is_empty() && field_state(label, &v) == FieldState::Valid {
                    // The value the filter allowed must be accepted by its SAVE authority.
                    let saves = if matches!(label, "name" | "extends") {
                        crate::config::validate_profile_name(&v).is_ok()
                    } else {
                        profile_line(label, &v).unwrap().is_some()
                    };
                    assert!(
                        saves,
                        "a Valid typed value must save: {label}={v:?} (from {input:?})"
                    );
                }
            }
        }
    }

    #[test]
    fn extreme_valid_values_type_through_unblocked() {
        // The other direction: a legitimate value must be typable in full (no false blocking).
        use crate::config::{field_state, FieldState};
        for (label, good) in [
            ("pins", "17 27 22"),
            ("pwm", "12,13"),
            ("numa", "3"),
            ("nice", "-20"),
            ("nice", "19"),
            ("cpus", "0.5"),
            ("cpus", "16"),
            ("cpuset", "0-3"),
            ("cpuset", "0,2,4"),
            ("memory", "512m"),
            ("size", "16t"),
            ("iops", "5000"),
        ] {
            let v = type_into("vcpu", label, good.as_bytes());
            assert_eq!(v, good, "'{good}' must type through {label} intact");
            assert_eq!(
                field_state(label, &v),
                FieldState::Valid,
                "{label}={good} is valid"
            );
        }
    }

    #[test]
    fn active_numeric_field_shows_a_three_state_indicator() {
        let mk = |label: &'static str| Form {
            title: "t".into(),
            fields: vec![Field::text(label, "")],
            active: 0,
            submit: Submit::SaveProfile {
                section: "vcpu",
                orig_name: None,
            },
            error: None,
            show_advanced: false,
        };
        let feed = |mut form: Form, bytes: &[u8]| {
            for &b in bytes {
                form = match handle_form_key(form, &[b]) {
                    FormOutcome::Stay(f) => f,
                    _ => panic!("stays"),
                };
            }
            form
        };
        // cpus "0" is an incomplete prefix (of "0.5") → "keep typing", not a green tick.
        let form = feed(mk("cpus"), b"0");
        let pane = form_pane(&plain(), &form, 80, 24);
        assert!(
            pane.contains("keep typing"),
            "incomplete shows a hint:\n{pane}"
        );
        // "0.5" is complete → a ✓.
        let form = feed(mk("cpus"), b"0.5");
        let pane = form_pane(&plain(), &form, 80, 24);
        assert!(pane.contains('✓'), "valid shows a tick:\n{pane}");
    }

    /// A NEW profile form arrives with the sentinel already picked, so filling the visible fields
    /// and pressing Enter SAVES instead of answering with an error about a field the form never
    /// showed. `backend` lives inside the Advanced fold, below every detected-device row, so on a
    /// board with real hardware it is further down the more hardware the host has - measured on a
    /// Jetson (seven i2c buses, four spi ports, four uarts) against a Pi 5 (no i2c nodes at all).
    ///
    /// The value is still written EXPLICITLY into the file: the 0.6.11 rule (no profile ever binds
    /// to an implicit default) is about what the FILE says, and it still says it.
    #[test]
    fn a_new_profile_form_arrives_with_the_backend_sentinel_already_picked() {
        let _g = crate::env_guard();
        for (kind, sentinel) in [("vcpu", "host"), ("vgpio", "host"), ("vdisk", "ram")] {
            let form = new_profile_form(kind);
            let f = form
                .fields
                .iter()
                .find(|f| f.label == "backend")
                .unwrap_or_else(|| panic!("{kind}: no backend field"));
            assert_eq!(f.value, sentinel, "{kind}: sentinel must be pre-picked");
            assert_eq!(
                f.sel.iter().filter(|s| **s).count(),
                1,
                "{kind}: exactly one backend, never two"
            );
            assert!(
                f.sel.first().copied().unwrap_or(false),
                "{kind}: the pre-picked one must be the sentinel, which is listed first"
            );
        }
    }

    #[test]
    fn backend_field_is_required_and_offers_the_sentinel_first() {
        let _g = crate::env_guard();
        // `backend` is MANDATORY on every profile kind. Its `kern top` form field is a single-select
        // radio (never free text), lists the reserved sentinel FIRST (host for vcpu/vgpio, ram for
        // vdisk) so a profile can bind to the whole host with no physical block declared, is never an
        // empty "info" dead-end, and its hint says "required".
        for (kind, sentinel) in [("vcpu", "host"), ("vgpio", "host"), ("vdisk", "ram")] {
            let f = backend_field(kind);
            assert!(f.radio, "{kind}: backend must be a single-select radio");
            assert!(
                !f.info,
                "{kind}: backend must never be an empty info dead-end"
            );
            assert_eq!(
                f.options.first().map(String::as_str),
                Some(sentinel),
                "{kind}: the reserved sentinel must be offered first"
            );
            assert!(
                f.hint.contains("required"),
                "{kind}: hint must say required, got {:?}",
                f.hint
            );
        }
    }

    #[test]
    fn radio_field_holds_a_single_value() {
        // A radio (single-select) pick - like `backend` - can never reach the invalid multi-value
        // state: ticking a second option clears the first.
        let mut form = Form {
            title: "t".into(),
            fields: vec![Field::radio(
                "backend",
                "pick one",
                vec!["gpio:0".into(), "gpio:1".into()],
            )],
            active: 0,
            submit: Submit::SaveProfile {
                section: "vgpio",
                orig_name: None,
            },
            error: None,
            show_advanced: false,
        };
        let feed = |form: Form, k: &[u8]| match handle_form_key(form, k) {
            FormOutcome::Stay(f) => f,
            _ => panic!("stays"),
        };
        form = feed(form, b" "); // tick gpio:0
        assert_eq!(form.fields[0].value, "gpio:0");
        form = feed(form, b"\x1b[C"); // → to gpio:1
        form = feed(form, b" "); // tick gpio:1 → gpio:0 cleared
        assert_eq!(
            form.fields[0].value, "gpio:1",
            "single value, not gpio:0,gpio:1"
        );
        assert_eq!(form.fields[0].sel, vec![false, true]);
        // The pane renders it as a radio, not a checkbox.
        form.active = 0;
        let pane = form_pane(&plain(), &form, 80, 24);
        assert!(pane.contains("(•)"), "radio uses round brackets:\n{pane}");
    }

    #[test]
    fn number_fields_reject_letters_as_you_type() {
        // pwm/pins/adc are line NUMBERS - typing letters must do nothing, so `1dfdf` can't happen.
        let mut form = Form {
            title: "t".into(),
            fields: vec![Field::text("pwm", "PWM lines"), Field::text("name", "n")],
            active: 0,
            submit: Submit::SaveProfile {
                section: "vgpio",
                orig_name: None,
            },
            error: None,
            show_advanced: false,
        };
        let feed = |mut form: Form, bytes: &[u8]| {
            for &byte in bytes {
                form = match handle_form_key(form, &[byte]) {
                    FormOutcome::Stay(f) => f,
                    _ => panic!("typing stays in the form"),
                };
            }
            form
        };
        form = feed(form, b"1dfdf2"); // the exact garbage the user typed, plus a digit
        assert_eq!(form.fields[0].value, "12", "letters dropped, digits kept");
        form = feed(form, b" 3,4"); // a pin list may use spaces and commas
        assert_eq!(form.fields[0].value, "12 3,4");
        // A profile NAME rejects spaces and punctuation (it's an identifier).
        form.active = 1;
        form = feed(form, b"my box!");
        assert_eq!(form.fields[1].value, "mybox");
    }

    #[test]
    fn number_fields_reject_out_of_range_values_as_you_type() {
        // The `44545454545` bug: a pin field must refuse a value that can never be a valid pin
        // (>= MAX_GPIO_PIN 1024), not just wrong characters. Same guarantee for vcpu / vdisk ranges.
        let feed = |mut form: Form, bytes: &[u8]| {
            for &byte in bytes {
                form = match handle_form_key(form, &[byte]) {
                    FormOutcome::Stay(f) => f,
                    _ => panic!("typing stays"),
                };
            }
            form
        };
        let mk = |section: &'static str, label: &'static str| Form {
            title: "t".into(),
            fields: vec![Field::text(label, "")],
            active: 0,
            submit: Submit::SaveProfile {
                section,
                orig_name: None,
            },
            error: None,
            show_advanced: false,
        };
        // pins: `44545454545` stops the moment the number would exceed the range - never the garbage.
        let f = feed(mk("vgpio", "pins"), b"44545454545");
        assert!(
            f.fields[0].value.parse::<u32>().unwrap() < crate::config::MAX_GPIO_PIN,
            "pins capped in range, got {:?}",
            f.fields[0].value
        );
        assert_ne!(f.fields[0].value, "44545454545");
        // A valid multi-pin list still types fine.
        assert_eq!(feed(mk("vgpio", "pins"), b"17 27").fields[0].value, "17 27");
        // nice -20..19: `20` can't be reached, but `-20` can.
        assert_eq!(feed(mk("vcpu", "nice"), b"20").fields[0].value, "2");
        assert_eq!(feed(mk("vcpu", "nice"), b"-20").fields[0].value, "-20");
        // cpus quota: a second dot is refused (`1.2.` → `1.2`).
        assert_eq!(feed(mk("vcpu", "cpus"), b"1.2.5").fields[0].value, "1.25");
        // memory / size: one unit at the end, nothing after it (`2gg` → `2g`, `5m2` → `5m`).
        assert_eq!(feed(mk("vcpu", "memory"), b"2gg").fields[0].value, "2g");
        assert_eq!(feed(mk("vdisk", "size"), b"5m2").fields[0].value, "5m");
        // Sizes are whole units (parse_binary_size takes a u64): the '.' in "1.5g" is refused at ENTRY,
        // not left to dead-end at save. So "1.5g" typed becomes "15g", a value the save DOES accept.
        let sz = feed(mk("vdisk", "size"), b"1.5g").fields[0].value.clone();
        assert_eq!(sz, "15g");
        assert!(
            crate::config::size_to_bytes(&sz).is_some(),
            "what the filter allowed must parse at save: {sz:?}"
        );
    }

    #[test]
    fn absent_device_is_a_read_only_note_you_cannot_type_into() {
        // A device the host lacks is a "none on this host" note: the cursor skips it and typing does
        // nothing - so a beginner can NEVER put garbage into, say, `spi` on a machine without SPI.
        let mut form = Form {
            title: "t".into(),
            fields: vec![
                Field::text("name", "n"),
                Field::info("spi", "none detected on this host"),
                Field::text("pins", "17 27"),
            ],
            active: 0,
            submit: Submit::SaveProfile {
                section: "vgpio",
                orig_name: None,
            },
            error: None,
            show_advanced: false,
        };
        // Tab from name skips the spi note and lands on pins.
        form = match handle_form_key(form, b"\t") {
            FormOutcome::Stay(f) => f,
            _ => panic!("tab stays"),
        };
        assert_eq!(
            form.fields[form.active].label, "pins",
            "nav skipped the note"
        );
        // Even if focus somehow sat on the note, typing can't fill it (it has no value box).
        form.active = 1;
        form = match handle_form_key(form, b"x") {
            FormOutcome::Stay(f) => f,
            other => match other {
                FormOutcome::Submit(f) => f,
                _ => panic!("unexpected"),
            },
        };
        assert!(
            form.fields[1].value.is_empty(),
            "a note never accepts typed text"
        );
        // The pane shows it as a dim note, not an input box.
        let pane = form_pane(&plain(), &form, 80, 24);
        assert!(
            pane.contains("spi") && pane.contains("none detected on this host"),
            "the note is visible:\n{pane}"
        );
    }
}

#[cfg(test)]
mod gpu_overview_tests {
    use super::*;

    /// `kern top` HAD NO GPU LINE. The parser takes nvidia-smi's CSV for two cards and a card whose
    /// power is `[N/A]`; the rows count the boxes holding each card by its `/dev/nvidiaN` minor, read
    /// the way the Boxes tab reads them.
    #[test]
    fn the_overview_lists_every_card_and_the_boxes_on_it() {
        let _g = crate::env_guard();
        let text = "0, NVIDIA GeForce RTX 5060 Ti, 00000000:01:00.0, 2404, 16311, 7, 41, 25.64\n\
                    1, NVIDIA GeForce RTX 5060 Ti, 00000000:06:00.0, 4895, 16311, 93, 60, [N/A]\n\
                    garbage line\n";
        let g = parse_smi_gpus(text);
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].bus, "0000:01:00.0");
        assert_eq!((g[1].util_pct, g[1].power_w), (Some(93), None));
        let p = Palette::plain();
        let row = |pid: i32, iso: &str| Row {
            name: format!("b{pid}"),
            pid,
            uptime: 1,
            mem: None,
            cpu_pct: 0.0,
            tasks: None,
            paused: false,
            health: String::new(),
            ports: String::new(),
            pod: String::new(),
            iso: iso.to_string(),
            sec: String::new(),
            orphaned: false,
            oom_kills: 0,
            restarts: 0,
            net: "",
            restarting: false,
            last_code: None,
        };
        // Three boxes: one on card 0, one on both, one with none. The minors are SWAPPED against the
        // nvidia-smi index on purpose (bus 01 is minor 1), so a count keyed on the index is caught.
        // Through the PRODUCTION reader of the Boxes tab's flag, so the row and the overview agree.
        let rows = [row(1, "gpu:1"), row(2, "net:host gpu:0,1"), row(3, "")];
        let nodes = gpu_nodes_from_flag;
        let minor = |bus: &str| match bus {
            "0000:01:00.0" => Some(1),
            "0000:06:00.0" => Some(0),
            _ => None,
        };
        let out = gpu_rows(&p, &rows, &g, nodes, minor);
        let line = |i: u32| {
            out.lines()
                .find(|l| l.contains(&format!("GPU {i}")))
                .unwrap_or("")
                .to_string()
        };
        assert!(
            line(0).ends_with(" · b1, b2"),
            "card 0 is minor 1, held by b1 and b2: {out}"
        );
        assert!(
            line(1).ends_with(" · b2"),
            "card 1 is minor 0, held by b2 alone: {out}"
        );
        // A JETSON: no bus, every reading `[N/A]`, then filled from a fake `/sys` (load in
        // thousandths, `gpu-thermal` in millidegrees). Rendered without a panic, memory named as
        // unified, counted in the title.
        let jet = parse_smi_gpus("0, Orin (nvgpu), [N/A], [N/A], [N/A], [N/A], [N/A], [N/A]\n");
        assert_eq!(jet.len(), 1, "the Jetson line is kept");
        assert_eq!(jet[0].bus, "");
        let sys = std::env::temp_dir().join(format!("kern-tegra-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sys);
        std::fs::create_dir_all(sys.join("sys/devices/platform/17000000.gpu")).unwrap();
        std::fs::write(sys.join("sys/devices/platform/17000000.gpu/load"), "457\n").unwrap();
        std::fs::create_dir_all(sys.join("sys/class/thermal/thermal_zone3")).unwrap();
        std::fs::write(
            sys.join("sys/class/thermal/thermal_zone3/type"),
            "gpu-thermal\n",
        )
        .unwrap();
        std::fs::write(sys.join("sys/class/thermal/thermal_zone3/temp"), "49250\n").unwrap();
        let filled = tegra_readings(jet[0].clone(), &sys);
        assert_eq!((filled.util_pct, filled.temp_c), (Some(45), Some(49)));
        // A card WITH a bus is not touched by the Tegra fallback.
        assert_eq!(tegra_readings(g[1].clone(), &sys), g[1]);
        let _ = std::fs::remove_dir_all(&sys);
        let jrow = gpu_rows(&p, &[], &[filled], gpu_nodes_from_flag, |_| None);
        assert!(
            jrow.contains("Orin (nvgpu)")
                && jrow.contains("memory unified with RAM")
                && jrow.contains("45 % busy")
                && jrow.contains("49 C"),
            "{jrow}"
        );
        assert_eq!(gpu_header(&p, &jet), "GPU 1");
        assert_eq!(gpu_header_with(&p, &[], 0), "GPU none");
        // A card doctor sees and the per-card reader cannot read (WSL2's /dev/dxg): counted, not "none".
        assert_eq!(gpu_header_with(&p, &[], 1), "GPU 1 · usage n/a");
        assert_eq!(gpu_header(&p, &g), "GPU 2 · 7.1G / 31.9G");
        assert_eq!(service_of("aistack-e1c0723b-llm0"), "llm0");
        assert_eq!(service_of("my-app-0a1b2c3d-api-v2"), "api-v2");
        assert_eq!(
            service_of("e1c0723b-x"),
            "e1c0723b-x",
            "the hash needs a project before it"
        );
        assert_eq!(service_of("hello"), "hello");
        let no_rows: Vec<Row> = Vec::new();
        let out = gpu_rows(&p, &no_rows, &g, gpu_nodes_from_flag, |_| None);
        assert!(out.contains("GPU 0") && out.contains("GPU 1"), "{out}");
        assert!(out.contains("GeForce RTX 5060 Ti"), "{out}");
        assert!(out.contains("01:00.0") && out.contains("06:00.0"), "{out}");
        assert!(out.contains("93 % busy") && !out.contains("[N/A]"), "{out}");
        assert!(
            out.lines()
                .all(|l| l.ends_with("01:00.0") || l.ends_with("06:00.0")),
            "a card no box holds ends at its bus, with no box text: {out}"
        );
        assert!(
            gpu_rows(&p, &no_rows, &[], gpu_nodes_from_flag, |_| None).is_empty(),
            "no card, no section"
        );
    }
}
