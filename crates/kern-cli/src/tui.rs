//! `kern top` — a small, dependency-free task-manager TUI (alternate screen, tabs, live refresh,
//! keyboard nav; each data tab shows a live item count, e.g. `Boxes (3)`). Seven tabs: **Overview** (host CPU / RAM / load + the box aggregate), **Boxes** (the
//! per-box table — MEM/CPU/PIDS plus HEALTH and PORTS (parity with `kern ps`) — with lifecycle
//! actions: stop/pause/unpause/kill/logs), **Runs** (aggregate `kern run` throughput — rate/sec, avg
//! setup latency, peak, total + sparkline; a `⚡` on the tab marks live activity), **Builds** (`kern
//! build` history), **Profiles** (the reusable
//! specs you attach by prefix — vcpu/vgpio/vdisk; a vdisk *selects* one of the read-only physical
//! disks, and its `[[disk]]` is materialised from that choice, never hand-created) and **Storage** (the
//! concrete data layer — physical disks read-only + named volumes you create). Host stats come straight
//! from `/proc`. Pure `libc` termios + ANSI, no curses/ratatui dependency.
//!
//! A `?` from any tab opens a full-keymap help overlay (the footer always advertises it), so the whole
//! interface is discoverable without docs.
//!
//! Interaction is a small [`Mode`] state machine — `Nav` plus three modals (`Overlay` read-only pane,
//! `Form` input, `Confirm` for destructive actions). Profile edits are written **surgically** (see
//! [`crate::toml_surgery`]) so a single edit never rewrites the whole file and drop the user's other
//! sections.
//!
//! Robustness: the terminal is put in raw mode + the alternate screen on entry and **restored on
//! drop** (so a panic or early return still leaves a sane terminal). `ISIG` is disabled, so Ctrl-C
//! arrives as a byte we handle as "quit" — clean teardown, no stranded alt-screen.

use crate::commands::{fmt_uptime, human_bytes};
use crate::registry;
use crate::ui::Palette;
use std::collections::HashMap;
use std::io::Write;
use std::time::Instant;

const TABS: [&str; 7] = [
    "Overview", "Boxes", "Runs", "Images", "Builds", "Profiles", "Storage",
];
const TAB_OVERVIEW: usize = 0;
const TAB_BOXES: usize = 1;
const TAB_RUNS: usize = 2;
const TAB_IMAGES: usize = 3;
const TAB_BUILDS: usize = 4;
const TAB_PROFILES: usize = 5;
const TAB_STORAGE: usize = 6;

/// What the TUI is doing right now: plain navigation, or a modal layered over it.
enum Mode {
    Nav,
    /// A read-only text pane (box logs, profile/volume detail). Any key closes it.
    Overlay(String),
    /// A multi-field text form (volume create, profile new/edit).
    Form(Form),
    /// The "new profile" kind picker (Profiles tab `n`): choose vcpu / vgpio / vdisk / disk.
    PickKind,
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
/// short form: a bus may be saved bare (`"1"`) or as `"i2c-1"` but the host scan lists `"/dev/i2c-1"`
/// — fold all three to the `/dev/` form so they compare equal. Everything else is returned unchanged.
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
    /// A boolean switch (`[x]`/`[ ]`, Space flips) rather than free-text — for keys like `persistent`
    /// that are a bool, so a beginner never types "true"/"false". On = non-empty value; off = empty.
    toggle: bool,
    /// Checkbox options: the host devices DETECTED for this field. Non-empty ⇒ a "pick" field — the
    /// user toggles which are selected (←/→ to move, Space to check) instead of typing a `/dev/…`
    /// path, so a wrong path is impossible. `value` (what `apply_form` saves) stays in sync = the
    /// checked options, comma-joined. `cur` is the highlighted option.
    options: Vec<String>,
    sel: Vec<bool>,
    cur: usize,
    /// A rare/expert knob: hidden under the "Advanced" fold so a beginner sees only the common fields.
    advanced: bool,
    /// The "▸ Advanced" fold row itself (not an input) — Space/←→ expand or collapse the advanced group.
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

    /// True while this is a dead "none on this host" note — no value, nothing to edit, skip in nav.
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

    /// A checkbox picker over detected devices — foolproof: you can only choose what exists.
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
        for s in &mut self.sel {
            *s = false;
        }
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
    /// Health-check state (`healthy`/`unhealthy`/`starting`, empty if the box has no `--health-cmd`) —
    /// the same signal `kern ps` shows, so a compose stack's readiness is visible in the TUI too.
    health: String,
    /// Published-ports summary (e.g. `8080->80`), empty if none — parity with `kern ps`.
    ports: String,
    /// The pod (compose stack) this box belongs to, empty for a standalone box — drives the `kern ps`
    /// tree grouping in the Boxes tab.
    pod: String,
    /// How this box DEVIATES from the secure default — `net:host` and/or `root-mapped`, empty when
    /// fully isolated (the common case). Flags only the LESS-confined boxes, never a vanity badge.
    iso: String,
}

/// Restores the terminal on drop: leave the alternate screen, show the cursor, re-enable line
/// wrap, and put `termios` back. Runs even on panic / early return.
struct TermGuard {
    orig: libc::termios,
    fd: i32,
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        let mut out = std::io::stdout();
        let _ = out.write_all(b"\x1b[?7h\x1b[?1049l\x1b[?25h");
        let _ = out.flush();
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig) };
    }
}

/// Saved `(termios, fd)` for the signal handler to restore. `TermGuard::drop` covers a normal
/// return and a panic (unwind runs Drop), but a fatal signal — `SIGTERM` (`kill`), `SIGHUP` (an SSH
/// disconnect), `SIGINT`/`SIGQUIT` via `kill` — terminates WITHOUT unwinding, leaving the terminal
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
/// the view INSTANTLY instead of on the next 1 s tick — the "no lag" property. Best-effort.
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

/// Run the interactive TUI. Returns when the user quits (`q`, `Esc`, or `Ctrl-C`).
pub fn run() -> Result<(), crate::error::Error> {
    let fd = 0; // stdin
    let mut orig: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut orig) } != 0 {
        return snapshot(); // not a real tty after all — one-shot fallback
    }
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

    let p = Palette::detect();
    let mut tab = 0usize;
    let mut sel = 0usize; // highlighted row on the active list tab
    let mut mode = Mode::Nav;
    let mut prev: HashMap<i32, (u64, Instant)> = HashMap::new();
    let mut prev_cpu: Option<(u64, u64)> = None;
    let mut prev_runs: Option<(u64, std::time::Instant)> = None;
    let mut runs_hist: Vec<f64> = Vec::new(); // reader-side sparkline ring for the Runs tab

    // Live wake: an inotify watch on the box registry dir so a box created/removed by ANY kern
    // process shows up INSTANTLY, with zero poll lag. Best-effort — if inotify or the dir is
    // unavailable, the 1 s timer below still keeps the view fresh (just not sub-second on changes).
    let ino_fd = setup_registry_watch();

    let mut snap = refresh_full(&mut prev, &mut prev_cpu, &mut prev_runs, &mut runs_hist);
    loop {
        let (cols, term_rows) = term_size();
        let list_len = tab_list_len(
            tab,
            &snap.rows,
            &snap.profs,
            &snap.vols,
            &snap.builds,
            &snap.images,
        );
        if sel >= list_len {
            sel = list_len.saturating_sub(1);
        }

        let frame = render(
            &p,
            tab,
            &snap.rows,
            &snap.host,
            &snap.profs,
            &snap.vols,
            &snap.builds,
            &snap.images,
            cols,
            term_rows,
            sel,
            &mode,
        );
        // Clear each line to end-of-line (`\x1b[K`) so a shorter/blank line in the new frame wipes
        // any leftover text from the previous one (no residue, no flicker), then erase everything
        // below the frame (`\x1b[J`) in case the new frame has fewer lines.
        let painted = frame.replace('\n', "\x1b[K\n");
        let _ = out.write_all(b"\x1b[H"); // cursor home
        let _ = out.write_all(painted.as_bytes());
        let _ = out.write_all(b"\x1b[J");
        let _ = out.flush();

        // Wait for a key, a registry change (inotify), or ~1 s (the CPU%/stats window). A registry
        // change wakes us instantly (no poll lag); the timer keeps stats fresh even when idle.
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
        ];
        let nfds = if ino_fd >= 0 { 2 } else { 1 };
        if unsafe { libc::poll(pfds.as_mut_ptr(), nfds, 1000) } <= 0 {
            snap = refresh_full(&mut prev, &mut prev_cpu, &mut prev_runs, &mut runs_hist); // timeout → periodic refresh (CPU% window)
            continue;
        }
        // A registry change woke us: drain the inotify queue and refresh NOW. If no key is also
        // pending, re-render and wait again — no 1 s lag on box appear/disappear.
        if ino_fd >= 0 && pfds[1].revents & libc::POLLIN != 0 {
            let mut ibuf = [0u8; 4096];
            while unsafe { libc::read(ino_fd, ibuf.as_mut_ptr().cast(), ibuf.len()) } > 0 {}
            snap = refresh_full(&mut prev, &mut prev_cpu, &mut prev_runs, &mut runs_hist);
            if pfds[0].revents & libc::POLLIN == 0 {
                continue;
            }
        }
        let mut buf = [0u8; 8];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            continue;
        }
        let key = &buf[..n.max(0) as usize];

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
                    perform_pending(action);
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
        // appears) but leaves the CPU% baselines alone — re-sampling over the sub-second gap since
        // the last tick would show a spurious spike. The next tick restores a full ~1 s window.
        if dirty {
            let (rows, _) = collect_rows(&prev);
            snap.rows = rows;
            snap.cfg = crate::config::load(None).unwrap_or_default();
            snap.profs = profile_rows(&snap.cfg);
            snap.vols = crate::volume::entries();
            // Also re-read the lists whose tabs now mutate (Images `d`/`p`, Builds `d`) so a deleted row
            // disappears on the very next frame, not on the ≤1 s periodic refresh (inotify watches the
            // box registry, not the image cache / build history).
            snap.builds = crate::builds::list();
            snap.images = crate::commands::image_entries();
        }
    }
    Ok(()) // _guard restores the terminal on drop
}

/// `q` / `Q` / `Ctrl-C`, or a lone `Esc` (not the start of an arrow-key escape sequence).
fn is_quit(key: &[u8]) -> bool {
    matches!(key.first(), Some(b'q' | b'Q' | 0x03)) || key == [0x1b]
}

/// Number of selectable rows on the active tab (0 for Overview).
fn tab_list_len(
    tab: usize,
    rows: &[Row],
    profs: &[ProfRow],
    vols: &[crate::volume::VolInfo],
    builds: &[crate::builds::Record],
    images: &[crate::commands::ImageEntry],
) -> usize {
    match tab {
        TAB_BOXES => rows.len(),
        TAB_IMAGES => images.len(),
        TAB_BUILDS => builds.len(),
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
    // Arrow-key escape sequences: ↑↓ select, ←→ switch tab. Pure navigation — never dirties data.
    if key.len() >= 3 && key[0] == 0x1b && key[1] == b'[' {
        match key[2] {
            b'A' => up(sel),
            b'B' => down(sel),
            b'C' => switch(tab, sel, (*tab + 1) % TABS.len()),
            b'D' => switch(tab, sel, (*tab + TABS.len() - 1) % TABS.len()),
            _ => {}
        }
        return false;
    }
    // `?` opens the full-key help overlay from ANY tab — the discoverable safety net every good TUI
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
        b'j' => down(sel),
        // Only the Boxes tab acts immediately (stop/pause/kill). Profiles/Storage keys just open a
        // modal, so the mutation (if any) happens later via Confirm/Form — nothing to refresh yet.
        _ if *tab == TAB_BOXES => return nav_boxes(key[0], *sel, rows, mode),
        _ if *tab == TAB_IMAGES => nav_images(key[0], *sel, images, mode),
        _ if *tab == TAB_BUILDS => nav_builds(key[0], *sel, builds, mode),
        _ if *tab == TAB_PROFILES => nav_profiles(key[0], *sel, profs, cfg, mode),
        _ if *tab == TAB_STORAGE => nav_storage(key[0], *sel, vols, mode),
        _ => {}
    }
    false
}

/// Boxes-tab action keys: stop / pause / unpause / kill the selected box, or open its logs. The CLI
/// helpers are reused with muted stdio so their messages don't bleed into the alt-screen. Returns
/// `true` when a lifecycle op changed box state (so the caller re-reads the list), `false` for a
/// read-only action (opening logs) or an unbound key.
fn nav_boxes(k: u8, sel: usize, rows: &[Row], mode: &mut Mode) -> bool {
    let Some(name) = rows.get(sel).map(|r| r.name.clone()) else {
        return false;
    };
    match k {
        b's' | b'k' => quiet_io(|| {
            let _ = crate::commands::stop(std::slice::from_ref(&name), false);
        }),
        b'p' => quiet_io(|| {
            let _ = crate::commands::pause(std::slice::from_ref(&name), false, true);
        }),
        b'u' => quiet_io(|| {
            let _ = crate::commands::pause(std::slice::from_ref(&name), false, false);
        }),
        b'\r' | b'\n' => {
            *mode = Mode::Overlay(
                crate::commands::box_log_tail(&name).unwrap_or_else(|| "(no output yet)".into()),
            );
            return false;
        }
        _ => return false,
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
                *mode = Mode::Confirm {
                    prompt: format!("remove volume '{}' and its data?  (y/n)", v.name),
                    action: Pending::RemoveVolume(v.name.clone()),
                };
            }
        }
        b'p' => {
            *mode = Mode::Confirm {
                prompt: "prune ALL unused volumes?  (y/n)".into(),
                action: Pending::PruneVolumes,
            };
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
/// the interactive surface is Delete + Prune + Read — the meaningful CRUD for a cache of artifacts.
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
        b'\r' | b'\n' => {
            if let Some(b) = builds.get(sel) {
                let body = crate::builds::read_log(&b.id)
                    .unwrap_or_else(|| "(no transcript captured for this build)".into());
                *mode = Mode::Overlay(format!("build {} — {}\n{}", b.id, b.tag, body));
            }
        }
        _ => {}
    }
}

/// A read-only detail block for one cached image (Images tab `Enter`). The ref is scrubbed of terminal
/// escapes — a `.ok` sentinel's content is untrusted.
fn image_detail(img: &crate::commands::ImageEntry) -> String {
    let now = registry::now_unix();
    // A dangling image (layers gone) shows that plainly instead of a misleading `0 B` size.
    let size = if img.dangling {
        "dangling (missing layers — would fail to run)".to_string()
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

/// Carry out a confirmed destructive action, muting the helper's stdio.
fn perform_pending(action: Pending) {
    match action {
        Pending::RemoveVolume(name) => quiet_io(|| {
            let _ = crate::volume::run(&["rm".to_string(), name]);
        }),
        Pending::PruneVolumes => quiet_io(|| {
            let _ = crate::volume::run(&["prune".to_string()]);
        }),
        Pending::DeleteProfile(section, name) => {
            let _ = delete_profile(section, &name);
        }
        Pending::RemoveImage(name) => quiet_io(|| {
            let _ = crate::commands::image_rm(&[name]);
        }),
        Pending::PruneImages => quiet_io(|| {
            let _ = crate::commands::image_prune();
        }),
        Pending::DeleteBuild(id) => {
            crate::builds::remove(&id);
        }
    }
}

/// Run `f` with fd 1 and fd 2 redirected to `/dev/null`, then restored — so a reused CLI helper's
/// `println!`/`eprintln!` can't corrupt the alt-screen. Used for the lifecycle key actions.
fn quiet_io(f: impl FnOnce()) {
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
    f();
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
}

// ───────────────────────────── Profiles & Volumes: model ─────────────────────────────

/// Flatten the three editable profile kinds into display rows (name + a one-line summary).
fn profile_rows(cfg: &crate::config::KernConfig) -> Vec<ProfRow> {
    let mut out = Vec::new();
    for e in &cfg.vcpu {
        let mut parts = Vec::new();
        if let Some(q) = e.vcpus {
            parts.push(format!("{} cores", trim_f(q)));
        }
        if let Some(c) = &e.cpus {
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
    // vdisk — a per-box scratch/disk profile (attached with `vdisk:name`).
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
    // Group by category (compute → device → storage) and sort by name within each — so the list is
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

/// The `backend` field for every profile kind — a SELECTION of the configured backends, never free text
/// (that's how `disk:0sfsf…` / `gpio:0sfsf…` were possible). vgpio→`[[gpio]]` ids, vcpu→`[[cpu]]` ids,
/// vdisk→`disk:<[[disk]] name>`. A single-select radio (a profile uses ONE backend); if none are
/// configured, a "run kern config setup" note instead of a blank box. Optional — leave it unticked and
/// the profile uses the default. One helper so all three kinds behave identically.
fn backend_field(kind: &str) -> Field {
    let cfg = crate::config::load(None).unwrap_or_default();
    let ids: Vec<String> = match kind {
        "vgpio" => cfg.gpio.iter().map(|g| g.id.clone()).collect(),
        "vcpu" => cfg.cpu.iter().map(|c| c.id.clone()).collect(),
        "vdisk" => cfg
            .disk
            .iter()
            .map(|d| format!("disk:{}", d.name))
            .collect(),
        _ => Vec::new(),
    };
    if ids.is_empty() {
        Field::info("backend", "no backend configured (run: kern config setup)")
    } else {
        Field::radio("backend", "the backend to use (optional)", ids)
    }
}

/// The editable fields for a compute/IO profile section (`vcpu`/`vgpio`) — used for new and edit.
/// (Storage kinds — vdisk, volume — have their own forms.)
fn section_fields(section: &str) -> Vec<Field> {
    // The common fields first (a beginner rarely scrolls past them), then the advanced ones. The form
    // scrolls, so every field of every kind is reachable — nothing is CLI-only.
    match section {
        "vcpu" => vec![
            Field::text("name", "e.g. heavy"),
            Field::text("vcpus", "cores, e.g. 4 or 0.5"),
            Field::text("cpus", "pin list, e.g. 0-3"),
            Field::text("memory", "e.g. 512m, 2g"),
            Field::text("priority", "0-99 (optional)"),
            Field::text("numa", "NUMA node, e.g. 0 (optional)"),
            Field::text("nice", "-20..19 (optional)"),
            backend_field("vcpu"),
            Field::text("extends", "base profile (optional)"),
        ],
        "vgpio" => {
            // For-dummies: the beginner sees only NAME + the everyday devices, each as a checkbox
            // list of what THIS host actually exposes — so there's nothing to type and nothing to
            // guess: tick the device you want the box to reach, or leave it empty. Everything rare
            // (LEDs, CAN, PWM, backend, …) lives under the "Advanced" fold so the form stays short.
            //
            // `pick(label, plain-language what-is-this)` when the host HAS that device — you tick it,
            // you never type a path. When the host DOESN'T have it, there's nothing valid to type, so
            // it becomes a read-only "none detected on this host" note instead of an empty box that
            // invites garbage. Same mechanism on every host — only the detected contents differ.
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
                ("i2c", "I²C bus — sensors, small displays"),
                ("spi", "SPI bus — displays, ADCs"),
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
            // type — but only when the host actually has a GPIO controller. Check the modern chardev
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
            // The rare / expert knobs — hidden until the user opens "Advanced". Anything the host can
            // enumerate is a pick (net interfaces, LEDs, …); a device it lacks is a note; pwm follows
            // the same GPIO gate as pins; only the truly free-form escape (`extra`) stays typed.
            // NOTE: `net` is deliberately absent — a vgpio profile does NOT attach a network interface
            // (the resolver ignores it), so offering it would be a lie. Network access is the box's
            // own `--net`. If net-passthrough is ever wired in the resolver, add it back here.
            for (label, plain) in [
                ("leds", "on-board LEDs"),
                ("can", "CAN bus"),
                ("input", "input devices (keys, touch)"),
                ("midi", "MIDI ports"),
                ("display", "display nodes (DRI)"),
            ] {
                advanced.push(mk(label, plain));
            }
            // A USB peripheral is passed by its FUNCTION, not as a raw bus node: a USB-serial adapter is
            // under 'serial' (ttyUSB), a webcam under 'camera' (video), a USB mic under 'sound card'.
            // Raw /dev/bus/usb passthrough is refused by the resolver (it reaches the WHOLE bus — BadUSB),
            // so a real usb pick would only ever be denied — an explanatory note instead of a lie.
            advanced.push(Field::info(
                "usb",
                "passed by function: serial / camera / sound card above",
            ));
            // Number fields (pwm/adc/onewire are channel/line indices you'd type) only accept typing
            // when the host actually HAS that controller; otherwise there's nothing to type, so it's a
            // "none here" note — never an empty box asking you to guess. A gated helper keeps it uniform.
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
/// I²C bus or a PWM line is — the help says it, with an everyday example. `None` = no help (e.g. the
/// Advanced fold row). Kept short (≤ ~74 chars) so it never wraps an 80-column terminal.
fn field_help(section: &str, label: &str) -> Option<&'static str> {
    let h = match (section, label) {
        ("vgpio", "name") => "A label for this hardware set — attach it to a box with  vgpio:NAME",
        ("vgpio", "i2c") => "I²C bus for sensors & small displays. Tick the bus your part is on.",
        ("vgpio", "spi") => "SPI bus for displays, ADCs, radios. Tick the port your part uses.",
        ("vgpio", "uart") => "Serial port for GPS, modems, consoles. Tick the tty it's on.",
        ("vgpio", "camera") => "A camera. Tick it to let the box capture video.",
        ("vgpio", "audio") => "The sound card. Tick to let the box play or record audio.",
        ("vgpio", "bluetooth") => "The Bluetooth adapter. Tick to let the box use Bluetooth/BLE.",
        ("vgpio", "pins") => "Raw GPIO pin numbers (e.g. 17 27) for LEDs, buttons, relays.",
        ("vgpio", "leds") => "On-board LEDs you want the box to control.",
        ("vgpio", "can") => "CAN bus — vehicle & industrial networking.",
        ("vgpio", "input") => "Input devices — keys, touchscreen, joystick.",
        ("vgpio", "midi") => "MIDI ports for music gear.",
        ("vgpio", "display") => "GPU display nodes (DRI) for rendering.",
        ("vgpio", "pwm") => "PWM outputs (e.g. 12 13) for servos, dimming, fans.",
        ("vgpio", "adc") => "Analog inputs (ADC channels).",
        ("vgpio", "onewire") => "1-Wire lines, e.g. a DS18B20 temperature sensor.",
        ("vgpio", "backend") => "Which detected GPIO controller to use (default gpio:0).",
        ("vgpio", "extra") => "Any other /dev path to pass, only if you know it exists.",
        ("vcpu", "name") => "A label for this CPU/memory slice — attach with  vcpu:NAME",
        ("vcpu", "vcpus") => "How many cores the box may use, e.g. 4 — or 0.5 for half a core.",
        ("vcpu", "cpus") => "Pin to specific cores, e.g. 0-3. Leave blank to let it float.",
        ("vcpu", "memory") => "Memory ceiling, e.g. 512m or 2g. The box is OOM-capped at this.",
        ("vdisk", "name") => "A label for this scratch disk — attach with  vdisk:NAME",
        ("vdisk", "size") => "Max size of the scratch disk, e.g. 2g. Writes past it fail.",
        ("vdisk", "persistent") => {
            "Keep the disk's data after the box is removed (default: wiped)."
        }
        _ => return None,
    };
    Some(h)
}

/// The ONE validation authority for a typed keystroke — the derived "char filter": a character is
/// accepted iff the resulting value isn't `field_state::Invalid`. `field_state` is itself derived from
/// the save parser (`profile_line` / `validate_profile_name`), so there is a SINGLE source of truth for
/// what any field may hold, shared by live-typing AND save; a per-field char-class list (which could
/// drift) no longer exists. A number field rejects a letter because the value would be `Invalid`; a
/// name rejects a space for the same reason; even `extra` rejects a non-`/dev/` string. The
/// printable-ASCII gate at the call site still blocks control / multibyte bytes for every field.
fn field_value_ok(label: &str, v: &str) -> bool {
    crate::config::field_state(label, v) != crate::config::FieldState::Invalid
}

/// Fields governed by `config::field_state` — the SINGLE rule shared with save — and given the live
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
            | "priority"
            | "numa"
            | "nice"
            | "vcpus"
            | "cpus"
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
/// configured GPIO ids (or a "run kern config setup" note), and it's optional — the resolver binds the
/// gpiochips from `pins` regardless — so a beginner leaves it alone.
fn new_profile_form(section: &'static str) -> Form {
    let fields = section_fields(section);
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
/// edit shows and re-saves all of them — nothing is dropped or hidden.
fn edit_profile_form(section: &'static str, name: &str, cfg: &crate::config::KernConfig) -> Form {
    let mut fields = section_fields(section);
    set_field(&mut fields, "name", name.to_string());
    for (k, v) in crate::config::profile_pairs(cfg, section, name) {
        set_field(&mut fields, &k, v);
    }
    // If the profile already sets an advanced field, open the fold so the edit SHOWS it — nothing the
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
    set_field(&mut fields, "name", v.name.clone());
    set_field(&mut fields, "size", size);
    Form {
        title: format!("edit volume:{}", v.name),
        fields,
        active: 0,
        submit: Submit::EditVolume {
            orig_name: v.name.clone(),
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
    // The Advanced fold row: Space toggles it; Enter still saves, Esc cancels, Tab moves on — but a
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
    // A "none on this host" note never takes input — its value stays empty so it stays a note and a
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
            // and `pins` can't reach `44545454545` — both because the value would be Invalid — with no
            // separate char-class list to drift. The `0x20..0x7f` gate blocks control / multibyte bytes.
            let label = form.fields[form.active].label;
            let v = &mut form.fields[form.active].value;
            for &b in key {
                if !(0x20..0x7f).contains(&b) {
                    continue;
                }
                // Append then roll back on reject — no per-byte clone of the whole value, so pasting
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
            // Blank size clears the quota; otherwise it must parse (and be > 0 — a 0-byte quota is
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

/// Turn a profile form's fields into (name, body lines) via the shared `config` schema — the
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
        || "∞ (unlimited — grows until the disk is full)".to_string(),
        human_bytes,
    );
    format!(
        "volume '{}'\n\n  data used   {}\n  quota       {}\n  mount with  -v {}:/path[:ro]",
        v.name,
        human_bytes(v.size),
        quota,
        v.name
    )
}

/// Snapshot the Boxes table once (used when stdout is not a TTY — e.g. piped).
pub fn snapshot() -> Result<(), crate::error::Error> {
    let p = Palette::detect();
    // Two `/proc/stat` samples ~120 ms apart give a real host CPU% even for a one-shot snapshot.
    let (_, s1) = read_host(None);
    std::thread::sleep(std::time::Duration::from_millis(120));
    let (host, _) = read_host(s1);
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
    let (rows, _) = collect_rows(&HashMap::new());
    print!("{}", boxes_table(&p, &rows, usize::MAX, usize::MAX));
    Ok(())
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
    images: Vec<crate::commands::ImageEntry>,
}

/// A full refresh: re-sample everything and advance the CPU% baselines (`prev`, `prev_cpu`) — used
/// on the 1 s tick, where the ~1 s delta gives a meaningful CPU percentage.
fn refresh_full(
    prev: &mut HashMap<i32, (u64, Instant)>,
    prev_cpu: &mut Option<(u64, u64)>,
    prev_runs: &mut Option<(u64, Instant)>,
    runs_hist: &mut Vec<f64>,
) -> Snapshot {
    let (rows, seen) = collect_rows(prev);
    *prev = seen;
    let (mut host, cpu_now) = read_host(*prev_cpu);
    *prev_cpu = cpu_now;
    // Live `kern run` throughput from the mmap counter: cumulative total + rate since the last sample,
    // plus the honest average setup latency (summed entry→exec µs / total).
    let (rt, lat_sum_us) = crate::runstats::snapshot();
    if let Some((pt, pi)) = *prev_runs {
        let dt = pi.elapsed().as_secs_f64();
        if dt > 0.05 {
            host.runs_per_sec = rt.saturating_sub(pt) as f64 / dt;
        }
    }
    host.runs_total = rt;
    host.runs_avg_us = lat_sum_us.checked_div(rt).unwrap_or(0);
    // Reader-side sparkline: keep the last N runs/sec samples so the Runs tab shows recent shape, and
    // track the session peak. The very first sample (no prior baseline) is 0 — harmless. One push per
    // refresh, so at most one drop keeps the ring bounded.
    const SPARK_N: usize = 48;
    runs_hist.push(host.runs_per_sec);
    if runs_hist.len() > SPARK_N {
        runs_hist.remove(0);
    }
    host.runs_peak = runs_hist.iter().copied().fold(0.0_f64, f64::max);
    host.runs_spark = runs_hist.clone();
    *prev_runs = Some((rt, Instant::now()));
    let cfg = crate::config::load(None).unwrap_or_default();
    let profs = profile_rows(&cfg);
    let vols = crate::volume::entries();
    let builds = crate::builds::list();
    let images = crate::commands::image_entries();
    Snapshot {
        rows,
        host,
        cfg,
        profs,
        vols,
        builds,
        images,
    }
}

/// A compact marker of how a running box DEVIATES from the secure default: `net:host` (it shares the
/// host network namespace instead of an isolated one) and/or `root-mapped` (its uid 0 maps to host uid
/// 0 — kern ran as root). Empty when the box is fully isolated, so the Boxes tab flags only the boxes
/// that are LESS confined than default (the always-on layers — seccomp, masked `/proc`, dropped caps —
/// are identical for every box, so a "secure" badge would be vanity). Read-only `/proc` introspection.
fn box_isolation(pid: i32) -> String {
    let mut flags = Vec::new();
    // Shared host netns? `kern top` runs in the host netns, so an equal namespace link means the box
    // was started with `--network host` (no isolated netns).
    if let (Ok(bx), Ok(me)) = (
        std::fs::read_link(format!("/proc/{pid}/ns/net")),
        std::fs::read_link("/proc/self/ns/net"),
    ) {
        if bx == me {
            flags.push("net:host");
        }
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
    // (DEFAULT_DROP — module load, raw I/O, BPF, …) was handed it back via `--cap-add`, so it is less
    // confined than default. The bounding set is the honest signal: a rootless box's `CapEff` is full
    // but namespaced (grants no host power) and would false-positive; `CapBnd` reflects what kern kept.
    if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
        if let Some(bnd) = status.lines().find_map(|l| l.strip_prefix("CapBnd:")) {
            if let Ok(bits) = u64::from_str_radix(bnd.trim(), 16) {
                if bits & kern_isolation::default_dropped_cap_mask() != 0 {
                    flags.push("caps:+");
                }
            }
        }
    }
    flags.join(" ")
}

fn collect_rows(prev: &HashMap<i32, (u64, Instant)>) -> (Vec<Row>, HashMap<i32, (u64, Instant)>) {
    let now_t = Instant::now();
    let now_u = registry::now_unix();
    let mut seen = HashMap::new();
    let mut rows = Vec::new();
    for b in registry::list() {
        // One cgroup resolve for all four readings (mem/cpu/tasks/frozen) instead of four.
        let st = registry::box_stats(b.pid);
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
        // Introspect the box's INTERIOR init (`pid1`), not the host-side supervisor `pid` — the
        // supervisor lives in the host netns with the kernel's trivial uid_map, which would falsely flag
        // every box. `pid1 == 0` (unrecorded / old entry) → the /proc reads fail → no flag, no false
        // positive.
        let iso = box_isolation(b.pid1);
        rows.push(Row {
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
        });
    }
    // Group for the pod-tree view: standalone boxes first, then each pod's members contiguous (pods in
    // name order). A STABLE sort, so registry order is preserved within a group — and the selection
    // index stays valid (it just indexes this display order; actions still hit rows[sel]).
    rows.sort_by(|a, b| {
        (!a.pod.is_empty())
            .cmp(&!b.pod.is_empty())
            .then_with(|| a.pod.cmp(&b.pod))
    });
    (rows, seen)
}

/// A snapshot of host-wide resource use, shown in the Overview tab (like the private's `kern top`).
struct HostStats {
    mem_used: u64,
    mem_total: u64,
    disk_used: u64,
    disk_total: u64,
    cpu_pct: f64,
    cores: usize,
    load1: f64,
    /// Cumulative `kern run` invocations (from the daemonless runstats mmap counter) + the derived
    /// rate/sec — kern's fire-and-forget capped-process throughput, which Docker can't show at scale.
    runs_total: u64,
    runs_per_sec: f64,
    /// Average per-run setup latency in microseconds (entry→exec, the honest "~1 ms"); 0 with no runs.
    runs_avg_us: u64,
    /// The highest runs/sec seen since `top` started (session peak throughput) and a reader-side ring of
    /// recent runs/sec samples for the Runs-tab sparkline — both derived from the monotonic total.
    runs_peak: f64,
    runs_spark: Vec<f64>,
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

/// `(busy, total)` jiffies from `/proc/stat`'s aggregate `cpu ` line — CPU% is the delta of two.
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
/// desktop — a netdev LED (`<iface>` or `<iface>-<port>` before `::`, e.g. `enp5s0-0::lan`, a NIC PHY
/// light) or an input LED (`inputN::…`, a keyboard capslock light) — neither of which is a meaningful
/// device to pass into a sandbox. Real board LEDs (`led0`, `ACT`, `PWR`, `mmc0::…`) pass.
fn is_board_led(name: &str, nets: &[String]) -> bool {
    let head = name.split("::").next().unwrap_or(name);
    let is_input_led = head
        .strip_prefix("input")
        .is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit()));
    let is_netdev_led = nets
        .iter()
        .any(|iface| head == iface || head.starts_with(&format!("{iface}-")));
    !is_input_led && !is_netdev_led
}

/// The host devices currently present for a vGPIO field `kind` — the options the new/edit form offers
/// as checkboxes, so a user PICKS from what actually exists instead of typing a `/dev/…` path (which
/// is easy to get wrong). Uniform for every host: the same probe runs everywhere, only the *contents*
/// differ — a Pi shows its i2c/gpio, a mini-PC its bluetooth/usb. Returns sorted; a busy desktop can
/// return many (e.g. 20 i2c DDC buses), so the form caps the visible count and keeps a manual field.
// Wired into the vGPIO new/edit form (checkbox picker) in a follow-up; kept here as the shared,
// host-uniform probe so every profile form uses one identical mechanism.
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
        // netdev LEDs (`enp5s0-0::lan` — a NIC PHY link light) and input LEDs (`input3::capslock` — a
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
        _ => Vec::new(),
    }
}

/// `(used, total)` bytes on the filesystem that backs the kern data root — `statvfs("/")`, matching
/// `df` (used = blocks − free). This is the disk where images / volumes / vdisks physically live.
fn host_disk() -> Option<(u64, u64)> {
    let path = std::ffi::CString::new("/").ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let bs = st.f_frsize as u64;
    let total = st.f_blocks as u64 * bs;
    let used = (st.f_blocks as u64).saturating_sub(st.f_bfree as u64) * bs;
    Some((used, total))
}

/// The host's logical CPU count (per-CPU lines in `/proc/stat`), resolved once — the core count is
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
    let (load1, cores) = host_load_cores();
    (
        HostStats {
            mem_used,
            mem_total,
            disk_used,
            disk_total,
            cpu_pct,
            cores,
            load1,
            runs_total: 0,
            runs_per_sec: 0.0,
            runs_avg_us: 0,
            runs_peak: 0.0,
            runs_spark: Vec::new(),
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
    images: &[crate::commands::ImageEntry],
    cols: usize,
    term_rows: usize,
    sel: usize,
    mode: &Mode,
) -> String {
    let (b, c, d, g, z) = (p.b, p.c, p.d, p.g, p.z);
    let width = cols.clamp(40, 120);
    // Chrome around the content is ~8 lines (title 2 + tabs 1 + rule 1 + footer 3 + header 1); cap
    // the table so the frame never exceeds the screen and scrolls (which corrupts the alt-screen).
    let body_rows = term_rows.saturating_sub(9).max(1);
    let mut s = String::new();

    // Title bar — a live host header, always visible on every tab (CPU · RAM · Disk · Boxes),
    // refreshed each frame. The green figures are the "now"; the dim ones the total/context.
    s.push_str(&format!(
        "{b}{c} kern top{z}   {d}CPU{z} {g}{:>3.0}%{z} {d}/ {} cores{z}   {d}RAM{z} {g}{}{z}{d} / {}{z}   {d}Disk{z} {g}{}{z}{d} / {}{z}   {d}Boxes{z} {g}{}{z}\n\n",
        host.cpu_pct,
        host.cores,
        human_bytes(host.mem_used),
        human_bytes(host.mem_total),
        human_bytes(host.disk_used),
        human_bytes(host.disk_total),
        rows.len(),
    ));

    // Tab bar — active tab inverted, each data tab showing a LIVE count of its rows so you can see how
    // many boxes/profiles/volumes exist without entering the tab. Overview is an aggregate → no count.
    // Each tab carries a live count — but 7 counted tabs (~87 cols) overflow a narrow/80-col
    // terminal: the bar wraps and shoves the later tabs (Images/Builds/…) off screen. If the full
    // bar won't fit `width`, drop the counts and render just the names so every tab stays visible.
    let label = |i: usize, compact: bool| -> String {
        if compact {
            return TABS[i].to_string();
        }
        match i {
            TAB_BOXES => format!("{} ({})", TABS[i], rows.len()),
            TAB_IMAGES => format!("{} ({})", TABS[i], images.len()),
            TAB_BUILDS => format!("{} ({})", TABS[i], builds.len()),
            TAB_PROFILES => format!("{} ({})", TABS[i], profs.len()),
            TAB_STORAGE => format!("{} ({})", TABS[i], vols.len()),
            // Runs are fire-and-forget (~1 ms) — there's no "current items" set like the other tabs,
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
    let full_w = 1
        + (0..TABS.len())
            .map(|i| label(i, false).chars().count() + 3)
            .sum::<usize>();
    let compact = full_w > width;
    s.push(' ');
    for i in 0..TABS.len() {
        let l = label(i, compact);
        if i == tab {
            s.push_str(&format!("{b}\x1b[7m {l} \x1b[27m{z} "));
        } else {
            s.push_str(&format!("{d} {l} {z} "));
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
        Mode::Confirm { prompt, .. } => {
            s.push_str(&confirm_pane(p, prompt));
            format!("{d}[{z}y{d}] yes   [{z}any other{d}] no{z}")
        }
        Mode::Nav => {
            match tab {
                TAB_BOXES => s.push_str(&boxes_table(p, rows, body_rows, sel)),
                TAB_RUNS => s.push_str(&runs_table(p, host)),
                TAB_IMAGES => s.push_str(&images_table(p, images, body_rows, sel)),
                TAB_BUILDS => s.push_str(&builds_table(p, builds, body_rows, sel)),
                TAB_PROFILES => s.push_str(&profiles_table(p, profs, body_rows, sel)),
                TAB_STORAGE => s.push_str(&storage_table(p, vols, body_rows, sel)),
                _ => s.push_str(&overview(p, rows, host)),
            }
            nav_footer(p, tab, rows, profs, vols, builds, images)
        }
    };
    s.push_str(&format!("\n{d}{}{z}\n  {keys}\n", "─".repeat(width)));
    s
}

/// The `?` help overlay: the complete keymap + what each tab is for, in plain language. Rendered in the
/// read-only [`Mode::Overlay`] pane (any key closes it). First line is the bold title (see `text_pane`).
fn help_text() -> String {
    "kern top — keyboard help  (press any key to close)\n\
     \n\
     MOVE\n\
       Tab / → / l      next tab            ← / h      previous tab\n\
       1 2 3 4 5 6 7    jump to a tab       ↑ ↓ / j k  select a row\n\
       q  or  Ctrl-C    quit\n\
     \n\
     TABS — what each one shows\n\
       1 Overview   host CPU / RAM / load and the box totals\n\
       2 Boxes      every running box (pods grouped): MEM, CPU%, PIDS, HEALTH, PORTS\n\
     \x20                (yellow net:host / root-mapped / caps:+ flags a box LESS isolated than default)\n\
       3 Runs       kern run throughput: rate/sec, avg latency, peak, total (aggregate)\n\
       4 Images     cached OCI images: repository:tag, size, pulled age (like kern images)\n\
       5 Builds     build history: status, duration, size, age (like kern builds)\n\
       6 Profiles   reusable resource specs (vcpu / vgpio / vdisk) in kern.toml\n\
       7 Storage    physical disks (read-only) and your named volumes\n\
     \n\
     BOXES tab — act on the selected box\n\
       s  stop        p  pause        u  unpause        k  kill\n\
       Enter          view its logs (a box's own output)\n\
     \n\
     IMAGES tab\n\
       d  delete      p  prune orphaned layers          Enter  detail\n\
     \n\
     BUILDS tab\n\
       d  delete      Enter  view the build transcript\n\
     \n\
     PROFILES tab\n\
       n  new         e  edit         d  delete\n\
     \n\
     STORAGE tab\n\
       n  new         e  edit         d  delete        Enter  details        p  prune unused\n\
     \n\
     HEALTH colors:  green = healthy   red = unhealthy   dim = starting or no check\n\
     Destructive actions (delete / kill / prune) ask y / n first."
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
    // Every footer ends with a permanent `[?] help` — a first-time user doesn't know `?` exists until
    // it's shown, and `?` is where they find everything else. The hint to `?` is what discovers `?`.
    let help = format!("   [{z}?{d}] help{z}");
    match tab {
        TAB_BOXES if !rows.is_empty() => format!(
            "{d}[{z}↑↓{d}] select   [{z}s{d}]top [{z}p{d}]ause [{z}u{d}]npause [{z}k{d}]ill [{z}⏎{d}]logs   [{z}Tab{d}] next   [{z}q{d}] quit{help}"
        ),
        TAB_IMAGES if !images.is_empty() => format!(
            "{d}[{z}↑↓{d}] select   [{z}d{d}]elete [{z}p{d}]rune-layers [{z}⏎{d}]detail   [{z}Tab{d}] next   [{z}q{d}] quit{help}"
        ),
        TAB_BUILDS if !builds.is_empty() => format!(
            "{d}[{z}↑↓{d}] select   [{z}d{d}]elete [{z}⏎{d}]logs   [{z}Tab{d}] next   [{z}q{d}] quit{help}"
        ),
        TAB_PROFILES => {
            let edit = if profs.is_empty() { "" } else { " [e]dit [d]elete" };
            format!("{d}[{z}↑↓{d}] select   [{z}n{d}]ew{edit}   [{z}Tab{d}] next   [{z}q{d}] quit{help}")
        }
        TAB_STORAGE => {
            let ops = if vols.is_empty() {
                ""
            } else {
                " [e]dit [d]elete [⏎]info"
            };
            format!(
                "{d}[{z}↑↓{d}] select   [{z}n{d}]ew{ops} [{z}p{d}]rune   [{z}Tab{d}] next   [{z}q{d}] quit{help}"
            )
        }
        _ => format!(
            "{d}[{z}q{d}] quit   [{z}Tab{d}/{z}←→{d}] switch tab   [{z}1{d}-{z}7{d}] jump{help}"
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
/// up (accent caret / label / brackets) and shows the text cursor `▏` **at the insertion point** — right
/// after what you've typed, or at the very start (before the dim placeholder) when the field is empty —
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
                Some("Give the box real hardware. Not doing hardware work? Leave it empty — that's fine.")
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
        // cursor never lands on it — it's there only so you can SEE the machine has no such device.
        if f.is_dead_info() {
            s.push_str(&format!("    {d}{:<9}{z} {d}— {} —{z}\n", f.label, f.hint));
            continue;
        }
        // The Advanced fold row: a single toggle line that hides the rare knobs. Collapsed, it lists a
        // few of what's inside so the user knows there's more (and that they can ignore it).
        if f.divider {
            let n_adv = form.fields.iter().filter(|x| x.advanced).count();
            let cap = if form.show_advanced {
                "▾ Advanced — hide rare devices".to_string()
            } else {
                let names: Vec<&str> = form
                    .fields
                    .iter()
                    .filter(|x| x.advanced)
                    .map(|x| x.label)
                    .take(4)
                    .collect();
                let more = if n_adv > names.len() { ", …" } else { "" };
                format!("▸ Advanced — {n_adv} more: {}{more}", names.join(", "))
            };
            // No generic caret here — the ▸/▾ in the cap IS the pointer; accent colour shows focus.
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
        // A pick field renders detected devices as checkboxes — ←/→ highlight one, Space checks it.
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
        // A toggle renders as a checkbox `[x]`/`[ ]` with its hint as caption — no text box / cursor.
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
        // while it's still an incomplete-but-ok prefix (keep typing) — so "valid yet?" is never a guess.
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
    // Contextual help: what the FOCUSED field is and when you'd use it, with an everyday example — so
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

/// The Profiles "new" kind picker: vcpu / vgpio / vdisk, each attachable to a box by prefix.
fn pick_pane(p: &Palette) -> String {
    let (b, c, d, z) = (p.b, p.c, p.d, p.z);
    let row = |key: &str, name: &str, what: &str| {
        format!("    {b}[{c}{key}{b}]{z}  {b}{name:<8}{z}{d}{what}{z}\n")
    };
    let mut s = format!("\n  {b}new profile{z}  {d}— pick a kind:{z}\n\n");
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
/// reads at a glance which row the lifecycle keys act on. (Reverse-video is avoided — an embedded
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
/// its own dim styling. Cached — disks are fixed hardware, so `top` scans `/sys/block` once, not
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
        "\n  {d}reusable specs — attach to a box: {z}{c}kern box vcpu:heavy vgpio:leds vdisk:scratch …{z}\n"
    );
    // One titled sub-table per category, in a fixed order — an empty category still shows its header
    // + "none yet" so it's obvious the kind exists. `sel` is a flat index into `profs` (already sorted
    // by category then name), so the caret lands on the right row across sections; navigation is
    // unchanged. Headers are visual only — they don't consume a selection index.
    const CATS: [(&str, &str, &str); 3] = [
        ("vcpu", "vCPU", "CPU / memory slices"),
        ("vgpio", "vGPIO", "GPIO · I²C · device passthrough"),
        ("vdisk", "vDisk", "per-box scratch disks"),
    ];
    let mut budget = max_rows;
    for (section, title, desc) in CATS {
        s.push_str(&format!("\n  {b}{title}{z}  {d}— {desc}{z}\n"));
        let rows: Vec<(usize, &ProfRow)> = profs
            .iter()
            .enumerate()
            .filter(|(_, r)| r.section == section)
            .collect();
        if rows.is_empty() {
            s.push_str(&format!(
                "    {d}none yet — press {z}{g}n{z}{d} to add one{z}\n"
            ));
            continue;
        }
        for (i, r) in rows {
            if budget == 0 {
                s.push_str(&format!("    {d}…{z}\n"));
                break;
            }
            budget -= 1;
            let (lead, col) = sel_marker(p, i == sel);
            s.push_str(&format!(
                "  {lead}{col}{:<22}{z}  {d}{}{z}\n",
                trunc(&prof_label(r), 22),
                r.summary
            ));
        }
    }
    s
}

/// The Storage tab — the concrete data layer: the read-only physical disks, then the named volumes
/// (persistent storage you mount with `-v`). Per-box vdisks are *specs*, so they live in Profiles.
fn storage_table(
    p: &Palette,
    vols: &[crate::volume::VolInfo],
    max_rows: usize,
    sel: usize,
) -> String {
    let (b, c, d, g, z) = (p.b, p.c, p.d, p.g, p.z);
    let mut s = String::new();

    // Physical disks — read-only hardware; where volumes and vdisks physically live.
    if let Some(summary) = disks_summary() {
        s.push_str(&format!(
            "\n  {b}DISKS{z} {d}(physical, read-only){z}\n    {d}{summary}{z}\n"
        ));
    }

    s.push_str(&format!(
        "\n  {d}named volumes — persistent, shared: {z}{c}kern box -v NAME:/data …{z}  {d}(per-box vdisks are in Profiles){z}\n\n"
    ));
    s.push_str(&format!(
        "  {b}{:<24}  {:>10}  {:>10}{z}\n",
        "VOLUME", "SIZE", "QUOTA"
    ));
    if vols.is_empty() {
        s.push_str(&format!(
            "  {d}no volumes yet — press {z}{g}n{z}{d} to create one{z}\n"
        ));
        return s;
    }
    let shown = vols.len().min(max_rows);
    for (i, v) in vols[..shown].iter().enumerate() {
        let (lead, col) = sel_marker(p, i == sel);
        // No quota = UNLIMITED (the volume can grow until the disk is full). A bare `-` read as
        // "unset/error"; `∞` says "no cap" at a glance (the `?` help and the create form spell it out).
        // `kern_common::pad_visible` right-pads by COLUMN width (`∞` is 1 col / 3 bytes) — the colour is
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
            human_bytes(v.size),
            quota_cell
        ));
    }
    if shown < vols.len() {
        s.push_str(&format!("  {d}… {} more{z}\n", vols.len() - shown));
    }
    s
}

/// Compact large counts (`1.2k`, `3.4M`) for the runs metric — thousands of runs shouldn't sprawl.
fn human_count(n: u64) -> String {
    if n < 1_000 {
        n.to_string()
    } else if n < 1_000_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    }
}

/// The Overview tab: host resources first (the machine kern runs on), then the box aggregate.
fn overview(p: &Palette, rows: &[Row], host: &HostStats) -> String {
    let (b, d, z) = (p.b, p.d, p.z);
    let mut s = String::from("\n");
    let row = |k: &str, v: String| format!("  {b}{:<16}{z}{v}\n", k);

    // Host — the machine kern is running on (like the private's top).
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
    // Physical disks — read-only hardware, the pool a `vdisk:` profile's image lives on.
    if let Some(summary) = disks_summary() {
        s.push_str(&row("Disks", format!("{d}{summary}{z}")));
    }
    // `kern run` throughput lives on its own **Runs** tab (fire-and-forget capped processes) — Overview
    // stays the host + box picture. A one-line pointer only while runs actively stream (same > 0.5/s
    // threshold as the Runs-tab `⚡`, so the two never disagree), never a stale idle cumulative.
    if host.runs_per_sec > 0.5 {
        s.push_str(&row(
            "Runs",
            format!("{d}⚡ live — see the {z}{b}Runs{z}{d} tab{z}"),
        ));
    }

    // Boxes — the aggregate of what kern is running.
    let total_mem: u64 = rows.iter().filter_map(|r| r.mem).sum();
    // `pct()` normalises a stray `-0.0` (float rounding on an idle host) to a clean `0.0`.
    let total_cpu: f64 = pct(rows.iter().map(|r| r.cpu_pct).sum());
    let total_tasks: u64 = rows.iter().filter_map(|r| r.tasks).sum();
    let cap = if rows.iter().any(|r| r.mem.is_some()) {
        "yes (systemd cgroup scope)"
    } else {
        "no dedicated cgroup"
    };
    s.push_str(&format!("\n  {b}BOXES{z}\n"));
    s.push_str(&row("Running", format!("{}", rows.len())));
    s.push_str(&row("Memory", human_bytes(total_mem)));
    s.push_str(&row("CPU", format!("{total_cpu:.1} %")));
    s.push_str(&row("Tasks", format!("{total_tasks}")));
    s.push_str(&row("Resource cap", format!("{d}{cap}{z}")));
    if rows.is_empty() {
        s.push_str(&format!(
            "\n  {d}no running boxes — start one with `kern box <name> -d …`{z}\n"
        ));
    }
    s
}

/// A tiny unicode-block sparkline of `samples`, scaled to their own max — a compact recent-shape glyph
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

/// The Runs tab. `kern run` is fire-and-forget (~1 ms, no sandbox, exec-in-place, not registered), so it
/// has NO per-row list — it's shown as **aggregate throughput**. Every figure here is really measured
/// from the daemonless mmap counter: the live rate, the honest average setup latency (entry→exec — this
/// IS the "~1 ms"), the session-peak rate, the cumulative total, and a recent-shape sparkline.
/// Deliberately NOT shown: "active / peak concurrent" — unmeasurable without a per-run reaper that would
/// defeat the whole point of a ~1 ms run, so we don't invent it.
fn runs_table(p: &Palette, host: &HostStats) -> String {
    let (b, c, d, g, z) = (p.b, p.c, p.d, p.g, p.z);
    let row = |k: &str, v: String| format!("  {b}{:<14}{z}{v}\n", k);
    let mut s = String::new();
    s.push_str(&format!(
        "\n  {b}Runs{z}{d} = fast, CPU/memory-capped commands — {z}{c}kern run -- <cmd>{z}{d} — with {z}{b}no sandbox{z}{d}, gone in ~1 ms.{z}\n"
    ));
    s.push_str(&format!(
        "  {d}A run is {z}{b}NOT a container{z}{d}: for an isolated box, use the {z}{c}Boxes{z}{d} tab. Runs are too fast/many to{z}\n"
    ));
    s.push_str(&format!(
        "  {d}list one-by-one, so this tab {z}{b}counts{z}{d} them as live throughput (what Docker can't do at scale).{z}\n\n"
    ));

    if host.runs_total == 0 {
        s.push_str(&format!(
            "  {d}no runs yet — fire capped processes with {z}{c}kern run -- <cmd>{z}\n"
        ));
        s.push_str(&format!(
            "  {d}e.g.  {z}{c}for i in $(seq 1000); do kern run -- true; done{z}\n\n"
        ));
        s.push_str(&format!(
            "  {d}a run is a CPU/mem-capped process with no sandbox — Docker has no analogue this fast.{z}\n"
        ));
        return s;
    }

    let rate = host.runs_per_sec.round().max(0.0) as u64;
    let per_min = (host.runs_per_sec * 60.0).round().max(0.0) as u64;
    // Live rate is green while streaming, dim when idle (0/s) — the number is the honest "now".
    let rate_col = if host.runs_per_sec > 0.5 { g } else { d };
    s.push_str(&row(
        "Speed",
        format!(
            "{rate_col}{} {d}runs/sec{z}   {d}({}/min){z}",
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
            "{} {d}runs/sec · session max{z}",
            human_count(host.runs_peak.round().max(0.0) as u64)
        ),
    ));
    s.push_str(&row(
        "Total",
        format!(
            "{} {d}runs, so far this session{z}",
            human_count(host.runs_total)
        ),
    ));

    // Recent-shape sparkline of runs/sec (the reader-side ring). When the whole window is idle, an
    // all-`▁` baseline rendered green looks like a growing bar next to "0 /s" (confusing) — so show a
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
                "\n  {b}{:<14}{z}{d}idle — no runs in the last window{z}\n",
                "Recent"
            ));
        }
    }

    s.push_str(&format!(
        "\n  {d}runs = capped processes (CPU/mem cgroup, no sandbox), fire-and-forget — shown as{z}\n"
    ));
    s.push_str(&format!(
        "  {d}aggregate throughput, not a per-row list. This is what Docker can't do at scale.{z}\n"
    ));
    s
}

/// The Images tab: cached OCI images (`repository` + `tag` split, size, pulled age) — a read-only
/// in-`top` mirror of `kern images`, sourced from the exact same [`crate::commands::image_entries`] so
/// the two never drift. `repository:tag` is split on the last `:` (unless that tail holds a `/`, i.e. a
/// `host:port/…` reference with no explicit tag → shown as `latest`).
fn images_table(
    p: &Palette,
    images: &[crate::commands::ImageEntry],
    max_rows: usize,
    sel: usize,
) -> String {
    let (b, c, d, y, z) = (p.b, p.c, p.d, p.y, p.z);
    let cut = |s: &str, n: usize| -> String { s.chars().take(n).collect() };
    let mut s = format!("\n  {d}cached images — {z}{c}kern pull <image>{z}{d} · name order{z}\n\n");
    s.push_str(&format!(
        "  {b}{:<24} {:<14} {:>9}  PULLED{z}\n",
        "REPOSITORY", "TAG", "SIZE"
    ));
    if images.is_empty() {
        s.push_str(&format!(
            "  {d}no images yet — pull one with {z}{c}kern pull alpine{z}\n"
        ));
        return s;
    }
    let now = registry::now_unix();
    let shown = images.len().min(max_rows);
    for (i, img) in images[..shown].iter().enumerate() {
        let (lead, col) = sel_marker(p, i == sel);
        let (repo, tag) = match img.name.rsplit_once(':') {
            Some((r, t)) if !t.contains('/') => (r, t),
            _ => (img.name.as_str(), "latest"),
        };
        // A dangling image (layers gone) shows `dangling` in yellow, never a misleading `0 B`. The ref is
        // untrusted `.ok` content — scrub escapes before the raw alt-screen (as image_detail / the CLI do).
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
    if shown < images.len() {
        s.push_str(&format!("  {d}… {} more{z}\n", images.len() - shown));
    }
    s
}

/// The Boxes tab: a per-box table, capped to `max_rows` so it never overflows the screen. `sel` is the
/// highlighted row (the target of the lifecycle keys), marked with a `›` and reverse-video.
/// The Builds tab: `kern build` history (newest first) — id, tag, coloured status (+ warning count),
/// duration, size, age. A read-only in-`top` mirror of `kern builds`.
fn builds_table(
    p: &Palette,
    builds: &[crate::builds::Record],
    max_rows: usize,
    sel: usize,
) -> String {
    let (b, c, d, g, y, r, z) = (p.b, p.c, p.d, p.g, p.y, p.r, p.z);
    let cut = |s: &str, n: usize| -> String { s.chars().take(n).collect() };
    let mut s = String::new();
    s.push_str(&format!(
        "\n  {d}build history — {z}{c}kern build -t NAME .{z}{d} · newest first{z}\n\n"
    ));
    s.push_str(&format!(
        "  {b}{:<18} {:<16} {:<11} {:>8} {:>9}  CREATED{z}\n",
        "ID", "TAG", "STATUS", "TIME", "SIZE"
    ));
    if builds.is_empty() {
        s.push_str(&format!(
            "  {d}no builds yet — run {z}{g}kern build -t app .{z}\n"
        ));
        return s;
    }
    let now = registry::now_unix();
    let shown = builds.len().min(max_rows);
    for (i, bd) in builds[..shown].iter().enumerate() {
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
    if shown < builds.len() {
        s.push_str(&format!("  {d}… {} more{z}\n", builds.len() - shown));
    }
    s
}

fn boxes_table(p: &Palette, rows: &[Row], max_rows: usize, sel: usize) -> String {
    let (b, c, d, g, y, z) = (p.b, p.c, p.d, p.g, p.y, p.z);
    let mut s = String::new();
    s.push_str(&format!(
        "    {b}{:<16}  {:>7}  {:>8}  {:>8}  {:>5}  {:>4}  {:<9}  {:<14}  STATUS{z}\n",
        "NAME", "PID", "UPTIME", "MEM", "CPU%", "PIDS", "HEALTH", "PORTS"
    ));
    if rows.is_empty() {
        s.push_str(&format!("  {d}no running boxes{z}\n"));
        return s;
    }
    let shown = rows.len().min(max_rows);
    let mut prev_pod = "";
    for (i, r) in rows[..shown].iter().enumerate() {
        // Pod header when entering a new pod group — the `kern ps` tree view: standalone boxes are
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
        } else if i + 1 >= shown || rows[i + 1].pod != r.pod {
            "└─ ".to_string()
        } else {
            "├─ ".to_string()
        };
        let name_cell = format!(
            "{connector}{}",
            trunc(&r.name, 16usize.saturating_sub(connector.chars().count()))
        );

        let mem = r.mem.map_or("-".into(), human_bytes);
        let tasks = r.tasks.map_or("-".into(), |n| n.to_string());
        let status = if r.paused {
            format!("{d}paused{z}")
        } else {
            format!("{g}running{z}")
        };
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
        // Trailing flag only when the box is LESS isolated than default (net:host / root-mapped) — in
        // yellow so it reads as "heads-up", never a green all-clear badge.
        let iso = if r.iso.is_empty() {
            String::new()
        } else {
            format!("  {y}{}{z}", r.iso)
        };
        let (lead, name_col) = sel_marker(p, i == sel);
        s.push_str(&format!(
            "  {lead}{name_col}{:<16}{z}  {:>7}  {:>8}  {:>8}  {:>4.0}%  {:>4}  {health}  {ports}  {status}{iso}\n",
            name_cell,
            r.pid,
            fmt_uptime(r.uptime),
            mem,
            pct(r.cpu_pct),
            tasks
        ));
    }
    if shown < rows.len() {
        s.push_str(&format!("  {d}… {} more{z}\n", rows.len() - shown));
    }
    s
}

/// Normalise a CPU% for display: clamp to ≥ 0 and collapse a signed zero (`-0.0`) to a clean `0.0`.
/// (`f64::max(-0.0, 0.0)` may keep the sign, which then prints as "-0" — an idle-host eyesore.)
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
        }
    }

    #[test]
    fn boxes_flag_only_reduced_isolation_never_a_secure_badge() {
        // A default (fully isolated) box carries NO isolation marker — no vanity "secure" badge.
        let out = boxes_table(&plain(), &[row("safe", false)], 10, usize::MAX);
        let safe = out.lines().find(|l| l.contains("safe")).unwrap();
        assert!(
            !safe.contains("net:host") && !safe.contains("root-mapped"),
            "an isolated box shows no deviation flag: {safe}"
        );
        // A box that deviates (net:host / root-mapped / caps:+) surfaces exactly that, as a heads-up.
        let mut r = row("loose", false);
        r.iso = "net:host root-mapped caps:+".into();
        let out2 = boxes_table(&plain(), &[r], 10, usize::MAX);
        let loose = out2.lines().find(|l| l.contains("loose")).unwrap();
        assert!(
            loose.contains("net:host") && loose.contains("root-mapped") && loose.contains("caps:+"),
            "a less-confined box flags its deviations: {loose}"
        );
    }

    #[test]
    fn selected_row_gets_a_caret() {
        let rows = [row("web", false), row("db", false)];
        let out = boxes_table(&plain(), &rows, 10, 1); // db selected
        let line = out.lines().find(|l| l.contains("db")).unwrap();
        assert!(line.contains('›'), "selected row should show the caret");
        let web = out.lines().find(|l| l.contains("web")).unwrap();
        assert!(!web.contains('›'), "unselected row must not show the caret");
    }

    #[test]
    fn boxes_table_shows_health_and_ports_like_ps() {
        // A box with a healthcheck + published port must surface both in the TUI, matching `kern ps`.
        let mut r = row("web", false);
        r.health = "healthy".into();
        r.ports = "8080->80".into();
        let out = boxes_table(&plain(), &[r], 10, 0);
        assert!(out.contains("HEALTH"), "header must include HEALTH");
        assert!(out.contains("PORTS"), "header must include PORTS");
        assert!(out.contains("healthy"), "row must show the health state");
        assert!(out.contains("8080->80"), "row must show the ports");
        // A box with no healthcheck / no ports shows a dim `-`, never an empty gap.
        let out2 = boxes_table(&plain(), &[row("db", false)], 10, 0);
        let dbrow = out2.lines().find(|l| l.contains("db")).unwrap();
        assert!(dbrow.contains('-'), "no-health/no-ports row shows a dash");
    }

    #[test]
    fn tab_bar_shows_live_counts() {
        // The tab bar shows a live count per data tab (Boxes/Profiles/Storage) so you see how many
        // items exist without entering — Overview (an aggregate) has no count.
        let host = HostStats {
            mem_used: 0,
            mem_total: 1,
            disk_used: 0,
            disk_total: 1,
            cpu_pct: 0.0,
            cores: 1,
            load1: 0.0,
            runs_total: 0,
            runs_per_sec: 0.0,
            runs_avg_us: 0,
            runs_peak: 0.0,
            runs_spark: Vec::new(),
        };
        let boxes = [row("a", false), row("b", false), row("c", false)];
        // A wide terminal (≥ the ~87-col full bar) shows the live counts.
        let out = render(
            &plain(),
            TAB_BOXES,
            &boxes,
            &host,
            &[],
            &[],
            &[],
            &[],
            100,
            24,
            0,
            &Mode::Nav,
        );
        // 3 boxes, 0 profiles, 0 volumes.
        assert!(
            out.contains("Boxes (3)"),
            "Boxes tab shows its count: {out}"
        );
        assert!(out.contains("Profiles (0)"), "Profiles tab shows 0");
        assert!(out.contains("Storage (0)"), "Storage tab shows 0");
        assert!(out.contains("Overview"), "Overview stays uncounted");
        assert!(
            !out.contains("Overview ("),
            "Overview must NOT carry a count"
        );

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
            &[],
            80,
            24,
            0,
            &Mode::Nav,
        );
        assert!(!narrow.contains("Boxes (3)"), "narrow bar drops counts");
        for t in [
            "Overview", "Boxes", "Runs", "Images", "Builds", "Profiles", "Storage",
        ] {
            assert!(
                narrow.contains(t),
                "narrow bar keeps every tab: missing {t}"
            );
        }
    }

    #[test]
    fn storage_shows_infinity_for_unlimited_quota() {
        // A volume with no quota is UNLIMITED — show `∞`, not an ambiguous `-`. A capped one shows the
        // human size. (The bug: `-` read as "unset/error" instead of "no cap".)
        let vols = [
            crate::volume::VolInfo {
                name: "boundless".into(),
                size: 11,
                quota: None,
            },
            crate::volume::VolInfo {
                name: "capped".into(),
                size: 0,
                quota: Some(2 * 1024 * 1024 * 1024),
            },
        ];
        let out = storage_table(&plain(), &vols, 10, 0);
        assert!(out.contains('∞'), "unlimited quota shows ∞: {out}");
        assert!(!out.contains(" - "), "no bare dash for the quota column");
        assert!(out.contains("2G"), "a capped quota shows its size");
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
        let out = boxes_table(&plain(), &rows, 10, usize::MAX); // snapshot mode
        assert!(!out.contains('›'));
    }

    #[test]
    fn negative_zero_cpu_renders_as_zero() {
        let mut rows = [row("web", false)];
        rows[0].cpu_pct = -0.0;
        let out = boxes_table(&plain(), &rows, 10, usize::MAX);
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
            tf("vcpus", "4"),
            tf("cpus", "0-3"),
            tf("memory", ""), // empty → skipped
            tf("priority", "10"),
        ];
        let (name, body) = form_to_body(&fields).unwrap();
        assert_eq!(name, "heavy");
        assert!(body.contains(&"name = \"heavy\"".to_string()));
        assert!(body.contains(&"vcpus = 4".to_string()));
        assert!(body.contains(&"cpus = \"0-3\"".to_string()));
        assert!(body.contains(&"priority = 10".to_string()));
        assert!(
            !body.iter().any(|l| l.starts_with("memory")),
            "empty field skipped"
        );

        // A bad number is rejected with a message, not silently written.
        let bad = vec![tf("name", "x"), tf("vcpus", "abc")];
        assert!(form_to_body(&bad).is_err());

        // A missing name is rejected.
        let noname = vec![tf("name", "  ")];
        assert!(form_to_body(&noname).is_err());
    }

    #[test]
    fn persistent_is_a_toggle_not_free_text() {
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
            tf("vcpus", "4"),
            tf("cpus", "0-3"),
            tf("memory", "512m"),
            tf("priority", "10"),
        ];
        let (_name, from_form) = form_to_body(&fields).unwrap();
        let from_cli = crate::config::profile_block(
            "heavy",
            &[
                ("vcpus", "4"),
                ("cpus", "0-3"),
                ("memory", "512m"),
                ("priority", "10"),
            ],
        )
        .unwrap();
        assert_eq!(from_form, from_cli);
    }

    #[test]
    fn edit_form_round_trips_every_field_losslessly() {
        // A profile hand-written with the full field set, loaded into the edit form and re-serialised,
        // must reproduce every field — no CLI-only / hand-edit-only field is dropped by an edit cycle.
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
            "[[vcpu]]\nname=\"h\"\nvcpus=4\nnuma=1\nnice=-5\nextends=\"base\"\n",
        )
        .unwrap();
        let (_n, b2) = form_to_body(&edit_profile_form("vcpu", "h", &cfg2).fields).unwrap();
        for e in ["vcpus = 4", "numa = 1", "nice = -5", "extends = \"base\""] {
            assert!(b2.iter().any(|l| l == e), "vcpu lost {e}: {b2:?}");
        }
    }

    #[test]
    fn active_field_cursor_sits_at_the_insertion_point() {
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
        // A bus NOT detected here is still kept (canonicalized) as a checked extra — lossless.
        let mut g = Field::pick("i2c", "h", vec!["/dev/i2c-0".into()]);
        g.value = "i2c-0, 9".into();
        g.seed_pick_selection();
        assert_eq!(g.options, vec!["/dev/i2c-0", "/dev/i2c-9"]);
        assert_eq!(g.sel, vec![true, true]);
    }

    #[test]
    fn vgpio_form_does_not_offer_net_a_field_the_resolver_ignores() {
        // `net` in a vgpio profile is inert (the resolver never attaches an interface), so the form
        // must not advertise it — offering a knob that does nothing is exactly the "misleading" trap.
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
        // Noise: NIC PHY LEDs and keyboard LEDs — never a meaningful sandbox device.
        for noise in [
            "enp5s0-0::lan",
            "enp5s0::act",
            "wlp4s0-1::wlan",
            "input3::capslock",
        ] {
            assert!(!is_board_led(noise, &nets), "{noise} should be dropped");
        }
        // Real board LEDs — kept. 'logo' starts with 'lo' but isn't the 'lo' iface → kept.
        for led in ["led0", "ACT", "PWR", "mmc0::activity", "default-on", "logo"] {
            assert!(is_board_led(led, &nets), "{led} should be kept");
        }
    }

    #[test]
    fn every_profile_field_is_guarded_for_all_kinds() {
        // EXTREME, for all vprofiles: no field in ANY profile form is unguarded free text. Each field
        // is validated by the field_state authority (numbers / name / sizes), a picker/radio selection,
        // a boolean toggle, or a "none here / explanatory" note — with ONE documented exception, the
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
                    "{kind} field {:?} is UNGUARDED free text — make it validated / a pick / a note",
                    f.label
                );
            }
        }
    }

    #[test]
    fn backend_is_a_selection_never_a_free_text_box() {
        // `backend` names a configured id (gpio/cpu/disk) — so for EVERY kind it must be a picker of
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
        // Whatever field is focused, the form shows a concrete "what is this / when to use it" line at
        // the bottom — the user is guided, never left guessing what to enter.
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
                FormOutcome::Cancel => return String::new(), // Esc aborts — nothing typed
            }
        }
        form.fields.into_iter().next().unwrap().value
    }

    #[test]
    fn extreme_typing_never_reaches_an_invalid_or_unsavable_value() {
        // Hammer every typed numeric/size field with adversarial byte strings and assert two things:
        //  (1) the accumulated value is NEVER config::field_state == Invalid (the filter never lets a
        //      dead value stick), and
        //  (2) whenever it IS Valid, config::profile_line accepts it — no value can dead-end at save.
        use crate::config::{field_state, profile_line, FieldState};
        let fields: &[(&str, &str)] = &[
            ("vgpio", "pins"),
            ("vgpio", "pwm"),
            ("vgpio", "adc"),
            ("vgpio", "onewire"),
            ("vcpu", "priority"),
            ("vcpu", "numa"),
            ("vcpu", "nice"),
            ("vcpu", "vcpus"),
            ("vcpu", "cpus"),
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
            ("priority", "99"),
            ("numa", "3"),
            ("nice", "-20"),
            ("nice", "19"),
            ("vcpus", "0.5"),
            ("vcpus", "16"),
            ("cpus", "0-3"),
            ("cpus", "0,2,4"),
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
        // vcpus "0" is an incomplete prefix (of "0.5") → "keep typing", not a green tick.
        let form = feed(mk("vcpus"), b"0");
        let pane = form_pane(&plain(), &form, 80, 24);
        assert!(
            pane.contains("keep typing"),
            "incomplete shows a hint:\n{pane}"
        );
        // "0.5" is complete → a ✓.
        let form = feed(mk("vcpus"), b"0.5");
        let pane = form_pane(&plain(), &form, 80, 24);
        assert!(pane.contains('✓'), "valid shows a tick:\n{pane}");
    }

    #[test]
    fn radio_field_holds_a_single_value() {
        // A radio (single-select) pick — like `backend` — can never reach the invalid multi-value
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
        // pwm/pins/adc are line NUMBERS — typing letters must do nothing, so `1dfdf` can't happen.
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
        // pins: `44545454545` stops the moment the number would exceed the range — never the garbage.
        let f = feed(mk("vgpio", "pins"), b"44545454545");
        assert!(
            f.fields[0].value.parse::<u32>().unwrap() < crate::config::MAX_GPIO_PIN,
            "pins capped in range, got {:?}",
            f.fields[0].value
        );
        assert_ne!(f.fields[0].value, "44545454545");
        // A valid multi-pin list still types fine.
        assert_eq!(feed(mk("vgpio", "pins"), b"17 27").fields[0].value, "17 27");
        // priority 0-99: `100` can't be reached.
        assert_eq!(feed(mk("vcpu", "priority"), b"100").fields[0].value, "10");
        // nice -20..19: `20` can't be reached, but `-20` can.
        assert_eq!(feed(mk("vcpu", "nice"), b"20").fields[0].value, "2");
        assert_eq!(feed(mk("vcpu", "nice"), b"-20").fields[0].value, "-20");
        // vcpus: a second dot is refused (`1.2.` → `1.2`).
        assert_eq!(feed(mk("vcpu", "vcpus"), b"1.2.5").fields[0].value, "1.25");
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
        // nothing — so a beginner can NEVER put garbage into, say, `spi` on a machine without SPI.
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
