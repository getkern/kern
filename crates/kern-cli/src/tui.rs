//! `kern top` — a small, dependency-free task-manager TUI over the box registry. Same htop-style
//! feel as the matrix's `kern top` (alternate screen, tabs, live refresh, keyboard nav) but
//! **boxes-only** — the public build has no GPU/vCPU/intelligence to monitor. Pure `libc` termios
//! + ANSI, no curses/ratatui dependency.
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

const TABS: [&str; 2] = ["Overview", "Boxes"];

/// A box row with its frame-to-frame CPU%.
struct Row {
    name: String,
    pid: i32,
    uptime: u64,
    mem: Option<u64>,
    cpu_pct: f64,
    tasks: Option<u64>,
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
    let mut prev: HashMap<i32, (u64, Instant)> = HashMap::new();

    loop {
        let (cols, term_rows) = term_size();
        let (rows, seen) = collect_rows(&prev);
        prev = seen;

        let frame = render(&p, tab, &rows, cols, term_rows);
        // Clear each line to end-of-line (`\x1b[K`) so a shorter/blank line in the new frame wipes
        // any leftover text from the previous one (no residue, no flicker), then erase everything
        // below the frame (`\x1b[J`) in case the new frame has fewer lines.
        let painted = frame.replace('\n', "\x1b[K\n");
        let _ = out.write_all(b"\x1b[H"); // cursor home
        let _ = out.write_all(painted.as_bytes());
        let _ = out.write_all(b"\x1b[J");
        let _ = out.flush();

        // Wait up to ~1s for a key; refresh on timeout.
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pfd, 1, 1000) } > 0 {
            let mut buf = [0u8; 8];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                continue;
            }
            match buf[0] {
                b'q' | b'Q' | 0x03 => break, // q / Ctrl-C
                b'\t' | b'l' => tab = (tab + 1) % TABS.len(),
                b'h' => tab = (tab + TABS.len() - 1) % TABS.len(),
                b'1' => tab = 0,
                b'2' => tab = 1,
                0x1b => {
                    if n >= 3 && buf[1] == b'[' {
                        match buf[2] {
                            b'C' => tab = (tab + 1) % TABS.len(),              // →
                            b'D' => tab = (tab + TABS.len() - 1) % TABS.len(), // ←
                            _ => {}
                        }
                    } else {
                        break; // lone Esc = quit
                    }
                }
                _ => {}
            }
        }
    }
    Ok(()) // _guard restores the terminal on drop
}

/// Snapshot the Boxes table once (used when stdout is not a TTY — e.g. piped).
pub fn snapshot() -> Result<(), crate::error::Error> {
    let p = Palette::detect();
    let (rows, _) = collect_rows(&HashMap::new());
    print!("{}", boxes_table(&p, &rows, usize::MAX));
    Ok(())
}

/// Read the registry and compute each box's frame-to-frame CPU%, returning the rows and the new
/// `(cpu_usec, instant)` map for the next frame.
fn collect_rows(prev: &HashMap<i32, (u64, Instant)>) -> (Vec<Row>, HashMap<i32, (u64, Instant)>) {
    let now_t = Instant::now();
    let now_u = registry::now_unix();
    let mut seen = HashMap::new();
    let mut rows = Vec::new();
    for b in registry::list() {
        let cpu_now = registry::cpu_usec(b.pid).unwrap_or(0);
        let cpu_pct = match prev.get(&b.pid) {
            Some((pu, t)) => {
                let dt = now_t.duration_since(*t).as_secs_f64().max(1e-6);
                (cpu_now.saturating_sub(*pu) as f64 / 1e6 / dt) * 100.0
            }
            None => 0.0,
        };
        seen.insert(b.pid, (cpu_now, now_t));
        rows.push(Row {
            uptime: now_u.saturating_sub(b.started),
            mem: registry::mem_bytes(b.pid),
            tasks: registry::tasks(b.pid),
            cpu_pct,
            name: b.name,
            pid: b.pid,
        });
    }
    (rows, seen)
}

/// Build a full frame for the active `tab`.
fn render(p: &Palette, tab: usize, rows: &[Row], cols: usize, term_rows: usize) -> String {
    let (b, c, d, z) = (p.b, p.c, p.d, p.z);
    let width = cols.clamp(40, 120);
    // Chrome around the content is ~8 lines (title 2 + tabs 1 + rule 1 + footer 3 + header 1); cap
    // the table so the frame never exceeds the screen and scrolls (which corrupts the alt-screen).
    let body_rows = term_rows.saturating_sub(9).max(1);
    let mut s = String::new();

    // Title bar.
    s.push_str(&format!(
        "{b}{c} kern top{z}  {d}{} box(es) running{z}\n\n",
        rows.len()
    ));

    // Tab bar — active tab inverted.
    s.push(' ');
    for (i, name) in TABS.iter().enumerate() {
        if i == tab {
            s.push_str(&format!("{b}\x1b[7m {name} \x1b[27m{z} "));
        } else {
            s.push_str(&format!("{d} {name} {z} "));
        }
    }
    s.push('\n');
    s.push_str(&format!("{d}{}{z}\n", "─".repeat(width)));

    match tab {
        0 => s.push_str(&overview(p, rows)),
        _ => s.push_str(&boxes_table(p, rows, body_rows)),
    }

    // Footer hint bar.
    s.push_str(&format!(
        "\n{d}{}{z}\n  {d}[{z}q{d}] quit   [{z}Tab{d}/{z}←→{d}] switch tab   [{z}1{d}/{z}2{d}] jump{z}\n",
        "─".repeat(width)
    ));
    s
}

/// The Overview tab: aggregate stats.
fn overview(p: &Palette, rows: &[Row]) -> String {
    let (b, d, z) = (p.b, p.d, p.z);
    let total_mem: u64 = rows.iter().filter_map(|r| r.mem).sum();
    let total_cpu: f64 = rows.iter().map(|r| r.cpu_pct).sum();
    let total_tasks: u64 = rows.iter().filter_map(|r| r.tasks).sum();
    let cap = if rows.iter().any(|r| r.mem.is_some()) {
        "yes (systemd cgroup scope)"
    } else {
        "no dedicated cgroup"
    };
    let mut s = String::from("\n");
    let row = |k: &str, v: String| format!("  {b}{:<16}{z}{v}\n", k);
    s.push_str(&row("Boxes running", format!("{}", rows.len())));
    s.push_str(&row("Total memory", human_bytes(total_mem)));
    s.push_str(&row("Total CPU", format!("{total_cpu:.1} %")));
    s.push_str(&row("Total tasks", format!("{total_tasks}")));
    s.push_str(&row("Resource cap", format!("{d}{cap}{z}")));
    if rows.is_empty() {
        s.push_str(&format!(
            "\n  {d}no running boxes — start one with `kern box <name> -d …`{z}\n"
        ));
    }
    s
}

/// The Boxes tab: a per-box table, capped to `max_rows` so it never overflows the screen.
fn boxes_table(p: &Palette, rows: &[Row], max_rows: usize) -> String {
    let (b, c, d, g, z) = (p.b, p.c, p.d, p.g, p.z);
    let mut s = String::new();
    s.push_str(&format!(
        "  {b}{:<16}  {:>7}  {:>9}  {:>9}  {:>6}  {:>5}  STATUS{z}\n",
        "NAME", "PID", "UPTIME", "MEM", "CPU%", "PIDS"
    ));
    if rows.is_empty() {
        s.push_str(&format!("  {d}no running boxes{z}\n"));
        return s;
    }
    let shown = rows.len().min(max_rows);
    for r in &rows[..shown] {
        let mem = r.mem.map_or("-".into(), human_bytes);
        let tasks = r.tasks.map_or("-".into(), |n| n.to_string());
        s.push_str(&format!(
            "  {c}{:<16}{z}  {:>7}  {:>9}  {:>9}  {:>5.0}%  {:>5}  {g}running{z}\n",
            trunc(&r.name, 16),
            r.pid,
            fmt_uptime(r.uptime),
            mem,
            r.cpu_pct,
            tasks
        ));
    }
    if shown < rows.len() {
        s.push_str(&format!("  {d}… {} more{z}\n", rows.len() - shown));
    }
    s
}

/// Truncate to `max` chars (char-safe).
fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}
