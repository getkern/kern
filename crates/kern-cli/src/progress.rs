//! `--progress auto|tty|plain|json|quiet` for `kern build` and `kern compose`: the mode, and the
//! events and live view built on it. The mode itself lives in `kern_common` (`ProgressMode`), where
//! the `progress!` narrator reads it; this module takes the flag off the command line, emits the
//! events, and draws the live view.

use kern_common::ProgressMode;

/// Compose verbs after which `--progress` is still kern's: they take flags and service names, never
/// a command of their own. After `run` or `exec` the rest is the box's command line, and a
/// `--progress` there (`npm --progress=false`) belongs to it.
const COMPOSE_VERBS_WITH_PROGRESS: [&str; 6] =
    ["up", "build", "pull", "create", "start", "restart"];

/// Take `--progress <mode>` (or `--progress=<mode>`) off a `kern build` / `kern compose` command line,
/// put the mode in force for this process and for every kern it starts (`KERN_PROGRESS`), and return
/// the rest. Other commands are returned unchanged. An unknown mode is refused.
pub fn take_progress_flag(args: &[String]) -> Result<Vec<String>, crate::error::Error> {
    let first = args.first().map(String::as_str);
    if !matches!(first, Some("build" | "compose")) {
        return Ok(args.to_vec());
    }
    let compose = first == Some("compose");
    let verbs: Vec<&str> = crate::commands::COMPOSE_VERBS
        .iter()
        .map(|(n, _)| *n)
        .collect();
    let mut out: Vec<String> = Vec::with_capacity(args.len());
    let mut mode: Option<ProgressMode> = None;
    let mut verb: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            out.extend(args[i..].iter().cloned());
            break;
        }
        if compose && verb.is_none() && i > 0 && verbs.contains(&a) {
            verb = Some(a);
        }
        let ours = !compose || verb.is_none_or(|v| COMPOSE_VERBS_WITH_PROGRESS.contains(&v));
        let value = if !ours {
            None
        } else if a == "--progress" {
            i += 1;
            Some(args.get(i).map(String::as_str).unwrap_or(""))
        } else {
            a.strip_prefix("--progress=")
        };
        match value {
            Some(v) => {
                mode = Some(ProgressMode::parse(v).ok_or(crate::error::Error::Usage(
                    "--progress auto|tty|plain|json|quiet",
                ))?);
            }
            None => out.push(args[i].clone()),
        }
        i += 1;
    }
    if let Some(m) = mode {
        kern_common::set_progress_mode(m);
        crate::set_global_env("KERN_PROGRESS", m.word());
    }
    Ok(out)
}

/// The live view's event pipe (write end), `-1` when no view is drawing.
static BOARD_EVENTS: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// A service changed state: a `service` event in `json` mode, a row of the live view in `tty` mode
/// when one is drawing, nothing otherwise. `state` is one word (`pulling`, `building`, `waiting`,
/// `starting`, `running`, `healthy`, `exited`, `failed`, `skipped`).
pub fn service(name: &str, state: &str, detail: &str) {
    use kern_common::json_str;
    kern_common::progress_event(
        "service",
        &format!(
            "\"service\":{},\"state\":{},\"detail\":{}",
            json_str(name),
            json_str(state),
            json_str(detail)
        ),
    );
    let fd = BOARD_EVENTS.load(std::sync::atomic::Ordering::Acquire);
    if fd < 0 {
        return;
    }
    let clean = |s: &str| -> String {
        s.chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(300)
            .collect()
    };
    let line = format!("S\t{}\t{}\t{}\n", clean(name), clean(state), clean(detail));
    // One write under PIPE_BUF: lines from concurrent workers never interleave.
    // SAFETY: `line` is a live buffer; a failed write only loses a row update.
    unsafe { libc::write(fd, line.as_ptr().cast(), line.len()) };
}

/// What a compose service waits for, as its row says it: every dependency, started, healthy or
/// completed.
pub fn deps_of(b: &crate::compose::ComposeBox) -> String {
    let mut all: Vec<String> = b.depends_on.clone();
    for d in b.depends_healthy.iter().chain(&b.depends_completed) {
        if !all.contains(d) {
            all.push(d.clone());
        }
    }
    all.join(", ")
}

/// The sentence an interrupted command leaves, prepared before the signal (see [`say_on_interrupt`]).
static INTERRUPT_NOTE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

extern "C" fn on_interrupt(sig: libc::c_int) {
    if let Some(note) = INTERRUPT_NOTE.get() {
        // SAFETY: `write` on a static buffer is async-signal-safe.
        unsafe { libc::write(2, note.as_ptr().cast(), note.len()) };
    }
    // SAFETY: back to the default action and raised again, so the command ends as it would have.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// On Ctrl-C (or SIGTERM) from here on, print `note` before the command ends as it would have. The
/// note is built now: a signal handler may only `write` what already exists. Once per process.
pub fn say_on_interrupt(note: String) {
    if INTERRUPT_NOTE.set(note.into_bytes()).is_err() {
        return;
    }
    for sig in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: installing a handler that only calls async-signal-safe functions.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_interrupt as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// The service whose image this thread is pulling now, for the layer hook's row update.
static PULLING_FOR: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn on_pull_layer(image: &str, done: usize, total: usize) {
    let who = PULLING_FOR
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if let Some(service_name) = who {
        service(
            &service_name,
            "pulling",
            &format!("{image} (layer {done}/{total})"),
        );
    }
}

/// From here until [`pulled`], a layer the pull finishes updates `service_name`'s row.
pub fn pulling_for(service_name: &str) {
    kern_common::set_pull_layer_hook(on_pull_layer);
    *PULLING_FOR.lock().unwrap_or_else(|e| e.into_inner()) = Some(service_name.to_string());
}

/// The pull [`pulling_for`] named is over.
pub fn pulled() {
    *PULLING_FOR.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Is a live view drawing in this process?
pub fn board_active() -> bool {
    BOARD_EVENTS.load(std::sync::atomic::Ordering::Acquire) >= 0
}

/// Read a child `kern build`'s `--progress json` events from its stdout until EOF and turn each into
/// a row update of `service`; a line that is not an event is passed to stderr as it came.
pub fn follow_build_events(service_name: &str, out: impl std::io::Read) {
    use std::io::{BufRead, Write};
    let field = |line: &str, key: &str| -> Option<String> {
        let start = line.find(&format!("\"{key}\":"))? + key.len() + 3;
        let rest = line.get(start..)?;
        if let Some(r) = rest.strip_prefix('"') {
            let end = r.find('"')?;
            Some(r.get(..end)?.replace("\\\"", "\""))
        } else {
            let end = rest.find([',', '}']).unwrap_or(rest.len());
            Some(rest.get(..end)?.to_string())
        }
    };
    for line in std::io::BufReader::new(out).lines() {
        let Ok(line) = line else { break };
        if !line.starts_with("{\"schema\":1,") {
            let _ = writeln!(std::io::stderr(), "{line}");
            continue;
        }
        match field(&line, "type").as_deref() {
            Some("build_step") => {
                let last = field(&line, "last_ms")
                    .and_then(|v| v.parse::<u64>().ok())
                    .map_or(String::new(), |ms| {
                        format!(
                            " (last time {})",
                            crate::commands::build::step_clock::short_ms(ms)
                        )
                    });
                let detail = format!(
                    "step {}/{} {}{last}",
                    field(&line, "step").unwrap_or_default(),
                    field(&line, "total").unwrap_or_default(),
                    field(&line, "instruction").unwrap_or_default()
                );
                service(service_name, "building", &detail);
            }
            Some("heartbeat") => {
                let ms: u64 = field(&line, "elapsed_ms")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                service(
                    service_name,
                    "building",
                    &format!(
                        "{} ({}m{:02}s, {})",
                        field(&line, "what").unwrap_or_default(),
                        ms / 60_000,
                        (ms / 1000) % 60,
                        field(&line, "usage").unwrap_or_default()
                    ),
                );
            }
            _ => {}
        }
    }
}

/// Is this process running one thread? The view is a forked process, and a fork of a threaded
/// process is not one this code makes.
fn single_threaded() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Threads:"))
                .and_then(|n| n.trim().parse::<u32>().ok())
        })
        == Some(1)
}

/// The live view of a `compose up` on a terminal (`--progress tty`, or `auto` on one): one row per
/// service, redrawn in place, with a header that counts them.
///
/// IT OWNS THE TERMINAL WHILE IT DRAWS, because a view redrawn under someone else's lines erases
/// them: fd 2 becomes a pipe to the drawing process, and every line written to it (kern's own notes
/// and warnings, a nested build, a box's launcher) is printed ABOVE the view, which is then redrawn.
/// Nothing printed is lost; every line is shown whole, above. Dropping the view draws it a last
/// time, waits for that, and gives fd 2 back.
///
/// The drawing process is detached from this one (a double fork), ignores the terminal's signals,
/// and after the last draw passes whatever still arrives straight through until its last writer is
/// gone, so a process that kept the pipe never writes into one nobody reads.
pub struct Board {
    saved_err: i32,
    events_wr: i32,
    ack_rd: i32,
}

impl Board {
    /// Start the view, or `None` (the command prints its plain lines) when the mode is not `tty`,
    /// stderr is not a terminal, or this process already runs threads.
    pub fn start(title: &str, project: &str) -> Option<Board> {
        if kern_common::progress_mode_resolved() != ProgressMode::Tty {
            return None;
        }
        // SAFETY: isatty takes a plain integer.
        if unsafe { libc::isatty(2) } != 1 || !single_threaded() {
            return None;
        }
        let pipe = || -> Option<(i32, i32)> {
            let mut f = [-1i32; 2];
            // SAFETY: `f` is two ints.
            (unsafe { libc::pipe2(f.as_mut_ptr(), libc::O_CLOEXEC) } == 0).then_some((f[0], f[1]))
        };
        let close = |fd: i32| {
            if fd >= 0 {
                // SAFETY: closing a descriptor this function opened.
                unsafe { libc::close(fd) };
            }
        };
        let (err_rd, err_wr) = pipe()?;
        let Some((ev_rd, ev_wr)) = pipe() else {
            close(err_rd);
            close(err_wr);
            return None;
        };
        let Some((ack_rd, ack_wr)) = pipe() else {
            for fd in [err_rd, err_wr, ev_rd, ev_wr] {
                close(fd);
            }
            return None;
        };
        // SAFETY: duplicating fd 2.
        let saved_err = unsafe { libc::fcntl(2, libc::F_DUPFD_CLOEXEC, 0) };
        if saved_err < 0 {
            for fd in [err_rd, err_wr, ev_rd, ev_wr, ack_rd, ack_wr] {
                close(fd);
            }
            return None;
        }
        // SAFETY: single-threaded (checked above); the child only calls async-signal-safe code
        // until it forks again, and the grandchild runs the drawing loop and `_exit`s.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            for fd in [err_rd, err_wr, ev_rd, ev_wr, ack_rd, ack_wr, saved_err] {
                close(fd);
            }
            return None;
        }
        if pid == 0 {
            // SAFETY: plain calls in a fresh child.
            unsafe {
                if libc::fork() != 0 {
                    libc::_exit(0);
                }
                for sig in [
                    libc::SIGINT,
                    libc::SIGHUP,
                    libc::SIGTERM,
                    libc::SIGQUIT,
                    libc::SIGPIPE,
                ] {
                    libc::signal(sig, libc::SIG_IGN);
                }
                libc::close(err_wr);
                libc::close(ev_wr);
                libc::close(ack_rd);
            }
            draw_loop(title, project, err_rd, ev_rd, ack_wr, saved_err);
            // SAFETY: never return into the parent's logic.
            unsafe { libc::_exit(0) };
        }
        // SAFETY: reaping the intermediate child, which exits at once.
        unsafe {
            let mut st = 0;
            crate::eintr::waitpid(pid, &mut st, 0);
            libc::close(err_rd);
            libc::close(ev_rd);
            libc::close(ack_wr);
            libc::dup2(err_wr, 2);
            libc::close(err_wr);
        }
        kern_common::set_progress_terminal(Some(true));
        BOARD_EVENTS.store(ev_wr, std::sync::atomic::Ordering::Release);
        Some(Board {
            saved_err,
            events_wr: ev_wr,
            ack_rd,
        })
    }
}

impl Drop for Board {
    fn drop(&mut self) {
        BOARD_EVENTS.store(-1, std::sync::atomic::Ordering::Release);
        // SAFETY: descriptors this value owns.
        unsafe {
            libc::close(self.events_wr);
            // The last draw is done when the byte (or EOF) arrives; bounded, so a view that died
            // cannot hold the command.
            let mut p = libc::pollfd {
                fd: self.ack_rd,
                events: libc::POLLIN,
                revents: 0,
            };
            if libc::poll(&mut p, 1, 3000) > 0 {
                let mut b = [0u8; 1];
                libc::read(self.ack_rd, b.as_mut_ptr().cast(), 1);
            }
            libc::close(self.ack_rd);
            libc::dup2(self.saved_err, 2);
            libc::close(self.saved_err);
        }
        kern_common::set_progress_terminal(None);
    }
}

/// One service row of the view.
struct Row {
    name: String,
    state: String,
    detail: String,
    since: std::time::Instant,
}

fn state_class(state: &str) -> u8 {
    match state {
        "started" | "running" | "healthy" | "completed" | "built" | "pulled" => 0,
        "failed" | "exited" | "skipped" => 2,
        _ => 1,
    }
}

fn write_all(fd: i32, mut b: &[u8]) {
    while !b.is_empty() {
        // SAFETY: `b` is a live slice.
        let n = unsafe { libc::write(fd, b.as_ptr().cast(), b.len()) };
        if n > 0 {
            b = &b[n as usize..];
        } else if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        } else {
            return;
        }
    }
}

fn term_cols(fd: i32) -> usize {
    // SAFETY: TIOCGWINSZ fills one winsize.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 10 {
            return usize::from(ws.ws_col);
        }
    }
    100
}

fn fit(s: &str, cols: usize) -> String {
    s.chars().take(cols.saturating_sub(1)).collect()
}

fn dur(d: std::time::Duration) -> String {
    let s = d.as_secs();
    format!("{}m{:02}s", s / 60, s % 60)
}

/// The view's lines: a header that counts, then one row per service.
fn board_lines(
    title: &str,
    project: &str,
    rows: &[Row],
    started: std::time::Instant,
    tick: usize,
    cols: usize,
) -> Vec<String> {
    const SPIN: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let (mut done, mut busy, mut bad) = (0, 0, 0);
    for r in rows {
        match state_class(&r.state) {
            0 => done += 1,
            2 => bad += 1,
            _ => busy += 1,
        }
    }
    let mut head = format!("{title} · {done}/{} ready", rows.len());
    if busy > 0 {
        head.push_str(&format!(" · {busy} in progress"));
    }
    if bad > 0 {
        head.push_str(&format!(" · {bad} failed"));
    }
    head.push_str(&format!(" · {}", dur(started.elapsed())));
    // A ROW SAYS THE SERVICE, not the project every row shares: `<project>-` comes off for display
    // (the events keep the box name, which is unique).
    let prefix = format!("{project}-");
    let shown = |n: &str| -> String {
        n.strip_prefix(prefix.as_str())
            .filter(|rest| !project.is_empty() && !rest.is_empty())
            .unwrap_or(n)
            .chars()
            .take(32)
            .collect()
    };
    let w = rows
        .iter()
        .map(|r| shown(&r.name).chars().count())
        .max()
        .unwrap_or(4);
    let mut out = vec![fit(&head, cols)];
    for r in rows {
        let icon = match state_class(&r.state) {
            0 => '✔',
            2 => '✗',
            _ => SPIN[tick % SPIN.len()],
        };
        let when = if state_class(&r.state) == 1 {
            format!(" {}", dur(r.since.elapsed()))
        } else {
            String::new()
        };
        let line = format!(
            "  {icon} {:<w$} {:<9}{when}  {}",
            shown(&r.name),
            r.state,
            r.detail
        );
        out.push(fit(&line, cols));
    }
    out
}

/// The drawing process: read lines from fd 2's pipe and row updates from the event pipe, redraw
/// four times a second, draw a last time when the event pipe closes, acknowledge, then pass the
/// rest through until no one writes.
fn draw_loop(title: &str, project: &str, err_rd: i32, ev_rd: i32, ack_wr: i32, out: i32) {
    let started = std::time::Instant::now();
    let mut rows: Vec<Row> = Vec::new();
    let mut pending: Vec<u8> = Vec::new();
    let mut ev_pending: Vec<u8> = Vec::new();
    let mut drawn = 0usize;
    let mut tick = 0usize;
    let mut ev_open = true;
    let mut err_open = true;
    let mut buf = [0u8; 8192];
    let redraw = |above: &[u8], rows: &[Row], drawn: &mut usize, tick: usize| {
        let cols = term_cols(out);
        let mut frame: Vec<u8> = Vec::new();
        if *drawn > 0 {
            frame.extend_from_slice(format!("\x1b[{}F\x1b[J", *drawn).as_bytes());
        }
        frame.extend_from_slice(above);
        let lines = board_lines(title, project, rows, started, tick, cols);
        for l in &lines {
            frame.extend_from_slice(l.as_bytes());
            frame.push(b'\n');
        }
        *drawn = lines.len();
        write_all(out, &frame);
    };
    while ev_open {
        let mut pfds = [
            libc::pollfd {
                fd: if err_open { err_rd } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: ev_rd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: two live pollfds.
        let n = unsafe { libc::poll(pfds.as_mut_ptr(), 2, 250) };
        let mut above: Vec<u8> = Vec::new();
        if n > 0 && pfds[0].revents != 0 {
            // SAFETY: `buf` is a live buffer.
            let got = unsafe { libc::read(err_rd, buf.as_mut_ptr().cast(), buf.len()) };
            if got > 0 {
                pending.extend_from_slice(&buf[..got as usize]);
                if let Some(last) = pending.iter().rposition(|b| *b == b'\n') {
                    above.extend(pending.drain(..=last));
                }
            } else if got == 0 {
                err_open = false;
            }
        }
        if n > 0 && pfds[1].revents != 0 {
            // SAFETY: `buf` is a live buffer.
            let got = unsafe { libc::read(ev_rd, buf.as_mut_ptr().cast(), buf.len()) };
            if got <= 0 {
                ev_open = false;
            } else {
                ev_pending.extend_from_slice(&buf[..got as usize]);
                while let Some(nl) = ev_pending.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = ev_pending.drain(..=nl).collect();
                    let text = String::from_utf8_lossy(&line);
                    let f: Vec<&str> = text.trim_end_matches('\n').splitn(4, '\t').collect();
                    if let ["S", name, state, detail] = f.as_slice() {
                        match rows.iter_mut().find(|r| r.name == *name) {
                            Some(r) => {
                                if r.state != *state {
                                    r.since = std::time::Instant::now();
                                }
                                r.state = (*state).to_string();
                                r.detail = (*detail).to_string();
                            }
                            None => rows.push(Row {
                                name: (*name).to_string(),
                                state: (*state).to_string(),
                                detail: (*detail).to_string(),
                                since: std::time::Instant::now(),
                            }),
                        }
                    }
                }
            }
        }
        tick = tick.wrapping_add(1);
        redraw(&above, &rows, &mut drawn, tick);
    }
    // THE LAST DRAW: what is waiting in the pipe goes above it, a partial line included.
    let mut above: Vec<u8> = Vec::new();
    // SAFETY: making our read end non-blocking for the final drain.
    unsafe {
        let fl = libc::fcntl(err_rd, libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(err_rd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }
    loop {
        // SAFETY: `buf` is a live buffer.
        let got = unsafe { libc::read(err_rd, buf.as_mut_ptr().cast(), buf.len()) };
        if got <= 0 {
            break;
        }
        pending.extend_from_slice(&buf[..got as usize]);
    }
    above.append(&mut pending);
    if !above.is_empty() && above.last() != Some(&b'\n') {
        above.push(b'\n');
    }
    redraw(&above, &rows, &mut drawn, tick);
    // SAFETY: one byte to the waiting command, then our end of that pipe goes.
    unsafe {
        libc::write(ack_wr, b"k".as_ptr().cast(), 1);
        libc::close(ack_wr);
        let fl = libc::fcntl(err_rd, libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(err_rd, libc::F_SETFL, fl & !libc::O_NONBLOCK);
        }
    }
    // A PASS-THROUGH until the last writer is gone, so a process that still holds the pipe never
    // writes into one nobody reads.
    loop {
        // SAFETY: `buf` is a live buffer.
        let got = unsafe { libc::read(err_rd, buf.as_mut_ptr().cast(), buf.len()) };
        if got > 0 {
            write_all(out, &buf[..got as usize]);
        } else if got < 0
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn progress_is_taken_where_it_is_kerns_and_left_where_it_is_the_boxes() {
        let _g = crate::env_guard();
        let cases: [(&[&str], &[&str]); 6] = [
            (
                &["build", "--progress", "plain", "-t", "x", "."],
                &["build", "-t", "x", "."],
            ),
            (
                &["compose", "--progress=quiet", "up", "-d"],
                &["compose", "up", "-d"],
            ),
            (
                &["compose", "f.yml", "up", "--progress", "json"],
                &["compose", "f.yml", "up"],
            ),
            (
                &["compose", "run", "app", "npm", "--progress=false"],
                &["compose", "run", "app", "npm", "--progress=false"],
            ),
            (
                &["compose", "exec", "app", "x", "--progress", "plain"],
                &["compose", "exec", "app", "x", "--progress", "plain"],
            ),
            (
                &["box", "x", "--progress", "plain"],
                &["box", "x", "--progress", "plain"],
            ),
        ];
        for (input, want) in cases {
            let got = take_progress_flag(&v(input)).ok();
            assert_eq!(got, Some(v(want)), "{input:?}");
        }
        assert!(take_progress_flag(&v(&["build", "--progress", "loud"])).is_err());
        assert!(take_progress_flag(&v(&["build", "--progress"])).is_err());
        let rows = vec![
            Row {
                name: "db".into(),
                state: "healthy".into(),
                detail: String::new(),
                since: std::time::Instant::now(),
            },
            Row {
                name: "web".into(),
                state: "starting".into(),
                detail: "after db".into(),
                since: std::time::Instant::now(),
            },
            Row {
                name: "job".into(),
                state: "failed".into(),
                detail: "exit 1".into(),
                since: std::time::Instant::now(),
            },
        ];
        let wide = board_lines(
            "kern compose up",
            "",
            &rows,
            std::time::Instant::now(),
            0,
            120,
        );
        assert!(
            wide[0].starts_with("kern compose up · 1/3 ready · 1 in progress · 1 failed"),
            "{}",
            wide[0]
        );
        let lines = board_lines(
            "kern compose up",
            "",
            &rows,
            std::time::Instant::now(),
            0,
            40,
        );
        let named = vec![Row {
            name: "proj-web-1".into(),
            state: "started".into(),
            detail: String::new(),
            since: std::time::Instant::now(),
        }];
        let shown = board_lines("t", "proj", &named, std::time::Instant::now(), 0, 80);
        assert!(shown[1].contains("✔ web-1 "), "{}", shown[1]);
        assert_eq!(lines.len(), 4);

        assert!(
            lines.iter().all(|l| l.chars().count() < 40),
            "a line wider than the terminal wraps and breaks the redraw"
        );
        kern_common::set_progress_mode(ProgressMode::Auto);
        crate::unset_global_env("KERN_PROGRESS");
    }
}
