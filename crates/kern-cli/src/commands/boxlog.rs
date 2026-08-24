//! A box's log: writing it under a cap, and reading it back.
//!
//! A SUPPORT module. `start` writes through the capped pump, `inspect` tails and follows, `system`
//! reads the last lines to explain an exit, so this belongs to none of them and the parent
//! re-exports it to all three.
//!
//! The cap is the point: a box that writes forever must not fill the disk, so the pump keeps the
//! newest `BOX_LOG_MAX_BYTES` and drops from the front, and the readers know the file can be
//! truncated underneath them.

use super::*;

/// Read the last `max` bytes of `path`, trimmed, or `None` if the file is missing/empty. Used to
/// surface a failed detached box's reason inline (the box logged it to its own stderr sink). Reads
/// the whole file - a box that "exited before starting" has only a few lines - and keeps the tail
/// lossily so non-UTF-8 output can't hide the reason.
pub(crate) fn read_log_tail(path: &std::path::Path, max: usize) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    let start = data.len().saturating_sub(max);
    let tail = String::from_utf8_lossy(&data[start..]);
    let t = tail.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// Read the box log's failure REASON, polling briefly for the asynchronous log pump to flush it.
/// A detached box's stdout/stderr is drained by a separate pump process, so the supervisor's
/// "kern: box failed to start: <reason>" line (printed to its pumped stderr AFTER the readiness
/// failure byte is already on the wire) can lag the byte. A single read here races the pump and
/// catches only the earlier lines - e.g. the benign "requested resource cap(s) could not be
/// enforced" notice - leaving `await_box_started` to surface a warning instead of the cause. Poll
/// up to ~1s for the supervisor's failure marker to land; fall back to whatever is there on timeout.
/// Only ever called on the (rare) start-failure path, so the bounded wait never touches a good start.
pub(crate) fn read_log_reason(path: &std::path::Path) -> Option<String> {
    // Bounded post-failure poll. NOT a start timeout: the box has ALREADY failed here (the launcher
    // received the readiness FAILURE byte, and that read itself has no deadline, so a slow board never
    // false-fails). This only waits for the async log pump to flush the supervisor's failure REASON
    // into the file. 3 s is generous even for a slow board's pump; on timeout we return whatever is
    // present, so the worst case is a less-detailed message, never a wrong verdict.
    for _ in 0..150 {
        let tail = read_log_tail(path, 1024);
        if tail
            .as_deref()
            .is_some_and(|t| t.contains("box failed to start") || t.contains("user namespaces"))
        {
            return tail;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    read_log_tail(path, 1024)
}

/// Per-file cap on a box's captured log. A single-generation ring (`<log>` + `<log>.1`) keeps at most
/// `2 * BOX_LOG_MAX_BYTES` on disk. The runtime dir is a small tmpfs (systemd default `size=` = 10% of
/// RAM), so an unbounded writer would otherwise fill it and break the user session (no more sockets or
/// state creatable in `/run/user/<uid>`). Docker solved the same class with `--log-opt max-size`.
pub(crate) const BOX_LOG_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Move up to `want` bytes from pipe `rd` into `sink` with `splice(2)` - a ZERO-COPY pipe->file move (no
/// userspace buffer, no `read`+`write` pair), so draining even a gigabyte-per-second flood costs syscall
/// overhead only. Returns bytes moved (`Ok(0)` = EOF) or `Err(errno)`.
pub(crate) fn splice_once(rd: i32, sink: i32, want: usize) -> Result<usize, i32> {
    let moved = unsafe {
        libc::splice(
            rd,
            std::ptr::null_mut(),
            sink,
            std::ptr::null_mut(),
            want,
            libc::SPLICE_F_MOVE,
        )
    };
    if moved >= 0 {
        Ok(moved as usize)
    } else {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }
}

/// A size-capped, single-generation-rotating append log. `write` never blocks the caller on a full disk
/// (`ENOSPC` drops the chunk) and never grows the active file past `max` (rotation renames it to
/// `<path>.1` and starts fresh), so total on-disk use is bounded at `2 * max`.
pub(crate) struct CappedLog {
    pub(crate) fd: i32,
    pub(crate) path: std::path::PathBuf,
    pub(crate) written: u64,
    pub(crate) max: u64,
}

impl CappedLog {
    fn open(path: &std::path::Path, max: u64) -> Option<Self> {
        let fd = open_log(path, false);
        if fd < 0 {
            return None;
        }
        // Non-append (the pump is the sole writer and drives the offset via `splice`). Seek to end so a
        // pre-existing log is appended to, not overwritten, and count from its size so the cap bounds the
        // FILE, not this session's bytes. `lseek(SEEK_END)` returns the new offset (= size); 0 for fresh.
        let end = unsafe { libc::lseek(fd, 0, libc::SEEK_END) };
        let written = if end > 0 { end as u64 } else { 0 };
        Some(Self {
            fd,
            path: path.to_path_buf(),
            written,
            max,
        })
    }

    /// Rename the active file to `<path>.1` (one generation kept, overwriting a previous `.1`) and reopen
    /// a fresh empty file. The rename is atomic, so a reader never sees the path missing. On failure the
    /// old fd is kept and `written` stays at the cap, so the next `write` retries rather than overflowing.
    fn rotate(&mut self) {
        let mut old = self.path.clone().into_os_string();
        old.push(".1");
        if std::fs::rename(&self.path, &old).is_err() {
            return; // keep the old fd; never grow past the cap
        }
        let fd = open_log(&self.path, false);
        if fd >= 0 {
            unsafe { libc::close(self.fd) };
            self.fd = fd;
            self.written = 0;
        }
    }

    fn write(&mut self, mut buf: &[u8]) {
        while !buf.is_empty() {
            if self.written >= self.max {
                self.rotate();
                if self.written >= self.max {
                    return; // rotation failed (rename/open) - drop rather than spin or overflow the cap
                }
            }
            let room = (self.max - self.written) as usize;
            let chunk = &buf[..buf.len().min(room)];
            let n = unsafe { libc::write(self.fd, chunk.as_ptr().cast(), chunk.len()) };
            if n < 0 {
                match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::EINTR) => continue,
                    // Disk full: drop the chunk and force a rotation next round (freeing `.1`'s space).
                    // The workload must NEVER block or die because its log is full - the log is
                    // diagnostics, not part of the workload's contract.
                    Some(libc::ENOSPC) => {
                        self.written = self.max;
                        return;
                    }
                    _ => return,
                }
            }
            self.written += n as u64;
            buf = &buf[n as usize..];
        }
    }
}

/// Drain the pipe `rd` into a byte-capped rotating log at `path` until EOF. Runs in the forked pump
/// child. Uses `splice(2)` (ZERO-COPY pipe->file) so draining a flood costs syscall overhead only, not
/// the two userspace memcpies of a `read`+`write` loop - the CPU that would otherwise burn OUTSIDE the
/// box's cgroup cap. Falls back to `read`+`write` permanently if the filesystem refuses `splice`
/// (`EINVAL`); drains to `/dev/null` (still zero-copy) when there is no log or the disk is full, so the
/// box NEVER blocks on a full pipe.
pub(crate) fn pump_capped_log(rd: i32, path: &std::path::Path) {
    let mut log = CappedLog::open(path, BOX_LOG_MAX_BYTES);
    // A /dev/null sink for the no-log case and disk-full overflow: the pipe must still be drained.
    let void = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    let mut use_splice = true;
    let mut scratch = [0u8; 64 * 1024]; // read+write fallback buffer (splice-unsupported fs)
    loop {
        // Choose this round's sink and how much may go to it. `to_log` distinguishes the real log (count
        // toward the cap) from the /dev/null shed (do not).
        let (sink, want, to_log) = match log.as_mut() {
            Some(l) => {
                if l.written >= l.max {
                    l.rotate();
                }
                let room = l.max.saturating_sub(l.written);
                if room == 0 {
                    (void, PUMP_SPLICE_CHUNK, false) // rotation could not free room -> shed this round
                } else {
                    (l.fd, room.min(PUMP_SPLICE_CHUNK as u64) as usize, true)
                }
            }
            None => (void, PUMP_SPLICE_CHUNK, false),
        };
        if sink < 0 {
            break; // neither a log nor /dev/null could be opened - nothing to drain into
        }
        if use_splice {
            match splice_once(rd, sink, want) {
                Ok(0) => break, // EOF: every write end (workload + supervisor) is closed
                Ok(n) => {
                    if to_log {
                        if let Some(l) = log.as_mut() {
                            l.written += n as u64;
                        }
                    }
                }
                Err(libc::EINTR) => {}
                // Disk full: force a rotation next round (freeing `.1`'s space), shedding meanwhile.
                Err(libc::ENOSPC) | Err(libc::EDQUOT) => {
                    if let Some(l) = log.as_mut() {
                        l.written = l.max;
                    }
                }
                // This kernel/filesystem cannot splice this pipe->fd pair: fall back permanently.
                Err(libc::EINVAL) => use_splice = false,
                Err(_) => break, // an unexpected splice error - stop draining
            }
        } else {
            let n = unsafe { libc::read(rd, scratch.as_mut_ptr().cast(), scratch.len()) };
            if n > 0 {
                match log.as_mut() {
                    Some(l) => l.write(&scratch[..n as usize]),
                    None => {
                        let _ = unsafe { libc::write(void, scratch.as_ptr().cast(), n as usize) };
                    }
                }
            } else if n == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
            {
                break; // EOF (n == 0) or a real read error; EINTR falls through and retries
            }
        }
    }
    if void >= 0 {
        unsafe { libc::close(void) };
    }
}

/// Interpose a byte-capped pump between the workload's stdout/stderr and the on-disk log. Creates a
/// pipe, forks a child that drains the read end into a [`CappedLog`], and returns the WRITE end for the
/// caller to `dup2` onto fd 1/2 - so a detached box that writes without bound (`yes`, a crash loop)
/// cannot fill the tmpfs runtime dir and break the user session. `None` if the pipe or fork fails - the
/// caller then falls back to writing the log directly (uncapped, but never lost).
///
/// # Safety
/// Runs during stdio detachment, before any namespace/seccomp setup, and forks. Single-threaded here, so
/// running Rust code in the child (no exec) is sound. The child sheds every inherited fd except the pipe
/// read end - crucially the readiness-pipe write end, which held here would stop the launcher from ever
/// seeing EOF and hang `kern box -d`.
pub(crate) unsafe fn start_log_pump(path: &std::path::Path) -> Option<i32> {
    let mut fds = [0i32; 2];
    if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
        return None;
    }
    let (rd, wr) = (fds[0], fds[1]);
    // Enlarge the pipe buffer to `PUMP_SPLICE_CHUNK` (default is 64 KiB = 16 pages). `splice` moves at
    // most what the pipe holds, so a bigger buffer means one `splice` drains up to 1 MiB instead of
    // 64 KiB - ~16x fewer syscalls under a flood, and fewer `write` wake-ups for the box. Best-effort:
    // capped by `/proc/sys/fs/pipe-max-size`, and a failure just leaves the default size (still correct).
    libc::fcntl(rd, libc::F_SETPIPE_SZ, PUMP_SPLICE_CHUNK as libc::c_int);
    let pid = libc::fork();
    if pid < 0 {
        libc::close(rd);
        libc::close(wr);
        return None;
    }
    if pid == 0 {
        // DETACH the pump from the parent's stdio FIRST. The pump is forked before `detach_stdio`
        // redirects fd 1/2 onto this pipe, so it inherits the LAUNCHER's stdout/stderr - and holding
        // that write end open would block a `kern box -d` whose stdout is a pipe (a test harness, a
        // script doing `$(kern box -d …)`) in `wait`/`output` until the BOX exits, breaking the
        // "detached returns immediately" contract. Point 0/1/2 at /dev/null so the pump holds no
        // inherited stream; it reads `rd` and writes only its own (later-opened) log fd.
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, 0);
            libc::dup2(devnull, 1);
            libc::dup2(devnull, 2);
            if devnull > 2 {
                libc::close(devnull);
            }
        }
        // Shed every OTHER inherited fd except the read end - most importantly the readiness-pipe write
        // end, which held here would stop the launcher from ever seeing EOF and hang `kern box -d`.
        kern_isolation::shed_inherited_fds(rd);
        pump_capped_log(rd, path);
        libc::_exit(0);
    }
    libc::close(rd); // the parent keeps only the write end (dup2'd onto 1/2 by the caller, then closed)
    Some(wr)
}

/// Open the box log for direct (uncapped) append - the fallback when the capped pump can't start.
pub(crate) fn open_log_direct(path: &std::path::Path) -> Option<i32> {
    let fd = open_log(path, true);
    (fd >= 0).then_some(fd)
}

/// Detach stdio: stdin from `/dev/null`; stdout/stderr into the box's size-capped `log` (via a pump
/// child, so an unbounded writer can't fill the tmpfs runtime dir), or `/dev/null` if no log path. So a
/// detached box neither holds nor spams the terminal, its output is captured, and its log cannot DoS the
/// user session. If the pump can't start, the log is written directly (uncapped) rather than lost.
pub(crate) fn detach_stdio(log: Option<&std::path::Path>) {
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null >= 0 {
            libc::dup2(null, 0);
        }
        let sink = log
            .and_then(|p| start_log_pump(p).or_else(|| open_log_direct(p)))
            .unwrap_or(null);
        if sink >= 0 {
            libc::dup2(sink, 1);
            libc::dup2(sink, 2);
        }
        // Close the source fd once it's duplicated onto 1/2 - unless it IS `null` (closed below) or a
        // std stream.
        if sink > 2 && sink != null {
            libc::close(sink);
        }
        if null > 2 {
            libc::close(null);
        }
    }
}

/// The byte slice of the last `n` lines of `content` (each line keeps its trailing `\n`). A single
/// trailing newline is not counted as an extra empty line, so `tail_lines(b"a\nb\n", 1) == b"b\n"`.
/// Zero-copy: returns a subslice of `content`. `n == 0` yields an empty slice; fewer than `n` lines
/// present yields all of `content`.
pub(crate) fn tail_lines(content: &[u8], n: usize) -> &[u8] {
    if n == 0 {
        return &[];
    }
    // Ignore one trailing newline so the final line is not read as an empty line after it.
    let scan_end = match content.last() {
        Some(b'\n') => content.len() - 1,
        _ => content.len(),
    };
    let mut seen = 0usize;
    let mut i = scan_end;
    while i > 0 {
        i -= 1;
        if content[i] == b'\n' {
            seen += 1;
            if seen == n {
                return &content[i + 1..];
            }
        }
    }
    content
}

/// Read only the last `n` lines of an already-open log `f`, seeking backward in bounded chunks so a
/// small `--tail` off a huge detached-box log costs O(bytes shown) plus one chunk, never a full slurp.
/// (A `--tail` larger than the file simply degrades to a single linear pass, like `read_to_end`.) Line
/// semantics match [`tail_lines`] (each line keeps its `\n`; a single trailing newline is not an extra
/// empty line). Leaves `f`'s cursor mid-file; the caller re-seeks to EOF for `--follow`.
pub(crate) fn tail_file(f: &mut std::fs::File, n: usize) -> Result<Vec<u8>, Error> {
    use std::io::{Read, Seek, SeekFrom};
    let map = |e: std::io::Error| Error::Sandbox(format!("reading log: {e}"));
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut pos = f.seek(SeekFrom::End(0)).map_err(map)?;
    const CHUNK: u64 = 8192;
    // Chunks are read high-offset first; collect them reversed and stitch ONCE at the end. Prepending
    // into one growing buffer would recopy it (and re-scan it for newlines) every iteration - O(size^2)
    // on a pathological `--tail 999999999`; here it stays O(bytes read). Newlines counted incrementally.
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut newlines = 0usize;
    // Walk backward a chunk at a time until the window holds more than `n` newlines (so the n-th line
    // from the end is fully captured - see the `> n` proof in `tail_lines`) or we reach the start of
    // the file (fewer than `n` lines exist -> return them all).
    while pos > 0 {
        let read_len = CHUNK.min(pos);
        pos -= read_len;
        let mut chunk = vec![0u8; read_len as usize];
        f.seek(SeekFrom::Start(pos)).map_err(map)?;
        f.read_exact(&mut chunk).map_err(map)?;
        newlines += chunk.iter().filter(|&&b| b == b'\n').count();
        chunks.push(chunk);
        if newlines > n {
            break;
        }
    }
    // Stitch the chunks back into file order (they were pushed EOF-first).
    let total: usize = chunks.iter().map(Vec::len).sum();
    let mut buf = Vec::with_capacity(total);
    for chunk in chunks.iter().rev() {
        buf.extend_from_slice(chunk);
    }
    Ok(tail_lines(&buf, n).to_vec())
}

/// Stream new appends of an already-open log `f` (from its current read offset) to stdout, polling
/// every 200 ms until the box `(name, pid)` leaves the registry. Panic-free; a stdout write error
/// (a closed pipe) ends the follow quietly. Shared by `kern attach` and `kern logs -f`.
pub(crate) fn follow_log(mut f: std::fs::File, name: &str, pid: i32) -> Result<(), Error> {
    use std::io::{Read, Write};
    let mut buf = [0u8; 8192];
    let stdout = std::io::stdout();
    loop {
        // Drain whatever is currently appended.
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(k) => {
                    let mut lock = stdout.lock();
                    if lock.write_all(&buf[..k]).is_err() {
                        return Ok(());
                    }
                    let _ = lock.flush();
                }
                Err(_) => break,
            }
        }
        // Exact (name,pid) pair: a duplicate same-name entry must not make a live box read as exited.
        if !registry::pair_alive(name, pid) {
            return Ok(());
        }
        unsafe { libc::usleep(200_000) }; // 200 ms - cheap follow poll
    }
}

/// The newest `<name>-<pid>.log` under the logs dir, or `None` if the box has produced no log.
pub(crate) fn newest_log(name: &str) -> Result<Option<PathBuf>, Error> {
    let dir = registry::logs_dir().map_err(|e| Error::Sandbox(format!("logs dir: {e}")))?;
    let prefix = format!("{name}-");
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let fname = e.file_name();
            let fname = fname.to_string_lossy();
            // Require exactly `<name>-<digits>.log`: strip the prefix and `.log`, then the middle must
            // be an all-digit PID. A bare `starts_with(prefix)` would let box `foo` match `foo-bar`'s
            // log file `foo-bar-<pid>.log` (box names may legally contain '-'), leaking another box's
            // output through `kern logs`/`attach`.
            let is_ours = fname
                .strip_prefix(&prefix)
                .and_then(|rest| rest.strip_suffix(".log"))
                .is_some_and(|mid| !mid.is_empty() && mid.bytes().all(|b| b.is_ascii_digit()));
            if is_ours {
                if let Ok(mtime) = e.metadata().and_then(|m| m.modified()) {
                    if newest.as_ref().is_none_or(|(t, _)| mtime > *t) {
                        newest = Some((mtime, e.path()));
                    }
                }
            }
        }
    }
    Ok(newest.map(|(_, p)| p))
}
