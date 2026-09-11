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
    /// How many files this log may occupy IN TOTAL, active one included - Docker's `max-file`
    /// counting, so `3` means `<path>`, `<path>.1` and `<path>.2`. `1` keeps no generation at all and
    /// truncates in place. Total on-disk use is bounded at `max * files`.
    pub(crate) files: u32,
}

/// How large a box log may grow and how many generations are kept.
///
/// A STRUCT AND NOT TWO ARGUMENTS because the two are one policy and are read together at every site:
/// a size without a generation count bounds nothing (the file is truncated), and a count without a
/// size never triggers. Passing them separately is how a call site comes to set one and forget the
/// other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LogCap {
    pub(crate) max_bytes: u64,
    pub(crate) files: u32,
}

impl Default for LogCap {
    /// EXACTLY WHAT EVERY BOX HAD BEFORE THE FLAGS EXISTED: 16 MiB active plus one rotated
    /// generation. Stated as the default rather than left implicit at the call sites, so adding a
    /// caller cannot quietly change the bound a box has always had.
    fn default() -> Self {
        Self {
            max_bytes: BOX_LOG_MAX_BYTES,
            files: 2,
        }
    }
}

impl CappedLog {
    fn open(path: &std::path::Path, cap: LogCap) -> Option<Self> {
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
            // A zero cap would make `write` rotate on every byte and never store anything; the
            // caller's parser refuses zero, and this is the second gate so the invariant holds for
            // any future caller that reaches this struct another way.
            max: cap.max_bytes.max(1),
            files: cap.files.max(1),
        })
    }

    /// Rename the active file to `<path>.1` (one generation kept, overwriting a previous `.1`) and reopen
    /// a fresh empty file. The rename is atomic, so a reader never sees the path missing. On failure the
    /// old fd is kept and `written` stays at the cap, so the next `write` retries rather than overflowing.
    fn rotate(&mut self) {
        // `files == 1` KEEPS NO GENERATION, which is Docker's `max-file: 1`. There is nothing to
        // rename to, so the active file is truncated in place: the fd stays valid and no reader ever
        // sees the path missing. Seeking back to 0 is required as well as truncating - the pump
        // drives the offset itself (the fd is not `O_APPEND`), so a file truncated without the seek
        // would be written at the old offset and come back as a sparse hole.
        if self.files <= 1 {
            // SAFETY: `self.fd` is the log descriptor this struct owns and keeps open for its whole
            // life; both calls take it by value and write through no pointer. The `&&` orders them:
            // the seek only runs if the truncate succeeded, so the offset is never reset on a file
            // that still holds its old bytes.
            if unsafe { libc::ftruncate(self.fd, 0) } == 0
                && unsafe { libc::lseek(self.fd, 0, libc::SEEK_SET) } == 0
            {
                self.written = 0;
            }
            return;
        }
        // Shift the generations down, OLDEST FIRST, so no rename overwrites a file that has not been
        // moved yet: `.n-2` → `.n-1` (dropping whatever `.n-1` held), then `.n-3` → `.n-2`, and so on
        // to `.1` → `.2`. `files` counts the active file, so the oldest generation is `.files-1`.
        // A rename that fails is skipped rather than aborting the rotation: losing one generation is
        // strictly better than letting the active file grow past its cap.
        let gen_path = |i: u32| {
            let mut p = self.path.clone().into_os_string();
            p.push(format!(".{i}"));
            std::path::PathBuf::from(p)
        };
        for i in (1..self.files - 1).rev() {
            let _ = std::fs::rename(gen_path(i), gen_path(i + 1));
        }
        if std::fs::rename(&self.path, gen_path(1)).is_err() {
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
///
/// AND IT ONLY EVER STOPS AT EOF. Every other outcome - no log, no `/dev/null`, an error `splice`
/// has never returned here before - drops to reading the pipe and throwing the bytes away. This
/// process is the only reader of the box's stdout: if it leaves while the box still holds the write
/// end, the box's next write raises SIGPIPE and takes the workload down, and the box's recorded exit
/// becomes 141 instead of whatever the workload meant to say. MEASURED: the suite's own
/// `stop_records_the_workloads_own_exit_code` recorded 141 for a box whose init does
/// `trap 'exit 7' TERM`, reproducibly at 28-way parallelism and never below 8, which is where a
/// descriptor runs out and an `open` starts failing. A log is diagnostics; it may be lost, and it
/// may never be the reason a workload dies.
pub(crate) fn pump_capped_log(rd: i32, path: &std::path::Path, cap: LogCap) {
    let mut log = CappedLog::open(path, cap);
    // A /dev/null sink for the no-log case and disk-full overflow: the pipe must still be drained.
    let void = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    let mut use_splice = true;
    let mut scratch = [0u8; 64 * 1024]; // read+write fallback buffer (splice-unsupported fs)
                                        // Set when there is nowhere left to put the bytes. The pipe is still drained - see the note on
                                        // this function about what leaving instead costs the workload.
    let mut discard = false;
    loop {
        if discard {
            // SAFETY: `scratch` is a live buffer this frame owns and `rd` is the pipe read end.
            let n = unsafe { libc::read(rd, scratch.as_mut_ptr().cast(), scratch.len()) };
            if n > 0 {
                continue; // bytes read and dropped: the box keeps writing, and keeps living
            }
            if n == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break; // EOF, or a read error on the pipe itself - there is no pipe left to serve
            }
            continue;
        }
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
            // Neither a log nor `/dev/null` could be opened - under fd exhaustion, both `open`s fail
            // at once. Keep reading anyway: the bytes go nowhere and the box stays alive.
            discard = true;
            continue;
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
                // An error `splice` has not returned here before. Whatever it is, it is not a
                // reason to leave the box's stdout without a reader.
                Err(_) => discard = true,
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
            } else if n == 0 {
                break; // EOF: every write end (workload + supervisor) is closed
            } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break; // a real error on the pipe read end itself; EINTR falls through and retries
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
pub(crate) unsafe fn start_log_pump(path: &std::path::Path, cap: LogCap) -> Option<i32> {
    let mut fds = [0i32; 2];
    if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
        return None;
    }
    let (rd, wr) = (fds[0], fds[1]);
    // Enlarge the pipe buffer to `PUMP_SPLICE_CHUNK` (default is 64 KiB = 16 pages). `splice` moves at
    // most what the pipe holds, so a bigger buffer means one `splice` drains up to 1 MiB instead of
    // 64 KiB - ~16x fewer syscalls under a flood, and fewer `write` wake-ups for the box. Best-effort:
    // capped by `/proc/sys/fs/pipe-max-size`, and a failure just leaves the default size (still correct).
    // THE WRITE END IS REOPENABLE BY THE WORKLOAD'S OWN UID, and that is not cosmetic: a pipe is
    // created 0600 owned by the caller, kern maps the caller to root inside the box, and an image
    // that runs as a non-root user is therefore a DIFFERENT uid in there. Such a workload can still
    // WRITE to the inherited fd 1, but it cannot REOPEN it - and `/dev/stdout` is a symlink to
    // `/proc/self/fd/1`, so opening it is a reopen.
    //
    // MEASURED, twice: `kern box --user 1997 -- sh -c 'echo x > /dev/stdout'` answers `Permission
    // denied` while the same box as root prints the line; and Zabbix's nginx frontend, whose image
    // runs as uid 1997 and whose config logs to `/dev/stdout`, died at start with `open()
    // "/dev/stdout" failed (13: Permission denied)` on every restart. Logging to `/dev/stdout` is
    // the convention EVERY containerised web server follows, so the uid that cannot do it is the
    // uid a large share of hardened images run as.
    //
    // 0666 on the pipe, not on the log file: the file keeps its owner-only mode, and the pipe is an
    // anonymous pipefs inode with no name in any filesystem. The only processes that can reach it
    // are the ones already holding the descriptor - this box and the pump.
    libc::fchmod(wr, 0o666);
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
        pump_capped_log(rd, path, cap);
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
pub(crate) fn detach_stdio(log: Option<&std::path::Path>, cap: LogCap) {
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null >= 0 {
            libc::dup2(null, 0);
        }
        let sink = log
            .and_then(|p| start_log_pump(p, cap).or_else(|| open_log_direct(p)))
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

/// Set by [`arm_follow_interrupt`]'s handler so an attached `compose up` can leave the follow loop
/// and tear its stack down, instead of dying where it stands and orphaning it.
///
/// A plain `logs -f` never arms the handler, so SIGINT keeps its default disposition there and
/// Ctrl-C ends the process at once, which is what a reader of a log expects.
static FOLLOW_STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn on_follow_signal(_: libc::c_int) {
    // The ONLY operation here is an atomic store, which is async-signal-safe. `Release` pairs with
    // the `Acquire` load in `follow_many`: everything the handler observed happens-before the loop's
    // exit, and no stronger ordering buys anything for a single flag.
    FOLLOW_STOP.store(true, std::sync::atomic::Ordering::Release);
}

/// Trap SIGINT/SIGTERM for the duration of an attached follow, and report whether the trap took.
///
/// Returns the flag the caller polls. Installed by `compose up` (attached) only.
pub(crate) fn arm_follow_interrupt() -> &'static std::sync::atomic::AtomicBool {
    FOLLOW_STOP.store(false, std::sync::atomic::Ordering::Release);
    unsafe {
        // `as *const () as sighandler_t`, the same two-step `watch` and the TUI use: a direct
        // function-item-to-integer cast is refused by lint, so the pointer is formed explicitly.
        libc::signal(
            libc::SIGINT,
            on_follow_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            on_follow_signal as *const () as libc::sighandler_t,
        );
    }
    &FOLLOW_STOP
}

/// A flag that is never set, for the follow paths that want SIGINT's default disposition.
pub(crate) static FOLLOW_FOREVER: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// One service being followed by [`follow_many`]: where its output is, and how to label it.
pub(crate) struct Followed {
    /// The name the compose FILE uses. Boxes are named `<project>-<service>`, and a reader
    /// recognises the service, so the prefix carries that and not the scoped name.
    label: String,
    /// The scoped box name and pid, the exact pair `registry::pair_alive` needs: a duplicate
    /// same-name entry must not make a live box read as exited.
    box_name: String,
    pid: i32,
    file: std::fs::File,
    /// Bytes read that do not yet end in a newline, held back so a prefix never lands mid-line.
    pending: Vec<u8>,
    /// Set once the box has left the registry AND its file has been drained one final time.
    done: bool,
}

impl Followed {
    /// Open a service's log for following, or `None` when it has produced none (never started, or
    /// started so recently the pump has not created the file yet).
    ///
    /// `tail` bounds what is shown BEFORE the follow begins, exactly as in the single-box path:
    /// `None` replays the whole log, `Some(n)` its last `n` lines.
    pub(crate) fn open(
        label: String,
        box_name: String,
        pid: i32,
        tail: Option<usize>,
    ) -> Result<Option<Self>, Error> {
        use std::io::{Read, Seek, SeekFrom};
        let Some(path) = newest_log(&box_name)? else {
            return Ok(None);
        };
        let mut file =
            std::fs::File::open(&path).map_err(|e| Error::Sandbox(format!("opening log: {e}")))?;
        let pending = match tail {
            Some(n) => {
                let window = tail_file(&mut file, n)?;
                // Leave the cursor at EOF so the follow streams only NEW appends.
                file.seek(SeekFrom::End(0))
                    .map_err(|e| Error::Sandbox(format!("seeking log: {e}")))?;
                window
            }
            None => {
                let mut all = Vec::new();
                file.read_to_end(&mut all)
                    .map_err(|e| Error::Sandbox(format!("reading log: {e}")))?;
                all
            }
        };
        Ok(Some(Self {
            label,
            box_name,
            pid,
            file,
            pending,
            done: false,
        }))
    }

    /// Append everything currently readable. A short read means "nothing more right now", not EOF:
    /// the box is still open on the other end.
    fn read_available(&mut self) {
        use std::io::Read;
        let mut buf = [0u8; 8192];
        loop {
            match self.file.read(&mut buf) {
                Ok(0) => break,
                Ok(k) => match buf.get(..k) {
                    Some(s) => self.pending.extend_from_slice(s),
                    None => break,
                },
                Err(_) => break,
            }
        }
    }

    /// Emit every COMPLETE line held, each prefixed, leaving a partial tail for the next pass.
    ///
    /// Linear in the bytes drained: `start` only moves forward, so the scan never re-reads a line.
    fn drain_lines(&mut self, width: usize, out: &mut Vec<u8>) {
        let mut start = 0usize;
        while let Some(rest) = self.pending.get(start..) {
            let Some(nl) = rest.iter().position(|&b| b == b'\n') else {
                break;
            };
            let Some(line) = rest.get(..nl) else {
                break;
            };
            push_prefixed(out, &self.label, width, line);
            start = start.saturating_add(nl).saturating_add(1);
        }
        if start > 0 {
            self.pending.drain(..start);
        }
    }

    /// Emit a final line that never got its newline, once the box is gone and none is coming.
    fn flush_partial(&mut self, width: usize, out: &mut Vec<u8>) {
        if !self.pending.is_empty() {
            let held = std::mem::take(&mut self.pending);
            push_prefixed(out, &self.label, width, &held);
        }
    }
}

/// Write one labelled line: `label<pad> | text`, the shape `docker compose logs` uses.
fn push_prefixed(out: &mut Vec<u8>, label: &str, width: usize, line: &[u8]) {
    out.extend_from_slice(label.as_bytes());
    for _ in label.chars().count()..width {
        out.push(b' ');
    }
    out.extend_from_slice(b" | ");
    out.extend_from_slice(line);
    out.push(b'\n');
}

/// Follow SEVERAL services at once, interleaved and prefixed, until every one has exited or `stop`
/// is set.
///
/// WHY POLLING AND NOT A READER PER SERVICE. A log file never blocks: a read at EOF returns 0
/// immediately, so one pass over N files costs N cheap reads and the loop sleeps 200 ms between
/// passes, the same cadence the single-box follow already uses. A thread per service would buy
/// nothing (there is nothing to block on) and would need a lock around stdout to keep lines whole.
///
/// ORDERING WITHIN A PASS is by service, not by timestamp: kern's box logs carry no per-line clock,
/// so lines written 10 ms apart in two services cannot be truthfully interleaved. `docker compose
/// logs` has the same property. Lines are never split or mixed - the whole pass is written under one
/// stdout lock.
///
/// `until_first_exit` returns as soon as ONE service has ended instead of waiting for all of them,
/// which is what `--abort-on-container-exit` needs.
///
/// THE FINAL DRAIN is not decoration. A box that writes its last line and exits would lose that line
/// to a loop that checked the registry first and read second, so each service is read again AFTER
/// its death is observed, and only then marked done.
pub(crate) fn follow_many(
    mut who: Vec<Followed>,
    stop: &std::sync::atomic::AtomicBool,
    until_first_exit: bool,
) -> Result<(), Error> {
    use std::io::Write;
    if who.is_empty() {
        return Ok(());
    }
    // Align the prefixes, but never let one long service name push every line off the screen.
    let width = who
        .iter()
        .map(|w| w.label.chars().count())
        .max()
        .unwrap_or(0)
        .min(24);
    let stdout = std::io::stdout();
    let mut out: Vec<u8> = Vec::new();
    loop {
        out.clear();
        let mut live = 0usize;
        for w in who.iter_mut() {
            if w.done {
                continue;
            }
            w.read_available();
            w.drain_lines(width, &mut out);
            if registry::pair_alive(&w.box_name, w.pid) {
                live = live.saturating_add(1);
            } else {
                w.read_available();
                w.drain_lines(width, &mut out);
                w.flush_partial(width, &mut out);
                w.done = true;
            }
        }
        if !out.is_empty() {
            let mut lock = stdout.lock();
            if lock.write_all(&out).is_err() {
                return Ok(()); // a closed pipe ends the follow quietly, as in `follow_log`
            }
            let _ = lock.flush();
        }
        // `until_first_exit` is `--abort-on-container-exit`: the caller tears the stack down as soon
        // as ONE service ends, so the follow has to stop at the same moment rather than waiting for
        // the rest. The final drain above has already run for whichever service ended, so its last
        // line is out before this returns.
        let ended = if until_first_exit {
            who.iter().any(|w| w.done)
        } else {
            live == 0
        };
        if ended || stop.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(());
        }
        unsafe { libc::usleep(200_000) }; // 200 ms - the cadence `follow_log` already uses
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

#[cfg(test)]
mod rotation_tests {
    /// THE DESCRIPTOR HAS ONE OWNER, AND NOTHING MAY CLOSE IT BESIDE THAT OWNER.
    ///
    /// `CappedLog` closes its own fd in `Drop`, so any second `close` of the same field is a double
    /// close - and a double close does not fail where it is written. It succeeds, having destroyed
    /// whatever the operating system handed that number to in the meantime, and the crash surfaces
    /// in an unrelated place: this exact mistake, made in the test below, made `remove_dir_all`
    /// panic with `closedir: Bad file descriptor` in a DIFFERENT test on each run.
    ///
    /// A SOURCE SCAN because no runtime assertion can see it. The victim is another thread, the
    /// damage is invisible at the call site, and reproducing it takes a dozen runs of the whole
    /// binary; a rule about where the close may be written is checkable in microseconds.
    #[test]
    fn only_rotate_closes_the_log_descriptor_and_only_when_it_replaces_it() {
        let src = include_str!("boxlog.rs");
        // THE SHAPES ARE BUILT, NOT WRITTEN. The bug this guards lived in a TEST, so the scan has to
        // cover the test module too - and a scan that covers itself would count its own search
        // strings. Assembling them at run time keeps the literals out of the file entirely.
        let close_of = |holder: &str| format!("libc::{}({holder}.fd)", "close");
        assert_eq!(
            src.matches(&close_of("self")).count(),
            1,
            "exactly one close in this file: `rotate`, immediately before it assigns the \
             replacement. `Drop` (in `mod.rs`) closes the last one"
        );
        // Every other holder a `CappedLog` is bound to here. Each would be a hand-close of a
        // descriptor that already has an owner, which is a double close.
        for holder in ["log", "l", "cap", "logger"] {
            let shape = close_of(holder);
            assert_eq!(
                src.matches(&shape).count(),
                0,
                "`{shape}` closes a descriptor `Drop` already closes: the second call succeeds, \
                 having destroyed whatever the OS handed that number to in the meantime, and the \
                 crash lands in an unrelated test"
            );
        }
    }

    use super::*;

    /// ROTATION MUST KEEP EXACTLY `files` FILES, COUNTING THE ACTIVE ONE.
    ///
    /// That is Docker's `max-file` arithmetic, and getting it wrong in either direction is a bug a
    /// user only finds when a disk fills: one too many and the bound the caller was promised
    /// (`max-size * max-file`) is exceeded, one too few and a generation they asked to keep is gone.
    ///
    /// `files == 1` IS ITS OWN BRANCH. There is no generation to rename to, so the active file is
    /// truncated in place - and the offset has to be reset with it, because the pump drives the
    /// offset itself (the fd is not `O_APPEND`) and a truncate without the seek leaves the next
    /// write at the old offset, producing a sparse hole instead of a fresh log.
    #[test]
    fn rotation_keeps_exactly_max_file_generations_and_truncates_when_it_is_one() {
        let dir = std::env::temp_dir().join(format!("kern-rot-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);

        let run = |name: &str, files: u32| -> Vec<String> {
            let path = dir.join(name);
            let _ = std::fs::remove_file(&path);
            for i in 1..6 {
                let _ = std::fs::remove_file(dir.join(format!("{name}.{i}")));
            }
            let mut log = CappedLog::open(
                &path,
                LogCap {
                    max_bytes: 16,
                    files,
                },
            )
            .expect("the log opens");
            // Six caps' worth: enough to rotate past any generation count under test.
            for _ in 0..6 {
                log.write(b"0123456789abcdef");
            }
            // DROPPED, NEVER HAND-CLOSED. `CappedLog` already has a `Drop` that closes its
            // descriptor, so the hand-written `close` of that field originally here was a DOUBLE
            // CLOSE: the explicit call closed the real descriptor, and the drop at the end of this
            // closure closed the same NUMBER a second time - by which point another test thread had
            // reopened it as a directory handle.
            //
            // MEASURED, because the symptom pointed nowhere near here: the unit binary failed 3
            // times in 14 with `remove_dir_all` panicking `closedir: Bad file descriptor`, in a
            // DIFFERENT unrelated test each run, and 0 times in 11 on `main`. A stranger's
            // descriptor dying is what a second close looks like from the outside, and the only
            // reason it is intermittent is that the number has to be reused first.
            //
            // The explicit `drop` stays (rather than letting it fall out of scope) because the
            // ordering matters: the bytes must reach the file before the directory is listed.
            drop(log);
            let mut found: Vec<String> = std::fs::read_dir(&dir)
                .expect("readable")
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|f| f == name || f.starts_with(&format!("{name}.")))
                .collect();
            found.sort();
            found
        };

        assert_eq!(run("three", 3), vec!["three", "three.1", "three.2"]);
        assert_eq!(run("two", 2), vec!["two", "two.1"]);
        // One file, truncated in place: no generation is ever created.
        assert_eq!(run("one", 1), vec!["one"]);
        // And the truncation really reset the offset: a sparse file would be larger than the cap.
        let size = std::fs::metadata(dir.join("one")).expect("stat").len();
        assert!(
            size <= 16,
            "a truncate without the seek leaves a hole: {size}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE DEFAULT IS WHAT EVERY BOX HAD BEFORE THE FLAGS EXISTED.
    ///
    /// The two settings are one policy, and the whole safety of adding them is that an unset flag
    /// changes nothing. A default that drifted would silently re-bound every box in the field.
    #[test]
    fn the_default_log_cap_is_the_historic_one() {
        assert_eq!(
            LogCap::default(),
            LogCap {
                max_bytes: BOX_LOG_MAX_BYTES,
                files: 2
            }
        );
    }
}
