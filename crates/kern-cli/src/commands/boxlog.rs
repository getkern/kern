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
        if tail.as_deref().is_some_and(log_carries_a_reason) {
            return tail;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    read_log_tail(path, 1024)
}

/// Does this log tail already carry the supervisor's REASON, whatever shape it took?
///
/// THE PREDICATE USED TO BE TWO LITERAL STRINGS, and the commonest user error matched neither. It
/// waited for `box failed to start` or `user namespaces`; a command that does not exist makes the
/// supervisor write `kern: cannot start '<cmd>' in box: No such file or directory`, which contains
/// neither. MEASURED: `kern box -d --image alpine -- /nonexistent-binary` took 3.035 SECONDS, all of
/// it in this loop, and then printed a message that had been in the file since the first poll. The
/// same command in the FOREGROUND took 5 ms, which is what told me the cost was here and not in the
/// box. `kern compose up -d` on a stack with one such service paid the same three seconds.
///
/// ANCHORED ON kern'S OWN PREFIX, MINUS ITS BENIGN ONES, which is the discipline the Python binding
/// already applies to the same question (`_looks_like_startup_failure`): the workload cannot forge a
/// verdict, because a `kern:` line here is written by the supervisor before the workload's output
/// reaches this file, and the three benign kinds - the posture banner, `warning:` and `note:` - are
/// exactly the lines that are NOT a reason. Matching on the prefix rather than on a sentence means
/// the next failure message kern grows is covered on the day it is written, instead of quietly
/// costing three seconds until someone measures it.
fn log_carries_a_reason(tail: &str) -> bool {
    tail.lines().any(|line| {
        let l = line.trim_start();
        l.starts_with("kern:") && !BENIGN_KERN_LINES.iter().any(|b| l.starts_with(b))
    })
}

/// The `kern:` lines that are NOT a failure reason, in one place because they are a set that grows.
///
/// A box that starts perfectly well can print all three: the posture banner (`print_box_status`), a
/// `warning:` about caps it could not enforce, and a `note:` about the wiring it chose. Anything else
/// carrying kern's prefix is the supervisor saying why the box did not start. A new benign kind added
/// to the product and not to this list would end the reason-wait early and report a warning as the
/// cause; a new FAILURE kind needs no change here, which is the asymmetry to preserve.
///
/// The Python binding holds the same three under the same reasoning (`_KERN_DIAGNOSTICS`). Two
/// processes in two languages cannot share a constant, so what they share is the rule and this note.
const BENIGN_KERN_LINES: [&str; 3] = ["kern: note:", "kern: warning:", "kern: security-profile="];

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
    /// The time index, `<path>.idx`: fixed 16-byte records of `(offset, unix nanos)`, appended at
    /// most once per `mark_every`. `-1` when it could not be opened, which costs only `logs -t`.
    ///
    /// 🔴 A SIDECAR AND NOT A PREFIX PER LINE, and the pump is the reason. It moves bytes with
    /// `splice(2)`, pipe to file, which never brings them into userspace: measured at 599 MB/s here
    /// against the 22 MB/s a shell workload produces. Framing each line would mean reading every
    /// byte back, scanning for newlines and rewriting - it would end the zero copy for a feature
    /// nobody uses on most boxes. So the log stays BYTE FOR BYTE what the box wrote, and the times
    /// live beside it.
    ///
    /// The cost of that choice, and it is stated in `logs --help` rather than hidden: a line's time
    /// is the time of the mark it falls after, so lines written inside one interval share a stamp.
    idx_fd: i32,
    /// Monotonic nanos of the last mark, so the interval survives a wall-clock step.
    last_mark: u64,
    /// Bytes currently in the index, tracked rather than `stat`ed: the pump must not pay a syscall
    /// per write to learn something it is the only writer of.
    idx_len: u64,
    /// The CURRENT mark interval, which doubles every time the index is compacted. Starts at
    /// [`MARK_EVERY`]; see [`CappedLog::compact_index`] for why it is a field and not a constant.
    mark_every: u64,
    /// Bytes of the box's output shed since the log last took a write: the store was full, or a
    /// rotation could not free room. Said IN THE LOG, at the gap, by the next write that lands
    /// ([`CappedLog::note_dropped`]): before this a full store lost lines and no reader could
    /// tell, `kern logs` included.
    pub(crate) dropped: u64,
    /// `<path>.streams` (`--log-streams` only, else `-1`), the stream of the bytes being written now,
    /// the last stream recorded (`0` = none yet, so the first write records one), and the sidecar's
    /// size. See [`streams_path`].
    streams_fd: i32,
    pub(crate) cur_stream: u8,
    last_stream: u8,
    /// The offset the last record points at: records store the step from it.
    last_stream_at: u64,
    streams_len: u64,
    split: bool,
}

/// The STARTING interval between time marks, and the finest resolution `logs -t` ever claims.
///
/// It only ever gets coarser: [`CappedLog::compact_index`] doubles it each time the index reaches its
/// cap, so a box that runs for days trades resolution for a bounded file rather than growing one
/// without limit. A stamp is therefore "the start of the bucket this line fell in", where the bucket
/// is at least this long.
///
/// Chosen against the two costs it sits between: a mark is 16 bytes and one `write`, so ten a second
/// is nothing next to a log that may hold 16 MiB, while a finer interval would buy a precision the
/// reader cannot use (a box that prints a thousand lines in one millisecond does not have a thousand
/// distinguishable instants worth showing).
const MARK_EVERY: u64 = 100_000_000;

/// Monotonic nanos, for the mark interval.
fn mono_nanos() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: one live local `timespec`, filled by the kernel.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// Wall-clock nanos since the epoch, which is what a reader wants to see.
fn wall_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// One record in `<log>.idx`.
pub(crate) const MARK_LEN: usize = 16;

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
    /// `false` for `--log-driver none`: the output goes to `/dev/null` and no log file is made.
    pub(crate) keep: bool,
    /// `--log-streams`, written by the Docker API server for the boxes it creates: stdout and stderr
    /// reach the pump on TWO pipes and `<log>.streams` records which stream each stretch of the log
    /// came from, so `docker logs` can answer them apart. Off everywhere else, where the pump keeps
    /// its single pipe exactly as before. See [`streams_path`].
    pub(crate) streams: bool,
    /// `--log-driver journald`: every line ALSO goes to the systemd journal, tagged with the box's
    /// name, as Docker's journald driver tags a container's; the file is kept, so `kern logs` reads
    /// the box as before (Docker's "dual logging"). The pump reads the bytes then, instead of
    /// splicing them past userspace, and takes stdout and stderr on two pipes for their priority.
    pub(crate) journald: bool,
}

impl Default for LogCap {
    /// EXACTLY WHAT EVERY BOX HAD BEFORE THE FLAGS EXISTED: 16 MiB active plus one rotated
    /// generation. Stated as the default rather than left implicit at the call sites, so adding a
    /// caller cannot quietly change the bound a box has always had.
    fn default() -> Self {
        Self {
            max_bytes: BOX_LOG_MAX_BYTES,
            files: 2,
            keep: true,
            streams: false,
            journald: false,
        }
    }
}

impl LogCap {
    /// The cap a box gets: its own `--log-max-size` / `--log-max-file` first, then `[kern]
    /// log_max_size` / `log_max_file` from the default `kern.toml`, then [`LogCap::default`].
    ///
    /// ONE RESOLVER, so the detached path and the systemd-managed path cannot read the precedence
    /// two ways. The config is read only when a flag is missing, so a box that names both pays no
    /// file read for it.
    pub(crate) fn resolve(flag_size: Option<u64>, flag_files: Option<u32>, keep: bool) -> Self {
        let base = LogCap::default();
        let cfg = if flag_size.is_none() || flag_files.is_none() {
            crate::config::load_cached(None).ok()
        } else {
            None
        };
        let k = cfg.as_ref().map(|c| &c.kern);
        Self::pick(
            flag_size,
            flag_files,
            k.and_then(|k| k.log_max_size),
            k.and_then(|k| k.log_max_file),
            keep,
        )
        .with_base(base)
    }

    /// The precedence alone, with no file read: flag, then config, then the built-in.
    fn pick(
        flag_size: Option<u64>,
        flag_files: Option<u32>,
        cfg_size: Option<u64>,
        cfg_files: Option<u32>,
        keep: bool,
    ) -> PartialCap {
        PartialCap {
            max_bytes: flag_size.or(cfg_size).filter(|n| *n > 0),
            files: flag_files.or(cfg_files).filter(|n| *n > 0),
            keep,
        }
    }
}

/// A cap whose missing parts come from a base: what [`LogCap::pick`] returns.
struct PartialCap {
    max_bytes: Option<u64>,
    files: Option<u32>,
    keep: bool,
}

impl PartialCap {
    fn with_base(self, base: LogCap) -> LogCap {
        LogCap {
            max_bytes: self.max_bytes.unwrap_or(base.max_bytes),
            files: self.files.unwrap_or(base.files),
            keep: self.keep,
            streams: base.streams,
            journald: base.journald,
        }
    }
}

/// `<log>.streams`: which stream each stretch of a `--log-streams` log came from.
///
/// 🔴 A SIDECAR, FOR THE SAME REASON AS THE TIME INDEX: the pump moves bytes with `splice(2)` and
/// never sees them, so the log stays byte for byte what the box wrote and `kern logs` reads it as it
/// always did. One record is written only when the stream CHANGES: a box that writes only stdout
/// leaves one record, an interleaved one a record per switch.
///
/// A RECORD IS 4 BYTES, little-endian: bit 31 is the stream (0 stdout, 1 stderr) and bits 0-30 how
/// far the stretch starts after the previous record's (the first counts from 0). Compact because the
/// count is what a chatty box spends: MEASURED with 16-byte `(offset, stream)` records capped like the
/// time index, a box alternating 6-byte lines on the two streams filled the record within a quarter
/// of its 1 MiB log and 17 711 line pieces were then filed as stdout. At 4 bytes, capped at half the
/// log (see [`CappedLog::note_stream`]), lines of 8 bytes or more stay apart for the whole log.
/// Bytes before the first record, and every byte of a log written without the flag, read as stdout.
pub(crate) fn streams_path(log: &std::path::Path) -> std::path::PathBuf {
    let mut p = log.to_path_buf().into_os_string();
    p.push(".streams");
    std::path::PathBuf::from(p)
}

/// Docker's stream numbers, as recorded in [`streams_path`] and framed by `kern logs --frames`.
pub(crate) const STREAM_STDOUT: u8 = 1;
pub(crate) const STREAM_STDERR: u8 = 2;

/// The bytes of one stream record. See [`streams_path`].
const STREAM_REC_LEN: usize = 4;
/// The largest step one record can describe (31 bits); a longer stretch is bridged by records that
/// repeat the stream.
const STREAMS_MAX_STEP: u64 = 0x7FFF_FFFF;

/// `<log>.idx`, beside the log rather than inside it. Same directory, same rotation, same lifetime.
pub(crate) fn idx_path(log: &std::path::Path) -> std::path::PathBuf {
    let mut p = log.to_path_buf().into_os_string();
    p.push(".idx");
    std::path::PathBuf::from(p)
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
            // BEST EFFORT, and its failure costs only `logs -t`. A box whose log opened but whose
            // index did not must still run and must still log: a missing index reads back as "no
            // times recorded", which is exactly what an older kern's log is too.
            idx_fd: open_log(&idx_path(path), false),
            // Zero means "no mark yet", so the first write always records one and a log never starts
            // with an unattributable stretch.
            last_mark: 0,
            idx_len: 0,
            mark_every: MARK_EVERY,
            dropped: 0,
            // Appended to, like the log: a log reopened for another run of the same box keeps its
            // earlier records, whose offsets still describe the same file.
            streams_fd: if cap.streams {
                open_log(&streams_path(path), true)
            } else {
                -1
            },
            cur_stream: STREAM_STDOUT,
            last_stream: 0,
            last_stream_at: 0,
            streams_len: 0,
            split: cap.streams,
        })
    }

    /// Write the line that says how much was lost here, if anything was, before the bytes that come
    /// after the gap. Best effort: a store still full keeps the count for the next attempt.
    pub(crate) fn note_dropped(&mut self) {
        if self.dropped == 0 || self.written >= self.max {
            return;
        }
        let line = format!(
            "kern: warning: {} byte(s) of this box's output were dropped here: the log store was \
             full (`kern prune` frees the logs of boxes that ended)\n",
            self.dropped
        );
        let room = usize::try_from(self.max - self.written).unwrap_or(usize::MAX);
        if line.len() > room {
            return;
        }
        // SAFETY: a live buffer of the length passed, to a descriptor this struct owns.
        let n = unsafe { libc::write(self.fd, line.as_ptr().cast(), line.len()) };
        if n == line.len() as isize {
            // kern's own line, so it is stderr whatever the box was writing around it.
            let box_stream = std::mem::replace(&mut self.cur_stream, STREAM_STDERR);
            self.mark();
            self.cur_stream = box_stream;
            self.written += line.len() as u64;
            self.dropped = 0;
        }
    }

    /// Rename the active file to `<path>.1` (one generation kept, overwriting a previous `.1`) and reopen
    /// a fresh empty file. The rename is atomic, so a reader never sees the path missing. On failure the
    /// old fd is kept and `written` stays at the cap, so the next `write` retries rather than overflowing.
    /// Start the index over, because rotation makes every offset in it a lie.
    ///
    /// The index describes the ACTIVE file, and rotation either truncates that file to zero or moves
    /// it to `.1` and opens a fresh one. Either way offset 0 now means a different byte, so an index
    /// kept across the boundary would attribute the new file's lines to the old file's times - a
    /// wrong answer delivered confidently, which is worse than no answer. `logs -t` on a rotated
    /// generation therefore shows no times, and says so rather than guessing.
    fn reset_index(&mut self) {
        if self.idx_fd < 0 {
            return;
        }
        // SAFETY: truncating and rewinding a descriptor this struct owns.
        unsafe {
            libc::ftruncate(self.idx_fd, 0);
            libc::lseek(self.idx_fd, 0, libc::SEEK_SET);
        }
        self.last_mark = 0;
        self.idx_len = 0;
        self.mark_every = MARK_EVERY;
    }

    /// Start the stream record over with the file it describes, for the reason [`reset_index`] gives:
    /// after a rotation offset 0 is a different byte. A record closed early (stream `0`) is reopened,
    /// because the new generation can be described again.
    ///
    /// [`reset_index`]: CappedLog::reset_index
    fn reset_streams(&mut self) {
        if !self.split {
            return;
        }
        if self.streams_fd < 0 {
            self.streams_fd = open_log(&streams_path(&self.path), true);
        }
        if self.streams_fd >= 0 {
            // SAFETY: truncating a descriptor this struct owns; `O_APPEND` puts the next record at 0.
            unsafe { libc::ftruncate(self.streams_fd, 0) };
        }
        self.last_stream = 0;
        self.last_stream_at = 0;
        self.streams_len = 0;
    }

    /// Record that the stream changes to `cur_stream` at `written`, when it differs from the last one
    /// recorded. Called from [`CappedLog::mark`], so it runs at exactly the two sites that advance
    /// `written`, immediately before the advance: the record points at the first byte of the stretch.
    ///
    /// BOUNDED at half the log's own cap: a box alternating streams on every write spends 4 bytes a
    /// switch. At the bound the last record is a STDOUT one and the record stops: the rest of the
    /// generation reads as stdout, separation degrades and the log itself loses nothing. A write
    /// that fails stops it the same way, minus that last record.
    fn note_stream(&mut self) {
        if self.streams_fd < 0 || self.cur_stream == self.last_stream {
            return;
        }
        let max = (self.max / 2).max(4096);
        let bit = |stream: u8| {
            if stream == STREAM_STDERR {
                1u32 << 31
            } else {
                0
            }
        };
        let mut step = self.written.saturating_sub(self.last_stream_at);
        // Bridge a stretch longer than one record can step over, under the stream it already has.
        while step > STREAMS_MAX_STEP {
            if !self.put_stream_record(bit(self.last_stream) | STREAMS_MAX_STEP as u32, max) {
                return;
            }
            self.last_stream_at += STREAMS_MAX_STEP;
            step -= STREAMS_MAX_STEP;
        }
        let rec = bit(self.cur_stream) | step as u32;
        if self.put_stream_record(rec, max) {
            self.last_stream = self.cur_stream;
            self.last_stream_at = self.written;
        }
    }

    /// Append one record; when it is the last that fits under `max`, as stdout, and stop. `false`
    /// once the record is closed.
    fn put_stream_record(&mut self, rec: u32, max: u64) -> bool {
        let full = self.streams_len + 2 * STREAM_REC_LEN as u64 > max;
        let rec = if full { rec & 0x7FFF_FFFF } else { rec };
        let bytes = rec.to_le_bytes();
        // SAFETY: a live local buffer of exactly the length passed, to a descriptor this struct owns.
        let n = unsafe { libc::write(self.streams_fd, bytes.as_ptr().cast(), bytes.len()) };
        if n != bytes.len() as isize || full {
            // SAFETY: closing a descriptor this struct owns, once; `-1` stops every later use.
            unsafe { libc::close(self.streams_fd) };
            self.streams_fd = -1;
            return false;
        }
        self.streams_len += STREAM_REC_LEN as u64;
        true
    }

    /// The index may not outgrow this. Beyond it the marks are thinned by half and the interval
    /// doubles, so a log that lives for days loses RESOLUTION instead of growing without bound.
    ///
    /// MEASURED, and it is the one way this feature could have hurt a running box: the log has a cap
    /// and the index had none. A service printing one line a second writes one mark a second - 16
    /// bytes for a ~20-byte line - so after a day its index was 1.4 MB against 50 KB of log, in
    /// `$XDG_RUNTIME_DIR`, which on most machines is tmpfs and therefore RAM. A week of `logs -t
    /// --tail 10` on such a box also read 92 MB to print ten lines, and took 164 ms doing it.
    ///
    /// A FRACTION OF THE LOG'S OWN CAP and not a constant, because a caller who asked for a 64 KiB
    /// log did not ask to spend a megabyte on its times. The floor keeps a very small log's index
    /// useful rather than compacting it into uselessness on the first rotation.
    fn idx_max(&self) -> u64 {
        (self.max / 16).max(4096)
    }

    /// Keep every other mark, rewrite the index, and double the interval.
    ///
    /// Thinning is honest where truncating would not be: a mark says "the bytes from here on were
    /// written at or after this time", so dropping one makes its successor's answer COARSER (an
    /// earlier time, by at most one interval) and never later than the line it labels, which is the
    /// same guarantee every stamp already carries. Dropping the OLDEST marks instead would leave the
    /// head of the log unattributed, which is a different and worse answer.
    fn compact_index(&mut self) {
        let Ok(data) = std::fs::read(idx_path(&self.path)) else {
            return self.drop_index();
        };
        let mut out = Vec::with_capacity(data.len() / 2 + MARK_LEN);
        for (i, rec) in data.chunks_exact(MARK_LEN).enumerate() {
            if i % 2 == 0 {
                out.extend_from_slice(rec);
            }
        }
        // SAFETY: rewinding and truncating a descriptor this struct owns, then writing a live local
        // buffer of exactly the length passed.
        let n = unsafe {
            libc::ftruncate(self.idx_fd, 0);
            libc::lseek(self.idx_fd, 0, libc::SEEK_SET);
            libc::write(self.idx_fd, out.as_ptr().cast(), out.len())
        };
        if n != out.len() as isize {
            return self.drop_index();
        }
        self.idx_len = out.len() as u64;
        self.mark_every = self.mark_every.saturating_mul(2);
    }

    /// Stop indexing for the rest of this log's life, leaving what is already there readable.
    ///
    /// Every index failure ends here rather than at its own call site, so "the index gave up" is one
    /// state with one spelling instead of a condition each writer has to remember to set.
    fn drop_index(&mut self) {
        // SAFETY: closing a descriptor this struct owns, exactly once; `-1` stops every later use.
        unsafe { libc::close(self.idx_fd) };
        self.idx_fd = -1;
    }

    /// Close the two sidecars (time index, stream record). For `Drop`, beside the log's own fd.
    pub(crate) fn close_sidecars(&mut self) {
        for fd in [&mut self.idx_fd, &mut self.streams_fd] {
            if *fd >= 0 {
                // SAFETY: a descriptor this struct owns, closed once and then forgotten.
                unsafe { libc::close(*fd) };
                *fd = -1;
            }
        }
    }

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
                self.reset_index();
                self.reset_streams();
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
            self.reset_index();
            self.reset_streams();
        }
    }

    /// Record `(written, now)` if at least [`MARK_EVERY`] has passed since the last one.
    ///
    /// CALLED FROM BOTH SITES THAT ADVANCE `written`, IMMEDIATELY BEFORE THE ADVANCE, and from nowhere
    /// else. Two reasons, and both were measured rather than reasoned:
    ///
    /// - Both sites, because the pump advances the offset in two places (the `splice` loop and the
    ///   userspace `write`), and a mark written in one of them only would leave half a log
    ///   unattributed with nothing to say so.
    /// - BEFORE and not after, because a mark holds the offset of the FIRST byte it describes. After
    ///   the advance it held the offset of the byte AFTER the batch, so nothing pointed at offset 0
    ///   and the first line of every log printed `-`: `kern logs -t` on a box that echoed three lines
    ///   attributed two of them and shrugged at the first. It also makes each mark the START of its
    ///   bucket rather than the end, so a stamp is never later than the line it labels.
    ///
    /// Failure is silence. A short `write` is treated as no mark at all rather than as a torn record:
    /// the reader refuses a trailing partial record for the same reason, so the two agree without
    /// either of them having to trust the other.
    fn mark(&mut self) {
        self.note_stream();
        if self.idx_fd < 0 {
            return;
        }
        let now = mono_nanos();
        if self.last_mark != 0 && now.saturating_sub(self.last_mark) < self.mark_every {
            return;
        }
        self.last_mark = now;
        let mut rec = [0u8; MARK_LEN];
        rec[..8].copy_from_slice(&self.written.to_le_bytes());
        rec[8..].copy_from_slice(&wall_nanos().to_le_bytes());
        // SAFETY: a live local buffer of exactly the length passed, to a descriptor this struct owns.
        let n = unsafe { libc::write(self.idx_fd, rec.as_ptr().cast(), rec.len()) };
        if n != rec.len() as isize {
            // Out of space, or a partial write: stop indexing rather than leave a torn record behind.
            return self.drop_index();
        }
        self.idx_len += MARK_LEN as u64;
        if self.idx_len >= self.idx_max() {
            self.compact_index();
        }
    }

    fn write(&mut self, mut buf: &[u8]) {
        while !buf.is_empty() {
            if self.written >= self.max {
                self.rotate();
                if self.written >= self.max {
                    // rotation failed (rename/open) - drop rather than spin or overflow the cap
                    self.dropped = self.dropped.saturating_add(buf.len() as u64);
                    return;
                }
            }
            self.note_dropped();
            let room = (self.max - self.written) as usize;
            let chunk = &buf[..buf.len().min(room)];
            let n = unsafe { libc::write(self.fd, chunk.as_ptr().cast(), chunk.len()) };
            if n < 0 {
                match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::EINTR) => continue,
                    // Disk full: drop the chunk and force a rotation next round (freeing `.1`'s space).
                    // The workload must NEVER block or die because its log is full - the log is
                    // diagnostics, not part of the workload's contract.
                    Some(libc::ENOSPC) | Some(libc::EDQUOT) => {
                        self.written = self.max;
                        self.dropped = self.dropped.saturating_add(buf.len() as u64);
                        return;
                    }
                    _ => {
                        self.dropped = self.dropped.saturating_add(buf.len() as u64);
                        return;
                    }
                }
            }
            self.mark();
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
    pump_capped_streams(&mut [(rd, STREAM_STDOUT)], path, cap);
}

/// Which source the pump reads next: the only one, or, with two, one `poll` reports readable (or hung
/// up: its EOF must be read too). When both are, the one NOT served last goes first, so a flooding
/// stream cannot starve the other, and stdout goes first at the start. `None` when every source has
/// reached EOF.
///
/// WHAT TWO PIPES CANNOT TELL: which of two writes that are both waiting came first. Docker's own
/// log driver reads the two streams separately and has the same limit; a box whose writes are apart
/// in time (a line, then the next) keeps its order.
///
/// ONE SOURCE NEVER POLLS. That is every box but the Docker API's, and its loop stays exactly the
/// `splice` it was, without a syscall added per chunk.
fn next_source(sources: &[(i32, u8)], last: Option<usize>) -> Option<usize> {
    // At most two sources (stdout, stderr): fixed arrays, no allocation per chunk.
    let mut open = [0usize; 2];
    let mut fds = [libc::pollfd {
        fd: -1,
        events: libc::POLLIN,
        revents: 0,
    }; 2];
    let mut count = 0usize;
    for (i, &(fd, _)) in sources.iter().enumerate().take(2) {
        if fd >= 0 {
            open[count] = i;
            fds[count].fd = fd;
            count += 1;
        }
    }
    match count {
        0 => return None,
        1 => return Some(open[0]),
        _ => {}
    }
    loop {
        // SAFETY: a live array of `count` (= 2) pollfd structs.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), count as libc::nfds_t, -1) };
        if n > 0 {
            break;
        }
        if n < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            // poll itself failing is not a reason to stop draining: read the first, blocking.
            return Some(open[0]);
        }
    }
    let ready = |k: usize| fds[k].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0;
    let first = usize::from(last == Some(open[0]));
    [first, 1 - first]
        .into_iter()
        .find(|&k| ready(k))
        .map(|k| open[k])
        .or(Some(open[0]))
}

/// [`pump_capped_log`] over one or more `(pipe, stream)` sources, until every one reaches EOF. With
/// two (`--log-streams`) each stretch is recorded with its stream; see [`streams_path`].
fn pump_capped_streams(sources: &mut [(i32, u8)], path: &std::path::Path, cap: LogCap) {
    let mut log = CappedLog::open(path, cap);
    // A /dev/null sink for the no-log case and disk-full overflow: the pipe must still be drained.
    let void = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    // `--log-driver journald`: the bytes have to pass through here to reach the journal too.
    let mut journal = cap.journald.then(|| Journal::for_log(path)).flatten();
    let mut use_splice = journal.is_none();
    let mut scratch = [0u8; 64 * 1024]; // read+write fallback buffer (splice-unsupported fs)
                                        // Set when there is nowhere left to put the bytes. The pipe is still drained - see the note on
                                        // this function about what leaving instead costs the workload.
    let mut discard = false;
    let mut last = None;
    // Until every source is at EOF.
    while let Some(at) = next_source(sources, last) {
        last = Some(at);
        let (rd, stream) = sources[at];
        // EOF (or a read error) on THIS source ends this source; the loop ends with the last one.
        let ended = |sources: &mut [(i32, u8)]| sources[at].0 = -1;
        if discard {
            // SAFETY: `scratch` is a live buffer this frame owns and `rd` is the pipe read end.
            let n = unsafe { libc::read(rd, scratch.as_mut_ptr().cast(), scratch.len()) };
            if n > 0 {
                continue; // bytes read and dropped: the box keeps writing, and keeps living
            }
            if n == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                ended(sources); // EOF, or a read error on the pipe itself: nothing left to serve here
            }
            continue;
        }
        if let Some(l) = log.as_mut() {
            l.cur_stream = stream;
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
                    // Room again after a shed: say what was lost before the bytes after it.
                    l.note_dropped();
                    let room = l.max.saturating_sub(l.written);
                    if room == 0 {
                        (void, PUMP_SPLICE_CHUNK, false)
                    } else {
                        (l.fd, room.min(PUMP_SPLICE_CHUNK as u64) as usize, true)
                    }
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
                Ok(0) => ended(sources), // EOF: every write end (workload + supervisor) is closed
                Ok(n) => {
                    if let Some(l) = log.as_mut() {
                        if to_log {
                            l.mark();
                            l.written += n as u64;
                        } else {
                            // Shed to /dev/null: counted, so the log says so when it can.
                            l.dropped = l.dropped.saturating_add(n as u64);
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
                if let Some(j) = journal.as_mut() {
                    j.feed(stream, &scratch[..n as usize]);
                }
                match log.as_mut() {
                    Some(l) => l.write(&scratch[..n as usize]),
                    None => {
                        let _ = unsafe { libc::write(void, scratch.as_ptr().cast(), n as usize) };
                    }
                }
            } else if n == 0 {
                ended(sources); // EOF: every write end (workload + supervisor) is closed
            } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                ended(sources); // a real error on the pipe read end itself; EINTR retries
            }
        }
    }
    if let Some(j) = journal.as_mut() {
        j.flush();
    }
    if void >= 0 {
        unsafe { libc::close(void) };
    }
}

/// The systemd journal's socket: where `--log-driver journald` sends a box's lines.
pub(crate) const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

/// The journal as a box's log driver: lines in, one journal entry each, with the box's name as
/// `CONTAINER_NAME` and `SYSLOG_IDENTIFIER` (Docker's journald driver sets both), and stdout at
/// priority 6 (info), stderr at 3 (err), as Docker's does. Native protocol on a datagram socket, no
/// library: `KEY=value` lines, one entry per datagram. A send that fails is dropped: the file keeps
/// the line, and a box never waits on the journal.
struct Journal {
    sock: std::os::unix::net::UnixDatagram,
    name: String,
    /// A line not yet ended, per stream (stdout, stderr).
    pending: [Vec<u8>; 2],
}

/// The longest line sent as one entry; a longer one is sent in pieces of this size.
const JOURNAL_LINE_MAX: usize = 16 * 1024;

impl Journal {
    /// The journal for the box whose log is `path` (`<name>-<pid>.log`).
    fn for_log(path: &std::path::Path) -> Option<Self> {
        let file = path.file_name()?.to_str()?;
        let key = crate::registry::split_log_file(file)?.0;
        let name = key.rsplit_once('-').map_or(key, |(n, _)| n).to_string();
        let sock = std::os::unix::net::UnixDatagram::unbound().ok()?;
        sock.connect(JOURNAL_SOCKET).ok()?;
        Some(Self {
            sock,
            name,
            pending: [Vec::new(), Vec::new()],
        })
    }

    fn feed(&mut self, stream: u8, bytes: &[u8]) {
        let i = usize::from(stream == STREAM_STDERR);
        self.pending[i].extend_from_slice(bytes);
        while let Some(at) = self.pending[i].iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.pending[i].drain(..=at).collect();
            self.send(i, &line[..line.len() - 1]);
        }
        while self.pending[i].len() >= JOURNAL_LINE_MAX {
            let part: Vec<u8> = self.pending[i].drain(..JOURNAL_LINE_MAX).collect();
            self.send(i, &part);
        }
    }

    /// What is left without a newline at the end of the box's output.
    fn flush(&mut self) {
        for i in 0..2 {
            let rest = std::mem::take(&mut self.pending[i]);
            if !rest.is_empty() {
                self.send(i, &rest);
            }
        }
    }

    fn send(&self, stream: usize, line: &[u8]) {
        let _ = self
            .sock
            .send(&journal_entry(&self.name, stream == 1, line));
    }
}

/// One journal entry in the native protocol. `MESSAGE` is written in the binary form (name, newline,
/// little-endian length, bytes), which takes any byte; the other fields are plain `KEY=value` lines.
fn journal_entry(name: &str, stderr: bool, line: &[u8]) -> Vec<u8> {
    let mut e = Vec::with_capacity(line.len() + name.len() * 2 + 96);
    let name: String = name.chars().filter(|c| !c.is_control()).collect();
    e.extend_from_slice(format!("PRIORITY={}\n", if stderr { 3 } else { 6 }).as_bytes());
    e.extend_from_slice(format!("SYSLOG_IDENTIFIER={name}\nCONTAINER_NAME={name}\n").as_bytes());
    e.extend_from_slice(b"MESSAGE\n");
    e.extend_from_slice(&(line.len() as u64).to_le_bytes());
    e.extend_from_slice(line);
    e.push(b'\n');
    e
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
///
/// RETURNS `(stdout, stderr)` write ends. They are the SAME descriptor unless `cap.streams` asks for
/// the two apart, and then the pump reads two pipes (see [`streams_path`]); a second pipe that cannot
/// be made leaves the box on one, which costs only the separation.
pub(crate) unsafe fn start_log_pump(path: &std::path::Path, cap: LogCap) -> Option<(i32, i32)> {
    let mut fds = [0i32; 2];
    if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
        return None;
    }
    let (rd, wr) = (fds[0], fds[1]);
    let mut efds = [-1i32; 2];
    if (cap.streams || cap.journald) && libc::pipe2(efds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
        efds = [-1, -1];
    }
    let (erd, ewr) = (efds[0], efds[1]);
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
    if ewr >= 0 {
        libc::fchmod(ewr, 0o666);
        libc::fcntl(erd, libc::F_SETPIPE_SZ, PUMP_SPLICE_CHUNK as libc::c_int);
    }
    let pid = libc::fork();
    if pid < 0 {
        for fd in [rd, wr, erd, ewr] {
            if fd >= 0 {
                libc::close(fd);
            }
        }
        return None;
    }
    if pid == 0 {
        // ITS OWN PROCESS GROUP, so no signal meant for the box's group can end it before the log
        // is whole. `kern stop` signals the supervisor's group (`kill(-pid, sig)`: a foreground
        // box's helpers must hear it), and then SIGKILLs it; in that group the pump died on the
        // SIGTERM while the workload's handler was still writing, and on the SIGKILL before it had
        // drained the pipe. MEASURED (0.56.0 and this branch): a box whose `trap ... TERM` printed
        // two lines and exited 0 had neither in `kern logs` after `kern stop`, a second later or
        // ever. The pump ends as it always has, at the end of its pipes, once every writer (the
        // box and the supervisor) has closed them.
        libc::setpgid(0, 0);
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
        // Shed every OTHER inherited fd except the read end(s) - most importantly the readiness-pipe
        // write end, which held here would stop the launcher from ever seeing EOF and hang `kern box
        // -d`. The write ends go too: a pump holding one would never see that stream's EOF.
        if erd >= 0 {
            kern_isolation::shed_inherited_fds_keeping(&[rd, erd]);
            pump_capped_streams(&mut [(rd, STREAM_STDOUT), (erd, STREAM_STDERR)], path, cap);
        } else {
            kern_isolation::shed_inherited_fds(rd);
            pump_capped_log(rd, path, cap);
        }
        libc::_exit(0);
    }
    // The parent keeps only the write ends (dup2'd onto 1/2 by the caller, then closed).
    PUMP_PID.store(pid, std::sync::atomic::Ordering::Release);
    libc::close(rd);
    if erd >= 0 {
        libc::close(erd);
    }
    Some((wr, if ewr >= 0 { ewr } else { wr }))
}

/// The log pump this process forked ([`start_log_pump`]), 0 for none. One per supervisor: it
/// outlives every `--restart` attempt and ends with the box.
static PUMP_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// How long a supervisor waits for its pump to finish the log. The pump only drains what its pipe
/// still holds (at most [`PUMP_SPLICE_CHUNK`]) into a file; a process that somehow still held a
/// write end must not keep the supervisor, and so the box's name, up past this.
const PUMP_FINISH_MS: i32 = 2000;

/// Let go of the log pump's pipes: fds 1 and 2 of the supervisor ARE them, and a pipe's reader sees
/// EOF only when the last write end closes, which was this process's exit. Called as soon as the box
/// has ended, so the pump drains and exits while the rest of the teardown runs; nothing this process
/// writes after its box has ended is the box's output. Idempotent.
pub(crate) fn release_log_pump() {
    if PUMP_PID.load(std::sync::atomic::Ordering::Acquire) <= 0 {
        return;
    }
    // SAFETY: `open`/`dup2`/`close` on descriptors this process owns; a failed open leaves 1/2 as
    // they are, and [`finish_log_pump`]'s bounded wait then simply times out.
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if null >= 0 {
            libc::dup2(null, 1);
            libc::dup2(null, 2);
            libc::close(null);
        }
    }
}

/// End the log pump BEFORE the supervisor leaves the registry, so a box that is no longer
/// registered is a box whose log is complete.
///
/// THE PUMP COULD ONLY END AFTER THE SUPERVISOR ([`release_log_pump`] says why), so a follower
/// that stopped when the box left the registry could stop before the last bytes reached the file;
/// it was the 200 ms poll of `kern logs -f` that hid it, and a follow that wakes at the removal
/// (see [`BoxWaiter`]) needs it to be true. Releases the pipes if that was not done yet, waits for
/// the pump (bounded), and reaps it.
pub(crate) fn finish_log_pump() {
    release_log_pump();
    let pid = PUMP_PID.swap(0, std::sync::atomic::Ordering::AcqRel);
    if pid <= 0 {
        return;
    }
    match crate::pidfd::PidFd::open(pid) {
        Some(p) => {
            let _ = p.wait_exit(PUMP_FINISH_MS);
        }
        None => {
            for _ in 0..PUMP_FINISH_MS {
                // SAFETY: `waitpid` on this process's own child, non-blocking.
                if unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) } == pid {
                    return;
                }
                // SAFETY: `usleep` takes an integer and has no other effect.
                unsafe { libc::usleep(1000) };
            }
        }
    }
    // SAFETY: reaping this process's own child, non-blocking: a pump still running past the bound
    // is left to finish on its own.
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
}

/// What a waiter for a box sleeps on: an entry leaving the registry (inotify on the instances dir)
/// and, for a follow, the log changing (inotify on the file, and on its directory for a rotation),
/// or a floor timer, whichever is first. `kern logs -f` and `kern wait` both.
///
/// THEY POLLED, 200 and 100 ms, so output reached a follower late, and the end of a box was seen
/// late, by up to that much; an attached `docker run` over kern's Docker API is a follow and a wait,
/// and paid both on every command. The end is the entry's REMOVAL, not the supervisor's exit: the
/// supervisor still cleans up after it leaves the registry (MEASURED about 10 ms), and both callers
/// test the registry. Without inotify, the floor is the old poll exactly; a supervisor that died
/// without removing its entry is found by the caller's liveness check at the floor.
pub(crate) struct BoxWaiter {
    inotify: Option<std::os::fd::OwnedFd>,
}

impl BoxWaiter {
    /// Watch the registry, and `log` (with its directory) when given.
    pub(crate) fn new(log: Option<&std::path::Path>) -> Self {
        use std::os::fd::FromRawFd;
        // SAFETY: `inotify_init1` takes flags and returns a new descriptor or -1.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        // SAFETY: a descriptor just returned to this process and owned by nothing else.
        let inotify = (fd >= 0).then(|| unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
        let w = Self { inotify };
        if let Ok(reg) = registry::dir() {
            w.add(
                &reg,
                libc::IN_DELETE | libc::IN_MOVED_FROM | libc::IN_ONLYDIR,
            );
        }
        if let Some(path) = log {
            w.watch(path);
            if let Some(dir) = path.parent() {
                w.add(dir, libc::IN_CREATE | libc::IN_MOVED_TO | libc::IN_ONLYDIR);
            }
        }
        w
    }

    /// Watch the log now at `path`: after a rotation it is a new inode.
    pub(crate) fn watch(&self, path: &std::path::Path) {
        self.add(
            path,
            libc::IN_MODIFY | libc::IN_CLOSE_WRITE | libc::IN_MOVE_SELF | libc::IN_DELETE_SELF,
        );
    }

    fn add(&self, path: &std::path::Path, mask: u32) {
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;
        let (Some(fd), Ok(c)) = (
            self.inotify.as_ref(),
            std::ffi::CString::new(path.as_os_str().as_bytes()),
        ) else {
            return;
        };
        // SAFETY: a live inotify descriptor and a NUL-terminated path; a failure adds no watch,
        // and the floor timer still wakes the waiter.
        unsafe { libc::inotify_add_watch(fd.as_raw_fd(), c.as_ptr(), mask) };
    }

    /// Sleep until something may have changed, at most `floor_ms`. The events are drained, not
    /// read: the caller reads the file and the registry, which are the truth. Created before the
    /// caller's first check, so a change between that check and this sleep is already queued.
    pub(crate) fn wait(&self, floor_ms: i32) {
        use std::os::fd::AsRawFd;
        let mut fds = [libc::pollfd {
            fd: self.inotify.as_ref().map_or(-1, AsRawFd::as_raw_fd),
            events: libc::POLLIN,
            revents: 0,
        }];
        if crate::eintr::poll(&mut fds, floor_ms) > 0 {
            let mut buf = [0u8; 4096];
            while crate::eintr::read(fds[0].fd, buf.as_mut_ptr().cast(), buf.len()) > 0 {}
        }
    }
}

/// The longest a follow sleeps with nothing to wake it.
const FOLLOW_FLOOR_MS: i32 = 200;

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
        // `--log-driver none`: nothing is captured and no file is made, as Docker keeps nothing for
        // that driver.
        let (out, err) = log
            .filter(|_| cap.keep)
            .and_then(|p| start_log_pump(p, cap).or_else(|| open_log_direct(p).map(|fd| (fd, fd))))
            .unwrap_or((null, null));
        if out >= 0 {
            libc::dup2(out, 1);
        }
        if err >= 0 {
            libc::dup2(err, 2);
        }
        // Close the source fds once duplicated onto 1/2 - unless one IS `null` (closed below) or a std
        // stream. `out == err` on every path but `--log-streams`: closed once.
        for (i, fd) in [out, err].into_iter().enumerate() {
            if fd > 2 && fd != null && !(i == 1 && fd == out) {
                libc::close(fd);
            }
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

/// Docker's frames (what a [`Stamper`] with frames writes) taken apart again: stream 1's payload to
/// `out`, stream 2's to `err`. How `kern logs` gives a box whose log recorded its two streams
/// (`--log-streams`, every container of kern's Docker API) back on stdout and stderr, as
/// `docker logs` does, through the one path that already cuts the log at every recorded change.
pub(crate) struct FrameDemux<A: std::io::Write, B: std::io::Write> {
    out: A,
    err: B,
    head: [u8; 8],
    have: usize,
    left: u64,
    to_err: bool,
}

impl<A: std::io::Write, B: std::io::Write> FrameDemux<A, B> {
    pub(crate) fn new(out: A, err: B) -> Self {
        Self {
            out,
            err,
            head: [0; 8],
            have: 0,
            left: 0,
            to_err: false,
        }
    }
}

impl<A: std::io::Write, B: std::io::Write> std::io::Write for FrameDemux<A, B> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut i = 0;
        while i < bytes.len() {
            if self.left == 0 {
                let take = (8 - self.have).min(bytes.len() - i);
                self.head[self.have..self.have + take].copy_from_slice(&bytes[i..i + take]);
                self.have += take;
                i += take;
                if self.have == 8 {
                    self.have = 0;
                    self.to_err = self.head[0] == STREAM_STDERR;
                    let mut len = [0u8; 4];
                    len.copy_from_slice(&self.head[4..]);
                    self.left = u64::from(u32::from_be_bytes(len));
                }
                continue;
            }
            let take = usize::try_from(self.left)
                .unwrap_or(usize::MAX)
                .min(bytes.len() - i);
            if self.to_err {
                self.err.write_all(&bytes[i..i + take])?;
            } else {
                self.out.write_all(&bytes[i..i + take])?;
            }
            self.left -= take as u64;
            i += take;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()?;
        self.err.flush()
    }
}

/// Does the newest log of `name` record its two streams apart? Its `.streams` file EXISTS: the
/// pump of a `--log-streams` box makes it at the start, and it stays empty until the first change
/// of stream, so an attach to a box that has written nothing yet would read it as one stream.
pub(crate) fn log_has_streams(name: &str) -> bool {
    newest_log(name)
        .ok()
        .flatten()
        .is_some_and(|p| streams_path(&p).exists())
}

/// Stream new appends of an already-open log to stdout, FOLLOWING THE NAME ACROSS ROTATIONS, woken by
/// a [`BoxWaiter`] (a write, a rotation, the box leaving the registry, a 200 ms floor) until the box
/// `(name, pid)` leaves the registry. Panic-free; a stdout write error (a
/// closed pipe) ends the follow quietly. Shared by `kern attach` and `kern logs -f`.
///
/// 🔴 IT USED TO FOLLOW AN INODE, AND A ROTATION ENDED THE STREAM IN SILENCE. `rotate` renames the
/// active log and opens a fresh one; a follower holding the old descriptor kept polling a file
/// nothing writes to any more, printed nothing, and reported nothing. MEASURED by an external
/// later pass in round 20 and reproduced here: a box that printed 120 lines after its first rotation
/// showed **zero** of them through `kern logs -f`, while all three generations sat on disk. Rotation
/// is the DEFAULT (16 MiB), so this was every long-running box, and `kern attach` had it too.
///
/// The fix is what `tail -F` does and what `tail -f` does not: compare the inode behind the NAME with
/// the one being read, and when they differ, drain what is left of the old file and reopen. The drain
/// comes first because the pump may have written the tail of a line before renaming.
pub(crate) fn follow_log<W: std::io::Write>(
    mut f: std::fs::File,
    path: &std::path::Path,
    name: &str,
    pid: i32,
    mut stamper: Option<Stamper>,
    data: &mut W,
) -> Result<(), Error> {
    use std::io::Read;
    let mut buf = [0u8; 8192];
    let waiter = BoxWaiter::new(Some(path));
    if let Some(s) = stamper.as_mut() {
        s.follow_live();
        if let Some(i) = fd_inode(&f) {
            s.bind_inode(i);
        }
    }
    // Drain everything currently readable on `f`; `false` means the caller should stop (closed pipe).
    let mut drain = |f: &mut std::fs::File, st: &mut Option<Stamper>, lock: &mut W| -> bool {
        loop {
            match f.read(&mut buf) {
                Ok(0) => return true,
                Ok(k) => {
                    let wrote = match st.as_mut() {
                        Some(s) => s.push(lock, &buf[..k]),
                        None => lock.write_all(&buf[..k]),
                    };
                    if wrote.is_err() {
                        return false;
                    }
                    let _ = lock.flush();
                }
                Err(_) => return true,
            }
        }
    };
    loop {
        if !drain(&mut f, &mut stamper, data) {
            return Ok(());
        }
        // The name now points at a different file: the pump rotated under us.
        if let (Some(open), Some(named)) = (fd_inode(&f), inode_of(path)) {
            if open != named {
                if let Ok(mut next) = std::fs::File::open(path) {
                    // Whatever the old file still holds belongs to the reader before the new one
                    // starts; its own index is already gone, so a Stamper prints `-` for it.
                    if !drain(&mut f, &mut stamper, data) {
                        return Ok(());
                    }
                    if let Some(s) = stamper.as_mut() {
                        // 🔴 THE HELD FRAGMENT IS NOT FLUSHED HERE, and flushing it was a defect this
                        // test caught in its first run. A byte cap splits whatever line it lands in,
                        // so the old generation can end mid-line and the new one opens with the rest.
                        // Releasing the fragment unstamped and then stamping its continuation put the
                        // time column INSIDE the line: `L_2026-09-16T20:21:12.838Z 77 aaa`, where the
                        // unstamped output reads `L_77 aaa` correctly. `rebind` deliberately leaves
                        // `pending` alone, so the two halves join and print as one line with one
                        // column - the new generation's first mark, which is the nearest recorded
                        // time to a line that spans both.
                        if let Some(i) = fd_inode(&next) {
                            s.rebind(i);
                        }
                    }
                    std::mem::swap(&mut f, &mut next);
                    waiter.watch(path);
                    continue; // read the new generation at once rather than after a poll
                }
            }
        }
        // Exact (name,pid) pair: a duplicate same-name entry must not make a live box read as exited.
        if !registry::pair_alive(name, pid) {
            // ONE LAST READ: the log is complete once the box has left the registry
            // (`finish_log_pump`), and bytes written after the read at the top of this turn would
            // otherwise be lost.
            if !drain(&mut f, &mut stamper, data) {
                return Ok(());
            }
            // The box is gone, so a line still waiting for a newline will never get one: print it,
            // through the same writer (a frame demultiplexer included).
            if let Some(s) = stamper.as_mut() {
                let _ = s.flush(data);
                let _ = data.flush();
            }
            return Ok(());
        }
        waiter.wait(FOLLOW_FLOOR_MS);
    }
}

/// The inode behind an OPEN descriptor, which a rename cannot change - that is the whole point.
fn fd_inode(f: &std::fs::File) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    f.metadata().ok().map(|m| m.ino())
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

/// What a follow shows before it streams new lines.
#[derive(Clone, Copy)]
pub(crate) enum Replay {
    /// Every run of the service, oldest first (`compose logs`), or its last `n` lines.
    AllRuns(Option<usize>),
    /// The newest run alone, from its start: what THIS `up` started, as Docker's attach shows it.
    ThisRun,
}

impl Followed {
    /// Open a service's log for following, or `None` when it has produced none (never started, or
    /// started so recently the pump has not created the file yet).
    ///
    /// `replay` says what is shown BEFORE the follow begins (see [`Replay`]).
    pub(crate) fn open(
        label: String,
        box_name: String,
        pid: i32,
        replay: Replay,
    ) -> Result<Option<Self>, Error> {
        use std::io::Read;
        // EVERY RUN OF THE SERVICE, OLDEST FIRST, as a container's log spans its restarts under
        // Docker. MEASURED: after two `compose restart`s Docker's `logs` held three runs' lines and
        // kern's one, so the output of the run that crashed was gone the moment it was restarted.
        // The runs are the ones since `up` created the service: `down` and a recreation remove a
        // service's old logs (see `remove_logs_of`), as Docker removes the container with its log.
        let runs = logs_oldest_first(&box_name)?;
        let Some(path) = runs.last().cloned() else {
            return Ok(None);
        };
        let mut all = Vec::new();
        // MEASURED 2026-11-20: five `kern up --exit-code-from t` in a row printed the service's
        // `hi` 1, 2, 3, 4, 5 times: each attach replayed every earlier run kept since the stack was
        // created. `compose logs` wants them all; `up` wants the run it started.
        let (older_runs, tail) = match replay {
            Replay::AllRuns(tail) => (runs.len() - 1, tail),
            Replay::ThisRun => (0, None),
        };
        for older in runs.iter().take(older_runs) {
            if let Ok(mut f) = std::fs::File::open(older) {
                let _ = f.read_to_end(&mut all);
            }
        }
        let mut file =
            std::fs::File::open(&path).map_err(|e| Error::Sandbox(format!("opening log: {e}")))?;
        // Reading the newest run to its end also leaves the cursor at EOF, so the follow streams
        // only NEW appends.
        file.read_to_end(&mut all)
            .map_err(|e| Error::Sandbox(format!("reading log: {e}")))?;
        let pending = match tail {
            Some(n) => last_lines(&all, n).to_vec(),
            None => all,
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

/// Write one labelled line: `label<pad>  | text`, the shape `docker compose logs` uses (MEASURED on
/// Docker Compose 5.3.1: `api-1   | a1` beside `ev-web  | hello`). An empty label writes the line
/// bare, which is `--no-log-prefix`.
fn push_prefixed(out: &mut Vec<u8>, label: &str, width: usize, line: &[u8]) {
    if !label.is_empty() {
        out.extend_from_slice(label.as_bytes());
        for _ in label.chars().count()..width {
            out.push(b' ');
        }
        out.extend_from_slice(b"  | ");
    }
    out.extend_from_slice(line);
    out.push(b'\n');
}

/// A writer that gives every line Docker's `label  | ` prefix as it passes (`label` already padded
/// to the column), and nothing with an empty label (`--no-log-prefix`). [`Self::finish`] ends a
/// last line that had no newline, as [`push_prefixed`] does.
pub(crate) struct PrefixWriter<'a, W: std::io::Write> {
    inner: W,
    label: &'a str,
    at_start: bool,
}

impl<'a, W: std::io::Write> PrefixWriter<'a, W> {
    pub(crate) fn new(inner: W, label: &'a str) -> Self {
        PrefixWriter {
            inner,
            label,
            at_start: true,
        }
    }

    pub(crate) fn finish(mut self) -> std::io::Result<()> {
        if !self.at_start {
            self.inner.write_all(b"\n")?;
        }
        self.inner.flush()
    }
}

impl<W: std::io::Write> std::io::Write for PrefixWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut rest = buf;
        while !rest.is_empty() {
            if self.at_start && !self.label.is_empty() {
                self.inner.write_all(self.label.as_bytes())?;
                self.inner.write_all(b"  | ")?;
            }
            self.at_start = false;
            match rest.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    let (line, tail) = rest.split_at(i + 1);
                    self.inner.write_all(line)?;
                    self.at_start = true;
                    rest = tail;
                }
                None => {
                    self.inner.write_all(rest)?;
                    rest = &[];
                }
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Follow SEVERAL services at once, interleaved and prefixed, until every one has exited or `stop`
/// is set.
///
/// WHY POLLING AND NOT A READER PER SERVICE. A log file never blocks: a read at EOF returns 0
/// immediately, so one pass over N files costs N cheap reads and the loop sleeps 200 ms between
/// passes, the floor of the single-box follow. A thread per service would buy
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
    // Aligned on the longest, with no cap, as Docker aligns them.
    let width = who
        .iter()
        .map(|w| w.label.chars().count())
        .max()
        .unwrap_or(0);
    let mut data = crate::ui::data_out();
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
            let lock = &mut data;
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
        unsafe { libc::usleep(200_000) }; // 200 ms - the floor `follow_log` wakes at with no event
    }
}

/// The last `n` lines of `bytes` (a trailing partial line counts as one).
fn last_lines(bytes: &[u8], n: usize) -> &[u8] {
    if n == 0 {
        return &bytes[bytes.len()..];
    }
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let mut seen = 0usize;
    for (i, b) in body.iter().enumerate().rev() {
        if *b == b'\n' {
            seen += 1;
            if seen == n {
                return &bytes[i + 1..];
            }
        }
    }
    bytes
}

/// The last `n` lines of the newest run log of box `name`, made safe for a terminal (control
/// characters dropped); empty when it has none. For the summary `compose up` prints for a service
/// that died during the bring-up.
pub(crate) fn tail_lines_of(name: &str, n: usize) -> Vec<String> {
    let Some(newest) = logs_oldest_first(name)
        .ok()
        .and_then(|v| v.into_iter().last())
    else {
        return Vec::new();
    };
    // The end of the file is enough for ten lines; reading a whole multi-megabyte log is not needed.
    let Ok(bytes) = std::fs::read(&newest) else {
        return Vec::new();
    };
    let tail = last_lines(&bytes, n);
    String::from_utf8_lossy(tail)
        .lines()
        .map(crate::ui::scrub)
        .collect()
}

/// Is `file` one of `name`'s run logs, `<name>-<digits>.log`? Exactly that shape, so box `foo` never
/// matches `foo-bar`'s logs (box names may contain `-`).
fn is_run_log_of(file: &str, name: &str) -> bool {
    file.strip_prefix(name)
        .and_then(|r| r.strip_prefix('-'))
        .and_then(|rest| rest.strip_suffix(".log"))
        .is_some_and(|mid| !mid.is_empty() && mid.bytes().all(|b| b.is_ascii_digit()))
}

/// Every run log of `name`, oldest first (by modification time).
pub(crate) fn logs_oldest_first(name: &str) -> Result<Vec<PathBuf>, Error> {
    registry::logs_dir().map_err(|e| Error::Sandbox(format!("logs dir: {e}")))?;
    let mut runs: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for dir in registry::log_dirs() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            if is_run_log_of(&e.file_name().to_string_lossy(), name) {
                if let Ok(t) = e.metadata().and_then(|m| m.modified()) {
                    runs.push((t, e.path()));
                }
            }
        }
    }
    runs.sort();
    Ok(runs.into_iter().map(|(_, p)| p).collect())
}

/// What the runs BEFORE the newest wrote, oldest first, bounded to the last `want` lines when given,
/// and how many lines the newest run holds: what `compose logs` prints ahead of the newest run so a
/// service's history spans its restarts, as a container's does under Docker. Empty with one run.
pub(crate) fn earlier_runs(name: &str, tail: Option<usize>) -> Vec<u8> {
    use std::io::Read;
    let runs = logs_oldest_first(name).unwrap_or_default();
    let Some((newest, older)) = runs.split_last() else {
        return Vec::new();
    };
    let mut text = Vec::new();
    for p in older {
        if let Ok(mut f) = std::fs::File::open(p) {
            let _ = f.read_to_end(&mut text);
        }
    }
    let Some(n) = tail else {
        return text;
    };
    let newest_lines = std::fs::read(newest)
        .map(|b| b.iter().filter(|c| **c == b'\n').count())
        .unwrap_or(0);
    if n <= newest_lines {
        return Vec::new();
    }
    last_lines(&text, n - newest_lines).to_vec()
}

/// Remove every run log of `name`, as Docker removes a container's log with the container: called
/// by `compose down`, a recreation and `kern rm` of a kept box, so the next life starts with an
/// empty history. One pass over the logs dir: a file belongs to a run of `name` when its key
/// ([`registry::split_log_file`]) is `<name>-<pid>`, even when the run's active `.log` is gone and
/// only a rotated generation or an index is left. Best effort: a file that is gone already is the
/// wanted state.
/// How many earlier runs of one container keep their logs, beside the current one: a `--restart
/// always` box that starts again every second would otherwise leave a file per run for good.
pub(crate) const KEPT_RUN_LOGS: usize = 16;

/// The runs of `name` that have a log here (`<name>-<pid>` keys), oldest first by their main
/// file's modification time.
pub(crate) fn runs_with_logs(name: &str) -> Vec<String> {
    let prefix = format!("{name}-");
    let mut runs: Vec<(std::time::SystemTime, String)> = Vec::new();
    for e in registry::log_dirs()
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flat_map(|rd| rd.flatten())
    {
        let fname = e.file_name();
        let Some((key, suffix)) = fname.to_str().and_then(registry::split_log_file) else {
            continue;
        };
        let ours = suffix.is_empty()
            && key
                .strip_prefix(&prefix)
                .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()));
        if ours {
            let t = e
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            runs.push((t, key.to_string()));
        }
    }
    runs.sort();
    runs.into_iter().map(|(_, k)| k).collect()
}

/// Keep the logs of `current` and of the last [`KEPT_RUN_LOGS`] runs of `name` before it.
pub(crate) fn prune_run_logs(name: &str, current: &str) {
    let earlier: Vec<String> = runs_with_logs(name)
        .into_iter()
        .filter(|k| k != current)
        .collect();
    let excess = earlier.len().saturating_sub(KEPT_RUN_LOGS);
    for key in earlier.iter().take(excess) {
        remove_run_logs(key);
    }
}

/// Is `name` ONE container across its runs, as Docker counts it: a kept box (`--keep`, every
/// container made through kern's socket) or one systemd runs again (`--restart always`)? Its runs
/// then share one log, as `docker logs` reads one container's.
pub(crate) fn runs_are_one_container(name: &str) -> bool {
    crate::keepbox::dir_of(name).is_some_and(|d| crate::keepbox::read(&d).is_some())
        || crate::commands::has_managed_unit(name)
}

pub(crate) fn remove_logs_of(name: &str) {
    let prefix = format!("{name}-");
    for e in registry::log_dirs()
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flat_map(|rd| rd.flatten())
    {
        let fname = e.file_name();
        let ours = fname
            .to_str()
            .and_then(registry::split_log_file)
            .and_then(|(key, _)| key.strip_prefix(&prefix))
            .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()));
        if ours {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Remove one run's log: every file [`registry::run_log_files`] names for `key` (`<name>-<pid>`).
pub(crate) fn remove_run_logs(key: &str) {
    for dir in registry::log_dirs() {
        for (path, _) in registry::run_log_files(&dir, key) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// The newest `<name>-<pid>.log` under the logs dir, or `None` if the box has produced no log.
pub(crate) fn newest_log(name: &str) -> Result<Option<PathBuf>, Error> {
    registry::logs_dir().map_err(|e| Error::Sandbox(format!("logs dir: {e}")))?;
    let prefix = format!("{name}-");
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for dir in registry::log_dirs() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
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
mod journald_tests {
    use super::*;

    /// One entry per LINE, a line split across two reads joined first, the stream's priority on it,
    /// the box's name as identifier, and what is left without a newline sent at the end.
    #[test]
    fn the_journal_gets_one_entry_per_line_with_the_box_name_and_the_streams_priority() {
        let (tx, rx) = std::os::unix::net::UnixDatagram::pair().expect("pair");
        let mut j = Journal {
            sock: tx,
            name: "web".into(),
            pending: [Vec::new(), Vec::new()],
        };
        j.feed(STREAM_STDOUT, b"uno\ndu");
        j.feed(STREAM_STDOUT, b"e\n");
        j.feed(STREAM_STDERR, b"errore\n");
        j.feed(STREAM_STDOUT, b"senza-a-capo");
        j.flush();
        let mut got = Vec::new();
        rx.set_nonblocking(true).expect("nonblocking");
        let mut buf = [0u8; 4096];
        while let Ok(n) = rx.recv(&mut buf) {
            got.push(buf[..n].to_vec());
        }
        assert_eq!(got.len(), 4, "one entry per line");
        let msg = |e: &[u8]| -> Vec<u8> {
            let at = e
                .windows(8)
                .position(|w| w == b"MESSAGE\n")
                .expect("MESSAGE")
                + 8;
            let len = u64::from_le_bytes(e[at..at + 8].try_into().expect("len")) as usize;
            e[at + 8..at + 8 + len].to_vec()
        };
        assert_eq!(msg(&got[0]), b"uno");
        assert_eq!(msg(&got[1]), b"due", "a line split across reads is joined");
        assert_eq!(msg(&got[2]), b"errore");
        assert_eq!(msg(&got[3]), b"senza-a-capo", "the tail is sent at the end");
        let text = |e: &[u8]| String::from_utf8_lossy(e).into_owned();
        assert!(text(&got[0]).contains("PRIORITY=6\n") && text(&got[2]).contains("PRIORITY=3\n"));
        assert!(text(&got[0]).contains("SYSLOG_IDENTIFIER=web\nCONTAINER_NAME=web\n"));
    }
}

#[cfg(test)]
mod run_log_retention_tests {
    /// The earlier runs of one container are listed oldest first, and only the last
    /// `KEPT_RUN_LOGS` of them stay beside the current one; another box's logs are not touched.
    #[test]
    fn earlier_runs_are_kept_up_to_the_bound_and_listed_oldest_first() {
        let _g = crate::env_guard();
        let base = std::env::temp_dir().join(format!("kern-runlogs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("kern/logs")).expect("logs dir");
        let prev = crate::global_env("XDG_RUNTIME_DIR");
        struct Restore(Option<std::ffi::OsString>, std::path::PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                match &self.0 {
                    Some(v) => crate::set_global_env("XDG_RUNTIME_DIR", v),
                    None => crate::unset_global_env("XDG_RUNTIME_DIR"),
                }
                let _ = std::fs::remove_dir_all(&self.1);
            }
        }
        let _restore = Restore(prev, base.clone());
        crate::set_global_env("XDG_RUNTIME_DIR", &base);
        let logs = base.join("kern/logs");
        let runs = super::KEPT_RUN_LOGS + 5;
        for i in 0..runs {
            let f = logs.join(format!("web-{}.log", 100 + i));
            std::fs::write(&f, format!("run {i}\n")).expect("write");
            std::fs::write(logs.join(format!("web-{}.log.idx", 100 + i)), b"").expect("idx");
            let t = std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(1_000 + i as u64);
            std::fs::File::options()
                .write(true)
                .open(&f)
                .and_then(|h| h.set_modified(t))
                .expect("mtime");
        }
        std::fs::write(logs.join("web-x-7.log"), b"another box").expect("write");
        let listed = super::runs_with_logs("web");
        assert_eq!(listed.len(), runs, "{listed:?}");
        assert_eq!(
            listed.first().map(String::as_str),
            Some("web-100"),
            "oldest first"
        );
        let current = format!("web-{}", 100 + runs - 1);
        super::prune_run_logs("web", &current);
        let kept = super::runs_with_logs("web");
        assert_eq!(kept.len(), super::KEPT_RUN_LOGS + 1, "{kept:?}");
        assert!(kept.contains(&current));
        assert!(!kept.contains(&"web-100".to_string()), "the oldest went");
        assert!(!logs.join("web-100.log.idx").exists(), "with its index");
        assert!(logs.join("web-x-7.log").exists(), "another box's log stays");
    }
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
                    keep: true,
                    streams: false,
                    journald: false,
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
            // ONE INDEX, AND IT BELONGS TO THE ACTIVE FILE. The time index is a sidecar of the log
            // the pump is writing right now: rotation truncates it rather than renaming it, so no
            // generation ever grows an index of its own and `logs -t` on a rotated file honestly
            // reports no times instead of the previous file's. Asserted here and then removed from
            // the generation list, because this closure's subject is how many GENERATIONS survive
            // and a filter alone would let the sidecar appear or vanish unnoticed.
            assert_eq!(
                found.iter().filter(|f| f.ends_with(".idx")).count(),
                1,
                "exactly one index, for the active file: {found:?}"
            );
            found.retain(|f| !f.ends_with(".idx"));
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
                files: 2,
                keep: true,
                streams: false,
                journald: false,
            }
        );
    }
}

#[cfg(test)]
mod reason_predicate_tests {
    use super::log_carries_a_reason;

    /// THE PREDICATE THAT COST THREE SECONDS PER TYPO.
    ///
    /// It waited for one of two literal sentences, and the commonest failure in the product - a
    /// command that does not exist - writes neither. MEASURED before the fix: `kern box -d --image
    /// alpine -- /nonexistent-binary` took 3.035 s and then printed a message that had been in the
    /// log since the first poll; the same command in the foreground took 5 ms. After: 8 ms.
    ///
    /// The cases below are the LOG LINES the supervisor actually writes, copied from a real run, not
    /// invented shapes.
    #[test]
    fn a_kern_failure_line_is_a_reason_and_a_benign_one_is_not() {
        // Every one of these must END the wait.
        for reason in [
            "kern: cannot start '/nonexistent-binary' in box: No such file or directory (os error 2)",
            "kern: sandbox setup failed: -v /tmp/f:/x: the source is a FIFO",
            "kern: box failed to start: unprivileged user namespaces are unavailable",
            "kern: pod: could not map the pod user namespace",
        ] {
            assert!(
                log_carries_a_reason(reason),
                "this is the supervisor's reason and the wait must end here: {reason}"
            );
        }
        // And every one of these must NOT: they are the three benign kinds kern prints on a box that
        // is starting perfectly well. Treating one as a reason would end the wait before the real
        // line lands and report a warning as the cause, which is the defect the loop exists to avoid.
        for benign in [
            "kern: note: this file separates services with `networks:`",
            "kern: warning: resource caps could not be enforced here",
            "kern: security-profile=untrusted seccomp=allowlist",
            "some workload output that mentions kern: in passing",
            "",
        ] {
            assert!(
                !log_carries_a_reason(benign),
                "this must not end the wait: {benign}"
            );
        }
        // A tail is many lines: a benign line FIRST must not mask the reason that follows it.
        assert!(log_carries_a_reason(
            "kern: warning: resource caps could not be enforced here\nkern: cannot start 'x' in box: No such file"
        ));
    }
}

/// Prefix each COMPLETE line with the recorded time of the mark it falls after, holding an
/// unterminated trailing fragment until its newline arrives.
///
/// HOLDING IS THE WHOLE POINT, and it is what stamping a write cannot do: `--follow` reads the log in
/// 8 KiB chunks and a long line lands across two of them, so "stamp whatever this read returned"
/// would drop a timestamp into the middle of a line. The fragment waits for its `\n`; [`flush`] at
/// the end of the stream releases whatever never gets one, unstamped, so nothing is swallowed.
///
/// [`flush`]: Stamper::flush
pub(crate) struct Stamper {
    log: std::path::PathBuf,
    marks: Vec<(u64, u64)>,
    /// File offset of the first byte of `pending` - the offset whose mark stamps the next line.
    at: u64,
    pending: Vec<u8>,
    /// Set by [`Stamper::follow_live`] when this Stamper is feeding a `--follow`.
    live: bool,
    /// The last time column rendered, with the mark it belongs to. See [`Stamper::emit`].
    column: (Option<u64>, Vec<u8>),
    /// The inode the READER has open, when following. See [`Stamper::bind_inode`].
    ino: u64,
    /// Set when the index stopped describing the bytes being read. See [`Stamper::bind_inode`].
    orphan: bool,
    /// The newest time already printed. See [`Stamper::emit`] for why it is a floor and not a record.
    floor: Option<u64>,
    /// `--since` / `--until` as unix NANOSECONDS, inclusive of `since` and of `until`.
    ///
    /// A LINE WITH NO RECORDED TIME IS KEPT, and that choice is the whole design of this filter. The
    /// index buckets from 100 ms and a log written before the index existed has no marks at all, so
    /// `nanos` is legitimately `None` for real output. Dropping those lines would make `--since`
    /// silently lose what a reader is looking for; keeping them makes the window a filter on what is
    /// KNOWN to be outside it, which is the only claim the index supports.
    window: (Option<u64>, Option<u64>),
    /// Print the time column. `false` when the window is the only reason this Stamper exists, which
    /// is `logs --since` without `-t`: Docker's `--since` does not imply `--timestamps` either.
    column_on: bool,
    /// `logs --frames`: write Docker's multiplexed frames instead of plain bytes, each stretch under
    /// the stream `<log>.streams` recorded for it (stdout where nothing was recorded).
    frames: bool,
    /// The stream record, `(offset, stream)`, read beside the time index. See [`read_streams`].
    runs: Vec<(u64, u8)>,
}

impl Stamper {
    /// Read the index for `log`; `start` is the file offset the first pushed byte has.
    pub(crate) fn new(log: &std::path::Path, start: u64) -> Self {
        Self {
            log: log.to_path_buf(),
            marks: read_marks(log),
            at: start,
            pending: Vec::new(),
            live: false,
            column: (None, Vec::new()),
            ino: 0,
            orphan: false,
            floor: None,
            window: (None, None),
            column_on: true,
            frames: false,
            runs: Vec::new(),
        }
    }

    /// Write Docker's multiplexed frames (`logs --frames`, the Docker API server's reader): every line
    /// is cut at the stream boundaries `<log>.streams` recorded and each piece framed as stdout (1) or
    /// stderr (2), the time column, when asked for, inside the line's first frame.
    pub(crate) fn with_frames(mut self, on: bool) -> Self {
        self.frames = on;
        if on {
            self.runs = read_streams(&self.log);
        }
        self
    }

    /// Restrict output to lines whose recorded time falls in `[since, until]`, and say whether the
    /// time column is printed at all.
    ///
    /// Built as a separate step rather than as four more arguments to [`Stamper::new`]: every
    /// existing caller wants the column and no window, and a constructor whose common call site ends
    /// in `, None, None, true` is a constructor nobody reads.
    pub(crate) fn with_window(
        mut self,
        since: Option<u64>,
        until: Option<u64>,
        column_on: bool,
    ) -> Self {
        self.window = (since, until);
        self.column_on = column_on;
        self
    }

    /// THE INDEX GROWS WHILE WE FOLLOW IT, so re-read it once per arriving chunk.
    ///
    /// MEASURED, and it is why this flag exists at all: without it a `logs -t -f` started on a box
    /// that had not written yet printed `-` for EVERY line, forever. The index did not exist when the
    /// Stamper was built, and a predicate that only re-read "past the newest mark we hold" never fires
    /// on an empty set. The re-read belongs to the follow and only to it: a one-shot `logs` prints a
    /// fixed window of a file it already measured, and any mark appended after that measurement
    /// describes bytes past the end of what it will print.
    ///
    /// Per CHUNK and not per line, so the cost is bounded by the follow's wakes rather than by the
    /// number of lines: the index of an hour-long box is half a megabyte, and re-reading it per line would
    /// turn printing a busy tail into an O(lines x index) crawl. The chunk was read from the log
    /// BEFORE this call, and the pump writes a mark only after the bytes it marks, so every mark this
    /// chunk needs is already on disk when we read it here.
    pub(crate) fn follow_live(&mut self) {
        self.live = true;
    }

    /// Tie this Stamper to the inode the reader actually has open, so a rotation cannot make it lie.
    ///
    /// 🔴 THE INDEX BELONGS TO A NAME, THE READER HOLDS A DESCRIPTOR, AND ROTATION SEPARATES THEM.
    /// `rotate` renames the active log and `reset_index` truncates the index in place, so the index
    /// now describes the NEW file while a follower keeps reading bytes from the old inode through its
    /// fd. Re-reading the index per chunk then applies small, RECENT offsets to a large, old cursor,
    /// and `mark_for` answers with the newest mark it has: stamps that are too recent on bytes that
    /// are older.
    ///
    /// ⭐ THE SYMPTOM IS FORWARD, WHICH IS WHY EVERY ASSERTION PASSED. The concurrency battery hunts
    /// time going BACKWARDS, torn records and missing columns; none of them fires on a stamp that is
    /// merely too new. A later pass predicted this from the code in round 20 and then measured
    /// it. A test that cannot see a defect is not evidence that the defect is absent.
    ///
    /// The check sits AFTER the index re-read on purpose: a rotation landing between the two leaves
    /// the marks this chunk was attributed with still being the pre-rotation ones, which are correct
    /// for these bytes. Landing before it is caught here. There is no third ordering.
    pub(crate) fn bind_inode(&mut self, ino: u64) {
        self.ino = ino;
        self.orphan = false;
    }

    /// Start over on a freshly opened generation: offset zero, its own index, stamping allowed again.
    pub(crate) fn rebind(&mut self, ino: u64) {
        self.at = 0;
        self.marks.clear();
        self.runs.clear();
        self.column = (None, Vec::new());
        self.bind_inode(ino);
    }

    /// Stamp and emit every COMPLETE line in `bytes`, holding any trailing fragment.
    ///
    /// LINEAR, AND IT HAD TO BE MEASURED TO FIND OUT IT WAS NOT. The first version appended `bytes`
    /// to `pending` and `drain`ed one line at a time, which moves the whole remaining buffer per
    /// line: on a real 23 MB log of 400 000 lines that was **96.8 seconds**, against 15.5 ms for the
    /// same log unstamped. A log is one big push, so the quadratic term is the entire cost. This
    /// version walks `bytes` in place by index and copies only the trailing fragment.
    pub(crate) fn push(
        &mut self,
        out: &mut impl std::io::Write,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        if self.live {
            self.marks = read_marks(&self.log);
            if self.frames {
                self.runs = read_streams(&self.log);
            }
            // The name may now be a DIFFERENT file than the one being read: see `bind_inode`.
            if self.ino != 0 && inode_of(&self.log).is_some_and(|i| i != self.ino) {
                self.orphan = true;
            }
        }
        // A fragment held from the previous chunk owns the start of this one, up to its newline.
        let rest = if self.pending.is_empty() {
            bytes
        } else if let Some(i) = bytes.iter().position(|&b| b == b'\n') {
            self.pending.extend_from_slice(&bytes[..=i]);
            let line = std::mem::take(&mut self.pending);
            self.emit(out, &line)?;
            &bytes[i + 1..]
        } else {
            self.pending.extend_from_slice(bytes);
            return Ok(());
        };
        let mut start = 0;
        while let Some(i) = rest[start..].iter().position(|&b| b == b'\n') {
            let end = start + i;
            self.emit(out, &rest[start..=end])?;
            start = end + 1;
        }
        self.pending.extend_from_slice(&rest[start..]);
        Ok(())
    }

    /// One line, already complete, with its time column in front of it.
    ///
    /// The column is CACHED per mark, not formatted per line. Every line inside one interval shares
    /// a stamp by construction, so formatting it again is work whose answer is known: the same 23 MB
    /// log has 400 000 lines and ten marks, which is ten civil-from-days conversions instead of
    /// 400 000, and no allocation per line.
    fn emit(&mut self, out: &mut impl std::io::Write, line: &[u8]) -> std::io::Result<()> {
        // 🔴 TIME NEVER GOES BACKWARDS IN THIS COLUMN, AND THE READER IS WHERE THAT IS DECIDED.
        // A stamp comes from whichever index is in front of the reader, and at a rotation seam the
        // last line of one generation and the first of the next are answered by two DIFFERENT
        // indexes: measured, 103 ms backwards across the seam, which is exactly one bucket. Chasing
        // every ordering between a pump that renames, truncates and compacts and a reader that polls
        // is a race with no end; holding a floor is one comparison and makes the guarantee checkable.
        //
        // The cost is stated rather than hidden: across a seam the column can repeat the previous
        // instant instead of showing a slightly older one. A repeated bucket is already the normal
        // case for lines inside one interval, so this loses resolution in the one place it was never
        // trustworthy, and it can never invent a time that is too NEW - the floor only holds a stamp
        // back to something already printed.
        //
        // An ORPHANED reader says `-` instead: the index in front of it describes another file
        // entirely, and a plausible instant nobody recorded is what this whole feature refuses.
        let nanos = if self.orphan {
            None
        } else {
            match (mark_for(&self.marks, self.at), self.floor) {
                (Some(n), Some(f)) if n < f => Some(f),
                (n, _) => n,
            }
        };
        if let Some(n) = nanos {
            self.floor = Some(n);
        }
        let line_at = self.at;
        // THE CURSOR ADVANCES WHETHER OR NOT THE LINE IS PRINTED. `at` is a file offset, and the
        // stamp of every later line is read from it: a filtered line that did not move it would
        // shift every remaining stamp backwards by its length.
        self.at += line.len() as u64;
        // OUTSIDE THE WINDOW ONLY WHEN THE TIME IS KNOWN. `None` means the index has nothing to say
        // about this line, and a filter that discards what it cannot place would drop real output on
        // any log written before its index existed.
        if let Some(n) = nanos {
            if self.window.0.is_some_and(|s| n < s) || self.window.1.is_some_and(|u| n > u) {
                return Ok(());
            }
        }
        if self.column_on {
            // The empty check is NOT redundant: `None` is a legal mark (the head of a log has none),
            // so a cache that started at `None` would match the very first line and print no column
            // at all.
            if self.column.1.is_empty() || self.column.0 != nanos {
                let stamp = nanos.map(fmt_mark).unwrap_or_else(|| "-".to_string());
                self.column = (nanos, format!("{stamp:<24} ").into_bytes());
            }
        }
        let column: &[u8] = if self.column_on { &self.column.1 } else { &[] };
        if self.frames {
            return write_frames(out, &self.runs, line_at, column, line);
        }
        out.write_all(column)?;
        out.write_all(line)?;
        Ok(())
    }

    /// Release an unterminated last line, unstamped: the stream is over and its newline is not coming.
    pub(crate) fn flush(&mut self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        if !self.pending.is_empty() {
            // Unstamped and therefore never filtered, for the same reason a `None` mark is kept
            // above: this line has no recorded time, so nothing is known to place it outside the
            // window.
            if self.frames {
                write_frames(out, &self.runs, self.at, &[], &self.pending)?;
            } else {
                out.write_all(&self.pending)?;
            }
            self.at += self.pending.len() as u64;
            self.pending.clear();
        }
        Ok(())
    }
}

/// The stream record of `log` as `(offset, stream)` in file order, or empty when there is none (a log
/// written without `--log-streams`). A trailing partial record is ignored, as [`read_marks`] ignores
/// one.
pub(crate) fn read_streams(log: &std::path::Path) -> Vec<(u64, u8)> {
    let Ok(data) = std::fs::read(streams_path(log)) else {
        return Vec::new();
    };
    let mut at = 0u64;
    let mut runs = Vec::with_capacity(data.len() / STREAM_REC_LEN);
    for c in data.chunks_exact(STREAM_REC_LEN) {
        let mut b = [0u8; STREAM_REC_LEN];
        b.copy_from_slice(c);
        let rec = u32::from_le_bytes(b);
        at += u64::from(rec & 0x7FFF_FFFF);
        let stream = if rec >> 31 == 1 {
            STREAM_STDERR
        } else {
            STREAM_STDOUT
        };
        runs.push((at, stream));
    }
    runs
}

/// The stream of the byte at `offset`, and the offset where the next recorded stretch starts.
/// Before the first record the answer is stdout.
fn stream_at(runs: &[(u64, u8)], offset: u64) -> (u8, Option<u64>) {
    let i = runs.partition_point(|r| r.0 <= offset);
    let stream = match i.checked_sub(1).map(|k| runs[k].1) {
        Some(STREAM_STDERR) => STREAM_STDERR,
        _ => STREAM_STDOUT,
    };
    (stream, runs.get(i).map(|r| r.0))
}

/// Frame `bytes`, which start at file offset `at`, cutting at every recorded stream change; `prefix`
/// (the time column, or nothing) leads the first frame. Docker's header: stream, three zero bytes,
/// the payload length as a big-endian u32.
fn write_frames(
    out: &mut impl std::io::Write,
    runs: &[(u64, u8)],
    at: u64,
    prefix: &[u8],
    bytes: &[u8],
) -> std::io::Result<()> {
    let mut done = 0usize;
    let mut prefix = prefix;
    while done < bytes.len() {
        let off = at + done as u64;
        let (stream, next) = stream_at(runs, off);
        // A frame's length is a u32, so no piece may be longer than that with its prefix.
        let room = (u32::MAX as usize).saturating_sub(prefix.len()).max(1);
        let take = next
            .and_then(|n| usize::try_from(n.saturating_sub(off)).ok())
            .filter(|&n| n > 0)
            .map_or(bytes.len() - done, |n| n.min(bytes.len() - done))
            .min(room);
        let piece = &bytes[done..done + take];
        let len = u32::try_from(prefix.len() + piece.len()).unwrap_or(u32::MAX);
        let mut head = [stream, 0, 0, 0, 0, 0, 0, 0];
        head[4..].copy_from_slice(&len.to_be_bytes());
        out.write_all(&head)?;
        out.write_all(prefix)?;
        out.write_all(piece)?;
        prefix = &[];
        done += take;
    }
    Ok(())
}

/// The inode behind a path right now, or `None` if it cannot be stat'ed.
pub(crate) fn inode_of(p: &std::path::Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).ok().map(|m| m.ino())
}

/// Read `<log>.idx` into `(offset, unix nanos)` pairs, oldest first.
///
/// A TRAILING PARTIAL RECORD IS DROPPED, not padded: the writer stops indexing when a write comes up
/// short, so a file whose length is not a multiple of [`MARK_LEN`] was cut by something else and its
/// last record cannot be trusted. Dropping one mark costs the resolution of one interval; keeping a
/// torn one would put a line at a time that was never recorded.
pub(crate) fn read_marks(log: &std::path::Path) -> Vec<(u64, u64)> {
    let Ok(data) = std::fs::read(idx_path(log)) else {
        return Vec::new();
    };
    data.chunks_exact(MARK_LEN)
        .map(|c| {
            let mut o = [0u8; 8];
            let mut w = [0u8; 8];
            o.copy_from_slice(&c[..8]);
            w.copy_from_slice(&c[8..]);
            (u64::from_le_bytes(o), u64::from_le_bytes(w))
        })
        .collect()
}

/// The recorded time at or before `offset`, or `None` before the first mark.
///
/// `None` is a real answer and the caller prints it as such: a log written by an older kern has no
/// index at all, and even a current one has no mark before its first, so the opening bytes of every
/// log are honestly unattributed rather than given the first mark's time.
pub(crate) fn mark_for(marks: &[(u64, u64)], offset: u64) -> Option<u64> {
    match marks.binary_search_by(|(o, _)| o.cmp(&offset)) {
        Ok(i) => Some(marks[i].1),
        Err(0) => None,
        Err(i) => Some(marks[i - 1].1),
    }
}

/// `2026-09-16T18:42:07.123Z`, which is what a reader compares against their own clock.
///
/// Millisecond precision and no more, because the mark interval starts at 100 ms and only widens:
/// printing nanoseconds would be six digits of invented precision on a number that is already a
/// bucket.
pub(crate) fn fmt_mark(nanos: u64) -> String {
    let secs = (nanos / 1_000_000_000) as i64;
    let ms = (nanos % 1_000_000_000) / 1_000_000;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    // Civil-from-days, Howard Hinnant's algorithm: no chrono dependency for four fields.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

#[cfg(test)]
mod stamper_tests {
    use super::{idx_path, Stamper, MARK_LEN};

    /// Write a synthetic index and return the log path it belongs to.
    fn with_index(tag: &str, marks: &[(u64, u64)]) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kern-stamper-{tag}-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        let log = d.join("l.log");
        let mut blob = Vec::with_capacity(marks.len() * MARK_LEN);
        for (o, w) in marks {
            blob.extend_from_slice(&o.to_le_bytes());
            blob.extend_from_slice(&w.to_le_bytes());
        }
        std::fs::write(idx_path(&log), blob).expect("write index");
        // The LOG has to exist too, not only its index: the orphan check asks what inode the NAME
        // points at, and a name that points at nothing answers neither "same" nor "different".
        std::fs::write(&log, b"").expect("write log");
        log
    }

    /// An index whose times run BACKWARDS still prints a column that does not.
    ///
    /// ISOLATED ON PURPOSE, because the end-to-end battery could not tell this apart from the orphan
    /// check: with either one in place the rotation seam stopped going backwards, so each passed with
    /// the other sabotaged. Two defences that cover each other are worth having and are worth
    /// testing SEPARATELY, or neither is really tested. Here there is no rotation and no second
    /// file - just an index that lies, which is also what a torn or hand-edited one looks like.
    #[test]
    fn a_backwards_index_cannot_make_the_column_go_backwards() {
        let log = with_index(
            "floor",
            &[(0, 5_000_000_000), (10, 3_000_000_000), (20, 9_000_000_000)],
        );
        let mut s = Stamper::new(&log, 0);
        let mut out: Vec<u8> = Vec::new();
        // TEN BYTES PER LINE, to match the mark offsets above. With short lines every line resolves
        // to the mark at offset 0 and the backwards marks are never reached: the test then passes
        // with the floor removed, which is how this fixture was wrong the first time.
        s.push(&mut out, b"aaaaaaaaa\nbbbbbbbbb\nccccccccc\n")
            .expect("write");
        let cols: Vec<&str> = std::str::from_utf8(&out)
            .expect("utf8")
            .lines()
            .map(|l| l.split_whitespace().next().unwrap_or(""))
            .collect();
        assert_eq!(cols.len(), 3, "three lines, three columns: {cols:?}");
        assert!(cols[1] >= cols[0], "the column went backwards: {cols:?}");
        assert!(cols[2] >= cols[1], "the column went backwards: {cols:?}");
        // And the floor HOLDS rather than skips: the middle line repeats the first line's instant,
        // which is the stated cost, instead of showing the older time the index claims.
        assert_eq!(
            cols[0], cols[1],
            "the floor should repeat, not advance: {cols:?}"
        );
        let _ = std::fs::remove_dir_all(log.parent().expect("dir"));
    }

    /// A reader bound to one inode stops stamping when the NAME becomes a different file.
    ///
    /// The other half of the same seam, and the half that keeps the answer HONEST rather than merely
    /// monotonic: the floor would hold a stale time across a rotation, while this says `-`, which is
    /// what the bytes deserve when the index in front of them describes another file.
    #[test]
    fn a_reader_whose_file_was_rotated_away_stops_stamping() {
        let log = with_index("orphan", &[(0, 5_000_000_000)]);
        let mut s = Stamper::new(&log, 0);
        s.follow_live();
        let mut out: Vec<u8> = Vec::new();
        s.push(&mut out, b"prima\n").expect("write");
        // NOT `starts_with("20")`: these marks are synthetic and land in 1970, which is the right
        // thing for a test that cares about the MECHANISM and not about the calendar. The question is
        // whether a column was rendered at all, and `-` is the only answer that means it was not.
        assert!(
            !std::str::from_utf8(&out).expect("utf8").starts_with('-'),
            "bound to nothing yet, it stamps normally: {:?}",
            String::from_utf8_lossy(&out)
        );
        // Bind to an inode the path cannot have: the same divergence a rotation produces.
        s.bind_inode(u64::MAX);
        out.clear();
        s.push(&mut out, b"dopo\n").expect("write");
        assert!(
            std::str::from_utf8(&out).expect("utf8").starts_with('-'),
            "an orphaned reader says `-`: {:?}",
            String::from_utf8_lossy(&out)
        );
        let _ = std::fs::remove_dir_all(log.parent().expect("dir"));
    }
}

#[cfg(test)]
mod compaction_tests {
    use super::{idx_path, mark_for, read_marks, CappedLog, LogCap, MARK_LEN};

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kern-idx-{tag}-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        d
    }

    /// Compacting the index may make a line's time OLDER, never newer.
    ///
    /// THIS IS THE ONE PROPERTY THAT MATTERS, and it is not "the file got smaller". A stamp is a
    /// promise that the line was written at or after the time shown; thinning the marks weakens the
    /// promise (an earlier mark now answers for more bytes) but must never break it, because a stamp
    /// LATER than its line is a lie a reader cannot detect. Checked at every byte offset in the log,
    /// against the answers the full index gave, rather than at a few sampled ones.
    /// OUTPUT LOST TO A FULL STORE IS SAID IN THE LOG, at the gap, before the lines after it.
    ///
    /// Before this a full log store shed bytes and nothing said so: `kern logs` showed the lines
    /// on either side of a hole as if they were consecutive.
    #[test]
    fn bytes_dropped_by_a_full_store_are_said_at_the_gap() {
        let dir = tmpdir("dropped");
        let path = dir.join("d.log");
        let _ = std::fs::remove_file(&path);
        let mut log = CappedLog::open(
            &path,
            LogCap {
                max_bytes: 1 << 20,
                files: 2,
                keep: true,
                streams: false,
                journald: false,
            },
        )
        .expect("the log opens");
        log.write(b"before\n");
        // What the pump does when a write meets ENOSPC or a rotation that frees nothing.
        log.dropped = 4096;
        log.write(b"after\n");
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.first().copied(), Some("before"));
        assert!(
            lines.get(1).is_some_and(
                |l| l.starts_with("kern: warning: 4096 byte(s)") && l.contains("dropped")
            ),
            "the gap must be said between the lines around it: {lines:?}"
        );
        assert_eq!(lines.get(2).copied(), Some("after"));
        assert_eq!(log.dropped, 0, "said once, then counted afresh");
    }

    #[test]
    fn compacting_the_index_never_moves_a_line_forward_in_time() {
        let dir = tmpdir("compact");
        let path = dir.join("l.log");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(idx_path(&path));
        // A cap big enough that 400 marks do not trigger the automatic compaction: this test drives
        // it by hand so the before/after comparison is of one known step.
        let mut log = CappedLog::open(
            &path,
            LogCap {
                max_bytes: 1 << 20,
                files: 2,
                keep: true,
                streams: false,
                journald: false,
            },
        )
        .expect("the log opens");
        log.mark_every = 0; // every write marks, so the test does not sleep for 40 seconds
        for i in 0..400 {
            log.write(format!("riga {i}\n").as_bytes());
        }
        let before = read_marks(&path);
        assert!(
            before.len() > 300,
            "expected a full index, got {}",
            before.len()
        );
        let end = log.written;

        log.compact_index();
        let after = read_marks(&path);
        assert_eq!(
            after.len(),
            before.len().div_ceil(2),
            "half the marks survive"
        );
        // WHICH half is thinned, not just how many. Keeping the OLDEST half would satisfy both the
        // count and the never-later rule above while collapsing the entire tail of the log onto one
        // stale mark - and the tail is the part a reader is looking at. Measured as the last surviving
        // mark still covering the end of the log: with every-other thinning it is the penultimate
        // original mark or better; with oldest-half thinning it sits at the middle of the file.
        // DENSITY IN THE INTERIOR, not only at the end. "The last mark still covers EOF" says nothing
        // about the middle: a compaction that kept the first mark, the last, and nothing between
        // would satisfy it while leaving the body of the log answered by one stale time. The bound is
        // what thinning by half means - every surviving gap is at most twice the spacing it replaced -
        // and it is checked against the MEDIAN rather than the max, so one naturally wide gap in the
        // original (a quiet stretch where the pump wrote nothing) cannot raise the ceiling for all.
        let gaps =
            |m: &[(u64, u64)]| -> Vec<u64> { m.windows(2).map(|w| w[1].0 - w[0].0).collect() };
        let median = |mut v: Vec<u64>| -> u64 {
            v.sort_unstable();
            if v.is_empty() {
                0
            } else {
                v[v.len() / 2]
            }
        };
        let before_median = median(gaps(&before));
        let worst_after = gaps(&after).into_iter().max().unwrap_or(0);
        assert!(
            before_median > 0,
            "the fixture produced no spacing to compare against"
        );
        assert!(
            worst_after <= 2 * before_median,
            "compaction left a hole in the interior: widest gap {worst_after} against a bound of \
             {} (2x the pre-compaction median of {before_median})",
            2 * before_median
        );

        let last_kept = after.last().expect("a compacted index still has marks").0;
        let penultimate = before[before.len() - 2].0;
        assert!(
            last_kept >= penultimate,
            "the tail lost its resolution: last kept mark at {last_kept}, log ends at {end}, \
             the original penultimate mark was at {penultimate}"
        );
        assert_eq!(
            log.mark_every, 0,
            "0 doubled is still 0, which keeps this test's cadence"
        );

        for o in 0..end {
            let (b, a) = (mark_for(&before, o), mark_for(&after, o));
            match (b, a) {
                (Some(b), Some(a)) => assert!(a <= b, "offset {o}: {a} is LATER than {b}"),
                (None, None) => {}
                (Some(_), None) => panic!("offset {o} lost its mark entirely"),
                (None, Some(a)) => panic!("offset {o} gained a mark ({a}) it never had"),
            }
        }
        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The index stays under its cap no matter how long the box runs.
    ///
    /// The log has a cap and the index did not, which on a tmpfs `XDG_RUNTIME_DIR` is RAM that grows
    /// until the box stops. Driven here with `mark_every` at zero, so a thousand writes stand in for
    /// the hours of real output it would otherwise take.
    #[test]
    fn the_index_never_outgrows_its_share_of_the_log() {
        let dir = tmpdir("cap");
        let path = dir.join("l.log");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(idx_path(&path));
        let mut log = CappedLog::open(
            &path,
            LogCap {
                max_bytes: 65_536,
                files: 2,
                keep: true,
                streams: false,
                journald: false,
            },
        )
        .expect("the log opens");
        let cap = log.idx_max();
        log.mark_every = 0;
        let mut worst = 0u64;
        for i in 0..2000 {
            log.write(format!("r{i}\n").as_bytes());
            let sz = std::fs::metadata(idx_path(&path))
                .map(|m| m.len())
                .unwrap_or(0);
            worst = worst.max(sz);
            assert!(
                sz <= cap,
                "the index passed its cap: {sz} > {cap} at write {i}"
            );
        }
        assert!(
            worst > cap / 2,
            "the cap was never approached, so nothing was tested: {worst}"
        );
        let sz = std::fs::metadata(idx_path(&path)).expect("stat").len();
        assert_eq!(
            sz % MARK_LEN as u64,
            0,
            "a compacted index is still whole records"
        );
        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod mark_tests {
    use super::{fmt_mark, mark_for};

    /// The formatter agrees with a date a human can check, at the boundaries that break naive ones.
    ///
    /// Written because the civil-from-days arithmetic is the kind that passes for a year and then
    /// prints 31 February: the cases below are the epoch, a leap day, the day after a leap day, and a
    /// century that is NOT a leap year (1900 is not, 2000 is), which is where the /100 and /400 rules
    /// disagree.
    #[test]
    fn the_timestamp_is_a_date_a_reader_can_check() {
        for (nanos, want) in [
            (0u64, "1970-01-01T00:00:00.000Z"),
            (1_000_000_000, "1970-01-01T00:00:01.000Z"),
            (951_782_400_000_000_000, "2000-02-29T00:00:00.000Z"), // a leap day
            (951_868_800_000_000_000, "2000-03-01T00:00:00.000Z"), // the day after it
            (1_789_000_000_123_000_000, "2026-09-10T00:26:40.123Z"),
        ] {
            assert_eq!(fmt_mark(nanos), want, "for {nanos}");
        }
    }

    /// A line before the first mark has NO time, and is not given the first mark's.
    ///
    /// The opening bytes of every log are written before the first interval elapses, and a log from
    /// an older kern has no marks at all. Both must read as "not recorded" rather than as a time,
    /// because a confident wrong instant is the failure this whole index exists to avoid.
    #[test]
    fn a_line_before_the_first_mark_has_no_time() {
        let marks = [(100u64, 1_000u64), (200, 2_000), (400, 4_000)];
        assert_eq!(mark_for(&marks, 0), None);
        assert_eq!(mark_for(&marks, 99), None);
        assert_eq!(mark_for(&marks, 100), Some(1_000));
        assert_eq!(mark_for(&marks, 150), Some(1_000));
        assert_eq!(mark_for(&marks, 399), Some(2_000));
        assert_eq!(mark_for(&marks, 10_000), Some(4_000));
        assert_eq!(mark_for(&[], 5), None);
    }
}

/// Parse a `logs --since` / `--until` value into unix NANOSECONDS, the unit the index records.
///
/// THREE SPELLINGS, BECAUSE DOCKER TAKES THREE and a script ported across carries whichever its
/// author used:
///
///  * a RELATIVE duration ending in `s`, `m`, `h` or `d` (`10m`, `90s`, `1h30m`, `2d`), measured
///    back from NOW - the form a monitoring loop writes,
///  * unix SECONDS (`1789730443`), the form a previous command's output carries,
///  * RFC3339 (`2026-09-18T12:00:00Z`, with optional fractional seconds), the form a log line of
///    kern's own `logs -t` prints, so its output can be fed straight back in.
///
/// `None` for anything else, and the caller names what is accepted rather than guessing: a
/// misparsed time silently shows the wrong window, which is worse than a refusal because the output
/// looks like an answer.
///
/// The civil-to-days conversion is the exact inverse of [`fmt_mark`]'s days-to-civil (both Howard
/// Hinnant's), so a stamp this crate printed round-trips through this function unchanged.
pub(crate) fn parse_log_time(v: &str, now_nanos: u64) -> Option<u64> {
    let v = v.trim();
    if v.is_empty() {
        return None;
    }
    // RFC3339 first: it is the only form containing a `-` after its first character, so the test is
    // unambiguous against both a bare number and a duration.
    if v.len() >= 20 && v.as_bytes()[4] == b'-' {
        return parse_rfc3339(v);
    }
    // A bare number is unix seconds. Checked before the duration parser so `1789730443` is not read
    // as a malformed duration.
    if v.bytes().all(|b| b.is_ascii_digit()) {
        return v.parse::<u64>().ok()?.checked_mul(1_000_000_000);
    }
    // A duration: one or more `<number><unit>` pairs, measured back from now.
    let mut secs: u64 = 0;
    let mut digits = String::new();
    for c in v.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let n: u64 = digits.parse().ok()?;
        digits.clear();
        let mult = match c {
            's' => 1,
            'm' => 60,
            'h' => 3_600,
            'd' => 86_400,
            _ => return None,
        };
        secs = secs.checked_add(n.checked_mul(mult)?)?;
    }
    // A trailing number with no unit (`10`) is not a duration; it was already handled as seconds
    // above, so reaching here with digits left over means a malformed value like `1h30`.
    if !digits.is_empty() {
        return None;
    }
    now_nanos.checked_sub(secs.checked_mul(1_000_000_000)?)
}

/// `YYYY-MM-DDThh:mm:ss[.frac][Z]` to unix nanoseconds. Only UTC is accepted: a numeric offset would
/// need a second field of arithmetic for a form no kern surface ever prints.
pub(crate) fn parse_rfc3339(v: &str) -> Option<u64> {
    let b = v.as_bytes();
    if b.len() < 19
        || b[10] != b'T'
        || b[4] != b'-'
        || b[7] != b'-'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> { v.get(from..to)?.parse().ok() };
    let (y, m, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hh, mm, ss) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days-from-civil, the inverse of the civil-from-days in `fmt_mark`.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days
        .checked_mul(86_400)?
        .checked_add(hh * 3600 + mm * 60 + ss)?;
    if secs < 0 {
        return None; // before 1970: the index cannot hold it and no kern log predates it
    }
    // Fractional seconds, to nanosecond precision, ignoring a trailing `Z`.
    let mut nanos = (secs as u64).checked_mul(1_000_000_000)?;
    if b.get(19) == Some(&b'.') {
        let frac: String = v[20..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .take(9)
            .collect();
        if !frac.is_empty() {
            let scale = 10u64.checked_pow(9 - frac.len() as u32)?;
            nanos = nanos.checked_add(frac.parse::<u64>().ok()?.checked_mul(scale)?)?;
        }
    }
    Some(nanos)
}

#[cfg(test)]
mod log_time_tests {
    use super::{fmt_mark, parse_log_time};

    /// THE THREE SPELLINGS DOCKER TAKES, and the round trip that makes the third one useful.
    ///
    /// `--since` is the flag a monitoring loop writes and an incident write-up writes, and the two
    /// write it differently: `--since 30s` against `--since 2026-09-18T11:33:44.731Z`, the second
    /// copied out of kern's own `logs -t` output. A parser that took only one of them would send
    /// half its callers to convert a timestamp by hand.
    #[test]
    fn a_log_time_is_a_duration_unix_seconds_or_rfc3339() {
        // Fixed "now" so the relative forms are exact rather than approximately right.
        let now: u64 = 1_800_000_000_000_000_000; // 2027-01-15T08:00:00Z, in nanoseconds
        let sec = 1_000_000_000u64;

        // RELATIVE, back from now, in every unit and in combination.
        assert_eq!(parse_log_time("30s", now), Some(now - 30 * sec));
        assert_eq!(parse_log_time("10m", now), Some(now - 600 * sec));
        assert_eq!(parse_log_time("2h", now), Some(now - 7_200 * sec));
        assert_eq!(parse_log_time("1d", now), Some(now - 86_400 * sec));
        assert_eq!(parse_log_time("1h30m", now), Some(now - 5_400 * sec));

        // UNIX SECONDS, the form a previous command's output carries.
        assert_eq!(parse_log_time("1789730443", now), Some(1_789_730_443 * sec));

        // RFC3339, with and without fractional seconds, and the ROUND TRIP: a stamp this crate
        // printed must parse back to the instant it was printed from. That is the property, and it
        // is what makes `--since "$(kern logs -t … | head -1 | cut -d' ' -f1)"` work.
        let printed = fmt_mark(1_789_730_443_731_000_000);
        assert_eq!(printed, "2026-09-18T11:20:43.731Z");
        assert_eq!(
            parse_log_time(&printed, now),
            Some(1_789_730_443_731_000_000),
            "a stamp kern printed must parse back to the same instant"
        );
        assert_eq!(
            parse_log_time("2026-09-18T11:20:43Z", now),
            Some(1_789_730_443 * sec)
        );

        // REFUSED, every one of them, because a misread time shows the wrong window and the output
        // looks like an answer.
        for bad in [
            "",
            "domani",
            "1h30",                 // a trailing number with no unit
            "10x",                  // an unknown unit
            "2026-13-01T00:00:00Z", // month 13
            "2026-09-18T25:00:00Z", // hour 25
            "2026-09-18",           // a date with no time
            "-5m",                  // a sign is not part of the grammar
        ] {
            assert_eq!(parse_log_time(bad, now), None, "{bad:?} must be refused");
        }

        // A duration longer than the epoch cannot underflow into a huge number.
        assert_eq!(parse_log_time("99999d", 0), None);
    }
}

#[cfg(test)]
mod log_time_totality {
    use super::parse_log_time;

    /// TOTALITY: no input makes the time parser panic, and none makes it overflow into a wrong
    /// answer.
    ///
    /// This function reads a value straight off the command line and does arithmetic on it -
    /// multiplications by 86400 and by a billion, a subtraction from "now". Every one of those is a
    /// place an unchecked operation panics in debug and wraps in release, and a WRAPPED time is
    /// worse than a panic: it shows a window nobody asked for and the output looks like output.
    ///
    /// Exhaustive over the alphabet that decides its control flow, at the lengths where its branches
    /// interact, plus the extremes of each numeric field. Not a sample: the failure mode of an
    /// arithmetic bug is one specific value, and a sample is exactly what misses it.
    #[test]
    fn no_input_panics_or_wraps_the_clock() {
        let now: u64 = 1_800_000_000_000_000_000;
        // Every string of length <= 4 over the characters that select a branch: the digits that
        // start a number, the unit letters, the separators of RFC3339, and a sign.
        let alphabet: &[u8] = b"019smhdT-:.Z";
        let mut buf = [0u8; 4];
        for len in 0..=4usize {
            let total = alphabet.len().pow(len as u32);
            for i in 0..total {
                let mut x = i;
                for slot in buf.iter_mut().take(len) {
                    *slot = alphabet[x % alphabet.len()];
                    x /= alphabet.len();
                }
                let s = std::str::from_utf8(&buf[..len]).expect("ascii alphabet");
                // The property is termination without a panic, and an answer that is a real instant
                // when there is one: nothing here may exceed "now" by construction, since every
                // relative form counts BACKWARDS.
                if let Some(t) = parse_log_time(s, now) {
                    assert!(
                        t <= now || !s.ends_with(['s', 'm', 'h', 'd']),
                        "{s:?} -> {t}"
                    );
                }
            }
        }

        // THE EXTREMES OF EACH FIELD, where a checked multiplication is the only thing between a
        // value and a wrapped clock. Every one of these must be refused rather than answered.
        for bad in [
            "99999999999999999999d",             // days that overflow a u64 of seconds
            "18446744073709551615s",             // u64::MAX seconds
            "9999999999999999999",               // unix seconds that overflow when scaled to nanos
            "99999-01-01T00:00:00Z",             // a year no epoch arithmetic can hold
            "0000-01-01T00:00:00Z", // before 1970: negative, and refused rather than wrapped
            "2026-09-18T00:00:00.999999999999Z", // more fractional digits than nanoseconds have
        ] {
            let got = parse_log_time(bad, now);
            assert!(
                got.is_none() || got.is_some_and(|t| t < now * 2),
                "{bad:?} produced {got:?}, which is not an instant"
            );
        }
        // A duration longer than the epoch cannot underflow into a huge number.
        assert_eq!(parse_log_time("99999999d", 0), None);
        // And the one value that must survive all of it: a stamp this crate prints.
        assert!(parse_log_time("2026-09-18T11:20:43.731Z", now).is_some());
    }
}

#[cfg(test)]
mod run_log_tests {
    /// A run log is exactly `<name>-<digits>.log`, so `foo` never takes `foo-bar`'s history, and the
    /// last-lines window counts a trailing partial line as a line.
    #[test]
    fn run_logs_match_exactly_and_the_tail_window_counts_lines() {
        assert!(super::is_run_log_of("web-123.log", "web"));
        assert!(!super::is_run_log_of("web-bar-123.log", "web"));
        assert!(!super::is_run_log_of("web-123.log.idx", "web"));
        assert!(!super::is_run_log_of("web-.log", "web"));
        assert_eq!(super::last_lines(b"a\nb\nc\n", 2), b"b\nc\n");
        assert_eq!(super::last_lines(b"a\nb\nc", 2), b"b\nc");
        assert_eq!(super::last_lines(b"a\nb\n", 5), b"a\nb\n");
        assert_eq!(super::last_lines(b"a\n", 0), b"");
    }
}

#[cfg(test)]
mod log_cap_precedence_tests {
    use super::*;

    /// Docker's order: the box's own flag, then the host setting, then the built-in default.
    #[test]
    fn the_flag_wins_over_the_config_and_the_config_over_the_default() {
        let base = LogCap::default();
        let cap =
            LogCap::pick(Some(1 << 20), Some(5), Some(10 << 20), Some(3), true).with_base(base);
        assert_eq!((cap.max_bytes, cap.files), (1 << 20, 5), "flags win");
        let cap = LogCap::pick(None, None, Some(10 << 20), Some(3), true).with_base(base);
        assert_eq!(
            (cap.max_bytes, cap.files),
            (10 << 20, 3),
            "config fills what flags left"
        );
        let cap = LogCap::pick(Some(1 << 20), None, None, Some(3), false).with_base(base);
        assert_eq!(
            (cap.max_bytes, cap.files, cap.keep),
            (1 << 20, 3, false),
            "mixed, per field"
        );
        let cap = LogCap::pick(None, None, None, None, true).with_base(base);
        assert_eq!(
            cap, base,
            "nothing set is exactly the cap every box always had"
        );
    }

    /// A zero from either source can never reach the pump, which would rotate on every byte.
    #[test]
    fn a_zero_from_any_source_falls_through_to_the_next() {
        let base = LogCap::default();
        let cap = LogCap::pick(Some(0), Some(0), Some(0), Some(0), true).with_base(base);
        assert_eq!(cap, base);
    }
}

#[cfg(test)]
mod demux_tests {
    use super::*;
    use std::io::Write;

    /// Frames taken apart onto two writers, whatever the pieces they arrive in.
    #[test]
    fn frames_are_taken_apart_onto_stdout_and_stderr() {
        let mut frames = Vec::new();
        for (kind, data) in [
            (STREAM_STDOUT, &b"o1\n"[..]),
            (STREAM_STDERR, b"e1\n"),
            (STREAM_STDOUT, b"o2\n"),
        ] {
            frames.extend_from_slice(&[kind, 0, 0, 0]);
            frames.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
            frames.extend_from_slice(data);
        }
        for piece in [1, 3, 8, frames.len()] {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            {
                let mut d = FrameDemux::new(&mut out, &mut err);
                for chunk in frames.chunks(piece) {
                    d.write_all(chunk).unwrap();
                }
                d.flush().unwrap();
            }
            assert_eq!(out, b"o1\no2\n", "pieces of {piece}");
            assert_eq!(err, b"e1\n", "pieces of {piece}");
        }
    }
}

#[cfg(test)]
mod run_file_tests {
    use super::*;

    /// One run's files are every file the pump and a rotation write for it, and none of another
    /// run's, of the same name or of a name that starts like it.
    #[test]
    fn a_runs_files_are_all_of_its_own_and_none_of_another() {
        let d = std::env::temp_dir().join(format!("kern-runfiles-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("dir");
        let mine = [
            "web-12.log",
            "web-12.log.idx",
            "web-12.log.streams",
            "web-12.log.1",
            "web-12.log.1.idx",
            "web-12.log.2",
        ];
        let others = [
            "web-123.log",
            "web-12.logx",
            "web-12.logger-5.log",
            "web-13.log.streams",
        ];
        for f in mine.iter().chain(others.iter()) {
            std::fs::write(d.join(f), b"x").expect("write");
        }
        let mut got: Vec<String> = registry::run_log_files(&d, "web-12")
            .into_iter()
            .map(|(_, suffix)| format!("web-12.log{suffix}"))
            .collect();
        got.sort();
        let mut want: Vec<String> = mine.iter().map(|s| (*s).to_string()).collect();
        want.sort();
        assert_eq!(got, want);
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kern-streams-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        assert!(std::fs::create_dir_all(&d).is_ok());
        d
    }

    fn split_cap(max_bytes: u64) -> LogCap {
        LogCap {
            max_bytes,
            files: 2,
            keep: true,
            streams: true,
            journald: false,
        }
    }

    /// `(stream, payload)` of every frame in `bytes`, and how many bytes were left over.
    fn decode(bytes: &[u8]) -> (Vec<(u8, Vec<u8>)>, usize) {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 8 <= bytes.len() {
            let mut len = [0u8; 4];
            len.copy_from_slice(&bytes[i + 4..i + 8]);
            let n = u32::from_be_bytes(len) as usize;
            out.push((bytes[i], bytes[i + 8..i + 8 + n].to_vec()));
            i += 8 + n;
        }
        (out, bytes.len() - i)
    }

    /// A switch is one record, a write in the same stream is none, and the record reads back as
    /// the offsets where each stretch starts.
    #[test]
    fn switches_are_recorded_once_and_read_back_as_offsets() {
        let d = dir("switch");
        let path = d.join("b.log");
        let Some(mut log) = CappedLog::open(&path, split_cap(1 << 20)) else {
            panic!("the log opens");
        };
        for (stream, bytes) in [
            (STREAM_STDOUT, &b"out\n"[..]),
            (STREAM_STDERR, b"err\n"),
            (STREAM_STDERR, b"err2\n"),
            (STREAM_STDOUT, b"o\n"),
        ] {
            log.cur_stream = stream;
            log.write(bytes);
        }
        drop(log);
        assert_eq!(
            read_streams(&path),
            vec![(0, STREAM_STDOUT), (4, STREAM_STDERR), (13, STREAM_STDOUT)]
        );
        assert_eq!(
            std::fs::metadata(streams_path(&path)).map(|m| m.len()).ok(),
            Some(3 * STREAM_REC_LEN as u64)
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A stretch longer than a record's 31-bit step is bridged under the stream it has, and the
    /// switch after it lands on the right offset.
    #[test]
    fn a_stretch_past_the_step_field_is_bridged() {
        let d = dir("bridge");
        let path = d.join("b.log");
        let Some(mut log) = CappedLog::open(&path, split_cap(u64::MAX)) else {
            panic!("the log opens");
        };
        log.cur_stream = STREAM_STDOUT;
        log.note_stream();
        let far = (1u64 << 32) + 5;
        log.written = far;
        log.cur_stream = STREAM_STDERR;
        log.note_stream();
        drop(log);
        let runs = read_streams(&path);
        assert_eq!(runs.first(), Some(&(0, STREAM_STDOUT)));
        assert_eq!(runs.last(), Some(&(far, STREAM_STDERR)));
        assert!(runs[1..runs.len() - 1]
            .iter()
            .all(|r| r.1 == STREAM_STDOUT && r.0 < far));
        assert_eq!(stream_at(&runs, far - 1).0, STREAM_STDOUT);
        assert_eq!(stream_at(&runs, far).0, STREAM_STDERR);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// At the cap the record ends on stdout and stops growing; the log goes on.
    #[test]
    fn the_record_is_capped_and_ends_on_stdout() {
        let d = dir("cap");
        let path = d.join("b.log");
        let Some(mut log) = CappedLog::open(&path, split_cap(8192)) else {
            panic!("the log opens");
        };
        for i in 0..3000u32 {
            log.cur_stream = if i % 2 == 0 {
                STREAM_STDOUT
            } else {
                STREAM_STDERR
            };
            log.write(b"x");
        }
        drop(log);
        let len = std::fs::metadata(streams_path(&path))
            .map(|m| m.len())
            .unwrap_or(0);
        assert!(len <= 4096, "the record outgrew half the log: {len}");
        let runs = read_streams(&path);
        assert_eq!(runs.last().map(|r| r.1), Some(STREAM_STDOUT));
        assert_eq!(stream_at(&runs, 2999).0, STREAM_STDOUT);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A line cut by a stream change becomes two frames, the time column inside the first.
    #[test]
    fn a_line_is_cut_at_the_stream_change_and_the_column_leads_it() {
        let runs = [(0, STREAM_STDOUT), (4, STREAM_STDERR)];
        let mut out = Vec::new();
        assert!(write_frames(&mut out, &runs, 2, b"T ", b"abcd\n").is_ok());
        assert_eq!(
            decode(&out),
            (
                vec![
                    (STREAM_STDOUT, b"T ab".to_vec()),
                    (STREAM_STDERR, b"cd\n".to_vec())
                ],
                0
            )
        );
        let mut plain = Vec::new();
        assert!(write_frames(&mut plain, &[], 0, b"", b"no record\n").is_ok());
        assert_eq!(
            decode(&plain).0,
            vec![(STREAM_STDOUT, b"no record\n".to_vec())]
        );
    }

    /// The reader `logs --frames` uses: a log written on two streams comes back as frames of the
    /// right stream, an unterminated last line included.
    #[test]
    fn the_stamper_writes_frames_by_stream() {
        let d = dir("stamper");
        let path = d.join("b.log");
        let Some(mut log) = CappedLog::open(&path, split_cap(1 << 20)) else {
            panic!("the log opens");
        };
        for (stream, bytes) in [
            (STREAM_STDOUT, &b"one\n"[..]),
            (STREAM_STDERR, b"two\n"),
            (STREAM_STDOUT, b"thr"),
            (STREAM_STDERR, b"ee\n"),
            (STREAM_STDOUT, b"tail"),
        ] {
            log.cur_stream = stream;
            log.write(bytes);
        }
        drop(log);
        let content = std::fs::read(&path).unwrap_or_default();
        let mut s = Stamper::new(&path, 0)
            .with_window(None, None, false)
            .with_frames(true);
        let mut out = Vec::new();
        assert!(s.push(&mut out, &content).is_ok());
        assert!(s.flush(&mut out).is_ok());
        assert_eq!(
            decode(&out),
            (
                vec![
                    (STREAM_STDOUT, b"one\n".to_vec()),
                    (STREAM_STDERR, b"two\n".to_vec()),
                    (STREAM_STDOUT, b"thr".to_vec()),
                    (STREAM_STDERR, b"ee\n".to_vec()),
                    (STREAM_STDOUT, b"tail".to_vec()),
                ],
                0
            )
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
