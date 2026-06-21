//! `kern run` throughput counter — a single mmap'd atomic, daemonless and lock-free.
//!
//! `kern run` is a fire-and-forget capped process (~1 ms, no sandbox, not registered). To let `kern
//! top` show LIVE run throughput without tracking each ephemeral run, every `kern run` does ONE
//! `fetch_add` on a shared-memory counter just before it `exec()`s the workload — cost a few
//! nanoseconds plus a one-time page map. `kern top` samples the MONOTONIC total each refresh and
//! derives runs/sec + a sparkline entirely reader-side.
//!
//! Two honest, zero-cost fields are tracked (a page has room for more): a monotonic **total** count
//! and the cumulative **setup latency** (process entry → `exec`, in microseconds) so `top` can show a
//! real average — the per-run exec-setup cost, measured not guessed. (Honest caveat: for a *scoped*
//! run the workload is exec'd in a re-exec'd child, so this is the child's entry→exec leg, not the full
//! outer→inner setup — an under-, never over-count.) What is NOT tracked:
//! "active/peak CONCURRENT" — `kern run` exec()s IN PLACE (no supervisor left to decrement on exit), so
//! a live-count would need a per-run reaper against the whole point of a ~1 ms run. `top` derives
//! runs/sec, a session peak throughput, and a sparkline entirely reader-side from the monotonic total.

use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicU64, Ordering};

// A page (room for future fields). Offset 0 = u64 total count, offset 8 = u64 sum of setup-latency µs.
const MAP_LEN: usize = 4096;

/// Captured once at process entry (see [`mark_start`]); [`record`] measures entry→exec against it to
/// accumulate the honest per-run setup latency. If `mark_start` was never called the latency add is 0
/// (the count still increments) — a metric must never change behaviour, only observe it.
static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Stamp the process-start instant, as early as possible in `main`. Cheap (one `Instant::now`), safe to
/// call on every `kern` invocation — only `kern run` reads it back via [`record`].
pub fn mark_start() {
    let _ = START.set(std::time::Instant::now());
}

/// `$XDG_RUNTIME_DIR/kern/runstats` (falling back to `/run/user/<uid>` then `/tmp/kern-<uid>`), the
/// same runtime-dir resolution as the box registry — so writer (`kern run`) and reader (`kern top`)
/// agree on the file without a shared constant.
fn path() -> std::path::PathBuf {
    if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR") {
        return std::path::PathBuf::from(x).join("kern/runstats");
    }
    let uid = unsafe { libc::getuid() };
    let run = std::path::PathBuf::from(format!("/run/user/{uid}"));
    if run.is_dir() {
        return run.join("kern/runstats");
    }
    std::path::PathBuf::from(format!("/tmp/kern-{uid}/runstats"))
}

/// Record one `kern run`. Best-effort and lock-free: ANY failure is silent (a metrics counter must
/// never fail a run). Called once, right before `kern run` exec()s the workload.
pub fn record() {
    let p = path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // Setup latency = time from process entry (mark_start) to here (right before exec) = kern's own
    // per-run overhead. Saturating cast so an absurd clock never wraps the accumulator.
    let micros = START
        .get()
        .map(|s| s.elapsed().as_micros().min(u64::MAX as u128) as u64)
        .unwrap_or(0);
    with_map(
        &p,
        libc::O_RDWR | libc::O_CREAT,
        libc::PROT_READ | libc::PROT_WRITE,
        |ptr| unsafe {
            // SAFETY: `ptr` is a valid MAP_SHARED page; offsets 0 and 8 are naturally-aligned u64s we only
            // ever touch atomically, so concurrent writers from other `kern run` processes are race-free.
            (*(ptr as *const AtomicU64)).fetch_add(1, Ordering::Relaxed);
            (*((ptr as *const u8).add(8) as *const AtomicU64)).fetch_add(micros, Ordering::Relaxed);
        },
    );
}

/// `(total, setup_latency_µs_sum)` — the cumulative `kern run` count and the summed entry→exec latency
/// (both 0 if the counter file is absent/unreadable). Read-only and lock-free — safe to sample from
/// `kern top` on every refresh; the average latency is `sum / total`.
pub fn snapshot() -> (u64, u64) {
    let mut out = (0u64, 0u64);
    with_map(&path(), libc::O_RDONLY, libc::PROT_READ, |ptr| unsafe {
        let total = (*(ptr as *const AtomicU64)).load(Ordering::Relaxed);
        let sum = (*((ptr as *const u8).add(8) as *const AtomicU64)).load(Ordering::Relaxed);
        out = (total, sum);
    });
    out
}

/// Open `path` with `open_flags`, ensure it's page-sized, `mmap` it `MAP_SHARED` with `prot`, run `f`
/// on the mapping, then unmap. All failures are swallowed (the caller gets its default). The fd is
/// closed right after mmap — the mapping keeps the page alive without it.
fn with_map(path: &std::path::Path, open_flags: i32, prot: i32, f: impl FnOnce(*mut libc::c_void)) {
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    unsafe {
        let fd = libc::open(c.as_ptr(), open_flags, 0o600);
        if fd < 0 {
            return;
        }
        if open_flags & libc::O_CREAT != 0 {
            // Idempotent: grow a fresh file to a page; never shrinks an existing one below a page.
            let _ = libc::ftruncate(fd, MAP_LEN as libc::off_t);
        }
        // Guard against a SIGBUS: mapping MAP_LEN over a file SHORTER than a page leaves the page we
        // touch (offsets 0/8) with no backing, and any access faults. A 0-byte counter — planted, or a
        // failed/racing ftruncate — must not crash `kern top`. Refuse to map under a full page: the
        // reader then reports 0, the writer skips this one increment rather than abort.
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 || (st.st_size as u64) < MAP_LEN as u64 {
            libc::close(fd);
            return;
        }
        let ptr = libc::mmap(std::ptr::null_mut(), MAP_LEN, prot, libc::MAP_SHARED, fd, 0);
        libc::close(fd);
        if ptr == libc::MAP_FAILED {
            return;
        }
        f(ptr);
        libc::munmap(ptr, MAP_LEN);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_increments_the_shared_total() {
        // Isolate the counter file to a temp runtime dir (process-global env — serialize with others).
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-runstats-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::env::set_var("XDG_RUNTIME_DIR", &tmp);

        assert_eq!(snapshot().0, 0, "fresh counter starts at 0");
        record();
        record();
        record();
        assert_eq!(snapshot().0, 3, "three records → total 3");

        std::env::remove_var("XDG_RUNTIME_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_short_counter_file_reads_as_empty_and_never_sigbuses() {
        // A 0-byte counter (planted, externally truncated, or a failed/racing ftruncate) mmaps a page
        // with no backing — touching it would SIGBUS and crash `kern top`. `with_map`'s fstat guard must
        // make the reader report 0 instead, and the writer must self-heal the file (ftruncate to a page)
        // then count. This test would ABORT the whole runner if the guard regressed.
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-runstats-short-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("kern")).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &tmp);

        std::fs::write(tmp.join("kern/runstats"), b"").unwrap(); // 0 bytes
        assert_eq!(
            snapshot(),
            (0, 0),
            "a 0-byte counter reads as empty, no crash"
        );
        record(); // self-heals: ftruncate grows it to a page, then increments
        assert_eq!(
            snapshot().0,
            1,
            "the writer grows the short file and counts"
        );

        std::env::remove_var("XDG_RUNTIME_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
