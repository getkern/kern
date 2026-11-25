//! Box-start counter - a single mmap'd atomic, daemonless and lock-free.
//!
//! A `kern box` can live a few milliseconds, below `kern top`'s one-second refresh, so an agent
//! starting hundreds of boxes a second would be invisible in the live list. Every box start does ONE
//! `fetch_add` on a shared-memory counter, and `kern top` samples the MONOTONIC total each refresh
//! and derives starts/sec, a session peak and a sparkline entirely reader-side.
//!
//! The page also carried `kern limit`'s count (offset 0) and its summed setup latency (offset 8)
//! until that verb was removed in 0.57.0. The box count stays at offset 16, so a `kern top` of
//! either version reads the other's file correctly.
//!
//! What is NOT tracked: "active/peak CONCURRENT". A live count needs something that decrements when
//! a box ends; the start rate is what this can say truthfully.
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicU64, Ordering};

// A page (room for future fields). Offset 16 = u64 box-START count (kern top's box-rate lens for
// ephemeral boxes); offsets 0 and 8 were `kern limit`'s and are no longer written.
const MAP_LEN: usize = 4096;

/// Captured once at process entry (see [`mark_start`]); [`record`] measures entry→exec against it to
/// accumulate the honest per-run setup latency. If `mark_start` was never called the latency add is 0
/// (the count still increments) - a metric must never change behaviour, only observe it.
static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Stamp the process-start instant, as early as possible in `main`. Cheap (one `Instant::now`), safe to
/// call on every `kern` invocation; [`since_start_us`] reads it back for the start-up profile.
pub fn mark_start() {
    let _ = START.set(std::time::Instant::now());
}

/// Microseconds since process entry, or `None` if [`mark_start`] never ran.
///
/// One stamp for the whole process, reused rather than taken a second time: a second clock read at
/// a second point would drift from this one and two profiles would disagree about the same box. `None` rather than zero, because "not stamped" and "took no time" are
/// different facts and a profiler that renders them the same is the class of defect this exists to
/// measure.
pub fn since_start_us() -> Option<u128> {
    START.get().map(|s| s.elapsed().as_micros())
}

/// `$XDG_RUNTIME_DIR/kern/runstats` (falling back to `/run/user/<uid>` then `/tmp/kern-<uid>`), the
/// same runtime-dir resolution as the box registry - so writer (a box start) and reader (`kern top`)
/// agree on the file without a shared constant. `pub(crate)` so the volume guard can add this FILE's
/// dev/ino to the non-mountable identity set (it is a runtime registry child, not a directory).
pub(crate) fn path() -> std::path::PathBuf {
    if let Some(x) = crate::xdg_var("XDG_RUNTIME_DIR") {
        return x.join("kern/runstats");
    }
    let uid = unsafe { libc::getuid() };
    let run = std::path::PathBuf::from(format!("/run/user/{uid}"));
    if run.is_dir() {
        return run.join("kern/runstats");
    }
    std::path::PathBuf::from(format!("/tmp/kern-{uid}/runstats"))
}

/// Record one box START, at offset 16 of the lock-free mmap page. Called once when a `kern box`
/// registers, so `kern top` can
/// show a box-start RATE the flickering live list can't: a box lives ~ms, below a 1 s refresh, so an
/// agent firing hundreds of ephemeral boxes/sec is otherwise invisible except as a rate.
pub fn record_box() {
    let p = path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    with_map(
        &p,
        libc::O_RDWR | libc::O_CREAT,
        libc::PROT_READ | libc::PROT_WRITE,
        |ptr| unsafe {
            // SAFETY: offset 16 is a naturally-aligned u64 within the page, only ever touched atomically.
            (*((ptr as *const u8).add(16) as *const AtomicU64)).fetch_add(1, Ordering::Relaxed);
        },
    );
}

/// Cumulative box-START count (offset 16), 0 if the counter file is absent/unreadable. Read-only and
/// lock-free, safe to sample from `kern top` each refresh; the rate is derived reader-side like runs.
pub fn box_total() -> u64 {
    let mut out = 0u64;
    with_map(&path(), libc::O_RDONLY, libc::PROT_READ, |ptr| unsafe {
        out = (*((ptr as *const u8).add(16) as *const AtomicU64)).load(Ordering::Relaxed);
    });
    out
}

/// Open `path` with `open_flags`, ensure it's page-sized, `mmap` it `MAP_SHARED` with `prot`, run `f`
/// on the mapping, then unmap. All failures are swallowed (the caller gets its default). The fd is
/// closed right after mmap - the mapping keeps the page alive without it.
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
        // touch (offset 16) with no backing, and any access faults. A 0-byte counter - planted, or a
        // failed/racing ftruncate - must not crash `kern top`. Refuse to map under a full page: the
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
    fn box_starts_increment_the_shared_total() {
        // Isolate the counter file to a temp runtime dir (process-global env - serialize with others).
        let _g = crate::env_guard();
        let tmp = std::env::temp_dir().join(format!("kern-boxstats-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        crate::set_global_env("XDG_RUNTIME_DIR", &tmp);

        assert_eq!(box_total(), 0, "fresh box counter starts at 0");
        record_box();
        record_box();
        assert_eq!(box_total(), 2, "two box starts → box total 2");

        crate::unset_global_env("XDG_RUNTIME_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_short_counter_file_reads_as_empty_and_never_sigbuses() {
        // A 0-byte counter (planted, externally truncated, or a failed/racing ftruncate) mmaps a page
        // with no backing - touching it would SIGBUS and crash `kern top`. `with_map`'s fstat guard must
        // make the reader report 0 instead, and the writer must self-heal the file (ftruncate to a page)
        // then count. This test would ABORT the whole runner if the guard regressed.
        let _g = crate::env_guard();
        let tmp = std::env::temp_dir().join(format!("kern-runstats-short-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("kern")).unwrap();
        crate::set_global_env("XDG_RUNTIME_DIR", &tmp);

        std::fs::write(tmp.join("kern/runstats"), b"").unwrap(); // 0 bytes
        assert_eq!(box_total(), 0, "a 0-byte counter reads as empty, no crash");
        record_box(); // self-heals: ftruncate grows it to a page, then increments
        assert_eq!(box_total(), 1, "the writer grows the short file and counts");

        crate::unset_global_env("XDG_RUNTIME_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
