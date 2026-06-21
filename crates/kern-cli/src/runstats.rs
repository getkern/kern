//! `kern run` throughput counter — a single mmap'd atomic, daemonless and lock-free.
//!
//! `kern run` is a fire-and-forget capped process (~1 ms, no sandbox, not registered). To let `kern
//! top` show LIVE run throughput without tracking each ephemeral run, every `kern run` does ONE
//! `fetch_add` on a shared-memory counter just before it `exec()`s the workload — cost a few
//! nanoseconds plus a one-time page map. `kern top` samples the MONOTONIC total each refresh and
//! derives runs/sec + a sparkline entirely reader-side.
//!
//! Only a monotonic total is tracked: `kern run` exec()s IN PLACE (no supervisor is left to run a
//! decrement on exit), so "active/peak concurrent" would require a per-run reaper process — against
//! the whole point of a ~1 ms run. Throughput + cumulative count are the honest, zero-cost metrics.

use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicU64, Ordering};

// A page (room for future fields); only offset 0 (a u64 total) is used today.
const MAP_LEN: usize = 4096;

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
    with_map(&p, libc::O_RDWR | libc::O_CREAT, libc::PROT_READ | libc::PROT_WRITE, |ptr| {
        // SAFETY: `ptr` is a valid MAP_SHARED page; offset 0 is a naturally-aligned u64 we only ever
        // touch atomically, so concurrent writers from other `kern run` processes are race-free.
        unsafe { &*(ptr as *const AtomicU64) }.fetch_add(1, Ordering::Relaxed);
    });
}

/// The cumulative number of `kern run` invocations (0 if the counter file is absent/unreadable).
/// Read-only and lock-free — safe to sample from `kern top` on every refresh.
pub fn total() -> u64 {
    let mut out = 0u64;
    with_map(&path(), libc::O_RDONLY, libc::PROT_READ, |ptr| {
        out = unsafe { &*(ptr as *const AtomicU64) }.load(Ordering::Relaxed);
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
        let _g = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-runstats-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::env::set_var("XDG_RUNTIME_DIR", &tmp);

        assert_eq!(total(), 0, "fresh counter starts at 0");
        record();
        record();
        record();
        assert_eq!(total(), 3, "three records → total 3");

        std::env::remove_var("XDG_RUNTIME_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
