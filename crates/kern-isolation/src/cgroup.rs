//! Best-effort cgroup v2 resource limits (memory + PIDs).
//!
//! Confines the sandbox so a runaway fork bomb or memory hog can't take down the host. Applied
//! before the namespace setup, so the forked workload inherits the cgroup. If the hierarchy
//! isn't delegated/writable (no systemd user delegation), it degrades gracefully: the namespace
//! isolation still holds; only the resource cap is skipped. cgroup v2 only.

use std::fs;
use std::path::PathBuf;

/// Memory ceiling for a sandbox (512 MiB) — conservative but generous.
const DEFAULT_MEMORY_MAX: &[u8] = b"536870912";
/// Process-count ceiling — caps fork bombs.
const DEFAULT_PIDS_MAX: &[u8] = b"512";

/// Confine the current process in a fresh cgroup with memory + pid caps. Returns the cgroup
/// path on success (the workload, forked later, inherits it), or `None` if unavailable.
pub fn apply_limits(tag: &str) -> Option<PathBuf> {
    // cgroup v2 presents a unified hierarchy with this file at the root.
    if !PathBuf::from("/sys/fs/cgroup/cgroup.controllers").exists() {
        return None;
    }
    // The current cgroup path is the tail of the single `0::<path>` line in /proc/self/cgroup.
    let cur = fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = cur.trim().rsplit("::").next()?.trim_start_matches('/');
    let parent = PathBuf::from("/sys/fs/cgroup").join(rel);
    let child = parent.join(format!("kern-box-{tag}-{}", std::process::id()));

    // Make the controllers available to children (may already be on, or denied by the
    // no-internal-process rule when the parent still has member processes).
    let _ = fs::write(parent.join("cgroup.subtree_control"), b"+memory +pids");
    fs::create_dir(&child).ok()?;

    // Set the caps. If BOTH fail, the controllers aren't delegated to this path — do NOT leave a
    // useless cgroup behind and do NOT pretend the workload is capped. Clean up and bail, so the
    // caller reports "no cap" honestly rather than a false sense of safety.
    let pids_ok = fs::write(child.join("pids.max"), DEFAULT_PIDS_MAX).is_ok();
    let mem_ok = fs::write(child.join("memory.max"), DEFAULT_MEMORY_MAX).is_ok();
    // Disable swap for the cgroup so `memory.max` is a hard total cap (else the overflow swaps).
    let _ = fs::write(child.join("memory.swap.max"), b"0");
    if !pids_ok && !mem_ok {
        let _ = fs::remove_dir(&child);
        return None;
    }

    // Join the cgroup — binds the limits to us (and our future forked workload).
    if fs::write(
        child.join("cgroup.procs"),
        std::process::id().to_string().as_bytes(),
    )
    .is_err()
    {
        let _ = fs::remove_dir(&child);
        return None;
    }
    Some(child)
}
