//! Best-effort cgroup v2 resource limits (memory + PIDs).
//!
//! Confines the sandbox so a runaway fork bomb or memory hog can't take down the host. Applied
//! before the namespace setup, so the forked workload inherits the cgroup. If the hierarchy
//! isn't delegated/writable (no systemd user delegation), it degrades gracefully: the namespace
//! isolation still holds; only the resource cap is skipped. cgroup v2 only.

use std::fs;
use std::path::PathBuf;

/// Default memory ceiling for a sandbox (512 MiB) — conservative but generous; `--memory` overrides.
const DEFAULT_MEMORY_MAX: u64 = 536_870_912;
/// Process-count ceiling — caps fork bombs.
const DEFAULT_PIDS_MAX: &[u8] = b"512";
/// cgroup v2 CPU period (µs) for `cpu.max`; the quota is `cores * PERIOD`.
const CPU_PERIOD_US: u64 = 100_000;

/// Confine the current process in a fresh cgroup with memory + pid (+ optional CPU) caps. Returns
/// the cgroup path on success (the workload, forked later, inherits it), or `None` if unavailable.
/// `memory_max` (bytes) overrides the default ceiling; `cpus` (cores, K8s semantics) caps CPU time
/// and is best-effort — silently skipped where the CPU controller isn't delegated.
pub fn apply_limits(tag: &str, memory_max: Option<u64>, cpus: Option<f64>) -> Option<PathBuf> {
    // cgroup v2 presents a unified hierarchy with this file at the root.
    if !PathBuf::from("/sys/fs/cgroup/cgroup.controllers").exists() {
        return None;
    }
    // The current cgroup path is the tail of the single `0::<path>` line in /proc/self/cgroup.
    let cur = fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = cur.trim().rsplit("::").next()?.trim_start_matches('/');
    let parent = PathBuf::from("/sys/fs/cgroup").join(rel);
    let child = parent.join(format!("kern-box-{tag}-{}", std::process::id()));

    // Make the controllers available to children, one at a time so an unavailable one (e.g. no
    // `cpu` controller on some Android-derived kernels) doesn't block enabling the others. (May
    // already be on, or be denied by the no-internal-process rule when the parent has members.)
    for ctrl in ["+memory", "+pids", "+cpu"] {
        let _ = fs::write(parent.join("cgroup.subtree_control"), ctrl);
    }
    fs::create_dir(&child).ok()?;

    // Set the memory + PID caps. If BOTH fail the controllers aren't delegated here — do NOT leave a
    // useless cgroup behind and do NOT pretend the workload is capped. Clean up and bail, so the
    // caller reports "no cap" honestly rather than a false sense of safety. (CPU never gates this.)
    let mem_bytes = memory_max.unwrap_or(DEFAULT_MEMORY_MAX);
    let mem_ok = fs::write(child.join("memory.max"), mem_bytes.to_string()).is_ok();
    let pids_ok = fs::write(child.join("pids.max"), DEFAULT_PIDS_MAX).is_ok();
    // Disable swap for the cgroup so `memory.max` is a hard total cap (else the overflow swaps).
    let _ = fs::write(child.join("memory.swap.max"), b"0");
    if !pids_ok && !mem_ok {
        let _ = fs::remove_dir(&child);
        return None;
    }

    // Optional CPU cap (`--cpus`). cgroup v2 `cpu.max` = "<quota_us> <period_us>"; cores =
    // quota/period. Clamp to the host CPU count. Best-effort: a write failure (no CPU controller,
    // e.g. some Android kernels) is ignored — isolation still holds, only the CPU cap is skipped.
    if let Some(c) = cpus {
        // `c` is already clamped to the host CPU count by the CLI (the single place that can warn);
        // an over-large quota would be harmless anyway (the kernel never grants more than the
        // physical cores), so we don't re-read /proc/cpuinfo on this hot path.
        let quota = (c * CPU_PERIOD_US as f64).round().max(1.0) as u64;
        let _ = fs::write(child.join("cpu.max"), format!("{quota} {CPU_PERIOD_US}"));
    }

    // Join the cgroup — binds the limits to us (and our future forked workload).
    if fs::write(child.join("cgroup.procs"), std::process::id().to_string()).is_err() {
        let _ = fs::remove_dir(&child);
        return None;
    }
    Some(child)
}
