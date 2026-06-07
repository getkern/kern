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

/// Confine the current process in a fresh cgroup with memory + pid (+ optional swap / CPU quota /
/// CPU pinning) caps. Returns the cgroup path on success (the workload, forked later, inherits it),
/// or `None` if unavailable. `memory_max` (bytes) overrides the default ceiling; `memory_swap_max`
/// (bytes, `--memory-swap-max`) sets `memory.swap.max` — the v2 swap *allowance*, separate from
/// `memory.max`, default `0` (swap off, so `memory.max` is a hard total); `cpuset` (`--cpuset-cpus`,
/// e.g. `"0-3"`) pins to specific CPUs via `cpuset.cpus`; `cpus` (cores, K8s semantics) caps CPU
/// time via `cpu.max`. The swap/CPU/cpuset knobs are all best-effort — silently skipped where the
/// controller isn't delegated (e.g. `cpuset` is often not delegated inside a systemd user scope).
#[allow(clippy::too_many_arguments)] // one cgroup knob per parameter — grouping them would only hide it
pub fn apply_limits(
    tag: &str,
    memory_max: Option<u64>,
    memory_swap_max: Option<u64>,
    cpuset: Option<&str>,
    cpus: Option<f64>,
    pids_max: Option<u64>,
    io_max: &[String],
    io_weight: Option<u64>,
) -> Option<PathBuf> {
    // cgroup v2 presents a unified hierarchy with this file at the root.
    if !PathBuf::from("/sys/fs/cgroup/cgroup.controllers").exists() {
        return None;
    }
    // The current cgroup path is the tail of the single `0::<path>` line in /proc/self/cgroup.
    let cur = fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = cur.trim().rsplit("::").next()?.trim_start_matches('/');
    let parent = PathBuf::from("/sys/fs/cgroup").join(rel);
    let child = parent.join(format!("kern-box-{tag}-{}", std::process::id()));

    // Make the controllers available to children. cgroup-v2 accepts several tokens in one write, so
    // try them all at once (1 syscall). Only if that fails do we fall back to enabling them one at a
    // time — so an unavailable controller (e.g. no `cpu` on some Android-derived kernels) still can't
    // block the others. (Controllers may already be on, or be denied by the no-internal-process rule
    // when the parent has members — all best-effort either way.)
    let subtree = parent.join("cgroup.subtree_control");
    if fs::write(&subtree, "+memory +pids +cpu +cpuset +io").is_err() {
        for ctrl in ["+memory", "+pids", "+cpu", "+cpuset", "+io"] {
            let _ = fs::write(&subtree, ctrl);
        }
    }
    fs::create_dir(&child).ok()?;

    // Set the memory + PID caps. If BOTH fail the controllers aren't delegated here — do NOT leave a
    // useless cgroup behind and do NOT pretend the workload is capped. Clean up and bail, so the
    // caller reports "no cap" honestly rather than a false sense of safety. (CPU never gates this.)
    let mem_bytes = memory_max.unwrap_or(DEFAULT_MEMORY_MAX);
    let mem_ok = fs::write(child.join("memory.max"), mem_bytes.to_string()).is_ok();
    // `--pids-limit N` sets `pids.max` (fork-bomb containment); default otherwise.
    let pids_ok = match pids_max {
        Some(n) => fs::write(child.join("pids.max"), n.to_string()).is_ok(),
        None => fs::write(child.join("pids.max"), DEFAULT_PIDS_MAX).is_ok(),
    };
    // `memory.swap.max` — the v2 swap allowance (separate from memory.max, NOT a combined total).
    // Default `0` keeps `memory.max` a hard total (overflow is OOM-killed, not swapped); a
    // `--memory-swap-max N` lets the box swap up to N.
    let _ = fs::write(
        child.join("memory.swap.max"),
        memory_swap_max.map_or_else(|| "0".to_string(), |b| b.to_string()),
    );
    if !pids_ok && !mem_ok {
        let _ = fs::remove_dir(&child);
        return None;
    }
    // (A "not enforced" warning for memory/CPU comes LATER — after all writes — and is based on the
    // EFFECTIVE limit up the cgroup tree, not this single inner write, since the outer systemd scope
    // may be the real enforcer. See `capped_in_tree` below.)

    // Optional CPU pinning (`--cpuset-cpus`, e.g. "0-3"). Best-effort: the `cpuset` controller is
    // frequently not delegated inside a systemd user scope, so a write failure is ignored. The CLI
    // has already validated the list is `[0-9,-]` only, so it can't inject anything into the file.
    if let Some(set) = cpuset {
        // Best-effort: the `cpuset` controller is frequently not delegated in a rootless user scope,
        // but the CLI also pins via `sched_setaffinity` (the real fallback), so a failure here is NOT
        // "unenforced" — no warning, unlike memory/cpu which have no affinity equivalent.
        let _ = fs::write(child.join("cpuset.cpus"), set);
    }

    // Optional CPU cap (`--cpus`). cgroup v2 `cpu.max` = "<quota_us> <period_us>"; cores =
    // quota/period. Clamp to the host CPU count. Best-effort: a write failure (no CPU controller,
    // e.g. some Android kernels) is ignored — isolation still holds, only the CPU cap is skipped.
    if let Some(c) = cpus {
        // `c` is already clamped to the host CPU count by the CLI (the single place that can warn);
        // an over-large quota would be harmless anyway (the kernel never grants more than the
        // physical cores), so we don't re-read /proc/cpuinfo on this hot path.
        let quota = (c * CPU_PERIOD_US as f64).round().max(1.0) as u64;
        // Best-effort like the rest: `--cpus` is primarily enforced by the outer systemd scope, so a
        // failure to write this inner `cpu.max` is not proof the workload is uncapped (see above).
        let _ = fs::write(child.join("cpu.max"), format!("{quota} {CPU_PERIOD_US}"));
    }

    // Optional per-device I/O limits (`vdisk:` `--iops`/`--bandwidth` → `io.max`) and `io.weight`
    // (`--io-weight`). One `io.max` line per device, `MAJ:MIN riops=… wbps=…`. Best-effort: the `io`
    // controller is usually NOT delegated to a rootless user scope, so a write failure is expected
    // and simply skips the limit (the vdisk still works, uncapped) — never a hard error. The lines
    // are built by the CLI from a stat'd loop device, so they can't inject arbitrary content.
    let io_requested = !io_max.is_empty() || io_weight.is_some();
    let mut io_applied = false;
    for line in io_max {
        io_applied |= fs::write(child.join("io.max"), line).is_ok();
    }
    if let Some(w) = io_weight {
        // Clamped by the CLI (1..=10000); re-clamped here as defence in depth.
        io_applied |= fs::write(child.join("io.weight"), w.clamp(1, 10_000).to_string()).is_ok();
    }
    // The user explicitly asked for an I/O limit — if the `io` controller isn't delegated to this
    // box's cgroup, say so rather than silently ignore it (feedback-first). Everything else the box
    // does still works; only the I/O cap is skipped.
    if io_requested && !io_applied {
        eprintln!(
            "kern: I/O limits (--iops/--bandwidth/--io-weight) not enforced — the cgroup `io` \
             controller isn't delegated to this box's cgroup"
        );
    }

    // Honest feedback on the two-layer model: memory/CPU are capped EITHER by this inner cgroup OR by
    // the outer systemd `--scope`. A failed inner write is fine as long as SOME ancestor caps it — so
    // check the EFFECTIVE limit up the tree, and only warn when NOTHING in the chain enforces a knob
    // the user explicitly asked for (e.g. a rootless host with the memory controller un-delegated, the
    // Pi-5 case). This never false-positives on a host where the scope enforces it.
    if memory_max.is_some() && !capped_in_tree(&child, "memory.max") {
        eprintln!(
            "kern: --memory not enforced — no cgroup memory cap took effect (the `memory` controller \
             isn't delegated to this rootless scope); the box can exceed the limit"
        );
    }
    if cpus.is_some() && !capped_in_tree(&child, "cpu.max") {
        eprintln!(
            "kern: --cpus not enforced — no cgroup cpu cap took effect (the `cpu` controller isn't \
             delegated to this rootless scope)"
        );
    }

    // Join the cgroup — binds the limits to us (and our future forked workload).
    if fs::write(child.join("cgroup.procs"), std::process::id().to_string()).is_err() {
        let _ = fs::remove_dir(&child);
        return None;
    }
    Some(child)
}

/// Is a `memory.max`/`cpu.max`-style cap actually in force for the box — at THIS cgroup OR any
/// ancestor up to the cgroup root? Accounts for the two-layer model (inner cgroup + outer systemd
/// scope): the inner write may fail while an ancestor still enforces the cap. The "no cap" sentinel
/// is `max` (`memory.max`) or `max <period>` (`cpu.max`), so any value not starting with `max` at any
/// level means a real limit is in effect.
fn capped_in_tree(child: &std::path::Path, file: &str) -> bool {
    let root = std::path::Path::new("/sys/fs/cgroup");
    let mut dir = child.to_path_buf();
    loop {
        if let Ok(v) = fs::read_to_string(dir.join(file)) {
            let v = v.trim();
            if !v.is_empty() && !v.starts_with("max") {
                return true;
            }
        }
        if dir.as_path() == root {
            break;
        }
        match dir.parent() {
            Some(p) if p.starts_with(root) => dir = p.to_path_buf(),
            _ => break,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capped_in_tree_reads_the_max_sentinel() {
        // A temp dir isn't under /sys/fs/cgroup, so the walk checks just this leaf — enough to lock
        // in the sentinel parsing (the bit that decides "enforced or not" and gates the warning).
        let d = std::env::temp_dir().join(format!("kern-cg-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let set = |f: &str, v: &str| std::fs::write(d.join(f), v).unwrap();

        set("memory.max", "max");
        assert!(!capped_in_tree(&d, "memory.max"), "`max` = no cap");
        set("memory.max", "67108864");
        assert!(capped_in_tree(&d, "memory.max"), "a byte count = capped");
        set("cpu.max", "max 100000");
        assert!(!capped_in_tree(&d, "cpu.max"), "`max <period>` = no cap");
        set("cpu.max", "50000 100000");
        assert!(capped_in_tree(&d, "cpu.max"), "a quota = capped");
        assert!(
            !capped_in_tree(&d, "does-not-exist"),
            "absent file = not capped"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
