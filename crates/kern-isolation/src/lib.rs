//! Isolation primitives (namespaces, mounts) for kern.
//!
//! The mount sequence is expressed against the [`MountOps`] trait - one ordered, fallible op
//! log. A [`Recorder`] captures the calls without privileges (characterization / `--plan`); the
//! real [`RealMounts`] performs the syscalls. Both flow through the SAME [`Rootfs`] typestate,
//! so the security-critical ordering (pivot before read-only) is enforced at compile time for
//! the real path too - not just the recorded one.
//!
//! The headline guarantee: [`Rootfs::into_readonly`] exists only on `Rootfs<OldRootReady>`, so
//! remounting the root read-only before pivoting into it is **unrepresentable** - it does not
//! compile.

use std::marker::PhantomData;

mod cgroup;
mod landlock;

/// The kernel's Landlock ABI version, or `None` when Landlock is unavailable (not compiled in, or
/// disabled at boot). Exposed so `kern doctor` can SAY SO up front: `--landlock-rw` degrades to
/// namespaces + seccomp with a warning at box start, which is honest but arrives late. A preflight
/// that answers "will boxes run here?" should also answer "and will the confinement I plan to rely
/// on exist?", especially on the ARM boards, where measured on three of them (Raspberry Pi OS,
/// Jetson tegra, Arduino UNO Q) NONE ships Landlock.
pub fn landlock_abi() -> Option<i32> {
    landlock::abi_version()
}

/// Confine the CALLING process's writes to `rw` (plus the minimum character devices a program needs to
/// open for writing), leaving the whole filesystem readable and executable. Survives `execve`, so the
/// workload `kern run` is about to exec inherits it and cannot lift it.
///
/// This is the `kern run` counterpart of the box's `--landlock-rw`: same kernel mechanism, but with the
/// auto-grant set that is correct when there is NO mount namespace and every path is the host's own.
/// The box path is not reachable from outside this crate and stays where it is, applied on box PID 1.
///
/// Returns `Ok(true)` when the ruleset is enforced, `Ok(false)` when this kernel has no Landlock, and
/// `Err` when a ruleset that WAS available could not be built or enforced. The caller must treat all
/// three distinctly: only `Ok(true)` means the operator got what they asked for.
///
/// Side effect the caller must document to the operator: this sets `PR_SET_NO_NEW_PRIVS`, which
/// Landlock requires. A workload run under it cannot gain privileges through a setuid binary, so
/// `sudo` and friends stop working inside the confined command.
pub fn landlock_confine_writes(rw: &[String]) -> Result<bool, Error> {
    landlock::apply_rw_allowlist_host(rw)
}
mod outcome;
mod ports;
mod real;
mod sandbox;
mod seccomp;
/// GENERATED per-arch allowlist syscall numbers (see `scripts/gen-seccomp-allowlist.py`), consumed
/// by `seccomp::build_allowlist_filter` under the opt-in `KERN_SECCOMP=allowlist`.
mod seccomp_allow;
mod ssh;
pub use cgroup::apply_limits as apply_cgroup_limits;
/// Resolve a box's exact direct-path cgroup dir from `/proc/<pid1>/cgroup` - the immediate, targeted
/// counterpart to [`gc_orphan_box_cgroups`]: `kern stop`/`compose down` capture the dir while the box is
/// alive and `rmdir` it after the SIGKILL, so the empty dir is gone at once instead of waiting for `gc`
/// or the next box start. See [`cgroup::box_cgroup_dir`].
pub use cgroup::box_cgroup_dir;
pub use cgroup::env_flag;
/// Reap orphaned `kern-box-*` cgroup dirs under kern.slice (the direct-cap path leaves an empty one
/// on a box SIGKILL). Called by `kern gc`. See [`cgroup::gc_orphan_box_cgroups`].
pub use cgroup::gc_orphan_box_cgroups;
/// Whether a `--memory` cap can actually be ENFORCED here (the `memory` controller is available in
/// the cgroup tree). False on kernels that don't delegate it - a stock Raspberry Pi OS and the
/// default WSL2 kernel - where a `memory.max` write is accepted but never bites. Used only to warn.
pub use cgroup::memory_cap_enforceable;
/// Move kern's own processes out of the box's scope root, so the box's whole-box OOM kill takes the
/// workload and not the supervisor that records its exit code. Call once, at process entry, before any
/// fork. See [`cgroup::prepare_delegated_scope`].
pub use cgroup::prepare_delegated_scope;
/// Will this systemd accept `OOMPolicy=` on a transient scope? Probed once per boot, because a manager
/// that refuses it fails the whole `systemd-run`. See [`cgroup::scope_accepts_oom_policy`].
pub use cgroup::scope_accepts_oom_policy;
/// Apply a fleet-wide `memory.max`/`pids.max` budget to kern's shared `kern.slice`, bounding the SUM of
/// all running boxes at the kernel. The real-enforcement backstop to the cooperative box counter. See
/// [`cgroup::set_fleet_caps`].
pub use cgroup::set_fleet_caps;
/// The systemd manager kern drives for its scope/slice: `--system` as real root, else `--user`. See
/// [`cgroup::systemd_scope_mode`].
pub use cgroup::systemd_scope_mode;
/// Is the systemd manager kern would use present? (root → the system manager `/run/systemd/system`,
/// else a per-user `systemd` dir under `$XDG_RUNTIME_DIR`). See [`cgroup::user_systemd_present`].
pub use cgroup::user_systemd_present;
pub use cgroup::warn_unenforced_caps;
/// Bytes the per-box scope gets ABOVE the box's `--memory`, to hold kern's supervisor without eating
/// into the workload's budget. See [`cgroup::SCOPE_SUPERVISOR_HEADROOM`].
pub use cgroup::SCOPE_SUPERVISOR_HEADROOM;
/// The direct-cap-path decision (skip the per-box scope iff kern's delegated `kern.slice` is usable;
/// records itself in an in-process marker) and the scrub of an INHERITED marker (a nested kern must
/// not be poisoned by its parent's decision). The fail-closed consumers (`took_direct_cap_path`,
/// `env_claims_enforcer_but_none_real`) stay crate-internal - only `real.rs` reads them.
pub use cgroup::{choose_direct_cap_path, choose_direct_cap_path_given, scrub_direct_marker};
pub use cgroup::{fleet_status, FleetStatus};
pub use cgroup::{memory_cap_signal, record_memory_cap_signal};
/// The write-tested state of `--memory` enforcement on this host (`Enforced` / `PresentNotDelegated`
/// / `Absent` / `Unknown`), by creating a throwaway child cgroup and checking a `memory.max` write
/// binds. Stronger than [`cgroup::memory_cap_enforceable`], which reads controller PRESENCE and
/// cannot tell "delegated" from "listed but inert". See [`cgroup::memory_cap_state`].
pub use cgroup::{memory_cap_state, MemoryCapState};
pub use outcome::{Outcome, OutputView, ResourceSource};
pub use ports::{preflight as preflight_ports, PortMap};
/// While kern waits for a box, treat a fatal signal as "end the BOX", not "end kern": forward it to
/// the box and keep reaping, so kern exits with (and records) the box's own status. See
/// [`real::forward_signals_to_the_box`].
pub use real::forward_signals_to_the_box;
/// Take the first fatal signal without dying, so this process lives to read the box's status and
/// record it. For every kern process behind a supervisor. See [`real::keep_waiting_through_signals`].
pub use real::keep_waiting_through_signals;
/// Apply cgroup v2 memory/PID/CPU caps to the current process (and whatever it forks/execs next).
/// Used by `kern box` (inside the sandbox) and `kern run` (caps without a sandbox).
/// The per-phase timer, exported because the PARENT was not instrumented at all: `KERN_TIMING`
/// covered only the child's setup, so the time spent before the fork was invisible, and no amount
/// of looking would have shown it.
pub use real::PhaseTimer;
pub use real::{
    default_dropped_cap_mask, exec_in_box, run_in_sandbox, run_in_sandbox_with, run_pod_holder,
    set_cpu_affinity, shed_inherited_fds, sub_range, trusted_helper, username, CapSpec,
    OverlayDirs, RealMounts, SandboxSpec, UidRange, VdiskMount, Volume,
};
/// The embeddable fluent SDK: `Sandbox::builder()…build()?.run(cmd, args)?`. See [`sandbox`].
pub use sandbox::{Sandbox, SandboxBuilder, SandboxError, SandboxResult, SeccompMode};
pub use seccomp::{denied_syscall_count, SeccompFilter};
pub use ssh::SshSetup;

/// `MS_BIND` from `<sys/mount.h>` - bind-mount an existing tree at a new location.
pub(crate) const MS_BIND: u64 = 0x1000;

/// An isolation error: a failed syscall (with context) or an unsupported environment.
#[derive(Debug)]
pub enum Error {
    /// Syscall `op` failed with the given OS error.
    Syscall(&'static str, std::io::Error),
    /// The environment cannot host a sandbox (e.g. unprivileged user namespaces disabled).
    Unsupported(&'static str),
    /// A spec value the kernel refused, with a message naming the exact field and reason (e.g. which
    /// `--sysctl` key and why). Owned because the detail is what makes it actionable; only built on
    /// the failure path, so it costs nothing when the box starts normally.
    Spec(String),
}

impl Error {
    /// Build a `Syscall` error from the current `errno` for `op`.
    pub(crate) fn last(op: &'static str) -> Self {
        Error::Syscall(op, std::io::Error::last_os_error())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Syscall(op, e) => write!(f, "{op} failed: {e}"),
            Error::Unsupported(why) => write!(f, "{why}"),
            Error::Spec(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for Error {}

/// The mount operations a sandbox setup performs, in order. One fallible op log: a `Recorder`
/// records it without privileges; `RealMounts` performs it. Same trait, two impls.
pub trait MountOps {
    fn mount(&mut self, src: &str, dst: &str, fstype: &str, flags: u64) -> Result<(), Error>;
    fn pivot(&mut self, new_root: &str, old_root: &str) -> Result<(), Error>;
    fn remount_ro(&mut self, target: &str) -> Result<(), Error>;
}

/// A `MountOps` that records every call instead of performing it - the characterization seam,
/// also used by `kern box --plan`.
#[derive(Default)]
pub struct Recorder {
    pub calls: Vec<String>,
}

impl MountOps for Recorder {
    fn mount(&mut self, src: &str, dst: &str, fstype: &str, flags: u64) -> Result<(), Error> {
        self.calls
            .push(format!("mount({src},{dst},{fstype},{flags:#x})"));
        Ok(())
    }
    fn pivot(&mut self, new_root: &str, old_root: &str) -> Result<(), Error> {
        self.calls.push(format!("pivot({new_root},{old_root})"));
        Ok(())
    }
    fn remount_ro(&mut self, target: &str) -> Result<(), Error> {
        self.calls.push(format!("remount_ro({target})"));
        Ok(())
    }
}

/// How a sandbox's root filesystem is provided. A closed set → an exhaustive `enum`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountMode {
    /// Copy-on-write overlay over a read-only lower - the default for OCI images.
    Overlay,
    /// Bind-mount an existing host directory as the root.
    Bind,
    /// A fresh, empty tmpfs root.
    Tmpfs,
}

impl MountMode {
    /// `(source, fstype, flags)` for the initial root mount.
    fn spec(self) -> (&'static str, &'static str, u64) {
        match self {
            MountMode::Overlay => ("overlay", "overlay", 0),
            MountMode::Bind => ("bind", "bind", MS_BIND),
            MountMode::Tmpfs => ("tmpfs", "tmpfs", 0),
        }
    }
}

// --- Mount-ordering typestate -------------------------------------------------------------
// States are zero-size markers carried in `PhantomData`, making the *order* part of the type.

/// The root is mounted but not yet pivoted into.
pub struct Mounted;
/// `.old_root` has been created and we have pivoted into the new root.
pub struct OldRootReady;
/// The new root has been remounted read-only - terminal state.
pub struct ReadOnly;

/// A sandbox root filesystem tracked through its setup states.
///
/// The setup order - mount → pivot → remount read-only - is encoded in the type: each step consumes
/// the previous state and returns the next, and [`into_readonly`](Rootfs::into_readonly) is
/// implemented only for `Rootfs<OldRootReady>`. Remounting the root read-only *before* the pivot - a
/// classic sandbox-escape shape - is therefore a compile error, not a test you hope you wrote:
///
/// ```compile_fail
/// use kern_isolation::{MountMode, Recorder, Rootfs};
/// let mut ops = Recorder::default();
/// // `into_readonly` doesn't exist on `Rootfs<Mounted>` (before the pivot) - this fails to compile.
/// let _ = Rootfs::mount(&mut ops, MountMode::Bind, "/r")
///     .unwrap()
///     .into_readonly(&mut ops);
/// ```
///
/// The legal order compiles and runs:
///
/// ```
/// use kern_isolation::{MountMode, Recorder, Rootfs};
/// let mut ops = Recorder::default();
/// let _ro = Rootfs::mount(&mut ops, MountMode::Bind, "/r")
///     .unwrap()
///     .create_old_root(&mut ops)
///     .unwrap()
///     .into_readonly(&mut ops)
///     .unwrap();
/// ```
pub struct Rootfs<S> {
    root: String,
    _state: PhantomData<S>,
}

impl<S> Rootfs<S> {
    /// The new-root path this `Rootfs` is anchored at.
    pub fn root(&self) -> &str {
        &self.root
    }
}

impl Rootfs<Mounted> {
    /// Step 1 - mount the new root for `root` using `mode`.
    pub fn mount<M: MountOps>(ops: &mut M, mode: MountMode, root: &str) -> Result<Self, Error> {
        let (src, fstype, flags) = mode.spec();
        ops.mount(src, root, fstype, flags)?;
        Ok(Rootfs {
            root: root.to_string(),
            _state: PhantomData,
        })
    }

    /// Wrap a root that is ALREADY a mount point (e.g. an overlayfs set up directly), so the
    /// pivot / read-only steps still flow through the ordering typestate.
    pub fn premounted(root: &str) -> Self {
        Rootfs {
            root: root.to_string(),
            _state: PhantomData,
        }
    }

    /// Step 2 - create `.old_root` inside the new root and `pivot_root` into it. Consumes the
    /// `Mounted` state, so this must precede any read-only remount.
    pub fn create_old_root<M: MountOps>(self, ops: &mut M) -> Result<Rootfs<OldRootReady>, Error> {
        let old = format!("{}/.old_root", self.root);
        ops.pivot(&self.root, &old)?;
        Ok(Rootfs {
            root: self.root,
            _state: PhantomData,
        })
    }
}

impl Rootfs<OldRootReady> {
    /// Step 3 - remount the root read-only. Reachable ONLY from `OldRootReady`, so "read-only
    /// before pivot" cannot be written.
    pub fn into_readonly<M: MountOps>(self, ops: &mut M) -> Result<Rootfs<ReadOnly>, Error> {
        ops.remount_ro("/")?;
        Ok(Rootfs {
            root: self.root,
            _state: PhantomData,
        })
    }
}

/// The overlay → pivot → read-only-root sequence, driven through the typestate so the ordering
/// is compile-time enforced. The recorded ops are byte-identical to the 0.1 golden.
pub fn overlay_ro_sequence<M: MountOps>(ops: &mut M, root: &str) -> Result<(), Error> {
    Rootfs::mount(ops, MountMode::Overlay, root)?
        .create_old_root(ops)?
        .into_readonly(ops)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Characterization: the recorded ordered call list must match the 0.1 golden sequence,
    /// proving the typestate refactor did NOT change observable behaviour.
    #[test]
    fn overlay_ro_sequence_is_stable() {
        let mut rec = Recorder::default();
        overlay_ro_sequence(&mut rec, "/tmp/root").unwrap();
        assert_eq!(
            rec.calls,
            vec![
                "mount(overlay,/tmp/root,overlay,0x0)".to_string(),
                "pivot(/tmp/root,/tmp/root/.old_root)".to_string(),
                "remount_ro(/)".to_string(),
            ]
        );
    }

    /// Each `MountMode` produces the expected initial mount call.
    #[test]
    fn mount_mode_specs_are_correct() {
        for (mode, expected) in [
            (MountMode::Overlay, "mount(overlay,/r,overlay,0x0)"),
            (MountMode::Bind, "mount(bind,/r,bind,0x1000)"),
            (MountMode::Tmpfs, "mount(tmpfs,/r,tmpfs,0x0)"),
        ] {
            let mut rec = Recorder::default();
            let _ = Rootfs::mount(&mut rec, mode, "/r").unwrap();
            assert_eq!(rec.calls, vec![expected.to_string()], "mode {mode:?}");
        }
    }

    /// The full typestate chain is expressible and ends in `ReadOnly`, anchored at `root`.
    #[test]
    fn typestate_chain_completes() {
        let mut rec = Recorder::default();
        let ro: Rootfs<ReadOnly> = Rootfs::mount(&mut rec, MountMode::Bind, "/data")
            .unwrap()
            .create_old_root(&mut rec)
            .unwrap()
            .into_readonly(&mut rec)
            .unwrap();
        assert_eq!(ro.root(), "/data");
        assert_eq!(rec.calls.len(), 3);
    }

    // COMPILE-TIME GUARANTEE (documented; not unit-testable without trybuild): `into_readonly`
    // exists only on `impl Rootfs<OldRootReady>`, so calling it on `Rootfs<Mounted>` (i.e.
    // remounting read-only before the pivot) does NOT compile.
}
