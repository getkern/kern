//! Isolation primitives (namespaces, mounts) for kern.
//!
//! The mount sequence is expressed against the [`MountOps`] trait — one ordered, fallible op
//! log. A [`Recorder`] captures the calls without privileges (characterization / `--plan`); the
//! real [`RealMounts`] performs the syscalls. Both flow through the SAME [`Rootfs`] typestate,
//! so the security-critical ordering (pivot before read-only) is enforced at compile time for
//! the real path too — not just the recorded one.
//!
//! The headline guarantee: [`Rootfs::into_readonly`] exists only on `Rootfs<OldRootReady>`, so
//! remounting the root read-only before pivoting into it is **unrepresentable** — it does not
//! compile.

use std::marker::PhantomData;

mod cgroup;
mod ports;
mod real;
mod seccomp;
/// Apply cgroup v2 memory/PID/CPU caps to the current process (and whatever it forks/execs next).
/// Used by `kern box` (inside the sandbox) and `kern run` (caps without a sandbox).
pub use cgroup::apply_limits as apply_cgroup_limits;
pub use real::{
    exec_in_box, run_in_sandbox, run_in_sandbox_with, shed_inherited_fds, OverlayDirs, RealMounts,
    SandboxSpec, Volume,
};
pub use seccomp::denied_syscall_count;

/// `MS_BIND` from `<sys/mount.h>` — bind-mount an existing tree at a new location.
pub(crate) const MS_BIND: u64 = 0x1000;

/// An isolation error: a failed syscall (with context) or an unsupported environment.
#[derive(Debug)]
pub enum Error {
    /// Syscall `op` failed with the given OS error.
    Syscall(&'static str, std::io::Error),
    /// The environment cannot host a sandbox (e.g. unprivileged user namespaces disabled).
    Unsupported(&'static str),
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

/// A `MountOps` that records every call instead of performing it — the characterization seam,
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
    /// Copy-on-write overlay over a read-only lower — the default for OCI images.
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
/// The new root has been remounted read-only — terminal state.
pub struct ReadOnly;

/// A sandbox root filesystem tracked through its setup states.
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
    /// Step 1 — mount the new root for `root` using `mode`.
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

    /// Step 2 — create `.old_root` inside the new root and `pivot_root` into it. Consumes the
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
    /// Step 3 — remount the root read-only. Reachable ONLY from `OldRootReady`, so "read-only
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
