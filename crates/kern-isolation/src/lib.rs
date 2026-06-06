//! Isolation primitives (namespaces, cgroups, mounts) for kern.
//!
//! 0.2 lands the **mount-ordering typestate** and the `MountMode` enum on top of the 0.1
//! characterization seam. The headline guarantee: the read-only remount of the new root can
//! only be reached *after* the pivot (`create_old_root`), because [`Rootfs::into_readonly`]
//! exists solely on `Rootfs<OldRootReady>`. "Remount read-only before pivoting in" — a classic
//! sandbox-escape footgun — is therefore **unrepresentable**: it does not compile.
//!
//! The mount/pivot sequence is still expressed against the [`MountOps`] trait. A [`Recorder`]
//! captures the exact ordered call list so a test asserts it is byte-identical before and after
//! a refactor — deterministic, privilege-free, normal CI. This *refactor-safety* net does NOT
//! replace the real-syscall correctness tests (those actually mount/pivot and assert
//! escape-blocked); the real `MountOps` impl + fallible `Error` type land with those (0.3).

use std::marker::PhantomData;

/// `MS_BIND` from `<sys/mount.h>` — bind-mount an existing tree at a new location.
const MS_BIND: u64 = 0x1000;

/// The mount operations a sandbox setup performs, in order. Abstracted so they can be recorded
/// (characterization) without privileges, and so the real impl is the single libc boundary.
pub trait MountOps {
    fn mount(&mut self, src: &str, dst: &str, fstype: &str, flags: u64);
    fn pivot(&mut self, new_root: &str, old_root: &str);
    fn remount_ro(&mut self, target: &str);
}

/// A `MountOps` that records every call instead of performing it — the characterization seam.
#[derive(Default)]
pub struct Recorder {
    pub calls: Vec<String>,
}

impl MountOps for Recorder {
    fn mount(&mut self, src: &str, dst: &str, fstype: &str, flags: u64) {
        self.calls
            .push(format!("mount({src},{dst},{fstype},{flags:#x})"));
    }
    fn pivot(&mut self, new_root: &str, old_root: &str) {
        self.calls.push(format!("pivot({new_root},{old_root})"));
    }
    fn remount_ro(&mut self, target: &str) {
        self.calls.push(format!("remount_ro({target})"));
    }
}

/// How a sandbox's root filesystem is provided. A closed set → an exhaustive `enum`, not a
/// trait object (the variants are known and stable).
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
// States are zero-size markers carried in `PhantomData`. They make the *order* of the mount
// sequence part of the type, so an out-of-order refactor fails at compile time rather than
// shipping a sandbox-escape bug.

/// The root is mounted but not yet pivoted into.
pub struct Mounted;
/// `.old_root` has been created and we have pivoted into the new root.
pub struct OldRootReady;
/// The new root has been remounted read-only — terminal state.
pub struct ReadOnly;

/// A sandbox root filesystem tracked through its setup states. See [`MountMode`] and the
/// module docs for the ordering guarantee.
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
    pub fn mount<M: MountOps>(ops: &mut M, mode: MountMode, root: &str) -> Self {
        let (src, fstype, flags) = mode.spec();
        ops.mount(src, root, fstype, flags);
        Rootfs {
            root: root.to_string(),
            _state: PhantomData,
        }
    }

    /// Step 2 — create `.old_root` inside the new root and `pivot_root` into it. Consumes the
    /// `Mounted` state, so this must precede any read-only remount.
    pub fn create_old_root<M: MountOps>(self, ops: &mut M) -> Rootfs<OldRootReady> {
        let old = format!("{}/.old_root", self.root);
        ops.pivot(&self.root, &old);
        Rootfs {
            root: self.root,
            _state: PhantomData,
        }
    }
}

impl Rootfs<OldRootReady> {
    /// Step 3 — remount the root read-only. Reachable ONLY from `OldRootReady`, so "read-only
    /// before pivot" cannot be written.
    pub fn into_readonly<M: MountOps>(self, ops: &mut M) -> Rootfs<ReadOnly> {
        ops.remount_ro("/");
        Rootfs {
            root: self.root,
            _state: PhantomData,
        }
    }
}

/// The overlay → pivot → read-only-root sequence, driven through the typestate so the ordering
/// is compile-time enforced. The recorded ops are byte-identical to the 0.1 golden.
pub fn overlay_ro_sequence<M: MountOps>(ops: &mut M, root: &str) {
    Rootfs::mount(ops, MountMode::Overlay, root)
        .create_old_root(ops)
        .into_readonly(ops);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Characterization: the recorded ordered call list must match the 0.1 golden sequence,
    /// proving the 0.2 typestate refactor did NOT change observable behaviour.
    #[test]
    fn overlay_ro_sequence_is_stable() {
        let mut rec = Recorder::default();
        overlay_ro_sequence(&mut rec, "/tmp/root");
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
            let _ = Rootfs::mount(&mut rec, mode, "/r");
            assert_eq!(rec.calls, vec![expected.to_string()], "mode {mode:?}");
        }
    }

    /// The full typestate chain is expressible and ends in `ReadOnly`, anchored at `root`.
    #[test]
    fn typestate_chain_completes() {
        let mut rec = Recorder::default();
        let ro: Rootfs<ReadOnly> = Rootfs::mount(&mut rec, MountMode::Bind, "/data")
            .create_old_root(&mut rec)
            .into_readonly(&mut rec);
        assert_eq!(ro.root(), "/data");
        assert_eq!(rec.calls.len(), 3);
    }

    // COMPILE-TIME GUARANTEE (cannot be unit-tested without a trybuild dependency, documented
    // here instead): `Rootfs::into_readonly` exists only on `impl Rootfs<OldRootReady>`, so
    //
    //     Rootfs::mount(&mut rec, MountMode::Overlay, "/r").into_readonly(&mut rec);
    //
    // does NOT compile — `into_readonly` is not a method on `Rootfs<Mounted>`. The read-only
    // remount is unreachable until `create_old_root` has produced `Rootfs<OldRootReady>`.
}
