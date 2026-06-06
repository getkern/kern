//! Isolation primitives (namespaces, cgroups, mounts) for kern.
//!
//! 0.1 scaffold: this seeds the **characterization-harness seam** that makes the upcoming
//! sandbox refactor (step sequence + mount-ordering typestate, roadmap 0.2) safe for a solo
//! maintainer on an escape-class path.
//!
//! The mount/pivot sequence is expressed against the [`MountOps`] trait. The real
//! implementation calls libc; a [`Recorder`] implementation captures the exact ordered call
//! list so a test can assert it is byte-identical before and after a refactor — deterministic,
//! privilege-free, runs in normal CI. This is the *refactor-safety* net; it does NOT replace
//! the real-syscall correctness tests (those actually mount/pivot and assert escape-blocked).

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

/// Example sandbox sub-sequence written against the seam (scaffold). The real steps land per
/// the roadmap; the shape is what matters: ordered ops a `Recorder` can capture.
pub fn overlay_ro_sequence<M: MountOps>(ops: &mut M, root: &str) {
    ops.mount("overlay", root, "overlay", 0);
    ops.pivot(root, &format!("{root}/.old_root"));
    ops.remount_ro("/");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Characterization: the recorded ordered call list must match the golden sequence.
    /// After the 0.2 refactor, this asserts the sequence is byte-identical (unchanged).
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
}
