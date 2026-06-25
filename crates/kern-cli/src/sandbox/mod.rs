//! Sandbox setup.
//!
//! [`SandboxCtx`] holds the resolved configuration; [`SandboxCtx::build_root`] runs the ordered
//! mount steps against any [`MountOps`] — the real libc impl (`kern box --rootfs`) and the
//! `Recorder` (`kern box --plan`) share the exact same typestate-driven sequence.

use kern_common::BoxName;
use kern_isolation::{Error as IsoError, MountMode, MountOps, Recorder, Rootfs};

/// Resolved configuration for one sandbox.
pub(crate) struct SandboxCtx {
    /// Validated box name (no path separators / traversal — see [`BoxName`]).
    pub name: BoxName,
    /// New-root path the box's filesystem is assembled at.
    pub root: String,
    /// How the root filesystem is provided.
    pub mode: MountMode,
}

impl SandboxCtx {
    /// A context for box `name`, with the default overlay root layout. The root path is
    /// derived, not yet created — `--plan` only records the sequence.
    pub fn new(name: BoxName) -> Self {
        let root = format!("/var/lib/kern/{}/rootfs", name.as_str());
        SandboxCtx {
            name,
            root,
            mode: MountMode::Overlay,
        }
    }

    /// Run the ordered mount steps against `ops`. The ordering (pivot before read-only) is
    /// enforced by the `Rootfs<State>` typestate, so an out-of-order edit is a COMPILE error,
    /// not a sandbox-escape bug.
    pub fn build_root<M: MountOps>(&self, ops: &mut M) -> Result<(), IsoError> {
        Rootfs::mount(ops, self.mode, &self.root)?
            .create_old_root(ops)?
            .into_readonly(ops)?;
        Ok(())
    }

    /// The isolation plan as an ordered, human-readable list — privilege-free, used by
    /// `kern box <name> --plan` to show exactly what the sandbox setup would do.
    pub fn plan(&self) -> Vec<String> {
        let mut rec = Recorder::default();
        // The `Recorder` only appends to a vec; it cannot fail.
        self.build_root(&mut rec).expect("Recorder is infallible");
        rec.calls
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_is_ordered_mount_pivot_readonly() {
        let ctx = SandboxCtx::new(BoxName::parse("web").unwrap());
        let plan = ctx.plan();
        assert_eq!(plan.len(), 3);
        assert!(plan[0].starts_with("mount(overlay,/var/lib/kern/web/rootfs"));
        assert!(plan[1].starts_with("pivot("));
        assert_eq!(plan[2], "remount_ro(/)");
    }
}
