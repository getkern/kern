//! Sandbox setup.
//!
//! 0.1 scaffold: the real setup (user namespace, mounts, pivot_root, seccomp, exec) lands per
//! the roadmap (0.2 = the step-sequence + mount-ordering typestate refactor). It is expressed
//! against the [`kern_isolation::MountOps`] seam so the mount/pivot sequence is characterized
//! (recorded & asserted byte-identical) before and after that refactor.

#[allow(unused_imports)]
use kern_isolation::{overlay_ro_sequence, MountOps};

// Intentionally empty at 0.1 beyond the re-export above; this module is the home of the
// step-sequence runner (`steps/`) and the `MountMode` enum + `Rootfs<State>` typestate.
