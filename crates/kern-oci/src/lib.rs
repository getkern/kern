//! OCI image handling for kern: pull, layer extraction, whiteout application, and Hub search.

mod json;
mod net;
mod pull;
mod search;
pub use pull::{pull, ImageConfig, OciError};
pub use search::{search, SearchResult};

use std::path::PathBuf;

/// Returns `true` if every component of `dir` under `rootfs_dir` is a REAL directory (none is
/// a symlink).
///
/// A layer can plant `dir -> /host/path`; without this guard a merge or whiteout under `dir`
/// would resolve THROUGH the symlink and touch a host file (rootfs escape). A non-existent
/// component is safe (nothing to traverse).
///
/// This lexical (check-then-use) guard is sound because there is no concurrent writer to race
/// it: extraction is single-threaded (so an image's own layers can't race each other), and the
/// caller's cache/scratch dirs are created mode 0700 owned by the user, so no *other* local user
/// can swap a component for a symlink between the check and the operation.
pub fn whiteout_dir_symlink_free(rootfs_dir: &str, dir: &str) -> bool {
    if dir.is_empty() {
        return true;
    }
    let mut cur = PathBuf::from(rootfs_dir);
    for comp in dir.split('/').filter(|c| !c.is_empty()) {
        cur.push(comp);
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => return false,
            Ok(_) => {}
            Err(_) => return true, // doesn't exist yet — nothing to traverse/delete
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_dir_is_safe() {
        let base = format!("/tmp/.kern-oci-plain-{}", std::process::id());
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(format!("{base}/a/b")).unwrap();
        assert!(whiteout_dir_symlink_free(&base, "a/b"));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// SECURITY regression: a whiteout under a symlinked parent must NOT be followed.
    /// Fixture is synthetic, minimal, self-contained — no private paths, no real exploit
    /// payload (the audit gate from the launch standard).
    #[test]
    fn refuses_to_traverse_a_symlinked_parent() {
        let base = format!("/tmp/.kern-oci-sym-{}", std::process::id());
        let _ = std::fs::remove_dir_all(&base);
        let victim = format!("{base}/victim");
        let rootfs = format!("{base}/rootfs");
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(format!("{victim}/secret"), b"HOST-DO-NOT-DELETE").unwrap();
        std::fs::create_dir_all(&rootfs).unwrap();
        std::os::unix::fs::symlink(&victim, format!("{rootfs}/pwned")).unwrap();

        // The guard must report "unsafe" for a whiteout whose dir crosses the planted symlink.
        assert!(!whiteout_dir_symlink_free(&rootfs, "pwned"));
        assert!(
            std::path::Path::new(&format!("{victim}/secret")).exists(),
            "guard is the precondition for not deleting through the symlink"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
