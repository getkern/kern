//! `kern cp` - copy a file between the host and a running box, with **symlink-confined** resolution
//! of the in-box path.
//!
//! The box side of the path is resolved with `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`
//! against the box's root directory (`/proc/<pid1>/root`). `RESOLVE_IN_ROOT` reinterprets every
//! absolute symlink and `..` as if that directory were `/`, so a hostile image cannot plant a symlink
//! (or a `..` chain) that makes the copy read or write a **host** file outside the box - the class of
//! bug behind CVE-2019-14271 (`docker cp` following a container symlink out to the host). We never
//! exec anything inside the box, and `RESOLVE_NO_MAGICLINKS` refuses to traverse `/proc`-style magic
//! links during resolution.
//!
//! Direction is Docker-style: `kern cp <box>:<src> <hostdst>` (out) or `kern cp <hostsrc> <box>:<dst>`
//! (in), where `<box>` is a running box name. Single regular files only for now.

use crate::error::Error;
use crate::openat2::openat2_in_root;
use std::os::unix::io::RawFd;

/// Open `/proc/<pid1>/root` as an `O_PATH` dirfd - the box's root for confined resolution.
fn box_root_fd(pid1: i32) -> std::io::Result<RawFd> {
    // A decimal pid can never contain a NUL, so this cannot fail - stated as an error rather than
    // asserted, because `panic = "abort"` turns a wrong assumption here into a dead process.
    let Ok(p) = std::ffi::CString::new(format!("/proc/{pid1}/root")) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "box root path contained a NUL",
        ));
    };
    let fd = unsafe {
        libc::open(
            p.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

/// What one `kern cp` argument turned out to be.
enum Side {
    /// `<name>:<path>` naming a box that is running: its pid 1 and the in-box path.
    Boxed(i32, String),
    /// `<name>:<path>`-shaped, naming no running box. Carries the name so the error can say it.
    NoSuchBox(String),
    /// Anything else: a path on the host.
    Host,
}

/// Classify one `kern cp` argument.
///
/// Separating "is this a box reference?" from "does that box exist?" is the whole point. Both used
/// to collapse into a single `None`, so a correct spelling whose box merely was not running was
/// reported as a SYNTAX error: `kern cp f.txt nobox:/tmp/x` answered "kern cp needs a box: one side
/// must be <box>:<path>", which is precisely the thing the user had got right, and sent them to
/// re-read a form that had nothing wrong with it. Docker answers "No such container: nobox".
///
/// An existing host path wins over the box reading, which keeps a file whose NAME contains a colon
/// copyable: `kern cp weird:name.txt web:/tmp/` used to work by falling through the old `None` and
/// still does. A first field containing `/` is a host path too (`./a:b`, `/tmp/a:b`), never a box
/// name. Only a spec that is box-shaped AND names nothing on disk is reported as a missing box.
fn classify(spec: &str) -> Side {
    if std::path::Path::new(spec).exists() {
        return Side::Host;
    }
    let Some((name, path)) = spec.split_once(':') else {
        return Side::Host;
    };
    if name.is_empty() || path.is_empty() || name.contains('/') {
        return Side::Host;
    }
    let Some(inst) = crate::registry::find_ref(name) else {
        return Side::NoSuchBox(name.to_string());
    };
    let pid1 = match inst.live_pid1() {
        Some(p) => p,
        None => match crate::registry::box_init_under(inst.pid) {
            Some(p) => p,
            // Registered, but its init is already gone: a box on its way out. "No such box" is the
            // truthful answer to "can I copy into it right now", and the alternative was to treat
            // the whole spec as a host path and write a file called `name:path` in the cwd.
            None => return Side::NoSuchBox(name.to_string()),
        },
    };
    Side::Boxed(pid1, path.to_string())
}

/// `kern cp <src> <dst>` - exactly one of `src`/`dst` must be `<box>:<path>`.
pub fn cp(src: &str, dst: &str) -> Result<(), Error> {
    match (classify(src), classify(dst)) {
        // Checked first: a missing box is a definite answer, and reporting it as anything else
        // (bad syntax, or "needs a box") describes a problem the caller does not have.
        (Side::NoSuchBox(name), _) | (_, Side::NoSuchBox(name)) => Err(Error::NotRunning(format!(
            "no box named '{name}' is running"
        ))),
        (Side::Boxed(..), Side::Boxed(..)) => Err(Error::Sandbox(
            "box-to-box copy isn't supported - copy via the host in two steps".into(),
        )),
        (Side::Boxed(pid1, box_src), Side::Host) => copy_out(pid1, &box_src, dst),
        (Side::Host, Side::Boxed(pid1, box_dst)) => copy_in(src, pid1, &box_dst),
        (Side::Host, Side::Host) => Err(Error::Sandbox(
            "kern cp needs a box: one side must be <box>:<path> (e.g. kern cp web:/etc/app.conf ./ )"
                .into(),
        )),
    }
}

/// box → host. Reads the in-box file (confined) and writes it to the host `dst` (a directory dst
/// takes the source basename).
fn copy_out(pid1: i32, box_src: &str, host_dst: &str) -> Result<(), Error> {
    let root = box_root_fd(pid1).map_err(|e| Error::Sandbox(format!("box root: {e}")))?;
    // `O_NONBLOCK`: a hostile image could plant a FIFO at `box_src` - a plain `O_RDONLY` open of a FIFO
    // BLOCKS until a writer appears, hanging the operator's `cp`. Opening non-blocking returns
    // immediately; we then `fstat` and reject anything but a regular file (below), for which the flag
    // is a no-op.
    let fd = openat2_in_root(root, box_src, libc::O_RDONLY | libc::O_NONBLOCK, 0).map_err(|e| {
        unsafe { libc::close(root) };
        Error::Sandbox(format!("box:{box_src}: {e}"))
    })?;
    unsafe { libc::close(root) };
    // Regular files ONLY (also excludes a directory, FIFO, socket, device).
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let meta = file
        .metadata()
        .map_err(|e| Error::Sandbox(format!("box:{box_src}: {e}")))?;
    if !meta.file_type().is_file() {
        return Err(Error::Sandbox(format!(
            "box:{box_src} is not a regular file (kern cp copies single files)"
        )));
    }
    let dst = resolve_host_dst(host_dst, box_src);
    // Guard the host DESTINATION: `kern cp box:/x <runtime>/kern/instances/<peer>` would let a box's
    // contents OVERWRITE a peer's recorded posture (the WRITE the `-v` guard warns about - forging a
    // capability/seccomp record to elevate a later `kern exec`). Shared write-guard: refuse when the
    // dst's PARENT resolves onto a trust-bearing registry dir (box-data dirs stay writable).
    crate::secret::guard_host_write_path(&dst, "cp destination")?;
    let mut out =
        std::fs::File::create(&dst).map_err(|e| Error::Sandbox(format!("writing {dst}: {e}")))?;
    // Stream with a fixed buffer + a hard size cap, so a multi-GB (or sparse-huge) in-box file can't
    // OOM the operator's `cp` process.
    let n = stream_capped(&mut file, &mut out)
        .map_err(|e| Error::Sandbox(format!("copying box:{box_src}: {e}")))?;
    println!("copied box:{box_src} → {dst} ({n} bytes)");
    Ok(())
}

/// Max bytes `kern cp` moves in one call (streamed) - a self-DoS guard, not a security boundary.
const MAX_CP_BYTES: u64 = 4 << 30; // 4 GiB

/// Copy `src` → `dst` with a fixed buffer, refusing past [`MAX_CP_BYTES`]. Returns bytes copied.
fn stream_capped(src: &mut std::fs::File, dst: &mut std::fs::File) -> std::io::Result<u64> {
    use std::io::{Read, Write};
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_CP_BYTES {
            return Err(std::io::Error::other(
                "file exceeds the 4 GiB kern cp limit",
            ));
        }
        dst.write_all(&buf[..n])?;
    }
    Ok(total)
}

/// host → box. Reads the host file and writes it to the in-box `dst` (confined). The box-side parent
/// directory must already exist.
fn copy_in(host_src: &str, pid1: i32, box_dst: &str) -> Result<(), Error> {
    // Guard the host SOURCE against the registry - the SAME class the `-v`/`--secret`/`--env-file` guard
    // closes, which `kern cp` was missing: `kern cp <runtime>/kern/ssh/<key> box:/x` (or a posture record
    // under `instances/`) would copy a peer's secret/state INTO the box. The box side is already confined
    // (`openat2_in_root`); this closes the host side. Canonicalize + refuse, then read the CANONICAL path
    // so a symlink can't redirect the read after the check.
    let canon = crate::secret::guard_host_path(host_src, "cp")?;
    let meta =
        std::fs::metadata(&canon).map_err(|e| Error::Sandbox(format!("host {host_src}: {e}")))?;
    if !meta.file_type().is_file() {
        return Err(Error::Sandbox(format!(
            "{host_src} is not a regular file (kern cp copies single files)"
        )));
    }
    if meta.len() > MAX_CP_BYTES {
        return Err(Error::Sandbox(format!(
            "{host_src} exceeds the 4 GiB kern cp limit"
        )));
    }
    let data =
        std::fs::read(&canon).map_err(|e| Error::Sandbox(format!("host {host_src}: {e}")))?;
    // If the box dst names an existing directory, drop the source basename into it.
    let root = box_root_fd(pid1).map_err(|e| Error::Sandbox(format!("box root: {e}")))?;
    let box_dst = box_dst_path(root, box_dst, host_src);
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode() & 0o777;
    let fd = openat2_in_root(
        root,
        &box_dst,
        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
        mode,
    )
    .map_err(|e| {
        unsafe { libc::close(root) };
        Error::Sandbox(format!(
            "box:{box_dst}: {e} (does the parent dir exist in the box?)"
        ))
    })?;
    unsafe { libc::close(root) };
    use std::io::Write;
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(&data)
        .map_err(|e| Error::Sandbox(format!("writing box:{box_dst}: {e}")))?;
    println!("copied {host_src} → box:{box_dst} ({} bytes)", data.len());
    Ok(())
}

/// A host destination that is an existing directory gets the source basename appended.
fn resolve_host_dst(host_dst: &str, box_src: &str) -> String {
    if std::path::Path::new(host_dst).is_dir() {
        let base = box_src
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("file");
        format!("{}/{base}", host_dst.trim_end_matches('/'))
    } else {
        host_dst.to_string()
    }
}

/// A box destination that resolves (confined) to an existing directory gets the source basename.
fn box_dst_path(root: RawFd, box_dst: &str, host_src: &str) -> String {
    // Probe whether box_dst is a directory, confined.
    if let Ok(fd) = openat2_in_root(root, box_dst, libc::O_PATH | libc::O_DIRECTORY, 0) {
        unsafe { libc::close(fd) };
        let base = host_src
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("file");
        return format!("{}/{base}", box_dst.trim_end_matches('/'));
    }
    box_dst.to_string()
}

use std::os::unix::io::FromRawFd;

#[cfg(test)]
mod tests {
    use super::*;

    /// The three answers `classify` must keep apart, because collapsing them is what produced a
    /// syntax error for a correct spelling: the old shape of this test asserted that a box-shaped
    /// spec with no live box came back as "not a box reference", which was the defect.
    ///
    /// No running box is needed. The only case that consults the registry is a box-shaped spec that
    /// names nothing on disk, and on a host with no box by that name the lookup misses, which is
    /// exactly the case under test.
    #[test]
    fn a_missing_box_is_not_reported_as_a_syntax_error() {
        // Box-shaped, no such box: the caller must be able to say WHICH name was missing.
        match classify("definitely-not-a-box:/etc/x") {
            Side::NoSuchBox(n) => assert_eq!(n, "definitely-not-a-box"),
            _ => panic!("a box-shaped spec with no live box must classify as NoSuchBox"),
        }
        // An existing host path wins over the box reading, so a file whose NAME contains a colon
        // stays copyable. This is the case the fix had to avoid breaking.
        let dir = std::env::temp_dir().join(format!("kern-cp-test-{}", std::process::id()));
        let weird = dir.join("weird:name.txt");
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(&weird, b"x").expect("temp file");
        assert!(
            matches!(classify(&weird.to_string_lossy()), Side::Host),
            "an existing host path must classify as Host even with a colon in its name"
        );
        let _ = std::fs::remove_file(&weird);
        let _ = std::fs::remove_dir(&dir);
        // A first field containing a slash is a path, never a box name; and the degenerate halves.
        for host in [
            "./a:b",
            "/tmp/a:b",
            "/plain/host/path",
            "plain-path",
            ":path",
            "boxname:",
        ] {
            assert!(matches!(classify(host), Side::Host), "{host} must be Host");
        }
    }

    #[test]
    fn host_dst_basename_join() {
        // Non-dir dst is returned as-is.
        assert_eq!(
            resolve_host_dst("/tmp/out.txt", "/etc/app.conf"),
            "/tmp/out.txt"
        );
    }

    #[test]
    fn cp_write_guard_allows_an_ordinary_host_path() {
        // A destination whose parent is NOT under the registry passes. The refuse case (a registry
        // parent) is covered by `path_overlaps_trusted_state`'s own env-mutating anti-forgery tests, so
        // this only pins that the shared write-guard does not false-positive on an ordinary path.
        let dir = std::env::temp_dir().join(format!("kern-cpw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dst = dir.join("out.txt");
        assert!(
            crate::secret::guard_host_write_path(&dst.to_string_lossy(), "cp destination").is_ok()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
