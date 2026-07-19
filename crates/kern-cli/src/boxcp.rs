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
    let p = std::ffi::CString::new(format!("/proc/{pid1}/root")).unwrap();
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

/// If `spec` is `<name>:<path>` and `name` is a running box, return `(pid1, path)`.
fn as_box_ref(spec: &str) -> Option<(i32, String)> {
    let (name, path) = spec.split_once(':')?;
    if name.is_empty() || path.is_empty() {
        return None;
    }
    let inst = crate::registry::find_ref(name)?;
    let pid1 = if inst.pid1 > 0 {
        inst.pid1
    } else {
        crate::registry::child_of(inst.pid)?
    };
    Some((pid1, path.to_string()))
}

/// `kern cp <src> <dst>` - exactly one of `src`/`dst` must be `<box>:<path>`.
pub fn cp(src: &str, dst: &str) -> Result<(), Error> {
    match (as_box_ref(src), as_box_ref(dst)) {
        (Some(_), Some(_)) => Err(Error::Sandbox(
            "box-to-box copy isn't supported - copy via the host in two steps".into(),
        )),
        (Some((pid1, box_src)), None) => copy_out(pid1, &box_src, dst),
        (None, Some((pid1, box_dst))) => copy_in(src, pid1, &box_dst),
        (None, None) => Err(Error::Sandbox(
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
    let meta =
        std::fs::metadata(host_src).map_err(|e| Error::Sandbox(format!("host {host_src}: {e}")))?;
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
        std::fs::read(host_src).map_err(|e| Error::Sandbox(format!("host {host_src}: {e}")))?;
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

    #[test]
    fn as_box_ref_needs_a_running_box() {
        // No such box → None (so it's treated as a host path).
        assert!(as_box_ref("definitely-not-a-box:/etc/x").is_none());
        assert!(as_box_ref("/plain/host/path").is_none());
        assert!(as_box_ref("name:").is_none());
        assert!(as_box_ref(":path").is_none());
    }

    #[test]
    fn host_dst_basename_join() {
        // Non-dir dst is returned as-is.
        assert_eq!(
            resolve_host_dst("/tmp/out.txt", "/etc/app.conf"),
            "/tmp/out.txt"
        );
    }
}
