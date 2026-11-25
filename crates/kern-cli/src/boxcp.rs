//! `kern cp` - copy files and directories between the host and a running box, as `docker cp` does,
//! with every in-box path resolved **inside the box**.
//!
//! Direction is Docker's: `kern cp <box>:<src> <dst>` (out) or `kern cp <src> <box>:<dst>` (in);
//! `-` on the host side is a tar archive on stdout (out) or stdin (in). A directory is copied whole;
//! a symlink is copied as a symlink (`-L` follows the one SRC names); a hardlink stays a hardlink.
//!
//! ONE ARCHIVE FORMAT FOR EVERY DIRECTION. The source side writes a tar stream, the destination side
//! reads one, and a copy between two paths is the two joined by a pipe. So `kern cp box:/d -`, the
//! Docker API's `GET /containers/{id}/archive` and `kern cp box:/d ./out` are one reader and one
//! writer, not three copiers that can disagree on a symlink.
//!
//! CONFINEMENT, the class behind CVE-2019-14271 (`docker cp` following a container symlink out to the
//! host). Neither side ever resolves a path the box controls with the host's root:
//!
//! * the box's paths go through `openat2(RESOLVE_IN_ROOT)` against `/proc/<pid1>/root`, so a link the
//!   box planted, absolute or `..`, lands inside the box;
//! * reading, every entry below the source is opened RELATIVE to its parent's descriptor with
//!   `O_NOFOLLOW`, one name at a time, so the walk never crosses a link;
//! * writing to the HOST, every member is resolved with `openat2(RESOLVE_BENEATH)` from the
//!   destination directory: a member or a link that would leave it is refused, not followed, and
//!   each file is checked against kern's own state ([`crate::secret::guard_host_write_path`]);
//! * a member name with a `..` component is refused outright.
//!
//! Ownership is not restored (a rootless copy cannot: the box's ids live in a subuid range); the mode
//! is, without the set-id bits on the host. The archive carries the ids the box sees.

use crate::error::Error;
use crate::openat2::box_root_fd;
use kern_isolation::archive::{
    cstr, is_dir, join, lstat_at, openat2_confined, owned, read_archive, write_archive, Confine,
    Dest, IdMap,
};
use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;

/// What one `kern cp` argument turned out to be.
enum Side {
    /// `<name>:<path>` naming a box that is running: its pid 1 and the in-box path.
    Boxed(i32, String),
    /// `<name>:<path>` naming a KEPT box that is not running (stopped, never started, or between two
    /// runs of its `--restart` policy): reached through a box kern starts on its layer.
    Kept(String, String),
    /// `<name>:<path>`-shaped, naming no running box. Carries the name so the error can say it.
    NoSuchBox(String),
    /// `-`: a tar archive on stdin or stdout.
    Stdio,
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
/// `-` is always the archive stream, as it is for `docker cp`.
fn classify(spec: &str) -> Side {
    if spec == "-" {
        return Side::Stdio;
    }
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
        // A KEPT BOX IS A CONTAINER THAT IS NOT RUNNING, and `docker cp` copies into and out of a
        // stopped container. MEASURED before: kern answered "no box named 'x' is running" for a
        // `--restart always` box between two runs, where Docker copied the file.
        if crate::keepbox::dir_of(name)
            .and_then(|d| crate::keepbox::read(&d))
            .is_some()
        {
            return Side::Kept(name.to_string(), path.to_string());
        }
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

/// `KERN_CP_STAT=1 kern cp <box>:<path> -` prints the path's stat as Docker's
/// `X-Docker-Container-Path-Stat` JSON instead of an archive: what the Docker API answers a `HEAD`
/// of `/containers/{id}/archive` with, and puts in front of a `GET`. An environment switch and not a
/// flag, because it is the API's question, not a user's.
const STAT_ENV: &str = "KERN_CP_STAT";

/// `kern cp [-L] <src> <dst>` - exactly one of `src`/`dst` must be `<box>:<path>`.
pub fn cp(src: &str, dst: &str, follow: bool) -> Result<(), Error> {
    let (src_side, dst_side) = (classify(src), classify(dst));
    // Refused before a box is started for either side: two boxes are never a copy kern makes.
    if matches!(
        (&src_side, &dst_side),
        (
            Side::Boxed(..) | Side::Kept(..),
            Side::Boxed(..) | Side::Kept(..)
        )
    ) {
        return Err(Error::Sandbox(
            "box-to-box copy isn't supported - copy via the host in two steps".into(),
        ));
    }
    // A kept box that is not running is reached through a box on its layer, which lives as long as
    // this copy (`LayerBox` removes it on every way out).
    let mut held: Option<LayerBox> = None;
    let mut reach = |side: Side| -> Result<Side, Error> {
        match side {
            Side::Kept(owner, path) => {
                let (lb, pid1) = LayerBox::start(&owner)?;
                held = Some(lb);
                Ok(Side::Boxed(pid1, path))
            }
            other => Ok(other),
        }
    };
    let src_side = reach(src_side)?;
    let dst_side = reach(dst_side)?;
    let done = dispatch(src_side, dst_side, src, dst, follow);
    drop(held);
    done
}

fn dispatch(
    src_side: Side,
    dst_side: Side,
    src: &str,
    dst: &str,
    follow: bool,
) -> Result<(), Error> {
    match (src_side, dst_side) {
        // Checked first: a missing box is a definite answer, and reporting it as anything else
        // (bad syntax, or "needs a box") describes a problem the caller does not have.
        (Side::NoSuchBox(name), _) | (_, Side::NoSuchBox(name)) => Err(Error::NotRunning(format!(
            "no box named '{name}' is running"
        ))),
        (Side::Boxed(..) | Side::Kept(..), Side::Boxed(..) | Side::Kept(..)) => Err(Error::Sandbox(
            "box-to-box copy isn't supported - copy via the host in two steps".into(),
        )),
        // `cp` resolves a kept side to a running one before it gets here.
        (Side::Kept(name, _), _) | (_, Side::Kept(name, _)) => Err(Error::NotRunning(format!(
            "kept box '{name}' could not be reached"
        ))),
        (Side::Boxed(pid1, box_src), Side::Stdio) => {
            if crate::global_env(STAT_ENV).is_some() {
                print_stat(pid1, &box_src, follow)
            } else {
                archive_out(pid1, &box_src, follow)
            }
        }
        (Side::Stdio, Side::Boxed(pid1, box_dst)) => archive_in(pid1, &box_dst),
        (Side::Boxed(pid1, box_src), Side::Host) => copy_out(pid1, &box_src, dst, follow),
        (Side::Host, Side::Boxed(pid1, box_dst)) => copy_in(src, pid1, &box_dst, follow),
        (Side::Host | Side::Stdio, Side::Host | Side::Stdio) => Err(Error::Sandbox(
            "kern cp needs a box: one side must be <box>:<path> (e.g. kern cp web:/etc/app.conf ./ )"
                .into(),
        )),
    }
}

/// A box kern starts on a kept box's layer so `kern cp` can reach its files while it is not
/// running, as `docker cp` reaches a stopped container's.
///
/// IT IS A BOX, NOT A SECOND READER OF LAYERS. The copy goes through the same `/proc/<pid1>/root`,
/// user namespace and mounts a running box gives, so whiteouts, opaque directories, the uid map and
/// the box's volumes are the kernel's and the box runtime's, not a reimplementation of them. Its
/// PID 1 runs nothing (`--idle`, so an image with no binaries works), it has no network, it pulls
/// nothing, and `--layer-of` gives it the owner's layer (held for its life, so no run of the owner
/// mounts it meanwhile), the owner's anonymous volumes and the image the owner was created from.
/// The owner's own volumes (`-v`, `--mount`) are mounted as they were recorded, from the directory
/// it was created in, so a path inside one reaches the volume, as it does under Docker.
struct LayerBox {
    name: String,
}

impl LayerBox {
    fn start(owner: &str) -> Result<(LayerBox, i32), Error> {
        let Some(dir) = crate::keepbox::dir_of(owner) else {
            return Err(Error::NotRunning(format!("no kept box '{owner}'")));
        };
        let Some((argv, meta)) = crate::keepbox::read(&dir) else {
            return Err(Error::NotRunning(format!("no kept box '{owner}'")));
        };
        let words: Option<Vec<String>> = argv
            .iter()
            .map(|a| a.to_str().map(str::to_string))
            .collect();
        let Some(words) = words else {
            return Err(Error::Sandbox(format!(
                "kept box '{owner}': its command line is not UTF-8, so kern cannot read which \
                 image and volumes it has"
            )));
        };
        let Ok((
            _,
            crate::cli::Command::BoxRun {
                image,
                rootfs,
                platform,
                volumes,
                mounts,
                uid_range,
                no_uid_range,
                ..
            },
        )) = crate::cli::parse(&words)
        else {
            return Err(Error::Sandbox(format!(
                "kept box '{owner}': its record is not a box command kern can read"
            )));
        };
        let me = std::env::current_exe()
            .map_err(|e| Error::Sandbox(format!("cannot locate the kern binary: {e}")))?;
        let name = Self::name_for(owner);
        let mut args: Vec<String> = vec![
            "box".into(),
            name.clone(),
            "-d".into(),
            "--rm".into(),
            "--idle".into(),
            "--net".into(),
            "none".into(),
            "--pull".into(),
            "never".into(),
            "--layer-of".into(),
            owner.to_string(),
        ];
        match (image, rootfs) {
            (Some(i), _) => args.extend(["--image".into(), i]),
            (None, Some(r)) => args.extend(["--rootfs".into(), r]),
            (None, None) => {
                return Err(Error::Sandbox(format!(
                    "kept box '{owner}': its record names no image and no rootfs"
                )))
            }
        }
        if let Some(p) = platform {
            args.extend(["--platform".into(), format!("{}/{}", p.os, p.arch)]);
        }
        if uid_range {
            args.push("--uid-range".into());
        }
        if no_uid_range {
            args.push("--no-uid-range".into());
        }
        for v in volumes {
            args.extend(["-v".into(), v]);
        }
        for (src, dst, ro) in mounts {
            args.extend([
                "-v".into(),
                if ro {
                    format!("{src}:{dst}:ro")
                } else {
                    format!("{src}:{dst}")
                },
            ]);
        }
        args.extend(["--".into(), "/kern-idle".into()]);
        let mut cmd = std::process::Command::new(&me);
        cmd.args(&args)
            .env_remove("KERN_MANAGED")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        if !meta.cwd.is_empty() && std::path::Path::new(&meta.cwd).is_dir() {
            cmd.current_dir(&meta.cwd);
        }
        let out = cmd
            .output()
            .map_err(|e| Error::Sandbox(format!("kept box '{owner}': cannot run kern: {e}")))?;
        // From here the box may exist: the guard removes it on every way out, the errors included.
        let lb = LayerBox { name };
        if !out.status.success() {
            let why = String::from_utf8_lossy(&out.stderr);
            let why = why.trim().trim_start_matches("error: ");
            return Err(Error::Sandbox(format!(
                "kept box '{owner}' is not running and kern could not open its layer to copy: {why}"
            )));
        }
        let pid1 = crate::registry::find(&lb.name).and_then(|i| {
            i.live_pid1()
                .or_else(|| crate::registry::box_init_under(i.pid))
        });
        match pid1 {
            Some(p) => Ok((lb, p)),
            None => Err(Error::Sandbox(format!(
                "kept box '{owner}': the box kern started on its layer is not up"
            ))),
        }
    }

    /// `<owner>-cp<pid>`, a valid box name that no user box shares; a short fallback when the
    /// owner's name is near the limit.
    fn name_for(owner: &str) -> String {
        let pid = std::process::id();
        let full = format!("{owner}-cp{pid}");
        if kern_common::BoxName::parse(&full).is_ok() {
            full
        } else {
            format!("kern-cp{pid}")
        }
    }
}

impl Drop for LayerBox {
    /// Removed as `kern rm -f` removes a box: its PID 1 ends on the SIGTERM, `--rm` leaves no record.
    fn drop(&mut self) {
        if let Ok(me) = std::env::current_exe() {
            let _ = std::process::Command::new(me)
                .args(["rm", "-f", &self.name])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Paths.

/// A copy source or destination split Docker's way: the directory it lives in, its own name, and
/// whether it ended in `/.` ("the CONTENTS of this directory") or in `/` ("this must be a
/// directory").
struct Split {
    parent: Vec<u8>,
    name: Vec<u8>,
    contents: bool,
    trailing_slash: bool,
}

fn split_path(p: &[u8]) -> Split {
    let contents = p.ends_with(b"/.") || p == b".";
    let mut q = p;
    if contents {
        q = &q[..q.len() - 1];
    }
    let trailing_slash = q.len() > 1 && q.ends_with(b"/");
    while q.len() > 1 && q.ends_with(b"/") {
        q = &q[..q.len() - 1];
    }
    match q.iter().rposition(|&b| b == b'/') {
        // `/` itself: its name is `.` under itself.
        Some(0) if q.len() == 1 => Split {
            parent: b"/".to_vec(),
            name: b".".to_vec(),
            contents,
            trailing_slash,
        },
        Some(i) => Split {
            parent: if i == 0 {
                b"/".to_vec()
            } else {
                q[..i].to_vec()
            },
            name: q[i + 1..].to_vec(),
            contents,
            trailing_slash,
        },
        None => Split {
            parent: b".".to_vec(),
            name: if q.is_empty() {
                b".".to_vec()
            } else {
                q.to_vec()
            },
            contents,
            trailing_slash,
        },
    }
}

/// The thing a copy reads: a name in a directory, or (`name` empty) an already-open node.
struct Source {
    dir: OwnedFd,
    name: CString,
    st: libc::stat,
}

/// Open the source `path` under `root` (`Confine::InRoot` for a box, the host's `/` otherwise is
/// [`host_source`]). Without `follow`, a symlink SRC is the link itself; with it, its target.
fn box_source(root: RawFd, path: &[u8], follow: bool) -> Result<(Source, Split), Error> {
    let sp = split_path(path);
    let shown = String::from_utf8_lossy(path).into_owned();
    if follow || sp.name == b"." {
        let fd = openat2_confined(root, path, libc::O_PATH, 0, Confine::InRoot)
            .map_err(|e| Error::Sandbox(format!("box:{shown}: {e}")))?;
        let dir = owned(fd);
        let name = CString::default();
        let st = lstat_at(dir.as_raw_fd(), &name)
            .map_err(|e| Error::Sandbox(format!("box:{shown}: {e}")))?;
        return Ok((Source { dir, name, st }, sp));
    }
    let fd = openat2_confined(
        root,
        &sp.parent,
        libc::O_PATH | libc::O_DIRECTORY,
        0,
        Confine::InRoot,
    )
    .map_err(|e| Error::Sandbox(format!("box:{shown}: {e}")))?;
    let dir = owned(fd);
    let name = cstr(&sp.name).map_err(|e| Error::Sandbox(format!("box:{shown}: {e}")))?;
    let st = lstat_at(dir.as_raw_fd(), &name)
        .map_err(|e| Error::Sandbox(format!("box:{shown}: {e}")))?;
    Ok((Source { dir, name, st }, sp))
}

/// The host side of a copy into a box: the path the user named, resolved as the host does (it is
/// the user's own tree), its last component a link or not as `follow` says.
fn host_source(path: &str, follow: bool) -> Result<(Source, Split), Error> {
    let sp = split_path(path.as_bytes());
    let open_path = |p: &[u8], flags: i32| -> Result<OwnedFd, Error> {
        let c = cstr(p).map_err(|e| Error::Sandbox(format!("host {path}: {e}")))?;
        let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(Error::Sandbox(format!(
                "host {path}: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(owned(fd))
    };
    if follow || sp.name == b"." {
        let dir = open_path(path.as_bytes(), libc::O_PATH)?;
        let name = CString::default();
        let st = lstat_at(dir.as_raw_fd(), &name)
            .map_err(|e| Error::Sandbox(format!("host {path}: {e}")))?;
        return Ok((Source { dir, name, st }, sp));
    }
    let dir = open_path(&sp.parent, libc::O_PATH | libc::O_DIRECTORY)?;
    let name = cstr(&sp.name).map_err(|e| Error::Sandbox(format!("host {path}: {e}")))?;
    let st = lstat_at(dir.as_raw_fd(), &name)
        .map_err(|e| Error::Sandbox(format!("host {path}: {e}")))?;
    Ok((Source { dir, name, st }, sp))
}

/// The name the archive gives the source: the source's own name, or the one the destination
/// renames it to. `None` = the CONTENTS of a directory, with no entry for the directory itself.
fn top_name(sp: &Split) -> Option<Vec<u8>> {
    (!sp.contents && sp.name != b".").then(|| sp.name.clone())
}

// ---------------------------------------------------------------------------------------------
// The copies.

/// Enter the user namespace of the box whose PID 1 is `pid1`, for the whole copy.
///
/// AS THE BOX'S ROOT, NOT AS THIS USER. The box's files belong to the ids of its own namespace: a
/// file of mode 000 is its root's, a service's data is its user's (postgres 70, an image's `app`
/// user), and from the host this user may read neither. MEASURED before: `kern cp` of such a
/// directory failed with "Permission denied", and `docker cp` through kern's socket printed nothing
/// and exited 0 with an EMPTY directory, where Docker copied both files.
///
/// The process stays this user (its kernel uid is unchanged, so what it writes on the host is this
/// user's, and a host file it could not read it still cannot): it gains the box root's capabilities
/// over the files whose ids that namespace maps, the box's own, which is what Docker's daemon has.
/// Only a single-threaded process may join a user namespace; one that cannot (`kern compose cp`
/// runs inside a threaded driver, or the box shares this namespace) copies as this user, as before.
///
/// Returns the id map an archive written from here needs: once inside, `stat` already answers in
/// the box's ids, so they are written as they are; outside, the host's are mapped through the box's
/// `uid_map` (mapping them twice wrote 65534 for every owner, measured).
fn enter_box_userns(pid1: i32) -> IdMap {
    let Ok(path) = cstr(format!("/proc/{pid1}/ns/user").as_bytes()) else {
        return IdMap::of_box(pid1);
    };
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return IdMap::of_box(pid1);
    }
    let fd = owned(fd);
    // EINVAL: already in it, or not single-threaded; EPERM: not ours to enter. Either way the copy
    // goes on with this user's rights, which is what it had before.
    if unsafe { libc::setns(fd.as_raw_fd(), libc::CLONE_NEWUSER) } == 0 {
        IdMap::default()
    } else {
        IdMap::of_box(pid1)
    }
}

/// Run the writer into a pipe on one thread and the reader from it on this one.
fn pipe_through(src: &Source, top: Option<&[u8]>, ids: IdMap, dest: &Dest) -> Result<u64, Error> {
    let mut fds = [0 as RawFd; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(Error::Sandbox(format!(
            "kern cp: pipe: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut rd = std::fs::File::from(owned(fds[0]));
    let wr = std::fs::File::from(owned(fds[1]));
    let (wrote, read) = std::thread::scope(|s| {
        let h = s.spawn(move || {
            write_archive(
                src.dir.as_raw_fd(),
                &src.name,
                &src.st,
                top,
                ids,
                std::io::BufWriter::new(wr),
            )
        });
        let read = read_archive(&mut rd, dest);
        // Unblock a writer still writing when the reader stopped on an error.
        drop(rd);
        (h.join(), read)
    });
    let read = read.map_err(|e| Error::Sandbox(format!("kern cp: {e}")))?;
    match wrote {
        Ok(Ok(_)) => Ok(read),
        Ok(Err(e)) => Err(Error::Sandbox(format!("kern cp: {e}"))),
        Err(_) => Err(Error::Sandbox("kern cp: the archive writer stopped".into())),
    }
}

/// Where a copy lands, Docker's rules: `(directory, top name)`, `None` top for a directory's
/// contents. `dst_kind` is what the destination is now (`Some(true)` a directory, `Some(false)`
/// something else, `None` nothing).
fn landing(
    src: &Source,
    sp: &Split,
    dst: &[u8],
    dst_kind: Option<bool>,
) -> Result<(Vec<u8>, Option<Vec<u8>>), Error> {
    let ds = split_path(dst);
    let shown = String::from_utf8_lossy(dst);
    match dst_kind {
        Some(true) => Ok((dst.to_vec(), top_name(sp))),
        Some(false) if is_dir(&src.st) => Err(Error::Sandbox(format!(
            "cannot copy a directory to the file {shown}"
        ))),
        Some(false) => Ok((ds.parent, Some(ds.name))),
        None if ds.trailing_slash && !is_dir(&src.st) => Err(Error::Sandbox(format!(
            "the destination directory {shown} does not exist"
        ))),
        None => Ok((ds.parent, Some(ds.name))),
    }
}

/// box → host path.
fn copy_out(pid1: i32, box_src: &str, host_dst: &str, follow: bool) -> Result<(), Error> {
    let ids = enter_box_userns(pid1);
    let root = box_root_fd(pid1).map_err(|e| Error::Sandbox(format!("box root: {e}")))?;
    let (src, sp) = box_source(root.as_raw_fd(), box_src.as_bytes(), follow)?;
    let kind = std::fs::metadata(host_dst).ok().map(|m| m.is_dir());
    let (dir, top) = landing(&src, &sp, host_dst.as_bytes(), kind)?;
    let dir_path = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&dir));
    let target = match &top {
        Some(t) => dir_path.join(std::ffi::OsStr::from_bytes(t)),
        None => dir_path.clone(),
    };
    crate::secret::guard_host_write_path(&target.to_string_lossy(), "cp destination")?;
    let base = std::fs::File::open(&dir_path)
        .map_err(|e| Error::Sandbox(format!("{}: {e}", dir_path.display())))?;
    let dest = Dest {
        base: OwnedFd::from(base),
        confine: Confine::Beneath,
        prefix: Vec::new(),
        mode_mask: 0o1777,
        // EVERY FILE checked against kern's own state, not only the top: a box's directory
        // copied to `$XDG_RUNTIME_DIR` would otherwise put its `kern/...` members in the registry.
        guard: Some(Box::new(move |member: &[u8]| {
            let p = dir_path.join(std::ffi::OsStr::from_bytes(member));
            crate::secret::guard_host_write_path(&p.to_string_lossy(), "cp destination").map_err(
                |e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string()),
            )
        })),
    };
    let n = pipe_through(&src, top.as_deref(), ids, &dest)?;
    println!("copied box:{box_src} → {} ({n} bytes)", target.display());
    Ok(())
}

/// The kind of `path` in the box, following its last link (confined): Docker's destination test.
fn box_kind(root: RawFd, path: &[u8]) -> Result<Option<bool>, Error> {
    match openat2_confined(root, path, libc::O_PATH, 0, Confine::InRoot) {
        Ok(fd) => {
            let fd = owned(fd);
            let st = lstat_at(fd.as_raw_fd(), &CString::default()).map_err(|e| {
                Error::Sandbox(format!("box:{}: {e}", String::from_utf8_lossy(path)))
            })?;
            Ok(Some(is_dir(&st)))
        }
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT)) => Ok(None),
        Err(e) => Err(Error::Sandbox(format!(
            "box:{}: {e}",
            String::from_utf8_lossy(path)
        ))),
    }
}

/// host path → box.
fn copy_in(host_src: &str, pid1: i32, box_dst: &str, follow: bool) -> Result<(), Error> {
    // Guard the host SOURCE against the registry - the SAME class the `-v`/`--secret`/`--env-file`
    // guard closes: `kern cp <runtime>/kern/ssh/<key> box:/x` (or a posture record under
    // `instances/`) would copy a peer's secret or state INTO the box. A directory source is checked
    // the same way, since the registry may lie below it.
    crate::secret::guard_host_path(host_src, "cp")?;
    let (src, sp) = host_source(host_src, follow)?;
    // The host source is open (as this user); the box side is written as the box's root.
    let _ = enter_box_userns(pid1);
    let root = box_root_fd(pid1).map_err(|e| Error::Sandbox(format!("box root: {e}")))?;
    let kind = box_kind(root.as_raw_fd(), box_dst.as_bytes())?;
    let (dir, top) = landing(&src, &sp, box_dst.as_bytes(), kind)?;
    if box_kind(root.as_raw_fd(), &dir)? != Some(true) {
        return Err(Error::Sandbox(format!(
            "box:{}: no such directory in the box",
            String::from_utf8_lossy(&dir)
        )));
    }
    let shown = match &top {
        Some(t) => String::from_utf8_lossy(&join(&dir, t)).into_owned(),
        None => String::from_utf8_lossy(&dir).into_owned(),
    };
    let dest = Dest {
        base: root,
        confine: Confine::InRoot,
        prefix: dir,
        mode_mask: 0o7777,
        guard: None,
    };
    let n = pipe_through(&src, top.as_deref(), IdMap::default(), &dest)?;
    println!("copied {host_src} → box:{shown} ({n} bytes)");
    Ok(())
}

/// box → an archive on stdout (`kern cp <box>:<src> -`).
fn archive_out(pid1: i32, box_src: &str, follow: bool) -> Result<(), Error> {
    let ids = enter_box_userns(pid1);
    let root = box_root_fd(pid1).map_err(|e| Error::Sandbox(format!("box root: {e}")))?;
    let (src, sp) = box_source(root.as_raw_fd(), box_src.as_bytes(), follow)?;
    let top = top_name(&sp);
    let out = std::io::BufWriter::new(std::io::stdout().lock());
    write_archive(
        src.dir.as_raw_fd(),
        &src.name,
        &src.st,
        top.as_deref(),
        ids,
        out,
    )
    .map_err(|e| Error::Sandbox(format!("kern cp: {e}")))?;
    Ok(())
}

/// An archive on stdin → the box directory `box_dst` (`kern cp - <box>:<dst>`), which must exist.
fn archive_in(pid1: i32, box_dst: &str) -> Result<(), Error> {
    let _ = enter_box_userns(pid1);
    let root = box_root_fd(pid1).map_err(|e| Error::Sandbox(format!("box root: {e}")))?;
    match box_kind(root.as_raw_fd(), box_dst.as_bytes())? {
        Some(true) => {}
        Some(false) => {
            return Err(Error::Sandbox(format!(
                "box:{box_dst}: the destination of an archive must be a directory"
            )))
        }
        None => {
            return Err(Error::Sandbox(format!(
                "box:{box_dst}: no such directory in the box"
            )))
        }
    }
    let dest = Dest {
        base: root,
        confine: Confine::InRoot,
        prefix: box_dst.as_bytes().to_vec(),
        mode_mask: 0o7777,
        guard: None,
    };
    let mut input = std::io::stdin().lock();
    let n = read_archive(&mut input, &dest).map_err(|e| Error::Sandbox(format!("kern cp: {e}")))?;
    eprintln!("copied an archive → box:{box_dst} ({n} bytes)");
    Ok(())
}

/// Docker's `os.FileMode` bits for a `stat` mode.
fn go_file_mode(mode: u32) -> u64 {
    let mut m = u64::from(mode & 0o777);
    m |= match mode & libc::S_IFMT {
        libc::S_IFDIR => 1 << 31,
        libc::S_IFLNK => 1 << 27,
        libc::S_IFIFO => 1 << 25,
        libc::S_IFSOCK => 1 << 24,
        libc::S_IFCHR => (1 << 26) | (1 << 21),
        libc::S_IFBLK => 1 << 26,
        _ => 0,
    };
    if mode & libc::S_ISUID != 0 {
        m |= 1 << 23;
    }
    if mode & libc::S_ISGID != 0 {
        m |= 1 << 22;
    }
    if mode & libc::S_ISVTX != 0 {
        m |= 1 << 20;
    }
    m
}

/// The stat Docker's API puts in `X-Docker-Container-Path-Stat`, for `KERN_CP_STAT=1`.
fn print_stat(pid1: i32, box_src: &str, follow: bool) -> Result<(), Error> {
    let _ = enter_box_userns(pid1);
    let root = box_root_fd(pid1).map_err(|e| Error::Sandbox(format!("box root: {e}")))?;
    let (src, sp) = box_source(root.as_raw_fd(), box_src.as_bytes(), follow)?;
    let mut link = String::new();
    if src.st.st_mode & libc::S_IFMT == libc::S_IFLNK {
        let mut buf = vec![0u8; libc::PATH_MAX as usize + 1];
        let n = unsafe {
            libc::readlinkat(
                src.dir.as_raw_fd(),
                src.name.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n >= 0 {
            buf.truncate(n as usize);
            let t = if buf.starts_with(b"/") {
                buf
            } else {
                join(&sp.parent, &buf)
            };
            link = String::from_utf8_lossy(&t).into_owned();
        }
    }
    let name = if sp.name == b"." {
        String::from_utf8_lossy(&split_path(sp.parent.as_slice()).name).into_owned()
    } else {
        String::from_utf8_lossy(&sp.name).into_owned()
    };
    println!(
        "{{\"name\":{},\"size\":{},\"mode\":{},\"mtime\":{},\"linkTarget\":{}}}",
        kern_common::json_str(&name),
        src.st.st_size.max(0),
        go_file_mode(src.st.st_mode),
        kern_common::json_str(&kern_common::rfc3339(src.st.st_mtime.max(0) as u64)),
        kern_common::json_str(&link)
    );
    Ok(())
}

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
        let _g = crate::env_guard();
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
        assert!(
            matches!(classify("-"), Side::Stdio),
            "`-` is the archive stream"
        );
    }

    #[test]
    fn cp_write_guard_allows_an_ordinary_host_path() {
        let _g = crate::env_guard();
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

    #[test]
    fn paths_split_the_way_docker_reads_them() {
        let s = split_path(b"/d/sub");
        assert_eq!(
            (s.parent.as_slice(), s.name.as_slice()),
            (&b"/d"[..], &b"sub"[..])
        );
        assert!(!s.contents && !s.trailing_slash);
        let s = split_path(b"/d/.");
        assert!(s.contents);
        assert_eq!(s.name, b"d");
        let s = split_path(b"out/");
        assert!(s.trailing_slash);
        assert_eq!(
            (s.parent.as_slice(), s.name.as_slice()),
            (&b"."[..], &b"out"[..])
        );
        let s = split_path(b"/f");
        assert_eq!(
            (s.parent.as_slice(), s.name.as_slice()),
            (&b"/"[..], &b"f"[..])
        );
        let s = split_path(b"/");
        assert_eq!(s.name, b".");
        assert_eq!(
            kern_isolation::archive::member_path(b"./a//b/./c"),
            Some(b"a/b/c".to_vec())
        );
        assert_eq!(kern_isolation::archive::member_path(b"a/../../etc"), None);
        assert_eq!(
            kern_isolation::archive::member_path(b"/abs/x"),
            Some(b"abs/x".to_vec())
        );
    }

    #[test]
    fn go_file_mode_marks_the_type_as_go_does() {
        assert_eq!(go_file_mode(libc::S_IFDIR | 0o755), (1 << 31) | 0o755);
        assert_eq!(go_file_mode(libc::S_IFLNK | 0o777), (1 << 27) | 0o777);
        assert_eq!(go_file_mode(libc::S_IFREG | 0o644), 0o644);
    }
}
