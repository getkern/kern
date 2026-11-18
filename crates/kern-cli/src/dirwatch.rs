//! `kern __watch-dir <root> <rel> <0|1>`: hidden. inotify on one directory of a sandbox workspace
//! (recursively with `1`), for an SDK that has no inotify of its own.
//!
//! WHY kern AND NOT THE SDK. Node's `fs.watch` reports `rename` or `change` and drops the rest of the
//! mask: MEASURED, `echo 1 > a.txt && mv a.txt b.txt && chmod 600 b.txt` arrived as `rename a.txt`
//! (already gone), `change a.txt`, `rename a.txt`, `rename b.txt`, `change b.txt`, so a create could
//! not be told from a remove, a write from a chmod, or a move from either. The Python SDK reads the
//! raw events; this is the same algorithm (`DirWatch` in `kern_sandbox`), so both SDKs report the same
//! events.
//!
//! NEVER THROUGH A SYMLINK. The workspace is box-controlled: every directory is opened one component
//! at a time with `O_NOFOLLOW` from `root` and watched through `/proc/self/fd/<fd>`, and listed
//! through its descriptor, so a directory the box swaps for a link to a host path is not followed.
//!
//! OUTPUT, one line each on stdout: `ready` once the starting tree is watched, then
//! `<type> <d|f> <hex path> [<hex old path>]`, paths relative to `root` and hex-encoded (a file name
//! may hold any byte but `/` and NUL). Types: create, write (closed after writing), remove, rename,
//! chmod (mode, owner or times), overflow (events were dropped, or the 8192-directory budget is spent:
//! re-read the directory). The verb ends when stdin reaches EOF (its caller is gone) or when nothing
//! is left to watch.

use crate::error::Error;
use std::io::Write;
use std::os::fd::RawFd;

/// At most this many directories per watch, so a box that creates a million directories cannot make
/// the host spend a million kernel watches. Past it, `overflow` is reported. Same budget as Python.
const MAX_DIRS: usize = 8192;

const MASK: u32 = libc::IN_ATTRIB
    | libc::IN_CLOSE_WRITE
    | libc::IN_MOVED_FROM
    | libc::IN_MOVED_TO
    | libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_DELETE_SELF
    | libc::IN_MOVE_SELF
    | libc::IN_ONLYDIR;

/// One reported change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Event {
    pub kind: &'static str,
    pub path: Vec<u8>,
    pub is_dir: bool,
    pub old: Option<Vec<u8>>,
}

impl Event {
    fn new(kind: &'static str, path: Vec<u8>, is_dir: bool) -> Self {
        Self {
            kind,
            path,
            is_dir,
            old: None,
        }
    }

    /// The output line, without its newline.
    pub(crate) fn line(&self) -> String {
        let mut s = format!(
            "{} {} {}",
            self.kind,
            if self.is_dir { "d" } else { "f" },
            hex(&self.path)
        );
        if let Some(old) = &self.old {
            s.push(' ');
            s.push_str(&hex(old));
        }
        s
    }
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// `a/b` from a base and a name; either may be empty.
fn join(base: &[u8], name: &[u8]) -> Vec<u8> {
    match (base.is_empty(), name.is_empty()) {
        (true, _) => name.to_vec(),
        (false, true) => base.to_vec(),
        (false, false) => [base, b"/", name].concat(),
    }
}

/// A descriptor this module closes when it is dropped.
struct Fd(RawFd);

impl Drop for Fd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe { libc::close(self.0) };
        }
    }
}

/// `name` under `dir`, as a directory, never following a symlink.
fn open_dir_at(dir: RawFd, name: &[u8]) -> Option<Fd> {
    let c = std::ffi::CString::new(name).ok()?;
    let fd = unsafe {
        libc::openat(
            dir,
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    (fd >= 0).then_some(Fd(fd))
}

/// The entries of the directory `fd` holds: (name, is a directory, without following a symlink).
fn list_dir(fd: RawFd) -> Vec<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    // `fdopendir` takes the descriptor over, so it gets its own copy.
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return out;
    }
    let dirp = unsafe { libc::fdopendir(dup) };
    if dirp.is_null() {
        unsafe { libc::close(dup) };
        return out;
    }
    loop {
        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            break;
        }
        // SAFETY: `ent` is the entry `readdir` just returned, valid until the next call.
        let (name, d_type) = unsafe {
            let e = &*ent;
            (
                std::ffi::CStr::from_ptr(e.d_name.as_ptr())
                    .to_bytes()
                    .to_vec(),
                e.d_type,
            )
        };
        if name == b"." || name == b".." {
            continue;
        }
        let is_dir = match d_type {
            libc::DT_DIR => true,
            libc::DT_UNKNOWN => is_dir_nofollow(fd, &name),
            _ => false,
        };
        out.push((name, is_dir));
    }
    unsafe { libc::closedir(dirp) };
    out
}

fn is_dir_nofollow(dir: RawFd, name: &[u8]) -> bool {
    let Ok(c) = std::ffi::CString::new(name) else {
        return false;
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::fstatat(dir, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    r == 0 && st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

struct Watcher {
    inotify: Fd,
    root: Fd,
    recursive: bool,
    /// Watch descriptor to the directory it watches, relative to the root.
    dirs: std::collections::HashMap<i32, Vec<u8>>,
    /// The budget was spent since the last batch: report `overflow` once.
    full: bool,
}

impl Watcher {
    /// Watch the directory `rel` names, reached from the root without following a symlink. The
    /// descriptor on it, for listing, or `None` when it is not a directory there (or vanished) or the
    /// budget is spent.
    fn watch_one(&mut self, rel: &[u8]) -> Option<Fd> {
        if self.dirs.len() >= MAX_DIRS {
            self.full = true;
            return None;
        }
        let mut cur: Option<Fd> = None;
        for part in rel.split(|b| *b == b'/').filter(|p| !p.is_empty()) {
            if part == b".." || part == b"." {
                return None;
            }
            let at = cur.as_ref().map_or(self.root.0, |f| f.0);
            cur = Some(open_dir_at(at, part)?);
        }
        let at = cur.as_ref().map_or(self.root.0, |f| f.0);
        let proc = std::ffi::CString::new(format!("/proc/self/fd/{at}")).ok()?;
        let wd = unsafe { libc::inotify_add_watch(self.inotify.0, proc.as_ptr(), MASK) };
        if wd < 0 {
            return None;
        }
        self.dirs.insert(wd, rel.to_vec());
        match cur {
            Some(f) => Some(f),
            // The root itself: a copy, so the caller may drop it.
            None => {
                let d = unsafe { libc::fcntl(self.root.0, libc::F_DUPFD_CLOEXEC, 0) };
                (d >= 0).then_some(Fd(d))
            }
        }
    }

    /// Watch `rel` and, when recursive, every directory under it. `found` collects a `create` for every
    /// entry already inside: a directory that appears while watched is watched only after it exists,
    /// and what was put in it before that moment would otherwise never be reported. The starting
    /// tree passes `None`: it is the starting state.
    fn add_tree(&mut self, rel: &[u8], mut found: Option<&mut Vec<Event>>) {
        let mut stack = vec![rel.to_vec()];
        while let Some(cur) = stack.pop() {
            let Some(fd) = self.watch_one(&cur) else {
                continue;
            };
            if !self.recursive {
                continue;
            }
            for (name, is_dir) in list_dir(fd.0) {
                let child = join(&cur, &name);
                if let Some(f) = found.as_deref_mut() {
                    f.push(Event::new("create", child.clone(), is_dir));
                }
                if is_dir {
                    stack.push(child);
                }
            }
        }
    }

    /// One `read`'s worth of events, in order; a move inside the tree is one `rename`.
    fn dispatch(&mut self, buf: &[u8]) -> Vec<Event> {
        const HDR: usize = std::mem::size_of::<libc::inotify_event>();
        let mut out: Vec<Event> = Vec::new();
        let mut moved_from: std::collections::HashMap<u32, (Vec<u8>, bool)> =
            std::collections::HashMap::new();
        let mut off = 0usize;
        while off + HDR <= buf.len() {
            // SAFETY: the header is read unaligned from bytes the kernel wrote whole.
            let ev: libc::inotify_event =
                unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off).cast()) };
            let len = ev.len as usize;
            let Some(raw) = buf.get(off + HDR..off + HDR + len) else {
                break;
            };
            off += HDR + len;
            let name = &raw[..raw.iter().position(|b| *b == 0).unwrap_or(raw.len())];
            let mask = ev.mask;
            if mask & libc::IN_Q_OVERFLOW != 0 {
                out.push(Event::new("overflow", Vec::new(), false));
                continue;
            }
            if mask & libc::IN_IGNORED != 0 {
                self.dirs.remove(&ev.wd);
                continue;
            }
            let Some(base) = self.dirs.get(&ev.wd).cloned() else {
                continue;
            };
            if mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0 {
                continue;
            }
            let is_dir = mask & libc::IN_ISDIR != 0;
            let path = join(&base, name);
            if mask & libc::IN_CREATE != 0 {
                out.push(Event::new("create", path.clone(), is_dir));
                if is_dir && self.recursive {
                    self.add_tree(&path, Some(&mut out));
                }
            } else if mask & libc::IN_CLOSE_WRITE != 0 {
                out.push(Event::new("write", path, false));
            } else if mask & libc::IN_DELETE != 0 {
                out.push(Event::new("remove", path, is_dir));
            } else if mask & libc::IN_ATTRIB != 0 {
                out.push(Event::new("chmod", path, is_dir));
            } else if mask & libc::IN_MOVED_FROM != 0 {
                moved_from.insert(ev.cookie, (path.clone(), is_dir));
                out.push(Event::new("remove", path, is_dir));
            } else if mask & libc::IN_MOVED_TO != 0 {
                if let Some((old, _)) = moved_from.remove(&ev.cookie) {
                    // A move inside the watched tree: the `remove` its first half emitted becomes the
                    // rename it was.
                    out.retain(|e| !(e.kind == "remove" && e.path == old));
                    out.push(Event {
                        kind: "rename",
                        path: path.clone(),
                        is_dir,
                        old: Some(old),
                    });
                } else {
                    out.push(Event::new("create", path.clone(), is_dir));
                }
                if is_dir && self.recursive {
                    self.add_tree(&path, Some(&mut out));
                }
            }
        }
        if self.full {
            self.full = false;
            out.push(Event::new("overflow", Vec::new(), false));
        }
        out
    }
}

/// The hidden verb. Errors before `ready` are the caller's refusal; after it, the verb only ends.
pub(crate) fn run(root: &str, rel: &str, recursive: bool) -> Result<(), Error> {
    if !root.starts_with('/') {
        return Err(Error::Cli(format!(
            "__watch-dir: the root must be an absolute path, got {root:?}"
        )));
    }
    let croot = std::ffi::CString::new(root)
        .map_err(|_| Error::Cli("__watch-dir: the root contains a NUL byte".into()))?;
    let rfd = unsafe {
        libc::open(
            croot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if rfd < 0 {
        return Err(Error::Cli(format!(
            "__watch-dir: cannot open {root:?}: {}",
            std::io::Error::last_os_error()
        )));
    }
    let root_fd = Fd(rfd);
    let ifd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if ifd < 0 {
        return Err(Error::Cli(format!(
            "__watch-dir: inotify_init1 failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut w = Watcher {
        inotify: Fd(ifd),
        root: root_fd,
        recursive,
        dirs: std::collections::HashMap::new(),
        full: false,
    };
    w.add_tree(rel.as_bytes(), None);
    if w.dirs.is_empty() {
        let shown = if rel.is_empty() { "." } else { rel };
        return Err(Error::Cli(format!(
            "__watch-dir: {shown:?} is not a directory in the workspace"
        )));
    }
    let mut stdout = std::io::stdout().lock();
    let say = |out: &mut std::io::StdoutLock, line: &str| -> bool {
        out.write_all(line.as_bytes())
            .and_then(|()| out.write_all(b"\n"))
            .and_then(|()| out.flush())
            .is_ok()
    };
    if !say(&mut stdout, "ready") {
        return Ok(());
    }
    // Whole events; each header is read unaligned (`dispatch`).
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let mut fds = [
            libc::pollfd {
                fd: w.inotify.0,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: 0,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Ok(());
        }
        // The caller closed our stdin, or is gone: the watch ends.
        if fds[1].revents != 0 {
            let mut b = [0u8; 256];
            let n = unsafe { libc::read(0, b.as_mut_ptr().cast(), b.len()) };
            if n <= 0 {
                return Ok(());
            }
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let n = unsafe { libc::read(w.inotify.0, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) {
                    continue;
                }
                return Ok(());
            }
            let n = usize::try_from(n).unwrap_or(0);
            for ev in w.dispatch(buf.get(..n).unwrap_or_default()) {
                if !say(&mut stdout, &ev.line()) {
                    return Ok(());
                }
            }
            if w.dirs.is_empty() {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kern-dirwatch-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    fn watcher(root: &std::path::Path, rel: &str, recursive: bool) -> Watcher {
        let c = std::ffi::CString::new(root.to_str().expect("utf8")).expect("cstr");
        let rfd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        assert!(rfd >= 0);
        let ifd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(ifd >= 0);
        let mut w = Watcher {
            inotify: Fd(ifd),
            root: Fd(rfd),
            recursive,
            dirs: std::collections::HashMap::new(),
            full: false,
        };
        w.add_tree(rel.as_bytes(), None);
        w
    }

    fn drain(w: &mut Watcher) -> Vec<(String, String, Option<String>)> {
        let mut buf = vec![0u8; 64 * 1024];
        let n = unsafe { libc::read(w.inotify.0, buf.as_mut_ptr().cast(), buf.len()) };
        let n = usize::try_from(n).unwrap_or(0);
        w.dispatch(&buf[..n])
            .into_iter()
            .map(|e| {
                (
                    e.kind.to_string(),
                    String::from_utf8_lossy(&e.path).into_owned(),
                    e.old.map(|o| String::from_utf8_lossy(&o).into_owned()),
                )
            })
            .collect()
    }

    #[test]
    fn create_write_rename_chmod_and_a_filled_new_directory_are_each_named() {
        use std::os::unix::fs::PermissionsExt;
        let d = temp("events");
        std::fs::create_dir_all(d.join("data")).expect("mkdir");
        std::fs::write(d.join("data/keep.txt"), "x").expect("write");
        let mut w = watcher(&d, "data", true);
        std::fs::write(d.join("data/a.txt"), "1").expect("write");
        std::fs::rename(d.join("data/a.txt"), d.join("data/b.txt")).expect("rename");
        std::fs::set_permissions(d.join("data/b.txt"), std::fs::Permissions::from_mode(0o600))
            .expect("chmod");
        std::fs::create_dir_all(d.join("data/sub/deep")).expect("mkdir");
        std::fs::write(d.join("data/sub/deep/c.txt"), "2").expect("write");
        std::fs::remove_file(d.join("data/keep.txt")).expect("rm");
        let got = drain(&mut w);
        let has = |k: &str, p: &str, o: Option<&str>| {
            got.iter()
                .any(|(gk, gp, go)| gk == k && gp == p && go.as_deref() == o)
        };
        assert!(has("create", "data/a.txt", None), "{got:?}");
        assert!(has("write", "data/a.txt", None), "{got:?}");
        assert!(has("rename", "data/b.txt", Some("data/a.txt")), "{got:?}");
        assert!(!has("remove", "data/a.txt", None), "{got:?}");
        assert!(has("chmod", "data/b.txt", None), "{got:?}");
        assert!(has("create", "data/sub", None), "{got:?}");
        assert!(has("create", "data/sub/deep/c.txt", None), "{got:?}");
        assert!(has("remove", "data/keep.txt", None), "{got:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_symlink_is_never_watched_or_descended() {
        let d = temp("link");
        let outside = temp("link-outside");
        std::os::unix::fs::symlink(&outside, d.join("link")).expect("symlink");
        assert!(watcher(&d, "link", true).dirs.is_empty());
        assert!(watcher(&d, "../x", true).dirs.is_empty());
        let mut w = watcher(&d, "", true);
        assert_eq!(w.dirs.len(), 1, "only the root: the link is not descended");
        std::fs::write(outside.join("secret.txt"), "host").expect("write");
        assert!(drain(&mut w).iter().all(|(_, p, _)| !p.contains("secret")));
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_line_is_kind_type_and_hex_paths() {
        let mut e = Event::new("rename", b"a b\n".to_vec(), false);
        e.old = Some(b"x".to_vec());
        assert_eq!(e.line(), "rename f 6120620a 78");
        assert_eq!(
            Event::new("overflow", Vec::new(), false).line(),
            "overflow f "
        );
    }
}
