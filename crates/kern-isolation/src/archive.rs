//! The tar archive `kern cp` and a box's `--copy-in` read and write, with every path CONFINED.
//!
//! ONE WRITER AND ONE READER for every copy kern makes: `kern cp` between a box and the host, the
//! Docker API's `/containers/{id}/archive`, and the files a client copies into a container before it
//! starts (written into the box's root before its workload runs). Two copiers would be two answers
//! to "what happens to this symlink", and the answer is a security boundary.
//!
//! CONFINEMENT, the class behind CVE-2019-14271 (`docker cp` following a container symlink out to the
//! host):
//!
//! * the writer opens every entry RELATIVE to its parent's descriptor with `O_NOFOLLOW`, one name at
//!   a time, so a walk never crosses a link: a link is archived as a link;
//! * the reader resolves every member with `openat2` under a [`Confine`]: `InRoot` for a box's root
//!   (the box's own links resolve as the box sees them, never onto the host), `Beneath` for a host
//!   directory (a member, or a link a member goes through, that would leave it is REFUSED);
//! * a member name with a `..` component is refused outright, and a hardlink's target is resolved
//!   as confined as any member.

use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

// `struct open_how` + `openat2` (`<linux/openat2.h>`, Linux 5.6+), nr 437 on every current arch.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
const SYS_OPENAT2: libc::c_long = 437;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;

/// How [`openat2_confined`] keeps a path inside its directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confine {
    /// `RESOLVE_IN_ROOT`: the directory is `/`; an absolute symlink or a `..` lands inside it. For a
    /// box's root, where the box's own links are meant to resolve as the box sees them.
    InRoot,
    /// `RESOLVE_BENEATH`: a path that would leave the directory, by `..` or by any symlink pointing
    /// out of it (an absolute one always does), is REFUSED (`EXDEV`). For a host directory a box's
    /// content is written into, where nothing the box wrote may take the write elsewhere.
    Beneath,
}

/// `openat2` relative to `dir_fd` under `confine`, never through a magic link; `O_CLOEXEC` always.
/// An empty path (or `/`) opens `dir_fd` itself (`.`).
pub fn openat2_confined(
    dir_fd: RawFd,
    path: &[u8],
    flags: i32,
    mode: u32,
    confine: Confine,
) -> std::io::Result<RawFd> {
    let mut rel = path;
    while let [b'/', tail @ ..] = rel {
        rel = tail;
    }
    let rel: &[u8] = if rel.is_empty() { b"." } else { rel };
    let c = cstr(rel)?;
    let how = OpenHow {
        flags: (libc::O_CLOEXEC | flags) as u64,
        mode: u64::from(mode),
        resolve: RESOLVE_NO_MAGICLINKS
            | match confine {
                Confine::InRoot => RESOLVE_IN_ROOT,
                Confine::Beneath => RESOLVE_BENEATH,
            },
    };
    let fd = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            dir_fd,
            c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(fd as RawFd)
    }
}

/// `b` as a C string (`EINVAL` for an interior NUL, which no path can carry).
pub fn cstr(b: &[u8]) -> std::io::Result<CString> {
    CString::new(b).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))
}

/// Take ownership of a descriptor the kernel has just returned.
pub fn owned(fd: RawFd) -> OwnedFd {
    // SAFETY: every caller passes a descriptor it has just been returned by the kernel and owns.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

/// `a/b`, where an empty or `.` `a` is `b` alone.
pub fn join(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a.is_empty() || a == b"." {
        return b.to_vec();
    }
    let mut out = a.to_vec();
    if !out.ends_with(b"/") {
        out.push(b'/');
    }
    out.extend_from_slice(b);
    out
}

/// `fstatat(dir, name, AT_SYMLINK_NOFOLLOW)`, or of `dir` itself when `name` is empty.
pub fn lstat_at(dir: RawFd, name: &CStr) -> std::io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let flags = if name.to_bytes().is_empty() {
        libc::AT_EMPTY_PATH
    } else {
        libc::AT_SYMLINK_NOFOLLOW
    };
    if unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, flags) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st)
}

/// `openat(dir, name, flags | O_NOFOLLOW)`; for an empty `name`, `dir` itself reopened through
/// `/proc/self/fd` (the inode it already names, whatever any path names by now).
pub fn open_at(dir: RawFd, name: &CStr, flags: i32) -> std::io::Result<OwnedFd> {
    let fd = if name.to_bytes().is_empty() {
        let p = cstr(format!("/proc/self/fd/{dir}").as_bytes())?;
        unsafe { libc::open(p.as_ptr(), flags | libc::O_CLOEXEC) }
    } else {
        unsafe {
            libc::openat(
                dir,
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        }
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(owned(fd))
    }
}

/// Is `st` a directory?
pub fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

/// Max bytes one FILE may carry through an archive - a self-DoS guard, not a boundary.
pub const MAX_FILE_BYTES: u64 = 4 << 30; // 4 GiB
/// Max directory depth a walk descends (one descriptor is held per level).
const MAX_DEPTH: usize = 256;

/// One id range of a box's `uid_map`/`gid_map`: `inside outside count`.
#[derive(Clone, Copy, Debug)]
struct IdRange {
    inside: u32,
    outside: u32,
    count: u32,
}

/// How the ids on disk read inside a box (empty: as they are, for a host source).
#[derive(Default, Debug)]
pub struct IdMap {
    uids: Vec<IdRange>,
    gids: Vec<IdRange>,
}

impl IdMap {
    /// The maps of the box whose pid 1 is `pid1`.
    pub fn of_box(pid1: i32) -> IdMap {
        let read = |f: &str| -> Vec<IdRange> {
            std::fs::read_to_string(format!("/proc/{pid1}/{f}"))
                .unwrap_or_default()
                .lines()
                .filter_map(|l| {
                    let mut it = l.split_whitespace().map(|x| x.parse::<u32>().ok());
                    Some(IdRange {
                        inside: it.next()??,
                        outside: it.next()??,
                        count: it.next()??,
                    })
                })
                .collect()
        };
        IdMap {
            uids: read("uid_map"),
            gids: read("gid_map"),
        }
    }

    fn map(ranges: &[IdRange], host: u32) -> u32 {
        if ranges.is_empty() {
            return host;
        }
        ranges
            .iter()
            .find(|r| host >= r.outside && host - r.outside < r.count)
            .map_or(65534, |r| r.inside + (host - r.outside))
    }
}

// ---------------------------------------------------------------------------------------------
// The writer.

struct TarWriter<W: Write> {
    out: W,
    ids: IdMap,
    /// `(dev, inode)` of a multiply-linked file already written, and the name it was written as.
    links: std::collections::HashMap<(u64, u64), Vec<u8>>,
    /// Bytes of file content written, for the caller's summary.
    bytes: u64,
}

fn octal(field: &mut [u8], v: u64) {
    // `len - 1` digits and a NUL, Docker's and GNU tar's shape.
    let digits = field.len() - 1;
    let s = format!("{v:0digits$o}");
    let b = s.as_bytes();
    let b = &b[b.len().saturating_sub(digits)..];
    field[..b.len()].copy_from_slice(b);
    field[digits] = 0;
}

fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
    // `"<len> <key>=<value>\n"`, where `<len>` counts itself.
    let body = key.len() + value.len() + 3;
    let mut len = body + 1;
    while format!("{len}").len() + body != len {
        len += 1;
    }
    let mut r = format!("{len} {key}=").into_bytes();
    r.extend_from_slice(value);
    r.push(b'\n');
    r
}

/// Split `name` into ustar's `prefix` (155) and `name` (100) at a `/`, if it fits.
fn ustar_split(name: &[u8]) -> Option<(&[u8], &[u8])> {
    if name.len() <= 100 {
        return Some((&[], name));
    }
    (0..name.len())
        .rev()
        .filter(|&i| name[i] == b'/')
        .find(|&i| i <= 155 && name.len() - i - 1 <= 100 && name.len() - i > 1)
        .map(|i| (&name[..i], &name[i + 1..]))
}

/// The fields of one ustar header block besides its names.
struct Fields<'a> {
    kind: u8,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u64,
    link: &'a [u8],
}

impl<W: Write> TarWriter<W> {
    fn header(
        &mut self,
        path: &[u8],
        kind: u8,
        size: u64,
        st: &libc::stat,
        link: &[u8],
    ) -> std::io::Result<()> {
        let split = ustar_split(path);
        let mut pax = Vec::new();
        if split.is_none() {
            pax.extend(pax_record("path", path));
        }
        if link.len() > 100 {
            pax.extend(pax_record("linkpath", link));
        }
        if size > 0o77777777777 {
            pax.extend(pax_record("size", size.to_string().as_bytes()));
        }
        if !pax.is_empty() {
            let mut h = [0u8; 512];
            let short = b"././@PaxHeader";
            h[..short.len()].copy_from_slice(short);
            self.block(
                &mut h,
                &Fields {
                    kind: b'x',
                    size: pax.len() as u64,
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    link: b"",
                },
            )?;
            self.out.write_all(&pax)?;
            self.pad(pax.len() as u64)?;
        }
        let mut h = [0u8; 512];
        let (prefix, name) = split.unwrap_or((&[], &path[..path.len().min(100)]));
        h[..name.len()].copy_from_slice(name);
        h[345..345 + prefix.len()].copy_from_slice(prefix);
        let fields = Fields {
            kind,
            size: size.min(0o77777777777),
            mode: st.st_mode & 0o7777,
            uid: IdMap::map(&self.ids.uids, st.st_uid),
            gid: IdMap::map(&self.ids.gids, st.st_gid),
            mtime: st.st_mtime.max(0) as u64,
            link: &link[..link.len().min(100)],
        };
        self.block(&mut h, &fields)
    }

    fn block(&mut self, h: &mut [u8; 512], f: &Fields<'_>) -> std::io::Result<()> {
        octal(&mut h[100..108], u64::from(f.mode));
        octal(&mut h[108..116], u64::from(f.uid).min(0o7777777));
        octal(&mut h[116..124], u64::from(f.gid).min(0o7777777));
        octal(&mut h[124..136], f.size);
        octal(&mut h[136..148], f.mtime.min(0o77777777777));
        h[156] = f.kind;
        h[157..157 + f.link.len()].copy_from_slice(f.link);
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        let s = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(s.as_bytes());
        self.out.write_all(h)
    }

    fn pad(&mut self, n: u64) -> std::io::Result<()> {
        let rem = (n % 512) as usize;
        if rem != 0 {
            self.out.write_all(&[0u8; 512][..512 - rem])?;
        }
        Ok(())
    }

    /// Write the entry `name` of `dir` (already stat'ed as `st`) as `arc`, and below it.
    fn entry(
        &mut self,
        dir: RawFd,
        name: &CStr,
        st: &libc::stat,
        arc: &[u8],
        depth: usize,
    ) -> std::io::Result<()> {
        match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                let fd = open_at(dir, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                if !arc.is_empty() {
                    let mut a = arc.to_vec();
                    a.push(b'/');
                    self.header(&a, b'5', 0, st, b"")?;
                }
                self.children(fd.as_raw_fd(), arc, depth + 1)
            }
            libc::S_IFREG => self.file(dir, name, st, arc),
            libc::S_IFLNK => {
                let mut buf = vec![0u8; libc::PATH_MAX as usize + 1];
                let n = unsafe {
                    libc::readlinkat(dir, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len())
                };
                if n < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                buf.truncate(n as usize);
                self.header(arc, b'2', 0, st, &buf)
            }
            libc::S_IFIFO => self.header(arc, b'6', 0, st, b""),
            _ => {
                eprintln!(
                    "kern cp: skipping {} (a device or a socket is not copied)",
                    String::from_utf8_lossy(arc)
                );
                Ok(())
            }
        }
    }

    fn file(
        &mut self,
        dir: RawFd,
        name: &CStr,
        st: &libc::stat,
        arc: &[u8],
    ) -> std::io::Result<()> {
        let key = (st.st_dev, st.st_ino);
        if st.st_nlink > 1 {
            if let Some(first) = self.links.get(&key).cloned() {
                return self.header(arc, b'1', 0, st, &first);
            }
            self.links.insert(key, arc.to_vec());
        }
        let size = st.st_size.max(0) as u64;
        if size > MAX_FILE_BYTES {
            return Err(std::io::Error::other(format!(
                "{} exceeds the 4 GiB limit per file",
                String::from_utf8_lossy(arc)
            )));
        }
        // O_NONBLOCK: a FIFO swapped in after the stat cannot hang the copy; the type is checked
        // again on the open descriptor, which is what is read.
        let fd = open_at(
            dir,
            name,
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY,
        )?;
        let mut f = std::fs::File::from(fd);
        if !f.metadata()?.file_type().is_file() {
            return Err(std::io::Error::other(format!(
                "{} changed type during the copy",
                String::from_utf8_lossy(arc)
            )));
        }
        self.header(arc, b'0', size, st, b"")?;
        // EXACTLY the size the header promised: a file that grew is cut there, one that shrank is
        // padded with zeros, so the archive stays well-formed either way.
        let mut left = size;
        let mut buf = vec![0u8; 64 * 1024];
        while left > 0 {
            let want = buf.len().min(left as usize);
            let n = f.read(&mut buf[..want])?;
            if n == 0 {
                break;
            }
            self.out.write_all(&buf[..n])?;
            left -= n as u64;
        }
        while left > 0 {
            let n = buf.len().min(left as usize);
            buf[..n].fill(0);
            self.out.write_all(&buf[..n])?;
            left -= n as u64;
        }
        self.bytes += size;
        self.pad(size)
    }

    /// Every entry of the open directory `dir`, in name order, as `<arc>/<name>`.
    fn children(&mut self, dir: RawFd, arc: &[u8], depth: usize) -> std::io::Result<()> {
        if depth > MAX_DEPTH {
            return Err(std::io::Error::other(format!(
                "{} is nested more than {MAX_DEPTH} directories deep",
                String::from_utf8_lossy(arc)
            )));
        }
        let mut names: Vec<CString> = Vec::new();
        // `fdopendir` takes the descriptor over, so it gets a duplicate of its own.
        let dup = unsafe { libc::fcntl(dir, libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let d = unsafe { libc::fdopendir(dup) };
        if d.is_null() {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(dup) };
            return Err(e);
        }
        loop {
            let ent = unsafe { libc::readdir(d) };
            if ent.is_null() {
                break;
            }
            let n = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
            if n.to_bytes() != b"." && n.to_bytes() != b".." {
                names.push(n.to_owned());
            }
        }
        unsafe { libc::closedir(d) };
        names.sort();
        for n in names {
            let st = match lstat_at(dir, &n) {
                Ok(st) => st,
                // Gone between the listing and now: a live box's tree changes under a copy.
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                Err(e) => return Err(e),
            };
            let child = join(arc, n.to_bytes());
            self.entry(dir, &n, &st, &child, depth)?;
        }
        Ok(())
    }

    fn finish(mut self) -> std::io::Result<u64> {
        self.out.write_all(&[0u8; 1024])?;
        self.out.flush()?;
        Ok(self.bytes)
    }
}

/// Write the entry `name` of `dir` (stat'ed as `st`) to `out` as an archive, its top entry named
/// `top`, or (`None`) the CONTENTS of that directory with no entry for the directory itself.
/// Returns the bytes of file content written.
pub fn write_archive<W: Write>(
    dir: RawFd,
    name: &CStr,
    st: &libc::stat,
    top: Option<&[u8]>,
    ids: IdMap,
    out: W,
) -> std::io::Result<u64> {
    let mut w = TarWriter {
        out,
        ids,
        links: std::collections::HashMap::new(),
        bytes: 0,
    };
    match top {
        Some(t) => w.entry(dir, name, st, t, 0)?,
        None => {
            if !is_dir(st) {
                return Err(std::io::Error::other(
                    "the source ends in `/.` and is not a directory",
                ));
            }
            let fd = open_at(dir, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            w.children(fd.as_raw_fd(), b"", 0)?;
        }
    }
    w.finish()
}

// ---------------------------------------------------------------------------------------------
// The reader.

/// A check run on each member that is not a directory, before it is created (the host side's
/// guard against kern's own state); its error stops the extraction.
pub type Guard = Box<dyn Fn(&[u8]) -> std::io::Result<()> + Send + Sync>;

/// Where an archive is written: a directory, how paths are kept inside it, and what is restored.
pub struct Dest {
    /// The directory paths start from: a box's root, or a host destination directory.
    pub base: OwnedFd,
    pub confine: Confine,
    /// Below `base`, where the members go (a box's destination directory; empty on the host).
    pub prefix: Vec<u8>,
    /// The mode bits kept: the set-id bits are dropped on the host.
    pub mode_mask: u32,
    pub guard: Option<Guard>,
}

/// A member path, normalized: no empty or `.` components; `None` when it has a `..`.
pub fn member_path(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    for c in raw.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => return None,
            c => {
                if !out.is_empty() {
                    out.push(b'/');
                }
                out.extend_from_slice(c);
            }
        }
    }
    Some(out)
}

/// A member path (or a hardlink's target) as Docker resolves it against the destination `prefix`:
/// lexically, `..` taking back one component, and refused only when the result is not inside the
/// destination. In a box's root (`clamp_at_root`) a `..` above `/` stays at `/`, as it does there
/// for every path; on the host it is a member leaving the directory, refused. Relative to `prefix`;
/// `None` when it leaves it.
///
/// MEASURED against Docker 29 (`docker cp - c:<dest> < archive`): `../../tmp/x` into `/` lands at
/// `/tmp/x`, into `/opt` is refused (`"../../tmp/x" is outside of "/opt"`), and `a/../b` is `b`.
/// kern refused every `..`, so an archive Docker extracts into `/` failed whole.
pub fn member_under(prefix: &[u8], raw: &[u8], clamp_at_root: bool) -> Option<Vec<u8>> {
    let parts = |p: &[u8]| -> Vec<Vec<u8>> {
        p.split(|&b| b == b'/')
            .filter(|c| !c.is_empty() && *c != b".")
            .map(<[u8]>::to_vec)
            .collect()
    };
    let base = parts(prefix);
    if base.iter().any(|c| c == b"..") {
        return None;
    }
    let mut at = base.clone();
    for c in parts(raw) {
        if c == b".." {
            if at.pop().is_none() && !clamp_at_root {
                return None;
            }
        } else {
            at.push(c);
        }
    }
    if at.len() < base.len() || at[..base.len()] != base[..] {
        return None;
    }
    Some(at[base.len()..].join(&b'/'))
}

fn parse_octal(f: &[u8]) -> u64 {
    // GNU's base-256 for a value that does not fit the octal field.
    if f.first().is_some_and(|b| b & 0x80 != 0) {
        return f[1..].iter().fold(0u64, |a, &b| (a << 8) | u64::from(b));
    }
    f.iter()
        .skip_while(|&&b| b == b' ' || b == 0)
        .take_while(|&&b| (b'0'..=b'7').contains(&b))
        .fold(0u64, |a, &b| (a << 3) | u64::from(b - b'0'))
}

fn cfield(f: &[u8]) -> &[u8] {
    let end = f.iter().position(|&b| b == 0).unwrap_or(f.len());
    &f[..end]
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut off = 0;
    while off < buf.len() {
        let n = r.read(&mut buf[off..])?;
        if n == 0 {
            if off == 0 {
                return Ok(false);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the archive ends inside a block",
            ));
        }
        off += n;
    }
    Ok(true)
}

fn skip<R: Read>(r: &mut R, mut n: u64) -> std::io::Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    while n > 0 {
        let want = buf.len().min(n as usize);
        if !read_full(r, &mut buf[..want])? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the archive ends inside a member",
            ));
        }
        n -= want as u64;
    }
    Ok(())
}

fn padded(n: u64) -> u64 {
    n.div_ceil(512) * 512
}

fn bad(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

fn set_times(fd: RawFd, mtime: i64) {
    let t = libc::timespec {
        tv_sec: mtime,
        tv_nsec: 0,
    };
    let times = [t, t];
    unsafe { libc::futimens(fd, times.as_ptr()) };
}

impl Dest {
    fn full(&self, member: &[u8]) -> Vec<u8> {
        join(&self.prefix, member)
    }

    fn open_dir(&self, rel: &[u8]) -> std::io::Result<OwnedFd> {
        let fd = openat2_confined(
            self.base.as_raw_fd(),
            &self.full(rel),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
            self.confine,
        )?;
        Ok(owned(fd))
    }

    /// Create the directory `rel` (below the prefix) and its parents, each step confined.
    fn make_dirs(&self, rel: &[u8]) -> std::io::Result<()> {
        let mut built: Vec<u8> = Vec::new();
        for c in rel.split(|&b| b == b'/').filter(|c| !c.is_empty()) {
            let at = self.open_dir(&built)?;
            let cn = cstr(c)?;
            if unsafe { libc::mkdirat(at.as_raw_fd(), cn.as_ptr(), 0o755) } != 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EEXIST) {
                    return Err(e);
                }
            }
            built = join(&built, c);
        }
        Ok(())
    }

    /// Make the prefix itself, with its parents, from the base (for a box's `--copy-in`, whose
    /// destination the image may not have).
    pub fn make_prefix(&self) -> std::io::Result<()> {
        let mut built: Vec<u8> = Vec::new();
        for c in self.prefix.split(|&b| b == b'/').filter(|c| !c.is_empty()) {
            let fd = openat2_confined(
                self.base.as_raw_fd(),
                &built,
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
                self.confine,
            )?;
            let at = owned(fd);
            let cn = cstr(c)?;
            if unsafe { libc::mkdirat(at.as_raw_fd(), cn.as_ptr(), 0o755) } != 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EEXIST) {
                    return Err(e);
                }
            }
            built = join(&built, c);
        }
        Ok(())
    }

    /// The directory `member` goes in, opened confined, created with its parents if missing.
    fn parent_of(&self, member: &[u8]) -> std::io::Result<(OwnedFd, CString)> {
        let (dir, name) = match member.iter().rposition(|&b| b == b'/') {
            Some(i) => (&member[..i], &member[i + 1..]),
            None => (&b""[..], member),
        };
        self.make_dirs(dir)?;
        Ok((self.open_dir(dir)?, cstr(name)?))
    }

    /// Clear the way for a non-directory `name` in `dir`: whatever non-directory is there goes, a
    /// directory there is an error (Docker's "cannot overwrite directory with non-directory").
    fn make_room(&self, dir: RawFd, name: &CStr, shown: &[u8]) -> std::io::Result<()> {
        match lstat_at(dir, name) {
            Ok(st) if is_dir(&st) => Err(bad(format!(
                "cannot overwrite the directory {} with a non-directory",
                String::from_utf8_lossy(shown)
            ))),
            Ok(_) => {
                if unsafe { libc::unlinkat(dir, name.as_ptr(), 0) } != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn check(&self, member: &[u8]) -> std::io::Result<()> {
        match &self.guard {
            Some(g) => g(member),
            None => Ok(()),
        }
    }

    fn write_file<R: Read>(
        &self,
        r: &mut R,
        member: &[u8],
        size: u64,
        mode: u32,
        mtime: i64,
    ) -> std::io::Result<()> {
        if size > MAX_FILE_BYTES {
            return Err(bad(format!(
                "{} exceeds the 4 GiB limit per file",
                String::from_utf8_lossy(member)
            )));
        }
        self.check(member)?;
        let (dir, name) = self.parent_of(member)?;
        self.make_room(dir.as_raw_fd(), &name, member)?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut f = std::fs::File::from(owned(fd));
        let mut buf = vec![0u8; 64 * 1024];
        let mut left = size;
        // A BLOCK OF ZEROS IS A HOLE, NOT A WRITE: a tar carries a sparse file whole, and writing
        // it out filled the disk with its zeros. MEASURED: a 1 GiB file holding 1 MiB of data took
        // 1048580 KiB on the destination after `kern cp` and after `docker cp` alike. Each 64 KiB
        // block that is all zero is skipped with a seek, and the length is set at the end, so the
        // file reads back the same and takes the space its data takes.
        let mut holes = false;
        while left > 0 {
            let want = buf.len().min(left as usize);
            if !read_full(r, &mut buf[..want])? {
                return Err(bad("the archive ends inside a file".into()));
            }
            if buf[..want].iter().all(|&b| b == 0) {
                use std::io::Seek;
                f.seek(std::io::SeekFrom::Current(want as i64))?;
                holes = true;
            } else {
                f.write_all(&buf[..want])?;
            }
            left -= want as u64;
        }
        if holes {
            f.set_len(size)?;
        }
        unsafe { libc::fchmod(f.as_raw_fd(), mode) };
        set_times(f.as_raw_fd(), mtime);
        Ok(())
    }

    fn make_dir(&self, member: &[u8]) -> std::io::Result<()> {
        let (dir, name) = self.parent_of(member)?;
        if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) } == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EEXIST) {
            return Err(e);
        }
        match lstat_at(dir.as_raw_fd(), &name) {
            Ok(st) if is_dir(&st) => Ok(()),
            _ => {
                self.make_room(dir.as_raw_fd(), &name, member)?;
                if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            }
        }
    }

    fn make_symlink(&self, member: &[u8], target: &[u8]) -> std::io::Result<()> {
        self.check(member)?;
        let (dir, name) = self.parent_of(member)?;
        self.make_room(dir.as_raw_fd(), &name, member)?;
        let t = cstr(target)?;
        if unsafe { libc::symlinkat(t.as_ptr(), dir.as_raw_fd(), name.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn make_hardlink(&self, member: &[u8], target: &[u8]) -> std::io::Result<()> {
        self.check(member)?;
        let target = member_under(&self.prefix, target, self.confine == Confine::InRoot)
            .ok_or_else(|| {
                bad(format!(
                    "the archive's hardlink {} leaves the destination",
                    String::from_utf8_lossy(target)
                ))
            })?;
        // The link's target, resolved as confined as any member: never a file outside.
        let src = owned(openat2_confined(
            self.base.as_raw_fd(),
            &self.full(&target),
            libc::O_PATH | libc::O_NOFOLLOW,
            0,
            self.confine,
        )?);
        let (dir, name) = self.parent_of(member)?;
        self.make_room(dir.as_raw_fd(), &name, member)?;
        let via = cstr(format!("/proc/self/fd/{}", src.as_raw_fd()).as_bytes())?;
        if unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                via.as_ptr(),
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn make_fifo(&self, member: &[u8], mode: u32) -> std::io::Result<()> {
        self.check(member)?;
        let (dir, name) = self.parent_of(member)?;
        self.make_room(dir.as_raw_fd(), &name, member)?;
        if unsafe { libc::mkfifoat(dir.as_raw_fd(), name.as_ptr(), mode) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// The extended header state that applies to the next member.
#[derive(Default)]
struct Pending {
    long_name: Option<Vec<u8>>,
    long_link: Option<Vec<u8>>,
    pax_path: Option<Vec<u8>>,
    pax_link: Option<Vec<u8>>,
    pax_size: Option<u64>,
}

impl Pending {
    fn read_pax(&mut self, data: &[u8]) -> std::io::Result<()> {
        let mut rest = data;
        while !rest.is_empty() {
            let Some(sp) = rest.iter().position(|&b| b == b' ') else {
                break;
            };
            let len = std::str::from_utf8(&rest[..sp])
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|&l| l > sp && l <= rest.len())
                .ok_or_else(|| bad("the archive has a corrupt PAX record".into()))?;
            let rec = &rest[sp + 1..len];
            let rec = rec.strip_suffix(b"\n").unwrap_or(rec);
            if let Some(eq) = rec.iter().position(|&b| b == b'=') {
                let (k, v) = (&rec[..eq], &rec[eq + 1..]);
                match k {
                    b"path" => self.pax_path = Some(v.to_vec()),
                    b"linkpath" => self.pax_link = Some(v.to_vec()),
                    b"size" => {
                        self.pax_size = std::str::from_utf8(v).ok().and_then(|s| s.parse().ok())
                    }
                    _ => {}
                }
            }
            rest = &rest[len..];
        }
        Ok(())
    }
}

/// Extract the archive `r` under `dest`. Returns the bytes of file content written.
pub fn read_archive<R: Read>(r: &mut R, dest: &Dest) -> std::io::Result<u64> {
    let mut block = [0u8; 512];
    let mut pending = Pending::default();
    let mut dirs: Vec<(Vec<u8>, u32, i64)> = Vec::new();
    let mut written = 0u64;
    loop {
        if !read_full(r, &mut block)? || block.iter().all(|&b| b == 0) {
            break;
        }
        let stored = parse_octal(&block[148..156]);
        let mut h = block;
        h[148..156].copy_from_slice(b"        ");
        let unsigned: u64 = h.iter().map(|&b| u64::from(b)).sum();
        let signed: i64 = h.iter().map(|&b| i64::from(b as i8)).sum();
        if stored != unsigned && stored as i64 != signed {
            return Err(bad("the archive has a corrupt header (checksum)".into()));
        }
        let kind = block[156];
        let size = pending
            .pax_size
            .take()
            .unwrap_or_else(|| parse_octal(&block[124..136]));
        let mode = parse_octal(&block[100..108]) as u32 & dest.mode_mask;
        let mtime = parse_octal(&block[136..148]) as i64;
        if matches!(kind, b'x' | b'g' | b'L' | b'K') {
            if size > 1 << 20 {
                return Err(bad("the archive has an extended header over 1 MiB".into()));
            }
            let mut data = vec![0u8; padded(size) as usize];
            if !read_full(r, &mut data)? {
                return Err(bad("the archive ends inside a header".into()));
            }
            data.truncate(size as usize);
            match kind {
                b'L' => pending.long_name = Some(cfield(&data).to_vec()),
                b'K' => pending.long_link = Some(cfield(&data).to_vec()),
                b'x' => pending.read_pax(&data)?,
                _ => {}
            }
            continue;
        }
        let raw_name = match (pending.pax_path.take(), pending.long_name.take()) {
            (Some(p), _) | (None, Some(p)) => p,
            (None, None) => {
                let name = cfield(&block[0..100]);
                let prefix = cfield(&block[345..500]);
                if &block[257..262] == b"ustar" && !prefix.is_empty() {
                    join(prefix, name)
                } else {
                    name.to_vec()
                }
            }
        };
        let link = match (pending.pax_link.take(), pending.long_link.take()) {
            (Some(l), _) | (None, Some(l)) => l,
            (None, None) => cfield(&block[157..257]).to_vec(),
        };
        let member = member_under(&dest.prefix, &raw_name, dest.confine == Confine::InRoot)
            .ok_or_else(|| {
                bad(format!(
                    "the archive member {} is outside of the destination",
                    String::from_utf8_lossy(&raw_name)
                ))
            })?;
        let regular = matches!(kind, b'0' | 0 | b'7');
        if member.is_empty() {
            // The destination directory itself (`./`): it exists; nothing to create.
            skip(r, padded(if regular { size } else { 0 }))?;
            continue;
        }
        match kind {
            b'5' => {
                dest.make_dir(&member)?;
                dirs.push((member, mode, mtime));
            }
            b'0' | 0 | b'7' => {
                dest.write_file(r, &member, size, mode, mtime)?;
                skip(r, padded(size) - size)?;
                written += size;
                continue;
            }
            b'2' => dest.make_symlink(&member, &link)?,
            b'1' => dest.make_hardlink(&member, &link)?,
            b'6' => dest.make_fifo(&member, mode)?,
            _ => eprintln!(
                "kern cp: skipping {} (a device is not created)",
                String::from_utf8_lossy(&member)
            ),
        }
        skip(r, padded(if regular { size } else { 0 }))?;
    }
    // Directory modes and times LAST, deepest first: a read-only directory set at once would refuse
    // its own children, and every child written would move its mtime.
    dirs.sort_by_key(|d| std::cmp::Reverse(d.0.len()));
    for (member, mode, mtime) in dirs {
        if let Ok(fd) = dest.open_dir(&member) {
            unsafe { libc::fchmod(fd.as_raw_fd(), mode) };
            set_times(fd.as_raw_fd(), mtime);
        }
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kern-arc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("tmp");
        d
    }

    fn host_dest(dir: &std::path::Path) -> Dest {
        Dest {
            base: OwnedFd::from(std::fs::File::open(dir).expect("open dest")),
            confine: Confine::Beneath,
            prefix: Vec::new(),
            mode_mask: 0o1777,
            guard: None,
        }
    }

    fn archive_of(dir: &std::path::Path, name: &str, top: Option<&[u8]>) -> Vec<u8> {
        let d = std::fs::File::open(dir).expect("open src parent");
        let n = cstr(name.as_bytes()).expect("name");
        let st = lstat_at(d.as_raw_fd(), &n).expect("stat");
        let mut tar = Vec::new();
        write_archive(d.as_raw_fd(), &n, &st, top, IdMap::default(), &mut tar).expect("write");
        tar
    }

    /// A tree through the writer and the reader: a file, its hardlink, a relative and an absolute
    /// symlink kept as links, a nested directory with its mode, and a name past ustar's 100 bytes.
    #[test]
    fn a_tree_round_trips_through_the_archive_links_as_links() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let src = tmp("src");
        let d = src.join("d");
        std::fs::create_dir_all(d.join("sub")).expect("mkdir");
        std::fs::write(d.join("f"), b"dati\n").expect("write");
        std::fs::hard_link(d.join("f"), d.join("hard")).expect("link");
        std::os::unix::fs::symlink("/etc/passwd", d.join("abs")).expect("symlink");
        std::os::unix::fs::symlink("f", d.join("rel")).expect("symlink");
        std::fs::set_permissions(d.join("sub"), std::fs::Permissions::from_mode(0o750))
            .expect("chmod");
        let long = "n".repeat(150);
        std::fs::write(d.join("sub").join(&long), b"long").expect("write");
        let tar = archive_of(&src, "d", Some(b"d"));
        let out = tmp("out");
        let n = read_archive(&mut tar.as_slice(), &host_dest(&out)).expect("read archive");
        assert_eq!(n, 5 + 4, "the hardlink's bytes are not written twice");
        let o = out.join("d");
        assert_eq!(std::fs::read(o.join("f")).expect("f"), b"dati\n");
        assert_eq!(
            std::fs::read_link(o.join("abs")).expect("abs"),
            std::path::PathBuf::from("/etc/passwd")
        );
        assert_eq!(
            std::fs::read_link(o.join("rel")).expect("rel"),
            std::path::PathBuf::from("f")
        );
        assert_eq!(
            std::fs::metadata(o.join("f")).expect("f").ino(),
            std::fs::metadata(o.join("hard")).expect("hard").ino(),
            "a hardlink stays one"
        );
        assert_eq!(
            std::fs::metadata(o.join("sub"))
                .expect("sub")
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
        assert_eq!(
            std::fs::read(o.join("sub").join(&long)).expect("long"),
            b"long"
        );
        // `None`: the contents, with no entry for the directory itself.
        let tar = archive_of(&src, "d", None);
        let flat = tmp("flat");
        read_archive(&mut tar.as_slice(), &host_dest(&flat)).expect("read");
        assert!(flat.join("f").is_file() && !flat.join("d").exists());
        // GNU tar reads what this writes.
        let gnu = std::process::Command::new("tar")
            .args(["-tf", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn();
        if let Ok(mut child) = gnu {
            let tar = archive_of(&src, "d", Some(b"d"));
            if let Some(mut i) = child.stdin.take() {
                let _ = i.write_all(&tar);
            }
            let out = child.wait_with_output().expect("tar -t");
            let listing = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success(),
                "GNU tar refused the archive: {listing}"
            );
            assert!(listing.contains(&format!("d/sub/{long}")), "{listing}");
        }
        for p in [src, out, flat] {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    /// A file mostly of zeros comes out with its holes: the same bytes, a fraction of the blocks.
    #[test]
    fn a_sparse_file_keeps_its_holes_through_the_archive() {
        use std::io::{Seek, Write};
        use std::os::unix::fs::MetadataExt;
        let src = tmp("sparse-src");
        let d = src.join("d");
        std::fs::create_dir_all(&d).expect("mkdir");
        let mut f = std::fs::File::create(d.join("s")).expect("create");
        f.seek(std::io::SeekFrom::Start(8 << 20)).expect("seek");
        f.write_all(b"tail").expect("write");
        drop(f);
        std::fs::write(d.join("zeros-at-end"), vec![0u8; 256 << 10]).expect("write");
        let tar = archive_of(&src, "d", Some(b"d"));
        let out = tmp("sparse-out");
        read_archive(&mut tar.as_slice(), &host_dest(&out)).expect("read archive");
        let o = out.join("d");
        let m = std::fs::metadata(o.join("s")).expect("s");
        assert_eq!(m.len(), (8 << 20) + 4);
        assert!(
            m.blocks() * 512 < 1 << 20,
            "{} bytes allocated",
            m.blocks() * 512
        );
        let back = std::fs::read(o.join("s")).expect("read");
        assert!(back[..8 << 20].iter().all(|&b| b == 0) && &back[8 << 20..] == b"tail");
        // A file that ENDS in zeros still has its length.
        assert_eq!(
            std::fs::metadata(o.join("zeros-at-end")).expect("z").len(),
            256 << 10
        );
        for p in [src, out] {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    /// Docker's resolution of a member against the destination, case by case as measured on
    /// Docker 29: into a box's `/` a `..` above the root stays at the root; into `/opt` a member
    /// that leaves `/opt` is refused; inside the destination `a/../b` is `b`; on the host any exit
    /// from the directory is refused.
    #[test]
    fn a_member_resolves_against_the_destination_as_docker_resolves_it() {
        let m = |prefix: &str, raw: &str, root: bool| {
            member_under(prefix.as_bytes(), raw.as_bytes(), root)
                .map(|v| String::from_utf8_lossy(&v).into_owned())
        };
        assert_eq!(m("/", "../../../../tmp/x", true).as_deref(), Some("tmp/x"));
        assert_eq!(m("", "../x", true).as_deref(), Some("x"));
        assert_eq!(m("/", "a/../../x", true).as_deref(), Some("x"));
        assert_eq!(m("/opt", "../x", true), None);
        assert_eq!(m("/opt", "a/../../x", true), None);
        assert_eq!(m("/opt", "../opt/x", true).as_deref(), Some("x"));
        assert_eq!(m("/opt", "a/../b", true).as_deref(), Some("b"));
        assert_eq!(m("/opt", "/abs/x", true).as_deref(), Some("abs/x"));
        assert_eq!(m("", "../escaped", false), None);
        assert_eq!(m("", "a/../../x", false), None);
        assert_eq!(m("", "a/../b", false).as_deref(), Some("b"));
        assert_eq!(m("", "./", false).as_deref(), Some(""));
        assert_eq!(
            m("/x/../y", "f", true),
            None,
            "a destination with `..` is not resolved"
        );
    }

    /// What a hostile box can put in an archive does not leave a host destination: a `..` member,
    /// a symlink to the outside followed by a member written through it, a hardlink to outside.
    #[test]
    fn an_archive_cannot_write_outside_the_host_destination() {
        let outside = tmp("outside");
        std::fs::write(outside.join("secret"), b"s").expect("write");
        let target = outside.to_string_lossy().into_owned();
        let build = |entries: &[(&[u8], u8, &[u8])]| -> Vec<u8> {
            let mut w = TarWriter {
                out: Vec::new(),
                ids: IdMap::default(),
                links: std::collections::HashMap::new(),
                bytes: 0,
            };
            let st: libc::stat = unsafe { std::mem::zeroed() };
            for (name, kind, link) in entries {
                w.header(name, *kind, 0, &st, link).expect("header");
            }
            w.out.write_all(&[0u8; 1024]).expect("end");
            w.out
        };
        let cases: Vec<Vec<u8>> = vec![
            build(&[(b"esc", b'2', target.as_bytes()), (b"esc/pwned", b'0', b"")]),
            build(&[(b"../escaped", b'0', b"")]),
            build(&[(b"h", b'1', format!("../{}/secret", target).as_bytes())]),
            build(&[(b"up", b'2', b"../.."), (b"up/escaped2", b'0', b"")]),
        ];
        for (i, tar) in cases.iter().enumerate() {
            let out = tmp(&format!("dest{i}"));
            let r = read_archive(&mut tar.as_slice(), &host_dest(&out));
            assert!(r.is_err(), "case {i}: the archive was extracted");
            let _ = std::fs::remove_dir_all(out);
        }
        assert!(
            !outside.join("pwned").exists(),
            "a write left the destination"
        );
        let _ = std::fs::remove_dir_all(outside);
    }
}
