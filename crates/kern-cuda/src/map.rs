//! THE SHARED MAPPING, and the crate's only `unsafe`.
//!
//! [`crate::shared`] is an algorithm over a `&[AtomicU64]` and knows nothing about files. This module
//! produces such a slice from a region of memory that two processes can both see, and does nothing
//! else. Every property of the accounting is proved over a `Vec` in that module's tests; every
//! property of the mapping is proved here. Neither test has to reason about the other's failure
//! modes, which is the whole reason the two are separate files.
//!
//! WHY A FILE AND NOT `shm_open`
//!     POSIX shared memory lands in `/dev/shm`, which is a tmpfs kern's own boxes routinely mount
//!     over, and its objects are not visible in the mount namespace a box lives in unless something
//!     puts them there. A plain file under the runtime directory is visible to exactly the processes
//!     kern intends and disappears with that directory. It is also inspectable: an operator can
//!     `ls -l` it and `hexdump` it, which for a mechanism whose whole purpose is accounting is worth
//!     more than the theoretical tidiness of an anonymous object.
//!
//! THE FAILURE THAT KILLS A PROCESS RATHER THAN RETURNING AN ERROR
//!     Touching a page of a mapping that is beyond the end of the backing file raises SIGBUS, not a
//!     Rust error. There is no way to catch that and no way to unwind from it. The file is therefore
//!     sized with `ftruncate` BEFORE it is mapped and never shortened afterwards, and the mapped
//!     length is taken from the size the file actually has rather than from the size that was asked
//!     for. A file that is shorter than the layout needs is refused at open time, when refusing is
//!     still possible.

use core::sync::atomic::AtomicU64;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use crate::shared::{self, AttachError};

/// Why a mapping could not be established.
///
/// `errno` is carried rather than a message: the caller renders it, and an operator debugging a
/// permissions problem on a runtime directory wants the number their other tools also print.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MapError {
    /// `open` failed.
    Open(i32),
    /// `ftruncate` failed while sizing a newly created file.
    Truncate(i32),
    /// `fstat` failed, so the real length of the file is unknown and mapping it could SIGBUS.
    Stat(i32),
    /// The file exists and is shorter than the layout needs. Refused rather than mapped: mapping it
    /// and touching the far end would raise SIGBUS, which cannot be caught.
    TooShort {
        /// The file's real length in bytes.
        have: u64,
        /// What the layout needs.
        need: u64,
    },
    /// `mmap` failed.
    Mmap(i32),
    /// The kernel returned a mapping that is not aligned for a `u64`. Not reachable in practice,
    /// since `mmap` returns page-aligned addresses, and refused rather than assumed.
    Misaligned,
    /// The segment's own header rejected us. Carries the reason from [`crate::shared`].
    Layout(AttachError),
}

/// A `mmap`ed region, unmapped when dropped.
///
/// Owns the mapping and nothing else: the file descriptor is closed immediately after `mmap`, which
/// is correct and deliberate. A mapping keeps its own reference to the underlying object, so the
/// descriptor is not needed to keep the memory alive, and holding it open would leak one per box.
pub struct Segment {
    ptr: *mut libc::c_void,
    /// Length in BYTES, which is what `munmap` takes. Kept separate from the word count so the two
    /// cannot be confused at the point where confusing them would unmap the wrong amount.
    len: usize,
    words: usize,
}

// SAFETY: the mapping is `MAP_SHARED` and every access to it goes through `AtomicU64`, which is the
// documented way to share memory between threads and, on Linux with a lock-free `AtomicU64`, between
// processes on the same machine. `Segment` itself hands out only `&[AtomicU64]`, so there is no path
// by which a caller obtains a `&mut` to the region and no path by which two accesses to one word are
// non-atomic. Sending the handle to another thread moves a pointer and a length; sharing it lends a
// slice of atomics.
#[allow(unsafe_code)]
unsafe impl Send for Segment {}
#[allow(unsafe_code)]
unsafe impl Sync for Segment {}

impl Segment {
    /// Open or create the segment at `path`, sized for `slots` tenants, and hand back the mapping.
    ///
    /// `created` in the returned pair is `true` when this call is the one that made the file, which
    /// is the caller's signal to call [`crate::shared::init`] on the words before anybody attaches.
    /// It is derived from `O_EXCL` succeeding rather than from an existence check, because an
    /// existence check followed by a create is a race that two boxes starting together will lose:
    /// both would see no file, both would create, and one would zero the other's live segment.
    ///
    /// MODE 0600, not 0666. The segment is shared between processes of ONE user; kern is rootless and
    /// its boxes run as the invoking user. A wider mode would let any account on the host rewrite the
    /// accounting, which does not make the quota a boundary (it never was) but does turn a
    /// cooperative mechanism into one a bystander can break by accident.
    pub fn open(path: &Path, slots: usize) -> Result<(Self, bool), MapError> {
        let need_words = shared::words_for(slots);
        let need_bytes = (need_words * core::mem::size_of::<u64>()) as u64;

        let c_path = path_to_c(path)?;

        // Try to create exclusively first. Success means this process owns initialisation.
        let mut created = true;
        // SAFETY: `c_path` is a NUL-terminated C string that outlives the call, and the flags and
        // mode are constants. `open` returns a descriptor or -1 and touches nothing else.
        #[allow(unsafe_code)]
        let mut fd = unsafe {
            libc::open(
                c_path.as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            let e = errno();
            if e != libc::EEXIST {
                return Err(MapError::Open(e));
            }
            created = false;
            // SAFETY: as above, without O_CREAT.
            #[allow(unsafe_code)]
            {
                fd = unsafe {
                    libc::open(
                        c_path.as_ptr() as *const libc::c_char,
                        libc::O_RDWR | libc::O_CLOEXEC,
                    )
                };
            }
            if fd < 0 {
                return Err(MapError::Open(errno()));
            }
        }
        // SAFETY: `fd` is a descriptor this function just obtained and has not shared. `OwnedFd`
        // closes it on every exit path from here, including the error returns below.
        #[allow(unsafe_code)]
        let fd = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };

        if created {
            // SIZE BEFORE MAP. A mapping longer than its file SIGBUSes on the pages past the end,
            // and SIGBUS cannot be caught or unwound from. `ftruncate` on a fresh file also zeroes
            // it, which is what `shared::init` expects to find.
            // SAFETY: `fd` is open for writing and the length is a positive constant.
            #[allow(unsafe_code)]
            let rc = unsafe { libc::ftruncate(fd.as_raw_fd(), need_bytes as libc::off_t) };
            if rc != 0 {
                let e = errno();
                let _ = std::fs::remove_file(path);
                return Err(MapError::Truncate(e));
            }
        }

        // Map only what the file REALLY has, and refuse if that is less than the layout needs. The
        // size that was asked for is not evidence about the file: another kern build may have made it
        // with a different slot count, and trusting the request over the reality is how a mapping
        // ends up longer than its object.
        // SAFETY: `stat` is written only on success and is a plain POD structure; `fd` is open.
        #[allow(unsafe_code)]
        let real_bytes = unsafe {
            let mut st: libc::stat = core::mem::zeroed();
            if libc::fstat(fd.as_raw_fd(), &mut st) != 0 {
                return Err(MapError::Stat(errno()));
            }
            st.st_size as u64
        };
        if real_bytes < need_bytes {
            return Err(MapError::TooShort {
                have: real_bytes,
                need: need_bytes,
            });
        }
        let len = real_bytes as usize;

        // SAFETY: `len` is the file's own length, so no mapped page is beyond the end of the object
        // and no access can SIGBUS. The address is chosen by the kernel (null hint) and the mapping
        // is MAP_SHARED, which is what makes the atomics visible to other processes.
        #[allow(unsafe_code)]
        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(MapError::Mmap(errno()));
        }
        // The descriptor has done its job: a mapping holds its own reference to the object.
        drop(fd);

        if (ptr as usize) % core::mem::align_of::<AtomicU64>() != 0 {
            // Not reachable: `mmap` returns page-aligned addresses. Checked anyway, because the
            // alternative to checking is an unaligned atomic access, which is undefined behaviour
            // rather than a wrong number.
            // SAFETY: `ptr` and `len` are exactly what `mmap` returned and it has not been unmapped.
            #[allow(unsafe_code)]
            unsafe {
                libc::munmap(ptr, len)
            };
            return Err(MapError::Misaligned);
        }

        Ok((
            Segment {
                ptr,
                len,
                words: len / core::mem::size_of::<u64>(),
            },
            created,
        ))
    }

    /// The mapping as a slice of atomics.
    ///
    /// The lifetime ties the slice to `&self`, so it cannot outlive the mapping, and the element type
    /// is `AtomicU64` rather than `u64`, so a caller has no way to perform a non-atomic access to a
    /// word another process may be writing.
    pub fn words(&self) -> &[AtomicU64] {
        // SAFETY: `ptr` is a live `MAP_SHARED` mapping of `len` bytes, checked above to be aligned
        // for `AtomicU64`, and `words` is `len` divided by the element size, so the slice lies
        // entirely inside the mapping. `AtomicU64` has the same layout as `u64` and permits
        // concurrent access through a shared reference, which is exactly what other processes will
        // be doing to the same pages. The lifetime is bound to `&self`, so the slice cannot outlive
        // the `munmap` in `Drop`.
        #[allow(unsafe_code)]
        unsafe {
            core::slice::from_raw_parts(self.ptr as *const AtomicU64, self.words)
        }
    }

    /// The mapping's length in bytes.
    pub fn len_bytes(&self) -> usize {
        self.len
    }
}

impl Drop for Segment {
    fn drop(&mut self) {
        // SAFETY: `ptr` and `len` are the values `mmap` returned and this is the only place they are
        // unmapped, on a type that is neither `Copy` nor `Clone`, so this runs exactly once.
        #[allow(unsafe_code)]
        unsafe {
            libc::munmap(self.ptr, self.len)
        };
    }
}

/// `errno` for the call that just failed.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// A path as a NUL-terminated byte vector for `open`.
///
/// Returned as bytes and cast at the call site rather than built as `*const c_char` here, because
/// `c_char` is `i8` on x86_64 and `u8` on aarch64: a function that produced one of the two directly
/// would compile on this desktop and fail on every board kern targets.
///
/// Refuses a path containing an interior NUL rather than truncating at it. Truncation is how a path
/// check gets bypassed: a caller validates `/run/user/1000/kern/vram\0/../../etc/passwd`, the
/// validator sees the whole string, and `open` sees only the part before the NUL.
fn path_to_c(path: &Path) -> Result<Vec<u8>, MapError> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&0) {
        return Err(MapError::Open(libc::EINVAL));
    }
    let mut v = Vec::with_capacity(bytes.len() + 1);
    v.extend_from_slice(bytes);
    v.push(0);
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::{Liveness, Shared};
    use core::sync::atomic::Ordering;

    struct AllAlive;
    impl Liveness for AllAlive {
        fn alive(&self, _pid: u64, _start: u64) -> bool {
            true
        }
    }

    /// A temp directory that removes itself, so a failing assertion cannot leave a segment behind for
    /// the next run to attach to and be confused by.
    struct TmpDir(std::path::PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "kern-cuda-map-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            let _ = std::fs::create_dir_all(&p);
            TmpDir(p)
        }
        fn join(&self, n: &str) -> std::path::PathBuf {
            self.0.join(n)
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_fresh_segment_is_created_sized_and_zeroed() {
        let d = TmpDir::new("fresh");
        let p = d.join("vram");
        let (seg, created) = Segment::open(&p, 8).expect("open");
        assert!(
            created,
            "the first open must report that it created the file"
        );
        assert_eq!(
            seg.len_bytes(),
            shared::words_for(8) * 8,
            "the file is sized for exactly the layout"
        );
        assert!(
            seg.words().iter().all(|w| w.load(Ordering::Relaxed) == 0),
            "ftruncate must leave a zeroed file for init to write into"
        );
        assert_eq!(
            std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0),
            seg.len_bytes() as u64
        );
    }

    /// The second opener must NOT report `created`, or it would re-initialise a live segment and
    /// strand every reservation in it.
    #[test]
    fn the_second_open_attaches_instead_of_creating() {
        let d = TmpDir::new("second");
        let p = d.join("vram");
        let (a, created_a) = Segment::open(&p, 4).expect("first");
        assert!(created_a);
        assert_eq!(shared::init(a.words(), 4), Ok(()));
        let sa = Shared::attach(a.words(), 1, 1, &AllAlive).expect("attach a");
        assert_eq!(sa.reserve(1024, 4096), Ok(()));

        let (b, created_b) = Segment::open(&p, 4).expect("second");
        assert!(
            !created_b,
            "an existing file must not be reported as created"
        );
        let sb = Shared::attach(b.words(), 2, 2, &AllAlive).expect("attach b");
        assert_eq!(
            sb.total(),
            1024,
            "the second mapping must see the first's accounting"
        );
    }

    /// THE POINT OF THE WHOLE MODULE: two independent mappings of one file are one piece of memory.
    /// If this failed, every process would have its own private total and the shared quota would be
    /// an elaborate way of doing nothing.
    #[test]
    fn two_mappings_of_one_file_see_each_others_writes() {
        let d = TmpDir::new("coherent");
        let p = d.join("vram");
        let (a, _) = Segment::open(&p, 4).expect("a");
        assert_eq!(shared::init(a.words(), 4), Ok(()));
        let (b, _) = Segment::open(&p, 4).expect("b");

        let sa = Shared::attach(a.words(), 10, 10, &AllAlive).expect("attach a");
        let sb = Shared::attach(b.words(), 20, 20, &AllAlive).expect("attach b");
        assert_ne!(sa.slot(), sb.slot());

        assert_eq!(sa.reserve(4096, 8192), Ok(()));
        assert_eq!(sb.total(), 4096, "b sees a's reservation");
        assert_eq!(
            sb.reserve(8192, 8192),
            Err(crate::Refused::OverQuota {
                held: 4096,
                limit: 8192
            }),
            "b is refused by a's usage, which is the entire purpose"
        );
        sa.release(4096);
        assert_eq!(sb.reserve(8192, 8192), Ok(()), "and capacity comes back");
    }

    /// A file shorter than the layout is refused at open. Mapping it and touching the far end raises
    /// SIGBUS, which cannot be caught, so the check has to happen while refusing is still possible.
    #[test]
    fn a_file_shorter_than_the_layout_is_refused_rather_than_mapped() {
        let d = TmpDir::new("short");
        let p = d.join("vram");
        std::fs::write(&p, [0u8; 64]).expect("write a short file");
        let need = (shared::words_for(8) * 8) as u64;
        // Compared on the ERROR rather than on the whole `Result`: `Segment` owns a raw pointer and
        // is deliberately not `Debug`, so that a mapping cannot be printed into a log by accident.
        assert_eq!(
            Segment::open(&p, 8).err(),
            Some(MapError::TooShort { have: 64, need }),
            "a short file must never be mapped"
        );
    }

    /// A segment made for eight slots, reopened asking for four, must still map its real length
    /// rather than the length that was asked for.
    #[test]
    fn the_mapping_takes_its_length_from_the_file_and_not_from_the_request() {
        let d = TmpDir::new("bigger");
        let p = d.join("vram");
        let (big, _) = Segment::open(&p, 16).expect("create 16");
        let big_len = big.len_bytes();
        drop(big);
        let (small_request, created) = Segment::open(&p, 4).expect("reopen asking 4");
        assert!(!created);
        assert_eq!(
            small_request.len_bytes(),
            big_len,
            "the file's real size wins over the requested one"
        );
    }

    /// An interior NUL is refused rather than silently truncated at, since truncation is how a
    /// validated path turns into a different path by the time `open` sees it.
    #[test]
    fn a_path_with_an_interior_nul_is_refused() {
        use std::os::unix::ffi::OsStrExt;
        let p = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/kern\0/../etc/passwd"));
        assert_eq!(
            Segment::open(&p, 1).err(),
            Some(MapError::Open(libc::EINVAL))
        );
    }

    #[test]
    fn an_unopenable_path_reports_errno_and_does_not_panic() {
        let p = std::path::Path::new("/proc/definitely/not/a/directory/vram");
        match Segment::open(p, 1).err() {
            Some(MapError::Open(e)) => assert!(e != 0, "errno must be carried"),
            other => panic!("expected an Open error, got {other:?}"),
        }
    }

    /// The mapping must survive the descriptor being closed, which it is, immediately after `mmap`.
    /// A mapping holds its own reference to the object; keeping the fd would leak one per box.
    #[test]
    fn the_mapping_outlives_the_descriptor_that_made_it() {
        let d = TmpDir::new("fdclosed");
        let p = d.join("vram");
        let (seg, _) = Segment::open(&p, 2).expect("open");
        assert_eq!(shared::init(seg.words(), 2), Ok(()));
        let s = Shared::attach(seg.words(), 1, 1, &AllAlive).expect("attach");
        assert_eq!(s.reserve(128, 256), Ok(()));
        assert_eq!(
            s.total(),
            128,
            "writing through a mapping whose fd is closed"
        );
    }

    /// The mapping must also survive the FILE being unlinked, because the runtime directory is
    /// cleaned up under running boxes on some hosts. A `mmap`ed object stays alive until the last
    /// mapping goes.
    #[test]
    fn the_mapping_outlives_the_file_being_unlinked() {
        let d = TmpDir::new("unlinked");
        let p = d.join("vram");
        let (seg, _) = Segment::open(&p, 2).expect("open");
        assert_eq!(shared::init(seg.words(), 2), Ok(()));
        let s = Shared::attach(seg.words(), 1, 1, &AllAlive).expect("attach");
        assert_eq!(s.reserve(64, 128), Ok(()));
        std::fs::remove_file(&p).expect("unlink");
        assert_eq!(s.reserve(64, 128), Ok(()), "still writable after unlink");
        assert_eq!(s.total(), 128);
    }

    /// A segment is shared between processes of ONE user. A wider mode would let a bystander account
    /// break it by accident, which does not make the quota a boundary but does make it fragile.
    #[test]
    fn the_segment_is_created_private_to_the_user() {
        use std::os::unix::fs::PermissionsExt;
        let d = TmpDir::new("mode");
        let p = d.join("vram");
        let (_seg, _) = Segment::open(&p, 1).expect("open");
        let mode = std::fs::metadata(&p)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0);
        assert_eq!(
            mode, 0o600,
            "the segment must not be group or world writable"
        );
    }

    /// Concurrent creation: many threads racing to `open` one path. Exactly one must report
    /// `created`, or two of them would initialise the segment and the second would zero the first's
    /// slots. `O_EXCL` is what makes that true; an existence check followed by a create would not.
    #[test]
    fn exactly_one_of_many_racing_creators_reports_created() {
        const N: usize = 12;
        let d = TmpDir::new("race");
        let p = std::sync::Arc::new(d.join("vram"));
        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let p = std::sync::Arc::clone(&p);
            handles.push(std::thread::spawn(move || {
                Segment::open(&p, 4).map(|(seg, created)| {
                    // Keep the mapping alive for the duration, so no unmapping races the others.
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    drop(seg);
                    created
                })
            }));
        }
        let created_count = handles
            .into_iter()
            .filter_map(|h| h.join().ok())
            .filter_map(|r| r.ok())
            .filter(|c| *c)
            .count();
        assert_eq!(
            created_count, 1,
            "exactly one creator, or two would initialise the same segment"
        );
    }
}
