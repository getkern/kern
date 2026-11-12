//! THE PURE GPU RESOLVER: a root goes in, a [`GpuGrant`] comes out, and nothing is touched.
//!
//! This module computes what a box would need for a GPU. It mounts nothing, starts nothing and
//! changes no process state. Every function here is a function of its arguments, so the whole
//! surface is testable on a synthetic tree with no GPU, no driver and no privileges, which is the
//! point: if this part needs hardware, every phase after it needs hardware too, and three hosts
//! cannot keep a CI green.
//!
//! THE ROOT IS A PARAMETER, in the shape `outer_memory_high_under` already uses in `kern-isolation`:
//! the public entry point passes `/`, and the `_under` form takes the root so a test can build a
//! tree anywhere. Nothing in this file reads an absolute path that the caller did not derive from
//! the root it was given.
//!
//! WHAT WAS MEASURED BEFORE A LINE OF THIS WAS WRITTEN, on this host (two RTX 5060 Ti, driver
//! 580.173.02, kernel 7.0.0-38), because three of the four decisions below were wrong on the first
//! reading and only the measurement corrected them:
//!
//! 1. **A box carries no supplementary group.** `getgroups()` is empty in a default box and after
//!    `--user`. A node reachable only through a group is therefore unreachable from a box.
//!
//! 2. **An inherited kgid that is NOT mapped still counts for permission checks.** In a user
//!    namespace where `setgroups` was never called, the caller's 14 groups are all displayed as
//!    `65534` and `getgroups()` cannot name any of them, yet `/dev/ttyS0` (`root:dialout 0660`, no
//!    ACL) OPENS. So "keep the groups" is a real option and not a figure of speech.
//!
//! 3. **`setgroups` cannot put a host group back.** Inside a box the call with the grant's gid
//!    SUCCEEDS, because that number is mapped, and grants nothing: the box's `gid_map` is
//!    `0 1000 1` plus `1 100000 65536`, so in-box gid 20 is kgid 100019 and not the host's
//!    `dialout`. `/dev/ttyS0` stays `EACCES` after the call. The first call also destroys the
//!    inherited set, and there is no way back. So the policy is KEEP or REFUSE, never merge, and
//!    [`GroupPolicy`] has no third variant for a thing the kernel will not do.
//!
//! 4. **Keep is all-or-nothing.** Not calling `setgroups` keeps every inherited kgid, not the one
//!    the grant wants. On this host that set reaches the raw disk, the docker socket and
//!    `/dev/kvm`, to grant two render nodes. The resolver therefore reports WHICH gids a node
//!    needs, and never implies that keeping them is narrow.
//!
//! THE LIBRARY SET IS COMPUTED, NOT LISTED. The driver version is read from the root's
//! `proc/driver/nvidia/version` and every file carrying that exact suffix in the linker's
//! directories joins the grant. Two failure modes were found by measuring rather than by reading,
//! and both are closed here with a test each:
//!
//!   * **The version line has more than one shape.** The open kernel module writes
//!     `NVIDIA UNIX Open Kernel Module for x86_64  580.173.02  Release Build`, which a parser keyed
//!     on the position after `Kernel Module` reads as the empty string. [`driver_version_from`]
//!     keys on the PATTERN, the first `N.N.N` token on the line, and a test carries both shapes.
//!
//!   * **One directory is reachable by two paths, and the naive count doubles.** `/lib` is a
//!     symlink to `/usr/lib` on a usrmerge host, so a sweep over the linker's directories finds
//!     `libcuda.so.580.173.02` twice with `dev=66307 ino=41944022` both times. Counting paths gives
//!     96 libraries on this host; counting identities gives **29**, which is the figure the plan
//!     carries. The sweep deduplicates on `(dev, ino)`, the same way the SDK's workspace accounting
//!     already deduplicates hard links.
//!
//!   * **A 32-bit library is not a candidate for a 64-bit box.** The i386 tree carries the same
//!     names with the same suffix. Each candidate's ELF class is read from byte 4 of its header and
//!     compared with the class the grant is being built for.
//!
//! ALLOCATION NOTE, in the same terms the detection module states it. This path allocates: it
//! returns owned paths and strings. The project's no-heap rule governs the per-box hot path where a
//! box starts in ~2.3 ms. The resolver is not on that path in S1 at all, because nothing calls it
//! from box startup yet; it exists to be printed and tested. When a later phase does call it, the
//! cost is a sweep of a handful of directories, and the number that matters will be measured then
//! rather than guessed now.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The file the NVIDIA kernel module publishes its version in, relative to the root.
const DRIVER_VERSION_REL: &str = "proc/driver/nvidia/version";

/// The linker's configuration file, relative to the root.
const LD_SO_CONF_REL: &str = "etc/ld.so.conf";

/// Directories the dynamic linker searches without being told, relative to the root. A host that
/// lists them in `ld.so.conf` too is harmless: the sweep deduplicates by identity.
const DEFAULT_LIB_DIRS: [&str; 6] = [
    "lib/x86_64-linux-gnu",
    "usr/lib/x86_64-linux-gnu",
    "lib64",
    "usr/lib64",
    "lib",
    "usr/lib",
];

/// How deep `include` directives in `ld.so.conf` are followed. The format allows a glob that can
/// name a file which includes again; a bound makes a cycle finite instead of fatal.
const MAX_LD_CONF_DEPTH: u8 = 4;

/// `EI_CLASS` values from the ELF header's fifth byte.
const ELF_CLASS_32: u8 = 1;
const ELF_CLASS_64: u8 = 2;

/// The first four bytes of any ELF file.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// POSIX ACL tags, from `<sys/acl.h>`. Only the two that carry an id are named, because only those
/// two change the answer: an `ACL_USER` entry is a uid path and survives a box, an `ACL_GROUP`
/// entry is a group path and does not.
const ACL_USER: u16 = 0x0002;
const ACL_GROUP: u16 = 0x0008;
const ACL_MASK: u16 = 0x0010;

/// The version word at the head of `system.posix_acl_access`.
const ACL_XATTR_VERSION: u32 = 2;

/// The ACL entry's permission bits, in the xattr's own encoding.
const ACL_READ: u16 = 0x04;
const ACL_WRITE: u16 = 0x02;

/// The architecture a grant is being built for. The box inherits the host's architecture, so this
/// is not a choice the caller makes; it is recorded so the library sweep can reject the other tree
/// rather than silently mount a library the loader will refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass {
    /// 32-bit objects (`EI_CLASS` 1).
    Bits32,
    /// 64-bit objects (`EI_CLASS` 2).
    Bits64,
}

impl ElfClass {
    /// The class this binary was compiled for, which is the class a box on this host needs.
    pub const fn native() -> Self {
        if cfg!(target_pointer_width = "64") {
            ElfClass::Bits64
        } else {
            ElfClass::Bits32
        }
    }
}

/// The invoking user, as the permission check sees them.
///
/// `gids` is the whole supplementary set INCLUDING the primary gid, because the kernel's check does
/// not distinguish them: the group class matches if any of them equals the file's gid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The real uid the kernel checks against the owner and against `ACL_USER` entries.
    pub uid: u32,
    /// Every gid the process carries, primary first by convention and unordered in effect.
    pub gids: Vec<u32>,
}

impl Caller {
    /// The caller this process is, read from the kernel rather than from the environment.
    ///
    /// `getgroups` is asked twice, once for the count and once for the data, which is the documented
    /// form. A count that grows between the two calls is handled by trusting the second return
    /// value rather than the first, so a race widens nothing.
    pub fn current() -> Self {
        let uid = unsafe { libc::getuid() } as u32;
        let mut gids: Vec<u32> = Vec::new();

        let needed = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if needed > 0 {
            let mut buffer: Vec<libc::gid_t> = vec![0; needed as usize];
            let got = unsafe { libc::getgroups(needed, buffer.as_mut_ptr()) };
            if got > 0 {
                let got = (got as usize).min(buffer.len());
                gids.extend(buffer[..got].iter().copied());
            }
        }
        let primary = unsafe { libc::getgid() } as u32;
        if !gids.contains(&primary) {
            gids.push(primary);
        }
        Caller { uid, gids }
    }

    /// Whether the caller is in the group class for a file owned by `gid`.
    fn in_group(&self, gid: u32) -> bool {
        self.gids.contains(&gid)
    }
}

/// What the kernel knows about one node, reduced to the fields the decision turns on.
///
/// This is a VALUE, not a path, which is what makes [`access_path`] a pure function over a finite
/// input space: a test enumerates the space without creating a single file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeFacts {
    /// The owning uid.
    pub uid: u32,
    /// The owning gid.
    pub gid: u32,
    /// The permission bits, the low nine of `st_mode`.
    pub mode: u32,
    /// uids named by an `ACL_USER` entry that grants at least read.
    pub acl_users: Vec<u32>,
    /// gids named by an `ACL_GROUP` entry that grants at least read.
    pub acl_groups: Vec<u32>,
    /// Whether an `ACL_MASK` entry exists and denies read to the whole group class. When a mask is
    /// present it bounds every group-class entry, so a mask without read makes the group path dead
    /// whatever the individual entries say.
    pub acl_mask_denies_read: bool,
}

impl NodeFacts {
    /// The `other` class grants read.
    fn other_reads(&self) -> bool {
        self.mode & 0o004 != 0
    }

    /// The `owner` class grants read.
    fn owner_reads(&self) -> bool {
        self.mode & 0o400 != 0
    }

    /// The `group` class grants read, before the ACL mask is applied.
    fn group_reads(&self) -> bool {
        self.mode & 0o040 != 0
    }
}

/// How a caller reaches a node, and therefore whether a box still reaches it.
///
/// The order of the variants is the order the kernel decides in, and it matters: the owner class is
/// consulted FIRST and exclusively, so a file owned by the caller with `0o040` is denied to the
/// caller even when the caller is in the group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessPath {
    /// The caller is the owner and the owner class grants read. Survives a box: the box keeps the
    /// caller's uid.
    Owner,
    /// An `ACL_USER` entry names the caller's uid. Survives a box, for the same reason, and this is
    /// why a desktop with per-uid ACLs on its DRM nodes never meets the group question at all.
    AclUser,
    /// The `other` class grants read, so nobody needs to be anybody. Survives a box.
    Other,
    /// The only way in is the group class, whether through the file's gid or through an
    /// `ACL_GROUP` entry. DOES NOT survive a box, because a box carries no supplementary group.
    GroupOnly,
    /// The caller cannot read the node at all. A grant that names it must refuse and say so, rather
    /// than mount it and let the workload meet the error.
    Unreachable,
}

impl AccessPath {
    /// Whether this path still works from inside a box that dropped its supplementary groups.
    pub const fn survives_a_box(self) -> bool {
        matches!(
            self,
            AccessPath::Owner | AccessPath::AclUser | AccessPath::Other
        )
    }
}

/// THE policy function, in one place.
///
/// It answers "how does this caller reach this node", and every other surface derives its decision
/// from the answer rather than re-deriving the rule. A derived condition computed in two places is
/// this project's recurring defect, and the group rule is exactly the shape that invites it: the
/// resolver, the message and the refusal would each be tempted to ask it again.
///
/// The kernel's order is reproduced exactly:
///   1. the owner class is consulted first AND EXCLUSIVELY when the uid matches;
///   2. then `ACL_USER` for the caller's uid;
///   3. then the group class, which is the file's gid plus any `ACL_GROUP` entry, bounded by
///      `ACL_MASK` when one is present;
///   4. then `other`.
///
/// Step 1 being exclusive is not a detail: a node owned by the caller with mode `0o040` is
/// `Unreachable`, not `GroupOnly`, and a resolver that fell through to the group class would report
/// a decision the kernel never offers.
pub fn access_path(node: &NodeFacts, who: &Caller) -> AccessPath {
    if node.uid == who.uid {
        return if node.owner_reads() {
            AccessPath::Owner
        } else {
            AccessPath::Unreachable
        };
    }

    if node.acl_users.contains(&who.uid) {
        return AccessPath::AclUser;
    }

    let group_class_open = !node.acl_mask_denies_read;
    let by_file_gid = node.group_reads() && who.in_group(node.gid);
    let by_acl_group = node.acl_groups.iter().any(|g| who.in_group(*g));
    if group_class_open && (by_file_gid || by_acl_group) {
        return AccessPath::GroupOnly;
    }

    if node.other_reads() {
        return AccessPath::Other;
    }

    AccessPath::Unreachable
}

/// What the grant says about supplementary groups. There are two choices and the kernel offers no
/// third, which module documentation point 3 records as a measurement rather than an opinion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupPolicy {
    /// No node in the grant needs a group: every one of them is reached by uid or by `other`. The
    /// box drops its groups as it always has and nothing is lost.
    NotNeeded,
    /// At least one node is reachable only through the group class. The listed gids are the ones
    /// those nodes need, reported so a message can name them.
    ///
    /// ⚠️ Keeping them is ALL OR NOTHING: the only way to keep these is to not call `setgroups`,
    /// which keeps every other inherited kgid as well. The variant carries what is needed, never a
    /// promise that only these would be kept.
    Needed {
        /// The gids that would unlock the group-gated nodes, sorted and unique.
        gids: Vec<u32>,
        /// The nodes that cannot be reached without them, in the order the grant lists them.
        nodes: Vec<PathBuf>,
    },
    /// At least one node cannot be reached by the caller at all, with or without groups. Nothing a
    /// box does can fix this, so the grant refuses instead of mounting a node that will fail.
    Unreachable {
        /// The nodes the caller cannot open on the host either.
        nodes: Vec<PathBuf>,
    },
}

/// One library the grant would bind, with the links that have to point at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Library {
    /// The real file, as found under the root.
    pub path: PathBuf,
    /// The device and inode that make this file's identity, which is what the sweep deduplicates
    /// on. Two paths with the same pair are one library reached twice.
    pub dev: u64,
    pub ino: u64,
}

/// Everything a box would need for a GPU, computed from one root and one caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuGrant {
    /// The driver version the library set was computed from.
    pub driver_version: String,
    /// The device nodes, in a stable order.
    pub nodes: Vec<PathBuf>,
    /// The libraries, deduplicated by identity and filtered to one ELF class.
    pub libraries: Vec<Library>,
    /// The directories the loader has to search, derived from where the libraries actually are.
    pub ldconfig_dirs: Vec<PathBuf>,
    /// The one group decision, computed once.
    pub group_policy: GroupPolicy,
}

/// Why a grant could not be computed. Every variant names a fact, so a message can be built from it
/// without the caller guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// The root carries no `proc/driver/nvidia/version`, so no NVIDIA driver is loaded there.
    NoDriverVersionFile {
        /// The path that was looked for, under the root that was passed.
        looked_for: PathBuf,
    },
    /// The file exists but carries no `N.N.N` token on its first line.
    DriverVersionUnparsable {
        /// The first line, truncated, so a report can show what was actually there.
        first_line: String,
    },
    /// The driver is present and no device node is.
    NoNodes {
        /// The version that was read, so the message can say the driver is there and the nodes are
        /// not, which is a different fault from having no driver.
        driver_version: String,
    },
}

/// The device nodes an NVIDIA grant needs, relative to the root, in the order a grant lists them.
///
/// `nvidiactl` and the per-card nodes are not interchangeable and the measurement says so: without
/// `nvidiactl` the driver answers `100 CUDA_ERROR_NO_DEVICE`, and without `nvidia-uvm` it answers
/// `999 CUDA_ERROR_UNKNOWN`. Both are in the set because a grant that omits either produces a
/// working mount and a broken workload.
fn candidate_nodes(root: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    let dev = root.join("dev");

    for fixed in [
        "nvidiactl",
        "nvidia-uvm",
        "nvidia-uvm-tools",
        "nvidia-modeset",
    ] {
        let p = dev.join(fixed);
        if p.exists() {
            found.push(p);
        }
    }

    // The per-card nodes are `nvidia0`, `nvidia1`, ... and the set is whatever the driver created,
    // so it is read from the directory rather than assumed to be contiguous from zero.
    let mut cards: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dev) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(rest) = name.strip_prefix("nvidia") else {
                continue;
            };
            if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
                cards.push(entry.path());
            }
        }
    }
    cards.sort();
    found.extend(cards);
    found
}

/// The driver version, read from the first `N.N.N` token on the file's first line.
///
/// Keyed on the pattern and not on the position, because the two kernel modules write different
/// sentences around the same number and a positional parser reads the open module's line as empty.
/// Both shapes are in the tests.
pub fn driver_version_from(contents: &str) -> Option<String> {
    let first_line = contents.lines().next().unwrap_or("");
    let bytes = first_line.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() {
            index += 1;
            continue;
        }
        let start = index;
        let mut dots = 0u8;
        while index < bytes.len() {
            let b = bytes[index];
            if b.is_ascii_digit() {
                index += 1;
            } else if b == b'.' && index + 1 < bytes.len() && bytes[index + 1].is_ascii_digit() {
                dots = dots.saturating_add(1);
                index += 1;
            } else {
                break;
            }
        }
        if dots >= 2 {
            if let Some(token) = first_line.get(start..index) {
                return Some(token.to_string());
            }
        }
        // Not a version: step past this run of digits so the scan cannot stall on it.
        while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'.') {
            index += 1;
        }
    }
    None
}

/// Every directory the dynamic loader searches under this root.
///
/// The defaults come first so a host with no `ld.so.conf` still resolves, then the configuration is
/// parsed with its `include` directives followed to a bounded depth. A glob in an `include` is
/// expanded by reading the directory, because the format allows one and a loader honours it.
fn linker_dirs(root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();

    let push = |dir: PathBuf, out: &mut Vec<PathBuf>, seen: &mut BTreeSet<PathBuf>| {
        if seen.insert(dir.clone()) {
            out.push(dir);
        }
    };

    for rel in DEFAULT_LIB_DIRS {
        push(root.join(rel), &mut out, &mut seen);
    }

    let mut pending: Vec<(PathBuf, u8)> = vec![(root.join(LD_SO_CONF_REL), 0)];
    while let Some((conf, depth)) = pending.pop() {
        if depth > MAX_LD_CONF_DEPTH {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&conf) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("include ") {
                let pattern = rest.trim();
                // An `include` is relative to the root. The wildcard is ONE `*` anywhere in the
                // file name, matched as a prefix and a suffix around it, which is the form every
                // Debian-family host actually ships: `include /etc/ld.so.conf.d/*.conf`. A parser
                // that only handled a TRAILING star read that line, found no match and silently
                // included nothing; the library sweep still answered 29 on this host because the
                // directory it needed was already a default, so the fault was invisible until a
                // synthetic root put a library somewhere only the include could reach.
                let as_path = pattern.trim_start_matches('/');
                let joined = root.join(as_path);
                if let (Some(parent), Some(name)) = (joined.parent(), joined.file_name()) {
                    let name = name.to_string_lossy().to_string();
                    match name.split_once('*') {
                        Some((prefix, suffix)) => {
                            if let Ok(entries) = std::fs::read_dir(parent) {
                                for entry in entries.flatten() {
                                    let file = entry.file_name();
                                    let file = file.to_string_lossy();
                                    // Both ends must match AND the name must be long enough to
                                    // carry them without overlapping, or `ab*ba` would accept `aba`.
                                    if file.len() >= prefix.len().saturating_add(suffix.len())
                                        && file.starts_with(prefix)
                                        && file.ends_with(suffix)
                                    {
                                        pending.push((entry.path(), depth.saturating_add(1)));
                                    }
                                }
                            }
                        }
                        None => pending.push((joined.clone(), depth.saturating_add(1))),
                    }
                }
                continue;
            }
            let dir = line.trim_start_matches('/');
            if !dir.is_empty() {
                push(root.join(dir), &mut out, &mut seen);
            }
        }
    }
    out
}

/// The ELF class of a candidate, read from the header's fifth byte.
///
/// Returns `None` for anything that is not an ELF file at all, so a stray text file with a matching
/// name is excluded rather than mounted.
fn elf_class_of(path: &Path) -> Option<ElfClass> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).ok()?;
    let mut header = [0u8; 5];
    if file.read_exact(&mut header).is_err() {
        return None;
    }
    if header[..4] != ELF_MAGIC {
        return None;
    }
    match header[4] {
        ELF_CLASS_32 => Some(ElfClass::Bits32),
        ELF_CLASS_64 => Some(ElfClass::Bits64),
        _ => None,
    }
}

/// Every library carrying the driver's exact version suffix, deduplicated by identity.
///
/// The suffix is `.so.<version>` and the match is on the whole ending, not on a substring, so
/// `libfoo.so.580.173.021` cannot join a `580.173.02` grant.
fn libraries_under(root: &Path, version: &str, want: ElfClass) -> Vec<Library> {
    let suffix = format!(".so.{version}");
    let mut out: Vec<Library> = Vec::new();
    let mut identities: BTreeSet<(u64, u64)> = BTreeSet::new();

    for dir in linker_dirs(root) {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.ends_with(&suffix) {
                continue;
            }
            let path = entry.path();
            // `symlink_metadata` would describe the link; the identity that matters is the file the
            // link resolves to, because that is what two paths share.
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            if elf_class_of(&path) != Some(want) {
                continue;
            }
            let identity = (meta.dev(), meta.ino());
            if !identities.insert(identity) {
                continue;
            }
            out.push(Library {
                path,
                dev: identity.0,
                ino: identity.1,
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Read the POSIX access ACL of `path` and reduce it to the fields [`NodeFacts`] carries.
///
/// A node with no ACL answers with empty lists and no mask, which is the common case and the one
/// that must not cost anything: `getxattr` returns `ENODATA` and the function is done.
fn acl_facts(path: &Path) -> (Vec<u32>, Vec<u32>, bool) {
    let empty = (Vec::new(), Vec::new(), false);

    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return empty;
    };
    let name = c"system.posix_acl_access";

    let needed = unsafe { libc::getxattr(c_path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if needed <= 0 {
        return empty;
    }
    let mut buffer = vec![0u8; needed as usize];
    let got = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            name.as_ptr(),
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
        )
    };
    if got <= 0 {
        return empty;
    }
    let got = (got as usize).min(buffer.len());
    parse_acl_xattr(&buffer[..got])
}

/// Parse `system.posix_acl_access` into (acl users, acl groups, mask denies read).
///
/// Separated from the syscall so the whole format is testable from a byte slice, including the
/// shapes a filesystem should never produce: a wrong version, a truncated entry, a trailing
/// fragment. Each of those returns what it can rather than failing the whole grant, because an ACL
/// that cannot be read is an ACL that grants nothing, which is the fail-closed answer.
fn parse_acl_xattr(bytes: &[u8]) -> (Vec<u32>, Vec<u32>, bool) {
    let mut users: Vec<u32> = Vec::new();
    let mut groups: Vec<u32> = Vec::new();
    let mut mask_denies_read = false;

    if bytes.len() < 4 {
        return (users, groups, mask_denies_read);
    }
    let Some(version_bytes) = bytes.get(..4) else {
        return (users, groups, mask_denies_read);
    };
    let Ok(version_array) = <[u8; 4]>::try_from(version_bytes) else {
        return (users, groups, mask_denies_read);
    };
    if u32::from_le_bytes(version_array) != ACL_XATTR_VERSION {
        return (users, groups, mask_denies_read);
    }

    let mut offset = 4usize;
    while offset + 8 <= bytes.len() {
        let Some(tag_bytes) = bytes.get(offset..offset + 2) else {
            break;
        };
        let Some(perm_bytes) = bytes.get(offset + 2..offset + 4) else {
            break;
        };
        let Some(id_bytes) = bytes.get(offset + 4..offset + 8) else {
            break;
        };
        let (Ok(tag_array), Ok(perm_array), Ok(id_array)) = (
            <[u8; 2]>::try_from(tag_bytes),
            <[u8; 2]>::try_from(perm_bytes),
            <[u8; 4]>::try_from(id_bytes),
        ) else {
            break;
        };
        let tag = u16::from_le_bytes(tag_array);
        let perm = u16::from_le_bytes(perm_array);
        let id = u32::from_le_bytes(id_array);
        let grants_read = perm & ACL_READ != 0;

        match tag {
            ACL_USER if grants_read => users.push(id),
            ACL_GROUP if grants_read => groups.push(id),
            ACL_MASK => mask_denies_read = !grants_read,
            _ => {}
        }
        // A node is opened for reading, so the write bit is read and discarded deliberately: it is
        // named here so a later phase that needs write access knows where the bit was dropped.
        let _ = perm & ACL_WRITE;
        offset += 8;
    }

    users.sort_unstable();
    users.dedup();
    groups.sort_unstable();
    groups.dedup();
    (users, groups, mask_denies_read)
}

/// The facts about one node, read from the filesystem.
fn node_facts(path: &Path) -> Option<NodeFacts> {
    let meta = std::fs::metadata(path).ok()?;
    let (acl_users, acl_groups, acl_mask_denies_read) = acl_facts(path);
    Some(NodeFacts {
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode() & 0o777,
        acl_users,
        acl_groups,
        acl_mask_denies_read,
    })
}

/// The one group decision for a whole set of nodes, computed from [`access_path`] and nothing else.
///
/// `Unreachable` wins over `Needed`, because a node the caller cannot open at all is a harder fault
/// than one that wants a group: keeping groups would not fix it, and reporting the softer verdict
/// would send the caller down a road that ends in the same error.
pub fn group_policy(nodes: &[(PathBuf, NodeFacts)], who: &Caller) -> GroupPolicy {
    let mut needed_gids: BTreeSet<u32> = BTreeSet::new();
    let mut needed_nodes: Vec<PathBuf> = Vec::new();
    let mut unreachable: Vec<PathBuf> = Vec::new();

    for (path, facts) in nodes {
        let reach = access_path(facts, who);
        if reach.survives_a_box() {
            continue;
        }
        match reach {
            // Unreachable by construction: `survives_a_box` is true for exactly these three, and
            // the `continue` above has already taken them.
            AccessPath::Owner | AccessPath::AclUser | AccessPath::Other => {}
            AccessPath::GroupOnly => {
                if facts.group_reads() && who.in_group(facts.gid) {
                    needed_gids.insert(facts.gid);
                }
                for g in &facts.acl_groups {
                    if who.in_group(*g) {
                        needed_gids.insert(*g);
                    }
                }
                needed_nodes.push(path.clone());
            }
            AccessPath::Unreachable => unreachable.push(path.clone()),
        }
    }

    if !unreachable.is_empty() {
        return GroupPolicy::Unreachable { nodes: unreachable };
    }
    if needed_nodes.is_empty() {
        return GroupPolicy::NotNeeded;
    }
    GroupPolicy::Needed {
        gids: needed_gids.into_iter().collect(),
        nodes: needed_nodes,
    }
}

/// Resolve a grant from the real root.
pub fn resolve(who: &Caller) -> Result<GpuGrant, ResolveError> {
    resolve_under(Path::new("/"), who, ElfClass::native())
}

/// [`resolve`] with the root and the target class as parameters, so a test can build a tree.
///
/// Nothing below reads a path the caller did not derive from `root`, which is the property that
/// makes the whole module testable without hardware and the one a sabotage test removes first.
pub fn resolve_under(root: &Path, who: &Caller, want: ElfClass) -> Result<GpuGrant, ResolveError> {
    let version_path = root.join(DRIVER_VERSION_REL);
    let Ok(contents) = std::fs::read_to_string(&version_path) else {
        return Err(ResolveError::NoDriverVersionFile {
            looked_for: version_path,
        });
    };
    let Some(driver_version) = driver_version_from(&contents) else {
        let first_line = contents.lines().next().unwrap_or("");
        let truncated: String = first_line.chars().take(120).collect();
        return Err(ResolveError::DriverVersionUnparsable {
            first_line: truncated,
        });
    };

    let node_paths = candidate_nodes(root);
    if node_paths.is_empty() {
        return Err(ResolveError::NoNodes { driver_version });
    }

    let mut with_facts: Vec<(PathBuf, NodeFacts)> = Vec::with_capacity(node_paths.len());
    for path in &node_paths {
        if let Some(facts) = node_facts(path) {
            with_facts.push((path.clone(), facts));
        }
    }
    let policy = group_policy(&with_facts, who);

    let libraries = libraries_under(root, &driver_version, want);

    // The loader's directories are DERIVED from where the libraries are, not copied from the host's
    // configuration: a directory with no library in it would tell the box to search a path that has
    // nothing in it, and a library in a directory the list omits would not be found.
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    for library in &libraries {
        if let Some(parent) = library.path.parent() {
            if seen.insert(parent.to_path_buf()) {
                dirs.push(parent.to_path_buf());
            }
        }
    }

    Ok(GpuGrant {
        driver_version,
        nodes: node_paths,
        libraries,
        ldconfig_dirs: dirs,
        group_policy: policy,
    })
}

/// How much of the grant a render spells out.
///
/// ONE renderer with two verbosities rather than two renderers: the preview and the full listing
/// would otherwise be two spellings of the same structure, and this project's recurring defect is a
/// derived thing computed in two places.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detail {
    /// Counts and the group decision. What `--plan` prints, because the other sections of a plan
    /// are three lines each and forty lines of library paths would bury them.
    Summary,
    /// Every node, library and directory by name.
    Full,
}

/// The grant, rendered for `--plan`, one fact per line and no adjectives.
///
/// A print surface and nothing else: it mounts nothing and decides nothing, so the preview a reader
/// sees is the same structure a later phase would act on.
pub fn render_plan(grant: &GpuGrant, detail: Detail) -> String {
    let mut out = String::new();
    out.push_str(&format!("driver {}\n", grant.driver_version));
    out.push_str(&format!("nodes {}\n", grant.nodes.len()));
    if detail == Detail::Full {
        for node in &grant.nodes {
            out.push_str(&format!("  node {}\n", node.display()));
        }
    }
    out.push_str(&format!("libraries {}\n", grant.libraries.len()));
    if detail == Detail::Full {
        for library in &grant.libraries {
            out.push_str(&format!("  lib {}\n", library.path.display()));
        }
    }
    out.push_str(&format!("ldconfig dirs {}\n", grant.ldconfig_dirs.len()));
    if detail == Detail::Full {
        for dir in &grant.ldconfig_dirs {
            out.push_str(&format!("  dir {}\n", dir.display()));
        }
    }
    match &grant.group_policy {
        GroupPolicy::NotNeeded => {
            out.push_str("groups not needed: every node is reached by uid or by other\n");
        }
        GroupPolicy::Needed { gids, nodes } => {
            let names: Vec<String> = gids.iter().map(|g| g.to_string()).collect();
            out.push_str(&format!("groups needed: {}\n", names.join(", ")));
            if detail == Detail::Full {
                for node in nodes {
                    out.push_str(&format!("  group-gated {}\n", node.display()));
                }
            }
            out.push_str(
                "  keeping them is all or nothing: a box keeps every inherited group or none\n",
            );
        }
        GroupPolicy::Unreachable { nodes } => {
            out.push_str("refuse: the invoking user cannot open these on the host either\n");
            for node in nodes {
                out.push_str(&format!("  unreachable {}\n", node.display()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A caller with the given uid and groups, written once so a test reads as its own case.
    fn caller(uid: u32, gids: &[u32]) -> Caller {
        Caller {
            uid,
            gids: gids.to_vec(),
        }
    }

    /// A node with no ACL, which is the common shape.
    fn plain(uid: u32, gid: u32, mode: u32) -> NodeFacts {
        NodeFacts {
            uid,
            gid,
            mode,
            acl_users: Vec::new(),
            acl_groups: Vec::new(),
            acl_mask_denies_read: false,
        }
    }

    /// THE POLICY, over its whole input space rather than over the state this machine is in.
    ///
    /// The space is (owner matches or not) x (group matches or not) x (each of the three read bits)
    /// x (acl user present or not) x (acl group present or not) x (mask denies or not). Every
    /// combination is generated and checked against the kernel's own order, so a rule that happens
    /// to be right for this desktop's `0666` nodes cannot pass.
    #[test]
    fn the_policy_answers_every_combination_the_way_the_kernel_orders_them() {
        let who = caller(1000, &[1000, 44]);
        let mut seen_each_variant = [false; 5];

        for owner_matches in [false, true] {
            for group_matches in [false, true] {
                for owner_bit in [false, true] {
                    for group_bit in [false, true] {
                        for other_bit in [false, true] {
                            for acl_user in [false, true] {
                                for acl_group in [false, true] {
                                    for mask_denies in [false, true] {
                                        let mut node = plain(
                                            if owner_matches { 1000 } else { 4242 },
                                            if group_matches { 44 } else { 4242 },
                                            (if owner_bit { 0o400 } else { 0 })
                                                | (if group_bit { 0o040 } else { 0 })
                                                | (if other_bit { 0o004 } else { 0 }),
                                        );
                                        if acl_user {
                                            node.acl_users.push(1000);
                                        }
                                        if acl_group {
                                            node.acl_groups.push(44);
                                        }
                                        node.acl_mask_denies_read = mask_denies;

                                        let got = access_path(&node, &who);

                                        // The expected answer, derived here independently of the
                                        // implementation so the test is not the code again.
                                        let expected = if owner_matches {
                                            if owner_bit {
                                                AccessPath::Owner
                                            } else {
                                                AccessPath::Unreachable
                                            }
                                        } else if acl_user {
                                            AccessPath::AclUser
                                        } else if !mask_denies
                                            && ((group_bit && group_matches)
                                                || (acl_group && who.in_group(44)))
                                        {
                                            AccessPath::GroupOnly
                                        } else if other_bit {
                                            AccessPath::Other
                                        } else {
                                            AccessPath::Unreachable
                                        };

                                        assert_eq!(
                                            got, expected,
                                            "owner_matches={owner_matches} group_matches={group_matches} \
                                             bits={owner_bit}{group_bit}{other_bit} acl_user={acl_user} \
                                             acl_group={acl_group} mask_denies={mask_denies}"
                                        );

                                        let index = match got {
                                            AccessPath::Owner => 0,
                                            AccessPath::AclUser => 1,
                                            AccessPath::Other => 2,
                                            AccessPath::GroupOnly => 3,
                                            AccessPath::Unreachable => 4,
                                        };
                                        seen_each_variant[index] = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // An enumeration that never produced one of the answers would be testing a narrower space
        // than it claims, which is the shape of a measurement that cannot fail.
        assert!(
            seen_each_variant.iter().all(|x| *x),
            "the enumeration never produced every variant: {seen_each_variant:?}"
        );
    }

    /// The owner class is consulted FIRST AND EXCLUSIVELY, which is the rule most likely to be got
    /// wrong by falling through to the group.
    #[test]
    fn a_node_owned_by_the_caller_with_no_owner_bit_is_unreachable_not_group_only() {
        let who = caller(1000, &[1000, 44]);
        let node = plain(1000, 44, 0o060);
        assert_eq!(access_path(&node, &who), AccessPath::Unreachable);
    }

    /// The shape this desktop actually has: `root:video 0660` plus an `ACL_USER` for the caller.
    /// It must answer `AclUser` and NOT `GroupOnly`, because that is why a box opens the node even
    /// with no groups, measured on this host.
    #[test]
    fn a_per_uid_acl_outranks_the_group_class_and_survives_a_box() {
        let who = caller(1000, &[1000, 44]);
        let mut node = plain(0, 44, 0o660);
        node.acl_users.push(1000);
        let got = access_path(&node, &who);
        assert_eq!(got, AccessPath::AclUser);
        assert!(got.survives_a_box());
    }

    /// The shape a server has: the same node with the ACL removed. It must answer `GroupOnly`, and
    /// that answer must NOT survive a box.
    #[test]
    fn the_same_node_without_the_acl_is_group_only_and_does_not_survive_a_box() {
        let who = caller(1000, &[1000, 44]);
        let node = plain(0, 44, 0o660);
        let got = access_path(&node, &who);
        assert_eq!(got, AccessPath::GroupOnly);
        assert!(!got.survives_a_box());
    }

    /// An `ACL_GROUP` entry is a group path like any other and must not be mistaken for a uid path.
    #[test]
    fn an_acl_group_entry_is_a_group_path_and_is_lost_with_the_others() {
        let who = caller(1000, &[1000, 44]);
        let mut node = plain(0, 4242, 0o600);
        node.acl_groups.push(44);
        let got = access_path(&node, &who);
        assert_eq!(got, AccessPath::GroupOnly);
        assert!(!got.survives_a_box());
    }

    /// A mask without read kills the whole group class, entries included.
    #[test]
    fn an_acl_mask_without_read_closes_the_group_path_entirely() {
        let who = caller(1000, &[1000, 44]);
        let mut node = plain(0, 44, 0o660);
        node.acl_groups.push(44);
        node.acl_mask_denies_read = true;
        assert_eq!(access_path(&node, &who), AccessPath::Unreachable);
    }

    /// `/dev/nvidia0` on this host: `root:root 0666`. Nobody needs to be anybody.
    #[test]
    fn a_world_readable_node_needs_no_identity_at_all() {
        let who = caller(1000, &[1000]);
        let node = plain(0, 0, 0o666);
        let got = access_path(&node, &who);
        assert_eq!(got, AccessPath::Other);
        assert!(got.survives_a_box());
    }

    /// The group decision for a whole set, and the precedence between its two bad outcomes.
    #[test]
    fn the_group_policy_reports_unreachable_over_needed() {
        let who = caller(1000, &[1000, 44]);
        let nodes = vec![
            (PathBuf::from("/dev/nvidia0"), plain(0, 0, 0o666)),
            (PathBuf::from("/dev/dri/card0"), plain(0, 44, 0o660)),
            (PathBuf::from("/dev/locked"), plain(0, 0, 0o600)),
        ];
        match group_policy(&nodes, &who) {
            GroupPolicy::Unreachable { nodes } => {
                assert_eq!(nodes, vec![PathBuf::from("/dev/locked")]);
            }
            other => panic!("expected Unreachable, got {other:?}"),
        }
    }

    /// With the unreachable node removed, the same set reports the gid that would unlock it.
    #[test]
    fn the_group_policy_names_the_gids_the_gated_nodes_need() {
        let who = caller(1000, &[1000, 44, 992]);
        let nodes = vec![
            (PathBuf::from("/dev/nvidia0"), plain(0, 0, 0o666)),
            (PathBuf::from("/dev/dri/card0"), plain(0, 44, 0o660)),
            (PathBuf::from("/dev/dri/renderD128"), plain(0, 992, 0o660)),
        ];
        match group_policy(&nodes, &who) {
            GroupPolicy::Needed { gids, nodes } => {
                assert_eq!(gids, vec![44, 992]);
                assert_eq!(nodes.len(), 2);
            }
            other => panic!("expected Needed, got {other:?}"),
        }
    }

    /// Every node reached by uid or by other means no decision to make.
    #[test]
    fn a_set_reached_without_groups_needs_no_policy() {
        let who = caller(1000, &[1000]);
        let nodes = vec![
            (PathBuf::from("/dev/nvidia0"), plain(0, 0, 0o666)),
            (PathBuf::from("/dev/nvidiactl"), plain(0, 0, 0o666)),
        ];
        assert_eq!(group_policy(&nodes, &who), GroupPolicy::NotNeeded);
    }

    /// BOTH version-line shapes, because the positional parser read the open module's line as
    /// empty and that is how the 29-library figure was nearly lost.
    #[test]
    fn the_driver_version_is_read_from_both_kernel_modules_line_shapes() {
        let open_module = "NVRM version: NVIDIA UNIX Open Kernel Module for x86_64  580.173.02  \
                           Release Build  (dvs-builder@U22)  Tue Jun 23 08:17:01 UTC 2026\n\
                           GCC version:  gcc version 13.3.0\n";
        assert_eq!(
            driver_version_from(open_module).as_deref(),
            Some("580.173.02")
        );

        let proprietary = "NVRM version: NVIDIA UNIX x86_64 Kernel Module  535.183.01  \
                           Sun May 12 19:39:15 UTC 2024\n";
        assert_eq!(
            driver_version_from(proprietary).as_deref(),
            Some("535.183.01")
        );

        let four_part = "NVRM version: NVIDIA UNIX Kernel Module for aarch64  540.4.0  Build\n";
        assert_eq!(driver_version_from(four_part).as_deref(), Some("540.4.0"));
    }

    /// A line with numbers that are not a version must not produce one.
    #[test]
    fn a_line_without_a_version_token_yields_none() {
        assert_eq!(driver_version_from(""), None);
        assert_eq!(driver_version_from("NVRM version: unknown\n"), None);
        // A single dotted pair is a date fragment or a size, not a driver version.
        assert_eq!(driver_version_from("built on 23.10 for x86_64\n"), None);
    }

    /// The scan must terminate on every input, including ones built to stall it.
    #[test]
    fn the_version_scan_terminates_on_pathological_lines() {
        let awkward = ".....\n";
        assert_eq!(driver_version_from(awkward), None);
        let digits = "1234567890\n";
        assert_eq!(driver_version_from(digits), None);
        let trailing_dot = "12.34.\n";
        assert_eq!(driver_version_from(trailing_dot), None);
        let many = "1.2.3.4.5.6\n";
        assert_eq!(driver_version_from(many).as_deref(), Some("1.2.3.4.5.6"));
    }

    /// The ACL parser over the shapes a filesystem should never produce.
    #[test]
    fn the_acl_parser_fails_closed_on_every_malformed_shape() {
        // Too short to carry a version.
        assert_eq!(parse_acl_xattr(&[]), (Vec::new(), Vec::new(), false));
        assert_eq!(parse_acl_xattr(&[2, 0, 0]), (Vec::new(), Vec::new(), false));
        // A version this parser does not know grants nothing.
        let wrong_version = [9u8, 0, 0, 0, 0x02, 0, 0x04, 0, 0xE8, 0x03, 0, 0];
        assert_eq!(
            parse_acl_xattr(&wrong_version),
            (Vec::new(), Vec::new(), false)
        );
        // A trailing fragment shorter than one entry is dropped, and what came before survives.
        let mut good = vec![2u8, 0, 0, 0];
        good.extend_from_slice(&ACL_USER.to_le_bytes());
        good.extend_from_slice(&ACL_READ.to_le_bytes());
        good.extend_from_slice(&1000u32.to_le_bytes());
        good.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
        let (users, groups, mask) = parse_acl_xattr(&good);
        assert_eq!(users, vec![1000]);
        assert!(groups.is_empty());
        assert!(!mask);
    }

    /// A real ACL, in the shape `getfacl` showed on this host's `/dev/dri/card0`.
    #[test]
    fn the_acl_parser_reads_a_user_entry_a_group_entry_and_a_mask() {
        let mut bytes = vec![2u8, 0, 0, 0];
        for (tag, perm, id) in [
            (ACL_USER, ACL_READ | ACL_WRITE, 1000u32),
            (ACL_GROUP, ACL_READ, 44u32),
            (ACL_MASK, ACL_READ | ACL_WRITE, 0xFFFF_FFFFu32),
        ] {
            bytes.extend_from_slice(&tag.to_le_bytes());
            bytes.extend_from_slice(&perm.to_le_bytes());
            bytes.extend_from_slice(&id.to_le_bytes());
        }
        let (users, groups, mask_denies) = parse_acl_xattr(&bytes);
        assert_eq!(users, vec![1000]);
        assert_eq!(groups, vec![44]);
        assert!(!mask_denies);
    }

    /// A mask with no read bit sets the flag the policy turns on.
    #[test]
    fn a_mask_entry_without_read_sets_the_deny_flag() {
        let mut bytes = vec![2u8, 0, 0, 0];
        bytes.extend_from_slice(&ACL_MASK.to_le_bytes());
        bytes.extend_from_slice(&ACL_WRITE.to_le_bytes());
        bytes.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let (_, _, mask_denies) = parse_acl_xattr(&bytes);
        assert!(mask_denies);
    }

    /// A root with no driver file is a different fault from a root with an unreadable one, and the
    /// error names which.
    #[test]
    fn a_root_without_a_driver_file_is_named_as_such() {
        let dir = std::env::temp_dir().join(format!("kern-gpu-grant-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let who = caller(1000, &[1000]);
        match resolve_under(&dir, &who, ElfClass::Bits64) {
            Err(ResolveError::NoDriverVersionFile { looked_for }) => {
                assert!(looked_for.ends_with(DRIVER_VERSION_REL));
            }
            other => panic!("expected NoDriverVersionFile, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The resolver reads the root it is GIVEN and never `/`. The proof is a synthetic root whose
    /// driver version cannot exist on any host: if the resolver leaked to `/`, it would answer with
    /// this machine's version instead.
    #[test]
    fn the_resolver_reads_the_root_it_is_given_and_not_the_real_one() {
        let dir = std::env::temp_dir().join(format!("kern-gpu-root-{}", std::process::id()));
        let proc_dir = dir.join("proc/driver/nvidia");
        let dev_dir = dir.join("dev");
        let _ = std::fs::create_dir_all(&proc_dir);
        let _ = std::fs::create_dir_all(&dev_dir);
        let wrote_version = std::fs::write(
            proc_dir.join("version"),
            "NVRM version: NVIDIA UNIX Kernel Module  1.2.3  Build\n",
        );
        let wrote_node = std::fs::write(dev_dir.join("nvidiactl"), b"");
        assert!(wrote_version.is_ok() && wrote_node.is_ok());

        let who = caller(1000, &[1000]);
        let grant = resolve_under(&dir, &who, ElfClass::Bits64);
        match grant {
            Ok(g) => {
                assert_eq!(g.driver_version, "1.2.3");
                assert!(g.nodes.iter().any(|n| n.ends_with("nvidiactl")));
                // No library on this synthetic root carries the `.so.1.2.3` suffix.
                assert!(g.libraries.is_empty());
                assert!(g.ldconfig_dirs.is_empty());
            }
            Err(e) => panic!("expected a grant from the synthetic root, got {e:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A driver with no node is a different fault from no driver, and the error carries the version
    /// so a message can say so.
    #[test]
    fn a_driver_with_no_nodes_names_the_version_it_found() {
        let dir = std::env::temp_dir().join(format!("kern-gpu-nonodes-{}", std::process::id()));
        let proc_dir = dir.join("proc/driver/nvidia");
        let _ = std::fs::create_dir_all(&proc_dir);
        let _ = std::fs::create_dir_all(dir.join("dev"));
        let wrote = std::fs::write(
            proc_dir.join("version"),
            "NVRM version: NVIDIA UNIX Kernel Module  7.8.9  Build\n",
        );
        assert!(wrote.is_ok());
        let who = caller(1000, &[1000]);
        match resolve_under(&dir, &who, ElfClass::Bits64) {
            Err(ResolveError::NoNodes { driver_version }) => {
                assert_eq!(driver_version, "7.8.9");
            }
            other => panic!("expected NoNodes, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The per-card nodes are read from the directory, not assumed contiguous from zero, and the
    /// numeric suffix must be a number and nothing else.
    #[test]
    fn the_card_nodes_come_from_the_directory_and_reject_non_numeric_suffixes() {
        let dir = std::env::temp_dir().join(format!("kern-gpu-cards-{}", std::process::id()));
        let proc_dir = dir.join("proc/driver/nvidia");
        let dev_dir = dir.join("dev");
        let _ = std::fs::create_dir_all(&proc_dir);
        let _ = std::fs::create_dir_all(&dev_dir);
        let _ = std::fs::write(
            proc_dir.join("version"),
            "NVRM version: NVIDIA UNIX Kernel Module  1.2.3  Build\n",
        );
        for name in ["nvidia0", "nvidia3", "nvidiactl", "nvidia-uvm", "nvidiafoo"] {
            let _ = std::fs::write(dev_dir.join(name), b"");
        }
        let who = caller(1000, &[1000]);
        let Ok(grant) = resolve_under(&dir, &who, ElfClass::Bits64) else {
            panic!("expected a grant");
        };
        let names: Vec<String> = grant
            .nodes
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .collect();
        assert!(names.contains(&"nvidia0".to_string()));
        assert!(names.contains(&"nvidia3".to_string()));
        assert!(names.contains(&"nvidiactl".to_string()));
        assert!(names.contains(&"nvidia-uvm".to_string()));
        assert!(
            !names.contains(&"nvidiafoo".to_string()),
            "a non-numeric suffix must not be read as a card: {names:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Build a synthetic root carrying a driver version, one node, and whatever libraries the
    /// caller asks for. Returns the root, which the caller removes.
    ///
    /// `libs` is a list of (relative directory, file name, ELF class byte, link_to). A `link_to`
    /// names an already-written file to HARD LINK to, which is how the usrmerge shape is
    /// reproduced without needing a symlinked `/lib`: the two names share one `(dev, ino)`, which
    /// is the only property the deduplication turns on.
    fn synthetic_root(
        tag: &str,
        version: &str,
        libs: &[(&str, &str, u8, Option<&str>)],
    ) -> PathBuf {
        let root = std::env::temp_dir().join(format!("kern-gpu-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let proc_dir = root.join("proc/driver/nvidia");
        let _ = std::fs::create_dir_all(&proc_dir);
        let _ = std::fs::create_dir_all(root.join("dev"));
        let _ = std::fs::write(
            proc_dir.join("version"),
            format!("NVRM version: NVIDIA UNIX Kernel Module  {version}  Build\n"),
        );
        let _ = std::fs::write(root.join("dev/nvidiactl"), b"");

        // The loader's configuration, written with an `include` and a glob so the parser's two
        // other paths are exercised by every test that builds a root rather than by none of them.
        // A directory that is already in `DEFAULT_LIB_DIRS` appearing here too is deliberate: the
        // sweep must not double it, and the identity set is what stops it.
        let conf_dir = root.join("etc/ld.so.conf.d");
        let _ = std::fs::create_dir_all(&conf_dir);
        let _ = std::fs::write(
            root.join(LD_SO_CONF_REL),
            "# synthetic\ninclude /etc/ld.so.conf.d/*.conf\n",
        );
        let mut listed: Vec<String> = libs.iter().map(|(d, _, _, _)| (*d).to_string()).collect();
        listed.sort();
        listed.dedup();
        let _ = std::fs::write(
            conf_dir.join("extra.conf"),
            listed.iter().map(|d| format!("/{d}\n")).collect::<String>(),
        );

        for (dir, name, class, link_to) in libs {
            let full_dir = root.join(dir);
            let _ = std::fs::create_dir_all(&full_dir);
            let target = full_dir.join(name);
            match link_to {
                Some(existing) => {
                    let _ = std::fs::hard_link(root.join(existing), &target);
                }
                None => {
                    // A minimal ELF header: the magic, then the class byte the test asks for, then
                    // enough padding that a reader of the first five bytes is never short.
                    let mut bytes = Vec::with_capacity(64);
                    bytes.extend_from_slice(&ELF_MAGIC);
                    bytes.push(*class);
                    bytes.extend_from_slice(&[0u8; 59]);
                    let _ = std::fs::write(&target, &bytes);
                }
            }
        }
        root
    }

    /// THE DEDUPLICATION, which a sabotage proved the rest of the suite could not see.
    ///
    /// Removing the `(dev, ino)` check left all 21 other tests green while the count on this host
    /// went from 29 to 58, because no synthetic tree had one file reachable by two paths. A hard
    /// link reproduces exactly that: two names, two directories the linker searches, one inode.
    #[test]
    fn one_file_reachable_by_two_linker_paths_is_one_library() {
        let root = synthetic_root(
            "dedup",
            "9.9.9",
            &[
                (
                    "usr/lib/x86_64-linux-gnu",
                    "libfoo.so.9.9.9",
                    ELF_CLASS_64,
                    None,
                ),
                (
                    "lib/x86_64-linux-gnu",
                    "libfoo.so.9.9.9",
                    ELF_CLASS_64,
                    Some("usr/lib/x86_64-linux-gnu/libfoo.so.9.9.9"),
                ),
            ],
        );
        let who = caller(1000, &[1000]);
        let Ok(grant) = resolve_under(&root, &who, ElfClass::Bits64) else {
            let _ = std::fs::remove_dir_all(&root);
            panic!("expected a grant from the synthetic root");
        };
        let count = grant.libraries.len();
        let dirs = grant.ldconfig_dirs.len();
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(
            count, 1,
            "one inode reached by two linker paths must count once, got {count}"
        );
        assert_eq!(
            dirs, 1,
            "and it must contribute one loader directory, got {dirs}"
        );
    }

    /// THE ELF CLASS FILTER, for the same reason: the i386 tree carries the same names with the
    /// same suffix, and a 32-bit library in a 64-bit box is a mount the loader refuses.
    #[test]
    fn a_library_of_the_other_elf_class_is_not_a_candidate() {
        let root = synthetic_root(
            "class",
            "8.8.8",
            &[
                (
                    "usr/lib/x86_64-linux-gnu",
                    "libbar.so.8.8.8",
                    ELF_CLASS_64,
                    None,
                ),
                (
                    "usr/lib/i386-linux-gnu",
                    "libbar.so.8.8.8",
                    ELF_CLASS_32,
                    None,
                ),
            ],
        );
        let who = caller(1000, &[1000]);

        let sixty_four = resolve_under(&root, &who, ElfClass::Bits64);
        let thirty_two = resolve_under(&root, &who, ElfClass::Bits32);
        let _ = std::fs::remove_dir_all(&root);

        let Ok(sixty_four) = sixty_four else {
            panic!("expected a 64-bit grant");
        };
        let Ok(thirty_two) = thirty_two else {
            panic!("expected a 32-bit grant");
        };
        assert_eq!(
            sixty_four.libraries.len(),
            1,
            "a 64-bit grant must take only the 64-bit file"
        );
        assert!(sixty_four.libraries[0]
            .path
            .to_string_lossy()
            .contains("x86_64"));
        assert_eq!(
            thirty_two.libraries.len(),
            1,
            "a 32-bit grant must take only the 32-bit file"
        );
        assert!(thirty_two.libraries[0]
            .path
            .to_string_lossy()
            .contains("i386"));
    }

    /// A file that carries the suffix and is not an ELF object at all is excluded, so a stray text
    /// file named like a library cannot be mounted into a box.
    #[test]
    fn a_non_elf_file_with_the_right_suffix_is_refused() {
        let root = synthetic_root("notelf", "7.7.7", &[]);
        let dir = root.join("usr/lib/x86_64-linux-gnu");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(
            dir.join("libtrap.so.7.7.7"),
            b"this is not an ELF file at all",
        );
        let who = caller(1000, &[1000]);
        let got = resolve_under(&root, &who, ElfClass::Bits64);
        let _ = std::fs::remove_dir_all(&root);
        let Ok(grant) = got else {
            panic!("expected a grant");
        };
        assert!(
            grant.libraries.is_empty(),
            "a non-ELF file must not join the grant: {:?}",
            grant.libraries
        );
    }

    /// The suffix match is on the whole ending, not on a substring, so a longer version cannot be
    /// swept into a shorter one's grant.
    #[test]
    fn a_longer_version_suffix_does_not_match_a_shorter_grant() {
        let root = synthetic_root(
            "suffix",
            "1.2.3",
            &[
                (
                    "usr/lib/x86_64-linux-gnu",
                    "libexact.so.1.2.3",
                    ELF_CLASS_64,
                    None,
                ),
                (
                    "usr/lib/x86_64-linux-gnu",
                    "liblonger.so.1.2.34",
                    ELF_CLASS_64,
                    None,
                ),
            ],
        );
        let who = caller(1000, &[1000]);
        let got = resolve_under(&root, &who, ElfClass::Bits64);
        let _ = std::fs::remove_dir_all(&root);
        let Ok(grant) = got else {
            panic!("expected a grant");
        };
        let names: Vec<String> = grant
            .libraries
            .iter()
            .filter_map(|l| l.path.file_name().map(|n| n.to_string_lossy().to_string()))
            .collect();
        assert_eq!(
            names,
            vec!["libexact.so.1.2.3".to_string()],
            "got {names:?}"
        );
    }

    /// `render_plan` prints what the grant says and invents nothing.
    #[test]
    fn the_plan_prints_the_group_decision_in_each_of_its_three_shapes() {
        let base = GpuGrant {
            driver_version: "580.173.02".to_string(),
            nodes: vec![PathBuf::from("/dev/nvidia0")],
            libraries: vec![Library {
                path: PathBuf::from("/usr/lib/x86_64-linux-gnu/libcuda.so.580.173.02"),
                dev: 1,
                ino: 2,
            }],
            ldconfig_dirs: vec![PathBuf::from("/usr/lib/x86_64-linux-gnu")],
            group_policy: GroupPolicy::NotNeeded,
        };
        let text = render_plan(&base, Detail::Full);
        assert!(text.contains("driver 580.173.02"));
        assert!(text.contains("groups not needed"));

        let needed = GpuGrant {
            group_policy: GroupPolicy::Needed {
                gids: vec![44],
                nodes: vec![PathBuf::from("/dev/dri/card0")],
            },
            ..base.clone()
        };
        let text = render_plan(&needed, Detail::Full);
        assert!(text.contains("groups needed: 44"));
        assert!(
            text.contains("all or nothing"),
            "the plan must not imply that only the named gid would be kept"
        );

        let refused = GpuGrant {
            group_policy: GroupPolicy::Unreachable {
                nodes: vec![PathBuf::from("/dev/locked")],
            },
            ..base
        };
        let text = render_plan(&refused, Detail::Full);
        assert!(text.contains("refuse:"));
        assert!(text.contains("/dev/locked"));
    }
}
