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

/// How many symlink hops a library's chain may take before the sweep gives up. A chain on this
/// host is at most two (`libcuda.so` to `libcuda.so.1` to the versioned file); a filesystem permits
/// a loop, and an unbounded resolver meeting one would not return.
const MAX_LINK_HOPS: u8 = 8;

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

/// One link that has to exist beside a granted library for the loader to find it.
///
/// WHY A GRANT WITHOUT THESE IS A GRANT THAT DOES NOT WORK. A library's file name carries the
/// driver version, and nothing loads it by that name: `dlopen` is called with the SONAME, and the
/// SONAME is a symlink that does NOT carry the version and is therefore not in the computed set.
/// Measured on this host: 29 versioned files, and beside them 19 SONAME links
/// (`libnvidia-ml.so.1 -> libnvidia-ml.so.580.173.02`) plus 10 development links
/// (`libnvidia-ml.so -> libnvidia-ml.so.1`). Ten of the 29 have no link at all, because the driver
/// loads them by their full versioned name.
///
/// COMPUTED LIKE THE LIBRARIES, NEVER LISTED. The sweep walks the same linker directories looking
/// for symlinks, resolves each chain to its end, and keeps the link when the end is one of the
/// granted identities. A hand-written list of SONAMEs would be the "curated discovery" the plan
/// names as a way to fail: it would be right on this driver and wrong on the next one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symlink {
    /// The link itself, as found under the root.
    pub link: PathBuf,
    /// What the link says, verbatim. A relative target is kept relative, because the link and its
    /// target sit in the same directory and rewriting it to an absolute path would make the box's
    /// copy point outside the box.
    pub target: PathBuf,
    /// The granted library the chain ends at, recorded while the chain is walked.
    ///
    /// Carried rather than re-derived: the mount plan needs to know which real file to put at this
    /// link's path, and resolving the chain a second time there would be the same derived
    /// condition computed in two places that this project keeps paying for.
    pub resolved: PathBuf,
}

/// One card's nodes: its `/dev/nvidiaN` and the DRM nodes of the same physical device.
///
/// A STRUCT RATHER THAN A FLAT LIST, because the card a node belongs to used to be DERIVED from
/// its file name in two places, and a DRM node's name does not carry the card's index at all. On
/// this host `nvidia0`'s display node is `card1`: any rule that read the index out of the name
/// would pair them wrongly and no single-GPU test could see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardNodes {
    /// The `/dev/nvidiaN` index, which is the number `--gpus` names.
    pub index: u32,
    /// Every node of this card, with the facts the group policy turns on.
    pub nodes: Vec<(PathBuf, NodeFacts)>,
}

/// Everything a box would need for a GPU, computed from one root and one caller.
///
/// THE GROUP POLICY IS NOT A FIELD. It is a function of the nodes that will actually be MOUNTED,
/// and a grant for card 0 must not refuse because card 1's display node is group-gated. Storing it
/// would be a derived condition kept in a second place, which is this project's recurring defect;
/// `group_policy` is called with the selection instead, by `--plan` over everything and by
/// `mount_plan` over the card it is building.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuGrant {
    /// The driver version the library set was computed from.
    pub driver_version: String,
    /// The nodes every card shares, with their facts.
    pub shared: Vec<(PathBuf, NodeFacts)>,
    /// The cards, by index, each with its own nodes.
    pub cards: Vec<CardNodes>,
    /// The libraries, deduplicated by identity and filtered to one ELF class.
    pub libraries: Vec<Library>,
    /// The links that have to exist beside them, computed from the same directories.
    pub symlinks: Vec<Symlink>,
    /// The directories the loader has to search, derived from where the libraries actually are.
    pub ldconfig_dirs: Vec<PathBuf>,
}

impl GpuGrant {
    /// Every node in the grant, shared first then per card, for the surfaces that describe the
    /// whole host rather than one selection.
    pub fn all_nodes(&self) -> Vec<(PathBuf, NodeFacts)> {
        let mut out = self.shared.clone();
        for card in &self.cards {
            out.extend(card.nodes.iter().cloned());
        }
        out
    }
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

/// The nodes every card shares, relative to the root, in the order a grant lists them.
///
/// `nvidiactl` and `nvidia-uvm` are not optional and the measurement says so: without `nvidiactl`
/// the driver answers `100 CUDA_ERROR_NO_DEVICE`, without `nvidia-uvm` it answers
/// `999 CUDA_ERROR_UNKNOWN`. A grant that omits either produces a working mount and a broken
/// workload.
fn shared_node_paths(root: &Path) -> Vec<PathBuf> {
    let dev = root.join("dev");
    let mut found = Vec::new();
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
    found
}

/// The `Device Minor` a card's own `information` file reports, which IS its `/dev/nvidiaN` number.
///
/// Established from NVIDIA's own source rather than inferred, and the citation lives in this repo
/// already (see `gpu::mig_instances_for_card`): `nv-procfs.c` prints the field from `nvl->minor_num`
/// and `nv.c` returns the same value from `nv_get_dev_minor()`. Reading it is the difference between
/// knowing which card a PCI address is and guessing from the order a directory happens to list.
fn device_minor_of(information: &Path) -> Option<u32> {
    let text = std::fs::read_to_string(information).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("Device Minor:"))?
        .trim()
        .parse()
        .ok()
}

/// The DRM nodes that belong to the same physical card as `/dev/nvidiaN`, resolved through the PCI
/// address and never through the index.
///
/// 🚨 THE INDEX IS NOT A SOURCE, and this host proves it: `nvidia0` is PCI `0000:01:00.0`, whose DRM
/// nodes are **`card1`** and `renderD128`, while `nvidia1` is `0000:06:00.0` with **`card0`** and
/// `renderD129`. The two numberings are INVERTED here. A grant that paired `nvidia0` with `card0`
/// would hand the box the other card's display node, silently, and every test on a single-GPU host
/// would pass.
///
/// The chain is: `proc/driver/nvidia/gpus/<bdf>/information` gives the minor, the directory name
/// gives the PCI address, and `sys/bus/pci/devices/<bdf>/drm/` lists the nodes. Only `card*` and
/// `renderD*` are taken; `controlD*` is a legacy node no current driver uses.
fn drm_nodes_for(root: &Path, minor: u32) -> Vec<PathBuf> {
    let gpus = root.join("proc/driver/nvidia/gpus");
    let Ok(entries) = std::fs::read_dir(&gpus) else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        if device_minor_of(&entry.path().join("information")) != Some(minor) {
            continue;
        }
        let bdf = entry.file_name();
        let drm_dir = root.join("sys/bus/pci/devices").join(&bdf).join("drm");
        let Ok(nodes) = std::fs::read_dir(&drm_dir) else {
            return Vec::new();
        };
        let mut out: Vec<PathBuf> = Vec::new();
        for node in nodes.flatten() {
            let name = node.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with("card") || name.starts_with("renderD") {
                let path = root.join("dev/dri").join(name);
                if path.exists() {
                    out.push(path);
                }
            }
        }
        out.sort();
        return out;
    }
    Vec::new()
}

/// The per-card nodes: `/dev/nvidiaN` plus the DRM nodes of the same physical card.
///
/// The set of cards is read from the directory rather than assumed contiguous from zero, because a
/// driver may leave a gap and a grant that counted upwards would miss the card that is there.
fn card_node_paths(root: &Path) -> Vec<(u32, Vec<PathBuf>)> {
    let dev = root.join("dev");
    let mut cards: Vec<(u32, Vec<PathBuf>)> = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dev) else {
        return cards;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(rest) = name.strip_prefix("nvidia") else {
            continue;
        };
        if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(index) = rest.parse::<u32>() else {
            continue;
        };
        let mut nodes = vec![entry.path()];
        nodes.extend(drm_nodes_for(root, index));
        cards.push((index, nodes));
    }
    cards.sort_by_key(|(i, _)| *i);
    cards
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

/// Resolve a directory to its canonical form WITHIN the root, following relative symlinks on the
/// way and refusing absolute ones.
///
/// WHY A GRANT CANNOT SKIP THIS. On a usrmerge host `/lib` is a symlink to `usr/lib`, so the same
/// directory is reachable by two names and the sweep may produce either. The name matters because
/// it becomes the bind's TARGET inside the box, and the box's own filesystem has the same symlink:
/// kern resolves a bind target without traversing symlinked components, so a target under `/lib`
/// is refused with `ENOTDIR` and the whole box fails to build. Measured: with `/lib/...` paths the
/// box died with `openat(volume source, O_NOFOLLOW) failed: Not a directory`.
///
/// `std::fs::canonicalize` cannot be used: it resolves against the real filesystem root, which on a
/// synthetic tree walks out of the root under test and on a real host turns a relative link into
/// the host's own absolute path.
fn canonical_dir_under(root: &Path, dir: &Path) -> PathBuf {
    let Ok(relative) = dir.strip_prefix(root) else {
        return dir.to_path_buf();
    };
    let mut out = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            continue;
        };
        out.push(name);
        let mut hops = 0u8;
        while hops < MAX_LINK_HOPS {
            let Ok(meta) = std::fs::symlink_metadata(&out) else {
                break;
            };
            if !meta.file_type().is_symlink() {
                break;
            }
            let Ok(target) = std::fs::read_link(&out) else {
                break;
            };
            // An absolute target would leave the root, and a grant never follows one.
            if target.is_absolute() {
                break;
            }
            let Some(parent) = out.parent().map(Path::to_path_buf) else {
                break;
            };
            out = parent.join(target);
            hops = hops.saturating_add(1);
        }
    }
    out
}

/// Every directory the dynamic loader searches under this root.
///
/// The defaults come first so a host with no `ld.so.conf` still resolves, then the configuration is
/// parsed with its `include` directives followed to a bounded depth. A glob in an `include` is
/// expanded by reading the directory, because the format allows one and a loader honours it.
fn linker_dirs(root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();

    // CANONICALISED BEFORE THE DUPLICATE CHECK, so `/lib/...` and `/usr/lib/...` collapse into one
    // entry and the only form that leaves this function is one a box can mount at. The name is not
    // cosmetic: it becomes the bind's TARGET, the image has the same `/lib` symlink, and kern
    // resolves a target without traversing symlinked components. Measured before this: a grant
    // carrying `/lib/...` paths failed the whole box with
    // `openat(volume source, O_NOFOLLOW) failed: Not a directory`.
    let push = |dir: PathBuf, out: &mut Vec<PathBuf>, seen: &mut BTreeSet<PathBuf>| {
        let dir = canonical_dir_under(root, &dir);
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

/// Every symlink in the linker's directories whose chain ends at one of the granted libraries.
///
/// The chain is followed by hand rather than with `std::fs::canonicalize`, for one reason that a
/// grant cannot afford to get wrong: `canonicalize` resolves against the REAL filesystem root, so
/// on a synthetic tree it would walk out of the root it was given, and on a real host it would
/// follow an absolute target to the host's own path. The walk here stays inside the directory the
/// link lives in, which is where a library's SONAME link always points.
///
/// `MAX_LINK_HOPS` bounds it. A symlink loop is a thing a filesystem permits, and an unbounded
/// resolver meeting one would not return.
fn symlinks_for(root: &Path, granted: &[Library]) -> Vec<Symlink> {
    let identities: BTreeSet<(u64, u64)> = granted.iter().map(|l| (l.dev, l.ino)).collect();
    let mut out: Vec<Symlink> = Vec::new();
    // DEDUPLICATED BY THE LINK'S OWN IDENTITY, not by its path, for exactly the reason the library
    // sweep is: `/lib` is a symlink to `/usr/lib`, so the same link inode is reached by two paths.
    // Keying on the path answered 58 on this host where the truth is 29. This is the second time
    // the same mistake was made in this file, once for the files and once for the links, which is
    // why both now use the same key.
    let mut seen: BTreeSet<(u64, u64)> = BTreeSet::new();

    for dir in linker_dirs(root) {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let link = entry.path();
            // THE KIND COMES FROM THE DIRECTORY READ, NOT FROM A `statx` PER ENTRY. `getdents64`
            // already carried `d_type` for every name, so asking the entry costs nothing, and when
            // a filesystem answers `DT_UNKNOWN` the standard library does the `lstat` itself: the
            // non-symlink case is never worse than asking directly. Measured on this host, where
            // `/usr/lib/x86_64-linux-gnu` holds 2805 entries of which 1291 are links: this one line
            // used to spend a syscall on each of the 1514 files that could never be a symlink.
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if !kind.is_symlink() {
                continue;
            }
            // The link's OWN target. It is read once here and then used as the first hop of the
            // walk below, which used to re-read it: the loop started by asking again what kind
            // `link` was, when the branch above had just established it, and then read the same
            // target a second time.
            let Ok(target) = std::fs::read_link(&link) else {
                continue;
            };
            // Resolve the chain within the directory, hop by hop and bounded.
            let mut current = link.clone();
            let mut next_rel = target.clone();
            let mut hops = 0u8;
            let ends_in_grant = loop {
                if hops >= MAX_LINK_HOPS {
                    break None;
                }
                // An absolute target would leave the root; a grant never follows one.
                if next_rel.is_absolute() {
                    break None;
                }
                let Some(parent) = current.parent() else {
                    break None;
                };
                current = parent.join(&next_rel);
                hops = hops.saturating_add(1);
                let Ok(meta) = std::fs::symlink_metadata(&current) else {
                    break None;
                };
                if !meta.file_type().is_symlink() {
                    break if identities.contains(&(meta.dev(), meta.ino())) {
                        Some(current.clone())
                    } else {
                        None
                    };
                }
                let Ok(next) = std::fs::read_link(&current) else {
                    break None;
                };
                next_rel = next;
            };
            if let Some(resolved) = ends_in_grant {
                // THE LINK'S OWN IDENTITY, ASKED ONLY FOR A LINK THAT IS ACTUALLY GRANTED. This is
                // the `statx` the loop above no longer spends on every entry; here it runs once per
                // kept link, which on this host is 29 times rather than 2805.
                let Ok(link_meta) = std::fs::symlink_metadata(&link) else {
                    continue;
                };
                if seen.insert((link_meta.dev(), link_meta.ino())) {
                    out.push(Symlink {
                        link,
                        target,
                        resolved,
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| a.link.cmp(&b.link));
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
///
/// NO CALLER PARAMETER, and its absence is the design rather than an omission: the grant describes
/// what the HOST has, and who may reach it is a question about a SELECTION. `mount_plan` asks it
/// over the nodes it is about to bind, which is the only set the answer can be right about.
pub fn resolve() -> Result<GpuGrant, ResolveError> {
    resolve_under(Path::new("/"), ElfClass::native())
}

/// [`resolve`] with the root and the target class as parameters, so a test can build a tree.
///
/// Nothing below reads a path the caller did not derive from `root`, which is the property that
/// makes the whole module testable without hardware and the one a sabotage test removes first.
pub fn resolve_under(root: &Path, want: ElfClass) -> Result<GpuGrant, ResolveError> {
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

    let shared_paths = shared_node_paths(root);
    let card_paths = card_node_paths(root);
    if shared_paths.is_empty() && card_paths.is_empty() {
        return Err(ResolveError::NoNodes { driver_version });
    }

    // Facts are read ONCE, here, and travel with the node. Reading them again where the policy is
    // applied would be the same filesystem asked twice about the same thing, with a window between
    // the two answers.
    let facts_of = |paths: &[PathBuf]| -> Vec<(PathBuf, NodeFacts)> {
        let mut out = Vec::with_capacity(paths.len());
        for path in paths {
            if let Some(facts) = node_facts(path) {
                out.push((path.clone(), facts));
            }
        }
        out
    };

    let shared = facts_of(&shared_paths);
    let cards: Vec<CardNodes> = card_paths
        .into_iter()
        .map(|(index, paths)| CardNodes {
            index,
            nodes: facts_of(&paths),
        })
        .collect();

    let libraries = libraries_under(root, &driver_version, want);
    let symlinks = symlinks_for(root, &libraries);

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
        shared,
        cards,
        libraries,
        symlinks,
        ldconfig_dirs: dirs,
    })
}

/// Why `--gpus` could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GpuSpecError {
    /// The value was empty.
    Empty,
    /// `all` names more than one card, and this phase grants one. Refused rather than narrowed:
    /// a flag that takes a word and does something smaller than the word says is a defect.
    AllNotYet,
    /// The value is not a card index.
    NotAnIndex {
        /// What was passed, so the message can quote it.
        given: String,
    },
}

/// Read `--gpus`: one card, by index.
///
/// Accepts `0`, `device=0` and `gpu=0`, which are the three spellings a reader arrives with from
/// other runtimes. Refuses `all` by name rather than treating it as "the first one".
pub fn parse_gpu_spec(value: &str) -> Result<u32, GpuSpecError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(GpuSpecError::Empty);
    }
    if trimmed.eq_ignore_ascii_case("all") {
        return Err(GpuSpecError::AllNotYet);
    }
    let digits = trimmed
        .strip_prefix("device=")
        .or_else(|| trimmed.strip_prefix("gpu="))
        .unwrap_or(trimmed);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(GpuSpecError::NotAnIndex {
            given: trimmed.to_string(),
        });
    }
    digits.parse::<u32>().map_err(|_| GpuSpecError::NotAnIndex {
        given: trimmed.to_string(),
    })
}

/// Why a grant cannot be turned into mounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountPlanError {
    /// The card the caller asked for does not exist on this host.
    NoSuchCard {
        /// The index that was asked for.
        wanted: u32,
        /// The indices that do exist, so the message can list them.
        present: Vec<u32>,
    },
    /// A node in the grant is reachable only through a group the box cannot carry. Refused, per
    /// the roadmap's §5.4: keeping the groups is all-or-nothing and is not something a GPU flag
    /// may decide on the caller's behalf.
    GroupsNeeded {
        /// The gids that would unlock them.
        gids: Vec<u32>,
        /// The nodes that need them.
        nodes: Vec<PathBuf>,
    },
    /// A node cannot be opened by the invoking user at all, with or without groups.
    Unreachable {
        /// The nodes in question.
        nodes: Vec<PathBuf>,
    },
}

/// One bind the box needs: a host path, where it appears inside, and whether it is read-only.
///
/// A plain triple rather than a type of its own: the launch converts it straight into the
/// `Volume` the `-v` path already uses, and introducing a parallel type here would be a second
/// spelling of a thing that exists.
pub type Bind = (String, String, bool);

/// Turn a grant into the binds that give a box exactly ONE card.
///
/// THE SHARED NODES COME TOO, and leaving one out is not a smaller grant but a broken one. S0
/// measured what each absence does: without `nvidiactl` the driver answers `100
/// CUDA_ERROR_NO_DEVICE`, without `nvidia-uvm` it answers `999 CUDA_ERROR_UNKNOWN`. A plan that
/// mounted the card alone would produce a box that looks granted and fails at `cuInit`.
///
/// THE OTHER CARDS ARE NOT MOUNTED, which is how a non-granted card fails: it is absent, and S0's
/// control showed a box cannot fabricate it (`mknod` answers `EPERM`).
///
/// EVERY LIBRARY IS READ-ONLY. The host's libraries are mounted, never copied and never modified,
/// which is also what the vendor licence requires of them.
///
/// THE SYMLINKS BECOME BINDS OF THEIR RESOLVED FILE, placed at the link's own path. The box gets
/// `libcuda.so.1` as a real file rather than as a link, which loads identically and needs no
/// writable directory inside the box: `dlopen("libcuda.so.1")` is a name lookup, not a link walk.
pub fn mount_plan(grant: &GpuGrant, card: u32, who: &Caller) -> Result<Vec<Bind>, MountPlanError> {
    let Some(wanted) = grant.cards.iter().find(|c| c.index == card) else {
        return Err(MountPlanError::NoSuchCard {
            wanted: card,
            present: grant.cards.iter().map(|c| c.index).collect(),
        });
    };

    // The selection, and the policy over EXACTLY it: the shared nodes plus this card's, never the
    // other cards'. A grant for card 0 refusing because card 1's display node is group-gated would
    // be answering a question nobody asked.
    let mut selected: Vec<(PathBuf, NodeFacts)> = grant.shared.clone();
    selected.extend(wanted.nodes.iter().cloned());

    match group_policy(&selected, who) {
        GroupPolicy::Unreachable { nodes } => return Err(MountPlanError::Unreachable { nodes }),
        GroupPolicy::Needed { gids, nodes } => {
            return Err(MountPlanError::GroupsNeeded { gids, nodes })
        }
        GroupPolicy::NotNeeded => {}
    }

    let mut binds: Vec<Bind> =
        Vec::with_capacity(selected.len() + grant.libraries.len() + grant.symlinks.len());

    for (node, _) in &selected {
        let path = node.to_string_lossy().to_string();
        binds.push((path.clone(), path, false));
    }

    for library in &grant.libraries {
        let path = library.path.to_string_lossy().to_string();
        binds.push((path.clone(), path, true));
    }

    for link in &grant.symlinks {
        let source = link.resolved.to_string_lossy().to_string();
        let target = link.link.to_string_lossy().to_string();
        binds.push((source, target, true));
    }

    Ok(binds)
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
    let every = grant.all_nodes();
    out.push_str(&format!(
        "nodes {} ({} shared, {} card(s))\n",
        every.len(),
        grant.shared.len(),
        grant.cards.len()
    ));
    if detail == Detail::Full {
        for (node, _) in &grant.shared {
            out.push_str(&format!("  shared {}\n", node.display()));
        }
        for card in &grant.cards {
            for (node, _) in &card.nodes {
                out.push_str(&format!("  card {} {}\n", card.index, node.display()));
            }
        }
    }
    out.push_str(&format!("libraries {}\n", grant.libraries.len()));
    if detail == Detail::Full {
        for library in &grant.libraries {
            out.push_str(&format!("  lib {}\n", library.path.display()));
        }
    }
    out.push_str(&format!("symlinks {}\n", grant.symlinks.len()));
    if detail == Detail::Full {
        for link in &grant.symlinks {
            out.push_str(&format!(
                "  link {} -> {}\n",
                link.link.display(),
                link.target.display()
            ));
        }
    }
    out.push_str(&format!("ldconfig dirs {}\n", grant.ldconfig_dirs.len()));
    if detail == Detail::Full {
        for dir in &grant.ldconfig_dirs {
            out.push_str(&format!("  dir {}\n", dir.display()));
        }
    }
    // The policy is a FUNCTION of a selection, not a field: `--plan` describes the host, so it
    // asks over every node, while `mount_plan` asks over the one card it is building.
    match &group_policy(&every, &Caller::current()) {
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
        match resolve_under(&dir, ElfClass::Bits64) {
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

        let grant = resolve_under(&dir, ElfClass::Bits64);
        match grant {
            Ok(g) => {
                assert_eq!(g.driver_version, "1.2.3");
                assert!(g.shared.iter().any(|(n, _)| n.ends_with("nvidiactl")));
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
        match resolve_under(&dir, ElfClass::Bits64) {
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
        let Ok(grant) = resolve_under(&dir, ElfClass::Bits64) else {
            panic!("expected a grant");
        };
        let names: Vec<String> = grant
            .all_nodes()
            .iter()
            .filter_map(|(p, _)| p.file_name().map(|n| n.to_string_lossy().to_string()))
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

    /// Put a symlink beside a library in the synthetic root.
    fn link_in(root: &Path, dir: &str, name: &str, target: &str) {
        let full = root.join(dir).join(name);
        let _ = std::fs::remove_file(&full);
        let _ = std::os::unix::fs::symlink(target, &full);
    }

    /// THE SONAME LINKS, computed and not listed, and deduplicated by the LINK'S identity.
    ///
    /// Keying on the link's path answered 58 on this host where the truth is 29, because `/lib` is
    /// a symlink to `/usr/lib` and the same link inode is reached twice. That is the same mistake
    /// the library sweep already made once, made a second time in the same file, and the real host
    /// was again the only thing that could see it. A hard-linked tree cannot reproduce a symlink's
    /// identity, so the two directories here are made to be one.
    #[test]
    fn a_link_reached_by_two_linker_paths_is_one_link() {
        let root = synthetic_root(
            "linkdedup",
            "5.5.5",
            &[(
                "usr/lib/x86_64-linux-gnu",
                "libz.so.5.5.5",
                ELF_CLASS_64,
                None,
            )],
        );
        link_in(
            &root,
            "usr/lib/x86_64-linux-gnu",
            "libz.so.1",
            "libz.so.5.5.5",
        );
        // `lib` IS `usr/lib`, the usrmerge shape, so both linker defaults reach one directory.
        let _ = std::fs::remove_dir_all(root.join("lib"));
        let _ = std::os::unix::fs::symlink("usr/lib", root.join("lib"));

        let got = resolve_under(&root, ElfClass::Bits64);
        let _ = std::fs::remove_dir_all(&root);
        let Ok(grant) = got else {
            panic!("expected a grant");
        };
        assert_eq!(
            grant.libraries.len(),
            1,
            "one library reached twice is one: {:?}",
            grant.libraries
        );
        assert_eq!(
            grant.symlinks.len(),
            1,
            "one link reached twice is one: {:?}",
            grant.symlinks
        );
    }

    /// A chain of two links is followed to its end, which is the `libcuda.so -> libcuda.so.1 ->
    /// libcuda.so.580.173.02` shape this host actually has.
    #[test]
    fn a_two_hop_chain_ending_in_a_granted_library_is_taken() {
        let root = synthetic_root(
            "chain",
            "4.4.4",
            &[(
                "usr/lib/x86_64-linux-gnu",
                "libchain.so.4.4.4",
                ELF_CLASS_64,
                None,
            )],
        );
        link_in(
            &root,
            "usr/lib/x86_64-linux-gnu",
            "libchain.so.1",
            "libchain.so.4.4.4",
        );
        link_in(
            &root,
            "usr/lib/x86_64-linux-gnu",
            "libchain.so",
            "libchain.so.1",
        );

        let got = resolve_under(&root, ElfClass::Bits64);
        let _ = std::fs::remove_dir_all(&root);
        let Ok(grant) = got else {
            panic!("expected a grant");
        };
        let names: Vec<String> = grant
            .symlinks
            .iter()
            .filter_map(|s| s.link.file_name().map(|n| n.to_string_lossy().to_string()))
            .collect();
        assert!(
            names.contains(&"libchain.so.1".to_string()),
            "got {names:?}"
        );
        assert!(names.contains(&"libchain.so".to_string()), "got {names:?}");
        assert_eq!(names.len(), 2, "and nothing else: {names:?}");
    }

    /// A link whose chain ends somewhere that is not in the grant is not in the grant either.
    #[test]
    fn a_link_pointing_outside_the_grant_is_not_taken() {
        let root = synthetic_root(
            "outside",
            "3.3.3",
            &[(
                "usr/lib/x86_64-linux-gnu",
                "libin.so.3.3.3",
                ELF_CLASS_64,
                None,
            )],
        );
        let dir = root.join("usr/lib/x86_64-linux-gnu");
        let _ = std::fs::write(dir.join("libother.so.9.9.9"), b"\x7fELF\x02 not granted");
        link_in(
            &root,
            "usr/lib/x86_64-linux-gnu",
            "libother.so.1",
            "libother.so.9.9.9",
        );
        link_in(
            &root,
            "usr/lib/x86_64-linux-gnu",
            "libin.so.1",
            "libin.so.3.3.3",
        );

        let got = resolve_under(&root, ElfClass::Bits64);
        let _ = std::fs::remove_dir_all(&root);
        let Ok(grant) = got else {
            panic!("expected a grant");
        };
        let names: Vec<String> = grant
            .symlinks
            .iter()
            .filter_map(|s| s.link.file_name().map(|n| n.to_string_lossy().to_string()))
            .collect();
        assert_eq!(names, vec!["libin.so.1".to_string()], "got {names:?}");
    }

    /// An ABSOLUTE target would leave the root, so the grant refuses to follow it. On a synthetic
    /// tree that is the difference between reading the test's files and reading this machine's.
    #[test]
    fn a_link_with_an_absolute_target_is_refused() {
        let root = synthetic_root(
            "absolute",
            "2.2.2",
            &[(
                "usr/lib/x86_64-linux-gnu",
                "libabs.so.2.2.2",
                ELF_CLASS_64,
                None,
            )],
        );
        let full = root.join("usr/lib/x86_64-linux-gnu/libabs.so.1");
        let target = root.join("usr/lib/x86_64-linux-gnu/libabs.so.2.2.2");
        let _ = std::os::unix::fs::symlink(&target, &full);

        let got = resolve_under(&root, ElfClass::Bits64);
        let _ = std::fs::remove_dir_all(&root);
        let Ok(grant) = got else {
            panic!("expected a grant");
        };
        assert!(
            grant.symlinks.is_empty(),
            "an absolute target leaves the root and must not be followed: {:?}",
            grant.symlinks
        );
    }

    /// A loop is a thing a filesystem permits. The sweep must return.
    #[test]
    fn a_symlink_loop_terminates_instead_of_hanging() {
        let root = synthetic_root(
            "loop",
            "1.1.1",
            &[(
                "usr/lib/x86_64-linux-gnu",
                "libok.so.1.1.1",
                ELF_CLASS_64,
                None,
            )],
        );
        link_in(&root, "usr/lib/x86_64-linux-gnu", "liba.so.1", "libb.so.1");
        link_in(&root, "usr/lib/x86_64-linux-gnu", "libb.so.1", "liba.so.1");
        link_in(
            &root,
            "usr/lib/x86_64-linux-gnu",
            "libok.so.1",
            "libok.so.1.1.1",
        );

        let got = resolve_under(&root, ElfClass::Bits64);
        let _ = std::fs::remove_dir_all(&root);
        let Ok(grant) = got else {
            panic!("expected a grant");
        };
        let names: Vec<String> = grant
            .symlinks
            .iter()
            .filter_map(|s| s.link.file_name().map(|n| n.to_string_lossy().to_string()))
            .collect();
        assert_eq!(
            names,
            vec!["libok.so.1".to_string()],
            "the loop must be dropped and the good link kept: {names:?}"
        );
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
        let Ok(grant) = resolve_under(&root, ElfClass::Bits64) else {
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

        let sixty_four = resolve_under(&root, ElfClass::Bits64);
        let thirty_two = resolve_under(&root, ElfClass::Bits32);
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
        let got = resolve_under(&root, ElfClass::Bits64);
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
        let got = resolve_under(&root, ElfClass::Bits64);
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

    /// THE DRM NODES ARE PAIRED BY PCI ADDRESS, AND THE NUMBERINGS CAN BE INVERTED.
    ///
    /// Measured on this host: `nvidia0` is PCI `0000:01:00.0` whose display node is **`card1`**,
    /// and `nvidia1` is `0000:06:00.0` with **`card0`**. A grant that paired `nvidiaN` with `cardN`
    /// would hand the box the other card's node, silently, and no single-GPU host could tell. The
    /// synthetic root reproduces exactly that inversion, so the test fails the moment the pairing
    /// goes back to the index.
    #[test]
    fn the_drm_nodes_are_paired_through_pci_and_survive_an_inverted_numbering() {
        let root = std::env::temp_dir().join(format!("kern-gpu-drm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::create_dir_all(root.join("proc/driver/nvidia"));
        let _ = std::fs::create_dir_all(root.join("dev/dri"));
        let _ = std::fs::write(
            root.join("proc/driver/nvidia/version"),
            "NVRM version: NVIDIA UNIX Kernel Module  1.2.3  Build\n",
        );
        for name in ["nvidiactl", "nvidia-uvm", "nvidia0", "nvidia1"] {
            let _ = std::fs::write(root.join("dev").join(name), b"");
        }
        // `controlD*` EXISTS in /dev here on purpose: without it the filter would be excluded by
        // the existence check rather than by the name, and a sabotage that added `controlD` to the
        // filter left every test green. The node has to be present for the name rule to be the
        // thing under test.
        for name in [
            "card0",
            "card1",
            "renderD128",
            "renderD129",
            "controlD64",
            "controlD65",
        ] {
            let _ = std::fs::write(root.join("dev/dri").join(name), b"");
        }
        // THE INVERSION: minor 0 lives at 01:00.0 and owns card1; minor 1 at 06:00.0 owns card0.
        for (bdf, minor, drm) in [
            ("0000:01:00.0", 0u32, ["card1", "renderD128", "controlD65"]),
            ("0000:06:00.0", 1u32, ["card0", "renderD129", "controlD64"]),
        ] {
            let gpu_dir = root.join("proc/driver/nvidia/gpus").join(bdf);
            let _ = std::fs::create_dir_all(&gpu_dir);
            let _ = std::fs::write(
                gpu_dir.join("information"),
                format!("Model: \t synthetic\nDevice Minor: \t {minor}\n"),
            );
            let drm_dir = root.join("sys/bus/pci/devices").join(bdf).join("drm");
            let _ = std::fs::create_dir_all(&drm_dir);
            for node in drm {
                let _ = std::fs::write(drm_dir.join(node), b"");
            }
        }

        let got = resolve_under(&root, ElfClass::Bits64);
        let _ = std::fs::remove_dir_all(&root);
        let Ok(grant) = got else {
            panic!("expected a grant from the synthetic root");
        };

        let named = |index: u32| -> Vec<String> {
            grant
                .cards
                .iter()
                .find(|c| c.index == index)
                .map(|c| {
                    let mut v: Vec<String> = c
                        .nodes
                        .iter()
                        .filter_map(|(p, _)| p.file_name().map(|n| n.to_string_lossy().to_string()))
                        .collect();
                    v.sort();
                    v
                })
                .unwrap_or_default()
        };

        assert_eq!(
            named(0),
            vec![
                "card1".to_string(),
                "nvidia0".to_string(),
                "renderD128".to_string()
            ],
            "card 0 must carry card1, not card0"
        );
        assert_eq!(
            named(1),
            vec![
                "card0".to_string(),
                "nvidia1".to_string(),
                "renderD129".to_string()
            ],
            "card 1 must carry card0, not card1"
        );
        // `controlD*` is a legacy node no current driver uses and must not be swept in.
        for index in [0u32, 1] {
            assert!(
                !named(index).iter().any(|n| n.starts_with("controlD")),
                "controlD must not join the grant: {:?}",
                named(index)
            );
        }
        // The shared nodes stay shared and do not land on a card.
        let shared: Vec<String> = grant
            .shared
            .iter()
            .filter_map(|(p, _)| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .collect();
        assert!(shared.contains(&"nvidiactl".to_string()), "{shared:?}");
        assert!(shared.contains(&"nvidia-uvm".to_string()), "{shared:?}");
    }

    /// `--gpus` over its whole input space, including the forms a reader arrives with from other
    /// runtimes and the ones that must be refused by name.
    #[test]
    fn the_gpus_spec_accepts_three_spellings_of_one_card_and_refuses_the_rest() {
        for good in ["0", "1", "7", "device=0", "gpu=3", " 2 "] {
            let Ok(n) = parse_gpu_spec(good) else {
                panic!("{good:?} should parse");
            };
            let digits: String = good
                .trim()
                .trim_start_matches("device=")
                .trim_start_matches("gpu=")
                .to_string();
            assert_eq!(n.to_string(), digits, "{good:?} parsed to the wrong index");
        }
        assert_eq!(parse_gpu_spec(""), Err(GpuSpecError::Empty));
        assert_eq!(parse_gpu_spec("   "), Err(GpuSpecError::Empty));
        // `all` is refused BY NAME. A flag that takes a word and grants something narrower than
        // the word says is the defect this refusal exists to prevent.
        assert_eq!(parse_gpu_spec("all"), Err(GpuSpecError::AllNotYet));
        assert_eq!(parse_gpu_spec("ALL"), Err(GpuSpecError::AllNotYet));
        for bad in ["-1", "0,1", "0.5", "first", "device=", "gpu=x", "0x1"] {
            match parse_gpu_spec(bad) {
                Err(GpuSpecError::NotAnIndex { given }) => assert_eq!(given, bad.trim()),
                other => panic!("{bad:?} should be NotAnIndex, got {other:?}"),
            }
        }
    }

    /// The two edges where a digit check usually breaks: the top of the type, and a character that
    /// is a digit to a human and to `char::is_numeric` but not to `is_ascii_digit`.
    ///
    /// `u32::MAX` must PARSE and then be refused later for not existing, because those are two
    /// different answers and the caller is owed the right one: "no card 4294967295 on this host,
    /// present: 0, 1" tells them to look at their index, "not a card index" tells them to look at
    /// their spelling. One past the top is a spelling problem, and it reaches `parse` rather than
    /// the digit filter, so it is the only refusal here that comes from the integer conversion.
    #[test]
    fn the_spec_holds_at_the_top_of_u32_and_refuses_a_digit_that_is_not_ascii() {
        assert_eq!(parse_gpu_spec("4294967295"), Ok(u32::MAX));
        assert_eq!(parse_gpu_spec("device=4294967295"), Ok(u32::MAX));
        for over in ["4294967296", "99999999999999999999"] {
            match parse_gpu_spec(over) {
                Err(GpuSpecError::NotAnIndex { given }) => assert_eq!(given, over),
                other => panic!("{over:?} is past u32 and must not parse, got {other:?}"),
            }
        }
        // FULLWIDTH ZERO, U+FF10, then Arabic-Indic and Devanagari. `char::is_numeric` answers
        // true for all three where `is_ascii_digit` does not.
        //
        // MEASURED, because the obvious claim about this is wrong: swapping the filter to
        // `is_numeric` leaves every assertion here green, since `parse::<u32>` refuses a
        // non-ASCII digit on its own and returns the SAME `NotAnIndex`. So this test pins the
        // behaviour a caller sees, not which of the two guards catches it, and the ASCII filter
        // earns its place by rejecting earlier rather than by rejecting more.
        for wide in ["\u{FF10}", "\u{0660}", "\u{0966}", "0\u{FF10}"] {
            match parse_gpu_spec(wide) {
                Err(GpuSpecError::NotAnIndex { given }) => assert_eq!(given, wide),
                other => panic!("{wide:?} is not an ASCII index, got {other:?}"),
            }
        }
        // Leading zeros name the same card and are not a spelling error: `00` is card 0.
        assert_eq!(parse_gpu_spec("00"), Ok(0));
        assert_eq!(parse_gpu_spec("0000000001"), Ok(1));
    }

    /// A grant with two cards, used by the mount-plan tests. The nodes carry the FACTS the policy
    /// turns on, so a test produces a refusal by building a gated node rather than by handing the
    /// grant a verdict: there is one policy function and the tests go through it like everything
    /// else does.
    fn two_card_grant(card0: NodeFacts) -> GpuGrant {
        GpuGrant {
            driver_version: "580.173.02".to_string(),
            shared: vec![
                (PathBuf::from("/dev/nvidiactl"), plain(0, 0, 0o666)),
                (PathBuf::from("/dev/nvidia-uvm"), plain(0, 0, 0o666)),
            ],
            cards: vec![
                CardNodes {
                    index: 0,
                    nodes: vec![(PathBuf::from("/dev/nvidia0"), card0)],
                },
                CardNodes {
                    index: 1,
                    nodes: vec![(PathBuf::from("/dev/nvidia1"), plain(0, 0, 0o666))],
                },
            ],
            libraries: vec![Library {
                path: PathBuf::from("/usr/lib/x86_64-linux-gnu/libcuda.so.580.173.02"),
                dev: 1,
                ino: 2,
            }],
            symlinks: vec![Symlink {
                link: PathBuf::from("/usr/lib/x86_64-linux-gnu/libcuda.so.1"),
                target: PathBuf::from("libcuda.so.580.173.02"),
                resolved: PathBuf::from("/usr/lib/x86_64-linux-gnu/libcuda.so.580.173.02"),
            }],
            ldconfig_dirs: vec![PathBuf::from("/usr/lib/x86_64-linux-gnu")],
        }
    }

    /// ONE card, and the shared nodes with it. Leaving a shared node out is not a smaller grant,
    /// it is a broken one: S0 measured that a box without `nvidiactl` answers `100` and a box
    /// without `nvidia-uvm` answers `999`.
    #[test]
    fn the_mount_plan_takes_one_card_and_every_shared_node() {
        let grant = two_card_grant(plain(0, 0, 0o666));
        let Ok(binds) = mount_plan(&grant, 0, &caller(1000, &[1000])) else {
            panic!("expected a plan for card 0");
        };
        let targets: Vec<&str> = binds.iter().map(|(_, t, _)| t.as_str()).collect();
        assert!(targets.contains(&"/dev/nvidiactl"), "{targets:?}");
        assert!(targets.contains(&"/dev/nvidia-uvm"), "{targets:?}");
        assert!(targets.contains(&"/dev/nvidia0"), "{targets:?}");
        assert!(
            !targets.contains(&"/dev/nvidia1"),
            "the other card must stay out: {targets:?}"
        );

        // And the other way round, so the filter is not accidentally keeping the first card.
        let Ok(binds) = mount_plan(&grant, 1, &caller(1000, &[1000])) else {
            panic!("expected a plan for card 1");
        };
        let targets: Vec<&str> = binds.iter().map(|(_, t, _)| t.as_str()).collect();
        assert!(targets.contains(&"/dev/nvidia1"), "{targets:?}");
        assert!(!targets.contains(&"/dev/nvidia0"), "{targets:?}");
    }

    /// Libraries and links are READ-ONLY, device nodes are not. A read-only device node would
    /// break the driver's own ioctls; a writable host library is a write into the host.
    #[test]
    fn libraries_are_read_only_and_nodes_are_not() {
        let grant = two_card_grant(plain(0, 0, 0o666));
        let Ok(binds) = mount_plan(&grant, 0, &caller(1000, &[1000])) else {
            panic!("expected a plan");
        };
        for (source, target, read_only) in &binds {
            if target.starts_with("/dev/") {
                assert!(!read_only, "a device node must stay writable: {target}");
            } else {
                assert!(read_only, "a host library must be read-only: {source}");
            }
        }
    }

    /// A link becomes a bind of the file it RESOLVES to, placed at the link's own path, so the box
    /// needs no writable directory and `dlopen` finds the SONAME as a real file.
    #[test]
    fn a_link_is_mounted_as_its_resolved_file_at_the_links_path() {
        let grant = two_card_grant(plain(0, 0, 0o666));
        let Ok(binds) = mount_plan(&grant, 0, &caller(1000, &[1000])) else {
            panic!("expected a plan");
        };
        let found = binds.iter().find(|(_, t, _)| t.ends_with("libcuda.so.1"));
        let Some((source, target, read_only)) = found else {
            panic!("the SONAME link is not in the plan: {binds:?}");
        };
        assert_eq!(source, "/usr/lib/x86_64-linux-gnu/libcuda.so.580.173.02");
        assert_eq!(target, "/usr/lib/x86_64-linux-gnu/libcuda.so.1");
        assert!(read_only);
    }

    /// A card this host has not got is refused, and the refusal lists the ones it has.
    #[test]
    fn a_card_that_does_not_exist_is_refused_with_the_ones_that_do() {
        let grant = two_card_grant(plain(0, 0, 0o666));
        match mount_plan(&grant, 7, &caller(1000, &[1000])) {
            Err(MountPlanError::NoSuchCard { wanted, present }) => {
                assert_eq!(wanted, 7);
                assert_eq!(present, vec![0, 1]);
            }
            other => panic!("expected NoSuchCard, got {other:?}"),
        }
    }

    /// THE GROUP POLICY STOPS THE MOUNT, which is the whole point of computing it in S1. A grant
    /// whose nodes need a group the box cannot carry must not be mounted and hoped for: the
    /// workload would meet the error with no way to learn that the flag did nothing.
    ///
    /// The refusal is produced by building a GATED NODE, not by handing the grant a verdict. There
    /// is one policy function and the tests reach it the way the launch does.
    #[test]
    fn a_grant_needing_groups_is_refused_before_anything_is_mounted() {
        let who = caller(1000, &[1000, 44]);
        // `root:video 0660`, no ACL: the server shape, where the only way in is the group.
        let grant = two_card_grant(plain(0, 44, 0o660));
        match mount_plan(&grant, 0, &who) {
            Err(MountPlanError::GroupsNeeded { gids, nodes }) => {
                assert_eq!(gids, vec![44]);
                assert_eq!(nodes, vec![PathBuf::from("/dev/nvidia0")]);
            }
            other => panic!("expected GroupsNeeded, got {other:?}"),
        }

        // And a node the caller cannot open at all, with or without groups.
        let grant = two_card_grant(plain(0, 0, 0o600));
        match mount_plan(&grant, 0, &who) {
            Err(MountPlanError::Unreachable { nodes }) => {
                assert_eq!(nodes, vec![PathBuf::from("/dev/nvidia0")]);
            }
            other => panic!("expected Unreachable, got {other:?}"),
        }
    }

    /// A GATED NODE ON ANOTHER CARD MUST NOT REFUSE THIS ONE. The policy is a function of the
    /// selection, and a grant for card 0 that looked at card 1's nodes would answer a question
    /// nobody asked. This is the reason the verdict is not a field on the grant.
    #[test]
    fn another_cards_gated_node_does_not_refuse_the_one_being_granted() {
        let who = caller(1000, &[1000, 44]);
        let mut grant = two_card_grant(plain(0, 0, 0o666));
        // Card 1 gets a node reachable only through a group; card 0 stays world-readable.
        grant.cards[1].nodes = vec![(PathBuf::from("/dev/nvidia1"), plain(0, 44, 0o660))];

        assert!(
            mount_plan(&grant, 0, &who).is_ok(),
            "card 0 must be grantable while card 1 is gated"
        );
        match mount_plan(&grant, 1, &who) {
            Err(MountPlanError::GroupsNeeded { gids, .. }) => assert_eq!(gids, vec![44]),
            other => panic!("card 1 should be refused, got {other:?}"),
        }
    }

    /// `render_plan` prints what the grant says and invents nothing.
    #[test]
    fn the_plan_prints_the_group_decision_in_each_of_its_three_shapes() {
        let base = GpuGrant {
            driver_version: "580.173.02".to_string(),
            shared: vec![(PathBuf::from("/dev/nvidiactl"), plain(0, 0, 0o666))],
            cards: vec![CardNodes {
                index: 0,
                nodes: vec![(PathBuf::from("/dev/nvidia0"), plain(0, 0, 0o666))],
            }],
            libraries: vec![Library {
                path: PathBuf::from("/usr/lib/x86_64-linux-gnu/libcuda.so.580.173.02"),
                dev: 1,
                ino: 2,
            }],
            symlinks: vec![Symlink {
                link: PathBuf::from("/usr/lib/x86_64-linux-gnu/libcuda.so.1"),
                target: PathBuf::from("libcuda.so.580.173.02"),
                resolved: PathBuf::from("/usr/lib/x86_64-linux-gnu/libcuda.so.580.173.02"),
            }],
            ldconfig_dirs: vec![PathBuf::from("/usr/lib/x86_64-linux-gnu")],
        };
        let text = render_plan(&base, Detail::Full);
        assert!(text.contains("driver 580.173.02"));
        assert!(text.contains("groups not needed"));

        // The three group shapes are produced the way the launch produces them: by the FACTS of
        // the nodes, through the one policy function.
        let gated = GpuGrant {
            cards: vec![CardNodes {
                index: 0,
                nodes: vec![(PathBuf::from("/dev/dri/card0"), plain(0, 44, 0o660))],
            }],
            ..base.clone()
        };
        let text = render_plan(&gated, Detail::Full);
        assert!(
            text.contains("groups needed:"),
            "a gated node must be reported: {text}"
        );
        assert!(
            text.contains("all or nothing"),
            "the plan must not imply that only the named gid would be kept"
        );

        let refused = GpuGrant {
            cards: vec![CardNodes {
                index: 0,
                nodes: vec![(PathBuf::from("/dev/locked"), plain(0, 0, 0o600))],
            }],
            ..base
        };
        let text = render_plan(&refused, Detail::Full);
        assert!(text.contains("refuse:"));
        assert!(text.contains("/dev/locked"));
    }
}
