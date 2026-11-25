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
//! 1. **A box carries no supplementary group ON THE RANGED MAP, which is the default and not every
//!    box.** `getgroups()` is empty in a default `--image` box and after `--user`, because
//!    `newgidmap` is the privileged writer there and the clear in `drop_caps_around_identity`
//!    succeeds. A SINGLE-UID box (`--no-uid-range`, or a host with no range in `/etc/subuid`) keeps
//!    the caller's whole inherited set, because that map requires `/proc/self/setgroups` to be
//!    `deny` before the kernel will write it and the clear is then EPERM for the life of the
//!    namespace: measured 2026-11-11 over six orderings, none of which drops the groups, with the
//!    ranged path as the positive control that does. So axiom 2 below is not hypothetical, it is
//!    what a `--no-uid-range` box IS, and a node reachable only through a group is unreachable from
//!    a default box and reachable from that one. Anything built on this axiom has to say which map
//!    it is talking about.
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
//! ⚠️ THE SHAPE EVERY ONE OF THOSE FOUR DECIDES HAS NEVER BEEN RUN ON A REAL HOST. A headless
//! server's nodes are commonly `root:video 0660` with no `other` bit, so the group class is the only
//! way in and the whole group policy turns on it. THIS host's nodes are `0666` for `/dev/nvidia*`
//! and `0660` plus an `ACL_USER` for `/dev/dri/*`, which means the group class never decides
//! anything here: on this machine `access_path` answers `Other` or `AclUser` for every node a grant
//! touches, and `GroupPolicy::Needed` is unreachable.
//!
//! So the headless case is covered SYNTHETICALLY and on purpose, and the fixtures say which level
//! they reach: `plain(0, 44, 0o660)` through [`mount_plan`] in
//! `a_grant_needing_groups_is_refused_before_anything_is_mounted`, the same facts through
//! [`access_path`] and [`group_policy`], and `doctor`'s `gated_node()` through the `gpu` row. That is
//! a simulation of a host, not a measurement of one, and it CANNOT answer four things: whether
//! [`node_facts`] reads such a node off a real devtmpfs the way the fixture states it, whether the
//! driver's own `O_RDWR` open agrees with the verdict (it asks only about read today), whether the
//! grant then works end to end, and what group list a real headless operator's service account
//! actually carries. Anyone reading a green test here must not read it as "kern works on a headless
//! server". Finding one host of that shape and running `pentest/pentest-gpu-grant.sh` on it would
//! retire this paragraph; until then it stays.
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

/// POSIX ACL tags, from `<sys/acl.h>`. ALL SIX are named, and the three that were missing are the
/// defect: `ACL_USER_OBJ`, `ACL_GROUP_OBJ` and `ACL_OTHER` carry the permissions of the owner, the
/// owning group and everybody else when an ACL is present, and a reader that takes those three from
/// `st_mode` instead gets the group one WRONG, because with a mask present `st_mode`'s group bits
/// are the MASK and not the owning group's permission. Measured with `getfacl`: a node with
/// `group::rw-` and `mask::r--` displays `-r--` in the group position of `ls -l`.
const ACL_USER_OBJ: u16 = 0x0001;
const ACL_USER: u16 = 0x0002;
const ACL_GROUP_OBJ: u16 = 0x0004;
const ACL_GROUP: u16 = 0x0008;
const ACL_MASK: u16 = 0x0010;
const ACL_OTHER: u16 = 0x0020;

/// The version word at the head of `system.posix_acl_access`.
const ACL_XATTR_VERSION: u32 = 2;

/// The ACL entry's permission bits, in the xattr's own encoding, which is also the encoding of one
/// `st_mode` permission triad. `ACL_EXECUTE` is named for completeness of the triad and is never
/// part of a `want`: a character device is opened, not executed.
const ACL_READ: u8 = 0x04;
const ACL_WRITE: u8 = 0x02;
const ACL_EXECUTE: u8 = 0x01;

/// The most bytes read from one of the driver's own `information` files, and from a linker
/// configuration file.
///
/// Neither is a parser bound: both files are small by construction (the driver's is written by the
/// kernel module, a linker conf is a handful of lines), so the limit only has to exclude a path that
/// is not that file at all. Before these existed the reads were unbounded `read_to_string` calls
/// with no type check, and a FIFO at either name hung `kern doctor`, `kern run --gpus` and
/// `kern box --plan` for ever (measured 2026-11-12).
const MAX_DRIVER_INFO_BYTES: u64 = 64 * 1024;
const MAX_LINKER_CONF_BYTES: u64 = 1024 * 1024;

/// Every bit of a triad, the value a MISSING `ACL_MASK` stands for.
///
/// A minimal ACL (three entries, no mask) is what a filesystem stores for a node that has no named
/// entry at all, and there the mask bounds nothing. Using `0` for an absent mask would make every
/// such node unreachable, which is the direction that fails CLOSED and would refuse every grant on
/// a host with plain permissions.
const ACL_PERM_ALL: u8 = ACL_READ | ACL_WRITE | ACL_EXECUTE;

/// What a GPU node must support to be worth mounting: the driver opens its nodes `O_RDWR`.
///
/// This is the whole correction of 2026-11-12. The policy asked only about READ while every node in
/// a grant is bound read-write and the driver opens it read-write, so a node the caller can read and
/// not write was reported reachable and the workload died at `cuInit` with no diagnostic from kern.
/// Measured on this host: all seven nodes a one-card grant touches are rw-reachable, so requiring
/// write changes no verdict here and closes the case on a host where it would.
const WANT_RW: u8 = ACL_READ | ACL_WRITE;

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
        let uid = unsafe { libc::getuid() };
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
        let primary = unsafe { libc::getgid() };
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
    /// The permission bits, the low nine of `st_mode`. Authoritative ONLY when `acl` is `None`:
    /// with an ACL present the group triad is the mask, which is why [`Acl`] carries its own
    /// group-owner permission instead of deriving it from here.
    pub mode: u32,
    /// The node's POSIX access ACL, or `None` when it carries none.
    pub acl: Option<Acl>,
}

impl NodeFacts {
    /// The `owner` triad of `st_mode`, as ACL permission bits.
    const fn mode_owner(&self) -> u8 {
        ((self.mode >> 6) & 0o7) as u8
    }

    /// The `group` triad of `st_mode`, as ACL permission bits.
    const fn mode_group(&self) -> u8 {
        ((self.mode >> 3) & 0o7) as u8
    }

    /// The `other` triad of `st_mode`, as ACL permission bits.
    const fn mode_other(&self) -> u8 {
        (self.mode & 0o7) as u8
    }
}

/// A node's POSIX access ACL, as the kernel's own check consumes it.
///
/// ALL SIX ENTRY KINDS, because the check consults all six and the previous reduction to
/// (`users`, `groups`, `mask_denies_read`) could not express three things the kernel decides on:
/// that the mask bounds a NAMED USER entry and not only the group class, that a matched group-class
/// entry must carry EVERY requested bit by itself, and that the permissions of the owning group are
/// not `st_mode`'s group bits when a mask is present.
///
/// Permissions are ACL bits (`ACL_READ` | `ACL_WRITE` | `ACL_EXECUTE`), one triad per field, which
/// is the same encoding as one `st_mode` triad.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acl {
    /// `ACL_USER_OBJ`: the owner's permission. Never bounded by the mask.
    pub user_obj: u8,
    /// `ACL_USER`: named uids and their permission, bounded by the mask.
    pub users: Vec<(u32, u8)>,
    /// `ACL_GROUP_OBJ`: the owning group's permission, bounded by the mask.
    pub group_obj: u8,
    /// `ACL_GROUP`: named gids and their permission, bounded by the mask.
    pub groups: Vec<(u32, u8)>,
    /// `ACL_MASK`, absent on a minimal ACL, where it bounds nothing.
    pub mask: Option<u8>,
    /// `ACL_OTHER`: everybody else. Never bounded by the mask.
    pub other: u8,
}

impl Acl {
    /// The mask's bits, or every bit when there is no mask.
    const fn mask_bits(&self) -> u8 {
        match self.mask {
            Some(bits) => bits,
            None => ACL_PERM_ALL,
        }
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
    /// Whether this path still works from inside a box that dropped its supplementary GROUPS.
    ///
    /// GROUPS AND NOTHING ELSE. It says nothing about the box's UID, and `Owner` and `AclUser` both
    /// depend on one: a box started `--user <non-root>` or from an image with a `USER` runs as a
    /// subordinate uid, where neither applies. [`uid_dependent_nodes`] answers that question, and
    /// the two are separate because the answers arrive at different times, the groups at resolve and
    /// the identity only once `run_as` has folded in the image's own declaration.
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
/// The kernel's order is reproduced exactly, and the list below was WRONG until 2026-11-12: it put
/// the mask on step 3 alone. POSIX bounds every NAMED entry by the mask, step 2 included, and the
/// comment stating otherwise was the specification the code implemented.
///
///   1. the owner class is consulted first AND EXCLUSIVELY when the uid matches, and is NOT
///      bounded by the mask;
///   2. then `ACL_USER` for the caller's uid, exclusive once it matches, BOUNDED BY THE MASK;
///   3. then the group class, the file's gid plus any `ACL_GROUP` entry, each entry bounded by the
///      mask, with no union between entries and no fall-through to `other` once the caller is in
///      any of them;
///   4. then `other`, which is also not bounded by the mask.
///
/// And it answers for the access the DRIVER performs, [`WANT_RW`], not for read: a node the caller
/// can read and not write is Unreachable, because `cuInit` opens it `O_RDWR`.
///
/// Step 1 being exclusive is not a detail: a node owned by the caller with mode `0o040` is
/// `Unreachable`, not `GroupOnly`, and a resolver that fell through to the group class would report
/// a decision the kernel never offers.
pub fn access_path(node: &NodeFacts, who: &Caller) -> AccessPath {
    access_path_for(node, who, WANT_RW)
}

/// [`access_path`] for an arbitrary `want`, which is what makes the rule testable against the
/// kernel's own behaviour one bit at a time.
///
/// `want` is a triad of ACL permission bits. Production asks for [`WANT_RW`] and nothing else; the
/// parameter exists because a test that can only ask the production question cannot show that
/// asking a DIFFERENT one changes the answer, and "read is enough" was the defect.
pub fn access_path_for(node: &NodeFacts, who: &Caller, want: u8) -> AccessPath {
    let granted = |perm: u8| perm & want == want;

    // ROOT IS NOT SUBJECT TO THE MODE, and this answered as though it were: `sudo kern --gpus`
    // refused a node root can open, because the arithmetic below is the DAC check and root carries
    // `CAP_DAC_OVERRIDE` in the initial user namespace, which skips it. The caller here is the
    // host-side process running `kern`, so uid 0 means real root.
    //
    // `Owner` is the honest variant: it is uid-based, so it survives a box for the same reason the
    // owner class does, and `uid_dependent_nodes` separately asks whether the BOX's identity still
    // reaches the node. A box's own root is a different thing from this one, which holds
    // `CAP_DAC_OVERRIDE` only over objects whose owner is mapped into its namespace, and that
    // question is not this function's.
    if who.uid == 0 {
        return AccessPath::Owner;
    }

    // 1. THE OWNER CLASS, consulted first and EXCLUSIVELY, and never bounded by the mask.
    //    `posix_acl_permission` reaches `check_perm` for `ACL_USER_OBJ` without passing through the
    //    mask label, and `acl_permission_check` returns on the owner triad before it even looks for
    //    an ACL. So a node owned by the caller with mode `0o040` is Unreachable and not GroupOnly.
    if node.uid == who.uid {
        let perm = match &node.acl {
            Some(acl) => acl.user_obj,
            None => node.mode_owner(),
        };
        return if granted(perm) {
            AccessPath::Owner
        } else {
            AccessPath::Unreachable
        };
    }

    let Some(acl) = &node.acl else {
        // NO ACL: `acl_permission_check`'s plain path, through the same group-class spelling. The
        // group class is still EXCLUSIVE, which is the part a fall-through gets wrong: the kernel
        // shifts to the group triad whenever group and other differ in a requested bit, so `0o606`
        // denies a group member the write it would have had as `other`. There is no mask to apply.
        let (found, satisfying) = group_class_matches(node, who, want);
        if found {
            return if satisfying.is_empty() {
                AccessPath::Unreachable
            } else {
                AccessPath::GroupOnly
            };
        }
        return if granted(node.mode_other()) {
            AccessPath::Other
        } else {
            AccessPath::Unreachable
        };
    };

    // 2. A NAMED USER ENTRY, exclusive once it matches, and BOUNDED BY THE MASK. This is the
    //    defect: the previous rule returned `AclUser` here without consulting the mask at all, so a
    //    node carrying `user:alex:rw-` under `mask::---`, which `getfacl` itself prints as
    //    `#effective:---`, was reported reachable. On this host BOTH DRM nodes a grant touches go
    //    through this branch (`user:<caller>:rw-` on a root-owned node), so the case is live here
    //    and not only on the headless shape.
    if let Some((_, perm)) = acl.users.iter().find(|(uid, _)| *uid == who.uid) {
        return if granted(perm & acl.mask_bits()) {
            AccessPath::AclUser
        } else {
            AccessPath::Unreachable
        };
    }

    // 3. THE GROUP CLASS: the owning group plus every named group entry. One spelling, shared with
    //    `group_policy`, so the verdict and the message it prints cannot disagree.
    let (found, satisfying) = group_class_matches(node, who, want);
    if found {
        return if !satisfying.is_empty() && granted(acl.mask_bits()) {
            AccessPath::GroupOnly
        } else {
            AccessPath::Unreachable
        };
    }

    // 4. EVERYBODY ELSE, never bounded by the mask.
    if granted(acl.other) {
        AccessPath::Other
    } else {
        AccessPath::Unreachable
    }
}

/// The group class of a node, as the caller meets it: whether the caller is in it at all, and which
/// of its gids carry every bit of `want` on their own entry.
///
/// THE ONE SPELLING of the group-class question. [`access_path_for`] decides with it and
/// [`group_policy`] reports its gids, so a node refused for wanting a group and the list of gids
/// printed beside the refusal are computed once. A derived condition evaluated in two places is
/// this project's recurring defect, and this is the condition that invited it: the resolver, the
/// refusal and the doctor row would each be tempted to ask it again.
///
/// TWO PROPERTIES, both of which the previous rule lacked. The kernel does not UNION entries: a
/// single entry must carry every requested bit by itself, so `group::r--` beside `group:other:-w-`
/// under `mask::rw-` satisfies a read check and a write check SEPARATELY and refuses `O_RDWR`.
/// And `found` is not the same as satisfied: once the caller is in any group-class entry the
/// decision is made there, because `posix_acl_permission` sets `found` and its `ACL_OTHER` arm then
/// returns `-EACCES` instead of consulting `other`.
///
/// The mask is deliberately NOT applied here. It bounds the whole class rather than one entry, so
/// the caller applies it once; folding it in would make an empty result mean two different things.
fn group_class_matches(node: &NodeFacts, who: &Caller, want: u8) -> (bool, Vec<u32>) {
    let mut found = false;
    let mut satisfying: Vec<u32> = Vec::new();

    // With an ACL present the owning group's permission is `ACL_GROUP_OBJ` and NOT `st_mode`'s
    // group triad, which is the mask. Taking it from the mode here is the mirror of the defect this
    // function exists to fix.
    let group_obj = match &node.acl {
        Some(acl) => acl.group_obj,
        None => node.mode_group(),
    };
    if who.in_group(node.gid) {
        found = true;
        if group_obj & want == want {
            satisfying.push(node.gid);
        }
    }
    if let Some(acl) = &node.acl {
        for (gid, perm) in &acl.groups {
            if who.in_group(*gid) {
                found = true;
                if perm & want == want {
                    satisfying.push(*gid);
                }
            }
        }
    }

    satisfying.sort_unstable();
    satisfying.dedup();
    (found, satisfying)
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
    /// The card's PCI address, exactly as `/proc/driver/nvidia/gpus` spells it, when the driver's
    /// own directory names one. It is read in the SAME walk that paired this card with its DRM
    /// nodes, so the two cannot disagree.
    ///
    /// `None` on a host whose driver exposes no `gpus` directory, and in a synthetic root that
    /// builds only `/dev`. A caller that needs the address must handle its absence rather than
    /// assume a shape the filesystem did not provide.
    pub pci_address: Option<String>,
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
    /// The driver's own tools this host has, each bound read-only at `/usr/bin/<name>` in the box.
    pub tools: Vec<DriverTool>,
    /// The driver's configuration files this host has (Vulkan, EGL, OptiX), as (host file, path in
    /// the box). See [`DRIVER_CONFIG_FILES`].
    pub configs: Vec<(PathBuf, String)>,
    /// Directories bound whole, read-only (`dir` rows of a Jetson's CSV, such as `/dev/dri/by-path`).
    pub dirs: Vec<PathBuf>,
    /// The libraries and links go at the HOST's paths, and the box's loader is told their
    /// directories (see [`TegraCsv`]), instead of being placed in the image's library directory.
    pub at_host_paths: bool,
    /// The sysfs paths a Jetson's GPU runtime reads to identify the chip, bound read-only into the
    /// box's `/sys` (see [`TEGRA_SYSFS`]). Empty everywhere else.
    pub sysfs: Vec<PathBuf>,
    /// The nodes in `shared` that came from a Jetson's CSV rather than from every NVIDIA host. One
    /// of them the caller cannot open is left out rather than refusing the grant (see
    /// `plan_binds`): the list names debug and profiler nodes of a group the caller is not in.
    pub listed_nodes: BTreeSet<PathBuf>,
}

/// Where NVIDIA's container toolkit lists, on a Jetson, every file a GPU container is given: the
/// toolkit's "CSV mode", which it auto-detects from [`TEGRA_RELEASE_REL`].
const TEGRA_CSV_DIR_REL: &str = "etc/nvidia-container-runtime/host-files-for-container.d";
/// What marks a Jetson (L4T) host, as the toolkit's mode detection reads it.
const TEGRA_RELEASE_REL: &str = "etc/nv_tegra_release";

/// The sysfs a Jetson's GPU runtime reads before `cuInit` can succeed, and nothing more.
///
/// ⛔ A KERN BOX MOUNTS NO SYSFS, and docker gives its container the whole of `/sys` read-only. With
/// none, `libnvrm_gpu` said "No matching chip spec found for chip Id=0" and `NvRmGpuLibOpen failed`.
/// MEASURED with `strace` around `cuInit` on a Jetson Orin Nano: it reads `/sys/devices/soc0/
/// {soc_id,revision,major,platform}`, `/sys/devices/system/cpu/online` (which a box already has, as
/// kern's own CPU topology), and the chip's fuses (`/sys/bus/nvmem/devices/fuse/nvmem`), which are
/// left out: they are the chip's unique identifiers, root-only on the host, and the runtime does
/// without them.
const TEGRA_SYSFS: [&str; 1] = ["sys/devices/soc0"];

/// A Jetson's GPU, as NVIDIA's own CSV lists it: device nodes, directories, libraries, links.
///
/// ⛔ WHY THE LIST AND NOT THE DESKTOP SWEEP. On a Jetson the desktop rule (every library carrying
/// the driver version) found 12 graphics libraries and NOT `libcuda.so.1.1`, whose name carries no
/// version, nor the Tegra libraries CUDA loads (`libnvrm_gpu.so`, `libnvos.so`...): MEASURED on a
/// Jetson Orin Nano (JetPack R36.4.7), `cuInit` worked on the host and the box had no `libcuda.so.1`.
/// Docker there runs the toolkit in CSV mode: `--runtime nvidia` with `NVIDIA_VISIBLE_DEVICES` mounts
/// the 39 nodes of `devices.csv` and the 239 libraries and 46 links of `drivers.csv` at their host
/// paths, writes their directories to `/etc/ld.so.conf.d/00-nvcr-*.conf`, and CUDA initialises (same
/// board, measured). kern reads the same files and does the same.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TegraCsv {
    pub devs: Vec<PathBuf>,
    pub dirs: Vec<PathBuf>,
    pub libs: Vec<PathBuf>,
    pub syms: Vec<PathBuf>,
}

/// Add the rows of one CSV file (`<kind>, <absolute path>`) to `into`, each path placed under
/// `root`. Comments, blank lines, unknown kinds and relative paths are skipped.
pub fn parse_tegra_csv(text: &str, root: &Path, into: &mut TegraCsv) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((kind, path)) = line.split_once(',') else {
            continue;
        };
        let path = path.trim();
        if !path.starts_with('/') || path.split('/').any(|c| c == "..") {
            continue;
        }
        let at = root.join(path.trim_start_matches('/'));
        // A ROW MAY BE A PATTERN: `dev, /dev/dri/card*` and `dev, /dev/dri/renderD*` on JetPack 6.
        // Read literally they named no file, and the box had no DRM node: MEASURED on a Jetson Orin
        // Nano, `cuInit` then died with SIGSEGV in the box while docker's container, given the four
        // nodes, initialised.
        let found = expand_last_component(&at);
        let list = match kind.trim() {
            "dev" => &mut into.devs,
            "dir" => &mut into.dirs,
            "lib" => &mut into.libs,
            "sym" => &mut into.syms,
            _ => continue,
        };
        list.extend(found);
    }
}

/// `path` itself, or, when its last component holds `*` or `?`, the entries of its directory that
/// match it, sorted. A pattern in an earlier component is not expanded: NVIDIA's lists put them last.
fn expand_last_component(path: &Path) -> Vec<PathBuf> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return vec![path.to_path_buf()];
    };
    if !name.contains(['*', '?']) {
        return vec![path.to_path_buf()];
    }
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .is_some_and(|n| wildcard_match(name, n))
                })
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// Shell-style match of `name` against `pattern`, where `*` is any run and `?` any one character.
fn wildcard_match(pattern: &str, name: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (pattern.chars().collect(), name.chars().collect());
    let (mut pi, mut ni) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// The Jetson CSV lists under `root`, when this is a Jetson that has them. A list file must be a
/// regular file owned by root and writable by nobody else, as the CDI specs kern reads must be: it
/// decides what a box is handed. A synthetic root (a test's) is not held to the owner.
fn tegra_csv_under(root: &Path) -> Option<TegraCsv> {
    use std::os::unix::fs::MetadataExt;
    if !root.join(TEGRA_RELEASE_REL).exists() {
        return None;
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(root.join(TEGRA_CSV_DIR_REL))
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "csv"))
        .collect();
    files.sort();
    let real_root = root == Path::new("/");
    let mut csv = TegraCsv::default();
    for f in files {
        let Ok(m) = std::fs::symlink_metadata(&f) else {
            continue;
        };
        if !m.is_file() || (real_root && (m.uid() != 0 || m.mode() & 0o022 != 0)) {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&f) {
            parse_tegra_csv(&text, root, &mut csv);
        }
    }
    (!csv.libs.is_empty()).then_some(csv)
}

/// `path`, already resolved by [`follow_links_under`], as the canonical path it names, when that stays
/// under `root`. NVIDIA's list holds links like `gbm/tegra_gbm.so -> ../nvidia/libnvidia-allocator.so`,
/// and a bind source with a `..` in it is refused by the box: MEASURED on a Jetson Orin Nano, "volume
/// source must be canonical".
fn canonical_under(root: &Path, path: &Path) -> Option<PathBuf> {
    let real = canonical(path)?;
    let real_root = canonical(root)?;
    real.starts_with(&real_root).then_some(real)
}

/// `std::fs::canonicalize`, with each DIRECTORY resolved once per process.
///
/// A GRANT RESOLVES HUNDREDS OF FILES IN A FEW DIRECTORIES, and `canonicalize` walks every component
/// of every path with a `readlink`: MEASURED on a Jetson, 748 path syscalls under `/usr` for one
/// grant, every library repeating the walk of `/usr/lib/aarch64-linux-gnu`, and the root resolved
/// again for each one. The answer is the same: a file that is not itself a link is its directory's
/// canonical path plus its name, and the directory's answer is remembered. A link, or anything
/// that cannot be read as "not a link", takes the full walk as before, so the result is the one
/// `canonicalize` gives. One invocation of kern lives milliseconds; a directory's canonical path
/// does not change under it in a way the box's own no-follow bind would not refuse anyway.
fn canonical(path: &Path) -> Option<PathBuf> {
    use std::cell::RefCell;
    use std::collections::HashMap;
    thread_local! {
        static DIRS: RefCell<HashMap<PathBuf, PathBuf>> = RefCell::new(HashMap::new());
    }
    let dir_of = |d: &Path| -> Option<PathBuf> {
        if let Some(hit) = DIRS.with(|m| m.borrow().get(d).cloned()) {
            return Some(hit);
        }
        let real = std::fs::canonicalize(d).ok()?;
        DIRS.with(|m| m.borrow_mut().insert(d.to_path_buf(), real.clone()));
        Some(real)
    };
    // A `.` or `..` anywhere, or a trailing `/`, takes the full walk: `Path` drops a trailing `.`
    // from `file_name`, so `link/.` would read as the link's own name and not its target.
    let plain = {
        use std::os::unix::ffi::OsStrExt;
        let b = path.as_os_str().as_bytes();
        !b.ends_with(b"/") && !b.split(|c| *c == b'/').any(|s| s == b"." || s == b"..")
    };
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name))
            if plain
                && !parent.as_os_str().is_empty()
                && std::fs::symlink_metadata(path).is_ok_and(|m| !m.file_type().is_symlink()) =>
        {
            Some(dir_of(parent)?.join(name))
        }
        _ => std::fs::canonicalize(path).ok(),
    }
}

/// The CSV's libraries that exist under `root`, resolved, of the wanted class, deduplicated by
/// identity: the same rules as the desktop sweep, applied to NVIDIA's list instead of a suffix.
fn csv_libraries(root: &Path, csv: &TegraCsv, want: ElfClass) -> Vec<Library> {
    let mut out: Vec<Library> = Vec::new();
    let mut identities: BTreeSet<(u64, u64)> = BTreeSet::new();
    for listed in &csv.libs {
        let mut path = listed.clone();
        if !follow_links_under(root, &mut path) {
            continue;
        }
        let Some(path) = canonical_under(root, &path) else {
            continue;
        };
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() || elf_class_of(&path) != Some(want) {
            continue;
        }
        if identities.insert((meta.dev(), meta.ino())) {
            out.push(Library {
                path,
                dev: meta.dev(),
                ino: meta.ino(),
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// The CSV's links that exist under `root` and end, inside it, at a regular file.
fn csv_symlinks(root: &Path, csv: &TegraCsv) -> Vec<Symlink> {
    let mut out: Vec<Symlink> = Vec::new();
    for link in &csv.syms {
        let Ok(target) = std::fs::read_link(link) else {
            continue;
        };
        let mut resolved = link.clone();
        if !follow_links_under(root, &mut resolved) {
            continue;
        }
        let Some(resolved) = canonical_under(root, &resolved) else {
            continue;
        };
        if std::fs::metadata(&resolved).is_ok_and(|m| m.is_file()) {
            out.push(Symlink {
                link: link.clone(),
                target,
                resolved,
            });
        }
    }
    out.sort_by(|a, b| a.link.cmp(&b.link));
    out
}

/// The NVIDIA configuration files a grant binds, as (path under the root, path in the box): the set
/// NVIDIA's own CDI spec mounts, at the paths it mounts them.
///
/// MEASURED on this host, `nvidia-ctk` 1.18.2's spec against a docker 29.1.3 container given
/// `--device nvidia.com/gpu=0`: the Vulkan ICD and layer files land in `/etc/vulkan/…`, the EGL and
/// OptiX ones at their own path, and with them `vulkaninfo` in `ubuntu:24.04` lists the RTX 5060 Ti
/// as an NVIDIA device. A kern box had none of the files, so the Vulkan and EGL loaders could not
/// learn that an NVIDIA driver exists, whatever libraries were bound.
///
/// Two rows can fill one box path (a host that keeps the ICD in `/etc` rather than `/usr/share`); the
/// first found wins. Left out on purpose, though the spec mounts them: the GSP firmware (the host's
/// kernel loads it, a box has no use for it), `xorg.conf.d` (a box runs no X server), and the
/// `nvidia-persistenced` socket, which would be a channel from the box to a root daemon on the host.
pub const DRIVER_CONFIG_FILES: [(&str, &str); 8] = [
    (
        "usr/share/vulkan/icd.d/nvidia_icd.json",
        "/etc/vulkan/icd.d/nvidia_icd.json",
    ),
    (
        "etc/vulkan/icd.d/nvidia_icd.json",
        "/etc/vulkan/icd.d/nvidia_icd.json",
    ),
    (
        "usr/share/vulkan/implicit_layer.d/nvidia_layers.json",
        "/etc/vulkan/implicit_layer.d/nvidia_layers.json",
    ),
    (
        "etc/vulkan/implicit_layer.d/nvidia_layers.json",
        "/etc/vulkan/implicit_layer.d/nvidia_layers.json",
    ),
    (
        "usr/share/glvnd/egl_vendor.d/10_nvidia.json",
        "/usr/share/glvnd/egl_vendor.d/10_nvidia.json",
    ),
    (
        "usr/share/egl/egl_external_platform.d/10_nvidia_wayland.json",
        "/usr/share/egl/egl_external_platform.d/10_nvidia_wayland.json",
    ),
    (
        "usr/share/egl/egl_external_platform.d/15_nvidia_gbm.json",
        "/usr/share/egl/egl_external_platform.d/15_nvidia_gbm.json",
    ),
    (
        "usr/share/nvidia/nvoptix.bin",
        "/usr/share/nvidia/nvoptix.bin",
    ),
];

/// The configuration files of [`DRIVER_CONFIG_FILES`] that exist under `root` as regular files.
pub fn driver_configs_under(root: &Path) -> Vec<(PathBuf, String)> {
    let mut out: Vec<(PathBuf, String)> = Vec::new();
    for (rel, target) in DRIVER_CONFIG_FILES {
        if out.iter().any(|(_, t)| t == target) {
            continue;
        }
        let Some(real) = canonical(&root.join(rel)) else {
            continue;
        };
        if std::fs::metadata(&real)
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            out.push((real, target.to_string()));
        }
    }
    out
}

/// The links NVIDIA's CDI hook creates beside the libraries, as (library file prefix, link path under
/// the library directory). kern binds the file at the link's path, as it does for every other link.
///
/// MEASURED in the docker container given the spec: `libGLX_indirect.so.0 -> libGLX_nvidia.so.<v>`
/// and `gbm/nvidia-drm_gbm.so -> ../libnvidia-allocator.so.1`; GLVND's indirect GLX and GBM's
/// backend loader open those names.
const DRIVER_ALIAS_LINKS: [(&str, &str); 2] = [
    ("libGLX_nvidia.so.", "libGLX_indirect.so.0"),
    ("libnvidia-allocator.so.", "gbm/nvidia-drm_gbm.so"),
];

/// One of the driver's own tools (`nvidia-smi` and the four beside it), found on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverTool {
    /// The bare name, which is also its name in the box.
    pub name: String,
    /// The host file, symlinks resolved, so the bind lands the binary and not a dangling link.
    pub source: PathBuf,
}

/// Where a box finds the driver's tools: the directory docker's NVIDIA runtime puts them in.
///
/// MEASURED against docker 29.1.3 with toolkit 1.20.2, on this host (`--gpus device=1`, ubuntu:24.04)
/// and on a WSL2 guest: `/usr/bin/nvidia-smi` is there in both, plus `nvidia-debugdump`,
/// `nvidia-persistenced`, `nvidia-cuda-mps-control` and `nvidia-cuda-mps-server` on the native host.
/// Every guide checks a GPU container with `nvidia-smi`, and the `nvidia/cuda:*-base` images ship
/// none, so a grant without the tools failed the first command anyone types.
pub const DRIVER_TOOLS_IN_BOX: &str = "/usr/bin";

/// Where the host's tools are looked for, in this order, relative to the root: the
/// `PATH` libnvidia-container searches, so the file found is the one docker would have bound.
const DRIVER_TOOL_DIRS_REL: [&str; 6] = [
    "usr/local/sbin",
    "usr/local/bin",
    "usr/sbin",
    "usr/bin",
    "sbin",
    "bin",
];

/// The driver tools under `root`, at most one per name, each a regular file once resolved.
///
/// A NAME THE HOST DOES NOT HAVE IS SIMPLY ABSENT, which is what docker does too: a driver installed
/// without `nvidia-persistenced` gives a box without it, and the four others still come.
pub fn driver_tools_under(root: &Path) -> Vec<DriverTool> {
    let mut out: Vec<DriverTool> = Vec::new();
    for name in kern_isolation::driver_tools() {
        for dir in DRIVER_TOOL_DIRS_REL {
            let Some(real) = canonical(&root.join(dir).join(name)) else {
                continue;
            };
            if std::fs::metadata(&real)
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                out.push(DriverTool {
                    name: (*name).to_string(),
                    source: real,
                });
                break;
            }
        }
    }
    out
}

impl GpuGrant {
    /// Every node in the grant, shared first then per card.
    ///
    /// TEST-ONLY, because no production surface describes the whole host any more: `render_plan`
    /// used this and now builds the SELECTION's node list instead, which is the fix that made
    /// `--plan` describe the box being planned. Keeping it `pub` in the shipped build would be the
    /// same smell as the `Detail::Full` that had no caller, one directory along.
    #[cfg(test)]
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
    // Bounded and type-checked: this walk runs on `kern doctor`, `kern run --gpus` and `--plan`,
    // and a FIFO at the name would hang all three.
    let text = crate::openat2::read_regular_path(information, MAX_DRIVER_INFO_BYTES).ok()??;
    text.lines()
        .find_map(|l| l.strip_prefix("Device Minor:"))?
        .trim()
        .parse()
        .ok()
}

/// The DRM nodes that belong to the same physical card as `/dev/nvidiaN`, resolved through the PCI
/// address and never through the index.
///
/// 🚨 THE INDEX IS NOT A SOURCE, and the reason is stronger than a static example: THE PAIRING IS
/// NOT STABLE ON ONE MACHINE. This comment used to read "this host proves it: `nvidia0` is PCI
/// `0000:01:00.0`, whose DRM nodes are `card1` and `renderD128`", which was measured and true when
/// written. After a reboot on 2026-11-12 the same machine derives `0000:01:00.0` as `nvidia0` AND
/// `card0`. DRM minors are handed out in probe order, so a kernel or firmware change reorders them
/// while the PCI address does not move. A grant that paired `nvidia0` with `card0` would hand the
/// box the other card's display node on SOME BOOTS, silently, and every test on a single-GPU host
/// would pass.
///
/// The chain is: `proc/driver/nvidia/gpus/<bdf>/information` gives the minor, the directory name
/// gives the PCI address, and `sys/bus/pci/devices/<bdf>/drm/` lists the nodes. Only `card*` and
/// `renderD*` are taken; `controlD*` is a legacy node no current driver uses.
/// THE ADDRESS COMES BACK WITH THE NODES, from the SAME walk. It is also what masks the other
/// cards out of the box's `/proc/driver/nvidia/gpus`, and reading it a second time elsewhere would
/// be the same derived condition computed in two places that this file already warns about: a
/// second walk could pair a card with one address here and another there, and the mask would hide
/// the card that was granted.
fn drm_nodes_for(root: &Path, minor: u32) -> (Option<String>, Vec<PathBuf>) {
    let gpus = root.join("proc/driver/nvidia/gpus");
    let Ok(entries) = std::fs::read_dir(&gpus) else {
        return (None, Vec::new());
    };
    for entry in entries.flatten() {
        if device_minor_of(&entry.path().join("information")) != Some(minor) {
            continue;
        }
        let bdf = entry.file_name();
        // A directory name that is not UTF-8 is not a PCI address, and the mask would have nothing
        // to name. The nodes are still resolved: the two answers are independent.
        let address = bdf.to_str().map(str::to_string);
        let drm_dir = root.join("sys/bus/pci/devices").join(&bdf).join("drm");
        let Ok(nodes) = std::fs::read_dir(&drm_dir) else {
            return (address, Vec::new());
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
        return (address, out);
    }
    (None, Vec::new())
}

/// The per-card nodes: `/dev/nvidiaN` plus the DRM nodes of the same physical card.
///
/// The set of cards is read from the directory rather than assumed contiguous from zero, because a
/// driver may leave a gap and a grant that counted upwards would miss the card that is there.
fn card_node_paths(root: &Path) -> Vec<(u32, Option<String>, Vec<PathBuf>)> {
    let dev = root.join("dev");
    let mut cards: Vec<(u32, Option<String>, Vec<PathBuf>)> = Vec::new();
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
        let (address, drm) = drm_nodes_for(root, index);
        nodes.extend(drm);
        cards.push((index, address, nodes));
    }
    cards.sort_by_key(|(i, _, _)| *i);
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
/// Follow the symlink chain at `path`, in place, with every target resolved UNDER `root`.
///
/// ONE SPELLING for the two callers that need it, and the reason they both needed fixing is that
/// they disagreed about the same question. An ABSOLUTE target used to stop the walk in
/// [`canonical_dir_under`], which left THE SYMLINK in the result, the exact shape that function
/// exists to remove; and [`libraries_from`] followed one with `std::fs::metadata` and recorded the
/// LINK as the path to mount, which breaks the invariant [`symlinks_for`] enforces (the resolved
/// file is bound at the link's own path).
///
/// AN ABSOLUTE TARGET IS TAKEN AGAINST THE ROOT, which is both the correct resolution and the one
/// that cannot escape: inside a root, `/usr/lib` means `<root>/usr/lib`, exactly as it would after
/// a `pivot_root`. With the production root of `/` that is the identity, so nothing changes there;
/// under a synthetic root it is the difference between resolving a link and leaving it.
///
/// `false` when the chain did not reach a non-symlink within [`MAX_LINK_HOPS`], or when a target
/// climbed out of the root with `..`. `path` is left wherever the walk stopped, so a caller that
/// treats `false` as a skip never mounts a half-resolved path. A loop is a thing a filesystem
/// permits and an unbounded walk is a hang.
fn follow_links_under(root: &Path, path: &mut PathBuf) -> bool {
    !matches!(
        walk_links_under(root, path, MAX_LINK_HOPS),
        LinkWalk::Refused
    )
}

/// Where a chain walked by [`walk_links_under`] stopped.
enum LinkWalk {
    /// At a non-symlink, with its `lstat`, which for a non-symlink IS its `stat`: the caller that
    /// needs the file's identity has it without asking the filesystem a second time.
    Reached(std::fs::Metadata),
    /// At a path with nothing there. Not a link, so as resolved as it gets.
    Missing,
    /// Out of hops, an unreadable link, or a target that climbed out of the root.
    Refused,
}

/// [`follow_links_under`] with the final metadata kept and the hop budget the caller's: a caller
/// that has already taken the first hop itself passes one hop fewer, so the bound on the WHOLE
/// chain is the same [`MAX_LINK_HOPS`] either way.
fn walk_links_under(root: &Path, path: &mut PathBuf, hops: u8) -> LinkWalk {
    walk_links_noting(root, path, hops, &mut |_| {})
}

/// [`walk_links_under`], telling `note` every path a hop lands on, whether or not the hop is then
/// accepted: the record of a scan ([`remember_scan`]) needs every directory whose contents the
/// answer depended on, and a refused hop depended on its directory as much as a followed one.
fn walk_links_noting(
    root: &Path,
    path: &mut PathBuf,
    hops: u8,
    note: &mut dyn FnMut(&Path),
) -> LinkWalk {
    for _ in 0..hops {
        let Ok(meta) = std::fs::symlink_metadata(&*path) else {
            // Nothing there: not a symlink, so the chain is as resolved as it gets. A caller that
            // needs the path to EXIST checks that itself; this answers about links only.
            return LinkWalk::Missing;
        };
        if !meta.file_type().is_symlink() {
            return LinkWalk::Reached(meta);
        }
        let Ok(target) = std::fs::read_link(&*path) else {
            return LinkWalk::Refused;
        };
        let Some(next) = link_hop_target(root, path, &target) else {
            return LinkWalk::Refused;
        };
        note(&next);
        if !hop_stays_under(root, &next) {
            return LinkWalk::Refused;
        }
        *path = next;
    }
    LinkWalk::Refused
}

/// One hop of a chain: where `target`, read from the link at `link`, points under `root`, or
/// `None` when it climbs out. [`link_hop_target`], then [`hop_stays_under`].
fn link_hop_under(root: &Path, link: &Path, target: &Path) -> Option<PathBuf> {
    let next = link_hop_target(root, link, target)?;
    hop_stays_under(root, &next).then_some(next)
}

/// Where `target`, read from the link at `link`, points. AN ABSOLUTE TARGET IS TAKEN AGAINST THE
/// ROOT (see [`follow_links_under`]). `None` only for a link with no parent, which no path read out
/// of a directory is.
fn link_hop_target(root: &Path, link: &Path, target: &Path) -> Option<PathBuf> {
    if target.is_absolute() {
        Some(root.join(target.strip_prefix("/").unwrap_or(target)))
    } else {
        Some(link.parent()?.join(target))
    }
}

/// Whether a hop's destination stays under `root`.
///
/// `..` IN A TARGET CAN STILL CLIMB OUT, and joining it does not normalise, so the check is on what
/// the filesystem says the path really is. An unresolvable path cannot be shown to stay inside, so
/// it does not, unless it has no `..` at all: a dangling link is not an escape, and the walk stops
/// on the next turn because `symlink_metadata` fails.
///
/// UNDER THE REAL ROOT A PLAIN TARGET IS ACCEPTED WITHOUT ASKING. With `root` = `/` every resolved
/// path starts with `/`, and a path with no `..` is accepted whether it resolves or not, so the
/// `canonicalize` could only ever answer "accepted". It was still asked, and on a musl build it is
/// a `readlink` per component: MEASURED on a desktop with 2805 entries in `/usr/lib/x86_64-linux-gnu`
/// (1291 links), 7041 `readlink`s for one `--gpus` start, most of them this question.
fn hop_stays_under(root: &Path, next: &Path) -> bool {
    let climbs = next
        .components()
        .any(|c| c == std::path::Component::ParentDir);
    if !climbs && root == Path::new("/") {
        return true;
    }
    match std::fs::canonicalize(next) {
        Ok(real) => real.starts_with(root),
        Err(_) => !climbs,
    }
}

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
        // Best-effort per component, as before: a component that cannot be resolved is left as it
        // is rather than discarding the whole directory, because the caller only needs the
        // DIRECTORY NAMES the linker was told about and a later phase checks what it mounts.
        let _ = follow_links_under(root, &mut out);
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
    // EVERY CONF FILE IS READ ONCE. `MAX_LD_CONF_DEPTH` bounds how DEEP the includes nest and
    // bounded nothing about how WIDE they are: a file whose glob matches N files, each including a
    // glob matching N more, is N^depth reads, and two files that include each other are re-read at
    // every level until the depth runs out. Keyed on the canonical path, so the same file reached
    // through `/etc` and through a symlinked `/usr/etc` is one entry.
    let mut read_already: BTreeSet<PathBuf> = BTreeSet::new();
    while let Some((conf, depth)) = pending.pop() {
        if depth > MAX_LD_CONF_DEPTH {
            continue;
        }
        let key = std::fs::canonicalize(&conf).unwrap_or_else(|_| conf.clone());
        if !read_already.insert(key) {
            continue;
        }
        // THE SAME SHAPE AS THE CDI READ, and the same reach: a FIFO at `/etc/ld.so.conf` hung the
        // resolver, which runs on `kern doctor`, `kern run --gpus` and `kern box --plan`.
        let Ok(Some(text)) = crate::openat2::read_regular_path(&conf, MAX_LINKER_CONF_BYTES) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // ANY WHITESPACE AFTER `include`, AND EVERY PATTERN ON THE LINE. This matched
            // `"include "` with a single space and took the whole remainder as ONE pattern. glibc's
            // own parser skips any run of whitespace and reads a LIST, so `include<TAB>/a/*.conf`
            // was read as a directory called `include\t/a/*.conf` and
            // `include /a/*.conf /b/*.conf` found only the first. Both forms are in the wild and
            // both failed silently: the line was consumed and nothing was included.
            let include_patterns = line.strip_prefix("include").and_then(|rest| {
                // `include` must be a WORD: `included/lib` is a directory, not a directive.
                let trimmed = rest.trim_start();
                (trimmed.len() < rest.len()).then_some(trimmed)
            });
            if let Some(patterns) = include_patterns {
                for pattern in patterns.split_whitespace() {
                    // An `include` is relative to the root. The wildcard is ONE `*` anywhere in the
                    // file name, matched as a prefix and a suffix around it, which is the form every
                    // Debian-family host actually ships: `include /etc/ld.so.conf.d/*.conf`. A parser
                    // that only handled a TRAILING star read that line, found no match and silently
                    // included nothing; the library sweep still answered 29 on this host because the
                    // directory it needed was already a default, so the fault was invisible until a
                    // synthetic root put a library somewhere only the include could reach.
                    // A `..` IN A CONF LINE IS REFUSED, not rewritten. `trim_start_matches('/')`
                    // made a path relative to the root and a `..` then climbed straight back out of
                    // it, which on a synthetic root means reading the real host's files. There is no
                    // legitimate `..` in a linker configuration, so refusing is free.
                    if pattern.split('/').any(|c| c == "..") {
                        continue;
                    }
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
                                        // carry them without overlapping, or `ab*ba` would accept
                                        // `aba`.
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
                }
                continue;
            }
            // THE SAME REFUSAL FOR A BARE DIRECTORY LINE, which is the half that would otherwise
            // leave the hole open: `../../etc` as a directory entry climbs out exactly as an
            // include pattern does.
            if line.split('/').any(|c| c == "..") {
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
#[cfg(test)]
fn libraries_under(root: &Path, version: &str, want: ElfClass) -> Vec<Library> {
    libraries_from(root, want, &library_candidates(&linker_dirs(root), version))
}

/// The directory entries a grant's libraries can come from: every name in the linker's directories
/// that ends with `.so.<version>`, in the order the directories are read.
///
/// The match is on the whole ending, not on a substring, so `libfoo.so.580.173.021` cannot join a
/// `580.173.02` grant.
fn library_candidates(dirs: &[PathBuf], version: &str) -> Vec<PathBuf> {
    let suffix = format!(".so.{version}");
    let mut out: Vec<PathBuf> = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.ends_with(&suffix) {
                out.push(entry.path());
            }
        }
    }
    out
}

/// The libraries `candidates` resolve to: regular files of the wanted class, deduplicated by
/// identity, sorted by path.
fn libraries_from(root: &Path, want: ElfClass, candidates: &[PathBuf]) -> Vec<Library> {
    let mut out: Vec<Library> = Vec::new();
    let mut identities: BTreeSet<(u64, u64)> = BTreeSet::new();
    for candidate in candidates {
        // THE RESOLVED FILE, AND IT MUST STAY UNDER THE ROOT. This used to take `entry.path()` and
        // `std::fs::metadata`, which follows a symlink wherever it points, including out of the
        // root, and then recorded THE LINK as the path to mount. That breaks the invariant
        // `symlinks_for` enforces, where the resolved file is bound at the link's own path, and
        // under a synthetic root it names a file the bind would fail on with O_NOFOLLOW. A chain
        // that leaves the root is skipped: a library kern cannot name inside the root is not a
        // library it can hand over.
        let mut path = candidate.clone();
        // The walk's last `lstat` is the resolved file's own metadata (it is not a link), and the
        // identity that matters is the file's, because that is what two paths share.
        let LinkWalk::Reached(meta) = walk_links_under(root, &mut path, MAX_LINK_HOPS) else {
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
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Every symlink in the linker's directories `dirs` whose chain ends at one of the granted libraries.
///
/// The chain is followed by hand rather than with `std::fs::canonicalize`, for one reason that a
/// grant cannot afford to get wrong: `canonicalize` resolves against the REAL filesystem root, so
/// on a synthetic tree it would walk out of the root it was given, and on a real host it would
/// follow an absolute target to the host's own path. The walk here stays inside the directory the
/// link lives in, which is where a library's SONAME link always points.
///
/// `MAX_LINK_HOPS` bounds it. A symlink loop is a thing a filesystem permits, and an unbounded
/// resolver meeting one would not return. `note` is told every path a hop lands on
/// ([`walk_links_noting`]).
fn symlinks_for(
    root: &Path,
    dirs: &[PathBuf],
    granted: &[Library],
    note: &mut dyn FnMut(&Path),
) -> Vec<Symlink> {
    let identities: BTreeSet<(u64, u64)> = granted.iter().map(|l| (l.dev, l.ino)).collect();
    let mut out: Vec<Symlink> = Vec::new();
    // DEDUPLICATED BY THE LINK'S OWN IDENTITY, not by its path, for exactly the reason the library
    // sweep is: `/lib` is a symlink to `/usr/lib`, so the same link inode is reached by two paths.
    // Keying on the path answered 58 on this host where the truth is 29. This is the second time
    // the same mistake was made in this file, once for the files and once for the links, which is
    // why both now use the same key.
    let mut seen: BTreeSet<(u64, u64)> = BTreeSet::new();
    // First hop -> the granted file its chain ends at, or `None` when it ends anywhere else.
    let mut chains: std::collections::HashMap<PathBuf, Option<PathBuf>> =
        std::collections::HashMap::new();

    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
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
            // The link's OWN target, read once: it is the first hop of the walk below.
            let Ok(target) = std::fs::read_link(&link) else {
                continue;
            };
            // THE ONE RESOLVER, and this was the THIRD copy of the same hop loop. It carried the
            // same absolute-target bug the other two did, in the same direction as
            // `canonical_dir_under`'s: it gave up, so a library reached through an absolute link
            // inside the root had no symlink recorded and the box got the file with no SONAME
            // pointing at it. A derived condition evaluated in three places is this project's
            // recurring defect, and this one took three fixes to notice.
            //
            // THE FIRST HOP IS TAKEN FROM THE TARGET JUST READ, and the walk goes on from there with
            // one hop fewer, so the bound on the whole chain is unchanged. The walk used to start
            // again at the link: an `lstat` to learn it was a link and a second `readlink` of it.
            //
            // AND A CHAIN IS WALKED ONCE PER STARTING POINT. `libz.so` and `libz.so.1` both point
            // at `libz.so.1.3`; what that path resolves to does not depend on which link led
            // there. MEASURED on this host (2805 entries, 1291 links in `/usr/lib/x86_64-linux-gnu`):
            // about 9 syscalls per link before, 1 `readlink` plus at most 1 `lstat` now, and the
            // final `stat` is the walk's own last `lstat`, which for a non-link is the same answer.
            let Some(first) = link_hop_target(root, &link, &target) else {
                continue;
            };
            note(&first);
            if !hop_stays_under(root, &first) {
                continue;
            }
            let ends_in_grant = match chains.get(&first) {
                Some(known) => known.clone(),
                None => {
                    let mut resolved = first.clone();
                    let answer = match walk_links_noting(
                        root,
                        &mut resolved,
                        MAX_LINK_HOPS.saturating_sub(1),
                        note,
                    ) {
                        LinkWalk::Reached(meta)
                            if identities.contains(&(meta.dev(), meta.ino())) =>
                        {
                            Some(resolved)
                        }
                        _ => None,
                    };
                    chains.insert(first, answer.clone());
                    answer
                }
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

/// The grant's libraries and links under `root`: from the record of an earlier scan when it still
/// holds ([`recall_scan`]), otherwise from a scan, which is then recorded ([`remember_scan`]).
///
/// THE SCAN WAS MOST OF A `--gpus` START. MEASURED on a desktop (2x RTX 5060 Ti, 2805 entries and
/// 1291 links in `/usr/lib/x86_64-linux-gnu`), medians of 15: 7.5 ms of the parent's 8.7 ms
/// `config+volumes`, 5.5 ms of it reading every link in the linker's directories, on every box,
/// to find the 29 that end at the driver's libraries. The answer changes only when those
/// directories do.
fn libraries_and_links(
    root: &Path,
    version: &str,
    want: ElfClass,
    record: Option<&Path>,
) -> (Vec<Library>, Vec<Symlink>) {
    // Recomputed every time, not recorded: it is the configuration the loader reads, cheap to
    // parse, and a record compared against it cannot miss an `ld.so.conf` edit.
    let dirs = linker_dirs(root);
    if let Some(found) = record.and_then(|r| recall_scan(r, root, version, want, &dirs)) {
        return found;
    }
    let started = std::time::SystemTime::now();
    let candidates = library_candidates(&dirs, version);
    let libraries = libraries_from(root, want, &candidates);
    let mut touched: BTreeSet<PathBuf> = BTreeSet::new();
    let symlinks = symlinks_for(root, &dirs, &libraries, &mut |hop: &Path| {
        if let Some(parent) = hop.parent() {
            if !touched.contains(parent) {
                touched.insert(parent.to_path_buf());
            }
        }
    });
    if let Some(r) = record {
        let scan = ScanRecord {
            root,
            version,
            want,
            dirs: &dirs,
            touched: &touched,
            candidates: &candidates,
            libraries: &libraries,
            symlinks: &symlinks,
        };
        if let Some(cutoff) = settled_before(started) {
            remember_scan(r, &scan, cutoff);
        }
    }
    (libraries, symlinks)
}

/// Format tag of the scan record. A record written by another version of the format is a miss.
const SCAN_RECORD_MAGIC: &[u8] = b"kern-gpu-scan-1";

/// How recently a watched directory may have changed for a scan to be recorded, in seconds.
///
/// A directory's timestamps have a granularity (the kernel's coarse clock), so a change made in the
/// same tick as one the scan already saw leaves them EQUAL, and a record keyed on them would hold a
/// stale answer. A scan that saw a directory change this recently is used and not recorded; the
/// next one records it.
const SCAN_RECORD_SETTLE_SECS: u64 = 2;

/// Everything a scan's answer was derived from, for [`remember_scan`].
struct ScanRecord<'a> {
    root: &'a Path,
    version: &'a str,
    want: ElfClass,
    dirs: &'a [PathBuf],
    touched: &'a BTreeSet<PathBuf>,
    candidates: &'a [PathBuf],
    libraries: &'a [Library],
    symlinks: &'a [Symlink],
}

fn class_tag(want: ElfClass) -> &'static [u8] {
    match want {
        ElfClass::Bits32 => b"32",
        ElfClass::Bits64 => b"64",
    }
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(field);
    out.push(0);
}

fn push_number(out: &mut Vec<u8>, n: impl std::fmt::Display) {
    push_field(out, n.to_string().as_bytes());
}

/// A directory's identity and both of its timestamps: what changes when an entry is added, removed,
/// renamed or replaced (`mtime`), and what no caller can set back (`ctime`, which `utime` itself
/// moves forward).
fn dir_stamp(meta: &std::fs::Metadata) -> [i64; 6] {
    // `dev` and `ino` are `u64`; they are compared, never computed with, so the bit pattern is the
    // value and the cast cannot lose one.
    [
        meta.dev() as i64,
        meta.ino() as i64,
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
    ]
}

/// The newest timestamp, in seconds since the epoch, a watched directory may carry for a scan that
/// started at `started` to be recorded ([`SCAN_RECORD_SETTLE_SECS`]).
fn settled_before(started: std::time::SystemTime) -> Option<i64> {
    let since_epoch = started.duration_since(std::time::UNIX_EPOCH).ok()?;
    i64::try_from(
        since_epoch
            .as_secs()
            .saturating_sub(SCAN_RECORD_SETTLE_SECS),
    )
    .ok()
}

/// Record a scan at `record`, unless one of the directories it depended on carries a timestamp at or
/// after `cutoff` ([`settled_before`]) or can no longer be read.
///
/// WHAT IS WATCHED: every linker directory (its entries are the candidates and the links), and the
/// directory of every path any chain's hop landed on, followed or refused. A link anywhere in those
/// directories cannot be added, removed or re-pointed without changing that directory's `mtime`
/// and `ctime`, and a directory reached through a re-pointed directory link is a different `ino`.
/// What is NOT watched, because it is re-derived on every recall: the libraries (each candidate is
/// walked and its ELF header read again) and the granted links (each is read and walked again).
fn remember_scan(record: &Path, scan: &ScanRecord<'_>, cutoff: i64) {
    let mut watched: BTreeSet<&Path> = scan.dirs.iter().map(PathBuf::as_path).collect();
    watched.extend(scan.touched.iter().map(PathBuf::as_path));

    let mut out: Vec<u8> = Vec::new();
    push_field(&mut out, SCAN_RECORD_MAGIC);
    push_field(&mut out, scan.root.as_os_str().as_bytes());
    push_field(&mut out, scan.version.as_bytes());
    push_field(&mut out, class_tag(scan.want));
    push_field(&mut out, b"L");
    push_number(&mut out, scan.dirs.len());
    for dir in scan.dirs {
        push_field(&mut out, dir.as_os_str().as_bytes());
    }
    push_field(&mut out, b"D");
    push_number(&mut out, watched.len());
    for dir in &watched {
        // A DIRECTORY THAT IS NOT THERE IS RECORDED AS ABSENT, and a recall needs it still absent.
        // That is the whole of what the scan depended on: a missing directory has no entries, and
        // the answer changes only when it appears, however it appears (created, or reached through
        // a link that stopped dangling). Giving up instead left the record unwritten on any host
        // without one of the loader's default directories.
        let Ok(meta) = std::fs::metadata(dir) else {
            push_field(&mut out, b"-");
            push_field(&mut out, dir.as_os_str().as_bytes());
            continue;
        };
        if meta.mtime() >= cutoff || meta.ctime() >= cutoff {
            return;
        }
        push_field(&mut out, b"+");
        push_field(&mut out, dir.as_os_str().as_bytes());
        for n in dir_stamp(&meta) {
            push_number(&mut out, n);
        }
    }
    push_field(&mut out, b"C");
    push_number(&mut out, scan.candidates.len());
    for candidate in scan.candidates {
        push_field(&mut out, candidate.as_os_str().as_bytes());
    }
    push_field(&mut out, b"G");
    push_number(&mut out, scan.libraries.len());
    for library in scan.libraries {
        push_field(&mut out, library.path.as_os_str().as_bytes());
        push_number(&mut out, library.dev);
        push_number(&mut out, library.ino);
    }
    push_field(&mut out, b"S");
    push_number(&mut out, scan.symlinks.len());
    for symlink in scan.symlinks {
        push_field(&mut out, symlink.link.as_os_str().as_bytes());
        push_field(&mut out, symlink.target.as_os_str().as_bytes());
        push_field(&mut out, symlink.resolved.as_os_str().as_bytes());
    }
    push_field(&mut out, b"E");
    // A record that cannot be written is a scan next time, which is what there was before.
    let _ = crate::config::write_atomic_bytes(record, &out);
}

/// The NUL-separated fields of a scan record, read in order.
struct RecordFields<'a> {
    fields: std::slice::Split<'a, u8, fn(&u8) -> bool>,
}

impl<'a> RecordFields<'a> {
    fn new(data: &'a [u8]) -> Self {
        let is_nul: fn(&u8) -> bool = |b| *b == 0;
        RecordFields {
            fields: data.split(is_nul),
        }
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        self.fields.next()
    }

    fn tag(&mut self, tag: &[u8]) -> Option<()> {
        (self.bytes()? == tag).then_some(())
    }

    fn path(&mut self) -> Option<PathBuf> {
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(self.bytes()?)))
    }

    fn number<T: std::str::FromStr>(&mut self) -> Option<T> {
        std::str::from_utf8(self.bytes()?).ok()?.parse().ok()
    }
}

/// The answer of a recorded scan, when every directory it depended on is as it was and every part
/// of it re-derives to the same thing; `None` otherwise, which is a scan.
///
/// BELIEVED ONLY AS FAR AS IT IS CHECKED, as the WSL store's record is ([`crate::gpu`]). The record
/// lives in kern's runtime directory, which no box can mount, and still nothing in it is taken on
/// its word: a candidate must sit in a linker directory and carry the version suffix, the libraries
/// are re-derived from the candidates (walk, regular file, ELF class, identity) and must equal the
/// recorded ones, and each granted link is read and walked again to the same library. A forged
/// record can therefore only OMIT something, never add a file the scan would not have chosen. What
/// the directory stamps add is the one thing re-derivation cannot: that no link was added.
fn recall_scan(
    record: &Path,
    root: &Path,
    version: &str,
    want: ElfClass,
    dirs: &[PathBuf],
) -> Option<(Vec<Library>, Vec<Symlink>)> {
    let data = std::fs::read(record).ok()?;
    let mut f = RecordFields::new(&data);
    f.tag(SCAN_RECORD_MAGIC)?;
    f.tag(root.as_os_str().as_bytes())?;
    f.tag(version.as_bytes())?;
    f.tag(class_tag(want))?;

    f.tag(b"L")?;
    let count: usize = f.number()?;
    if count != dirs.len() {
        return None;
    }
    for dir in dirs {
        if f.path()? != *dir {
            return None;
        }
    }

    f.tag(b"D")?;
    let count: usize = f.number()?;
    for _ in 0..count {
        let present = match f.bytes()? {
            b"+" => true,
            b"-" => false,
            _ => return None,
        };
        let dir = f.path()?;
        let now = std::fs::metadata(&dir);
        if !present {
            if now.is_ok() {
                return None;
            }
            continue;
        }
        let mut stamp = [0i64; 6];
        for n in &mut stamp {
            *n = f.number()?;
        }
        if dir_stamp(&now.ok()?) != stamp {
            return None;
        }
    }

    let suffix = format!(".so.{version}");
    let in_dirs = |p: &Path| {
        p.parent()
            .is_some_and(|parent| dirs.iter().any(|d| d.as_path() == parent))
    };
    f.tag(b"C")?;
    let count: usize = f.number()?;
    let mut candidates: Vec<PathBuf> = Vec::new();
    for _ in 0..count {
        let candidate = f.path()?;
        let named = candidate
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(&suffix));
        if !named || !in_dirs(&candidate) {
            return None;
        }
        candidates.push(candidate);
    }
    let libraries = libraries_from(root, want, &candidates);

    f.tag(b"G")?;
    let count: usize = f.number()?;
    if count != libraries.len() {
        return None;
    }
    for library in &libraries {
        let path = f.path()?;
        let dev: u64 = f.number()?;
        let ino: u64 = f.number()?;
        if path != library.path || dev != library.dev || ino != library.ino {
            return None;
        }
    }

    let identities: BTreeSet<(u64, u64)> = libraries.iter().map(|l| (l.dev, l.ino)).collect();
    let mut seen: BTreeSet<(u64, u64)> = BTreeSet::new();
    f.tag(b"S")?;
    let count: usize = f.number()?;
    let mut symlinks: Vec<Symlink> = Vec::new();
    for _ in 0..count {
        let link = f.path()?;
        let target = f.path()?;
        let resolved = f.path()?;
        if !in_dirs(&link) || std::fs::read_link(&link).ok()? != target {
            return None;
        }
        let mut walked = link_hop_under(root, &link, &target)?;
        let LinkWalk::Reached(meta) =
            walk_links_under(root, &mut walked, MAX_LINK_HOPS.saturating_sub(1))
        else {
            return None;
        };
        if walked != resolved || !identities.contains(&(meta.dev(), meta.ino())) {
            return None;
        }
        let link_meta = std::fs::symlink_metadata(&link).ok()?;
        if !seen.insert((link_meta.dev(), link_meta.ino())) {
            return None;
        }
        symlinks.push(Symlink {
            link,
            target,
            resolved,
        });
    }
    f.tag(b"E")?;
    // The last NUL ends the record; anything after it is not a record this wrote.
    if !f.bytes()?.is_empty() || f.bytes().is_some() {
        return None;
    }
    symlinks.sort_by(|a, b| a.link.cmp(&b.link));
    Some((libraries, symlinks))
}

/// Read the POSIX access ACL of `path` and reduce it to the fields [`NodeFacts`] carries.
///
/// A node with no ACL answers with empty lists and no mask, which is the common case and the one
/// that must not cost anything: `getxattr` returns `ENODATA` and the function is done.
fn acl_facts(path: &Path) -> Option<Acl> {
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return None;
    };
    let name = c"system.posix_acl_access";

    let needed = unsafe { libc::getxattr(c_path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if needed <= 0 {
        // No xattr, or a filesystem that does not carry one. Either way the node has no ACL and
        // `st_mode` is the whole truth about it.
        return None;
    }
    // `needed` is the kernel's own answer to the size query and is positive here, so the cast is
    // exact on every target this builds for; it is bounded by the attribute size limit (64 KiB).
    let Ok(size) = usize::try_from(needed) else {
        return None;
    };
    let mut buffer = vec![0u8; size];
    let got = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            name.as_ptr(),
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
        )
    };
    if got <= 0 {
        return None;
    }
    let Ok(got) = usize::try_from(got) else {
        return None;
    };
    // The ACL can have CHANGED between the two calls and come back longer than the buffer; the
    // kernel would have returned ERANGE, but clamping keeps the slice in bounds without relying on
    // that, which is the difference between a bound and a belief.
    let got = got.min(buffer.len());
    parse_acl_xattr(buffer.get(..got)?)
}

/// Parse `system.posix_acl_access` into (acl users, acl groups, mask denies read).
///
/// Separated from the syscall so the whole format is testable from a byte slice, including the
/// shapes a filesystem should never produce: a wrong version, a truncated entry, a trailing
/// fragment. Each of those returns what it can rather than failing the whole grant, because an ACL
/// that cannot be read is an ACL that grants nothing, which is the fail-closed answer.
fn parse_acl_xattr(bytes: &[u8]) -> Option<Acl> {
    let version_bytes = bytes.get(..4)?;
    let version_array = <[u8; 4]>::try_from(version_bytes).ok()?;
    if u32::from_le_bytes(version_array) != ACL_XATTR_VERSION {
        return None;
    }

    // A conforming ACL always carries all three class entries. They are seeded to deny rather than
    // to allow so a truncated or malformed blob yields a node nobody reaches, which is the
    // fail-closed direction: a grant refused with a reason beats a grant mounted and dying at
    // `cuInit`. `mask` stays `None` until an `ACL_MASK` entry appears, because a minimal ACL has
    // none and there it must bound nothing.
    let mut acl = Acl {
        user_obj: 0,
        users: Vec::new(),
        group_obj: 0,
        groups: Vec::new(),
        mask: None,
        other: 0,
    };
    let mut saw_entry = false;

    let mut offset = 4usize;
    while offset + 8 <= bytes.len() {
        let tag_bytes = bytes.get(offset..offset + 2)?;
        let perm_bytes = bytes.get(offset + 2..offset + 4)?;
        let id_bytes = bytes.get(offset + 4..offset + 8)?;
        let (Ok(tag_array), Ok(perm_array), Ok(id_array)) = (
            <[u8; 2]>::try_from(tag_bytes),
            <[u8; 2]>::try_from(perm_bytes),
            <[u8; 4]>::try_from(id_bytes),
        ) else {
            break;
        };
        let tag = u16::from_le_bytes(tag_array);
        // The permission word is 16 bits on the wire and only the low triad is defined. Masking
        // rather than truncating: a filesystem that set a reserved high bit must not turn into a
        // permission this code then grants.
        let perm = (u16::from_le_bytes(perm_array) & u16::from(ACL_PERM_ALL)) as u8;
        let id = u32::from_le_bytes(id_array);
        saw_entry = true;

        match tag {
            ACL_USER_OBJ => acl.user_obj = perm,
            ACL_USER => acl.users.push((id, perm)),
            ACL_GROUP_OBJ => acl.group_obj = perm,
            ACL_GROUP => acl.groups.push((id, perm)),
            ACL_MASK => acl.mask = Some(perm),
            ACL_OTHER => acl.other = perm,
            // An unknown tag is skipped rather than refused: the entry length is fixed, so the
            // walk stays in step, and a kernel that grows a seventh tag must not disable the six.
            _ => {}
        }
        offset += 8;
    }

    if !saw_entry {
        // A version word and nothing after it is not an ACL. Reporting `None` sends the decision
        // back to `st_mode`, which is what a node with no ACL has, rather than to an all-deny
        // structure that would refuse every grant on such a node.
        return None;
    }

    // DUPLICATE IDS ARE REDUCED BY INTERSECTION, not by first or last wins. A conforming ACL cannot
    // carry the same id twice, so this path is only reachable on a malformed blob, and intersecting
    // is the only reduction that cannot GRANT something no single entry granted.
    merge_acl_ids(&mut acl.users);
    merge_acl_ids(&mut acl.groups);
    Some(acl)
}

/// Collapse repeated ids in an ACL entry list, keeping only the bits every copy agreed on.
fn merge_acl_ids(entries: &mut Vec<(u32, u8)>) {
    entries.sort_unstable_by_key(|(id, _)| *id);
    let mut merged: Vec<(u32, u8)> = Vec::with_capacity(entries.len());
    for (id, perm) in entries.drain(..) {
        match merged.last_mut() {
            Some((last_id, last_perm)) if *last_id == id => *last_perm &= perm,
            _ => merged.push((id, perm)),
        }
    }
    *entries = merged;
}

/// The gid through which the caller ALONE reaches a character device, or `None` when the node opens
/// for the caller's uid (owner, ACL, other) or is not a node. `kern box --device <host path>` asks
/// it, to keep the groups a box would otherwise clear, as a `--gpus` grant does.
pub(crate) fn node_needs_a_group(path: &Path) -> Option<u32> {
    let facts = node_facts(path)?;
    (access_path(&facts, &Caller::current()) == AccessPath::GroupOnly).then_some(facts.gid)
}

/// The facts about one node, read from the filesystem.
fn node_facts(path: &Path) -> Option<NodeFacts> {
    let meta = std::fs::metadata(path).ok()?;
    // A GRANT MOUNTS CHARACTER DEVICES AND NOTHING ELSE, and this did not check. `metadata`
    // FOLLOWS a symlink, so a path named like a node and pointing at a regular file was described
    // as that file, given an access verdict from its mode, and handed to the mount plan. The
    // candidate paths come from fixed names and from a directory read, so neither is third-party
    // input today, which is why this is the layer rather than the hole; it is also the ONE place
    // the question is asked, so a future caller that builds a path differently cannot skip it.
    //
    // `metadata` and not `symlink_metadata`: a host whose `/dev/nvidia0` is a symlink to the real
    // node is a host kern should still work on, and following to a real character device is right.
    // What is refused is following to something that is not one.
    use std::os::unix::fs::FileTypeExt;
    if !meta.file_type().is_char_device() {
        return None;
    }
    Some(NodeFacts {
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode() & 0o777,
        acl: acl_facts(path),
    })
}

/// The nodes in this selection that only a particular UID reaches, and therefore the nodes a box
/// running as somebody else loses.
///
/// [`AccessPath::survives_a_box`] answers whether a path survives the loss of the caller's GROUPS,
/// which is what a default box drops. It cannot answer whether the path survives the loss of the
/// caller's UID, and `--user <non-root>` or an image `USER` is exactly that: the workload runs as
/// an in-box uid that maps to a SUBORDINATE uid on the host, so `Owner` and `AclUser` stop applying
/// while `Other` still does. A grant whose nodes are reached only by uid would be reported fine and
/// die at `cuInit`, which is the same failure the rest of this policy exists to prevent.
///
/// ANSWERED BY ASKING THE POLICY AGAIN with a caller that holds nothing: a uid no account can name
/// and no group at all. Whatever that probe still reaches is reached through the `other` class, so
/// whatever it does NOT reach is uid-dependent. One spelling, and the probe cannot drift from the
/// rule because it IS the rule.
///
/// NOT A REFUSAL, and that is deliberate. `--gpus --user nobody` works on any host whose nodes are
/// world-accessible, which is this host and which pentest case C1 measures, so refusing it would
/// break the common shape in order to describe a rare one. The caller warns and still binds, the
/// way the vgpio path does. Nodes the CALLER cannot reach either are not listed: `mount_plan`
/// already refuses those, and repeating them here would blame the box identity for a host problem.
pub fn uid_dependent_nodes(
    grant: &GpuGrant,
    selection: &GpuSelection,
    who: &Caller,
    box_uid: u32,
    keeps_groups: bool,
) -> Vec<PathBuf> {
    // THE UID THE BOX WILL ACTUALLY CARRY, not a uid chosen to be unreachable. The first version of
    // this probed with `u32::MAX - 1`, a uid no account can name, and that models the wrong thing:
    // on the ranged map a box started `--user N` runs as `subuid_base + N - 1`, which IS an account
    // an operator can write an ACL for. A node carrying `user:<that subuid>:rw` beside
    // `user:<caller>:rw` would have been reported as lost while the box reaches it perfectly well,
    // so the warning would fire on a box that works. Probing INSIDE the range the box draws from is
    // the only thing that answers the question that was asked.
    //
    // No groups, because a box on the ranged map carries none: the clear in
    // `drop_caps_around_identity` succeeds there, which is measured in this module's axiom 1. EXCEPT
    // a box that keeps them (`keeps_groups`, a grant whose nodes open only through a group), whose
    // workload carries the caller's groups whatever its uid: on a Jetson the warning named all 16
    // nodes of a `--user 1000` box that `video` opens.
    let holds_nothing = Caller {
        uid: box_uid,
        gids: if keeps_groups {
            who.gids.clone()
        } else {
            Vec::new()
        },
    };
    let Ok(cards) = cards_of(grant, selection) else {
        // An unresolvable selection is `mount_plan`'s error to report, with its own message. There
        // is nothing to warn about yet.
        return Vec::new();
    };

    let mut out: Vec<PathBuf> = Vec::new();
    for (path, facts) in grant
        .shared
        .iter()
        .chain(cards.iter().flat_map(|card| card.nodes.iter()))
    {
        if access_path(facts, who) == AccessPath::Unreachable {
            continue;
        }
        if access_path(facts, &holds_nothing) == AccessPath::Unreachable {
            out.push(path.clone());
        }
    }
    out.sort();
    out.dedup();
    out
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
                // THE SAME FUNCTION THE VERDICT USED. This arm used to re-derive the question with
                // `group_reads()` and a membership test, which asked about READ while the verdict
                // asked about `O_RDWR`, so the gids printed beside a refusal could include one
                // whose entry does not actually unlock the node. `group_class_matches` returns
                // exactly the gids whose own entry carries every bit of `WANT_RW`.
                let (_, satisfying) = group_class_matches(facts, who, WANT_RW);
                needed_gids.extend(satisfying);
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
    resolve_recorded(Path::new("/"), ElfClass::native(), ScanRecordAt::RuntimeDir)
}

/// [`resolve`] with the root and the target class as parameters, so a test can build a tree.
///
/// Nothing below reads a path the caller did not derive from `root`, which is the property that
/// makes the whole module testable without hardware and the one a sabotage test removes first.
pub fn resolve_under(root: &Path, want: ElfClass) -> Result<GpuGrant, ResolveError> {
    resolve_recorded(root, want, ScanRecordAt::Nowhere)
}

/// Where a resolve keeps the record of its library scan ([`libraries_and_links`]).
#[derive(Clone, Copy)]
enum ScanRecordAt {
    /// Not recorded: a synthetic root, whose scan describes no host.
    Nowhere,
    /// `<runtime>/kern/gpu/scan`, beside the WSL store's record, for the real root.
    RuntimeDir,
}

impl ScanRecordAt {
    /// The path, resolved only when a scan is actually reached: a host whose grant comes from the
    /// WSL store or a Jetson's list never asks, so it never creates the directory.
    ///
    /// NONE IN THIS CRATE'S UNIT TESTS. The runtime directory is the process-wide
    /// `XDG_RUNTIME_DIR`, which a test may only read under the environment lock, and a test that
    /// calls [`resolve`] to compare it with another surface is not about the record. The record has
    /// its own test, with explicit paths:
    /// `a_recorded_library_scan_is_recalled_only_while_its_directories_are_unchanged`.
    fn path(self) -> Option<PathBuf> {
        match self {
            ScanRecordAt::Nowhere => None,
            ScanRecordAt::RuntimeDir if cfg!(test) => None,
            ScanRecordAt::RuntimeDir => crate::registry::runtime_subdir_public("gpu")
                .ok()
                .map(|d| d.join("scan")),
        }
    }
}

/// [`resolve_under`], with the library scan recorded where `record` says and recalled from it.
fn resolve_recorded(
    root: &Path,
    want: ElfClass,
    record: ScanRecordAt,
) -> Result<GpuGrant, ResolveError> {
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

    let csv = tegra_csv_under(root);
    let mut shared = facts_of(&shared_paths);
    // A Jetson's own nodes, as NVIDIA's list names them, beside the ones every NVIDIA host has.
    let mut listed_nodes: BTreeSet<PathBuf> = BTreeSet::new();
    if let Some(c) = &csv {
        let known: BTreeSet<PathBuf> = shared.iter().map(|(p, _)| p.clone()).collect();
        let listed: Vec<PathBuf> = c
            .devs
            .iter()
            .filter(|p| !known.contains(*p))
            .cloned()
            .collect();
        let found = facts_of(&listed);
        listed_nodes = found.iter().map(|(p, _)| p.clone()).collect();
        shared.extend(found);
    }
    let cards: Vec<CardNodes> = card_paths
        .into_iter()
        .map(|(index, pci_address, paths)| CardNodes {
            index,
            pci_address,
            nodes: facts_of(&paths),
        })
        .collect();

    let (libraries, symlinks) = match &csv {
        Some(c) => (csv_libraries(root, c, want), csv_symlinks(root, c)),
        None => libraries_and_links(root, &driver_version, want, record.path().as_deref()),
    };

    // The loader's directories are DERIVED from where the libraries are, not copied from the host's
    // configuration: a directory with no library in it would tell the box to search a path that has
    // nothing in it, and a library in a directory the list omits would not be found.
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    // ONLY A DIRECTORY HOLDING A SHARED OBJECT: a Jetson's list names a few executables as `lib`
    // (`/usr/sbin/nvidia-smi`), and docker's `00-nvcr-*.conf` lists no `/usr/bin` either.
    for library in &libraries {
        let shared_object = library
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.contains(".so"));
        if let (true, Some(parent)) = (shared_object, library.path.parent()) {
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
        tools: driver_tools_under(root),
        configs: driver_configs_under(root),
        dirs: csv
            .as_ref()
            .map(|c| c.dirs.iter().filter(|d| d.is_dir()).cloned().collect())
            .unwrap_or_default(),
        at_host_paths: csv.is_some(),
        sysfs: if csv.is_some() {
            TEGRA_SYSFS
                .iter()
                .map(|rel| root.join(rel))
                .filter(|p| p.exists())
                .collect()
        } else {
            Vec::new()
        },
        listed_nodes,
    })
}

/// Why `--gpus` could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GpuSpecError {
    /// The value was empty.
    Empty,
    /// `all` was written beside something else, as in `0,all`. The two mean different things and
    /// only one of them can be true, so this is refused rather than resolved one way: whichever
    /// way it went, half of what the caller wrote would be silently discarded.
    AllWithMore {
        /// What was passed, so the message can quote it.
        given: String,
    },
    /// An index was named twice, as in `device=0,0`. Deduplicating silently would make it the same
    /// command as naming it once, and the caller who wrote it almost certainly meant two cards.
    Duplicate {
        /// The index that repeats.
        index: u32,
    },
    /// A bare `0`, which Docker reads as "no GPUs" and a reader of this project's own examples
    /// reads as "card 0". Refused rather than resolved, because the two are both plausible and
    /// the cost of guessing wrong is a workload that fails at its first CUDA call.
    ZeroIsAmbiguous,
    /// A count of more cards than a request can mean, or a count that is not a number.
    NotACount {
        /// What was passed, so the message can quote it.
        given: String,
    },
    /// The value is not a card index.
    NotAnIndex {
        /// What was passed, so the message can quote it.
        given: String,
    },
    /// A `GPU-…` or `MIG-…` token that no card on this host carries.
    ///
    /// SEPARATE FROM `NotAnIndex`, because the two send a reader to different places: a typo in an
    /// index is a typo, and a UUID that does not resolve is either the wrong machine or a card that
    /// moved. The variant carries what the driver DOES publish so the message can show it.
    UnknownUuid {
        /// What was written.
        given: String,
        /// Every `GPU UUID` the driver lists, which is empty on a host with no driver.
        known: Vec<String>,
    },
}

impl GpuSpecError {
    /// Why a spec is not a GPU request, in words, for the place that quotes the spec: a compose
    /// file's `gpus:`, a `NVIDIA_VISIBLE_DEVICES` value. One text, so the two cannot drift, and never
    /// the enum's debug form (MEASURED before, Grok's round 7, case 28: `--runtime nvidia` printed
    /// `UnknownUuid { given: "GPU-...", known: [...] }`).
    pub(crate) fn reason(&self) -> String {
        use GpuSpecError as G;
        match self {
            G::Empty => "it is empty".to_string(),
            G::ZeroIsAmbiguous => {
                "a bare 0 has two readings, docker's \"no gpus\" and this project's \
             \"card 0\"; write device=0 for the card"
                    .to_string()
            }
            G::AllWithMore { .. } => {
                "`all` names every card and cannot stand beside another".to_string()
            }
            G::Duplicate { index } => {
                format!("card {index} is named twice and each is granted once")
            }
            G::NotACount { .. } => {
                "a bare value is HOW MANY cards, as in docker (gpus: 2); device=0 names which"
                    .to_string()
            }
            G::NotAnIndex { .. } => {
                "the value after device= is a card index, or a list of them".to_string()
            }
            // THE FILE'S OWN SHAPE: `device_ids` takes indices or UUIDs, so a compose author who wrote
            // a UUID wrote something Docker documents, and the reason has to be that THIS HOST does
            // not have it, with what it does have.
            G::UnknownUuid { given, known } => {
                if known.is_empty() {
                    format!(
                        "{given} is a GPU UUID and this host's driver publishes none, so there is \
                     nothing to match it against"
                    )
                } else {
                    format!(
                        "{given} is a GPU UUID that no card here carries. This host has: {}",
                        known.join(", ")
                    )
                }
            }
        }
    }
}

/// Which cards `--gpus` asked for.
///
/// `all` AND A COUNT STAY UNRESOLVED HERE, and that is the whole reason this type exists rather
/// than a `Vec<u32>`. The parser has no host in front of it: it cannot know which cards exist, nor
/// how many, and turning either into indices at parse time would mean reading the filesystem from
/// a pure function or assuming the indices run from zero without gaps. The driver is allowed to
/// leave a gap, and [`card_node_paths`] reads the set from the directory for exactly that reason.
/// The expansion happens in [`mount_plan`], where the grant is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GpuSelection {
    /// Every card the driver lists on this host, however many that turns out to be.
    All,
    /// ANY `n` cards, which is what Docker's `--gpus 2` and `--gpus count=2` ask for. Resolved to
    /// the `n` lowest indices the host actually has, so a host whose cards are 0 and 2 answers
    /// with both rather than refusing for a card 1 that was never named.
    Count(u32),
    /// The indices the caller named, in the order they wrote them, with no repeats.
    These(Vec<u32>),
}

/// Read `--gpus`, with Docker's grammar, because the flag carries Docker's name.
///
/// 🚨 A BARE NUMBER IS A COUNT, NOT AN INDEX, and this is a correction rather than a choice.
/// MEASURED against docker 29.1.3 on this host: `--gpus 2` hands over `/dev/nvidia0` AND
/// `/dev/nvidia1`, `--gpus 1` hands over `/dev/nvidia0`, and `--gpus 0` hands over NOTHING while
/// the container still runs. This flag shipped reading the bare number as an index, so
/// `--gpus 2` gave card 2 where Docker gives two cards. The project's rule is that a flag taking
/// Docker's name takes Docker's meaning with it; a flag that looks identical and does something
/// else is worse than one that is missing, because nobody checks a flag they already know.
///
/// The accepted grammar, every form of it measured against docker first:
///
///   - `all`, and `count=all`, which Docker also accepts: every card.
///   - `2`, and `count=2`: any two cards.
///   - `device=1`: card 1 by index. `gpu=1` is kern's own spelling of the same thing.
///   - `device=0,1`: cards 0 and 1. Docker needs the quotes written INSIDE the value for this,
///     `--gpus "device=0,1"`, because its own value is a comma-separated list of `key=value` and
///     the comma would otherwise end the pair; measured, the unquoted form is a usage error there.
///     kern takes one argv token, so it needs no quoting, and it strips a surrounding pair anyway
///     so a command pasted from a Docker example works as written.
///
/// `0` IS REFUSED RATHER THAN RESOLVED. Docker reads it as "no GPUs"; every example this project
/// has written reads it as "card 0". Both are plausible, and a caller who meant card 0 and got a
/// box with no GPU learns it at their first CUDA call, from an error that says nothing about the
/// flag. So it is named, with both readings and the spelling for each.
pub fn parse_gpu_spec(value: &str) -> Result<GpuSelection, GpuSpecError> {
    // A pasted Docker example carries its own quotes inside the value. Stripping ONE surrounding
    // pair is enough and is not a general unquoting: a value with a quote anywhere else is not a
    // shape either runtime accepts, and it reaches the refusals below with the quote still in it,
    // which is what lets the message quote back what the caller actually typed.
    let trimmed = value.trim();
    let trimmed = trimmed
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(trimmed)
        .trim();
    if trimmed.is_empty() {
        return Err(GpuSpecError::Empty);
    }

    // `all`, alone. Written beside anything else it is a contradiction rather than an addition.
    let lower = trimmed.to_ascii_lowercase();
    if lower == "all" || lower == "count=all" {
        return Ok(GpuSelection::All);
    }
    // `-1` IS EVERY CARD, which is the Docker API's own convention (`DeviceRequest.Count = -1`) and
    // what compose writes when a file says so directly. MEASURED against docker compose v5.0.2 on
    // this host, two cards, the same reservation block:
    //
    //     count: -1   ->  the container saw 2 cards
    //     count: 1    ->  1
    //     count: 0    ->  0, and the container ran
    //
    // kern refused it with "not a number of cards", so a file docker runs died here. The grammar
    // lives in ONE place, which is why this is read here and not translated in the compose layer.
    if lower == "-1" || lower == "count=-1" {
        return Ok(GpuSelection::All);
    }
    if lower.split(',').any(|p| p.trim() == "all") {
        return Err(GpuSpecError::AllWithMore {
            given: trimmed.to_string(),
        });
    }

    // Indices: `device=<list>` or `gpu=<list>`. The list lives inside the value, so it is split
    // here and not by the caller.
    if let Some(list) = trimmed
        .strip_prefix("device=")
        .or_else(|| trimmed.strip_prefix("gpu="))
    {
        // `device=all` IS EVERY CARD, and this is a measurement rather than a reading of a guide.
        // On docker 29.1.3 on this host, with two cards:
        //
        //   docker run --gpus device=all alpine ls /dev/nvidia[0-9]*  ->  /dev/nvidia0 /dev/nvidia1
        //   docker run --gpus all        alpine ls /dev/nvidia[0-9]*  ->  /dev/nvidia0 /dev/nvidia1
        //   docker run --gpus device=0   alpine ls /dev/nvidia[0-9]*  ->  /dev/nvidia0
        //
        // kern refused it with "not a card index", and the form is in NVIDIA's and Triton's own
        // pages. Note what the same measurement showed about the FLAG parse: docker accepted
        // `--gpus device=nonsense` at the command line and only failed when it created the
        // container, so the grammar cannot be measured without running one.
        if list.trim().eq_ignore_ascii_case("all") {
            return Ok(GpuSelection::All);
        }
        // `all` BESIDE INDICES is the same contradiction `all,2` is, and gets the same refusal:
        // one of the two statements has to be the false one and kern does not pick.
        if list
            .split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("all"))
        {
            return Err(GpuSpecError::AllWithMore {
                given: trimmed.to_string(),
            });
        }
        return parse_index_list(trimmed, list).map(GpuSelection::These);
    }

    // A count, written either way.
    let digits = trimmed.strip_prefix("count=").unwrap_or(trimmed);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(GpuSpecError::NotACount {
            given: trimmed.to_string(),
        });
    }
    let n = digits.parse::<u32>().map_err(|_| GpuSpecError::NotACount {
        given: trimmed.to_string(),
    })?;
    if n == 0 {
        return Err(GpuSpecError::ZeroIsAmbiguous);
    }
    Ok(GpuSelection::Count(n))
}

/// The index list inside a `device=` or `gpu=` value.
///
/// `whole` is the value as the caller wrote it, and every refusal quotes THAT rather than the
/// fragment that failed: on its own an empty element reads as `""` and tells a caller nothing
/// about where in their command to look.
fn parse_index_list(whole: &str, list: &str) -> Result<Vec<u32>, GpuSpecError> {
    let mut out: Vec<u32> = Vec::new();
    for part in list.split(',') {
        let part = part.trim();
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(GpuSpecError::NotAnIndex {
                given: whole.to_string(),
            });
        }
        let index = part.parse::<u32>().map_err(|_| GpuSpecError::NotAnIndex {
            given: whole.to_string(),
        })?;
        if out.contains(&index) {
            return Err(GpuSpecError::Duplicate { index });
        }
        out.push(index);
    }
    if out.is_empty() {
        return Err(GpuSpecError::NotAnIndex {
            given: whole.to_string(),
        });
    }
    Ok(out)
}

/// [`parse_gpu_spec`], with any `GPU-…` token resolved to the card index the driver gives it.
///
/// WHY IT IS A SEPARATE FUNCTION. `parse_gpu_spec` has no host in front of it, which is what makes
/// its grammar testable without hardware, and a UUID can only be resolved by reading what the
/// driver publishes. So the host-reading half lives here, in one place, and every caller that has
/// a root goes through this instead of pairing the two itself.
///
/// THE SHAPE COMES FROM DOCKER'S OWN REFERENCE, which documents `device_ids` as either indices or
/// UUIDs: `device_ids: ['0', '3']` and `device_ids: ["GPU-ebc4a5d2"]`. Measured on 2026-11-12
/// before this existed: a compose file carrying the UUID form was refused with
/// `--gpus device=GPU-1950be8a-…: not a card index`, on a host where the CDI path resolved the very
/// same UUID through the very same driver files. kern had the machinery and refused the shape.
///
/// `MIG-` IS ACCEPTED INTO THE LOOKUP and will simply not be found on a host without MIG, which is
/// the honest outcome: the driver publishes no such UUID, and the message says what it does
/// publish. Inventing a MIG answer here would be a claim about a mode this binary does not support.
/// Split a `--gpus` value on commas that are NOT inside double quotes.
///
/// Docker's grammar needs this and documents why: "the device value must be quoted because it
/// contains a comma", as in `--gpus '"device=0,2"'` and `--gpus 'all,"capabilities=compute,utility"'`.
/// The shell removes the single quotes, so the value that arrives here still carries the doubles.
fn comma_tokens(value: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for ch in value.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    out.push(cur);
    out.into_iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

/// The `capabilities=` token Docker takes inside `--gpus`, and what kern does about it.
///
/// MEASURED 2026-11-12: `--gpus 'all,"capabilities=compute,utility"'`, which NVIDIA's own
/// documentation prints, was refused with "`all` and anything beside it name different things and
/// only one can be true" - a message about a contradiction that is not there, naming nothing the
/// caller wrote.
///
/// IT IS SATISFIED BY CONSTRUCTION AND SAYING SO IS THE POINT. Docker uses the list to decide which
/// driver libraries and binaries to inject; a kern grant binds the driver's library set wholesale
/// (29 libraries on the host this was measured on) and every driver tool the host has, so `compute`, `utility`, `video` and the rest
/// are all present whether or not they were asked for. kern therefore accepts the token and reports
/// that it selected nothing, because a request silently exceeded is still a request whose answer the
/// caller cannot see.
pub fn capabilities_note(spec: &str) -> Option<String> {
    let asked: Vec<String> = comma_tokens(spec)
        .into_iter()
        .filter_map(|t| {
            let lower = t.to_ascii_lowercase();
            lower
                .strip_prefix("capabilities=")
                .map(|rest| rest.to_string())
        })
        .collect();
    if asked.is_empty() {
        return None;
    }
    Some(format!(
        "--gpus capabilities={} selects nothing here, and nothing is missing: a grant binds the \
         driver's whole library set and its tools, so every capability in that list is present \
         and so are the others. Docker uses the list to choose what to inject; kern does not choose",
        asked.join(",")
    ))
}

/// THE THREE WORDS THAT MEAN "NO GPU" in the device list, which docker honours and kern refused.
///
/// MEASURED against docker 29.1.3 on a two-card host, `--gpus '"device=<x>"'` with alpine listing
/// `/dev/nvidia[0-9]*`:
///
/// ```text
/// device=none      ->  0 cards, and the container RAN
/// device=void      ->  0 cards, and the container RAN
/// device=nonsense  ->  docker refuses the flag
/// device=99        ->  docker refuses the flag
/// ```
///
/// So they are sentinels, not garbage docker happens to swallow: they carry the
/// `NVIDIA_VISIBLE_DEVICES=none|void` meaning into the flag. kern answered "not a card index",
/// which is the same inconsistency the compose layer had with `count: 0` until today: a request
/// for ZERO cards is a request, and refusing it kills a command that runs everywhere else.
const NO_GPU_WORDS: [&str; 2] = ["none", "void"];

/// Does this spec ask for NO card? One reader for the words, used by the surfaces that announce it.
pub fn asks_for_no_gpu(spec: &str) -> bool {
    let t = spec.trim().trim_matches('"').trim().to_ascii_lowercase();
    let body = t
        .strip_prefix("device=")
        .or_else(|| t.strip_prefix("gpu="))
        .unwrap_or("");
    NO_GPU_WORDS.contains(&body)
}

/// The one line for a spec that asks for no card, so both surfaces say it the same way.
pub fn describe_no_gpu(spec: &str) -> String {
    format!(
        "--gpus {spec} asks for NO card, which is what it means in docker too \
         (NVIDIA_VISIBLE_DEVICES=none|void), so this box gets none and nothing was refused"
    )
}

/// [`selection_from_spec`], where `Ok(None)` means the caller asked for NO card.
///
/// The outer `Option` is how the callers already spell "no `--gpus` given", so a spec that asks for
/// nothing lands on the same path as not passing the flag: the box gets no grant and nothing in the
/// GPU plumbing has to learn a fourth selection.
pub fn selection_from_spec(root: &Path, spec: &str) -> Result<Option<GpuSelection>, GpuSpecError> {
    // THE SENTINELS FIRST, before the grammar, because `device=none` is not an index list and the
    // grammar is right to say so.
    if asks_for_no_gpu(spec) {
        return Ok(None);
    }
    selection_from_spec_inner(root, spec).map(Some)
}

fn selection_from_spec_inner(root: &Path, spec: &str) -> Result<GpuSelection, GpuSpecError> {
    // THE CAPABILITIES TOKEN IS DROPPED BEFORE THE GRAMMAR SEES IT, and here rather than in
    // `parse_gpu_spec` on purpose: that function is the grammar, it is tested without a host, and
    // this is Docker-compatibility sugar for a request kern answers by construction. The caller
    // prints `capabilities_note` beside the result.
    let tokens = comma_tokens(spec);
    let had_caps = tokens
        .iter()
        .any(|t| t.to_ascii_lowercase().starts_with("capabilities="));
    let without_caps: String = tokens
        .into_iter()
        .filter(|t| !t.to_ascii_lowercase().starts_with("capabilities="))
        .collect::<Vec<_>>()
        .join(",");
    // ONLY WHEN THERE WAS ONE, so every other spec reaches the grammar byte for byte as it was
    // typed and the quoting the grammar already handles is not second-guessed here.
    let spec: &str = if had_caps && !without_caps.is_empty() {
        &without_caps
    } else {
        spec
    };
    let trimmed = spec.trim();
    let lower = trimmed.to_ascii_lowercase();
    let body = lower
        .strip_prefix("device=")
        .or_else(|| lower.strip_prefix("gpu="))
        .is_some();
    // ONLY INSIDE AN INDEX LIST. A bare `GPU-…` with no `device=` in front of it is not a shape
    // either runtime accepts, and rewriting it would invent a spelling for the user.
    let names_a_uuid = |t: &str| {
        let u = t
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_ascii_uppercase();
        u.starts_with("GPU-") || u.starts_with("MIG-") || bare_uuid(&u)
    };
    let list_has_uuid = trimmed
        .split_once('=')
        .is_some_and(|(_, l)| l.split(',').any(names_a_uuid));
    if !body || !list_has_uuid {
        return parse_gpu_spec(spec);
    }
    let (prefix, list) = trimmed.split_once('=').unwrap_or(("device", trimmed));
    // ON WSL2 THE DRIVER PUBLISHES NO `/proc/driver/nvidia`, so the table is the adapter list the
    // vendor's tool prints. MEASURED: docker resolves `device=GPU-…` there, and kern answered
    // "this host's driver publishes no GPU UUID at all" for the very UUID `nvidia-smi -L` showed.
    let mut table = crate::cdi::uuid_minors(root);
    if table.is_empty() {
        table = crate::gpu::wsl_adapters(root)
            .unwrap_or_default()
            .into_iter()
            .map(|(index, uuid)| (uuid, index))
            .collect();
    }
    // ON A JETSON THE DRIVER PUBLISHES NO `gpus` DIRECTORY EITHER, and the UUID `nvidia-smi` prints
    // has no `GPU-` prefix. MEASURED on a Jetson Orin Nano: `--gpus device=ed5c5ba5-abef-…`, the UUID
    // `nvidia-smi -L` showed, was answered "not a card index".
    if table.is_empty() {
        table = tegra_adapters(root)
            .into_iter()
            .map(|(index, uuid)| (uuid, index))
            .collect();
    }
    let mut rewritten: Vec<String> = Vec::new();
    for part in list.split(',') {
        let token = part.trim().trim_matches('"').trim_matches('\'');
        let upper = token.to_ascii_uppercase();
        if !upper.starts_with("GPU-") && !upper.starts_with("MIG-") && !bare_uuid(&upper) {
            rewritten.push(token.to_string());
            continue;
        }
        // CASE-INSENSITIVE on the UUID, because `nvidia-smi` prints it lower case and a file may
        // carry either. The driver's own string is the one compared against.
        match table
            .iter()
            .find(|(u, _)| u.eq_ignore_ascii_case(token))
            .map(|(_, m)| *m)
        {
            Some(minor) => rewritten.push(minor.to_string()),
            None => {
                return Err(GpuSpecError::UnknownUuid {
                    given: token.to_string(),
                    known: table.into_iter().map(|(u, _)| u).collect(),
                });
            }
        }
    }
    parse_gpu_spec(&format!("{prefix}={}", rewritten.join(",")))
}

/// Whether `s` is a UUID written without a prefix, `8-4-4-4-12` hex digits: how a Jetson's
/// `nvidia-smi` prints its GPU's.
fn bare_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(p, n)| p.len() == n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A Jetson's GPUs as `(index, UUID)`, from the vendor's own `nvidia-smi` under `root`, bounded in
/// time like the WSL2 list. Empty anywhere that is not a Jetson or that has no tool.
fn tegra_adapters(root: &Path) -> Vec<(u32, String)> {
    if !root.join(TEGRA_RELEASE_REL).exists() {
        return Vec::new();
    }
    ["usr/bin/nvidia-smi", "usr/sbin/nvidia-smi"]
        .iter()
        .map(|rel| root.join(rel))
        .find(|p| p.is_file())
        .and_then(|smi| {
            crate::gpu::run_bounded(&smi, &["--query-gpu=index,uuid", "--format=csv,noheader"])
        })
        .map(|text| {
            text.lines()
                .filter_map(|line| {
                    let (index, uuid) = line.split_once(',')?;
                    let (index, uuid) = (index.trim().parse::<u32>().ok()?, uuid.trim());
                    let upper = uuid.to_ascii_uppercase();
                    (upper.starts_with("GPU-") || bare_uuid(&upper))
                        .then(|| (index, uuid.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The `NVIDIA_VISIBLE_DEVICES` a box is given for a `--gpus` spec: the value docker gives it.
///
/// MEASURED against docker 29.1.3 with toolkit 1.20.2, two cards, `env` in the container:
///
/// ```text
/// --gpus all                ->  all
/// --gpus device=0           ->  0
/// --gpus '"device=0,1"'     ->  0,1
/// --gpus 2                  ->  0,1
/// --gpus 1                  ->  0
/// --gpus device=GPU-1950…   ->  GPU-1950…   (as written)
/// -e NVIDIA_VISIBLE_DEVICES=xyz --gpus device=1  ->  1   (the grant's value replaces the caller's)
/// ```
///
/// Images and entrypoints read it (the CUDA images' scripts, the device plugins, a `test -n` in a
/// start script), so a box granted a card with the variable unset looked to them like a box with none.
///
/// A COUNT IS THE CARDS GRANTED when they are known, which is docker's `0..n` on any host whose
/// cards have no gap; on one that has (cards 0 and 2) docker would name a card 1 the box does not
/// hold, and this names the two it does. `granted` is `None` where nothing lists them.
pub fn visible_devices(spec: &str, selection: &GpuSelection, granted: Option<&[u32]>) -> String {
    let csv = |v: &[u32]| v.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
    match selection {
        // A DEVICE LIST THAT RESOLVED TO EVERY CARD is still written back as it was given: on a WSL2
        // guest that cannot read UUIDs, `device=GPU-…` grants every adapter and docker would write
        // the UUID. `device=all` writes `all` either way.
        GpuSelection::All => written_device_list(spec).unwrap_or_else(|| "all".to_string()),
        GpuSelection::Count(n) => match granted {
            Some(g) => csv(g),
            None => csv(&(0..*n).collect::<Vec<u32>>()),
        },
        // AS WRITTEN, so a UUID stays a UUID: docker hands the spec's list through untouched.
        GpuSelection::These(indices) => written_device_list(spec).unwrap_or_else(|| csv(indices)),
    }
}

/// The list after `device=` (or `gpu=`), quotes and a `capabilities=` token removed, as written.
fn written_device_list(spec: &str) -> Option<String> {
    let joined = comma_tokens(spec)
        .into_iter()
        .filter(|t| !t.to_ascii_lowercase().starts_with("capabilities="))
        .collect::<Vec<_>>()
        .join(",");
    let body = joined
        .strip_prefix("device=")
        .or_else(|| joined.strip_prefix("gpu="))?;
    let parts: Vec<&str> = body
        .split(',')
        .map(|p| p.trim().trim_matches('"').trim_matches('\''))
        .filter(|p| !p.is_empty())
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(","))
    }
}

/// The indices a selection resolves to on this grant, for [`visible_devices`].
pub fn granted_indices(grant: &GpuGrant, selection: &GpuSelection) -> Option<Vec<u32>> {
    cards_of(grant, selection)
        .ok()
        .map(|cards| cards.iter().map(|c| c.index).collect())
}

/// Why a grant cannot be turned into mounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountPlanError {
    /// The caller asked for more cards than this host has. Distinct from [`Self::NoSuchCard`]
    /// because the correction is different: there is no index to fix, there are simply not enough
    /// cards, and the message has to say how many there are rather than which ones.
    TooFewCards {
        /// How many were asked for.
        wanted: u32,
        /// The indices that do exist, so the message can count and list them.
        present: Vec<u32>,
    },
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
/// Turn a selection into the cards it names, in the order the caller wrote them.
///
/// THE ONE PLACE `all` BECOMES A LIST. The parser cannot do it, because it has no host in front of
/// it; every other caller reads the result of this function, so there is one expansion to test and
/// one to get wrong. `all` on a host the driver lists no card for is refused with the same error
/// as a named index that does not exist, because it is the same disappointment: the caller asked
/// for cards and there are none.
fn cards_of<'g>(
    grant: &'g GpuGrant,
    selection: &GpuSelection,
) -> Result<Vec<&'g CardNodes>, MountPlanError> {
    match selection {
        GpuSelection::All => {
            if grant.cards.is_empty() {
                return Err(MountPlanError::NoSuchCard {
                    wanted: 0,
                    present: Vec::new(),
                });
            }
            Ok(grant.cards.iter().collect())
        }
        // ANY `n` CARDS, resolved to the `n` LOWEST indices the host has. `grant.cards` is sorted
        // by index and read from the directory rather than counted from zero, so a host whose
        // cards are 0 and 2 answers `count=2` with both instead of refusing for a card 1 that was
        // never named and does not exist.
        GpuSelection::Count(n) => {
            let want = *n as usize;
            if grant.cards.len() < want {
                return Err(MountPlanError::TooFewCards {
                    wanted: *n,
                    present: grant.cards.iter().map(|c| c.index).collect(),
                });
            }
            Ok(grant.cards.iter().take(want).collect())
        }
        GpuSelection::These(indices) => {
            let mut out = Vec::with_capacity(indices.len());
            for &index in indices {
                let Some(card) = grant.cards.iter().find(|c| c.index == index) else {
                    return Err(MountPlanError::NoSuchCard {
                        wanted: index,
                        present: grant.cards.iter().map(|c| c.index).collect(),
                    });
                };
                out.push(card);
            }
            Ok(out)
        }
    }
}

/// The PCI addresses of the cards a grant is about to hand over, for the box's `/proc` mask.
///
/// ONE ADDRESS PER CARD THAT HAS ONE, and a card with no address contributes nothing rather than
/// a placeholder. The caller masks to exactly this list, so a card missing from it is a card whose
/// directory the box will not see; that is the honest failure, because masking on a guessed
/// address would keep the wrong card's directory and hide a granted one.
///
/// `None` means the set CANNOT BE NAMED, which is not the same as naming nothing: masking to a
/// partial list would hand the box one of the two cards it was given and hide the other, and masking
/// to an empty list would hide both. The caller turns this into the third state the mask understands.
///
/// ALL OR NOTHING, and the earlier version was not: it `filter_map`ped away every card whose address
/// did not resolve, so a two-card grant with one unreadable `information` file was masked down to the
/// other card, silently, which is exactly the "partial listing a reader would trust and should not"
/// that the mask's own doc refuses to produce.
#[must_use]
pub fn pci_addresses_of(grant: &GpuGrant, selection: &GpuSelection) -> Option<Vec<String>> {
    let cards = cards_of(grant, selection).ok()?;
    let mut out = Vec::with_capacity(cards.len());
    for card in cards {
        out.push(card.pci_address.clone()?);
    }
    Some(out)
}

/// The sysfs a granted card needs read under `root`, RELATIVE to it, for the box to place it the way
/// the host does: the card's own PCI device directory, its link under `sys/bus/pci/devices`, every
/// PCI bridge above it as its ATTRIBUTE FILES and its link, and the host's CPU and NUMA topology
/// directories. The box reproduces these read-only, links as links (`SandboxSpec::gpu_sysfs`).
///
/// NVML READS A CARD'S PCI IDENTITY FROM SYSFS: MEASURED on this host with two RTX 5060 Ti,
/// `nvidia-smi --query-gpu=pci.bus_id` answered `[Unknown Error]` in a box with no sysfs and
/// `00000000:06:00.0` under docker 29, which mounts the host's whole `/sys` read-only.
///
/// AND IT PLACES THE CARDS FROM THE TREE ABOVE THEM. With only the device directories, `nvidia-smi
/// topo -m` said `NODE` for two cards the host and Docker report as `PHB` (one host bridge). MEASURED
/// by hand in a box, one variable at a time: it took all three of the CPU/NUMA topology (without it
/// hwloc says "failed to find sysfs cpu topology directory"), the bridges, and the `bus/pci/devices`
/// entries as LINKS; any one alone left `NODE`. The bridges' attribute files were enough, so their
/// directories, which list every other device behind them, are not given.
///
/// An address that is not a plain PCI address, or whose link leaves `sys/devices`, contributes
/// nothing.
pub fn pci_sysfs_paths(root: &Path, addresses: &[String]) -> Vec<PathBuf> {
    // What hwloc and NVML read of a bridge. `config` is the bridge's config space, read for its bus
    // range; the rest are its identity, its link and where it sits.
    const BRIDGE_ATTRS: &[&str] = &[
        "class",
        "vendor",
        "device",
        "subsystem_vendor",
        "subsystem_device",
        "revision",
        "config",
        "max_link_speed",
        "max_link_width",
        "current_link_speed",
        "current_link_width",
        "numa_node",
        "local_cpulist",
        "local_cpus",
    ];
    let is_pci_addr = |a: &str| {
        !a.is_empty()
            && a.chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
    };
    let devices = root.join("sys/devices");
    let mut out: Vec<PathBuf> = Vec::new();
    let push = |p: PathBuf, out: &mut Vec<PathBuf>| {
        if !out.contains(&p) {
            out.push(p);
        }
    };
    for a in addresses {
        if !is_pci_addr(a) {
            continue;
        }
        let bus = PathBuf::from("sys/bus/pci/devices").join(a);
        let Ok(real) = std::fs::canonicalize(root.join(&bus)) else {
            continue;
        };
        let Ok(rel) = real.strip_prefix(root) else {
            continue;
        };
        if !real.starts_with(&devices) || !real.is_dir() {
            continue;
        }
        push(rel.to_path_buf(), &mut out);
        push(bus, &mut out);
        // The card's bus under `class/pci_bus`, which NCCL resolves to find the card's PCI path:
        // without it NCCL took the class from NVML (`0x03`) where Docker's box reads `0x030000`.
        // The link, and the `pci_bus/<bus>` directory it points to (affinity files and links only).
        if let Some((domain_bus, _)) = a.rsplit_once(':') {
            let class_link = PathBuf::from("sys/class/pci_bus").join(domain_bus);
            if let Ok(bus_dir) = std::fs::canonicalize(root.join(&class_link)) {
                if let Ok(bus_rel) = bus_dir.strip_prefix(root) {
                    if bus_dir.starts_with(&devices) && bus_dir.is_dir() {
                        push(bus_rel.to_path_buf(), &mut out);
                        push(class_link, &mut out);
                    }
                }
            }
        }
        // The bridges, from the card up to (not including) the host bridge `pciDDDD:BB`.
        let mut up = rel.parent();
        while let Some(dir) = up {
            let Some(name) = dir.file_name().and_then(|n| n.to_str()) else {
                break;
            };
            if !is_pci_addr(name) || !name.contains(':') {
                break;
            }
            for attr in BRIDGE_ATTRS {
                let f = dir.join(attr);
                if root.join(&f).is_file() {
                    push(f, &mut out);
                }
            }
            let link = PathBuf::from("sys/bus/pci/devices").join(name);
            if root.join(&link).exists() {
                push(link, &mut out);
            }
            up = dir.parent();
        }
    }
    if !out.is_empty() {
        for topo in ["sys/devices/system/cpu", "sys/devices/system/node"] {
            if root.join(topo).is_dir() {
                push(PathBuf::from(topo), &mut out);
            }
        }
    }
    out
}

pub fn mount_plan(
    grant: &GpuGrant,
    selection: &GpuSelection,
    who: &Caller,
) -> Result<Vec<Bind>, MountPlanError> {
    plan_binds(grant, selection, who, None, Groups::Enforce)
}

/// [`mount_plan`] with the libraries placed in the box's library directory, `lib_dir`, the way
/// docker places them (see [`box_library_dir`]), instead of at the host's own paths. The launch uses
/// [`mount_plan_keeping_groups`], having settled the group question against the box's uid map.
#[cfg(test)]
pub fn mount_plan_into(
    grant: &GpuGrant,
    selection: &GpuSelection,
    who: &Caller,
    lib_dir: &str,
) -> Result<Vec<Bind>, MountPlanError> {
    plan_binds(grant, selection, who, Some(lib_dir), Groups::Enforce)
}

/// [`mount_plan`] for a box that keeps the caller's supplementary groups (the single-uid map), so a
/// node reached only through one of them is reachable in the box too. A node nobody can open is
/// still refused. The caller decides which map the box gets; see `kern box`'s grant check.
pub fn mount_plan_keeping_groups(
    grant: &GpuGrant,
    selection: &GpuSelection,
    who: &Caller,
    lib_dir: Option<&str>,
) -> Result<Vec<Bind>, MountPlanError> {
    plan_binds(grant, selection, who, lib_dir, Groups::KeptByTheBox)
}

/// Whether a node reached only through a supplementary group refuses the plan.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Groups {
    /// The box drops supplementary groups (the ranged map): such a node refuses.
    Enforce,
    /// The box keeps them (the single-uid map): such a node is reachable.
    KeptByTheBox,
}

/// The Debian multiarch directory for this build's architecture, the one docker's toolkit uses.
#[cfg(target_arch = "aarch64")]
const MULTIARCH_LIB_DIR: &str = "/usr/lib/aarch64-linux-gnu";
#[cfg(not(target_arch = "aarch64"))]
const MULTIARCH_LIB_DIR: &str = "/usr/lib/x86_64-linux-gnu";

/// Where the driver's libraries go in a box whose root is `layers` (top first): docker's rule.
///
/// MEASURED against docker 29.1.3 + toolkit 1.20.2, `grep libcuda /proc/mounts` in the container:
///
/// ```text
/// ubuntu:24.04        /etc/debian_version yes   ->  /usr/lib/x86_64-linux-gnu  (it has /usr/lib64 too)
/// fedora:41           no                        ->  /usr/lib64
/// alpine:3.20         no                        ->  /usr/lib64                 (created)
/// python:3.12-alpine  no                        ->  /usr/lib64                 (created)
/// ```
///
/// kern mounted them at the HOST's path, which is right for a Debian-family image on a Debian-family
/// host and nothing else: in `fedora:41`, whose loader searches `/usr/lib64`, `nvidia-smi` answered
/// "couldn't find libnvidia-ml.so" under kern and listed the card under docker.
///
/// The marker is looked up layer by layer and never followed: a symlink there is an image's own
/// file, and a whiteout (a 0/0 character device) in a higher layer means the image deleted it.
pub fn box_library_dir(layers: &[String]) -> String {
    use std::os::unix::fs::FileTypeExt;
    let debian = layers
        .iter()
        .find_map(|layer| {
            match std::fs::symlink_metadata(Path::new(layer).join("etc/debian_version")) {
                Ok(m) if m.file_type().is_char_device() => Some(false),
                Ok(_) => Some(true),
                Err(_) => None,
            }
        })
        .unwrap_or(false);
    if debian {
        MULTIARCH_LIB_DIR.to_string()
    } else {
        "/usr/lib64".to_string()
    }
}

fn plan_binds(
    grant: &GpuGrant,
    selection: &GpuSelection,
    who: &Caller,
    lib_dir: Option<&str>,
    groups: Groups,
) -> Result<Vec<Bind>, MountPlanError> {
    let wanted = cards_of(grant, selection)?;

    // The selection, and the policy over EXACTLY it: the shared nodes plus the nodes of the cards
    // that were asked for, never the others'. A grant for card 0 refusing because card 1's display
    // node is group-gated would be answering a question nobody asked.
    //
    // ASKING FOR MORE CARDS CAN TURN A GRANT THAT WOULD HAVE WORKED INTO A REFUSAL, and that is
    // correct rather than unfortunate: `--gpus device=0,1` is one request, so it succeeds or
    // one. Granting the half that is reachable would hand back a box with fewer cards than the
    // command named, and nothing in the box could tell that from a card that failed later.
    let mut selected: Vec<(PathBuf, NodeFacts)> = grant.shared.clone();
    for card in &wanted {
        selected.extend(card.nodes.iter().cloned());
    }
    // ⛔ A JETSON'S LISTED NODE THE CALLER CANNOT OPEN IS LEFT OUT, NOT A REASON TO REFUSE. NVIDIA's
    // CSV names the profiler and debugger nodes too, `root:debug 0660`: MEASURED on a Jetson Orin
    // Nano, a user in `video` and not in `debug` was refused the whole GPU over 13 of them. Docker
    // mounts them because it runs as root; in a box they could not be opened either. If none of the
    // listed nodes can be opened, the grant is refused as before, by the policy below.
    if !grant.listed_nodes.is_empty() {
        let unreachable = |(p, f): &(PathBuf, NodeFacts)| {
            grant.listed_nodes.contains(p) && access_path(f, who) == AccessPath::Unreachable
        };
        let listed = selected
            .iter()
            .filter(|(p, _)| grant.listed_nodes.contains(p))
            .count();
        let dropped = selected.iter().filter(|e| unreachable(e)).count();
        if dropped < listed {
            selected.retain(|e| !unreachable(e));
        }
    }

    match group_policy(&selected, who) {
        GroupPolicy::Unreachable { nodes } => return Err(MountPlanError::Unreachable { nodes }),
        GroupPolicy::Needed { gids, nodes } if groups == Groups::Enforce => {
            return Err(MountPlanError::GroupsNeeded { gids, nodes })
        }
        GroupPolicy::Needed { .. } | GroupPolicy::NotNeeded => {}
    }

    // A Jetson's grant keeps NVIDIA's paths (see `TegraCsv`); the box's loader is told them.
    let lib_dir = if grant.at_host_paths { None } else { lib_dir };
    let mut binds: Vec<Bind> =
        Vec::with_capacity(selected.len() + grant.libraries.len() + grant.symlinks.len());

    for (node, _) in &selected {
        let path = node.to_string_lossy().to_string();
        binds.push((path.clone(), path, false));
    }

    // IN THE BOX'S LIBRARY DIRECTORY when one is given, by file name, which is how docker flattens
    // them; the first file to claim a name keeps it, so two host directories cannot bind twice onto
    // one target.
    let place = |host: &Path| -> String {
        match (lib_dir, host.file_name()) {
            (Some(dir), Some(name)) => format!("{dir}/{}", name.to_string_lossy()),
            _ => host.to_string_lossy().to_string(),
        }
    };
    let mut lib_targets: BTreeSet<String> = BTreeSet::new();
    for library in &grant.libraries {
        let target = place(&library.path);
        if lib_targets.insert(target.clone()) {
            binds.push((library.path.to_string_lossy().to_string(), target, true));
        }
    }

    for link in &grant.symlinks {
        let target = place(&link.link);
        if lib_targets.insert(target.clone()) {
            binds.push((link.resolved.to_string_lossy().to_string(), target, true));
        }
    }

    // THE LINKS THE CDI HOOK WOULD CREATE, as binds of the file they point at, beside the libraries.
    for (prefix, link) in DRIVER_ALIAS_LINKS {
        let Some(library) = grant.libraries.iter().find(|l| {
            l.path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(prefix))
        }) else {
            continue;
        };
        let dir = match lib_dir {
            Some(d) => d.to_string(),
            None => library
                .path
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
        };
        let target = format!("{dir}/{link}");
        if lib_targets.insert(target.clone()) {
            binds.push((library.path.to_string_lossy().to_string(), target, true));
        }
    }

    // THE LISTED DIRECTORIES, read-only, at their own paths (`/dev/dri/by-path` on a Jetson).
    for dir in &grant.dirs {
        let path = dir.to_string_lossy().to_string();
        binds.push((path.clone(), path, true));
    }

    // THE CONFIGURATION FILES, read-only, at the paths NVIDIA's own spec gives them.
    for (host, target) in &grant.configs {
        binds.push((host.to_string_lossy().to_string(), target.clone(), true));
    }

    // THE TOOLS, READ-ONLY, where docker puts them. Bound and never copied, like the libraries.
    for tool in &grant.tools {
        binds.push((
            tool.source.to_string_lossy().to_string(),
            format!("{DRIVER_TOOLS_IN_BOX}/{}", tool.name),
            true,
        ));
    }

    Ok(binds)
}

/// Why a selection was refused, as one sentence for a reader.
///
/// ONE SPELLING, because there are now two callers. `kern box` mapped every variant to prose inline
/// and `kern box --plan` had none, so the preview printed the `Debug` form of the error:
/// `NoSuchCard { wanted: 9, present: [0, 1] }`. A plan whose refusal reads differently from the
/// launch's refusal is a plan the reader cannot compare with what happens next.
///
/// The group sentence says "a box carries no supplementary group ON THE DEFAULT MAP", because a
/// single-uid box keeps them: the flat claim was corrected elsewhere in this crate and repeating
/// the old one here would reintroduce it.
pub fn describe_mount_plan_error(e: &MountPlanError) -> String {
    match e {
        // NOT ENOUGH CARDS IS NOT A WRONG INDEX. The caller named no card, so there is nothing for
        // them to correct except the number they asked for, and the message has to say how many are
        // here rather than which ones.
        MountPlanError::TooFewCards { wanted, present } => format!(
            "--gpus {wanted}: this host has {} card(s), which is fewer than the {} asked for. \
             Present: {}",
            present.len(),
            wanted,
            join_indices(present)
        ),
        MountPlanError::NoSuchCard { wanted, present } => format!(
            // `device=`, BECAUSE A BARE NUMBER IS A COUNT in this grammar. MEASURED in the field on
            // a WSL2 guest, docker's own docs example `device_ids: ['0', '3']`: the refusal read
            // "--gpus 3: this host has no card 3", which names a request for THREE cards.
            "--gpus device={wanted}: this host has no card {wanted}. Present: {}",
            join_indices(present)
        ),
        MountPlanError::GroupsNeeded { gids, nodes } => format!(
            "--gpus: {} is reachable only through group(s) {}, and a box on the default map \
             carries no supplementary group. Keeping them is all or nothing, so kern refuses \
             rather than deciding it for you: relax the node's mode on the host, or start the box \
             with --no-uid-range, which keeps EVERY inherited group and is the price of that map",
            join_paths_for_message(nodes),
            gids.iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        MountPlanError::Unreachable { nodes } => format!(
            "--gpus: the invoking user cannot open {} on this host either, so no box could use it",
            join_paths_for_message(nodes)
        ),
    }
}

/// Card indices for a message, or `none`.
fn join_indices(present: &[u32]) -> String {
    if present.is_empty() {
        return "none".to_string();
    }
    present
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Paths for a message.
fn join_paths_for_message(nodes: &[PathBuf]) -> String {
    nodes
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The grant, rendered for `--plan`, one fact per line and no adjectives.
///
/// A print surface and nothing else: it mounts nothing and decides nothing, so the preview a reader
/// sees is the same structure a later phase would act on.
pub fn render_plan(grant: &GpuGrant, selection: &GpuSelection) -> String {
    render_plan_for(grant, selection, &Caller::current())
}

/// [`render_plan`] for a given caller. The group decision depends on who asks, and a test that
/// asked the process answered differently as root (no node is gated for root) and as a user outside
/// the node's group: MEASURED as root in a WSL2 guest, "a gated node must be reported" failed.
pub fn render_plan_for(grant: &GpuGrant, selection: &GpuSelection, who: &Caller) -> String {
    let mut out = String::new();
    out.push_str(&format!("driver {}\n", grant.driver_version));

    // THE SELECTION, NOT THE INVENTORY. This took no selection, so `--plan` described the whole
    // host: a box asking for `--gpus device=0` was shown every card's nodes, and the caller had no
    // way to tell which lines were about the box being planned. The cards are the ones
    // `mount_plan` would take; a selection this host cannot satisfy renders nothing here, because
    // the caller already prints the launch's own refusal for that case.
    let chosen: Vec<&CardNodes> = cards_of(grant, selection).unwrap_or_default();
    let mut every: Vec<(PathBuf, NodeFacts)> = grant.shared.clone();
    for card in &chosen {
        every.extend(card.nodes.iter().cloned());
    }
    out.push_str(&format!(
        "nodes {} ({} shared, {} of {} card(s))\n",
        every.len(),
        grant.shared.len(),
        chosen.len(),
        grant.cards.len()
    ));
    // WHICH CARD EACH INDEX MEANS, before anything is mounted. `--gpus device=0` names an
    // reader has another number in front of them, the `cardN` their desktop and `nvidia-smi` use,
    // index, and on this host it is INVERTED against `cardN`: card 0 is `0000:01:00.0`, which
    // preview that showed only the count would let someone confirm a plan for the other card.
    for card in &chosen {
        match card.pci_address.as_deref() {
            Some(addr) => out.push_str(&format!("  --gpus device={} is {}\n", card.index, addr)),
            None => out.push_str(&format!(
                "  --gpus device={} has no PCI address in /proc/driver/nvidia\n",
                card.index
            )),
        }
    }
    {
        for (node, _) in &grant.shared {
            out.push_str(&format!("  shared {}\n", node.display()));
        }
        for card in &chosen {
            for (node, _) in &card.nodes {
                out.push_str(&format!("  card {} {}\n", card.index, node.display()));
            }
        }
    }
    out.push_str(&format!("libraries {}\n", grant.libraries.len()));
    {
        for library in &grant.libraries {
            out.push_str(&format!("  lib {}\n", library.path.display()));
        }
    }
    out.push_str(&format!("symlinks {}\n", grant.symlinks.len()));
    {
        for link in &grant.symlinks {
            out.push_str(&format!(
                "  link {} -> {}\n",
                link.link.display(),
                link.target.display()
            ));
        }
    }
    out.push_str(&format!("ldconfig dirs {}\n", grant.ldconfig_dirs.len()));
    {
        for dir in &grant.ldconfig_dirs {
            out.push_str(&format!("  dir {}\n", dir.display()));
        }
    }
    out.push_str(&format!("configs {}\n", grant.configs.len()));
    for (host, target) in &grant.configs {
        out.push_str(&format!("  config {} -> {target}\n", host.display()));
    }
    out.push_str(&format!("tools {}\n", grant.tools.len()));
    for tool in &grant.tools {
        out.push_str(&format!(
            "  tool {} -> {DRIVER_TOOLS_IN_BOX}/{}\n",
            tool.source.display(),
            tool.name
        ));
    }
    // The policy is a FUNCTION of a selection, not a field, and it is now asked over the SAME
    // nodes `mount_plan` would take rather than over the host's whole set. Asking over every node
    // made `--plan` report a group that only the card nobody asked for needs.
    match &group_policy(&every, who) {
        GroupPolicy::NotNeeded => {
            out.push_str("groups not needed: every node is reached by uid or by other\n");
        }
        GroupPolicy::Needed { gids, nodes } => {
            let names: Vec<String> = gids.iter().map(|g| g.to_string()).collect();
            out.push_str(&format!("groups needed: {}\n", names.join(", ")));
            {
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
    /// The memoised resolution answers what `canonicalize` answers: a file, a file through a linked
    /// directory, a link, a missing name, and the `.`/`..` forms that must not take the short cut.
    #[test]
    fn the_memoised_resolution_answers_what_canonicalize_answers() {
        let base = std::env::temp_dir().join(format!("kern-canon-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("real/sub")).unwrap();
        std::fs::write(base.join("real/lib.so"), b"elf").unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("linkdir")).unwrap();
        std::os::unix::fs::symlink("lib.so", base.join("real/link.so")).unwrap();
        std::os::unix::fs::symlink("real/sub", base.join("subl")).unwrap();
        for rel in [
            "real/lib.so",
            "linkdir/lib.so",
            "linkdir/link.so",
            "linkdir/missing.so",
            "linkdir/.",
            "subl/.",
            "subl/..",
            "linkdir/./lib.so",
            "real/../linkdir/lib.so",
            "linkdir/",
        ] {
            let p = PathBuf::from(format!("{}/{rel}", base.display()));
            // Twice: the second call answers from the memo.
            for _ in 0..2 {
                assert_eq!(
                    super::canonical(&p),
                    std::fs::canonicalize(&p).ok(),
                    "{rel}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    use super::*;

    /// Put a stand-in DEVICE NODE at `path`, the way an unprivileged test can.
    ///
    /// These fixtures used regular files, and `node_facts` now requires a character device, which
    /// is what a grant actually mounts. A whiteout (`c 0 0`) is the only character device an
    /// unprivileged process may create: `vfs_mknod` tests CAP_MKNOD only
    /// `if ((S_ISCHR || S_ISBLK) && !is_whiteout && !capable(...))`. So the fixture is now the right
    /// KIND, which is closer to the real thing than a regular file was, and `false` says the kernel
    /// refused it rather than leaving a caller to wonder.
    ///
    /// ⚠️ The device NUMBER is 0:0 and no real node has that, which is why the hardware row and the
    /// CDI nesting rule both check `rdev` on top of the kind. `node_facts` deliberately does not:
    /// its job is to describe a node the resolver already found by name under `dev`, and requiring a
    /// vendor's major there would make every synthetic root untestable for no boundary.
    fn fixture_node(path: &Path) -> bool {
        std::ffi::CString::new(path.as_os_str().as_bytes())
            .map(|p| unsafe { libc::mknod(p.as_ptr(), libc::S_IFCHR | 0o666, 0) } == 0)
            .unwrap_or(false)
    }

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
            acl: None,
        }
    }

    /// A node carrying an ACL, with `st_mode` built to match it the way a filesystem stores it.
    ///
    /// `ACL_USER_OBJ` is the owner triad and `ACL_OTHER` is the other triad, but `ACL_GROUP_OBJ` is
    /// the OWNING GROUP's permission and `st_mode`'s group triad is the MASK whenever one exists.
    /// The helper derives the mode from those rules rather than taking it, so no fixture can state
    /// a node that two kernel interfaces would describe differently, and so a reader cannot repeat
    /// the defect these cases exist for by writing the mask into `group_obj`.
    // EIGHT ARGUMENTS ON PURPOSE: they are the fields of a POSIX ACL, and the whole point of the
    // helper is that a fixture cannot state a node the two kernel interfaces would describe
    // differently. Grouping them into a struct would put the same eight values one indirection
    // away and let a caller build the struct wrong, which is the defect these cases exist for.
    #[allow(clippy::too_many_arguments)]
    fn acl_node(
        uid: u32,
        gid: u32,
        owner: u8,
        group_obj: u8,
        other: u8,
        users: &[(u32, u8)],
        groups: &[(u32, u8)],
        mask: Option<u8>,
    ) -> NodeFacts {
        NodeFacts {
            uid,
            gid,
            mode: (u32::from(owner) << 6)
                | (u32::from(mask.unwrap_or(group_obj)) << 3)
                | u32::from(other),
            acl: Some(Acl {
                user_obj: owner,
                users: users.to_vec(),
                group_obj,
                groups: groups.to_vec(),
                mask,
                other,
            }),
        }
    }

    /// THE POLICY, over its whole input space rather than over the state this machine is in.
    ///
    /// The space is (owner matches) x (group matches) x (owner triad) x (owning-group triad) x
    /// (other triad) x (a named-user entry, absent or with any triad) x (a named-group entry, the
    /// same) x (the mask, absent or any triad) x (the access asked for). Triads are enumerated as
    /// the four combinations of read and write that matter, so a rule that happens to be right for
    /// this desktop's `0666` nodes cannot pass.
    ///
    /// WANT IS A DIMENSION, and that is the correction of 2026-11-12. The previous version of this
    /// test asked only the read question, which is the question the implementation also asked, so
    /// the pair agreed and both were wrong about the access the driver performs. Running the whole
    /// space at `ACL_READ` and again at `WANT_RW` is what makes "read is enough" visible.
    ///
    /// WHAT THIS TEST IS AND IS NOT. The expectation below is the POSIX algorithm written out, so
    /// it is not an independent derivation and does not pretend to be: its value is total coverage
    /// and regression, and the independence comes from the kernel cross-check in
    /// `the_kernel_agrees_about_the_classes_this_caller_can_actually_produce` plus the three named
    /// cases that cite `posix_acl_permission` directly.
    #[test]
    fn the_policy_answers_every_combination_the_way_the_kernel_orders_them() {
        const TRIADS: [u8; 4] = [0, ACL_READ, ACL_WRITE, ACL_READ | ACL_WRITE];
        const ENTRIES: [Option<u8>; 5] = [
            None,
            Some(0),
            Some(ACL_READ),
            Some(ACL_WRITE),
            Some(ACL_READ | ACL_WRITE),
        ];
        let who = caller(1000, &[1000, 44]);
        let mut seen_each_variant = [false; 5];
        let mut cases = 0usize;

        for want in [ACL_READ, WANT_RW] {
            for owner_matches in [false, true] {
                for group_matches in [false, true] {
                    for owner in TRIADS {
                        for group_obj in TRIADS {
                            for other in TRIADS {
                                for acl_present in [false, true] {
                                    for named_user in ENTRIES {
                                        for named_group in ENTRIES {
                                            for mask in ENTRIES {
                                                // Without an ACL there are no entries and no mask,
                                                // so only the all-absent combination is a real
                                                // node; generating the others would count cases
                                                // that cannot exist.
                                                if !acl_present
                                                    && (named_user.is_some()
                                                        || named_group.is_some()
                                                        || mask.is_some())
                                                {
                                                    continue;
                                                }
                                                let uid = if owner_matches { 1000 } else { 4242 };
                                                let gid = if group_matches { 44 } else { 4242 };
                                                let users: Vec<(u32, u8)> = named_user
                                                    .map(|p| vec![(1000u32, p)])
                                                    .unwrap_or_default();
                                                let groups: Vec<(u32, u8)> = named_group
                                                    .map(|p| vec![(44u32, p)])
                                                    .unwrap_or_default();
                                                let node = if acl_present {
                                                    acl_node(
                                                        uid, gid, owner, group_obj, other, &users,
                                                        &groups, mask,
                                                    )
                                                } else {
                                                    plain(
                                                        uid,
                                                        gid,
                                                        (u32::from(owner) << 6)
                                                            | (u32::from(group_obj) << 3)
                                                            | u32::from(other),
                                                    )
                                                };

                                                let got = access_path_for(&node, &who, want);

                                                let has = |perm: u8| perm & want == want;
                                                let mask_bits = mask.unwrap_or(ACL_PERM_ALL);
                                                let expected = if owner_matches {
                                                    // The owner class is exclusive and unmasked.
                                                    if has(owner) {
                                                        AccessPath::Owner
                                                    } else {
                                                        AccessPath::Unreachable
                                                    }
                                                } else if let Some(p) = named_user {
                                                    // A named user is exclusive once it matches,
                                                    // and the mask bounds it.
                                                    if has(p & mask_bits) {
                                                        AccessPath::AclUser
                                                    } else {
                                                        AccessPath::Unreachable
                                                    }
                                                } else {
                                                    // The group class: membership makes the
                                                    // decision final, one entry must carry every
                                                    // wanted bit alone, and the mask bounds the
                                                    // class.
                                                    let mut found = false;
                                                    let mut satisfied = false;
                                                    if group_matches {
                                                        found = true;
                                                        satisfied |= has(group_obj);
                                                    }
                                                    if let Some(p) = named_group {
                                                        found = true;
                                                        satisfied |= has(p);
                                                    }
                                                    if found {
                                                        if satisfied && has(mask_bits) {
                                                            AccessPath::GroupOnly
                                                        } else {
                                                            AccessPath::Unreachable
                                                        }
                                                    } else if has(other) {
                                                        AccessPath::Other
                                                    } else {
                                                        AccessPath::Unreachable
                                                    }
                                                };

                                                assert_eq!(
                                                    got, expected,
                                                    "want={want:#o} owner_matches={owner_matches} \
                                                     group_matches={group_matches} acl={acl_present} \
                                                     triads={owner:#o}/{group_obj:#o}/{other:#o} \
                                                     user={named_user:?} group={named_group:?} \
                                                     mask={mask:?}"
                                                );

                                                let index = match got {
                                                    AccessPath::Owner => 0,
                                                    AccessPath::AclUser => 1,
                                                    AccessPath::Other => 2,
                                                    AccessPath::GroupOnly => 3,
                                                    AccessPath::Unreachable => 4,
                                                };
                                                seen_each_variant[index] = true;
                                                cases += 1;
                                            }
                                        }
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
        // And an enumeration whose `continue` filtered everything would also pass the line above
        // on a single lucky case, so the count is pinned too.
        assert!(
            cases > 5000,
            "the enumeration collapsed to {cases} cases, so it is not the space it claims"
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
        let node = acl_node(
            0,
            44,
            WANT_RW,
            WANT_RW,
            0,
            &[(1000, WANT_RW)],
            &[],
            Some(WANT_RW),
        );
        let got = access_path(&node, &who);
        assert_eq!(got, AccessPath::AclUser);
        assert!(got.survives_a_box());
    }

    /// THE FIRST OF THE THREE CASES THAT WERE THE DEFECT. A named-user entry is bounded by the
    /// mask, and the previous rule returned `AclUser` from the entry alone without ever reading the
    /// mask that `NodeFacts` already carried.
    ///
    /// `getfacl` prints this node's entry as `user:alex:rw-  #effective:---`, which is the kernel
    /// stating that the entry grants nothing. `posix_acl_permission` reaches its `mask` label for
    /// `ACL_USER` and returns `-EACCES` unless `(entry & mask & want) == want`. Reported reachable,
    /// the grant mounts and the workload dies at `cuInit` with no diagnostic from kern, which is
    /// the one failure mode this whole policy exists to prevent.
    #[test]
    fn a_named_user_entry_is_bounded_by_the_mask() {
        let who = caller(1000, &[1000, 44]);
        let denied = acl_node(0, 44, WANT_RW, WANT_RW, 0, &[(1000, WANT_RW)], &[], Some(0));
        assert_eq!(
            access_path(&denied, &who),
            AccessPath::Unreachable,
            "a named entry under a mask that denies everything must not read as reachable"
        );

        // POSITIVE CONTROL on the same node with the mask opened, so the refusal above is the mask
        // and not the entry, the uid or the mode.
        let allowed = acl_node(
            0,
            44,
            WANT_RW,
            WANT_RW,
            0,
            &[(1000, WANT_RW)],
            &[],
            Some(WANT_RW),
        );
        assert_eq!(access_path(&allowed, &who), AccessPath::AclUser);

        // And a mask that allows READ only still refuses, because the driver opens `O_RDWR`. This
        // is the line where the two halves of the defect meet.
        let read_only_mask = acl_node(
            0,
            44,
            WANT_RW,
            WANT_RW,
            0,
            &[(1000, WANT_RW)],
            &[],
            Some(ACL_READ),
        );
        assert_eq!(access_path(&read_only_mask, &who), AccessPath::Unreachable);
        assert_eq!(
            access_path_for(&read_only_mask, &who, ACL_READ),
            AccessPath::AclUser,
            "the same node must be reachable for a READ, or this case proves nothing about rw"
        );
    }

    /// THE SECOND CASE. A node the caller can read and not write is Unreachable, because the driver
    /// opens its nodes `O_RDWR`. The policy used to read the write bit out of the ACL and discard
    /// it with a comment saying so.
    #[test]
    fn a_read_only_node_is_unreachable_because_the_driver_opens_rw() {
        let who = caller(1000, &[1000, 44]);
        let node = plain(0, 0, 0o444);
        assert_eq!(access_path(&node, &who), AccessPath::Unreachable);
        // POSITIVE CONTROL: the same node answers for a read, so the refusal is the write bit and
        // not the node being unreadable by anyone.
        assert_eq!(
            access_path_for(&node, &who, ACL_READ),
            AccessPath::Other,
            "0o444 must be reachable for a READ, or the rw refusal above proves nothing"
        );
        // And `0o666`, which is what this host's `/dev/nvidia*` nodes are, is reachable.
        assert_eq!(access_path(&plain(0, 0, 0o666), &who), AccessPath::Other);
    }

    /// THE THIRD CASE, and the one no reading of the old code would have caught: THE KERNEL DOES
    /// NOT UNION TWO ENTRIES FOR ONE ACCESS.
    ///
    /// `group::r--` beside `group:44:-w-` under `mask::rw-` satisfies a read check through the
    /// first entry and a write check through the second, and refuses `O_RDWR`, because
    /// `posix_acl_permission` only reaches its `mask` label from an entry for which
    /// `(e_perm & want) == want` holds ALONE. A policy that asks about read and about write
    /// separately concludes rw-reachable and the workload dies at `cuInit`.
    #[test]
    fn two_group_entries_do_not_combine_into_one_access() {
        let who = caller(1000, &[1000, 44]);
        let split = acl_node(
            0,
            44,
            WANT_RW,
            ACL_READ,
            0,
            &[],
            &[(44, ACL_WRITE)],
            Some(WANT_RW),
        );
        assert_eq!(
            access_path(&split, &who),
            AccessPath::Unreachable,
            "read from one entry and write from another is not an rw access"
        );
        // POSITIVE CONTROLS, one per half, so the refusal is the SPLIT and not either entry being
        // ignored: each access the entries do carry on their own must be granted.
        assert_eq!(
            access_path_for(&split, &who, ACL_READ),
            AccessPath::GroupOnly,
            "the read the owning-group entry carries alone must be granted"
        );
        assert_eq!(
            access_path_for(&split, &who, ACL_WRITE),
            AccessPath::GroupOnly,
            "the write the named-group entry carries alone must be granted"
        );
        // And one entry carrying BOTH bits is reachable, which is the same node with the split
        // repaired.
        let whole = acl_node(0, 44, WANT_RW, WANT_RW, 0, &[], &[], Some(WANT_RW));
        assert_eq!(access_path(&whole, &who), AccessPath::GroupOnly);
    }

    /// Being in the group class is FINAL: the kernel does not fall through to `other` once the
    /// caller matched a group-class entry, so `0o606` denies a group member the write it would have
    /// had as a stranger. A resolver that fell through would report a node the kernel refuses.
    #[test]
    fn the_group_class_does_not_fall_through_to_other() {
        let member = caller(1000, &[1000, 44]);
        let stranger = caller(1000, &[1000]);
        let node = plain(0, 44, 0o606);
        assert_eq!(
            access_path(&node, &member),
            AccessPath::Unreachable,
            "a group member must not be handed the `other` triad"
        );
        assert_eq!(
            access_path(&node, &stranger),
            AccessPath::Other,
            "and a stranger must still get it, or the case above is about something else"
        );
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
        let node = acl_node(0, 4242, WANT_RW, 0, 0, &[], &[(44, WANT_RW)], Some(WANT_RW));
        let got = access_path(&node, &who);
        assert_eq!(got, AccessPath::GroupOnly);
        assert!(!got.survives_a_box());
    }

    /// A mask that denies kills the whole group class, entries included.
    #[test]
    fn an_acl_mask_without_the_wanted_bits_closes_the_group_path_entirely() {
        let who = caller(1000, &[1000, 44]);
        let node = acl_node(0, 44, WANT_RW, WANT_RW, 0, &[], &[(44, WANT_RW)], Some(0));
        assert_eq!(access_path(&node, &who), AccessPath::Unreachable);
        // POSITIVE CONTROL: the same node with the mask open is reachable, so the refusal is the
        // mask.
        let open = acl_node(
            0,
            44,
            WANT_RW,
            WANT_RW,
            0,
            &[],
            &[(44, WANT_RW)],
            Some(WANT_RW),
        );
        assert_eq!(access_path(&open, &who), AccessPath::GroupOnly);
    }

    /// A MINIMAL ACL HAS NO MASK, and there the mask must bound nothing.
    ///
    /// Treating an absent mask as zero would be the fail-closed direction and would refuse every
    /// grant on a host whose nodes carry a three-entry ACL, which is what a filesystem stores for a
    /// node with no named entry at all.
    #[test]
    fn an_absent_mask_bounds_nothing() {
        let who = caller(1000, &[1000, 44]);
        let node = acl_node(0, 44, WANT_RW, WANT_RW, 0, &[], &[], None);
        assert_eq!(access_path(&node, &who), AccessPath::GroupOnly);
        let named = acl_node(0, 4242, WANT_RW, 0, 0, &[(1000, WANT_RW)], &[], None);
        assert_eq!(access_path(&named, &who), AccessPath::AclUser);
    }

    /// THE KERNEL ITSELF, on the classes this caller can actually produce without privilege.
    ///
    /// The matrix test's expectation is the POSIX algorithm written out, so it cannot be its own
    /// independent check. This one asks the KERNEL: it creates files, opens them `O_RDWR`, and
    /// compares the verdict with [`access_path`]. What it can reach is the owner class and the
    /// group class (a file can be `chgrp`-ed to a group the caller already holds) and the mode
    /// path; what it cannot reach is a named-user entry for a DIFFERENT uid, because creating a
    /// file owned by somebody else needs privilege. That gap is the reason the three cases above
    /// cite `posix_acl_permission` by name instead of measuring it.
    ///
    /// ⚠️ A file owned by the caller is decided by the OWNER class, exclusively. Putting a named
    /// entry on one's own file and concluding anything about named entries is the exact trap that
    /// produced the original defect, so this test never does it.
    #[test]
    fn the_kernel_agrees_about_the_classes_this_caller_can_actually_produce() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kern-aclk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        if std::fs::create_dir_all(&dir).is_err() {
            eprintln!("skip: no writable temp dir, so the kernel cannot be asked");
            return;
        }
        let who = Caller::current();
        let mut checked = 0usize;
        for (index, mode) in [0o600u32, 0o400, 0o200, 0o000, 0o666, 0o060, 0o006]
            .into_iter()
            .enumerate()
        {
            let path = dir.join(format!("f{index}"));
            if std::fs::write(&path, b"x").is_err() {
                continue;
            }
            if std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).is_err() {
                continue;
            }
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            let facts = NodeFacts {
                uid: meta.uid(),
                gid: meta.gid(),
                mode: meta.mode() & 0o777,
                acl: acl_facts(&path),
            };
            let kernel_opens = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .is_ok();
            let policy_says = access_path(&facts, &who) != AccessPath::Unreachable;
            assert_eq!(
                policy_says, kernel_opens,
                "mode {mode:#o}: policy says reachable={policy_says}, the kernel says {kernel_opens}"
            );
            checked += 1;
        }
        let _ = std::fs::remove_dir_all(&dir);
        // Both answers must have occurred, or this compared a constant with a constant.
        assert!(
            checked >= 4,
            "only {checked} modes were testable, which is not a cross-check"
        );
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

    /// One ACL entry as the xattr encodes it: a 16-bit tag, a 16-bit permission word, a 32-bit id.
    fn acl_entry(tag: u16, perm: u8, id: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&u16::from(perm).to_le_bytes());
        out.extend_from_slice(&id.to_le_bytes());
        out
    }

    /// A whole `system.posix_acl_access` blob from a list of entries.
    fn acl_blob(entries: &[(u16, u8, u32)]) -> Vec<u8> {
        let mut bytes = ACL_XATTR_VERSION.to_le_bytes().to_vec();
        for (tag, perm, id) in entries {
            bytes.extend_from_slice(&acl_entry(*tag, *perm, *id));
        }
        bytes
    }

    /// The ACL parser over the shapes a filesystem should never produce.
    ///
    /// `None` is the answer for every one of them, and `None` means "this node has no ACL, decide
    /// from `st_mode`". That is deliberately NOT the same as an all-deny ACL: a node whose xattr
    /// cannot be parsed still has permission bits, and refusing it outright would refuse grants on
    /// a host whose filesystem simply answers the query differently.
    #[test]
    fn the_acl_parser_fails_closed_on_every_malformed_shape() {
        // Too short to carry a version word.
        assert_eq!(parse_acl_xattr(&[]), None);
        assert_eq!(parse_acl_xattr(&[2, 0, 0]), None);
        // A version word and nothing after it is not an ACL.
        assert_eq!(parse_acl_xattr(&ACL_XATTR_VERSION.to_le_bytes()), None);
        // A version this parser does not know grants nothing.
        let mut wrong_version = 9u32.to_le_bytes().to_vec();
        wrong_version.extend_from_slice(&acl_entry(ACL_USER, ACL_READ, 1000));
        assert_eq!(parse_acl_xattr(&wrong_version), None);
        // A trailing fragment shorter than one entry is dropped, and what came before survives.
        let mut good = acl_blob(&[(ACL_USER, ACL_READ | ACL_WRITE, 1000)]);
        good.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
        let parsed = parse_acl_xattr(&good).expect("the complete entry must survive");
        assert_eq!(parsed.users, vec![(1000, ACL_READ | ACL_WRITE)]);
        assert_eq!(parsed.mask, None);
        // A reserved high bit in the permission word must not become a permission.
        let reserved = {
            let mut bytes = ACL_XATTR_VERSION.to_le_bytes().to_vec();
            bytes.extend_from_slice(&ACL_USER.to_le_bytes());
            bytes.extend_from_slice(&0xFF04u16.to_le_bytes());
            bytes.extend_from_slice(&1000u32.to_le_bytes());
            bytes
        };
        let parsed = parse_acl_xattr(&reserved).expect("the entry is well formed");
        assert_eq!(
            parsed.users,
            vec![(1000, ACL_READ)],
            "a reserved bit leaked into the permission triad"
        );
        // An unknown tag is skipped without derailing the walk, so the entry after it is still read.
        let unknown = acl_blob(&[(0x4000, ACL_PERM_ALL, 0), (ACL_USER, ACL_READ, 1000)]);
        let parsed = parse_acl_xattr(&unknown).expect("the known entry must survive");
        assert_eq!(parsed.users, vec![(1000, ACL_READ)]);
    }

    /// A real ACL, in the shape `getfacl` shows on this host's `/dev/dri/card0`: all six entry
    /// kinds, with the permissions each one carries.
    #[test]
    fn the_acl_parser_reads_every_entry_kind_with_its_permissions() {
        let bytes = acl_blob(&[
            (ACL_USER_OBJ, ACL_READ | ACL_WRITE, 0xFFFF_FFFF),
            (ACL_USER, ACL_READ | ACL_WRITE, 1000),
            (ACL_GROUP_OBJ, ACL_READ | ACL_WRITE, 0xFFFF_FFFF),
            (ACL_GROUP, ACL_READ, 44),
            (ACL_MASK, ACL_READ | ACL_WRITE, 0xFFFF_FFFF),
            (ACL_OTHER, 0, 0xFFFF_FFFF),
        ]);
        let acl = parse_acl_xattr(&bytes).expect("a conforming ACL must parse");
        assert_eq!(acl.user_obj, ACL_READ | ACL_WRITE);
        assert_eq!(acl.users, vec![(1000, ACL_READ | ACL_WRITE)]);
        assert_eq!(acl.group_obj, ACL_READ | ACL_WRITE);
        assert_eq!(acl.groups, vec![(44, ACL_READ)]);
        assert_eq!(acl.mask, Some(ACL_READ | ACL_WRITE));
        assert_eq!(acl.other, 0);
    }

    /// THE MASK IS A PERMISSION, NOT A FLAG, which is what the previous reduction could not say.
    ///
    /// It used to collapse to "the mask denies read", so a mask of `r--` over an entry of `rw-`
    /// read as permissive and the write it removes was invisible. The parser keeps the triad and
    /// the policy intersects with it.
    #[test]
    fn the_mask_is_kept_as_a_triad_and_not_as_a_deny_flag() {
        for (bits, label) in [
            (0u8, "no access at all"),
            (ACL_READ, "read only"),
            (ACL_WRITE, "write only"),
            (ACL_READ | ACL_WRITE, "both"),
        ] {
            let bytes = acl_blob(&[(ACL_MASK, bits, 0xFFFF_FFFF)]);
            let acl = parse_acl_xattr(&bytes).expect("a mask entry is an ACL");
            assert_eq!(acl.mask, Some(bits), "the mask lost its triad: {label}");
        }
    }

    /// A DUPLICATE ID IS INTERSECTED, never first-wins or last-wins.
    ///
    /// A conforming ACL cannot carry the same id twice, so this is only reachable on a malformed
    /// blob. Intersection is the only reduction that cannot GRANT a permission no single entry
    /// granted, which is the direction that matters when the input is not trusted.
    #[test]
    fn a_duplicate_acl_id_is_reduced_by_intersection() {
        let bytes = acl_blob(&[
            (ACL_USER, ACL_READ | ACL_WRITE, 1000),
            (ACL_USER, ACL_READ, 1000),
            (ACL_GROUP, ACL_WRITE, 44),
            (ACL_GROUP, ACL_READ | ACL_WRITE, 44),
        ]);
        let acl = parse_acl_xattr(&bytes).expect("the blob parses");
        assert_eq!(
            acl.users,
            vec![(1000, ACL_READ)],
            "two user entries for one id must intersect, not pick one"
        );
        assert_eq!(
            acl.groups,
            vec![(44, ACL_WRITE)],
            "two group entries for one id must intersect, not pick one"
        );
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
        let wrote_node = fixture_node(&dev_dir.join("nvidiactl"));
        assert!(wrote_version.is_ok());
        if !wrote_node {
            eprintln!("skip: this kernel refused a whiteout, so no stand-in node can be made");
            return;
        }

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
            let _ = fixture_node(&dev_dir.join(name));
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
        let _ = fixture_node(&root.join("dev/nvidiactl"));

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

    /// ⛔ A JETSON'S GRANT IS NVIDIA'S CSV LIST, AT THE HOST'S PATHS. The desktop rule (the driver
    /// version in the file name) missed `libcuda.so.1.1` on a Jetson Orin Nano, and a row may be a
    /// pattern (`/dev/dri/card*`). The positive control: the same tree without `nv_tegra_release` is
    /// a desktop host again and gets the desktop rule.
    #[test]
    fn a_jetson_grant_reads_nvidias_csv_and_keeps_its_paths() {
        let class = if cfg!(target_pointer_width = "64") {
            2
        } else {
            1
        };
        let root = synthetic_root(
            "tegra",
            "540.4.0",
            &[
                (
                    "usr/lib/aarch64-linux-gnu/nvidia",
                    "libcuda.so.1.1",
                    class,
                    None,
                ),
                (
                    "usr/lib/aarch64-linux-gnu/nvidia",
                    "libnvidia-glcore.so.540.4.0",
                    class,
                    None,
                ),
                ("usr/sbin", "nvidia-smi", class, None),
            ],
        );
        link_in(
            &root,
            "usr/lib/aarch64-linux-gnu",
            "libcuda.so",
            "nvidia/libcuda.so.1.1",
        );
        let made = [
            "dev/nvidia0",
            "dev/nvhost-gpu",
            "dev/dri/card0",
            "dev/dri/card1",
        ]
        .iter()
        .all(|n| {
            let _ = std::fs::create_dir_all(root.join(n).parent().unwrap_or(&root));
            fixture_node(&root.join(n))
        });
        if !made {
            let _ = std::fs::remove_dir_all(&root);
            eprintln!("skip: this kernel refused a whiteout, so no stand-in node can be made");
            return;
        }
        let _ = std::fs::create_dir_all(root.join("dev/dri/by-path"));
        let _ = std::fs::create_dir_all(root.join("sys/devices/soc0"));
        let csv = root.join(TEGRA_CSV_DIR_REL);
        let _ = std::fs::create_dir_all(&csv);
        let _ = std::fs::write(
            csv.join("devices.csv"),
            "# devices\ndev, /dev/nvhost-gpu\ndev, /dev/dri/card*\ndir, /dev/dri/by-path\n",
        );
        let _ = std::fs::write(
            csv.join("drivers.csv"),
            "lib, /usr/lib/aarch64-linux-gnu/nvidia/libcuda.so.1.1\nlib, /usr/sbin/nvidia-smi\n\
             sym, /usr/lib/aarch64-linux-gnu/libcuda.so\n",
        );
        let desktop = resolve_under(&root, ElfClass::native());
        let _ = std::fs::write(root.join(TEGRA_RELEASE_REL), "# R36 (release)\n");
        let jetson = resolve_under(&root, ElfClass::native());
        let _ = std::fs::remove_dir_all(&root);
        let (Ok(desktop), Ok(g)) = (desktop, jetson) else {
            panic!("a synthetic root did not resolve");
        };
        let has = |libs: &[Library], name: &str| {
            libs.iter()
                .any(|l| l.path.file_name().is_some_and(|n| n == name))
        };
        assert!(
            !desktop.at_host_paths && !has(&desktop.libraries, "libcuda.so.1.1"),
            "without nv_tegra_release the desktop rule must apply (the positive control)"
        );
        assert!(g.at_host_paths, "a Jetson grant must keep NVIDIA's paths");
        assert!(
            has(&g.libraries, "libcuda.so.1.1"),
            "libcuda.so.1.1 is not in the grant: {:?}",
            g.libraries
        );
        let shared: Vec<String> = g
            .shared
            .iter()
            .map(|(p, _)| p.to_string_lossy().into_owned())
            .collect();
        for n in ["dev/nvhost-gpu", "dev/dri/card0", "dev/dri/card1"] {
            assert!(
                shared.iter().any(|p| p.ends_with(n)),
                "{n} missing (a pattern row?): {shared:?}"
            );
        }
        assert!(
            g.dirs.iter().any(|d| d.ends_with("dev/dri/by-path")),
            "the dir row is missing"
        );
        assert!(
            g.ldconfig_dirs.iter().all(|d| !d.ends_with("usr/sbin")),
            "an executable's directory reached the loader: {:?}",
            g.ldconfig_dirs
        );
        assert!(g
            .ldconfig_dirs
            .iter()
            .any(|d| d.ends_with("aarch64-linux-gnu/nvidia")));
        assert!(
            g.sysfs.iter().any(|d| d.ends_with("sys/devices/soc0")),
            "soc0 is not granted"
        );
        let planned =
            mount_plan_keeping_groups(&g, &GpuSelection::All, &caller(0, &[0]), Some("/usr/lib64"));
        let Ok(binds) = planned else {
            panic!("the Jetson grant did not plan: {planned:?}");
        };
        assert!(
            binds
                .iter()
                .any(|(src, dst, _)| src == dst && dst.ends_with("nvidia/libcuda.so.1.1")),
            "libcuda was moved away from its host path: {binds:?}"
        );
    }

    /// ⛔ ON A JETSON, A LISTED NODE THE CALLER CANNOT OPEN IS LEFT OUT, AND A NODE REACHED THROUGH A
    /// GROUP IS THE BOX'S MAP'S QUESTION. A user in `video` and not in `debug` was refused the whole
    /// GPU over 13 debugger nodes, and then refused again with the `--no-uid-range` the message
    /// recommended. If NO listed node can be opened, the grant is still refused.
    #[test]
    fn listed_nodes_the_caller_cannot_open_are_left_out_and_groups_follow_the_map() {
        let grant = |shared: Vec<(PathBuf, NodeFacts)>| {
            let listed_nodes = shared.iter().map(|(p, _)| p.clone()).collect();
            GpuGrant {
                driver_version: "540.4.0".into(),
                shared,
                // A Jetson has its card node too (`/dev/nvidia0`, measured).
                cards: vec![CardNodes {
                    index: 0,
                    pci_address: None,
                    nodes: Vec::new(),
                }],
                libraries: Vec::new(),
                symlinks: Vec::new(),
                ldconfig_dirs: Vec::new(),
                tools: Vec::new(),
                configs: Vec::new(),
                dirs: Vec::new(),
                at_host_paths: true,
                sysfs: Vec::new(),
                listed_nodes,
            }
        };
        let g = grant(vec![
            (PathBuf::from("/dev/nvhost-gpu"), plain(0, 44, 0o20660)),
            (PathBuf::from("/dev/nvhost-dbg-gpu"), plain(0, 77, 0o20660)),
        ]);
        let in_video = caller(1000, &[1000, 44]);
        let enforced = mount_plan(&g, &GpuSelection::All, &in_video);
        assert!(
            matches!(enforced, Err(MountPlanError::GroupsNeeded { .. })),
            "a group-only node must refuse a box that drops its groups: {enforced:?}"
        );
        let kept = mount_plan_keeping_groups(&g, &GpuSelection::All, &in_video, None);
        let Ok(binds) = kept else {
            panic!("a box that keeps its groups was refused: {kept:?}");
        };
        let targets: Vec<&str> = binds.iter().map(|(_, d, _)| d.as_str()).collect();
        assert!(
            targets.contains(&"/dev/nvhost-gpu"),
            "the GPU node is missing: {targets:?}"
        );
        assert!(
            !targets.contains(&"/dev/nvhost-dbg-gpu"),
            "the debug node nobody can open was bound"
        );
        let nobody = caller(1000, &[1000]);
        assert!(
            mount_plan_keeping_groups(&g, &GpuSelection::All, &nobody, None).is_err(),
            "with no listed node openable the grant must still be refused"
        );
    }

    /// Shell-style patterns as NVIDIA's lists write them, and the bare UUID a Jetson prints.
    #[test]
    fn csv_patterns_and_bare_uuids_are_read_as_written() {
        assert!(wildcard_match("card*", "card0") && wildcard_match("renderD*", "renderD128"));
        assert!(wildcard_match("lib?.so", "libx.so") && !wildcard_match("card*", "renderD128"));
        assert!(!wildcard_match("card*", "xcard0") && wildcard_match("*", ""));
        assert!(bare_uuid("ED5C5BA5-ABEF-55DD-9C02-71B8EBDAE1D8"));
        assert!(
            !bare_uuid("GPU-ED5C5BA5")
                && !bare_uuid("0")
                && !bare_uuid("ED5C5BA5-ABEF-55DD-9C02-71B8EBDAE1DZ")
        );
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
    /// THE `capabilities=` TOKEN NVIDIA'S OWN DOCUMENTATION PRINTS is accepted, and said out loud.
    ///
    /// MEASURED 2026-11-12: `--gpus 'all,"capabilities=compute,utility"'`, which
    /// docs.nvidia.com prints for Docker, was refused with "`all` and anything beside it name
    /// different things and only one can be true" - a contradiction that is not there, and a
    /// message naming nothing the caller wrote.
    #[test]
    fn the_capabilities_token_is_accepted_and_reported_rather_than_refused() {
        let root = std::env::temp_dir().join(format!("kern-gpu-caps-{}", std::process::id()));
        // NO DRIVER UNDER THIS ROOT ON PURPOSE: these cases carry no UUID, so nothing here should
        // read the filesystem at all, and a root with nothing in it proves it.
        let _ = std::fs::create_dir_all(&root);

        // THE QUOTING IS DOCKER'S: the shell removes the single quotes and the doubles arrive.
        assert_eq!(
            selection_from_spec(&root, "all,\"capabilities=compute,utility\""),
            Ok(Some(GpuSelection::All))
        );
        assert_eq!(
            selection_from_spec(&root, "device=0,\"capabilities=compute\""),
            Ok(Some(GpuSelection::These(vec![0])))
        );
        // A single capability needs no quotes, and a comma-bearing one must not be split.
        assert_eq!(
            selection_from_spec(&root, "all,capabilities=compute"),
            Ok(Some(GpuSelection::All))
        );
        let note = capabilities_note("all,\"capabilities=compute,utility\"")
            .expect("the token must be reported");
        assert!(note.contains("compute,utility"), "{note}");
        assert!(
            note.contains("binds the driver's whole library set"),
            "the note must say why nothing is missing: {note}"
        );
        // AND SILENCE WHERE THERE IS NO TOKEN, on every other shape, or the note becomes noise on
        // every GPU box.
        for quiet in ["all", "2", "count=2", "device=0,1", "\"device=0,2\""] {
            assert_eq!(
                capabilities_note(quiet),
                None,
                "{quiet} is not a capability"
            );
        }

        // THE QUOTE-AWARE SPLIT, which is what makes the above work: a comma inside quotes is part
        // of the value, and `"device=0,2"` must stay ONE token.
        assert_eq!(
            comma_tokens("\"device=0,2\""),
            vec!["device=0,2".to_string()]
        );
        assert_eq!(
            comma_tokens("all,\"capabilities=compute,utility\""),
            vec![
                "all".to_string(),
                "capabilities=compute,utility".to_string()
            ]
        );
        // AND THE GRAMMAR IS UNTOUCHED for the shape Docker documents with the whole value quoted:
        // this host's own measurement of `--gpus '"device=0,1"'` is two cards.
        assert_eq!(
            selection_from_spec(&root, "\"device=0,1\""),
            Ok(Some(GpuSelection::These(vec![0, 1])))
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A GPU UUID RESOLVES TO THE CARD THE DRIVER GIVES IT, which is a shape Docker documents
    /// (`device_ids: ["GPU-ebc4a5d2"]`) and this flag refused until 2026-11-12 with
    /// `not a card index`, on a host where the CDI path resolved the same UUID from the same files.
    #[test]
    fn a_gpu_uuid_in_a_spec_resolves_to_its_card_and_an_unknown_one_names_what_is_here() {
        let root = std::env::temp_dir().join(format!("kern-gpu-uuid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // TWO CARDS WITH THE NUMBERS CROSSED, so a resolver that answers with the directory's
        // order, or always with zero, fails here. `0000:06:00.0` sorts second and carries minor 0.
        for (addr, uuid, minor) in [
            ("0000:01:00.0", "GPU-aaaaaaaa-1111", 1),
            ("0000:06:00.0", "GPU-bbbbbbbb-2222", 0),
        ] {
            let dir = root.join("proc/driver/nvidia/gpus").join(addr);
            std::fs::create_dir_all(&dir).expect("gpus dir");
            std::fs::write(
                dir.join("information"),
                format!("Model: \t NVIDIA Test\nGPU UUID: \t {uuid}\nDevice Minor: \t {minor}\n"),
            )
            .expect("information");
        }

        assert_eq!(
            selection_from_spec(&root, "device=GPU-aaaaaaaa-1111"),
            Ok(Some(GpuSelection::These(vec![1]))),
            "the UUID must resolve to the minor the driver published, not to the directory order"
        );
        // CASE-INSENSITIVE, because `nvidia-smi` prints lower case and a file may carry either.
        assert_eq!(
            selection_from_spec(&root, "device=gpu-bbbbbbbb-2222"),
            Ok(Some(GpuSelection::These(vec![0])))
        );
        // MIXED, which is the shape a file ends up with when one card is pinned by UUID.
        assert_eq!(
            selection_from_spec(&root, "device=0,GPU-aaaaaaaa-1111"),
            Ok(Some(GpuSelection::These(vec![0, 1])))
        );
        // UNKNOWN, with what the host DOES publish, sorted so the message is stable.
        match selection_from_spec(&root, "device=GPU-nope") {
            Err(GpuSpecError::UnknownUuid { given, known }) => {
                assert_eq!(given, "GPU-nope");
                assert_eq!(
                    known,
                    vec![
                        "GPU-aaaaaaaa-1111".to_string(),
                        "GPU-bbbbbbbb-2222".to_string()
                    ]
                );
            }
            other => panic!("expected UnknownUuid, got {other:?}"),
        }
        // THE GRAMMAR IS UNTOUCHED where no UUID appears: these must answer exactly as the pure
        // parser does, so the wrapper cannot become a second grammar.
        for spec in ["all", "2", "count=2", "device=0,1", "0", ""] {
            assert_eq!(
                selection_from_spec(&root, spec),
                parse_gpu_spec(spec).map(Some),
                "the wrapper changed the answer for {spec:?}"
            );
        }
        // ⛔ THE THREE WORDS THAT MEAN NO CARD. Measured against docker 29.1.3 on a two-card host:
        // `--gpus '"device=none"'` and `device=void` run the container with 0 nodes, while
        // `device=nonsense` and `device=99` are refused by docker itself. They are sentinels, not
        // garbage, and kern answered "not a card index" to all four.
        for none in [
            "device=none",
            "device=void",
            "gpu=none",
            "DEVICE=NONE",
            "\"device=none\"",
        ] {
            assert_eq!(
                selection_from_spec(&root, none),
                Ok(None),
                "{none:?} asks for no card"
            );
            assert!(asks_for_no_gpu(none), "{none:?}");
            assert!(
                describe_no_gpu(none).contains("NO card"),
                "the sentence must say what happened: {}",
                describe_no_gpu(none)
            );
        }
        // AND NOT THE ONES DOCKER REFUSES, or kern would swallow a typo docker catches.
        for bad in ["device=nonsense", "device=99", "device=no", "none", "void"] {
            assert!(
                !asks_for_no_gpu(bad),
                "{bad:?} is not one of docker's sentinels"
            );
        }
        // AND A BARE UUID WITH NO `device=` IS NOT REWRITTEN: inventing that spelling would accept
        // a shape neither runtime does.
        assert_eq!(
            selection_from_spec(&root, "GPU-aaaaaaaa-1111"),
            parse_gpu_spec("GPU-aaaaaaaa-1111").map(Some)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

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
            let _ = fixture_node(&root.join("dev").join(name));
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
            let _ = fixture_node(&root.join("dev/dri").join(name));
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
    /// THE GRAMMAR IS DOCKER'S, and every row of this test was measured against docker 29.1.3 on
    /// a two-card host before it was written here.
    ///
    /// | written            | docker gave            | so kern gives |
    /// |--------------------|------------------------|---------------|
    /// | `all`, `count=all` | nvidia0 nvidia1        | every card    |
    /// | `2`, `count=2`     | nvidia0 nvidia1        | any two       |
    /// | `1`                | nvidia0                | any one       |
    /// | `device=1`         | nvidia1                | card 1        |
    /// | `"device=0,1"`     | nvidia0 nvidia1        | cards 0 and 1 |
    /// | `device=0,1`       | a usage error          | cards 0 and 1 |
    /// | `0`                | NOTHING, and it ran    | refused       |
    ///
    /// The last two rows are the only places kern is not identical, and both are deliberate: the
    /// unquoted list is a superset, because kern takes one argv token and has no comma problem to
    /// solve; and `0` is refused because its two readings, docker's "no gpus" and this project's
    /// own "card 0", are both plausible and guessing costs a workload its first CUDA call.
    #[test]
    fn the_gpus_spec_reads_docker_grammar_a_count_an_index_or_all() {
        for (good, want) in [
            ("2", GpuSelection::Count(2)),
            ("1", GpuSelection::Count(1)),
            ("7", GpuSelection::Count(7)),
            ("count=2", GpuSelection::Count(2)),
            (" 3 ", GpuSelection::Count(3)),
            ("device=1", GpuSelection::These(vec![1])),
            ("gpu=3", GpuSelection::These(vec![3])),
            ("device=0,1", GpuSelection::These(vec![0, 1])),
            // ORDER IS THE CALLER'S. Nothing downstream reads meaning into which came first, and
            // reordering their input is a liberty this parser has no reason to take.
            ("device=1,0", GpuSelection::These(vec![1, 0])),
            ("gpu=3,1,2", GpuSelection::These(vec![3, 1, 2])),
            ("device= 0 , 1 ", GpuSelection::These(vec![0, 1])),
            // The quotes a docker example carries inside its value. Stripped so a pasted command
            // works as written.
            ("\"device=0,1\"", GpuSelection::These(vec![0, 1])),
            ("\"all\"", GpuSelection::All),
            ("all", GpuSelection::All),
            ("ALL", GpuSelection::All),
            ("count=all", GpuSelection::All),
            // `device=all` IS EVERY CARD, measured against docker 29.1.3 on a two-card host:
            // `docker run --gpus device=all alpine ls /dev/nvidia[0-9]*` answers
            // `/dev/nvidia0 /dev/nvidia1`, the same as `--gpus all`. kern refused it with "not a
            // card index", and the form is printed in NVIDIA's and Triton's own pages.
            ("device=all", GpuSelection::All),
            ("device=ALL", GpuSelection::All),
            ("gpu=all", GpuSelection::All),
            ("\"device=all\"", GpuSelection::All),
            // `-1` is the Docker API's "all", which is what `docker compose` writes: measured,
            // `count: -1` on compose v5.0.2 handed the container both cards of a two-card host.
            ("-1", GpuSelection::All),
            ("count=-1", GpuSelection::All),
        ] {
            assert_eq!(parse_gpu_spec(good), Ok(want), "{good:?}");
        }
        assert_eq!(parse_gpu_spec(""), Err(GpuSpecError::Empty));
        assert_eq!(parse_gpu_spec("   "), Err(GpuSpecError::Empty));
        assert_eq!(parse_gpu_spec("0"), Err(GpuSpecError::ZeroIsAmbiguous));
        assert_eq!(
            parse_gpu_spec("count=0"),
            Err(GpuSpecError::ZeroIsAmbiguous)
        );
        // `all` BESIDE ANYTHING is refused rather than resolved either way: whichever way it went,
        // half of what the caller wrote would be discarded in silence.
        // ⛔ `all` FIRST INSIDE THE LIST IS ITS OWN CASE. The check that catches a bare `all`
        // beside indices reads the WHOLE value and splits it on commas, so `device=0,all` has a
        // token that trims to `all` and `device=all,0` does not: its first token is `device=all`.
        // Deleting the guard inside the `device=` branch left this test green until these two rows
        // were added, which is the test being wrong rather than the branch being dead.
        for mixed in [
            "all,1",
            "2,all",
            "device=0,all",
            "device=all,0",
            "gpu=all,1",
        ] {
            match parse_gpu_spec(mixed) {
                Err(GpuSpecError::AllWithMore { given }) => assert_eq!(given, mixed),
                other => panic!("{mixed:?} should be AllWithMore, got {other:?}"),
            }
        }
        // THE SAME CARD TWICE is refused, not deduplicated.
        for (dup, index) in [("device=0,0", 0), ("gpu=1,2,1", 1)] {
            match parse_gpu_spec(dup) {
                Err(GpuSpecError::Duplicate { index: got }) => assert_eq!(got, index, "{dup:?}"),
                other => panic!("{dup:?} should be Duplicate, got {other:?}"),
            }
        }
        // A bare value that is not a number is a COUNT that failed, and the message has to say so:
        // telling a caller "not a card index" would point them at `device=` when what they wrote
        // was in the count position.
        // ⛔ `-1` LEFT THIS LIST on 2026-11-12: it is the Docker API's convention for "all", and
        // `docker compose` v5.0.2 resolves `count: -1` to every card (measured on a two-card host),
        // so a file docker runs was dying here. `-2` and the rest stay refused.
        for bad in ["x", "first", "2.5", "-2", "0x1", "count=x", "count="] {
            match parse_gpu_spec(bad) {
                Err(GpuSpecError::NotACount { given }) => assert_eq!(given, bad.trim()),
                other => panic!("{bad:?} should be NotACount, got {other:?}"),
            }
        }
        // Inside `device=` the position IS an index, so the same garbage gets the other message.
        // An empty element quotes the WHOLE value: on its own it reads as "" and says nothing.
        for bad in [
            "device=",
            "gpu=x",
            "device=0,",
            "device=,0",
            "device=0,,1",
            "device=-1",
        ] {
            match parse_gpu_spec(bad) {
                Err(GpuSpecError::NotAnIndex { given }) => assert_eq!(given, bad.trim()),
                other => panic!("{bad:?} should be NotAnIndex, got {other:?}"),
            }
        }
    }

    /// The two edges where a digit check usually breaks, in BOTH positions the grammar has.
    ///
    /// `u32::MAX` must PARSE and then be refused later for not existing, because those are two
    /// different answers and the caller is owed the right one: "this host has 2 card(s), fewer
    /// than the 4294967295 asked for" tells them to look at their number, "not a number of cards"
    /// tells them to look at their spelling. One past the top is a spelling problem and reaches
    /// `parse` rather than the digit filter.
    ///
    /// The count position and the index position give DIFFERENT errors for the same garbage, and
    /// that is the point of testing both: a caller who wrote `2x` was counting and one who wrote
    /// `device=2x` was naming, and sending either to the other's message sends them to the wrong
    /// half of their command.
    #[test]
    fn the_spec_holds_at_the_top_of_u32_in_both_positions() {
        assert_eq!(
            parse_gpu_spec("4294967295"),
            Ok(GpuSelection::Count(u32::MAX))
        );
        assert_eq!(
            parse_gpu_spec("count=4294967295"),
            Ok(GpuSelection::Count(u32::MAX))
        );
        assert_eq!(
            parse_gpu_spec("device=4294967295"),
            Ok(GpuSelection::These(vec![u32::MAX]))
        );
        for over in ["4294967296", "99999999999999999999"] {
            match parse_gpu_spec(over) {
                Err(GpuSpecError::NotACount { given }) => assert_eq!(given, over),
                other => panic!("{over:?} is past u32 and must not count, got {other:?}"),
            }
        }
        for over in ["device=4294967296", "gpu=99999999999999999999"] {
            match parse_gpu_spec(over) {
                Err(GpuSpecError::NotAnIndex { given }) => assert_eq!(given, over),
                other => panic!("{over:?} is past u32 and must not index, got {other:?}"),
            }
        }
        // FULLWIDTH ZERO, U+FF10, then Arabic-Indic and Devanagari. `char::is_numeric` answers
        // true for all three where `is_ascii_digit` does not.
        //
        // MEASURED, because the obvious claim about this is wrong: swapping either filter to
        // `is_numeric` leaves every assertion here green, since `parse::<u32>` refuses a
        // non-ASCII digit on its own and returns the SAME error. So this pins the behaviour a
        // caller sees, not which of the two guards catches it, and the ASCII filter earns its
        // place by rejecting earlier rather than by rejecting more.
        for wide in ["\u{FF10}", "\u{0660}", "\u{0966}", "2\u{FF10}"] {
            match parse_gpu_spec(wide) {
                Err(GpuSpecError::NotACount { given }) => assert_eq!(given, wide),
                other => panic!("{wide:?} is not an ASCII count, got {other:?}"),
            }
        }
        for wide in ["device=\u{FF10}", "gpu=0,\u{0660}"] {
            match parse_gpu_spec(wide) {
                Err(GpuSpecError::NotAnIndex { given }) => assert_eq!(given, wide),
                other => panic!("{wide:?} is not an ASCII index, got {other:?}"),
            }
        }
        // Leading zeros name the same thing and are not a spelling error.
        assert_eq!(parse_gpu_spec("02"), Ok(GpuSelection::Count(2)));
        assert_eq!(
            parse_gpu_spec("device=0000000001"),
            Ok(GpuSelection::These(vec![1]))
        );
    }

    /// A grant with two cards, used by the mount-plan tests. The nodes carry the FACTS the policy
    /// turns on, so a test produces a refusal by building a gated node rather than by handing the
    /// grant a verdict: there is one policy function and the tests go through it like everything
    /// else does.
    /// The address the box's `/proc` mask keeps comes from the CARD, never from its index.
    ///
    /// The fixture numbers them against each other on purpose, the way this host does: card 0 is
    /// `0000:06:00.0`. A mask that formed the address from the index would keep the other card's
    /// directory and hide the granted one, and on a host whose two numberings agreed, or on a
    /// fixture that copied the index into the address, it would pass.
    #[test]
    fn the_masked_addresses_follow_the_cards_and_not_their_indices() {
        let grant = two_card_grant(plain(0, 0, 0o666));
        let these = |v: Vec<u32>| GpuSelection::These(v);
        assert_eq!(
            pci_addresses_of(&grant, &these(vec![0])),
            Some(vec!["0000:06:00.0".to_string()])
        );
        assert_eq!(
            pci_addresses_of(&grant, &these(vec![1])),
            Some(vec!["0000:01:00.0".to_string()])
        );
        // TWO CARDS KEEP TWO DIRECTORIES, in the order they were asked for. A mask that kept one
        // would leave a box holding two cards able to see only one of them in the driver's own
        // listing, which is a shape a reader would trust and should not.
        assert_eq!(
            pci_addresses_of(&grant, &these(vec![0, 1])),
            Some(vec!["0000:06:00.0".to_string(), "0000:01:00.0".to_string()])
        );
        assert_eq!(
            pci_addresses_of(&grant, &these(vec![1, 0])),
            Some(vec!["0000:01:00.0".to_string(), "0000:06:00.0".to_string()])
        );
        // `all` RESOLVES HERE AND NOWHERE ELSE, to every card the grant lists.
        assert_eq!(
            pci_addresses_of(&grant, &GpuSelection::All),
            Some(vec!["0000:06:00.0".to_string(), "0000:01:00.0".to_string()])
        );
        // `None` IS "CANNOT BE NAMED", AND IT IS NOT "NAMES NOTHING". The two used to be one empty
        // vector, and the cost of collapsing them was the whole mask: the caller could not tell a
        // box that was granted no card, which may see none, from a grant whose addresses did not
        // resolve, which must see the host's listing rather than lose its own card. A selection
        // `mount_plan` refuses never reaches the mask anyway; if one ever did, it is the second case.
        assert_eq!(pci_addresses_of(&grant, &these(vec![2])), None);
        assert_eq!(pci_addresses_of(&grant, &these(vec![u32::MAX])), None);
        assert_eq!(pci_addresses_of(&grant, &these(vec![0, 9])), None);

        // AND A CARD THE DRIVER PUBLISHED NO ADDRESS FOR TAKES THE WHOLE ANSWER WITH IT, rather
        // than contributing nothing to a list the caller then trusts. The earlier version
        // `filter_map`ped it away, so a two-card grant with one unreadable `information` file was
        // masked down to the other card: a box holding two cards, shown one, with nothing in it
        // able to tell that from a card that failed later.
        let mut partial = two_card_grant(plain(0, 0, 0o666));
        partial.cards[1].pci_address = None;
        assert_eq!(
            pci_addresses_of(&partial, &these(vec![0])),
            Some(vec!["0000:06:00.0".to_string()]),
            "the card that DOES have an address is still named when it is the only one asked for"
        );
        assert_eq!(
            pci_addresses_of(&partial, &these(vec![0, 1])),
            None,
            "but a selection containing the nameless card cannot be masked at all"
        );
        assert_eq!(pci_addresses_of(&partial, &GpuSelection::All), None);
    }

    fn two_card_grant(card0: NodeFacts) -> GpuGrant {
        GpuGrant {
            driver_version: "580.173.02".to_string(),
            shared: vec![
                (PathBuf::from("/dev/nvidiactl"), plain(0, 0, 0o666)),
                (PathBuf::from("/dev/nvidia-uvm"), plain(0, 0, 0o666)),
            ],
            cards: vec![
                // THE ADDRESSES ARE NOT IN INDEX ORDER, deliberately: `0000:06:00.0` belongs to
                // card 0 here. A mask that derived the address from the index instead of carrying
                // it would hide the granted card and show the other one, and on a fixture whose
                // numbering agreed it would pass.
                CardNodes {
                    index: 0,
                    pci_address: Some("0000:06:00.0".to_string()),
                    nodes: vec![(PathBuf::from("/dev/nvidia0"), card0)],
                },
                CardNodes {
                    index: 1,
                    pci_address: Some("0000:01:00.0".to_string()),
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
            tools: Vec::new(),
            configs: Vec::new(),
            dirs: Vec::new(),
            at_host_paths: false,
            sysfs: Vec::new(),
            listed_nodes: BTreeSet::new(),
        }
    }

    /// ONE card, and the shared nodes with it. Leaving a shared node out is not a smaller grant,
    /// it is a broken one: S0 measured that a box without `nvidiactl` answers `100` and a box
    /// without `nvidia-uvm` answers `999`.
    #[test]
    fn the_mount_plan_takes_one_card_and_every_shared_node() {
        let grant = two_card_grant(plain(0, 0, 0o666));
        let Ok(binds) = mount_plan(
            &grant,
            &GpuSelection::These(vec![0]),
            &caller(1000, &[1000]),
        ) else {
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
        let Ok(binds) = mount_plan(
            &grant,
            &GpuSelection::These(vec![1]),
            &caller(1000, &[1000]),
        ) else {
            panic!("expected a plan for card 1");
        };
        let targets: Vec<&str> = binds.iter().map(|(_, t, _)| t.as_str()).collect();
        assert!(targets.contains(&"/dev/nvidia1"), "{targets:?}");
        assert!(!targets.contains(&"/dev/nvidia0"), "{targets:?}");
    }

    /// TWO CARDS ARE ONE REQUEST, and the shared nodes are still mounted once.
    ///
    /// The shared set (`nvidiactl`, `nvidia-uvm`, and the rest) goes with ANY card, so a plan built
    /// by concatenating per-card plans would bind each of them as many times as there are cards.
    /// Two binds onto the same target is not an error the kernel reports: the second simply
    /// shadows the first, and the only sign of it is a mount table twice the size it should be.
    #[test]
    fn two_cards_are_granted_together_and_the_shared_nodes_are_bound_once() {
        let grant = two_card_grant(plain(0, 0, 0o666));
        for selection in [
            GpuSelection::These(vec![0, 1]),
            GpuSelection::These(vec![1, 0]),
            GpuSelection::All,
        ] {
            let Ok(binds) = mount_plan(&grant, &selection, &caller(1000, &[1000])) else {
                panic!("expected a plan for {selection:?}");
            };
            let targets: Vec<&str> = binds.iter().map(|(_, t, _)| t.as_str()).collect();
            assert!(
                targets.contains(&"/dev/nvidia0"),
                "{selection:?}: {targets:?}"
            );
            assert!(
                targets.contains(&"/dev/nvidia1"),
                "{selection:?}: {targets:?}"
            );
            for shared in ["/dev/nvidiactl", "/dev/nvidia-uvm"] {
                assert_eq!(
                    targets.iter().filter(|t| **t == shared).count(),
                    1,
                    "{shared} bound more than once for {selection:?}: {targets:?}"
                );
            }
            // NO TARGET IS BOUND TWICE, whatever it is. The check above names the two shared nodes
            // because they are the ones a concatenating plan would duplicate; this one holds the
            // property for every path, including the libraries and the symlinks.
            let mut seen = targets.clone();
            seen.sort_unstable();
            let before = seen.len();
            seen.dedup();
            assert_eq!(before, seen.len(), "a target repeats for {selection:?}");
        }
    }

    /// A SELECTION IS SATISFIED WHOLE OR REFUSED WHOLE.
    ///
    /// `--gpus device=0,9` on a two-card host is a request for a card that is not there, and
    /// honest answer is a refusal naming the indices that exist. Granting the half that is
    /// reachable would hand back a box with fewer cards than the command named, and nothing
    /// inside it could tell that from a card that failed later.
    #[test]
    fn a_selection_naming_a_card_that_is_not_here_is_refused_whole() {
        let grant = two_card_grant(plain(0, 0, 0o666));
        for selection in [
            GpuSelection::These(vec![0, 9]),
            GpuSelection::These(vec![9, 0]),
            GpuSelection::These(vec![9]),
        ] {
            match mount_plan(&grant, &selection, &caller(1000, &[1000])) {
                Err(MountPlanError::NoSuchCard { wanted, present }) => {
                    assert_eq!(wanted, 9, "{selection:?}");
                    assert_eq!(present, vec![0, 1], "{selection:?}");
                }
                other => panic!("{selection:?} must be refused, got {other:?}"),
            }
        }
    }

    /// `all` ON A HOST WITH NO CARD is the same disappointment as naming one that is not there,
    /// and gets the same refusal rather than an empty plan.
    ///
    /// An empty plan would start the box with no GPU and no error, which is the "runs and lies"
    /// outcome: the workload meets its first CUDA call and has no way to learn that the flag it
    /// passed did nothing.
    #[test]
    fn all_on_a_host_with_no_card_is_refused_rather_than_granting_nothing() {
        let mut grant = two_card_grant(plain(0, 0, 0o666));
        grant.cards.clear();
        match mount_plan(&grant, &GpuSelection::All, &caller(1000, &[1000])) {
            Err(MountPlanError::NoSuchCard { present, .. }) => assert!(present.is_empty()),
            other => panic!("all with no cards must be refused, got {other:?}"),
        }
    }

    /// Libraries and links are READ-ONLY, device nodes are not. A read-only device node would
    /// break the driver's own ioctls; a writable host library is a write into the host.
    #[test]
    fn libraries_are_read_only_and_nodes_are_not() {
        let grant = two_card_grant(plain(0, 0, 0o666));
        let Ok(binds) = mount_plan(
            &grant,
            &GpuSelection::These(vec![0]),
            &caller(1000, &[1000]),
        ) else {
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
        let Ok(binds) = mount_plan(
            &grant,
            &GpuSelection::These(vec![0]),
            &caller(1000, &[1000]),
        ) else {
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
        match mount_plan(
            &grant,
            &GpuSelection::These(vec![7]),
            &caller(1000, &[1000]),
        ) {
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
        match mount_plan(&grant, &GpuSelection::These(vec![0]), &who) {
            Err(MountPlanError::GroupsNeeded { gids, nodes }) => {
                assert_eq!(gids, vec![44]);
                assert_eq!(nodes, vec![PathBuf::from("/dev/nvidia0")]);
            }
            other => panic!("expected GroupsNeeded, got {other:?}"),
        }

        // And a node the caller cannot open at all, with or without groups.
        let grant = two_card_grant(plain(0, 0, 0o600));
        match mount_plan(&grant, &GpuSelection::These(vec![0]), &who) {
            Err(MountPlanError::Unreachable { nodes }) => {
                assert_eq!(nodes, vec![PathBuf::from("/dev/nvidia0")]);
            }
            other => panic!("expected Unreachable, got {other:?}"),
        }
    }

    /// A GRANT MOUNTS CHARACTER DEVICES, AND ROOT IS NOT SUBJECT TO THE MODE.
    ///
    /// Two separate gaps in the same decision path. `node_facts` used `std::fs::metadata`, which
    /// FOLLOWS a symlink, with no check on the KIND, so a path named like a node and pointing at a
    /// regular file was described as that file, given an access verdict from its mode, and handed to
    /// the mount plan. And `access_path` computed the DAC check for uid 0, which the kernel skips:
    /// root carries `CAP_DAC_OVERRIDE` in the initial user namespace, so `sudo kern --gpus` was
    /// refused a node root can open.
    #[test]
    fn a_non_device_is_not_a_node_and_root_is_not_refused_by_a_mode() {
        let dir = std::env::temp_dir().join(format!("kern-nodekind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        if std::fs::create_dir_all(&dir).is_err() {
            eprintln!("skip: no writable temp dir");
            return;
        }

        // POSITIVE CONTROL FIRST: a character device IS a node, so every refusal below is the kind
        // being checked and not a function that answers nothing.
        let node = dir.join("nvidia0");
        if !fixture_node(&node) {
            eprintln!("skip: this kernel refused a whiteout, so no stand-in node can be made");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        assert!(
            node_facts(&node).is_some(),
            "a character device must read as a node"
        );

        // A REGULAR FILE IS NOT A NODE, which is what every synthetic fixture in this module used
        // to be: they were testing a shape the resolver never sees.
        let plain_file = dir.join("nvidia1");
        let _ = std::fs::write(&plain_file, b"not a device");
        assert!(
            node_facts(&plain_file).is_none(),
            "a regular file named like a node is not a node"
        );

        // A DIRECTORY IS NOT A NODE EITHER.
        let as_dir = dir.join("nvidia2");
        let _ = std::fs::create_dir_all(&as_dir);
        assert!(node_facts(&as_dir).is_none(), "a directory is not a node");

        // A SYMLINK TO A REGULAR FILE IS NOT A NODE, and this is the case `metadata` alone missed:
        // it follows the link and describes the target without asking what kind it is.
        let link_to_file = dir.join("nvidia3");
        let _ = std::os::unix::fs::symlink(&plain_file, &link_to_file);
        assert!(
            node_facts(&link_to_file).is_none(),
            "a symlink to a regular file is not a node"
        );

        // A SYMLINK TO A REAL NODE *IS* ONE, which is why the check follows rather than refusing
        // every link: a host whose `/dev/nvidia0` is a symlink to the real node is a host kern
        // should still work on.
        let link_to_node = dir.join("nvidia4");
        let _ = std::os::unix::fs::symlink(&node, &link_to_node);
        assert!(
            node_facts(&link_to_node).is_some(),
            "a symlink to a character device is still a node"
        );

        // ROOT IS NOT SUBJECT TO THE MODE. `0o000` owned by somebody else is `Unreachable` for an
        // ordinary caller and reachable for root, because the arithmetic in `access_path` is the
        // DAC check and root skips it.
        let shut = NodeFacts {
            uid: 4242,
            gid: 4242,
            mode: 0o000,
            acl: None,
        };
        assert_eq!(
            access_path(&shut, &caller(1000, &[1000])),
            AccessPath::Unreachable,
            "an ordinary caller cannot open a 0o000 node"
        );
        let as_root = access_path(&shut, &caller(0, &[0]));
        assert_eq!(
            as_root,
            AccessPath::Owner,
            "root is not refused by a mode it overrides"
        );
        assert!(
            as_root.survives_a_box(),
            "and the verdict is uid-based, so it survives the loss of groups"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE LINKER CONFIGURATION PARSER, OVER THE FORMS GLIBC ACCEPTS AND IT DID NOT.
    ///
    /// Four defects, each failing SILENTLY: the line was consumed and nothing was included, so the
    /// library sweep answered a smaller number with no sign that a directory had been missed. On
    /// this host they were invisible because every directory the sweep needs is already a default,
    /// which is exactly why they need a synthetic root.
    ///
    ///   * `include` was matched as `"include "`, one space, so `include<TAB>/a/*.conf` was read as
    ///     a DIRECTORY whose name begins `include\t`. glibc skips any run of whitespace.
    ///   * the remainder was taken as ONE pattern, so `include /a/*.conf /b/*.conf` found only the
    ///     first. glibc reads a list.
    ///   * `..` was rewritten rather than refused: `trim_start_matches('/')` makes a path relative
    ///     to the root and a `..` climbs straight back out, which on a synthetic root means reading
    ///     the real host's files.
    ///   * nothing bounded the BREADTH. `MAX_LD_CONF_DEPTH` bounds nesting; a file whose glob
    ///     matches N files each including N more is N^depth reads, and two files that include each
    ///     other are re-read at every level.
    #[test]
    fn the_linker_config_reads_every_form_glibc_accepts_and_refuses_the_escape() {
        let root = std::env::temp_dir().join(format!("kern-ldconf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        if std::fs::create_dir_all(root.join("etc/ld.so.conf.d")).is_err() {
            eprintln!("skip: no writable temp dir");
            return;
        }
        for d in ["aa", "bb", "tabbed", "listed"] {
            let _ = std::fs::create_dir_all(root.join("opt").join(d));
        }
        let conf = root.join("etc/ld.so.conf");

        // A TAB AFTER `include`, which is the form that read as a directory name.
        let _ = std::fs::write(&conf, "include\t/etc/ld.so.conf.d/*.conf\n");
        let _ = std::fs::write(root.join("etc/ld.so.conf.d/t.conf"), "/opt/tabbed\n");
        assert!(
            linker_dirs(&root).contains(&root.join("opt/tabbed")),
            "a tab after `include` must be whitespace, not part of a path"
        );

        // TWO PATTERNS ON ONE LINE, where only the first used to be read.
        let _ = std::fs::write(
            &conf,
            "include /etc/ld.so.conf.d/a-*.conf /etc/ld.so.conf.d/b-*.conf\n",
        );
        let _ = std::fs::write(root.join("etc/ld.so.conf.d/a-x.conf"), "/opt/aa\n");
        let _ = std::fs::write(root.join("etc/ld.so.conf.d/b-x.conf"), "/opt/bb\n");
        let dirs = linker_dirs(&root);
        assert!(
            dirs.contains(&root.join("opt/aa")),
            "the first pattern must still be read: {dirs:?}"
        );
        assert!(
            dirs.contains(&root.join("opt/bb")),
            "every pattern on the line must be read: {dirs:?}"
        );

        // `include` MUST BE A WORD. A directory called `included` is not a directive, and treating
        // it as one would drop a real directory.
        let _ = std::fs::create_dir_all(root.join("included/lib"));
        let _ = std::fs::write(&conf, "/included/lib\n");
        assert!(
            linker_dirs(&root).contains(&root.join("included/lib")),
            "`included/lib` is a directory, not an `include` directive"
        );

        // `..` IN AN INCLUDE PATTERN IS THE LOAD-BEARING HALF, and it took a sabotage to find out
        // which half was. An include pattern is used DIRECTLY as a file to read, so a `..` in one
        // reaches outside the root; a bare directory line goes through `canonical_dir_under`, which
        // drops every `ParentDir` component, so the escape never existed there and removing that
        // refusal changes no answer. Both refusals stay, and this case proves the one that matters:
        // a conf file OUTSIDE the root, whose content names a directory nothing else would add.
        let outside_conf =
            std::env::temp_dir().join(format!("kern-ldconf-out-{}.conf", std::process::id()));
        let _ = std::fs::write(&outside_conf, "/opt/from-outside\n");
        let _ = std::fs::create_dir_all(root.join("opt/from-outside"));
        if let Some(name) = outside_conf.file_name().and_then(|n| n.to_str()) {
            let _ = std::fs::write(&conf, format!("include ../{name}\n"));
            let dirs = linker_dirs(&root);
            assert!(
                !dirs.contains(&root.join("opt/from-outside")),
                "an include pattern climbed out of the root and its file was read: {dirs:?}"
            );
            // POSITIVE CONTROL: the SAME file inside the root IS read, so the refusal above is the
            // `..` and not the include machinery failing.
            let inside = root.join("etc/ld.so.conf.d/from-inside.conf");
            let _ = std::fs::write(&inside, "/opt/from-outside\n");
            let _ = std::fs::write(&conf, "include /etc/ld.so.conf.d/from-inside.conf\n");
            assert!(
                linker_dirs(&root).contains(&root.join("opt/from-outside")),
                "the same content inside the root must be read"
            );
            let _ = std::fs::remove_file(&inside);
        }
        let _ = std::fs::remove_file(&outside_conf);

        // AND NO RETURNED PATH CARRIES A `..`, for the directory-line half. Not `starts_with`,
        // which is COMPONENT-BASED and therefore blind here: `<root>/../../etc` starts with
        // `<root>` by that test, so the first version of this assertion passed with the escape
        // wide open.
        for line in [
            "include ../../etc/ld.so.conf.d/*.conf\n",
            "/../../../etc\n",
            "../../usr/lib\n",
        ] {
            let _ = std::fs::write(&conf, line);
            for dir in linker_dirs(&root) {
                // NOT `starts_with`, which is COMPONENT-BASED and therefore blind here:
                // `<root>/../../etc` starts with `<root>` by that test, so the first version of
                // this assertion passed with the escape wide open (found by sabotage). The
                // property is that no returned path carries a `..` at all, which is also what a
                // later `openat2(O_NOFOLLOW)` needs.
                assert!(
                    !dir.components()
                        .any(|c| c == std::path::Component::ParentDir),
                    "a `..` survived into a linker directory: {} from {line:?}",
                    dir.display()
                );
            }
        }

        // THE EXPONENTIAL, SIZED SO THAT IT IS VISIBLE. A two-file cycle terminates either way,
        // because `MAX_LD_CONF_DEPTH` bounds the nesting, so timing it proves nothing: that was the
        // first version of this case and the sabotage passed. The cost is BREADTH to the power of
        // the depth, so N files each including every other is N reads with the visited set and N^4
        // without it. 48 files is 48 reads against 5.3 million, which the clock can tell apart
        // without making the passing case slow.
        let _ = std::fs::remove_dir_all(root.join("etc/ld.so.conf.d"));
        let _ = std::fs::create_dir_all(root.join("etc/ld.so.conf.d"));
        const CYCLE: usize = 48;
        let every: String = (0..CYCLE)
            .map(|i| format!("include /etc/ld.so.conf.d/c{i}.conf\n"))
            .collect();
        for i in 0..CYCLE {
            let mut body = String::from("/opt/listed\n");
            body.push_str(&every);
            let _ = std::fs::write(root.join(format!("etc/ld.so.conf.d/c{i}.conf")), &body);
        }
        let _ = std::fs::write(&conf, &every);
        let started = std::time::Instant::now();
        let dirs = linker_dirs(&root);
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_secs(5),
            "{CYCLE} mutually-including files took {took:?}, so each was read once per path \
             through the graph instead of once"
        );
        assert!(
            dirs.contains(&root.join("opt/listed")),
            "the directory behind the cycle must still be found: {dirs:?}"
        );

        // AND THE DEFAULTS ARE ALWAYS THERE, which is the positive control: a parser that returned
        // nothing would satisfy the `..` assertion above.
        let _ = std::fs::write(&conf, "#only a comment\n");
        let dirs = linker_dirs(&root);
        assert!(
            !dirs.is_empty(),
            "the default library directories must always be returned"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A SYMLINK IS RESOLVED UNDER THE ROOT, OR IT IS NOT FOLLOWED AT ALL.
    ///
    /// Two call sites disagreed about the same question, and both were wrong in opposite
    /// directions. `canonical_dir_under` STOPPED on an absolute target, which left the symlink in
    /// its result, the exact shape it exists to remove. `libraries_under` FOLLOWED one with
    /// `std::fs::metadata`, wherever it pointed, and then recorded the LINK as the path to mount,
    /// which breaks the invariant `symlinks_for` enforces: the resolved file is bound at the link's
    /// own path, so a link recorded as a library would be bound over itself and fail O_NOFOLLOW.
    ///
    /// An absolute target is taken AGAINST THE ROOT, which is the correct resolution inside a root
    /// and the one that cannot escape. With the production root of `/` it is the identity, which is
    /// why nothing on this host changes: 29 libraries, 29 symlinks and 1 linker directory before
    /// and after.
    #[test]
    fn a_symlink_is_resolved_under_the_root_or_not_followed() {
        let root = std::env::temp_dir().join(format!("kern-links-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let real = root.join("usr/lib/x86_64-linux-gnu");
        if std::fs::create_dir_all(&real).is_err() {
            eprintln!("skip: no writable temp dir");
            return;
        }
        let outside = std::env::temp_dir().join(format!("kern-links-out-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&outside);
        // THE ESCAPED TARGET IS A VALID 64-BIT ELF, so if the link were followed it WOULD be
        // accepted: skipping it for being malformed would prove nothing about the root check.
        let mut escaped_elf = Vec::with_capacity(64);
        escaped_elf.extend_from_slice(&ELF_MAGIC);
        escaped_elf.push(ELF_CLASS_64);
        escaped_elf.extend_from_slice(&[0u8; 59]);
        let _ = std::fs::write(outside.join("escaped.so.1.2.3"), &escaped_elf);

        // AN ABSOLUTE SYMLINK IN A DIRECTORY PATH. `<root>/lib -> /usr/lib` is what a merged-usr
        // host has, and inside a root it means `<root>/usr/lib`.
        let _ = std::os::unix::fs::symlink("/usr/lib", root.join("lib"));
        let got = canonical_dir_under(&root, &root.join("lib/x86_64-linux-gnu"));
        assert_eq!(
            got, real,
            "an absolute link must resolve against the root, not be left in the result"
        );
        // AND NOT BY SUBSTRING. The first version of this assertion looked for `/lib/x86` in the
        // result, which the CORRECT answer contains (`usr/lib/x86_64-linux-gnu`), so it failed on a
        // passing fix. The link is `<root>/lib`, so the thing to assert is that the result does not
        // start there.
        assert!(
            !got.starts_with(root.join("lib")),
            "the symlink survived in the result: {}",
            got.display()
        );

        // A RELATIVE ONE STILL WORKS, which is the positive control: the change must not have
        // replaced one resolution with no resolution.
        let _ = std::os::unix::fs::symlink("usr", root.join("rel"));
        assert_eq!(
            canonical_dir_under(&root, &root.join("rel/lib/x86_64-linux-gnu")),
            real,
            "a relative link must still resolve"
        );

        // AN ABSOLUTE TARGET CANNOT REACH OUTSIDE, which is the security-relevant half and not an
        // escape to refuse: taken against the root, `/tmp/x` means `<root>/tmp/x`, so a link
        // pointing at a real directory outside becomes a DANGLING path inside. That is the correct
        // resolution and it is why absolute targets need no refusal of their own.
        let _ = std::os::unix::fs::symlink(&outside, root.join("abs-out"));
        let mut absolute = root.join("abs-out");
        assert!(
            follow_links_under(&root, &mut absolute),
            "an absolute target is resolved, not refused"
        );
        assert!(
            absolute.starts_with(&root),
            "an absolute target must land inside the root: {}",
            absolute.display()
        );
        assert!(
            !absolute.exists(),
            "and outside the root there is nothing for it to name: {}",
            absolute.display()
        );

        // A CHAIN THAT CLIMBS OUT WITH `..` IS REFUSED. Joining does not normalise, so the check is
        // on what the filesystem says the path really is.
        // ONE `..`, not two: the root is a direct child of the temp dir, so `../<sibling>` is the
        // climb that LANDS somewhere, and two would reach a path that does not exist, where the
        // check cannot distinguish a refusal from a dangling link. The first version of this used
        // two and the half SKIPPED, which is the outcome this project counts rather than ignores.
        let up = PathBuf::from("..").join(
            outside
                .file_name()
                .map(std::path::Path::new)
                .unwrap_or(std::path::Path::new("x")),
        );
        let _ = std::os::unix::fs::symlink(&up, root.join("escape"));
        let mut climbing = root.join("escape");
        if std::fs::canonicalize(root.join("escape")).is_ok_and(|p| !p.starts_with(&root)) {
            assert!(
                !follow_links_under(&root, &mut climbing),
                "a `..` chain that lands outside the root must not be followed"
            );
        } else {
            eprintln!("skip: the `..` target does not land outside here, so that half did not run");
        }

        // A LOOP IS BOUNDED. A filesystem permits one and an unbounded walk is a hang.
        let _ = std::os::unix::fs::symlink("b", root.join("a"));
        let _ = std::os::unix::fs::symlink("a", root.join("b"));
        let mut looping = root.join("a");
        let started = std::time::Instant::now();
        assert!(
            !follow_links_under(&root, &mut looping),
            "a loop must be refused rather than walked"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the loop was walked rather than bounded"
        );

        // AND A LIBRARY WHOSE NAME IS A LINK OUT OF THE ROOT IS SKIPPED, not recorded as the link.
        let _ = std::fs::write(root.join("etc/ld.so.conf"), b"/usr/lib/x86_64-linux-gnu\n");
        let _ = std::fs::create_dir_all(root.join("etc"));
        let _ = std::fs::write(root.join("etc/ld.so.conf"), b"/usr/lib/x86_64-linux-gnu\n");
        let _ = std::os::unix::fs::symlink(
            outside.join("escaped.so.1.2.3"),
            real.join("libescape.so.1.2.3"),
        );
        // A real file beside it, so the sweep has something to find and the emptiness below is the
        // escape being skipped rather than the sweep finding nothing.
        // A minimal 64-bit ELF: the magic, the class byte, and padding so a reader of the first
        // five bytes is never short. Same shape the other fixtures in this module build.
        let mut elf = Vec::with_capacity(64);
        elf.extend_from_slice(&ELF_MAGIC);
        elf.push(ELF_CLASS_64);
        elf.extend_from_slice(&[0u8; 59]);
        let _ = std::fs::write(real.join("libgood.so.1.2.3"), &elf);
        let found = libraries_under(&root, "1.2.3", ElfClass::Bits64);
        let names: Vec<String> = found
            .iter()
            .filter_map(|l| l.path.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        assert!(
            names.iter().any(|n| n == "libgood.so.1.2.3"),
            "the real library must be found, or this case proves nothing: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n == "libescape.so.1.2.3"),
            "a link out of the root must not be recorded as a library: {names:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// THE PLAN DESCRIBES THE SELECTION, NOT THE HOST'S INVENTORY.
    ///
    /// `render_plan` took no selection, so `kern box --plan --gpus device=0` printed every card's
    /// nodes and the reader had no way to tell which lines were about the box being planned. The
    /// parser also dropped `--gpus` on the `--plan` path entirely, so a box with NO GPU flag
    /// previewed the whole inventory as though it were getting one.
    ///
    /// AND THE LONG FORM HAD NO PRODUCTION CALLER, so the one thing an operator needs from a
    /// device preview was unreachable: the NAMES of the host paths they are authorising. Only the
    /// counts could be printed. The enum that chose between the two forms is gone, because once
    /// the plan printed the names its `Summary` variant had no caller either, which is the same
    /// smell with the sign reversed.
    #[test]
    fn the_plan_describes_the_cards_that_were_asked_for() {
        let grant = two_card_grant(plain(0, 0, 0o666));

        let one = render_plan(&grant, &GpuSelection::These(vec![0]));
        assert!(
            one.contains("1 of 2 card(s)"),
            "the count must say which part of the host this is: {one}"
        );
        assert!(
            one.contains("/dev/nvidia0"),
            "the chosen card's node: {one}"
        );
        assert!(
            !one.contains("/dev/nvidia1"),
            "a card nobody asked for must not be previewed: {one}"
        );
        // The shared nodes belong to any selection, so they ARE listed.
        assert!(one.contains("/dev/nvidiactl"), "{one}");
        // POSITIVE CONTROL: the other card alone, so the filter is the selection and not a
        // hard-coded index.
        let other = render_plan(&grant, &GpuSelection::These(vec![1]));
        assert!(other.contains("/dev/nvidia1"), "{other}");
        assert!(!other.contains("/dev/nvidia0"), "{other}");
        // And every card when every card is asked for.
        let all = render_plan(&grant, &GpuSelection::All);
        assert!(all.contains("2 of 2 card(s)"), "{all}");
        assert!(
            all.contains("/dev/nvidia0") && all.contains("/dev/nvidia1"),
            "{all}"
        );

        // THE PATHS ARE NAMED, which is what had no caller: only the counts were reachable. Both
        // are asserted, because a plan that lost its counts would be a different regression from
        // one that lost its paths.
        assert!(
            one.contains("libraries 1"),
            "the counts must survive beside the names: {one}"
        );
        assert!(
            one.contains("  lib /usr/lib/x86_64-linux-gnu/libcuda.so"),
            "the plan must name the library paths: {one}"
        );
        assert!(
            one.contains("  link /usr/lib/x86_64-linux-gnu/libcuda.so.1"),
            "the plan must name the symlinks it would create: {one}"
        );
        assert!(
            one.contains("  dir /usr/lib/x86_64-linux-gnu"),
            "the plan must name the linker directories: {one}"
        );
    }

    /// A REFUSAL READS THE SAME FROM `kern box` AND FROM `kern box --plan`.
    ///
    /// The four sentences lived inline in `box_run` and the preview had none, so the plan printed
    /// the `Debug` form of the same error: `NoSuchCard { wanted: 9, present: [0, 1] }`. A plan whose
    /// refusal reads differently from the launch's is a plan the reader cannot compare with what
    /// happens next.
    #[test]
    fn every_refusal_has_one_wording_for_both_surfaces() {
        let said = describe_mount_plan_error(&MountPlanError::NoSuchCard {
            wanted: 9,
            present: vec![0, 1],
        });
        assert!(said.contains("no card 9"), "{said}");
        assert!(said.contains("Present: 0, 1"), "{said}");
        assert!(!said.contains('{'), "the Debug form leaked: {said}");

        let empty = describe_mount_plan_error(&MountPlanError::NoSuchCard {
            wanted: 0,
            present: Vec::new(),
        });
        assert!(
            empty.contains("Present: none"),
            "an empty list must read as a word, not as nothing: {empty}"
        );

        let few = describe_mount_plan_error(&MountPlanError::TooFewCards {
            wanted: 4,
            present: vec![0, 1],
        });
        assert!(
            few.contains("2 card(s)") && few.contains("fewer than the 4"),
            "{few}"
        );

        // THE GROUP SENTENCE MUST NOT CARRY THE FLAT CLAIM. "a box carries no supplementary group"
        // is true of the ranged map only, and a single-uid box keeps them; that was corrected
        // elsewhere in this crate and repeating it here would put it back.
        let groups = describe_mount_plan_error(&MountPlanError::GroupsNeeded {
            gids: vec![44],
            nodes: vec![PathBuf::from("/dev/dri/card0")],
        });
        assert!(groups.contains("on the default map"), "{groups}");
        assert!(
            groups.contains("--no-uid-range"),
            "the lever is not named: {groups}"
        );
        assert!(
            groups.contains("all or nothing"),
            "the price is not named: {groups}"
        );

        let dead = describe_mount_plan_error(&MountPlanError::Unreachable {
            nodes: vec![PathBuf::from("/dev/nvidia0")],
        });
        assert!(dead.contains("cannot open /dev/nvidia0"), "{dead}");
    }

    /// A NODE REACHED ONLY BY THE CALLER'S UID IS NOT REACHED BY A BOX RUNNING AS SOMEBODY ELSE.
    ///
    /// `survives_a_box` answers for the loss of GROUPS and cannot answer for the loss of the UID,
    /// and `--user <non-root>` or an image `USER` is exactly that: the workload runs as a
    /// subordinate uid, so `Owner` and `AclUser` stop applying while `Other` still does. Reported
    /// fine, such a grant mounts and the workload meets `CUDA_ERROR_NO_DEVICE` with nothing from
    /// kern to explain it.
    ///
    /// NOT A REFUSAL: the caller warns and still binds, because `--gpus --user nobody` works on
    /// every host whose nodes are world-accessible, which pentest case C1 measures on this one.
    #[test]
    fn a_node_reached_only_by_uid_is_named_for_a_box_that_changes_identity() {
        let who = caller(1000, &[1000, 44]);
        let selection = GpuSelection::These(vec![0]);
        // The uid a box started `--user 1` carries on the ranged map: `subuid_base + N - 1`.
        // Measured on this host, `--user nobody` (65534) runs as 165533 with a base of 100000.
        const BOX_UID: u32 = 100_000;

        // THE OWNER CASE: `0o600` owned by the caller. They open it; a subordinate uid does not.
        let owned = two_card_grant(plain(1000, 1000, 0o600));
        assert_eq!(
            access_path(&owned.cards[0].nodes[0].1, &who),
            AccessPath::Owner
        );
        assert_eq!(
            uid_dependent_nodes(&owned, &selection, &who, BOX_UID, false),
            vec![PathBuf::from("/dev/nvidia0")],
            "a node the caller owns and nobody else can open must be named"
        );

        // THE ACL CASE, which is the shape of this host's DRM nodes: root-owned, no `other` bit,
        // with a named entry for the caller.
        let acl = two_card_grant(acl_node(
            0,
            44,
            WANT_RW,
            0,
            0,
            &[(1000, WANT_RW)],
            &[],
            Some(WANT_RW),
        ));
        assert_eq!(
            access_path(&acl.cards[0].nodes[0].1, &who),
            AccessPath::AclUser
        );
        assert_eq!(
            uid_dependent_nodes(&acl, &selection, &who, BOX_UID, false),
            vec![PathBuf::from("/dev/nvidia0")],
            "a node reached through an ACL_USER entry for the caller must be named"
        );

        // AN ACL THAT NAMES THE BOX'S OWN SUBORDINATE UID IS NOT LOST, and this is the case the
        // first version of this function got wrong. It probed with `u32::MAX - 1`, a uid no account
        // can name, so a node an operator had deliberately opened to the box's subuid was reported
        // as unreachable and the box was warned about hardware it reaches perfectly well. The
        // subuid IS an account: on the ranged map in-box uid N lands on `subuid_base + N - 1`.
        let for_the_box = two_card_grant(acl_node(
            0,
            44,
            WANT_RW,
            0,
            0,
            &[(1000, WANT_RW), (BOX_UID, WANT_RW)],
            &[],
            Some(WANT_RW),
        ));
        assert!(
            uid_dependent_nodes(&for_the_box, &selection, &who, BOX_UID, false).is_empty(),
            "a node whose ACL names the box's own uid must not be reported as lost"
        );
        // POSITIVE CONTROL on that case: the SAME node is lost to a DIFFERENT subuid, so the pass
        // above is the entry matching and not the function having stopped answering.
        assert_eq!(
            uid_dependent_nodes(&for_the_box, &selection, &who, BOX_UID + 1, false),
            vec![PathBuf::from("/dev/nvidia0")],
            "another subuid has no entry here and must still be reported"
        );

        // POSITIVE CONTROL, and the one that matters: this host's actual shape for `/dev/nvidia*`.
        // `0o666` is reached by `other`, so NOTHING is uid-dependent and no warning may fire.
        // Without this the function could be one that always answers "everything".
        let open = two_card_grant(plain(0, 0, 0o666));
        assert!(
            uid_dependent_nodes(&open, &selection, &who, BOX_UID, false).is_empty(),
            "a world-accessible grant must name nothing, or every box would be warned"
        );

        // A node the CALLER cannot reach either is `mount_plan`'s refusal to report, not this
        // function's: blaming the box identity for a host problem would send the operator to the
        // wrong flag.
        let dead = two_card_grant(plain(0, 0, 0o000));
        assert_eq!(
            access_path(&dead.cards[0].nodes[0].1, &who),
            AccessPath::Unreachable
        );
        assert!(
            uid_dependent_nodes(&dead, &selection, &who, BOX_UID, false).is_empty(),
            "a node nobody reaches is not a uid-dependence finding"
        );

        // THE SELECTION IS RESPECTED. Card 1 is world-accessible in the fixture, so asking for it
        // names nothing even when card 0 is uid-dependent: a warning about a card nobody asked for
        // is a warning the operator cannot act on.
        assert!(
            uid_dependent_nodes(&owned, &GpuSelection::These(vec![1]), &who, BOX_UID, false)
                .is_empty(),
            "the answer must follow the selection and not the whole grant"
        );
        // And asking for BOTH names the one that is.
        assert_eq!(
            uid_dependent_nodes(
                &owned,
                &GpuSelection::These(vec![0, 1]),
                &who,
                BOX_UID,
                false
            ),
            vec![PathBuf::from("/dev/nvidia0")]
        );

        // A NODE THE CALLER REACHES THROUGH A GROUP, in a box that KEEPS its groups (a Jetson's
        // `root:video 0660`): the workload's uid changes and its groups do not, so nothing is lost.
        // Without the kept groups the same node is named, which is the box that clears them.
        let video = two_card_grant(plain(0, 44, 0o660));
        assert!(
            uid_dependent_nodes(&video, &selection, &who, BOX_UID, true).is_empty(),
            "a kept `video` group still opens the node"
        );
        assert_eq!(
            uid_dependent_nodes(&video, &selection, &who, BOX_UID, false),
            vec![PathBuf::from("/dev/nvidia0")]
        );
    }

    /// THE GRANTED CARD'S PCI DIRECTORY AND ITS BUS NAME, and nothing that leaves `sys/devices` or
    /// is not a PCI address. A fake sysfs: one card under a bridge, one link pointing outside.
    #[test]
    fn a_granted_cards_pci_sysfs_is_its_directory_and_its_bus_name() {
        let root = std::env::temp_dir().join(format!("kern-pcisys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let card = root.join("sys/devices/pci0000:00/0000:00:01.1/0000:06:00.0");
        std::fs::create_dir_all(&card).unwrap();
        std::fs::create_dir_all(root.join("sys/bus/pci/devices")).unwrap();
        std::fs::create_dir_all(root.join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(
            "../../../devices/pci0000:00/0000:00:01.1/0000:06:00.0",
            root.join("sys/bus/pci/devices/0000:06:00.0"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "../../../../elsewhere",
            root.join("sys/bus/pci/devices/0000:07:00.0"),
        )
        .unwrap();
        let got = pci_sysfs_paths(
            &root,
            &[
                "0000:06:00.0".into(),
                "0000:07:00.0".into(),
                "../../etc".into(),
                "0000:09:00.0".into(),
            ],
        );
        assert_eq!(
            got,
            vec![
                PathBuf::from("sys/devices/pci0000:00/0000:00:01.1/0000:06:00.0"),
                PathBuf::from("sys/bus/pci/devices/0000:06:00.0"),
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The tree above a card: its bridge's ATTRIBUTE FILES (never the bridge directory, which lists
    /// the other devices behind it), the bridge's `bus/pci/devices` link, and the CPU and NUMA
    /// topology, once. Measured as what `nvidia-smi topo -m` needs to say `PHB` (see the function).
    #[test]
    fn a_cards_sysfs_includes_its_bridges_attributes_and_the_cpu_topology() {
        let root = std::env::temp_dir().join(format!("kern-pcisys-br-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let card = root.join("sys/devices/pci0000:00/0000:00:01.0/0000:01:00.0");
        std::fs::create_dir_all(&card).expect("card dir");
        let bridge = root.join("sys/devices/pci0000:00/0000:00:01.0");
        for f in ["class", "vendor", "max_link_width"] {
            std::fs::write(bridge.join(f), "x\n").expect("attr");
        }
        // A sibling device behind the same bridge: must NOT be listed.
        std::fs::create_dir_all(bridge.join("0000:01:00.1")).expect("sibling");
        let devs = root.join("sys/bus/pci/devices");
        std::fs::create_dir_all(&devs).expect("bus dir");
        std::os::unix::fs::symlink(
            "../../../devices/pci0000:00/0000:00:01.0/0000:01:00.0",
            devs.join("0000:01:00.0"),
        )
        .expect("card link");
        std::os::unix::fs::symlink(
            "../../../devices/pci0000:00/0000:00:01.0",
            devs.join("0000:00:01.0"),
        )
        .expect("bridge link");
        std::fs::create_dir_all(root.join("sys/devices/system/cpu")).expect("cpu");
        std::fs::create_dir_all(root.join("sys/devices/system/node")).expect("node");
        let got = pci_sysfs_paths(&root, &["0000:01:00.0".into()]);
        let _ = std::fs::remove_dir_all(&root);
        let want: Vec<PathBuf> = [
            "sys/devices/pci0000:00/0000:00:01.0/0000:01:00.0",
            "sys/bus/pci/devices/0000:01:00.0",
            "sys/devices/pci0000:00/0000:00:01.0/class",
            "sys/devices/pci0000:00/0000:00:01.0/vendor",
            "sys/devices/pci0000:00/0000:00:01.0/max_link_width",
            "sys/bus/pci/devices/0000:00:01.0",
            "sys/devices/system/cpu",
            "sys/devices/system/node",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        assert_eq!(got, want);
        assert!(
            !got.iter().any(|p| p.ends_with("0000:01:00.1")),
            "a sibling leaked"
        );
        assert!(
            !got.contains(&PathBuf::from("sys/devices/pci0000:00/0000:00:01.0")),
            "the bridge directory itself is not given"
        );
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
            mount_plan(&grant, &GpuSelection::These(vec![0]), &who).is_ok(),
            "card 0 must be grantable while card 1 is gated"
        );
        match mount_plan(&grant, &GpuSelection::These(vec![1]), &who) {
            Err(MountPlanError::GroupsNeeded { gids, .. }) => assert_eq!(gids, vec![44]),
            other => panic!("card 1 should be refused, got {other:?}"),
        }
    }

    /// `render_plan` prints what the grant says and invents nothing.
    #[test]
    fn the_plan_prints_the_group_decision_in_each_of_its_three_shapes() {
        // A non-root user in `video` (44), whoever runs the test: see `render_plan_for`.
        let who = caller(1000, &[1000, 44]);
        let base = GpuGrant {
            driver_version: "580.173.02".to_string(),
            shared: vec![(PathBuf::from("/dev/nvidiactl"), plain(0, 0, 0o666))],
            cards: vec![CardNodes {
                index: 0,
                pci_address: Some("0000:01:00.0".to_string()),
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
            tools: vec![DriverTool {
                name: "nvidia-smi".to_string(),
                source: PathBuf::from("/usr/bin/nvidia-smi"),
            }],
            configs: Vec::new(),
            dirs: Vec::new(),
            at_host_paths: false,
            sysfs: Vec::new(),
            listed_nodes: BTreeSet::new(),
        };
        let text = render_plan_for(&base, &GpuSelection::All, &who);
        assert!(text.contains("driver 580.173.02"));
        assert!(
            text.contains("tools 1\n  tool /usr/bin/nvidia-smi -> /usr/bin/nvidia-smi\n"),
            "the plan names the tools the box gets: {text}"
        );
        assert!(text.contains("groups not needed"));

        // The three group shapes are produced the way the launch produces them: by the FACTS of
        // the nodes, through the one policy function.
        let gated = GpuGrant {
            cards: vec![CardNodes {
                index: 0,
                pci_address: Some("0000:01:00.0".to_string()),
                nodes: vec![(PathBuf::from("/dev/dri/card0"), plain(0, 44, 0o660))],
            }],
            ..base.clone()
        };
        let text = render_plan_for(&gated, &GpuSelection::All, &who);
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
                // No address: a host whose driver exposes no `gpus` directory still resolves its
                // nodes, and the mask has nothing to name.
                pci_address: None,
                nodes: vec![(PathBuf::from("/dev/locked"), plain(0, 0, 0o600))],
            }],
            ..base
        };
        let text = render_plan_for(&refused, &GpuSelection::All, &who);
        assert!(text.contains("refuse:"));
        assert!(text.contains("/dev/locked"));
    }

    /// A missing card is named as the INDEX it is, never in the count's spelling.
    #[test]
    fn a_missing_card_is_named_as_an_index_not_a_count() {
        let msg = describe_mount_plan_error(&MountPlanError::NoSuchCard {
            wanted: 3,
            present: vec![0],
        });
        assert!(
            msg.starts_with("--gpus device=3: this host has no card 3"),
            "{msg}"
        );
    }

    /// ⛔ THE VALUE DOCKER GIVES `NVIDIA_VISIBLE_DEVICES`, for every spelling it was measured on.
    #[test]
    fn the_visible_devices_value_is_dockers_for_every_spelling() {
        let v = |spec: &str, granted: Option<&[u32]>| {
            let sel = parse_gpu_spec(spec)
                .or_else(|_| {
                    // A UUID never reaches the grammar unresolved; stand in the index it maps to.
                    parse_gpu_spec("device=0")
                })
                .expect("a selection");
            visible_devices(spec, &sel, granted)
        };
        assert_eq!(v("all", None), "all");
        assert_eq!(v("device=all", None), "all");
        assert_eq!(v("count=all", None), "all");
        assert_eq!(v("device=0", None), "0");
        assert_eq!(v("\"device=0,1\"", None), "0,1");
        assert_eq!(v("device=0,1", None), "0,1");
        assert_eq!(v("device=1,0", None), "1,0", "the order written is kept");
        assert_eq!(v("2", None), "0,1");
        assert_eq!(v("1", None), "0");
        assert_eq!(
            v("count=2", Some(&[0, 2])),
            "0,2",
            "the cards granted, gap and all"
        );
        assert_eq!(
            v("device=GPU-1950be8a-cbd3", None),
            "GPU-1950be8a-cbd3",
            "a UUID is handed through as written"
        );
        assert_eq!(
            visible_devices("device=GPU-e02e0ecf", &GpuSelection::All, None),
            "GPU-e02e0ecf",
            "a UUID granted as every adapter (WSL2, unreadable UUIDs) is still written as given"
        );
        assert_eq!(
            v("device=0,capabilities=compute", None),
            "0",
            "the capabilities token is not a card"
        );
    }

    /// ⛔ DOCKER'S LIBRARY DIRECTORY: Debian-family images get the multiarch directory, every other
    /// image `/usr/lib64`, decided by `/etc/debian_version` layer by layer, a whiteout counting as
    /// deleted. And the plan places every library and link there by name, once.
    #[test]
    fn the_libraries_go_where_docker_puts_them_for_the_image() {
        let base = std::env::temp_dir().join(format!("kern-gpu-libdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let layer = |n: &str| {
            let d = base.join(n);
            std::fs::create_dir_all(d.join("etc")).expect("layer");
            d.to_string_lossy().into_owned()
        };
        let (deb, bare, top) = (layer("deb"), layer("bare"), layer("top"));
        std::fs::write(Path::new(&deb).join("etc/debian_version"), b"12\n").expect("w");
        assert_eq!(
            box_library_dir(std::slice::from_ref(&deb)),
            MULTIARCH_LIB_DIR
        );
        assert_eq!(box_library_dir(std::slice::from_ref(&bare)), "/usr/lib64");
        assert_eq!(box_library_dir(&[]), "/usr/lib64");
        assert_eq!(
            box_library_dir(&[bare.clone(), deb.clone()]),
            MULTIARCH_LIB_DIR,
            "the marker in a lower layer is the image's"
        );
        // A symlink is the image's own file and is not followed.
        std::os::unix::fs::symlink("/nonexistent", Path::new(&top).join("etc/debian_version"))
            .expect("link");
        assert_eq!(
            box_library_dir(std::slice::from_ref(&top)),
            MULTIARCH_LIB_DIR
        );
        // A whiteout above it deletes it, when this kernel lets us make one.
        let wo = layer("wo");
        if fixture_node(&Path::new(&wo).join("etc/debian_version")) {
            assert_eq!(box_library_dir(&[wo, deb]), "/usr/lib64");
        }

        let mut grant = two_card_grant(plain(0, 0, 0o666));
        grant.libraries.push(Library {
            path: PathBuf::from("/usr/lib/x86_64-linux-gnu/nvidia/current/libcuda.so.580.173.02"),
            dev: 9,
            ino: 9,
        });
        let Ok(binds) = mount_plan_into(
            &grant,
            &GpuSelection::These(vec![0]),
            &caller(1000, &[1000]),
            "/usr/lib64",
        ) else {
            panic!("expected a plan");
        };
        let libs: Vec<&(String, String, bool)> =
            binds.iter().filter(|(_, t, _)| t.contains("lib")).collect();
        assert!(!libs.is_empty());
        for (_, target, ro) in &libs {
            assert!(target.starts_with("/usr/lib64/") && *ro, "{target}");
        }
        let mut targets: Vec<&String> = libs.iter().map(|(_, t, _)| t).collect();
        let n = targets.len();
        targets.sort();
        targets.dedup();
        assert_eq!(targets.len(), n, "one bind per name: {libs:?}");
        assert!(
            binds.iter().any(|(_, t, _)| t == "/dev/nvidia0"),
            "the nodes stay where they are"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// ⛔ THE VULKAN, EGL AND OPTIX FILES, AND THE TWO LINKS, where NVIDIA's own spec puts them.
    /// Measured: with them, `vulkaninfo` in a docker container lists the NVIDIA device; a kern box
    /// had none of them.
    #[test]
    fn the_graphics_files_and_links_are_bound_where_the_cdi_spec_puts_them() {
        let dir = std::env::temp_dir().join(format!("kern-gpu-configs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (rel, _) in DRIVER_CONFIG_FILES {
            if rel.starts_with("etc/") {
                continue; // the /usr/share row is present, so the /etc one must lose
            }
            let f = dir.join(rel);
            std::fs::create_dir_all(f.parent().expect("parent")).expect("dir");
            std::fs::write(&f, b"{}").expect("w");
        }
        // The /etc spelling of the ICD too: one box path, the first row wins.
        std::fs::create_dir_all(dir.join("etc/vulkan/icd.d")).expect("dir");
        std::fs::write(dir.join("etc/vulkan/icd.d/nvidia_icd.json"), b"{}").expect("w");
        let configs = driver_configs_under(&dir);
        let targets: Vec<&str> = configs.iter().map(|(_, t)| t.as_str()).collect();
        assert_eq!(
            targets,
            vec![
                "/etc/vulkan/icd.d/nvidia_icd.json",
                "/etc/vulkan/implicit_layer.d/nvidia_layers.json",
                "/usr/share/glvnd/egl_vendor.d/10_nvidia.json",
                "/usr/share/egl/egl_external_platform.d/10_nvidia_wayland.json",
                "/usr/share/egl/egl_external_platform.d/15_nvidia_gbm.json",
                "/usr/share/nvidia/nvoptix.bin",
            ]
        );
        assert!(
            configs[0]
                .0
                .ends_with("usr/share/vulkan/icd.d/nvidia_icd.json"),
            "the first row wins a shared box path: {:?}",
            configs[0]
        );

        let mut grant = two_card_grant(plain(0, 0, 0o666));
        grant.configs = configs;
        for name in [
            "libGLX_nvidia.so.580.173.02",
            "libnvidia-allocator.so.580.173.02",
        ] {
            grant.libraries.push(Library {
                path: PathBuf::from(format!("/usr/lib/x86_64-linux-gnu/{name}")),
                dev: 3,
                ino: name.len() as u64,
            });
        }
        let Ok(binds) = mount_plan_into(
            &grant,
            &GpuSelection::These(vec![0]),
            &caller(1000, &[1000]),
            "/usr/lib64",
        ) else {
            panic!("expected a plan");
        };
        for (source, target) in [
            (
                "/usr/lib/x86_64-linux-gnu/libGLX_nvidia.so.580.173.02",
                "/usr/lib64/libGLX_indirect.so.0",
            ),
            (
                "/usr/lib/x86_64-linux-gnu/libnvidia-allocator.so.580.173.02",
                "/usr/lib64/gbm/nvidia-drm_gbm.so",
            ),
        ] {
            let want = (source.to_string(), target.to_string(), true);
            assert!(binds.contains(&want), "{want:?} not in {binds:?}");
        }
        assert!(
            binds
                .iter()
                .any(|(_, t, ro)| t == "/etc/vulkan/icd.d/nvidia_icd.json" && *ro),
            "the ICD is bound read-only at the spec's path"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE TOOLS ARE FOUND UNDER THE ROOT, one per name, in the `PATH` order docker's toolkit
    /// searches, symlinks resolved; and the plan binds each read-only at `/usr/bin/<name>`.
    #[test]
    fn the_driver_tools_are_found_under_the_root_and_bound_at_usr_bin() {
        let dir = std::env::temp_dir().join(format!("kern-gpu-tools-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in ["usr/local/bin", "usr/bin", "opt/nvidia"] {
            std::fs::create_dir_all(dir.join(sub)).expect("dir");
        }
        // `nvidia-smi` in two places: the earlier directory in the search order wins.
        std::fs::write(dir.join("usr/local/bin/nvidia-smi"), b"local").expect("w");
        std::fs::write(dir.join("usr/bin/nvidia-smi"), b"usr").expect("w");
        // `nvidia-debugdump` as a link, as an alternatives system writes it.
        std::fs::write(dir.join("opt/nvidia/nvidia-debugdump"), b"real").expect("w");
        std::os::unix::fs::symlink(
            dir.join("opt/nvidia/nvidia-debugdump"),
            dir.join("usr/bin/nvidia-debugdump"),
        )
        .expect("link");
        // A directory with a tool's name is not the tool.
        std::fs::create_dir_all(dir.join("usr/bin/nvidia-persistenced")).expect("dir");
        let tools = driver_tools_under(&dir);
        let canon = |rel: &str| std::fs::canonicalize(dir.join(rel)).expect("canonical");
        assert_eq!(
            tools,
            vec![
                DriverTool {
                    name: "nvidia-smi".to_string(),
                    source: canon("usr/local/bin/nvidia-smi"),
                },
                DriverTool {
                    name: "nvidia-debugdump".to_string(),
                    source: canon("opt/nvidia/nvidia-debugdump"),
                },
            ]
        );

        let mut grant = two_card_grant(plain(0, 0, 0o666));
        grant.tools = tools;
        let Ok(binds) = mount_plan(
            &grant,
            &GpuSelection::These(vec![0]),
            &caller(1000, &[1000]),
        ) else {
            panic!("expected a plan");
        };
        for (name, rel) in [
            ("nvidia-smi", "usr/local/bin/nvidia-smi"),
            ("nvidia-debugdump", "opt/nvidia/nvidia-debugdump"),
        ] {
            let want = (
                canon(rel).to_string_lossy().into_owned(),
                format!("/usr/bin/{name}"),
                true,
            );
            assert!(binds.contains(&want), "{want:?} not in {binds:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Set a directory's `mtime` to an hour ago, so the next change to it is visible whatever the
    /// granularity of the clock: a change made in the same tick as the fixture's own creation would
    /// otherwise leave the stamp equal, which is the case [`SCAN_RECORD_SETTLE_SECS`] exists for and
    /// not the one these tests are about.
    fn age(dir: &Path) {
        let Ok(c) = CString::new(dir.as_os_str().as_bytes()) else {
            panic!("path with a NUL: {}", dir.display());
        };
        let hour_ago = libc::timespec {
            tv_sec: unsafe { libc::time(std::ptr::null_mut()) } - 3600,
            tv_nsec: 0,
        };
        let times = [hour_ago, hour_ago];
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) };
        assert_eq!(rc, 0, "utimensat {}", dir.display());
    }

    /// THE RECORD OF A SCAN ANSWERS WHAT THE SCAN ANSWERS, AND STOPS ANSWERING WHEN IT WOULD NOT.
    ///
    /// The scan of the linker's directories was most of a `--gpus` start, so it is recorded and
    /// recalled. What a recall must never do is hand a box the answer for a directory that has
    /// changed since: a link added or re-pointed, a library replaced, `ld.so.conf` edited. Each is
    /// made here and each must turn the recall into a miss; the positive control first, so a recall
    /// that never hits cannot pass the misses.
    #[test]
    fn a_recorded_library_scan_is_recalled_only_while_its_directories_are_unchanged() {
        let root =
            std::env::temp_dir().join(format!("kern-gpu-scan-record-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let lib = root.join("usr/lib/x86_64-linux-gnu");
        let other = root.join("opt/vendor");
        std::fs::create_dir_all(&lib).expect("lib dir");
        std::fs::create_dir_all(&other).expect("vendor dir");
        std::fs::create_dir_all(root.join("etc")).expect("etc");
        std::fs::write(root.join("etc/ld.so.conf"), b"/usr/lib/x86_64-linux-gnu\n").expect("conf");
        let mut elf = Vec::with_capacity(64);
        elf.extend_from_slice(&ELF_MAGIC);
        elf.push(ELF_CLASS_64);
        elf.extend_from_slice(&[0u8; 59]);
        std::fs::write(lib.join("libnv.so.1.2.3"), &elf).expect("lib");
        std::fs::write(other.join("libnv-alt.so.1.2.3"), &elf).expect("alt lib");
        std::fs::write(lib.join("libz.so.1"), b"not elf").expect("other file");
        std::os::unix::fs::symlink("libnv.so.1.2.3", lib.join("libnv.so.1")).expect("soname link");
        std::os::unix::fs::symlink("libz.so.1", lib.join("libz.so")).expect("other link");
        // A chain through ANOTHER directory, which the record has to watch as well.
        std::os::unix::fs::symlink(
            "../../../opt/vendor/libnv-alt.so.1.2.3",
            lib.join("libalt.so"),
        )
        .expect("cross-directory link");
        for d in [
            &lib,
            &other,
            &root.join("opt"),
            &root.join("usr/lib"),
            &root.join("usr"),
            &root,
        ] {
            age(d);
        }
        let record = root.join("scan-record");
        let want = ElfClass::Bits64;

        let scan = |root: &Path| {
            let dirs = linker_dirs(root);
            let candidates = library_candidates(&dirs, "1.2.3");
            let libraries = libraries_from(root, want, &candidates);
            let mut touched: BTreeSet<PathBuf> = BTreeSet::new();
            let symlinks = symlinks_for(root, &dirs, &libraries, &mut |hop: &Path| {
                if let Some(parent) = hop.parent() {
                    touched.insert(parent.to_path_buf());
                }
            });
            (dirs, touched, candidates, libraries, symlinks)
        };
        let remember = |root: &Path| {
            let (dirs, touched, candidates, libraries, symlinks) = scan(root);
            let rec = ScanRecord {
                root,
                version: "1.2.3",
                want,
                dirs: &dirs,
                touched: &touched,
                candidates: &candidates,
                libraries: &libraries,
                symlinks: &symlinks,
            };
            // Every stamp is older than this, so the record is written.
            remember_scan(&record, &rec, i64::MAX);
            (libraries, symlinks)
        };
        let recall = |root: &Path| recall_scan(&record, root, "1.2.3", want, &linker_dirs(root));

        // THE POSITIVE CONTROL: the record is written and recalled, and the recall IS the scan.
        let fresh = remember(&root);
        assert!(record.is_file(), "the record was not written");
        assert_eq!(
            fresh.1.len(),
            1,
            "one link ends at the granted library: {:?}",
            fresh.1
        );
        assert_eq!(
            recall(&root),
            Some(fresh.clone()),
            "the recall must equal the scan"
        );

        // A DIRECTORY CHANGED TOO RECENTLY IS NOT RECORDED: the cutoff is the scan's own start.
        let _ = std::fs::remove_file(&record);
        let (dirs, touched, candidates, libraries, symlinks) = scan(&root);
        let rec = ScanRecord {
            root: &root,
            version: "1.2.3",
            want,
            dirs: &dirs,
            touched: &touched,
            candidates: &candidates,
            libraries: &libraries,
            symlinks: &symlinks,
        };
        // `ctime` cannot be aged, so every directory here changed "now": the cutoff of a scan started
        // now refuses all of them.
        let cutoff = settled_before(std::time::SystemTime::now()).expect("cutoff");
        remember_scan(&record, &rec, cutoff);
        assert!(
            !record.exists(),
            "a scan of directories that just changed was recorded"
        );

        // A LINK ADDED to a linker directory: nothing re-derived can see it, only the stamp.
        remember(&root);
        std::os::unix::fs::symlink("libnv.so.1", lib.join("libnv.so")).expect("new link");
        assert_eq!(
            recall(&root),
            None,
            "a link added since the record was recalled past"
        );
        age(&lib);
        let with_new = remember(&root);
        assert_eq!(
            with_new.1.len(),
            2,
            "the new link is found by the scan: {:?}",
            with_new.1
        );
        assert_eq!(recall(&root), Some(with_new), "the new record recalls");

        // A CHAIN'S OTHER DIRECTORY CHANGED: the cross-directory link now ends at a granted file.
        std::fs::remove_file(other.join("libnv-alt.so.1.2.3")).expect("remove alt");
        std::os::unix::fs::symlink(
            "../../usr/lib/x86_64-linux-gnu/libnv.so.1.2.3",
            other.join("libnv-alt.so.1.2.3"),
        )
        .expect("alt now a link to the granted library");
        assert_eq!(
            recall(&root),
            None,
            "a change in a directory a chain passed through was recalled past"
        );
        age(&other);
        let through = remember(&root);
        assert!(
            through.1.iter().any(|l| l.link == lib.join("libalt.so")),
            "the scan follows the chain through the other directory: {:?}",
            through.1
        );
        assert_eq!(recall(&root), Some(through), "the new record recalls");

        // THE LOADER'S CONFIGURATION EDITED: a different directory list is a miss.
        std::fs::write(
            root.join("etc/ld.so.conf"),
            b"/usr/lib/x86_64-linux-gnu\n/opt/vendor\n",
        )
        .expect("conf");
        assert_eq!(recall(&root), None, "an ld.so.conf edit was recalled past");
        std::fs::write(root.join("etc/ld.so.conf"), b"/usr/lib/x86_64-linux-gnu\n").expect("conf");
        assert!(
            recall(&root).is_some(),
            "the original configuration recalls again"
        );

        // A DIRECTORY THAT WAS ABSENT AND APPEARS: the loader's defaults include directories this
        // root does not have, and a library placed in one of them must not be recalled past.
        let absent = linker_dirs(&root)
            .into_iter()
            .find(|d| !d.exists())
            .expect("a default linker directory this root lacks, or this case proves nothing");
        remember(&root);
        std::fs::create_dir_all(&absent).expect("create the absent directory");
        std::fs::write(absent.join("libnv-late.so.1.2.3"), &elf).expect("late lib");
        assert_eq!(
            recall(&root),
            None,
            "a directory that appeared was recalled past"
        );
        std::fs::remove_dir_all(&absent).expect("remove it again");

        // A FORGED RECORD CAN ONLY OMIT. A consistent forgery: a real ELF file with the version
        // suffix OUTSIDE the linker's directories, listed as a candidate, with the library list
        // re-derived from the forged candidates so it agrees with them. Only the check that a
        // candidate sits in a linker directory stands between it and a box. (The first version of
        // this case forged `ld.so.conf`, which the suffix check refused before the directory
        // check ran: a sabotage of the directory check went unnoticed.)
        let outside = root.join("etc/libsecret.so.1.2.3");
        std::fs::write(&outside, &elf).expect("outside lib");
        let (dirs, touched, mut candidates, _, symlinks) = scan(&root);
        candidates.push(outside.clone());
        let forged_libraries = libraries_from(&root, want, &candidates);
        assert!(
            forged_libraries.iter().any(|l| l.path == outside),
            "the forged candidate must resolve to a library, or this case proves nothing"
        );
        let forged = ScanRecord {
            root: &root,
            version: "1.2.3",
            want,
            dirs: &dirs,
            touched: &touched,
            candidates: &candidates,
            libraries: &forged_libraries,
            symlinks: &symlinks,
        };
        remember_scan(&record, &forged, i64::MAX);
        assert_eq!(
            recall(&root),
            None,
            "a candidate outside the linker's directories was believed"
        );

        // AND A TRUNCATED ONE IS A MISS, not a partial answer.
        remember(&root);
        let bytes = std::fs::read(&record).expect("record");
        std::fs::write(&record, &bytes[..bytes.len() / 2]).expect("truncate");
        assert_eq!(recall(&root), None, "a truncated record was believed");

        let _ = std::fs::remove_dir_all(&root);
    }
}
