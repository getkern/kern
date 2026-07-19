//! Always-on seccomp denylist.
//!
//! Blocks the syscalls a sandboxed workload must never make - kexec, kernel-module
//! (un)loading, ptrace, reboot, swap on/off, and further mount/namespace manipulation. It is an
//! allow-by-default *denylist* (kern's "always-on" baseline); a stricter allowlist mode can land
//! later. The filter is installed last, after kern's own setup syscalls, so it only constrains
//! the workload. Wrong-arch syscalls are killed, closing the foreign-ABI number-confusion bypass.

use crate::Error;

// BPF instruction classes / fields (`<linux/bpf_common.h>`).
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
#[cfg(target_arch = "x86_64")] // only the x32-ABI kill uses JSET (x86_64-only)
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// `__X32_SYSCALL_BIT` (`<asm/unistd.h>`). On x86_64 the x32 ABI reuses the x86_64 `AUDIT_ARCH`
// token but sets this bit on the syscall number - so a plain number-equality denylist can be
// bypassed by calling the x32 variant of a blocked syscall. Kill anything with the bit set.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// seccomp return actions (`<linux/seccomp.h>`).
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
// Deny gracefully with an errno instead of killing. The syscall STILL never runs (isolation is
// identical to a kill), but the caller gets `ENOSYS` and can take its fallback path - so software
// that merely PROBES an optional capability (io_uring, perf, userfaultfd, keyring) keeps working
// instead of being SIGSYS-killed mid-startup. Reserved for deny-but-degrade syscalls (see
// `errno_syscalls`); true escape vectors still kill. `SECCOMP_RET_DATA` masks the errno into the low
// 16 bits of the return value.
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_DATA: u32 = 0x0000_ffff;

// Offsets into `struct seccomp_data`.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

// The audit-arch token for the build target. A syscall number is only meaningful for one ABI,
// so we kill anything arriving under a different arch.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

/// The syscalls a *nested* `kern box` needs and nothing else: create its own namespaces
/// (`unshare`/`setns`) and set up its rootfs (`mount`/`umount2`/`pivot_root`, the CLASSIC mount
/// API kern itself uses). These are the ONLY entries `denylist(true)` drops for a `--privileged`
/// box. Everything else in the always-on set (kexec, modules, bpf, io_uring, keyring, ptrace, the
/// NEW mount API, …) stays blocked even under `--privileged` - so a kern privileged box is
/// materially stronger than a Docker `--privileged` container (which drops the seccomp filter
/// wholesale). `--privileged` is honoured ONLY in rootless mode (see `real.rs`): when the box's
/// root maps to an unprivileged host uid, a nested userns grants no new host privilege - exactly
/// why rootless podman-in-podman is safe.
fn nesting_syscalls() -> [libc::c_long; 5] {
    [
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
    ]
}

/// Dangerous syscalls. `libc::SYS_*` resolves to the correct number for the compile target.
/// `clone`/`clone3` are intentionally NOT blocked - they're how ordinary programs fork.
/// Returned as a `Vec` because a few `SYS_*` constants aren't exposed by `libc` on every arch
/// (e.g. `kexec_file_load` on aarch64-musl), so they're added conditionally rather than as a
/// fixed-size array.
///
/// `allow_nesting` (a rootless `--privileged` box) omits exactly [`nesting_syscalls`] so a nested
/// `kern box` can create its namespaces and mount its rootfs; every other entry stays blocked.
fn denylist(allow_nesting: bool) -> Vec<libc::c_long> {
    let mut v = vec![
        // Debugging / cross-process memory (ptrace-equivalents).
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        // Kernel image / modules / power.
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        // Mounting - classic API. Dropped only for a rootless `--privileged` (nesting) box; see
        // `nesting_syscalls`. `mount`/`umount2`/`pivot_root` are re-added below unless nesting.
        // … and the new mount API (would otherwise bypass the `mount` denial). Kept blocked ALWAYS
        // - kern's own setup uses the classic API, so even a nested box never needs the new one.
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        // `fspick(2)` opens an fs-context on an existing mount to reconfigure it. It's inert on its own
        // (the reconfigure only commits via `fsconfig(FSCONFIG_CMD_RECONFIGURE)`, already denied above),
        // but block the whole reconfiguration family so the guarantee doesn't rest on that one coupling
        // - a future edit to the fsconfig handling can't silently re-open an RO-clear path.
        libc::SYS_fspick,
        // `mount_setattr(2)` changes attributes of an existing mount - with CAP_SYS_ADMIN in the box's
        // own userns it could clear `MS_RDONLY` and strip a `--read-only` box (or a `:ro` volume). Same
        // family as the mount API above; deny it outright so the read-only contract can't be undone.
        libc::SYS_mount_setattr,
        // Kernel attack surface a sandboxed workload never needs and that has a long history of
        // local-privilege-escalation bugs.
        libc::SYS_bpf,
        // io_uring, userfaultfd, perf_event_open, the keyring family (add_key/request_key/keyctl) and
        // syslog(2) are ALSO denied - but via `errno_syscalls()` (→ ENOSYS) rather than a kill. They're
        // deny-but-degrade: legitimate software probes them for an optional fast-path (async I/O,
        // profiling, GC) and falls back when they're unavailable, so a SIGSYS-kill was a needless
        // compat break (it killed Redis 8's modules mid-startup) while the isolation - the syscall
        // never runs - is identical. See `errno_syscalls`.
    ];
    // Namespace creation + classic mount API. Blocked by default (nested userns → CAP_SYS_ADMIN
    // escape, and mount would undo the RO/masked-/proc contract). A rootless `--privileged` box
    // keeps them ALLOWED so a nested `kern box` can start - safe because the box's root is an
    // unprivileged host uid (the caller is non-root; enforced in `real.rs`).
    if !allow_nesting {
        v.extend_from_slice(&nesting_syscalls());
    }
    // `kexec_file_load` (load a new kernel image from an fd): `libc` exposes the constant on
    // x86_64 but not on aarch64-musl, so add it by number where missing. Denying a number that
    // doesn't exist on an arch is harmless, so unknown arches simply omit it.
    #[cfg(target_arch = "x86_64")]
    v.push(libc::SYS_kexec_file_load);
    #[cfg(target_arch = "aarch64")]
    v.push(294); // __NR_kexec_file_load (aarch64)
    v
}

/// Denied, but with `ENOSYS` instead of a kill (see [`SECCOMP_RET_ERRNO`]). A hostile payload can't
/// escape through any of these anyway - they're capabilities that legitimate software merely PROBES
/// for an optional fast-path and gracefully falls back on when unavailable. Killing on them (the old
/// behaviour) needlessly broke such software: Redis 8's modules probe io_uring on startup and were
/// SIGSYS-killed. Returning `ENOSYS` keeps the isolation IDENTICAL (the syscall still never runs)
/// while letting the fallback path (epoll/threads/no-op) take over. Not affected by `allow_nesting` -
/// none of these are nesting syscalls. True escape vectors (kexec, modules, the mount API, bpf,
/// ptrace, the nesting set) stay in [`denylist`] and still KILL.
fn errno_syscalls() -> [libc::c_long; 9] {
    [
        // io_uring: bug-rich async-I/O (LPE-CVE history). Still fully denied - callers fall back to
        // epoll/thread-pool I/O, which is exactly what every one of them already ships as the default.
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        // Optional GC / profiling fast-paths - software runs fine without them.
        libc::SYS_userfaultfd,
        libc::SYS_perf_event_open,
        // Kernel keyring: already namespaced by the box user-ns (defense-in-depth, not a live escape);
        // callers that probe it degrade cleanly.
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_keyctl,
        // syslog(2)/klogctl reads the kernel ring buffer (dmesg) - an info leak; a prober just gets
        // nothing. (The libc `syslog()` LOGGING function uses /dev/log, not this syscall - unaffected.)
        libc::SYS_syslog,
    ]
}

/// How many syscalls the denylist blocks (for the box status banner - kept truthful by reading the
/// live list rather than a hard-coded number). `allow_nesting` reflects a rootless `--privileged`
/// box, which blocks [`nesting_syscalls`] fewer.
pub fn denied_syscall_count(allow_nesting: bool) -> usize {
    denylist(allow_nesting).len() + errno_syscalls().len()
}

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Install the filter: set `NO_NEW_PRIVS` (required for unprivileged seccomp), then load the BPF.
/// `allow_nesting` (a rootless `--privileged` box) leaves the namespace + classic-mount syscalls
/// allowed so a nested `kern box` can start; every other dangerous syscall stays blocked.
pub fn install(allow_nesting: bool) -> Result<(), Error> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(Error::last("prctl(NO_NEW_PRIVS)"));
    }

    // 1. Validate arch (mismatch → kill), then 2. load the syscall number.
    let mut prog: Vec<libc::sock_filter> = vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH),
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0), // ==arch → skip the kill below
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
    ];
    // 2b. x86_64 only: kill any x32-ABI syscall (the `__X32_SYSCALL_BIT` is set on `nr`). Without
    // this, the number-equality denylist below is bypassable by invoking the x32 variant of a
    // blocked syscall (same `AUDIT_ARCH`, different number). The `nr` is already loaded above.
    #[cfg(target_arch = "x86_64")]
    {
        prog.push(jump(BPF_JMP | BPF_JSET | BPF_K, X32_SYSCALL_BIT, 0, 1)); // bit set → next (kill)
        prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }
    // 3. Each KILL-set number: ==nr → kill the process. These are real escape vectors / pure-attack
    // syscalls (kexec, modules, the mount API, bpf, ptrace, nesting) - no legitimate workload calls
    // them, so an attempt is treated as hostile and the process dies.
    for nr in denylist(allow_nesting) {
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 1)); // ==nr → next (kill); else skip
        prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }
    // 3b. Each deny-but-degrade number: ==nr → return ENOSYS instead of killing. The syscall still
    // never runs (isolation identical to a kill); the caller merely sees "not implemented" and takes
    // its fallback path, so probing software (Redis 8's io_uring, profilers, …) keeps working.
    let errno_ret = SECCOMP_RET_ERRNO | (libc::ENOSYS as u32 & SECCOMP_RET_DATA);
    for nr in errno_syscalls() {
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 1)); // ==nr → next (errno); else skip
        prog.push(stmt(BPF_RET | BPF_K, errno_ret));
    }
    // 4. Default: allow.
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_mut_ptr(),
    };
    let r = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER as libc::c_ulong,
            std::ptr::addr_of!(fprog) as libc::c_ulong,
            0,
            0,
        )
    };
    if r != 0 {
        return Err(Error::last("prctl(SET_SECCOMP)"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{denylist, errno_syscalls, nesting_syscalls};

    /// Every high-value syscall a sandboxed workload must never run stays DENIED - whether by a kill
    /// (escape vectors) or by ENOSYS (deny-but-degrade). A regression that drops an entry from BOTH
    /// sets silently reopens a kernel surface, so the test checks the union.
    #[test]
    fn all_critical_syscalls_stay_denied() {
        let denied: Vec<_> = denylist(false)
            .into_iter()
            .chain(errno_syscalls())
            .collect();
        let must = [
            libc::SYS_ptrace,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_bpf,
            libc::SYS_userfaultfd,
            libc::SYS_perf_event_open,
            // Mount API v2 (would bypass the classic mount denial).
            libc::SYS_open_tree,
            libc::SYS_move_mount,
            libc::SYS_fsopen,
            libc::SYS_mount_setattr,
            // io_uring family + keyring (now denied via ENOSYS, still denied).
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
            libc::SYS_add_key,
            libc::SYS_request_key,
            libc::SYS_keyctl,
        ];
        for nr in must {
            assert!(
                denied.contains(&nr),
                "syscall nr {nr} is no longer denied by EITHER set"
            );
        }
    }

    /// The KILL set and the ENOSYS set must stay DISJOINT, and - critically - the ENOSYS demotion must
    /// only ever apply to deny-but-degrade syscalls. A real escape vector (kexec, bpf, ptrace, the
    /// mount API) demoted to a mere ENOSYS would let a hostile payload keep probing instead of dying,
    /// so this asserts every escape vector stays a hard kill.
    #[test]
    fn kill_and_errno_sets_are_disjoint_escape_vectors_still_kill() {
        let kill = denylist(false);
        let errno = errno_syscalls();
        for nr in errno {
            assert!(
                !kill.contains(&nr),
                "syscall {nr} is in BOTH the kill and errno sets"
            );
        }
        // The deny-but-degrade family lands in the errno set…
        assert!(errno.contains(&libc::SYS_io_uring_setup));
        // …while every real escape vector stays a hard KILL and is NEVER demoted to ENOSYS.
        for nr in [
            libc::SYS_kexec_load,
            libc::SYS_init_module,
            libc::SYS_bpf,
            libc::SYS_ptrace,
            libc::SYS_mount_setattr,
            libc::SYS_open_tree,
        ] {
            assert!(
                kill.contains(&nr),
                "escape vector {nr} must stay in the KILL set"
            );
            assert!(
                !errno.contains(&nr),
                "escape vector {nr} must NOT be demoted to ENOSYS"
            );
        }
    }

    /// A rootless `--privileged` (nesting) box drops EXACTLY the namespace + classic-mount syscalls
    /// and nothing else - so a nested `kern box` can start while every other escape/DoS syscall
    /// (kexec, modules, bpf, io_uring, keyring, ptrace, the NEW mount API) stays blocked. This is
    /// the property that makes a kern privileged box stronger than a Docker `--privileged` one.
    #[test]
    fn nesting_mode_drops_only_the_namespace_and_mount_syscalls() {
        let strict = denylist(false);
        let nest = denylist(true);
        // The nesting set is exactly what differs.
        assert_eq!(strict.len() - nest.len(), nesting_syscalls().len());
        for nr in nesting_syscalls() {
            assert!(strict.contains(&nr), "strict must block {nr}");
            assert!(!nest.contains(&nr), "nesting must allow {nr}");
        }
        // Everything a nested box never needs stays blocked even under `--privileged` - unlike
        // Docker's `--privileged`, which drops the seccomp filter entirely.
        for nr in [
            libc::SYS_kexec_load,
            libc::SYS_init_module,
            libc::SYS_reboot,
            libc::SYS_bpf,
            libc::SYS_ptrace,
            libc::SYS_open_tree, // new mount API stays blocked; kern uses the classic one
            libc::SYS_mount_setattr,
        ] {
            assert!(nest.contains(&nr), "nesting must STILL block (kill) {nr}");
        }
        // io_uring + the keyring stay denied under `--privileged` too - via ENOSYS. The errno set is
        // independent of nesting, so a privileged box is no weaker on these than a strict one.
        for nr in [libc::SYS_io_uring_setup, libc::SYS_keyctl] {
            assert!(
                errno_syscalls().contains(&nr),
                "nesting must STILL deny (errno) {nr}"
            );
        }
    }
}
