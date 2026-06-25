//! Always-on seccomp denylist.
//!
//! Blocks the syscalls a sandboxed workload must never make — kexec, kernel-module
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
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// seccomp return actions (`<linux/seccomp.h>`).
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

// Offsets into `struct seccomp_data`.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

// The audit-arch token for the build target. A syscall number is only meaningful for one ABI,
// so we kill anything arriving under a different arch.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

/// Dangerous syscalls. `libc::SYS_*` resolves to the correct number for the compile target.
/// `clone`/`clone3` are intentionally NOT blocked — they're how ordinary programs fork.
/// Returned as a `Vec` because a few `SYS_*` constants aren't exposed by `libc` on every arch
/// (e.g. `kexec_file_load` on aarch64-musl), so they're added conditionally rather than as a
/// fixed-size array.
fn denylist() -> Vec<libc::c_long> {
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
        // Mounting — classic API …
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        // … and the new mount API (would otherwise bypass the `mount` denial).
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        // Namespace entry / creation (nested userns → CAP_SYS_ADMIN escape).
        libc::SYS_setns,
        libc::SYS_unshare,
        // Kernel attack surface a sandboxed workload never needs and that has a long history of
        // local-privilege-escalation bugs.
        libc::SYS_bpf,
        libc::SYS_userfaultfd,
        libc::SYS_perf_event_open,
    ];
    // `kexec_file_load` (load a new kernel image from an fd): `libc` exposes the constant on
    // x86_64 but not on aarch64-musl, so add it by number where missing. Denying a number that
    // doesn't exist on an arch is harmless, so unknown arches simply omit it.
    #[cfg(target_arch = "x86_64")]
    v.push(libc::SYS_kexec_file_load);
    #[cfg(target_arch = "aarch64")]
    v.push(294); // __NR_kexec_file_load (aarch64)
    v
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
pub fn install() -> Result<(), Error> {
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
    // 3. Each denied number: ==nr → kill.
    for nr in denylist() {
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 1)); // ==nr → next (kill); else skip
        prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
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
