//! Always-on seccomp: a deny-by-default allowlist by default, a wider denylist as an opt-out.
//!
//! Blocks the syscalls a sandboxed workload must never make - kexec, kernel-module
//! (un)loading, ptrace, reboot, swap on/off, and further mount/namespace manipulation. The shipped
//! default is a deny-by-default *allowlist* (moby's own default filter minus kern's 35 escape
//! syscalls); the wider allow-by-default *denylist* is the opt-out via `KERN_SECCOMP=denylist`. The
//! filter is installed last, after kern's own setup syscalls, so it only constrains the workload.
//! Wrong-arch syscalls are killed, closing the foreign-ABI number-confusion bypass.
//!
//! Three shapes of rule, and the difference matters when reading the program:
//!
//! 1. **Number equality → kill** ([`denylist`]): a syscall no sandboxed workload has any business
//!    calling, so an attempt is treated as hostile and the process dies.
//! 2. **Number equality → `ENOSYS`** ([`errno_syscalls`]): equally denied, the call never runs, but
//!    the caller is told "not implemented" so software that merely PROBES an optional fast path
//!    takes its fallback instead of dying mid-startup.
//! 3. **Argument inspection → kill** ([`CLONE_NEW_MASK`]): `clone(2)` cannot be denied outright,
//!    because it is how every program forks, so its flags are examined and only the
//!    namespace-creating ones are refused. This is possible ONLY because `clone` passes flags in a
//!    register; `clone3` passes them behind a pointer that BPF cannot follow, which is why that one
//!    falls under rule 2 instead.

use crate::Error;

// BPF instruction classes / fields (`<linux/bpf_common.h>`).
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
// Used on EVERY arch by the `clone` flag check, and additionally on x86_64 by the x32-ABI kill. It
// was `#[cfg(target_arch = "x86_64")]` while the x32 kill was its only user; the clone check made
// that gate a compile error on aarch64, which no amount of x86 testing would have shown.
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;
// `BPF_JA` (unconditional jump) takes a 32-bit `k` offset with NO 255 limit, unlike the u8 `jt`/`jf`
// of `BPF_JEQ`/`BPF_JGT`. The allowlist binary search uses `JA` for every far jump (to the ALLOW and
// ENOSYS terminals, and over a left subtree), keeping the conditional jumps at offset 0/1 so a tree
// of ~300 leaves never overflows an 8-bit branch. `BPF_JGT` (`nr > k`) splits the search.
const BPF_JA: u16 = 0x00;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;

// `__X32_SYSCALL_BIT` (`<asm/unistd.h>`). On x86_64 the x32 ABI reuses the x86_64 `AUDIT_ARCH`
// token but sets this bit on the syscall number - so a plain number-equality denylist can be
// bypassed by calling the x32 variant of a blocked syscall. Kill anything with the bit set.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// seccomp return actions (`<linux/seccomp.h>`).
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
// Log the syscall (subject to `/proc/sys/kernel/seccomp/actions_logged`), then EXECUTE it as if
// allowed. Used ONLY by the allowlist AUDIT mode: the would-be-denied branch logs instead of
// returning `ENOSYS`, so a workload runs exactly as it would under the denylist while every syscall a
// real allowlist flip would refuse is recorded - the exact delta to validate before flipping default.
// Never used in a shipped posture: escape vectors still kill, the allow set still allows silently.
const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
// Deny gracefully with an errno instead of killing. The syscall STILL never runs (isolation is
// identical to a kill), but the caller gets `ENOSYS` and can take its fallback path - so software
// that merely PROBES an optional capability (io_uring, perf, userfaultfd, keyring) keeps working
// instead of being SIGSYS-killed mid-startup. Reserved for deny-but-degrade syscalls (see
// `errno_syscalls`); true escape vectors still kill. `SECCOMP_RET_DATA` masks the errno into the low
// 16 bits of the return value.
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_DATA: u32 = 0x0000_ffff;

// Offsets into `struct seccomp_data`:
//   int   nr;                    // 0
//   __u32 arch;                  // 4
//   __u64 instruction_pointer;   // 8
//   __u64 args[6];               // 16, 24, 32, …
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
/// Low 32 bits of `args[0]`. `BPF_LD|BPF_W|BPF_ABS` loads a 32-bit word, and every `CLONE_NEW*` bit
/// lives in the low half, so this is the whole check on a little-endian target. kern only builds for
/// x86_64 and aarch64 (both little-endian, enforced by [`AUDIT_ARCH`] having no other arm), and on a
/// big-endian port this would have to become 20.
const OFF_ARG0: u32 = 16;

/// The namespace-creating bits of `clone(2)`'s flags. `unshare` and `setns` are in [`denylist`] and
/// hard-kill, but `clone`/`clone3` take the SAME `CLONE_NEW*` flags and reach the same capability, so
/// denying only the first two left the door open: measured inside a box, `unshare(CLONE_NEWUSER)` was
/// SIGSYS-killed while `clone(CLONE_NEWUSER)` succeeded and handed the child a FULL capability set,
/// bounding set included (`CapBnd` 00000110bda4ffff → 000001ffffffffff, all 14 dropped caps back).
///
/// `clone` cannot simply be denied: it is how every program forks, and `fork`, `vfork`,
/// `posix_spawn` and `pthread_create` are all `clone` with no namespace bit set. So the flags are
/// inspected instead, which seccomp CAN do here because they arrive in a REGISTER (`args[0]`) rather
/// than behind a pointer. `clone3` puts them in a `struct clone_args` behind a pointer, which
/// seccomp-BPF cannot dereference at all; it is handled separately, in [`errno_syscalls`].
///
/// `CLONE_NEWTIME` (0x80) is deliberately absent: it is rejected by `clone` itself (it collides with
/// the `CSIGNAL` byte) and is reachable only through `clone3`, which is denied outright.
/// `CLONE_IO` (0x8000_0000) is likewise absent: it shares an io-context, it creates no namespace.
const CLONE_NEW_MASK: u32 = 0x0002_0000  // CLONE_NEWNS
    | 0x0200_0000                        // CLONE_NEWCGROUP
    | 0x0400_0000                        // CLONE_NEWUTS
    | 0x0800_0000                        // CLONE_NEWIPC
    | 0x1000_0000                        // CLONE_NEWUSER
    | 0x2000_0000                        // CLONE_NEWPID
    | 0x4000_0000; // CLONE_NEWNET

/// `AF_VSOCK` address family. Unlike a syscall number, an `AF_*` constant is the SAME on every Linux
/// architecture (kernel UAPI `socket.h`), so a literal is correct on x86_64 and aarch64 alike. A
/// `socket(AF_VSOCK, …)` opens a channel the network namespace does NOT contain: on a host with a
/// `vsock` transport loaded - WSL2, where `VMADDR_CID_HOST` reaches the Windows side - a box could reach
/// the host past its loopback-only netns. It is a REACHABILITY gap, not a privilege escalation, and it
/// is exactly the domain moby's default profile refuses; kern refuses it too (see
/// [`emit_socket_vsock_rule`]), closing the one place its default was wider than moby's on `socket`.
const AF_VSOCK: u32 = 40;

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

/// Dangerous syscalls, denied by NUMBER and killed on sight.
///
/// `clone` is deliberately absent and always will be: it is how every program forks, so denying the
/// number would kill `fork`, `vfork`, `posix_spawn` and `pthread_create` with it. It is filtered on
/// its FLAGS instead, in `build_filter`, against [`CLONE_NEW_MASK`]. `clone3` is absent from this
/// list too but is NOT permitted: its flags sit behind a pointer BPF cannot read, so it is refused
/// wholesale with `ENOSYS` from [`errno_syscalls`], which is the only shape that leaves modern
/// glibc's `clone3`-then-`clone` fallback working.
///
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
fn errno_syscalls() -> [libc::c_long; 11] {
    [
        // `clone3(2)`: the ONLY entry here that is not a deny-but-degrade capability probe, and the
        // reason it is here rather than in `denylist` is a hard limit of seccomp-BPF, not a policy
        // choice. `clone3` takes its flags in a `struct clone_args` behind a POINTER, and a BPF
        // filter cannot dereference memory: there is no way to allow an ordinary `clone3` fork while
        // refusing `clone3(CLONE_NEWUSER)`. The whole call has to go, or the `CLONE_NEW*` denial that
        // `CLONE_NEW_MASK` enforces on `clone` is bypassable by using the newer entry point.
        //
        // `ENOSYS` rather than a kill is what makes that safe, and it is what Docker and podman do
        // for the same reason: every libc that uses `clone3` probes it and falls back to `clone` on
        // `ENOSYS`. glibc 2.34+ does exactly this in `pthread_create`/`posix_spawn`; glibc below 2.34
        // never calls it; musl calls `clone` directly and never `clone3`. Killing here would break
        // `fork` on modern glibc images, which is the one failure mode that takes everything with it.
        libc::SYS_clone3,
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
        // `open_by_handle_at(2)`: opens a file by an OPAQUE handle, bypassing the path + mount-namespace
        // view - the classic container-escape primitive with `CAP_DAC_READ_SEARCH` (a box keeps it,
        // userns-scoped). Already neutered here (`pivot_root` detaches the host mounts, the box overlay
        // returns EOPNOTSUPP to `name_to_handle_at`, and the cap is not effective over host-owned inodes,
        // verified), but denied at the FILTER too so the primitive is closed at the layer rather than
        // left to the cap model - the posture Docker's default reaches by gating it on the dropped cap. A
        // handle-based tool degrades to a path-based open on `ENOSYS`; ordinary workloads never call it.
        // `name_to_handle_at` stays allowed: it only mints a handle, inert without this call to open it.
        libc::SYS_open_by_handle_at,
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

/// Build the BPF program, separately from installing it, so the invariants that are invisible to a
/// reader can be ASSERTED instead of trusted. A jump offset in this program is a raw instruction
/// count: get one wrong and the filter still loads, still runs, and silently permits or refuses the
/// wrong thing. `the_clone_flag_check_is_the_last_block_and_its_jumps_land_correctly` walks the
/// emitted instructions and checks exactly that.
/// The security prologue both filters share, byte-for-byte: validate the arch (mismatch → kill),
/// load the syscall number, kill any x32-ABI call on x86_64 (the number-only match is otherwise
/// bypassable via the x32 alias), and hard-kill every number in the always-dropped set. Extracted so
/// these controls exist ONCE: a change to the arch token, the x32 guard, or the kill set applied to
/// one builder and not the other would silently weaken whichever was missed, and both filters would
/// still load and run. `denylist(allow_nesting)` drops the 5 nesting syscalls for a `--privileged` box.
fn emit_kill_prologue(allow_nesting: bool) -> Vec<libc::sock_filter> {
    let mut prog: Vec<libc::sock_filter> = vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH),
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0), // ==arch → skip the kill below
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        prog.push(jump(BPF_JMP | BPF_JSET | BPF_K, X32_SYSCALL_BIT, 0, 1)); // bit set → next (kill)
        prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }
    for nr in denylist(allow_nesting) {
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 1)); // ==nr → next (kill); else skip
        prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }
    prog
}

/// Emit the `socket(2)` argument rule: `socket(AF_VSOCK, …)` returns `EAFNOSUPPORT` - the exact errno a
/// host with no vsock transport already gives, so a workload that PROBES vsock falls back cleanly rather
/// than dying - while every other address family is allowed. Shared by both the denylist and the
/// allowlist so the two agree by construction.
///
/// Self-contained by design: BOTH exits are an explicit `BPF_RET`, so loading `args[0]` (which clobbers
/// the accumulator that until now held `nr`) is safe - nothing downstream re-reads `nr` for a matched
/// `socket`. A NON-`socket` call takes the `jf = 4` branch and skips the whole block with `nr` intact
/// for the rules that follow, so this may sit before the `clone` flag check or the allow search without
/// disturbing either. NOT gated on `allow_nesting`: a nested runtime never needs `AF_VSOCK`, so a
/// `--privileged` box is refused it too.
fn emit_socket_vsock_rule(prog: &mut Vec<libc::sock_filter>) {
    let eafnosupport = SECCOMP_RET_ERRNO | (libc::EAFNOSUPPORT as u32 & SECCOMP_RET_DATA);
    // nr == socket ? fall through to the 4-instruction body : skip it (jf = 4), nr preserved.
    prog.push(jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_socket as u32,
        0,
        4,
    ));
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0)); // A = domain (low 32 bits of args[0])
    prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AF_VSOCK, 0, 1)); // ==AF_VSOCK → next (errno); else skip 1
    prog.push(stmt(BPF_RET | BPF_K, eafnosupport)); // vsock → EAFNOSUPPORT
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)); // any other domain → allow
}

fn build_filter(allow_nesting: bool) -> Vec<libc::sock_filter> {
    // Arch guard, load nr, x32 kill, and the hard-kill set - shared with the allowlist builder.
    let mut prog = emit_kill_prologue(allow_nesting);
    // 3b. Each deny-but-degrade number: ==nr → return ENOSYS instead of killing. The syscall still
    // never runs (isolation identical to a kill); the caller merely sees "not implemented" and takes
    // its fallback path, so probing software (Redis 8's io_uring, profilers, …) keeps working.
    let errno_ret = SECCOMP_RET_ERRNO | (libc::ENOSYS as u32 & SECCOMP_RET_DATA);
    for nr in errno_syscalls() {
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 1)); // ==nr → next (errno); else skip
        prog.push(stmt(BPF_RET | BPF_K, errno_ret));
    }
    // 3b-vsock. `socket(AF_VSOCK, …)` → EAFNOSUPPORT (the netns does not contain vsock; see
    // `emit_socket_vsock_rule`). Placed while the accumulator still holds `nr`; a non-`socket` call
    // skips it with `nr` intact for the `clone` block below.
    emit_socket_vsock_rule(&mut prog);
    // 3c. `clone(2)` carrying ANY namespace bit → kill; every other `clone` passes untouched.
    //
    // This closes the hole that denying `unshare`/`setns` alone left open: they are not the only way
    // to make a namespace, and `clone` reaches the same capability with the same `CLONE_NEW*` flags.
    // Measured before this block existed: inside a box `unshare(CLONE_NEWUSER)` died with SIGSYS
    // while `clone(CLONE_NEWUSER)` succeeded and the child came back holding every capability kern
    // had just dropped, bounding set included.
    //
    // It MUST be the last block before the default, because loading `args[0]` overwrites the
    // accumulator, which until here holds `nr` for the equality chains above. Nothing after this
    // reads `nr` again, so clobbering it is free; putting the block any earlier would silently
    // break every comparison that follows it.
    //
    // Skipped entirely for a rootless `--privileged` box, for the same reason `nesting_syscalls`
    // relaxes `unshare`/`setns` there: a nested `kern box` (or podman) has to be able to create its
    // namespaces, and doing it through `clone` instead of `unshare` is an implementation detail of
    // whichever runtime is nested. Refusing it here while allowing `unshare` would make the flag
    // work for one runtime and not another.
    if !allow_nesting {
        // != clone → skip the three instructions below and land on the default ALLOW.
        prog.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            libc::SYS_clone as u32,
            0,
            3,
        ));
        prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0)); // A = low 32 bits of flags
        prog.push(jump(BPF_JMP | BPF_JSET | BPF_K, CLONE_NEW_MASK, 0, 1)); // any bit → next (kill)
        prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }
    // 4. Default: allow.
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    prog
}

// Sentinel `k` values marking a `BPF_JA` whose target is the ALLOW / ENOSYS terminal at the end of
// the program. They are patched to real forward offsets once the whole filter is assembled and the
// terminal positions are known. A real jump offset is at most the filter length (~1200), so these
// 4-billion-range sentinels can never collide with a genuine `JA` offset (the left-subtree skips).
const JA_ALLOW: u32 = 0xFFFF_FFFF;
const JA_ENOSYS: u32 = 0xFFFF_FFFE;

/// Collapse a SORTED, deduplicated slice of allowed syscall numbers into its contiguous runs
/// `[(lo, hi), ...]`. moby's allow set is densely contiguous (x86_64: 317 numbers -> 27 runs; aarch64:
/// 274 -> 21), so a binary search over the RUNS emits ~5x fewer cBPF instructions than one over the
/// individual numbers - and the kernel's per-install cost (the cBPF->eBPF JIT and the constant-action
/// bitmap prepare, both O(instructions)) drops with it. A run `[lo, hi]` contains EXACTLY `lo..=hi`,
/// every one of which is in `allow` because the run only extends on a contiguous number, so the
/// classification is identical to a per-number search (proven exhaustively for 0..600 by
/// `allowlist_filter_classifies_every_syscall_as_intended`). Built once per process (the compiled
/// program is cached), never on a per-syscall path.
fn allow_ranges(allow: &[u32]) -> Vec<(u32, u32)> {
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for &n in allow {
        match ranges.last_mut() {
            // Extend the current run iff `n` is the next contiguous number. `allow` is sorted and
            // deduplicated (a filter invariant), so `n > hi` always holds and a run never goes backwards.
            Some((_, hi)) if n == *hi + 1 => *hi = n,
            // A gap (or the first number) opens a new run.
            _ => ranges.push((n, n)),
        }
    }
    // Every run is a subset of `allow` by construction; this asserts the runs also COVER `allow` and
    // nothing else - a widened run would silently ALLOW a denied syscall, the worst filter defect.
    debug_assert!(
        ranges
            .iter()
            .map(|(lo, hi)| (*hi - *lo + 1) as usize)
            .sum::<usize>()
            == allow.len(),
        "allow_ranges must cover every allowed number and no other"
    );
    ranges
}

/// Emit a cBPF binary search over the SORTED `ranges` (contiguous runs of the allow set), APPENDED in
/// place to `out`, testing the accumulator (which holds `nr`). A run `[lo, hi]` matches iff
/// `lo <= nr <= hi`. Same discipline as the per-number search it replaced: every exit is an explicit
/// `BPF_JA` to the ALLOW or ENOSYS terminal (sentinel `k`, patched later), so nothing relies on
/// fall-through; the only real `JA` is the backpatched jump OVER a left subtree to reach the right one,
/// with a RELATIVE offset (correct whatever prefix `out` holds); and the whole search is ONE growing
/// allocation. The subtree-skip uses `JA`'s 32-bit `k`, never a `jt`/`jf` (8-bit), so it cannot overflow.
fn emit_allow_ranges_into(out: &mut Vec<libc::sock_filter>, ranges: &[(u32, u32)]) {
    match ranges {
        [] => out.push(jump(BPF_JMP | BPF_JA, JA_ENOSYS, 0, 0)),
        [(lo, hi)] => {
            // nr < lo -> ENOSYS ; nr > hi -> ENOSYS ; lo <= nr <= hi -> ALLOW.
            out.push(jump(BPF_JMP | BPF_JGE | BPF_K, *lo, 0, 2)); // nr>=lo -> next; else skip 2 -> JA ENOSYS
            out.push(jump(BPF_JMP | BPF_JGT | BPF_K, *hi, 1, 0)); // nr>hi -> skip 1 -> JA ENOSYS; else -> JA ALLOW
            out.push(jump(BPF_JMP | BPF_JA, JA_ALLOW, 0, 0));
            out.push(jump(BPF_JMP | BPF_JA, JA_ENOSYS, 0, 0));
        }
        _ => {
            let mid = ranges.len() / 2;
            let (lo, hi) = ranges[mid];
            // nr > hi -> RIGHT subtree (a real JA, k backpatched to skip the in-range test + the left).
            out.push(jump(BPF_JMP | BPF_JGT | BPF_K, hi, 0, 1)); // nr>hi -> next (JA-to-right); else skip it
            let patch = out.len();
            out.push(jump(BPF_JMP | BPF_JA, 0, 0, 0)); // placeholder: k = jump over left to right, set below
                                                       // here nr <= hi.
            out.push(jump(BPF_JMP | BPF_JGE | BPF_K, lo, 0, 1)); // nr>=lo -> next (JA ALLOW); else skip -> LEFT
            out.push(jump(BPF_JMP | BPF_JA, JA_ALLOW, 0, 0)); // lo <= nr <= hi
            emit_allow_ranges_into(out, &ranges[..mid]); // LEFT: nr < lo falls straight into it
            out[patch].k = (out.len() - patch - 1) as u32; // RIGHT begins right after the left subtree
            emit_allow_ranges_into(out, &ranges[mid + 1..]);
        }
    }
}

/// The ALLOWLIST filter: deny every syscall except a vetted set (OCI/moby's default MINUS kern's 35),
/// the inverse of [`build_filter`]. Structure: arch/x32 guard, the dangerous set KILLED explicitly,
/// the `clone` flag check, then a BINARY SEARCH over the allowed number RANGES - matched → ALLOW, anything
/// else → ENOSYS (a survivable denial, so software probing an unknown/new syscall falls back rather
/// than dying, and the whole future syscall surface is closed by default). This is the SHIPPED
/// DEFAULT (a real-workload corpus validated it); the wider denylist is the opt-out `KERN_SECCOMP=denylist`.
fn build_allowlist_filter(allow_nesting: bool, audit: bool) -> Vec<libc::sock_filter> {
    let allow: &[u32] = crate::seccomp_allow::ALLOW;
    // Same security prologue as the denylist: arch guard, load nr, x32 kill, and the hard-kill set.
    // The dangerous set still HARD-KILLS (not the default ENOSYS): a box that tries `kexec`/`ptrace`/
    // the mount API is hostile, and killing it is the verdict the denylist gives too. Those numbers
    // are excluded from the allow set, so without the explicit kill they would merely ENOSYS.
    let mut prog = emit_kill_prologue(allow_nesting);
    // A rootless `--privileged` box runs a NESTED runtime that must create namespaces, so the five
    // nesting syscalls are re-permitted here (they are NOT in the allow numbers, which exclude all 35
    // kern-denied). Mirrors the denylist's `allow_nesting`, which lets them fall to the default ALLOW.
    if allow_nesting {
        for nr in nesting_syscalls() {
            prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 1)); // ==nesting → next (JA ALLOW)
            prog.push(jump(BPF_JMP | BPF_JA, JA_ALLOW, 0, 0));
        }
    }
    // `socket(AF_VSOCK, …)` → EAFNOSUPPORT, every other domain allowed. Same rule and same reasoning as
    // the denylist, so the two postures agree; self-contained (explicit `RET` exits), so it sits ahead of
    // the clone check and the allow search without disturbing `nr` for a non-`socket` call.
    emit_socket_vsock_rule(&mut prog);
    // `clone` with any `CLONE_NEW*` bit is a namespace-creation vector and dies; a plain `clone`
    // (fork/pthread) is allowed. Skipped under `allow_nesting`, where `clone` is allowed unconditionally
    // via the search. Placed before the search because it inspects `args[0]`, which clobbers `nr`.
    if !allow_nesting {
        prog.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            libc::SYS_clone as u32,
            0,
            4,
        )); // !=clone → skip 4 → search
        prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0)); // A = low 32 bits of clone flags
        prog.push(jump(BPF_JMP | BPF_JSET | BPF_K, CLONE_NEW_MASK, 0, 1)); // any ns bit → next (kill)
        prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
        prog.push(jump(BPF_JMP | BPF_JA, JA_ALLOW, 0, 0)); // clone without a ns bit → allow
    }
    // Collapse the sorted allow numbers into their contiguous RUNS and binary-search the runs, appended
    // straight into `prog` (its every exit is a sentinel `JA` to a terminal). ~5x fewer instructions than
    // searching the individual numbers, so the kernel's per-install cost (cBPF->eBPF JIT + constant-action
    // bitmap prepare, both O(instructions)) drops with it - measured: the seccomp install phase fell from
    // ~385us to ~200us, near the denylist's. Appended in place - no throwaway Vec - offsets are relative.
    let ranges = allow_ranges(allow);
    emit_allow_ranges_into(&mut prog, &ranges);
    // Terminals, in this order: a non-match falls to the DEFAULT-deny terminal, a match jumps to ALLOW.
    // In `audit` mode the default terminal LOGS-and-runs (`SECCOMP_RET_LOG`) instead of `ENOSYS`, so
    // the workload behaves as under the denylist while the would-be-denied syscalls are recorded; the
    // kill set and the allow set are byte-for-byte identical between the two, so audit observes the
    // real allowlist's deny surface and nothing else.
    let default_action = if audit {
        SECCOMP_RET_LOG
    } else {
        SECCOMP_RET_ERRNO | (libc::ENOSYS as u32 & SECCOMP_RET_DATA)
    };
    let enosys_idx = prog.len();
    prog.push(stmt(BPF_RET | BPF_K, default_action));
    let allow_idx = prog.len();
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    // Patch every sentinel `JA` to the real forward offset of its terminal. A `JA`'s `k` is relative
    // to the FOLLOWING instruction, so the offset is `terminal - (i + 1)`. Only sentinel `k` values
    // are patched; a genuine left-subtree `JA` (small `k`) is left untouched.
    for (i, ins) in prog.iter_mut().enumerate() {
        if ins.code == (BPF_JMP | BPF_JA) {
            if ins.k == JA_ALLOW {
                ins.k = (allow_idx - (i + 1)) as u32;
            } else if ins.k == JA_ENOSYS {
                ins.k = (enosys_idx - (i + 1)) as u32;
            }
        }
    }
    prog
}

/// The seccomp posture kern applies to a box, resolved ONCE at box creation and recorded in the
/// instance registry so `kern exec` reproduces the box's OWN filter instead of re-deriving it from a
/// possibly-different environment. Without this, a box started with the deny-by-default allowlist
/// could be entered by an `exec` that silently fell back to the (wider) denylist - the exec'd process
/// would run under a MORE permissive posture than the box's PID 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SeccompFilter {
    /// Allow everything except the always-denied set (kill) and the deny-but-degrade set (ENOSYS).
    /// The WIDER, more permissive posture. Opt-OUT via `KERN_SECCOMP=denylist`, for a workload that
    /// needs a syscall outside moby's allow set (the shipped default is now the allowlist below).
    Denylist,
    /// Deny everything except a vetted allow set (OCI/moby default minus kern's 35); the rest → ENOSYS,
    /// while the escape vectors STILL HARD-KILL (`emit_kill_prologue`, verified: mount/unshare/a
    /// namespace-flagged clone all SIGSYS). This is moby's own default filter - validated by billions of
    /// container starts - MINUS the 35 kern denies for being rootless, so it is at least as compatible
    /// as Docker's default while being strictly narrower. **The shipped default**: deny-by-default, so a
    /// syscall nobody vetted is refused rather than reached. Opt-out with `KERN_SECCOMP=denylist`.
    #[default]
    Allowlist,
    /// Like [`Allowlist`], but the would-be-denied branch LOGS the syscall (`SECCOMP_RET_LOG`) and lets
    /// it RUN instead of returning `ENOSYS`. A VALIDATION aid, NOT a shipped posture, and MORE permissive
    /// than either shipped one: because the terminal action is log-and-run, the syscalls the denylist and
    /// allowlist both refuse with `ENOSYS` (measured: `clone3`, `io_uring_setup`) actually RUN here, so
    /// the box is LESS confined during an audit run than in production. That is the point - the workload
    /// completes instead of failing at the first refused call, so ONE corpus run logs the EXACT set a
    /// real allowlist flip would refuse. The kill set STILL kills (mount, unshare, and a namespace-
    /// flagged clone all SIGSYS, verified), and the allow set still allows silently. Opt-in via
    /// `KERN_SECCOMP=allowlist-audit`.
    AllowlistAudit,
}

impl SeccompFilter {
    /// Resolve from the environment. `KERN_SECCOMP=allowlist` selects the allowlist, `allowlist-audit`
    /// its log-and-run validation variant; anything else (including unset) is the denylist. Called
    /// ONCE, at box creation, by the launcher - NEVER on the `exec` path, which reads the mode the box
    /// recorded so PID 1 and the exec agree by construction.
    pub fn from_env() -> Self {
        // Delegate the token→variant mapping to `parse` (single source of truth); an unset or
        // unrecognised value falls to the `Default` (allowlist).
        std::env::var_os("KERN_SECCOMP")
            .as_deref()
            .and_then(|v| v.to_str())
            .and_then(Self::parse)
            .unwrap_or_default()
    }

    /// Stable one-word registry token.
    pub fn as_str(self) -> &'static str {
        match self {
            SeccompFilter::Denylist => "denylist",
            SeccompFilter::Allowlist => "allowlist",
            SeccompFilter::AllowlistAudit => "allowlist-audit",
        }
    }

    /// Parse a registry token. `None` for an unrecognised token: the caller treats a present-but-
    /// malformed mode as a CORRUPT record and refuses the exec, never as a silent default. A record
    /// with NO mode line at all is a different case (a box from before this field existed), handled
    /// by the caller as the provable denylist, since the allowlist did not exist for that box.
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "denylist" => Some(SeccompFilter::Denylist),
            "allowlist" => Some(SeccompFilter::Allowlist),
            "allowlist-audit" => Some(SeccompFilter::AllowlistAudit),
            _ => None,
        }
    }
}

/// Install the filter: set `NO_NEW_PRIVS` (required for unprivileged seccomp), then load the BPF for
/// `mode`. The mode is passed EXPLICITLY - resolved by the launcher via [`SeccompFilter::from_env`] and
/// carried in the box spec / instance record - so PID 1 and every `exec` into the same box install
/// the identical filter. `allow_nesting` (a rootless `--privileged` box) leaves the namespace +
/// classic-mount syscalls allowed so a nested `kern box` can start; every other dangerous syscall
/// stays blocked.
/// Set once [`install`] has applied a seccomp filter to the CURRENT process (`PR_SET_SECCOMP`
/// returned success). The workload exec path reads it through [`is_installed`] and REFUSES to exec
/// while it is false, a RUNTIME choke point for the setup window: it catches an exec reached through
/// indirection or aliasing (a helper that spawns, `Command as C`, a fn pointer to `libc::fork`) that
/// the lexical `no_untrusted_exec_before_the_seccomp_filter` source guard - one stack frame - cannot
/// see. Per-process and never reset: a `fork` after `install` copies it as `true`, which is correct
/// because that child also inherits the actual kernel filter (seccomp survives fork and exec).
static SECCOMP_INSTALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether a seccomp filter has been installed in THIS process. The workload exec path fails closed
/// unless this is true, so no code path can reach `execvp` before the filter is in force.
/// Syscalls a peer relay half is killed for, installed after it has entered a box and shed its
/// privileges.
///
/// A DENYLIST HERE, WHILE A BOX GETS AN ALLOWLIST, and the asymmetry is deliberate rather than a
/// weaker version of the same thing.
///
/// A box runs arbitrary tenant code, so nothing but "everything not named is refused" is meaningful
/// there. A relay half runs ~1,200 lines of this crate, in a straight line, and PARSES NO TENANT
/// BYTES: it moves descriptors and pumps bytes it never interprets. Its syscall set after setup is
/// exactly `accept`, `sendmsg`, `recvmsg`, `socket`, `bind`, `connect`, `setsockopt`, `poll`, `read`,
/// `write`, `shutdown`, `close`, `clone`, `wait4` and `exit_group`.
///
/// An allowlist over that set would have to be right on every architecture kern publishes, and musl
/// picks syscall spellings per architecture (`fork` against `clone`, `open` against `openat`, `poll`
/// against `ppoll`, `accept` against `accept4`). One missing spelling is a `SIGSYS` on a board rather
/// than a test failure, and it would buy nothing over what is denied here, because the only thing
/// worth taking away from this process is the set below.
///
/// WHAT IT TAKES AWAY IS THE POINT. These halves keep the HOST mount namespace: they are the only
/// processes in a stack with a host filesystem view reachable over a socket from inside a box. That
/// view is worth something only with a syscall that opens, executes, mounts or inspects with it, and
/// after setup this process legitimately uses none of them. Denying them costs nothing that can be
/// measured and removes every primitive an escalation would need.
///
/// `open`/`openat` are in the list even though `enter_box_ns_pinned` uses them, because the filter is
/// installed AFTER the namespaces are entered and nothing opens a file again.
fn relay_denied() -> Vec<libc::c_long> {
    let mut v: Vec<libc::c_long> = vec![
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_openat,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_add_key,
        libc::SYS_keyctl,
    ];
    // `open` and `creat` DO NOT EXIST ON EVERY ARCHITECTURE: aarch64 has only `openat`, so naming
    // them unconditionally would not compile there. Extending from a per-architecture slice rather
    // than pushing inside a `cfg` block keeps `v` mutable on every target; a `cfg` push made the
    // binding needlessly mutable on aarch64 and the build was refused, which is the same
    // "right on the machine I tested on" shape as the `msg_controllen` cast this module's neighbour
    // had to fix.
    v.extend_from_slice(arch_only_denied());
    v
}

/// Denied syscalls that exist only on some architectures.
#[cfg(target_arch = "x86_64")]
fn arch_only_denied() -> &'static [libc::c_long] {
    &[libc::SYS_open, libc::SYS_creat]
}

/// Nothing to add: this architecture reaches the same handlers through `openat`, already denied.
#[cfg(not(target_arch = "x86_64"))]
fn arch_only_denied() -> &'static [libc::c_long] {
    &[]
}

/// Install [`relay_denied`] on the calling process, killing it on any of those syscalls.
///
/// # Errors
///
/// The failing `prctl`, so a caller can refuse to serve unfiltered rather than serve and hope.
pub fn install_relay_filter() -> Result<(), Error> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(Error::last("prctl(NO_NEW_PRIVS)"));
    }
    let mut prog: Vec<libc::sock_filter> = vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH),
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0), // ==arch → skip the kill below
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        // The x32 ABI reaches the same handlers with a bit set, so a filter that only compares the
        // number can be walked past by setting it. Same rule the box filters apply.
        prog.push(jump(BPF_JMP | BPF_JSET | BPF_K, X32_SYSCALL_BIT, 0, 1));
        prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }
    for nr in relay_denied() {
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 1)); // ==nr → next (kill); else skip
        prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
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

pub fn is_installed() -> bool {
    SECCOMP_INSTALLED.load(std::sync::atomic::Ordering::Acquire)
}

pub fn install(mode: SeccompFilter, allow_nesting: bool) -> Result<(), Error> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(Error::last("prctl(NO_NEW_PRIVS)"));
    }

    // The compiled program is a pure function of `(mode, allow_nesting)` and byte-identical for every
    // box, so it is built ONCE per combination and reused (see `cached_program`) instead of rebuilding a
    // multi-KiB `Vec` + a backpatch loop on every box start and every `exec`.
    let prog = cached_program(mode, allow_nesting);
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        // The kernel COPIES the program at `PR_SET_SECCOMP` and never writes through this pointer, so a
        // shared `&'static` view cast to `*mut` is sound.
        filter: prog.as_ptr() as *mut libc::sock_filter,
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
    // The filter is now in force in this process; the exec choke point may proceed. `Release` pairs
    // with the `Acquire` in `is_installed` so a reader that observes `true` also observes the filter.
    SECCOMP_INSTALLED.store(true, std::sync::atomic::Ordering::Release);
    Ok(())
}

/// The compiled BPF program for `(mode, allow_nesting)`, built once per combination and memoized. The
/// program is a pure function of its inputs and byte-identical for every box, so rebuilding a multi-KiB
/// `Vec` (the allowlist is ~10 KiB) plus its relative-backpatch loop on every box start and every `exec`
/// is wasted work. Six combinations exist (3 modes x 2 nesting); each slot fills on first use, thread-safe
/// via `OnceLock` (a single `Acquire` load once warm, no lock on the steady-state path). The returned
/// slice is read-only to the kernel, which copies the program into its own storage at `PR_SET_SECCOMP`.
fn cached_program(mode: SeccompFilter, allow_nesting: bool) -> &'static [libc::sock_filter] {
    use std::sync::OnceLock;
    static SLOTS: [OnceLock<Vec<libc::sock_filter>>; 6] = [
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
    ];
    let mode_idx = match mode {
        SeccompFilter::Denylist => 0,
        SeccompFilter::Allowlist => 1,
        SeccompFilter::AllowlistAudit => 2,
    };
    SLOTS[mode_idx * 2 + allow_nesting as usize]
        .get_or_init(|| match mode {
            SeccompFilter::Allowlist => build_allowlist_filter(allow_nesting, false),
            SeccompFilter::AllowlistAudit => build_allowlist_filter(allow_nesting, true),
            SeccompFilter::Denylist => build_filter(allow_nesting),
        })
        .as_slice()
}

#[cfg(test)]
mod tests {
    use super::{
        build_allowlist_filter, build_filter, denylist, errno_syscalls, install_relay_filter,
        nesting_syscalls, AF_VSOCK, AUDIT_ARCH, BPF_ABS, BPF_JA, BPF_JEQ, BPF_JGE, BPF_JGT,
        BPF_JMP, BPF_JSET, BPF_K, BPF_LD, BPF_RET, BPF_W, CLONE_NEW_MASK, OFF_ARCH, OFF_ARG0,
        OFF_NR, SECCOMP_RET_ALLOW, SECCOMP_RET_DATA, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS,
        SECCOMP_RET_LOG,
    };

    /// A minimal classic-BPF interpreter for the seccomp program: enough opcodes to execute what
    /// `build_allowlist_filter`/`build_filter` emit (LD abs, JEQ/JGT/JSET/JA, RET). Returns the
    /// `SECCOMP_RET_*` value the kernel would. This is the harness that makes the hand-laid-out binary
    /// search VERIFIABLE: it does not matter how intricate the jump layout is if every syscall number
    /// is proven to classify correctly.
    fn run_filter(prog: &[libc::sock_filter], nr: u32, arch: u32, arg0: u64) -> u32 {
        let mut pc = 0usize;
        let mut acc: u32 = 0;
        // A real filter terminates in a few dozen steps; cap to catch a mis-laid-out jump loop.
        for _ in 0..100_000 {
            let ins = prog[pc];
            let jt = ins.jt as usize;
            let jf = ins.jf as usize;
            match ins.code {
                c if c == BPF_LD | BPF_W | BPF_ABS => {
                    acc = match ins.k {
                        x if x == OFF_NR => nr,
                        x if x == OFF_ARCH => arch,
                        x if x == OFF_ARG0 => (arg0 & 0xFFFF_FFFF) as u32,
                        _ => 0,
                    };
                    pc += 1;
                }
                c if c == BPF_JMP | BPF_JA => pc += 1 + ins.k as usize,
                c if c == BPF_JMP | BPF_JEQ | BPF_K => pc += 1 + if acc == ins.k { jt } else { jf },
                c if c == BPF_JMP | BPF_JGT | BPF_K => pc += 1 + if acc > ins.k { jt } else { jf },
                c if c == BPF_JMP | BPF_JGE | BPF_K => pc += 1 + if acc >= ins.k { jt } else { jf },
                c if c == BPF_JMP | BPF_JSET | BPF_K => {
                    pc += 1 + if acc & ins.k != 0 { jt } else { jf }
                }
                c if c == BPF_RET | BPF_K => return ins.k,
                other => panic!("run_filter: unhandled opcode {other:#x} at pc {pc}"),
            }
        }
        panic!("run_filter did not terminate - a jump offset is wrong");
    }

    /// The allowlist array must be SORTED (the binary search's precondition) and must NOT contain any
    /// syscall kern denies (or the search would ALLOW something the kill/ENOSYS logic means to block).
    /// Both are enforced by the generator; this pins them so a hand-edit or a bad regenerate is caught.
    #[test]
    fn the_allow_array_is_sorted_and_excludes_every_denied_syscall() {
        let allow: &[u32] = crate::seccomp_allow::ALLOW;
        assert!(
            allow.windows(2).all(|w| w[0] < w[1]),
            "ALLOW must be strictly sorted for binary search"
        );
        let mut denied: Vec<u32> = denylist(false).iter().map(|&n| n as u32).collect();
        denied.extend(errno_syscalls().iter().map(|&n| n as u32));
        for d in denied {
            assert!(
                allow.binary_search(&d).is_err(),
                "denied syscall {d} leaked into the allow list"
            );
        }
    }

    /// Every generated filter must fit the kernel's `BPF_MAXINSNS` (4096) with headroom, or a future
    /// profile bump would fail to load at box start. Their EXACT sizes are also PINNED so no instruction
    /// count can drift silently (the class that has already produced ~1273, ~1174 and a stale denylist
    /// figure): the allowlist is 178 on x86_64 after the range-merge (173 for a nesting box), the
    /// denylist 86 (72 nesting). A change to an emitter or the ALLOW set fails this test and forces the
    /// ROADMAP/seccomp docs that cite these four numbers to be updated in the same change.
    #[test]
    fn the_seccomp_filter_instruction_counts_are_pinned() {
        for &nesting in &[false, true] {
            for &audit in &[false, true] {
                // `audit` only swaps the default terminal action (ENOSYS vs LOG), never the count.
                let len = build_allowlist_filter(nesting, audit).len();
                assert!(
                    len < 4096,
                    "allowlist filter (nesting={nesting} audit={audit}) is {len} instructions, over BPF_MAXINSNS"
                );
                // The EXACT count is arch-specific (x86_64 has the x32 kill and a 317-number ALLOW set;
                // aarch64 has 274 and no x32), so the pinned figures - the ones the docs cite - are gated
                // to x86_64. aarch64 still gets the fit check above.
                #[cfg(target_arch = "x86_64")]
                {
                    let allow_expected = if nesting { 173 } else { 178 };
                    assert_eq!(
                        len, allow_expected,
                        "x86_64 allowlist instruction count changed (nesting={nesting}): {len} vs \
                         {allow_expected}. If intentional, update ROADMAP.md (cites 178) + the doc-comment."
                    );
                }
            }
            // The denylist counts are cited in the same ROADMAP note (86 / 72), so pin them too - the
            // reviewer's point: the number the docs cite for the denylist had no guard, same drift class.
            let deny = build_filter(nesting).len();
            assert!(
                deny < 4096,
                "denylist filter is {deny} instructions, over BPF_MAXINSNS"
            );
            #[cfg(target_arch = "x86_64")]
            {
                let deny_expected = if nesting { 72 } else { 86 };
                assert_eq!(
                    deny, deny_expected,
                    "x86_64 denylist instruction count changed (nesting={nesting}): {deny} vs \
                     {deny_expected}. If intentional, update ROADMAP.md (cites 86)."
                );
            }
        }
    }

    /// Compiler-free half of the allow-list diff-gate (the profile-vs-names half lives in
    /// `scripts/gen-seccomp-allowlist.py --check`, wired into CI). Ties the tracked decision record
    /// (`seccomp/allow-names.txt`) to the compiled numbers this binary actually uses: the names are
    /// sorted + unique, and this arch's `ALLOW` numbers are a SUBSET of them (a name resolves to at
    /// most one number, and some names do not exist on this arch), so `ALLOW.len() <= names.len()`.
    /// If someone regenerates the numbers but not the sidecar (or the reverse), the counts diverge.
    #[test]
    fn the_allow_names_sidecar_matches_the_compiled_numbers() {
        const SIDECAR: &str = include_str!("../seccomp/allow-names.txt");
        let names: Vec<&str> = SIDECAR
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        assert!(!names.is_empty(), "the allow-names sidecar is empty");
        assert!(
            names.windows(2).all(|w| w[0] < w[1]),
            "allow-names.txt must be strictly sorted and de-duplicated (codepoint order)"
        );
        let allow: &[u32] = crate::seccomp_allow::ALLOW;
        assert!(
            allow.len() <= names.len(),
            "this arch resolves {} numbers but the sidecar lists only {} names - regenerate both",
            allow.len(),
            names.len()
        );
        // The kern-denied vectors must never appear as an allowed NAME (defence in depth alongside the
        // number-level exclusion in `the_allow_array_is_sorted_and_excludes_every_denied_syscall`).
        for denied in [
            "clone3",
            "mount",
            "unshare",
            "setns",
            "ptrace",
            "bpf",
            "pivot_root",
        ] {
            assert!(
                !names.contains(&denied),
                "denied syscall '{denied}' is present in the allow-names sidecar"
            );
        }
    }

    /// EXHAUSTIVE proof that the allowlist filter classifies every syscall as intended: the dangerous
    /// set is KILLED, `clone` is allowed only without a namespace bit, every allowed number is ALLOWED,
    /// and everything else (including the whole unknown/future surface) hits the DEFAULT-deny terminal.
    /// Run for the normal and `--privileged` (nesting) policy AND for both the enforcing (`ENOSYS`) and
    /// the `audit` (`SECCOMP_RET_LOG`) variant: audit must differ from enforcement in EXACTLY one place,
    /// the default terminal, so the audit run observes the real deny surface and nothing else. This is
    /// what makes the hand-rolled binary search safe to trust.
    #[test]
    fn allowlist_filter_classifies_every_syscall_as_intended() {
        let allow: &[u32] = crate::seccomp_allow::ALLOW;
        let enosys = SECCOMP_RET_ERRNO | (libc::ENOSYS as u32 & SECCOMP_RET_DATA);
        let eafnosupport = SECCOMP_RET_ERRNO | (libc::EAFNOSUPPORT as u32 & SECCOMP_RET_DATA);
        let clone = libc::SYS_clone as u32;
        let socket_nr = libc::SYS_socket as u32;

        for &allow_nesting in &[false, true] {
            for &audit in &[false, true] {
                let prog = build_allowlist_filter(allow_nesting, audit);
                let killset: Vec<u32> = denylist(allow_nesting).iter().map(|&n| n as u32).collect();
                let nesting: Vec<u32> = nesting_syscalls().iter().map(|&n| n as u32).collect();
                // The ONLY difference the `audit` flag makes: the default-deny terminal LOGS-and-runs
                // instead of returning ENOSYS. Kill set, allow set and clone flag check are identical.
                let default_deny = if audit { SECCOMP_RET_LOG } else { enosys };

                // The reference verdict, independent of the BPF layout.
                let expect = |nr: u32, arg0: u64| -> u32 {
                    if killset.contains(&nr) {
                        return SECCOMP_RET_KILL_PROCESS;
                    }
                    if allow_nesting && nesting.contains(&nr) {
                        return SECCOMP_RET_ALLOW;
                    }
                    if nr == clone {
                        // Under nesting, clone is allowed unconditionally (via the search). Otherwise
                        // the flag check governs it.
                        if allow_nesting || (arg0 as u32 & CLONE_NEW_MASK) == 0 {
                            return SECCOMP_RET_ALLOW;
                        }
                        return SECCOMP_RET_KILL_PROCESS;
                    }
                    if nr == socket_nr {
                        // The dedicated socket block governs it (NOT the allow search), regardless of
                        // nesting or audit: `AF_VSOCK` → EAFNOSUPPORT, any other domain → ALLOW.
                        if (arg0 as u32) == AF_VSOCK {
                            return eafnosupport;
                        }
                        return SECCOMP_RET_ALLOW;
                    }
                    if allow.binary_search(&nr).is_ok() {
                        return SECCOMP_RET_ALLOW;
                    }
                    default_deny
                };

                // Every syscall number in a generous range, with a plain call, a namespace-creating
                // clone flag word, and the `AF_VSOCK` domain (which only matters for `socket`).
                for nr in 0u32..600 {
                    for &arg0 in &[0u64, CLONE_NEW_MASK as u64, AF_VSOCK as u64] {
                        let got = run_filter(&prog, nr, AUDIT_ARCH, arg0);
                        let want = expect(nr, arg0);
                        assert_eq!(
                            got, want,
                            "nesting={allow_nesting} audit={audit} nr={nr} arg0={arg0:#x}: filter said {got:#x}, expected {want:#x}"
                        );
                    }
                }

                // A syscall arriving under the WRONG architecture is killed before the number is read.
                assert_eq!(
                    run_filter(&prog, libc::SYS_read as u32, AUDIT_ARCH ^ 0x1, 0),
                    SECCOMP_RET_KILL_PROCESS,
                    "a wrong-arch syscall must be killed (audit={audit})"
                );
                // x86_64 only: the x32 alias of an allowed syscall (high bit set) is killed.
                #[cfg(target_arch = "x86_64")]
                assert_eq!(
                    run_filter(
                        &prog,
                        libc::SYS_read as u32 | super::X32_SYSCALL_BIT,
                        AUDIT_ARCH,
                        0
                    ),
                    SECCOMP_RET_KILL_PROCESS,
                    "an x32-ABI syscall must be killed (audit={audit})"
                );
            }
        }
    }

    /// `socket(AF_VSOCK, …)` is the second argument-inspection rule (after `clone`), and the same
    /// invisibility risk applies: a wrong offset or a wrong action would silently leave the vsock reach
    /// open on WSL2. Asserted against the BPF the box actually loads, in both postures, both nesting
    /// modes, and audit, with an offset control (a high-word-only match must NOT trip it).
    #[test]
    fn socket_af_vsock_is_refused_with_eafnosupport_and_nothing_else_is() {
        assert_eq!(
            AF_VSOCK, 40,
            "AF_VSOCK is 40 in the Linux UAPI on every arch"
        );
        let socket_nr = libc::SYS_socket as u32;
        let eafnosupport = SECCOMP_RET_ERRNO | (libc::EAFNOSUPPORT as u32 & SECCOMP_RET_DATA);
        let other_families = [
            libc::AF_INET as u64,  // ordinary networking must keep working
            libc::AF_UNIX as u64,  // local sockets must keep working
            libc::AF_INET6 as u64, // IPv6 too
            0u64,                  // AF_UNSPEC
        ];

        // Every posture the box can install: denylist and allowlist, each with and without nesting, and
        // the allowlist's audit variant. The vsock refusal is an EXPLICIT rule, so it holds even in
        // audit mode (whose default terminal only affects the would-be-denied SEARCH surface).
        let progs = [
            build_filter(false),
            build_filter(true),
            build_allowlist_filter(false, false),
            build_allowlist_filter(true, false),
            build_allowlist_filter(false, true),
            build_allowlist_filter(true, true),
        ];
        for prog in &progs {
            assert_eq!(
                run_filter(prog, socket_nr, AUDIT_ARCH, AF_VSOCK as u64),
                eafnosupport,
                "socket(AF_VSOCK) must return EAFNOSUPPORT in every posture"
            );
            for &fam in &other_families {
                assert_eq!(
                    run_filter(prog, socket_nr, AUDIT_ARCH, fam),
                    SECCOMP_RET_ALLOW,
                    "socket(domain={fam}) (not vsock) must stay allowed"
                );
            }
            // Offset control: AF_VSOCK sitting ONLY in the high 32 bits of args[0] must be read as
            // domain 0, not as vsock - proof the rule keys on the low word `OFF_ARG0` loads.
            assert_eq!(
                run_filter(prog, socket_nr, AUDIT_ARCH, (AF_VSOCK as u64) << 32),
                SECCOMP_RET_ALLOW,
                "AF_VSOCK only in the high word must not be treated as the domain"
            );
        }
    }

    /// `CLONE_NEW_MASK` is the whole point of the argument-inspection rule, and a wrong bit in it is
    /// invisible: too few and a namespace is creatable, too many and ordinary programs die. Pinned
    /// against the kernel's own numbers (`linux/sched.h`) rather than against itself.
    #[test]
    fn clone_new_mask_is_exactly_the_namespace_bits() {
        const CLONE_NEWNS: u32 = 0x0002_0000;
        const CLONE_NEWCGROUP: u32 = 0x0200_0000;
        const CLONE_NEWUTS: u32 = 0x0400_0000;
        const CLONE_NEWIPC: u32 = 0x0800_0000;
        const CLONE_NEWUSER: u32 = 0x1000_0000;
        const CLONE_NEWPID: u32 = 0x2000_0000;
        const CLONE_NEWNET: u32 = 0x4000_0000;
        let want = CLONE_NEWNS
            | CLONE_NEWCGROUP
            | CLONE_NEWUTS
            | CLONE_NEWIPC
            | CLONE_NEWUSER
            | CLONE_NEWPID
            | CLONE_NEWNET;
        assert_eq!(CLONE_NEW_MASK, want, "mask drifted from the kernel's flags");
        assert_eq!(CLONE_NEW_MASK, 0x7E02_0000);

        // Ordinary process creation must NOT trip it, or `fork` dies and everything with it.
        const CLONE_VM: u32 = 0x0000_0100;
        const CLONE_FS: u32 = 0x0000_0200;
        const CLONE_FILES: u32 = 0x0000_0400;
        const CLONE_SIGHAND: u32 = 0x0000_0800;
        const CLONE_VFORK: u32 = 0x0000_4000;
        const CLONE_THREAD: u32 = 0x0001_0000;
        const CLONE_SYSVSEM: u32 = 0x0004_0000;
        const CLONE_SETTLS: u32 = 0x0008_0000;
        const CLONE_PARENT_SETTID: u32 = 0x0010_0000;
        const CLONE_CHILD_CLEARTID: u32 = 0x0020_0000;
        const CLONE_IO: u32 = 0x8000_0000;
        const SIGCHLD: u32 = 17;
        let benign = [
            ("fork", SIGCHLD),
            ("vfork", CLONE_VM | CLONE_VFORK | SIGCHLD),
            (
                "pthread_create",
                CLONE_VM
                    | CLONE_FS
                    | CLONE_FILES
                    | CLONE_SIGHAND
                    | CLONE_THREAD
                    | CLONE_SYSVSEM
                    | CLONE_SETTLS
                    | CLONE_PARENT_SETTID
                    | CLONE_CHILD_CLEARTID,
            ),
            ("posix_spawn", CLONE_VM | CLONE_VFORK | SIGCHLD),
            ("io-context share", CLONE_IO | SIGCHLD),
        ];
        for (what, flags) in benign {
            assert_eq!(
                flags & CLONE_NEW_MASK,
                0,
                "{what} would be SIGSYS-killed by the clone flag check"
            );
        }
        // …and every namespace flag alone must trip it.
        for (what, flag) in [
            ("NEWNS", CLONE_NEWNS),
            ("NEWCGROUP", CLONE_NEWCGROUP),
            ("NEWUTS", CLONE_NEWUTS),
            ("NEWIPC", CLONE_NEWIPC),
            ("NEWUSER", CLONE_NEWUSER),
            ("NEWPID", CLONE_NEWPID),
            ("NEWNET", CLONE_NEWNET),
        ] {
            assert_ne!(
                (flag | SIGCHLD) & CLONE_NEW_MASK,
                0,
                "clone(CLONE_{what}) would slip through"
            );
        }
    }

    /// The clone block reads `args[0]`, which OVERWRITES the accumulator that every equality
    /// comparison before it depends on. It is therefore only correct as the final block, and its two
    /// jumps have to land on exactly the right instructions. Both facts are invisible when reading
    /// the emitter, so they are walked here on the instructions it actually produces.
    #[test]
    fn the_clone_flag_check_is_the_last_block_and_its_jumps_land_correctly() {
        let prog = build_filter(false);
        let n = prog.len();
        assert!(n >= 5, "program too short: {n}");

        // Layout of the tail, counted back from the end:
        //   n-5  JEQ nr == SYS_clone      jt=0 (fall through), jf=3 (→ the final ALLOW)
        //   n-4  LD  args[0] low word
        //   n-3  JSET CLONE_NEW_MASK      jt=0 (→ KILL),       jf=1 (→ the final ALLOW)
        //   n-2  RET KILL_PROCESS
        //   n-1  RET ALLOW
        let jeq = prog[n - 5];
        assert_eq!(
            jeq.code,
            BPF_JMP | BPF_JEQ | BPF_K,
            "instruction n-5 is not the clone equality test"
        );
        assert_eq!(jeq.k, libc::SYS_clone as u32, "n-5 does not test SYS_clone");
        assert_eq!(
            jeq.jt, 0,
            "on a match it must fall through to the flag load"
        );
        assert_eq!(
            jeq.jf as usize, 3,
            "on a non-match it must skip to the default ALLOW"
        );
        // The false branch must land EXACTLY on the last instruction, and that must be the ALLOW.
        assert_eq!(n - 5 + 1 + jeq.jf as usize, n - 1, "jf lands off the ALLOW");

        let ld = prog[n - 4];
        assert_eq!(ld.code, BPF_LD | BPF_W | BPF_ABS, "n-4 is not a word load");
        assert_eq!(ld.k, OFF_ARG0, "n-4 loads the wrong seccomp_data offset");

        let jset = prog[n - 3];
        assert_eq!(jset.code, BPF_JMP | BPF_JSET | BPF_K, "n-3 is not a JSET");
        assert_eq!(jset.k, CLONE_NEW_MASK, "n-3 tests the wrong mask");
        assert_eq!(jset.jt, 0, "a set bit must fall through to the kill");
        assert_eq!(jset.jf as usize, 1, "no set bit must skip to the ALLOW");
        assert_eq!(
            n - 3 + 1 + jset.jf as usize,
            n - 1,
            "jf lands off the ALLOW"
        );

        assert_eq!(prog[n - 2].code, BPF_RET | BPF_K, "n-2 is not a return");
        assert_eq!(prog[n - 2].k, SECCOMP_RET_KILL_PROCESS, "n-2 does not kill");
        assert_eq!(prog[n - 1].code, BPF_RET | BPF_K, "n-1 is not a return");
        assert_eq!(prog[n - 1].k, super::SECCOMP_RET_ALLOW, "n-1 is not ALLOW");

        // Nothing after the clone block may read `nr`: the accumulator no longer holds it.
        // Equivalently, the block is last, which the offsets above already pin.
    }

    /// A rootless `--privileged` box omits the clone flag check, for the same reason it omits
    /// `unshare`/`setns`: a nested runtime has to create its namespaces, and which syscall it picks
    /// is its own business. The relaxation must be EXACTLY that and nothing else.
    #[test]
    fn privileged_omits_the_clone_check_and_nothing_more() {
        let strict = build_filter(false);
        let nested = build_filter(true);
        assert!(
            nested.len() < strict.len(),
            "privileged must emit fewer instructions"
        );
        // 4 instructions for the clone block, plus 2 per omitted nesting syscall.
        let expected_drop = 4 + 2 * nesting_syscalls().len();
        assert_eq!(
            strict.len() - nested.len(),
            expected_drop,
            "privileged relaxed something other than the clone block + the nesting set"
        );
        // The nested program must NOT contain a JSET on the namespace mask anywhere.
        assert!(
            !nested
                .iter()
                .any(|i| i.code == (BPF_JMP | BPF_JSET | BPF_K) && i.k == CLONE_NEW_MASK),
            "the clone flag check survived into the privileged filter"
        );
        // …while the strict one must contain exactly one.
        assert_eq!(
            strict
                .iter()
                .filter(|i| i.code == (BPF_JMP | BPF_JSET | BPF_K) && i.k == CLONE_NEW_MASK)
                .count(),
            1,
            "the clone flag check must appear exactly once"
        );
    }

    /// Every number the filter emits is cast `c_long as u32`, and every length is cast
    /// `usize as u16`. Both casts are safe for the values that exist today and neither is checked at
    /// run time, so the invariant is pinned here instead. They are not cosmetic:
    ///
    /// * a syscall number that did not fit `u32` would be emitted TRUNCATED, so the filter would
    ///   compare against a number nothing calls and the syscall it was meant to deny would be
    ///   allowed. Silently, with the entry still visibly present in [`denylist`];
    /// * a program longer than `u16::MAX` would have its length wrap, and the kernel would load a
    ///   TRUNCATED filter, permitting everything past the cut. The kernel's own `BPF_MAXINSNS`
    ///   (4096) rejects such a program first, which is a guard we do not own, so the margin to it is
    ///   asserted here as well.
    #[test]
    fn every_emitted_number_and_length_survives_its_cast() {
        const BPF_MAXINSNS: usize = 4096;
        let numbers: Vec<libc::c_long> = denylist(false)
            .into_iter()
            .chain(denylist(true))
            .chain(errno_syscalls())
            .chain(nesting_syscalls())
            .chain(std::iter::once(libc::SYS_clone))
            .collect();
        assert!(!numbers.is_empty());
        for nr in numbers {
            assert!(
                nr > 0,
                "syscall number {nr} is not positive: the cast to u32 would wrap"
            );
            assert!(
                u32::try_from(nr).is_ok(),
                "syscall number {nr} does not fit u32: the emitted filter constant would be truncated"
            );
        }
        for nesting in [false, true] {
            let n = build_filter(nesting).len();
            assert!(
                n < BPF_MAXINSNS,
                "filter is {n} instructions, at or past the kernel's BPF_MAXINSNS ({BPF_MAXINSNS}): \
                 prctl would refuse to load it"
            );
            assert!(
                u16::try_from(n).is_ok(),
                "filter is {n} instructions, which does not fit the u16 `sock_fprog.len`: the \
                 kernel would load a truncated program and allow everything past the cut"
            );
            // Ample margin, so this fails while there is still room to think rather than on the
            // release that finally crosses the line.
            assert!(
                n < BPF_MAXINSNS / 4,
                "filter grew to {n} instructions, over a quarter of BPF_MAXINSNS"
            );
        }
    }

    /// `clone3` has to be denied by NUMBER, because its flags are behind a pointer BPF cannot read.
    /// It must be in the ENOSYS set and not the kill set: killing it breaks `fork` on any glibc that
    /// probes `clone3` first, which is every glibc from 2.34 on.
    #[test]
    fn clone3_is_denied_by_enosys_not_by_a_kill() {
        assert!(
            errno_syscalls().contains(&libc::SYS_clone3),
            "clone3 must be denied: it is the pointer-argument bypass of the clone flag check"
        );
        assert!(
            !denylist(false).contains(&libc::SYS_clone3),
            "clone3 in the KILL set would break fork on glibc >= 2.34, which probes it first"
        );
        assert!(
            !denylist(true).contains(&libc::SYS_clone3),
            "clone3 must not be in the kill set for a privileged box either"
        );
        // `clone` itself must NEVER be denied by number: that is how every program forks.
        assert!(
            !denylist(false).contains(&libc::SYS_clone),
            "clone must not be denied by number, only by flags"
        );
        assert!(
            !errno_syscalls().contains(&libc::SYS_clone),
            "clone must not be ENOSYS'd either"
        );
    }

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

    /// The syscall counts the documentation publishes are the counts the filter actually has.
    ///
    /// This exists because they drifted, and in the direction that flatters us. `SECURITY.md` said
    /// "**33 syscalls denied**: 24 that hard-kill plus the 9 that return `ENOSYS`" in one paragraph
    /// and "`ENOSYS` moves five syscalls" two paragraphs later: five is the number of FAMILIES
    /// (io_uring, userfaultfd, perf_event_open, the keyring, syslog), nine is the number of calls,
    /// and the page therefore offered 5 + 24 = 29 against its own 33. An outside security audit read
    /// the smaller number and repeated it, which is the whole problem with a count that lives only
    /// in prose: it understated a deliberate weakening by four syscalls, in the very section that
    /// analyses that weakening.
    ///
    /// A number in a security document has to be able to fail a build. Skip-graceful: the repo root
    /// is found by walking up, so a checkout without the docs (a packaged crate) does not fail here.
    #[test]
    fn the_syscall_counts_in_the_docs_match_the_filter() {
        let kill = denylist(false).len();
        let errno = errno_syscalls().len();
        let total = kill + errno;
        let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        while !dir.join("SECURITY.md").is_file() {
            if !dir.pop() {
                eprintln!("skip: no SECURITY.md above CARGO_MANIFEST_DIR");
                return;
            }
        }
        // The word form of the ENOSYS count, for the prose that spells it out instead of writing a
        // digit. `clone3` joining the set turned "Nine" into "Ten" in three separate paragraphs.
        let word = match errno {
            9 => "Nine",
            10 => "Ten",
            11 => "Eleven",
            12 => "Twelve",
            _ => "UNMAPPED-COUNT-add-the-word-here",
        };
        let expect: [(&str, Vec<String>); 3] = [
            (
                "SECURITY.md",
                vec![
                    format!("**{total} escape syscalls**"),
                    format!("{kill} that hard-kill"),
                    format!("the {errno} that return"),
                    // SECURITY.md said "**34 syscalls denied**" in one bullet and "9 plus 24 is the
                    // 33" two paragraphs below, having been half-updated when `clone3` joined. Only
                    // the first was covered here, so the file contradicted itself through a release.
                    // The prose count is now pinned too.
                    format!(
                        "{word}, in {} families",
                        match errno {
                            10 => "six",
                            11 => "seven",
                            _ => "?",
                        }
                    ),
                ],
            ),
            ("README.md", vec![format!("kern's {total} escape syscalls")]),
            // ROADMAP.md states the ENOSYS count in words, and it went stale the moment `clone3`
            // joined the set: the file said "Nine denied syscalls" while the filter denied ten. It
            // was not covered here, which is exactly why nobody noticed. Word forms are checked
            // rather than digits because that is how the page is written.
            ("ROADMAP.md", vec![format!("{word} denied syscalls")]),
        ];
        for (file, needles) in expect {
            let path = dir.join(file);
            let Ok(text) = std::fs::read_to_string(&path) else {
                eprintln!("skip: cannot read {}", path.display());
                continue;
            };
            // Collapse whitespace before searching. These pages are hard-wrapped at 100 columns, so a
            // needle only had to straddle a line break to stop matching, and the test would then be
            // green because the prose was REFLOWED rather than because it was right.
            let text: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
            for needle in needles {
                let needle = needle.split_whitespace().collect::<Vec<_>>().join(" ");
                assert!(
                    text.contains(&needle),
                    "{file} no longer contains {needle:?}. The filter denies {total} syscalls \
                     ({kill} by SIGSYS, {errno} by ENOSYS); update the prose to match the code, \
                     not the other way round."
                );
            }
        }
    }

    /// The range-merged allowlist is correct only if the runs cover EXACTLY the allow set: a run that
    /// reached one number past the set would silently PERMIT a denied syscall - the worst filter defect.
    /// Verify against whichever `ALLOW` this build compiled (x86_64 or aarch64): every run ascending and
    /// non-inverted, runs gap-separated (adjacent runs would mean a missed merge), every number inside a
    /// run present in the set, and the runs covering the set exactly.
    #[test]
    fn allow_ranges_partition_the_allow_set_exactly() {
        let allow = crate::seccomp_allow::ALLOW;
        let set: std::collections::BTreeSet<u32> = allow.iter().copied().collect();
        let ranges = super::allow_ranges(allow);
        let mut prev_hi: Option<u32> = None;
        let mut covered = 0usize;
        for (lo, hi) in &ranges {
            assert!(lo <= hi, "a run must not be inverted: {lo}..{hi}");
            if let Some(p) = prev_hi {
                assert!(
                    *lo > p + 1,
                    "runs must be gap-separated, not adjacent: {p} then {lo}"
                );
            }
            for n in *lo..=*hi {
                assert!(
                    set.contains(&n),
                    "run {lo}..{hi} includes {n}, which is NOT in the allow set"
                );
            }
            prev_hi = Some(*hi);
            covered += (*hi - *lo + 1) as usize;
        }
        assert_eq!(
            covered,
            set.len(),
            "the runs must cover every allowed number and no other"
        );
    }

    /// The `OnceLock` cache in `install` must serve the SAME bytes a fresh build would, for every
    /// `(mode, allow_nesting)` - a drift would install a filter different from the one every other test
    /// in this file validates, silently.
    #[test]
    fn cached_program_is_byte_identical_to_a_fresh_build() {
        for mode in [
            super::SeccompFilter::Denylist,
            super::SeccompFilter::Allowlist,
            super::SeccompFilter::AllowlistAudit,
        ] {
            for nesting in [false, true] {
                let fresh = match mode {
                    super::SeccompFilter::Allowlist => build_allowlist_filter(nesting, false),
                    super::SeccompFilter::AllowlistAudit => build_allowlist_filter(nesting, true),
                    super::SeccompFilter::Denylist => build_filter(nesting),
                };
                let cached = super::cached_program(mode, nesting);
                assert_eq!(
                    cached.len(),
                    fresh.len(),
                    "{mode:?} nesting={nesting}: cached program length differs from a fresh build"
                );
                // `libc::sock_filter` is a POD without `PartialEq`, so compare its four fields.
                for (i, (c, f)) in cached.iter().zip(fresh.iter()).enumerate() {
                    assert!(
                        c.code == f.code && c.jt == f.jt && c.jf == f.jf && c.k == f.k,
                        "{mode:?} nesting={nesting}: cBPF instruction {i} differs from a fresh build"
                    );
                }
            }
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

    /// THE RELAY FILTER KILLS ON A DENIED CALL AND LETS THE RELAY'S OWN WORK THROUGH.
    ///
    /// Both halves are asserted in one forked child, because a filter that allows everything would
    /// pass the second half alone and a filter that kills everything would pass the first alone.
    ///
    /// The denied call under test is `openat`, which is the one that matters: these halves keep the
    /// HOST mount namespace, so opening a file is the primitive that makes that view worth anything.
    /// The permitted calls under test are a socketpair and a byte through it, which is the shape of
    /// everything a half does after setup.
    ///
    /// Runs in a forked child because the filter is irreversible and installing it in the test
    /// process would silently constrain every later test in this binary.
    #[test]
    fn the_relay_filter_kills_on_openat_and_allows_the_relay_s_own_syscalls() {
        let mut fds = [0i32; 2];
        // SAFETY: fills a two-element array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
        // SAFETY: fork in a test binary; the child only makes the calls named below.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            // SAFETY: the read end belongs to the parent.
            unsafe { libc::close(fds[0]) };
            if install_relay_filter().is_err() {
                let m = b"noinstall";
                // SAFETY: writes a static buffer to a descriptor this child owns.
                unsafe {
                    libc::write(fds[1], m.as_ptr() as *const libc::c_void, m.len());
                    libc::_exit(0);
                }
            }
            // THE ALLOWED HALF FIRST, so a child killed on these would report nothing and the parent
            // would see the same "no message" as a child killed on `openat`. Reporting "ok" before
            // the denied call is what separates the two outcomes.
            let mut sp = [0i32; 2];
            // SAFETY: fills a two-element array.
            let made =
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sp.as_mut_ptr()) };
            let byte = b"x";
            // SAFETY: descriptors this child owns, one byte from a buffer it owns.
            let moved = unsafe {
                libc::write(sp[1], byte.as_ptr() as *const libc::c_void, 1);
                let mut got = [0u8; 1];
                libc::read(sp[0], got.as_mut_ptr() as *mut libc::c_void, 1)
            };
            let m = if made == 0 && moved == 1 {
                b"ok"
            } else {
                b"no"
            };
            // SAFETY: writes a static buffer to a descriptor this child owns.
            unsafe { libc::write(fds[1], m.as_ptr() as *const libc::c_void, m.len()) };
            // AND NOW THE DENIED ONE. `std::fs` would work equally well; the raw call is used so the
            // syscall under test is the one named in the filter and not whatever a wrapper chooses.
            let path = b"/etc/passwd\0";
            // SAFETY: a NUL-terminated path in this child's own memory.
            unsafe {
                libc::openat(
                    libc::AT_FDCWD,
                    path.as_ptr() as *const libc::c_char,
                    libc::O_RDONLY,
                );
                // Unreachable if the filter works. Reaching it is the failure the parent reports.
                let m = b" survived";
                libc::write(fds[1], m.as_ptr() as *const libc::c_void, m.len());
                libc::_exit(0);
            }
        }
        // SAFETY: the write end belongs to the child.
        unsafe { libc::close(fds[1]) };
        let mut buf = [0u8; 64];
        // SAFETY: reads at most `buf.len()` into a buffer this function owns.
        let n = unsafe { libc::read(fds[0], buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        let mut st: libc::c_int = 0;
        // SAFETY: waits on this process's own child.
        unsafe {
            libc::close(fds[0]);
            libc::waitpid(pid, &mut st, 0);
        }
        let msg = String::from_utf8_lossy(&buf[..n.max(0) as usize]).to_string();
        if msg.starts_with("noinstall") {
            eprintln!("skip: this host refuses PR_SET_SECCOMP");
            return;
        }
        assert!(
            msg.starts_with("ok"),
            "the filter must let a socketpair and a byte through: {msg:?}"
        );
        assert!(
            !msg.contains("survived"),
            "openat must not return under the relay filter: {msg:?}"
        );
        // `SIGSYS` is the signal a `SECCOMP_RET_KILL_PROCESS` delivers.
        assert!(
            libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == libc::SIGSYS,
            "the child must die of SIGSYS, not exit: status {st}"
        );
    }
}
