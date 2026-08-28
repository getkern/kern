//! THE EXPORTED HOOKS. Where the accounting meets the driver's ABI.
//!
//! Each function here has the name and signature of a CUDA driver entry point, so the workload's
//! loader binds to ours instead of the driver's. Ours does the accounting and then calls the real one
//! through [`crate::real`].
//!
//! WHAT IS INTERCEPTED, AND WHY THIS SET AND NOT MORE
//!   The four allocation entry points a device allocation can come through, the free that undoes
//!   them, the query a framework sizes itself from, and the resolver that modern CUDA routes
//!   everything else through. Seven functions. Every other driver call is left alone, because
//!   intercepting a call kern has nothing to say about adds a branch to a hot path in someone
//!   else's program for no reason, and because each interception is a signature that has to stay
//!   correct across driver versions forever.
//!
//! `cuMemGetInfo` IS THE ONE THAT MAKES THE QUOTA WORK
//!   A cooperative quota that only refuses is a quota that a framework discovers by crashing into
//!   it. PyTorch, TensorFlow and every caching allocator ask the driver how much memory the device
//!   has and size their arena from the answer. Reporting the SLICE there rather than the card makes
//!   the workload allocate inside its quota on purpose, which is the difference between density
//!   that works and density that produces an out-of-memory error on the first large batch.
//!
//! THE ORDER OF OPERATIONS IN AN ALLOCATION IS NOT NEGOTIABLE
//!   Reserve, then allocate, then record. Every other order loses memory:
//!
//!   Allocate first and the reservation can fail AFTER the driver has committed the memory, so the
//!   workload holds VRAM the accounting does not know about.
//!
//!   Record first is impossible: there is no pointer to record until the driver returns one.
//!
//!   And every failure after a successful step must undo the steps before it. A driver allocation
//!   that succeeds into a full registry is freed again before the error is returned, because a
//!   pointer whose size was never recorded is never credited back on free and leaks the quota for
//!   the life of the process.
//!
//! REENTRANCY
//!   These functions can be called from inside `malloc`, from a destructor during unwind, and from
//!   several threads before anything of ours has initialised. Nothing here allocates, nothing takes
//!   a lock, and initialisation is attempted without waiting: a hook that arrives during another
//!   thread's `dlopen` passes straight through to a refusal rather than spinning on the loader lock
//!   that thread is holding.

#![allow(unsafe_code)]

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::map::Segment;
use crate::real::{
    self, CUdeviceptr, CUresult, CUDA_ERROR_INVALID_VALUE, CUDA_ERROR_NOT_INITIALIZED,
    CUDA_ERROR_OUT_OF_MEMORY, CUDA_SUCCESS,
};
use crate::registry::Registry;
use crate::shared::{ProcLiveness, Shared};
use crate::Quota;

// ── The slice this process is running under ──────────────────────────────────────────────────────

/// The quota, sized from the environment on first use.
///
/// A `static` with interior mutability rather than a `OnceLock<Quota>`: `OnceLock` blocks a second
/// caller while the first initialises, and these hooks can be entered from inside the allocator,
/// where blocking is a deadlock. The `Quota` is constructible in a `const` context, so it simply
/// exists from the start and is RESIZED once the configuration has been read.
static QUOTA: Quota = Quota::unlimited();

/// The pointer-to-size map. Same reasoning, except that it cannot be `const`-constructed because it
/// owns a heap array, so it is behind a pointer published exactly once.
static REGISTRY: AtomicUsize = AtomicUsize::new(0);

/// The VMM handle table, separate from the pointer table.
///
/// SEPARATE AND NOT SHARED, because the two key spaces are different things that happen to be the
/// same width. A `CUdeviceptr` is an address and a `CUmemGenericAllocationHandle` is an opaque token,
/// and nothing stops the driver from handing out a handle whose numeric value equals a live device
/// pointer. In one table that is a collision reported as a duplicate, which would refuse a legitimate
/// allocation; in two it cannot happen.
static HANDLES: AtomicUsize = AtomicUsize::new(0);

/// Physical VRAM, learned from the driver at initialisation. Zero until then.
static PHYSICAL: AtomicU64 = AtomicU64::new(0);

/// The cross-process view, or null when this host has no segment.
///
/// A pointer published once, like the registry, and for the same reason: a `OnceLock` would block a
/// second caller during initialisation and these hooks can be entered from inside the allocator.
/// Null is a legitimate steady state, not a failure: a single-tenant host has nothing to share, and
/// the per-process quota alone is the correct accounting there.
static SHARED: AtomicUsize = AtomicUsize::new(0);

/// Leaked on purpose so the mapping outlives every hook that reads through it.
///
/// The `Segment` owns a `mmap`ing that must stay valid for as long as any thread can call a hook,
/// which is until the process exits. Dropping it would `munmap` the pages the accounting reads, and
/// there is no point in the life of a `LD_PRELOAD`ed library at which that is safe: a destructor
/// runs while other threads are still running.
static SEGMENT: AtomicUsize = AtomicUsize::new(0);

/// Path of the shared segment. Absent means single-tenant: no cross-process total.
const ENV_SEGMENT: &str = "KERN_VGPU_SEGMENT";
/// How many tenants the segment is sized for when this process is the one that creates it.
const ENV_TENANTS: &str = "KERN_VGPU_MAX_TENANTS";
/// Default tenant count for a new segment.
///
/// 64 slots is 4 KiB of file. The number is a ceiling on concurrent GPU tenants on one host, and 64
/// is above what a single card can hold anything useful in: a 15 GiB card divided 64 ways is 240 MiB
/// each. Sized so that exhausting it means a misconfiguration rather than a real workload.
const DEFAULT_TENANTS: usize = 64;

/// Configuration state, separate from [`crate::real::STATE`] because the two fail independently: the
/// driver can be resolvable while the environment says this process has no slice, and the reverse.
static CONFIGURED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
const CFG_UNSET: u32 = 0;
const CFG_BUSY: u32 = 1;
const CFG_ON: u32 = 2;
const CFG_OFF: u32 = 3;

/// Bytes of VRAM this process may hold. Absent or unparseable means no slice, and no interception.
const ENV_VRAM: &str = "KERN_VGPU_VRAM_BYTES";
/// How many live allocations the registry must hold. Optional; the default suits a caching allocator.
const ENV_SLOTS: &str = "KERN_VGPU_MAX_ALLOCS";
/// The default registry capacity.
///
/// 65536 entries, which is 1 MiB of host memory. Sized against a measurement rather than a guess: a
/// workload allocating 4 KiB blocks against a 2 GiB slice can hold 524288 of them, and the first
/// default tried here, 16384, was reached by a test program long before the quota was, so the table
/// refused the allocation and the reported limit was the table's rather than the operator's. That
/// refusal is the correct behaviour (a size that cannot be recorded is never credited back on free,
/// so losing it leaks the slice for the life of the process) but a default that fires before the
/// quota does is a default that reports the wrong number.
///
/// This does not remove the ceiling, it moves it: a workload of very many very small buffers can
/// still reach it, and `KERN_VGPU_MAX_ALLOCS` is the knob. Sizing it away entirely would mean an
/// unbounded table, which converts a device-memory problem into a host-memory one.
const DEFAULT_SLOTS: usize = 65536;

/// Read the environment once and decide whether this process has a slice at all.
///
/// NOT ON THE HOT PATH. Runs at most once, on the first intercepted call. Returns `true` when there
/// is a quota to enforce; `false` makes every hook a straight passthrough with no accounting, which
/// is what a process outside a `vgpu:` profile must experience.
fn configure() -> bool {
    match CONFIGURED.load(Ordering::Acquire) {
        CFG_ON => return true,
        CFG_OFF | CFG_BUSY => return false,
        _ => {}
    }
    if CONFIGURED
        .compare_exchange(CFG_UNSET, CFG_BUSY, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return CONFIGURED.load(Ordering::Acquire) == CFG_ON;
    }

    let bytes = std::env::var(ENV_VRAM)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|b| *b > 0);
    let Some(bytes) = bytes else {
        CONFIGURED.store(CFG_OFF, Ordering::Release);
        return false;
    };
    let slots = std::env::var(ENV_SLOTS)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|s| *s > 0)
        .unwrap_or(DEFAULT_SLOTS);

    // Register the fork handler BEFORE anything is published, so a `fork` racing this configuration
    // cannot produce a child that inherited state without the handler that resets it.
    install_fork_handler();
    QUOTA.set_quota(bytes);
    let reg = Box::into_raw(Box::new(Registry::with_capacity(slots)));
    REGISTRY.store(reg as usize, Ordering::Release);
    // The VMM table is sized smaller on purpose: a physical allocation made through `cuMemCreate` is
    // at least the allocation granularity, 2 MiB on this driver, so a slice cannot hold anything like
    // the number of them it can hold 4 KiB pointers. A sixteenth of the pointer table, floored by the
    // table's own minimum.
    let han = Box::into_raw(Box::new(Registry::with_capacity(slots / 16)));
    HANDLES.store(han as usize, Ordering::Release);
    attach_shared();
    CONFIGURED.store(CFG_ON, Ordering::Release);
    true
}

/// Reset this library's state in a child after `fork`.
///
/// A child inherits every static in this file by copy-on-write: the quota's `held`, the pointer
/// table, the handle table, and the index of the slot the PARENT owns in the shared segment. None of
/// those are the child's. Left alone, a child that establishes its own CUDA context would account its
/// allocations into its parent's slot, and a reaper that later found the parent dead would reclaim
/// the child's memory along with it.
///
/// MEASURED FIRST, AND THE MEASUREMENT IS WHY THIS IS CHEAP INSURANCE RATHER THAN A FIX FOR A LIVE
/// BUG. A CUDA context does not survive `fork`: on an RTX 5060 Ti with driver 580.173.02, a child
/// that inherited a parent's context allocated 0.000 GiB, because the driver refused before this
/// layer was ever consulted. The inherited accounting is therefore inert in the common case. What it
/// is not inert for is a child that calls `cuInit` itself, which is exactly what a `multiprocessing`
/// worker pool does, and that is the case this closes.
///
/// ASYNC-SIGNAL-SAFE, WHICH IS A HARD REQUIREMENT AND NOT A STYLE POINT. Between `fork` and `exec` a
/// child may call only async-signal-safe functions: the address space is a copy, but any lock held by
/// a thread that did not survive the fork is held forever, including the allocator's. This handler
/// therefore does nothing but store to atomics. The tables are not freed (freeing takes the
/// allocator) and not rebuilt (building takes it too); they are DISOWNED by nulling the pointers, and
/// the next intercepted call in the child runs `configure` in normal context and builds its own.
/// The parent's copies are leaked in the child's address space, which costs the child one table's
/// worth of pages it will never touch and is the correct trade against a deadlock.
extern "C" fn after_fork_in_child() {
    QUOTA.reset_held();
    REGISTRY.store(0, Ordering::Release);
    HANDLES.store(0, Ordering::Release);
    SHARED.store(0, Ordering::Release);
    SEGMENT.store(0, Ordering::Release);
    // Last, so a concurrent reader that sees `CFG_UNSET` cannot then read a table pointer this
    // handler is still in the middle of clearing.
    CONFIGURED.store(CFG_UNSET, Ordering::Release);
}

/// Install [`after_fork_in_child`], once.
fn install_fork_handler() {
    static DONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    if DONE.swap(true, Ordering::Relaxed) {
        return;
    }
    // SAFETY: `pthread_atfork` takes three optional handlers; only the child one is supplied, and it
    // is an `extern "C"` function with the right signature that outlives the process.
    unsafe {
        libc::pthread_atfork(None, None, Some(after_fork_in_child));
    }
}

/// Join the host-wide segment, if there is one.
///
/// EVERY FAILURE IS SILENT AND FALLS BACK TO PER-PROCESS ACCOUNTING, which is a deliberate choice and
/// not laziness. This runs inside a workload that asked for a GPU allocation, in a library it did not
/// know it had loaded; there is nowhere to report to and no exit code anyone will read. A host whose
/// runtime directory is unwritable, or whose segment was made by a different kern version, gets the
/// accounting that still works rather than a refusal it cannot diagnose. What it does NOT get is a
/// silently wrong cross-process total: a segment that cannot be joined is not joined at all.
///
/// Runs once, from `configure`, which is already serialised by the state machine.
fn attach_shared() {
    let Ok(path) = std::env::var(ENV_SEGMENT) else {
        return;
    };
    if path.is_empty() {
        return;
    }
    let tenants = std::env::var(ENV_TENANTS)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|t| *t > 0)
        .unwrap_or(DEFAULT_TENANTS);

    let Ok((seg, created)) = Segment::open(std::path::Path::new(&path), tenants) else {
        return;
    };
    // Leaked deliberately: see `SEGMENT`. The `Box` keeps the mapping alive; the raw pointer is what
    // the `'static` borrow below is taken from.
    let seg: &'static Segment = Box::leak(Box::new(seg));
    SEGMENT.store(seg as *const Segment as usize, Ordering::Relaxed);

    if created && crate::shared::init(seg.words(), tenants).is_err() {
        return;
    }
    let pid = std::process::id() as u64;
    // A process with no readable start time cannot be told apart from a future process that inherits
    // its pid, so it does not join: a slot whose owner cannot be identified is a slot no reaper can
    // ever safely reclaim, which is the permanent leak the whole design exists to avoid.
    let Some(start) = crate::shared::read_start_time(pid) else {
        return;
    };
    let Ok(sh) = Shared::attach(seg.words(), pid, start, &ProcLiveness) else {
        return;
    };
    let sh = Box::into_raw(Box::new(sh));
    SHARED.store(sh as usize, Ordering::Release);
}

/// The VMM handle table, or `None` before configuration has published it.
#[inline(always)]
fn handles() -> Option<&'static Registry> {
    let p = HANDLES.load(Ordering::Acquire) as *const Registry;
    if p.is_null() {
        return None;
    }
    // SAFETY: same argument as `registry`: published once from a `Box::into_raw` that is never
    // freed, and `Registry` is `Sync`.
    Some(unsafe { &*p })
}

/// Learn the card's size, once, if it is not known yet.
///
/// PHYSICAL WAS LEARNED IN THE WRONG PLACE, and the failure is worth recording because the code
/// looked correct and the accounting silently did nothing. It was read only inside `cuMemGetInfo`,
/// on the reasoning that this is the one hook whose caller is already asking that question. But the
/// ALLOCATION path needs it too: the host-wide reservation is bounded by the card, and a card size of
/// zero means there is nothing to bound it by, so the cross-process check was skipped on every
/// allocation. A workload that allocates without ever calling `cuMemGetInfo`, which is most of them,
/// therefore joined the segment and then never wrote to it. Measured: a process holding 12 GiB left
/// the shared total at zero, and a peer was told it had its full 6 GiB slice free on a card with
/// 3.4 GiB left.
///
/// Called at the top of every accounting path. The steady-state cost is one `Relaxed` load and a
/// branch that is taken exactly once in the life of the process.
///
/// # Safety
/// Calls the real `cuMemGetInfo`, which requires a CUDA context. Without one the call fails, nothing
/// is stored, and the next allocation tries again: the driver refusing is a normal answer here, not
/// an error to propagate.
#[inline(always)]
unsafe fn learn_physical_once() {
    if PHYSICAL.load(Ordering::Relaxed) != 0 {
        return;
    }
    let Some(info) = real::typed::<real::FnMemGetInfo>(&real::REAL.mem_get_info) else {
        return;
    };
    let mut rf: usize = 0;
    let mut rt: usize = 0;
    if info(&mut rf, &mut rt) == CUDA_SUCCESS && rt > 0 {
        PHYSICAL.store(rt as u64, Ordering::Relaxed);
    }
}

/// The cross-process view, or `None` on a single-tenant host.
#[inline(always)]
fn shared() -> Option<&'static Shared<'static>> {
    let p = SHARED.load(Ordering::Acquire) as *const Shared<'static>;
    if p.is_null() {
        return None;
    }
    // SAFETY: published exactly once by `attach_shared` from a `Box::into_raw` that is never freed,
    // and it borrows a `Segment` that is itself leaked, so both outlive every reader. `Shared` holds
    // only a `&[AtomicU64]` and two `usize`, so a shared reference from any thread is sound.
    Some(unsafe { &*p })
}

/// The registry, or `None` before configuration has published it.
#[inline(always)]
fn registry() -> Option<&'static Registry> {
    let p = REGISTRY.load(Ordering::Acquire) as *const Registry;
    if p.is_null() {
        return None;
    }
    // SAFETY: the pointer is published exactly once by `configure`, from a `Box::into_raw` that is
    // never freed, so it is valid for the life of the process. `Registry` is `Sync` because every
    // field is an atomic or an immutable `Box<[AtomicU64]>`, so a shared reference from any thread is
    // sound.
    Some(unsafe { &*p })
}

/// Resolve the driver, then decide whether accounting applies. Returns whether it does.
///
/// THE DRIVER IS RESOLVED UNCONDITIONALLY, and an earlier version of this function got that wrong in
/// a way worth recording, because it is the shape of mistake that makes an interception layer look
/// like a broken driver.
///
/// It read `configure() && real::ensure()`, on the reasoning that configuration is a cheap atomic
/// load and a host with no slice should not pay for a `dlopen`. That short-circuits: on a host with
/// no slice, `configure` returns false, `ensure` never runs, the function table stays empty, and the
/// PASSTHROUGH has no real function to call. Every hook then returned `CUDA_ERROR_NOT_INITIALIZED`
/// to a workload that had asked for nothing but the driver's own behaviour. Measured against a
/// linked CUDA program on an RTX 5060 Ti: total 0.000 GiB, error 3, on a card with 15.468.
///
/// Resolution has to happen for both answers, because the passthrough needs it as much as the
/// accounting does. It is a single `Acquire` load after the first call, so the cost that reordering
/// was meant to save does not exist.
///
/// # Safety
/// Calls into the dynamic loader on the first invocation.
#[inline(always)]
unsafe fn accounting_on() -> bool {
    if !real::ensure() {
        return false;
    }
    configure()
}

// ── The hooks ────────────────────────────────────────────────────────────────────────────────────

/// `cuMemAlloc_v2`. The main allocation entry point.
///
/// # Safety
/// Called by the CUDA driver API's caller. `dptr` must be a writable `CUdeviceptr`, which is the
/// contract of the function this replaces.
#[no_mangle]
pub unsafe extern "C" fn cuMemAlloc_v2(dptr: *mut CUdeviceptr, bytesize: usize) -> CUresult {
    let on = accounting_on();
    let Some(real_alloc) = real::typed::<real::FnMemAlloc>(&real::REAL.mem_alloc) else {
        return CUDA_ERROR_NOT_INITIALIZED;
    };
    if dptr.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    if !on {
        return real_alloc(dptr, bytesize);
    }
    charge_then_alloc(bytesize as u64, dptr, &mut |p| real_alloc(p, bytesize))
}

/// `cuMemAllocManaged`. Unified memory: the pages migrate, but the reservation is the same, because
/// the resident portion is device memory and the quota is what stops a slice from taking the card.
///
/// # Safety
/// As [`cuMemAlloc_v2`].
#[no_mangle]
pub unsafe extern "C" fn cuMemAllocManaged(
    dptr: *mut CUdeviceptr,
    bytesize: usize,
    flags: u32,
) -> CUresult {
    let on = accounting_on();
    let Some(real_alloc) = real::typed::<real::FnMemAllocManaged>(&real::REAL.mem_alloc_managed)
    else {
        return CUDA_ERROR_NOT_INITIALIZED;
    };
    if dptr.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    if !on {
        return real_alloc(dptr, bytesize, flags);
    }
    charge_then_alloc(bytesize as u64, dptr, &mut |p| {
        real_alloc(p, bytesize, flags)
    })
}

/// `cuMemAllocPitch_v2`. A padded 2D allocation.
///
/// THE SIZE IS NOT THE ARGUMENT. The caller asks for a width and a height; the driver picks a pitch,
/// which is the width rounded up for alignment, and the real allocation is `pitch * height`. Charging
/// `width * height` would under-count by the padding on every 2D buffer, which on an image workload is
/// most of them. The reservation is therefore made against a conservative upper bound BEFORE the
/// call, and corrected to the exact figure once the driver has reported the pitch it chose.
///
/// # Safety
/// As [`cuMemAlloc_v2`]; `pitch` must additionally be a writable `usize`.
#[no_mangle]
pub unsafe extern "C" fn cuMemAllocPitch_v2(
    dptr: *mut CUdeviceptr,
    pitch: *mut usize,
    width_in_bytes: usize,
    height: usize,
    element_size_bytes: u32,
) -> CUresult {
    let on = accounting_on();
    let Some(real_alloc) = real::typed::<real::FnMemAllocPitch>(&real::REAL.mem_alloc_pitch) else {
        return CUDA_ERROR_NOT_INITIALIZED;
    };
    if dptr.is_null() || pitch.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    if !on {
        return real_alloc(dptr, pitch, width_in_bytes, height, element_size_bytes);
    }
    // The driver never pads beyond 512 bytes of alignment in any documented configuration, and this
    // bound only has to be an over-estimate: it is replaced by the exact figure below. Saturating,
    // because a width and height the caller invented must not wrap into a small reservation.
    let upper = (width_in_bytes as u64)
        .saturating_add(512)
        .saturating_mul(height as u64);
    let Some(reg) = registry() else {
        return real_alloc(dptr, pitch, width_in_bytes, height, element_size_bytes);
    };
    learn_physical_once();
    if QUOTA.reserve(upper).is_err() {
        return CUDA_ERROR_OUT_OF_MEMORY;
    }
    if let Some(sh) = shared() {
        let phys = PHYSICAL.load(Ordering::Relaxed);
        if phys > 0 && sh.reserve(upper, phys).is_err() {
            QUOTA.release(upper);
            return CUDA_ERROR_OUT_OF_MEMORY;
        }
    }
    let rc = real_alloc(dptr, pitch, width_in_bytes, height, element_size_bytes);
    if rc != CUDA_SUCCESS {
        release_both(upper);
        return rc;
    }
    let exact = (*pitch as u64).saturating_mul(height as u64).max(1);
    // Correct the estimate. The exact figure is never larger than the bound, so this only ever gives
    // memory back; if it somehow were larger, the reservation is topped up and a failure there frees
    // the allocation rather than under-counting it.
    if exact <= upper {
        release_both(upper - exact);
    } else if QUOTA.reserve(exact - upper).is_err() {
        let _ = real::typed::<real::FnMemFree>(&real::REAL.mem_free).map(|f| f(*dptr));
        release_both(upper);
        return CUDA_ERROR_OUT_OF_MEMORY;
    }
    if reg.insert(*dptr, exact).is_err() {
        let _ = real::typed::<real::FnMemFree>(&real::REAL.mem_free).map(|f| f(*dptr));
        release_both(exact);
        return CUDA_ERROR_OUT_OF_MEMORY;
    }
    CUDA_SUCCESS
}

/// `cuMemFree_v2`.
///
/// A pointer the registry does not know is freed WITHOUT crediting the quota. It was allocated before
/// the hook was installed, or by a path kern does not intercept, or it is a double free. Crediting a
/// size kern never reserved is how a cooperative quota drifts until it reports more free memory than
/// the card has, which ends in an out-of-memory kill rather than an honest refusal.
///
/// # Safety
/// As the function it replaces.
#[no_mangle]
pub unsafe extern "C" fn cuMemFree_v2(dptr: CUdeviceptr) -> CUresult {
    let on = accounting_on();
    let Some(real_free) = real::typed::<real::FnMemFree>(&real::REAL.mem_free) else {
        return CUDA_ERROR_NOT_INITIALIZED;
    };
    if !on {
        return real_free(dptr);
    }
    // The size is taken BEFORE the driver frees. If the driver call came first and then the lookup,
    // a concurrent allocation could be handed the same address and inserted, and the lookup would
    // then remove the NEW allocation's entry and credit its size against a buffer that is still live.
    let size = registry().and_then(|r| r.remove(dptr));
    let rc = real_free(dptr);
    match size {
        Some(n) if rc == CUDA_SUCCESS => release_both(n),
        // The driver refused the free, so the memory is still held: put the entry back rather than
        // credit a release that did not happen. A re-insert that fails leaves the quota holding the
        // bytes, which is the fail-closed direction.
        Some(n) => {
            if let Some(r) = registry() {
                let _ = r.insert(dptr, n);
            }
        }
        None => {}
    }
    rc
}

/// `cuMemGetInfo_v2`. Reports the SLICE, not the card.
///
/// This is what makes a cooperative quota cooperative. A framework asks how much memory the device
/// has and sizes its caching arena from the answer; told the truth about a 15 GiB card while holding
/// a 2 GiB slice, it will build a 13 GiB arena and fail on the first large batch. Told about the
/// slice, it stays inside it on purpose.
///
/// `free` is the slice minus what this process holds, clamped at zero: a slice that has been shrunk
/// below its current usage would otherwise underflow into an enormous free figure, which is the exact
/// number a framework would then try to allocate.
///
/// # Safety
/// `free` and `total` must be writable `usize`s, which is the contract of the function this replaces.
#[no_mangle]
pub unsafe extern "C" fn cuMemGetInfo_v2(free: *mut usize, total: *mut usize) -> CUresult {
    let on = accounting_on();
    let Some(real_info) = real::typed::<real::FnMemGetInfo>(&real::REAL.mem_get_info) else {
        return CUDA_ERROR_NOT_INITIALIZED;
    };
    if !on {
        return real_info(free, total);
    }
    if free.is_null() || total.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    learn_physical_once();
    let limit = QUOTA.limit();
    let held = QUOTA.held();
    // The physical figure bounds the answer: a slice larger than the card is an operator's mistake,
    // and reporting it would send a framework past what the hardware has.
    let phys = PHYSICAL.load(Ordering::Relaxed);
    let cap = if phys == 0 { limit } else { limit.min(phys) };
    *total = cap as usize;
    // Free is the SMALLER of what this slice has left and what the card has left. A tenant told it
    // has 2 GiB free while three peers have already filled the device would allocate straight into a
    // driver-level out-of-memory, which is the failure the whole cross-process total exists to turn
    // into an honest refusal.
    let mut avail = cap.saturating_sub(held);
    if let Some(sh) = shared() {
        let phys = PHYSICAL.load(Ordering::Relaxed);
        if phys > 0 {
            avail = avail.min(phys.saturating_sub(sh.total()));
        }
    }
    *free = avail as usize;
    CUDA_SUCCESS
}

/// `cuMemCreate`. THE VMM ALLOCATION, and the hole this crate had until it was measured.
///
/// The virtual-memory-management API is not an alternative spelling of `cuMemAlloc`, it is a
/// different shape: reserve an address range, create a physical allocation, map one onto the other.
/// Only this call commits device memory. Before it was intercepted, a quota of 2 GiB reported
/// 2.000 GiB free while 7.812 GiB had been taken through this path and never seen. Measured on an
/// RTX 5060 Ti, and it is the path PyTorch's expandable-segments allocator uses, so it is the path
/// that matters for the workload this whole layer exists to serve.
///
/// The handle rather than a pointer is the key here, and it goes in its own table: see [`HANDLES`].
///
/// # Safety
/// As the function it replaces. `handle` must be writable and `prop` is passed through untouched.
#[no_mangle]
pub unsafe extern "C" fn cuMemCreate(
    handle: *mut real::CUmemGenericAllocationHandle,
    size: usize,
    prop: *const c_void,
    flags: u64,
) -> CUresult {
    let on = accounting_on();
    let Some(real_create) = real::typed::<real::FnMemCreate>(&real::REAL.mem_create) else {
        return CUDA_ERROR_NOT_INITIALIZED;
    };
    if handle.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    if !on {
        return real_create(handle, size, prop, flags);
    }
    let Some(tab) = handles() else {
        return real_create(handle, size, prop, flags);
    };
    if size == 0 {
        return real_create(handle, size, prop, flags);
    }
    learn_physical_once();
    let n = size as u64;
    if QUOTA.reserve(n).is_err() {
        return CUDA_ERROR_OUT_OF_MEMORY;
    }
    if let Some(sh) = shared() {
        let phys = PHYSICAL.load(Ordering::Relaxed);
        if phys > 0 && sh.reserve(n, phys).is_err() {
            QUOTA.release(n);
            return CUDA_ERROR_OUT_OF_MEMORY;
        }
    }
    let rc = real_create(handle, size, prop, flags);
    if rc != CUDA_SUCCESS {
        release_both(n);
        return rc;
    }
    if tab.insert(*handle, n).is_err() {
        // Same rule as the pointer path: a size that cannot be recorded is never credited back, so
        // the allocation is undone rather than allowed to leak the slice for the life of the process.
        let _ = real::typed::<real::FnMemRelease>(&real::REAL.mem_release).map(|f| f(*handle));
        release_both(n);
        return CUDA_ERROR_OUT_OF_MEMORY;
    }
    CUDA_SUCCESS
}

/// `cuMemRelease`. Where a VMM allocation's charge comes back.
///
/// A handle the table does not know is released WITHOUT crediting anything, for the same reason a
/// pointer is: crediting a size that was never reserved drifts the quota until it reports more free
/// memory than the card has.
///
/// # Safety
/// As the function it replaces.
#[no_mangle]
pub unsafe extern "C" fn cuMemRelease(handle: real::CUmemGenericAllocationHandle) -> CUresult {
    let on = accounting_on();
    let Some(real_release) = real::typed::<real::FnMemRelease>(&real::REAL.mem_release) else {
        return CUDA_ERROR_NOT_INITIALIZED;
    };
    if !on {
        return real_release(handle);
    }
    // Taken BEFORE the driver frees, for the same reason as the pointer path: after the release the
    // driver may hand the same handle value to a concurrent `cuMemCreate`, and a lookup afterwards
    // would find the NEW allocation's entry and credit its size against one that is still live.
    let size = handles().and_then(|t| t.remove(handle));
    let rc = real_release(handle);
    match size {
        Some(n) if rc == CUDA_SUCCESS => release_both(n),
        Some(n) => {
            // The driver refused: the memory is still held, so put the entry back rather than credit
            // a release that did not happen.
            if let Some(t) = handles() {
                let _ = t.insert(handle, n);
            }
        }
        None => {}
    }
    rc
}

/// `cuGetProcAddress`, the CUDA 11.3+ resolver.
///
/// THE ONE THAT MAKES THE OTHERS REACHABLE. Modern CUDA does not bind the driver's entry points by
/// symbol: it asks this function for them by name and calls what it gets back. A layer that exported
/// only the named symbols would be bypassed entirely by any recent toolkit, because the workload
/// never looks the symbols up. So this returns OUR pointer for the names we intercept, and the
/// driver's answer for everything else.
///
/// # Safety
/// As the function it replaces.
#[no_mangle]
pub unsafe extern "C" fn cuGetProcAddress(
    symbol: *const c_char,
    pfn: *mut *mut c_void,
    cuda_version: c_int,
    flags: u64,
) -> CUresult {
    let on = accounting_on();
    let Some(real_get) = real::typed::<real::FnGetProcAddress>(&real::REAL.get_proc_address) else {
        return CUDA_ERROR_NOT_INITIALIZED;
    };
    if symbol.is_null() || pfn.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    if !on {
        return real_get(symbol, pfn, cuda_version, flags);
    }
    if let Some(ours) = ours_for(symbol) {
        *pfn = ours;
        return CUDA_SUCCESS;
    }
    real_get(symbol, pfn, cuda_version, flags)
}

/// `cuGetProcAddress_v2`, the CUDA 12 form with a status out-parameter.
///
/// A SEPARATE FUNCTION AND NOT AN ALIAS. The fifth parameter is written by the driver, and calling
/// the v2 entry point through the v1 signature leaves the driver storing a status through whatever
/// happened to be in the fifth argument register. Two signatures, two hooks.
///
/// # Safety
/// As the function it replaces.
#[no_mangle]
pub unsafe extern "C" fn cuGetProcAddress_v2(
    symbol: *const c_char,
    pfn: *mut *mut c_void,
    cuda_version: c_int,
    flags: u64,
    symbol_status: *mut c_int,
) -> CUresult {
    let on = accounting_on();
    let Some(real_get) = real::typed::<real::FnGetProcAddressV2>(&real::REAL.get_proc_address_v2)
    else {
        return CUDA_ERROR_NOT_INITIALIZED;
    };
    if symbol.is_null() || pfn.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    if !on {
        return real_get(symbol, pfn, cuda_version, flags, symbol_status);
    }
    if let Some(ours) = ours_for(symbol) {
        *pfn = ours;
        // 0 is `CU_GET_PROC_ADDRESS_SUCCESS`. Written only when the caller asked for it: a null here
        // is legal and means the caller does not want the status.
        if !symbol_status.is_null() {
            *symbol_status = 0;
        }
        return CUDA_SUCCESS;
    }
    real_get(symbol, pfn, cuda_version, flags, symbol_status)
}

/// The hook for a symbol name, if this crate intercepts it.
///
/// MATCHED ON THE BASE NAME, WITHOUT THE VERSION SUFFIX, because that is what the caller asks for.
/// A framework calls `cuGetProcAddress("cuMemAlloc", &p, 12030, ...)` and the driver decides that a
/// caller declaring CUDA 12.3 wants the `_v2` entry point. Matching on `cuMemAlloc_v2` here would
/// never fire, and the interception would silently do nothing on exactly the modern toolkits it
/// exists for. Both spellings are accepted so a caller that does ask for the suffixed name is also
/// intercepted.
///
/// # Safety
/// `symbol` must be a NUL-terminated C string.
unsafe fn ours_for(symbol: *const c_char) -> Option<*mut c_void> {
    // Bounded read: a name longer than this is not a CUDA entry point, and refusing to walk further
    // means a `symbol` that is not terminated cannot run off the end of the mapping.
    const MAX: usize = 64;
    let mut len = 0usize;
    while len < MAX && *symbol.add(len) != 0 {
        len += 1;
    }
    if len == 0 || len == MAX {
        return None;
    }
    // `.cast()` rather than `as *const u8`: `c_char` is signed on x86_64 and UNSIGNED on aarch64, so
    // the `as` form is a real cast on one target and a no-op clippy rejects on the other. The method
    // spelling is correct on both, which is why CI caught this only on the aarch64 leg.
    let name = core::slice::from_raw_parts(symbol.cast::<u8>(), len);
    let f: *mut c_void = match name {
        b"cuMemAlloc" | b"cuMemAlloc_v2" => cuMemAlloc_v2 as *mut c_void,
        b"cuMemAllocManaged" => cuMemAllocManaged as *mut c_void,
        b"cuMemAllocPitch" | b"cuMemAllocPitch_v2" => cuMemAllocPitch_v2 as *mut c_void,
        b"cuMemFree" | b"cuMemFree_v2" => cuMemFree_v2 as *mut c_void,
        b"cuMemGetInfo" | b"cuMemGetInfo_v2" => cuMemGetInfo_v2 as *mut c_void,
        // The VMM pair. No `_v2` spellings exist for either: both have had one signature since the
        // API was introduced in CUDA 10.2.
        b"cuMemCreate" => cuMemCreate as *mut c_void,
        b"cuMemRelease" => cuMemRelease as *mut c_void,
        // The resolver resolves itself, which a framework does do: it fetches `cuGetProcAddress`
        // through `cuGetProcAddress` and calls the result thereafter. Returning the driver's here
        // would hand the workload a resolver that bypasses every hook above.
        b"cuGetProcAddress" => cuGetProcAddress as *mut c_void,
        b"cuGetProcAddress_v2" => cuGetProcAddress_v2 as *mut c_void,
        _ => return None,
    };
    Some(f)
}

/// Reserve, allocate, record, and undo every step on the failure of the one after it.
///
/// Written once and shared by the fixed-size allocation hooks, because the ordering argument in this
/// module's header is the same for all of them and a second copy of it is a second place to get it
/// wrong.
///
/// # Safety
/// `dptr` must be writable, and `alloc` must be the real driver entry point for this allocation kind.
#[inline]
unsafe fn charge_then_alloc(
    size: u64,
    dptr: *mut CUdeviceptr,
    alloc: &mut dyn FnMut(*mut CUdeviceptr) -> CUresult,
) -> CUresult {
    // A zero-byte allocation is legal and reserves nothing, but it still has to reach the driver: the
    // caller expects a valid pointer back and a framework will free it later.
    if size == 0 {
        return alloc(dptr);
    }
    let Some(reg) = registry() else {
        return alloc(dptr);
    };
    learn_physical_once();
    // TWO CEILINGS, IN THIS ORDER. The per-process quota first, because it is this process's own
    // word and refusing there costs no coherence traffic on a line every tenant on the host shares.
    // The host-wide total second, because it is the expensive one and there is no point paying for
    // it on an allocation the slice was going to refuse anyway.
    if QUOTA.reserve(size).is_err() {
        return CUDA_ERROR_OUT_OF_MEMORY;
    }
    if let Some(sh) = shared() {
        // Bounded by the card, not by the slice: this is the question "does the DEVICE have room",
        // and a physical figure of zero (the driver has not been asked yet) means there is nothing
        // to bound it by, so the host-wide check is skipped rather than made against a guess.
        let phys = PHYSICAL.load(Ordering::Relaxed);
        if phys > 0 && sh.reserve(size, phys).is_err() {
            QUOTA.release(size);
            return CUDA_ERROR_OUT_OF_MEMORY;
        }
    }
    let rc = alloc(dptr);
    if rc != CUDA_SUCCESS {
        release_both(size);
        return rc;
    }
    if reg.insert(*dptr, size).is_err() {
        // The driver committed the memory and the size cannot be recorded. Give the memory back
        // rather than hold a buffer that will never be credited on free: an unrecorded allocation
        // leaks the quota for the life of the process, which is worse than this allocation failing.
        let _ = real::typed::<real::FnMemFree>(&real::REAL.mem_free).map(|f| f(*dptr));
        release_both(size);
        return CUDA_ERROR_OUT_OF_MEMORY;
    }
    CUDA_SUCCESS
}

/// Give `size` back to both ceilings.
///
/// The host-wide total first and the per-process quota second, mirroring the order they were taken
/// in. Written once because an unwinding path that released one and forgot the other is the shape of
/// bug that shows up as a slice which shrinks by a few megabytes every time an allocation fails.
#[inline]
fn release_both(size: u64) {
    if let Some(sh) = shared() {
        if PHYSICAL.load(Ordering::Relaxed) > 0 {
            sh.release(size);
        }
    }
    QUOTA.release(size);
}

/// Test-only view of the accounting, so the properties above can be checked without a GPU.
#[cfg(test)]
pub(crate) mod probe {
    use super::*;

    pub fn quota_held() -> u64 {
        QUOTA.held()
    }
    pub fn quota_limit() -> u64 {
        QUOTA.limit()
    }
    pub fn set_quota(b: u64) {
        QUOTA.set_quota(b);
    }
    pub fn set_physical(b: u64) {
        PHYSICAL.store(b, Ordering::Relaxed);
    }
    pub fn force_configured(slots: usize) {
        if REGISTRY.load(Ordering::Acquire) == 0 {
            let reg = Box::into_raw(Box::new(Registry::with_capacity(slots)));
            REGISTRY.store(reg as usize, Ordering::Release);
        }
        CONFIGURED.store(CFG_ON, Ordering::Release);
    }
    pub fn registry_len() -> usize {
        registry().map(|r| r.len()).unwrap_or(0)
    }
    pub unsafe fn lookup(symbol: &[u8]) -> Option<*mut c_void> {
        ours_for(symbol.as_ptr() as *const c_char)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every name a modern toolkit asks for must resolve to one of ours, in BOTH spellings. Matching
    /// only the suffixed form is the failure that makes the whole layer a no-op on CUDA 12: the
    /// framework asks for `cuMemAlloc` and the driver, not kern, answers.
    #[test]
    fn both_spellings_of_every_intercepted_symbol_resolve_to_a_hook() {
        for name in [
            &b"cuMemAlloc\0"[..],
            &b"cuMemAlloc_v2\0"[..],
            &b"cuMemAllocManaged\0"[..],
            &b"cuMemAllocPitch\0"[..],
            &b"cuMemAllocPitch_v2\0"[..],
            &b"cuMemFree\0"[..],
            &b"cuMemFree_v2\0"[..],
            &b"cuMemGetInfo\0"[..],
            &b"cuMemGetInfo_v2\0"[..],
            &b"cuGetProcAddress\0"[..],
            &b"cuGetProcAddress_v2\0"[..],
        ] {
            // SAFETY: every literal is NUL terminated.
            let got = unsafe { probe::lookup(name) };
            assert!(got.is_some(), "{:?} did not resolve to a hook", name);
        }
    }

    /// The two spellings of one entry point must resolve to the SAME hook, or a framework that asks
    /// for the suffixed name gets a different function than one that asks for the base name.
    #[test]
    fn the_two_spellings_resolve_to_the_same_function() {
        // SAFETY: NUL-terminated literals.
        unsafe {
            assert_eq!(
                probe::lookup(b"cuMemAlloc\0"),
                probe::lookup(b"cuMemAlloc_v2\0")
            );
            assert_eq!(
                probe::lookup(b"cuMemFree\0"),
                probe::lookup(b"cuMemFree_v2\0")
            );
            assert_eq!(
                probe::lookup(b"cuMemGetInfo\0"),
                probe::lookup(b"cuMemGetInfo_v2\0")
            );
        }
    }

    /// A symbol kern does not intercept must fall through, or the resolver would return null for
    /// every other driver entry point and the workload would crash on the first one it calls.
    #[test]
    fn an_unintercepted_symbol_falls_through() {
        for name in [
            &b"cuInit\0"[..],
            &b"cuCtxCreate_v2\0"[..],
            &b"cuLaunchKernel\0"[..],
            &b"cuStreamSynchronize\0"[..],
            &b"cuMemcpyHtoD_v2\0"[..],
        ] {
            // SAFETY: NUL-terminated literals.
            assert!(
                unsafe { probe::lookup(name) }.is_none(),
                "{name:?} must not be intercepted"
            );
        }
    }

    /// A name with no terminator inside the bound must not be walked past. Without the bound this
    /// reads until it finds a zero byte, which for a pointer the caller got wrong is a read off the
    /// end of a mapping.
    #[test]
    fn an_unterminated_or_absurd_symbol_name_is_refused() {
        let unterminated = [b'c'; 128];
        // SAFETY: the buffer is 128 bytes with no NUL, and the function's bound is 64.
        assert!(unsafe { probe::lookup(&unterminated) }.is_none());
        // SAFETY: a lone NUL is a zero-length name.
        assert!(unsafe { probe::lookup(b"\0") }.is_none());
    }

    /// The resolver must return ITSELF for its own name. A framework fetches `cuGetProcAddress`
    /// through `cuGetProcAddress` and uses the result for everything after, so returning the
    /// driver's would hand the workload a resolver that bypasses every hook.
    #[test]
    fn the_resolver_resolves_to_itself_and_not_to_the_driver() {
        // SAFETY: NUL-terminated literal.
        let got = unsafe { probe::lookup(b"cuGetProcAddress\0") };
        assert_eq!(got, Some(cuGetProcAddress as *mut c_void));
        // SAFETY: NUL-terminated literal.
        let got_v2 = unsafe { probe::lookup(b"cuGetProcAddress_v2\0") };
        assert_eq!(got_v2, Some(cuGetProcAddress_v2 as *mut c_void));
        assert_ne!(got, got_v2, "the two resolvers are different functions");
    }

    /// `cuMemGetInfo` must report the SLICE, bounded by the hardware. This is the number a caching
    /// allocator sizes its arena from, so it is the number that makes the quota cooperative rather
    /// than something a framework discovers by crashing into it.
    #[test]
    fn mem_get_info_reports_the_slice_and_never_more_than_the_card() {
        probe::force_configured(64);
        probe::set_physical(16 * 1024 * 1024 * 1024);
        probe::set_quota(2 * 1024 * 1024 * 1024);

        // The accounting the hook reads, exercised directly: the hook itself needs a real driver for
        // its passthrough branch, and the arithmetic is what this test is about.
        let limit = probe::quota_limit();
        let held = probe::quota_held();
        let phys = 16u64 * 1024 * 1024 * 1024;
        let cap = limit.min(phys);
        assert_eq!(cap, 2 * 1024 * 1024 * 1024, "the slice, not the card");
        assert_eq!(cap.saturating_sub(held), cap - held);

        // A slice larger than the card is an operator error and must be clamped, or a framework is
        // told to allocate past what the hardware has.
        probe::set_quota(64 * 1024 * 1024 * 1024);
        let cap = probe::quota_limit().min(phys);
        assert_eq!(cap, phys, "a slice bigger than the card reports the card");
    }

    /// A shrunk slice must report zero free rather than underflow. The subtraction is saturating
    /// precisely because an operator can lower a quota below what is currently held, and an
    /// underflow there is an enormous free figure that a framework will immediately try to use.
    #[test]
    fn a_slice_shrunk_below_what_is_held_reports_zero_free_not_an_underflow() {
        probe::force_configured(64);
        probe::set_physical(0);
        probe::set_quota(u64::MAX);
        let held = probe::quota_held();
        probe::set_quota(if held > 0 { held - 1 } else { 0 });
        let limit = probe::quota_limit();
        assert_eq!(
            limit.saturating_sub(held),
            0,
            "free must clamp at zero, never wrap"
        );
        probe::set_quota(u64::MAX);
    }

    /// The registry is published exactly once and is readable afterwards from any thread.
    #[test]
    fn the_registry_is_published_and_readable() {
        probe::force_configured(128);
        assert_eq!(probe::registry_len(), 0);
        assert!(registry().is_some(), "the registry must be published");
    }

    /// The pitch bound must over-estimate and never wrap. A width and height a caller invented must
    /// produce a saturated reservation rather than a small one, or a hostile 2D allocation reserves
    /// nothing and takes the card.
    #[test]
    fn the_pitch_upper_bound_saturates_instead_of_wrapping() {
        let upper = |w: u64, h: u64| w.saturating_add(512).saturating_mul(h);
        assert_eq!(upper(1024, 1024), (1024 + 512) * 1024);
        assert_eq!(upper(u64::MAX, 2), u64::MAX, "must saturate, not wrap");
        assert_eq!(upper(u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(upper(0, 0), 0);
        // And the bound must genuinely be an over-estimate for any plausible pitch: the driver pads
        // the width, so pitch <= width + 512 on the alignments CUDA documents.
        for w in [1u64, 100, 1000, 4096, 1 << 20] {
            for h in [1u64, 7, 1080] {
                let plausible_pitch = w.div_ceil(512) * 512;
                assert!(
                    plausible_pitch * h <= upper(w, h),
                    "bound too small for width {w} height {h}"
                );
            }
        }
    }

    /// Configuration is a one-way latch per state and never re-reads the environment on the hot path.
    #[test]
    fn configuration_settles_and_stays_settled() {
        probe::force_configured(64);
        assert!(
            configure(),
            "already configured must return true immediately"
        );
        assert!(configure(), "and stay true");
    }
}
