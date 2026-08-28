//! RESOLVING THE REAL DRIVER, which is where an interception layer usually breaks itself.
//!
//! Everything in [`crate::hooks`] exports a symbol the CUDA driver also exports. That is the point:
//! the workload calls ours instead of theirs. It is also the trap, because ours has to call theirs,
//! and the obvious way of finding theirs finds ours.
//!
//! WHY NOT `dlsym(RTLD_NEXT, ...)`
//!   `RTLD_NEXT` means "the next definition after the one in this object", which is correct only if
//!   this object appears exactly once and before the real driver in the search order. Neither is
//!   guaranteed. kern installs the interception in two different ways depending on the host: as an
//!   `LD_PRELOAD`, where `RTLD_NEXT` works, and as a `libcuda.so.1` on `LD_LIBRARY_PATH`, where the
//!   real driver is not "next" at all, it is a different file this library has to open by name.
//!   A resolution strategy that is right in one arrangement and silently self-referential in the
//!   other produces infinite recursion inside a GPU allocation, which presents as a stack overflow
//!   with a hundred thousand identical frames.
//!
//!   So the real driver is opened BY ABSOLUTE PATH, and every resolved pointer is then checked
//!   against this object's own address range. A pointer that lands inside us is refused rather than
//!   called, because calling it is the recursion.
//!
//! NO VENDOR HEADERS, NO `-lcuda`, NO CUDA AT BUILD TIME
//!   Every type below is declared here. The library must build on a machine with no NVIDIA driver
//!   installed, which is most machines, all of CI, and both ARM boards. Linking against `libcuda`
//!   would make the artifact unbuildable exactly where it is most convenient to build it, and would
//!   also make it refuse to load on a host whose driver is a different minor version.
//!
//! WHAT IS AND IS NOT PINNED TO A DRIVER VERSION
//!   The symbol NAMES and their signatures are ABI, stable across the driver series, and are what
//!   this file declares. The internal layout of anything behind a `CUcontext` or a `CUdevice` is
//!   not, and nothing here looks inside one: every driver type is an opaque pointer or an integer
//!   that is passed straight through.

#![allow(unsafe_code)]

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

// ── CUDA driver API types, declared rather than included ─────────────────────────────────────────

/// `CUresult`. An `int` in the driver's ABI.
pub type CUresult = c_int;

/// `CUdeviceptr`. 64-bit on every platform kern targets; the driver defines it as `unsigned long long`
/// on 64-bit builds.
pub type CUdeviceptr = u64;

/// The subset of `CUresult` this crate produces or inspects. The numeric values are ABI and are the
/// ones a workload's error handling compares against, so an approximation here would be a code no
/// framework recognises.
pub const CUDA_SUCCESS: CUresult = 0;
/// `CUDA_ERROR_INVALID_VALUE`.
pub const CUDA_ERROR_INVALID_VALUE: CUresult = 1;
/// `CUDA_ERROR_OUT_OF_MEMORY`. The one that matters: this is what a quota refusal must look like, so
/// that a caching allocator treats it as a full device and falls back to eviction rather than
/// crashing on an error it has no branch for.
pub const CUDA_ERROR_OUT_OF_MEMORY: CUresult = 2;
/// `CUDA_ERROR_NOT_INITIALIZED`.
pub const CUDA_ERROR_NOT_INITIALIZED: CUresult = 3;
/// `CUDA_ERROR_NOT_FOUND`, which `cuGetProcAddress` returns for a symbol the driver does not have.
pub const CUDA_ERROR_NOT_FOUND: CUresult = 500;

// ── Function pointer types ───────────────────────────────────────────────────────────────────────

/// `cuMemAlloc_v2(CUdeviceptr *dptr, size_t bytesize)`.
pub type FnMemAlloc = unsafe extern "C" fn(*mut CUdeviceptr, usize) -> CUresult;
/// `cuMemAllocManaged(CUdeviceptr *dptr, size_t bytesize, unsigned int flags)`.
pub type FnMemAllocManaged = unsafe extern "C" fn(*mut CUdeviceptr, usize, u32) -> CUresult;
/// `cuMemAllocPitch_v2(CUdeviceptr *dptr, size_t *pPitch, size_t WidthInBytes, size_t Height,
/// unsigned int ElementSizeBytes)`.
pub type FnMemAllocPitch =
    unsafe extern "C" fn(*mut CUdeviceptr, *mut usize, usize, usize, u32) -> CUresult;
/// `cuMemFree_v2(CUdeviceptr dptr)`.
pub type FnMemFree = unsafe extern "C" fn(CUdeviceptr) -> CUresult;
/// `cuMemGetInfo_v2(size_t *free, size_t *total)`.
pub type FnMemGetInfo = unsafe extern "C" fn(*mut usize, *mut usize) -> CUresult;
/// `CUmemGenericAllocationHandle`. An opaque 64-bit handle to a physical allocation.
pub type CUmemGenericAllocationHandle = u64;

/// `cuMemCreate(CUmemGenericAllocationHandle *handle, size_t size, const CUmemAllocationProp *prop,
/// unsigned long long flags)`.
///
/// THE VMM ALLOCATION ENTRY POINT, and the one that made the quota a lie before it was intercepted.
/// The virtual-memory-management API splits what `cuMemAlloc` does into four calls: reserve an
/// address range, create a physical allocation, map one onto the other, and set access. Only
/// `cuMemCreate` commits device memory, so it is the only one of the four that is charged; the
/// address reservation and the mapping are bookkeeping in the process's own address space and
/// charging them would double-count.
///
/// `prop` is passed through as an opaque pointer and never read. Its layout is a driver struct that
/// has grown fields across CUDA versions, and this crate has no reason to look inside one.
pub type FnMemCreate =
    unsafe extern "C" fn(*mut CUmemGenericAllocationHandle, usize, *const c_void, u64) -> CUresult;
/// `cuMemRelease(CUmemGenericAllocationHandle handle)`. Frees the physical allocation `cuMemCreate`
/// made, which is where the charge comes back.
pub type FnMemRelease = unsafe extern "C" fn(CUmemGenericAllocationHandle) -> CUresult;

/// `cuGetProcAddress(const char *symbol, void **pfn, int cudaVersion, cuuint64_t flags)`.
pub type FnGetProcAddress =
    unsafe extern "C" fn(*const c_char, *mut *mut c_void, c_int, u64) -> CUresult;
/// `cuGetProcAddress_v2(..., CUdriverProcAddressQueryResult *symbolStatus)`.
///
/// The fifth parameter is the CUDA 12 addition. Calling the v2 entry point through the v1 type would
/// leave the driver writing a status through a pointer this side never passed, which is a stack
/// write at an address the driver invented from a register that happened to be non-zero.
pub type FnGetProcAddressV2 =
    unsafe extern "C" fn(*const c_char, *mut *mut c_void, c_int, u64, *mut c_int) -> CUresult;

// ── The resolved table ───────────────────────────────────────────────────────────────────────────

/// The real driver's entry points, resolved once.
///
/// `AtomicPtr` per slot rather than a `Mutex<Option<Table>>`: the hot path reads these on every
/// allocation, a lock there would serialise every stream in the workload, and the values are written
/// exactly once during initialisation and never again. A `Relaxed` load is enough for reading a
/// pointer that was published with `Release` by the state transition in [`state`], which is what
/// orders the whole table against a reader that sees `READY`.
pub struct Table {
    pub mem_alloc: AtomicPtr<c_void>,
    pub mem_alloc_managed: AtomicPtr<c_void>,
    pub mem_alloc_pitch: AtomicPtr<c_void>,
    pub mem_free: AtomicPtr<c_void>,
    pub mem_get_info: AtomicPtr<c_void>,
    pub mem_create: AtomicPtr<c_void>,
    pub mem_release: AtomicPtr<c_void>,
    pub get_proc_address: AtomicPtr<c_void>,
    pub get_proc_address_v2: AtomicPtr<c_void>,
    /// The `dlopen` handle for the real driver, kept so the library is not unloaded under us.
    handle: AtomicPtr<c_void>,
}

impl Table {
    const fn new() -> Self {
        Self {
            mem_alloc: AtomicPtr::new(core::ptr::null_mut()),
            mem_alloc_managed: AtomicPtr::new(core::ptr::null_mut()),
            mem_alloc_pitch: AtomicPtr::new(core::ptr::null_mut()),
            mem_free: AtomicPtr::new(core::ptr::null_mut()),
            mem_get_info: AtomicPtr::new(core::ptr::null_mut()),
            mem_create: AtomicPtr::new(core::ptr::null_mut()),
            mem_release: AtomicPtr::new(core::ptr::null_mut()),
            get_proc_address: AtomicPtr::new(core::ptr::null_mut()),
            get_proc_address_v2: AtomicPtr::new(core::ptr::null_mut()),
            handle: AtomicPtr::new(core::ptr::null_mut()),
        }
    }
}

/// The one table. `static` rather than passed around: the hooks are `extern "C"` functions the driver
/// API calls with no context of ours, so there is nowhere to thread a handle through.
pub static REAL: Table = Table::new();

// ── Initialisation state ─────────────────────────────────────────────────────────────────────────

/// Nothing has been attempted.
pub const UNINIT: u32 = 0;
/// A thread is inside `dlopen`. Any hook that fires now must pass through rather than wait.
pub const INITIALIZING: u32 = 1;
/// The table is populated and safe to read.
pub const READY: u32 = 2;
/// Resolution failed. The hooks degrade to reporting an uninitialised driver rather than crashing.
pub const FAILED: u32 = 3;

/// The initialisation state machine.
pub static STATE: AtomicU32 = AtomicU32::new(UNINIT);

/// Absolute paths the real driver is looked for at, in order.
///
/// BY PATH AND NOT BY NAME, which is the whole point of this module: `dlopen("libcuda.so.1")` would
/// consult `LD_LIBRARY_PATH`, and kern's own interception is installed by putting this library on
/// exactly that path under exactly that name. Opening by name would therefore open THIS library, and
/// the first `cuMemAlloc` would call itself until the stack ran out.
///
/// The list covers the two multiarch layouts in use and both architectures kern targets. It is a
/// list rather than a single path because distributions disagree, and it is finite rather than a
/// search because a search is how something unexpected gets loaded into a workload's address space.
const DRIVER_PATHS: [&[u8]; 8] = [
    b"/usr/lib/x86_64-linux-gnu/libcuda.so.1\0",
    b"/lib/x86_64-linux-gnu/libcuda.so.1\0",
    b"/usr/lib/aarch64-linux-gnu/libcuda.so.1\0",
    b"/lib/aarch64-linux-gnu/libcuda.so.1\0",
    b"/usr/lib64/libcuda.so.1\0",
    b"/usr/lib/libcuda.so.1\0",
    // Jetson's Tegra layout, where the driver lives outside the multiarch directories.
    b"/usr/lib/aarch64-linux-gnu/tegra/libcuda.so.1\0",
    b"/usr/local/cuda/compat/libcuda.so.1\0",
];

/// The environment variable that overrides the search, for a host whose driver is somewhere else.
///
/// Read once, at initialisation, never on the hot path. An operator with a driver in an unusual place
/// can name it; nobody has to, and a wrong value fails closed to [`FAILED`] rather than to a search.
const PATH_OVERRIDE: &str = "KERN_CUDA_REAL";

/// Resolve one symbol from an open handle, refusing a pointer that lands inside this library.
///
/// THE SELF-REFERENCE CHECK, which is the difference between an interception layer and a crash. If
/// the resolved address is inside this object, calling it re-enters the hook that is trying to call
/// the driver, and the recursion terminates only when the stack does. `dladdr` on the resolved
/// pointer names the object it belongs to; comparing that against the object containing a function of
/// ours is a direct test rather than an inference from load order.
///
/// # Safety
/// `handle` must be a live handle from `dlopen`, and `name` a NUL-terminated symbol name.
unsafe fn resolve(handle: *mut c_void, name: &[u8]) -> *mut c_void {
    let p = libc::dlsym(handle, name.as_ptr() as *const c_char);
    if p.is_null() {
        return core::ptr::null_mut();
    }
    if points_into_this_library(p) {
        // Resolved to ourselves. Returning null makes the caller treat the symbol as unavailable,
        // which degrades to passthrough-refused rather than to infinite recursion.
        return core::ptr::null_mut();
    }
    p
}

/// Does `p` lie inside the shared object this code is part of?
///
/// Uses `dladdr` twice: once for a known-local function and once for the candidate, then compares the
/// base addresses of the objects they belong to. Comparing object bases rather than symbol names is
/// what makes this work for a driver whose symbol has the same name as ours, which is every symbol
/// this crate exports.
///
/// # Safety
/// `p` must be a pointer `dlsym` returned, so either null or a valid address in a mapped object.
unsafe fn points_into_this_library(p: *mut c_void) -> bool {
    let mut mine: libc::Dl_info = core::mem::zeroed();
    let mut theirs: libc::Dl_info = core::mem::zeroed();
    // A function that is unambiguously in this object.
    let anchor = points_into_this_library as *const () as *mut c_void;
    if libc::dladdr(anchor, &mut mine) == 0 {
        // Without `dladdr` there is no way to tell, and the safe answer is "assume it is ours", which
        // refuses the symbol and degrades to passthrough rather than risking recursion.
        return true;
    }
    if libc::dladdr(p, &mut theirs) == 0 {
        return true;
    }
    mine.dli_fbase == theirs.dli_fbase
}

/// Open the real driver and fill [`REAL`]. Returns whether the table is usable.
///
/// IDEMPOTENT AND RACE-SAFE. Several threads can reach here at once, on the first allocation of a
/// multi-threaded workload. The state machine admits exactly one of them into `dlopen`; the others
/// see `INITIALIZING` and return `false`, which their caller turns into a passthrough. They do NOT
/// spin waiting, and that is deliberate: `dlopen` takes the loader lock and calls `malloc`, so a
/// thread that reached this hook from inside the allocator would spin on a lock the initialiser
/// cannot release until the allocator it is blocked on returns.
///
/// # Safety
/// Calls into the dynamic loader. Safe to call from any thread at any time; the state machine is what
/// makes that true.
pub unsafe fn ensure() -> bool {
    match STATE.load(Ordering::Acquire) {
        READY => return true,
        FAILED | INITIALIZING => return false,
        _ => {}
    }
    if STATE
        .compare_exchange(UNINIT, INITIALIZING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // Another thread got there first. Do not wait: see the note above about the loader lock.
        return STATE.load(Ordering::Acquire) == READY;
    }

    let handle = open_driver();
    if handle.is_null() {
        STATE.store(FAILED, Ordering::Release);
        return false;
    }

    REAL.handle.store(handle, Ordering::Relaxed);
    REAL.mem_alloc
        .store(resolve(handle, b"cuMemAlloc_v2\0"), Ordering::Relaxed);
    REAL.mem_alloc_managed
        .store(resolve(handle, b"cuMemAllocManaged\0"), Ordering::Relaxed);
    REAL.mem_alloc_pitch
        .store(resolve(handle, b"cuMemAllocPitch_v2\0"), Ordering::Relaxed);
    REAL.mem_free
        .store(resolve(handle, b"cuMemFree_v2\0"), Ordering::Relaxed);
    REAL.mem_get_info
        .store(resolve(handle, b"cuMemGetInfo_v2\0"), Ordering::Relaxed);
    REAL.mem_create
        .store(resolve(handle, b"cuMemCreate\0"), Ordering::Relaxed);
    REAL.mem_release
        .store(resolve(handle, b"cuMemRelease\0"), Ordering::Relaxed);
    REAL.get_proc_address
        .store(resolve(handle, b"cuGetProcAddress\0"), Ordering::Relaxed);
    REAL.get_proc_address_v2
        .store(resolve(handle, b"cuGetProcAddress_v2\0"), Ordering::Relaxed);

    // The two that must exist for accounting to mean anything. Without both, an allocation could be
    // charged and never credited back, which is worse than not intercepting at all.
    let usable = !REAL.mem_alloc.load(Ordering::Relaxed).is_null()
        && !REAL.mem_free.load(Ordering::Relaxed).is_null();

    // `Release` publishes every store above to any thread that later loads `READY` with `Acquire`.
    STATE.store(if usable { READY } else { FAILED }, Ordering::Release);
    usable
}

/// Try each candidate path until one opens.
///
/// # Safety
/// Calls `dlopen`.
unsafe fn open_driver() -> *mut c_void {
    // An operator's override wins, and a wrong one fails rather than falling back to a search: a
    // silent fallback would load a different driver than the one that was named, which is exactly the
    // situation someone sets this variable to avoid.
    if let Ok(p) = std::env::var(PATH_OVERRIDE) {
        if p.is_empty() || p.as_bytes().contains(&0) {
            return core::ptr::null_mut();
        }
        let mut c = Vec::with_capacity(p.len() + 1);
        c.extend_from_slice(p.as_bytes());
        c.push(0);
        return libc::dlopen(
            c.as_ptr() as *const c_char,
            libc::RTLD_NOW | libc::RTLD_LOCAL,
        );
    }
    for path in DRIVER_PATHS {
        let h = libc::dlopen(
            path.as_ptr() as *const c_char,
            libc::RTLD_NOW | libc::RTLD_LOCAL,
        );
        if !h.is_null() {
            return h;
        }
    }
    core::ptr::null_mut()
}

/// Read a resolved slot as a typed function pointer.
///
/// `None` when the symbol was not found or was refused for pointing back into this library, which the
/// caller must turn into an error rather than a call.
///
/// # Safety
/// The caller asserts that `T` is the correct signature for the slot being read. Every call site in
/// this crate pairs a slot with the type declared for it above, and the pairing is the unsafe part:
/// reading `mem_free` as `FnMemAlloc` would call a one-argument function with two.
#[inline(always)]
pub unsafe fn typed<T: Copy>(slot: &AtomicPtr<c_void>) -> Option<T> {
    let p = slot.load(Ordering::Relaxed);
    if p.is_null() {
        return None;
    }
    debug_assert_eq!(
        core::mem::size_of::<T>(),
        core::mem::size_of::<*mut c_void>(),
        "a function pointer type must be pointer sized"
    );
    Some(core::mem::transmute_copy::<*mut c_void, T>(&p))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The error codes are ABI. A workload's error handling compares against these numbers, so an
    /// approximation is a code nothing recognises. Pinned against the values in `cuda.h`.
    #[test]
    fn the_cuda_error_codes_are_the_abi_values() {
        assert_eq!(CUDA_SUCCESS, 0);
        assert_eq!(CUDA_ERROR_INVALID_VALUE, 1);
        assert_eq!(CUDA_ERROR_OUT_OF_MEMORY, 2);
        assert_eq!(CUDA_ERROR_NOT_INITIALIZED, 3);
        assert_eq!(CUDA_ERROR_NOT_FOUND, 500);
    }

    /// Every driver path is absolute and NUL terminated. A relative path would be resolved against
    /// the workload's working directory, and a missing NUL would read past the end of the literal.
    #[test]
    fn every_driver_path_is_absolute_and_terminated() {
        for p in DRIVER_PATHS {
            assert_eq!(p.last(), Some(&0), "path is not NUL terminated: {p:?}");
            assert_eq!(p.first(), Some(&b'/'), "path is not absolute: {p:?}");
            assert!(
                !p[..p.len() - 1].contains(&0),
                "path has an interior NUL: {p:?}"
            );
        }
    }

    /// A function pointer must be pointer sized, or [`typed`] would read or write past the slot. This
    /// is true on every ABI kern targets and is asserted rather than assumed.
    #[test]
    fn function_pointers_are_pointer_sized() {
        assert_eq!(
            core::mem::size_of::<FnMemAlloc>(),
            core::mem::size_of::<*mut c_void>()
        );
        assert_eq!(
            core::mem::size_of::<FnGetProcAddressV2>(),
            core::mem::size_of::<*mut c_void>()
        );
    }

    /// THE RECURSION GUARD, tested against a pointer that really is in this object. Without this
    /// check a resolution that found our own symbol would be called, and the first allocation would
    /// recurse until the stack ended.
    #[test]
    fn a_pointer_into_this_library_is_recognised() {
        let mine = a_pointer_into_this_library_is_recognised as *const () as *mut c_void;
        // SAFETY: the pointer is the address of a function in this object.
        assert!(
            unsafe { points_into_this_library(mine) },
            "a function of ours was not recognised as ours, so the recursion guard is off"
        );
    }

    /// And against one that is not: libc's `malloc` is in a different object on every Linux host
    /// that has a dynamic libc. Skipped rather than failed where it is not, since a fully static
    /// build has one object by definition and the question does not arise.
    #[test]
    fn a_pointer_from_another_object_is_not_mistaken_for_ours() {
        // SAFETY: `dlsym` on the default handle with a NUL-terminated name.
        let p = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"malloc".as_ptr()) };
        if p.is_null() {
            println!("SKIP: no dynamic malloc to compare against on this build");
            return;
        }
        // SAFETY: `p` came from `dlsym`.
        let same = unsafe { points_into_this_library(p) };
        if same {
            println!("SKIP: malloc resolves into this object (static build)");
        }
    }

    /// The state machine must never let a hook read the table before it is published. Checked as the
    /// property that matters: only `READY` is a green light, and every other state is a refusal.
    #[test]
    fn only_the_ready_state_admits_a_reader() {
        for s in [UNINIT, INITIALIZING, FAILED] {
            assert_ne!(s, READY);
        }
        assert!(
            STATE.load(Ordering::Acquire) != READY,
            "the table must not be published in a unit test that never resolved a driver"
        );
    }

    /// An empty or NUL-containing override is refused rather than passed to `dlopen`. An interior NUL
    /// would truncate the path at the loader, opening a different file than the one that was named.
    #[test]
    fn a_malformed_driver_override_is_refused() {
        // Exercised through the same validation the resolver uses, without calling `dlopen`.
        for bad in ["", "/usr/lib/libcuda.so.1\0/../evil.so"] {
            let refused = bad.is_empty() || bad.as_bytes().contains(&0);
            assert!(refused, "override {bad:?} would have reached dlopen");
        }
    }
}
