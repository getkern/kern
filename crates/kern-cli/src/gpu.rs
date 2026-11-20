//! GPU DETECTION, read-only.
//!
//! This module answers one question and refuses the others: *which GPUs does this host have, and
//! which of them can a grant pair with?* It does not slice, cap, intercept or load anything. It
//! reads sysfs, names each card, and reads the PCI address that pairs it with the grant.
//!
//! IT USED TO CLASSIFY A CAPABILITY TIER, and most of its length was that. The model asked what a
//! VRAM cap would be worth on each card and answered `TIER-HW` or `TIER-SOFT` with the evidence
//! for it. That vocabulary is device-level partitioning, which kern does not do: it grants whole
//! cards. A row describing a mechanism this binary does not have spent the reader's attention on
//! a question they could not act on, and the framing had already outlived itself, claiming that
//! `kern box --help` has no `--gpus` after `--gpus` shipped. The tiers, the evidence, the
//! classifier and the `dmem` and `/dev/kfd` facts that qualified them went together.
//!
//! WHAT SURVIVED THE REMOVAL, because it was never about tiers:
//!
//!   THE MEASUREMENT. On the two NVIDIA hosts this project can reach (an RTX 5060 Ti on driver
//!   580.173.02 and a Jetson Orin Nano on 540.4.0), a process with libc and nothing else in its
//!   address space opens the device node and receives an answer from the driver. Any cap installed
//!   in front of the vendor library is a cap that tenant never went through. Same result from the
//!   vendor-neutral side on a Raspberry Pi 5 (`v3d`, `vc4`). `pentest/pentest-gpu-claims.sh` runs
//!   it, and it is why a granted card is described as not a boundary rather than as a quota.
//!
//!   THE DISTINCTION THAT GOVERNED THE FILE, which now governs the one claim it still makes:
//!   "the limit applies" and "the limit is a security boundary" are different properties, and
//!   conflating them is the failure this exists to prevent.
//!
//!   THE `dmem` FINDING, kept because it is the reason no cap is offered. On an RX 6700 XT
//!   (gfx1031), amdgpu/ROCm on kernel 6.17, `CONFIG_CGROUP_DMEM=y`: with a per-cgroup `dmem.max`
//!   of 2 GB an 8 GB `hipMalloc` SUCCEEDED and the leaf cgroup's `dmem.current` stayed at 0 while
//!   8 GB sat in VRAM, while managed memory did charge the leaf 166 MiB. The DRM render path is
//!   charged and the KFD compute path, the one ML tenants use, is not. One card, one driver, one
//!   kernel: nothing here says what `dmem` does on any other, and that uncertainty is exactly why
//!   it was never allowed to promote anything.
//!
//! ALLOCATION NOTE
//!   This path allocates: it reads sysfs into `String`s and returns an owned `Vec`. That is
//!   deliberate and in scope. The project's no-heap rule governs the per-box hot path, where a box
//!   starts in ~2.3 ms and an allocation is a measurable fraction of it. This is not that path, and
//!   the difference is measured rather than assumed: [`detect`] costs 36 us per call (1000
//!   iterations, i7-14700KF) against a `kern doctor` run that already spends milliseconds forking
//!   `systemd-run` three times to time the scope toll. Optimising a `read_to_string` here would buy
//!   a fraction of a percent of one interactive command and cost clarity.

use std::path::Path;

/// PCI vendor identifiers, as they appear in `/sys/class/drm/card*/device/vendor`.
const PCI_VENDOR_NVIDIA: u32 = 0x10de;
const PCI_VENDOR_AMD: u32 = 0x1002;
const PCI_VENDOR_INTEL: u32 = 0x8086;

/// Words that may only ever appear in text kern prints about a [`Tier::Hw`] GPU.
///
/// Enforced mechanically by the unit tests below rather than trusted to a reading, in the same spirit
/// as the em-dash and stale-numbers gates. A claim that overstates the boundary is the single most
/// expensive defect this project can ship, because every other honest statement stops being
/// believed with it, and prose drifts upward under editing in a way that code does not.
///
/// Matched case-insensitively on the raw substring, so `hard` also catches `hardware` and
/// `hardened`. That is deliberate over-reach: a false positive costs one rewording, a false
/// negative ships an overstated claim.
///
/// Test-only, and deliberately so. A runtime check here could only ever redact a string that a
/// correct build never produces, which is an unreachable branch nobody has read the output of. The
/// contract belongs where it can fail loudly, at build time, in one place: [`crate::doctor`] uses
/// this same constant on the ASSEMBLED line rather than keeping a second copy of the vocabulary.
#[cfg(test)]
pub const BOUNDARY_WORDS: [&str; 3] = ["isolation", "secure", "hard"];

/// Does `text` contain a word reserved for hardware-enforced partitioning?
#[cfg(test)]
pub fn overclaims(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    BOUNDARY_WORDS.into_iter().find(|w| lower.contains(w))
}

/// The GPU vendor, from the PCI id rather than from a driver name or a marketing string.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Vendor {
    Nvidia,
    Amd,
    Intel,
    /// A PCI vendor kern has no constant for. The id is carried so the line still identifies it.
    Other(u32),
    /// NOT A PCI DEVICE, which is the normal case on every ARM board kern targets. A Raspberry Pi 5
    /// exposes `card0` (driver `v3d`) and `card1` (`vc4-drm`) on the platform bus, and a Jetson Orin
    /// Nano exposes `card0` (`drm`) and `card1` (`nv_platform`); none of the four has a
    /// `device/vendor` attribute at all. Measured on both boards on 2026-08-28.
    NonPci,
}

impl Vendor {
    fn from_pci(id: u32) -> Self {
        match id {
            PCI_VENDOR_NVIDIA => Vendor::Nvidia,
            PCI_VENDOR_AMD => Vendor::Amd,
            PCI_VENDOR_INTEL => Vendor::Intel,
            other => Vendor::Other(other),
        }
    }

    /// How the vendor appears on the `doctor` line. Owned, because an unrecognised PCI vendor is
    /// named by its id and there is no static string for that.
    pub fn label(self) -> String {
        match self {
            Vendor::Nvidia => "NVIDIA".to_string(),
            Vendor::Amd => "AMD".to_string(),
            Vendor::Intel => "Intel".to_string(),
            Vendor::Other(id) => format!("PCI vendor {id:#06x}"),
            Vendor::NonPci => "non-PCI".to_string(),
        }
    }
}

/// What a box gets when a compute node is handed to it.
///
/// THE ONE CLAIM THIS MODULE MAKES, in one place, so the two surfaces that print it cannot drift.
/// It replaced four lines describing a "cooperative VRAM quota" and pointing a reader who wanted a
/// boundary at "a device-level partition (MIG or SR-IOV)": kern caps no VRAM and partitions no
/// device, so both sentences answered a question about a mechanism that was never offered.
///
/// What is left is the promise that holds and was measured: a card with no node in the box cannot
/// be initialised by CUDA there. `pentest/pentest-gpu-claims.sh` and `overclaims` both read this
/// string.
pub const COMPUTE_NODE_CLAIM: &str =
    "a granted compute node talks to the host's driver, so it is NOT a boundary against malicious \
     code in the box; a card with no node here cannot be initialised by CUDA at all";

/// One GPU as kern sees it: what the device is, and how to pair it with a grant.
#[derive(Clone, Debug)]
pub struct Gpu {
    /// The DRM card name, for example `card0`. Owned because the caller outlives the scan.
    pub card: String,
    pub vendor: Vendor,
    /// PCI device id. `None` when sysfs did not expose one, which is itself worth showing.
    pub device_id: Option<u32>,
    /// The kernel driver bound to the card (`nvidia`, `amdgpu`, `v3d`, `nv_platform`). On a board
    /// with no PCI identity this is the ONLY thing that names the device, which is why it is here.
    pub driver: Option<String>,
    /// The card's PCI address, read from where `/sys/class/drm/<card>/device` points.
    ///
    /// IT IS THE JOIN KEY, and it is here so there is only one. A DRM card and the `/dev/nvidiaN`
    /// a grant names are two views of one device, and the number in one name does not determine the
    /// number in the other. Pairing them by number would report the wrong card's grant, and would
    /// pass on any host whose two numberings happened to agree.
    ///
    /// THE PAIRING IS NOT EVEN STABLE ON ONE MACHINE, which is better evidence than the static
    /// claim that used to stand here. This file said "on this host their numbering is INVERTED:
    /// `nvidia0` is `card1`", measured and true when written. After a reboot on 2026-11-12 the same
    /// machine reports `0000:01:00.0` as `nvidia0` AND `card0`, derived from
    /// `/sys/bus/pci/devices/<addr>/drm` and `Device Minor:` in the driver's own directory. DRM
    /// minors are handed out in probe order, so a kernel or firmware change reorders them. Anything
    /// that caches the pairing, or states it in prose, expires without warning; the address does
    /// not.
    ///
    /// `None` for a device with no PCI identity, which is the normal case on an ARM board.
    pub pci_address: Option<String>,
}

/// Read a sysfs attribute and strip the trailing newline the kernel always appends.
///
/// Returns `None` for every failure mode rather than distinguishing them: a GPU attribute that
/// cannot be read is, for this module's purposes, an attribute that does not exist. The caller
/// resolves absence to the weakest tier, so no error is silently upgraded into a claim.
fn read_attr(path: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

/// Parse a sysfs `0x`-prefixed hex id.
///
/// Rejects, rather than truncates, anything that does not match the kernel's own format. A vendor
/// id parsed loosely could map a garbage value onto a real vendor constant and produce a confident
/// wrong answer, which is worse than reporting nothing.
fn read_hex_id(path: &Path) -> Option<u32> {
    let text = read_attr(path)?;
    let digits = text.strip_prefix("0x")?;
    u32::from_str_radix(digits, 16).ok()
}

/// The PCI address (`0000:01:00.0`) behind a `/sys/class/drm/cardN/device` link.
///
/// Validated to the kernel's own `domain:bus:device.function` shape before it is returned, because
/// it is then used to BUILD A PATH under `/proc`. Nothing here is attacker-controlled today (sysfs
/// is the kernel's), but a component that reaches a path join has to be validated where it is read,
/// not where it happens to be safe. A value that does not match the shape yields `None`, and the
/// caller resolves `None` to the weakest tier.
fn pci_address(device_dir: &Path) -> Option<String> {
    let resolved = std::fs::canonicalize(device_dir).ok()?;
    let bdf = resolved.file_name()?.to_str()?.to_string();
    // dddd:bb:dd.f, hex, fixed widths. Rejects `.`, `..`, anything with a separator, and anything
    // the kernel would not have written.
    let ok = bdf.len() == 12
        && bdf.as_bytes()[4] == b':'
        && bdf.as_bytes()[7] == b':'
        && bdf.as_bytes()[10] == b'.'
        && bdf
            .bytes()
            .enumerate()
            .all(|(i, b)| matches!(i, 4 | 7 | 10) || b.is_ascii_hexdigit());
    ok.then_some(bdf)
}

/// The kernel driver bound to a card, from the `device/driver` symlink.
///
/// Validated to a plain file name for the same reason as [`pci_address`]: it is read from a link
/// target and then printed, and a component read from a link is validated where it is read. Names
/// seen in the wild are `nvidia`, `amdgpu`, `v3d`, `vc4-drm`, `nv_platform` and, on a Jetson's
/// host1x aggregator, literally `drm`.
fn driver_name(device_dir: &Path) -> Option<String> {
    let target = std::fs::read_link(device_dir.join("driver")).ok()?;
    let name = target.file_name()?.to_str()?.to_string();
    let ok = !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && name != "."
        && name != "..";
    ok.then_some(name)
}

/// Enumerate the GPUs on this host.
///
/// Reads `/sys/class/drm`, which the kernel populates for every DRM device, and keeps only the
/// primary nodes (`cardN`). Render nodes (`renderD*`) and the connector entries (`card0-HDMI-A-1`)
/// describe the same device and would otherwise be counted several times.
///
/// Returns an empty vector on a host with no GPU, which is a normal and reportable outcome, not an
/// error. A machine without a GPU is the majority case for this runtime.
///
/// A CARD IS NEVER DROPPED FOR BEING UNIDENTIFIABLE. The first version of this required a PCI
/// `vendor` attribute and skipped any card without one, which made `kern doctor` print "no GPU
/// found" on a Raspberry Pi 5 and on a Jetson Orin Nano, both of which have two DRM cards on the
/// platform bus and no `vendor` file on any of them (measured on both boards, 2026-08-28). Those
/// boards are the platforms kern is aimed at, and "no GPU found" on a machine with a GPU is a plain
/// false statement, which costs more than a line that says non-PCI and names the driver. Absent
/// identity now weakens the DESCRIPTION and never removes the device.
/// Is `path` a device node through which a tenant can reach GPU COMPUTE?
///
/// Used by `kern box --plan` to decide whether the full [`Tier::claim`] is worth printing. The
/// render node is the one a `vgpio:` profile is expected to grant and the one the config layer
/// allows; the primary `cardN` node is refused there today, and is matched anyway so that a future
/// grant cannot slip past this without also changing this function.
///
/// Prefix matching on the whole path, not a substring: a bind of `/home/user/renderD128` is a file
/// with a confusing name and not a GPU.
pub fn is_compute_node(path: &str) -> bool {
    path.starts_with("/dev/dri/renderD")
        || path.starts_with("/dev/dri/card")
        || path.starts_with("/dev/nvidia")
        || path == "/dev/kfd"
}

/// WSL2's GPU node, and the directory it mounts the vendor's user-space libraries into.
///
/// Relative to a root, like every other path in this module, so a test can build the shape without
/// a Windows kernel under it.
const WSL_NODE_REL: &str = "dev/dxg";
const WSL_LIB_REL: &str = "usr/lib/wsl/lib";
/// The Windows driver store, which WSL2 mounts read-only over 9p. The vendor's user-mode driver in
/// [`WSL_LIB_REL`] loads the rest of itself from here by absolute path, so a box needs it at the same
/// path: MEASURED on a WSL2 Ubuntu guest, CUDA in a box ran with it bound and not without it.
const WSL_DRIVERS_REL: &str = "usr/lib/wsl/drivers";
/// The library without which there is no CUDA driver to hand over.
const WSL_CUDA_LIB: &str = "libcuda.so.1";

/// The vendor's `nvidia-smi` on a WSL2 guest, relative to the root. It is the only reader of the
/// adapter list this binary can use: docker's toolkit asks `libdxcore` (a glibc library kern does
/// not load), and on WSL2 there is no `/proc/driver/nvidia` to read the cards from.
const WSL_SMI_REL: &str = "usr/lib/wsl/lib/nvidia-smi";

/// The file that marks a driver-store directory as the NVIDIA one: the real CUDA driver, which the
/// `libcuda.so.1` in the vendor directory loads from there.
const WSL_STORE_CUDA: &str = "libcuda.so.1.1";

/// The adapters a WSL2 VM has, as `(index, UUID)` in the order `nvidia-smi` lists them, or `None`
/// when the list cannot be read here.
///
/// `None` IS NOT "NO ADAPTER". The vendor's tool is a glibc build, so on a musl guest (the Alpine
/// distribution this was measured on) it cannot run at all, and the caller says the selection went
/// unchecked rather than refusing a card that may well exist.
///
/// BOUNDED: a tool that hangs costs a deadline and not the box start. MEASURED on a WSL2 Ubuntu
/// guest: 53 to 69 ms, which is why the launch asks only when the selection is narrower than `all`.
pub fn wsl_adapters(root: &Path) -> Option<Vec<(u32, String)>> {
    // ONCE PER PROCESS FOR THE REAL ROOT: one box start asked up to three times (the selection, the
    // UUID check and the grant), each a 53 to 69 ms `nvidia-smi`, and the adapters cannot change
    // while kern runs. Any other root is a test's, which rewrites its tool between calls.
    if root == Path::new("/") {
        static REAL: std::sync::OnceLock<Option<Vec<(u32, String)>>> = std::sync::OnceLock::new();
        return REAL.get_or_init(|| wsl_adapters_asked(root)).clone();
    }
    wsl_adapters_asked(root)
}

/// [`wsl_adapters`], asked of the tool every time.
fn wsl_adapters_asked(root: &Path) -> Option<Vec<(u32, String)>> {
    foreign_shape_in(root)?;
    let text = run_bounded(
        &root.join(WSL_SMI_REL),
        &["--query-gpu=index,uuid", "--format=csv,noheader"],
    )?;
    let adapters = parse_adapters(&text);
    if adapters.is_empty() {
        None
    } else {
        Some(adapters)
    }
}

/// The indices of the NVIDIA adapters a WSL2 VM has, or `None` when they cannot be known here.
///
/// FROM THE VENDOR'S TOOL WHEN IT RUNS, and otherwise from `/dev/dxg` itself, which answers without
/// any C library: on the Alpine guest, where the glibc `nvidia-smi` cannot start, kern accepted
/// `--gpus device=1` unchecked. nvidia-smi numbers the NVIDIA adapters 0 to n-1, so a count is
/// enough to check an index or a count; it is not enough to resolve a UUID, which only the tool
/// prints.
pub fn wsl_adapter_indices(root: &Path) -> Option<Vec<u32>> {
    if let Some(listed) = wsl_adapters(root) {
        return Some(listed.into_iter().map(|(index, _)| index).collect());
    }
    let shape = foreign_shape_in(root)?;
    match dxg_nvidia_adapters(&shape.node)? {
        0 => None,
        n => Some((0..n).collect()),
    }
}

/// How many GPUs this host has, by the one rule every surface uses: the DRM cards, else (WSL2, which
/// has no DRM card for its GPU) the NVIDIA adapters behind `/dev/dxg`.
pub fn card_count() -> usize {
    match detect().len() {
        0 => wsl_nvidia_adapter_count(Path::new("/")).map_or(0, |n| n as usize),
        n => n,
    }
}

/// How many NVIDIA adapters a WSL2 guest has, asked of `/dev/dxg` alone: `Some(0)` for a WSL2
/// guest with none, `None` when this is not a WSL2 guest or the driver cannot be asked.
///
/// FOR `kern info`, which must not pay for the vendor's tool (53 to 69 ms) on every orientation:
/// two ioctls on a node already open, no process. WSL2 has no `/sys/class/drm` card for the GPU,
/// so the inventory that reads only that tree said `gpu none` on a guest where `--gpus all` runs
/// `nvidia-smi` (reported on WSL2 against 6d93b85).
pub fn wsl_nvidia_adapter_count(root: &Path) -> Option<u32> {
    let shape = foreign_shape_in(root)?;
    Some(dxg_nvidia_adapters(&shape.node).unwrap_or(0))
}

/// Is this a WSL2 guest whose adapters' UUIDs cannot be read? Only the vendor's `nvidia-smi` prints
/// them, and on a musl guest it cannot start; `/dev/dxg` gives ids and a count, never a UUID.
pub fn wsl_uuids_unreadable(root: &Path) -> bool {
    foreign_shape_in(root).is_some() && wsl_adapters(root).is_none()
}

/// The note for a `device=GPU-…` accepted unchecked on such a guest, one spelling for both surfaces.
pub fn describe_wsl_unchecked_uuid(spec: &str) -> String {
    format!(
        "--gpus {spec}: this WSL2 guest cannot read its adapters' UUIDs (only the vendor's \
         nvidia-smi prints them, and it is a glibc build that cannot start here), so the UUID is \
         not checked. The GPU reaches the box through /dev/dxg, which carries every adapter"
    )
}

/// PCI vendor id the WSL2 host reports for an NVIDIA adapter.
const DXG_VENDOR_NVIDIA: u32 = 0x10de;
/// `D3DKMT_ADAPTERS_MAX` in the WSL kernel's `d3dkmthk.h`: more is not an answer, it is garbage.
const DXG_ADAPTERS_MAX: u32 = 64;
/// `KMTQAITYPE_PHYSICALADAPTERDEVICEIDS`, a Windows query type the WSL kernel passes to the host
/// unfiltered (`dxgvmb_send_query_adapter_info`), answered with the adapter's PCI ids.
const KMTQAITYPE_PHYSICALADAPTERDEVICEIDS: u32 = 31;

/// `_IOWR(0x47, nr, size)`, the dxgkrnl ioctl encoding.
const fn dxg_iowr(nr: u64, size: usize) -> u64 {
    (3u64 << 30) | ((size as u64) << 16) | (0x47u64 << 8) | nr
}

/// `struct d3dkmt_adapterinfo`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DxgAdapterInfo {
    handle: u32,
    luid_low: u32,
    luid_high: u32,
    num_sources: u32,
    present_move_regions_preferred: u32,
}

/// `struct d3dkmt_enumadapters2`, user-space layout.
#[repr(C)]
struct DxgEnumAdapters2 {
    num_adapters: u32,
    reserved: u32,
    adapters: u64,
}

/// `struct d3dkmt_queryadapterinfo`, user-space layout (24 bytes with its padding).
#[repr(C)]
struct DxgQueryAdapterInfo {
    adapter: u32,
    kind: u32,
    private_data: u64,
    private_data_size: u32,
}

/// `D3DKMT_QUERY_DEVICE_IDS`: the physical adapter index, then `D3DKMT_DEVICE_IDS`.
#[repr(C)]
#[derive(Default)]
struct DxgDeviceIds {
    physical_adapter_index: u32,
    vendor_id: u32,
    device_id: u32,
    sub_vendor_id: u32,
    sub_system_id: u32,
    revision_id: u32,
    bus_type: u32,
}

/// How many adapters behind `node` are NVIDIA's, asked of the kernel driver directly.
///
/// MEASURED on the Alpine WSL2 guest with a static probe of exactly these calls before they were
/// written here: one adapter, vendor `0x10de`, device `0x2504` (the RTX 3060 Windows shows), every
/// ioctl returning 0. Every handle the enumeration opens is closed again.
fn dxg_nvidia_adapters(node: &Path) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(node)
        .ok()?;
    let fd = file.as_raw_fd();
    let enum_req = dxg_iowr(0x14, std::mem::size_of::<DxgEnumAdapters2>());
    let mut e = DxgEnumAdapters2 {
        num_adapters: 0,
        reserved: 0,
        adapters: 0,
    };
    // SAFETY: `e` is a live, correctly laid out `d3dkmt_enumadapters2` with no adapter buffer, which
    // the driver answers with the count alone.
    if unsafe { libc::ioctl(fd, enum_req as _, &mut e as *mut DxgEnumAdapters2) } != 0 {
        return None;
    }
    if e.num_adapters == 0 || e.num_adapters > DXG_ADAPTERS_MAX {
        return None;
    }
    let mut infos = vec![DxgAdapterInfo::default(); e.num_adapters as usize];
    e.adapters = infos.as_mut_ptr() as u64;
    // SAFETY: the buffer holds `num_adapters` entries and outlives the call.
    if unsafe { libc::ioctl(fd, enum_req as _, &mut e as *mut DxgEnumAdapters2) } != 0 {
        return None;
    }
    let filled = (e.num_adapters as usize).min(infos.len());
    let query_req = dxg_iowr(0x09, std::mem::size_of::<DxgQueryAdapterInfo>());
    let close_req = dxg_iowr(0x15, std::mem::size_of::<u32>());
    let mut nvidia = 0u32;
    let mut every_query_answered = true;
    for info in &infos[..filled] {
        let mut ids = DxgDeviceIds::default();
        let mut q = DxgQueryAdapterInfo {
            adapter: info.handle,
            kind: KMTQAITYPE_PHYSICALADAPTERDEVICEIDS,
            private_data: &mut ids as *mut DxgDeviceIds as u64,
            private_data_size: std::mem::size_of::<DxgDeviceIds>() as u32,
        };
        // SAFETY: `q` points at `ids`, which is `private_data_size` bytes and outlives the call.
        let rc = unsafe { libc::ioctl(fd, query_req as _, &mut q as *mut DxgQueryAdapterInfo) };
        if rc != 0 {
            every_query_answered = false;
        } else if ids.vendor_id == DXG_VENDOR_NVIDIA {
            nvidia += 1;
        }
        let mut handle = info.handle;
        // SAFETY: a `d3dkmt_closeadapter` is the one handle the enumeration opened.
        let _ = unsafe { libc::ioctl(fd, close_req as _, &mut handle as *mut u32) };
    }
    // AN ADAPTER THAT DID NOT ANSWER MAKES THE COUNT A GUESS, and a guess would refuse a card that
    // may exist: no answer then, and the caller says the selection went unchecked.
    if every_query_answered {
        Some(nvidia)
    } else {
        None
    }
}

/// `nvidia-smi --query-gpu=index,uuid --format=csv,noheader`, read. A line that is not an index and
/// a `GPU-` UUID is skipped rather than guessed at.
pub fn parse_adapters(text: &str) -> Vec<(u32, String)> {
    let mut out: Vec<(u32, String)> = Vec::new();
    for line in text.lines() {
        let Some((index, uuid)) = line.split_once(',') else {
            continue;
        };
        let (Ok(index), uuid) = (index.trim().parse::<u32>(), uuid.trim()) else {
            continue;
        };
        if uuid.len() > 4 && uuid[..4].eq_ignore_ascii_case("GPU-") {
            out.push((index, uuid.to_string()));
        }
    }
    out.sort();
    out
}

/// Run `program args` with a deadline and return its stdout, or `None` if it could not start, did
/// not exit in time, or failed. The child is killed AND reaped on the deadline.
pub(crate) fn run_bounded(program: &Path, args: &[&str]) -> Option<String> {
    use std::io::Read;
    use std::time::{Duration, Instant};
    const BUDGET: Duration = Duration::from_secs(5);
    const READ_MAX: u64 = 64 * 1024;
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + BUDGET;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            Ok(None) | Err(_) => break None,
        }
    };
    let Some(status) = status else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    if !status.success() {
        return None;
    }
    let mut buf = Vec::new();
    if let Some(out) = child.stdout.take() {
        let _ = out.take(READ_MAX).read_to_end(&mut buf);
    }
    String::from_utf8(buf).ok()
}

/// What a selection narrower than `all` means on a WSL2 guest whose adapters are known.
///
/// DOCKER'S REFUSALS, MEASURED with toolkit 1.20.2 on a one-adapter guest: `--gpus device=1` and
/// `--gpus 2` both fail with `nvidia-container-cli: device error: 1: unknown device`, while
/// `device=0`, `1` and `all` run. kern refuses the same two, with the sentences the native grant
/// uses for the same cases, so a reader meets one wording for one mistake.
///
/// `Ok(true)` means the selection names FEWER adapters than the VM has: it is accepted, and the
/// caller says that `/dev/dxg` still carries all of them.
pub fn wsl_check_selection(
    selection: &crate::gpu_grant::GpuSelection,
    present: &[u32],
) -> Result<bool, crate::gpu_grant::MountPlanError> {
    use crate::gpu_grant::{GpuSelection, MountPlanError};
    let present: Vec<u32> = present.to_vec();
    match selection {
        GpuSelection::All => Ok(false),
        GpuSelection::Count(n) => {
            if (*n as usize) > present.len() {
                return Err(MountPlanError::TooFewCards {
                    wanted: *n,
                    present,
                });
            }
            Ok((*n as usize) < present.len())
        }
        GpuSelection::These(wanted) => {
            if let Some(missing) = wanted.iter().find(|w| !present.contains(w)) {
                return Err(MountPlanError::NoSuchCard {
                    wanted: *missing,
                    present,
                });
            }
            Ok(wanted.len() < present.len())
        }
    }
}

/// The NVIDIA directories of the WSL2 driver store, or `None` when none can be told apart.
///
/// DOCKER BINDS ONE DIRECTORY OF THE STORE, NOT THE STORE. Measured with toolkit 1.20.2: the box gets
/// `nvmdi.inf_amd64_<hash>` and nothing else from `/usr/lib/wsl/drivers`, which on the guest this was
/// measured on holds 795 directories, every vendor's driver for every device Windows ever saw.
///
/// ONLY THE `nv*` NAMES ARE OPENED, and that is a cost measured, not a style: the store is a 9p share,
/// and a `stat` in each of the 795 took 720 ms, on every box start. The 12 `nv*` names took 11 ms
/// and include the one that matters. The name only narrows WHERE to look; what makes a directory
/// the NVIDIA one is the CUDA driver inside it.
/// [`wsl_nvidia_store_dirs`], remembered across boxes and re-read only when the store changed.
///
/// MEASURED BOTTLENECK, the largest in a GPU box on WSL2: `/usr/lib/wsl/drivers` is the Windows
/// driver store over 9p, where a `stat` costs 0.5-0.7 ms, and the walk tests every `nv*` directory
/// of it (on the guest measured, about twenty) for the CUDA driver, on every `--gpus` box. A box
/// with the grant took 24.4 ms against 5.2 ms without, 15.2 of the difference in this one phase.
///
/// THE KEY is the store's device, inode and modification time, which change when Windows adds or
/// removes a driver directory. The cache lives in kern's runtime directory, which no box can mount,
/// and is believed only as far as it can be checked: a listed directory must sit directly in the
/// store, be named like the ones the walk accepts and still hold the CUDA driver, so a forged line
/// can neither name a directory outside the store nor one the walk would not have chosen.
fn wsl_nvidia_store_dirs_cached(drivers: &Path) -> Option<Vec<std::path::PathBuf>> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(drivers).ok()?;
    let key = format!(
        "v1 {} {} {} {}",
        m.dev(),
        m.ino(),
        m.mtime(),
        m.mtime_nsec()
    );
    let cache = crate::registry::runtime_subdir_public("gpu")
        .ok()
        .map(|d| d.join("wsl-store"));
    if let Some(text) = cache.as_ref().and_then(|c| std::fs::read_to_string(c).ok()) {
        let mut lines = text.lines();
        if lines.next() == Some(key.as_str()) {
            let dirs: Vec<std::path::PathBuf> = lines
                .map(std::path::PathBuf::from)
                .filter(|d| {
                    d.parent() == Some(drivers)
                        && d.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.to_ascii_lowercase().starts_with("nv"))
                        && d.join(WSL_STORE_CUDA).is_file()
                })
                .collect();
            if !dirs.is_empty() {
                return Some(dirs);
            }
        }
    }
    let dirs = wsl_nvidia_store_dirs(drivers)?;
    if let Some(c) = cache {
        let mut body = key;
        for d in &dirs {
            body.push('\n');
            body.push_str(&d.to_string_lossy());
        }
        body.push('\n');
        let _ = crate::config::write_atomic(&c, &body);
    }
    Some(dirs)
}

fn wsl_nvidia_store_dirs(drivers: &Path) -> Option<Vec<std::path::PathBuf>> {
    let mut out: Vec<std::path::PathBuf> = Vec::new();
    for entry in std::fs::read_dir(drivers).ok()?.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.to_ascii_lowercase().starts_with("nv") {
            continue;
        }
        let dir = entry.path();
        if dir.join(WSL_STORE_CUDA).is_file() {
            out.push(dir);
        }
    }
    if out.is_empty() {
        None
    } else {
        out.sort();
        Some(out)
    }
}

/// A GPU that is PRESENT on this host and that a grant cannot read, because the host exposes it
/// through an interface other than a vendor device node.
///
/// THE FIELD CASE, measured on 2026-11-12 on a Windows host reached over the network. The Windows
/// side answers `nvidia-smi.exe` with `NVIDIA GeForce RTX 3060, 591.74, 12288 MiB`. The WSL2 guest
/// on the same machine (Alpine 3.20.10, kernel `6.18.33.2-microsoft-standard-WSL2`) has:
///
///   - `/dev/dxg`, `crw-rw-rw- 10, 258`, and NO `/dev/nvidia*` and no `/dev/dri` at all,
///   - no `/proc/driver/nvidia` directory, so no version file,
///   - 21 files in `/usr/lib/wsl/lib`, `libcuda.so.1` among them, on an overlay of
///     `/gpu_lib_packaged:/gpu_lib_inbox`.
///
/// So [`detect`] finds no DRM card and [`crate::gpu_grant::resolve`] finds no driver version, and
/// every surface that reported those two absences told the operator of a machine with a 12 GB card
/// that there was no GPU. The kern installed on that host said `no GPU found` with a green tick.
/// The comment on [`detect`] already forbids exactly this for the Pi and the Jetson, where the card
/// has no PCI identity; WSL2 is the third shape, and there the DEVICE NODE is the part that is
/// missing, which is one layer below anything `detect` reads.
///
/// IT IS GRANTED NOW, BY [`wsl_grant`], and the first measurement explains why it was not. On the
/// Alpine guest above `cuInit` returned 100 (`CUDA_ERROR_NO_DEVICE`): the vendor libraries are glibc
/// builds and that distribution is musl, so nothing there could load them. On an Ubuntu 24.04 guest
/// of the same machine a CUDA kernel ran and returned the right answer, outside kern and then inside
/// a box given `/dev/dxg`, the library directory, the driver store and the loader path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignShape {
    /// How the interface is named to a reader. Static: there is one shape, and a second one would
    /// be a second measurement rather than a second format string.
    pub interface: &'static str,
    /// The device node, under the root that was passed.
    pub node: std::path::PathBuf,
    /// The vendor's library directory, when it is there. `None` keeps the row honest on a kernel
    /// that exposes the node with no libraries mounted next to it.
    pub libraries: Option<std::path::PathBuf>,
}

/// Does `root` expose a GPU through an interface no grant in this binary reads?
///
/// `symlink_metadata`, so a symlink at the node path is NOT followed: a link is not the device, and
/// following one would let the answer come from a file outside the root a test or a caller named.
///
/// THE NODE MUST BE A CHARACTER DEVICE, which is the same first question [`crate::gpu_grant`] asks
/// of every path it is about to bind. The rdev is NOT also checked here, and the asymmetry is
/// deliberate: that check exists in the grant path because a forged `c 0 0` would be BOUND INTO A
/// BOX, while the only thing this function can change is one line of prose about the host's own
/// `/dev`, where planting a node already requires root.
pub fn foreign_shape_in(root: &Path) -> Option<ForeignShape> {
    use std::os::unix::fs::FileTypeExt;
    let node = root.join(WSL_NODE_REL);
    if !std::fs::symlink_metadata(&node)
        .map(|m| m.file_type().is_char_device())
        .unwrap_or(false)
    {
        return None;
    }
    let lib_dir = root.join(WSL_LIB_REL);
    let libraries = std::fs::metadata(&lib_dir)
        .ok()
        .filter(|m| m.is_dir())
        .map(|_| lib_dir);
    Some(ForeignShape {
        interface: "WSL2's paravirtual GPU interface",
        node,
        libraries,
    })
}

/// The one sentence that describes [`ForeignShape`], written once because several surfaces print it:
/// the `doctor` row for a host with no DRM card, the `--gpus` refusal when the shape cannot be
/// granted, and the `--device` refusal.
///
/// ⛔ IT USED TO SAY "neither --gpus nor --device has a node to name", which became false for
/// `--gpus` the day [`wsl_grant`] existed. It now says what is TRUE on the host it is printed on:
/// whether the CUDA driver is there to hand over, and why `--device` still has nothing to resolve
/// to (CDI names one card, and WSL2 gives no per-card node).
pub fn describe_foreign_shape(shape: &ForeignShape) -> String {
    let node = shape.node.display();
    match &shape.libraries {
        Some(dir) if dir.join(WSL_CUDA_LIB).exists() => format!(
            "a GPU is present here through {} at {node}, with the vendor libraries in {}: \
             `--gpus` grants it, as that node and those libraries. Every adapter comes with it, \
             because WSL2 gives no per-card node, and for the same reason a CDI name for one card \
             (`--device`) has nothing to resolve to",
            shape.interface,
            dir.display()
        ),
        Some(dir) => format!(
            "a GPU is present here through {} at {node}, and {} holds no {WSL_CUDA_LIB}, so there \
             is no CUDA driver for `--gpus` or `--device` to hand over",
            shape.interface,
            dir.display()
        ),
        None => format!(
            "a GPU is present here through {} at {node}, with no vendor library directory next to \
             it, so there is nothing for `--gpus` or `--device` to hand over",
            shape.interface
        ),
    }
}

/// What a box is given for a WSL2 GPU: every bind, as (host source, box target, read-only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WslGrant {
    /// The node, the NVIDIA part of the driver store and the tools: binds whose target does not
    /// depend on the image.
    pub binds: Vec<(String, String, bool)>,
    /// The vendor's libraries, as (host file, name), placed by [`WslGrant::binds_into`] in the
    /// image's library directory once the image is known.
    pub libraries: Vec<(String, String)>,
}

impl WslGrant {
    /// Every bind, the libraries in `lib_dir` (see [`crate::gpu_grant::box_library_dir`]).
    ///
    /// DOCKER'S SHAPE, MEASURED with toolkit 1.20.2 on a WSL2 Ubuntu guest: the libraries are bound
    /// file by file into `/usr/lib/x86_64-linux-gnu`, `/usr/lib/wsl/lib` is not mounted, and
    /// `LD_LIBRARY_PATH` is empty. kern bound the directory and put it first on `LD_LIBRARY_PATH`,
    /// so an image whose entrypoint set its own value lost the driver; in the image's own library
    /// directory nothing an image does to its environment can take it away. Every library of the
    /// directory comes, where docker takes the five its default capabilities name, which is the
    /// native grant's rule too: the whole set.
    pub fn binds_into(&self, lib_dir: &str) -> Vec<(String, String, bool)> {
        let mut out = self.binds.clone();
        for (source, name) in &self.libraries {
            out.push((source.clone(), format!("{lib_dir}/{name}"), true));
        }
        out
    }
}

/// Why a WSL2 GPU that is present cannot be granted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WslGrantError {
    /// The node is there and the vendor library directory is not.
    NoLibraries { node: std::path::PathBuf },
    /// The directory is there and holds no CUDA driver.
    NoCudaLibrary { dir: std::path::PathBuf },
}

/// The grant for WSL2's paravirtual GPU, or `None` when `root` has no such shape.
///
/// THE RECIPE WAS MEASURED BEFORE IT WAS WRITTEN, on a WSL2 Ubuntu 24.04 guest (RTX 3060 on the
/// Windows side, driver 591.74), with the battery's own CUDA probe:
///
/// ```text
/// no grant                                                 NO-LIBCUDA   (the control)
/// /dev/dxg + /usr/lib/wsl/lib + /usr/lib/wsl/drivers
///   + /usr/lib/wsl/lib first on LD_LIBRARY_PATH            KERNEL-OK
/// ```
///
/// and then reshaped to docker's: the libraries file by file into the image's library directory
/// (see [`WslGrant::binds_into`]), no `LD_LIBRARY_PATH`, and of the driver store only the NVIDIA
/// directory, which the driver loads its pieces from by absolute path and so keeps its own path.
///
/// ⛔ NO PER-CARD SELECTION EXISTS. `/dev/dxg` carries every adapter the WSL2 VM has, so a box
/// granted it sees all of them whatever `--gpus` named; the caller says so rather than pretending
/// `device=0` narrowed anything.
pub fn wsl_grant(root: &Path) -> Option<Result<WslGrant, WslGrantError>> {
    let shape = foreign_shape_in(root)?;
    let Some(lib) = shape.libraries.clone() else {
        return Some(Err(WslGrantError::NoLibraries { node: shape.node }));
    };
    if !lib.join(WSL_CUDA_LIB).exists() {
        return Some(Err(WslGrantError::NoCudaLibrary { dir: lib }));
    }
    let as_box = |rel: &str| format!("/{rel}");
    let mut binds = vec![(
        shape.node.to_string_lossy().into_owned(),
        as_box(WSL_NODE_REL),
        false,
    )];
    // THE LIBRARIES BY NAME, symlinks resolved so the bind lands the file: the directory holds 21
    // `.so` entries on the guest measured, one of them a link (`libnvoptix_loader.so.1`).
    //
    // ONE `canonicalize` FOR THE DIRECTORY, and one more per entry that IS a link. Resolving every
    // entry walked each path component with a `readlink` (`/usr`, `/usr/lib`, ...): MEASURED, 136
    // of them per GPU box on that guest, for 21 libraries of which one is a link. The entry's type
    // comes with the directory listing, so a regular file is its directory's path plus its name.
    let mut libraries: Vec<(String, String)> = Vec::new();
    let lib_real = std::fs::canonicalize(&lib).unwrap_or_else(|_| lib.clone());
    if let Ok(entries) = std::fs::read_dir(&lib) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.contains(".so") {
                continue;
            }
            let real = match entry.file_type() {
                Ok(t) if t.is_file() => Some(lib_real.join(&name)),
                Ok(t) if t.is_symlink() => std::fs::canonicalize(entry.path())
                    .ok()
                    .filter(|r| r.is_file()),
                _ => None,
            };
            if let Some(real) = real {
                libraries.push((real.to_string_lossy().into_owned(), name));
            }
        }
    }
    libraries.sort_by(|a, b| a.1.cmp(&b.1));
    // THE NVIDIA PART OF THE STORE, as docker binds it; the whole store only when no directory in it
    // can be told to be NVIDIA's, which is the shape measured working before the narrowing existed.
    let drivers = root.join(WSL_DRIVERS_REL);
    if drivers.is_dir() {
        // The cache is for the HOST's store: a root other than `/` (a test's fixture) walks its own.
        let found = if root == Path::new("/") {
            wsl_nvidia_store_dirs_cached(&drivers)
        } else {
            wsl_nvidia_store_dirs(&drivers)
        };
        match found {
            Some(dirs) => {
                for dir in dirs {
                    let Some(name) = dir.file_name().and_then(|n| n.to_str()) else {
                        continue;
                    };
                    binds.push((
                        dir.to_string_lossy().into_owned(),
                        format!("/{WSL_DRIVERS_REL}/{name}"),
                        true,
                    ));
                }
            }
            None => binds.push((
                drivers.to_string_lossy().into_owned(),
                as_box(WSL_DRIVERS_REL),
                true,
            )),
        }
    }
    // THE DRIVER'S TOOLS AT `/usr/bin`, where docker puts them on WSL2 as well (measured: `nvidia-smi`
    // there, from this directory). Bound from the vendor directory, never copied.
    for name in kern_isolation::driver_tools() {
        if let Ok(real) = std::fs::canonicalize(lib.join(name)) {
            if real.is_file() {
                binds.push((
                    real.to_string_lossy().into_owned(),
                    format!("{}/{name}", crate::gpu_grant::DRIVER_TOOLS_IN_BOX),
                    true,
                ));
            }
        }
    }
    Some(Ok(WslGrant { binds, libraries }))
}

/// One sentence for a WSL2 GPU that cannot be granted.
pub fn describe_wsl_grant_error(e: &WslGrantError) -> String {
    match e {
        WslGrantError::NoLibraries { node } => format!(
            "--gpus: WSL2's GPU node {} is here and its vendor library directory /{WSL_LIB_REL} is \
             not, so there is no driver to hand a box. It is mounted by WSL when the Windows driver \
             supports WSL; `wsl --update` on the Windows side and a restart of the distribution is \
             the usual repair",
            node.display()
        ),
        WslGrantError::NoCudaLibrary { dir } => format!(
            "--gpus: {} holds no {WSL_CUDA_LIB}, so the Windows driver exposes no CUDA to this \
             distribution and there is nothing for a box to run",
            dir.display()
        ),
    }
}

/// [`describe_foreign_shape`] for the root, or an empty string. The empty case is the majority of
/// hosts and the caller prints nothing for it.
pub fn foreign_shape_note(root: &Path) -> String {
    foreign_shape_in(root)
        .map(|s| describe_foreign_shape(&s))
        .unwrap_or_default()
}

/// [`foreign_shape_note`] at the length a `kern doctor` note line holds (140 characters).
///
/// THE LONG SENTENCE IS RIGHT IN A REFUSAL AND WRONG IN `doctor`, whose rows are held to a terminal's
/// width by a test: on a WSL2 guest the note was 329 characters and the test failed there, while on
/// a host without `/dev/dxg` it never ran. MEASURED 2026-11-14 in `kern-ubuntu`. The row's TITLE
/// already says whether `--gpus` grants the GPU, so the note carries only what the title cannot.
pub fn foreign_shape_short(root: &Path) -> String {
    let Some(shape) = foreign_shape_in(root) else {
        return String::new();
    };
    match &shape.libraries {
        Some(dir) if dir.join(WSL_CUDA_LIB).exists() => {
            "every adapter comes with it (WSL2 gives no per-card node), so --device, which names one \
             card, has nothing to resolve to"
                .to_string()
        }
        Some(dir) => format!(
            "{} is here, but {} holds no {WSL_CUDA_LIB}: no CUDA driver for --gpus or --device to \
             hand over",
            shape.node.display(),
            dir.display()
        ),
        None => format!(
            "{} with no vendor library directory beside it: nothing for --gpus to hand over",
            shape.node.display()
        ),
    }
}

/// `base`, with the foreign-shape sentence joined onto it when the root has one.
///
/// For the surfaces that have one line to say everything in, where `doctor` has a note line.
pub fn with_foreign_shape(base: &str, root: &Path) -> String {
    let note = foreign_shape_note(root);
    if note.is_empty() {
        base.to_string()
    } else {
        format!("{base}; {note}")
    }
}

pub fn detect() -> Vec<Gpu> {
    let mut out: Vec<Gpu> = Vec::new();

    let Ok(entries) = std::fs::read_dir("/sys/class/drm") else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // `cardN` and nothing else: a connector is `card0-DP-1`, so require the remainder after
        // "card" to be entirely digits.
        let Some(index) = name.strip_prefix("card") else {
            continue;
        };
        if index.is_empty() || !index.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let device_dir = entry.path().join("device");
        let vendor = match read_hex_id(&device_dir.join("vendor")) {
            Some(id) => Vendor::from_pci(id),
            None => Vendor::NonPci,
        };
        let device_id = read_hex_id(&device_dir.join("device"));
        // THE VALIDATING READER, not a `read_link` of my own: `pci_address` already resolves the
        // link and then checks the result is a `dddd:bb:dd.f` and nothing else, which matters
        // because this string is printed and is used to pair a card with its grant. A board with
        // no PCI identity has nothing to read here, which is an answer rather than a failure.
        let pci_address = pci_address(&device_dir);
        out.push(Gpu {
            card: name,
            vendor,
            device_id,
            driver: driver_name(&device_dir),
            pci_address,
        });
    }
    // Stable order, so two runs on the same host produce the same output and a diff of `kern
    // doctor` between two boots is meaningful.
    out.sort_by(|a, b| a.card.cmp(&b.card));
    out
}

/// WHICH CARD THIS IS, with no verdict attached.
///
/// Split out of [`describe`] because the two answers have different lifetimes. The identity is a
/// fact about the hardware and does not change; the sentence after the colon is a claim about what
/// kern can do with it, and that one has already been rewritten twice. A caller that wants to say
/// something new about a card should not have to take the old claim with it.
///
/// Built from whatever is actually there, in decreasing order of authority: the PCI vendor, the
/// PCI device id, the bound driver. A board has only the last of the three, so the line degrades
/// to `card0 non-PCI (v3d)` rather than to a row of "unknown".
pub fn describe_identity(gpu: &Gpu) -> String {
    let mut ident = gpu.vendor.label();
    if let Some(d) = gpu.device_id {
        ident.push_str(&format!(" {d:#06x}"));
    }
    if let Some(driver) = &gpu.driver {
        ident.push_str(&format!(" ({driver})"));
    }
    format!("{card} {ident}", card = gpu.card)
}

#[cfg(test)]
mod tests {
    /// The driver-store cache is believed only where it can be checked: with the key unchanged a
    /// forged line naming `/etc`, a directory outside the store or one without the CUDA driver is
    /// dropped, and a change to the store (a new directory moves its mtime) re-walks it.
    #[test]
    fn the_wsl_store_cache_is_checked_and_follows_the_store() {
        let _g = crate::env_guard();
        let base = std::env::temp_dir().join(format!("kern-wslstore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let store = base.join("drivers");
        for d in [
            "nvreal.inf_amd64_1",
            "nvaudio.inf_amd64_2",
            "intel.inf_amd64_3",
        ] {
            std::fs::create_dir_all(store.join(d)).unwrap();
        }
        std::fs::write(store.join("nvreal.inf_amd64_1").join(WSL_STORE_CUDA), b"x").unwrap();
        std::fs::create_dir_all(base.join("run")).unwrap();
        let prev = crate::global_env("XDG_RUNTIME_DIR");
        crate::set_global_env("XDG_RUNTIME_DIR", base.join("run"));
        let real = vec![store.join("nvreal.inf_amd64_1")];
        assert_eq!(wsl_nvidia_store_dirs_cached(&store), Some(real.clone()));
        let cache = crate::registry::runtime_subdir_public("gpu")
            .unwrap()
            .join("wsl-store");
        let text = std::fs::read_to_string(&cache).unwrap();
        let key = text.lines().next().unwrap_or_default().to_string();
        // Forged lines under the SAME key: only the real directory survives the check.
        std::fs::write(
            &cache,
            format!(
                "{key}\n/etc\n{}\n{}\n{}\n",
                base.display(),
                store.join("nvaudio.inf_amd64_2").display(),
                store.join("nvreal.inf_amd64_1").display()
            ),
        )
        .unwrap();
        assert_eq!(wsl_nvidia_store_dirs_cached(&store), Some(real.clone()));
        // A new driver directory changes the store, and the walk finds it.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::create_dir_all(store.join("nvnew.inf_amd64_4")).unwrap();
        std::fs::write(store.join("nvnew.inf_amd64_4").join(WSL_STORE_CUDA), b"x").unwrap();
        let mut both = vec![
            store.join("nvnew.inf_amd64_4"),
            store.join("nvreal.inf_amd64_1"),
        ];
        both.sort();
        assert_eq!(wsl_nvidia_store_dirs_cached(&store), Some(both));
        match prev {
            Some(v) => crate::set_global_env("XDG_RUNTIME_DIR", v),
            None => crate::unset_global_env("XDG_RUNTIME_DIR"),
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    use super::*;

    /// A temporary directory that cleans itself up, so a failing assertion cannot leave a fake
    /// sysfs tree behind. Hand-rolled because this crate has no dev-dependency on `tempfile` and a
    /// new dependency for four tests is a worse trade than fifteen lines.
    struct TmpDir(std::path::PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("kern-gpu-test-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).expect("create temp dir");
            TmpDir(p)
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // ── the claim contract ──

    /// The gate has to be able to FAIL, or a green result proves nothing. Positive control.
    #[test]
    fn the_claim_gate_catches_an_overstated_string() {
        assert_eq!(overclaims("a cooperative quota"), None);
        assert_eq!(overclaims("provides VRAM isolation"), Some("isolation"));
        assert_eq!(overclaims("a SECURE per-tenant cap"), Some("secure"));
        assert_eq!(overclaims("a hardware partition"), Some("hard"));
    }

    /// The node test decides whether `--plan` prints the full claim, so a miss on either side is a
    /// defect: a granted GPU with no caveat, or a caveat on a bind that is not a GPU at all.
    #[test]
    fn a_gpu_compute_node_is_told_apart_from_a_file_that_looks_like_one() {
        for yes in [
            "/dev/dri/renderD128",
            "/dev/dri/card0",
            "/dev/nvidia0",
            "/dev/nvidiactl",
            "/dev/kfd",
        ] {
            assert!(is_compute_node(yes), "missed a GPU node: {yes}");
        }
        for no in [
            "/dev/i2c-5",
            "/dev/gpiochip0",
            "/dev/null",
            "/home/user/renderD128", // a file with a confusing name
            "/tmp/dev/nvidia0",      // not an absolute device path
            "",
        ] {
            assert!(!is_compute_node(no), "claimed a non-GPU as one: {no}");
        }
    }

    // ── classification ──

    /// The PCI address is validated where it is READ, because it then builds a path under `/proc`.
    ///
    /// Written to hold on a board as well as on a desktop. A Raspberry Pi 5 and a Jetson Orin Nano
    /// have DRM cards on the PLATFORM bus with no PCI address at all, so `None` is a correct answer
    /// here and asserting otherwise would have turned this test red on the hardware kern targets.
    /// What must hold everywhere is the other half: whatever comes back is a single safe component.
    #[test]
    fn only_a_kernel_shaped_pci_address_is_accepted() {
        let d = TmpDir::new("bdf");
        assert_eq!(pci_address(&d.0), None, "a temp dir is not a PCI address");
        for card in detect() {
            let dev = std::path::Path::new("/sys/class/drm")
                .join(&card.card)
                .join("device");
            let Some(bdf) = pci_address(&dev) else {
                continue; // a platform-bus card, which is the normal case on an ARM board
            };
            assert_eq!(bdf.len(), 12, "{bdf}");
            assert!(
                !bdf.contains('/')
                    && bdf != ".."
                    && bdf
                        .chars()
                        .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.'),
                "a path component reached a `/proc` join unvalidated: {bdf}"
            );
        }
    }

    /// A vendor id is parsed strictly or not at all, never guessed. Checked through the parser,
    /// since that is where a loose read would invent one.
    #[test]
    fn hex_ids_are_rejected_rather_than_truncated() {
        let d = TmpDir::new("hex");
        let f = d.0.join("vendor");
        for (content, want) in [
            ("0x10de\n", Some(PCI_VENDOR_NVIDIA)),
            ("0x1002", Some(PCI_VENDOR_AMD)),
            ("10de\n", None),       // the kernel always writes the 0x prefix
            ("0x10dez\n", None),    // trailing garbage must not parse as 0x10de
            ("0x\n", None),         // prefix with no digits
            ("\n", None),           // empty attribute
            ("0xffffffffff", None), // wider than u32: reject, never wrap
        ] {
            std::fs::write(&f, content).expect("write vendor");
            assert_eq!(read_hex_id(&f), want, "input {content:?}");
        }
        let _ = std::fs::remove_file(&f);
        assert_eq!(read_hex_id(&f), None, "a missing attribute reads as absent");
    }

    /// THE BOARD CASE, which is the one this module got wrong first. A card with no PCI identity is
    /// described, not dropped, and the line names the driver because that is all the kernel offers.
    /// The three shapes here are the ones measured on real hardware: a PCI card with both ids, a
    /// Raspberry Pi 5 platform card (`v3d`), and a Jetson Orin Nano platform card (`nv_platform`).
    #[test]
    fn a_card_with_no_pci_identity_is_still_described() {
        let row = |vendor, device_id, driver: Option<&str>| {
            describe_identity(&Gpu {
                card: "card0".into(),
                vendor,
                device_id,
                driver: driver.map(str::to_string),
                pci_address: None,
            })
        };
        assert_eq!(
            row(Vendor::Nvidia, Some(0x2d04), Some("nvidia")),
            "card0 NVIDIA 0x2d04 (nvidia)"
        );
        assert_eq!(
            row(Vendor::NonPci, None, Some("v3d")),
            "card0 non-PCI (v3d)"
        );
        assert_eq!(
            row(Vendor::NonPci, None, Some("nv_platform")),
            "card0 non-PCI (nv_platform)"
        );
        // An unrecognised PCI vendor keeps its id rather than becoming an anonymous "unknown".
        assert!(row(Vendor::Other(0x1af4), Some(0x1050), None).contains("PCI vendor 0x1af4 0x1050"));
        // Nothing readable at all is still a line, and still not an overclaim.
        assert_eq!(row(Vendor::NonPci, None, None), "card0 non-PCI");
    }

    /// The driver name is read from a symlink and then printed, so it is validated where it is read.
    #[test]
    fn the_driver_name_is_a_plain_component_or_nothing() {
        let d = TmpDir::new("driver");
        let link = d.0.join("driver");
        // Every name measured in the wild, including the Jetson aggregator's bare `drm`.
        for good in ["nvidia", "amdgpu", "v3d", "vc4-drm", "nv_platform", "drm"] {
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(format!("/sys/bus/platform/drivers/{good}"), &link)
                .expect("symlink");
            assert_eq!(driver_name(&d.0).as_deref(), Some(good));
        }
        // A target whose last component is not a plain name yields nothing rather than a printed
        // path fragment. `..` is the one that matters: it is the shape a traversal would take.
        for bad in ["/sys/bus/platform/drivers/..", "/", "/sys/a/b/na me"] {
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(bad, &link).expect("symlink");
            assert_eq!(driver_name(&d.0), None, "accepted {bad:?}");
        }
        let _ = std::fs::remove_file(&link);
        assert_eq!(driver_name(&d.0), None, "no driver link is not a driver");
    }

    /// `detect` runs against the REAL sysfs of whatever host the suite runs on, including CI with no
    /// GPU at all. It must never panic and must never award a tier without evidence.
    #[test]
    fn detect_is_consistent_on_this_host() {
        let gpus = detect();
        let mut cards: Vec<&str> = gpus.iter().map(|g| g.card.as_str()).collect();
        let sorted = {
            let mut c = cards.clone();
            c.sort_unstable();
            c
        };
        assert_eq!(cards, sorted, "output order must be stable across runs");
        cards.dedup();
        assert_eq!(cards.len(), gpus.len(), "a card was reported twice");
        for g in &gpus {
            assert!(
                g.card.starts_with("card") && g.card[4..].bytes().all(|b| b.is_ascii_digit()),
                "connector or render node leaked into the card list: {}",
                g.card
            );
            assert_eq!(
                overclaims(&describe_identity(g)),
                None,
                "{}",
                describe_identity(g)
            );
            // THE JOIN KEY IS A PCI ADDRESS OR IT IS ABSENT, never something in between. It pairs
            // a DRM card with the grant that names it, and a half-read string would pair it with
            // the wrong one or with nothing.
            if let Some(addr) = &g.pci_address {
                assert_eq!(addr.len(), 12, "not a kernel-shaped PCI address: {addr}");
            }
        }
    }

    /// A character device at `path`, unprivileged.
    ///
    /// `c 0 0` is a WHITEOUT, the one character device the kernel lets an unprivileged caller
    /// create: `vfs_mknod` tests `CAP_MKNOD` only when the node is not a whiteout. It is enough
    /// here because [`foreign_shape_in`] asks whether the node is a character device and
    /// deliberately does not read the rdev. Returns false when the filesystem under `/tmp` refuses
    /// it, which is a SKIP rather than a pass.
    fn fixture_node(path: &std::path::Path) -> bool {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::CString::new(path.as_os_str().as_bytes())
            .map(|p| unsafe { libc::mknod(p.as_ptr(), libc::S_IFCHR | 0o666, 0) } == 0)
            .unwrap_or(false)
    }

    /// Build `<root>/dev/dxg` as a device, and the library directory when asked.
    fn wsl_root(tag: &str, with_libs: bool) -> Option<TmpDir> {
        let t = TmpDir::new(tag);
        std::fs::create_dir_all(t.0.join("dev")).expect("dev");
        if !fixture_node(&t.0.join(WSL_NODE_REL)) {
            return None;
        }
        if with_libs {
            std::fs::create_dir_all(t.0.join(WSL_LIB_REL)).expect("lib dir");
        }
        Some(t)
    }

    /// EVERY WSL SHAPE'S DOCTOR NOTE FITS THE NOTE LINE (140), measured as it prints on a real host,
    /// where the root is `/`: the fixture's own directory is taken out of the count. The long
    /// sentence was 329 characters and only the host the test ran on was checked.
    #[test]
    fn every_wsl_doctor_note_fits_the_note_line() {
        for (tag, libs, cuda) in [
            ("wsl-cuda", true, true),
            ("wsl-nocuda", true, false),
            ("wsl-nolib", false, false),
        ] {
            let Some(t) = wsl_root(tag, libs) else {
                println!("SKIP: /tmp refused an unprivileged whiteout, cannot build a device node");
                return;
            };
            if cuda {
                std::fs::write(t.0.join(WSL_LIB_REL).join(WSL_CUDA_LIB), b"").expect("lib");
            }
            let note = foreign_shape_short(&t.0);
            let as_printed = note.replace(&*t.0.to_string_lossy(), "");
            assert!(!note.is_empty(), "{tag}: a shape is there");
            assert!(
                as_printed.len() <= 140,
                "{tag}: {} chars: {as_printed}",
                as_printed.len()
            );
            assert!(
                foreign_shape_note(&t.0).len() > as_printed.len(),
                "{tag}: the short one IS shorter"
            );
        }
        assert_eq!(foreign_shape_short(&TmpDir::new("wsl-none").0), "");
    }

    /// THE MAJORITY CASE, and the negative half of every case below: a root with nothing in it has
    /// no foreign shape, so a `Some` elsewhere is the node and not the function's optimism.
    #[test]
    fn a_root_with_nothing_in_it_has_no_foreign_shape() {
        let t = TmpDir::new("noshape");
        assert_eq!(foreign_shape_in(&t.0), None);
        assert_eq!(foreign_shape_note(&t.0), "");
        assert_eq!(with_foreign_shape("base", &t.0), "base");
    }

    /// THE PATHS COME FROM THE ROOT. A resolver that reads the literal `/dev/dxg` would pass every
    /// other case on a WSL2 host and fail this one everywhere, which is the sabotage this case is
    /// built to catch: it asserts the node it found is UNDER the root it was given.
    #[test]
    fn the_wsl_shape_is_found_and_its_paths_come_from_the_root() {
        let Some(t) = wsl_root("wslshape", true) else {
            println!("SKIP: /tmp refused an unprivileged whiteout, cannot build a device node");
            return;
        };
        let shape = foreign_shape_in(&t.0).expect("the shape is there");
        assert_eq!(shape.node, t.0.join("dev/dxg"));
        assert_eq!(shape.libraries, Some(t.0.join("usr/lib/wsl/lib")));
        assert!(
            shape.node.starts_with(&t.0),
            "the node was not read under the root: {}",
            shape.node.display()
        );
    }

    /// The node with no libraries next to it is still the shape, and the sentence drops the clause
    /// rather than naming a directory that is not there.
    #[test]
    fn the_node_alone_is_the_shape_and_the_sentence_omits_the_libraries() {
        let Some(t) = wsl_root("wslnolibs", false) else {
            println!("SKIP: /tmp refused an unprivileged whiteout, cannot build a device node");
            return;
        };
        let shape = foreign_shape_in(&t.0).expect("the shape is there");
        assert_eq!(shape.libraries, None);
        let text = describe_foreign_shape(&shape);
        assert!(
            !text.contains("vendor libraries"),
            "named a library directory that does not exist: {text}"
        );
        assert!(text.contains("dev/dxg"), "{text}");
    }

    /// A REGULAR FILE WITH THE RIGHT NAME IS NOT A DEVICE. The same forgery that defeated an
    /// earlier version of the grant path: four synthetic roots had been writing regular files where
    /// nodes belong, and every test passed.
    #[test]
    fn a_regular_file_named_dxg_is_not_a_device() {
        let t = TmpDir::new("wslfile");
        std::fs::create_dir_all(t.0.join("dev")).expect("dev");
        std::fs::write(t.0.join(WSL_NODE_REL), b"not a device").expect("write");
        assert_eq!(foreign_shape_in(&t.0), None);
    }

    /// A SYMLINK IS NOT FOLLOWED, so the answer cannot be made to come from a device outside the
    /// root. The positive control is in the same case: the link target IS a device, and pointing
    /// the path at it directly would answer `Some`.
    #[test]
    fn a_symlink_at_the_node_path_is_not_followed() {
        let t = TmpDir::new("wsllink");
        std::fs::create_dir_all(t.0.join("dev")).expect("dev");
        let real = t.0.join("dev").join("real-device");
        if !fixture_node(&real) {
            println!("SKIP: /tmp refused an unprivileged whiteout, cannot build a device node");
            return;
        }
        // THE CONTROL: the target is a device, read directly.
        use std::os::unix::fs::FileTypeExt;
        assert!(
            std::fs::symlink_metadata(&real)
                .expect("stat")
                .file_type()
                .is_char_device(),
            "the control failed: the fixture is not a character device"
        );
        std::os::unix::fs::symlink(&real, t.0.join(WSL_NODE_REL)).expect("symlink");
        assert_eq!(
            foreign_shape_in(&t.0),
            None,
            "a symlink was followed to a device outside the node path"
        );
    }

    /// THE SENTENCE SAYS WHAT IS TRUE ON THE HOST IT IS PRINTED ON. It used to say "neither --gpus
    /// nor --device has a node to name" everywhere, which became false for `--gpus` once
    /// `wsl_grant` existed. With the CUDA driver present it says `--gpus` grants it and why
    /// `--device` still cannot; with the directory but no driver it says there is nothing to hand
    /// over. Both name the node, and neither may claim a boundary.
    #[test]
    fn the_sentence_says_whether_the_wsl_gpu_can_be_granted_on_this_host() {
        let Some(t) = wsl_root("wslsentence", true) else {
            println!("SKIP: /tmp refused an unprivileged whiteout, cannot build a device node");
            return;
        };
        // The directory with no CUDA driver in it.
        let none = foreign_shape_note(&t.0);
        assert!(
            none.contains("dev/dxg") && none.contains("libcuda.so.1"),
            "{none}"
        );
        assert!(
            !none.contains("grants it"),
            "nothing to grant, and it said grants: {none}"
        );
        // The CUDA driver present: `--gpus` grants it, `--device` still cannot.
        std::fs::write(t.0.join(WSL_LIB_REL).join(WSL_CUDA_LIB), b"stub").expect("lib");
        let some = foreign_shape_note(&t.0);
        for needle in [
            "dev/dxg",
            "usr/lib/wsl/lib",
            "`--gpus` grants it",
            "--device",
        ] {
            assert!(
                some.contains(needle),
                "the note does not name {needle}: {some}"
            );
        }
        assert_eq!(overclaims(&some), None, "{some}");
        let joined = with_foreign_shape("a GPU was asked for", &t.0);
        assert!(joined.starts_with("a GPU was asked for; "), "{joined}");
    }

    /// ⛔ THE WSL2 GRANT, IN EVERY OUTCOME, FROM THE ROOT IT IS GIVEN.
    ///
    /// The recipe was measured before it was written (a CUDA kernel in a box on a WSL2 Ubuntu
    /// guest: NO-LIBCUDA without the grant, KERNEL-OK with it), so what is pinned here is that the
    /// function hands over exactly that recipe and refuses with its cause when a piece is missing.
    #[test]
    fn the_wsl_grant_binds_node_libraries_and_driver_store_or_says_what_is_missing() {
        // No shape at all: not a WSL2 host, nothing to say.
        let plain = TmpDir::new("wslgrant-none");
        assert_eq!(wsl_grant(&plain.0), None);

        // The node alone.
        let Some(t) = wsl_root("wslgrant-nolib", false) else {
            println!("SKIP: /tmp refused an unprivileged whiteout, cannot build a device node");
            return;
        };
        assert!(matches!(
            wsl_grant(&t.0),
            Some(Err(WslGrantError::NoLibraries { .. }))
        ));

        // The directory with no CUDA driver in it.
        let Some(t) = wsl_root("wslgrant-nocuda", true) else {
            return;
        };
        match wsl_grant(&t.0) {
            Some(Err(WslGrantError::NoCudaLibrary { dir })) => {
                assert_eq!(dir, t.0.join(WSL_LIB_REL));
            }
            other => panic!("expected NoCudaLibrary, got {other:?}"),
        }

        // The driver: the node read-write, and each library read-only, BY NAME, in the image's
        // library directory as docker binds them: not the directory, and nothing that is not a
        // library (the tool goes to /usr/bin, below). A link lands its file.
        std::fs::write(t.0.join(WSL_LIB_REL).join(WSL_CUDA_LIB), b"stub").expect("lib");
        std::fs::write(t.0.join(WSL_LIB_REL).join("libnvoptix.so.1"), b"stub").expect("lib");
        std::os::unix::fs::symlink(
            "libnvoptix.so.1",
            t.0.join(WSL_LIB_REL).join("libnvoptix_loader.so.1"),
        )
        .expect("link");
        let g = wsl_grant(&t.0).expect("the shape").expect("grantable");
        let src = |rel: &str| t.0.join(rel).to_string_lossy().into_owned();
        let canon = |rel: &str| {
            std::fs::canonicalize(t.0.join(rel))
                .expect("canonical")
                .to_string_lossy()
                .into_owned()
        };
        assert_eq!(
            g.binds_into("/usr/lib/x86_64-linux-gnu"),
            vec![
                (src(WSL_NODE_REL), "/dev/dxg".to_string(), false),
                (
                    canon("usr/lib/wsl/lib/libcuda.so.1"),
                    "/usr/lib/x86_64-linux-gnu/libcuda.so.1".to_string(),
                    true
                ),
                (
                    canon("usr/lib/wsl/lib/libnvoptix.so.1"),
                    "/usr/lib/x86_64-linux-gnu/libnvoptix.so.1".to_string(),
                    true
                ),
                (
                    canon("usr/lib/wsl/lib/libnvoptix.so.1"),
                    "/usr/lib/x86_64-linux-gnu/libnvoptix_loader.so.1".to_string(),
                    true
                ),
            ],
            "with no driver store on the host, nothing is invented for it"
        );
        assert!(
            g.binds_into("/usr/lib64")
                .iter()
                .skip(1)
                .all(|(_, t, _)| t.starts_with("/usr/lib64/")),
            "the directory is the one the image asks for"
        );

        // And the driver store, when the host has one, at the same path.
        std::fs::create_dir_all(t.0.join(WSL_DRIVERS_REL)).expect("drivers");
        let g = wsl_grant(&t.0).expect("the shape").expect("grantable");
        assert_eq!(g.binds.len(), 2);
        assert_eq!(
            g.binds[1],
            (
                src(WSL_DRIVERS_REL),
                "/usr/lib/wsl/drivers".to_string(),
                true
            )
        );
        assert!(
            g.binds
                .iter()
                .all(|(s, _, _)| s.starts_with(&*t.0.to_string_lossy())),
            "every source comes from the root, not from this host's /: {:?}",
            g.binds
        );

        // ONLY THE NVIDIA DIRECTORY OF A STORE THAT HAS ONE, as docker binds it. A `nv*` name
        // without the CUDA driver (the audio driver) stays out, and so does a CUDA file under a
        // name that is not NVIDIA's: the name narrows where to look, the file decides.
        let store = t.0.join(WSL_DRIVERS_REL);
        for (dir, cuda) in [
            ("nvmdi.inf_amd64_98af", true),
            ("nvhda.inf_amd64_17d2", false),
            ("iigd_dch.inf_amd64_aaaa", true),
        ] {
            std::fs::create_dir_all(store.join(dir)).expect("store dir");
            if cuda {
                std::fs::write(store.join(dir).join(WSL_STORE_CUDA), b"stub").expect("cuda");
            }
        }
        // And the tool, which goes to `/usr/bin` as docker puts it.
        std::fs::write(t.0.join(WSL_LIB_REL).join("nvidia-smi"), b"stub").expect("smi");
        let g = wsl_grant(&t.0).expect("the shape").expect("grantable");
        let canonical_smi = std::fs::canonicalize(t.0.join(WSL_LIB_REL).join("nvidia-smi"))
            .expect("canonical")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            g.binds[1..],
            [
                (
                    src("usr/lib/wsl/drivers/nvmdi.inf_amd64_98af"),
                    "/usr/lib/wsl/drivers/nvmdi.inf_amd64_98af".to_string(),
                    true
                ),
                (canonical_smi, "/usr/bin/nvidia-smi".to_string(), true),
            ],
            "the store narrowed to NVIDIA's directory and the tool at /usr/bin: {:?}",
            g.binds
        );
        assert!(
            g.libraries.iter().all(|(_, name)| name.contains(".so")),
            "the tool is not a library and does not land in the library directory: {:?}",
            g.libraries
        );
    }

    /// ⛔ THE DXG LAYOUT IS THE KERNEL'S, byte for byte: `include/uapi/misc/d3dkmthk.h` of the WSL
    /// kernel (linux-msft-wsl-6.6.y). A size off by one is an ioctl the driver rejects or, worse, one
    /// it reads past. The request numbers are the header's `_IOWR(0x47, nr, struct)`.
    #[test]
    fn the_dxg_structures_and_requests_match_the_wsl_kernel_header() {
        assert_eq!(std::mem::size_of::<DxgAdapterInfo>(), 20);
        assert_eq!(std::mem::size_of::<DxgEnumAdapters2>(), 16);
        assert_eq!(std::mem::size_of::<DxgQueryAdapterInfo>(), 24);
        assert_eq!(std::mem::size_of::<DxgDeviceIds>(), 28);
        // LX_DXENUMADAPTERS2, LX_DXQUERYADAPTERINFO, LX_DXCLOSEADAPTER.
        assert_eq!(dxg_iowr(0x14, 16), 0xC010_4714);
        assert_eq!(dxg_iowr(0x09, 24), 0xC018_4709);
        assert_eq!(dxg_iowr(0x15, 4), 0xC004_4715);
        // And a node that is not the driver answers nothing rather than a count.
        let plain = TmpDir::new("dxg-notadevice");
        let fake = plain.0.join("dxg");
        std::fs::write(&fake, b"").expect("file");
        assert_eq!(dxg_nvidia_adapters(&fake), None);
    }

    /// The adapter list as `nvidia-smi` prints it, and nothing it did not print.
    #[test]
    fn the_adapter_list_reads_index_and_uuid_and_skips_anything_else() {
        assert_eq!(
            parse_adapters("1, GPU-bbb-2\n0, GPU-aaa-1\n"),
            vec![(0, "GPU-aaa-1".to_string()), (1, "GPU-bbb-2".to_string())]
        );
        assert_eq!(
            parse_adapters("No devices were found\n,\nx, GPU-1\n2, MIG-x\n"),
            Vec::<(u32, String)>::new()
        );
    }

    /// ⛔ DOCKER'S TWO REFUSALS ON WSL2, and the cases it runs. Measured with toolkit 1.20.2 on a
    /// one-adapter guest: `device=1` and `--gpus 2` fail with "unknown device"; `device=0`, `1`
    /// and `all` run.
    #[test]
    fn a_wsl_selection_is_refused_where_docker_refuses_it_and_says_when_it_is_narrower() {
        use crate::gpu_grant::{GpuSelection, MountPlanError};
        let one = vec![0];
        assert_eq!(wsl_check_selection(&GpuSelection::All, &one), Ok(false));
        assert_eq!(
            wsl_check_selection(&GpuSelection::Count(1), &one),
            Ok(false)
        );
        assert_eq!(
            wsl_check_selection(&GpuSelection::These(vec![0]), &one),
            Ok(false)
        );
        assert_eq!(
            wsl_check_selection(&GpuSelection::These(vec![1]), &one),
            Err(MountPlanError::NoSuchCard {
                wanted: 1,
                present: vec![0]
            })
        );
        assert_eq!(
            wsl_check_selection(&GpuSelection::Count(2), &one),
            Err(MountPlanError::TooFewCards {
                wanted: 2,
                present: vec![0]
            })
        );
        let two = vec![0, 1];
        assert_eq!(
            wsl_check_selection(&GpuSelection::These(vec![1]), &two),
            Ok(true),
            "one of two adapters is narrower than what /dev/dxg carries"
        );
        assert_eq!(wsl_check_selection(&GpuSelection::Count(1), &two), Ok(true));
    }

    /// The list comes from the vendor's tool UNDER THE ROOT, run with a deadline, and a tool that
    /// cannot run is `None`, never an empty list a caller would read as "no adapter".
    #[test]
    fn the_wsl_adapters_come_from_the_vendor_tool_under_the_root() {
        use std::os::unix::fs::PermissionsExt;
        let Some(t) = wsl_root("wsladapters", true) else {
            println!("SKIP: /tmp refused an unprivileged whiteout, cannot build a device node");
            return;
        };
        assert_eq!(wsl_adapters(&t.0), None, "no tool, no list");
        let smi = t.0.join(WSL_SMI_REL);
        std::fs::write(&smi, "#!/bin/sh\necho '0, GPU-aaa'\necho '1, GPU-bbb'\n").expect("tool");
        std::fs::set_permissions(&smi, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(
            wsl_adapters(&t.0),
            Some(vec![(0, "GPU-aaa".to_string()), (1, "GPU-bbb".to_string())])
        );
        // A VALID LINE AND A FAILURE: the exit code decides, not whether the output parses.
        assert!(
            !wsl_uuids_unreadable(&t.0),
            "the tool lists UUIDs, so they are readable"
        );
        std::fs::write(&smi, "#!/bin/sh\necho '0, GPU-aaa'\nexit 9\n").expect("tool");
        assert!(
            wsl_uuids_unreadable(&t.0),
            "a tool that fails leaves the UUIDs unreadable, and only then is one accepted unchecked"
        );
        let plain = TmpDir::new("wsl-uuid-plain");
        assert!(
            !wsl_uuids_unreadable(&plain.0),
            "not a WSL2 guest: a UUID there is the native grant's question"
        );
        assert_eq!(
            wsl_adapters(&t.0),
            None,
            "a tool that failed is not believed"
        );
    }
}
