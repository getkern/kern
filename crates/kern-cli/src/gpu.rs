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
/// IT ASSERTS PRESENCE AND NOTHING ABOUT FUNCTION. On the host this was measured on, with
/// `/usr/lib/wsl/lib` on the loader path, `cuInit` returned 100 (`CUDA_ERROR_NO_DEVICE`) and
/// `cuDeviceGetCount` returned 0, so that paravirtual path was not carrying compute at the time.
/// Saying "this host has a GPU kern's grant does not read" is true either way; saying anything
/// about whether CUDA runs there would not be.
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

/// The one sentence that describes [`ForeignShape`], written once because three surfaces print it:
/// the `doctor` row for a host with no DRM card, and both `--gpus` refusals in
/// [`crate::commands::start`].
///
/// It names BOTH sides of the mismatch, the interface that is there and the two things a grant
/// looks for, because "no NVIDIA driver is loaded on this host" is the message those refusals used
/// to carry and on this host it is false: the driver is loaded, on the other side of the
/// paravirtual boundary, and what is absent is the node and the version file kern reads.
pub fn describe_foreign_shape(shape: &ForeignShape) -> String {
    let node = shape.node.display();
    let where_libs = match &shape.libraries {
        Some(dir) => format!(", with the vendor libraries in {}", dir.display()),
        None => String::new(),
    };
    // NEITHER FLAG, not `--gpus` alone. The sentence is printed by four surfaces and one of them is
    // the `--device` refusal, where naming only the other flag tells the operator about a spelling
    // they did not use. The two are documented as the same request written two ways, and this is
    // the one sentence that has to be true on every surface that prints it.
    format!(
        "a GPU is present here through {} at {node}{where_libs}: a grant reads \
         /proc/driver/nvidia/version and binds /dev/nvidia* nodes, and this kernel has neither, so \
         neither --gpus nor --device has a node to name",
        shape.interface
    )
}

/// [`describe_foreign_shape`] for the root, or an empty string. The empty case is the majority of
/// hosts and the caller prints nothing for it.
pub fn foreign_shape_note(root: &Path) -> String {
    foreign_shape_in(root)
        .map(|s| describe_foreign_shape(&s))
        .unwrap_or_default()
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

    /// THE SENTENCE NAMES BOTH SIDES OF THE MISMATCH. Its whole reason to exist is that
    /// "no NVIDIA driver is loaded on this host" is false on a WSL2 guest, so it must say what IS
    /// there and what kern looked for, and it must not drift into claiming a boundary.
    #[test]
    fn the_sentence_names_what_is_there_and_what_kern_looked_for() {
        let Some(t) = wsl_root("wslsentence", true) else {
            println!("SKIP: /tmp refused an unprivileged whiteout, cannot build a device node");
            return;
        };
        let note = foreign_shape_note(&t.0);
        for needle in [
            "dev/dxg",
            "usr/lib/wsl/lib",
            "/proc/driver/nvidia/version",
            "/dev/nvidia*",
            // BOTH SPELLINGS, because one of the four surfaces that prints this is the `--device`
            // refusal and naming only `--gpus` there describes a flag the operator did not type.
            "--gpus",
            "--device",
        ] {
            assert!(
                note.contains(needle),
                "the note does not name {needle}: {note}"
            );
        }
        assert_eq!(overclaims(&note), None, "{note}");
        let joined = with_foreign_shape("a GPU was asked for", &t.0);
        assert!(joined.starts_with("a GPU was asked for; "), "{joined}");
        assert!(joined.contains("dev/dxg"), "{joined}");
    }
}
