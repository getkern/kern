//! GPU DETECTION AND CAPABILITY TIER, read-only.
//!
//! This module answers one question and refuses the others: *what would a VRAM cap on this GPU
//! actually be worth?* It does not slice, cap, intercept or load anything. It reads sysfs and
//! `/proc`, classifies each GPU into a capability tier, and emits the claim string that tier is
//! entitled to.
//!
//! WHY THIS SHIPS BEFORE ANY SLICING CODE
//!   A cooperative VRAM quota is trivially bypassed on consumer NVIDIA: a tenant that never calls
//!   into `libcuda` and talks to the device with raw ioctls does not pass through any userspace
//!   interception, and VRAM is committed by a page fault handled in the kernel and the GSP, so
//!   there is no syscall to trap either. That is a property of the problem, not a defect that can
//!   be fixed above the kernel. A project that shipped the cap first and the honest description
//!   second would be selling the cap as a boundary for however long the gap lasted. So the
//!   judgement ships first and the capability follows it.
//!
//! THE ONE DISTINCTION THAT GOVERNS THIS FILE
//!   "the slice applies" and "the slice is a security boundary" are different properties, and
//!   conflating them is the failure this tier model exists to prevent. A cooperative quota holds
//!   for a workload that is not trying to escape it, which is genuinely useful for density,
//!   fairness and accidental-overcommit. It holds for nothing else.
//!
//! FAIL-CLOSED
//!   Every unknown resolves to [`Tier::Soft`], the weakest claim. A GPU is promoted only on
//!   unambiguous evidence read from the kernel, never inferred from a vendor name or a model
//!   number. When kern cannot tell, kern says the smaller thing.
//!
//! THE MISSING MIDDLE TIER
//!   The capability model has three levels, and this file can only ever produce two of them. The
//!   middle one is a kernel-enforced device-memory limit (`dmem`) that charges the path the
//!   workload actually allocates through. `dmem` accounts faithfully on AMD and Intel from kernel
//!   6.14, but on the driver this was measured against it does not ENFORCE for the ROCm compute
//!   path: with a per-cgroup `dmem.max` of 2 GB, an 8 GB `hipMalloc` succeeded and the leaf
//!   cgroup's `dmem.current` stayed at 0 while 8 GB sat in VRAM. The DRM render/GEM path IS
//!   charged; the KFD compute path, the one ML tenants use, is not.
//!
//!   So the middle tier is DEFINED but not ATTAINABLE, and no [`Tier`] variant exists for it.
//!   Shipping a variant that no code path can construct would put a tier in the model that kern
//!   cannot award and cannot test. Reaching it requires re-running that measurement per (vendor,
//!   driver, kernel) and finding the leaf charged, which is an allocation test and therefore
//!   outside what a read-only preflight may do. Until then, a `dmem` controller is reported as a
//!   FACT next to the GPU and never as a promotion.
//!
//! ALLOCATION NOTE
//!   This path allocates: it reads sysfs into `String`s and returns an owned `Vec`. That is
//!   deliberate and in scope. The project's no-heap rule governs the per-box hot path, where a
//!   box starts in ~2.3 ms and an allocation is a measurable fraction of it. `kern doctor` runs
//!   once, interactively, and already shells out to `systemd-run` three times to measure the
//!   scope toll. Optimising a `read_to_string` here would buy nothing and cost clarity.

use std::path::Path;

/// PCI vendor identifiers, as they appear in `/sys/class/drm/card*/device/vendor`.
const PCI_VENDOR_NVIDIA: u32 = 0x10de;
const PCI_VENDOR_AMD: u32 = 0x1002;
const PCI_VENDOR_INTEL: u32 = 0x8086;

/// What kern can honestly promise about a VRAM cap on a given GPU.
///
/// The tiers are not a quality ranking of the hardware. They rank the strength of the ENFORCEMENT
/// AUTHORITY behind a cap: hardware partitioning, or nothing but the tenant's own cooperation. The
/// model's middle tier has no variant here because nothing can construct it: see the module header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier {
    /// A true hardware partition: NVIDIA MIG, or an SR-IOV virtual function. The cap is enforced by
    /// the device, so it holds against a tenant that is actively trying to exceed it.
    Hw,
    /// A cooperative quota. Applies to a workload that does not evade it, and to nothing else.
    Soft,
}

/// Words that may only ever appear in text kern prints about a [`Tier::Hw`] GPU.
///
/// Enforced mechanically by the unit tests below rather than trusted to review, in the same spirit
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

impl Tier {
    /// The claim string kern is entitled to emit for this tier. Contractual, not cosmetic: see
    /// `BOUNDARY_WORDS` below.
    pub fn claim(self) -> &'static str {
        match self {
            Tier::Hw => {
                "hardware-isolated vGPU (MIG or SR-IOV): per-tenant VRAM enforced by the device"
            }
            Tier::Soft => {
                "cooperative VRAM quota: fairness, accidental-overcommit and accounting for \
                 trusted and semi-trusted tenants. NOT a boundary against malicious code. For a \
                 real boundary use a MIG GPU or an SR-IOV part"
            }
        }
    }

    /// Short label for tables and machine-readable output.
    pub fn label(self) -> &'static str {
        match self {
            Tier::Hw => "TIER-HW",
            Tier::Soft => "TIER-SOFT",
        }
    }
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

/// Why a GPU landed in the tier it did, so `kern doctor` can show the evidence and not just the
/// verdict. A tier without its reason is an assertion; with it, the reader can check kern.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Evidence {
    /// The device is an SR-IOV virtual function: it has a `physfn` link back to its parent.
    SriovVirtualFunction,
    /// MIG instances are configured FOR THIS CARD, matched by its PCI address, not merely present
    /// somewhere on the host.
    MigInstance,
    /// Nothing that grants a stronger tier was found. Worded as "device-level" and not as
    /// "hardware" because the claim gate below refuses the reserved vocabulary on a
    /// cooperative row, and it refuses the raw substring: it cannot tell a negated `hard` from
    /// an asserted one, and a gate that tries to would be the one that lets the real case pass.
    NoPartitionFound,
}

impl Evidence {
    pub fn describe(self) -> &'static str {
        match self {
            Evidence::SriovVirtualFunction => "SR-IOV virtual function (device/physfn present)",
            Evidence::MigInstance => "MIG instances configured for this card",
            Evidence::NoPartitionFound => "no device-level partition found",
        }
    }
}

/// One GPU as kern sees it, with the tier it is entitled to and the evidence for that tier.
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
    pub tier: Tier,
    pub evidence: Evidence,
    /// Whether the AMD/Intel `dmem` cgroup controller is available on this host. Reported as a
    /// FACT, never as a tier: `dmem` being present says nothing about whether it charges the path
    /// the tenant allocates through, and that difference is the whole of the missing middle tier
    /// described in the module header.
    pub dmem_controller: bool,
    /// Whether the ROCm compute device node is present. Relevant because it is exactly the path
    /// measured NOT to be charged to the allocating cgroup.
    pub kfd_present: bool,
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

/// Is the AMD/Intel `dmem` cgroup controller available on this host?
///
/// Read from the ROOT cgroup's `cgroup.controllers`, because that is where the kernel advertises
/// what it compiled in. A leaf may not have it delegated, which is a different question and not
/// this one: the point here is only whether the mechanism exists at all on this kernel.
fn dmem_controller_available() -> bool {
    std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
        .map(|s| s.split_whitespace().any(|c| c == "dmem"))
        .unwrap_or(false)
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

/// The NVIDIA device minor for a card, from the driver's own per-PCI-address record.
///
/// `/proc/driver/nvidia/gpus/<bdf>/information` carries a `Device Minor:` line. This is how kern
/// crosses from the DRM view of a card to the NVIDIA view of it, so a MIG instance can be attributed
/// to the card that owns it rather than to whichever NVIDIA card the scan happened to be looking at.
fn nvidia_device_minor(bdf: &str) -> Option<u32> {
    let info =
        std::fs::read_to_string(format!("/proc/driver/nvidia/gpus/{bdf}/information")).ok()?;
    info.lines()
        .find_map(|l| l.strip_prefix("Device Minor:"))?
        .trim()
        .parse()
        .ok()
}

/// Are NVIDIA MIG instances configured ON THIS CARD?
///
/// PER CARD, AND THE DIFFERENCE IS THE WHOLE POINT. The first version of this asked whether MIG was
/// configured ANYWHERE on the host, which on a two-NVIDIA-card machine with MIG enabled on one of
/// them promoted BOTH to the hardware tier. That is the exact defect class this module exists to
/// prevent, produced by the module itself: a claim of device-enforced partitioning for a card that
/// has none.
///
/// The driver publishes capabilities under `capabilities/gpu<minor>/mig/gi<id>/`, keyed by the same
/// device minor that `/proc/driver/nvidia/gpus/<bdf>/information` reports. The `mig` directory alone
/// is not enough: a MIG-capable card with MIG disabled still exposes it, so kern requires at least
/// one configured GPU INSTANCE (`gi*`), which is the thing that actually partitions the device.
///
/// The minor-to-`gpu<N>` correspondence is corroborated on the one NVIDIA host available here
/// (minor 0, `capabilities/gpu0/mig` present) and NOT verified against real MIG hardware, which this
/// project does not own. That is why the whole path is written to fail closed: every unreadable
/// file, unparsed line and absent directory returns `false`, so being wrong about the layout costs a
/// MIG card an unearned `TIER-HW` and never gives a consumer card one.
fn mig_instances_for_card(device_dir: &Path) -> bool {
    let Some(bdf) = pci_address(device_dir) else {
        return false;
    };
    let Some(minor) = nvidia_device_minor(&bdf) else {
        return false;
    };
    let mig = format!("/proc/driver/nvidia/capabilities/gpu{minor}/mig");
    let Ok(entries) = std::fs::read_dir(&mig) else {
        return false;
    };
    entries
        .flatten()
        .any(|e| e.file_name().to_string_lossy().starts_with("gi"))
}

/// Classify one card.
///
/// The order is deliberate: the strongest evidence is tested first, and anything that is not
/// positively established falls through to [`Tier::Soft`]. Nothing here can award the model's
/// middle tier, and that absence is the honest encoding of a measurement that failed rather than an
/// oversight. See the module header.
fn classify(device_dir: &Path, vendor: Vendor) -> (Tier, Evidence) {
    // An SR-IOV virtual function carries a `physfn` link back to the physical function that
    // created it. This is unambiguous and vendor-neutral: if kern is looking at a VF, the
    // partitioning was done by the device, not by kern.
    if device_dir.join("physfn").exists() {
        return (Tier::Hw, Evidence::SriovVirtualFunction);
    }
    // MIG is NVIDIA-only. The vendor test comes first so kern does not walk the NVIDIA proc tree for
    // an AMD card at all; the attribution that keeps one card's MIG instances from promoting another
    // is inside `mig_instances_for_card`, which is where it belongs.
    if vendor == Vendor::Nvidia && mig_instances_for_card(device_dir) {
        return (Tier::Hw, Evidence::MigInstance);
    }
    (Tier::Soft, Evidence::NoPartitionFound)
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
pub fn detect() -> Vec<Gpu> {
    let dmem = dmem_controller_available();
    let kfd = Path::new("/dev/kfd").exists();
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
        let (tier, evidence) = classify(&device_dir, vendor);
        out.push(Gpu {
            card: name,
            vendor,
            device_id,
            driver: driver_name(&device_dir),
            tier,
            evidence,
            dmem_controller: dmem,
            kfd_present: kfd,
        });
    }
    // Stable order, so two runs on the same host produce the same output and a diff of `kern
    // doctor` between two boots is meaningful.
    out.sort_by(|a, b| a.card.cmp(&b.card));
    out
}

/// One human-readable line per GPU: what it is, which tier it gets, and why.
///
/// Kept separate from [`detect`] so the classification can be tested without a terminal and
/// rendered differently by a future `kern probe` without duplicating the policy.
pub fn describe(gpu: &Gpu) -> String {
    // Identity is built from whatever is actually there, in decreasing order of authority: the PCI
    // vendor, the PCI device id, the bound driver. A board has only the last of the three, so the
    // line degrades to `card0 non-PCI (v3d)` rather than to a row of "unknown".
    let mut ident = gpu.vendor.label();
    if let Some(d) = gpu.device_id {
        ident.push_str(&format!(" {d:#06x}"));
    }
    if let Some(driver) = &gpu.driver {
        ident.push_str(&format!(" ({driver})"));
    }
    format!(
        "{card} {ident}: {tier}, {evidence}",
        card = gpu.card,
        ident = ident,
        tier = gpu.tier.label(),
        evidence = gpu.evidence.describe(),
    )
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

    /// THE GATE THIS MODULE EXISTS FOR. Every string kern can print about a non-hardware tier is
    /// checked against the reserved vocabulary. Written over the `match` rather than over one
    /// hand-listed string, so a tier added later is covered without anyone remembering to add it.
    #[test]
    fn only_hardware_tier_may_use_boundary_words() {
        for tier in [Tier::Hw, Tier::Soft] {
            let text = format!("{} {}", tier.label(), tier.claim());
            match tier {
                Tier::Hw => assert!(
                    overclaims(&text).is_some(),
                    "the hardware tier is the one that MAY claim a boundary, and its claim no \
                     longer does. If that is intentional the gate below is now vacuous: {text}"
                ),
                Tier::Soft => assert_eq!(
                    overclaims(&text),
                    None,
                    "tier {} claims a boundary it does not have: {text}",
                    tier.label()
                ),
            }
        }
    }

    /// The gate has to be able to FAIL, or a green result proves nothing. Positive control.
    #[test]
    fn the_claim_gate_catches_an_overstated_string() {
        assert_eq!(overclaims("a cooperative quota"), None);
        assert_eq!(overclaims("provides VRAM isolation"), Some("isolation"));
        assert_eq!(overclaims("a SECURE per-tenant cap"), Some("secure"));
        assert_eq!(overclaims("a hardware partition"), Some("hard"));
    }

    /// The reason kern prints for a tier must not be an assertion of the tier itself: evidence
    /// strings are shown next to a `TIER-SOFT` line too, so they carry the same restriction.
    #[test]
    fn evidence_strings_never_overclaim() {
        for e in [
            Evidence::SriovVirtualFunction,
            Evidence::MigInstance,
            Evidence::NoPartitionFound,
        ] {
            assert_eq!(
                overclaims(e.describe()),
                None,
                "evidence string claims a boundary: {}",
                e.describe()
            );
        }
    }

    // ── classification ──

    /// An SR-IOV virtual function is the one vendor-neutral hardware partition kern can see, and it
    /// is a link the kernel creates, so its presence is the whole test.
    #[test]
    fn physfn_link_promotes_to_hardware_tier() {
        let d = TmpDir::new("physfn");
        std::fs::write(d.0.join("physfn"), "").expect("write physfn");
        assert_eq!(
            classify(&d.0, Vendor::Amd),
            (Tier::Hw, Evidence::SriovVirtualFunction)
        );
    }

    /// FAIL-CLOSED, stated as a test: an empty device directory is not an error, it is a
    /// `TIER-SOFT`. This is the branch every consumer GPU takes.
    ///
    /// Deterministic on EVERY host, including one with MIG configured, and that is the point of the
    /// per-card attribution: a device directory that has no PCI address the NVIDIA driver knows
    /// cannot inherit another card's MIG instances. Before that fix this test had to be written as a
    /// property ("promoted only with evidence") because the answer depended on the machine.
    #[test]
    fn a_bare_device_falls_through_to_the_cooperative_tier() {
        let d = TmpDir::new("bare");
        for v in [Vendor::Nvidia, Vendor::Amd, Vendor::Intel, Vendor::Other(1)] {
            assert_eq!(
                classify(&d.0, v),
                (Tier::Soft, Evidence::NoPartitionFound),
                "vendor {v:?} was promoted with no evidence for it"
            );
        }
    }

    /// THE OVERCLAIM THIS MODULE ALMOST SHIPPED. MIG configured anywhere on the host must not reach
    /// a card that does not own it. Written against the two joints where the attribution can break:
    /// a device directory with no resolvable PCI address, and a PCI address the NVIDIA driver has no
    /// record of. Both return `false` before any capability directory is read at all, so neither
    /// depends on the host's MIG state.
    ///
    /// NO POSITIVE CONTROL, and the reason is worth stating rather than hiding: nothing here can
    /// make this function return `true`, because that needs MIG hardware this project does not own
    /// and `/proc` cannot be faked. So this test proves only the fail-closed half. The `physfn` path
    /// has its positive control above precisely because a link CAN be created; the MIG path is
    /// written to fail closed for exactly the reason that it cannot.
    #[test]
    fn mig_is_attributed_to_a_card_and_not_to_the_host() {
        let d = TmpDir::new("mig");
        assert!(
            !mig_instances_for_card(&d.0),
            "a directory with no PCI address inherited someone else's MIG instances"
        );
        // A real-looking BDF that no NVIDIA card has: the lookup must fail, not fall back to a scan.
        assert_eq!(nvidia_device_minor("ffff:ff:1f.7"), None);
    }

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
            describe(&Gpu {
                card: "card0".into(),
                vendor,
                device_id,
                driver: driver.map(str::to_string),
                tier: Tier::Soft,
                evidence: Evidence::NoPartitionFound,
                dmem_controller: false,
                kfd_present: false,
            })
        };
        assert_eq!(
            row(Vendor::Nvidia, Some(0x2d04), Some("nvidia")),
            "card0 NVIDIA 0x2d04 (nvidia): TIER-SOFT, no device-level partition found"
        );
        assert_eq!(
            row(Vendor::NonPci, None, Some("v3d")),
            "card0 non-PCI (v3d): TIER-SOFT, no device-level partition found"
        );
        assert_eq!(
            row(Vendor::NonPci, None, Some("nv_platform")),
            "card0 non-PCI (nv_platform): TIER-SOFT, no device-level partition found"
        );
        // An unrecognised PCI vendor keeps its id rather than becoming an anonymous "unknown".
        assert!(row(Vendor::Other(0x1af4), Some(0x1050), None).contains("PCI vendor 0x1af4 0x1050"));
        // Nothing readable at all is still a line, and still not an overclaim.
        assert_eq!(
            row(Vendor::NonPci, None, None),
            "card0 non-PCI: TIER-SOFT, no device-level partition found"
        );
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
            if g.tier == Tier::Soft {
                assert_eq!(g.evidence, Evidence::NoPartitionFound);
                assert_eq!(overclaims(&describe(g)), None, "{}", describe(g));
            } else {
                assert_ne!(
                    g.evidence,
                    Evidence::NoPartitionFound,
                    "promoted with no evidence"
                );
            }
        }
    }
}
