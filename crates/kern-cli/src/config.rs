//! `kern.toml` — the resource-centric config schema.
//!
//! The implemented sections mirror the private runtime's `kern.toml` model (same sections, same
//! resource-centric shape). The CPU **field names are spelled to match the CLI flags 1:1** here
//! (`cpus` = `--cpus` quota, `cpuset` = `--cpuset-cpus` pin, `cores` = host capacity, `nice`), a
//! deliberate divergence from the private runtime's older `vcpus`/`priority` spelling; those legacy
//! keys are REJECTED with a migration hint (not silently ignored) so a stale config can't apply a
//! silently-wrong limit. It is parsed by kern's own dependency-free TOML reader (no `serde`/`toml`
//! crates) — see [`parse`].
//!
//! The model is **resource-centric**, not box-centric: you *declare* the host resources you want
//! kern to consider (`[[cpu]]`, `[[gpio]]`, `[[disk]]`) and *define* named virtual profiles that
//! carve them up (`[[vcpu]]`, `[[vgpio]]`, `[[vdisk]]`). A profile is then attached to a command by
//! its prefix — `kern run vcpu:heavy vgpio:leds -- cmd` — exactly as in the private runtime.
//!
//! kern-public models **CPU, GPIO and disk** resources only; there is no GPU concept here. The
//! parser is deliberately **tolerant**: a `kern.toml` shared with another kern edition may carry
//! sections or keys this build doesn't implement (or TOML syntax this hand-rolled reader doesn't
//! model), and those are ignored rather than rejected, so the config still loads.

/// Top-level `kern.toml`. Section names are identical to the private runtime.
#[derive(Debug, Clone, Default)]
pub struct KernConfig {
    /// `[kern]` — global settings.
    pub kern: KernSettings,
    /// `[[cpu]]` — physical CPU resource declarations that `[[vcpu]]` profiles split.
    pub cpu: Vec<CpuEntry>,
    /// `[[vcpu]]` — virtual CPU profiles (`vcpu:<name>`).
    pub vcpu: Vec<VCpuEntry>,
    /// `[[gpio]]` — physical GPIO/peripheral declarations that `[[vgpio]]` profiles reference.
    pub gpio: Vec<GpioEntry>,
    /// `[[vgpio]]` — virtual GPIO / I/O peripheral profiles (`vgpio:<name>`).
    pub vgpio: Vec<VGpioEntry>,
    /// `[[disk]]` — physical disk pools that `[[vdisk]]` profiles place volumes on.
    pub disk: Vec<DiskEntry>,
    /// `[[vdisk]]` — virtual disk profiles: size quota + I/O limits (`vdisk:<name>`).
    pub vdisk: Vec<VDiskEntry>,
}

/// `[kern]` — global settings.
#[derive(Debug, Clone, Default)]
pub struct KernSettings {
    /// Config schema version (currently 1).
    pub config_version: Option<u32>,
    /// Log level: `trace`/`debug`/`info`/`warn`/`error` (default `info`).
    pub log_level: Option<String>,
    /// Persistent allocation tracking for crash recovery (default off).
    pub crash_recovery: bool,
}

// ─────────────────────────────── CPU (implemented) ───────────────────────────────

/// `[[cpu]]` — a physical CPU resource declaration (the budget a `[[vcpu]]` splits).
#[derive(Debug, Clone, Default)]
pub struct CpuEntry {
    pub id: String,
    /// Physical core budget this host CPU can hand out.
    pub cores: Option<f64>,
    pub memory: Option<String>,
    /// CPU pinning range, e.g. `"0-7"`, `"0,2,4"`.
    pub cpuset: Option<String>,
    pub numa: Option<i32>,
    pub name: Option<String>,
}

/// `[[vcpu]]` — a virtual CPU profile. Field names match the CLI flags 1:1, so a profile reads like
/// the command line: `cpus` = the core *quota* (`--cpus`, cgroup `cpu.max`), `cpuset` = CPU *pinning*
/// (`--cpuset-cpus`), `memory` = `--memory`, `nice` = `--nice`.
#[derive(Debug, Clone, Default)]
pub struct VCpuEntry {
    pub name: String,
    /// `backend = "cpu:0"` → a `[[cpu]]` id. `None` = standalone.
    pub backend: Option<String>,
    /// CPU pinning range, e.g. `"0-7"`, `"0,2,4"` — like `--cpuset-cpus`.
    pub cpuset: Option<String>,
    /// Core quota (K8s/Docker units): `4.0` = 4 cores, `0.5` = half — like `--cpus`. cgroup `cpu.max`.
    pub cpus: Option<f64>,
    /// NUMA node; CPUs auto-detected from its cpulist. Mutually exclusive with `cpuset`.
    pub numa: Option<i32>,
    /// RAM limit, e.g. `"512 MB"`, `"16 GB"` — like `--memory`. cgroup `memory.max`.
    pub memory: Option<String>,
    /// Scheduling niceness (-20 high … 19 low) — like `--nice`.
    pub nice: i32,
    /// Inherit another `[[vcpu]]` by name.
    pub extends: Option<String>,
}

// ─────────────────────────────── GPIO (implemented) ───────────────────────────────

/// `[[gpio]]` — a physical GPIO / peripheral controller declaration.
#[derive(Debug, Clone, Default)]
pub struct GpioEntry {
    pub id: String,
    pub name: Option<String>,
    pub total_pins: Option<u32>,
    pub pins: Vec<u32>,
    pub pwm: Vec<u32>,
    pub i2c: Vec<String>,
    pub spi: Vec<String>,
    pub uart: Vec<String>,
    pub adc: Vec<u32>,
    pub onewire: Vec<u32>,
    pub can: Vec<String>,
    pub camera: Vec<String>,
    pub audio: Vec<String>,
    pub leds: Vec<String>,
    pub bluetooth: Vec<String>,
    pub usb: Vec<String>,
    pub input: Vec<String>,
    pub midi: Vec<String>,
    pub display: Vec<String>,
    pub net: Vec<String>,
    pub extra: Vec<String>,
    pub usb_ports: Vec<UsbPortEntry>,
}

/// A specific USB port on a `[[gpio]]` board (`[[gpio.usb_ports]]`).
#[derive(Debug, Clone, Default)]
pub struct UsbPortEntry {
    pub bus: u32,
    pub port: u32,
    pub usb: Option<String>,
    pub name: Option<String>,
    pub reserved: Option<String>,
}

/// `[[vgpio]]` — a virtual GPIO / I/O peripheral profile. Field names identical to the private.
#[derive(Debug, Clone, Default)]
pub struct VGpioEntry {
    pub name: String,
    /// `backend = "gpio:0"` → a `[[gpio]]` id.
    pub backend: String,
    pub pins: Vec<u32>,
    pub pwm: Vec<u32>,
    pub i2c: Vec<String>,
    pub spi: Vec<String>,
    pub uart: Vec<String>,
    pub adc: Vec<u32>,
    pub onewire: Vec<u32>,
    pub can: Vec<String>,
    pub camera: Vec<String>,
    pub audio: Vec<String>,
    pub leds: Vec<String>,
    pub bluetooth: Vec<String>,
    pub usb: Vec<String>,
    pub input: Vec<String>,
    pub midi: Vec<String>,
    pub display: Vec<String>,
    pub net: Vec<String>,
    pub extra: Vec<String>,
}

// ─────────────────────────────── Disk (implemented) ───────────────────────────────

/// `[[disk]]` — a physical disk pool volumes are placed on.
#[derive(Debug, Clone, Default)]
pub struct DiskEntry {
    pub name: String,
    pub path: String,
    pub default: bool,
    pub size: Option<String>,
    pub iops: Option<u64>,
    pub bandwidth: Option<String>,
    pub device: Option<String>,
    pub model: Option<String>,
}

/// `[[vdisk]]` — a virtual disk profile: size quota + optional I/O limits. Identical to the private.
#[derive(Debug, Clone, Default)]
pub struct VDiskEntry {
    pub name: String,
    /// `backend = "disk:0"` → a `[[disk]]` name.
    pub backend: String,
    /// Quota, e.g. `"2g"`.
    pub size: Option<String>,
    pub iops: Option<u64>,
    pub bandwidth: Option<String>,
    /// Survive box removal.
    pub persistent: bool,
}

// ─────────────────────────────────── parser ───────────────────────────────────
//
// A dependency-free reader for the TOML subset the schema uses: `[table]`, `[[array.of.tables]]`,
// and `key = value` where a value is a quoted string, a bare int/float, a bool, or an array of
// strings / ints. Hand-rolled (no serde/toml). It is deliberately TOLERANT for cross-edition
// portability: an unrecognized section, an unrecognized key, or a line of TOML this reader doesn't
// model (a multi-line array, an inline table) is ignored rather than rejected. A *malformed value*
// of a key we DO implement is still an error (with its line) — tolerance skips unknowns, it doesn't
// swallow real mistakes.

/// Which section the current `key = value` lines belong to.
enum Ctx {
    None,
    Kern,
    Cpu,
    Vcpu,
    Gpio,
    UsbPort,
    Vgpio,
    Disk,
    Vdisk,
    /// A section kern-public recognizes in the schema but does not implement — its keys are ignored
    /// so an existing `kern.toml` (e.g. one that also targets the private runtime) still loads. No
    /// output mentions it.
    Skip,
}

/// Parse a `kern.toml` document. Errors carry the 1-based line of the offending token.
pub fn parse(text: &str) -> Result<KernConfig, String> {
    let mut cfg = KernConfig::default();
    let mut ctx = Ctx::None;
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let n = i + 1;
        let line = strip_comment(lines[i]).trim();
        if line.is_empty() {
            i += 1;
            continue;
        }
        if let Some((_double, path)) = section_header(line) {
            ctx = enter_section(&mut cfg, path, n)?;
            i += 1;
            continue;
        }
        // A line that is neither a `[section]` nor `key = value` is unsupported syntax — skip it
        // rather than fail. A kern.toml can carry TOML this hand-rolled reader doesn't model (an
        // inline table like `{bus=1, …}`); dropping those lines keeps the rest of the config usable.
        let Some((key, val)) = line.split_once('=') else {
            i += 1;
            continue;
        };
        let key = key.trim();
        // Multi-line array: `key = [` whose closing `]` is on a later line (as `kern setup -c` itself
        // writes for long device lists — e.g. a `[[gpio]]`'s `i2c`/`spi`). Gather the following
        // comment-stripped lines up to the `]` into one array literal so the reader accepts it,
        // instead of failing the whole config. The error still points at the array's opening line.
        let first = val.trim();
        let joined;
        let val: &str = if first.starts_with('[') && !first.contains(']') {
            let mut buf = String::from(first);
            while i + 1 < lines.len() {
                i += 1;
                let more = strip_comment(lines[i]).trim();
                if !more.is_empty() {
                    buf.push(' ');
                    buf.push_str(more);
                }
                if more.contains(']') {
                    break;
                }
            }
            joined = buf;
            joined.as_str()
        } else {
            first
        };
        let at = |e: String| format!("line {n}: {e}");
        match ctx {
            Ctx::None => {} // a key before any section — ignore (tolerant of foreign layouts)
            Ctx::Skip => {} // an unimplemented section — ignore its keys (schema-compat, no output)
            Ctx::Kern => apply_kern(&mut cfg.kern, key, val).map_err(at)?,
            Ctx::Cpu => apply_cpu(cfg.cpu.last_mut().unwrap(), key, val).map_err(at)?,
            Ctx::Vcpu => apply_vcpu(cfg.vcpu.last_mut().unwrap(), key, val).map_err(at)?,
            Ctx::Gpio => apply_gpio(cfg.gpio.last_mut().unwrap(), key, val).map_err(at)?,
            Ctx::UsbPort => {
                let ports = &mut cfg.gpio.last_mut().unwrap().usb_ports;
                apply_usb_port(ports.last_mut().unwrap(), key, val).map_err(at)?;
            }
            Ctx::Vgpio => apply_vgpio(cfg.vgpio.last_mut().unwrap(), key, val).map_err(at)?,
            Ctx::Disk => apply_disk(cfg.disk.last_mut().unwrap(), key, val).map_err(at)?,
            Ctx::Vdisk => apply_vdisk(cfg.vdisk.last_mut().unwrap(), key, val).map_err(at)?,
        }
        i += 1;
    }
    Ok(cfg)
}

/// Open a new section, pushing a fresh array-of-tables entry where needed.
fn enter_section(cfg: &mut KernConfig, path: &str, n: usize) -> Result<Ctx, String> {
    Ok(match path {
        "kern" => Ctx::Kern,
        "cpu" => {
            cfg.cpu.push(CpuEntry::default());
            Ctx::Cpu
        }
        "vcpu" => {
            cfg.vcpu.push(VCpuEntry::default());
            Ctx::Vcpu
        }
        "gpio" => {
            cfg.gpio.push(GpioEntry::default());
            Ctx::Gpio
        }
        "gpio.usb_ports" => {
            let g = cfg
                .gpio
                .last_mut()
                .ok_or_else(|| format!("line {n}: [[gpio.usb_ports]] before any [[gpio]]"))?;
            g.usb_ports.push(UsbPortEntry::default());
            Ctx::UsbPort
        }
        "vgpio" => {
            cfg.vgpio.push(VGpioEntry::default());
            Ctx::Vgpio
        }
        "disk" => {
            cfg.disk.push(DiskEntry::default());
            Ctx::Disk
        }
        "vdisk" => {
            cfg.vdisk.push(VDiskEntry::default());
            Ctx::Vdisk
        }
        // Any other section is unrecognized — ignore it (and its keys) rather than fail. A kern.toml
        // is meant to be portable across kern editions, so one may carry sections this build doesn't
        // implement (e.g. a private-runtime GPU section); dropping them keeps the config loadable.
        _ => Ctx::Skip,
    })
}

// ── per-section key handlers. An unrecognized key is ignored (not an error), so a kern.toml written
//    by another kern edition — with keys this build doesn't model — still loads. ──

fn apply_kern(k: &mut KernSettings, key: &str, v: &str) -> Result<(), String> {
    match key {
        "config_version" => k.config_version = Some(value_u32(v)?),
        "log_level" => k.log_level = Some(value_string(v)?),
        "crash_recovery" => k.crash_recovery = value_bool(v)?,
        _ => {} // unrecognized key: ignored (forward/cross-version config compat)
    }
    Ok(())
}

fn apply_cpu(e: &mut CpuEntry, key: &str, v: &str) -> Result<(), String> {
    match key {
        "id" => e.id = value_string(v)?,
        "cores" => e.cores = Some(value_f64(v)?),
        "memory" => e.memory = Some(value_string(v)?),
        "cpuset" => e.cpuset = Some(value_string(v)?),
        "numa" => e.numa = Some(value_i32(v)?),
        "name" => e.name = Some(value_string(v)?),
        // Keys RENAMED in this schema: reject with a migration hint instead of silently ignoring
        // them (unknown-key tolerance) — an ignored capacity key would misstate the host budget.
        "vcpus" => return Err("[[cpu]] 'vcpus' was renamed to 'cores'".into()),
        "cpus" => {
            return Err(
                "[[cpu]] 'cpus' was renamed: use 'cores' for capacity or 'cpuset' for CPU pinning"
                    .into(),
            )
        }
        _ => {} // unrecognized key: ignored (forward/cross-version config compat)
    }
    Ok(())
}

fn apply_vcpu(e: &mut VCpuEntry, key: &str, v: &str) -> Result<(), String> {
    match key {
        "name" => e.name = value_string(v)?,
        "backend" => e.backend = Some(value_string(v)?),
        "cpuset" => e.cpuset = Some(value_string(v)?),
        "cpus" => {
            e.cpus = Some(value_f64(v).map_err(|orig| {
                // A LEGACY string pin (`cpus = "0-3"`) can't parse as the new f64 quota — point at the
                // rename (`cpus` = quota, pin moved to `cpuset`) instead of a bare "expected a number".
                let unq = v.trim().trim_matches(['"', '\'']);
                if is_cpu_list(unq) {
                    "'cpus' is now the core quota (a number, like --cpus); the CPU pin list moved to \
                     'cpuset' (--cpuset-cpus)"
                        .to_string()
                } else {
                    orig
                }
            })?);
        }
        "numa" => e.numa = Some(value_i32(v)?),
        "memory" => e.memory = Some(value_string(v)?),
        "nice" => e.nice = value_i32(v)?,
        "extends" => e.extends = Some(value_string(v)?),
        // Keys RENAMED in this schema: reject with a migration hint rather than silently ignoring
        // them. Silence here is dangerous — an ignored `vcpus` drops the CPU quota, and a legacy
        // `cpus` pin would be re-read as a quota: a silently-WRONG resource limit, no error.
        "vcpus" => {
            return Err(
                "'vcpus' was renamed: use 'cpus' for the core quota (--cpus) and \
                        'cpuset' for CPU pinning (--cpuset-cpus)"
                    .into(),
            )
        }
        "priority" => {
            return Err(
                "'priority' was removed: use 'nice' (-20 high .. 19 low, the --nice flag)".into(),
            )
        }
        _ => {} // unrecognized key: ignored (forward/cross-version config compat)
    }
    Ok(())
}

fn apply_gpio(e: &mut GpioEntry, key: &str, v: &str) -> Result<(), String> {
    match key {
        "id" => e.id = value_string(v)?,
        "name" => e.name = Some(value_string(v)?),
        "total_pins" => e.total_pins = Some(value_u32(v)?),
        "pins" => e.pins = value_u32_array(v)?,
        "pwm" => e.pwm = value_u32_array(v)?,
        "adc" => e.adc = value_u32_array(v)?,
        "onewire" => e.onewire = value_u32_array(v)?,
        "i2c" => e.i2c = value_str_array(v)?,
        "spi" => e.spi = value_str_array(v)?,
        "uart" => e.uart = value_str_array(v)?,
        "can" => e.can = value_str_array(v)?,
        "camera" => e.camera = value_str_array(v)?,
        "audio" => e.audio = value_str_array(v)?,
        "leds" => e.leds = value_str_array(v)?,
        "bluetooth" => e.bluetooth = value_str_array(v)?,
        "usb" => e.usb = value_str_array(v)?,
        "input" => e.input = value_str_array(v)?,
        "midi" => e.midi = value_str_array(v)?,
        "display" => e.display = value_str_array(v)?,
        "net" => e.net = value_str_array(v)?,
        "extra" => e.extra = value_str_array(v)?,
        _ => {} // unrecognized key: ignored (forward/cross-version config compat)
    }
    Ok(())
}

fn apply_usb_port(e: &mut UsbPortEntry, key: &str, v: &str) -> Result<(), String> {
    match key {
        "bus" => e.bus = value_u32(v)?,
        "port" => e.port = value_u32(v)?,
        "usb" => e.usb = Some(value_string(v)?),
        "name" => e.name = Some(value_string(v)?),
        "reserved" => e.reserved = Some(value_string(v)?),
        _ => {} // unrecognized key: ignored (forward/cross-version config compat)
    }
    Ok(())
}

fn apply_vgpio(e: &mut VGpioEntry, key: &str, v: &str) -> Result<(), String> {
    match key {
        "name" => e.name = value_string(v)?,
        "backend" => e.backend = value_string(v)?,
        "pins" => e.pins = value_u32_array(v)?,
        "pwm" => e.pwm = value_u32_array(v)?,
        "adc" => e.adc = value_u32_array(v)?,
        "onewire" => e.onewire = value_u32_array(v)?,
        "i2c" => e.i2c = value_str_array(v)?,
        "spi" => e.spi = value_str_array(v)?,
        "uart" => e.uart = value_str_array(v)?,
        "can" => e.can = value_str_array(v)?,
        "camera" => e.camera = value_str_array(v)?,
        "audio" => e.audio = value_str_array(v)?,
        "leds" => e.leds = value_str_array(v)?,
        "bluetooth" => e.bluetooth = value_str_array(v)?,
        "usb" => e.usb = value_str_array(v)?,
        "input" => e.input = value_str_array(v)?,
        "midi" => e.midi = value_str_array(v)?,
        "display" => e.display = value_str_array(v)?,
        "net" => e.net = value_str_array(v)?,
        "extra" => e.extra = value_str_array(v)?,
        _ => {} // unrecognized key: ignored (forward/cross-version config compat)
    }
    Ok(())
}

fn apply_disk(e: &mut DiskEntry, key: &str, v: &str) -> Result<(), String> {
    match key {
        "name" => e.name = value_string(v)?,
        "path" => e.path = value_string(v)?,
        "default" => e.default = value_bool(v)?,
        "size" => e.size = Some(value_string(v)?),
        "iops" => e.iops = Some(value_u64(v)?),
        "bandwidth" => e.bandwidth = Some(value_string(v)?),
        "device" => e.device = Some(value_string(v)?),
        "model" => e.model = Some(value_string(v)?),
        _ => {} // unrecognized key: ignored (forward/cross-version config compat)
    }
    Ok(())
}

fn apply_vdisk(e: &mut VDiskEntry, key: &str, v: &str) -> Result<(), String> {
    match key {
        "name" => e.name = value_string(v)?,
        "backend" => e.backend = value_string(v)?,
        "size" => e.size = Some(value_string(v)?),
        "iops" => e.iops = Some(value_u64(v)?),
        "bandwidth" => e.bandwidth = Some(value_string(v)?),
        "persistent" => e.persistent = value_bool(v)?,
        _ => {} // unrecognized key: ignored (forward/cross-version config compat)
    }
    Ok(())
}

// ── low-level TOML value/line helpers ──

/// Drop a `#` comment outside a quoted string.
fn strip_comment(line: &str) -> &str {
    kern_common::toml_lite::strip_comment(line)
}

/// `[x]` → `(false, "x")`, `[[x]]` → `(true, "x")`; `None` if not a header. Inner is trimmed.
fn section_header(line: &str) -> Option<(bool, &str)> {
    if let Some(inner) = line.strip_prefix("[[").and_then(|s| s.strip_suffix("]]")) {
        return Some((true, inner.trim()));
    }
    if let Some(inner) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return Some((false, inner.trim()));
    }
    None
}

fn value_string(v: &str) -> Result<String, String> {
    kern_common::toml_lite::quoted_string(v)
}

fn value_bool(v: &str) -> Result<bool, String> {
    kern_common::toml_lite::parse_bool(v)
}

fn value_f64(v: &str) -> Result<f64, String> {
    v.trim()
        .parse::<f64>()
        .ok()
        .filter(|f| f.is_finite())
        .ok_or_else(|| format!("expected a number, got `{}`", v.trim()))
}

fn value_i32(v: &str) -> Result<i32, String> {
    v.trim()
        .parse::<i32>()
        .map_err(|_| format!("expected an integer, got `{}`", v.trim()))
}

fn value_u32(v: &str) -> Result<u32, String> {
    v.trim()
        .parse::<u32>()
        .map_err(|_| format!("expected a non-negative integer, got `{}`", v.trim()))
}

fn value_u64(v: &str) -> Result<u64, String> {
    v.trim()
        .parse::<u64>()
        .map_err(|_| format!("expected a non-negative integer, got `{}`", v.trim()))
}

/// The `a, b, c` inside an array `[ ... ]`, split on commas that are not inside a quoted string.
fn array_items(v: &str) -> Result<Vec<String>, String> {
    let v = v.trim();
    let inner = v
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| format!("expected an array `[...]`, got `{v}`"))?;
    Ok(kern_common::toml_lite::split_top_commas(inner))
}

fn value_str_array(v: &str) -> Result<Vec<String>, String> {
    array_items(v)?
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| value_string(s.trim()))
        .collect()
}

fn value_u32_array(v: &str) -> Result<Vec<u32>, String> {
    array_items(v)?
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| value_u32(s.trim()))
        .collect()
}

// ─────────────────────────────── load + resolve ───────────────────────────────

/// Default config location: `$XDG_CONFIG_HOME/kern/kern.toml`, else `~/.config/kern/kern.toml`.
/// Mirrors the private runtime's path.
pub fn default_path() -> Option<std::path::PathBuf> {
    // An empty `XDG_CONFIG_HOME` (exported but blank) must be treated as unset — otherwise it forms a
    // *relative* `kern/kern.toml` and the config lands in the current directory.
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME").filter(|x| !x.is_empty()) {
        return Some(std::path::PathBuf::from(x).join("kern").join("kern.toml"));
    }
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(|h| std::path::PathBuf::from(h).join(".config/kern/kern.toml"))
}

/// Load `kern.toml` from `path` (or the default location). A missing file is not an error — it
/// yields an empty config, so profiles are simply "not found". A present-but-malformed file IS an
/// error (with its line).
pub fn load(path: Option<&str>) -> Result<KernConfig, String> {
    load_impl(path, std::env::var_os("KERN_CONFIG"), &default_path())
}

/// Testable core of [`load`]. Precedence: explicit `--config` > `KERN_CONFIG` env > default location.
/// A source named *explicitly* (either of the first two) that is missing/malformed is an error; a
/// merely-absent default yields an empty config (profiles simply "not found").
fn load_impl(
    path: Option<&str>,
    env_cfg: Option<std::ffi::OsString>,
    default: &Option<std::path::PathBuf>,
) -> Result<KernConfig, String> {
    let explicit = path.is_some() || env_cfg.is_some();
    let p = match path {
        Some(p) => std::path::PathBuf::from(p),
        None => match env_cfg {
            Some(e) => std::path::PathBuf::from(e),
            None => match default.as_ref().filter(|p| p.exists()) {
                Some(p) => p.clone(),
                None => return Ok(KernConfig::default()),
            },
        },
    };
    match std::fs::read_to_string(&p) {
        Ok(text) => parse(&text).map_err(|e| format!("{}: {e}", p.display())),
        Err(_) if !explicit => Ok(KernConfig::default()),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

/// A `prefix:name` profile reference on the command line.
pub enum ProfileRef<'a> {
    Vcpu(&'a str),
    Vgpio(&'a str),
    Vdisk(&'a str),
}

/// Classify a leading command token as a resource-profile reference, or `None` if it's the command.
pub fn classify(token: &str) -> Option<ProfileRef<'_>> {
    token
        .strip_prefix("vcpu:")
        .map(ProfileRef::Vcpu)
        .or_else(|| token.strip_prefix("vgpio:").map(ProfileRef::Vgpio))
        .or_else(|| token.strip_prefix("vdisk:").map(ProfileRef::Vdisk))
}

/// The CPU/memory limits a resolved `[[vcpu]]` profile contributes, in the same units the CLI flags
/// use — so applying a profile is just "fill the flags the user didn't set".
#[derive(Debug, Default, PartialEq)]
pub struct ResolvedCpu {
    pub memory: Option<u64>,
    pub cpus: Option<f64>,
    pub cpuset: Option<String>,
    pub nice: Option<i32>,
}

/// Resolve a `[[vcpu]]` entry to concrete limits: `cpus`→quota, `cpuset`/`numa`→pinning,
/// `memory`→bytes, `nice`→nice. `extends` is followed one level (a base profile).
pub fn resolve_vcpu(cfg: &KernConfig, name: &str) -> Result<ResolvedCpu, String> {
    resolve_vcpu_seen(cfg, name, &mut Vec::new())
}

/// `extends` is followed recursively (a base may itself extend another). `seen` tracks the chain so a
/// cycle (`a extends b`, `b extends a`, or `a extends a`) is reported as an error instead of
/// recursing until the stack overflows and the process aborts.
fn resolve_vcpu_seen(
    cfg: &KernConfig,
    name: &str,
    seen: &mut Vec<String>,
) -> Result<ResolvedCpu, String> {
    if seen.iter().any(|s| s == name) {
        seen.push(name.to_string());
        return Err(format!("[[vcpu]] 'extends' cycle: {}", seen.join(" -> ")));
    }
    seen.push(name.to_string());
    let e = cfg
        .vcpu
        .iter()
        .find(|e| e.name == name)
        .ok_or_else(|| format!("no [[vcpu]] profile named '{name}' in kern.toml"))?;
    // Same schema the forms/`config add` enforce, applied to a possibly hand-edited file so a bad
    // value fails HERE with a clear message rather than silently doing nothing.
    let ctx = |m: String| format!("[[vcpu]] '{name}': {m}");
    validate_profile_name(&e.name).map_err(ctx)?;
    if let Some(c) = &e.cpuset {
        check_cpus(c).map_err(ctx)?;
    }
    // Base (extends) first, then this entry overrides.
    let mut r = ResolvedCpu::default();
    if let Some(base) = &e.extends {
        r = resolve_vcpu_seen(cfg, base, seen)?;
    }
    if let Some(q) = e.cpus {
        // Same positivity rule the form / `config add` enforce (`profile_line`): a hand-edited
        // `cpus = 0` / `-4` / `inf` would otherwise resolve to a quota the cgroup backend floors to
        // ~1% of a core — a silent near-freeze rather than the clear error this resolver promises.
        if !q.is_finite() || q <= 0.0 {
            return Err(ctx(format!(
                "cpus must be a positive number of cores (got {q})"
            )));
        }
        r.cpus = Some(q);
    }
    if let Some(m) = &e.memory {
        r.memory =
            Some(size_to_bytes(m).ok_or_else(|| format!("bad memory '{m}' in [[vcpu]] '{name}'"))?);
    }
    // Pinning: explicit `cpuset`, else derive from `numa` node's cpulist.
    if let Some(c) = &e.cpuset {
        r.cpuset = Some(c.clone());
    } else if let Some(node) = e.numa {
        if let Some(list) = numa_cpulist(node) {
            r.cpuset = Some(list);
        }
    }
    // Scheduling niceness (-20 high … 19 low), like `--nice`.
    if e.nice != 0 {
        r.nice = Some(e.nice.clamp(-20, 19));
    }
    Ok(r)
}

/// A resolved `[[vgpio]]` profile: the concrete host device nodes and sysfs directories the box
/// should expose. Faithful to the private runtime's `discover_iot_devices`.
#[derive(Debug, Default, PartialEq)]
pub struct ResolvedVgpio {
    pub name: String,
    /// Character device nodes to bind into the box's `/dev` (gpiochips + `/dev/*` peripherals).
    pub devs: Vec<String>,
    /// sysfs directories to bind into the box's `/sys` (pwm / adc / 1-wire / leds).
    pub sysfs: Vec<String>,
    /// The requested GPIO pins (for the `KERN_VGPIO_PINS` env var in the no-sandbox `run` path).
    pub pins: Vec<u32>,
}

/// Resolve a `[[vgpio]]` entry to the concrete host paths that exist right now. Mirrors the private:
/// `pins` → every `/dev/gpiochipN` (the chip exposes all its lines; per-pin isolation is metadata);
/// `pwm`/`adc`/`onewire`/`leds` → their sysfs dirs; the string fields (`i2c`/`spi`/`uart`/`can`/
/// `camera`/`audio`/…) are `/dev/*` paths, **canonicalized and re-checked to stay under `/dev/`** so
/// a symlink can't redirect the bind outside `/dev`. Only paths that exist on this host are returned.
pub fn resolve_vgpio(cfg: &KernConfig, name: &str) -> Result<ResolvedVgpio, String> {
    let e = cfg
        .vgpio
        .iter()
        .find(|e| e.name == name)
        .ok_or_else(|| format!("no [[vgpio]] profile named '{name}' in kern.toml"))?;
    // A vgpio may legitimately have no `backend` (e.g. an i2c/spi-only profile with no pins), so the
    // backend is not required here — only the pin numbers are range-checked.
    let ctx = |m: String| format!("[[vgpio]] '{name}': {m}");
    validate_profile_name(&e.name).map_err(ctx)?;
    check_pins(&e.pins).map_err(ctx)?;
    let mut devs = Vec::new();
    let mut sysfs = Vec::new();

    // pins → every gpiochip node (single readdir). HONEST LIMITATION (matches the private runtime):
    // GPIO isolation is *chip-granular*, not per-line — a `/dev/gpiochipN` chardev exposes ALL lines
    // of that controller via ioctl, and requesting any pin binds every gpiochip present. The per-pin
    // list is cooperative metadata (surfaced as `KERN_VGPIO_PINS`), not a kernel boundary. Documented
    // in SECURITY.md so a profile author isn't misled into thinking `pins = [17]` hands out only
    // line 17.
    if !e.pins.is_empty() {
        if let Ok(entries) = std::fs::read_dir("/dev") {
            let mut chips: Vec<String> = entries
                .flatten()
                .filter_map(|d| d.file_name().to_str().map(str::to_string))
                .filter(|s| s.starts_with("gpiochip") && s[8..].bytes().all(|b| b.is_ascii_digit()))
                .map(|s| format!("/dev/{s}"))
                .collect();
            chips.sort();
            devs.extend(chips);
        }
    }

    // sysfs-backed peripherals — only if the dir exists.
    let mut push_sysfs = |p: String| {
        if std::path::Path::new(&p).is_dir() {
            sysfs.push(p);
        }
    };
    for &ch in &e.pwm {
        push_sysfs(format!("/sys/class/pwm/pwmchip{ch}"));
    }
    for &ch in &e.adc {
        push_sysfs(format!("/sys/bus/iio/devices/iio:device{ch}"));
    }
    if !e.onewire.is_empty() {
        push_sysfs("/sys/bus/w1/devices".to_string());
    }
    for led in &e.leds {
        // A LED is a simple name under /sys/class/leds — never a path (no traversal into the host).
        if led.is_empty() || led.contains('/') || led.contains("..") {
            eprintln!("kern: vgpio led '{led}' is not a simple name — skipped");
            continue;
        }
        push_sysfs(format!("/sys/class/leds/{led}"));
    }

    // Direct `/dev/*` device nodes: canonicalize, require the real path stays under `/dev/`, AND
    // refuse the dangerous ones. "Under /dev/" is NOT a sufficient boundary — it still includes
    // `/dev/mem` (physical RAM), `/dev/sda` (the host disk), `/dev/kmem`, `/dev/port`. vGPIO passes
    // *character peripherals* (buses, serial, cameras, sound), never storage or raw memory — so we
    // deny every block device (that's `vdisk`'s job) and the raw-memory char nodes. This closes the
    // hole where an `extra = "/dev/mem"` in a hand-written or imported profile would otherwise bind
    // physical memory into a box.
    for path in vgpio_device_paths(e) {
        match std::fs::canonicalize(&path) {
            Ok(real) if real.starts_with("/dev/") && is_dangerous_dev(&real) => {
                eprintln!(
                    "kern: vgpio device {path} → {} gives the box control over the host (disk / memory / watchdog / firmware / tun / fuse) — refused",
                    real.display()
                );
            }
            Ok(real) if real.starts_with("/dev/") => {
                // Not dangerous, but if it's an UNRECOGNIZED kind (only reachable via `extra`), bind it
                // yet flag it — the expert escape hatch stays open, an accidental pick gets a heads-up.
                if !is_recognized_dev(&real) {
                    eprintln!(
                        "kern: vgpio binding {} — not a recognized peripheral kind; ensure this is intended",
                        real.display()
                    );
                }
                devs.push(real.to_string_lossy().into_owned());
            }
            Ok(real) => {
                eprintln!(
                    "kern: vgpio device {path} resolves to {} (outside /dev/) — skipped",
                    real.display()
                );
            }
            Err(_) => {} // device not present on this host — skip
        }
    }

    // `net` is parsed and preserved for round-trip, but a vGPIO profile does not (yet) move a network
    // interface into the box — so say so rather than silently doing nothing. (Note: this is interface
    // passthrough, NOT the box's `--net`/`--network` host-network SHARING — a different mechanism; we
    // deliberately don't point at `--net` here to avoid conflating the two.)
    if !e.net.is_empty() {
        eprintln!(
            "kern: vgpio '{}' sets net={:?}, but vgpio does not attach network interfaces yet — ignored",
            e.name, e.net
        );
    }

    Ok(ResolvedVgpio {
        name: e.name.clone(),
        devs,
        sysfs,
        pins: e.pins.clone(),
    })
}

/// The canonical `/dev` path of an i2c bus reference. `"1"` or `"i2c-1"` → `Some("/dev/i2c-1")`;
/// a full `/dev/…` path or anything that isn't a plain bus number → `None` (the caller keeps it as-is
/// or rejects it). The single source of truth for i2c normalization, shared by the resolver here and
/// the TUI's edit-seed dedup so the two can't drift apart. Validates all-digits BEFORE building the
/// path, so a crafted `"1/../spi0"` can never concatenate into `/dev/i2c-1/../spi0` → `/dev/spi0`.
pub(crate) fn canon_i2c_bus(s: &str) -> Option<String> {
    if s.starts_with('/') {
        return None;
    }
    let n = s.strip_prefix("i2c-").unwrap_or(s);
    (!n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())).then(|| format!("/dev/i2c-{n}"))
}

/// Is `s` a well-formed `/dev/…` path (SHAPE only — not existence)? `/dev/` then a non-empty run of
/// path chars (alnum `/ . _ -`), no spaces/junk. The single rule shared by the `extra` field's save
/// validation and its live filter, so the CLI, a hand-edited file and the TUI all agree.
pub(crate) fn is_dev_path(s: &str) -> bool {
    s.strip_prefix("/dev/").is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
    })
}

/// A `/dev` node that must never be bound into a deny-by-default *peripheral* sandbox. The rule is a
/// finite CAPABILITY test, not a list to chase: refuse a node that grants any of the host-control
/// capabilities below; allow plain I/O peripherals (gpio, i2c, spi, uart, can, render-GPU, rtc, …).
///
/// 1. host storage — any BLOCK device (sda, mmcblk\*, dm-\*, loop\*) AND the CHARACTER nodes that
///    reach a disk by ioctl: `sg*` (SG_IO), the `nvme0` controller (admin cmd), `/dev/bsg/*`,
///    `/dev/mapper/control`, `loop-control`, `btrfs-control`
/// 2. raw memory / I/O ports — mem, kmem, port, kmsg, fmem, mergemem
/// 3. arbitrary DMA — VFIO (`/dev/vfio/*`, incl. the 6.x cdev `/dev/vfio/devices/*`)
/// 4. host reboot / brick — watchdog\*, mtd\*, nvram (raw flash/firmware)
/// 5. virtualization / hypervisor — kvm, vhost\* (vhost-net/vsock/vdpa), vboxdrv
/// 6. input/HID injection — uinput, uhid, hidraw\*, hiddev\* (raw HID write injects keystrokes)
/// 7. host network creation — net/tun, ppp
/// 8. display control — dri/card\* (the privileged KMS/modeset node)
/// 9. mount confusion — fuse
/// 10. raw USB — /dev/bus/usb/\* (reprogram/impersonate any device on the bus — BadUSB)
/// 11. management engine — mei\* (Intel ME: privileged out-of-band host access)
///
/// The render-only GPU node (`dri/renderD*`) is allowed — it's the real GPU-compute case — but note it
/// is "safe *if* the IOMMU isolates" (a GPU is a DMA engine), NOT zero-risk like an i2c bus. rtc/hpet
/// are allowed; only the privileged `card*` DRM node is refused.
fn is_dangerous_dev(real: &std::path::Path) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    // IDENTITY-based deny (major/minor), not name — a char node's major/minor is its REAL kernel
    // identity; the name is only a udev label. This catches a dangerous node hidden behind an innocent
    // name: a `/dev/i2c-x` that is actually `1:1` (/dev/mem) or major 21 (SCSI generic) would pass the
    // name checks below but is refused here. Block devices are identity-checked too (a disk named like
    // a peripheral is still a disk). (A pure allowlist-by-major isn't viable — gpiochip/rtc have DYNAMIC
    // majors — so identity DENY of the fixed-major raw primitives is the robust part; the name/path
    // layer covers the dynamic-major dangerous nodes.)
    if let Ok(md) = std::fs::metadata(real) {
        let ft = md.file_type();
        if ft.is_block_device() {
            return true; // (1) host storage — by identity, so a disk named like a peripheral is caught
        }
        if ft.is_char_device() {
            let rdev = md.rdev();
            let (maj, min) = (libc::major(rdev), libc::minor(rdev));
            if maj == 1 && matches!(min, 1 | 2 | 4 | 11 | 12) {
                return true; // mem, kmem, port, kmsg, oldmem (12) — raw memory / I/O ports
            }
            if maj == 21 {
                return true; // /dev/sg* — SCSI generic (raw disk via SG_IO), regardless of its name
            }
        }
    }
    let name = real.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let parent = real
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("");
    // NAME/prefix layer — belt-and-braces over the identity check, and the ONLY guard for the
    // dynamic-major dangerous nodes (their major isn't fixed, so identity-by-major can't catch them).
    // (2) raw memory + oldmem · (2b) DAX direct-access · (4) nvram · (5) kvm · (6) uinput/uhid ·
    //     (7) tun/ppp · (9) fuse · (3) udmabuf · storage/dm/loop CONTROL · (12) host console/VC
    //     (TIOCSTI keystroke injection): console + tty0..N (VCs) + vcs\* · (13) cuse (register a host cdev).
    if matches!(
        name,
        "mem"
            | "kmem"
            | "port"
            | "kmsg"
            | "oldmem"
            | "fmem"
            | "mergemem"
            | "nvram"
            | "kvm"
            | "uinput"
            | "uhid"
            | "tun"
            | "ppp"
            | "fuse"
            | "udmabuf"
            | "loop-control"
            | "btrfs-control"
            | "console"
            | "cuse"
    ) {
        return true;
    }
    // family prefixes: (4) reboot/brick · (5) vhost-net/vsock/vdpa + vbox* · (6) HID injection
    // (hidraw + hiddev) · (11) mei · (2b) dax\* · storage: NVMe char (nvme0 controller, nvme-generic,
    // nvme-fabrics — all admin/control; the nvme0n1 block namespace is caught by the identity check).
    if [
        "watchdog", "mtd", "vhost", "vbox", "hidraw", "hiddev", "mei", "dax", "nvme", "vcs",
    ]
    .iter()
    .any(|p| name.starts_with(p))
    {
        return true; // …+ vcs\*/vcsa\* (virtual-console memory — read the host console back)
    }
    // SCSI-generic (`sg0`) and the VIRTUAL CONSOLES (`tty0..N`) by stem+digits — `sgx_enclave`,
    // `ttyS0`/`ttyUSB0`/`ttyACM0` (real serial) keep a non-digit tail and are NOT matched.
    let stem_digits = |stem: &str| {
        name.strip_prefix(stem)
            .is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit()))
    };
    if stem_digits("sg") || stem_digits("tty") {
        return true;
    }
    // path-ancestor families: (3) VFIO — ALL layouts incl. the 6.x cdev node /dev/vfio/devices/vfioN ·
    // block-SCSI-generic /dev/bsg/* · device-mapper control /dev/mapper/control (a real /dev/mapper LV
    // canonicalizes to /dev/dm-N, a block device, and is caught above).
    if real.to_str().is_some_and(|s| {
        ["/vfio/", "/bsg/", "/mapper/"]
            .iter()
            .any(|p| s.contains(p))
    }) {
        return true;
    }
    // (10) raw USB: refuse the whole-BUS reach (/dev/bus/usb, or /dev/bus/usb/<bus> which reaches EVERY
    // device on it — BadUSB), but ALLOW a SPECIFIC device node /dev/bus/usb/<bus>/<dev>: that's a scoped
    // libusb passthrough of the one device the user chose (DFU flashing, an SDR, a programmer), no
    // different in kind from handing over /dev/ttyUSB0. Depth 2 (bus/dev) = a device; fewer = a bus.
    if let Some(rest) = real.to_str().and_then(|s| s.strip_prefix("/dev/bus/usb")) {
        let depth = rest.split('/').filter(|c| !c.is_empty()).count();
        if depth < 2 {
            return true;
        }
    }
    // (8) the privileged DRM node (modeset); the render-only node renderD* stays allowed.
    parent == "dri" && name.starts_with("card")
}

/// A `/dev` node kind that vGPIO *recognizes* as a plain peripheral. Anything under `/dev/` that is
/// neither dangerous nor recognized still binds (via `extra`), but with a heads-up — so a beginner who
/// lands there by accident is told, while the expert escape hatch stays open.
fn is_recognized_dev(real: &std::path::Path) -> bool {
    let name = real.file_name().and_then(|n| n.to_str()).unwrap_or("");
    // buses / serial / gpio / sensors
    for p in [
        "i2c-", "spidev", "ttyS", "ttyUSB", "ttyACM", "ttyAMA", "gpiochip", "can", "video",
        "media", "vchiq", "rtc", "input",
    ] {
        if name.starts_with(p) {
            return true;
        }
    }
    // camera/audio/dri/input live in subdirs — match on the parent directory instead
    let parent = real
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("");
    matches!(parent, "snd" | "dri" | "input" | "i2c")
}

/// The `/dev/*`-path fields of a vGPIO profile (everything except pins/pwm/adc/onewire/leds/net,
/// which map to gpiochips or sysfs). Matches the private's `device_paths()`. An `i2c` entry may be a
/// bare bus number (`"1"`) or `"i2c-1"` — both normalise to `/dev/i2c-1` — or a full `/dev/…` path;
/// the other buses are taken as `/dev/*` paths verbatim.
fn vgpio_device_paths(e: &VGpioEntry) -> Vec<String> {
    let i2c = e.i2c.iter().filter_map(|s| {
        // A full path is taken verbatim — the `canonicalize` + `starts_with("/dev/")` gate at the call
        // site is the confinement check. A NON-path entry must be a plain bus NUMBER (all-digits
        // validated inside `canon_i2c_bus` before the path is built).
        if s.starts_with('/') {
            return Some(s.clone());
        }
        canon_i2c_bus(s).or_else(|| {
            eprintln!(
                "kern: vgpio i2c entry {s:?} is not a bus number (e.g. \"1\", \"i2c-1\") or a /dev/ path — skipped"
            );
            None
        })
    });
    let rest = [
        &e.spi,
        &e.uart,
        &e.can,
        &e.camera,
        &e.audio,
        &e.bluetooth,
        &e.usb,
        &e.input,
        &e.midi,
        &e.display,
        &e.extra,
    ]
    .into_iter()
    .flatten()
    .cloned();
    i2c.chain(rest).collect()
}

/// A resolved `[[vdisk]]` profile: a size-capped volume the box mounts at `/vdisk/<name>`. The
/// `size` cap is enforced rootless by a `tmpfs size=` mount (RAM-backed, ephemeral); when kern runs
/// privileged with loop devices available it is upgraded to an ext4-on-loop image (disk-backed,
/// `persistent`, `iops`/`bandwidth`-limited) — mirroring the private runtime.
#[derive(Debug, Default, PartialEq)]
pub struct ResolvedVdisk {
    pub name: String,
    /// Size cap in bytes (`size = "2g"`). `None` = uncapped (a plain writable scratch dir).
    pub size: Option<u64>,
    /// I/O limits (ext4-loop backend only): ops/s and bytes/s. `None` = unlimited.
    pub iops: Option<u64>,
    pub bandwidth: Option<u64>,
    /// Keep the backing image across box removals (ext4-loop backend only).
    pub persistent: bool,
    /// Host directory the ext4 image lives in (from the `[[disk]]` backend, or a default). Unused by
    /// the tmpfs fallback.
    pub backend_dir: Option<String>,
}

/// Resolve a `[[vdisk]]` entry to concrete values. `backend = "disk:<name>"` (or a bare `[[disk]]`
/// name) selects the physical disk pool the ext4 image is placed on; unknown/absent → a default is
/// chosen at mount time.
pub fn resolve_vdisk(cfg: &KernConfig, name: &str) -> Result<ResolvedVdisk, String> {
    let e = cfg
        .vdisk
        .iter()
        .find(|e| e.name == name)
        .ok_or_else(|| format!("no [[vdisk]] profile named '{name}' in kern.toml"))?;
    validate_profile_name(&e.name).map_err(|m| format!("[[vdisk]] '{name}': {m}"))?;
    let size = match &e.size {
        Some(s) => {
            Some(size_to_bytes(s).ok_or_else(|| format!("bad size '{s}' in [[vdisk]] '{name}'"))?)
        }
        None => None,
    };
    let bandwidth = match &e.bandwidth {
        Some(b) => Some(
            size_to_bytes(b).ok_or_else(|| format!("bad bandwidth '{b}' in [[vdisk]] '{name}'"))?,
        ),
        None => None,
    };
    // Resolve the backend to a host directory: `disk:<name>` or a bare name → the [[disk]]'s path.
    let want = e.backend.strip_prefix("disk:").unwrap_or(&e.backend);
    let backend_dir = cfg
        .disk
        .iter()
        .find(|d| d.name == want)
        .filter(|_| !e.backend.is_empty())
        .map(|d| d.path.clone());
    Ok(ResolvedVdisk {
        name: e.name.clone(),
        size,
        iops: e.iops,
        bandwidth,
        persistent: e.persistent,
        backend_dir,
    })
}

/// The cpulist of a NUMA node (`/sys/devices/system/node/node<N>/cpulist`), trimmed.
fn numa_cpulist(node: i32) -> Option<String> {
    std::fs::read_to_string(format!("/sys/devices/system/node/node{node}/cpulist"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Parse a memory/disk size for the profile schema: binary units up to terabytes, tolerant of a space
/// and a trailing `b` (`"2g"`, `"512m"`, `"16 GB"`, `"16t"`, or bare bytes). The shared
/// [`kern_common::parse_binary_size`] — one definition for the whole tree.
pub(crate) fn size_to_bytes(s: &str) -> Option<u64> {
    kern_common::parse_binary_size(s)
}

// ═══════════════════ profile field validation + emission (the shared schema) ═══════════════════
//
// ONE source of truth for what a profile field may hold and how it's written back to kern.toml —
// used by BOTH `kern top`'s forms AND `kern config add`, and (for the semantic ranges) by the
// resolve path. So the TUI, the CLI and a hand-edited file all agree on what is valid, and the TUI
// can never save a value the loader would later reject.

/// A generous ceiling for a GPIO line number. Real controllers expose far fewer lines; this only
/// rejects nonsense like `70000` while staying board-agnostic.
pub(crate) const MAX_GPIO_PIN: u32 = 1024;

/// A profile / vdisk name usable as a `kind:name` attach token: letters, digits, `_ - .` — no `:`
/// (it would split the token) and no path separators. Enforced by the TUI form, `kern config add`
/// AND the resolve path, so all three agree.
pub(crate) fn validate_profile_name(name: &str) -> Result<(), String> {
    // Keep the specific empty/length messages (better UX in the TUI form), delegate the charset +
    // traversal + leading-char rule to the shared [`kern_common::valid_resource_name`] so a profile/
    // vdisk name obeys exactly the same rule as a volume/secret/pod name. In particular `..` is
    // rejected so `vdisk:..` fails at create-time (a persistent vdisk interpolates the name into an
    // image path) — no "created ok" then "fails".
    if name.is_empty() {
        return Err("name is required".into());
    }
    if name.chars().count() > 64 {
        return Err("name: 64 characters max".into());
    }
    if kern_common::valid_resource_name(name) {
        Ok(())
    } else {
        Err("name: letters, digits, _ - . only, no leading '-'/'.' or '..' (no ':' or '/')".into())
    }
}

/// `memory` / `size` must parse as a size (`512m`, `2g`, `16 GB`).
pub(crate) fn check_size(field: &str, v: &str) -> Result<(), String> {
    if size_to_bytes(v).is_some() {
        Ok(())
    } else {
        Err(format!("{field}: not a size — e.g. 512m, 2g, 1g"))
    }
}

/// A cpuset list like `0-3,7`: each token is `N` or `A-B` with `A <= B`. The single rule shared by
/// the `--cpuset-cpus` flag, the profile forms and `kern config add`.
pub(crate) fn is_cpu_list(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.split(',').all(|tok| match tok.split_once('-') {
        Some((lo, hi)) => {
            matches!((lo.parse::<u32>(), hi.parse::<u32>()), (Ok(lo), Ok(hi)) if lo <= hi)
        }
        None => tok.parse::<u32>().is_ok(),
    })
}

/// A cpuset value for a profile (`cpus`), with a message for the forms/CLI.
pub(crate) fn check_cpus(v: &str) -> Result<(), String> {
    if is_cpu_list(v) {
        Ok(())
    } else {
        Err("cpuset: a CPU list like 0-3 or 0,2,4 (start ≤ end)".into())
    }
}

/// GPIO pins within a sane ceiling.
pub(crate) fn check_pins(pins: &[u32]) -> Result<(), String> {
    match pins.iter().find(|&&p| p >= MAX_GPIO_PIN) {
        Some(p) => Err(format!("pins: {p} out of range (0-{})", MAX_GPIO_PIN - 1)),
        None => Ok(()),
    }
}

/// Parse a lenient boolean (`true`/`yes`/`y`/`on`/`1` → true; the negatives → false).
pub(crate) fn parse_bool(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "y" | "on" | "1" => Some(true),
        "false" | "no" | "n" | "off" | "0" => Some(false),
        _ => None,
    }
}

/// TOML-quote a basic string, escaping `\`, `"` and every control character (defence in depth
/// against a value that would break the string or splice in a new key).
pub(crate) fn toml_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// EVERY field a given profile kind accepts — `kern config add` exposes all of them, so there is no
/// field you can only reach by hand-editing. `name` is handled separately. (The `kern top` form shows
/// the common subset for a friendly UX, but the field-surgical merge means it never drops the rest.)
pub(crate) fn profile_fields(kind: &str) -> &'static [&'static str] {
    match kind {
        "vcpu" => &[
            "cpus", "cpuset", "memory", "numa", "nice", "backend", "extends",
        ],
        "vgpio" => &[
            "backend",
            "pins",
            "pwm",
            "adc",
            "onewire",
            "i2c",
            "spi",
            "uart",
            "can",
            "camera",
            "audio",
            "leds",
            "bluetooth",
            "usb",
            "input",
            "midi",
            "display",
            "net",
            "extra",
        ],
        "vdisk" => &["size", "persistent", "backend", "iops", "bandwidth"],
        _ => &[],
    }
}

/// The comma/space-separated GPIO-line lists (emitted as `[1, 2]`); everything else on a vgpio that is
/// a *list of strings* (`/dev` paths or names) is emitted as `["a", "b"]`.
const U32_LIST_FIELDS: &[&str] = &["pins", "pwm", "adc", "onewire"];
const STR_LIST_FIELDS: &[&str] = &[
    "i2c",
    "spi",
    "uart",
    "can",
    "camera",
    "audio",
    "leds",
    "bluetooth",
    "usb",
    "input",
    "midi",
    "display",
    "net",
    "extra",
];

/// `list` holds `&'static str` while `key` is a borrowed `&str`, so `.contains(&key)` won't typecheck.
#[allow(clippy::manual_contains)]
fn field_in(list: &[&str], key: &str) -> bool {
    list.iter().any(|f| *f == key)
}

/// Validate + format one profile field as a `key = value` TOML line. `None` = nothing to emit (an
/// empty optional, or `persistent = false`). The single emitter for vcpu/vgpio/vdisk fields.
pub(crate) fn profile_line(key: &str, raw: &str) -> Result<Option<String>, String> {
    let v = raw.trim();
    if v.is_empty() {
        return Ok(None);
    }
    if field_in(U32_LIST_FIELDS, key) {
        let mut nums = Vec::new();
        for p in v.split([',', ' ']).map(str::trim).filter(|s| !s.is_empty()) {
            nums.push(
                p.parse::<u32>()
                    .map_err(|_| format!("{key}: comma-separated numbers — e.g. 17,27"))?,
            );
        }
        // pin/pwm/adc/onewire are all line indices → same range guard, but name the actual field.
        if let Some(&p) = nums.iter().find(|&&p| p >= MAX_GPIO_PIN) {
            return Err(format!("{key}: {p} out of range (0-{})", MAX_GPIO_PIN - 1));
        }
        let joined = nums
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        return Ok(Some(format!("{key} = [{joined}]")));
    }
    if field_in(STR_LIST_FIELDS, key) {
        let trimmed: Vec<&str> = v
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        // `extra` is the /dev-path escape — each entry MUST be a `/dev/…` path (not free text), so the
        // CLI and a hand-edited file reject garbage exactly as the TUI live filter does (one rule). The
        // resolver still does the existence/safety check at launch.
        if key == "extra" {
            for t in &trimmed {
                if !is_dev_path(t) {
                    return Err(format!("extra: {t:?} is not a /dev/… path"));
                }
            }
        }
        // `i2c` accepts a bus NUMBER (`1`, `i2c-1`) or a full `/dev/…` path — reject anything else at
        // SAVE (e.g. `1/../spi0`), matching the resolver's all-digits `canon_i2c_bus` guard, so a
        // malformed bus can't be stored to silently do nothing at launch.
        if key == "i2c" {
            for t in &trimmed {
                if canon_i2c_bus(t).is_none() && !is_dev_path(t) {
                    return Err(format!(
                        "i2c: {t:?} — a bus number (e.g. 1, i2c-1) or a /dev/… path"
                    ));
                }
            }
        }
        if trimmed.is_empty() {
            return Ok(None);
        }
        let items: Vec<String> = trimmed.into_iter().map(toml_quote).collect();
        return Ok(Some(format!("{key} = [{}]", items.join(", "))));
    }
    let line = match key {
        // CPU *quota* — like `--cpus` (fractional cores → cgroup cpu.max).
        "cpus" => {
            let n: f64 = v.parse().map_err(|_| "cpus: a number — e.g. 4 or 0.5")?;
            // `!is_finite()` rejects both `nan` and `inf` (which would write a nonsense `cpus = inf`).
            if !n.is_finite() || n <= 0.0 {
                return Err("cpus: must be a finite number greater than 0".into());
            }
            format!("cpus = {}", crate::ui::fmt_cpus(n))
        }
        // CPU *pinning* — like `--cpuset-cpus` (a cpulist: `0-3`, `0,2,4`).
        "cpuset" => {
            check_cpus(v)?;
            format!("cpuset = {}", toml_quote(v))
        }
        "memory" | "size" | "bandwidth" => {
            check_size(key, v)?;
            format!("{key} = {}", toml_quote(v))
        }
        // Free string refs (`gpio:0`, `disk:0`) — quoted as-is (colons are legal here).
        "backend" => format!("backend = {}", toml_quote(v)),
        // `extends` names another profile, so it obeys the profile-name charset.
        "extends" => {
            validate_profile_name(v).map_err(|m| format!("extends: {m}"))?;
            format!("extends = {}", toml_quote(v))
        }
        "numa" => {
            let n: i32 = v.parse().map_err(|_| "numa: a node number (0, 1, …)")?;
            if n < 0 {
                return Err("numa: node must be ≥ 0".into());
            }
            format!("numa = {n}")
        }
        "nice" => {
            let n: i32 = v.parse().map_err(|_| "nice: a number -20..19")?;
            if !(-20..=19).contains(&n) {
                return Err("nice: must be between -20 and 19".into());
            }
            format!("nice = {n}")
        }
        "iops" => {
            let n: u64 = v.parse().map_err(|_| "iops: a whole number of ops/s")?;
            format!("iops = {n}")
        }
        "persistent" => match parse_bool(v) {
            Some(true) => "persistent = true".to_string(),
            Some(false) => return Ok(None),
            None => return Err("persistent: yes or no".into()),
        },
        _ => return Ok(None),
    };
    Ok(Some(line))
}

/// The live-validation state of a field value, so the TUI can accept/reject a keystroke and show a
/// three-state hint. It is DERIVED from [`profile_line`] (the save-time authority) so live and save
/// can never diverge — the class of bug behind the "1.5g" dead-end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldState {
    /// A complete, save-acceptable value (`profile_line` would emit it).
    Valid,
    /// A prefix that isn't valid yet but could still become valid — keep typing (`-`, `0`, `0-`, …).
    Incomplete,
    /// No completion can ever be valid — the keystroke that produced it is refused.
    Invalid,
}

/// Classify a field value for LIVE validation using the SAME rule as the save-time `profile_line`:
/// `Valid` ⇔ `profile_line` accepts it. `Incomplete` = a prefix that could still complete (so a
/// keystroke toward it is allowed, and a form can show "keep typing"). `Invalid` = unreachable, the
/// keystroke is refused. ONE source of truth: the range/format lives once, in `profile_line`.
pub(crate) fn field_state(key: &str, v: &str) -> FieldState {
    use FieldState::*;
    if v.is_empty() {
        return Incomplete;
    }
    // `name`/`extends` are validated by `validate_profile_name`, not `profile_line` — but route them
    // through the SAME dispatcher so they get the live three-state indicator and can't drift from the
    // save rule (the bug that would otherwise re-open the two-implementations risk for names). A name
    // prefix is either a valid name or has an unfixable problem (bad leading char, `..`, too long),
    // so there's no incomplete middle state beyond empty.
    if matches!(key, "name" | "extends") {
        return if validate_profile_name(v).is_ok() {
            Valid
        } else {
            Invalid
        };
    }
    // `extra` is the /dev-path escape — but it's still a `/dev/…` path, not free text. Each comma token
    // must be a valid `/dev/…` path (shared `is_dev_path`, the same rule the save uses) or a prefix of
    // `/dev/` mid-typing; a first non-`/` char (`rftre…`) is refused. The resolver does the real
    // existence/safety check at launch.
    if key == "extra" {
        for tok in v.split(',') {
            if !is_dev_path(tok) && !"/dev/".starts_with(tok) {
                return Invalid;
            }
        }
        return if is_dev_path(v.rsplit(',').next().unwrap_or("")) {
            Valid
        } else {
            Incomplete // last token still being typed (`/de…`, a trailing comma)
        };
    }
    if let Ok(opt) = profile_line(key, v) {
        // Ok(None) = a value profile_line legitimately omits (e.g. `persistent = no`); still editable.
        return if opt.is_some() { Valid } else { Incomplete };
    }
    // profile_line rejected the COMPLETE value — but is it a prefix that a further keystroke can fix?
    let could_complete = match key {
        // a lone minus is the start of a negative nice value
        "nice" => v == "-",
        // a float prefix (`0`, `0.`, `1.`) can still reach a valid cpus quota like `0.5`
        "cpus" => {
            v.bytes().filter(|b| *b == b'.').count() <= 1
                && v.chars().all(|c| c.is_ascii_digit() || c == '.')
        }
        // a partial cpulist (`0-`, `0,`) can still reach a valid cpuset. Match `is_cpu_list`'s shape with
        // NO upper bound (it has none — a portable profile may pin a high core, host-fit is launch-time),
        // so a Valid value like `5000-9000` isn't blocked mid-typing at the `-`.
        "cpuset" => v.split(',').all(|t| {
            let parts: Vec<&str> = t.split('-').collect();
            parts.len() <= 2
                && parts
                    .iter()
                    .all(|p| p.is_empty() || p.parse::<u32>().is_ok())
        }),
        _ => false, // pins/priority/size/… : an out-of-range or malformed complete value can't be fixed
    };
    if could_complete {
        Incomplete
    } else {
        Invalid
    }
}

/// Build the body lines of a `[[section]]` block from `(key, value)` pairs, validating each. The
/// leading `name = "…"` is always first. Shared by the TUI forms and `kern config add`.
pub(crate) fn profile_block(name: &str, pairs: &[(&str, &str)]) -> Result<Vec<String>, String> {
    validate_profile_name(name)?;
    let mut body = vec![format!("name = {}", toml_quote(name))];
    for (k, v) in pairs {
        if let Some(line) = profile_line(k, v)? {
            body.push(line);
        }
    }
    Ok(body)
}

/// EVERY set field of an existing profile as `(key, value)` strings (lists comma-joined) — used to
/// pre-fill the `kern top` edit form so it shows and preserves all fields, not a subset. The inverse
/// of [`profile_line`]'s parsing: values here feed straight back through it on save.
pub(crate) fn profile_pairs(cfg: &KernConfig, kind: &str, name: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let u32s = |v: &[u32]| v.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
    match kind {
        "vcpu" => {
            if let Some(e) = cfg.vcpu.iter().find(|e| e.name == name) {
                if let Some(v) = e.cpus {
                    out.push(("cpus".into(), crate::ui::fmt_cpus(v)));
                }
                if let Some(c) = &e.cpuset {
                    out.push(("cpuset".into(), c.clone()));
                }
                if let Some(m) = &e.memory {
                    out.push(("memory".into(), m.clone()));
                }
                if let Some(n) = e.numa {
                    out.push(("numa".into(), n.to_string()));
                }
                if e.nice != 0 {
                    out.push(("nice".into(), e.nice.to_string()));
                }
                if let Some(b) = &e.backend {
                    out.push(("backend".into(), b.clone()));
                }
                if let Some(x) = &e.extends {
                    out.push(("extends".into(), x.clone()));
                }
            }
        }
        "vgpio" => {
            if let Some(e) = cfg.vgpio.iter().find(|e| e.name == name) {
                if !e.backend.is_empty() {
                    out.push(("backend".into(), e.backend.clone()));
                }
                for (k, v) in [
                    ("pins", &e.pins),
                    ("pwm", &e.pwm),
                    ("adc", &e.adc),
                    ("onewire", &e.onewire),
                ] {
                    if !v.is_empty() {
                        out.push((k.into(), u32s(v)));
                    }
                }
                for (k, v) in [
                    ("i2c", &e.i2c),
                    ("spi", &e.spi),
                    ("uart", &e.uart),
                    ("can", &e.can),
                    ("camera", &e.camera),
                    ("audio", &e.audio),
                    ("leds", &e.leds),
                    ("bluetooth", &e.bluetooth),
                    ("usb", &e.usb),
                    ("input", &e.input),
                    ("midi", &e.midi),
                    ("display", &e.display),
                    ("net", &e.net),
                    ("extra", &e.extra),
                ] {
                    if !v.is_empty() {
                        out.push((k.into(), v.join(",")));
                    }
                }
            }
        }
        "vdisk" => {
            if let Some(e) = cfg.vdisk.iter().find(|e| e.name == name) {
                if let Some(s) = &e.size {
                    out.push(("size".into(), s.clone()));
                }
                if e.persistent {
                    out.push(("persistent".into(), "true".into()));
                }
                if !e.backend.is_empty() {
                    out.push(("backend".into(), e.backend.clone()));
                }
                if let Some(i) = e.iops {
                    out.push(("iops".into(), i.to_string()));
                }
                if let Some(b) = &e.bandwidth {
                    out.push(("bandwidth".into(), b.clone()));
                }
            }
        }
        _ => {}
    }
    out
}

/// Take an exclusive advisory lock for the whole read-modify-write of `kern.toml`, held until the
/// returned handle drops. Concurrent `config add`/`rm` (and the TUI) would otherwise each read the
/// same base, splice their own block, and write — last-writer-wins, silently losing the others'
/// edits. A SEPARATE lock file (stable inode; kern.toml itself is replaced by rename) serialises
/// them. Fail-open: if the lock can't be taken (e.g. a filesystem without `flock`), proceed unlocked.
fn config_lock() -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::io::AsRawFd as _;
    let path = default_path()?;
    let parent = path.parent()?;
    let _ = std::fs::create_dir_all(parent);
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(parent.join(".kern-config.lock"))
        .ok()?;
    // Blocking exclusive lock; released automatically when `f` is dropped/closed.
    (unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } == 0).then_some(f)
}

/// The default `kern.toml` path + its current contents (empty when absent), ensuring the parent dir
/// exists so a later write succeeds.
pub(crate) fn read_kern_toml() -> Result<(std::path::PathBuf, String), String> {
    let path = default_path().ok_or("no config path (is HOME set?)")?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let raw = std::fs::read_to_string(&path).unwrap_or_default();
    Ok((path, raw))
}

/// Atomic, private, symlink-safe write of `kern.toml`: a per-pid temp opened with `O_CREAT|O_EXCL`
/// (never follows a planted symlink), mode `0600`, `fsync`ed before the rename so the swapped-in file
/// is never a partial write.
pub(crate) fn write_atomic(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let tmp = path.with_extension(format!("toml.tmp.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp); // clear a temp left by our own crashed write
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let res = f.write_all(content.as_bytes()).and_then(|()| f.sync_all());
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    drop(f);
    std::fs::rename(&tmp, path)
}

/// Splice a profile block into `kern.toml`. `managed` is the set of keys THIS caller controls (the
/// form's fields, or the CLI flags actually passed) — a field-surgical merge replaces exactly those,
/// keeps every other key already in the block (a hand-added `numa`/`i2c`, another surface's fields),
/// and a managed key omitted from `body` is cleared. So a partial edit never drops what it didn't
/// touch, whichever surface made it. The read-modify-write is serialised by [`config_lock`] so
/// concurrent writers don't clobber each other.
/// Whole-profile validation, AFTER each field is individually valid: a profile can be field-valid yet
/// reference something that doesn't exist. Checks the internal, save-time coherence a single field
/// can't (a `backend`/`extends` that points at no configured `[[cpu]]`/`[[gpio]]`/`[[disk]]`/profile).
/// Host-fit checks (e.g. `cpus` ≤ this host's cores) are LAUNCH-time and live in the resolver — a
/// profile is portable, so `cpuset = "0-7"` is legal to author on a 4-core box for an 8-core target.
pub(crate) fn validate_profile_refs(
    cfg: &KernConfig,
    section: &str,
    name: &str,
) -> Result<(), String> {
    match section {
        "vcpu" => {
            if let Some(e) = cfg.vcpu.iter().find(|e| e.name == name) {
                if let Some(b) = e.backend.as_deref().filter(|b| !b.is_empty()) {
                    if !cfg
                        .cpu
                        .iter()
                        .any(|c| backend_ref_matches(b, "cpu:", &c.id))
                    {
                        return Err(format!("backend '{b}' is not a configured [[cpu]] id"));
                    }
                }
                if let Some(x) = e.extends.as_deref().filter(|x| !x.is_empty()) {
                    if !cfg.vcpu.iter().any(|v| v.name == x) {
                        return Err(format!("extends '{x}' is not another vcpu profile"));
                    }
                }
            }
        }
        "vgpio" => {
            if let Some(e) = cfg.vgpio.iter().find(|e| e.name == name) {
                if !e.backend.is_empty()
                    && !cfg
                        .gpio
                        .iter()
                        .any(|g| backend_ref_matches(&e.backend, "gpio:", &g.id))
                {
                    return Err(format!(
                        "backend '{}' is not a configured [[gpio]] id (run: kern config setup)",
                        e.backend
                    ));
                }
            }
        }
        "vdisk" => {
            if let Some(e) = cfg.vdisk.iter().find(|e| e.name == name) {
                if !e.backend.is_empty()
                    && !cfg
                        .disk
                        .iter()
                        .any(|d| backend_ref_matches(&e.backend, "disk:", &d.name))
                {
                    return Err(format!(
                        "backend '{}' is not a configured [[disk]]",
                        e.backend
                    ));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// Match a `backend = "kind:name"` reference against a declared `[[cpu]]`/`[[gpio]]`/`[[disk]]`
/// id/name, tolerating the optional `kind:` prefix on EITHER side. The docs show `[[cpu]] id = "0"`
/// while the shipped example bakes in `id = "cpu:0"`, and a user may write `backend = "cpu:0"` or a
/// bare `backend = "0"` — all of these resolve, so the same-looking token means the same thing across
/// every kind (previously cpu/gpio needed a literal match and only disk stripped the prefix).
fn backend_ref_matches(reference: &str, prefix: &str, declared: &str) -> bool {
    reference.strip_prefix(prefix).unwrap_or(reference)
        == declared.strip_prefix(prefix).unwrap_or(declared)
}

pub(crate) fn save_named_block(
    section: &str,
    orig_name: Option<&str>,
    name: &str,
    managed: &[&str],
    body: &[String],
) -> Result<(), String> {
    let _lock = config_lock(); // held until this function returns
    let (path, raw) = read_kern_toml()?;
    if orig_name != Some(name) && crate::toml_surgery::block_exists(&raw, section, name) {
        return Err(format!("a {section} named '{name}' already exists"));
    }
    // For a rename, the OLD block is rewritten in place under the new name (carrying its other keys).
    let source = orig_name.unwrap_or(name);
    let out = crate::toml_surgery::upsert_block_merge(&raw, section, source, name, managed, body);
    // FAIL-CLOSED: never write a config we can't re-parse. If the merged output doesn't parse, writing
    // it would CORRUPT kern.toml (the next load/launch fails to read ANYTHING) — worse than the
    // pre-existing problem. Refuse instead, and tell the user their file needs fixing first.
    let cfg = parse(&out).map_err(|e| {
        format!("refusing to write: the resulting kern.toml would not parse ({e}) — your existing config may be malformed; fix it first")
    })?;
    // Whole-profile coherence: a field-valid profile whose backend/extends points at nothing is refused
    // here, before the write — so a save never produces a broken profile.
    validate_profile_refs(&cfg, section, name)?;
    write_atomic(&path, &out).map_err(|e| format!("writing {}: {e}", path.display()))
}

/// Remove a named `[[section]]` block from `kern.toml` (used by `kern config rm` and the TUI). Errors
/// when the block isn't there, so the caller can report a clean "no such profile".
pub(crate) fn delete_named_block(section: &str, name: &str) -> Result<(), String> {
    let _lock = config_lock(); // serialise with concurrent add/rm
    let (path, raw) = read_kern_toml()?;
    if !crate::toml_surgery::block_exists(&raw, section, name) {
        return Err(format!("no {section} profile named '{name}'"));
    }
    let out = crate::toml_surgery::delete_block(&raw, section, name);
    write_atomic(&path, &out).map_err(|e| format!("writing {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"
        [kern]
        config_version = 1
        log_level = "debug"

        [[cpu]]
        id = "cpu:0"
        cores = 8.0

        [[vcpu]]
        name = "heavy"
        backend = "cpu:0"
        cpus = 4.0
        cpuset = "0-3"
        memory = "2g"
        nice = -5

        [[gpio]]
        id = "gpio:0"
        pins = [17, 27, 22]
        i2c = ["1"]
        [[gpio.usb_ports]]
        bus = 1
        port = 2
        name = "sensor"

        [[vgpio]]
        name = "leds"
        backend = "gpio:0"
        leds = ["led0", "led1"]
        pins = [17]

        [[vdisk]]
        name = "data"
        backend = "disk:0"
        size = "2g"
        persistent = true
    "#;

    #[test]
    fn parses_the_resource_centric_schema() {
        let c = parse(DOC).unwrap();
        assert_eq!(c.kern.config_version, Some(1));
        assert_eq!(c.kern.log_level.as_deref(), Some("debug"));
        assert_eq!(c.cpu[0].id, "cpu:0");
        assert_eq!(c.cpu[0].cores, Some(8.0));
        let v = &c.vcpu[0];
        assert_eq!(v.name, "heavy");
        assert_eq!(v.backend.as_deref(), Some("cpu:0"));
        assert_eq!(v.cpus, Some(4.0));
        assert_eq!(v.cpuset.as_deref(), Some("0-3"));
        assert_eq!(v.nice, -5);
        assert_eq!(c.gpio[0].pins, [17, 27, 22]);
        assert_eq!(c.gpio[0].i2c, ["1"]);
        assert_eq!(c.gpio[0].usb_ports[0].bus, 1);
        assert_eq!(c.gpio[0].usb_ports[0].name.as_deref(), Some("sensor"));
        assert_eq!(c.vgpio[0].name, "leds");
        assert_eq!(c.vgpio[0].leds, ["led0", "led1"]);
        assert_eq!(c.vdisk[0].size.as_deref(), Some("2g"));
        assert!(c.vdisk[0].persistent);
    }

    #[test]
    fn unimplemented_sections_load_leniently() {
        // A shared kern.toml that also targets the private runtime (with a [[vgpu]] section) still
        // parses — the unimplemented section and its keys are ignored, not errored, so the file's
        // implemented profiles (e.g. [[vcpu]]) load normally. Nothing about it is surfaced.
        let c = parse(
            "[[vgpu]]\nname = \"gaming\"\nvram = \"4g\"\ncompute = 0.5\n[[vcpu]]\nname = \"x\"",
        )
        .unwrap();
        assert_eq!(c.vcpu[0].name, "x");
    }

    #[test]
    fn tolerant_of_unknown_keys_sections_and_stray_syntax() {
        // Forward/cross-version compat: an unknown key, an unknown section, a key before any section,
        // and TOML this hand-rolled reader doesn't model are all IGNORED (not errors) — so a kern.toml
        // shared with another edition still loads.
        assert!(parse("[[vcpu]]\nname = \"x\"\nbogus = 1").is_ok());
        assert!(parse("[nope]\nx = 1").is_ok());
        assert!(parse("x = 1").is_ok());
        // A multi-line array of inline tables (how the private writes usb_ports) — skipped, not fatal.
        assert!(
            parse("[[gpio]]\nusb_ports = [\n  {bus=1, port=9},\n]\n[[vcpu]]\nname=\"y\"").is_ok()
        );
        // The implemented profile still loads despite the ignored noise around it.
        let c = parse("[nope]\nx=1\n[[vcpu]]\nname=\"ok\"\nbogus=2").unwrap();
        assert_eq!(c.vcpu[0].name, "ok");
        // A BAD VALUE for a RECOGNIZED key is still a real error — tolerance ignores unknowns, it does
        // not swallow malformed values of keys we do implement.
        assert!(parse("[[vcpu]]\nname = \"x\"\ncpus = abc").is_err());
    }

    #[test]
    fn legacy_renamed_cpu_keys_are_rejected_not_silently_ignored() {
        // The renamed keys must NOT fall through the unknown-key tolerance (that would drop/misread a
        // resource limit in silence). They error with a migration hint pointing at the new spelling.
        let e = parse("[[vcpu]]\nname = \"x\"\nvcpus = 4").unwrap_err();
        assert!(
            e.contains("cpus"),
            "vcpus error should point to 'cpus': {e}"
        );
        assert!(parse("[[vcpu]]\nname = \"x\"\npriority = 80").is_err());
        let ec = parse("[[cpu]]\nid = \"0\"\nvcpus = 8").unwrap_err();
        assert!(
            ec.contains("cores"),
            "[[cpu]] vcpus should point to 'cores': {ec}"
        );
        // `[[cpu]] cpus` was renamed — the hint offers BOTH intents (capacity `cores` / pin `cpuset`),
        // since a new user might mean either.
        let ecc = parse("[[cpu]]\nid = \"0\"\ncpus = \"0-7\"").unwrap_err();
        assert!(
            ecc.contains("cores") && ecc.contains("cpuset"),
            "[[cpu]] cpus hint should mention both cores and cpuset: {ecc}"
        );
        // A LEGACY `[[vcpu]]` string pin (`cpus = "0-3"`) can't parse as the new f64 quota → the error
        // points at `cpuset`, not a bare "expected a number". A genuinely bad value stays generic.
        let ep = parse("[[vcpu]]\nname = \"x\"\ncpus = \"0-3\"").unwrap_err();
        assert!(
            ep.contains("cpuset"),
            "legacy vcpu cpus pin should point to 'cpuset': {ep}"
        );
        let eb = parse("[[vcpu]]\nname = \"x\"\ncpus = abc").unwrap_err();
        assert!(
            !eb.contains("cpuset") && eb.contains("number"),
            "a non-cpulist bad quota stays a generic number error: {eb}"
        );
    }

    #[test]
    fn parses_multiline_arrays_for_recognized_keys() {
        // `kern setup -c` writes long device lists as MULTI-LINE arrays (a `[[gpio]]`'s `i2c`/`spi`).
        // The hand-rolled reader must gather the lines up to `]` — it used to error on `= [`, failing
        // the WHOLE config, so a board kern itself set up couldn't load its own profiles (real Jetson).
        let c = parse(
            "[[gpio]]\nid = \"0\"\ni2c = [\n    \"/dev/i2c-0\",\n    \"/dev/i2c-1\",\n    \"/dev/i2c-2\",\n]\n\n[[vcpu]]\nname = \"after\"\ncpus = 1.0",
        )
        .unwrap();
        assert_eq!(c.gpio[0].i2c, ["/dev/i2c-0", "/dev/i2c-1", "/dev/i2c-2"]);
        // ...and parsing CONTINUES past the multi-line array — the profile after it still loads.
        assert_eq!(c.vcpu[0].name, "after");
        assert_eq!(c.vcpu[0].cpus, Some(1.0));
        // A multi-line INT array (pins) works too, with a trailing comma.
        let c2 = parse("[[gpio]]\nid=\"0\"\npins = [\n  1,\n  2,\n  3,\n]").unwrap();
        assert_eq!(c2.gpio[0].pins, [1, 2, 3]);
    }

    #[test]
    fn classify_recognizes_prefixes() {
        assert!(matches!(
            classify("vcpu:heavy"),
            Some(ProfileRef::Vcpu("heavy"))
        ));
        assert!(matches!(
            classify("vgpio:leds"),
            Some(ProfileRef::Vgpio("leds"))
        ));
        assert!(matches!(
            classify("vdisk:data"),
            Some(ProfileRef::Vdisk("data"))
        ));
        // `vgpu:` is NOT a kern-public concept — it is not a profile prefix (GPU is out of this
        // edition), so it classifies as a plain command token, not a reserved profile.
        assert!(classify("vgpu:gaming").is_none());
        assert!(classify("echo").is_none());
        assert!(classify("/bin/ls").is_none());
    }

    #[test]
    fn resolves_vcpu_to_concrete_limits() {
        let c = parse(DOC).unwrap();
        let r = resolve_vcpu(&c, "heavy").unwrap();
        assert_eq!(r.cpus, Some(4.0)); // cpus → quota (= --cpus)
        assert_eq!(r.cpuset.as_deref(), Some("0-3")); // cpuset → pinning (= --cpuset-cpus)
        assert_eq!(r.memory, Some(2 * 1024 * 1024 * 1024)); // "2g"
        assert_eq!(r.nice, Some(-5)); // nice → nice (= --nice)
        assert!(resolve_vcpu(&c, "ghost").is_err());
    }

    #[test]
    fn vcpu_extends_inherits_then_overrides() {
        let doc = "[[vcpu]]\nname = \"base\"\ncpus = 1.0\nmemory = \"1g\"\n\
                   [[vcpu]]\nname = \"big\"\nextends = \"base\"\nmemory = \"4g\"";
        let c = parse(doc).unwrap();
        let r = resolve_vcpu(&c, "big").unwrap();
        assert_eq!(r.cpus, Some(1.0)); // inherited from base
        assert_eq!(r.memory, Some(4 * 1024 * 1024 * 1024)); // overridden
    }

    #[test]
    fn load_precedence_config_then_kern_config_then_default() {
        use std::ffi::OsString;
        let dir = std::env::temp_dir().join(format!("kern-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mk = |n: &str, cpu: &str| {
            let f = dir.join(n);
            std::fs::write(&f, format!("[[vcpu]]\nname=\"p\"\ncpus={cpu}\n")).unwrap();
            f
        };
        let cfg_file = mk("a.toml", "1.0");
        let env_file = mk("b.toml", "2.0");
        let def = Some(mk("d.toml", "3.0"));

        // KERN_CONFIG is honoured when no --config is given (the regression: it was ignored).
        let r = load_impl(None, Some(OsString::from(&env_file)), &def).unwrap();
        assert_eq!(resolve_vcpu(&r, "p").unwrap().cpus, Some(2.0));
        // Explicit --config wins over KERN_CONFIG.
        let r = load_impl(
            Some(cfg_file.to_str().unwrap()),
            Some(OsString::from(&env_file)),
            &def,
        )
        .unwrap();
        assert_eq!(resolve_vcpu(&r, "p").unwrap().cpus, Some(1.0));
        // Neither set → the default location.
        let r = load_impl(None, None, &def).unwrap();
        assert_eq!(resolve_vcpu(&r, "p").unwrap().cpus, Some(3.0));
        // An explicitly-named (KERN_CONFIG) missing file is an error, not a silent empty config.
        assert!(load_impl(None, Some(OsString::from("/no/such/kern.toml")), &def).is_err());
        // A merely-absent default is NOT an error (empty config).
        assert!(load_impl(None, None, &Some(std::path::PathBuf::from("/no/such"))).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vcpu_extends_cycle_errors_not_stack_overflow() {
        // Self-cycle and mutual cycle must be reported, never recurse until the stack overflows.
        let self_c = parse("[[vcpu]]\nname = \"a\"\nextends = \"a\"").unwrap();
        let e = resolve_vcpu(&self_c, "a").unwrap_err();
        assert!(e.contains("cycle"), "got: {e}");
        let mutual = parse(
            "[[vcpu]]\nname = \"a\"\nextends = \"b\"\n[[vcpu]]\nname = \"b\"\nextends = \"a\"",
        )
        .unwrap();
        assert!(resolve_vcpu(&mutual, "a").unwrap_err().contains("cycle"));
    }

    #[test]
    fn size_forms_match_the_private() {
        assert_eq!(size_to_bytes("2g"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(size_to_bytes("16 GB"), Some(16 * 1024 * 1024 * 1024));
        assert_eq!(size_to_bytes("512 MB"), Some(512 * 1024 * 1024));
        assert_eq!(size_to_bytes("1048576"), Some(1048576));
        assert_eq!(size_to_bytes("16t"), Some(16 * 1024 * 1024 * 1024 * 1024));
        assert_eq!(size_to_bytes("nope"), None);
        assert_eq!(size_to_bytes("g"), None); // unit with no number
        assert_eq!(size_to_bytes("0"), None); // zero rejected
        assert_eq!(size_to_bytes("99999999999g"), None); // overflows u64 → rejected
    }

    #[test]
    fn resolve_vgpio_takes_dev_paths_and_rejects_led_traversal() {
        let mut cfg = KernConfig::default();
        cfg.vgpio.push(VGpioEntry {
            name: "t".into(),
            // `/dev/null` exists everywhere and is under /dev — it must be taken.
            i2c: vec!["/dev/null".into()],
            // a device that doesn't exist is silently skipped, not an error.
            spi: vec!["/dev/kern-nope-xyz".into()],
            // a LED name that is a path / traversal must be refused (no host escape via sysfs).
            leds: vec!["../../etc".into(), "bad/name".into()],
            ..Default::default()
        });
        let r = resolve_vgpio(&cfg, "t").unwrap();
        assert!(r.devs.iter().any(|d| d == "/dev/null"), "{:?}", r.devs);
        assert!(
            !r.devs.iter().any(|d| d.contains("kern-nope")),
            "absent device skipped"
        );
        assert!(
            r.sysfs
                .iter()
                .all(|s| !s.contains("..") && !s.contains("etc")),
            "led traversal must not leak into sysfs: {:?}",
            r.sysfs
        );
        assert!(resolve_vgpio(&cfg, "ghost").is_err());
    }

    #[test]
    fn extreme_vgpio_never_binds_a_dangerous_device_via_any_field_or_path_trick() {
        // A battery of host-control / raw devices, some with path tricks (../, ./, double-/dev), fed
        // through `extra` — none may ever reach `devs`, whether present-and-refused or absent-and-skipped.
        let dangerous = [
            "/dev/mem",
            "/dev/kmem",
            "/dev/port",
            "/dev/sda",
            "/dev/sda1",
            "/dev/nvme0n1",
            "/dev/mmcblk0",
            "/dev/dm-0",
            "/dev/loop0",
            "/dev/watchdog",
            "/dev/watchdog0",
            "/dev/mtd0",
            "/dev/mtdblock0",
            "/dev/nvram",
            "/dev/kvm",
            "/dev/vhost-net",
            "/dev/vhost-vsock",
            "/dev/uinput",
            "/dev/vfio/vfio",
            "/dev/vfio/10",
            "/dev/dri/card0",
            "/dev/fuse",
            "/dev/../dev/mem",
            "/dev/./mem",
            "/dev/../dev/sda",
        ];
        let bad = |x: &str| {
            [
                "mem", "sda", "nvme", "mmcblk", "dm-", "loop", "watchdog", "mtd", "nvram", "kvm",
                "vhost", "uinput", "vfio", "/card", "fuse",
            ]
            .iter()
            .any(|k| x.contains(k))
                || x.ends_with("/tun")
        };
        for d in dangerous {
            let mut cfg = KernConfig::default();
            cfg.vgpio.push(VGpioEntry {
                name: "x".into(),
                extra: vec![d.to_string()],
                ..Default::default()
            });
            let r = resolve_vgpio(&cfg, "x").unwrap();
            assert!(
                !r.devs.iter().any(|x| bad(x)),
                "dangerous device {d:?} leaked into devs: {:?}",
                r.devs
            );
        }
    }

    #[test]
    fn extreme_i2c_normalization_rejects_tricks_and_is_the_shared_rule() {
        // The one ambiguous form. All-digits validated BEFORE the path is built, so a traversal can't
        // concatenate; a full path is left to the caller's canonicalize gate; junk is refused.
        assert_eq!(canon_i2c_bus("1"), Some("/dev/i2c-1".into()));
        assert_eq!(canon_i2c_bus("i2c-5"), Some("/dev/i2c-5".into()));
        assert_eq!(canon_i2c_bus("0"), Some("/dev/i2c-0".into()));
        assert_eq!(canon_i2c_bus("/dev/i2c-1"), None); // a full path → caller keeps it verbatim
        assert_eq!(canon_i2c_bus("1/../spi0"), None); // NOT a bus number → refused (no /dev/spi0)
        assert_eq!(canon_i2c_bus("i2c-"), None);
        assert_eq!(canon_i2c_bus(""), None);
        assert_eq!(canon_i2c_bus("abc"), None);
        assert_eq!(canon_i2c_bus("-1"), None);
        assert_eq!(canon_i2c_bus("1a"), None);
        assert_eq!(canon_i2c_bus(" 1"), None); // a space is not a digit
                                               // The SAVE path (profile_line) rejects the same junk the resolver would skip — one rule.
        assert!(profile_line("i2c", "1").unwrap().is_some());
        assert!(profile_line("i2c", "i2c-1").unwrap().is_some());
        assert!(profile_line("i2c", "/dev/i2c-1").unwrap().is_some());
        assert!(profile_line("i2c", "1/../spi0").is_err()); // traversal — refused at save
        assert!(profile_line("i2c", "abc").is_err());
    }

    #[test]
    fn vgpio_refuses_disk_and_raw_memory_devices() {
        // The security boundary: even though they live under /dev/, memory and disk nodes must never be
        // bound into a peripheral sandbox. Name-based denial is deterministic (no metadata needed).
        for dev in [
            "/dev/mem",
            "/dev/kmem",
            "/dev/port",
            "/dev/watchdog",
            "/dev/watchdog0",
            "/dev/mtd0",
            "/dev/nvram",
            "/dev/net/tun",
            "/dev/fuse",
            "/dev/kvm",                // hypervisor
            "/dev/vhost-net",          // VM network backend
            "/dev/vhost-vsock",        // VM vsock backend
            "/dev/uinput",             // input injection
            "/dev/vfio/vfio",          // arbitrary DMA — the worst
            "/dev/vfio/42",            // a vfio group
            "/dev/dri/card0",          // privileged DRM (modeset)
            "/dev/vhost-vdpa",         // vhost family (prefix) — vdpa
            "/dev/vboxdrv",            // VirtualBox hypervisor driver
            "/dev/hidraw0", // raw HID — write injects keystrokes / reprograms (like uinput)
            "/dev/hiddev0", // HID injection (HIDIOCSREPORT)
            "/dev/uhid",    // create a virtual HID device
            "/dev/mei0",    // Intel Management Engine
            "/dev/bus/usb/001", // a whole USB BUS (reaches every device on it — BadUSB)
            "/dev/bus/usb", // the USB bus root
            "/dev/sg0",     // SCSI generic (char) — SG_IO reaches the host disk
            "/dev/nvme0",   // NVMe CONTROLLER (char) — admin cmd formats/reads any namespace
            "/dev/bsg/0:0:0:0", // block-SCSI-generic (char) — SG_IO
            "/dev/mapper/control", // device-mapper control — maps arbitrary host block ranges
            "/dev/loop-control", // create loop devices
            "/dev/ppp",     // create PPP network interfaces
            "/dev/vfio/devices/vfio0", // 6.x VFIO cdev — arbitrary DMA
            "/dev/dax0.0",  // DAX — mmaps physical NVDIMM (raw memory)
            "/dev/udmabuf", // dma-buf from user memory
            "/dev/nvme-generic0", // NVMe admin passthrough (char)
            "/dev/nvme-fabrics", // NVMe-oF connect node (char control)
            "/dev/console", // host console (TIOCSTI keystroke injection)
            "/dev/tty0",    // virtual console 0
            "/dev/tty63",   // a virtual console
            "/dev/vcs1",    // virtual-console memory
            "/dev/vcsa1",   // virtual-console memory (attributes)
            "/dev/oldmem",  // previous kernel's physical RAM (kdump)
            "/dev/cuse",    // register a host-visible char device from userspace
        ] {
            assert!(is_dangerous_dev(std::path::Path::new(dev)), "{dev} refused");
        }
        // Legitimate peripherals must NOT be refused; the name rules must not false-positive on SGX, a
        // device merely starting "sg", or SERIAL ttys (vs the virtual consoles tty0..N).
        for dev in [
            "/dev/i2c-1",
            "/dev/null", // major 1 minor 3 — NOT in the raw-memory minor set, allowed
            "/dev/spidev0.0",
            "/dev/dri/renderD128", // render-only GPU node — allowed
            "/dev/rtc0",
            "/dev/sgx_enclave",     // SGX (not sg+digits) — allowed
            "/dev/bus/usb/001/002", // a SPECIFIC USB device (scoped libusb, like ttyUSB) — allowed
            "/dev/ttyS0",           // serial — allowed (not tty+pure-digits)
            "/dev/ttyUSB0",         // USB serial — allowed
            "/dev/ttyACM0",         // USB CDC serial — allowed
        ] {
            assert!(
                !is_dangerous_dev(std::path::Path::new(dev)),
                "{dev} allowed"
            );
        }
        // IDENTITY check (major/minor, not name): on hosts that actually HAVE these nodes, /dev/mem is
        // refused by its 1:1 identity and /dev/null (1:3) stays allowed — so a name-spoof (a dangerous
        // node under an innocent name) can't slip past.
        if std::path::Path::new("/dev/mem").exists() {
            assert!(
                is_dangerous_dev(std::path::Path::new("/dev/mem")),
                "mem by identity"
            );
        }
        assert!(
            !is_dangerous_dev(std::path::Path::new("/dev/null")),
            "null (1:3) allowed by identity"
        );
        // End to end: an `extra = "/dev/mem"` (hand-written / imported profile) never reaches `devs` —
        // either the host lacks it (skipped) or it's present and refused. Both outcomes: not bound.
        let mut cfg = KernConfig::default();
        cfg.vgpio.push(VGpioEntry {
            name: "danger".into(),
            extra: vec!["/dev/mem".into(), "/dev/../dev/mem".into()],
            ..Default::default()
        });
        let r = resolve_vgpio(&cfg, "danger").unwrap();
        assert!(
            !r.devs.iter().any(|d| d.ends_with("/mem")),
            "physical memory must never be bound: {:?}",
            r.devs
        );
    }

    #[test]
    fn resolve_vdisk_parses_size_and_backend() {
        let doc = "[[disk]]\nname = \"pool\"\npath = \"/srv/disks\"\n\
                   [[vdisk]]\nname = \"data\"\nbackend = \"disk:pool\"\nsize = \"2g\"\n\
                   iops = 500\nbandwidth = \"50m\"\npersistent = true\n";
        let cfg = parse(doc).unwrap();
        let r = resolve_vdisk(&cfg, "data").unwrap();
        assert_eq!(r.size, Some(2 * 1024 * 1024 * 1024));
        assert_eq!(r.iops, Some(500));
        assert_eq!(r.bandwidth, Some(50 * 1024 * 1024));
        assert!(r.persistent);
        assert_eq!(r.backend_dir.as_deref(), Some("/srv/disks"));
        assert!(resolve_vdisk(&cfg, "ghost").is_err());
    }

    #[test]
    fn whole_profile_refs_are_validated() {
        // vgpio backend must reference a configured [[gpio]] id.
        let cfg = parse(
            "[[gpio]]\nid=\"gpio:0\"\n[[vgpio]]\nname=\"ok\"\nbackend=\"gpio:0\"\n\
             [[vgpio]]\nname=\"bad\"\nbackend=\"gpio:9\"\n",
        )
        .unwrap();
        assert!(validate_profile_refs(&cfg, "vgpio", "ok").is_ok());
        assert!(validate_profile_refs(&cfg, "vgpio", "bad").is_err());
        // vcpu: backend → [[cpu]] id, extends → another vcpu profile.
        let cfg2 = parse(
            "[[cpu]]\nid=\"cpu:0\"\n[[vcpu]]\nname=\"base\"\ncpus=2.0\n\
             [[vcpu]]\nname=\"ok\"\nbackend=\"cpu:0\"\nextends=\"base\"\n\
             [[vcpu]]\nname=\"bad\"\nextends=\"nope\"\n",
        )
        .unwrap();
        assert!(validate_profile_refs(&cfg2, "vcpu", "ok").is_ok());
        assert!(validate_profile_refs(&cfg2, "vcpu", "bad").is_err());
        // vdisk backend → [[disk]] name.
        let cfg3 = parse(
            "[[disk]]\nname=\"pool\"\npath=\"/srv\"\n\
             [[vdisk]]\nname=\"ok\"\nbackend=\"disk:pool\"\nsize=\"1g\"\n\
             [[vdisk]]\nname=\"bad\"\nbackend=\"disk:ghost\"\nsize=\"1g\"\n",
        )
        .unwrap();
        assert!(validate_profile_refs(&cfg3, "vdisk", "ok").is_ok());
        assert!(validate_profile_refs(&cfg3, "vdisk", "bad").is_err());
        // No backend set → nothing to resolve → fine.
        let cfg4 = parse("[[vgpio]]\nname=\"n\"\npins=[17]\n").unwrap();
        assert!(validate_profile_refs(&cfg4, "vgpio", "n").is_ok());
        // The `kind:` prefix is tolerated on EITHER side: the docs form (`[[cpu]] id = "0"` +
        // `backend = "cpu:0"`) and a bare `backend = "0"` both resolve, not just the literal match.
        let cfg5 = parse(
            "[[cpu]]\nid=\"0\"\n[[vcpu]]\nname=\"pfx\"\nbackend=\"cpu:0\"\n\
             [[vcpu]]\nname=\"bare\"\nbackend=\"0\"\n",
        )
        .unwrap();
        assert!(validate_profile_refs(&cfg5, "vcpu", "pfx").is_ok());
        assert!(validate_profile_refs(&cfg5, "vcpu", "bare").is_ok());
    }

    // ── shared profile schema: the single source of truth the TUI form and `kern config add` share ──

    #[test]
    fn profile_line_validates_every_field() {
        // Good values emit the expected TOML. `cpus` = quota (float), `cpuset` = pinning (cpulist).
        assert_eq!(profile_line("cpus", "4").unwrap().unwrap(), "cpus = 4");
        assert_eq!(profile_line("cpus", "0.5").unwrap().unwrap(), "cpus = 0.5");
        assert_eq!(
            profile_line("cpuset", "0-3").unwrap().unwrap(),
            r#"cpuset = "0-3""#
        );
        assert_eq!(
            profile_line("memory", "512m").unwrap().unwrap(),
            r#"memory = "512m""#
        );
        assert_eq!(
            profile_line("pins", "17, 27").unwrap().unwrap(),
            "pins = [17, 27]"
        );
        assert_eq!(
            profile_line("persistent", "yes").unwrap().unwrap(),
            "persistent = true"
        );
        // Empty → nothing to emit; `persistent = no` → nothing.
        assert!(profile_line("memory", "  ").unwrap().is_none());
        assert!(profile_line("persistent", "no").unwrap().is_none());
        // Bad values are REJECTED — the same rejections the loader would give.
        assert!(profile_line("memory", "banana").is_err());
        assert!(profile_line("cpuset", "99-0").is_err()); // reversed range
        assert!(profile_line("cpus", "-5").is_err()); // quota must be > 0
        assert!(profile_line("cpus", "abc").is_err());
        assert!(profile_line("pins", "70000").is_err()); // out of GPIO range
        assert!(profile_line("size", "wat").is_err());
        assert!(profile_line("backend", "  ").unwrap().is_none()); // empty optional → skipped
    }

    #[test]
    fn field_state_is_the_one_rule_shared_with_save() {
        use FieldState::*;
        // Valid: a complete, save-acceptable value.
        for (k, v) in [
            ("pins", "17"),
            ("memory", "512m"),
            ("cpus", "0.5"),
            ("nice", "-5"),
            ("size", "2g"),
            ("cpuset", "0-3"),
        ] {
            assert_eq!(field_state(k, v), Valid, "{k}={v}");
        }
        // Incomplete: a prefix that can still complete — allowed live, not yet savable.
        for (k, v) in [
            ("nice", "-"),
            ("cpus", "0"),
            ("cpuset", "0-"),
            ("cpuset", "4095-"), // degenerate range 4095-4095 IS valid → not a dead-end
            ("cpuset", "5000-"), // no upper bound → 5000-9000 is reachable → typeable
        ] {
            assert_eq!(field_state(k, v), Incomplete, "{k}={v:?}");
        }
        // A high-core range is a VALID cpulist (host-fit is launch-time) — it must not be blocked
        // mid-typing: `5000-9000` types through, so `5000-` above is Incomplete, not Invalid.
        assert_eq!(field_state("cpuset", "4095-4095"), Valid);
        assert_eq!(field_state("cpuset", "5000-9000"), Valid);
        // Invalid: no completion can be valid — the keystroke that produced it is refused.
        for (k, v) in [
            ("pins", "44545454545"),
            ("nice", "-25"),
            ("memory", "1.5g"),
            ("cpus", "1.2.3"),
            ("extra", "rftre errte"), // garbage — not a /dev path (the reported bug)
            ("extra", "/etc/passwd"), // a path, but not under /dev
        ] {
            assert_eq!(field_state(k, v), Invalid, "{k}={v}");
        }
        // `extra` is a /dev-path list, not free text: a `/dev/…` path is Valid, a prefix Incomplete,
        // and its Valid values save (shared is_dev_path rule) — no more `rftre errte`.
        assert_eq!(field_state("extra", "/dev/foo"), Valid);
        assert_eq!(field_state("extra", "/dev/a,/dev/b"), Valid);
        assert_eq!(field_state("extra", "/de"), Incomplete); // prefix of /dev/
        assert_eq!(field_state("extra", "/dev/a,"), Incomplete); // last token mid-typing
        assert!(profile_line("extra", "/dev/foo").unwrap().is_some());
        assert!(profile_line("extra", "rftre").is_err());
        // `name`/`extends` route through the SAME dispatcher (not a second validator) — so they get the
        // three-state too and can't drift from validate_profile_name at save.
        assert_eq!(field_state("name", "sensors"), Valid);
        assert_eq!(field_state("name", "a.b-c_1"), Valid);
        assert_eq!(field_state("extends", "base"), Valid);
        assert_eq!(field_state("name", ""), Incomplete);
        assert_eq!(field_state("name", "-lead"), Invalid); // leading '-' is unfixable
        assert_eq!(field_state("name", ".hidden"), Invalid); // leading '.'
        assert_eq!(field_state("name", "a..b"), Invalid); // traversal
        assert_eq!(field_state("name", &"x".repeat(65)), Invalid); // too long
                                                                   // And the same anti-dead-end invariant for names: field_state Valid ⇒ validate accepts.
        for v in ["a", "web-1", "a.b", "MyBox_2", "-x", ".x", "a/b", "a:b", ""] {
            if field_state("name", v) == Valid {
                assert!(
                    validate_profile_name(v).is_ok(),
                    "Valid name must save: {v:?}"
                );
            }
        }
        // THE invariant that kills the dead-end class: whatever field_state calls Valid, the SAVE
        // (profile_line) must accept. Otherwise the filter lets you type a value the save rejects.
        for k in [
            "pins", "numa", "nice", "cpus", "cpuset", "memory", "size", "iops",
        ] {
            for v in [
                "0", "1", "5", "17", "50", "99", "100", "512", "2g", "16t", "1.5", "1.5g", ".5g",
                "5m2", "-5", "0-3", "0-", "-", "1.2.3",
            ] {
                if field_state(k, v) == Valid {
                    assert!(
                        profile_line(k, v).unwrap().is_some(),
                        "Valid must save: {k}={v}"
                    );
                }
            }
        }
    }

    #[test]
    fn profile_line_covers_every_field_type() {
        // The extended field set — i32 ranges, u64, sizes, u32-lists and string-lists — every one
        // reachable from `kern config add`, all through the single validated emitter.
        assert_eq!(profile_line("numa", "1").unwrap().unwrap(), "numa = 1");
        assert_eq!(profile_line("nice", "-5").unwrap().unwrap(), "nice = -5");
        assert_eq!(profile_line("iops", "500").unwrap().unwrap(), "iops = 500");
        assert_eq!(
            profile_line("bandwidth", "50m").unwrap().unwrap(),
            r#"bandwidth = "50m""#
        );
        assert_eq!(
            profile_line("pwm", "12, 13").unwrap().unwrap(),
            "pwm = [12, 13]"
        );
        assert_eq!(
            profile_line("i2c", "/dev/i2c-1,/dev/i2c-2")
                .unwrap()
                .unwrap(),
            r#"i2c = ["/dev/i2c-1", "/dev/i2c-2"]"#
        );
        assert_eq!(
            profile_line("extends", "base").unwrap().unwrap(),
            r#"extends = "base""#
        );
        // Ranges enforced.
        assert!(profile_line("nice", "40").is_err());
        assert!(profile_line("numa", "-1").is_err());
        assert!(profile_line("extends", "a:b").is_err());
        assert!(profile_line("adc", "70000").is_err()); // line-index range
                                                        // A non-finite cpus quota (`inf`/`nan`) is rejected — it would write a nonsense `cpus = inf`.
        assert!(profile_line("cpus", "inf").is_err());
        assert!(profile_line("cpus", "nan").is_err());
    }

    #[test]
    fn profile_name_charset_is_enforced_here_for_all_callers() {
        assert!(validate_profile_name("heavy").is_ok());
        assert!(validate_profile_name("a.b-c_d").is_ok());
        assert!(validate_profile_name("").is_err());
        assert!(validate_profile_name("a:b").is_err()); // ':' would split the attach token
        assert!(validate_profile_name("../x").is_err());
        assert!(validate_profile_name("..").is_err()); // no lying "created ok" for a path-escape name
        assert!(validate_profile_name("a..b").is_err());
        assert!(validate_profile_name(&"a".repeat(65)).is_err());
    }

    #[test]
    fn resolve_rejects_a_hand_edited_out_of_range_profile() {
        // A file the TUI would never have written (a reversed cpuset range) fails at attach with a clear message.
        let cfg = parse("[[vcpu]]\nname=\"p\"\ncpus=1\ncpuset=\"9-0\"\n").unwrap();
        let e = resolve_vcpu(&cfg, "p").unwrap_err();
        assert!(e.contains("cpuset"), "got: {e}");
        // A ':' in a name is refused at resolve too, matching the form.
        let cfg2 = parse("[[vcpu]]\nname=\"a:b\"\ncpus=1\n").unwrap();
        assert!(resolve_vcpu(&cfg2, "a:b").is_err());
        // A GPIO pin far out of range is refused.
        let cfg3 = parse("[[vgpio]]\nname=\"g\"\nbackend=\"gpio:0\"\npins=[70000]\n").unwrap();
        assert!(resolve_vgpio(&cfg3, "g").is_err());
    }

    #[test]
    fn toml_quote_escapes_injection_and_control_chars() {
        assert_eq!(toml_quote(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(toml_quote("a\nb\tc\rd"), r#""a\nb\tc\rd""#);
        let q = toml_quote("x\u{7}y"); // BEL → 
        assert!(!q.contains('\u{7}'), "no raw control byte survives");
        assert!(!q.contains('\n'), "output stays single-line");
    }

    #[test]
    fn write_atomic_is_private_and_wont_follow_a_symlink() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("kern-wa-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("kern.toml");
        write_atomic(&target, "a = 1\n").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "a = 1\n");
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "config must be private");
        // A symlink pre-planted at the per-pid temp path must never be written through.
        let victim = dir.join("victim");
        std::fs::write(&victim, "DO-NOT-TOUCH").unwrap();
        let tmp = target.with_extension(format!("toml.tmp.{}", std::process::id()));
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();
        write_atomic(&target, "b = 2\n").unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "DO-NOT-TOUCH");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "b = 2\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
