//! Subcommand implementations. One responsibility per function; the roadmap splits each verb
//! (box/run/pull/compose) into its own module here as the surface grows.

use crate::error::Error;
use crate::registry;
use crate::sandbox::SandboxCtx;
use kern_common::{json_str, BoxName};
use kern_isolation::{
    exec_in_box, run_in_sandbox_with, MountMode, OverlayDirs, SandboxSpec, UidRange, Volume,
};
use std::io::IsTerminal;
use std::path::PathBuf;

/// A copy of `s` with ANSI escape sequences and control characters removed.
///
/// One pass, one allocation, and it does not need to know the palette: a CSI sequence is `ESC [`
/// followed by parameter/intermediate bytes and terminated by a final byte in `@`..`~`, and any
/// other `ESC x` form is two bytes. Anything a palette can produce is covered, so this cannot go
/// stale when a colour is added.
///
/// Deliberately not `ui::scrub`: scrub DELETES the ESC and leaves the `[1m` tail as printable text,
/// which is right for its job (an error message must not repaint a terminal, and what remains is
/// inert) and wrong for matching, where the residue is indistinguishable from content.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            match it.next() {
                // CSI (`ESC [ … final`) and OSC (`ESC ] … BEL/ST`): consume up to the terminator.
                // Every colour kern emits is a CSI SGR, so this is the branch that matters.
                Some('[') => {
                    for n in it.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&n) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    for n in it.by_ref() {
                        // BEL, or the ST introducer whose ESC was already eaten by this loop.
                        if n == '\u{7}' || n == '\\' {
                            break;
                        }
                    }
                }
                // Charset designation (`ESC ( B`, `ESC ) 0`, …): one intermediate, one final. Nothing
                // in kern emits these; they are handled because leaving the final byte behind turns
                // an escape into a stray letter that reads as content, which is the failure mode this
                // whole function exists to avoid.
                Some('(') | Some(')') | Some('*') | Some('+') | Some('#') => {
                    let _ = it.next();
                }
                // Any other two-byte form (`ESC 7`, `ESC =`, …) is fully consumed by the `next()`
                // above. Out of scope, and stated rather than assumed: a form not listed here loses
                // its ESC and keeps its payload.
                Some(_) | None => {}
            }
            continue;
        }
        if !c.is_control() {
            out.push(c);
        }
    }
    out
}

/// Bare `kern`: a short, friendly banner - the logo, the tagline, and the handful of commands most
/// people reach for first. The full command + flag reference is `kern --help`.
pub fn banner() -> Result<(), Error> {
    let p = crate::ui::Palette::detect();
    let (b, c, d, z) = (p.b, p.c, p.d, p.z);
    println!("{}", crate::ui::logo(&p));
    println!(
        "\
  {b}kern {ver}{z}{d}: a fast, rootless sandbox & virtual resource runtime{z}

    {b}kern box{z} <name> --image alpine -- sh   {d}run a command in a sandbox{z}
    {b}kern box{z} app --image alpine vcpu:big -- sh  {d}attach a resource profile (make one: {z}{b}kern config{z}{d}){z}
    {b}kern run{z} --memory 512m -- <cmd>         {d}govern a command's CPU/memory (no sandbox){z}
    {b}kern ps{z} {d}·{z} {b}logs{z} {d}·{z} {b}exec{z} {d}·{z} {b}stop{z}            {d}manage running boxes{z}
    {b}kern pull{z} {d}·{z} {b}build{z} {d}·{z} {b}push{z} {d}·{z} {b}images{z}       {d}work with OCI images{z}
    {b}kern compose{z} stack.yml                  {d}bring up a stack (docker-compose.yml too){z}

  {b}kern --help{z} {d}all commands{z} {d}·{z} {b}kern top{z} {d}live TUI{z} {d}·{z} {b}kern doctor{z} {d}check this host{z}
  {d}{z}{c}https://github.com/getkern/kern{z}",
        ver = kern_common::VERSION
    );
    Ok(())
}

/// `--restart [policy]` - what to do when a detached box exits. `no` (default) leaves it dead;
/// `on-failure` re-runs it on a non-zero exit via kern's own in-process supervisor (dies with the
/// host); `always`/`unless-stopped` hand supervision to the user's **systemd** (a generated
/// `~/.config/systemd/user/kern-<name>.service` + linger) so the box restarts on ANY exit AND
/// survives reboot - all WITHOUT a kern daemon. Exception: a `--pod` MEMBER with `always`/
/// `unless-stopped` is supervised in-process for the stack's lifetime instead (it needs the pod
/// holder's shared namespace, which a standalone systemd unit could not re-join).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RestartPolicy {
    #[default]
    No,
    OnFailure,
    Always,
    UnlessStopped,
}

impl RestartPolicy {
    /// Parse a `--restart` value; `None` if unrecognized (so a bare `--restart` can fall back to
    /// `on-failure` without swallowing the next token).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "no" => Some(Self::No),
            "on-failure" => Some(Self::OnFailure),
            "always" => Some(Self::Always),
            "unless-stopped" => Some(Self::UnlessStopped),
            _ => None,
        }
    }

    /// Human name (matches the CLI value + Docker's).
    fn as_str(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::OnFailure => "on-failure",
            Self::Always => "always",
            Self::UnlessStopped => "unless-stopped",
        }
    }

    /// Does this policy persist across reboot (→ hand off to a systemd user unit)?
    fn persistent(self) -> bool {
        matches!(self, Self::Always | Self::UnlessStopped)
    }
}

/// `--pull <policy>` - when an `--image` names a registry ref, decide whether to hit the network.
/// `Missing` (Docker's default) pulls only when the image is not already cached; `Never` fails closed
/// if it is not local (never touches the network); `Always` forces a fresh pull with an atomic cache
/// swap. A locally-built (`.layers`/`.base`) or `scratch` image is used as-is under every policy -
/// kern has nothing to re-pull for it, so those resolve before the network decision is ever reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PullPolicy {
    #[default]
    Missing,
    Never,
    Always,
}

/// `--security-profile <name>`: a named bundle of opt-in hardening applied as a BASE that explicit
/// flags override. A CLOSED set (one value today); a registry stays premature until a second profile
/// and an external request exist. The resolved constituents are printed (at start and by `--plan`), so
/// the macro is visible and a future change to a constituent surfaces rather than shifting silently.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecurityProfile {
    /// `untrusted`: seccomp ALLOWLIST + `--cap-drop ALL` + `--read-only`, for running code nobody has
    /// read. Explicit flags/env override it (`--cap-add X`, `KERN_SECCOMP=...`). Deliberately does NOT
    /// touch Landlock (a write-allowlist needs the workload's real paths, which a profile cannot guess:
    /// build it from a `--landlock-rw` audit run) and does NOT set `--require-limits` (which would break
    /// a host with no cgroup delegation, exactly what an opt-in hardening profile must not do).
    Untrusted,
}

impl SecurityProfile {
    /// Parse the flag value; `None` on an unknown name so the caller emits a usage error naming the set.
    pub fn parse(v: &str) -> Option<Self> {
        match v {
            "untrusted" => Some(Self::Untrusted),
            _ => None,
        }
    }
}

/// Resolve the box's seccomp mode WITHOUT touching the process environment. Precedence, explicit first:
/// a non-empty `KERN_SECCOMP` (a valid token parses as [`kern_isolation::SeccompFilter::parse`] does),
/// then the security profile, then the default (allowlist). Pure and total: the caller passes the env
/// value read once, so there is no `env::set_var` - which is a data race on the un-locked `environ` in a
/// multi-threaded process and a process-global side effect that would leak into a later box in the same
/// process. Unlike `from_env`, a SET-but-unrecognised (or non-UTF-8) value is a FAIL-LOUD usage error,
/// not a silent fall to the default: a malformed security control must stop, never downgrade a profile
/// silently. Only an ABSENT or EMPTY value falls through to the profile, then the default.
fn resolve_seccomp_mode(
    env: Option<&std::ffi::OsStr>,
    profile: Option<SecurityProfile>,
) -> Result<kern_isolation::SeccompFilter, Error> {
    use kern_isolation::SeccompFilter;
    if let Some(v) = env {
        if !v.is_empty() {
            // A SET-but-unrecognised value is a FAIL-LOUD usage error, not a silent fall to the
            // default. Silently defaulting would let a typo (`allowlist-audi`) downgrade a
            // `--security-profile untrusted` box from the allowlist to the denylist while the box
            // still advertises `untrusted`: the label would lie. A malformed security control must stop.
            return match v.to_str().and_then(SeccompFilter::parse) {
                Some(f) => Ok(f),
                None => Err(Error::Usage(
                    "KERN_SECCOMP: unrecognised value (expected `denylist`, `allowlist`, or \
                     `allowlist-audit`)",
                )),
            };
        }
    }
    Ok(match profile {
        Some(SecurityProfile::Untrusted) => SeccompFilter::Allowlist,
        None => SeccompFilter::default(),
    })
}

/// Arguments for [`box_run`]. A struct (not a long parameter list) keeps the call site readable
/// as box options grow (`-v`, `--env`, `--workdir`, `--net`).
pub struct BoxRunArgs<'a> {
    pub name: &'a str,
    pub rootfs: Option<&'a str>,
    pub image: Option<&'a str>,
    /// `--pull <missing|never|always>`: registry-image fetch policy (see [`PullPolicy`]).
    pub pull: PullPolicy,
    pub command: &'a [String],
    /// `--entrypoint` (repeatable): REPLACE the image's `ENTRYPOINT`, per Docker.
    ///
    /// `None` = absent, the image's entrypoint stands. `Some(list)` replaces it AND discards the
    /// image's `CMD`, because that default belonged to the entrypoint being replaced.
    /// `Some(empty)` clears it. See [`crate::commands::resolve_image_command`].
    pub entrypoint: Option<&'a [String]>,
    pub detached: bool,
    pub read_only: bool,
    pub volumes: &'a [String],
    pub env: &'a [String],
    /// `--egress-allow d1,d2`: outbound network restricted to these domains (+ subdomains) via a
    /// kern-run filtering proxy; empty = the default (no outbound unless `--net`/`--pod`).
    pub egress_allow: &'a [String],
    /// `--landlock-rw <path>` (repeatable): a Landlock (LSM) write-allowlist; the box root is read+exec
    /// and writes are confined to these paths (+ box scratch dirs). Empty = no Landlock. Each path must
    /// EXIST at box start (typically a `-v` volume or a dir the image ships): the box root is read-only
    /// under Landlock, so the workload cannot `mkdir` a missing allowlist dir, and a path absent at start
    /// is skipped (fail-safe, so the box is only ever MORE confined, never less).
    pub landlock_rw: &'a [String],
    /// `--ip <addr>` (repeatable): extra IPv4 addresses this box's loopback answers on.
    pub net_ips: &'a [std::net::Ipv4Addr],
    /// `--pod-bridge <ip>/<prefix>`: this box's place on the pod's bridge, when it has one.
    pub pod_bridge: Option<kern_isolation::BridgeAttach>,
    /// `--apparmor <profile>`: a pre-loaded AppArmor profile the box enters on exec, or None.
    pub apparmor: Option<&'a str>,
    pub workdir: Option<&'a str>,
    pub share_net: bool,
    /// `--pod <name>`: join this pod's shared network (created by `kern pod create`).
    pub pod: Option<&'a str>,
    pub uid_range: bool,
    /// `--no-uid-range`: opt OUT of the range mapping an `--image` box gets by default.
    pub no_uid_range: bool,
    pub bind_rootfs: bool,
    /// `--privileged`: relax the seccomp filter to allow a NESTED `kern box` (rootless-only; see
    /// [`kern_isolation::SandboxSpec::privileged`]).
    pub privileged: bool,
    /// `--require-limits`: refuse to start (non-zero exit) if a resource cap cannot be enforced here,
    /// instead of running best-effort UNCAPPED (see [`kern_isolation::SandboxSpec::require_limits`]).
    pub require_limits: bool,
    /// `--allow-uncapped`: accept running uncapped silently on a host with no cgroup delegation (see
    /// [`kern_isolation::SandboxSpec::allow_uncapped`]). Mutually exclusive with `require_limits`.
    pub allow_uncapped: bool,
    /// `--security-profile <untrusted>`: opt-in hardening bundle applied as a base (see
    /// [`SecurityProfile`]). `None` = no profile.
    pub security_profile: Option<SecurityProfile>,
    /// INTERNAL (build): explicit colon-joined overlay lower dir(s), used instead of `--rootfs`/
    /// `--image` and paired with `overlay_upper` to run a build's RUN step against the base.
    pub overlay_lower: Option<&'a str>,
    /// INTERNAL (build): a persistent overlay upper (the build layer) instead of ephemeral scratch.
    pub overlay_upper: Option<&'a str>,
    /// `--memory`/`-m`: hard memory ceiling in bytes (default cap if `None`).
    pub memory: Option<u64>,
    /// `--memory-swap-max`: swap allowance in bytes → `memory.swap.max` (`None` → `0`, swap off).
    pub memory_swap_max: Option<u64>,
    /// `--cpus`: CPU cap in cores, K8s semantics (uncapped if `None`).
    pub cpus: Option<f64>,
    /// `--cpuset-cpus`: pin to specific CPUs (e.g. `"0-3"`; `None` → no pinning).
    pub cpuset: Option<&'a str>,
    /// `-it`/`-t`: allocate a PTY so the box gets an interactive controlling terminal.
    pub tty: bool,
    /// `-p host:box` (repeatable): publish a box TCP port on a host port.
    pub ports: &'a [kern_isolation::PortMap],
    /// `--secret SRC[:NAME]` / `NAME=value` / `NAME=-` (repeatable): deliver a secret as
    /// `/run/secrets/NAME` (mode 0400) without it hitting the image or the workload env.
    pub secrets: &'a [String],
    /// `--secret-env <name>`: content from `KERN_SECRET_<name>` rather than from argv.
    pub secret_envs: &'a [String],
    /// `--secret-mode <octal>`: the file mode every `--secret` of this box is created with.
    ///
    /// PER BOX AND NOT PER SECRET, deliberately and measurably: `mode:` under a service's `secrets:`
    /// does not appear ONCE in 259 real compose files nor in any of Docker's own eight samples that
    /// use secrets, so a per-secret channel would be machinery for a case that does not occur. A
    /// file that does declare two DIFFERENT modes for one service is REFUSED by the compose driver
    /// rather than silently given one of them.
    pub secret_mode: libc::mode_t,
    /// `--ssh PORT`: run an in-box sshd and publish it on host `PORT` (→ box `:22`). `None` → no SSH.
    pub ssh_port: Option<u16>,
    /// `--ssh-key FILE`: authorize this public key file instead of generating a throwaway keypair.
    pub ssh_key: Option<&'a str>,
    /// `--hostname NAME`: the box's UTS hostname (default: the box name).
    pub hostname: Option<&'a str>,
    /// `--tun`: expose `/dev/net/tun` in the box (WireGuard / userspace VPN).
    pub tun: bool,
    /// `--init`: run a built-in reaping init as box PID 1 (no zombies; forwards SIGTERM/SIGINT).
    pub init: bool,
    /// `--pids-limit N`: cap the box's task count (`pids.max`) - fork-bomb containment.
    pub pids_limit: Option<u64>,
    /// `--tmpfs PATH[:size]` (repeatable): mount a fresh tmpfs at PATH inside the box.
    pub tmpfs: &'a [String],
    /// `--shm-size SIZE`: an explicit cap for `/dev/shm`, in bytes. `None` derives one from `--memory`.
    pub shm_size: Option<u64>,
    /// `--ulimit` limits, pre-resolved to `(RLIMIT_*, soft, hard)` by the CLI.
    pub ulimits: &'a [(i32, u64, u64)],
    /// `--sysctl KEY=VALUE` pairs, applied inside the box's namespaces.
    pub sysctls: &'a [(String, String)],
    /// `--label k=v` metadata (repeatable). Descriptive only: it does not change how the box runs,
    /// but it is recorded in the registry so `kern ps --filter label=` and `kern inspect` can use it.
    pub labels: &'a [String],
    /// `--restart-max <n>`: retry cap for the on-failure supervisor (0 = kern's default).
    pub restart_max: u32,
    /// `--stop-signal <name|num>`: signal sent before the SIGKILL. `None` = the flag was not given,
    /// which is NOT the same as `Some(SIGTERM)`: absent, the image's own `STOPSIGNAL` decides, and
    /// only if the image declares none does it fall back to `SIGTERM`.
    pub stop_signal: Option<i32>,
    /// `--stop-timeout <secs>`: grace given to the workload before the SIGKILL.
    pub stop_grace: u64,
    /// `--def-hash <hex>`: fingerprint of the compose definition this box comes from, recorded so a
    /// later `up` can tell whether the file still describes the running service.
    pub def_hash: &'a str,
    /// `--user UID[:GID]`: drop to this uid/gid inside the box before the command runs.
    pub run_as: Option<&'a str>,
    /// `--cap-add CAP` (repeatable): keep a capability kern would otherwise drop (or `ALL`).
    pub cap_add: &'a [String],
    /// `--cap-drop CAP` (repeatable): drop an extra capability (or `ALL`).
    pub cap_drop: &'a [String],
    /// `--restart [policy]`: what to do when the detached box exits (see [`RestartPolicy`]).
    pub restart: RestartPolicy,
    /// `--health-cmd <cmd>`: shell command run periodically in the box (exit 0 = healthy).
    pub health_cmd: Option<&'a str>,
    /// `--health-cmd-argv <arg>` (repeatable): the SAME check in Docker's `CMD` exec form - one
    /// argv element per occurrence, exec'd directly with no shell. The form an image without a
    /// shell needs, and the form compose's `test: ["CMD", …]` means.
    pub health_cmd_argv: &'a [String],
    /// `--health-interval <sec>`: seconds between health checks.
    pub health_interval: u64,
    /// `--health-retries <n>`: consecutive failures before "unhealthy".
    pub health_retries: u32,
    /// `--health-start-period <sec>`: grace period where a failing check keeps "starting".
    pub health_start_period: u64,
    /// `--health-timeout <sec>`: kill a single check that exceeds this (0 = no timeout).
    pub health_timeout: u64,
    /// `--health-action <restart|stop|none>`: what to do when a box turns unhealthy.
    pub health_action: Option<&'a str>,
    /// `--env-file <file>` (repeatable): read `K=V` lines into the box environment.
    pub env_file: &'a [String],
    /// `--timeout <sec>`: auto-stop the box after this many seconds (0 = no timeout).
    pub timeout: u64,
    /// `--nice <n>`: scheduling niceness for the box workload.
    pub nice: Option<i64>,
    /// `--io-weight <n>`: cgroup v2 `io.weight` (relative I/O priority).
    pub io_weight: Option<u64>,
    /// `--config <path>`: a specific `kern.toml` for this invocation.
    pub config: Option<&'a str>,
    /// `--show-config`: print the resolved box configuration and exit.
    pub show_config: bool,
    /// `--quiet`: suppress the foreground status panel.
    pub quiet: bool,
    /// `--verbose`: expand the one-line summary into the full isolation posture panel.
    pub verbose: bool,
    /// Resource-profile tokens (`vcpu:name` …) applied to the box's caps.
    pub profiles: &'a [String],
    /// `--add-host NAME:IP` extra `/etc/hosts` entries; the IP may be the keyword `host-gateway`
    /// (resolved to the host's reachable address at build time).
    pub add_hosts: &'a [(String, String)],
    /// `--dns IP`: the box's `nameserver` lines (already validated as IP literals by the CLI).
    pub dns: &'a [String],
    /// `--dns-search DOMAIN`: the `search` line of the box's `/etc/resolv.conf`.
    pub dns_search: &'a [String],
    /// `--dns-option OPT`: the `options` line of the box's `/etc/resolv.conf`.
    pub dns_options: &'a [String],
    /// `--log-max-size`: the captured log's rotation threshold in bytes; `None` = kern's default.
    pub log_max_size: Option<u64>,
    /// `--log-max-file`: how many log files to keep, active one included; `None` = kern's default.
    pub log_max_file: Option<u32>,
    /// `--memory-reservation`: cgroup `memory.low`, a soft floor.
    pub memory_reservation: Option<u64>,
    /// `--cpu-weight`: cgroup `cpu.weight`, a relative share.
    pub cpu_weight: Option<u64>,
}

/// Resolve `--add-host` entries: the `host-gateway` keyword becomes the host's reachable address -
/// `127.0.0.1` when the box shares the host network, else the host's primary (default-route) IPv4 (the
/// address a box with egress uses to reach the host). Other values pass through verbatim.
fn resolve_add_hosts(raw: &[(String, String)], share_net: bool) -> Vec<(String, String)> {
    let gateway = || -> String {
        if share_net {
            return "127.0.0.1".to_string();
        }
        host_primary_ipv4().unwrap_or_else(|| "127.0.0.1".to_string())
    };
    raw.iter()
        .map(|(name, ip)| {
            let ip = if ip.eq_ignore_ascii_case("host-gateway") {
                gateway() // resolved lazily, only for host-gateway entries
            } else {
                ip.clone()
            };
            (name.clone(), ip)
        })
        .collect()
}

/// The host's primary IPv4 (the source address the default route would use), found by `connect()`ing a
/// UDP socket to a public address - no packet is sent; the kernel just picks the route's source IP. So
/// it works offline as long as a default route exists. `None` if there's no usable route.
fn host_primary_ipv4() -> Option<String> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:53").ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => {
            Some(v4.to_string())
        }
        _ => None,
    }
}

/// The host's online CPU count (`processor` lines in `/proc/cpuinfo`), floored at 1. Memoized - the
/// single reader, so a box passing BOTH `--cpus` and `--cpuset-cpus` reads `/proc/cpuinfo` once, not
/// twice. (Counts online CPUs on purpose: `available_parallelism()` respects kern's own affinity mask
/// and would undercount the `0..host` pin range if kern were itself pinned.)
fn host_cpu_count() -> usize {
    use std::sync::OnceLock;
    static N: OnceLock<usize> = OnceLock::new();
    *N.get_or_init(|| {
        std::fs::read_to_string("/proc/cpuinfo")
            .map(|s| s.lines().filter(|l| l.starts_with("processor")).count())
            .ok()
            .filter(|&n| n > 0)
            .unwrap_or(1)
    })
}

/// Clamp a `--cpus` request to the host's physical CPU count (from `/proc/cpuinfo`), so the cap
/// is consistent across the systemd scope AND the in-namespace cgroup. The warning fires once - in
/// the original process, before the scope re-exec (which sets `KERN_SCOPE`) runs the parse again.
/// Is a `--cpus` request above what the machine has?
///
/// Extracted so the boundary can be asserted. Inside `clamp_cpus` it could not be: at `c == host`
/// the clamped result and the unclamped one are the SAME NUMBER, so a mutation from `>` to `>=`
/// leaves the return value untouched and changes only the warning - which then tells the operator
/// that 28 CPUs "exceeds the 28 available". A false message is the whole observable difference, and
/// a test on the return value cannot see it.
///
/// Equality is NOT above: asking for exactly the machine is asking for the machine.
fn cpus_exceed_host(requested: f64, host: f64) -> bool {
    requested > host
}

fn clamp_cpus(cpus: Option<f64>) -> Option<f64> {
    let c = cpus?;
    let host = host_cpu_count() as f64;
    if cpus_exceed_host(c, host) {
        if std::env::var_os("KERN_SCOPE").is_none() {
            eprintln!(
                "kern: --cpus {c} exceeds the {host:.0} available CPUs - clamping to {host:.0}"
            );
        }
        return Some(host);
    }
    Some(c)
}

/// Clamp a `--cpuset-cpus` list to the host's CPU range (`0..host`), so an over-wide pin (`0-9999` on
/// a 4-CPU box) becomes the valid subset (`0-3`) instead of a raw `systemd`/kernel "Failed to parse
/// AllowedCPUs" that aborts the box start. Each range/single is intersected with `[0, host-1]`;
/// out-of-range items are dropped. Warns once, like `clamp_cpus`.
///
/// A list in which NOTHING exists on this host is REFUSED rather than passed through. It used to be
/// passed through, on the reasoning that "the backend rejects an all-invalid pin loudly rather than
/// us silently running unpinned". Measured on a 28-CPU machine, that reasoning was false for the
/// values people actually mistype: `--cpuset-cpus 28` (one past the end) reached systemd, which
/// accepted it, applied nothing, printed nothing, and exited 0 with the process free to use all 28
/// CPUs. Only absurd values (`999999`) overflow systemd's parser and fail loudly, so the fallback
/// worked precisely where it was not needed and failed on the off-by-one. A resource cap that cannot
/// be applied must not silently become no cap, the same fail-closed rule `--user` follows.
///
/// Refusing rather than clamping is deliberate here and differs from [`clamp_cpus`]. Clamping
/// `--cpus 999` to 28 moves TOWARD the request (you wanted a lot, you get the most there is), while
/// clamping `--cpuset-cpus 28` to `0-27` INVERTS it: the caller asked to be confined to one CPU and
/// would be handed the whole machine. There is no safe subset to pick, so the caller is told.
fn clamp_cpuset(set: Option<String>) -> Result<Option<String>, Error> {
    let Some(s) = set else {
        return Ok(None);
    };
    let host = host_cpu_count(); // >= 1 by construction, so `host - 1` cannot underflow
    let max = host - 1;
    let mut out: Vec<String> = Vec::new();
    // Distinguishes "every item parsed and every item was out of range" (refuse) from "an item did
    // not parse at all" (leave it to the backend, since the CLI validator already vetted the form
    // and a parser disagreement here is our bug, not the caller's).
    let mut parsed_any = false;
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('-') {
            Some((a, b)) => {
                let (Ok(a), Ok(b)) = (a.trim().parse::<usize>(), b.trim().parse::<usize>()) else {
                    return Ok(Some(s)); // unparseable - leave it (the CLI boundary vetted the form)
                };
                parsed_any = true;
                let (lo, hi) = (a.min(b), a.max(b));
                if lo > max {
                    continue; // wholly above the host range → drop
                }
                let hi = hi.min(max);
                out.push(if lo == hi {
                    lo.to_string()
                } else {
                    format!("{lo}-{hi}")
                });
            }
            None => match part.parse::<usize>() {
                Ok(n) if n <= max => {
                    parsed_any = true;
                    out.push(n.to_string());
                }
                Ok(_) => parsed_any = true, // single CPU out of range → drop
                Err(_) => return Ok(Some(s)),
            },
        }
    }
    if out.is_empty() {
        if parsed_any {
            let range = if max == 0 {
                "0".to_string()
            } else {
                format!("0-{max}")
            };
            return Err(Error::Cli(format!(
                "--cpuset-cpus {s}: this machine has {host} CPU(s), numbered {range}, so none of \
                 the CPUs you asked for exist. Refusing rather than starting with no pin at all."
            )));
        }
        return Ok(Some(s));
    }
    let clamped = out.join(",");
    if clamped != s && std::env::var_os("KERN_SCOPE").is_none() {
        eprintln!(
            "kern: --cpuset-cpus {s} exceeds the {host} available CPUs - clamping to {clamped}"
        );
    }
    Ok(Some(clamped))
}

/// `kern box <name> (--rootfs <dir> | --image <ref>) [-d] [-v ...] [--env ...] [-- cmd...]` - run
/// a command in a real sandbox: a fresh user + PID + (net) + UTS + IPC + mount namespace, the
/// rootfs pivoted in, seccomp-filtered, cgroup-capped. `--image` pulls an OCI image (cached).
/// Defaults to `/bin/sh`. Foreground propagates the exit code; `-d` detaches (track via `kern ps`).
/// Enforce deployment-level FLEET limits from the environment before a box starts.
///
///  * `KERN_MAX_CONCURRENT=N`: a COOPERATIVE ceiling on the number of running boxes. Refuses the N+1th
///    box so a runaway (an agent spawning `box fn` in a loop) can't exhaust the host. Counts LIVE boxes
///    via the registry, which prunes dead entries on read, so a crashed box frees its slot. First-party
///    and cooperative (a caller can unset the env): NOT a security boundary. The check HERE is a fast-
///    fail advisory; the AUTHORITATIVE count is race-free - `claim_name_capped` re-counts and refuses
///    under the same lock it takes the name claim under (see `box_run`), so a parallel burst
///    (`kern compose up`, `xargs -P kern box`) can no longer overshoot N. For a HARD bound on total
///    fleet RESOURCES (not box count) use `KERN_FLEET_PIDS_MAX` / `KERN_FLEET_MEMORY_MAX` below
///    (cgroup-enforced on the shared slice, so the kernel caps the SUM no matter how boxes are started).
///  * `KERN_FLEET_MEMORY_MAX` / `KERN_FLEET_PIDS_MAX`: a REAL, kernel-enforced budget on kern's shared
///    `kern.slice`, bounding the SUM of all boxes' memory / pids. This is the hard backstop the counter
///    lacks: even past the cooperative ceiling, the kernel caps total fleet memory. Best-effort (needs
///    systemd-user delegation); engages once the slice exists (from the first box onward).
///
/// Returns an error only for the max-concurrent refusal; the budget is best-effort and never fails a box.
/// `KERN_MAX_CONCURRENT` parsed to a ceiling, or `None` (unset/unparseable). The single reader, shared
/// by the advisory fast-fail here and the authoritative under-lock check in `box_run`, so the env key
/// and its parse rule live once.
fn fleet_max() -> Option<usize> {
    std::env::var("KERN_MAX_CONCURRENT")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
}

/// The one refusal message for the fleet ceiling, shared by both checks so the wording can't drift.
fn fleet_limit_error(live: usize, max: usize) -> Error {
    Error::Sandbox(format!(
        "fleet limit reached: {live} box(es) already running (KERN_MAX_CONCURRENT={max}); \
         stop one, or raise/unset the limit"
    ))
}

fn fleet_gate_and_budget() -> Result<(), Error> {
    if let Some(max) = fleet_max() {
        let live = registry::list().len(); // prunes dead entries as a side effect (crash-safe count)
        if live >= max {
            return Err(fleet_limit_error(live, max));
        }
    }
    let mem = std::env::var("KERN_FLEET_MEMORY_MAX")
        .ok()
        .and_then(|v| kern_common::parse_binary_size(v.trim()));
    let pids = std::env::var("KERN_FLEET_PIDS_MAX")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok());
    if mem.is_some() || pids.is_some() {
        kern_isolation::set_fleet_caps(mem, pids);
        // The fleet SUM cap lives on kern's delegated `kern.slice` and only bounds boxes that actually
        // run INSIDE it (the direct-cap path). Where kern falls back to per-box systemd scopes (the
        // common ROOTLESS case: verified on Jetson/Pi5, boxes land in `app.slice/run-*.scope`), the boxes
        // are NOT under kern.slice, so the SUM is unbounded even though `set_fleet_caps` wrote the limit.
        // Do NOT silently no-op a security-relevant cap: warn once (same posture as the `--memory`
        // not-enforced warning). Per-box `--memory`/`--pids` still enforce; those are the reliable knob.
        if !kern_isolation::choose_direct_cap_path() {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| {
                eprintln!(
                    "kern: warning: KERN_FLEET_MEMORY_MAX / KERN_FLEET_PIDS_MAX bound the SUM across boxes \
                     ONLY when boxes share kern's delegated kern.slice, which this host does not use (boxes \
                     run in per-box systemd scopes). The fleet SUM is NOT enforced here; per-box \
                     --memory / --pids still are. For a hard fleet bound, run kern as root, or cap each box."
                );
            });
        }
    }
    Ok(())
}

/// The supervision decision for a detached box: `(use_systemd_unit, in_process_restart_always)`, from
/// its flags and whether a `systemd --user` manager exists. A STANDALONE persistent box
/// (`always`/`unless-stopped`, detached, no pod) is supervised by a systemd unit where a manager exists
/// (survives reboot), and FALLS BACK to the in-process supervisor where none does (restart on any exit
/// for this process's lifetime, no reboot-survival) - without which a systemd-less host (WSL2 without
/// systemd, a minimal container) could not run `--restart always` at all. A pod member ALWAYS uses the
/// in-process supervisor (it needs the holder's namespace, which a standalone unit could not re-join).
/// Pure, so the systemd-absent fallback is testable without a live systemd.
fn persistent_supervision(
    detached: bool,
    persistent: bool,
    has_pod: bool,
    systemd_present: bool,
) -> (bool, bool) {
    let standalone = detached && persistent && !has_pod;
    let use_systemd = standalone && systemd_present;
    let restart_always = persistent && (has_pod || (standalone && !use_systemd));
    (use_systemd, restart_always)
}

/// The `KERN_STARTED_FD` write end an SDK passes to receive the unforgeable "box started" byte, or
/// `None`. VALIDATES the fd (`> 2`, never stdin/stdout/stderr, and a live descriptor) but does NOT set
/// FD_CLOEXEC - that is deferred to [`cloexec_started_fd`], called AFTER the `systemd-run --scope`
/// re-exec. A CLOEXEC fd is DROPPED by that re-exec (a plain one is inherited), so marking it here
/// would lose the channel on every host that takes the scope path. Called ONCE, EARLY in `box_run`
/// (before the box is forked). Fail-closed: a fd we cannot even stat is dropped (`None`), since no
/// signal beats a forgeable one. Mirrors [`ready_fd_to_signal`]'s `> 2` discipline.
fn started_signal_fd() -> Option<i32> {
    let fd = std::env::var("KERN_STARTED_FD")
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()?;
    if fd <= 2 {
        return None;
    }
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return None;
    }
    Some(fd)
}

/// Mark the started-fd **FD_CLOEXEC** in the FINAL process - after the `systemd-run --scope` re-exec,
/// which inherits a plain fd but drops a CLOEXEC one. From here the box's execvp closes it, so the
/// workload can never inherit or write it (a byte it wrote would spoof or suppress the signal).
/// Fail-closed: a fd we cannot protect is dropped (`None`), so the SDK reads EOF and falls back to its
/// stderr heuristic (which only ever over-reports a failure, never masks one) rather than trusting a
/// descriptor the workload might reach.
fn cloexec_started_fd(fd: Option<i32>) -> Option<i32> {
    let fd = fd?;
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return None;
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return None;
    }
    Some(fd)
}

/// Print the `kern box` status panel (aligned isolation + resource posture, actionable warnings)
/// to stderr - but ONLY when stderr is a terminal, so pipes/scripts/`kern logs` stay clean. `cpus`
/// is the already-clamped value, so the panel shows the cap that's actually enforced.
fn print_box_status(args: &BoxRunArgs, cpus: Option<f64>) {
    if !std::io::stderr().is_terminal() {
        return;
    }
    let (source, cmd) = display_source_cmd(args);
    let status = crate::ui::BoxStatus {
        name: args.name,
        source,
        cmd: &cmd,
        read_only: args.read_only,
        bind_rootfs: args.bind_rootfs,
        share_net: args.share_net,
        memory: args.memory,
        cpus,
        volumes: args.volumes.len(),
        tty: args.tty,
        seccomp_syscalls: kern_isolation::denied_syscall_count(nesting_active(args.privileged)),
    };
    let p = crate::ui::Palette::detect_stderr();
    let gl = crate::ui::Glyphs::detect();
    // Concise by default - a beginner running `kern box … -- cmd` wants their command's output, not a
    // six-line posture panel. One line ("▸ box 'x' · alpine  ✔ isolated"); `--verbose` expands it to
    // the full panel (with the once-per-session wordmark, which would only be noise on the one-liner).
    if !args.verbose {
        eprint!("{}", crate::ui::box_line(&status, &p, &gl));
        return;
    }
    let w = crate::ui::term_width(libc::STDERR_FILENO);
    if first_box_of_session() {
        eprintln!("{}\n", crate::ui::logo(&p));
    }
    eprint!("{}", crate::ui::box_banner(&status, &p, &gl, w));
}

/// Render an optional value for `--show-config`: the value, or `-` when absent.
fn or_dash<T: std::fmt::Display>(o: Option<T>) -> String {
    o.map_or_else(|| "-".to_string(), |v| v.to_string())
}

/// The box's display source (`--image`, else `--rootfs`) and effective command (defaults to
/// `/bin/sh` when none is given, like docker's COMMAND column). Shared by the status panel and the
/// `--show-config` dry run so the two can't drift.
fn display_source_cmd<'a>(args: &'a BoxRunArgs) -> (&'a str, String) {
    let source = args.image.or(args.rootfs).unwrap_or("");
    let cmd = if args.command.is_empty() {
        "/bin/sh".to_string()
    } else {
        args.command.join(" ")
    };
    (source, cmd)
}

/// `--show-config`: print the resolved box configuration (after profiles, clamps and flag merges) to
/// stdout as plain `key: value` lines, then the caller exits. A dry run - unlike the status panel it
/// always prints (it's the whole point of the command) and goes to stdout so it can be captured.
fn print_resolved_config(
    args: &BoxRunArgs,
    name: &str,
    memory: Option<u64>,
    cpus: Option<f64>,
    cpuset: Option<&str>,
    nice: Option<i32>,
) {
    let (source, cmd) = display_source_cmd(args);
    println!("name: {name}");
    println!("source: {source}");
    println!("command: {cmd}");
    println!("read_only: {}", args.read_only);
    println!("bind_rootfs: {}", args.bind_rootfs);
    println!("share_net: {}", args.share_net);
    println!("memory: {}", or_dash(memory));
    println!("memory_swap_max: {}", or_dash(args.memory_swap_max));
    println!("cpus: {}", or_dash(cpus));
    println!("cpuset: {}", cpuset.unwrap_or("-"));
    println!("pids_limit: {}", or_dash(args.pids_limit));
    println!("nice: {}", or_dash(nice));
    println!("io_weight: {}", or_dash(args.io_weight));
    println!("volumes: {}", args.volumes.len());
    println!("ports: {}", args.ports.len());
    println!("secrets: {}", args.secrets.len());
    println!("cap_add: {}", args.cap_add.join(","));
    println!("cap_drop: {}", args.cap_drop.join(","));
    println!("hostname: {}", args.hostname.unwrap_or("-"));
    println!("user: {}", args.run_as.unwrap_or("-"));
    // The effective uid-range rule the box will actually apply (mirror of `box_run`): explicit
    // --uid-range, OR --ssh, OR a non-root --user (its uid must be mapped in). Derived the same way
    // here so the dry run can't report a different value than the box uses.
    let non_root_user = parse_user(args.run_as)
        .ok()
        .flatten()
        .is_some_and(|(u, _)| u != 0);
    // Report the range AND where it came from. The bare boolean stays a bare boolean (scripts parse
    // these lines), so the provenance is its own key: a caller can see that kern, not they, turned it
    // on, which is the difference between a default one may opt out of and a request one asked for.
    // The dry run runs before the image is resolved, so an image that declares a non-root USER can
    // still promote this to `request` at run time; `image-default` is a floor, never a ceiling.
    let asked = args.uid_range || args.ssh_port.is_some() || non_root_user;
    let by_image = image_default_uid_range(args);
    println!("uid_range: {}", asked || by_image);
    println!(
        "uid_range_source: {}",
        match (asked, by_image) {
            (true, _) => "request",
            (false, true) => "image-default",
            (false, false) => "-",
        }
    );
    println!("tun: {}", args.tun);
    println!("tty: {}", args.tty);
    println!("detached: {}", args.detached);
    println!(
        "timeout: {}",
        or_dash((args.timeout != 0).then_some(args.timeout))
    );
    println!(
        "seccomp_denied_syscalls: {}",
        kern_isolation::denied_syscall_count(nesting_active(args.privileged))
    );
    println!("privileged: {}", nesting_active(args.privileged));
}

/// Whether a `--privileged` request will ACTUALLY relax seccomp for nesting: only rootless (as real
/// host root the flag is refused earlier, but keep the display honest if that path is ever reached).
fn nesting_active(privileged: bool) -> bool {
    privileged && unsafe { libc::geteuid() } != 0
}

/// True the first time a foreground box runs in this login session, recording a marker under
/// `$XDG_RUNTIME_DIR` (tmpfs → cleared on logout, so "once per session") so the wordmark prints
/// once and not before every box. Best-effort: with no runtime dir (can't track) it returns false,
/// better to skip the logo than to reprint it every time. A lost race (two boxes at once) just
/// prints the logo twice, which is harmless.
fn first_box_of_session() -> bool {
    let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") else {
        return false;
    };
    let marker = std::path::Path::new(&dir).join("kern").join(".greeted");
    if marker.exists() {
        return false;
    }
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&marker, b"").is_ok()
}

/// Foreground `-it`: allocate a PTY, hand its slave to the box as a controlling terminal, put the
/// host terminal in raw mode, and let `run_in_sandbox_with` pump bytes between them until the box
/// exits - then restore the terminal and propagate the exit code.
fn run_box_interactive(
    mut spec: SandboxSpec,
    scratch: Option<PathBuf>,
    ports: &[kern_isolation::PortMap],
    timeout: u64,
) -> Result<(), Error> {
    let pty = crate::pty::open().map_err(|e| Error::Sandbox(format!("openpty: {e}")))?;
    spec.tty_slave = Some(pty.slave);
    // THE BOX GETS TO BUILD ITS OWN TERMINAL, and this channel is how its master comes back. The
    // host pair above is opened anyway and stays the fallback: if the box cannot make one (no
    // devpts, a `--rootfs` kern did not populate, a kernel that refused the mount) nothing here
    // changes and the box behaves as it did before. See `kern_isolation::ptybox`.
    let chan = kern_isolation::fd_channel();
    if let Some((parent, child)) = chan {
        spec.pty_sock = Some(child);
        spec.pty_sock_parent = Some(parent);
    }
    let saved = crate::pty::raw_with_resize(pty.master);
    // The master the pump ends up using, so it is closed exactly once at the end whichever pair won.
    let live_master = std::cell::Cell::new(pty.master);
    // `--timeout N`: same host-namespace watchdog as the non-tty path (forked here, before the
    // unshare), so a hung interactive session is force-stopped after N seconds.
    let timeout_wd = (timeout > 0)
        .then(|| spawn_foreground_timeout(timeout))
        .flatten();
    let result = run_in_sandbox_with(
        &spec,
        None,
        |pid1| {
            feed_timeout_pid(timeout_wd, pid1);
            // The child sends at most once and closes; `recv_fd` answers `None` on EOF, so a box
            // that never got there costs one non-blocking-ish read and the host pty stays in charge.
            let m = spec.pty_sock_parent.and_then(kern_isolation::recv_fd)?;
            // The window size was copied onto the HOST master before the fork and `SIGWINCH` was
            // pointed at it. Both have to follow the terminal that is actually in use, or an
            // interactive box would start at the wrong size and never learn about a resize.
            crate::pty::retarget_resize(m);
            live_master.set(m);
            Some(m)
        },
        Some(pty.master),
        ports,
        // `-it`: leave the box tied to the controlling terminal/session, not to a launcher PDEATHSIG -
        // the terminal owns the session and the pty pump already ends the box when the tty closes.
        false,
    );
    cancel_foreground_timeout(timeout_wd);
    if let Some(ref prev) = saved {
        crate::pty::restore(0, prev);
    }
    unsafe {
        libc::close(pty.master);
        // The box's master, when it won, is a DIFFERENT fd and closing only the host one would leak
        // a terminal per interactive box.
        let live = live_master.get();
        if live != pty.master {
            libc::close(live);
        }
        // Both ends of the handover channel: the child end was inherited across the fork and the
        // child closes its copy, but this process holds one too.
        if let Some((parent, child)) = chan {
            libc::close(parent);
            libc::close(child);
        }
    }
    cleanup_scratch(scratch.as_deref());
    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => Err(Error::Setup(e.to_string())), // genuine sandbox-start failure → userns hint
    }
}

/// The effective resources a set of resource profiles contributes. `memory`/`cpus`/`cpuset`/`nice`
/// are pre-seeded from the CLI flags and a `vcpu:` fills only the ones left unset (explicit flags
/// win); `vgpio`/`vdisk` accumulate the resolved device/disk profiles the caller then applies.
#[derive(Default)]
struct AppliedProfiles {
    memory: Option<u64>,
    cpus: Option<f64>,
    cpuset: Option<String>,
    nice: Option<i32>,
    vgpio: Vec<crate::config::ResolvedVgpio>,
    vdisk: Vec<crate::config::ResolvedVdisk>,
}

/// Resolve resource-profile tokens (`vcpu:`/`vgpio:`/`vdisk:`) into `out`. Shared by `run` and `box`;
/// `kern.toml` (the `--config` path, else the default / `KERN_CONFIG`) is loaded once, lazily.
fn apply_profile_list(
    profiles: &[String],
    config: Option<&str>,
    out: &mut AppliedProfiles,
) -> Result<(), Error> {
    use crate::config::ProfileRef;
    if profiles.is_empty() {
        return Ok(());
    }
    // Memoised: this runs once per box, and a large stack made it a per-service disk read.
    let cfg = crate::config::load_cached(config).map_err(Error::Config)?;
    // Multiple `vcpu:` profiles on one box do NOT merge: the FIRST to set each field wins (documented),
    // so a second `vcpu:` is a silent no-op on every field the first already set. That is almost always a
    // typo, so name it - which profile is in force, which are ignored - rather than pick one quietly.
    // Only `vcpu:` needs this: `vgpio:`/`vdisk:` STACK (each adds its own devices/disks), so several are
    // legitimate. Runs once, on the warning path only, so its allocations never touch a normal start.
    let vcpu_names: Vec<&str> = profiles
        .iter()
        .filter_map(|t| match crate::config::classify(t) {
            Some(ProfileRef::Vcpu(n)) => Some(n),
            _ => None,
        })
        .collect();
    if vcpu_names.len() > 1 {
        let all = vcpu_names
            .iter()
            .map(|n| format!("vcpu:{n}"))
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!(
            "kern: warning: {} vcpu: profiles given ({all}); only the first (vcpu:{}) sets each cap it \
             defines - the others are ignored on any field it already set (first-wins). Merge them into \
             one profile with `extends` if you meant to layer them.",
            vcpu_names.len(),
            vcpu_names[0]
        );
    }
    for tok in profiles {
        match crate::config::classify(tok) {
            Some(ProfileRef::Vcpu(name)) => {
                let r = crate::config::resolve_vcpu(&cfg, name).map_err(Error::Config)?;
                out.memory = out.memory.or(r.memory);
                out.cpus = out.cpus.or(r.cpus);
                out.cpuset = out.cpuset.take().or(r.cpuset);
                out.nice = out.nice.or(r.nice);
            }
            Some(ProfileRef::Vgpio(name)) => {
                out.vgpio
                    .push(crate::config::resolve_vgpio(&cfg, name).map_err(Error::Config)?);
            }
            Some(ProfileRef::Vdisk(name)) => {
                out.vdisk
                    .push(crate::config::resolve_vdisk(&cfg, name).map_err(Error::Config)?);
            }
            None => {} // not a profile token - ignored (callers pass only classified tokens)
        }
    }
    Ok(())
}

/// For `run`: peel the leading profile tokens from `command` (plus a `--` separator the parser keeps
/// after the first non-flag token), resolve them into `out`, and return where the real command
/// starts.
fn peel_run_profiles(
    command: &[String],
    config: Option<&str>,
    out: &mut AppliedProfiles,
) -> Result<usize, Error> {
    // A LEADING `--` means the command was explicitly delimited (`kern run -- vcpu:heavy prog`): the
    // `--` end-of-options contract says the following tokens are the literal command, so we must NOT
    // peel a `vcpu:`/`vgpio:`/`vdisk:`-looking token as a profile. Skip the `--` and stop. (Matches the
    // `box` path, which never re-classifies past `--`.)
    if command.first().map(String::as_str) == Some("--") {
        return Ok(1);
    }
    let mut i = 0;
    while i < command.len() && crate::config::classify(&command[i]).is_some() {
        i += 1;
    }
    let profiles = command[..i].to_vec();
    if command.get(i).map(String::as_str) == Some("--") {
        i += 1;
    }
    apply_profile_list(&profiles, config, out)?;
    Ok(i)
}

/// A quota'd named volume couldn't get its ext4-loop backing (unprivileged, or `-d`/`-it`): bind the
/// plain data dir and say the quota isn't enforced - never silently.
fn quota_fallback(name: &str) -> Result<String, Error> {
    eprintln!(
        "kern: volume '{name}' has a quota but it isn't enforced here - the ext4-loop backend needs \
         a plain foreground box as root (or `disk` group); mounted as a plain directory. Note the \
         enforced (ext4 image) and unenforced (data dir) backends hold data separately."
    );
    crate::volume::resolve_named(name)
}

/// Turn a resolved vDisk into a box mount. Rootless (the default): a `size=`-capped `tmpfs` - the box
/// gets a real size quota with no privilege (RAM-backed, ephemeral). `iops`/`bandwidth`/`persistent`
/// need a disk-backed ext4-on-loop backend (root); rather than silently drop them, we say so. (The
/// ext4-loop backend is the next increment; the tmpfs path means a `vdisk:` profile always works.)
fn prepare_vdisk(
    vd: crate::config::ResolvedVdisk,
    ext4_ok: bool,
    work: &std::path::Path,
    handles: &mut Vec<crate::vdisk::Ext4Vdisk>,
    io_max: &mut Vec<String>,
) -> kern_isolation::VdiskMount {
    // Preferred: a real ext4-on-loop disk (needs privilege). Only for a plain foreground box, where
    // the handle's teardown is bounded to `box_run`. `prepare` returns `None` unprivileged → tmpfs.
    if ext4_ok {
        if let Some(size) = vd.size {
            if let Some(h) = crate::vdisk::prepare(
                &vd.name,
                size,
                vd.persistent,
                vd.backend_dir.as_deref(),
                work,
            ) {
                // `--iops`/`--bandwidth` → a cgroup `io.max` line for the loop device backing this
                // vdisk (`MAJ:MIN riops=… wiops=… rbps=… wbps=…`). The box's `apply_limits` writes it;
                // it takes effect only where the `io` controller is delegated (else a no-op, reported).
                if vd.iops.is_some() || vd.bandwidth.is_some() {
                    match h.loop_dev_num() {
                        Some((maj, min)) => {
                            io_max.push(io_max_line(maj, min, vd.iops, vd.bandwidth))
                        }
                        None => eprintln!(
                            "kern: vdisk:{} - could not resolve the loop device for iops/bandwidth",
                            vd.name
                        ),
                    }
                }
                let host_dir = h.mount.to_string_lossy().into_owned();
                handles.push(h);
                return kern_isolation::VdiskMount {
                    name: vd.name,
                    size: vd.size,
                    host_dir: Some(host_dir),
                };
            }
        }
    }
    // `backend = "disk:<pool>"` is an explicit request for a DISK, and this is the path where it did
    // not happen. Until now it only got a message if the profile ALSO set `iops`/`bandwidth`/
    // `persistent`, or asked for >= 1 GiB - so the ordinary case (a disk pool, a modest size) was told
    // nothing at all and got RAM. Found on a root VPS on 2026-08-01: `backend = "disk:pool"`,
    // `size = "64m"`, `mkfs.ext4` present, `/dev/loop-control` writable, and `df` inside the box said
    // `tmpfs`, because the box was `--detach`ed. Name the reason, since the two are fixed differently.
    if vd.backend_dir.is_some() {
        let why = if !ext4_ok {
            "the ext4-loop backend is only used for a FOREGROUND box (its teardown is bounded to the \
             box's run); drop -d / -it to get the disk-backed quota"
        } else {
            "the ext4-loop backend needs privilege: root (or the `disk` group) for /dev/loop-control, \
             plus mkfs.ext4 - see `kern doctor`"
        };
        eprintln!(
            "kern: vdisk:{} asked for a disk backend but is RAM-backed (tmpfs) here: {}. The size cap \
             is still enforced; the data is EPHEMERAL and counts against the box's memory.",
            vd.name, why
        );
    }
    // Rootless fallback: a size-capped tmpfs. Be honest about what it can't do.
    if vd.iops.is_some() || vd.bandwidth.is_some() || vd.persistent {
        eprintln!(
            "kern: vdisk:{} - iops/bandwidth/persistent need the ext4-loop backend (root, foreground \
             box); the rootless tmpfs backend applies only the size cap",
            vd.name
        );
    }
    // The tmpfs is RAM-backed, so `size` counts against RAM (correctly charged to the box's memory
    // cgroup - a write past `--memory` OOM-kills the box, exit 137; verified) AND its data is
    // EPHEMERAL - gone when the box exits. Say both, so a large scratch isn't mistaken for a disk.
    if vd.size.is_some_and(|b| b >= 1 << 30) {
        eprintln!(
            "kern: vdisk:{} is RAM-backed (tmpfs) rootless - its data is EPHEMERAL (gone when the box \
             exits) and its size counts against RAM; pair a large vdisk with --memory (or run a \
             foreground box as root for the persistent ext4 backend)",
            vd.name
        );
    }
    kern_isolation::VdiskMount {
        name: vd.name,
        size: vd.size,
        host_dir: None,
    }
}

/// Build a cgroup v2 `io.max` line for a device: `MAJ:MIN` + read/write IOPS (from `--iops`) and
/// read/write bytes-per-second (from `--bandwidth`), applied symmetrically to reads and writes.
fn io_max_line(maj: u32, min: u32, iops: Option<u64>, bandwidth: Option<u64>) -> String {
    let mut s = format!("{maj}:{min}");
    if let Some(n) = iops {
        s.push_str(&format!(" riops={n} wiops={n}"));
    }
    if let Some(b) = bandwidth {
        s.push_str(&format!(" rbps={b} wbps={b}"));
    }
    s
}

/// Parsed inputs for [`build_spec`].
struct BuildSpec<'a> {
    name: &'a BoxName,
    lower: String,
    cmd: Vec<String>,
    read_only: bool,
    landlock_rw: Vec<String>,
    net_ips: Vec<std::net::Ipv4Addr>,
    pod_bridge: Option<kern_isolation::BridgeAttach>,
    apparmor: Option<String>,
    volumes: Vec<Volume>,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    share_net: bool,
    /// `--pod`: the pod holder PID whose user+net ns this box joins (`None` = its own).
    pod_holder: Option<i32>,
    uid_range: UidRange,
    bind_rootfs: bool,
    /// `--privileged`: relax seccomp for a nested `kern box` (rootless-only).
    privileged: bool,
    /// `--require-limits`: fail-closed if a resource cap cannot be enforced (else best-effort uncapped).
    require_limits: bool,
    /// `--allow-uncapped`: accept running uncapped silently (no best-effort notice). XOR require_limits.
    allow_uncapped: bool,
    /// The box's seccomp filter, RESOLVED by the caller (explicit `KERN_SECCOMP` > profile > default)
    /// into a value, not read from the environment here - see [`resolve_seccomp_mode`].
    seccomp_mode: kern_isolation::SeccompFilter,
    /// INTERNAL (build): a persistent overlay upper dir; overlays `lower` and keeps writes there.
    overlay_upper: Option<String>,
    memory: Option<u64>,
    /// `--shm-size`: an explicit `/dev/shm` cap in bytes. `None` derives one from `memory`.
    shm_size: Option<u64>,
    memory_swap_max: Option<u64>,
    cpus: Option<f64>,
    cpuset: Option<String>,
    vgpio_devs: Vec<String>,
    vgpio_sysfs: Vec<String>,
    vdisks: Vec<kern_isolation::VdiskMount>,
    secrets: Vec<kern_isolation::Secret>,
    ssh: Option<kern_isolation::SshSetup>,
    hostname: Option<String>,
    tun: bool,
    init: bool,
    tmpfs: Vec<kern_isolation::TmpfsMount>,
    run_as: Option<(u32, u32)>,
    /// The supplementary groups the image puts that user in. See
    /// [`crate::commands::image_supplementary_gids`] for why they are resolved and when they are not.
    extra_gids: Vec<u32>,
    pids_max: Option<u64>,
    caps: kern_isolation::CapSpec,
    io_max: Vec<String>,
    io_weight: Option<u64>,
    /// `--add-host NAME:IP` entries (`host-gateway` already resolved to a concrete address).
    extra_hosts: Vec<(String, String)>,
    memory_low: Option<u64>,
    cpu_weight: Option<u64>,
    dns: Vec<String>,
    dns_search: Vec<String>,
    dns_options: Vec<String>,
    /// `--ulimit`, pre-resolved to `(RLIMIT_*, soft, hard)`.
    ulimits: Vec<(i32, u64, u64)>,
    /// `--sysctl KEY=VALUE`, applied inside the box's namespaces.
    sysctls: Vec<(String, String)>,
}

/// Build the sandbox spec. **Always an overlay** (the image/rootfs is the read-only lower; a
/// private upper takes writes) over a scratch tree under the runtime dir, removed after the box
/// exits. `--read-only` then remounts that overlay read-only.
///
/// Why overlay even for `--read-only` (rather than a plain bind + remount-ro): on some kernels a
/// **bind** mount cannot be remounted read-only inside a user namespace (e.g. Android-kernel
/// boards return EPERM - the bind inherits a lock from a host mount the child userns doesn't own),
/// whereas an **overlay** has its own superblock created in the namespace and *can* be remounted
/// read-only. Using overlay for both modes makes `--read-only` work everywhere and keeps the
/// image immutable (writes, when allowed, only ever hit the discarded upper).
///
/// When `--net` shares the host network, the host's `/etc/resolv.conf` is copied into the upper
/// so DNS works out of the box.
/// Resolve the resource-cap posture from the two flags and their env fallbacks, in ONE place, and
/// reject the contradiction on the RESOLVED values rather than on the raw flags. This is what catches
/// the mixed forms a flag-only parse check misses: `--require-limits` paired with `KERN_ALLOW_UNCAPPED`
/// (or `--allow-uncapped` with `KERN_REQUIRE_LIMITS`). `require`/`allow` are `flag || env`, so an env
/// can only ENABLE, never override an explicit flag - the safe direction for a fail-closed control.
/// Pure and total: it reads no environment itself (the caller passes the two resolved env booleans),
/// so it unit-tests every combination without touching the process state.
fn resolve_limit_policy(
    require_flag: bool,
    require_env: bool,
    allow_flag: bool,
    allow_env: bool,
) -> Result<(bool, bool), Error> {
    let require = require_flag || require_env;
    let allow = allow_flag || allow_env;
    if require && allow {
        return Err(Error::Usage(
            "--require-limits and --allow-uncapped are mutually exclusive (one refuses an \
             unenforceable cap, the other accepts it); this also holds when either is set through \
             KERN_REQUIRE_LIMITS or KERN_ALLOW_UNCAPPED",
        ));
    }
    Ok((require, allow))
}

fn build_spec(b: BuildSpec) -> Result<(SandboxSpec, Option<PathBuf>), Error> {
    // Hostname: `--hostname` wins, else the box name (the box's own UTS namespace, so it's private).
    let hostname = b
        .hostname
        .clone()
        .unwrap_or_else(|| b.name.as_str().to_string());

    // `--bind-rootfs`: skip the overlay and bind the rootfs directly. On kernels with a slow
    // overlayfs mount (some Android-kernel boards: ~31 ms for an overlay vs ~8 ms for a bind) this
    // is the difference between winning and losing on raw start. The trade-off - accepted by the
    // explicit flag - is that the source is mutable and shared: writes land in the rootfs dir and
    // boxes sharing one rootfs are not isolated from each other. There is no overlay scratch.
    //
    // Unlike the overlay path, we deliberately do NOT inject `/etc/resolv.conf` here even with
    // `--net`: that would be a host-side, privileged write into the user-supplied rootfs, and a
    // symlink there (e.g. `/etc/resolv.conf -> ../../host/file`) would make it clobber a file
    // *outside* the rootfs. A bind-mode box uses whatever `/etc/resolv.conf` its rootfs already
    // ships (`--net` still gives outbound networking; add a resolv.conf to the rootfs if needed).
    // The rootfs strategy is the ONLY thing that differs between bind and overlay: pick
    // `(root, mode, overlay, cleanup)` here, then build the one shared SandboxSpec below (its ~27
    // other fields were duplicated field-for-field in both branches - a silent-drift hazard).
    let (root, mode, overlay, eph): (String, MountMode, Option<OverlayDirs>, Option<PathBuf>) = if b
        .bind_rootfs
    {
        (b.lower, MountMode::Bind, None, None)
    } else {
        // The writable overlay upper. Normally an ephemeral scratch (discarded on exit). For a `kern
        // build` RUN step (`overlay_upper` set) the UPPER persists in the build tree so successive RUN/
        // COPY steps accumulate into it (the "diff" layer). overlayfs requires upperdir and workdir to be
        // on the SAME filesystem, so in build mode BOTH live under the build tree (work is cleared each
        // step - overlay wants a fresh workdir); only `merged` (a bare mountpoint) stays ephemeral.
        let eph = scratch_dir().join(format!("{}-{}", b.name.as_str(), std::process::id()));
        // Create the ephemeral parent once (0700) so the per-leaf creates below (`upper`/`work`/`merged`,
        // all under `eph` in the common case) are a single bare mkdir each instead of each re-walking
        // and re-stat-ing the shared parent chain - a few fewer serial pre-fork syscalls per box.
        // Name the directory. `overlay scratch: Permission denied (os error 13)` was the whole
        // message, and a reader cannot act on it: the path is derived from `$XDG_RUNTIME_DIR` when
        // that is set, so the fix is usually to unset or correct a variable the message never
        // mentioned. `scratch_dir` now falls back when that variable is unusable, so reaching this
        // error means the fallback failed too - which makes the path the only useful thing to say.
        own_only_dir(&eph)
            .map_err(|e| Error::Sandbox(format!("overlay scratch {}: {e}", eph.display())))?;
        let merged = eph.join("merged");
        let (upper, work) = match &b.overlay_upper {
            Some(dir) => {
                let root = PathBuf::from(dir);
                let w = root.join("work");
                // overlayfs REQUIRES an empty workdir, so this is a precondition, not tidying. Left
                // discarded, a refused removal surfaced later as a bare `mount: invalid argument` with
                // no way to connect it to the leftover directory that caused it.
                match std::fs::remove_dir_all(&w) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(Error::Sandbox(format!(
                            "overlay work dir {}: cannot clear it, and overlayfs requires it empty: {e}",
                            w.display()
                        )))
                    }
                }
                (build_upper_dir(&root), w)
            }
            None => (eph.join("upper"), eph.join("work")),
        };
        own_only_dir(&upper).map_err(|e| Error::Sandbox(format!("overlay upper: {e}")))?;
        // overlayfs presents the merged root's mode as the UPPER dir's mode. The upper is 0700 (own-only)
        // by default, which makes the box's `/` un-traversable by ANY dropped, cap-less non-root uid →
        // exec/read fails EACCES on `/` itself (the first path component). A `--user` uid hits this, but
        // so does the far more common case: an OCI image whose ENTRYPOINT drops privilege internally
        // (postgres/redis/mysql/nginx `setpriv`/`gosu` to a service uid) - there is no `--user`, yet the
        // workload still ends up non-root and needs a world-traversable `/`. So give the box a normal
        // 0755 root (exactly like a real rootfs) whenever privilege MIGHT be dropped: an explicit
        // non-root `--user`, OR a `--uid-range` box (which exists precisely to run such images). This is
        // the fix for the "official images don't start" gap. It's safe: the HOST scratch dir is still
        // 0700 (no other host user can enter), and root=0755 is the norm for every real filesystem -
        // it's the in-box view only, and the box's isolation is the namespace, not the root's mode.
        //
        // A POD MEMBER (`pod_holder` set) gets the same treatment: it joins a shared user namespace that
        // may map a subordinate uid range (`pod create --uid-range`), and its image may drop privilege to
        // a service uid - but the box's own `uid_range` flag is false there (the range lives on the pod
        // holder, not this box), so it must be included explicitly or postgres/redis/… in a pod hit the
        // exact EACCES-on-`/` gap this whole block fixes. Harmless for a single-uid pod (no other uid to
        // traverse). Found via a live python+postgres pod stack: the entrypoint's `gosu postgres` drop
        // could not traverse the 0700 `/`, so every PATH lookup failed "not found".
        let root_traversable = matches!(b.run_as, Some((u, _)) if u != 0)
            || b.uid_range.is_on()
            || b.pod_holder.is_some();
        if root_traversable {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&upper, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| Error::Sandbox(format!("overlay upper perms: {e}")))?;
        }
        for d in [&work, &merged] {
            std::fs::create_dir_all(d).map_err(|e| Error::Sandbox(format!("scratch dir: {e}")))?;
        }
        // With `--net` sharing the host network, copy the host's resolv.conf into the upper so DNS
        // resolves inside the box. A private copy → the box can't touch the host's file, and it's
        // removed with the scratch. (Best-effort: no host resolv.conf → IPs still work.)
        if b.share_net {
            if let Ok(conf) = std::fs::read("/etc/resolv.conf") {
                let etc = upper.join("etc");
                // Best-effort, and now audible. A box whose `resolv.conf` could not be written still
                // runs and still reaches every literal IP, so this must not fail the box - but silence
                // turned "DNS does not resolve in here" into a symptom with no stated cause.
                let placed = std::fs::create_dir_all(&etc)
                    .and_then(|()| std::fs::write(etc.join("resolv.conf"), conf));
                if let Err(e) = placed {
                    eprintln!(
                        "kern: warning: could not place /etc/resolv.conf in the box: {e} - \
                         name resolution will not work inside it (literal IPs still do)"
                    );
                }
            }
        }
        (
            merged.to_string_lossy().into_owned(),
            MountMode::Overlay,
            Some(OverlayDirs {
                lower: b.lower,
                upper: upper.to_string_lossy().into_owned(),
                work: work.to_string_lossy().into_owned(),
            }),
            // Clean up work/merged (and, when the upper is ephemeral, the upper too) after the box
            // exits; a build's persistent upper lives outside `eph`, owned by the build driver.
            Some(eph),
        )
    };

    // Resolve the cap posture from flags + env in ONE place, and reject the contradiction on the
    // RESOLVED values (so `--require-limits` + `KERN_ALLOW_UNCAPPED`, and every other mix, is caught -
    // a flag-only parse check would miss the env combinations).
    let (require_limits, allow_uncapped) = resolve_limit_policy(
        b.require_limits,
        kern_common::env_flag("KERN_REQUIRE_LIMITS"),
        b.allow_uncapped,
        kern_common::env_flag("KERN_ALLOW_UNCAPPED"),
    )?;

    let spec = SandboxSpec {
        root,
        mode,
        overlay,
        read_only: b.read_only,
        landlock_rw: b.landlock_rw,
        net_ips: b.net_ips,
        pod_bridge: b.pod_bridge,
        apparmor: b.apparmor,
        command: b.cmd,
        hostname,
        volumes: b.volumes,
        env: b.env,
        workdir: b.workdir,
        share_net: b.share_net,
        pod_holder: b.pod_holder,
        uid_range: b.uid_range,
        memory_max: b.memory,
        // `--shm-size` when given, else the cap that is ACTUALLY in force: `--memory` when the operator
        // set one, and kern's own 512 MiB default when they did not. Resolved here because this is
        // where that default lives - `SandboxSpec::memory_max` carries the raw flag, so deriving from
        // it inside the isolation crate left the common case (no `--memory`) unsized, which is the
        // exact case that was reporting half the HOST's RAM to a box the cgroup holds at 512 MiB.
        shm_max: Some(
            b.shm_size
                .unwrap_or_else(|| b.memory.unwrap_or(SCOPE_MEMORY_MAX_BYTES)),
        ),
        memory_swap_max: b.memory_swap_max,
        cpuset: b.cpuset,
        cpus: b.cpus,
        tty_slave: None,
        pty_sock: None,
        pty_sock_parent: None,
        vgpio_devs: b.vgpio_devs,
        vgpio_sysfs: b.vgpio_sysfs,
        vdisks: b.vdisks,
        secrets: b.secrets,
        ssh: b.ssh,
        tun: b.tun,
        init: b.init,
        tmpfs: b.tmpfs,
        run_as: b.run_as,
        extra_gids: b.extra_gids,
        pids_max: b.pids_max,
        caps: b.caps,
        io_max: b.io_max,
        io_weight: b.io_weight,
        extra_hosts: b.extra_hosts,
        memory_low: b.memory_low,
        cpu_weight: b.cpu_weight,
        dns: b.dns,
        dns_search: b.dns_search,
        dns_options: b.dns_options,
        ulimits: b.ulimits,
        sysctls: b.sysctls,
        privileged: b.privileged,
        // Resolved above (flag || env, contradiction rejected). `--require-limits`/`KERN_REQUIRE_LIMITS`
        // fail-closed; `--allow-uncapped`/`KERN_ALLOW_UNCAPPED` accept-uncapped; mutually exclusive.
        require_limits,
        allow_uncapped,
        // The seccomp filter, RESOLVED ONCE by the caller (`resolve_seccomp_mode`: explicit
        // `KERN_SECCOMP` > `--security-profile` > default) into `b.seccomp_mode` - a value, never a
        // re-read of the environment here. PID 1 installs it and the instance record carries it, so
        // `kern exec` reproduces the box's filter (a profile-set allowlist reproduces as allowlist, not
        // as the wider denylist). Single point of resolution for the box's whole lifetime.
        seccomp_mode: b.seccomp_mode,
    };
    // Audit mode is a validation aid, deliberately LESS confined than the shipped denylist (its
    // log-and-run default lets clone3/io_uring RUN instead of returning ENOSYS). Warn loudly, once per
    // box, so it can never be mistaken for a production posture on an operator who set the env by habit.
    if spec.seccomp_mode == kern_isolation::SeccompFilter::AllowlistAudit {
        eprintln!(
            "kern: warning: KERN_SECCOMP=allowlist-audit is a VALIDATION mode - it records the syscalls a \
             real allowlist would refuse but LETS THEM RUN (clone3, io_uring, and every other \
             ENOSYS-denied call), so the box is LESS confined than the default allowlist. The kill set \
             still kills; do NOT use this as a production posture."
        );
    }
    Ok((spec, eph))
}

/// The third field of a `-v` spec: mount options kern reads, and options it accepts and does not act
/// on.
///
/// `z` AND `Z` ARE SELINUX RELABEL REQUESTS, and refusing them cost a whole stack. Docker relabels
/// the host path so a confined container may read it; kern sets no SELinux label on anything, so the
/// request is satisfied by there being nothing to relabel. MEASURED on Supabase's own
/// `docker-compose.yml`, 587 lines and 11 services: three of its binds carry `:z`/`:Z` and the first
/// box refused to start with `bad -v … (expected src:dst[:ro])`, which named the wrong thing - the
/// spec was not malformed, it was Docker's.
///
/// THE macOS PERFORMANCE HINTS ARE THE SAME SHAPE: `cached`, `delegated` and `consistent` describe
/// how a bind is synchronised through a VM that does not exist on Linux, and Docker itself ignores
/// them there. `nocopy` asks that a named volume NOT be seeded from the image, which kern reads.
///
/// AN UNKNOWN OPTION IS STILL AN ERROR. The table is a list of things kern has decided about; a
/// value nobody has decided about must not be silently dropped, because the next one may be a
/// boundary.
fn volume_option(opt: &str) -> Option<VolumeOpt> {
    match opt {
        "ro" => Some(VolumeOpt::ReadOnly),
        "rw" => Some(VolumeOpt::ReadWrite),
        "nocopy" => Some(VolumeOpt::NoCopy),
        // SELinux relabelling and the macOS consistency hints: accepted, acted on by nobody here.
        "z" | "Z" | "cached" | "delegated" | "consistent" => Some(VolumeOpt::Inert),
        _ => None,
    }
}

/// What one `-v` option means to kern.
#[derive(Clone, Copy, PartialEq, Eq)]
enum VolumeOpt {
    ReadOnly,
    ReadWrite,
    /// Do not seed an empty named volume from the image.
    NoCopy,
    /// Recognised, and there is nothing for kern to do about it.
    Inert,
}

/// Parse `-v src:dst[:opt,opt…]` specs into [`Volume`]s. The target must be absolute; the source is a
/// volume name, an absolute path, or a `./`-style path relative to the current directory, and must
/// exist on the host. The options are read by [`volume_option`].
fn parse_volumes(specs: &[String]) -> Result<Vec<Volume>, Error> {
    let mut out = Vec::with_capacity(specs.len());
    for s in specs {
        let parts: Vec<&str> = s.split(':').collect();
        let (source, target, read_only) = match parts.as_slice() {
            [src, dst] => (*src, *dst, false),
            // THE OPTION FIELD IS A COMMA-SEPARATED LIST, which is what Docker accepts: `:ro,z` is
            // one field with two options, and splitting on `:` alone made it a fourth part and an
            // error. The last of `ro`/`rw` wins, as it does for a mount option list.
            [src, dst, opts] => {
                let mut ro = false;
                for opt in opts.split(',').filter(|o| !o.is_empty()) {
                    match volume_option(opt) {
                        Some(VolumeOpt::ReadOnly) => ro = true,
                        Some(VolumeOpt::ReadWrite) => ro = false,
                        Some(VolumeOpt::NoCopy | VolumeOpt::Inert) => {}
                        None => {
                            return Err(Error::Sandbox(format!(
                                "bad -v '{s}': unknown mount option '{opt}' (kern reads ro, rw and \
                                 nocopy, and accepts z, Z, cached, delegated and consistent)"
                            )))
                        }
                    }
                }
                (*src, *dst, ro)
            }
            _ => {
                return Err(Error::Sandbox(format!(
                    "bad -v '{s}' (expected src:dst[:ro])"
                )))
            }
        };
        // The target is always an absolute, `.`/`..`-free, NUL-free path inside the box.
        if !target.starts_with('/') {
            return Err(Error::Sandbox(format!("-v '{s}': target must be absolute")));
        }
        if target.contains('\0') {
            return Err(Error::Sandbox(format!("-v '{s}': target has a NUL byte")));
        }
        if target.split('/').any(|c| c == "." || c == "..") {
            return Err(Error::Sandbox(format!(
                "-v '{s}': target must not contain '.' or '..'"
            )));
        }
        // Refuse to shadow the box's own essential mounts: a `-v` exactly over `/`, `/proc`, `/sys` or
        // `/dev` would hide the sandbox's isolation setup (masked proc/sys, minimal dev). A SUBPATH
        // (e.g. `/dev/foo`, `/data`) is fine - only these exact roots are protected. Normalize the way
        // the mount actually resolves it (`open_in_root` splits on '/' and drops empty components), so
        // a leading-double-slash target like `//dev` - which trims to a non-matching string but still
        // resolves to `/dev` at mount time - can't slip past this guard.
        let comps: Vec<&str> = target.split('/').filter(|c| !c.is_empty()).collect();
        if comps.is_empty() || matches!(comps.as_slice(), ["proc"] | ["sys"] | ["dev"]) {
            let shown = if comps.is_empty() {
                "/".to_string()
            } else {
                format!("/{}", comps.join("/"))
            };
            return Err(Error::Sandbox(format!(
                "-v '{s}': cannot mount over {shown} (a box essential mount)"
            )));
        }
        // A NAMED volume resolves to its data dir (auto-created on first use); a PATH is
        // canonicalized symlink-free, so a missing source is rejected here rather than as an opaque
        // post-fork mount failure. `canonicalize` resolves a relative path (`.`, `./src`,
        // `../shared`) against the current directory, which is what makes `-v .:/app` work. No
        // containment guard on purpose: unlike compose, which confines binds under the project dir,
        // a direct CLI invocation can already name any absolute path, so resolving a relative one
        // grants nothing new and refusing `../shared:/x` would only break a legitimate call.
        // `volume::classify` owns the name-or-path decision so this site cannot disagree with it.
        let source = match crate::volume::classify(source) {
            crate::volume::SourceKind::Named => crate::volume::resolve_named(source)?,
            crate::volume::SourceKind::Path => {
                // A MISSING SOURCE IS CREATED, WHICH IS WHAT DOCKER DOES and what compose files are
                // written against: "if you bind-mount a directory that does not yet exist, Docker
                // creates it on the host for you". kern refused, and a file that relies on it
                // stopped with a bare errno. MEASURED on two of Docker's own samples in one sitting:
                // `pihole-cloudflared-DoH` binds `/etc/pihole/` and `wireguard` binds
                // `/usr/share/appdata/wireguard/config`.
                //
                // CREATED ONLY WHERE THE CALLER ALREADY COULD, which is the whole difference between
                // this and Docker's daemon: `create_dir_all` runs as the user, so a path under
                // `/etc` or `/usr` fails with EACCES and is reported instead of being made. kern is
                // rootless, so the rule needs no policy of its own - the kernel is the policy.
                //
                // THE REGISTRY IS CHECKED BEFORE ANYTHING IS CREATED, on the nearest ancestor that
                // exists. The guard below runs on the canonical path and cannot run before the path
                // is there, so creating first would let a compose file plant empty directories
                // inside the registry and have the mount refused afterwards - the refusal would be
                // correct and the directories would still be there.
                if !std::path::Path::new(source).exists() {
                    if let Some(planned) = planned_bind_source(source) {
                        if !crate::registry::path_overlaps_trusted_state(&planned) {
                            let _ = std::fs::create_dir_all(source);
                        }
                    }
                }
                let canon = std::fs::canonicalize(source).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        Error::Sandbox(format!(
                            "-v '{s}': source {source} does not exist and kern could not create it. \
                             Docker's daemon creates a missing bind source as root; kern is \
                             rootless, so it can only create one where you could yourself. Create \
                             it first, or point the mount at a path you own"
                        ))
                    } else {
                        Error::Sandbox(format!("-v '{s}': source {source}: {e}"))
                    }
                })?;
                // A box that can WRITE the kern registry can forge a PEER box's recorded capability/
                // seccomp posture and elevate that peer's `kern exec` (proven, adversarial review).
                // Refuse to bind a trust-bearing registry dir - or a parent that contains one - into
                // any box. Named volumes resolve in the SIBLING branch above and are unaffected.
                if crate::registry::path_overlaps_trusted_state(&canon) {
                    return Err(Error::Sandbox(format!(
                        "-v '{s}': refusing to mount the kern registry ({}) into a box - a box able \
                         to write it could forge another box's recorded capability/seccomp posture \
                         and elevate its own `kern exec`",
                        canon.display()
                    )));
                }
                canon.to_string_lossy().into_owned()
            }
            crate::volume::SourceKind::Neither => {
                return Err(Error::Sandbox(format!(
                    "-v '{s}': source must be a volume name or a path (absolute, or ./ or ../)"
                )))
            }
        };
        out.push(Volume {
            source,
            target: target.to_string(),
            read_only,
        });
    }
    Ok(out)
}

/// The command a box/exec runs when none is given.
const DEFAULT_SHELL: &str = "/bin/sh";

/// `command` if non-empty, else a one-element argv of [`DEFAULT_SHELL`].
fn default_if_empty(command: &[String]) -> Vec<String> {
    if command.is_empty() {
        vec![DEFAULT_SHELL.to_string()]
    } else {
        command.to_vec()
    }
}

/// Parse `--env K=V` specs. The value may contain `=`; the key may not be empty.
fn parse_envs(specs: &[String]) -> Result<Vec<(String, String)>, Error> {
    let mut out = Vec::with_capacity(specs.len());
    for s in specs {
        match s.split_once('=') {
            Some((k, v)) if !k.is_empty() => out.push((k.to_string(), v.to_string())),
            _ => return Err(Error::Sandbox(format!("bad --env '{s}' (expected K=V)"))),
        }
    }
    Ok(out)
}

/// Parse `--env-file PATH` files with Docker's `.env` rules, through the compose crate's reader -
/// the ONE implementation of that format. Later files (and `--env`) override earlier keys by list
/// order; a line that binds nothing is refused by name rather than skipped.
fn parse_env_files(paths: &[String]) -> Result<Vec<(String, String)>, Error> {
    let mut out = Vec::new();
    for p in paths {
        // Route through the ONE guarded host-file reader: `--env-file` delivers a file's K=V lines into
        // the box's env, so `--env-file <runtime>/kern/instances/<peer>` would inject a peer's posture
        // record (`capdropall=`, `seccompmode=`, …) - the same class `--secret` and `-v` are guarded for.
        let bytes = crate::secret::read_host_file_for_box(p, "--env-file")?;
        let body = String::from_utf8(bytes)
            .map_err(|_| Error::Sandbox(format!("--env-file '{p}' is not valid UTF-8")))?;
        // A LINE THAT BINDS NOTHING IS STILL AN ERROR, and it is checked here rather than left to
        // the reader below: `parse_dotenv` is deliberately total (it skips what it cannot read, so
        // one stray line cannot take a whole stack down), and a `--env-file` the caller named
        // explicitly deserves to be told instead. Both properties, one pass each.
        for (n, raw) in body.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if !line.contains('=') && !line.contains(':') {
                return Err(Error::Sandbox(format!(
                    "bad line {} in --env-file '{p}' (expected K=V): {line}",
                    n + 1
                )));
            }
        }
        // ONE READER OF THE `.env` FORMAT, and it is the compose crate's, which implements Docker's
        // rules: `export ` tolerated, `K:V` as well as `K=V`, quotes stripped with single-quoted
        // values left literal, an inline ` #` comment removed, and `${VAR}` interpolated for
        // unquoted and double-quoted values. This function used to be a second, cruder reader -
        // split on the first `=`, keep the rest verbatim - and the two disagreed about the same
        // file. MEASURED on Zabbix, whose `.env_srv` ends a line with ` # Available since 6.0.0`:
        // the comment reached the box as part of the value and `zabbix_server` exited with
        // `invalid "NodeAddress" configuration parameter`, naming a config key nobody had written
        // that way.
        out.extend(crate::compose::parse_dotenv(&body).into_pairs());
    }
    Ok(out)
}

/// Validate a `--hostname` before it reaches `sethostname`: a DNS-label-ish name (letters/digits/`.`/
/// `-`, no leading/trailing `-`/`.`, ≤ 64, no `/` or NUL). `None` → keep the default (the box name).
fn validate_hostname(h: Option<&str>) -> Result<Option<String>, Error> {
    let Some(h) = h else { return Ok(None) };
    let ok = !h.is_empty()
        && h.len() <= 64
        && !h.starts_with(['-', '.'])
        && !h.ends_with(['-', '.'])
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    if ok {
        Ok(Some(h.to_string()))
    } else {
        Err(Error::Sandbox(format!(
            "invalid --hostname '{h}' (letters/digits/-/. only, no leading/trailing -/., ≤64)"
        )))
    }
}

/// Is this path `/dev/pts`, however it is spelled?
///
/// Split out so the refusal above and the test below read the SAME predicate: a message that fires on
/// the wrong path is worse than the generic one it replaces, so both directions have to be pinned to
/// one definition rather than to two that can drift.
///
/// Empty components are dropped exactly as the mount resolves them, so `//dev/pts`, `/dev//pts` and a
/// trailing slash all fold onto the same answer, while `/dev/ptsx` and `/dev/pts/x` do not.
fn is_dev_pts_path(path: &str) -> bool {
    is_dev_leaf(path, "pts")
}

/// Is this path exactly `/dev/<leaf>`, however it is spelled?
///
/// One predicate for the two places that need it (`/dev/pts` and `/dev/shm`), because they are the
/// same rule with a different word and two copies of it would drift on the next spelling anyone
/// thinks of.
fn is_dev_leaf(path: &str, leaf: &str) -> bool {
    let mut parts = path.split('/').filter(|c| !c.is_empty());
    parts.next() == Some("dev") && parts.next() == Some(leaf) && parts.next().is_none()
}

/// Mount option names kern RECOGNISES in a `--tmpfs` suffix but does not act on.
///
/// Recognised and not honoured are different things, and the caller says which: kern mounts every
/// `--tmpfs` with `MS_NOSUID | MS_NODEV` and `mode=1777`, read-write, so `rw`/`nosuid`/`nodev` are
/// already true and `ro`/`noexec`/`suid`/`dev`/`mode=` are not. Listing them here means a compose
/// file written for Docker parses instead of dying, and the warning below means nobody believes the
/// flag took effect. An option NOT in this list is refused by name rather than dropped, because a
/// typo silently ignored is how `--tmpfs /run:sze=64m` becomes an unsized tmpfs.
const TMPFS_KNOWN_OPTS: [&str; 22] = [
    "rw",
    "ro",
    "exec",
    "noexec",
    "suid",
    "nosuid",
    "dev",
    "nodev",
    "sync",
    "async",
    "atime",
    "noatime",
    "diratime",
    "nodiratime",
    "relatime",
    "norelatime",
    "strictatime",
    "lazytime",
    "nolazytime",
    "mand",
    "nomand",
    "remount",
];

/// Key=value tmpfs options kern recognises and does not forward. `size` is handled separately: it is
/// the one kern implements.
const TMPFS_KNOWN_KEYS: [&str; 5] = ["mode", "uid", "gid", "nr_blocks", "nr_inodes"];

/// Is `t` a bare tmpfs size, kern's own `PATH:64m` spelling?
fn is_bare_tmpfs_size(t: &str) -> bool {
    let core = t
        .strip_suffix(['k', 'm', 'g', 't', 'K', 'M', 'G', 'T'])
        .unwrap_or(t);
    !core.is_empty() && core.bytes().all(|b| b.is_ascii_digit())
}

/// Parse `--tmpfs PATH[:opts]` specs into `(path, size)` - `size` a tmpfs `size=` token (`"64m"`),
/// empty for the kernel default. The path must be absolute, `.`/`..`/NUL-free, and not shadow a
/// hardened mount (`/proc`, `/sys`, `/dev`).
///
/// THE SUFFIX IS A COMMA-SEPARATED OPTION LIST, WHICH IS DOCKER'S GRAMMAR, and it is parsed here
/// because parsing it in two places is what broke. kern's own spelling is `PATH:64m`; Docker's is
/// `PATH:size=64m,mode=1770,uid=1000`. `kern-compose` used to pre-chew the second into the first and
/// decided which it had by asking whether the suffix contained an `=` at all, so an option list with
/// no `=` in it was read as a size:
///
///     compose  tmpfs /run:size=64m                  accepted
///     compose  tmpfs /run:rw,noexec,nosuid,size=64m accepted
///     compose  tmpfs /run:rw                        REFUSED, "bad size 'rw'"
///     compose  tmpfs /run:exec                       REFUSED, "bad size 'exec'"
///     box --tmpfs /run:size=64m                      REFUSED, "bad size 'size=64m'"
///     box --tmpfs /run:64m                           accepted
///
/// The last two are the same binary disagreeing with itself: the CLI refused the spelling compose
/// accepted, and accepted the one compose could not produce. Two grammars, one of them reachable
/// only through the other. Now there is one, here, and `tmpfs_value` forwards the entry untouched.
///
/// Found by running 245 real `docker-compose.yml` files from public repositories through
/// `compose config`; `scripts/compose-corpus-gate.py` keeps it found.
fn parse_tmpfs(specs: &[String]) -> Result<Vec<kern_isolation::TmpfsMount>, Error> {
    let mut out = Vec::with_capacity(specs.len());
    for s in specs {
        let (path, suffix) = match s.split_once(':') {
            Some((p, sz)) => (p, sz),
            None => (s.as_str(), ""),
        };
        // Split the suffix into what kern APPLIES (size, mode, noexec, ro) and what it only
        // RECOGNISES. An unknown token is an error rather than a drop: dropping a typo is how a cap
        // goes missing.
        //
        // THE RECOGNISED LIST SHRANK, and what left it is now enforced rather than announced. `mode`
        // sets the mount's mode, `noexec` and `ro` set `MS_NOEXEC` and `MS_RDONLY`, and their
        // opposites (`exec`, `rw`) are the defaults so they are satisfied by doing nothing. What
        // stays in the list is what kern will not do: `suid` and `dev` ask for a weaker mount than
        // kern's floor, and the timestamp/sync knobs have no effect on a RAM-backed filesystem this
        // process mounts for one box.
        let mut size = String::new();
        let mut mode = String::new();
        let (mut uid, mut gid) = (String::new(), String::new());
        let (mut noexec, mut read_only) = (false, false);
        let mut recognised: Vec<&str> = Vec::new();
        for tok in suffix.split(',').filter(|t| !t.is_empty()) {
            match tok.split_once('=') {
                Some(("size", v)) => size = v.to_string(),
                // AN OCTAL MODE, CHECKED HERE, because it travels to `mount(2)` as text: a value
                // the kernel cannot parse makes the whole mount fail, and the box would then be
                // missing a `/tmp` with nothing said about why.
                Some(("mode", v)) => {
                    let ok = !v.is_empty()
                        && v.len() <= 4
                        && v.bytes().all(|b| (b'0'..=b'7').contains(&b));
                    if !ok {
                        return Err(Error::Sandbox(format!(
                            "--tmpfs '{s}': mode '{v}' is not octal (e.g. 1777, 0755)"
                        )));
                    }
                    mode = v.to_string();
                }
                // `uid=`/`gid=` ARE APPLIED NOW. They are the tmpfs mount's own options, the box
                // sets them at mount time, and the sandbox retries without them when the user
                // namespace does not map the id - so asking for an ownership kern cannot give costs
                // the ownership and never the mount. Validated here as digits: the value travels to
                // `mount(2)` as text, and one the kernel cannot parse fails the whole mount.
                Some((k @ ("uid" | "gid"), v)) => {
                    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(Error::Sandbox(format!(
                            "--tmpfs '{s}': {k} '{v}' is not a numeric id"
                        )));
                    }
                    if k == "uid" {
                        uid = v.to_string();
                    } else {
                        gid = v.to_string();
                    }
                }
                Some((k, _)) if TMPFS_KNOWN_KEYS.contains(&k) => recognised.push(tok),
                Some(_) => {
                    return Err(Error::Sandbox(format!(
                        "--tmpfs '{s}': unknown option '{tok}' (kern implements size=, mode=, \
                         noexec and ro, and recognises the usual mount flags)"
                    )))
                }
                None if tok == "noexec" => noexec = true,
                None if tok == "ro" => read_only = true,
                // `exec` and `rw` are kern's defaults, so they are honoured by not acting.
                None if tok == "exec" || tok == "rw" => {}
                // `nosuid` AND `nodev` ARE ALREADY APPLIED, so asking for them is not a loss and
                // must not be reported as one. MEASURED on a running box:
                // `tmpfs /scratch tmpfs rw,nosuid,nodev,relatime,...`. The sentence below even says
                // kern "mounts every --tmpfs nosuid and nodev, which it will not relax", and it was
                // printed for files that asked for exactly that: on the corpus, 6 files carried
                // this as their ONLY difference from Docker.
                None if tok == "nosuid" || tok == "nodev" => {}
                None if TMPFS_KNOWN_OPTS.contains(&tok) => recognised.push(tok),
                None if is_bare_tmpfs_size(tok) => size = tok.to_string(),
                None => {
                    return Err(Error::Sandbox(format!(
                        "--tmpfs '{s}': bad size or unknown option '{tok}' (a size is digits + \
                         optional k/m/g/t, e.g. 64m)"
                    )))
                }
            }
        }
        if !recognised.is_empty() {
            // Say it once per entry, and say what kern DOES rather than only what it ignores: the
            // reader's next question after "ignored" is always "so what did I get".
            eprintln!(
                "kern: --tmpfs '{path}': option(s) {} recognised but not applied - kern applies \
                 size=, mode=, noexec and ro, and mounts every --tmpfs nosuid and nodev, which it \
                 will not relax",
                recognised.join(",")
            );
        }
        if !path.starts_with('/')
            || path.contains('\0')
            || path.split('/').any(|c| c == "." || c == "..")
        {
            return Err(Error::Sandbox(format!(
                "--tmpfs '{s}': path must be absolute, without '.'/'..'/NUL"
            )));
        }
        // Normalize like the mount resolves it (drop empty components) so a leading-double-slash path
        // (`//proc`) can't slip past. Block the hardened roots AND anything under them: the first real
        // path component being proc/sys/dev is the test.
        let first = path.split('/').find(|c| !c.is_empty());
        if matches!(first, Some("proc") | Some("sys") | Some("dev")) {
            // `/dev/pts` GETS ITS OWN SENTENCE, because the generic refusal sends the reader to the
            // wrong conclusion at the one place they are most likely to hit it. Issue #8 is
            // `forkpty(3)` failing in a box with no devpts; the reporter's workaround was
            // `tmpfs: /dev/pts`, and that spelling now lives in a public issue thread. Someone who
            // arrives there, copies the compose as written and retries on a FIXED binary gets
            // "refused" and concludes kern still does not work - when their problem is already
            // solved and the fix is to delete two lines.
            //
            // The refusal itself stays: a tmpfs over `/dev/pts` would cover the private devpts the
            // box now mounts and reintroduce exactly the failure. What changes is that the message
            // states the mount is already there, which is what makes the refusal actionable instead
            // of terminal.
            if is_dev_pts_path(path) {
                return Err(Error::Sandbox(
                    "--tmpfs '/dev/pts' is refused: the box already mounts a private devpts there \
                     (so forkpty/openpty work), and a tmpfs over it would break exactly that. \
                     Remove the entry."
                        .to_string(),
                ));
            }
            // `/dev/shm` GETS ITS OWN SENTENCE for the same reason `/dev/pts` does, and it is the
            // single most common `tmpfs:` entry in real compose files: `tmpfs: - /dev/shm` is the
            // standard workaround for Docker's 64 MB `/dev/shm`, which breaks Postgres and Chrome
            // under load. Someone carrying that idiom to kern reads the generic refusal and concludes
            // the shared-memory problem is unsolved here, when it never existed.
            //
            // ⛔ THE MESSAGE MUST NOT POINT AT `shm_size:`. kern-compose RECOGNISES that key and
            // ignores it on purpose, with its reason written beside it, so naming it would send the
            // reader to write a line that does nothing.
            //
            // WHAT IT SAYS INSTEAD IS MEASURED, because the first draft of this sentence claimed
            // `/dev/shm` is mounted UNSIZED and that is false. `df -h /dev/shm` inside a box:
            //
            //     --memory 32M     32.0M          --memory 256M    256.0M
            //     no flags        512.0M          --shm-size 8m      8.0M
            //
            // It IS sized, and the size TRACKS the memory cap unless `--shm-size` overrides it. That
            // is the fact worth telling someone carrying Docker's idiom over, and it is a different
            // fact from "there is no limit".
            if is_dev_leaf(path, "shm") {
                return Err(Error::Sandbox(
                    "--tmpfs '/dev/shm' is refused, and the entry is not needed: kern already sizes \
                     /dev/shm to the box's memory cap, so there is no 64 MB default to work around. \
                     Remove the entry; set it explicitly with --shm-size, or raise --memory \
                     (compose: `mem_limit`)."
                        .to_string(),
                ));
            }
            return Err(Error::Sandbox(format!(
                "--tmpfs '{path}' is refused (it would shadow the sandbox's hardened /proc, /sys or /dev)"
            )));
        }
        // A `size=` VALUE still has to be a size: `size=wat` reached here as a recognised key with a
        // value nobody checked, and an unchecked cap is no cap.
        if !size.is_empty() && !is_bare_tmpfs_size(&size) {
            return Err(Error::Sandbox(format!(
                "--tmpfs '{s}': bad size '{size}' (digits + optional k/m/g/t, e.g. 64m)"
            )));
        }
        out.push(kern_isolation::TmpfsMount {
            path: path.to_string(),
            size: size.to_ascii_lowercase(),
            mode,
            uid,
            gid,
            noexec,
            read_only,
        });
    }
    Ok(out)
}

/// Parse `--user UID[:GID]` into `(uid, gid)` (a bare `UID` uses `UID` for the gid too). Numeric only
/// - a user namespace maps ids, not names. `None` → keep the box's namespace root.
fn parse_user(spec: Option<&str>) -> Result<Option<(u32, u32)>, Error> {
    let Some(s) = spec else { return Ok(None) };
    let bad = || Error::Sandbox(format!("--user '{s}': expected UID or UID:GID (numeric)"));
    let (uid, gid) = match s.split_once(':') {
        Some((u, g)) => (
            u.parse::<u32>().map_err(|_| bad())?,
            g.parse::<u32>().map_err(|_| bad())?,
        ),
        None => {
            let u = s.parse::<u32>().map_err(|_| bad())?;
            (u, u)
        }
    };
    Ok(Some((uid, gid)))
}

// Subuid/subgid range resolution and the trusted id-map helper lookup are the ONE authoritative
// implementation in kern-isolation (`sub_range` / `trusted_helper` / `username`), reused here so the
// cleanup path can't drift from the box-start path.

/// Human-readable summary of `-p` mappings for `kern ps`, always showing the bind address so the
/// exposure is visible at a glance (e.g. `127.0.0.1:8080->80, 0.0.0.0:443->443`).
/// Comma-joined **named volumes** a box mounts (from its `-v name:/dst` specs) - recorded in the
/// registry so `kern volume rm` can refuse to delete a volume still in use. Host paths and network
/// URLs are skipped (only named volumes matter here).
fn mounted_named_volumes(specs: &[String]) -> String {
    let mut names: Vec<String> = specs
        .iter()
        .filter(|s| !crate::volume::is_network(s))
        .filter_map(|s| {
            let src = s.split(':').next().unwrap_or("");
            crate::volume::is_named(src).then(|| src.to_string())
        })
        .collect();
    names.sort();
    names.dedup();
    names.join(",")
}

fn ports_summary(ports: &[kern_isolation::PortMap]) -> String {
    ports
        .iter()
        .map(crate::ports::fmt)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The user's systemd unit directory (`$XDG_CONFIG_HOME/systemd/user`, else `~/.config/systemd/user`).
fn user_systemd_dir() -> Result<PathBuf, Error> {
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME") {
        if !x.is_empty() {
            return Ok(PathBuf::from(x).join("systemd/user"));
        }
    }
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .ok_or_else(|| {
            Error::Sandbox("HOME not set - cannot locate the systemd user dir".into())
        })?;
    Ok(PathBuf::from(home).join(".config/systemd/user"))
}

/// Run `systemctl --user <args>` quietly; `true` on success. Used for the persistent-box unit.
fn systemctl_user(args: &[&str]) -> bool {
    std::process::Command::new("systemctl")
        .arg("--user")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Quote one argv element for a systemd `ExecStart=` line: wrap in double quotes and escape the
/// characters systemd would otherwise act on - `"`/`\` (C-escapes), `$` (env expansion → `$$`), and
/// `%` (specifier → `%%`). Keeps arbitrary box names/commands/paths intact when systemd re-runs us.
fn systemd_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    for c in arg.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '$' => out.push_str("$$"),
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Memory + task ceilings for a sandbox scope. `MemorySwapMax=0` makes `MemoryMax` a HARD total
/// cap - without it, a workload over the RAM cap just swaps (on a host with swap) instead of OOM.
/// In BYTES, because the scope's ceiling is the box's cap plus `SCOPE_SUPERVISOR_HEADROOM` (kern's own
/// supervisor lives in the scope, in its own leaf, and must not eat into what the workload asked for).
const SCOPE_MEMORY_MAX_BYTES: u64 = 512 * 1024 * 1024;
const SCOPE_SWAP_MAX: &str = "MemorySwapMax=0";
const SCOPE_TASKS_MAX: &str = "TasksMax=512";

/// Where the "this host cannot enforce resource caps" notice records that it has been shown.
///
/// Persistent user data, so it survives a reboot: the host property it records does too, since it
/// comes from the kernel command line. Mirrors [`crate::volume::volumes_dir`] and
/// [`crate::builds::builds_dir`] rather than inventing a fourth location rule.
fn uncapped_notice_path() -> PathBuf {
    if let Some(x) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(x).join("kern").join("uncapped-notice");
    }
    if let Some(h) = std::env::var_os("HOME") {
        return PathBuf::from(h).join(".local/share/kern/uncapped-notice");
    }
    PathBuf::from(format!("/tmp/kern-uncapped-notice-{}", unsafe {
        libc::getuid()
    }))
}

/// True the first time this host is told its resource caps are not enforceable, false afterwards.
///
/// `create_new` is `O_CREAT|O_EXCL`, so two boxes starting at the same instant race in the kernel
/// and exactly one of them prints. A `Once` alone would not do: it is per PROCESS, and every box is
/// a new process, which is precisely how this ends up on every line.
///
/// FAILURE MODES, each decided rather than left to chance:
///   * marker already there  -> `AlreadyExists` -> false. The steady state, one `openat` that fails.
///   * parent dir missing    -> created, then retried once. A first run has no `~/.local/share/kern`.
///   * cannot create at all  -> TRUE, every time. A read-only HOME with no writable `/tmp` is rare;
///     an unbounded box is worth a repeated line more than it is worth silence, so this fails loud.
///   * host later fixed      -> the marker is stale and the notice stays quiet, which is correct:
///     `memory_cap_enforceable()` is checked FIRST, so a host that now enforces never reaches here.
fn claim_uncapped_host_notice() -> bool {
    claim_notice_at(&uncapped_notice_path())
}

/// Testable core of [`claim_uncapped_host_notice`]. Split for the same reason `config::load_impl` is:
/// the wrapper reads `XDG_DATA_HOME`/`HOME`, and a test that set those would be mutating
/// process-global state under a parallel test runner.
fn claim_notice_at(path: &std::path::Path) -> bool {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    match opts.open(path) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(_) => {
            if let Some(parent) = path.parent() {
                if std::fs::create_dir_all(parent).is_err() {
                    return true;
                }
            }
            match opts.open(path) {
                Ok(_) => true,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
                Err(_) => true,
            }
        }
    }
}

/// If a systemd user manager is available and we aren't already inside a kern scope, re-exec
/// the whole `kern` invocation under `systemd-run --user --scope` with cgroup caps, so the
/// sandbox (and any fork bomb in it) is hard-limited. This replaces the process on success; on
/// any failure it returns and the caller falls back to the best-effort cgroup path.
/// Parameters for [`reexec_in_scope_if_possible`], grouped into one value (the caps plus the three
/// posture bits) so the call is a single argument rather than an 8-wide positional list.
struct ScopeReexec<'a> {
    memory: Option<u64>,
    memory_swap_max: Option<u64>,
    cpuset: Option<&'a str>,
    cpus: Option<f64>,
    pids_max: Option<u64>,
    /// May this invocation take the direct `kern.slice` path and skip the per-box systemd scope?
    ///
    /// Granted by a caller that leaves a process behind to `rmdir` the leaf afterwards: `kern box`,
    /// whose supervisor forks the box, and `kern run`, which forks its workload on that path for
    /// exactly this reason (`run_forked_under_direct_caps`). A caller that `exec()`s in place with
    /// nothing left behind must NOT grant it - the scope's `--collect` is then the only cleanup there
    /// is.
    allow_direct: bool,
    /// A FOREGROUND box dies with its launcher (arm PDEATHSIG across the exec into systemd-run).
    die_with_parent: bool,
    /// `--allow-uncapped`/`KERN_ALLOW_UNCAPPED`: suppress the once-per-host "not enforced" notice.
    allow_uncapped: bool,
}

/// The ceiling the per-box SCOPE gets, in bytes: the box's own `--memory` (or the default) plus kern's
/// supervisor headroom.
///
/// The scope holds kern's bookkeeping AND the box; the box itself is capped at EXACTLY what was asked
/// for, by the inner `kern-box-*` child (see `prepare_delegated_scope`). The two ceilings must not be
/// equal: charges are counted at every level, so an equal outer one is reached FIRST - by exactly the
/// supervisor's share - and the box would be killed by the scope's OOM, which takes the supervisor with
/// it and loses the exit code. A pure function so that arithmetic is checked on every run, including
/// the `saturating_add`: a `--memory` near `u64::MAX` must not wrap the scope's ceiling down to a tiny
/// number and make every box OOM instantly.
fn scope_memory_max(memory: Option<u64>) -> u64 {
    memory
        .unwrap_or(SCOPE_MEMORY_MAX_BYTES)
        .saturating_add(kern_isolation::SCOPE_SUPERVISOR_HEADROOM)
}

/// The scope re-exec parent (proxy). Blocks on `read_fd` until the re-exec'd kern signals the scope is
/// up (one byte) or the child chain closes the pipe (EOF = `systemd-run` failed before the box started).
/// On a byte: forward the catchable fatal signals to `child` (`systemd-run`), wait for it, and `exit`
/// with its code - never returns. On EOF: reap `child` and RETURN, so the caller falls back.
fn scope_reexec_proxy(child: libc::pid_t, read_fd: i32) {
    let mut byte = [0u8; 1];
    let n = loop {
        let r = unsafe { libc::read(read_fd, byte.as_mut_ptr().cast(), 1) };
        if r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break r;
    };
    unsafe { libc::close(read_fd) };
    if n <= 0 {
        // `systemd-run` died before the scope existed. Reap the child, then fall back.
        reap(child);
        return;
    }
    // THE BASELINE, read here rather than before the wait, and from the CHILD rather than from us.
    //
    // The byte means the re-exec'd kern reached `main` inside the scope, so the box's cgroup exists
    // and the workload has not run yet: the first moment the right directory can be named, and still
    // before anything can allocate.
    //
    // From the child because kern's own ancestors answer for the box only when the two share one.
    // Measured on a root VPS: kern sits in `/user.slice/user-0.slice/session-N.scope` and the box
    // lands in `/system.slice/kern-box-N.scope`, whose only common ancestor is the cgroup root, which
    // never exposes `memory.events`. The kill happened and this message never printed, on precisely
    // the hosts where the cap binds. `systemd-run --scope` puts the child INSIDE the scope, so its
    // cgroup is the box's and the parent of that is the slice that outlives it.
    let oom_dir = kern_isolation::oom_kill_dir_for_pid(child);
    // Nothing to overlap here: on this path the box's own launcher sweeps after it spawns
    // (`sweep_orphans_off_hot_path`), and this process is only a proxy in front of `systemd-run`.
    std::process::exit(proxy_child_to_exit(child, oom_dir.as_deref(), || {}));
}

/// Become a transparent proxy for `child` and return the code the caller must exit with: forward the
/// catchable fatal signals to it, wait, and translate its status (`128 + signal` when it was killed).
///
/// `oom_dir` is the cgroup whose `memory.events` answers "did the kernel's OOM killer fire while this
/// ran": the box's own leaf where the caller knows it exactly (`kern run`'s direct path), or the
/// nearest ancestor that survives the child where it does not (the scope path, where `--collect`
/// removes the box's own cgroup before this can read it). `None` disables the message rather than
/// guessing.
///
/// SPLIT OUT OF [`scope_reexec_proxy`] rather than copied, because it now has two callers and the part
/// that is easy to get subtly wrong is not the waiting: it is reading the OOM counter from the SAME
/// directory before and after. Measured on a root VPS, an earlier version that read the "after" from
/// kern's own ancestors instead compared two unrelated subtrees and printed the message on one run and
/// not the next two, which reads as a kernel race and is a wrong line of code.
///
/// `while_it_runs` is work that must happen in this process AFTER the fatal-signal handlers are armed
/// and BEFORE the wait, and it exists for one job: garbage collection that overlaps the workload
/// instead of preceding it. Putting it before the arming would widen the window in which a Ctrl-C
/// takes the proxy's default action and orphans the workload; putting it before the fork would put its
/// cost on the start path, which is the mistake `sweep_orphans_off_hot_path` was written to undo. The
/// scope caller passes a no-op.
///
/// THE WINDOW IS NOT CLOSED, only kept at its floor: between the caller's `fork` and the `sigaction`
/// below, a SIGINT still kills this process by default and leaves the workload running with no parent
/// to reap it. Blocking the signals across the fork would close it and would put the burden on the
/// CHILD to restore the mask before `execve` - an inherited block is a workload that ignores Ctrl-C,
/// which is a worse and far more likely failure than a race of a few microseconds. The scope path has
/// carried the same window since it grew this proxy, and there it is LONGER (it waits on the readiness
/// pipe first).
///
/// Never returns to a caller that intends to keep running: the code it hands back is an exit status.
pub(crate) fn proxy_child_to_exit(
    child: libc::pid_t,
    oom_dir: Option<&std::path::Path>,
    while_it_runs: impl FnOnce(),
) -> i32 {
    // THE BASELINE, read before the wait and from the directory the caller resolved. On the scope path
    // the readiness byte has arrived, so the box's cgroup exists and the workload has not run yet; on
    // the direct path the leaf was created moments ago and is empty. Both are the first instant at
    // which the right directory can be named.
    let oom_before = oom_dir.and_then(kern_isolation::oom_kill_count_at);
    // The scope is up and the box runs under `systemd-run` (our child). Forward the catchable fatal
    // signals so Ctrl-C and a SIGTERM reach `systemd-run` (which relays them to the box) and the proxy
    // does not die first and orphan the wait. This path is `!die_with_parent` (detached / `kern run`):
    // there is no PDEATHSIG, and an uncatchable proxy SIGKILL simply leaves `systemd-run` and the box
    // running - correct for a detached box, and matching `kern run`'s no-die-with-launcher contract.
    SCOPE_PROXY_CHILD.store(child, std::sync::atomic::Ordering::SeqCst);
    // Install via `sigaction` (the codebase convention, not `signal`): explicit persistent-handler
    // semantics with no SysV one-shot reset, `SA_RESTART` so the `waitpid` below resumes instead of
    // failing with EINTR, and an `sa_mask` blocking the sibling fatal signals so one forward cannot
    // interrupt another mid-`kill`.
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = scope_proxy_forward as extern "C" fn(libc::c_int) as libc::sighandler_t;
        act.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut act.sa_mask);
        for &sig in &[libc::SIGINT, libc::SIGTERM, libc::SIGQUIT, libc::SIGHUP] {
            libc::sigaddset(&mut act.sa_mask, sig);
        }
        for &sig in &[libc::SIGINT, libc::SIGTERM, libc::SIGQUIT, libc::SIGHUP] {
            libc::sigaction(sig, &act, std::ptr::null_mut());
        }
    }
    while_it_runs();
    let status = reap(child);
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    };
    // A BOX KILLED BY ITS OWN MEMORY CAP MUST NOT VANISH IN SILENCE.
    //
    // 137 is `128 + SIGKILL` and SIGKILL has many senders, so on its own it tells an operator
    // nothing. Measured before this: `kern run -- python3 -c "bytearray(900*1024*1024)"` against the
    // default cap exits 137 with EMPTY output and the workload simply disappears. kern applied the
    // limit, the limit fired, and kern said nothing, which is the failure this codebase calls the
    // expensive one. It costs more on a device with UNIFIED memory, where GPU allocations are
    // charged to the same cap: on a Jetson Orin Nano the vgpu probe was killed this way on every run
    // until the cap was raised, and the only symptom was an empty screen.
    //
    // The claim is kept to what was measured, and how much it can claim depends on which directory
    // the caller resolved. On the scope path the box's own cgroup is gone (`--collect`), so this reads
    // a hierarchical ANCESTOR counter before and after, which says the OOM killer fired in this
    // subtree and not which process it took; `kern run`'s direct path passes the leaf itself, where the
    // counter is the workload's own. One wording covers both, and it is the weaker one - "fired in
    // kern's cgroup while it ran" is true in either case, and claiming more on the path that could
    // support it would mean two messages to keep honest instead of one.
    if code == 128 + libc::SIGKILL {
        // THE SAME DIRECTORY AS THE BEFORE, which is the whole point of resolving it once. Reading
        // the after with `oom_kill_count()` compares the box's slice against KERN's OWN ancestors:
        // two unrelated counters, so `b > a` is decided by whichever subtree happened to be busier.
        // Measured on a root VPS, where those are different branches entirely: the same binary
        // printed the message on one run and stayed silent on the next two. That intermittency was
        // this line, not a kernel race.
        let after = oom_dir.and_then(kern_isolation::oom_kill_count_at);
        if let (Some(a), Some(b)) = (oom_before, after) {
            if b > a {
                eprintln!(
                    "kern: the workload was killed by the kernel's OOM killer, which fired in \
                     kern's cgroup while it ran. A box gets a memory cap it cannot exceed; raise it \
                     with `--memory <size>` (or `memory = \"<size>\"` in a vcpu: profile) if the \
                     workload needs more. On a device with unified memory, GPU allocations count \
                     against the same cap."
                );
            }
        }
    }
    code
}

/// The `systemd-run` child pid, for the async-signal-safe forwarding handler in the scope proxy.
static SCOPE_PROXY_CHILD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Async-signal-safe: relay a catchable fatal signal from the proxy to `systemd-run` (`kill` and an
/// atomic load are both async-signal-safe).
extern "C" fn scope_proxy_forward(sig: libc::c_int) {
    let child = SCOPE_PROXY_CHILD.load(std::sync::atomic::Ordering::SeqCst);
    if child > 0 {
        unsafe { libc::kill(child, sig) };
    }
}

/// The fd `main` should write the scope-readiness byte to, resolved from the environment. Returns
/// `Some(fd)` ONLY for a legitimate scope re-exec: `KERN_SCOPE` must be set (the outer parent sets both
/// it and `KERN_SCOPE_READY_FD` on the `systemd-run` command, so they always arrive together), AND the
/// value must be a real, NON-STANDARD descriptor (> 2). This refuses a `KERN_SCOPE_READY_FD` planted in
/// the environment by a caller without the matching re-exec, so kern never writes a stray byte to or
/// closes its own std streams (0/1/2), or an arbitrary descriptor, on an env var's say-so.
pub(crate) fn ready_fd_to_signal(scope_set: bool, val: Option<&std::ffi::OsStr>) -> Option<i32> {
    if !scope_set {
        return None;
    }
    let fd = val?.to_str()?.trim().parse::<i32>().ok()?;
    (fd > 2).then_some(fd)
}

/// Max bytes moved per `splice` in the pump: large enough to amortise the syscall across a flood, small
/// enough that one call can't monopolise the pump or overshoot the rotation boundary by much.
const PUMP_SPLICE_CHUNK: usize = 1 << 20;

/// Open `path` for log writing (`O_WRONLY|O_CREAT|O_CLOEXEC`, mode 0600), with `O_APPEND` iff `append`.
/// Returns the fd, or `-1` on error. The capped pump opens WITHOUT `O_APPEND` - it is the sole writer and
/// drives the offset itself via `splice`, whose interaction with `O_APPEND` is not guaranteed across
/// kernels - while the uncapped `open_log_direct` fallback opens WITH `O_APPEND` because the box writes
/// to it directly and its two inherited stdio streams stay ordered only through the append flag.
fn open_log(path: &std::path::Path, append: bool) -> i32 {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return -1;
    };
    let flags =
        libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC | if append { libc::O_APPEND } else { 0 };
    unsafe { libc::open(c.as_ptr(), flags, 0o600) }
}

impl Drop for CappedLog {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

/// True if the LIVE box `b` satisfies every `--filter` (AND semantics). Keys are pre-validated by
/// [`ps`]. `name` is a substring match (like `docker ps --filter name=`), `id` is an exact host-pid
/// match, `status` is running/paused/orphaned. `status=exited`/`dead` is answered by [`exited_matches`]
/// against the `waitexit` breadcrumb, not here, so a live box correctly fails those.
fn ps_matches(b: &registry::Instance, filters: &[(String, String)]) -> bool {
    filters.iter().all(|(k, v)| match k.as_str() {
        "name" => b.name.contains(v.as_str()),
        // Exact pod match - the grouping key `compose ps` scopes on. Exact, not substring: two stacks
        // whose pod names share a prefix must never be listed as one.
        "pod" => b.pod == *v,
        // `label=k=v` matches an exact pair; `label=k` matches the key whatever its value - the two
        // forms Docker supports. Matching is over the comma-joined field, so a bare key must not be
        // satisfied by a mere substring of another key (`app` must not match `apple=1`): compare the
        // key segment up to its `=`.
        "label" => b.labels.split(',').filter(|l| !l.is_empty()).any(|l| {
            l == v.as_str()
                || (!v.contains('=') && l.split_once('=').map(|(k, _)| k) == Some(v.as_str()))
        }),
        "id" => b.pid.to_string() == *v,
        // Mirror `box_status`'s priority so the filter never drifts from the STATUS column: orphaned
        // wins, and a `running`/`paused` query must therefore EXCLUDE an orphaned box (its supervisor
        // is dead - it is not simply running).
        "status" => match v.as_str() {
            "orphaned" => b.orphaned,
            "running" => !b.orphaned && !registry::is_paused(b.cgroup_pid()),
            "paused" => !b.orphaned && registry::is_paused(b.cgroup_pid()),
            _ => false,
        },
        _ => false, // unreachable: keys are validated in `ps` before this runs (fail closed anyway)
    })
}

/// The `ps_matches` twin for an EXITED box (`kern ps -a`). Same filter keys, but an exited box has no
/// live cgroup to read `paused`/`orphaned` from and did not keep its `labels`: a `status=running`
/// query therefore correctly excludes it, and `label=` matches nothing. Only `status=exited` accepts
/// it - kern has no `dead` state, so `status=dead` matches nothing (Docker's `dead` is a failed
/// removal kern cannot produce).
fn exited_matches(e: &registry::ExitedBox, filters: &[(String, String)]) -> bool {
    filters.iter().all(|(k, v)| match k.as_str() {
        "name" => e.name.contains(v.as_str()),
        "pod" => e.pod == *v,
        "id" => e.pid.to_string() == *v,
        "status" => v == "exited",
        _ => false,
    })
}

/// One box's display status: `paused` (frozen by `kern pause`), else its health-check verdict, else
/// `empty` when no health check is configured. The single source of truth for `ps`'s HEALTH column,
/// `ps --format {{.Status}}`, and `--filter status=` - so they never drift on what "paused" means.
fn box_status(b: &registry::Instance, empty: &str) -> String {
    // ORPHANED wins over every other status: the supervisor is dead but the box's PID 1 / `-p` forwarder
    // are still running (and still holding the host port). Surfacing it is the whole point - the box used
    // to vanish from `ps` here - and `kern stop <name>` reaps it via `cgroup.kill`.
    if b.orphaned {
        return "orphaned".to_string();
    }
    if registry::is_paused(b.cgroup_pid()) {
        return "paused".to_string();
    }
    let h = registry::health_of(&b.name, b.pid);
    if h.is_empty() {
        empty.to_string()
    } else {
        h
    }
}

/// Append `s` to `out`, turning the two-char escapes `\t`/`\n` into a tab / newline (the docker
/// `--format` convention); any other backslash is kept verbatim. Pure.
fn push_unescaped(out: &mut String, s: &str) {
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.peek() {
                Some('t') => {
                    out.push('\t');
                    it.next();
                }
                Some('n') => {
                    out.push('\n');
                    it.next();
                }
                _ => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
}

/// The fields `ps --format` reads, so ONE template renderer serves both a live [`registry::Instance`]
/// and an exited [`registry::ExitedBox`] (Docker's `ps -a --format`). An exited box has no live
/// rootfs/ports left to report; those render empty rather than as a stale value.
trait PsRow {
    fn ps_name(&self) -> &str;
    fn ps_pid(&self) -> i32;
    fn ps_image(&self) -> String;
    fn ps_command(&self) -> String;
    fn ps_ports(&self) -> &str;
    fn ps_pod(&self) -> &str;
    fn ps_running_for(&self, now: u64) -> String;
    fn ps_status(&self) -> String;
}

impl PsRow for registry::Instance {
    fn ps_name(&self) -> &str {
        &self.name
    }
    fn ps_pid(&self) -> i32 {
        self.pid
    }
    fn ps_image(&self) -> String {
        crate::ui::scrub(&self.rootfs)
    }
    fn ps_command(&self) -> String {
        crate::ui::scrub(&self.command)
    }
    fn ps_ports(&self) -> &str {
        &self.ports
    }
    fn ps_pod(&self) -> &str {
        &self.pod
    }
    fn ps_running_for(&self, now: u64) -> String {
        fmt_uptime(now.saturating_sub(self.started))
    }
    fn ps_status(&self) -> String {
        box_status(self, "running")
    }
}

impl PsRow for registry::ExitedBox {
    fn ps_name(&self) -> &str {
        &self.name
    }
    fn ps_pid(&self) -> i32 {
        self.pid
    }
    fn ps_image(&self) -> String {
        String::new()
    }
    fn ps_command(&self) -> String {
        crate::ui::scrub(&self.command)
    }
    fn ps_ports(&self) -> &str {
        ""
    }
    fn ps_pod(&self) -> &str {
        &self.pod
    }
    fn ps_running_for(&self, _now: u64) -> String {
        format!("{} ago", fmt_uptime(self.exited_ago))
    }
    fn ps_status(&self) -> String {
        format!("exited ({})", self.code)
    }
}

/// Render one box through a `ps --format` template: the `{{.Field}}` placeholders below, plus `\t`/`\n`
/// in literal text. A Go-template with logic (ranges/conditionals/functions) is NOT supported: an
/// unterminated `{{` or an unknown token is a hard error (use `--json` for arbitrary shaping). Validated
/// fields (name/pod/ports/status) are borrowed straight in; the UNTRUSTED command/rootfs are
/// control-scrubbed first so a crafted box argv or `--rootfs` can't inject ANSI escapes into the
/// terminal (the same guard the `ps` table, `images`, and `--json` already apply).
fn render_ps_format<R: PsRow>(tmpl: &str, b: &R, now: u64) -> Result<String, Error> {
    let mut out = String::with_capacity(tmpl.len());
    let mut rest = tmpl;
    while let Some(open) = rest.find("{{") {
        push_unescaped(&mut out, &rest[..open]);
        let after = &rest[open + 2..];
        let close = after
            .find("}}")
            .ok_or(Error::Usage("ps --format: unterminated `{{`"))?;
        match after[..close].trim() {
            ".Names" | ".Name" => out.push_str(b.ps_name()),
            ".ID" | ".Pid" => out.push_str(&b.ps_pid().to_string()),
            ".Image" | ".Rootfs" => out.push_str(&b.ps_image()),
            ".Command" => out.push_str(&b.ps_command()),
            ".Ports" => out.push_str(b.ps_ports()),
            ".Pod" => out.push_str(b.ps_pod()),
            ".RunningFor" => out.push_str(&b.ps_running_for(now)),
            ".Status" => out.push_str(&b.ps_status()),
            _ => {
                return Err(Error::Usage(
                    "ps --format: unsupported token (supported: {{.Names}} {{.Pid}} {{.Image}} \
                     {{.Command}} {{.Ports}} {{.Pod}} {{.Status}} {{.RunningFor}}; use --json for more)",
                ))
            }
        }
        rest = &after[close + 2..];
    }
    push_unescaped(&mut out, rest);
    Ok(out)
}

/// A JSON number field, or `null` when the value is absent (`stats`/`inspect`). One definition so the
/// two emitters render a missing metric the same way.
fn json_num(v: Option<u64>) -> String {
    v.map_or_else(|| "null".to_string(), |n| n.to_string())
}

/// Human-readable byte size - the shared [`kern_common::fmt_bytes`] convention (`ps`/`stats` columns).
pub(crate) fn human_bytes(b: u64) -> String {
    kern_common::fmt_bytes(b)
}

/// `remove_dir_all` that can also delete an extracted OCI image.
///
/// An image ships directories with their original modes, and real images ship read-only ones: alpine's
/// `/proc` is `r-xr-xr-x`, amazonlinux adds `/root`, `/boot` and `/sbin`. Unlinking a child needs WRITE
/// on its parent directory, so `std::fs::remove_dir_all` stops at the first of them with EACCES, and so
/// does `rm -rf`, which leaves the tree too - but `rm` REPORTS it and exits 1. kern's defect was the
/// other half: it printed to stderr and returned Ok, so `kern gc --images && echo cleaned` printed
/// "cleaned" over an untouched cache while `rm -rf ... && echo cleaned` prints nothing. An earlier
/// version of this comment claimed `rm` exits 0, measured by reading `$?` after a pipe - which reads
/// the exit of `head`, not of `rm`. The rule against that is written down in this project, and it was
/// broken in the act of producing the false claim. 62 such directories sat in this machine's cache,
/// which is why `kern gc --images` had never actually cleared it.
///
/// Also called by `doctor` on overlayfs workdirs, a different shape of tree entirely: their
/// `work/work` is mode 000, created by uid 0 inside a user namespace that maps to the caller's
/// real uid, so the chmod reaches it. The paragraph above describes only the OCI-image caller.
///
/// We own these directories, so the fix is to restore write permission on the way down and then remove.
/// Only ever applied to a path kern created inside its own cache, and only to DIRECTORIES: file modes
/// are irrelevant to unlinking and are left alone. Symlinks are unlinked, never followed, so a link
/// pointing out of the tree cannot lead the chmod anywhere.
pub(crate) fn remove_tree_forced(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    // Every failure names the path AND why. "Permission denied" on its own sent me hunting through 3 GB
    // of cache for the one directory that blocked it: it was owned by uid 100999, a subuid left by a
    // layer built with `--uid-range`. An unprivileged user cannot chmod what it does not own, so that
    // case is genuinely unremovable from here, and the message says so rather than leaving it to be
    // discovered.
    let annotate = |e: std::io::Error, at: &std::path::Path| -> std::io::Error {
        let me = unsafe { libc::getuid() };
        let owner = std::fs::symlink_metadata(at).map(|m| m.uid()).ok();
        let why = match owner {
            Some(u) if u != me => format!(
                "{} is owned by uid {u}, not you - a layer built with --uid-range leaves subuid-owned files that an unprivileged user cannot remove",
                at.display()
            ),
            _ => at.display().to_string(),
        };
        std::io::Error::new(e.kind(), format!("{e} at {why}"))
    };
    let md = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(annotate(e, path)),
    };
    if !md.is_dir() {
        return std::fs::remove_file(path).map_err(|e| annotate(e, path));
    }
    // u+rwx on this directory first, or its own entries cannot be listed or unlinked. An extracted OCI
    // image ships read-only directories with their original modes (alpine's `/proc` is r-xr-xr-x;
    // amazonlinux adds `/root`, `/boot`, `/sbin`), and unlinking a child needs WRITE on its parent, so
    // `std::fs::remove_dir_all` stops at the first one with EACCES. So does `rm -rf`, which leaves the
    // tree, but `rm` reports it and exits 1; kern's defect was printing to stderr and returning Ok.
    // 62 such directories sat in this machine's cache, which is why
    // `kern gc --images` had never actually cleared it.
    let mode = md.permissions().mode();
    if mode & 0o700 != 0o700 {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | 0o700));
    }
    for entry in std::fs::read_dir(path).map_err(|e| annotate(e, path))? {
        let entry = entry.map_err(|e| annotate(e, path))?;
        remove_tree_forced(&entry.path())?;
    }
    std::fs::remove_dir(path).map_err(|e| annotate(e, path))
}

/// [`remove_tree_forced`], and then the same thing again as root of an id-mapped namespace if the
/// first attempt could not finish.
///
/// A SUBUID-OWNED DIRECTORY IS UNREMOVABLE FROM HERE, and now it is the normal case. Layers are
/// unpacked with the image's own ownership preserved (that is what lets a service write its own data
/// directory), so an image built around a non-root user leaves directories this process does not own
/// and cannot chmod - and unlinking inside a directory needs write permission ON THAT DIRECTORY.
/// MEASURED before this existed: `kern rmi kibana:7.16.1` printed "removed image, freed 1.1G" and
/// left 85 entries behind, four of them subuid-owned.
///
/// Inside the mapped namespace those ids are ours and `CAP_DAC_OVERRIDE` applies, so the retry can
/// finish what the first pass started. The first pass is kept, and runs first, because it needs no
/// fork at all and handles every ordinary tree.
pub(crate) fn remove_tree_mapped(path: &std::path::Path) -> std::io::Result<()> {
    let first = remove_tree_forced(path);
    if first.is_ok() {
        return first;
    }
    let owned = path.to_path_buf();
    match kern_isolation::with_id_mapped_userns(move |_| {
        i32::from(remove_tree_forced(&owned).is_err())
    }) {
        Ok(0) => Ok(()),
        // The retry ran and still could not finish, or no namespace could be mapped: report the
        // FIRST error, which names the path and the owner that blocked it. The second attempt's
        // failure would say the same thing with less context.
        _ => first,
    }
}

/// cgroup v2 CPU period (µs) for `cpu.max` (`cpu.max = "<quota> <period>"`, cores = quota/period).
/// Matches the value the isolation layer uses at box start so a live update stays consistent.
const CPU_PERIOD_US: u64 = 100_000;

/// Write one cgroup v2 control file for [`update`]. On failure returns a short reason string. The
/// delegation hint is appended ONLY for the delegation-shaped errnos (EACCES/EPERM/ENOENT/ENODEV); a
/// value the kernel rejects (e.g. EINVAL) is left to speak for itself rather than misattributed to
/// delegation.
fn write_cgroup(cg: &std::path::Path, file: &str, val: &str) -> Result<(), String> {
    std::fs::write(cg.join(file), val).map_err(|e| {
        let delegation = matches!(
            e.raw_os_error(),
            Some(libc::EACCES | libc::EPERM | libc::ENOENT | libc::ENODEV)
        );
        let ctrl = file.split('.').next().unwrap_or(file);
        if delegation {
            format!("{file}: {e} (the {ctrl} controller may not be delegated here)")
        } else {
            format!("{file}: {e}")
        }
    })
}

/// Bounds for [`walk_diff`] against a box that fills its own overlay upper to exhaust the host `kern
/// diff` process. `DIFF_MAX_DEPTH` caps recursion (a box can't stack-overflow the walker); paths are
/// already ~PATH_MAX-bounded, so this is generous belt-and-suspenders. `DIFF_MAX_ENTRIES` caps the
/// collected output against an inode-bomb upper (millions of files) that would otherwise OOM the Vec.
const DIFF_MAX_DEPTH: usize = 4096;
const DIFF_MAX_ENTRIES: usize = 1_000_000;

/// Recursively classify overlay-upper entries into Docker `diff` markers, appending `(marker, in-box
/// absolute path)`. A whiteout (a char device with rdev 0:0) is a deletion `D`; every other entry
/// present in the upper is a change `C` (a changed dir is also recursed). Best-effort: an unreadable
/// subdir is skipped rather than aborting the whole diff. `metadata()` on a `DirEntry` does NOT follow
/// symlinks, so a whiteout or a symlink is classified by its own type, never its target's. Each
/// directory's fd is released (the `ReadDir` is dropped) BEFORE recursing, so open fds don't grow with
/// depth - otherwise a deep tree hits EMFILE and the diff silently truncates.
fn walk_diff(
    root: &std::path::Path,
    dir: &std::path::Path,
    depth: usize,
    out: &mut Vec<(char, String)>,
) {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    if depth > DIFF_MAX_DEPTH || out.len() >= DIFF_MAX_ENTRIES {
        return;
    }
    let mut subdirs: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if out.len() >= DIFF_MAX_ENTRIES {
                break;
            }
            let path = e.path();
            let Ok(md) = e.metadata() else { continue };
            let rel = path.strip_prefix(root).unwrap_or(&path);
            let inbox = format!("/{}", rel.to_string_lossy());
            let ft = md.file_type();
            if ft.is_char_device() && md.rdev() == 0 {
                out.push(('D', inbox)); // overlayfs whiteout = deleted in the box
            } else if ft.is_dir() {
                out.push(('C', inbox));
                subdirs.push(path); // defer: recurse AFTER this dir's fd is released below
            } else {
                out.push(('C', inbox));
            }
        }
    } // `rd` dropped here -> this level's directory fd is freed before we descend
    for sub in subdirs {
        walk_diff(root, &sub, depth + 1, out);
    }
}

/// Print one `kern events` line: `<unix-seconds> box <action> <name> (pid <pid>)`, with `from <old>`
/// appended for a rename. Unix seconds (not a localized clock) keeps it timezone-unambiguous and
/// dependency-free.
fn emit_event(action: &str, name: &str, pid: i32, from: Option<&str>) {
    let t = registry::now_unix();
    match from {
        Some(old) => println!("{t} box {action} {name} (pid {pid}, from {old})"),
        None => println!("{t} box {action} {name} (pid {pid})"),
    }
}

/// `kern images [--json]` - list OCI images pulled into the local cache. Each completed pull leaves
/// a `<sanitized>.ok` sentinel whose *content* is the original image ref, next to the `<sanitized>/`
/// rootfs dir - so we recover the real name, the on-disk size, and when it was pulled.
/// One cached OCI image as shown by `kern images` and the `kern top` Images tab.
pub(crate) struct ImageEntry {
    /// The original ref (`repository:tag`), recovered from the `.ok` sentinel's content.
    pub name: String,
    /// On-disk size in bytes (0 for an empty build - a valid image that added no files).
    pub size: u64,
    /// When it was pulled/built (unix seconds).
    pub pulled: u64,
    /// The image can't be assembled: a multi-layer build whose `.layers` manifest names an `L/` layer
    /// dir that is GONE (swept/deleted), or a sentinel with no payload at all. It would FAIL to run, so
    /// callers show a distinct `dangling` marker rather than a misleading `0 B` (which reads as "empty").
    pub dangling: bool,
}

/// The cached OCI images, sorted by name - the SINGLE source for both `kern images` and the `kern top`
/// Images tab, so the CLI and TUI can never drift on which images exist, their sizes, or their health.
pub(crate) fn image_entries() -> Vec<ImageEntry> {
    let cache = cache_dir();
    let mut rows: Vec<ImageEntry> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&cache) {
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|s| s.to_str()) != Some("ok") {
                continue; // skip the `<name>/` dirs, `.lock` files, `scratch/`
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()).map(String::from) else {
                continue;
            };
            // Shown with its implied tag, so every row is a reference you can paste straight back
            // into `--image` or `rmi`. The sentinel records the ref as first written (`alpine` from
            // a pull, `alpine:latest` from a load), and listing the two spellings side by side made
            // one image look like two.
            let name = std::fs::read_to_string(&path)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .map(|s| kern_oci::normalize_ref(&s))
                .unwrap_or_else(|| stem.clone());
            let (size, dangling) = image_stat(&cache, &stem);
            let pulled = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            rows.push(ImageEntry {
                name,
                size,
                pulled,
                dangling,
            });
        }
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    rows
}

/// Reclaim orphaned build layers (`L/` dirs referenced by no image). Safe and non-destructive: every
/// tagged image is kept; only dangling layers are freed. Invoked from the `kern top` Images tab (`p`);
/// the CLI equivalent is `kern gc` (which also prunes dead-box sidecars).
pub(crate) fn image_prune() -> Result<(), Error> {
    let (n, freed) = sweep_orphan_layers(&cache_dir());
    let p = crate::ui::Palette::detect();
    if n == 0 {
        println!("{}nothing to prune - no orphaned layers{}", p.d, p.z);
    } else {
        println!(
            "{}pruned{} {n} orphaned layer{}, freed {}",
            p.g,
            p.z,
            if n == 1 { "" } else { "s" },
            human_bytes(freed)
        );
    }
    Ok(())
}

/// Compact build duration for the `kern builds` table (`ms` / `s` / `m` `s`).
fn fmt_dur(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{}m{}s", ms / 60_000, (ms % 60_000) / 1000)
    }
}

/// Compact relative age for a duration in seconds (`s`/`m`/`h`/`d`).
fn fmt_age(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s ago"),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86_399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86_400),
    }
}

/// Prepare an **untrusted** string for a terminal table: first strip control/escape characters
/// (so a crafted registry name/description or cached image ref can't inject ANSI sequences into the
/// user's terminal), then truncate to at most `max` characters with an `…`.
fn truncate(s: &str, max: usize) -> String {
    let clean = crate::ui::scrub(s); // single definition of "strip terminal escapes"
    if clean.chars().count() <= max {
        return clean;
    }
    let mut t: String = clean.chars().take(max.saturating_sub(1)).collect();
    t.push('…');
    t
}

/// The current contents of a box's newest log, for the `kern top` log overlay (`Enter`). `None` if the
/// box has produced no log yet; errors are swallowed (the TUI shows an empty pane rather than blowing
/// up mid-frame).
pub(crate) fn box_log_tail(name: &str) -> Option<String> {
    let path = newest_log(name).ok().flatten()?;
    std::fs::read_to_string(path).ok()
}

/// Uptime as `Xh YYm` / `Xm YYs` / `Xs` (matches the `kern top` style).
pub(crate) fn fmt_uptime(s: u64) -> String {
    if s >= 3600 {
        format!("{}h {:02}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m {:02}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

/// One thing `kern uninstall` would remove: where it is, how big, and whether it is user DATA.
struct Removable {
    path: PathBuf,
    what: &'static str,
    /// Data the user made (named volumes, a hand-written config) as opposed to a cache kern can
    /// refetch. The plan lists these separately because losing them is not the same as losing bytes
    /// that a `pull` restores.
    is_user_data: bool,
    bytes: u64,
    /// The path itself is a symlink. `dir_bytes` deliberately does not follow one, so the size reads 0 and
    /// the plan claimed there was nothing there while a real tree sat on the other side. Removing the link
    /// is still the right act (following it would delete outside what kern owns), but reporting 0 B is not:
    /// it tells the reader the cache is empty when it is merely elsewhere.
    is_symlink: bool,
}

/// Recursive DISK USAGE of a tree, following no symlinks. Best-effort: an unreadable subtree
/// contributes 0 rather than aborting the plan, because this number exists to inform a decision.
///
/// Two details, both measured on a real cache of 85302 files:
///
/// - **Each inode counts once.** 4434 of those files were hardlinks, which the layer store creates for
///   blobs shared between images. Summing `len()` per directory entry reported **5.22 GiB** where
///   removing the tree actually freed **3.38 GiB**: a 55% overstatement on the one figure a reader uses
///   to decide whether this is worth doing.
/// - **Allocated blocks, not apparent length.** `du` agrees with allocation, and on 85k mostly-small
///   files the rounding is not noise (it added 0.26 GiB here). It also makes a sparse file count as what
///   it occupies rather than what it claims.
///
/// Two limits it has by construction, and does not hide:
///
/// - **Copy-on-write.** On btrfs or ZFS, blocks whose extents are shared with a snapshot are not freed by
///   removing the file, so on those filesystems this is an upper bound rather than a measurement.
/// - **Per item, not per plan.** Each row's size stands on its own, which is what a reader comparing rows
///   wants; the consequence is that an inode hardlinked ACROSS two rows is counted in both, so the total
///   can overstate. Within a row (the layer store, where sharing actually happens) it cannot.
fn dir_bytes(p: &std::path::Path) -> u64 {
    let mut seen = std::collections::HashSet::new();
    disk_usage(p, &mut seen)
}

fn disk_usage(p: &std::path::Path, seen: &mut std::collections::HashSet<(u64, u64)>) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let Ok(md) = std::fs::symlink_metadata(p) else {
        return 0;
    };
    if md.file_type().is_symlink() {
        return 0;
    }
    // A hardlink already counted contributes nothing more: the blocks are the same blocks.
    if md.nlink() > 1 && !seen.insert((md.dev(), md.ino())) {
        return 0;
    }
    let own = md.blocks() * 512;
    if !md.is_dir() {
        return own;
    }
    let Ok(rd) = std::fs::read_dir(p) else {
        return own;
    };
    own + rd
        .flatten()
        .map(|e| disk_usage(&e.path(), seen))
        .sum::<u64>()
}

/// Are we the kern inside a WSL2 distro? `WSL_DISTRO_NAME` is set by WSL for every process it starts;
/// the osrelease check catches a process that inherited a stripped environment.
///
/// It matters to `uninstall` alone: on Windows the pieces a user sees (`kern.exe`, the PATH entry) live
/// OUTSIDE this filesystem, so removing the Linux binary from in here leaves a shim pointing at a distro
/// with no kern. Recoverable - the shim says how - but not something to discover afterwards.
fn in_wsl() -> bool {
    if std::env::var_os("WSL_DISTRO_NAME").is_some() {
        return true;
    }
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| {
            let s = s.to_ascii_lowercase();
            s.contains("microsoft") || s.contains("wsl")
        })
        .unwrap_or(false)
}

/// Is `exe` a kern that an installer put where an installer puts it? Only then is deleting it this
/// verb's business: a kern built in a source tree, or one somebody dropped in `/opt`, is not.
///
/// Compares FILE IDENTITY, `(st_dev, st_ino)`, not path strings. `current_exe()` resolves symlinks, so a
/// packaged install where `/usr/bin/kern` is a symlink into `/usr/lib/kern/` reports the resolved target,
/// which matches none of the candidate paths as text: string comparison refused to remove a perfectly
/// legitimate install. Measured, with `~/.local/bin/kern` symlinked at a copy elsewhere. Identity also
/// absorbs the harmless spellings that broke the string form: a trailing slash, `bin/../bin`, `~`.
///
/// A build output in a source tree still answers false, because no candidate path points at it.
fn is_installed_binary(exe: &std::path::Path, home: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(me) = std::fs::metadata(exe) else {
        return false;
    };
    [
        home.join(".local/bin/kern"),
        PathBuf::from("/usr/local/bin/kern"),
        PathBuf::from("/usr/bin/kern"),
    ]
    .iter()
    .any(|cand| {
        std::fs::metadata(cand)
            .map(|c| c.dev() == me.dev() && c.ino() == me.ino())
            .unwrap_or(false)
    })
}

/// `kern save <image> [-o file]` - export a cached image to a `docker load`-compatible tar (offline /
/// air-gapped transfer). Materializes the image to one rootfs (like `push`), then writes the archive.
/// Normalise an image ref to a `repo:tag` that `docker load` accepts: append `:latest` when the ref
/// carries no tag. A registry port (`localhost:5000/img`) is not a tag - only a `:` in the LAST path
/// component (after the final `/`) counts, so `localhost:5000/app` → `localhost:5000/app:latest`.
fn ensure_repo_tag(image: &str) -> String {
    let last = image.rsplit('/').next().unwrap_or(image);
    if last.contains(':') {
        image.to_string()
    } else {
        format!("{image}:latest")
    }
}

/// Copy the `user.*` extended attributes from `src_fd` to `dst_fd`, best-effort. Carries ONLY `user.*`
/// (application metadata, no privilege). Deliberately NOT `security.capability`: file-capabilities are a
/// privilege channel like setuid, and the source image is untrusted - blindly propagating an attacker's
/// `cap_setuid+ep` would inject an escalation into the copied/pushed image (worse than setuid: caps
/// bypass MS_NOSUID). `system.*`/`trusted.*` need privilege we don't have. Failures are ignored (xattrs
/// are best-effort like `cp --preserve=all`; a filesystem without xattr support must not fail the copy).
unsafe fn copy_xattrs(src_fd: libc::c_int, dst_fd: libc::c_int) {
    // List the source's xattr names into a buffer. `flistxattr(_, NULL, 0)` returns the needed size.
    let need = libc::flistxattr(src_fd, std::ptr::null_mut(), 0);
    if need <= 0 {
        return; // no xattrs (0) or not supported (<0)
    }
    let mut names = vec![0u8; need as usize];
    let got = libc::flistxattr(src_fd, names.as_mut_ptr() as *mut libc::c_char, names.len());
    if got <= 0 {
        return;
    }
    let mut val = vec![0u8; 4096];
    // Names are a NUL-separated, NUL-terminated list.
    for name in names[..got as usize]
        .split(|&b| b == 0)
        .filter(|n| !n.is_empty())
    {
        // Carry ONLY `user.*`. NOT `security.capability` (privilege channel - an untrusted image's caps
        // would be injected into the output; kern uses no runtime file-caps), NOT `system.*`/`trusted.*`
        // (need privilege, not ours to move).
        if !name.starts_with(b"user.") {
            continue;
        }
        let Ok(name_c) = std::ffi::CString::new(name) else {
            continue;
        };
        let vlen = libc::fgetxattr(
            src_fd,
            name_c.as_ptr(),
            val.as_mut_ptr() as *mut libc::c_void,
            val.len(),
        );
        if vlen < 0 {
            continue;
        }
        libc::fsetxattr(
            dst_fd,
            name_c.as_ptr(),
            val.as_ptr() as *const libc::c_void,
            vlen as usize,
            0,
        );
    }
}

/// `write(open(path), val)` - async-signal-safe (no allocation). `true` on full write.
unsafe fn write_proc_self(path: &[u8], val: &[u8]) -> bool {
    let fd = libc::open(path.as_ptr() as *const libc::c_char, libc::O_WRONLY);
    if fd < 0 {
        return false;
    }
    let n = libc::write(fd, val.as_ptr() as *const libc::c_void, val.len());
    libc::close(fd);
    n == val.len() as isize
}

/// Write a single-uid map line `0 <id> 1` to `path` (uid_map/gid_map), async-signal-safe. Formats the
/// number into a stack buffer (no allocation) to stay fork-safe.
unsafe fn write_proc_self_map(path: &[u8], id: u32) -> bool {
    let mut buf = [0u8; 32];
    let mut i = 0;
    buf[i] = b'0';
    i += 1;
    buf[i] = b' ';
    i += 1;
    let mut digits = [0u8; 10];
    let mut d = 0;
    let mut v = id;
    if v == 0 {
        digits[d] = b'0';
        d += 1;
    }
    while v > 0 {
        digits[d] = b'0' + (v % 10) as u8;
        v /= 10;
        d += 1;
    }
    while d > 0 {
        d -= 1;
        buf[i] = digits[d];
        i += 1;
    }
    buf[i] = b' ';
    i += 1;
    buf[i] = b'1';
    i += 1;
    write_proc_self(path, &buf[..i])
}

/// Create `dir` (and parents) private to this user (mode 0700). Mitigates a local-user symlink/
/// clobber attack on a predictable cache path: another user can't pre-create or enter it.
/// Size of the caller's subordinate-uid range from `/etc/subuid` (box uids 1..count map here, so the
/// box can use uids 0..count-1). `0` if there's no allocation (single-uid only). Best-effort, matching
/// how `newuidmap` resolves the row - a name match wins, else a numeric-uid row. Used only to warn (F1)
/// when an image's declared uid exceeds what `--uid-range` can map; never to clamp.
/// Size of the caller's `/etc/subuid` range (box uids 0..count usable), or 0 if none. Delegates to the
/// ONE authoritative parser in kern-isolation (`sub_range`: `count>1`, name-row-wins) so the box path,
/// the cleanup path, and this F1 warning can't drift apart.
fn mapped_uid_count() -> u32 {
    let uid = unsafe { libc::getuid() };
    let name = kern_isolation::username(uid);
    kern_isolation::sub_range("/etc/subuid", name.as_deref(), uid)
        .map(|(_start, count)| count)
        .unwrap_or(0)
}

/// Arguments for [`build`] (`kern build`).
pub struct BuildArgs<'a> {
    /// `-t <name[:tag]>`: the local image name to store the result under. Required.
    pub tag: Option<&'a str>,
    /// `-f <file>`: the Dockerfile path. `None` → `<context>/Dockerfile`.
    pub file: Option<&'a str>,
    /// The build context directory (default `.`) - the root COPY/ADD sources resolve against.
    pub context: &'a str,
    /// `--build-arg K=V` (repeatable): values for `ARG` substitution.
    pub build_args: &'a [String],
    /// `--quiet`: suppress per-step progress.
    pub quiet: bool,
    /// `--target <stage>`: stop at the named stage of a multi-stage Dockerfile and tag THAT.
    ///
    /// Compose spells it `build.target:`, and it is how a project selects between the `development`
    /// and `production` stages of one Dockerfile. Building the last stage instead produces a working
    /// image that is the WRONG image, with nothing said, so the name is resolved against the file's
    /// stage names and an unknown one is refused rather than approximated.
    pub target: Option<&'a str>,
}

/// Execute a MULTI-STAGE build. Each stage is built in order via the ordinary single-stage `build_run`
/// under an internal temp tag (`.stage-<pid>-<idx>`), so every stage reuses the proven, byte-identical
/// single-stage path (RUN batching, layer cache, config handling). Only the LAST stage is built under
/// the user's real `tag`; the temp stage images are dropped at the end.
///
/// `COPY --from=<stage>` (the multi-stage feature) is made safe by REUSE, not by a hand-rolled overlay
/// mount: the source stage is materialized to a single merged rootfs dir (`materialize_image`, which
/// already resolves the overlay chain + whiteouts correctly), and the copy runs through the SAME
/// `copy_into_rootfs` guards as a context COPY - it canonicalizes the source under the stage rootfs and
/// rejects any `..`/symlink escape, so `COPY --from=build /etc/../../host` fails exactly like a hostile
/// context COPY. The `--from` COPY is rewritten to a plain COPY whose "context" is that merged rootfs.
///
/// Non-final stages build under an internal tag prefixed with [`STAGE_TAG_PREFIX`]; that prefix is the
/// single source of truth for both creating those tags and suppressing their "built …" line
/// ([`announce_built`]). A leading `.` never appears in a user ref, so the two can't collide.
const STAGE_TAG_PREFIX: &str = ".stage-";

/// Print the "built '<tag>'" success line - UNLESS `tag` is an internal multi-stage stage tag (prefixed
/// [`STAGE_TAG_PREFIX`]), which the user shouldn't see. Single-sourced so the create/suppress contract
/// can't drift.
fn announce_built(tag: &str) {
    if !tag.starts_with(STAGE_TAG_PREFIX) {
        println!("built '{tag}'");
        println!("  run: kern box myapp --image {tag}");
    }
}

/// A stage's rewritten instruction list plus the two flags that pick its build context.
struct StagePrep {
    stage_instrs: Vec<crate::dockerfile::Instr>,
    /// The stage pulled from ≥1 source stage (files grafted into the sub-context `subctx`).
    pulled_from_stage: bool,
    /// The stage has ≥1 plain `COPY` from the real build context.
    stage_uses_context: bool,
    /// This stage's `FROM` named an EARLIER STAGE and was rewritten to that stage's temp tag.
    ///
    /// The caller needs it because the consequence outlives this function: the built image's overlay
    /// chain then rests on a tag that gets deleted, so the FINAL image has to be materialised before
    /// the temp tags go. Returning the fact is cheaper and harder to get wrong than re-deriving it
    /// from the instruction slice at the call site.
    from_stage: bool,
}

/// Rewrite a stage's instruction slice, turning every `COPY --from=<stage|image>` into a plain COPY
/// whose source is the referenced stage's built rootfs - OR, for an external `--from=<image>`, the
/// image's pulled rootfs (`resolve_image`, the same path `FROM`/`--image` use). Files are grafted into
/// `subctx` through the SAME confine guards as a context COPY (`copy_from_stage_chain`), so an external
/// image's `srcs` can't `..`/symlink-escape its rootfs any more than a stage's can. Each distinct
/// source stage/image is resolved AT MOST ONCE (perf) so the caller sees a straight `?`.
fn prepare_stage(
    slice: &[crate::dockerfile::Instr],
    stage_tags: &[String],
    stage_names: &[Option<String>],
    si: usize,
    subctx: &std::path::Path,
) -> Result<StagePrep, Error> {
    use crate::dockerfile::{resolve_from, CopyFrom, Instr};
    let mut stage_instrs: Vec<Instr> = Vec::with_capacity(slice.len());
    let mut stage_uses_context = false;
    let mut pulled_from_stage = false;
    let mut from_stage = false;
    // Resolve each SOURCE STAGE's overlay chain at most once per stage. We copy files DIRECTLY from the
    // chain (no full-rootfs squash) - the squash only happens as a fallback for a directory source,
    // inside copy_from_stage_chain. Caching the chain dedups N `COPY --from=X`.
    let mut chains: std::collections::HashMap<usize, Vec<String>> =
        std::collections::HashMap::new();
    // Same idea for external `COPY --from=<image>`: pull+resolve each distinct image AT MOST ONCE.
    let mut image_chains: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut build = || -> Result<(), Error> {
        for ins in slice {
            match ins {
                Instr::Copy {
                    srcs,
                    dst,
                    from: Some(cf),
                    chmod,
                } => {
                    // Resolve the source's overlay chain (top-first list of layer dirs), pulling an
                    // external image on demand. A build STAGE takes precedence over an image of the same
                    // spelling - already decided by the parser, which only emits `CopyFrom::Image` when
                    // the token names NO earlier stage. Both paths feed the SAME confined copy helper
                    // (`copy_from_stage_chain` → single-layer `starts_with` guard, or ≥2-layer
                    // `merged_view_extract` with `openat2(RESOLVE_IN_ROOT)`), so an external image's
                    // `srcs` are confined to its rootfs exactly like a stage's - no `..`/symlink escape.
                    let (chain, label): (Vec<String>, String) = match cf {
                        CopyFrom::Stage(fref) => {
                            let src_idx = resolve_from(fref, stage_names, si).ok_or_else(|| {
                                Error::Build(format!(
                                    "COPY --from='{fref}' does not name an earlier stage"
                                ))
                            })?;
                            if let std::collections::hash_map::Entry::Vacant(slot) =
                                chains.entry(src_idx)
                            {
                                // The chain is `top:...:base`; split into a top-first Vec of layer dirs.
                                let (lower, _cfg) = resolve_image(&stage_tags[src_idx])?;
                                slot.insert(lower.split(':').map(str::to_string).collect());
                            }
                            (chains[&src_idx].clone(), stage_tags[src_idx].clone())
                        }
                        CopyFrom::Image(img) => {
                            if let std::collections::hash_map::Entry::Vacant(slot) =
                                image_chains.entry(img.clone())
                            {
                                // Pull (if not cached) + resolve the external image's overlay chain -
                                // the SAME path `FROM`/`--image` use (`resolve_image` → `pull_to_cache`).
                                // Runs synchronously on the single-threaded build main, so the confined
                                // copy that follows keeps the fork-safety invariant.
                                let (lower, _cfg) = resolve_image(img)?;
                                slot.insert(lower.split(':').map(str::to_string).collect());
                            }
                            (image_chains[img].clone(), img.clone())
                        }
                    };
                    if !pulled_from_stage {
                        let _ = std::fs::create_dir_all(subctx);
                        pulled_from_stage = true;
                    }
                    for s in srcs {
                        copy_from_stage_chain(&chain, s, subctx, &label)?;
                    }
                    // Rewrite to a plain COPY from the sub-context (same dst-side guards downstream).
                    let names: Vec<String> = srcs
                        .iter()
                        .map(|s| {
                            std::path::Path::new(s.trim_end_matches('/'))
                                .file_name()
                                .map(|b| b.to_string_lossy().into_owned())
                                .unwrap_or_else(|| s.clone())
                        })
                        .collect();
                    stage_instrs.push(Instr::Copy {
                        srcs: names,
                        dst: dst.clone(),
                        from: None,
                        chmod: chmod.clone(),
                    });
                }
                // A context COPY (from: None) - the stage references the real build context.
                Instr::Copy { .. } => {
                    stage_uses_context = true;
                    stage_instrs.push(ins.clone());
                }
                // `FROM <earlier-stage>` - the OTHER half of multi-stage, and it was missing.
                //
                // `COPY --from=<stage>` already worked, by name and by index, so the stage table and
                // the per-stage temp tags were here; `FROM` never consulted them. A stage name fell
                // through as an image reference and kern tried to PULL it: `FROM base AS finale`
                // warned "no tag pinned" and died with `cannot access 'library/base' on
                // registry-1.docker.io`, naming a registry the author never mentioned.
                //
                // The rewrite is the one the COPY arm does: point at `stage_tags[src_idx]`, the local
                // tag that stage was built under. `resolve_from` validates against EARLIER stages
                // only, so a forward or self reference still falls through to the image path and
                // fails as an unknown image, which is what Docker does with the same input.
                //
                // THIS REWRITE ALONE SHIPS A BROKEN IMAGE, and `build_multi_stage` is where that is
                // closed. `COPY --from` takes FILES out of a stage, so the product owns them;
                // `FROM <stage>` makes the stage the product's BASE, so the final image's overlay
                // chain points at a temp tag that `cleanup_stage_tags` deletes. Measured: the build
                // printed `built` and the image would not run (`no layers in manifest`). The caller
                // therefore MATERIALISES the final image before that cleanup - see `from_stage`.
                Instr::From { image, as_name } => {
                    match crate::dockerfile::resolve_from(image, stage_names, si) {
                        Some(src_idx) => {
                            from_stage = true;
                            stage_instrs.push(Instr::From {
                                image: stage_tags[src_idx].clone(),
                                as_name: as_name.clone(),
                            });
                        }
                        None => stage_instrs.push(ins.clone()),
                    }
                }
                other => stage_instrs.push(other.clone()),
            }
        }
        Ok(())
    };
    // The chain-copy owns no temp squash dir (the dir-source fallback inside copy_from_stage_chain
    // cleans up its own squash), so there's nothing to reap here.
    build()?;
    Ok(StagePrep {
        stage_instrs,
        pulled_from_stage,
        stage_uses_context,
        from_stage,
    })
}

/// Copy `src_rel` OUT of a source stage's overlay `chain` (top-first list of layer dirs) into `dest`,
/// honouring overlay opaque/whiteout semantics so a file DELETED in a build step never resurfaces.
///
/// For a ≥2-layer chain this reads from the KERNEL-MERGED view ([`merged_view_extract`]) - the ONLY
/// correct reader: a top-first walk of the RAW layers leaks a file whose PARENT directory was made
/// OPAQUE in an upper layer (`rm -rf dir && mkdir dir`), because the walk finds the file in a lower
/// layer that the opaque was meant to hide. (Verified live: a secret `rm`'d in a build step reappeared
/// via `COPY --from`.) The merged view also confines an untrusted `src_rel` by CONSTRUCTION
/// (`openat2(RESOLVE_IN_ROOT)`), so a `..`-escape and an in-image absolute-symlink-escape are both
/// closed - see the primitive's doc. A single-layer chain has no cross-layer opaque possible, so it's
/// copied directly (host-side canonicalize + `starts_with` confine).
fn copy_from_stage_chain(
    chain: &[String],
    src_rel: &str,
    dest: &std::path::Path,
    _stage_tag: &str,
) -> Result<(), Error> {
    if chain.len() >= 2 {
        // ≥2 stacked layers → cross-layer opaque is possible → read the kernel-merged view (which also
        // handles file AND directory sources uniformly, confining `src_rel` via `openat2(RESOLVE_IN_ROOT)`).
        return merged_view_extract(chain, Extract::Entry(src_rel), dest);
    }
    // Exactly one layer: it IS its own merged rootfs (no cross-layer opaque to honour). Copy directly
    // through the shared single-rootfs confine helper (canonicalize + `starts_with`, `cp -a` no-follow).
    copy_from_stage_rootfs(std::path::Path::new(&chain[0]), src_rel, dest)
}

/// Copy `src_rel` OUT of a single source rootfs `src_rootfs` into `dest`, confined to it (canonicalize +
/// `starts_with`, the same escape guard a context COPY uses) with a no-follow `cp -a`. Used for a
/// SINGLE-layer `COPY --from` chain (a ≥2-layer chain goes through [`merged_view_extract`] instead,
/// which honours cross-layer opaque).
fn copy_from_stage_rootfs(
    src_rootfs: &std::path::Path,
    src_rel: &str,
    dest: &std::path::Path,
) -> Result<(), Error> {
    let clean = src_rel.trim_start_matches('/');
    // Canonicalize the ROOT too, so the confinement check compares canonical-vs-canonical. Without
    // this, a `src_rootfs` reached through a symlinked component (e.g. a cache dir under a symlinked
    // $HOME) would make `canonicalize(src)` resolve past the raw prefix and FALSE-reject a legitimate
    // copy. Security is unchanged: a src that symlinks OUT of the image still resolves outside `root`
    // and is rejected.
    let root = std::fs::canonicalize(src_rootfs).map_err(|e| {
        Error::Build(format!(
            "COPY --from source rootfs '{}': {e}",
            src_rootfs.display()
        ))
    })?;
    let src = std::fs::canonicalize(root.join(clean))
        .map_err(|e| Error::Build(format!("COPY --from source '{src_rel}': {e}")))?;
    if !src.starts_with(&root) {
        return Err(Error::Build(format!(
            "COPY --from source '{src_rel}' escapes the source stage"
        )));
    }
    let name = src
        .file_name()
        .ok_or(Error::Build("COPY --from source has no file name".into()))?;
    let target = dest.join(name);
    // `cp -a --` no-follow, preserving modes - same tool/flags as the rest of the builder.
    let ok = std::process::Command::new("cp")
        .arg("-a")
        .arg("--reflink=auto") // CoW clone on btrfs/xfs (near-free); plain copy elsewhere
        .arg("--")
        .arg(&src)
        .arg(&target)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        return Err(Error::Build(format!(
            "COPY --from could not copy '{src_rel}'"
        )));
    }
    Ok(())
}

/// Overlay `from`'s entries onto `into` (used to graft stage-copied files onto a build sub-context).
/// Each entry may be a file OR a directory, so we can't use `copy_tree` (which assumes a dir); a plain
/// `cp -a --` on the entry path handles both.
fn merge_context(from: &std::path::Path, into: &std::path::Path) -> Result<(), Error> {
    for e in std::fs::read_dir(from).map_err(|e| Error::Build(e.to_string()))? {
        let e = e.map_err(|e| Error::Build(e.to_string()))?;
        let dst = into.join(e.file_name());
        let _ = std::fs::remove_dir_all(&dst);
        let _ = std::fs::remove_file(&dst);
        let ok = std::process::Command::new("cp")
            .arg("-a")
            .arg("--reflink=auto") // CoW clone on btrfs/xfs (near-free); plain copy elsewhere
            .arg("--")
            .arg(e.path())
            .arg(&dst)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            return Err(Error::Build(format!(
                "grafting '{}' into the build context failed",
                e.file_name().to_string_lossy()
            )));
        }
    }
    Ok(())
}

/// The local filename an `ADD <url>` downloads to: the URL's last path segment minus any
/// query/fragment. SANITIZED - a URL ending in `/..` or `/.`, an empty segment (bare host), or a
/// segment bearing a path separator / NUL would let `dir.join(name)` escape the scratch dir (and feed
/// `..` into the copy as a source), so those fall back to a fixed safe name. Pure, so it's unit-tested.
fn add_url_basename(url: &str) -> &str {
    let tail = url.rsplit('/').next().unwrap_or("");
    let name = tail.split(['?', '#']).next().unwrap_or("");
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
        "download"
    } else {
        name
    }
}

/// Fetch `url` into `dir` for a Dockerfile `ADD <url> <dst>`, returning the basename written. HTTPS
/// only (`--proto '=https'`, incl. redirects) - an `http://` URL is refused rather than silently
/// downgrading build integrity - via `curl`, matching kern's dependency-free (curl/tar/cp) posture. When `checksum`
/// (`<algo>:<hex>`) is given it's verified and a mismatch fails the build.
fn fetch_add_url(
    url: &str,
    checksum: Option<&str>,
    dir: &std::path::Path,
) -> Result<String, Error> {
    if !url.starts_with("https://") {
        return Err(Error::Sandbox(format!(
            "ADD {url}: only https:// URLs are fetched (http is refused; download over TLS or vendor \
             the file and COPY it)"
        )));
    }
    // Fresh scratch dir to download into (owned by the caller's `work`); it holds only this file.
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).map_err(|e| Error::Sandbox(format!("ADD download dir: {e}")))?;
    let name = add_url_basename(url);
    let out = dir.join(name);
    // HTTPS only, on the initial request AND across redirects (`--proto-redir`), so a 302 can't
    // silently downgrade the fetch to cleartext http.
    let status = std::process::Command::new("curl")
        .args([
            "-fSL",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "20",
            "-o",
        ])
        .arg(&out)
        .arg(url)
        .status()
        .map_err(|e| Error::Sandbox(format!("ADD {url}: curl: {e}")))?;
    if !status.success() {
        return Err(Error::Sandbox(format!("ADD {url}: download failed")));
    }
    if let Some(cs) = checksum {
        verify_download_checksum(&out, cs)?;
    }
    Ok(name.to_string())
}

/// Write an inline `COPY <<heredoc` body to a scratch file `dir/f` (a fresh dir), so the same
/// confined `copy_into_rootfs` path that a real COPY uses places it at the destination. Returns the
/// scratch dir ready with the single file `f`.
fn write_inline_file(dir: &std::path::Path, content: &str) -> Result<(), Error> {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).map_err(|e| Error::Sandbox(format!("inline COPY dir: {e}")))?;
    std::fs::write(dir.join("f"), content)
        .map_err(|e| Error::Sandbox(format!("inline COPY write: {e}")))?;
    Ok(())
}

/// Verify a downloaded file against a BuildKit `--checksum=<algo>:<hex>` using coreutils
/// `sha{256,384,512}sum`. A malformed spec, unsupported algorithm, or digest mismatch fails the build.
fn verify_download_checksum(path: &std::path::Path, checksum: &str) -> Result<(), Error> {
    let (algo, want) = checksum.split_once(':').ok_or_else(|| {
        Error::Sandbox(format!(
            "ADD --checksum must be '<algo>:<hex>' (e.g. sha256:…), got '{checksum}'"
        ))
    })?;
    let tool = match algo {
        "sha256" => "sha256sum",
        "sha384" => "sha384sum",
        "sha512" => "sha512sum",
        other => {
            return Err(Error::Sandbox(format!(
                "ADD --checksum: unsupported algorithm '{other}' (use sha256/sha384/sha512)"
            )))
        }
    };
    let out = std::process::Command::new(tool)
        .arg("--")
        .arg(path)
        .output()
        .map_err(|e| Error::Sandbox(format!("ADD --checksum: {tool}: {e}")))?;
    if !out.status.success() {
        return Err(Error::Sandbox(format!("ADD --checksum: {tool} failed")));
    }
    let got = String::from_utf8_lossy(&out.stdout);
    let got = got.split_whitespace().next().unwrap_or("");
    if !got.eq_ignore_ascii_case(want) {
        return Err(Error::Sandbox(format!(
            "ADD checksum mismatch: expected {algo}:{want}, got {algo}:{got}"
        )));
    }
    Ok(())
}

/// Child of [`probe_opaque_honored`]: mount a RW overlay (lower has `dir/secret`), `rm -rf dir && mkdir
/// dir` in the merged view, then re-open the merged view read-only and check `dir/secret` is GONE (the
/// opaque was honoured). `_exit(0)` iff hidden; any other path `_exit`s non-zero. Async-signal-safe until
/// the `system()` - acceptable here (single-threaded at fork, like `merged_view_child`).
unsafe fn probe_opaque_child(tmp: &std::path::Path, euid: libc::uid_t, egid: libc::gid_t) -> ! {
    // A path with an interior NUL cannot name a file, and this ran inside a FORKED CHILD where a
    // panic is not a clean error: unwinding past a `-> !` in a half-set-up namespace is the worst
    // place in this codebase to abort. The child has an exit-code protocol already, so a path it
    // cannot express is one more code, and the parent reads it like any other refusal.
    let cs = |p: String| match std::ffi::CString::new(p) {
        Ok(c) => c,
        Err(_) => libc::_exit(19),
    };
    if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
        libc::_exit(11);
    }
    if !write_proc_self(b"/proc/self/setgroups\0", b"deny")
        || !write_proc_self_map(b"/proc/self/uid_map\0", euid)
        || !write_proc_self_map(b"/proc/self/gid_map\0", egid)
    {
        libc::_exit(12);
    }
    libc::mount(
        c"none".as_ptr(),
        c"/".as_ptr(),
        std::ptr::null(),
        libc::MS_REC | libc::MS_PRIVATE,
        std::ptr::null(),
    );
    let d = tmp.to_string_lossy();
    let opts = cs(format!("lowerdir={d}/lower,upperdir={d}/up,workdir={d}/wk"));
    let mg = cs(format!("{d}/mg"));
    if libc::mount(
        c"overlay".as_ptr(),
        mg.as_ptr(),
        c"overlay".as_ptr(),
        0,
        opts.as_ptr() as *const libc::c_void,
    ) != 0
    {
        libc::_exit(13);
    }
    // Reproduce EXACTLY what a build does - and the leak that only shows on RE-MOUNT. A build RUN does
    // `rm -rf dir && mkdir dir` in the live overlay (which every kernel honours in the LIVE view), then
    // `commit_layer` saves the UPPER as a standalone layer, and later the merged-view RE-MOUNTS
    // upper-as-lower. The leak is that some kernels (tegra 5.15) honour the opaque live but DON'T
    // persist it into the upper (no opaque xattr / whiteout written) - so on re-mount the lower's file
    // resurfaces. So: do the rm in the live mount, then RE-MOUNT `up:lower` read-only (as the merged
    // view would) and check the secret is STILL hidden. Only if it stays hidden across the re-mount is
    // the opaque truly persisted → layered is safe.
    // stderr silenced ({{…}} 2>/dev/null): this is an internal PROBE - only its exit status matters
    // (drives the layered-vs-flat decision). On a filesystem where the overlay `rm` can't fully remove
    // the dir (WSL's 9p/overlay: "rm: can't remove …: I/O error"), the probe correctly falls back to a
    // flat build; leaking that rm's diagnostic to the user's build output just looks alarming.
    let script = cs(format!(
        "{{ rm -rf {d}/mg/dir && mkdir {d}/mg/dir && \
           umount {d}/mg && \
           mount -t overlay overlay -o lowerdir={d}/up:{d}/lower,ro {d}/mg && \
           test ! -e {d}/mg/dir/secret; }} 2>/dev/null"
    ));
    let ret = libc::system(script.as_ptr());
    // system() returns the shell's wait-status; 0 exit == opaque persisted (secret gone after re-mount).
    if ret == 0 {
        libc::_exit(0);
    }
    libc::_exit(14);
}

/// Run one `RUN` step inside a `kern box` with host networking, so writes persist to the build layer
/// and the command can fetch packages. **Layered:** overlay `base_lower` with the persistent upper
/// under `work` (no base copy). **Flat:** bind-mount the copied `write_dir`. Reuses the full box
/// isolation rather than a second sandbox path; a non-zero exit fails the build.
#[allow(clippy::too_many_arguments)]
fn run_build_step(
    self_exe: &std::path::Path,
    layered: bool,
    base_lower: &str,
    work: &std::path::Path,
    write_dir: &std::path::Path,
    config: &kern_oci::ImageConfig,
    argv: &[String],
    step: usize,
) -> Result<(), Error> {
    let mut cmd = std::process::Command::new(self_exe);
    cmd.env("KERN_BUILD_STEP", "1"); // skip the transient systemd-scope re-exec (build boxes are hot)
    cmd.arg("box")
        .arg(format!("_build-{}-{step}", std::process::id()));
    if layered {
        cmd.arg("--overlay-lower")
            .arg(base_lower)
            .arg("--overlay-upper")
            .arg(work);
    } else {
        cmd.arg("--rootfs").arg(write_dir).arg("--bind-rootfs");
    }
    cmd.arg("--net").arg("--uid-range").arg("--quiet");
    // A BUILD STEP IS NOT A SERVICE, AND THE SERVICE DEFAULT BREAKS IT.
    //
    // `kern box` defaults to 512 MiB, which is a sensible ceiling for a long-running workload and is
    // far below what an ordinary build needs. MEASURED on the first three real projects cloned from
    // GitHub for this check: `npm install` (alitarhinisv/Notes-FE) and `bun install`
    // (aloshai/aequi-monorepo) were both killed by the box's own OOM at 512 MiB, exit 137. Docker's
    // builder has no memory limit at all, and NO compose key can express one - `deploy` and
    // `mem_limit` describe the service, not the build - so a user hitting this has nothing to write
    // in the file. It is a blocker, not a trade.
    //
    // BOUNDED BY THE MACHINE RATHER THAN UNCAPPED. The cap becomes the host's own RAM, which is what
    // bounds a `docker build` in practice, and keeps the failure ATTRIBUTABLE: a build that really
    // does exhaust memory is killed against its own cgroup, with kern's message naming the cap,
    // instead of the host OOM killer choosing a victim somewhere else on the machine.
    //
    // A `/proc/meminfo` that cannot be read leaves the box default in place, which is the behaviour
    // this replaces: a build that then fails fails the way it did before, never in a new way.
    if let Some(total) = host_meminfo_bytes("MemTotal:") {
        cmd.arg("--memory").arg(total.to_string());
    }
    // SWAP TOO, FOR THE SAME REASON AND THE SAME BOUND. A box gets `memory.swap.max = 0` by default,
    // which is right for a service: swapping one is a service that has already failed its latency
    // budget. A BUILD is the opposite case - it is a one-shot burst that Docker lets swap, and the
    // heaviest ones (a `pip install` that pulls the CUDA wheels, a `cargo build` of a large tree)
    // genuinely need the headroom. MEASURED on `abisheik687/kavach-ai`: `pip install` of the torch
    // and NVIDIA stack was OOM-killed at the host's full 33 GiB of RAM with 21 GiB of swap sitting
    // unused beside it.
    //
    // Bounded by what the machine actually has, so this grants no more than the host does, and the
    // box's own cgroup still makes the kill attributable when even that is not enough.
    if let Some(swap) = host_meminfo_bytes("SwapTotal:") {
        cmd.arg("--memory-swap-max").arg(swap.to_string());
    }
    for e in &config.env {
        cmd.arg("--env").arg(e);
    }
    if let Some(w) = &config.workdir {
        cmd.arg("--workdir").arg(w);
    }
    cmd.arg("--");
    for a in argv {
        cmd.arg(a);
    }
    let status = cmd
        .status()
        .map_err(|e| Error::Sandbox(format!("RUN: cannot start kern box: {e}")))?;
    if !status.success() {
        // For a batched RUN this prints the combined `&&` chain; the box inherited stdio, so the
        // failing sub-step's own stderr already appeared above - enough to see which step failed.
        return Err(Error::Sandbox(format!(
            "RUN failed (exit {}): {}",
            status.code().unwrap_or(-1),
            display_run(argv)
        )));
    }
    Ok(())
}

/// Set (replace or append) `K=V` in an image-config env list.
fn set_config_env(env: &mut Vec<String>, k: &str, v: &str) {
    let prefix = format!("{k}=");
    let entry = format!("{k}={v}");
    match env.iter_mut().find(|e| e.starts_with(&prefix)) {
        Some(e) => *e = entry,
        None => env.push(entry),
    }
}

/// Apply a CMD or ENTRYPOINT instruction to the image config - the ONE place the Docker rule
/// "ENTRYPOINT resets an inherited base CMD unless this Dockerfile set its own CMD" lives, so the
/// flat and layer-cached build loops can't drift. Config-only: neither touches the filesystem.
/// `cmd_seen` records whether THIS Dockerfile has set a CMD.
fn apply_cmd_entrypoint(
    config: &mut kern_oci::ImageConfig,
    ins: &crate::dockerfile::Instr,
    cmd_seen: &mut bool,
) {
    use crate::dockerfile::Instr;
    match ins {
        Instr::Cmd(a) => {
            config.cmd = a.clone();
            *cmd_seen = true;
        }
        Instr::Entrypoint(a) => {
            config.entrypoint = a.clone();
            if !*cmd_seen {
                config.cmd.clear();
            }
        }
        _ => {}
    }
}

/// Apply a DECLARATION-only instruction (`HEALTHCHECK`, `STOPSIGNAL`) to the image config.
///
/// ONE PLACE, FOR THE SAME REASON AS `apply_cmd_entrypoint`: the flat and the layer-cached build
/// loops both reach it, and a rule written twice is a rule that drifts. Neither instruction touches
/// the filesystem, so neither advances the layer key.
///
/// `HEALTHCHECK NONE` CLEARS an inherited check rather than storing the word: that is Docker's
/// meaning, and storing `["NONE"]` would leave the runtime to interpret a sentinel it has no reason
/// to know about. The runtime asks one question, "is there a check", and this answers it.
fn apply_declaration(config: &mut kern_oci::ImageConfig, ins: &crate::dockerfile::Instr) {
    use crate::dockerfile::Instr;
    match ins {
        Instr::StopSignal(sig) => config.stop_signal = Some(sig.clone()),
        Instr::Healthcheck {
            test,
            interval_ns,
            timeout_ns,
            start_period_ns,
            retries,
        } => {
            if test.first().is_some_and(|t| t == "NONE") {
                config.healthcheck = None;
            } else {
                config.healthcheck = Some(kern_oci::ImageHealthcheck {
                    test: test.clone(),
                    interval_ns: *interval_ns,
                    timeout_ns: *timeout_ns,
                    start_period_ns: *start_period_ns,
                    retries: *retries,
                });
            }
        }
        _ => {}
    }
}

/// Resolve a `WORKDIR` operand: absolute stays as-is, relative joins onto the previous workdir
/// (default `/`), matching Docker.
fn resolve_workdir(prev: Option<&str>, d: &str) -> String {
    if d.starts_with('/') {
        d.to_string()
    } else {
        format!("{}/{}", prev.unwrap_or("/").trim_end_matches('/'), d)
    }
}

/// The shell script of a shell-form RUN (`["/bin/sh","-c",<script>]`), or `None` for an exec-form
/// RUN - only shell-form RUNs are safe to batch into one box.
fn run_shell_script(argv: &[String]) -> Option<&str> {
    match argv {
        [sh, dashc, s] if sh == "/bin/sh" && dashc == "-c" => Some(s),
        _ => None,
    }
}

/// Single-quote a string for POSIX sh (`'` → `'\''`), so an arbitrary RUN script can be embedded in
/// the batched command without the outer shell reinterpreting it.
fn shell_quote_single(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Combine consecutive shell-form RUN scripts into one box command: each original script runs in its
/// own `/bin/sh -c '<script>'` subshell (exact per-RUN semantics + cwd reset), chained with `&&` so
/// the batch fails at the first failing step. A single script needs no re-wrap.
fn combine_run_scripts(scripts: &[&str]) -> Vec<String> {
    debug_assert!(!scripts.is_empty(), "combine_run_scripts needs ≥1 script");
    if scripts.len() == 1 {
        return vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            scripts[0].to_string(),
        ];
    }
    let combined = scripts
        .iter()
        .map(|s| format!("/bin/sh -c {}", shell_quote_single(s)))
        .collect::<Vec<_>>()
        .join(" && ");
    vec!["/bin/sh".to_string(), "-c".to_string(), combined]
}

/// Human-readable form of a RUN/CMD argv for progress lines: unwrap the `sh -c "…"` shell form.
fn display_run(argv: &[String]) -> String {
    // Unwrap OUR shell-form wrapper (`/bin/sh -c <s>`); an exec-form the user wrote prints in full.
    match run_shell_script(argv) {
        Some(s) => s.to_string(),
        None => argv.join(" "),
    }
}

/// Filesystem magic (`statfs.f_type`) of `p`'s deepest EXISTING ancestor - the path itself usually
/// doesn't exist yet (the scratch is created later). `None` only if nothing up to `/` can be stat'd.
fn fs_magic_of(p: &std::path::Path) -> Option<i64> {
    let mut cur = p;
    loop {
        if let Ok(c) = std::ffi::CString::new(cur.as_os_str().as_encoded_bytes()) {
            let mut st: libc::statfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::statfs(c.as_ptr(), &mut st) } == 0 {
                return Some(st.f_type as i64);
            }
        }
        cur = cur.parent()?;
    }
}

/// `kern stop <name>... | --all` - stop running box(es): SIGKILL each target supervisor's process
/// group (tearing down the box's PID namespace), drop its registry entry, and remove its writable
/// scratch. Stops every name in `names` (a name may match more than one box if names ever collide),
/// or - with `all` - every running box. A requested name that isn't running is reported on stderr
/// (never silently ignored); the command succeeds as long as at least one box was stopped.
/// The running boxes matching a list of user refs - each a box NAME or (fallback) its `kern ps`
/// supervisor PID. NAME WINS GLOBALLY: `!live_names.contains(n)` gates the pid branch, so an all-digit
/// box name is never shadowed by a coincidental pid, and `stop 79` can't hit both a box named "79" and
/// a different pid-79 box. Shared by `stop` and `pause`/`unpause` (the multi-target live commands).
fn boxes_matching_refs(
    running: Vec<registry::Instance>,
    refs: &[String],
) -> Vec<registry::Instance> {
    let live_names = live_name_set(&running);
    running
        .into_iter()
        .filter(|b| refs.iter().any(|n| ref_matches(b, n, &live_names)))
        .collect()
}

/// The set of live box names, for the NAME-wins gate. A `HashSet` (not a `Vec`) so `ref_matches`'
/// membership test is O(1): it's called for every (box × ref) pair, so a `Vec::contains` scan would
/// make selection O(N²) in the box count when stopping/pausing many refs.
fn live_name_set(running: &[registry::Instance]) -> std::collections::HashSet<String> {
    running.iter().map(|b| b.name.clone()).collect()
}

/// Does ref `n` select box `b`? A ref matches by NAME (always), else - only when no live box bears
/// that exact name (NAME wins globally) - by its PID or by its POD name. Matching a pod name selects
/// every member of that pod, so `kern stop <pod>` / `kern pause <pod>` act on the whole group.
fn ref_matches(
    b: &registry::Instance,
    n: &str,
    live_names: &std::collections::HashSet<String>,
) -> bool {
    n == b.name
        // `HashSet<String>::contains(&str)` via Borrow - O(1), no per-call allocation.
        || (!live_names.contains(n)
            // The pod branch guards against an EMPTY ref: a standalone box has `pod == ""`, so an
            // empty `n` would otherwise sweep every standalone box. A pid parses only when non-empty.
            && (n.parse::<i32>().ok() == Some(b.pid) || (!n.is_empty() && n == b.pod)))
}

/// The systemd unit file name for a persistent box - the naming convention lives here only.
fn unit_file_name(name: &str) -> String {
    format!("kern-{name}.service")
}

/// The `X-` key kern stamps into every unit IT writes for a persistent box. systemd ignores unknown
/// `X-` keys and preserves them, which makes this a free, machine-readable claim of ownership.
const MANAGED_MARKER: &str = "X-KernManagedBox";

/// Is this unit file one kern wrote for a persistent box, and therefore one kern may DELETE?
///
/// The name is not evidence. `stop --all` used to treat every `kern-*.service` in the user's unit
/// directory as its own and remove it, so a unit the user wrote by hand - including the one
/// `kern compose … systemd` tells them to write, which is named exactly that way - was deleted by an
/// unrelated `kern stop --all`. Deleting a file kern never created, outside kern's own state
/// directories, is not a cleanup; it is data loss.
///
/// Ownership is therefore asserted POSITIVELY, by two marks, and anything else is left alone:
///
/// * [`MANAGED_MARKER`], stamped by every unit kern writes from now on;
/// * `Description=kern box <name>`, which every unit kern wrote BEFORE the marker existed carries,
///   so an already-installed persistent box keeps being cleaned up across the upgrade.
///
/// Fail-safe by construction: a file that cannot be read, or is too large to be one of ours, is NOT
/// ours. The read is bounded because this runs over every candidate in a directory kern does not own.
fn is_kern_managed_unit(path: &std::path::Path) -> bool {
    use std::io::Read;
    // A kern unit is a few hundred bytes. 64 KiB is far above any of ours and far below a file worth
    // paging in; a truncated read can only ever make the answer "not ours", which is the safe one.
    const MAX: usize = 64 * 1024;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = Vec::new();
    if f.by_ref().take(MAX as u64).read_to_end(&mut buf).is_err() {
        return false;
    }
    let Ok(text) = std::str::from_utf8(&buf) else {
        return false;
    };
    text.lines().any(|l| {
        let l = l.trim();
        l.starts_with(MANAGED_MARKER) || l.starts_with("Description=kern box ")
    })
}

/// Path of the systemd user unit for a persistent box named `name` (if the user's systemd dir is
/// resolvable). Existence of this file is what marks a box as systemd-managed. Returns `None` for a
/// name that isn't a valid box name - `kern stop <name>` takes raw, unvalidated names, and a `../`
/// one must never let `stop_managed_unit`'s `remove_file` escape the systemd user dir.
fn managed_unit_path(name: &str) -> Option<PathBuf> {
    BoxName::parse(name).ok()?;
    user_systemd_dir()
        .ok()
        .map(|d| d.join(unit_file_name(name)))
}

/// If `name` is a persistent (systemd-managed) box, stop + disable its unit and remove the unit file
/// so it neither restarts nor returns at reboot. Returns `true` if a unit was found and torn down.
fn stop_managed_unit(name: &str) -> bool {
    let Some(path) = managed_unit_path(name) else {
        return false;
    };
    // Last line of defence, deliberately duplicated with the callers' filter: this function DELETES,
    // and a future caller that forgets to filter must not be able to remove a stranger's unit.
    if !is_kern_managed_unit(&path) {
        return false;
    }
    let unit = unit_file_name(name);
    systemctl_user(&["disable", "--now", &unit]);
    // Clear any lingering `failed` state so the removed unit doesn't leave a ghost in `systemctl
    // --user status`; then delete the unit file and reload so systemd forgets it entirely.
    systemctl_user(&["reset-failed", &unit]);
    let _ = std::fs::remove_file(&path);
    systemctl_user(&["daemon-reload"]);
    true
}

/// How long `compose up` waits for a `depends_healthy` / `depends_completed` condition before it
/// gives up and aborts the bring-up. Docker's default `--wait` has no ceiling; we cap it so a stuck
/// dependency fails loudly instead of hanging a scripted `up` forever. Generous enough for a cold
/// database (postgres init + first health pass is a few seconds).
const COMPOSE_CONDITION_TIMEOUT_SECS: u64 = 120;

/// The exit-sidecar key for a box: `<pod>-<token>-<name>`. `<pod>` namespaces by STACK (two stacks
/// with a `db` don't collide - review 1b); `<token>` namespaces by this `up`'s RUN (two concurrent
/// `up`s of the SAME stack own separate files, so one's clear/write can't clobber the other's real
/// completion - review round 2, the round-1 "token only inside the file" left the filename shared).
/// `compose_pod_name(file)` is stable per compose file even for a `--no-pod` stack (no live pod), so
/// the prefix is well-defined in both modes. `compose down` doesn't know the `up`'s token, so it reaps
/// each box's sidecar by `exit_key_prefix(pod)` ++ `-<name>` (pod-prefix AND name-suffix) - NOT a
/// blind pod prefix, which would wipe a concurrent same-stack run's in-flight files.
fn exit_key(pod: &str, token: &str, name: &str) -> String {
    format!("{pod}-{token}-{name}")
}

/// The `<pod>-` prefix shared by every exit key of a stack - the LEADING anchor for `compose down`'s
/// reap; the box name (`-<name>`) is the trailing anchor, so together they bracket any token.
fn exit_key_prefix(pod: &str) -> String {
    format!("{pod}-")
}

/// Resolve every service's compose `build:` into a built image via `kern build`, mutating the box's
/// `image` to the built tag. See the call site for the four hardenings; this enforces them.
/// The directory a `build.context` is confined under: the compose file's parent, canonical.
///
/// Its own function because TWO callers need the identical base - `resolve_builds`, which builds, and
/// `compose watch`, which watches what a build would read. A second hand-written canonicalize is how
/// one of them ends up confining against a different directory than the other.
fn compose_base(file: &str) -> Result<std::path::PathBuf, Error> {
    let dir = compose_dir(file);
    std::fs::canonicalize(&dir)
        .map_err(|e| Error::Compose(format!("resolving compose dir '{}': {e}", dir.display())))
}

/// Resolve ONE service's build context and dockerfile against `base`, applying the confinement rules
/// in full, or `Ok(None)` when the service declares no `build:`.
///
/// THE GUARDS LIVE HERE AND NOWHERE ELSE. `resolve_builds` used to hold them inline, and adding a
/// second reader of `build.context` (`watch`) would have meant a second copy of a traversal check -
/// the exact shape in which one copy later drifts and stops refusing `context: ../../../etc`. Both
/// callers now get the same answer or the same refusal.
///
/// Guard 1: the canonical `base/context` must stay beneath `base`, so a context in a third-party
/// compose file cannot escape the project tree. Guard 1b: a `dockerfile:`, which Docker resolves
/// relative to the CONTEXT, must stay beneath the context for the same reason.
fn resolved_build_context(
    b: &crate::compose::ComposeBox,
    base: &std::path::Path,
) -> Result<Option<(std::path::PathBuf, Option<std::path::PathBuf>)>, Error> {
    let Some(bd) = b.build.as_ref() else {
        return Ok(None);
    };
    let ctx_abs = std::fs::canonicalize(base.join(&bd.context)).map_err(|e| {
        Error::Compose(format!(
            "service '{}': build context '{}': {e}",
            b.name, bd.context
        ))
    })?;
    if !ctx_abs.starts_with(base) {
        return Err(Error::Compose(format!(
            "service '{}': build context '{}' escapes the compose directory (refused)",
            b.name, bd.context
        )));
    }
    let dfile = match &bd.dockerfile {
        Some(df) => {
            let df_abs = std::fs::canonicalize(ctx_abs.join(df)).map_err(|e| {
                Error::Compose(format!("service '{}': dockerfile '{df}': {e}", b.name))
            })?;
            if !df_abs.starts_with(&ctx_abs) {
                return Err(Error::Compose(format!(
                    "service '{}': dockerfile '{df}' escapes the build context (refused)",
                    b.name
                )));
            }
            Some(df_abs)
        }
        None => None,
    };
    Ok(Some((ctx_abs, dfile)))
}

fn resolve_builds(
    boxes: &mut [crate::compose::ComposeBox],
    file: &str,
    self_exe: &std::path::Path,
) -> Result<(), Error> {
    let base = compose_base(file)?;

    for b in boxes.iter_mut() {
        // The guards moved into `resolved_build_context` so `watch` applies the identical ones; see
        // its doc comment for why a second copy of a traversal check is the thing to avoid.
        //
        // NOTE (duale-di-Z2): confining the context ROOT is not enough on its own - `kern build` then
        // DESCENDS the context (COPY). That descent is itself confined: `copy_into_rootfs`
        // canonicalizes each COPY source and requires `starts_with(ctx)` (a source symlink pointing
        // out is rejected), and `cp -a` PRESERVES inner symlinks rather than following them (so a
        // symlink buried in the tree lands in the image verbatim, dangling inside the pivoted rootfs,
        // never read at build time). Verified live: a `leak -> /host/secret` inside the context does
        // not leak the host file into the image. So root-confine here + no-follow descent = closed.
        let Some((ctx_abs, dfile)) = resolved_build_context(b, &base)? else {
            continue;
        };
        let Some(bd) = b.build.clone() else { continue };

        // Guard 4 - `image:` + `build:` = build AND tag as `image`; `build:` alone → synthesized tag.
        // Either way the box RUNS the freshly built image, never a stale registry one.
        // LOWERCASED, BECAUSE KERN GENERATES THIS NAME AND OCI REPOSITORY NAMES ARE LOWERCASE.
        //
        // The box name carries the project directory, and a directory with a capital letter is
        // ordinary: MEASURED on the real repository `alitarhinisv/Notes-FE`, whose clone directory
        // produced `kern-compose-alitarhinisvNotes-FE-…:latest`, which `kern build` then REFUSED as
        // an invalid reference. kern was rejecting a name kern itself had just built, so a project
        // that builds under Docker could not be brought up at all - and the advice in the refusal
        // ("use the lowercase form") was addressed to a user who never typed the name.
        //
        // Only the SYNTHESIZED tag is touched. An `image:` the file wrote is passed through
        // unchanged: if that one is invalid the refusal is about something the author can see and
        // fix, which is the opposite situation.
        let tag = b
            .image
            .clone()
            .unwrap_or_else(|| synthesized_build_tag(&b.name));

        kern_common::progress!("→ building '{}' from {}", b.name, bd.context);
        let mut cmd = std::process::Command::new(self_exe);
        cmd.arg("build").arg("-t").arg(&tag);
        if let Some(df) = &dfile {
            cmd.arg("-f").arg(df);
        }
        // `build.target:` SELECTS THE STAGE, and forwarding it is the difference between running the
        // image the file asked for and running the last one in the Dockerfile. It used to be dropped
        // in the parser, so a `target: development` produced the production stage with nothing said.
        if let Some(t) = &bd.target {
            cmd.arg("--target").arg(t);
        }
        for a in &bd.args {
            cmd.arg("--build-arg").arg(a); // already ${VAR}-interpolated by the parser (guard 2)
        }
        cmd.arg(&ctx_abs);
        // Guard 3 - a build failure fails the whole `up` with a linked, service-named message.
        let status = cmd.status().map_err(|e| {
            Error::Compose(format!("service '{}': running `kern build`: {e}", b.name))
        })?;
        if !status.success() {
            return Err(Error::Compose(format!(
                "service '{}': build failed - run `kern build -t {tag} {}` to see why",
                b.name,
                ctx_abs.display()
            )));
        }
        b.image = Some(tag);
    }
    Ok(())
}

/// Reject conditional dependencies that can NEVER be satisfied, at bring-up time rather than after a
/// two-minute timeout (adversarial-review 2d). `topo_order` (called before this) already rejects
/// cycles and unknown deps; this adds the one statically-impossible case:
///   * `depends_healthy` on a box with no `health_cmd` - it can never report healthy.
///
/// NOTE on `depends_completed` + `restart`: the review suggested rejecting it, but in kern's compose
/// `restart = true` means ON-FAILURE (a bare `--restart`), NOT always-respawn - the supervisor re-runs
/// the box ONLY on a non-zero exit. So a `depends_completed` target that exits 0 completes normally,
/// and one that keeps failing crash-loops to the restart cap and then records its final non-zero exit,
/// which fails the wait cleanly. `restart = true` + `depends_completed` is therefore COHERENT, not
/// impossible - we must NOT reject it. (Were compose ever to gain an `always`/`unless-stopped` policy,
/// THAT would be the never-completes case to reject here.)
fn validate_conditions(boxes: &[crate::compose::ComposeBox]) -> Result<(), Error> {
    let find = |n: &str| boxes.iter().find(|x| x.name == n);
    for b in boxes {
        for dep in &b.depends_healthy {
            // BOTH SOURCES. `has_health()` answers about the file; `health_from_image` is set by
            // `settle_deferred_health_gates` when the image supplies the check. Reading only the
            // first refused a gate kern was about to honour, on a box already reporting `starting`.
            if find(dep).is_some_and(|x| !x.has_health() && !x.health_from_image) {
                return Err(Error::Compose(format!(
                    "box '{}' waits for '{dep}' to be healthy, but '{dep}' declares no `health_cmd` \
                     (add one, or use `depends_on`/`depends_completed`)",
                    b.name
                )));
            }
        }
    }
    Ok(())
}

/// Block until every conditional dependency of `b` is satisfied, or fail with a precise reason.
/// `depends_healthy[dep]` waits until `dep`'s health check reports `healthy`; `depends_completed[dep]`
/// waits until `dep` has run to completion (exit 0), keyed by `pod`+`token` so a same-named service in
/// another stack, or a previous run's sidecar, can't satisfy it. Driven off the registry sidecars the
/// box machinery already writes - no IPC of our own. Polled at 100 ms so a fast dep adds only a
/// sub-100 ms tail, not Docker's whole-second-per-health-interval granularity.
///
/// A dependency that DIES before satisfying its condition aborts immediately (adversarial-review 2a) -
/// we don't burn the full timeout on an already-decided outcome. The registry's liveness (a dep no
/// longer in `list()` and with no completion recorded) is the death signal.
fn wait_for_conditions(
    b: &crate::compose::ComposeBox,
    pod: &str,
    token: &str,
) -> Result<(), Error> {
    use std::time::{Duration, Instant};
    if b.depends_healthy.is_empty() && b.depends_completed.is_empty() {
        return Ok(());
    }
    let deadline = Instant::now() + Duration::from_secs(COMPOSE_CONDITION_TIMEOUT_SECS);
    let key_of = |dep: &str| exit_key(pod, token, dep);

    // `depends_healthy`: poll each dep's health sidecar until healthy. Abort on unhealthy, on the dep
    // dying, or on timeout.
    for dep in &b.depends_healthy {
        eprintln!(
            "  ⋯ waiting for '{dep}' to become healthy (for '{}')",
            b.name
        );
        loop {
            let status = current_health(dep);
            if status == "healthy" {
                break;
            }
            if status == "unhealthy" {
                return Err(Error::Compose(format!(
                    "box '{}': dependency '{dep}' is unhealthy (its health check keeps failing)",
                    b.name
                )));
            }
            // Dead before healthy - decided; don't wait out the timeout. Prefer the POSITIVE death
            // signal (a written exit sidecar) over the prune-timing one (absence from `list()`): a box
            // targeted by a `depends_completed` writes its exit on death, so a completion sidecar for
            // this dep is proof it's gone. Fall back to registry liveness for a dep that ISN'T a
            // completion target (no sidecar), where absence-from-`list()` is the only death signal -
            // there the timeout backstops the ≤1-poll prune lag (review 2a).
            let died = registry::exit_of(&key_of(dep)).is_some() || !is_box_alive(dep);
            if died {
                return Err(Error::Compose(format!(
                    "box '{}': dependency '{dep}' exited before becoming healthy - run `kern logs \
                     {dep}` for the reason (a crash, or e.g. a port already bound by a pod peer)",
                    b.name
                )));
            }
            if Instant::now() >= deadline {
                return Err(Error::Compose(format!(
                    "box '{}': timed out after {COMPOSE_CONDITION_TIMEOUT_SECS}s waiting for '{dep}' \
                     to become healthy (last status: '{}')",
                    b.name,
                    if status.is_empty() { "none yet" } else { &status }
                )));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    // `depends_completed`: poll each dep's stack+run-scoped exit sidecar until it completes; require 0.
    for dep in &b.depends_completed {
        eprintln!("  ⋯ waiting for '{dep}' to complete (for '{}')", b.name);
        loop {
            if let Some(code) = registry::exit_of(&key_of(dep)) {
                if code == 0 {
                    break;
                }
                return Err(Error::Compose(format!(
                    "box '{}': dependency '{dep}' did not complete successfully (exit {code}) - \
                     run `kern logs {dep}` for the reason",
                    b.name
                )));
            }
            if Instant::now() >= deadline {
                return Err(Error::Compose(format!(
                    "box '{}': timed out after {COMPOSE_CONDITION_TIMEOUT_SECS}s waiting for '{dep}' \
                     to complete",
                    b.name
                )));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    Ok(())
}

/// Is a box with this name currently in the registry (i.e. still running)? `list()` prunes dead
/// entries, so presence == alive. Used to fail a `depends_healthy` wait fast when the dep has died.
fn is_box_alive(name: &str) -> bool {
    registry::name_taken(name)
}

/// What `kern compose <file> <verb>` should do. One enum instead of a `down: bool` so every verb is
/// exhaustively handled at the dispatch (a new verb cannot be silently forgotten by the compiler).
///
/// kern's model differs from Docker's in one way that shapes these semantics: a kern box is
/// EPHEMERAL - there is no "created but stopped" state to restart into. So `Stop` ends the boxes and
/// keeps the pod (the shared network), and `Start` launches whatever is not currently running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposeAction {
    /// Bring the whole stack up (create the pod, build, launch in dependency order).
    Up,
    /// Stop every service AND tear the pod down.
    Down,
    /// Stop every service, KEEP the pod - so `start` can re-join the same shared network.
    Stop,
    /// Launch the services that are not currently running (the rest are left untouched).
    Start,
    /// `Stop` followed by a full `Up`.
    Restart,
    /// List this stack's boxes.
    Ps,
    /// Print this stack's logs (`--tail N`, and `-f` for a single service).
    Logs,
    /// Only run the `build:` directives; start nothing.
    Build,
    /// Only fetch each service's `image:`; start nothing.
    Pull,
    /// Parse, interpolate and validate, then print the resolved services. No side effects.
    Config,
    /// `exec [-T] [-e K=V] [-w DIR] <service> <command…>`: run a command in a RUNNING service.
    ///
    /// It used to be read as a service name, then as "a docker verb kern does not have, run
    /// `kern exec <box> …` instead". Both were wrong answers to the same question: the reader knows
    /// `web`, not `<project>-<hash>-web`, and looking the box up by hand is the step that sends
    /// people back to Docker. The command's exit status is kern's, as it is under Docker.
    Exec,
    /// `cp <service>:<path> <dst>` / `cp <src> <service>:<path>`: copy a file in or out.
    ///
    /// The same copier `kern cp` uses, with the SERVICE name resolved to the box name it now has.
    /// That resolution is the whole point: a reader of a compose file knows `web`, not
    /// `<project>-<hash>-web`, and looking it up by hand is the step that makes people reach for
    /// `exec … | tar` instead.
    Cp,
    /// `run <service> [command…]`: one-off box from a service's definition, in the foreground.
    ///
    /// The step 2 of nearly every project README (`run --rm web python manage.py migrate`), and the
    /// verb two independent reviewers both put first among what kern was missing. It brings the
    /// service's dependencies up exactly as `up` does, because it IS `up`: the dependencies are
    /// started by re-invoking this binary rather than by a second copy of the ordering rules.
    Run,
    /// `watch [service...]`: rebuild and restart a service when its `build:` context changes, and
    /// nothing else. Blocks until interrupted. See [`watch`] for the failure modes it handles.
    Watch,
    /// `port <service> <container-port>`: print the host address that serves that box port, read
    /// from the RUNNING box rather than from the file, so it answers what is published now. Exits
    /// non-zero when the service is not running or does not publish that port. No side effects.
    Port,
    /// Print a systemd unit for this stack on stdout. Installs nothing: kern is daemonless, so the
    /// one thing it cannot do for itself is come back after a reboot, and where that unit belongs is
    /// a decision about the user's machine. No side effects.
    Systemd,
}

/// Every compose sub-verb, in the order the help prints them. THE list: `from_verb`, the help line
/// and the usage error all read it, so a verb cannot work while being absent from what the CLI tells
/// you about itself. `systemd` shipped exactly that way, working but undocumented in both, because
/// the same list was written out three times by hand.
pub const COMPOSE_VERBS: &[(&str, ComposeAction)] = &[
    ("up", ComposeAction::Up),
    ("down", ComposeAction::Down),
    ("stop", ComposeAction::Stop),
    ("start", ComposeAction::Start),
    ("restart", ComposeAction::Restart),
    ("ps", ComposeAction::Ps),
    ("logs", ComposeAction::Logs),
    ("build", ComposeAction::Build),
    ("pull", ComposeAction::Pull),
    ("config", ComposeAction::Config),
    ("watch", ComposeAction::Watch),
    ("port", ComposeAction::Port),
    ("systemd", ComposeAction::Systemd),
    ("run", ComposeAction::Run),
    ("cp", ComposeAction::Cp),
    ("exec", ComposeAction::Exec),
];

impl ComposeAction {
    /// Parse a compose sub-verb. `None` for an unknown word, so the caller can report it with the
    /// full list rather than guessing.
    pub fn from_verb(v: &str) -> Option<Self> {
        COMPOSE_VERBS
            .iter()
            .find_map(|(name, a)| (*name == v).then_some(*a))
    }
}

/// Stop every service of a stack and reap its exit sidecars. Shared by `down`, `stop` and `restart`
/// so the (subtle) sidecar-reaping rule below lives in exactly one place. Returns the service names.
///
/// Sidecar keys are `<pod>-<token>-<name>`; a teardown does not know the `up`'s token, so it clears
/// `<pod>-*-<name>` per box it stopped - NOT a blind `<pod>-*`, which would wipe a concurrent
/// same-stack run's OTHER boxes. Each `remove_file` is atomic and ENOENT-safe, so two concurrent
/// teardowns just no-op over each other.
///
/// One race remains for pure name-scoping: `down A` stops A's `migrate`, a concurrent `up B`
/// re-creates a `migrate` box, then A's reap would delete B's fresh sidecar. Closed BY CONSTRUCTION:
/// a box's sidecars are reaped ONLY if that box is no longer alive.
fn stop_stack(boxes: &[crate::compose::ComposeBox], selected: &[String], pod: &str) -> Vec<String> {
    // DEPENDENTS FIRST, AND ONE LEVEL AT A TIME. Docker stops a service before the services it
    // depends on, and waits for a level to exit (or exhaust its grace) before signalling the next.
    //
    // kern signalled the whole stack at once. MEASURED with a trap that timestamps both the signal
    // and its own exit, on `a` depending on `b`: both traps fired in the same centisecond and the
    // whole `down` cost 3011 ms, which is ONE trap and not two. The consequence is not cosmetic: an
    // application writing to a database receives SIGTERM at the same instant as the database, so the
    // write it is in the middle of has nowhere to land.
    //
    // `stop` is already two-phase - it signals its batch, then waits per box - so calling it once
    // per level in reverse order is exactly the semantics, with no second mechanism. A level whose
    // boxes are already gone returns `NotRunning`, which is why the result stays best-effort.
    //
    // WHAT IT COSTS, so nobody reads a slow teardown as a hang: a five-level stack with a ten-second
    // grace can take fifty seconds to stop, and that is what Docker does with the same file.
    // THE ORDER COMES FROM THE WHOLE GRAPH, THE SET FROM THE SELECTION. `compose stop web` stops one
    // service, and the level it belongs to is still decided by every edge in the file: intersecting
    // afterwards keeps one rule instead of two.
    let names: Vec<String> = selected.to_vec();
    for batch in stop_batches(boxes, &names) {
        let _ = stop(&batch, false);
    }
    for n in &names {
        if !is_box_alive(n) {
            registry::clear_exit_matching(&exit_key_prefix(pod), &format!("-{n}"));
        }
    }
    names
}

/// The batches a teardown signals, in the order it signals them: dependents first, one dependency
/// level at a time, intersected with the services actually being stopped.
///
/// SPLIT OUT SO THE ORDER IS TESTABLE WITHOUT STOPPING ANYTHING. The rule is two lines and the cost
/// of getting it wrong is a database that receives SIGTERM in the same instant as the application
/// writing to it, which no test that only checks "everything stopped" can see.
///
/// A GRAPH THAT DOES NOT SORT STILL HAS TO STOP: `up` refuses a cycle, so an unsortable graph is
/// reachable only for a stack whose file changed under a running deployment. That falls back to one
/// batch with everything in it, which is what the teardown did before it had an order at all.
fn stop_batches(boxes: &[crate::compose::ComposeBox], selected: &[String]) -> Vec<Vec<String>> {
    let Ok(levels) = crate::compose::topo_levels(boxes) else {
        return vec![selected.to_vec()];
    };
    levels
        .iter()
        .rev()
        .map(|level| {
            level
                .iter()
                .filter(|n| selected.iter().any(|s| s == *n))
                .cloned()
                .collect::<Vec<String>>()
        })
        .filter(|batch| !batch.is_empty())
        .collect()
}

/// Every container port a service declares, with its protocol, from all THREE spellings.
///
/// `port:` (declared, injected as `PORT`), `expose:` (declared, the Compose spelling) and the
/// container side of each `ports:` mapping (published). They are one statement, "this service binds
/// this port in its namespace", and a reader that looks at only one of them protects only the source
/// it happened to look at: derived from `ports:` alone, the collision check saw only the services
/// that publish, which is the smaller half of a stack.
///
/// Its own function because there are now TWO readers - the collision check and the `--no-pod` relay
/// plan - and a second inline chain is how one of them later forgets `expose:`.
///
/// A malformed `ports:` spec contributes nothing here; the per-box path reports it precisely, and
/// duplicating that message from a planner would give the same file two different errors.
fn declared_container_ports(b: &crate::compose::ComposeBox) -> Vec<(u16, bool)> {
    b.port
        .map(|p| (p, false))
        .into_iter()
        .chain(b.expose.iter().copied())
        .chain(b.ports.iter().flat_map(|spec| {
            crate::ports::parse(spec)
                .unwrap_or_default()
                .into_iter()
                .map(|m| (m.box_port, m.udp))
        }))
        .collect()
}

/// The HOST ports a service publishes, deduplicated, in the order the file names them.
///
/// The host side, unlike [`declared_container_ports`]'s box side: what the stack claims on the
/// machine, which is what the privileged-port floor and the shift plan are about.
pub(crate) fn declared_host_ports(b: &crate::compose::ComposeBox) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::new();
    for spec in &b.ports {
        for pm in crate::ports::parse(spec).unwrap_or_default() {
            if !out.contains(&pm.host) {
                out.push(pm.host);
            }
        }
    }
    out
}

/// Fingerprint of everything that DEFINES a box, so `up` can tell a running service apart from the
/// file that describes it now.
///
/// The input is the exact argv `push_box_flags` builds plus the command: that argv IS the definition,
/// so anything that would produce a different box produces a different hash, and anything that would
/// not (comments, key order inside a mapping, a field kern ignores) does not. Deriving it from the
/// argv instead of from the YAML text is what keeps it from firing on cosmetic edits.
///
/// FNV-1a 64: deterministic, allocation-free over the input, no dependency. This is an
/// equality check between two runs of the SAME binary, not a security boundary - collisions here
/// would mean a missed recreate, not a trust decision, and no adversary chooses the input.
fn definition_hash(b: &crate::compose::ComposeBox) -> String {
    let mut cmd = std::process::Command::new("kern");
    b.push_box_flags(&mut cmd);
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |bytes: &[u8]| {
        for byte in bytes {
            h ^= u64::from(*byte);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    for a in cmd.get_args() {
        eat(a.as_encoded_bytes());
        eat(&[0]); // separator: `["ab","c"]` must not hash like `["a","bc"]`
    }
    for c in &b.command {
        eat(c.as_bytes());
        eat(&[0]);
    }
    format!("{h:016x}")
}

/// What `up` must do with a service that is ALREADY running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reconcile {
    /// Running and still matches the file: leave it alone.
    UpToDate,
    /// Running but the file changed since: stop it so the launch loop recreates it.
    Recreate,
}

/// Decide, for one running service, whether the file still describes it.
///
/// A box registered by an older kern (or started outside compose) carries no fingerprint. Treating
/// that as "changed" would recreate it on every `up` forever; treating it as "up to date" is the
/// conservative choice and costs at most one missed recreate, after which the box carries a
/// fingerprint and behaves normally.
fn reconcile_decision(running: &registry::Instance, want: &str) -> Reconcile {
    if running.def_hash.is_empty() || running.def_hash == want {
        Reconcile::UpToDate
    } else {
        Reconcile::Recreate
    }
}

/// Reject, BEFORE anything starts, the conflicts a shared network namespace makes inevitable.
///
/// A pod is one net ns, so several properties that read as per-service in the file are in fact
/// pod-global. Each produces either a CONFLICT (two services declare incompatible values, and which
/// one wins depends on start order) or a silent INHERITANCE (one declares, all receive). This checks
/// the first kind; the second is announced at bring-up.
///
/// The generalisation matters more than any single case: the internal-port clash was found only
/// because a reviewer's premise was tested, and it is one member of a class, not a special case.
///
/// The gate lives HERE, not at the call sites. It used to be written at each of them, and they drifted
/// exactly as that always ends: `up` gated it, `systemd` ran it ungated, and `config` (the verb whose
/// whole job is answering "will this come up?") did not run it at all, so a stack that `up` refused
/// was reported clean by the dry run. One statement of the rule, three callers that cannot restate it
/// differently.
///
/// Not gated on `use_pod`'s third term (`any(!b.net)`) on purpose: services on the HOST network share
/// the host's namespace, so their internal ports collide just as surely. `use_pod` answers "create a
/// pod?", this answers "can these ports coexist?" - different questions that happen to share two terms.
/// Refuse a stack whose profiles resolve to HOST DEVICE NODES, unless the person running it said so
/// on the command line.
///
/// EVERY OTHER PROFILE KIND NARROWS. The file names a want, `kern.toml` holds the grant, and the local
/// grant is a ceiling: a downloaded compose file naming `x-kern-vdisk: scratch` cannot get more than
/// this host's `scratch` allows, whatever its author meant. "The local one wins" is the conservative
/// answer there by construction, because local is the smaller of the two authorities.
///
/// A `vgpio` PROFILE DOES NOT NARROW, and that is the whole reason this exists. Its resolution is a
/// device, not a bound, and there is no ordering on device nodes: `/dev/gpiochip0` is not a smaller
/// `/dev/gpiochip1`. One host's `leds` may be an LED; another's may be a relay board or a motor
/// controller. There is no direction in which taking the local grant is the safe one.
///
/// SO THE GATE IS ON THE PROPERTY, not on a list of kinds: does this profile resolve to a host path?
/// A future kind that also resolves to hardware inherits this without anyone remembering to add it.
///
/// NOT GATED OUTSIDE COMPOSE, and the reason is the root of trust rather than who typed the command.
/// `kern box vgpio:leds` is ungated, and so is a profile reached from `kern.toml` by any other route,
/// because `kern.toml` IS the authority on what a name grants in this model. "The person typed it"
/// would be the wrong reason: it breaks the day somebody proposes reading profiles from a system
/// directory or a package, where nobody typed anything.
///
/// The acknowledgement is UNFORGEABLE BY THE FILE: `--allow-device-grants` is a command-line flag, so
/// the author of a downloaded stack cannot put it in the YAML. It is not a prompt, because kern has
/// none and adding one for this would be a worse trade: the person typing the flag has read what
/// `kern compose <file> config` printed, which names the exact devices.
/// The dry-run rule has exactly ONE declared exception, and this array is what keeps it at one.
///
/// The rule is that `kern compose <file> config` refuses whatever the bring-up refuses, because a dry
/// run that disagrees is worse than none: it is the output people trust before committing a file.
/// Device grants are the exception, for the reason spelled out on [`device_grant_problem`].
///
/// AN EXCEPTION IS ONLY USEFUL WHILE THERE IS ONE. A second turns the rule into "usually", and a rule
/// with several exceptions stops applying itself. A test asserts this array's LENGTH, so adding the
/// second is a decision somebody makes on purpose rather than a precedent they inherit.
const DRY_RUN_REFUSAL_EXCEPTIONS: [&str; 1] = ["device grants (config reports, bring-up refuses)"];

/// The problem text, or `None` when there is none. Callers decide what to DO with it, and they do
/// not agree on purpose: a bring-up refuses, and `config` only reports.
///
/// `config` MAY NOT REFUSE THIS ONE, and it is the single exception to the rule that a dry run
/// rejects whatever the bring-up rejects. The refusal tells the reader to run `config` to see which
/// devices a name reaches, so a `config` that refused would make its own advice circular, and the
/// flag is meant to be passed by somebody who has READ that output. A verb that starts nothing can
/// state the verdict without enforcing it.
/// Is a persistent device grant recorded in the operator's OWN `kern.toml`?
///
/// READ FROM THE DEFAULT CONFIG ONLY, and that is the security property rather than a detail. The
/// native stack format lets a file point at its own config (`config = "bundled.toml"`), so a bundle
/// downloaded from anywhere could otherwise ship a `kern.toml` that sets `allow_device_grants = true`
/// and grant itself the hardware the gate exists to withhold. `load(None)` resolves the operator's
/// config (or `KERN_CONFIG`, which is equally theirs and equally outside the file), and nothing a
/// compose file says can redirect it.
///
/// A config that cannot be read is NOT a grant: an unreadable or malformed file answers `false`, so
/// the gate stays closed. Failing open here would make a corrupt config a permission.
/// The host's publish policy: which address a `-p`/`ports:` spec binds, and whether it OVERRIDES a
/// spec that named one.
///
/// READ FROM THE DEFAULT CONFIG ONLY, never from a `--config` path a compose file chose, for exactly
/// the reason `device_grants_allowed_by_config` is: a stack obtained from anywhere must not be able
/// to decide where the host listens by shipping its own `kern.toml`.
///
/// A CEILING, NOT A DEFAULT, and the distinction is the whole value of the key. An operator who sets
/// `publish_bind = "127.0.0.1"` is saying "nothing on this host is published beyond loopback"; a
/// policy that any file could defeat by writing `0.0.0.0:8080:80` would not be a policy at all. It is
/// never silent: the caller names how many specs it narrowed and what they had asked for.
///
/// `None` means the shipped behaviour, which is Docker's: bind every interface when the spec says
/// nothing, and honour an explicit address exactly as written.
/// `Err` carries the config's own error text; the CALLER decides what to do with it, and the only
/// correct choice is the narrow one.
///
/// AN UNREADABLE CONFIG MUST NOT MEAN "PUBLISH ON EVERY INTERFACE". The first version of this
/// function answered `None` on any error, which fell back to the shipped Docker default: a typo in
/// `kern.toml` therefore WIDENED every published port on the host, silently. MEASURED: with a config
/// holding `publish_bind = "1.2.3.4"`, `kern config list` refused it by line and `kern box` started
/// and bound `0.0.0.0` without a word. An absent config is not this case and never was: `load`
/// returns the defaults for a file that does not exist, so an `Err` here is always a file the
/// operator wrote and kern could not read.
pub(crate) fn publish_policy() -> Result<Option<u32>, String> {
    let cfg = crate::config::load_cached(None)?;
    Ok(match cfg.kern.publish_bind.as_deref() {
        Some("127.0.0.1") => Some(crate::ports::LOOPBACK_IP),
        Some("0.0.0.0") => Some(crate::ports::PUBLISH_DEFAULT_IP),
        // Absent: the shipped behaviour, which is Docker's. A value the parser refuses never reaches
        // here, because `load` fails first and this returns `Err`.
        _ => None,
    })
}

/// Apply [`publish_policy`] to a parsed spec list, returning how many maps it moved.
///
/// SEPARATED FROM THE POLICY LOOKUP so the decision can be asserted without a `kern.toml` on disk:
/// a function that both reads the filesystem and rewrites its argument can be checked by nothing.
pub(crate) fn apply_publish_policy(
    ports: &mut [kern_isolation::PortMap],
    policy: Option<u32>,
) -> usize {
    let Some(ip) = policy else {
        return 0;
    };
    let mut moved = 0;
    for p in ports.iter_mut() {
        if p.bind_ip != ip {
            p.bind_ip = ip;
            moved += 1;
        }
    }
    moved
}

/// Whether a published port kern cannot bind is moved or refused.
pub(crate) fn privileged_port_policy() -> Result<bool, String> {
    let cfg = crate::config::load_cached(None)?;
    // Absent means shift, which is what makes a file written for Docker run here at all.
    Ok(cfg.kern.privileged_port.as_deref() != Some("refuse"))
}

/// The port a privileged one is moved to. `80` becomes `8080`, `443` becomes `8443`, `53` becomes
/// `8053`: the conventional alternative for every port people actually publish, from one rule.
const PRIVILEGED_PORT_SHIFT: u16 = 8000;

/// Move every published host port below `floor` to one above it, returning `(from, to)` per port.
///
/// SEPARATED FROM THE POLICY LOOKUP for [`apply_publish_policy`]'s reason: a function that both
/// reads a config and rewrites its argument can be asserted by nothing.
///
/// KEYED BY THE PORT AND NOT BY THE ENTRY, so `53/tcp` and `53/udp` move together. A file that
/// publishes both and got two different host ports would be broken in a way that is very hard to
/// see: the DNS sample in Docker's own examples publishes exactly that pair.
///
/// A SHIFT NEVER LANDS ON A PORT THE SAME BOX ALREADY CLAIMS. Without that, a file publishing `80`
/// and `8080` would end with two entries on `8080`, and the second bind would fail with
/// `EADDRINUSE` blamed on some other process.
pub(crate) fn shift_privileged_ports(
    ports: &mut [kern_isolation::PortMap],
    floor: u16,
) -> Vec<(u16, u16)> {
    let mut low: Vec<u16> = ports
        .iter()
        .map(|p| p.host)
        .filter(|h| *h < floor)
        .collect();
    low.sort_unstable();
    low.dedup();
    let mut taken: std::collections::HashSet<u16> = ports
        .iter()
        .map(|p| p.host)
        .filter(|h| *h >= floor)
        .collect();
    let mut plan: Vec<(u16, u16)> = Vec::new();
    for from in low {
        let mut to = from.saturating_add(PRIVILEGED_PORT_SHIFT);
        while (to < floor || taken.contains(&to)) && to < u16::MAX {
            to = to.saturating_add(1);
        }
        if to < floor || taken.contains(&to) {
            // Nothing free above the floor at all. Left alone, so the bind fails and says so
            // rather than this quietly producing a duplicate.
            continue;
        }
        taken.insert(to);
        plan.push((from, to));
    }
    // Every `from` is below the floor and every `to` is at or above it, so a port moved here can
    // never match another `from` and be moved twice.
    for p in ports.iter_mut() {
        if let Some((_, to)) = plan.iter().find(|(f, _)| *f == p.host) {
            p.host = *to;
        }
    }
    plan
}

/// Re-spell one published port spec with new host ports, keeping everything the operator wrote.
///
/// THE BIND ADDRESS IS COPIED AS TEXT, never rebuilt from the parsed value. `crate::ports::parse`
/// fills in a DEFAULT address for a spec that names none, and that default is the operator's
/// `publish` policy at the box, so emitting `0.0.0.0:8080:80` for a file that said `80:80` would
/// silently overrule a configured `publish = "127.0.0.1"`. Copying the written prefix (present or
/// absent) leaves that decision exactly where it was.
///
/// `hosts` is one port per `PortMap` the spec expands to, in order, so a range spec becomes one spec
/// per element - the only way to say "these three moved and that one did not" in this syntax.
fn respell_port_spec(spec: &str, hosts: &[u16]) -> Option<Vec<String>> {
    let pms = crate::ports::parse(spec)?;
    if pms.len() != hosts.len() {
        return None;
    }
    let (head, proto) = match spec.rsplit_once('/') {
        Some((h, p)) if p.eq_ignore_ascii_case("udp") || p.eq_ignore_ascii_case("tcp") => {
            (h, format!("/{p}"))
        }
        _ => (spec, String::new()),
    };
    // Three parts means an explicit `ip:`; two means the caller's policy decides, and it must keep
    // deciding.
    let ip = match head.split(':').collect::<Vec<_>>().as_slice() {
        [ip, _, _] => format!("{ip}:"),
        _ => String::new(),
    };
    Some(
        pms.iter()
            .zip(hosts)
            .map(|(pm, host)| format!("{ip}{host}:{}{proto}", pm.box_port))
            .collect(),
    )
}

/// Move every privileged host port in the STACK to one kern can bind, as ONE plan.
///
/// Returns `(service, from, to)` per port moved, and rewrites the services' `ports:` in place.
///
/// ONE PLAN FOR THE WHOLE STACK, because the per-box shift cannot see its peers and that is a
/// MEASURED failure, not a theoretical one: a file where `web` publishes `80` and `other` publishes
/// `8080` starts `other` on 8080, moves `web`'s 80 onto 8080, and kills `web` with
/// `cannot publish host port 8080: Address already in use (os error 98)` - a message that names
/// neither the shift nor the service it collided with. Each box was avoiding only its OWN ports, so
/// every box independently picked the same conventional target.
///
/// Run before anything starts, so `config` and `up` report the same plan and neither can start half
/// a stack. A port at or above the floor is untouched, and a spec that does not parse is left for
/// the validation that already reports it.
pub(crate) fn shift_privileged_ports_across(
    boxes: &mut [crate::compose::ComposeBox],
    floor: u16,
) -> Vec<(String, u16, u16)> {
    // Every published PortMap in the stack, flattened, remembering where each came from.
    let mut all: Vec<kern_isolation::PortMap> = Vec::new();
    let mut origin: Vec<(usize, usize)> = Vec::new();
    for (bi, b) in boxes.iter().enumerate() {
        for (si, spec) in b.ports.iter().enumerate() {
            let Some(pms) = crate::ports::parse(spec) else {
                continue;
            };
            for pm in pms {
                all.push(pm);
                origin.push((bi, si));
            }
        }
    }
    let before: Vec<u16> = all.iter().map(|p| p.host).collect();
    let plan = shift_privileged_ports(&mut all, floor);
    if plan.is_empty() {
        return Vec::new();
    }
    // Group the new host ports back by (service, spec), then re-spell only the specs that moved.
    let mut moves: Vec<(String, u16, u16)> = Vec::new();
    let mut rewrites: std::collections::BTreeMap<(usize, usize), Vec<u16>> =
        std::collections::BTreeMap::new();
    let mut changed: std::collections::BTreeSet<(usize, usize)> = std::collections::BTreeSet::new();
    for (i, pm) in all.iter().enumerate() {
        let key = origin[i];
        rewrites.entry(key).or_default().push(pm.host);
        if pm.host != before[i] {
            changed.insert(key);
            let service = boxes[key.0].service_name().to_string();
            let mv = (service, before[i], pm.host);
            if !moves.contains(&mv) {
                moves.push(mv);
            }
        }
    }
    for (key, hosts) in rewrites {
        if !changed.contains(&key) {
            continue;
        }
        let (bi, si) = key;
        let Some(new_specs) = respell_port_spec(&boxes[bi].ports[si], &hosts) else {
            continue;
        };
        // The spec at `si` becomes the first, and any extra elements are appended: the indices of
        // the specs still to be visited must not move under this loop.
        let mut it = new_specs.into_iter();
        if let Some(first) = it.next() {
            boxes[bi].ports[si] = first;
        }
        let extra: Vec<String> = it.collect();
        boxes[bi].ports.extend(extra);
    }
    moves
}

/// The memory ceiling policy for a `kern compose` stack: `(operator_ceiling, host_ram)`.
///
/// FAIL-CLOSED ON A BROKEN CONFIG, for [`publish_policy`]'s reason and with the same asymmetry: an
/// unreadable `kern.toml` must not silently WIDEN what a service may take, so a config that will not
/// parse falls back to the historic `kern box` default and says so. The two wrong answers are not
/// symmetric, and only one of them lets a downloaded file take the machine.
pub(crate) fn compose_memory_policy() -> (Option<u64>, Option<u64>) {
    let loaded = crate::config::load_cached(None);
    if let Err(e) = &loaded {
        eprintln!(
            "kern: warning: {e}; compose services fall back to the {} MiB box default rather than \
             the host's RAM (an unreadable config must not widen a limit)",
            kern_isolation::DEFAULT_MEMORY_MAX / (1024 * 1024)
        );
    }
    let ceiling = compose_memory_ceiling(
        loaded
            .as_ref()
            .map(|c| c.kern.compose_memory_max.as_deref())
            .map_err(|_| ()),
    );
    (ceiling, host_meminfo_bytes("MemTotal:"))
}

/// The ceiling itself, given what the config said: `Ok(Some(text))` the key, `Ok(None)` no key,
/// `Err(())` a config that would not load.
///
/// SEPARATED FROM THE READ, exactly as `apply_publish_policy` is separated from `publish_policy`:
/// the fail-closed arm is the one that matters most and a function that reads the filesystem can be
/// asserted by nothing short of writing a `kern.toml` into the developer's own home.
pub(crate) fn compose_memory_ceiling(configured: Result<Option<&str>, ()>) -> Option<u64> {
    match configured {
        Ok(None) => None,
        // A VALUE THE PARSER CANNOT READ IS TREATED LIKE A CONFIG THAT WILL NOT LOAD, and that is
        // not belt-and-braces for its own sake: `v.and_then(parse)` reads an unparseable ceiling as
        // "no ceiling", which is the fail-OPEN shape one layer down from the arm below. The config
        // validator refuses such a value at load today, so this arm is unreachable through the
        // shipped path - and an unreachable arm that answers "uncapped" is one refactor away from
        // being the bug.
        Ok(Some(v)) => {
            Some(kern_common::parse_binary_size(v).unwrap_or(kern_isolation::DEFAULT_MEMORY_MAX))
        }
        // FAIL-CLOSED. The two wrong answers are not symmetric: falling back to the historic box
        // default costs a service that needed more an error naming a cap, while falling through to
        // "no ceiling" would let a typo in `kern.toml` hand every stack on the machine the whole of
        // its RAM, silently. The same asymmetry `publish_policy` is built on.
        Err(()) => Some(kern_isolation::DEFAULT_MEMORY_MAX),
    }
}

/// The `--memory` value one service gets, given what its file asked for and the policy.
///
/// A FUNCTION TAKING BOTH INPUTS, so the decision can be asserted without a `kern.toml` on disk and
/// without a particular machine's RAM. `None` means "pass no `--memory`", which leaves the box on
/// its own default - the answer when neither the file nor the operator nor `/proc/meminfo` said
/// anything, and the behaviour kern shipped before, so a host that cannot be read never fails in a
/// NEW way.
///
/// THE CEILING WINS OVER A LARGER `mem_limit:`, which is what makes it a policy rather than a
/// suggestion: a compose file is frequently something downloaded, and a limit a downloaded file can
/// raise by writing a bigger number limits nothing. It never RAISES a smaller `mem_limit:` - a
/// service that asked for less is asking for less than the operator allows, which is allowed.
/// The swap allowance a compose service gets, which until now was ZERO and is the difference that
/// kills a workload silently.
///
/// MEASURED ON THREE RUNTIMES, the same file, the same question:
///
/// ```text
///                                  Docker 29.6.2   podman 4.9.3   kern (before)
///   no memory key at all            max / max       max / max      hostRAM / 0
///   mem_limit: 256m                 256m / 256m     256m / 256m    256m / 0
/// ```
///
/// THE PREMISE OF THE OLD CHOICE WAS FALSE. `memory.swap.max = 0` was taken as "stricter and said
/// so", on the belief that a rootless runtime had to. podman is rootless and gives `max`/`max`, so
/// it did not have to; and kern's own ceiling is the host's RAM, not a small number, so the box was
/// not bounded either. Not strict, not Docker, and with no warning: a service that would have
/// swapped and survived under both references was OOM-killed here at the host's RAM, and nothing
/// at `config` said a word.
///
/// THE RULES, each one the measured behaviour of the two references:
///
///  * `memswap_limit` written: untouched. The parser already turned Docker's TOTAL into the v2
///    swap-only figure by subtraction, with Docker's two refusals copied.
///  * `mem_limit` written and no `memswap_limit`: the allowance equals the limit, so the service
///    gets the same 2x total Docker gives it. A file tuned against Docker's behaviour keeps it.
///  * nothing written: the host's own `SwapTotal`, which is the same decision the BUILD path already
///    took for the same measured reason, and grants no more than the machine has.
///
/// A host with no swap gets no flag: there is nothing to allow, and writing 0 would restate the
/// defect this closes.
pub(crate) fn service_swap_allowance(
    declared_memswap: Option<&str>,
    file_asked_memory: Option<&str>,
    host_swap: Option<u64>,
) -> Option<String> {
    if declared_memswap.is_some() {
        return None; // the file said it; the parser has already converted it
    }
    if let Some(asked) = file_asked_memory {
        // Docker's own pairing: `mem_limit` alone means memory AND an equal swap allowance.
        // An unparseable value is left alone rather than guessed at, exactly as the ceiling does.
        return kern_common::parse_binary_size(asked).map(|b| b.to_string());
    }
    host_swap.filter(|s| *s > 0).map(|s| s.to_string())
}

pub(crate) fn service_memory_cap(
    asked: Option<&str>,
    ceiling: Option<u64>,
    host_ram: Option<u64>,
) -> Option<String> {
    match asked {
        // The file asked for nothing: the operator's ceiling, else the machine's own RAM. Docker
        // imposes no limit on such a service and the machine is what bounds it, so this is the same
        // bound with the failure kept attributable to the box's own cgroup.
        None => ceiling.or(host_ram).map(|v| v.to_string()),
        Some(a) => match (kern_common::parse_binary_size(a), ceiling) {
            // The file asked and the operator caps it: the smaller of the two.
            (Some(bytes), Some(c)) => Some(bytes.min(c).to_string()),
            // Either no ceiling, or a `mem_limit:` KERN COULD NOT PARSE. Both forward the file's own
            // text verbatim, and the second case is the reason this is not written as one `min`:
            // substituting the ceiling for an unparseable value would swallow the typo and start the
            // service on a limit nobody wrote. Forwarded, the box's flag parser refuses it and names
            // it, which is a better error than anything this function could invent.
            _ => Some(a.to_string()),
        },
    }
}

/// Did the ceiling actually change what this service gets? Compared by VALUE, never by text.
///
/// `"32m"` and `"33554432"` are the same limit written two ways, and a check on the strings reports
/// every service in the stack as capped the moment a ceiling exists. A service the file left unset
/// (`before == None`) DID move: it would have had the host's RAM.
pub(crate) fn ceiling_moved(before: Option<&str>, after: &Option<String>) -> bool {
    let Some(after) = after.as_deref().and_then(kern_common::parse_binary_size) else {
        return false;
    };
    match before.and_then(kern_common::parse_binary_size) {
        Some(b) => after < b,
        // Nothing was written, so the ceiling decided the number: that is a move worth naming.
        None => true,
    }
}

/// The sentence an operator ceiling owes the reader, or `None` when it owes none.
///
/// NEVER SILENT WHEN IT BINDS, and silent otherwise. Without `[kern] compose_memory_max` a service
/// gets the machine's own RAM, which is what bounds it under Docker too, so there is no difference
/// to report and a line on every stack would be noise on 243 of 259 real files. With the key set,
/// the ceiling can be LOWER than a `mem_limit:` the file wrote, and a limit silently replaced by a
/// smaller one is exactly the shape that gets diagnosed as "the service is flaky" for a week.
///
/// The same rule `publish_bind` follows: a policy that overrides the file announces what it moved.
pub(crate) fn memory_ceiling_note(capped: &[&str], ceiling_bytes: u64) -> Option<String> {
    if capped.is_empty() {
        return None;
    }
    Some(format!(
        "`[kern] compose_memory_max` caps compose services at {} MiB, so {} under that rather \
         than under what the file asks for: {}. Over it a service is OOM-killed (exit 137) against \
         its own cgroup, not slowed down. Raise or remove the key to give a service more; a bigger \
         `mem_limit:` cannot, by design",
        ceiling_bytes / (1024 * 1024),
        // The VERB comes with the noun: "so this service runs under that" / "so these services run
        // under that". Split across the format string it read "so this service run".
        if capped.len() == 1 {
            "this service runs"
        } else {
            "these services run"
        },
        crate::compose::name_list(capped)
    ))
}

fn device_grants_allowed_by_config() -> bool {
    match crate::config::load_cached(None) {
        Ok(cfg) => cfg.kern.allow_device_grants,
        Err(_) => false,
    }
}

/// Has the OPERATOR granted `privileged: true` to compose files, on the command line or in their
/// own config?
///
/// NEVER THE COMPOSE FILE, and never a config a compose file named: the same rule as
/// [`device_grants_allowed_by_config`], for the same reason. `privileged: true` relaxes the seccomp
/// filter, and a filter a downloaded file can switch off is not a filter.
///
/// FAIL-CLOSED ON AN UNREADABLE CONFIG, which is the only safe direction for a grant: a file that
/// will not parse must not be read as permission.
fn privileged_allowed_by_config() -> bool {
    match crate::config::load_cached(None) {
        Ok(cfg) => cfg.kern.compose_privileged,
        Err(_) => false,
    }
}

/// Apply the operator's decision to every service that asked for `privileged: true`, and return the
/// sentence the stack is owed.
///
/// TAKES THE GRANT AS AN ARGUMENT AND CLEARS THE FIELD ITSELF, so `push_box_flags` has nothing to
/// decide: a flag that is emitted from a field which one caller sets and another might not clear is
/// how a grant comes to be applied where nobody asked for it. After this runs, `privileged` is true
/// only where it was granted.
///
/// WHAT IS GRANTED, EXACTLY: every capability the box's own user namespace can hold, and the relaxed
/// seccomp a nested runtime needs. What is NOT granted, and it is the dangerous third of Docker's
/// key: `/proc` and `/sys` stay masked. `/proc/sys/kernel/core_pattern` is not namespaced on Linux,
/// and unmasking it has already been a real escape in this project.
pub(crate) fn apply_privileged_grant(
    boxes: &mut [crate::compose::ComposeBox],
    granted: bool,
) -> Option<String> {
    let asked: Vec<String> = boxes
        .iter()
        .filter(|b| b.privileged)
        .map(|b| b.service_name().to_string())
        .collect();
    if asked.is_empty() {
        return None;
    }
    if !granted {
        for b in boxes.iter_mut() {
            b.privileged = false;
        }
        let names: Vec<&str> = asked.iter().map(String::as_str).collect();
        return Some(format!(
            "service(s) {} ask for `privileged: true`, which relaxes the seccomp filter, so kern \
             does not take it from the file: they run unprivileged. Grant it with \
             `--allow-privileged` on this command, or `[kern] compose_privileged = true` in your \
             own kern.toml. Rootless, the grant is every capability inside the box's OWN user \
             namespace and nothing over the host",
            crate::compose::name_list(&names)
        ));
    }
    let names: Vec<&str> = asked.iter().map(String::as_str).collect();
    Some(format!(
        "service(s) {} run with `privileged: true` as you granted: every capability their own user \
         namespace can hold, and the relaxed seccomp a nested runtime needs. NOT granted, because a \
         rootless runtime must not: `/proc` and `/sys` stay masked, so `core_pattern` and its \
         neighbours are unreachable. Docker's `privileged` unmasks them and is not rootless",
        crate::compose::name_list(&names)
    ))
}

fn device_grant_problem(boxes: &[crate::compose::ComposeBox], allow: bool) -> Option<String> {
    // The command line, or the operator's own config. Never the compose file, and never a config the
    // compose file named: see `device_grants_allowed_by_config`.
    if allow || device_grants_allowed_by_config() {
        return None;
    }
    for b in boxes {
        let toks = b.profile_tokens();
        if toks.is_empty() {
            continue;
        }
        let mut ap = AppliedProfiles::default();
        // A profile that does not resolve is somebody else's error, reported by the resolver that
        // runs beside this one. Silence here rather than a second, worse-worded version of it.
        if apply_profile_list(&toks, b.config.as_deref(), &mut ap).is_err() {
            continue;
        }
        if let Some(msg) = device_grant_refusal(b.service_name(), &ap.vgpio) {
            return Some(msg);
        }
    }
    None
}

/// The refusal text for a resolved set of `vgpio` profiles, or `None` when they grant no hardware.
///
/// THE PREDICATE IS OBSERVATIONAL, and the property it stands for is "does this grant access to
/// hardware". A resolved host path is how that is observed TODAY. A future kind that grants a device
/// by major/minor, by an inherited fd, or by a symbolic name inherits this gate only if its
/// resolution also produces a path; if it does not, the predicate has to grow rather than the kind
/// being added to a list.
///
/// TWO READS, ONE PATH. The gate resolves here and the box resolves again in its own process from the
/// same `--config`, so a `kern.toml` edited in between could differ from what was shown. That is the
/// validate-then-run shape, and it is accepted rather than closed: the file cannot reach it, because
/// only `kern.toml` decides what a name grants and the compose file's own `config:` key is reported
/// as `defined in:` when it names one. Closing it properly means passing a resolution across a
/// process boundary that today carries tokens.
///
/// Split from the check so the DECISION can be asserted: whether a grant is a device grant is the
/// whole of the behaviour, and it cannot be exercised end to end on a host with no gpiochip. The
/// predicate is "did this resolve to any host path", never "is this kind called vgpio", so a profile
/// that resolves to nothing is not gated and a future kind that resolves to hardware is.
fn device_grant_refusal(service: &str, vgpio: &[crate::config::ResolvedVgpio]) -> Option<String> {
    let devs: Vec<&str> = vgpio
        .iter()
        .flat_map(|g| g.devs.iter().chain(g.sysfs.iter()).map(String::as_str))
        .collect();
    if devs.is_empty() {
        return None;
    }
    let names: Vec<String> = vgpio.iter().map(|g| format!("vgpio:{}", g.name)).collect();
    Some(format!(
        "service '{service}' asks for {}, which on THIS host resolves to {}. A profile name says \
         nothing about which hardware it reaches: another machine's '{}' may be something else \
         entirely, and unlike a cpu or disk profile there is no sense in which the local grant is \
         the smaller one. Check what it resolves to with `kern compose <file> config`, then pass \
         --allow-device-grants to run it.",
        names.join(" "),
        devs.join(" "),
        vgpio.first().map(|g| g.name.as_str()).unwrap_or("")
    ))
}

/// Would ONE shared namespace refuse this stack because two services claim the same internal port?
///
/// THE PREDICATE THE REFUSAL IMPLIES, so the driver can act on it before deciding the wiring rather
/// than only after it has committed to the pod. It reads the SAME source as
/// [`check_pod_global_conflicts`] - `declared_container_ports`, which folds `port:`, `expose:` and
/// the container side of `ports:` into one claim - so the two cannot come to disagree about which
/// stacks collide.
///
/// MEASURED ON A REAL PROJECT: `AP0827/Multi-Threaded-Web-Server` puts an application and a
/// modsecurity proxy both on container port 8080. Docker runs it, because there each container has
/// its own namespace; kern refused it outright. That is a file Docker runs and kern would not, which
/// is the difference this project exists to remove - and the per-service wiring expresses it
/// exactly, so the answer is to choose that wiring rather than to refuse.
#[must_use]
pub(crate) fn pod_would_collide(boxes: &[crate::compose::ComposeBox]) -> bool {
    if boxes.len() < 2 {
        return false;
    }
    let mut seen: std::collections::HashMap<(u16, bool), &str> = std::collections::HashMap::new();
    for b in boxes {
        for slot in declared_container_ports(b) {
            if let Some(other) = seen.insert(slot, b.service_name()) {
                if other != b.service_name() {
                    return true;
                }
            }
        }
    }
    false
}

/// The image tag kern gives a service that has `build:` and no `image:`.
///
/// LOWERCASED, BECAUSE KERN GENERATES THIS NAME AND OCI REPOSITORY NAMES ARE LOWERCASE. The box name
/// carries the project directory, and a directory with a capital letter is ordinary: MEASURED on the
/// real repository `alitarhinisv/Notes-FE`, whose clone directory produced
/// `kern-compose-alitarhinisvNotes-FE-…:latest`, which `kern build` then REFUSED as an invalid
/// reference. kern was rejecting a name kern itself had just built, and the refusal's advice ("use
/// the lowercase form") was addressed to a user who never typed the name.
///
/// A FUNCTION SO THE TWO CALLERS CANNOT DRIFT: the builder synthesises this tag and `kern compose
/// watch` must rebuild the SAME one, or a watch rebuilds a tag nothing runs.
#[must_use]
pub(crate) fn synthesized_build_tag(box_name: &str) -> String {
    format!("kern-compose-{}:latest", box_name.to_ascii_lowercase())
}

/// One `/proc/meminfo` field in BYTES, or `None` when it cannot be read.
///
/// The kernel reports these in kibibytes, which is the one unit conversion here and the one place to
/// get it wrong; the value is multiplied by 1024 exactly once.
///
/// A FIELD PARAMETER RATHER THAN TWO NEAR-IDENTICAL FUNCTIONS, because the second reader
/// (`SwapTotal:`) arrived a day after the first and copying the parse would have been two places to
/// fix the day a kernel changes the format.
///
/// THE ORIGINAL LOOP RETURNED `None` ON THE FIRST NON-MATCHING LINE, which happened to work only
/// because `MemTotal:` is the first line of the file; `SwapTotal:` is not, so the loop now scans.
///
/// `None` rather than a guess: a caller that cannot learn the machine's size must fall back to
/// whatever it did before, not to a number invented here. A zero value (a host with no swap) is also
/// `None`, because passing `0` would mean "swap off", which is the state this exists to change.
#[must_use]
fn host_meminfo_bytes(field: &str) -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            let kib: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return kib.checked_mul(1024).filter(|b| *b > 0);
        }
    }
    None
}

fn check_pod_global_conflicts(
    boxes: &[crate::compose::ComposeBox],
    no_pod: bool,
) -> Result<(), Error> {
    // `--no-pod` gives each service its own namespace, and a lone service shares with nobody.
    if no_pod || boxes.len() < 2 {
        return Ok(());
    }
    // THE NAME THE FILE USES, which is what a reader compares a refusal against. One definition, in
    // `ComposeBox::service_name`, and it borrows: quoting a service in an error allocates nothing.
    let short = crate::compose::ComposeBox::service_name;

    // 1. INTERNAL ports. Two services listening on the same box port share one namespace: one binds,
    //    the other dies with EADDRINUSE. Common by default, not by accident - every framework has one
    //    canonical port (Node 3000, Flask 5000, Spring 8080), so two services of the same stack
    //    routinely want the same one even when their PUBLISHED ports differ.
    // Borrowed: `boxes` outlives this scan, so recording a name here allocates nothing. It held
    // owned `String`s cloned once per port per service, for values that never leave this function.
    let mut seen: std::collections::HashMap<(u16, bool), &str> = std::collections::HashMap::new();
    for b in boxes {
        // A declared `port` counts exactly like a published mapping's container port, and is the only
        // way an INTERNAL-only service (reached by name, publishing nothing) becomes visible here at
        // all. Derived from `ports:` alone, this check saw only the services that publish, so the
        // stack it protected was the smaller half of the stack. Declared ports are TCP.
        // Three sources, ONE space: `port:` (declared, injected as PORT), `expose:` (declared,
        // the Compose spelling) and the mappings from `ports:` (published). They are all the same
        // statement, "this service binds this port in the pod namespace", and have to be compared
        // together or the check protects only the source it happened to look at.
        for (port, udp) in declared_container_ports(b) {
            if let Some(other) = seen.insert((port, udp), short(b)) {
                if other != b.service_name() {
                    let proto = if udp { "udp" } else { "tcp" };
                    // THIS REFUSAL IS THE PRODUCT. There is no configuration that gives a stack both
                    // "two services on one internal port" and "peers resolve by name", so the whole
                    // of what kern can do for this file is explain the trade well, once, here.
                    //
                    // It shows the edit rather than describing it, and it prices BOTH routes.
                    // `--no-pod` used to be named with no cost attached, and MEASURED it is not free:
                    // in a pod `getent hosts db` answers `127.0.0.1 db db`, under `--no-pod` nothing.
                    // Sending someone from a loud port collision into a silent resolution failure
                    // inside their own code is not help.
                    //
                    // `PORT` IS NAMED AS A CONVENTION, not as a contract. kern really does pass it
                    // (measured: `port: 8081` clears the collision and the box gets PORT=8081), but
                    // an image is free to read a variable of its own instead, and for those the "two
                    // line edit" is two lines PLUS knowing which variable. Quoting the cheaper number
                    // and leaving the reader to find the rest is the same defect one level up.
                    //
                    // THE EDIT IS SPELLED, NOT DESCRIBED - inline rather than as a YAML block,
                    // because `ui::scrub` strips every control character from an error on the way
                    // out. That is deliberate and right: this message interpolates names that came
                    // from the file, and a newline is the cheap end of the same channel a terminal
                    // escape uses. Formatting is not worth weakening it for.
                    let svc = short(b);
                    let alt = port.saturating_add(1);
                    return Err(Error::Compose(format!(
                        "services '{other}' and '{svc}' both listen on container port {port}/{proto}. \
                         Services in a stack share ONE network namespace (like a Kubernetes pod), so \
                         only one of them can bind it. Either give one a different internal port - add \
                         `port: {alt}` under service '{svc}', and the stack keeps resolving peers by \
                         service name (kern passes it as PORT={alt}; PORT is a convention, not a \
                         contract, so an image that reads a variable of its own needs that one set \
                         instead). Or run with --no-pod, where each service gets its own network \
                         namespace and kern reaches peers through per-service loopback aliases: \
                         that works for this pair too, IF the service that hosts the alias binds a \
                         specific address rather than 0.0.0.0:{port}, since a wildcard listener owns \
                         every address on its port. kern measures which it is once the services are \
                         running and says so per direction, so with --no-pod you may lose one \
                         direction, both, or neither. Making one of them bind 127.0.0.1:{port} \
                         explicitly is usually a one-line change and costs no port renumber. \
                         Bring-up is ordered: each service is held before its first instruction \
                         until the relays it will use exist, so it never sees a half-built network \
                         (a service with `restart:` is started by systemd instead and is not held; \
                         `up` names it)."
                    )));
                }
            }
        }
    }

    // 2. `net.*` sysctls set to DIFFERENT values by different services. The knob belongs to the
    //    namespace, so the last service to start wins and the file does not say which that is.
    let mut sys: std::collections::HashMap<String, (String, String)> =
        std::collections::HashMap::new();
    for b in boxes {
        for kv in b.sysctls.iter().filter(|s| s.starts_with("net.")) {
            let (k, v) = kv.split_once('=').unwrap_or((kv.as_str(), ""));
            if let Some((prev_v, prev_svc)) = sys.get(k) {
                if prev_v != v {
                    return Err(Error::Compose(format!(
                        "services '{prev_svc}' and '{}' set sysctl '{k}' to different values \
                         ('{prev_v}' and '{v}'). `net.*` knobs belong to the pod's shared network \
                         namespace, so the last service to start would decide: set one value, or \
                         run with --no-pod.",
                        short(b)
                    )));
                }
            } else {
                sys.insert(k.to_string(), (v.to_string(), short(b).to_string()));
            }
        }
    }

    // 3. An `extra_hosts` entry that shadows a SERVICE name. Both write the pod's /etc/hosts, so the
    //    winner is decided by write order - and a service silently resolving to somewhere else is the
    //    worst kind of wrong.
    if let Some((svc, host)) = pod_hosts_collision(boxes) {
        return Err(Error::Compose(format!(
            "service '{svc}': extra_hosts entry '{host}' has the same name as a service in this \
             stack. Both write the pod's shared /etc/hosts, so which one resolves would depend \
             on start order: rename one of them."
        )));
    }
    Ok(())
}

/// Where a bind source WOULD land if it were created, symlink-resolved as far as the path exists.
///
/// EXISTS BECAUSE THE REGISTRY GUARD RUNS ON A CANONICAL PATH AND A MISSING PATH HAS NONE. The guard
/// has to answer before anything is created, or a compose file could plant empty directories inside
/// the registry and have the mount refused afterwards: the refusal would be right and the
/// directories would still be there.
///
/// THE FIRST VERSION ASKED THE GUARD ABOUT THE NEAREST EXISTING ANCESTOR AND THAT IS A DIFFERENT
/// QUESTION. The guard refuses any path that is an ANCESTOR of the registry root, because mounting
/// one exposes the whole registry - so `/run/user/1000` is refused, and every path under it was
/// therefore treated as registry-adjacent and never created. MEASURED with a positive control: a
/// source under `/run/user/1000/kern-not-the-registry/` was not created either, which is how the
/// mistake surfaced. Only the FULL intended path can be asked.
///
/// `None` when the path cannot be resolved that way, which includes a `..` in the part that does not
/// exist yet. Nothing is created then, which is the conservative direction.
fn planned_bind_source(source: &str) -> Option<std::path::PathBuf> {
    let want = std::path::Path::new(source);
    let abs = if want.is_absolute() {
        want.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(want)
    };
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut probe = abs.as_path();
    loop {
        if let Ok(existing) = std::fs::canonicalize(probe) {
            let mut planned = existing;
            for name in tail.iter().rev() {
                planned.push(name);
            }
            return Some(planned);
        }
        match (probe.parent(), probe.file_name()) {
            (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
                tail.push(name.to_os_string());
                probe = parent;
            }
            _ => return None,
        }
    }
}

/// The first `extra_hosts` entry that shadows a service name, as `(service, host)`.
///
/// ONE DEFINITION FOR TWO READERS, and they ask opposite questions of it: the pod conflict check
/// turns it into a refusal, and the wiring selector turns it into a REASON TO PICK THE OTHER WIRING.
/// Written twice they would drift, and the drift has a direction that matters: a selector that
/// missed a collision the checker catches would refuse a file kern can run.
///
/// WHY IT IS A POD CONDITION AND NOT A DEFECT IN THE FILE. Under Docker every container has its own
/// `/etc/hosts`, so a service mapping `postgres` to a fixed address shadows the name FOR ITSELF and
/// nobody else, and the file is unambiguous. Only one shared namespace makes the two entries fight,
/// so only one shared namespace has to refuse.
#[must_use]
pub(crate) fn pod_hosts_collision(
    boxes: &[crate::compose::ComposeBox],
) -> Option<(String, String)> {
    let names: std::collections::HashSet<&str> = boxes.iter().map(|b| b.name.as_str()).collect();
    for b in boxes {
        for host in b.add_host.iter().filter_map(|h| h.split(':').next()) {
            // Service names are project-scoped by now; `extra_hosts` carries what the file wrote, so
            // compare against both spellings.
            let clashes = names.contains(host)
                || boxes
                    .iter()
                    .any(|o| o.net_aliases.iter().any(|a| a == host));
            if clashes {
                return Some((b.service_name().to_string(), host.to_string()));
            }
        }
    }
    None
}

/// Best-effort WARNING for two pod services whose IMAGES expose the same container port even though
/// NEITHER declares it in the compose file - the implicit-EXPOSE case `check_pod_global_conflicts`
/// cannot see (two `nginx` default to :80, two `node` apps to :3000). A pod shares one network
/// namespace, so if both actually bind it the second dies with EADDRINUSE at runtime, with an obscure
/// error and no compose-time hint. This is deliberately SOFT: an image's `ExposedPorts` is a hint, not
/// a guaranteed bind (an nginx reconfigured off :80 will not collide), so it warns, never refuses.
/// Cache-only via [`PullPolicy::Never`]: it never pulls just to warn, so an uncached service is
/// skipped (and warned about, if it collides, once its image is present - e.g. the second `up`).
/// `--no-pod` gives each service its own network namespace, which is exactly why peers stop resolving
/// each other by service name. Say it once, at bring-up.
///
/// The two are the same fact seen from both ends: a shared namespace is what makes `db` an entry in
/// the pod's `/etc/hosts`, and it is also what makes two services unable to bind one port. Whoever
/// passes `--no-pod` is buying the second and paying the first, and until now nothing said so - a
/// service that resolved `db` yesterday simply fails to connect today, from inside its own code,
/// where the reason is invisible. Silent for a single service (it has no peers to lose).
/// What a resolved set of profiles actually granted, one line per kind, for `compose config`.
///
/// Separated from the printing so it can be asserted: the value of this output is entirely in WHICH
/// facts it carries, and a function that only writes to stdout can be checked by nothing. Empty when
/// the profiles granted nothing this host can name, which is itself worth seeing.
fn resolved_profile_lines(ap: &AppliedProfiles) -> Vec<String> {
    let mut out = Vec::new();
    let mut cpu = Vec::new();
    if let Some(c) = ap.cpus {
        cpu.push(format!("cpus {}", crate::ui::fmt_cpus(c)));
    }
    if let Some(c) = &ap.cpuset {
        cpu.push(format!("cpuset {c}"));
    }
    if let Some(n) = ap.nice {
        cpu.push(format!("nice {n}"));
    }
    if let Some(m) = ap.memory {
        cpu.push(format!("memory {}", human_bytes(m)));
    }
    if !cpu.is_empty() {
        out.push(format!("resolves to: {}", cpu.join(", ")));
    }
    for d in &ap.vdisk {
        let mut f = vec![match d.size {
            Some(s) => format!("size {}", human_bytes(s)),
            None => "uncapped".to_string(),
        }];
        if d.persistent {
            f.push("persistent".to_string());
        }
        if let Some(i) = d.iops {
            f.push(format!("{i} iops"));
        }
        if let Some(bw) = d.bandwidth {
            f.push(format!("{}/s", human_bytes(bw)));
        }
        out.push(format!("vdisk:{} resolves to: {}", d.name, f.join(", ")));
    }
    for g in &ap.vgpio {
        // The DEVICE NODES, because that is the grant. A name says nothing about which hardware a
        // host's `leds` reaches, and this is the one place an operator can see it before it runs.
        let mut paths: Vec<&str> = g.devs.iter().map(String::as_str).collect();
        paths.extend(g.sysfs.iter().map(String::as_str));
        let what = if paths.is_empty() {
            "nothing present on this host".to_string()
        } else {
            paths.join(" ")
        };
        out.push(format!("vgpio:{} resolves to: {what}", g.name));
    }
    out
}

/// Returns the note rather than printing it, like `container_only_port_note`: the DECISION of when to
/// say this is the whole of the behaviour, and a function that only writes to stderr can be asserted
/// on by nothing.
/// Services that declare no port at all, which under `--no-pod` cannot be reached by name.
///
/// A relay is built per DECLARED port (`port:`, `expose:`, or the container side of `ports:`), so a
/// service that declares none gets no relay and its peers get `Connection refused` at runtime, in a
/// service log, rather than a line at config time.
///
/// REPORTED FROM A REAL STACK, and the reason it catches people is worth stating: in Docker,
/// `expose:` grants nothing and is barely written any more, and kern IN A POD does not need it either
/// because the shared namespace makes it moot. So the requirement shows up in exactly the mode where
/// a file is most likely to have arrived unchanged from someone else.
///
/// Returns the note rather than printing it, like the other two, so a test can assert on the
/// decision instead of on stderr.
fn no_pod_undeclared_ports_note(
    boxes: &[crate::compose::ComposeBox],
    no_pod: bool,
) -> Option<String> {
    if !no_pod || boxes.len() < 2 {
        return None;
    }
    let mute: Vec<&str> = boxes
        .iter()
        .filter(|b| declared_container_ports(b).is_empty())
        .map(|b| b.service.as_str())
        .collect();
    if mute.is_empty() {
        return None;
    }
    // A stack where NOTHING declares a port is not a stack whose peers talk to each other, so the
    // note would be noise. It is the mixture that is a mistake: some services reachable, some not.
    if mute.len() == boxes.len() {
        return None;
    }
    let one = mute.len() == 1;
    Some(format!(
        "kern: note: {} {} no port (`port:`, `expose:` or `ports:`), so no peer relay is built for \
         {} and a peer reaches {} with a connection refused rather than by name. Declare the port \
         {} listens on to make {} reachable under --no-pod.",
        mute.iter()
            .map(|m| format!("'{m}'"))
            .collect::<Vec<_>>()
            .join(", "),
        if one { "declares" } else { "declare" },
        if one { "it" } else { "them" },
        if one { "it" } else { "them" },
        if one { "it" } else { "each one" },
        if one { "it" } else { "them" },
    ))
}

fn no_pod_peer_names_note(boxes: &[crate::compose::ComposeBox], no_pod: bool) -> Option<String> {
    if !no_pod || boxes.len() < 2 {
        return None;
    }
    // THE SECOND CLAUSE USED TO SAY "a peer address has to be a published 127.0.0.1:PORT", and that
    // advice does not work. MEASURED: without a pod a service's namespace holds only loopback and no
    // routes, so `127.0.0.1` inside a box is that box's OWN loopback. A port published to the host is
    // reachable from the host (verified, it answers) and not from a peer (verified, it does not). The
    // note was sending an operator to a workaround that fails, which is worse than saying nothing.
    // THIS NOTE HAS BEEN WRONG TWICE, IN OPPOSITE DIRECTIONS, and both times because it described the
    // mechanism rather than the outcome.
    //
    // It first said a peer address "has to be a published 127.0.0.1:PORT", which does not work: a
    // no-pod box holds only its own loopback, so that address is its own, and a port published to the
    // host is not reachable from a peer (both measured). It was then rewritten to say the services
    // "cannot reach each other at all", which was true when it was written and is no longer: peer
    // relays now give them name resolution over per-service loopback aliases.
    //
    // What stays true in every case is the one thing a reader must act on: a service cannot host a
    // peer's alias on a port it binds ITSELF, so two services sharing an internal port are still not
    // mutually reachable. `up` names each such pair, with the port.
    //
    // IT DOES NOT SAY "BELOW" ANY MORE. It did, and the pairs are measured from the RUNNING services,
    // so on a stack that builds first they arrive minutes later: reported from a real stack where a
    // TensorFlow build sat between the two, the line after this one was `building 'sidecar'` and the
    // reader concluded that nothing had been named. The note now travels with the pairs instead of
    // promising them.
    Some(
        "kern: note: --no-pod gives each service its own network namespace, and peers are reached \
         through per-service loopback aliases instead of a shared one. A service cannot host a peer's \
         alias on a port it binds itself, so two services that share an internal port are still not \
         mutually reachable; any such pair is named with it. A relay exists per DECLARED port \
         (`ports:`, `expose:` or `port:`), so a peer answers by name only on a port the file names, \
         and it carries TCP, so a datagram sent to another service's UDP port does not cross at all. Every other service is held before its first instruction until its \
         relays exist, so none of them starts against a half-built network."
            .to_string(),
    )
}

/// The services that a `--no-pod` bring-up CANNOT order, named.
///
/// Under `--no-pod` a box is held at a pre-exec gate until every relay it will use exists, so a
/// workload never observes a half-built network. A service that sets `restart:` does not get that:
/// outside a pod it is installed as a systemd unit and started later by the manager, in a process
/// that inherits no descriptor from `up`, so there is no gate to hold it with.
///
/// MEASURED, and the two directions differ, which is why this names the risk instead of the key.
/// Same fixture, one variable, three runs each: with the `restart:` service as the CONSUMER,
/// connecting at t=0, three of three got `NO-API`; with the line removed, three of three got the
/// peer's payload. As a PRODUCER it is unaffected (three of three delivered), because starting
/// early is not a problem for something that only has to be listening.
///
/// It is a note and not a refusal: `restart:` under `--no-pod` works, and the service that pays is
/// only one that connects out before its peers are up - which is also the case a restart loop is
/// there to survive. Returned rather than printed so the DECISION can be asserted.
fn no_pod_restart_gate_note(boxes: &[crate::compose::ComposeBox], no_pod: bool) -> Option<String> {
    if !no_pod || boxes.len() < 2 {
        return None;
    }
    let managed: Vec<&str> = boxes
        .iter()
        .filter(|b| b.restart_always)
        .map(|b| b.service.as_str())
        .collect();
    if managed.is_empty() {
        return None;
    }
    let one = managed.len() == 1;
    Some(format!(
        "kern: note: {} {} `restart:`, so under --no-pod {} started by systemd and {} NOT held \
         until the peer relays are up like the rest of the stack. {} listens for peers, nothing \
         changes; if {} connects out at startup, that first connection can precede the relay and \
         needs a retry (or drop `restart:` to have kern order it).",
        managed
            .iter()
            .map(|m| format!("'{m}'"))
            .collect::<Vec<_>>()
            .join(", "),
        if one { "sets" } else { "set" },
        if one { "it is" } else { "they are" },
        if one { "is" } else { "are" },
        if one { "If it only" } else { "If they only" },
        if one { "it" } else { "one of them" },
    ))
}

/// Pairs of services whose IMAGES expose the same port without either DECLARING it: `(first,
/// second, port, udp)`. Best-effort and cache-only - an image kern has not pulled contributes
/// nothing, because pulling to answer a question about wiring would be a surprise.
///
/// ONE SCAN, TWO READERS, and that is the whole point of returning them. This used to warn inline,
/// so the wiring decision could not see what the warning had just found: kern printed "the images
/// of 'postgres' and 'pgbouncer' both EXPOSE 5432/tcp; if both bind it the second fails at runtime
/// with EADDRINUSE" and then ran the stack in one shared namespace, where pgbouncer died with
/// exactly that. MEASURED on Sentry self-hosted, and the same shape had already cost Supabase a
/// bring-up (studio and rest, both on 3000).
pub(crate) fn image_expose_collisions(
    boxes: &[crate::compose::ComposeBox],
) -> Vec<(String, String, u16, bool)> {
    let mut out = Vec::new();
    if boxes.len() < 2 {
        return out;
    }
    let mut seen: std::collections::HashMap<(u16, bool), String> = std::collections::HashMap::new();
    for b in boxes {
        let Some(image) = b.image.as_deref() else {
            continue; // a `--rootfs`/`build`-only service has no image config to read
        };
        // Local image, then the memo, then the registry's CONFIG BLOB: see `image_exposed_ports`.
        // `None` is "could not find out" and is left to `images_not_read` to report; it is NOT an
        // empty EXPOSE set, which would put two colliding services into one namespace.
        let Some(exposed) = image_exposed_ports(image) else {
            continue;
        };
        for (port, udp) in exposed {
            if let Some(other) = seen.insert((port, udp), b.name.clone()) {
                if other != b.name {
                    out.push((other, b.name.clone(), port, udp));
                }
            }
        }
    }
    out
}

/// Where the EXPOSE sets read from a registry are remembered, for the wiring decision only.
///
/// A DIRECTORY OF ITS OWN, deliberately not the image store. An image-store entry holding a config
/// and no layers would read as "this image is present" to every other caller, and the next
/// `kern box --image` would fail on a rootfs nobody extracted. Nothing here is ever mistaken for an
/// image: the files hold port numbers and nothing else.
fn expose_memo_dir() -> std::path::PathBuf {
    if let Some(x) = std::env::var_os("XDG_CACHE_HOME") {
        return std::path::PathBuf::from(x).join("kern").join("expose");
    }
    if let Some(h) = std::env::var_os("HOME") {
        return std::path::PathBuf::from(h).join(".cache/kern/expose");
    }
    std::path::PathBuf::from(format!("/tmp/kern-expose-{}", unsafe { libc::getuid() }))
}

/// A filename for an image reference: every byte that is not a safe name character becomes `_`.
///
/// NOT a hash, so the directory stays readable by a person debugging a wiring decision, and not the
/// raw reference, which carries `/` and `:`. The mapping is many-to-one in principle
/// (`a/b:1` and `a_b_1` collide), so the file's FIRST LINE is the reference it was written for and a
/// read that does not match it is discarded. A collision then costs a refetch, never a wrong answer.
fn expose_memo_name(image: &str) -> String {
    image
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The ports an image EXPOSEs, for the wiring decision: from the local image if it is there, from
/// this cache if it has been asked before, and from the registry's CONFIG BLOB otherwise.
///
/// THE ORDER IS THE POINT. A pulled image always wins, so a `pull` that changes what a tag means
/// takes effect immediately and this cache can never override the real thing. The memo exists so a
/// second `config` on the same file is offline. The network is the last resort and costs a few
/// kilobytes: the config blob is a JSON document named by the manifest, not a layer.
///
/// `None` means "could not find out", which is a THIRD answer and not an empty set: an empty set
/// says the image exposes nothing, and reading a failure as that would put two services that do
/// collide into one namespace. Every caller distinguishes them.
fn image_exposed_ports(image: &str) -> Option<Vec<(u16, bool)>> {
    if let Ok((_, cfg)) = resolve_image_depth(image, 0, PullPolicy::Never) {
        return Some(cfg.exposed_ports);
    }
    let memo = expose_memo_dir().join(expose_memo_name(image));
    if let Ok(text) = std::fs::read_to_string(&memo) {
        let mut lines = text.lines();
        // The reference is the first line: a sanitised name is many-to-one, so a memo that was
        // written for a different image is discarded rather than trusted.
        if lines.next() == Some(image) {
            let mut ports = Vec::new();
            for l in lines {
                let (p, proto) = match l.split_once('/') {
                    Some((p, proto)) => (p, proto),
                    None => (l, "tcp"),
                };
                if let Ok(port) = p.parse::<u16>() {
                    ports.push((port, proto == "udp"));
                }
            }
            return Some(ports);
        }
    }
    // THE REGISTRY IS OPT-IN, and the measurement is why. Fetching a config blob costs one round
    // trip per image when the registry answers (~2 s measured on Docker Hub) and EIGHTY SECONDS for
    // a two-service file whose registry does not resolve at all, because the curl timeouts under
    // this path are 10 s connect / 30 s total and there are several requests per image. A dry run
    // that can take eighty seconds is not a dry run; Docker's `config` never touches the network.
    //
    // So the default answer stays "could not find out", declared as `wiring-images-unread:`, and
    // the fetch happens for callers that want the exact answer and can pay for it:
    // `compose-compat-rate.py` sets this because a published number must not depend on which
    // images a machine happens to hold.
    //
    // `up` DOES NOT NEED THIS. It resolves its images through the ordinary pull path before the
    // wiring is decided (see `ensure_images_for_wiring`), so the runtime answer is exact whatever
    // this variable says.
    std::env::var_os("KERN_COMPOSE_FETCH_IMAGE_CONFIG")?;
    // A scratch directory that is removed either way: the blob is a means, not a thing to keep, and
    // the image store must not learn about an image whose layers are absent.
    let scratch = expose_memo_dir().join(format!(".fetch-{}", std::process::id()));
    let fetched = kern_oci::fetch_image_config(image, &scratch, None);
    let _ = std::fs::remove_dir_all(&scratch);
    let cfg = fetched.ok()?;
    let mut text = String::with_capacity(64);
    text.push_str(image);
    text.push('\n');
    for (port, udp) in &cfg.exposed_ports {
        text.push_str(&format!("{port}/{}\n", if *udp { "udp" } else { "tcp" }));
    }
    // Best effort: a cache that cannot be written costs a refetch, not an answer.
    if std::fs::create_dir_all(expose_memo_dir()).is_ok() {
        let _ = std::fs::write(&memo, text);
    }
    Some(cfg.exposed_ports)
}

/// Settle the `service_healthy` gates the parser could not decide, now that images can be read.
///
/// THE DEFECT THIS CLOSES. A service with no `healthcheck:` in the file whose IMAGE carries a
/// `HEALTHCHECK` is healthy-gateable under Docker; kern downgraded the gate to start-order at parse
/// time, because the parser cannot open an image config. MEASURED with an image whose check flips at
/// 6 s: the dependent started at 0 s, so `condition: service_healthy` was another name for
/// `service_started`. `kern box` has always applied the image's healthcheck (`image_health_defaults`
/// in `start`), so the box really does report health; only the GATE was lost.
///
/// RESTORED, NOT WARNED, when the image supplies one: the gate is the file's own instruction and
/// kern can honour it. Reported when it does not, which is the warning the parser used to print and
/// now prints only for a target it could judge itself.
///
/// `depends_on` keeps the entry the parser added. It is implied by the stronger gate, so leaving it
/// costs an ordering constraint that is already satisfied and avoids a removal that could reorder a
/// graph for a reason unrelated to health.
fn settle_deferred_health_gates(boxes: &mut [crate::compose::ComposeBox]) {
    // Which services have an image healthcheck, resolved once: a stack of eight services on one
    // image must not open it eight times.
    let mut verdict: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    for b in boxes.iter() {
        let Some(img) = b.image.as_deref() else {
            continue;
        };
        if verdict.contains_key(img) {
            continue;
        }
        let has = resolve_image_depth(img, 0, PullPolicy::Never)
            .map(|(_, cfg)| cfg.healthcheck.is_some())
            .unwrap_or(false);
        verdict.insert(img.to_string(), has);
    }
    // Name -> image, so a gate can ask about its TARGET rather than about itself.
    let image_of: std::collections::HashMap<String, String> = boxes
        .iter()
        .filter_map(|b| b.image.as_ref().map(|i| (b.name.clone(), i.clone())))
        .collect();
    let mut restored: Vec<(String, String)> = Vec::new();
    let mut lost: Vec<(String, String)> = Vec::new();
    for b in boxes.iter_mut() {
        for dep in std::mem::take(&mut b.degraded_health) {
            let has = image_of
                .get(&dep)
                .and_then(|img| verdict.get(img))
                .copied()
                .unwrap_or(false);
            if has {
                if !b.depends_healthy.contains(&dep) {
                    b.depends_healthy.push(dep.clone());
                }
                restored.push((b.service_name().to_string(), dep));
            } else {
                lost.push((b.service_name().to_string(), dep));
            }
        }
    }
    // The TARGETS whose health comes from their image, marked so every later reader agrees with the
    // box that is already running that check. Done in a second pass because the loop above holds a
    // mutable borrow of the dependent, not of the target.
    let targets: std::collections::HashSet<String> =
        restored.iter().map(|(_, dep)| dep.clone()).collect();
    for b in boxes.iter_mut() {
        if targets.contains(&b.name) {
            b.health_from_image = true;
        }
    }
    for (who, dep) in restored {
        eprintln!(
            "kern: note: compose: service '{who}': dependency '{dep}' declares no `healthcheck:` but \
             its IMAGE carries one, so the `service_healthy` gate is honoured"
        );
    }
    for (who, dep) in lost {
        eprintln!(
            "kern: warning: compose: service '{who}': dependency '{dep}' has no usable healthcheck \
             (neither the file nor its image declares one) → its `service_healthy` gate is degraded \
             to start-order (depends_on); verify that's acceptable"
        );
    }
}

/// The services whose image could not be read, because it is not in the local cache.
///
/// WHY THIS HAS TO BE REPORTED. `image_expose_collisions` reads each image's `EXPOSE` set with
/// `PullPolicy::Never`, so its answer depends on what happens to be cached, and that answer DECIDES
/// THE WIRING: a file whose two services expose the same port is wired per service, and the same
/// file with the images absent is wired into one pod.
///
/// MEASURED on this corpus, same binary, same file, one pull apart:
///
/// ```text
/// image in the cache      config -> wiring: bridge
/// kern rmi <image>        config -> wiring: pod
/// ```
///
/// Two files moved between the buckets of a published rate that way, silently. Pulling to answer a
/// question about a file would be worse (a `config` that downloads gigabytes is not a dry run), so
/// the answer stays cache-dependent and SAYS SO.
pub(crate) fn images_not_read(boxes: &[crate::compose::ComposeBox]) -> Vec<String> {
    let mut out = Vec::new();
    if boxes.len() < 2 {
        return out; // one service cannot collide with another
    }
    for b in boxes {
        let Some(image) = b.image.as_deref() else {
            continue;
        };
        if image_exposed_ports(image).is_none() {
            out.push(format!("{} ({image})", b.service_name()));
        }
    }
    out
}

fn warn_image_expose_collisions(boxes: &[crate::compose::ComposeBox], no_pod: bool) {
    if no_pod {
        return;
    }
    for (other, name, port, udp) in image_expose_collisions(boxes) {
        let proto = if udp { "udp" } else { "tcp" };
        eprintln!(
            "kern: warning: the images of '{other}' and '{name}' both EXPOSE {port}/{proto}; a \
             stack shares ONE network namespace, so if both bind it the second fails at runtime \
             with EADDRINUSE. If they really serve the same port, give one a different internal \
             port (its own config, or `port:`), or run with `--bridge`, which gives each service \
             its own loopback."
        );
    }
}

/// How long to watch a freshly-launched stack for an IMMEDIATE death. Not "how long a service takes
/// to start": a service is not required to be READY here, only to still exist. This covers a failed
/// `execve`, a failed bind, a permission error and a missing file, which is the entire class `up` can
/// honestly speak about.
///
/// MEASURED, not chosen. A service that fails at once (`exit 3`, a missing binary, a failed exec) is
/// observably gone 0.7 ms after its box returns. This window is two orders of magnitude above that,
/// which leaves room for a board an order of magnitude slower than the desktop it was measured on.
///
/// It was 500 ms, justified by a comment stating the window "adds a fixed 500 ms to a bring-up that
/// already takes seconds". The bring-up measures ~40 ms: the window WAS the cost of `compose up`,
/// twelve times the work it was watching over. `compose up` of four services went from 540 ms to
/// ~190, and a stack with a failing service now reports in milliseconds instead of half a second.
const BRING_UP_SETTLE_MS: u64 = 150;

/// Watch the freshly-started services and return AS SOON AS one is gone, or when `ms` elapses.
///
/// The window used to be a flat sleep, so a stack whose service died instantly still took the whole
/// window to say so. Watching costs one cheap liveness check per service per tick and turns the
/// failure path from "always the full window" into "as fast as the failure happened", while a stack
/// that stays up pays exactly what it paid before.
fn watch_for_early_death(boxes: &[&crate::compose::ComposeBox], ms: u64) {
    // 10 ms: far below the window, far above the cost of one liveness check per service, so the
    // watch adds no measurable work to a stack that stays up.
    const TICK_MS: u64 = 10;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(ms);
    loop {
        if boxes.iter().any(|b| !is_box_alive(&b.name)) {
            return; // one is gone: the caller's registry pass decides whether that was legitimate
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return;
        }
        let left = deadline.saturating_duration_since(now);
        std::thread::sleep(left.min(std::time::Duration::from_millis(TICK_MS)));
    }
}

/// Names of the services that are gone after the settle window, in file order.
///
/// A service counts as legitimately finished when its exit sidecar records 0 - that is the same
/// signal `depends_completed` waits on, so a one-shot task that did its job is not reported as a
/// failure. Anything else that is no longer in the registry died, and `up` must say so.
///
/// One watch for the whole stack, then one registry read per service to classify what is gone.
fn settle_and_collect_dead(
    boxes: &[&crate::compose::ComposeBox],
    pod: &str,
    token: &str,
) -> Vec<String> {
    // BY REFERENCE, because the caller passes a SUBSET: `up web` starts web and its dependencies,
    // and the services the caller deliberately left out must not be examined. They were reported as
    // "died within 150ms of starting" - a death for a box that was never started - and turned a
    // bring-up that did exactly what was asked into a non-zero exit. MEASURED on a two-service file:
    // `up -d uno` printed `1 service(s) died: due`.
    watch_for_early_death(boxes, BRING_UP_SETTLE_MS);
    boxes
        .iter()
        .filter(|b| {
            if is_box_alive(&b.name) {
                return false;
            }
            // Gone: legitimate only if it recorded a clean completion.
            registry::exit_of(&exit_key(pod, token, &b.name)) != Some(0)
        })
        .map(|b| {
            b.name
                .strip_prefix(&format!("{pod}-"))
                .unwrap_or(&b.name)
                .to_string()
        })
        .collect()
}

/// The compose file's own directory - Docker's "project directory", which anchors `.env`, relative
/// bind sources and `build.context`. A bare filename (`docker-compose.yml`, no parent) means the
/// current directory, so the empty parent is mapped to `.` rather than to the filesystem root.
fn compose_dir(file: &str) -> std::path::PathBuf {
    std::path::Path::new(file)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// Stop this project's boxes that the file no longer names: `docker compose down --remove-orphans`.
///
/// WHAT LEAVES ONE BEHIND. A service renamed in the file (`web` becomes `api`) leaves the old box
/// running under the old name, still holding its published ports, and the next `up` fails on a bind
/// conflict against something the file no longer mentions. `down` alone cannot see it: it stops what
/// the file declares, and the orphan is by definition not declared.
///
/// THE SCOPE IS THE POD, which is this project's identity: a box is an orphan when it is a member of
/// this project's pod and its name is not one of the names the file resolves to. Nothing outside the
/// pod is touched, so another project's `db` is never in range however it is named.
///
/// Returns the names stopped.
fn remove_orphan_boxes(boxes: &[crate::compose::ComposeBox], pod: &str) -> Vec<String> {
    if pod.is_empty() {
        return Vec::new(); // a `--no-pod` stack has no membership to read
    }
    let declared: Vec<&str> = boxes.iter().map(|b| b.name.as_str()).collect();
    let orphans: Vec<String> = registry::list()
        .into_iter()
        .filter(|i| i.pod == pod && !declared.iter().any(|d| *d == i.name))
        .map(|i| i.name)
        .collect();
    let mut stopped = Vec::new();
    for name in orphans {
        // Best effort and one at a time: an orphan that is already gone must not stop the rest.
        if stop(std::slice::from_ref(&name), false).is_ok() {
            stopped.push(name);
        }
    }
    stopped
}

/// Delete the named volumes a project OWNS: `docker compose down -v`.
///
/// THREE CONDITIONS, and each one keeps a deletion from reaching data that is not this project's:
///
///  * the source must be a NAME, never a host path - a `-v /srv/db:/data` names a directory the
///    project did not create and must not remove;
///  * it must carry this project's prefix, which `scope_named_volumes` put there. A volume without
///    it predates the scoping and may hold another stack's data (that sharing is the very defect
///    the scoping fixed), so it is left alone;
///  * it must not be declared `external: true`. Docker never removes an external volume, because
///    the key means "this exists independently of me".
///
/// The path is then re-derived through `volume::volumes_dir()` and checked to still live under it
/// after canonicalisation, so a symlink planted at `<volumes dir>/<name>` cannot turn a delete into
/// a delete somewhere else.
///
/// Returns how many volumes were removed.
fn remove_project_volumes(
    boxes: &[crate::compose::ComposeBox],
    project: &str,
) -> Result<usize, Error> {
    let dir = crate::volume::volumes_dir();
    let base = std::fs::canonicalize(&dir).unwrap_or(dir.clone());
    let prefix = format!("{project}_");
    let mut done: Vec<String> = Vec::new();
    for b in boxes {
        for v in &b.volumes {
            let Some((src, _)) = v.split_once(':') else {
                continue;
            };
            if !matches!(
                crate::volume::classify(src),
                crate::volume::SourceKind::Named
            ) || !src.starts_with(&prefix)
                || b.external_volumes.iter().any(|e| e == src)
                || done.iter().any(|d| d == src)
            {
                continue;
            }
            let path = dir.join(src);
            if !path.exists() {
                continue;
            }
            let real = std::fs::canonicalize(&path)
                .map_err(|e| Error::Volume(format!("volume '{src}': {e}")))?;
            if !real.starts_with(&base) {
                return Err(Error::Volume(format!(
                    "volume '{src}' resolves outside the volumes directory (symlink?) - refusing to \
                     remove it"
                )));
            }
            std::fs::remove_dir_all(&real)
                .map_err(|e| Error::Volume(format!("removing volume '{src}': {e}")))?;
            done.push(src.to_string());
        }
    }
    Ok(done.len())
}

/// Stop a stack's services, reap its sidecars and remove its pod: the body of `compose down`.
///
/// SHARED with an attached `up`, whose Ctrl-C means exactly what `down` means, so the two cannot
/// drift into tearing down different amounts of the same stack. `selected` is what to stop (the
/// whole file for `down`, only what this invocation started for an attached `up`); `boxes` stays the
/// WHOLE graph either way, because the teardown order is read from the full dependency graph.
///
/// Returns how many services were stopped and whether a pod existed to remove.
pub(crate) fn tear_down_stack(
    boxes: &[crate::compose::ComposeBox],
    selected: &[String],
    pod: &str,
) -> (usize, bool) {
    tear_down_stack_keeping(boxes, selected, pod, true).0
}

/// [`tear_down_stack`], with a say over whether the exit records are reaped, and returning the
/// names it stopped.
///
/// WHY THE CHOICE EXISTS. `--exit-code-from` has to READ a service's exit status, and the status of
/// a service the teardown itself killed is only written DURING the stop. Reaping inside the teardown
/// left nothing to read: measured, `up --exit-code-from tests` exited 0 on a stack whose `tests`
/// exits 3, because `clear_waitexit_pod` had already removed the record by the time it was looked
/// up. That path stops, reads, and reaps afterwards.
pub(crate) fn tear_down_stack_keeping(
    boxes: &[crate::compose::ComposeBox],
    selected: &[String],
    pod: &str,
    reap: bool,
) -> ((usize, bool), Vec<String>) {
    // The relay holder FIRST, before the boxes stop. Killing it takes every relay with it through
    // PDEATHSIG, and doing it first means no relay is left pumping into a box that is being torn
    // down under it. Best-effort and idempotent: a stack that ran in a pod has no holder, and a
    // second `down` finds no file.
    if let Ok(dir) = crate::relayhold::stack_dir(pod) {
        crate::relayhold::kill_holder(&dir);
    }
    // LEAVE EVERY `external:` NETWORK, BEFORE THE BOXES STOP, and in this order for two reasons.
    //
    // The hosts lines this project wrote into ANOTHER project's boxes are removed by reaching into
    // those boxes, which only works while OUR record still says which networks we were on - and a
    // box that has stopped can no longer be looked up to find its peers. Leaving first also means a
    // stack coming up in the same instant never sees us as a member we are about to stop being.
    //
    // BEST EFFORT, LIKE THE HOLDER ABOVE. A `down` after a crash, a second `down`, or a stack that
    // never joined anything all reach this and must all be quiet: every step is a removal, and a
    // removal of something absent is what was wanted.
    let external: Vec<(String, String)> = boxes
        .iter()
        .filter(|b| !b.external_networks.is_empty())
        .flat_map(|b| {
            b.external_networks
                .iter()
                .map(|n| (n.clone(), b.name.clone()))
                .collect::<Vec<_>>()
        })
        .collect();
    if !external.is_empty() {
        // The foreign boxes that hold our names: everything on those networks that is not ours.
        let mut nets: Vec<String> = external.iter().map(|(n, _)| n.clone()).collect();
        nets.sort();
        nets.dedup();
        for (_, m, _) in crate::network::peers_of(&nets, pod) {
            crate::network::drop_foreign_hosts(&m.box_name, pod);
        }
        for (net, box_name) in &external {
            crate::network::leave(net, box_name);
        }
    }
    let names = stop_stack(boxes, selected, pod);
    // Reap THIS stack's `waitexit` sidecars (by pod + our own service names), including services
    // that had ALREADY exited before `down` - a live-only capture would miss exactly those. So
    // `compose ps -a` is empty after a `down` (matching Docker), while `compose stop` (which does
    // not call this) leaves the exited services visible.
    if reap {
        registry::clear_waitexit_pod(pod, &names);
    }
    // Tear the pod down QUIETLY (we just stopped the members, so `pod::remove`'s "members keep
    // running" note would contradict this). Only claim it was removed if one existed - a `--no-pod`
    // stack has none.
    let (pod_existed, _) = crate::pod::teardown(pod);
    ((names.len(), pod_existed), names)
}

/// Every mapping seen so far for ONE `(host port, protocol)` pair - the bucket that makes the
/// collision check linear instead of pairwise. `wildcard` is the service that bound `0.0.0.0` on this
/// pair (it subsumes every address, so anything else here conflicts with it); `specific` maps each
/// concrete bind address to its owner, and `first_specific` remembers one of them so a later wildcard
/// can name a counterpart in O(1).
#[derive(Default)]
struct PortSlot<'a> {
    wildcard: Option<&'a str>,
    first_specific: Option<&'a str>,
    specific: std::collections::HashMap<u32, &'a str>,
}

/// Pre-flight for `compose up`: reject two published mappings that would fight for the SAME host port.
///
/// Reuses the verified spec parser ([`crate::ports::parse`]) so range/`ip:host:box`/`/udp` forms are
/// interpreted exactly as at box-start. Two mappings conflict when they share protocol and host port
/// AND their bind addresses overlap - identical, or either bound to `0.0.0.0` (`bind_ip == 0`), which
/// subsumes any specific address.
///
/// LINEAR in the number of published mappings, by bucketing on `(host, udp)` and hashing the bind
/// address inside each bucket. The obvious pairwise form is quadratic, and that is NOT academic here:
/// a single `-p` may expand to 1024 ports (`ports::MAX_RANGE`), so a perfectly legal
/// 40-service stack of ranges reaches ~41k mappings and measured **10.5 s** of pure comparison before
/// a single box started (10/20/40 services = 0.7/2.7/10.5 s, textbook x4-per-doubling). Bucketing
/// makes the same file ~40 ms.
///
/// Panic-free (`Result` throughout); an unparseable spec is left for the per-box path to report, not
/// silently treated as a conflict.
///
/// On the protocol dimension: the compose parser (`ports_value`) already STRIPS the `/tcp` suffix and
/// drops non-TCP entries with a warning, so specs arriving here are always TCP today. Bucketing on
/// `(host, udp)` anyway keeps this faithful to `ports::parse`'s contract - the day kern publishes UDP,
/// a `udp/8080` and a `tcp/8080` won't be conflated into a bogus conflict.
fn check_port_collisions(boxes: &[crate::compose::ComposeBox]) -> Result<(), Error> {
    let mut slots: std::collections::HashMap<(u16, bool), PortSlot> =
        std::collections::HashMap::new();
    for b in boxes {
        // The name the file uses, for the same reason as in `check_pod_global_conflicts`.
        let name = b.service_name();
        for spec in &b.ports {
            let Some(pms) = crate::ports::parse(spec) else {
                continue;
            };
            for pm in pms {
                let slot = slots.entry((pm.host, pm.udp)).or_default();
                // Who (if anyone) already holds an address overlapping this one on this port+proto.
                let prior = match slot.wildcard {
                    Some(w) => Some(w), // 0.0.0.0 is already taken: everything here conflicts
                    None if pm.bind_ip == 0 => slot.first_specific, // we ARE the wildcard
                    None => slot.specific.get(&pm.bind_ip).copied(), // exact same address
                };
                if let Some(other) = prior {
                    let proto = if pm.udp { "udp" } else { "tcp" };
                    let who = if other == name {
                        format!(
                            "service '{name}' publishes host port {}/{proto} more than once",
                            pm.host
                        )
                    } else {
                        format!(
                            "services '{other}' and '{name}' both publish host port {}/{proto}",
                            pm.host
                        )
                    };
                    return Err(Error::Compose(format!(
                        "{who}. Only one process can bind a host port; give each a distinct one."
                    )));
                }
                if pm.bind_ip == 0 {
                    slot.wildcard = Some(name);
                } else {
                    slot.specific.insert(pm.bind_ip, name);
                    slot.first_specific.get_or_insert(name);
                }
            }
        }
    }
    Ok(())
}

/// Everything `compose` needs for the verbs that do NOT start anything, grouped so the extracted
/// dispatch keeps a readable signature instead of eight positional arguments.
struct TerminalOpts<'a> {
    pod: &'a str,
    file: &'a str,
    tail: Option<usize>,
    follow: bool,
    /// `-a/--all` for `ps`: also list the stack's recently-exited services.
    all: bool,
    services: &'a [String],
    /// Whether the bring-up this verb is answering questions about gives each service its OWN
    /// network namespace.
    ///
    /// NAMED FOR WHAT IT MEANS AND NOT FOR THE FLAG. It was called `no_pod`, and the name was the
    /// defect: `--bridge` also gives each service its own namespace, and the field kept saying "was
    /// --no-pod typed". MEASURED on the corpus: `config --bridge` refused 17 files that `config`
    /// accepts, all of them for the ONE-shared-namespace reason that a bridge does not have.
    own_namespaces: bool,
    /// Whether that bring-up reaches peers through RELAYS, which is a narrower question than the
    /// field above and the reason both exist.
    ///
    /// A bridge also gives each service its own namespace, but its members meet on a real network:
    /// they resolve each other by name, on any port, with no relay in between. The relay notes were
    /// keyed on `own_namespaces` and so were printed for a bridge stack, where every sentence in
    /// them is false. MEASURED on Elastic's own compose file, which kern wires on a bridge because
    /// three nodes share port 9200: kern said it was giving each service its own namespace on a
    /// bridge and then, in the next line, that two services sharing an internal port "are still not
    /// mutually reachable" - which is exactly what the bridge had just fixed.
    relay_wiring: bool,
    /// Whether the wiring was TYPED (`--pod`, `--bridge`, `--no-pod`) rather than chosen by kern.
    /// Reported by `config` as `wiring-source:`; see where it is captured in the driver for why the
    /// provenance has to travel next to the decision.
    wiring_from_flag: bool,
    /// See [`ComposeOpts::allow_device_grants`]; `config`/`systemd` refuse what `up` would.
    allow_device_grants: bool,
    /// `down -v`: also delete the named volumes this project owns.
    remove_volumes: bool,
    /// `down --remove-orphans`: also stop this project's boxes the file no longer names.
    remove_orphans: bool,
    /// `ps -q` / `--services` / `--format`.
    ps_quiet: bool,
    ps_services: bool,
    ps_format: Option<&'a str>,
}

/// Run the compose verbs that never launch a box, and report whether one ran.
///
/// `Ok(true)` means the verb was terminal and the command is done; `Ok(false)`
/// means the caller must continue to the bring-up (`up`, `start`, and `restart` after it has
/// stopped the stack). Extracted from `compose`, which had grown past 500 lines: the split is
/// exactly the boundary between "answers a question about the stack" and "changes it".
fn run_terminal_verb(
    action: ComposeAction,
    boxes: &mut [crate::compose::ComposeBox],
    o: &TerminalOpts<'_>,
) -> Result<bool, Error> {
    let (pod, file, tail, follow, all, services, own_namespaces) = (
        o.pod,
        o.file,
        o.tail,
        o.follow,
        o.all,
        o.services,
        o.own_namespaces,
    );
    let relay_wiring = o.relay_wiring;
    let allow_device_grants = o.allow_device_grants;
    let selected =
        |b: &crate::compose::ComposeBox| services.is_empty() || services.contains(&b.name);

    match action {
        // Read-only / terminal verbs: each returns, so the bring-up below is reached ONLY by the
        // verbs that actually start something (Up, Start, Restart).
        ComposeAction::Systemd => {
            // The SAME validation `config` runs, before emitting anything: a unit generated from a
            // file that cannot come up would fail at boot, on a machine nobody is watching, which is
            // the worst possible moment to discover a broken graph. Then the unit, on stdout only.
            crate::compose::topo_levels(boxes).map_err(Error::Compose)?;
            validate_conditions(boxes)?;
            check_port_collisions(boxes)?;
            check_pod_global_conflicts(boxes, own_namespaces)?;
            // REFUSES, unlike `config` below: this emits a unit that a machine will run unattended,
            // so it is a bring-up with a delay rather than a dry run.
            if let Some(msg) = device_grant_problem(boxes, allow_device_grants) {
                return Err(Error::Compose(msg));
            }
            crate::systemd::print_unit(file, pod)?;
            return Ok(true);
        }
        ComposeAction::Config => {
            // Parse + interpolate + validate, then print what kern actually resolved - the answer to
            // "is my file what I think it is" WITHOUT starting anything. Validation runs first so a
            // broken graph is reported here rather than at the next `up`.
            crate::compose::topo_levels(boxes).map_err(Error::Compose)?;
            validate_conditions(boxes)?;
            check_port_collisions(boxes)?;
            // The pod-global conflicts too: `config` is the verb you run to find out whether the file
            // will come up, so every rejection `up` performs has to be reachable from here. Reporting
            // a clean dry run for a stack that `up` then refuses is worse than not having the verb.
            check_pod_global_conflicts(boxes, own_namespaces)?;
            // The `--no-pod` trade belongs here too, not only at bring-up: `config` is the command
            // that answers "what will this file be", and `--no-pod` changes the answer. Measured
            // before this: `up --no-pod` said what it cost and `config --no-pod` said nothing, so
            // the reader who checks a file first was the one who did not hear it.
            // THE SEGREGATED PAIRS BELONG HERE TOO. They are a STATIC property of the file - the
            // memberships decide them and nothing has to be running - so `config`, the command that
            // answers "what will this file be", can and must state them. Measured before this: `up
            // --no-pod` named the cut pairs and `config --no-pod` named none, which is exactly the
            // split this file's own comment about the `--no-pod` trade was written to close.
            //
            // Unlike the unreachable-pair report, which is measured from RUNNING services and can
            // therefore only exist at bring-up, nothing here needs a box.
            // ONLY WHEN THE FILE SEGREGATES, which is what makes this correct under `--bridge`
            // too: a file whose `networks:` separate keeps the relay wiring even with the flag (one
            // bridge would put every service back on one network), and a file that separates nothing
            // produces no pairs here at all.
            if own_namespaces {
                let members: Vec<(String, Vec<String>)> = boxes
                    .iter()
                    .map(|b| (b.service.clone(), b.networks.clone()))
                    .collect();
                let cut = crate::nopod::segregated_pairs(&members);
                if !cut.is_empty() {
                    eprintln!(
                        "kern: note: {} service pair(s) share no network, so they get no relay and \
                         do not resolve each other: {}",
                        cut.len(),
                        cut.join("; ")
                    );
                }
            }
            if let Some(note) = no_pod_peer_names_note(boxes, relay_wiring) {
                eprintln!("{note}");
            }
            // REPORTS, and does not refuse. The device-grant refusal tells its reader to run THIS
            // verb to see which devices a profile name reaches; a `config` that refused would make
            // that advice circular, and the flag exists to be passed by somebody who has read this
            // output. The single deliberate exception to "a dry run refuses what the bring-up
            // refuses", and it is stated here rather than left as an inconsistency to be discovered.
            if let Some(msg) = device_grant_problem(boxes, allow_device_grants) {
                // THE LIST DECIDES, not this branch: drop the entry from
                // `DRY_RUN_REFUSAL_EXCEPTIONS` and `config` goes back to refusing, which is what
                // makes the list a mechanism rather than a note somebody has to remember.
                if DRY_RUN_REFUSAL_EXCEPTIONS
                    .iter()
                    .any(|e| e.starts_with("device grants"))
                {
                    eprintln!("kern: warning: {msg}");
                } else {
                    return Err(Error::Compose(msg));
                }
            }
            // Validate every published spec HERE, with the same parser the box uses. `config` is the
            // verb people run to check a file, so a typo must surface without starting anything (as
            // `docker compose config` does) instead of failing one box at bring-up. ALL bad specs are
            // reported together: fixing them one error per run is a poor loop.
            let bad: Vec<String> = boxes
                .iter()
                .flat_map(|b| {
                    b.ports
                        .iter()
                        .filter(|spec| crate::ports::parse(spec).is_none())
                        // NAME THE REASON WHEN IT IS KNOWN. An IPv6 or empty bind address is not a
                        // typo, it is a feature kern does not have, and "invalid port spec" sends the
                        // reader hunting for a mistake that is not in the line. Measured on a
                        // 240-file corpus: mailcow's `${HTTPS_BIND:-:}:443:443` expands to
                        // `::443:443` and cost an author a spec-by-spec bisection of fourteen ports.
                        .map(move |spec| {
                            if crate::ports::names_ipv6_or_empty_bind(spec) {
                                format!(
                                    "  {}: port '{spec}' - kern publishes on IPv4 only, so an IPv6 \
                                     or empty bind address cannot be expressed; use \
                                     `0.0.0.0:HOST:BOX` for every interface or `127.0.0.1:HOST:BOX` \
                                     for loopback",
                                    b.name
                                )
                            } else {
                                format!("  {}: invalid port '{spec}'", b.name)
                            }
                        })
                })
                .collect();
            if !bad.is_empty() {
                return Err(Error::Compose(format!(
                    "{} invalid port spec(s) - expected [ip:]host:box[/tcp|/udp], ports 1-65535:\n{}",
                    bad.len(),
                    bad.join("\n")
                )));
            }
            // `tmpfs:` GOES THROUGH THE SAME PARSER, for the same reason as `ports:` above and with
            // the same words in front of it: `config` exists so a file can be checked without
            // starting anything. It was not checked, and the gap has a name.
            //
            // Issue #8's published workaround is `tmpfs: - /dev/pts`. On a fixed binary `config`
            // answered "1 service(s)" and exited 0, and `up` then refused - so the verb whose whole
            // job is "tell me if this file is good" said yes about a file that cannot run. A reader
            // who trusts it concludes the refusal at `up` is a bug rather than the answer.
            //
            // `parse_tmpfs` is the SAME function the box start calls, so the two cannot disagree
            // about what is acceptable, and its message (including the devpts-specific one) is
            // reused verbatim rather than restated here.
            for b in boxes.iter() {
                if b.tmpfs.is_empty() {
                    continue;
                }
                if let Err(e) = parse_tmpfs(&b.tmpfs) {
                    return Err(Error::Compose(format!("service '{}': {e}", b.name)));
                }
            }
            // `config` REFUSES WHAT `up` WOULD REFUSE, and resource profiles were the one thing it
            // did not check. A file naming `x-kern-vgpio: leds` printed `profiles: vgpio:leds` and
            // exited 0, and `up` then failed with `no [[vgpio]] profile named 'leds'`. A dry run that
            // disagrees with the bring-up is worse than no dry run, because it is believed - the same
            // rule this command already follows for ports, invalid images and port collisions.
            //
            // THE RUNTIME'S OWN RESOLVER, not a second copy of the rule: `apply_profile_list` is the
            // function `kern box` calls, loading the same `kern.toml` through the same `--config`
            // path, so the two cannot drift into disagreeing about what resolves.
            for b in boxes.iter().filter(|b| selected(b)) {
                let toks = b.profile_tokens();
                if !toks.is_empty() {
                    let mut ap = AppliedProfiles::default();
                    apply_profile_list(&toks, b.config.as_deref(), &mut ap)?;
                }
                // The same rule for the same reason, one field over: `x-kern-security-profile: bogus`
                // used to print a clean preview and exit 0, and `up` then refused it with
                // `--security-profile: expected untrusted`. THE RUNTIME'S OWN VOCABULARY answers, so
                // this cannot drift from what `kern box` accepts - the compose crate deliberately does
                // not carry a copy of the list.
                if let Some(sp) = b.security_profile.as_deref() {
                    if SecurityProfile::parse(sp).is_none() {
                        return Err(Error::Compose(format!(
                            "config: service '{}': x-kern-security-profile: '{sp}' is not a \
                             security profile - kern box takes `untrusted`",
                            b.service_name()
                        )));
                    }
                }
            }
            println!("compose config: {} service(s) in {file}", boxes.len());
            // ONE FIELD, FOR WHATEVER COUNTS. The wiring is announced on stderr in prose that says
            // what it costs and what the alternatives are, which is right for a reader and wrong for
            // a tool: a census that matched `"on a bridge"` counted every POD stack as a bridge,
            // because the pod advisory recommends the bridge in that same sentence. It reported 60%
            // bridge on a corpus that is 85% pod, and it was only caught by a count that refused to
            // reconcile (136 files carrying the shared-loopback advisory against 85 read as pod).
            //
            // Improving an advisory must not be able to move a number, so the decision is also
            // printed as a token that says nothing else: `wiring: pod|bridge|relay`. Prose for the
            // reader, a field for whoever counts, and never one read as the other. It is derived
            // from the SAME two flags the bring-up carries, not re-derived from the file.
            println!(
                "  wiring: {}",
                match (own_namespaces, relay_wiring) {
                    (_, true) => "relay",
                    (true, false) => "bridge",
                    (false, false) => "pod",
                }
            );
            // A SECOND TOKEN, so the first one stays stable. `file` is not reachable yet: no compose
            // key pins the wiring today. It is in the vocabulary because the census that will have
            // to separate "kern chose this" from "the file asked for this" is written against this
            // field, and adding the value later must not change what `auto` and `flag` mean.
            println!(
                "  wiring-source: {}",
                if o.wiring_from_flag { "flag" } else { "auto" }
            );
            // THE ANSWER'S DEPENDENCE ON THE LOCAL CACHE, stated where the answer is. kern reads
            // each image's `EXPOSE` set to find two services claiming one internal port, and that
            // decides the wiring; an image that is not cached is not read, so the SAME file answers
            // `pod` before a pull and `bridge` after one. Measured on this corpus, one `kern rmi`
            // apart. A `config` that pulled to answer would not be a dry run, so the dependence
            // stays and is named.
            if !o.wiring_from_flag {
                let unread = images_not_read(boxes);
                if !unread.is_empty() {
                    println!(
                        "  wiring-images-unread: {} ({})",
                        unread.len(),
                        unread.join(", ")
                    );
                    eprintln!(
                        "kern: note: compose: the wiring above was decided WITHOUT reading {} \
                         image(s) that are not in the local cache: {}. kern reads an image's \
                         EXPOSE set to find two services claiming one internal port, so this answer \
                         can change after `kern compose <file> pull`.",
                        unread.len(),
                        unread.join(", ")
                    );
                }
            }
            // `config` reports the FILE, so it prints service names as written, not the
            // project-scoped box names the runtime uses.
            //
            // THE SERVICE NAME COMES FROM THE FIELD THAT KEPT IT, not from stripping a prefix off
            // the box name. Stripping worked for the default `<project>-<service>` form and did
            // nothing at all when a `container_name` replaced it, so the line printed the container
            // name while the comment above claimed it printed service names. A field report read
            // that output, concluded kern had replaced the service hostname, and removed four
            // `container_name` keys from a working file over it. Peers resolve by service name
            // either way - the alias is registered at bring-up - so the output was the entire
            // defect. `short` remains for a box that never went through the rewrite.
            let short = |n: &str| n.strip_prefix(&format!("{pod}-")).unwrap_or(n).to_string();
            // BOX NAME BACK TO THE FILE'S NAME, for the dependency edges. Those are rewritten onto
            // box names at parse time so everything downstream agrees on one set of names, which is
            // right for the runtime and wrong for this view: `config` reports the FILE, and the file
            // writes `depends_on: [keycloak]`, not `depends_on: [myapp-keycloak]`. Printing the box
            // name here is the same defect this line already had for the service name itself, one
            // row further down. Built once, outside the loop: it is a scan over every box.
            let service_of: std::collections::HashMap<&str, &str> = boxes
                .iter()
                .map(|b| (b.name.as_str(), b.service_name()))
                .collect();
            for b in boxes.iter().filter(|b| selected(b)) {
                let src = b
                    .image
                    .as_deref()
                    .or(b.rootfs.as_deref())
                    .unwrap_or("(build)");
                let svc = b.service_name().to_string();
                // The box name is shown only when it is NOT derivable from the service name, which
                // is exactly when a `container_name` set it. Printing `box=<project>-<service>` on
                // every line would be noise, and noise is how a reader stops reading the line that
                // matters.
                let boxed = if b.name == svc || b.name == format!("{pod}-{svc}") {
                    String::new()
                } else {
                    format!("  box={}", b.name)
                };
                println!("  {svc}  image={src}{boxed}");
                if !b.ports.is_empty() {
                    println!("    ports: {}", b.ports.join(", "));
                }
                // The v-profiles, because `config` answers "what did kern understand" and a profile
                // changes every cap the box runs under. Shown as the TOKENS the box will receive, so
                // the line can be copied onto a `kern box` command and behave the same; the file they
                // resolve against is named too, since a profile that is not in it is the one failure
                // this preview can warn about before anything starts.
                let tokens = b.profile_tokens();
                if !tokens.is_empty() {
                    println!("    profiles: {}", tokens.join(" "));
                    if let Some(c) = &b.config {
                        println!("      defined in: {c}");
                    }
                    // WHAT THE NAME RESOLVED TO ON THIS HOST, not just the name.
                    //
                    // A compose file names a grant and does not carry it, which is the right way round:
                    // a file downloaded from anywhere must not be able to grant itself hardware, so the
                    // LOCAL `kern.toml` always wins. The cost is that two hosts can read one file
                    // completely differently and say the same thing about it. MEASURED before this:
                    // `x-kern-vdisk: scratch` against a `scratch` of 64m and against a `scratch` of 50g
                    // printed the identical line, `profiles: vdisk:scratch`, on both.
                    //
                    // For `vgpio` that is the sharp case: the token is a name, and what it resolves to
                    // is a set of DEVICE NODES on this machine. An operator who runs somebody else's
                    // file is entitled to see which ones before anything starts, from the command whose
                    // whole job is explaining the file.
                    //
                    // Resolution errors are not reported here: the validation pass above already ran
                    // the same function and returned them, so reaching this line means it resolves.
                    let mut ap = AppliedProfiles::default();
                    if apply_profile_list(&tokens, b.config.as_deref(), &mut ap).is_ok() {
                        let lines = resolved_profile_lines(&ap);
                        if lines.is_empty() {
                            // SILENCE IS NOT AN ANSWER. A profile that resolves to nothing printed
                            // no line at all, so `profiles: vcpu:ml` with nothing under it read the
                            // same as a profile whose output this command simply does not show. It
                            // is also exactly what a MISTYPED key produces (`cores` where the key is
                            // `cpus`), which is the case this whole pairing exists to make visible.
                            println!(
                                "      resolves to: nothing (this build reads no cap from it - \
                                 check the [[...]] block for keys it does not have)"
                            );
                        }
                        for line in lines {
                            println!("      {line}");
                        }
                    }
                }
                // THE ONE KEY THIS FILE CARRIES THAT DOCKER WILL NOT ENFORCE, named with what it does
                // rather than left to a reader who has to know what the bundle contains. `config` is
                // the command that exists to explain the file, and a hardening bundle that is silent
                // here is a security posture the operator has to take on trust.
                if let Some(sp) = &b.security_profile {
                    println!(
                        "    security-profile: {sp} (seccomp allowlist + --cap-drop ALL + \
                         --read-only; kern only, Docker ignores it)"
                    );
                }
                // `config` answers "what did kern understand", so it must show a declared `port:`:
                // it is what the pod preflight reserves AND what the service receives as `PORT`, so
                // hiding it would leave the one command that exists to explain the file silent about
                // a field that changes both. Named as what it does, not just as its number.
                if let Some(p) = b.port {
                    // WHERE IT IS RESERVED DEPENDS ON THE WIRING, and this line said "in the
                    // pod" under every one of them. Measured on a `--no-pod` stack: `config`
                    // announced a reservation in a pod the stack does not have.
                    println!(
                        "    port: {p} (reserved {}, passed as PORT={p})",
                        if own_namespaces {
                            "for this service"
                        } else {
                            "in the pod"
                        }
                    );
                }
                if !b.expose.is_empty() {
                    let list: Vec<String> = b
                        .expose
                        .iter()
                        .map(|(n, udp)| format!("{n}/{}", if *udp { "udp" } else { "tcp" }))
                        .collect();
                    println!(
                        "    expose: {} (reserved {})",
                        list.join(", "),
                        if own_namespaces {
                            "for this service"
                        } else {
                            "in the pod"
                        }
                    );
                }
                // Through the reverse map first; `short` remains the fallback for an edge onto a
                // service that is not in this file, where there is no service name to recover and
                // the scoped form is all there is.
                let deps: Vec<String> = b
                    .all_deps()
                    .into_iter()
                    .map(|d| {
                        service_of
                            .get(d)
                            .map(|s| (*s).to_string())
                            .unwrap_or_else(|| short(d))
                    })
                    .collect();
                if !deps.is_empty() {
                    println!("    depends_on: {}", deps.join(", "));
                }
            }
            return Ok(true);
        }
        ComposeAction::Watch => {
            // The SAME confinement a build applies, by calling the same function: a context that
            // `resolve_builds` would refuse is refused here too, before a single watch is added.
            let base = compose_base(file)?;
            let mut contexts: Vec<(String, std::path::PathBuf, Option<std::path::PathBuf>)> =
                Vec::new();
            for b in boxes.iter().filter(|b| selected(b)) {
                if let Some((ctx, df)) = resolved_build_context(b, &base)? {
                    contexts.push((b.name.clone(), ctx, df));
                }
            }
            let selected_boxes: Vec<&crate::compose::ComposeBox> =
                boxes.iter().filter(|b| selected(b)).collect();
            let set = watch::watch_set(&selected_boxes, &contexts);
            // Resolved here rather than threaded through `TerminalOpts`: `watch` is the only terminal
            // verb that spawns kern again, and widening a struct six verbs share for one of them is
            // the wrong trade.
            let self_exe = std::env::current_exe()
                .map_err(|e| Error::Compose(format!("locating kern: {e}")))?;
            return watch::run(set, file, &self_exe).map(|()| true);
        }
        ComposeAction::Port => {
            // `kern compose <file> port <service> <container-port>` -> `IP:PORT` on stdout.
            //
            // READ FROM THE RUNNING BOX, NOT FROM THE FILE. The file says what was asked for; the
            // registry entry says what was actually bound, and those differ exactly when it matters
            // (a bind that failed refuses the box, but a stack brought up from an EDITED file that
            // has not been re-upped would otherwise print an address nothing serves). The cost is
            // that the service has to be running, which is also what `docker compose port` requires.
            //
            // Exit code is the contract as much as the output: a caller writes
            // `addr=$(kern compose f port web 8000) || exit 1`, so every "no answer" path has to be
            // an Err rather than an empty line with status 0.
            let (svc, want) = match services {
                [s, p] => (s.as_str(), p.as_str()),
                _ => {
                    return Err(Error::Compose(format!(
                        "compose port takes exactly two arguments, the service and its container \
                         port: `kern compose {file} port <service> <container-port>`"
                    )))
                }
            };
            // Parse the wanted port BEFORE looking anything up, so a typo is named as a typo instead
            // of reported as "not published", which would send the reader to the wrong file.
            let want_port: u16 = match want.parse::<u16>() {
                Ok(p) if p > 0 => p,
                _ => {
                    return Err(Error::Compose(format!(
                        "'{want}' is not a container port; it must be a number in 1..=65535"
                    )))
                }
            };
            // BOTH SPELLINGS, because the caller's word has already been mapped: the selection
            // above rewrites a known service name into its scoped box name, so `svc` arrives here as
            // `<pod>-<token>-web` for a valid service and as the raw word for an unknown one. Match
            // either, and report the FILE's names, which is what the reader typed.
            let Some(b) = boxes.iter().find(|b| b.name == svc || b.service == svc) else {
                let known: Vec<&str> = boxes.iter().map(|b| b.service.as_str()).collect();
                return Err(Error::Compose(format!(
                    "no service '{svc}' in {file}; it defines: {}",
                    known.join(", ")
                )));
            };
            let Some(inst) = registry::list().into_iter().find(|i| i.name == b.name) else {
                return Err(Error::Compose(format!(
                    "service '{}' is not running, so nothing is published for it; bring the stack \
                     up first: `kern compose {file} up`",
                    b.service
                )));
            };
            let published = crate::ports::parse_display_list(&inst.ports);
            if published.is_empty() {
                return Err(Error::Compose(format!(
                    "service '{}' publishes no ports",
                    b.service
                )));
            }
            // TCP first, then UDP, and never both: two protocols can legitimately share one box port,
            // and printing two lines would break the `addr=$(...)` shape this exists to serve. TCP is
            // the default protocol of a `ports:` entry, so it is the one a caller means by default.
            let hit = published
                .iter()
                .find(|m| m.box_port == want_port && !m.udp)
                .or_else(|| published.iter().find(|m| m.box_port == want_port));
            let Some(m) = hit else {
                let have: Vec<String> = published
                    .iter()
                    .map(|m| format!("{}{}", m.box_port, if m.udp { "/udp" } else { "" }))
                    .collect();
                // `b.service`, not `svc`: the caller's word was rewritten into the scoped box
                // name upstream, and echoing `pod-token-web` back at someone who typed `web` makes
                // them hunt for a name their file does not contain.
                return Err(Error::Compose(format!(
                    "container port {want_port} is not published by '{}'; it publishes: {}",
                    b.service,
                    have.join(", ")
                )));
            };
            println!(
                "{}.{}.{}.{}:{}",
                m.bind_ip >> 24 & 0xff,
                m.bind_ip >> 16 & 0xff,
                m.bind_ip >> 8 & 0xff,
                m.bind_ip & 0xff,
                m.host
            );
            return Ok(true);
        }
        ComposeAction::Ps => {
            // Reuse `kern ps` itself, scoped to this stack's pod - one renderer, so the compose view
            // can never drift from `kern ps` (same columns, same status rules, same --json). `-a`
            // threads straight through, so `compose ps -a` shows the stack's recently-exited services;
            // the phantom worry (a PRIOR run of the same pod name) is closed at the source by `down`
            // reaping its own boxes' sidecars precisely (see `ComposeAction::Down`).
            // THE POD FILTER FINDS NOTHING IN A `--no-pod` STACK, and the report was not "no pod",
            // it was "no services". MEASURED: two boxes up and visible in `kern ps`, and
            // `kern compose <file> ps` printing `0/2 services running` for the same stack, because a
            // no-pod box carries an EMPTY `pod` field and the filter compared it against the stack's
            // name. A status view that reports a running service as gone is worse than one that
            // refuses, since it is the view a person consults to decide whether something is wrong.
            //
            // The stack's box NAMES are the identity that holds in both modes, and they are already
            // scoped `<pod>-<service>`, so a substring filter on `<pod>-` selects this stack and no
            // other. Used only when the pod filter would match nothing, so a pod stack keeps the
            // exact selection it had, including any member renamed by `container_name` (which the
            // prefix would miss, and which keeps its `pod` field either way).
            let in_pod = registry::list().iter().any(|b| b.pod == pod);
            let filter = if in_pod {
                ("pod".to_string(), pod.to_string())
            } else {
                ("name".to_string(), format!("{pod}-"))
            };
            // `--services` ANSWERS FROM THE FILE, not from the registry, which is Docker's
            // behaviour and the only one that is useful: the list a deploy script iterates must be
            // the same whether the stack is up or down. Every other form asks `kern ps`.
            if o.ps_services {
                for b in boxes.iter().filter(|b| selected(b)) {
                    println!("{}", b.service_name());
                }
                return Ok(true);
            }
            // `--format json` is the spelling `docker compose ps` takes; `kern ps` calls the same
            // thing `--json`, so the two words are mapped onto the one renderer rather than
            // duplicating it. Any other template goes through as a template.
            let (shape, template) = match o.ps_format {
                // NDJSON, not an array: see `JsonShape::Lines` for the version this tracks.
                Some(f) if f.eq_ignore_ascii_case("json") => (JsonShape::Lines, None),
                Some(f) => (JsonShape::No, Some(f)),
                None => (JsonShape::No, None),
            };
            let as_json = shape != JsonShape::No;
            let rc = ps(
                shape,
                o.ps_quiet,
                all,
                std::slice::from_ref(&filter),
                template,
            );
            // The lines below explain a DEGRADED stack to a person. A machine-readable form has no
            // room for prose, and a script parsing NDJSON must not be handed a sentence.
            if as_json || o.ps_quiet || template.is_some() {
                return rc.map(|()| true);
            }
            // DEGRADED EDGES, NAMED HERE, because this is where a person looks to decide whether
            // something is wrong. A `--no-pod` stack's relays repair themselves; an edge that could
            // not be rebuilt is left alone so the rest keep working, and that trade is only
            // acceptable if the loss is reported somewhere. Silence would make it the partial
            // failure this codebase refuses.
            // ONLY WHILE A LIVE HOLDER OWNS THE FILE. `degraded` is written by the holder and
            // removed by `down`; a holder that is SIGKILLed or dies with the session leaves it
            // behind, and reading it then reports edges that are down on a stack that has no relays
            // at all. MEASURED: kill the holder without a `down` and `compose ps` kept naming two
            // edges as down for a set of relays that no longer existed.
            //
            // The liveness of the holder is a fact about a process; the file is a leftover. This is
            // the same rule the no-pod mode follows after it stopped being inferred from the plan
            // file's presence.
            if let Ok(rdir) = crate::relayhold::stack_dir(pod) {
                if crate::relayhold::holder_pid(&rdir).is_some() {
                    if let Ok(edges) =
                        std::fs::read_to_string(crate::relayhold::degraded_path(&rdir))
                    {
                        for e in edges.lines().filter(|l| !l.is_empty()) {
                            let p = crate::ui::Palette::detect();
                            println!("{}peer edge DOWN: {e}{}", p.r, p.z);
                        }
                    }
                }
            }
            // Without `-a`, a running-only view cannot answer "which service died?" - point AT the
            // answer when the file defines more services than are up, instead of leaving the user to
            // know that the pod name is the stack name.
            if !all {
                let defined = boxes.len();
                // Counted the same way the view above selects, or the count contradicts the rows.
                let running = registry::list()
                    .iter()
                    .filter(|b| {
                        if in_pod {
                            b.pod == pod
                        } else {
                            boxes.iter().any(|x| x.name == b.name)
                        }
                    })
                    .count();
                if running < defined {
                    let p = crate::ui::Palette::detect();
                    println!(
                        "{d}{running}/{defined} services running - exited: kern compose … ps -a{z}",
                        d = p.d,
                        z = p.z
                    );
                }
            }
            return rc.map(|()| true);
        }
        ComposeAction::Logs => {
            let wanted: Vec<&str> = boxes
                .iter()
                .filter(|b| selected(b))
                .map(|b| b.name.as_str())
                .collect();
            // `-f` over the WHOLE stack, interleaved and prefixed, which is what `docker compose
            // logs -f` does and what an attached `up` needs. It used to be refused ("follows ONE
            // service at a time"), on the belief that it needed a blocking reader per service; a log
            // file never blocks, so one poll pass reads them all (see `follow_many`).
            if follow && wanted.len() > 1 {
                let mut who = Vec::with_capacity(wanted.len());
                for b in boxes.iter().filter(|b| selected(b)) {
                    let Some(ins) = registry::find_ref(&b.name) else {
                        continue; // never started, or already exited: nothing to follow
                    };
                    match Followed::open(
                        b.service_name().to_string(),
                        b.name.clone(),
                        ins.pid,
                        tail,
                    ) {
                        Ok(Some(f)) => who.push(f),
                        Ok(None) => {}
                        Err(e) => eprintln!("compose logs: {}: {e}", b.service_name()),
                    }
                }
                if who.is_empty() {
                    return Err(Error::Compose(
                        "compose logs -f: none of the selected services is running".to_string(),
                    ));
                }
                follow_many(who, &FOLLOW_FOREVER, false)?;
                return Ok(true);
            }
            for (i, name) in wanted.iter().enumerate() {
                if wanted.len() > 1 {
                    if i > 0 {
                        println!();
                    }
                    println!("=== {name} ===");
                }
                // A service that never started (or already exited) has no log: report it and keep
                // going, so one missing service can't hide the others' output.
                if let Err(e) = logs(name, tail, follow) {
                    eprintln!("compose logs: {name}: {e}");
                }
            }
            return Ok(true);
        }
        ComposeAction::Pull => {
            let mut n = 0usize;
            for b in boxes.iter().filter(|b| selected(b)) {
                if let Some(img) = b.image.as_deref() {
                    pull(img, None, None)?;
                    n += 1;
                }
            }
            println!("compose pull: {n} image(s) up to date");
            return Ok(true);
        }
        ComposeAction::Build => {
            let self_exe = std::env::current_exe()
                .map_err(|e| Error::Compose(format!("locating kern: {e}")))?;
            resolve_builds(boxes, file, &self_exe)?;
            println!("compose build: done");
            return Ok(true);
        }
        ComposeAction::Down => {
            // ORPHANS FIRST, while the pod still exists to read membership from: `tear_down_stack`
            // removes the pod, and after that there is nothing left to ask which boxes were its
            // members.
            let orphans = if o.remove_orphans {
                remove_orphan_boxes(boxes, pod)
            } else {
                Vec::new()
            };
            let all: Vec<String> = boxes.iter().map(|b| b.name.clone()).collect();
            let (stopped, pod_existed) = tear_down_stack(boxes, &all, pod);
            if pod_existed {
                println!("compose down: {stopped} box(es) stopped, pod '{pod}' removed");
            } else {
                println!("compose down: {stopped} box(es) stopped");
            }
            if !orphans.is_empty() {
                println!(
                    "compose down: {} orphan(s) stopped: {}",
                    orphans.len(),
                    orphans.join(", ")
                );
            }
            if o.remove_volumes {
                match remove_project_volumes(boxes, pod) {
                    Ok(0) => println!("compose down: no named volumes to remove"),
                    Ok(n) => println!("compose down: {n} named volume(s) removed"),
                    Err(e) => return Err(e),
                }
            }
            return Ok(true);
        }
        ComposeAction::Stop => {
            // `stop` touches ONLY this file's services and never tears the pod down itself; `down`
            // removes the pod unconditionally. The distinction is real when the pod has members that
            // are NOT in this file (someone ran `kern box --pod <same>`): those keep running and the
            // pod with them. With no such member the pod still goes, because `kern stop` collapses a
            // pod once its LAST member exits (a deliberate, documented invariant - see `stop`); a
            // later `compose start` recreates it and services reach each other by name again.
            // ONLY THE SERVICES NAMED, and before this they were validated and then ignored: `stop b`
            // on an a/b/c stack stopped all three and reported "3 box(es) stopped" for one name. A
            // selector that is accepted and not honoured is the same class of defect as a cap that is
            // accepted and not enforced, which is the one thing this codebase refuses to do quietly.
            // No dependency expansion, matching Docker Compose: the named services are the whole
            // instruction, and pulling in a dependency would stop something the user did not name.
            // THE MODE IS READ BEFORE THE STOP, because afterwards there is nothing left to ask: a
            // stopped box leaves no registry entry to carry it. A stack running under `--no-pod` has
            // no pod at all, and the two-state message below called that "gone with its last member"
            // - false twice over, since nothing was ever there and the other services were still
            // running. Reported by an external reviewer against the released 0.8.6 binary.
            let was_no_pod = boxes
                .iter()
                .any(|b| registry::find(&b.name).is_some_and(|i| i.pod.is_empty()));
            // The same selection as before, and the ordering still read from the WHOLE graph: a
            // `stop web` must not lose the order the full teardown has.
            let chosen: Vec<String> = boxes
                .iter()
                .filter(|b| selected(b))
                .map(|b| b.name.clone())
                .collect();
            let names = stop_stack(boxes, &chosen, pod);
            if was_no_pod {
                // No pod is named, because none exists. `start` is still the way back, and it carries
                // the mode forward on its own.
                println!(
                    "compose stop: {} box(es) stopped (this stack runs without a pod)",
                    names.len()
                );
                return Ok(true);
            }
            let pod_alive = crate::pod::holder_pid(pod).is_some();
            println!(
                "compose stop: {} box(es) stopped, pod '{pod}' {}",
                names.len(),
                if pod_alive {
                    "still up (other members remain)"
                } else {
                    "gone with its last member (`start` recreates it)"
                }
            );
            return Ok(true);
        }
        // `restart` = stop everything, then fall through to the full bring-up below.
        ComposeAction::Restart => {
            // Same selection as `stop`; the bring-up below narrows to the same names, so
            // `restart b` stops and starts b and leaves its peers alone.
            // The same selection as before, and the ordering still read from the WHOLE graph: a
            // `stop web` must not lose the order the full teardown has.
            let chosen: Vec<String> = boxes
                .iter()
                .filter(|b| selected(b))
                .map(|b| b.name.clone())
                .collect();
            let names = stop_stack(boxes, &chosen, pod);
            println!(
                "compose restart: {} box(es) stopped, restarting",
                names.len()
            );
        }
        // `Run` is terminal but does its work in `compose()`, where the pod name, the project
        // directory and the resolved box flags all are. It falls through here for the same reason
        // `Up` does: this function answers "did a read-only verb already finish", and it did not.
        // `cp` IS TERMINAL and is answered here, where the box names are already resolved.
        ComposeAction::Cp => {
            let (Some(a), Some(b)) = (services.first(), services.get(1)) else {
                return Err(Error::Compose(format!(
                    "cp takes two paths: `kern compose {file} cp <service>:<path> <dst>` or the \
                     reverse"
                )));
            };
            // Rewrite `<service>:<path>` to `<box>:<path>` on whichever side names one. A side with
            // no colon is a host path and is passed through untouched; a side whose name is not a
            // service is left alone too, so `kern cp`'s own "no box named …" still reports it.
            let to_box = |arg: &String| -> String {
                match arg.split_once(':') {
                    Some((who, path)) => match boxes
                        .iter()
                        .find(|b| b.service_name() == who || b.name == who)
                    {
                        Some(b) => format!("{}:{}", b.name, path),
                        None => arg.clone(),
                    },
                    None => arg.clone(),
                }
            };
            crate::boxcp::cp(&to_box(a), &to_box(b))?;
            return Ok(true);
        }
        ComposeAction::Up | ComposeAction::Start | ComposeAction::Run | ComposeAction::Exec => {}
    }
    Ok(false)
}
/// `kern compose <file>` - bring up a stack of boxes (detached) in `depends_on` order. Each
/// service is launched via a fresh `kern box -d` subprocess, so it gets its own scope + registry
/// entry; track the stack with `kern ps`.
pub struct ComposeOpts<'a> {
    /// One or more compose files, merged left-to-right (`-f base.yml -f override.yml`).
    pub files: &'a [String],
    pub action: ComposeAction,
    /// `--wait`: hold after `up` until every service started is ready. See
    /// [`crate::cli::Command::Compose::wait_ready`] for the measured semantics.
    pub wait_ready: bool,
    /// `--wait-timeout N` in seconds; `None` uses kern's own condition timeout.
    pub wait_timeout: Option<u64>,
    /// The argv after `run <service>`; empty means the service's own `command:`.
    pub run_cmd: &'a [String],
    /// `run --rm`.
    pub run_rm: bool,
    /// `--no-deps`.
    pub no_deps: bool,
    /// `--exit-code-from <service>`: adopt that service's status. Implies `abort_on_exit`.
    pub exit_code_from: Option<&'a str>,
    /// `--abort-on-container-exit`: tear the stack down as soon as any service exits.
    pub abort_on_exit: bool,
    /// `down --remove-orphans`.
    pub remove_orphans: bool,
    /// `ps -q`.
    pub ps_quiet: bool,
    /// `ps --services`.
    pub ps_services: bool,
    /// `ps --format <template|json>`.
    pub ps_format: Option<&'a str>,
    /// `-v` on `down`: also delete the named volumes this project owns (see
    /// [`remove_project_volumes`] for the three conditions that bound what it deletes).
    pub remove_volumes: bool,
    /// `-d`: return as soon as the stack is up. Without it, an `up` whose stdout is a TERMINAL
    /// streams the stack's logs and stops the stack on Ctrl-C, as `docker compose up` does. See
    /// [`crate::cli::Command::Compose::detach`] for why the terminal is the condition.
    pub detach: bool,
    pub no_pod: bool,
    /// `--bridge`: a network namespace per service, meeting on a bridge the pod holds.
    pub bridge: bool,
    /// `--allow-privileged`: the operator granting a file's `privileged: true`.
    pub allow_privileged: bool,
    /// `--pod`: keep ONE namespace even when the file expresses segregation, which is the explicit
    /// opt-out of the auto-selection. Mutually exclusive with `no_pod`; the driver refuses both.
    pub force_pod: bool,
    /// `--allow-device-grants`: run a stack whose profiles resolve to HOST DEVICE NODES.
    ///
    /// Every other profile kind narrows: the file names a want, `kern.toml` holds a grant, and the
    /// local grant is a ceiling, so "the local one wins" is the conservative answer by construction.
    /// A `vgpio` profile does not narrow, because its resolution is a device rather than a bound and
    /// there is no ordering on device nodes: `/dev/gpiochip0` is not a smaller `/dev/gpiochip1`. One
    /// host's `leds` may be an LED and another's may be a relay board, and a downloaded compose file
    /// naming `x-kern-vgpio: leds` gets whichever this host has, silently.
    ///
    /// So a device grant asked for BY A COMPOSE FILE is refused unless the person running it says
    /// otherwise HERE, on the command line, where the file cannot reach. The gate is on the property
    /// (does this profile resolve to a device node?) and not on a list of kinds, so a future kind
    /// that also resolves to hardware inherits it without anyone remembering to add it.
    pub allow_device_grants: bool,
    pub tail: Option<usize>,
    pub follow: bool,
    /// `-a/--all` for `ps`: also list the stack's recently-exited services.
    pub all: bool,
    pub services: &'a [String],
    /// `-p/--project-name`: overrides the pod name normally derived from the file's directory.
    pub project: Option<&'a str>,
    /// `--env-file`: the interpolation table, instead of the project `.env`.
    pub env_file: Option<&'a str>,
    /// `--profile` (repeatable): profiles to activate, like `COMPOSE_PROFILES`.
    pub profiles: &'a [String],
}

/// Derive a STABLE, per-stack pod name from a compose file path. Uses the parent DIRECTORY name
/// (Docker's project-name rule - compose files are conventionally named `compose.yaml`, so the
/// directory identifies the stack, not the near-constant stem) plus a short hash of the CANONICAL
/// absolute path, so two same-named dirs in different locations never collapse into one pod. Same
/// file → same name (so `up` and `down` agree); different stacks → different pods.
fn compose_pod_name(file: &str) -> String {
    let path = std::path::Path::new(file);
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let raw = canon
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .or_else(|| path.file_stem().and_then(|s| s.to_str()))
        .unwrap_or("compose");
    let base: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(40)
        .collect();
    let base = if base.is_empty() { "compose" } else { &base };
    // A short hash of the canonical path disambiguates identical dir names in different locations.
    format!("{base}-{:08x}", fnv1a(&canon.to_string_lossy()) as u32)
}

/// The verbs `kern config` takes. ONE definition, referenced by the parser that refuses an unknown one
/// and by the dispatch below, because they were two lists and a verb added to one and not the other
/// would have been accepted and then silently treated as `list`.
pub(crate) const CONFIG_USAGE: &str = "config [list|add|rm|edit|setup|probe|clear]";

const CONFIG_ADD_USAGE: &str = "config add <vcpu|vgpio|vdisk>:<name> [--field value …] [--update]";
const CONFIG_RM_USAGE: &str = "config rm <vcpu|vgpio|vdisk>:<name>";

/// Split a `kind:name` token into a known profile kind + a name, or a usage error.
fn parse_profile_token(token: &str, usage: &'static str) -> Result<(String, String), Error> {
    let (kind, name) = token.split_once(':').ok_or(Error::Usage(usage))?;
    if crate::config::profile_fields(kind).is_empty() {
        return Err(Error::Config(format!(
            "unknown profile kind '{kind}' - use vcpu, vgpio or vdisk"
        )));
    }
    Ok((kind.to_string(), name.to_string()))
}

/// `kern config setup [--force]` - write a starter `kern.toml` to the default location (refusing to
/// clobber an existing one unless `--force`).
/// The host's resource inventory - `config probe` prints it; `config setup` seeds a kern.toml whose
/// example profiles already fit THIS machine (real core count / cpuset range / i2c buses).
pub(crate) struct HostInv {
    pub(crate) ncpu: usize,
    /// Total RAM in BYTES, or `None` when `/proc/meminfo` could not be read.
    ///
    /// BYTES AND NOT A DISPLAY STRING, which is what this used to hold. A humanised `"31.2G"` is
    /// lossy and, worse, is not a size this project's parser reads back, so the one caller that
    /// needed to WRITE the figure into a config could not have used it without generating a file
    /// `kern validate` refuses. The measurement is kept as a number and formatted at each use.
    pub(crate) ram_bytes: Option<u64>,
    /// Total bytes of the filesystem backing `/`, which is where a `[[vdisk]]` volume lands.
    pub(crate) root_total: Option<u64>,
    /// The whole disk backing `/`, resolved rather than guessed from the order of `/sys/block`.
    pub(crate) root_dev: Option<String>,
    pub(crate) disks: Vec<DiskInfo>, // physical block devices (whole disks, not partitions)
    pub(crate) gpiochips: Vec<String>, // short names, e.g. "gpiochip0"
    pub(crate) i2c: Vec<String>,     // "i2c-0", …
    pub(crate) spi: Vec<String>,     // "spidev0.0", …
}

/// A physical disk from `/sys/block`, for `kern probe` and the `[[disk]]` example in `config setup`.
pub(crate) struct DiskInfo {
    pub(crate) name: String, // "nvme0n1", "sda"
    size: u64,               // bytes
    ssd: bool,               // rotational == 0
    pub(crate) model: String,
}

/// Whole physical disks from `/sys/block`, sorted by name. Skips virtual/loop/ram/dm/optical devices
/// and zero-sized entries (empty card readers). Read-only - a hardware inventory, not a pool manager.
fn read_disks() -> Vec<DiskInfo> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/sys/block") else {
        return out;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if ["loop", "ram", "zram", "dm-", "sr", "md", "fd", "nbd"]
            .iter()
            .any(|p| name.starts_with(p))
        {
            continue;
        }
        let base = e.path();
        let sectors: u64 = std::fs::read_to_string(base.join("size"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        if sectors == 0 {
            continue; // an empty card reader / removed medium
        }
        let ssd = std::fs::read_to_string(base.join("queue/rotational"))
            .map(|s| s.trim() == "0")
            .unwrap_or(false);
        let model = std::fs::read_to_string(base.join("device/model"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        out.push(DiskInfo {
            name,
            size: sectors * 512, // /sys/block reports 512-byte sectors regardless of physical size
            ssd,
            model,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

pub(crate) fn detect_host() -> HostInv {
    let ncpu = std::fs::read_to_string("/proc/cpuinfo")
        .map(|s| s.lines().filter(|l| l.starts_with("processor")).count())
        .unwrap_or(0);
    // MemTotal is in kibibytes by kernel contract. The multiplication is checked because the value
    // is external input and a wrapped total would be written into a config as a budget.
    let ram_bytes = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("MemTotal:"))
                .and_then(|v| v.split_whitespace().next())
                .and_then(|kb| kb.parse::<u64>().ok())
        })
        .and_then(|kb| kb.checked_mul(1024))
        .filter(|b| *b > 0);
    let mut dev: Vec<String> = std::fs::read_dir("/dev")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    dev.sort();
    let by =
        |pat: &str| -> Vec<String> { dev.iter().filter(|n| n.starts_with(pat)).cloned().collect() };
    HostInv {
        ncpu,
        ram_bytes,
        root_total: fs_usage("/").map(|(_used, total)| total).filter(|t| *t > 0),
        root_dev: disk_backing("/"),
        disks: read_disks(),
        gpiochips: by("gpiochip"),
        i2c: by("i2c-"),
        spi: by("spidev"),
    }
}

/// Physical disks as display labels ("nvme0n1  931G  SSD (…)") for the `kern top` Overview tab. The
/// `/sys/block` parsing lives in one place ([`read_disks`]).
pub(crate) fn host_disks() -> Vec<String> {
    read_disks().iter().map(disk_label).collect()
}

/// `(used, total)` bytes of the filesystem backing `path`, or `None` when it cannot be measured.
///
/// `used` is blocks minus free, which is what `df` reports and is NOT the same as total minus
/// available: the reserve a filesystem keeps for root belongs to neither side, and reporting it as
/// free would overstate what a workload can actually write.
///
/// One implementation, because `kern top` and `config setup` were both going to want it and a second
/// copy is how the two would come to disagree about the same disk on the same screen.
pub(crate) fn fs_usage(path: &str) -> Option<(u64, u64)> {
    // A path with an interior NUL cannot name a file, so this is a refusal and not an error.
    let c = std::ffi::CString::new(path).ok()?;
    // SAFETY: `libc::statvfs` is a `repr(C)` aggregate of unsigned integers, for which the all-zero
    // bit pattern is valid and inhabited. No field is read before the call below reports success.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` owns a NUL-terminated buffer that outlives the call, and `st` is a live, fully
    // zeroed `statvfs` that the kernel only writes through this pointer. The return code is checked
    // before either field is read.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let bs = st.f_frsize as u64;
    let blocks = st.f_blocks as u64;
    // CHECKED AND NOT WRAPPING. `f_blocks * f_frsize` is a product of two kernel-supplied numbers,
    // and a filesystem that reports nonsense (a fuse mount is free to) must yield "unmeasurable"
    // rather than a small wrapped total, because a small total here becomes a DECLARED BUDGET.
    let total = blocks.checked_mul(bs)?;
    let used = blocks
        .saturating_sub(st.f_bfree as u64)
        .checked_mul(bs)
        .unwrap_or(total);
    Some((used, total))
}

/// The kernel name of the whole disk backing `path` (`"nvme1n1"`), or `None` when it does not resolve.
///
/// ## Why this exists
///
/// `config setup` wrote `device = <the first entry of /sys/block, alphabetically>` next to
/// `path = "/"`. Measured on the development host: `/` lives on `nvme1n1` and the generated config
/// named `nvme0n1`, a different physical disk. Nothing reads that field today, so it cost nothing so
/// far; it stops being free the moment a measured SIZE is written beside it, because a reader has no
/// way to tell that the number and the name came from different disks.
///
/// ## How
///
/// `/proc/self/mountinfo` gives the `major:minor` of each mount, and the mount that backs a path is
/// the longest mount point that is a prefix of it. `/sys/dev/block/<major>:<minor>` then resolves to
/// the partition, whose parent directory is the whole disk. No subprocess and no `dev_t` bit
/// arithmetic: the numbers are already text in `mountinfo`, and taking them from there avoids
/// depending on an encoding that differs between libc versions.
fn disk_backing(path: &str) -> Option<String> {
    let mi = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut best: Option<(usize, String)> = None;
    for line in mi.lines() {
        // `36 35 98:0 / /mnt rw,… - ext4 /dev/sda1 rw`: field 2 is major:minor, field 4 the mount
        // point. A line that does not have them is skipped rather than aborting the scan, because
        // one unparsable mount must not blind this to every other one.
        let mut f = line.split(' ');
        let (Some(devno), Some(_root), Some(mount)) = (f.nth(2), f.next(), f.next()) else {
            continue;
        };
        let mount = unescape_mountinfo(mount);
        if !mount_covers(path, &mount) {
            continue;
        }
        // The LAST longest match wins: mountinfo is in mount order, so a later line covering the
        // same point is the one currently on top of it.
        if best.as_ref().is_none_or(|(len, _)| mount.len() >= *len) {
            best = Some((mount.len(), devno.to_string()));
        }
    }
    let (_, devno) = best?;
    let node = std::path::Path::new("/sys/dev/block").join(&devno);
    let link = std::fs::read_link(&node).ok()?;
    let mut parts = link.components().rev().filter_map(|c| match c {
        std::path::Component::Normal(s) => s.to_str(),
        _ => None,
    });
    let leaf = parts.next()?;
    // `partition` exists only on a partition, so its presence is what says to climb one level to the
    // whole disk. A whole-disk mount (an unpartitioned device, or LVM) has no such file and is
    // already the answer.
    if node.join("partition").exists() {
        return parts.next().map(str::to_string);
    }
    Some(leaf.to_string())
}

/// Does the mount point `mount` contain `path`?
///
/// A PREFIX IN PATH TERMS AND NOT IN STRING TERMS. `"/variable".starts_with("/var")` is true and
/// `/var` does not contain `/variable`: they are sibling directories. A plain string prefix would
/// pick the wrong mount for any path whose name extends another mount's, and the wrong mount means
/// the wrong device number, which means a measured budget attributed to a disk that does not hold
/// the data. Extracted from the scan so the rule can be asserted without a filesystem.
pub(crate) fn mount_covers(path: &str, mount: &str) -> bool {
    if path == mount {
        return true;
    }
    // The root contains everything absolute, and it is the one mount whose name ends in a separator,
    // so the boundary test below would look for a second one.
    if mount == "/" {
        return path.starts_with('/');
    }
    // A trailing separator on the mount would otherwise make the boundary byte fall one place late.
    let mount = mount.strip_suffix('/').unwrap_or(mount);
    path.starts_with(mount) && path.as_bytes().get(mount.len()) == Some(&b'/')
}

/// Undo the four escapes the kernel writes into `mountinfo` fields.
///
/// Only these four are escaped by `seq_path` in the kernel: space, tab, newline and backslash. A
/// mount point containing one of them is rare and entirely legal, and reading it raw would compare
/// `\040` against a real space and silently fail to match.
pub(crate) fn unescape_mountinfo(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        // COMPARED AS BYTES, NOT AS A STRING SLICE. The first draft matched `&s[i..i + 4]`, and
        // slicing a `String` at an index that is not a UTF-8 boundary PANICS. `i` sits on a
        // backslash, which is a boundary, but `i + 4` need not be: `/mnt/\04è` puts the end of the
        // window in the middle of the two-byte `è`, and that input panics. Verified by running it.
        //
        // A mount point is attacker-influenceable on any host where a user may mount, so a panic
        // here is reachable from outside. Byte slices have no boundaries to violate, so the check
        // below cannot panic for any input at all.
        if b[i] == b'\\' && i + 3 < b.len() {
            let w = &b[i..i + 4];
            let decoded = match w {
                b"\\040" => Some(' '),
                b"\\011" => Some('\t'),
                b"\\012" => Some('\n'),
                b"\\134" => Some('\\'),
                _ => None,
            };
            if let Some(ch) = decoded {
                out.push(ch);
                i += 4;
                continue;
            }
        }
        // Not an escape: copy the character whole, so a multi-byte one is not split.
        match s[i..].chars().next() {
            Some(ch) => {
                out.push(ch);
                i += ch.len_utf8();
            }
            None => break,
        }
    }
    out
}

/// Can this process open `path` for reading AND writing?
///
/// Used to choose which peripheral a generated example names. A `[[vgpio]]` that lists a node the
/// caller cannot open is refused help by `kern validate`, which warns on exactly this, so a starter
/// file that names an unopenable bus warns about itself the first time it is checked. Probing with
/// `access(2)` and not by opening: opening an i2c bus is a bus transaction, and a config generator
/// has no business driving hardware.
///
/// A false answer is the safe one here: it only moves the choice to another bus, or to the comment.
fn can_use(path: &str) -> bool {
    let Ok(c) = std::ffi::CString::new(path) else {
        return false;
    };
    // SAFETY: `c` owns a NUL-terminated buffer that outlives the call. `access` only reads it.
    unsafe { libc::access(c.as_ptr(), libc::R_OK | libc::W_OK) == 0 }
}

/// A byte count rendered as a size string [`kern_common::parse_binary_size`] reads back, never above
/// the input, or `None` for a count that cannot be written as one.
///
/// ## Why not `fmt_bytes`
///
/// `fmt_bytes` is the DISPLAY convention and it emits one decimal place for anything that is not an
/// exact multiple: this host's 31.2 GiB of RAM renders `31.2G`. The parser deliberately refuses a
/// decimal, so writing a measured budget through the display formatter would have generated a
/// `kern.toml` that `kern validate` REJECTS. That is the same defect as a command that emits config
/// its own validator turns down, which is the one this work exists to remove.
///
/// ## Why it may only round DOWN
///
/// The value becomes a declared budget, and a budget larger than the machine would make the
/// over-budget check silent on a profile that really does overrun: the check compares against this
/// number, so an optimistic number disables it. Rounding down can only make the check fire earlier,
/// which is the harmless direction.
///
/// Exact whenever the count divides a unit evenly, which every RAM figure in mebibytes does; the
/// floor is to MEBIBYTES, so the most it can understate a budget by is one MiB.
/// `value` pulled into `[low, high]`, total for every input.
///
/// `u64::clamp` is the idiomatic spelling and it PANICS when `low > high`. The bounds at every call
/// site here are compile-time constants in the right order, so that branch is unreachable today, and
/// "unreachable today" is exactly the shape of a panic that ships. An inverted range resolves to the
/// CEILING rather than aborting, because every caller is sizing a budget and the ceiling is the bound
/// whose violation has a consequence: too small only makes a warning fire early.
pub(crate) const fn bounded(value: u64, low: u64, high: u64) -> u64 {
    if high < low {
        return high;
    }
    if value < low {
        low
    } else if value > high {
        high
    } else {
        value
    }
}

pub(crate) fn toml_size(bytes: u64) -> Option<String> {
    const K: u64 = 1024;
    // `parse_binary_size` refuses zero, so there is no string that round-trips to it. Saying so is
    // the honest answer: a zero-byte budget is a resource nobody can slice, and the caller omits the
    // field rather than writing something the parser will not take back.
    if bytes == 0 {
        return None;
    }
    for (unit, sz) in [("t", K.pow(4)), ("g", K.pow(3)), ("m", K.pow(2)), ("k", K)] {
        if bytes >= sz && bytes % sz == 0 {
            return Some(format!("{}{unit}", bytes / sz));
        }
    }
    if bytes >= K * K {
        return Some(format!("{}m", bytes / (K * K)));
    }
    // Under a mebibyte a bare integer is exact, and the parser reads a trailing digit as bytes.
    Some(format!("{bytes}"))
}

/// One-line label for a disk in `kern probe`: `nvme0n1  931G  SSD (Samsung 980)`.
fn disk_label(d: &DiskInfo) -> String {
    let kind = if d.ssd { "SSD" } else { "HDD" };
    let model = if d.model.is_empty() {
        String::new()
    } else {
        format!(" ({})", d.model)
    };
    format!("{}  {}  {kind}{model}", d.name, human_bytes(d.size))
}

/// A ready-to-use kern.toml whose example profiles use THIS host's real numbers (so a beginner can
/// `kern run vcpu:heavy` straight away, no guessing). Only includes a GPIO block if the host has one.
///
/// ## The physical blocks carry MEASURED budgets
///
/// `[[cpu]]` declared `cores` and nothing else; `[[disk]]` declared neither a size nor the disk it
/// actually sits on. That made the over-budget check in `kern validate` structurally silent on every
/// file this command generates, because that check compares a profile against the budget its backend
/// declares and there was no budget to compare against. The numbers were available the whole time:
/// this command already reads the host to fill in the core count.
///
/// Three rules govern every figure written here, and they are the reason the code below looks more
/// careful than "print the number":
///
///   1. NEVER FABRICATE. A figure that could not be measured is omitted, not defaulted. An absent
///      budget means "undeclared", which is a state the validator handles by saying nothing; a
///      guessed one is a number a reader would act on.
///   2. NEVER ROUND UP. See [`toml_size`]: the value becomes the ceiling the check compares against,
///      so an optimistic figure switches the check off rather than loosening it.
///   3. THE FILE MUST PASS ITS OWN VALIDATOR, CLEANLY. Not just parse: emit zero warnings. That is
///      why the example profiles below are derived from the measurement instead of being constants.
///      With a hard-coded `memory = "512 MB"`, generating this file on a 512 MiB board produced a
///      config that warned about itself the first time it was validated, which is precisely the
///      "kern emits config kern rejects" defect this work exists to remove.
pub(crate) fn tailored_kern_toml(h: &HostInv) -> String {
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;
    let n = h.ncpu.max(1);
    let half = ((n as f64 / 2.0) * 10.0).round() / 10.0; // ~half the cores, one decimal
    let pin_hi = n.saturating_sub(1).min(3);

    // The example profiles, sized against the measurement so they cannot overrun what is declared.
    //
    // `min(ceiling, share)` keeps the familiar 512M/256m on any host with at least 2 GiB, which is
    // every machine the quickstart is written for, and shrinks them on a board where the constant
    // would have been larger than the whole machine. The final `.min(ram)` matters on a host too
    // small for the floor: equal to the budget is not over it, and over is what warns.
    let (heavy_mem, lean_mem) = match h.ram_bytes {
        Some(ram) => (
            bounded(ram / 4, 16 * MIB, 512 * MIB).min(ram),
            bounded(ram / 8, 8 * MIB, 256 * MIB).min(ram),
        ),
        None => (512 * MIB, 256 * MIB),
    };
    let heavy_mem = toml_size(heavy_mem).unwrap_or_else(|| "512m".to_string());
    let lean_mem = toml_size(lean_mem).unwrap_or_else(|| "256m".to_string());

    // The RAM line on the `[[cpu]]` block, and the header's description of the host. Both come from
    // the same measurement, so a reader cannot find them disagreeing.
    let ram_display = h
        .ram_bytes
        .map(human_bytes)
        .unwrap_or_else(|| "unknown RAM".to_string());
    // THE EXACT VALUE, WITH THE HUMAN ONE BESIDE IT. `toml_size` is exact, which on a real
    // /proc/meminfo means kibibytes: `32680724k` round-trips perfectly and cannot be sanity-checked
    // by eye. The rounded figure goes in the comment so a reader can see at a glance that the budget
    // is this machine, while the value the parser reads stays the measurement rather than a
    // rounding of it.
    let cpu_memory = match h.ram_bytes.and_then(toml_size) {
        Some(v) => format!(
            "memory = \"{v}\"   # measured: {}, all of this host's RAM\n",
            ram_display
        ),
        // NOT A DEFAULT. An unreadable /proc/meminfo leaves the budget undeclared, and the comment
        // says why, so the gap reads as a measurement that failed rather than as an oversight.
        None => "# memory =        # /proc/meminfo was unreadable, so no RAM budget is declared\n"
            .to_string(),
    };

    let mut s = format!(
        "# ~/.config/kern/kern.toml - generated by `kern config setup` for this host \
         ({n} cores, {ram_display}).\n# Attach a profile by prefix:  kern run vcpu:heavy -- ./train.sh   \
         ·  edit with `kern config edit`\n\n[kern]\nlog_level = \"info\"\n\n\
         # ── CPU ──  (profile fields match the CLI flags: cpus=--cpus, cpuset=--cpuset-cpus, memory=--memory, nice=--nice)\n\
         [[cpu]]\nid = \"cpu:0\"\ncores = {n}.0\n{cpu_memory}\n\
         [[vcpu]]\nname = \"heavy\"     # ~half this host, pinned to the first cores\n\
         backend = \"cpu:0\"\ncpus = {half}\ncpuset = \"0-{pin_hi}\"\nmemory = \"{heavy_mem}\"\n\n\
         [[vcpu]]\nname = \"lean\"\nbackend = \"cpu:0\"\ncpus = 0.5\nmemory = \"{lean_mem}\"\n",
    );

    // A [[disk]] pool + a vdisk profile that references it, seeded from the filesystem that actually
    // backs `/`, so `kern box … vdisk:scratch` has a real target with a real ceiling.
    //
    // THE DISK IS RESOLVED, NOT GUESSED. This used to take the first entry of `/sys/block`
    // alphabetically and print it next to `path = "/"`. Measured on the development host, `/` is on
    // `nvme1n1` and the generated file said `nvme0n1`. Nothing read the field, so the wrong name was
    // free; writing a measured SIZE beside it is what makes it cost something.
    //
    // THE SIZE IS THE FILESYSTEM'S, NOT THE DEVICE'S, and they are different numbers: a volume is a
    // file under `path`, so the ceiling that can ever stop a write is the filesystem's, and the raw
    // capacity of a device that may not even hold that path is not a budget for anything.
    let described = h
        .root_dev
        .as_ref()
        .and_then(|dev| h.disks.iter().find(|d| &d.name == dev))
        .or_else(|| h.disks.first());
    if described.is_some() || h.root_total.is_some() {
        let hardware = match described {
            Some(d) => {
                let kind = if d.ssd { "SSD" } else { "HDD" };
                let model = if d.model.is_empty() {
                    String::new()
                } else {
                    format!(" {}", d.model)
                };
                format!("{} {kind}{model}", human_bytes(d.size))
            }
            None => "device not identified".to_string(),
        };
        let device_line = match h.root_dev.as_ref().or(described.map(|d| &d.name)) {
            Some(dev) => format!("device = \"{dev}\"   # {hardware}\n"),
            None => String::new(),
        };
        let size_line = match h.root_total.and_then(toml_size) {
            Some(v) => format!(
                "size = \"{v}\"   # measured: {}, the filesystem mounted at path\n",
                h.root_total.map(human_bytes).unwrap_or_default()
            ),
            None => {
                "# size =          # statvfs on the path failed, so no size budget is declared\n"
                    .to_string()
            }
        };
        // The example volume is a quarter of the filesystem, capped at 2 GiB and floored at 64 MiB,
        // for the same reason the memory profiles are derived: on a small card a constant 2 GiB was
        // larger than the disk, and the generated file warned about itself.
        let scratch = h
            .root_total
            .map(|t| bounded(t / 4, 64 * MIB, 2 * GIB).min(t))
            .unwrap_or(2 * GIB);
        let scratch = toml_size(scratch).unwrap_or_else(|| "2g".to_string());
        s.push_str(&format!(
            "\n# ── Disk - `kern box … vdisk:scratch` gets a size-capped ext4 volume ──\n\
             [[disk]]\nid = \"disk:0\"\npath = \"/\"\n{device_line}{size_line}\n\
             [[vdisk]]\nname = \"scratch\"\nbackend = \"disk:0\"\nsize = \"{scratch}\"\n",
        ));
    }
    // ── the RAM-backed form, which kern ACCEPTS and never once GENERATED ───────────────────────
    //
    // `backend = "ram"` is a tmpfs, and it is not a poorer `[[disk]]`: it is a different backend
    // with different properties. Nothing wrote it. `config add` used to emit it as a default and
    // stopped, correctly, because kern choosing a sentinel on a caller's behalf is what produced two
    // conventions from one tool; the effect was that a legal form became invisible, and a reader of
    // a generated config had no way to learn it exists.
    //
    // So it is written here as a SECOND, LABELLED example rather than as anybody's default: the
    // choice stays with the operator and the form stays discoverable.
    //
    // SIZED FOR THE BOX THAT WILL MOUNT IT, not for the host. A tmpfs is charged to the memory
    // cgroup of the box, measured on this host at one variable: writing 512 MiB into the volume
    // under `--memory 256m` was killed with 137, and the same write under `--memory 2g` completed.
    // A box with no memory profile gets `memory.max = 512 MiB`, so an example larger than that would
    // be killed the first time a reader tried it. A quarter of a gibibyte fits inside that default
    // with room for the workload itself.
    let ram_vol = match h.ram_bytes {
        Some(ram) => bounded(ram / 8, 32 * MIB, 256 * MIB).min(ram),
        None => 256 * MIB,
    };
    let ram_vol = toml_size(ram_vol).unwrap_or_else(|| "256m".to_string());
    s.push_str(&format!(
        "\n# ── RAM disk - a tmpfs, needs no [[disk]]: `ram` is a reserved backend ──\n\
         # EPHEMERAL (gone when the box exits) and charged to the box's memory, so keep it under\n\
         # the box's --memory. Attach with `kern box … vdisk:tmp`.\n\
         [[vdisk]]\nname = \"tmp\"\nbackend = \"ram\"\nsize = \"{ram_vol}\"\n",
    ));
    if !h.i2c.is_empty() || !h.gpiochips.is_empty() {
        s.push_str(
            "\n# ── GPIO / I/O - `kern box … vgpio:io` binds these peripherals into the box ──\n\
             [[gpio]]\nid = \"gpio:0\"\n\n[[vgpio]]\nname = \"io\"\nbackend = \"gpio:0\"\n",
        );
        // THE BUS NAMED IS ONE THIS USER CAN ACTUALLY OPEN, when there is one.
        //
        // The first bus alphabetically was named unconditionally, and `kern validate` warns when a
        // `[[vgpio]]` lists a node the caller cannot open. On a desktop every `/dev/i2c-*` is
        // root-only 0600, so the generated starter file warned about itself on the first check.
        // Measured on the development host: eleven buses, none openable.
        //
        // Where a usable bus exists it is named, which is also more useful. Where none does, the
        // line is written COMMENTED, with the reason: the file then validates clean, and a reader
        // who fixes the permissions has the exact line to uncomment. Emitting it live with a warning
        // teaches a new user that kern's own output is noisy, which is the more expensive lesson.
        let usable = h.i2c.iter().find(|n| can_use(&format!("/dev/{n}")));
        if let Some(first) = usable.or_else(|| h.i2c.first()) {
            // Keep the comment lean: show a few real buses, not all of them.
            let shown = h.i2c.iter().take(4).cloned().collect::<Vec<_>>().join(", ");
            let more = h.i2c.len().saturating_sub(4);
            let extra = if more > 0 {
                format!(" (+{more} more)")
            } else {
                String::new()
            };
            if usable.is_some() {
                s.push_str(&format!(
                    "i2c = [\"/dev/{first}\"]    # host buses: {shown}{extra}\n"
                ));
            } else {
                s.push_str(&format!(
                    "# i2c = [\"/dev/{first}\"]  # none of these is readable/writable by this user; \
                     fix the mode or group, then uncomment. host buses: {shown}{extra}\n"
                ));
            }
        }
        if !h.gpiochips.is_empty() {
            s.push_str(&format!(
                "pins = [17]           # gpiochips: {}\n",
                h.gpiochips.join(", ")
            ));
        }
    } else {
        s.push_str(
            "\n# (no GPIO/I2C detected here - add a [[vgpio]] profile when you attach hardware)\n",
        );
    }
    s
}

/// `kern validate [path]` - parse a `kern.toml` (the given path, or the default location) and report
/// success with profile counts, or the offending line. Exits non-zero on a parse error.
/// Count `[` and `]` in `line` that are OUTSIDE single/double quotes - so a bracket inside a string
/// value doesn't fool the multi-line-array tracking in `validate`. Escape-agnostic (TOML basic strings
/// use `\\`, but for bracket-balance the simple quote toggle is sufficient for a best-effort linter).
fn brackets_outside_quotes(line: &str) -> (usize, usize) {
    let (mut opens, mut closes, mut q) = (0usize, 0usize, 0u8);
    for b in line.bytes() {
        match b {
            b'"' | b'\'' if q == 0 => q = b,
            _ if b == q => q = 0,
            b'[' if q == 0 => opens += 1,
            b']' if q == 0 => closes += 1,
            _ => {}
        }
    }
    (opens, closes)
}

/// A ready-to-use example config covering the resource families kern-public supports (CPU/GPIO/disk).
const EXAMPLE_KERN_TOML: &str = r#"# ~/.config/kern/kern.toml - resource profiles for `kern run`/`kern box`.
# Attach a profile by prefix, e.g.  kern run vcpu:heavy -- ./train.sh

[kern]
log_level = "info"

# ── CPU ──────────────────────────────────────────────────────────────────
# Declare the host CPU budget (optional), then carve named vCPU profiles. Every [[vcpu]] MUST name a
# `backend`: a [[cpu]] id below, or the reserved "host" (the whole host CPU, no [[cpu]] needed).
[[cpu]]
id = "cpu:0"
cores = 8.0           # host capacity (physical cores)

[[vcpu]]
name = "heavy"
backend = "cpu:0"     # REQUIRED: a [[cpu]] id above, or "host" for the whole host CPU
cpus = 4.0            # core quota (like --cpus): 4 cores
cpuset = "0-3"        # pin to CPUs 0-3 (like --cpuset-cpus)
memory = "2g"         # RAM cap (like --memory)
nice = -5             # scheduling priority (like --nice): -20..19

[[vcpu]]
name = "lean"
backend = "host"      # no [[cpu]] to declare: slice the whole host directly
cpus = 0.5
memory = "256m"

# ── GPIO / I/O - `kern box vgpio:leds …` binds these peripherals into the box ──
[[gpio]]
id = "gpio:0"
pins = [17, 27, 22]

[[vgpio]]
name = "leds"
backend = "gpio:0"    # REQUIRED: a [[gpio]] id above, or "host" for the host's own device nodes
pins = [17, 27]       # WHICH lines you intend to drive. The grant is CHIP-granular, not per-line:
                      # asking for any pin binds the whole /dev/gpiochipN, so the box can reach
                      # every line on that chip. See SECURITY.md, "vGPIO device passthrough".

# ── Disk - `kern box vdisk:scratch …` mounts a size-capped volume at /vdisk/scratch ──
[[disk]]
id = "data"
path = "/var/lib/kern/volumes"

[[vdisk]]
name = "scratch"
backend = "data"      # REQUIRED: a [[disk]] id above, or "ram" for a RAM-backed tmpfs
size = "2g"
"#;

mod lifecycle;
pub(crate) use lifecycle::*;

mod boxlog;
pub(crate) use boxlog::*;

mod rootfs;
pub(crate) use rootfs::*;

mod imagecache;
pub(crate) use imagecache::*;

mod start;
pub use start::*;

mod inspect;
pub use inspect::*;

mod compose;
pub use compose::*;

mod system;
pub use system::*;

mod build;

/// `compose watch`: rebuild and restart one service when its build context changes.
mod watch;
pub use build::*;

mod images;
pub use images::*;

mod config;
pub use config::*;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tmpfs_devpts_message {
    use super::is_dev_pts_path;

    /// `/dev/pts` is refused with its OWN sentence, and every other hardened path keeps the generic one.
    ///
    /// The refusal is not in question: a tmpfs over `/dev/pts` covers the private devpts the box
    /// mounts and reintroduces the `forkpty(3)` failure of issue #8. What this pins is that the
    /// message SAYS the mount is already there. The workaround `tmpfs: /dev/pts` is written in a
    /// public issue thread, so a reader who copies it onto a fixed binary must learn that their
    /// problem is solved, not that kern refuses them.
    ///
    /// BOTH DIRECTIONS, because a message that fires on the wrong path is worse than the one it
    /// replaced: `/dev/shm`, `/dev/ptsx` and `/proc/x` must keep the generic wording.
    #[test]
    fn only_dev_pts_gets_the_already_mounted_sentence() {
        for p in [
            "/dev/pts",
            "//dev/pts",
            "/dev//pts",
            "/dev/pts/",
            "/dev/pts//",
        ] {
            assert!(
                is_dev_pts_path(p),
                "{p} must reach the devpts-specific message"
            );
        }
        for p in [
            "/dev",
            "/dev/shm",
            "/dev/ptsx",
            "/dev/pts/x",
            "/proc/x",
            "/sys/x",
            "/devpts",
        ] {
            assert!(!is_dev_pts_path(p), "{p} must keep the generic refusal");
        }
    }
}
