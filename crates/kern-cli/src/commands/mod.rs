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
    /// `--ulimit` limits, pre-resolved to `(RLIMIT_*, soft, hard)` by the CLI.
    pub ulimits: &'a [(i32, u64, u64)],
    /// `--sysctl KEY=VALUE` pairs, applied inside the box's namespaces.
    pub sysctls: &'a [(String, String)],
    /// `--label k=v` metadata (repeatable). Descriptive only: it does not change how the box runs,
    /// but it is recorded in the registry so `kern ps --filter label=` and `kern inspect` can use it.
    pub labels: &'a [String],
    /// `--restart-max <n>`: retry cap for the on-failure supervisor (0 = kern's default).
    pub restart_max: u32,
    /// `--stop-signal <name|num>`: signal sent before the SIGKILL (default SIGTERM).
    pub stop_signal: i32,
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
    let saved = crate::pty::raw_with_resize(pty.master);
    // `--timeout N`: same host-namespace watchdog as the non-tty path (forked here, before the
    // unshare), so a hung interactive session is force-stopped after N seconds.
    let timeout_wd = (timeout > 0)
        .then(|| spawn_foreground_timeout(timeout))
        .flatten();
    let result = run_in_sandbox_with(
        &spec,
        None,
        |pid1| feed_timeout_pid(timeout_wd, pid1),
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
    unsafe { libc::close(pty.master) };
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
    let cfg = crate::config::load(config).map_err(Error::Config)?;
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
    memory_swap_max: Option<u64>,
    cpus: Option<f64>,
    cpuset: Option<String>,
    vgpio_devs: Vec<String>,
    vgpio_sysfs: Vec<String>,
    vdisks: Vec<kern_isolation::VdiskMount>,
    secrets: Vec<(String, Vec<u8>)>,
    ssh: Option<kern_isolation::SshSetup>,
    hostname: Option<String>,
    tun: bool,
    init: bool,
    tmpfs: Vec<(String, String)>,
    run_as: Option<(u32, u32)>,
    pids_max: Option<u64>,
    caps: kern_isolation::CapSpec,
    io_max: Vec<String>,
    io_weight: Option<u64>,
    /// `--add-host NAME:IP` entries (`host-gateway` already resolved to a concrete address).
    extra_hosts: Vec<(String, String)>,
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
        own_only_dir(&eph).map_err(|e| Error::Sandbox(format!("overlay scratch: {e}")))?;
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
        memory_swap_max: b.memory_swap_max,
        cpuset: b.cpuset,
        cpus: b.cpus,
        tty_slave: None,
        vgpio_devs: b.vgpio_devs,
        vgpio_sysfs: b.vgpio_sysfs,
        vdisks: b.vdisks,
        secrets: b.secrets,
        ssh: b.ssh,
        tun: b.tun,
        init: b.init,
        tmpfs: b.tmpfs,
        run_as: b.run_as,
        pids_max: b.pids_max,
        caps: b.caps,
        io_max: b.io_max,
        io_weight: b.io_weight,
        extra_hosts: b.extra_hosts,
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

/// Parse `-v src:dst[:ro]` specs into [`Volume`]s. The target must be absolute; the source is a
/// volume name, an absolute path, or a `./`-style path relative to the current directory, and must
/// exist on the host. A trailing `:ro` (or `:rw`) sets the mode.
fn parse_volumes(specs: &[String]) -> Result<Vec<Volume>, Error> {
    let mut out = Vec::with_capacity(specs.len());
    for s in specs {
        let parts: Vec<&str> = s.split(':').collect();
        let (source, target, read_only) = match parts.as_slice() {
            [src, dst] => (*src, *dst, false),
            [src, dst, "ro"] => (*src, *dst, true),
            [src, dst, "rw"] => (*src, *dst, false),
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
                let canon = std::fs::canonicalize(source)
                    .map_err(|e| Error::Sandbox(format!("-v '{s}': source {source}: {e}")))?;
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

/// Parse `--env-file PATH` files: one `K=V` per line, `#`-comment and blank lines skipped, surrounding
/// whitespace on the key trimmed. Later files (and `--env`) override earlier keys by list order.
fn parse_env_files(paths: &[String]) -> Result<Vec<(String, String)>, Error> {
    let mut out = Vec::new();
    for p in paths {
        // Route through the ONE guarded host-file reader: `--env-file` delivers a file's K=V lines into
        // the box's env, so `--env-file <runtime>/kern/instances/<peer>` would inject a peer's posture
        // record (`capdropall=`, `seccompmode=`, …) - the same class `--secret` and `-v` are guarded for.
        let bytes = crate::secret::read_host_file_for_box(p, "--env-file")?;
        let body = String::from_utf8(bytes)
            .map_err(|_| Error::Sandbox(format!("--env-file '{p}' is not valid UTF-8")))?;
        for (n, raw) in body.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match line.split_once('=') {
                Some((k, v)) if !k.trim().is_empty() => {
                    out.push((k.trim().to_string(), v.to_string()))
                }
                _ => {
                    return Err(Error::Sandbox(format!(
                        "bad line {} in --env-file '{p}' (expected K=V): {line}",
                        n + 1
                    )))
                }
            }
        }
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

/// Parse `--tmpfs PATH[:size]` specs into `(path, size)` - `size` a tmpfs `size=` token (`"64m"`),
/// empty for the kernel default. The path must be absolute, `.`/`..`/NUL-free, and not shadow a
/// hardened mount (`/proc`, `/sys`, `/dev`). A bad size (not digits + optional k/m/g/t) is rejected.
fn parse_tmpfs(specs: &[String]) -> Result<Vec<(String, String)>, Error> {
    let mut out = Vec::with_capacity(specs.len());
    for s in specs {
        let (path, size) = match s.split_once(':') {
            Some((p, sz)) => (p, sz),
            None => (s.as_str(), ""),
        };
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
            return Err(Error::Sandbox(format!(
                "--tmpfs '{path}' is refused (it would shadow the sandbox's hardened /proc, /sys or /dev)"
            )));
        }
        if !size.is_empty() {
            let core = size
                .strip_suffix(['k', 'm', 'g', 't', 'K', 'M', 'G', 'T'])
                .unwrap_or(size);
            if core.is_empty() || !core.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::Sandbox(format!(
                    "--tmpfs '{s}': bad size '{size}' (digits + optional k/m/g/t, e.g. 64m)"
                )));
            }
        }
        out.push((path.to_string(), size.to_ascii_lowercase()));
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
    /// `kern box` (has a supervisor to hold the RAII guard) may take the direct kern.slice path;
    /// `kern run` (execs in place) must not, so it uses the systemd `--scope --collect` path.
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
    let status = reap(child);
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    };
    std::process::exit(code);
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
        return merged_view_extract(chain, Some(src_rel), dest);
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
fn resolve_builds(
    boxes: &mut [crate::compose::ComposeBox],
    file: &str,
    self_exe: &std::path::Path,
) -> Result<(), Error> {
    // The directory that a `build.context` is confined under: the compose file's parent (canonical).
    let compose_dir = compose_dir(file);
    let base = std::fs::canonicalize(&compose_dir).map_err(|e| {
        Error::Compose(format!(
            "resolving compose dir '{}': {e}",
            compose_dir.display()
        ))
    })?;

    for b in boxes.iter_mut() {
        let Some(bd) = b.build.clone() else { continue };
        // Guard 1 - CONFINE context under the compose dir. Canonicalize `base/context` and require the
        // result stays beneath `base`, so a `context: ../../../etc` in a third-party compose can't
        // escape the project tree. (Same traversal class as image/volume/pod names in the saga.)
        // NOTE (duale-di-Z2): confining the context ROOT here is not enough on its own - `kern build`
        // then DESCENDS the context (COPY). That descent is itself confined: `copy_into_rootfs`
        // canonicalizes each COPY source and requires `starts_with(ctx)` (a source symlink pointing out
        // is rejected), and `cp -a` PRESERVES inner symlinks rather than following them (so a symlink
        // buried in the tree lands in the image verbatim - dangling inside the pivoted rootfs - never
        // read at build time). Verified live: a `leak -> /host/secret` inside the context does not leak
        // the host file into the image. So root-confine here + no-follow descent in build = closed.
        let ctx_abs = std::fs::canonicalize(base.join(&bd.context)).map_err(|e| {
            Error::Compose(format!(
                "service '{}': build context '{}': {e}",
                b.name, bd.context
            ))
        })?;
        if !ctx_abs.starts_with(&base) {
            return Err(Error::Compose(format!(
                "service '{}': build context '{}' escapes the compose directory (refused)",
                b.name, bd.context
            )));
        }
        // Guard 1 (dockerfile) - if given, confine it under the CONTEXT (Docker resolves `dockerfile`
        // relative to the context). Reject an escaping dockerfile path.
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

        // Guard 4 - `image:` + `build:` = build AND tag as `image`; `build:` alone → synthesized tag.
        // Either way the box RUNS the freshly built image, never a stale registry one.
        let tag = b
            .image
            .clone()
            .unwrap_or_else(|| format!("kern-compose-{}:latest", b.name));

        eprintln!("→ building '{}' from {}", b.name, bd.context);
        let mut cmd = std::process::Command::new(self_exe);
        cmd.arg("build").arg("-t").arg(&tag);
        if let Some(df) = &dfile {
            cmd.arg("-f").arg(df);
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
            if find(dep).is_some_and(|x| x.health_cmd.is_none()) {
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
    ("systemd", ComposeAction::Systemd),
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
fn stop_stack(boxes: &[crate::compose::ComposeBox], pod: &str) -> Vec<String> {
    let names: Vec<String> = boxes.iter().map(|b| b.name.clone()).collect();
    let _ = stop(&names, false); // best-effort - some may already be gone
    for n in &names {
        if !is_box_alive(n) {
            registry::clear_exit_matching(&exit_key_prefix(pod), &format!("-{n}"));
        }
    }
    names
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
        let declared = b.port.map(|p| (p, false));
        for (port, udp) in
            declared
                .into_iter()
                .chain(b.expose.iter().copied())
                .chain(b.ports.iter().flat_map(|spec| {
                    crate::ports::parse(spec) // malformed: the per-box path reports it precisely
                        .unwrap_or_default()
                        .into_iter()
                        .map(|m| (m.box_port, m.udp))
                }))
        {
            if let Some(other) = seen.insert((port, udp), short(b)) {
                if other != b.service_name() {
                    let proto = if udp { "udp" } else { "tcp" };
                    return Err(Error::Compose(format!(
                        "services '{}' and '{}' both listen on container port {port}/{proto}. Services \
                         in a stack share ONE network namespace (like a Kubernetes pod), so only one \
                         can bind it: declare a different internal port with `port:` on one of them \
                         (kern passes it as PORT, which most images read), or run with --no-pod.",
                        other,
                        short(b)
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
                return Err(Error::Compose(format!(
                    "service '{}': extra_hosts entry '{host}' has the same name as a service in this \
                     stack. Both write the pod's shared /etc/hosts, so which one resolves would depend \
                     on start order: rename one of them.",
                    short(b)
                )));
            }
        }
    }
    Ok(())
}

/// Best-effort WARNING for two pod services whose IMAGES expose the same container port even though
/// NEITHER declares it in the compose file - the implicit-EXPOSE case `check_pod_global_conflicts`
/// cannot see (two `nginx` default to :80, two `node` apps to :3000). A pod shares one network
/// namespace, so if both actually bind it the second dies with EADDRINUSE at runtime, with an obscure
/// error and no compose-time hint. This is deliberately SOFT: an image's `ExposedPorts` is a hint, not
/// a guaranteed bind (an nginx reconfigured off :80 will not collide), so it warns, never refuses.
/// Cache-only via [`PullPolicy::Never`]: it never pulls just to warn, so an uncached service is
/// skipped (and warned about, if it collides, once its image is present - e.g. the second `up`).
fn warn_image_expose_collisions(boxes: &[crate::compose::ComposeBox], no_pod: bool) {
    if no_pod || boxes.len() < 2 {
        return;
    }
    let mut seen: std::collections::HashMap<(u16, bool), String> = std::collections::HashMap::new();
    for b in boxes {
        let Some(image) = b.image.as_deref() else {
            continue; // a `--rootfs`/`build`-only service has no image config to read
        };
        let Ok((_, cfg)) = resolve_image_depth(image, 0, PullPolicy::Never) else {
            continue; // not cached: do not pull just to warn
        };
        for (port, udp) in cfg.exposed_ports {
            if let Some(other) = seen.insert((port, udp), b.name.clone()) {
                if other != b.name {
                    let proto = if udp { "udp" } else { "tcp" };
                    eprintln!(
                        "kern: warning: the images of '{other}' and '{}' both EXPOSE {port}/{proto}; a \
                         stack shares ONE network namespace, so if both bind it the second fails at \
                         runtime with EADDRINUSE. If they really serve the same port, give one a \
                         different internal port (its own config, or `port:`), or run with --no-pod.",
                        b.name
                    );
                }
            }
        }
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
fn watch_for_early_death(boxes: &[crate::compose::ComposeBox], ms: u64) {
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
    boxes: &[crate::compose::ComposeBox],
    pod: &str,
    token: &str,
) -> Vec<String> {
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
    /// Needed by the read-only verbs too: `config` and `systemd` answer questions ABOUT a bring-up,
    /// so they have to know whether that bring-up would share a namespace.
    no_pod: bool,
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
    let (pod, file, tail, follow, all, services, no_pod) =
        (o.pod, o.file, o.tail, o.follow, o.all, o.services, o.no_pod);
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
            check_pod_global_conflicts(boxes, no_pod)?;
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
            check_pod_global_conflicts(boxes, no_pod)?;
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
                        .map(move |spec| format!("  {}: invalid port '{spec}'", b.name))
                })
                .collect();
            if !bad.is_empty() {
                return Err(Error::Compose(format!(
                    "{} invalid port spec(s) - expected [ip:]host:box[/tcp|/udp], ports 1-65535:\n{}",
                    bad.len(),
                    bad.join("\n")
                )));
            }
            println!("compose config: {} service(s) in {file}", boxes.len());
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
                }
                // `config` answers "what did kern understand", so it must show a declared `port:`:
                // it is what the pod preflight reserves AND what the service receives as `PORT`, so
                // hiding it would leave the one command that exists to explain the file silent about
                // a field that changes both. Named as what it does, not just as its number.
                if let Some(p) = b.port {
                    println!("    port: {p} (reserved in the pod, passed as PORT={p})");
                }
                if !b.expose.is_empty() {
                    let list: Vec<String> = b
                        .expose
                        .iter()
                        .map(|(n, udp)| format!("{n}/{}", if *udp { "udp" } else { "tcp" }))
                        .collect();
                    println!("    expose: {} (reserved in the pod)", list.join(", "));
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
        ComposeAction::Ps => {
            // Reuse `kern ps` itself, scoped to this stack's pod - one renderer, so the compose view
            // can never drift from `kern ps` (same columns, same status rules, same --json). `-a`
            // threads straight through, so `compose ps -a` shows the stack's recently-exited services;
            // the phantom worry (a PRIOR run of the same pod name) is closed at the source by `down`
            // reaping its own boxes' sidecars precisely (see `ComposeAction::Down`).
            let rc = ps(
                false,
                false,
                all,
                &[("pod".to_string(), pod.to_string())],
                None,
            );
            // Without `-a`, a running-only view cannot answer "which service died?" - point AT the
            // answer when the file defines more services than are up, instead of leaving the user to
            // know that the pod name is the stack name.
            if !all {
                let defined = boxes.len();
                let running = registry::list().iter().filter(|b| b.pod == pod).count();
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
            // `-f` on several services would need one blocking reader each; rather than interleave
            // them badly, require a single service and say exactly how to ask for it.
            if follow && wanted.len() != 1 {
                return Err(Error::Compose(format!(
                    "compose logs -f follows ONE service at a time; name it (e.g. `compose {file} logs -f {}`)",
                    wanted.first().copied().unwrap_or("<service>")
                )));
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
            let names = stop_stack(boxes, pod);
            // Reap THIS stack's `waitexit` sidecars (by pod + our own service names), including services
            // that had ALREADY exited before `down` - a live-only capture would miss exactly those. So
            // `compose ps -a` is empty after a `down` (matching Docker), while `compose stop` (which does
            // not call this) leaves the exited services visible.
            registry::clear_waitexit_pod(pod, &names);
            // Tear the pod down QUIETLY (we just stopped the members, so `pod::remove`'s "members keep
            // running" note would contradict this). Only claim it was removed if one existed - a
            // `--no-pod` stack has none.
            let (pod_existed, _) = crate::pod::teardown(pod);
            if pod_existed {
                println!(
                    "compose down: {} box(es) stopped, pod '{pod}' removed",
                    names.len()
                );
            } else {
                println!("compose down: {} box(es) stopped", names.len());
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
            let names = stop_stack(boxes, pod);
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
            let names = stop_stack(boxes, pod);
            println!(
                "compose restart: {} box(es) stopped, restarting",
                names.len()
            );
        }
        ComposeAction::Up | ComposeAction::Start => {}
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
    pub no_pod: bool,
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
pub use build::*;

mod images;
pub use images::*;

mod config;
pub use config::*;

#[cfg(test)]
mod tests;
