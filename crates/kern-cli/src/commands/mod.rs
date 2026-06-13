//! Subcommand implementations. One responsibility per function; the roadmap splits each verb
//! (box/run/pull/compose) into its own module here as the surface grows.

use crate::error::Error;
use crate::registry;
use crate::sandbox::SandboxCtx;
use kern_common::BoxName;
use kern_isolation::{
    exec_in_box, run_in_sandbox_with, MountMode, OverlayDirs, SandboxSpec, Volume,
};
use std::io::IsTerminal;
use std::path::PathBuf;

pub fn version() -> Result<(), Error> {
    println!("kern {}", kern_common::VERSION);
    Ok(())
}

pub fn help() -> Result<(), Error> {
    let p = crate::ui::Palette::detect();
    let (b, c, d, z) = (p.b, p.c, p.d, p.z);
    println!("{}", crate::ui::logo(&p));
    println!(
        "\
  {b}kern {ver}{z} {d}— a fast, lightweight sandbox & virtual resource manager{z}

{b}USAGE:{z}
    kern <COMMAND> [ARGS]

{b}COMMANDS:{z}
  {d}Essentials{z}
    {c}box{z} <name> (--rootfs <dir>|--image <ref>) [opts] [-- CMD...]   Run CMD in a sandbox
    {c}box{z} <name> --plan                                              Preview the isolation sequence
    {c}run{z} [--memory M] [--cpus N] [vcpu:PROFILE] [--] CMD...         Run CMD under CPU/mem caps (no sandbox)
    {c}exec{z} <name> [-it] [--env K=V] [-w <dir>] [-- CMD...]           Run CMD in a running box
    {c}ps{z} [--json]                                                    List running boxes
    {c}logs{z} <name>                                                    Show a box's output
    {c}stop{z} <name>... | --all                                         Stop box(es), or all

  {d}Images{z}
    {c}search{z} <query> [--json]                                        Search Docker Hub for images
    {c}pull{z} <image> [--dest <dir>]                                    Download an OCI image
    {c}push{z} <local-ref> [as <remote-ref>]                             Publish a cached image to a registry
    {c}build{z} -t <name> [-f Dockerfile] [--build-arg K=V] [ctx]        Build a local image from a Dockerfile
    {c}images{z} [--json]                                                List pulled (cached) images

  {d}Manage boxes{z}
    {c}top{z}                                                            Interactive task manager (TUI)
    {c}stats{z} [--json] [name...]                                       Per-box memory + CPU
    {c}inspect{z} <name> [--json]                                        Full detail for one box
    {c}attach{z} <name>                                                  Stream a box's output live (Ctrl-C detaches)
    {c}cp{z} <box>:<src> <dst> | <src> <box>:<dst>                       Copy a file host<->box
    {c}pause{z} <name>... | --all                                        Freeze box(es) (cgroup freezer)
    {c}unpause{z} <name>... | --all                                      Thaw frozen box(es)
    {c}kill{z} <name>... | killall                                       Stop box(es) (alias of stop)
    {c}prune{z}                                                          Remove leftovers of stopped boxes
    {c}gc{z} [--images]                                                  prune (+ reclaim the image cache)
    {c}recover{z}                                                        Clean orphaned scratch of dead boxes
    {c}history{z} [-n N]                                                 Recently-run boxes

  {d}Multi-box{z}
    {c}compose{z} <file>                                                 Bring up a stack (kern TOML or docker-compose.yml)
    {c}up{z} [--no-pod] / {c}down{z}                                          Bring up / tear down the compose file in this dir
    {c}pod{z} create <name> / pod ls / pod rm <name>                     Shared-network pod (boxes reach each other by name)

  {d}Config & storage{z}
    {c}config{z} [list|edit|setup|probe|clear]                          List resource profiles; manage kern.toml
    {c}config add{z} <kind:name> [--flags]                              Create a profile (vcpu/vgpio/vdisk) — CLI twin of `kern top`
    {c}config rm{z} <kind:name>                                         Delete a profile
    {c}validate{z} [path]                                                Check a kern.toml
    {c}examples{z}                                                       Print an example kern.toml
    {c}volume{z} <create|ls|rm|inspect|prune>                            Manage named volumes
    {c}login{z} [registry] [--username U] / {c}logout{z} [registry]         Registry credentials (private pulls)

  {d}Diagnostics{z}
    {c}doctor{z}                                                         Preflight: will boxes run here?
    {c}probe{z}                                                          Host resources you can put in kern.toml
    {c}info{z}                                                           Runtime + host snapshot
    {c}bench{z} --rootfs <dir> [-n N]                                    Time box start→exit latency
    {c}completions{z} <bash|zsh|fish>                                    Print a shell-completion script

{b}OPTIONS for box:{z}
    --rootfs <dir>      Root filesystem to enter
    --image <ref>       OCI image to pull and run (e.g. alpine, alpine:3.19)
    -d, --detach        Run in the background (track with `kern ps`)
    --read-only         Read-only root (default is a writable overlay)
    -v, --volume S:D[:ro]   Mount into the box (repeatable). S = a host path, a named volume
                        (auto-created; see `kern volume`), or nfs://|smb://|sshfs:// URL
    -e, --env K=V       Set an environment variable (repeatable)
    -w, --workdir <dir> Working directory inside the box
    -m, --memory <size> Hard memory cap (e.g. 512m, 1g; default 512m)
    --cpus <n>          CPU cap in cores (e.g. 1.5, 2; default uncapped)
    --cpuset-cpus <list>  Pin to specific CPUs (e.g. 0-3, 0,2,4; default no pinning)
    --memory-swap-max <size>  Swap allowance → cgroup-v2 memory.swap.max (default 0 = swap off)
    -it, -t, -i         Allocate an interactive PTY (shells/REPLs); foreground only
    -p, --publish H:B   Publish box port B on host port H ([ip:]H:B; binds 127.0.0.1 by
                        default — use 0.0.0.0:H:B to expose on all interfaces; repeatable)
    --secret SPEC       Deliver a secret as /run/secrets/NAME (mode 0400): SRC[:NAME] (file),
                        NAME=value (inline), or NAME=- (from stdin); repeatable
    --ssh PORT          Run an in-box sshd, published on host PORT (→ box :22); prints the ssh
                        command (auto-generates a keypair). Needs openssh in the image
    --ssh-key FILE      Authorize this public key instead of generating a throwaway keypair
    --restart           Restart a detached box if it exits non-zero (on-failure)
    --health-cmd <cmd>  Shell command probed in the box; sets ps HEALTH (exit 0 = healthy)
    --health-interval N Seconds between health checks (default 30)
    --health-retries N  Consecutive failures before a box is unhealthy (default 3)
    --health-start-period N  Grace period where failures keep it starting (default 0)
    --health-timeout N  Kill a single check that exceeds N seconds (default 0 = none)
    --health-action A   On unhealthy: restart | stop | none (default none)
    --timeout N         Auto-stop the box after N seconds (0 = no timeout)
    --net               Share the host network (outbound; no network isolation)
    --network <mode>    host = share host net (= --net); none = isolated (default)
    --pod <name>        Join a shared-network pod (reach peers by name; see `kern pod`)
    --hostname <name>   Set the box's hostname (default: the box name)
    --tun               Expose /dev/net/tun in the box (WireGuard / userspace VPN)
    --pids-limit <N>    Cap the box's process count (pids.max) — fork-bomb containment
    --io-weight <N>     cgroup-v2 io.weight — relative I/O priority (1–10000; best-effort)
    --nice <n>          Scheduling niceness for the box workload (-20 high … 19 low)
    --env-file <file>   Load K=V lines from a file into the box env (repeatable; --env wins)
    --config <path>     Use this kern.toml for resource-profile tokens (vcpu:/vgpio:/vdisk:)
    --show-config       Print the resolved box configuration and exit (a dry run)
    -q, --quiet         Suppress the foreground status line
    --verbose           Expand the status line into the full isolation panel
    --tmpfs <path[:sz]> Mount a fresh tmpfs at path in the box (e.g. /tmp:64m; repeatable)
    -u, --user <u[:g]>  Run the box command as this uid[:gid] (numeric; needs the id mapped)
    --cap-add <CAP>     Keep a capability kern would otherwise drop (e.g. NET_ADMIN, or ALL); repeatable
    --cap-drop <CAP>    Drop an extra capability (e.g. NET_RAW, or ALL); repeatable
    --uid-range         Map a sub-uid/gid range (needed for apt/dpkg, www-data); default maps
                        only the caller (faster + more isolated)
    --bind-rootfs       Bind --rootfs directly instead of an overlay — faster on kernels with a
                        slow overlayfs, but the source is mutable & shared (no per-box isolation)
    --plan              Preview the isolation sequence instead of running

{b}OPTIONS:{z}
    -V, --version  Print version
    -h, --help     Print this help

{d}Docs & issues: {z}{c}https://github.com/getkern/kern{z}",
        ver = kern_common::VERSION
    );
    Ok(())
}

/// Bare `kern`: a short, friendly banner — the logo, the tagline, and the handful of commands most
/// people reach for first. The full command + flag reference is `kern --help`.
pub fn banner() -> Result<(), Error> {
    let p = crate::ui::Palette::detect();
    let (b, c, d, z) = (p.b, p.c, p.d, p.z);
    println!("{}", crate::ui::logo(&p));
    println!(
        "\
  {b}kern {ver}{z} {d}— a fast, lightweight sandbox & virtual resource manager{z}

    {b}kern box{z} <name> --image alpine -- sh   {d}run a command in a sandbox{z}
    {b}kern run{z} --memory 512m -- <cmd>        {d}govern a command's CPU/memory (no sandbox){z}
    {b}kern ps{z} {d}·{z} {b}logs{z} {d}·{z} {b}exec{z} {d}·{z} {b}stop{z}               {d}manage running boxes{z}
    {b}kern compose{z} stack.toml               {d}bring up a stack{z}

  {b}kern --help{z} {d}for all commands{z}   {d}·{z}   {b}kern doctor{z} {d}to check this host{z}
  {d}{z}{c}https://github.com/getkern/kern{z}",
        ver = kern_common::VERSION
    );
    Ok(())
}

/// `kern box <name> --plan` — show the ordered mount/pivot/remount sequence the sandbox setup
/// would perform. Privilege-free: it records the sequence via the isolation seam rather than
/// executing it, so it works anywhere and exercises the 0.2 step-sequence + mount-ordering
/// typestate end to end.
pub fn box_plan(name: &str) -> Result<(), Error> {
    let name = BoxName::parse(name).map_err(Error::InvalidBox)?;
    let ctx = SandboxCtx::new(name);
    println!("isolation plan for box '{}':", ctx.name.as_str());
    for (i, step) in ctx.plan().iter().enumerate() {
        println!("  {}. {step}", i + 1);
    }
    Ok(())
}

/// `--restart [policy]` — what to do when a detached box exits. `no` (default) leaves it dead;
/// `on-failure` re-runs it on a non-zero exit via kern's own in-process supervisor (dies with the
/// host); `always`/`unless-stopped` hand supervision to the user's **systemd** (a generated
/// `~/.config/systemd/user/kern-<name>.service` + linger) so the box restarts on ANY exit AND
/// survives reboot — all WITHOUT a kern daemon.
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

/// Arguments for [`box_run`]. A struct (not a long parameter list) keeps the call site readable
/// as box options grow (`-v`, `--env`, `--workdir`, `--net`).
pub struct BoxRunArgs<'a> {
    pub name: &'a str,
    pub rootfs: Option<&'a str>,
    pub image: Option<&'a str>,
    pub command: &'a [String],
    pub detached: bool,
    pub read_only: bool,
    pub volumes: &'a [String],
    pub env: &'a [String],
    pub workdir: Option<&'a str>,
    pub share_net: bool,
    /// `--pod <name>`: join this pod's shared network (created by `kern pod create`).
    pub pod: Option<&'a str>,
    pub uid_range: bool,
    pub bind_rootfs: bool,
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
    pub ports: &'a [(u32, u16, u16)],
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
    /// `--pids-limit N`: cap the box's task count (`pids.max`) — fork-bomb containment.
    pub pids_limit: Option<u64>,
    /// `--tmpfs PATH[:size]` (repeatable): mount a fresh tmpfs at PATH inside the box.
    pub tmpfs: &'a [String],
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
}

/// Clamp a `--cpus` request to the host's physical CPU count (from `/proc/cpuinfo`), so the cap
/// is consistent across the systemd scope AND the in-namespace cgroup. The warning fires once — in
/// the original process, before the scope re-exec (which sets `KERN_SCOPE`) runs the parse again.
fn clamp_cpus(cpus: Option<f64>) -> Option<f64> {
    let c = cpus?;
    let host = std::fs::read_to_string("/proc/cpuinfo")
        .map(|s| s.lines().filter(|l| l.starts_with("processor")).count())
        .ok()
        .filter(|&n| n > 0)
        .unwrap_or(1) as f64;
    if c > host {
        if std::env::var_os("KERN_SCOPE").is_none() {
            eprintln!(
                "kern: --cpus {c} exceeds the {host:.0} available CPUs — clamping to {host:.0}"
            );
        }
        return Some(host);
    }
    Some(c)
}

/// `kern box <name> (--rootfs <dir> | --image <ref>) [-d] [-v ...] [--env ...] [-- cmd...]` — run
/// a command in a real sandbox: a fresh user + PID + (net) + UTS + IPC + mount namespace, the
/// rootfs pivoted in, seccomp-filtered, cgroup-capped. `--image` pulls an OCI image (cached).
/// Defaults to `/bin/sh`. Foreground propagates the exit code; `-d` detaches (track via `kern ps`).
pub fn box_run(args: BoxRunArgs) -> Result<(), Error> {
    let name = BoxName::parse(args.name).map_err(Error::InvalidBox)?;
    // Reject a name already held by a LIVE box — otherwise two boxes share a name and `stop`/`logs`/
    // `exec` become ambiguous (and a repeated `compose up` would silently stack duplicates). `list()`
    // returns only alive instances (it prunes dead ones), so a freed name is immediately reusable.
    if registry::list().iter().any(|i| i.name == name.as_str()) {
        return Err(Error::AlreadyRunning(format!(
            "a box named '{}' is already running",
            name.as_str()
        )));
    }
    // `--ssh` PREFLIGHT: sshd's privilege separation calls `setgroups()`, which a single-uid userns
    // forbids (`/proc/self/setgroups=deny`). It works only with a real uid RANGE via newuidmap/subuid.
    // On a host without those (common on edge boards), `--ssh` would leave a listening port whose auth
    // silently closes with a confusing "Connection closed" — so say it up front instead of at handshake.
    if args.ssh_port.is_some() {
        let uid = unsafe { libc::getuid() };
        let uname = kern_isolation::username(uid);
        let have_range = kern_isolation::trusted_helper("newuidmap").is_some()
            && kern_isolation::sub_range("/etc/subuid", uname.as_deref(), uid).is_some();
        if !have_range {
            eprintln!(
                "kern: warning: --ssh needs a uid range (newuidmap + /etc/subuid) for sshd's privsep; \
                 this host has none, so sshd will refuse the login (setgroups denied). Install \
                 newuidmap/uidmap + add a subuid allocation, or use `kern exec` instead of ssh."
            );
        }
    }
    // (The effective command is resolved AFTER the image is pulled, so an `--image`'s Entrypoint/Cmd
    // can supply the default — see `resolve_image_command` below.)
    // Split `-v` into local (host/named) and network (nfs/smb/sshfs) specs. Local ones are parsed
    // (named auto-created); network ones are FUSE/GVFS-mounted to staging and bound in — foreground
    // only, so their unmount is bounded to this call (detached network teardown lands later).
    let (net_specs, local_specs): (Vec<String>, Vec<String>) = args
        .volumes
        .iter()
        .cloned()
        .partition(|s| crate::volume::is_network(s));
    if !net_specs.is_empty() && (args.detached || args.tty) {
        return Err(Error::Sandbox(
            "network volumes (nfs/smb/sshfs) need a plain foreground box (not `-d` or `-it` yet)"
                .to_string(),
        ));
    }
    // Pull out named volumes that carry a recorded quota — those get an ext4-loop backing (real disk
    // quota) in the mount section; the rest (host paths + non-quota named) parse normally here.
    let (quota_specs, plain_specs): (Vec<String>, Vec<String>) =
        local_specs.into_iter().partition(|s| {
            let src = s.split(':').next().unwrap_or("");
            crate::volume::is_named(src) && crate::volume::size_limit(src).is_some()
        });
    let mut volumes = parse_volumes(&plain_specs)?;
    // `--pod <name>`: join the pod's shared user+net namespace (created by `kern pod create`). Resolve
    // its live holder PID, register this box in the pod's shared `/etc/hosts` (so peers resolve it by
    // name), and bind that hosts file read-only over the box's `/etc/hosts`.
    let pod_holder = match args.pod {
        Some(pod) => {
            let holder = crate::pod::holder_pid(pod).ok_or_else(|| {
                Error::Sandbox(format!(
                    "no running pod '{pod}' — create it first with `kern pod create {pod}`"
                ))
            })?;
            crate::pod::add_member(pod, name.as_str())?;
            // Bind the pod's shared hosts over /etc/hosts. RW (not `:ro`): a read-only remount of a
            // bind is refused inside the pod's single-uid user ns (EPERM), and pod members are
            // co-trusted anyway (they already share the user+net ns).
            volumes.push(kern_isolation::Volume {
                source: crate::pod::hosts_path(pod).to_string_lossy().into_owned(),
                target: "/etc/hosts".to_string(),
                read_only: false,
            });
            // If the pod has outbound (a pasta NAT → a pod resolv.conf exists), bind it so DNS works.
            let rp = crate::pod::resolv_path(pod);
            if rp.exists() {
                volumes.push(kern_isolation::Volume {
                    source: rp.to_string_lossy().into_owned(),
                    target: "/etc/resolv.conf".to_string(),
                    read_only: false,
                });
            }
            Some(holder)
        }
        None => None,
    };
    // `--env-file` first (K=V lines from a file), then `--env` on top (explicit wins).
    let mut env = parse_env_files(args.env_file)?;
    env.extend(parse_envs(args.env)?);
    // Fold resource profiles (`vcpu:name` …) into the caps — explicit flags win — before capping.
    let mut ap = AppliedProfiles {
        memory: args.memory,
        cpus: args.cpus,
        cpuset: args.cpuset.map(str::to_string),
        ..Default::default()
    };
    apply_profile_list(args.profiles, args.config, &mut ap)?;
    let AppliedProfiles {
        memory,
        cpus,
        cpuset,
        nice,
        vgpio,
        vdisk,
    } = ap;
    // `--nice` (an explicit flag) overrides a profile's `priority`/`nice`.
    let nice: Option<i32> = args.nice.map(|n| n as i32).or(nice);
    // Flatten the resolved vGPIO profiles into the device/sysfs paths the box will expose.
    let mut vgpio_devs: Vec<String> = Vec::new();
    let mut vgpio_sysfs: Vec<String> = Vec::new();
    for vg in vgpio {
        vgpio_devs.extend(vg.devs);
        vgpio_sysfs.extend(vg.sysfs);
    }
    let cpus = clamp_cpus(cpus);
    // `--show-config`: a dry run — print the resolved box configuration and exit BEFORE any host-side
    // mount or the systemd-scope re-exec, so nothing is created or torn down.
    if args.show_config {
        print_resolved_config(&args, name.as_str(), memory, cpus, cpuset.as_deref(), nice);
        std::process::exit(0);
    }
    // Validate `--health-action` up front (before any host-side mount) so a typo fails fast. A
    // `restart` action implies the on-failure restart policy (that's how it re-runs the box).
    let health_action = parse_health_action(args.health_action)?;
    // In-process supervisor (dies with the host): only `on-failure` — or a `restart` health action.
    // `always`/`unless-stopped` are persistent and handled by a systemd user unit below instead.
    let restart =
        args.restart == RestartPolicy::OnFailure || health_action == HealthAction::Restart;
    // When systemd (re-)starts a persistent box, it runs THIS binary in the foreground with
    // `KERN_MANAGED=1`: skip the transient-scope re-exec (the box already lives in the unit's own
    // service cgroup) and register the foreground run so `kern ps`/`logs`/`stop` still see it.
    let managed = std::env::var_os("KERN_MANAGED").is_some();
    // A `kern build` RUN step (`KERN_BUILD_STEP=1`) is a transient, first-party box run many times in
    // a row — the ~7ms transient-scope re-exec would dominate the build. Skip it (the best-effort
    // in-process cgroup in run_in_sandbox still applies caps; isolation is unchanged).
    let build_step = std::env::var_os("KERN_BUILD_STEP").is_some();
    // Robust resource caps: re-exec this whole invocation inside a transient systemd user scope
    // with memory + task limits (proper cgroup delegation). The scope's caps track the effective
    // memory/cpu so the outer scope never strangles a box that asked for more. No-op if already
    // scoped or if systemd --user isn't available — then the best-effort cgroup in run_in_sandbox
    // applies the same caps.
    if !managed && !build_step {
        reexec_in_scope_if_possible(
            memory,
            args.memory_swap_max,
            cpuset.as_deref(),
            cpus,
            args.pids_limit,
        );
    }
    // A profile's `nice` set here is inherited by the forked box workload.
    if let Some(n) = nice {
        unsafe { libc::setpriority(libc::PRIO_PROCESS as _, 0, n) };
    }

    // `--bind-rootfs` only makes sense for a real `--rootfs` directory: an `--image` must stay an
    // immutable, shareable overlay (the cache is read-only and shared across boxes), and a bind
    // can't be remounted read-only on the kernels where bind mode is even useful.
    if args.bind_rootfs {
        if args.image.is_some() {
            return Err(Error::Sandbox(
                "--bind-rootfs needs --rootfs; an --image stays an immutable overlay".to_string(),
            ));
        }
        if args.read_only {
            return Err(Error::Sandbox(
                "--bind-rootfs is writable-only — a read-only bind remount is denied on the \
                 kernels where it helps; drop --bind-rootfs to get a read-only overlay root"
                    .to_string(),
            ));
        }
    }

    // The lower/base rootfs: an explicit --rootfs, or pull --image into a local cache. An --image
    // also yields its OCI runtime config (Entrypoint/Cmd/Env/WorkingDir/User) — the defaults below.
    let (lower, image_config) = match (args.overlay_lower, args.rootfs, args.image) {
        // Build RUN step: an explicit (possibly colon-joined multi-) lower, no image config.
        (Some(ol), _, _) => (ol.to_string(), kern_oci::ImageConfig::default()),
        (None, Some(r), _) => (r.to_string(), kern_oci::ImageConfig::default()),
        // `--image` may be a pulled (flat) OR a locally-built (layered) image — resolve both.
        (None, None, Some(img)) => resolve_image(img)?,
        (None, None, None) => return Err(Error::Sandbox("need --rootfs or --image".to_string())),
    };
    // Resolve the effective command from the image config (docker semantics: Entrypoint + the user's
    // command, else the image's Cmd; a shell if nothing is set). `--ssh` with no command keeps the
    // box alive instead. Explicit `-- CMD` always wins over the image's Cmd.
    let cmd = resolve_image_command(args.command, args.ssh_port.is_some(), &image_config);
    // The image's Env are DEFAULTS: put them first, then the user's `--env`/`--env-file` on top so an
    // explicit variable overrides the image's.
    if !image_config.env.is_empty() {
        let mut merged = parse_envs(&image_config.env)?;
        merged.extend(env);
        env = merged;
    }

    // Host-side mounts happen HERE — AFTER the systemd-scope re-exec (above) and after every
    // fallible step (guards, pull), so each is done exactly once, in the process that also tears it
    // down, and a later `?` can't orphan one (the handles' `Drop` cleans up an error path; the
    // success path unmounts explicitly before `exit`). Network volumes: FUSE/GVFS mount → bind.
    let mut net_volumes: Vec<crate::volume::NetVolume> = Vec::new();
    for (idx, spec) in net_specs.iter().enumerate() {
        let (source, target, read_only, handle) = crate::volume::setup_network(spec, idx)?;
        volumes.push(Volume {
            source,
            target,
            read_only,
        });
        net_volumes.push(handle);
    }
    // vDisks: a plain foreground box that can reach loop devices (root/`disk`) gets an ext4-on-loop
    // image (real disk-backed quota + persistence); detached/`-it`/unprivileged → a `size=` tmpfs.
    let ext4_ok = !args.detached && !args.tty;
    let vdisk_work = scratch_dir().join(format!("vdisk-{}-{}", name.as_str(), std::process::id()));
    let mut ext4_handles: Vec<crate::vdisk::Ext4Vdisk> = Vec::new();
    // cgroup `io.max` lines for `--iops`/`--bandwidth` on the ext4-loop backend (applied in the box's
    // cgroup by `apply_limits` — best-effort, needs the `io` controller delegated).
    let mut vdisk_io_max: Vec<String> = Vec::new();
    let vdisks: Vec<kern_isolation::VdiskMount> = vdisk
        .into_iter()
        .map(|vd| {
            prepare_vdisk(
                vd,
                ext4_ok,
                &vdisk_work,
                &mut ext4_handles,
                &mut vdisk_io_max,
            )
        })
        .collect();
    // Quota'd named volumes: back them with an ext4-loop image (real disk quota + persistence) when
    // privileged; else bind the plain data dir and say the quota isn't enforced (never silently).
    for spec in &quota_specs {
        let (name_v, dest, ro) = crate::volume::parse_named_spec(spec)?;
        let limit = crate::volume::size_limit(name_v).unwrap_or(0);
        let backend = crate::volume::volumes_dir()
            .join(name_v)
            .to_string_lossy()
            .into_owned();
        let img_existed = std::path::Path::new(&backend)
            .join(format!("kern-vdisk-{name_v}.img"))
            .exists();
        let source = if ext4_ok {
            match crate::vdisk::prepare(name_v, limit, true, Some(&backend), &vdisk_work) {
                Some(h) => {
                    let m = h.mount.to_string_lossy().into_owned();
                    // First time this volume is upgraded to the enforced ext4 backend: seed the fresh
                    // image from the plain `data/` dir, so switching rootless→privileged doesn't hide
                    // the files already written to the volume (the enforced and unenforced backends are
                    // otherwise distinct on-disk locations).
                    if !img_existed {
                        let data = crate::volume::volumes_dir().join(name_v).join("data");
                        let has_data = data
                            .read_dir()
                            .map(|mut d| d.next().is_some())
                            .unwrap_or(false);
                        if has_data {
                            let _ = std::process::Command::new("cp")
                                .arg("-a")
                                .arg(format!("{}/.", data.display()))
                                .arg(&m)
                                .status();
                        }
                    }
                    ext4_handles.push(h);
                    m
                }
                None => quota_fallback(name_v)?,
            }
        } else {
            quota_fallback(name_v)?
        };
        volumes.push(Volume {
            source,
            target: dest,
            read_only: ro,
        });
    }

    // `--secret`: read the values on the host (files/stdin/inline) BEFORE the fork; the box writes
    // them into a RAM-backed `/run/secrets` tmpfs (mode 0400) that never touches the overlay upper.
    let secrets = crate::secret::parse_secrets(args.secrets)?;

    // `--ssh`: authorize a key (generate a throwaway keypair, or use `--ssh-key`) and publish the
    // in-box sshd on the host port (→ box `:22`) via the ordinary rootless forwarder. `eff_ports`
    // is the user's `-p` maps plus that SSH mapping.
    let (ssh, eff_ports) = prepare_ssh(&name, args.ssh_port, args.ssh_key, args.ports)?;
    let ports: &[(u32, u16, u16)] = &eff_ports;
    // Fail fast if a `-p` host port is already taken (by another box or any process): otherwise the
    // forwarder fails inside its fork — whose stderr a detached box swallows — and the box would
    // print "started" while nothing actually listens.
    if let Err((hp, e)) = kern_isolation::preflight_ports(ports) {
        // AlreadyRunning (not Sandbox): the cause is a resource already in use, so its
        // "run `kern ps` … `kern stop`" hint fits — not the sandbox's userns/rootfs hint.
        return Err(Error::AlreadyRunning(format!(
            "cannot publish host port {hp}: {e} — already in use (another box, or a non-kern process)"
        )));
    }

    // `--hostname`: validate before it reaches `sethostname`. `--tmpfs`: parse the Docker-style
    // specs (blocking a tmpfs over the hardened mounts). `--user`: parse UID[:GID].
    let hostname = validate_hostname(args.hostname)?;
    let tmpfs = parse_tmpfs(args.tmpfs)?;
    // `--user` wins; otherwise the image's `config.User` — but only if it's NUMERIC. A NAME (e.g.
    // `USER nginx`) would need the image's `/etc/passwd`, which isn't resolved pre-pivot, so it's
    // skipped (the box runs as its root) with an honest note rather than failing the box.
    let image_user = match image_config.user.as_deref() {
        Some(u) if parse_user(Some(u)).is_ok() => Some(u),
        Some(u) if args.run_as.is_none() => {
            eprintln!(
                "kern: image requests user '{u}' by name — running as box root \
                 (pass --user <uid[:gid]> to drop privilege)"
            );
            None
        }
        _ => None,
    };
    let run_as = parse_user(args.run_as.or(image_user))?;
    // COMPAT HEADS-UP (not a security check; not parsing the entrypoint — only the image's own declared
    // `User`). An OCI image that drops privilege to a non-root user (postgres/redis/nginx via `User` or
    // an entrypoint `setpriv`/`gosu`) needs uids beyond box-root. Two honest cases:
    //  - WITHOUT --uid-range (single-uid box): the drop's uid isn't mapped → the entrypoint's
    //    `chown`/`setuid` fails EINVAL. Tell the user to add --uid-range (which now makes these images
    //    work — the box root is world-traversable and the range maps the service uid).
    //  - WITH --uid-range but the image declares a numeric `User` >= the mapped range size: the drop is
    //    to a uid the range doesn't cover → still fails. Tell the user to widen /etc/subuid. We NEVER
    //    silently clamp the uid into range (that would run the service as a DIFFERENT uid than the image
    //    intends — a silent lie); we surface it and let the user fix the range.
    let declared_user = image_config
        .user
        .as_deref()
        .filter(|u| !u.is_empty() && *u != "0" && *u != "root");
    if let Some(u) = declared_user {
        if !args.uid_range {
            eprintln!(
                "kern: heads-up: image runs as non-root user '{u}' — under kern's rootless model a \
                 single-uid box can't map that uid, so the entrypoint may fail (chown/setuid EINVAL). \
                 Add --uid-range to run it (maps a subordinate uid range so the drop works)."
            );
        } else if let Ok(n) = u.split(':').next().unwrap_or(u).parse::<u32>() {
            // Numeric User declared AND --uid-range: warn only if it exceeds the range we can map.
            // (A name like `postgres` we can't resolve pre-pivot; the range covers the usual 0..65535.)
            let range = mapped_uid_count(); // best-effort: the caller's /etc/subuid range size
            if range != 0 && n >= range {
                eprintln!(
                    "kern: heads-up: image runs as uid {n}, but --uid-range maps only {range} uids \
                     (0..{}). The drop to {n} will fail; widen the caller's /etc/subuid allocation to \
                     cover it. kern will NOT remap it to a different uid.",
                    range - 1
                );
            }
        }
    }
    // `--cap-add`/`--cap-drop`: resolve names to a CapSpec (unknown name → error) layered on the
    // always-dropped dangerous baseline.
    let caps = crate::caps::resolve(args.cap_add, args.cap_drop)?;
    // A non-root `--user` needs its uid mapped into the box's namespace, which the single-uid map
    // doesn't provide — so a non-zero `--user` (like `--ssh`) implies the uid/gid-range mapping.
    let non_root_user = matches!(run_as, Some((u, _)) if u != 0);

    // Always an overlay (image/rootfs = read-only lower, private upper takes writes).
    // `--read-only` then remounts that overlay read-only after pivot.
    let (spec, scratch) = build_spec(BuildSpec {
        name: &name,
        lower,
        cmd,
        read_only: args.read_only,
        volumes,
        env,
        // `--workdir` wins; otherwise the image's `config.WorkingDir`.
        workdir: args
            .workdir
            .map(str::to_string)
            .or_else(|| image_config.workdir.clone()),
        share_net: args.share_net,
        pod_holder,
        // `--ssh` and a non-root `--user` imply the uid/gid *range* mapping: sshd's privsep needs a
        // working `setgroups` (a single-uid map forbids it via `/proc/self/setgroups=deny`), and a
        // non-zero target uid must be mapped in. With the range (via `newgidmap`/`newuidmap`) both
        // work; if the helpers are absent the box falls back to single-uid (warned elsewhere).
        uid_range: args.uid_range || ssh.is_some() || non_root_user,
        bind_rootfs: args.bind_rootfs,
        overlay_upper: args.overlay_upper.map(str::to_string),
        memory,
        memory_swap_max: args.memory_swap_max,
        cpus,
        cpuset,
        vgpio_devs,
        vgpio_sysfs,
        vdisks,
        secrets,
        ssh,
        hostname,
        tun: args.tun,
        tmpfs,
        run_as,
        pids_max: args.pids_limit,
        caps,
        io_max: vdisk_io_max,
        io_weight: args.io_weight,
    })?;

    if args.tty && args.detached {
        return Err(Error::Sandbox(
            "-it can't combine with -d — a detached box has no terminal to attach".to_string(),
        ));
    }
    // `--restart always|unless-stopped` (detached): hand supervision to the user's systemd instead of
    // kern's in-process supervisor — the box then restarts on ANY exit and survives reboot, with no
    // kern daemon. The generated unit re-runs THIS invocation in the foreground; the pull+mount we
    // just did warmed the image cache, so systemd's start is fast. We tear down this launcher's
    // scratch (the managed run makes its own) and return. Not reached in the managed run itself
    // (the unit strips `-d`, so `args.detached` is false there).
    if args.detached && args.restart.persistent() {
        for h in &ext4_handles {
            h.teardown();
        }
        for h in &net_volumes {
            h.teardown();
        }
        cleanup_scratch(scratch.as_deref());
        let _ = std::fs::remove_dir_all(&vdisk_work);
        return install_persistent_box(
            &name,
            args.restart,
            args.memory,
            args.memory_swap_max,
            cpus,
            args.pids_limit,
        );
    }
    // Each box records the named volumes it mounts (below, in the registry) BEFORE it mounts them, so
    // `kern volume rm` sees an in-use volume and refuses — race-free without holding an fd open on the
    // volume dir (which would disturb the sandbox's mount setup).
    let mounted_vols = mounted_named_volumes(args.volumes);
    if args.detached {
        return run_detached(
            &name,
            spec,
            scratch,
            ports,
            &mounted_vols,
            restart,
            HealthConfig {
                cmd: args.health_cmd,
                interval: args.health_interval,
                retries: args.health_retries,
                start_period: args.health_start_period,
                timeout: args.health_timeout,
                action: health_action,
            },
            args.timeout,
        );
    }
    // Foreground/interactive: print the status panel — but only when stderr is a real terminal, so
    // it stays out of pipes, scripts and `kern logs`. stderr (not stdout) keeps the box's own
    // stdout clean. Printed once: when a systemd scope re-execs us, only the inner process (which
    // actually reaches here) prints.
    if !args.quiet && !managed {
        print_box_status(&args, cpus);
    }
    if args.tty {
        return run_box_interactive(spec, scratch, ports, args.timeout);
    }
    // A persistent box (`--restart always`) is started by systemd in the foreground — systemd is the
    // supervisor. Send its output to the per-box log and register it so `kern ps`/`logs`/`stop` still
    // see it; below we re-register with PID 1 once it's up (so `kern exec` works) and unregister on exit.
    // Register EVERY foreground box (Docker-parity: `kern ps`/`stop`/`volume rm` all see it), and
    // unregister on exit below. Registering here — before the box binds its named volumes inside the
    // sandbox — makes `volume rm`'s in-use check race-free. A *managed* (persistent, systemd-unit) box
    // also redirects its stdio to a per-box log; a plain foreground box keeps its terminal. The entry
    // is removed on clean exit; a crash/kill leaves it, but `registry::list()` prunes it by start-time.
    let mut reg_state = {
        let pid = std::process::id() as i32;
        if managed {
            let log = registry::logs_dir()
                .ok()
                .map(|d| d.join(format!("{}-{}.log", name.as_str(), pid)));
            detach_stdio(log.as_deref());
        }
        let inst = registry::Instance {
            name: name.as_str().to_string(),
            pid,
            pid1: 0,
            rootfs: spec.root.clone(),
            command: spec.command.join(" "),
            started: registry::now_unix(),
            starttime: registry::proc_starttime(pid),
            ports: ports_summary(ports),
            volumes: mounted_vols.clone(),
        };
        let path = registry::register(&inst).ok();
        Some((inst, path))
    };
    // Foreground: run the box (the runtime forks `-p` forwarders before the unshare and tears them
    // down when the box exits). `--timeout N`: arm a watchdog that SIGKILLs the box's PID 1 after N
    // seconds. The watchdog MUST be forked here — BEFORE `run_in_sandbox_with` does its
    // `unshare(CLONE_NEWPID)` — so it lives in the host (ancestor) pid namespace; a process forked
    // after the unshare would land INSIDE the box's namespace, where a non-init member can't signal
    // the ns-init. It learns the box's PID 1 over a pipe (written by `on_started`). Skipped for a
    // managed box — a persistent box is meant to stay up; a timeout would just fight systemd's restart.
    let timeout_wd = (args.timeout > 0 && !managed)
        .then(|| spawn_foreground_timeout(args.timeout))
        .flatten();
    let result = run_in_sandbox_with(
        &spec,
        None,
        |pid1| {
            feed_timeout_pid(timeout_wd, pid1);
            if let Some((inst, path)) = reg_state.as_mut() {
                inst.pid1 = pid1;
                if path.is_some() {
                    let _ = registry::register(inst);
                }
            }
        },
        None,
        ports,
    );
    cancel_foreground_timeout(timeout_wd);
    // Tear down any ext4-loop vdisks (unmount + detach loop + remove ephemeral image) and network
    // volumes (fusermount/gio -u) now the box is gone; then the scratch (which holds the images) is
    // removed.
    for h in &ext4_handles {
        h.teardown();
    }
    for h in &net_volumes {
        h.teardown();
    }
    cleanup_scratch(scratch.as_deref());
    let _ = std::fs::remove_dir_all(&vdisk_work);
    if let Some((_, Some(path))) = &reg_state {
        registry::unregister(path);
    }
    match result {
        // Propagate the sandboxed command's exit code as kern's, like `docker run`. This is the
        // one place a non-0/1 exit code is produced — a deliberate terminal action.
        Ok(code) => std::process::exit(code),
        Err(e) => Err(Error::Setup(e.to_string())), // genuine sandbox-start failure → userns hint
    }
}

/// Print the `kern box` status panel (aligned isolation + resource posture, actionable warnings)
/// to stderr — but ONLY when stderr is a terminal, so pipes/scripts/`kern logs` stay clean. `cpus`
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
        seccomp_syscalls: kern_isolation::denied_syscall_count(),
    };
    let p = crate::ui::Palette::detect_stderr();
    let gl = crate::ui::Glyphs::detect();
    // Concise by default — a beginner running `kern box … -- cmd` wants their command's output, not a
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
/// stdout as plain `key: value` lines, then the caller exits. A dry run — unlike the status panel it
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
    println!(
        "uid_range: {}",
        args.uid_range || args.ssh_port.is_some() || non_root_user
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
        kern_isolation::denied_syscall_count()
    );
}

/// True the first time a foreground box runs in this login session, recording a marker under
/// `$XDG_RUNTIME_DIR` (tmpfs → cleared on logout, so "once per session") so the wordmark prints
/// once and not before every box. Best-effort: with no runtime dir (can't track) it returns false
/// — better to skip the logo than to reprint it every time. A lost race (two boxes at once) just
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
/// exits — then restore the terminal and propagate the exit code.
fn run_box_interactive(
    mut spec: SandboxSpec,
    scratch: Option<PathBuf>,
    ports: &[(u32, u16, u16)],
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

/// `kern run [--memory M] [--cpus N] [--] <cmd...>` — run a command under cgroup CPU/memory caps
/// WITHOUT a sandbox. The resource-governor verb: it governs *resources*, not isolation (that's
/// `box`). It replaces this process with the command — no fork, no namespaces, no seccomp — so it's
/// the leanest possible path: a transient capped cgroup + `exec`. The command's exit code becomes
/// kern's, exactly like a bare exec.
pub fn run(
    command: &[String],
    memory: Option<u64>,
    memory_swap_max: Option<u64>,
    cpus: Option<f64>,
    cpuset: Option<&str>,
    config: Option<&str>,
) -> Result<(), Error> {
    use std::os::unix::process::CommandExt;
    // Fold any leading resource-profile tokens (`vcpu:name` …) into the caps — explicit flags win —
    // and find where the real command begins.
    let mut ap = AppliedProfiles {
        memory,
        cpus,
        cpuset: cpuset.map(str::to_string),
        ..Default::default()
    };
    let start = peel_run_profiles(command, config, &mut ap)?;
    let AppliedProfiles {
        memory,
        cpus,
        cpuset,
        nice,
        vgpio,
        vdisk,
    } = ap;
    let command = &command[start..];
    if command.is_empty() {
        return Err(Error::Usage(
            "run [--memory M] [--cpus N] [--cpuset-cpus L] [--config F] [vcpu:PROFILE] [--] <cmd...>",
        ));
    }
    // `run` has no sandbox, so a `vgpio:` profile can't confine devices — instead export it as env
    // (`KERN_VGPIO_NAME`/`_PINS`), like the private, so a cooperative workload can find its pins. To
    // actually *isolate* the peripherals, use `kern box vgpio:NAME …`.
    if !vgpio.is_empty() {
        let names: Vec<&str> = vgpio.iter().map(|v| v.name.as_str()).collect();
        let pins: Vec<String> = vgpio
            .iter()
            .flat_map(|v| v.pins.iter())
            .map(u32::to_string)
            .collect();
        std::env::set_var("KERN_VGPIO_NAME", names.join(","));
        std::env::set_var("KERN_VGPIO_PINS", pins.join(","));
    }
    // A `vdisk:` needs a mount namespace to isolate — `run` has none. Say so rather than pretend.
    if !vdisk.is_empty() {
        eprintln!(
            "kern: vdisk profile(s) ignored by `run` (no mount namespace) — use `kern box vdisk:NAME …`"
        );
    }
    // Robust caps via a transient systemd user scope whose MemoryMax/CPUQuota track the caps; this
    // re-execs once and returns here under KERN_SCOPE. Where systemd --user isn't present it's a
    // no-op and the best-effort in-process cgroup below applies the same caps.
    let cpus = clamp_cpus(cpus);
    reexec_in_scope_if_possible(memory, memory_swap_max, cpuset.as_deref(), cpus, None);
    let _ = kern_isolation::apply_cgroup_limits(
        "run",
        memory,
        memory_swap_max,
        cpuset.as_deref(),
        cpus,
        None, // `kern run` has no --pids-limit; box's pids cap is applied in the sandbox
        &[],  // no vdisk io limits in `kern run`
        None, // no --io-weight in `kern run`
    );
    // Pin CPUs via affinity (works with no cgroup cpuset delegation), and apply a profile's `nice`.
    kern_isolation::set_cpu_affinity(cpuset.as_deref());
    if let Some(n) = nice {
        unsafe { libc::setpriority(libc::PRIO_PROCESS as _, 0, n) };
    }
    // exec() replaces this process with the command (which inherits the cgroup) and only returns on
    // failure — so a successful run propagates the command's own exit code as kern's.
    let err = std::process::Command::new(&command[0])
        .args(&command[1..])
        .exec();
    // `kern run` is the resource governor — there is NO sandbox here — so don't wrap this in the
    // "sandbox: …" error. Print a plain command-not-found message with a fitting hint and exit 127
    // (the conventional "command not found" code), mirroring the box path's exec-failure handling.
    eprintln!("kern: cannot run '{}': {err}", command[0]);
    eprintln!("hint: the command must exist and be executable (an absolute path, or on $PATH)");
    std::process::exit(127);
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
            None => {} // not a profile token — ignored (callers pass only classified tokens)
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

/// Prepare `--ssh`: authorize a public key (from `--ssh-key`, or a freshly generated throwaway
/// ed25519 keypair kept in the runtime dir) and add the `host_port → box:22` mapping to the port set.
/// Prints the ready-to-paste `ssh` command. Returns `(None, ports.to_vec())` when `--ssh` is unset.
#[allow(clippy::type_complexity)]
fn prepare_ssh(
    name: &BoxName,
    ssh_port: Option<u16>,
    ssh_key: Option<&str>,
    ports: &[(u32, u16, u16)],
) -> Result<(Option<kern_isolation::SshSetup>, Vec<(u32, u16, u16)>), Error> {
    let Some(port) = ssh_port else {
        return Ok((None, ports.to_vec()));
    };
    // Don't silently shadow a user `-p` on the same host port, or a second box-side :22.
    if ports.iter().any(|&(_, h, _)| h == port) {
        return Err(Error::Sandbox(format!(
            "--ssh {port} conflicts with a -p mapping on host port {port}"
        )));
    }

    let (authorized_key, hint_key) = match ssh_key {
        // `--ssh-key`: authorize the operator's own public key; nothing is generated.
        Some(path) => {
            let key = std::fs::read_to_string(path)
                .map_err(|e| Error::Sandbox(format!("--ssh-key '{path}': {e}")))?;
            // Validate the key TYPE token (first whitespace-delimited field), not a bare `ssh-`
            // substring — that wrongly rejected valid ECDSA keys (`ecdsa-sha2-nistp256`,
            // `sk-ecdsa-sha2-nistp256@openssh.com`), which contain no `ssh-`.
            let ktype = key.split_whitespace().next().unwrap_or("");
            let ok = ktype.starts_with("ssh-")
                || ktype.starts_with("ecdsa-")
                || ktype.starts_with("sk-ssh-")
                || ktype.starts_with("sk-ecdsa-");
            if !ok {
                return Err(Error::Sandbox(format!(
                    "--ssh-key '{path}' does not look like an OpenSSH public key"
                )));
            }
            (key, None)
        }
        // Generate a throwaway ed25519 keypair in the runtime dir; the private key path is printed
        // for `ssh -i`. Regenerated each launch (the box's authorized_keys is ephemeral anyway).
        None => {
            let dir = registry::ssh_dir()
                .map_err(|e| Error::Sandbox(format!("ssh key dir: {e}")))?
                .join(name.as_str());
            std::fs::create_dir_all(&dir)
                .map_err(|e| Error::Sandbox(format!("ssh key dir: {e}")))?;
            let key = dir.join("id");
            let _ = std::fs::remove_file(&key);
            let _ = std::fs::remove_file(dir.join("id.pub"));
            let ok = std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-N", "", "-q", "-f"])
                .arg(&key)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                return Err(Error::Sandbox(
                    "--ssh: ssh-keygen failed on the host (install openssh-client) — or pass \
                     --ssh-key <pubkey>"
                        .to_string(),
                ));
            }
            let pub_key = std::fs::read_to_string(dir.join("id.pub"))
                .map_err(|e| Error::Sandbox(format!("--ssh: reading generated key: {e}")))?;
            (pub_key, Some(key.to_string_lossy().into_owned()))
        }
    };

    let mut eff = ports.to_vec();
    eff.push((0x7f00_0001, port, 22)); // 127.0.0.1:<port> → box :22
    let id = hint_key.map(|k| format!(" -i {k}")).unwrap_or_default();
    eprintln!(
        "kern: ssh: ssh -p {port}{id} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         root@127.0.0.1"
    );
    Ok((Some(kern_isolation::SshSetup { authorized_key }), eff))
}

/// A quota'd named volume couldn't get its ext4-loop backing (unprivileged, or `-d`/`-it`): bind the
/// plain data dir and say the quota isn't enforced — never silently.
fn quota_fallback(name: &str) -> Result<String, Error> {
    eprintln!(
        "kern: volume '{name}' has a quota but it isn't enforced here — the ext4-loop backend needs \
         a plain foreground box as root (or `disk` group); mounted as a plain directory. Note the \
         enforced (ext4 image) and unenforced (data dir) backends hold data separately."
    );
    crate::volume::resolve_named(name)
}

/// Turn a resolved vDisk into a box mount. Rootless (the default): a `size=`-capped `tmpfs` — the box
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
                            "kern: vdisk:{} — could not resolve the loop device for iops/bandwidth",
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
    // Rootless fallback: a size-capped tmpfs. Be honest about what it can't do.
    if vd.iops.is_some() || vd.bandwidth.is_some() || vd.persistent {
        eprintln!(
            "kern: vdisk:{} — iops/bandwidth/persistent need the ext4-loop backend (root, foreground \
             box); the rootless tmpfs backend applies only the size cap",
            vd.name
        );
    }
    // The tmpfs is RAM-backed, so `size` counts against RAM — bound a large one with `--memory`.
    if vd.size.is_some_and(|b| b >= 1 << 30) {
        eprintln!(
            "kern: vdisk:{} is RAM-backed (tmpfs) rootless — its size counts against RAM; pair a \
             large vdisk with --memory (or run a foreground box as root for the ext4 backend)",
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
    volumes: Vec<Volume>,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    share_net: bool,
    /// `--pod`: the pod holder PID whose user+net ns this box joins (`None` = its own).
    pod_holder: Option<i32>,
    uid_range: bool,
    bind_rootfs: bool,
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
    tmpfs: Vec<(String, String)>,
    run_as: Option<(u32, u32)>,
    pids_max: Option<u64>,
    caps: kern_isolation::CapSpec,
    io_max: Vec<String>,
    io_weight: Option<u64>,
}

/// Build the sandbox spec. **Always an overlay** (the image/rootfs is the read-only lower; a
/// private upper takes writes) over a scratch tree under the runtime dir, removed after the box
/// exits. `--read-only` then remounts that overlay read-only.
///
/// Why overlay even for `--read-only` (rather than a plain bind + remount-ro): on some kernels a
/// **bind** mount cannot be remounted read-only inside a user namespace (e.g. Android-kernel
/// boards return EPERM — the bind inherits a lock from a host mount the child userns doesn't own),
/// whereas an **overlay** has its own superblock created in the namespace and *can* be remounted
/// read-only. Using overlay for both modes makes `--read-only` work everywhere and keeps the
/// image immutable (writes, when allowed, only ever hit the discarded upper).
///
/// When `--net` shares the host network, the host's `/etc/resolv.conf` is copied into the upper
/// so DNS works out of the box.
fn build_spec(b: BuildSpec) -> Result<(SandboxSpec, Option<PathBuf>), Error> {
    // Hostname: `--hostname` wins, else the box name (the box's own UTS namespace, so it's private).
    let hostname = b
        .hostname
        .clone()
        .unwrap_or_else(|| b.name.as_str().to_string());

    // `--bind-rootfs`: skip the overlay and bind the rootfs directly. On kernels with a slow
    // overlayfs mount (some Android-kernel boards: ~31 ms for an overlay vs ~8 ms for a bind) this
    // is the difference between winning and losing on raw start. The trade-off — accepted by the
    // explicit flag — is that the source is mutable and shared: writes land in the rootfs dir and
    // boxes sharing one rootfs are not isolated from each other. There is no overlay scratch.
    //
    // Unlike the overlay path, we deliberately do NOT inject `/etc/resolv.conf` here even with
    // `--net`: that would be a host-side, privileged write into the user-supplied rootfs, and a
    // symlink there (e.g. `/etc/resolv.conf -> ../../host/file`) would make it clobber a file
    // *outside* the rootfs. A bind-mode box uses whatever `/etc/resolv.conf` its rootfs already
    // ships (`--net` still gives outbound networking; add a resolv.conf to the rootfs if needed).
    // The rootfs strategy is the ONLY thing that differs between bind and overlay: pick
    // `(root, mode, overlay, cleanup)` here, then build the one shared SandboxSpec below (its ~27
    // other fields were duplicated field-for-field in both branches — a silent-drift hazard).
    let (root, mode, overlay, eph): (String, MountMode, Option<OverlayDirs>, Option<PathBuf>) = if b
        .bind_rootfs
    {
        (b.lower, MountMode::Bind, None, None)
    } else {
        // The writable overlay upper. Normally an ephemeral scratch (discarded on exit). For a `kern
        // build` RUN step (`overlay_upper` set) the UPPER persists in the build tree so successive RUN/
        // COPY steps accumulate into it (the "diff" layer). overlayfs requires upperdir and workdir to be
        // on the SAME filesystem, so in build mode BOTH live under the build tree (work is cleared each
        // step — overlay wants a fresh workdir); only `merged` (a bare mountpoint) stays ephemeral.
        let eph = scratch_dir().join(format!("{}-{}", b.name.as_str(), std::process::id()));
        // Create the ephemeral parent once (0700) so the per-leaf creates below (`upper`/`work`/`merged`,
        // all under `eph` in the common case) are a single bare mkdir each instead of each re-walking
        // and re-stat-ing the shared parent chain — a few fewer serial pre-fork syscalls per box.
        own_only_dir(&eph).map_err(|e| Error::Sandbox(format!("overlay scratch: {e}")))?;
        let merged = eph.join("merged");
        let (upper, work) = match &b.overlay_upper {
            Some(dir) => {
                let root = PathBuf::from(dir);
                let w = root.join("work");
                let _ = std::fs::remove_dir_all(&w); // fresh workdir per RUN (overlay requirement)
                (build_upper_dir(&root), w)
            }
            None => (eph.join("upper"), eph.join("work")),
        };
        own_only_dir(&upper).map_err(|e| Error::Sandbox(format!("overlay upper: {e}")))?;
        // overlayfs presents the merged root's mode as the UPPER dir's mode. The upper is 0700 (own-only)
        // by default, which makes the box's `/` un-traversable by ANY dropped, cap-less non-root uid →
        // exec/read fails EACCES on `/` itself (the first path component). A `--user` uid hits this, but
        // so does the far more common case: an OCI image whose ENTRYPOINT drops privilege internally
        // (postgres/redis/mysql/nginx `setpriv`/`gosu` to a service uid) — there is no `--user`, yet the
        // workload still ends up non-root and needs a world-traversable `/`. So give the box a normal
        // 0755 root (exactly like a real rootfs) whenever privilege MIGHT be dropped: an explicit
        // non-root `--user`, OR a `--uid-range` box (which exists precisely to run such images). This is
        // the fix for the "official images don't start" gap. It's safe: the HOST scratch dir is still
        // 0700 (no other host user can enter), and root=0755 is the norm for every real filesystem —
        // it's the in-box view only, and the box's isolation is the namespace, not the root's mode.
        let root_traversable = matches!(b.run_as, Some((u, _)) if u != 0) || b.uid_range;
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
                if std::fs::create_dir_all(&etc).is_ok() {
                    let _ = std::fs::write(etc.join("resolv.conf"), conf);
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

    let spec = SandboxSpec {
        root,
        mode,
        overlay,
        read_only: b.read_only,
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
        tmpfs: b.tmpfs,
        run_as: b.run_as,
        pids_max: b.pids_max,
        caps: b.caps,
        io_max: b.io_max,
        io_weight: b.io_weight,
    };
    Ok((spec, eph))
}

/// Parse `-v src:dst[:ro]` specs into [`Volume`]s. Both paths must be absolute; the source must
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
        // (e.g. `/dev/foo`, `/data`) is fine — only these exact roots are protected. Normalize the way
        // the mount actually resolves it (`open_in_root` splits on '/' and drops empty components), so
        // a leading-double-slash target like `//dev` — which trims to a non-matching string but still
        // resolves to `/dev` at mount time — can't slip past this guard.
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
        // The source is either a NAMED volume (a bare name — resolved to its data dir, auto-created
        // like Docker) or an absolute host path (canonicalized symlink-free; a missing one is
        // rejected early rather than as an opaque post-fork mount failure).
        let source = if crate::volume::is_named(source) {
            crate::volume::resolve_named(source)?
        } else if source.starts_with('/') {
            std::fs::canonicalize(source)
                .map_err(|e| Error::Sandbox(format!("-v '{s}': source {source}: {e}")))?
                .to_string_lossy()
                .into_owned()
        } else {
            return Err(Error::Sandbox(format!(
                "-v '{s}': source must be an absolute path or a volume name"
            )));
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

/// Resolve the box's effective command from the user's `-- CMD` and the image's OCI config, docker-
/// style: the image `Entrypoint` is prepended to either the user's command or (if none) the image's
/// `Cmd`; a shell is the fallback when nothing is set anywhere. `--ssh` with no command keeps the box
/// alive instead (the sshd is a child of PID 1, which would otherwise exit). For `--rootfs` the
/// config is empty, so this reduces to the user's command or a shell — the prior behaviour.
fn resolve_image_command(
    user_command: &[String],
    ssh: bool,
    img: &kern_oci::ImageConfig,
) -> Vec<String> {
    if user_command.is_empty() && ssh {
        return vec!["sleep".to_string(), "infinity".to_string()];
    }
    let args: Vec<String> = if user_command.is_empty() {
        img.cmd.clone()
    } else {
        user_command.to_vec()
    };
    let mut full = img.entrypoint.clone();
    full.extend(args);
    if full.is_empty() {
        full.push(DEFAULT_SHELL.to_string());
    }
    full
}

/// Serialize an image's OCI runtime config to a small tab-delimited sidecar (one directive per line)
/// so `kern box --image` can reapply it on a cache hit without re-pulling. Kept OUTSIDE the rootfs
/// (a sibling of the cache dir) so the file never appears inside the box.
fn write_image_config(path: &std::path::Path, c: &kern_oci::ImageConfig) {
    let mut s = String::new();
    let mut line = |k: &str, v: &str| {
        // A value with an embedded newline can't round-trip line-based; such values don't occur in
        // real image configs, so skip one defensively rather than corrupt the file.
        if !v.contains('\n') {
            s.push_str(k);
            s.push('\t');
            s.push_str(v);
            s.push('\n');
        }
    };
    for a in &c.entrypoint {
        line("entrypoint", a);
    }
    for a in &c.cmd {
        line("cmd", a);
    }
    for e in &c.env {
        line("env", e);
    }
    if let Some(w) = &c.workdir {
        line("workdir", w);
    }
    if let Some(u) = &c.user {
        line("user", u);
    }
    let _ = std::fs::write(path, s);
}

/// Read back a [`write_image_config`] sidecar. A missing/garbled file yields the default config.
fn read_image_config(path: &std::path::Path) -> kern_oci::ImageConfig {
    let mut c = kern_oci::ImageConfig::default();
    let Ok(body) = std::fs::read_to_string(path) else {
        return c;
    };
    for l in body.lines() {
        let Some((k, v)) = l.split_once('\t') else {
            continue;
        };
        match k {
            "entrypoint" => c.entrypoint.push(v.to_string()),
            "cmd" => c.cmd.push(v.to_string()),
            "env" => c.env.push(v.to_string()),
            "workdir" => c.workdir = Some(v.to_string()),
            "user" => c.user = Some(v.to_string()),
            _ => {}
        }
    }
    c
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
        let body = std::fs::read_to_string(p)
            .map_err(|e| Error::Sandbox(format!("cannot read --env-file '{p}': {e}")))?;
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

/// Parse `--tmpfs PATH[:size]` specs into `(path, size)` — `size` a tmpfs `size=` token (`"64m"`),
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
/// — a user namespace maps ids, not names. `None` → keep the box's namespace root.
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

/// `kern exec <name> [--env K=V] [--workdir <dir>] [-- cmd...]` — run a command inside an
/// already-running box, joining its namespaces. Defaults to `/bin/sh`. Propagates the exit code.
pub fn exec(
    name: &str,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    tty: bool,
) -> Result<(), Error> {
    let name = BoxName::parse(name).map_err(Error::InvalidBox)?;
    let env = parse_envs(env)?;
    let cmd = default_if_empty(command);
    let inst = registry::list()
        .into_iter()
        .find(|i| i.name == name.as_str())
        .ok_or_else(|| Error::NotRunning(format!("no running box named '{}'", name.as_str())))?;
    // PID 1 of the box. Older entries (or a race before the supervisor recorded it) → fall back
    // to the supervisor's sole child.
    let pid1 = if inst.pid1 > 0 {
        inst.pid1
    } else {
        registry::child_of(inst.pid)
            .ok_or_else(|| Error::Sandbox("could not locate the box's main process".to_string()))?
    };

    // `-it`: allocate a PTY and (when our own stdin is a terminal) put it in raw mode + forward
    // window resizes, exactly like `kern box -it`. `exec_in_box` hands the slave to the exec'd
    // process as its controlling tty and pumps host stdio <-> master; we restore the terminal after.
    let pty = if tty {
        Some(crate::pty::open().map_err(|e| Error::Sandbox(format!("openpty: {e}")))?)
    } else {
        None
    };
    let saved = pty
        .as_ref()
        .and_then(|p| crate::pty::raw_with_resize(p.master));

    let result = exec_in_box(
        pid1,
        &cmd,
        &env,
        workdir,
        pty.as_ref().map(|p| p.slave),
        pty.as_ref().map(|p| p.master),
        None, // `kern exec` has no timeout
    );

    if let Some(prev) = saved.as_ref() {
        crate::pty::restore(0, prev);
    }
    if let Some(p) = pty.as_ref() {
        unsafe { libc::close(p.master) };
    }
    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => Err(Error::Sandbox(e.to_string())),
    }
}

// Subuid/subgid range resolution and the trusted id-map helper lookup are the ONE authoritative
// implementation in kern-isolation (`sub_range` / `trusted_helper` / `username`), reused here so the
// cleanup path can't drift from the box-start path.

/// Remove a box's writable scratch tree (best-effort), with a ranged fallback for subuid-owned files.
fn cleanup_scratch(scratch: Option<&std::path::Path>) {
    if let Some(s) = scratch {
        if std::fs::remove_dir_all(s).is_ok() || !s.exists() {
            return;
        }
        // remove_dir_all failed and the dir is still there: a `--uid-range` box (or a pod member) can
        // leave files owned by SUBORDINATE uids (an image that dropped to e.g. uid 472 → host subuid
        // 100471) that we — as the plain host user, outside any userns — can't unlink (they sit under
        // subuid-owned dirs). Retry inside a `newuidmap`-mapped user namespace where those subuids map
        // back to ns-root, so the remove succeeds. This is what `podman unshare rm` does for the same
        // reason. Best-effort: if the range isn't available, we've already tried the plain remove.
        //
        // TOCTOU (the ranged remove is PRIVILEGED — subuids map to ns-root — and descends a tree a box
        // wrote): a box process surviving teardown could plant a symlink mid-descent to steer the
        // recursive remove outside the scratch tree. Two layers close it: (1) `remove_dir_all` is
        // no-follow at every level (openat+O_NOFOLLOW since Rust 1.26; our MSRV is 1.82, so guaranteed,
        // not toolchain-luck); (2) BEFORE removing, we re-open the target under kern's scratch-root with
        // `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` — a kernel-level check that no component is a
        // symlink or escapes the root. If that open is refused, we do NOT run the ranged remove.
        if !scratch_path_is_confined(s) {
            return;
        }
        remove_dir_all_ranged(s);
    }
}

/// True iff `dir` opens cleanly under kern's scratch-root with `openat2(RESOLVE_BENEATH |
/// RESOLVE_NO_SYMLINKS)` — i.e. every path component stays beneath the root and none is a symlink.
/// Kernel-enforced (Linux 5.6+ for openat2 / 5.3 for the resolve flags); if openat2 is unavailable the
/// no-follow `remove_dir_all` + the canonicalized parent check are the fallback confinement.
fn scratch_path_is_confined(dir: &std::path::Path) -> bool {
    const SYS_OPENAT2: libc::c_long = 437;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let root = scratch_dir();
    let Ok(root_c) = std::ffi::CString::new(root.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    let root_fd = unsafe {
        libc::open(
            root_c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return false;
    }
    // The path RELATIVE to the scratch root (RESOLVE_BENEATH interprets it from root_fd).
    let rel = dir.strip_prefix(&root).unwrap_or(dir);
    let Ok(rel_c) = std::ffi::CString::new(rel.as_os_str().as_encoded_bytes()) else {
        unsafe { libc::close(root_fd) };
        return false;
    };
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,
    };
    let fd = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            root_fd,
            rel_c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    unsafe { libc::close(root_fd) };
    if fd >= 0 {
        unsafe { libc::close(fd as libc::c_int) };
        true // confined: no symlink component, stays beneath the scratch root
    } else {
        // ENOSYS (no openat2) → fall back to the no-follow remove + canonical-parent check (still safe
        // on our MSRV); any other error (ELOOP/EXDEV = a symlink/escape component) → refuse.
        std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS)
    }
}

/// Remove `dir` from inside a user namespace mapped to the caller's full subordinate range, so files
/// owned by subordinate uids (left by a `--uid-range` / pod box whose workload dropped privilege) are
/// unlinkable (they appear owned by ns-root under the map). Forks a child that unshares a user ns and
/// blocks; the parent maps it with `newuidmap`/`newgidmap`; the child then `remove_dir_all`s as ns-root.
fn remove_dir_all_ranged(dir: &std::path::Path) {
    let (uid, gid) = (unsafe { libc::getuid() }, unsafe { libc::getgid() });
    // Resolve the range + trusted helpers via the ONE authoritative kern-isolation impl (same as the
    // box-start path), so cleanup can't drift; no allocation → give up.
    let name = kern_isolation::username(uid);
    let (Some(newuidmap), Some(newgidmap)) = (
        kern_isolation::trusted_helper("newuidmap"),
        kern_isolation::trusted_helper("newgidmap"),
    ) else {
        return;
    };
    let (Some((sub_uid, uc)), Some((sub_gid, gc))) = (
        kern_isolation::sub_range("/etc/subuid", name.as_deref(), uid),
        kern_isolation::sub_range("/etc/subgid", name.as_deref(), gid),
    ) else {
        return;
    };
    let mut c2p = [0i32; 2];
    let mut p2c = [0i32; 2];
    if unsafe { libc::pipe(c2p.as_mut_ptr()) } != 0 || unsafe { libc::pipe(p2c.as_mut_ptr()) } != 0
    {
        return;
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return;
    }
    if pid == 0 {
        unsafe {
            libc::close(c2p[0]);
            libc::close(p2c[1])
        };
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
            unsafe { libc::_exit(1) };
        }
        let _ = unsafe { libc::write(c2p[1], b"1".as_ptr().cast(), 1) };
        let mut b = [0u8; 1];
        let _ = unsafe { libc::read(p2c[0], b.as_mut_ptr().cast(), 1) };
        // ns-root over the whole range now: the subuid-owned files map to ids we own here → removable.
        let _ = std::fs::remove_dir_all(dir);
        unsafe { libc::_exit(0) };
    }
    unsafe {
        libc::close(c2p[1]);
        libc::close(p2c[0])
    };
    let mut b = [0u8; 1];
    let _ = unsafe { libc::read(c2p[0], b.as_mut_ptr().cast(), 1) };
    let map = |bin: &std::path::Path, own: u32, sub: u32, count: u32| {
        let _ = std::process::Command::new(bin)
            .args([
                pid.to_string(),
                "0".into(),
                own.to_string(),
                "1".into(),
                "1".into(),
                sub.to_string(),
                count.to_string(),
            ])
            .status();
    };
    map(&newuidmap, uid, sub_uid, uc);
    map(&newgidmap, gid, sub_gid, gc);
    let _ = unsafe { libc::write(p2c[1], b"1".as_ptr().cast(), 1) };
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
}

/// Fork a health-checker for a detached box: every `interval` s it runs `health_cmd` (via
/// `/bin/sh -c`) inside the box and records `healthy`/`unhealthy` in the registry health sidecar
/// (shown by `kern ps`). It re-reads the box's PID 1 each round, so it follows `--restart`s.
/// Returns the checker's pid.
fn spawn_health_checker(name: String, pid: i32, hc: OwnedHealth) -> i32 {
    let child = unsafe { libc::fork() };
    if child != 0 {
        return child;
    }
    // CHILD: shed inherited fds (the detached box's readiness pipe would otherwise hang `box -d`),
    // then quiet stdio so probe output doesn't land in the box log.
    kern_isolation::shed_inherited_fds(-1);
    detach_stdio(None);
    registry::set_health(&name, pid, "starting");
    let probe = ["/bin/sh".to_string(), "-c".to_string(), hc.cmd];
    let mut elapsed = 0u64; // seconds since the checker started
    let mut fails = 0u32; // consecutive failures
    let mut acted = false; // acted on the *current* unhealthy episode (reset when healthy again)
    loop {
        unsafe { libc::sleep(hc.interval as libc::c_uint) };
        elapsed = elapsed.saturating_add(hc.interval);
        // Current box PID 1 (changes across `--restart`); read it from the registry by name.
        let pid1 = registry::list()
            .into_iter()
            .find(|b| b.name == name)
            .map(|b| b.pid1)
            .unwrap_or(0);
        let status = if pid1 > 0 {
            let ok = run_probe(pid1, &probe, hc.timeout);
            if ok {
                fails = 0;
                acted = false;
                "healthy"
            } else {
                fails = fails.saturating_add(1);
                // During the start-period grace, a failure keeps the box "starting" (Docker
                // semantics — a slow-booting service isn't flapped to unhealthy). After it, a box is
                // "unhealthy" only once `retries` checks have failed in a row; until then hold
                // "starting" so a single blip doesn't trip an orchestrator.
                if elapsed <= hc.start_period || fails < hc.retries {
                    "starting"
                } else {
                    "unhealthy"
                }
            }
        } else {
            "starting"
        };
        registry::set_health(&name, pid, status);
        // `--health-action`: when the box first turns unhealthy, act once (not every interval).
        if status == "unhealthy" && !acted {
            acted = true;
            match hc.action {
                HealthAction::None => {}
                // Restart: kill box PID 1 so the supervisor's on-failure policy re-runs it. Signal
                // via a pidfd taken now, so a pid recycled during a restart gap can't be the victim
                // (the registry-supplied `pid1` could be stale between the box exiting and the
                // supervisor re-registering the new one). Falls back to `kill` on kernels < 5.3.
                HealthAction::Restart => {
                    if pid1 > 0 {
                        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid1, 0) as i32 };
                        unsafe { signal_box(pidfd, pid1, libc::SIGKILL) };
                        if pidfd >= 0 {
                            unsafe { libc::close(pidfd) };
                        }
                    }
                }
                // Stop: tear the whole box down (a detached stopper that has escaped this checker's
                // process group, so the group-kill can't cut its own cleanup short), then exit — the
                // box is going away, so there's nothing left to check.
                HealthAction::Stop => {
                    spawn_detached_stop(name.clone());
                    unsafe { libc::_exit(0) };
                }
            }
        }
    }
}

/// Fork a child that has left the caller's process group (`setsid`), with inherited fds shed and
/// stdio detached — the common prologue of the detached stop/timeout helpers. Returns the child pid
/// to the parent and `None` to the child (which then runs its body and `_exit`s). Escaping the group
/// matters because these children call `stop()`, which group-kills the box; an in-group caller would
/// otherwise be cut down mid-cleanup.
fn fork_detached() -> Option<i32> {
    let child = unsafe { libc::fork() };
    if child != 0 {
        return Some(child);
    }
    unsafe { libc::setsid() };
    kern_isolation::shed_inherited_fds(-1);
    detach_stdio(None);
    None
}

fn spawn_detached_stop(name: String) {
    if fork_detached().is_some() {
        return;
    }
    let _ = stop(std::slice::from_ref(&name), false);
    unsafe { libc::_exit(0) };
}

/// Fork a watchdog for a **foreground** `--timeout N`, returning `(watchdog_pid, write_fd)`. The
/// watchdog is created in the caller's (host) pid namespace — it MUST be forked before the box's
/// `unshare(CLONE_NEWPID)`, so it is an *ancestor* of the box and can therefore signal the box's
/// ns-init (a same-namespace member cannot). It blocks reading the box's PID 1 from the returned
/// pipe (written by `on_started`); once it has it, it sleeps `secs`, then SIGTERMs and — after a 2 s
/// grace — SIGKILLs the box's PID 1, tearing down the whole namespace. If the pipe closes first (the
/// box exited on its own and the caller cancels), the read returns 0 and the watchdog just exits.
/// Returns `None` if the pipe/fork failed (the box simply runs without a timeout).
fn spawn_foreground_timeout(secs: u64) -> Option<(i32, i32)> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return None;
    }
    let (rd, wr) = (fds[0], fds[1]);
    let child = unsafe { libc::fork() };
    if child < 0 {
        unsafe {
            libc::close(rd);
            libc::close(wr);
        }
        return None;
    }
    if child > 0 {
        // Parent keeps the write end. Mark it close-on-exec so the box's exec'd command doesn't
        // inherit a live host pipe fd (the parent's own `on_started` write is unaffected — CLOEXEC
        // only fires on exec).
        unsafe {
            libc::close(rd);
            libc::fcntl(wr, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        return Some((child, wr));
    }
    // CHILD (host-ns watchdog): escape our parent's group/session, drop the write end, quiet stdio.
    unsafe {
        libc::setsid();
        libc::close(wr);
    }
    kern_isolation::shed_inherited_fds(rd);
    detach_stdio(None);
    let mut buf = [0u8; 4];
    let mut got = 0usize;
    while got < buf.len() {
        let n = unsafe { libc::read(rd, buf[got..].as_mut_ptr().cast(), buf.len() - got) };
        if n <= 0 {
            unsafe { libc::_exit(0) }; // pipe closed before a pid arrived — box already gone
        }
        got += n as usize;
    }
    let pid1 = i32::from_ne_bytes(buf);
    // Pin the target with a pidfd taken NOW, while the box is still alive: a pidfd refers to that
    // exact process for its whole life, so the delayed signals below can never land on a reused pid
    // (if the box exits during the sleep, the signal just fails with ESRCH). Fall back to plain
    // `kill(pid1)` only on a kernel too old for pidfd (< 5.3) — the target boards are 5.15+.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid1, 0) as i32 };
    unsafe {
        libc::sleep(secs as libc::c_uint);
        signal_box(pidfd, pid1, libc::SIGTERM);
        libc::sleep(2);
        signal_box(pidfd, pid1, libc::SIGKILL);
        libc::_exit(0);
    }
}

/// Send `sig` to the box's PID 1: via its `pidfd` when we have one (reuse-proof), else plain `kill`.
/// SAFETY: async-signal-safe — only raw syscalls, called from the post-fork watchdog child.
unsafe fn signal_box(pidfd: i32, pid1: i32, sig: i32) {
    if pidfd >= 0 {
        libc::syscall(libc::SYS_pidfd_send_signal, pidfd, sig, 0, 0);
    } else {
        libc::kill(pid1, sig);
    }
}

/// Hand the box's PID 1 to a foreground `--timeout` watchdog over its pipe (from `on_started`, in the
/// host-ns parent). No-op when no timeout is armed.
fn feed_timeout_pid(wd: Option<(i32, i32)>, pid1: i32) {
    if let Some((_, wfd)) = wd {
        let p = pid1.to_ne_bytes();
        unsafe { libc::write(wfd, p.as_ptr().cast(), p.len()) };
    }
}

/// Cancel a foreground `--timeout` watchdog once the box has exited: close our pipe end (so a
/// still-blocked watchdog reads EOF and gives up), then SIGKILL and reap it. Reaping before we return
/// means the watchdog's pid can't be reused, and closing/killing a still-sleeping one stops it before
/// it can signal. No-op when no timeout is armed.
fn cancel_foreground_timeout(wd: Option<(i32, i32)>) {
    if let Some((wd_pid, wfd)) = wd {
        unsafe {
            libc::close(wfd);
            libc::kill(wd_pid, libc::SIGKILL);
            libc::waitpid(wd_pid, std::ptr::null_mut(), 0);
        }
    }
}

/// Fork a watchdog for a **detached** `--timeout N`: after N seconds it stops the box by name (the
/// same teardown as `kern stop`, so the registry/scratch are cleaned up and a `--restart` policy
/// can't resurrect it). It first checks the box is still the same instance (name + supervisor pid),
/// so a box that already exited on its own isn't "stopped" a second time. Returns its pid so the
/// supervisor can cancel it once the box exits normally.
fn spawn_timeout_stop(name: String, sup_pid: i32, secs: u64) -> i32 {
    if let Some(child) = fork_detached() {
        return child;
    }
    unsafe { libc::sleep(secs as libc::c_uint) };
    let still = registry::list()
        .into_iter()
        .any(|b| b.name == name && b.pid == sup_pid);
    if still {
        let _ = stop(std::slice::from_ref(&name), false);
    }
    unsafe { libc::_exit(0) };
}

/// Run one health probe inside the box and report whether it succeeded (exit 0). Forks a child that
/// `exec_in_box`es the probe (so the checker itself stays on the host); `timeout` > 0 is enforced
/// inside `exec_in_box`, which SIGKILLs the whole in-box probe group on expiry (→ non-zero) so a hung
/// check neither stalls the checker nor leaks a live process into the box each interval.
fn run_probe(pid1: i32, probe: &[String], timeout: u64) -> bool {
    let to = (timeout > 0).then_some(timeout);
    let probe_pid = unsafe { libc::fork() };
    if probe_pid == 0 {
        let code = exec_in_box(pid1, probe, &[], None, None, None, to).unwrap_or(1);
        unsafe { libc::_exit(code) };
    }
    if probe_pid <= 0 {
        return false;
    }
    let mut st = 0i32;
    if unsafe { libc::waitpid(probe_pid, &mut st, 0) } <= 0 {
        return false;
    }
    libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0
}

/// Human-readable summary of `-p` mappings for `kern ps`, always showing the bind address so the
/// exposure is visible at a glance (e.g. `127.0.0.1:8080->80, 0.0.0.0:443->443`).
/// Comma-joined **named volumes** a box mounts (from its `-v name:/dst` specs) — recorded in the
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

fn ports_summary(ports: &[(u32, u16, u16)]) -> String {
    ports
        .iter()
        .map(|&(ip, h, b)| crate::ports::fmt(ip, h, b))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Read the last `max` bytes of `path`, trimmed, or `None` if the file is missing/empty. Used to
/// surface a failed detached box's reason inline (the box logged it to its own stderr sink). Reads
/// the whole file — a box that "exited before starting" has only a few lines — and keeps the tail
/// lossily so non-UTF-8 output can't hide the reason.
fn read_log_tail(path: &std::path::Path, max: usize) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    let start = data.len().saturating_sub(max);
    let tail = String::from_utf8_lossy(&data[start..]);
    let t = tail.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// Foreground-launcher side of a detached start: block on the readiness pipe until the box `exec`s
/// (EOF = up) or signals failure (one byte → reap the supervisor and report why), then print the
/// "started" line. With no pipe it just announces. Retries the read on `EINTR` so a stray signal
/// isn't misread as a successful start.
fn await_box_started(
    name: &BoxName,
    child: i32,
    rd: i32,
    wr: i32,
    have_pipe: bool,
) -> Result<(), Error> {
    if have_pipe {
        unsafe { libc::close(wr) };
        let mut byte = [0u8; 1];
        let n = loop {
            let r = unsafe { libc::read(rd, byte.as_mut_ptr().cast(), 1) };
            if r < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break r;
        };
        unsafe { libc::close(rd) };
        if n > 0 {
            let mut st = 0i32;
            unsafe { libc::waitpid(child, &mut st, 0) };
            // The box's own error went to its per-box log (its stderr was detached there), so the
            // launcher only knows it died. `waitpid` above has reaped the supervisor, so the log is
            // now fully written — surface its tail inline. This turns the failure from an opaque
            // "run `kern logs`" round-trip into a reason the user (and a skip-graceful test) can act
            // on immediately, e.g. "unprivileged user namespaces are unavailable" on a locked host.
            // The log is named `<name>-<supervisor pid>.log`, and `child` IS that supervisor pid.
            let n = name.as_str();
            let reason = registry::logs_dir()
                .ok()
                .map(|d| d.join(format!("{n}-{child}.log")))
                .and_then(|p| read_log_tail(&p, 1024));
            return Err(Error::Sandbox(match reason {
                Some(r) => format!(
                    "box '{n}' exited before starting:\n{r}\n(run `kern logs {n}` for the full log)"
                ),
                None => {
                    format!("box '{n}' exited before starting — run `kern logs {n}` for the reason")
                }
            }));
        }
    }
    let p = crate::ui::Palette::detect();
    let gl = crate::ui::Glyphs::detect();
    let n = name.as_str();
    println!(
        "{}{} started{} {}'{n}'{} {}[pid {child}, detached]{}",
        p.g, gl.ok, p.z, p.b, p.z, p.d, p.z
    );
    println!(
        "  {}next: kern ps {} kern logs {n} {} kern stop {n}{}",
        p.d, gl.dot, gl.dot, p.z
    );
    Ok(())
}

/// Supervisor loop: run the box and wait for it; with `--restart` (on-failure) re-run it on a
/// non-zero exit, up to a cap with a 1 s backoff so a perpetually-crashing box eventually gives up.
/// Each attempt is a FRESH child — `run_in_sandbox_with` unshares its *caller*, so it can't be
/// re-run in place (the second `unshare` would `EINVAL`); the supervisor stays un-namespaced and
/// just waits. Readiness is signalled only on the first attempt (the launcher already returned by
/// the time a restart happens). `inst` is re-registered with each attempt's box PID 1.
fn supervise_box(
    name: &BoxName,
    spec: &SandboxSpec,
    have_pipe: bool,
    wr: i32,
    ports: &[(u32, u16, u16)],
    restart: bool,
    inst: &mut registry::Instance,
) {
    const MAX_RESTARTS: u32 = 10;
    // `compose` hands a box that is a `depends_completed` target an exit KEY via env `KERN_EXIT_KEY`.
    // The key is `<pod>-<token>-<name>` — it encodes both the stack AND the `up` epoch, so recording
    // the final code under it can't collide with a same-named service in another stack, nor with the
    // SAME stack under a concurrent `up` (that run has a different token → a different filename). Absent
    // for a plain `kern box` — no sidecar is written. Read ONCE at start; the box's own workload can't
    // change our env.
    let exit_key = std::env::var("KERN_EXIT_KEY")
        .ok()
        .filter(|k| !k.is_empty());
    let mut attempt = 0u32;
    let final_code = loop {
        let ready = if attempt == 0 {
            have_pipe.then_some(wr)
        } else {
            None
        };
        let runner = unsafe { libc::fork() };
        if runner == 0 {
            let code = match run_in_sandbox_with(
                spec,
                ready,
                |pid1| {
                    inst.pid1 = pid1;
                    let _ = registry::register(inst);
                },
                None,  // detached boxes have no terminal to attach
                ports, // the runtime forks `-p` forwarders before unshare, kills them on box exit
            ) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("kern: box failed to start: {e}");
                    127
                }
            };
            unsafe { libc::_exit(code) };
        }
        // Supervisor: drop our readiness-pipe copy so the launcher sees EOF when the box exec()s.
        if attempt == 0 && have_pipe {
            unsafe { libc::close(wr) };
        }
        let mut st = 0i32;
        let code = if runner > 0 && unsafe { libc::waitpid(runner, &mut st, 0) } > 0 {
            if libc::WIFEXITED(st) {
                libc::WEXITSTATUS(st)
            } else if libc::WIFSIGNALED(st) {
                128 + libc::WTERMSIG(st)
            } else {
                1
            }
        } else {
            1 // fork or waitpid failed — treat as a failure, don't spin
        };
        attempt += 1;
        if restart && code != 0 && attempt <= MAX_RESTARTS {
            eprintln!(
                "kern: box '{}' exited {code}; restarting ({attempt}/{MAX_RESTARTS})",
                name.as_str()
            );
            unsafe { libc::sleep(1) }; // brief backoff so a crash loop can't spin
            continue;
        }
        break code;
    };
    // The box has finished for good (no restart left). If compose is waiting on our completion, record
    // the final exit code under its stack+run-scoped key. Written LAST, after the box is truly gone
    // from the run, so a reader that sees the sidecar knows the box is done.
    if let Some(key) = &exit_key {
        registry::set_exit(key, final_code);
    }
}

/// What to do when a box's health check turns it "unhealthy" (`--health-action`).
#[derive(Clone, Copy, PartialEq)]
enum HealthAction {
    /// Record the status only (Docker's default) — an orchestrator decides what to do.
    None,
    /// Kill the box so the supervisor restarts it (implies the on-failure restart policy).
    Restart,
    /// Stop the box entirely (no restart).
    Stop,
}

/// Parse `--health-action <restart|stop|none>` (default `none`).
fn parse_health_action(s: Option<&str>) -> Result<HealthAction, Error> {
    match s {
        None | Some("none") => Ok(HealthAction::None),
        Some("restart") => Ok(HealthAction::Restart),
        Some("stop") => Ok(HealthAction::Stop),
        Some(o) => Err(Error::Sandbox(format!(
            "invalid --health-action '{o}' (expected restart, stop or none)"
        ))),
    }
}

/// The health-check policy for a detached box (`--health-*`).
struct HealthConfig<'a> {
    cmd: Option<&'a str>,
    interval: u64,
    retries: u32,
    start_period: u64,
    timeout: u64,
    action: HealthAction,
}

/// Owned health policy handed to the forked checker (it outlives `box_run`'s borrowed args).
struct OwnedHealth {
    cmd: String,
    interval: u64,
    retries: u32,
    start_period: u64,
    timeout: u64,
    action: HealthAction,
}

#[allow(clippy::too_many_arguments)]
fn run_detached(
    name: &BoxName,
    spec: SandboxSpec,
    scratch: Option<PathBuf>,
    ports: &[(u32, u16, u16)],
    volumes: &str,
    restart: bool,
    health: HealthConfig,
    timeout: u64,
) -> Result<(), Error> {
    // Readiness pipe: the read end stays in this foreground launcher; the write end travels down
    // to the box's PID 1 and is closed on a successful `execvp` (FD_CLOEXEC) → we read EOF = "the
    // box is up". If the box fails to set up or exec, it writes one byte first → we report a
    // truthful failure instead of a misleading "started". No sleep, no poll: the read returns the
    // instant the box is up or has failed, so the only added latency is the box's real start time.
    let mut fds = [0i32; 2];
    let have_pipe = unsafe { libc::pipe(fds.as_mut_ptr()) } == 0;
    let (rd, wr) = (fds[0], fds[1]);

    let child = unsafe { libc::fork() };
    if child < 0 {
        if have_pipe {
            unsafe {
                libc::close(rd);
                libc::close(wr);
            }
        }
        return Err(Error::Sandbox("fork for detach failed".to_string()));
    }
    if child > 0 {
        return await_box_started(name, child, rd, wr, have_pipe);
    }
    // ── Supervisor ──
    // SAFETY (fork): kern is single-threaded (std + libc only, no runtime threads), so running
    // ordinary Rust — allocation, registry writes — after fork is sound. If a future change ever
    // spawns a startup thread, this child must be reduced to async-signal-safe calls (or re-exec).
    if have_pipe {
        unsafe { libc::close(rd) };
    }
    unsafe { libc::setsid() };
    let pid = std::process::id() as i32;
    // Send the box's stdout/stderr to a per-box log file (so `kern logs` can show it).
    let log = registry::logs_dir()
        .ok()
        .map(|d| d.join(format!("{}-{}.log", name.as_str(), pid)));
    detach_stdio(log.as_deref());
    let mut inst = registry::Instance {
        name: name.as_str().to_string(),
        pid,
        pid1: 0,
        rootfs: spec.root.clone(),
        command: spec.command.join(" "),
        started: registry::now_unix(),
        starttime: registry::proc_starttime(pid),
        ports: ports_summary(ports),
        volumes: volumes.to_string(),
    };
    let path = registry::register(&inst).ok();
    // `--health-cmd`: a sidecar process that periodically probes the box and records its health for
    // `kern ps`. Lives in this supervisor's process group, so it's reaped on stop with everything else.
    let health_pid = health.cmd.map(|hc| {
        spawn_health_checker(
            name.as_str().to_string(),
            pid,
            OwnedHealth {
                cmd: hc.to_string(),
                interval: health.interval,
                retries: health.retries,
                start_period: health.start_period,
                timeout: health.timeout,
                action: health.action,
            },
        )
    });
    // `--timeout N`: a watchdog that auto-stops the box N seconds after it starts (registry/scratch
    // cleaned up like `kern stop`). Cancelled below if the box exits on its own first.
    let timeout_pid =
        (timeout > 0).then(|| spawn_timeout_stop(name.as_str().to_string(), pid, timeout));
    // Run the box (re-registering with its PID 1 so `kern exec` can find it), restarting it per
    // `--restart`. Blocks for the box's whole lifetime.
    supervise_box(name, &spec, have_pipe, wr, ports, restart, &mut inst);
    // Box is gone — cancel the sidecars and reap them (they're our children; setsid doesn't change
    // parentage) so we don't leave brief zombies behind before this supervisor exits.
    if let Some(tp) = timeout_pid {
        unsafe {
            libc::kill(tp, libc::SIGKILL);
            libc::waitpid(tp, std::ptr::null_mut(), 0);
        }
    }
    if let Some(hp) = health_pid {
        unsafe {
            libc::kill(hp, libc::SIGTERM);
            libc::waitpid(hp, std::ptr::null_mut(), 0);
        }
        registry::clear_health(name.as_str(), pid);
    }
    if let Some(p) = path {
        registry::unregister(&p);
    }
    cleanup_scratch(scratch.as_deref());
    unsafe { libc::_exit(0) };
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
            Error::Sandbox("HOME not set — cannot locate the systemd user dir".into())
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
/// characters systemd would otherwise act on — `"`/`\` (C-escapes), `$` (env expansion → `$$`), and
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

/// `--restart always|unless-stopped` + `-d`: write and enable a systemd **user** unit that supervises
/// this box, so it restarts on any exit AND survives reboot — WITHOUT a kern daemon (systemd, already
/// running, is the supervisor). The unit re-runs THIS binary in the foreground with `KERN_MANAGED=1`
/// (which registers the box for `kern ps`/`logs`/`stop`); `enable --now` starts it immediately and
/// `enable-linger` makes it come up at boot without a login session. Resource caps (`--memory`,
/// `--cpus`, `--pids-limit`) are applied by systemd via the unit's own service cgroup.
fn install_persistent_box(
    name: &BoxName,
    policy: RestartPolicy,
    memory: Option<u64>,
    memory_swap_max: Option<u64>,
    cpus: Option<f64>,
    pids_max: Option<u64>,
) -> Result<(), Error> {
    let unit_name = unit_file_name(name.as_str());
    let self_exe = std::env::current_exe()
        .map_err(|e| Error::Sandbox(format!("cannot locate the kern binary: {e}")))?;
    // Rebuild the argv for the managed foreground run so systemd re-runs exactly this each start.
    let mut exec = vec![systemd_quote(&self_exe.to_string_lossy())];
    let mut it = std::env::args().skip(1).peekable();
    let mut past_sep = false;
    while let Some(a) = it.next() {
        // Strip kern's own `-d`/`--restart` only among the flags BEFORE the `--` command separator.
        // After `--` the tokens are the box command and must be re-run verbatim (a `-d` there is the
        // workload's argument, not kern's). This can't distinguish a flag from an identical flag
        // *value* before `--` (e.g. `--workdir -d`), but the CLI already parsed those — only the
        // command portion, which we now copy untouched, actually matters for the managed re-run.
        if !past_sep {
            match a.as_str() {
                "-d" | "--detach" => continue,
                "--restart" => {
                    if it.peek().is_some_and(|v| RestartPolicy::parse(v).is_some()) {
                        it.next();
                    }
                    continue;
                }
                "--" => past_sep = true,
                _ => {}
            }
        }
        // A newline/CR would break out of the quoted `ExecStart` line and could inject a systemd
        // directive. It can't come from a normal shell, so reject it rather than emit a corrupt unit
        // (defence in depth — don't rely on systemd itself rejecting the malformed unit).
        if a.contains(['\n', '\r']) {
            return Err(Error::Sandbox(
                "a newline in the command isn't allowed with --restart always \
                 (it would corrupt the systemd unit)"
                    .to_string(),
            ));
        }
        exec.push(systemd_quote(&a));
    }
    // [Service] body. `Restart=always` + `RestartSec=1` for both persistent policies (the
    // stop-survival nuance between `always`/`unless-stopped` is handled by `kern stop` removing the
    // unit). Resource caps go here so systemd's service cgroup enforces them for the managed run.
    let mut svc = String::from("Type=simple\n");
    svc.push_str(&format!("ExecStart={}\n", exec.join(" ")));
    svc.push_str("Environment=KERN_MANAGED=1\n");
    svc.push_str("Restart=always\nRestartSec=1\n");
    // On stop/restart, SIGTERM the kern wrapper (MainPID) so it tears the box down gracefully, then
    // SIGKILL anything still in the cgroup after a bounded grace — otherwise a box whose init ignores
    // SIGTERM (PID 1 in its own namespace) would stall the whole 90s default `TimeoutStopSec`.
    svc.push_str("KillMode=mixed\nTimeoutStopSec=10\n");
    if let Some(m) = memory {
        // Mirror `--memory-swap-max` (default 0 = swap off) so the RAM cap is a hard total, instead
        // of silently pinning swap to 0 and negating a `--memory-swap-max` the user did pass.
        svc.push_str(&format!(
            "MemoryMax={m}\nMemorySwapMax={}\n",
            memory_swap_max.unwrap_or(0)
        ));
    }
    if let Some(c) = cpus {
        svc.push_str(&format!(
            "CPUQuota={}%\n",
            ((c * 100.0).round() as u64).max(1)
        ));
    }
    if let Some(p) = pids_max {
        svc.push_str(&format!("TasksMax={p}\n"));
    }
    let unit = format!(
        "[Unit]\nDescription=kern box {name}\nAfter=network-online.target\n\n\
         [Service]\n{svc}\n[Install]\nWantedBy=default.target\n",
        name = name.as_str(),
    );
    let dir = user_systemd_dir()?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::Sandbox(format!("cannot create {}: {e}", dir.display())))?;
    let path = dir.join(&unit_name);
    std::fs::write(&path, unit)
        .map_err(|e| Error::Sandbox(format!("cannot write {}: {e}", path.display())))?;
    // `enable-linger` so it starts at boot without a login session (best-effort — needs the session
    // bus); `enable --now` enables + starts it. systemd auto-loads a freshly-written unit on `start`,
    // so we SKIP the ~150ms `daemon-reload` in the common path and only fall back to it if the first
    // enable fails (e.g. a stale cached view of a same-named unit).
    let _ = std::process::Command::new("loginctl")
        .arg("enable-linger")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    if !systemctl_user(&["enable", "--now", &unit_name]) {
        systemctl_user(&["daemon-reload"]);
        if !systemctl_user(&["enable", "--now", &unit_name]) {
            // Don't leave a dangling unit if we couldn't start it.
            let _ = std::fs::remove_file(&path);
            systemctl_user(&["reset-failed", &unit_name]);
            systemctl_user(&["daemon-reload"]);
            return Err(Error::Sandbox(
                "systemctl --user enable failed — is a `systemd --user` manager available for this user?"
                    .into(),
            ));
        }
    }
    // Feedback-first: `enable --now` returns success once the start is *dispatched*, so verify the
    // service actually came up rather than printing a "started" that might be a lie (e.g. a bad
    // ExecStart, an image that exits immediately). `is-active` is true for active|activating.
    if !systemctl_user(&["is-active", "--quiet", &unit_name]) {
        return Err(Error::Sandbox(format!(
            "the box unit was installed but didn't start — check `systemctl --user status {unit_name}` \
             (then `kern stop {}` to remove it)",
            name.as_str(),
        )));
    }
    println!(
        "started '{}' (systemd-managed · restart={} · survives reboot)",
        name.as_str(),
        policy.as_str()
    );
    println!(
        "  stop:   kern stop {name}\n  \
           status: systemctl --user status {unit_name}\n  \
           logs:   kern logs {name}",
        name = name.as_str(),
    );
    Ok(())
}

/// Memory + task ceilings for a sandbox scope. `MemorySwapMax=0` makes `MemoryMax` a HARD total
/// cap — without it, a workload over the RAM cap just swaps (on a host with swap) instead of OOM.
const SCOPE_MEMORY_MAX: &str = "MemoryMax=512M";
const SCOPE_SWAP_MAX: &str = "MemorySwapMax=0";
const SCOPE_TASKS_MAX: &str = "TasksMax=512";

/// If a systemd user manager is available and we aren't already inside a kern scope, re-exec
/// the whole `kern` invocation under `systemd-run --user --scope` with cgroup caps, so the
/// sandbox (and any fork bomb in it) is hard-limited. This replaces the process on success; on
/// any failure it returns and the caller falls back to the best-effort cgroup path.
fn reexec_in_scope_if_possible(
    memory: Option<u64>,
    memory_swap_max: Option<u64>,
    cpuset: Option<&str>,
    cpus: Option<f64>,
    pids_max: Option<u64>,
) {
    use std::os::unix::process::CommandExt;

    if std::env::var_os("KERN_SCOPE").is_some() {
        return; // already inside our scope
    }
    if std::env::var_os("KERN_NO_SCOPE").is_some() {
        // Opt-out fast path: skip the systemd transient scope (which costs a `systemd-run` spawn +
        // a D-Bus round-trip + a second kern re-exec — several ms). Resource caps then fall through
        // to the best-effort cgroup path (same as when no user systemd is present). For latency-
        // critical callers (e.g. an agent dev loop firing many short boxes) that accept best-effort
        // instead of hard-delegated caps. Safe: it's the already-exercised no-user-systemd branch.
        return;
    }
    // Gate on a running user manager (so the exec can't strand us in a broken systemd-run).
    let has_user_systemd = std::env::var_os("XDG_RUNTIME_DIR")
        .map(|d| std::path::Path::new(&d).join("systemd").exists())
        .unwrap_or(false);
    if !has_user_systemd {
        return;
    }
    let Ok(self_exe) = std::env::current_exe() else {
        return;
    };
    let args: Vec<String> = std::env::args().skip(1).collect();

    // The scope's memory cap tracks `--memory` (so the outer scope never caps a box below what it
    // asked for); `--cpus` maps to a CPUQuota, `--cpuset-cpus` to AllowedCPUs. Swap tracks
    // `--memory-swap-max` (default 0 = hard cap) and TasksMax stays default.
    let mem_prop = match memory {
        Some(b) => format!("MemoryMax={b}"),
        None => SCOPE_MEMORY_MAX.to_string(),
    };
    let swap_prop = match memory_swap_max {
        Some(b) => format!("MemorySwapMax={b}"),
        None => SCOPE_SWAP_MAX.to_string(),
    };
    let tasks_prop = match pids_max {
        Some(n) => format!("TasksMax={n}"),
        None => SCOPE_TASKS_MAX.to_string(),
    };
    let mut props: Vec<String> = vec![
        "-p".into(),
        mem_prop,
        "-p".into(),
        swap_prop,
        "-p".into(),
        tasks_prop,
    ];
    if let Some(c) = cpus {
        props.push("-p".into());
        // Floor at 1% — a sub-1% `--cpus` would round to `CPUQuota=0%`, which systemd rejects,
        // silently dropping the whole scope (matches the persistent-unit path).
        props.push(format!("CPUQuota={}%", ((c * 100.0).round() as u64).max(1)));
    }
    if let Some(set) = cpuset {
        props.push("-p".into());
        props.push(format!("AllowedCPUs={set}"));
    }
    // Resolve `systemd-run` by trusted absolute path, NOT via `$PATH`: on a box start this spawn is on
    // the critical path, and a long user `$PATH` (cargo/nvm/local/…) makes the kernel try execve in each
    // dir until it finds it — several failed execves per box. The absolute path is one execve. (Same
    // trusted-bin policy as the id-map helpers.)
    let systemd_run = kern_isolation::trusted_helper("systemd-run")
        .unwrap_or_else(|| std::path::PathBuf::from("systemd-run"));
    let mut cmd = std::process::Command::new(systemd_run);
    cmd.args(["--user", "--scope", "--quiet", "--collect"])
        .args(&props)
        .arg("--")
        .arg(self_exe)
        .args(&args)
        .env("KERN_SCOPE", "1");
    // exec() only returns on failure → fall through to the best-effort path.
    let _ = cmd.exec();
}

/// Detach stdio: stdin from `/dev/null`; stdout/stderr to the box's `log` file (so `kern logs`
/// can show it), or `/dev/null` if no log path. So a detached box neither holds nor spams the
/// terminal, but its output is captured.
fn detach_stdio(log: Option<&std::path::Path>) {
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null >= 0 {
            libc::dup2(null, 0);
        }
        let out = log
            .and_then(|p| std::ffi::CString::new(p.to_string_lossy().as_bytes()).ok())
            .map(|c| {
                libc::open(
                    c.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
                    0o600,
                )
            })
            .filter(|fd| *fd >= 0);
        let sink = out.unwrap_or(null);
        if sink >= 0 {
            libc::dup2(sink, 1);
            libc::dup2(sink, 2);
        }
        if let Some(fd) = out {
            if fd > 2 {
                libc::close(fd);
            }
        }
        if null > 2 {
            libc::close(null);
        }
    }
}

/// `kern ps [--json]` — list running boxes. Dead entries are pruned on read.
pub fn ps(json: bool) -> Result<(), Error> {
    let boxes = registry::list();
    if json {
        let mut out = String::from("[");
        for (i, b) in boxes.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"name\":{},\"pid\":{},\"rootfs\":{},\"command\":{},\"started\":{},\"ports\":{},\"health\":{}}}",
                json_str(&b.name),
                b.pid,
                json_str(&b.rootfs),
                json_str(&b.command),
                b.started,
                json_str(&b.ports),
                json_str(&registry::health_of(&b.name, b.pid)),
            ));
        }
        out.push(']');
        println!("{out}");
    } else {
        // Build rows first so the PORTS column can size to its widest value (a published mapping
        // like `127.0.0.1:8080->80` is wider than the "PORTS" header) — keeps COMMAND aligned.
        let now = registry::now_unix();
        let rows: Vec<(&registry::Instance, u64, String, String)> = boxes
            .iter()
            .map(|b| {
                let up = now.saturating_sub(b.started);
                // A frozen box (`kern pause`) is reported as "paused" here — otherwise it looks
                // identical to a running one in `ps`.
                let health = if registry::is_paused(b.pid) {
                    "paused".to_string()
                } else {
                    let h = registry::health_of(&b.name, b.pid);
                    if h.is_empty() {
                        "-".to_string()
                    } else {
                        h
                    }
                };
                let ports = if b.ports.is_empty() {
                    "-".to_string()
                } else {
                    b.ports.clone()
                };
                (b, up, health, ports)
            })
            .collect();
        let pw = rows
            .iter()
            .map(|(_, _, _, p)| p.chars().count())
            .chain(std::iter::once(5)) // len("PORTS")
            .max()
            .unwrap_or(5);
        // On a TTY, truncate COMMAND to the remaining width so a long command never wraps (like
        // `docker ps`); piped/non-TTY prints it whole so scripts get the full line.
        let tty = std::io::stdout().is_terminal();
        let width = crate::ui::term_width(libc::STDOUT_FILENO);
        let p = crate::ui::Palette::detect();
        // The visible width before COMMAND is fixed (16+1+7+1+7+2+9+1+pw+1 = 45+pw), so the budget
        // is computed arithmetically — colour codes never enter the count.
        let prefix_w = 45 + pw;
        println!(
            "{d}{:<16} {:>7} {:>7}  {:<9} {:<pw$} COMMAND{z}",
            "NAME",
            "PID",
            "UPTIME",
            "HEALTH",
            "PORTS",
            d = p.d,
            z = p.z
        );
        for (b, up, health, ports) in &rows {
            // Colour follows the panel standard: bold-cyan NAME, semantic HEALTH. Each cell is
            // padded on its PLAIN value, then wrapped in colour, so alignment is preserved.
            let name = format!("{}{}{:<16}{}", p.b, p.c, b.name, p.z);
            let hc = match health.as_str() {
                "healthy" => p.g,
                "unhealthy" => p.r,
                _ => p.d,
            };
            let health_cell = format!("{hc}{:<9}{}", health, p.z);
            let cmd = if tty {
                truncate(&b.command, width.saturating_sub(prefix_w).max(8))
            } else {
                b.command.clone()
            };
            println!(
                "{name} {:>7} {:>6}s  {health_cell} {ports:<pw$} {cmd}",
                b.pid, up
            );
        }
    }
    Ok(())
}

/// Minimal JSON string escaping for `kern ps --json`.
fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            // Escape every other control char (C0/DEL/C1, incl. ESC `0x1b`) as `\u00XX` — keeps the
            // JSON valid and stops a crafted registry name/description from injecting a real escape
            // sequence into a terminal that cats the output.
            c if c.is_control() => o.push_str(&format!("\\u{:04x}", c as u32)),
            _ => o.push(c),
        }
    }
    o.push('"');
    o
}

/// A JSON number field, or `null` when the value is absent (`stats`/`inspect`). One definition so the
/// two emitters render a missing metric the same way.
fn json_num(v: Option<u64>) -> String {
    v.map_or_else(|| "null".to_string(), |n| n.to_string())
}

/// Human-readable byte size — the shared [`kern_common::fmt_bytes`] convention (`ps`/`stats` columns).
pub(crate) fn human_bytes(b: u64) -> String {
    kern_common::fmt_bytes(b)
}

/// `kern stats [--json]` — current memory + cumulative CPU time per running box (from cgroup).
pub fn stats(json: bool, names: &[String]) -> Result<(), Error> {
    let mut boxes = registry::list();
    // `stats <name>...` filters to the named boxes; a requested name that isn't running is reported
    // (not silently dropped — that would look like a box with no stats).
    if !names.is_empty() {
        for want in names {
            if !boxes.iter().any(|b| &b.name == want) {
                eprintln!("kern: no running box named '{want}'");
            }
        }
        boxes.retain(|b| names.iter().any(|n| n == &b.name));
    }
    if json {
        let mut out = String::from("[");
        for (i, b) in boxes.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            // `null` (not 0) when the box has no dedicated cgroup to read — "unknown", not "zero".
            let num = json_num;
            out.push_str(&format!(
                "{{\"name\":{},\"pid\":{},\"mem_bytes\":{},\"cpu_usec\":{}}}",
                json_str(&b.name),
                b.pid,
                num(registry::mem_bytes(b.pid)),
                num(registry::cpu_usec(b.pid))
            ));
        }
        out.push(']');
        println!("{out}");
    } else {
        let p = crate::ui::Palette::detect();
        println!(
            "{d}{:<16} {:>8} {:>9} {:>9}{z}",
            "NAME",
            "PID",
            "MEM",
            "CPU",
            d = p.d,
            z = p.z
        );
        for b in &boxes {
            let mem = registry::mem_bytes(b.pid).map_or("-".into(), human_bytes);
            let cpu =
                registry::cpu_usec(b.pid).map_or("-".into(), |u| format!("{:.1}s", u as f64 / 1e6));
            let name = format!("{}{}{:<16}{}", p.b, p.c, b.name, p.z);
            println!("{name} {:>8} {:>9} {:>9}", b.pid, mem, cpu);
        }
    }
    Ok(())
}

/// `kern inspect <name> [--json]` — full detail for one running box: its identity (pid, pid1,
/// rootfs, command, ports, uptime) plus live resource readings (mem/cpu/tasks) and health. A
/// superset of one `ps`+`stats` row for a single box. Untrusted fields (rootfs, command) are
/// scrubbed of terminal-escape sequences before display, exactly like the status panel and tables.
/// Errors with a `kern ps` hint if no live box has that name.
pub fn inspect(name: &str, json: bool) -> Result<(), Error> {
    let boxes = registry::list();
    let b = boxes
        .iter()
        .find(|b| b.name == name)
        .ok_or_else(|| Error::NotRunning(format!("no running box named '{name}'")))?;
    let health = registry::health_of(&b.name, b.pid);
    let mem = registry::mem_bytes(b.pid);
    let cpu = registry::cpu_usec(b.pid);
    let tasks = registry::tasks(b.pid);
    let up = registry::now_unix().saturating_sub(b.started);
    if json {
        // `null` (not 0) for a resource the box has no dedicated cgroup to read — "unknown".
        let num = json_num;
        println!(
            "{{\"name\":{},\"pid\":{},\"pid1\":{},\"rootfs\":{},\"command\":{},\"started\":{},\"uptime\":{},\"ports\":{},\"health\":{},\"mem_bytes\":{},\"cpu_usec\":{},\"tasks\":{}}}",
            json_str(&b.name),
            b.pid,
            b.pid1,
            json_str(&b.rootfs),
            json_str(&b.command),
            b.started,
            up,
            json_str(&b.ports),
            json_str(&health),
            num(mem),
            num(cpu),
            num(tasks),
        );
    } else {
        let p = crate::ui::Palette::detect();
        let row = |k: &str, v: &str| println!("{d}{k:<8}{z} {v}", d = p.d, z = p.z);
        // Bold-cyan name header, matching the panel/tables. The name is charset-validated by
        // `BoxName`; rootfs/command are untrusted, so they go through `scrub`.
        println!("{}{}{}{}", p.b, p.c, b.name, p.z);
        row("pid", &b.pid.to_string());
        if b.pid1 != 0 {
            row("pid1", &b.pid1.to_string());
        }
        row("uptime", &fmt_uptime(up));
        row("rootfs", &crate::ui::scrub(&b.rootfs));
        row("command", &crate::ui::scrub(&b.command));
        row("ports", if b.ports.is_empty() { "-" } else { &b.ports });
        row("health", if health.is_empty() { "-" } else { &health });
        row("mem", &mem.map_or("-".into(), human_bytes));
        row(
            "cpu",
            &cpu.map_or("-".into(), |u| format!("{:.1}s", u as f64 / 1e6)),
        );
        row("tasks", &tasks.map_or("-".into(), |t| t.to_string()));
    }
    Ok(())
}

/// `kern prune` — garbage-collect leftover `logs/` and `health/` sidecar files from boxes that are
/// no longer running (a detached box's captured log outlives it). Live boxes are never touched.
/// Reports what it reclaimed (feedback-first: an explicit "nothing to prune" rather than silence).
pub fn prune() -> Result<(), Error> {
    let (removed, freed) = registry::prune();
    let p = crate::ui::Palette::detect();
    if removed == 0 {
        println!("{}nothing to prune{}", p.d, p.z);
    } else {
        let files = if removed == 1 { "file" } else { "files" };
        println!(
            "{}pruned{} {removed} {files}, freed {}",
            p.g,
            p.z,
            human_bytes(freed)
        );
    }
    Ok(())
}

/// `kern gc [--images]` — `prune` the dead-box sidecars, and with `--images` also reclaim the pulled
/// OCI image cache. Never touches a running box or a partially-in-use image dir.
pub fn gc(images: bool) -> Result<(), Error> {
    prune()?;
    // Sweep orphaned build layers: a `kern build` that changes a RUN/COPY leaves its old layer dirs
    // in `L/`, referenced by no image. Delete any `L/<key>` (+ `.ok`) not named in a `<tag>.layers`
    // manifest — bounds the layer cache without nuking the shared, still-referenced layers.
    let (n, freed) = sweep_orphan_layers();
    if n > 0 {
        let p = crate::ui::Palette::detect();
        println!(
            "{}swept{} {n} orphaned build layer{}, freed {}",
            p.g,
            p.z,
            if n == 1 { "" } else { "s" },
            human_bytes(freed)
        );
    }
    if images {
        let p = crate::ui::Palette::detect();
        let cache = cache_dir();
        let freed = dir_size(&cache);
        if freed == 0 {
            println!("{}no cached images{}", p.d, p.z);
        } else if let Err(e) = std::fs::remove_dir_all(&cache) {
            eprintln!("kern: could not clear the image cache: {e}");
        } else {
            println!(
                "{}reclaimed{} the image cache, freed {}",
                p.g,
                p.z,
                human_bytes(freed)
            );
        }
    }
    Ok(())
}

/// Delete build-layer dirs in `L/` not referenced by any `<tag>.layers` manifest. Returns
/// `(count, bytes_freed)`. Only touches `L/<32hex>` entries, never a pulled/built image itself.
fn sweep_orphan_layers() -> (usize, u64) {
    let cache = cache_dir();
    let lc = layer_cache_dir();
    // Collect every layer key still referenced by some image's `.layers` manifest. This set is used
    // to decide what to DELETE, so it must be COMPLETE: if we can't read a manifest (transient IO /
    // permission error), a layer referenced only by it would look orphaned and be wrongly deleted.
    // Fail closed — abort the whole sweep (delete nothing) rather than sweep on a partial set.
    let mut referenced = std::collections::HashSet::new();
    if let Ok(rd) = std::fs::read_dir(&cache) {
        for e in rd.flatten() {
            if e.path().extension().and_then(|s| s.to_str()) == Some("layers") {
                match std::fs::read_to_string(e.path()) {
                    Ok(body) => {
                        for k in body.lines().skip(1).map(str::trim) {
                            referenced.insert(k.to_string());
                        }
                    }
                    Err(_) => return (0, 0), // incomplete reference set → don't risk deleting live layers
                }
            }
        }
    }
    let (mut count, mut freed) = (0usize, 0u64);
    let Ok(rd) = std::fs::read_dir(&lc) else {
        return (0, 0);
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        // Only reap `<32hex>` layer dirs (and their `.ok`); a `.ok` is handled with its dir.
        let key = name.strip_suffix(".ok").unwrap_or(&name);
        if key.len() != 32
            || !key.bytes().all(|b| b.is_ascii_hexdigit())
            || referenced.contains(key)
        {
            continue;
        }
        if e.path().is_dir() {
            freed += dir_size(&e.path());
            if std::fs::remove_dir_all(e.path()).is_ok() {
                count += 1;
            }
        } else {
            let _ = std::fs::remove_file(e.path()); // an orphaned `.ok`
        }
    }
    (count, freed)
}

/// `kern bench [--rootfs R] [-n N]` — measure end-to-end box start→exit latency by running N throwaway
/// boxes (each `/bin/true`, foreground) and timing them, then reporting min/median/avg/max +
/// boxes/sec. This is the real user-facing number (it spawns `kern box` just like you would), so it's
/// the honest figure to quote. Needs a `--rootfs` with a `/bin/true` (any busybox/distro rootfs).
pub fn bench(rootfs: Option<&str>, count: u32) -> Result<(), Error> {
    let rootfs = rootfs.ok_or(Error::Usage(
        "bench needs --rootfs <dir> (e.g. kern pull alpine && kern bench --rootfs ./alpine)",
    ))?;
    if !std::path::Path::new(rootfs).is_dir() {
        return Err(Error::Sandbox(format!(
            "--rootfs '{rootfs}' is not a directory"
        )));
    }
    let self_exe =
        std::env::current_exe().map_err(|e| Error::Sandbox(format!("locating kern: {e}")))?;
    let one = |name: &str| -> Option<std::time::Duration> {
        let t0 = std::time::Instant::now();
        let ok = std::process::Command::new(&self_exe)
            .args(["box", name, "--rootfs", rootfs, "--", "/bin/true"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        ok.then(|| t0.elapsed())
    };
    // Warm-up (image/overlay caches, first scope) — discarded.
    let pid = std::process::id();
    if one(&format!("bench-{pid}-warm")).is_none() {
        return Err(Error::Sandbox(
            "bench box failed to run — does the rootfs have /bin/true? (try a busybox/distro rootfs)"
                .into(),
        ));
    }
    let mut times: Vec<std::time::Duration> = Vec::with_capacity(count as usize);
    for i in 0..count {
        if let Some(d) = one(&format!("bench-{pid}-{i}")) {
            times.push(d);
        }
    }
    if times.is_empty() {
        return Err(Error::Sandbox("no bench runs succeeded".into()));
    }
    times.sort();
    let ms = |d: std::time::Duration| d.as_secs_f64() * 1000.0;
    let sum: f64 = times.iter().map(|d| ms(*d)).sum();
    let avg = sum / times.len() as f64;
    let p = crate::ui::Palette::detect();
    println!(
        "{b}kern bench{z}  {} runs, rootfs {rootfs}",
        times.len(),
        b = p.b,
        z = p.z
    );
    println!(
        "  min {:.1} ms · median {:.1} ms · avg {:.1} ms · max {:.1} ms",
        ms(times[0]),
        ms(times[times.len() / 2]),
        avg,
        ms(times[times.len() - 1])
    );
    println!(
        "  {g}{:.0} boxes/sec{z} (serial)",
        1000.0 / avg,
        g = p.g,
        z = p.z
    );
    Ok(())
}

/// `kern recover` — reconcile the runtime state: drop registry entries for boxes whose process is
/// gone (a crash/kill that skipped the supervisor's cleanup) and remove the orphaned overlay scratch
/// they left behind. Never touches a live box.
pub fn recover() -> Result<(), Error> {
    // `registry::list()` already prunes entries whose process is dead on read; call it to get the
    // set of *live* boxes and to trigger that cleanup.
    let live = registry::list();
    let live_scratch: std::collections::HashSet<String> =
        live.iter().map(|b| b.rootfs.clone()).collect();
    // Orphaned overlay scratch: `<scratch>/<name>-<pid>/` dirs whose box isn't live.
    let mut recovered = 0u32;
    let mut freed = 0u64;
    let scratch = scratch_dir();
    if let Ok(entries) = std::fs::read_dir(&scratch) {
        for e in entries.flatten() {
            let path = e.path();
            let merged = path.join("merged");
            // A live box's `rootfs` is its `.../merged` dir; if none matches, this scratch is orphaned.
            if !live_scratch.contains(&merged.to_string_lossy().into_owned()) && path.is_dir() {
                freed += dir_size(&path);
                if std::fs::remove_dir_all(&path).is_ok() {
                    recovered += 1;
                }
            }
        }
    }
    let p = crate::ui::Palette::detect();
    if recovered == 0 {
        println!(
            "{}nothing to recover — runtime state is consistent{}",
            p.d, p.z
        );
    } else {
        println!(
            "{g}recovered{z} {recovered} orphaned box scratch dir(s), freed {}",
            human_bytes(freed),
            g = p.g,
            z = p.z
        );
    }
    Ok(())
}

/// `kern history [-n N]` — the most recent boxes, reconstructed from their captured log files
/// (`<name>-<pid>.log`): name, pid, when it last ran, and whether it's still running. A lightweight
/// audit trail without a separate history store (prune/gc remove these, so it's "recent", not "all").
pub fn history(count: usize) -> Result<(), Error> {
    let dir = registry::logs_dir().map_err(|e| Error::Sandbox(format!("logs dir: {e}")))?;
    let mut rows: Vec<(String, i32, u64, bool)> = Vec::new(); // name, pid, mtime, alive
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let fname = e.file_name();
            let fname = fname.to_string_lossy();
            let Some(stem) = fname.strip_suffix(".log") else {
                continue;
            };
            // `<name>-<pid>` — split on the LAST '-' (a name may contain '-').
            let Some((name, pid_s)) = stem.rsplit_once('-') else {
                continue;
            };
            let Ok(pid) = pid_s.parse::<i32>() else {
                continue;
            };
            let mtime = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            let alive = unsafe { libc::kill(pid, 0) } == 0;
            rows.push((name.to_string(), pid, mtime, alive));
        }
    }
    rows.sort_by_key(|b| std::cmp::Reverse(b.2)); // newest first
    rows.truncate(count);
    let p = crate::ui::Palette::detect();
    if rows.is_empty() {
        println!("{}no box history yet{}", p.d, p.z);
        return Ok(());
    }
    let now = registry::now_unix();
    println!(
        "{d}{:<20} {:>8} {:>12}  STATUS{z}",
        "NAME",
        "PID",
        "WHEN",
        d = p.d,
        z = p.z
    );
    for (name, pid, mtime, alive) in &rows {
        let status = if *alive {
            format!("{}running{}", p.g, p.z)
        } else {
            format!("{}exited{}", p.d, p.z)
        };
        println!(
            "{b}{c}{:<20}{z} {:>8} {:>12}  {status}",
            truncate(name, 20),
            pid,
            fmt_age(now.saturating_sub(*mtime)),
            b = p.b,
            c = p.c,
            z = p.z
        );
    }
    Ok(())
}

/// `kern images [--json]` — list OCI images pulled into the local cache. Each completed pull leaves
/// a `<sanitized>.ok` sentinel whose *content* is the original image ref, next to the `<sanitized>/`
/// rootfs dir — so we recover the real name, the on-disk size, and when it was pulled.
pub fn images(json: bool) -> Result<(), Error> {
    let cache = cache_dir();
    let mut rows: Vec<(String, u64, u64)> = Vec::new(); // (image ref, size bytes, pulled unix)
    if let Ok(entries) = std::fs::read_dir(&cache) {
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|s| s.to_str()) != Some("ok") {
                continue; // skip the `<name>/` dirs, `.lock` files, `scratch/`
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()).map(String::from) else {
                continue;
            };
            let name = std::fs::read_to_string(&path)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| stem.clone());
            // Size: a pulled (flat) image is `<stem>/`; a single-diff build is `<stem>.diff/`; a
            // multi-layer build (`<stem>.layers`) is the sum of its layer dirs in the `L/` cache.
            let flat = cache.join(&stem);
            let layers_file = cache.join(format!("{stem}.layers"));
            let size = if flat.is_dir() {
                dir_size(&flat)
            } else if layers_file.exists() {
                let lc = layer_cache_dir();
                std::fs::read_to_string(&layers_file)
                    .unwrap_or_default()
                    .lines()
                    .skip(1) // line 0 is the base ref
                    .map(str::trim)
                    .filter(|k| !k.is_empty())
                    .map(|k| dir_size(&lc.join(k)))
                    .sum()
            } else {
                dir_size(&cache.join(format!("{stem}.diff")))
            };
            let pulled = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            rows.push((name, size, pulled));
        }
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));

    if json {
        let mut out = String::from("[");
        for (i, (name, size, pulled)) in rows.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"image\":{},\"size_bytes\":{size},\"pulled\":{pulled}}}",
                json_str(name)
            ));
        }
        out.push(']');
        println!("{out}");
    } else if rows.is_empty() {
        println!("no images cached yet — pull one with `kern pull <image>` (or `kern box <name> --image <image>`)");
    } else {
        let p = crate::ui::Palette::detect();
        println!(
            "{d}{:<30} {:>9}  PULLED{z}",
            "REPOSITORY",
            "SIZE",
            d = p.d,
            z = p.z
        );
        let now = registry::now_unix();
        for (name, size, pulled) in &rows {
            // `truncate` also strips escapes — the `.ok` sentinel content is untrusted.
            let repo = format!("{}{}{:<30}{}", p.b, p.c, truncate(name, 30), p.z);
            println!(
                "{repo} {:>9}  {}",
                human_bytes(*size),
                fmt_age(now.saturating_sub(*pulled))
            );
        }
    }
    Ok(())
}

/// Recursive on-disk size of `dir` in bytes (best-effort). Uses the no-follow dirent file type, so
/// symlinks are neither followed nor counted.
fn dir_size(dir: &std::path::Path) -> u64 {
    let mut total = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            match e.file_type() {
                Ok(ft) if ft.is_dir() => total += dir_size(&e.path()),
                Ok(ft) if ft.is_file() => total += e.metadata().map_or(0, |m| m.len()),
                _ => {}
            }
        }
    }
    total
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

/// `kern search <query> [--json]` — search Docker Hub (the same registry `kern pull` uses) for
/// public images. Prints name, stars, whether it's an official image, and the description.
pub fn search(query: &str, json: bool) -> Result<(), Error> {
    let results = kern_oci::search(query, 25).map_err(|e| Error::Oci(e.to_string()))?;
    if json {
        let mut out = String::from("[");
        for (i, r) in results.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"name\":{},\"description\":{},\"stars\":{},\"official\":{}}}",
                json_str(&r.name),
                json_str(&r.description),
                r.stars,
                r.official
            ));
        }
        out.push(']');
        println!("{out}");
    } else if results.is_empty() {
        println!("no images found for '{query}'");
    } else {
        let p = crate::ui::Palette::detect();
        let gl = crate::ui::Glyphs::detect();
        println!(
            "{d}{:<32} {:>6} {:<8} DESCRIPTION{z}",
            "NAME",
            "STARS",
            "OFFICIAL",
            d = p.d,
            z = p.z
        );
        for r in &results {
            // NAME bold-cyan, OFFICIAL a green check, DESCRIPTION dim — all on PLAIN-padded cells so
            // alignment holds. Both name and description are untrusted (registry data) → escapes stripped.
            let name = format!("{}{}{:<32}{}", p.b, p.c, truncate(&r.name, 32), p.z);
            let official = if r.official {
                format!("{}{:<8}{}", p.g, gl.ok, p.z)
            } else {
                format!("{:<8}", "")
            };
            let desc = format!("{}{}{}", p.d, truncate(&r.description, 46), p.z);
            println!("{name} {:>6} {official} {desc}", r.stars);
        }
        println!("\npull one with:  kern pull <NAME>");
    }
    Ok(())
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

/// `kern logs <name>` — print the captured stdout/stderr of the most recent box named `name`.
pub fn logs(name: &str) -> Result<(), Error> {
    match newest_log(name)? {
        Some(path) => {
            let body = std::fs::read_to_string(&path)
                .map_err(|e| Error::Sandbox(format!("reading log: {e}")))?;
            print!("{body}");
            Ok(())
        }
        None => Err(Error::NotRunning(format!("no logs for box '{name}'"))),
    }
}

/// The current contents of a box's newest log, for the `kern top` log overlay (`Enter`). `None` if the
/// box has produced no log yet; errors are swallowed (the TUI shows an empty pane rather than blowing
/// up mid-frame).
pub(crate) fn box_log_tail(name: &str) -> Option<String> {
    let path = newest_log(name).ok().flatten()?;
    std::fs::read_to_string(path).ok()
}

/// The newest `<name>-<pid>.log` under the logs dir, or `None` if the box has produced no log.
fn newest_log(name: &str) -> Result<Option<PathBuf>, Error> {
    let dir = registry::logs_dir().map_err(|e| Error::Sandbox(format!("logs dir: {e}")))?;
    let prefix = format!("{name}-");
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let fname = e.file_name();
            let fname = fname.to_string_lossy();
            // Require exactly `<name>-<digits>.log`: strip the prefix and `.log`, then the middle must
            // be an all-digit PID. A bare `starts_with(prefix)` would let box `foo` match `foo-bar`'s
            // log file `foo-bar-<pid>.log` (box names may legally contain '-'), leaking another box's
            // output through `kern logs`/`attach`.
            let is_ours = fname
                .strip_prefix(&prefix)
                .and_then(|rest| rest.strip_suffix(".log"))
                .is_some_and(|mid| !mid.is_empty() && mid.bytes().all(|b| b.is_ascii_digit()));
            if is_ours {
                if let Ok(mtime) = e.metadata().and_then(|m| m.modified()) {
                    if newest.as_ref().is_none_or(|(t, _)| mtime > *t) {
                        newest = Some((mtime, e.path()));
                    }
                }
            }
        }
    }
    Ok(newest.map(|(_, p)| p))
}

/// `kern attach <name>` — stream a running (detached) box's output live until it exits or you press
/// Ctrl-C (which **detaches** without stopping the box; a detached box has no stdin, so this is
/// output-only). Prints the log so far, then follows appends by polling the file, and stops when the
/// box leaves the registry.
pub fn attach(name: &str) -> Result<(), Error> {
    use std::io::{Read, Write};
    let bx = registry::list().into_iter().find(|b| b.name == name);
    let Some(bx) = bx else {
        return Err(Error::NotRunning(format!("no running box named '{name}'")));
    };
    let Some(path) = newest_log(name)? else {
        return Err(Error::NotRunning(format!(
            "box '{name}' has no log to attach to (only detached boxes log to a file)"
        )));
    };
    eprintln!(
        "kern: attached to '{name}' (pid {}) — Ctrl-C detaches (box keeps running)",
        bx.pid
    );
    let mut f =
        std::fs::File::open(&path).map_err(|e| Error::Sandbox(format!("opening log: {e}")))?;
    let mut buf = [0u8; 8192];
    let stdout = std::io::stdout();
    loop {
        // Drain whatever is currently appended.
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let _ = stdout.lock().write_all(&buf[..n]);
                    let _ = stdout.lock().flush();
                }
                Err(_) => break,
            }
        }
        // Stop once the box is gone (drain one final time first, above).
        if !registry::list()
            .iter()
            .any(|b| b.name == name && b.pid == bx.pid)
        {
            eprintln!("kern: box '{name}' exited");
            return Ok(());
        }
        unsafe { libc::usleep(200_000) }; // 200 ms — cheap follow poll
    }
}

/// `kern top` — live, auto-refreshing view of running boxes (name, pid, uptime, mem, cpu%).
/// Reads the registry + each box's cgroup every second; exit with Ctrl-C.
/// `kern top` — an interactive task-manager TUI (tabs, live refresh, keyboard nav) when stdout is
/// a terminal; a one-shot table when piped. The implementation lives in [`crate::tui`].
pub fn top() -> Result<(), Error> {
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() {
        crate::tui::run()
    } else {
        crate::tui::snapshot()
    }
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

/// `kern pull <image> [--dest <dir>]` — download an OCI image into a rootfs directory.
pub fn pull(image: &str, dest: Option<&str>) -> Result<(), Error> {
    let dest = match dest {
        Some(d) => PathBuf::from(d),
        None => std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(sanitize_ref(image)),
    };
    println!("pulling {image} -> {}", dest.display());
    kern_oci::pull(image, &dest).map_err(|e| Error::Oci(e.to_string()))?;
    println!(
        "done. run it: kern box <name> --rootfs {} -- /bin/sh",
        dest.display()
    );
    Ok(())
}

/// `kern push <local-ref> [as <remote-ref>]` — publish a locally-cached image to a registry as a
/// single-layer OCI image. The image must be present in the cache (pull/build it first). A push to a
/// private repo needs `kern login`. The rootfs is materialized (flat cache dir, or the overlay chain
/// squashed) and packed into one layer.
pub fn push(local_ref: &str, remote_ref: Option<&str>) -> Result<(), Error> {
    let remote = remote_ref.unwrap_or(local_ref);
    // Materialize the image to a single rootfs directory. A flat pulled image IS a cache dir; a
    // layered/built image is squashed into a temp dir via its overlay chain so we push one layer.
    let (rootfs, config, cleanup) = materialize_image(local_ref)?;
    let cfg = kern_oci::ImageConfigOut {
        entrypoint: config.entrypoint,
        cmd: config.cmd,
        env: config.env,
        workdir: config.workdir,
        user: config.user,
    };
    // Scratch dir for the layer/config blobs, cleaned up on exit.
    let work = cache_dir().join(format!(".push-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| Error::Oci(format!("push work dir: {e}")))?;

    let result =
        kern_oci::push(remote, &rootfs, &cfg, &work).map_err(|e| Error::Oci(e.to_string()));

    let _ = std::fs::remove_dir_all(&work);
    if let Some(tmp) = cleanup {
        remove_build_tree(&tmp); // squashed rootfs (overlay merge) → force-clean mode-000 dirs
    }
    result
}

/// Materialize an image reference to `(rootfs_dir, config, cleanup)`. `cleanup` is `Some(tmp)` when we
/// created a temporary squashed rootfs (layered image) that the caller must remove; `None` when the
/// rootfs is the persistent flat cache dir (do NOT delete it). Errors if the image isn't cached.
fn materialize_image(
    image: &str,
) -> Result<(PathBuf, kern_oci::ImageConfig, Option<PathBuf>), Error> {
    let cache = cache_dir();
    let safe = sanitize_ref(image);
    let flat = cache.join(&safe);
    // Flat pulled image: the cache dir is the rootfs, pushed in place (no copy).
    if flat.is_dir()
        && !cache.join(format!("{safe}.layers")).exists()
        && !cache.join(format!("{safe}.base")).exists()
    {
        let config = read_image_config(&cache.join(format!("{safe}.image")));
        return Ok((flat, config, None));
    }
    // Layered/built image: squash the overlay chain into a fresh temp rootfs so we push one layer.
    //
    // WHITEOUT INVARIANT (review §C — a leak-of-deleted-secrets if broken): a naive `cp -a` bottom-up
    // squash of RAW OCI layers would re-include a file that a higher layer DELETED via a `.wh.` whiteout
    // — e.g. a secret `rm`'d in a cleanup layer would reappear in the pushed image. kern's layers are
    // safe from this by construction: (a) a PULLED base is already the MERGED rootfs — the pull RESOLVES
    // `.wh.`/`.wh..wh..opq` during extraction (see kern_oci::pull), leaving no whiteout files; (b) a
    // BUILT image is base + a SINGLE upper diff where RUN `rm` deletes for real (one shared upper, no
    // per-step whiteout). So the chain here never contains whiteout files, and `cp -a` is correct.
    // Belt-and-braces AND future-proofing (if kern ever gains per-RUN whiteout layers): after the copy
    // we STRIP any `.wh.*` that somehow survived, so a whiteout can never be pushed as a literal file.
    let (lower, config) = resolve_image(image)?;
    let tmp = cache.join(format!(".push-squash-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| Error::Oci(format!("squash dir: {e}")))?;
    // The overlay chain is `top:...:base` (colon-joined). Copy each layer bottom-up into `tmp` so the
    // top layers shadow the base — a simple squash. `cp -a` preserves symlinks (no host-follow).
    let mut layers: Vec<&str> = lower.split(':').collect();
    layers.reverse(); // apply base first, then higher layers overwrite
    for layer in layers {
        let ok = std::process::Command::new("cp")
            .arg("-a")
            .arg("--")
            .arg(format!("{layer}/."))
            .arg(&tmp)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            remove_build_tree(&tmp);
            return Err(Error::Oci(format!("squashing image '{image}' failed")));
        }
    }
    // Defence-in-depth: strip any surviving OCI whiteout markers so a `.wh.<name>` can never be pushed
    // as a literal file (which a registry/Docker would then materialize as a real file named `.wh.…`).
    strip_whiteout_markers(&tmp);
    Ok((tmp.clone(), config, Some(tmp)))
}

/// Rewrite each service's RELATIVE bind-mount source to an absolute path under the compose file's
/// directory (Docker's rule), so kern's `-v` — which wants an absolute path or a named volume —
/// accepts the common `./dir:/dst` / `.:/app` compose form. A source that is already absolute (`/…`),
/// or a bare NAME (a named volume, no `/` and no leading `.`), is left untouched. The resolved path is
/// CONFINED under the compose dir (canonicalize + starts_with, same traversal guard as a build
/// context) so a `../../../etc:/x` can't escape the project tree.
fn resolve_relative_binds(
    boxes: &mut [crate::compose::ComposeBox],
    file: &str,
) -> Result<(), Error> {
    let compose_dir = std::path::Path::new(file)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let base = std::fs::canonicalize(&compose_dir)
        .map_err(|e| Error::Compose(format!("resolving compose dir: {e}")))?;

    for b in boxes.iter_mut() {
        for v in b.volumes.iter_mut() {
            // Split `src:dst[:opts]`. The source is the first segment; dst/opts follow.
            let (src, rest) = match v.split_once(':') {
                Some((s, r)) => (s, r),
                None => continue, // malformed spec — let `kern box` report it precisely
            };
            // Classify the source. A leading `/` is absolute (left as-is). A bare NAME with no `/` is a
            // named volume (left as-is; the box validates it). ANYTHING ELSE containing `/` is a
            // relative PATH and must be confined — not just the `./`/`../` forms: a source like
            // `foo/../../../etc` is relative but doesn't start with `./`, and the old check let it skip
            // the guard (the box's name-validator caught it as a backstop, but defense-in-depth wants
            // the compose layer to confine every relative path itself). (Hacker-mode audit, MEDIUM.)
            if src.starts_with('/') || !src.contains('/') {
                continue;
            }
            let abs = std::fs::canonicalize(base.join(src)).map_err(|e| {
                Error::Compose(format!("service '{}': bind source '{src}': {e}", b.name))
            })?;
            if !abs.starts_with(&base) {
                return Err(Error::Compose(format!(
                    "service '{}': bind source '{src}' escapes the compose directory (refused)",
                    b.name
                )));
            }
            *v = format!("{}:{rest}", abs.to_string_lossy());
        }
        // Compose `secrets:` map to `--secret <file>:<name>`; `<file>` came from a top-level `file: ./x`
        // and is relative → resolve against the compose dir, same traversal guard as a bind.
        for s in b.secrets.iter_mut() {
            let Some((file, nm)) = s.split_once(':') else {
                continue;
            };
            if file.starts_with('/') {
                continue; // already absolute
            }
            let abs = std::fs::canonicalize(base.join(file)).map_err(|e| {
                Error::Compose(format!("service '{}': secret file '{file}': {e}", b.name))
            })?;
            if !abs.starts_with(&base) {
                return Err(Error::Compose(format!(
                    "service '{}': secret file '{file}' escapes the compose directory (refused)",
                    b.name
                )));
            }
            *s = format!("{}:{nm}", abs.to_string_lossy());
        }
    }
    Ok(())
}

/// Walk a squashed rootfs and honour any OCI whiteout marker that survived the merge: `.wh.<name>`
/// deletes its sibling `<name>` (and itself), `.wh..wh..opq` clears its directory's contents. In
/// kern's model the chain has none (see the invariant at the call site), so this is a no-op belt —
/// but if a future layer format leaves whiteouts, this keeps a deleted file from being republished.
/// Best-effort, non-following (never descends a symlink), depth-first.
fn strip_whiteout_markers(root: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        let ft = match e.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if name == ".wh..wh..opq" {
            // Opaque dir marker: drop it (its "hide everything below" is already reflected in the
            // merged view we squashed; the marker itself must not ship).
            let _ = std::fs::remove_file(e.path());
            continue;
        }
        if let Some(victim) = name.strip_prefix(".wh.") {
            // Whiteout: remove the shadowed sibling (if it somehow got copied) and the marker.
            if !victim.is_empty() && !victim.contains('/') {
                let sib = root.join(victim);
                if sib.is_dir() {
                    let _ = std::fs::remove_dir_all(&sib);
                } else {
                    let _ = std::fs::remove_file(&sib);
                }
            }
            let _ = std::fs::remove_file(e.path());
            continue;
        }
        // Recurse into real subdirectories (not symlinks — no-follow).
        if ft.is_dir() {
            strip_whiteout_markers(&e.path());
        }
    }
}

/// Resolve `--image <ref>` to an overlay `(lowerdir, config)`. A pulled (flat) image is a single
/// cache dir. A locally-built (**layered**) image — marked by a `<ref>.base` sidecar — is its
/// `<ref>.diff` layer stacked over its base, resolved RECURSIVELY (the base may itself be layered)
/// and re-pulled if the base was pruned, so layered images are prune-safe. The returned `lowerdir`
/// may be a colon-joined chain (top layer first, exactly overlayfs's ordering).
fn resolve_image(image: &str) -> Result<(String, kern_oci::ImageConfig), Error> {
    resolve_image_depth(image, 0)
}

fn resolve_image_depth(image: &str, depth: u32) -> Result<(String, kern_oci::ImageConfig), Error> {
    // Bound the chain so a self-referential build (`FROM` its own tag) can't recurse forever.
    if depth > 128 {
        return Err(Error::Oci(
            "image layer chain too deep (a build FROM its own tag?)".into(),
        ));
    }
    let cache = cache_dir();
    let safe = sanitize_ref(image);
    // A cache-built (multi-layer) image: `<tag>.layers` = base ref, then one layer key per line.
    let layers_file = cache.join(format!("{safe}.layers"));
    if layers_file.exists() {
        let body = std::fs::read_to_string(&layers_file)
            .map_err(|e| Error::Oci(format!("read layers of '{image}': {e}")))?;
        let mut lines = body.lines();
        let base_ref = lines.next().unwrap_or("").trim();
        let (base_lower, _) = resolve_image_depth(base_ref, depth + 1)?;
        let lc = layer_cache_dir();
        let mut chain = vec![base_lower];
        for k in lines.map(str::trim).filter(|k| !k.is_empty()) {
            // A layer key MUST be 32 lowercase hex (what we write). Reject anything else so a corrupt
            // or (once layered images are shippable) hostile manifest can't turn a key into a `/etc`,
            // `../…`, or `:`/`,`-bearing path that escapes `L/` or injects an overlay mount option.
            if k.len() != 32 || !k.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::Oci(format!("corrupt layer manifest for '{image}'")));
            }
            chain.push(lc.join(k).to_string_lossy().into_owned());
        }
        let lower = chain_lower(&chain);
        if lower.len() > MAX_LOWERDIR_BYTES {
            return Err(Error::Oci(format!(
                "image '{image}' has too many layers to overlay (rebuild with fewer steps)"
            )));
        }
        let config = read_image_config(&cache.join(format!("{safe}.image")));
        return Ok((lower, config));
    }
    // Legacy single-diff (P3.5) image: `<tag>.base` + `<tag>.diff`.
    let base_marker = cache.join(format!("{safe}.base"));
    if base_marker.exists() {
        let base_ref = std::fs::read_to_string(&base_marker)
            .map_err(|e| Error::Oci(format!("read base of '{image}': {e}")))?
            .trim()
            .to_string();
        let (base_lower, _) = resolve_image_depth(&base_ref, depth + 1)?;
        let diff = cache.join(format!("{safe}.diff"));
        let config = read_image_config(&cache.join(format!("{safe}.image")));
        // Top (this image's diff) first, then the base chain — overlayfs shadows left-to-right.
        return Ok((format!("{}:{base_lower}", diff.to_string_lossy()), config));
    }
    pull_to_cache(image)
}

/// Pull `image` into a local cache and return `(rootfs path, its OCI runtime config)`. Reuse is gated
/// on a sibling completion sentinel (`<ref>.ok`), not "directory is non-empty" — so an interrupted
/// pull (or a stray file) never makes a partial/poisoned rootfs look valid; we re-pull cleanly. The
/// image config is persisted to a `<ref>.image` sidecar (outside the rootfs) so a cache hit reapplies
/// it without re-pulling.
fn pull_to_cache(image: &str) -> Result<(String, kern_oci::ImageConfig), Error> {
    use std::os::unix::io::AsRawFd;
    let cache = cache_dir();
    own_only_dir(&cache).map_err(|e| Error::Oci(format!("cache dir: {e}")))?;
    let safe = sanitize_ref(image);
    let dir = cache.join(&safe);
    let sentinel = cache.join(format!("{safe}.ok"));
    let cfgfile = cache.join(format!("{safe}.image"));
    if sentinel.exists() {
        // fast path: already cached
        return Ok((
            dir.to_string_lossy().into_owned(),
            read_image_config(&cfgfile),
        ));
    }
    // Serialize concurrent pulls of the SAME image: take an exclusive lock, then re-check the
    // sentinel (another process may have completed the pull while we waited). Different images
    // use different lock files, so they still pull in parallel.
    let lock = std::fs::File::create(cache.join(format!("{safe}.lock")))
        .map_err(|e| Error::Oci(format!("pull lock: {e}")))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(Error::Oci("could not acquire pull lock".into()));
    }
    if !sentinel.exists() {
        eprintln!("→ image '{image}' not cached — pulling once (reused after)");
        let _ = std::fs::remove_dir_all(&dir); // clear any partial extraction
        std::fs::create_dir_all(&dir).map_err(|e| Error::Oci(format!("cache dir: {e}")))?;
        let config = kern_oci::pull(image, &dir).map_err(|e| Error::Oci(e.to_string()))?;
        write_image_config(&cfgfile, &config);
        let _ = std::fs::write(&sentinel, image.as_bytes());
    }
    // lock released when `lock` drops
    Ok((
        dir.to_string_lossy().into_owned(),
        read_image_config(&cfgfile),
    ))
}

/// Image cache root: `$XDG_CACHE_HOME/kern/images` → `$HOME/.cache/kern/images` (both user-owned
/// and persistent) → `/tmp/kern-cache-<uid>/images` (created mode 0700, last resort).
fn cache_dir() -> PathBuf {
    if let Some(x) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(x).join("kern/images");
    }
    if let Some(h) = std::env::var_os("HOME") {
        return PathBuf::from(h).join(".cache/kern/images");
    }
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/tmp/kern-cache-{uid}/images"))
}

/// The content-addressed build **layer cache** (`<image cache>/L`): each `kern build` unit (a RUN
/// batch, a COPY, a WORKDIR) is stored here under its cache key so an unchanged rebuild reuses it
/// instead of re-executing — Docker-style layer caching, mounted back as an overlay lower.
fn layer_cache_dir() -> PathBuf {
    cache_dir().join("L")
}

/// A 128-bit FNV-1a cache key (32 hex) over `prev-key` then `repr` — the chained key that makes a
/// layer's identity depend on everything before it, so a change busts that layer and all after it.
/// Non-crypto: this is a LOCAL, first-party cache, and a collision only mis-reuses the user's OWN
/// layer (2^-128); it is never a trust boundary.
fn layer_key(prev: &str, repr: &str) -> String {
    let (mut a, mut b): (u64, u64) = (0xcbf2_9ce4_8422_2325, 0x9e37_79b9_7f4a_7c15);
    for byte in prev.bytes().chain([0u8]).chain(repr.bytes()) {
        a = (a ^ byte as u64).wrapping_mul(0x0000_0100_0000_01b3);
        b = (b ^ byte as u64)
            .wrapping_mul(0x0000_0100_0000_01b3)
            .rotate_left(13);
    }
    format!("{a:016x}{b:016x}")
}

/// Hash a COPY/ADD source's tree (paths + file bytes + symlink targets, order-stable) into the
/// layer key, so editing a copied file busts the cache. Best-effort: an unreadable entry still
/// contributes a marker so its absence/failure changes the key.
fn content_hash(path: &std::path::Path) -> String {
    fn feed(h: &mut u64, bytes: &[u8]) {
        for &b in bytes {
            *h = (*h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    fn walk(h: &mut u64, p: &std::path::Path, rel: &str) {
        match std::fs::symlink_metadata(p) {
            Ok(m) if m.file_type().is_symlink() => {
                feed(h, b"L");
                feed(h, rel.as_bytes());
                if let Ok(t) = std::fs::read_link(p) {
                    feed(h, t.to_string_lossy().as_bytes());
                }
            }
            Ok(m) if m.is_dir() => {
                feed(h, b"D");
                feed(h, rel.as_bytes());
                let mut names: Vec<_> = std::fs::read_dir(p)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(|e| e.file_name())
                    .collect();
                names.sort();
                for n in names {
                    let child = p.join(&n);
                    walk(h, &child, &format!("{rel}/{}", n.to_string_lossy()));
                }
            }
            Ok(m) => {
                use std::os::unix::fs::PermissionsExt;
                feed(h, b"F");
                feed(h, rel.as_bytes());
                // Fold in the file MODE: a `cp -a` COPY preserves it, so a chmod-only change (e.g.
                // adding +x to an entrypoint) must bust the cache or the layer ships the old mode.
                feed(h, &(m.permissions().mode() & 0o7777).to_le_bytes());
                match std::fs::read(p) {
                    Ok(c) => feed(h, &c),
                    Err(_) => feed(h, b"?"),
                }
            }
            Err(_) => feed(h, b"?"),
        }
    }
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    walk(&mut h, path, "");
    format!("{h:016x}")
}

/// A completed layer's sentinel exists (`<key>.ok`) → it's a cache hit.
fn layer_cached(lc: &std::path::Path, key: &str) -> bool {
    lc.join(format!("{key}.ok")).exists()
}

/// Commit a freshly-built layer's content dir into the layer cache under `key` (atomic rename +
/// completion sentinel). A concurrent build that produced the same key first simply wins the race.
fn commit_layer(content: &std::path::Path, lc: &std::path::Path, key: &str) -> Result<(), Error> {
    let dest = lc.join(key);
    if !dest.exists() {
        // Ignore a rename race (another build committed the identical key first) — content is equal.
        let _ = std::fs::rename(content, &dest);
    }
    // Only mark the layer complete once its content dir is actually in place — otherwise a failed
    // rename (e.g. ENOSPC) would leave a sentinel with no dir → a poisoned "hit" that later fails
    // to mount. A missing sentinel just means the next build re-runs the unit (safe).
    if dest.exists() {
        let _ = std::fs::write(lc.join(format!("{key}.ok")), b"");
    }
    Ok(())
}

/// `true` if `rel` resolves to a directory anywhere in the overlay `chain` (layer dirs + base),
/// searched top-first — used by COPY to decide "into a dir" vs "as a file" against the MERGED image
/// (a lower layer may hold the dir). Build layers never delete, so the first hit wins.
fn chain_has_dir(chain: &[String], rel: &str) -> bool {
    if rel.is_empty() {
        return true;
    }
    chain.iter().rev().any(|d| {
        std::fs::symlink_metadata(std::path::Path::new(d).join(rel))
            .map(|m| m.is_dir())
            .unwrap_or(false)
    })
}

/// Create `dir` (and parents) private to this user (mode 0700). Mitigates a local-user symlink/
/// clobber attack on a predictable cache path: another user can't pre-create or enter it.
/// Size of the caller's subordinate-uid range from `/etc/subuid` (box uids 1..count map here, so the
/// box can use uids 0..count-1). `0` if there's no allocation (single-uid only). Best-effort, matching
/// how `newuidmap` resolves the row — a name match wins, else a numeric-uid row. Used only to warn (F1)
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

fn own_only_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// A filesystem-safe directory name for an image reference.
fn sanitize_ref(image: &str) -> String {
    // A filesystem-safe, COLLISION-FREE cache key. Map anything outside `[A-Za-z0-9_-]` to `_` — so
    // `/`, `:`, and crucially any `.`/`..` can't build a traversal like `cache/..` (which a later
    // `remove_dir_all` would then wipe) — then append a short hash of the FULL ref so distinct images
    // (`foo/bar` vs `foo_bar`) can never share a cache dir / config sidecar.
    let base: String = image
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{base}-{:016x}", fnv1a(image))
}

/// FNV-1a 64-bit — a fast non-cryptographic hash, used ONLY to make [`sanitize_ref`] cache keys
/// collision-free (never for anything security-sensitive).
fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Arguments for [`build`] (`kern build`).
pub struct BuildArgs<'a> {
    /// `-t <name[:tag]>`: the local image name to store the result under. Required.
    pub tag: Option<&'a str>,
    /// `-f <file>`: the Dockerfile path. `None` → `<context>/Dockerfile`.
    pub file: Option<&'a str>,
    /// The build context directory (default `.`) — the root COPY/ADD sources resolve against.
    pub context: &'a str,
    /// `--build-arg K=V` (repeatable): values for `ARG` substitution.
    pub build_args: &'a [String],
    /// `--quiet`: suppress per-step progress.
    pub quiet: bool,
}

/// `kern build -t <name> [-f Dockerfile] [--build-arg K=V] [<context>]` — build a local image from a
/// **subset** of Dockerfile (see [`crate::dockerfile`]). `FROM` pulls the base into a mutable build
/// rootfs; `RUN` executes inside a `kern box` (bind-mounted rootfs + host net); `COPY`/`ADD` copy
/// from the context (symlink-safe both sides); `ENV`/`WORKDIR`/`USER`/`CMD`/`ENTRYPOINT` accumulate
/// into the image config. The result is stored in the image cache so `kern box --image <name>` runs
/// it with no pull (reusing the P1 config sidecar). Daemonless, dependency-free (curl/tar/cp).
pub fn build(args: BuildArgs) -> Result<(), Error> {
    let tag = args
        .tag
        .filter(|t| !t.is_empty())
        .ok_or(Error::Usage("kern build needs -t <name[:tag]>"))?;
    let ctx = std::fs::canonicalize(args.context)
        .map_err(|e| Error::Build(format!("build context '{}': {e}", args.context)))?;
    if !ctx.is_dir() {
        return Err(Error::Build(format!(
            "build context '{}' is not a directory",
            args.context
        )));
    }
    let dfpath = match args.file {
        Some(f) => PathBuf::from(f),
        None => ctx.join("Dockerfile"),
    };
    let text = std::fs::read_to_string(&dfpath)
        .map_err(|e| Error::Build(format!("cannot read {}: {e}", dfpath.display())))?;
    let mut bmap = std::collections::HashMap::new();
    for ba in args.build_args {
        let (k, v) = ba
            .split_once('=')
            .ok_or(Error::Usage("--build-arg expects K=V"))?;
        bmap.insert(k.to_string(), v.to_string());
    }
    let instrs = crate::dockerfile::parse(&text, &bmap).map_err(Error::Build)?;

    let cache = cache_dir();
    own_only_dir(&cache).map_err(|e| Error::Oci(format!("cache dir: {e}")))?;
    // A private, mutable build tree, cleaned up on every exit (a stale one from a crashed build is
    // cleared first). Keyed by pid so concurrent builds don't collide.
    let work = cache.join(format!(".build-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| Error::Sandbox(format!("build dir: {e}")))?;
    let result = build_run(args.quiet, tag, &ctx, &work, &instrs);
    remove_build_tree(&work); // overlay leaves mode-000 workdirs; force-clean so nothing leaks
    result
}

/// The build body — separated so [`build`] can always clean up the work tree, success or error.
///
/// Prefers a **layered** build: the base stays a shared read-only overlay lower, and RUN/COPY writes
/// accumulate in a persistent upper (the diff) — so the base is **never copied** (closing the
/// base-copy bottleneck). The image is stored as its diff + a `<tag>.base` marker, and
/// [`resolve_image`] stacks it back over the (re-resolvable) base at run. Where unprivileged overlay
/// isn't usable (probed once), it falls back to a **flat** build: copy the base, RUN over a bind
/// mount, store a full rootfs — exactly as before, at the cost of the base copy.
fn build_run(
    quiet: bool,
    tag: &str,
    ctx: &std::path::Path,
    work: &std::path::Path,
    instrs: &[crate::dockerfile::Instr],
) -> Result<(), Error> {
    use crate::dockerfile::Instr;
    let self_exe = std::env::current_exe()
        .map_err(|e| Error::Sandbox(format!("cannot locate the kern binary: {e}")))?;
    let total = instrs.len();

    // FROM is always the first instruction (the parser guarantees it). Resolve the base to an overlay
    // lower (a single dir, or a colon chain for a layered base).
    let Some(Instr::From(base_ref)) = instrs.first() else {
        return Err(Error::Sandbox("internal: build has no FROM".into()));
    };
    if !quiet {
        eprintln!("[1/{total}] FROM {base_ref}");
    }
    let (base_lower, base_cfg) = resolve_image(base_ref)?;
    let mut config = base_cfg;

    // Choose the build strategy: layered (overlay, no base copy) unless the user forces a flat build
    // (`KERN_BUILD_FLAT=1`, an escape hatch for a misbehaving overlay) or the probe says overlay
    // isn't usable here. A layered base can only be built on with overlay (cp can't duplicate a colon
    // chain), so require overlay in that case.
    let layered = std::env::var_os("KERN_BUILD_FLAT").is_none()
        && probe_overlay(&self_exe, &base_lower, work);
    if !layered && base_lower.contains(':') {
        return Err(Error::Sandbox(
            "cannot build FROM a layered image without unprivileged-overlay support on this kernel"
                .into(),
        ));
    }
    // Feedback-first: say which strategy ran, so a silent flat fallback (slower + a full base copy)
    // never looks like "layered but big".
    if !quiet {
        eprintln!(
            "  [{}]",
            if layered {
                "layered · base shared, no copy"
            } else {
                "flat · unprivileged overlay unavailable, copying the base"
            }
        );
    }
    // Layered mode: per-unit **cached** layers (each RUN batch / COPY / WORKDIR is a content-addressed
    // overlay layer reused on an unchanged rebuild). The flat fallback below has no per-layer cache.
    if layered {
        return build_layered_cached(quiet, tag, ctx, work, instrs, base_ref, &base_lower, config);
    }
    // From here on this is the FLAT fallback only (layered returned above). The whole image is a full
    // copy of the base that COPY/WORKDIR/RUN mutate in place; a bind-mounted box runs each RUN.
    let write_dir = work.join("rootfs");
    copy_tree(std::path::Path::new(&base_lower), &write_dir)?;
    // DNS for RUN: seed the host resolv.conf into the copied rootfs so apk/apt resolve; stripped
    // before finalize (if we created it) so the host's DNS servers aren't baked into the image.
    let seeded_resolv = seed_resolv_conf(&write_dir);

    let announce = |s: usize, what: String| {
        if !quiet {
            eprintln!("[{s}/{total}] {what}");
        }
    };
    let mut cmd_from_dockerfile = false;
    let mut i = 1; // instrs[0] is the FROM handled above
    while i < instrs.len() {
        let step = i + 1;
        match &instrs[i] {
            Instr::From(_) => i += 1, // only one FROM (parser-enforced); ignore any stray defensively
            Instr::Run(argv) => {
                // Batch CONSECUTIVE shell-form RUNs into ONE box, so the per-box overhead (fork+exec
                // + overlay mount) is paid once, not per step. Each original RUN still runs in its own
                // `/bin/sh -c` subshell, chained with `&&` (fail-fast, and Docker's per-RUN cwd reset).
                // An exec-form RUN (`RUN ["a","b"]`) or any non-RUN instruction ends the batch.
                let mut scripts: Vec<&str> = Vec::new();
                let mut j = i;
                while let Some(Instr::Run(a)) = instrs.get(j) {
                    match run_shell_script(a) {
                        Some(s) => {
                            announce(j + 1, format!("RUN {s}"));
                            scripts.push(s);
                            j += 1;
                        }
                        None => break,
                    }
                }
                let (run_argv, next) = if scripts.is_empty() {
                    announce(step, format!("RUN {}", display_run(argv))); // exec-form: run alone
                    (argv.clone(), i + 1)
                } else {
                    (combine_run_scripts(&scripts), j)
                };
                run_build_step(
                    &self_exe,
                    false, // flat fallback: bind-mount the copied rootfs
                    &base_lower,
                    work,
                    &write_dir,
                    &config,
                    &run_argv,
                    step,
                )?;
                i = next;
            }
            Instr::Copy { srcs, dst } => {
                announce(step, format!("COPY {} {dst}", srcs.join(" ")));
                // Copying multiple sources requires a directory destination (else each would clobber
                // the same name) — error rather than silently keep only the last, like Docker.
                if srcs.len() > 1
                    && !(dst.ends_with('/') || write_dir.join(dst.trim_start_matches('/')).is_dir())
                {
                    return Err(Error::Sandbox(format!(
                        "COPY with multiple sources needs a directory destination (end '{dst}' with '/')"
                    )));
                }
                for s in srcs {
                    copy_into_rootfs(ctx, s, &write_dir, dst, config.workdir.as_deref(), &[])?;
                }
                i += 1;
            }
            Instr::Env(k, v) => {
                set_config_env(&mut config.env, k, v);
                i += 1;
            }
            Instr::Workdir(d) => {
                let wd = resolve_workdir(config.workdir.as_deref(), d);
                mkdir_in_rootfs(&write_dir, &wd)?;
                config.workdir = Some(wd);
                i += 1;
            }
            Instr::User(u) => {
                config.user = Some(u.clone());
                i += 1;
            }
            Instr::Cmd(_) | Instr::Entrypoint(_) => {
                apply_cmd_entrypoint(&mut config, &instrs[i], &mut cmd_from_dockerfile);
                i += 1;
            }
            Instr::Expose(p) => {
                announce(
                    step,
                    format!("EXPOSE {p} (informational — publish with -p at run)"),
                );
                i += 1;
            }
        }
    }
    // Strip the resolv.conf we seeded so host DNS isn't baked in; leave a base's own untouched.
    if seeded_resolv {
        let _ = std::fs::remove_file(write_dir.join("etc/resolv.conf"));
    }

    // Finalize: commit the new form FIRST (clearing only THIS mode's prior target so the rename can
    // land), THEN drop the OTHER mode's stale artifacts and the sentinel — so a failed rename never
    // leaves the tag with neither the old nor the new image.
    let cache = cache_dir();
    let safe = sanitize_ref(tag);
    // Flat fallback (build_run is only reached when NOT layered — layered returns early above).
    let flat = cache.join(&safe);
    let _ = std::fs::remove_dir_all(&flat);
    std::fs::rename(&write_dir, &flat)
        .map_err(|e| Error::Sandbox(format!("finalize image '{tag}': {e}")))?;
    // Drop any stale LAYERED form of this tag (single-diff or multi-layer).
    let _ = std::fs::remove_dir_all(cache.join(format!("{safe}.diff")));
    let _ = std::fs::remove_file(cache.join(format!("{safe}.base")));
    let _ = std::fs::remove_file(cache.join(format!("{safe}.layers")));
    write_image_config(&cache.join(format!("{safe}.image")), &config);
    let _ = std::fs::write(cache.join(format!("{safe}.ok")), tag.as_bytes());
    println!("built '{tag}'");
    println!("  run: kern box myapp --image {tag}");
    Ok(())
}

/// Max bytes of the overlay `lowerdir=` chain — the mount-options buffer is ~one page (4 KiB); this
/// leaves headroom for `upperdir=`/`workdir=` so a long build/image chain fails with our clear error
/// instead of a cryptic kernel `EINVAL`.
const MAX_LOWERDIR_BYTES: usize = 3500;

/// Join an overlay lower `chain` (base first) into a `lowerdir=` string (TOP layer first, base last).
fn chain_lower(chain: &[String]) -> String {
    chain.iter().rev().cloned().collect::<Vec<_>>().join(":")
}

/// Layered build with a Docker-style **per-unit layer cache**. Each unit — a batched RUN, a COPY, a
/// WORKDIR — is a content-addressed overlay layer keyed by the running chain key (which folds in the
/// previous key + the instruction + its context: ENV/WORKDIR/USER for RUN, the copied file contents
/// for COPY). An unchanged unit is a **cache hit** → its cached layer is stacked as a lower and the
/// unit is NOT re-executed; the first changed unit (and everything after) is a miss and re-runs.
/// Config-only instructions produce no layer: ENV/USER advance the key (they change a later RUN's
/// output), but CMD/ENTRYPOINT/EXPOSE do NOT (they only set config, never the filesystem). The tag
/// stores its base ref + ordered layer keys (`<tag>.layers`); [`resolve_image`] stacks them at run.
#[allow(clippy::too_many_arguments)]
fn build_layered_cached(
    quiet: bool,
    tag: &str,
    ctx: &std::path::Path,
    work: &std::path::Path,
    instrs: &[crate::dockerfile::Instr],
    base_ref: &str,
    base_lower: &str,
    mut config: kern_oci::ImageConfig,
) -> Result<(), Error> {
    use crate::dockerfile::Instr;
    let self_exe = std::env::current_exe()
        .map_err(|e| Error::Sandbox(format!("cannot locate the kern binary: {e}")))?;
    let lc = layer_cache_dir();
    own_only_dir(&lc).map_err(|e| Error::Sandbox(format!("layer cache: {e}")))?;
    let total = instrs.len();
    let announce = |s: usize, what: String| {
        if !quiet {
            eprintln!("[{s}/{total}] {what}");
        }
    };
    // Overlay lower chain (base first); a layer dir is appended per fs-unit. `key` is the running
    // chained key; `layer_keys` are the produced layers in order (→ the tag's `.layers` manifest).
    let mut chain: Vec<String> = vec![base_lower.to_string()];
    // Seed the chain key from the RESOLVED base lower (content-addressed for a locally-built base:
    // its colon-chain of layer keys), not just the ref string — so rebuilding the base busts a child.
    let mut key = layer_key("", base_lower);
    let mut layer_keys: Vec<String> = Vec::new();
    let mut cmd_from_dockerfile = false;
    let mut unit = 0usize;
    let mut i = 1;
    while i < instrs.len() {
        // The overlay `lowerdir=` string (all layers + base) must fit ~one kernel page. Stop with a
        // clear message BEFORE the chain overflows and the mount fails with a cryptic EINVAL.
        if chain_lower(&chain).len() > MAX_LOWERDIR_BYTES {
            return Err(Error::Sandbox(
                "build has too many layers to overlay — squash consecutive RUN/COPY steps or reduce \
                 the number of instructions"
                    .into(),
            ));
        }
        let step = i + 1;
        match &instrs[i] {
            Instr::From(_) => i += 1,
            Instr::Run(argv) => {
                // Batch consecutive shell-form RUNs (one box + one cache unit); an exec-form RUN or a
                // non-RUN ends the batch.
                let mut scripts: Vec<&str> = Vec::new();
                let mut j = i;
                while let Some(Instr::Run(a)) = instrs.get(j) {
                    match run_shell_script(a) {
                        Some(s) => {
                            scripts.push(s);
                            j += 1;
                        }
                        None => break,
                    }
                }
                let (run_argv, next, body) = if scripts.is_empty() {
                    (argv.clone(), i + 1, argv.join("\u{0}"))
                } else {
                    (combine_run_scripts(&scripts), j, scripts.join("\u{0}"))
                };
                // The key folds in the ENV/WORKDIR/USER the box runs with (they change the result).
                key = layer_key(
                    &key,
                    &format!(
                        "RUN\u{0}{body}\u{0}ENV\u{0}{}\u{0}WD\u{0}{}\u{0}U\u{0}{}",
                        config.env.join("\u{1}"),
                        config.workdir.as_deref().unwrap_or(""),
                        config.user.as_deref().unwrap_or(""),
                    ),
                );
                let hit = layer_cached(&lc, &key);
                let mark = if hit { " (cached)" } else { "" };
                if scripts.is_empty() {
                    announce(step, format!("RUN {}{mark}", display_run(argv)));
                } else {
                    for (k, s) in scripts.iter().enumerate() {
                        announce(i + 1 + k, format!("RUN {s}{mark}"));
                    }
                }
                if !hit {
                    let fresh = work.join(format!("u{unit}"));
                    let _ = std::fs::remove_dir_all(&fresh);
                    run_build_step(
                        &self_exe,
                        true,
                        &chain_lower(&chain),
                        &fresh,
                        &fresh,
                        &config,
                        &run_argv,
                        step,
                    )?;
                    let content = build_upper_dir(&fresh);
                    let _ = std::fs::remove_file(content.join("etc/resolv.conf")); // no host DNS baked in
                    commit_layer(&content, &lc, &key)?;
                    unit += 1;
                }
                chain.push(lc.join(&key).to_string_lossy().into_owned());
                layer_keys.push(key.clone());
                i = next;
            }
            Instr::Copy { srcs, dst } => {
                let content: Vec<String> =
                    srcs.iter().map(|s| content_hash(&ctx.join(s))).collect();
                key = layer_key(
                    &key,
                    &format!(
                        "COPY\u{0}{dst}\u{0}WD\u{0}{}\u{0}{}",
                        config.workdir.as_deref().unwrap_or(""),
                        content.join(","),
                    ),
                );
                let hit = layer_cached(&lc, &key);
                announce(
                    step,
                    format!(
                        "COPY {} {dst}{}",
                        srcs.join(" "),
                        if hit { " (cached)" } else { "" }
                    ),
                );
                if !hit {
                    let fresh = work.join(format!("u{unit}"));
                    let _ = std::fs::remove_dir_all(&fresh);
                    own_only_dir(&fresh)
                        .map_err(|e| Error::Sandbox(format!("build layer: {e}")))?;
                    if srcs.len() > 1
                        && !(dst.ends_with('/')
                            || chain_has_dir(&chain, dst.trim_start_matches('/')))
                    {
                        return Err(Error::Sandbox(format!(
                            "COPY with multiple sources needs a directory destination (end '{dst}' with '/')"
                        )));
                    }
                    for s in srcs {
                        copy_into_rootfs(ctx, s, &fresh, dst, config.workdir.as_deref(), &chain)?;
                    }
                    commit_layer(&fresh, &lc, &key)?;
                    unit += 1;
                }
                chain.push(lc.join(&key).to_string_lossy().into_owned());
                layer_keys.push(key.clone());
                i += 1;
            }
            Instr::Workdir(d) => {
                let wd = resolve_workdir(config.workdir.as_deref(), d);
                key = layer_key(&key, &format!("WD\u{0}{wd}"));
                let hit = layer_cached(&lc, &key);
                announce(
                    step,
                    format!("WORKDIR {wd}{}", if hit { " (cached)" } else { "" }),
                );
                if !hit {
                    let fresh = work.join(format!("u{unit}"));
                    let _ = std::fs::remove_dir_all(&fresh);
                    own_only_dir(&fresh)
                        .map_err(|e| Error::Sandbox(format!("build layer: {e}")))?;
                    mkdir_in_rootfs(&fresh, &wd)?;
                    commit_layer(&fresh, &lc, &key)?;
                    unit += 1;
                }
                chain.push(lc.join(&key).to_string_lossy().into_owned());
                layer_keys.push(key.clone());
                config.workdir = Some(wd);
                i += 1;
            }
            Instr::Env(k, v) => {
                set_config_env(&mut config.env, k, v);
                key = layer_key(&key, &format!("ENV\u{0}{k}={v}"));
                i += 1;
            }
            Instr::User(u) => {
                config.user = Some(u.clone());
                key = layer_key(&key, &format!("USER\u{0}{u}"));
                i += 1;
            }
            // CMD/ENTRYPOINT/EXPOSE change only the image CONFIG, never the filesystem — they persist
            // via `config`/`.image` and are reapplied on resolve. So they do NOT advance the layer key
            // (editing a CMD must not bust the cached RUN/COPY layers). ENV/USER above DO advance it,
            // because they change a subsequent RUN's output.
            Instr::Cmd(_) | Instr::Entrypoint(_) => {
                apply_cmd_entrypoint(&mut config, &instrs[i], &mut cmd_from_dockerfile);
                i += 1;
            }
            Instr::Expose(p) => {
                announce(
                    step,
                    format!("EXPOSE {p} (informational — publish with -p at run)"),
                );
                i += 1;
            }
        }
    }
    // Finalize: write the tag's layer manifest (base ref + ordered layer keys) + config sidecar +
    // sentinel; clear any prior form of this tag (flat dir, old .diff/.base) first.
    let cache = cache_dir();
    let safe = sanitize_ref(tag);
    let mut manifest = String::from(base_ref);
    manifest.push('\n');
    for k in &layer_keys {
        manifest.push_str(k);
        manifest.push('\n');
    }
    let _ = std::fs::remove_dir_all(cache.join(&safe));
    let _ = std::fs::remove_dir_all(cache.join(format!("{safe}.diff")));
    let _ = std::fs::remove_file(cache.join(format!("{safe}.base")));
    std::fs::write(cache.join(format!("{safe}.layers")), manifest)
        .map_err(|e| Error::Sandbox(format!("finalize image '{tag}': {e}")))?;
    write_image_config(&cache.join(format!("{safe}.image")), &config);
    let _ = std::fs::write(cache.join(format!("{safe}.ok")), tag.as_bytes());
    println!("built '{tag}'");
    println!("  run: kern box myapp --image {tag}");
    Ok(())
}

/// The persistent overlay upper dir under a `kern build` work/`--overlay-upper` root — the ONE place
/// this layout convention lives, shared by [`build_run`] (writes COPY/WORKDIR here) and [`build_spec`]
/// (mounts it as the RUN box's overlay upperdir) so the two can't silently desync.
fn build_upper_dir(overlay_root: &std::path::Path) -> PathBuf {
    overlay_root.join("upper")
}

/// Remove a build work tree. overlayfs leaves its workdir's inner `work/` at mode `000`, which a
/// plain `remove_dir_all` can't traverse (→ a leaked `.build-*` dir on disk). We own every entry, so
/// chmod each directory back to `0700` before recursing, then remove.
fn remove_build_tree(path: &std::path::Path) {
    fn chmod_dirs(p: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    chmod_dirs(&e.path());
                }
            }
        }
    }
    chmod_dirs(path);
    let _ = std::fs::remove_dir_all(path);
}

/// Probe whether an unprivileged overlay with a persistent upper actually mounts on this kernel (a
/// tiny `true`-box over `base_lower`). Decides layered-vs-flat build up front. Best-effort; any
/// failure → `false` → the flat copy path.
fn probe_overlay(self_exe: &std::path::Path, base_lower: &str, work: &std::path::Path) -> bool {
    let probe = work.join(".probe");
    let ok = std::process::Command::new(self_exe)
        .env("KERN_BUILD_STEP", "1") // no transient scope for the throwaway probe box
        .arg("box")
        .arg(format!("_probe-{}", std::process::id()))
        .arg("--overlay-lower")
        .arg(base_lower)
        .arg("--overlay-upper")
        .arg(&probe)
        .arg("--quiet")
        .arg("--")
        .arg("true")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    remove_build_tree(&probe); // the probe leaves a mode-000 overlay workdir too
    ok
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
        // failing sub-step's own stderr already appeared above — enough to see which step failed.
        return Err(Error::Sandbox(format!(
            "RUN failed (exit {}): {}",
            status.code().unwrap_or(-1),
            display_run(argv)
        )));
    }
    Ok(())
}

/// `cp -a src/. dst` — copy the CONTENTS of `src` into the existing `dst`, preserving symlinks,
/// modes and timestamps (used to make a mutable copy of the pulled base rootfs).
fn copy_tree(src: &std::path::Path, dst: &std::path::Path) -> Result<(), Error> {
    std::fs::create_dir_all(dst).map_err(|e| Error::Sandbox(format!("build rootfs: {e}")))?;
    let ok = std::process::Command::new("cp")
        .arg("-a")
        .arg("--reflink=auto") // copy-on-write clone on btrfs/xfs (near-free); plain copy elsewhere
        .arg("--") // paths are absolute, but stop cp treating any of them as a flag
        .arg(format!("{}/.", src.display()))
        .arg(dst)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(Error::Sandbox(
            "copying the base rootfs failed (is `cp` available?)".into(),
        ))
    }
}

/// Copy `src_rel` (relative to the build context) into the build `rootfs` at `dst`, refusing to
/// escape the context (source) or traverse a symlinked component of the image (destination). A
/// relative `dst` (e.g. `COPY x .`) resolves against the current `workdir` (Docker semantics).
fn copy_into_rootfs(
    ctx: &std::path::Path,
    src_rel: &str,
    rootfs: &std::path::Path,
    dst: &str,
    workdir: Option<&str>,
    chain: &[String],
) -> Result<(), Error> {
    // Source must resolve to a real path INSIDE the context (no `../`, no symlink pointing out).
    let src = std::fs::canonicalize(ctx.join(src_rel))
        .map_err(|e| Error::Sandbox(format!("COPY source '{src_rel}': {e}")))?;
    if !src.starts_with(ctx) {
        return Err(Error::Sandbox(format!(
            "COPY source '{src_rel}' escapes the build context"
        )));
    }
    // A relative destination is taken against the current WORKDIR (default `/`).
    let dst_abs = if dst.starts_with('/') {
        dst.to_string()
    } else {
        format!("{}/{}", workdir.unwrap_or("/").trim_end_matches('/'), dst)
    };
    // Destination: if it names (or ends like) a directory, copy INTO it under the source basename.
    // `rootfs` is this unit's fresh (empty) layer, so a dir that exists only in a LOWER layer is
    // found via `chain` (the cached-layer build); the flat build passes an empty chain.
    let dst_clean = dst_abs.trim_start_matches('/');
    let dst_is_dir =
        dst.ends_with('/') || rootfs.join(dst_clean).is_dir() || chain_has_dir(chain, dst_clean);
    let target_rel = if dst_is_dir {
        let base = src
            .file_name()
            .ok_or(Error::Sandbox("COPY source has no file name".into()))?;
        format!(
            "{}/{}",
            dst_clean.trim_end_matches('/'),
            base.to_string_lossy()
        )
    } else {
        dst_clean.to_string()
    };
    // Reject `..` (and re-strip any leading `/` the dir-branch reintroduced): a `..` component is a
    // real directory, so `whiteout_dir_symlink_free` (symlinks only) waves it through, and
    // `rootfs.join(..)` / `cp` would then escape the rootfs to write anywhere on the host.
    let target_rel = sanitize_rootfs_rel(dst, &target_rel)?;
    // No symlinked component in the target's parent may lead out of the rootfs (image could plant
    // `dst -> /host`). Then create the parents as REAL dirs and copy.
    let parent_rel = std::path::Path::new(&target_rel)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !kern_oci::whiteout_dir_symlink_free(&rootfs.to_string_lossy(), &parent_rel) {
        return Err(Error::Sandbox(format!(
            "COPY dest '{dst}' crosses a symlink in the image"
        )));
    }
    let target = rootfs.join(&target_rel);
    if let Some(p) = target.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    // If the target itself is an existing symlink, unlink it so we don't copy THROUGH it out of the
    // rootfs (COPY overwrites the name, following Docker).
    if let Ok(m) = std::fs::symlink_metadata(&target) {
        if m.file_type().is_symlink() {
            let _ = std::fs::remove_file(&target);
        }
    }
    let arg = if src.is_dir() {
        let _ = std::fs::create_dir_all(&target);
        format!("{}/.", src.display())
    } else {
        src.to_string_lossy().into_owned()
    };
    // SECURITY INVARIANT (do not break): `cp -a` implies `--no-dereference` — it PRESERVES symlinks in
    // the copied tree rather than following them. This is load-bearing for the build-context confinement
    // (the "duale-di-Z2" note in `resolve_builds`): the COPY source root is confined by canonicalize +
    // starts_with, and because the recursive descent here does NOT follow inner symlinks, a symlink
    // buried in the context lands in the image verbatim (dangling in the pivoted rootfs) and its host
    // target is never read at build time. If this `cp -a` is ever replaced (e.g. a Rust `walkdir` copy
    // for portability), that replacement MUST be no-follow too, or a `leak -> /host/secret` inside a
    // build context would leak the host file into the image. Verified live: it does not, today.
    let ok = std::process::Command::new("cp")
        .arg("-a")
        .arg("--") // src/target are absolute, but never let cp parse them as flags
        .arg(&arg)
        .arg(&target)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(Error::Sandbox(format!("COPY '{src_rel}' → '{dst}' failed")))
    }
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

/// Apply a CMD or ENTRYPOINT instruction to the image config — the ONE place the Docker rule
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

/// Turn an in-image path into a rootfs-relative one that CANNOT escape: strip leading `/`, then
/// reject any `..` component. `..` is a real directory, so the symlink-only
/// [`kern_oci::whiteout_dir_symlink_free`] guard doesn't catch it; without this a `COPY`/`WORKDIR`
/// dest of `../../etc/…` would let `cp`/`create_dir_all` write outside the rootfs onto the host.
fn sanitize_rootfs_rel(orig: &str, rel: &str) -> Result<String, Error> {
    let rel = rel.trim_start_matches('/');
    if std::path::Path::new(rel)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Error::Build(format!(
            "'{orig}' escapes the image rootfs (`..`)"
        )));
    }
    Ok(rel.to_string())
}

/// `mkdir -p` a workdir inside the rootfs, refusing a `..` escape or a symlinked component that
/// leads out.
fn mkdir_in_rootfs(rootfs: &std::path::Path, dir: &str) -> Result<(), Error> {
    let rel = sanitize_rootfs_rel(dir, dir)?;
    if !kern_oci::whiteout_dir_symlink_free(&rootfs.to_string_lossy(), &rel) {
        return Err(Error::Sandbox(format!(
            "WORKDIR '{dir}' crosses a symlink in the image"
        )));
    }
    let _ = std::fs::create_dir_all(rootfs.join(&rel));
    Ok(())
}

/// Seed `/etc/resolv.conf` in the build rootfs from the host so RUN steps can resolve DNS over the
/// shared network namespace. Returns `true` if it CREATED the file (the base had none) so the caller
/// can remove it before finalizing — we don't want the host's DNS servers baked into the image
/// (Docker provides resolv.conf only at runtime). Best-effort; a base that ships its own is left be.
fn seed_resolv_conf(rootfs: &std::path::Path) -> bool {
    let dst = rootfs.join("etc/resolv.conf");
    if dst.exists() {
        return false; // base image already has one — leave it, don't touch/remove it
    }
    if let Ok(rc) = std::fs::read("/etc/resolv.conf") {
        let _ = std::fs::create_dir_all(rootfs.join("etc"));
        if std::fs::write(&dst, rc).is_ok() {
            return true;
        }
    }
    false
}

/// The shell script of a shell-form RUN (`["/bin/sh","-c",<script>]`), or `None` for an exec-form
/// RUN — only shell-form RUNs are safe to batch into one box.
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

/// Per-box writable overlay scratch (upper/work) — placed on **tmpfs** where possible
/// (`$XDG_RUNTIME_DIR` → `/run/user/<uid>`, both tmpfs), else `/tmp`. tmpfs makes the create /
/// overlay-mount / cleanup RAM-fast and keeps the writable layer ephemeral; its pages count
/// against the box's memory cap. Created mode 0700 by the caller.
fn scratch_dir() -> PathBuf {
    if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(x).join("kern/scratch");
    }
    let uid = unsafe { libc::getuid() };
    let run = PathBuf::from(format!("/run/user/{uid}"));
    if run.is_dir() {
        return run.join("kern/scratch");
    }
    PathBuf::from(format!("/tmp/kern-{uid}/scratch"))
}

/// `kern stop <name>... | --all` — stop running box(es): SIGKILL each target supervisor's process
/// group (tearing down the box's PID namespace), drop its registry entry, and remove its writable
/// scratch. Stops every name in `names` (a name may match more than one box if names ever collide),
/// or — with `all` — every running box. A requested name that isn't running is reported on stderr
/// (never silently ignored); the command succeeds as long as at least one box was stopped.
pub fn stop(names: &[String], all: bool) -> Result<(), Error> {
    let dir = registry::dir().map_err(|e| Error::Sandbox(format!("registry: {e}")))?;
    let running = registry::list();
    let targets: Vec<_> = if all {
        running
    } else {
        running
            .into_iter()
            .filter(|b| names.iter().any(|n| n == &b.name))
            .collect()
    };
    // A persistent (`--restart always`) box is supervised by systemd and may be momentarily down
    // between restarts — not in the registry, but its unit still exists and would resurrect it at
    // reboot. Collect those so stop reliably removes them too: for explicit names, the requested
    // ones; for `--all`, every `kern-*.service` in the user unit dir not already a live target.
    let managed_only: Vec<String> = if all {
        user_systemd_dir()
            .ok()
            .and_then(|d| std::fs::read_dir(d).ok())
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter_map(|f| {
                Some(
                    f.strip_prefix("kern-")?
                        .strip_suffix(".service")?
                        .to_string(),
                )
            })
            .filter(|n| !targets.iter().any(|b| &b.name == n))
            .collect()
    } else {
        names
            .iter()
            .filter(|n| !targets.iter().any(|b| &b.name == *n))
            .filter(|n| managed_unit_path(n).is_some_and(|p| p.exists()))
            .cloned()
            .collect()
    };
    if targets.is_empty() && managed_only.is_empty() {
        return Err(Error::NotRunning(if all {
            "no running boxes to stop".to_string()
        } else {
            let listed = names
                .iter()
                .map(|n| format!("'{n}'"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("no running box named {listed}")
        }));
    }
    for b in &targets {
        // A persistent box: tell systemd to stop AND disable the unit (so it neither restarts now
        // nor comes back at reboot), then remove it. Killing the process instead would just trip
        // systemd's `Restart=always`. Otherwise: the supervisor `setsid`-ed, so its pgid == its pid.
        if !stop_managed_unit(&b.name) {
            unsafe { libc::kill(-b.pid, libc::SIGKILL) };
        }
        let _ = std::fs::remove_file(dir.join(format!("{}-{}", b.name, b.pid)));
        registry::clear_health(&b.name, b.pid); // a kill/SIGTERM skips the supervisor's own cleanup
        cleanup_box_scratch(&b.rootfs);
        println!("stopped '{}' (pid {})", b.name, b.pid);
    }
    for n in &managed_only {
        stop_managed_unit(n);
        println!("stopped '{n}' (systemd-managed)");
    }
    // Don't silently ignore names that matched no running box (and no managed unit).
    if !all {
        for n in names {
            if !targets.iter().any(|b| &b.name == n) && !managed_only.contains(n) {
                eprintln!("kern: no running box named '{n}'");
            }
        }
    }
    Ok(())
}

/// The systemd unit file name for a persistent box — the naming convention lives here only.
fn unit_file_name(name: &str) -> String {
    format!("kern-{name}.service")
}

/// Path of the systemd user unit for a persistent box named `name` (if the user's systemd dir is
/// resolvable). Existence of this file is what marks a box as systemd-managed. Returns `None` for a
/// name that isn't a valid box name — `kern stop <name>` takes raw, unvalidated names, and a `../`
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
    if !path.exists() {
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

/// `kern pause <name>...` / `kern unpause <name>...` — freeze / thaw a running box via the cgroup v2
/// **freezer** (`cgroup.freeze`), which suspends every process in the box's cgroup atomically (no
/// signal races, and a paused box can't be woken by `SIGCONT` from inside). Needs the box to have a
/// dedicated cgroup (a `systemd --user` scope, the default when present); without one there's nothing
/// to freeze and we say so rather than pretend. `freeze=true` pauses, `false` resumes.
pub fn pause(names: &[String], all: bool, freeze: bool) -> Result<(), Error> {
    let verb = if freeze { "pause" } else { "unpause" };
    let running = registry::list();
    let targets: Vec<_> = if all {
        running
    } else {
        running
            .into_iter()
            .filter(|b| names.iter().any(|n| n == &b.name))
            .collect()
    };
    if targets.is_empty() {
        return Err(Error::NotRunning(format!("no running box to {verb}")));
    }
    for b in &targets {
        match registry::box_cgroup(b.pid) {
            Some(cg) => {
                let path = cg.join("cgroup.freeze");
                match std::fs::write(&path, if freeze { "1" } else { "0" }) {
                    Ok(()) => println!("{}d '{}' (pid {})", verb, b.name, b.pid),
                    Err(e) => eprintln!("kern: cannot {verb} '{}': {e}", b.name),
                }
            }
            None => eprintln!(
                "kern: cannot {verb} '{}' — the box has no dedicated cgroup (needs a systemd --user \
                 scope; pause/unpause is a cgroup-freezer operation)",
                b.name
            ),
        }
    }
    if !all {
        for n in names {
            if !targets.iter().any(|b| &b.name == n) {
                eprintln!("kern: no running box named '{n}'");
            }
        }
    }
    Ok(())
}

/// Remove the overlay scratch behind a box, derived from its merge path
/// (`<cache>/scratch/<name>-<pid>/merged`).
fn cleanup_box_scratch(rootfs: &str) {
    let p = std::path::Path::new(rootfs);
    if p.file_name().is_none_or(|n| n != "merged") {
        return;
    }
    let Some(scratch) = p.parent() else { return };
    // CONFINEMENT (the ranged fallback below runs a privileged newuidmap'd remove_dir_all, so the path
    // must be provably ours): require `scratch`'s parent to be kern's own scratch root — not a weak
    // `.contains("/scratch/")` (which `/tmp/scratch/../../etc` would pass). Canonicalize both sides so
    // no `..`/symlink in the registry-derived rootfs can steer the remove outside kern's scratch tree.
    let root = scratch_dir();
    let canon_root = std::fs::canonicalize(&root).unwrap_or(root);
    let parent_ok = scratch.parent().is_some_and(|par| {
        std::fs::canonicalize(par)
            .map(|c| c == canon_root)
            .unwrap_or(false)
    });
    if !parent_ok {
        return;
    }
    // Route through cleanup_scratch's ranged fallback: a `--uid-range`/pod box whose image dropped
    // privilege leaves subordinate-uid-owned files (e.g. grafana's /var/lib/grafana owned by subuid
    // 100471) that a plain remove_dir_all can't unlink from the host — the fallback retries inside a
    // newuidmap'd user ns where they're removable.
    cleanup_scratch(Some(scratch));
}

/// How long `compose up` waits for a `depends_healthy` / `depends_completed` condition before it
/// gives up and aborts the bring-up. Docker's default `--wait` has no ceiling; we cap it so a stuck
/// dependency fails loudly instead of hanging a scripted `up` forever. Generous enough for a cold
/// database (postgres init + first health pass is a few seconds).
const COMPOSE_CONDITION_TIMEOUT_SECS: u64 = 120;

/// The exit-sidecar key for a box: `<pod>-<token>-<name>`. `<pod>` namespaces by STACK (two stacks
/// with a `db` don't collide — review 1b); `<token>` namespaces by this `up`'s RUN (two concurrent
/// `up`s of the SAME stack own separate files, so one's clear/write can't clobber the other's real
/// completion — review round 2, the round-1 "token only inside the file" left the filename shared).
/// `compose_pod_name(file)` is stable per compose file even for a `--no-pod` stack (no live pod), so
/// the prefix is well-defined in both modes. `compose down` doesn't know the `up`'s token, so it reaps
/// each box's sidecar by `exit_key_prefix(pod)` ++ `-<name>` (pod-prefix AND name-suffix) — NOT a
/// blind pod prefix, which would wipe a concurrent same-stack run's in-flight files.
fn exit_key(pod: &str, token: &str, name: &str) -> String {
    format!("{pod}-{token}-{name}")
}

/// The `<pod>-` prefix shared by every exit key of a stack — the LEADING anchor for `compose down`'s
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
    let compose_dir = std::path::Path::new(file)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let base = std::fs::canonicalize(&compose_dir).map_err(|e| {
        Error::Compose(format!(
            "resolving compose dir '{}': {e}",
            compose_dir.display()
        ))
    })?;

    for b in boxes.iter_mut() {
        let Some(bd) = b.build.clone() else { continue };
        // Guard 1 — CONFINE context under the compose dir. Canonicalize `base/context` and require the
        // result stays beneath `base`, so a `context: ../../../etc` in a third-party compose can't
        // escape the project tree. (Same traversal class as image/volume/pod names in the saga.)
        // NOTE (duale-di-Z2): confining the context ROOT here is not enough on its own — `kern build`
        // then DESCENDS the context (COPY). That descent is itself confined: `copy_into_rootfs`
        // canonicalizes each COPY source and requires `starts_with(ctx)` (a source symlink pointing out
        // is rejected), and `cp -a` PRESERVES inner symlinks rather than following them (so a symlink
        // buried in the tree lands in the image verbatim — dangling inside the pivoted rootfs — never
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
        // Guard 1 (dockerfile) — if given, confine it under the CONTEXT (Docker resolves `dockerfile`
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

        // Guard 4 — `image:` + `build:` = build AND tag as `image`; `build:` alone → synthesized tag.
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
        // Guard 3 — a build failure fails the whole `up` with a linked, service-named message.
        let status = cmd.status().map_err(|e| {
            Error::Compose(format!("service '{}': running `kern build`: {e}", b.name))
        })?;
        if !status.success() {
            return Err(Error::Compose(format!(
                "service '{}': build failed — run `kern build -t {tag} {}` to see why",
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
///   * `depends_healthy` on a box with no `health_cmd` — it can never report healthy.
///
/// NOTE on `depends_completed` + `restart`: the review suggested rejecting it, but in kern's compose
/// `restart = true` means ON-FAILURE (a bare `--restart`), NOT always-respawn — the supervisor re-runs
/// the box ONLY on a non-zero exit. So a `depends_completed` target that exits 0 completes normally,
/// and one that keeps failing crash-loops to the restart cap and then records its final non-zero exit,
/// which fails the wait cleanly. `restart = true` + `depends_completed` is therefore COHERENT, not
/// impossible — we must NOT reject it. (Were compose ever to gain an `always`/`unless-stopped` policy,
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
/// box machinery already writes — no IPC of our own. Polled at 100 ms so a fast dep adds only a
/// sub-100 ms tail, not Docker's whole-second-per-health-interval granularity.
///
/// A dependency that DIES before satisfying its condition aborts immediately (adversarial-review 2a) —
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
            // Dead before healthy — decided; don't wait out the timeout. Prefer the POSITIVE death
            // signal (a written exit sidecar) over the prune-timing one (absence from `list()`): a box
            // targeted by a `depends_completed` writes its exit on death, so a completion sidecar for
            // this dep is proof it's gone. Fall back to registry liveness for a dep that ISN'T a
            // completion target (no sidecar), where absence-from-`list()` is the only death signal —
            // there the timeout backstops the ≤1-poll prune lag (review 2a).
            let died = registry::exit_of(&key_of(dep)).is_some() || !is_box_alive(dep);
            if died {
                return Err(Error::Compose(format!(
                    "box '{}': dependency '{dep}' exited before becoming healthy — run `kern logs \
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
                    "box '{}': dependency '{dep}' did not complete successfully (exit {code}) — \
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

/// A running box's current health status by NAME (`healthy`/`unhealthy`/`starting`/empty). The
/// sidecar is keyed `name-pid`, so resolve the pid via the registry first; a box that has already
/// left the registry reads as empty (which the caller treats as "not yet healthy").
fn current_health(name: &str) -> String {
    registry::list()
        .into_iter()
        .find(|i| i.name == name)
        .map(|i| registry::health_of(name, i.pid))
        .unwrap_or_default()
}

/// Is a box with this name currently in the registry (i.e. still running)? `list()` prunes dead
/// entries, so presence == alive. Used to fail a `depends_healthy` wait fast when the dep has died.
fn is_box_alive(name: &str) -> bool {
    registry::list().iter().any(|i| i.name == name)
}

/// `kern compose <file>` — bring up a stack of boxes (detached) in `depends_on` order. Each
/// service is launched via a fresh `kern box -d` subprocess, so it gets its own scope + registry
/// entry; track the stack with `kern ps`.
pub fn compose(file: &str, down: bool, no_pod: bool) -> Result<(), Error> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| Error::Compose(format!("reading {file}: {e}")))?;
    let mut boxes = crate::compose::parse(&text).map_err(Error::Compose)?;
    // The stack's pod is named after the compose file (Docker's project-name idea) — one shared
    // network so services reach each other by name.
    let pod = compose_pod_name(file);

    // `compose down`: stop every box in the stack, then tear the pod down QUIETLY (we just stopped
    // the members, so `pod::remove`'s "members keep running" note would contradict this).
    if down {
        let names: Vec<String> = boxes.iter().map(|b| b.name.clone()).collect();
        let _ = stop(&names, false); // best-effort — some may already be gone
                                     // Reap this stack's exit sidecars. Keys are `<pod>-<token>-<name>`; `down` doesn't know the
                                     // `up`'s token, so it clears `<pod>-*-<name>` per box it stopped — NOT a blind `<pod>-*` (that
                                     // would wipe a concurrent same-stack run's OTHER boxes). There's no shared state-file and no
                                     // read-modify-write, so no lost-update: each `remove_file` is atomic and ENOENT-safe, so two
                                     // concurrent `down`s just no-op over each other.
                                     //
                                     // The one race left by pure name-scoping: `down A` stops A's `migrate`, then a concurrent
                                     // `up B` re-creates a `migrate` box (allowed once A's is gone), then A's reap fires and would
                                     // delete B's fresh `<pod>-<tokenB>-migrate`. Close it BY CONSTRUCTION: reap a box's sidecars
                                     // ONLY if that box is no longer alive. If B brought `migrate` back, it's alive again → we skip
                                     // it → B's sidecar survives. `down` legitimately reaps only what it actually tore down.
        for n in &names {
            if !is_box_alive(n) {
                registry::clear_exit_matching(&exit_key_prefix(&pod), &format!("-{n}"));
            }
        }
        let (pod_existed, _) = crate::pod::teardown(&pod);
        // Only claim the pod was removed if one actually existed (a `--no-pod` stack has none).
        if pod_existed {
            println!(
                "compose down: {} box(es) stopped, pod '{pod}' removed",
                names.len()
            );
        } else {
            println!("compose down: {} box(es) stopped", names.len());
        }
        return Ok(());
    }

    let order = crate::compose::topo_order(&boxes).map_err(Error::Compose)?;
    // Static rejection of conditions that can NEVER be satisfied — caught here, not left to time out
    // at runtime (adversarial-review 2d). `topo_order` above already rejects cycles and unknown deps.
    validate_conditions(&boxes)?;
    let self_exe =
        std::env::current_exe().map_err(|e| Error::Compose(format!("locating kern: {e}")))?;

    // Compose `build:` — build each service's image via `kern build` BEFORE the launch loop, so a box
    // with `build:` gets a real image to run. Four hardenings the adversarial review demanded, because
    // `build:` is the first place the YAML parser drives a privileged operation on host paths:
    //  1. `context`/`dockerfile` are CONFINED under the compose file's directory (traversal guard).
    //  2. `build.args` are already `${VAR}`-interpolated by the parser (never literal `${VAR}`).
    //  3. a build failure fails the WHOLE `up` with a linked message ("service X: build failed …"),
    //     since a box whose image never built can't start (and its depends_completed/healthy peers
    //     would hang) — fail-fast beats a half-up stack.
    //  4. `image:` + `build:` together = build AND tag as `image` (compose semantics); a `build:` with
    //     no `image:` gets a synthesized tag. We never silently use a stale registry image for a box
    //     the user meant to build locally.
    resolve_builds(&mut boxes, file, &self_exe)?;
    // Docker resolves a RELATIVE bind source (`./certs:/dst`, `.:/app`) against the compose file's
    // directory. kern's `-v` needs an absolute path or a named volume, so rewrite relative binds here
    // to absolute (confined under the compose dir — traversal guard, like a build context). A `named:`
    // source or an already-absolute `/host:/dst` passes through untouched.
    resolve_relative_binds(&mut boxes, file)?;

    // A fresh epoch token for THIS `up`. Stamped into every `depends_completed` target's exit sidecar
    // and required to match on read, so a sidecar left by a previous `up` of the same stack can't
    // satisfy this run's wait (adversarial-review 1a). Uniqueness only needs to hold within this
    // process's lifetime; our pid + a monotonic-ish clock read is plenty and needs no rng/new deps.
    let up_token = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );

    // Auto-pod: a multi-service stack gets a shared network (name resolution + outbound) unless the
    // user opts out or every box already shares the host net (`--net`). Reuse an existing pod so
    // `up` is idempotent.
    let use_pod = !no_pod && boxes.len() >= 2 && boxes.iter().any(|b| !b.net);
    if use_pod && crate::pod::holder_pid(&pod).is_none() {
        // Map a uid RANGE into the pod's shared user ns when ANY member needs it: an OCI-image box
        // (official images drop privilege in their entrypoint) OR a box that explicitly set
        // `uid_range = true`. A pod member setns's into the holder's user ns and writes NO map of its
        // own, so the holder's map is authoritative — `--uid-range` on the member alone is a no-op. This
        // MUST match `push_box_flags`'s per-box rule exactly (`uid_range || image-and-not-opted-out`),
        // decided HERE, before the holder is created (it writes its map at unshare). A pod of only
        // single-uid rootfs services stays single-uid (faster).
        let pod_needs_range = boxes
            .iter()
            .any(|b| b.uid_range || (b.image.is_some() && !b.uid_range_explicit_false));
        crate::pod::create_with_range(&pod, true, pod_needs_range)?;
    }
    // Feedback-first: a `--net` (host-network) service in a podded stack is NOT on the pod net, so its
    // peers can't reach it by name — say so rather than let it silently not resolve.
    if use_pod {
        for b in boxes.iter().filter(|b| b.net) {
            eprintln!(
                "kern: note: service '{}' uses --net (host network) — it is NOT reachable by name inside pod '{pod}'",
                b.name
            );
        }
    }

    eprintln!(
        "→ bringing up {} box(es) in order: {}",
        order.len(),
        order.join(" → ")
    );
    for (i, name) in order.iter().enumerate() {
        let b = boxes.iter().find(|b| &b.name == name).unwrap();
        // Docker's `depends_on: {condition: ...}`. Before starting this box, WAIT for each dependency
        // it named with a condition: `depends_healthy` → the dep's health check must pass;
        // `depends_completed` → the dep must have run to exit 0. Topo order guarantees those deps are
        // already started. A timeout, a dead dependency, or a failed completion aborts with a reason.
        wait_for_conditions(b, &pod, &up_token)?;

        let dep = if b.depends_on.is_empty() {
            String::new()
        } else {
            format!(" (after {})", b.depends_on.join(", "))
        };
        let src = b
            .image
            .as_deref()
            .or(b.rootfs.as_deref())
            .unwrap_or("(no source)");
        eprintln!(
            "→ [{}/{}] starting '{name}'  {src}{dep}",
            i + 1,
            order.len()
        );
        let mut cmd = std::process::Command::new(&self_exe);
        cmd.arg("box").arg(&b.name);
        b.push_box_flags(&mut cmd);
        // A box that isn't on the host net joins the stack pod → reachable by name from its peers.
        if use_pod && !b.net {
            cmd.arg("--pod").arg(&pod);
        }
        // If any peer waits on THIS box's completion, hand it the stack+run-scoped exit KEY
        // (`<pod>-<token>-<name>`) via env, and CLEAR that exact key BEFORE the spawn (the clear
        // causally precedes the launch and every later poll). Because the key carries this `up`'s
        // token, a concurrent `up` of the same stack uses a DIFFERENT key — its clear/write can't
        // touch ours (review round 2). Env, not a flag, so the security-reviewed `kern box` arg
        // surface is untouched.
        let is_completion_target = boxes
            .iter()
            .any(|other| other.depends_completed.iter().any(|d| d == &b.name));
        if is_completion_target {
            let key = exit_key(&pod, &up_token, &b.name);
            registry::clear_exit(&key);
            cmd.env("KERN_EXIT_KEY", &key);
        }
        cmd.arg("-d");
        if !b.command.is_empty() {
            cmd.arg("--").args(&b.command);
        }
        let status = cmd
            .status()
            .map_err(|e| Error::Compose(format!("starting '{}': {e}", b.name)))?;
        if !status.success() {
            return Err(Error::Compose(format!("box '{}' failed to start", b.name)));
        }
    }
    println!(
        "compose up: {} box(es) started. track with `kern ps`.",
        order.len()
    );
    if use_pod {
        println!(
            "  pod '{pod}': services reach each other by name. tear down with `kern compose {file} down`."
        );
    }
    Ok(())
}

/// Derive a STABLE, per-stack pod name from a compose file path. Uses the parent DIRECTORY name
/// (Docker's project-name rule — compose files are conventionally named `compose.yaml`, so the
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

/// `kern config` — list the resource profiles defined in `kern.toml`. Read-only; a missing config
/// is not an error.
/// `kern config [edit|setup|probe|clear]` — dispatch the config-management subcommands (default:
/// list the profiles).
pub fn config_cmd(sub: &str, force: bool) -> Result<(), Error> {
    match sub {
        "edit" => config_edit(),
        "setup" => config_setup(force),
        "probe" => config_probe(),
        "clear" => config_clear(force),
        _ => config_show(),
    }
}

const CONFIG_ADD_USAGE: &str = "config add <vcpu|vgpio|vdisk>:<name> [--field value …] [--update]";
const CONFIG_RM_USAGE: &str = "config rm <vcpu|vgpio|vdisk>:<name>";

/// Split a `kind:name` token into a known profile kind + a name, or a usage error.
fn parse_profile_token(token: &str, usage: &'static str) -> Result<(String, String), Error> {
    let (kind, name) = token.split_once(':').ok_or(Error::Usage(usage))?;
    if crate::config::profile_fields(kind).is_empty() {
        return Err(Error::Config(format!(
            "unknown profile kind '{kind}' — use vcpu, vgpio or vdisk"
        )));
    }
    Ok((kind.to_string(), name.to_string()))
}

/// `kern config add <kind:name> [--field value …] [--replace]` — the CLI twin of `kern top`'s profile
/// forms. Builds the profile through the SAME `config` schema (validation + surgical, atomic write),
/// so a profile made from the CLI is byte-for-byte what the TUI would write, and vice-versa.
pub fn config_add(args: &[String]) -> Result<(), Error> {
    let token = args.first().ok_or(Error::Usage(CONFIG_ADD_USAGE))?;
    let (kind, name) = parse_profile_token(token, CONFIG_ADD_USAGE)?;
    let allowed = crate::config::profile_fields(&kind);
    // `--update` (alias `--replace`): edit an existing profile IN PLACE, keeping every field you don't
    // pass — the field-surgical merge does that; the only keys touched are the flags given here.
    // Without it, a duplicate name is refused.
    let update = args.iter().any(|a| a == "--update" || a == "--replace");
    let mut pairs: Vec<(String, String)> = Vec::new();
    // Override a repeated flag in place (last wins), else append.
    let mut set_pair = |k: &str, v: String| match pairs.iter_mut().find(|(pk, _)| pk == k) {
        Some(slot) => slot.1 = v,
        None => pairs.push((k.to_string(), v)),
    };

    // Map `--field value` flags onto the pairs; `--persistent` is a bare bool. An unknown flag is
    // rejected (not silently dropped) so a typo can't quietly produce an empty profile.
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        if a == "--update" || a == "--replace" {
            i += 1;
            continue;
        }
        let raw = a.strip_prefix("--").ok_or_else(|| {
            Error::Config(format!(
                "unexpected argument '{a}' (flags look like --vcpus 4)"
            ))
        })?;
        // Accept both `--flag value` and `--flag=value` (GNU/Docker style).
        let (field, inline) = match raw.split_once('=') {
            Some((f, v)) => (f, Some(v)),
            None => (raw, None),
        };
        if allowed.iter().all(|f| *f != field) {
            return Err(Error::Config(format!(
                "{kind} has no --{field}; valid flags: {}",
                allowed
                    .iter()
                    .map(|f| format!("--{f}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            )));
        }
        // `--persistent` is a bare boolean switch (Docker-style, like `-d`) — it never consumes the
        // next token; `--persistent=false` explicitly turns it off.
        if field == "persistent" {
            set_pair("persistent", inline.unwrap_or("true").to_string());
            i += 1;
            continue;
        }
        // `--flag=value` carries its value inline; `--flag value` takes the next token.
        let value = match inline {
            Some(v) => {
                i += 1;
                v.to_string()
            }
            None => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| Error::Config(format!("--{field} needs a value")))?
                    .clone();
                i += 2;
                v
            }
        };
        set_pair(field, value);
    }

    let refs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let body = crate::config::profile_block(&name, &refs).map_err(Error::Config)?;
    // The flags passed here are the fields this command controls; the merge keeps every other key in
    // the block. Update edits in place (orig = the name, skipping the collision guard); a plain add
    // refuses to clobber an existing profile.
    let managed: Vec<&str> = refs.iter().map(|(k, _)| *k).collect();
    let orig = update.then_some(name.as_str());
    crate::config::save_named_block(&kind, orig, &name, &managed, &body).map_err(Error::Config)?;
    let p = crate::ui::Palette::detect();
    println!(
        "{g}{}{z} {kind}:{name}   {d}attach with `{kind}:{name}`{z}",
        if update { "updated" } else { "added" },
        g = p.g,
        z = p.z,
        d = p.d
    );
    Ok(())
}

/// `kern config rm <kind:name>` — delete a resource profile (the CLI twin of the TUI's `d`elete).
pub fn config_rm(args: &[String]) -> Result<(), Error> {
    let token = args.first().ok_or(Error::Usage(CONFIG_RM_USAGE))?;
    let (kind, name) = parse_profile_token(token, CONFIG_RM_USAGE)?;
    crate::config::delete_named_block(&kind, &name).map_err(Error::Config)?;
    let p = crate::ui::Palette::detect();
    println!("{d}removed{z} {kind}:{name}", d = p.d, z = p.z);
    Ok(())
}

/// The default `kern.toml` path, or an error if `$HOME`/`$XDG_CONFIG_HOME` is unset.
fn config_path() -> Result<PathBuf, Error> {
    crate::config::default_path()
        .ok_or_else(|| Error::Config("no config path (set $HOME or $XDG_CONFIG_HOME)".into()))
}

/// `kern config setup [--force]` — write a starter `kern.toml` to the default location (refusing to
/// clobber an existing one unless `--force`).
/// The host's resource inventory — `config probe` prints it; `config setup` seeds a kern.toml whose
/// example profiles already fit THIS machine (real core count / cpuset range / i2c buses).
struct HostInv {
    ncpu: usize,
    ram: String,
    disks: Vec<DiskInfo>, // physical block devices (whole disks, not partitions)
    gpiochips: Vec<String>, // short names, e.g. "gpiochip0"
    i2c: Vec<String>,     // "i2c-0", …
    spi: Vec<String>,     // "spidev0.0", …
}

/// A physical disk from `/sys/block`, for `kern probe` and the `[[disk]]` example in `config setup`.
struct DiskInfo {
    name: String, // "nvme0n1", "sda"
    size: u64,    // bytes
    ssd: bool,    // rotational == 0
    model: String,
}

/// Whole physical disks from `/sys/block`, sorted by name. Skips virtual/loop/ram/dm/optical devices
/// and zero-sized entries (empty card readers). Read-only — a hardware inventory, not a pool manager.
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

fn detect_host() -> HostInv {
    let ncpu = std::fs::read_to_string("/proc/cpuinfo")
        .map(|s| s.lines().filter(|l| l.starts_with("processor")).count())
        .unwrap_or(0);
    let ram = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("MemTotal:"))
                .and_then(|v| v.split_whitespace().next())
                .and_then(|kb| kb.parse::<u64>().ok())
        })
        .map(|kb| human_bytes(kb * 1024))
        .unwrap_or_else(|| "?".into());
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
        ram,
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
fn tailored_kern_toml(h: &HostInv) -> String {
    let n = h.ncpu.max(1);
    let half = ((n as f64 / 2.0) * 10.0).round() / 10.0; // ~half the cores, one decimal
    let pin_hi = n.saturating_sub(1).min(3);
    let mut s = format!(
        "# ~/.config/kern/kern.toml — generated by `kern config setup` for this host \
         ({n} cores, {ram}).\n# Attach a profile by prefix:  kern run vcpu:heavy -- ./train.sh   \
         ·  edit with `kern config edit`\n\n[kern]\nlog_level = \"info\"\n\n\
         # ── CPU ──\n[[cpu]]\nid = \"cpu:0\"\nvcpus = {n}.0\n\n\
         [[vcpu]]\nname = \"heavy\"     # ~half this host, pinned to the first cores\n\
         vcpus = {half}\ncpus = \"0-{pin_hi}\"\nmemory = \"512 MB\"\n\n\
         [[vcpu]]\nname = \"lean\"\nvcpus = 0.5\nmemory = \"256m\"\n",
        ram = h.ram
    );
    // A [[disk]] pool + a vdisk profile that references it, seeded from this host's primary disk, so
    // `kern box … vdisk:scratch` has a real target. Only when a disk was actually detected.
    if let Some(d) = h.disks.first() {
        let kind = if d.ssd { "SSD" } else { "HDD" };
        let model = if d.model.is_empty() {
            String::new()
        } else {
            format!(" {}", d.model)
        };
        s.push_str(&format!(
            "\n# ── Disk — `kern box … vdisk:scratch` gets a size-capped ext4 volume ──\n\
             [[disk]]\nname = \"disk:0\"\npath = \"/\"\ndevice = \"{dev}\"   # {size} {kind}{model}\n\n\
             [[vdisk]]\nname = \"scratch\"\nbackend = \"disk:0\"\nsize = \"2g\"\n",
            dev = d.name,
            size = human_bytes(d.size),
        ));
    }
    if !h.i2c.is_empty() || !h.gpiochips.is_empty() {
        s.push_str(
            "\n# ── GPIO / I/O — `kern box … vgpio:io` binds ONLY these devices into the box ──\n\
             [[gpio]]\nid = \"gpio:0\"\n\n[[vgpio]]\nname = \"io\"\nbackend = \"gpio:0\"\n",
        );
        if let Some(first) = h.i2c.first() {
            // Keep the comment lean: show a few real buses, not all of them.
            let shown = h.i2c.iter().take(4).cloned().collect::<Vec<_>>().join(", ");
            let more = h.i2c.len().saturating_sub(4);
            let extra = if more > 0 {
                format!(" (+{more} more)")
            } else {
                String::new()
            };
            s.push_str(&format!(
                "i2c = [\"/dev/{first}\"]    # host buses: {shown}{extra}\n"
            ));
        }
        if !h.gpiochips.is_empty() {
            s.push_str(&format!(
                "pins = [17]           # gpiochips: {}\n",
                h.gpiochips.join(", ")
            ));
        }
    } else {
        s.push_str(
            "\n# (no GPIO/I2C detected here — add a [[vgpio]] profile when you attach hardware)\n",
        );
    }
    s
}

fn config_setup(force: bool) -> Result<(), Error> {
    let path = config_path()?;
    if path.exists() && !force {
        return Err(Error::Config(format!(
            "{} already exists — pass --force to overwrite",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::Config(format!("config dir: {e}")))?;
    }
    let toml = tailored_kern_toml(&detect_host());
    std::fs::write(&path, &toml)
        .map_err(|e| Error::Config(format!("writing {}: {e}", path.display())))?;
    println!(
        "wrote a starter config to {} (tailored to this host — `kern config edit` to tweak)",
        path.display()
    );
    Ok(())
}

/// `kern config edit` — open `kern.toml` in `$EDITOR` (seeding a starter file first if none exists).
fn config_edit() -> Result<(), Error> {
    let path = config_path()?;
    if !path.exists() {
        config_setup(false)?;
    }
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "vi".into());
    let status = std::process::Command::new(&editor)
        .arg(&path)
        .status()
        .map_err(|e| Error::Config(format!("launching {editor}: {e}")))?;
    if !status.success() {
        return Err(Error::Config(format!("{editor} exited non-zero")));
    }
    // Validate what the user just edited, so a typo is caught now rather than at the next run.
    match crate::config::parse(&std::fs::read_to_string(&path).unwrap_or_default()) {
        Ok(_) => println!("saved {} (valid)", path.display()),
        Err(e) => eprintln!("kern: warning: {} has an error: {e}", path.display()),
    }
    Ok(())
}

/// `kern config clear [--yes]` — remove the `kern.toml` (destructive → needs `--yes`).
fn config_clear(yes: bool) -> Result<(), Error> {
    let path = config_path()?;
    if !path.exists() {
        println!("no kern.toml to clear");
        return Ok(());
    }
    if !yes {
        return Err(Error::Config(format!(
            "would remove {} — pass --yes to confirm",
            path.display()
        )));
    }
    std::fs::remove_file(&path)
        .map_err(|e| Error::Config(format!("removing {}: {e}", path.display())))?;
    println!("removed {}", path.display());
    Ok(())
}

/// `kern config probe` — read-only inventory of host resources you can *declare* in a profile: CPUs,
/// RAM, and any GPIO/I2C/SPI/disk devices present. Doesn't touch the config; it just tells you what's
/// available to reference.
fn config_probe() -> Result<(), Error> {
    let p = crate::ui::Palette::detect();
    let row = |k: &str, v: &str| println!("{d}{k:<14}{z} {v}", d = p.d, z = p.z);
    let h = detect_host();
    // Clamp long inventories (a server can expose 20+ i2c buses) so one row can't dominate the panel;
    // the full set is a `ls /dev` away and rarely all relevant.
    let list = |v: &[String]| match v.len() {
        0 => "-".to_string(),
        n if n <= 8 => v.join(", "),
        n => format!("{}, … (+{} more)", v[..8].join(", "), n - 8),
    };
    println!("{b}host resources{z}", b = p.b, z = p.z);
    row(
        "cpus",
        &format!("{} (cpuset range 0-{})", h.ncpu, h.ncpu.saturating_sub(1)),
    );
    row("memory", &h.ram);
    // Disks get their own formatter (name/size/type/model), joined and clamped like the bus lists.
    let disks = match h.disks.len() {
        0 => "-".to_string(),
        n if n <= 4 => h
            .disks
            .iter()
            .map(disk_label)
            .collect::<Vec<_>>()
            .join("  ·  "),
        n => format!(
            "{}  ·  … (+{} more)",
            h.disks[..4]
                .iter()
                .map(disk_label)
                .collect::<Vec<_>>()
                .join("  ·  "),
            n - 4
        ),
    };
    row("disks", &disks);
    row("gpiochips", &list(&h.gpiochips));
    row("i2c buses", &list(&h.i2c));
    row("spi devices", &list(&h.spi));
    println!(
        "{d}`kern config setup` writes a kern.toml tailored to these — or `kern examples`{z}",
        d = p.d,
        z = p.z
    );
    Ok(())
}

pub fn config_show() -> Result<(), Error> {
    let p = crate::ui::Palette::detect();
    let Some(path) = crate::config::default_path().filter(|p| p.exists()) else {
        println!(
            "{d}no kern.toml — run `kern examples` to see the format{z}",
            d = p.d,
            z = p.z
        );
        return Ok(());
    };
    let cfg = crate::config::load(None).map_err(Error::Config)?;
    println!("{d}{}{z}", path.display(), d = p.d, z = p.z);
    for e in &cfg.vcpu {
        let mut parts = Vec::new();
        if let Some(q) = e.vcpus {
            parts.push(format!("{q} cores"));
        }
        if let Some(c) = &e.cpus {
            parts.push(format!("pin {c}"));
        }
        if let Some(m) = &e.memory {
            parts.push(m.clone());
        }
        println!(
            "  {b}{c}vcpu:{}{z}  {d}{}{z}",
            e.name,
            parts.join(", "),
            b = p.b,
            c = p.c,
            d = p.d,
            z = p.z
        );
    }
    for e in &cfg.vgpio {
        println!(
            "  {b}{c}vgpio:{}{z}  {d}backend {}, {} pin(s){z}",
            e.name,
            e.backend,
            e.pins.len(),
            b = p.b,
            c = p.c,
            d = p.d,
            z = p.z
        );
    }
    for e in &cfg.vdisk {
        println!(
            "  {b}{c}vdisk:{}{z}  {d}{}{z}",
            e.name,
            e.size.as_deref().unwrap_or("-"),
            b = p.b,
            c = p.c,
            d = p.d,
            z = p.z
        );
    }
    if cfg.vcpu.is_empty() && cfg.vgpio.is_empty() && cfg.vdisk.is_empty() {
        println!("{d}(no vcpu/vgpio/vdisk profiles){z}", d = p.d, z = p.z);
    }
    Ok(())
}

/// `kern validate [path]` — parse a `kern.toml` (the given path, or the default location) and report
/// success with profile counts, or the offending line. Exits non-zero on a parse error.
pub fn validate(path: Option<&str>) -> Result<(), Error> {
    let target = match path {
        Some(p) => std::path::PathBuf::from(p),
        None => crate::config::default_path()
            .ok_or_else(|| Error::Config("no default config path (set $HOME)".to_string()))?,
    };
    let text = std::fs::read_to_string(&target)
        .map_err(|e| Error::Config(format!("{}: {e}", target.display())))?;
    let cfg = crate::config::parse(&text)
        .map_err(|e| Error::Config(format!("{}: {e}", target.display())))?;
    let p = crate::ui::Palette::detect();
    println!(
        "{g}valid{z} {} {d}—{z} {} vcpu, {} vgpio, {} vdisk profile(s)",
        target.display(),
        cfg.vcpu.len(),
        cfg.vgpio.len(),
        cfg.vdisk.len(),
        g = p.g,
        d = p.d,
        z = p.z
    );
    Ok(())
}

/// `kern examples` — print a commented example `kern.toml` to stdout (redirect it into
/// `~/.config/kern/kern.toml` to get started).
pub fn examples() -> Result<(), Error> {
    print!("{EXAMPLE_KERN_TOML}");
    Ok(())
}

/// A ready-to-use example config covering the resource families kern-public supports (CPU/GPIO/disk).
const EXAMPLE_KERN_TOML: &str = r#"# ~/.config/kern/kern.toml — resource profiles for `kern run`/`kern box`.
# Attach a profile by prefix, e.g.  kern run vcpu:heavy -- ./train.sh

[kern]
log_level = "info"

# ── CPU ──────────────────────────────────────────────────────────────────
# Declare the host CPU budget (optional), then carve named vCPU profiles.
[[cpu]]
id = "cpu:0"
vcpus = 8.0

[[vcpu]]
name = "heavy"
backend = "cpu:0"     # optional link to a [[cpu]]
vcpus = 4.0           # core quota (like --cpus): 4 cores
cpus = "0-3"          # pin to CPUs 0-3 (like --cpuset-cpus)
memory = "2g"         # RAM cap (like --memory)
priority = 80         # 0..99 -> nice

[[vcpu]]
name = "lean"
vcpus = 0.5
memory = "256m"

# ── GPIO / I/O — `kern box vgpio:leds …` binds ONLY these devices into the box ──
[[gpio]]
id = "gpio:0"
pins = [17, 27, 22]

[[vgpio]]
name = "leds"
backend = "gpio:0"
pins = [17, 27]
i2c = ["1"]

# ── Disk — `kern box vdisk:scratch …` mounts a size-capped volume at /vdisk/scratch ──
[[disk]]
name = "data"
path = "/var/lib/kern/volumes"

[[vdisk]]
name = "scratch"
backend = "data"
size = "2g"
"#;

#[cfg(test)]
mod net_resource_tests {
    use super::*;

    #[test]
    fn parse_volumes_guards_targets() {
        // Bad targets are rejected before any mount.
        for bad in [
            "data:mnt",        // relative
            "data:/../escape", // traversal
            "data:/proc",      // shadows the box's proc
            "data:/sys",
            "data:/dev",
            "data:/",      // over the whole rootfs
            "data:/./x",   // dot component
            "data://proc", // leading-double-slash bypass — resolves to /proc at mount time
            "data://sys",
            "data://dev",
            "data:///dev", // triple slash too
            "data://dev/", // trailing slash after the bypass
        ] {
            assert!(
                parse_volumes(&[bad.into()]).is_err(),
                "should reject -v {bad}"
            );
        }
        // A subpath of an essential mount is allowed (use an existing host source to stay hermetic).
        assert!(
            parse_volumes(&["/tmp:/dev/foo".into()]).is_ok(),
            "a subpath like /dev/foo must be allowed"
        );
        assert!(parse_volumes(&["/tmp:/data".into()]).is_ok());
    }

    #[test]
    fn parse_tmpfs_guards_hardened_mounts_incl_double_slash() {
        for bad in [
            "/proc",
            "/sys",
            "/dev",      // exact hardened roots
            "/proc/foo", // under a hardened root
            "//proc",
            "//sys",
            "//dev", // leading-double-slash bypass
            "///dev/x",
        ] {
            assert!(
                parse_tmpfs(&[bad.into()]).is_err(),
                "should reject --tmpfs {bad}"
            );
        }
        // A normal tmpfs path is fine.
        assert!(parse_tmpfs(&["/scratch".into()]).is_ok());
        assert!(parse_tmpfs(&["/var/cache:64m".into()]).is_ok());
    }

    #[test]
    fn image_command_resolution() {
        let img = kern_oci::ImageConfig {
            entrypoint: vec!["docker-entrypoint.sh".into()],
            cmd: vec!["redis-server".into()],
            ..Default::default()
        };
        // No user command → entrypoint + image Cmd.
        assert_eq!(
            resolve_image_command(&[], false, &img),
            vec!["docker-entrypoint.sh", "redis-server"]
        );
        // User command → entrypoint + user command (image Cmd dropped, docker-style).
        assert_eq!(
            resolve_image_command(&["redis-cli".into()], false, &img),
            vec!["docker-entrypoint.sh", "redis-cli"]
        );
        // --ssh + no command → keep-alive, ignore the image command.
        assert_eq!(
            resolve_image_command(&[], true, &img),
            vec!["sleep", "infinity"]
        );
        // No image config + no command → a shell (the --rootfs / bare case).
        let empty = kern_oci::ImageConfig::default();
        assert_eq!(
            resolve_image_command(&[], false, &empty),
            vec![DEFAULT_SHELL]
        );
        // No image config + user command → the user command unchanged.
        assert_eq!(
            resolve_image_command(&["echo".into(), "hi".into()], false, &empty),
            vec!["echo", "hi"]
        );
    }

    #[test]
    fn restart_policy_parses_docker_names_only() {
        assert_eq!(RestartPolicy::parse("no"), Some(RestartPolicy::No));
        assert_eq!(
            RestartPolicy::parse("on-failure"),
            Some(RestartPolicy::OnFailure)
        );
        assert_eq!(RestartPolicy::parse("always"), Some(RestartPolicy::Always));
        assert_eq!(
            RestartPolicy::parse("unless-stopped"),
            Some(RestartPolicy::UnlessStopped)
        );
        // Unknown tokens don't parse — so a bare `--restart` won't swallow the next arg/command.
        assert_eq!(RestartPolicy::parse("sh"), None);
        assert_eq!(RestartPolicy::parse("--memory"), None);
        assert_eq!(RestartPolicy::parse(""), None);
        // Only always/unless-stopped are reboot-persistent (→ a systemd unit).
        assert!(RestartPolicy::Always.persistent() && RestartPolicy::UnlessStopped.persistent());
        assert!(!RestartPolicy::OnFailure.persistent() && !RestartPolicy::No.persistent());
    }

    #[test]
    fn systemd_quote_neutralizes_expansion_and_quoting() {
        // Plain arg is just wrapped.
        assert_eq!(systemd_quote("alpine"), "\"alpine\"");
        // `$` and `%` (systemd env/specifier expansion) are doubled so they stay literal.
        assert_eq!(systemd_quote("echo $(date +%s)"), "\"echo $$(date +%%s)\"");
        // Embedded quotes/backslashes are C-escaped so the ExecStart line stays parseable.
        assert_eq!(systemd_quote(r#"a"b\c"#), r#""a\"b\\c""#);
    }

    #[test]
    fn sanitize_ref_is_traversal_free_and_collision_free() {
        // No `.`/`/`/`:` survive → a `..` ref can't build a `cache/..` traversal.
        for r in ["..", ".", "../../etc", "a/../b"] {
            let s = sanitize_ref(r);
            assert!(
                !s.contains('/') && s != ".." && s != "." && !s.split('-').any(|p| p == ".."),
                "{r} → {s} still looks traversal-ish"
            );
        }
        // Distinct refs that used to collapse together now differ (the hash suffix).
        assert_ne!(sanitize_ref("foo/bar"), sanitize_ref("foo_bar"));
        assert_ne!(sanitize_ref("alpine:3.19"), sanitize_ref("alpine:3_19"));
        // Same ref → same key (stable cache).
        assert_eq!(sanitize_ref("redis:alpine"), sanitize_ref("redis:alpine"));
    }

    #[test]
    fn layer_cache_key_helpers() {
        // Deterministic + chained: same inputs → same key; a changed repr OR a changed parent key
        // → different key (so a change busts this layer and everything after it).
        let k0 = layer_key("base", "RUN a");
        assert_eq!(k0, layer_key("base", "RUN a"));
        assert_ne!(k0, layer_key("base", "RUN b")); // repr changed
        assert_ne!(k0, layer_key("other", "RUN a")); // parent key changed
        assert_eq!(k0.len(), 32); // 128-bit hex
                                  // chain_lower stacks top (last) first, base (first) last — overlayfs shadow order.
        assert_eq!(
            chain_lower(&["base".into(), "l1".into(), "l2".into()]),
            "l2:l1:base"
        );
    }

    #[test]
    fn content_hash_changes_with_content() {
        let d = format!("/tmp/.kern-ch-{}", std::process::id());
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(format!("{d}/a"), b"one").unwrap();
        let h1 = content_hash(std::path::Path::new(&d));
        assert_eq!(h1, content_hash(std::path::Path::new(&d))); // stable
        std::fs::write(format!("{d}/a"), b"two").unwrap();
        assert_ne!(h1, content_hash(std::path::Path::new(&d))); // content changed
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn compose_pod_name_is_stable_unique_and_safe() {
        let ok = |n: &str| {
            !n.is_empty()
                && !n.starts_with('.')
                && n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        };
        // Stable for the same path (so `up` and `down` agree) and always a valid pod name.
        let n = compose_pod_name("/srv/myapp/compose.yaml");
        assert_eq!(n, compose_pod_name("/srv/myapp/compose.yaml"));
        assert!(ok(&n) && n.starts_with("myapp-"), "dir-based + valid: {n}");
        // Two same-named compose files in DIFFERENT dirs → DIFFERENT pods (no cross-stack collision).
        assert_ne!(
            compose_pod_name("/srv/a/compose.yaml"),
            compose_pod_name("/srv/b/compose.yaml")
        );
        // Odd/empty stems still produce a valid name (base falls back, hash suffix appended).
        assert!(ok(&compose_pod_name("compose.yaml")));
        assert!(ok(&compose_pod_name("....")));
    }

    #[test]
    fn run_batching_helpers() {
        // Only the shell form is batchable.
        assert_eq!(
            run_shell_script(&["/bin/sh".into(), "-c".into(), "echo hi".into()]),
            Some("echo hi")
        );
        assert_eq!(run_shell_script(&["node".into(), "app.js".into()]), None);
        // Single quoting is `'\''`-safe.
        assert_eq!(shell_quote_single("a'b"), "'a'\\''b'");
        // A single script isn't re-wrapped.
        assert_eq!(
            combine_run_scripts(&["echo hi"]),
            vec!["/bin/sh", "-c", "echo hi"]
        );
        // Multiple scripts → each in its own subshell, `&&`-chained (fail-fast) and quoting-safe.
        assert_eq!(
            combine_run_scripts(&["a", "it's b"]),
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "/bin/sh -c 'a' && /bin/sh -c 'it'\\''s b'".to_string(),
            ]
        );
    }

    #[test]
    fn image_config_sidecar_round_trips() {
        let c = kern_oci::ImageConfig {
            entrypoint: vec!["/entry".into()],
            cmd: vec!["-c".into(), "run".into()],
            env: vec!["A=1".into(), "B=2".into()],
            workdir: Some("/app".into()),
            user: Some("1000:1000".into()),
        };
        let dir = std::env::temp_dir().join(format!("kern-imgcfg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("x.image");
        write_image_config(&f, &c);
        let r = read_image_config(&f);
        assert_eq!(r.entrypoint, c.entrypoint);
        assert_eq!(r.cmd, c.cmd);
        assert_eq!(r.env, c.env);
        assert_eq!(r.workdir, c.workdir);
        assert_eq!(r.user, c.user);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hostname_validation() {
        assert_eq!(validate_hostname(None).unwrap(), None);
        assert_eq!(
            validate_hostname(Some("my-box.1")).unwrap().as_deref(),
            Some("my-box.1")
        );
        for bad in [
            "-lead",
            "trail-",
            ".dot",
            "has/slash",
            "sp ace",
            &"x".repeat(65),
        ] {
            assert!(
                validate_hostname(Some(bad)).is_err(),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn tmpfs_parse_and_blocked_mounts() {
        assert_eq!(
            parse_tmpfs(&["/scratch:64M".into()]).unwrap(),
            vec![("/scratch".to_string(), "64m".to_string())]
        );
        // No size → empty (kernel default).
        assert_eq!(
            parse_tmpfs(&["/cache".into()]).unwrap(),
            vec![("/cache".to_string(), String::new())]
        );
        // Hardened mounts and their subpaths are refused; so are relative/`..` paths and bad sizes.
        for bad in [
            "/proc",
            "/sys/kernel",
            "/dev",
            "/dev/shm",
            "relative",
            "/a/../b",
            "/x:huge",
        ] {
            assert!(
                parse_tmpfs(&[bad.to_string()]).is_err(),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn user_parse() {
        assert_eq!(parse_user(None).unwrap(), None);
        assert_eq!(parse_user(Some("1000")).unwrap(), Some((1000, 1000)));
        assert_eq!(parse_user(Some("1000:2000")).unwrap(), Some((1000, 2000)));
        for bad in ["alice", "1000:bob", ":5", "1000:"] {
            assert!(parse_user(Some(bad)).is_err(), "should reject {bad:?}");
        }
    }
}
