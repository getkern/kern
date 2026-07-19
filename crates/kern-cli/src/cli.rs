//! Command parsing and dispatch.
//!
//! A tiny hand-rolled parser keeps the binary dependency-free. The roadmap target is a
//! `clap`-derive command enum + `match` dispatch (same shape, see ARCHITECTURE.md).

use crate::commands;
use crate::error::Error;

/// Global runtime options that apply to any command. Reserved for future global flags (none today).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct GlobalOpts;

/// The parsed subcommand.
// `BoxRun` carries every `kern box` flag, so it dwarfs the unit variants — but a `Command` is built
// exactly once per process on the cold parse path, so boxing it would only add indirection for no
// runtime benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq)]
pub enum Command {
    Version,
    /// Bare `kern`: a short logo + tagline + the most-used commands (full list via `--help`).
    Banner,
    Help,
    /// `kern box <name> --plan`: print the ordered isolation step sequence (no privileges).
    BoxPlan {
        name: String,
    },
    /// `kern box <name> (--rootfs <dir> | --image <ref>) [-d] [-- cmd...]`: run in a sandbox.
    BoxRun {
        name: String,
        rootfs: Option<String>,
        image: Option<String>,
        command: Vec<String>,
        detached: bool,
        read_only: bool,
        /// `-v src:dst[:ro]` (repeatable): host paths bind-mounted in.
        volumes: Vec<String>,
        /// `--env K=V` / `-e K=V` (repeatable): extra environment for the workload.
        env: Vec<String>,
        /// `--workdir <dir>` / `-w <dir>`: working directory inside the box.
        workdir: Option<String>,
        /// `--net`: share the host network namespace (outbound networking; no net isolation).
        share_net: bool,
        /// `--pod <name>`: join a pod's shared loopback network (reach peers by name).
        pod: Option<String>,
        /// `--uid-range`: map a sub-uid/gid range (apt/dpkg, www-data). Default maps only the caller.
        uid_range: bool,
        /// `--bind-rootfs`: bind the rootfs directly instead of an overlay (faster on slow-overlay
        /// kernels; source becomes mutable & shared).
        bind_rootfs: bool,
        /// `--privileged`: relax the seccomp filter so a NESTED `kern box` (or docker-in-docker-style
        /// workload) can create its namespaces. Rootless-only; refused as real host root.
        privileged: bool,
        /// INTERNAL (used by `kern build`): explicit overlay lower dir(s), colon-joined, used as the
        /// read-only base instead of `--rootfs`/`--image`. Paired with `--overlay-upper`.
        overlay_lower: Option<String>,
        /// INTERNAL (used by `kern build`): a PERSISTENT overlay upper dir (the build layer) instead
        /// of the ephemeral scratch upper — so a build's writes accumulate across RUN steps.
        overlay_upper: Option<String>,
        /// `--memory`/`-m`: hard memory ceiling in bytes (default cap if `None`).
        memory: Option<u64>,
        /// `--memory-swap-max`: swap allowance in bytes → `memory.swap.max` (v2, separate from
        /// `memory.max`; NOT Docker's combined mem+swap total). `None` → `0` (swap off).
        memory_swap_max: Option<u64>,
        /// `--cpus`: CPU cap in cores, K8s semantics (1.5 = 1½ cores; uncapped if `None`).
        cpus: Option<f64>,
        /// `--cpuset-cpus`: pin to specific CPUs (e.g. `"0-3"`, `"0,2,4"`). `None` → no pinning.
        cpuset: Option<String>,
        /// `-it`/`-t`: allocate a PTY so the box gets an interactive controlling terminal.
        tty: bool,
        /// `-p host:box` (repeatable): publish a box TCP/UDP port (or range) on a host port.
        ports: Vec<kern_isolation::PortMap>,
        /// `--add-host NAME:IP` (repeatable): extra `/etc/hosts` entries; `IP` may be `host-gateway`.
        add_hosts: Vec<(String, String)>,
        /// `--secret SRC[:NAME]` / `NAME=value` / `NAME=-` (repeatable): deliver a secret to the box
        /// as `/run/secrets/NAME` (mode 0400) without it touching the image or the workload env.
        secrets: Vec<String>,
        /// `--ssh PORT`: run an in-box sshd, published on host `PORT` (→ box `:22`).
        ssh_port: Option<u16>,
        /// `--ssh-key FILE`: authorize this public key instead of generating a throwaway keypair.
        ssh_key: Option<String>,
        /// `--hostname NAME`: the box's UTS hostname (default: the box name).
        hostname: Option<String>,
        /// `--tun`: expose `/dev/net/tun` in the box (WireGuard / userspace VPN).
        tun: bool,
        /// `--init`: run a built-in reaping init as box PID 1 (no zombies; forwards SIGTERM/SIGINT).
        init: bool,
        /// `--pids-limit N`: cap the box's process/thread count (`pids.max`) — fork-bomb containment.
        pids_limit: Option<u64>,
        /// `--tmpfs PATH[:size]` (repeatable): mount a fresh tmpfs at PATH inside the box.
        tmpfs: Vec<String>,
        /// `--user UID[:GID]` / `-u`: drop to this uid/gid inside the box before the command runs.
        run_as: Option<String>,
        /// `--cap-add CAP` (repeatable): keep a capability kern would otherwise drop (or `ALL`).
        cap_add: Vec<String>,
        /// `--cap-drop CAP` (repeatable): drop an extra capability (or `ALL`).
        cap_drop: Vec<String>,
        /// `--restart [policy]`: restart policy for a detached box (see `commands::RestartPolicy`).
        restart: commands::RestartPolicy,
        /// `--health-cmd <cmd>`: shell command run periodically in the box (exit 0 = healthy).
        health_cmd: Option<String>,
        /// `--health-interval <sec>`: seconds between health checks (default 30).
        health_interval: u64,
        /// `--health-retries <n>`: consecutive failures before a box is marked unhealthy (default 3).
        health_retries: u32,
        /// `--health-start-period <sec>`: initial grace where a failing check keeps "starting" (0).
        health_start_period: u64,
        /// `--health-timeout <sec>`: kill a single check that runs longer than this (0 = no timeout).
        health_timeout: u64,
        /// `--health-action <restart|stop|none>`: what to do when a box turns unhealthy.
        health_action: Option<String>,
        /// `--env-file <file>` (repeatable): read `K=V` lines from a file into the box's environment.
        env_file: Vec<String>,
        /// `--timeout <sec>`: stop the box automatically after this many seconds (0 = no timeout).
        timeout: u64,
        /// `--nice <n>`: scheduling niceness (-20..19) for the box workload.
        nice: Option<i64>,
        /// `--io-weight <n>`: cgroup v2 `io.weight` (1..10000) — relative I/O priority.
        io_weight: Option<u64>,
        /// `--config <path>`: a specific `kern.toml` for this invocation (else the default / `KERN_CONFIG`).
        config: Option<String>,
        /// `--show-config`: print the resolved box configuration and exit (no run).
        show_config: bool,
        /// `--quiet` / `-q`: suppress the foreground status panel.
        quiet: bool,
        /// `--verbose`: expand the one-line summary into the full isolation posture panel.
        verbose: bool,
        /// Resource-profile tokens (`vcpu:name` …) given before the command; applied to the box's
        /// caps (see `kern.toml`). Empty when none.
        profiles: Vec<String>,
    },
    /// `kern run [--memory M] [--memory-swap-max S] [--cpus N] [--cpuset-cpus L] [--] <cmd...>`:
    /// run a command under cgroup CPU/memory caps WITHOUT a full sandbox — the resource-governor
    /// verb (composes with `box`'s isolation). Takes the same resource flags as `kern box`.
    Run {
        command: Vec<String>,
        memory: Option<u64>,
        memory_swap_max: Option<u64>,
        cpus: Option<f64>,
        cpuset: Option<String>,
        /// `--config <path>`: a specific `kern.toml` for the profile tokens (parity with `box`).
        config: Option<String>,
    },
    /// `kern exec <name> [-it] [--env K=V] [--workdir <dir>] [-- cmd...]`: run a command in a box.
    Exec {
        name: String,
        command: Vec<String>,
        env: Vec<String>,
        workdir: Option<String>,
        /// `-it`/`-t`/`-i`: allocate an interactive PTY for the exec'd command.
        tty: bool,
    },
    /// `kern stop <name>... | --all`: stop running box(es) by name, or every running box.
    Stop {
        names: Vec<String>,
        all: bool,
    },
    /// `kern pause <name>... | --all` / `kern unpause …`: freeze / thaw running box(es).
    Pause {
        names: Vec<String>,
        all: bool,
        freeze: bool,
    },
    /// `kern attach <name>`: stream a detached box's output live (Ctrl-C detaches).
    Attach {
        name: String,
    },
    /// `kern cp <src> <dst>`: copy a file between the host and a box (one side is `<box>:<path>`).
    Cp {
        src: String,
        dst: String,
    },
    /// `kern pull <image> [--dest <dir>]`: download an OCI image into a rootfs.
    Pull {
        image: String,
        dest: Option<String>,
        /// `--platform os/arch`: fetch a specific arch from a multi-arch index (default: this host).
        platform: Option<String>,
    },
    /// `kern push <local-ref> [as <remote-ref>]`: publish a cached image to a registry.
    Push {
        local: String,
        remote: Option<String>,
    },
    /// `kern tag <src> <dst>`: give a cached image a second name (build→tag→push).
    Tag {
        src: String,
        dst: String,
    },
    /// `kern build -t <name> [-f Dockerfile] [--build-arg K=V] [<context>]`: build a local image
    /// from a Dockerfile subset.
    Build {
        tag: Option<String>,
        file: Option<String>,
        context: String,
        build_args: Vec<String>,
        quiet: bool,
    },
    /// `kern pod create <name> [--no-outbound] [--uid-range]` / `pod ls` / `pod rm <name>`: shared-network pods.
    PodCreate {
        name: String,
        outbound: bool,
        uid_range: bool,
    },
    PodList,
    PodRemove {
        names: Vec<String>,
    },
    /// Hidden: the pod namespace holder process (spawned by `pod create`, not user-facing).
    PodHolder,
    /// `kern search <query> [--json]`: search Docker Hub for images.
    Search {
        query: String,
        json: bool,
    },
    /// `kern images [--json]`: list pulled (cached) images.
    Images {
        json: bool,
    },
    /// `kern rmi <image>...`: remove cached images by ref (or sanitized stem), reclaiming any layers
    /// left referenced by no other image.
    Rmi {
        images: Vec<String>,
    },
    /// `kern save <image> [-o file]`: export a cached image to a `docker load`-compatible tar.
    Save {
        image: String,
        out: Option<String>,
    },
    /// `kern load [-i file]`: import an image from a `docker save`-format tar (file or stdin).
    Load {
        input: Option<String>,
    },
    /// `kern builds [<tag>] [--status S] [-n N] [--json]`: list past builds (build history — the
    /// `docker buildx history` analogue), optionally filtered by tag substring / outcome / count.
    Builds {
        json: bool,
        filter: Option<String>,
        status: Option<String>,
        limit: Option<usize>,
    },
    /// `kern build logs <id>`: print a past build's captured transcript.
    BuildLogs {
        id: String,
    },
    /// `kern build inspect <id> [--json]`: full detail for one past build.
    BuildInspect {
        id: String,
        json: bool,
    },
    /// `kern build rm <id>...`: delete build-history records.
    BuildRm {
        ids: Vec<String>,
    },
    /// `kern build prune [--keep N]`: keep the N newest build records, delete the rest.
    BuildPrune {
        keep: usize,
    },
    /// `kern ps [--json]`: list running boxes.
    Ps {
        json: bool,
    },
    /// `kern stats [--json] [name...]`: per-box memory + CPU (all boxes, or just the named ones).
    Stats {
        json: bool,
        names: Vec<String>,
    },
    /// `kern logs <name>`: print a box's captured output.
    Logs {
        name: String,
    },
    /// `kern inspect <name> [--json]`: full detail for one running box (identity + resources).
    Inspect {
        name: String,
        json: bool,
    },
    /// `kern prune`: garbage-collect leftover logs/health/registry files of boxes no longer running.
    Prune,
    /// `kern gc [--images]`: `prune` + optionally reclaim the pulled-image cache.
    Gc {
        images: bool,
    },
    /// `kern doctor`: preflight — will boxes run here, and which optional features are available?
    Doctor,
    /// `kern info`: compact runtime + host snapshot.
    Info,
    /// `kern bench [--rootfs R] [-n N]`: time N box start→exit cycles.
    Bench {
        rootfs: Option<String>,
        count: u32,
    },
    /// `kern recover`: clean up stale registry entries / orphaned scratch of dead boxes.
    Recover,
    /// `kern history [-n N]`: recent boxes (from their captured logs).
    History {
        count: usize,
    },
    /// `kern login [registry] [--username U]`: store registry credentials for private-image pulls.
    Login {
        registry: Option<String>,
        username: Option<String>,
    },
    /// `kern logout [registry]`: remove stored registry credentials.
    Logout {
        registry: Option<String>,
    },
    /// `kern completions <bash|zsh|fish>`: print a shell-completion script.
    Completions {
        shell: String,
    },
    /// `kern top`: live auto-refreshing box monitor.
    Top,
    /// `kern compose <file> [up|down] [--no-pod]`: bring up (or tear down) a stack of boxes in
    /// dependency order. `up` auto-creates a pod so services reach each other by name (`--no-pod`
    /// opts out); `down` stops the boxes and removes the pod.
    Compose {
        file: String,
        down: bool,
        no_pod: bool,
    },
    /// `kern config [edit|setup|probe|clear]`: manage `kern.toml` (default: list its profiles).
    Config {
        sub: String,
        force: bool,
    },
    /// `kern config add <kind:name> [--flags]`: create/replace a resource profile non-interactively —
    /// the CLI twin of `kern top`'s profile forms (same validation + surgical write).
    ConfigAdd {
        args: Vec<String>,
    },
    /// `kern config rm <kind:name>`: delete a resource profile.
    ConfigRm {
        args: Vec<String>,
    },
    /// `kern validate [path]`: parse a `kern.toml` and report OK or the offending line.
    Validate {
        path: Option<String>,
    },
    /// `kern examples`: print an example `kern.toml` to stdout.
    Examples,
    /// `kern volume <create|ls|rm|inspect|prune> …`: manage named volumes.
    Volume {
        args: Vec<String>,
    },
}

// Usage/rejection strings shared by the `box` and `run` resource-flag arms, so the two parsers
// can never drift out of sync (they take the same flags with identical semantics).
const USAGE_MEMORY: &str = "--memory <size> (e.g. 512m, 1g, 268435456)";
const USAGE_CPUS: &str = "--cpus <n> (e.g. 1.5 = 1½ cores, 2)";
const USAGE_CPUSET: &str = "--cpuset-cpus <list> (e.g. 0-3, 0,2,4)";
const USAGE_SWAP_MAX: &str = "--memory-swap-max <size> (e.g. 1g, 512m)";
const REJECT_MEMORY_SWAP: &str =
    "--memory-swap is not supported (Docker's mem+swap total, ambiguous on cgroup v2); \
     use --memory-swap-max <size> = the swap allowance (memory.swap.max)";

/// Split argv into global options and a subcommand.
pub fn parse(args: &[String]) -> Result<(GlobalOpts, Command), Error> {
    let opts = GlobalOpts;
    let rest: Vec<&str> = args.iter().map(String::as_str).collect();
    // `kern <cmd> --help` / `-h` / `help` anywhere in the args → show the full reference, instead of
    // letting the per-command parser reject `--help` as an "unknown flag" (a bad first impression: the
    // universal `<tool> <cmd> --help` habit must not error). The bare/first-arg forms are handled below;
    // this catches the second-and-later positions for every command. `--` ends option scanning so a
    // `-- --help` inside a box/run command is NOT treated as a help request.
    if rest.len() > 1 {
        let mut saw_help = false;
        for a in &rest[1..] {
            if *a == "--" {
                break;
            }
            if matches!(*a, "--help" | "-h") {
                saw_help = true;
                break;
            }
        }
        if saw_help {
            return Ok((opts, Command::Help));
        }
    }
    let cmd = match rest.first().copied() {
        // Bare `kern` → the short banner; `--help`/`-h`/`help` → the full command reference.
        None => Command::Banner,
        Some("--help" | "-h" | "help") => Command::Help,
        Some("--version" | "-V" | "version") => Command::Version,
        // `box`: `--plan` previews; `--rootfs <dir>`/`--image <ref>` [-d] [-- cmd] runs it.
        Some("box") => parse_box(&rest)?,
        // `exec <name> [opts] [-- cmd]`: run a command in an existing box.
        Some("exec") => parse_exec(&rest)?,
        // `search <query> [--json]`: search Docker Hub for images.
        Some("search") => match rest.iter().skip(1).find(|a| !a.starts_with('-')) {
            Some(q) => Command::Search {
                query: (*q).to_string(),
                json: rest.contains(&"--json"),
            },
            None => return Err(Error::Usage("search <query> [--json]")),
        },
        // `pod create <name> [-p …]` / `pod ls` / `pod rm <name>…`: shared-network pods.
        Some("pod") => parse_pod(&rest)?,
        // Hidden: the pod namespace holder (spawned by `pod create`).
        Some("__pod-holder") => Command::PodHolder,
        // `build -t <name> [-f Dockerfile] [--build-arg K=V] [<context>]`: build a local image.
        Some("build") => parse_build(&rest)?,
        // `pull <image> [--dest <dir>]`: download an OCI image.
        Some("pull") => parse_pull(&rest).ok_or(Error::Usage("pull <image> [--dest <dir>]"))?,
        // `push <local-ref> [as <remote-ref>]` — publish a cached image. `as` lets you retag on push
        // (e.g. `kern push myapp as ghcr.io/me/myapp:1.0`).
        Some("push") => {
            let args: Vec<&&str> = rest
                .iter()
                .skip(1)
                .filter(|a| !a.starts_with('-'))
                .collect();
            let local = args
                .first()
                .map(|s| s.to_string())
                .ok_or(Error::Usage("push <local-ref> [as <remote-ref>]"))?;
            // Optional `as <remote>` (or just a second positional). A DANGLING `as` with no ref after
            // it is a usage error, NOT a silent fall-through to the local ref — otherwise
            // `kern push myimg as` would push to Docker Hub as `library/myimg` unintentionally.
            let remote = match args.get(1) {
                Some(s) if **s == "as" => Some(args.get(2).map(|s| s.to_string()).ok_or(
                    Error::Usage("push <local-ref> as <remote-ref> (remote-ref missing)"),
                )?),
                Some(s) => Some(s.to_string()),
                None => None,
            };
            Command::Push { local, remote }
        }
        // `tag <src> <dst>`: give a cached image a second name.
        Some("tag") => {
            let args: Vec<&&str> = rest
                .iter()
                .skip(1)
                .filter(|a| !a.starts_with('-'))
                .collect();
            let src = args
                .first()
                .map(|s| s.to_string())
                .ok_or(Error::Usage("tag <src> <dst>"))?;
            let dst = args
                .get(1)
                .map(|s| s.to_string())
                .ok_or(Error::Usage("tag <src> <dst>"))?;
            Command::Tag { src, dst }
        }
        // `images`: list pulled (cached) images.
        Some("images") => Command::Images {
            json: rest.contains(&"--json"),
        },
        // `rmi <image>...`: delete cached images (the counterpart to `pull`).
        Some("rmi") => Command::Rmi {
            images: rest.iter().skip(1).map(|s| s.to_string()).collect(),
        },
        Some("save") => {
            let (mut image, mut out) = (None, None);
            let mut it = rest.iter().skip(1);
            while let Some(a) = it.next() {
                match *a {
                    "-o" | "--output" => {
                        out = Some(
                            it.next()
                                .ok_or(Error::Usage("save <image> -o <file>"))?
                                .to_string(),
                        )
                    }
                    s if !s.starts_with('-') && image.is_none() => image = Some(s.to_string()),
                    _ => return Err(Error::Usage("save <image> [-o <file>]")),
                }
            }
            Command::Save {
                image: image.ok_or(Error::Usage("save <image> [-o <file>]"))?,
                out,
            }
        }
        Some("load") => {
            let mut input = None;
            let mut it = rest.iter().skip(1);
            while let Some(a) = it.next() {
                match *a {
                    "-i" | "--input" => {
                        input = Some(it.next().ok_or(Error::Usage("load -i <file>"))?.to_string())
                    }
                    _ => return Err(Error::Usage("load [-i <file>]")),
                }
            }
            Command::Load { input }
        }
        Some("builds") => {
            let mut json = false;
            let (mut filter, mut status, mut limit) = (None, None, None);
            let mut it = rest.iter().skip(1);
            while let Some(a) = it.next() {
                match *a {
                    "--json" => json = true,
                    "--status" => {
                        status = Some(
                            it.next()
                                .ok_or(Error::Usage(
                                    "builds --status <ok|warn|failed|interrupted>",
                                ))?
                                .to_string(),
                        )
                    }
                    "-n" | "--limit" => {
                        limit = Some(
                            it.next()
                                .and_then(|n| n.parse().ok())
                                .ok_or(Error::Usage("builds -n <N>"))?,
                        )
                    }
                    // The first bare word is a tag-substring filter (`kern builds web`).
                    s if !s.starts_with('-') && filter.is_none() => filter = Some(s.to_string()),
                    _ => return Err(Error::Usage("builds [<tag>] [--status S] [-n N] [--json]")),
                }
            }
            Command::Builds {
                json,
                filter,
                status,
                limit,
            }
        }
        // `stop <name>` / `kill <name>`: stop running box(es). kern's `stop` already SIGKILLs the
        // box's process group, so `kill` is a Docker-parity alias. `killall` = `stop --all`.
        Some("stop" | "kill") => {
            let all = rest.iter().any(|a| *a == "--all" || *a == "-a");
            let names: Vec<String> = rest
                .iter()
                .skip(1)
                .filter(|a| !a.starts_with('-'))
                .map(|s| (*s).to_string())
                .collect();
            if !all && names.is_empty() {
                return Err(Error::Usage("stop <name>... | stop --all"));
            }
            Command::Stop { names, all }
        }
        Some("killall") => Command::Stop {
            names: Vec::new(),
            all: true,
        },
        // `pause`/`unpause` (aka `freeze`/`unfreeze`): freeze/thaw box(es) via the cgroup freezer.
        Some(v @ ("pause" | "freeze" | "unpause" | "unfreeze" | "resume")) => {
            let freeze = matches!(v, "pause" | "freeze");
            let all = rest.iter().any(|a| *a == "--all" || *a == "-a");
            let names: Vec<String> = rest
                .iter()
                .skip(1)
                .filter(|a| !a.starts_with('-'))
                .map(|s| (*s).to_string())
                .collect();
            if !all && names.is_empty() {
                return Err(Error::Usage(
                    "pause <name>... | pause --all (also: unpause)",
                ));
            }
            Command::Pause { names, all, freeze }
        }
        // `attach <name>`: follow a detached box's output live.
        Some("attach") => match rest.get(1) {
            Some(n) if !n.starts_with('-') => Command::Attach {
                name: (*n).to_string(),
            },
            _ => return Err(Error::Usage("attach <name>")),
        },
        // `cp <src> <dst>`: copy a file host<->box (one side is `<box>:<path>`).
        Some("cp") => {
            let pos: Vec<&str> = rest
                .iter()
                .skip(1)
                .filter(|a| !a.starts_with('-'))
                .copied()
                .collect();
            match pos.as_slice() {
                [src, dst] => Command::Cp {
                    src: (*src).to_string(),
                    dst: (*dst).to_string(),
                },
                _ => {
                    return Err(Error::Usage(
                        "cp <box>:<src> <hostdst>  |  cp <hostsrc> <box>:<dst>",
                    ))
                }
            }
        }
        // `ps`: list running boxes.
        Some("ps") => Command::Ps {
            json: rest.contains(&"--json"),
        },
        // `stats`: per-box memory + CPU.
        Some("stats") => Command::Stats {
            json: rest.contains(&"--json"),
            names: rest[1..]
                .iter()
                .filter(|a| !a.starts_with('-'))
                .map(|s| (*s).to_string())
                .collect(),
        },
        // `logs <name>`: a box's captured output.
        Some("logs") => match rest.get(1) {
            Some(n) if !n.starts_with('-') => Command::Logs {
                name: (*n).to_string(),
            },
            _ => return Err(Error::Usage("logs <name>")),
        },
        // `inspect <name> [--json]`: full detail for one box.
        Some("inspect") => match rest.iter().skip(1).find(|a| !a.starts_with('-')) {
            Some(n) => Command::Inspect {
                name: (*n).to_string(),
                json: rest.contains(&"--json"),
            },
            None => return Err(Error::Usage("inspect <name> [--json]")),
        },
        // `prune`: GC leftover logs/health/registry files of boxes no longer running.
        Some("prune") => Command::Prune,
        // `gc [--images]`: prune dead-box leftovers (+ the image cache with `--images`).
        Some("gc") => Command::Gc {
            images: rest.contains(&"--images"),
        },
        // `doctor`: environment preflight. `info`: runtime snapshot.
        Some("doctor") => Command::Doctor,
        Some("info") => Command::Info,
        // `probe`: a top-level alias for `config probe` — the short form a newcomer reaches for first.
        Some("probe") => Command::Config {
            sub: "probe".into(),
            force: false,
        },
        // `bench [--rootfs R] [-n N]`: measure box start→exit latency.
        Some("bench") => Command::Bench {
            rootfs: flag_value(&rest, "--rootfs"),
            count: flag_value(&rest, "-n")
                .or_else(|| flag_value(&rest, "--count"))
                .and_then(|v| v.parse().ok())
                .filter(|n| *n >= 1)
                .unwrap_or(20),
        },
        Some("recover") => Command::Recover,
        Some("history") => Command::History {
            count: flag_value(&rest, "-n")
                .and_then(|v| v.parse().ok())
                .filter(|n| *n >= 1)
                .unwrap_or(20),
        },
        // `login [registry] [--username U]` / `logout [registry]`: registry credentials.
        Some("login") => {
            let username = flag_value(&rest, "--username").or_else(|| flag_value(&rest, "-u"));
            // The positional registry is the first bare token that ISN'T the value of `--username`/`-u`.
            let registry = positional_after_flags(&rest, &["--username", "-u"]);
            Command::Login { registry, username }
        }
        Some("logout") => Command::Logout {
            registry: positional_after_flags(&rest, &[]),
        },
        // `completions <bash|zsh|fish>`: print a shell-completion script.
        Some("completions") => match rest.get(1) {
            Some(s) if !s.starts_with('-') => Command::Completions {
                shell: (*s).to_string(),
            },
            _ => return Err(Error::Usage("completions <bash|zsh|fish>")),
        },
        // `top`: live box monitor.
        Some("top") => Command::Top,
        // `compose <file> [up|down] [--no-pod]`: bring up / tear down a stack.
        Some("compose") => {
            let mut file: Option<String> = None;
            let mut down = false;
            let mut no_pod = false;
            for a in rest.iter().skip(1) {
                match *a {
                    "up" => {}
                    "down" | "stop" => down = true,
                    "--no-pod" => no_pod = true,
                    f if !f.starts_with('-') && file.is_none() => file = Some(f.to_string()),
                    _ => return Err(Error::Usage("compose <file> [up|down] [--no-pod]")),
                }
            }
            Command::Compose {
                file: file.ok_or(Error::Usage("compose <file> [up|down] [--no-pod]"))?,
                down,
                no_pod,
            }
        }
        // `up [--no-pod]` / `down`: Docker-familiar shorthands that DISCOVER a compose file in the CWD
        // (`docker-compose.yml`/`compose.yml`/…) and bring it up / tear it down. The whole point of the
        // compat surface: land in a dir with a compose file, type `kern up`, it just works.
        Some("up") | Some("down") => {
            let down = rest.first().copied() == Some("down");
            let no_pod = rest.contains(&"--no-pod");
            let file = discover_compose_file().ok_or_else(|| {
                Error::Compose(
                    "no compose file in this directory (looked for docker-compose.yml, compose.yml, compose.yaml, kern.toml)".to_string(),
                )
            })?;
            Command::Compose { file, down, no_pod }
        }
        // `config`: list resource profiles from kern.toml.
        Some("config" | "cfg") => {
            let sub = rest
                .get(1)
                .filter(|s| !s.starts_with('-'))
                .map(|s| (*s).to_string())
                .unwrap_or_else(|| "list".into());
            match sub.as_str() {
                "list" | "edit" | "setup" | "probe" | "clear" => Command::Config {
                    force: rest
                        .iter()
                        .any(|a| *a == "--force" || *a == "--yes" || *a == "-y"),
                    sub,
                },
                "add" => Command::ConfigAdd {
                    args: rest.iter().skip(2).map(|s| (*s).to_string()).collect(),
                },
                "rm" | "remove" | "delete" => Command::ConfigRm {
                    args: rest.iter().skip(2).map(|s| (*s).to_string()).collect(),
                },
                _ => return Err(Error::Usage("config [list|add|rm|edit|setup|probe|clear]")),
            }
        }
        // `validate [path]`: parse a kern.toml and report OK or the offending line.
        Some("validate") => Command::Validate {
            path: rest
                .iter()
                .skip(1)
                .find(|a| !a.starts_with('-'))
                .map(|s| (*s).to_string()),
        },
        // `examples`: print an example kern.toml.
        Some("examples" | "example") => Command::Examples,
        // `volume <sub> …`: manage named volumes.
        Some("volume" | "vol") => Command::Volume {
            args: rest.iter().skip(1).map(|s| (*s).to_string()).collect(),
        },
        // `run [--memory M] [--cpus N] [--] <cmd...>`: cap a command without a full sandbox.
        Some("run") => parse_run(&rest)?,
        Some(other) => return Err(Error::UnknownCommand(other.to_string())),
    };
    Ok((opts, cmd))
}

/// Parse the `box` subcommand. `--plan` previews the isolation sequence (no privileges);
/// `--rootfs <dir>` or `--image <ref>` runs the command (after `--`, default `/bin/sh`) in a
/// real sandbox. Without a rootfs/image it still routes to `BoxRun` (which reports the missing
/// source); `--plan` previews instead of running.
fn parse_box(rest: &[&str]) -> Result<Command, Error> {
    let mut name: Option<&str> = None;
    let mut rootfs: Option<String> = None;
    let mut image: Option<String> = None;
    let mut plan = false;
    let mut detached = false;
    let mut read_only = false;
    let mut share_net = false;
    let mut pod: Option<String> = None;
    let mut uid_range = false;
    let mut bind_rootfs = false;
    let mut privileged = false;
    let mut overlay_lower: Option<String> = None;
    let mut overlay_upper: Option<String> = None;
    let mut tty = false;
    let mut restart = commands::RestartPolicy::No;
    let mut health_cmd: Option<String> = None;
    let mut health_interval = 30u64;
    let mut health_retries = 3u32;
    let mut health_start_period = 0u64;
    let mut health_timeout = 0u64;
    let mut health_action: Option<String> = None;
    let mut env_file: Vec<String> = Vec::new();
    let mut timeout = 0u64;
    let mut nice: Option<i64> = None;
    let mut io_weight: Option<u64> = None;
    let mut config: Option<String> = None;
    let mut show_config = false;
    let mut quiet = false;
    let mut verbose = false;
    let mut ports: Vec<kern_isolation::PortMap> = Vec::new();
    let mut add_hosts: Vec<(String, String)> = Vec::new();
    let mut secrets: Vec<String> = Vec::new();
    let mut ssh_port: Option<u16> = None;
    let mut ssh_key: Option<String> = None;
    let mut hostname: Option<String> = None;
    let mut tun = false;
    let mut init = false;
    let mut pids_limit: Option<u64> = None;
    let mut tmpfs: Vec<String> = Vec::new();
    let mut run_as: Option<String> = None;
    let mut cap_add: Vec<String> = Vec::new();
    let mut cap_drop: Vec<String> = Vec::new();
    let mut memory: Option<u64> = None;
    let mut memory_swap_max: Option<u64> = None;
    let mut cpus: Option<f64> = None;
    let mut cpuset: Option<String> = None;
    let mut volumes: Vec<String> = Vec::new();
    let mut env: Vec<String> = Vec::new();
    let mut workdir: Option<String> = None;
    let mut command: Vec<String> = Vec::new();
    let mut profiles: Vec<String> = Vec::new();
    let mut after_dd = false;
    let mut i = 1; // rest[0] == "box"
    while i < rest.len() {
        let a = rest[i];
        if after_dd {
            command.push(a.to_string());
        } else {
            match a {
                "--" => after_dd = true,
                "--plan" => plan = true,
                "-d" | "--detach" => detached = true,
                "--read-only" | "--ro" => read_only = true,
                // `--net` is Docker-shaped and value-OPTIONAL: bare `--net` shares the host network
                // (back-compat), and `--net host`/`--net none` are honored too. Before, `--net none`
                // set share=true and silently dropped the `none` token — a Docker user's muscle-memory
                // isolation request produced a LESS-isolated box with no error.
                "--net" => match rest.get(i + 1).copied() {
                    Some("host") => {
                        share_net = true;
                        i += 1;
                    }
                    Some("none") => {
                        share_net = false;
                        i += 1;
                    }
                    // A non-flag token that isn't host|none is a Docker network mode kern has no
                    // concept of (`bridge`, a named network, …): reject it with the same message
                    // `--network` gives, instead of sharing the host net and swallowing it as the box
                    // name — the box name goes FIRST (`kern box NAME --net`).
                    Some(v) if !v.starts_with('-') => {
                        return Err(Error::Usage(
                            "--net <host|none> (host = share host net; none = isolated)",
                        ));
                    }
                    // Bare `--net`, or `--net` before another flag / `--` / end-of-args = share host net.
                    _ => share_net = true,
                },
                "--pod" => {
                    i += 1;
                    pod = Some(rest.get(i).ok_or(Error::Usage("--pod <name>"))?.to_string());
                }
                // `--network host|none`: the Docker-style spelling. `host` shares the host network
                // (= `--net`); `none` is the default isolated loopback-only namespace, made explicit.
                "--network" => {
                    i += 1;
                    match rest.get(i).copied() {
                        Some("host") => share_net = true,
                        Some("none") => share_net = false,
                        _ => {
                            return Err(Error::Usage(
                                "--network <host|none> (host = share host net; none = isolated)",
                            ))
                        }
                    }
                }
                // `--tun`: expose /dev/net/tun so a WireGuard / userspace-VPN workload can create a
                // tunnel inside the box's own network namespace.
                "--tun" => tun = true,
                "--init" => init = true,
                // `--hostname NAME`: override the box's UTS hostname (default: the box name).
                "--hostname" => {
                    i += 1;
                    match rest.get(i) {
                        Some(v) => hostname = Some((*v).to_string()),
                        None => return Err(Error::Usage("--hostname <name>")),
                    }
                }
                // `--pids-limit N`: cap the box's task count (`pids.max`) — fork-bomb containment.
                "--pids-limit" => {
                    i += 1;
                    match rest
                        .get(i)
                        .and_then(|v| v.parse::<u64>().ok())
                        .filter(|n| *n >= 1)
                    {
                        Some(n) => pids_limit = Some(n),
                        None => return Err(Error::Usage("--pids-limit <N> (>= 1, e.g. 256)")),
                    }
                }
                // `--tmpfs PATH[:size]`: mount a fresh tmpfs inside the box (repeatable).
                "--tmpfs" => {
                    i += 1;
                    match rest.get(i) {
                        Some(v) => tmpfs.push((*v).to_string()),
                        None => return Err(Error::Usage("--tmpfs /path[:size] (e.g. /tmp:64m)")),
                    }
                }
                // `--user UID[:GID]` / `-u`: run the box command as this uid/gid.
                "--user" | "-u" => {
                    i += 1;
                    match rest.get(i) {
                        Some(v) => run_as = Some((*v).to_string()),
                        None => {
                            return Err(Error::Usage("--user <uid[:gid]> (e.g. 1000 or 1000:1000)"))
                        }
                    }
                }
                // `--cap-add CAP` / `--cap-drop CAP` (repeatable; CAP name or ALL).
                "--cap-add" => {
                    i += 1;
                    match rest.get(i) {
                        Some(v) => cap_add.push((*v).to_string()),
                        None => {
                            return Err(Error::Usage("--cap-add <CAP> (e.g. NET_ADMIN, or ALL)"))
                        }
                    }
                }
                "--cap-drop" => {
                    i += 1;
                    match rest.get(i) {
                        Some(v) => cap_drop.push((*v).to_string()),
                        None => {
                            return Err(Error::Usage("--cap-drop <CAP> (e.g. NET_RAW, or ALL)"))
                        }
                    }
                }
                "--uid-range" => uid_range = true,
                "--bind-rootfs" => bind_rootfs = true,
                "--privileged" => privileged = true,
                // Internal build-layer flags (see the Command::BoxRun docs) — take a value.
                "--overlay-lower" => {
                    i += 1;
                    overlay_lower = Some(
                        rest.get(i)
                            .ok_or(Error::Usage("--overlay-lower <dir>"))?
                            .to_string(),
                    );
                }
                "--overlay-upper" => {
                    i += 1;
                    overlay_upper = Some(
                        rest.get(i)
                            .ok_or(Error::Usage("--overlay-upper <dir>"))?
                            .to_string(),
                    );
                }
                // `--restart [policy]`: no | on-failure | always | unless-stopped. `always`/
                // `unless-stopped` persist via a systemd user unit (survive reboot); `on-failure`
                // uses kern's in-process supervisor. A bare `--restart` = on-failure (back-compat) —
                // an unrecognized next token is left for the parser, not swallowed.
                "--restart" => {
                    match rest
                        .get(i + 1)
                        .and_then(|v| commands::RestartPolicy::parse(v))
                    {
                        Some(p) => {
                            restart = p;
                            i += 1;
                        }
                        None => restart = commands::RestartPolicy::OnFailure,
                    }
                }
                // `--health-cmd <cmd>`: shell command run periodically in the box; exit 0 = healthy.
                "--health-cmd" => {
                    i += 1;
                    match rest.get(i) {
                        Some(c) => health_cmd = Some((*c).to_string()),
                        None => return Err(Error::Usage("--health-cmd <shell command>")),
                    }
                }
                // `--health-interval <sec>`: seconds between health checks (default 30).
                "--health-interval" => {
                    i += 1;
                    match rest
                        .get(i)
                        .and_then(|v| v.parse::<u64>().ok())
                        .filter(|s| *s > 0)
                    {
                        Some(s) => health_interval = s,
                        None => return Err(Error::Usage("--health-interval <seconds> (e.g. 10)")),
                    }
                }
                // `--health-retries <n>`: consecutive failures before "unhealthy" (default 3).
                "--health-retries" => {
                    i += 1;
                    match rest
                        .get(i)
                        .and_then(|v| v.parse::<u32>().ok())
                        .filter(|n| *n >= 1)
                    {
                        Some(n) => health_retries = n,
                        None => return Err(Error::Usage("--health-retries <n> (>= 1, e.g. 3)")),
                    }
                }
                // `--health-start-period <sec>`: grace period where failures keep "starting".
                "--health-start-period" => {
                    i += 1;
                    match rest.get(i).and_then(|v| v.parse::<u64>().ok()) {
                        Some(s) => health_start_period = s,
                        None => {
                            return Err(Error::Usage("--health-start-period <seconds> (e.g. 5)"))
                        }
                    }
                }
                // `--health-timeout <sec>`: kill a single check that exceeds this (0 = no timeout).
                "--health-timeout" => {
                    i += 1;
                    match rest.get(i).and_then(|v| v.parse::<u64>().ok()) {
                        Some(s) => health_timeout = s,
                        None => return Err(Error::Usage("--health-timeout <seconds> (e.g. 5)")),
                    }
                }
                // `--health-action <restart|stop|none>`: action when the box turns unhealthy.
                "--health-action" => {
                    i += 1;
                    match rest.get(i).copied() {
                        Some(a @ ("restart" | "stop" | "none")) => {
                            health_action = Some(a.to_string())
                        }
                        _ => return Err(Error::Usage("--health-action <restart|stop|none>")),
                    }
                }
                // `--env-file <file>` (repeatable): read K=V lines into the environment.
                "--env-file" => {
                    i += 1;
                    match rest.get(i) {
                        Some(v) => env_file.push((*v).to_string()),
                        None => return Err(Error::Usage("--env-file <file>")),
                    }
                }
                // `--timeout <sec>`: auto-stop the box after N seconds.
                "--timeout" => {
                    i += 1;
                    match rest.get(i).and_then(|v| v.parse::<u64>().ok()) {
                        Some(s) => timeout = s,
                        None => return Err(Error::Usage("--timeout <seconds> (e.g. 60)")),
                    }
                }
                // `--nice <n>`: scheduling niceness (-20..19).
                "--nice" => {
                    i += 1;
                    match rest
                        .get(i)
                        .and_then(|v| v.parse::<i64>().ok())
                        .filter(|n| (-20..=19).contains(n))
                    {
                        Some(n) => nice = Some(n),
                        None => return Err(Error::Usage("--nice <n> (-20..19)")),
                    }
                }
                // `--io-weight <n>`: cgroup io.weight (1..10000).
                "--io-weight" => {
                    i += 1;
                    match rest
                        .get(i)
                        .and_then(|v| v.parse::<u64>().ok())
                        .filter(|n| (1..=10000).contains(n))
                    {
                        Some(n) => io_weight = Some(n),
                        None => return Err(Error::Usage("--io-weight <n> (1..10000)")),
                    }
                }
                // `--config <path>`: a specific kern.toml for this invocation.
                "--config" => {
                    i += 1;
                    match rest.get(i) {
                        Some(v) => config = Some((*v).to_string()),
                        None => return Err(Error::Usage("--config <path-to-kern.toml>")),
                    }
                }
                "--show-config" => show_config = true,
                "-q" | "--quiet" => quiet = true,
                "--verbose" => verbose = true,
                // `-it`/`-ti`/`-t`/`-i`: allocate an interactive PTY for the box (shells, REPLs).
                "-it" | "-ti" | "-t" | "-i" | "--tty" | "--interactive" => tty = true,
                "--rootfs" => {
                    i += 1;
                    rootfs = rest.get(i).map(|v| (*v).to_string());
                }
                "--image" => {
                    i += 1;
                    image = rest.get(i).map(|v| (*v).to_string());
                }
                "-v" | "--volume" => {
                    i += 1;
                    if let Some(v) = rest.get(i) {
                        volumes.push((*v).to_string());
                    }
                }
                "-e" | "--env" => {
                    i += 1;
                    if let Some(v) = rest.get(i) {
                        env.push((*v).to_string());
                    }
                }
                "-w" | "--workdir" => {
                    i += 1;
                    workdir = rest.get(i).map(|v| (*v).to_string());
                }
                "-p" | "--publish" => {
                    i += 1;
                    match rest.get(i).and_then(|v| crate::ports::parse(v)) {
                        Some(p) => ports.extend(p), // one mapping, or many for a port range
                        None => {
                            return Err(Error::Usage(
                                "-p [ip:]<hostport>:<boxport>[/tcp|/udp] (e.g. 8080:80 or 8000-8010:8000-8010)",
                            ))
                        }
                    }
                }
                "--add-host" => {
                    i += 1;
                    // `NAME:IP` — the name has no colon, so split on the first `:` (IP is v4 or the
                    // `host-gateway` keyword). Both halves must be non-empty.
                    match rest.get(i).and_then(|v| v.split_once(':')) {
                        Some((n, ip)) if !n.is_empty() && !ip.is_empty() => {
                            add_hosts.push((n.to_string(), ip.to_string()))
                        }
                        _ => {
                            return Err(Error::Usage(
                                "--add-host <name>:<ip> (ip may be host-gateway)",
                            ))
                        }
                    }
                }
                "--secret" => {
                    i += 1;
                    match rest.get(i) {
                        Some(v) => secrets.push((*v).to_string()),
                        None => {
                            return Err(Error::Usage(
                                "--secret SRC[:NAME] | NAME=value | NAME=- (from stdin)",
                            ))
                        }
                    }
                }
                "--ssh" => {
                    i += 1;
                    match rest
                        .get(i)
                        .and_then(|v| v.parse::<u16>().ok())
                        .filter(|p| *p > 0)
                    {
                        Some(p) => ssh_port = Some(p),
                        None => return Err(Error::Usage("--ssh <host-port> (1-65535, e.g. 2222)")),
                    }
                }
                "--ssh-key" => {
                    i += 1;
                    match rest.get(i) {
                        Some(v) => ssh_key = Some((*v).to_string()),
                        None => return Err(Error::Usage("--ssh-key <public-key-file>")),
                    }
                }
                "-m" | "--memory" => {
                    i += 1;
                    match rest.get(i).and_then(|v| parse_size(v)) {
                        Some(b) => memory = Some(b),
                        None => return Err(Error::Usage(USAGE_MEMORY)),
                    }
                }
                "--cpus" => {
                    i += 1;
                    match rest
                        .get(i)
                        .and_then(|v| v.parse::<f64>().ok())
                        .filter(|c| *c > 0.0 && c.is_finite())
                    {
                        Some(c) => cpus = Some(c),
                        None => return Err(Error::Usage(USAGE_CPUS)),
                    }
                }
                "--cpuset-cpus" => {
                    i += 1;
                    match rest.get(i).filter(|v| is_cpu_list(v)) {
                        Some(v) => cpuset = Some((*v).to_string()),
                        None => return Err(Error::Usage(USAGE_CPUSET)),
                    }
                }
                "--memory-swap-max" => {
                    i += 1;
                    match rest.get(i).and_then(|v| parse_size_z(v)) {
                        Some(b) => memory_swap_max = Some(b),
                        None => return Err(Error::Usage(USAGE_SWAP_MAX)),
                    }
                }
                // Reject Docker's `--memory-swap` explicitly (don't alias it): on pure cgroup v2 the
                // swap limit is a SEPARATE knob (`memory.swap.max`), not Docker's combined mem+swap
                // total — aliasing would silently mean something different. Point to the honest flag.
                "--memory-swap" => return Err(Error::Usage(REJECT_MEMORY_SWAP)),
                // Reject an unknown flag rather than silently ignoring it: a typo'd `--read-only`
                // must NOT quietly run a writable box. (Flags after `--` are part of the command.)
                s if s.starts_with('-') => {
                    return Err(Error::Usage("box: unknown flag (see --help)"))
                }
                // A `vcpu:`/`vgpio:`/`vdisk:`/`vgpu:` token is a resource profile, not the box name.
                s if crate::config::classify(s).is_some() => profiles.push(s.to_string()),
                s if name.is_none() => name = Some(s),
                // A SECOND bare token (name already set, not a flag, not a profile) is junk — almost
                // always a command the user forgot to put after `--`. Reject it rather than silently
                // dropping it (same anti-footgun rule as the unknown-flag arm above).
                _ => {
                    return Err(Error::Usage(
                        "box: unexpected argument (did you forget `--` before the command?)",
                    ))
                }
            }
        }
        i += 1;
    }
    // Two `-p` mappings can't share the same host address+port (one host port → one box port). Catch
    // this impossible config here rather than let the second forwarder silently fail to bind.
    for a in 0..ports.len() {
        for b in (a + 1)..ports.len() {
            if ports[a].bind_ip == ports[b].bind_ip && ports[a].host == ports[b].host {
                return Err(Error::Usage(
                    "duplicate -p host port (one host port maps to a single box port)",
                ));
            }
        }
    }
    // Always route to the real command; missing name → BoxName rejects it, missing rootfs/image
    // → box_run reports it. `--plan` wins (non-destructive preview).
    let cmd = if plan {
        Command::BoxPlan {
            name: name.unwrap_or_default().to_string(),
        }
    } else {
        Command::BoxRun {
            // The name is optional (Docker-style): omit it and kern assigns `box-<pid>`, so a quick
            // `kern box --image alpine -- sh` needs no invented name.
            name: name
                .map(str::to_string)
                .unwrap_or_else(|| format!("box-{}", std::process::id())),
            rootfs,
            image,
            command,
            detached,
            read_only,
            volumes,
            env,
            workdir,
            share_net,
            pod,
            uid_range,
            bind_rootfs,
            privileged,
            overlay_lower,
            overlay_upper,
            memory,
            memory_swap_max,
            cpus,
            cpuset,
            tty,
            ports,
            add_hosts,
            secrets,
            ssh_port,
            ssh_key,
            hostname,
            tun,
            init,
            pids_limit,
            tmpfs,
            run_as,
            cap_add,
            cap_drop,
            restart,
            health_cmd,
            health_interval,
            health_retries,
            health_start_period,
            health_timeout,
            health_action,
            env_file,
            timeout,
            nice,
            io_weight,
            config,
            show_config,
            quiet,
            verbose,
            profiles,
        }
    };
    Ok(cmd)
}

/// Parse `run [--memory M] [--cpus N] [--] <cmd...>`. Flags come first; the first bare token (or
/// everything after `--`) begins the command, after which nothing is treated as a flag. An empty
/// command is a usage error.
fn parse_run(rest: &[&str]) -> Result<Command, Error> {
    let mut memory: Option<u64> = None;
    let mut memory_swap_max: Option<u64> = None;
    let mut cpus: Option<f64> = None;
    let mut cpuset: Option<String> = None;
    let mut config: Option<String> = None;
    let mut command: Vec<String> = Vec::new();
    let mut i = 1; // rest[0] == "run"
    while i < rest.len() {
        match rest[i] {
            "--" => {
                // Preserve the `--` as the first command token so `peel_run_profiles` knows the command
                // was EXPLICITLY delimited and must NOT re-classify a leading `vcpu:`/`vgpio:`/`vdisk:`
                // token as a profile. Without this, `kern run -- vcpu:heavy prog` would strip `vcpu:heavy`
                // as a profile (violating the `--` end-of-options contract, and diverging from `box`).
                command.push("--".to_string());
                command.extend(rest[i + 1..].iter().map(|s| (*s).to_string()));
                break;
            }
            "--config" => {
                i += 1;
                match rest.get(i) {
                    Some(v) => config = Some((*v).to_string()),
                    None => return Err(Error::Usage("--config <path/to/kern.toml>")),
                }
            }
            "-m" | "--memory" => {
                i += 1;
                match rest.get(i).and_then(|v| parse_size(v)) {
                    Some(b) => memory = Some(b),
                    None => return Err(Error::Usage(USAGE_MEMORY)),
                }
            }
            "--memory-swap-max" => {
                i += 1;
                match rest.get(i).and_then(|v| parse_size_z(v)) {
                    Some(b) => memory_swap_max = Some(b),
                    None => return Err(Error::Usage(USAGE_SWAP_MAX)),
                }
            }
            "--memory-swap" => return Err(Error::Usage(REJECT_MEMORY_SWAP)),
            "--cpus" => {
                i += 1;
                match rest
                    .get(i)
                    .and_then(|v| v.parse::<f64>().ok())
                    .filter(|c| *c > 0.0 && c.is_finite())
                {
                    Some(c) => cpus = Some(c),
                    None => return Err(Error::Usage(USAGE_CPUS)),
                }
            }
            "--cpuset-cpus" => {
                i += 1;
                match rest.get(i).filter(|v| is_cpu_list(v)) {
                    Some(v) => cpuset = Some((*v).to_string()),
                    None => return Err(Error::Usage(USAGE_CPUSET)),
                }
            }
            s if s.starts_with('-') => {
                return Err(Error::Usage(
                    "run: unknown flag (put `--` before the command)",
                ))
            }
            // First bare token → the command starts here; everything from here on is the command.
            _ => {
                command.extend(rest[i..].iter().map(|s| (*s).to_string()));
                break;
            }
        }
        i += 1;
    }
    if command.is_empty() {
        return Err(Error::Usage(
            "run [--memory M] [--memory-swap-max S] [--cpus N] [--cpuset-cpus L] [--config F] [vcpu:PROFILE] [--] <cmd...>",
        ));
    }
    Ok(Command::Run {
        command,
        memory,
        memory_swap_max,
        cpus,
        cpuset,
        config,
    })
}

/// Like [`parse_size`] but accepts an explicit `0`. Used for `--memory-swap-max`, where `0` is a
/// meaningful, valid value (zero swap allowance = swap off — the default) rather than a nonsense cap.
fn parse_size_z(s: &str) -> Option<u64> {
    if s.trim() == "0" {
        Some(0)
    } else {
        parse_size(s)
    }
}

/// Parse a memory size like `512m`, `1g`, `512mb`, `2t`, or a bare `268435456` (= bytes) into bytes.
/// Units are binary (k = 1024). Returns `None` on a malformed value — the caller turns that into a
/// usage error. Delegates to the shared [`kern_common::parse_binary_size`] so `--memory`, `--size`
/// and profile size fields can never disagree on what `512m` means.
fn parse_size(s: &str) -> Option<u64> {
    kern_common::parse_binary_size(s)
}

/// A valid `--cpuset-cpus` list (`0-3`, `0,2,4`, `1-2,5`): the SAME rule the profile `cpus` field
/// uses, so the flag and the profiles can't disagree. See [`crate::config::is_cpu_list`]. Validating
/// at the parse boundary means a typo can't silently produce an *unpinned* box, and only digits/`,`/`-`
/// survive the numeric parse — no arbitrary string reaches the kernel's `cpuset.cpus`.
fn is_cpu_list(s: &str) -> bool {
    crate::config::is_cpu_list(s)
}

/// Parse `exec <name> [--env K=V] [--workdir <dir>] [-- cmd...]`. Missing name → usage error.
fn parse_exec(rest: &[&str]) -> Result<Command, Error> {
    let mut name: Option<&str> = None;
    let mut env: Vec<String> = Vec::new();
    let mut workdir: Option<String> = None;
    let mut command: Vec<String> = Vec::new();
    let mut tty = false;
    let mut after_dd = false;
    let mut i = 1; // rest[0] == "exec"
    while i < rest.len() {
        let a = rest[i];
        if after_dd {
            command.push(a.to_string());
        } else {
            match a {
                "--" => after_dd = true,
                "-e" | "--env" => {
                    i += 1;
                    if let Some(v) = rest.get(i) {
                        env.push((*v).to_string());
                    }
                }
                "-w" | "--workdir" => {
                    i += 1;
                    workdir = rest.get(i).map(|v| (*v).to_string());
                }
                "-it" | "-ti" | "-t" | "-i" | "--tty" | "--interactive" => tty = true,
                s if s.starts_with('-') => {
                    return Err(Error::Usage("exec: unknown flag (see --help)"))
                }
                s if name.is_none() => name = Some(s),
                _ => {}
            }
        }
        i += 1;
    }
    match name {
        Some(n) => Ok(Command::Exec {
            name: n.to_string(),
            command,
            env,
            workdir,
            tty,
        }),
        None => Err(Error::Usage("exec <name> [-- cmd...]")),
    }
}

/// Parse `pull <image> [--dest <dir>]`. `None` if no image was given.
/// Value following a `--flag` token in `rest` (e.g. `--username alice`), or `None`.
fn flag_value(rest: &[&str], flag: &str) -> Option<String> {
    rest.iter()
        .position(|a| *a == flag)
        .and_then(|i| rest.get(i + 1))
        .map(|s| (*s).to_string())
}

/// The first bare positional token in `rest[1..]` that is neither an option nor the *value* consumed
/// by one of `value_flags` (so `login --username alice` doesn't read `alice` as the registry).
fn positional_after_flags(rest: &[&str], value_flags: &[&str]) -> Option<String> {
    let mut i = 1; // rest[0] == the verb
    while i < rest.len() {
        let a = rest[i];
        if value_flags.contains(&a) {
            i += 2; // skip the flag and its value
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        return Some(a.to_string());
    }
    None
}

fn parse_pull(rest: &[&str]) -> Option<Command> {
    let mut image: Option<&str> = None;
    let mut dest: Option<String> = None;
    let mut platform: Option<String> = None;
    let mut i = 1; // rest[0] == "pull"
    while i < rest.len() {
        match rest[i] {
            "--dest" => {
                i += 1;
                dest = rest.get(i).map(|v| (*v).to_string());
            }
            "--platform" => {
                i += 1;
                platform = rest.get(i).map(|v| (*v).to_string());
            }
            s if s.starts_with('-') => {}
            s if image.is_none() => image = Some(s),
            _ => {}
        }
        i += 1;
    }
    image.map(|img| Command::Pull {
        image: img.to_string(),
        dest,
        platform,
    })
}

/// `kern pod create <name> [-p [ip:]host:pod]…` | `pod ls` | `pod rm <name>…`.
fn parse_pod(rest: &[&str]) -> Result<Command, Error> {
    match rest.get(1).copied() {
        Some("create" | "new" | "up") => {
            let name = rest
                .iter()
                .skip(2)
                .find(|a| !a.starts_with('-'))
                .ok_or(Error::Usage(
                    "pod create <name> [--no-outbound] [--uid-range]",
                ))?;
            Ok(Command::PodCreate {
                name: name.to_string(),
                outbound: !rest.contains(&"--no-outbound"),
                // Map a subordinate uid range into the pod's shared user namespace, so member OCI
                // images that drop privilege / chown to a fixed uid (postgres, mysql, …) work inside
                // the pod. Without it the holder maps a single uid and such entrypoints fail closed.
                uid_range: rest.contains(&"--uid-range"),
            })
        }
        Some("ls" | "list" | "ps") => Ok(Command::PodList),
        Some("rm" | "remove" | "down") => {
            let names: Vec<String> = rest
                .iter()
                .skip(2)
                .filter(|a| !a.starts_with('-'))
                .map(|s| (*s).to_string())
                .collect();
            if names.is_empty() {
                return Err(Error::Usage("pod rm <name>..."));
            }
            Ok(Command::PodRemove { names })
        }
        _ => Err(Error::Usage(
            "pod create <name> [-p …] | pod ls | pod rm <name>",
        )),
    }
}

/// Discover a compose file in the current directory for `kern up`/`down`. Prefers Docker's canonical
/// names (so an existing project just works), then kern's own. Returns the first that exists.
fn discover_compose_file() -> Option<String> {
    for name in [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
        "kern.toml",
    ] {
        if std::path::Path::new(name).is_file() {
            return Some(name.to_string());
        }
    }
    None
}

/// `kern build -t <name[:tag]> [-f <Dockerfile>] [--build-arg K=V]... [-q] [<context>]`.
fn parse_build(rest: &[&str]) -> Result<Command, Error> {
    // `build <sub> …` — build-history management subcommands. A bare `build … -t <name>` (an actual
    // build) never starts with one of these verbs, so the dispatch is unambiguous. `--json` may sit
    // anywhere after the verb.
    let json = rest.contains(&"--json");
    let first_id = || -> Result<String, Error> {
        rest.iter()
            .skip(2)
            .find(|a| !a.starts_with('-'))
            .map(|s| (*s).to_string())
            .ok_or(Error::Usage("build <logs|inspect|rm> <id>"))
    };
    match rest.get(1).copied() {
        Some("logs") => return Ok(Command::BuildLogs { id: first_id()? }),
        Some("inspect") => {
            return Ok(Command::BuildInspect {
                id: first_id()?,
                json,
            })
        }
        Some("rm" | "remove" | "delete") => {
            let ids: Vec<String> = rest
                .iter()
                .skip(2)
                .filter(|a| !a.starts_with('-'))
                .map(|s| (*s).to_string())
                .collect();
            if ids.is_empty() {
                return Err(Error::Usage("build rm <id>..."));
            }
            return Ok(Command::BuildRm { ids });
        }
        Some("prune") => {
            // `--keep N` (default 20): how many newest records to retain.
            let mut keep = 20usize;
            let mut it = rest.iter().skip(2);
            while let Some(a) = it.next() {
                if *a == "--keep" {
                    keep = it
                        .next()
                        .and_then(|n| n.parse().ok())
                        .ok_or(Error::Usage("build prune --keep <N>"))?;
                }
            }
            return Ok(Command::BuildPrune { keep });
        }
        _ => {}
    }
    let mut tag: Option<String> = None;
    let mut file: Option<String> = None;
    let mut context: Option<String> = None;
    let mut build_args: Vec<String> = Vec::new();
    let mut quiet = false;
    let mut i = 1; // rest[0] == "build"
    while i < rest.len() {
        match rest[i] {
            "-t" | "--tag" => {
                i += 1;
                tag = Some(
                    rest.get(i)
                        .ok_or(Error::Usage("-t <name[:tag]>"))?
                        .to_string(),
                );
            }
            "-f" | "--file" => {
                i += 1;
                file = Some(
                    rest.get(i)
                        .ok_or(Error::Usage("-f <Dockerfile>"))?
                        .to_string(),
                );
            }
            "--build-arg" => {
                i += 1;
                build_args.push(
                    rest.get(i)
                        .ok_or(Error::Usage("--build-arg K=V"))?
                        .to_string(),
                );
            }
            "-q" | "--quiet" => quiet = true,
            s if s.starts_with('-') => return Err(Error::Usage("unknown build flag")),
            s if context.is_none() => context = Some(s.to_string()),
            _ => return Err(Error::Usage("build takes a single context directory")),
        }
        i += 1;
    }
    Ok(Command::Build {
        tag,
        file,
        context: context.unwrap_or_else(|| ".".to_string()),
        build_args,
        quiet,
    })
}

/// Parse and run.
pub fn run(args: &[String]) -> Result<(), Error> {
    let (_opts, cmd) = parse(args)?;
    match cmd {
        Command::Version => commands::version(),
        Command::Banner => commands::banner(),
        Command::Help => commands::help(),
        Command::BoxPlan { name } => commands::box_plan(&name),
        Command::BoxRun {
            name,
            rootfs,
            image,
            command,
            detached,
            read_only,
            volumes,
            env,
            workdir,
            share_net,
            pod,
            uid_range,
            bind_rootfs,
            privileged,
            overlay_lower,
            overlay_upper,
            memory,
            memory_swap_max,
            cpus,
            cpuset,
            tty,
            ports,
            add_hosts,
            secrets,
            ssh_port,
            ssh_key,
            hostname,
            tun,
            init,
            pids_limit,
            tmpfs,
            run_as,
            cap_add,
            cap_drop,
            restart,
            health_cmd,
            health_interval,
            health_retries,
            health_start_period,
            health_timeout,
            health_action,
            env_file,
            timeout,
            nice,
            io_weight,
            config,
            show_config,
            quiet,
            verbose,
            profiles,
        } => commands::box_run(commands::BoxRunArgs {
            name: &name,
            rootfs: rootfs.as_deref(),
            image: image.as_deref(),
            command: &command,
            detached,
            read_only,
            volumes: &volumes,
            env: &env,
            workdir: workdir.as_deref(),
            share_net,
            pod: pod.as_deref(),
            uid_range,
            bind_rootfs,
            privileged,
            overlay_lower: overlay_lower.as_deref(),
            overlay_upper: overlay_upper.as_deref(),
            memory,
            memory_swap_max,
            cpus,
            cpuset: cpuset.as_deref(),
            tty,
            ports: &ports,
            secrets: &secrets,
            ssh_port,
            ssh_key: ssh_key.as_deref(),
            hostname: hostname.as_deref(),
            tun,
            init,
            pids_limit,
            tmpfs: &tmpfs,
            run_as: run_as.as_deref(),
            cap_add: &cap_add,
            cap_drop: &cap_drop,
            restart,
            health_cmd: health_cmd.as_deref(),
            health_interval,
            health_retries,
            health_start_period,
            health_timeout,
            health_action: health_action.as_deref(),
            env_file: &env_file,
            timeout,
            nice,
            io_weight,
            config: config.as_deref(),
            show_config,
            quiet,
            verbose,
            profiles: &profiles,
            add_hosts: &add_hosts,
        }),
        Command::Run {
            command,
            memory,
            memory_swap_max,
            cpus,
            cpuset,
            config,
        } => commands::run(
            &command,
            memory,
            memory_swap_max,
            cpus,
            cpuset.as_deref(),
            config.as_deref(),
        ),
        Command::Exec {
            name,
            command,
            env,
            workdir,
            tty,
        } => commands::exec(&name, &command, &env, workdir.as_deref(), tty),
        Command::Build {
            tag,
            file,
            context,
            build_args,
            quiet,
        } => commands::build(commands::BuildArgs {
            tag: tag.as_deref(),
            file: file.as_deref(),
            context: &context,
            build_args: &build_args,
            quiet,
        }),
        Command::PodCreate {
            name,
            outbound,
            uid_range,
        } => crate::pod::create_with_range(&name, outbound, uid_range),
        Command::PodList => crate::pod::list(),
        Command::PodRemove { names } => crate::pod::remove(&names),
        Command::PodHolder => crate::pod::run_holder(),
        Command::Search { query, json } => commands::search(&query, json),
        Command::Images { json } => commands::images(json),
        Command::Rmi { images } => commands::image_rm(&images),
        Command::Save { image, out } => commands::save(&image, out.as_deref()),
        Command::Load { input } => commands::load(input.as_deref()),
        Command::Builds {
            json,
            filter,
            status,
            limit,
        } => commands::builds_list(json, filter.as_deref(), status.as_deref(), limit),
        Command::BuildLogs { id } => commands::build_logs(&id),
        Command::BuildInspect { id, json } => commands::build_inspect(&id, json),
        Command::BuildRm { ids } => commands::build_rm(&ids),
        Command::BuildPrune { keep } => commands::build_prune(keep),
        Command::Pull {
            image,
            dest,
            platform,
        } => commands::pull(&image, dest.as_deref(), platform.as_deref()),
        Command::Push { local, remote } => commands::push(&local, remote.as_deref()),
        Command::Tag { src, dst } => commands::tag(&src, &dst),
        Command::Stop { names, all } => commands::stop(&names, all),
        Command::Pause { names, all, freeze } => commands::pause(&names, all, freeze),
        Command::Attach { name } => commands::attach(&name),
        Command::Cp { src, dst } => crate::boxcp::cp(&src, &dst),
        Command::Ps { json } => commands::ps(json),
        Command::Stats { json, names } => commands::stats(json, &names),
        Command::Logs { name } => commands::logs(&name),
        Command::Inspect { name, json } => commands::inspect(&name, json),
        Command::Prune => commands::prune(),
        Command::Gc { images } => commands::gc(images),
        Command::Doctor => crate::doctor::doctor(),
        Command::Info => crate::doctor::info(),
        Command::Bench { rootfs, count } => commands::bench(rootfs.as_deref(), count),
        Command::Recover => commands::recover(),
        Command::History { count } => commands::history(count),
        Command::Login { registry, username } => {
            crate::auth::login(registry.as_deref(), username.as_deref())
        }
        Command::Logout { registry } => crate::auth::logout(registry.as_deref()),
        Command::Completions { shell } => crate::completions::completions(&shell),
        Command::Top => commands::top(),
        Command::Compose { file, down, no_pod } => commands::compose(&file, down, no_pod),
        Command::Config { sub, force } => commands::config_cmd(&sub, force),
        Command::ConfigAdd { args } => commands::config_add(&args),
        Command::ConfigRm { args } => commands::config_rm(&args),
        Command::Validate { path } => commands::validate(path.as_deref()),
        Command::Examples => commands::examples(),
        Command::Volume { args } => crate::volume::run(&args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_help_and_banner_resolve() {
        assert_eq!(parse(&["--version".into()]).unwrap().1, Command::Version);
        assert_eq!(parse(&["--help".into()]).unwrap().1, Command::Help);
        assert_eq!(parse(&["help".into()]).unwrap().1, Command::Help);
        // Bare `kern` → the short banner, not the full help.
        assert_eq!(parse(&[]).unwrap().1, Command::Banner);
        // `kern <cmd> --help` / `-h` (any command, any position before `--`) → the full reference,
        // NOT an "unknown flag" error. This is the universal `<tool> <cmd> --help` habit.
        for c in [
            vec!["box", "--help"],
            vec!["run", "-h"],
            vec!["pull", "--help"],
            vec!["push", "--help"],
            vec!["compose", "f.yml", "--help"],
            vec!["exec", "name", "-h"],
        ] {
            let argv: Vec<String> = c.iter().map(|s| s.to_string()).collect();
            assert_eq!(
                parse(&argv).unwrap().1,
                Command::Help,
                "`kern {}` should show help",
                c.join(" ")
            );
        }
        // But a `--help` AFTER `--` is part of the box command, not a help request.
        let argv: Vec<String> = ["box", "n", "--rootfs", "/r", "--", "prog", "--help"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(
            !matches!(parse(&argv).map(|(_, c)| c), Ok(Command::Help)),
            "`--help` after `--` is the command's arg, not a help request"
        );
    }

    #[test]
    fn box_dispatch_and_plan() {
        // `box <name> --plan` → BoxPlan.
        let plan = parse(&["box".into(), "web".into(), "--plan".into()])
            .unwrap()
            .1;
        assert_eq!(plan, Command::BoxPlan { name: "web".into() });
        // `box <name>` with no rootfs/image still routes to BoxRun (box_run reports the missing
        // source) — NOT a misleading "not implemented".
        assert!(matches!(
            parse(&["box".into(), "web".into()]).unwrap().1,
            Command::BoxRun { name, rootfs: None, image: None, .. } if name == "web"
        ));
    }

    #[test]
    fn parse_size_units() {
        assert_eq!(parse_size("512"), Some(512));
        assert_eq!(parse_size("512m"), Some(512 * 1024 * 1024));
        assert_eq!(parse_size("1g"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_size("512mb"), Some(512 * 1024 * 1024));
        assert_eq!(parse_size("1024k"), Some(1024 * 1024));
        assert_eq!(parse_size("0"), None); // zero is not a useful cap
        assert_eq!(parse_size("pippo"), None);
        assert_eq!(parse_size(""), None);
        // `--memory-swap-max` accepts an explicit 0 (swap off), unlike `--memory`.
        assert_eq!(parse_size_z("0"), Some(0));
        assert_eq!(parse_size_z(" 0 "), Some(0));
        assert_eq!(parse_size_z("512m"), Some(512 * 1024 * 1024));
        assert_eq!(parse_size_z("bad"), None);
    }

    #[test]
    fn box_parses_memory_and_cpus() {
        let cmd = parse(&[
            "box".into(),
            "x".into(),
            "--memory".into(),
            "256m".into(),
            "--cpus".into(),
            "1.5".into(),
        ])
        .unwrap()
        .1;
        assert!(matches!(
            cmd,
            Command::BoxRun { memory: Some(m), cpus: Some(c), .. }
                if m == 256 * 1024 * 1024 && (c - 1.5).abs() < 1e-9
        ));
        // Malformed values are usage errors, never silently ignored.
        assert!(matches!(
            parse(&["box".into(), "x".into(), "--memory".into(), "nope".into()]),
            Err(Error::Usage(_))
        ));
        assert!(matches!(
            parse(&["box".into(), "x".into(), "--cpus".into(), "0".into()]),
            Err(Error::Usage(_))
        ));
    }

    #[test]
    fn box_publish_ports() {
        let (_, cmd) = parse(&[
            "box".into(),
            "x".into(),
            "-p".into(),
            "8080:80".into(), // default → 127.0.0.1 (loopback only), tcp
            "-p".into(),
            "0.0.0.0:443:443".into(), // explicit all-interfaces
            "-p".into(),
            "53:53/udp".into(), // explicit udp
        ])
        .unwrap();
        let Command::BoxRun { ports, .. } = cmd else {
            panic!("expected BoxRun")
        };
        let pm = |bind_ip, host, box_port, udp| kern_isolation::PortMap {
            bind_ip,
            host,
            box_port,
            udp,
        };
        assert_eq!(
            ports,
            vec![
                pm(0x7f00_0001, 8080, 80, false),
                pm(0, 443, 443, false),
                pm(0x7f00_0001, 53, 53, true),
            ]
        );
        // Malformed mappings are usage errors, never silently dropped.
        for bad in ["0:80", "abc", "80", "80:0", "999.0.0.1:8080:80"] {
            assert!(
                matches!(
                    parse(&["box".into(), "x".into(), "-p".into(), bad.to_string()]),
                    Err(Error::Usage(_))
                ),
                "-p {bad}"
            );
        }
        // The same host address+port can't map to two box ports (would silently fail to bind twice).
        assert!(matches!(
            parse(&[
                "box".into(),
                "x".into(),
                "-p".into(),
                "19000:80".into(),
                "-p".into(),
                "19000:81".into(),
            ]),
            Err(Error::Usage(_))
        ));
        // …but the same port on DIFFERENT bind addresses is fine.
        assert!(parse(&[
            "box".into(),
            "x".into(),
            "-p".into(),
            "127.0.0.1:19000:80".into(),
            "-p".into(),
            "0.0.0.0:19000:81".into(),
        ])
        .is_ok());
    }

    #[test]
    fn box_it_flag_allocates_tty() {
        for f in ["-it", "-ti", "-t", "-i", "--tty", "--interactive"] {
            let (_, cmd) = parse(&["box".into(), "x".into(), f.to_string()]).unwrap();
            assert!(matches!(cmd, Command::BoxRun { tty: true, .. }), "flag {f}");
        }
        // off by default
        let (_, cmd) = parse(&["box".into(), "x".into()]).unwrap();
        assert!(matches!(cmd, Command::BoxRun { tty: false, .. }));
    }

    #[test]
    fn box_privileged_flag_parses_and_defaults_off() {
        let (_, cmd) = parse(&["box".into(), "x".into(), "--privileged".into()]).unwrap();
        assert!(matches!(
            cmd,
            Command::BoxRun {
                privileged: true,
                ..
            }
        ));
        // off by default — nesting stays blocked unless explicitly requested
        let (_, cmd) = parse(&["box".into(), "x".into()]).unwrap();
        assert!(matches!(
            cmd,
            Command::BoxRun {
                privileged: false,
                ..
            }
        ));
    }

    #[test]
    fn run_parses_flags_then_command() {
        // Flags first, then the command; the first bare token begins the command.
        let (_, cmd) = parse(&[
            "run".into(),
            "--memory".into(),
            "256m".into(),
            "--cpus".into(),
            "2".into(),
            "echo".into(),
            "hi".into(),
        ])
        .unwrap();
        let Command::Run {
            command,
            memory,
            cpus,
            ..
        } = cmd
        else {
            panic!("expected Run")
        };
        assert_eq!(command, ["echo", "hi"]);
        assert_eq!(memory, Some(256 * 1024 * 1024));
        assert_eq!(cpus, Some(2.0));
        // `--` form; flags after it belong to the command. The leading `--` is PRESERVED in the parsed
        // command (so the run profile-peeler knows the command was explicitly delimited and won't
        // re-classify a `vcpu:`-looking first token); `peel_run_profiles` then strips it before exec.
        let (_, cmd) = parse(&["run".into(), "--".into(), "ls".into(), "-la".into()]).unwrap();
        let Command::Run { command, .. } = cmd else {
            panic!()
        };
        assert_eq!(command, ["--", "ls", "-la"]);
        // An unknown flag before the command is a usage error (catches typos), not a silent run.
        assert!(matches!(
            parse(&["run".into(), "--bogus".into()]),
            Err(Error::Usage(_))
        ));
        // Empty command → usage error.
        assert!(matches!(parse(&["run".into()]), Err(Error::Usage(_))));
    }

    // The 0.5 CPU/RAM knob set is frozen: `--cpuset-cpus` (pinning) and `--memory-swap-max` (swap
    // allowance) parse on both `run` and `box`, and Docker's `--memory-swap` (mem+swap total,
    // ambiguous on pure v2) is REJECTED, not silently aliased. These assert the surface stays put.
    #[test]
    fn cpu_ram_flag_freeze() {
        // `run --cpuset-cpus --memory-swap-max` populate the Run fields.
        let (_, cmd) = parse(&[
            "run".into(),
            "--cpuset-cpus".into(),
            "0-3".into(),
            "--memory-swap-max".into(),
            "1g".into(),
            "true".into(),
        ])
        .unwrap();
        let Command::Run {
            cpuset,
            memory_swap_max,
            ..
        } = cmd
        else {
            panic!("expected Run")
        };
        assert_eq!(cpuset.as_deref(), Some("0-3"));
        assert_eq!(memory_swap_max, Some(1024 * 1024 * 1024));

        // Same flags on `box`.
        let (_, cmd) = parse(&[
            "box".into(),
            "x".into(),
            "--cpuset-cpus".into(),
            "0,2,4".into(),
            "--memory-swap-max".into(),
            "512m".into(),
        ])
        .unwrap();
        let Command::BoxRun {
            cpuset,
            memory_swap_max,
            ..
        } = cmd
        else {
            panic!("expected BoxRun")
        };
        assert_eq!(cpuset.as_deref(), Some("0,2,4"));
        assert_eq!(memory_swap_max, Some(512 * 1024 * 1024));

        // A cpuset list must be structurally valid: injection chars, non-numeric tokens, empty
        // tokens, dangling/reversed ranges are all refused at the parse boundary — so a typo can't
        // silently yield an unpinned box (and nothing arbitrary reaches the kernel's cpuset file).
        for bad in ["0;rm", "bad", "0-", "-", "1,,2", "3-1", "", "0-3-5", " 0"] {
            assert!(
                matches!(
                    parse(&[
                        "run".into(),
                        "--cpuset-cpus".into(),
                        bad.into(),
                        "true".into()
                    ]),
                    Err(Error::Usage(_))
                ),
                "cpuset {bad:?} must be rejected"
            );
        }
        // ...while the well-formed forms are accepted.
        for good in ["0", "0-3", "0,2,4", "1-2,5", "7"] {
            let (_, cmd) = parse(&[
                "run".into(),
                "--cpuset-cpus".into(),
                good.into(),
                "true".into(),
            ])
            .unwrap();
            assert!(
                matches!(cmd, Command::Run { cpuset: Some(c), .. } if c == good),
                "cpuset {good:?} must parse"
            );
        }

        // Docker's `--memory-swap` is explicitly rejected on both verbs (not aliased).
        assert!(matches!(
            parse(&[
                "run".into(),
                "--memory-swap".into(),
                "1g".into(),
                "true".into()
            ]),
            Err(Error::Usage(_))
        ));
        assert!(matches!(
            parse(&[
                "box".into(),
                "x".into(),
                "--memory-swap".into(),
                "1g".into()
            ]),
            Err(Error::Usage(_))
        ));
    }

    #[test]
    fn inspect_and_prune_parse() {
        // `inspect <name>` captures the name; `--json` is picked up regardless of position.
        assert_eq!(
            parse(&["inspect".into(), "web".into()]).unwrap().1,
            Command::Inspect {
                name: "web".into(),
                json: false
            }
        );
        assert_eq!(
            parse(&["inspect".into(), "--json".into(), "web".into()])
                .unwrap()
                .1,
            Command::Inspect {
                name: "web".into(),
                json: true
            }
        );
        // Missing name → usage error (a lone `--json` is not a name).
        assert!(matches!(parse(&["inspect".into()]), Err(Error::Usage(_))));
        assert!(matches!(
            parse(&["inspect".into(), "--json".into()]),
            Err(Error::Usage(_))
        ));
        // `prune` takes no args.
        assert_eq!(parse(&["prune".into()]).unwrap().1, Command::Prune);
    }

    #[test]
    fn stop_takes_multiple_names_or_all() {
        // Multiple names are ALL captured (the old parser silently kept only the first).
        let cmd = parse(&["stop".into(), "a".into(), "b".into(), "c".into()])
            .unwrap()
            .1;
        assert_eq!(
            cmd,
            Command::Stop {
                names: vec!["a".into(), "b".into(), "c".into()],
                all: false,
            }
        );
        // `--all` sets the flag; names may be empty.
        assert_eq!(
            parse(&["stop".into(), "--all".into()]).unwrap().1,
            Command::Stop {
                names: vec![],
                all: true
            }
        );
        // Flags are not captured as names: `stop --all x` keeps all=true and name x.
        assert_eq!(
            parse(&["stop".into(), "--all".into(), "x".into()])
                .unwrap()
                .1,
            Command::Stop {
                names: vec!["x".into()],
                all: true
            }
        );
    }

    #[test]
    fn missing_required_args_are_usage_errors() {
        // `pull`/`compose`/`stop` without their argument → a usage error, not "not implemented".
        for argv in [vec!["pull"], vec!["compose"], vec!["stop"]] {
            let args: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
            assert!(matches!(parse(&args), Err(Error::Usage(_))), "{argv:?}");
        }
    }

    #[test]
    fn unknown_command_errors() {
        assert!(matches!(
            parse(&["frobnicate".into()]),
            Err(Error::UnknownCommand(_))
        ));
    }

    #[test]
    fn exec_parses_it_flag() {
        let argv: Vec<String> = ["exec", "svc", "-it", "--", "sh"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        match parse(&argv).unwrap().1 {
            Command::Exec {
                name, tty, command, ..
            } => {
                assert_eq!(name, "svc");
                assert!(tty, "-it should set tty");
                assert_eq!(command, vec!["sh".to_string()]);
            }
            other => panic!("expected Exec, got {other:?}"),
        }
        // Without -it, tty is false.
        let argv: Vec<String> = ["exec", "svc"].iter().map(|s| s.to_string()).collect();
        assert!(matches!(
            parse(&argv).unwrap().1,
            Command::Exec { tty: false, .. }
        ));
    }

    #[test]
    fn stats_captures_names_and_json() {
        // Regression: `stats <name>` used to drop the name and print every box.
        let p = |a: &[&str]| {
            parse(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap()
                .1
        };
        assert!(
            matches!(p(&["stats"]), Command::Stats { json: false, ref names } if names.is_empty())
        );
        match p(&["stats", "web", "db"]) {
            Command::Stats { json: false, names } => assert_eq!(names, vec!["web", "db"]),
            other => panic!("expected Stats, got {other:?}"),
        }
        match p(&["stats", "--json", "web"]) {
            Command::Stats { json: true, names } => assert_eq!(names, vec!["web"]),
            other => panic!("expected Stats, got {other:?}"),
        }
    }
}
