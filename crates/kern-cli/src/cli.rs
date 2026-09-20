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
// `BoxRun` carries every `kern box` flag, so it dwarfs the unit variants - but a `Command` is built
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
        /// The `vcpu:`/`vgpio:`/`vdisk:` tokens on the command line. A preview that omits the
        /// hardware a profile hands over is not a preview of what will be created.
        profiles: Vec<String>,
        /// `--config <path>`, carried because the preview resolves those tokens. Without it the
        /// plan read a DIFFERENT kern.toml from the one the launch would use, and reported
        /// "no [[vcpu]] profile named 'slim'" for a profile sitting in the file that was passed.
        config: Option<String>,
    },
    /// `kern box <name> (--rootfs <dir> | --image <ref>) [-d] [-- cmd...]`: run in a sandbox.
    BoxRun {
        /// `--rm`: leave no exit record behind, as Docker's `--rm` leaves no container.
        ///
        /// A BOX IS ALREADY THROWN AWAY: its scratch and its registry entry go at teardown, and the
        /// only residue is the transient `waitexit` breadcrumb `kern ps -a` reads for an hour. This
        /// flag drops that too, which is the whole difference between kern's default and Docker's
        /// flag. `kern wait` then has nothing to read, exactly as `docker wait` has nothing to read
        /// for a container that removed itself.
        rm: bool,
        name: String,
        rootfs: Option<String>,
        image: Option<String>,
        /// `--pull <missing|never|always>`: registry-image fetch policy (see [`commands::PullPolicy`]).
        pull: commands::PullPolicy,
        command: Vec<String>,
        /// `--entrypoint <arg>` (repeatable): REPLACE the image's `ENTRYPOINT`.
        ///
        /// `None` when the flag is absent, which leaves the image's own entrypoint standing.
        /// `Some(list)` replaces it, and Docker's rule then applies: the image's `CMD` is discarded,
        /// because that default belonged to the entrypoint being replaced.
        ///
        /// REPEATABLE, one argv element per occurrence, because the two spellings kern must speak
        /// disagree: `docker run --entrypoint` takes a single executable, compose's `entrypoint:`
        /// takes a list. One occurrence is Docker's form; several express compose's exec form
        /// without a second flag or a quoting convention to get wrong.
        ///
        /// `Some(empty)` CLEARS the entrypoint: `--entrypoint ""`, which is compose's
        /// `entrypoint: []`. The distinction between absent and cleared is why this is an `Option`
        /// around a `Vec` and not a bare `Vec`.
        entrypoint: Option<Vec<String>>,
        detached: bool,
        read_only: bool,
        /// `-v src:dst[:ro]` (repeatable): host paths bind-mounted in.
        volumes: Vec<String>,
        /// `--env K=V` / `-e K=V` (repeatable): extra environment for the workload.
        env: Vec<String>,
        /// `--egress-allow d1,d2` (repeatable / comma-separated): outbound restricted to these domains.
        egress_allow: Vec<String>,
        /// `--landlock-rw <path>` (repeatable): a Landlock write-allowlist (box RO except these paths).
        landlock_rw: Vec<String>,
        /// `--pod-bridge <ip>/<prefix>`: join the pod through its bridge with this address.
        pod_bridge: Option<kern_isolation::BridgeAttach>,
        /// `--ip <addr>` (repeatable): extra IPv4 addresses this box's `lo` answers on, each a `/32`.
        /// Parsed into `Ipv4Addr` here rather than carried as a string, so a value that is not an
        /// address is refused before a box exists instead of failing where nothing can point at it.
        net_ips: Vec<std::net::Ipv4Addr>,
        /// `--apparmor <profile>`: a pre-loaded AppArmor profile the box enters on exec (Docker's
        /// `--security-opt apparmor=`). A missing/unloaded profile fails the box closed.
        apparmor: Option<String>,
        /// `--workdir <dir>` / `-w <dir>`: working directory inside the box.
        workdir: Option<String>,
        /// `--net`: share the host network namespace (outbound networking; no net isolation).
        share_net: bool,
        /// `--pod <name>`: join a pod's shared loopback network (reach peers by name).
        pod: Option<String>,
        /// `--uid-range`: map a sub-uid/gid range (apt/dpkg, www-data). Default maps only the caller.
        uid_range: bool,
        /// `--no-uid-range`: opt OUT of the range mapping an `--image` box gets by default.
        no_uid_range: bool,
        /// `--bind-rootfs`: bind the rootfs directly instead of an overlay (faster on slow-overlay
        /// kernels; source becomes mutable & shared).
        bind_rootfs: bool,
        /// `--privileged`: relax the seccomp filter so a NESTED `kern box` (or docker-in-docker-style
        /// workload) can create its namespaces. Rootless-only; refused as real host root.
        privileged: bool,
        /// `--require-limits`: refuse to start (non-zero exit) if a requested/default resource cap
        /// cannot actually be enforced here, instead of running best-effort UNCAPPED with a warning.
        require_limits: bool,
        /// `--allow-uncapped`: explicitly accept running UNCAPPED on a host with no cgroup delegation,
        /// silencing the best-effort notice. Mutually exclusive with `--require-limits`.
        allow_uncapped: bool,
        /// `--security-profile <untrusted>`: a bundle of opt-in hardening (seccomp allowlist +
        /// cap-drop ALL + read-only) applied as a base that explicit flags override.
        security_profile: Option<commands::SecurityProfile>,
        /// INTERNAL (used by `kern build`): explicit overlay lower dir(s), colon-joined, used as the
        /// read-only base instead of `--rootfs`/`--image`. Paired with `--overlay-upper`.
        overlay_lower: Option<String>,
        /// INTERNAL (used by `kern build`): a PERSISTENT overlay upper dir (the build layer) instead
        /// of the ephemeral scratch upper - so a build's writes accumulate across RUN steps.
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
        /// `--dns IP` (repeatable): the box's `nameserver` lines. Validated as IP literals HERE, so
        /// no later layer parses them and a typo is refused before anything is started.
        dns: Vec<String>,
        /// `--dns-search DOMAIN` (repeatable): the `search` line of the box's `/etc/resolv.conf`.
        dns_search: Vec<String>,
        /// `--dns-option OPT` (repeatable): the `options` line (e.g. `ndots:2`, `timeout:2`).
        dns_options: Vec<String>,
        /// `--log-max-size <size>`: how large the box's captured log may grow before it rotates.
        /// `None` leaves kern's default (16 MiB).
        log_max_size: Option<u64>,
        /// `--log-max-file <n>`: how many log files are kept IN TOTAL, active one included (Docker's
        /// `max-file` counting). `None` leaves kern's default (2: active plus one generation).
        log_max_file: Option<u32>,
        /// `--memory-reservation <size>` → cgroup `memory.low`: a soft floor, never a cap.
        memory_reservation: Option<u64>,
        /// `--cpu-weight <n>` (1..=10000) → cgroup `cpu.weight`: relative CPU share under contention.
        cpu_weight: Option<u64>,
        /// `--secret SRC[:NAME]` / `NAME=value` / `NAME=-` (repeatable): deliver a secret to the box
        /// as `/run/secrets/NAME` (mode 0400) without it touching the image or the workload env.
        secrets: Vec<String>,
        /// `--secret-env <name>`: content from `KERN_SECRET_<name>`, never from argv.
        secret_envs: Vec<String>,
        /// `--secret-mode <octal>`: the mode every secret of this box is created with. Defaults to
        /// `secret::DEFAULT_SECRET_MODE` (0400); `kern compose` passes the Compose Specification's
        /// `0444` explicitly, because a secret only the owner can read is unreadable to every image
        /// that drops to a non-root user.
        secret_mode: libc::mode_t,
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
        /// `--pids-limit N`: cap the box's process/thread count (`pids.max`) - fork-bomb containment.
        pids_limit: Option<u64>,
        /// `--tmpfs PATH[:size]` (repeatable): mount a fresh tmpfs at PATH inside the box.
        tmpfs: Vec<String>,
        /// `--shm-size SIZE`: cap `/dev/shm`. `None` derives the cap from `--memory`, which is the
        /// bound the cgroup already enforces; this only overrides what the box is TOLD it has.
        shm_size: Option<u64>,
        /// `--ulimit NAME=SOFT[:HARD]` (repeatable), pre-resolved to `(RLIMIT_*, soft, hard)` so the
        /// sandbox layer does no parsing. `unlimited`/`-1` map to `RLIM_INFINITY`.
        ulimits: Vec<(i32, u64, u64)>,
        /// `--sysctl KEY=VALUE` (repeatable): namespaced kernel knobs set inside the box.
        sysctls: Vec<(String, String)>,
        /// `--label k=v` (repeatable): descriptive metadata recorded in the registry.
        labels: Vec<String>,
        /// `--restart-max <n>`: retry cap for the on-failure policy (0 = kern's default).
        restart_max: u32,
        /// `--def-hash <hex>`: fingerprint of the compose definition (drift detection).
        def_hash: Option<String>,
        /// `--stop-signal`: signal sent before the SIGKILL. `None` = not given, which lets the
        /// image's own `STOPSIGNAL` decide (Docker's rule); neither means `SIGTERM`.
        stop_signal: Option<i32>,
        /// `--stop-timeout <secs>`: grace before the SIGKILL.
        stop_grace: u64,
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
        /// `--health-cmd-argv <arg>` (repeatable): the same check in Docker's `CMD` exec form - one
        /// argv element per occurrence, run with NO shell.
        health_cmd_argv: Vec<String>,
        /// `--health-interval <sec>`: seconds between health checks (default 30).
        health_interval: u64,
        /// `--health-retries <n>`: consecutive failures before a box is marked unhealthy (default 3).
        health_retries: u32,
        /// `--health-start-period <sec>`: initial grace where a failing check keeps "starting" (0).
        health_start_period: u64,
        /// `--health-start-interval <sec>`: probe THIS often while inside the start period (0 = use
        /// the steady interval throughout). Docker 25+'s `StartInterval`.
        health_start_interval: u64,
        /// `--health-timeout <sec>`: kill a single check that runs longer than this (0 = no timeout).
        health_timeout: u64,
        /// `--health-action <restart|stop|none>`: what to do when a box turns unhealthy.
        health_action: Option<String>,
        /// `--env-file <file>` (repeatable): read `K=V` lines from a file into the box's environment.
        env_file: Vec<String>,
        /// `--timeout <sec>`: stop the box automatically after this many seconds (0 = no timeout).
        ///
        /// N is when the SIGTERM lands, NOT when the process is gone: a workload that ignores it
        /// gets a fixed 2 s grace and then a SIGKILL, so the wall-clock is N+2 in that case. This is
        /// `docker stop`'s shape and it is deliberate, but it was never written down and never
        /// timed, so `--timeout 30` in a CI job that budgets exactly 30 s would overrun. The 2 s
        /// here is the foreground watchdog's own (`commands::mod`), unrelated to `--stop-timeout`,
        /// which defaults to 10 and governs `kern stop`.
        timeout: u64,
        /// `--nice <n>`: scheduling niceness (-20..19) for the box workload.
        nice: Option<i64>,
        /// `--io-weight <n>`: cgroup v2 `io.weight` (1..10000) - relative I/O priority.
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
    /// run a command under cgroup CPU/memory caps WITHOUT a full sandbox - the resource-governor
    /// verb (composes with `box`'s isolation). Takes the same resource flags as `kern box`.
    Run {
        command: Vec<String>,
        memory: Option<u64>,
        memory_swap_max: Option<u64>,
        cpus: Option<f64>,
        cpuset: Option<String>,
        /// `--config <path>`: a specific `kern.toml` for the profile tokens (parity with `box`).
        config: Option<String>,
        /// `--landlock-rw <path>` (repeatable): confine the workload's WRITES to these paths via the
        /// Landlock LSM. The only real confinement `run` can offer, because Landlock restricts the
        /// calling process rather than requiring a mount namespace.
        landlock_rw: Vec<String>,
    },
    /// `kern exec <name> [-it] [--env K=V] [--workdir <dir>] [--] [cmd...]`: run a command in a box.
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
    /// `kern pull <image>`: fetch an OCI image into the cache. `--dest <dir>` extracts a rootfs
    /// instead.
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
    /// `kern commit <box> <image>`: snapshot a running box's filesystem into a reusable local image
    /// (warm sessions: bake an expensive setup once, start the next box warm).
    Commit {
        box_ref: String,
        image: String,
    },
    /// `kern build -t <name> [-f Dockerfile] [--build-arg K=V] [<context>]`: build a local image
    /// from a Dockerfile subset.
    Build {
        /// `--check`: parse the Dockerfile, report what kern does with every instruction, and build
        /// nothing. `compose config`'s sibling for a Dockerfile.
        check: bool,
        /// The FIRST `-t`: the name the build itself is stored under.
        tag: Option<String>,
        /// Every LATER `-t`, applied to the finished image as an alias. Docker takes one `-t` per
        /// name and applies them all; kern kept only the last and said nothing, so a CI line like
        /// `build -t repo:$VERSION -t repo:latest .` produced `:latest` alone and the `push
        /// repo:$VERSION` that followed it failed on an image that had never been named.
        extra_tags: Vec<String>,
        file: Option<String>,
        context: String,
        build_args: Vec<String>,
        quiet: bool,
        /// `--target <stage>`: stop at that stage of a multi-stage Dockerfile (compose's
        /// `build.target:`).
        target: Option<String>,
    },
    /// `kern pod create <name> [--no-outbound] [--uid-range] [--bridge <cidr>]` / `pod ls` / `pod rm
    /// <name>`: a pod is a shared network, either one namespace or one bridge.
    PodCreate {
        name: String,
        outbound: bool,
        uid_range: bool,
        /// `--bridge <cidr>`: hold a bridge instead of a shared loopback, so every member gets its
        /// own network namespace and its own `127.0.0.1` while still reaching its peers.
        bridge: Option<String>,
    },
    PodList {
        /// `--json`: the same scan as the table, machine-readable. Every read verb takes it; a verb
        /// that does not is a hole a script falls into, and it falls into it by parsing a table.
        json: bool,
    },
    PodRemove {
        names: Vec<String>,
    },
    /// `kern network create <name>` / `network ls [--json]` / `network rm <name>`: a network shared
    /// BETWEEN projects, which is what `networks: {x: {external: true}}` in a compose file names.
    ///
    /// EXPLICIT, LIKE DOCKER'S. `docker compose up` refuses a file naming an external network that
    /// does not exist, and so does kern: inferring it would turn a typo in a network name into a
    /// second, empty network whose members resolve nothing, which is the failure the key exists to
    /// prevent.
    NetworkCreate {
        name: String,
    },
    NetworkList {
        /// `--json`: the same scan as the table, machine-readable, like every other read verb here.
        json: bool,
    },
    /// `network inspect <name>`: one network's subnet and its live members.
    NetworkInspect {
        name: String,
        json: bool,
        /// `-f`/`--format`: the Docker keys kern has a true value for (`.Name`, `.IPAM.Config`,
        /// `.Containers`). Any other is refused rather than rendered empty.
        format: Option<String>,
    },
    NetworkRemove {
        names: Vec<String>,
    },
    /// Hidden: the pod namespace holder process (spawned by `pod create`, not user-facing).
    PodHolder,
    /// Hidden: owns a `--no-pod` stack's peer relays until killed. Argument is the stack's
    /// runtime directory, where the plan file lives.
    RelayHolder {
        dir: String,
    },
    /// Hidden: the re-exec'd egress filtering proxy (spawned by `--egress-allow`, not user-facing).
    EgressProxy {
        sock: String,
        allow: String,
    },
    /// Hidden: the re-exec'd egress box-netns pump (spawned by `--egress-allow`, not user-facing).
    /// `read_fd` is an inherited pipe from box_run over which the box init pid arrives (the pump is
    /// spawned in the HOST pid namespace, before box_run unshares CLONE_NEWPID, so it cannot be told the
    /// pid at spawn time; delivering it over a pipe keeps the pump out of the box pidns).
    EgressPump {
        read_fd: i32,
        box_port: u16,
        sock: String,
        /// Write end of the readiness pipe: the pump writes one byte once it is listening inside
        /// the box. `-1` when the launcher passed none, which is how an older launcher behaves.
        ready_fd: i32,
    },
    /// `kern search <query> [--json]`: search Docker Hub for images.
    Search {
        query: String,
        json: bool,
    },
    /// `kern images [--json]`: list pulled (cached) images.
    Images {
        json: bool,
        /// `--filter reference=<pattern>` / `--filter dangling=<bool>`, repeatable and ANDed. The
        /// two keys kern's cache can answer; any other is refused at parse time by name.
        filters: Vec<(String, String)>,
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
    /// `kern builds [<tag>] [--status S] [-n N] [--json]`: list past builds (build history - the
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
    /// `kern ps [-a] [--json]`: list running boxes (`-a`/`--all` also lists recently-exited ones).
    Ps {
        json: bool,
        quiet: bool,
        /// `-a`/`--all`: also list RECENTLY exited boxes (from the `waitexit` breadcrumb), not only the
        /// running ones. Unlike Docker's `ps -a`, these are transient: reaped by `gc` (and past a display
        /// window), they do NOT hold the box name, and may disappear - kern keeps no durable store.
        all: bool,
        filters: Vec<(String, String)>,
        format: Option<String>,
        /// `--no-trunc` and `--last N`: how the listing is PRESENTED, as opposed to which boxes it
        /// holds. See [`commands::PsView`].
        view: commands::PsView,
    },
    /// `kern stats [--json] [name...]`: per-box memory + CPU (all boxes, or just the named ones).
    Stats {
        json: bool,
        names: Vec<String>,
    },
    /// `kern logs <name>`: print a box's captured output.
    Logs {
        name: String,
        tail: Option<usize>,
        follow: bool,
        /// Prefix each line with the recorded time of the mark it falls after. See
        /// `boxlog::MARK_EVERY` for why that is a bucket and not a per-line instant.
        timestamps: bool,
        /// `--since` / `--until` as unix nanoseconds: show only lines the index places inside the
        /// window. A line the index cannot place is KEPT (see `boxlog::Stamper::window`).
        window: (Option<u64>, Option<u64>),
    },
    /// `kern inspect <name> [--json]`: full detail for one running box (identity + resources).
    Inspect {
        name: String,
        json: bool,
        /// `--format <go template>`: Docker's, for the field set kern can answer truthfully.
        format: Option<String>,
    },
    /// `kern prune`: garbage-collect leftover logs/health/registry files of boxes no longer running.
    Prune,
    /// `kern gc [--images]`: `prune` + optionally reclaim the pulled-image cache.
    Gc {
        images: bool,
    },
    /// `kern doctor`: preflight - will boxes run here, and which optional features are available?
    Doctor,
    /// `doctor --apparmor-profile`: write the shipped AppArmor profile to stdout and exit.
    DoctorApparmorProfile,
    /// `kern info`: compact runtime + host snapshot.
    Info,
    /// `kern bench [--rootfs R] [--bind-rootfs] [-n N]`: time N box start→exit cycles.
    Bench {
        rootfs: Option<String>,
        /// `--image <ref>`: bench an OCI image instead of a prepared directory. Every other verb
        /// that needs a filesystem takes `--image`; bench took only `--rootfs`, so the one command
        /// the README tells a newcomer to run was the one command that needed two others first.
        image: Option<String>,
        /// `--bind-rootfs`: bench the bind path instead of the overlay, the same choice `kern box`
        /// offers. bench accepted this flag and dropped it, so on a host where the overlay mount is
        /// the cost (22 ms on the Arduino UNO Q's Android kernel, 0.1 ms on x86) it reported the
        /// overlay number for a run the user believed was measuring the bind. A benchmark that
        /// silently measures something other than what was asked is worse than one that refuses.
        bind_rootfs: bool,
        count: u32,
    },
    /// `kern recover`: clean up stale registry entries / orphaned scratch of dead boxes.
    Recover,
    /// `kern rename <old> <new>`: give a running box a new name.
    Rename {
        old: String,
        new: String,
    },
    /// `kern port <box> [<container-port>[/tcp|/udp]]`: the host address serving a running box's
    /// port, or every mapping it has. `docker port`, for one box rather than a stack.
    Port {
        name: String,
        /// `None` lists every mapping, as `docker port <container>` with no port does.
        container_port: Option<String>,
    },
    /// `kern update <box> [--memory M] [--cpus N] [--pids-limit P]`: change a running box's caps live.
    Update {
        name: String,
        memory: Option<u64>,
        cpus: Option<f64>,
        pids: Option<u64>,
    },
    /// `kern wait <box>...`: block until each box exits, print its exit code.
    Wait {
        names: Vec<String>,
    },
    /// `kern diff <box>`: list filesystem changes vs the box's image.
    Diff {
        name: String,
        /// `--json`: `[{"change":"C","path":"/etc/hosts"}]`. The human form prints `C /etc/hosts`,
        /// which a script has to split on the first space, and a box-controlled filename is exactly
        /// the input that makes that split wrong.
        json: bool,
    },
    /// `kern <verb> --help`: the slice of the full reference describing that verb.
    HelpFor(String),
    /// `kern events`: stream box lifecycle events (start/die/rename) until interrupted.
    Events,
    /// `kern history [-n N]`: recent boxes (from their captured logs).
    History {
        count: usize,
    },
    /// `kern login [registry] [--username U]`: store registry credentials for private-image pulls.
    Login {
        registry: Option<String>,
        username: Option<String>,
        /// `-p/--password <value>`: the password on the command line, where `ps` can read it.
        /// Docker's own help deprecates it; kern accepts it and says what it costs.
        password: Option<String>,
        /// `--password-stdin`: read the password from stdin with no prompt, which is the form every
        /// CI pipeline uses (`… get-login-password | kern login -u AWS --password-stdin <reg>`).
        password_stdin: bool,
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
    /// `kern compose <file> [up|down] [--no-pod] [-d]`: bring up (or tear down) a stack of boxes in
    /// dependency order. `up` auto-creates a pod so services reach each other by name (`--no-pod`
    /// opts out); `down` stops the boxes and removes the pod. `-d`/`--detach` returns as soon as the
    /// stack is up; without it, an `up` ON A TERMINAL streams the stack's logs the way `docker
    /// compose up` does, and Ctrl-C stops the stack (see [`Command::Compose::detach`]).
    Compose {
        /// One or more compose files, merged left-to-right (`-f base -f override`).
        files: Vec<String>,
        /// Which compose verb to run (see [`commands::ComposeAction`]).
        /// `--pull <always|missing|never>`: overrides every service's `pull_policy:` for this
        /// invocation, which is what `docker compose run --pull=never` means.
        pull: Option<String>,
        /// `-t/--timeout <secs>` on `stop`/`down`/`restart`: the grace before the SIGKILL.
        stop_timeout: Option<u64>,
        /// `--ignore-pull-failures`: a registry that cannot serve an image ends the image, not the run.
        ignore_pull_failures: bool,
        /// `build --build-arg K=V`, repeatable: forwarded to every service built by this invocation.
        build_args: Vec<String>,
        /// `run --name <n>`: the one-off's box name.
        run_name: Option<String>,
        /// `run --entrypoint <cmd>`: replaces the image's entrypoint for this run.
        run_entrypoint: Option<String>,
        /// `run -e KEY=VALUE`, repeatable: environment for this one-off, over the service's own.
        run_env: Vec<String>,
        /// `run --user <uid[:gid]>`: the identity this one-off runs as.
        run_user: Option<String>,
        /// `down --rmi <local|all>`: `Some(false)` removes the images this file BUILDS, `Some(true)`
        /// every image it names.
        rmi: Option<bool>,
        /// `up --force-recreate` / `up --no-recreate`: the override of the drift comparison that
        /// decides which running services `up` leaves alone. See [`commands::RecreatePolicy`].
        recreate: commands::RecreatePolicy,
        /// `up -V/--renew-anon-volumes`: discard the anonymous volumes of the services this `up`
        /// starts, instead of carrying the previous run's contents into them.
        renew_anon_volumes: bool,
        /// `logs -t/--timestamps`.
        log_timestamps: bool,
        /// `logs --since` / `--until`, as unix nanoseconds.
        log_window: (Option<u64>, Option<u64>),
        /// `logs --no-log-prefix`: no `=== <service> ===` heading between services' blocks.
        no_log_prefix: bool,
        action: commands::ComposeAction,
        no_pod: bool,
        /// `--bridge`: wire the stack the way Docker does. Each service keeps its OWN network
        /// namespace, and therefore its own `127.0.0.1`, and they meet on a bridge the pod holds.
        /// One `veth` per service instead of a TCP relay per ordered pair per port.
        bridge: bool,
        /// `--allow-privileged`: the operator's half of a file's `privileged: true`.
        allow_privileged: bool,
        /// `--pod`: keep one shared namespace even when the file expresses segregation.
        force_pod: bool,
        /// `--allow-device-grants`: see [`commands::ComposeOpts::allow_device_grants`]. CLI-only on
        /// purpose, so a compose file cannot grant itself the hardware it names.
        allow_device_grants: bool,
        /// `-d`/`--detach`: return as soon as the stack is up, instead of streaming its logs.
        ///
        /// THE FLAG USED TO DO NOTHING. `up` always returned immediately, and `-d` was accepted as
        /// a name for what already happened - a flag that changes nothing, which is the shape this
        /// codebase refuses everywhere else. `docker compose up` attaches, and a switcher's first
        /// command produced a prompt where Docker produces a stream of logs.
        ///
        /// ATTACHING IS GATED ON STDOUT BEING A TERMINAL, which is not timidity: every existing
        /// caller that redirects or pipes (a CI script, a systemd unit, the SDK, `getkern.dev`'s own
        /// unit) keeps today's behaviour exactly and CANNOT be left blocking on a follow that never
        /// ends. An interactive `up` is the one place where the Docker habit is unambiguous.
        detach: bool,
        /// `--wait`: after `up`, hold until every service this invocation started is ready.
        ///
        /// Docker's semantics, MEASURED on 29.6.2: a service with a healthcheck must reach
        /// `healthy` (7 s for one that flips at 6 s), a service without one must be RUNNING and
        /// returns at once, a service that has already EXITED fails the wait even with status 0,
        /// and `--wait-timeout 8` on a check that never passes exits 1 after 8 seconds.
        wait_ready: bool,
        /// `--wait-timeout N`, in seconds. `None` uses kern's own condition timeout, the same bound
        /// `depends_on: service_healthy` already waits under.
        wait_timeout: Option<u64>,
        /// The argv after `run <service>`, verbatim. Empty means "the service's own command".
        run_cmd: Vec<String>,
        /// `run --rm`: drop the one-off box's registry entry when it exits.
        run_rm: bool,
        /// `--no-deps`: do not bring the target's `depends_on` up first.
        no_deps: bool,
        /// `--exit-code-from <service>`: adopt that service's exit status as kern's.
        ///
        /// MEASURED on Docker 29.6.2, three cases: with `tests` exiting 3 it exits 3 and leaves no
        /// container running; `--abort-on-container-exit` alone exits 3 the same way; and
        /// `--exit-code-from db`, where `db` never exits on its own, exits **137**, because the
        /// abort is what ended it. Naming a service the file does not define is refused there
        /// ("no such service") and here.
        exit_code_from: Option<String>,
        /// `--abort-on-container-exit`: stop the whole stack as soon as any service exits.
        abort_on_exit: bool,
        /// `down --remove-orphans`: also stop this project's boxes the file no longer names.
        remove_orphans: bool,
        /// `ps -q`: print ids only, for `for c in $(compose ps -q)`.
        ps_quiet: bool,
        /// `ps --services`: print this stack's service NAMES, one per line.
        ps_services: bool,
        /// `ps --format <template|json>`: threaded to `kern ps`, the renderer the compose view
        /// already shares, so the two can never disagree about a column.
        ps_format: Option<String>,
        /// `-v`/`--volumes` on `down`: also delete the named volumes this project owns.
        ///
        /// kern DOES create named volumes and never removed them, so a stack torn down and started
        /// again silently reused the previous run's data - the opposite of what someone typing
        /// `down -v` is asking for. The flag used to be a usage error whose message named no flag.
        remove_volumes: bool,
        /// `--tail N` for `logs`.
        tail: Option<usize>,
        /// `-f/--follow` for `logs` (the whole stack, interleaved, or a named subset).
        follow: bool,
        /// `-a/--all` for `ps`: also list the stack's recently-exited services.
        all: bool,
        /// Optional service subset for the read-only verbs; empty = every service.
        services: Vec<String>,
        /// `-p/--project-name`: pod name override.
        project: Option<String>,
        /// `--env-file`: interpolation table instead of the project `.env`.
        env_file: Option<String>,
        /// `--profile` (repeatable).
        profiles: Vec<String>,
    },
    /// `kern config [edit|setup|probe|clear]`: manage `kern.toml` (default: list its profiles).
    Config {
        sub: String,
        force: bool,
        /// `--json`, accepted by `config list` only. See the parser for why the other four refuse it.
        json: bool,
    },
    /// `kern config add <kind:name> [--flags]`: create/replace a resource profile non-interactively -
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
    /// `kern uninstall [--yes] [--keep-images]`: remove everything kern created on this host. A dry
    /// run by default, because the paths it owns hold the image cache and named volumes.
    Uninstall {
        yes: bool,
        keep_images: bool,
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

/// The message for a size flag whose VALUE is wrong, as opposed to missing.
///
/// IT NAMES THE VALUE, and the sentence it replaces did not. `usage: kern --memory <size>` is what a
/// compose user saw when their file said `memory: 1.5G`: an error about a kern flag they never
/// typed, for a value it did not print, from a file it did not mention. Three keys in a compose file
/// reach this flag, so the last line says so and the reader knows where to look.
fn bad_size(flag: &str, v: &str) -> String {
    format!(
        "{flag} '{v}' is not a size. Write digits with an optional binary unit (512m, 1g, 1.5g, \
         2gb, 268435456). A compose file's `mem_limit:`, `memswap_limit:` or \
         `deploy.resources.limits.memory:` reaches this flag, so this may be a value your compose \
         file wrote rather than one you typed"
    )
}
/// The message for a memory cap that PARSED but is too small for a box to start.
///
/// Separate from [`bad_size`] because the reader's mistake is different: the value is a well-formed
/// size, so telling them how to write a size answers a question they did not ask. What they did was
/// omit the unit, and a bare number is bytes. MEASURED before this existed: `--memory 64` exits 137 in
/// 3 ms on every box, with kern's OOM message advising a bigger cap; a reader who then writes `128`
/// gets the identical failure. The floor and the measurement behind it are
/// [`kern_common::MIN_MEMORY_CAP_BYTES`].
fn cap_below_floor(flag: &str, v: &str, bytes: u64) -> String {
    format!(
        "{flag} '{v}' is {bytes} bytes, below the {floor} KiB a box needs to start. A BARE NUMBER IS \
         BYTES: `{flag} 64` caps the box at 64 bytes, not at 64 MiB. Write the unit ({flag} 64m, \
         {flag} 1g), or a byte count of at least {min}. A compose file's `mem_limit:`, \
         `memswap_limit:` or `deploy.resources.limits.memory:` reaches this flag, so this may be a \
         value your compose file wrote rather than one you typed",
        floor = kern_common::MIN_MEMORY_CAP_BYTES / 1024,
        min = kern_common::MIN_MEMORY_CAP_BYTES,
    )
}
const USAGE_CPUS: &str = "--cpus <n> (e.g. 1.5 = 1½ cores, 2)";
const USAGE_CPUSET: &str = "--cpuset-cpus <list> (e.g. 0-3, 0,2,4)";
const USAGE_SWAP_MAX: &str = "--memory-swap-max <size> (e.g. 1g, 512m)";
/// `run`'s message for a missing or empty `--landlock-rw` value. `box` accepts the same flag but merely
/// SKIPS an empty one, because a box that loses a Landlock grant still has its namespaces, seccomp and
/// read-only root. `run` has none of those: the allowlist is the entire confinement, so a value that
/// silently vanishes turns a confinement request into an unconfined process. It is an error here.
const USAGE_LANDLOCK_RW: &str = "--landlock-rw <path> (an existing path; repeatable)";
const REJECT_MEMORY_SWAP: &str =
    "--memory-swap is not supported (Docker's mem+swap total, ambiguous on cgroup v2); \
     use --memory-swap-max <size> = the swap allowance (memory.swap.max)";

/// Split argv into global options and a subcommand.
/// Refuse a flag the verb does not take, instead of ignoring it.
///
/// ONE definition, because the rule was being written out per verb and thirteen verbs had simply never
/// had it written: measured with a sweep of every verb in `--help`, `kern ps --zzzz`, `kern images
/// --zzzz`, `kern stats --zzzz`, `doctor`, `examples`, `gc`, `history`, `info`, `probe`, `prune`,
/// `recover`, `top` and `validate` all printed their normal output and exited **0**. The dangerous shape
/// is the format flag: `kern ps --jsn` printed the human table and exited 0, so a script that asked for
/// JSON got prose and had no way to tell.
///
/// The message POINTS AT `--help` rather than enumerating `allowed`: that list is a hand-kept
/// duplicate of what the parser accepts, and stating it to a user who is already confused asserts,
/// as fact, what the verb takes. This line used to say the opposite and call it an advantage -
/// left stale by the fix twenty lines below, which is the same way three earlier defects were born. A bare
/// `-` and everything after `--` are left alone: the former is a conventional stdin marker, the latter is
/// a workload's own argv and not ours to judge.
/// `args[0]` is the verb (or subcommand) itself and is skipped; callers with a nested subcommand
/// pass the slice starting AT that subcommand, so `pod ls --x` and `volume ls --x` reach the same
/// rule as `ps --x`. Shared rather than restated: a refusal expressed twice drifts, and the drift is
/// invisible precisely because both spellings look right.
pub(crate) fn reject_unknown_flags(
    verb: &str,
    args: &[&str],
    allowed: &[&str],
) -> Result<(), Error> {
    for a in args.iter().skip(1) {
        let s: &str = a;
        if s == "--" {
            break;
        }
        if !s.starts_with('-') || s == "-" {
            continue;
        }
        // EXACT match, on the argument as written. The `--flag=value` form used to be normalised to
        // `--flag` before the lookup, on the same unmeasured assumption that cost this function three
        // rewrites for `-n5`: that the parsers honour the attached form. They do not. `kern images
        // --json=1` was accepted here, ignored there, and printed the HUMAN TABLE with exit 0 - a
        // script asking for JSON got prose, which is the opening case of this whole change committed
        // by the function that closes it. `kern gc --images=no` was accepted and did not touch the
        // image cache. Both are refused now; `--json` and `--images` are the documented forms.
        let name = s;
        // Two attempts at an attached SHORT form (`-n5`) failed the same way:
        // the first let any argument beginning with an allowed short flag through, so `ps -quiet`
        // printed the table and exited 0; the second restricted the tail to digits, which refused that
        // but ACCEPTED `-n5` while no parser honours it - `history -n 3` prints 3 rows and `history -n3`
        // prints all of them, `builds -n 2` prints 2 and `-n2` prints none. Permitting a form the
        // parsers ignore is the silent acceptance this function exists to refuse, committed by the
        // function itself. `-n 5` is the documented form and it works.
        if allowed.contains(&name) {
            continue;
        }
        // Point at `--help`, do NOT enumerate `allowed`. That list is a hand-kept duplicate of what the
        // parser accepts, and printing it tells the user, as a fact, what the verb takes - at the exact
        // moment they are already confused. If the list ever omits a spelling the parser honours, the
        // message does not merely refuse it, it asserts the verb has no such flag. `--help` is generated
        // from the parser and cannot drift, which is what the README already promises about it.
        return Err(Error::Cli(format!(
            "{verb}: unknown flag {s:?} - run `kern {verb} --help` for what it accepts"
        )));
    }
    Ok(())
}

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
        // A FLAG'S VALUE IS NOT A HELP REQUEST, and for these two flags a value that begins with a
        // dash is ORDINARY. Each carries ONE ARGV ELEMENT and is repeated to build a list, so
        // `-h`, `--help` or any other option of the program being described is a normal element:
        // `--health-cmd-argv pg_isready --health-cmd-argv -U --health-cmd-argv postgres
        // --health-cmd-argv -h --health-cmd-argv localhost` is Supabase's own database check.
        //
        // MEASURED, not anticipated: eight of the eleven Supabase services died within 150 ms of
        // starting, each `kern box` printing the box help instead of running, because the `-h` in
        // `pg_isready -h localhost` reached this scan as an argument of its own. The shell form
        // hid it - there the whole check is a single argv element, so `-h` never appears alone -
        // which is why it surfaced only when the exec form started being preserved.
        //
        // A LIST OF TWO, on a criterion rather than by enumeration of what has broken so far: a
        // flag belongs here exactly when its value is one element of somebody else's argv.
        const ARGV_ELEMENT_FLAGS: &[&str] = &["--health-cmd-argv", "--entrypoint"];
        let mut skip_value = false;
        for a in &rest[1..] {
            if *a == "--" {
                break;
            }
            if std::mem::take(&mut skip_value) {
                continue;
            }
            if ARGV_ELEMENT_FLAGS.contains(a) {
                skip_value = true;
                continue;
            }
            if matches!(*a, "--help" | "-h") {
                saw_help = true;
                break;
            }
        }
        if saw_help {
            // The VERB's help, not the whole reference. `kern volume --help` printing 160 lines of
            // everything was the same answer `kern pod --help` and four others gave, and the reader
            // then has to find their verb in it. `help_for` falls back to the full page when the
            // verb has no lines of its own, so nothing becomes less discoverable than it was.
            //
            // BUT A VERB THAT DOES NOT EXIST IS STILL AN ERROR. `kern frobnicate --help` used to
            // print that same full page and exit 0, so a typo was indistinguishable from a real
            // verb with no section of its own, which is why "found no lines" cannot be the test.
            // (This named `install` and `docker` as two such verbs, and MEASURED on 2026-09-12 neither
            // is a verb at all: both answer `unknown command`. A comment that names a CLI surface has
            // to be checked like any other claim about it.) `kern frobnicate` without `--help` has
            // always said `unknown command`; asking for help about it should not be the one spelling
            // that hides the typo.
            //
            // THE PARSER IS ITS OWN ORACLE: parse the bare verb and look only for `UnknownCommand`.
            // A list of known verbs kept next to this line would be a second copy of the match below,
            // and copies drift. Any other parse error (a verb that needs arguments, a compose file
            // that is not in this directory) is not a spelling problem, so help is still the answer.
            // The recursion terminates because the argument vector it builds carries no `--help`.
            if let Some(v) = rest.first().copied().filter(|v| !v.starts_with('-')) {
                if let Err(Error::UnknownCommand(_)) = parse(&[v.to_string()]) {
                    return Err(Error::UnknownCommand(v.to_string()));
                }
                return Ok((opts, Command::HelpFor(v.to_string())));
            }
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
        Some("search") => {
            reject_unknown_flags("search", &rest, &["--json"])?;
            match rest.iter().skip(1).find(|a| !a.starts_with('-')) {
                Some(q) => Command::Search {
                    query: (*q).to_string(),
                    json: rest.contains(&"--json"),
                },
                None => return Err(Error::Usage("search <query> [--json]")),
            }
        }
        // `pod create <name> [-p …]` / `pod ls` / `pod rm <name>…`: shared-network pods.
        Some("pod") => parse_pod(&rest)?,
        Some("network" | "net") => parse_network(&rest)?,
        // `image <sub>`: the noun-verb grouping Docker moved its image commands into, mapped onto
        // the verbs kern already has.
        //
        // A REWRITE AND NOT A SECOND SET OF PARSERS. Each arm renames the first token and re-enters
        // this function, so `image ls --json` and `images --json` cannot come to accept different
        // flags or render different output: there is one parser per verb and this only chooses
        // which one. The cost of the alternative is measured elsewhere in this file, where two
        // paths answering one input differently is the divergence class treated as a defect.
        Some("image") => {
            let sub = rest.get(1).copied().unwrap_or_default();
            let mapped = match sub {
                "inspect" => "inspect",
                "ls" | "list" => "images",
                "rm" | "remove" => "rmi",
                "pull" => "pull",
                "push" => "push",
                "tag" => "tag",
                "history" => "history",
                "save" => "save",
                "load" => "load",
                "build" => "build",
                // `image prune` is NOT mapped to `gc --images`, which is the nearest thing kern
                // has and is not the same operation: Docker prunes DANGLING images by default and
                // `gc --images` clears what no box references. Aliasing them would delete more
                // than the caller asked for on a verb whose whole risk is deleting too much.
                "prune" => {
                    return Err(Error::Usage(
                        "image prune has no alias: `kern gc --images` frees images no box \
                         references, which is a wider sweep than Docker's dangling-only default. \
                         Run it deliberately, or `kern rmi <image>` for one",
                    ))
                }
                "" => return Err(Error::Usage("image ls|inspect|rm|pull|push|tag|history|save|load|build")),
                other => {
                    return Err(Error::Cli(format!(
                        "image {other}: not a kern verb (image ls|inspect|rm|pull|push|tag|history|save|load|build)"
                    )))
                }
            };
            let mut rewritten: Vec<String> = vec![mapped.to_string()];
            rewritten.extend(args.iter().skip(2).cloned());
            return parse(&rewritten);
        }
        // Hidden: the pod namespace holder (spawned by `pod create`).
        Some("__pod-holder") => Command::PodHolder,
        // Hidden: the relay holder (spawned by `compose up --no-pod`).
        Some("__relay-holder") => Command::RelayHolder {
            dir: rest.get(1).map(|s| s.to_string()).unwrap_or_default(),
        },
        Some("__egress-proxy") => Command::EgressProxy {
            sock: rest.get(1).map(|s| s.to_string()).unwrap_or_default(),
            allow: rest.get(2).map(|s| s.to_string()).unwrap_or_default(),
        },
        Some("__egress-pump") => Command::EgressPump {
            read_fd: rest.get(1).and_then(|s| s.parse().ok()).unwrap_or(-1),
            box_port: rest.get(2).and_then(|s| s.parse().ok()).unwrap_or(0),
            sock: rest.get(3).map(|s| s.to_string()).unwrap_or_default(),
            // `-1` when absent: an older launcher spawning a newer pump is not waiting for
            // the byte, so the pump skips it and the pair degrades to the old behaviour.
            ready_fd: rest.get(4).and_then(|s| s.parse().ok()).unwrap_or(-1),
        },
        // `build -t <name> [-f Dockerfile] [--build-arg K=V] [<context>]`: build a local image.
        Some("build") => parse_build(&rest)?,
        // `pull <image>`: fetch into the image cache; `--dest <dir>` extracts a rootfs instead.
        // An unknown flag used to be SKIPPED here, and the next token then became the image, because
        // `parse_pull` takes the first argument that is not a flag. One typo was enough:
        // `kern pull --platfrom linux/arm64 alpine:3.19` tried to pull an image literally named
        // `linux/arm64`, silently dropped the `alpine:3.19` the caller asked for, and failed with
        // "it may be private (run `kern login`)" - which sends the reader to authentication for a
        // spelling mistake. Thirty other verbs already refuse unknown flags; `pull` and `push` were
        // the two that did not.
        Some("pull") => {
            reject_unknown_flags("pull", &rest, &["--dest", "--platform"])?;
            let cmd = parse_pull(&rest).ok_or(Error::Usage("pull <image> [--dest <dir>]"))?;
            if let Command::Pull { image, .. } = &cmd {
                check_reference(image, "pull")?;
            }
            cmd
        }
        // `push <local-ref> [as <remote-ref>]` - publish a cached image. `as` lets you retag on push
        // (e.g. `kern push myapp as ghcr.io/me/myapp:1.0`).
        Some("push") => {
            // Same shape as `pull`: the filter below drops anything starting with `-`, so an unknown
            // flag was discarded and ITS VALUE was read as the local ref. `push` takes no flags at
            // all, which makes the allowed list empty and the rule exact.
            reject_unknown_flags("push", &rest, &[])?;
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
            // it is a usage error, NOT a silent fall-through to the local ref - otherwise
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
            reject_unknown_flags("tag", &rest, &[])?;
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
        Some("commit") => {
            reject_unknown_flags("commit", &rest, &[])?;
            let args: Vec<&&str> = rest
                .iter()
                .skip(1)
                .filter(|a| !a.starts_with('-'))
                .collect();
            let box_ref = args
                .first()
                .map(|s| s.to_string())
                .ok_or(Error::Usage("commit <box> <image>"))?;
            let image = args
                .get(1)
                .map(|s| s.to_string())
                .ok_or(Error::Usage("commit <box> <image>"))?;
            Command::Commit { box_ref, image }
        }
        // `images`: list pulled (cached) images.
        Some("images") => {
            reject_unknown_flags("images", &rest, &["--json", "--filter"])?;
            // `--filter` with the two keys a cache actually has an answer for. Docker's other keys
            // (`before=`, `since=`, `label=`) need per-image metadata kern's cache does not keep, so
            // they are refused BY NAME rather than accepted and ignored: a filter that silently
            // matches everything is a listing a script reads as "these are the ones that matched".
            let mut filters: Vec<(String, String)> = Vec::new();
            let mut i = 1;
            while i < rest.len() {
                if rest[i] == "--filter" {
                    let kv = rest
                        .get(i + 1)
                        .ok_or(Error::Usage("images --filter needs key=value"))?;
                    let (k, v) = kv.split_once('=').ok_or(Error::Usage(
                        "images --filter expects key=value (reference=alpine*, dangling=true)",
                    ))?;
                    match k {
                        "reference" | "dangling" | "label" | "before" | "since" => {}
                        other => {
                            return Err(Error::Cli(format!(
                                "images --filter {other}=: kern's image cache keeps no value for that key. It has reference= (a name pattern, `*` allowed), dangling= (true|false), label= (k or k=v), and before=/since= (another image's ref)"
                            )))
                        }
                    }
                    if k == "dangling" && !matches!(v, "true" | "false") {
                        return Err(Error::Usage("images --filter dangling=true|false"));
                    }
                    filters.push((k.to_string(), v.to_string()));
                    i += 1;
                }
                i += 1;
            }
            Command::Images {
                json: rest.contains(&"--json"),
                filters,
            }
        }
        // `rmi <image>...`: delete cached images (the counterpart to `pull`).
        Some("rmi") => {
            reject_unknown_flags("rmi", &rest, &[])?;
            Command::Rmi {
                images: rest.iter().skip(1).map(|s| s.to_string()).collect(),
            }
        }
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
        Some(v @ ("stop" | "kill")) => {
            reject_unknown_flags(v, &rest, &["--all", "-a"])?;
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
        Some("killall") => {
            reject_unknown_flags("killall", &rest, &[])?;
            Command::Stop {
                names: Vec::new(),
                all: true,
            }
        }
        // `pause`/`unpause` (aka `freeze`/`unfreeze`): freeze/thaw box(es) via the cgroup freezer.
        Some(v @ ("pause" | "freeze" | "unpause" | "unfreeze" | "resume")) => {
            let freeze = matches!(v, "pause" | "freeze");
            reject_unknown_flags(v, &rest, &["--all", "-a"])?;
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
        Some("attach") => {
            reject_unknown_flags("attach", &rest, &[])?;
            match rest.get(1) {
                Some(n) if !n.starts_with('-') => Command::Attach {
                    name: (*n).to_string(),
                },
                _ => return Err(Error::Usage("attach <name>")),
            }
        }
        // `cp <src> <dst>`: copy a file host<->box (one side is `<box>:<path>`).
        Some("cp") => {
            // `-a`/`--archive` ASKS FOR WHAT ROOTLESS CANNOT GIVE, and saying so is the only honest
            // answer. Docker's flag preserves uid/gid across the copy; a rootless box's files are
            // owned through a subuid range, so a file the box sees as `postgres` (999) is 100998 on
            // the host and there is no uid to preserve on either side of the boundary. kern's `cp`
            // already preserves the MODE, which is the half that survives the mapping. Refused by
            // name rather than accepted as a no-op: a backup script passing `-a` and getting files
            // it cannot restore is the failure this refusal exists to prevent.
            if rest.iter().any(|a| *a == "-a" || *a == "--archive") {
                return Err(Error::Cli(
                    "cp -a/--archive preserves uid/gid, which a rootless copy cannot: the box's ids live in a subuid range and do not exist on the host (a box's uid 999 is the host's 100998). The mode IS preserved without the flag; for ownership, copy inside the box and set it there".to_string(),
                ));
            }
            reject_unknown_flags("cp", &rest, &[])?;
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
        // `ps [--json] [-q|--quiet] [--filter key=value]...`: list running boxes.
        Some("ps") => {
            reject_unknown_flags(
                "ps",
                &rest,
                &[
                    "--json",
                    "-q",
                    "--quiet",
                    "--filter",
                    "--format",
                    "-a",
                    "--all",
                    "--no-trunc",
                    "--last",
                    "-n",
                ],
            )?;
            let json = rest.contains(&"--json");
            let quiet = rest.iter().any(|a| *a == "-q" || *a == "--quiet");
            let mut all = rest.iter().any(|a| *a == "-a" || *a == "--all");
            let no_trunc = rest.contains(&"--no-trunc");
            let mut last: Option<usize> = None;
            let mut filters = Vec::new();
            let mut format = None;
            let mut i = 1;
            while i < rest.len() {
                if rest[i] == "--filter" {
                    let kv = rest
                        .get(i + 1)
                        .ok_or(Error::Usage("ps --filter needs key=value"))?;
                    let (k, v) = kv.split_once('=').ok_or(Error::Usage(
                        "ps --filter expects key=value (e.g. name=web, status=running)",
                    ))?;
                    filters.push((k.to_string(), v.to_string()));
                    i += 1;
                } else if rest[i] == "--format" {
                    let f = rest.get(i + 1).ok_or(Error::Usage(
                        "ps --format needs a template (e.g. '{{.Names}}')",
                    ))?;
                    format = Some((*f).to_string());
                    i += 1;
                } else if rest[i] == "--last" || rest[i] == "-n" {
                    let v = rest
                        .get(i + 1)
                        .ok_or(Error::Usage("ps --last/-n needs a count"))?;
                    last = Some(
                        v.parse::<usize>()
                            .map_err(|_| Error::Usage("ps --last/-n expects a whole number"))?,
                    );
                    // `--last` IMPLIES `-a`, as Docker's does: "the last N containers" means the
                    // last N, and a flag that silently skipped every finished one would answer a
                    // different question from the one it names.
                    all = true;
                    i += 1;
                }
                i += 1;
            }
            Command::Ps {
                json,
                quiet,
                all,
                filters,
                format,
                view: commands::PsView { no_trunc, last },
            }
        }
        // `stats`: per-box memory + CPU.
        Some("stats") => {
            // `--no-stream` NAMES WHAT ALREADY HAPPENS. `docker stats` streams a live table and
            // `--no-stream` prints one snapshot and exits; kern's `stats` has only ever printed the
            // snapshot, because a daemonless runtime has no event stream to tail. Refusing the flag
            // sent a monitoring script that had it back to edit a line whose meaning kern already
            // honoured, so it is accepted; `kern top` is the live view.
            reject_unknown_flags("stats", &rest, &["--json", "--no-stream"])?;
            Command::Stats {
                json: rest.contains(&"--json"),
                names: rest[1..]
                    .iter()
                    .filter(|a| !a.starts_with('-'))
                    .map(|s| (*s).to_string())
                    .collect(),
            }
        }
        // `logs <name> [--tail N] [-f|--follow]`: a box's captured output.
        Some("logs") => {
            let (mut lname, mut tail, mut follow) = (None, None, false);
            let mut timestamps = false;
            let (mut since, mut until) = (None, None);
            let now_nanos = log_clock_now();
            let mut i = 1;
            while i < rest.len() {
                match rest[i] {
                    "-f" | "--follow" => follow = true,
                    "-t" | "--timestamps" => timestamps = true,
                    // `--since`/`--until`: the flags a monitoring loop writes (`logs --since 30s`)
                    // and the ones an incident review writes (an RFC3339 pair). A value that does
                    // not parse is REFUSED with the three forms named: a silently misread time
                    // shows the wrong window, and wrong output that looks like output is the worst
                    // of the three outcomes.
                    "--since" | "--until" => {
                        let key = rest[i];
                        let v = rest.get(i + 1).ok_or(Error::Usage(
                            "logs --since/--until <10m|1h30m|1789730443|2026-09-18T12:00:00Z>",
                        ))?;
                        let t = parse_log_window(key, v, now_nanos)?;
                        if key == "--since" {
                            since = Some(t);
                        } else {
                            until = Some(t);
                        }
                        i += 1;
                    }
                    "--tail" => {
                        let v = rest
                            .get(i + 1)
                            .ok_or(Error::Usage("logs: --tail needs a number"))?;
                        tail =
                            Some(v.parse::<usize>().map_err(|_| {
                                Error::Usage("logs: --tail expects a whole number")
                            })?);
                        i += 1;
                    }
                    s if !s.starts_with('-') => {
                        if lname.is_none() {
                            lname = Some(s.to_string());
                        }
                    }
                    _ => {
                        return Err(Error::Usage(
                            "logs <name> [--tail N] [-f|--follow] [-t|--timestamps]",
                        ))
                    }
                }
                i += 1;
            }
            // AN EMPTY WINDOW IS A TYPO, NOT A QUERY. `--since 5m --until 10m` asks for lines after
            // five minutes ago and before ten minutes ago, which is nothing: printing an empty log
            // reads as "the box said nothing" and sends the reader to look at the box.
            if let (Some(s), Some(u)) = (since, until) {
                if s > u {
                    return Err(Error::Cli(
                        "logs: --since is later than --until, so the window is empty (a duration counts BACK from now, so --since 10m --until 5m is the interval you want)"
                            .to_string(),
                    ));
                }
            }
            match lname {
                Some(name) => Command::Logs {
                    name,
                    tail,
                    follow,
                    timestamps,
                    window: (since, until),
                },
                None => {
                    return Err(Error::Usage(
                        "logs <name> [--tail N] [-f|--follow] [-t|--timestamps] [--since T] [--until T]",
                    ))
                }
            }
        }
        // `inspect <name> [--json] [--format <tmpl>]`: full detail for one box or image.
        //
        // `--format` IS DOCKER'S, AND IT IS WHAT SCRIPTS READ. A wait loop asking
        // `docker inspect --format '{{.State.Running}}' <name>` is the canonical way to poll a
        // container, and kern answered `unknown flag "--format"`: measured on Sentry's `install.sh`,
        // whose SeaweedFS migration polls exactly that. A field kern cannot answer truthfully is
        // refused BY NAME rather than guessed, which is the rule the `version`/`info` renderer
        // already follows.
        Some("inspect") => {
            // `-f` IS THE SPELLING PEOPLE ACTUALLY TYPE. `docker inspect -f '{{.State.Status}}' <c>`
            // is the line in every wait loop and every deploy script; `--format` was accepted and
            // `-f` was `unknown flag "-f"`, so a script ported across had to be edited for a flag
            // that does the same thing under a shorter name. Both spellings, one value.
            reject_unknown_flags("inspect", &rest, &["--json", "--format", "-f"])?;
            let format = flag_value(&rest, "--format").or_else(|| flag_value(&rest, "-f"));
            // The NAME is the first positional that is not a flag's value. Walked explicitly,
            // because `--format '{{.State.Running}}' <name>` puts a non-flag token immediately after
            // a flag and a naive "first token without a dash" takes the template for the box.
            let mut name: Option<&str> = None;
            let mut skip_next = false;
            for a in rest.iter().skip(1) {
                if skip_next {
                    skip_next = false;
                    continue;
                }
                if *a == "--format" || *a == "-f" {
                    skip_next = true;
                    continue;
                }
                if !a.starts_with('-') && name.is_none() {
                    name = Some(a);
                }
            }
            match name {
                Some(n) => Command::Inspect {
                    name: n.to_string(),
                    json: rest.contains(&"--json"),
                    format,
                },
                None => {
                    return Err(Error::Usage(
                        "inspect <name> [--json] [--format <template>]",
                    ))
                }
            }
        }
        // `prune`: GC leftover logs/health/registry files of boxes no longer running.
        Some("prune") => {
            reject_unknown_flags("prune", &rest, &[])?;
            Command::Prune
        }
        // `gc [--images]`: prune dead-box leftovers (+ the image cache with `--images`).
        Some("gc") => {
            reject_unknown_flags("gc", &rest, &["--images"])?;
            Command::Gc {
                images: rest.contains(&"--images"),
            }
        }
        // `doctor`: environment preflight. `info`: runtime snapshot.
        Some("doctor") => {
            reject_unknown_flags("doctor", &rest, &["--apparmor-profile"])?;
            // Emitting the profile is a DIFFERENT command from diagnosing, so it is a different
            // variant: `doctor` must not write or print anything but its report, and the emitter
            // must not run the checks. The flag exists because the install line `doctor` prints
            // has to be runnable by someone who installed from a release tarball or
            // `cargo install`, neither of which carries the repo's `packaging/` directory.
            if rest.contains(&"--apparmor-profile") {
                Command::DoctorApparmorProfile
            } else {
                Command::Doctor
            }
        }
        Some("info") => {
            reject_unknown_flags("info", &rest, &[])?;
            Command::Info
        }
        // `probe`: a top-level alias for `config probe` - the short form a newcomer reaches for first.
        Some("probe") => {
            reject_unknown_flags("probe", &rest, &[])?;
            Command::Config {
                sub: "probe".into(),
                force: false,
                json: false,
            }
        }
        // `bench [--rootfs R] [--bind-rootfs] [-n N]`: measure box start→exit latency.
        Some("bench") => {
            reject_unknown_flags(
                "bench",
                &rest,
                &["--rootfs", "--image", "--bind-rootfs", "-n", "--count"],
            )?;
            Command::Bench {
                rootfs: flag_value(&rest, "--rootfs"),
                image: flag_value(&rest, "--image"),
                bind_rootfs: rest.contains(&"--bind-rootfs"),
                count: flag_value(&rest, "-n")
                    .or_else(|| flag_value(&rest, "--count"))
                    .and_then(|v| v.parse().ok())
                    .filter(|n| *n >= 1)
                    .unwrap_or(20),
            }
        }
        Some("recover") => {
            reject_unknown_flags("recover", &rest, &[])?;
            Command::Recover
        }
        // `update <box> [--memory M] [--cpus N] [--pids-limit P]`: change a running box's caps live.
        Some("update") => {
            reject_unknown_flags(
                "update",
                &rest,
                &["-m", "--memory", "--cpus", "--pids-limit"],
            )?;
            let name = rest
                .iter()
                .skip(1)
                .find(|a| !a.starts_with('-'))
                .map(|s| (*s).to_string())
                .ok_or(Error::Usage(
                    "update <box> [--memory M] [--cpus N] [--pids-limit P]",
                ))?;
            let memory = match flag_value(&rest, "-m").or_else(|| flag_value(&rest, "--memory")) {
                Some(v) => {
                    let b = kern_common::parse_binary_size(&v).ok_or(Error::Usage(
                        "update: --memory expects a size (e.g. 512m, 1g)",
                    ))?;
                    // The SAME floor as `box`/`run`: lowering a live box's cap to 64 bytes would have
                    // the kernel OOM-kill it the moment the write lands, which is a box destroyed by a
                    // missing unit rather than a cap changed.
                    if kern_common::memory_cap_below_floor(b) {
                        return Err(Error::Cli(cap_below_floor("--memory", &v, b)));
                    }
                    Some(b)
                }
                None => None,
            };
            let cpus = match flag_value(&rest, "--cpus") {
                Some(v) => {
                    let c = v
                        .parse::<f64>()
                        .ok()
                        .filter(|c| *c > 0.0 && c.is_finite())
                        .ok_or(Error::Usage(
                            "update: --cpus expects a positive number (e.g. 1.5)",
                        ))?;
                    Some(c)
                }
                None => None,
            };
            let pids = match flag_value(&rest, "--pids-limit") {
                Some(v) => Some(
                    v.parse::<u64>()
                        .map_err(|_| Error::Usage("update: --pids-limit expects a whole number"))?,
                ),
                None => None,
            };
            Command::Update {
                name,
                memory,
                cpus,
                pids,
            }
        }
        // `events`: stream box lifecycle events until Ctrl-C (Docker parity, best-effort/daemonless).
        Some("events") => {
            reject_unknown_flags("events", &rest, &[])?;
            Command::Events
        }
        // `diff <box>`: list filesystem changes vs the box's image (Docker parity).
        Some("diff") => {
            reject_unknown_flags("diff", &rest, &["--json"])?;
            match rest.iter().skip(1).find(|a| !a.starts_with('-')) {
                Some(n) => Command::Diff {
                    name: (*n).to_string(),
                    json: rest.contains(&"--json"),
                },
                None => return Err(Error::Usage("diff <box> [--json]")),
            }
        }
        // `wait <box>...`: block until each box exits, print its exit code (Docker parity).
        Some("wait") => {
            reject_unknown_flags("wait", &rest, &[])?;
            let names: Vec<String> = rest
                .iter()
                .skip(1)
                .filter(|a| !a.starts_with('-'))
                .map(|s| (*s).to_string())
                .collect();
            if names.is_empty() {
                return Err(Error::Usage("wait <box>..."));
            }
            Command::Wait { names }
        }
        // `rename <old> <new>`: give a running box a new name (Docker parity).
        Some("rename") => {
            reject_unknown_flags("rename", &rest, &[])?;
            let mut pos = rest.iter().skip(1).filter(|a| !a.starts_with('-'));
            match (pos.next(), pos.next()) {
                (Some(old), Some(new)) => Command::Rename {
                    old: (*old).to_string(),
                    new: (*new).to_string(),
                },
                _ => return Err(Error::Usage("rename <old> <new>")),
            }
        }
        // `port <box> [<container-port>]`: what the host serves for that box's port. Docker's verb,
        // for ONE box; `kern compose <file> port <service> <port>` is the same question for a stack
        // and reaches the same selection code.
        Some("port") => {
            reject_unknown_flags("port", &rest, &[])?;
            let mut pos = rest.iter().skip(1).filter(|a| !a.starts_with('-'));
            match pos.next() {
                Some(name) => Command::Port {
                    name: (*name).to_string(),
                    container_port: pos.next().map(|p| (*p).to_string()),
                },
                None => return Err(Error::Usage("port <box> [<container-port>[/tcp|/udp]]")),
            }
        }
        Some("history") => {
            reject_unknown_flags("history", &rest, &["-n"])?;
            Command::History {
                count: flag_value(&rest, "-n")
                    .and_then(|v| v.parse().ok())
                    .filter(|n| *n >= 1)
                    .unwrap_or(20),
            }
        }
        // `login [registry] [--username U]` / `logout [registry]`: registry credentials.
        Some("login") => {
            // AN UNKNOWN FLAG IS REFUSED HERE, and it was not. `--password-stdin` was read by
            // nothing, and because the password is read from stdin anyway when stdin is not a
            // terminal, `kern login -u AWS --password-stdin` APPEARED to work: the flag was
            // discarded, the prompt was printed into the CI log, and the piped line was consumed as
            // the password. It happened to do the right thing; nothing said so, and a typo
            // (`--password-stidn`) would have done the same thing just as silently.
            reject_unknown_flags(
                "login",
                &rest,
                &["--username", "-u", "--password-stdin", "-p", "--password"],
            )?;
            let username = flag_value(&rest, "--username").or_else(|| flag_value(&rest, "-u"));
            // The positional registry is the first bare token that ISN'T the value of `--username`/`-u`.
            let registry = positional_after_flags(&rest, &["--username", "-u", "-p", "--password"]);
            // `-p/--password <value>` is Docker's, and Docker deprecates it in its own help for the
            // reason that applies here too: the value lands in argv, where any process on the host
            // reads it out of `/proc/<pid>/cmdline`. Accepted, because refusing a flag a script
            // already has helps nobody, and named for what it costs.
            let password = flag_value(&rest, "--password").or_else(|| flag_value(&rest, "-p"));
            Command::Login {
                registry,
                username,
                password,
                password_stdin: rest.contains(&"--password-stdin"),
            }
        }
        Some("logout") => Command::Logout {
            registry: positional_after_flags(&rest, &[]),
        },
        // `completions <bash|zsh|fish>`: print a shell-completion script.
        Some("completions") => {
            reject_unknown_flags("completions", &rest, &[])?;
            match rest.get(1) {
                Some(s) if !s.starts_with('-') => Command::Completions {
                    shell: (*s).to_string(),
                },
                _ => return Err(Error::Usage("completions <bash|zsh|fish>")),
            }
        }
        // `top`: live box monitor.
        Some("top") => {
            reject_unknown_flags("top", &rest, &[])?;
            Command::Top
        }
        // `compose <file> [up|down] [--no-pod]`: bring up / tear down a stack.
        Some("compose") => {
            // Verbs from COMPOSE_VERBS, so this message cannot list a set the parser does not
            // accept. It listed ten while the parser took eleven, so `systemd` was invisible here.
            // `Error::Usage` wants a `'static`: a `OnceLock` gives one without leaking, and the
            // string is built at most once per process, on an error path that ends it anyway.
            static COMPOSE_USAGE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
            let usage: &'static str = COMPOSE_USAGE
                .get_or_init(|| {
                    format!(
                        "compose [<file>...] <{}> [-p NAME] [--env-file F] [--profile P] \
                         [--no-pod] [-d] [--tail N] [-f] [-a] [service...] - with no file, the \
                         directory is searched for {}",
                        crate::commands::compose_verbs_help(),
                        COMPOSE_FILE_NAMES.join(", ")
                    )
                })
                .as_str();
            let mut files: Vec<String> = Vec::new();
            let mut project: Option<String> = None;
            let mut env_file: Option<String> = None;
            let mut profiles: Vec<String> = Vec::new();
            let mut file: Option<String> = None;
            let mut action: Option<commands::ComposeAction> = None;
            let mut no_pod = false;
            let mut force_pod = false;
            let mut bridge = false;
            let mut allow_privileged = false;
            let mut allow_device_grants = false;
            let mut pull: Option<String> = None;
            let mut stop_timeout: Option<u64> = None;
            let mut ignore_pull_failures = false;
            let mut build_args: Vec<String> = Vec::new();
            let mut run_name: Option<String> = None;
            let mut run_entrypoint: Option<String> = None;
            let mut run_env: Vec<String> = Vec::new();
            let mut run_user: Option<String> = None;
            // `Some(false)` = `--rmi local`, `Some(true)` = `--rmi all`.
            let mut rmi: Option<bool> = None;
            let mut tail: Option<usize> = None;
            let mut follow = false;
            let mut all = false;
            let mut detach = false;
            let mut remove_volumes = false;
            let mut wait_ready = false;
            let mut wait_timeout: Option<u64> = None;
            let mut exit_code_from: Option<String> = None;
            let mut abort_on_exit = false;
            let mut remove_orphans = false;
            let mut ps_quiet = false;
            let mut ps_services = false;
            let mut ps_format: Option<String> = None;
            let mut run_cmd: Vec<String> = Vec::new();
            let mut run_rm = false;
            let mut no_deps = false;
            // `--force-recreate` / `--no-recreate`: tracked as two booleans rather than one policy
            // so the contradiction of writing BOTH can be refused by name, the way Docker refuses it.
            let mut force_recreate = false;
            let mut no_recreate = false;
            let mut renew_anon_volumes = false;
            let mut log_timestamps = false;
            let (mut log_since, mut log_until) = (None, None);
            let mut no_log_prefix = false;
            let log_now = log_clock_now();
            let mut services: Vec<String> = Vec::new();
            let mut it = rest.iter().skip(1).peekable();
            while let Some(a) = it.next() {
                // `run <service> <command…>`: ONCE THE SERVICE IS NAMED, THE REST IS THE COMMAND,
                // flags and all. Without this, `run web sh -c 'exit 7'` has `-c` read as a kern
                // flag and the invocation from every project README is a usage error.
                if matches!(
                    action,
                    Some(commands::ComposeAction::Run) | Some(commands::ComposeAction::Exec)
                ) && !services.is_empty()
                {
                    run_cmd.push((*a).to_string());
                    continue;
                }
                // `--flag=value` IS THE SAME FLAG. Docker accepts both spellings and real scripts
                // use both: Sentry's `install.sh` runs `docker compose … run --pull=never --rm`,
                // and kern answered `unknown flag '--pull=never'`, which stopped the official
                // installer of a stack this runtime claims to run. Normalised HERE and not before
                // the loop, because after `run <service>` every token belongs to the command and
                // `mycmd --opt=1` must reach it whole.
                let (key, inline) = match a.split_once('=') {
                    Some((k, v)) if k.starts_with("--") => (k, Some(v)),
                    _ => (*a, None),
                };
                match key {
                    "--no-pod" => no_pod = true,
                    // `--bridge`: the third wiring, and the only one that is Docker's arrangement.
                    // Each service gets its own network namespace on a bridge the pod holds, so a
                    // port a service binds on its loopback is ITS OWN, two services may bind the
                    // same container port, and peers meet at addresses instead of through a relay.
                    "--bridge" => bridge = true,
                    // The explicit opt-OUT of the auto-selection below. Without it a file that
                    // expresses segregation is wired per service, which is what it asked for; with
                    // it the stack keeps one namespace and the segregation is dropped, which is what
                    // kern did before and is still the faster wiring.
                    "--pod" => force_pod = true,
                    // `--pull <policy>`: Docker's per-invocation override, mapped through the ONE
                    // table the `pull_policy:` key uses (`pull_policy_word`). A word neither
                    // vocabulary knows is REFUSED rather than ignored: silently pulling when the
                    // caller asked not to is the failure this flag exists to prevent.
                    "--pull" => {
                        let raw = inline_or_next(inline, &mut it)
                            .ok_or(Error::Usage("compose --pull <always|missing|never>"))?;
                        match kern_compose::pull_policy_word(&raw) {
                            Some(mapped) => pull = Some(mapped.to_string()),
                            None => {
                                return Err(Error::Usage(
                                    "compose --pull takes always, missing or never",
                                ))
                            }
                        }
                    }
                    // `-t` IS TWO FLAGS AND THE VERB DECIDES WHICH, exactly as it does under
                    // Docker: `compose logs -t` asks for timestamps, `compose down -t 30` for a stop
                    // grace. The guarded arm comes FIRST, so the verb is consulted before the
                    // fallback claims the token; written the other way round the compiler says so
                    // (`unreachable pattern`), which is how the ordering was found.
                    "-t" | "--timestamps" if action == Some(commands::ComposeAction::Logs) => {
                        log_timestamps = true
                    }
                    // `-t/--timeout <secs>`: the stop grace for THIS teardown, replacing what each
                    // box recorded at start. `0` is a real value (Docker reads it as "kill now"), so
                    // a parse failure is refused rather than folded into the default.
                    "-t" | "--timeout" => {
                        let raw = inline_or_next(inline, &mut it)
                            .ok_or(Error::Usage("compose -t <seconds>"))?;
                        stop_timeout =
                            Some(raw.trim().parse::<u64>().map_err(|_| {
                                Error::Usage("compose -t <seconds> (a whole number)")
                            })?);
                    }
                    // `--ignore-pull-failures` is what `compose pull` ALREADY does for a service that
                    // declares `build:`, and the flag asks for it unconditionally: a registry that
                    // does not have an image is reported and the run continues.
                    "--ignore-pull-failures" => ignore_pull_failures = true,
                    // `run --name <n>` and `run --entrypoint <cmd>`: Docker's two one-off overrides.
                    // Sentry's installer uses both in one command to run a migration under a name it
                    // then waits on.
                    "--name" => {
                        run_name = Some(
                            inline_or_next(inline, &mut it)
                                .ok_or(Error::Usage("compose run --name <name>"))?,
                        )
                    }
                    "--entrypoint" => {
                        run_entrypoint = Some(
                            inline_or_next(inline, &mut it)
                                .ok_or(Error::Usage("compose run --entrypoint <command>"))?,
                        )
                    }
                    // `run -e KEY=VALUE`, repeatable: an environment entry for THIS one-off, on top
                    // of the service's own. Sentry's installer bootstraps its node store with three
                    // of them in one command.
                    "-e" | "--env" => run_env.push(
                        inline_or_next(inline, &mut it)
                            .ok_or(Error::Usage("compose run -e KEY=VALUE"))?,
                    ),
                    // `run --user <uid[:gid]>`: Docker's per-invocation identity, which kern's box
                    // already takes as `--user`. Sentry's installer fixes a directory's ownership
                    // with `run --user 0 ... chown`.
                    "-u" | "--user" => {
                        run_user = Some(
                            inline_or_next(inline, &mut it)
                                .ok_or(Error::Usage("compose run --user <uid[:gid]>"))?,
                        )
                    }
                    // `compose build --build-arg K=V`, repeatable, forwarded to every service this
                    // invocation builds. Sentry's installer passes six of them (the proxy set) on
                    // every single build, so without this its `build` step could not run at all.
                    "--build-arg" => build_args.push(
                        inline_or_next(inline, &mut it)
                            .ok_or(Error::Usage("compose build --build-arg K=V"))?,
                    ),
                    // `--rmi <local|all>` on `down`: also remove the stack's images. `local` is
                    // Docker's "only the ones this file produced", which for kern is exactly the
                    // services that declare `build:`; `all` is every image the file names. A third
                    // word is refused rather than folded into one of the two, because the difference
                    // between them is other people's images.
                    "--rmi" => {
                        let raw = inline_or_next(inline, &mut it)
                            .ok_or(Error::Usage("compose down --rmi <local|all>"))?;
                        match raw.trim().to_ascii_lowercase().as_str() {
                            "local" => rmi = Some(false),
                            "all" => rmi = Some(true),
                            _ => return Err(Error::Usage("compose down --rmi takes local or all")),
                        }
                    }
                    // `--quiet-pull` only asks for less output, and kern's pull narration is already
                    // terminal-gated: accepted, with the same note the other no-effect flags get.
                    "--quiet-pull" => eprintln!(
                        "kern: warning: compose: '--quiet-pull' has no effect on kern - ignored"
                    ),
                    "--allow-device-grants" => allow_device_grants = true,
                    // The operator's half of `privileged: true`. Its own flag and not folded into
                    // `--allow-device-grants`: one grants access to named device nodes, the other
                    // relaxes the seccomp filter, and an operator who wants one has not asked for
                    // the other.
                    "--allow-privileged" => allow_privileged = true,
                    // `-f` IS DOCKER'S FILE FLAG BEFORE THE VERB AND ITS FOLLOW FLAG AFTER `logs`,
                    // and reading it as `--follow` everywhere is how `kern compose -f
                    // docker-compose.yml logs web` came to hang. MEASURED by an independent test,
                    // who lost half an hour to a job parked on it, and reproduced here in one pair:
                    // `compose docker-compose.yml logs a` prints and exits, `compose -f
                    // docker-compose.yml logs a` never returns. It is also the invocation in every
                    // project README, since that is how `docker compose` is written, which is why it
                    // silently "worked" for `up -d` (a harmless follow) and bit only on `logs`.
                    "-f" | "--file" if action.is_none() => {
                        let w = inline_or_next(inline, &mut it)
                            .ok_or(Error::Usage("compose -f <file>"))?;
                        // Same slots the positional form fills, so `-f a.yml -f b.yml` merges exactly
                        // as `compose a.yml b.yml` does.
                        if file.is_none() {
                            file = Some(w.clone());
                        }
                        files.push(w);
                    }
                    "-f" | "--follow" => follow = true,
                    "-a" | "--all" => all = true,
                    "-p" | "--project-name" => {
                        project = Some(
                            inline_or_next(inline, &mut it)
                                .map(|v| (*v).to_string())
                                .ok_or(Error::Usage("compose -p <project-name>"))?,
                        );
                    }
                    "--env-file" => {
                        env_file = Some(
                            inline_or_next(inline, &mut it)
                                .map(|v| (*v).to_string())
                                .ok_or(Error::Usage("compose --env-file <path>"))?,
                        );
                    }
                    "--profile" => {
                        profiles.push(
                            inline_or_next(inline, &mut it)
                                .map(|v| (*v).to_string())
                                .ok_or(Error::Usage("compose --profile <name>"))?,
                        );
                    }
                    // Presentation/scheduling knobs with no semantic effect here: accepted so a Docker
                    // script runs unchanged, and NOTED so nobody believes they did something.
                    // `--parallel` is not silently honoured - kern has its own concurrency cap.
                    "--ansi" | "--progress" | "--parallel" => {
                        let v = inline_or_next(inline, &mut it).unwrap_or_default();
                        eprintln!(
                            "kern: warning: compose: '{a} {v}' has no effect on kern - ignored"
                        );
                    }
                    "--no-ansi" | "--compatibility" | "--dry-run" => {
                        eprintln!("kern: warning: compose: '{a}' has no effect on kern - ignored");
                    }
                    // `-d`/`--detach` is how almost every Docker user starts a stack. It now carries
                    // the meaning it names: WITH it `up` returns as soon as the stack is up, and
                    // WITHOUT it an interactive `up` streams the stack's logs like Docker's. It used
                    // to be a no-op, which made the two spellings indistinguishable.
                    "-d" | "--detach" => detach = true,
                    // `down -v` deletes this project's named volumes, as Docker's does. Refused
                    // before, with a usage dump that named no flag: MEASURED that kern DOES create
                    // named volumes (under its volumes dir) and never removed them, so a stack torn
                    // down and started fresh silently reused the old data.
                    "-v" | "--volumes" => remove_volumes = true,
                    // `up -d --wait`: hold until every service is ready, which is what a CI job
                    // needs before it runs anything against the stack. Docker's semantics,
                    // measured on 29.6.2 and reproduced here: a service with a healthcheck must
                    // reach `healthy`, one without must still be RUNNING, and a service that has
                    // already exited fails the wait even with status 0.
                    "--wait" => wait_ready = true,
                    // `run --rm`: the spelling every README uses. kern's foreground box leaves no
                    // running entry either way, so this is accepted and honoured rather than
                    // refused on a technicality.
                    "--rm" if action == Some(commands::ComposeAction::Run) => run_rm = true,
                    // `-T` disables the TTY under Docker. kern's `exec` allocates one only when it
                    // is asked to, so the flag names what already happens and is taken silently.
                    "-T" | "--no-TTY"
                        if matches!(
                            action,
                            Some(commands::ComposeAction::Run)
                                | Some(commands::ComposeAction::Exec)
                        ) => {}
                    "--no-deps" => no_deps = true,
                    // `up --force-recreate`: recreate every running service, drift or no drift. The
                    // line a deploy script writes after changing something the definition does not
                    // hash - a bind-mounted config file, a token injected into a shared volume by
                    // the step before. kern compares a fingerprint and leaves a matching service
                    // alone, which is right by default and wrong exactly here.
                    "--force-recreate" => force_recreate = true,
                    // `up --no-recreate`: start what is missing, touch nothing that is running, even
                    // where the file HAS moved.
                    "--no-recreate" => no_recreate = true,
                    // `up -V/--renew-anon-volumes`: discard the anonymous volumes of the services
                    // this `up` starts, instead of carrying the previous run's contents into them.
                    "-V" | "--renew-anon-volumes" => renew_anon_volumes = true,
                    "--no-log-prefix" => no_log_prefix = true,
                    "--since" | "--until" => {
                        let v = inline_or_next(inline, &mut it).ok_or(Error::Usage(
                            "compose logs --since/--until <10m|1h30m|1789730443|2026-09-18T12:00:00Z>",
                        ))?;
                        let t = parse_log_window(key, &v, log_now)?;
                        if key == "--since" {
                            log_since = Some(t);
                        } else {
                            log_until = Some(t);
                        }
                    }
                    // `up --exit-code-from S`: the CI line that turns a test service's status into
                    // the job's. MEASURED on Docker 29.6.2: it implies `--abort-on-container-exit`,
                    // the whole stack is torn down when ANY service exits, and the status reported
                    // is the NAMED service's, which is 137 when the abort is what killed it.
                    "--exit-code-from" => {
                        exit_code_from = Some(
                            inline_or_next(inline, &mut it)
                                .map(|v| (*v).to_string())
                                .ok_or(Error::Usage("compose --exit-code-from <service>"))?,
                        );
                        abort_on_exit = true;
                    }
                    "--abort-on-container-exit" => abort_on_exit = true,
                    // `down --remove-orphans`: stop this project's boxes whose service the file no
                    // longer names, which is what a renamed service leaves behind.
                    "--remove-orphans" => remove_orphans = true,
                    // `ps` FORMATTING, threaded straight to `kern ps`, which is the renderer the
                    // compose view already uses. These are the three spellings a deploy script
                    // reaches for: `ps -q` for a loop over ids, `--services` for a loop over names,
                    // `--format json` for anything that parses.
                    "-q" | "--quiet" => ps_quiet = true,
                    "--services" => ps_services = true,
                    "--format" => {
                        ps_format = Some(
                            inline_or_next(inline, &mut it)
                                .map(|v| (*v).to_string())
                                .ok_or(Error::Usage("compose ps --format <template|json>"))?,
                        );
                    }
                    "--wait-timeout" => {
                        wait_timeout = Some(
                            inline_or_next(inline, &mut it)
                                .and_then(|v| v.parse::<u64>().ok())
                                .ok_or(Error::Usage("compose --wait-timeout N (seconds)"))?,
                        );
                        wait_ready = true;
                    }
                    // `--build` names what kern ALREADY does, and this one is measured rather than
                    // assumed: with the Dockerfile edited between two runs, Docker without the flag
                    // printed the OLD marker and kern printed the new one. So the flag is accepted
                    // silently, and `--no-build` is refused loudly for the same reason: kern cannot
                    // promise the stale image the flag is asking for.
                    "--build" => {}
                    "--no-build" => {
                        eprintln!(
                            "kern: warning: compose: '--no-build' cannot be honoured - kern rebuilds \
                             a `build:` service whose context changed, where Docker would reuse the \
                             image it built before. Run `kern compose <file> build` when you want \
                             the build on its own."
                        );
                    }
                    "--tail" => {
                        // A non-numeric `--tail` is a typo, not "show everything": refuse it.
                        tail = Some(
                            inline_or_next(inline, &mut it)
                                .and_then(|v| v.parse::<usize>().ok())
                                .ok_or(Error::Usage("compose --tail N (a number of lines)"))?,
                        );
                    }
                    f if f.starts_with('-') => {
                        return Err(Error::Compose(unknown_compose_flag(f)));
                    }
                    // First bare word that names a verb IS the verb; the file is the first bare word
                    // that is not one (Docker puts the file behind `-f`, kern takes it positionally).
                    w => {
                        if action.is_none() {
                            if let Some(act) = commands::ComposeAction::from_verb(w) {
                                action = Some(act);
                                continue;
                            }
                            // A DOCKER VERB KERN DOES NOT HAVE IS REFUSED BY NAME, before it can be
                            // read as something else. Without this, `kern compose f.yml create`
                            // parsed `create` as a SERVICE name and reported "no such service:
                            // create", which sends the reader to look at their file for a service
                            // they never wrote. The word is a verb; the answer has to be about the
                            // verb.
                            if let Some(why) = refused_compose_verb(w) {
                                return Err(Error::Compose(why));
                            }
                        }
                        if file.is_none() {
                            file = Some(w.to_string());
                            files.push(w.to_string());
                        } else if action.is_none()
                            && (w.ends_with(".yml") || w.ends_with(".yaml") || w.ends_with(".toml"))
                        {
                            // Another compose FILE (kern takes them positionally; the shim turns each
                            // Docker `-f` into one of these). Anything else selects services.
                            files.push(w.to_string());
                        } else {
                            // Anything after the file and the verb selects services (`logs api web`).
                            services.push(w.to_string());
                        }
                    }
                }
            }
            // NO FILE NAMED IS `docker compose <verb>`, WHICH IS HOW THE COMMAND IS ACTUALLY
            // WRITTEN. Every README, every `npm start`, every `Makefile` runs `docker compose up -d`
            // from the directory holding the file, and kern answered a usage dump listing a
            // positional `<file>` it did not have to require: `kern up` and `kern down` have
            // discovered the file in the working directory since they existed, from the same four
            // names Docker looks for. The verb form now reaches the same discovery, so the two
            // spellings cannot disagree about which file a directory means.
            //
            // A BARE `kern compose` STILL PRINTS USAGE. Discovery answers "which file", not "which
            // verb", and a lone `kern compose` has named neither: guessing `up` there would start a
            // stack on a keystroke, which is the one outcome nobody would have wanted.
            if files.is_empty() {
                if action.is_none() {
                    return Err(Error::Usage(usage));
                }
                let found = discover_compose_file().ok_or_else(no_compose_file_here)?;
                file = Some(found.clone());
                files.push(found);
            }
            // `--` AFTER THE SERVICE IS A SEPARATOR, NOT THE PROGRAM TO RUN. The loop above sends
            // everything after the service name into the command, flags and all, which is what makes
            // `run web sh -c 'exit 7'` work. It also swallowed the `--` that people type out of habit
            // and that `docker compose` accepts and drops, so `exec -T web -- echo hi` tried to
            // execute a file called `--` and died with `execvp failed: No such file or directory`.
            // MEASURED before the fix: without `--` it printed `hi`, with it exit 127 and that error;
            // `kern exec <box> -- echo hi` has always worked, so the two verbs disagreed.
            //
            // ONLY THE FIRST TOKEN, and only when it is exactly `--`: a later one belongs to the
            // command (`sh -c 'git log --'`) and is none of kern's business.
            if run_cmd.first().is_some_and(|a| a == "--") {
                run_cmd.remove(0);
            }
            let _ = file;
            // THE TWO CONTRADICT EACH OTHER AND ARE REFUSED TOGETHER, by name, as Docker refuses
            // them. Picking one silently would recreate a stack somebody asked not to touch, or
            // leave one somebody asked to replace, and either way the command line said otherwise.
            let recreate =
                match (force_recreate, no_recreate) {
                    (true, true) => return Err(Error::Compose(
                        "--force-recreate and --no-recreate cannot be combined: one says recreate \
                         every running service, the other says recreate none"
                            .to_string(),
                    )),
                    (true, false) => commands::RecreatePolicy::Always,
                    (false, true) => commands::RecreatePolicy::Never,
                    (false, false) => commands::RecreatePolicy::OnDrift,
                };
            Command::Compose {
                files,
                action: action.unwrap_or(commands::ComposeAction::Up),
                pull,
                stop_timeout,
                ignore_pull_failures,
                build_args,
                run_name,
                run_entrypoint,
                run_env,
                run_user,
                rmi,
                recreate,
                renew_anon_volumes,
                log_timestamps,
                log_window: (log_since, log_until),
                no_log_prefix,
                no_pod,
                bridge,
                allow_privileged,
                force_pod,
                allow_device_grants,
                detach,
                remove_volumes,
                wait_ready,
                wait_timeout,
                run_cmd,
                run_rm,
                no_deps,
                exit_code_from,
                abort_on_exit,
                remove_orphans,
                ps_quiet,
                ps_services,
                ps_format,
                tail,
                follow,
                all,
                services,
                project,
                env_file,
                profiles,
            }
        }
        // `up [--no-pod]` / `down`: Docker-familiar shorthands that DISCOVER a compose file in the CWD
        // (`docker-compose.yml`/`compose.yml`/…) and bring it up / tear it down. The whole point of the
        // compat surface: land in a dir with a compose file, type `kern up`, it just works.
        Some("up") | Some("down") => {
            let action = if rest.first().copied() == Some("down") {
                commands::ComposeAction::Down
            } else {
                commands::ComposeAction::Up
            };
            let no_pod = rest.contains(&"--no-pod");
            let bridge = rest.contains(&"--bridge");
            let force_pod = rest.contains(&"--pod");
            let allow_device_grants = rest.contains(&"--allow-device-grants");
            let allow_privileged = rest.contains(&"--allow-privileged");
            let file = discover_compose_file().ok_or_else(no_compose_file_here)?;
            Command::Compose {
                files: vec![file],
                action,
                // The shorthand takes no `--pull`: it is `kern up` in a directory, and a policy
                // override belongs to the explicit form.
                pull: None,
                stop_timeout: None,
                ignore_pull_failures: false,
                build_args: Vec::new(),
                run_name: None,
                run_entrypoint: None,
                run_env: Vec::new(),
                run_user: None,
                rmi: None,
                // The shorthand carries the recreate overrides too: `kern up --force-recreate` in a
                // directory is the same habit as the explicit form, and a flag that parses on one
                // and not the other is a difference nobody can hold in their head.
                recreate: match (
                    rest.contains(&"--force-recreate"),
                    rest.contains(&"--no-recreate"),
                ) {
                    (true, true) => {
                        return Err(Error::Compose(
                            "--force-recreate and --no-recreate cannot be combined: one says \
                             recreate every running service, the other says recreate none"
                                .to_string(),
                        ))
                    }
                    (true, false) => commands::RecreatePolicy::Always,
                    (false, true) => commands::RecreatePolicy::Never,
                    (false, false) => commands::RecreatePolicy::OnDrift,
                },
                renew_anon_volumes: rest.contains(&"-V") || rest.contains(&"--renew-anon-volumes"),
                // The `kern up`/`kern down` shorthand has no `logs` verb, so the log flags cannot be
                // typed on it and carry their defaults rather than a parse nobody can reach.
                log_timestamps: false,
                log_window: (None, None),
                no_log_prefix: false,
                no_pod,
                bridge,
                allow_privileged,
                force_pod,
                allow_device_grants,
                // The shorthand takes `-d` too: `kern up -d` is the same habit as `docker compose
                // up -d`, and without it an interactive `kern up` streams like Docker's.
                detach: rest.contains(&"-d") || rest.contains(&"--detach"),
                remove_volumes: rest.contains(&"-v") || rest.contains(&"--volumes"),
                wait_ready: rest.contains(&"--wait"),
                wait_timeout: None,
                run_cmd: Vec::new(),
                run_rm: false,
                no_deps: rest.contains(&"--no-deps"),
                exit_code_from: None,
                abort_on_exit: false,
                remove_orphans: rest.contains(&"--remove-orphans"),
                ps_quiet: false,
                ps_services: false,
                ps_format: None,
                tail: None,
                follow: false,
                all: false,
                services: Vec::new(),
                project: None,
                env_file: None,
                profiles: Vec::new(),
            }
        }
        // `config`: list resource profiles from kern.toml.
        Some("config" | "cfg") => {
            let sub = rest
                .get(1)
                .filter(|s| !s.starts_with('-'))
                .map(|s| (*s).to_string())
                .unwrap_or_else(|| "list".into());
            match sub.as_str() {
                "list" | "edit" | "setup" | "probe" | "clear" => {
                    // A flag these verbs do not take is REFUSED, never ignored: a script that asked
                    // for JSON and silently got prose could not tell, and the same held for any typo.
                    // `--json` is accepted by `list` ALONE, because `list` is the only read verb here;
                    // on `edit`/`setup`/`probe`/`clear` it stays an error rather than being tolerated,
                    // since those change things and a caller passing --json to them has the wrong verb.
                    let json = rest.contains(&"--json");
                    for a in rest.iter().skip(1) {
                        let s: &str = a;
                        let ok = matches!(s, "--force" | "--yes" | "-y")
                            || (s == "--json" && sub == "list");
                        if s.starts_with('-') && !ok {
                            return Err(Error::Cli(format!(
                                "config {sub}: unknown flag {s:?} - `config list` takes --json; `config setup`/`clear` take --force/--yes/-y"
                            )));
                        }
                    }
                    Command::Config {
                        force: rest
                            .iter()
                            .any(|a| *a == "--force" || *a == "--yes" || *a == "-y"),
                        json,
                        sub,
                    }
                }
                "add" => Command::ConfigAdd {
                    args: rest.iter().skip(2).map(|s| (*s).to_string()).collect(),
                },
                "rm" | "remove" | "delete" => Command::ConfigRm {
                    args: rest.iter().skip(2).map(|s| (*s).to_string()).collect(),
                },
                _ => return Err(Error::Usage(crate::commands::CONFIG_USAGE)),
            }
        }
        // `validate [path]`: parse a kern.toml and report OK or the offending line.
        // `uninstall`: the confirm flag is spelled as the other destructive verbs spell it
        // (`config clear`), and an unknown flag is refused rather than ignored, so `--dry-run` (which
        // does not exist, because a dry run IS the default) cannot be mistaken for a no-op switch.
        Some("uninstall") => {
            for a in rest.iter().skip(1) {
                let s: &str = a;
                if s.starts_with('-') && !matches!(s, "--yes" | "-y" | "--force" | "--keep-images")
                {
                    return Err(Error::Cli(format!(
                        "uninstall: unknown flag {s:?} - it takes --yes (or --force) and --keep-images"
                    )));
                }
            }
            Command::Uninstall {
                yes: rest
                    .iter()
                    .any(|a| *a == "--yes" || *a == "-y" || *a == "--force"),
                keep_images: rest.contains(&"--keep-images"),
            }
        }
        Some("validate") => {
            reject_unknown_flags("validate", &rest, &[])?;
            Command::Validate {
                path: rest
                    .iter()
                    .skip(1)
                    .find(|a| !a.starts_with('-'))
                    .map(|s| (*s).to_string()),
            }
        }
        // `examples`: print an example kern.toml.
        Some("examples" | "example") => {
            reject_unknown_flags("examples", &rest, &[])?;
            Command::Examples
        }
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
/// Resolve a Docker-style `--ulimit NAME=SOFT[:HARD]` into `(RLIMIT_*, soft, hard)`.
///
/// Only POSIX resources with a stable `RLIMIT_*` constant are accepted; an unknown name is REFUSED
/// rather than ignored, because a limit the workload believes is in force but is not is exactly the
/// silent-divergence class this codebase refuses. `unlimited`, `infinity` and `-1` mean
/// `RLIM_INFINITY`; a bare `NAME=N` sets soft and hard alike, as Docker does.
/// Resolve a signal written as a name (`SIGTERM`, `TERM`) or a number (`15`).
///
/// Only signals a stop contract can meaningfully use are accepted; an unknown name is REFUSED rather
/// than quietly falling back to SIGTERM, because a workload trapping SIGUSR1 that silently got
/// SIGTERM would shut down the wrong way and look like the trap never ran.
/// The same table, for a signal that came from an IMAGE rather than from a flag.
///
/// `None` RATHER THAN A REFUSAL, and the difference is who wrote the value. A flag is typed by the
/// person running kern, so an unknown name is their typo and must be refused before anything starts.
/// An image's `STOPSIGNAL` is written by whoever built the image, is read on a path where there is
/// no usage error to return, and a name kern does not know (`SIGPWR`, say) must not stop a box from
/// running: the caller falls back to `SIGTERM`, which is what kern did before it read the field at
/// all.
pub(crate) fn parse_signal_name(s: &str) -> Option<i32> {
    parse_signal(s).ok()
}

fn parse_signal(s: &str) -> Result<i32, Error> {
    const USAGE: &str = "--stop-signal <NAME|NUM>: TERM INT QUIT HUP USR1 USR2 KILL (or a number)";
    let t = s.trim();
    if let Ok(n) = t.parse::<i32>() {
        return if (1..=64).contains(&n) {
            Ok(n)
        } else {
            Err(Error::Usage(USAGE))
        };
    }
    let name = t.to_ascii_uppercase();
    let name = name.strip_prefix("SIG").unwrap_or(&name);
    Ok(match name {
        "TERM" => libc::SIGTERM,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "HUP" => libc::SIGHUP,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "KILL" => libc::SIGKILL,
        _ => return Err(Error::Usage(USAGE)),
    })
}

fn parse_ulimit(spec: &str) -> Result<(i32, u64, u64), Error> {
    const USAGE: &str =
        "--ulimit NAME=SOFT[:HARD] where NAME is one of: core cpu data fsize locks \
                         memlock msgqueue nice nofile nproc rss rtprio rttime sigpending stack";
    let (name, bounds) = spec.split_once('=').ok_or(Error::Usage(USAGE))?;
    // ONE table for the whole binary, and it is the sandbox's: the CLI resolves a name to a number
    // here, and a diagnostic from inside the box resolves that number back to this same name. The
    // copy that used to live in this function was the reason a clamped limit was reported as
    // `--ulimit resource 8`. See `kern_isolation::ULIMITS`.
    let wanted = name.trim().to_ascii_lowercase();
    let resource: i32 = kern_isolation::ULIMITS
        .iter()
        .find(|(n, _, _, _)| *n == wanted)
        .map(|(_, r, _, _)| *r)
        .ok_or(Error::Usage(USAGE))?;
    let one = |v: &str| -> Result<u64, Error> {
        let v = v.trim();
        match v {
            "unlimited" | "infinity" | "-1" => Ok(libc::RLIM_INFINITY),
            _ => v.parse::<u64>().map_err(|_| Error::Usage(USAGE)),
        }
    };
    let (soft, hard) = match bounds.split_once(':') {
        Some((s, h)) => (one(s)?, one(h)?),
        None => {
            let both = one(bounds)?;
            (both, both)
        }
    };
    // The kernel refuses soft > hard with EINVAL; catching it here names the actual mistake.
    if soft > hard {
        return Err(Error::Usage(
            "--ulimit: the soft limit cannot exceed the hard limit (NAME=SOFT:HARD)",
        ));
    }
    Ok((resource, soft, hard))
}

/// A loadable AppArmor profile name, validated at the CLI edge with the SAME charset the SDK
/// bindings enforce (`APPARMOR_RE`): `[A-Za-z0-9_.]` first, `[A-Za-z0-9_.-]` after, 1..=128 bytes.
/// The CLI does NOT go through the bindings, so without this a name with a newline/space/`=` would
/// reach the registry record's `key=value` line format (only `one_line`'s flattening keeps it from
/// forging a field today) and, worse, a name AppArmor cannot load would start the box only to fail
/// the transition later with a baffling EACCES. Reject it here, where the error is actionable.
fn valid_apparmor_name(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 128 {
        return false;
    }
    let ok_first = b[0].is_ascii_alphanumeric() || matches!(b[0], b'_' | b'.');
    ok_first
        && b[1..]
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

/// What one `--mount` spec turned into: the `-v` string it is equivalent to, or a `--tmpfs` one.
///
/// TWO OUTPUTS AND NOT ONE, because `--mount` spans two of kern's flags. `type=bind` and
/// `type=volume` are both `-v` (the source tells them apart, which is [`crate::volume::classify`]'s
/// job and not this function's); `type=tmpfs` has no source at all and is `--tmpfs`. Collapsing
/// them into one string would put a tmpfs spec through the volume resolver, which would read the
/// empty source as a named volume and create a directory on disk for it.
#[derive(Debug, PartialEq, Eq)]
enum MountSpec {
    /// A `-v` spec: `src:dst` or `src:dst:ro`.
    Volume(String),
    /// A `--tmpfs` spec: `dst` or `dst:size`.
    Tmpfs(String),
}

/// Parse one Docker `--mount type=…,src=…,dst=…` spec into the `-v`/`--tmpfs` spec it means.
///
/// WHY THIS EXISTS AS A TRANSLATION AND NOT A SECOND MOUNT PATH. Everything `--mount` can express,
/// `-v` and `--tmpfs` already express; what it has that they do not is a NAME for each field, which
/// is why generated command lines and orchestrators emit this form. Parsing it into the existing
/// spec strings means the mount reaches exactly one resolver, so a `--mount` and the `-v` it is
/// equivalent to cannot start to behave differently.
///
/// GRAMMAR, comma-separated `key=value` pairs, Docker's own key aliases accepted:
///
/// ```text
///   type=bind|volume|tmpfs     default volume, as Docker's
///   src=|source=               the host path or volume name
///   dst=|destination=|target=  the path inside the box
///   ro|readonly|readonly=true  read-only
///   tmpfs-size=<size>          type=tmpfs only
/// ```
///
/// ⛔ THE ONE CASE THAT IS REFUSED RATHER THAN TRANSLATED, and it is the reason this is not a
/// three-line `split(',')`: `type=bind,src=data,dst=/app`. `-v data:/app` is a NAMED VOLUME, because
/// the source is not absolute and does not start with `./`. Passed through, a caller who wrote
/// `bind` and meant "the `data` directory next to me" would get an empty auto-created volume, the
/// box would start, and the mount would be empty with no error anywhere. Docker refuses the same
/// input. The check is `volume::classify`, so the rule that decides it is the same one the resolver
/// applies later and the two cannot drift.
fn parse_mount_spec(spec: &str) -> Result<MountSpec, Error> {
    const USAGE: Error = Error::Usage(
        "--mount type=bind|volume|tmpfs,src=<source>,dst=<path>[,ro] \
         (e.g. --mount type=bind,src=/srv/app,dst=/app,ro)",
    );
    let (mut kind, mut src, mut dst, mut ro, mut size) = ("volume", "", "", false, "");
    for field in spec.split(',') {
        let field = field.trim();
        if field.is_empty() {
            continue;
        }
        // A bare `ro`/`readonly` is a flag, not a pair. Docker accepts both spellings and also the
        // `readonly=true` pair form, so all three land here.
        let (key, value) = match field.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (field, ""),
        };
        match key {
            "type" => kind = value,
            "src" | "source" => src = value,
            "dst" | "destination" | "target" => dst = value,
            // `readonly=false` is an explicit NO and must not turn the mount read-only: reading any
            // `readonly` key as "yes" would make the one spelling that disables it enable it.
            "ro" | "readonly" | "read-only" => ro = value.is_empty() || value == "true",
            "tmpfs-size" => size = value,
            // An unknown key is refused, not skipped: `type=bind,src=/a,dest=/b` (a real typo, the
            // key is `dst` or `destination`) would otherwise parse as a mount with NO destination.
            _ => return Err(USAGE),
        }
    }
    if dst.is_empty() {
        return Err(USAGE);
    }
    match kind {
        "tmpfs" => {
            if !src.is_empty() {
                return Err(Error::Usage(
                    "--mount type=tmpfs takes no src= (a tmpfs is empty by definition)",
                ));
            }
            Ok(MountSpec::Tmpfs(if size.is_empty() {
                dst.to_string()
            } else {
                format!("{dst}:{size}")
            }))
        }
        "bind" | "volume" => {
            if src.is_empty() {
                return Err(USAGE);
            }
            if !size.is_empty() {
                return Err(Error::Usage(
                    "--mount tmpfs-size= applies to type=tmpfs only",
                ));
            }
            // THE REFUSAL DOCUMENTED ABOVE. Asked of the resolver's own classifier, both ways: a
            // `bind` whose source is not a path would become a volume, and a `volume` whose source
            // is a path would become a bind. Either way the caller named one thing and would get
            // the other, silently.
            let named = crate::volume::classify(src) == crate::volume::SourceKind::Named;
            if kind == "bind" && named {
                return Err(Error::Usage(
                    "--mount type=bind needs an absolute or ./-relative src (a bare name is a \
                     named volume, which would mount an empty directory instead)",
                ));
            }
            if kind == "volume" && !named {
                return Err(Error::Usage(
                    "--mount type=volume needs a volume NAME as src, not a path (use type=bind)",
                ));
            }
            Ok(MountSpec::Volume(if ro {
                format!("{src}:{dst}:ro")
            } else {
                format!("{src}:{dst}")
            }))
        }
        _ => Err(USAGE),
    }
}

/// real sandbox. Without a rootfs/image it still routes to `BoxRun` (which reports the missing
/// source); `--plan` previews instead of running.
fn parse_box(rest: &[&str]) -> Result<Command, Error> {
    let mut rm = false;
    let mut name: Option<&str> = None;
    let mut rootfs: Option<String> = None;
    let mut image: Option<String> = None;
    let mut pull = commands::PullPolicy::default();
    let mut plan = false;
    let mut detached = false;
    let mut read_only = false;
    let mut share_net = false;
    let mut pod: Option<String> = None;
    let mut pod_bridge: Option<kern_isolation::BridgeAttach> = None;
    let mut uid_range = false;
    let mut no_uid_range = false;
    let mut bind_rootfs = false;
    let mut privileged = false;
    let mut require_limits = false;
    let mut allow_uncapped = false;
    let mut security_profile: Option<commands::SecurityProfile> = None;
    let mut overlay_lower: Option<String> = None;
    let mut overlay_upper: Option<String> = None;
    let mut tty = false;
    let mut restart = commands::RestartPolicy::No;
    let mut health_cmd: Option<String> = None;
    let mut health_cmd_argv: Vec<String> = Vec::new();
    let mut health_interval = 30u64;
    let mut health_retries = 3u32;
    let mut health_start_period = 0u64;
    let mut health_start_interval = 0u64;
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
    let mut dns: Vec<String> = Vec::new();
    let mut dns_search: Vec<String> = Vec::new();
    let mut dns_options: Vec<String> = Vec::new();
    let mut log_max_size: Option<u64> = None;
    let mut log_max_file: Option<u32> = None;
    let mut memory_reservation: Option<u64> = None;
    let mut cpu_weight: Option<u64> = None;
    let mut secrets: Vec<String> = Vec::new();
    let mut secret_envs: Vec<String> = Vec::new();
    let mut ssh_port: Option<u16> = None;
    let mut ssh_key: Option<String> = None;
    let mut hostname: Option<String> = None;
    let mut tun = false;
    let mut init = false;
    let mut pids_limit: Option<u64> = None;
    let mut tmpfs: Vec<String> = Vec::new();
    let mut shm_size: Option<u64> = None;
    let mut ulimits: Vec<(i32, u64, u64)> = Vec::new();
    let mut sysctls: Vec<(String, String)> = Vec::new();
    let mut labels: Vec<String> = Vec::new();
    let mut restart_max: u32 = 0;
    let mut def_hash: Option<String> = None;
    // `None` = the flag was NOT given, which is a different fact from "given as SIGTERM".
    //
    // An image may declare its own `STOPSIGNAL` (nginx `SIGQUIT`, apache `SIGWINCH`), and Docker
    // uses it when the caller names none. Stored as `SIGTERM` outright, the two cases were the same
    // value and the image's signal could only be honoured by ignoring an explicit `--stop-signal
    // SIGTERM`, which is somebody's deliberate choice.
    let mut secret_mode: libc::mode_t = crate::secret::DEFAULT_SECRET_MODE;
    let mut stop_signal: Option<i32> = None;
    let mut stop_grace: u64 = 10;
    let mut run_as: Option<String> = None;
    let mut cap_add: Vec<String> = Vec::new();
    let mut cap_drop: Vec<String> = Vec::new();
    let mut memory: Option<u64> = None;
    let mut memory_swap_max: Option<u64> = None;
    let mut cpus: Option<f64> = None;
    let mut cpuset: Option<String> = None;
    let mut volumes: Vec<String> = Vec::new();
    let mut env: Vec<String> = Vec::new();
    let mut egress_allow: Vec<String> = Vec::new();
    let mut landlock_rw: Vec<String> = Vec::new();
    let mut net_ips: Vec<std::net::Ipv4Addr> = Vec::new();
    let mut apparmor: Option<String> = None;
    let mut workdir: Option<String> = None;
    let mut entrypoint: Option<Vec<String>> = None;
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
                // set share=true and silently dropped the `none` token - a Docker user's muscle-memory
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
                    // name - the box name goes FIRST (`kern box NAME --net`).
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
                // `--pod-bridge <ip>/<prefix>`: join the pod through its bridge with this address,
                // instead of sharing the pod's network namespace. Parsed here so a value that is
                // not an address and a prefix is refused before a box exists.
                "--pod-bridge" => {
                    i += 1;
                    let v = rest.get(i).copied().ok_or(Error::Usage(
                        "--pod-bridge <ip>/<prefix> (e.g. 10.89.0.2/24)",
                    ))?;
                    let bad = || {
                        Error::Cli(format!(
                            "--pod-bridge '{v}' is not an address and a prefix. Write it like \
                             10.89.0.2/24, inside the network the pod was created with"
                        ))
                    };
                    let (ip, prefix) = v.split_once('/').ok_or_else(bad)?;
                    let ip: std::net::Ipv4Addr = ip.trim().parse().map_err(|_| bad())?;
                    let prefix: u8 = prefix.trim().parse().map_err(|_| bad())?;
                    if !(8..=30).contains(&prefix) {
                        return Err(bad());
                    }
                    pod_bridge = Some(kern_isolation::BridgeAttach { ip, prefix });
                }
                // `--network host|none`: the Docker-style spelling. `host` shares the host network
                // (= `--net`); `none` is the default isolated loopback-only namespace, made explicit.
                // A NAME IS A POD, which is the thing a compose stack IS. `docker run --rm --network
                // <stack-net> <img> <cmd>` is how a one-off talks to a running stack - generating a
                // token, seeding a database, running a migration - and kern answered
                // `--network <host|none>`, a usage line naming neither of the two joinable things it
                // has. A stack brought up by `kern compose` is a pod whose members resolve each
                // other by name, so joining it by name is the same operation under a second
                // spelling, and `--pod` keeps working unchanged.
                //
                // AN EXTERNAL `kern network` IS NOT THE SAME OBJECT and is not accepted here. It is
                // built from per-pair relays planned across a whole project, which a standalone box
                // has no part in; claiming to join one and wiring nothing would be the "accepted it
                // and did something else" failure. The refusal says which of the two it found and
                // what to run instead, rather than repeating the two words `host` and `none`.
                "--network" => {
                    i += 1;
                    match rest.get(i).copied() {
                        Some("host") => share_net = true,
                        Some("none") => share_net = false,
                        // THE NAME IS RECORDED, NOT RESOLVED. Whether it names a running pod, a
                        // `kern network` or nothing is a question about runtime state, and a parser
                        // that answers it is a parser whose result depends on which boxes happen to
                        // be running - untestable without a live registry, and different on two
                        // machines given one command line. `join_pod_and_bind_its_files` already
                        // asks that question for `--pod` and now answers it for both flags.
                        Some(name) if !name.starts_with('-') => pod = Some(name.to_string()),
                        _ => {
                            return Err(Error::Usage(
                                "--network <host|none|pod-name> (host = share host net; none = isolated)",
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
                // `--pids-limit N`: cap the box's task count (`pids.max`) - fork-bomb containment.
                "--pids-limit" => {
                    i += 1;
                    // Floor of 2, not 1: the box needs one slot for its own PID 1 and at least one more
                    // for the workload it execs. Measured, `--pids-limit 1` fails the box's setup fork
                    // with EAGAIN and surfaces only a generic "fork failed" that never names the cap.
                    // Reject it here, by name, before the fork. Fork-bomb containment starts at 2.
                    match rest
                        .get(i)
                        .and_then(|v| v.parse::<u64>().ok())
                        .filter(|n| *n >= 2)
                    {
                        Some(n) => pids_limit = Some(n),
                        None => {
                            return Err(Error::Usage(
                                "--pids-limit <N> (>= 2: the box needs a process slot for its own PID 1 \
                                 plus the workload; 1 cannot start the box, e.g. use 256)",
                            ))
                        }
                    }
                }
                // `--ulimit NAME=SOFT[:HARD]`: a POSIX resource limit, Docker's spelling. Resolved
                // here (name → RLIMIT_*, bounds → u64) so the sandbox layer never parses strings.
                "--ulimit" => {
                    i += 1;
                    match rest.get(i) {
                        Some(v) => ulimits.push(parse_ulimit(v)?),
                        None => {
                            return Err(Error::Usage(
                                "--ulimit NAME=SOFT[:HARD] (e.g. --ulimit nofile=1024:2048)",
                            ))
                        }
                    }
                }
                // `--stop-signal NAME|NUM` / `--stop-timeout SECS`: Docker's shutdown contract. A
                // hard kill makes redis lose unsaved data and postgres do crash recovery on the next
                // start, so the default is SIGTERM with a 10 s grace, exactly like Docker.
                // `--restart-max N`: how many times the on-failure supervisor retries before giving
                // up. Compose's `on-failure:N` maps here; 0 keeps kern's built-in cap.
                // `--def-hash <hex>`: written by `kern compose`, never typed by hand. Recorded in the
                // registry so a later `up` can tell a running service apart from the file that
                // describes it now.
                "--def-hash" => {
                    i += 1;
                    def_hash = match rest.get(i) {
                        Some(v) => Some((*v).to_string()),
                        None => return Err(Error::Usage("--def-hash <hex>")),
                    };
                }
                "--restart-max" => {
                    i += 1;
                    restart_max = match rest.get(i).and_then(|v| v.parse::<u32>().ok()) {
                        Some(v) => v,
                        None => return Err(Error::Usage("--restart-max <n>")),
                    };
                }
                "--secret-mode" => {
                    i += 1;
                    // OCTAL AND BOUNDED. A mode is written in octal everywhere it appears (the
                    // specification says "in octal notation"), and a value above 0o777 would carry
                    // setuid/setgid/sticky bits into a file kern creates for a workload.
                    secret_mode =
                        match rest.get(i).and_then(|v| {
                            libc::mode_t::from_str_radix(v, 8)
                                .ok()
                                .filter(|m| *m <= 0o777)
                        }) {
                            Some(m) => m,
                            None => return Err(Error::Usage(
                                "--secret-mode <OCTAL>: three or four octal digits, at most 777 \
                                 (e.g. 400 owner-only, 444 world-readable)",
                            )),
                        };
                }
                "--stop-signal" => {
                    i += 1;
                    stop_signal = match rest.get(i) {
                        Some(v) => Some(parse_signal(v)?),
                        None => {
                            return Err(Error::Usage("--stop-signal <NAME|NUM> (e.g. SIGTERM, 15)"))
                        }
                    };
                }
                "--stop-timeout" => {
                    i += 1;
                    stop_grace = match rest.get(i).and_then(|v| v.parse::<u64>().ok()) {
                        Some(v) => v,
                        None => return Err(Error::Usage("--stop-timeout <seconds>")),
                    };
                }
                // `-l/--label k=v`: descriptive metadata. Requires the `=` (Docker's own rule) so a
                // typo can't silently register a key with an empty value that no filter will match.
                "-l" | "--label" => {
                    i += 1;
                    match rest.get(i) {
                        Some(v) if v.contains('=') && !v.starts_with('=') => {
                            labels.push((*v).to_string())
                        }
                        _ => return Err(Error::Usage("--label k=v (e.g. --label app=web)")),
                    }
                }
                // `--sysctl KEY=VALUE`: a namespaced kernel knob, Docker's spelling.
                "--sysctl" => {
                    i += 1;
                    match rest.get(i) {
                        Some(v) => {
                            match v.split_once('=') {
                                Some((k, val)) if !k.trim().is_empty() => {
                                    sysctls.push((k.trim().to_string(), val.trim().to_string()))
                                }
                                _ => return Err(Error::Usage(
                                    "--sysctl KEY=VALUE (e.g. --sysctl net.core.somaxconn=1024)",
                                )),
                            }
                        }
                        None => {
                            return Err(Error::Usage(
                                "--sysctl KEY=VALUE (e.g. --sysctl net.core.somaxconn=1024)",
                            ))
                        }
                    }
                }
                // `--tmpfs PATH[:size]`: mount a fresh tmpfs inside the box (repeatable).
                // `--shm-size SIZE`: cap `/dev/shm`. Without it the cap comes from `--memory`.
                "--shm-size" => {
                    i += 1;
                    match rest.get(i).and_then(|v| parse_size(v)) {
                        Some(b) => shm_size = Some(b),
                        None => return Err(Error::Usage("--shm-size SIZE (e.g. 64m, 1g)")),
                    }
                }
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
                // Opt OUT of the range mapping, which an `--image` box gets by default (see
                // `box_run`). Single-uid is tighter isolation; it is a deliberate choice, not one to
                // arrive at by accident when an official image fails to start.
                "--no-uid-range" => no_uid_range = true,
                "--bind-rootfs" => bind_rootfs = true,
                "--privileged" => privileged = true,
                "--require-limits" => require_limits = true,
                "--allow-uncapped" => allow_uncapped = true,
                "--security-profile" => {
                    i += 1;
                    security_profile = match rest
                        .get(i)
                        .copied()
                        .and_then(commands::SecurityProfile::parse)
                    {
                        Some(p) => Some(p),
                        None => {
                            return Err(Error::Usage("--security-profile: expected `untrusted`"))
                        }
                    };
                }
                // Internal build-layer flags (see the Command::BoxRun docs) - take a value.
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
                // uses kern's in-process supervisor. A bare `--restart` = on-failure (back-compat) -
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
                // `--health-cmd-argv <arg>` (repeatable): the same check WITHOUT a shell - Docker's
                // `CMD` exec form, one argv element per occurrence. Repeatable rather than one
                // string, because a string would have to be split and splitting on spaces is the
                // very loss this flag exists to avoid.
                "--health-cmd-argv" => {
                    i += 1;
                    match rest.get(i) {
                        Some(c) => health_cmd_argv.push((*c).to_string()),
                        None => return Err(Error::Usage("--health-cmd-argv <argv element>")),
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
                // `--health-start-interval <sec>`: cadence INSIDE the start period. Separate from
                // `--health-interval` because Docker 25+ separates them, and reading only the steady
                // one made the first probe land a whole interval in: a database ready in ten seconds
                // reported `starting` for five minutes.
                "--health-start-interval" => {
                    i += 1;
                    match rest.get(i).and_then(|v| v.parse::<u64>().ok()) {
                        Some(s) => health_start_interval = s,
                        None => {
                            return Err(Error::Usage("--health-start-interval <seconds> (e.g. 5)"))
                        }
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
                // `-it`/`-ti`/`-t`: allocate an interactive PTY for the box (shells, REPLs).
                //
                // `-i` IS A DIFFERENT FLAG AND DOES NOT ALLOCATE ONE, for the reason measured on
                // `exec` (see [`parse_exec`]): a PTY echoes its input, rewrites `\n` as `\r\n`, and
                // never receives EOF from a redirected file, so `docker run -i img < file` - the
                // shape a build or seeding script uses - would hang and corrupt its own output.
                // kern's box inherits stdin either way, so `-i` names what already happens.
                "-it" | "-ti" | "-t" | "--tty" => tty = true,
                "-i" | "--interactive" => {}
                "--rootfs" => {
                    i += 1;
                    rootfs = rest.get(i).map(|v| (*v).to_string());
                }
                "--image" => {
                    i += 1;
                    image = rest.get(i).map(|v| (*v).to_string());
                }
                // `--pull missing|never|always` (Docker parity). `missing` (default) = pull only if
                // absent; `never` = fail if not already cached, never touch the network; `always` =
                // force a fresh network pull with an atomic cache swap.
                "--pull" => {
                    i += 1;
                    pull = match rest.get(i).copied() {
                        Some("never") => commands::PullPolicy::Never,
                        Some("always") => commands::PullPolicy::Always,
                        Some("missing") => commands::PullPolicy::Missing,
                        _ => {
                            return Err(Error::Usage(
                                "--pull: expected `missing`, `never`, or `always`",
                            ))
                        }
                    };
                }
                "-v" | "--volume" => {
                    i += 1;
                    if let Some(v) = rest.get(i) {
                        volumes.push((*v).to_string());
                    }
                }
                // `--mount type=…,src=…,dst=…`: the long form of `-v`/`--tmpfs`, translated into
                // them by `parse_mount_spec` so one resolver serves both spellings.
                "--mount" => {
                    i += 1;
                    let Some(v) = rest.get(i) else {
                        return Err(Error::Usage("--mount type=…,src=…,dst=… (see --help)"));
                    };
                    match parse_mount_spec(v)? {
                        MountSpec::Volume(s) => volumes.push(s),
                        MountSpec::Tmpfs(s) => tmpfs.push(s),
                    }
                }
                // `--name <box>`: Docker's spelling for the name kern takes positionally. The SAME
                // field, so giving both is refused rather than resolved by a precedence rule nobody
                // would remember: `kern box web --name api` has said two things about one box, and
                // silently picking either would name it something the command line also denies.
                // `--rm`: drop the exit breadcrumb too. See `Command::BoxRun::rm` for why this is
                // the only thing left for the flag to do.
                "--rm" => rm = true,
                "--name" => {
                    i += 1;
                    match rest.get(i) {
                        Some(v) if !v.is_empty() && !v.starts_with('-') => {
                            if name.is_some() {
                                return Err(Error::Usage(
                                    "--name and the positional name are the same field; pass one",
                                ));
                            }
                            name = Some(v);
                        }
                        _ => return Err(Error::Usage("--name <box> (e.g. --name web)")),
                    }
                }
                "-e" | "--env" => {
                    i += 1;
                    if let Some(v) = rest.get(i) {
                        env.push((*v).to_string());
                    }
                }
                // `--entrypoint <arg>`, repeatable: one argv element per occurrence. See the field
                // docs on `Command::BoxRun::entrypoint` for why it is repeatable and why an empty
                // value is a distinct state rather than a missing one.
                "--entrypoint" => {
                    i += 1;
                    match rest.get(i) {
                        // An EMPTY value CLEARS the entrypoint (`--entrypoint ""`, compose's
                        // `entrypoint: []`), and only as the FIRST occurrence: a later empty
                        // argument is a legitimate empty argv element for the program named before
                        // it, and reading that as "clear everything" would silently discard the
                        // override the caller had just built.
                        Some(v) if v.is_empty() && entrypoint.is_none() => {
                            entrypoint = Some(Vec::new());
                        }
                        // A LEADING DASH IS REFUSED ON THE FIRST OCCURRENCE ONLY.
                        //
                        // `--entrypoint --privileged` is a typo, not a program: the value is taken
                        // as the executable and the box then fails with `cannot start
                        // '--privileged'`, which names the symptom and not the mistake. The `docker`
                        // shim already refuses this shape (`reject_leading_dash`), and two paths
                        // answering one input differently is the divergence class this codebase
                        // treats as a defect.
                        //
                        // ONLY the first, because a later occurrence is an ARGUMENT to the program
                        // named before it: `--entrypoint /bin/sh --entrypoint -c` is the exec-form
                        // list this flag is repeatable for, and refusing `-c` there would break the
                        // form the repetition exists to express.
                        Some(v) if v.starts_with('-') && entrypoint.is_none() => {
                            return Err(Error::Usage(
                                "--entrypoint: the first value is the program to run and cannot start with '-'",
                            ))
                        }
                        Some(v) => entrypoint
                            .get_or_insert_with(Vec::new)
                            .push((*v).to_string()),
                        // The flag with nothing after it. An override of nothing is not an override,
                        // and ignoring it would run the image's own entrypoint while the caller
                        // believed they had replaced it.
                        None => {
                            return Err(Error::Usage(
                                "--entrypoint needs a value (repeat it for an exec-form list; \
                                 `--entrypoint \"\"` clears the image's entrypoint)",
                            ))
                        }
                    }
                }
                "--egress-allow" => {
                    i += 1;
                    if let Some(v) = rest.get(i) {
                        // comma-separated and repeatable; empties filtered.
                        egress_allow.extend(
                            v.split(',')
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(String::from),
                        );
                    }
                }
                // `--ip <addr>`: an extra address this box's loopback answers on. REFUSED AT THE
                // BOUNDARY rather than carried as a string, so a value that is not an IPv4 literal
                // cannot reach a box and fail there with nothing to point at. Repeatable: a service
                // may sit on more than one network.
                "--ip" => {
                    i += 1;
                    match rest.get(i).map(|v| v.trim()) {
                        Some(v) if !v.is_empty() => match v.parse::<std::net::Ipv4Addr>() {
                            Ok(ip) => {
                                if !net_ips.contains(&ip) {
                                    net_ips.push(ip);
                                }
                            }
                            Err(_) => {
                                return Err(Error::Cli(format!(
                                    "--ip '{v}' is not an IPv4 address. A compose file's \
                                     `ipv4_address:` under a service's `networks:` reaches this \
                                     flag, so this may be a value your compose file wrote"
                                )))
                            }
                        },
                        _ => return Err(Error::Usage("--ip <address> (e.g. 172.20.0.5)")),
                    }
                }
                "--landlock-rw" => {
                    i += 1;
                    if let Some(v) = rest.get(i) {
                        // one absolute path per flag; repeatable.
                        let p = v.trim();
                        if !p.is_empty() {
                            landlock_rw.push(p.to_string());
                        }
                    }
                }
                "--apparmor" => {
                    i += 1;
                    match rest.get(i).map(|v| v.trim()) {
                        Some(v) if valid_apparmor_name(v) => apparmor = Some(v.to_string()),
                        _ => return Err(Error::Usage(
                            "--apparmor <profile> (letters, digits, '.', '_', '-'; no leading '-')",
                        )),
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
                    // `NAME:IP` - the name has no colon, so split on the first `:` (IP is v4 or the
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
                // AN IP LITERAL, REFUSED HERE RATHER THAN WRITTEN AND IGNORED. `resolv.conf` takes
                // an address, never a name: a resolver cannot resolve the address of its own
                // resolver. glibc silently skips a `nameserver` line it cannot parse, so a typo
                // would leave a box with no DNS and no message anywhere - the exact silent
                // degradation this project refuses. `IpAddr` accepts v4 and v6 and nothing else.
                "--dns" => {
                    i += 1;
                    match rest
                        .get(i)
                        .filter(|v| v.parse::<std::net::IpAddr>().is_ok())
                    {
                        Some(v) => dns.push((*v).to_string()),
                        None => {
                            return Err(Error::Usage(
                                "--dns <ip> (an IPv4 or IPv6 address, e.g. 1.1.1.1; resolv.conf takes no hostnames)",
                            ))
                        }
                    }
                }
                // A DOMAIN AND AN OPTION ARE FREE-FORM, so the only gate is the one that keeps the
                // file line-oriented: no whitespace (a newline would forge a directive, a space
                // would split the field) and no control characters. The same predicate runs again
                // in the box, deliberately: this one gives the caller a message, that one holds
                // even if a future caller reaches the spec by another route.
                "--dns-search" => {
                    i += 1;
                    match rest.get(i).filter(|v| {
                        !v.is_empty() && !v.chars().any(|c| c.is_whitespace() || c.is_control())
                    }) {
                        Some(v) => dns_search.push((*v).to_string()),
                        None => {
                            return Err(Error::Usage(
                                "--dns-search <domain> (one domain, no spaces; repeat the flag for more)",
                            ))
                        }
                    }
                }
                "--dns-option" => {
                    i += 1;
                    match rest.get(i).filter(|v| {
                        !v.is_empty() && !v.chars().any(|c| c.is_whitespace() || c.is_control())
                    }) {
                        Some(v) => dns_options.push((*v).to_string()),
                        None => return Err(Error::Usage(
                            "--dns-option <opt> (a resolv.conf option, e.g. ndots:2 or timeout:2)",
                        )),
                    }
                }
                // ZERO IS REFUSED, not clamped. A zero-byte cap makes every write rotate and the
                // log store nothing, which is a silently broken box rather than a small one; a
                // caller who wants no log has `>/dev/null` in their command.
                "--log-max-size" => {
                    i += 1;
                    match rest.get(i).and_then(|v| parse_size(v)).filter(|n| *n > 0) {
                        Some(n) => log_max_size = Some(n),
                        None => {
                            return Err(Error::Usage(
                                "--log-max-size <size> (e.g. 10m, 1g; binary units, must be > 0)",
                            ))
                        }
                    }
                }
                // COUNTS THE ACTIVE FILE, like Docker's `max-file`, so `1` means no rotated
                // generation at all (the active file is truncated when it fills) and `3` means the
                // active file plus `.1` and `.2`. The bound a caller gets is `max-size * max-file`.
                "--log-max-file" => {
                    i += 1;
                    match rest
                        .get(i)
                        .and_then(|v| v.parse::<u32>().ok())
                        .filter(|n| *n > 0)
                    {
                        Some(n) => log_max_file = Some(n),
                        None => {
                            return Err(Error::Usage(
                                "--log-max-file <n> (how many log files to keep, active one included; 1 or more)",
                            ))
                        }
                    }
                }
                // A SIZE, AND NOT ZERO. `memory.low = 0` is the kernel's default (no protection), so
                // accepting a `0` would let a file ask for something and get nothing, which reads as
                // applied and is not.
                "--memory-reservation" => {
                    i += 1;
                    match rest.get(i).and_then(|v| parse_size(v)).filter(|n| *n > 0) {
                        Some(n) => memory_reservation = Some(n),
                        None => return Err(Error::Usage(
                            "--memory-reservation <size> (e.g. 256m, 1g; a soft floor, not a cap)",
                        )),
                    }
                }
                // The cgroup v2 range, refused outside it rather than clamped: a caller who wrote
                // Docker's `cpu_shares` scale (1024) by hand into this flag means something different
                // from 1024/10000, and silently clamping would hide that. The compose parser converts
                // the Docker scale explicitly.
                "--cpu-weight" => {
                    i += 1;
                    match rest
                        .get(i)
                        .and_then(|v| v.parse::<u64>().ok())
                        .filter(|n| (1..=10_000).contains(n))
                    {
                        Some(n) => cpu_weight = Some(n),
                        None => {
                            return Err(Error::Usage(
                                "--cpu-weight <n> (1-10000, cgroup v2 cpu.weight; relative share under contention)",
                            ))
                        }
                    }
                }
                // `--secret-env <name>`: the content comes from `KERN_SECRET_<name>` in this
                // process's environment, so it never appears in `argv`. This is what a compose
                // file's `secrets: {x: {environment: VAR}}` becomes.
                "--secret-env" => {
                    i += 1;
                    match rest.get(i) {
                        Some(v) => secret_envs.push((*v).to_string()),
                        None => return Err(Error::Usage("--secret-env <name>")),
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
                    match rest.get(i) {
                        None => return Err(Error::Usage(USAGE_MEMORY)),
                        Some(v) => match parse_size(v) {
                            Some(b) if kern_common::memory_cap_below_floor(b) => {
                                return Err(Error::Cli(cap_below_floor("--memory", v, b)))
                            }
                            Some(b) => memory = Some(b),
                            None => return Err(Error::Cli(bad_size("--memory", v))),
                        },
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
                // total - aliasing would silently mean something different. Point to the honest flag.
                "--memory-swap" => return Err(Error::Usage(REJECT_MEMORY_SWAP)),
                // Reject an unknown flag rather than silently ignoring it: a typo'd `--read-only`
                // must NOT quietly run a writable box. (Flags after `--` are part of the command.)
                s if s.starts_with('-') => {
                    return Err(Error::Usage("box: unknown flag (see --help)"))
                }
                // A `vcpu:`/`vgpio:`/`vdisk:`/`vgpu:` token is a resource profile, not the box name.
                s if crate::config::classify(s).is_some() => profiles.push(s.to_string()),
                s if name.is_none() => name = Some(s),
                // A SECOND bare token (name already set, not a flag, not a profile) is junk - almost
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
            // Keyed on protocol too: TCP and UDP are SEPARATE host ports, so `-p 53:53/tcp -p 53:53/udp`
            // (the common DNS shape) is NOT a duplicate - only two mappings of the SAME proto+addr+port
            // collide on one bind.
            if ports[a].bind_ip == ports[b].bind_ip
                && ports[a].host == ports[b].host
                && ports[a].udp == ports[b].udp
            {
                return Err(Error::Usage(
                    "duplicate -p host port (one host port maps to a single box port)",
                ));
            }
        }
    }
    // NOTE: the `--require-limits` / `--allow-uncapped` contradiction is rejected in `build_spec`, on
    // the RESOLVED values (flag || env), not here on the raw flags - so the mix with `KERN_*` env is
    // caught too. A parse-time flag-only check would silently miss `--require-limits` + `KERN_ALLOW_UNCAPPED`.
    //
    // `--cap-add ALL` under `--security-profile untrusted`, by contrast, IS a parse-time flag-only
    // check (neither has an env form): it NEGATES the profile's cap-drop, leaving a box labelled
    // `untrusted` that holds every capability - a contradiction, not the override of a single cap that
    // `--cap-add NET_BIND_SERVICE` is. Reject it by name, as with require/allow.
    if security_profile.is_some() && cap_add.iter().any(|a| a.eq_ignore_ascii_case("ALL")) {
        return Err(Error::Usage(
            "--cap-add ALL cancels the cap-drop of --security-profile untrusted; these are \
             contradictory. Drop the profile, or add the specific capabilities you need.",
        ));
    }
    // `--privileged` under `--security-profile untrusted`: same shape as `--cap-add ALL`. `--privileged`
    // relaxes the seccomp filter (it re-allows the namespace/mount syscalls for nesting), which negates
    // the profile's `allowlist` constituent. A box that says `untrusted` and then relaxes seccomp is a
    // contradiction, not the override of one setting. Reject it by name.
    if security_profile.is_some() && privileged {
        return Err(Error::Usage(
            "--privileged relaxes the seccomp filter that --security-profile untrusted tightens; \
             these are contradictory. Drop the profile, or drop --privileged.",
        ));
    }
    // ONE HEALTH CHECK, IN ONE FORM. The two flags are the two Docker forms of the same check
    // (`CMD-SHELL` and `CMD`), so a command line carrying both has said two different things about
    // one probe and there is no reading of it that is not a guess. Refusing costs a retyped line;
    // picking one silently would run a check the caller did not write.
    if health_cmd.is_some() && !health_cmd_argv.is_empty() {
        return Err(Error::Usage(
            "--health-cmd and --health-cmd-argv are the two forms of ONE check (shell and exec); \
             pass one of them, not both",
        ));
    }
    // Always route to the real command; missing name → BoxName rejects it, missing rootfs/image
    // → box_run reports it. `--plan` wins (non-destructive preview).
    let cmd = if plan {
        Command::BoxPlan {
            name: name.unwrap_or_default().to_string(),
            profiles: profiles.clone(),
            config: config.clone(),
        }
    } else {
        Command::BoxRun {
            rm,
            // The name is optional (Docker-style): omit it and kern assigns `box-<pid>`, so a quick
            // `kern box --image alpine -- sh` needs no invented name.
            name: name
                .map(str::to_string)
                .unwrap_or_else(|| format!("box-{}", std::process::id())),
            rootfs,
            image,
            pull,
            command,
            entrypoint,
            detached,
            read_only,
            volumes,
            env,
            egress_allow,
            landlock_rw,
            net_ips,
            pod_bridge,
            apparmor,
            workdir,
            share_net,
            pod,
            uid_range,
            no_uid_range,
            bind_rootfs,
            privileged,
            require_limits,
            allow_uncapped,
            security_profile,
            overlay_lower,
            overlay_upper,
            memory,
            memory_swap_max,
            cpus,
            cpuset,
            tty,
            ports,
            add_hosts,
            dns,
            dns_search,
            dns_options,
            log_max_size,
            log_max_file,
            memory_reservation,
            cpu_weight,
            secrets,
            secret_envs,
            secret_mode,
            ssh_port,
            ssh_key,
            hostname,
            tun,
            init,
            pids_limit,
            tmpfs,
            shm_size,
            ulimits,
            sysctls,
            labels,
            restart_max,
            def_hash,
            stop_signal,
            stop_grace,
            run_as,
            cap_add,
            cap_drop,
            restart,
            health_cmd,
            health_cmd_argv,
            health_interval,
            health_retries,
            health_start_period,
            health_start_interval,
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
/// Flags that belong to `box` and cannot mean anything on `run`, because `run` has no image and no
/// namespaces. Every entry is checked against the `box` parser by
/// `every_box_only_flag_is_really_a_box_flag`, so the redirect can never name a flag `box` does not
/// take. `--rm` is deliberately absent: `run` is a foreground one-shot that leaves nothing behind,
/// so pointing at `box` for it would trade one wrong answer for another.
const BOX_ONLY_FLAGS: &[&str] = &[
    "--mount",
    "--name",
    "--image",
    "--rootfs",
    "--bind-rootfs",
    "-d",
    "--detach",
    "-p",
    "--publish",
    "-v",
    "--volume",
    "-i",
    "-t",
    "-it",
    "-ti",
    "--interactive",
    "--tty",
    "--network",
    "--net",
    "--read-only",
    "--ro",
    "-e",
    "--env",
    "--env-file",
    "-w",
    "--workdir",
    "-u",
    "--user",
    "--cap-drop",
    "--cap-add",
    "--privileged",
    "--require-limits",
    "--allow-uncapped",
    "--security-profile",
    "--secret",
    "--secret-env",
    "--tmpfs",
    "--shm-size",
    "--pids-limit",
    "--restart",
    "--health-cmd",
    "--health-cmd-argv",
    "--ssh",
    "--pod",
    "--hostname",
    "--egress-allow",
    // `--landlock-rw` is deliberately NOT here: it is the one confinement that needs no mount
    // namespace, so it is the one `box` flag that `run` can honour for real. See `parse_run`.
];

fn parse_run(rest: &[&str]) -> Result<Command, Error> {
    let mut memory: Option<u64> = None;
    let mut memory_swap_max: Option<u64> = None;
    let mut cpus: Option<f64> = None;
    let mut cpuset: Option<String> = None;
    let mut config: Option<String> = None;
    let mut landlock_rw: Vec<String> = Vec::new();
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
                match rest.get(i) {
                    None => return Err(Error::Usage(USAGE_MEMORY)),
                    Some(v) => match parse_size(v) {
                        Some(b) if kern_common::memory_cap_below_floor(b) => {
                            return Err(Error::Cli(cap_below_floor("--memory", v, b)))
                        }
                        Some(b) => memory = Some(b),
                        None => return Err(Error::Cli(bad_size("--memory", v))),
                    },
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
            // The one `box` confinement `run` can honour: Landlock restricts the calling process, so it
            // needs no mount namespace, no image and no pivot_root. Repeatable, like on `box`. An empty
            // value is rejected here rather than becoming a rule on "" that `add_path` would silently
            // skip, leaving a workload confined to nothing while the operator asked for a grant.
            "--landlock-rw" => {
                i += 1;
                match rest.get(i).map(|v| v.trim()) {
                    Some(p) if !p.is_empty() => landlock_rw.push(p.to_string()),
                    _ => return Err(Error::Usage(USAGE_LANDLOCK_RW)),
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
            // A `box` flag on `run` is the Docker reflex, and it is the one place where the two-verb
            // split can hurt rather than merely confuse: `docker run` starts a container, `kern run`
            // caps a process on the host with NO image, NO namespaces and NO sandbox. Someone who
            // types `kern run --read-only --network none -- ./untrusted` believes they are isolated
            // and is not. The generic answer below made it worse: it read "put `--` before the
            // command", so the next attempt is `kern run -- --image alpine`, which passes the flag
            // to the workload. Name the flag, say what `run` is, and name the verb that does it.
            s if BOX_ONLY_FLAGS.contains(&s) => {
                return Err(Error::Cli(format!(
                    "`kern run` has no {s}. It caps a process on the host: no image, \
                     no namespaces, no sandbox. That flag belongs to the sandboxed verb: \
                     kern box <name> --image <ref> [-- CMD...]"
                )))
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
            "run [--memory M] [--memory-swap-max S] [--cpus N] [--cpuset-cpus L] [--landlock-rw P] [--config F] [vcpu:PROFILE] [--] <cmd...>",
        ));
    }
    Ok(Command::Run {
        command,
        memory,
        memory_swap_max,
        cpus,
        cpuset,
        config,
        landlock_rw,
    })
}

/// Like [`parse_size`] but accepts an explicit `0`. Used for `--memory-swap-max`, where `0` is a
/// meaningful, valid value (zero swap allowance = swap off - the default) rather than a nonsense cap.
fn parse_size_z(s: &str) -> Option<u64> {
    match s.trim() {
        "0" => Some(0),
        // `max` IS A SIZE HERE, and the only way to say "not capped". cgroup v2 spells an absent
        // limit exactly that way, and a compose `memswap_limit: -1` has to reach it: the largest
        // finite byte count is still a cap, which is a different statement. `-1` is accepted as the
        // spelling the compose file uses, so the two layers do not need a translation table.
        "max" | "-1" => Some(u64::MAX),
        other => parse_size(other),
    }
}

/// Parse a memory size like `512m`, `1g`, `512mb`, `2t`, or a bare `268435456` (= bytes) into bytes.
/// Units are binary (k = 1024). Returns `None` on a malformed value - the caller turns that into a
/// usage error. Delegates to the shared [`kern_common::parse_binary_size`] so `--memory`, `--size`
/// and profile size fields can never disagree on what `512m` means.
fn parse_size(s: &str) -> Option<u64> {
    kern_common::parse_binary_size(s)
}

/// A valid `--cpuset-cpus` list (`0-3`, `0,2,4`, `1-2,5`): the SAME rule the profile `cpus` field
/// uses, so the flag and the profiles can't disagree. See [`crate::config::is_cpu_list`]. Validating
/// at the parse boundary means a typo can't silently produce an *unpinned* box, and only digits/`,`/`-`
/// survive the numeric parse - no arbitrary string reaches the kernel's `cpuset.cpus`.
fn is_cpu_list(s: &str) -> bool {
    crate::config::is_cpu_list(s)
}

/// Parse `exec <name> [--env K=V] [--workdir <dir>] [--] [cmd...]`. Missing name → usage error.
/// The `--` is OPTIONAL: trailing words are the command, as `docker exec <c> ls` reads.
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
                // `-t` ALLOCATES A PTY. `-i` DOES NOT, and treating them as one flag was a defect
                // with a very large blast radius, because `docker exec -i <c> psql … < file.sql` is
                // how every seeding and migration script in existence talks to a database.
                //
                // MEASURED before the fix, against a running box: `kern exec -i box cat < file`
                // never returned (killed at 120 s), and what it had written was `line1\r\nline2\r\n`
                // followed by the ECHO of its own input - a PTY's line discipline adding carriage
                // returns and echoing, and never delivering EOF because a redirected file is not a
                // terminal that can send one. The same command without `-i` exited 0 and wrote the
                // file back byte for byte.
                //
                // Docker's two flags are two different things: `-t` allocates the pseudo-terminal,
                // `-i` keeps stdin attached. kern's exec inherits stdin unconditionally, so `-i`
                // names what already happens and is taken without side effects; only `-t` may reach
                // for a PTY. `-it`/`-ti` ask for both and get both.
                "-it" | "-ti" | "-t" | "--tty" => tty = true,
                "-i" | "--interactive" => {}
                s if s.starts_with('-') => {
                    return Err(Error::Usage("exec: unknown flag (see --help)"))
                }
                s if name.is_none() => name = Some(s),
                // The command WITHOUT the `--`, which is how `docker exec <c> ls` reads and how
                // people type it. This arm used to be `_ => {}`: the words were parsed, dropped on
                // the floor, and the empty command then defaulted to an interactive shell - so
                // `kern exec box echo hi` printed NOTHING, exited 0, and looked like the command had
                // run and produced no output. MEASURED that way before the fix. Taking arguments and
                // silently doing something else is the one thing this codebase refuses to do; the
                // separator stays supported and is still what the help shows for an ambiguous
                // command, but omitting it can no longer lose what you typed.
                //
                // `after_dd` is set with the first word so the REST of the command is taken
                // verbatim - `kern exec box ls -la` passes `-la` to `ls` rather than failing on an
                // unknown kern flag, which is again what the same line does under docker.
                s => {
                    command.push(s.to_string());
                    after_dd = true;
                }
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
        None => Err(Error::Usage("exec <name> [--] [cmd...]")),
    }
}

/// Parse `pull <image> [--dest <dir>] [--platform os/arch]`. `None` if no image was given.
/// Value following a `--flag` token in `rest` (e.g. `--username alice`), or `None`.
/// The value of a flag written either way: `--flag value` or `--flag=value`.
///
/// `inline` is the right-hand side when the caller split one off the token; otherwise the value is
/// the next argument. ONE function, so a flag cannot accept one spelling and not the other - which is
/// what `--pull=never` did, and it stopped Sentry's official installer.
fn inline_or_next<'a, I: Iterator<Item = &'a &'a str>>(
    inline: Option<&str>,
    it: &mut std::iter::Peekable<I>,
) -> Option<String> {
    match inline {
        Some(v) => Some(v.to_string()),
        None => it.next().map(|v| (*v).to_string()),
    }
}

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

/// Refuse an image reference the OCI grammar cannot represent, AT THE MOMENT THE USER SUPPLIES IT.
///
/// `kern build -t Foo-BAR:latest` used to succeed and put that name in the local cache, which no
/// registry will accept, so the refusal arrived at `kern push` long after the build was paid for.
/// `kern pull Foo-BAR:latest` was worse: it went to the network and came back `registry: no layers
/// in manifest`, which names nothing about the actual problem. Docker refuses the same input before
/// doing any work, with `repository name must be lowercase`; measured against Docker 29.6.2 on the
/// same host as kern, where kern accepted `dd-A:latest` and docker would not build it at all.
///
/// The rule itself is `kern_oci::valid_reference`, which already rejected uppercase: it simply was
/// not consulted on this path. Nothing here is a new restriction, it is an existing one applied
/// where it can still be acted on.
fn check_reference(spec: &str, flag: &str) -> Result<(), Error> {
    if kern_oci::valid_reference(spec) {
        return Ok(());
    }
    // Name the fix when the fix is mechanical. A spec that becomes valid by lowercasing is the
    // common case (a directory named `Foo` used as a tag), and printing the exact string the user
    // should have typed is worth more than restating the grammar.
    let lower = spec.to_ascii_lowercase();
    let remedy = if lower != spec && kern_oci::valid_reference(&lower) {
        format!(" - OCI repository names are lowercase: use `{lower}`")
    } else {
        String::new()
    };
    Err(Error::Cli(format!(
        "{flag}: '{spec}' is not a valid image reference{remedy}"
    )))
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
    // A port is published on the BOX that serves it, never on the pod: the pod owns the network
    // namespace, the box owns the listener. `pod create -p 8080:80` used to exit 0 with the flag
    // dropped, so the pod came up and nothing was published, which reads exactly like a kern bug
    // until you find the port was never asked for. The usage line advertised `-p` as well, so the
    // CLI documented a flag it did not implement.
    if let Some(p) = rest.iter().skip(2).find(|a| {
        **a == "-p" || **a == "--publish" || a.starts_with("-p=") || a.starts_with("--publish=")
    }) {
        return Err(Error::Cli(format!(
            "pod: {p:?} belongs on the box, not the pod - publish with `kern box <name> --pod <pod> -p 8080:80`"
        )));
    }
    match rest.get(1).copied() {
        Some("create" | "new" | "up") => {
            reject_unknown_flags(
                "pod create",
                &rest[1..],
                &["--no-outbound", "--uid-range", "--bridge"],
            )?;
            let name = rest
                .iter()
                .skip(2)
                .find(|a| !a.starts_with('-'))
                .ok_or(Error::Usage(
                    "pod create <name> [--no-outbound] [--uid-range] [--bridge <cidr>]",
                ))?;
            Ok(Command::PodCreate {
                name: name.to_string(),
                bridge: flag_value(rest, "--bridge"),
                outbound: !rest.contains(&"--no-outbound"),
                // Map a subordinate uid range into the pod's shared user namespace, so member OCI
                // images that drop privilege / chown to a fixed uid (postgres, mysql, …) work inside
                // the pod. Without it the holder maps a single uid and such entrypoints fail closed.
                uid_range: rest.contains(&"--uid-range"),
            })
        }
        Some("ls" | "list" | "ps") => {
            reject_unknown_flags("pod ls", &rest[1..], &["--json"])?;
            Ok(Command::PodList {
                json: rest[1..].contains(&"--json"),
            })
        }
        Some("rm" | "remove" | "down") => {
            reject_unknown_flags("pod rm", &rest[1..], &[])?;
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
            "pod create <name> [--no-outbound] [--uid-range] [--bridge <cidr>] | pod ls | pod rm <name>",
        )),
    }
}

/// `kern network create|ls|rm`: the object behind an `external: true` compose network.
///
/// THE SHAPE IS `kern pod`'s, DELIBERATELY. The two are the same kind of thing to an operator - a
/// named object a stack joins - and giving them different verb spellings would be a second grammar
/// to learn for no reason. `net` is accepted as well because `docker network` has no short form and
/// people type one anyway.
fn parse_network(rest: &[&str]) -> Result<Command, Error> {
    match rest.get(1).copied() {
        Some("create" | "new") => {
            reject_unknown_flags("network create", &rest[1..], &[])?;
            let name = rest
                .iter()
                .skip(2)
                .find(|a| !a.starts_with('-'))
                .ok_or(Error::Usage("network create <name>"))?;
            Ok(Command::NetworkCreate {
                name: (*name).to_string(),
            })
        }
        Some("ls" | "list") => {
            // `--format json` IS THE SPELLING DOCKER USES for the same request `--json` makes here,
            // and a script ported across carries it. Mapped onto the one renderer rather than
            // growing a second output path; any OTHER template is refused by name, because kern has
            // no per-network fields to render and a silently ignored template would print the human
            // table to a caller that asked for something else.
            reject_unknown_flags("network ls", &rest[1..], &["--json", "--format"])?;
            let fmt = flag_value(&rest[1..], "--format");
            if let Some(f) = fmt.as_deref() {
                if !f.eq_ignore_ascii_case("json") {
                    return Err(Error::Cli(format!(
                        "network ls --format '{f}': only `json` is supported here (kern's networks carry a name and its members, and no template fields beyond them)"
                    )));
                }
            }
            Ok(Command::NetworkList {
                json: rest[1..].contains(&"--json") || fmt.is_some(),
            })
        }
        // `network inspect <name>`: the verb a script ported from Docker reaches for to learn a
        // network's subnet. Only the keys kern holds a true value for are rendered; see
        // `network::print_inspect` for what is deliberately absent and why.
        Some("inspect") => {
            reject_unknown_flags("network inspect", &rest[1..], &["--json", "--format", "-f"])?;
            let name = rest
                .iter()
                .skip(2)
                .find(|a| !a.starts_with('-'))
                .ok_or(Error::Usage("network inspect <name> [--json] [-f T]"))?;
            Ok(Command::NetworkInspect {
                name: (*name).to_string(),
                json: rest[1..].contains(&"--json"),
                format: flag_value(&rest[1..], "--format").or_else(|| flag_value(&rest[1..], "-f")),
            })
        }
        Some("rm" | "remove") => {
            reject_unknown_flags("network rm", &rest[1..], &[])?;
            let names: Vec<String> = rest
                .iter()
                .skip(2)
                .filter(|a| !a.starts_with('-'))
                .map(|s| (*s).to_string())
                .collect();
            if names.is_empty() {
                return Err(Error::Usage("network rm <name>..."));
            }
            Ok(Command::NetworkRemove { names })
        }
        _ => Err(Error::Usage(
            "network create <name> | network ls [--json] | network inspect <name> [--json] [-f T] \
             | network rm <name>",
        )),
    }
}

/// What to say about a flag `kern compose` does not accept.
///
/// IT USED TO SAY NOTHING. Every unknown flag returned the same usage dump, which does not contain
/// the flag that was rejected: `kern compose x.yml down -v` printed the full verb list and left the
/// reader to diff it by eye. MEASURED across the Docker habits a switcher arrives with -
/// `--remove-orphans`, `--wait`, `--exit-code-from`, `--format`, `--services`, `-q` - all six
/// produced that same dump.
///
/// Each clause below states only what has been measured about kern, and says nothing about flags
/// whose kern-side answer has not been. A flag with no entry gets the accurate general sentence
/// rather than an invented equivalence.
fn unknown_compose_flag(flag: &str) -> String {
    // The `docker compose` flags kern DOES NOT take, each with what it does instead.
    //
    // THIS TABLE IS PRUNED WHENEVER A FLAG IS IMPLEMENTED, and the pruning is the point. It used to
    // carry an entry for every flag a switcher might type, including ones kern had since grown:
    // `--no-deps` was still described as something kern "cannot be asked" to do, `--wait` as a flag
    // with no equivalent, `--build` as a separate verb. Those sentences were unreachable - the
    // parser accepts all three above, so this function is never called for them - which is exactly
    // what makes a stale entry dangerous: it cannot fail a test, and it is read only by a person
    // who has just hit the error, at the moment they are most likely to believe it.
    let known: &[(&str, &str)] = &[
        ("--scale", "kern has no replica count; a service is one box"),
        (
            "--compatibility",
            "kern has no v1 naming to fall back to; boxes are named <project>-<service>",
        ),
        (
            "--project-directory",
            "kern resolves a service's relative paths against the FILE's directory; \
             `-p/--project-name` sets the name the pod and the volumes are scoped by",
        ),
        (
            "--attach-dependencies",
            "an attached `kern compose <file> up` streams every service it started, dependencies \
             included; there is nothing narrower to opt out of",
        ),
    ];
    let extra = known
        .iter()
        .find(|(f, _)| *f == flag)
        .map(|(_, what)| format!(" {what}."))
        .unwrap_or_default();
    format!(
        "unknown flag '{flag}'.{extra} `kern compose` takes: -p/--project-name, \
         --env-file, --profile, --no-pod, --pod, --bridge, --allow-privileged, \
         --allow-device-grants, -d/--detach, -v/--volumes (on `down`), --tail N, -f/--follow, \
         -a/--all, --build, --no-deps, --force-recreate, --no-recreate, -V/--renew-anon-volumes, \
         --wait, --wait-timeout, --exit-code-from, --abort-on-container-exit, --remove-orphans, \
         --pull, -t/--timeout, --rmi, --format, --services, -q/--quiet, -T, --rm"
    )
}

/// What to say about a `docker compose` verb kern does not implement.
///
/// EACH ONE IS A DECISION, not a gap waiting to be filled, and the sentence says which decision.
/// `scale` has no meaning in a model where a service is one box; `create` has none in a model with
/// no "created but not started" state to create INTO. Answering either with the generic verb list
/// leaves the reader to work out which of sixteen words they should have typed, for a question whose
/// answer is that the concept is absent.
fn refused_compose_verb(verb: &str) -> Option<String> {
    let why = match verb {
        "scale" => {
            "kern has no replica count: a service is one box. Declare the copies you want as \
             separate services, or run the same image again with `kern compose <file> run`"
        }
        "create" => {
            "kern has no CREATED-but-not-started state for a box to be created into - a box exists \
             by running. `up --no-start` has the same shape and the same answer; to prepare without \
             starting, `kern compose <file> pull` fetches the images and \
             `kern compose <file> build` builds what the file builds"
        }
        "alpha" | "beta" => {
            "that is Docker's staging area for unreleased subcommands, and kern implements the \
             released surface"
        }
        _ => return None,
    };
    Some(format!("`compose {verb}` is not implemented: {why}."))
}

/// "Now" in unix nanoseconds, for a `--since`/`--until` measured back from it.
///
/// Read ONCE per invocation and passed down, so `--since 10m --until 5m` describes one interval
/// rather than two windows read from two instants five minutes apart.
fn log_clock_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// One `--since`/`--until` value, for either verb that takes them, with the refusal that names what
/// IS accepted.
///
/// ONE FUNCTION FOR TWO CALL SITES, because it is one grammar: `kern logs` and
/// `kern compose <file> logs` both take these flags, and the sentence describing the three forms was
/// written out at each of them. Two copies of a grammar's description drift, and the copy that
/// drifts is the one a reader is holding at the moment their value was refused.
///
/// A value that does not parse is REFUSED rather than approximated: a misread time shows the wrong
/// window, and wrong output that looks like output is the worst of the three outcomes.
fn parse_log_window(flag: &str, v: &str, now: u64) -> Result<u64, Error> {
    crate::commands::boxlog::parse_log_time(v, now).ok_or_else(|| {
        Error::Cli(format!(
            "logs {flag} '{v}': expected a duration back from now (10m, 90s, 1h30m, 2d), unix seconds (1789730443), or RFC3339 UTC (2026-09-18T12:00:00Z)"
        ))
    })
}

/// The file names a stack is discovered under, in the order they are tried: Docker's canonical four
/// (so an existing project just works), then kern's own.
///
/// ONE ARRAY, because the refusal has to name exactly what was looked for. The sentence used to be
/// written out by hand at the one call site and had already drifted: it listed four of these five,
/// omitting `docker-compose.yaml`, so a directory holding that exact file was told kern had looked
/// for it under a name it does not use. A list that is not the list is worse than no list.
const COMPOSE_FILE_NAMES: [&str; 5] = [
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "kern.toml",
];

/// Discover a compose file in the current directory for `kern up`/`down` and for a `kern compose`
/// invocation that named a verb but no file. Returns the first of [`COMPOSE_FILE_NAMES`] that exists.
fn discover_compose_file() -> Option<String> {
    COMPOSE_FILE_NAMES
        .iter()
        .find(|name| std::path::Path::new(name).is_file())
        .map(|name| (*name).to_string())
}

/// The refusal when discovery found nothing, naming every name it tried and both ways to say it
/// explicitly.
fn no_compose_file_here() -> Error {
    Error::Compose(format!(
        "no compose file in this directory (looked for {}) - name one with \
         `kern compose <file> <verb>` or `-f <file>`",
        COMPOSE_FILE_NAMES.join(", ")
    ))
}

/// `kern build -t <name[:tag]> [-f <Dockerfile>] [--build-arg K=V]... [-q] [<context>]`.
fn parse_build(rest: &[&str]) -> Result<Command, Error> {
    // `build <sub> …` - build-history management subcommands. A bare `build … -t <name>` (an actual
    // build) never starts with one of these verbs, so the dispatch is unambiguous.
    //
    // `--json` may sit anywhere after the verb OF A SUBCOMMAND THAT EMITS JSON, which is `inspect`.
    // This line used to say "anywhere after the verb" without that qualification, and `prune` now
    // refuses the flag, so the sentence promised something the code no longer does. Prose and code
    // disagreeing about a predicate is the shape of today's other defect, where the comment above
    // the line-folding rule already said `- ` with the space and the code tested for a bare `-`.
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
                } else if *a == "--json" {
                    // `--json` is READ AT THE TOP OF THIS FUNCTION for every `build` subcommand, but
                    // `Command::BuildPrune` has no field for it and prune has never emitted JSON, so
                    // it was accepted and did nothing. Refusing it is the same rule as the branch
                    // below, but the reason is different and the message has to say which: telling
                    // someone who typed `--json` that "the count needs --keep" is a WRONG
                    // explanation, and a wrong explanation costs more than a vague one because it
                    // sends them to look at the wrong argument.
                    return Err(Error::Usage(
                        "build prune has no JSON output (drop --json; `build inspect` has it)",
                    ));
                } else {
                    // Anything else was SILENTLY IGNORED, and that is worse than refusing it: the
                    // obvious guess is a positional count, so `kern build prune 0` read as "keep
                    // nothing", ran with the default 20, and reported "kept the 20 newest" - a line
                    // nobody re-reads after asking for zero. Measured live: the caller believed the
                    // cache was empty and debugged the next failure against that belief.
                    return Err(Error::Usage(
                        "build prune [--keep <N>] (the count needs --keep)",
                    ));
                }
            }
            return Ok(Command::BuildPrune { keep });
        }
        _ => {}
    }
    // EVERY `-t`, in the order written. The first names the build, the rest are applied to it.
    let mut tags: Vec<String> = Vec::new();
    // `--check`: parse and report, build nothing. See [`commands::build_check`].
    let mut check = false;
    let mut file: Option<String> = None;
    let mut context: Option<String> = None;
    let mut build_args: Vec<String> = Vec::new();
    let mut target: Option<String> = None;
    let mut quiet = false;
    let mut i = 1; // rest[0] == "build"
    while i < rest.len() {
        // `--flag=value` IS THE SAME FLAG HERE TOO, and a build is where scripts use it most:
        // `docker build --platform=linux/amd64 --build-arg=K=V`. The split takes the FIRST `=` only,
        // so `--build-arg=K=V` keeps `K=V` whole.
        let (key, inline) = match rest[i].split_once('=') {
            Some((k, v)) if k.starts_with("--") => (k, Some(v)),
            _ => (rest[i], None),
        };
        // The value of the flag just matched, from the token itself or from the next argument.
        let mut value = |usage: &'static str| -> Result<String, Error> {
            match inline {
                Some(v) => Ok(v.to_string()),
                None => {
                    i += 1;
                    rest.get(i)
                        .map(|v| (*v).to_string())
                        .ok_or(Error::Usage(usage))
                }
            }
        };
        match key {
            // REPEATABLE, as docker's is. Each name is validated as it arrives, so an invalid
            // fourth `-t` is refused before any work starts rather than after the build has run.
            "-t" | "--tag" => {
                let t = value("-t <name[:tag]>")?;
                check_reference(&t, "build -t")?;
                tags.push(t);
            }
            "-f" | "--file" => {
                file = Some(value("-f <Dockerfile>")?);
            }
            "--build-arg" => {
                build_args.push(value("--build-arg K=V")?);
            }
            // `--platform <os/arch>`: ACCEPTED WHEN IT IS THIS MACHINE, REFUSED OTHERWISE. kern runs
            // the host's architecture and emulates nothing, so honouring a foreign platform is not
            // something it can do and ignoring the flag would build the wrong image quietly. The
            // same rule and the same words the compose parser already applies to `platform:`.
            //
            // MEASURED: Sentry's `install.sh` builds every one of its images with
            // `--platform=linux/amd64`, which on this machine IS the host, and kern refused the flag
            // outright - so the official installer stopped at its first build.
            "--platform" => {
                let want = value("--platform <os/arch> (e.g. linux/amd64)")?;
                let host_os = "linux";
                let host_arch = match std::env::consts::ARCH {
                    "x86_64" => "amd64",
                    "aarch64" => "arm64",
                    other => other,
                };
                let w = want.trim().to_ascii_lowercase();
                let matches = w.is_empty()
                    || w == host_arch
                    || w == format!("{host_os}/{host_arch}")
                    || w.starts_with(&format!("{host_os}/{host_arch}/"));
                if !matches {
                    return Err(Error::Build(format!(
                        "--platform {want}: kern builds for this machine ({host_os}/{host_arch}) and emulates nothing, so the image would build and then fail to exec. Build it on a matching host"
                    )));
                }
            }
            // `--target <stage>`: stop at that stage of a multi-stage Dockerfile. Compose spells the
            // same thing `build.target:`, and the builder refuses a name the file does not define
            // rather than falling back to the last stage, which would build the wrong image quietly.
            "--target" => {
                let t = value("--target <stage> (a name from a `FROM … AS <name>`)")?;
                if t.trim().is_empty() {
                    return Err(Error::Usage(
                        "--target <stage> (a name from a `FROM … AS <name>`)",
                    ));
                }
                target = Some(t);
            }
            "-q" | "--quiet" => quiet = true,
            "--check" => check = true,
            // NAMED, because "unknown build flag" sent a reader to re-read their whole command line
            // to find which word kern meant.
            s if s.starts_with('-') => {
                return Err(Error::Build(format!(
                    "unknown build flag '{s}' - `kern build` takes -t/--tag, -f/--file, --build-arg, --target, --platform, -q/--quiet, --check"
                )))
            }
            s if context.is_none() => context = Some(s.to_string()),
            _ => return Err(Error::Usage("build takes a single context directory")),
        }
        i += 1;
    }
    // One pass, no clone: the first name is the build's, the remainder are its aliases.
    let mut named = tags.into_iter();
    let tag = named.next();
    let extra_tags: Vec<String> = named.collect();
    // `--check` NEEDS NO `-t`: requiring a name for an image that is not going to exist would make
    // the dry run harder to type than the build it is standing in for.
    Ok(Command::Build {
        check,
        tag,
        extra_tags,
        file,
        context: context.unwrap_or_else(|| ".".to_string()),
        build_args,
        quiet,
        target,
    })
}

/// Parse and run.
pub fn run(args: &[String]) -> Result<(), Error> {
    let (_opts, cmd) = parse(args)?;
    match cmd {
        Command::Version => commands::version(),
        Command::Banner => commands::banner(),
        Command::Help => commands::help(),
        Command::HelpFor(verb) => commands::help_for(&verb),
        Command::BoxPlan {
            name,
            profiles,
            config,
        } => commands::box_plan(&name, &profiles, config.as_deref()),
        Command::BoxRun {
            name,
            rootfs,
            image,
            pull,
            command,
            entrypoint,
            detached,
            read_only,
            volumes,
            env,
            egress_allow,
            landlock_rw,
            net_ips,
            pod_bridge,
            apparmor,
            workdir,
            share_net,
            pod,
            uid_range,
            no_uid_range,
            bind_rootfs,
            privileged,
            require_limits,
            allow_uncapped,
            security_profile,
            overlay_lower,
            overlay_upper,
            memory,
            memory_swap_max,
            cpus,
            cpuset,
            tty,
            ports,
            add_hosts,
            dns,
            dns_search,
            dns_options,
            log_max_size,
            log_max_file,
            memory_reservation,
            cpu_weight,
            secrets,
            secret_envs,
            secret_mode,
            ssh_port,
            ssh_key,
            hostname,
            tun,
            init,
            pids_limit,
            tmpfs,
            shm_size,
            ulimits,
            sysctls,
            labels,
            restart_max,
            def_hash,
            stop_signal,
            stop_grace,
            run_as,
            cap_add,
            cap_drop,
            restart,
            health_cmd,
            health_cmd_argv,
            health_interval,
            health_retries,
            health_start_period,
            health_start_interval,
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
            rm,
        } => commands::box_run(commands::BoxRunArgs {
            rm,
            name: &name,
            rootfs: rootfs.as_deref(),
            image: image.as_deref(),
            pull,
            command: &command,
            entrypoint: entrypoint.as_deref(),
            detached,
            read_only,
            volumes: &volumes,
            env: &env,
            egress_allow: &egress_allow,
            landlock_rw: &landlock_rw,
            net_ips: &net_ips,
            pod_bridge: pod_bridge.clone(),
            apparmor: apparmor.as_deref(),
            workdir: workdir.as_deref(),
            share_net,
            pod: pod.as_deref(),
            uid_range,
            no_uid_range,
            bind_rootfs,
            privileged,
            require_limits,
            allow_uncapped,
            security_profile,
            overlay_lower: overlay_lower.as_deref(),
            overlay_upper: overlay_upper.as_deref(),
            memory,
            memory_swap_max,
            cpus,
            cpuset: cpuset.as_deref(),
            tty,
            ports: &ports,
            secrets: &secrets,
            secret_envs: &secret_envs,
            secret_mode,
            ssh_port,
            ssh_key: ssh_key.as_deref(),
            hostname: hostname.as_deref(),
            tun,
            init,
            pids_limit,
            tmpfs: &tmpfs,
            shm_size,
            ulimits: &ulimits,
            sysctls: &sysctls,
            labels: &labels,
            restart_max,
            def_hash: def_hash.as_deref().unwrap_or(""),
            stop_signal,
            stop_grace,
            run_as: run_as.as_deref(),
            cap_add: &cap_add,
            cap_drop: &cap_drop,
            restart,
            health_cmd: health_cmd.as_deref(),
            health_cmd_argv: &health_cmd_argv,
            health_interval,
            health_retries,
            health_start_period,
            health_start_interval,
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
            dns: &dns,
            dns_search: &dns_search,
            dns_options: &dns_options,
            log_max_size,
            log_max_file,
            memory_reservation,
            cpu_weight,
        }),
        Command::Run {
            command,
            memory,
            memory_swap_max,
            cpus,
            cpuset,
            config,
            landlock_rw,
        } => commands::run(
            &command,
            memory,
            memory_swap_max,
            cpus,
            cpuset.as_deref(),
            config.as_deref(),
            &landlock_rw,
        ),
        Command::Exec {
            name,
            command,
            env,
            workdir,
            tty,
        } => commands::exec(&name, &command, &env, workdir.as_deref(), tty, false),
        Command::Build {
            check,
            tag,
            extra_tags,
            file,
            context,
            build_args,
            quiet,
            target,
        } => {
            let a = commands::BuildArgs {
                tag: tag.as_deref(),
                extra_tags: &extra_tags,
                file: file.as_deref(),
                context: &context,
                build_args: &build_args,
                quiet,
                target: target.as_deref(),
            };
            // ONE ARGUMENT STRUCT FOR BOTH, so `--check` resolves the Dockerfile, the context and
            // the build args through exactly the fields a real build does: a report about a
            // different file from the one that would be built would be worse than no report.
            if check {
                commands::build_check(a)
            } else {
                commands::build(a)
            }
        }
        Command::PodCreate {
            name,
            outbound,
            uid_range,
            bridge,
        } => crate::pod::create_with_range(
            &name,
            outbound,
            // `kern pod create --uid-range` is the caller asking in as many words.
            if uid_range {
                kern_isolation::UidRange::Requested
            } else {
                kern_isolation::UidRange::Off
            },
            bridge.as_deref(),
        ),
        Command::PodList { json } => {
            if json {
                crate::pod::list_json()
            } else {
                crate::pod::list()
            }
        }
        Command::PodRemove { names } => crate::pod::remove(&names),
        Command::NetworkCreate { name } => {
            crate::network::create(&name)?;
            println!("created network '{name}'");
            Ok(())
        }
        Command::NetworkList { json } => crate::network::print_list(json),
        Command::NetworkInspect { name, json, format } => {
            crate::network::print_inspect(&name, json, format.as_deref())
        }
        Command::NetworkRemove { names } => crate::network::remove_many(&names),
        Command::PodHolder => crate::pod::run_holder(),
        Command::RelayHolder { dir } => crate::relayhold::run_holder(&dir),
        Command::EgressProxy { sock, allow } => crate::egress::proxy_reexec(&sock, &allow),
        Command::EgressPump {
            read_fd,
            box_port,
            sock,
            ready_fd,
        } => crate::egress::pump_reexec(read_fd, box_port, &sock, ready_fd),
        Command::Search { query, json } => commands::search(&query, json),
        Command::Images { json, filters } => commands::images(json, &filters),
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
        Command::Commit { box_ref, image } => commands::commit(&box_ref, &image),
        Command::Stop { names, all } => commands::stop(&names, all),
        Command::Pause { names, all, freeze } => commands::pause(&names, all, freeze),
        Command::Attach { name } => commands::attach(&name),
        Command::Cp { src, dst } => crate::boxcp::cp(&src, &dst),
        Command::Ps {
            json,
            quiet,
            all,
            filters,
            format,
            view,
        } => commands::ps(
            if json {
                commands::JsonShape::Array
            } else {
                commands::JsonShape::No
            },
            quiet,
            all,
            &filters,
            format.as_deref(),
            view,
        ),
        Command::Stats { json, names } => commands::stats(json, &names),
        Command::Logs {
            name,
            tail,
            follow,
            timestamps,
            window,
        } => commands::logs(&name, tail, follow, timestamps, window),
        Command::Inspect { name, json, format } => {
            commands::inspect_formatted(&name, json, format.as_deref())
        }
        Command::Prune => commands::prune(),
        Command::Gc { images } => commands::gc(images),
        Command::Doctor => crate::doctor::doctor(),
        Command::DoctorApparmorProfile => crate::doctor::print_apparmor_profile(),
        Command::Info => crate::doctor::info(),
        Command::Bench {
            rootfs,
            image,
            bind_rootfs,
            count,
        } => commands::bench(rootfs.as_deref(), image.as_deref(), bind_rootfs, count),
        Command::Recover => commands::recover(),
        Command::Rename { old, new } => commands::rename(&old, &new),
        Command::Port {
            name,
            container_port,
        } => commands::port(&name, container_port.as_deref()),
        Command::Update {
            name,
            memory,
            cpus,
            pids,
        } => commands::update(&name, memory, cpus, pids),
        Command::Wait { names } => commands::wait(&names),
        Command::Diff { name, json } => commands::diff(&name, json),
        Command::Events => commands::events(),
        Command::History { count } => commands::history(count),
        Command::Login {
            registry,
            username,
            password,
            password_stdin,
        } => crate::auth::login(
            registry.as_deref(),
            username.as_deref(),
            password.as_deref(),
            password_stdin,
        ),
        Command::Logout { registry } => crate::auth::logout(registry.as_deref()),
        Command::Completions { shell } => crate::completions::completions(&shell),
        Command::Top => commands::top(),
        Command::Compose {
            files,
            action,
            pull,
            stop_timeout,
            ignore_pull_failures,
            build_args,
            run_name,
            run_entrypoint,
            run_env,
            run_user,
            rmi,
            recreate,
            renew_anon_volumes,
            log_timestamps,
            log_window,
            no_log_prefix,
            no_pod,
            bridge,
            allow_privileged,
            force_pod,
            allow_device_grants,
            detach,
            remove_volumes,
            wait_ready,
            wait_timeout,
            run_cmd,
            run_rm,
            no_deps,
            exit_code_from,
            abort_on_exit,
            remove_orphans,
            ps_quiet,
            ps_services,
            ps_format,
            tail,
            follow,
            all,
            services,
            project,
            env_file,
            profiles,
        } => commands::compose(commands::ComposeOpts {
            files: &files,
            action,
            pull: pull.as_deref(),
            stop_timeout,
            ignore_pull_failures,
            build_args: &build_args,
            run_name: run_name.as_deref(),
            run_entrypoint: run_entrypoint.as_deref(),
            recreate,
            renew_anon_volumes,
            log_timestamps,
            log_window,
            no_log_prefix,
            run_env: &run_env,
            run_user: run_user.as_deref(),
            rmi,
            no_pod,
            bridge,
            allow_privileged,
            force_pod,
            allow_device_grants,
            detach,
            remove_volumes,
            wait_ready,
            wait_timeout,
            run_cmd: &run_cmd,
            run_rm,
            no_deps,
            exit_code_from: exit_code_from.as_deref(),
            abort_on_exit,
            remove_orphans,
            ps_quiet,
            ps_services,
            ps_format: ps_format.as_deref(),
            tail,
            follow,
            all,
            services: &services,
            project: project.as_deref(),
            env_file: env_file.as_deref(),
            profiles: &profiles,
        }),
        Command::Config { sub, force, json } => commands::config_cmd(&sub, force, json),
        Command::ConfigAdd { args } => commands::config_add(&args),
        Command::ConfigRm { args } => commands::config_rm(&args),
        Command::Validate { path } => commands::validate(path.as_deref()),
        Command::Uninstall { yes, keep_images } => commands::uninstall(yes, keep_images),
        Command::Examples => commands::examples(),
        Command::Volume { args } => crate::volume::run(&args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `--ulimit` name the usage line advertises resolves, and nothing else does.
    ///
    /// The usage text and the table used to be two lists in one function; they are now a list and a
    /// table in two crates, which is exactly the shape that drifts. This compares one against the
    /// other, so adding a limit to the sandbox's table without advertising it (or the reverse) is a
    /// red test rather than a name that parses but is undocumented.
    #[test]
    fn every_advertised_ulimit_name_resolves_and_nothing_else_does() {
        let usage = match parse_ulimit("nonsense") {
            Err(Error::Usage(u)) => u,
            other => panic!("a spec with no '=' must be a usage error, got {other:?}"),
        };
        let advertised: Vec<&str> = usage
            .split_once("one of:")
            .map(|(_, tail)| tail.split_whitespace().collect())
            .unwrap_or_default();
        assert_eq!(advertised.len(), 15, "usage list: {advertised:?}");
        for name in &advertised {
            let (res, soft, hard) = parse_ulimit(&format!("{name}=1:2"))
                .unwrap_or_else(|_| panic!("advertised name `{name}` does not parse"));
            assert_eq!((soft, hard), (1, 2));
            assert_eq!(
                kern_isolation::ulimit_named(res).map(|(n, _, _)| n),
                Some(*name),
                "`{name}` resolves to {res}, which the sandbox names differently"
            );
        }
        let table: Vec<&str> = kern_isolation::ULIMITS.iter().map(|(n, ..)| *n).collect();
        assert_eq!(advertised, table, "usage line and table disagree");
        // Nothing outside the table parses, including a near-miss and a bare RLIMIT number.
        for bad in ["nofiles=1", "mem lock=1", "8=1", "=1"] {
            assert!(
                parse_ulimit(bad).is_err(),
                "`{bad}` must not resolve to a limit"
            );
        }
        // The name is case-insensitive and space-tolerant, as it was before the table moved.
        let mixed = parse_ulimit(" MemLock =-1").expect("case and spaces are tolerated");
        // COMPARED THROUGH i64, not `as i32`, because the constant's TYPE differs between libcs: an
        // unsigned `__rlimit_resource_t` on glibc, a plain `c_int` on musl. Any conversion to `i32` is
        // redundant on exactly one of them, and `-D warnings` against the musl target - which is what
        // kern actually SHIPS - turned that redundancy into the only error in the tree. Widening both
        // sides is correct on both, and says what the comparison is about: the resource NUMBER.
        assert_eq!(i64::from(mixed.0), libc::RLIMIT_MEMLOCK as i64);
        assert_eq!(mixed.1, libc::RLIM_INFINITY);
        assert_eq!(mixed.2, libc::RLIM_INFINITY);
    }

    /// A flag the read-only config verbs do not take must be REFUSED. `kern config list --json`
    /// printed the human listing and exited 0, so a script that asked for JSON got prose and had no
    /// way to tell; the same held for any typo. `--force`/`--yes`/`-y` stay accepted (setup/clear
    /// need a confirm), and `config add`/`rm` are untouched: their flags are the profile fields.
    /// `--platform` cannot reach the image cache: the cache key is the reference alone, with no
    /// platform component, and the cache path fetches the host architecture. Writing a foreign-arch
    /// rootfs under a host-arch key is cache poisoning, a class already fixed once here. Since a bare
    /// `pull` now fills the cache, the combination must be REFUSED rather than silently falling back
    /// to a directory, which would be a third behaviour for one verb.
    /// A mistyped flag on `pull`/`push` must be REFUSED, not skipped with its value read as the ref.
    ///
    /// `parse_pull` takes the first argument that does not start with `-`, and the old arm skipped
    /// anything that did, so `kern pull --platfrom linux/arm64 alpine:3.19` (one transposition) took
    /// `linux/arm64` as the image, dropped `alpine:3.19` entirely, and reported
    /// "cannot access 'linux/arm64' ... it may be private (run `kern login`)". The user is then told
    /// to authenticate because of a spelling mistake, and the image they named never appears in any
    /// message. `push` had the same shape through its `filter(|a| !a.starts_with('-'))`.
    ///
    /// ASKING FOR HELP ABOUT A VERB THAT DOES NOT EXIST IS STILL AN ERROR.
    ///
    /// `kern frobnicate --help` printed the whole 180-line reference and exited 0, so a typo was
    /// indistinguishable from a real verb that has no section of its own, while `kern frobnicate`
    /// on its own had always said `unknown command`. Asking for help was the one spelling that hid
    /// the mistake.
    ///
    /// "found no lines in the reference" cannot be the test, and that is measured, not assumed:
    /// `install` and `docker` also fall through to the full page, and both are genuinely NOT verbs
    /// (`kern install` and `kern docker` each answer `unknown command`; the docker shim is argv0
    /// only). The parser is its own oracle instead, so there is no second list of verbs to drift.
    #[test]
    fn help_for_a_verb_that_does_not_exist_is_an_error_not_the_whole_reference() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());

        for typo in ["frobnicate", "bx", "puul", "install", "docker"] {
            match p(&[typo, "--help"]) {
                Err(Error::UnknownCommand(v)) => {
                    assert_eq!(v, typo, "the error must name the typo")
                }
                other => panic!("`kern {typo} --help` must be an unknown command: {other:?}"),
            }
        }

        // POSITIVE CONTROLS, and the second one is the one that matters: `wait` has no section of
        // its own in the reference, so a fix that keyed on "no lines found" would have broken it.
        assert_eq!(
            p(&["box", "--help"]).unwrap().1,
            Command::HelpFor("box".to_string())
        );
        assert_eq!(
            p(&["wait", "--help"]).unwrap().1,
            Command::HelpFor("wait".to_string())
        );
        // A verb that needs arguments is not a spelling problem: help is still the answer.
        assert_eq!(
            p(&["exec", "--help"]).unwrap().1,
            Command::HelpFor("exec".to_string())
        );
        // And a bare `--help` is still the whole reference.
        assert_eq!(p(&["--help"]).unwrap().1, Command::Help);
    }

    /// A REFERENCE NO REGISTRY WILL ACCEPT IS REFUSED WHERE THE USER TYPED IT.
    ///
    /// `kern build -t Foo-BAR:latest` used to succeed and put that name in the local cache, so the
    /// refusal arrived at `kern push`, after the build was paid for. `kern pull Foo-BAR:latest` was
    /// worse: it dialled the registry and returned `registry: no layers in manifest`, which names
    /// nothing about the real problem. The rule is `kern_oci::valid_reference`, which already
    /// rejected uppercase; it was simply not consulted on either path.
    ///
    /// Measured against Docker 29.6.2 on one host: docker refuses `dd-A:latest` at build with
    /// `repository name must be lowercase`, and kern built it.
    #[test]
    fn an_image_reference_the_oci_grammar_cannot_hold_is_refused_before_any_work() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());

        let err = p(&["build", "-t", "Foo-BAR:latest", "."])
            .expect_err("an uppercase tag is not a valid OCI reference");
        let msg = format!("{err}");
        assert!(
            msg.contains("Foo-BAR:latest"),
            "the error must quote what was typed: {msg}"
        );
        assert!(
            msg.contains("foo-bar:latest"),
            "and must name the exact string to type instead, since the fix is mechanical: {msg}"
        );

        let err = p(&["pull", "NotInCache-UPPER:latest"])
            .expect_err("pull must refuse before it dials a registry");
        assert!(
            format!("{err}").contains("notincache-upper:latest"),
            "pull's refusal carries the same remedy: {err}"
        );

        // A reference invalid for a reason lowercasing does NOT fix must not carry a false remedy:
        // telling someone to retype the same broken string in lower case is worse than saying
        // nothing. `a..b` is a path traversal component, rejected by `valid_repo_path` either way.
        let err = p(&["build", "-t", "a..b:latest", "."]).expect_err("`..` is never a valid path");
        let msg = format!("{err}");
        assert!(
            !msg.contains("lowercase"),
            "no lowercase remedy when lowercasing changes nothing: {msg}"
        );

        // POSITIVE CONTROL, both verbs: a valid reference still parses, so the three refusals above
        // are about the grammar and not about the arm rejecting everything it is given.
        assert!(
            p(&["build", "-t", "foo-bar:latest", "."]).is_ok(),
            "a lowercase tag must still build"
        );
        assert!(
            p(&["pull", "ghcr.io/owner/name:1.2.3"]).is_ok(),
            "a fully qualified reference must still pull"
        );
    }

    /// EVERY `-t` SURVIVES, and only the LAST one used to.
    ///
    /// `docker build -t repo:$VERSION -t repo:latest .` is how a release pipeline names an image it
    /// is about to promote: one build, two names, a `push` of each. kern parsed both flags, kept the
    /// second, and said nothing - so `repo:$VERSION` never existed and the `push repo:$VERSION` on
    /// the next line failed on a name nothing had created. MEASURED before the fix:
    /// `kern build -t probeone:1 -t probetwo:2 ctx` printed `built 'probetwo:2'` and `kern images`
    /// listed `probetwo:2` alone.
    #[test]
    fn every_build_tag_is_kept_and_the_first_names_the_build() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        let built = |a: &[&str]| match p(a) {
            Ok((
                _,
                Command::Build {
                    tag, extra_tags, ..
                },
            )) => (tag, extra_tags),
            other => panic!("expected a Build command, got {other:?}"),
        };

        // The reported shape: the FIRST name is the build's, the rest are applied to it.
        let (tag, extra) = built(&["build", "-t", "repo:1.2.3", "-t", "repo:latest", "."]);
        assert_eq!(tag.as_deref(), Some("repo:1.2.3"));
        assert_eq!(extra, ["repo:latest"]);

        // Three names, order preserved, and `--tag` is the same flag.
        let (tag, extra) = built(&["build", "-t", "a:1", "--tag", "b:2", "-t", "c:3", "ctx"]);
        assert_eq!(tag.as_deref(), Some("a:1"));
        assert_eq!(extra, ["b:2", "c:3"]);

        // One name is unchanged: no extras, and nothing about the single-tag path moved.
        let (tag, extra) = built(&["build", "-t", "only:1", "."]);
        assert_eq!(tag.as_deref(), Some("only:1"));
        assert!(extra.is_empty(), "a single -t must produce no aliases");

        // An invalid LATER name is refused at parse time, before the build is paid for.
        assert!(
            p(&["build", "-t", "ok:1", "-t", "Bad-NAME:2", "."]).is_err(),
            "the grammar applies to every -t, not only the first"
        );
    }

    /// THE RECREATE OVERRIDES PARSE ON BOTH SPELLINGS OF `up`, AND CONTRADICT EACH OTHER LOUDLY.
    ///
    /// `up -d --build --force-recreate --no-deps <svc>` is one line out of a real rebuild script,
    /// and `--force-recreate` was the one word in it kern refused, so the whole invocation died on a
    /// flag whose meaning kern's reconciler could express exactly. `kern up` (the directory
    /// shorthand) takes them too: a flag that parses on one spelling and not the other is a
    /// difference nobody can hold in their head.
    #[test]
    fn the_recreate_overrides_parse_and_refuse_their_own_contradiction() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        let policy = |a: &[&str]| match p(a) {
            Ok((
                _,
                Command::Compose {
                    recreate,
                    renew_anon_volumes,
                    ..
                },
            )) => (recreate, renew_anon_volumes),
            other => panic!("expected a Compose command, got {other:?}"),
        };

        // The reported line, whole.
        assert_eq!(
            policy(&[
                "compose",
                "f.yml",
                "up",
                "-d",
                "--build",
                "--force-recreate",
                "--no-deps",
                "worker",
            ]),
            (commands::RecreatePolicy::Always, false)
        );
        assert_eq!(
            policy(&["compose", "f.yml", "up", "--no-recreate"]),
            (commands::RecreatePolicy::Never, false)
        );
        assert_eq!(
            policy(&["compose", "f.yml", "up"]),
            (commands::RecreatePolicy::OnDrift, false),
            "the comparison stays the default"
        );
        // `-V` and its long spelling, which are one flag.
        for v in ["-V", "--renew-anon-volumes"] {
            assert_eq!(
                policy(&["compose", "f.yml", "up", v]),
                (commands::RecreatePolicy::OnDrift, true),
                "{v} must set the renewal without touching the recreate policy"
            );
        }

        // BOTH AT ONCE IS REFUSED BY NAME rather than resolved by precedence: whichever kern picked,
        // half the readers would expect the other.
        let err = p(&[
            "compose",
            "f.yml",
            "up",
            "--force-recreate",
            "--no-recreate",
        ])
        .expect_err("the two contradict each other");
        let msg = format!("{err}");
        assert!(
            msg.contains("--force-recreate") && msg.contains("--no-recreate"),
            "the refusal must name both flags: {msg}"
        );
    }

    /// EVERY COMPOSE VERB THE HELP LISTS PARSES, AND EVERY ONE KERN REFUSES IS REFUSED BY NAME.
    ///
    /// The verb table is the single list behind `from_verb`, the help line and the usage error, so a
    /// verb can never work while being absent from what the CLI says about itself. What that table
    /// cannot catch is the OTHER direction: a Docker verb kern does not have used to fall through to
    /// the bare-word arm and be read as a SERVICE name, so `compose f.yml create` answered "no such
    /// service: create" and sent the reader to look at their file for a service nobody wrote.
    #[test]
    fn every_compose_verb_parses_and_the_absent_ones_are_refused_by_name() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        // The seven verbs added as thin scopings of a box-level verb, plus `kill`, which is `stop`
        // under Docker's name for it.
        for (verb, want) in [
            ("wait", commands::ComposeAction::Wait),
            ("events", commands::ComposeAction::Events),
            ("images", commands::ComposeAction::Images),
            ("push", commands::ComposeAction::Push),
            ("rm", commands::ComposeAction::Rm),
            ("top", commands::ComposeAction::Top),
            ("version", commands::ComposeAction::Version),
            ("kill", commands::ComposeAction::Stop),
        ] {
            match p(&["compose", "f.yml", verb]) {
                Ok((_, Command::Compose { action, .. })) => {
                    assert_eq!(action, want, "compose {verb}")
                }
                other => panic!("compose {verb}: expected a Compose command, got {other:?}"),
            }
        }
        // REFUSED BY NAME, with the reason rather than a verb list: the concept is absent, so
        // "did you mean one of these sixteen" answers a question nobody asked.
        for (verb, word) in [("create", "started"), ("scale", "replica")] {
            let err = p(&["compose", "f.yml", verb]).expect_err("{verb} must be refused");
            let msg = format!("{err}");
            assert!(msg.contains(verb), "the refusal must name the verb: {msg}");
            assert!(
                msg.contains(word),
                "and say WHY kern has no such thing: {msg}"
            );
        }
    }

    /// `compose wait` RETURNS THE STATUS; `kern wait` PRINTS IT. Two verbs, two contracts, on
    /// purpose.
    ///
    /// A CI job writes `docker compose wait tests` and branches on the exit code - that is the whole
    /// use of the verb, and Docker documents it as the status of the first container to stop. The
    /// first version of this printed the numbers and exited 0, which reports every failing suite as
    /// a pass. `kern wait <box>` keeps printing and exiting 0: it is older, its contract is frozen
    /// with the CLI, and a script already reading its stdout is correct.
    ///
    /// This test pins the SHAPES rather than the runtime behaviour (which needs live boxes and is
    /// measured against them): that both verbs parse, and that the compose one carries the services
    /// it was given.
    #[test]
    fn compose_wait_is_a_distinct_verb_from_the_box_level_wait() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        match p(&["compose", "f.yml", "wait", "tests"]).unwrap().1 {
            Command::Compose {
                action, services, ..
            } => {
                assert_eq!(action, commands::ComposeAction::Wait);
                assert_eq!(services, ["tests"], "the named service reaches the verb");
            }
            other => panic!("expected Compose, got {other:?}"),
        }
        // The box-level verb is untouched and still takes bare names.
        match p(&["wait", "boxa", "boxb"]).unwrap().1 {
            Command::Wait { names } => assert_eq!(names, ["boxa", "boxb"]),
            other => panic!("expected Wait, got {other:?}"),
        }
    }

    /// `compose logs -t` IS TIMESTAMPS AND `compose down -t 30` IS A TIMEOUT, on one flag.
    ///
    /// Docker overloads `-t` exactly this way and the verb is what disambiguates it. The guarded arm
    /// has to be tried FIRST or the timeout arm claims every `-t`; written the other way round the
    /// compiler says `unreachable pattern`, which is how the ordering was found rather than guessed.
    #[test]
    fn dash_t_is_timestamps_on_logs_and_a_timeout_everywhere_else() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        match p(&["compose", "f.yml", "logs", "-t"]) {
            Ok((
                _,
                Command::Compose {
                    log_timestamps,
                    stop_timeout,
                    ..
                },
            )) => {
                assert!(log_timestamps, "logs -t asks for the time column");
                assert_eq!(stop_timeout, None, "and not for a stop grace");
            }
            other => panic!("expected Compose, got {other:?}"),
        }
        match p(&["compose", "f.yml", "down", "-t", "30"]) {
            Ok((
                _,
                Command::Compose {
                    log_timestamps,
                    stop_timeout,
                    ..
                },
            )) => {
                assert_eq!(stop_timeout, Some(30), "down -t is the stop grace");
                assert!(!log_timestamps);
            }
            other => panic!("expected Compose, got {other:?}"),
        }
        // `--since`/`--until` reach the window, and an unparseable value is refused rather than
        // silently showing a different window.
        match p(&["compose", "f.yml", "logs", "--since", "10m"]) {
            Ok((_, Command::Compose { log_window, .. })) => {
                assert!(log_window.0.is_some() && log_window.1.is_none())
            }
            other => panic!("expected Compose, got {other:?}"),
        }
        assert!(p(&["compose", "f.yml", "logs", "--since", "domani"]).is_err());
    }

    /// `kern port <box> [<port>]` EXISTS, and the compose form is not the only way to ask.
    #[test]
    fn port_parses_with_and_without_a_container_port() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        assert_eq!(
            p(&["port", "web", "80"]).unwrap().1,
            Command::Port {
                name: "web".to_string(),
                container_port: Some("80".to_string()),
            }
        );
        // No port is the listing form, as `docker port <container>` is.
        assert_eq!(
            p(&["port", "web"]).unwrap().1,
            Command::Port {
                name: "web".to_string(),
                container_port: None,
            }
        );
        // A protocol suffix reaches the command rather than being refused by the parser.
        assert_eq!(
            p(&["port", "web", "53/udp"]).unwrap().1,
            Command::Port {
                name: "web".to_string(),
                container_port: Some("53/udp".to_string()),
            }
        );
        assert!(p(&["port"]).is_err(), "a box is required");
    }

    /// `docker inspect -f …` IS THE SPELLING IN EVERY WAIT LOOP, and only `--format` was accepted.
    #[test]
    fn inspect_takes_both_spellings_of_format() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        for flag in ["-f", "--format"] {
            match p(&["inspect", flag, "{{.State.Status}}", "web"]).unwrap().1 {
                Command::Inspect { name, format, .. } => {
                    assert_eq!(
                        name, "web",
                        "{flag}: the template must not be read as the box"
                    );
                    assert_eq!(format.as_deref(), Some("{{.State.Status}}"), "{flag}");
                }
                other => panic!("{flag}: expected Inspect, got {other:?}"),
            }
        }
    }

    /// `login` REFUSES A FLAG IT DOES NOT READ, and `--password-stdin` is now one it does.
    ///
    /// Nothing checked login's flags, so `--password-stdin` was discarded and the command still
    /// happened to work: the password is read from stdin anyway when stdin is not a terminal. A
    /// misspelling would have been discarded just as quietly, and the prompt it printed into a CI
    /// log was the only sign either way.
    #[test]
    fn login_reads_the_password_flags_and_refuses_what_it_cannot() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        match p(&["login", "ghcr.io", "--username", "u", "--password-stdin"])
            .unwrap()
            .1
        {
            Command::Login {
                registry,
                username,
                password,
                password_stdin,
            } => {
                assert_eq!(registry.as_deref(), Some("ghcr.io"));
                assert_eq!(username.as_deref(), Some("u"));
                assert_eq!(password, None);
                assert!(password_stdin);
            }
            other => panic!("expected Login, got {other:?}"),
        }
        // The username's VALUE is not the registry, and neither is the password's.
        match p(&["login", "-u", "alice", "-p", "secret"]).unwrap().1 {
            Command::Login {
                registry,
                username,
                password,
                ..
            } => {
                assert_eq!(registry, None, "'alice'/'secret' are flag values");
                assert_eq!(username.as_deref(), Some("alice"));
                assert_eq!(password.as_deref(), Some("secret"));
            }
            other => panic!("expected Login, got {other:?}"),
        }
        assert!(
            p(&["login", "--password-stidn"]).is_err(),
            "a misspelling must be refused, not discarded"
        );
    }

    /// `docker compose up -d` IS THE MOST COMMON WAY ANYONE STARTS A STACK, AND IT MUST PARSE.
    ///
    /// It used to be a usage error: the flag loop rejected every unknown `-x`, and `-d` was not in
    /// the list. Found while running kern's own acceptance battery, which reached for the Docker
    /// habit without thinking, which is the point.
    ///
    /// IT ALSO USED TO MEAN NOTHING. `up` always returned as soon as the stack was started, so `-d`
    /// was accepted as a name for what already happened, and the two spellings were
    /// indistinguishable: MEASURED by diffing the output of `up` against `up -d` on the same file,
    /// which differed only in a pid. `up` now streams the stack on a terminal, as Docker's does,
    /// and `-d` is what turns that off - so the flag is asserted here to REACH the command, not
    /// merely to parse. A no-op flag cannot be tested for its effect; that was the defect.
    #[test]
    fn compose_up_accepts_the_detach_flag_and_carries_it() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());

        for flag in ["-d", "--detach"] {
            let (_, cmd) = p(&["compose", "stack.yml", "up", flag])
                .unwrap_or_else(|e| panic!("`compose up {flag}` must parse: {e}"));
            match cmd {
                Command::Compose {
                    files,
                    action,
                    detach,
                    ..
                } => {
                    assert_eq!(files, vec!["stack.yml".to_string()]);
                    assert_eq!(action, crate::commands::ComposeAction::Up);
                    assert!(detach, "`{flag}` must reach the command, not be swallowed");
                }
                other => panic!("`compose up {flag}` must stay a compose up: {other:?}"),
            }
        }

        // THE DISCRIMINATOR. Without the flag the same command must arrive with `detach` false, or
        // the assertion above passes on a parser that hardcodes it and `-d` means nothing again.
        let (_, plain) = p(&["compose", "stack.yml", "up"]).unwrap_or_else(|e| panic!("{e}"));
        match plain {
            Command::Compose { detach, .. } => {
                assert!(!detach, "a bare `up` must not arrive pre-detached")
            }
            other => panic!("`compose up` must stay a compose up: {other:?}"),
        }

        // The `kern up` shorthand carries the same flag, and is NOT asserted here: it discovers its
        // file in the process CWD, which a test cannot pin without mutating global state that the
        // other tests in this binary read concurrently.

        // POSITIVE CONTROL: an unknown flag is STILL refused, so the arm above did not open the
        // gate for everything. A parser that accepts any `-x` cannot report a typo.
        assert!(
            p(&["compose", "stack.yml", "up", "--detatch"]).is_err(),
            "a typo must still be a usage error"
        );
    }

    /// AFTER `run <service>`, EVERYTHING IS THE COMMAND, flags included.
    ///
    /// `docker compose run --rm web sh -c 'exit 7'` is the line in nearly every project README, and
    /// a parser that kept reading flags past the service name would take `-c` for one of its own
    /// and answer with a usage error. The service is the LAST thing the parser decides; the rest is
    /// handed over verbatim.
    #[test]
    fn run_hands_everything_after_the_service_to_the_command() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        let (_, cmd) = p(&[
            "compose",
            "stack.yml",
            "run",
            "--rm",
            "web",
            "sh",
            "-c",
            "exit 7",
        ])
        .unwrap_or_else(|e| panic!("the README line must parse: {e}"));
        match cmd {
            Command::Compose {
                action,
                services,
                run_cmd,
                run_rm,
                ..
            } => {
                assert_eq!(action, crate::commands::ComposeAction::Run);
                assert!(run_rm, "--rm before the service is still a kern flag");
                assert_eq!(services, vec!["web".to_string()], "one service, not three");
                assert_eq!(
                    run_cmd,
                    vec!["sh".to_string(), "-c".to_string(), "exit 7".to_string()],
                    "`-c` belongs to the command, not to kern"
                );
            }
            other => panic!("must be a compose run: {other:?}"),
        }

        // POSITIVE CONTROL: for any OTHER verb the same words are service selectors, and a stray
        // flag is still refused. Without this the test passes on a parser that stopped reading
        // flags everywhere.
        assert!(
            p(&["compose", "stack.yml", "logs", "web", "-c", "x"]).is_err(),
            "outside `run`, an unknown flag is still a usage error"
        );
    }

    /// `--exit-code-from` implies the abort, and both reach the command.
    ///
    /// MEASURED on Docker 29.6.2 before it was written: `--exit-code-from tests` and
    /// `--abort-on-container-exit` both exit 3 on a stack whose `tests` exits 3, and both leave no
    /// container running, so the first flag cannot be the second one's weaker cousin.
    #[test]
    fn exit_code_from_implies_the_abort() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        let (_, cmd) = p(&["compose", "s.yml", "up", "--exit-code-from", "tests"])
            .unwrap_or_else(|e| panic!("{e}"));
        match cmd {
            Command::Compose {
                exit_code_from,
                abort_on_exit,
                ..
            } => {
                assert_eq!(exit_code_from.as_deref(), Some("tests"));
                assert!(
                    abort_on_exit,
                    "naming a service implies aborting on an exit"
                );
            }
            other => panic!("must be a compose up: {other:?}"),
        }
        // The abort ALONE names nobody, and that is the difference between the two flags.
        let (_, alone) = p(&["compose", "s.yml", "up", "--abort-on-container-exit"])
            .unwrap_or_else(|e| panic!("{e}"));
        match alone {
            Command::Compose {
                exit_code_from,
                abort_on_exit,
                ..
            } => {
                assert!(abort_on_exit);
                assert_eq!(exit_code_from, None);
            }
            other => panic!("must be a compose up: {other:?}"),
        }
        assert!(
            p(&["compose", "s.yml", "up", "--exit-code-from"]).is_err(),
            "the flag needs a service name"
        );
    }

    /// A `--` AFTER THE SERVICE IS THE SEPARATOR EVERY DOCKER USER TYPES, and it must not become the
    /// program to run.
    ///
    /// FOUND BY TESTING ON A HOST THIS ONE IS NOT, executing: `compose f.yml exec -T web -- echo hi` died with
    /// `execvp failed: No such file or directory` and exit 127, while the same line without `--`
    /// printed `hi`. `docker compose` accepts it and drops it, and `kern exec <box> -- cmd` has
    /// always worked, so the two kern verbs disagreed with each other and with the reference.
    ///
    /// The last case is the one that makes this a rule rather than a strip: only the FIRST token,
    /// and only when it is exactly `--`. A later one belongs to the command.
    #[test]
    fn compose_run_and_exec_drop_a_leading_double_dash_before_the_command() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        let cmd = |args: &[&str]| match p(args).unwrap_or_else(|e| panic!("{e}")).1 {
            Command::Compose { run_cmd, .. } => run_cmd,
            other => panic!("must be a compose command: {other:?}"),
        };
        assert_eq!(
            cmd(&["compose", "s.yml", "exec", "-T", "web", "--", "echo", "hi"]),
            vec!["echo", "hi"]
        );
        assert_eq!(
            cmd(&["compose", "s.yml", "run", "--rm", "web", "--", "echo", "hi"]),
            vec!["echo", "hi"]
        );
        // CONTROL: without the separator nothing changes, or the assertions above would hold for a
        // parser that drops the first token whatever it is.
        assert_eq!(
            cmd(&["compose", "s.yml", "exec", "-T", "web", "echo", "hi"]),
            vec!["echo", "hi"]
        );
        // And a `--` the COMMAND owns survives, at the front of its own argv and in the middle.
        assert_eq!(
            cmd(&["compose", "s.yml", "exec", "web", "sh", "-c", "git log --"]),
            vec!["sh", "-c", "git log --"]
        );
        assert_eq!(
            cmd(&["compose", "s.yml", "exec", "web", "--", "--", "x"]),
            vec!["--", "x"],
            "only the separator goes: a second one is the command's own"
        );
    }

    /// The three `ps` spellings a deploy script reaches for all arrive, and none of them turns on
    /// either of the others.
    #[test]
    fn compose_ps_carries_quiet_services_and_format() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        let got = |args: &[&str]| match p(args).unwrap_or_else(|e| panic!("{e}")).1 {
            Command::Compose {
                ps_quiet,
                ps_services,
                ps_format,
                ..
            } => (ps_quiet, ps_services, ps_format),
            other => panic!("must be a compose command: {other:?}"),
        };
        assert_eq!(got(&["compose", "s.yml", "ps", "-q"]), (true, false, None));
        assert_eq!(
            got(&["compose", "s.yml", "ps", "--services"]),
            (false, true, None)
        );
        assert_eq!(
            got(&["compose", "s.yml", "ps", "--format", "json"]),
            (false, false, Some("json".to_string()))
        );
        // DISCRIMINATOR: a plain `ps` turns none of them on, or the assertions above would pass on
        // a parser that hardcodes all three.
        assert_eq!(got(&["compose", "s.yml", "ps"]), (false, false, None));
        assert!(
            p(&["compose", "s.yml", "ps", "--format"]).is_err(),
            "--format needs its argument"
        );
    }

    /// `--no-deps` reaches `up`, not only `run`.
    ///
    /// It arrived with `run` and was honoured only there, which made `up --no-deps web` a flag that
    /// parsed and changed nothing. MEASURED once it was wired: `up -d web` starts two boxes,
    /// `up -d --no-deps web` starts one.
    #[test]
    fn no_deps_reaches_up_and_not_only_run() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        for verb in ["up", "run"] {
            let (_, cmd) = p(&["compose", "s.yml", verb, "--no-deps", "web"])
                .unwrap_or_else(|e| panic!("`{verb} --no-deps` must parse: {e}"));
            match cmd {
                Command::Compose { no_deps, .. } => {
                    assert!(no_deps, "`{verb} --no-deps` must carry the flag")
                }
                other => panic!("must stay a compose command: {other:?}"),
            }
        }
        // DISCRIMINATOR: without the flag the same command must arrive with it unset.
        let (_, plain) = p(&["compose", "s.yml", "up", "web"]).unwrap_or_else(|e| panic!("{e}"));
        match plain {
            Command::Compose { no_deps, .. } => assert!(!no_deps),
            other => panic!("must stay a compose up: {other:?}"),
        }
    }

    /// `--wait-timeout N` implies `--wait`, because a bound with nothing to bound is a typo that
    /// would otherwise return instantly and look like success.
    #[test]
    fn wait_timeout_implies_wait_and_takes_seconds() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        let (_, cmd) = p(&["compose", "s.yml", "up", "-d", "--wait-timeout", "8"])
            .unwrap_or_else(|e| panic!("{e}"));
        match cmd {
            Command::Compose {
                wait_ready,
                wait_timeout,
                ..
            } => {
                assert!(wait_ready, "a timeout implies the wait");
                assert_eq!(wait_timeout, Some(8));
            }
            other => panic!("must be a compose up: {other:?}"),
        }
        assert!(
            p(&["compose", "s.yml", "up", "--wait-timeout", "soon"]).is_err(),
            "a non-numeric bound is a typo, not a default"
        );
    }

    /// Asserted on the exact typo that produced it, plus the positive control that the correctly
    /// spelled flag still parses, so this cannot pass on a build that refuses everything.
    #[test]
    fn a_mistyped_flag_on_pull_or_push_is_refused_instead_of_eating_the_image() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());

        let err = p(&["pull", "--platfrom", "linux/arm64", "alpine:3.19"])
            .expect_err("a mistyped flag must not parse");
        let msg = format!("{err}");
        assert!(
            msg.contains("--platfrom"),
            "the error must name the flag that was not understood: {msg}"
        );

        let err = p(&["push", "--bogus", "x", "alpine:3.19"]).expect_err("push takes no flags");
        assert!(
            format!("{err}").contains("--bogus"),
            "push must name the unknown flag: {err}"
        );

        // Positive control: the correctly spelled flags still reach the command intact.
        let cmd = p(&[
            "pull",
            "--platform",
            "linux/arm64",
            "--dest",
            "/tmp/x",
            "alpine:3.19",
        ])
        .expect("the documented spelling still parses")
        .1;
        assert!(
            matches!(&cmd, Command::Pull { image, dest: Some(d), platform: Some(pl) }
                     if image == "alpine:3.19" && d == "/tmp/x" && pl == "linux/arm64"),
            "the correct spelling must be unaffected: {cmd:?}"
        );
        let cmd = p(&["push", "myimg", "as", "ghcr.io/me/myimg:1"])
            .expect("push still parses")
            .1;
        assert!(
            matches!(&cmd, Command::Push { local, remote: Some(r) }
                     if local == "myimg" && r == "ghcr.io/me/myimg:1"),
            "push's positional form must be unaffected: {cmd:?}"
        );
    }

    #[test]
    fn platform_without_dest_is_refused_because_the_cache_is_host_arch() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        // The parse itself accepts it; the refusal is the command's, so assert the SHAPE reaches it.
        let cmd = p(&["pull", "alpine", "--platform", "linux/arm64"])
            .expect("parses")
            .1;
        assert!(
            matches!(&cmd, Command::Pull { image, dest: None, platform: Some(pl) }
                     if image == "alpine" && pl == "linux/arm64"),
            "platform without dest must reach the command layer intact: {cmd:?}"
        );
        // With --dest it is the long-standing, supported combination.
        let cmd = p(&[
            "pull",
            "alpine",
            "--platform",
            "linux/arm64",
            "--dest",
            "/tmp/x",
        ])
        .expect("parses")
        .1;
        assert!(
            matches!(&cmd, Command::Pull { dest: Some(d), platform: Some(_), .. } if d == "/tmp/x"),
            "platform WITH dest stays supported: {cmd:?}"
        );
        // And a bare pull carries neither, which is the case that now fills the cache.
        assert!(matches!(
            p(&["pull", "alpine"]).expect("parses").1,
            Command::Pull {
                dest: None,
                platform: None,
                ..
            }
        ));
    }

    #[test]
    fn a_flag_the_config_verbs_do_not_take_is_refused_not_ignored() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        for bad in [
            vec!["config", "list", "--zzzz"],
            vec!["config", "probe", "-x"],
            // `--json` is a READ flag, so it stays refused on the four verbs that change something.
            // Tolerating it there would let `kern config clear --json` look like a query and delete
            // the profiles.
            vec!["config", "setup", "--json"],
            vec!["config", "clear", "--json"],
            vec!["config", "edit", "--json"],
            vec!["config", "probe", "--json"],
        ] {
            assert!(p(&bad).is_err(), "{bad:?} should be refused");
        }
        for good in [
            vec!["config"],
            vec!["config", "list"],
            // `config list --json` was refused until every read verb gained JSON: a script that
            // asked for it got an error, and before that it got the human listing with exit 0.
            vec!["config", "list", "--json"],
            // Bare `config` IS `list`, so the flag has to work in that spelling too, or the reader
            // has to know which of two identical commands takes it.
            vec!["config", "--json"],
            vec!["config", "setup", "--force"],
            vec!["config", "clear", "-y"],
            // `add`/`rm` parse their own flags - the guard must not reach them.
            vec!["config", "add", "vcpu:x", "--cpus", "1"],
            vec!["config", "rm", "vcpu:x"],
        ] {
            assert!(p(&good).is_ok(), "{good:?} should parse");
        }
    }

    #[test]
    fn version_help_and_banner_resolve() {
        assert_eq!(parse(&["--version".into()]).unwrap().1, Command::Version);
        assert_eq!(parse(&["--help".into()]).unwrap().1, Command::Help);
        assert_eq!(parse(&["help".into()]).unwrap().1, Command::Help);
        // Bare `kern` → the short banner, not the full help.
        assert_eq!(parse(&[]).unwrap().1, Command::Banner);
        // `kern <cmd> --help` / `-h` (any command, any position before `--`) → the help FOR THAT
        // COMMAND, NOT an "unknown flag" error. This is the universal `<tool> <cmd> --help` habit.
        //
        // It used to resolve to `Command::Help`, the whole 160-line reference, for every verb. That
        // was better than an error and worse than an answer: six subcommands replied to a question
        // about one verb by printing everything. `HelpFor` carries the verb; `commands::help_for`
        // filters the single reference text and falls back to all of it when a verb has no lines,
        // so nothing became less discoverable.
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
                Command::HelpFor(c[0].to_string()),
                "`kern {}` should show the help for `{}`",
                c.join(" "),
                c[0]
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

    /// A FLAG'S VALUE IS NOT A HELP REQUEST. `--health-cmd-argv` and `--entrypoint` each carry one
    /// element of somebody else's argv, where a leading dash is ordinary.
    ///
    /// MEASURED FIRST, on the real thing: eight of the eleven Supabase self-hosted services died
    /// within 150 ms of starting, every `kern box` printing the box help instead of running,
    /// because `pg_isready -U postgres -h localhost` sends `-h` through as an argument of its own.
    #[test]
    fn an_argv_element_that_looks_like_help_is_not_a_help_request() {
        let argv = |v: &[&str]| -> Vec<String> { v.iter().map(|s| (*s).to_string()).collect() };
        for c in [
            vec!["box", "n", "--image", "i", "--health-cmd-argv", "-h"],
            vec!["box", "n", "--image", "i", "--health-cmd-argv", "--help"],
            vec![
                "box",
                "n",
                "--image",
                "i",
                "--health-cmd-argv",
                "pg_isready",
                "--health-cmd-argv",
                "-h",
                "--health-cmd-argv",
                "localhost",
            ],
            // `--entrypoint` refuses a leading dash on its FIRST occurrence (a typo guard, see its
            // parse arm), so the element that can legitimately look like a flag is a later one.
            vec![
                "box",
                "n",
                "--image",
                "i",
                "--entrypoint",
                "prog",
                "--entrypoint",
                "-h",
            ],
        ] {
            assert!(
                matches!(parse(&argv(&c)).map(|(_, c)| c), Ok(Command::BoxRun { .. })),
                "`kern {}` must RUN, not print help",
                c.join(" ")
            );
        }
        // POSITIVE CONTROL, twice over: skipping a value must not deafen the scan. A `-h` that is
        // NOT a value is still a help request, both after such a flag has taken its own value and
        // before one appears at all.
        for c in [
            vec!["box", "n", "--health-cmd-argv", "true", "-h"],
            vec!["box", "n", "-h", "--health-cmd-argv", "true"],
            vec!["box", "n", "--entrypoint", "sh", "--help"],
        ] {
            assert_eq!(
                parse(&argv(&c)).unwrap().1,
                Command::HelpFor("box".to_string()),
                "`kern {}` asks for help",
                c.join(" ")
            );
        }
        // And the two forms of one check are refused together rather than one being picked.
        let both = argv(&[
            "box",
            "n",
            "--image",
            "i",
            "--health-cmd",
            "true",
            "--health-cmd-argv",
            "true",
        ]);
        assert!(
            matches!(parse(&both), Err(Error::Usage(_))),
            "the shell and exec forms of one check cannot both be given"
        );
    }

    #[test]
    fn box_dispatch_and_plan() {
        // `box <name> --plan` → BoxPlan.
        let plan = parse(&["box".into(), "web".into(), "--plan".into()])
            .unwrap()
            .1;
        assert_eq!(
            plan,
            Command::BoxPlan {
                name: "web".into(),
                profiles: vec![],
                config: None
            }
        );
        // A `--plan` that carries profiles keeps them: the preview resolves the device grants, so
        // dropping them here would show three mounts and stay silent about `/dev/i2c-5`.
        assert_eq!(
            parse(&[
                "box".into(),
                "web".into(),
                "vgpio:sensor".into(),
                "--plan".into()
            ])
            .unwrap()
            .1,
            Command::BoxPlan {
                name: "web".into(),
                profiles: vec!["vgpio:sensor".into()],
                config: None
            }
        );
        // `--config` reaches the preview. Without this the plan resolved profiles against a
        // different kern.toml than the launch and denied one that was declared in the file passed.
        assert_eq!(
            parse(&[
                "box".into(),
                "web".into(),
                "--config".into(),
                "/tmp/k.toml".into(),
                "vcpu:slim".into(),
                "--plan".into()
            ])
            .unwrap()
            .1,
            Command::BoxPlan {
                name: "web".into(),
                profiles: vec!["vcpu:slim".into()],
                config: Some("/tmp/k.toml".into())
            }
        );
        // `box <name>` with no rootfs/image still routes to BoxRun (box_run reports the missing
        // source) - NOT a misleading "not implemented".
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

    /// `--entrypoint` PARSES INTO THE THREE STATES IT HAS, and refuses the fourth.
    ///
    /// Absent, an override, and CLEARED are three different things, which is why the field is an
    /// `Option<Vec<_>>` and not a `Vec<_>`: `--entrypoint ""` means "the image has no entrypoint",
    /// and a bare `Vec` cannot tell that from "the flag was never given".
    #[test]
    fn entrypoint_parses_absent_override_cleared_and_refuses_a_leading_dash() {
        let ep = |args: &[&str]| -> Result<Option<Vec<String>>, Error> {
            let mut v = vec!["box", "b", "--image", "alpine"];
            v.extend_from_slice(args);
            match parse_box(&v)? {
                Command::BoxRun { entrypoint, .. } => Ok(entrypoint),
                _ => Ok(None),
            }
        };

        // Absent: the image's own entrypoint stands.
        assert_eq!(ep(&[]).expect("parses"), None);
        // One occurrence: Docker's form.
        assert_eq!(
            ep(&["--entrypoint", "/bin/sh"]).expect("parses"),
            Some(vec!["/bin/sh".to_string()])
        );
        // Repeated: the exec-form list, in order.
        assert_eq!(
            ep(&["--entrypoint", "/bin/sh", "--entrypoint", "-c"]).expect("parses"),
            Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
            "a later value may start with '-': it is an ARGUMENT to the program named first"
        );
        // Cleared: distinct from absent.
        assert_eq!(ep(&["--entrypoint", ""]).expect("parses"), Some(Vec::new()));

        // A LEADING DASH ON THE FIRST VALUE is a typo, not a program. Without this the value is
        // taken as the executable and the box fails later with `cannot start '--privileged'`, which
        // names the symptom and not the mistake. The `docker` shim already refuses the same shape.
        assert!(
            ep(&["--entrypoint", "--privileged"]).is_err(),
            "the first value must not be a flag"
        );
        // And the flag with nothing after it is refused rather than silently ignored, which would
        // run the image's own entrypoint while the caller believed they had replaced it.
        assert!(ep(&["--entrypoint"]).is_err());
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
        // Malformed values are refused, never silently ignored. THE ERROR CARRIES THE VALUE now:
        // `Error::Usage` holds a `&'static str` and could only print the flag's grammar, which is
        // what a compose user saw when their file wrote a size kern did not parse. `Error::Cli`
        // carries an owned message and gets the same `--help` hint.
        let bad = parse(&["box".into(), "x".into(), "--memory".into(), "nope".into()]);
        match bad {
            Err(Error::Cli(msg)) => {
                assert!(
                    msg.contains("'nope'"),
                    "the message must quote the value: {msg}"
                );
                assert!(
                    msg.contains("mem_limit"),
                    "and say a compose file reaches it: {msg}"
                );
            }
            other => panic!("a malformed --memory must be refused with the value named: {other:?}"),
        }
        // A BARE NUMBER IS BYTES, and a cap of 64 bytes cannot start a box. MEASURED before this
        // refusal existed: `--memory 64` exits 137 in 3 ms on every box, with kern's own OOM message
        // advising a bigger cap - so a reader who writes `128` next gets the identical failure, and the
        // output never mentions the unit. The refusal names it.
        for v in ["64", "4096", "65536", "131071"] {
            match parse(&["box".into(), "x".into(), "--memory".into(), v.into()]) {
                Err(Error::Cli(msg)) => {
                    assert!(msg.contains(v), "the message must quote the value: {msg}");
                    assert!(
                        msg.contains("BARE NUMBER IS BYTES"),
                        "and name the actual mistake: {msg}"
                    );
                    assert!(msg.contains("64m"), "and show the unit it wants: {msg}");
                }
                other => panic!("--memory {v} (bytes) must be refused: {other:?}"),
            }
        }
        // POSITIVE CONTROL, and it is what keeps this from becoming docker's 6 MiB minimum: every cap
        // at or above the floor still parses, including the 384 KiB at which a real shell was measured
        // to run and the bare byte counts a compose file writes.
        for (v, want) in [
            ("131072", 131_072_u64),
            ("393216", 393_216),
            ("384k", 384 * 1024),
            ("268435456", 268_435_456),
            ("512m", 512 * 1024 * 1024),
        ] {
            let cmd = parse(&["box".into(), "x".into(), "--memory".into(), v.into()])
                .map(|p| p.1)
                .unwrap_or_else(|e| panic!("--memory {v} must be accepted: {e:?}"));
            assert!(
                matches!(cmd, Command::BoxRun { memory: Some(m), .. } if m == want),
                "--memory {v} must parse to {want} bytes"
            );
        }
        // And the floor is not applied to sizes that are legitimately small: a 64 KiB tmpfs or
        // shm-size is a size, not a cap, and only a CAP is impossible at that value.
        assert!(parse(&[
            "box".into(),
            "x".into(),
            "--shm-size".into(),
            "65536".into()
        ])
        .is_ok());
        // `--ip` IS REFUSED AT THE BOUNDARY, WITH THE VALUE AND ITS ORIGIN NAMED. The value comes
        // from a compose file's `ipv4_address:` far more often than from a keyboard, so an error
        // that only printed the flag's grammar would be addressed to the wrong person.
        match parse(&[
            "box".into(),
            "x".into(),
            "--ip".into(),
            "172.28.1.999".into(),
        ]) {
            Err(Error::Cli(msg)) => {
                assert!(msg.contains("'172.28.1.999'"), "quote the value: {msg}");
                assert!(
                    msg.contains("ipv4_address"),
                    "name where it comes from: {msg}"
                );
            }
            other => panic!("a malformed --ip must be refused with the value named: {other:?}"),
        }
        // A good one parses, repeats, and de-duplicates: a service on two networks may name the
        // same address twice and the box has no use for it twice.
        let (_, cmd) = parse(&[
            "box".into(),
            "x".into(),
            "--image".into(),
            "alpine".into(),
            "--ip".into(),
            "172.28.1.10".into(),
            "--ip".into(),
            "10.5.0.7".into(),
            "--ip".into(),
            "172.28.1.10".into(),
        ])
        .expect("parses");
        match cmd {
            Command::BoxRun { net_ips, .. } => assert_eq!(
                net_ips,
                vec![
                    "172.28.1.10"
                        .parse::<std::net::Ipv4Addr>()
                        .expect("literal"),
                    "10.5.0.7".parse::<std::net::Ipv4Addr>().expect("literal"),
                ]
            ),
            other => panic!("expected BoxRun, got {other:?}"),
        }
        // `--pod-bridge` IS AN ADDRESS AND A PREFIX, refused at the boundary like every other
        // network value. A box that reached the sandbox with a malformed one would fail where
        // nothing can point at the flag.
        match parse(&[
            "box".into(),
            "x".into(),
            "--pod-bridge".into(),
            "10.89.0.2".into(),
        ]) {
            Err(Error::Cli(msg)) => assert!(msg.contains("10.89.0.2"), "{msg}"),
            other => panic!("an address with no prefix must be refused: {other:?}"),
        }
        for bad in ["10.89.0.2/31", "10.89.0.2/7", "nope/24", "10.89.0.2/x"] {
            assert!(
                matches!(
                    parse(&["box".into(), "x".into(), "--pod-bridge".into(), bad.into()]),
                    Err(Error::Cli(_))
                ),
                "{bad} must be refused"
            );
        }
        let (_, cmd) = parse(&[
            "box".into(),
            "x".into(),
            "--image".into(),
            "alpine".into(),
            "--pod-bridge".into(),
            "10.89.0.2/24".into(),
        ])
        .expect("parses");
        match cmd {
            Command::BoxRun { pod_bridge, .. } => assert_eq!(
                pod_bridge,
                Some(kern_isolation::BridgeAttach {
                    ip: "10.89.0.2".parse().expect("literal"),
                    prefix: 24,
                })
            ),
            other => panic!("expected BoxRun, got {other:?}"),
        }
        // A flag with NO value at all is still the flag's own usage error: there is no value to name.
        assert!(matches!(
            parse(&["box".into(), "x".into(), "--memory".into()]),
            Err(Error::Usage(_))
        ));
        assert!(matches!(
            parse(&["box".into(), "x".into(), "--cpus".into(), "0".into()]),
            Err(Error::Usage(_))
        ));
    }

    #[test]
    fn box_apparmor_name_is_validated_at_the_cli_edge() {
        // The CLI never passes through the SDK bindings, so it enforces the SAME charset here
        // (mirrors `APPARMOR_RE`): a valid name reaches the parsed command trimmed and verbatim.
        let (_, cmd) = parse(&[
            "box".into(),
            "x".into(),
            "--apparmor".into(),
            "  kern-demo.deny_1  ".into(),
        ])
        .unwrap();
        assert!(
            matches!(cmd, Command::BoxRun { apparmor: Some(p), .. } if p == "kern-demo.deny_1"),
            "a valid profile name is accepted, trimmed"
        );

        // The validator on the vectors that matter: letters/digits/`._-` (not leading `-`),
        // 1..=128 bytes. A space/`=`/newline would otherwise reach the registry record's `key=value`
        // line format; an unloadable name would start the box only to fail the transition later.
        for ok in [
            "a".to_string(),
            "_x".into(),
            ".x".into(),
            "K3rn-d.e_m-o".into(),
            "a".repeat(128),
        ] {
            assert!(valid_apparmor_name(&ok), "should accept {ok:?}");
        }
        for bad in [
            "".to_string(),
            "-x".into(),
            "a b".into(),
            "a=b".into(),
            "a\nb".into(),
            "a\tb".into(),
            "a/b".into(),
            "a".repeat(129),
        ] {
            assert!(!valid_apparmor_name(&bad), "should reject {bad:?}");
        }

        // End to end: a bad name is a usage error, never a silently-accepted profile the box would
        // later fail to enter.
        for bad in ["a b", ""] {
            assert!(
                matches!(
                    parse(&["box".into(), "x".into(), "--apparmor".into(), bad.into()]),
                    Err(Error::Usage(_))
                ),
                "parse must reject --apparmor {bad:?}"
            );
        }
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
                pm(0, 8080, 80, false),
                pm(0, 443, 443, false),
                pm(0, 53, 53, true),
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
        // …and TCP + UDP on the SAME host port is fine (the DNS shape): they are separate host ports,
        // so the duplicate check must key on protocol, not just address+port.
        assert!(parse(&[
            "box".into(),
            "x".into(),
            "-p".into(),
            "53:53/tcp".into(),
            "-p".into(),
            "53:53/udp".into(),
        ])
        .is_ok());
        // Same proto twice on one host port is still a duplicate.
        assert!(matches!(
            parse(&[
                "box".into(),
                "x".into(),
                "-p".into(),
                "53:53/udp".into(),
                "-p".into(),
                "53:54/udp".into(),
            ]),
            Err(Error::Usage(_))
        ));
    }

    /// `-t` ALLOCATES A PTY AND `-i` DOES NOT, which is Docker's split and was not kern's.
    ///
    /// The two used to set the same flag, so `-i` reached for a pseudo-terminal. MEASURED against a
    /// running box before the fix: `kern exec -i box cat < file` never returned (killed at 120 s)
    /// and wrote `line1\r\nline2\r\n` plus the echo of its own input - the line discipline adding
    /// carriage returns, echoing, and never seeing the EOF a redirected file cannot send. That is
    /// the exact shape of `docker exec -i <c> psql … < seed.sql`, which is how database seeding is
    /// written everywhere.
    #[test]
    fn t_allocates_a_pty_and_i_only_keeps_stdin() {
        for f in ["-it", "-ti", "-t", "--tty"] {
            let (_, cmd) = parse(&["box".into(), "x".into(), f.to_string()]).unwrap();
            assert!(matches!(cmd, Command::BoxRun { tty: true, .. }), "flag {f}");
            let (_, cmd) = parse(&["exec".into(), "x".into(), f.to_string()]).unwrap();
            assert!(matches!(cmd, Command::Exec { tty: true, .. }), "exec {f}");
        }
        // `-i` IS ACCEPTED AND ALLOCATES NOTHING: stdin is inherited either way, so the flag names
        // what already happens and a redirected file reaches the workload byte for byte.
        for f in ["-i", "--interactive"] {
            let (_, cmd) = parse(&["box".into(), "x".into(), f.to_string()]).unwrap();
            assert!(
                matches!(cmd, Command::BoxRun { tty: false, .. }),
                "box {f} must not allocate a PTY"
            );
            let (_, cmd) = parse(&["exec".into(), "x".into(), f.to_string()]).unwrap();
            assert!(
                matches!(cmd, Command::Exec { tty: false, .. }),
                "exec {f} must not allocate a PTY"
            );
        }
        // `-i -t` written apart is still both, which is what a script that spells them out types.
        let (_, cmd) = parse(&["exec".into(), "x".into(), "-i".into(), "-t".into()]).unwrap();
        assert!(matches!(cmd, Command::Exec { tty: true, .. }));
        // off by default, on both verbs
        let (_, cmd) = parse(&["box".into(), "x".into()]).unwrap();
        assert!(matches!(cmd, Command::BoxRun { tty: false, .. }));
        let (_, cmd) = parse(&["exec".into(), "x".into()]).unwrap();
        assert!(matches!(cmd, Command::Exec { tty: false, .. }));
    }

    /// `--network <name>` IS A POD JOIN, and it used to be a usage error.
    ///
    /// `docker run --rm --network <stack-net> <img> <cmd>` is how a one-off talks to a running stack
    /// (generate a token, seed a database, run a migration), and kern answered
    /// `--network <host|none>`, a usage line naming neither of the two joinable things it has. A
    /// stack brought up by `kern compose` IS a pod, so the name joins it; whether the name exists is
    /// decided at bring-up, where the registry is already being read, and is measured against a live
    /// pod rather than asserted here.
    #[test]
    fn a_network_name_is_carried_as_a_pod_join() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        let (_, cmd) = p(&["box", "x", "--image", "alpine", "--network", "mystack"]).unwrap();
        match cmd {
            Command::BoxRun { pod, share_net, .. } => {
                assert_eq!(pod.as_deref(), Some("mystack"));
                assert!(!share_net, "a named network is not the host's network");
            }
            other => panic!("expected BoxRun, got {other:?}"),
        }
        // `--pod` is the same slot, so the two spellings cannot diverge.
        let (_, cmd) = p(&["box", "x", "--image", "alpine", "--pod", "mystack"]).unwrap();
        assert!(matches!(cmd, Command::BoxRun { pod: Some(ref n), .. } if n == "mystack"));

        // THE TWO WORDS STILL MEAN WHAT THEY MEANT, and `none` especially: a Docker user's isolation
        // request must never fall through to sharing the host's network.
        let (_, cmd) = p(&["box", "x", "--image", "alpine", "--network", "host"]).unwrap();
        assert!(matches!(
            cmd,
            Command::BoxRun {
                share_net: true,
                ..
            }
        ));
        let (_, cmd) = p(&["box", "x", "--image", "alpine", "--network", "none"]).unwrap();
        assert!(matches!(
            cmd,
            Command::BoxRun {
                share_net: false,
                pod: None,
                ..
            }
        ));
        // A FLAG IS NOT A NETWORK NAME: `--network --detach` must be a usage error, not a box that
        // tries to join a pod called `--detach` while `--detach` is silently eaten.
        assert!(p(&["box", "x", "--image", "alpine", "--network", "-d"]).is_err());
        assert!(p(&["box", "x", "--image", "alpine", "--network"]).is_err());
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
        // off by default - nesting stays blocked unless explicitly requested
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
    fn box_require_limits_and_allow_uncapped_parse_default_off() {
        // --require-limits parses, off by default.
        let (_, cmd) = parse(&["box".into(), "x".into(), "--require-limits".into()]).unwrap();
        assert!(matches!(
            cmd,
            Command::BoxRun {
                require_limits: true,
                allow_uncapped: false,
                ..
            }
        ));
        // --allow-uncapped parses, off by default.
        let (_, cmd) = parse(&["box".into(), "x".into(), "--allow-uncapped".into()]).unwrap();
        assert!(matches!(
            cmd,
            Command::BoxRun {
                allow_uncapped: true,
                require_limits: false,
                ..
            }
        ));
        // Neither set on a bare box: current best-effort behaviour is preserved.
        let (_, cmd) = parse(&["box".into(), "x".into()]).unwrap();
        assert!(matches!(
            cmd,
            Command::BoxRun {
                require_limits: false,
                allow_uncapped: false,
                ..
            }
        ));
        // The contradiction (both set, in any flag/env combination) is rejected in `build_spec` on the
        // resolved values, not at parse - see `commands::limit_policy_tests`.
    }

    #[test]
    fn box_security_profile_parses_untrusted_and_rejects_unknown() {
        let (_, cmd) = parse(&[
            "box".into(),
            "x".into(),
            "--security-profile".into(),
            "untrusted".into(),
        ])
        .unwrap();
        assert!(matches!(
            cmd,
            Command::BoxRun {
                security_profile: Some(commands::SecurityProfile::Untrusted),
                ..
            }
        ));
        // None by default: no profile is applied unless asked.
        let (_, cmd) = parse(&["box".into(), "x".into()]).unwrap();
        assert!(matches!(
            cmd,
            Command::BoxRun {
                security_profile: None,
                ..
            }
        ));
        // A closed set: an unknown name is a usage error that names the accepted value.
        let err = parse(&[
            "box".into(),
            "x".into(),
            "--security-profile".into(),
            "paranoid".into(),
        ])
        .unwrap_err();
        assert!(
            matches!(&err, Error::Usage(m) if m.contains("untrusted")),
            "unknown profile must be a usage error naming `untrusted`, got {err:?}"
        );
    }

    #[test]
    fn box_security_profile_untrusted_rejects_cap_add_all() {
        // `--cap-add ALL` negates the profile's cap-drop: a box labelled untrusted that holds every
        // capability is a contradiction, rejected by name (flag-only, so parse is the complete site).
        let err = parse(&[
            "box".into(),
            "x".into(),
            "--security-profile".into(),
            "untrusted".into(),
            "--cap-add".into(),
            "ALL".into(),
        ])
        .unwrap_err();
        assert!(
            matches!(&err, Error::Usage(m) if m.contains("cancels") && m.contains("untrusted")),
            "cap-add ALL under the profile must be a usage error, got {err:?}"
        );
        // Case-insensitive on the cap name.
        assert!(parse(&[
            "box".into(),
            "x".into(),
            "--security-profile".into(),
            "untrusted".into(),
            "--cap-add".into(),
            "all".into(),
        ])
        .is_err());
        // A SPECIFIC `--cap-add` under the profile is fine: it overrides ONE cap, not the whole drop.
        let (_, cmd) = parse(&[
            "box".into(),
            "x".into(),
            "--security-profile".into(),
            "untrusted".into(),
            "--cap-add".into(),
            "NET_BIND_SERVICE".into(),
        ])
        .unwrap();
        assert!(matches!(
            cmd,
            Command::BoxRun {
                security_profile: Some(commands::SecurityProfile::Untrusted),
                ..
            }
        ));
        // `--cap-add ALL` WITHOUT the profile stays valid (no contradiction).
        let ok = parse(&["box".into(), "x".into(), "--cap-add".into(), "ALL".into()]);
        assert!(ok.is_ok());
        // Evasion D1: `CAP_ALL` is NOT the special `ALL` token; it resolves as a capability NAME, which
        // is unknown, so it is rejected downstream in `caps::resolve` (an error either way, no silent
        // cap-add-all). `ALL,NET_ADMIN` is one unknown name, likewise rejected. Neither slips through.
        assert!(parse(&[
            "box".into(),
            "x".into(),
            "--security-profile".into(),
            "untrusted".into(),
            "--cap-add".into(),
            "CAP_ALL".into(),
        ])
        .and_then(|(_, c)| match c {
            Command::BoxRun { cap_add, .. } => crate::caps::resolve(&cap_add, &[]).map(|_| ()),
            _ => Ok(()),
        })
        .is_err());
    }

    #[test]
    fn box_security_profile_untrusted_rejects_privileged() {
        // D8: `--privileged` relaxes the seccomp filter the profile tightens - a contradiction on the
        // same axis, rejected by name like `--cap-add ALL`.
        let err = parse(&[
            "box".into(),
            "x".into(),
            "--security-profile".into(),
            "untrusted".into(),
            "--privileged".into(),
        ])
        .unwrap_err();
        assert!(
            matches!(&err, Error::Usage(m) if m.contains("privileged") && m.contains("contradictory")),
            "privileged under the profile must be a usage error, got {err:?}"
        );
        // `--privileged` alone stays valid.
        assert!(parse(&["box".into(), "x".into(), "--privileged".into()]).is_ok());
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

    /// A `box` flag typed on `run` gets the two-verb explanation, not "put `--` before the command".
    /// The old answer was actively wrong: `kern run --image alpine -- sh` said to move the `--`, so
    /// the obvious next attempt is `kern run -- --image alpine`, which hands `--image` to the
    /// workload. This is the one place the Docker reflex meets kern, and the isolation-shaped flags
    /// (`--read-only`, `--network`, `--cap-drop`) are the ones where a wrong answer lets someone
    /// believe they are sandboxed when `run` never sandboxes anything.
    #[test]
    fn a_box_flag_on_run_explains_the_two_verbs() {
        for flag in [
            "--image",
            "--read-only",
            "--network",
            "--cap-drop",
            "-v",
            "-d",
        ] {
            let err = parse(&["run".into(), (*flag).into(), "x".into()])
                .expect_err("a box flag on run must be refused");
            let msg = err.to_string();
            assert!(
                msg.contains(flag),
                "{flag}: the message must name the flag, got {msg}"
            );
            assert!(
                msg.contains("kern box"),
                "{flag}: must point at `box`, got {msg}"
            );
            assert!(
                !msg.contains("put `--` before"),
                "{flag}: must not repeat the misleading hint, got {msg}"
            );
        }
        // The generic answer still stands for a flag that is nobody's: `run` has no `--frobnicate`
        // and neither does `box`, so there is no verb to redirect to.
        let err = parse(&["run".into(), "--frobnicate".into()]).expect_err("unknown flag");
        assert!(err.to_string().contains("unknown flag"), "{err}");
    }

    /// Every entry in [`BOX_ONLY_FLAGS`] must really be a `box` flag, or the redirect sends someone
    /// to a verb that rejects it too. Asserted against the `box` parser itself rather than a second
    /// hand-kept list, which would be the same fact with two homes.
    #[test]
    fn every_box_only_flag_is_really_a_box_flag() {
        let src = include_str!("cli.rs");
        let start = src.find("fn parse_box").expect("parse_box exists");
        let body = &src[start..];
        for flag in BOX_ONLY_FLAGS {
            assert!(
                body.contains(&format!("\"{flag}\"")),
                "BOX_ONLY_FLAGS names {flag}, which the box parser does not accept"
            );
        }
    }

    // `--mount` is a TRANSLATION into `-v`/`--tmpfs`, so what it must be pinned against is the spec
    // string it produces: if the two ever stopped agreeing, a `--mount` and the `-v` it is
    // documented to equal would resolve differently and nothing else would notice.
    #[test]
    fn mount_spec_translates_to_the_volume_flag() {
        let v = |s: &str| parse_mount_spec(s).unwrap();
        // The two `-v` shapes, by both key spellings Docker accepts.
        assert_eq!(
            v("type=bind,src=/srv/app,dst=/app"),
            MountSpec::Volume("/srv/app:/app".into())
        );
        assert_eq!(
            v("type=bind,source=/srv/app,target=/app"),
            MountSpec::Volume("/srv/app:/app".into())
        );
        assert_eq!(
            v("type=volume,src=data,destination=/data"),
            MountSpec::Volume("data:/data".into())
        );
        // `type=` DEFAULTS to volume, as Docker's does.
        assert_eq!(
            v("src=data,dst=/data"),
            MountSpec::Volume("data:/data".into())
        );
        // Read-only, in all three spellings, and `readonly=false` is an explicit NO.
        for ro in ["ro", "readonly", "readonly=true", "read-only"] {
            assert_eq!(
                v(&format!("type=bind,src=/a,dst=/b,{ro}")),
                MountSpec::Volume("/a:/b:ro".into()),
                "{ro} should be read-only"
            );
        }
        assert_eq!(
            v("type=bind,src=/a,dst=/b,readonly=false"),
            MountSpec::Volume("/a:/b".into()),
            "readonly=false must NOT make the mount read-only"
        );
        // tmpfs is the other flag, and `--tmpfs`'s own `path[:size]` grammar.
        assert_eq!(v("type=tmpfs,dst=/run"), MountSpec::Tmpfs("/run".into()));
        assert_eq!(
            v("type=tmpfs,dst=/run,tmpfs-size=64m"),
            MountSpec::Tmpfs("/run:64m".into())
        );
    }

    // THE REFUSALS, which are the reason this is a parser and not a `split(',')`. Each of these
    // would otherwise start a box whose mounts are not the ones the caller wrote.
    #[test]
    fn mount_spec_refuses_what_it_cannot_translate_faithfully() {
        for bad in [
            // A `bind` whose source is a bare name: `-v data:/app` is a NAMED VOLUME, so this would
            // silently mount an empty auto-created directory instead of the caller's data.
            "type=bind,src=data,dst=/app",
            // And the mirror: a `volume` whose source is a path would become a bind mount.
            "type=volume,src=/srv/data,dst=/data",
            // A typo'd key would parse as a mount with no destination at all.
            "type=bind,src=/a,dest=/b",
            // Missing halves.
            "type=bind,src=/a",
            "type=bind,dst=/b",
            "",
            // A tmpfs has no source, and a size belongs only to a tmpfs.
            "type=tmpfs,src=/a,dst=/b",
            "type=bind,src=/a,dst=/b,tmpfs-size=64m",
            // An unknown type.
            "type=nfs,src=/a,dst=/b",
        ] {
            assert!(
                parse_mount_spec(bad).is_err(),
                "--mount {bad:?} should be refused, not translated"
            );
        }
    }

    // `--name` is the SAME field as the positional name, and the parser must treat it as one: both
    // spellings land in the same place, and a command line carrying both is refused.
    #[test]
    fn name_flag_is_the_positional_name() {
        let named = |args: &[&str]| {
            let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            parse(&owned).map(|(_, c)| match c {
                Command::BoxRun { name, .. } => name,
                other => panic!("expected BoxRun, got {other:?}"),
            })
        };
        assert_eq!(
            named(&["box", "--name", "web", "--image", "alpine", "--", "true"]).unwrap(),
            "web"
        );
        assert_eq!(
            named(&["box", "web", "--image", "alpine", "--", "true"]).unwrap(),
            "web"
        );
        assert!(
            named(&["box", "web", "--name", "api", "--image", "alpine", "--", "true"]).is_err(),
            "the positional name and --name are one field; both is a contradiction"
        );
    }

    // `image <sub>` is a REWRITE onto the verb kern already has, so what must hold is that it
    // reaches the SAME command the direct spelling reaches. If the two ever parsed differently,
    // there would be two grammars for one operation and only one of them under test.
    #[test]
    fn image_group_rewrites_onto_the_existing_verbs() {
        let cmd = |args: &[&str]| {
            let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            parse(&owned).map(|(_, c)| format!("{c:?}"))
        };
        for (grouped, direct) in [
            (
                vec!["image", "inspect", "alpine"],
                vec!["inspect", "alpine"],
            ),
            (vec!["image", "ls", "--json"], vec!["images", "--json"]),
            (vec!["image", "rm", "alpine"], vec!["rmi", "alpine"]),
            (vec!["image", "pull", "alpine"], vec!["pull", "alpine"]),
            (vec!["image", "tag", "a", "b"], vec!["tag", "a", "b"]),
        ] {
            assert_eq!(
                cmd(&grouped).unwrap(),
                cmd(&direct).unwrap(),
                "`kern {}` must reach the same command as `kern {}`",
                grouped.join(" "),
                direct.join(" ")
            );
        }
        // `image prune` is NOT aliased onto `gc --images`: Docker prunes DANGLING images by
        // default and `gc --images` clears what no box references, which is a wider sweep. On a
        // verb whose whole risk is deleting too much, the nearest thing is not the same thing.
        assert!(cmd(&["image", "prune"]).is_err());
        assert!(cmd(&["image", "frobnicate"]).is_err());
        assert!(cmd(&["image"]).is_err());
    }

    // `--rm` must reach the command as a FACT, because everything it does happens far from here:
    // the foreground sweep and the supervisor's skipped write both read this one field.
    #[test]
    fn rm_flag_reaches_the_command() {
        let rm_of = |args: &[&str]| {
            let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            match parse(&owned).map(|(_, c)| c) {
                Ok(Command::BoxRun { rm, .. }) => rm,
                other => panic!("expected BoxRun, got {other:?}"),
            }
        };
        assert!(rm_of(&[
            "box", "w", "--rm", "--image", "alpine", "--", "true"
        ]));
        assert!(rm_of(&[
            "box", "w", "-d", "--rm", "--image", "alpine", "--", "true"
        ]));
        assert!(!rm_of(&["box", "w", "--image", "alpine", "--", "true"]));
    }

    // `network inspect` carries its name and its two output knobs. `-f` and `--format` are the same
    // field, as they are on `inspect`.
    #[test]
    fn network_inspect_parses_its_knobs() {
        let cmd = |args: &[&str]| {
            let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            parse(&owned).map(|(_, c)| c)
        };
        assert!(matches!(
            cmd(&["network", "inspect", "proxy"]),
            Ok(Command::NetworkInspect { ref name, json: false, format: None }) if name == "proxy"
        ));
        assert!(matches!(
            cmd(&["network", "inspect", "proxy", "--json"]),
            Ok(Command::NetworkInspect { json: true, .. })
        ));
        for spelling in [["--format"], ["-f"]] {
            assert!(
                matches!(
                    cmd(&["network", "inspect", "proxy", spelling[0], "{{.Name}}"]),
                    Ok(Command::NetworkInspect { format: Some(ref f), .. }) if f == "{{.Name}}"
                ),
                "{} must carry the template",
                spelling[0]
            );
        }
        // A network is named, never defaulted: `network inspect` with nothing to inspect is a
        // usage error and not an inspection of some implicit network.
        assert!(cmd(&["network", "inspect"]).is_err());
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
        // tokens, dangling/reversed ranges are all refused at the parse boundary - so a typo can't
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
                json: false,
                format: None
            }
        );
        assert_eq!(
            parse(&["inspect".into(), "--json".into(), "web".into()])
                .unwrap()
                .1,
            Command::Inspect {
                name: "web".into(),
                json: true,
                format: None
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

    /// `bench` was the one verb that neither refused an unknown flag nor carried `--bind-rootfs`
    /// through: it took the flag, dropped it, and printed an overlay number under a header naming
    /// the run the user asked for. On the Arduino UNO Q the overlay mount alone is 22 ms against
    /// 0.1 ms on x86, so the two paths are not close and the silence was worth ~20 ms of wrong
    /// answer. Asserted on the PARSED command rather than on the process output, because the old
    /// code also exited 0 for this invocation: only the parsed value distinguishes "accepted and
    /// honoured" from "accepted and discarded", which is the whole defect.
    #[test]
    fn bench_carries_bind_rootfs_and_refuses_unknown_flags() {
        let cmd = parse(&[
            "bench".into(),
            "--rootfs".into(),
            "/x".into(),
            "--bind-rootfs".into(),
        ])
        .unwrap()
        .1;
        assert_eq!(
            cmd,
            Command::Bench {
                rootfs: Some("/x".into()),
                image: None,
                bind_rootfs: true,
                count: 20,
            }
        );

        // Absent means absent: the default must not quietly become the bind path either.
        let cmd = parse(&["bench".into(), "--rootfs".into(), "/x".into()])
            .unwrap()
            .1;
        assert!(matches!(
            cmd,
            Command::Bench {
                bind_rootfs: false,
                ..
            }
        ));

        // And a typo is refused rather than ignored, the rule the other verbs already follow.
        assert!(matches!(
            parse(&[
                "bench".into(),
                "--rootfs".into(),
                "/x".into(),
                "--bnid-rootfs".into()
            ]),
            Err(Error::Usage(_)) | Err(Error::Cli(_))
        ));
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

    /// A command typed WITHOUT the `--` is the command, not silence.
    ///
    /// It used to be dropped: `kern exec box echo hi` parsed the words, discarded them, and the empty
    /// command then defaulted to an interactive shell - so the line printed nothing, exited 0, and
    /// read exactly like a command that had run and produced no output. Measured that way. This is the
    /// assertion that keeps the drop from coming back, and it covers the part that makes the feature
    /// usable rather than merely present: everything after the first word goes to the COMMAND, flags
    /// included, so `ls -la` reaches `ls` instead of failing on an unknown kern flag.
    #[test]
    fn exec_takes_the_command_with_or_without_the_separator() {
        let cases: [(&[&str], &[&str]); 5] = [
            (&["exec", "svc", "echo", "hi"], &["echo", "hi"]),
            (&["exec", "svc", "--", "echo", "hi"], &["echo", "hi"]),
            (&["exec", "svc", "ls", "-la"], &["ls", "-la"]),
            (
                &["exec", "svc", "-it", "sh", "-c", "id"],
                &["sh", "-c", "id"],
            ),
            (&["exec", "svc"], &[]), // no command at all is still the interactive default
        ];
        for (argv, want) in cases {
            let args: Vec<String> = argv.iter().map(|s| (*s).to_string()).collect();
            match parse(&args).unwrap().1 {
                Command::Exec { name, command, .. } => {
                    assert_eq!(name, "svc", "{argv:?}");
                    assert_eq!(command, want, "{argv:?}");
                }
                other => panic!("expected Exec for {argv:?}, got {other:?}"),
            }
        }
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

#[cfg(test)]
mod no_verb_swallows_a_flag_it_does_not_take {
    use super::*;

    fn parse_v(argv: &[&str]) -> Result<(GlobalOpts, Command), Error> {
        parse(&argv.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn a_typo_in_a_format_flag_is_refused_not_ignored() {
        // The shape that made this worth fixing: `--jsn` printed the human table and exited 0, so a
        // script that asked for JSON got prose with no way to notice.
        for argv in [
            vec!["ps", "--jsn"],
            vec!["images", "--jsonn"],
            vec!["stats", "--jso"],
            vec!["gc", "--image"],
            vec!["history", "--count", "5"],
            vec!["doctor", "--json"],
            vec!["info", "--verbose"],
            vec!["probe", "--all"],
            vec!["prune", "-f"],
            vec!["recover", "--dry-run"],
            vec!["top", "--json"],
            vec!["validate", "--strict"],
            vec!["examples", "--toml"],
        ] {
            let r = parse_v(&argv);
            assert!(
                matches!(r, Err(Error::Cli(_))),
                "{argv:?} must be refused, got {r:?}"
            );
        }
    }

    #[test]
    fn every_flag_the_help_advertises_still_parses() {
        // The other half: a refusal that also refuses the real flags would be worse than the defect.
        for argv in [
            vec!["ps", "--json"],
            vec!["ps", "-q"],
            vec!["ps", "--quiet"],
            vec!["ps", "--filter", "name=x"],
            vec!["ps", "--format", "{{.Name}}"],
            vec!["images", "--json"],
            vec!["stats", "--json"],
            vec!["stats", "mybox"],
            vec!["history", "-n", "5"],
            // NOT `-n5`: the attached form was accepted by the flag check and then ignored by the
            // parser (`history -n 3` prints 3 rows, `history -n3` printed all of them). Asserting it
            // "must parse" was asserting that a silently-ignored flag is fine, which is the defect
            // this module exists to refuse. `-n 5` is the documented form and the one that works.
            vec!["gc", "--images"],
            vec!["validate", "/tmp/kern.toml"],
            vec!["doctor"],
            vec!["examples"],
        ] {
            let r = parse_v(&argv);
            assert!(r.is_ok(), "{argv:?} must still parse, got {r:?}");
        }
    }

    #[test]
    fn the_refusal_names_the_verb_and_lists_the_real_flags() {
        // The message must NAME the verb and the offending flag, and must NOT enumerate the allowed
        // list. That list is a hand-kept duplicate of what the parser accepts; printing it states, to
        // the user, as a fact, what the verb takes - and if it ever omits a spelling the parser
        // honours, the message does not merely refuse it, it asserts the verb has no such flag.
        // `--help` is generated from the parser and cannot drift. This test used to assert the
        // OPPOSITE (that the message listed --json, -q, --filter, --format), which enshrined the
        // defect: it would have passed against a message that lied.
        let Err(Error::Cli(msg)) = parse_v(&["ps", "--nope"]) else {
            panic!("ps --nope was not refused");
        };
        assert!(msg.starts_with("ps:"), "does not name the verb: {msg}");
        assert!(
            msg.contains("--nope"),
            "does not name the offending flag: {msg}"
        );
        assert!(
            msg.contains("--help"),
            "does not point at the one source that cannot drift: {msg}"
        );
        for f in ["--json", "-q", "--filter", "--format"] {
            assert!(
                !msg.contains(f),
                "the message enumerates {f} from the hand-kept list: {msg}"
            );
        }
        let Err(Error::Cli(msg)) = parse_v(&["examples", "--nope"]) else {
            panic!("examples --nope was not refused");
        };
        assert!(
            msg.contains("--help"),
            "the no-flag verb must point at --help too: {msg}"
        );
    }
}
