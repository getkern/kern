//! The `kern compose` file parser - `docker-compose.yml` (YAML-lite, in the private `yaml` module) and the native
//! kern TOML subset - both lowered to a `Vec<`[`ComposeBox`]`>`. This crate is **pure parsing**: it
//! is CLI-free (no `std::process`, no filesystem) so it can be fuzzed in isolation
//! (`fuzz/compose_yaml`) and reused by an SDK. The orchestration that shells out to `kern box`
//! (build/up/down, dependency waits, GC) lives in the CLI's `commands/` module, not here.
//!
//! The TOML side parses a small subset (no external crate): `[box.NAME]` tables whose keys
//! **mirror the `kern box` CLI** one-to-one (see `docs/CONFIG.md` for the frozen schema). Boxes are
//! started detached in dependency order (`depends_on`), so `kern compose up.toml` brings up a stack
//! and `kern ps` shows it. The parser is intentionally strict and reports the offending line.
//!
//! **Mirror-CLI rule (frozen).** A scalar key is a quoted string carrying the exact CLI argument
//! (`memory = "512m"`, `cpus = "1.5"`, `cpuset = "0-3"`); a repeatable flag is an array of those
//! same strings (`volumes = ["src:dst:ro"]`); a switch is a TOML bool (`read_only = true`). Because
//! `compose` shells out to `kern box`, each value is validated by the very same parser the CLI uses,
//! the TOML surface can never drift from the flag surface. The same `[box.NAME]` table is the
//! unit a future `--profile` will reuse, which is why the key names are frozen now.

use std::collections::{HashMap, HashSet, VecDeque};

mod yaml;

/// A resolved compose `build:` directive. `context` is a path RELATIVE to the compose file's dir (the
/// caller confines it beneath that dir before use - traversal guard). `dockerfile` is relative to the
/// context. `args` are the `--build-arg K=V` pairs (already `${VAR}`-interpolated).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BuildDirective {
    pub context: String,
    pub dockerfile: Option<String>,
    pub args: Vec<String>,
}

/// The resource-profile kinds a compose file may name.
///
/// The kind → field pairing is [`ComposeBox::profile_list`], not this array: `profile_tokens` walks
/// these kinds and asks that function for each list, and the YAML reader accepts `x-kern-<kind>` for
/// whatever it resolves. A test asserts the two agree, so a kind added here without its field is a
/// failing test rather than a key that parses and does nothing.
///
/// `vgpu` is deliberately ABSENT rather than listed-and-dead: `kern_cli::config::classify` does not
/// know a `vgpu:` token in this build, so the CLI would answer `unexpected argument` on a token this
/// crate had happily built. [`ABSENT_PROFILE_KINDS`] carries it instead, so a file written for a
/// build that has it is told exactly that rather than being told it looks like a typo.
pub const PROFILE_KINDS: [&str; 3] = ["vcpu", "vdisk", "vgpio"];

/// Profile kinds that are real elsewhere and are NOT in this build - the difference between "you
/// mistyped a key" and "this key is for a build kern does not have here", which are different
/// problems and deserve different sentences.
pub const ABSENT_PROFILE_KINDS: [&str; 1] = ["vgpu"];

/// One service in a compose file. Most fields mirror a `kern box` flag (`None`/empty/`false` =
/// "flag absent"); `name`/`command`/`depends_on` are structural - `depends_on` is compose-only, and
/// `push_box_flags` deliberately skips all three. Frozen key ↔ flag map (non-obvious names):
/// `swap_max`→`--memory-swap-max`, `cpuset`→`--cpuset-cpus`, `net`→`--net`, `ssh`→`--ssh`,
/// `user`→`--user`, `volumes`→`-v`, `env`→`-e`, `ports`→`-p`, `secrets`→`--secret`; the rest share
/// the flag's long name (`pids_limit`, `io_weight`, `nice`, `timeout`, `hostname`, `tun`, `tmpfs`,
/// `cap_add`, `cap_drop`, `env_file`, `health_retries`/`_start_period`/`_timeout`/`_action`).
#[derive(Default, Debug)]
pub struct ComposeBox {
    pub name: String,
    /// Docker's `container_name:`. When set, `kern compose` names the box this EXACTLY (not
    /// `<project>-<service>`), so `docker exec <container_name>` ports to `kern exec <container_name>`
    /// verbatim. The service name still resolves inside the pod (kept as a DNS alias), so peers reach
    /// it by the compose-file name regardless. `None` = the default `<project>-<service>` name.
    pub container_name: Option<String>,
    /// The name this service has IN THE FILE, kept after `name` is rewritten to the box name.
    ///
    /// WHY THE STRUCT HAS TO CARRY IT. `kern compose` rewrites `name` to the box name - the
    /// `container_name` when one is set, else `<project>-<service>` - and the service name was
    /// simply gone after that. `kern compose … config` then printed the box name while its own
    /// comment said it "prints service names as written", and a field report read that output,
    /// concluded kern had replaced the service hostname, and deleted four `container_name` keys
    /// from a working file to fix a problem that did not exist. Peers resolve by service name
    /// either way: the alias is registered a few lines above the rewrite.
    ///
    /// Reconstructing it from `net_aliases` was the alternative and is worse: aliases are a list a
    /// user also writes into, so the recovery would be a guess. Empty on a box that never went
    /// through that rewrite, in which case `name` is still the service name.
    pub service: String,
    pub image: Option<String>,
    pub rootfs: Option<String>,
    pub command: Vec<String>,
    /// Compose's `entrypoint:`, forwarded as `--entrypoint` rather than folded into `command`.
    ///
    /// `None` = not set. `Some(list)` REPLACES the image's `ENTRYPOINT` and discards its `CMD`, per
    /// Docker. `Some(empty)` is `entrypoint: []`, which clears the entrypoint.
    ///
    /// IT USED TO BE FOLDED IN: `b.command = entrypoint ++ command`, which the box then prepended
    /// the image's own entrypoint to - `IMAGE_ENTRYPOINT ++ override ++ args`. That composes
    /// correctly only for an image with no entrypoint, and an image with one is exactly when a
    /// compose file writes `entrypoint:`. The same defect lived in the `docker` shim, from the same
    /// cause: neither could perform a replacement from outside the box.
    pub entrypoint: Option<Vec<String>>,
    pub depends_on: Vec<String>,
    /// Dependencies this box waits to become HEALTHY before it starts (Docker's
    /// `condition: service_healthy`). Each named box must declare `health_cmd`. A superset relation
    /// with `depends_on` is NOT required - a `depends_healthy` entry implies the ordering edge too
    /// (see `all_deps`), so you don't have to repeat the name in `depends_on`.
    pub depends_healthy: Vec<String>,
    /// Dependencies this box waits to RUN TO SUCCESSFUL COMPLETION (exit 0) before it starts
    /// (Docker's `condition: service_completed_successfully`) - the init-container / migration-job
    /// pattern. Implies the ordering edge, like `depends_healthy`.
    pub depends_completed: Vec<String>,
    /// A compose `build:` directive resolved to `(context_dir, dockerfile_opt, build_args)`. When set,
    /// `kern compose` builds this image via `kern build` before starting the box. `context`/`dockerfile`
    /// are CONFINED under the compose file's directory (traversal guard); `build_args` are `${VAR}`-
    /// interpolated like `environment`. Set only by the YAML parser (TOML compose has no `build:`).
    pub build: Option<BuildDirective>,
    pub workdir: Option<String>,
    pub memory: Option<String>,
    pub cpus: Option<String>,
    pub cpuset: Option<String>,
    pub swap_max: Option<String>,
    pub pids_limit: Option<String>,
    pub io_weight: Option<String>,
    pub nice: Option<String>,
    pub timeout: Option<String>,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub ssh: Option<String>,
    pub ssh_key: Option<String>,
    pub health_cmd: Option<String>,
    pub health_interval: Option<i64>,
    pub health_retries: Option<String>,
    pub health_start_period: Option<String>,
    pub health_timeout: Option<String>,
    pub health_action: Option<String>,
    pub read_only: bool,
    /// Compose `init: true` → `--init`: a minimal reaping PID 1 in the box, so a service that
    /// forks (nginx, supervisord, any `sh -c` wrapper) doesn't accumulate zombies.
    pub init: bool,
    pub net: bool,
    pub uid_range: bool,
    /// Set when the compose file wrote `uid_range = false` explicitly, so the per-image default
    /// (turn it ON for OCI images) does NOT override a deliberate opt-out.
    pub uid_range_explicit_false: bool,
    pub bind_rootfs: bool,
    pub restart: bool,
    /// Compose `restart: always`/`unless-stopped` → `--restart always`. kern honours it on a pod
    /// member in-process for the stack's lifetime (restart on ANY exit), not degraded to on-failure.
    pub restart_always: bool,
    pub tun: bool,
    pub volumes: Vec<String>,
    pub env: Vec<String>,
    pub env_file: Vec<String>,
    pub ports: Vec<String>,
    /// `port: 3000` - the port this service LISTENS on inside the pod, declared rather than inferred.
    ///
    /// The stack shares one network namespace, so two services cannot both bind the same container
    /// port. kern already refuses that, but only for services that PUBLISH: the conflict was derived
    /// from `ports:` mappings, so an internal-only service (reached by name, publishing nothing) was
    /// invisible to the check and collided at run time with `EADDRINUSE` instead. Declaring it makes
    /// the whole stack visible to the preflight, and gives the user the way out that Docker solves
    /// with separate networks: give each service a different internal port.
    ///
    /// TCP by construction: every framework port this exists for is a TCP listener.
    pub port: Option<u16>,
    /// Docker's `expose:` - the ports a service listens on, DOCUMENTED rather than published. It is
    /// the Compose-native spelling of what `port:` declares, so kern honours it for the same reason:
    /// it is a claim on the pod's single network namespace and belongs in the collision preflight.
    ///
    /// It differs from `port:` in two ways that are Docker's, not ours. It is a LIST (a service may
    /// listen on several), and it sets no environment variable: `expose` documents, `port` also
    /// hands the number to the service as `PORT`. `(number, is_udp)` because Docker's `"53/udp"` form
    /// is a different socket from `"53/tcp"` and the two do not collide.
    pub expose: Vec<(u16, bool)>,
    pub secrets: Vec<String>,
    pub tmpfs: Vec<String>,
    /// Compose `extra_hosts:` → one `--add-host` per entry (`name:ip`). Docker also accepts the
    /// `name=ip` spelling and the long mapping form; both are normalised to `name:ip` by the parser.
    pub add_host: Vec<String>,
    /// Compose `ulimits:` → one `--ulimit NAME=SOFT:HARD` per entry. Both Docker forms are accepted:
    /// the scalar (`nofile: 1024`, soft == hard) and the mapping (`nofile: {soft: N, hard: M}`).
    pub ulimits: Vec<String>,
    /// Compose `labels:` → one `--label k=v` per entry (mapping `k: v` or `k=v` list form).
    pub labels: Vec<String>,
    /// Compose `restart: "on-failure:N"` → `--restart-max N` (retry cap).
    pub restart_max: Option<String>,
    /// Compose `stop_signal:` → `--stop-signal` (the signal sent before the SIGKILL).
    pub stop_signal: Option<String>,
    /// Compose `stop_grace_period:` → `--stop-timeout` (seconds; Docker's duration form is parsed).
    pub stop_grace_period: Option<String>,
    /// Compose `sysctls:` → one `--sysctl KEY=VALUE` per entry (mapping or `KEY=VALUE` list form).
    pub sysctls: Vec<String>,
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
    /// Compose `profiles: [...]`. A service with a non-empty profile list is INACTIVE unless one of
    /// its profiles is enabled (via `COMPOSE_PROFILES`), exactly like Docker: a plain `up` starts only
    /// the profile-less services. Empty = always active. `parse` drops inactive services from the
    /// returned set (with a warning) so a profiled service can never be started by accident.
    pub profiles: Vec<String>,
    /// `--config <file>`: the file that DEFINES the named `[[vcpu]]`/`[[vdisk]]`/`[[vgpio]]` profiles
    /// this box attaches. Without it kern uses its usual config discovery, so a stack that ships its
    /// own profiles next to itself names the file here and stops depending on the caller's `$HOME`.
    pub config: Option<String>,
    /// Named virtual-CPU profiles (`[[vcpu]] name = "db"` → the `vcpu:db` token `kern box` takes
    /// positionally). A stack file could express the raw caps (`cpus`, `cpuset`, `memory`, `nice`)
    /// but not a PROFILE, so the one thing kern has that the engines do not - reuse a named slice
    /// across boxes - stopped at the CLI and never reached the file where per-service sizing is
    /// written. The prefix is optional in the value: `vcpu = "db"` and `vcpu = "vcpu:db"` are the
    /// same token, because a reader who writes the prefix means the profile they can see in the
    /// config, and refusing it would be pedantry.
    pub vcpu: Vec<String>,
    /// Named virtual-disk profiles (`[[vdisk]] name = "dbdata"` → `vdisk:dbdata`). A list: a box can
    /// mount more than one, each at `/vdisk/<name>` with its own size cap.
    pub vdisk: Vec<String>,
    /// Named GPIO/device profiles (`[[vgpio]] name = "leds"` → `vgpio:leds`).
    pub vgpio: Vec<String>,
    /// `--security-profile <untrusted>`: the opt-in hardening bundle (seccomp allowlist +
    /// `--cap-drop ALL` + `--read-only`). Compose has no way to say "this code is not trusted", and
    /// the three flags it would take instead are easy to get half-right; naming the bundle is the
    /// whole point of having one.
    pub security_profile: Option<String>,
    /// Network aliases from a service's `networks.<net>.aliases` - extra names the service is reachable
    /// by inside the stack pod (Docker gives each service DNS for its aliases). `kern compose` adds
    /// each to the pod's shared `/etc/hosts` (→ `127.0.0.1`), so a peer that connects to an alias
    /// resolves it exactly like the service name. Empty for the common (no-alias) case.
    pub net_aliases: Vec<String>,
}

impl ComposeBox {
    /// The `PORT=<n>` pair kern adds for a declared `port`, or `None` when there is nothing to add.
    ///
    /// `PORT` is the only variable injected, and deliberately so. It is the one convention shared
    /// across the ecosystem (Node, Rails, Heroku-style buildpacks, Cloud Run) rather than one
    /// framework's private spelling, so injecting it is a single well-understood act instead of a
    /// growing table of guesses. Two entries proposed for such a table did not survive checking:
    /// `GUNICORN_CMD_ARGS` is not a port at all but a CLI argument string (`--bind 0.0.0.0:3000`),
    /// and `RAILS_PORT` is not a documented Rails variable (Rails reads `PORT`). A per-framework
    /// table therefore needs each entry MEASURED against its real image before it can be believed.
    ///
    /// kern's responsibility ends at delivering the variable: whether an image reads it is the
    /// image's business, and an image that ignores it keeps its own default port. That is why an
    /// explicit `PORT` in `environment:` always wins - it is also the opt-out for anyone who passes
    /// the port some other way (a flag in `command`, a config file).
    pub fn port_env(&self) -> Option<String> {
        let n = self.port?;
        // The user's own value is authoritative. Comparing on the `PORT=` prefix (not equality)
        // catches `PORT=8080` as well as an empty `PORT=`, which is still a deliberate statement.
        if stated_port(&self.env).is_some() {
            return None;
        }
        Some(format!("{PORT_VAR}={n}"))
    }

    /// Whether this box ends up with a subordinate uid RANGE: because it asked, or because it is an
    /// OCI IMAGE box, since official images (postgres/redis/nginx/mariadb/grafana) drop privilege in
    /// their entrypoint to a service uid and need the range to do it (the 0.6 official-image fix). A
    /// `rootfs` box is the user's own tree and keeps the single-uid map (faster, more isolated); an
    /// explicit `uid_range = false` is respected, only the ABSENT default flips per image.
    ///
    /// This is the ONE statement of that rule on the compose side. `push_box_flags` deliberately does
    /// not restate it (it forwards intent and lets `kern box` apply the default); the pod holder needs
    /// it here, because a member setns's into the holder's user ns and writes no map of its own, so
    /// the decision must be made BEFORE the holder unshares.
    pub fn wants_uid_range(&self) -> bool {
        self.uid_range || (self.image.is_some() && !self.uid_range_explicit_false)
    }

    // Every field's "flag absent" value is its type's Default (None/empty/false), so `new` only sets
    // the name - a newly-added mirror-CLI field can never be silently left out of construction.
    fn new(name: String) -> Self {
        ComposeBox {
            name,
            ..Default::default()
        }
    }

    /// Every box this one depends on, for ordering purposes: the union of `depends_on` (start-only),
    /// `depends_healthy`, and `depends_completed`. A conditional dependency implies the ordering edge
    /// (you can't wait for something that hasn't been asked to start), so callers building the
    /// start-order graph use THIS, not `depends_on` alone. Order-stable and de-duplicated.
    pub fn all_deps(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for d in self
            .depends_on
            .iter()
            .chain(&self.depends_healthy)
            .chain(&self.depends_completed)
        {
            if !out.contains(&d.as_str()) {
                out.push(d.as_str());
            }
        }
        out
    }

    /// Append this box's fields to a `kern box <name>` command line as their mirror flags, in a
    /// stable order. The detached `-d` and the trailing `-- command` are added by the caller.
    /// The name this service has IN THE FILE.
    ///
    /// `name` is the BOX name once `resolve_box_names` has run - `<project>-<service>`, or a
    /// `container_name` verbatim - and that is the right name for the runtime and the wrong one for
    /// anything a reader compares against their own file. Every message that quotes a service, and
    /// `compose … config`, goes through here.
    ///
    /// ONE DEFINITION, because there were three. The same three-line fallback was written into the
    /// pod-conflict check, the host-port check and the config printer, one per fix, and a fourth
    /// caller would have written a fourth. Borrowed, so quoting a service name in an error costs no
    /// allocation.
    ///
    /// `service` is empty only for a box that never went through the rename, where `name` IS the
    /// service name.
    pub fn service_name(&self) -> &str {
        if self.service.is_empty() {
            &self.name
        } else {
            &self.service
        }
    }

    pub fn push_box_flags(&self, cmd: &mut std::process::Command) {
        if let Some(v) = &self.config {
            cmd.arg("--config").arg(v);
        }
        // Position in argv carries no meaning here, and an earlier draft of this comment claimed it
        // did. Measured: `kern box` assigns each flag in one pass and validates the combinations after
        // it, so `--security-profile untrusted --cap-add ALL` and the reverse produce the identical
        // refusal. The flag sits here because the field does, and for no other reason.
        if let Some(v) = &self.security_profile {
            cmd.arg("--security-profile").arg(v);
        }
        if let Some(v) = &self.image {
            cmd.arg("--image").arg(v);
        }
        if let Some(v) = &self.rootfs {
            cmd.arg("--rootfs").arg(v);
        }
        if let Some(v) = &self.workdir {
            cmd.arg("--workdir").arg(v);
        }
        // One `--entrypoint` per argv element; the flag is repeatable exactly so an exec-form list
        // needs no quoting convention. An EMPTY list still emits one empty occurrence, which is how
        // `entrypoint: []` reaches the box as "clear it" rather than as "not set".
        if let Some(ep) = &self.entrypoint {
            if ep.is_empty() {
                cmd.arg("--entrypoint").arg("");
            } else {
                for a in ep {
                    cmd.arg("--entrypoint").arg(a);
                }
            }
        }
        if let Some(v) = &self.memory {
            cmd.arg("--memory").arg(v);
        }
        if let Some(v) = &self.cpus {
            cmd.arg("--cpus").arg(v);
        }
        if let Some(v) = &self.cpuset {
            cmd.arg("--cpuset-cpus").arg(v);
        }
        if let Some(v) = &self.swap_max {
            cmd.arg("--memory-swap-max").arg(v);
        }
        if let Some(v) = &self.pids_limit {
            cmd.arg("--pids-limit").arg(v);
        }
        if let Some(v) = &self.io_weight {
            cmd.arg("--io-weight").arg(v);
        }
        if let Some(v) = &self.nice {
            cmd.arg("--nice").arg(v);
        }
        if let Some(v) = &self.timeout {
            cmd.arg("--timeout").arg(v);
        }
        if let Some(v) = &self.hostname {
            cmd.arg("--hostname").arg(v);
        }
        if let Some(v) = &self.user {
            cmd.arg("--user").arg(v);
        }
        if let Some(v) = &self.ssh {
            cmd.arg("--ssh").arg(v);
        }
        if let Some(v) = &self.ssh_key {
            cmd.arg("--ssh-key").arg(v);
        }
        if let Some(v) = &self.health_cmd {
            cmd.arg("--health-cmd").arg(v);
        }
        if let Some(n) = self.health_interval {
            cmd.arg("--health-interval").arg(n.to_string());
        }
        if let Some(v) = &self.health_retries {
            cmd.arg("--health-retries").arg(v);
        }
        if let Some(v) = &self.health_start_period {
            cmd.arg("--health-start-period").arg(v);
        }
        if let Some(v) = &self.health_timeout {
            cmd.arg("--health-timeout").arg(v);
        }
        if let Some(v) = &self.health_action {
            cmd.arg("--health-action").arg(v);
        }
        if self.read_only {
            cmd.arg("--read-only");
        }
        if self.init {
            cmd.arg("--init");
        }
        if self.net {
            cmd.arg("--net");
        }
        // Forward the box's STATED intent only, never the per-image default: `kern box` applies that
        // default itself for any `--image` box (see `wants_uid_range`), so re-deriving it here would
        // put the same rule in two places AND erase the difference between "the file asked" and "kern
        // decided", which is what lets an unavailable range warn only when someone actually asked.
        // A deliberate `uid_range = false` still has to travel, to suppress that default downstream.
        if self.uid_range {
            cmd.arg("--uid-range");
        } else if self.uid_range_explicit_false {
            cmd.arg("--no-uid-range");
        }
        if self.bind_rootfs {
            cmd.arg("--bind-rootfs");
        }
        if self.restart_always {
            cmd.arg("--restart").arg("always");
        } else if self.restart {
            cmd.arg("--restart");
        }
        if self.tun {
            cmd.arg("--tun");
        }
        for v in &self.add_host {
            cmd.arg("--add-host").arg(v);
        }
        for v in &self.ulimits {
            cmd.arg("--ulimit").arg(v);
        }
        for v in &self.sysctls {
            cmd.arg("--sysctl").arg(v);
        }
        for v in &self.labels {
            cmd.arg("--label").arg(v);
        }
        if let Some(v) = &self.restart_max {
            cmd.arg("--restart-max").arg(v);
        }
        if let Some(v) = &self.stop_signal {
            cmd.arg("--stop-signal").arg(v);
        }
        if let Some(v) = &self.stop_grace_period {
            cmd.arg("--stop-timeout").arg(v);
        }
        for v in &self.volumes {
            cmd.arg("--volume").arg(v);
        }
        for v in &self.env {
            cmd.arg("--env").arg(v);
        }
        if let Some(kv) = self.port_env() {
            cmd.arg("--env").arg(kv);
        }
        for v in &self.env_file {
            cmd.arg("--env-file").arg(v);
        }
        for v in &self.ports {
            cmd.arg("--publish").arg(v);
        }
        for v in &self.secrets {
            cmd.arg("--secret").arg(v);
        }
        for v in &self.tmpfs {
            cmd.arg("--tmpfs").arg(v);
        }
        for v in &self.cap_add {
            cmd.arg("--cap-add").arg(v);
        }
        for v in &self.cap_drop {
            cmd.arg("--cap-drop").arg(v);
        }
        // LAST, and positional rather than flagged, because that is how `kern box` takes them:
        // `kern box <name> [flags] vcpu:db vdisk:dbdata -- <command>`. The caller appends the `--`
        // and the command after this, so the tokens land in the one place the parser reads them.
        for t in self.profile_tokens() {
            cmd.arg(t);
        }
    }

    /// The `vcpu:`/`vdisk:`/`vgpio:` tokens this box attaches, in the order `kern box` would take
    /// them. A value that already carries its prefix is passed through unchanged, so a file may say
    /// `vcpu = "db"` or `vcpu = "vcpu:db"` and mean the same profile; anything else gets the prefix
    /// its key implies. Split out from `push_box_flags` so the normalisation is unit-testable without
    /// building a `Command`.
    /// The profile list for one [`PROFILE_KINDS`] entry, or `None` for a kind this build has no field
    /// for. THE kind → field pairing: `profile_tokens` reads through it and the YAML door writes
    /// through [`profile_list_mut`](Self::profile_list_mut), so neither spells a kind's field name
    /// itself and the two cannot come to disagree about which list `x-kern-vdisk` fills.
    pub fn profile_list(&self, kind: &str) -> Option<&Vec<String>> {
        match kind {
            "vcpu" => Some(&self.vcpu),
            "vdisk" => Some(&self.vdisk),
            "vgpio" => Some(&self.vgpio),
            _ => None,
        }
    }

    /// [`profile_list`](Self::profile_list), for the reader that fills these from `x-kern-<kind>`.
    pub fn profile_list_mut(&mut self, kind: &str) -> Option<&mut Vec<String>> {
        match kind {
            "vcpu" => Some(&mut self.vcpu),
            "vdisk" => Some(&mut self.vdisk),
            "vgpio" => Some(&mut self.vgpio),
            _ => None,
        }
    }

    pub fn profile_tokens(&self) -> Vec<String> {
        let mut out = Vec::new();
        for kind in PROFILE_KINDS {
            // `continue`, never a panic or an `unwrap`: a kind listed with no field is a bug the
            // pairing test catches, not something this function may take the process down over.
            let Some(names) = self.profile_list(kind) else {
                continue;
            };
            for n in names.iter().filter(|n| !n.trim().is_empty()) {
                let n = n.trim();
                if n.starts_with(&format!("{kind}:")) {
                    out.push(n.to_string());
                } else {
                    out.push(format!("{kind}:{n}"));
                }
            }
        }
        out
    }
}

/// Parse a compose document, auto-detecting the format (boxes are returned in file order). A
/// `docker-compose.yml` (first meaningful line is `services:`/`version:`/`name:`, or any `key:` block)
/// is parsed by the YAML-lite parser; a native kern stack (`[box.NAME]` tables) by the TOML parser.
/// Both produce the SAME `ComposeBox`es, so the
/// whole downstream pipeline (topo/conditions/exit-sidecar/pod/launch) is format-agnostic. This is the
/// compat entry: point `kern compose` at either and it just works (YAML degrades-with-warning on the
/// long tail - see `yaml::parse`). Auto-detect is deliberate: the two grammars are unambiguous at the
/// first non-comment line (`[` opens a TOML table; a bare `key:` opens a YAML mapping).
pub fn parse(text: &str) -> Result<Vec<ComposeBox>, String> {
    parse_with_env(text, &DotEnv::default())
}

/// [`parse`], plus a project `.env` consulted for `${VAR}` interpolation when the process environment
/// does not define the name. Split from `parse` so the pure-text entry point (and the fuzz target)
/// keeps its one-argument signature.
pub fn parse_with_env(text: &str, dotenv: &DotEnv) -> Result<Vec<ComposeBox>, String> {
    parse_layer(text, dotenv, true)
}

/// Parse an OVERRIDE layer (`-f base.yml -f override.yml`, every file after the first).
///
/// Docker merges the documents BEFORE validating them, so an override legitimately carries no
/// `image:` - it only restates the keys it changes. Validating each file standalone rejected exactly
/// the file an override is supposed to be; the "nothing to run" check is therefore deferred to the
/// MERGED result, where it still catches a service no layer ever gave something to run.
pub fn parse_override(text: &str, dotenv: &DotEnv) -> Result<Vec<ComposeBox>, String> {
    parse_layer(text, dotenv, false)
}

/// Assert every service ended up with something to run. Called on the merged stack (see
/// [`parse_override`]).
/// The environment variable kern uses to hand a declared `port:` to the service. One name, one
/// spelling, read and written through [`stated_port`] and [`ComposeBox::port_env`] only: written out
/// three times by hand, the injection site and the contradiction check could disagree about which
/// variable they are even talking about.
const PORT_VAR: &str = "PORT";

/// Parse ONE `expose:` entry (`"3000"`, `"53/udp"`, `"8080/tcp"`) into `(port, is_udp)`.
///
/// The single reader of that syntax: the YAML front end and the kern profile both call it, so the two
/// spellings of the same file cannot come to different conclusions about what `"53/udp"` means. Ranges
/// (`3000-3005`) are refused by name rather than expanded, because an expanded range makes a collision
/// message unreadable and a service that listens on one port has no use for one.
pub fn parse_expose_entry(raw: &str) -> Result<(u16, bool), String> {
    let raw = raw.trim();
    if raw.contains('-') {
        return Err(format!(
            "'{raw}' is a range - not supported, list the ports one by one"
        ));
    }
    let (num, proto) = raw.split_once('/').unwrap_or((raw, "tcp"));
    // Case-insensitive: there is no evidence here that Docker accepts `/TCP`, but accepting it
    // cannot break anything, whereas refusing an otherwise valid file can.
    let proto = proto.trim();
    let udp = if proto.eq_ignore_ascii_case("tcp") {
        false
    } else if proto.eq_ignore_ascii_case("udp") {
        true
    } else {
        return Err(format!(
            "'{raw}' has an unknown protocol '{proto}' (tcp or udp)"
        ));
    };
    match num.trim().parse::<u16>() {
        Ok(n) if n > 0 => Ok((n, udp)),
        _ => Err(format!("'{raw}' is not a port in 1..=65535")),
    }
}

/// The value of an explicit `PORT=` in a service's inline environment, if it states one. Borrows from
/// `env`, so asking the question costs no allocation.
fn stated_port(env: &[String]) -> Option<&str> {
    env.iter()
        .find_map(|e| e.strip_prefix(PORT_VAR)?.strip_prefix('='))
}

pub fn validate_runnable(boxes: &[ComposeBox]) -> Result<(), String> {
    for b in boxes {
        let has_image = b.image.as_deref().is_some_and(|s| !s.is_empty());
        let has_rootfs = b.rootfs.as_deref().is_some_and(|s| !s.is_empty());
        if !has_image && !has_rootfs && b.build.is_none() {
            return Err(format!(
                "service '{}' has no `image:`, `rootfs:` or `build:` (nothing to run)",
                b.name
            ));
        }
        // The same flag-injection rule the docker shim applies to a positional, applied here too.
        // The shim refused `docker run -- --rootfs=/etc`; compose accepted the identical string as an
        // `image:` and only failed much later, at the registry, with "no layers in manifest" - a
        // message about the wrong thing entirely. Docker refuses such a reference outright, and one
        // rule stated in one place beats two paths that disagree about the same string.
        for (role, value) in [
            ("image", b.image.as_deref()),
            ("rootfs", b.rootfs.as_deref()),
            ("service name", Some(b.name.as_str())),
        ] {
            if let Some(v) = value.filter(|v| v.starts_with('-')) {
                return Err(format!(
                    "service '{}': {role} '{v}' begins with '-' and would be read as a flag (injection). A {role} cannot start with '-'",
                    b.name
                ));
            }
        }
        // `port:` and an explicit `PORT=` that DISAGREE are a contradiction, and silently picking a
        // winner is the worst answer available: `port:` is what the pod preflight reserves, so if the
        // service actually listens on the other number the preflight is protecting a port nobody
        // binds while the real one collides unnoticed. Refuse and name both, rather than let the
        // declaration and the runtime drift apart. Agreeing values are simply redundant, not an error.
        if let Some(declared) = b.port {
            if let Some(stated) = stated_port(&b.env).filter(|v| v.trim() != declared.to_string()) {
                return Err(format!(
                    "service '{}' declares `port: {declared}` but also sets `PORT={stated}`: the \
                     preflight reserves {declared} while the service would listen on {stated}. Keep \
                     one of the two (dropping `port:` leaves kern with nothing to reserve, so prefer \
                     dropping the `PORT=` and letting `port:` set it).",
                    b.name
                ));
            }
        }
    }
    // A `depends_completed` TARGET that is `restart: always`/`unless-stopped` can NEVER complete, so the
    // dependent waits forever. Docker Compose rejects this combination at validation rather than hang;
    // kern names both services and the two keys that contradict - the same discipline as the `port:`/
    // `PORT=` clash above and `--cap-add ALL` under `--security-profile untrusted`. A hang is the worst
    // outcome: the user cannot see WHAT it is waiting for.
    for b in boxes {
        for dep in &b.depends_completed {
            if boxes.iter().any(|t| &t.name == dep && t.restart_always) {
                return Err(format!(
                    "service '{}' waits for '{dep}' to COMPLETE (depends_on condition \
                     service_completed_successfully), but '{dep}' sets `restart: always` (or \
                     unless-stopped) and never completes: the two contradict. Drop the restart policy on \
                     '{dep}', or the completion dependency on it in '{}'.",
                    b.name, b.name
                ));
            }
        }
    }
    Ok(())
}

fn parse_layer(
    text: &str,
    dotenv: &DotEnv,
    require_runnable: bool,
) -> Result<Vec<ComposeBox>, String> {
    // Strip a leading UTF-8 BOM (Windows editors add one) so the first key/table header is recognized
    // - Docker/YAML ignore a BOM, and without this it glues onto `services`/`[box.…]` and the file
    // "has no services".
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    // An empty file matches NEITHER format, so `is_yaml` says no and it fell through to the TOML
    // parser, which answered "no [box.NAME] tables found" - a TOML noun, for a file the user almost
    // certainly saved as `.yml`. Name the actual problem instead of guessing a format for a document
    // that has none.
    if text.trim().is_empty() {
        return Err("the file is empty: a compose file needs a `services:` block".into());
    }
    if is_yaml(text) {
        yaml::parse_with_env(text, dotenv, require_runnable)
    } else {
        parse_toml(text)
    }
}

/// Merge an OVERRIDE stack into a BASE one, Docker's `-f base.yml -f override.yml` semantics.
///
/// Docker merges the files before interpreting them; kern merges the interpreted services, which is
/// equivalent for everything a compose override actually expresses, and is stated here precisely so
/// the behaviour is checkable rather than folklore:
///
///  * a service only in the override is ADDED;
///  * for a service in both, a SCALAR the override sets wins (image, command, user, mem_limit, …) and
///    one it leaves unset keeps the base value - "unset" being the field's `Default`, exactly how the
///    parser records an absent key;
///  * SEQUENCES are APPENDED (ports, volumes, environment, labels, …) with the override last, so a
///    later `environment` entry wins at runtime and an override can add a port without restating the
///    base ones;
///  * `command`/`entrypoint` REPLACE rather than append - concatenating two argv would run neither.
///
/// Order matters: `merge(a, b)` is "b overrides a". Not commutative, by design.
pub fn merge_stacks(base: Vec<ComposeBox>, over: Vec<ComposeBox>) -> Vec<ComposeBox> {
    let mut out = base;
    for o in over {
        match out.iter_mut().find(|b| b.name == o.name) {
            Some(b) => b.merge_from(o),
            None => out.push(o),
        }
    }
    out
}

impl ComposeBox {
    /// Apply `o` over `self` - see [`merge_stacks`] for the rules.
    fn merge_from(&mut self, o: ComposeBox) {
        // Scalars: the override wins when it set one.
        macro_rules! opt {
            ($($f:ident),* $(,)?) => { $( if o.$f.is_some() { self.$f = o.$f; } )* };
        }
        opt!(
            image,
            rootfs,
            build,
            workdir,
            memory,
            cpus,
            cpuset,
            swap_max,
            pids_limit,
            io_weight,
            nice,
            timeout,
            hostname,
            user,
            ssh,
            ssh_key,
            health_cmd,
            health_interval,
            health_retries,
            health_start_period,
            health_timeout,
            health_action,
            // Added late and forgotten once each: a field that reaches the struct but not this list
            // is dropped in SILENCE by an override file, which is the worst shape a bug can take in a
            // merge. `every_optional_field_survives_a_merge` now fails when the next one is missed.
            port,
            restart_max,
            stop_signal,
            stop_grace_period,
            security_profile,
        );
        // Booleans: an override can only turn one ON (its `false` is indistinguishable from absent).
        macro_rules! flag {
            ($($f:ident),* $(,)?) => { $( self.$f |= o.$f; )* };
        }
        flag!(
            read_only,
            net,
            uid_range,
            bind_rootfs,
            restart,
            restart_always,
            tun,
            init
        );
        if o.uid_range_explicit_false {
            self.uid_range_explicit_false = true;
        }
        // Sequences: append, override last.
        macro_rules! seq {
            ($($f:ident),* $(,)?) => { $( self.$f.extend(o.$f); )* };
        }
        seq!(
            expose,
            volumes,
            env,
            env_file,
            ports,
            secrets,
            tmpfs,
            cap_add,
            cap_drop,
            add_host,
            ulimits,
            sysctls,
            labels,
            net_aliases,
            profiles,
            depends_on,
            depends_healthy,
            depends_completed,
        );
        // PROFILE LISTS REPLACE, unlike every other list above, and the difference is not tidiness.
        // A `vcpu:` profile does NOT stack (the first to set each cap wins, with a warning), so an
        // override that APPENDED would leave the base's caps in force and the override's ignored,
        // which is the reverse of what an override means. The compose spelling is a scalar
        // (`x-kern-vcpu: ml`), so a reader who writes a different name in an override expects that
        // name and not both.
        //
        // MEASURED BEFORE THIS EXISTED: an override adding `x-kern-vgpio: leds` reached the struct
        // and was dropped in silence - `config` printed no `profiles:` line and the box got no
        // device. Accepted-and-ignored, in the merge, which is the shape this file's own comment
        // eight lines up warns about.
        //
        // Removal is NOT expressible: an empty value contributes no entries and so reads as "not
        // mentioned". Said here rather than discovered, because an override CANNOT take a grant away.
        macro_rules! replace_seq {
            ($($f:ident),* $(,)?) => { $( if !o.$f.is_empty() { self.$f = o.$f; } )* };
        }
        replace_seq!(vcpu, vdisk, vgpio);
        // argv REPLACES: appending two commands would run neither.
        if !o.command.is_empty() {
            self.command = o.command;
        }
    }
}

/// Variables from a project `.env`, consulted ONLY when the process environment does not define the
/// name - Docker's precedence is shell > `.env`, and inverting it would let a checked-in file silently
/// override what an operator exported for one run.
///
/// A contiguous `Vec` scanned linearly, not a hash map: a real `.env` holds a handful of keys, so the
/// whole table sits in a couple of cache lines and a linear scan wins on both lookup latency and setup
/// cost at these sizes. The common case (no `.env` at all) is [`DotEnv::default`], where every lookup
/// is one length check.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct DotEnv(Vec<(String, String)>);

impl DotEnv {
    /// The value bound to `key`, or `None`. Last definition wins (like a shell sourcing the file), so
    /// the scan runs backwards and stops at the first hit.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Number of bindings (0 when there is no `.env`).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Parse `.env` text per Docker's rules. Pure and total: any input yields a table, never an error -
/// a malformed line is skipped, because refusing to run a stack over one stray line in a file Docker
/// tolerates would be worse than ignoring it.
///
/// Implemented rules (docs.docker.com/compose/how-tos/environment-variables/variable-interpolation):
///  * blank lines and lines whose first non-space character is `#` are ignored;
///  * `KEY=VALUE` or `KEY:VALUE` (first delimiter wins), spaces around both sides trimmed;
///  * a leading `export ` is tolerated (shells write it; Docker ignores it);
///  * single-quoted values are LITERAL; double-quoted values decode `\n`, `\r`, `\t`, `\\`, `\"`;
///  * an inline comment is stripped after the closing quote, or - for an unquoted value - at the first
///    ` #` (a `#` with no preceding space is part of the value, e.g. a colour or a fragment URL);
///  * a key that is empty or contains whitespace is skipped (it could not be referenced anyway).
///
/// `${…}` inside values is NOT expanded here: kern interpolates once, over the whole compose document,
/// after the environment and this table are merged - expanding twice would substitute a value that
/// itself looks like a reference.
pub fn parse_dotenv(text: &str) -> DotEnv {
    let mut out: Vec<(String, String)> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        // First `=` or `:` delimits; whichever comes first, so `URL=http://x` keeps its colons.
        let cut = match (line.find('='), line.find(':')) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => continue, // no delimiter: not a binding
        };
        let key = line[..cut].trim();
        if key.is_empty() || key.split_whitespace().count() != 1 {
            continue;
        }
        out.push((key.to_string(), dotenv_value(line[cut + 1..].trim())));
    }
    DotEnv(out)
}

/// Decode one `.env` value: quote handling + inline-comment stripping. See [`parse_dotenv`].
fn dotenv_value(v: &str) -> String {
    let mut chars = v.chars();
    match chars.next() {
        // Single quotes: literal to the closing quote; anything after it is a comment.
        Some('\'') => match v[1..].find('\'') {
            Some(end) => v[1..1 + end].to_string(),
            None => v[1..].to_string(), // unterminated: take the rest, don't drop the value
        },
        // Double quotes: honour backslash escapes, stop at the first UNescaped closing quote.
        Some('"') => {
            let mut out = String::with_capacity(v.len());
            let mut esc = false;
            for c in v[1..].chars() {
                if esc {
                    out.push(match c {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        other => other, // covers \\ and \" ; unknown escapes stay literal
                    });
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else if c == '"' {
                    break;
                } else {
                    out.push(c);
                }
            }
            out
        }
        // Unquoted: an inline comment must be preceded by a space, so only ` #` ends the value.
        _ => match v.find(" #") {
            Some(at) => v[..at].trim_end().to_string(),
            None => v.to_string(),
        },
    }
}

/// True if `text` looks like a compose YAML rather than a kern TOML stack. Decides on the FIRST
/// meaningful line: a `[…]` table header → TOML; anything else that is `key:`-shaped → YAML. Comments
/// and blanks are skipped. Conservative: only an explicit `[` says TOML, so an ambiguous file falls to
/// YAML (which reports precise line errors if it's actually malformed).
fn is_yaml(text: &str) -> bool {
    for raw in text.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        // A TOML stack opens with `[box.NAME]`. Anything else meaningful → treat as YAML.
        return !line.starts_with('[');
    }
    false // empty document → let the TOML parser produce its "no boxes" error
}

/// Parse the native kern TOML stack format (`[box.NAME]` tables). See [`parse`] for auto-detect.
///
/// `pub(crate)`, not `pub`: the crate exposes ONE parse door ([`parse`], which auto-detects YAML vs
/// TOML). Callers must not reach past the format sniff and hand a YAML file to the TOML parser.
pub(crate) fn parse_toml(text: &str) -> Result<Vec<ComposeBox>, String> {
    let mut boxes: Vec<ComposeBox> = Vec::new();
    let mut cur: Option<usize> = None;
    for (i, logical) in logical_lines(text) {
        let line = logical.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = parse_box_header(line) {
            // Validate the name at THIS layer (not only in the child `kern box`), so a bad header
            // like `[box.--net]` reports a precise line rather than an opaque "failed to start".
            kern_common::BoxName::parse(&name)
                .map_err(|e| format!("line {}: invalid box name '{name}': {e}", i + 1))?;
            if boxes.iter().any(|b| b.name == name) {
                return Err(format!("line {}: duplicate box '{name}'", i + 1));
            }
            boxes.push(ComposeBox::new(name));
            cur = Some(boxes.len() - 1);
            continue;
        }
        let idx = cur.ok_or_else(|| format!("line {}: key outside any [box.NAME] table", i + 1))?;
        let (key, val) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected `key = value`", i + 1))?;
        let b = &mut boxes[idx];
        let s = |v: &str| parse_string(v).map_err(|e| line_err(i, &e));
        // BOX-KEYS-BEGIN - every arm below is asserted to appear in docs/CONFIG.md by
        // `every_box_key_is_documented`. Ten of them were not, and that file is the one the README
        // calls the schema field by field, so a user reading it could not learn that `ulimits`,
        // `sysctls`, `init` or `stop_signal` work at all. Move this marker if the match moves.
        match key.trim() {
            // Scalars - quoted strings carrying the exact CLI argument.
            "image" => b.image = Some(s(val)?),
            "rootfs" => b.rootfs = Some(s(val)?),
            "workdir" => b.workdir = Some(s(val)?),
            "memory" => b.memory = Some(s(val)?),
            "cpus" => b.cpus = Some(s(val)?),
            "cpuset" => b.cpuset = Some(s(val)?),
            "swap_max" => b.swap_max = Some(s(val)?),
            // These three existed as CLI flags and as Docker keys but NOT as kern profile keys, so
            // a kern-native stack could not express them, against the project's "profile field ==
            // CLI flag, 1:1" rule. Validation stays downstream, where it already lives for the YAML
            // path, so the two routes cannot diverge on what value they accept.
            "restart_max" => b.restart_max = Some(s(val)?),
            "stop_signal" => b.stop_signal = Some(s(val)?),
            "stop_grace_period" => b.stop_grace_period = Some(s(val)?),
            "pids_limit" => b.pids_limit = Some(s(val)?),
            "io_weight" => b.io_weight = Some(s(val)?),
            "nice" => b.nice = Some(s(val)?),
            "timeout" => b.timeout = Some(s(val)?),
            "hostname" => b.hostname = Some(s(val)?),
            "user" => b.user = Some(s(val)?),
            "ssh" => b.ssh = Some(s(val)?),
            "ssh_key" => b.ssh_key = Some(s(val)?),
            "health_cmd" => b.health_cmd = Some(s(val)?),
            "health_interval" => {
                b.health_interval = Some(parse_positive_int(val).map_err(|e| line_err(i, &e))?)
            }
            "health_retries" => b.health_retries = Some(s(val)?),
            "health_start_period" => b.health_start_period = Some(s(val)?),
            "health_timeout" => b.health_timeout = Some(s(val)?),
            "health_action" => b.health_action = Some(s(val)?),
            // Switches - TOML booleans.
            "read_only" => b.read_only = parse_bool(val).map_err(|e| line_err(i, &e))?,
            "net" => b.net = parse_bool(val).map_err(|e| line_err(i, &e))?,
            "uid_range" => {
                b.uid_range = parse_bool(val).map_err(|e| line_err(i, &e))?;
                b.uid_range_explicit_false = !b.uid_range; // remember a deliberate `= false`
            }
            "bind_rootfs" => b.bind_rootfs = parse_bool(val).map_err(|e| line_err(i, &e))?,
            "restart" => b.restart = parse_bool(val).map_err(|e| line_err(i, &e))?,
            "tun" => b.tun = parse_bool(val).map_err(|e| line_err(i, &e))?,
            "init" => b.init = parse_bool(val).map_err(|e| line_err(i, &e))?,
            // Repeatable flags - arrays of the same CLI strings.
            "command" => b.command = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            // `depends_on` accepts BOTH the array form (`["db"]` - start-order only, like Docker's
            // short syntax) and the Docker long-syntax inline table (`{ db = { condition =
            // "service_healthy" } }`), so a real `docker-compose.yml` snippet can be pasted as-is and
            // the health/completion waits just work. The table form routes each dep into the right
            // bucket by its condition.
            "depends_on" => parse_depends(b, val).map_err(|e| line_err(i, &e))?,
            "depends_healthy" => {
                b.depends_healthy = parse_string_array(val).map_err(|e| line_err(i, &e))?
            }
            "depends_completed" => {
                b.depends_completed = parse_string_array(val).map_err(|e| line_err(i, &e))?
            }
            "config" => b.config = Some(s(val)?),
            // The v-profile keys. Each takes a bare profile NAME or a list of them, because the table
            // that declares them is already `[[vcpu]]`/`[[vdisk]]`/`[[vgpio]]`: repeating the prefix in
            // the value would be the file saying twice what it says once. A value that DOES carry the
            // prefix is accepted and normalised (see `profile_tokens`), since it names the same thing.
            "vcpu" => b.vcpu = parse_scalar_or_array(val).map_err(|e| line_err(i, &e))?,
            "vdisk" => b.vdisk = parse_scalar_or_array(val).map_err(|e| line_err(i, &e))?,
            "vgpio" => b.vgpio = parse_scalar_or_array(val).map_err(|e| line_err(i, &e))?,
            // The native spelling of `--security-profile`, which the YAML door has as
            // `x-kern-security-profile`. Missing until now, so the native format could not say
            // something the compose format could, and the merge test (which is a TOML fixture)
            // could not cover the field at all.
            "security_profile" => b.security_profile = Some(s(val)?),
            "volumes" => b.volumes = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "env" => b.env = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "env_file" => b.env_file = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "ports" => b.ports = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            // Malformed = REFUSED, with the line number, where the same value in a
            // `docker-compose.yml` is warned and skipped. Deliberate rather than inconsistent: this
            // is kern's own format, where a typo is a typo to fix; that is someone else's file,
            // where refusing a whole stack over one line of pure documentation would be the wrong
            // trade. The PARSER is the same, so the string means the same thing in both; only what
            // the reader does with it differs.
            "expose" => {
                b.expose.clear();
                for raw in parse_string_array(val).map_err(|e| line_err(i, &e))? {
                    b.expose.push(
                        parse_expose_entry(&raw)
                            .map_err(|e| line_err(i, &format!("expose: {e}")))?,
                    );
                }
            }
            "port" => {
                // Narrowed to `u16` HERE, at the one place the text is read, so nothing downstream
                // ever holds a port that might not be one. `parse_positive_int` already refuses `0`
                // and negatives: to `bind()` a `0` means "any free port", which is the opposite of a
                // DECLARED port and would have the preflight compare a number nobody listens on.
                // Both `port = 3000` and a quoted `port = "3000"` are accepted, because the YAML
                // front end passes a quoted scalar through as written.
                let raw = val.trim().trim_matches('"');
                let n = parse_positive_int(raw).map_err(|e| line_err(i, &format!("port: {e}")))?;
                let n = u16::try_from(n).map_err(|_| {
                    line_err(i, &format!("port: {n} is outside the 1..=65535 port range"))
                })?;
                b.port = Some(n);
            }
            "secrets" => b.secrets = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "tmpfs" => b.tmpfs = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "cap_add" => b.cap_add = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "cap_drop" => b.cap_drop = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            // Five fields had the CLI flag and the Docker key but not the kern profile key, so a
            // kern-native stack could not express them. The project's law is "profile field == CLI
            // flag, 1:1", and this was the only half of it missing.
            "add_host" => b.add_host = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "ulimits" => b.ulimits = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "labels" => b.labels = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "sysctls" => b.sysctls = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            other => return Err(format!("line {}: unknown key '{other}'", i + 1)),
        }
        // BOX-KEYS-END
    }
    if boxes.is_empty() {
        return Err("no [box.NAME] tables found".into());
    }
    for b in &boxes {
        // An empty string (`image = ""`) counts as absent - otherwise it only fails downstream in
        // the child with an opaque error instead of a line-level "needs image or rootfs".
        let nonempty = |o: &Option<String>| o.as_deref().is_some_and(|s| !s.is_empty());
        if !nonempty(&b.image) && !nonempty(&b.rootfs) {
            return Err(format!(
                "box '{}': needs a non-empty `image` or `rootfs`",
                b.name
            ));
        }
    }
    Ok(boxes)
}

/// Dependency order (a box starts after every box it depends on - `depends_on` plus the conditional
/// `depends_healthy`/`depends_completed`, via [`ComposeBox::all_deps`]). Errors on an unknown
/// dependency or a cycle.
pub fn topo_order(boxes: &[ComposeBox]) -> Result<Vec<String>, String> {
    let names: HashSet<&str> = boxes.iter().map(|b| b.name.as_str()).collect();
    let mut indeg: HashMap<&str, usize> = boxes.iter().map(|b| (b.name.as_str(), 0)).collect();
    let mut succ: HashMap<&str, Vec<&str>> = HashMap::new();
    for b in boxes {
        for d in b.all_deps() {
            if !names.contains(d) {
                return Err(format!("box '{}' depends on unknown box '{d}'", b.name));
            }
            succ.entry(d).or_default().push(b.name.as_str());
            // `indeg` was seeded with every box name, so the entry is there by construction - but
            // `or_insert(0)` states that instead of asserting it, and an unexpected shape becomes a
            // wrong ordering rather than an abort in a parser that also runs under the fuzzer.
            *indeg.entry(b.name.as_str()).or_insert(0) += 1;
        }
    }
    // Seed the queue in file order for a deterministic result.
    let mut queue: VecDeque<&str> = boxes
        .iter()
        .map(|b| b.name.as_str())
        .filter(|n| indeg[n] == 0)
        .collect();
    let mut order = Vec::with_capacity(boxes.len());
    while let Some(n) = queue.pop_front() {
        order.push(n.to_string());
        if let Some(ms) = succ.get(n) {
            for &m in ms {
                // Same construction as above: the successor is a known box name. Skipping an
                // unknown one keeps the traversal total instead of aborting the process.
                let Some(e) = indeg.get_mut(m) else { continue };
                *e -= 1;
                if *e == 0 {
                    queue.push_back(m);
                }
            }
        }
    }
    if order.len() != boxes.len() {
        // Name the services still in the cycle (indegree never reached 0) - like Docker's
        // "dependency cycle detected: a -> b -> a", this points the user at the offending set instead
        // of just "there's a cycle somewhere". File order, so it's deterministic.
        let mut stuck: Vec<&str> = boxes
            .iter()
            .map(|b| b.name.as_str())
            .filter(|n| indeg[n] > 0)
            .collect();
        stuck.sort_by_key(|n| boxes.iter().position(|b| b.name == *n));
        return Err(format!(
            "dependency cycle detected among: {}",
            stuck.join(", ")
        ));
    }
    Ok(order)
}

/// Like [`topo_order`], but grouped into dependency LEVELS: every box in level `k` depends only on
/// boxes in levels `< k`, so all boxes WITHIN one level are independent and can be started
/// concurrently - a barrier between levels preserves `depends_on`. Same deterministic file-order
/// tie-break, same unknown-dep / cycle errors as [`topo_order`].
pub fn topo_levels(boxes: &[ComposeBox]) -> Result<Vec<Vec<String>>, String> {
    let names: HashSet<&str> = boxes.iter().map(|b| b.name.as_str()).collect();
    let mut indeg: HashMap<&str, usize> = boxes.iter().map(|b| (b.name.as_str(), 0)).collect();
    let mut succ: HashMap<&str, Vec<&str>> = HashMap::new();
    for b in boxes {
        for d in b.all_deps() {
            if !names.contains(d) {
                return Err(format!("box '{}' depends on unknown box '{d}'", b.name));
            }
            succ.entry(d).or_default().push(b.name.as_str());
            // `indeg` was seeded with every box name, so the entry is there by construction - but
            // `or_insert(0)` states that instead of asserting it, and an unexpected shape becomes a
            // wrong ordering rather than an abort in a parser that also runs under the fuzzer.
            *indeg.entry(b.name.as_str()).or_insert(0) += 1;
        }
    }
    // Level 0 = every indegree-0 box, in file order. Then repeatedly: emit the current level, decrement
    // successors, and the boxes that hit indegree 0 form the next level (a box lands one level after
    // its LAST-satisfied dependency - standard levelised Kahn).
    // A precomputed name→file-index map keeps the per-level `sort_by_key` at O(k log k): looking the
    // index up here is O(1), vs an O(N) `position` scan that would make the sort O(N·k log k).
    let index: HashMap<&str, usize> = boxes
        .iter()
        .enumerate()
        .map(|(i, b)| (b.name.as_str(), i))
        .collect();
    let pos = |n: &str| index.get(n).copied().unwrap_or(usize::MAX);
    let mut level: Vec<&str> = boxes
        .iter()
        .map(|b| b.name.as_str())
        .filter(|n| indeg[n] == 0)
        .collect();
    let mut levels: Vec<Vec<String>> = Vec::new();
    let mut placed = 0usize;
    while !level.is_empty() {
        placed += level.len();
        let mut next: Vec<&str> = Vec::new();
        for &n in &level {
            if let Some(ms) = succ.get(n) {
                for &m in ms {
                    // Same construction as above; skip an unknown successor rather than abort.
                    let Some(e) = indeg.get_mut(m) else { continue };
                    *e -= 1;
                    if *e == 0 {
                        next.push(m);
                    }
                }
            }
        }
        levels.push(level.iter().map(|s| s.to_string()).collect());
        next.sort_by_key(|n| pos(n)); // deterministic order within the next level
        level = next;
    }
    if placed != boxes.len() {
        let mut stuck: Vec<&str> = boxes
            .iter()
            .map(|b| b.name.as_str())
            .filter(|n| indeg[n] > 0)
            .collect();
        stuck.sort_by_key(|n| pos(n));
        return Err(format!(
            "dependency cycle detected among: {}",
            stuck.join(", ")
        ));
    }
    Ok(levels)
}

/// Parse a `depends_on` value into the box's dependency buckets. Two accepted shapes:
///
///   * Array (Docker short syntax): `["db", "redis"]` → start-order edges only.
///   * Inline table (Docker long syntax): `{ db = { condition = "service_healthy" }, migrate = {
///     condition = "service_completed_successfully" } }` → each dep routed to `depends_healthy` /
///     `depends_completed` / `depends_on` by its `condition`. `service_started` (or a bare `{}`)
///     means start-order only.
///
/// The point is copy-paste fidelity: a real `docker-compose.yml` block drops in and the waits work.
fn parse_depends(b: &mut ComposeBox, val: &str) -> Result<(), String> {
    let v = val.trim();
    if !v.starts_with('{') {
        // Array form - plain start-order dependencies.
        b.depends_on = parse_string_array(v)?;
        return Ok(());
    }
    // Inline-table form. Parse `name = { condition = "..." }` entries at the top level. We scan
    // rather than pull in a TOML crate (the whole compose parser is dependency-free by design).
    // Robustness (this is user-supplied - a docker-compose.yml from a third-party repo): reject
    // malformed brace/quote nesting with a clean error, NEVER panic. `balanced_braces` verifies the
    // WHOLE value is a single well-formed `{ … }` (quotes respected, no over-close) before we strip.
    balanced_braces(v)?;
    let inner = v
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| "malformed depends_on table (missing closing `}`)".to_string())?
        .trim();
    if inner.is_empty() {
        return Ok(());
    }
    for entry in split_top_level_commas(inner) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (name, spec) = entry
            .split_once('=')
            .ok_or_else(|| format!("depends_on entry '{entry}': expected `name = {{ ... }}`"))?;
        let name = name.trim().trim_matches('"').to_string();
        if name.is_empty() {
            return Err("depends_on entry: empty dependency name".to_string());
        }
        // Find the condition inside the nested `{ ... }` (default: service_started).
        let cond = spec
            .trim()
            .strip_prefix('{')
            .and_then(|s| s.trim().strip_suffix('}'))
            .map(str::trim)
            .and_then(|body| body.split_once('='))
            .map(|(k, cv)| (k.trim(), cv.trim().trim_matches('"')))
            .filter(|(k, _)| *k == "condition")
            .map(|(_, cv)| cv)
            .unwrap_or("service_started");
        match cond {
            "service_healthy" => b.depends_healthy.push(name),
            "service_completed_successfully" => b.depends_completed.push(name),
            "service_started" => b.depends_on.push(name),
            other => {
                return Err(format!(
                    "depends_on '{name}': unknown condition '{other}' (want service_started, \
                     service_healthy, or service_completed_successfully)"
                ))
            }
        }
    }
    Ok(())
}

/// Verify `s` is a single well-formed `{ … }` inline table: it opens and closes with braces, brace
/// depth never goes negative (no over-close like `x } }`) and returns to zero (no unterminated `{`),
/// and braces inside double quotes are literal (not structural). Quotes must be balanced too. Returns
/// a clean parse error on any violation - the guard that keeps a malformed `docker-compose.yml`
/// snippet from reaching the slicing/splitting code below as garbage. Iterative (no recursion → no
/// stack overflow on pathological `{{{{…}}}}`); scans `char`s (never raw byte offsets).
fn balanced_braces(s: &str) -> Result<(), String> {
    let mut depth = 0i32;
    let mut in_quote = false;
    for c in s.chars() {
        match c {
            '"' => in_quote = !in_quote,
            '{' if !in_quote => depth += 1,
            '}' if !in_quote => {
                depth -= 1;
                if depth < 0 {
                    return Err("malformed depends_on table (unbalanced `}`)".to_string());
                }
            }
            _ => {}
        }
    }
    if in_quote {
        return Err("malformed depends_on table (unterminated string)".to_string());
    }
    if depth != 0 {
        return Err("malformed depends_on table (unterminated `{`)".to_string());
    }
    Ok(())
}

/// Split on commas that are NOT inside a nested `{ ... }` and NOT inside double quotes - for the
/// inline-table `depends_on` form, where the whole list is comma-separated but each entry
/// (`name = { condition = "..." }`) has its own braces (and a value may quote a comma). Depth- and
/// quote-tracked. Assumes `balanced_braces(s's wrapper)` already passed, so depth stays ≥ 0. Splits on
/// the ASCII byte `,`, so `s[start..i]` is always on a char boundary (`char_indices` yields boundaries
/// and `i+1` past a 1-byte `,` is one too) - no UTF-8 slicing panic.
fn split_top_level_commas(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_quote = false;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_quote = !in_quote,
            '{' if !in_quote => depth += 1,
            '}' if !in_quote => depth -= 1,
            ',' if depth == 0 && !in_quote => {
                out.push(s[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(s[start..].to_string());
    out
}

fn line_err(i: usize, e: &str) -> String {
    format!("line {}: {e}", i + 1)
}

use kern_common::toml_lite;

fn strip_comment(line: &str) -> &str {
    toml_lite::strip_comment(line)
}

/// Fold physical lines into LOGICAL lines so a multi-line array value -
/// `command = [\n  "a",\n  "b",\n]` (standard TOML) - is parsed as one unit instead of the parser
/// choking on the bare `[`. Comments are stripped per physical line first; a logical line stays open
/// while its bracket depth (counted OUTSIDE quoted strings, so a `[`/`]` inside a string doesn't
/// count) is positive. Returns `(start_line_index, joined)` so errors still point at the opening line.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut acc = String::new();
    let mut start = 0usize;
    let mut depth: i32 = 0;
    for (i, raw) in text.lines().enumerate() {
        let piece = strip_comment(raw);
        if depth == 0 && acc.is_empty() {
            if piece.trim().is_empty() {
                continue;
            }
            start = i;
            acc.push_str(piece.trim());
        } else {
            acc.push(' ');
            acc.push_str(piece.trim());
        }
        depth += bracket_delta(piece);
        if depth <= 0 {
            out.push((start, std::mem::take(&mut acc)));
            depth = 0;
        }
    }
    if !acc.trim().is_empty() {
        out.push((start, acc));
    }
    out
}

/// Net `[` minus `]` in `line`, ignoring brackets inside double- or single-quoted strings.
fn bracket_delta(line: &str) -> i32 {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in line.chars() {
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' && q == '"' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(c),
                '[' => depth += 1,
                ']' => depth -= 1,
                _ => {}
            },
        }
    }
    depth
}

fn parse_box_header(line: &str) -> Option<String> {
    let inner = line.strip_prefix('[')?.strip_suffix(']')?;
    let name = inner.strip_prefix("box.")?.trim();
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

fn parse_string(v: &str) -> Result<String, String> {
    toml_lite::quoted_string(v)
}

fn parse_bool(v: &str) -> Result<bool, String> {
    toml_lite::parse_bool(v)
}

/// A positive integer (the only int key, `health_interval`, is seconds - 0/negative is nonsense).
/// Validating here gives a precise line-numbered error instead of an opaque child "failed to start".
fn parse_positive_int(v: &str) -> Result<i64, String> {
    match v.trim().parse::<i64>() {
        Ok(n) if n > 0 => Ok(n),
        Ok(_) => Err(format!("expected a positive integer, got `{}`", v.trim())),
        Err(_) => Err(format!("expected an integer, got `{}`", v.trim())),
    }
}

/// A key that takes either one value or several: `vcpu = "db"` and `vcpu = ["db", "burst"]` both
/// parse. The v-profile keys use it because attaching exactly one is the common case and forcing
/// `["db"]` on every line would be ceremony; the array form stays for a box that mounts two vdisks.
fn parse_scalar_or_array(val: &str) -> Result<Vec<String>, String> {
    let t = val.trim();
    if t.starts_with('[') {
        parse_string_array(t)
    } else {
        Ok(vec![parse_string(t)?])
    }
}

fn parse_string_array(v: &str) -> Result<Vec<String>, String> {
    toml_lite::string_array(v)
}

// (comment stripping, quoted strings, bools and string arrays now live in `kern_common::toml_lite`,
//  shared with the profile loader so the two parsers can't drift.)

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"
        # a small stack
        [box.web]
        image = "alpine"
        command = ["/bin/sh", "-c", "echo hi, there"]
        depends_on = ["db"]

        [box.db]
        image = "alpine"
    "#;

    #[test]
    fn parses_boxes_and_values() {
        let boxes = parse(DOC).unwrap();
        assert_eq!(boxes.len(), 2);
        let web = &boxes[0];
        assert_eq!(web.name, "web");
        assert_eq!(web.image.as_deref(), Some("alpine"));
        // the comma inside the quoted string must NOT split the array
        assert_eq!(web.command, ["/bin/sh", "-c", "echo hi, there"]);
        assert_eq!(web.depends_on, ["db"]);
    }

    #[test]
    fn multiline_array_folds_into_one_logical_line() {
        // Standard TOML multi-line array: the parser must fold the continuation lines, not choke on
        // the bare `[`. A `[bracket]` and a comma inside a quoted string must NOT affect folding.
        let doc = r#"
            [box.web]
            image = "alpine"
            command = [
              "/bin/sh", "-c",
              "echo one, two [three]",
            ]
            depends_on = ["db"]
        "#;
        let boxes = parse(doc).unwrap();
        let web = &boxes[0];
        assert_eq!(web.command, ["/bin/sh", "-c", "echo one, two [three]"]);
        assert_eq!(web.depends_on, ["db"]);
    }

    #[test]
    fn topo_respects_depends_on() {
        let boxes = parse(DOC).unwrap();
        let order = topo_order(&boxes).unwrap();
        let (a, b) = (
            order.iter().position(|n| n == "db").unwrap(),
            order.iter().position(|n| n == "web").unwrap(),
        );
        assert!(a < b, "db must start before web: {order:?}");
    }

    #[test]
    fn detects_cycles_and_unknown_deps() {
        let cyc =
            "[box.a]\nimage=\"x\"\ndepends_on=[\"b\"]\n[box.b]\nimage=\"x\"\ndepends_on=[\"a\"]";
        assert!(topo_order(&parse(cyc).unwrap()).is_err());
        let unknown = "[box.a]\nimage=\"x\"\ndepends_on=[\"ghost\"]";
        assert!(topo_order(&parse(unknown).unwrap()).is_err());
        // topo_levels rejects the same bad graphs.
        assert!(topo_levels(&parse(cyc).unwrap()).is_err());
        assert!(topo_levels(&parse(unknown).unwrap()).is_err());
    }

    #[test]
    fn topo_levels_group_independent_services() {
        // a (no deps) and c (no deps) are level 0; b depends on a; d depends on b and c. So:
        // level 0 = {a, c}, level 1 = {b}, level 2 = {d}. Independent services share a level.
        let doc = "[box.a]\nimage=\"x\"\n\
                   [box.c]\nimage=\"x\"\n\
                   [box.b]\nimage=\"x\"\ndepends_on=[\"a\"]\n\
                   [box.d]\nimage=\"x\"\ndepends_on=[\"b\",\"c\"]";
        let levels = topo_levels(&parse(doc).unwrap()).unwrap();
        assert_eq!(levels.len(), 3, "three levels: {levels:?}");
        assert!(levels[0].contains(&"a".to_string()) && levels[0].contains(&"c".to_string()));
        assert_eq!(levels[1], vec!["b".to_string()]);
        assert_eq!(levels[2], vec!["d".to_string()]);
        // Every box appears exactly once across all levels.
        let total: usize = levels.iter().map(|l| l.len()).sum();
        assert_eq!(total, 4);
    }

    #[test]
    fn parses_conditional_deps_array_form() {
        let doc = r#"
            [box.db]
            image = "postgres:16-alpine"
            health_cmd = "pg_isready"
            [box.migrate]
            image = "postgres:16-alpine"
            depends_healthy = ["db"]
            [box.api]
            image = "alpine"
            depends_completed = ["migrate"]
            depends_healthy = ["db"]
        "#;
        let boxes = parse(doc).unwrap();
        let mig = boxes.iter().find(|b| b.name == "migrate").unwrap();
        assert_eq!(mig.depends_healthy, ["db"]);
        let api = boxes.iter().find(|b| b.name == "api").unwrap();
        assert_eq!(api.depends_completed, ["migrate"]);
        assert_eq!(api.depends_healthy, ["db"]);
        // A conditional dep implies the ordering edge (all_deps) even without a `depends_on`.
        assert!(api.all_deps().contains(&"migrate"));
        assert!(api.all_deps().contains(&"db"));
        // Topo order must place db and migrate before api.
        let order = topo_order(&boxes).unwrap();
        let pos = |n: &str| order.iter().position(|x| x == n).unwrap();
        assert!(pos("db") < pos("migrate"));
        assert!(pos("migrate") < pos("api"));
    }

    #[test]
    fn parses_docker_nested_table_depends_on() {
        // A verbatim Docker long-syntax block must route each dep to the right bucket.
        let doc = r#"
            [box.postgres]
            image = "postgres:16-alpine"
            health_cmd = "pg_isready"
            [box.redis]
            image = "redis:7-alpine"
            health_cmd = "redis-cli ping"
            [box.migrate]
            image = "postgres:16-alpine"
            depends_on = { postgres = { condition = "service_healthy" } }
            [box.api]
            image = "alpine"
            depends_on = { migrate = { condition = "service_completed_successfully" }, redis = { condition = "service_healthy" } }
        "#;
        let boxes = parse(doc).unwrap();
        let mig = boxes.iter().find(|b| b.name == "migrate").unwrap();
        assert_eq!(mig.depends_healthy, ["postgres"]);
        let api = boxes.iter().find(|b| b.name == "api").unwrap();
        assert_eq!(api.depends_completed, ["migrate"]);
        assert_eq!(api.depends_healthy, ["redis"]);
        assert!(topo_order(&boxes).is_ok());
    }

    #[test]
    fn nested_table_default_condition_is_start_order() {
        // Bare `{}` and an explicit service_started are ordering-only, not a wait.
        let doc = r#"
            [box.a]
            image = "alpine"
            [box.b]
            image = "alpine"
            depends_on = { a = { condition = "service_started" } }
        "#;
        let b = &parse(doc).unwrap()[1];
        assert_eq!(b.depends_on, ["a"]);
        assert!(b.depends_healthy.is_empty() && b.depends_completed.is_empty());
    }

    #[test]
    fn rejects_unknown_condition() {
        let doc = "[box.a]\nimage=\"x\"\n[box.b]\nimage=\"x\"\ndepends_on = { a = { condition = \"service_banana\" } }";
        let err = match parse(doc) {
            Err(e) => e,
            Ok(_) => panic!("expected an error for unknown condition"),
        };
        assert!(err.contains("service_banana"), "got: {err}");
    }

    #[test]
    fn conditional_dep_to_unknown_box_is_rejected() {
        let doc = "[box.a]\nimage=\"x\"\ndepends_healthy=[\"ghost\"]";
        assert!(topo_order(&parse(doc).unwrap()).is_err());
    }

    #[test]
    fn balanced_braces_accepts_wellformed_and_rejects_malformed() {
        assert!(balanced_braces("{ a = { condition = \"x\" } }").is_ok());
        assert!(balanced_braces("{}").is_ok());
        assert!(balanced_braces("{ a = { condition = \"}\" } }").is_ok()); // brace in quotes is literal
        assert!(balanced_braces("{ a = { condition = \"x\"").is_err()); // unterminated `{`
        assert!(balanced_braces("{ a = { condition = \"x\" } } }").is_err()); // over-close
        assert!(balanced_braces("{ a = \"unterminated").is_err()); // unterminated string
    }

    #[test]
    fn split_top_level_commas_respects_quotes_and_braces() {
        // Comma inside a nested brace is NOT a top-level split.
        let parts = split_top_level_commas("a = { condition = \"h\" }, b = { condition = \"c\" }");
        assert_eq!(parts.len(), 2);
        // Comma inside quotes is NOT a split.
        let q = split_top_level_commas("a = \"x,y\", b = \"z\"");
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn malformed_nested_depends_on_errors_never_panics() {
        // Each of these is a broken `depends_on` inline table. The contract: a clean parse Err, never
        // a panic (slicing, unwrap, underflow). This is user-supplied input (a third-party compose).
        let bad = [
            "{ a = { condition = \"service_healthy\"", // unterminated braces
            "{ a = { condition = \"service_healthy\" }", // one `}` short
            "{ a = { condition = \"x\" } } }",         // extra `}`
            "{ = { condition = \"service_healthy\" } }", // empty name
            "{ a = }", // missing spec (still routes: no cond → started, but name ok)
            "{ a = { condition = } }", // empty condition value
            "{ a = { condition = \"heal{thy,\" } }", // brace+comma inside quotes
            "{ a = { condition = \"héalthy\" } }", // multibyte in value (UTF-8 boundary)
            "{ a = { condition = \"banana\" } }", // unknown condition
            "{{{{{{{{{{}}}}}}}}}}", // deep nesting, no stack overflow
        ];
        for input in bad {
            let doc = format!("[box.a]\nimage=\"x\"\n[box.b]\nimage=\"x\"\ndepends_on = {input}");
            // Must return Ok or Err - the point is it does not panic. (`std::panic` would abort the
            // test.) A few of these are actually well-formed-but-benign (e.g. `{ a = }` → start-order),
            // which is fine; the invariant under test is "no panic on any of them".
            let _ = parse(&doc);
        }
    }

    #[test]
    fn exhaustive_short_strings_never_panic() {
        // Enumerate ALL length-6 strings over the structural ASCII alphabet - total coverage of the
        // short-input space where a brace/quote/comma scanner bug lives. Complements the randomized
        // test below (which reaches long inputs, multibyte, and deep nesting the enumeration can't).
        let alphabet = *b"{}\",=a";
        let n = alphabet.len();
        for i in 0..n.pow(6) {
            let mut buf = [0u8; 6];
            let mut x = i;
            for slot in buf.iter_mut() {
                *slot = alphabet[x % n];
                x /= n;
            }
            let s = std::str::from_utf8(&buf).unwrap();
            let _ = balanced_braces(s);
            let _ = split_top_level_commas(s);
            let _ = parse(&format!("[box.a]\nimage=\"x\"\ndepends_on = {s}"));
        }
    }

    #[test]
    fn randomized_fuzz_never_panics_incl_multibyte_and_deep_nesting() {
        // Property: `balanced_braces` / `split_top_level_commas` / `parse_depends` NEVER panic on any
        // input - Err or benign Ok only. This is the `cargo fuzz`-equivalent the review asked for,
        // run inline (the parser is a private fn in a bin crate, not reachable from the fuzz
        // workspace). Two classes the length-6 enumeration can't reach are covered HERE:
        //   * MULTIBYTE UTF-8 in values (`é`, `→`, emoji) - the byte-offset-slicing panic class. The
        //     scanner uses `char_indices`, so a multibyte char never splits a boundary; this proves it.
        //   * DEEP NESTING (`{{{…}}}` hundreds deep) - the recursion/stack-overflow class. The scanner
        //     is iterative, so depth is just a counter; this proves it doesn't blow the stack.
        // Deterministic LCG (no rng dep, reproducible): if this ever finds a panic, the seed+len make
        // it replayable.
        let alphabet: [&str; 12] = [
            "{",
            "}",
            "\"",
            ",",
            "=",
            " ",
            "a",
            "condition",
            "service_healthy",
            "é",
            "→",
            "🦀",
        ];
        let mut state: u64 = 0x9E3779B97F4A7C15; // fixed seed
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as usize
        };
        for _ in 0..20_000 {
            let len = next() % 40; // inputs up to ~40 tokens
            let mut s = String::new();
            for _ in 0..len {
                s.push_str(alphabet[next() % alphabet.len()]);
            }
            let _ = balanced_braces(&s);
            let _ = split_top_level_commas(&s);
            let _ = parse(&format!("[box.a]\nimage=\"x\"\ndepends_on = {s}"));
        }
        // Explicit pathological deep nesting - a single input the LCG is unlikely to build exactly.
        let deep_open = "{".repeat(2000);
        let deep = format!("{deep_open}{}", "}".repeat(2000));
        assert!(balanced_braces(&deep).is_ok()); // balanced, just deep - must not overflow
        let _ = parse(&format!("[box.a]\nimage=\"x\"\ndepends_on = {deep}"));
        // Unbalanced deep (2000 opens, no closes) → clean Err, no overflow.
        assert!(balanced_braces(&deep_open).is_err());
    }

    #[test]
    fn rejects_box_without_image_or_rootfs() {
        assert!(parse("[box.a]\ncommand=[\"x\"]").is_err());
    }

    #[test]
    fn parses_full_box_schema_mirroring_cli() {
        let doc = r#"
            [box.api]
            image = "alpine"
            workdir = "/srv"
            memory = "512m"
            cpus = "1.5"
            cpuset = "0-3"
            swap_max = "1g"
            pids_limit = "128"
            io_weight = "200"
            nice = "5"
            timeout = "30"
            hostname = "api-host"
            user = "1000:1000"
            ssh = "2222"
            ssh_key = "/keys/id.pub"
            health_cmd = "wget -q -O- localhost"
            health_interval = 15
            health_retries = "3"
            health_start_period = "10"
            health_timeout = "2"
            health_action = "restart"
            read_only = true
            net = true
            uid_range = false
            bind_rootfs = false
            restart = true
            tun = true
            volumes = ["/data:/data:ro", "/etc/app:/app"]
            env = ["LOG=debug", "PORT=8080"]
            env_file = ["/etc/app.env"]
            ports = ["127.0.0.1:8080:80"]
            secrets = ["db-pw:/run/secrets/db"]
            tmpfs = ["/tmp:64m"]
            cap_add = ["NET_ADMIN"]
            cap_drop = ["ALL"]
        "#;
        let b = &parse(doc).unwrap()[0];
        assert_eq!(b.workdir.as_deref(), Some("/srv"));
        assert_eq!(b.memory.as_deref(), Some("512m"));
        assert_eq!(b.cpus.as_deref(), Some("1.5"));
        assert_eq!(b.cpuset.as_deref(), Some("0-3"));
        assert_eq!(b.swap_max.as_deref(), Some("1g"));
        assert_eq!(b.pids_limit.as_deref(), Some("128"));
        assert_eq!(b.io_weight.as_deref(), Some("200"));
        assert_eq!(b.nice.as_deref(), Some("5"));
        assert_eq!(b.timeout.as_deref(), Some("30"));
        assert_eq!(b.hostname.as_deref(), Some("api-host"));
        assert_eq!(b.user.as_deref(), Some("1000:1000"));
        assert_eq!(b.ssh.as_deref(), Some("2222"));
        assert_eq!(b.ssh_key.as_deref(), Some("/keys/id.pub"));
        assert_eq!(b.health_cmd.as_deref(), Some("wget -q -O- localhost"));
        assert_eq!(b.health_interval, Some(15));
        assert_eq!(b.health_retries.as_deref(), Some("3"));
        assert_eq!(b.health_start_period.as_deref(), Some("10"));
        assert_eq!(b.health_timeout.as_deref(), Some("2"));
        assert_eq!(b.health_action.as_deref(), Some("restart"));
        assert!(b.read_only && b.net && b.restart && b.tun);
        assert!(!b.uid_range && !b.bind_rootfs);
        assert_eq!(b.volumes, ["/data:/data:ro", "/etc/app:/app"]);
        assert_eq!(b.env, ["LOG=debug", "PORT=8080"]);
        assert_eq!(b.env_file, ["/etc/app.env"]);
        assert_eq!(b.ports, ["127.0.0.1:8080:80"]);
        assert_eq!(b.secrets, ["db-pw:/run/secrets/db"]);
        assert_eq!(b.tmpfs, ["/tmp:64m"]);
        assert_eq!(b.cap_add, ["NET_ADMIN"]);
        assert_eq!(b.cap_drop, ["ALL"]);

        // The mirror flags are emitted in a stable order, using the frozen key→flag map.
        let mut cmd = std::process::Command::new("kern");
        b.push_box_flags(&mut cmd);
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.windows(2).any(|w| w == ["--cpuset-cpus", "0-3"]));
        assert!(args.windows(2).any(|w| w == ["--memory-swap-max", "1g"]));
        assert!(args.windows(2).any(|w| w == ["--pids-limit", "128"]));
        assert!(args.windows(2).any(|w| w == ["--io-weight", "200"]));
        assert!(args.windows(2).any(|w| w == ["--nice", "5"]));
        assert!(args.windows(2).any(|w| w == ["--timeout", "30"]));
        assert!(args.windows(2).any(|w| w == ["--hostname", "api-host"]));
        assert!(args.windows(2).any(|w| w == ["--user", "1000:1000"]));
        assert!(args.windows(2).any(|w| w == ["--ssh", "2222"]));
        assert!(args.windows(2).any(|w| w == ["--health-action", "restart"]));
        assert!(args
            .windows(2)
            .any(|w| w == ["--secret", "db-pw:/run/secrets/db"]));
        assert!(args.windows(2).any(|w| w == ["--cap-add", "NET_ADMIN"]));
        assert!(args.windows(2).any(|w| w == ["--cap-drop", "ALL"]));
        assert!(args.windows(2).any(|w| w == ["--env-file", "/etc/app.env"]));
        assert!(args
            .windows(2)
            .any(|w| w == ["--publish", "127.0.0.1:8080:80"]));
        assert!(args.iter().any(|a| a == "--read-only"));
        assert!(args.iter().any(|a| a == "--net"));
        assert!(args.iter().any(|a| a == "--tun"));
        // A `false` switch emits no flag.
        assert!(!args
            .iter()
            .any(|a| a == "--uid-range" || a == "--bind-rootfs"));
    }

    #[test]
    fn rejects_malformed_scalar_bool_and_int() {
        // A switch must be a real TOML bool, an interval a real integer, a scalar a quoted string.
        assert!(parse("[box.a]\nimage=\"x\"\nread_only=\"yes\"").is_err());
        assert!(parse("[box.a]\nimage=\"x\"\nhealth_interval=\"soon\"").is_err());
        assert!(parse("[box.a]\nimage=\"x\"\nhealth_interval=0").is_err()); // must be positive
        assert!(parse("[box.a]\nimage=\"x\"\nhealth_interval=-5").is_err());
        assert!(parse("[box.a]\nimage=\"x\"\nmemory=512m").is_err()); // unquoted
        assert!(parse("[box.a]\nimage=\"x\"\nbogus_key=\"v\"").is_err()); // unknown key
    }

    #[test]
    fn rejects_bad_box_name_and_empty_source_at_the_line() {
        // A crafted header is caught HERE (not just in the child kern box).
        assert!(parse("[box.--net]\nimage=\"x\"").is_err());
        assert!(parse("[box.a/b]\nimage=\"x\"").is_err());
        // An empty source is treated as absent.
        assert!(parse("[box.a]\nimage=\"\"").is_err());
    }
}

#[cfg(test)]
mod compat_field_tests {
    use super::*;

    fn one(yaml: &str) -> ComposeBox {
        let mut v = parse(yaml).expect("parses");
        assert_eq!(v.len(), 1, "expected exactly one service");
        v.remove(0)
    }

    #[test]
    fn extra_hosts_all_three_docker_spellings() {
        // List with ':', list with '=', and the mapping form - all normalised to kern's `name:ip`.
        let b = one("services:\n  a:\n    image: x\n    extra_hosts:\n      - \"api:10.0.0.5\"\n      - \"db=10.0.0.6\"\n");
        assert_eq!(b.add_host, ["api:10.0.0.5", "db:10.0.0.6"]);
        let m = one("services:\n  a:\n    image: x\n    extra_hosts:\n      cache: 10.0.0.7\n");
        assert_eq!(m.add_host, ["cache:10.0.0.7"]);
    }

    #[test]
    fn extra_hosts_keeps_ipv6_intact_and_drops_malformed() {
        // Splitting on the FIRST separator matters: an IPv6 value is full of colons.
        let b = one("services:\n  a:\n    image: x\n    extra_hosts:\n      - \"v6=::1\"\n      - \"nonsense\"\n");
        assert_eq!(
            b.add_host,
            ["v6:::1"],
            "only the well-formed entry survives"
        );
    }

    #[test]
    fn init_maps_to_the_flag() {
        assert!(one("services:\n  a:\n    image: x\n    init: true\n").init);
        assert!(!one("services:\n  a:\n    image: x\n    init: false\n").init);
        assert!(!one("services:\n  a:\n    image: x\n").init);
    }

    #[test]
    fn ulimits_scalar_and_mapping_forms() {
        let b = one("services:\n  a:\n    image: x\n    ulimits:\n      nofile: 1024\n      nproc:\n        soft: 512\n        hard: 1024\n");
        assert!(
            b.ulimits.contains(&"nofile=1024".to_string()),
            "{:?}",
            b.ulimits
        );
        assert!(
            b.ulimits.contains(&"nproc=512:1024".to_string()),
            "{:?}",
            b.ulimits
        );
    }

    #[test]
    fn ulimits_partial_mapping_reuses_the_given_bound() {
        // Docker tolerates only one of soft/hard; reusing it keeps `soft <= hard` true by construction.
        let b =
            one("services:\n  a:\n    image: x\n    ulimits:\n      nofile:\n        soft: 2048\n");
        assert_eq!(b.ulimits, ["nofile=2048"]);
    }

    #[test]
    fn sysctls_mapping_and_list_forms() {
        let m =
            one("services:\n  a:\n    image: x\n    sysctls:\n      net.core.somaxconn: 4096\n");
        assert_eq!(m.sysctls, ["net.core.somaxconn=4096"]);
        let l =
            one("services:\n  a:\n    image: x\n    sysctls:\n      - net.core.somaxconn=4096\n");
        assert_eq!(l.sysctls, ["net.core.somaxconn=4096"]);
    }

    #[test]
    fn flow_mappings_resolve_like_block_mappings() {
        // REGRESSION: `{...}` arrives as one opaque scalar. Before this was handled, an inline
        // `sysctls: {k: v}` reached the box as a single unparsable argument (hard error) and an inline
        // `ulimits: {nofile: N}` was dropped SILENTLY - a limit the operator wrote, not in force.
        let f = one("services:\n  a:\n    image: x\n    sysctls: {net.core.somaxconn: 1500}\n");
        assert_eq!(f.sysctls, ["net.core.somaxconn=1500"]);
        let l = one("services:\n  a:\n    image: x\n    labels: {app: web, tier: front}\n");
        assert_eq!(l.labels, ["app=web", "tier=front"]);
        let u = one("services:\n  a:\n    image: x\n    ulimits: {nofile: 2048}\n");
        assert_eq!(u.ulimits, ["nofile=2048"]);
        let h = one("services:\n  a:\n    image: x\n    extra_hosts: {h.local: 10.1.2.3}\n");
        assert_eq!(h.add_host, ["h.local:10.1.2.3"]);
        // Nested value: the comma inside the inner map must NOT split the outer one.
        let n =
            one("services:\n  a:\n    image: x\n    ulimits: {nofile: {soft: 256, hard: 512}}\n");
        assert_eq!(n.ulimits, ["nofile=256:512"]);
        // Two ulimits, one of them nested - depth tracking on the top-level comma.
        let m = one(
            "services:\n  a:\n    image: x\n    ulimits: {nproc: 64, nofile: {soft: 1, hard: 2}}\n",
        );
        assert!(
            m.ulimits.contains(&"nproc=64".to_string()),
            "{:?}",
            m.ulimits
        );
        assert!(
            m.ulimits.contains(&"nofile=1:2".to_string()),
            "{:?}",
            m.ulimits
        );
    }

    #[test]
    fn bare_dollar_var_is_interpolated_like_docker() {
        // Docker substitutes a BARE `$NAME` exactly like `${NAME}`; kern left it literal, so
        // `image: myapp:$TAG` shipped the string "$TAG" as a tag.
        std::env::set_var("KERN_BARE_T", "3.19");
        let b = one("services:\n  a:\n    image: \"alpine:$KERN_BARE_T\"\n");
        assert_eq!(b.image.as_deref(), Some("alpine:3.19"));
        std::env::remove_var("KERN_BARE_T");
    }

    #[test]
    fn dollar_forms_docker_does_not_touch_stay_literal() {
        // `$(cmd)`, `$1` and `$$` must survive for the in-box shell: interpolating them would rewrite
        // a command's meaning. `$$` is the documented escape for a literal `$`.
        let b = one(
            "services:\n  a:\n    image: alpine\n    command: sh -c \"echo $(date) $1 $$HOME\"\n",
        );
        let cmd = b.command.join(" ");
        assert!(cmd.contains("$(date)"), "{cmd}");
        assert!(cmd.contains("$1"), "{cmd}");
        assert!(cmd.contains("$HOME") && !cmd.contains("$$HOME"), "{cmd}");
    }

    #[test]
    fn merge_stacks_follows_the_documented_rules() {
        let base = parse("services:\n  a:\n    image: alpine\n    command: base\n    ports: [\"1:1\"]\n    environment: [X=1]\n").expect("base");
        let over = parse_override("services:\n  a:\n    command: over\n    ports: [\"2:2\"]\n    environment: [Y=2]\n  b:\n    image: busybox\n", &DotEnv::default()).expect("override");
        let m = merge_stacks(base, over);
        assert_eq!(m.len(), 2, "a service only in the override is added");
        let a = m.iter().find(|b| b.name == "a").expect("a");
        assert_eq!(
            a.image.as_deref(),
            Some("alpine"),
            "base scalar kept when the override omits it"
        );
        // A shell-form `command:` is recorded as `sh -c <string>`, so assert on content: the
        // override's argv is there and the base's is GONE (a concatenation would keep both).
        let cmd = a.command.join(" ");
        assert!(
            cmd.contains("over") && !cmd.contains("base"),
            "argv REPLACES, never concatenates: {cmd}"
        );
        assert_eq!(a.ports, ["1:1", "2:2"], "sequences append, override last");
        assert_eq!(a.env, ["X=1", "Y=2"]);
    }

    #[test]
    fn an_override_layer_needs_no_image_but_the_result_does() {
        // The whole point of `-f base -f override`: the override restates only what it changes.
        let over = parse_override(
            "services:\n  a:\n    environment: [X=1]\n",
            &DotEnv::default(),
        )
        .expect("override parses without image");
        assert!(
            validate_runnable(&over).is_err(),
            "…but the merged result must still be runnable"
        );
        let base = parse("services:\n  a:\n    image: alpine\n").expect("base");
        assert!(validate_runnable(&merge_stacks(base, over)).is_ok());
    }

    #[test]
    fn depends_completed_on_an_always_service_is_refused_not_hung() {
        // `always`/`unless-stopped` never completes; a `service_completed_successfully` dependency on it
        // would wait forever. Docker rejects the combination at validation; kern must too, naming both.
        let dep = |policy: &str| {
            format!(
                "services:\n  migrate:\n    image: x\n    restart: {policy}\n  \
                 api:\n    image: y\n    depends_on:\n      migrate:\n        \
                 condition: service_completed_successfully\n"
            )
        };
        for policy in ["always", "unless-stopped"] {
            // `parse` may run `validate_runnable` itself or leave it to the caller; the contradiction
            // must be refused on either path.
            let refused = match parse(&dep(policy)) {
                Err(e) => e,
                Ok(boxes) => validate_runnable(&boxes).expect_err(&format!(
                    "must refuse depends_completed on a '{policy}' service"
                )),
            };
            assert!(
                refused.contains("migrate") && refused.contains("api"),
                "the error names both services: {refused}"
            );
        }
        // `on-failure` DOES complete (it stops on a zero exit), so the dependency is satisfiable.
        let ok = parse(&dep("on-failure")).expect("on-failure parses");
        assert!(
            validate_runnable(&ok).is_ok(),
            "on-failure completes on success, so a completion dependency on it is fine"
        );
    }

    #[test]
    fn on_failure_with_a_count_caps_the_retries() {
        // `on-failure:3` exists to give up when the author said, not merely to give up eventually.
        let b = one("services:\n  a:\n    image: x\n    restart: \"on-failure:3\"\n");
        assert!(b.restart, "still an on-failure policy");
        assert_eq!(b.restart_max.as_deref(), Some("3"));
        // A plain policy leaves the cap to kern's default.
        assert_eq!(
            one("services:\n  a:\n    image: x\n    restart: on-failure\n").restart_max,
            None
        );
        // A malformed count falls back to the default rather than silently meaning zero retries.
        assert_eq!(
            one("services:\n  a:\n    image: x\n    restart: \"on-failure:abc\"\n").restart_max,
            None
        );
    }

    #[test]
    fn restart_always_is_honored_not_degraded() {
        // `always`/`unless-stopped` are no longer flattened to on-failure: they set `restart_always`,
        // which emits `--restart always` so a pod member is kept up on ANY exit (including a clean 0).
        for policy in ["always", "unless-stopped"] {
            let b = one(&format!(
                "services:\n  a:\n    image: x\n    restart: {policy}\n"
            ));
            assert!(
                b.restart && b.restart_always,
                "'{policy}' → restart on any exit"
            );
            let mut cmd = std::process::Command::new("kern");
            b.push_box_flags(&mut cmd);
            let args: Vec<String> = cmd
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            assert!(
                args.windows(2).any(|w| w == ["--restart", "always"]),
                "'{policy}' emits `--restart always`, got {args:?}"
            );
        }
        // `on-failure` stays on-failure (not 'always'): a bare `--restart`, no value.
        let b = one("services:\n  a:\n    image: x\n    restart: on-failure\n");
        assert!(b.restart && !b.restart_always);
    }

    #[test]
    fn merge_preserves_an_override_introduced_restart_always() {
        // The multi-file path (`-f base -f override`) merges each override box over the base via
        // `merge_from`. `restart: always` set ONLY in an override must survive, or it silently degrades
        // to on-failure and a service that exits 0 stays dead instead of being kept up. The all-fields
        // merge test cannot catch this: it builds from TOML, whose `restart` key sets `restart` but
        // never `restart_always` (only YAML's `apply_restart` does), so the field is false on both
        // sides and the debug-compare is blind to it.
        let over = one("services:\n  a:\n    image: x\n    restart: always\n");
        assert!(
            over.restart && over.restart_always,
            "control: parse sets both"
        );
        let mut base = one("services:\n  a:\n    image: x\n    restart: \"no\"\n");
        assert!(!base.restart_always, "control: base carries no 'always'");
        base.merge_from(over);
        assert!(
            base.restart && base.restart_always,
            "an override's `restart: always` must survive merge_from, not degrade to on-failure"
        );
    }

    #[test]
    fn stop_contract_maps_to_flags_and_seconds() {
        // Without this contract every service is hard-killed: redis loses whatever it had not saved
        // and postgres does crash recovery on the NEXT start, on every stop.
        let b = one("services:\n  a:\n    image: x\n    stop_signal: SIGUSR1\n    stop_grace_period: 1m30s\n");
        assert_eq!(b.stop_signal.as_deref(), Some("SIGUSR1"));
        // Docker writes durations; the flag takes seconds.
        assert_eq!(b.stop_grace_period.as_deref(), Some("90"));
        for (written, secs) in [("10s", "10"), ("2m", "120"), ("0s", "0"), ("45", "45")] {
            let g = one(&format!(
                "services:\n  a:\n    image: x\n    stop_grace_period: {written}\n"
            ));
            assert_eq!(g.stop_grace_period.as_deref(), Some(secs), "{written}");
        }
        // Sub-second rounds UP: `500ms` asked for a graceful phase, and 0 would mean none at all.
        let ms = one("services:\n  a:\n    image: x\n    stop_grace_period: 500ms\n");
        assert_eq!(ms.stop_grace_period.as_deref(), Some("1"));
    }

    #[test]
    fn flow_mapping_values_keep_their_colons() {
        // The key ends at the FIRST top-level ':'; a value with colons (URL, IPv6) stays whole.
        let l = one("services:\n  a:\n    image: x\n    labels: {url: http://h:8080/p}\n");
        assert_eq!(l.labels, ["url=http://h:8080/p"]);
    }

    #[test]
    fn labels_mapping_and_list_forms() {
        let m = one("services:\n  a:\n    image: x\n    labels:\n      app: web\n");
        assert_eq!(m.labels, ["app=web"]);
        let l = one("services:\n  a:\n    image: x\n    labels:\n      - app=web\n");
        assert_eq!(l.labels, ["app=web"]);
    }

    #[test]
    fn all_five_reach_the_box_command_line() {
        // The end that matters: each field must become the kern flag that implements it. A field
        // parsed but never emitted would be exactly the silent no-op these fixes removed.
        let b = one(
            "services:\n  a:\n    image: x\n    init: true\n    extra_hosts: [\"h:1.2.3.4\"]\n             \n    ulimits:\n      nofile: 64\n    sysctls:\n      net.core.somaxconn: 8\n             \n    labels:\n      app: web\n",
        );
        let mut cmd = std::process::Command::new("kern");
        b.push_box_flags(&mut cmd);
        let argv: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for expected in [
            "--init",
            "--add-host",
            "h:1.2.3.4",
            "--ulimit",
            "nofile=64",
            "--sysctl",
            "net.core.somaxconn=8",
            "--label",
            "app=web",
        ] {
            assert!(
                argv.iter().any(|a| a == expected),
                "{expected:?} missing from {argv:?}"
            );
        }
    }
}

#[cfg(test)]
mod dotenv_tests {
    use super::*;

    fn v(text: &str, key: &str) -> Option<String> {
        parse_dotenv(text).get(key).map(str::to_string)
    }

    #[test]
    fn plain_bindings_and_both_delimiters() {
        let e = parse_dotenv("A=1\nB:2\n");
        assert_eq!(e.get("A"), Some("1"));
        assert_eq!(
            e.get("B"),
            Some("2"),
            "Docker accepts `:` as a delimiter too"
        );
        assert_eq!(e.get("MISSING"), None);
        assert_eq!(e.len(), 2);
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let e = parse_dotenv("# commento\n\n   \n#A=nascosto\nA=visibile\n");
        assert_eq!(e.get("A"), Some("visibile"));
        assert_eq!(e.len(), 1, "only the one real binding: {e:?}");
    }

    #[test]
    fn spaces_around_key_and_value_are_trimmed() {
        assert_eq!(v("  A  =   1   \n", "A").as_deref(), Some("1"));
    }

    #[test]
    fn export_prefix_is_tolerated() {
        // Shells write `export K=V` into these files; Docker reads the binding either way.
        assert_eq!(v("export A=1\n", "A").as_deref(), Some("1"));
    }

    #[test]
    fn first_delimiter_wins_so_urls_keep_their_colons() {
        assert_eq!(
            v("URL=http://host:5432/db\n", "URL").as_deref(),
            Some("http://host:5432/db")
        );
        // …and a `:`-delimited key whose value contains `=` keeps the `=`.
        assert_eq!(v("Q:a=b\n", "Q").as_deref(), Some("a=b"));
    }

    #[test]
    fn single_quotes_are_literal() {
        // No escape processing, no interpolation - the value is exactly what is between the quotes.
        assert_eq!(
            v("A='ciao \\n $NOPE'\n", "A").as_deref(),
            Some("ciao \\n $NOPE")
        );
    }

    #[test]
    fn double_quotes_decode_escapes() {
        assert_eq!(
            v(r#"A="riga1\nriga2""#, "A").as_deref(),
            Some("riga1\nriga2")
        );
        assert_eq!(v(r#"A="tab\there""#, "A").as_deref(), Some("tab\there"));
        assert_eq!(v(r#"A="back\\slash""#, "A").as_deref(), Some("back\\slash"));
        assert_eq!(v(r#"A="say \"hi\"""#, "A").as_deref(), Some("say \"hi\""));
    }

    #[test]
    fn inline_comments() {
        // Unquoted: only a SPACE-prefixed `#` starts a comment, so a `#` glued to the value stays.
        assert_eq!(v("A=valore # nota\n", "A").as_deref(), Some("valore"));
        assert_eq!(v("A=#ffffff\n", "A").as_deref(), Some("#ffffff"));
        assert_eq!(v("A=col#ore\n", "A").as_deref(), Some("col#ore"));
        // Quoted: the comment follows the closing quote and is dropped.
        assert_eq!(
            v("A=\"con spazi\"  # nota\n", "A").as_deref(),
            Some("con spazi")
        );
        assert_eq!(
            v("A='letterale'  # nota\n", "A").as_deref(),
            Some("letterale")
        );
    }

    #[test]
    fn last_definition_wins() {
        // A file that binds the same key twice behaves like a shell sourcing it top to bottom.
        assert_eq!(v("A=primo\nA=secondo\n", "A").as_deref(), Some("secondo"));
    }

    #[test]
    fn malformed_lines_are_skipped_never_fatal() {
        // Total function: a stray line must not take the stack down (Docker tolerates these files).
        let e =
            parse_dotenv("questa riga non ha delimitatore\n=senza_chiave\nA B=due parole\nOK=1\n");
        assert_eq!(e.get("OK"), Some("1"));
        assert_eq!(e.len(), 1, "only the well-formed binding survives: {e:?}");
    }

    #[test]
    fn empty_and_edge_values() {
        assert_eq!(v("A=\n", "A").as_deref(), Some(""));
        assert_eq!(v("A=''\n", "A").as_deref(), Some(""));
        assert_eq!(v("A=\"\"\n", "A").as_deref(), Some(""));
        // Unterminated quote: keep the rest rather than silently dropping the value.
        assert_eq!(v("A='non chiusa\n", "A").as_deref(), Some("non chiusa"));
        // No trailing newline at EOF.
        assert_eq!(v("A=1", "A").as_deref(), Some("1"));
    }

    #[test]
    fn dollar_is_left_for_the_document_pass() {
        // `${…}` inside a value must survive verbatim: kern interpolates ONCE over the whole compose
        // document after merging env + .env. Expanding here would substitute twice.
        assert_eq!(v("A=${B}\n", "A").as_deref(), Some("${B}"));
    }

    #[test]
    fn shell_environment_wins_over_dotenv() {
        // Docker precedence: shell > .env. Verified through the real interpolation path. The var
        // name is unique to this test, so it needs no lock against the other env-touching tests.
        let de = parse_dotenv("KERN_DOTENV_PREC_TEST=da-dotenv\n");
        let yaml =
            "services:\n  a:\n    image: alpine\n    command: echo ${KERN_DOTENV_PREC_TEST}\n";

        let only_dotenv = parse_with_env(yaml, &de).expect("parses");
        assert!(
            only_dotenv[0].command.join(" ").contains("da-dotenv"),
            "unset in the shell → the .env value is used: {:?}",
            only_dotenv[0].command
        );

        std::env::set_var("KERN_DOTENV_PREC_TEST", "da-shell");
        let with_shell = parse_with_env(yaml, &de).expect("parses");
        std::env::remove_var("KERN_DOTENV_PREC_TEST");
        assert!(
            with_shell[0].command.join(" ").contains("da-shell"),
            "the shell must WIN over .env: {:?}",
            with_shell[0].command
        );
    }

    #[test]
    fn totality_under_random_input() {
        // `parse_dotenv` is documented as TOTAL: any byte string yields a table, never a panic. The
        // slicing inside it is index-arithmetic on `find()` results and on quote characters, so a
        // wrong assumption about char boundaries would panic on multibyte input. Deterministic
        // xorshift (no `rand` dependency, reproducible on failure) over the bytes most likely to break
        // it: quotes, backslashes, delimiters, `#`, and multibyte UTF-8.
        let alphabet: &[&str] = &[
            "=", ":", "#", "'", "\"", "\\", " ", "\n", "\t", "A", "1", "export ", "$", "{", "}",
            "à", "€", "🦀", "\u{feff}", "",
        ];
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..100_000 {
            let len = (next() % 24) as usize;
            let mut s = String::new();
            for _ in 0..len {
                s.push_str(alphabet[(next() as usize) % alphabet.len()]);
            }
            let e = parse_dotenv(&s);
            // Whatever comes back must be self-consistent: every key it reports is retrievable.
            for (k, _) in &e.0 {
                assert!(e.get(k).is_some(), "key {k:?} not retrievable from {s:?}");
            }
        }
    }

    #[test]
    fn no_dotenv_behaves_exactly_as_before() {
        // The default table must change nothing for a project without a `.env`.
        let yaml =
            "services:\n  a:\n    image: alpine\n    command: echo ${KERN_NO_DOTENV_XYZ:-def}\n";
        assert_eq!(
            parse_with_env(yaml, &DotEnv::default()).map(|b| b[0].command.clone()),
            parse(yaml).map(|b| b[0].command.clone())
        );
    }
    /// The per-image uid-range default is `kern box`'s to apply, so compose must forward INTENT and
    /// nothing else: `--uid-range` only when the file asked, `--no-uid-range` only for a deliberate
    /// opt-out, and NEITHER for a plain image box (whose default is applied downstream). Emitting the
    /// default here would state the rule twice and make every image box look like an explicit request.
    #[test]
    fn push_box_flags_forwards_uid_range_intent_not_the_image_default() {
        let argv = |src: &str| -> Vec<String> {
            let s = parse(src).expect("parses");
            let mut cmd = std::process::Command::new("kern");
            s[0].push_box_flags(&mut cmd);
            cmd.get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };

        // A plain image box: neither flag - `kern box` turns the range on for `--image` itself.
        let plain = argv("[box.a]\nimage = \"redis\"\n");
        assert!(!plain.iter().any(|a| a == "--uid-range"));
        assert!(!plain.iter().any(|a| a == "--no-uid-range"));
        // ...but it still says `--image`, which is what makes that default fire downstream.
        assert!(plain.windows(2).any(|w| w == ["--image", "redis"]));

        // An explicit ask travels, and stays distinguishable from the default.
        let asked = argv("[box.a]\nimage = \"redis\"\nuid_range = true\n");
        assert!(asked.iter().any(|a| a == "--uid-range"));

        // A deliberate opt-out must travel too, or the downstream default would silently undo it.
        let off = argv("[box.a]\nimage = \"redis\"\nuid_range = false\n");
        assert!(off.iter().any(|a| a == "--no-uid-range"));
        assert!(!off.iter().any(|a| a == "--uid-range"));

        // A rootfs box keeps the single-uid map: no flag either way.
        let rootfs = argv("[box.a]\nrootfs = \"/tmp/r\"\n");
        assert!(!rootfs.iter().any(|a| a == "--uid-range"));
        assert!(!rootfs.iter().any(|a| a == "--no-uid-range"));
    }

    /// `wants_uid_range` is the pod holder's input: it must answer for the whole rule, since a member
    /// setns's into the holder's map and can't add a range of its own afterwards.
    #[test]
    fn wants_uid_range_covers_ask_and_image_default() {
        let one = |src: &str| parse(src).expect("parses").remove(0);
        assert!(one("[box.a]\nimage = \"redis\"\n").wants_uid_range());
        assert!(one("[box.a]\nrootfs = \"/tmp/r\"\nuid_range = true\n").wants_uid_range());
        assert!(!one("[box.a]\nimage = \"redis\"\nuid_range = false\n").wants_uid_range());
        assert!(!one("[box.a]\nrootfs = \"/tmp/r\"\n").wants_uid_range());
    }
    /// `port:` exists so an INTERNAL-only service is visible to the pod preflight, and so a user has
    /// the way out that Docker solves with separate networks. Every branch of the declaration is
    /// pinned here, including the two that would silently do the wrong thing: a `0` (which means
    /// "any free port" to `bind()`, so it could never be compared against anything) and an explicit
    /// `PORT` in `environment:`, which must always beat kern's injection.
    #[test]
    fn declared_port_parses_injects_and_refuses_a_contradiction() {
        let one = |src: &str| parse(src).expect("parses").remove(0);

        let b = one("[box.api]\nimage = \"node\"\nport = 3000\n");
        assert_eq!(b.port, Some(3000));
        assert_eq!(b.port_env().as_deref(), Some("PORT=3000"));

        // The user's own PORT wins: `port:` is then only a declaration for the preflight.
        let owned = one("[box.api]\nimage = \"node\"\nport = 3000\nenv = [\"PORT=9999\"]\n");
        assert_eq!(owned.port, Some(3000));
        assert_eq!(
            owned.port_env(),
            None,
            "kern must not overwrite a stated PORT"
        );

        // Even an empty `PORT=` is a deliberate statement and must not be overwritten.
        let empty = one("[box.api]\nimage = \"node\"\nport = 3000\nenv = [\"PORT=\"]\n");
        assert_eq!(empty.port_env(), None);

        // No declaration, nothing injected: a stack that never mentions ports is untouched.
        let none = one("[box.api]\nimage = \"node\"\n");
        assert_eq!(none.port, None);
        assert_eq!(none.port_env(), None);

        // Boundaries and refusals.
        assert_eq!(
            one("[box.a]\nimage = \"x\"\nport = 65535\n").port,
            Some(65535)
        );
        assert_eq!(one("[box.a]\nimage = \"x\"\nport = 1\n").port, Some(1));
        assert!(
            parse("[box.a]\nimage = \"x\"\nport = 0\n").is_err(),
            "0 is not a declared port"
        );
        assert!(
            parse("[box.a]\nimage = \"x\"\nport = 65536\n").is_err(),
            "out of u16 range"
        );
        assert!(
            parse("[box.a]\nimage = \"x\"\nport = -1\n").is_err(),
            "negative"
        );
        assert!(
            parse("[box.a]\nimage = \"x\"\nport = \"http\"\n").is_err(),
            "not a number"
        );
    }

    /// The injected pair must travel in the argv, and must not appear when there is nothing to inject.
    #[test]
    fn push_box_flags_carries_the_injected_port() {
        let argv = |src: &str| -> Vec<String> {
            let s = parse(src).expect("parses");
            let mut cmd = std::process::Command::new("kern");
            s[0].push_box_flags(&mut cmd);
            cmd.get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };
        let with = argv("[box.a]\nimage = \"node\"\nport = 3000\n");
        assert!(
            with.windows(2).any(|w| w == ["--env", "PORT=3000"]),
            "got {with:?}"
        );

        let without = argv("[box.a]\nimage = \"node\"\n");
        assert!(
            !without.iter().any(|a| a.starts_with("PORT=")),
            "got {without:?}"
        );

        // A stated PORT travels once, from the user, never twice.
        let stated = argv("[box.a]\nimage = \"node\"\nport = 3000\nenv = [\"PORT=3000\"]\n");
        assert_eq!(
            stated.iter().filter(|a| a.starts_with("PORT=")).count(),
            1,
            "got {stated:?}"
        );
        assert!(stated.contains(&"PORT=3000".to_string()));
    }
    /// STRUCTURAL GUARD. A field that reaches the struct but not `merge_from` is dropped SILENTLY
    /// by an override file, which is the worst shape a defect can take in a merge: the file says one
    /// thing, the stack does another, and nothing reports it. Four fields were already in that state
    /// (`port`, `restart_max`, `stop_signal`, `stop_grace_period`).
    ///
    /// The test does NOT list the fields by hand, which would repeat the very mistake it exists to
    /// catch: it merges a COMPLETE box over an empty one and compares the `Debug` representation
    /// against the same box unmerged. Any field `merge_from` forgets shows up as a difference, and
    /// the next field added is covered without touching this test.
    #[test]
    fn every_optional_field_survives_a_merge() {
        // Every key the parser knows, each with a non-default value.
        const FULL: &str = concat!(
            "[box.a]\n",
            "image = \"img\"\n",
            "workdir = \"/w\"\n",
            "memory = \"64m\"\n",
            "cpus = \"1.5\"\n",
            "cpuset = \"0-1\"\n",
            "swap_max = \"1g\"\n",
            "pids_limit = \"128\"\n",
            "io_weight = \"200\"\n",
            "nice = \"5\"\n",
            "timeout = \"30\"\n",
            "hostname = \"h\"\n",
            "user = \"1000:1000\"\n",
            "ssh = \"2222\"\n",
            "ssh_key = \"/k.pub\"\n",
            "health_cmd = \"true\"\n",
            "health_interval = 15\n",
            "health_retries = \"3\"\n",
            "health_start_period = \"10\"\n",
            "health_timeout = \"2\"\n",
            "health_action = \"restart\"\n",
            "port = 3000\n",
            "expose = [\"3000\", \"53/udp\"]\n",
            "restart = true\n",
            "restart_max = \"3\"\n",
            "stop_signal = \"SIGINT\"\n",
            "stop_grace_period = \"30\"\n",
            "vcpu = \"ml\"\n",
            "vdisk = \"scratch\"\n",
            "vgpio = \"leds\"\n",
            "security_profile = \"untrusted\"\n",
            "read_only = true\n",
            "net = true\n",
            "uid_range = true\n",
            "bind_rootfs = true\n",
            "tun = true\n",
            "init = true\n",
            "add_host = [\"h:1.2.3.4\"]\n",
            "volumes = [\"/a:/a\"]\n",
            "env = [\"K=V\"]\n",
            "env_file = [\"/e\"]\n",
            "ports = [\"1:2\"]\n",
            "secrets = [\"s:/s\"]\n",
            "tmpfs = [\"/t:1m\"]\n",
            "cap_add = [\"NET_ADMIN\"]\n",
            "cap_drop = [\"ALL\"]\n",
            "labels = [\"l=1\"]\n",
            "ulimits = [\"nofile=1024\"]\n",
            "sysctls = [\"net.core.somaxconn=1024\"]\n",
            "command = [\"true\"]\n",
        );

        // Two identical instances: one stays the reference, the other is merged over an empty box.
        let reference = parse(FULL).expect("parses").remove(0);
        let overriding = parse(FULL).expect("parses").remove(0);
        let mut base = ComposeBox::new("a".to_string());
        base.merge_from(overriding);

        assert_eq!(
            format!("{base:?}"),
            format!("{reference:?}"),
            "un campo non sopravvive a merge_from: confronta le due righe e cerca il campo che \
             differisce, poi aggiungilo alla macro giusta (opt!/flag!/seq!)"
        );

        // Positive control: if the merge did NOTHING, the assertion above would have to fail.
        // Without it, a gutted `merge_from` would pass whenever the reference is empty too.
        let empty = ComposeBox::new("a".to_string());
        assert_ne!(
            format!("{empty:?}"),
            format!("{reference:?}"),
            "il riferimento deve essere diverso da una scatola vuota, altrimenti non prova nulla"
        );
    }
    /// `expose:` is the Compose spelling of what `port:` declares, so it lands in the same pod port
    /// space. The syntax has three shapes and two ways of being wrong, and one reader has to
    /// interpret all of them the same way for both spellings of the file.
    #[test]
    fn expose_entries_parse_every_docker_form_and_refuse_the_rest() {
        assert_eq!(parse_expose_entry("3000"), Ok((3000, false)));
        assert_eq!(parse_expose_entry("3000/tcp"), Ok((3000, false)));
        assert_eq!(parse_expose_entry("53/udp"), Ok((53, true)));
        // Upper case accepted: refusing an otherwise valid file costs more than tolerating it.
        assert_eq!(parse_expose_entry("3000/TCP"), Ok((3000, false)));
        assert_eq!(parse_expose_entry("53/UDP"), Ok((53, true)));
        assert_eq!(parse_expose_entry("  8080  "), Ok((8080, false)));
        assert_eq!(parse_expose_entry("65535"), Ok((65535, false)));
        assert_eq!(parse_expose_entry("1"), Ok((1, false)));

        // A range is refused BY NAME, not silently expanded.
        let r = parse_expose_entry("3000-3005").expect_err("range");
        assert!(r.contains("range") && r.contains("3000-3005"), "{r}");

        // Zero, out of range, unknown protocol, plain text: all refused.
        for bad in ["0", "65536", "-1", "3000/sctp", "http", "", "3000/", "/udp"] {
            assert!(
                parse_expose_entry(bad).is_err(),
                "'{bad}' doveva essere rifiutato"
            );
        }
    }

    /// The two spellings share the PARSER but not the DISPOSAL of a malformed entry, and the
    /// difference is a choice rather than an inconsistency: the TOML is kern's own format, where a
    /// typo is said at once with its line, and the YAML is someone else's file, where refusing a
    /// whole stack over one line of pure documentation would be the wrong trade.
    ///
    /// This holds BOTH of them in one place. They had already drifted apart while a comment asserted
    /// that they could not, because nobody had ever asserted them together.
    #[test]
    fn range_disposition_differs_by_spelling_on_purpose() {
        let yaml = "services:\n  a:\n    image: alpine\n    expose: [\"3000-3005\"]\n";
        let toml = "[box.a]\nimage = \"alpine\"\nexpose = [\"3000-3005\"]\n";

        // YAML: accepted, the range skipped, the rest of the service untouched.
        let parsed = parse(yaml).expect("un intervallo non deve far fallire un compose YAML");
        assert_eq!(parsed.len(), 1);
        assert!(
            parsed[0].expose.is_empty(),
            "l'intervallo va saltato, non espanso"
        );
        assert_eq!(parsed[0].image.as_deref(), Some("alpine"));

        // TOML: refused, and the message names the line and the value.
        let e = parse(toml).expect_err("un intervallo deve far fallire un profilo kern");
        assert!(e.contains("3000-3005") && e.contains("range"), "{e}");

        // Positive control: a VALID entry reaches the same conclusion in both spellings, which is
        // what sharing the parser is supposed to guarantee.
        for src in [
            "services:\n  a:\n    image: alpine\n    expose: [\"53/udp\"]\n",
            "[box.a]\nimage = \"alpine\"\nexpose = [\"53/udp\"]\n",
        ] {
            let p = parse(src).expect("voce valida");
            assert_eq!(p[0].expose, vec![(53, true)], "grafie in disaccordo: {src}");
        }
    }

    /// The three port sources (`port:`, `expose:`, `ports:`) are the same statement and must land
    /// in the same space, or the preflight only protects whichever one it happens to look at. This
    /// checks that the parser carries all three through to the struct.
    #[test]
    fn expose_reaches_the_box_from_both_spellings() {
        let b = parse("[box.a]\nimage = \"x\"\nexpose = [\"3000\", \"53/udp\"]\n")
            .expect("parses")
            .remove(0);
        assert_eq!(b.expose, vec![(3000, false), (53, true)]);

        // A malformed entry in a kern profile is a file error, not a warning: the profile is
        // written for kern, so there is no "otherwise valid file" to rescue.
        assert!(parse("[box.a]\nimage = \"x\"\nexpose = [\"3000-3005\"]\n").is_err());
    }
}

/// Contract tests: invariants about the SHAPE of this module rather than its behaviour. They read
/// this file's own source, so they cannot describe code that is no longer here.
#[cfg(test)]
mod contract_tests {
    /// Every field of `ComposeBox` must REACH the box, or be named here with the reader that consumes
    /// it. A field can be parsed out of a compose file, stored, and then referenced by nothing at all:
    /// the file said something, kern accepted it, and it changed nothing. That is not hypothetical
    /// bookkeeping, it is the exact shape of every defect found in the publishing path (a port
    /// announced and never bound, a device grant dropped in silence, a disk-backed vdisk that was
    /// RAM). Here it would be worse, because compose SHELLS OUT: a field missing from
    /// `push_box_flags` never becomes an argument, and `kern box` cannot warn about a flag it was
    /// never given.
    ///
    /// The check parses THIS file, so it cannot drift from the code it describes, and it fails with
    /// the field name rather than a count. Adding a field to `ComposeBox` now forces a decision:
    /// forward it, or state who reads it.
    ///
    /// Deliberately strict about the allowlist: each entry carries its consumer, so "it is handled
    /// somewhere" is not an acceptable answer to this test.
    #[test]
    fn every_compose_field_is_forwarded_or_has_a_named_reader() {
        const SRC: &str = include_str!("lib.rs");

        // Field names of `pub struct ComposeBox { ... }`, ignoring doc comments and attributes.
        let struct_body = {
            let start = SRC
                .find("pub struct ComposeBox {")
                .expect("struct ComposeBox must exist");
            let rest = &SRC[start..];
            let end = rest
                .find("\n}\n")
                .expect("struct must be closed at column 0");
            &rest[..end]
        };
        let mut fields: Vec<&str> = Vec::new();
        for line in struct_body.lines() {
            let t = line.trim_start();
            if let Some(rest) = t.strip_prefix("pub ") {
                if let Some((name, _)) = rest.split_once(':') {
                    let name = name.trim();
                    if !name.is_empty()
                        && name
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
                    {
                        fields.push(name);
                    }
                }
            }
        }
        assert!(
            fields.len() > 30,
            "the field scan found only {} fields, so it is not reading the struct",
            fields.len()
        );

        // Everything `push_box_flags` touches, as `self.<ident>`.
        let fn_body = {
            let start = SRC
                .find("pub fn push_box_flags(&self, cmd: &mut std::process::Command) {")
                .expect("push_box_flags must exist");
            let rest = &SRC[start..];
            let end = rest
                .find("\n    }\n")
                .expect("push_box_flags must be closed");
            &rest[..end]
        };
        let mut forwarded: Vec<&str> = Vec::new();
        let mut cur = fn_body;
        while let Some(i) = cur.find("self.") {
            let tail = &cur[i + 5..];
            let n = tail
                .find(|c: char| !(c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()))
                .unwrap_or(tail.len());
            if n > 0 {
                forwarded.push(&tail[..n]);
            }
            cur = &tail[n..];
        }

        // Field -> the reader that consumes it instead of `push_box_flags`. Structural fields are the
        // command line's shape, not a flag; the rest name a real call site.
        const READERS: &[(&str, &str)] = &[
            ("name", "the `kern box <name>` argument itself"),
            (
                "container_name",
                "compose() names the box this exactly instead of <project>-<service>",
            ),
            (
                "service",
                "`compose ... config` prints it: the FILE's name for this service, kept when \
                 resolve_box_names() rewrites `name` to the box name",
            ),
            ("command", "the trailing `-- <command>`"),
            (
                "depends_on",
                "topo_order / all_deps: start ordering, compose-only",
            ),
            ("depends_healthy", "all_deps + the health wait before start"),
            ("depends_completed", "all_deps + the run-to-completion wait"),
            ("build", "`kern build` runs before the box exists"),
            (
                "port",
                "port_env() injects PORT=, and check_pod_global_conflicts claims the slot",
            ),
            (
                "expose",
                "check_pod_global_conflicts: a claim on the pod's shared namespace",
            ),
            (
                "profiles",
                "the YAML parser DROPS an inactive service, so it never reaches a command line",
            ),
            // Read by `profile_tokens`, which `push_box_flags` appends: the scanner below only sees
            // `self.<field>` written in that function's own body, and these three are consumed one
            // call away so the normalisation stays unit-testable without building a `Command`.
            (
                "vcpu",
                "profile_tokens(): the positional `vcpu:<name>` push_box_flags appends",
            ),
            (
                "vdisk",
                "profile_tokens(): the positional `vdisk:<name>` push_box_flags appends",
            ),
            (
                "vgpio",
                "profile_tokens(): the positional `vgpio:<name>` push_box_flags appends",
            ),
            (
                "net_aliases",
                "extra-host resolution for the pod's shared namespace",
            ),
        ];

        let mut orphans: Vec<&str> = Vec::new();
        for f in &fields {
            if forwarded.contains(f) {
                continue;
            }
            if READERS.iter().any(|(k, _)| k == f) {
                continue;
            }
            orphans.push(f);
        }
        assert!(
            orphans.is_empty(),
            "these ComposeBox fields are parsed and then reach nothing: {orphans:?}. \
             Either forward them in push_box_flags, or add them to READERS with the reader that \
             consumes them. A field that is stored and never read means the compose file said \
             something kern silently ignored."
        );

        // The allowlist must not rot either: an entry naming a field that no longer exists is a stale
        // exemption that would hide the next orphan.
        let stale: Vec<&str> = READERS
            .iter()
            .map(|(k, _)| *k)
            .filter(|k| !fields.contains(k))
            .collect();
        assert!(
            stale.is_empty(),
            "READERS names fields that ComposeBox no longer has: {stale:?}"
        );
    }
    /// Every key the `[box.NAME]` parser accepts must appear in `docs/CONFIG.md`, the file the
    /// README calls "the `kern.toml` schema, field by field". Ten did not: `add_host`, `expose`,
    /// `init`, `labels`, `port`, `restart_max`, `stop_grace_period`, `stop_signal`, `sysctls` and
    /// `ulimits` were parsed, forwarded and working, and documented nowhere. A schema reference
    /// that omits a working field is worse than no reference at all, because a reader concludes the
    /// field does not exist. The sibling test above pins field -> reader; this one pins key -> docs,
    /// so a key cannot be added in silence at either end.
    /// A named v-profile reaches the command line as the token `kern box` takes positionally.
    ///
    /// Before this, a stack file could set `cpus`/`cpuset`/`memory` per service but could not
    /// reference a PROFILE: the one thing kern has that the engines do not, a named slice reused
    /// across boxes, stopped at the CLI and never reached the file where per-service sizing is
    /// actually written. `profiles` was already taken, by Docker's own meaning (which services a
    /// plain `up` starts), so the keys are named after the tables that declare them.
    #[test]
    fn v_profiles_reach_the_command_line_as_positional_tokens() {
        let src = r#"
[box.db]
image = "mariadb:lts"
config = "profili.toml"
vcpu = "db"
vdisk = ["dbdata", "logs"]
"#;
        let boxes = crate::parse(src).expect("parses");
        let b = &boxes[0];
        assert_eq!(b.config.as_deref(), Some("profili.toml"));
        assert_eq!(b.vcpu, vec!["db"]);
        assert_eq!(b.vdisk, vec!["dbdata", "logs"]);
        assert_eq!(
            b.profile_tokens(),
            vec!["vcpu:db", "vdisk:dbdata", "vdisk:logs"],
            "the tokens are what `kern box <name> … vcpu:db vdisk:dbdata -- cmd` expects"
        );
    }

    /// The prefix is optional, and writing it means the same profile rather than a different one.
    ///
    /// `vcpu = "vcpu:db"` is what a reader copies out of the CLI line they already had working, and
    /// turning that into `vcpu:vcpu:db` would fail with "no [[vcpu]] profile named 'vcpu:db'" - a
    /// message about a name they never typed.
    #[test]
    fn a_profile_value_may_carry_its_own_prefix() {
        let src = r#"
[box.a]
image = "alpine"
vcpu = "vcpu:db"
vdisk = ["vdisk:scratch", "logs"]
vgpio = "leds"
"#;
        let b = &crate::parse(src).expect("parses")[0];
        assert_eq!(
            b.profile_tokens(),
            vec!["vcpu:db", "vdisk:scratch", "vdisk:logs", "vgpio:leds"]
        );
    }

    /// An empty or whitespace-only entry is dropped rather than turned into a bare `vcpu:` token,
    /// which `kern box` would classify as a profile with no name and refuse - an error about the
    /// file's punctuation, not about anything the reader meant.
    #[test]
    fn an_empty_profile_entry_produces_no_token() {
        let src = r#"
[box.a]
image = "alpine"
vcpu = ""
vdisk = ["", "  ", "real"]
"#;
        let b = &crate::parse(src).expect("parses")[0];
        assert_eq!(b.profile_tokens(), vec!["vdisk:real"]);
    }

    /// The tokens come LAST on the command line, after every flag, because that is where the box
    /// parser reads them: they are positional, and the caller appends `--` and the command after
    /// this call. A token emitted before `--image` would still parse today, but the order is part of
    /// what the generated line looks like when a user copies it out of `compose config`.
    #[test]
    fn profile_tokens_are_appended_after_the_flags() {
        let src = r#"
[box.a]
image = "alpine"
memory = "256m"
vcpu = "slim"
"#;
        let b = &crate::parse(src).expect("parses")[0];
        let mut cmd = std::process::Command::new("kern");
        b.push_box_flags(&mut cmd);
        let argv: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let mem = argv.iter().position(|a| a == "--memory").expect("--memory");
        let tok = argv.iter().position(|a| a == "vcpu:slim").expect("token");
        assert!(tok > mem, "the token must follow the flags: {argv:?}");
        assert_eq!(argv.last().map(String::as_str), Some("vcpu:slim"));
    }

    #[test]
    fn every_box_key_is_documented() {
        let src = include_str!("lib.rs");
        let (Some(start), Some(end)) = (src.find("// BOX-KEYS-BEGIN"), src.find("// BOX-KEYS-END"))
        else {
            panic!("the BOX-KEYS markers are gone; this test can no longer find the key match");
        };
        let mut keys: Vec<&str> = Vec::new();
        for line in src[start..end].lines() {
            let Some(rest) = line.trim_start().strip_prefix('"') else {
                continue;
            };
            let Some(q) = rest.find('"') else { continue };
            let key = &rest[..q];
            if rest[q + 1..].trim_start().starts_with("=>")
                && !key.is_empty()
                && key.chars().all(|c| c.is_ascii_lowercase() || c == '_')
            {
                keys.push(key);
            }
        }
        assert!(
            keys.len() > 30,
            "only {} keys parsed out of the marker block: the arm shape changed and this test \
             would now pass by finding nothing",
            keys.len()
        );

        let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        while !dir.join("docs").join("CONFIG.md").is_file() {
            if !dir.pop() {
                eprintln!("skip: no docs/CONFIG.md above CARGO_MANIFEST_DIR");
                return;
            }
        }
        let Ok(doc) = std::fs::read_to_string(dir.join("docs").join("CONFIG.md")) else {
            eprintln!("skip: cannot read docs/CONFIG.md");
            return;
        };
        let missing: Vec<&str> = keys.iter().copied().filter(|k| !doc.contains(k)).collect();
        assert!(
            missing.is_empty(),
            "these `[box.NAME]` keys are accepted by the parser and appear nowhere in \
             docs/CONFIG.md: {missing:?}. Document them, or stop accepting them."
        );
    }
}
