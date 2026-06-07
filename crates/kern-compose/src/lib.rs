//! The `kern compose` file parser — `docker-compose.yml` (YAML-lite, in the private `yaml` module) and the native
//! kern TOML subset — both lowered to a `Vec<`[`ComposeBox`]`>`. This crate is **pure parsing**: it
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
//! `compose` shells out to `kern box`, each value is validated by the very same parser the CLI uses
//! — the TOML surface can never drift from the flag surface. The same `[box.NAME]` table is the
//! unit a future `--profile` will reuse, which is why the key names are frozen now.

use std::collections::{HashMap, HashSet, VecDeque};

mod yaml;

/// A resolved compose `build:` directive. `context` is a path RELATIVE to the compose file's dir (the
/// caller confines it beneath that dir before use — traversal guard). `dockerfile` is relative to the
/// context. `args` are the `--build-arg K=V` pairs (already `${VAR}`-interpolated).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BuildDirective {
    pub context: String,
    pub dockerfile: Option<String>,
    pub args: Vec<String>,
}

/// One service in a compose file. Most fields mirror a `kern box` flag (`None`/empty/`false` =
/// "flag absent"); `name`/`command`/`depends_on` are structural — `depends_on` is compose-only, and
/// `push_box_flags` deliberately skips all three. Frozen key ↔ flag map (non-obvious names):
/// `swap_max`→`--memory-swap-max`, `cpuset`→`--cpuset-cpus`, `net`→`--net`, `ssh`→`--ssh`,
/// `user`→`--user`, `volumes`→`-v`, `env`→`-e`, `ports`→`-p`, `secrets`→`--secret`; the rest share
/// the flag's long name (`pids_limit`, `io_weight`, `nice`, `timeout`, `hostname`, `tun`, `tmpfs`,
/// `cap_add`, `cap_drop`, `env_file`, `health_retries`/`_start_period`/`_timeout`/`_action`).
#[derive(Default, Debug)]
pub struct ComposeBox {
    pub name: String,
    pub image: Option<String>,
    pub rootfs: Option<String>,
    pub command: Vec<String>,
    pub depends_on: Vec<String>,
    /// Dependencies this box waits to become HEALTHY before it starts (Docker's
    /// `condition: service_healthy`). Each named box must declare `health_cmd`. A superset relation
    /// with `depends_on` is NOT required — a `depends_healthy` entry implies the ordering edge too
    /// (see `all_deps`), so you don't have to repeat the name in `depends_on`.
    pub depends_healthy: Vec<String>,
    /// Dependencies this box waits to RUN TO SUCCESSFUL COMPLETION (exit 0) before it starts
    /// (Docker's `condition: service_completed_successfully`) — the init-container / migration-job
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
    pub net: bool,
    pub uid_range: bool,
    /// Set when the compose file wrote `uid_range = false` explicitly, so the per-image default
    /// (turn it ON for OCI images) does NOT override a deliberate opt-out.
    pub uid_range_explicit_false: bool,
    pub bind_rootfs: bool,
    pub restart: bool,
    pub tun: bool,
    pub volumes: Vec<String>,
    pub env: Vec<String>,
    pub env_file: Vec<String>,
    pub ports: Vec<String>,
    pub secrets: Vec<String>,
    pub tmpfs: Vec<String>,
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
}

impl ComposeBox {
    // Every field's "flag absent" value is its type's Default (None/empty/false), so `new` only sets
    // the name — a newly-added mirror-CLI field can never be silently left out of construction.
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
    pub fn push_box_flags(&self, cmd: &mut std::process::Command) {
        if let Some(v) = &self.image {
            cmd.arg("--image").arg(v);
        }
        if let Some(v) = &self.rootfs {
            cmd.arg("--rootfs").arg(v);
        }
        if let Some(v) = &self.workdir {
            cmd.arg("--workdir").arg(v);
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
        if self.net {
            cmd.arg("--net");
        }
        // `--uid-range` when the box asked for it, OR by default for an OCI IMAGE box: official images
        // (postgres/redis/nginx/mariadb/grafana) drop privilege in their entrypoint to a service uid,
        // which needs the subordinate uid range to work (see the 0.6 official-image fix). A `rootfs` box
        // is the user's own tree and keeps the default single-uid map (faster, more isolated). Explicit
        // `uid_range = false` in the compose file is respected — only the ABSENT default flips per image.
        if self.uid_range || (self.image.is_some() && !self.uid_range_explicit_false) {
            cmd.arg("--uid-range");
        }
        if self.bind_rootfs {
            cmd.arg("--bind-rootfs");
        }
        if self.restart {
            cmd.arg("--restart");
        }
        if self.tun {
            cmd.arg("--tun");
        }
        for v in &self.volumes {
            cmd.arg("--volume").arg(v);
        }
        for v in &self.env {
            cmd.arg("--env").arg(v);
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
    }
}

/// Parse a compose document, auto-detecting the format (boxes are returned in file order). A
/// `docker-compose.yml` (first meaningful line is `services:`/`version:`/`name:`, or any `key:` block)
/// is parsed by the YAML-lite parser; a native kern stack (`[box.NAME]` tables) by the TOML parser.
/// Both produce the SAME `ComposeBox`es, so the
/// whole downstream pipeline (topo/conditions/exit-sidecar/pod/launch) is format-agnostic. This is the
/// compat entry: point `kern compose` at either and it just works (YAML degrades-with-warning on the
/// long tail — see `yaml::parse`). Auto-detect is deliberate: the two grammars are unambiguous at the
/// first non-comment line (`[` opens a TOML table; a bare `key:` opens a YAML mapping).
pub fn parse(text: &str) -> Result<Vec<ComposeBox>, String> {
    if is_yaml(text) {
        yaml::parse(text)
    } else {
        parse_toml(text)
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
    for (i, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
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
        match key.trim() {
            // Scalars — quoted strings carrying the exact CLI argument.
            "image" => b.image = Some(s(val)?),
            "rootfs" => b.rootfs = Some(s(val)?),
            "workdir" => b.workdir = Some(s(val)?),
            "memory" => b.memory = Some(s(val)?),
            "cpus" => b.cpus = Some(s(val)?),
            "cpuset" => b.cpuset = Some(s(val)?),
            "swap_max" => b.swap_max = Some(s(val)?),
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
            // Switches — TOML booleans.
            "read_only" => b.read_only = parse_bool(val).map_err(|e| line_err(i, &e))?,
            "net" => b.net = parse_bool(val).map_err(|e| line_err(i, &e))?,
            "uid_range" => {
                b.uid_range = parse_bool(val).map_err(|e| line_err(i, &e))?;
                b.uid_range_explicit_false = !b.uid_range; // remember a deliberate `= false`
            }
            "bind_rootfs" => b.bind_rootfs = parse_bool(val).map_err(|e| line_err(i, &e))?,
            "restart" => b.restart = parse_bool(val).map_err(|e| line_err(i, &e))?,
            "tun" => b.tun = parse_bool(val).map_err(|e| line_err(i, &e))?,
            // Repeatable flags — arrays of the same CLI strings.
            "command" => b.command = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            // `depends_on` accepts BOTH the array form (`["db"]` — start-order only, like Docker's
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
            "volumes" => b.volumes = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "env" => b.env = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "env_file" => b.env_file = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "ports" => b.ports = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "secrets" => b.secrets = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "tmpfs" => b.tmpfs = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "cap_add" => b.cap_add = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "cap_drop" => b.cap_drop = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            other => return Err(format!("line {}: unknown key '{other}'", i + 1)),
        }
    }
    if boxes.is_empty() {
        return Err("no [box.NAME] tables found".into());
    }
    for b in &boxes {
        // An empty string (`image = ""`) counts as absent — otherwise it only fails downstream in
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

/// Dependency order (a box starts after every box it depends on — `depends_on` plus the conditional
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
            *indeg.get_mut(b.name.as_str()).unwrap() += 1;
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
                let e = indeg.get_mut(m).unwrap();
                *e -= 1;
                if *e == 0 {
                    queue.push_back(m);
                }
            }
        }
    }
    if order.len() != boxes.len() {
        return Err("dependency cycle detected".into());
    }
    Ok(order)
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
        // Array form — plain start-order dependencies.
        b.depends_on = parse_string_array(v)?;
        return Ok(());
    }
    // Inline-table form. Parse `name = { condition = "..." }` entries at the top level. We scan
    // rather than pull in a TOML crate (the whole compose parser is dependency-free by design).
    // Robustness (this is user-supplied — a docker-compose.yml from a third-party repo): reject
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
/// a clean parse error on any violation — the guard that keeps a malformed `docker-compose.yml`
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

/// Split on commas that are NOT inside a nested `{ ... }` and NOT inside double quotes — for the
/// inline-table `depends_on` form, where the whole list is comma-separated but each entry
/// (`name = { condition = "..." }`) has its own braces (and a value may quote a comma). Depth- and
/// quote-tracked. Assumes `balanced_braces(s's wrapper)` already passed, so depth stays ≥ 0. Splits on
/// the ASCII byte `,`, so `s[start..i]` is always on a char boundary (`char_indices` yields boundaries
/// and `i+1` past a 1-byte `,` is one too) — no UTF-8 slicing panic.
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

/// A positive integer (the only int key, `health_interval`, is seconds — 0/negative is nonsense).
/// Validating here gives a precise line-numbered error instead of an opaque child "failed to start".
fn parse_positive_int(v: &str) -> Result<i64, String> {
    match v.trim().parse::<i64>() {
        Ok(n) if n > 0 => Ok(n),
        Ok(_) => Err(format!("expected a positive integer, got `{}`", v.trim())),
        Err(_) => Err(format!("expected an integer, got `{}`", v.trim())),
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
            // Must return Ok or Err — the point is it does not panic. (`std::panic` would abort the
            // test.) A few of these are actually well-formed-but-benign (e.g. `{ a = }` → start-order),
            // which is fine; the invariant under test is "no panic on any of them".
            let _ = parse(&doc);
        }
    }

    #[test]
    fn exhaustive_short_strings_never_panic() {
        // Enumerate ALL length-6 strings over the structural ASCII alphabet — total coverage of the
        // short-input space where a brace/quote/comma scanner bug lives. Complements the randomized
        // test below (which reaches long inputs, multibyte, and deep nesting the enumeration can't).
        let alphabet = [b'{', b'}', b'"', b',', b'=', b'a'];
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
        // input — Err or benign Ok only. This is the `cargo fuzz`-equivalent the review asked for,
        // run inline (the parser is a private fn in a bin crate, not reachable from the fuzz
        // workspace). Two classes the length-6 enumeration can't reach are covered HERE:
        //   * MULTIBYTE UTF-8 in values (`é`, `→`, emoji) — the byte-offset-slicing panic class. The
        //     scanner uses `char_indices`, so a multibyte char never splits a boundary; this proves it.
        //   * DEEP NESTING (`{{{…}}}` hundreds deep) — the recursion/stack-overflow class. The scanner
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
        // Explicit pathological deep nesting — a single input the LCG is unlikely to build exactly.
        let deep_open = "{".repeat(2000);
        let deep = format!("{deep_open}{}", "}".repeat(2000));
        assert!(balanced_braces(&deep).is_ok()); // balanced, just deep — must not overflow
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
