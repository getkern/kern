//! `kern compose` — minimal TOML orchestration.
//!
//! Parses a small TOML subset (no external crate): `[box.NAME]` tables whose keys **mirror the
//! `kern box` CLI** one-to-one (see `docs/CONFIG.md` for the frozen schema). Boxes are started
//! detached in dependency order (`depends_on`), so `kern compose up.toml` brings up a stack and
//! `kern ps` shows it. The parser is intentionally strict and reports the offending line.
//!
//! **Mirror-CLI rule (frozen).** A scalar key is a quoted string carrying the exact CLI argument
//! (`memory = "512m"`, `cpus = "1.5"`, `cpuset = "0-3"`); a repeatable flag is an array of those
//! same strings (`volumes = ["src:dst:ro"]`); a switch is a TOML bool (`read_only = true`). Because
//! `compose` shells out to `kern box`, each value is validated by the very same parser the CLI uses
//! — the TOML surface can never drift from the flag surface. The same `[box.NAME]` table is the
//! unit a future `--profile` will reuse, which is why the key names are frozen now.

use std::collections::{HashMap, HashSet, VecDeque};

/// One service in a compose file. Most fields mirror a `kern box` flag (`None`/empty/`false` =
/// "flag absent"); `name`/`command`/`depends_on` are structural — `depends_on` is compose-only, and
/// `push_box_flags` deliberately skips all three. Frozen key ↔ flag map (non-obvious names):
/// `swap_max`→`--memory-swap-max`, `cpuset`→`--cpuset-cpus`, `net`→`--net`, `ssh`→`--ssh`,
/// `user`→`--user`, `volumes`→`-v`, `env`→`-e`, `ports`→`-p`, `secrets`→`--secret`; the rest share
/// the flag's long name (`pids_limit`, `io_weight`, `nice`, `timeout`, `hostname`, `tun`, `tmpfs`,
/// `cap_add`, `cap_drop`, `env_file`, `health_retries`/`_start_period`/`_timeout`/`_action`).
#[derive(Default)]
pub struct ComposeBox {
    pub name: String,
    pub image: Option<String>,
    pub rootfs: Option<String>,
    pub command: Vec<String>,
    pub depends_on: Vec<String>,
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
        if self.uid_range {
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

/// Parse the compose document into boxes (file order preserved).
pub fn parse(text: &str) -> Result<Vec<ComposeBox>, String> {
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
            "uid_range" => b.uid_range = parse_bool(val).map_err(|e| line_err(i, &e))?,
            "bind_rootfs" => b.bind_rootfs = parse_bool(val).map_err(|e| line_err(i, &e))?,
            "restart" => b.restart = parse_bool(val).map_err(|e| line_err(i, &e))?,
            "tun" => b.tun = parse_bool(val).map_err(|e| line_err(i, &e))?,
            // Repeatable flags — arrays of the same CLI strings.
            "command" => b.command = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "depends_on" => b.depends_on = parse_string_array(val).map_err(|e| line_err(i, &e))?,
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

/// Dependency order (a box starts after everything in its `depends_on`). Errors on an unknown
/// dependency or a cycle.
pub fn topo_order(boxes: &[ComposeBox]) -> Result<Vec<String>, String> {
    let names: HashSet<&str> = boxes.iter().map(|b| b.name.as_str()).collect();
    let mut indeg: HashMap<&str, usize> = boxes.iter().map(|b| (b.name.as_str(), 0)).collect();
    let mut succ: HashMap<&str, Vec<&str>> = HashMap::new();
    for b in boxes {
        for d in &b.depends_on {
            if !names.contains(d.as_str()) {
                return Err(format!("box '{}' depends on unknown box '{d}'", b.name));
            }
            succ.entry(d.as_str()).or_default().push(b.name.as_str());
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

fn line_err(i: usize, e: &str) -> String {
    format!("line {}: {e}", i + 1)
}

fn strip_comment(line: &str) -> &str {
    // `#` outside a string starts a comment. (Values are quoted, so a `#` inside quotes is safe.)
    let mut in_str = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return &line[..i],
            _ => {}
        }
    }
    line
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
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        Ok(v[1..v.len() - 1].to_string())
    } else {
        Err(format!("expected a quoted string, got `{v}`"))
    }
}

fn parse_bool(v: &str) -> Result<bool, String> {
    match v.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!("expected `true` or `false`, got `{other}`")),
    }
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
    let v = v.trim();
    let inner = v
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| format!("expected an array `[...]`, got `{v}`"))?;
    let mut out = Vec::new();
    for part in split_top_commas(inner) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(parse_string(part)?);
    }
    Ok(out)
}

/// Split on commas that are not inside a quoted string.
fn split_top_commas(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut in_str, mut esc) = (false, false);
    for c in s.chars() {
        if in_str {
            cur.push(c);
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
            cur.push(c);
        } else if c == ',' {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

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
