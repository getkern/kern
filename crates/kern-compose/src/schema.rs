//! Docker Compose's own refusal of a compose file, reproduced: the steps compose-go v2.13.0 runs on
//! each file BEFORE it builds a project, in its order and with its words.
//!
//! 1. **Interpolation casts.** compose-go interpolates every string value and then converts the
//!    ones at 42 known paths (`deploy.replicas`, `cpus`, `init`, ...) to the type the field has, so
//!    `replicas: "3"` is the integer 3 and `replicas: x` is refused with Go's `strconv` error.
//! 2. **`EnforceUnicity`.** Lists such as `cap_add`, `ports`, `volumes` lose their repeated entries
//!    (the later one taking the earlier one's place), and an entry the indexer cannot key is refused.
//! 3. **The JSON schema.** `compose-spec.json` (vendored from compose-go v2.13.0, Apache-2.0, see
//!    NOTICE) is checked as santhosh-tekuri/jsonschema v6.0.1 checks it, and of all the failures the
//!    one compose-go prints is the deepest (`getMostSpecificError`), worded as compose-go words it.
//!
//! MEASURED on Docker Compose 5.3.1 (compose-go v2.13.0), 37 files pinned in the tests below: `command: [echo, 1, true]` is
//! `validating <file>: services.a.command.1 must be a string`, `cap_add: SYS_ADMIN` is `... must be a
//! array`, a key under the top level is `validating <file>:  additional properties 'foo' not allowed`
//! (two spaces: the location is empty), `cpus: .inf` is `json: unsupported value: +Inf`.
//!
//! WHERE DOCKER IS NOT DETERMINISTIC, kern takes one of its answers. compose-go walks Go maps, whose
//! order changes on every run: with two failures at the same depth Docker names either (measured: 5
//! runs `container_name`, 1 run `image` for one file). kern takes the first in file order, which is
//! one of the answers Docker gives.
//!
//! Each file is checked alone, where compose-go checks the files merged so far under the name of the
//! latest. A merge of two files that each pass is checked by kern's own merge.

use crate::canon::{self, Typed, Val};
use std::collections::HashMap;

/// compose-go v2.13.0's `schema/compose-spec.json`, unmodified.
const SPEC: &str = include_str!("compose-spec.json");

/// The path Docker names a file by: absolute against `cwd`, cleaned (`filepath.Abs`).
pub fn file_label(path: &str, cwd: &std::path::Path) -> String {
    if path.starts_with('/') {
        canon::clean_path(path)
    } else {
        canon::clean_path(&format!("{}/{path}", cwd.display()))
    }
}

/// How Docker answers a file it refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Docker's message, and the file is refused with it.
    Final(String),
    /// Docker refuses a key it does not know (`additional properties ... not allowed`). kern's own
    /// parse names the same key and the one closest to it, so kern's message is the one shown; this
    /// one is shown when kern's parse accepts the file.
    UnknownKey(String),
}

/// True when `msg` is one of the refusals this module writes, in Docker's words: the schema's
/// (`validating <file>: ...`), the interpolation casts', `EnforceUnicity`'s and `ParseVolume`'s. A
/// caller adding its own hint under an error leaves these alone, as Docker prints nothing under them.
pub fn is_docker_refusal(msg: &str) -> bool {
    const LEADS: &[&str] = &[
        "validating ",
        "error while interpolating ",
        "invalid empty volume spec",
        "invalid spec: ",
        "service ports ",
        "service volume ",
        "service device ",
        "environment path attribute ",
        "go-yaml load error ",
    ];
    const INNER: &[&str] = &[": unexpected type ", ": unsupported expose value "];
    LEADS.iter().any(|l| msg.starts_with(l)) || INNER.iter().any(|i| msg.contains(i))
}

/// The parse `parse` runs, after Docker's refusal if there is one: a [`Refusal::Final`] is the
/// answer, a [`Refusal::UnknownKey`] gives way to kern's own error and stands when kern accepts.
pub fn refused_or<T>(
    refusal: Option<Refusal>,
    parse: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    match refusal {
        None => parse(),
        Some(Refusal::Final(m)) => Err(m),
        Some(Refusal::UnknownKey(m)) => match parse() {
            Err(e) => Err(e),
            Ok(_) => Err(m),
        },
    }
}

/// What Docker's reading of one compose file gives the caller: its refusal, if it refuses.
#[derive(Debug, Clone, Default)]
pub struct DockerCheck {
    pub refusal: Option<Refusal>,
}

/// [`DockerCheck`] for the compose YAML `text`, read from the file `file` (the absolute path Docker
/// names in its message). No refusal when Docker accepts it, when it is a kern TOML stack, and when
/// kern's front end cannot read it (the parse that follows reports that).
pub fn docker_check(
    text: &str,
    dotenv: &crate::DotEnv,
    dir: Option<&std::path::Path>,
    file: &str,
    interpolate: bool,
) -> DockerCheck {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    if !crate::is_yaml(text) {
        return DockerCheck::default();
    }
    if let Some(e) = flow_indicator_in_plain_scalar(text) {
        return DockerCheck {
            refusal: Some(Refusal::Final(e)),
        };
    }
    let Ok(val) = crate::yaml::document_val(text, dotenv, dir, interpolate) else {
        return DockerCheck::default();
    };
    if !matches!(val, Val::Map(_)) {
        return DockerCheck::default();
    }
    DockerCheck {
        refusal: check_val(&val, file, interpolate),
    }
}

/// [`docker_check`]'s refusal alone.
pub fn docker_refusal(
    text: &str,
    dotenv: &crate::DotEnv,
    dir: Option<&std::path::Path>,
    file: &str,
    interpolate: bool,
) -> Option<Refusal> {
    docker_check(text, dotenv, dir, file, interpolate).refusal
}

/// go-yaml's refusal of a flow collection holding a plain scalar that runs into `{` or `[`: in a
/// flow (`[...]`, `{...}`) those are indicators, so `[echo, ${X}]` is the scalar `$` and then a
/// mapping nobody separated. MEASURED on Docker Compose 5.3.1, `command: [echo, ${X}]` is `go-yaml
/// load error in parser (while parsing a flow sequence) at L4.C14-C22: did not find expected ','
/// or ']'`: the line, the column of the bracket that opened the flow and the column of the
/// indicator, counted from 1; kern read the `${X}` and ran the command. A quoted scalar and a block
/// scalar (`|`, `>`) are text and are not looked into, and a flow spanning lines is not checked.
fn flow_indicator_in_plain_scalar(text: &str) -> Option<String> {
    let mut block_indent: Option<usize> = None;
    for (ln, line) in text.lines().enumerate() {
        let indent = line.len() - line.trim_start().len();
        if let Some(b) = block_indent {
            if line.trim().is_empty() || indent > b {
                continue;
            }
            block_indent = None;
        }
        let chars: Vec<char> = line.chars().collect();
        // Where a value starts: after `key: ` or `- `, or at the start of the line.
        let mut i = chars.iter().take_while(|c| **c == ' ').count();
        while chars.get(i) == Some(&'-') && chars.get(i + 1) == Some(&' ') {
            i += 2;
            while chars.get(i) == Some(&' ') {
                i += 1;
            }
        }
        if !matches!(chars.get(i), Some('[' | '{')) {
            // `key: value`: find the `: ` outside quotes, then the value.
            let mut j = i;
            let mut quote: Option<char> = None;
            let mut found = None;
            while let Some(&c) = chars.get(j) {
                match quote {
                    Some(q) if c == q => quote = None,
                    Some(_) => {}
                    None if c == '"' || c == '\'' => quote = Some(c),
                    None if c == '#' && j > 0 && chars.get(j - 1) == Some(&' ') => break,
                    None if c == ':' && matches!(chars.get(j + 1), Some(' ') | None) => {
                        found = Some(j + 1);
                        break;
                    }
                    None => {}
                }
                j += 1;
            }
            let Some(mut v) = found else {
                continue;
            };
            while chars.get(v) == Some(&' ') {
                v += 1;
            }
            match chars.get(v) {
                Some('|' | '>') => {
                    block_indent = Some(indent);
                    continue;
                }
                Some('[' | '{') => i = v,
                _ => continue,
            }
        }
        // Walk the flow.
        let mut stack: Vec<(char, usize)> = Vec::new();
        let mut plain = false;
        let mut k = i;
        while let Some(&c) = chars.get(k) {
            match c {
                '"' | '\'' if !plain => {
                    let q = c;
                    k += 1;
                    while let Some(&d) = chars.get(k) {
                        if d == q {
                            if q == '\'' && chars.get(k + 1) == Some(&'\'') {
                                k += 2;
                                continue;
                            }
                            break;
                        }
                        if q == '"' && d == '\\' {
                            k += 1;
                        }
                        k += 1;
                    }
                }
                '[' | '{' => {
                    if plain {
                        if let Some((open, at)) = stack.last() {
                            let (what, close) = if *open == '[' {
                                ("sequence", ']')
                            } else {
                                ("mapping", '}')
                            };
                            return Some(format!(
                                "go-yaml load error in parser (while parsing a flow {what}) at \
                                 L{}.C{}-C{}: did not find expected ',' or '{close}'",
                                ln + 1,
                                at + 1,
                                k + 1
                            ));
                        }
                    }
                    stack.push((c, k));
                    plain = false;
                }
                ']' | '}' => {
                    stack.pop();
                    plain = false;
                    if stack.is_empty() {
                        break;
                    }
                }
                ',' => plain = false,
                ':' if matches!(chars.get(k + 1), Some(' ' | ',' | ']' | '}') | None) => {
                    plain = false
                }
                '#' if chars.get(k.wrapping_sub(1)) == Some(&' ') => break,
                ' ' | '\t' => {}
                _ => plain = true,
            }
            k += 1;
        }
    }
    None
}

/// [`docker_refusal`] on a tree already read.
fn check_val(val: &Val, file: &str, interpolate: bool) -> Option<Refusal> {
    let mut g = G::from_val(val);
    // kern's own service keys are kern's parser's to judge, not Docker's schema's.
    if let G::Map(top) = &mut g {
        for (k, services) in top.iter_mut() {
            if k != "services" {
                continue;
            }
            if let G::Map(svcs) = services {
                for (_, svc) in svcs.iter_mut() {
                    if let G::Map(keys) = svc {
                        keys.retain(|(key, _)| {
                            !crate::yaml::KERN_SERVICE_KEYS.contains(&key.as_str())
                        });
                    }
                }
            }
        }
    }
    let mut path = Vec::new();
    if interpolate {
        if let Err(m) = cast_walk(&mut g, &mut path) {
            return Some(Refusal::Final(m));
        }
    }
    if let Err(m) = unicity(&mut g, &mut path) {
        return Some(Refusal::Final(m));
    }
    if let Some(bad) = first_unsupported(&g) {
        return Some(Refusal::Final(format!(
            "validating {file}: json: unsupported value: {bad}"
        )));
    }
    let spec = match spec() {
        Ok(s) => s,
        Err(e) => return Some(Refusal::Final(e.clone())),
    };
    let instance = g.to_json();
    let mut leaves = Vec::new();
    let mut at = Vec::new();
    if let Err(e) = spec.check(&spec.root, &instance, &mut at, &mut leaves) {
        return Some(Refusal::Final(e));
    }
    let best = most_specific(&leaves)?;
    let msg = format!("validating {file}: {}", best.message());
    Some(if matches!(best.kind, Kind::Additional(_)) {
        Refusal::UnknownKey(msg)
    } else {
        Refusal::Final(msg)
    })
}

// ------------------------------------------------------------------------------------------------
// The typed tree, as Go holds a decoded YAML document: the Go type of every scalar is kept, because
// `EnforceUnicity`'s messages print it (`unexpected type int`).

#[derive(Debug, Clone, PartialEq)]
enum G {
    Null,
    Bool(bool),
    /// The value and its Go type (`int` from the YAML decoder and `toInt`, `int64` from `toInt64`).
    Int(i64, &'static str),
    /// The value and its Go type (`float64`, or `float32` from `toFloat32`).
    Float(f64, &'static str),
    Str(String),
    /// A YAML timestamp, in `time.Time.String()` form (see [`canon::Typed::Time`]).
    Time(String),
    Seq(Vec<G>),
    Map(Vec<(String, G)>),
}

impl G {
    fn from_val(v: &Val) -> G {
        match v {
            Val::Null => G::Null,
            Val::Scalar(s, true) => G::Str(s.clone()),
            Val::Scalar(s, false) => match canon::resolve(s) {
                Typed::Null => G::Null,
                Typed::Bool(b) => G::Bool(b),
                Typed::Int(i) => G::Int(i, "int"),
                Typed::Float(f) => G::Float(f, "float64"),
                Typed::Time(t) => G::Time(t),
                Typed::Str(s) => G::Str(s),
            },
            Val::Seq(items) => G::Seq(items.iter().map(G::from_val).collect()),
            Val::Map(m) => G::Map(m.iter().map(|(k, v)| (k.clone(), G::from_val(v))).collect()),
        }
    }

    /// Go's `%T`.
    fn go_type(&self) -> &'static str {
        match self {
            G::Null => "<nil>",
            G::Bool(_) => "bool",
            G::Int(_, t) | G::Float(_, t) => t,
            G::Str(_) => "string",
            G::Time(_) => "time.Time",
            G::Seq(_) => "[]interface {}",
            G::Map(_) => "map[string]interface {}",
        }
    }

    fn get(&self, key: &str) -> Option<&G> {
        match self {
            G::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// What `json.Unmarshal(json.Marshal(v))` gives compose-go's validator: numbers are float64,
    /// a timestamp is its RFC 3339 text.
    fn to_json(&self) -> J {
        match self {
            G::Null => J::Null,
            G::Bool(b) => J::Bool(*b),
            G::Int(i, _) => J::Num(*i as f64),
            G::Float(f, _) => J::Num(*f),
            G::Str(s) => J::Str(s.clone()),
            G::Time(t) => J::Str(rfc3339(t)),
            G::Seq(items) => J::Arr(items.iter().map(G::to_json).collect()),
            G::Map(m) => J::Obj(m.iter().map(|(k, v)| (k.clone(), v.to_json())).collect()),
        }
    }
}

/// Go's `%s` of a decoded value (`fmt.Sprintf("%s", v)`).
fn go_s(g: &G) -> String {
    match g {
        G::Str(s) | G::Time(s) => s.clone(),
        G::Null => "%!s(<nil>)".to_string(),
        G::Bool(b) => format!("%!s(bool={b})"),
        G::Int(i, t) => format!("%!s({t}={i})"),
        G::Float(f, t) => format!("%!s({t}={})", go_v_float(*f, t)),
        G::Seq(items) => format!("[{}]", items.iter().map(go_s).collect::<Vec<_>>().join(" ")),
        G::Map(m) => {
            let mut kv: Vec<(&String, &G)> = m.iter().map(|(k, v)| (k, v)).collect();
            kv.sort_by(|a, b| a.0.cmp(b.0));
            let body: Vec<String> = kv.iter().map(|(k, v)| format!("{k}:{}", go_s(v))).collect();
            format!("map[{}]", body.join(" "))
        }
    }
}

/// Go's `%d` of a decoded value.
fn go_d(g: &G) -> String {
    match g {
        G::Int(i, _) => i.to_string(),
        G::Str(s) => format!("%!d(string={s})"),
        G::Time(s) => format!("%!d(time.Time={s})"),
        G::Null => "%!d(<nil>)".to_string(),
        G::Bool(b) => format!("%!d(bool={b})"),
        G::Float(f, t) => format!("%!d({t}={})", go_v_float(*f, t)),
        G::Seq(items) => format!("[{}]", items.iter().map(go_d).collect::<Vec<_>>().join(" ")),
        G::Map(m) => {
            let mut kv: Vec<(&String, &G)> = m.iter().map(|(k, v)| (k, v)).collect();
            kv.sort_by(|a, b| a.0.cmp(b.0));
            let body: Vec<String> = kv
                .iter()
                .map(|(k, v)| format!("%!d(string={k}):{}", go_d(v)))
                .collect();
            format!("map[{}]", body.join(" "))
        }
    }
}

/// Go's `%v` of a float of Go type `t`.
fn go_v_float(f: f64, t: &str) -> String {
    canon::go_format_float(f, if t == "float32" { 32 } else { 64 })
}

/// `time.Time.String()` (`2001-12-14 21:59:43.1 -0500 -0500`) as `encoding/json` writes the same
/// time: RFC 3339 with nanoseconds, `Z` for a zero offset.
fn rfc3339(t: &str) -> String {
    let mut parts = t.split(' ');
    let (Some(date), Some(clock), Some(offset)) = (parts.next(), parts.next(), parts.next()) else {
        return t.to_string();
    };
    let zone = match offset.as_bytes() {
        [s @ (b'+' | b'-'), h1, h2, m1, m2] => {
            if [h1, h2, m1, m2].iter().all(|c| **c == b'0') {
                "Z".to_string()
            } else {
                format!(
                    "{}{}{}:{}{}",
                    *s as char, *h1 as char, *h2 as char, *m1 as char, *m2 as char
                )
            }
        }
        _ => return t.to_string(),
    };
    format!("{date}T{clock}{zone}")
}

/// The first value `json.Marshal` refuses, in the order it writes them (map keys sorted): NaN and
/// the infinities, as `strconv.FormatFloat` prints them.
fn first_unsupported(g: &G) -> Option<String> {
    match g {
        G::Float(f, t) if !f.is_finite() => Some(go_v_float(*f, t)),
        G::Seq(items) => items.iter().find_map(first_unsupported),
        G::Map(m) => {
            let mut kv: Vec<&(String, G)> = m.iter().collect();
            kv.sort_by(|a, b| a.0.cmp(&b.0));
            kv.iter().find_map(|(_, v)| first_unsupported(v))
        }
        _ => None,
    }
}

// ------------------------------------------------------------------------------------------------
// Step 1: compose-go's `interpolateTypeCastMapping` (loader/interpolate.go).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cast {
    Int,
    Int64,
    Float,
    Float32,
    Bool,
}

/// The 42 paths, `*` for any key and `[]` for any list item, as compose-go v2.13.0 lists them.
const CASTS: &[(&str, Cast)] = &[
    ("services.*.cpu_count", Cast::Int64),
    ("services.*.cpu_percent", Cast::Float),
    ("services.*.cpu_period", Cast::Int64),
    ("services.*.cpu_quota", Cast::Int64),
    ("services.*.cpu_rt_period", Cast::Int64),
    ("services.*.cpu_rt_runtime", Cast::Int64),
    ("services.*.cpus", Cast::Float32),
    ("services.*.cpu_shares", Cast::Int64),
    ("services.*.init", Cast::Bool),
    ("services.*.depends_on.*.required", Cast::Bool),
    ("services.*.depends_on.*.restart", Cast::Bool),
    ("services.*.deploy.replicas", Cast::Int),
    ("services.*.deploy.update_config.parallelism", Cast::Int),
    (
        "services.*.deploy.update_config.max_failure_ratio",
        Cast::Float,
    ),
    ("services.*.deploy.rollback_config.parallelism", Cast::Int),
    (
        "services.*.deploy.rollback_config.max_failure_ratio",
        Cast::Float,
    ),
    ("services.*.deploy.restart_policy.max_attempts", Cast::Int),
    (
        "services.*.deploy.placement.max_replicas_per_node",
        Cast::Int,
    ),
    ("services.*.healthcheck.retries", Cast::Int),
    ("services.*.healthcheck.disable", Cast::Bool),
    ("services.*.oom_kill_disable", Cast::Bool),
    ("services.*.oom_score_adj", Cast::Int64),
    ("services.*.pids_limit", Cast::Int64),
    ("services.*.ports.[].target", Cast::Int),
    ("services.*.privileged", Cast::Bool),
    ("services.*.read_only", Cast::Bool),
    ("services.*.scale", Cast::Int),
    ("services.*.stdin_open", Cast::Bool),
    ("services.*.tty", Cast::Bool),
    ("services.*.ulimits.*", Cast::Int),
    ("services.*.ulimits.*.hard", Cast::Int),
    ("services.*.ulimits.*.soft", Cast::Int),
    ("services.*.volumes.[].read_only", Cast::Bool),
    ("services.*.volumes.[].volume.nocopy", Cast::Bool),
    ("networks.*.external", Cast::Bool),
    ("networks.*.internal", Cast::Bool),
    ("networks.*.attachable", Cast::Bool),
    ("networks.*.enable_ipv4", Cast::Bool),
    ("networks.*.enable_ipv6", Cast::Bool),
    ("volumes.*.external", Cast::Bool),
    ("secrets.*.external", Cast::Bool),
    ("configs.*.external", Cast::Bool),
];

/// `tree.Path.Matches`: as many parts, each `*` or equal.
fn path_matches(path: &[String], pattern: &str) -> bool {
    // Asked of every value of the file against every entry of a table: no allocation.
    pattern.split('.').count() == path.len()
        && pattern
            .split('.')
            .zip(path)
            .all(|(p, part)| p == "*" || p == part)
}

fn cast_walk(g: &mut G, path: &mut Vec<String>) -> Result<(), String> {
    match g {
        G::Str(s) => {
            if let Some((_, cast)) = CASTS.iter().find(|(p, _)| path_matches(path, p)) {
                *g = apply_cast(*cast, s).map_err(|e| {
                    format!(
                        "error while interpolating {}: failed to cast to expected type: {e}",
                        path.join(".")
                    )
                })?;
            }
            Ok(())
        }
        G::Map(m) => {
            for (k, v) in m.iter_mut() {
                path.push(k.clone());
                let r = cast_walk(v, path);
                path.pop();
                r?;
            }
            Ok(())
        }
        G::Seq(items) => {
            for v in items.iter_mut() {
                path.push("[]".to_string());
                let r = cast_walk(v, path);
                path.pop();
                r?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn apply_cast(cast: Cast, s: &str) -> Result<G, String> {
    match cast {
        Cast::Int => go_parse_int10(s, "Atoi").map(|i| G::Int(i, "int")),
        Cast::Int64 => go_parse_int10(s, "ParseInt").map(|i| G::Int(i, "int64")),
        Cast::Float => go_parse_float(s, 64).map(|f| G::Float(f, "float64")),
        Cast::Float32 => go_parse_float(s, 32).map(|f| G::Float(f, "float32")),
        Cast::Bool => match s.to_lowercase().as_str() {
            "true" | "y" | "yes" | "on" => Ok(G::Bool(true)),
            "false" | "n" | "no" | "off" => Ok(G::Bool(false)),
            _ => Err(format!("invalid boolean: {s}")),
        },
    }
}

/// `strconv.ParseInt(s, 10, 64)` (and `Atoi`, the same on a 64-bit Go): a sign, then decimal
/// digits only, no underscores, with Go's two errors.
fn go_parse_int10(s: &str, func: &str) -> Result<i64, String> {
    let syntax = || format!("strconv.{func}: parsing {}: invalid syntax", go_quote(s));
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return Err(syntax());
    }
    s.parse::<i64>().map_err(|_| {
        format!(
            "strconv.{func}: parsing {}: value out of range",
            go_quote(s)
        )
    })
}

/// `strconv.ParseFloat(s, bits)`: decimal or hexadecimal (`0x1.8p1`), underscores between digits,
/// `inf`/`infinity`/`nan` in any case, the whole text consumed; past the largest finite value is
/// `value out of range`.
fn go_parse_float(s: &str, bits: u32) -> Result<f64, String> {
    let syntax = || {
        format!(
            "strconv.ParseFloat: parsing {}: invalid syntax",
            go_quote(s)
        )
    };
    let range = || {
        format!(
            "strconv.ParseFloat: parsing {}: value out of range",
            go_quote(s)
        )
    };
    let (neg, body) = match s.as_bytes().first() {
        Some(b'+') => (false, &s[1..]),
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    let lower = body.to_ascii_lowercase();
    if lower == "inf" || lower == "infinity" {
        return Ok(if neg {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        });
    }
    // `special` takes `nan` only without a sign.
    if s.eq_ignore_ascii_case("nan") {
        return Ok(f64::NAN);
    }
    if body.contains('_') && !underscore_ok(s) {
        return Err(syntax());
    }
    let clean: String = body.chars().filter(|c| *c != '_').collect();
    let mag = if let Some(hex) = clean
        .strip_prefix("0x")
        .or_else(|| clean.strip_prefix("0X"))
    {
        parse_hex_float(hex).ok_or_else(syntax)?
    } else {
        if !is_go_decimal_float(&clean) {
            return Err(syntax());
        }
        if bits == 32 {
            f64::from(clean.parse::<f32>().map_err(|_| syntax())?)
        } else {
            clean.parse::<f64>().map_err(|_| syntax())?
        }
    };
    let mag = if bits == 32 {
        f64::from(mag as f32)
    } else {
        mag
    };
    if mag.is_infinite() {
        return Err(range());
    }
    Ok(if neg { -mag } else { mag })
}

/// `[0-9]+(\.[0-9]*)?|\.[0-9]+`, then `[eE][+-]?[0-9]+` optionally.
fn is_go_decimal_float(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    let mut mantissa = 0;
    while b.get(i).is_some_and(u8::is_ascii_digit) {
        i += 1;
        mantissa += 1;
    }
    if b.get(i) == Some(&b'.') {
        i += 1;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
            mantissa += 1;
        }
    }
    if mantissa == 0 {
        return false;
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    i == b.len()
}

/// A hexadecimal mantissa (after `0x`) with its mandatory `p` exponent, as `strconv` reads it.
fn parse_hex_float(s: &str) -> Option<f64> {
    let (mant, exp) = s.split_once(['p', 'P'])?;
    let exp: i32 = {
        let digits = exp.strip_prefix(['+', '-']).unwrap_or(exp);
        if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        exp.parse().unwrap_or(if exp.starts_with('-') {
            i32::MIN / 2
        } else {
            i32::MAX / 2
        })
    };
    let (int, frac) = mant.split_once('.').unwrap_or((mant, ""));
    if int.is_empty() && frac.is_empty() {
        return None;
    }
    let mut v = 0f64;
    for c in int.chars() {
        v = v * 16.0 + f64::from(c.to_digit(16)?);
    }
    let mut scale = 1.0 / 16.0;
    for c in frac.chars() {
        v += f64::from(c.to_digit(16)?) * scale;
        scale /= 16.0;
    }
    Some(v * 2f64.powi(exp))
}

/// `strconv`'s `underscoreOK`: underscores only between digits (a base prefix counts as one).
fn underscore_ok(s: &str) -> bool {
    let b = s.strip_prefix(['+', '-']).unwrap_or(s).as_bytes();
    let mut saw = b'^';
    let mut i = 0;
    let mut hex = false;
    if b.len() >= 2 && b[0] == b'0' && matches!(b[1].to_ascii_lowercase(), b'b' | b'o' | b'x') {
        i = 2;
        saw = b'0';
        hex = b[1].eq_ignore_ascii_case(&b'x');
    }
    while let Some(&c) = b.get(i) {
        i += 1;
        if c.is_ascii_digit() || (hex && c.is_ascii_hexdigit()) {
            saw = b'0';
            continue;
        }
        if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
            continue;
        }
        if saw == b'_' {
            return false;
        }
        saw = b'!';
    }
    saw != b'_'
}

/// Go's `strconv.Quote`: `"` around, `\"` and `\\`, the C escapes, `\x..` for the other control
/// bytes, `\u....` for the C1 controls and the non-printing code points kern names here (the
/// separators, the format characters, the private-use and non-characters). Every printable code
/// point is kept as it is, as Go keeps it.
pub fn go_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c if !go_is_print(c) => {
                if (c as u32) < 0x10000 {
                    out.push_str(&format!("\\u{:04x}", c as u32));
                } else {
                    out.push_str(&format!("\\U{:08x}", c as u32));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `strconv.IsPrint` for the code points outside the graphic classes that a compose file can hold.
fn go_is_print(c: char) -> bool {
    let u = c as u32;
    !matches!(u,
        0x80..=0x9f
        | 0xa0 | 0xad | 0x1680 | 0x180e
        | 0x2000..=0x200f | 0x2028..=0x202f | 0x205f..=0x206f
        | 0x3000 | 0xd800..=0xdfff | 0xe000..=0xf8ff | 0xfeff | 0xfff9..=0xfffb | 0xfffe | 0xffff
        | 0xf0000..=0x10ffff)
}

/// santhosh-tekuri's `quote`: Go's quoting in single quotes, `"` bare and `'` escaped.
fn kind_quote(s: &str) -> String {
    let q = go_quote(s);
    let inner = q.get(1..q.len() - 1).unwrap_or("");
    format!("'{}'", inner.replace("\\\"", "\"").replace('\'', "\\'"))
}

/// An integer as `golang.org/x/text/message`'s English printer writes `%d`: thousands grouped.
fn grouped(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

// ------------------------------------------------------------------------------------------------
// Step 2: compose-go's `override.EnforceUnicity` (override/uncity.go).

#[derive(Debug, Clone, Copy)]
enum Indexer {
    KeyValue,
    Volume,
    DeviceMapping,
    Expose,
    Mount(&'static str),
    Port,
    EnvFile,
}

/// compose-go's table; `services.*.devices` is assigned twice there and the second assignment
/// (the device indexer) is the one that holds.
const UNIQUE: &[(&str, Indexer)] = &[
    ("networks.*.labels", Indexer::KeyValue),
    ("networks.*.ipam.options", Indexer::KeyValue),
    ("services.*.annotations", Indexer::KeyValue),
    ("services.*.build.args", Indexer::KeyValue),
    ("services.*.build.additional_contexts", Indexer::KeyValue),
    ("services.*.build.platform", Indexer::KeyValue),
    ("services.*.build.tags", Indexer::KeyValue),
    ("services.*.build.labels", Indexer::KeyValue),
    ("services.*.cap_add", Indexer::KeyValue),
    ("services.*.cap_drop", Indexer::KeyValue),
    ("services.*.configs", Indexer::Mount("")),
    ("services.*.deploy.labels", Indexer::KeyValue),
    ("services.*.dns", Indexer::KeyValue),
    ("services.*.dns_opt", Indexer::KeyValue),
    ("services.*.dns_search", Indexer::KeyValue),
    ("services.*.environment", Indexer::KeyValue),
    ("services.*.env_file", Indexer::EnvFile),
    ("services.*.expose", Indexer::Expose),
    ("services.*.labels", Indexer::KeyValue),
    ("services.*.links", Indexer::KeyValue),
    ("services.*.networks.*.aliases", Indexer::KeyValue),
    ("services.*.networks.*.link_local_ips", Indexer::KeyValue),
    ("services.*.ports", Indexer::Port),
    ("services.*.profiles", Indexer::KeyValue),
    ("services.*.secrets", Indexer::Mount("/run/secrets")),
    ("services.*.sysctls", Indexer::KeyValue),
    ("services.*.tmpfs", Indexer::KeyValue),
    ("services.*.volumes", Indexer::Volume),
    ("services.*.devices", Indexer::DeviceMapping),
];

/// Walks mappings only, as compose-go does: a list is deduplicated where the table names it and is
/// not walked into.
fn unicity(g: &mut G, path: &mut Vec<String>) -> Result<(), String> {
    match g {
        G::Map(m) => {
            for (k, v) in m.iter_mut() {
                path.push(k.clone());
                let r = unicity(v, path);
                path.pop();
                r?;
            }
            Ok(())
        }
        G::Seq(items) => {
            let Some((_, ix)) = UNIQUE.iter().find(|(p, _)| path_matches(path, p)) else {
                return Ok(());
            };
            let mut seq: Vec<G> = Vec::new();
            let mut keys: HashMap<String, usize> = HashMap::new();
            for (i, entry) in items.iter().enumerate() {
                let at = format!("{}.[{i}]", path.join("."));
                let key = index_key(*ix, entry, &at)?;
                match keys.get(&key) {
                    Some(&j) => {
                        if let Some(slot) = seq.get_mut(j) {
                            *slot = entry.clone();
                        }
                    }
                    None => {
                        seq.push(entry.clone());
                        keys.insert(key, seq.len() - 1);
                    }
                }
            }
            *items = seq;
            Ok(())
        }
        _ => Ok(()),
    }
}

fn index_key(ix: Indexer, g: &G, p: &str) -> Result<String, String> {
    match ix {
        Indexer::KeyValue => match g {
            G::Str(s) => Ok(s.split_once('=').map_or(s.as_str(), |(k, _)| k).to_string()),
            _ => Err(format!("{p}: unexpected type {}", g.go_type())),
        },
        Indexer::Volume => match g {
            G::Map(_) => match g.get("target") {
                Some(G::Str(t)) => Ok(t.clone()),
                _ => Err(format!("service volume {p} is missing a mount target")),
            },
            G::Str(s) => parse_volume_target(s),
            _ => Ok(String::new()),
        },
        Indexer::DeviceMapping => match g {
            G::Map(_) => match g.get("target") {
                Some(G::Str(t)) => Ok(t.clone()),
                _ => Err(format!("service device {p} is missing a mount target")),
            },
            G::Str(s) => {
                let arr: Vec<&str> = s.split(':').collect();
                Ok(arr
                    .get(1)
                    .or(arr.first())
                    .copied()
                    .unwrap_or("")
                    .to_string())
            }
            _ => Ok(String::new()),
        },
        Indexer::Expose => match g {
            G::Str(s) => Ok(s.clone()),
            G::Int(i, "int") => Ok(i.to_string()),
            _ => Err(format!("{p}: unsupported expose value {}", go_s(g))),
        },
        // compose-go asserts a `target` to a string and would stop on another type; kern keys it by
        // its text instead.
        Indexer::Mount(default) => match g {
            G::Str(s) => Ok(format!("{default}/{s}")),
            G::Map(_) => match g.get("target") {
                Some(t) => Ok(go_s(t)),
                None => Ok(format!(
                    "{default}/{}",
                    go_s(g.get("source").unwrap_or(&G::Null))
                )),
            },
            _ => Err(format!("{p}: unsupported expose value {}", go_s(g))),
        },
        Indexer::Port => match g {
            G::Int(i, "int") => Ok(i.to_string()),
            G::Map(_) => {
                let Some(target) = g.get("target") else {
                    return Err(format!("service ports {p} is missing a target port"));
                };
                let host = g.get("host_ip").map_or("0.0.0.0".to_string(), go_s);
                let published = go_s(g.get("published").unwrap_or(&G::Null));
                let protocol = g.get("protocol").map_or("tcp".to_string(), go_s);
                Ok(format!("{host}:{published}:{}/{protocol}", go_d(target)))
            }
            G::Str(s) => Ok(s.clone()),
            _ => Ok(String::new()),
        },
        Indexer::EnvFile => match g {
            G::Str(s) => Ok(s.clone()),
            G::Map(_) => match g.get("path") {
                Some(v) => Ok(go_s(v)),
                None => Err(format!("environment path attribute {p} is missing")),
            },
            _ => Ok(String::new()),
        },
    }
}

/// The target compose-go's `format.ParseVolume` reads from a short volume, with its three errors.
fn parse_volume_target(spec: &str) -> Result<String, String> {
    match spec.len() {
        0 => return Err("invalid empty volume spec".to_string()),
        1 | 2 => return Ok(spec.to_string()),
        _ => {}
    }
    let bytes = spec.as_bytes();
    let mut buffer: Vec<char> = Vec::new();
    let mut in_var = 0usize;
    let mut source = String::new();
    let mut target = String::new();
    let chars = spec
        .char_indices()
        .chain(std::iter::once((spec.len(), '\0')));
    for (i, c) in chars {
        if c == '$' && i + 1 < spec.len() && bytes.get(i + 1) == Some(&b'{') {
            in_var += 1;
            buffer.push(c);
            continue;
        }
        if c == '}' && in_var > 0 {
            in_var -= 1;
            buffer.push(c);
            continue;
        }
        let windows_drive =
            c == ':' && buffer.len() == 1 && buffer.first().is_some_and(|b| b.is_alphabetic());
        if windows_drive {
            buffer.push(c);
        } else if (c == ':' || c == '\0') && in_var == 0 {
            let text: String = buffer.iter().collect();
            let err = if buffer.is_empty() {
                Some("empty section between colons")
            } else if source.is_empty() && c == '\0' {
                target = text;
                None
            } else if source.is_empty() {
                source = text;
                None
            } else if target.is_empty() {
                target = text;
                None
            } else if c == ':' {
                Some("too many colons")
            } else {
                None
            };
            if let Some(e) = err {
                return Err(format!("invalid spec: {spec}: {e}"));
            }
            buffer.clear();
        } else {
            buffer.push(c);
        }
    }
    Ok(target)
}

// ------------------------------------------------------------------------------------------------
// Step 3: the schema, as santhosh-tekuri/jsonschema v6.0.1 checks it.

/// A JSON value: the schema, and the document as compose-go hands it to the validator.
#[derive(Debug, Clone, PartialEq)]
enum J {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    fn get(&self, key: &str) -> Option<&J> {
        match self {
            J::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn type_name(&self) -> &'static str {
        match self {
            J::Null => "null",
            J::Bool(_) => "boolean",
            J::Num(_) => "number",
            J::Str(_) => "string",
            J::Arr(_) => "array",
            J::Obj(_) => "object",
        }
    }
}

/// santhosh-tekuri's `duplicates`: the first `i` with an equal earlier item, and the first such `j`.
/// Pairwise up to 20 items, as there; above, by a canonical key per item, so a file listing
/// thousands of distinct entries costs one pass and not a square.
fn first_duplicate(items: &[J]) -> Option<(usize, usize)> {
    if items.len() <= 20 {
        for i in 1..items.len() {
            for j in 0..i {
                if let (Some(a), Some(b)) = (items.get(i), items.get(j)) {
                    if equals(a, b) {
                        return Some((j, i));
                    }
                }
            }
        }
        return None;
    }
    let mut seen: HashMap<String, usize> = HashMap::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let key = canonical(item);
        if let Some(&j) = seen.get(&key) {
            return Some((j, i));
        }
        seen.insert(key, i);
    }
    None
}

/// One text per value under [`equals`]: equal values, and only they, give equal keys (objects with
/// their keys sorted, numbers by value).
fn canonical(v: &J) -> String {
    match v {
        J::Null => "n".to_string(),
        J::Bool(b) => format!("b{b}"),
        J::Num(n) => format!("d{}", if *n == 0.0 { 0.0 } else { *n }),
        J::Str(s) => format!("s{}:{s}", s.len()),
        J::Arr(a) => {
            let parts: Vec<String> = a.iter().map(canonical).collect();
            format!("a{}[{}]", parts.len(), parts.join(","))
        }
        J::Obj(m) => {
            let mut kv: Vec<(&String, String)> = m.iter().map(|(k, v)| (k, canonical(v))).collect();
            kv.sort_by(|a, b| a.0.cmp(b.0));
            let parts: Vec<String> = kv
                .iter()
                .map(|(k, v)| format!("{}:{k}={v}", k.len()))
                .collect();
            format!("o{}{{{}}}", parts.len(), parts.join(","))
        }
    }
}

/// santhosh-tekuri's `equals`: numbers by value, objects regardless of key order.
fn equals(a: &J, b: &J) -> bool {
    match (a, b) {
        (J::Obj(x), J::Obj(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| b.get(k).is_some_and(|w| equals(v, w)))
                && y.iter().all(|(k, _)| a.get(k).is_some())
        }
        (J::Arr(x), J::Arr(y)) => x.len() == y.len() && x.iter().zip(y).all(|(v, w)| equals(v, w)),
        _ => a == b,
    }
}

/// A JSON reader for the vendored schema.
struct JsonReader<'a> {
    b: &'a [u8],
    i: usize,
}

impl JsonReader<'_> {
    fn err(&self, what: &str) -> String {
        format!("compose-spec.json: {what} at byte {}", self.i)
    }

    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Result<J, String> {
        if depth > 128 {
            return Err(self.err("nesting too deep"));
        }
        self.ws();
        match self.b.get(self.i) {
            Some(b'{') => {
                self.i += 1;
                let mut m = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(J::Obj(m));
                }
                loop {
                    self.ws();
                    let k = self.string()?;
                    self.ws();
                    if self.b.get(self.i) != Some(&b':') {
                        return Err(self.err("expected ':'"));
                    }
                    self.i += 1;
                    let v = self.value(depth + 1)?;
                    m.push((k, v));
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(J::Obj(m));
                        }
                        _ => return Err(self.err("expected ',' or '}'")),
                    }
                }
            }
            Some(b'[') => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(J::Arr(a));
                }
                loop {
                    a.push(self.value(depth + 1)?);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(J::Arr(a));
                        }
                        _ => return Err(self.err("expected ',' or ']'")),
                    }
                }
            }
            Some(b'"') => self.string().map(J::Str),
            Some(b't') => self.word("true", J::Bool(true)),
            Some(b'f') => self.word("false", J::Bool(false)),
            Some(b'n') => self.word("null", J::Null),
            Some(c) if *c == b'-' || c.is_ascii_digit() => {
                let start = self.i;
                while matches!(
                    self.b.get(self.i),
                    Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                ) {
                    self.i += 1;
                }
                std::str::from_utf8(self.b.get(start..self.i).unwrap_or_default())
                    .ok()
                    .and_then(|t| t.parse::<f64>().ok())
                    .map(J::Num)
                    .ok_or_else(|| self.err("bad number"))
            }
            _ => Err(self.err("unexpected character")),
        }
    }

    fn word(&mut self, w: &str, v: J) -> Result<J, String> {
        if self.b.get(self.i..self.i + w.len()) == Some(w.as_bytes()) {
            self.i += w.len();
            Ok(v)
        } else {
            Err(self.err("unexpected word"))
        }
    }

    fn string(&mut self) -> Result<String, String> {
        if self.b.get(self.i) != Some(&b'"') {
            return Err(self.err("expected a string"));
        }
        self.i += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(&c) = self.b.get(self.i) else {
                return Err(self.err("unterminated string"));
            };
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let Some(&e) = self.b.get(self.i) else {
                        return Err(self.err("unterminated escape"));
                    };
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let code = if (0xd800..0xdc00).contains(&hi) {
                                if self.b.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return Err(self.err("lone surrogate"));
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                0x10000 + ((hi - 0xd800) << 10) + (lo.wrapping_sub(0xdc00) & 0x3ff)
                            } else {
                                hi
                            };
                            char::from_u32(code).ok_or_else(|| self.err("bad escape"))?
                        }
                        _ => return Err(self.err("bad escape")),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                c => out.push(c),
            }
        }
        String::from_utf8(out).map_err(|_| self.err("invalid UTF-8"))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let t = self
            .b
            .get(self.i..self.i + 4)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u32::from_str_radix(h, 16).ok())
            .ok_or_else(|| self.err("bad \\u escape"))?;
        self.i += 4;
        Ok(t)
    }
}

/// The keywords compose-spec.json uses that change a result, and the ones that are annotations.
/// [`Spec::load`] refuses a schema with any other, so a newer vendored file cannot be checked by a
/// validator that skips what it says.
const KEYWORDS: &[&str] = &[
    "type",
    "enum",
    "$ref",
    "properties",
    "patternProperties",
    "additionalProperties",
    "required",
    "items",
    "uniqueItems",
    "pattern",
    "minimum",
    "maximum",
    "oneOf",
];
const ANNOTATIONS: &[&str] = &[
    "$schema",
    "$id",
    "$defs",
    "title",
    "description",
    "deprecated",
    "default",
    "examples",
];

struct Spec {
    root: J,
    regexes: HashMap<String, Regex>,
}

fn spec() -> Result<&'static Spec, &'static String> {
    static SPEC_ONCE: std::sync::OnceLock<Result<Spec, String>> = std::sync::OnceLock::new();
    SPEC_ONCE.get_or_init(Spec::load).as_ref()
}

impl Spec {
    fn load() -> Result<Spec, String> {
        let mut r = JsonReader {
            b: SPEC.as_bytes(),
            i: 0,
        };
        let root = r.value(0)?;
        let mut spec = Spec {
            root,
            regexes: HashMap::new(),
        };
        let mut patterns = Vec::new();
        audit(&spec.root, &mut patterns, "#")?;
        for p in patterns {
            // 63 uses of 7 patterns: each compiled once.
            if spec.regexes.contains_key(&p) {
                continue;
            }
            let re =
                Regex::new(&p).map_err(|e| format!("compose-spec.json: pattern {p:?}: {e}"))?;
            spec.regexes.insert(p, re);
        }
        Ok(spec)
    }

    fn regex(&self, p: &str) -> Result<&Regex, String> {
        self.regexes
            .get(p)
            .ok_or_else(|| format!("compose-spec.json: pattern {p:?} was not compiled"))
    }

    fn resolve(&self, r: &str) -> Result<&J, String> {
        let Some(pointer) = r.strip_prefix("#/") else {
            return Err(format!("compose-spec.json: $ref {r:?} is not local"));
        };
        let mut at = &self.root;
        for tok in pointer.split('/') {
            let tok = tok.replace("~1", "/").replace("~0", "~");
            at = at
                .get(&tok)
                .ok_or_else(|| format!("compose-spec.json: $ref {r:?} names nothing"))?;
        }
        Ok(at)
    }

    /// santhosh-tekuri's `validator.validate` for draft 2020-12, keyword by keyword in its order,
    /// pushing every failure that has no causes (the leaves `getMostSpecificError` chooses from).
    /// A value is valid when nothing was pushed.
    fn check(&self, s: &J, v: &J, at: &mut Vec<String>, out: &mut Vec<Leaf>) -> Result<(), String> {
        let leaf = |kind: Kind, at: &[String]| Leaf {
            at: at.to_vec(),
            kind,
        };
        let kw = match s {
            J::Bool(true) => return Ok(()),
            J::Bool(false) => {
                out.push(leaf(Kind::False, at));
                return Ok(());
            }
            J::Obj(_) => s,
            _ => return Ok(()),
        };
        // type: a failure ends the check of this value.
        if let Some(t) = kw.get("type") {
            let want: Vec<String> = match t {
                J::Str(one) => vec![one.clone()],
                J::Arr(many) => many
                    .iter()
                    .filter_map(|x| match x {
                        J::Str(s) => Some(s.clone()),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            };
            let got = v.type_name();
            let integer = matches!(v, J::Num(n) if n.fract() == 0.0 && n.is_finite());
            let matched = want.iter().any(|w| w == got || (w == "integer" && integer));
            if !want.is_empty() && !matched {
                out.push(leaf(Kind::Type(want), at));
                return Ok(());
            }
        }
        // enum: likewise.
        if let Some(J::Arr(values)) = kw.get("enum") {
            if !values.iter().any(|e| equals(v, e)) {
                out.push(leaf(Kind::Enum(values.clone()), at));
                return Ok(());
            }
        }
        if let Some(J::Str(r)) = kw.get("$ref") {
            let target = self.resolve(r)?;
            self.check(target, v, at, out)?;
        }
        match v {
            J::Obj(members) => {
                if let Some(J::Arr(req)) = kw.get("required") {
                    let missing: Vec<String> = req
                        .iter()
                        .filter_map(|r| match r {
                            J::Str(name) if v.get(name).is_none() => Some(name.clone()),
                            _ => None,
                        })
                        .collect();
                    if !missing.is_empty() {
                        out.push(leaf(Kind::Required(missing), at));
                    }
                }
                let props = kw.get("properties");
                let pattern_props = kw.get("patternProperties");
                let additional = kw.get("additionalProperties");
                let mut extra: Vec<String> = Vec::new();
                for (name, value) in members {
                    let mut evaluated = false;
                    if let Some(sub) = props.and_then(|p| p.get(name)) {
                        evaluated = true;
                        at.push(name.clone());
                        let r = self.check(sub, value, at, out);
                        at.pop();
                        r?;
                    }
                    if let Some(J::Obj(pp)) = pattern_props {
                        for (re, sub) in pp {
                            if self.regex(re)?.is_match(name) {
                                evaluated = true;
                                at.push(name.clone());
                                let r = self.check(sub, value, at, out);
                                at.pop();
                                r?;
                            }
                        }
                    }
                    if !evaluated {
                        match additional {
                            Some(J::Bool(false)) => extra.push(name.clone()),
                            Some(sub @ J::Obj(_)) => {
                                at.push(name.clone());
                                let r = self.check(sub, value, at, out);
                                at.pop();
                                r?;
                            }
                            _ => {}
                        }
                    }
                }
                if !extra.is_empty() {
                    // MEASURED: Docker names them sorted (`'bar', 'foo'` for `foo:` then `bar:`, 6
                    // runs of 6).
                    extra.sort();
                    out.push(leaf(Kind::Additional(extra), at));
                }
            }
            J::Arr(items) => {
                if kw.get("uniqueItems") == Some(&J::Bool(true)) && items.len() > 1 {
                    if let Some((j, i)) = first_duplicate(items) {
                        out.push(leaf(Kind::Unique(j, i), at));
                    }
                }
                if let Some(sub) = kw.get("items") {
                    for (i, item) in items.iter().enumerate() {
                        at.push(i.to_string());
                        let r = self.check(sub, item, at, out);
                        at.pop();
                        r?;
                    }
                }
            }
            J::Str(text) => {
                if let Some(J::Str(p)) = kw.get("pattern") {
                    if !self.regex(p)?.is_match(text) {
                        out.push(leaf(Kind::Pattern(text.clone(), p.clone()), at));
                    }
                }
            }
            J::Num(n) => {
                if let Some(J::Num(min)) = kw.get("minimum") {
                    if n < min {
                        out.push(leaf(Kind::Minimum(*min), at));
                    }
                }
                if let Some(J::Num(max)) = kw.get("maximum") {
                    if n > max {
                        out.push(leaf(Kind::Maximum(*max), at));
                    }
                }
            }
            _ => {}
        }
        if let Some(J::Arr(branches)) = kw.get("oneOf") {
            let mut matched: Option<usize> = None;
            let mut failures: Vec<Leaf> = Vec::new();
            for (i, sub) in branches.iter().enumerate() {
                let mut local = Vec::new();
                self.check(sub, v, at, &mut local)?;
                if local.is_empty() {
                    if let Some(first) = matched {
                        out.push(leaf(Kind::OneOfTwo(first, i), at));
                        break;
                    }
                    matched = Some(i);
                } else if matched.is_none() {
                    failures.extend(local);
                }
            }
            if matched.is_none() {
                out.extend(failures);
            }
        }
        Ok(())
    }
}

/// Every keyword of the schema is one [`Spec::check`] implements or an annotation, every
/// `minimum`/`maximum` is an integer (compose-go prints `Want.Num()`, the numerator), and every
/// pattern is collected for compiling.
fn audit(s: &J, patterns: &mut Vec<String>, at: &str) -> Result<(), String> {
    let J::Obj(kw) = s else {
        return Ok(());
    };
    for (k, v) in kw {
        let here = format!("{at}/{k}");
        if !KEYWORDS.contains(&k.as_str()) && !ANNOTATIONS.contains(&k.as_str()) {
            return Err(format!(
                "compose-spec.json: keyword {k:?} at {at} is not one kern's validator implements"
            ));
        }
        match k.as_str() {
            "properties" | "$defs" => {
                if let J::Obj(m) = v {
                    for (name, sub) in m {
                        audit(sub, patterns, &format!("{here}/{name}"))?;
                    }
                }
            }
            "patternProperties" => {
                if let J::Obj(m) = v {
                    for (re, sub) in m {
                        patterns.push(re.clone());
                        audit(sub, patterns, &format!("{here}/{re}"))?;
                    }
                }
            }
            "pattern" => {
                if let J::Str(p) = v {
                    patterns.push(p.clone());
                }
            }
            "minimum" | "maximum" => {
                if !matches!(v, J::Num(n) if n.fract() == 0.0) {
                    return Err(format!("compose-spec.json: {here} is not an integer"));
                }
            }
            "items" | "additionalProperties" => {
                if matches!(v, J::Arr(_)) {
                    return Err(format!("compose-spec.json: {here} is a list of schemas"));
                }
                audit(v, patterns, &here)?;
            }
            "oneOf" => {
                if let J::Arr(a) = v {
                    for (i, sub) in a.iter().enumerate() {
                        audit(sub, patterns, &format!("{here}/{i}"))?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
enum Kind {
    Type(Vec<String>),
    Enum(Vec<J>),
    Required(Vec<String>),
    Additional(Vec<String>),
    Pattern(String, String),
    Unique(usize, usize),
    Minimum(f64),
    Maximum(f64),
    OneOfTwo(usize, usize),
    False,
}

#[derive(Debug, Clone, PartialEq)]
struct Leaf {
    at: Vec<String>,
    kind: Kind,
}

impl Leaf {
    /// compose-go's `specificity`: the depth, one more for an unknown key.
    fn specificity(&self) -> usize {
        self.at.len() + usize::from(matches!(self.kind, Kind::Additional(_)))
    }

    /// compose-go's `validationError.Error()`, over santhosh-tekuri's English wording.
    fn message(&self) -> String {
        let path = self.at.join(".");
        match &self.kind {
            Kind::Type(want) => format!("{path} must be a {}", human_type(want)),
            Kind::Minimum(w) => format!("{path} must be greater than or equal to {}", *w as i64),
            Kind::Maximum(w) => format!("{path} must be less than or equal to {}", *w as i64),
            Kind::Required(missing) => match missing.as_slice() {
                [one] => format!("{path} missing property {}", kind_quote(one)),
                many => format!("{path} missing properties {}", join_quoted(many)),
            },
            Kind::Additional(names) => {
                format!(
                    "{path} additional properties {} not allowed",
                    join_quoted(names)
                )
            }
            Kind::Enum(values) => {
                if values.iter().any(|v| matches!(v, J::Arr(_) | J::Obj(_))) {
                    format!("{path} enum failed")
                } else if let [one] = values.as_slice() {
                    format!("{path} value must be {}", display(one))
                } else {
                    let shown: Vec<String> = values.iter().map(display).collect();
                    format!("{path} value must be one of {}", shown.join(", "))
                }
            }
            Kind::Pattern(got, want) => format!(
                "{path} {} does not match pattern {}",
                kind_quote(got),
                kind_quote(want)
            ),
            Kind::Unique(i, j) => {
                format!(
                    "{path} items at {} and {} are equal",
                    grouped(*i),
                    grouped(*j)
                )
            }
            Kind::OneOfTwo(i, j) => format!(
                "{path} oneOf failed, subschemas {}, {} matched",
                grouped(*i),
                grouped(*j)
            ),
            Kind::False => format!("{path} false schema"),
        }
    }
}

fn join_quoted(names: &[String]) -> String {
    names
        .iter()
        .map(|n| kind_quote(n))
        .collect::<Vec<_>>()
        .join(", ")
}

/// santhosh-tekuri's `display` of a primitive enum value.
fn display(v: &J) -> String {
    match v {
        J::Str(s) => kind_quote(s),
        J::Null => "<nil>".to_string(),
        J::Bool(b) => b.to_string(),
        J::Num(n) => canon::go_format_float(*n, 64),
        J::Arr(_) | J::Obj(_) => "value".to_string(),
    }
}

/// compose-go's `humanReadableType`: `object` is `mapping`; several are sorted, `a, b or c`.
fn human_type(want: &[String]) -> String {
    let name = |w: &str| {
        if w == "object" {
            "mapping".to_string()
        } else {
            w.to_string()
        }
    };
    match want {
        [one] => name(one),
        many => {
            let mut names: Vec<String> = many.iter().map(|w| name(w)).collect();
            names.sort();
            match names.split_last() {
                Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
                None => String::new(),
            }
        }
    }
}

/// compose-go's `getMostSpecificError`: the deepest leaf, the first of equals.
fn most_specific(leaves: &[Leaf]) -> Option<&Leaf> {
    let mut best: Option<&Leaf> = None;
    for l in leaves {
        if best.is_none_or(|b| l.specificity() > b.specificity()) {
            best = Some(l);
        }
    }
    best
}

// ------------------------------------------------------------------------------------------------
// The patterns, as Go's `regexp` matches them (RE2: `MatchString` finds a match anywhere, `.` is any
// character but a newline, `^`/`$` are the ends of the text). A Pike VM: linear in the text, so a
// value written to make a backtracking matcher spin cannot.

#[derive(Debug, Clone)]
enum Node {
    Char(char),
    Any,
    Class(Vec<(char, char)>, bool),
    Begin,
    End,
    Cat(Vec<Node>),
    Alt(Vec<Node>),
    Star(Box<Node>),
    Plus(Box<Node>),
    Quest(Box<Node>),
}

#[derive(Debug, Clone)]
enum Inst {
    Char(char),
    Any,
    Class(Vec<(char, char)>, bool),
    Begin,
    End,
    Split(usize, usize),
    Jmp(usize),
    Match,
}

#[derive(Debug, Clone)]
struct Regex {
    prog: Vec<Inst>,
    /// `^` and plain characters only (`^x-`, asked of nearly every key of a file): the match is
    /// `starts_with`, without the machine.
    prefix: Option<String>,
}

struct ReParser<'a> {
    c: Vec<char>,
    i: usize,
    src: &'a str,
}

impl ReParser<'_> {
    fn err(&self, what: &str) -> String {
        format!("{what} at {} in {:?}", self.i, self.src)
    }

    fn alt(&mut self) -> Result<Node, String> {
        let mut branches = vec![self.cat()?];
        while self.c.get(self.i) == Some(&'|') {
            self.i += 1;
            branches.push(self.cat()?);
        }
        Ok(if branches.len() == 1 {
            branches.remove(0)
        } else {
            Node::Alt(branches)
        })
    }

    fn cat(&mut self) -> Result<Node, String> {
        let mut items = Vec::new();
        while let Some(&c) = self.c.get(self.i) {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.atom()?;
            let atom = match self.c.get(self.i) {
                Some('*') => {
                    self.i += 1;
                    Node::Star(Box::new(atom))
                }
                Some('+') => {
                    self.i += 1;
                    Node::Plus(Box::new(atom))
                }
                Some('?') => {
                    self.i += 1;
                    Node::Quest(Box::new(atom))
                }
                _ => atom,
            };
            if matches!(self.c.get(self.i), Some('*' | '+' | '?' | '{')) {
                return Err(self.err("repetition kern's matcher does not implement"));
            }
            items.push(atom);
        }
        Ok(Node::Cat(items))
    }

    fn atom(&mut self) -> Result<Node, String> {
        let Some(&c) = self.c.get(self.i) else {
            return Err(self.err("unexpected end"));
        };
        self.i += 1;
        match c {
            '(' => {
                if self.c.get(self.i) == Some(&'?') {
                    if self.c.get(self.i + 1) == Some(&':') {
                        self.i += 2;
                    } else {
                        return Err(self.err("group flag kern's matcher does not implement"));
                    }
                }
                let inner = self.alt()?;
                if self.c.get(self.i) != Some(&')') {
                    return Err(self.err("missing ')'"));
                }
                self.i += 1;
                Ok(inner)
            }
            '[' => self.class(),
            '.' => Ok(Node::Any),
            '^' => Ok(Node::Begin),
            '$' => Ok(Node::End),
            '\\' => self.escape().map(Node::Char),
            '*' | '+' | '?' | '{' | ')' => Err(self.err("misplaced operator")),
            c => Ok(Node::Char(c)),
        }
    }

    fn escape(&mut self) -> Result<char, String> {
        let Some(&e) = self.c.get(self.i) else {
            return Err(self.err("trailing backslash"));
        };
        self.i += 1;
        if e.is_ascii_punctuation() {
            Ok(e)
        } else {
            match e {
                'n' => Ok('\n'),
                't' => Ok('\t'),
                'r' => Ok('\r'),
                _ => Err(self.err("escape kern's matcher does not implement")),
            }
        }
    }

    fn class(&mut self) -> Result<Node, String> {
        let negated = self.c.get(self.i) == Some(&'^');
        if negated {
            self.i += 1;
        }
        let mut ranges = Vec::new();
        let mut first = true;
        loop {
            let Some(&c) = self.c.get(self.i) else {
                return Err(self.err("missing ']'"));
            };
            if c == ']' && !first {
                self.i += 1;
                break;
            }
            first = false;
            self.i += 1;
            let lo = match c {
                '\\' => self.escape()?,
                '[' if self.c.get(self.i) == Some(&':') => {
                    return Err(self.err("character class name kern's matcher does not implement"));
                }
                c => c,
            };
            let hi = if self.c.get(self.i) == Some(&'-')
                && self.c.get(self.i + 1).is_some_and(|n| *n != ']')
            {
                self.i += 1;
                let Some(&h) = self.c.get(self.i) else {
                    return Err(self.err("missing ']'"));
                };
                self.i += 1;
                if h == '\\' {
                    self.escape()?
                } else {
                    h
                }
            } else {
                lo
            };
            if hi < lo {
                return Err(self.err("range out of order"));
            }
            ranges.push((lo, hi));
        }
        Ok(Node::Class(ranges, negated))
    }
}

impl Regex {
    fn new(src: &str) -> Result<Regex, String> {
        let mut p = ReParser {
            c: src.chars().collect(),
            i: 0,
            src,
        };
        let node = p.alt()?;
        if p.i != p.c.len() {
            return Err(p.err("unbalanced ')'"));
        }
        let mut prog = Vec::new();
        emit(&node, &mut prog);
        prog.push(Inst::Match);
        let prefix = src.strip_prefix('^').filter(|rest| {
            !rest.is_empty()
                && rest
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        });
        Ok(Regex {
            prog,
            prefix: prefix.map(str::to_string),
        })
    }

    /// Go's `MatchString`: a match starting anywhere.
    fn is_match(&self, text: &str) -> bool {
        if let Some(p) = &self.prefix {
            return text.starts_with(p.as_str());
        }
        let chars: Vec<char> = text.chars().collect();
        let n = self.prog.len();
        let mut seen = vec![usize::MAX; n];
        let mut current: Vec<usize> = Vec::new();
        let mut next: Vec<usize> = Vec::new();
        for pos in 0..=chars.len() {
            if self.add(&mut current, &mut seen, 0, pos, chars.len()) {
                return true;
            }
            let Some(&c) = chars.get(pos) else {
                break;
            };
            next.clear();
            for &pc in &current {
                let step = match self.prog.get(pc) {
                    Some(Inst::Char(x)) => *x == c,
                    Some(Inst::Any) => c != '\n',
                    Some(Inst::Class(ranges, neg)) => {
                        ranges.iter().any(|(lo, hi)| *lo <= c && c <= *hi) != *neg
                    }
                    _ => false,
                };
                if step && self.add(&mut next, &mut seen, pc + 1, pos + 1, chars.len()) {
                    return true;
                }
            }
            std::mem::swap(&mut current, &mut next);
        }
        false
    }

    /// Follow the empty transitions from `pc` at `pos`, adding the threads that wait on a
    /// character; true when one reaches `Match`.
    fn add(
        &self,
        list: &mut Vec<usize>,
        seen: &mut [usize],
        pc: usize,
        pos: usize,
        len: usize,
    ) -> bool {
        let mut stack = vec![pc];
        while let Some(pc) = stack.pop() {
            match seen.get_mut(pc) {
                Some(s) if *s == pos => continue,
                Some(s) => *s = pos,
                None => continue,
            }
            match self.prog.get(pc) {
                Some(Inst::Match) => return true,
                Some(Inst::Jmp(t)) => stack.push(*t),
                Some(Inst::Split(a, b)) => {
                    stack.push(*b);
                    stack.push(*a);
                }
                Some(Inst::Begin) => {
                    if pos == 0 {
                        stack.push(pc + 1);
                    }
                }
                Some(Inst::End) => {
                    if pos == len {
                        stack.push(pc + 1);
                    }
                }
                Some(_) => list.push(pc),
                None => {}
            }
        }
        false
    }
}

fn emit(node: &Node, prog: &mut Vec<Inst>) {
    match node {
        Node::Char(c) => prog.push(Inst::Char(*c)),
        Node::Any => prog.push(Inst::Any),
        Node::Class(r, neg) => prog.push(Inst::Class(r.clone(), *neg)),
        Node::Begin => prog.push(Inst::Begin),
        Node::End => prog.push(Inst::End),
        Node::Cat(items) => {
            for i in items {
                emit(i, prog);
            }
        }
        Node::Alt(branches) => {
            let mut jumps = Vec::new();
            for (k, b) in branches.iter().enumerate() {
                if k + 1 < branches.len() {
                    let split = prog.len();
                    prog.push(Inst::Split(split + 1, 0));
                    emit(b, prog);
                    jumps.push(prog.len());
                    prog.push(Inst::Jmp(0));
                    let after = prog.len();
                    if let Some(Inst::Split(_, second)) = prog.get_mut(split) {
                        *second = after;
                    }
                } else {
                    emit(b, prog);
                }
            }
            let end = prog.len();
            for j in jumps {
                if let Some(Inst::Jmp(t)) = prog.get_mut(j) {
                    *t = end;
                }
            }
        }
        Node::Star(inner) => {
            let split = prog.len();
            prog.push(Inst::Split(split + 1, 0));
            emit(inner, prog);
            prog.push(Inst::Jmp(split));
            let after = prog.len();
            if let Some(Inst::Split(_, second)) = prog.get_mut(split) {
                *second = after;
            }
        }
        Node::Plus(inner) => {
            let start = prog.len();
            emit(inner, prog);
            let split = prog.len();
            prog.push(Inst::Split(start, split + 1));
        }
        Node::Quest(inner) => {
            let split = prog.len();
            prog.push(Inst::Split(split + 1, 0));
            emit(inner, prog);
            let after = prog.len();
            if let Some(Inst::Split(_, second)) = prog.get_mut(split) {
                *second = after;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(yaml: &str) -> Option<Refusal> {
        let val = crate::yaml::document_val(yaml, &crate::DotEnv::default(), None, true)
            .expect("test YAML reads");
        check_val(&val, "/p/compose.yaml", true)
    }

    fn message(yaml: &str) -> String {
        match refusal(yaml) {
            Some(Refusal::Final(m)) | Some(Refusal::UnknownKey(m)) => m,
            None => String::from("<accepted>"),
        }
    }

    /// go-yaml's measured answers (Docker Compose 5.3.1), and the forms it accepts.
    #[test]
    fn a_flow_with_an_unquoted_interpolation_is_go_yaml_s_parse_error() {
        let h = "services:\n  a:\n    image: alpine\n";
        assert_eq!(
            flow_indicator_in_plain_scalar(&format!("{h}    command: [echo, ${{X}}]\n")),
            Some("go-yaml load error in parser (while parsing a flow sequence) at L4.C14-C22: did not find expected ',' or ']'".to_string())
        );
        assert_eq!(
            flow_indicator_in_plain_scalar(&format!("{h}    labels: {{a: ${{X}}}}\n")),
            Some("go-yaml load error in parser (while parsing a flow mapping) at L4.C13-C18: did not find expected ',' or '}'".to_string())
        );
        assert_eq!(
            flow_indicator_in_plain_scalar(&format!("{h}    command:\n      - [x${{A}}]\n")),
            Some("go-yaml load error in parser (while parsing a flow sequence) at L5.C9-C12: did not find expected ',' or ']'".to_string())
        );
        for ok in [
            "    command: [\"${X}\", a]\n",
            "    command: [a b, c]\n",
            "    command: |\n      [x${A}]\n",
            "    environment: [A=${X:-1}]  # no\n"
                .replace("[A=${X:-1}]", "[\"A=${X:-1}\"]")
                .as_str(),
            "    healthcheck: {test: [CMD, true], interval: 1s}\n",
            "    command: echo [${X}]\n",
        ] {
            assert_eq!(
                flow_indicator_in_plain_scalar(&format!("{h}{ok}")),
                None,
                "{ok}"
            );
        }
    }

    /// Each kern-only key is one kern's parser takes and Docker's schema does not have: the two ends
    /// of the exemption, held together.
    #[test]
    fn kern_s_own_service_keys_are_left_to_kern_and_are_kern_s() {
        let s = spec().expect("schema loads");
        let props = s
            .root
            .get("$defs")
            .and_then(|d| d.get("service"))
            .and_then(|v| v.get("properties"))
            .expect("service properties");
        for k in crate::yaml::KERN_SERVICE_KEYS {
            assert!(props.get(k).is_none(), "{k} is Docker's, not kern's");
            let value = match *k {
                "bind_rootfs" => "true",
                "port" => "8080",
                "cpus_shares" => "2",
                "memory" | "mem_swap_limit" | "memory_reservation" => "64m",
                "dns_options" => "[ndots:1]",
                "rootfs" => "/tmp",
                _ => "/w",
            };
            // A swap limit is memory PLUS swap, refused alone by kern as by Docker.
            let with = if *k == "mem_swap_limit" {
                "    mem_limit: 32m\n"
            } else {
                ""
            };
            let text = format!("services:\n  a:\n    image: alpine\n{with}    {k}: {value}\n");
            assert_eq!(
                refusal(&text),
                None,
                "{k} must not be refused by Docker's schema"
            );
            assert!(
                crate::parse(&text).is_ok() || *k == "rootfs",
                "{k}: kern reads it"
            );
        }
    }

    /// The hashed path finds what the pairwise one finds, at the same indices.
    #[test]
    fn duplicates_are_found_alike_by_both_paths() {
        let mut long: Vec<J> = (0..30).map(|i| J::Str(format!("x{i}"))).collect();
        assert_eq!(first_duplicate(&long), None);
        long.push(J::Str("x7".into()));
        assert_eq!(first_duplicate(&long), Some((7, 30)));
        let objs = vec![
            J::Obj(vec![("a".into(), J::Num(1.0)), ("b".into(), J::Null)]),
            J::Obj(vec![("b".into(), J::Null), ("a".into(), J::Num(1.0))]),
        ];
        assert_eq!(first_duplicate(&objs), Some((0, 1)));
        let mut many: Vec<J> = (0..25).map(|i| J::Num(f64::from(i))).collect();
        many.push(J::Num(3.0));
        assert_eq!(first_duplicate(&many), Some((3, 25)));
    }

    /// The project's `name:` read by a line scan: top level only, quotes and a comment removed,
    /// interpolated, and a service's own `name:`-like keys ignored.
    #[test]
    fn the_top_level_name_is_read_without_a_parse() {
        let env = crate::DotEnv(vec![("PN".into(), "fromenv".into())]);
        let n = |t: &str| crate::yaml::top_level_name(t, &env);
        assert_eq!(n("name: myapp\nservices: {}\n"), Some("myapp".to_string()));
        assert_eq!(
            n("services: {}\nname: \"quoted\"  # c\n"),
            Some("quoted".to_string())
        );
        assert_eq!(
            n("name: ${PN}\nservices: {}\n"),
            Some("fromenv".to_string())
        );
        assert_eq!(n("services:\n  a:\n    name: inner\n"), None);
        assert_eq!(n("name:\nservices: {}\n"), None);
        assert_eq!(n("\u{feff}name: bom\n"), Some("bom".to_string()));
    }

    #[test]
    fn the_vendored_schema_loads_with_every_keyword_and_pattern_understood() {
        let s = spec().expect("schema loads");
        assert_eq!(
            s.regexes.len(),
            7,
            "{:?}",
            s.regexes.keys().collect::<Vec<_>>()
        );
    }

    /// Each pinned answer is Docker Compose 5.3.1's, measured on the Jetson (`~/kern-msgs/sprobe`).
    #[test]
    fn docker_s_measured_refusals_are_reproduced_word_for_word() {
        let a = "services:\n  a:\n    image: alpine\n";
        let cases: &[(&str, &str)] = &[
            ("    command: [echo, 1, true]\n", "validating /p/compose.yaml: services.a.command.1 must be a string"),
            ("    cap_add: SYS_ADMIN\n", "validating /p/compose.yaml: services.a.cap_add must be a array"),
            ("    environment:\n", "validating /p/compose.yaml: services.a.environment must be a mapping"),
            ("    foo: 1\n    bar: 2\n", "validating /p/compose.yaml: services.a additional properties 'bar', 'foo' not allowed"),
            ("    pull_policy: sometimes\n", "validating /p/compose.yaml: services.a.pull_policy 'sometimes' does not match pattern 'always|never|build|if_not_present|missing|refresh|daily|weekly|every_([0-9]+[wdhms])+'"),
            ("    cap_add: [A, B, A]\n", "<accepted>"),
            ("    oom_score_adj: -2000\n", "validating /p/compose.yaml: services.a.oom_score_adj must be a string"),
            ("    ulimits:\n      nofile:\n        soft: 1\n", "validating /p/compose.yaml: services.a.ulimits.nofile must be a integer or string"),
            ("    healthcheck:\n      test: 5\n", "validating /p/compose.yaml: services.a.healthcheck.test must be a string"),
            ("    ports:\n      - 80\n      - true\n", "validating /p/compose.yaml: services.a.ports.1 must be a number"),
            ("    restart: 5\n", "validating /p/compose.yaml: services.a.restart must be a string"),
            ("    deploy:\n      replicas: x\n", "error while interpolating services.a.deploy.replicas: failed to cast to expected type: strconv.Atoi: parsing \"x\": invalid syntax"),
            ("    cpu_shares: abc\n", "error while interpolating services.a.cpu_shares: failed to cast to expected type: strconv.ParseInt: parsing \"abc\": invalid syntax"),
            ("    blkio_config:\n      weight: 5\n", "<accepted>"),
            ("    cpus: .inf\n", "validating /p/compose.yaml: json: unsupported value: +Inf"),
            ("    cpus: \"inf\"\n", "validating /p/compose.yaml: json: unsupported value: +Inf"),
            ("    labels: [a=1, a=1]\n    x-foo: [1]\n", "<accepted>"),
            ("    environment:\n      A: [1]\n", "validating /p/compose.yaml: services.a.environment.A must be a boolean, null, number or string"),
            ("    volumes:\n      - type: bind\n        target: /x\n        foo: 1\n", "validating /p/compose.yaml: services.a.volumes.0 additional properties 'foo' not allowed"),
            ("    cap_add: [A, 5]\n", "services.a.cap_add.[1]: unexpected type int"),
            ("    volumes: [\"a:b:c:d\"]\n", "<accepted>"),
            ("    expose: [1.5]\n", "services.a.expose.[0]: unsupported expose value %!s(float64=1.5)"),
            ("    ports:\n      - published: 80\n", "service ports services.a.ports.[0] is missing a target port"),
            ("    ulimits:\n      nofile: \"x\"\n", "error while interpolating services.a.ulimits.nofile: failed to cast to expected type: strconv.Atoi: parsing \"x\": invalid syntax"),
            ("    volumes: [\"\", \"/x\"]\n", "invalid empty volume spec"),
            ("    environment:\n      - A=1\n      - 5\n", "services.a.environment.[1]: unexpected type int"),
            ("    labels:\n      when: 2001-12-14\n    container_name: 2001-12-14\n    hostname: 2001-12-14t21:59:43.10-05:00\n    domainname: 1e3\n", "validating /p/compose.yaml: services.a.domainname must be a string"),
            ("    ports: [80, 80]\n    dns: [1.1.1.1, 1.1.1.1]\n    command: [a, a]\n", "<accepted>"),
            ("    healthcheck:\n      retries: 1.5\n    oom_score_adj: 2000\n", "validating /p/compose.yaml: services.a.oom_score_adj must be a string"),
            ("    depends_on:\n      b:\n        condition: sometimes\n  b:\n    image: alpine\n", "validating /p/compose.yaml: services.a.depends_on.b.condition value must be one of 'service_started', 'service_healthy', 'service_completed_successfully'"),
            ("    networks:\n      n:\n        priority: x\nnetworks:\n  n: {}\n", "validating /p/compose.yaml: services.a.networks.n.priority must be a number"),
        ];
        for (tail, want) in cases {
            assert_eq!(message(&format!("{a}{tail}")), *want, "{tail}");
        }
        assert_eq!(
            message("version: 3\nservices:\n  a:\n    image: alpine\n"),
            "validating /p/compose.yaml: version must be a string"
        );
        assert_eq!(
            message("foo: 1\nservices:\n  a:\n    image: alpine\n"),
            "validating /p/compose.yaml:  additional properties 'foo' not allowed"
        );
        assert_eq!(
            message("services:\n  a:\n"),
            "validating /p/compose.yaml: services.a must be a mapping"
        );
        assert_eq!(
            message("x-foo: .nan\nservices:\n  a:\n    image: alpine\n"),
            "validating /p/compose.yaml: json: unsupported value: NaN"
        );
        assert_eq!(
            message("services:\n  \"a b\":\n    image: alpine\n"),
            "validating /p/compose.yaml: services additional properties 'a b' not allowed"
        );
        assert_eq!(
            message("services:\n  a:\n    image: alpine\n    container_name: \"\"\n"),
            "validating /p/compose.yaml: services.a.container_name '' does not match pattern '[a-zA-Z0-9][a-zA-Z0-9_.-]+'"
        );
    }

    #[test]
    fn an_unknown_key_gives_way_to_kern_s_message_and_stands_when_kern_accepts() {
        let r = refusal("services:\n  a:\n    image: alpine\n    foo: 1\n");
        assert!(matches!(r, Some(Refusal::UnknownKey(_))), "{r:?}");
        let kern: Result<(), String> = Err("kern's".into());
        assert_eq!(refused_or(r.clone(), || kern), Err("kern's".to_string()));
        assert_eq!(
            refused_or(r, || Ok(())),
            Err(
                "validating /p/compose.yaml: services.a additional properties 'foo' not allowed"
                    .to_string()
            )
        );
        let typed = refusal("services:\n  a:\n    image: alpine\n    restart: 5\n");
        assert!(matches!(typed, Some(Refusal::Final(_))), "{typed:?}");
        assert_eq!(refused_or(None, || Ok(7)), Ok(7));
        // Every refusal this module writes is recognised as Docker's, and kern's own are not.
        for yaml in [
            "services:\n  a:\n    image: alpine\n    restart: 5\n",
            "services:\n  a:\n    image: alpine\n    cap_add: [A, 5]\n",
            "services:\n  a:\n    image: alpine\n    deploy:\n      replicas: x\n",
            "services:\n  a:\n    image: alpine\n    volumes: [\"\"]\n",
            "services:\n  a:\n    image: alpine\n    expose: [1.5]\n",
            "services:\n  a:\n    image: alpine\n    ports:\n      - published: 80\n",
        ] {
            let m = message(yaml);
            assert!(is_docker_refusal(&m), "{m}");
        }
        assert!(!is_docker_refusal("duplicate service 'a'"));
    }

    #[test]
    fn an_interpolated_value_is_a_string_and_a_cast_one_is_converted() {
        let env = crate::DotEnv(vec![("R".into(), "3".into()), ("B".into(), "true".into())]);
        let text = "services:\n  a:\n    image: alpine\n    command: [\"echo\", \"${B}\"]\n    deploy:\n      replicas: ${R}\n";
        let val = crate::yaml::document_val(text, &env, None, true).expect("reads");
        assert_eq!(check_val(&val, "/f", true), None);
        // Without interpolation compose-go casts nothing, and the schema takes `${R}` as a string.
        let raw = crate::yaml::document_val(text, &env, None, false).expect("reads");
        assert_eq!(check_val(&raw, "/f", false), None);
    }

    #[test]
    fn go_s_number_parsers_answer_as_strconv() {
        assert_eq!(go_parse_int10("12", "Atoi"), Ok(12));
        assert_eq!(go_parse_int10("+12", "Atoi"), Ok(12));
        assert!(go_parse_int10("1_000", "Atoi").is_err());
        assert_eq!(
            go_parse_int10("99999999999999999999", "ParseInt"),
            Err(
                "strconv.ParseInt: parsing \"99999999999999999999\": value out of range"
                    .to_string()
            )
        );
        assert_eq!(
            go_parse_int10("", "Atoi"),
            Err("strconv.Atoi: parsing \"\": invalid syntax".to_string())
        );
        assert_eq!(go_parse_float("1_000", 64), Ok(1000.0));
        assert_eq!(go_parse_float("0x1.8p1", 64), Ok(3.0));
        assert_eq!(go_parse_float(".5", 64), Ok(0.5));
        assert_eq!(go_parse_float("1.", 64), Ok(1.0));
        assert!(go_parse_float("+nan", 64).is_err());
        assert!(go_parse_float("NaN", 64).is_ok_and(f64::is_nan));
        assert_eq!(go_parse_float("-Infinity", 64), Ok(f64::NEG_INFINITY));
        assert_eq!(
            go_parse_float("1e39", 32),
            Err("strconv.ParseFloat: parsing \"1e39\": value out of range".to_string())
        );
        assert!(go_parse_float("1e", 64).is_err());
        assert!(go_parse_float("_1", 64).is_err());
        assert_eq!(go_quote("a\"b\tc\u{1}"), "\"a\\\"b\\tc\\x01\"");
        assert_eq!(kind_quote("it's \"x\""), "'it\\'s \"x\"'");
        assert_eq!(grouped(1234567), "1,234,567");
        assert_eq!(grouped(999), "999");
    }

    #[test]
    fn the_matcher_answers_as_go_regexp_on_the_schema_s_patterns() {
        let re = |p: &str| Regex::new(p).expect("compiles");
        let pull = re(
            "always|never|build|if_not_present|missing|refresh|daily|weekly|every_([0-9]+[wdhms])+",
        );
        assert!(pull.is_match("every_12h30m"));
        assert!(pull.is_match("xalwaysx"), "unanchored, as MatchString");
        assert!(!pull.is_match("every_"));
        assert!(!pull.is_match("sometimes"));
        // Linear: a long run of digits with no unit does not spin.
        assert!(!pull.is_match(&format!("every_{}", "1".repeat(20000))));
        let name = re("[a-zA-Z0-9][a-zA-Z0-9_.-]+");
        assert!(name.is_match("a1"));
        assert!(!name.is_match("a"));
        assert!(!name.is_match(""));
        let line = re("^.+$");
        assert!(line.is_match("x"));
        assert!(!line.is_match("a\nb"));
        assert!(!line.is_match(""));
        assert!(re("^x-").is_match("x-y"));
        assert!(!re("^x-").is_match("ax-y"));
        assert!(re("^[a-z]+$").is_match("abc"));
        assert!(!re("^[a-z]+$").is_match("abC"));
        assert!(re(".+").is_match("\nx"));
        assert!(!re(".+").is_match("\n"));
        assert!(Regex::new("a{2}").is_err());
        assert!(Regex::new("\\d").is_err());
    }

    #[test]
    fn parse_volume_reads_the_target_and_its_three_errors() {
        assert_eq!(parse_volume_target("./a:/b:ro"), Ok("/b".to_string()));
        assert_eq!(parse_volume_target("/x"), Ok("/x".to_string()));
        assert_eq!(parse_volume_target("ab"), Ok("ab".to_string()));
        assert_eq!(parse_volume_target("a:b:c:d"), Ok("c:d".to_string()));
        assert_eq!(
            parse_volume_target("/a:/b:ro:x"),
            Err("invalid spec: /a:/b:ro:x: too many colons".to_string())
        );
        assert_eq!(
            parse_volume_target("/a::/b"),
            Err("invalid spec: /a::/b: empty section between colons".to_string())
        );
        assert_eq!(parse_volume_target("${A:-x}:/b"), Ok("/b".to_string()));
    }
}
