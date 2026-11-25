//! The Docker Engine API endpoints kern-serve translates, each into `kern` commands.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{ChildStderr, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::Duration;

use kern_common::json::{self, Value};
use kern_common::json_str;

use crate::{percent_decode, Request, Response};

/// The API version kern-serve speaks, and the oldest a client may ask for.
pub(crate) const API_VERSION: &str = "1.43";
const MIN_API_VERSION: &str = "1.24";

// ---------------------------------------------------------------------------------------------
// Responses.

fn json_response(status: u16, body: String) -> Response {
    Response::Full {
        status,
        content_type: "application/json",
        body: body.into_bytes(),
        extra: Vec::new(),
    }
}

/// Docker's error shape: `{"message": "..."}`.
pub(crate) fn error(status: u16, message: &str) -> Response {
    json_response(status, format!("{{\"message\":{}}}", json_str(message)))
}

fn no_content() -> Response {
    Response::Full {
        status: 204,
        content_type: "text/plain",
        body: Vec::new(),
        extra: Vec::new(),
    }
}

// ---------------------------------------------------------------------------------------------
// Running kern.

/// `kern args...` to its end: (exit code, stdout, stderr).
fn kern(bin: &Path, args: &[&str]) -> (i32, String, String) {
    match Command::new(bin).args(args).stdin(Stdio::null()).output() {
        Ok(o) => (
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        ),
        Err(e) => (
            -1,
            String::new(),
            format!("cannot run {}: {e}", bin.display()),
        ),
    }
}

/// The first `error:` line kern printed, without the prefix, or the whole stderr.
fn kern_error(stderr: &str) -> String {
    stderr
        .lines()
        .find_map(|l| l.strip_prefix("error: "))
        .map(str::to_string)
        .unwrap_or_else(|| stderr.trim().to_string())
}

// ---------------------------------------------------------------------------------------------
// Names and ids.

/// A container's 64-hex id, derived from its box name, so the mapping needs no state: the same
/// name always has the same id, and any client's short prefix of it finds it.
pub(crate) fn id_of(name: &str) -> String {
    let mut out = String::with_capacity(64);
    for round in 0u8..4 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ u64::from(round);
        for b in name.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        out.push_str(&format!("{h:016x}"));
    }
    out
}

/// `n` random bytes from the kernel, as hex.
fn random_hex(n: usize) -> Option<String> {
    let mut b = vec![0u8; n];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .ok()?;
    Some(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// A random box name for a container created without one: `kd-` and 8 hex digits.
fn fresh_name() -> Option<String> {
    Some(format!("kd-{}", random_hex(4)?))
}

/// A name a box may have (kern's own check refuses anything else; this keeps a client's name from
/// reaching kern's argv as something else).
fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 63
        && n.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.')
        && !n.starts_with(['-', '.'])
}

/// A container created and not yet started: what `start` needs to run it.
#[derive(Clone)]
struct Created {
    argv: Vec<String>,
    image: String,
    created: u64,
    labels: Vec<(String, String)>,
    env: Vec<String>,
    cmd: Vec<String>,
    exposed: Vec<String>,
    auto_remove: bool,
}

static CREATED: Mutex<Option<HashMap<String, Created>>> = Mutex::new(None);

fn created_get(name: &str) -> Option<Created> {
    CREATED
        .lock()
        .ok()
        .and_then(|g| g.as_ref().and_then(|m| m.get(name).cloned()))
}

fn created_put(name: &str, c: Created) {
    if let Ok(mut g) = CREATED.lock() {
        g.get_or_insert_with(HashMap::new)
            .insert(name.to_string(), c);
    }
}

/// Take a created container out (it starts, or is removed), waking whoever waits for that.
fn created_take(name: &str) -> Option<Created> {
    let taken = CREATED
        .lock()
        .ok()
        .and_then(|mut g| g.as_mut().and_then(|m| m.remove(name)));
    LEFT_CREATED.notify_all();
    taken
}

/// The containers whose start is under way: a second start meanwhile answers 304.
static STARTING: Mutex<Option<std::collections::HashSet<String>>> = Mutex::new(None);

fn start_claim(name: &str) -> bool {
    STARTING
        .lock()
        .map(|mut g| {
            g.get_or_insert_with(Default::default)
                .insert(name.to_string())
        })
        .unwrap_or(false)
}

fn start_release(name: &str) {
    if let Ok(mut g) = STARTING.lock() {
        if let Some(s) = g.as_mut() {
            s.remove(name);
        }
    }
}

/// Woken each time a container leaves `CREATED`.
static LEFT_CREATED: Condvar = Condvar::new();

/// Block until `name` is no longer a created-and-not-started container.
fn wait_until_started(name: &str) {
    let Ok(mut g) = CREATED.lock() else { return };
    while g.as_ref().is_some_and(|m| m.contains_key(name)) {
        g = match LEFT_CREATED.wait(g) {
            Ok(g) => g,
            Err(_) => return,
        };
    }
}

/// Every box kern lists (running and exited) as `(name, json)`.
fn kern_boxes(bin: &Path) -> Vec<(String, Value)> {
    let (_, out, _) = kern(bin, &["ps", "-a", "--json"]);
    json::parse(out.trim())
        .ok()
        .and_then(|v| v.as_array().map(<[Value]>::to_vec))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|b| {
            b.get("name")
                .and_then(Value::as_str)
                .map(|n| (n.to_string(), b.clone()))
        })
        .collect()
}

/// The box a client means by `id`: a name, a full id, or a prefix of one.
fn resolve(bin: &Path, id: &str) -> Option<String> {
    let id = id.trim_start_matches('/');
    if created_get(id).is_some() {
        return Some(id.to_string());
    }
    let pending: Vec<String> = CREATED
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|m| m.keys().cloned().collect()))
        .unwrap_or_default();
    let ended = runs_ended().into_iter().map(|(n, _)| n);
    let names = kern_boxes(bin)
        .into_iter()
        .map(|(n, _)| n)
        .chain(pending)
        .chain(ended);
    let mut by_id = None;
    for n in names {
        if n == id {
            return Some(n);
        }
        if id.len() >= 6 && id.bytes().all(|c| c.is_ascii_hexdigit()) && id_of(&n).starts_with(id) {
            by_id = Some(n);
        }
    }
    by_id
}

// ---------------------------------------------------------------------------------------------
// containers/create: the body, translated into a `kern box` argv.

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|x| x.as_str().map(str::to_string))
        .collect()
}

/// A field kern does not open over the socket: set to anything but its empty value, the create is
/// refused, naming it.
/// A bind whose source is a socket, as Testcontainers' reaper (Ryuk) asks for the Docker socket. kern
/// never mounts a socket into a box, and this API's socket least of all: whatever runs in the box
/// is this user, and could ask for any box. Refused at the create, naming the way round, rather
/// than at the start with kern's general refusal.
fn refuse_socket_bind(bind: &str) -> Result<(), String> {
    use std::os::unix::fs::FileTypeExt;
    let source = bind.split(':').next().unwrap_or_default();
    if !source.starts_with('/') {
        return Ok(());
    }
    let is_socket = std::fs::metadata(source).is_ok_and(|m| m.file_type().is_socket());
    let docker_socket = Path::new(source)
        .file_name()
        .is_some_and(|n| n == "docker.sock");
    if is_socket || docker_socket {
        return Err(format!(
            "Binds {bind:?}: the source is a socket, and kern mounts no socket into a box (a box \
             holding this API's socket could ask it for any box). For Testcontainers, whose reaper \
             Ryuk asks for it: set TESTCONTAINERS_RYUK_DISABLED=true; kern removes a test session's \
             containers itself when the process that made them ends"
        ));
    }
    Ok(())
}

fn refuse_if_set(host: Option<&Value>, field: &str) -> Result<(), String> {
    let set = match host.and_then(|h| h.get(field)) {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Arr(a)) => !a.is_empty(),
        Some(Value::Obj(o)) => !o.is_empty(),
        Some(Value::Str(s)) => !s.is_empty(),
        Some(Value::Num(n)) => n != "0",
    };
    if set {
        Err(format!(
            "HostConfig.{field}: kern does not grant it over the socket; run that container with \
             kern directly, where the flag is explicit"
        ))
    } else {
        Ok(())
    }
}

/// The `kern box` argv for a create body (without the leading `kern`), and what `inspect` reports.
fn create_argv(name: &str, body: &Value) -> Result<Created, String> {
    let image = body
        .get("Image")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("Image is required")?
        .to_string();
    let host = body.get("HostConfig");
    for f in [
        "Privileged",
        "Devices",
        "DeviceRequests",
        "CapAdd",
        "SecurityOpt",
        "VolumesFrom",
        "Links",
    ] {
        refuse_if_set(host, f)?;
    }
    // `--mount` is not translated, and a mount dropped in silence is a test reading other data.
    if host
        .and_then(|h| h.get("Mounts"))
        .and_then(Value::as_array)
        .is_some_and(|m| !m.is_empty())
    {
        return Err(
            "HostConfig.Mounts (`--mount`): not translated by kern; use a bind (`-v src:dst`, Binds)"
                .into(),
        );
    }
    for (f, refused) in [
        ("PidMode", "host"),
        ("IpcMode", "host"),
        ("UTSMode", "host"),
    ] {
        if host.and_then(|h| h.get(f)).and_then(Value::as_str) == Some(refused) {
            return Err(format!(
                "HostConfig.{f}: \"host\" is not granted over the socket"
            ));
        }
    }
    // `--log-streams`: the box's log keeps stdout and stderr apart, so `logs` and an `attach` after
    // the start answer them as Docker does. Right after `-d`, which an attached start removes.
    let mut argv: Vec<String> = vec![
        "box".into(),
        name.into(),
        "-d".into(),
        "--log-streams".into(),
    ];
    let env = strings(body.get("Env"));
    for e in &env {
        argv.push("-e".into());
        argv.push(e.clone());
    }
    let mut labels: Vec<(String, String)> = Vec::new();
    if let Some(m) = body.get("Labels").and_then(Value::as_object) {
        for (k, v) in m {
            let v = v.as_str().unwrap_or_default();
            labels.push((k.clone(), v.to_string()));
            argv.push("-l".into());
            argv.push(format!("{k}={v}"));
        }
    }
    if let Some(w) = body
        .get("WorkingDir")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        argv.push("-w".into());
        argv.push(w.to_string());
    }
    if let Some(u) = body
        .get("User")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        argv.push("-u".into());
        argv.push(u.to_string());
    }
    if let Some(h) = body
        .get("Hostname")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        argv.push("--hostname".into());
        argv.push(h.to_string());
    }
    // Published ports: `PortBindings` names them; `PublishAllPorts` publishes every exposed one on a
    // free host port. An empty HostIp is every address, as under Docker.
    let mut exposed: Vec<String> = body
        .get("ExposedPorts")
        .and_then(Value::as_object)
        .unwrap_or_default()
        .iter()
        .map(|(k, _)| k.clone())
        .collect();
    let mut published: Vec<String> = Vec::new();
    if let Some(pb) = host
        .and_then(|h| h.get("PortBindings"))
        .and_then(Value::as_object)
    {
        for (cport, binds) in pb {
            if !exposed.contains(cport) {
                exposed.push(cport.clone());
            }
            let (num, proto) = cport.split_once('/').unwrap_or((cport.as_str(), "tcp"));
            let binds = binds.as_array().unwrap_or_default();
            let binds: Vec<&Value> = if binds.is_empty() {
                vec![&Value::Null]
            } else {
                binds.iter().collect()
            };
            for b in binds {
                let ip = b
                    .get("HostIp")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("0.0.0.0");
                let hp = b
                    .get("HostPort")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                published.push(format!("{ip}:{hp}:{num}/{proto}"));
            }
        }
    }
    if host
        .and_then(|h| h.get("PublishAllPorts"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        for cport in &exposed {
            let (num, proto) = cport.split_once('/').unwrap_or((cport.as_str(), "tcp"));
            let spec = format!("0.0.0.0::{num}/{proto}");
            if !published
                .iter()
                .any(|p| p.ends_with(&format!(":{num}/{proto}")))
            {
                published.push(spec);
            }
        }
    }
    for p in &published {
        argv.push("-p".into());
        argv.push(p.clone());
    }
    for b in strings(host.and_then(|h| h.get("Binds"))) {
        refuse_socket_bind(&b)?;
        argv.push("-v".into());
        argv.push(b);
    }
    if let Some(m) = host
        .and_then(|h| h.get("Memory"))
        .and_then(Value::as_i64)
        .filter(|m| *m > 0)
    {
        argv.push("--memory".into());
        argv.push(m.to_string());
    }
    if let Some(n) = host
        .and_then(|h| h.get("NanoCpus"))
        .and_then(Value::as_i64)
        .filter(|n| *n > 0)
    {
        argv.push("--cpus".into());
        argv.push(format!("{:.3}", n as f64 / 1e9));
    }
    let auto_remove = host
        .and_then(|h| h.get("AutoRemove"))
        .and_then(Value::as_bool)
        == Some(true);
    if auto_remove {
        argv.push("--rm".into());
    }
    match host
        .and_then(|h| h.get("NetworkMode"))
        .and_then(Value::as_str)
    {
        None | Some("" | "default" | "bridge") => {}
        Some("host") => {
            argv.push("--network".into());
            argv.push("host".into());
        }
        Some("none") => {
            argv.push("--network".into());
            argv.push("none".into());
        }
        Some(other) => {
            return Err(format!(
                "HostConfig.NetworkMode {other:?}: networks are not translated in this phase \
                 (default, host and none are)"
            ))
        }
    }
    let entry = strings(body.get("Entrypoint"));
    let mut cmd = strings(body.get("Cmd"));
    if let Some((first, rest)) = entry.split_first() {
        argv.push("--entrypoint".into());
        argv.push(first.clone());
        let mut c = rest.to_vec();
        c.extend(cmd);
        cmd = c;
    }
    argv.push("--image".into());
    argv.push(image.clone());
    if !cmd.is_empty() {
        argv.push("--".into());
        argv.extend(cmd.iter().cloned());
    }
    Ok(Created {
        argv,
        image,
        created: now(),
        labels,
        env,
        cmd,
        exposed,
        auto_remove,
    })
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Unix seconds as RFC 3339 UTC, which Docker clients parse.
fn rfc3339(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mo <= 2);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

// ---------------------------------------------------------------------------------------------
// The Docker shapes of what kern reports.

/// kern's `ports` field (`127.0.0.1:56679->80, 0.0.0.0:8080->443/tcp`) as Docker's
/// `NetworkSettings.Ports`: `{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"56679"}]}`.
fn ports_json(ports: &str, exposed: &[String]) -> String {
    let mut map: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for p in ports.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let Some((host, cport)) = p.split_once("->") else {
            continue;
        };
        let cport = if cport.contains('/') {
            cport.to_string()
        } else {
            format!("{cport}/tcp")
        };
        let (ip, hp) = host.rsplit_once(':').unwrap_or(("0.0.0.0", host));
        let ip = ip.trim_start_matches('[').trim_end_matches(']');
        match map.iter_mut().find(|(k, _)| *k == cport) {
            Some((_, v)) => v.push((ip.to_string(), hp.to_string())),
            None => map.push((cport, vec![(ip.to_string(), hp.to_string())])),
        }
    }
    for e in exposed {
        if !map.iter().any(|(k, _)| k == e) {
            map.push((e.clone(), Vec::new()));
        }
    }
    let items: Vec<String> = map
        .iter()
        .map(|(k, binds)| {
            if binds.is_empty() {
                format!("{}:null", json_str(k))
            } else {
                let b: Vec<String> = binds
                    .iter()
                    .map(|(ip, hp)| {
                        format!(
                            "{{\"HostIp\":{},\"HostPort\":{}}}",
                            json_str(ip),
                            json_str(hp)
                        )
                    })
                    .collect();
                format!("{}:[{}]", json_str(k), b.join(","))
            }
        })
        .collect();
    format!("{{{}}}", items.join(","))
}

fn labels_json(labels: &[(String, String)]) -> String {
    let items: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{}:{}", json_str(k), json_str(v)))
        .collect();
    format!("{{{}}}", items.join(","))
}

fn str_array(v: &[String]) -> String {
    let items: Vec<String> = v.iter().map(|s| json_str(s)).collect();
    format!("[{}]", items.join(","))
}

fn labels_of(v: &Value) -> Vec<(String, String)> {
    v.get("labels")
        .and_then(Value::as_object)
        .unwrap_or_default()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
        .collect()
}

/// `GET /containers/{id}/json`.
fn inspect(bin: &Path, name: &str) -> Response {
    let id = id_of(name);
    if let Some(c) = created_get(name) {
        return json_response(
            200,
            format!(
                "{{\"Id\":{},\"Created\":{},\"Name\":{},\"Image\":{},\"State\":{{\"Status\":\"created\",\"Running\":false,\"Paused\":false,\"Restarting\":false,\"OOMKilled\":false,\"Dead\":false,\"Pid\":0,\"ExitCode\":0,\"Error\":\"\",\"StartedAt\":\"0001-01-01T00:00:00Z\",\"FinishedAt\":\"0001-01-01T00:00:00Z\"}},\"Config\":{{\"Image\":{},\"Env\":{},\"Cmd\":{},\"Labels\":{},\"Tty\":false}},\"HostConfig\":{{\"NetworkMode\":\"default\"}},\"NetworkSettings\":{{\"Ports\":{},\"IPAddress\":\"\",\"Networks\":{{}}}},\"Mounts\":[]}}",
                json_str(&id),
                json_str(&rfc3339(c.created)),
                json_str(&format!("/{name}")),
                json_str(&c.image),
                json_str(&c.image),
                str_array(&c.env),
                str_array(&c.cmd),
                labels_json(&c.labels),
                ports_json("", &c.exposed)
            ),
        );
    }
    let (code, out, _) = kern(bin, &["inspect", "--json", name]);
    let live = if code == 0 {
        json::parse(out.trim()).ok()
    } else {
        None
    };
    let exited = || {
        kern_boxes(bin)
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v)
    };
    let (v, running) = match live {
        Some(v) if v.get("status").and_then(Value::as_str) != Some("exited") => (v, true),
        _ => match exited() {
            Some(v) => (v, false),
            None => match run_ended(name) {
                Some(r) => return inspect_ended(name, &r),
                None => return error(404, &format!("No such container: {name}")),
            },
        },
    };
    let started = v.get("started").and_then(Value::as_i64).unwrap_or(0).max(0) as u64;
    let exit_code = v.get("exit_code").and_then(Value::as_i64).unwrap_or(0);
    let pid = if running {
        v.get("pid1").and_then(Value::as_i64).unwrap_or(0)
    } else {
        0
    };
    let ports = v.get("ports").and_then(Value::as_str).unwrap_or_default();
    let command = v.get("command").and_then(Value::as_str).unwrap_or_default();
    let health = v.get("health").and_then(Value::as_str).unwrap_or_default();
    let health_json = match health {
        "healthy" | "unhealthy" | "starting" => {
            format!(",\"Health\":{{\"Status\":{}}}", json_str(health))
        }
        _ => String::new(),
    };
    let labels = labels_of(&v);
    json_response(
        200,
        format!(
            "{{\"Id\":{},\"Created\":{},\"Name\":{},\"Path\":{},\"Args\":[],\"Image\":\"\",\"State\":{{\"Status\":{},\"Running\":{running},\"Paused\":false,\"Restarting\":false,\"OOMKilled\":false,\"Dead\":false,\"Pid\":{pid},\"ExitCode\":{exit_code},\"Error\":\"\",\"StartedAt\":{},\"FinishedAt\":\"0001-01-01T00:00:00Z\"{health_json}}},\"Config\":{{\"Labels\":{},\"Tty\":false,\"Env\":[]}},\"HostConfig\":{{\"NetworkMode\":\"default\"}},\"NetworkSettings\":{{\"Ports\":{},\"IPAddress\":\"\",\"Networks\":{{}}}},\"Mounts\":[]}}",
            json_str(&id),
            json_str(&rfc3339(started)),
            json_str(&format!("/{name}")),
            json_str(command),
            json_str(if running { "running" } else { "exited" }),
            json_str(&rfc3339(started)),
            labels_json(&labels),
            ports_json(ports, &[])
        ),
    )
}

/// `GET /containers/json`: running boxes, `all=1` the exited ones too, `filters={"label":[...]}`.
/// `inspect` of a foreground box that ended, from this server's record of it.
fn inspect_ended(name: &str, r: &Run) -> Response {
    let c = &r.created;
    json_response(
        200,
        format!(
            "{{\"Id\":{},\"Created\":{},\"Name\":{},\"Image\":{},\"State\":{{\"Status\":\"exited\",\"Running\":false,\"Paused\":false,\"Restarting\":false,\"OOMKilled\":false,\"Dead\":false,\"Pid\":0,\"ExitCode\":{},\"Error\":\"\",\"StartedAt\":{},\"FinishedAt\":{}}},\"Config\":{{\"Image\":{},\"Env\":{},\"Cmd\":{},\"Labels\":{},\"Tty\":false}},\"HostConfig\":{{\"NetworkMode\":\"default\"}},\"NetworkSettings\":{{\"Ports\":{{}},\"IPAddress\":\"\",\"Networks\":{{}}}},\"Mounts\":[]}}",
            json_str(&id_of(name)),
            json_str(&rfc3339(c.created)),
            json_str(&format!("/{name}")),
            json_str(&c.image),
            r.exit.unwrap_or(-1),
            json_str(&rfc3339(c.created)),
            json_str(&rfc3339(r.finished)),
            json_str(&c.image),
            str_array(&c.env),
            str_array(&c.cmd),
            labels_json(&c.labels)
        ),
    )
}

fn list(bin: &Path, req: &Request) -> Response {
    let all = req.flag("all");
    let wanted: Vec<String> = req
        .param("filters")
        .and_then(|f| json::parse(f).ok())
        .map(|f| strings(f.get("label")))
        .unwrap_or_default();
    let mut items = Vec::new();
    for (name, v) in kern_boxes(bin) {
        let running = v.get("status").and_then(Value::as_str) != Some("exited");
        if !running && !all {
            continue;
        }
        let labels = labels_of(&v);
        let keep = wanted.iter().all(|w| match w.split_once('=') {
            Some((k, val)) => labels.iter().any(|(lk, lv)| lk == k && lv == val),
            None => labels.iter().any(|(lk, _)| lk == w),
        });
        if !keep {
            continue;
        }
        let ports: Vec<String> = v
            .get("ports")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter_map(|p| {
                let (host, cport) = p.split_once("->")?;
                let (num, proto) = cport.split_once('/').unwrap_or((cport, "tcp"));
                let (ip, hp) = host.rsplit_once(':').unwrap_or(("0.0.0.0", host));
                Some(format!(
                    "{{\"IP\":{},\"PrivatePort\":{},\"PublicPort\":{},\"Type\":{}}}",
                    json_str(ip),
                    num.parse::<u32>().unwrap_or(0),
                    hp.parse::<u32>().unwrap_or(0),
                    json_str(proto)
                ))
            })
            .collect();
        items.push(format!(
            "{{\"Id\":{},\"Names\":[{}],\"Image\":\"\",\"Command\":{},\"Created\":{},\"State\":{},\"Status\":{},\"Ports\":[{}],\"Labels\":{}}}",
            json_str(&id_of(&name)),
            json_str(&format!("/{name}")),
            json_str(v.get("command").and_then(Value::as_str).unwrap_or_default()),
            v.get("started").and_then(Value::as_i64).unwrap_or(0),
            json_str(if running { "running" } else { "exited" }),
            json_str(if running { "Up" } else { "Exited" }),
            ports.join(","),
            labels_json(&labels)
        ));
    }
    if all {
        let listed: Vec<String> = items.clone();
        for (name, r) in runs_ended() {
            let id = id_of(&name);
            if listed.iter().any(|i| i.contains(&id)) {
                continue;
            }
            let keep = wanted.iter().all(|w| match w.split_once('=') {
                Some((k, val)) => r.created.labels.iter().any(|(lk, lv)| lk == k && lv == val),
                None => r.created.labels.iter().any(|(lk, _)| lk == w),
            });
            if !keep {
                continue;
            }
            items.push(format!(
                "{{\"Id\":{},\"Names\":[{}],\"Image\":{},\"Command\":{},\"Created\":{},\"State\":\"exited\",\"Status\":{},\"Ports\":[],\"Labels\":{}}}",
                json_str(&id),
                json_str(&format!("/{name}")),
                json_str(&r.created.image),
                json_str(&r.created.cmd.join(" ")),
                r.created.created,
                json_str(&format!("Exited ({})", r.exit.unwrap_or(-1))),
                labels_json(&r.created.labels)
            ));
        }
    }
    json_response(200, format!("[{}]", items.join(",")))
}

/// Forward the frames `kern logs --frames` writes, keeping those of the streams asked for
/// (`(stdout, stderr)`), until `from` ends. A frame is passed on as it arrives: its header first,
/// since it carries the full length, then the payload in whatever pieces the pipe gives, so a long
/// line is never held whole. `false` when the client went away.
fn copy_frames(mut from: impl Read, w: &mut impl Write, (out, err): (bool, bool)) -> bool {
    let mut buf = [0u8; 16 * 1024];
    let mut head = [0u8; 8];
    let mut have = 0usize;
    let mut left: u64 = 0;
    let mut keep = false;
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) => return true,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return true,
        };
        let mut i = 0;
        while i < n {
            if left == 0 && have < 8 {
                let take = (8 - have).min(n - i);
                head[have..have + take].copy_from_slice(&buf[i..i + take]);
                have += take;
                i += take;
                if have < 8 {
                    continue;
                }
                have = 0;
                let mut len = [0u8; 4];
                len.copy_from_slice(&head[4..]);
                left = u64::from(u32::from_be_bytes(len));
                keep = match head[0] {
                    1 => out,
                    2 => err,
                    _ => false,
                };
                if keep && w.write_all(&head).is_err() {
                    return false;
                }
                continue;
            }
            let take = usize::try_from(left).unwrap_or(usize::MAX).min(n - i);
            if keep && w.write_all(&buf[i..i + take]).is_err() {
                return false;
            }
            left -= take as u64;
            i += take;
        }
        if w.flush().is_err() {
            return false;
        }
    }
}

/// A frame of stream `kind` (1 stdout, 2 stderr).
fn frame_of(kind: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 8);
    out.extend_from_slice(&[kind, 0, 0, 0]);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// The `tail` of a logs request as a line count, `None` for the whole log. Docker's daemon reads
/// anything that is not a whole number (`all`, empty) and any negative number as the whole log;
/// Testcontainers for Node sends `tail=-1`, which `kern logs --tail` refuses.
fn tail_lines(tail: Option<&str>) -> Option<u64> {
    tail.and_then(|t| t.parse::<u64>().ok())
}

/// `GET /containers/{id}/logs`: kern's log of the box, in Docker's multiplexed frames, which
/// `kern logs --frames` writes itself: stdout and stderr apart for a box this server created (its
/// `--log-streams`), all stdout for one started otherwise. `stdout=0`/`stderr=0` drop a stream;
/// `follow=1` streams until the box ends.
fn logs(bin: &Path, name: &str, req: &Request) -> Response {
    let wanted = (req.flag("stdout"), req.flag("stderr"));
    if wanted == (false, false) {
        // Docker's answer to the same request, word for word.
        return error(400, "Bad parameters: you must choose at least one stream");
    }
    let mut args: Vec<String> = vec!["logs".into(), "--frames".into()];
    if req.flag("follow") {
        args.push("-f".into());
    }
    if let Some(t) = tail_lines(req.param("tail")) {
        args.push("--tail".into());
        args.push(t.to_string());
    }
    if let Some(s) = req.param("since").filter(|s| *s != "0" && !s.is_empty()) {
        args.push("--since".into());
        args.push(s.to_string());
    }
    if req.flag("timestamps") {
        args.push("-t".into());
    }
    args.push(name.to_string());
    let bin = bin.to_path_buf();
    Response::Stream {
        status: 200,
        content_type: "application/vnd.docker.multiplexed-stream",
        upgrade: false,
        writer: Box::new(move |w: &mut crate::Out| {
            let child = Command::new(&bin)
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn();
            let Ok(mut child) = child else { return };
            if let Some(out) = child.stdout.take() {
                if !copy_frames(out, w, wanted) {
                    let _ = child.kill();
                }
            }
            let _ = child.wait();
        }),
    }
}

/// `POST /images/create?fromImage=X&tag=Y`: `kern pull`, answered as Docker's progress stream.
fn pull(bin: &Path, req: &Request) -> Response {
    let Some(from) = req.param("fromImage").filter(|f| !f.is_empty()) else {
        return error(
            400,
            "fromImage is required (building from a source is not translated)",
        );
    };
    let tag = req.param("tag").filter(|t| !t.is_empty());
    let image = match tag {
        Some(t)
            if !from.contains('@') && !from.rsplit('/').next().unwrap_or(from).contains(':') =>
        {
            format!("{from}:{t}")
        }
        _ => from.to_string(),
    };
    let bin = bin.to_path_buf();
    Response::Stream {
        status: 200,
        content_type: "application/json",
        upgrade: false,
        writer: Box::new(move |w: &mut crate::Out| {
            let _ = writeln!(
                w,
                "{{\"status\":{}}}",
                json_str(&format!("Pulling {image} with kern"))
            );
            let (code, _, err) = kern(&bin, &["pull", "-q", &image]);
            let line = if code == 0 {
                format!(
                    "{{\"status\":{}}}",
                    json_str(&format!("Status: Image is up to date for {image}"))
                )
            } else {
                let m = kern_error(&err);
                format!(
                    "{{\"errorDetail\":{{\"message\":{}}},\"error\":{}}}",
                    json_str(&m),
                    json_str(&m)
                )
            };
            let _ = writeln!(w, "{line}");
            let _ = w.flush();
        }),
    }
}

/// `GET /images/{name}/json`.
fn image_inspect(bin: &Path, name: &str) -> Response {
    let (_, out, _) = kern(bin, &["images", "--json"]);
    let want_latest = if name.contains(':') || name.contains('@') {
        name.to_string()
    } else {
        format!("{name}:latest")
    };
    let images = json::parse(out.trim())
        .ok()
        .and_then(|v| v.as_array().map(<[Value]>::to_vec))
        .unwrap_or_default();
    let found = images.into_iter().find(|i| {
        i.get("image")
            .and_then(Value::as_str)
            .is_some_and(|n| n == name || n == want_latest || n.split('@').next() == Some(name))
    });
    match found {
        Some(i) => {
            let n = i.get("image").and_then(Value::as_str).unwrap_or(name);
            json_response(
                200,
                format!(
                    "{{\"Id\":{},\"RepoTags\":[{}],\"RepoDigests\":[],\"Size\":{},\"Created\":{},\"Os\":\"linux\",\"Architecture\":{}}}",
                    json_str(&format!("sha256:{}", id_of(n))),
                    json_str(n),
                    i.get("size_bytes").and_then(Value::as_i64).unwrap_or(0),
                    json_str(&rfc3339(i.get("pulled").and_then(Value::as_i64).unwrap_or(0).max(0) as u64)),
                    json_str(arch())
                ),
            )
        }
        None => error(404, &format!("No such image: {name}")),
    }
}

fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

fn version() -> Response {
    let ver = kern_common::VERSION;
    json_response(
        200,
        format!(
            "{{\"Platform\":{{\"Name\":\"kern\"}},\"Components\":[{{\"Name\":\"kern\",\"Version\":{v}}}],\"Version\":{v},\"ApiVersion\":\"{API_VERSION}\",\"MinAPIVersion\":\"{MIN_API_VERSION}\",\"Os\":\"linux\",\"Arch\":{},\"KernelVersion\":{},\"GitCommit\":\"\",\"GoVersion\":\"\",\"BuildTime\":\"\"}}",
            json_str(arch()),
            json_str(&kernel_release()),
            v = json_str(ver)
        ),
    )
}

fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn info(bin: &Path) -> Response {
    let boxes = kern_boxes(bin);
    let running = boxes
        .iter()
        .filter(|(_, v)| v.get("status").and_then(Value::as_str) != Some("exited"))
        .count();
    let mem_total = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|m| {
            m.lines()
                .find_map(|l| l.strip_prefix("MemTotal:"))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
        })
        .unwrap_or(0)
        * 1024;
    let ncpu = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    json_response(
        200,
        format!(
            "{{\"ID\":\"kern\",\"Containers\":{},\"ContainersRunning\":{running},\"ContainersPaused\":0,\"ContainersStopped\":{},\"Images\":0,\"Driver\":\"overlay\",\"OperatingSystem\":\"kern\",\"OSType\":\"linux\",\"Architecture\":{},\"NCPU\":{ncpu},\"MemTotal\":{mem_total},\"Name\":\"kern\",\"ServerVersion\":{},\"KernelVersion\":{},\"Labels\":[],\"SecurityOptions\":[\"name=seccomp\",\"name=rootless\"]}}",
            boxes.len(),
            boxes.len() - running,
            json_str(std::env::consts::ARCH),
            json_str(kern_common::VERSION),
            json_str(&kernel_release())
        ),
    )
}

// ---------------------------------------------------------------------------------------------
// Sessions: kern's own reaper, in place of Testcontainers' Ryuk.
//
// Ryuk is a container holding the Docker socket, which kern refuses to mount. What it does, removing a
// test run's containers when that run ends, this server does itself: a container labelled with a
// Testcontainers session is filed under the process that created it (from the socket, with its start
// time), and removed once that process is gone, a crash or `kill -9` included. No TCP port, no
// container with the socket.

/// The label Testcontainers puts on every container of one test run.
const SESSION_LABEL: &str = "org.testcontainers.session-id";

/// A process, by pid and start time, so a reused pid is not mistaken for it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Peer {
    pid: i32,
    start: u64,
}

impl Peer {
    /// The live process `pid`, or `None` when it is gone.
    pub(crate) fn of(pid: i32) -> Option<Peer> {
        proc_start(pid).map(|start| Peer { pid, start })
    }

    fn alive(self) -> bool {
        proc_start(self.pid) == Some(self.start)
    }
}

/// Field 22 of `/proc/<pid>/stat`, the start time in clock ticks. Read after the LAST `)`: the
/// command name before it may hold spaces and parentheses.
fn proc_start(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    // After `)` the fields start at field 3 (state); field 22 is the 20th of them.
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Whose test session a container is: a process here, or a Windows process behind `kern.exe`'s pipe,
/// which only `kern.exe` can watch and which it reports ended (`POST /_kern/session-ended`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum Owner {
    Local(Peer),
    Windows(String),
}

static SESSIONS: Mutex<Option<HashMap<String, Owner>>> = Mutex::new(None);
/// How many containers wait for their session's end: the server stays up while any do.
static TRACKED: AtomicUsize = AtomicUsize::new(0);
static REAPER: std::sync::Once = std::sync::Once::new();

/// Containers of a test session are open: the server must not exit, or nothing would remove them.
pub(crate) fn sessions_open() -> bool {
    TRACKED.load(Ordering::Acquire) > 0
}

fn session_track(bin: &Path, name: &str, peer: Owner) {
    if let Ok(mut g) = SESSIONS.lock() {
        let m = g.get_or_insert_with(HashMap::new);
        m.insert(name.to_string(), peer);
        TRACKED.store(m.len(), Ordering::Release);
    }
    let bin = bin.to_path_buf();
    REAPER.call_once(move || {
        let _ = std::thread::Builder::new()
            .name("kern-compat-reaper".into())
            .spawn(move || reaper(&bin));
    });
}

fn session_forget(name: &str) {
    if let Ok(mut g) = SESSIONS.lock() {
        if let Some(m) = g.as_mut() {
            m.remove(name);
            TRACKED.store(m.len(), Ordering::Release);
        }
    }
}

/// Once a second, while sessions are open: remove the containers whose process ended.
fn reaper(bin: &Path) {
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let ended: Vec<String> = SESSIONS
            .lock()
            .ok()
            .and_then(|g| {
                g.as_ref().map(|m| {
                    m.iter()
                        .filter(|(_, o)| matches!(o, Owner::Local(p) if !p.alive()))
                        .map(|(n, _)| n.clone())
                        .collect()
                })
            })
            .unwrap_or_default();
        for name in ended {
            remove_container(bin, &name);
            session_forget(&name);
        }
    }
}

/// `POST /_kern/session-ended?owner=<key>`: the Windows process `key` ended; its containers go.
fn session_ended(bin: &Path, req: &Request) -> Response {
    let Some(key) = req.param("owner").filter(|k| crate::valid_peer_key(k)) else {
        return error(400, "owner=<pid>-<time> is required");
    };
    let gone = Owner::Windows(key.to_string());
    let names: Vec<String> = SESSIONS
        .lock()
        .ok()
        .and_then(|g| {
            g.as_ref().map(|m| {
                m.iter()
                    .filter(|(_, o)| **o == gone)
                    .map(|(n, _)| n.clone())
                    .collect()
            })
        })
        .unwrap_or_default();
    for name in names {
        remove_container(bin, &name);
        session_forget(&name);
    }
    no_content()
}

/// Remove `name` whatever its state: created, running (stopped at once) or ended.
fn remove_container(bin: &Path, name: &str) {
    if created_take(name).is_some() {
        drop(attached_take(name));
        return;
    }
    if run_ended(name).is_some() {
        run_forget(name);
    }
    let _ = kern(bin, &["stop", "-t", "0", name]);
    let _ = kern(bin, &["rm", "-f", name]);
}

// ---------------------------------------------------------------------------------------------
// Streams: a command's stdout and stderr, as Docker's frames, on one connection.

/// Copy `out` and `err` to `w` until both end, as Docker's frames (stream 1 and 2), or as the raw
/// bytes for a tty. ONE LOCK PER WHOLE FRAME: two readers share the connection, and a frame of one
/// stream must never be cut by a frame of the other.
fn pump(w: &crate::Out, out: Option<ChildStdout>, err: Option<ChildStderr>, raw: bool) {
    let Ok(sink) = w.try_clone() else { return };
    let sink = Arc::new(Mutex::new(sink));
    let pipes: [(u8, Option<Box<dyn Read + Send>>); 2] = [
        (1, out.map(|p| Box::new(p) as Box<dyn Read + Send>)),
        (2, err.map(|p| Box::new(p) as Box<dyn Read + Send>)),
    ];
    let mut readers = Vec::new();
    for (kind, pipe) in pipes {
        let Some(mut pipe) = pipe else { continue };
        let sink = Arc::clone(&sink);
        readers.push(std::thread::spawn(move || {
            let mut buf = [0u8; 16 * 1024];
            loop {
                let n = match pipe.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let bytes = if raw {
                    buf[..n].to_vec()
                } else {
                    frame_of(kind, &buf[..n])
                };
                let sent = sink
                    .lock()
                    .map(|mut s| s.write_all(&bytes).and_then(|()| s.flush()).is_ok())
                    .unwrap_or(false);
                if !sent {
                    break;
                }
            }
        }));
    }
    for r in readers {
        let _ = r.join();
    }
}

// ---------------------------------------------------------------------------------------------
// attach: a container's output on the connection (`docker run` without `-d`).

type Pipes = (Option<ChildStdout>, Option<ChildStderr>);

/// The attaches waiting for their container's start, which hands each the box's two pipes.
static ATTACHED: Mutex<Option<HashMap<String, mpsc::Sender<Pipes>>>> = Mutex::new(None);

fn attached_take(name: &str) -> Option<mpsc::Sender<Pipes>> {
    ATTACHED
        .lock()
        .ok()
        .and_then(|mut g| g.as_mut().and_then(|m| m.remove(name)))
}

/// A box this server runs in the foreground for an attach. kern keeps no record of a foreground
/// box once it ends, so this one does: the exit code for `wait` (also for a `--rm` box, which is
/// gone), and for a box without `--rm` what `inspect`, `ps -a` and `rm` need.
#[derive(Clone)]
struct Run {
    created: Created,
    exit: Option<i32>,
    finished: u64,
}

static RUNS: Mutex<Option<HashMap<String, Run>>> = Mutex::new(None);

/// Woken each time a foreground box ends.
static RUN_ENDED: Condvar = Condvar::new();

/// How long the exit code of an ended `--rm` box is kept for a late `wait`.
const GONE_KEPT_SECS: u64 = 60;

fn run_begin(name: &str, created: &Created) {
    if let Ok(mut g) = RUNS.lock() {
        let m = g.get_or_insert_with(HashMap::new);
        let now = now();
        m.retain(|_, r| {
            !(r.created.auto_remove
                && r.exit.is_some()
                && now.saturating_sub(r.finished) > GONE_KEPT_SECS)
        });
        m.insert(
            name.to_string(),
            Run {
                created: created.clone(),
                exit: None,
                finished: 0,
            },
        );
    }
}

fn run_end(name: &str, code: i32) {
    if let Ok(mut g) = RUNS.lock() {
        if let Some(r) = g.as_mut().and_then(|m| m.get_mut(name)) {
            r.exit = Some(code);
            r.finished = now();
        }
    }
    RUN_ENDED.notify_all();
}

fn run_forget(name: &str) {
    if let Ok(mut g) = RUNS.lock() {
        if let Some(m) = g.as_mut() {
            m.remove(name);
        }
    }
}

/// An ended foreground box without `--rm`: what kern no longer lists.
fn run_ended(name: &str) -> Option<Run> {
    RUNS.lock().ok().and_then(|g| {
        g.as_ref()
            .and_then(|m| m.get(name))
            .filter(|r| r.exit.is_some() && !r.created.auto_remove)
            .cloned()
    })
}

fn runs_ended() -> Vec<(String, Run)> {
    RUNS.lock()
        .ok()
        .and_then(|g| {
            g.as_ref().map(|m| {
                m.iter()
                    .filter(|(_, r)| r.exit.is_some() && !r.created.auto_remove)
                    .map(|(n, r)| (n.clone(), r.clone()))
                    .collect()
            })
        })
        .unwrap_or_default()
}

/// The exit code of `name` if this server runs it in the foreground, waiting for its end; `None`
/// when it is not one of those.
fn run_exit(name: &str) -> Option<i32> {
    let mut g = RUNS.lock().ok()?;
    loop {
        match g.as_ref().and_then(|m| m.get(name)) {
            None => return None,
            Some(Run {
                exit: Some(code), ..
            }) => return Some(*code),
            Some(_) => {}
        }
        g = RUN_ENDED.wait(g).ok()?;
    }
}

/// `kern wait NAME` while the client stays: one `poll` on kern's answer and on the connection, no
/// timeout, so the answer comes the moment kern gives it. `None` when the client hung up first; the
/// `kern wait` is killed then.
fn kern_wait_while_connected(
    bin: &Path,
    name: &str,
    client: &UnixStream,
) -> Option<(i32, String, String)> {
    use std::os::fd::AsRawFd;
    let mut child = Command::new(bin)
        .args(["wait", name])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let answer = child.stdout.as_ref().map(AsRawFd::as_raw_fd)?;
    let mut fds = [
        libc::pollfd {
            fd: answer,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: client.as_raw_fd(),
            events: libc::POLLRDHUP,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: two pollfds owned here; no timeout.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
    let gone = libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR;
    if fds[0].revents == 0 && fds[1].revents & gone != 0 {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }
    let o = child.wait_with_output().ok()?;
    Some((
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    ))
}

/// `POST /containers/{id}/wait`. The head goes at once and the body when the box ends, as Docker
/// does it: `docker run` asks for the wait BEFORE the start, and starts only once the head is in.
fn wait(bin: &Path, name: String) -> Response {
    let bin = bin.to_path_buf();
    Response::Stream {
        status: 200,
        content_type: "application/json",
        upgrade: false,
        writer: Box::new(move |w: &mut crate::Out| {
            wait_until_started(&name);
            let body = match run_exit(&name) {
                Some(status) => format!("{{\"StatusCode\":{status},\"Error\":null}}"),
                None => {
                    // A client that gave up (`docker run -d` drops its wait once the box started)
                    // ends this wait too: it would hold a `kern wait` and keep the server awake for
                    // as long as the box runs.
                    let Some((code, out, err)) = kern_wait_while_connected(&bin, &name, w.socket())
                    else {
                        return;
                    };
                    match out.trim().parse::<i64>() {
                        Ok(status) if code == 0 => {
                            format!("{{\"StatusCode\":{status},\"Error\":null}}")
                        }
                        _ => format!(
                            "{{\"StatusCode\":-1,\"Error\":{{\"Message\":{}}}}}",
                            json_str(&kern_error(&err))
                        ),
                    }
                }
            };
            let _ = w.write_all(body.as_bytes()).and_then(|()| w.flush());
        }),
    }
}

/// `POST /containers/{id}/attach`. Before the start (as `docker run` does it) the box will run in
/// the foreground with its stdout and stderr apart; after it, kern's log of the box is followed,
/// which is one stream (kern keeps a box's output as one).
fn attach(bin: &Path, name: &str, req: &Request) -> Response {
    if created_get(name).is_some() {
        let (to, from) = mpsc::channel::<Pipes>();
        match ATTACHED.lock() {
            Ok(mut g) => {
                g.get_or_insert_with(HashMap::new)
                    .insert(name.to_string(), to);
            }
            Err(_) => return error(500, "the attach table is unusable"),
        }
        return Response::Stream {
            status: 200,
            content_type: "application/vnd.docker.multiplexed-stream",
            upgrade: req.upgrade,
            writer: Box::new(move |w: &mut crate::Out| {
                // Ends without a word when the container is removed instead of started.
                if let Ok((out, err)) = from.recv() {
                    pump(w, out, err, false);
                }
            }),
        };
    }
    // Both streams unless the client named its own: an attach that asks for neither is how the
    // CLI's older clients spoke, and it always meant both.
    let wanted = match (req.flag("stdout"), req.flag("stderr")) {
        (false, false) => (true, true),
        named => named,
    };
    let mut args: Vec<String> = vec![
        "logs".into(),
        "--frames".into(),
        "-f".into(),
        name.to_string(),
    ];
    if !req.flag("logs") {
        args.push("--tail".into());
        args.push("0".into());
    }
    let mut cmd = Command::new(bin);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    Response::Stream {
        status: 200,
        content_type: "application/vnd.docker.multiplexed-stream",
        upgrade: req.upgrade,
        writer: Box::new(move |w: &mut crate::Out| {
            let Ok(mut child) = cmd.spawn() else { return };
            if let Some(out) = child.stdout.take() {
                let _ = copy_frames(out, w, wanted);
            }
            let _ = child.kill();
            let _ = child.wait();
        }),
    }
}

/// Start a created container in the foreground and hand its pipes to the attach waiting for it, so
/// the box's stdout and stderr stay apart and its exit code is the process's.
fn start_attached(bin: &Path, name: &str, c: &Created, to: mpsc::Sender<Pipes>) -> Response {
    let mut argv = c.argv.clone();
    if argv.get(2).map(String::as_str) == Some("-d") {
        argv.remove(2);
    }
    let mut child = match Command::new(bin)
        .args(&argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            run_end(name, 125);
            return error(500, &format!("cannot run kern box: {e}"));
        }
    };
    // The attach may have gone: then the pipes close and the box's writes fail, as a closed
    // terminal's do.
    let _ = to.send((child.stdout.take(), child.stderr.take()));
    let watched = name.to_string();
    let reaper = std::thread::Builder::new()
        .name("kern-serve-run".into())
        .spawn(move || run_end(&watched, exit_code(&mut child)));
    if reaper.is_err() {
        run_end(name, -1);
    }
    no_content()
}

// ---------------------------------------------------------------------------------------------
// exec: `kern exec` in a running box.

/// One exec: what to run, and how it ended.
#[derive(Clone)]
struct Exec {
    name: String,
    argv: Vec<String>,
    cmd: Vec<String>,
    tty: bool,
    started: bool,
    running: bool,
    exit: Option<i32>,
}

static EXECS: Mutex<Option<HashMap<String, Exec>>> = Mutex::new(None);

fn exec_get(id: &str) -> Option<Exec> {
    EXECS
        .lock()
        .ok()
        .and_then(|g| g.as_ref().and_then(|m| m.get(id).cloned()))
}

/// Claim an exec for a start: false when it was started already (Docker answers 409).
fn exec_claim(id: &str) -> Option<Exec> {
    let mut g = EXECS.lock().ok()?;
    let e = g.as_mut()?.get_mut(id)?;
    if e.started {
        return None;
    }
    e.started = true;
    e.running = true;
    Some(e.clone())
}

fn exec_finish(id: &str, code: i32) {
    if let Ok(mut g) = EXECS.lock() {
        if let Some(e) = g.as_mut().and_then(|m| m.get_mut(id)) {
            e.running = false;
            e.exit = Some(code);
        }
    }
}

/// `POST /containers/{id}/exec`.
fn exec_create(name: &str, body: &Value) -> Response {
    let cmd = strings(body.get("Cmd"));
    if cmd.is_empty() {
        return error(400, "No exec command specified");
    }
    if body.get("Privileged").and_then(Value::as_bool) == Some(true) {
        return error(
            400,
            "Privileged exec: kern does not grant extra privileges to a command in a box",
        );
    }
    let tty = body.get("Tty").and_then(Value::as_bool) == Some(true);
    let mut argv: Vec<String> = vec!["exec".into()];
    if tty {
        argv.push("-t".into());
    }
    if let Some(u) = body
        .get("User")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        argv.push("-u".into());
        argv.push(u.to_string());
    }
    if let Some(w) = body
        .get("WorkingDir")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        argv.push("-w".into());
        argv.push(w.to_string());
    }
    for e in strings(body.get("Env")) {
        argv.push("--env".into());
        argv.push(e);
    }
    argv.push(name.to_string());
    argv.push("--".into());
    argv.extend(cmd.iter().cloned());
    let Some(id) = random_hex(32) else {
        return error(500, "no exec id could be made (/dev/urandom)");
    };
    match EXECS.lock() {
        Ok(mut g) => {
            g.get_or_insert_with(HashMap::new).insert(
                id.clone(),
                Exec {
                    name: name.to_string(),
                    argv,
                    cmd,
                    tty,
                    started: false,
                    running: false,
                    exit: None,
                },
            );
        }
        Err(_) => return error(500, "the exec table is unusable"),
    }
    json_response(201, format!("{{\"Id\":{}}}", json_str(&id)))
}

fn exit_code(child: &mut std::process::Child) -> i32 {
    child.wait().ok().and_then(|s| s.code()).unwrap_or(-1)
}

/// `POST /exec/{id}/start`. Attached, the command's stdout and stderr come back as Docker's frames
/// (raw bytes for a tty) on the connection, handed over with `101` when the client asked for it.
fn exec_start(bin: &Path, id: &str, req: &Request) -> Response {
    if exec_get(id).is_none() {
        return error(404, &format!("No such exec instance: {id}"));
    }
    let Some(e) = exec_claim(id) else {
        return error(409, &format!("exec {id} has been started already"));
    };
    let body = json::parse(&String::from_utf8_lossy(&req.body)).unwrap_or(Value::Null);
    let detach = body.get("Detach").and_then(Value::as_bool) == Some(true);
    let mut cmd = Command::new(bin);
    cmd.args(&e.argv).stdin(Stdio::null());
    let id = id.to_string();
    if detach {
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        return match cmd.spawn() {
            Ok(mut child) => {
                let watcher = id.clone();
                let spawned = std::thread::Builder::new()
                    .name("kern-serve-exec".into())
                    .spawn(move || exec_finish(&watcher, exit_code(&mut child)));
                if spawned.is_err() {
                    exec_finish(&id, -1);
                }
                Response::Full {
                    status: 200,
                    content_type: "application/json",
                    body: Vec::new(),
                    extra: Vec::new(),
                }
            }
            Err(err) => {
                exec_finish(&id, 126);
                error(500, &format!("cannot run kern exec: {err}"))
            }
        };
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let tty = e.tty;
    Response::Stream {
        status: 200,
        content_type: if tty {
            "application/vnd.docker.raw-stream"
        } else {
            "application/vnd.docker.multiplexed-stream"
        },
        upgrade: req.upgrade,
        writer: Box::new(move |w: &mut crate::Out| {
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(err) => {
                    let msg = format!("kern: cannot run kern exec: {err}\n");
                    let _ = w.write_all(&frame_of(2, msg.as_bytes()));
                    exec_finish(&id, 126);
                    return;
                }
            };
            let out = child.stdout.take();
            let err = child.stderr.take();
            pump(w, out, err, tty);
            exec_finish(&id, exit_code(&mut child));
        }),
    }
}

/// `GET /exec/{id}/json`.
fn exec_inspect(id: &str) -> Response {
    let Some(e) = exec_get(id) else {
        return error(404, &format!("No such exec instance: {id}"));
    };
    let (entry, args) = e
        .cmd
        .split_first()
        .map_or((String::new(), Vec::new()), |(a, b)| {
            (a.clone(), b.to_vec())
        });
    json_response(
        200,
        format!(
            "{{\"ID\":{},\"Running\":{},\"ExitCode\":{},\"ProcessConfig\":{{\"tty\":{},\"entrypoint\":{},\"arguments\":{},\"privileged\":false}},\"OpenStdin\":false,\"OpenStderr\":true,\"OpenStdout\":true,\"CanRemove\":false,\"ContainerID\":{},\"Pid\":0}}",
            json_str(id),
            e.running,
            e.exit.map_or_else(|| "null".to_string(), |c| c.to_string()),
            e.tty,
            json_str(&entry),
            str_array(&args),
            json_str(&id_of(&e.name))
        ),
    )
}

// ---------------------------------------------------------------------------------------------
// Routing.

fn not_translated(what: &str) -> Response {
    error(
        501,
        &format!("{what}: not translated by kern-serve in this phase (kern never hands it to a docker engine)"),
    )
}

/// One request.
pub(crate) fn handle(req: &Request, bin: &Path) -> Response {
    let segs: Vec<String> = req
        .path
        .trim_matches('/')
        .split('/')
        .map(|s| percent_decode(s, false))
        .collect();
    let seg: Vec<&str> = segs.iter().map(String::as_str).collect();
    match (req.method.as_str(), seg.as_slice()) {
        ("GET" | "HEAD", ["_ping"]) => Response::Full {
            status: 200,
            content_type: "text/plain; charset=utf-8",
            body: b"OK".to_vec(),
            extra: vec![
                ("Docker-Experimental", "false".into()),
                ("Ostype", "linux".into()),
            ],
        },
        ("GET", ["version"]) => version(),
        ("GET", ["info"]) => info(bin),
        ("POST", ["_kern", "session-ended"]) => session_ended(bin, req),
        ("GET", ["containers", "json"]) => list(bin, req),
        ("POST", ["containers", "create"]) => {
            let name = match req.param("name").filter(|n| !n.is_empty()) {
                Some(n) if valid_name(n) => n.to_string(),
                Some(n) => return error(400, &format!("Invalid container name ({n})")),
                None => match fresh_name() {
                    Some(n) => n,
                    None => return error(500, "no random name could be made (/dev/urandom)"),
                },
            };
            if resolve(bin, &name).is_some() {
                return error(
                    409,
                    &format!("Conflict. The container name \"/{name}\" is already in use"),
                );
            }
            let body = match json::parse(&String::from_utf8_lossy(&req.body)) {
                Ok(b) => b,
                Err(e) => return error(400, &e.to_string()),
            };
            match create_argv(&name, &body) {
                Ok(c) => {
                    let session = c.labels.iter().any(|(k, _)| k == SESSION_LABEL);
                    created_put(&name, c);
                    if let (true, Some(owner)) = (session, req.peer.clone()) {
                        session_track(bin, &name, owner);
                    }
                    json_response(
                        201,
                        format!("{{\"Id\":{},\"Warnings\":[]}}", json_str(&id_of(&name))),
                    )
                }
                Err(e) => error(400, &e),
            }
        }
        ("POST", ["containers", id, "start"]) => {
            let Some(name) = resolve(bin, id) else {
                return error(404, &format!("No such container: {id}"));
            };
            let not_modified = || Response::Full {
                status: 304,
                content_type: "text/plain",
                body: Vec::new(),
                extra: Vec::new(),
            };
            // Started already, or being started: Docker answers 304.
            let Some(c) = created_get(&name) else {
                return not_modified();
            };
            if !start_claim(&name) {
                return not_modified();
            }
            let resp = match attached_take(&name) {
                Some(to) => {
                    run_begin(&name, &c);
                    start_attached(bin, &name, &c, to)
                }
                None => {
                    let argv: Vec<&str> = c.argv.iter().map(String::as_str).collect();
                    let (code, _, err) = kern(bin, &argv);
                    if code == 0 {
                        no_content()
                    } else {
                        error(500, &kern_error(&err))
                    }
                }
            };
            // The container leaves CREATED only once kern runs it: `docker run` asked for its
            // wait before the start, and a wait woken earlier would find no box. A start that
            // failed leaves it created, as Docker does.
            if matches!(resp, Response::Full { status: 204, .. }) {
                drop(created_take(&name));
            }
            start_release(&name);
            resp
        }
        ("GET", ["containers", id, "json"]) => match resolve(bin, id) {
            Some(name) => inspect(bin, &name),
            None => error(404, &format!("No such container: {id}")),
        },
        ("GET", ["containers", id, "logs"]) => match resolve(bin, id) {
            Some(name) => logs(bin, &name, req),
            None => error(404, &format!("No such container: {id}")),
        },
        ("POST", ["containers", id, "wait"]) => {
            let Some(name) = resolve(bin, id) else {
                return error(404, &format!("No such container: {id}"));
            };
            wait(bin, name)
        }
        ("POST", ["containers", id, verb @ ("stop" | "kill" | "restart")]) => {
            let Some(name) = resolve(bin, id) else {
                return error(404, &format!("No such container: {id}"));
            };
            if created_get(&name).is_some() {
                return Response::Full {
                    status: 304,
                    content_type: "text/plain",
                    body: Vec::new(),
                    extra: Vec::new(),
                };
            }
            let t = req
                .param("t")
                .filter(|t| t.bytes().all(|c| c.is_ascii_digit()) && !t.is_empty())
                .unwrap_or("10")
                .to_string();
            let args: Vec<&str> = match *verb {
                "kill" => vec!["kill", &name],
                "restart" => vec!["restart", "-t", &t, &name],
                _ => vec!["stop", "-t", &t, &name],
            };
            let (code, _, err) = kern(bin, &args);
            if code == 0 {
                no_content()
            } else if err.contains("no running box") {
                Response::Full {
                    status: 304,
                    content_type: "text/plain",
                    body: Vec::new(),
                    extra: Vec::new(),
                }
            } else {
                error(500, &kern_error(&err))
            }
        }
        ("DELETE", ["containers", id]) => {
            let Some(name) = resolve(bin, id) else {
                return error(404, &format!("No such container: {id}"));
            };
            session_forget(&name);
            if created_take(&name).is_some() {
                // A pending attach ends with the container.
                drop(attached_take(&name));
                return no_content();
            }
            if run_ended(&name).is_some() {
                run_forget(&name);
                return no_content();
            }
            let force = req.flag("force");
            let running = kern_boxes(bin).into_iter().any(|(n, v)| {
                n == name && v.get("status").and_then(Value::as_str) != Some("exited")
            });
            if running && !force {
                return error(409, &format!("You cannot remove a running container {name}. Stop the container before attempting removal or force remove"));
            }
            if running {
                let _ = kern(bin, &["stop", "-t", "0", &name]);
            }
            let _ = kern(bin, &["rm", "-f", &name]);
            no_content()
        }
        ("POST", ["images", "create"]) => pull(bin, req),
        ("GET", ["images", rest @ .., "json"]) if !rest.is_empty() => {
            image_inspect(bin, &rest.join("/"))
        }
        ("POST", ["containers", id, "exec"]) => {
            let Some(name) = resolve(bin, id) else {
                return error(404, &format!("No such container: {id}"));
            };
            match json::parse(&String::from_utf8_lossy(&req.body)) {
                Ok(b) => exec_create(&name, &b),
                Err(e) => error(400, &e.to_string()),
            }
        }
        ("POST", ["containers", id, "attach"]) => {
            let Some(name) = resolve(bin, id) else {
                return error(404, &format!("No such container: {id}"));
            };
            attach(bin, &name, req)
        }
        ("POST", ["exec", id, "start"]) => exec_start(bin, id, req),
        ("GET", ["exec", id, "json"]) => exec_inspect(id),
        ("POST", ["exec", _, "resize"]) => no_content(),
        (_, ["networks", ..]) => not_translated("networks"),
        (_, ["volumes", ..]) => not_translated("the volumes API"),
        ("POST", ["build"]) => not_translated("build"),
        (m, _) => not_translated(&format!("{m} {}", req.path)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(s: &str) -> Value {
        json::parse(s).unwrap_or(Value::Null)
    }

    #[test]
    fn a_session_peer_is_this_process_until_it_ends() {
        let me = Peer::of(std::process::id() as i32);
        assert!(
            me.is_some_and(Peer::alive),
            "this process must read as alive"
        );
        let Ok(mut child) = Command::new("true").spawn() else {
            panic!("no child")
        };
        let pid = child.id() as i32;
        let _ = child.wait();
        assert!(
            Peer::of(pid).is_none(),
            "an ended, reaped child must not read as alive"
        );
        // A name with spaces and a `)` must not shift the fields.
        let Ok(mut odd) = Command::new("sh")
            .args(["-c", "exec -a 'a ) b' sleep 5"])
            .spawn()
        else {
            panic!("no child")
        };
        let st = proc_start(odd.id() as i32);
        let _ = odd.kill();
        let _ = odd.wait();
        assert!(st.is_some_and(|s| s > 0), "{st:?}");
    }

    #[test]
    fn an_exec_becomes_one_kern_exec_and_a_privileged_one_is_refused() {
        let r = exec_create(
            "web",
            &body(
                r#"{"Cmd":["psql","-c","select 1"],"User":"postgres","WorkingDir":"/tmp","Env":["A=1"],"Tty":false}"#,
            ),
        );
        let Response::Full {
            status, body: b, ..
        } = r
        else {
            panic!("not a full answer")
        };
        assert_eq!(status, 201);
        let id = json::parse(&String::from_utf8_lossy(&b))
            .ok()
            .and_then(|v| v.get("Id").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_default();
        assert_eq!(id.len(), 64, "{id}");
        let e = exec_get(&id).map(|e| e.argv).unwrap_or_default();
        assert_eq!(
            e,
            [
                "exec", "-u", "postgres", "-w", "/tmp", "--env", "A=1", "web", "--", "psql", "-c",
                "select 1"
            ]
        );
        assert!(exec_claim(&id).is_some());
        assert!(exec_claim(&id).is_none(), "a second start must be refused");
        let refused = exec_create("web", &body(r#"{"Cmd":["id"],"Privileged":true}"#));
        assert!(matches!(refused, Response::Full { status: 400, .. }));
        let empty = exec_create("web", &body(r#"{"Cmd":[]}"#));
        assert!(matches!(empty, Response::Full { status: 400, .. }));
        assert_eq!(frame_of(2, b"ab"), [2, 0, 0, 0, 0, 0, 0, 2, b'a', b'b']);
    }

    #[test]
    fn a_testcontainers_create_becomes_one_kern_box() {
        let b = body(
            r#"{"Image":"nginx:alpine","Cmd":["nginx","-g","daemon off;"],"Env":["A=1"],
            "ExposedPorts":{"80/tcp":{}},"Labels":{"org.testcontainers":"true"},
            "HostConfig":{"PortBindings":{"80/tcp":[{"HostIp":"","HostPort":""}]},"Memory":0}}"#,
        );
        let c = create_argv("kd-1", &b).map(|c| c.argv);
        assert_eq!(
            c,
            Ok(vec![
                "box",
                "kd-1",
                "-d",
                "--log-streams",
                "-e",
                "A=1",
                "-l",
                "org.testcontainers=true",
                "-p",
                "0.0.0.0::80/tcp",
                "--image",
                "nginx:alpine",
                "--",
                "nginx",
                "-g",
                "daemon off;"
            ]
            .into_iter()
            .map(String::from)
            .collect())
        );
    }

    #[test]
    fn what_kern_grants_only_by_flag_is_refused_by_name() {
        for (field, v) in [
            ("Privileged", "true"),
            ("Devices", r#"[{"PathOnHost":"/dev/kvm"}]"#),
            ("DeviceRequests", r#"[{"Driver":"nvidia"}]"#),
            ("CapAdd", r#"["SYS_ADMIN"]"#),
            ("SecurityOpt", r#"["seccomp=unconfined"]"#),
            ("PidMode", r#""host""#),
        ] {
            let b = body(&format!(
                r#"{{"Image":"x","HostConfig":{{"{field}":{v}}}}}"#
            ));
            let r = create_argv("n", &b).map(|c| c.argv);
            assert!(matches!(&r, Err(m) if m.contains(field)), "{field}: {r:?}");
        }
        // Their empty values are not a request.
        let b =
            body(r#"{"Image":"x","HostConfig":{"Privileged":false,"CapAdd":null,"Devices":[]}}"#);
        assert!(create_argv("n", &b).is_ok());
        assert!(create_argv("n", &body(r#"{"Cmd":["x"]}"#)).is_err());
    }

    #[test]
    fn entrypoint_publish_all_and_network_modes_translate() {
        let b = body(
            r#"{"Image":"x","Entrypoint":["/bin/sh","-c"],"Cmd":["echo hi"],"ExposedPorts":{"6379/tcp":{}},
            "HostConfig":{"PublishAllPorts":true,"NetworkMode":"host","AutoRemove":true,"NanoCpus":500000000,"Binds":["/data:/d:ro"]}}"#,
        );
        let a = create_argv("n", &b)
            .map(|c| c.argv.join(" "))
            .unwrap_or_default();
        assert_eq!(
            a,
            "box n -d --log-streams -p 0.0.0.0::6379/tcp -v /data:/d:ro --cpus 0.500 --rm --network host --entrypoint /bin/sh --image x -- -c echo hi"
        );
        let b = body(r#"{"Image":"x","HostConfig":{"NetworkMode":"mynet"}}"#);
        assert!(create_argv("n", &b).is_err());
    }

    #[test]
    fn kern_ports_read_as_docker_network_settings() {
        assert_eq!(
            ports_json(
                "127.0.0.1:56679->80, 0.0.0.0:9000->53/udp",
                &["443/tcp".to_string()]
            ),
            r#"{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"56679"}],"53/udp":[{"HostIp":"0.0.0.0","HostPort":"9000"}],"443/tcp":null}"#
        );
        assert_eq!(ports_json("", &[]), "{}");
    }

    #[test]
    fn ids_are_stable_hex_and_names_are_checked() {
        let a = id_of("kd-1");
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a, id_of("kd-1"));
        assert_ne!(a, id_of("kd-2"));
        assert!(valid_name("web_1.a-b"));
        for bad in ["", "-x", ".x", "a b", "a/b", "a;b"] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn dates_are_rfc3339_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_795_188_825), "2026-11-20T15:33:45Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn a_log_frame_is_docker_s_eight_byte_header() {
        assert_eq!(
            frame_of(1, b"hi\n"),
            vec![1, 0, 0, 0, 0, 0, 0, 3, b'h', b'i', b'\n']
        );
    }

    /// A reader that hands out `step` bytes at a time, so headers and payloads arrive cut anywhere.
    struct Trickle<'a> {
        data: &'a [u8],
        step: usize,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.step.min(self.data.len()).min(buf.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    /// `tail` as Docker's daemon reads it: a whole number is a line count, anything else (the
    /// `-1` Testcontainers for Node sends, `all`, empty, junk) is the whole log, never a
    /// `--tail` that `kern logs` refuses and that ends the stream empty.
    #[test]
    fn tail_negative_or_not_a_number_is_the_whole_log() {
        assert_eq!(tail_lines(Some("10")), Some(10));
        assert_eq!(tail_lines(Some("0")), Some(0));
        for t in ["-1", "-20", "all", "", "x"] {
            assert_eq!(tail_lines(Some(t)), None, "tail={t:?}");
        }
        assert_eq!(tail_lines(None), None);
    }

    /// The frames `kern logs --frames` writes pass through whole, and only the streams asked for:
    /// cut into 3-byte reads, with an empty frame among them, the output is the same frames.
    #[test]
    fn framed_logs_pass_through_and_a_stream_not_asked_for_is_dropped() {
        let mut input = Vec::new();
        input.extend(frame_of(1, b"out one\n"));
        input.extend(frame_of(2, b"err one\n"));
        input.extend(frame_of(1, b""));
        input.extend(frame_of(2, b"err two, longer than a read\n"));
        input.extend(frame_of(1, b"out two\n"));
        let run = |wanted: (bool, bool)| {
            let mut out = Vec::new();
            let ok = copy_frames(
                Trickle {
                    data: &input,
                    step: 3,
                },
                &mut out,
                wanted,
            );
            assert!(ok);
            out
        };
        assert_eq!(run((true, true)), input);
        let mut only_out = Vec::new();
        only_out.extend(frame_of(1, b"out one\n"));
        only_out.extend(frame_of(1, b""));
        only_out.extend(frame_of(1, b"out two\n"));
        assert_eq!(run((true, false)), only_out);
        let mut only_err = Vec::new();
        only_err.extend(frame_of(2, b"err one\n"));
        only_err.extend(frame_of(2, b"err two, longer than a read\n"));
        assert_eq!(run((false, true)), only_err);
    }
}
