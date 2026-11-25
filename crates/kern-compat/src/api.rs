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
use kern_common::rfc3339;

use crate::{percent_decode, Request, Response};

/// The API version kern-serve speaks, and the oldest a client may ask for.
pub(crate) const API_VERSION: &str = "1.43";
const MIN_API_VERSION: &str = "1.24";
/// The Docker Engine release whose API is [`API_VERSION`]: what `Version` in `/version` and
/// `ServerVersion` in `/info` say. Clients read those as the engine's version and gate on it
/// (Testcontainers for Java refuses a server below 1.6.0), so kern's own version, `v0.x`, would
/// fail them; kern and its version are in `Platform` and `Components`, where `docker version`
/// prints them.
const ENGINE_VERSION: &str = "24.0.0";

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
    /// `OpenStdin` (`docker run -i`): the attach's bytes are the workload's stdin.
    stdin: bool,
    /// `Tty` (`docker run -t`): a terminal, and the attach is one raw stream, not frames.
    tty: bool,
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
/// Every container created and not yet started (or whose start failed), for the list.
fn created_all() -> Vec<(String, Created)> {
    CREATED
        .lock()
        .ok()
        .and_then(|g| {
            g.as_ref()
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        })
        .unwrap_or_default()
}

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
/// Whether a row of `kern ps -a --json` is a box that runs: an `exited` one and a `kept` one not
/// running (a stopped container whose layer is kept) are not.
fn box_running(v: &Value) -> bool {
    !matches!(
        v.get("status").and_then(Value::as_str),
        Some("exited" | "kept")
    )
}

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
    let names = kern_boxes(bin).into_iter().map(|(n, _)| n).chain(pending);
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
            "the bind {bind:?}: the source is a socket, and kern mounts no socket into a box (a box \
             holding this API's socket could ask it for any box). For Testcontainers, whose reaper \
             Ryuk asks for it: set TESTCONTAINERS_RYUK_DISABLED=true; kern removes a test session's \
             containers itself when the process that made them ends"
        ));
    }
    Ok(())
}

/// A field set to anything but its empty value (`null`, `false`, `0`, `""`, `[]`, `{}`).
fn is_set(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Arr(a)) => !a.is_empty(),
        Some(Value::Obj(o)) => !o.is_empty(),
        Some(Value::Str(s)) => !s.is_empty(),
        Some(Value::Num(n)) => n != "0",
    }
}

/// `HostConfig.Mounts` (`--mount`) as kern's own `--mount` values, which take the same three types.
/// Dev Containers mounts the workspace this way, always. An option kern's mount does not have is
/// refused by name rather than dropped: a mount quietly made another way is a test reading other
/// data. `Consistency` is accepted and has no effect, as with Docker on Linux.
fn translate_mounts(host: Option<&Value>) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for m in host
        .and_then(|h| h.get("Mounts"))
        .and_then(Value::as_array)
        .unwrap_or_default()
    {
        let field = |k: &str| m.get(k).and_then(Value::as_str).unwrap_or_default();
        let (kind, source, target) = (field("Type"), field("Source"), field("Target"));
        let refuse = |what: &str| {
            Err(format!(
                "HostConfig.Mounts {kind} {target:?}: {what} is not translated by kern"
            ))
        };
        if target.is_empty() {
            return refuse("a mount without a Target");
        }
        if source.contains(',') || target.contains(',') {
            return refuse("a path with a comma");
        }
        let opts = |o: &str, keys: &[&str]| {
            keys.iter()
                .find(|k| is_set(m.get(o).and_then(|v| v.get(k))))
                .map(|k| format!("{o}.{k}"))
        };
        let mut spec = format!("type={kind},");
        match kind {
            "bind" => {
                if !source.starts_with('/') {
                    return refuse("a bind whose Source is not an absolute path");
                }
                let propagation = m
                    .get("BindOptions")
                    .and_then(|b| b.get("Propagation"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if !matches!(propagation, "" | "rprivate") {
                    return refuse(&format!("BindOptions.Propagation {propagation:?}"));
                }
                if let Some(o) = opts(
                    "BindOptions",
                    &[
                        "NonRecursive",
                        "CreateMountpoint",
                        "ReadOnlyNonRecursive",
                        "ReadOnlyForceRecursive",
                    ],
                ) {
                    return refuse(&o);
                }
                refuse_socket_bind(source)?;
                spec.push_str(&format!("src={source},"));
            }
            "volume" => {
                if let Some(o) = opts(
                    "VolumeOptions",
                    &["NoCopy", "Labels", "DriverConfig", "Subpath"],
                ) {
                    return refuse(&o);
                }
                if !source.is_empty() {
                    spec.push_str(&format!("src={source},"));
                }
            }
            "tmpfs" => {
                if !source.is_empty() {
                    return refuse("a tmpfs with a Source");
                }
                if let Some(o) = opts("TmpfsOptions", &["Mode", "Options"]) {
                    return refuse(&o);
                }
                if let Some(size) = m
                    .get("TmpfsOptions")
                    .and_then(|t| t.get("SizeBytes"))
                    .and_then(Value::as_i64)
                    .filter(|n| *n > 0)
                {
                    spec.push_str(&format!("tmpfs-size={size},"));
                }
            }
            _ => return refuse("this Type"),
        }
        spec.push_str(&format!("dst={target}"));
        if m.get("ReadOnly").and_then(Value::as_bool) == Some(true) {
            spec.push_str(",ro");
        }
        out.push(spec);
    }
    Ok(out)
}

fn refuse_if_set(host: Option<&Value>, field: &str) -> Result<(), String> {
    if is_set(host.and_then(|h| h.get(field))) {
        Err(format!(
            "HostConfig.{field}: kern does not grant it over the socket; run that container with \
             kern directly, where the flag is explicit"
        ))
    } else {
        Ok(())
    }
}

/// The `kern box` argv for a create body (without the leading `kern`), and what `inspect` reports.
/// A `platform` query parameter as Docker spells one: `os/arch[/variant]`, lowercase, nothing a
/// flag or a path could be made of.
fn valid_platform(p: &str) -> bool {
    p.len() <= 64
        && p.contains('/')
        && !p.starts_with(['/', '-'])
        && p.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'/' | b'_' | b'-' | b'.')
        })
}

/// The create's `?platform=` as `kern box --platform`, before the image and its command.
fn with_platform(mut c: Created, platform: Option<&str>) -> Created {
    if let Some(p) = platform {
        let at = c
            .argv
            .iter()
            .position(|a| a == "--image")
            .unwrap_or(c.argv.len());
        c.argv
            .splice(at..at, ["--platform".to_string(), p.to_string()]);
    }
    c
}

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
    let mounts = translate_mounts(host)?;
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
                let hp = b
                    .get("HostPort")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                // NO ADDRESS MEANS EVERY ADDRESS, as in Docker: kern's `-p <host>:<box>` binds
                // `0.0.0.0` and `[::]`. Spelled `0.0.0.0` it was IPv4 alone, and a Windows client
                // that asks for `localhost` (.NET, PowerShell) tries `::1` first: MEASURED on WSL,
                // `::1` is refused only after 2068 ms, paid on every new connection.
                match b
                    .get("HostIp")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    Some(ip) => published.push(format!("{ip}:{hp}:{num}/{proto}")),
                    None => published.push(format!("{hp}:{num}/{proto}")),
                }
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
            // Every address, as a `HostIp` left empty above.
            let spec = format!(":{num}/{proto}");
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
    for m in mounts {
        argv.push("--mount".into());
        argv.push(m);
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
    } else if !in_session(&labels) {
        // A container keeps its filesystem until it is removed, and `docker start` runs it again
        // on the same files (Dev Containers does at every reopen): a kept box. Not one that removes
        // itself, nor a Testcontainers run's, which this server removes when the run ends and
        // nothing starts again; those keep their writes in memory, where they are fastest.
        // MEASURED: a kept box starts in 25.6 ms against 5.4 ms, the copy-up of `/etc/hosts` into a
        // layer on disk.
        argv.push("--keep".into());
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
    // `HostConfig.RestartPolicy` is `kern box --restart`: Docker's names, and `MaximumRetryCount` as
    // `on-failure:N`. MEASURED before: the field was not read at all, so `docker run --restart
    // on-failure:2` through the socket ran once and stayed down, accepted and not honoured. A policy
    // with `AutoRemove` is refused, as Docker's daemon refuses it.
    let policy = host.and_then(|h| h.get("RestartPolicy"));
    match policy.and_then(|p| p.get("Name")).and_then(Value::as_str) {
        None | Some("" | "no") => {}
        Some(name @ ("on-failure" | "always" | "unless-stopped")) => {
            if auto_remove {
                return Err(format!(
                    "HostConfig.RestartPolicy {name:?} with AutoRemove: a container that removes \
                     itself cannot be restarted (Docker refuses the pair too)"
                ));
            }
            let retries = policy
                .and_then(|p| p.get("MaximumRetryCount"))
                .and_then(Value::as_i64)
                .filter(|n| *n > 0);
            argv.push("--restart".into());
            argv.push(match (name, retries) {
                ("on-failure", Some(n)) => format!("on-failure:{n}"),
                _ => name.to_string(),
            });
        }
        Some(other) => {
            return Err(format!(
                "HostConfig.RestartPolicy {other:?}: Docker's policies are no, on-failure, always \
                 and unless-stopped"
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
    let flag = |k: &str| body.get(k).and_then(Value::as_bool) == Some(true);
    Ok(Created {
        argv,
        image,
        created: now(),
        labels,
        env,
        cmd,
        exposed,
        auto_remove,
        stdin: flag("OpenStdin"),
        tty: flag("Tty"),
    })
}

/// Docker's zero time, for a moment that has not happened, as clients compare it: Testcontainers
/// for Java takes a container as stopped only once `FinishedAt` is not this, and kept polling an
/// exited box for its whole startup timeout while it was.
const ZERO_TIME: &str = "0001-01-01T00:00:00Z";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
                "{{\"Id\":{},\"Created\":{},\"Name\":{},\"Image\":{},\"RestartCount\":0,\"State\":{{\"Status\":\"created\",\"Running\":false,\"Paused\":false,\"Restarting\":false,\"OOMKilled\":false,\"Dead\":false,\"Pid\":0,\"ExitCode\":0,\"Error\":\"\",\"StartedAt\":\"{ZERO_TIME}\",\"FinishedAt\":\"{ZERO_TIME}\"}},\"Config\":{{\"Image\":{},\"Env\":{},\"Cmd\":{},\"Labels\":{},\"Tty\":false}},\"HostConfig\":{{\"NetworkMode\":\"default\"}},\"NetworkSettings\":{{\"Ports\":{},\"IPAddress\":\"\",\"Networks\":{{}}}},\"Mounts\":[]}}",
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
        Some(v) if box_running(&v) => (v, true),
        _ => match exited() {
            Some(v) => (v, false),
            None => return error(404, &format!("No such container: {name}")),
        },
    };
    let secs = |k: &str| {
        v.get(k)
            .and_then(Value::as_i64)
            .and_then(|s| u64::try_from(s).ok())
    };
    let started = secs("started").map_or_else(|| ZERO_TIME.to_string(), rfc3339);
    // When the box was made (`created`, stable across the restarts of a kept box), else when it
    // started: Dev Containers runs `postCreateCommand` again whenever `Created` moves.
    let created = secs("created")
        .or_else(|| secs("started"))
        .map_or_else(|| ZERO_TIME.to_string(), rfc3339);
    let finished = match v.get("exited_ago").and_then(Value::as_i64) {
        Some(ago) if !running => rfc3339(now().saturating_sub(u64::try_from(ago).unwrap_or(0))),
        _ => ZERO_TIME.to_string(),
    };
    let exit_code = v.get("exit_code").and_then(Value::as_i64).unwrap_or(0);
    // Docker's `RestartCount`, which kern records per run (0 for a box that never restarted).
    let restart_count = v.get("restart_count").and_then(Value::as_i64).unwrap_or(0);
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
    // The image the box was started from (`kern inspect --json`'s `image`, empty for a `--rootfs`
    // box and for a box that has exited, whose record no longer holds it).
    let image = json_str(v.get("image").and_then(Value::as_str).unwrap_or_default());
    json_response(
        200,
        format!(
            "{{\"Id\":{},\"Created\":{},\"Name\":{},\"Path\":{},\"Args\":[],\"Image\":{image},\"RestartCount\":{restart_count},\"State\":{{\"Status\":{},\"Running\":{running},\"Paused\":false,\"Restarting\":false,\"OOMKilled\":false,\"Dead\":false,\"Pid\":{pid},\"ExitCode\":{exit_code},\"Error\":\"\",\"StartedAt\":{},\"FinishedAt\":{}{health_json}}},\"Config\":{{\"Image\":{image},\"Labels\":{},\"Tty\":false,\"Env\":[]}},\"HostConfig\":{{\"NetworkMode\":\"default\"}},\"NetworkSettings\":{{\"Ports\":{},\"IPAddress\":\"\",\"Networks\":{{}}}},\"Mounts\":[]}}",
            json_str(&id),
            json_str(&created),
            json_str(&format!("/{name}")),
            json_str(command),
            json_str(if running { "running" } else { "exited" }),
            json_str(&started),
            json_str(&finished),
            labels_json(&labels),
            ports_json(ports, &[])
        ),
    )
}

/// `GET /containers/json`: running boxes, `all=1` the exited ones too, `filters={"label":[...]}`.
/// The filters of `GET /containers/json` kern translates. A filter is how a client finds ITS
/// container among the user's boxes (Dev Containers looks its own up by label, then `exec`s into
/// it), so one that is not understood is refused by name: ignored, the list came back whole and the
/// client took another box for its own.
struct ListFilters {
    labels: Vec<String>,
    names: Vec<String>,
    ids: Vec<String>,
    statuses: Vec<String>,
}

impl ListFilters {
    fn parse(req: &Request) -> Result<Self, String> {
        let f = match req.param("filters").filter(|f| !f.is_empty()) {
            Some(f) => json::parse(f).map_err(|e| format!("invalid filters: {e}"))?,
            None => Value::Null,
        };
        if let Some((k, _)) = f
            .as_object()
            .unwrap_or_default()
            .iter()
            .find(|(k, _)| !matches!(k.as_str(), "label" | "name" | "id" | "status"))
        {
            return Err(format!(
                "containers filter {k:?}: not translated by kern-serve"
            ));
        }
        let names = filter_values(&f, "name");
        if let Some(n) = names.iter().find(|n| name_pattern(n).is_none()) {
            return Err(format!(
                "containers filter name={n:?}: a regular expression beyond ^ and $ is not translated"
            ));
        }
        Ok(Self {
            labels: filter_values(&f, "label"),
            names,
            ids: filter_values(&f, "id"),
            statuses: filter_values(&f, "status"),
        })
    }

    /// Docker lists exited containers for `status=exited`, as for `all=1`.
    fn wants_exited(&self) -> bool {
        self.statuses.iter().any(|s| s != "running")
    }

    /// `state` is Docker's: `running`, `exited` or `created`.
    fn keeps(&self, name: &str, state: &str, labels: &[(String, String)]) -> bool {
        let id = id_of(name);
        self.labels.iter().all(|w| match w.split_once('=') {
            Some((k, val)) => labels.iter().any(|(lk, lv)| lk == k && lv == val),
            None => labels.iter().any(|(lk, _)| lk == w),
        }) && (self.names.is_empty()
            || self
                .names
                .iter()
                .any(|n| name_pattern(n).is_some_and(|p| p.matches(name))))
            && (self.ids.is_empty()
                || self
                    .ids
                    .iter()
                    .any(|i| !i.is_empty() && id.starts_with(i.as_str())))
            && (self.statuses.is_empty() || self.statuses.iter().any(|s| s == state))
    }
}

/// A `name` filter: Docker matches a regular expression against the name with its leading `/`;
/// the forms clients send are a plain substring and `^`/`$` anchors, which is what is translated.
/// A `.` is taken as itself: names contain it, and the regular expression matches that too.
struct NamePattern<'a> {
    text: &'a str,
    start: bool,
    end: bool,
}

impl NamePattern<'_> {
    fn matches(&self, name: &str) -> bool {
        let full = format!("/{name}");
        // `^name` and `^/name` both anchor at the name's first character.
        let needle = if self.start && !self.text.starts_with('/') {
            format!("/{}", self.text)
        } else {
            self.text.to_string()
        };
        match (self.start, self.end) {
            (true, true) => full == needle,
            (true, false) => full.starts_with(&needle),
            (false, true) => full.ends_with(&needle),
            (false, false) => full.contains(&needle),
        }
    }
}

fn name_pattern(p: &str) -> Option<NamePattern<'_>> {
    let (start, rest) = p.strip_prefix('^').map_or((false, p), |r| (true, r));
    let (end, text) = rest.strip_suffix('$').map_or((false, rest), |r| (true, r));
    if text.chars().any(|c| "*+?[](){}|\\^$".contains(c)) {
        return None;
    }
    Some(NamePattern { text, start, end })
}

fn list(bin: &Path, req: &Request) -> Response {
    let filters = match ListFilters::parse(req) {
        Ok(f) => f,
        Err(e) => return error(400, &e),
    };
    let all = req.flag("all") || filters.wants_exited();
    // A container created here and not started yet is listed as Docker's `created`, and a box a
    // failed start left behind under its name is not listed twice.
    let created = created_all();
    let created_names: std::collections::HashSet<String> =
        created.iter().map(|(n, _)| n.clone()).collect();
    let mut items = Vec::new();
    for (name, v) in kern_boxes(bin) {
        let running = box_running(&v);
        if !running && !all {
            continue;
        }
        let labels = labels_of(&v);
        if created_names.contains(&name)
            || !filters.keeps(&name, if running { "running" } else { "exited" }, &labels)
        {
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
                // `[::]` as Docker spells it, `::`.
                let ip = ip.trim_start_matches('[').trim_end_matches(']');
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
            // The image kern recorded, running or exited: it was an empty string for every row, so
            // `docker ps` showed `<no image>` for every container.
            "{{\"Id\":{},\"Names\":[{}],\"Image\":{},\"Command\":{},\"Created\":{},\"State\":{},\"Status\":{},\"Ports\":[{}],\"Labels\":{}}}",
            json_str(&id_of(&name)),
            json_str(&format!("/{name}")),
            json_str(v.get("image").and_then(Value::as_str).unwrap_or_default()),
            json_str(v.get("command").and_then(Value::as_str).unwrap_or_default()),
            // The same `Created` `inspect` says: when the box was made.
            v.get("created")
                .or_else(|| v.get("started"))
                .and_then(Value::as_i64)
                .unwrap_or(0),
            json_str(if running { "running" } else { "exited" }),
            json_str(if running { "Up" } else { "Exited" }),
            ports.join(","),
            labels_json(&labels)
        ));
    }
    if all {
        // CREATED AND NOT STARTED, or whose start failed, as Docker lists them: `docker create`
        // then `ps -a` showed nothing, and Testcontainers' cleanup, which lists by label, never
        // found a container whose start had failed, so it stayed behind.
        for (name, c) in &created {
            if !filters.keeps(name, "created", &c.labels) {
                continue;
            }
            items.push(format!(
                "{{\"Id\":{},\"Names\":[{}],\"Image\":{},\"Command\":{},\"Created\":{},\"State\":\"created\",\"Status\":\"Created\",\"Ports\":[],\"Labels\":{}}}",
                json_str(&id_of(name)),
                json_str(&format!("/{name}")),
                json_str(&c.image),
                json_str(&c.cmd.join(" ")),
                c.created,
                labels_json(&c.labels)
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
        extra: Vec::new(),
        writer: Box::new(move |w: &mut crate::Out| {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            kern_frames(&bin, &args, w, wanted);
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
    // `docker pull --platform` / `docker run --platform`: that platform's own cache entry, the one
    // the create's `--platform` then runs.
    let platform = match req.param("platform").filter(|p| !p.is_empty()) {
        Some(p) if valid_platform(p) => Some(p.to_string()),
        Some(p) => return error(400, &format!("invalid platform: {p:?}")),
        None => None,
    };
    let bin = bin.to_path_buf();
    Response::Stream {
        status: 200,
        content_type: "application/json",
        upgrade: false,
        extra: Vec::new(),
        writer: Box::new(move |w: &mut crate::Out| {
            let _ = writeln!(
                w,
                "{{\"status\":{}}}",
                json_str(&format!("Pulling {image} with kern"))
            );
            let mut args = vec!["pull", "-q", image.as_str()];
            if let Some(p) = &platform {
                args.extend(["--platform", p.as_str()]);
            }
            let (code, _, err) = kern(&bin, &args);
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

/// The local image cache, as `kern images --json` lists it; with `digests`, each image's
/// repository digest too (`repo_digest`), which costs a read per image and only the list shows.
fn kern_images(bin: &Path, digests: bool) -> Vec<Value> {
    let args: &[&str] = if digests {
        &["images", "--json", "--digests"]
    } else {
        &["images", "--json"]
    };
    let (_, out, _) = kern(bin, args);
    json::parse(out.trim())
        .ok()
        .and_then(|v| v.as_array().map(<[Value]>::to_vec))
        .unwrap_or_default()
}

/// The values of one key of a Docker `filters` parameter, in either of its two spellings:
/// `{"reference":["alpine"]}` and the older `{"reference":{"alpine":true}}`.
pub(crate) fn filter_values(filters: &Value, key: &str) -> Vec<String> {
    let v = filters.get(key);
    match v.and_then(Value::as_object) {
        Some(set) => set
            .iter()
            .filter(|(_, on)| on.as_bool() != Some(false))
            .map(|(k, _)| k.clone())
            .collect(),
        None => strings(v),
    }
}

/// The repository of an image reference, without its tag or digest: `alpine` for `alpine:3.19`,
/// `localhost:5000/app` for `localhost:5000/app:1` (a colon before the last `/` is a port).
fn repository_of(image: &str) -> &str {
    let image = image.split('@').next().unwrap_or(image);
    let last = image.rfind('/').map_or(0, |i| i + 1);
    match image[last..].rfind(':') {
        Some(c) => &image[..last + c],
        None => image,
    }
}

/// Whether `image` matches a `reference` filter: the name itself, `name:latest` for a bare name, or
/// every tag of a repository. Docker's glob patterns (`alp*`) are not translated: `*` matches
/// nothing rather than everything, so a filtered list never comes back unfiltered.
fn reference_matches(image: &str, pattern: &str) -> bool {
    image == pattern || repository_of(image) == pattern || image == format!("{pattern}:latest")
}

/// `GET /images/json`: the local image cache as Docker's image summaries. Testcontainers for Java
/// lists it before its first pull, and stopped on the 501 this was. Filters: `reference` and
/// `dangling`; any other is refused by name rather than ignored.
fn image_list(bin: &Path, req: &Request) -> Response {
    let filters = match req.param("filters").filter(|f| !f.is_empty()) {
        Some(f) => match json::parse(f) {
            Ok(v) => v,
            Err(e) => return error(400, &format!("invalid filters: {e}")),
        },
        None => Value::Null,
    };
    if let Some(keys) = filters.as_object() {
        if let Some((k, _)) = keys
            .iter()
            .find(|(k, _)| k != "reference" && k != "dangling")
        {
            return error(
                400,
                &format!("images filter {k:?}: not translated by kern-serve"),
            );
        }
    }
    let references = filter_values(&filters, "reference");
    let dangling = filter_values(&filters, "dangling");
    let dangling = dangling.first().map(|d| d == "true" || d == "1");
    let mut items = Vec::new();
    for i in kern_images(bin, true) {
        let Some(n) = i.get("image").and_then(Value::as_str) else {
            continue;
        };
        let is_dangling = i.get("dangling").and_then(Value::as_bool) == Some(true);
        if dangling.is_some_and(|d| d != is_dangling)
            || (!references.is_empty() && !references.iter().any(|r| reference_matches(n, r)))
        {
            continue;
        }
        let tags = if is_dangling {
            String::new()
        } else {
            json_str(n)
        };
        let size = i.get("size_bytes").and_then(Value::as_i64).unwrap_or(0);
        // `repo@sha256:...`, as Docker lists the digest a pull recorded; none for a build.
        let digests = i
            .get("repo_digest")
            .and_then(Value::as_str)
            .map_or_else(String::new, |d| {
                json_str(&kern_common::repo_digest_ref(n, d))
            });
        items.push(format!(
            "{{\"Id\":{},\"ParentId\":\"\",\"RepoTags\":[{tags}],\"RepoDigests\":[{digests}],\"Created\":{},\"Size\":{size},\"SharedSize\":-1,\"VirtualSize\":{size},\"Labels\":{{}},\"Containers\":-1}}",
            json_str(&format!("sha256:{}", id_of(n))),
            i.get("pulled").and_then(Value::as_i64).unwrap_or(0).max(0),
        ));
    }
    json_response(200, format!("[{}]", items.join(",")))
}

/// The cached image an API path names, as `kern images --json` lists it: the name itself, a bare
/// name as `:latest`, or a repository pulled by digest.
fn cached_image(bin: &Path, name: &str) -> Option<Value> {
    let want_latest = if name.contains(':') || name.contains('@') {
        name.to_string()
    } else {
        format!("{name}:latest")
    };
    kern_images(bin, false).into_iter().find(|i| {
        i.get("image")
            .and_then(Value::as_str)
            .is_some_and(|n| n == name || n == want_latest || n.split('@').next() == Some(name))
    })
}

/// `GET /images/{name}/history`: `kern image history --json`, in Docker's shape, newest first.
/// Docker gives the top step the image's id and tags and the others `<missing>`, as it does for a
/// pulled image. `Size` is the layer's COMPRESSED size where kern knows it (the manifest's, what a
/// pull downloads; kern does not keep a layer's unpacked size) and 0 where it does not.
fn image_history(bin: &Path, name: &str) -> Response {
    let Some(i) = cached_image(bin, name) else {
        return error(404, &format!("No such image: {name}"));
    };
    let n = i.get("image").and_then(Value::as_str).unwrap_or(name);
    let (code, out, err) = kern(bin, &["image", "history", "--json", n]);
    if code != 0 {
        return error(500, &kern_error(&err));
    }
    let Ok(steps) = json::parse(out.trim()) else {
        return error(500, "kern image history --json printed no JSON array");
    };
    let rows: Vec<String> = steps
        .as_array()
        .unwrap_or_default()
        .iter()
        .enumerate()
        .map(|(ix, h)| {
            let text = |k: &str| h.get(k).and_then(Value::as_str).unwrap_or_default();
            let int = |k: &str| h.get(k).and_then(Value::as_i64).unwrap_or(0).max(0);
            format!(
                "{{\"Id\":{},\"Created\":{},\"CreatedBy\":{},\"Tags\":{},\"Size\":{},\"Comment\":{}}}",
                if ix == 0 {
                    json_str(&format!("sha256:{}", id_of(n)))
                } else {
                    json_str("<missing>")
                },
                int("Created"),
                json_str(text("CreatedBy")),
                if ix == 0 {
                    format!("[{}]", json_str(n))
                } else {
                    "null".to_string()
                },
                int("CompressedSize"),
                json_str(text("Comment")),
            )
        })
        .collect();
    json_response(200, format!("[{}]", rows.join(",")))
}

// ---------------------------------------------------------------------------------------------
// containers/{id}/archive: `docker cp`, onto `kern cp`.

/// `KERN_CP_STAT=1 kern cp <name>:<path> -`: Docker's stat of the path, or kern's error.
fn path_stat(bin: &Path, name: &str, path: &str) -> Result<String, String> {
    let out = Command::new(bin)
        .env("KERN_CP_STAT", "1")
        .args(["cp", &format!("{name}:{path}"), "-"])
        .stdin(Stdio::null())
        .output();
    match out {
        Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).trim().to_string()),
        Ok(o) => Err(kern_error(&String::from_utf8_lossy(&o.stderr))),
        Err(e) => Err(format!("cannot run {}: {e}", bin.display())),
    }
}

/// kern's refusal of a copy as Docker's status: a missing path 404, a box not running 409.
fn copy_refusal(id: &str, path: &str, why: &str) -> Response {
    if why.contains("No such file") || why.contains("no such directory") {
        return error(
            404,
            &format!("Could not find the file {path} in container {id}"),
        );
    }
    if why.contains("no box named") {
        return error(409, &format!("Container {id} is not running"));
    }
    if why.contains("must be a directory") || why.contains("Not a directory") {
        return error(400, &format!("{path}: not a directory"));
    }
    error(500, why)
}

/// `HEAD`/`GET /containers/{id}/archive?path=P`: the stat of P in `X-Docker-Container-Path-Stat`
/// (what `docker cp` reads to know a file from a directory), and for `GET` P as a tar, streamed from
/// `kern cp <box>:P -`, which resolves P inside the box and never follows a link out of it.
fn archive_get(bin: &Path, req: &Request, id: &str, head: bool) -> Response {
    let Some(path) = req.param("path").filter(|p| !p.is_empty()) else {
        return error(400, "path is required");
    };
    let Some(name) = resolve(bin, id) else {
        return error(404, &format!("No such container: {id}"));
    };
    if created_get(&name).is_some() {
        return error(
            409,
            &format!("Container {id} is created and not started: kern copies out of a running box"),
        );
    }
    let stat = match path_stat(bin, &name, path) {
        Ok(s) => s,
        Err(why) => return copy_refusal(id, path, &why),
    };
    let header = (
        "X-Docker-Container-Path-Stat",
        kern_common::registry_auth::b64_encode(stat.as_bytes()),
    );
    if head {
        return Response::Full {
            status: 200,
            content_type: "application/json",
            body: Vec::new(),
            extra: vec![header],
        };
    }
    let child = Command::new(bin)
        .args(["cp", &format!("{name}:{path}"), "-"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return error(500, &format!("cannot run {}: {e}", bin.display())),
    };
    Response::Stream {
        status: 200,
        content_type: "application/x-tar",
        upgrade: false,
        extra: vec![header],
        writer: Box::new(move |w: &mut crate::Out| {
            if let Some(mut out) = child.stdout.take() {
                let _ = std::io::copy(&mut out, w);
            }
            let _ = child.kill();
            let _ = child.wait();
        }),
    }
}

/// Where the archives a client copies into a CREATED container wait for its start, one directory per
/// container: `$XDG_CACHE_HOME/kern/compat-stage/<name>` (never the runtime dir, whose `kern/` is the
/// registry and is never handed to a box).
fn stage_dir(name: &str) -> Option<std::path::PathBuf> {
    let cache = kern_common::xdg_cache_dir()?;
    valid_name(name).then(|| cache.join("kern").join("compat-stage").join(name))
}

/// The container is gone: its staged archives go with it.
fn stage_forget(name: &str) {
    if let Some(d) = stage_dir(name) {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// A `PUT .../archive` on a container that is CREATED and not started, which is when Testcontainers
/// copies its files (`withCopyToContainer`): Docker writes them into the container's filesystem
/// before its process runs. kern has no box yet, so the archive is kept, and the start hands it to
/// the box as `--copy-in`: extracted into the box's root after its mounts and before its workload,
/// resolved inside the box as `kern cp` resolves a path. Kept until the container is removed, so a
/// restart finds the same files.
fn stage_archive(
    name: &str,
    path: &str,
    r: &mut std::io::BufReader<UnixStream>,
    framing: crate::Framing,
) -> Response {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let Some(dir) = stage_dir(name) else {
        return error(
            500,
            "no cache directory to keep the archive in (HOME is unset)",
        );
    };
    if let Err(e) = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
    {
        return error(500, &format!("{}: {e}", dir.display()));
    }
    let n = std::fs::read_dir(&dir)
        .map(|d| {
            d.flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "tar"))
                .count()
        })
        .unwrap_or(0);
    let tar = dir.join(format!("{n:04}.tar"));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tar);
    let mut file = match file {
        Ok(f) => f,
        Err(e) => return error(500, &format!("{}: {e}", tar.display())),
    };
    match crate::copy_body(r, framing, &mut file) {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            let _ = std::fs::remove_file(&tar);
            return error(500, &format!("{}: {e}", tar.display()));
        }
        Err(why) => {
            let _ = std::fs::remove_file(&tar);
            return error(400, why);
        }
    }
    let dest = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if let Err(e) = std::fs::write(dir.join(format!("{n:04}.tar.dir")), &dest) {
        return error(500, &format!("{}: {e}", dir.display()));
    }
    let Some(mut c) = created_get(name) else {
        return error(
            409,
            &format!("Container {name} started while the archive arrived"),
        );
    };
    let at = c
        .argv
        .iter()
        .position(|a| a == "--image")
        .unwrap_or(c.argv.len());
    c.argv.splice(
        at..at,
        ["--copy-in".to_string(), tar.to_string_lossy().into_owned()],
    );
    created_put(name, c);
    Response::Full {
        status: 200,
        content_type: "text/plain",
        body: Vec::new(),
        extra: Vec::new(),
    }
}

/// `PUT /containers/{id}/archive?path=DIR`: the client's tar, streamed into `kern cp - <box>:DIR`
/// on its stdin (any size; the body is never held here), extracted inside the box.
pub(crate) fn archive_put(
    req: &Request,
    bin: &Path,
    r: &mut std::io::BufReader<UnixStream>,
    framing: crate::Framing,
) -> Response {
    let segs: Vec<String> = req
        .path
        .trim_matches('/')
        .split('/')
        .map(|s| percent_decode(s, false))
        .collect();
    let Some(id) = segs.get(1).cloned() else {
        return error(404, "No such container");
    };
    let Some(path) = req.param("path").filter(|p| !p.is_empty()) else {
        return error(400, "path is required");
    };
    let Some(name) = resolve(bin, &id) else {
        return error(404, &format!("No such container: {id}"));
    };
    if created_get(&name).is_some() {
        return stage_archive(&name, path, r, framing);
    }
    let child = Command::new(bin)
        .args(["cp", "-", &format!("{name}:{path}")])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return error(500, &format!("cannot run {}: {e}", bin.display())),
    };
    let err = child.stderr.take().map(|mut p| {
        std::thread::spawn(move || {
            let mut v = Vec::new();
            let _ = p.read_to_end(&mut v);
            v
        })
    });
    let copied = match child.stdin.take() {
        Some(mut sin) => crate::copy_body(r, framing, &mut sin),
        None => Err("kern cp took no stdin"),
    };
    let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
    let err = err
        .and_then(|h| h.join().ok())
        .map(|v| String::from_utf8_lossy(&v).into_owned())
        .unwrap_or_default();
    if code != 0 {
        return copy_refusal(&id, path, &kern_error(&err));
    }
    if let Err(why) = copied {
        return error(400, why);
    }
    Response::Full {
        status: 200,
        content_type: "text/plain",
        body: Vec::new(),
        extra: Vec::new(),
    }
}

/// `POST /images/load`: the archive the client sends, streamed into `kern load` on its stdin, so an
/// image of any size is loaded without the body being held here. Docker's answer is a JSON line per
/// loaded image (`Loaded image: <name>`), with `quiet` or without.
pub(crate) fn image_load(
    _req: &Request,
    bin: &Path,
    r: &mut std::io::BufReader<UnixStream>,
    framing: crate::Framing,
) -> Response {
    let child = Command::new(bin)
        .arg("load")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return error(500, &format!("cannot run {}: {e}", bin.display())),
    };
    // Its output read while the body is written, so a load that speaks early cannot fill a pipe
    // and stop reading the body.
    let drain = |p: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut v = Vec::new();
            if let Some(mut p) = p {
                let _ = p.read_to_end(&mut v);
            }
            v
        })
    };
    let out = drain(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err = drain(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let copied = match child.stdin.take() {
        Some(mut sin) => crate::copy_body(r, framing, &mut sin),
        None => Err("kern load took no stdin"),
    };
    let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
    let out = String::from_utf8_lossy(&out.join().unwrap_or_default()).into_owned();
    let err = String::from_utf8_lossy(&err.join().unwrap_or_default()).into_owned();
    if let Err(why) = copied {
        return error(400, why);
    }
    if code != 0 {
        return error(500, &kern_error(&err));
    }
    let lines: Vec<String> = out
        .lines()
        .chain(err.lines())
        .filter_map(|l| l.trim().strip_prefix("loaded '")?.strip_suffix('\''))
        .map(|name| {
            format!(
                "{{\"stream\":{}}}\n",
                json_str(&format!("Loaded image: {name}\n"))
            )
        })
        .collect();
    Response::Full {
        status: 200,
        content_type: "application/json",
        body: lines.concat().into_bytes(),
        extra: Vec::new(),
    }
}

/// `DELETE /images/{name}`: `kern rmi`, `force` as `-f`. Docker's answer lists what went: the tag,
/// then the image. An image a container uses is 409 without `force`, as Docker answers it.
fn image_remove(bin: &Path, name: &str, req: &Request) -> Response {
    let Some(i) = cached_image(bin, name) else {
        return error(404, &format!("No such image: {name}"));
    };
    let n = i.get("image").and_then(Value::as_str).unwrap_or(name);
    let mut args = vec!["rmi"];
    if req.flag("force") {
        args.push("-f");
    }
    args.push(n);
    let (code, _out, err) = kern(bin, &args);
    if code != 0 {
        let msg = kern_error(&err);
        return error(
            if msg.starts_with("conflict:") {
                409
            } else {
                500
            },
            &msg,
        );
    }
    json_response(
        200,
        format!(
            "[{{\"Untagged\":{}}},{{\"Deleted\":{}}}]",
            json_str(n),
            json_str(&format!("sha256:{}", id_of(n)))
        ),
    )
}

/// `GET /images/{name}/json`.
fn image_inspect(bin: &Path, name: &str) -> Response {
    let Some(i) = cached_image(bin, name) else {
        return error(404, &format!("No such image: {name}"));
    };
    let n = i.get("image").and_then(Value::as_str).unwrap_or(name);
    // `kern inspect --json` of the image is already Docker's shape (`RepoTags`, `Os`,
    // `Architecture`, `Size`, and the `Config` Dev Containers reads its `User` from); this adds what
    // the API has besides. Asked by the cache's own name, which always carries a `:tag` or an
    // `@digest`, so a running box with the image's bare name is never the one answered.
    let (code, out, err) = kern(bin, &["inspect", "--json", n]);
    match image_object_members(&out) {
        Some(members) if code == 0 => json_response(
            200,
            format!(
                // `RepoDigests` is in kern's own object, with the tags.
                "{{\"Id\":{},\"Created\":{},{members}}}",
                json_str(&format!("sha256:{}", id_of(n))),
                json_str(&rfc3339(
                    i.get("pulled").and_then(Value::as_i64).unwrap_or(0).max(0) as u64
                )),
            ),
        ),
        _ => error(500, &kern_error(&err)),
    }
}

/// The members of the one object `kern inspect --json <image>` prints (`[{...}]`), as text to
/// splice into the API's object, after checking that the whole is that shape and nothing else.
fn image_object_members(out: &str) -> Option<&str> {
    let out = out.trim();
    let one = json::parse(out).ok()?;
    let [obj] = one.as_array()? else {
        return None;
    };
    obj.as_object()?;
    out.strip_prefix('[')?
        .strip_suffix(']')?
        .trim()
        .strip_prefix('{')?
        .strip_suffix('}')
        .map(str::trim)
        .filter(|m| !m.is_empty())
}

fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

fn version() -> Response {
    json_response(
        200,
        format!(
            "{{\"Platform\":{{\"Name\":\"kern\"}},\"Components\":[{{\"Name\":\"kern\",\"Version\":{v}}}],\"Version\":\"{ENGINE_VERSION}\",\"ApiVersion\":\"{API_VERSION}\",\"MinAPIVersion\":\"{MIN_API_VERSION}\",\"Os\":\"linux\",\"Arch\":{},\"KernelVersion\":{},\"GitCommit\":\"\",\"GoVersion\":\"\",\"BuildTime\":\"\"}}",
            json_str(arch()),
            json_str(&kernel_release()),
            v = json_str(kern_common::VERSION)
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
    let running = boxes.iter().filter(|(_, v)| box_running(v)).count();
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
            "{{\"ID\":\"kern\",\"Containers\":{},\"ContainersRunning\":{running},\"ContainersPaused\":0,\"ContainersStopped\":{},\"Images\":0,\"Driver\":\"overlay\",\"OperatingSystem\":\"kern\",\"OSType\":\"linux\",\"Architecture\":{},\"NCPU\":{ncpu},\"MemTotal\":{mem_total},\"Name\":\"kern\",\"ServerVersion\":\"{ENGINE_VERSION}\",\"KernelVersion\":{},\"Labels\":[],\"SecurityOptions\":[\"name=seccomp\",\"name=rootless\"]}}",
            boxes.len(),
            boxes.len() - running,
            json_str(std::env::consts::ARCH),
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

/// The label Testcontainers puts on every container of one test run, in its two spellings:
/// `session-id` from Node, Python and .NET, `sessionId` from Java and Go. With only the first, a
/// Java run's containers were never filed, and outlived a crashed JVM.
const SESSION_LABELS: [&str; 2] = [
    "org.testcontainers.session-id",
    "org.testcontainers.sessionId",
];

/// Whether `labels` mark a container of a Testcontainers run.
fn in_session(labels: &[(String, String)]) -> bool {
    labels
        .iter()
        .any(|(k, _)| SESSION_LABELS.contains(&k.as_str()))
}

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
    stage_forget(name);
    if created_take(name).is_some() {
        drop(attached_take(name));
        return;
    }
    run_forget(name);
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

/// What a start hands the attach waiting for it.
enum Started {
    /// The box runs detached and the attach follows its log. Dropping this sender, once the log
    /// has been followed to its end, tells the run that its output has been read (a `--rm` box is
    /// removed only then).
    Detached(mpsc::Sender<()>),
    /// The box runs in the foreground, its stdio the attach's: `docker run -i` (the attach's bytes
    /// are its stdin) or `-t` (a terminal, one raw stream).
    Foreground {
        stdin: Option<std::process::ChildStdin>,
        out: Option<ChildStdout>,
        err: Option<ChildStderr>,
        tty: bool,
    },
}

/// The attaches waiting for their container's start.
static ATTACHED: Mutex<Option<HashMap<String, mpsc::Sender<Started>>>> = Mutex::new(None);

fn attached_take(name: &str) -> Option<mpsc::Sender<Started>> {
    ATTACHED
        .lock()
        .ok()
        .and_then(|mut g| g.as_mut().and_then(|m| m.remove(name)))
}

/// A box this server started for an attach (`docker run` without `-d`): the exit code for `wait`
/// (also for a `--rm` box, which is gone), and for a box without `--rm` what `inspect`, `ps -a`
/// and `rm` need once it has ended.
#[derive(Clone)]
struct Run {
    created: Created,
    exit: Option<i32>,
    finished: u64,
}

static RUNS: Mutex<Option<HashMap<String, Run>>> = Mutex::new(None);

/// Woken each time a box started for an attach ends.
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

/// Whether a box this server started for an attach is still running. The box does not depend on
/// this process, but what follows its end does: the exit code `wait` answers, the `die` event, and
/// the removal of a `--rm` one; so the server does not leave on idle while one runs.
pub(crate) fn runs_alive() -> bool {
    RUNS.lock().ok().is_some_and(|g| {
        g.as_ref()
            .is_some_and(|m| m.values().any(|r| r.exit.is_none()))
    })
}

fn run_forget(name: &str) {
    if let Ok(mut g) = RUNS.lock() {
        if let Some(m) = g.as_mut() {
            m.remove(name);
        }
    }
}

/// The exit code of `name` if this server started it for an attach, waiting for its end; `None`
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
        extra: Vec::new(),
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

/// `POST /containers/{id}/attach`: kern's log of the box, followed, in Docker's frames with stdout
/// and stderr apart (`--log-streams`). Before the start (as `docker run` does it), from the box's
/// first byte, once the start has said the box runs; after it, from now on unless `logs=1`.
fn attach(bin: &Path, name: &str, req: &Request) -> Response {
    // Both streams unless the client named its own: an attach that asks for neither is how the
    // CLI's older clients spoke, and it always meant both.
    let wanted = match (req.flag("stdout"), req.flag("stderr")) {
        (false, false) => (true, true),
        named => named,
    };
    if let Some(created) = created_get(name) {
        let (to, from) = mpsc::channel::<Started>();
        match ATTACHED.lock() {
            Ok(mut g) => {
                g.get_or_insert_with(HashMap::new)
                    .insert(name.to_string(), to);
            }
            Err(_) => return error(500, "the attach table is unusable"),
        }
        let (bin, name) = (bin.to_path_buf(), name.to_string());
        return Response::Stream {
            status: 200,
            // A terminal is one raw stream, as Docker sends it to a `-t` client.
            content_type: if created.tty {
                "application/vnd.docker.raw-stream"
            } else {
                "application/vnd.docker.multiplexed-stream"
            },
            upgrade: req.upgrade,
            extra: Vec::new(),
            writer: Box::new(move |w: &mut crate::Out| {
                // Ends without a word when the container is removed instead of started.
                match from.recv() {
                    Ok(Started::Detached(done)) => {
                        kern_frames(&bin, &["logs", "--frames", "-f", &name], w, wanted);
                        drop(done);
                    }
                    Ok(Started::Foreground {
                        stdin,
                        out,
                        err,
                        tty,
                    }) => {
                        let feeder = stdin.and_then(|sin| feed_stdin(w, sin));
                        pump(w, out, err, tty);
                        end_feed(w, feeder);
                    }
                    Err(_) => {}
                }
            }),
        };
    }
    // From now on, unless the client asked for what was logged before (`logs=1`).
    let from_now = !req.flag("logs");
    let (bin, name) = (bin.to_path_buf(), name.to_string());
    Response::Stream {
        status: 200,
        content_type: "application/vnd.docker.multiplexed-stream",
        upgrade: req.upgrade,
        extra: Vec::new(),
        writer: Box::new(move |w: &mut crate::Out| {
            let mut args = vec!["logs", "--frames", "-f"];
            if from_now {
                args.extend(["--tail", "0"]);
            }
            args.push(&name);
            kern_frames(&bin, &args, w, wanted);
        }),
    }
}

/// Run `kern <args>` (a `logs --frames` command) and forward its frames onto `w`, the streams in
/// `wanted` only, until it ends; killed when the client goes away first.
fn kern_frames(bin: &Path, args: &[&str], w: &mut crate::Out, wanted: (bool, bool)) {
    let Ok(mut child) = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return;
    };
    if let Some(out) = child.stdout.take() {
        if !copy_frames(out, w, wanted) {
            let _ = child.kill();
        }
    }
    let _ = child.wait();
}

/// Start a created container that an attach waits on (`docker run` without `-d`), and tell the
/// attach to follow it.
///
/// DETACHED, like every other container: it used to run in the foreground as this server's child,
/// and so ended with this server (stopping it, a crash, an upgrade) while Docker's outlives its client.
/// Its stdout and stderr are its log's, apart (`--log-streams`), and the attach follows that log
/// from its first byte; the exit code comes from `kern wait`. Both wake when the box leaves the
/// registry, not on a timer, so a command that ends at once pays no poll interval.
///
/// `--rm` IS KERN'S, as for every other container: it keeps the log for the follow for a while after
/// the box has gone (`registry::set_box_exit_removed`), so a box that ends at once cannot be gone
/// before the follow opened it, and no removal is left to this server, which may not be there to do
/// it when the box ends.
fn start_attached(bin: &Path, name: &str, c: &Created, to: mpsc::Sender<Started>) -> Response {
    let argv: Vec<&str> = c.argv.iter().map(String::as_str).collect();
    if let Err(e) = start_detached(bin, name, c, &argv) {
        run_end(name, 125);
        return e;
    }
    // The attach may have gone: then `done` is dropped at once, and nothing waits on it.
    let (done, read) = mpsc::channel::<()>();
    let _ = to.send(Started::Detached(done));
    let (bin, watched, created) = (bin.to_path_buf(), name.to_string(), c.clone());
    let reaper = std::thread::Builder::new()
        .name("kern-serve-run".into())
        .spawn(move || {
            // THE FOLLOW ENDS WHEN THE BOX DOES, so it is waited for first and the one `kern
            // wait` after it answers at once from the exit record, instead of a second `kern`
            // resident for the box's life. Bounded: past it (a long run, or a client that keeps
            // the connection and stops reading) the `kern wait` is the one that waits.
            let _ = read.recv_timeout(FOLLOW_FIRST);
            // A `--rm` box has gone by now, so its code is the one its hidden record keeps, which
            // `kern wait` does not read (a late wait finds no box, as Docker's does). MEASURED
            // before: `docker run --rm alpine sh -c 'exit 7'` answered 255.
            let code = if created.auto_remove {
                kern_wait_code_with(&bin, "__wait-removed", &watched)
            } else {
                kern_wait_code(&bin, &watched)
            };
            crate::events::publish(&event_of("die", &watched, &created, Some(code)));
            run_end(&watched, code);
        });
    if reaper.is_err() {
        run_end(name, -1);
    }
    no_content()
}

/// Start a created container that an attach waits on WITH ITS STDIN OR A TERMINAL (`docker run -i`,
/// `-t`, `-it`): in the foreground, its stdio the attach's. A detached box's stdin is `/dev/null`
/// and its output a log, so neither reaches it there. MEASURED before: `echo x | docker run -i
/// alpine cat` printed nothing and exited 0 (the stdin dropped in silence), and `docker run -t`
/// printed the frame headers, because the client of a terminal reads one raw stream.
///
/// THE PRICE: a foreground box is this server's child and ends with it, as a terminal ends the
/// command it runs. A container run with neither stays detached (see [`start_attached`]).
fn start_foreground(bin: &Path, name: &str, c: &Created, to: mpsc::Sender<Started>) -> Response {
    // `box <name> -d --log-streams ...` -> `box <name> -q [-t|-i] ...`: in the foreground, with no
    // status line in the client's stderr.
    let mut argv: Vec<String> = without_flags(&c.argv, &["-d", "--log-streams"])
        .into_iter()
        .map(str::to_string)
        .collect();
    let mut extra = vec!["-q".to_string()];
    if c.tty {
        extra.push("-t".into());
    } else if c.stdin {
        extra.push("-i".into());
    }
    let at = argv.len().min(2);
    argv.splice(at..at, extra);
    let mut child = match Command::new(bin)
        .args(&argv)
        .stdin(if c.stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        })
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
    let _ = to.send(Started::Foreground {
        stdin: child.stdin.take(),
        out: child.stdout.take(),
        err: child.stderr.take(),
        tty: c.tty,
    });
    crate::events::publish(&event_of("start", name, c, None));
    let (watched, created) = (name.to_string(), c.clone());
    let reaper = std::thread::Builder::new()
        .name("kern-serve-run".into())
        .spawn(move || {
            let code = exit_code(&mut child);
            crate::events::publish(&event_of("die", &watched, &created, Some(code)));
            run_end(&watched, code);
        });
    if reaper.is_err() {
        run_end(name, -1);
    }
    no_content()
}

/// How long a run's end is left to its attach's follow before `kern wait` waits for it.
const FOLLOW_FIRST: Duration = Duration::from_secs(60);

/// `kern box -d` of a created container, which returns once the box has started, and its `start`
/// event. The `Err` is the answer to give.
fn start_detached(bin: &Path, name: &str, c: &Created, argv: &[&str]) -> Result<(), Response> {
    let (code, _, err) = kern(bin, argv);
    if code != 0 {
        return Err(error(500, &kern_error(&err)));
    }
    crate::events::publish(&event_of("start", name, c, None));
    Ok(())
}

/// A `kern box` argv without the valueless flags `drop`, which stand among the flags (before the
/// workload's `--`) and nowhere else: a workload argument spelled the same is the workload's.
fn without_flags<'a>(argv: &'a [String], drop: &[&str]) -> Vec<&'a str> {
    let mut out = Vec::with_capacity(argv.len());
    let mut in_flags = true;
    for a in argv {
        if in_flags && a == "--" {
            in_flags = false;
        } else if in_flags && drop.contains(&a.as_str()) {
            continue;
        }
        out.push(a.as_str());
    }
    out
}

/// The exit code of `name` from `kern wait`, -1 when it says none.
fn kern_wait_code(bin: &Path, name: &str) -> i32 {
    kern_wait_code_with(bin, "wait", name)
}

/// The exit code of `name` from the waiting verb `verb` (`wait`, or `__wait-removed` for a box that
/// removed itself), -1 when it says none.
fn kern_wait_code_with(bin: &Path, verb: &str, name: &str) -> i32 {
    let (_, out, _) = kern(bin, &[verb, name]);
    out.trim().parse().unwrap_or(-1)
}

/// `docker start` of a container that has run already. Running: `running`, Docker's 304. Stopped
/// with its layer kept: `kern start`, the recorded command on the same files, detached as
/// `docker start` is. Stopped without one (it removed itself, or a Testcontainers run made it):
/// there is nothing to run it on, and the answer says so. It was a 304 for every one of these,
/// which told a client that a stopped container had started, and Dev Containers, which starts its
/// stopped container at every reopen, then found it not running.
fn start_again(bin: &Path, name: &str, running: Response) -> Response {
    let Some(v) = kern_boxes(bin)
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v)
    else {
        return error(404, &format!("No such container: {name}"));
    };
    if box_running(&v) {
        return running;
    }
    if v.get("status").and_then(Value::as_str) != Some("kept") {
        return error(
            500,
            &format!(
                "container {name} has exited and kern kept no filesystem for it (it removed itself, or a Testcontainers run made it): create it again"
            ),
        );
    }
    let (code, _, err) = kern(bin, &["start", name]);
    if code != 0 {
        return error(500, &kern_error(&err));
    }
    // An attached run's record would answer a `wait` with the run before this one.
    run_forget(name);
    crate::events::publish(&crate::events::Event {
        action: "start",
        name: name.to_string(),
        image: v
            .get("image")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        labels: labels_of(&v),
        exit: None,
    });
    no_content()
}

/// The event of a container this server made.
fn event_of(
    action: &'static str,
    name: &str,
    c: &Created,
    exit: Option<i32>,
) -> crate::events::Event {
    crate::events::Event {
        action,
        name: name.to_string(),
        image: c.image.clone(),
        labels: c.labels.clone(),
        exit,
    }
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
    /// `AttachStdin`: the client's bytes on the hijacked connection are the command's stdin.
    stdin: bool,
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
    let stdin = body.get("AttachStdin").and_then(Value::as_bool) == Some(true);
    let mut argv: Vec<String> = vec!["exec".into()];
    if tty {
        argv.push("-t".into());
    }
    if stdin {
        argv.push("-i".into());
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
                    stdin,
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
    // Stdin travels only on a hijacked connection: on a plain HTTP answer the client has no way to
    // send it, and the command gets none, as before.
    let stdin = e.stdin && req.upgrade;
    if stdin {
        cmd.stdin(Stdio::piped());
    }
    let tty = e.tty;
    Response::Stream {
        status: 200,
        content_type: if tty {
            "application/vnd.docker.raw-stream"
        } else {
            "application/vnd.docker.multiplexed-stream"
        },
        upgrade: req.upgrade,
        extra: Vec::new(),
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
            let feeder = child.stdin.take().and_then(|sin| feed_stdin(w, sin));
            pump(w, out, err, tty);
            // The exit is recorded BEFORE the feeder ends: a client that has read the end of the
            // output asks for the code at once, and the feeder may wait for that client to go.
            exec_finish(&id, exit_code(&mut child));
            end_feed(w, feeder);
        }),
    }
}

/// Copy the client's bytes on the hijacked connection to the command's stdin until the client
/// closes its sending side (`CloseWrite`), which is the command's end of input. The connection's
/// read timeout is for requests: an interactive shell's stdin may stay quiet for hours, so a
/// timeout here is waiting, not an end.
fn feed_stdin(w: &mut crate::Out, sin: std::process::ChildStdin) -> Option<Feeder> {
    let mut sock = w.socket().try_clone().ok()?;
    let early = w.take_input();
    let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen_end = Arc::clone(&ended);
    let handle = std::thread::Builder::new()
        .name("kern-serve-stdin".into())
        .spawn(move || {
            // `None` once the workload stopped reading its stdin: what the client still sends is
            // read and dropped, so the connection is not closed under it (see [`end_feed`]).
            let mut sink = Some(sin);
            if !early.is_empty() && sink.as_mut().is_some_and(|s| s.write_all(&early).is_err()) {
                sink = None;
            }
            let mut buf = [0u8; 16 * 1024];
            let mut ended_at: Option<std::time::Instant> = None;
            loop {
                match sock.read(&mut buf) {
                    Ok(0) => return,
                    Ok(n) => {
                        if sink
                            .as_mut()
                            .is_some_and(|s| s.write_all(&buf[..n]).is_err())
                        {
                            sink = None;
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => return,
                }
                if seen_end.load(Ordering::Acquire) {
                    let at = *ended_at.get_or_insert_with(std::time::Instant::now);
                    if at.elapsed() >= DRAIN {
                        return;
                    }
                }
            }
        })
        .ok()?;
    Some(Feeder { handle, ended })
}

/// The thread carrying a client's stdin to a workload, and the flag that says the workload ended.
struct Feeder {
    handle: std::thread::JoinHandle<()>,
    ended: Arc<std::sync::atomic::AtomicBool>,
}

/// The longest a connection is held after the output ended, for its client to hang up.
const DRAIN: Duration = Duration::from_secs(2);

/// The workload is done and its output sent: stop the feeder, the one way for every caller.
///
/// ⛔ NOT BY CLOSING UNDER THE CLIENT. MEASURED: `head -c 20M /dev/zero | docker exec -i c true`
/// exited 1 with "connection reset by peer" where Docker exits 0. `true` reads none of its stdin,
/// the client was still sending it, and a socket closed with bytes unread resets the connection
/// before the client reads the end of the output. On a handed-over connection the end of the output
/// is sent first (our side closed for writing), and what the client still sends is dropped until
/// it hangs up, which it does once it has read that end; [`DRAIN`] bounds a client that does not.
/// A chunked answer has more to write after this (its last chunk), so there the feeder is only
/// woken, as before.
fn end_feed(w: &mut crate::Out, feeder: Option<Feeder>) {
    let Some(f) = feeder else {
        return;
    };
    if w.hijacked() {
        let _ = w.flush();
        let _ = w.socket().shutdown(std::net::Shutdown::Write);
        f.ended.store(true, Ordering::Release);
        let _ = w
            .socket()
            .set_read_timeout(Some(Duration::from_millis(100)));
    } else {
        let _ = w.socket().shutdown(std::net::Shutdown::Read);
    }
    let _ = f.handle.join();
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
            "{{\"ID\":{},\"Running\":{},\"ExitCode\":{},\"ProcessConfig\":{{\"tty\":{},\"entrypoint\":{},\"arguments\":{},\"privileged\":false}},\"OpenStdin\":{},\"OpenStderr\":true,\"OpenStdout\":true,\"CanRemove\":false,\"ContainerID\":{},\"Pid\":0}}",
            json_str(id),
            e.running,
            e.exit.map_or_else(|| "null".to_string(), |c| c.to_string()),
            e.tty,
            json_str(&entry),
            str_array(&args),
            e.stdin,
            json_str(&id_of(&e.name))
        ),
    )
}

// ---------------------------------------------------------------------------------------------
// Routing.

/// `POST /{networks,volumes,images}/prune` with a `label` filter, which is how Testcontainers'
/// reaper ends a session when Ryuk is off: what it prunes is what that session made, and this API
/// makes no network, no volume and no image (build is not translated, a pull carries no client
/// label), so nothing matches and the answer is Docker's empty one. A prune without a label
/// filter would reach kern's own networks and volumes, which this API does not translate.
fn labelled_prune(kind: &str, req: &Request) -> Response {
    let labelled = req
        .param("filters")
        .and_then(|f| json::parse(f).ok())
        .is_some_and(|f| !filter_values(&f, "label").is_empty());
    if !labelled {
        return not_translated(&format!("{kind} prune without a label filter"));
    }
    let body = match kind {
        "networks" => "{\"NetworksDeleted\":[]}",
        "volumes" => "{\"VolumesDeleted\":[],\"SpaceReclaimed\":0}",
        _ => "{\"ImagesDeleted\":[],\"SpaceReclaimed\":0}",
    };
    json_response(200, body.to_string())
}

/// 501 for an endpoint this API does not serve, saying what does the job instead. MEASURED: `docker
/// compose up` through the socket stopped at its first `networks` call with "not translated by
/// kern-serve in this phase", which names an internal server and leaves the reader nowhere to go.
fn not_translated(what: &str) -> Response {
    let instead = if what.starts_with("networks") || what.starts_with("the volumes") {
        "; a compose file runs with `kern compose -f <file> up`, which makes its networks and volumes"
    } else if what == "build" {
        "; `kern build` builds the same Dockerfile"
    } else {
        ""
    };
    error(
        501,
        &format!(
            "{what}: not served by kern's Docker API, which never hands a request to a Docker \
             engine{instead}"
        ),
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
            let platform = match req.param("platform").filter(|p| !p.is_empty()) {
                Some(p) if valid_platform(p) => Some(p.to_string()),
                Some(p) => return error(400, &format!("invalid platform: {p:?}")),
                None => None,
            };
            match create_argv(&name, &body).map(|c| with_platform(c, platform.as_deref())) {
                Ok(c) => {
                    let session = in_session(&c.labels);
                    crate::events::publish(&event_of("create", &name, &c, None));
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
            // Started before: running is Docker's 304, stopped is a start again.
            let Some(c) = created_get(&name) else {
                return start_again(bin, &name, not_modified());
            };
            if !start_claim(&name) {
                return not_modified();
            }
            let resp = match attached_take(&name) {
                Some(to) => {
                    run_begin(&name, &c);
                    if c.stdin || c.tty {
                        start_foreground(bin, &name, &c, to)
                    } else {
                        start_attached(bin, &name, &c, to)
                    }
                }
                None => {
                    let argv: Vec<&str> = c.argv.iter().map(String::as_str).collect();
                    match start_detached(bin, &name, &c, &argv) {
                        Ok(()) => no_content(),
                        Err(e) => e,
                    }
                }
            };
            // The container leaves CREATED only once kern runs it: `docker run` asked for its
            // wait before the start, and a wait woken earlier would find no box. A start that
            // failed leaves it created, as Docker does.
            if matches!(resp, Response::Full { status: 204, .. }) {
                drop(created_take(&name));
            } else if c.auto_remove {
                // EXCEPT ONE WITH `--rm`, which Docker removes when its start fails, and its
                // client waits for that removal before it reports the error: MEASURED before,
                // `docker run --rm` with a start that failed hung for good (its wait never woke),
                // while `docker run -d` answered 125 at once.
                // Its wait, woken by the removal, answers the 125 from a run recorded first (a
                // `docker run -d --rm` has none, and its wait printed kern's "no running box").
                run_begin(&name, &c);
                run_end(&name, 125);
                session_forget(&name);
                drop(created_take(&name));
                drop(attached_take(&name));
                let _ = kern(bin, &["rm", "-f", &name]);
            }
            start_release(&name);
            resp
        }
        ("GET", ["containers", id, "json"]) => match resolve(bin, id) {
            Some(name) => inspect(bin, &name),
            None => error(404, &format!("No such container: {id}")),
        },
        ("GET" | "HEAD", ["containers", id, "archive"]) => {
            archive_get(bin, req, id, req.method == "HEAD")
        }
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
                // A created container does not run: Docker's `kill` answers 409 (and the CLI exits
                // 1), its `stop` and `restart` 304. MEASURED before: `docker kill` of one exited 0.
                if *verb == "kill" {
                    return error(409, &format!("Container {name} is not running"));
                }
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
            // `kill?signal=HUP` is `kern kill -s HUP`: the signal to the init. Without one it is the
            // kill with no grace, as Docker's. MEASURED before: the signal was ignored and the kill
            // waited the box's grace (10 s for a workload that traps SIGTERM).
            let signal = req
                .param("signal")
                .filter(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric()))
                .unwrap_or("KILL")
                .to_string();
            let args: Vec<&str> = match *verb {
                "kill" => vec!["kill", "-s", &signal, &name],
                "restart" => vec!["restart", "-t", &t, &name],
                _ => vec!["stop", "-t", &t, &name],
            };
            let (code, _, err) = kern(bin, &args);
            if code == 0 {
                no_content()
            } else if *verb == "kill" && err.contains("no running box") {
                // Docker's answer to a kill of a container that does not run: 409, not 304.
                error(409, &format!("Container {name} is not running"))
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
            stage_forget(&name);
            if created_take(&name).is_some() {
                // A pending attach ends with the container.
                drop(attached_take(&name));
                // A start that failed may have left kern a box under this name (a kept layer, an
                // exit record): removed with the container, or `ps -a` keeps showing it.
                let _ = kern(bin, &["rm", "-f", &name]);
                return no_content();
            }
            // An attached run that ended: forgotten here, and its kept layer, if it has one, is
            // removed below like any other container's.
            run_forget(&name);
            let force = req.flag("force");
            let running = kern_boxes(bin)
                .into_iter()
                .any(|(n, v)| n == name && box_running(&v));
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
        ("GET", ["images", "json"]) => image_list(bin, req),
        ("GET", ["images", rest @ .., "json"]) if !rest.is_empty() => {
            image_inspect(bin, &rest.join("/"))
        }
        ("GET", ["images", rest @ .., "history"]) if !rest.is_empty() => {
            image_history(bin, &rest.join("/"))
        }
        ("DELETE", ["images", rest @ ..]) if !rest.is_empty() => {
            image_remove(bin, &rest.join("/"), req)
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
        ("POST", [kind @ ("networks" | "volumes" | "images"), "prune"]) => {
            labelled_prune(kind, req)
        }
        (_, ["networks", ..]) => not_translated("networks"),
        (_, ["volumes", ..]) => not_translated("the volumes API"),
        ("GET", ["events"]) => crate::events::events(req),
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

    /// The tests that drive `handle` through a fake `kern` take this, so no two write one at once.
    static FAKE_KERN: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A fake `kern` at `dir/kern` running `script`, ready to exec. MEASURED: a script written while
    /// another test thread forked failed to start with ETXTBSY (the child held the write fd for an
    /// instant), only in a parallel run; the exec is retried here until the file is free.
    fn fake_kern(dir: &Path, script: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::create_dir_all(dir);
        let bin = dir.join("kern");
        assert!(std::fs::write(&bin, script).is_ok());
        assert!(std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).is_ok());
        for _ in 0..200 {
            match Command::new(&bin).arg("__probe").output() {
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                _ => break,
            }
        }
        bin
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

    /// `docker run --platform linux/arm64` sends `?platform=` to the create (and to the pull): it
    /// was not read, so the container ran this machine's image and said nothing.
    #[test]
    fn a_create_platform_becomes_box_platform_before_the_image() {
        let b = body(r#"{"Image":"alpine:3.20","Cmd":["uname","-m"]}"#);
        let argv = create_argv("n", &b)
            .map(|c| with_platform(c, Some("linux/arm64")).argv)
            .unwrap_or_default();
        let at = argv.iter().position(|a| a == "--platform");
        let img = argv.iter().position(|a| a == "--image");
        assert!(
            matches!((at, img), (Some(a), Some(i)) if a < i && argv[a + 1] == "linux/arm64"),
            "{argv:?}"
        );
        let plain = create_argv("n", &b).map(|c| with_platform(c, None).argv);
        assert!(plain.is_ok_and(|a| !a.iter().any(|x| x == "--platform")));
        for ok in ["linux/arm64", "linux/arm/v7", "linux/amd64"] {
            assert!(valid_platform(ok), "{ok}");
        }
        for bad in [
            "",
            "arm64",
            "-x/y",
            "/x",
            "linux/ARM64",
            "linux/a b",
            "linux/a;rm",
        ] {
            assert!(!valid_platform(bad), "{bad}");
        }
    }

    #[test]
    fn a_testcontainers_create_becomes_one_kern_box() {
        let b = body(
            r#"{"Image":"nginx:alpine","Cmd":["nginx","-g","daemon off;"],"Env":["A=1"],
            "ExposedPorts":{"80/tcp":{}},"Labels":{"org.testcontainers":"true","org.testcontainers.sessionId":"s1"},
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
                "-l",
                "org.testcontainers.sessionId=s1",
                "-p",
                ":80/tcp",
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

    /// A start that kern refuses (MEASURED: an unreadable cache dir) answers its error, and the
    /// client's wait is not left hanging: a `--rm` container is removed and its wait answers 125,
    /// as Docker does; one without it stays created, as Docker leaves it.
    #[test]
    fn a_refused_start_removes_a_rm_container_and_wakes_its_wait() {
        let _g = FAKE_KERN.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("kern-compat-refused-{}", std::process::id()));
        let script = "#!/bin/sh\ncase \"$1\" in\n box) echo 'cache dir: Permission denied (os error 13)' >&2; exit 1;;\n ps) echo '[]';;\nesac\nexit 0\n";
        let bin = fake_kern(&dir, script);
        let start = |name: &str| Request {
            method: "POST".into(),
            path: format!("/containers/{name}/start"),
            query: Vec::new(),
            body: Vec::new(),
            upgrade: false,
            peer: None,
            close: false,
        };
        for (name, rm, attached) in [
            ("kd-refused-rm", true, true),
            ("kd-refused-rm-d", true, false),
            ("kd-refused-keep", false, true),
        ] {
            let b = body(&format!(
                r#"{{"Image":"alpine:3.21","Cmd":["true"],"HostConfig":{{"AutoRemove":{rm}}}}}"#
            ));
            let Ok(c) = create_argv(name, &b) else {
                panic!("create {name}")
            };
            assert_eq!(c.auto_remove, rm, "{name}");
            created_put(name, c);
            let from = attached.then(|| {
                let (to, from) = mpsc::channel::<Started>();
                if let Ok(mut g) = ATTACHED.lock() {
                    g.get_or_insert_with(HashMap::new)
                        .insert(name.to_string(), to);
                }
                from
            });
            let Response::Full { status, body, .. } = handle(&start(name), &bin) else {
                panic!("a whole body for {name}");
            };
            assert_eq!(status, 500, "{name}");
            assert!(
                String::from_utf8_lossy(&body).contains("cache dir: Permission denied"),
                "{name}: {}",
                String::from_utf8_lossy(&body)
            );
            // The attach ends without a word.
            if let Some(from) = from {
                assert!(from.recv_timeout(Duration::from_secs(5)).is_err(), "{name}");
            }
            if rm {
                assert!(created_get(name).is_none(), "{name} must be removed");
                let (tx, rx) = mpsc::channel();
                let n = name.to_string();
                std::thread::spawn(move || {
                    wait_until_started(&n);
                    let _ = tx.send(run_exit(&n));
                });
                assert_eq!(
                    rx.recv_timeout(Duration::from_secs(5)),
                    Ok(Some(125)),
                    "{name}: the wait must answer 125 at once"
                );
            } else {
                assert!(created_get(name).is_some(), "{name} must stay created");
                drop(created_take(name));
            }
            run_forget(name);
        }
        let _ = std::fs::remove_file(&bin);
        let _ = std::fs::remove_dir(&dir);
    }

    /// `POST /containers/{id}/kill` is Docker's: `signal` reaches `kern kill -s`, no `signal` is
    /// `KILL` (the kill with no grace), and a container that does not run answers 409, not 304.
    #[test]
    fn a_kill_passes_its_signal_and_a_stopped_one_is_409() {
        let _g = FAKE_KERN.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("kern-compat-kill-{}", std::process::id()));
        let argv_log = dir.join("argv");
        let script = format!(
            "#!/bin/sh\ncase \"$1\" in\n ps) echo '[{{\"name\":\"kd-kill1\",\"status\":\"running\"}}]';;\n \
             kill) echo \"$*\" >> {log}; [ \"$4\" = kd-gone ] && {{ echo \"no running box named 'kd-gone'\" >&2; exit 1; }};;\nesac\nexit 0\n",
            log = argv_log.display()
        );
        let bin = fake_kern(&dir, &script);
        let kill = |id: &str, query: Vec<(String, String)>| Request {
            method: "POST".into(),
            path: format!("/containers/{id}/kill"),
            query,
            body: Vec::new(),
            upgrade: false,
            peer: None,
            close: false,
        };
        let status = |r: Response| match r {
            Response::Full { status, .. } => status,
            _ => 0,
        };
        assert_eq!(
            status(handle(
                &kill("kd-kill1", vec![("signal".into(), "HUP".into())]),
                &bin
            )),
            204
        );
        assert_eq!(status(handle(&kill("kd-kill1", Vec::new()), &bin)), 204);
        let logged = std::fs::read_to_string(&argv_log).unwrap_or_default();
        assert_eq!(logged, "kill -s HUP kd-kill1\nkill -s KILL kd-kill1\n");
        // A name the fake lists as not running: rewrite its listing to include it.
        let script2 = script.replace("kd-kill1", "kd-gone");
        let bin = fake_kern(&dir, &script2);
        assert_eq!(status(handle(&kill("kd-gone", Vec::new()), &bin)), 409);
        // Created and never started: 409 for `kill`, as Docker answers, and still 304 for `stop`.
        let b = body(r#"{"Image":"alpine:3.21","Cmd":["true"]}"#);
        let Ok(c) = create_argv("kd-created", &b) else {
            panic!("create")
        };
        created_put("kd-created", c);
        assert_eq!(status(handle(&kill("kd-created", Vec::new()), &bin)), 409);
        let stop = Request {
            path: "/containers/kd-created/stop".into(),
            ..kill("kd-created", Vec::new())
        };
        assert_eq!(status(handle(&stop, &bin)), 304);
        drop(created_take("kd-created"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `HostConfig.RestartPolicy` is `kern box --restart`, in Docker's names; with `AutoRemove` it
    /// is refused, as Docker refuses it. MEASURED before: the field was not read at all.
    #[test]
    fn a_restart_policy_becomes_kerns_and_one_with_auto_remove_is_refused() {
        let argv = |host: &str| {
            create_argv(
                "kd-r",
                &body(&format!(r#"{{"Image":"x","HostConfig":{host}}}"#)),
            )
            .map(|c| c.argv)
        };
        let restart = |host: &str| {
            argv(host).ok().and_then(|a| {
                a.iter()
                    .position(|x| x == "--restart")
                    .and_then(|i| a.get(i + 1).cloned())
            })
        };
        assert_eq!(
            restart(r#"{"RestartPolicy":{"Name":"on-failure","MaximumRetryCount":2}}"#),
            Some("on-failure:2".into())
        );
        assert_eq!(
            restart(r#"{"RestartPolicy":{"Name":"on-failure","MaximumRetryCount":0}}"#),
            Some("on-failure".into())
        );
        assert_eq!(
            restart(r#"{"RestartPolicy":{"Name":"always"}}"#),
            Some("always".into())
        );
        assert_eq!(
            restart(r#"{"RestartPolicy":{"Name":"unless-stopped"}}"#),
            Some("unless-stopped".into())
        );
        for none in [
            r#"{"RestartPolicy":{"Name":"no"}}"#,
            r#"{"RestartPolicy":{"Name":""}}"#,
            "{}",
        ] {
            assert_eq!(restart(none), None, "{none}");
        }
        assert!(argv(r#"{"AutoRemove":true,"RestartPolicy":{"Name":"always"}}"#).is_err());
        assert!(argv(r#"{"AutoRemove":true,"RestartPolicy":{"Name":"no"}}"#).is_ok());
        assert!(argv(r#"{"RestartPolicy":{"Name":"sometimes"}}"#).is_err());
    }

    /// A container keeps its layer (`--keep`, so `docker start` runs it again on the same files)
    /// unless it removes itself or a Testcontainers run made it, in either label spelling.
    #[test]
    fn a_container_is_kept_unless_it_removes_itself_or_a_test_run_made_it() {
        let argv = |b: &str| {
            create_argv("n", &body(b))
                .map(|c| c.argv)
                .unwrap_or_default()
        };
        let has = |a: &[String], f: &str| a.iter().any(|x| x == f);
        let plain = argv(r#"{"Image":"x","Labels":{"devcontainer.local_folder":"/w"}}"#);
        assert!(has(&plain, "--keep") && !has(&plain, "--rm"));
        let auto = argv(r#"{"Image":"x","HostConfig":{"AutoRemove":true}}"#);
        assert!(has(&auto, "--rm") && !has(&auto, "--keep"));
        for label in [
            "org.testcontainers.session-id",
            "org.testcontainers.sessionId",
        ] {
            let run = argv(&format!(r#"{{"Image":"x","Labels":{{"{label}":"s"}}}}"#));
            assert!(!has(&run, "--keep"), "{label}");
        }
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
            "box n -d --log-streams -p :6379/tcp -v /data:/d:ro --cpus 0.500 --rm --network host --entrypoint /bin/sh --image x -- -c echo hi"
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

    fn list_req(filters: &str) -> Request {
        Request {
            method: "GET".into(),
            path: "/containers/json".into(),
            query: vec![("filters".into(), filters.into())],
            body: Vec::new(),
            upgrade: false,
            peer: None,
            close: false,
        }
    }

    /// The container list's filters. The label filter in its map form (`docker ps --filter`,
    /// Dev Containers) is applied, not dropped: dropped, every box came back and a client took
    /// another user box for its own. A filter not translated, or filters that do not parse, are
    /// refused, never read as "no filter".
    #[test]
    fn list_filters_apply_both_label_forms_and_refuse_what_they_do_not_know() {
        let mine = vec![("devcontainer.local_folder".to_string(), "/w".to_string())];
        let other: Vec<(String, String)> = Vec::new();
        for f in [
            r#"{"label":{"devcontainer.local_folder=/w":true}}"#,
            r#"{"label":["devcontainer.local_folder=/w"]}"#,
        ] {
            let lf = ListFilters::parse(&list_req(f)).unwrap();
            assert!(lf.keeps("mine", "running", &mine), "{f}");
            assert!(!lf.keeps("other", "running", &other), "{f}");
        }
        for bad in [
            r#"{"ancestor":["alpine"]}"#,
            "{not json",
            r#"{"name":["a.*b"]}"#,
        ] {
            assert!(ListFilters::parse(&list_req(bad)).is_err(), "{bad}");
        }
        let by_name = ListFilters::parse(&list_req(r#"{"name":["^web"]}"#)).unwrap();
        assert!(by_name.keeps("web-1", "running", &other));
        assert!(!by_name.keeps("my-web", "running", &other));
        let exact = ListFilters::parse(&list_req(r#"{"name":{"^/web$":true}}"#)).unwrap();
        assert!(exact.keeps("web", "running", &other) && !exact.keeps("web-1", "running", &other));
        let sub = ListFilters::parse(&list_req(r#"{"name":["app.v2"]}"#)).unwrap();
        assert!(sub.keeps("my-app.v2-1", "running", &other));
        let id = id_of("web");
        let by_id =
            ListFilters::parse(&list_req(&format!(r#"{{"id":["{}"]}}"#, &id[..12]))).unwrap();
        assert!(by_id.keeps("web", "running", &other) && !by_id.keeps("db", "running", &other));
        let exited = ListFilters::parse(&list_req(r#"{"status":["exited"]}"#)).unwrap();
        assert!(exited.wants_exited());
        assert!(exited.keeps("x", "exited", &other) && !exited.keeps("x", "running", &other));
        let created = ListFilters::parse(&list_req(r#"{"status":["created"]}"#)).unwrap();
        assert!(created.wants_exited());
        assert!(created.keeps("x", "created", &other) && !created.keeps("x", "exited", &other));
    }

    /// A port binding with no `HostIp` is every address (kern's `-p <host>:<box>`, `0.0.0.0` and
    /// `[::]`), not `0.0.0.0` alone; one with an address keeps it.
    #[test]
    fn an_empty_host_ip_publishes_on_every_address() {
        let b = body(
            r#"{"Image":"x","ExposedPorts":{"80/tcp":{},"81/tcp":{}},
            "HostConfig":{"PortBindings":{"80/tcp":[{"HostIp":"","HostPort":""}],
            "81/tcp":[{"HostIp":"127.0.0.1","HostPort":"9081"}]}}}"#,
        );
        let argv = create_argv("n", &b).map(|c| c.argv).unwrap_or_default();
        assert!(argv.iter().any(|a| a == ":80/tcp"), "{argv:?}");
        assert!(
            argv.iter().any(|a| a == "127.0.0.1:9081:81/tcp"),
            "{argv:?}"
        );
        assert!(!argv.iter().any(|a| a.starts_with("0.0.0.0")), "{argv:?}");
    }

    /// The foreground run drops `-d` and `--log-streams` among the flags only.
    #[test]
    fn without_flags_leaves_the_workloads_arguments_alone() {
        let argv: Vec<String> = [
            "box",
            "n",
            "-d",
            "--log-streams",
            "--image",
            "x",
            "--",
            "nginx",
            "-d",
        ]
        .iter()
        .map(|a| (*a).to_string())
        .collect();
        assert_eq!(
            without_flags(&argv, &["-d", "--log-streams"]),
            ["box", "n", "--image", "x", "--", "nginx", "-d"]
        );
    }

    /// `HostConfig.Mounts` as kern's `--mount`: the workspace bind Dev Containers always sends, a
    /// read-only bind, a named volume, a sized tmpfs; what kern's mount lacks is refused by name.
    #[test]
    fn host_mounts_translate_to_kern_mounts_and_unknown_options_are_refused() {
        let host = |mounts: &str| json::parse(&format!(r#"{{"Mounts":{mounts}}}"#)).unwrap();
        let ok = host(
            r#"[{"Type":"bind","Source":"/tmp","Target":"/workspaces/w","Consistency":"cached"},
                {"Type":"bind","Source":"/etc/hostname","Target":"/h","ReadOnly":true,"BindOptions":{"Propagation":"rprivate"}},
                {"Type":"volume","Source":"cache","Target":"/c"},
                {"Type":"tmpfs","Target":"/t","TmpfsOptions":{"SizeBytes":1048576}}]"#,
        );
        assert_eq!(
            translate_mounts(Some(&ok)).unwrap(),
            vec![
                "type=bind,src=/tmp,dst=/workspaces/w".to_string(),
                "type=bind,src=/etc/hostname,dst=/h,ro".to_string(),
                "type=volume,src=cache,dst=/c".to_string(),
                "type=tmpfs,tmpfs-size=1048576,dst=/t".to_string(),
            ]
        );
        for (bad, says) in [
            (
                r#"[{"Type":"bind","Source":"/tmp","Target":"/w","BindOptions":{"Propagation":"rshared"}}]"#,
                "Propagation",
            ),
            (
                r#"[{"Type":"bind","Source":"/tmp","Target":"/w","BindOptions":{"NonRecursive":true}}]"#,
                "NonRecursive",
            ),
            (
                r#"[{"Type":"bind","Source":"rel","Target":"/w"}]"#,
                "absolute",
            ),
            (
                r#"[{"Type":"bind","Source":"/a,b","Target":"/w"}]"#,
                "comma",
            ),
            (
                r#"[{"Type":"volume","Source":"v","Target":"/w","VolumeOptions":{"DriverConfig":{"Name":"nfs"}}}]"#,
                "DriverConfig",
            ),
            (
                r#"[{"Type":"tmpfs","Target":"/t","TmpfsOptions":{"Mode":448}}]"#,
                "Mode",
            ),
            (r#"[{"Type":"npipe","Source":"x","Target":"/w"}]"#, "Type"),
            (r#"[{"Type":"bind","Source":"/tmp"}]"#, "Target"),
        ] {
            let e = translate_mounts(Some(&host(bad))).unwrap_err();
            assert!(e.contains(says), "{bad}: {e}");
        }
        let defaults = host(
            r#"[{"Type":"bind","Source":"/tmp","Target":"/w","BindOptions":{"NonRecursive":false},"ReadOnly":false}]"#,
        );
        assert_eq!(
            translate_mounts(Some(&defaults)).unwrap(),
            vec!["type=bind,src=/tmp,dst=/w".to_string()]
        );
    }

    /// The image object `kern inspect --json` prints is spliced only when it is exactly one object.
    #[test]
    fn image_object_members_take_one_object_only() {
        let one = r#"[{"RepoTags":["alpine:3.19"],"Config":{"User":null,"Cmd":["/bin/sh"]}}]"#;
        let m = image_object_members(one).unwrap();
        let v = json::parse(&format!(r#"{{"Id":"sha256:x",{m}}}"#)).unwrap();
        assert!(v.get("Config").and_then(|c| c.get("Cmd")).is_some());
        for bad in [
            "",
            "[]",
            "[{}]",
            r#"[{"a":1},{"b":2}]"#,
            r#"{"a":1}"#,
            "[1]",
            "error: x",
        ] {
            assert!(image_object_members(bad).is_none(), "{bad:?}");
        }
    }

    /// A prune filtered by label (Testcontainers' reaper with Ryuk off) answers Docker's empty
    /// result for networks, volumes and images; one without a label filter is still refused.
    #[test]
    fn labelled_prune_is_empty_and_a_bare_prune_is_refused() {
        let req = |query: Vec<(String, String)>| Request {
            method: "POST".into(),
            path: "/networks/prune".into(),
            query,
            body: Vec::new(),
            upgrade: false,
            peer: None,
            close: false,
        };
        let labelled = req(vec![(
            "filters".into(),
            r#"{"label":{"org.testcontainers.sessionId=abc":true}}"#.into(),
        )]);
        for (kind, key) in [
            ("networks", "NetworksDeleted"),
            ("volumes", "VolumesDeleted"),
            ("images", "ImagesDeleted"),
        ] {
            let Response::Full { status, body, .. } = labelled_prune(kind, &labelled) else {
                panic!("a whole body");
            };
            assert_eq!(status, 200, "{kind}");
            let v = json::parse(std::str::from_utf8(&body).unwrap()).unwrap();
            assert_eq!(
                v.get(key).and_then(Value::as_array).map(<[Value]>::len),
                Some(0)
            );
        }
        let Response::Full { status, .. } = labelled_prune("volumes", &req(Vec::new())) else {
            panic!("a whole body");
        };
        assert_eq!(status, 501);
    }

    /// `docker compose` through the socket stops at its first network call: the 501 says what runs
    /// the file instead, and names no internal server.
    #[test]
    fn a_networks_call_is_refused_naming_kern_compose() {
        let req = Request {
            method: "GET".into(),
            path: "/networks".into(),
            query: Vec::new(),
            body: Vec::new(),
            upgrade: false,
            peer: None,
            close: false,
        };
        let Response::Full { status, body, .. } = handle(&req, Path::new("/nonexistent/kern"))
        else {
            panic!("a whole body");
        };
        let text = String::from_utf8_lossy(&body);
        assert_eq!(status, 501, "{text}");
        assert!(text.contains("kern compose -f"), "{text}");
        assert!(!text.contains("kern-serve"), "{text}");
    }

    /// The `reference` filter of `GET /images/json`: a name, a bare name as `:latest`, a repository
    /// for all its tags; a registry port is not a tag; a glob matches nothing.
    #[test]
    fn image_reference_filter_matches_name_latest_and_repository() {
        assert!(reference_matches("alpine:3.19", "alpine:3.19"));
        assert!(reference_matches("alpine:3.19", "alpine"));
        assert!(reference_matches("alpine:latest", "alpine"));
        assert!(!reference_matches("alpine/openssl:latest", "alpine"));
        assert!(reference_matches(
            "localhost:5000/app:1",
            "localhost:5000/app"
        ));
        assert!(!reference_matches("localhost:5000/app:1", "localhost"));
        assert!(!reference_matches("alpine:3.19", "alp*"));
        assert_eq!(repository_of("ghcr.io/o/app@sha256:ab"), "ghcr.io/o/app");
        let f = json::parse(r#"{"reference":{"alpine":true,"busybox":false}}"#).unwrap();
        assert_eq!(filter_values(&f, "reference"), vec!["alpine".to_string()]);
        let f = json::parse(r#"{"reference":["alpine","busybox"]}"#).unwrap();
        assert_eq!(filter_values(&f, "reference").len(), 2);
    }

    /// `/version` says the engine version clients gate on (a dotted number at or above 1.6.0,
    /// which Testcontainers for Java demands) and keeps kern's own in `Components`.
    #[test]
    fn version_reports_the_engine_version_and_kern_in_components() {
        let Response::Full { body, .. } = version() else {
            panic!("version is a whole body");
        };
        let v = json::parse(std::str::from_utf8(&body).unwrap()).unwrap();
        assert_eq!(
            v.get("Version").and_then(Value::as_str),
            Some(ENGINE_VERSION)
        );
        assert!(ENGINE_VERSION.split('.').all(|p| p.parse::<u32>().is_ok()));
        let kern = v
            .get("Components")
            .and_then(Value::as_array)
            .and_then(|c| c.first())
            .and_then(|c| c.get("Version"))
            .and_then(Value::as_str);
        assert_eq!(kern, Some(kern_common::VERSION));
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
