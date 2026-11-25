//! The Docker Engine API endpoints kern-serve translates, each into `kern` commands.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{ChildStderr, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

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

pub(crate) fn json_response(status: u16, body: String) -> Response {
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

pub(crate) fn no_content() -> Response {
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
pub(crate) fn kern(bin: &Path, args: &[&str]) -> (i32, String, String) {
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
pub(crate) fn kern_error(stderr: &str) -> String {
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
    if let Some(id) = renamed_id(name) {
        return id;
    }
    hashed_id(name)
}

/// The id a name hashes to: a container's id unless it was renamed (see [`renamed_id`]).
fn hashed_id(name: &str) -> String {
    let mut out = String::with_capacity(64);
    for round in 0u8..4 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ u64::from(round);
        for b in name.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        out.push_str(&format!("{:016x}", avalanche(h)));
    }
    out
}

/// splitmix64's finalizer: every input bit reaches every output bit. Without it the four rounds
/// above differ only by their seed, and two names one byte apart got ids alike for their first ten
/// hex digits (MEASURED: `g11img:q` 651325dd78c9e69e, `g11img:p` 651326dd78c9e851), which is the
/// part a client shows and matches a prefix against.
fn avalanche(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// THE ID SURVIVES A RENAME, as Docker's does: `docker compose up --force-recreate` creates the new
/// container under a temporary name, removes the old one, renames the new one to the service's name
/// and then STARTS IT BY ITS ID. An id derived from the name changed with the rename, and the start
/// found nothing. So a renamed container keeps the id it had, here, and the name it left is given a
/// fresh one, so a later container under that name is not taken for it. Kept on disk beside the
/// labels (`compat-meta/ids/<name>`): this server exits when idle and the ids must outlive it.
static IDS: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

fn ids_dir() -> Option<std::path::PathBuf> {
    Some(
        kern_common::xdg_cache_dir()?
            .join("kern")
            .join("compat-meta")
            .join("ids"),
    )
}

fn with_ids<T>(f: impl FnOnce(&mut HashMap<String, String>) -> T) -> Option<T> {
    let mut g = IDS.lock().ok()?;
    let m = g.get_or_insert_with(|| {
        let mut m = HashMap::new();
        if let Some(rd) = ids_dir().and_then(|d| std::fs::read_dir(d).ok()) {
            for e in rd.flatten() {
                if let (Some(n), Ok(id)) = (
                    e.file_name().to_str().map(str::to_string),
                    std::fs::read_to_string(e.path()),
                ) {
                    let id = id.trim().to_string();
                    if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
                        m.insert(n, id);
                    }
                }
            }
        }
        m
    });
    Some(f(m))
}

fn renamed_id(name: &str) -> Option<String> {
    with_ids(|m| m.get(name).cloned()).flatten()
}

fn id_set(name: &str, id: &str) {
    use std::os::unix::fs::DirBuilderExt;
    let _ = with_ids(|m| m.insert(name.to_string(), id.to_string()));
    if let Some(d) = ids_dir() {
        if std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&d)
            .is_ok()
        {
            let _ = std::fs::write(d.join(name), id);
        }
    }
}

/// `old` became `new`: `new` keeps `old`'s id, and `old` gets one nobody had.
fn id_rename(old: &str, new: &str) {
    let id = id_of(old);
    id_set(new, &id);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    id_set(old, &hashed_id(&format!("{old}#{nanos}")));
}

/// The container is removed: a later one under its name hashes again.
fn id_forget(name: &str) {
    let _ = with_ids(|m| m.remove(name));
    if let Some(d) = ids_dir() {
        let _ = std::fs::remove_file(d.join(name));
    }
}

/// Rename a container that is CREATED and not started: there is no box yet, so `kern rename` has
/// nothing to act on; what this server keeps for it moves to the new name instead (its argv, the
/// archives copied into it, its aliases).
fn rename_created(name: &str, new: &str) -> Option<Response> {
    let mut c = created_take(name)?;
    if let Some(slot) = c.argv.get_mut(1).filter(|a| a.as_str() == name) {
        *slot = new.to_string();
    }
    if let (Some(from), Some(to)) = (stage_dir(name), stage_dir(new)) {
        if from.is_dir() && std::fs::rename(&from, &to).is_ok() {
            let (f, t) = (
                from.to_string_lossy().into_owned(),
                to.to_string_lossy().into_owned(),
            );
            for a in c.argv.iter_mut() {
                if let Some(rest) = a.strip_prefix(f.as_str()) {
                    *a = format!("{t}{rest}");
                }
            }
        }
    }
    if let Ok(mut g) = NET_ALIASES.lock() {
        if let Some(m) = g.as_mut() {
            if let Some(v) = m.remove(name) {
                m.insert(new.to_string(), v);
            }
        }
    }
    created_put(new, c);
    Some(no_content())
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
pub(crate) fn valid_name(n: &str) -> bool {
    // kern's own rule for a box's name, the one every path it becomes is sized for: up to
    // `BoxName::MAX_LEN`, not 63. MEASURED before: a 128-character name Docker accepts was refused
    // here, while `kern run --name` takes it (its hostname cut to 64, as the kernel's limit is).
    kern_common::BoxName::parse(n).is_ok()
}

/// A container created and not yet started: what `start` needs to run it.
#[derive(Clone)]
pub(crate) struct Created {
    pub(crate) argv: Vec<String>,
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
    /// What the create asked for that kern does not apply: Docker's `Warnings`, which the client
    /// prints, so a setting is never dropped in silence.
    warnings: Vec<String>,
}

static CREATED: Mutex<Option<HashMap<String, Created>>> = Mutex::new(None);

pub(crate) fn created_get(name: &str) -> Option<Created> {
    CREATED
        .lock()
        .ok()
        .and_then(|g| g.as_ref().and_then(|m| m.get(name).cloned()))
}

pub(crate) fn created_put(name: &str, c: Created) {
    if let Ok(mut g) = CREATED.lock() {
        g.get_or_insert_with(HashMap::new)
            .insert(name.to_string(), c);
    }
}

/// The network aliases each container's create asked for, kept past its start (when `Created` is
/// taken) so `inspect` reports them while the box runs.
static NET_ALIASES: Mutex<Option<HashMap<String, Vec<String>>>> = Mutex::new(None);

fn net_remember(name: &str, argv: &[String]) {
    let (_, aliases) = crate::netvol::created_network(argv);
    if let Ok(mut g) = NET_ALIASES.lock() {
        let m = g.get_or_insert_with(HashMap::new);
        if aliases.is_empty() {
            m.remove(name);
        } else {
            m.insert(name.to_string(), aliases);
        }
    }
}

fn net_forget(name: &str) {
    if let Ok(mut g) = NET_ALIASES.lock() {
        if let Some(m) = g.as_mut() {
            m.remove(name);
        }
    }
}

/// Docker's `HostConfig.RestartPolicy` of a `kern box` argv: `--restart` (a bare one is
/// `on-failure`), its `:N`, or `--restart-max N`. `no` when none was asked. PURE.
fn restart_policy_json(argv: &[String]) -> String {
    let mut name = "no".to_string();
    let mut max = 0u64;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--" => break,
            "--restart" => {
                let v = argv.get(i + 1).map(String::as_str).unwrap_or_default();
                let (n, m) = v.split_once(':').unwrap_or((v, ""));
                if matches!(n, "always" | "unless-stopped" | "on-failure" | "no") {
                    name = n.to_string();
                    max = m.parse().unwrap_or(0);
                    i += 1;
                } else {
                    name = "on-failure".to_string();
                }
            }
            "--restart-max" => {
                max = argv.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(0);
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    format!(
        "{{\"Name\":{},\"MaximumRetryCount\":{max}}}",
        json_str(&name)
    )
}

/// The `kern box` argv a KEPT box was made with (every container this API makes is one, but for
/// `--rm` and a test session's): its record, `$XDG_DATA_HOME/kern/boxes/<name>/box.rec`, a header,
/// a blank line, then the argv NUL-separated. Empty for a box with none.
fn kept_argv(name: &str) -> Vec<String> {
    if !valid_name(name) {
        return Vec::new();
    }
    let root = kern_common::xdg_data_dir();
    let Some(rec) = root.map(|r| r.join("kern/boxes").join(name).join("box.rec")) else {
        return Vec::new();
    };
    let Ok(raw) = std::fs::read(rec) else {
        return Vec::new();
    };
    let Some(at) = raw.windows(2).position(|w| w == b"\n\n") else {
        return Vec::new();
    };
    raw[at + 2..]
        .split(|b| *b == 0)
        .filter(|a| !a.is_empty())
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect()
}

/// The policy of the systemd unit kern wrote for `name` (`kern-<name>.service`, its
/// `X-KernRestart=`), `always` for a unit kern wrote before it recorded one. `None` without a unit.
fn unit_restart_policy(name: &str) -> Option<String> {
    if !valid_name(name) {
        return None;
    }
    let unit = kern_common::xdg_config_dir()?
        .join("systemd/user")
        .join(format!("kern-{name}.service"));
    let text = std::fs::read_to_string(unit).ok()?;
    if !text.lines().any(|l| l.starts_with("X-KernManagedBox=")) {
        return None;
    }
    Some(
        text.lines()
            .find_map(|l| l.strip_prefix("X-KernRestart="))
            .filter(|p| matches!(*p, "always" | "unless-stopped"))
            .unwrap_or("always")
            .to_string(),
    )
}

fn net_aliases(name: &str) -> Vec<String> {
    if let Some(c) = created_get(name) {
        return crate::netvol::created_network(&c.argv).1;
    }
    NET_ALIASES
        .lock()
        .ok()
        .and_then(|g| g.as_ref().and_then(|m| m.get(name).cloned()))
        .unwrap_or_default()
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
pub(crate) fn box_running(v: &Value) -> bool {
    !matches!(
        v.get("status").and_then(Value::as_str),
        Some("exited" | "kept")
    )
}

pub(crate) fn kern_boxes(bin: &Path) -> Vec<(String, Value)> {
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
pub(crate) fn resolve(bin: &Path, id: &str) -> Option<String> {
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

/// This process's hard limit for the `ulimit` named as Docker names it, `None` when unlimited or
/// not a name kern maps.
fn hard_limit_of(name: &str) -> Option<u64> {
    let res = match name {
        "nofile" => libc::RLIMIT_NOFILE,
        "nproc" => libc::RLIMIT_NPROC,
        "memlock" => libc::RLIMIT_MEMLOCK,
        "core" => libc::RLIMIT_CORE,
        "stack" => libc::RLIMIT_STACK,
        "fsize" => libc::RLIMIT_FSIZE,
        "cpu" => libc::RLIMIT_CPU,
        "as" => libc::RLIMIT_AS,
        "data" => libc::RLIMIT_DATA,
        "locks" => libc::RLIMIT_LOCKS,
        "sigpending" => libc::RLIMIT_SIGPENDING,
        "msgqueue" => libc::RLIMIT_MSGQUEUE,
        "nice" => libc::RLIMIT_NICE,
        "rtprio" => libc::RLIMIT_RTPRIO,
        _ => return None,
    };
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit on this process with a struct owned here.
    if unsafe { libc::getrlimit(res, &mut lim) } != 0 || lim.rlim_max == libc::RLIM_INFINITY {
        return None;
    }
    Some(lim.rlim_max)
}

#[cfg(test)]
fn create_argv(name: &str, body: &Value) -> Result<Created, String> {
    create_argv_gated(name, body, false, false)
}

/// `HostConfig.DeviceRequests` as `kern box --gpus`: GPU requests only (driver `nvidia`, or a `gpu`
/// capability), `Count` -1 as `all`, a count as how many, `DeviceIDs` as `device=`. `None` for no
/// request. MEASURED before: `docker run --gpus all` through kern's socket was refused whatever the
/// operator had allowed, where `kern compose` grants the same request under `allow_gpu_grants`.
fn gpu_spec(host: Option<&Value>) -> Result<Option<String>, String> {
    let reqs = host
        .and_then(|h| h.get("DeviceRequests"))
        .and_then(Value::as_array)
        .unwrap_or_default();
    if reqs.is_empty() {
        return Ok(None);
    }
    let mut all = false;
    let mut count: i64 = 0;
    let mut ids: Vec<String> = Vec::new();
    for r in reqs {
        let driver = r.get("Driver").and_then(Value::as_str).unwrap_or_default();
        let gpu_cap = r
            .get("Capabilities")
            .and_then(Value::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(Value::as_array)
            .any(|set| set.iter().any(|c| c.as_str() == Some("gpu")));
        if !(driver == "nvidia" || (driver.is_empty() && gpu_cap)) {
            return Err(format!(
                "HostConfig.DeviceRequests with driver {driver:?}: kern grants NVIDIA GPUs and no \
                 other device this way"
            ));
        }
        for id in r
            .get("DeviceIDs")
            .and_then(Value::as_array)
            .unwrap_or_default()
        {
            let Some(id) = id.as_str().filter(|i| {
                !i.is_empty()
                    && i.len() <= 64
                    && i.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }) else {
                return Err("HostConfig.DeviceRequests: a device id is a GPU index or UUID".into());
            };
            ids.push(id.to_string());
        }
        match r.get("Count").and_then(Value::as_i64).unwrap_or(0) {
            n if n < 0 => all = true,
            n => count += n,
        }
    }
    Ok(Some(if !ids.is_empty() {
        format!("device={}", ids.join(","))
    } else if all || count == 0 {
        "all".to_string()
    } else {
        count.to_string()
    }))
}

/// [`create_argv`], with `gpu_allowed` the operator's `allow_gpu_grants` (or `allow_device_grants`):
/// the same gate `kern compose` applies, since a Docker client can no more grant itself a card than a
/// compose file can. `privileged_allowed` is the operator's `compose_privileged`, the gate a compose
/// file's `privileged: true` passes too.
fn create_argv_gated(
    name: &str,
    body: &Value,
    gpu_allowed: bool,
    privileged_allowed: bool,
) -> Result<Created, String> {
    let image = body
        .get("Image")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("Image is required")?
        .to_string();
    let host = body.get("HostConfig");
    for f in ["Devices", "CapAdd", "SecurityOpt", "Links"] {
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
        // Docker's daemon refuses a relative one, in these words (measured: `docker run -w ./tmp`
        // exits 125 under Docker; through kern's socket it ran in `/tmp`).
        if !w.starts_with('/') {
            return Err(format!(
                "the working directory '{w}' is invalid, it needs to be an absolute path"
            ));
        }
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
    // `VolumesFrom: ["<container>[:ro|:rw]"]`: kern's `--volumes-from`, which applies every check a
    // mount of the box gets. A container ID is turned into its box name by the caller.
    if let Some(list) = host
        .and_then(|h| h.get("VolumesFrom"))
        .and_then(Value::as_array)
    {
        for v in list {
            let Some(v) = v.as_str().filter(|v| !v.is_empty()) else {
                return Err("HostConfig.VolumesFrom: each entry is a container name".into());
            };
            argv.push("--volumes-from".into());
            argv.push(v.to_string());
        }
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
        // Another container's namespace, as `docker run --network container:<c>` asks.
        Some(other) if other.starts_with("container:") => {
            argv.push("--network".into());
            argv.push(other.to_string());
        }
        // A NETWORK BY NAME is a kern pod (see `netvol`): the box joins it, reached by its
        // endpoint's aliases (compose's service name) as well as by its own name.
        Some(net) => {
            argv.push("--network".into());
            argv.push(net.to_string());
            let endpoints = body
                .get("NetworkingConfig")
                .and_then(|n| n.get("EndpointsConfig"))
                .and_then(Value::as_object)
                .unwrap_or_default();
            // Every other network the create names goes on as well; whether they can all be one
            // box's (the networks of one compose project) is decided where the networks are known,
            // `projnet_argv`, which refuses the rest by name.
            for (other, _) in endpoints.iter().filter(|(k, _)| k != net) {
                argv.push("--network".into());
                argv.push(other.clone());
            }
            let ep = endpoints.iter().find(|(k, _)| k == net).map(|(_, v)| v);
            for a in crate::netvol::endpoint_aliases(ep, name) {
                argv.push("--network-alias".into());
                argv.push(a);
            }
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
    // THE REST OF `HostConfig`, AND `StopSignal`/`StopTimeout`, as the `kern box` flags of the same
    // meaning. MEASURED before: only Memory and NanoCpus were read, and every other limit or setting
    // a client sent was accepted and dropped: `docker run --pids-limit 32` through the socket ran
    // with kern's default and 100 forks all succeeded, where Docker refused the 33rd. A field kern has
    // no flag for is a `Warning` in the answer, which the client prints.
    let mut warnings: Vec<String> = Vec::new();
    let num = |k: &str| {
        host.and_then(|h| h.get(k))
            .and_then(Value::as_i64)
            .filter(|n| *n > 0)
    };
    let text = |k: &str| {
        host.and_then(|h| h.get(k))
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
    };
    let mut flag_n = |flag: &str, v: Option<i64>| {
        if let Some(v) = v {
            argv.push(flag.into());
            argv.push(v.to_string());
        }
    };
    flag_n("--pids-limit", num("PidsLimit"));
    flag_n("--shm-size", num("ShmSize"));
    flag_n("--memory-reservation", num("MemoryReservation"));
    flag_n("--io-weight", num("BlkioWeight").map(|w| w * 10));
    // `MemorySwap` is memory PLUS swap in Docker; kern's knob is the swap alone.
    if let (Some(total), Some(mem)) = (num("MemorySwap"), num("Memory")) {
        if total > mem {
            argv.push("--memory-swap-max".into());
            argv.push((total - mem).to_string());
        }
    }
    // `--cpu-quota` / `--cpu-period` are a CPU count, as `--cpus` is.
    if let (Some(q), Some(p)) = (num("CpuQuota"), num("CpuPeriod")) {
        if num("NanoCpus").is_none() {
            argv.push("--cpus".into());
            argv.push(format!("{:.3}", q as f64 / p as f64));
        }
    }
    if let Some(c) = text("CpusetCpus") {
        argv.push("--cpuset-cpus".into());
        argv.push(c.to_string());
    }
    if host
        .and_then(|h| h.get("ReadonlyRootfs"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        argv.push("--read-only".into());
    }
    if host.and_then(|h| h.get("Init")).and_then(Value::as_bool) == Some(true) {
        argv.push("--init".into());
    }
    for (field, flag) in [
        ("ExtraHosts", "--add-host"),
        ("Dns", "--dns"),
        ("DnsSearch", "--dns-search"),
        ("DnsOptions", "--dns-option"),
        ("CapDrop", "--cap-drop"),
        ("GroupAdd", "--group-add"),
    ] {
        for v in strings(host.and_then(|h| h.get(field))) {
            argv.push(flag.into());
            argv.push(v);
        }
    }
    for (k, v) in host
        .and_then(|h| h.get("Sysctls"))
        .and_then(Value::as_object)
        .unwrap_or_default()
    {
        argv.push("--sysctl".into());
        argv.push(format!("{k}={}", v.as_str().unwrap_or_default()));
    }
    for (path, opts) in host
        .and_then(|h| h.get("Tmpfs"))
        .and_then(Value::as_object)
        .unwrap_or_default()
    {
        let opts = opts.as_str().unwrap_or_default();
        argv.push("--tmpfs".into());
        argv.push(if opts.is_empty() {
            path.clone()
        } else {
            format!("{path}:{opts}")
        });
    }
    for u in host
        .and_then(|h| h.get("Ulimits"))
        .and_then(Value::as_array)
        .unwrap_or_default()
    {
        let (Some(name), Some(soft)) = (
            u.get("Name").and_then(Value::as_str),
            u.get("Soft").and_then(Value::as_i64),
        ) else {
            continue;
        };
        let hard = u.get("Hard").and_then(Value::as_i64).unwrap_or(soft);
        // A rootless box cannot raise a hard limit above the one this server has, and kern then
        // applies that one and says so on its stderr, which the Docker client never reads.
        // MEASURED before: `--ulimit nofile=9999999:9999999` ran with 1048576 and not a word.
        if let Some(cap) = hard_limit_of(name) {
            if u64::try_from(hard).is_ok_and(|h| h > cap) {
                warnings.push(format!(
                    "Ulimits {name}={soft}:{hard}: kern runs the box rootless and cannot raise a \
                     hard limit above {cap}, so the box gets {cap}"
                ));
            }
        }
        argv.push("--ulimit".into());
        argv.push(format!("{name}={soft}:{hard}"));
    }
    if let Some(lc) = host.and_then(|h| h.get("LogConfig")) {
        match lc.get("Type").and_then(Value::as_str) {
            None | Some("" | "json-file" | "local") => {}
            Some(d @ ("none" | "journald")) => {
                argv.push("--log-driver".into());
                argv.push(d.into());
            }
            Some(other) => warnings.push(format!(
                "log driver {other:?}: kern keeps a box's output for `docker logs` (json-file)"
            )),
        }
        let opt = |k: &str| {
            lc.get("Config")
                .and_then(|c| c.get(k))
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
        };
        if let Some(v) = opt("max-size") {
            argv.push("--log-max-size".into());
            argv.push(v.to_string());
        }
        if let Some(v) = opt("max-file") {
            argv.push("--log-max-file".into());
            argv.push(v.to_string());
        }
    }
    if let Some(sig) = body
        .get("StopSignal")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
    {
        argv.push("--stop-signal".into());
        argv.push(sig.to_string());
    }
    if let Some(t) = body
        .get("StopTimeout")
        .and_then(Value::as_i64)
        .filter(|n| *n >= 0)
    {
        argv.push("--stop-timeout".into());
        argv.push(t.to_string());
    }
    for (field, what) in [
        ("CpuShares", "a relative CPU share"),
        ("OomScoreAdj", "an OOM score adjustment"),
        ("CpuRealtimePeriod", "a realtime CPU period"),
    ] {
        if num(field).is_some() {
            warnings.push(format!(
                "HostConfig.{field} ({what}) is not applied by kern's Docker API"
            ));
        }
    }
    if host
        .and_then(|h| h.get("OomKillDisable"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        warnings.push(
            "HostConfig.OomKillDisable is not applied: kern's boxes keep the OOM killer".into(),
        );
    }
    // `Healthcheck`, as `kern box --health-*`: what `depends_on: condition: service_healthy` waits on.
    // MEASURED before: it was not read, the box had no check, and the docker compose client refused
    // the stack ("container ... has no healthcheck configured"). Docker's durations are nanoseconds;
    // kern's are whole seconds, rounded up so a 500 ms interval is not 0.
    if let Some(hc) = body.get("Healthcheck") {
        let test = strings(hc.get("Test"));
        match test.first().map(String::as_str) {
            Some("CMD-SHELL") if test.len() > 1 => {
                argv.push("--health-cmd".into());
                argv.push(test[1..].join(" "));
            }
            Some("CMD") if test.len() > 1 => {
                for a in &test[1..] {
                    argv.push("--health-cmd-argv".into());
                    argv.push(a.clone());
                }
            }
            // `NONE` turns the image's check off, and an empty `Test` keeps the image's: neither has
            // a command of its own to pass.
            _ => {}
        }
        if test.first().is_some_and(|t| t == "CMD-SHELL" || t == "CMD") {
            let secs = |k: &str| {
                hc.get(k)
                    .and_then(Value::as_i64)
                    .filter(|n| *n > 0)
                    .map(|ns| (ns + 999_999_999) / 1_000_000_000)
            };
            for (field, flag) in [
                ("Interval", "--health-interval"),
                ("Timeout", "--health-timeout"),
                ("StartPeriod", "--health-start-period"),
                ("StartInterval", "--health-start-interval"),
            ] {
                if let Some(n) = secs(field) {
                    argv.push(flag.into());
                    argv.push(n.to_string());
                }
            }
            if let Some(r) = hc.get("Retries").and_then(Value::as_i64).filter(|n| *n > 0) {
                argv.push("--health-retries".into());
                argv.push(r.to_string());
            }
        }
    }
    // `Privileged`: `kern box --privileged`, every capability in the box's own user namespace, the
    // seccomp a nested runtime needs and a cgroup tree it may write below the box's caps. Granted by
    // the operator only, as a compose file's `privileged: true` is: a client that could grant it to
    // itself would make it no gate.
    if host
        .and_then(|h| h.get("Privileged"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        if !privileged_allowed {
            return Err(
                "HostConfig.Privileged: a Docker client cannot grant itself privileges: set \
                 compose_privileged in YOUR OWN kern.toml (`kern config set compose_privileged \
                 true`), the gate a compose file's `privileged: true` passes too. Rootless, it is \
                 every capability in the box's own user namespace, nothing over the host's"
                    .into(),
            );
        }
        argv.push("--privileged".into());
    }
    if let Some(spec) = gpu_spec(host)? {
        if !gpu_allowed {
            return Err(
                "HostConfig.DeviceRequests: a GPU is a device grant, and a Docker client cannot grant \
                 itself one: set allow_gpu_grants (GPUs only) in YOUR OWN kern.toml (`kern config \
                 set allow_gpu_grants true`), the gate `kern compose` reads too"
                    .into(),
            );
        }
        argv.push("--gpus".into());
        argv.push(spec);
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
        warnings,
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

pub(crate) fn labels_json(labels: &[(String, String)]) -> String {
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

/// A container's `Mounts`, as Docker's summary and inspect carry them, from the argv the box was made
/// with: `-v name:dst` and `--mount type=volume` a named volume, `-v /path:dst` and `type=bind` a bind,
/// `type=tmpfs` a tmpfs. `docker compose` reads them to decide whether a container still has the
/// volumes its service declares (`checkExpectedVolumes`). MEASURED before (Grok's round 6+1, case 2):
/// the field was `[]`, so compose recreated every service with a named volume at each `up`, where
/// Docker starts the stopped container again.
fn mounts_json(argv: &[String]) -> String {
    let mut out = Vec::new();
    let mut it = argv.iter();
    while let Some(a) = it.next() {
        let spec = match a.as_str() {
            "-v" | "--volume" | "--mount" => it.next(),
            _ => continue,
        };
        let Some(spec) = spec else { break };
        let (kind, src, dst, ro) = if a == "--mount" {
            let mut kind = "volume";
            let (mut src, mut dst, mut ro) = ("", "", false);
            for kv in spec.split(',') {
                match kv.split_once('=') {
                    Some(("type", v)) => {
                        kind = match v {
                            "bind" => "bind",
                            "tmpfs" => "tmpfs",
                            _ => "volume",
                        }
                    }
                    Some(("src" | "source", v)) => src = v,
                    Some(("dst" | "destination" | "target", v)) => dst = v,
                    Some(("readonly" | "ro", v)) => ro = v != "false" && v != "0",
                    None if kv == "ro" || kv == "readonly" => ro = true,
                    _ => {}
                }
            }
            (kind, src, dst, ro)
        } else {
            let mut f = spec.splitn(3, ':');
            let src = f.next().unwrap_or_default();
            let Some(dst) = f.next() else { continue };
            let ro = f.next().is_some_and(|o| o.split(',').any(|x| x == "ro"));
            let kind = if src.starts_with('/') || src.starts_with('.') {
                "bind"
            } else {
                "volume"
            };
            (kind, src, dst, ro)
        };
        if dst.is_empty() {
            continue;
        }
        out.push(match kind {
            "volume" => format!(
                "{{\"Type\":\"volume\",\"Name\":{},\"Source\":\"\",\"Destination\":{},\"Driver\":\"local\",\"Mode\":\"z\",\"RW\":{},\"Propagation\":\"\"}}",
                json_str(src),
                json_str(dst),
                !ro
            ),
            "bind" => format!(
                "{{\"Type\":\"bind\",\"Source\":{},\"Destination\":{},\"Mode\":\"\",\"RW\":{},\"Propagation\":\"rprivate\"}}",
                json_str(src),
                json_str(dst),
                !ro
            ),
            _ => format!(
                "{{\"Type\":\"tmpfs\",\"Source\":\"\",\"Destination\":{},\"Mode\":\"\",\"RW\":{},\"Propagation\":\"\"}}",
                json_str(dst),
                !ro
            ),
        });
    }
    format!("[{}]", out.join(","))
}

/// `GET /containers/{id}/json`.
fn inspect(bin: &Path, name: &str) -> Response {
    let id = id_of(name);
    if let Some(c) = created_get(name) {
        let (net, aliases) = crate::netvol::created_network(&c.argv);
        let nets = crate::netvol::container_networks_json(name, net.as_deref(), &aliases);
        let policy = restart_policy_json(&c.argv);
        let privileged = c.argv.iter().any(|a| a == "--privileged");
        let mounts = mounts_json(&c.argv);
        return json_response(
            200,
            format!(
                "{{\"Id\":{},\"Created\":{},\"Name\":{},\"Image\":{},\"RestartCount\":0,\"State\":{{\"Status\":\"created\",\"Running\":false,\"Paused\":false,\"Restarting\":false,\"OOMKilled\":false,\"Dead\":false,\"Pid\":0,\"ExitCode\":0,\"Error\":\"\",\"StartedAt\":\"{ZERO_TIME}\",\"FinishedAt\":\"{ZERO_TIME}\"}},\"Config\":{{\"Image\":{},\"Env\":{},\"Cmd\":{},\"Labels\":{},\"Tty\":false}},\"HostConfig\":{{\"NetworkMode\":\"default\",\"Privileged\":{privileged},\"RestartPolicy\":{policy}}},\"NetworkSettings\":{{\"Ports\":{},\"IPAddress\":\"\",\"Networks\":{nets}}},\"Mounts\":{mounts}}}",
                json_str(&id),
                json_str(&rfc3339(c.created)),
                json_str(&format!("/{name}")),
                json_str(&container_image_id(&kern_images(bin, false), &c.image)),
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
    // `kern pause` freezes the box: Docker's `paused`, still `Running` as Docker reports it. MEASURED
    // before: `docker pause` then `inspect` answered `running`, and `Paused` was false whatever.
    let paused = running && v.get("status").and_then(Value::as_str) == Some("paused");
    // A `--restart always` box between two runs: Docker's `restarting`, which it also counts as
    // `Running`. MEASURED before: such a container read `exited` with `RestartCount` 0 while systemd
    // had run it ten times.
    let restarting = v.get("status").and_then(Value::as_str) == Some("restarting");
    // Docker's `OOMKilled`: the OOM killer struck in the container, the one that ended it or a
    // child it lost while it runs, as kern records and reads it (`oom_killed`).
    let oom_killed = v.get("oom_killed").and_then(Value::as_bool) == Some(true);
    // The pod the box is in is its network; the aliases are the ones its create asked for.
    let pod = v.get("pod").and_then(Value::as_str).unwrap_or_default();
    let nets = crate::netvol::container_networks_json(name, Some(pod), &net_aliases(name));
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
    let image_name = v.get("image").and_then(Value::as_str).unwrap_or_default();
    let image = json_str(image_name);
    let image_id = json_str(&recorded_or_current_image_id(bin, &v, image_name));
    // Docker's `HostConfig.RestartPolicy`, from the argv the box was kept with, or the systemd unit
    // a standalone `always`/`unless-stopped` box runs under (its argv carries no `--restart`: systemd
    // does the restarting). MEASURED before: empty for every container.
    let kept = kept_argv(name);
    let privileged = kept.iter().any(|a| a == "--privileged");
    let mounts = mounts_json(&kept);
    let policy = match unit_restart_policy(name) {
        Some(p) => format!("{{\"Name\":{},\"MaximumRetryCount\":0}}", json_str(&p)),
        None => restart_policy_json(&kept),
    };
    json_response(
        200,
        format!(
            "{{\"Id\":{},\"Created\":{},\"Name\":{},\"Path\":{},\"Args\":[],\"Image\":{image_id},\"RestartCount\":{restart_count},\"State\":{{\"Status\":{},\"Running\":{},\"Paused\":{paused},\"Restarting\":{restarting},\"OOMKilled\":{oom_killed},\"Dead\":false,\"Pid\":{pid},\"ExitCode\":{exit_code},\"Error\":\"\",\"StartedAt\":{},\"FinishedAt\":{}{health_json}}},\"Config\":{{\"Image\":{image},\"Labels\":{},\"Tty\":false,\"Env\":[]}},\"HostConfig\":{{\"NetworkMode\":\"default\",\"Privileged\":{privileged},\"RestartPolicy\":{policy}}},\"NetworkSettings\":{{\"Ports\":{},\"IPAddress\":\"\",\"Networks\":{nets}}},\"Mounts\":{mounts}}}",
            json_str(&id),
            json_str(&created),
            json_str(&format!("/{name}")),
            json_str(command),
            json_str(if paused {
                "paused"
            } else if restarting {
                "restarting"
            } else if running {
                "running"
            } else {
                "exited"
            }),
            running || restarting,
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
    let images = kern_images(bin, false);
    for (name, v) in kern_boxes(bin) {
        let running = box_running(&v);
        if !running && !all {
            continue;
        }
        // A frozen box (`kern pause`) is Docker's `paused`, in the list as in `inspect`.
        let paused = running && v.get("status").and_then(Value::as_str) == Some("paused");
        let pod = v.get("pod").and_then(Value::as_str).unwrap_or_default();
        let labels = labels_of(&v);
        let state = if paused {
            "paused"
        } else if v.get("status").and_then(Value::as_str) == Some("restarting") {
            "restarting"
        } else if running {
            "running"
        } else {
            "exited"
        };
        if created_names.contains(&name) || !filters.keeps(&name, state, &labels) {
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
            // `NetworkSettings.Networks`, `HostConfig` and `Mounts`, as Docker's summary carries them:
            // compose's second `up` reads the networks from THIS list to decide whether a container
            // must be recreated. MEASURED before: the field was absent and the docker compose v5
            // client crashed with a nil pointer (`checkExpectedNetworks`).
            "{{\"Id\":{},\"Names\":[{}],\"Image\":{},\"ImageID\":{},\"Command\":{},\"Created\":{},\"State\":{},\"Status\":{},\"Ports\":[{}],\"Labels\":{},\"HostConfig\":{{\"NetworkMode\":{}}},\"NetworkSettings\":{{\"Networks\":{}}},\"Mounts\":{}}}",
            json_str(&id_of(&name)),
            json_str(&format!("/{name}")),
            json_str(v.get("image").and_then(Value::as_str).unwrap_or_default()),
            json_str(
                &v.get("image_id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                    .map_or_else(
                        || container_image_id(
                            &images,
                            v.get("image").and_then(Value::as_str).unwrap_or_default()
                        ),
                        str::to_string
                    )
            ),
            json_str(v.get("command").and_then(Value::as_str).unwrap_or_default()),
            // The same `Created` `inspect` says: when the box was made.
            v.get("created")
                .or_else(|| v.get("started"))
                .and_then(Value::as_i64)
                .unwrap_or(0),
            // ONE STATE, the one the filter above was asked about: this wrote its own `paused` /
            // `running` / `exited`, so a box between two runs of its `--restart` policy was
            // filtered as `restarting` and listed as `Up`. Docker: `Restarting (1) ...`.
            json_str(state),
            json_str(&match state {
                "paused" => "Up (Paused)".to_string(),
                "running" => "Up".to_string(),
                "restarting" => match v.get("exit_code").and_then(Value::as_i64) {
                    Some(c) => format!("Restarting ({c})"),
                    None => "Restarting".to_string(),
                },
                _ => "Exited".to_string(),
            }),
            ports.join(","),
            labels_json(&labels),
            json_str(if pod.is_empty() { "default" } else { pod }),
            crate::netvol::container_networks_json(&name, Some(pod), &net_aliases(&name)),
            mounts_json(&kept_argv(&name))
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
            let (net, aliases) = crate::netvol::created_network(&c.argv);
            items.push(format!(
                "{{\"Id\":{},\"Names\":[{}],\"Image\":{},\"ImageID\":{},\"Command\":{},\"Created\":{},\"State\":\"created\",\"Status\":\"Created\",\"Ports\":[],\"Labels\":{},\"HostConfig\":{{\"NetworkMode\":{}}},\"NetworkSettings\":{{\"Networks\":{}}},\"Mounts\":{}}}",
                json_str(&id_of(name)),
                json_str(&format!("/{name}")),
                json_str(&c.image),
                json_str(&container_image_id(&images, &c.image)),
                json_str(&c.cmd.join(" ")),
                c.created,
                labels_json(&c.labels),
                json_str(net.as_deref().unwrap_or("default")),
                crate::netvol::container_networks_json(name, net.as_deref(), &aliases),
                mounts_json(&c.argv)
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
/// The image buildx runs its own BuildKit in, when the daemon it talks to has none: `moby/buildkit`
/// at a `buildx-stable` tag (the driver's default).
fn is_buildx_builder(image: &str) -> bool {
    let image = image.strip_prefix("docker.io/").unwrap_or(image);
    image
        .strip_prefix("moby/buildkit:")
        .is_some_and(|tag| tag.starts_with("buildx-stable"))
}

/// `docker build` WITH BUILDX, refused before it costs anything and with the way that works. On
/// Linux the docker CLI hands every build to buildx when the plugin is installed, whatever the
/// daemon says (`cmd/docker/builder.go`: only a Windows daemon without BuildKit keeps the classic
/// builder), and buildx, finding no BuildKit in this API, pulls `moby/buildkit` to run one in a
/// privileged container. MEASURED with buildx 0.39.1: a 23 s pull of 230 MB, then "HostConfig.
/// Privileged: kern does not grant it", which names neither the cause nor the way out.
/// `DOCKER_BUILDKIT=0` is that way: the classic builder, `POST /build`, measured working for
/// `docker build` and `docker compose build` alike with buildx installed.
fn buildx_refusal() -> Response {
    error(
        501,
        "docker build with buildx runs BuildKit in a privileged container of its own, which kern's \
         Docker API does not start. Build with the classic builder, which it serves: \
         `DOCKER_BUILDKIT=0 docker build ...` (and `DOCKER_BUILDKIT=0 docker compose build`), \
         or `kern build`",
    )
}

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
    if is_buildx_builder(&image) {
        return buildx_refusal();
    }
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
            json_str(&format!(
                "sha256:{}",
                image_entry_id(&i).unwrap_or_else(|| id_of(n))
            )),
            i.get("pulled").and_then(Value::as_i64).unwrap_or(0).max(0),
        ));
    }
    json_response(200, format!("[{}]", items.join(",")))
}

/// The cached image an API path names, as `kern images --json` lists it: its id (`sha256:<hex>`
/// or a prefix of 12 or more, which is how a client hands an image back), else the name itself, a
/// bare name as `:latest`, or a repository pulled by digest. By name, this machine's entry before
/// another platform's, as `kern run` picks it.
fn cached_image(bin: &Path, name: &str) -> Option<Value> {
    cached_image_in(&kern_images(bin, false), name).cloned()
}

/// [`cached_image`] over a listing already in hand. PURE.
fn cached_image_in<'a>(images: &'a [Value], name: &str) -> Option<&'a Value> {
    // THE NAME FIRST, then the id, as Docker resolves them: an image called `bf` is that image, not
    // the one whose id starts with `bf`.
    let want_latest = if name.contains(':') || name.contains('@') {
        name.to_string()
    } else {
        format!("{name}:latest")
    };
    let by_name = images
        .iter()
        .filter(|i| {
            i.get("image")
                .and_then(Value::as_str)
                .is_some_and(|n| n == name || n == want_latest || n.split('@').next() == Some(name))
        })
        .min_by_key(|i| i.get("platform").is_some());
    by_name.or_else(|| image_by_id_prefix(images, name))
}

/// The one cached entry whose id `r` names (`sha256:<hex>` or a prefix of 2 or more, as Docker
/// takes one); `None` for no match and for an ambiguous prefix.
fn image_by_id_prefix<'a>(images: &'a [Value], r: &str) -> Option<&'a Value> {
    let hex = image_id_ref(r)?;
    let mut hits = images
        .iter()
        .filter(|i| image_entry_id(i).is_some_and(|id| id.starts_with(hex)));
    let one = hits.next()?;
    hits.next().is_none().then_some(one)
}

/// A box's image id for `inspect`: the one kern recorded when the box started (`image_id` in
/// `kern ps --json`), which a rebuild of the tag does not move, as Docker keeps the id a container
/// was created from; for a record without one, the id its image's name has now.
fn recorded_or_current_image_id(bin: &Path, v: &Value, image: &str) -> String {
    match v
        .get("image_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    {
        Some(id) => id.to_string(),
        None => container_image_id(&kern_images(bin, false), image),
    }
}

/// The image id of a container that runs `image`, as Docker reports it: `Image` in `inspect` and
/// `ImageID` in the list are the id (`sha256:<hex>`), the name is `Config.Image` and the list's
/// `Image`. MEASURED before: both said the name, where a client that compares a container's image
/// with an image's `Id` (`docker inspect -f '{{.Image}}'` against `docker images -q`) never matched.
/// An image no longer cached keeps an id, as Docker's container keeps the id of a removed image:
/// the one derived from its name, which is also what a cache entry with no content id answers.
/// `images` is one `kern images --json` per request (0.55 ms median, 6 images, measured).
fn container_image_id(images: &[Value], image: &str) -> String {
    if image.is_empty() {
        return String::new();
    }
    let hex = cached_image_in(images, image)
        .and_then(image_entry_id)
        .unwrap_or_else(|| id_of(image));
    format!("sha256:{hex}")
}

/// The id a client sees for a cached image: of its name, and for another platform's entry of the
/// name and that platform, so the two entries of one tag are two images. MEASURED before: both
/// `alpine:3.20` entries had one id, and the `docker compose` client, which inspects a service's
/// image by the id it was given, could not tell the arm64 one from the amd64.
fn image_entry_id(i: &Value) -> Option<String> {
    let n = i.get("image").and_then(Value::as_str)?;
    if let Some(id) = i.get("cache").and_then(Value::as_str).and_then(content_id) {
        return Some(id);
    }
    Some(match image_entry_platform(i) {
        Some(p) => id_of(&format!("{n}#{p}")),
        None => id_of(n),
    })
}

/// AN IMAGE'S ID IS ITS CONTENT, as Docker's is its config's digest: the cache entry's config (the
/// `.image` sidecar, history included) and its layers (`.layers`). Named after the NAME before, an
/// image rebuilt under the same tag kept its id, and `docker compose up --build` (which recreates a
/// container when the image id differs from the one in its `com.docker.compose.image` label) left
/// the old container running the old code. MEASURED: v1 still answering after the rebuild to v2.
///
/// Read once per change of the two files: their modification times key a memo, so a listing costs a
/// `stat` of each per image.
fn content_id(stem: &str) -> Option<String> {
    content_id_in(
        &kern_common::xdg_cache_dir()?.join("kern").join("images"),
        stem,
    )
}

/// The id (`sha256:<hex>`) of the cached image whose entry is `stem` in the image cache `dir`,
/// named `name`: its content, as the socket's `images/json` and `inspect` report it, or the id
/// derived from the name for an entry with no config to read. For `kern inspect`, so the CLI and
/// kern's Docker API give one image one id.
pub fn image_id_for_entry(dir: &std::path::Path, stem: &str, name: &str) -> String {
    format!(
        "sha256:{}",
        content_id_in(dir, stem).unwrap_or_else(|| id_of(name))
    )
}

/// The memo of [`content_id_in`]: per entry, the modification times its id was read at.
type ContentIds = HashMap<String, ((i64, i64), String)>;

/// [`content_id`] in the image cache `dir`.
fn content_id_in(dir: &std::path::Path, stem: &str) -> Option<String> {
    static SEEN: Mutex<Option<ContentIds>> = Mutex::new(None);
    if stem.is_empty() || stem.contains('/') || stem.starts_with('.') {
        return None;
    }
    let (img, layers) = (
        dir.join(format!("{stem}.image")),
        dir.join(format!("{stem}.layers")),
    );
    let stamp = |p: &std::path::Path| {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(p).map_or(0, |m| m.mtime_nsec() + m.mtime() * 1_000_000_000)
    };
    let key = (stamp(&img), stamp(&layers));
    if key.0 == 0 {
        return None;
    }
    let memo = format!("{}/{stem}", dir.display());
    if let Some(id) = SEEN.lock().ok().and_then(|g| {
        g.as_ref()
            .and_then(|m| m.get(&memo))
            .filter(|(k, _)| *k == key)
            .map(|(_, id)| id.clone())
    }) {
        return Some(id);
    }
    let mut text = String::from_utf8_lossy(&std::fs::read(&img).ok()?).into_owned();
    text.push('\n');
    text.push_str(&String::from_utf8_lossy(
        &std::fs::read(&layers).unwrap_or_default(),
    ));
    let id = hashed_id(&text);
    if let Ok(mut g) = SEEN.lock() {
        g.get_or_insert_with(HashMap::new)
            .insert(memo, (key, id.clone()));
    }
    Some(id)
}

/// `os/arch` of a cache entry for another platform; `None` for this machine's.
fn image_entry_platform(i: &Value) -> Option<&str> {
    i.get("platform")
        .and_then(Value::as_str)
        .filter(|p| valid_platform(p))
}

/// The hex of an image id as a client passes one: `sha256:<hex>`, or a bare lowercase hex prefix
/// of at least 12 (what `docker images` prints).
fn image_id_ref(r: &str) -> Option<&str> {
    let hex = r.strip_prefix("sha256:").unwrap_or(r);
    (2..=64).contains(&hex.len()).then_some(hex).filter(|h| {
        h.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The create's `Image` when it is an image id: the cached entry's name in its place, and that
/// entry's platform when the create named none. `None` when it is not an id of a cached image.
fn image_by_id(bin: &Path, body: &Value) -> Option<(String, Option<String>)> {
    let r = body.get("Image").and_then(Value::as_str)?;
    image_id_ref(r)?;
    let images = kern_images(bin, false);
    // A cached image of that NAME is the one meant, as in `cached_image`.
    if images.iter().any(|i| {
        i.get("image")
            .and_then(Value::as_str)
            .is_some_and(|n| n == r || n == format!("{r}:latest"))
    }) {
        return None;
    }
    let i = image_by_id_prefix(&images, r)?;
    let name = i.get("image").and_then(Value::as_str)?.to_string();
    Some((name, image_entry_platform(i).map(str::to_string)))
}

/// Put the image `name` in place of the id a create gave (`--image`, and the event's image).
fn with_image_name(mut c: Created, name: &str) -> Created {
    if let Some(at) = c.argv.iter().position(|a| a == "--image") {
        if let Some(v) = c.argv.get_mut(at + 1) {
            *v = name.to_string();
        }
    }
    c.image = name.to_string();
    c
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
    // Another platform's entry is asked for by that platform, or kern answers this machine's.
    let mut args = vec!["image", "history", "--json"];
    if let Some(p) = image_entry_platform(&i) {
        args.extend(["--platform", p]);
    }
    args.push(n);
    let (code, out, err) = kern(bin, &args);
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
                    json_str(&format!(
                        "sha256:{}",
                        image_entry_id(&i).unwrap_or_else(|| id_of(n))
                    ))
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
// containers/{id}/top: `docker top`, read from the host's /proc as Docker's daemon reads it.

/// One process of a box, as `ps -ef` prints it: `UID PID PPID C STIME TTY TIME CMD`.
fn ps_row(pid: i32, hz: u64, boot: u64) -> Option<Vec<String>> {
    use std::os::unix::fs::MetadataExt;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `comm` is in parentheses and may hold spaces: the fields after it start past the LAST `)`.
    let rest = stat.get(stat.rfind(')')? + 2..)?;
    let f: Vec<&str> = rest.split_whitespace().collect();
    let num = |i: usize| f.get(i).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
    let ppid = num(1);
    let cpu_secs = (num(11) + num(12)) / hz.max(1);
    let start = boot + num(19) / hz.max(1);
    let uid = std::fs::metadata(format!("/proc/{pid}")).ok()?.uid();
    // A kernel thread, or a process that cleared its arguments, has none: `ps` shows `[comm]`.
    let comm = stat
        .find('(')
        .zip(stat.rfind(')'))
        .and_then(|(a, b)| stat.get(a + 1..b))
        .map(|c| format!("[{c}]"))
        .unwrap_or_default();
    let cmd = std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .map(|b| {
            b.split(|c| *c == 0)
                .filter(|a| !a.is_empty())
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|c| !c.is_empty())
        .unwrap_or(comm);
    let hm = rfc3339(start);
    Some(vec![
        uid.to_string(),
        pid.to_string(),
        ppid.to_string(),
        "0".into(),
        hm.get(11..16).unwrap_or("").to_string(),
        "?".into(),
        format!(
            "{:02}:{:02}:{:02}",
            cpu_secs / 3600,
            cpu_secs / 60 % 60,
            cpu_secs % 60
        ),
        cmd,
    ])
}

/// `GET /containers/{id}/top`: every process in the box's pid namespace (the one its PID 1 is in),
/// in `ps -ef`'s columns, with host pids as Docker's daemon gives them.
fn container_top(bin: &Path, id: &str) -> Response {
    let Some(name) = resolve(bin, id) else {
        return error(404, &format!("No such container: {id}"));
    };
    // `pid1` is in `inspect`, not in `ps`: the box's PID 1, whose pid namespace is the box's.
    let (code, out, _) = kern(bin, &["inspect", "--json", &name]);
    let pid1 = (code == 0)
        .then(|| json::parse(out.trim()).ok())
        .flatten()
        .and_then(|v| v.get("pid1").and_then(Value::as_i64))
        .and_then(|p| i32::try_from(p).ok())
        .filter(|p| *p > 0);
    let Some(pid1) = pid1 else {
        return error(409, &format!("Container {id} is not running"));
    };
    let Ok(ns) = std::fs::read_link(format!("/proc/{pid1}/ns/pid")) else {
        return error(409, &format!("Container {id} is not running"));
    };
    // SAFETY: sysconf has no preconditions.
    let hz = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).unwrap_or(100);
    let boot = std::fs::read_to_string("/proc/stat")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let mut rows: Vec<(i32, Vec<String>)> = std::fs::read_dir("/proc")
        .map(|d| {
            d.flatten()
                .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
                .filter(|p| std::fs::read_link(format!("/proc/{p}/ns/pid")).is_ok_and(|n| n == ns))
                .filter_map(|p| Some((p, ps_row(p, hz, boot)?)))
                .collect()
        })
        .unwrap_or_default();
    rows.sort_by_key(|(p, _)| *p);
    let titles = ["UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"]
        .iter()
        .map(|t| json_str(t))
        .collect::<Vec<_>>()
        .join(",");
    let procs = rows
        .iter()
        .map(|(_, r)| {
            format!(
                "[{}]",
                r.iter().map(|c| json_str(c)).collect::<Vec<_>>().join(",")
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    json_response(
        200,
        format!("{{\"Titles\":[{titles}],\"Processes\":[{procs}]}}"),
    )
}

// ---------------------------------------------------------------------------------------------
// containers/{id}/stats: `docker stats`, onto `kern stats --json`.

/// One reading of a box (`kern stats --json --no-stream <name>`) and of the host's CPU clock at
/// the same moment, which is what Docker's CPU percentage is computed from.
struct Sample {
    at: u64,
    cpu_ns: u64,
    mem: u64,
    mem_limit: Option<u64>,
    inactive_file: u64,
    tasks: u64,
    pids_limit: Option<u64>,
    net: Vec<(String, u64, u64, u64, u64)>,
    system_ns: u64,
    cpus: u64,
}

/// The host's CPU time in nanoseconds (the `cpu` line of `/proc/stat`, in clock ticks) and its
/// number of CPUs: Docker's `system_cpu_usage` and `online_cpus`.
fn host_cpu() -> (u64, u64) {
    let text = std::fs::read_to_string("/proc/stat").unwrap_or_default();
    // SAFETY: sysconf has no preconditions.
    let hz = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })
        .ok()
        .filter(|&h| h > 0)
        .unwrap_or(100);
    let ticks: u64 = text
        .lines()
        .find(|l| l.starts_with("cpu "))
        .map(|l| {
            l.split_whitespace()
                .skip(1)
                .filter_map(|x| x.parse::<u64>().ok())
                .sum()
        })
        .unwrap_or(0);
    let cpus = text
        .lines()
        .filter(|l| l.starts_with("cpu") && l.as_bytes().get(3).is_some_and(u8::is_ascii_digit))
        .count() as u64;
    (ticks.saturating_mul(1_000_000_000 / hz), cpus.max(1))
}

/// The host's memory, Docker's `limit` for a container with no memory limit.
fn host_mem_total() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
        .map_or(0, |kb| kb * 1024)
}

fn sample(bin: &Path, name: &str) -> Option<Sample> {
    let (code, out, _) = kern(bin, &["stats", "--json", "--no-stream", name]);
    if code != 0 {
        return None;
    }
    let (system_ns, cpus) = host_cpu();
    let v = json::parse(out.trim()).ok()?;
    let b = v.as_array()?.first()?.clone();
    let n = |k: &str| {
        b.get(k)
            .and_then(Value::as_i64)
            .and_then(|x| u64::try_from(x).ok())
    };
    let net = b
        .get("net")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(iface, c)| {
                    let f = |k: &str| {
                        c.get(k)
                            .and_then(Value::as_i64)
                            .and_then(|x| u64::try_from(x).ok())
                            .unwrap_or(0)
                    };
                    (
                        iface.clone(),
                        f("rx_bytes"),
                        f("rx_packets"),
                        f("tx_bytes"),
                        f("tx_packets"),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    Some(Sample {
        at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        cpu_ns: n("cpu_usec").unwrap_or(0).saturating_mul(1000),
        mem: n("mem_bytes").unwrap_or(0),
        mem_limit: n("mem_limit"),
        inactive_file: n("inactive_file").unwrap_or(0),
        tasks: n("tasks").unwrap_or(0),
        pids_limit: n("pids_limit"),
        net,
        system_ns,
        cpus,
    })
}

fn cpu_json(s: Option<&Sample>) -> String {
    let (total, system, cpus) = s.map_or((0, 0, 0), |s| (s.cpu_ns, s.system_ns, s.cpus));
    format!(
        "{{\"cpu_usage\":{{\"total_usage\":{total},\"usage_in_kernelmode\":0,\"usage_in_usermode\":0}},\"system_cpu_usage\":{system},\"online_cpus\":{cpus},\"throttling_data\":{{\"periods\":0,\"throttled_periods\":0,\"throttled_time\":0}}}}"
    )
}

/// Docker's `StatsJSON` for `name` from a reading and the one before it (CPU% is their delta).
fn stats_json(name: &str, cur: &Sample, pre: Option<&Sample>) -> String {
    let networks: Vec<String> = cur
        .net
        .iter()
        .map(|(n, rb, rp, tb, tp)| {
            format!(
                "{}:{{\"rx_bytes\":{rb},\"rx_packets\":{rp},\"rx_errors\":0,\"rx_dropped\":0,\"tx_bytes\":{tb},\"tx_packets\":{tp},\"tx_errors\":0,\"tx_dropped\":0}}",
                json_str(n)
            )
        })
        .collect();
    let limit = cur.mem_limit.unwrap_or_else(host_mem_total);
    let pids_limit = cur
        .pids_limit
        .map_or_else(|| "0".to_string(), |l| l.to_string());
    let when =
        |s: Option<&Sample>| json_str(&s.map_or_else(|| ZERO_TIME.to_string(), |s| rfc3339(s.at)));
    format!(
        "{{\"read\":{},\"preread\":{},\"pids_stats\":{{\"current\":{},\"limit\":{pids_limit}}},\"blkio_stats\":{{\"io_service_bytes_recursive\":null,\"io_serviced_recursive\":null,\"io_queue_recursive\":null,\"io_service_time_recursive\":null,\"io_wait_time_recursive\":null,\"io_merged_recursive\":null,\"io_time_recursive\":null,\"sectors_recursive\":null}},\"num_procs\":0,\"storage_stats\":{{}},\"cpu_stats\":{},\"precpu_stats\":{},\"memory_stats\":{{\"usage\":{},\"stats\":{{\"inactive_file\":{}}},\"limit\":{limit}}},\"name\":{},\"id\":{},\"networks\":{{{}}}}}",
        when(Some(cur)),
        when(pre),
        cur.tasks,
        cpu_json(Some(cur)),
        cpu_json(pre),
        cur.mem,
        cur.inactive_file,
        json_str(&format!("/{name}")),
        json_str(&id_of(name)),
        networks.join(",")
    )
}

/// `GET /containers/{id}/stats`: `stream=false` answers one reading with the one a second before it
/// as `precpu_stats` (none with `one-shot`), which is how Docker's daemon answers and what `docker
/// stats --no-stream` computes its CPU% from; a stream sends one a second until the box ends or
/// the client goes.
fn container_stats(bin: &Path, req: &Request, id: &str) -> Response {
    let Some(name) = resolve(bin, id) else {
        return error(404, &format!("No such container: {id}"));
    };
    let stream = !matches!(req.param("stream"), Some("0" | "false" | "False"));
    let one_shot = req.flag("one-shot");
    let Some(first) = sample(bin, &name) else {
        return error(409, &format!("Container {id} is not running"));
    };
    if !stream {
        if one_shot {
            return json_response(200, stats_json(&name, &first, None));
        }
        std::thread::sleep(Duration::from_secs(1));
        let Some(cur) = sample(bin, &name) else {
            return json_response(200, stats_json(&name, &first, None));
        };
        return json_response(200, stats_json(&name, &cur, Some(&first)));
    }
    let bin = bin.to_path_buf();
    Response::Stream {
        status: 200,
        content_type: "application/json",
        upgrade: false,
        extra: Vec::new(),
        writer: Box::new(move |w: &mut crate::Out| {
            let mut pre: Option<Sample> = None;
            let mut cur = Some(first);
            while let Some(s) = cur {
                let line = format!("{}\n", stats_json(&name, &s, pre.as_ref()));
                if w.write_all(line.as_bytes())
                    .and_then(|()| w.flush())
                    .is_err()
                {
                    return;
                }
                pre = Some(s);
                std::thread::sleep(Duration::from_secs(1));
                cur = sample(&bin, &name);
            }
        }),
    }
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

/// The same for `PUT`, where only a missing DESTINATION is Docker's 404. An archive entry that
/// fails on its way in (a member under a link that resolves, inside the box, to nothing) is named
/// by kern and is the 500 Docker gives for an extraction error: answering "Could not find the file
/// /tmp" for a `/tmp` that exists sent the reader looking for the wrong thing.
fn put_refusal(id: &str, path: &str, why: &str) -> Response {
    if why.contains("no such directory in the box") {
        return error(
            404,
            &format!("Could not find the file {path} in container {id}"),
        );
    }
    if why.contains("No such file") {
        return error(500, why);
    }
    copy_refusal(id, path, why)
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
            let copied = child
                .stdout
                .take()
                .map(|mut out| std::io::copy(&mut out, w).is_ok())
                .unwrap_or(false);
            let ended_well = child.wait().is_ok_and(|s| s.success());
            // A COPY THAT FAILED IS NOT ANSWERED AS ONE THAT ENDED. The body is chunked: closing
            // the connection before its last chunk is how the client learns the archive is cut.
            // MEASURED before: a copy kern could not read answered a complete empty stream, and
            // `docker cp` exited 0 with an empty directory.
            if !(copied && ended_well) {
                let _ = w.socket().shutdown(std::net::Shutdown::Both);
            }
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
        return put_refusal(&id, path, &kern_error(&err));
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

/// A build's context directory under kern's CACHE (on disk: a context can be large, and the runtime
/// directory is RAM), removed when the build is done whatever it did.
struct BuildDir(std::path::PathBuf);

impl Drop for BuildDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A `dockerfile` the API names, as a path INSIDE the context: relative, and never climbing out.
fn dockerfile_in_context(p: &str) -> Option<&str> {
    let p = p.trim_start_matches("./");
    let ok = !p.is_empty()
        && !p.starts_with('/')
        && std::path::Path::new(p)
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)));
    ok.then_some(p)
}

/// The `kern build` argv of a `POST /build`'s query, or the refusal a client reads. PURE.
fn build_argv(req: &Request, ctx: &str) -> Result<(Vec<String>, Vec<String>), String> {
    let tags: Vec<String> = req
        .query
        .iter()
        .filter(|(k, v)| k == "t" && !v.is_empty())
        .map(|(_, v)| v.clone())
        .collect();
    if tags.is_empty() {
        return Err("kern builds a named image: give it one (`docker build -t <name>`)".into());
    }
    if req.param("remote").is_some_and(|r| !r.is_empty()) {
        return Err("a remote build context (a URL) is not fetched by kern's Docker API:                     clone it and build the directory"
            .into());
    }
    let file = req
        .param("dockerfile")
        .filter(|f| !f.is_empty())
        .unwrap_or("Dockerfile");
    let Some(file) = dockerfile_in_context(file) else {
        return Err(format!(
            "dockerfile {file:?}: a path inside the build context"
        ));
    };
    let mut argv = vec!["build".to_string(), "--progress".into(), "plain".into()];
    for t in &tags {
        argv.extend(["-t".to_string(), t.clone()]);
    }
    argv.extend(["-f".to_string(), format!("{ctx}/{file}")]);
    if let Some(raw) = req.param("buildargs").filter(|b| !b.is_empty()) {
        let parsed = json::parse(raw).map_err(|e| format!("buildargs: {e}"))?;
        if let Some(obj) = parsed.as_object() {
            for (k, v) in obj {
                let arg = match v.as_str() {
                    Some(v) => format!("{k}={v}"),
                    None => k.clone(),
                };
                argv.extend(["--build-arg".to_string(), arg]);
            }
        }
    }
    if let Some(t) = req.param("target").filter(|t| !t.is_empty()) {
        argv.extend(["--target".to_string(), t.to_string()]);
    }
    if let Some(p) = req.param("platform").filter(|p| !p.is_empty()) {
        argv.extend(["--platform".to_string(), p.to_string()]);
    }
    if req.flag("nocache") {
        argv.push("--no-cache".into());
    }
    argv.push(ctx.to_string());
    Ok((argv, tags))
}

/// `POST /build` (`docker build` with the classic builder, `docker compose build` without buildx,
/// Testcontainers' image from a Dockerfile): the context the client sends, streamed to a directory
/// on disk and unpacked by the system `tar` as `kern build -` unpacks one, then `kern build`, its
/// lines sent as Docker's `{"stream": ...}`, the image's id as its `aux`. MEASURED before: every
/// such build answered 501.
pub(crate) fn image_build(
    req: &Request,
    bin: &Path,
    r: &mut std::io::BufReader<UnixStream>,
    framing: crate::Framing,
) -> Response {
    use std::os::unix::fs::DirBuilderExt;
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let Some(cache) = kern_common::xdg_cache_dir() else {
        return error(500, "no cache directory for the build context");
    };
    let root = cache.join("kern").join("compat-build");
    if let Err(e) = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&root)
    {
        return error(500, &format!("build context: {}: {e}", root.display()));
    }
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = BuildDir(root.join(format!("{}-{n}", std::process::id())));
    let _ = std::fs::remove_dir_all(&dir.0);
    let ctx = dir.0.join("context");
    if let Err(e) = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&ctx)
    {
        return error(500, &format!("build context: {}: {e}", ctx.display()));
    }
    let tar = dir.0.join("context.tar");
    let copied = std::fs::File::create(&tar)
        .map_err(|_| "the build context could not be written")
        .and_then(|mut f| crate::copy_body(r, framing, &mut f));
    match copied {
        Err(why) => return error(400, why),
        Ok(Err(e)) => return error(500, &format!("build context: {e}")),
        Ok(Ok(_)) => {}
    }
    let (argv, tags) = match build_argv(req, &ctx.to_string_lossy()) {
        Ok(a) => a,
        Err(why) => return error(400, &why),
    };
    let head = {
        let mut h = [0u8; 2];
        std::fs::File::open(&tar)
            .and_then(|mut f| f.read_exact(&mut h))
            .map(|()| h)
            .unwrap_or_default()
    };
    // Unpacked without the archive's owners and permissions, as `kern build -` unpacks one.
    let unpacked = Command::new("tar")
        .arg(if head == [0x1f, 0x8b] { "-xzf" } else { "-xf" })
        .arg(&tar)
        .args(["--no-same-owner", "--no-same-permissions", "-C"])
        .arg(&ctx)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    let _ = std::fs::remove_file(&tar);
    if !unpacked {
        return error(400, "the build context is not a tar archive tar can unpack");
    }
    // ONE PIPE FOR BOTH STREAMS, so the client reads kern's lines in the order they were written.
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return error(
            500,
            &format!("build: a pipe: {}", std::io::Error::last_os_error()),
        );
    }
    // SAFETY: `pipe2` returned these two descriptors, owned by nothing else from here on.
    let (rd, wr) = unsafe {
        use std::os::fd::FromRawFd;
        (
            std::fs::File::from_raw_fd(fds[0]),
            std::fs::File::from_raw_fd(fds[1]),
        )
    };
    let child = wr.try_clone().and_then(|wr2| {
        Command::new(bin)
            .args(&argv)
            .stdin(Stdio::null())
            .stdout(wr)
            .stderr(wr2)
            .spawn()
    });
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return error(500, &format!("cannot run {}: {e}", bin.display())),
    };
    let bin = bin.to_path_buf();
    let labels = req
        .param("labels")
        .is_some_and(|l| !matches!(l.trim(), "" | "{}" | "null"));
    // `docker build -q`: the id alone, as Docker's daemon sends no step output for it.
    let quiet = req.flag("q");
    Response::Stream {
        status: 200,
        content_type: "application/json",
        upgrade: false,
        extra: Vec::new(),
        writer: Box::new(move |w: &mut crate::Out| {
            let _dir = dir;
            let send = |w: &mut crate::Out, line: &str| {
                let _ = w.write_all(format!("{{\"stream\":{}}}\r\n", json_str(line)).as_bytes());
            };
            if labels {
                send(
                    w,
                    "kern: the build's labels are not applied (kern build sets none)\n",
                );
            }
            let mut last = String::new();
            for line in std::io::BufRead::lines(std::io::BufReader::new(rd)) {
                let Ok(line) = line else { break };
                if !quiet {
                    send(w, &format!("{line}\n"));
                }
                if !line.trim().is_empty() {
                    last = line;
                }
            }
            let ok = child.wait().is_ok_and(|s| s.success());
            // The id `docker images` and `docker inspect` give the image, from the same function.
            let id = cached_image(&bin, &tags[0])
                .and_then(|i| image_entry_id(&i))
                .map(|id| format!("sha256:{id}"));
            match (ok, id) {
                (true, Some(id)) => {
                    let _ = w.write_all(
                        format!("{{\"aux\":{{\"ID\":{}}}}}\r\n", json_str(&id)).as_bytes(),
                    );
                    let short = id
                        .trim_start_matches("sha256:")
                        .chars()
                        .take(12)
                        .collect::<String>();
                    // Quiet, Docker's daemon sends the id as the one stream line, and the client
                    // prints that line.
                    if quiet {
                        send(w, &format!("{id}\n"));
                    } else {
                        send(w, &format!("Successfully built {short}\n"));
                        for t in &tags {
                            send(w, &format!("Successfully tagged {t}\n"));
                        }
                    }
                }
                _ => {
                    let msg = if last.is_empty() {
                        "the build failed".to_string()
                    } else {
                        last
                    };
                    let _ = w.write_all(
                        format!(
                            "{{\"errorDetail\":{{\"message\":{m}}},\"error\":{m}}}\r\n",
                            m = json_str(&msg)
                        )
                        .as_bytes(),
                    );
                }
            }
        }),
    }
}

/// `GET /images/get?names=` and `GET /images/{name}/get` (`docker save`): `kern save`, its archive
/// streamed as it is written, so an image of any size is not held here; several names are one
/// archive, as Docker's. MEASURED before: `docker save` through kern's socket answered "not served
/// by kern's Docker API", and then, served, refused more than one image.
fn image_save(bin: &Path, names: &[String]) -> Response {
    if names.is_empty() {
        return error(400, "no image to save");
    }
    for name in names {
        if cached_image(bin, name).is_none() {
            return error(404, &format!("reference does not exist: {name}"));
        }
    }
    let child = Command::new(bin)
        .arg("save")
        .args(names)
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
        extra: Vec::new(),
        writer: Box::new(move |w: &mut crate::Out| {
            let copied = child
                .stdout
                .take()
                .map(|mut out| std::io::copy(&mut out, w).is_ok())
                .unwrap_or(false);
            // A save that failed is cut, not ended: see `archive_get`.
            if !(copied && child.wait().is_ok_and(|s| s.success())) {
                let _ = w.socket().shutdown(std::net::Shutdown::Both);
            }
        }),
    }
}

/// `DELETE /images/{name}`: `kern rmi`, `force` as `-f`. Docker's answer lists what went: the tag,
/// then the image. An image a container uses is 409 without `force`, as Docker answers it.
fn image_remove(bin: &Path, name: &str, req: &Request) -> Response {
    let Some(i) = cached_image(bin, name) else {
        return error(404, &format!("No such image: {name}"));
    };
    let n = i.get("image").and_then(Value::as_str).unwrap_or(name);
    // ANOTHER PLATFORM'S ENTRY BY ITS CACHE NAME, which `kern rmi` takes: by the tag it would be
    // this machine's entry that went.
    let target = match (
        image_entry_platform(&i),
        i.get("cache").and_then(Value::as_str),
    ) {
        (Some(_), Some(cache)) => cache,
        (Some(p), None) => {
            return error(
                500,
                &format!("kern lists the {p} entry of {n} without its cache name: not removed"),
            )
        }
        (None, _) => n,
    };
    let mut args = vec!["rmi"];
    if req.flag("force") {
        args.push("-f");
    }
    args.push(target);
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
            json_str(&format!(
                "sha256:{}",
                image_entry_id(&i).unwrap_or_else(|| id_of(n))
            ))
        ),
    )
}

/// `POST /images/{name}/tag?repo=R&tag=T`: `kern tag`, the source by name or id, `latest` for no
/// tag, and Docker's 201. MEASURED before: `docker tag` through kern's socket answered "not served
/// by kern's Docker API", which a build-tag-push script meets at its second line.
fn image_tag(bin: &Path, name: &str, req: &Request) -> Response {
    let Some(repo) = req.param("repo").filter(|r| !r.is_empty()) else {
        return error(400, "repo is required");
    };
    let tag = req
        .param("tag")
        .filter(|t| !t.is_empty())
        .unwrap_or("latest");
    // A reference, never a flag: Docker's characters, and nothing that starts with `-`.
    let ok = |s: &str, extra: &[u8]| {
        !s.starts_with(['-', '.', '/'])
            && s.len() <= 255
            && s.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'.' | b'_' | b'-')
                    || extra.contains(&b)
            })
    };
    if !ok(repo, b"/:") || !ok(tag, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ") || tag.len() > 128 {
        return error(400, &format!("invalid reference format: {repo}:{tag}"));
    }
    let Some(i) = cached_image(bin, name) else {
        return error(404, &format!("No such image: {name}"));
    };
    // Another platform's entry by that platform: by the tag alone it would be this machine's entry
    // that gets the new name.
    let src = i.get("image").and_then(Value::as_str).unwrap_or(name);
    let dst = format!("{repo}:{tag}");
    let mut args = vec!["tag"];
    if let Some(p) = image_entry_platform(&i) {
        args.extend(["--platform", p]);
    }
    args.extend([src, dst.as_str()]);
    let (code, _, err) = kern(bin, &args);
    if code != 0 {
        return error(500, &kern_error(&err));
    }
    Response::Full {
        status: 201,
        content_type: "text/plain",
        body: Vec::new(),
        extra: Vec::new(),
    }
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
    // Another platform's entry is asked for by that platform, or kern answers this machine's.
    let mut args = vec!["inspect", "--json"];
    if let Some(p) = image_entry_platform(&i) {
        args.extend(["--platform", p]);
    }
    args.push(n);
    let (code, out, err) = kern(bin, &args);
    match image_object_members(&out) {
        Some(members) if code == 0 => json_response(
            200,
            format!(
                // `RepoDigests` is in kern's own object, with the tags.
                "{{\"Id\":{},\"Created\":{},{members}}}",
                json_str(&format!(
                    "sha256:{}",
                    image_entry_id(&i).unwrap_or_else(|| id_of(n))
                )),
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
            remove_container(bin, &name, true);
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
        remove_container(bin, &name, true);
    }
    no_content()
}

/// Remove `name` whatever its state: created, running (stopped at once, when `running`) or ended;
/// then Docker's `destroy`.
/// The networks a create's argv names (`--network`, past the builtins), in order.
pub(crate) fn argv_networks(argv: &[String]) -> Vec<String> {
    argv.windows(2)
        .filter(|w| w[0] == "--network")
        .map(|w| w[1].clone())
        .filter(|n| !matches!(n.as_str(), "host" | "none") && !n.starts_with("container:"))
        .collect()
}

/// A create's argv with its networks made one box's. On networks of a compose project (see
/// `projnet`) each is attached with the aliases its endpoint asked for, taking an address on that
/// network's bridge, and the aliases leave the argv: the project's records carry them. On one
/// network of any other kind nothing changes. Several networks that are not one project's are
/// refused by name, a box being in one pod.
fn projnet_argv(
    bin: &Path,
    name: &str,
    argv: Vec<String>,
    body: &Value,
) -> Result<Vec<String>, String> {
    let nets = argv_networks(&argv);
    let Some(first) = nets.first() else {
        return Ok(argv);
    };
    if crate::projnet::get(first).is_none() {
        if let Some(other) = nets.get(1) {
            return Err(format!(
                "NetworkingConfig names {other:?} beside {first:?}: kern's Docker API puts a \
                 container on several networks when they are one compose project's, and a box \
                 is in one pod otherwise. For such a file, `kern compose -f <file> up` runs it"
            ));
        }
        return Ok(argv);
    }
    let endpoints = body
        .get("NetworkingConfig")
        .and_then(|n| n.get("EndpointsConfig"))
        .and_then(Value::as_object)
        .unwrap_or_default();
    for (i, net) in nets.iter().enumerate() {
        let ep = endpoints.iter().find(|(k, _)| k == net).map(|(_, v)| v);
        let aliases = crate::netvol::endpoint_aliases(ep, name);
        crate::projnet::attach(bin, net, name, &aliases, &nets[..i])?.ok_or_else(|| {
            format!("network {net} is not a network of the same compose project as {first}")
        })?;
    }
    let mut out = Vec::with_capacity(argv.len());
    let mut it = argv.into_iter();
    while let Some(a) = it.next() {
        if a == "--network-alias" {
            let _ = it.next();
            continue;
        }
        out.push(a);
    }
    Ok(out)
}

fn remove_container(bin: &Path, name: &str, running: bool) {
    crate::projnet::detach_everywhere(bin, name);
    session_forget(name);
    stage_forget(name);
    net_forget(name);
    id_forget(name);
    if created_take(name).is_some() {
        // A pending attach ends with the container.
        drop(attached_take(name));
        // A start that failed may have left kern a box under this name (a kept layer, an exit
        // record): removed with the container, or `ps -a` keeps showing it.
        let _ = kern(bin, &["rm", "-f", name]);
    } else {
        if running {
            if die_pending(name) {
                crate::events::publish_named("kill", name, None);
            }
            let _ = kern(bin, &["stop", "-t", "0", name]);
            // The reaper of a box this server started publishes its `die` once the box is down.
            run_ended_within(name, DIE_FIRST);
            die_within(name, DIE_FIRST);
        }
        // An attached run that ended: forgotten here, and its kept layer, if it has one, is
        // removed like any other container's.
        run_forget(name);
        let _ = kern(bin, &["rm", "-f", name]);
    }
    watch_forget(name);
    crate::events::destroyed(name);
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

/// Is `name` a box this server started for an attach, still running?
fn run_attached(name: &str) -> bool {
    RUNS.lock().ok().is_some_and(|g| {
        g.as_ref()
            .and_then(|m| m.get(name))
            .is_some_and(|r| r.exit.is_none())
    })
}

fn run_forget(name: &str) {
    if let Ok(mut g) = RUNS.lock() {
        if let Some(m) = g.as_mut() {
            m.remove(name);
        }
    }
}

/// Wait up to `limit` for the end of `name`, if this server started it; at once otherwise.
fn run_ended_within(name: &str, limit: Duration) {
    let Ok(mut g) = RUNS.lock() else {
        return;
    };
    let deadline = Instant::now() + limit;
    while g
        .as_ref()
        .and_then(|m| m.get(name))
        .is_some_and(|r| r.exit.is_none())
    {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        match RUN_ENDED.wait_timeout(g, left) {
            Ok((next, _)) => g = next,
            Err(_) => return,
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
    let mut command = Command::new(bin);
    let size_file = c.tty.then(|| tty_prepare(name, None)).flatten();
    if let Some(f) = &size_file {
        command.env("KERN_TTY_SIZE_FILE", f);
    }
    let mut child = match command
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
    if size_file.is_some() {
        tty_register(name, child.id());
    }
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
            tty_forget(&watched);
            crate::events::publish(&event_of("die", &watched, &created, Some(code)));
            run_end(&watched, code);
        });
    if reaper.is_err() {
        run_end(name, -1);
    }
    no_content()
}

// ---------------------------------------------------------------------------------------------
// Terminal sizes: `docker exec -it` and `docker run -it` resizes, onto `KERN_TTY_SIZE_FILE`.

/// The terminals this server's clients drive: an exec id or a container name, and the pid of the
/// `kern` that sizes that terminal from its file on `SIGWINCH`.
static TTYS: Mutex<Option<HashMap<String, u32>>> = Mutex::new(None);

/// The size file of terminal `key`: `$XDG_CACHE_HOME/kern/compat-tty/<key>` (an exec id is hex, a
/// container name a valid name, so the key is one path component).
fn tty_file(key: &str) -> Option<std::path::PathBuf> {
    // Not `valid_name`: an exec id is 64 hex digits, one past a box name's 63.
    let one_component = !key.is_empty()
        && key.len() <= 128
        && !key.starts_with('.')
        && key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.');
    one_component.then_some(())?;
    Some(
        kern_common::xdg_cache_dir()?
            .join("kern")
            .join("compat-tty")
            .join(key),
    )
}

/// Write `COLSxROWS` to `key`'s size file, atomically (a `kern` reading it on `SIGWINCH` sees the
/// old size or the new one, never half of one).
fn tty_write(key: &str, cols: u16, rows: u16) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let f = tty_file(key)?;
    let dir = f.parent()?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .ok()?;
    let tmp = dir.join(format!(".{key}.new"));
    std::fs::write(&tmp, format!("{cols}x{rows}")).ok()?;
    std::fs::rename(&tmp, &f).ok()?;
    Some(f)
}

/// A size file for a terminal about to start: `size` is Docker's `ConsoleSize` (`[rows, cols]`),
/// 80x24 without one; the client sends its real size in a resize right after.
fn tty_prepare(key: &str, size: Option<(u16, u16)>) -> Option<std::path::PathBuf> {
    let (rows, cols) = size.unwrap_or((24, 80));
    tty_write(key, cols, rows)
}

fn tty_register(key: &str, pid: u32) {
    if let Ok(mut g) = TTYS.lock() {
        g.get_or_insert_with(HashMap::new)
            .insert(key.to_string(), pid);
    }
}

fn tty_forget(key: &str) {
    if let Ok(mut g) = TTYS.lock() {
        if let Some(m) = g.as_mut() {
            m.remove(key);
        }
    }
    if let Some(f) = tty_file(key) {
        let _ = std::fs::remove_file(f);
    }
}

/// `POST /exec/{id}/resize` and `/containers/{id}/resize` (`h`, `w`): the new size in the file,
/// then `SIGWINCH` to the `kern` that sizes the terminal, which pushes it to the pty, and the
/// kernel signals the program in the box. A terminal this server is not driving (no `-t`, or a
/// box started elsewhere) has nothing to resize, which Docker also answers with 200.
fn tty_resize(key: &str, req: &Request) -> Response {
    let dim = |k: &str| req.param(k).and_then(|v| v.parse::<u16>().ok());
    let (Some(rows), Some(cols)) = (dim("h"), dim("w")) else {
        return error(400, "resize needs h and w, the terminal's rows and columns");
    };
    let pid = TTYS
        .lock()
        .ok()
        .and_then(|g| g.as_ref().and_then(|m| m.get(key).copied()));
    if let Some(pid) = pid {
        if tty_write(key, cols, rows).is_some() {
            if let Ok(p) = libc::pid_t::try_from(pid) {
                // SAFETY: a signal to a pid this server started and still records; a reaped pid
                // was removed from the table when its run or exec ended.
                unsafe { libc::kill(p, libc::SIGWINCH) };
            }
        }
    }
    Response::Full {
        status: 200,
        content_type: "text/plain",
        body: Vec::new(),
        extra: Vec::new(),
    }
}

/// How long a run's end is left to its attach's follow before `kern wait` waits for it.
const FOLLOW_FIRST: Duration = Duration::from_secs(60);

/// `kern box -d` of a created container, which returns once the box has started, and its `start`
/// event. The `Err` is the answer to give. Its `die` is the caller's: an attach's reaper publishes
/// it, and a detached start arms [`watch_die`].
fn start_detached(bin: &Path, name: &str, c: &Created, argv: &[&str]) -> Result<(), Response> {
    let (code, _, err) = kern(bin, argv);
    if code != 0 {
        return Err(error(500, &kern_error(&err)));
    }
    crate::events::publish(&event_of("start", name, c, None));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// `die` of the boxes started detached: nothing of this server waits on them otherwise.

/// The detached boxes whose `die` is not published yet. A removal or a restart waits for it, so
/// the events follow in Docker's order (`die` before `destroy`, before the next `start`).
static DIE_PENDING: Mutex<Option<std::collections::HashSet<String>>> = Mutex::new(None);
static DIE_PUBLISHED: Condvar = Condvar::new();

/// The containers watched past each `die` (a `--restart always` or `unless-stopped` one, see
/// [`watch_die_with`]), and of those the ones a `docker restart` is restarting now: that watch
/// publishes the `die` and leaves the next run to the restart, which says `stop`, `start` and
/// `restart` and watches it. MEASURED before: `docker restart` of such a container printed `kill die
/// start restart start`, the watch's own `start` after the restart's, where Docker's is `kill die
/// stop start restart`.
static FOREVER: Mutex<Option<std::collections::HashSet<String>>> = Mutex::new(None);
static API_RESTART: Mutex<Option<std::collections::HashSet<String>>> = Mutex::new(None);

fn in_set(set: &Mutex<Option<std::collections::HashSet<String>>>, name: &str) -> bool {
    set.lock()
        .ok()
        .is_some_and(|g| g.as_ref().is_some_and(|s| s.contains(name)))
}

fn set_in(set: &Mutex<Option<std::collections::HashSet<String>>>, name: &str, on: bool) {
    if let Ok(mut g) = set.lock() {
        let s = g.get_or_insert_with(Default::default);
        if on {
            s.insert(name.to_string());
        } else {
            s.remove(name);
        }
    }
}

/// How long a removal or a restart waits for the `die` of the box it stopped.
const DIE_FIRST: Duration = Duration::from_secs(3);

/// kern's `attempt/` directory, where a detached box's supervisor records each run and each exit
/// it restarts after. Given by the CLI (`serve`), which resolves kern's runtime root; without it
/// no restart is reported, and the end of the box still is.
static ATTEMPTS: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

pub(crate) fn set_attempt_dir(dir: std::path::PathBuf) {
    let _ = ATTEMPTS.set(dir);
}

/// A thread pinned by a pidfd to the box's supervisor, which exits with the box and leaves its exit
/// record: woken at the exit, it reads the code and publishes `die`. No `kern wait` stays resident
/// for the box's life. MEASURED before: `docker events` on kern's socket printed no `die` for a
/// `docker run -d`, not at its exit, not at a `stop`, not at an `rm -f`.
///
/// AND EACH RESTART IN BETWEEN: a `--restart` box is run again by the same supervisor, which
/// records the exit and the next run in its attempt file; the thread wakes on that file too
/// (inotify) and publishes the run's `die` and the next `start`, as Docker does. MEASURED against
/// Docker 29, `on-failure:2` exiting 3: `create start die 3 start die 3 start die 3 destroy`, where
/// kern's socket printed `create start die 3 destroy`.
///
/// One watch per box: a second call for a box already watched does nothing. `supervisor` when the
/// caller has it, else it is looked up.
fn watch_die(bin: &Path, name: &str, auto_remove: bool, supervisor: Option<libc::pid_t>) {
    watch_die_with(bin, name, auto_remove, supervisor, false);
}

/// [`watch_die`], and with `forever` (a `--restart always` or `unless-stopped` container) on past
/// each `die`: systemd runs such a box again with a new supervisor, whose run is Docker's next
/// `start`, watched the same way. MEASURED before: such a container's stream was `create start die
/// destroy` while systemd ran it ten times, where Docker's is a `start` and a `die` per run.
fn watch_die_with(
    bin: &Path,
    name: &str,
    auto_remove: bool,
    supervisor: Option<libc::pid_t>,
    forever: bool,
) {
    let fresh = DIE_PENDING.lock().is_ok_and(|mut g| {
        g.get_or_insert_with(Default::default)
            .insert(name.to_string())
    });
    if !fresh {
        return;
    }
    set_in(&FOREVER, name, forever);
    let (bin, watched) = (bin.to_path_buf(), name.to_string());
    let gen = watch_gen(name);
    let spawned = std::thread::Builder::new()
        .name("kern-serve-die".into())
        .stack_size(256 << 10)
        .spawn(move || {
            let mut supervisor = supervisor.or_else(|| {
                kern_boxes(&bin)
                    .into_iter()
                    .find(|(n, v)| *n == watched && box_running(v))
                    .and_then(|(_, v)| supervisor_of(&v))
            });
            loop {
                // A box already down has its record; without a pidfd (a kernel before 5.3, or the
                // supervisor gone) `kern wait` below is the wait.
                if let Some((pid, fd)) = supervisor.and_then(|p| pidfd_open(p).map(|fd| (p, fd))) {
                    follow_restarts(&watched, pid, &fd);
                }
                // By the name the box has now: a rename while it ran moved it.
                let now = current_name(&watched);
                // Removed meanwhile: its `die` went before its `destroy`, or there is none to say.
                if watch_gen(&now) != gen {
                    break;
                }
                let code = if auto_remove {
                    kern_wait_code_with(&bin, "__wait-removed", &now)
                } else {
                    kern_wait_code(&bin, &now)
                };
                // A run systemd restarts leaves its code where `kern ps -a` reads it, and not always
                // where `kern wait` looks first (MEASURED: the first `die` said -1, Docker's 1).
                let code = if code < 0 {
                    kern_boxes(&bin)
                        .into_iter()
                        .find(|(n, _)| *n == now)
                        .and_then(|(_, v)| v.get("exit_code").and_then(Value::as_i64))
                        .and_then(|c| i32::try_from(c).ok())
                        .unwrap_or(code)
                } else {
                    code
                };
                // Asked BEFORE the `die` is settled, which is what wakes a restart waiting for it.
                let follow = forever && !in_set(&API_RESTART, &now);
                crate::events::publish_named("die", &now, Some(code));
                die_settled(&now);
                let next = if follow {
                    next_supervisor(&bin, &now, supervisor, gen)
                } else {
                    None
                };
                let Some(next) = next else { break };
                if watch_gen(&now) != gen {
                    break;
                }
                // Pending again, for the run systemd started.
                if let Ok(mut g) = DIE_PENDING.lock() {
                    g.get_or_insert_with(Default::default).insert(now.clone());
                }
                crate::events::publish_named("start", &now, None);
                supervisor = Some(next);
            }
            if let Ok(mut g) = RENAMED.lock() {
                if let Some(m) = g.as_mut() {
                    m.remove(&watched);
                }
            }
        });
    if spawned.is_err() {
        die_settled(name);
    }
}

/// The supervisor of the next run systemd starts for `name` that is still running when looked at,
/// a different one from `before`; `None` once the container is gone (stopped or removed, which
/// removes its unit). A run that ends before it is seen (a command that exits at once, run again
/// every second) is still Docker's `start` and `die`: read off the unit's restart count, which
/// `kern ps` reports, with the code the run left. Looked at twice a second, and only for a
/// container systemd restarts that is between two runs.
fn next_supervisor(
    bin: &Path,
    name: &str,
    before: Option<libc::pid_t>,
    gen: u64,
) -> Option<libc::pid_t> {
    let count_of = |v: &Value| v.get("restart_count").and_then(Value::as_i64).unwrap_or(0);
    let mut counted: Option<i64> = None;
    let mut missing = 0;
    loop {
        // The container was removed, and the name may be another one's now.
        if watch_gen(name) != gen {
            return None;
        }
        // Gone only when missing three looks in a row: between two runs, as one supervisor leaves
        // and systemd starts the next, the name can be absent from `kern ps -a` for a moment.
        let Some(row) = kern_boxes(bin)
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v)
        else {
            missing += 1;
            if missing >= 3 {
                return None;
            }
            std::thread::sleep(Duration::from_millis(500));
            continue;
        };
        missing = 0;
        let restarting = row.get("status").and_then(Value::as_str) == Some("restarting");
        if box_running(&row) && !restarting {
            if let Some(p) = supervisor_of(&row).filter(|p| Some(*p) != before) {
                return Some(p);
            }
        }
        let now = count_of(&row);
        if let Some(seen) = counted {
            let code = row
                .get("exit_code")
                .and_then(Value::as_i64)
                .and_then(|c| i32::try_from(c).ok());
            for _ in seen..now {
                crate::events::publish_named("start", name, None);
                crate::events::publish_named("die", name, code);
            }
        }
        counted = Some(now);
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Does this create's argv run the box under a policy systemd restarts forever (`--restart always`
/// or `unless-stopped`)?
fn restarts_forever(argv: &[String]) -> bool {
    argv.windows(2)
        .any(|w| w[0] == "--restart" && matches!(w[1].as_str(), "always" | "unless-stopped"))
}

/// The supervisor's pid of a box as `kern ps --json` lists it.
fn supervisor_of(v: &Value) -> Option<libc::pid_t> {
    v.get("pid")
        .and_then(Value::as_i64)
        .and_then(|p| libc::pid_t::try_from(p).ok())
}

/// Until the supervisor exits: each change of its attempt record publishes what it means.
fn follow_restarts(name: &str, pid: libc::pid_t, pidfd: &std::os::fd::OwnedFd) {
    use std::os::fd::AsRawFd;
    let file = ATTEMPTS.get().map(|d| d.join(format!("{name}-{pid}")));
    // Watched BEFORE the first read, so a change between the read and the wait is queued.
    let inotify = ATTEMPTS.get().and_then(|d| attempt_inotify(d));
    let mut seen = Published::default();
    loop {
        if let Some(a) = file
            .as_ref()
            .and_then(|f| std::fs::read_to_string(f).ok())
            .and_then(|t| kern_common::attempt::Attempt::parse(&t))
        {
            if let Some((action, exit)) = seen.next(a) {
                crate::events::publish_named(action, &current_name(name), exit);
            }
        }
        let mut fds = [
            libc::pollfd {
                fd: pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: inotify.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: two pollfds owned here (a negative fd is ignored), no timeout.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if fds[0].revents != 0 {
            return;
        }
        if let Some(fd) = &inotify {
            let mut buf = [0u8; 4096];
            // SAFETY: a nonblocking inotify descriptor owned here and a buffer of that length.
            while unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
        }
    }
}

/// An inotify on the attempt directory, for the supervisor's atomic replace of a record.
fn attempt_inotify(dir: &std::path::Path) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: `inotify_init1` takes flags and returns a new descriptor or -1.
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if fd < 0 {
        return None;
    }
    // SAFETY: a descriptor just returned to this process and owned by nothing else.
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    // SAFETY: a live inotify descriptor and a NUL-terminated path.
    let w = unsafe {
        libc::inotify_add_watch(
            fd.as_raw_fd(),
            c.as_ptr(),
            libc::IN_MOVED_TO | libc::IN_CLOSE_WRITE | libc::IN_ONLYDIR,
        )
    };
    (w >= 0).then_some(fd)
}

/// What a box's restarts have published so far: the restart whose exit was reported, and the
/// restart count of the last run whose start was (0, the first run's, by the start itself).
#[derive(Default)]
struct Published {
    died_for: Option<u32>,
    started: u32,
}

impl Published {
    /// The event a record now means, once: `die` with the code of a run that ended for a restart,
    /// `start` of a run after one.
    fn next(&mut self, a: kern_common::attempt::Attempt) -> Option<(&'static str, Option<i32>)> {
        use kern_common::attempt::Attempt;
        match a {
            Attempt::Restarting { code, restarts, .. } if self.died_for != Some(restarts) => {
                self.died_for = Some(restarts);
                Some(("die", Some(code)))
            }
            Attempt::Running { restarts, .. } if restarts > self.started => {
                self.started = restarts;
                Some(("start", None))
            }
            _ => None,
        }
    }
}

/// The running boxes whose `die` nothing watches, armed when a client opens `/events`. A server
/// started again (idle, or a new binary) has lost the watches the one before it armed, and a box
/// started with kern directly never had one: Docker's stream reports every container's end, so
/// this one does, with the image and labels `kern ps` lists. Only while someone listens: a box
/// nobody follows costs nothing.
pub(crate) fn watch_unwatched(bin: &Path) {
    for (n, v) in kern_boxes(bin) {
        // An attached run's box has its reaper, which publishes its `die`.
        if !box_running(&v) || die_pending(&n) || run_attached(&n) {
            continue;
        }
        crate::events::remember(
            &n,
            v.get("image").and_then(Value::as_str).unwrap_or_default(),
            labels_of(&v),
        );
        // `__wait-removed` also answers for a `--rm` box, which `ps` does not mark.
        watch_die(bin, &n, true, supervisor_of(&v));
    }
}

/// How many times a container of each name was removed: a watch belongs to the generation it was
/// armed in, and one of a removed container stops instead of following the next container that
/// takes the name (MEASURED before: `docker rm -f x` then `docker run --restart always --name x`
/// left the new one with no watch at all, the old one's pending `die` standing in for it).
static WATCH_GEN: Mutex<Option<HashMap<String, u64>>> = Mutex::new(None);

fn watch_gen(name: &str) -> u64 {
    WATCH_GEN
        .lock()
        .ok()
        .and_then(|g| g.as_ref().and_then(|m| m.get(name).copied()))
        .unwrap_or(0)
}

/// `name` was removed: its watch, if one runs, is of a container that is gone.
fn watch_forget(name: &str) {
    if let Ok(mut g) = WATCH_GEN.lock() {
        *g.get_or_insert_with(HashMap::new)
            .entry(name.to_string())
            .or_insert(0) += 1;
    }
    set_in(&FOREVER, name, false);
    die_settled(name);
}

/// The containers renamed while their `die` was watched, old name to new: the watch reads the box's
/// code and publishes under the name it has NOW (`kern wait` by the old one finds nothing).
static RENAMED: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

/// The name `name` goes by now, following renames (bounded, a cycle cannot hang it).
fn current_name(name: &str) -> String {
    let Ok(g) = RENAMED.lock() else {
        return name.to_string();
    };
    let mut now = name.to_string();
    for _ in 0..16 {
        match g.as_ref().and_then(|m| m.get(&now)) {
            Some(next) => now.clone_from(next),
            None => break,
        }
    }
    now
}

/// `old` is now `new`: its pending `die` and its watch follow it, and its events carry the new name.
fn watch_renamed(old: &str, new: &str) {
    if let Ok(mut g) = RENAMED.lock() {
        g.get_or_insert_with(HashMap::new)
            .insert(old.to_string(), new.to_string());
    }
    if let Ok(mut g) = DIE_PENDING.lock() {
        if let Some(s) = g.as_mut() {
            if s.remove(old) {
                s.insert(new.to_string());
            }
        }
    }
    if in_set(&FOREVER, old) {
        set_in(&FOREVER, old, false);
        set_in(&FOREVER, new, true);
    }
    crate::events::renamed(old, new);
}

fn die_pending(name: &str) -> bool {
    DIE_PENDING
        .lock()
        .ok()
        .is_some_and(|g| g.as_ref().is_some_and(|s| s.contains(name)))
}

fn die_settled(name: &str) {
    if let Ok(mut g) = DIE_PENDING.lock() {
        if let Some(s) = g.as_mut() {
            s.remove(name);
        }
    }
    DIE_PUBLISHED.notify_all();
}

/// Wait up to `limit` for the `die` of `name`, if one is pending.
fn die_within(name: &str, limit: Duration) {
    let Ok(mut g) = DIE_PENDING.lock() else {
        return;
    };
    let deadline = Instant::now() + limit;
    while g.as_ref().is_some_and(|s| s.contains(name)) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        match DIE_PUBLISHED.wait_timeout(g, left) {
            Ok((next, _)) => g = next,
            Err(_) => return,
        }
    }
}

fn pidfd_open(pid: libc::pid_t) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    if pid <= 0 {
        return None;
    }
    // SAFETY: `pidfd_open(pid, 0)` takes two integers and returns a new descriptor or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    let fd = std::os::fd::RawFd::try_from(fd).ok().filter(|f| *f >= 0)?;
    // SAFETY: a descriptor the kernel just returned to this process, owned by nothing else.
    Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
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
        action: "start".into(),
        name: name.to_string(),
        image: v
            .get("image")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        labels: labels_of(&v),
        exit: None,
    });
    watch_die(bin, name, false, None);
    no_content()
}

/// The event of a container this server made.
fn event_of(action: &str, name: &str, c: &Created, exit: Option<i32>) -> crate::events::Event {
    crate::events::Event {
        action: action.to_string(),
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
    let claimed = {
        let mut g = EXECS.lock().ok()?;
        let e = g.as_mut()?.get_mut(id)?;
        if e.started {
            return None;
        }
        e.started = true;
        e.running = true;
        e.clone()
    };
    crate::events::exec_event("exec_start", &claimed.name, &claimed.cmd, id, None);
    Some(claimed)
}

fn exec_finish(id: &str, code: i32) {
    let ended = EXECS.lock().ok().and_then(|mut g| {
        let e = g.as_mut()?.get_mut(id)?;
        e.running = false;
        e.exit = Some(code);
        Some((e.name.clone(), e.cmd.clone()))
    });
    if let Some((name, cmd)) = ended {
        crate::events::exec_event("exec_die", &name, &cmd, id, Some(code));
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
                    cmd: cmd.clone(),
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
    crate::events::exec_event("exec_create", name, &cmd, &id, None);
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
    // Docker's `ConsoleSize` (`[rows, cols]`): the terminal's size from its first byte.
    let console = body
        .get("ConsoleSize")
        .and_then(Value::as_array)
        .and_then(|a| {
            let n = |i: usize| {
                a.get(i)
                    .and_then(Value::as_i64)
                    .and_then(|x| u16::try_from(x).ok())
            };
            Some((n(0)?, n(1)?)).filter(|&(r, c)| r > 0 && c > 0)
        });
    let size_file = tty.then(|| tty_prepare(&id, console)).flatten();
    if let Some(f) = &size_file {
        cmd.env("KERN_TTY_SIZE_FILE", f);
    }
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
            if size_file.is_some() {
                tty_register(&id, child.id());
            }
            let out = child.stdout.take();
            let err = child.stderr.take();
            let feeder = child.stdin.take().and_then(|sin| feed_stdin(w, sin));
            pump(w, out, err, tty);
            // The exit is recorded BEFORE the feeder ends: a client that has read the end of the
            // output asks for the code at once, and the feeder may wait for that client to go.
            let code = exit_code(&mut child);
            tty_forget(&id);
            exec_finish(&id, code);
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

/// The `kern update` flags of a `POST /containers/{id}/update` body: `Memory` (bytes), the CPU limit
/// (`NanoCpus`, or `CpuQuota` over `CpuPeriod`) and `PidsLimit`, the caps kern changes on a box.
/// Any other field SET to something (a restart policy, a CPU share, a cpuset, a block-IO weight, a
/// swap figure) is refused BY NAME: answering 200 and changing nothing is the "runs and lies" kern
/// refuses everywhere. Zero, `-1` and empty values are not requests. MEASURED before: `docker update
/// --memory 64m` answered 501 while `kern update` existed. PURE.
fn update_args(body: &Value) -> Result<Vec<String>, String> {
    let num = |k: &str| body.get(k).and_then(Value::as_i64).unwrap_or(0);
    let mut flags = Vec::new();
    if num("Memory") > 0 {
        flags.extend(["--memory".to_string(), num("Memory").to_string()]);
    }
    let cpus = match (num("NanoCpus"), num("CpuQuota"), num("CpuPeriod")) {
        (n, _, _) if n > 0 => Some(n as f64 / 1e9),
        (_, q, p) if q > 0 && p > 0 => Some(q as f64 / p as f64),
        _ => None,
    };
    if let Some(c) = cpus {
        flags.extend(["--cpus".to_string(), format!("{c}")]);
    }
    if num("PidsLimit") > 0 {
        flags.extend(["--pids-limit".to_string(), num("PidsLimit").to_string()]);
    }
    let policy_set = body
        .get("RestartPolicy")
        .and_then(|p| p.get("Name"))
        .and_then(Value::as_str)
        .is_some_and(|n| !n.is_empty());
    if policy_set {
        return Err(
            "RestartPolicy: kern's update changes caps, not a restart policy; `docker rm -f` and \
             run the container again with the policy"
                .to_string(),
        );
    }
    for key in [
        "CpuShares",
        "CpusetCpus",
        "CpusetMems",
        "BlkioWeight",
        "MemoryReservation",
        "KernelMemory",
        "CpuRealtimePeriod",
        "CpuRealtimeRuntime",
    ] {
        let set = body.get(key).is_some_and(|v| {
            v.as_i64().is_some_and(|n| n > 0) || v.as_str().is_some_and(|s| !s.is_empty())
        });
        if set {
            return Err(format!(
                "{key}: not a cap kern's update changes; it changes Memory, the CPU limit \
                 (NanoCpus, CpuQuota/CpuPeriod) and PidsLimit"
            ));
        }
    }
    // `MemorySwap` the client sends beside `--memory` (equal to it, or -1) is not a request; a
    // figure beyond the memory asks for swap, which kern's update does not set.
    let swap = num("MemorySwap");
    if swap > 0 && swap != num("Memory") {
        return Err(
            "MemorySwap: kern's update does not change swap; it changes Memory, the CPU limit and \
             PidsLimit"
                .to_string(),
        );
    }
    Ok(flags)
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
                // THE CLASSIC BUILDER, the one `POST /build` serves (Docker says `2`, BuildKit).
                // True, and read by the clients that ask; the docker CLI on Linux hands a build to
                // buildx regardless, which is why `buildx_refusal` exists.
                ("Builder-Version", "1".into()),
            ],
        },
        ("GET", ["version"]) => version(),
        ("GET", ["info"]) => info(bin),
        ("POST", ["_kern", "session-ended"]) => session_ended(bin, req),
        ("GET", ["containers", "json"]) => list(bin, req),
        // KERN HAS NO PLUGINS, so every plugin by name is one that is not there: Docker's 404, which
        // its CLI reads as "no such object" at the end of `docker inspect <name>`'s search (it
        // asks containers, images, networks, volumes, then plugins). MEASURED before: a 501, and
        // `docker inspect` of a removed container printed "GET /plugins/<name>/json: not served".
        ("GET", ["plugins", name, "json"]) => error(404, &format!("plugin \"{name}\" not found")),
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
            if body
                .get("Image")
                .and_then(Value::as_str)
                .is_some_and(is_buildx_builder)
            {
                return buildx_refusal();
            }
            let platform = match req.param("platform").filter(|p| !p.is_empty()) {
                Some(p) if valid_platform(p) => Some(p.to_string()),
                Some(p) => return error(400, &format!("invalid platform: {p:?}")),
                None => None,
            };
            // A network by name must exist, as Docker's create answers 404 for one that does not.
            if let Some(net) = body
                .get("HostConfig")
                .and_then(|h| h.get("NetworkMode"))
                .and_then(Value::as_str)
                .filter(|n| {
                    !matches!(*n, "" | "default" | "bridge" | "host" | "none")
                        && !n.starts_with("container:")
                })
            {
                if !crate::netvol::network_usable(bin, net) {
                    return error(404, &format!("network {net} not found"));
                }
            }
            // AN IMAGE ID FOR `Image`, as the `docker compose` client gives for a service with
            // `platform:`: the cached entry's name, and its platform unless the create names one.
            // MEASURED before: "No such image: sha256:4422...", and the service never started.
            let by_id = image_by_id(bin, &body);
            let platform = platform.or_else(|| by_id.as_ref().and_then(|(_, p)| p.clone()));
            // The GPU gate is read only for a create that asks for a card.
            let wants_gpu = gpu_spec(body.get("HostConfig")).ok().flatten().is_some();
            let gpu_allowed = wants_gpu
                && ["allow_gpu_grants", "allow_device_grants"].iter().any(|k| {
                    let (code, out, _) = kern(bin, &["config", "get", k]);
                    code == 0 && out.trim() == "true"
                });
            // The privilege gate, likewise, only for a create that asks for it.
            let wants_privileged = body
                .get("HostConfig")
                .and_then(|h| h.get("Privileged"))
                .and_then(Value::as_bool)
                == Some(true);
            let privileged_allowed = wants_privileged && {
                let (code, out, _) = kern(bin, &["config", "get", "compose_privileged"]);
                code == 0 && out.trim() == "true"
            };
            match create_argv_gated(&name, &body, gpu_allowed, privileged_allowed)
                .map(|mut c| {
                    // A `VolumesFrom` entry may be a container ID: the box's name for kern.
                    let mut i = 0;
                    while i + 1 < c.argv.len() {
                        if c.argv[i] == "--volumes-from" {
                            let v = c.argv[i + 1].clone();
                            let (id, mode) = match v.rsplit_once(':') {
                                Some((n, m @ ("ro" | "rw"))) => (n.to_string(), format!(":{m}")),
                                _ => (v.clone(), String::new()),
                            };
                            if let Some(n) = resolve(bin, &id) {
                                c.argv[i + 1] = format!("{n}{mode}");
                            }
                            i += 1;
                        }
                        i += 1;
                    }
                    c
                })
                .map(|c| match &by_id {
                    Some((image, _)) => with_image_name(c, image),
                    None => c,
                })
                .map(|c| with_platform(c, platform.as_deref()))
                .and_then(|mut c| {
                    c.argv = projnet_argv(bin, &name, c.argv, &body)?;
                    Ok(c)
                }) {
                Ok(c) => {
                    net_remember(&name, &c.argv);
                    let session = in_session(&c.labels);
                    crate::events::publish(&event_of("create", &name, &c, None));
                    let warnings = c.warnings.clone();
                    created_put(&name, c);
                    if let (true, Some(owner)) = (session, req.peer.clone()) {
                        session_track(bin, &name, owner);
                    }
                    json_response(
                        201,
                        format!(
                            "{{\"Id\":{},\"Warnings\":[{}]}}",
                            json_str(&id_of(&name)),
                            warnings
                                .iter()
                                .map(|w| json_str(w))
                                .collect::<Vec<_>>()
                                .join(",")
                        ),
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
                        Ok(()) => {
                            let forever = restarts_forever(&c.argv);
                            // VISIBLE BEFORE THE ANSWER: systemd starts a `--restart always` box a
                            // moment after its unit is enabled, and until that first run kern lists
                            // no such box. MEASURED before: for about 1.2 s after `docker run -d
                            // --restart always` returned, `docker inspect` answered "No such
                            // container". Waited for here (3 s at most), where nothing holds the box.
                            if forever {
                                let deadline = Instant::now() + Duration::from_secs(3);
                                while Instant::now() < deadline
                                    && !kern_boxes(bin).iter().any(|(n, _)| *n == name)
                                {
                                    std::thread::sleep(Duration::from_millis(100));
                                }
                            }
                            watch_die_with(bin, &name, c.auto_remove, None, forever);
                            no_content()
                        }
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
        ("GET", ["containers", id, "stats"]) => container_stats(bin, req, id),
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
        // `docker update`: kern's own `update`, live on a running box and into a kept box's record.
        ("POST", ["containers", id, "update"]) => match resolve(bin, id) {
            None => error(404, &format!("No such container: {id}")),
            Some(name) => {
                let body = json::parse(&String::from_utf8_lossy(&req.body)).unwrap_or(Value::Null);
                match update_args(&body) {
                    Err(why) => error(400, &why),
                    Ok(flags) if flags.is_empty() => {
                        json_response(200, "{\"Warnings\":[]}".to_string())
                    }
                    Ok(flags) => {
                        let mut args: Vec<&str> = vec!["update"];
                        args.extend(flags.iter().map(String::as_str));
                        args.push(&name);
                        let (code, _, err) = kern(bin, &args);
                        if code == 0 {
                            json_response(200, "{\"Warnings\":[]}".to_string())
                        } else {
                            error(500, &kern_error(&err))
                        }
                    }
                }
            }
        },
        ("POST", ["containers", id, verb @ ("pause" | "unpause")]) => match resolve(bin, id) {
            None => error(404, &format!("No such container: {id}")),
            Some(name) => {
                let (code, _, err) = kern(bin, &[verb, &name]);
                if code == 0 {
                    no_content()
                } else {
                    error(409, &kern_error(&err))
                }
            }
        },
        ("POST", ["containers", id, "rename"]) => {
            let Some(new) = req.param("name").filter(|n| !n.is_empty()) else {
                return error(400, "name is required");
            };
            if !valid_name(new) {
                return error(400, &format!("Invalid container name ({new})"));
            }
            match resolve(bin, id) {
                None => error(404, &format!("No such container: {id}")),
                Some(_) if resolve(bin, new).is_some() => error(
                    409,
                    &format!("Conflict. The container name \"/{new}\" is already in use"),
                ),
                Some(name) => {
                    if created_get(&name).is_some() {
                        id_rename(&name, new);
                        crate::projnet::rename(bin, &name, new);
                        crate::events::renamed(&name, new);
                        return rename_created(&name, new).unwrap_or_else(no_content);
                    }
                    let (code, _, err) = kern(bin, &["rename", &name, new]);
                    if code == 0 {
                        id_rename(&name, new);
                        crate::projnet::rename(bin, &name, new);
                        watch_renamed(&name, new);
                        no_content()
                    } else if err.contains("in use") || err.contains("exists") {
                        error(
                            409,
                            &format!("Conflict. The container name \"/{new}\" is already in use"),
                        )
                    } else {
                        error(500, &kern_error(&err))
                    }
                }
            }
        }
        ("GET", ["containers", id, "top"]) => container_top(bin, id),
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
            // Docker's order: `kill` (before the signal, so before the `die` it causes), the box's
            // `die`, then `stop`, or `start` and `restart`. Only for a box whose `die` is watched,
            // which is a running one: a kill that finds none makes no event.
            if die_pending(&name) {
                crate::events::publish_named("kill", &name, None);
            }
            let forever = in_set(&FOREVER, &name);
            if *verb == "restart" {
                set_in(&API_RESTART, &name, true);
            }
            let (code, _, err) = kern(bin, &args);
            if code == 0 && *verb != "kill" {
                die_within(&name, DIE_FIRST);
            }
            set_in(&API_RESTART, &name, false);
            if code == 0 {
                if *verb != "kill" {
                    crate::events::publish_named("stop", &name, None);
                    if *verb == "restart" {
                        crate::events::publish_named("start", &name, None);
                        crate::events::publish_named("restart", &name, None);
                        watch_die_with(bin, &name, false, None, forever);
                    }
                }
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
            // Refused before anything is forgotten: a container a 409 leaves running keeps its id,
            // its network and its events' labels.
            let running = created_get(&name).is_none()
                && kern_boxes(bin)
                    .into_iter()
                    .any(|(n, v)| n == name && box_running(&v));
            if running && !req.flag("force") {
                return error(409, &format!("You cannot remove a running container {name}. Stop the container before attempting removal or force remove"));
            }
            remove_container(bin, &name, running);
            no_content()
        }
        ("POST", ["images", "create"]) => pull(bin, req),
        ("GET", ["images", "get"]) => {
            let names: Vec<String> = req
                .query
                .iter()
                .filter(|(k, _)| k == "names")
                .map(|(_, v)| v.clone())
                .collect();
            image_save(bin, &names)
        }
        ("GET", ["images", rest @ .., "get"]) if !rest.is_empty() => {
            image_save(bin, &[rest.join("/")])
        }
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
        ("POST", ["images", rest @ .., "tag"]) if !rest.is_empty() => {
            image_tag(bin, &rest.join("/"), req)
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
        ("POST", ["exec", id, "resize"]) => {
            if exec_get(id).is_none() {
                return error(404, &format!("No such exec instance: {id}"));
            }
            tty_resize(id, req)
        }
        ("POST", ["containers", id, "resize"]) => match resolve(bin, id) {
            Some(name) => tty_resize(&name, req),
            None => error(404, &format!("No such container: {id}")),
        },
        ("POST", [kind @ ("networks" | "volumes" | "images"), "prune"]) => {
            labelled_prune(kind, req)
        }
        (_, ["networks" | "volumes", ..]) => match crate::netvol::handle(req, bin, &seg) {
            Some(r) => r,
            None => not_translated(&format!("{} {}", req.method, req.path)),
        },
        ("GET", ["events"]) => {
            watch_unwatched(bin);
            crate::events::events(req)
        }
        (m, _) => not_translated(&format!("{m} {}", req.path)),
    }
}

#[cfg(test)]
mod tests {

    /// `HostConfig.VolumesFrom` becomes `--volumes-from`, each entry as given (the handler turns an
    /// ID into a name); it was refused outright before kern had the flag.
    #[test]
    fn volumes_from_becomes_the_flag() {
        let body = json::parse(
            r#"{"Image":"alpine","HostConfig":{"VolumesFrom":["data","logs:ro"]}}"#,
        )
        .expect("json");
        let c = create_argv("web", &body).expect("accepted");
        let pairs: Vec<&[String]> = c.argv.windows(2).filter(|w| w[0] == "--volumes-from").collect();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0][1], "data");
        assert_eq!(pairs[1][1], "logs:ro");
    }

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

    /// A GPU request is `--gpus` under the operator's gate, and refused naming the gate without it;
    /// a request for another driver is refused either way.
    #[test]
    fn a_gpu_request_is_granted_under_the_gate_and_refused_without_it() {
        let b = |dr: &str| {
            body(&format!(
                r#"{{"Image":"x","HostConfig":{{"DeviceRequests":{dr}}}}}"#
            ))
        };
        let spec = |dr: &str| {
            let a = create_argv_gated("n", &b(dr), true, false).unwrap().argv;
            let i = a.iter().position(|x| x == "--gpus").unwrap();
            assert!(i < a.iter().position(|x| x == "--image").unwrap());
            a[i + 1].clone()
        };
        assert_eq!(
            spec(r#"[{"Driver":"nvidia","Count":-1,"Capabilities":[["gpu"]]}]"#),
            "all"
        );
        assert_eq!(spec(r#"[{"Count":2,"Capabilities":[["gpu"]]}]"#), "2");
        assert_eq!(
            spec(r#"[{"Driver":"nvidia","DeviceIDs":["1"]}]"#),
            "device=1"
        );
        let refused =
            create_argv_gated("n", &b(r#"[{"Driver":"nvidia","Count":-1}]"#), false, false)
                .map(|c| c.argv);
        assert!(
            matches!(&refused, Err(m) if m.contains("allow_gpu_grants")),
            "{refused:?}"
        );
        let other = create_argv_gated("n", &b(r#"[{"Driver":"amd","Count":1}]"#), true, false)
            .map(|c| c.argv);
        assert!(
            matches!(&other, Err(m) if m.contains("NVIDIA")),
            "{other:?}"
        );
        let bad_id = create_argv_gated(
            "n",
            &b(r#"[{"Driver":"nvidia","DeviceIDs":["0;rm"]}]"#),
            true,
            false,
        );
        assert!(bad_id.is_err());
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
        // `Privileged` is the operator's to grant, named by its key, and becomes `--privileged`
        // before the image when granted.
        let p = body(r#"{"Image":"x","HostConfig":{"Privileged":true}}"#);
        let refused = create_argv_gated("n", &p, false, false).map(|c| c.argv);
        assert!(
            matches!(&refused, Err(m) if m.contains("compose_privileged")),
            "{refused:?}"
        );
        let granted = create_argv_gated("n", &p, false, true)
            .map(|c| c.argv)
            .unwrap_or_default();
        let at = |f: &str| granted.iter().position(|a| a == f);
        assert!(
            matches!((at("--privileged"), at("--image")), (Some(a), Some(b)) if a < b),
            "{granted:?}"
        );
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
        // A network by name is a kern pod, joined with the endpoint's aliases (compose's service
        // name); a second network is a second `--network`, joined or refused at the create by
        // `projnet_argv`.
        let b = body(
            r#"{"Image":"x","HostConfig":{"NetworkMode":"shop_default"},"NetworkingConfig":{"EndpointsConfig":{"shop_default":{"Aliases":["web","n"]}}}}"#,
        );
        let a = create_argv("n", &b)
            .map(|c| c.argv.join(" "))
            .unwrap_or_default();
        assert!(
            a.contains("--network shop_default --network-alias web") && !a.contains("alias n"),
            "{a}"
        );
        let two = body(
            r#"{"Image":"x","HostConfig":{"NetworkMode":"a"},"NetworkingConfig":{"EndpointsConfig":{"a":{},"b":{}}}}"#,
        );
        let a = create_argv("n", &two)
            .map(|c| c.argv.join(" "))
            .unwrap_or_default();
        assert!(
            a.contains("--network a") && a.contains("--network b"),
            "{a}"
        );
        // Two networks that are not one compose project's are refused by name, before any kern
        // call: a box is in one pod.
        let argv: Vec<String> = [
            "--network",
            "kern-test-solo-a",
            "--network",
            "kern-test-solo-b",
        ]
        .map(String::from)
        .to_vec();
        let refused = projnet_argv(Path::new("/nonexistent/kern"), "n", argv, &two);
        assert!(
            refused.as_ref().is_err_and(
                |e| e.contains("\"kern-test-solo-b\"") && e.contains("one compose project's")
            ),
            "{refused:?}"
        );
        let one: Vec<String> = ["--network", "kern-test-solo-a"].map(String::from).to_vec();
        assert_eq!(
            projnet_argv(Path::new("/nonexistent/kern"), "n", one.clone(), &two).ok(),
            Some(one),
            "one network of any other kind passes unchanged"
        );
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
        assert!(
            valid_name(&"x".repeat(128)),
            "Docker takes a 128-character name"
        );
        assert!(!valid_name(&"x".repeat(201)));
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

    /// A `POST /build`'s query becomes `kern build`'s argv: every tag, the Dockerfile as a path inside
    /// the context, the build args (a `null` value is the bare name, taken from the environment),
    /// the target, the platform, `--no-cache`. A build with no tag, a remote context and a
    /// Dockerfile outside the context are refused.
    #[test]
    fn a_build_query_becomes_kern_builds_argv() {
        let q = |pairs: &[(&str, &str)]| Request {
            method: "POST".into(),
            path: "/build".into(),
            query: pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            body: Vec::new(),
            upgrade: false,
            peer: None,
            close: false,
        };
        let (argv, tags) = build_argv(
            &q(&[
                ("t", "a:1"),
                ("t", "b"),
                ("dockerfile", "./sub/Containerfile"),
                ("buildargs", r#"{"V":"1","FROM_ENV":null}"#),
                ("target", "run"),
                ("platform", "linux/arm64"),
                ("nocache", "1"),
            ]),
            "/c",
        )
        .expect("argv");
        assert_eq!(tags, ["a:1", "b"]);
        assert_eq!(
            argv.join(" "),
            "build --progress plain -t a:1 -t b -f /c/sub/Containerfile --build-arg V=1 \
             --build-arg FROM_ENV --target run --platform linux/arm64 --no-cache /c"
        );
        let (plain, _) = build_argv(&q(&[("t", "x")]), "/c").expect("argv");
        assert_eq!(
            plain.join(" "),
            "build --progress plain -t x -f /c/Dockerfile /c"
        );
        assert!(build_argv(&q(&[]), "/c").is_err(), "no tag");
        assert!(build_argv(&q(&[("t", "x"), ("remote", "https://x/y.git")]), "/c").is_err());
        for bad in ["../Dockerfile", "/etc/Dockerfile", "a/../../b"] {
            assert!(
                build_argv(&q(&[("t", "x"), ("dockerfile", bad)]), "/c").is_err(),
                "{bad}"
            );
        }
    }

    /// An image's id follows its content: a rebuild under the same name (a new config, new layers)
    /// is a new id, the same content the same id, and an entry with no sidecar has none here.
    #[test]
    fn an_image_id_follows_its_content() {
        let dir = std::env::temp_dir().join(format!("kern-cid-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let write = |cfg: &str, secs: u64| {
            for (ext, body) in [("image", cfg), ("layers", "alpine:3.21\nabc\n")] {
                let p = dir.join(format!("app_dev.{ext}"));
                std::fs::write(&p, body).expect("write");
                let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
                std::fs::File::options()
                    .write(true)
                    .open(&p)
                    .and_then(|f| f.set_modified(t))
                    .expect("mtime");
            }
        };
        write("cmd\tv1\n", 1_000);
        let v1 = content_id_in(&dir, "app_dev").expect("id");
        write("cmd\tv2\n", 2_000);
        let v2 = content_id_in(&dir, "app_dev").expect("id");
        write("cmd\tv1\n", 3_000);
        let again = content_id_in(&dir, "app_dev").expect("id");
        let missing = content_id_in(&dir, "missing");
        let climbing = content_id_in(&dir, "../x");
        let _ = std::fs::remove_dir_all(&dir);
        assert_ne!(v1, v2, "a rebuild is a new id");
        assert_eq!(v1, again, "the same content is the same id");
        assert_eq!(v1.len(), 64);
        assert!(missing.is_none() && climbing.is_none());
    }

    /// Names one byte apart get ids that differ from their first hex digits: a client shows 12 and
    /// matches a prefix.
    #[test]
    fn ids_of_names_one_byte_apart_differ_at_once() {
        for (a, b) in [("g11img:q", "g11img:p"), ("web-1", "web-2"), ("x", "y")] {
            let (ia, ib) = (hashed_id(a), hashed_id(b));
            let common = ia
                .chars()
                .zip(ib.chars())
                .take_while(|(x, y)| x == y)
                .count();
            assert!(common < 4, "{a} {ia} / {b} {ib}: {common} digits alike");
        }
    }

    /// buildx's own builder image is recognised at its default tags, and nothing else is.
    #[test]
    fn buildx_builder_image_is_recognised() {
        for yes in [
            "moby/buildkit:buildx-stable-1",
            "docker.io/moby/buildkit:buildx-stable-1",
        ] {
            assert!(is_buildx_builder(yes), "{yes}");
        }
        for no in [
            "moby/buildkit:latest",
            "moby/buildkit",
            "alpine:3.21",
            "x/moby/buildkit:buildx-stable-1",
        ] {
            assert!(!is_buildx_builder(no), "{no}");
        }
    }

    /// The restart policy of an argv, as Docker spells it in `HostConfig.RestartPolicy`.
    #[test]
    fn a_restart_policy_is_read_off_the_argv() {
        let p = |a: &[&str]| {
            restart_policy_json(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
        };
        assert_eq!(p(&["box", "x"]), r#"{"Name":"no","MaximumRetryCount":0}"#);
        assert_eq!(
            p(&["box", "x", "--restart", "always"]),
            r#"{"Name":"always","MaximumRetryCount":0}"#
        );
        assert_eq!(
            p(&["box", "x", "--restart", "on-failure:3"]),
            r#"{"Name":"on-failure","MaximumRetryCount":3}"#
        );
        assert_eq!(
            p(&["box", "x", "--restart", "--image", "a"]),
            r#"{"Name":"on-failure","MaximumRetryCount":0}"#
        );
        assert_eq!(
            p(&["box", "x", "--restart", "on-failure", "--restart-max", "5"]),
            r#"{"Name":"on-failure","MaximumRetryCount":5}"#
        );
        assert_eq!(
            p(&["box", "x", "--", "--restart", "always"]),
            r#"{"Name":"no","MaximumRetryCount":0}"#
        );
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

    /// `docker top` reads `ps -ef`'s eight columns; the row of this very process has its pid, its
    /// parent and its command line. MEASURED before: `/containers/{id}/top` was a 501.
    #[test]
    fn a_top_row_is_ps_ef_shaped() {
        let me = std::process::id() as i32;
        let hz = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).unwrap_or(100);
        let row = ps_row(me, hz, 0).expect("this process has a row");
        assert_eq!(row.len(), 8, "{row:?}");
        assert_eq!(row[1], me.to_string());
        assert_eq!(row[2], std::os::unix::process::parent_id().to_string());
        assert!(
            row[6].len() == 8 && row[6].as_bytes()[2] == b':',
            "TIME is HH:MM:SS: {row:?}"
        );
        assert!(!row[7].is_empty(), "a command line: {row:?}");
    }

    /// `docker stats` reads Docker's `StatsJSON`: the CPU delta against `precpu_stats`, the memory
    /// usage and limit, the pids, the networks. MEASURED before: `/containers/{id}/stats` was a 501.
    #[test]
    fn stats_are_dockers_stats_json() {
        let s = |cpu: u64, sys: u64| Sample {
            at: 1_795_000_000,
            cpu_ns: cpu,
            mem: 3 << 20,
            mem_limit: Some(100 << 20),
            inactive_file: 1 << 20,
            tasks: 2,
            pids_limit: Some(512),
            net: vec![("eth0".into(), 10, 1, 20, 2)],
            system_ns: sys,
            cpus: 8,
        };
        let pre = s(1_000, 10_000);
        let cur = s(6_000, 20_000);
        let v = json::parse(&stats_json("kd-s", &cur, Some(&pre))).unwrap();
        let n = |path: &[&str]| {
            let mut x = &v;
            for p in path {
                x = x.get(p).unwrap();
            }
            x.as_i64().unwrap()
        };
        assert_eq!(n(&["cpu_stats", "cpu_usage", "total_usage"]), 6_000);
        assert_eq!(n(&["precpu_stats", "cpu_usage", "total_usage"]), 1_000);
        assert_eq!(n(&["cpu_stats", "system_cpu_usage"]), 20_000);
        assert_eq!(n(&["cpu_stats", "online_cpus"]), 8);
        assert_eq!(n(&["memory_stats", "limit"]), 100 << 20);
        assert_eq!(n(&["memory_stats", "stats", "inactive_file"]), 1 << 20);
        assert_eq!(n(&["pids_stats", "current"]), 2);
        assert_eq!(n(&["networks", "eth0", "tx_bytes"]), 20);
        assert_eq!(v.get("name").and_then(Value::as_str), Some("/kd-s"));
        let one = json::parse(&stats_json("kd-s", &cur, None)).unwrap();
        assert_eq!(
            one.get("precpu_stats")
                .and_then(|p| p.get("system_cpu_usage"))
                .and_then(Value::as_i64),
            Some(0)
        );
        let (sys, cpus) = host_cpu();
        assert!(
            sys > 0 && cpus >= 1,
            "the host's CPU clock reads: {sys} {cpus}"
        );
    }

    /// An exec's terminal has a size file under its 64-hex id (one past a box name's 63), and a
    /// key that could be a path is refused.
    #[test]
    fn a_terminal_size_file_takes_an_exec_id_and_refuses_a_path() {
        let id = "a".repeat(64);
        assert!(tty_file(&id).is_some_and(|p| p.ends_with(&id)));
        for bad in ["", "..", ".x", "a/b", "a b"] {
            assert!(tty_file(bad).is_none(), "{bad:?}");
        }
    }

    /// The rest of `HostConfig` reaches the box: limits, mounts, names, resolvers, signals; a field
    /// kern has no flag for is a warning. MEASURED before: only Memory and NanoCpus were read, and
    /// `--pids-limit 32` through the socket let 100 forks through.
    /// An image id as a client hands one back is recognised, and another platform's entry of a
    /// tag has an id of its own; a create given an id runs the entry's name.
    /// A `PUT` archive answers 404 only for a missing destination; an entry that fails inside an
    /// existing one is a 500 that names the entry, not "Could not find the file /tmp".
    #[test]
    fn a_put_is_404_only_for_a_missing_destination() {
        let status = |why: &str| match put_refusal("c", "/tmp", why) {
            Response::Full { status, body, .. } => {
                (status, String::from_utf8_lossy(&body).into_owned())
            }
            _ => (0, String::new()),
        };
        assert_eq!(status("box:/nope: no such directory in the box").0, 404);
        let (code, body) = status("kern cp: d/x: No such file or directory (os error 2)");
        assert_eq!(code, 500);
        assert!(body.contains("d/x"), "{body}");
        assert_eq!(status("no box named 'c'").0, 409);
    }

    /// `docker update` asks kern for the caps it changes, and a field it does not change is refused
    /// by name rather than answered 200 with nothing done.
    #[test]
    fn an_update_body_becomes_kern_update_flags_or_a_named_refusal() {
        let b = |t: &str| json::parse(t).unwrap();
        let full = r#"{"Memory":67108864,"MemorySwap":-1,"NanoCpus":1500000000,"PidsLimit":64,"RestartPolicy":{"Name":""},"CpuShares":0}"#;
        assert_eq!(
            update_args(&b(full)),
            Ok([
                "--memory",
                "67108864",
                "--cpus",
                "1.5",
                "--pids-limit",
                "64"
            ]
            .map(String::from)
            .to_vec())
        );
        assert_eq!(
            update_args(&b(r#"{"CpuQuota":50000,"CpuPeriod":100000}"#)),
            Ok(["--cpus", "0.5"].map(String::from).to_vec())
        );
        assert_eq!(update_args(&b("{}")), Ok(Vec::new()));
        assert!(update_args(&b(r#"{"RestartPolicy":{"Name":"always"}}"#))
            .is_err_and(|e| e.starts_with("RestartPolicy")));
        assert!(update_args(&b(r#"{"CpuShares":512}"#)).is_err_and(|e| e.starts_with("CpuShares")));
        assert!(update_args(&b(r#"{"Memory":1000,"MemorySwap":5000}"#)).is_err());
    }

    /// A container's image id is the id the image list gives the same image, for the name it was
    /// run by (a bare name being `:latest`), and this machine's entry before another platform's:
    /// what a client compares `inspect -f '{{.Image}}'` with. An image no longer cached keeps an
    /// id; a container with no image has none.
    #[test]
    fn a_container_reports_the_id_the_image_list_gives_its_image() {
        let images = [
            json::parse(r#"{"image":"alpine:3.21","platform":"linux/arm64"}"#).unwrap(),
            json::parse(r#"{"image":"alpine:3.21"}"#).unwrap(),
            json::parse(r#"{"image":"nginx:latest"}"#).unwrap(),
        ];
        let listed = |i: &Value| format!("sha256:{}", image_entry_id(i).unwrap());
        assert_eq!(
            container_image_id(&images, "alpine:3.21"),
            listed(&images[1])
        );
        assert_ne!(
            container_image_id(&images, "alpine:3.21"),
            listed(&images[0])
        );
        assert_eq!(container_image_id(&images, "nginx"), listed(&images[2]));
        assert_eq!(
            container_image_id(&images, "gone:1"),
            format!("sha256:{}", id_of("gone:1"))
        );
        assert_eq!(container_image_id(&images, ""), "");
    }

    #[test]
    fn image_ids_tell_platforms_apart_and_a_create_by_id_runs_the_name() {
        assert_eq!(
            image_id_ref("sha256:442210d3f5f95933ad9f"),
            Some("442210d3f5f95933ad9f")
        );
        assert_eq!(image_id_ref("442210d3f5f9"), Some("442210d3f5f9"));
        // Docker takes a prefix from two characters (measured: `docker image inspect bf`).
        assert_eq!(image_id_ref("44"), Some("44"));
        assert_eq!(image_id_ref("4"), None);
        let two = [
            json::parse(r#"{"image":"a:1"}"#).unwrap(),
            json::parse(r#"{"image":"b:1"}"#).unwrap(),
        ];
        let (ia, ib) = (
            image_entry_id(&two[0]).unwrap(),
            image_entry_id(&two[1]).unwrap(),
        );
        let unique = (2..12)
            .map(|n| &ia[..n])
            .find(|p| !ib.starts_with(p))
            .unwrap();
        assert!(
            image_by_id_prefix(&two, unique).is_some(),
            "a unique prefix names one"
        );
        let common: String = ia
            .chars()
            .zip(ib.chars())
            .take_while(|(x, y)| x == y)
            .map(|(x, _)| x)
            .collect();
        if common.len() >= 2 {
            assert!(
                image_by_id_prefix(&two, &common).is_none(),
                "an ambiguous one names none"
            );
        }
        assert_eq!(image_id_ref("alpine:3.20"), None);
        assert_eq!(
            image_id_ref("ABCDEF012345"),
            None,
            "Docker ids are lowercase"
        );
        let native = json::parse(r#"{"image":"alpine:3.20"}"#).unwrap();
        let arm = json::parse(r#"{"image":"alpine:3.20","platform":"linux/arm64"}"#).unwrap();
        let (a, b) = (
            image_entry_id(&native).unwrap(),
            image_entry_id(&arm).unwrap(),
        );
        assert_eq!(a, id_of("alpine:3.20"), "this machine's id is unchanged");
        assert_ne!(a, b);
        assert_eq!(image_entry_platform(&arm), Some("linux/arm64"));
        assert_eq!(image_entry_platform(&native), None);
        let b = json::parse(&format!(r#"{{"Image":"sha256:{b}","Cmd":["uname","-m"]}}"#)).unwrap();
        let c = with_platform(
            with_image_name(create_argv("n", &b).unwrap(), "alpine:3.20"),
            Some("linux/arm64"),
        );
        let at = c.argv.iter().position(|x| x == "--image").unwrap();
        assert_eq!(c.argv[at + 1], "alpine:3.20");
        assert_eq!(c.image, "alpine:3.20");
        let p = c.argv.iter().position(|x| x == "--platform").unwrap();
        assert_eq!(c.argv[p + 1], "linux/arm64");
        assert!(p < at, "--platform before the image");
    }

    /// Each restart's record publishes its `die` and the next run's `start` once, whatever else
    /// wakes the watch; the first run's start is the start itself.
    #[test]
    fn a_restarting_box_publishes_die_and_start_once_per_restart() {
        use kern_common::attempt::Attempt;
        let mut p = Published::default();
        let run = |restarts| Attempt::Running {
            since_ms: 1,
            restarts,
        };
        let restarting = |code, restarts| Attempt::Restarting {
            since_ms: 2,
            code,
            restarts,
        };
        let mut out = Vec::new();
        for a in [
            run(0),
            run(0),
            restarting(3, 1),
            restarting(3, 1),
            run(1),
            run(1),
            restarting(3, 2),
            run(2),
        ] {
            if let Some(e) = p.next(a) {
                out.push(e);
            }
        }
        assert_eq!(
            out,
            [
                ("die", Some(3)),
                ("start", None),
                ("die", Some(3)),
                ("start", None)
            ]
        );
    }

    /// A relative working directory is Docker's 400; a hard limit above this process's own is
    /// applied as that one, and the create says so.
    #[test]
    fn a_relative_workdir_is_refused_and_a_ulimit_above_ours_is_a_warning() {
        let b = |s: &str| json::parse(s).unwrap();
        let e = create_argv("n", &b(r#"{"Image":"x","WorkingDir":"./tmp"}"#))
            .err()
            .unwrap();
        assert!(e.contains("needs to be an absolute path"), "{e}");
        assert!(create_argv("n", &b(r#"{"Image":"x","WorkingDir":"/tmp"}"#)).is_ok());
        let Some(cap) = hard_limit_of("nofile") else {
            return;
        };
        let over = cap.saturating_add(1);
        let c = create_argv(
            "n",
            &b(&format!(
                r#"{{"Image":"x","HostConfig":{{"Ulimits":[{{"Name":"nofile","Soft":{over},"Hard":{over}}}]}}}}"#
            )),
        )
        .unwrap();
        assert!(
            c.warnings
                .iter()
                .any(|w| w.contains("cannot raise a hard limit")),
            "{:?}",
            c.warnings
        );
    }

    /// Only `always` and `unless-stopped` are restarted for ever (by systemd); `on-failure` is the
    /// box's own supervisor, which follows its runs itself.
    #[test]
    fn only_a_forever_policy_is_followed_past_its_die() {
        let argv = |p: &str| {
            ["box", "x", "--restart", p, "--image", "a"]
                .map(str::to_string)
                .to_vec()
        };
        assert!(restarts_forever(&argv("always")));
        assert!(restarts_forever(&argv("unless-stopped")));
        assert!(!restarts_forever(&argv("on-failure:3")));
        assert!(!restarts_forever(&argv("no")));
        assert!(!restarts_forever(&["box".to_string(), "x".to_string()]));
    }

    /// A removal or a restart waits for the pending `die`, so it is published first; with none
    /// pending it does not wait.
    #[test]
    fn die_within_waits_for_the_pending_die_and_only_for_it() {
        let t = Instant::now();
        die_within("kd-no-die-pending", Duration::from_secs(2));
        assert!(t.elapsed() < Duration::from_millis(100));
        if let Ok(mut g) = DIE_PENDING.lock() {
            g.get_or_insert_with(Default::default)
                .insert("kd-die-pending".to_string());
        }
        assert!(die_pending("kd-die-pending"));
        let settler = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(150));
            die_settled("kd-die-pending");
        });
        let t = Instant::now();
        die_within("kd-die-pending", Duration::from_secs(2));
        let waited = t.elapsed();
        assert!(
            waited >= Duration::from_millis(140) && waited < Duration::from_secs(1),
            "{waited:?}"
        );
        assert!(!die_pending("kd-die-pending"));
        settler.join().unwrap();
    }

    #[test]
    fn host_config_limits_and_settings_reach_the_box() {
        let b = body(
            r#"{"Image":"x","StopSignal":"SIGINT","StopTimeout":3,"HostConfig":{"PidsLimit":32,"ShmSize":67108864,"Memory":104857600,"MemorySwap":209715200,"CpusetCpus":"0-1","ReadonlyRootfs":true,"Init":true,"ExtraHosts":["db:10.0.0.5"],"Dns":["9.9.9.9"],"CapDrop":["NET_RAW"],"Sysctls":{"net.core.somaxconn":"1024"},"Tmpfs":{"/run":"rw,size=64k"},"Ulimits":[{"Name":"nofile","Soft":1024,"Hard":2048}],"LogConfig":{"Type":"json-file","Config":{"max-size":"10m"}},"CpuShares":512}}"#,
        );
        let c = create_argv("n", &b).expect("translates");
        let a = c.argv.join(" ");
        for want in [
            "--pids-limit 32",
            "--shm-size 67108864",
            "--memory-swap-max 104857600",
            "--cpuset-cpus 0-1",
            "--read-only",
            "--init",
            "--add-host db:10.0.0.5",
            "--dns 9.9.9.9",
            "--cap-drop NET_RAW",
            "--sysctl net.core.somaxconn=1024",
            "--tmpfs /run:rw,size=64k",
            "--ulimit nofile=1024:2048",
            "--log-max-size 10m",
            "--stop-signal SIGINT",
            "--stop-timeout 3",
        ] {
            assert!(a.contains(want), "{want} missing: {a}");
        }
        assert!(
            c.warnings.iter().any(|w| w.contains("CpuShares")),
            "{:?}",
            c.warnings
        );
    }

    /// Docker's `Healthcheck` (nanosecond durations, `CMD-SHELL` or `CMD`) as `kern box --health-*`
    /// in whole seconds rounded up; compose's `service_healthy` waits on it. MEASURED before: not read.
    #[test]
    fn a_healthcheck_becomes_the_boxs_health_flags() {
        let b = body(
            r#"{"Image":"x","Healthcheck":{"Test":["CMD-SHELL","pg_isready -U u"],"Interval":1000000000,"Timeout":3000000000,"Retries":30,"StartPeriod":500000000}}"#,
        );
        let a = create_argv("n", &b)
            .map(|c| c.argv.join(" "))
            .unwrap_or_default();
        assert!(a.contains("--health-cmd pg_isready -U u"), "{a}");
        assert!(
            a.contains("--health-interval 1") && a.contains("--health-timeout 3"),
            "{a}"
        );
        assert!(
            a.contains("--health-retries 30") && a.contains("--health-start-period 1"),
            "{a}"
        );
        let exec = body(r#"{"Image":"x","Healthcheck":{"Test":["CMD","mysqladmin","ping"]}}"#);
        let a = create_argv("n", &exec)
            .map(|c| c.argv.join(" "))
            .unwrap_or_default();
        assert!(
            a.contains("--health-cmd-argv mysqladmin --health-cmd-argv ping"),
            "{a}"
        );
        let none = body(r#"{"Image":"x","Healthcheck":{"Test":["NONE"]}}"#);
        let a = create_argv("n", &none)
            .map(|c| c.argv.join(" "))
            .unwrap_or_default();
        assert!(!a.contains("--health"), "{a}");
    }

    /// An endpoint this API does not serve answers 501 naming it and saying the API hands nothing to
    /// a Docker engine, and names no internal server. `/networks` and `/build` used to be such
    /// endpoints; both are served now (see `netvol` and `image_build`).
    #[test]
    fn an_unserved_call_is_refused_naming_what_does_it() {
        let req = Request {
            method: "GET".into(),
            path: "/swarm".into(),
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
        assert!(
            text.contains("GET /swarm: not served by kern's Docker API"),
            "{text}"
        );
        assert!(!text.contains("kern-serve"), "{text}");
    }

    /// `GET /networks` lists Docker's three builtins whatever kern has, as Docker's daemon does.
    /// A container's mounts read as Docker's: what compose's second `up` checks a service's named
    /// volumes against. A named volume by `-v` and by `--mount`, a read-only bind, a tmpfs; an argv
    /// with none is `[]`.
    #[test]
    fn a_containers_mounts_read_as_dockers() {
        let argv: Vec<String> = [
            "box",
            "x",
            "-v",
            "proj_data:/var/lib/data",
            "-v",
            "/srv/conf:/etc/app:ro",
            "--mount",
            "type=volume,src=proj_cache,dst=/cache",
            "--mount",
            "type=tmpfs,dst=/run/t",
            "--image",
            "alpine",
        ]
        .map(String::from)
        .to_vec();
        let m = body(&mounts_json(&argv));
        let arr = m.as_array().unwrap_or_default();
        assert_eq!(arr.len(), 4, "{}", mounts_json(&argv));
        let get = |i: usize, k: &str| {
            arr[i]
                .get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        assert_eq!(
            (get(0, "Type"), get(0, "Name"), get(0, "Destination")),
            ("volume".into(), "proj_data".into(), "/var/lib/data".into())
        );
        assert_eq!(
            (get(1, "Type"), get(1, "Source")),
            ("bind".into(), "/srv/conf".into())
        );
        assert_eq!(arr[1].get("RW").and_then(Value::as_bool), Some(false));
        assert_eq!(
            (get(2, "Type"), get(2, "Name")),
            ("volume".into(), "proj_cache".into())
        );
        assert_eq!(
            (get(3, "Type"), get(3, "Destination")),
            ("tmpfs".into(), "/run/t".into())
        );
        assert_eq!(mounts_json(&["box".to_string()]), "[]");
    }

    #[test]
    fn the_network_list_has_dockers_builtins() {
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
        let v = json::parse(&String::from_utf8_lossy(&body)).unwrap();
        let names: Vec<&str> = v
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|n| n.get("Name").and_then(Value::as_str))
            .collect();
        assert_eq!(status, 200);
        assert_eq!(names, ["bridge", "host", "none"]);
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
