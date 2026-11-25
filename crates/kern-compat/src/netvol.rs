//! `/networks` and `/volumes`: what `docker compose` (the client, through kern's socket) creates
//! around its containers, onto kern's pods and named volumes.
//!
//! A DOCKER NETWORK IS A KERN POD. Its members share one network namespace and a hosts file every
//! member reads, the ones already running included, so a service is reached by its name (a
//! `--network-alias`) whenever it joins, as Docker's embedded DNS answers. A box is in one pod, so
//! the networks of one compose project are bridges of ONE pod (`projnet`), and a container joins as
//! many of them as compose asks; any other second network is refused by name rather than half-joined.
//!
//! A DOCKER VOLUME IS A KERN VOLUME. kern keeps no labels on either, and compose finds what it made
//! by label (`com.docker.compose.project`) and refuses to reuse one it did not make, so the labels a
//! client gave are kept here, beside kern's cache, and dropped with the object.

use std::path::{Path, PathBuf};

use kern_common::json::{self, Value};
use kern_common::{json_str, rfc3339};

use crate::api::{
    created_get, created_put, error, filter_values, id_of, json_response, kern, kern_boxes,
    kern_error, labels_json, no_content, resolve, valid_name,
};
use crate::{Request, Response};

/// Docker's own networks, always listed and never removed.
const BUILTIN: [(&str, &str); 3] = [("bridge", "bridge"), ("host", "host"), ("none", "null")];

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `<cache>/kern/compat-meta/<kind>/`, where the labels a client gave an object are kept.
pub(crate) fn meta_dir(kind: &str) -> Option<PathBuf> {
    Some(
        kern_common::xdg_cache_dir()?
            .join("kern")
            .join("compat-meta")
            .join(kind),
    )
}

/// What this API keeps about an object kern has no field for.
#[derive(Default)]
struct Meta {
    labels: Vec<(String, String)>,
    created: u64,
    internal: bool,
}

fn meta_read(kind: &str, name: &str) -> Meta {
    let Some(text) = meta_dir(kind).and_then(|d| std::fs::read_to_string(d.join(name)).ok()) else {
        return Meta::default();
    };
    let Ok(v) = json::parse(&text) else {
        return Meta::default();
    };
    Meta {
        labels: labels_of_value(v.get("labels")),
        created: v
            .get("created")
            .and_then(Value::as_i64)
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(0),
        internal: v.get("internal").and_then(Value::as_bool) == Some(true),
    }
}

fn meta_write(kind: &str, name: &str, m: &Meta) {
    use std::os::unix::fs::DirBuilderExt;
    let Some(dir) = meta_dir(kind) else { return };
    if std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .is_err()
    {
        return;
    }
    let body = format!(
        "{{\"labels\":{},\"created\":{},\"internal\":{}}}",
        labels_json(&m.labels),
        m.created,
        m.internal
    );
    let tmp = dir.join(format!(".{name}.new"));
    if std::fs::write(&tmp, body).is_ok() {
        let _ = std::fs::rename(&tmp, dir.join(name));
    }
}

fn meta_forget(kind: &str, name: &str) {
    if let Some(d) = meta_dir(kind) {
        let _ = std::fs::remove_file(d.join(name));
    }
}

fn labels_of_value(v: Option<&Value>) -> Vec<(String, String)> {
    v.and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// `label=k` / `label=k=v` against an object's labels, as Docker's filter reads them.
fn labels_match(want: &[String], labels: &[(String, String)]) -> bool {
    want.iter().all(|l| match l.split_once('=') {
        Some((k, v)) => labels.iter().any(|(lk, lv)| lk == k && lv == v),
        None => labels.iter().any(|(lk, _)| lk == l),
    })
}

fn filters_of(req: &Request) -> Result<Value, Response> {
    match req.param("filters").filter(|f| !f.is_empty()) {
        Some(f) => json::parse(f).map_err(|e| error(400, &format!("invalid filters: {e}"))),
        None => Ok(Value::Null),
    }
}

// ---------------------------------------------------------------------------------------------
// Networks.

pub(crate) fn network_id(name: &str) -> String {
    id_of(&format!("network/{name}"))
}

/// The pods kern has now.
fn pods(bin: &Path) -> Vec<String> {
    let (_, out, _) = kern(bin, &["pod", "ls", "--json"]);
    json::parse(out.trim())
        .ok()
        .and_then(|v| v.as_array().map(<[Value]>::to_vec))
        .unwrap_or_default()
        .iter()
        .filter_map(|p| p.get("name").and_then(Value::as_str).map(str::to_string))
        .collect()
}

/// The networks this API answers for beside the builtins: every pod but a compose project's own
/// (see `projnet`), and every network of a project, whose pod may not exist yet.
fn networks(bin: &Path) -> Vec<String> {
    let mut v: Vec<String> = pods(bin)
        .into_iter()
        .filter(|p| !crate::projnet::is_project_pod(p))
        .collect();
    for p in crate::projnet::all() {
        if !v.contains(&p.name) {
            v.push(p.name);
        }
    }
    v
}

/// The network a client means by `id`: a builtin, a pod by name, or an id or a prefix of one.
fn resolve_network(bin: &Path, id: &str) -> Option<String> {
    let names = BUILTIN
        .iter()
        .map(|(n, _)| (*n).to_string())
        .chain(networks(bin));
    let mut by_id = None;
    for n in names {
        if n == id {
            return Some(n);
        }
        if id.len() >= 6 && network_id(&n).starts_with(id) {
            by_id = Some(n);
        }
    }
    by_id
}

/// Is `name` a pod that exists?
pub(crate) fn network_exists(bin: &Path, name: &str) -> bool {
    pods(bin).iter().any(|p| p == name)
}

/// Is `name` a network this API can put a container on: a pod that exists, or a compose project's
/// network (its pod is made by its first container).
pub(crate) fn network_usable(bin: &Path, name: &str) -> bool {
    crate::projnet::get(name).is_some() || network_exists(bin, name)
}

fn network_json(bin: &Path, name: &str, members: &[(String, Value)]) -> String {
    let builtin = BUILTIN.iter().find(|(n, _)| *n == name);
    let m = if builtin.is_some() {
        Meta::default()
    } else {
        meta_read("networks", name)
    };
    let driver = builtin.map_or("bridge", |(_, d)| d);
    let project = crate::projnet::get(name);
    let containers: Vec<String> = members
        .iter()
        .filter(|(n, v)| match &project {
            Some(p) => p.address_of(n).is_some(),
            None => v.get("pod").and_then(Value::as_str) == Some(name),
        })
        .map(|(n, _)| {
            format!(
                "{}:{{\"Name\":{},\"EndpointID\":{},\"MacAddress\":\"\",\"IPv4Address\":\"\",\"IPv6Address\":\"\"}}",
                json_str(&id_of(n)),
                json_str(n),
                json_str(&id_of(&format!("endpoint/{name}/{n}")))
            )
        })
        .collect();
    let _ = bin;
    format!(
        "{{\"Name\":{},\"Id\":{},\"Created\":{},\"Scope\":\"local\",\"Driver\":{},\"EnableIPv6\":false,\"IPAM\":{{\"Driver\":\"default\",\"Options\":null,\"Config\":[]}},\"Internal\":{},\"Attachable\":true,\"Ingress\":false,\"ConfigFrom\":{{\"Network\":\"\"}},\"ConfigOnly\":false,\"Containers\":{{{}}},\"Options\":{{}},\"Labels\":{}}}",
        json_str(name),
        json_str(&network_id(name)),
        json_str(&rfc3339(if m.created > 0 { m.created } else { now() })),
        json_str(driver),
        m.internal,
        containers.join(","),
        labels_json(&m.labels)
    )
}

/// `GET /networks` (`label`, `name`, `id`, `driver`, `type` filters).
fn network_list(bin: &Path, req: &Request) -> Response {
    let f = match filters_of(req) {
        Ok(f) => f,
        Err(r) => return r,
    };
    let (labels, names, ids, drivers, types) = (
        filter_values(&f, "label"),
        filter_values(&f, "name"),
        filter_values(&f, "id"),
        filter_values(&f, "driver"),
        filter_values(&f, "type"),
    );
    let members = kern_boxes(bin);
    let all: Vec<String> = BUILTIN
        .iter()
        .map(|(n, _)| (*n).to_string())
        .chain(networks(bin))
        .collect();
    let rows: Vec<String> = all
        .iter()
        .filter(|n| {
            let builtin = BUILTIN.iter().find(|(b, _)| b == n);
            let driver = builtin.map_or("bridge", |(_, d)| d);
            let m = if builtin.is_some() {
                Meta::default()
            } else {
                meta_read("networks", n)
            };
            (names.is_empty() || names.iter().any(|w| n.contains(w.as_str())))
                && (ids.is_empty() || ids.iter().any(|w| network_id(n).starts_with(w.as_str())))
                && (drivers.is_empty() || drivers.iter().any(|d| d == driver))
                && (types.is_empty()
                    || types.iter().any(|t| {
                        (t == "builtin" && builtin.is_some())
                            || (t == "custom" && builtin.is_none())
                    }))
                && labels_match(&labels, &m.labels)
        })
        .map(|n| network_json(bin, n, &members))
        .collect();
    json_response(200, format!("[{}]", rows.join(",")))
}

/// `POST /networks/create`: a kern pod (with its NAT, or none for `Internal`), the client's labels
/// kept beside it.
fn network_create(bin: &Path, req: &Request) -> Response {
    let body = match json::parse(&String::from_utf8_lossy(&req.body)) {
        Ok(b) => b,
        Err(e) => return error(400, &e.to_string()),
    };
    let Some(name) = body
        .get("Name")
        .and_then(Value::as_str)
        .filter(|n| !n.is_empty())
    else {
        return error(400, "network name is required");
    };
    if !valid_name(name) {
        return error(400, &format!("invalid network name {name:?}"));
    }
    match body.get("Driver").and_then(Value::as_str) {
        None | Some("" | "bridge") => {}
        Some(d) => {
            return error(
                400,
                &format!(
                "network driver {d:?}: kern makes bridge networks (a pod), the only driver it has"
            ),
            )
        }
    }
    if BUILTIN.iter().any(|(n, _)| *n == name) || network_usable(bin, name) {
        return error(409, &format!("network with name {name} already exists"));
    }
    let internal = body.get("Internal").and_then(Value::as_bool) == Some(true);
    let labels = labels_of_value(body.get("Labels"));
    // A COMPOSE PROJECT'S NETWORK is recorded and becomes a bridge of the project's pod when its
    // first container is made (see `projnet`), so a service can be on several. Any other network, or
    // one created after its project's pod was made, is a pod of its own, as before.
    let recorded = crate::projnet::project_of(name, &labels).is_some_and(|(project, network)| {
        crate::projnet::create(name, &project, &network, internal).is_ok()
    });
    if !recorded {
        let mut args = vec!["pod", "create", name];
        if internal {
            args.push("--no-outbound");
        }
        let (code, _, err) = kern(bin, &args);
        if code != 0 {
            return error(500, &kern_error(&err));
        }
    }
    meta_write(
        "networks",
        name,
        &Meta {
            labels,
            created: now(),
            internal,
        },
    );
    json_response(
        201,
        format!(
            "{{\"Id\":{},\"Warning\":\"\"}}",
            json_str(&network_id(name))
        ),
    )
}

fn network_remove(bin: &Path, id: &str) -> Response {
    let Some(name) = resolve_network(bin, id) else {
        return error(404, &format!("network {id} not found"));
    };
    if BUILTIN.iter().any(|(n, _)| *n == name) {
        return error(
            403,
            &format!("{name} is a pre-defined network and cannot be removed"),
        );
    }
    if crate::projnet::get(&name).is_some() {
        return match crate::projnet::remove(bin, &name) {
            Ok(()) => {
                meta_forget("networks", &name);
                no_content()
            }
            Err((status, why)) => error(status, &why),
        };
    }
    let busy = kern_boxes(bin).iter().any(|(_, v)| {
        v.get("pod").and_then(Value::as_str) == Some(name.as_str()) && crate::api::box_running(v)
    });
    if busy {
        return error(
            409,
            &format!(
                "error while removing network: network {name} id {} has active endpoints",
                network_id(&name)
            ),
        );
    }
    let (code, _, err) = kern(bin, &["pod", "rm", &name]);
    if code != 0 {
        return error(500, &kern_error(&err));
    }
    meta_forget("networks", &name);
    no_content()
}

/// The aliases a create or a connect gives a container on `net`: `Aliases` and `DNSNames`, without
/// the container's own name (which the pod's hosts file has already).
pub(crate) fn endpoint_aliases(endpoint: Option<&Value>, own: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for key in ["Aliases", "DNSNames"] {
        for a in endpoint
            .and_then(|e| e.get(key))
            .and_then(Value::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(Value::as_str)
        {
            if a != own && valid_name(a) && !out.iter().any(|o| o == a) {
                out.push(a.to_string());
            }
        }
    }
    out
}

/// The network a created container's argv puts it on, if any.
fn argv_network(argv: &[String]) -> Option<&str> {
    argv.windows(2)
        .find(|w| w[0] == "--network" || w[0] == "--pod")
        .map(|w| w[1].as_str())
}

/// `POST /networks/{id}/connect`: onto a container created and not started, its network (and
/// aliases) at its start; a running one already on that network is connected; any other is
/// refused by name, a box being in one pod.
fn network_connect(bin: &Path, id: &str, req: &Request) -> Response {
    let Some(net) = resolve_network(bin, id) else {
        return error(404, &format!("network {id} not found"));
    };
    let body = json::parse(&String::from_utf8_lossy(&req.body)).unwrap_or(Value::Null);
    let Some(container) = body.get("Container").and_then(Value::as_str) else {
        return error(400, "Container is required");
    };
    let Some(name) = resolve(bin, container) else {
        return error(404, &format!("No such container: {container}"));
    };
    let aliases = endpoint_aliases(body.get("EndpointConfig"), &name);
    // A COMPOSE PROJECT'S NETWORK, onto a container created and not started: another bridge of the
    // project's pod, its address taken now so the peers created after know it (see `projnet`). This
    // is how `docker compose` puts a service on its second network (API 1.43: one network at the
    // create, the rest connected before the start).
    if let Some(mut c) = created_get(&name).filter(|_| crate::projnet::get(&net).is_some()) {
        let on = crate::api::argv_networks(&c.argv);
        if let Err(why) = crate::projnet::attach(bin, &net, &name, &aliases, &on) {
            return error(400, &why);
        }
        if !on.contains(&net) {
            let at = c
                .argv
                .iter()
                .position(|a| a == "--image")
                .unwrap_or(c.argv.len());
            c.argv
                .splice(at..at, ["--network".to_string(), net.clone()]);
        }
        created_put(&name, c);
        return json_response(200, String::new());
    }
    if let Some(mut c) = created_get(&name) {
        match argv_network(&c.argv) {
            Some(n) if n == net => {}
            Some(other) => {
                return error(
                    400,
                    &format!(
                        "container {name} is on network {other}: through kern's Docker API a \
                         container joins several networks only when they are one compose \
                         project's (a kern box is in one pod, and a project's networks are \
                         bridges of one pod). Put both networks in one compose file, or run it \
                         with `kern compose -f <file> up`"
                    ),
                )
            }
            None => {
                let at = c
                    .argv
                    .iter()
                    .position(|a| a == "--image")
                    .unwrap_or(c.argv.len());
                c.argv
                    .splice(at..at, ["--network".to_string(), net.clone()]);
            }
        }
        for a in aliases {
            let at = c
                .argv
                .iter()
                .position(|x| x == "--image")
                .unwrap_or(c.argv.len());
            c.argv.splice(at..at, ["--network-alias".to_string(), a]);
        }
        created_put(&name, c);
        return json_response(200, String::new());
    }
    let on = kern_boxes(bin)
        .into_iter()
        .find(|(n, _)| *n == name)
        .and_then(|(_, v)| v.get("pod").and_then(Value::as_str).map(str::to_string));
    if on.as_deref() == Some(net.as_str()) {
        return json_response(200, String::new());
    }
    error(
        400,
        &format!(
            "container {name} is running: kern puts a box on its network when it starts, and a box \
             is in one pod. Recreate it with the network, or run the file with `kern compose`"
        ),
    )
}

/// `POST /networks/{id}/disconnect`: off a container created and not started; a running one is
/// not taken off its pod.
fn network_disconnect(bin: &Path, id: &str, req: &Request) -> Response {
    let Some(net) = resolve_network(bin, id) else {
        return error(404, &format!("network {id} not found"));
    };
    let body = json::parse(&String::from_utf8_lossy(&req.body)).unwrap_or(Value::Null);
    let Some(container) = body.get("Container").and_then(Value::as_str) else {
        return error(400, "Container is required");
    };
    let Some(name) = resolve(bin, container) else {
        return error(404, &format!("No such container: {container}"));
    };
    if let Some(mut c) = created_get(&name).filter(|_| crate::projnet::get(&net).is_some()) {
        crate::projnet::detach(bin, &net, &name);
        let mut out: Vec<String> = Vec::with_capacity(c.argv.len());
        let mut it = c.argv.into_iter();
        while let Some(a) = it.next() {
            if a == "--network" {
                match it.next() {
                    Some(n) if n == net => continue,
                    Some(n) => {
                        out.push(a);
                        out.push(n);
                        continue;
                    }
                    None => break,
                }
            }
            out.push(a);
        }
        c.argv = out;
        created_put(&name, c);
        return json_response(200, String::new());
    }
    if let Some(mut c) = created_get(&name) {
        if argv_network(&c.argv) == Some(net.as_str()) {
            let mut out: Vec<String> = Vec::with_capacity(c.argv.len());
            let mut it = c.argv.into_iter();
            while let Some(a) = it.next() {
                if a == "--network" || a == "--pod" || a == "--network-alias" {
                    let _ = it.next();
                    continue;
                }
                out.push(a);
            }
            c.argv = out;
            created_put(&name, c);
        }
        return json_response(200, String::new());
    }
    let on = kern_boxes(bin)
        .into_iter()
        .find(|(n, _)| *n == name)
        .and_then(|(_, v)| v.get("pod").and_then(Value::as_str).map(str::to_string));
    if on.as_deref() != Some(net.as_str())
        || body.get("Force").and_then(Value::as_bool) == Some(true)
    {
        return json_response(200, String::new());
    }
    error(
        400,
        &format!("container {name} is running on {net}: kern does not take a running box off its network"),
    )
}

/// The `NetworkSettings.Networks` of `container`: every compose project network it is on, each with
/// its address on that network's bridge (`10.89.<bridge>.0/24`, the bridge `.1`), or else the one
/// `net` with its `aliases`, as [`networks_json`] says it.
pub(crate) fn container_networks_json(
    container: &str,
    net: Option<&str>,
    aliases: &[String],
) -> String {
    let projnets = crate::projnet::networks_of(container);
    if projnets.is_empty() {
        return networks_json(net, aliases);
    }
    let rows: Vec<String> = projnets
        .iter()
        .map(|(n, ip, als)| {
            let a: Vec<String> = als.iter().map(|x| json_str(x)).collect();
            let o = ip.octets();
            format!(
                "{}:{{\"Aliases\":[{a}],\"DNSNames\":[{a}],\"NetworkID\":{},\"EndpointID\":\"\",\"Gateway\":\"{}.{}.{}.1\",\"IPAddress\":\"{ip}\",\"IPPrefixLen\":24,\"MacAddress\":\"\"}}",
                json_str(n),
                json_str(&network_id(n)),
                o[0],
                o[1],
                o[2],
                a = a.join(","),
            )
        })
        .collect();
    format!("{{{}}}", rows.join(","))
}

/// The `NetworkSettings.Networks` of a container on `net`, as `inspect` reports it.
pub(crate) fn networks_json(net: Option<&str>, aliases: &[String]) -> String {
    match net.filter(|n| !n.is_empty()) {
        None => "{}".to_string(),
        Some(n) => {
            let a: Vec<String> = aliases.iter().map(|x| json_str(x)).collect();
            format!(
                "{{{}:{{\"Aliases\":[{}],\"DNSNames\":[{}],\"NetworkID\":{},\"EndpointID\":\"\",\"Gateway\":\"\",\"IPAddress\":\"\",\"IPPrefixLen\":0,\"MacAddress\":\"\"}}}}",
                json_str(n),
                a.join(","),
                a.join(","),
                json_str(&network_id(n))
            )
        }
    }
}

/// The network and the aliases a created container's argv names.
pub(crate) fn created_network(argv: &[String]) -> (Option<String>, Vec<String>) {
    let net = argv_network(argv).map(str::to_string);
    let aliases = argv
        .windows(2)
        .filter(|w| w[0] == "--network-alias")
        .map(|w| w[1].clone())
        .collect();
    (net, aliases)
}

// ---------------------------------------------------------------------------------------------
// Volumes.

fn volume_names(bin: &Path) -> Vec<String> {
    let (_, out, _) = kern(bin, &["volume", "ls", "--json"]);
    json::parse(out.trim())
        .ok()
        .and_then(|v| v.as_array().map(<[Value]>::to_vec))
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.get("name").and_then(Value::as_str).map(str::to_string))
        .collect()
}

fn volume_json(name: &str, mountpoint: &str) -> String {
    let m = meta_read("volumes", name);
    format!(
        "{{\"CreatedAt\":{},\"Driver\":\"local\",\"Labels\":{},\"Mountpoint\":{},\"Name\":{},\"Options\":{{}},\"Scope\":\"local\"}}",
        json_str(&rfc3339(if m.created > 0 { m.created } else { now() })),
        labels_json(&m.labels),
        json_str(mountpoint),
        json_str(name)
    )
}

fn volume_path(bin: &Path, name: &str) -> Option<String> {
    let (code, out, _) = kern(bin, &["volume", "inspect", name, "--json"]);
    if code != 0 {
        return None;
    }
    json::parse(out.trim())
        .ok()?
        .get("path")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// `GET /volumes` (`label`, `name` filters; `dangling` is answered with every volume).
fn volume_list(bin: &Path, req: &Request) -> Response {
    let f = match filters_of(req) {
        Ok(f) => f,
        Err(r) => return r,
    };
    let (labels, names) = (filter_values(&f, "label"), filter_values(&f, "name"));
    let rows: Vec<String> = volume_names(bin)
        .iter()
        .filter(|n| {
            (names.is_empty() || names.iter().any(|w| n.contains(w.as_str())))
                && labels_match(&labels, &meta_read("volumes", n).labels)
        })
        .map(|n| volume_json(n, ""))
        .collect();
    json_response(
        200,
        format!("{{\"Volumes\":[{}],\"Warnings\":null}}", rows.join(",")),
    )
}

/// `POST /volumes/create`: a kern named volume, the client's labels kept; one that exists is
/// answered as it is, as Docker answers it.
fn volume_create(bin: &Path, req: &Request) -> Response {
    let body = json::parse(&String::from_utf8_lossy(&req.body)).unwrap_or(Value::Null);
    match body.get("Driver").and_then(Value::as_str) {
        None | Some("" | "local") => {}
        Some(d) => {
            return error(
                400,
                &format!("volume driver {d:?}: kern's volumes are local, the only driver it has"),
            )
        }
    }
    // THE LOCAL DRIVER'S OPTIONS GO TO `kern volume create --opt`, which takes Docker's bind form
    // (`type=none`, `o=bind`, `device=<dir>`: the volume's files in that directory) and refuses
    // anything else with its reason. They were refused here wholesale, so a client creating a
    // volume on a disk of its choosing could not (MEASURED: 400 for `device=`).
    let mut opts: Vec<String> = Vec::new();
    if let Some(o) = body.get("DriverOpts").and_then(Value::as_object) {
        for (k, v) in o {
            let Some(v) = v.as_str() else {
                return error(400, &format!("DriverOpts {k:?}: a value is a string"));
            };
            opts.push("--opt".to_string());
            opts.push(format!("{k}={v}"));
        }
    }
    let name = match body
        .get("Name")
        .and_then(Value::as_str)
        .filter(|n| !n.is_empty())
    {
        Some(n) => n.to_string(),
        None => id_of(&format!("volume/{}/{}", now(), std::process::id())),
    };
    if !valid_name(&name) && !(name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())) {
        return error(400, &format!("invalid volume name {name:?}"));
    }
    if !volume_names(bin).contains(&name) {
        let mut args: Vec<&str> = vec!["volume", "create", &name];
        args.extend(opts.iter().map(String::as_str));
        let (code, _, err) = kern(bin, &args);
        if code != 0 {
            // Options kern refused are the request's fault, not the server's.
            return error(if opts.is_empty() { 500 } else { 400 }, &kern_error(&err));
        }
        meta_write(
            "volumes",
            &name,
            &Meta {
                labels: labels_of_value(body.get("Labels")),
                created: now(),
                internal: false,
            },
        );
    }
    let path = volume_path(bin, &name).unwrap_or_default();
    json_response(201, volume_json(&name, &path))
}

fn volume_inspect(bin: &Path, name: &str) -> Response {
    match volume_path(bin, name) {
        Some(p) => json_response(200, volume_json(name, &p)),
        None => error(404, &format!("get {name}: no such volume")),
    }
}

fn volume_remove(bin: &Path, name: &str) -> Response {
    if !volume_names(bin).iter().any(|n| n == name) {
        return error(404, &format!("get {name}: no such volume"));
    }
    let (code, _, err) = kern(bin, &["volume", "rm", name]);
    if code != 0 {
        let why = kern_error(&err);
        let status = if why.contains("in use") || why.contains("used by") {
            409
        } else {
            500
        };
        return error(status, &why);
    }
    meta_forget("volumes", name);
    no_content()
}

// ---------------------------------------------------------------------------------------------
// Routing.

/// The `/networks` and `/volumes` requests, or `None` for a path that is neither.
pub(crate) fn handle(req: &Request, bin: &Path, seg: &[&str]) -> Option<Response> {
    Some(match (req.method.as_str(), seg) {
        ("GET", ["networks"]) => network_list(bin, req),
        ("POST", ["networks", "create"]) => network_create(bin, req),
        ("GET", ["networks", id]) => match resolve_network(bin, id) {
            Some(n) => json_response(200, network_json(bin, &n, &kern_boxes(bin))),
            None => error(404, &format!("network {id} not found")),
        },
        ("DELETE", ["networks", id]) => network_remove(bin, id),
        ("POST", ["networks", id, "connect"]) => network_connect(bin, id, req),
        ("POST", ["networks", id, "disconnect"]) => network_disconnect(bin, id, req),
        ("GET", ["volumes"]) => volume_list(bin, req),
        ("POST", ["volumes", "create"]) => volume_create(bin, req),
        ("GET", ["volumes", name]) => volume_inspect(bin, name),
        ("DELETE", ["volumes", name]) => volume_remove(bin, name),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_filter_as_docker_reads_it() {
        let l = vec![
            ("com.docker.compose.project".to_string(), "shop".to_string()),
            (
                "com.docker.compose.network".to_string(),
                "default".to_string(),
            ),
        ];
        assert!(labels_match(
            &["com.docker.compose.project=shop".into()],
            &l
        ));
        assert!(labels_match(&["com.docker.compose.network".into()], &l));
        assert!(!labels_match(
            &["com.docker.compose.project=other".into()],
            &l
        ));
        assert!(labels_match(&[], &l));
    }

    #[test]
    fn aliases_skip_the_own_name_and_repeats() {
        let ep =
            json::parse(r#"{"Aliases":["web","shop-web-1"],"DNSNames":["web","w2"]}"#).unwrap();
        assert_eq!(endpoint_aliases(Some(&ep), "shop-web-1"), vec!["web", "w2"]);
        let argv: Vec<String> = [
            "box",
            "n",
            "--network",
            "shop_default",
            "--network-alias",
            "web",
            "--image",
            "x",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            created_network(&argv),
            (Some("shop_default".into()), vec!["web".into()])
        );
        let nj = json::parse(&networks_json(Some("shop_default"), &["web".into()])).unwrap();
        assert!(nj
            .get("shop_default")
            .and_then(|n| n.get("Aliases"))
            .is_some());
    }
}
