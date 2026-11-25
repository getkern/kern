//! The networks of one compose project as bridges of ONE kern pod, so a container can be on several.
//!
//! WHY. A Docker network made through this API is a kern pod (see `netvol`), and a box is in one pod,
//! so a compose service on two networks was refused by name. `kern compose` runs such a file by
//! giving the stack one pod with a bridge per network, each service attached to the bridges of its
//! own networks; this module does the same for a project that `docker compose` creates through the
//! socket. MEASURED before: a file whose `mid` service is on `front` and `back` was refused at its
//! `network connect`, where Docker and `kern compose` ran it.
//!
//! HOW, as the client drives it. `docker compose` creates the project's networks first (with the
//! labels `com.docker.compose.project` and `com.docker.compose.network`), then every container, then
//! starts them. So:
//!
//! - a network with those labels is RECORDED here and no pod is made for it yet;
//! - the first container attached to one makes the project's pod (`kern pod create <project>`), with
//!   one bridge per network recorded so far, in creation order, `10.89.<bridge>.0/24`;
//! - each attachment takes the next free address on that network's bridge and writes the network's
//!   record (`kern pod __record`, the record `kern compose` writes at `up`) with every member's name
//!   and aliases, so a container started later knows every peer created before it, which with
//!   compose is all of them;
//! - the box starts with `--network <project>_<network>` once per network, and `kern box` takes the
//!   address the record gives its name on each.
//!
//! Kept on disk beside the other objects this API keeps (`compat-meta/projnets/<network>`): the
//! server exits when idle and the plan must outlive it.

use std::net::Ipv4Addr;
use std::path::Path;

use kern_common::json::{self, Value};
use kern_common::json_str;

use crate::api::{kern, kern_error, valid_name};

/// ONE CHANGE AT A TIME. `docker compose` creates a project's containers in parallel, and two first
/// containers each made the project's pod: MEASURED, the second answered "pod already exists". Every
/// read-modify-write of this module's state holds this, so a pod is made once and two attachments
/// cannot take one address. The server is one process; its requests are threads.
static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn locked() -> std::sync::MutexGuard<'static, ()> {
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The compose labels that make a network one of a project's.
const PROJECT_LABEL: &str = "com.docker.compose.project";
const NETWORK_LABEL: &str = "com.docker.compose.network";

/// One network of a project, as recorded here.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProjNet {
    /// The Docker network's name, `<project>_<network>` as compose makes it.
    pub(crate) name: String,
    pub(crate) project: String,
    pub(crate) network: String,
    /// Its bridge in the project's pod (`kbr<bridge>`), in creation order.
    pub(crate) bridge: u8,
    pub(crate) internal: bool,
    /// Each member's address and its names: the container's own first, then its aliases.
    pub(crate) members: Vec<(Ipv4Addr, Vec<String>)>,
}

impl ProjNet {
    /// The subnet of its bridge.
    /// The member called `old` is called `new` now (see [`rename`]); `true` when there was one.
    fn rename_member(&mut self, old: &str, new: &str) -> bool {
        let mut changed = false;
        for (_, names) in &mut self.members {
            if names.first().is_some_and(|n| n == old) {
                names.retain(|n| n != new);
                if let Some(first) = names.first_mut() {
                    *first = new.to_string();
                }
                changed = true;
            }
        }
        changed
    }

    pub(crate) fn cidr(&self) -> String {
        format!("10.89.{}.0/24", self.bridge)
    }

    /// The member address of `container` on this network, if it is one.
    pub(crate) fn address_of(&self, container: &str) -> Option<Ipv4Addr> {
        self.members
            .iter()
            .find(|(_, names)| names.first().is_some_and(|n| n == container))
            .map(|(ip, _)| *ip)
    }

    /// The lowest free member address, `.2` onwards (`.1` is the bridge's own).
    fn next_free(&self) -> Option<Ipv4Addr> {
        (2u8..=254)
            .map(|h| Ipv4Addr::new(10, 89, self.bridge, h))
            .find(|ip| !self.members.iter().any(|(m, _)| m == ip))
    }
}

/// The project and network a network's labels name, when it is a compose project's and its name is
/// the one compose gives it, `<project>_<network>`. PURE.
pub(crate) fn project_of(name: &str, labels: &[(String, String)]) -> Option<(String, String)> {
    let get = |k: &str| labels.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let (project, network) = (get(PROJECT_LABEL)?, get(NETWORK_LABEL)?);
    (format!("{project}_{network}") == name && valid_name(&project) && !network.is_empty())
        .then_some((project, network))
}

fn dir() -> Option<std::path::PathBuf> {
    crate::netvol::meta_dir("projnets")
}

fn encode(p: &ProjNet) -> String {
    let members: Vec<String> = p
        .members
        .iter()
        .map(|(ip, names)| {
            let n: Vec<String> = names.iter().map(|x| json_str(x)).collect();
            format!("[{},[{}]]", json_str(&ip.to_string()), n.join(","))
        })
        .collect();
    format!(
        "{{\"project\":{},\"network\":{},\"bridge\":{},\"internal\":{},\"members\":[{}]}}",
        json_str(&p.project),
        json_str(&p.network),
        p.bridge,
        p.internal,
        members.join(",")
    )
}

fn decode(name: &str, text: &str) -> Option<ProjNet> {
    let v = json::parse(text).ok()?;
    let members = v
        .get("members")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|m| {
            let m = m.as_array()?;
            let ip: Ipv4Addr = m.first()?.as_str()?.parse().ok()?;
            let names: Vec<String> = m
                .get(1)?
                .as_array()?
                .iter()
                .filter_map(|n| n.as_str().map(str::to_string))
                .collect();
            (!names.is_empty()).then_some((ip, names))
        })
        .collect();
    Some(ProjNet {
        name: name.to_string(),
        project: v.get("project")?.as_str()?.to_string(),
        network: v.get("network")?.as_str()?.to_string(),
        bridge: u8::try_from(v.get("bridge")?.as_i64()?).ok()?,
        internal: v.get("internal").and_then(Value::as_bool) == Some(true),
        members,
    })
}

/// The recorded network called `name`, if it is a project's.
pub(crate) fn get(name: &str) -> Option<ProjNet> {
    if !valid_name(name) {
        return None;
    }
    let text = std::fs::read_to_string(dir()?.join(name)).ok()?;
    decode(name, &text)
}

/// Every network recorded here, in no particular order.
pub(crate) fn all() -> Vec<ProjNet> {
    let Some(d) = dir() else {
        return Vec::new();
    };
    let Ok(rd) = std::fs::read_dir(d) else {
        return Vec::new();
    };
    rd.flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with('.') {
                return None;
            }
            decode(&n, &std::fs::read_to_string(e.path()).ok()?)
        })
        .collect()
}

/// A project's networks, in bridge order.
fn of_project(project: &str) -> Vec<ProjNet> {
    let mut v: Vec<ProjNet> = all().into_iter().filter(|p| p.project == project).collect();
    v.sort_by_key(|p| p.bridge);
    v
}

fn save(p: &ProjNet) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    let d = dir().ok_or("no cache directory for the project networks")?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&d)
        .map_err(|e| format!("{}: {e}", d.display()))?;
    let tmp = d.join(format!(".{}.new", p.name));
    std::fs::write(&tmp, encode(p)).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, d.join(&p.name)).map_err(|e| format!("{}: {e}", p.name))
}

fn forget(name: &str) {
    if let Some(d) = dir() {
        let _ = std::fs::remove_file(d.join(name));
    }
}

/// The marker this API leaves for the pod it made for a project, with how many bridges it was made
/// with: a network recorded after that cannot be one of its bridges.
fn pod_marker(project: &str) -> Option<std::path::PathBuf> {
    crate::netvol::meta_dir("projpods").map(|d| d.join(project))
}

/// Is `pod` the pod this API made for a compose project? It is an implementation of the project's
/// networks and is not listed as a network of its own.
pub(crate) fn is_project_pod(pod: &str) -> bool {
    valid_name(pod) && pod_bridges(pod).is_some()
}

fn pod_bridges(project: &str) -> Option<u8> {
    std::fs::read_to_string(pod_marker(project)?)
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Record a project's network at its create: no pod yet (see the module). `Err` when the project's
/// pod already exists, which a new bridge cannot join; the caller then makes it a pod of its own.
pub(crate) fn create(
    name: &str,
    project: &str,
    network: &str,
    internal: bool,
) -> Result<(), String> {
    let _g = locked();
    if pod_bridges(project).is_some() {
        return Err(format!(
            "project {project} already has its pod, made with its other networks"
        ));
    }
    let bridge = u8::try_from(of_project(project).len())
        .map_err(|_| "a project has more networks than a pod can carry (256)".to_string())?;
    save(&ProjNet {
        name: name.to_string(),
        project: project.to_string(),
        network: network.to_string(),
        bridge,
        internal,
        members: Vec::new(),
    })
}

/// The project's pod, made on first need with a bridge per network recorded so far.
fn ensure_pod(bin: &Path, project: &str) -> Result<(), String> {
    let nets = of_project(project);
    // A pod this API made and that no longer runs (the machine restarted, or it was removed by
    // hand) is made again, with every network the project has now.
    if pod_bridges(project).is_some() && !crate::netvol::network_exists(bin, project) {
        if let Some(m) = pod_marker(project) {
            let _ = std::fs::remove_file(m);
        }
    }
    if let Some(n) = pod_bridges(project) {
        if let Some(late) = nets.iter().find(|p| p.bridge >= n) {
            return Err(format!(
                "network {} was created after the project's first container, when its pod was \
                 made with the networks before it; `docker compose down` and `up` makes them all",
                late.name
            ));
        }
        return Ok(());
    }
    let mut args: Vec<String> = vec![
        "pod".into(),
        "create".into(),
        project.into(),
        "--no-outbound".into(),
    ];
    for p in &nets {
        args.push("--bridge".into());
        args.push(p.cidr());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, _, err) = kern(bin, &refs);
    if code != 0 {
        return Err(format!("the project's pod {project}: {}", kern_error(&err)));
    }
    if let Some(m) = pod_marker(project) {
        use std::os::unix::fs::DirBuilderExt;
        if let Some(parent) = m.parent() {
            let _ = std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent);
        }
        let _ = std::fs::write(&m, nets.len().to_string());
    }
    for p in &nets {
        write_record(bin, p)?;
    }
    Ok(())
}

/// The network's record in the project's pod, every member's names at its address.
fn write_record(bin: &Path, p: &ProjNet) -> Result<(), String> {
    use std::io::Write;
    let mut hosts = String::new();
    for (ip, names) in &p.members {
        for n in names {
            hosts.push_str(&format!("{ip} {n}\n"));
        }
    }
    let bridge = p.bridge.to_string();
    let mut args = vec![
        "pod",
        "__record",
        p.project.as_str(),
        p.network.as_str(),
        bridge.as_str(),
        "24",
    ];
    if p.internal {
        args.push("internal");
    }
    let child = std::process::Command::new(bin)
        .args(&args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn();
    let mut child = child.map_err(|e| format!("cannot run {}: {e}", bin.display()))?;
    if let Some(mut sin) = child.stdin.take() {
        let _ = sin.write_all(hosts.as_bytes());
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("pod __record: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(kern_error(&String::from_utf8_lossy(&out.stderr)))
    }
}

/// Put `container` on the project network `name` with its `aliases`: the project's pod made if this
/// is its first container, an address taken on the network's bridge (the one it already has, for a
/// container attached again), and the record rewritten. `Ok(None)` when `name` is no project's
/// network. `others` are the networks the container is already on, which must be the same
/// project's: a box is in one pod.
pub(crate) fn attach(
    bin: &Path,
    name: &str,
    container: &str,
    aliases: &[String],
    others: &[String],
) -> Result<Option<Ipv4Addr>, String> {
    let _g = locked();
    let Some(mut p) = get(name) else {
        return Ok(None);
    };
    for o in others.iter().filter(|o| *o != name) {
        match get(o) {
            Some(q) if q.project == p.project => {}
            _ => {
                return Err(format!(
                    "container {container} is on network {o}, which is not a network of compose \
                     project {}: a kern box is in one pod, and the networks of one project are \
                     bridges of the same one",
                    p.project
                ))
            }
        }
    }
    ensure_pod(bin, &p.project)?;
    // Re-read: `ensure_pod` may have run on a state another request changed.
    p = get(name).ok_or_else(|| format!("network {name} was removed"))?;
    let ip = match p.address_of(container) {
        Some(ip) => ip,
        None => p
            .next_free()
            .ok_or_else(|| format!("network {name} has no free address left"))?,
    };
    let mut names = vec![container.to_string()];
    for a in aliases {
        if a != container && valid_name(a) && !names.contains(a) {
            names.push(a.clone());
        }
    }
    p.members
        .retain(|(_, n)| n.first().is_none_or(|n| n != container));
    p.members.push((ip, names));
    save(&p)?;
    write_record(bin, &p)?;
    Ok(Some(ip))
}

/// `container` leaves the project network `name` (a `network disconnect` before its start).
pub(crate) fn detach(bin: &Path, name: &str, container: &str) {
    let _g = locked();
    if let Some(mut p) = get(name) {
        let before = p.members.len();
        p.members
            .retain(|(_, n)| n.first().is_none_or(|n| n != container));
        if p.members.len() != before && save(&p).is_ok() && pod_bridges(&p.project).is_some() {
            let _ = write_record(bin, &p);
        }
    }
}

/// `container` is gone: its addresses are freed and the records rewritten.
pub(crate) fn detach_everywhere(bin: &Path, container: &str) {
    let _g = locked();
    for mut p in all() {
        let before = p.members.len();
        p.members
            .retain(|(_, n)| n.first().is_none_or(|n| n != container));
        if p.members.len() != before && save(&p).is_ok() && pod_bridges(&p.project).is_some() {
            let _ = write_record(bin, &p);
        }
    }
}

/// A container renamed: its membership of every project network goes by the new name. `docker
/// compose` recreates a service under a TEMPORARY name (`<id>_<project>-<service>-1`) and renames it
/// once the old one is gone, and the member kept the temporary name: removing the container by its
/// real name then left it on the network, which `down` could not remove ("active endpoints").
/// MEASURED in Grok's round 6, case 49. The new name becomes the member's own, once (it was
/// usually one of its aliases already), and the record is written again.
pub(crate) fn rename(bin: &Path, old: &str, new: &str) {
    let _g = locked();
    for mut p in all() {
        if p.rename_member(old, new) && save(&p).is_ok() && pod_bridges(&p.project).is_some() {
            let _ = write_record(bin, &p);
        }
    }
}

/// The project networks `container` is a member of, with its address on each.
pub(crate) fn networks_of(container: &str) -> Vec<(String, Ipv4Addr, Vec<String>)> {
    let mut v: Vec<(String, Ipv4Addr, Vec<String>)> = all()
        .into_iter()
        .filter_map(|p| {
            let (ip, names) = p
                .members
                .iter()
                .find(|(_, n)| n.first().is_some_and(|n| n == container))?
                .clone();
            Some((p.name.clone(), ip, names.into_iter().skip(1).collect()))
        })
        .collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

/// `DELETE /networks/<name>` of a project network: refused while a container is on it; the last
/// network of a project takes the project's pod with it.
pub(crate) fn remove(bin: &Path, name: &str) -> Result<(), (u16, String)> {
    let _g = locked();
    let Some(p) = get(name) else {
        return Err((404, format!("network {name} not found")));
    };
    if !p.members.is_empty() {
        return Err((
            409,
            format!("error while removing network: network {name} has active endpoints"),
        ));
    }
    forget(name);
    if of_project(&p.project).is_empty() && pod_bridges(&p.project).is_some() {
        let (code, _, err) = kern(bin, &["pod", "rm", &p.project]);
        if let Some(m) = pod_marker(&p.project) {
            let _ = std::fs::remove_file(m);
        }
        if code != 0 {
            return Err((500, kern_error(&err)));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A compose project's network is recognised by its two labels and the name compose gives it,
    /// and nothing else is.
    #[test]
    fn a_project_network_is_named_by_its_labels() {
        let l = |p: &str, n: &str| {
            vec![
                (PROJECT_LABEL.to_string(), p.to_string()),
                (NETWORK_LABEL.to_string(), n.to_string()),
            ]
        };
        assert_eq!(
            project_of("shop_back", &l("shop", "back")),
            Some(("shop".into(), "back".into()))
        );
        assert_eq!(
            project_of("other", &l("shop", "back")),
            None,
            "not compose's name"
        );
        assert_eq!(project_of("shop_back", &[]), None, "no labels");
    }

    /// The record round-trips, and addresses are taken lowest-free from `.2`, the container's own
    /// first, a freed one taken again.
    #[test]
    fn a_project_network_round_trips_and_takes_the_lowest_free_address() {
        let mut p = ProjNet {
            name: "shop_back".into(),
            project: "shop".into(),
            network: "back".into(),
            bridge: 1,
            internal: true,
            members: vec![],
        };
        assert_eq!(p.cidr(), "10.89.1.0/24");
        assert_eq!(p.next_free(), Some(Ipv4Addr::new(10, 89, 1, 2)));
        p.members.push((
            Ipv4Addr::new(10, 89, 1, 2),
            vec!["db-1".into(), "db".into()],
        ));
        p.members
            .push((Ipv4Addr::new(10, 89, 1, 4), vec!["web-1".into()]));
        assert_eq!(p.next_free(), Some(Ipv4Addr::new(10, 89, 1, 3)));
        assert_eq!(p.address_of("db-1"), Some(Ipv4Addr::new(10, 89, 1, 2)));
        assert_eq!(p.address_of("db"), None, "an alias is not a member");
        assert_eq!(decode("shop_back", &encode(&p)), Some(p));
    }

    /// `docker compose` recreates a service under a temporary name and renames it: the member takes
    /// the new name once (it was one of its aliases), keeps its address and its other aliases, and a
    /// member of another name is not touched.
    #[test]
    fn a_renamed_member_takes_its_new_name_once() {
        let mut p = ProjNet {
            name: "g_default".into(),
            project: "g".into(),
            network: "default".into(),
            bridge: 0,
            internal: false,
            members: vec![
                (
                    Ipv4Addr::new(10, 89, 0, 3),
                    vec!["b846550b81ee_g-s-1".into(), "g-s-1".into(), "s".into()],
                ),
                (
                    Ipv4Addr::new(10, 89, 0, 2),
                    vec!["g-db-1".into(), "db".into()],
                ),
            ],
        };
        assert!(p.rename_member("b846550b81ee_g-s-1", "g-s-1"));
        assert_eq!(p.members[0].1, vec!["g-s-1".to_string(), "s".to_string()]);
        assert_eq!(p.address_of("g-s-1"), Some(Ipv4Addr::new(10, 89, 0, 3)));
        assert_eq!(p.members[1].1, vec!["g-db-1".to_string(), "db".to_string()]);
        assert!(!p.rename_member("nobody", "x"));
    }
}
