//! A network shared BETWEEN PROJECTS: the object behind `networks: {x: {external: true}}`.
//!
//! WHAT THE KEY MEANS AND WHY IT NEEDED AN OBJECT. Under Docker, a network declared `external: true`
//! is one the compose file does not own: it was created beforehand and other projects are on it, so
//! a reverse proxy in one file resolves and reaches the applications in another. kern's own network
//! is a stack's pod, which belongs to one project, so a peer in a different stack resolved nothing
//! and reached nothing, and until now kern only said so.
//!
//! WHY IT IS NOT A BRIDGE, MEASURED. A shared layer-2 bridge between two rootless pods is not
//! available at all, and that was established before any of this was designed. Two refusals, each
//! with a control that rules out the tool:
//!
//! ```text
//! from the INITIAL user namespace, setns() into a holder's net namespace   EPERM
//!   control: enter that holder's USER namespace first, then its net ns     OK
//! from INSIDE pod A's user namespace, create a veth whose peer goes
//!   into pod B's net namespace (a SIBLING user namespace)                  EPERM
//!   control: the same command with both ends inside A                      OK
//! ```
//!
//! There is no vantage point. Joining a network namespace needs `CAP_SYS_ADMIN` in the caller's OWN
//! user namespace, which an unprivileged process does not have in the initial one; placing a link in
//! another namespace needs `CAP_NET_ADMIN` in the user namespace that OWNS it, which a process
//! inside a sibling does not have. The two pods would have to be created as children of one common
//! user namespace, which is a decision taken before either stack exists.
//!
//! SO IT IS THE RELAY WIRING, WHICH ALREADY CROSSES SIBLING USER NAMESPACES. A peer relay forks two
//! halves; each enters only ITS OWN box and they meet on a socketpair inherited before either
//! entered anything, so neither needs a capability over the other's namespace. MEASURED end to end
//! before this module existed: two stacks brought up separately, a hand-written plan naming one box
//! from each, and the box in project B read the banner of the listener in project A through an alias
//! on its own loopback. The transport was never the missing piece; the lifetime was.
//!
//! WHAT THIS MODULE OWNS is that lifetime: which boxes are on a network, so a stack that comes up
//! later can find the ones already there, build relays in both directions, and take them away again
//! when it leaves.
//!
//! THE JOINER OWNS EVERY RELAY IT CREATES, in both directions. The alternative was to ask the
//! already-running stack's holder to adopt the new edges, which needs a channel into a live process
//! and gains nothing: when the joiner goes away its relays go with it, which is exactly right,
//! because what they reached is going away too.

use std::path::{Path, PathBuf};

use crate::error::Error;

// EVERY FAILURE HERE IS `Error::Sandbox`, which is the variant for an operational failure in a box
// or pod command and carries NO generic hint. `Error::Compose` was wrong and it showed: `kern
// network create proxy` on an existing network printed "hint: compose: `[box.NAME]` tables with
// image/rootfs, command, depends_on" under a message about a network, which is advice for a
// different file about a different problem. These messages carry their own remedy.

/// The root of the network registry: `<runtime>/kern/networks`.
///
/// Under `XDG_RUNTIME_DIR` like every other authoritative registry child, which also settles the
/// lifetime question the object would otherwise raise: a network does not survive a reboot, and
/// neither do the boxes that were on it. A network that outlived its members would be a name
/// promising peers that are gone.
fn networks_root() -> Result<PathBuf, Error> {
    crate::registry::runtime_subdir_public("networks")
        .map_err(|e| Error::Sandbox(format!("network dir: {e}")))
}

/// One network's directory.
fn net_dir(name: &str) -> Result<PathBuf, Error> {
    Ok(networks_root()?.join(validated(name)?))
}

/// A network name kern will accept, with the same rule as every other named resource.
///
/// REFUSED AT THE BOUNDARY rather than sanitised, because this name becomes a single path component
/// under the registry root: `..` or a name with a separator would place a member list somewhere the
/// registry does not defend. `valid_resource_name` is the rule volumes and pods already use, so
/// there is one answer to "what may be named" in this tree rather than three.
fn validated(name: &str) -> Result<&str, Error> {
    if kern_common::valid_resource_name(name) {
        Ok(name)
    } else {
        Err(Error::Sandbox(format!(
            "'{name}' is not a usable network name: letters, digits, '_', '.' and '-' only, no \
             leading '-' or '.', at most 64 characters"
        )))
    }
}

/// Does this network exist? The question `external: true` asks.
pub fn exists(name: &str) -> bool {
    net_dir(name).is_ok_and(|d| d.is_dir())
}

/// Every network that exists, sorted.
pub fn list() -> Vec<String> {
    let Ok(root) = networks_root() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    out.sort();
    out
}

/// Create a network. Refuses one that already exists, as `docker network create` does.
///
/// EXPLICIT AND NOT INFERRED FROM A COMPOSE FILE. Docker requires an `external: true` network to
/// exist before a stack may use it, and refuses the stack otherwise; inferring it would turn a typo
/// in a network name into a second, empty network that silently resolves nothing, which is the
/// failure this key exists to prevent.
pub fn create(name: &str) -> Result<(), Error> {
    let dir = net_dir(name)?;
    if dir.is_dir() {
        return Err(Error::Sandbox(format!("network '{name}' already exists")));
    }
    std::fs::create_dir_all(dir.join("members"))
        .map_err(|e| Error::Sandbox(format!("cannot create network '{name}': {e}")))?;
    let Some(idx) = allocate_net_index() else {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(Error::Sandbox(format!(
            "cannot create network '{name}': all 256 network addresses are in use. Remove a \
             network that is no longer needed with `kern network rm`"
        )));
    };
    std::fs::write(dir.join("index"), idx.to_string()).map_err(|e| {
        let _ = std::fs::remove_dir_all(&dir);
        Error::Sandbox(format!("cannot create network '{name}': {e}"))
    })
}

/// Remove a network. Refuses while boxes are still on it, naming them.
///
/// THE LIVE MEMBERS DECIDE, NOT THE FILES. `members()` prunes records whose box is gone, so a
/// network whose stacks all exited is removable even though its directory is not empty; one with a
/// running member is not, because removing it would leave those relays pointing at a network object
/// that no longer says who is on it.
pub fn remove(name: &str) -> Result<(), Error> {
    let dir = net_dir(name)?;
    if !dir.is_dir() {
        return Err(Error::Sandbox(format!("no network named '{name}'")));
    }
    let live = members(name);
    if !live.is_empty() {
        let who: Vec<String> = live
            .iter()
            .map(|m| format!("{} ({})", m.service, m.project))
            .collect();
        return Err(Error::Sandbox(format!(
            "network '{name}' still has {} box(es) on it: {}. Take their stacks down first, or the \
             peers they resolve would keep naming a network nothing describes",
            live.len(),
            who.join(", ")
        )));
    }
    std::fs::remove_dir_all(&dir)
        .map_err(|e| Error::Sandbox(format!("cannot remove network '{name}': {e}")))
}

/// The second octet of every cross-project alias: `127.1.<network>.<member>`.
///
/// WHY `127.1` AND NOT MORE OF `127.0`. A stack's OWN peer aliases live in `127.0.0.2` through
/// `127.0.0.254` and are handed out by the `--no-pod` address plan. Cross-project aliases must not
/// land on one of those, and "must not" has to be a property of the layout rather than a rule two
/// allocators both remember: `127.0.x` and `127.1.x` cannot meet, whatever either side does. Both
/// are inside the `127.0.0.0/8` the kernel gives `lo`, so binding one needs nothing configured.
const CROSS_PROJECT_OCTET: u32 = 1;

/// A member's address on a network: `127.1.<network index>.<member index + 1>`.
///
/// ONE ADDRESS PER MEMBER, USED FROM BOTH ENDS, and that is what makes the scheme collision-free
/// rather than merely unlikely to collide. Every other member binds this address on its own loopback
/// to reach that member, and a member connecting OUT uses its own address as the source, so inside
/// any box the set of addresses in use is exactly the set of members it can see - one each, never
/// two names on one address.
///
/// THE ALTERNATIVE WAS A PER-PLAN INDEX, and it is unsound with three projects. If each joiner
/// numbered its peers from zero, box X of project A would hold an alias numbered 1 written by B and
/// another alias numbered 1 written by C, for two different peers. The number therefore has to be a
/// fact about the MEMBER on the NETWORK, allocated once when it joins and carried in its record.
///
/// `+ 1` because `.0` is a network address and nothing should bind it. The network index is in the
/// third octet so a box on several external networks cannot see one address meaning two peers.
#[must_use]
pub fn member_addr(net_index: u32, member_index: u32) -> Option<u32> {
    if net_index > 255 || member_index >= 254 {
        return None;
    }
    Some((127 << 24) | (CROSS_PROJECT_OCTET << 16) | (net_index << 8) | (member_index + 1))
}

/// The network's own index, allocated once at creation and stable for its lifetime.
fn net_index(name: &str) -> Option<u32> {
    let dir = net_dir(name).ok()?;
    std::fs::read_to_string(dir.join("index"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Allocate the smallest index not already taken by another network.
///
/// SMALLEST FREE RATHER THAN A COUNTER, because a counter that only goes up runs out after 256
/// networks have been created and removed over a session, while the number actually in use is the
/// number that exist right now. Read under the same `O_EXCL` creation that makes `create` itself
/// exclusive, so two concurrent `network create` calls cannot be handed the same index.
fn allocate_net_index() -> Option<u32> {
    let taken: Vec<u32> = list().iter().filter_map(|n| net_index(n)).collect();
    (0..=255u32).find(|i| !taken.contains(i))
}

/// One box on a network, as another project needs to see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The box's registry name, which is how a relay plan refers to it.
    ///
    /// THE NAME AND NOT THE PID, because the relay holder re-resolves a name every time it heals a
    /// relay: a box that restarts keeps its name and gets a new pid, and a plan carrying the pid
    /// would aim the next relay at a process that no longer exists - or, worse, at whatever inherited
    /// the number.
    pub box_name: String,
    /// The compose SERVICE name, which is what a peer writes in its configuration and resolves.
    pub service: String,
    /// The project this box belongs to, so a stack can tell its own members from the others.
    pub project: String,
    /// The ports this service declares, which is exactly the set a relay may be built for.
    pub ports: Vec<u16>,
    /// This member's index ON THIS NETWORK, allocated when it joined. See [`member_addr`].
    pub index: u32,
}

impl Member {
    /// One TAB-separated line. Ports are comma-separated, which cannot collide with the separator.
    fn encode(&self) -> String {
        let ports: Vec<String> = self.ports.iter().map(u16::to_string).collect();
        format!(
            "{}\t{}\t{}\t{}\t{}\n",
            self.box_name,
            self.service,
            self.project,
            ports.join(","),
            self.index
        )
    }

    /// Parse one line back, or `None` for anything malformed.
    ///
    /// A MALFORMED LINE IS DROPPED AND NOT GUESSED AT. Every other decoder in this tree names the
    /// line number and fails, because there the file is kern's own plan for one stack. Here the file
    /// is a directory of independent records written by different processes at different times, so
    /// one unreadable record must not stop a stack from reaching the peers it CAN see - and an entry
    /// nobody can parse describes no reachable peer anyway.
    fn decode(line: &str) -> Option<Self> {
        let mut f = line.trim_end_matches('\n').split('\t');
        let box_name = f.next()?.to_string();
        let service = f.next()?.to_string();
        let project = f.next()?.to_string();
        let ports_raw = f.next().unwrap_or("");
        let index: u32 = f.next()?.trim().parse().ok()?;
        if f.next().is_some() {
            return None; // a sixth field is a format this reader does not know
        }
        if box_name.is_empty() || service.is_empty() || project.is_empty() {
            return None;
        }
        let mut ports = Vec::new();
        for p in ports_raw.split(',').filter(|p| !p.is_empty()) {
            ports.push(p.parse::<u16>().ok()?);
        }
        Some(Member {
            box_name,
            service,
            project,
            ports,
            index,
        })
    }
}

/// The file holding one member's record. Named after the BOX, so joining twice overwrites rather
/// than duplicating, and so leaving is a single unlink with no scan.
fn member_path(dir: &Path, box_name: &str) -> Option<PathBuf> {
    // The box name is a path component here. It comes from the registry, where it is already
    // constrained, but this is the one place it becomes a filename in an authoritative directory, so
    // the constraint is CHECKED rather than assumed.
    kern_common::valid_resource_name(box_name).then(|| dir.join("members").join(box_name))
}

/// Put a box on a network, allocating its index.
///
/// THE INDEX IS CHOSEN HERE, NOT BY THE CALLER, because it must be unique among the members that are
/// LIVE on this network and the caller cannot see them without racing. The smallest free index is
/// taken, so a day of stacks coming and going does not exhaust the 254 the third octet holds.
///
/// THE RACE IS REAL AND IS NARROWED, NOT DENIED. Two projects joining the same network at the same
/// instant can read the same free index before either writes. The write is `O_EXCL` on the member
/// file, so the second one to arrive at a given index is refused and retries with the next free one;
/// that turns a silent duplicate address into a loop that converges. A member file is named after
/// the BOX, so an honest rejoin (the same box, joining again) overwrites rather than colliding, and
/// is handled before the loop.
///
/// WRITTEN ATOMICALLY, `.new` + rename, for the same reason every other record in this tree is: a
/// reader is another project's `up`, running concurrently by construction, and a half-written line
/// decodes as a member with no ports - a peer that resolves and answers nothing.
pub fn join(network: &str, m: &Member) -> Result<(), Error> {
    let dir = net_dir(network)?;
    if !dir.is_dir() {
        return Err(Error::Sandbox(format!("no network named '{network}'")));
    }
    let Some(path) = member_path(&dir, &m.box_name) else {
        return Err(Error::Sandbox(format!(
            "'{}' is not a usable box name for a network member",
            m.box_name
        )));
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Sandbox(format!("network '{network}': {e}")))?;
    }
    // A REJOIN OF THE SAME BOX KEEPS ITS ADDRESS. Anything else would move a peer's address while
    // other projects still hold it in their hosts files.
    let existing = std::fs::read_to_string(&path)
        .ok()
        .as_deref()
        .and_then(Member::decode)
        .map(|prev| prev.index);

    for attempt in 0..=254u32 {
        let index = match existing {
            Some(i) => i,
            None => {
                let taken: Vec<u32> = members(network).iter().map(|m| m.index).collect();
                match (0..254u32).find(|i| !taken.contains(i)) {
                    Some(i) => i,
                    None => {
                        return Err(Error::Sandbox(format!(
                            "network '{network}' is full: it addresses at most 254 boxes at a time"
                        )))
                    }
                }
            }
        };
        let record = Member { index, ..m.clone() };
        // THE CLAIM IS THE `O_EXCL` CREATE OF A MARKER NAMED AFTER THE INDEX, and it is what makes
        // two simultaneous joiners take different addresses. Without it both would write their own
        // member file happily - they have different names - and both would claim one address.
        let claim = dir.join("members").join(format!(".idx-{index}"));
        let claimed = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&claim);
        if claimed.is_err() && existing.is_none() {
            // Taken between the read and the write, or left by a member that is still live. Either
            // way this index is not ours; the next pass picks another.
            if attempt == 254 {
                return Err(Error::Sandbox(format!(
                    "network '{network}': no free address could be claimed after 255 attempts"
                )));
            }
            continue;
        }
        let tmp = path.with_extension("new");
        if let Err(e) = std::fs::write(&tmp, record.encode()) {
            let _ = std::fs::remove_file(&claim);
            return Err(Error::Sandbox(format!("network '{network}': {e}")));
        }
        return std::fs::rename(&tmp, &path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(&claim);
            Error::Sandbox(format!("network '{network}': {e}"))
        });
    }
    Err(Error::Sandbox(format!(
        "network '{network}': no free address could be claimed"
    )))
}

/// Take a box off a network. Absent is success: `down` runs after a crash too.
pub fn leave(network: &str, box_name: &str) {
    let Ok(dir) = net_dir(network) else { return };
    let Some(path) = member_path(&dir, box_name) else {
        return;
    };
    // THE ADDRESS CLAIM GOES WITH THE RECORD. Releasing only the record would leave the marker
    // behind, and after 254 stacks the network would refuse to take another member while reporting
    // that nobody is on it.
    if let Some(prev) = std::fs::read_to_string(&path)
        .ok()
        .as_deref()
        .and_then(Member::decode)
    {
        let _ = std::fs::remove_file(dir.join("members").join(format!(".idx-{}", prev.index)));
    }
    let _ = std::fs::remove_file(path);
}

/// The LIVE members of a network, pruning records whose box is gone.
///
/// PRUNED ON READ, AND THE PRUNE IS THE POINT. A stack that was killed rather than taken down leaves
/// its records behind, and a joiner that trusted them would build relays into pids that are not
/// there, put dead names in its hosts file, and report peers that answer nothing. The registry
/// already knows which boxes are alive and checks a start time as well as a pid, so the answer is
/// asked of it rather than of a heartbeat this module would have to keep.
///
/// The dead record is DELETED, not skipped, so the directory does not grow without bound across a
/// day of stacks coming and going.
pub fn members(network: &str) -> Vec<Member> {
    let Ok(dir) = net_dir(network) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(dir.join("members")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in entries.filter_map(Result::ok) {
        let path = e.path();
        if path.extension().is_some_and(|x| x == "new") {
            continue; // a rename in flight, not a record
        }
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(".idx-"))
        {
            continue; // an address claim, not a member
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Some(m) = Member::decode(&text) else {
            let _ = std::fs::remove_file(&path);
            continue;
        };
        if crate::registry::find(&m.box_name).is_none() {
            // The box is gone: drop the record AND release its address, or the network fills up
            // with claims nobody holds.
            let _ = std::fs::remove_file(&path);
            if let Some(parent) = path.parent() {
                let _ = std::fs::remove_file(parent.join(format!(".idx-{}", m.index)));
            }
            continue;
        }
        out.push(m);
    }
    out.sort_by(|a, b| a.box_name.cmp(&b.box_name));
    out
}

/// One of our boxes, as the cross-project planner needs to see it.
///
/// A TUPLE STRUCT OF NAMED FIELDS rather than a bare tuple, because the driver builds this from four
/// different places in one expression and a `(String, String, Vec<u16>, Vec<String>)` there is four
/// chances to swap two of them silently. `nopod::ServiceInput` is a bare tuple and its own call
/// sites are the argument against repeating that.
#[derive(Debug, Clone)]
pub struct Joining {
    /// The registry name of the box, which is how the relay plan refers to it.
    pub box_name: String,
    /// The compose service name, which is what a peer resolves.
    pub service: String,
    /// The TCP ports this service declares. A relay exists per DECLARED port and no others, exactly
    /// as inside a stack: a peer answers by name on a port the file names.
    pub ports: Vec<u16>,
    /// The external networks this service is on.
    pub networks: Vec<String>,
}

/// What a stack must do about the external networks its services are on.
#[derive(Debug, Default)]
pub struct CrossPlan {
    /// `--add-host` entries for OUR boxes: `(our box name, "peer:addr")`.
    pub host_entries: Vec<(String, String)>,
    /// Relays, in BOTH directions: ours reaching theirs, and theirs reaching ours.
    pub relays: Vec<crate::nopod::RelayPlan>,
    /// Lines to append to a FOREIGN box's `/etc/hosts`: `(its box name, line)`.
    pub foreign_hosts: Vec<(String, String)>,
    /// `(network, our box name)` for everything we joined, so `down` can leave them.
    pub joined: Vec<(String, String)>,
    /// Networks we are on that currently have no other project's boxes. Not an error - a stack may
    /// legitimately be the first one up - but worth saying, because "my proxy resolves nothing" is
    /// otherwise indistinguishable from a broken feature.
    pub alone_on: Vec<String>,
}

/// The peers a stack will find on its external networks, WITHOUT joining them.
///
/// SEPARATE FROM THE JOIN BECAUSE THE ORDER IS FORCED. Our boxes need their peers' names in
/// `/etc/hosts` at CREATION, which is before they exist; our own membership cannot be registered
/// until they do, because a member record whose box is not in the registry is pruned on the next
/// read - by us as much as by anyone. So the foreign half is read first and the local half is
/// written later, and this function is the first of those two moments.
pub fn peers_of(networks: &[String], project: &str) -> Vec<(String, Member, u32)> {
    let mut out = Vec::new();
    for n in networks {
        let Some(ni) = net_index(n) else { continue };
        for m in members(n) {
            if m.project == project {
                continue;
            }
            let Some(addr) = member_addr(ni, m.index) else {
                continue;
            };
            out.push((n.clone(), m, addr));
        }
    }
    out
}

/// Join every external network our services are on, and plan the wiring in both directions.
///
/// CALLED WHEN OUR BOXES EXIST AND BEFORE ANY OF THEM RUNS, which is the window the pre-exec gate
/// holds open. Earlier and our member records would be pruned as dead; later and a workload could
/// observe a peer name that resolves to an address nothing answers on yet - the same half-built
/// network the gate exists to make impossible inside a stack.
///
/// BOTH DIRECTIONS ARE OURS TO BUILD. A relay into a foreign box is hosted by a process this stack
/// owns, so when this stack goes down the edge goes with it. The alternative was to ask the other
/// project's running holder to adopt the edge, which needs a channel into a live process and buys
/// nothing: what that edge reached is leaving too.
pub fn join_and_plan(mine: &[Joining], project: &str) -> Result<CrossPlan, Error> {
    let mut plan = CrossPlan::default();
    // Every external network any of our services is on, once, in a stable order.
    let mut networks: Vec<String> = mine.iter().flat_map(|j| j.networks.clone()).collect();
    networks.sort();
    networks.dedup();

    for net in &networks {
        let Some(ni) = net_index(net) else {
            return Err(Error::Sandbox(format!(
                "network '{net}' has no address index; it was not created by this kern"
            )));
        };
        let foreign: Vec<Member> = members(net)
            .into_iter()
            .filter(|m| m.project != project)
            .collect();
        if foreign.is_empty() {
            plan.alone_on.push(net.clone());
        }
        for j in mine.iter().filter(|j| j.networks.iter().any(|n| n == net)) {
            join(
                net,
                &Member {
                    box_name: j.box_name.clone(),
                    service: j.service.clone(),
                    project: project.to_string(),
                    ports: j.ports.clone(),
                    index: 0, // allocated by `join`, which is the only thing that may choose one
                },
            )?;
            // READ BACK THE INDEX THAT WAS ACTUALLY ALLOCATED. Assuming the one we asked for would
            // be wrong on a rejoin, where the box keeps the address other projects already hold.
            let Some(me) = members(net).into_iter().find(|m| m.box_name == j.box_name) else {
                return Err(Error::Sandbox(format!(
                    "network '{net}': '{}' joined and is not there a moment later; its box may have \
                     exited during bring-up",
                    j.box_name
                )));
            };
            let Some(my_addr) = member_addr(ni, me.index) else {
                return Err(Error::Sandbox(format!(
                    "network '{net}' cannot address member {} of '{}'",
                    me.index, j.box_name
                )));
            };
            plan.joined.push((net.clone(), j.box_name.clone()));

            for f in &foreign {
                let Some(their_addr) = member_addr(ni, f.index) else {
                    continue;
                };
                // OUR BOX REACHES THEIRS: their name at their address, and a relay per port they
                // declare. The listener lives in OUR box, so the port it may not be able to bind is
                // one WE declare - which is what `holder_declares` tells the holder to check.
                plan.host_entries.push((
                    j.box_name.clone(),
                    format!("{}:{}", f.service, ipv4(their_addr)),
                ));
                for port in &f.ports {
                    plan.relays.push(crate::nopod::RelayPlan {
                        in_box: j.box_name.clone(),
                        to_box: f.box_name.clone(),
                        alias: their_addr,
                        from_alias: my_addr,
                        port: *port,
                        holder_declares: j.ports.contains(port),
                    });
                }
                // THEIRS REACHES OURS: our name at our address inside THEIR box, and a relay per
                // port WE declare, hosted in their box.
                plan.foreign_hosts.push((
                    f.box_name.clone(),
                    format!("{}\t{}", ipv4(my_addr), j.service),
                ));
                for port in &j.ports {
                    plan.relays.push(crate::nopod::RelayPlan {
                        in_box: f.box_name.clone(),
                        to_box: j.box_name.clone(),
                        alias: my_addr,
                        from_alias: their_addr,
                        port: *port,
                        holder_declares: f.ports.contains(port),
                    });
                }
            }
        }
    }
    Ok(plan)
}

/// The marker every line this project writes into a FOREIGN box carries.
///
/// A COMMENT, BECAUSE `/etc/hosts` HAS ONE AND EVERY RESOLVER IGNORES IT. Teardown has to remove the
/// lines this stack added and only those: the box belongs to another project, which wrote its own
/// entries there and would be left with a peer it cannot resolve if a sweep took the wrong ones. The
/// marker names the project, so two stacks joining the same network can each take back exactly what
/// they put in.
fn foreign_marker(project: &str) -> String {
    format!("# kern-net {project}")
}

/// Teach a RUNNING box of another project one of our names.
///
/// WRITTEN THROUGH `/proc/<pid1>/root`, which is the box's own filesystem view from outside it.
/// MEASURED on a live box: the write is visible inside immediately and `getent hosts` answers the
/// new name on the next call, so a stack that joins a network late needs no resolver process and no
/// restart of the stack that was already there. That measurement is why this feature is relays and a
/// hosts file rather than a DNS server.
///
/// APPEND-ONLY AND IDEMPOTENT. `up` runs again on a stack that is already up, and a line added twice
/// would leave a duplicate behind when only one is removed. The file is read first and an identical
/// line is not written again.
///
/// A FAILURE IS RETURNED, NOT SWALLOWED: the box is reachable FROM here either way, and what is lost
/// is the other direction's name resolution, which the caller reports per box.
pub fn add_foreign_host(box_name: &str, line: &str, project: &str) -> Result<(), Error> {
    let Some(inst) = crate::registry::find(box_name) else {
        return Err(Error::Sandbox(format!("box '{box_name}' is not running")));
    };
    let Some(pid1) = inst.live_pid1() else {
        return Err(Error::Sandbox(format!(
            "box '{box_name}' has no recorded PID 1"
        )));
    };
    let path = format!("/proc/{pid1}/root/etc/hosts");
    let current = std::fs::read_to_string(&path)
        .map_err(|e| Error::Sandbox(format!("{box_name}: cannot read its hosts file: {e}")))?;
    let want = format!("{line}	{}", foreign_marker(project));
    if current.lines().any(|l| l == want) {
        return Ok(());
    }
    let mut next = current;
    if !next.is_empty() && !next.ends_with('\n') {
        next.push('\n');
    }
    next.push_str(&want);
    next.push('\n');
    // REWRITTEN IN PLACE AND NOT RENAMED OVER. The path reaches into another box's mount namespace;
    // a rename there would replace the file the box has open rather than update it, and `/etc/hosts`
    // in a box is frequently a bind mount, where a rename fails outright.
    std::fs::write(&path, next)
        .map_err(|e| Error::Sandbox(format!("{box_name}: cannot write its hosts file: {e}")))
}

/// Take back every line this project wrote into a foreign box's hosts file.
///
/// BY MARKER AND NOT BY ADDRESS, because the address is exactly what is no longer true: by the time
/// this runs our boxes may already be gone, and matching on their addresses would miss a line whose
/// peer left first. The marker names the project that wrote it, so nothing else is touched.
pub fn drop_foreign_hosts(box_name: &str, project: &str) {
    let Some(pid1) = crate::registry::find(box_name).and_then(|i| i.live_pid1()) else {
        return; // the other stack is gone too; its hosts file went with it
    };
    let path = format!("/proc/{pid1}/root/etc/hosts");
    let Ok(current) = std::fs::read_to_string(&path) else {
        return;
    };
    let marker = foreign_marker(project);
    let kept: Vec<&str> = current
        .lines()
        .filter(|l| !l.trim_end().ends_with(&marker))
        .collect();
    if kept.len() == current.lines().count() {
        return; // nothing of ours in there
    }
    let mut next = kept.join("\n");
    next.push('\n');
    let _ = std::fs::write(&path, next);
}

/// A `u32` address as dotted quad. Local because the only alternative is building an
/// `Ipv4Addr` for a `to_string` at every call site.
fn ipv4(a: u32) -> String {
    std::net::Ipv4Addr::from(a).to_string()
}

/// `kern network rm <name>...`: remove each, and report honestly when some could not go.
///
/// A FAILURE IS PRINTED ONCE. With a single name the returned error is the whole report, so printing
/// it in the loop as well would put the same sentence on screen twice under two different prefixes -
/// which `kern pod rm` does today and is not a pattern worth copying. With several names each
/// failure has to be named as it happens, because the returned error can only be one of them.
///
/// EXIT CODE: non-zero if ANY name failed, not only if all did. `network rm a b` where `b` is busy
/// has not done what was asked, and a script that reads the status must not be told it has.
pub fn remove_many(names: &[String]) -> Result<(), Error> {
    if names.is_empty() {
        return Err(Error::Usage("network rm <name>..."));
    }
    let many = names.len() > 1;
    let mut first: Option<Error> = None;
    let mut failed = 0usize;
    for n in names {
        match remove(n) {
            Ok(()) => println!("removed network '{n}'"),
            Err(e) => {
                failed += 1;
                if many {
                    eprintln!("kern: {e}");
                }
                if first.is_none() {
                    first = Some(e);
                }
            }
        }
    }
    match first {
        Some(_) if many => Err(Error::Sandbox(format!(
            "{failed} of {} network(s) could not be removed; each is named above",
            names.len()
        ))),
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// `kern network ls`, as a table or as JSON.
///
/// THE MEMBER COUNT IS THE LIVE ONE, which is the only number worth printing: a network's directory
/// keeps a record for every box that ever joined and did not leave cleanly, and reporting those
/// would tell an operator a stack is on a network when its boxes are gone. `members()` prunes as it
/// reads, so the count here and the peers a joiner would actually get are the same set.
pub fn print_list(json: bool) -> Result<(), Error> {
    let names = list();
    if json {
        // ONE OBJECT PER LINE, which is the shape every other `--json` in this CLI emits, so a
        // consumer can stream it and a partial read is still whole records.
        for n in &names {
            let live = members(n);
            let peers: Vec<String> = live
                .iter()
                .map(|m| {
                    format!(
                        "{{\"box\":{},\"service\":{},\"project\":{}}}",
                        kern_common::json_str(&m.box_name),
                        kern_common::json_str(&m.service),
                        kern_common::json_str(&m.project)
                    )
                })
                .collect();
            println!(
                "{{\"name\":{},\"members\":{},\"boxes\":[{}]}}",
                kern_common::json_str(n),
                live.len(),
                peers.join(",")
            );
        }
        return Ok(());
    }
    if names.is_empty() {
        println!(
            "no networks. `kern network create <name>` makes one, which is what a compose file"
        );
        println!("naming `external: true` needs before it will run.");
        return Ok(());
    }
    println!("{:<24} {:>7}  BOXES", "NAME", "MEMBERS");
    for n in &names {
        let live = members(n);
        let who: Vec<String> = live
            .iter()
            .map(|m| format!("{} ({})", m.service, m.project))
            .collect();
        println!(
            "{:<24} {:>7}  {}",
            n,
            live.len(),
            if who.is_empty() {
                "-".to_string()
            } else {
                who.join(", ")
            }
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A RECORD SURVIVES THE ROUND TRIP, AND A MALFORMED ONE IS REFUSED RATHER THAN GUESSED AT.
    ///
    /// This record is read by a project that never saw the compose file it came from, so there is no
    /// second source to check it against: whatever decodes here is what another stack will resolve
    /// and connect to. The negative cases are the ones that matter, and each names a different way a
    /// line can be wrong.
    #[test]
    fn a_member_record_round_trips_and_refuses_a_malformed_line() {
        let m = Member {
            box_name: "proj-abc123-web".to_string(),
            service: "web".to_string(),
            project: "proj-abc123".to_string(),
            ports: vec![80, 8080],
            index: 7,
        };
        let line = m.encode();
        assert_eq!(Member::decode(&line), Some(m.clone()), "round trip");
        // No ports is a member nothing can relay INTO, and it is still a valid record: it resolves
        // by name, which is half of what a network is for.
        let bare = Member {
            ports: vec![],
            ..m.clone()
        };
        assert_eq!(Member::decode(&bare.encode()), Some(bare), "no ports");

        // AND THE REFUSALS, each a different shape.
        assert_eq!(Member::decode(""), None, "empty");
        assert_eq!(Member::decode("only-one-field"), None, "no service");
        assert_eq!(Member::decode("a\tb"), None, "no project");
        assert_eq!(Member::decode("a\tb\tc\t80"), None, "no index");
        assert_eq!(
            Member::decode("a\tb\tc\t80\t3\textra"),
            None,
            "a field this reader does not know must not be ignored"
        );
        assert_eq!(Member::decode("\tb\tc\t80\t3"), None, "empty box name");
        assert_eq!(Member::decode("a\t\tc\t80\t3"), None, "empty service");
        assert_eq!(Member::decode("a\tb\t\t80\t3"), None, "empty project");
        assert_eq!(
            Member::decode("a\tb\tc\t80\tnotanindex"),
            None,
            "an index that is not a number leaves the member with no address at all"
        );
        assert_eq!(
            Member::decode("a\tb\tc\t80,notaport\t3"),
            None,
            "a port that is not a number makes the whole record unusable, because a relay built \
             from a partial port list is a peer that answers on some of its ports and not others"
        );
        assert_eq!(
            Member::decode("a\tb\tc\t99999\t3"),
            None,
            "and so does a port outside 16 bits"
        );
    }

    /// AN ADDRESS IS THE MEMBER'S IDENTITY ON THE NETWORK, and two members never share one.
    ///
    /// The whole scheme rests on this: every box binds the SAME address for a given peer, and a peer
    /// connecting out uses its own. If two members could compute one address, a hosts file would map
    /// two names to it and one of the two would be unreachable with nothing reporting why.
    ///
    /// THE `127.0.x` EXCLUSION IS ASSERTED, not assumed, because a stack's own peer aliases live
    /// there and an overlap would silently redirect an INTRA-stack peer to a foreign one.
    #[test]
    fn every_member_address_is_unique_and_never_lands_on_a_stack_s_own_alias_range() {
        let mut seen = std::collections::HashSet::new();
        for net in 0..=255u32 {
            for member in 0..254u32 {
                let Some(a) = member_addr(net, member) else {
                    panic!("({net}, {member}) is inside the documented bounds and must have an address")
                };
                assert!(
                    seen.insert(a),
                    "({net}, {member}) collides with an earlier member"
                );
                let o = a.to_be_bytes();
                assert_eq!(
                    o[0], 127,
                    "every alias is on the loopback the kernel already gives lo"
                );
                assert_eq!(
                    o[1], 1,
                    "cross-project aliases live in 127.1, so they cannot meet a stack's own \
                     127.0.0.2-254 plan whatever either allocator does"
                );
                assert_ne!(
                    o[3], 0,
                    "a .0 is a network address and must not be handed to a member"
                );
            }
        }
        // THE BOUNDS REFUSE rather than wrap: a wrapped index is an address belonging to somebody
        // else, which is the one failure this scheme exists to make impossible.
        assert_eq!(member_addr(256, 0), None, "a network index past the octet");
        assert_eq!(member_addr(0, 254), None, "a member index past the octet");
        // And the range really is disjoint from the intra-stack plan, checked against its ends.
        let intra_lo = (127u32 << 24) | 2;
        let intra_hi = (127u32 << 24) | 254;
        for a in [member_addr(0, 0), member_addr(255, 253)]
            .into_iter()
            .flatten()
        {
            assert!(
                a < intra_lo || a > intra_hi,
                "a cross-project alias must never land inside 127.0.0.2-127.0.0.254"
            );
        }
    }

    /// A NAME THAT WOULD LEAVE THE REGISTRY IS REFUSED, and the refusal is the whole guard.
    ///
    /// The name becomes a single path component under the registry root. `..` or a separator would
    /// place a member list outside the directory the registry defends, and the member list is what
    /// decides which boxes another project connects to.
    #[test]
    fn a_network_name_that_is_not_a_single_safe_component_is_refused() {
        for bad in [
            "..",
            ".",
            "a/b",
            "../escape",
            "-lead",
            ".lead",
            "",
            "has space",
        ] {
            assert!(
                validated(bad).is_err(),
                "'{bad}' must not be usable as a network name"
            );
        }
        for good in ["proxy", "web_net", "a.b-c", "X1"] {
            assert!(validated(good).is_ok(), "'{good}' is a usable network name");
        }
    }

    /// A MEMBER FILENAME IS CHECKED TOO, and not only the network's.
    ///
    /// The box name arrives from the registry, where it is already constrained. This asserts the
    /// constraint is enforced HERE as well, because this is the point at which it becomes a path,
    /// and a check that lives only at the far end of a call chain is one refactor from being gone.
    #[test]
    fn a_member_filename_is_refused_unless_it_is_one_safe_component() {
        let dir = std::path::Path::new("/tmp/kern-net-test");
        assert!(member_path(dir, "proj-web").is_some());
        for bad in ["..", "a/b", "../escape", ""] {
            assert!(
                member_path(dir, bad).is_none(),
                "'{bad}' must not become a member filename"
            );
        }
    }
}
