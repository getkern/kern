//! Peer reachability for a `--no-pod` stack: the per-service `/etc/hosts` and the relay plan.
//!
//! # What this closes
//!
//! Without a pod every service gets its own network namespace holding only loopback and no routes, so
//! peers are unreachable by name AND by address, and a port published to the host does not reach a
//! peer either (all three measured). This module names the addresses that make them reachable again
//! and produces the hosts file each box needs to resolve them; the transport itself is
//! [`kern_isolation::peer`].
//!
//! # The addressing rule, and why it also removes the port collision
//!
//! Every service gets a stack-wide loopback alias, `127.0.0.2` upward, assigned by its position in
//! the file's service order. Inside box A, a relay binds peer B's alias and forwards to B's real
//! `127.0.0.1:<port>`.
//!
//! A service therefore keeps binding its OWN `127.0.0.1:<port>` while its peers answer elsewhere, so
//! two services CAN both listen on 8080, which is the constraint the pod imposes, removed rather than
//! worked around.
//!
//! NOT UNCONDITIONALLY, and an earlier version of this paragraph said otherwise. A wildcard listener
//! owns every address on its port, so a service on `0.0.0.0:8080` leaves no room for a peer's alias
//! there; one on `127.0.0.1:8080` does. Which it is cannot be read from a compose file, which
//! declares a port and never an address, so the holder measures it once the services are running and
//! names any direction it cannot serve. See `relayhold::port_state`.
//!
//! # Why a hosts file per service and not one shared file
//!
//! A box must resolve ITS OWN name to `127.0.0.1`, where its own listener actually is, and every peer
//! to that peer's alias, where the relay is. One shared file cannot say both: it would send a service
//! that resolves its own name to an alias nothing binds inside its namespace. The files differ in
//! exactly one line, and getting that line wrong is a service that cannot reach itself, which is a
//! failure people spend an afternoon on.
//!
//! # Failure modes
//!
//!  1. **More services than addresses.** `127.0.0.2 ..= .254` is 253 peers. Beyond that
//!     [`assign_aliases`] refuses by name rather than wrapping, because a wrapped alias hands two
//!     peers one address and the symptom is a service talking to the wrong peer while both look
//!     healthy.
//!  2. **A service name that is not a valid hosts token.** A name carrying whitespace or a `#` would
//!     produce a hosts line that resolves to something else, or a comment. Refused by
//!     [`hosts_name_is_safe`], which is applied before a single file is written.
//!  3. **Duplicate service names.** Two entries for one name make resolution order-dependent.
//!     Refused, naming the duplicate.
//!  4. **A service with no declared port.** It has nothing for a peer to reach, so it appears in
//!     every hosts file (its name resolves) but no relay is planned for it. A connection then fails
//!     at connect, which is the same answer Docker gives for a service that listens on nothing.
//!  5. **A mesh wider than the machine.** The count is `services * (services - 1) * ports_each`, and
//!     the 253-service alias cap does not bound it: 253 services with one port each is 63,756 relays
//!     and 127,513 processes, more than a typical `RLIMIT_NPROC`. Bounded by the caller, which
//!     refuses past `peer::MAX_RELAYS` before a box starts.

use kern_isolation::peer::{alias_to_dotted, peer_alias, MAX_PEER_INDEX};

/// One service's place in the stack's address plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assigned {
    /// The name as written in the compose file. This is what a peer resolves.
    pub service: String,
    /// The scoped box name, used to find the running box.
    pub box_name: String,
    /// Stack-wide loopback alias, host byte order.
    pub alias: u32,
    /// Container ports this service declares, in file order. Empty is legal and means no relay.
    pub ports: Vec<u16>,
    /// The networks this service joins, as written in the compose file. EMPTY means the implicit
    /// `default` network, which is the Compose Specification's rule; [`shares_network`] resolves it
    /// there rather than
    /// filling it in here, so one place decides what an absent key means.
    pub networks: Vec<String>,
    /// The extra names this service answers to - `networks.<net>.aliases` - INCLUDING its own name,
    /// which the driver puts there.
    ///
    /// They are peers' names too: a service that writes `aliases: [db]` is asking to be reachable as
    /// `db`, and a stack whose DSNs say `db` needs that to resolve. In a POD they already do (the
    /// shared hosts file carries them); on a bridge and under `--no-pod` each box gets `--add-host`
    /// entries instead, and the aliases were not among them - so the same file resolved `db` in one
    /// wiring and not in the other. MEASURED on a real dev stack whose postgres declares
    /// `aliases: [db]`: `getent hosts db` answered in the pod and answered nothing on the bridge.
    pub aliases: Vec<String>,
}

/// Docker's implicit network: the one a service with no `networks:` key joins.
const DEFAULT_NETWORK: &str = "default";

/// Do these two services have a network in common, and therefore an edge?
///
/// THIS IS THE WHOLE SEGREGATION RULE, in one predicate, because it decides TWO things that must
/// never disagree: whether a relay is built, and whether the peer's name resolves at all. If the
/// hosts file listed a peer the relay graph does not connect, a service would resolve a name to an
/// alias nothing binds inside its namespace and get `Connection refused` where Docker gives an
/// unknown host - a failure that reads like the peer is down rather than like it is not on your
/// network, which is an afternoon of looking in the wrong place.
///
/// AN EMPTY LIST IS `default`, NOT "every network". A service with no `networks:` key joins the
/// project's implicit network in Docker, so two such services see each other and a service pinned to
/// `backend` does not see them. Reading empty as "unrestricted" would make the common file (nobody
/// writes `networks:`) behave one way and the segregated file another, with the boundary depending
/// on whether some OTHER service in the same file happened to declare a key.
/// ALLOCATION-FREE, because this runs once per ORDERED PAIR PER PORT: the relay plan is quadratic
/// in the service count (33 services with one port each is 1,056 calls) and the first version built
/// two `Vec<String>` on every one of them purely to write the implicit `default` into a list. The
/// four arms below say the same thing by comparing against the constant directly, so the common
/// case (both lists empty, i.e. every stack that never writes `networks:`) is one boolean test and
/// touches no heap at all.
pub fn shares_network(a: &[String], b: &[String]) -> bool {
    match (a.is_empty(), b.is_empty()) {
        // Neither declared: both are on the implicit network, so they see each other.
        (true, true) => true,
        // One declared: they meet only if the other one named the implicit network explicitly,
        // which is the same statement as writing nothing.
        (true, false) => b.iter().any(|y| y == DEFAULT_NETWORK),
        (false, true) => a.iter().any(|x| x == DEFAULT_NETWORK),
        // Both declared: any overlap is an edge.
        (false, false) => a.iter().any(|x| b.iter().any(|y| x == y)),
    }
}

/// Whether a name may appear in a hosts file without changing its meaning.
///
/// Deliberately narrow: letters, digits, `-`, `.` and `_`. A hosts entry is parsed by splitting on
/// whitespace, so a name containing a space would silently become two names, and a `#` would comment
/// out the rest of the line. Compose service names are already restricted to this shape by the
/// spec, so the check refuses only input a file should not have contained.
pub fn hosts_name_is_safe(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
}

/// Assign every service its alias, in file order.
///
/// # Errors
///
/// A message naming the offending service when a name is unusable in a hosts file, when two services
/// share a name, or when the stack has more services than there are addresses.
/// One service as the address plan needs it: `(service name, box name, declared container ports,
/// networks, aliases)`. Named because the tuple travels from the compose driver to here and a
/// five-element type spelled out at every site is a type nobody can read.
pub type ServiceInput = (String, String, Vec<u16>, Vec<String>, Vec<String>);

pub fn assign_aliases(services: &[ServiceInput]) -> Result<Vec<Assigned>, String> {
    if services.len() > MAX_PEER_INDEX {
        return Err(format!(
            "a --no-pod stack can address at most {MAX_PEER_INDEX} services (127.0.0.2 through \
             127.0.0.254); this one has {}",
            services.len()
        ));
    }
    let mut out: Vec<Assigned> = Vec::with_capacity(services.len());
    for (i, (service, box_name, ports, networks, aliases)) in services.iter().enumerate() {
        if !hosts_name_is_safe(service) {
            return Err(format!(
                "service '{service}' cannot be written into a hosts file: a name may hold only \
                 letters, digits, '-', '.' and '_'"
            ));
        }
        if out.iter().any(|a| a.service == *service) {
            return Err(format!(
                "two services are both named '{service}'; peer resolution would depend on order"
            ));
        }
        let Some(alias) = peer_alias(i) else {
            return Err(format!(
                "no loopback alias left for service '{service}' (index {i})"
            ));
        };
        // An alias is written into a hosts file exactly like the service name, so it is held to the
        // same rule and refused by NAME rather than dropped: a file whose alias cannot be a host
        // name is broken for Docker too, and silently losing it would leave a DSN pointing at
        // nothing with no line saying why.
        for al in aliases {
            if !hosts_name_is_safe(al) {
                return Err(format!(
                    "service '{service}' declares the alias '{al}', which cannot be written into a \
                     hosts file: a name may hold only letters, digits, '-', '.' and '_'"
                ));
            }
        }
        out.push(Assigned {
            service: service.clone(),
            box_name: box_name.clone(),
            alias,
            ports: ports.clone(),
            networks: networks.clone(),
            aliases: aliases.clone(),
        });
    }
    Ok(out)
}

/// The `--add-host NAME:IP` values this box needs, given the whole plan.
///
/// `me` maps to `127.0.0.1`, where its own listener is; every peer maps to that peer's alias, where
/// the relay binds inside this box. Returns `None` when `me` is not in the plan, which is a caller
/// bug rather than a runtime condition.
///
/// `--add-host` RATHER THAN A BOUND HOSTS FILE, deliberately. kern already has that flag, it is
/// already the tested way an entry reaches a box's `/etc/hosts`, and it needs no file in the runtime
/// directory whose lifetime someone then has to own. The pod path binds a shared file because its
/// members APPEND to one as they join; a no-pod stack knows every entry before the first box starts.
///
/// A BOX MUST RESOLVE ITS OWN NAME TO `127.0.0.1` and not to its alias: the alias is bound by relays
/// inside OTHER boxes, so a service that resolved itself there would reach nothing at all.
pub fn add_host_args(plan: &[Assigned], me: &str, via_relay: bool) -> Option<Vec<String>> {
    if !plan.iter().any(|a| a.service == me) {
        return None;
    }
    let mine: &[String] = plan
        .iter()
        .find(|a| a.service == me)
        .map_or(&[], |a| a.networks.as_slice());
    let my_ports: &[u16] = plan
        .iter()
        .find(|a| a.service == me)
        .map_or(&[], |a| a.ports.as_slice());
    let mut out = Vec::with_capacity(plan.len());
    out.push(format!("{me}:127.0.0.1"));
    // MY OWN BOX NAME TOO, because that is what `hostname` answers inside the box and what a
    // clustered service ANNOUNCES to its peers. See the peer loop below for what it cost.
    if let Some(bn) = plan
        .iter()
        .find(|a| a.service == me)
        .map(|a| a.box_name.as_str())
    {
        if bn != me {
            out.push(format!("{bn}:127.0.0.1"));
        }
    }
    // MY OWN ALIASES POINT AT MY OWN LOOPBACK, like my name: a service that calls itself by an alias
    // must not be sent across the network to reach itself.
    for al in plan
        .iter()
        .find(|a| a.service == me)
        .map_or(&[][..], |a| a.aliases.as_slice())
    {
        if al != me {
            out.push(format!("{al}:127.0.0.1"));
        }
    }
    let mut buf = [0u8; 15];
    for a in plan {
        if a.service == me {
            continue;
        }
        // A PEER ON NO SHARED NETWORK DOES NOT RESOLVE. That is what the Compose Specification
        // describes (NOT verified against a Docker daemon on this host: none is installed here, and
        // the board that has one was unreachable), and it is also the
        // only answer consistent with the relay graph: `relay_plan` builds no edge for this pair, so
        // an entry here would name an address nothing binds in this box.
        if !shares_network(mine, &a.networks) {
            continue;
        }
        // A PEER THAT DECLARES A PORT THIS BOX ALSO DECLARES DOES NOT RESOLVE EITHER, and this is
        // the same rule as the line above for a harder-to-see reason.
        //
        // WHAT THE ENTRY USED TO DO. The peer's alias is in `127.0.0.0/8`, which is local in every
        // namespace without being configured, so the address EXISTS here whether or not kern
        // managed to bind a relay on it. When both services bind the same port, kern deliberately
        // does not bind the alias (the workload's own bind would fail), and the workload's
        // `0.0.0.0` listener then owns every local address on that port - the peer's alias
        // included. So a call to the peer BY NAME connected to the caller ITSELF and returned the
        // caller's own response.
        //
        // MEASURED, twice, by an outside reviewer on the released binary and again here: two
        // services both binding 8080, the client fetches `srv:8080` and reads back its own body,
        // while from outside `:9201` serves one and `:9202` serves the other, so neither is broken.
        // The stack reports the pair on a `kern: unreachable:` line, and the word is wrong: the
        // call does not fail, it succeeds to the wrong service. A name that answers as the wrong
        // service costs hours; a name that does not resolve costs a minute.
        //
        // PER PEER AND NOT PER PORT, because a hosts entry maps a NAME to ONE address and there is
        // nowhere to record "this name, but not on 8080". A pair that collides on one port and
        // needs another therefore loses both, which is the smaller of the two wrongs.
        //
        // ONLY WHERE PEERS ARE REACHED THROUGH A RELAY. On a bridge each service has its own network
        // namespace and its own port space, so two services binding the same container port is
        // ordinary and both names must resolve: it is exactly what Docker does. The rule is about
        // the relay taking a port in THIS box, not about the port number.
        if via_relay && a.ports.iter().any(|p| my_ports.contains(p)) {
            continue;
        }
        let addr = alias_to_dotted(a.alias, &mut buf).to_string();
        out.push(format!("{}:{}", a.service, addr));
        // AND THE PEER'S BOX NAME, which is the name it ANNOUNCES rather than the name the file
        // calls it by.
        //
        // A clustered service does not publish the string in the compose file: it publishes what
        // `hostname` returns, and puts THAT in its membership state. Kafka writes it into
        // `advertised.listeners`, a Mongo replica set into `rs.initiate`, Redis Sentinel into its
        // gossip. Every peer then dials the announced name.
        //
        // MEASURED on a two-service stack where one writes `hostname` to a shared file and the other
        // reads it back: in a POD the name resolves and the TCP connect succeeds, because the pod's
        // shared hosts file carries an entry per BOX name. On a bridge the same file answered
        // `NON-RISOLVE` and `nc: bad address`, because these entries carried the SERVICE name and
        // nothing else. The stack comes up, every health check passes, and the cluster is dead at
        // the first rebalance - which is the shape that costs a day rather than a minute.
        if a.box_name != a.service {
            out.push(format!("{}:{}", a.box_name, addr));
        }
        // AND EVERY NAME THAT PEER ANSWERS TO. `aliases:` is how a compose file says "this service
        // is also called `db`", and a DSN written against that name resolves only if the entry is
        // here: the pod's shared hosts file carries them, and without this the same file worked in
        // one wiring and not in the other.
        for al in &a.aliases {
            if al != &a.service {
                out.push(format!("{al}:{addr}"));
            }
        }
    }
    Some(out)
}

/// The `--add-host ALIAS:IP` values a service's `links:` need, in EITHER stack mode.
///
/// ONE FUNCTION FOR BOTH MODES, because a link is the same statement in both and the only thing that
/// differs is the address the target answers on: in a pod every service shares one namespace and
/// therefore one loopback, so a link resolves to `127.0.0.1`; without a pod each service has its own
/// stack-wide alias, which is exactly what `add_host_args` already hands out for the plain service
/// names. Deriving the address twice, once per mode, is how the two come to disagree.
///
/// A LINK TO A SERVICE THAT IS NOT IN THE PLAN IS SKIPPED, not guessed. Under `--no-pod` there is no
/// address to give it, and inventing one would produce a name that resolves to the wrong box. In a
/// pod the plan is empty by construction, so `use_pod` short-circuits before the lookup and every
/// link resolves to the shared loopback; a link naming a service that does not exist is reported by
/// the parser, which is the layer that can see the whole file.
///
/// `me`'s own links only: a link is a statement about the SOURCE service's hosts file.
pub fn link_host_args(links: &[String], plan: &[Assigned], use_pod: bool) -> Vec<String> {
    let mut out = Vec::with_capacity(links.len());
    let mut buf = [0u8; 15];
    for l in links {
        let Some((service, alias)) = l.split_once(':') else {
            continue;
        };
        // An alias equal to the service name is already resolvable in both modes (the pod's shared
        // hosts file, or `add_host_args`), so emitting it again would write a duplicate line.
        if alias == service {
            continue;
        }
        if use_pod {
            out.push(format!("{alias}:127.0.0.1"));
            continue;
        }
        if let Some(a) = plan.iter().find(|a| a.service == service) {
            out.push(format!("{alias}:{}", alias_to_dotted(a.alias, &mut buf)));
        }
    }
    out
}

/// The service pairs this plan does NOT connect, and the network sets that decided it.
///
/// SEGREGATION HAS TO BE VISIBLE OR IT IS INDISTINGUISHABLE FROM A BUG. The symptom of a removed
/// edge is `bad address 'db'` inside a service log, minutes later, in a process the operator did not
/// write - the same symptom as a typo in a service name, a service that failed to start, or a relay
/// that could not bind. Naming the pairs at bring-up is what separates "kern enforced what your file
/// asked for" from "something is broken", and it costs one line on the stacks that have it and
/// nothing at all on the stacks that do not.
///
/// Each pair is reported ONCE, in file order, with both memberships spelled out: the reader's next
/// question after "these two cannot talk" is always "according to what", and the answer is the two
/// sets. An empty set is printed as `default`, which is the network they are actually on.
///
/// Returns an empty vector when every pair shares something, which is every stack that does not use
/// `networks:` at all - so the common case pays a comparison per pair and prints nothing.
/// TAKES NAMES AND MEMBERSHIPS, NOT AN ADDRESS PLAN, because it never used the aliases and the
/// prerequisite mattered: `up` builds a plan and `config` does not, so a version that needed one
/// could only be called from `up` - and `config` is the command that answers "what will this file
/// be". MEASURED before this signature: `up --no-pod` named the cut pairs and `config --no-pod` said
/// nothing about them, which is the same split this repository already fixed once for the `--no-pod`
/// trade itself.
#[must_use]
pub fn segregated_pairs(services: &[(String, Vec<String>)]) -> Vec<String> {
    let mut out = Vec::new();
    let show = |v: &[String]| -> String {
        if v.is_empty() {
            DEFAULT_NETWORK.to_string()
        } else {
            v.join(", ")
        }
    };
    for (i, (a_name, a_nets)) in services.iter().enumerate() {
        for (b_name, b_nets) in services.iter().skip(i + 1) {
            if !shares_network(a_nets, b_nets) {
                out.push(format!(
                    "'{a_name}' [{}] and '{b_name}' [{}]",
                    show(a_nets),
                    show(b_nets)
                ));
            }
        }
    }
    out
}

/// The `(service, networks)` pairs [`segregated_pairs`] wants, from an address plan.
///
/// A helper rather than an inline `map` at the call site, so the `up` path and the `config` path
/// cannot come to build the tuple differently.
#[must_use]
pub fn membership_of(plan: &[Assigned]) -> Vec<(String, Vec<String>)> {
    plan.iter()
        .map(|a| (a.service.clone(), a.networks.clone()))
        .collect()
}

/// One relay to spawn: inside `in_box`, bind `alias:port` and forward to `to_box`'s
/// `127.0.0.1:port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPlan {
    /// Box whose namespace holds the listening side.
    pub in_box: String,
    /// Box the connection is forwarded into.
    pub to_box: String,
    /// Address bound inside `in_box`. This is the TARGET's alias, which is what a peer resolves.
    pub alias: u32,
    /// Whether the HOLDER declares this port itself.
    ///
    /// THE MEASUREMENT ALONE IS NOT THE ANSWER, and leaving this out inverted the decision. The
    /// holder is asked what it has bound on `port`, and "nothing" means two opposite things: a
    /// service that never uses that port will never bind it, so the alias is free forever; a service
    /// that DECLARES it and has not bound it yet would have its own `bind` refused if the alias were
    /// taken first. Without this flag every pair read as the second case, and a four-service stack
    /// reported twelve blocked edges that were all fine.
    pub holder_declares: bool,
    /// The HOLDER's own alias, used as the SOURCE address when the connector connects inside
    /// `to_box`. Without it the target sees every peer as `127.0.0.1`, indistinguishable from a
    /// connection it made itself, which quietly restores localhost-equivalence between exactly the
    /// pairs a `--no-pod` stack asked to separate.
    pub from_alias: u32,
    /// Port, the same on both sides.
    pub port: u16,
}

/// Every relay a stack needs: one per ordered service pair, per declared port of the target.
///
/// NOTHING IS REFUSED HERE ANY MORE, and the reason is that this function cannot see what decides it.
/// A relay listens on `alias:port` inside the holder, so whether it can bind depends on whether the
/// HOLDER'S OWN listener took the whole port, and a compose file declares a port without an address.
/// An earlier version skipped every pair whose two services declared the same port, which is the
/// worst case rather than the case: MEASURED, two specific binds on different addresses do not
/// conflict, so a service configured to bind `127.0.0.1` leaves the peer's alias free and that pair
/// worked. Refusing it here refused a working stack.
///
/// The decision moved to the holder, which runs after the boxes do and reads
/// `/proc/<pid1>/net/tcp` to see what is actually bound. See `relayhold::port_state`.
///
/// The count is `services * (services - 1) * ports_each`, and the caller is expected to bound it.
pub fn relay_plan(plan: &[Assigned]) -> Vec<RelayPlan> {
    let mut out = Vec::new();
    for target in plan {
        for port in &target.ports {
            for holder in plan {
                if holder.service == target.service {
                    continue;
                }
                // SEGREGATION IS THE ABSENCE OF AN EDGE, not a rule applied to one. Two services
                // with no network in common get no relay, so the connection fails in the kernel
                // (nothing is listening on that address in this namespace) rather than at a filter
                // that has to stay correct. Same predicate as the hosts file, so the two cannot
                // drift into naming a peer that cannot be reached.
                if !shares_network(&holder.networks, &target.networks) {
                    continue;
                }
                out.push(RelayPlan {
                    in_box: holder.box_name.clone(),
                    to_box: target.box_name.clone(),
                    alias: target.alias,
                    from_alias: holder.alias,
                    holder_declares: holder.ports.contains(port),
                    port: *port,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A service on NO declared network, i.e. Docker's implicit `default` - which is what almost
    /// every compose file in the wild writes, and therefore the case the existing tests assert.
    type Svc = super::ServiceInput;

    fn svc(name: &str, ports: &[u16]) -> Svc {
        (
            name.to_string(),
            format!("pod-tok-{name}"),
            ports.to_vec(),
            Vec::new(),
            Vec::new(),
        )
    }

    /// The same, on an explicit set of networks.
    fn svc_on(name: &str, ports: &[u16], nets: &[&str]) -> Svc {
        (
            name.to_string(),
            format!("pod-tok-{name}"),
            ports.to_vec(),
            nets.iter().map(|n| (*n).to_string()).collect(),
            Vec::new(),
        )
    }

    /// The same, answering to extra names (`networks.<net>.aliases`).
    fn svc_aka(name: &str, ports: &[u16], aliases: &[&str]) -> Svc {
        (
            name.to_string(),
            format!("pod-tok-{name}"),
            ports.to_vec(),
            Vec::new(),
            aliases.iter().map(|a| (*a).to_string()).collect(),
        )
    }

    /// A `networks.<net>.aliases` NAME RESOLVES IN EVERY WIRING, not only in the pod.
    ///
    /// A service that writes `aliases: [db]` is asking to be reachable as `db`, and a DSN written
    /// against that name is the reason the key exists. In a pod the shared hosts file carries the
    /// aliases; on a bridge and under `--no-pod` each box gets `--add-host` entries instead, and the
    /// aliases were not among them - so the same file resolved `db` in one wiring and answered
    /// nothing in the other. MEASURED on a real dev stack whose postgres declares `aliases: [db]`:
    /// `getent hosts db` answered `127.0.0.1 db` in the pod and answered NOTHING on the bridge.
    #[test]
    fn an_alias_resolves_for_its_peers_and_for_the_service_itself() {
        let plan = assign_aliases(&[
            svc_aka("postgres", &[5432], &["db", "primary"]),
            svc("rest", &[3000]),
        ])
        .expect("plan");
        let db_addr = alias_to_dotted(plan[0].alias, &mut [0u8; 15]).to_string();

        // From a PEER: the aliases point where the service is.
        let from_rest = add_host_args(&plan, "rest", true).expect("rest is in the plan");
        assert!(from_rest.contains(&format!("postgres:{db_addr}")));
        assert!(
            from_rest.contains(&format!("db:{db_addr}")),
            "the alias must resolve to the same address as the service: {from_rest:?}"
        );
        assert!(from_rest.contains(&format!("primary:{db_addr}")));

        // From the service ITSELF: its own aliases are its own loopback, like its own name - a
        // service that calls itself `db` must not be sent across the network to reach itself.
        let from_pg = add_host_args(&plan, "postgres", true).expect("postgres is in the plan");
        assert!(from_pg.contains(&"postgres:127.0.0.1".to_string()));
        assert!(from_pg.contains(&"db:127.0.0.1".to_string()), "{from_pg:?}");

        // THE BOX NAME RESOLVES TOO, and it is not decoration: `hostname` inside the box answers the
        // BOX name, and a clustered service publishes THAT rather than the string in the compose
        // file. Kafka puts it in `advertised.listeners`, a Mongo replica set in `rs.initiate`, Redis
        // Sentinel in its gossip, and every peer then dials the announced name.
        //
        // MEASURED on a two-service stack where one writes `hostname` to a shared file and the other
        // reads it back: in a POD both the resolve and the connect succeed, because the pod's shared
        // hosts file carries an entry per box name; on a bridge the same file answered `NON-RISOLVE`
        // and `nc: bad address`. The stack comes up, every health check passes, and the cluster is
        // dead at its first rebalance.
        assert!(
            from_rest.contains(&format!("{}:{db_addr}", plan[0].box_name)),
            "a peer must resolve the name the service ANNOUNCES, not only the one the file uses: \
             {from_rest:?}"
        );
        assert!(
            from_pg.contains(&format!("{}:127.0.0.1", plan[0].box_name)),
            "and a service must resolve its OWN announced name to its own loopback: {from_pg:?}"
        );

        // THE CONTROL: a peer on no shared network contributes nothing, aliases included. Without
        // it this test would pass on an implementation that hands every name to everybody.
        let split = assign_aliases(&[
            (
                "postgres".into(),
                "b-postgres".into(),
                vec![5432],
                vec!["back".into()],
                vec!["db".into()],
            ),
            (
                "web".into(),
                "b-web".into(),
                vec![80],
                vec!["front".into()],
                Vec::new(),
            ),
        ])
        .expect("plan");
        let from_web = add_host_args(&split, "web", true).expect("web is in the plan");
        assert!(
            !from_web.iter().any(|e| e.starts_with("db:")),
            "an alias of a service on no shared network must not resolve: {from_web:?}"
        );

        // An alias that cannot be a host name is refused BY NAME, like a service name.
        let e = assign_aliases(&[svc_aka("postgres", &[5432], &["db name"])])
            .expect_err("an unusable alias is refused");
        assert!(e.contains("db name"), "{e}");
    }

    /// AN ABSENT `networks:` KEY IS THE `default` NETWORK, NOT "every network".
    ///
    /// This is the predicate the whole segregation rests on, and reading empty as "unrestricted"
    /// would be the difference between the Compose Specification's behaviour and a boundary that
    /// quietly is not one: a
    /// service pinned to `backend` would then be reachable from every service that wrote no key,
    /// which is most of them. It also has to be symmetric, or the relay graph and the hosts file
    /// would disagree about the same pair depending on which side was asked first.
    #[test]
    fn an_absent_networks_key_means_default_and_the_rule_is_symmetric() {
        let n = |v: &[&str]| -> Vec<String> { v.iter().map(|s| (*s).to_string()).collect() };

        // Two services with no key: both on `default`, so they see each other. This is the common
        // file, and it must keep working exactly as it did before segregation existed.
        assert!(shares_network(&[], &[]));

        // One pinned, one not: DISJOINT, because the implicit network is a network.
        assert!(!shares_network(&[], &n(&["back"])));
        assert!(!shares_network(&n(&["back"]), &[]));

        // Writing `default` explicitly is the same statement as writing nothing.
        assert!(shares_network(&[], &n(&["default"])));

        // Overlap anywhere is enough; disjoint sets are not.
        assert!(shares_network(&n(&["front", "back"]), &n(&["back"])));
        assert!(!shares_network(&n(&["front"]), &n(&["back"])));

        // Symmetry, on every pair above: the two readers of this predicate ask it in both orders.
        for (a, b) in [
            (n(&["front"]), n(&["back"])),
            (n(&["front", "back"]), n(&["back"])),
            (Vec::new(), n(&["back"])),
        ] {
            assert_eq!(
                shares_network(&a, &b),
                shares_network(&b, &a),
                "the rule must not depend on which service is asked first: {a:?} {b:?}"
            );
        }
    }

    /// SEGREGATION IS THE ABSENCE OF AN EDGE, AND IT MUST REMOVE THE NAME TOO.
    ///
    /// The relay graph and the per-service hosts file are two readers of one rule, and they fail
    /// differently when they disagree: a hosts entry without a relay resolves a peer to an address
    /// nothing binds in that namespace, so the workload gets `Connection refused` where Docker gives
    /// an unknown host. That reads like the peer is down rather than like it is not on your network.
    ///
    /// MEASURED end to end on this tree with a three-service stack (`web` on front, `app` on both,
    /// `db` on back): `web` reaches `app` and `app` reaches `db` with their payloads, while
    /// `web -> db` and `db -> web` both answer `nc: bad address`, and the plan drops from six relays
    /// to four.
    #[test]
    fn two_services_with_no_shared_network_get_neither_a_relay_nor_a_hosts_entry() {
        let plan = assign_aliases(&[
            svc_on("web", &[8080], &["front"]),
            svc_on("app", &[8081], &["front", "back"]),
            svc_on("db", &[5432], &["back"]),
        ])
        .expect("three services");

        let relays = relay_plan(&plan);
        let edge = |from: &str, to: &str| {
            relays.iter().any(|r| {
                r.in_box == format!("pod-tok-{from}") && r.to_box == format!("pod-tok-{to}")
            })
        };
        assert!(edge("web", "app") && edge("app", "web"), "front is shared");
        assert!(edge("app", "db") && edge("db", "app"), "back is shared");
        assert!(!edge("web", "db"), "web and db share nothing");
        assert!(!edge("db", "web"), "and the other direction too");
        assert_eq!(
            relays.len(),
            4,
            "six ordered pairs minus the two cut: {relays:?}"
        );

        // The hosts file must agree with the graph, name by name.
        let web = add_host_args(&plan, "web", true).expect("web is in the plan");
        assert!(web.iter().any(|e| e.starts_with("web:127.0.0.1")));
        assert!(web.iter().any(|e| e.starts_with("app:")));
        assert!(
            !web.iter().any(|e| e.starts_with("db:")),
            "a peer with no shared network must not resolve at all: {web:?}"
        );
        let app = add_host_args(&plan, "app", true).expect("app is in the plan");
        assert!(
            app.iter().any(|e| e.starts_with("db:")) && app.iter().any(|e| e.starts_with("web:"))
        );
    }

    /// A STACK THAT DECLARES NO NETWORKS MUST BE EXACTLY THE FULL MESH IT ALWAYS WAS.
    ///
    /// Segregation changes the reachability of existing stacks, so the file that writes no
    /// `networks:` key at all - which is most of them - is the one case where a regression would be
    /// invisible until someone's service stopped answering.
    #[test]
    fn a_stack_without_networks_keeps_the_full_mesh() {
        let plan = assign_aliases(&[svc("a", &[8080]), svc("b", &[8081]), svc("c", &[8082])])
            .expect("three plain services");
        assert_eq!(
            relay_plan(&plan).len(),
            6,
            "three services, one port each, every ordered pair"
        );
        assert_eq!(
            add_host_args(&plan, "a", true)
                .expect("a is in the plan")
                .len(),
            6,
            "itself plus both peers, each under its compose name and its box name"
        );
        assert!(
            segregated_pairs(&membership_of(&plan)).is_empty(),
            "nothing is separated"
        );
    }

    /// THE PAIRS THAT WERE CUT ARE NAMED, WITH BOTH MEMBERSHIPS, ONCE.
    ///
    /// A removed edge surfaces as `bad address '<peer>'` in a service log, which is the same symptom
    /// as a typo or a dead peer. The report is what makes it readable as enforcement rather than as
    /// a failure, so it has to carry the two network sets - the reader's next question after "these
    /// two cannot talk" is "according to what".
    #[test]
    fn the_segregated_pairs_are_named_once_with_both_memberships() {
        let plan = assign_aliases(&[
            svc_on("web", &[8080], &["front"]),
            svc_on("app", &[8081], &["front", "back"]),
            svc_on("db", &[5432], &["back"]),
        ])
        .expect("three services");
        let cut = segregated_pairs(&membership_of(&plan));
        assert_eq!(cut.len(), 1, "exactly one pair is separated: {cut:?}");
        let line = &cut[0];
        assert!(line.contains("'web'") && line.contains("'db'"), "{line}");
        assert!(line.contains("front") && line.contains("back"), "{line}");

        // A service with no key is reported as being on `default`, which is where it actually is -
        // an empty bracket would read like "on no network", which is a different (and wrong) fact.
        let mixed = assign_aliases(&[svc("a", &[8080]), svc_on("b", &[8081], &["back"])])
            .expect("two services");
        let cut = segregated_pairs(&membership_of(&mixed));
        assert_eq!(cut.len(), 1);
        assert!(cut[0].contains("default"), "{}", cut[0]);
    }

    /// `config` AND `up` MUST NAME THE SAME PAIRS, so they read the same function from the same
    /// shape.
    ///
    /// `up` has an address plan and `config` has only the parsed services, and the first version of
    /// this report took a plan - so it could be called from one and not the other. MEASURED then:
    /// `up --no-pod` named the cut pair and `config --no-pod` named none, which is the same split
    /// this repository already closed once for the `--no-pod` trade itself. A dry run that omits a
    /// boundary the real run enforces is worse than no dry run.
    #[test]
    fn the_cut_pairs_are_the_same_whether_asked_from_a_plan_or_from_the_parsed_services() {
        let plan = assign_aliases(&[
            svc_on("web", &[8080], &["front"]),
            svc_on("app", &[8081], &["front", "back"]),
            svc_on("db", &[5432], &["back"]),
        ])
        .expect("three services");

        // What `up` has.
        let from_plan = segregated_pairs(&membership_of(&plan));
        // What `config` has: names and memberships straight off the parsed services, no aliases.
        let from_services = segregated_pairs(&[
            ("web".to_string(), vec!["front".to_string()]),
            (
                "app".to_string(),
                vec!["front".to_string(), "back".to_string()],
            ),
            ("db".to_string(), vec!["back".to_string()]),
        ]);
        assert_eq!(
            from_plan, from_services,
            "the dry run and the real run must name the same pairs"
        );
        assert_eq!(from_plan.len(), 1, "and it is the one pair: {from_plan:?}");
    }

    /// Aliases are assigned in file order, starting at `127.0.0.2`, and every service keeps its own.
    #[test]
    fn aliases_follow_file_order_from_two() {
        let plan = assign_aliases(&[svc("db", &[5432]), svc("api", &[8080]), svc("web", &[8080])])
            .expect("three ordinary services");
        assert_eq!(plan.len(), 3);
        assert_eq!(plan[0].alias, 0x7f00_0002, "db");
        assert_eq!(plan[1].alias, 0x7f00_0003, "api");
        assert_eq!(plan[2].alias, 0x7f00_0004, "web");
        assert_eq!(plan[1].box_name, "pod-tok-api");
        assert_eq!(plan[2].ports, vec![8080]);
    }

    /// TWO SERVICES ON ONE CONTAINER PORT IS THE CASE THIS EXISTS FOR. They get different aliases, so
    /// both keep 8080, which is exactly what the pod cannot do.
    #[test]
    fn two_services_may_share_a_container_port() {
        let plan = assign_aliases(&[svc("keycloak", &[8080]), svc("api", &[8080])])
            .expect("the colliding stack");
        assert_ne!(
            plan[0].alias, plan[1].alias,
            "the whole point is that they differ"
        );
        assert_eq!(plan[0].ports, plan[1].ports, "and the port does not change");
    }

    /// A name that would change meaning inside a hosts file is refused before anything is written.
    #[test]
    fn an_unsafe_service_name_is_refused() {
        for bad in [
            "two words",
            "has#hash",
            "",
            "tab\there",
            "new\nline",
            "semi;colon",
        ] {
            assert!(
                !hosts_name_is_safe(bad),
                "{bad:?} must not be accepted as a hosts name"
            );
            let e = assign_aliases(&[svc(bad, &[80])]).expect_err("must refuse");
            assert!(e.contains("hosts file"), "the refusal must say why: {e}");
        }
        for good in ["db", "api-1", "web.local", "under_score", "A1"] {
            assert!(hosts_name_is_safe(good), "{good:?} is a legal hosts name");
        }
    }

    /// Duplicate names are refused: two entries for one name make resolution order-dependent, and the
    /// order is not something a compose author controls.
    #[test]
    fn duplicate_service_names_are_refused() {
        let e = assign_aliases(&[svc("api", &[80]), svc("api", &[81])]).expect_err("must refuse");
        assert!(e.contains("both named 'api'"), "{e}");
    }

    /// A stack larger than the address range is refused by name rather than wrapped.
    #[test]
    fn a_stack_larger_than_the_range_is_refused() {
        let many: Vec<_> = (0..=MAX_PEER_INDEX)
            .map(|i| svc(&format!("s{i}"), &[80]))
            .collect();
        let e = assign_aliases(&many).expect_err("must refuse");
        assert!(e.contains("at most"), "{e}");
        // One fewer is accepted, so the boundary is the boundary and not an off-by-one.
        let ok: Vec<_> = (0..MAX_PEER_INDEX)
            .map(|i| svc(&format!("s{i}"), &[80]))
            .collect();
        assert_eq!(
            assign_aliases(&ok).expect("the largest legal stack").len(),
            MAX_PEER_INDEX
        );
    }

    /// A box resolves ITSELF to `127.0.0.1` and each peer to that peer's alias. Getting the self
    /// entry wrong is a service that cannot reach its own listener, because the alias is bound by
    /// relays living in OTHER boxes.
    #[test]
    fn add_host_points_a_box_at_itself_and_its_peers_at_their_aliases() {
        let plan = assign_aliases(&[svc("db", &[5432]), svc("api", &[8080])]).expect("plan");
        let db = add_host_args(&plan, "db", true).expect("db is in the plan");
        // TWO NAMES EACH: the compose name and the box name, which is what `hostname` answers inside
        // the box and what a clustered service announces to its peers.
        assert_eq!(
            db.len(),
            4,
            "two names for itself and two for its peer: {db:?}"
        );
        assert!(db.contains(&"db:127.0.0.1".to_string()), "{db:?}");
        assert!(db.contains(&"api:127.0.0.3".to_string()), "{db:?}");
        assert!(
            !db.iter().any(|e| e == "db:127.0.0.2"),
            "never itself at its own alias, where nothing binds inside its namespace: {db:?}"
        );
        let api = add_host_args(&plan, "api", true).expect("api is in the plan");
        assert!(api.contains(&"api:127.0.0.1".to_string()), "{api:?}");
        assert!(api.contains(&"db:127.0.0.2".to_string()), "{api:?}");
    }

    /// A service outside the plan gets no entries, and saying so is better than emitting a set that
    /// cannot resolve the caller.
    /// A PEER THAT DECLARES A PORT THIS SERVICE ALSO DECLARES MUST NOT RESOLVE.
    ///
    /// FOUND ON THE RELEASED BINARY BY AN OUTSIDE REVIEWER, and reproduced here before anything was
    /// changed. Two services both binding 8080: kern deliberately does not bind the peer's alias
    /// (the workload's own bind would fail), the alias is in `127.0.0.0/8` and therefore local
    /// anyway, and the caller's `0.0.0.0` listener owns every local address on that port. So a
    /// fetch of `peer:8080` by NAME returned the CALLER'S OWN response, while both services were
    /// healthy and answered differently from outside. The stack reported the pair as `unreachable`,
    /// and the call was not unreachable: it succeeded, to the wrong service.
    ///
    /// A name that answers as the wrong service is worse than a name that does not answer: the
    /// first presents as an application misconfiguration and costs hours, the second is a one-line
    /// diagnosis. Measured after the change: the same fetch answers `bad address`.
    #[test]
    fn a_peer_that_shares_a_declared_port_is_left_out_of_the_hosts_file() {
        let plan = assign_aliases(&[svc("srv", &[8080]), svc("cli", &[8080]), svc("db", &[5432])])
            .expect("plan");

        let cli = add_host_args(&plan, "cli", true).expect("cli is in the plan");
        assert!(
            !cli.iter().any(|e| e.starts_with("srv:")),
            "a peer on the same declared port must not resolve: {cli:?}"
        );
        // THE CONTROL, and without it this test passes against a function that writes nothing: a
        // peer on a DIFFERENT port still resolves, and the service still finds itself.
        assert!(cli.iter().any(|e| e == "db:127.0.0.4"), "{cli:?}");
        assert!(cli.iter().any(|e| e == "cli:127.0.0.1"), "{cli:?}");

        // Symmetric: the rule is about the pair, so `srv` does not see `cli` either.
        let srv = add_host_args(&plan, "srv", true).expect("srv is in the plan");
        assert!(!srv.iter().any(|e| e.starts_with("cli:")), "{srv:?}");
        assert!(srv.iter().any(|e| e.starts_with("db:")), "{srv:?}");

        // And a service that declares nothing collides with nobody.
        let db = add_host_args(&plan, "db", true).expect("db is in the plan");
        assert!(db.iter().any(|e| e.starts_with("srv:")), "{db:?}");
        assert!(db.iter().any(|e| e.starts_with("cli:")), "{db:?}");
    }

    #[test]
    fn a_service_outside_the_plan_gets_no_entries() {
        let plan = assign_aliases(&[svc("db", &[5432])]).expect("plan");
        assert_eq!(add_host_args(&plan, "nosuch", true), None);
        assert_eq!(
            add_host_args(&[], "db", true),
            None,
            "an empty plan resolves nothing"
        );
        // A single-service stack still names itself: a workload that resolves its own hostname works.
        // BOTH names: the compose one and the BOX one, which is what `hostname` answers inside it.
        let solo = add_host_args(&plan, "db", true).expect("db is in the plan");
        assert_eq!(
            solo,
            vec![
                "db:127.0.0.1".to_string(),
                format!("{}:127.0.0.1", plan[0].box_name)
            ]
        );
    }

    /// The relay plan is every ordered pair of distinct services, per declared port, and never a
    /// service to itself: a box reaching its own alias would loop through a relay to reach a loopback
    /// it already has.
    #[test]
    fn the_relay_plan_covers_ordered_pairs_and_never_a_self_pair() {
        let plan = assign_aliases(&[svc("db", &[5432]), svc("api", &[8080]), svc("web", &[])])
            .expect("plan");
        let relays = relay_plan(&plan);
        // db:5432 reachable from api and web; api:8080 from db and web; web declares nothing.
        assert_eq!(relays.len(), 4, "{relays:?}");
        assert!(
            relays.iter().all(|r| r.in_box != r.to_box),
            "no relay may point a box at itself: {relays:?}"
        );
        assert!(
            relays.iter().any(|r| r.in_box == "pod-tok-api"
                && r.to_box == "pod-tok-db"
                && r.port == 5432
                && r.alias == 0x7f00_0002),
            "api must reach db at db's alias: {relays:?}"
        );
        assert!(
            relays.iter().all(|r| r.to_box != "pod-tok-web"),
            "a service that declares no port needs no relay: {relays:?}"
        );
    }

    /// A SHARED PORT IS NO LONGER REFUSED HERE, and it used to be.
    ///
    /// This function skipped every pair whose two services declared the same port, which is the worst
    /// case rather than the case: MEASURED, two SPECIFIC binds on different addresses do not conflict
    /// on one port, so a service configured to bind `127.0.0.1` leaves the peer's alias free and that
    /// relay works. Refusing it here refused a working stack, and the file cannot tell the two apart
    /// because it declares a port and never an address.
    ///
    /// The decision moved to the holder, which reads `/proc/<pid1>/net/tcp` after the services have
    /// bound. What is asserted here is that the plan no longer drops anything: a pair that shares a
    /// port must still be PLANNED, or the measurement never gets a chance to run.
    #[test]
    fn a_shared_port_is_planned_and_decided_later_not_dropped_here() {
        let plan = assign_aliases(&[svc("keycloak", &[8080]), svc("api", &[8080])]).expect("plan");
        let relays = relay_plan(&plan);
        assert_eq!(
            relays.len(),
            2,
            "both directions must be planned, not skipped: {relays:?}"
        );

        // The asymmetric case, which the old static rule got wrong in BOTH directions: it refused
        // api->db and db->api on 5432 alike, and neither was certain from the file.
        let mixed = assign_aliases(&[svc("db", &[5432]), svc("api", &[5432, 8080])]).expect("plan");
        let relays = relay_plan(&mixed);
        assert_eq!(
            relays.len(),
            3,
            "db->api on 5432 and on 8080, api->db on 5432: {relays:?}"
        );
    }

    /// The count is `services * (services - 1) * ports_each`, unconditionally now.
    ///
    /// It used to depend on which services shared a port, because this function dropped those pairs.
    /// It no longer does, so the cost this mechanism charges is a pure function of the file's shape,
    /// which is the number a caller has to bound.
    #[test]
    fn the_relay_count_is_the_plain_quadratic() {
        let shared = assign_aliases(&[
            svc("a", &[80, 443]),
            svc("b", &[80, 443]),
            svc("c", &[80, 443]),
            svc("d", &[80, 443]),
        ])
        .expect("plan");
        // 4 * 3 * 2, with no deduction for the shared ports: the holder decides those later.
        assert_eq!(
            relay_plan(&shared).len(),
            24,
            "{}",
            relay_plan(&shared).len()
        );

        let plan = assign_aliases(&[
            svc("a", &[81, 444]),
            svc("b", &[82, 445]),
            svc("c", &[83, 446]),
            svc("d", &[84, 447]),
        ])
        .expect("plan");
        assert_eq!(
            relay_plan(&plan).len(),
            24,
            "distinct ports give the same count"
        );

        let plan1 = assign_aliases(&[svc("a", &[80]), svc("b", &[81])]).expect("plan");
        assert_eq!(
            relay_plan(&plan1).len(),
            2,
            "a pair needs one relay each way"
        );
        assert!(
            relay_plan(&assign_aliases(&[svc("only", &[80])]).expect("plan")).is_empty(),
            "a single service has no peer to reach"
        );
    }

    /// THE MESH IS QUADRATIC AND THE ALIAS CAP DOES NOT BOUND IT.
    ///
    /// `assign_aliases` refuses past 253 services, which looks like a limit and is not one for the
    /// relay count: 253 services with one port each is `253 * 252` = 63,756 relays and 127,513
    /// processes, against an `RLIMIT_NPROC` of 126,965 on the machine this was measured on. The worst
    /// case the alias range permits therefore exceeded the process limit of the host.
    ///
    /// MEASURED, release build, 32 services: 992 relays, 1,987 processes, 474 MB of real resident
    /// memory, `up` in 1.54 s. So the arithmetic below is not theoretical, and `compose` refuses past
    /// `MAX_RELAYS` before a single box starts.
    #[test]
    fn the_relay_count_outgrows_the_process_limit_before_the_alias_range_runs_out() {
        // The widest stack the aliases allow, one port each.
        let widest = MAX_PEER_INDEX * (MAX_PEER_INDEX - 1);
        assert_eq!(widest, 63_756, "253 services, one port each");
        assert!(
            2 * widest + 1 > 100_000,
            "and that is {} processes, which no bound in this module stops",
            2 * widest + 1
        );
        assert!(
            widest > kern_isolation::peer::MAX_RELAYS,
            "so the cap has to come from somewhere else, and it does"
        );

        // The cap is where a real plan meets it: 33 services with one port each is 1,056.
        let svcs: Vec<Svc> = (0..33)
            .map(|i| {
                (
                    format!("s{i}"),
                    format!("b{i}"),
                    vec![9000 + i as u16],
                    Vec::new(),
                    Vec::new(),
                )
            })
            .collect();
        let plan = assign_aliases(&svcs).expect("33 services fit the alias range");
        let n = relay_plan(&plan).len();
        assert_eq!(n, 33 * 32, "one relay per ordered pair per port");
        assert!(
            n > kern_isolation::peer::MAX_RELAYS,
            "33 services already exceed the cap: {n}"
        );

        // And 32 does not, so the cap sits between two stacks a person could plausibly write.
        let svcs: Vec<Svc> = (0..32)
            .map(|i| {
                (
                    format!("s{i}"),
                    format!("b{i}"),
                    vec![9000 + i as u16],
                    Vec::new(),
                    Vec::new(),
                )
            })
            .collect();
        let plan = assign_aliases(&svcs).expect("32 services");
        assert!(
            relay_plan(&plan).len() <= kern_isolation::peer::MAX_RELAYS,
            "32 services must still be allowed"
        );
    }
}
