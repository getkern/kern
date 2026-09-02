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
pub fn assign_aliases(services: &[(String, String, Vec<u16>)]) -> Result<Vec<Assigned>, String> {
    if services.len() > MAX_PEER_INDEX {
        return Err(format!(
            "a --no-pod stack can address at most {MAX_PEER_INDEX} services (127.0.0.2 through \
             127.0.0.254); this one has {}",
            services.len()
        ));
    }
    let mut out: Vec<Assigned> = Vec::with_capacity(services.len());
    for (i, (service, box_name, ports)) in services.iter().enumerate() {
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
        out.push(Assigned {
            service: service.clone(),
            box_name: box_name.clone(),
            alias,
            ports: ports.clone(),
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
pub fn add_host_args(plan: &[Assigned], me: &str) -> Option<Vec<String>> {
    if !plan.iter().any(|a| a.service == me) {
        return None;
    }
    let mut out = Vec::with_capacity(plan.len());
    out.push(format!("{me}:127.0.0.1"));
    let mut buf = [0u8; 15];
    for a in plan {
        if a.service == me {
            continue;
        }
        out.push(format!(
            "{}:{}",
            a.service,
            alias_to_dotted(a.alias, &mut buf)
        ));
    }
    Some(out)
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

    fn svc(name: &str, ports: &[u16]) -> (String, String, Vec<u16>) {
        (name.to_string(), format!("pod-tok-{name}"), ports.to_vec())
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
        let db = add_host_args(&plan, "db").expect("db is in the plan");
        assert_eq!(db.len(), 2, "one self entry and one peer: {db:?}");
        assert!(db.contains(&"db:127.0.0.1".to_string()), "{db:?}");
        assert!(db.contains(&"api:127.0.0.3".to_string()), "{db:?}");
        assert!(
            !db.iter().any(|e| e == "db:127.0.0.2"),
            "never itself at its own alias, where nothing binds inside its namespace: {db:?}"
        );
        let api = add_host_args(&plan, "api").expect("api is in the plan");
        assert!(api.contains(&"api:127.0.0.1".to_string()), "{api:?}");
        assert!(api.contains(&"db:127.0.0.2".to_string()), "{api:?}");
    }

    /// A service outside the plan gets no entries, and saying so is better than emitting a set that
    /// cannot resolve the caller.
    #[test]
    fn a_service_outside_the_plan_gets_no_entries() {
        let plan = assign_aliases(&[svc("db", &[5432])]).expect("plan");
        assert_eq!(add_host_args(&plan, "nosuch"), None);
        assert_eq!(
            add_host_args(&[], "db"),
            None,
            "an empty plan resolves nothing"
        );
        // A single-service stack still names itself: a workload that resolves its own hostname works.
        let solo = add_host_args(&plan, "db").expect("db is in the plan");
        assert_eq!(solo, vec!["db:127.0.0.1".to_string()]);
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
        let svcs: Vec<(String, String, Vec<u16>)> = (0..33)
            .map(|i| (format!("s{i}"), format!("b{i}"), vec![9000 + i as u16]))
            .collect();
        let plan = assign_aliases(&svcs).expect("33 services fit the alias range");
        let n = relay_plan(&plan).len();
        assert_eq!(n, 33 * 32, "one relay per ordered pair per port");
        assert!(
            n > kern_isolation::peer::MAX_RELAYS,
            "33 services already exceed the cap: {n}"
        );

        // And 32 does not, so the cap sits between two stacks a person could plausibly write.
        let svcs: Vec<(String, String, Vec<u16>)> = (0..32)
            .map(|i| (format!("s{i}"), format!("b{i}"), vec![9000 + i as u16]))
            .collect();
        let plan = assign_aliases(&svcs).expect("32 services");
        assert!(
            relay_plan(&plan).len() <= kern_isolation::peer::MAX_RELAYS,
            "32 services must still be allowed"
        );
    }
}
