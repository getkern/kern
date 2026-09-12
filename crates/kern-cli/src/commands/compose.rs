//! `kern compose …`: the orchestration verb.
//!
//! Parsing lives in the CLI-free `kern-compose` crate (so it can be fuzzed in isolation); what is
//! here is the orchestration that turns a parsed file into boxes, a pod and a dependency order.
//! Split out of `commands/mod.rs` for size; the box lifecycle it drives stays in the parent.

use super::*;

/// The `up|down|…` fragment both help sites print, built from [`COMPOSE_VERBS`] so it cannot drift.
pub fn compose_verbs_help() -> String {
    COMPOSE_VERBS
        .iter()
        .map(|(v, _)| *v)
        .collect::<Vec<_>>()
        .join("|")
}

/// Rewrite every box's `name` to its BOX name and every `depends_on` edge with it, returning the
/// service-to-box map so the caller can resolve command-line selectors through the same table.
///
/// ## What it decides
///
/// Docker names a container `<project>-<service>`; kern used the bare service name, and box names
/// are global, so two projects that both have a `db` could not coexist. The rename happens once,
/// right after parsing, and everything downstream - topological order, conditional waits, exit
/// sidecars, health lookups, liveness - works on one consistent set of names without knowing about
/// projects at all.
///
/// A `container_name:` wins over the scoped form, so `docker exec <name>` ports 1:1 to
/// `kern exec <name>`. It does NOT change what peers resolve: the bare service name is pushed onto
/// `net_aliases` here and registered in the pod's `/etc/hosts` at bring-up.
///
/// ## Why it is its own function
///
/// It was inline in `compose`, which meant the naming contract - the one a field report got wrong,
/// and acted on by editing a working file - could not be asserted without starting a stack. Every
/// claim in the paragraph above is now a case in this module's tests.
/// The descriptor number the gate's read end is pinned to in the box process.
///
/// HIGH AND FIXED. kern's own setup opens descriptors from the bottom of the table and marks them
/// `CLOEXEC`, so anything it hands out is recycled well below this; 900 sits above every one of them
/// and below the 1024 that `shed_inherited_fds_keeping` sweeps, which is what lets that sweep keep
/// exactly this descriptor and close the rest.
const GATE_FD: libc::c_int = 900;

/// The network ONE bridge will carry, from the subnets the file declares. Pure: the notes about a
/// file that declares several, or one kern cannot build a bridge on, stay at the bring-up site that
/// owns them. Split out so `config` can answer the `ipv4_address:` question with the same value the
/// bring-up will use instead of a second derivation that can drift from it.
fn bridge_cidr_for<'a>(declared: &[&'a str]) -> &'a str {
    match declared.first() {
        Some(cidr) if kern_isolation::pod_bridge_parts(cidr).is_some() => cidr,
        _ => COMPOSE_BRIDGE_CIDR,
    }
}

/// Give every service the memory ceiling the policy says it gets, and return the sentence that owes
/// the reader, if any.
///
/// TAKES THE POLICY RATHER THAN READING IT, so the whole rule can be asserted without a `kern.toml`
/// on the developer's machine - the split `apply_publish_policy` already makes for the same reason.
/// It also keeps the decision out of `compose()`, which is long enough that a block buried in it is
/// a block nobody finds.
/// The sentences a stack is owed about a service that died on a port something else holds.
///
/// A FUNCTION AND NOT AN INLINE `eprintln`, so a test can ask what a given shape is told. The two
/// wirings fail for MIRROR reasons and one sentence would be wrong for one of them: in a pod a PEER
/// holds the port, and without a pod it is kern's OWN relay that took it before the workload could.
fn dead_service_port_notes(
    dead: &[String],
    boxes: &[crate::compose::ComposeBox],
    use_pod: bool,
    address_plan: &[crate::nopod::Assigned],
) -> Vec<String> {
    let mut out = Vec::new();
    // Any LIVE member sees the pod's shared socket table; the dead one's namespace is already gone.
    let live_pid1 = if use_pod {
        boxes
            .iter()
            .filter(|b| !dead.iter().any(|d| d == b.service_name()))
            .find_map(|b| crate::registry::find(&b.name).and_then(|i| i.live_pid1()))
    } else {
        None
    };
    for name in dead {
        let Some(b) = boxes.iter().find(|b| b.service_name() == name) else {
            continue;
        };
        for (port, udp) in crate::commands::declared_container_ports(b) {
            if udp {
                continue; // the check below reads the TCP table
            }
            let held = live_pid1.is_some_and(|pid1| {
                !matches!(
                    crate::relayhold::port_state(pid1, port),
                    crate::relayhold::PortState::NotListening
                )
            });
            if use_pod && held {
                out.push(format!(
                    "service '{name}' declares container port {port} and something else in this \
                     stack is already listening on it. Every service here shares ONE network \
                     namespace, so only one of them can bind a given port; under Docker each has its \
                     own and both can. Change one of the two container ports, or run the stack with \
                     `--no-pod` and read the note it prints about ports a peer also binds"
                ));
            }
        }
    }
    // WITHOUT A POD THE DEAD SERVICE IS USUALLY THE ONE THAT DECLARED NOTHING, so its own ports say
    // nothing about why it died. What kern DOES know is what kern itself bound in that box: a relay
    // for every port a PEER declares. A workload that then binds the same port on `0.0.0.0` cannot
    // start, and this is the one place that can say so, because nothing in the file mentions it.
    if !use_pod {
        for name in dead {
            let Some(me) = boxes.iter().find(|b| b.service_name() == name) else {
                continue;
            };
            let mut ports: Vec<u16> = crate::nopod::relay_plan(address_plan)
                .into_iter()
                .filter(|r| r.in_box == me.name)
                .map(|r| r.port)
                .collect();
            ports.sort_unstable();
            ports.dedup();
            if ports.is_empty() {
                continue;
            }
            let list = ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            out.push(format!(
                "service '{name}' died, and kern had bound port(s) {list} inside its network \
                 namespace to serve a peer's alias. A workload that binds one of those on 0.0.0.0 \
                 cannot start: the address is already taken. Under Docker a peer is reached over a \
                 network rather than a loopback alias, so those ports stay free"
            ));
        }
    }
    out
}

fn apply_memory_policy(
    boxes: &mut [crate::compose::ComposeBox],
    (ceiling, host_ram): (Option<u64>, Option<u64>),
    host_swap: Option<u64>,
) -> Option<String> {
    let mut moved: Vec<String> = Vec::new();
    for b in boxes.iter_mut() {
        let before = b.memory.clone();
        b.memory = crate::commands::service_memory_cap(before.as_deref(), ceiling, host_ram);
        // NAMED ONLY WHEN THE CEILING ACTUALLY MOVED THE SERVICE, compared by VALUE and not by the
        // string. The first version compared the strings, so a service whose `mem_limit: 32m` was
        // already under the ceiling was named as capped: `"32m"` and `"33554432"` are different text
        // for the same number. An operator reading that goes looking for a limit that was never
        // applied, which is the false-alarm class that teaches people to skip the line that matters.
        if ceiling.is_some() && crate::commands::ceiling_moved(before.as_deref(), &b.memory) {
            moved.push(b.service_name().to_string());
        }
        // THE SWAP ALLOWANCE, for the same reason and from the same facts. See
        // `service_swap_allowance`: zero was a choice taken on a premise that podman disproves, and
        // it is the difference that turns a workload which survives under Docker into an OOM here.
        if b.swap_max.is_none() {
            b.swap_max =
                crate::commands::service_swap_allowance(None, before.as_deref(), host_swap);
        }
    }
    let named: Vec<&str> = moved.iter().map(String::as_str).collect();
    crate::commands::memory_ceiling_note(&named, ceiling?)
}

/// The refusal a stack has earned by declaring `external: true` on a volume that does not exist, or
/// `None`. `exists` answers "is this volume present on this host".
///
/// A FUNCTION TAKING THE EXISTENCE TEST, rather than the check written inline where the volumes
/// directory is at hand: the decision is the behaviour, and a decision taken inline inside the `up`
/// path can be asserted by nothing short of creating volumes on the developer's own machine. The
/// same reasoning already produced `internal_note` and `outbound_targets`.
///
/// SORTED AND DEDUPED because the same volume is normally mounted by several services, and a message
/// naming it three times reads as three problems.
fn missing_external_volumes(
    boxes: &[crate::compose::ComposeBox],
    exists: impl Fn(&str) -> bool,
) -> Option<String> {
    let mut missing: Vec<&str> = boxes
        .iter()
        .flat_map(|b| b.external_volumes.iter())
        .map(String::as_str)
        .filter(|n| !exists(n))
        .collect();
    missing.sort_unstable();
    missing.dedup();
    if missing.is_empty() {
        return None;
    }
    let one = missing.len() == 1;
    Some(format!(
        "the file declares {} `external: true`, which means kern must NOT create {}, and {} does \
         not exist: {}. Create it with `kern volume create <name>` (or drop `external: true` to let \
         kern create it on first use, accepting that the service starts on empty storage).",
        if one { "this volume" } else { "these volumes" },
        if one { "it" } else { "them" },
        if one { "it" } else { "they" },
        missing.join(", "),
    ))
}

/// A `CLOEXEC` pipe for one box's pre-exec gate: `(read, write)`.
///
/// `pipe2(O_CLOEXEC)` and not `pipe()` + two `fcntl`s, because the atomic form is the only one with
/// no window in which a concurrently spawning worker can inherit a descriptor it must not hold. The
/// read end's `CLOEXEC` is cleared later, in the child, where exactly one process sees it.
///
/// Panic-free: every failure is the caller's `Error`, and no descriptor leaks on the error path
/// because `pipe2` either fills both slots or fills neither.
/// The network a `--bridge` stack meets on.
///
/// A FIXED PRIVATE /24, which holds 253 services and is the range Docker's own default bridge pools
/// draw from. It lives only inside the pod's network namespaces, so it cannot collide with anything
/// on the host: two stacks with the same number are two different bridges in two different
/// namespaces.
const COMPOSE_BRIDGE_CIDR: &str = "10.89.0.0/24";

/// Which services get a NAT of their own, decided from the file before anything starts.
///
/// A FUNCTION AND NOT AN INLINE FILTER, because this decides where a workload can reach and that is
/// the kind of decision a test has to be able to ask about. The same lesson as `internal_note`: a
/// rule written inside the loop that consumes it can be checked by nothing.
///
/// IN A POD, NOBODY. The pod carries one NAT for every member, and attaching a second per box would
/// put two default routes in one namespace.
///
/// WITHOUT A POD, EVERY SERVICE EXCEPT THREE KINDS:
///  * one confined to internal networks - this is the first wiring in which `internal: true` can
///    mean what Compose says it means, and it means it by the ABSENCE of a route rather than by a
///    filter that has to stay correct;
///  * one on the host network, which already has the host's own connectivity;
///  * one with `restart:` that SYSTEMD will start, which is a different thing from a service that
///    merely writes `restart:`. A standalone persistent box is installed as a unit and started later
///    by the manager, so `up` never holds it at the gate and there is no instant at which a NAT
///    could be attached. A POD MEMBER is not: `persistent_supervision` puts every pod member on the
///    in-process supervisor regardless of systemd, because it needs the holder's namespace - so it
///    IS held at the gate and can be given one.
///
/// THAT DISTINCTION WAS MISSING AND IT COST A WHOLE STACK. The filter asked "does it write
/// `restart:`" instead of "will systemd start it", so on a bridge - where every member has its own
/// namespace and needs its own NAT - a stack that sets `restart: unless-stopped` on its services got
/// no route out and no `/etc/resolv.conf` at all. MEASURED on Sentry self-hosted, which sets it on
/// nearly every service: `ip route` inside a member showed the on-link `10.89.0.0/24` and nothing
/// else, and pgbouncer died in libevent's `evdns_base_new` for want of a resolver.
#[must_use]
fn outbound_targets(
    boxes: &[crate::compose::ComposeBox],
    shared_namespace: bool,
    members_supervised_in_process: bool,
) -> std::collections::HashSet<String> {
    if shared_namespace {
        return std::collections::HashSet::new();
    }
    boxes
        .iter()
        .filter(|b| !b.net && !b.net_none && !b.only_internal_networks)
        .filter(|b| members_supervised_in_process || !b.restart_always)
        .map(|b| b.name.clone())
        .collect()
}

fn gate_pipe() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd), Error> {
    use std::os::fd::FromRawFd;
    let mut fds: [libc::c_int; 2] = [-1, -1];
    // SAFETY: `fds` is a live array of exactly the two elements `pipe2` writes; the flag is a valid
    // constant. On failure nothing is written and both slots stay `-1`.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(Error::Compose(format!(
            "cannot create the pre-exec gate pipe: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: both descriptors were just created by `pipe2` and are owned by this process; each is
    // wrapped exactly once, so ownership is not duplicated.
    let rd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
    let wr = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
    Ok((rd, wr))
}

/// Release one prepared box by writing the single gate byte. `true` when the box was released.
///
/// A short write cannot happen for one byte on a pipe with a live reader, and `EINTR` is retried
/// because a signal is not an answer. Any other error means the box is already gone, which is not a
/// reason to fail the stack: the settle check reports a box that died, and reporting the same fact
/// twice in two different words is worse than reporting it once.
fn gate_release(fd: &std::os::fd::OwnedFd) -> bool {
    let raw = std::os::fd::AsRawFd::as_raw_fd(fd);
    let byte: [u8; 1] = [1];
    // SIGPIPE IS SET TO `SIG_DFL` BY THIS BINARY, ON PURPOSE (`main.rs`: so `kern … | head` dies like
    // a Unix tool). A write to a gate whose reader is gone therefore KILLS `up` instead of returning
    // `EPIPE`, and the caller never gets to report which service went missing. Ignoring it for the
    // duration of this one write turns the signal back into the error code the loop below already
    // handles, and the previous disposition is restored immediately so the pipe behaviour of every
    // other path is untouched.
    //
    // THE DISPOSITION IS PROCESS-WIDE, so this is only correct because the release loop is
    // sequential: `topo_levels` is walked one box at a time under the registry lock, and two
    // overlapping save/restore pairs would end with whichever thread restored last, leaving SIGPIPE
    // ignored for the rest of the run. If that loop is ever given a worker pool, this has to become
    // a single ignore around the whole loop rather than one per write.
    //
    // SAFETY: `signal` on the calling process with a valid handler constant; the returned previous
    // disposition is restored below on every path out of this function.
    let prev = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    let restore = |r: bool| -> bool {
        // SAFETY: restoring the disposition captured one statement above.
        unsafe { libc::signal(libc::SIGPIPE, prev) };
        r
    };
    loop {
        // SAFETY: writing one byte from a live local buffer to a descriptor this process owns.
        let n = unsafe { libc::write(raw, byte.as_ptr().cast::<libc::c_void>(), 1) };
        if n == 1 {
            return restore(true);
        }
        // SAFETY: `__errno_location` is always valid for the calling thread.
        let err = unsafe { *libc::__errno_location() };
        if err != libc::EINTR {
            return restore(false);
        }
    }
}

fn resolve_box_names(
    boxes: &mut [crate::compose::ComposeBox],
    pod: &str,
) -> std::collections::HashMap<String, String> {
    let scoped = |svc: &str| format!("{pod}-{svc}");
    // Each service's BOX name, built ONCE so the box's own name and every `depends_on` edge that
    // names a service map to the SAME box name.
    let box_name_of: std::collections::HashMap<String, String> = boxes
        .iter()
        .map(|b| {
            (
                b.name.clone(),
                b.container_name.clone().unwrap_or_else(|| scoped(&b.name)),
            )
        })
        .collect();
    let box_name = |svc: &str| box_name_of.get(svc).cloned().unwrap_or_else(|| scoped(svc));
    for b in boxes.iter_mut() {
        // The service name must survive as an alias: it is what peers connect to inside the pod,
        // regardless of what the box itself is named (a `container_name` does not change the DNS).
        let svc = b.name.clone();
        // Kept before the rewrite below destroys it: `config` reports the FILE, and the file calls
        // this service `svc` whatever the box ends up being named.
        b.service = svc.clone();
        if !b.net_aliases.contains(&svc) {
            b.net_aliases.push(svc.clone());
        }
        // EVERY EDGE THAT NAMES A SERVICE, and `degraded_health` is one. It was added later and
        // missed here once: the parser records SERVICE names, this rewrite makes everything else
        // speak BOX names, and the settler then looked up `svc` in a map keyed by
        // `<project>-<hash>-svc` and found nothing. The gate it was restoring stayed degraded, with
        // the warning saying the image had no healthcheck when it had one. A field that reaches the
        // struct but not this loop is dropped in silence, which is the same class the merge guard
        // in `kern-compose` exists to catch.
        for d in b
            .depends_on
            .iter_mut()
            .chain(b.depends_healthy.iter_mut())
            .chain(b.depends_completed.iter_mut())
            .chain(b.degraded_health.iter_mut())
        {
            *d = box_name(d);
        }
        b.name = box_name(&svc);
    }
    box_name_of
}

/// The four names `docker compose` looks for when no `-f` is given, most specific first.
const DEFAULT_COMPOSE_NAMES: [&str; 4] = [
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
];

/// The four override names, searched in this order and INDEPENDENTLY of which base name was used.
///
/// MEASURED on Docker 29.6.2: a project whose base file is `compose.yaml` still picks up
/// `docker-compose.override.yml`, so the two searches do not have to agree on a spelling.
const DEFAULT_OVERRIDE_NAMES: [&str; 4] = [
    "compose.override.yaml",
    "compose.override.yml",
    "docker-compose.override.yaml",
    "docker-compose.override.yml",
];

/// The override file `docker compose` would have loaded beside `files[0]`, if there is one.
///
/// THE SILENT DIFFERENCE THIS CLOSES. A developer whose project has `docker-compose.yml` plus
/// `docker-compose.override.yml` - the standard way to keep source bind-mounts and debug ports out
/// of the committed file - runs `docker compose up` and gets both. The same person runs
/// `kern compose docker-compose.yml up` and got only the base: the overrides vanished with no
/// message, which is the worst shape a compose difference can take.
///
/// The mapping is not exact and the deviation is deliberate. `kern compose F` is literally Docker's
/// `-f F`, and `-f` SUPPRESSES the auto-override (measured: with `-f docker-compose.yml` the
/// override's `command`, `environment` and second port were all absent). kern follows the
/// no-`-f` behaviour instead, because that is the command the file's author actually runs, and it
/// PRINTS the file it added, so the difference is visible rather than silent.
///
/// Three conditions, each one measured against Docker rather than assumed:
///
///  * exactly ONE file was given - two files are already an explicit list, and Docker adds nothing
///    to an explicit list;
///  * that file carries one of the four default names - a file named `ci.yml` is not a default
///    project file, and Docker would not have found it without `-f` either;
///  * `COMPOSE_FILE` is unset - setting it declares the exact list, and Docker suppresses the
///    auto-override when it is set (measured: `COMPOSE_FILE=docker-compose.yml docker compose
///    config` printed `B: base`, the un-overridden value). That is also the escape hatch here, and
///    it needs no flag kern does not already have.
fn default_override_for(files: &[String]) -> Option<String> {
    let [only] = files else {
        return None;
    };
    if std::env::var_os("COMPOSE_FILE").is_some() {
        return None;
    }
    let path = std::path::Path::new(only);
    let name = path.file_name()?.to_str()?;
    if !DEFAULT_COMPOSE_NAMES.contains(&name) {
        return None;
    }
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    DEFAULT_OVERRIDE_NAMES
        .iter()
        .map(|n| dir.join(n))
        .find(|p| p.is_file())
        .and_then(|p| p.to_str().map(str::to_string))
}

/// The message for a `docker compose` verb kern does not have, or `None` when the word is not one.
///
/// `on_box` is the scoped box name the NEXT word refers to, when it names a service, so the
/// suggested command can be copied and run rather than adapted. kern's own verbs take a BOX name
/// (`<project>-<service>`), which is exactly the thing a reader of a compose file does not know.
///
/// Every target named here is a verb kern actually has: `kern --help` lists cp, events, exec,
/// images, inspect, kill, logs, ps, run, stats, stop, top, wait.
fn docker_only_verb_hint(word: &str, on_box: Option<&str>) -> Option<String> {
    let target = on_box.unwrap_or("<box>");
    let what = match word {
        "kill" => format!("`kern kill {target}`"),
        "wait" => format!("`kern wait {target}`"),
        "top" => "`kern top`".to_string(),
        "stats" => "`kern stats`".to_string(),
        "images" => "`kern images`".to_string(),
        "events" => "`kern events`".to_string(),
        "ls" => "`kern ps`".to_string(),
        "rm" => format!("`kern stop {target}`, or `compose down` for the whole stack"),
        "create" => "`compose up` (kern has no create/start split)".to_string(),
        "version" => "`kern --version`".to_string(),
        _ => return None,
    };
    // THE VERB LIST IS DERIVED, not retyped. `run` was in the table above until kern grew the verb,
    // and a hand-written list here would still be telling readers it does not exist.
    let verbs: Vec<&str> = crate::commands::COMPOSE_VERBS
        .iter()
        .map(|(name, _)| *name)
        .collect();
    Some(format!(
        "'{word}' is a `docker compose` verb that kern's compose does not have; run \
         {what}. kern compose takes: {}.",
        verbs.join(", ")
    ))
}

/// Fetch every service's image before the wiring is decided, for the verbs that are about to start
/// boxes.
///
/// See the call site for the measurement: without this, the FIRST `up` on a machine that has never
/// pulled an image decides the wiring blind and can put two services that both EXPOSE one port into
/// a single namespace, where the second one dies. The second `up` then succeeds, which is the worst
/// shape a defect can take: it repairs itself for whoever is watching.
///
/// A `build:` service is skipped. Its image does not exist yet by definition, and asking a registry
/// for a tag that is about to be built locally is a request that can only fail, slowly.
///
/// DISTINCT IMAGES ONLY, in file order: a stack of eight services on one image resolves it once.
fn ensure_images_for_wiring(boxes: &[crate::compose::ComposeBox]) {
    if boxes.len() < 2 {
        return; // one service cannot collide with another, so nothing here changes an answer
    }
    let mut done: Vec<&str> = Vec::with_capacity(boxes.len());
    for b in boxes {
        if b.build.is_some() {
            continue;
        }
        let Some(img) = b.image.as_deref() else {
            continue;
        };
        if done.contains(&img) {
            continue;
        }
        done.push(img);
        // Best effort by design: the launch path reports a fetch failure with the service that
        // wanted the image, which is a better message than anything this loop could produce.
        let _ = crate::commands::resolve_image_depth(img, 0, crate::commands::PullPolicy::Missing);
    }
}

/// Scope a project's NAMED volumes to that project, as Docker names them `<project>_<volume>`.
///
/// THE DEFECT THIS CLOSES IS DATA CROSSING BETWEEN UNRELATED STACKS. kern mounted a named volume at
/// `<volumes dir>/<name>/data`, with nothing in the path naming the project, so every stack that
/// declares the ordinary names - `data`, `db_data`, `pgdata`, `redis-data` - shared ONE directory.
///
/// MEASURED, both runtimes, same two files: project A writes `/d/who`, project B mounts a volume
/// with the same name and reads it. Docker 29.6.2 printed `EMPTY` and holds two volumes, `pa_shared`
/// and `pb_shared`. kern printed `FROM_PROJECT_A`. Two Postgres stacks that both call their volume
/// `pgdata` were sharing one data directory.
///
/// THE KEY IS KERN'S PROJECT NAME, not Docker's. Docker keys on the directory's basename, so
/// `/a/myapp` and `/b/myapp` are ONE project and share volumes; kern's project name carries a hash
/// of the file's path, so those two do not collide. The cost is the mirror case: moving a project
/// directory changes its project name, and its volumes stay behind under the old one. `-p NAME`
/// pins the project name and is the answer to both, exactly as it is under Docker.
///
/// NOT SCOPED: a volume declared `external: true`. Docker uses an external name verbatim, because
/// the whole meaning of the key is "this one already exists and is not mine to name".
///
/// Returns the scoped names this project owns, deduped, for `down -v` to remove.
fn scope_named_volumes(boxes: &mut [crate::compose::ComposeBox], project: &str) -> Vec<String> {
    let mut owned: Vec<String> = Vec::new();
    for b in boxes.iter_mut() {
        for v in b.volumes.iter_mut() {
            let Some((src, rest)) = v.split_once(':') else {
                continue; // malformed spec: `kern box` reports it precisely
            };
            if !matches!(
                crate::volume::classify(src),
                crate::volume::SourceKind::Named
            ) {
                continue; // a host path is not ours to rename
            }
            if b.external_volumes.iter().any(|e| e == src) {
                continue;
            }
            let scoped = format!("{project}_{src}");
            if !owned.iter().any(|o| o == &scoped) {
                owned.push(scoped.clone());
            }
            *v = format!("{scoped}:{rest}");
        }
    }
    owned
}

/// Name the volumes that hold data under the OLD unscoped layout, so an upgrade cannot look like
/// data loss.
///
/// A stack that ran before volumes were project-scoped left its data at `<volumes dir>/<name>/data`.
/// After the scoping the same stack looks for `<project>_<name>` and finds nothing, so it would
/// create an empty volume and the reader would see an empty database with no explanation.
///
/// NOTHING IS MOVED. Two projects may hold data under one legacy name - that is the defect being
/// fixed - so no rule here can decide whose it is. The paths are printed and the reader decides.
fn legacy_volume_notes(owned: &[String], project: &str) -> Vec<String> {
    let dir = crate::volume::volumes_dir();
    let mut notes = Vec::new();
    for scoped in owned {
        let Some(bare) = scoped.strip_prefix(&format!("{project}_")) else {
            continue;
        };
        let legacy = dir.join(bare).join("data");
        // Only when the old volume HOLDS something and the new one does not exist yet: an empty
        // leftover directory is not data, and a project already migrated must stay quiet.
        let has_data = std::fs::read_dir(&legacy).is_ok_and(|mut e| e.next().is_some());
        if has_data && !dir.join(scoped).exists() {
            notes.push(format!(
                "volume '{bare}' now belongs to this project as '{scoped}' (volumes used to be \
                 shared by name across every stack). Its old contents are still at {}; move them \
                 with `mv {} {}` if they are this project's.",
                legacy.display(),
                dir.join(bare).display(),
                dir.join(scoped).display()
            ));
        }
    }
    notes
}

pub fn compose(o: ComposeOpts<'_>) -> Result<(), Error> {
    let ComposeOpts {
        files,
        action,
        bridge: want_bridge,
        allow_privileged,
        force_pod,
        no_pod,
        allow_device_grants,
        detach,
        remove_volumes,
        wait_ready,
        wait_timeout,
        run_cmd,
        run_rm,
        no_deps,
        exit_code_from,
        abort_on_exit,
        remove_orphans,
        ps_quiet,
        ps_services,
        ps_format,
        tail,
        follow,
        all,
        services,
        project,
        env_file,
        profiles,
    } = o;
    // `--profile` is DEFINED by Docker as equivalent to `COMPOSE_PROFILES`, so it is applied by
    // exporting that variable once here, at the CLI boundary, before any parsing. One assignment in a
    // one-shot process, never from library code - the parser keeps reading a single source of truth.
    if !profiles.is_empty() {
        let mut all: Vec<String> = std::env::var("COMPOSE_PROFILES")
            .ok()
            .into_iter()
            .flat_map(|v| v.split(',').map(str::to_string).collect::<Vec<_>>())
            .filter(|p| !p.is_empty())
            .collect();
        all.extend(profiles.iter().cloned());
        std::env::set_var("COMPOSE_PROFILES", all.join(","));
    }
    // The override `docker compose` would have loaded, appended so it merges LAST (see
    // `default_override_for` for the three conditions and what each one was measured against).
    let with_override: Vec<String>;
    let files: &[String] = match default_override_for(files) {
        Some(extra) => {
            eprintln!(
                "kern: note: also loading {extra} (docker compose loads it too; set COMPOSE_FILE \
                 to pin an exact list)"
            );
            with_override = files
                .iter()
                .cloned()
                .chain(std::iter::once(extra))
                .collect();
            &with_override
        }
        None => files,
    };
    // The FIRST file names the project (pod, relative paths, `.env` location), as in Docker.
    let file = files
        .first()
        .map(String::as_str)
        .ok_or_else(|| Error::Compose("compose needs at least one file".to_string()))?;
    let text = std::fs::read_to_string(file)
        .map_err(|e| Error::Compose(format!("reading {file}: {e}")))?;
    // Docker loads a `.env` sitting next to the compose file and uses it for `${VAR}` interpolation.
    // Without this, every real project (nearly all ship one) silently substituted EMPTY: a
    // `"${PORT}:80"` became `":80"` and a `${POSTGRES_PASSWORD}` became blank, with only a warning.
    // Absent/unreadable `.env` → an empty table, i.e. exactly the previous behaviour.
    // `--env-file` REPLACES the project `.env` (Docker's rule), and is required to exist when named:
    // a typo'd path must not silently fall back to no interpolation at all.
    let dotenv = match env_file {
        Some(p) => crate::compose::parse_dotenv(
            &std::fs::read_to_string(p)
                .map_err(|e| Error::Compose(format!("--env-file {p}: {e}")))?,
        ),
        None => std::fs::read_to_string(compose_dir(file).join(".env"))
            .map(|t| crate::compose::parse_dotenv(&t))
            .unwrap_or_default(),
    };
    // COMPOSE'S OWN VARIABLES COME FROM THE `.env` TOO, which is what Docker means by loading that
    // file "both for self-configuration and interpolation". kern read `COMPOSE_PROFILES` from the
    // process environment alone, so a project that ships its profile selection in its `.env` - the
    // ordinary way to ship one - had every profiled service silently skipped.
    //
    // MEASURED on Sentry self-hosted, whose `.env` opens with `COMPOSE_PROFILES=feature-complete`:
    // 28 of its 55 services were reported "skipped - profile(s) [feature-complete] not active",
    // advising the reader to set a variable their file already sets.
    //
    // THE SHELL STILL WINS, and `--profile` (merged into the same variable above) with it: this only
    // fills in a value nobody supplied. One assignment, at the CLI boundary, exactly like the flag.
    if std::env::var("COMPOSE_PROFILES")
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        if let Some(v) = dotenv
            .get("COMPOSE_PROFILES")
            .filter(|v| !v.trim().is_empty())
        {
            std::env::set_var("COMPOSE_PROFILES", v);
        }
    }
    // The project name follows the same rule, in Docker's order: `-p` wins, then the environment,
    // then the `.env`, then the name kern derives from the file. Without it a stack that names
    // itself in its `.env` came up under a different name than `docker compose` gives it, so its
    // boxes and its pod answered to something else.
    let project_from_env = std::env::var("COMPOSE_PROJECT_NAME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            dotenv
                .get("COMPOSE_PROJECT_NAME")
                .filter(|v| !v.trim().is_empty())
                .map(str::to_string)
        });
    // THE MODE IS KNOWN HERE AND ONLY HERE, so it is handed to the parser rather than guessed there.
    // `networks:` means opposite things in the two wirings, and the parser's sentence about it is a
    // claim about what this run will do.
    // THE WIRING IS CHOSEN FROM THE FILE, so the parser cannot be told which one it is yet.
    //
    // A file that puts two services on networks with nothing in common has asked for a boundary, and
    // the only wiring that can give it one is a namespace per service. Deciding that needs the parse,
    // and the parse's own sentence about `networks:` needs the decision - so the parser is handed
    // `Undecided`, stays silent about `networks:` and `internal:`, and this function says both once
    // it knows. An explicit `--no-pod` or `--pod` settles it before the file is read at all.
    // ALWAYS `Undecided`, even when a flag settled the wiring before the file was read.
    //
    // The driver is the ONE emitter of the `networks:`/`internal:` sentences now, and letting the
    // parser also emit them when the mode happened to be known produced the file's note TWICE:
    // measured with `--pod`, the `networks: ignored` line appeared once from the parser's
    // `warn_once` and once from here. Two copies of one fact is the defect class this codebase keeps
    // paying for, and the fix is one emitter, not a second deduplication.
    let stack_net = crate::compose::StackNet::Undecided;
    if o.no_pod && force_pod {
        return Err(Error::Compose(
            "--no-pod and --pod ask for opposite wirings; pass one or neither (without either, kern \
             uses a namespace per service only when the file's `networks:` actually separate two \
             services)"
                .to_string(),
        ));
    }
    // THE FILE'S OWN DIRECTORY, not the working one: a cross-file `extends: {file: …}` resolves
    // against the file that wrote it (the Specification says so), and `kern compose -f
    // ../stack/compose.yaml` is run from somewhere else entirely. Each `-f` carries its own.
    let dir_of = |f: &str| {
        std::path::Path::new(f)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."))
    };
    let mut boxes = crate::compose::parse_with_env_at(
        &text,
        &dotenv,
        stack_net,
        Some(dir_of(&files[0]).as_path()),
    )
    .map_err(Error::Compose)?;
    // Merge every additional `-f`, left to right (see `merge_stacks` for the exact rules).
    for extra in &files[1..] {
        let t = std::fs::read_to_string(extra)
            .map_err(|e| Error::Compose(format!("reading {extra}: {e}")))?;
        let over = crate::compose::parse_override_at(
            &t,
            &dotenv,
            stack_net,
            Some(dir_of(extra).as_path()),
        )
        .map_err(Error::Compose)?;
        boxes = crate::compose::merge_stacks(boxes, over);
    }
    // Per-service validation, on the MERGED stack and UNCONDITIONALLY. Merged, because an override
    // legitimately carries no `image:` and only the result must be runnable. Unconditional, because
    // these are per-service facts that do not depend on how many files stated them: gated on
    // `files.len() > 1`, the single-file case skipped them entirely, which left a lone YAML stack
    // unchecked (the TOML parser refuses "nothing to run" itself, the YAML front end defers it here)
    // and let a `port:`/`PORT=` contradiction through in the common one-file case.
    crate::compose::validate_runnable(&boxes).map_err(Error::Compose)?;
    // The stack's pod is named after the compose file (Docker's project-name idea) - one shared
    // network so services reach each other by name.
    let pod = match project {
        Some(p) => p.to_string(),
        None => project_from_env
            .clone()
            .unwrap_or_else(|| compose_pod_name(file)),
    };

    // PROJECT-SCOPED BOX NAMES. Docker names a container `<project>-<service>`; kern used the bare
    // service name, and box names are global, so two projects that both have a `db` (or `web`, or
    // `api` - the most common names there are) could not coexist: the second `up` failed with
    // "a box named 'db' is already running".
    //
    // The rename happens HERE, once, right after parsing: `depends_on` lists are rewritten with it, so
    // everything downstream (topological order, conditional waits, exit sidecars, health lookups,
    // liveness) keeps working on one consistent set of names without knowing about projects at all.
    // The bare service name is registered as a pod ALIAS below, so peers still reach each other as
    // `db` inside the stack - the name that appears in the compose file is the name that resolves.
    let service_names: Vec<String> = boxes.iter().map(|b| b.name.clone()).collect();
    let box_name_of = resolve_box_names(&mut boxes, &pod);
    let box_name = |svc: &str| {
        box_name_of
            .get(svc)
            .cloned()
            .unwrap_or_else(|| format!("{pod}-{svc}"))
    };
    // Selectors from the command line name SERVICES; map them onto the boxes they now identify.
    let services: Vec<String> = services
        .iter()
        .map(|s| {
            if service_names.iter().any(|n| n == s) {
                box_name(s)
            } else {
                s.clone()
            }
        })
        .collect();
    let services = &services[..];

    // AN `external: true` NETWORK MUST EXIST BEFORE A STACK MAY USE IT, which is what Docker does.
    //
    // The key means "this network is not mine, somebody else made it and other projects are on it".
    // Creating it here would turn a typo in the name into a second, empty network whose members
    // resolve nothing - the exact failure the key exists to prevent - and it would do so silently,
    // because an empty network looks just like one whose peers have not come up yet.
    //
    // REFUSED FOR EVERY VERB THAT WOULD WIRE THE STACK, and NOT for `config`: a dry run answers what
    // the file means, and a file is not wrong because a network has not been created on THIS machine
    // yet. `config` names the missing network as a difference instead, which is what the
    // compatibility measurement reads.
    let external_nets: Vec<String> = {
        let mut v: Vec<String> = boxes
            .iter()
            .flat_map(|b| b.external_networks.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    };
    let missing_nets: Vec<&String> = external_nets
        .iter()
        .filter(|n| !crate::network::exists(n))
        .collect();
    if !missing_nets.is_empty() {
        if matches!(
            action,
            ComposeAction::Up | ComposeAction::Start | ComposeAction::Restart | ComposeAction::Run
        ) {
            return Err(Error::Compose(format!(
                "network {} declared `external: true`, which means this file does not create it: \
                 make it first with `kern network create {}`. Docker refuses the same file for the \
                 same reason",
                missing_nets
                    .iter()
                    .map(|n| format!("'{n}'"))
                    .collect::<Vec<_>>()
                    .join(", "),
                missing_nets
                    .iter()
                    .map(|n| (*n).clone())
                    .collect::<Vec<_>>()
                    .join(" ")
            )));
        }
        eprintln!(
            "kern: warning: compose: network {} is declared `external: true` and does not exist on \
             this machine; `up` would refuse the stack, as Docker does. `kern network create {}` \
             makes it",
            missing_nets
                .iter()
                .map(|n| format!("'{n}'"))
                .collect::<Vec<_>>()
                .join(", "),
            missing_nets
                .iter()
                .map(|n| (*n).clone())
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    // NAMED VOLUMES BELONG TO THE PROJECT, as they do under Docker. Done here, before the verbs
    // split, so `config` prints the name that will be mounted and `down -v` removes the name that
    // was. See `scope_named_volumes` for the measurement that made this necessary.
    let owned_volumes = scope_named_volumes(&mut boxes, &pod);
    // THE MIGRATION NOTE BELONGS TO A BRING-UP, NOT TO A READING OF THE FILE. It reports what is on
    // this machine's disk, so emitting it from `config` made a STATIC answer depend on local state:
    // MEASURED on the neutral corpus, where leftover volumes from unrelated stacks made 15 files
    // print it and cost the measured rate 12 points that had nothing to do with the files. `config`
    // answers what the file means; only a verb that is about to MOUNT something needs to say where
    // the old contents are.
    if matches!(
        action,
        ComposeAction::Up | ComposeAction::Start | ComposeAction::Restart
    ) {
        for note in legacy_volume_notes(&owned_volumes, &pod) {
            eprintln!("kern: note: {note}");
        }
    }

    // A `--filter`/service selection narrows the read-only verbs to the named services; empty = all.
    // Validated up front so a typo names itself instead of silently matching nothing.
    //
    // `port` IS THE ONE VERB WHOSE POSITIONALS ARE NOT ALL SERVICE NAMES: it takes
    // `<service> <container-port>`. Running the port through this check reported a mistyped NUMBER as
    // an unknown service, which sends the reader to look for a service that was never meant to exist.
    // Only the first positional is a name here; the arm itself validates the port, and does it as a
    // port.
    // `cp` IS THE OTHER VERB WHOSE POSITIONALS ARE NOT SERVICE NAMES: they are `<service>:<path>`
    // and `<host path>`, neither of which can match a service, so running them through this check
    // refused every `cp` with "no service 'web:/etc/nginx.conf'" - a sentence about a service
    // nobody wrote. The arm itself resolves the service half and hands the rest to `kern cp`, which
    // reports a name that is not a box.
    let to_validate: &[String] = if action == ComposeAction::Port {
        services.get(..1).unwrap_or(&[])
    } else if action == ComposeAction::Cp {
        &[]
    } else if action == ComposeAction::Exec {
        // Only the FIRST positional is a service; everything after it is the command, which the
        // parser has already split off into `run_cmd`. Validating the rest would report a shell
        // word as a missing service.
        services.get(..1).unwrap_or(&[])
    } else {
        services
    };
    for (i, want) in to_validate.iter().enumerate() {
        if boxes.iter().any(|b| &b.name == want) {
            continue;
        }
        // A DOCKER VERB IS NOT A MISSING SERVICE. The parser takes the first bare word that is not
        // one of kern's verbs as the FILE and every later bare word as a SERVICE, so
        // `kern compose x.yml exec web sh` reported "no service 'exec' in x.yml" - a sentence about
        // a service the reader never wrote, for a verb they did. Only the FIRST positional can be a
        // mistaken verb; a later one really is a service name.
        if i == 0 {
            // The box the next word names, so the suggested command can be run as printed.
            let on_box = to_validate
                .get(1)
                .and_then(|next| boxes.iter().find(|b| &b.name == next || &b.service == next))
                .map(|b| b.name.as_str());
            if let Some(msg) = docker_only_verb_hint(want, on_box) {
                return Err(Error::Compose(msg));
            }
        }
        {
            return Err(Error::Compose(format!(
                // `b.service` is the name as WRITTEN IN THE FILE; `b.name` is the scoped box name
                // kern gives it. Listing the latter answered a typo with names the reader's file does
                // not contain, which is a worse sentence than saying nothing.
                "no service '{}' in {file} (services: {})",
                boxes
                    .iter()
                    .find(|b| &b.name == want)
                    .map(|b| b.service.as_str())
                    .unwrap_or(want.as_str()),
                boxes
                    .iter()
                    .map(|b| b.service.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }
    // THE WIRING IS DECIDED HERE, BEFORE THE VERBS SPLIT, and said here for the same reason.
    //
    // `config` is the verb that answers "what will this file be", so it must give the same answer as
    // `up`. Deciding inside the `up` path put the selection after this dispatch and left `config`
    // saying nothing at all about `networks:` - which is exactly the split this file already closed
    // once, for the `--no-pod` trade and again for the segregated pairs. One decision, before the
    // fork, read by every verb.
    //
    // AUTO-SELECTION: a file whose `networks:` leave two services with nothing in common has asked
    // for a boundary that ONE namespace cannot provide, so the stack is wired per service and the
    // boundary is real. Every other file keeps the pod, which is faster (measured previously at -34%
    // bulk throughput and -16% connection rate for the relay hop) and simpler. MEASURED on a neutral
    // corpus of 259 compose files, one per repository: 75 of them express segregation the pod
    // silently dropped, the largest remaining difference from Docker after the publish default.
    //
    // Never silent and never irreversible: the selection is announced with what it costs, and
    // `--pod` keeps the old wiring for anyone who prefers the speed to the boundary.
    let segregates = !crate::nopod::segregated_pairs(
        &boxes
            .iter()
            .map(|b| (b.service.clone(), b.networks.clone()))
            .collect::<Vec<_>>(),
    )
    .is_empty();
    // THE SECOND REASON ONE NAMESPACE CANNOT EXPRESS THE FILE: two services claiming the same
    // internal port. Docker runs such a stack because each container has its own namespace; kern
    // used to refuse it outright. MEASURED on a real project (`AP0827/Multi-Threaded-Web-Server`, an
    // app and a modsecurity proxy both on 8080): `config` errored, and the same file with `--no-pod`
    // parsed and ran. A file Docker runs and kern refuses is the difference this implementation
    // exists to remove, so the collision now SELECTS the wiring that expresses it instead of ending
    // the run. `--pod` still gets the refusal, which is the right answer for someone who asked for
    // one namespace.
    // THE IMAGES COME FIRST WHEN A BRING-UP IS ABOUT TO HAPPEN, because the decision below reads
    // them and a decision taken without them is taken wrong.
    //
    // MEASURED, and this is a RUNTIME defect and not a cosmetic one. Two services on
    // `memcached:1.6.34-alpine`, whose collision exists only in the image's EXPOSE and nowhere in
    // the file. On a machine that has never pulled it:
    //
    // ```text
    // up -d   ->  wiring: pod  ->  "1 service(s) died within 150ms of starting: a"
    // up -d   ->  wiring: bridge (the image is now cached)  ->  both services up
    // ```
    //
    // The same command, twice, two outcomes: the first `up` on a clean machine breaks the stack and
    // the second one fixes it. An outside reviewer predicted exactly this shape from the `config`
    // behaviour and asked which side of the pull the decision falls on. It falls on the wrong one.
    //
    // Pulling here is also what Docker does: MEASURED on 29.6.2, `docker compose up -d` on a cold
    // cache prints every `Pulling` line before the first `Creating`, so the images are resolved as a
    // phase and the containers are made afterwards. The bytes are the same bytes the launch loop
    // would have fetched moments later.
    //
    // NOT for `config`, which must stay a dry run: there the answer is left provisional and SAID so
    // (`wiring-images-unread:`). Best effort: an image that cannot be fetched leaves the decision
    // where it was, and the launch reports the failure with the service that wanted it.
    if matches!(
        action,
        ComposeAction::Up | ComposeAction::Start | ComposeAction::Restart | ComposeAction::Run
    ) {
        ensure_images_for_wiring(&boxes);
    }
    // NOW THAT IMAGES CAN BE READ, the health gates the parser deferred are decided. Before the
    // wiring note below, so a reader sees the gate's fate next to the rest of the stack's plan.
    crate::commands::settle_deferred_health_gates(&mut boxes);
    let collides = crate::commands::pod_would_collide(&boxes)
        // THE SAME KNOWLEDGE THE WARNING HAS. A collision between two IMAGES' exposed ports is a
        // collision: kern named it and then ran the stack in one namespace anyway, where the second
        // service died of the EADDRINUSE the warning had just predicted. Measured on Sentry
        // (postgres and pgbouncer, both 5432) and on Supabase (studio and rest, both 3000).
        || !crate::commands::image_expose_collisions(&boxes).is_empty();
    // THE THIRD REASON ONE NAMESPACE CANNOT EXPRESS THE FILE: an `extra_hosts` entry that shadows a
    // service name. Under Docker each container has its own `/etc/hosts`, so a service mapping
    // `postgres` to a fixed address shadows the name for ITSELF and the file is unambiguous; one
    // shared namespace makes the two entries fight over a single file and kern refused the stack.
    // MEASURED: the two `bitmagnet` files in the corpus do exactly this, and both are files Docker
    // runs. They were being accepted only because a service with `network_mode:` used to fall onto
    // the implicit `default` network and segregate the stack by accident, so the refusal was already
    // reachable and was being dodged rather than answered.
    let hosts_collide = crate::commands::pod_hosts_collision(&boxes).is_some();
    // `--bridge` ANSWERS TWO OF THE THREE REASONS, so it must be consulted before the selection and
    // not after it. A port collision and an `extra_hosts` collision are both "one namespace cannot
    // hold this", and a bridge gives each service its own namespace: they are exactly what it is for.
    // Segregation is the one it does NOT answer yet, because one bridge puts every service back on
    // one network, so a file whose `networks:` separate still gets the relay wiring.
    //
    // Without this the flag was silently ignored on the files that need it most: MEASURED on a
    // two-service file where both bind 8080, `--bridge` fell through to the relay wiring and the
    // stack behaved as if the flag had not been typed.
    // A COLLISION SELECTS THE BRIDGE, NOT THE RELAY WIRING, and that is a correctness change rather
    // than a preference. Both reasons are "one namespace cannot hold this", and both wirings answer
    // it by giving each service its own namespace - but the relay wiring then BINDS the colliding
    // port inside each box to serve a peer's alias, and a workload that wants that port on
    // `0.0.0.0` cannot start. MEASURED on Docker's own `nginx-golang`, where `proxy` and `backend`
    // both bind 80: the pod cannot run it, the relay wiring kills `backend`, and the bridge answers
    // HTTP 200. A bridge costs one `veth` per service, which is less than a relay per ordered pair
    // per port.
    //
    // SEGREGATION STILL GOES TO RELAYS, because one bridge puts every service back on one network
    // and would drop the separation the file asked for. A bridge per compose network is the next
    // step and is not this one.
    // WHERE THE WIRING CAME FROM, captured BEFORE the automatic decisions are folded into the two
    // flags below, because after that the answer is unrecoverable. Reported next to the wiring
    // itself: today `wiring: pod` can only mean "kern chose it", but once a compose file can pin the
    // wiring explicitly the same token will also mean "the file asked for it", and the two count in
    // opposite directions. One is the divergence from Docker that a default change would remove; the
    // other is a file that diverges ON PURPOSE and must not be counted as anything to fix. A census
    // taken after the change would otherwise not be comparable with one taken before it.
    let wiring_from_flag = no_pod || want_bridge || force_pod;
    // THE DEFAULT WIRING, AND THE ONE LINE THAT CHANGES IT.
    //
    // A bridge gives every service its OWN network namespace and therefore its own `127.0.0.1`,
    // which is Docker's arrangement. A pod gives the stack one shared namespace, which is faster and
    // is a WEAKER boundary than the reference: a service that binds loopback is private under Docker
    // and reachable by every peer here.
    //
    // WHAT IT COSTS, MEASURED: alternated runs of this binary, whole `up -d`, images warm, medians
    // of five (`scripts/wiring-cost.py`). A pod is FLAT at about 172 ms for 1, 4 or 8 services (paid
    // once, and the bring-up is concurrent per level); a bridge is 190 ms for 2, 195 for 4, 202 for
    // 8. It is nearly flat too, because the two things that made it per-service are gone: a veth
    // peer is created directly inside the member's namespace instead of being MOVED there, which
    // saves a full RCU grace period (14-22 ms) each, and every NAT is attached concurrently before
    // any service is released instead of one at a time (about 17 ms each). Before those two the same
    // eight-service stack cost +239 ms instead of +27.
    //
    // WHAT IT BUYS, MEASURED: on the neutral corpus 135 files carry the shared-loopback note and 101
    // carry nothing else, so the wiring is the single largest difference from Docker that remains.
    // A census of 22 of those stacks, read from inside with a probe that discriminates on both axes,
    // found 2 with a loopback-only listener and 0 with a collision; both of the 2 were then
    // classified NOMINAL (one publishes the port to the host itself, the other binds its own service
    // name, which a pod resolves to 127.0.0.1 and which Docker's peers reach just as well).
    //
    // So the benefit on the measured sample is silence, not correctness, and the cost is real. The
    // default is nevertheless the ARRANGEMENT THE REFERENCE HAS, because a runtime whose reason is
    // confinement does not ship a weaker boundary than the reference by default to save 20 ms,
    // and because "no exposure in 22 stacks" is not "no exposure".
    //
    // ONE SERVICE KEEPS THE POD: it has no peer to be separated from, so a bridge would buy nothing
    // and cost a namespace. `--pod` restores the old wiring for anyone who prefers the speed.
    // A FILE THAT ASKS FOR A SHARED NAMESPACE GETS ONE. `network_mode: service:X` is not a nicety
    // about naming, it is the tightest coupling compose can express: the service wants X's loopback,
    // X's interfaces, X's published ports and X's route out, which is how every gluetun-and-client
    // file on the internet puts one service behind another's VPN.
    //
    // MEASURED, AND IT IS WHY THIS CLAUSE EXISTS. Before the default became a namespace per service,
    // such a file got the pod and the key was satisfied. After, it was wired on a bridge: `client`
    // came up on 10.89.0.3 with `vpn` on 10.89.0.2, `nc 127.0.0.1 8080` from the client reached
    // nothing, and the traffic the file put behind a VPN went out directly. Silently: there WAS a
    // warning, and it was the pod arm of the note, claiming the key was satisfied.
    //
    // ONE NAMESPACE FOR THE WHOLE STACK IS COARSER THAN DOCKER, which puts only the naming service
    // in the named one and leaves the rest apart. It is what kern can express today, it is what
    // these files had until the default changed, and it satisfies the key rather than dropping it.
    // The note says which of the two a stack got, and `--bridge` still asks for the other and is
    // then told, truthfully, what it does not get.
    // ONLY WHEN ONE NAMESPACE IS ACTUALLY POSSIBLE, and that clause was added after the corpus gate
    // went red. Forcing the pod unconditionally turned five real files into REFUSALS: a stack whose
    // services collide on a container port cannot be a pod at all - kern says so at `config` and has
    // always said so - and `network_mode: service:` files are full of exactly that shape, because
    // the client and the VPN container in front of it routinely declare the same port. Docker
    // accepts those files and lets the second bind fail at run time.
    //
    // So the order is: honour the key when the wiring that honours it can be built, and otherwise
    // keep the bridge and SAY the key is not given, which the note's other arm does. Refusing the
    // file is the one answer that is worse than both, because it is the one Docker does not give.
    let wants_shared_netns = boxes.iter().any(|b| b.net_share.is_some());
    let shared_netns_is_possible = wants_shared_netns && !collides && !hosts_collide;
    let auto_bridge = !no_pod
        && !force_pod
        && !segregates
        && !shared_netns_is_possible
        && (collides || hosts_collide || boxes.len() >= 2);
    let want_bridge = want_bridge || auto_bridge;
    let auto_no_pod = !no_pod && !force_pod && segregates;
    // THE DEFAULT ARM SPEAKS FOR ITSELF, and does not borrow the sentence below.
    //
    // That sentence is built for a file that ASKS for something one namespace cannot give, and its
    // last clause ("`--pod` refuses the stack rather than running it with the separation dropped")
    // is TRUE only there: with `--pod` a colliding or segregating file is refused, and a file whose
    // only property is having two services is wired as a pod and run. Splicing the default case into
    // that frame printed a threat kern does not carry out, which is the class of defect this file
    // spends the most comment on. The default arm therefore prints its own line, and the `if` below
    // sees only the three cases the frame was written for.
    let default_bridge = auto_bridge && !collides && !hosts_collide;
    // ONLY WHERE THE WIRING IS ABOUT TO BE BUILT, OR ASKED FOR.
    //
    // The three arms below fire on a property of the FILE and are rare (a collision, a segregation,
    // an `extra_hosts:` self-address): about twenty files in 259. This one fires on "two services",
    // which is 71% of them, and it is emitted from the shared decision path every verb goes through
    // - so before this line `kern compose ... ps` and `... logs` printed a paragraph about bridges
    // above the output the reader asked for, on almost every stack. A note whose reader has already
    // seen it twice is a note that stops being read.
    //
    // `Config` is in the list because a dry run is where the question is asked on purpose.
    let wiring_is_the_subject = matches!(
        action,
        ComposeAction::Up
            | ComposeAction::Start
            | ComposeAction::Restart
            | ComposeAction::Run
            | ComposeAction::Config
    );
    if default_bridge && wiring_is_the_subject {
        eprintln!(
            "kern: note: compose: each of this stack's {} services gets its own network namespace \
             on a bridge, which is the arrangement Docker has: a port a service binds on its \
             127.0.0.1 stays private to it. That costs about 20 ms for the stack, nearly flat in \
             the number of services; `--pod` puts the whole stack in ONE namespace instead, which \
             is faster still and makes every loopback port reachable by every peer",
            boxes.len()
        );
    }
    if auto_no_pod || (auto_bridge && !default_bridge) {
        let why = if segregates {
            "separates services with `networks:`"
        } else if collides {
            "puts two services on the same internal port"
        } else {
            "gives a service's own name a fixed address with `extra_hosts:`"
        };
        // THE 30 ms IS MEASURED AND BROKEN DOWN, because the breakdown is what decides whether the
        // bridge can ever become the default wiring. Alternated runs of this same binary, whole
        // `up -d`, image warm: a pod is FLAT at 172 ms for 1, 4 or 8 services (it is paid once and
        // the bring-up is concurrent per level), while a bridge is 198 ms for 1, 312 for 4 and 402
        // for 8 - about 30 ms per service. Of those 30, roughly 12 are the per-member NAT and 17
        // are the namespace, the veth and its addressing: the same 8 services on a bridge whose
        // network is `internal: true`, which gets no NAT at all (measured: 9 pasta processes for 8
        // members with outbound, 0 without, 1 for the whole pod), come up in 305 ms. So one NAT per
        // bridge instead of one per member would buy back 12 ms a service and not the other 17.
        let how = if auto_bridge {
            "so kern gives each service its own network namespace on a bridge, which is Docker's \
             arrangement. That costs about 20 ms for the stack"
        } else {
            "so kern gives each service its own network namespace (as `--no-pod` does). That costs \
             a relay hop between peers"
        };
        eprintln!(
            "kern: note: this file {why}, which ONE shared namespace cannot do, {how}; pass `--pod` \
             to keep one shared namespace instead, where kern refuses the stack rather than running \
             it with the separation dropped"
        );
    }
    let no_pod = no_pod || auto_no_pod;
    // The two sentences the parser no longer says, said once, now that the wiring is settled.
    //
    // ONLY WHEN THE MEMBERSHIPS SEPARATE SOMETHING. A file can name three networks and still put
    // every pair of services on a shared one, and then the pod reaches exactly what the file says it
    // reaches: nothing is dropped, nothing is enforced, and "'networks:' ignored" is a warning about
    // a loss that did not happen. MEASURED on a neutral corpus of 259 files: 75 declared per-service
    // networks and only 11 of them actually separate a pair, so the sentence was firing on 64 files
    // where it had nothing to report - which is how a reader learns to skip the line that matters.
    if segregates {
        let mode = if no_pod {
            crate::compose::StackNet::PerService
        } else {
            crate::compose::StackNet::Pod
        };
        if let Some(note) = crate::compose::networks_note(mode) {
            eprintln!("kern: warning: compose: {note}");
        }
        if boxes.iter().any(|b| b.on_internal_network) {
            if let Some(note) =
                crate::compose::internal_note(mode, crate::compose::stack_is_internal_only(&boxes))
            {
                eprintln!("kern: warning: compose: {note}");
            }
        }
    }
    // `network_mode: service:X` ANSWERED HERE, for the reason the two sentences above are answered
    // here: what to say about it is a claim about the wiring, and the wiring is settled one line
    // above rather than while the file is being read. Outside the `segregates` block on purpose - a
    // file can reach the per-service wiring through a port collision without any `networks:` key at
    // all, and that stack is owed the sentence just as much.
    //
    // ONLY THE SHARES THAT RESOLVED. A target the file names but does not define was already
    // reported by the parser as naming no service, and listing it here again would put it in a
    // sentence that says what the wiring gives it - a claim about a service that does not exist.
    let net_share_pairs: Vec<(String, String)> = boxes
        .iter()
        .filter_map(|b| b.net_share.as_ref().map(|t| (b.service.clone(), t.clone())))
        .filter(|(_, target)| {
            boxes
                .iter()
                .any(|o| o.service == *target || o.name == *target)
        })
        .collect();
    // WHICH ARM OF THE NOTE IS TRUE DEPENDS ON THE NAMESPACES, NOT ON WHETHER A POD EXISTS. A
    // bridge-wired stack IS in a pod - the bridge lives in the pod's namespace - so asking `no_pod`
    // read `--bridge` as "one shared namespace" and printed the arm that says the key is satisfied
    // about a stack where every service has its own loopback. MEASURED: `wiring: bridge` printed
    // beside "every service in this stack shares ONE network namespace", with the two services on
    // 10.89.0.2 and 10.89.0.3 and nothing answering on the client's 127.0.0.1.
    //
    // `want_bridge` is read AFTER the automatic decision above has been folded into it, so this is
    // the wiring the stack will actually get and not the flag someone typed.
    if let Some(note) = crate::compose::net_share_note(
        if no_pod || want_bridge {
            crate::compose::StackNet::PerService
        } else {
            crate::compose::StackNet::Pod
        },
        &net_share_pairs,
    ) {
        eprintln!("kern: warning: compose: {note}");
    }
    // THE MEMORY CEILING EVERY SERVICE ACTUALLY GETS, RESOLVED ONCE FOR THE WHOLE STACK.
    //
    // A Docker container with no `mem_limit:` has no memory limit and is bounded by the machine; a
    // kern box with no `--memory` used to get `kern box`'s 512 MiB default, so a service that runs
    // under Docker was OOM-killed at a number written NOWHERE in the file. MEASURED on a neutral
    // corpus of 259 files: 243 have at least one service in that position, which made it the largest
    // remaining difference from Docker after the publish default.
    //
    // A service with nothing written now gets the HOST'S RAM - the same bound Docker leaves it, and
    // the same decision the build step already took for the same measured reason - so the failure
    // stays attributable to the box's own cgroup instead of the host OOM killer choosing a victim.
    // `[kern] compose_memory_max` restores a strict ceiling and is a CEILING: it also caps a
    // `mem_limit:` that asks for more, because a limit a downloaded file can raise limits nothing.
    //
    // BEFORE THE VERB DISPATCH, so `config` shows the caps `up` applies. This file has paid three
    // times for a decision taken inside the `up` branch.
    if let Some(note) = apply_memory_policy(
        &mut boxes,
        crate::commands::compose_memory_policy(),
        crate::commands::host_meminfo_bytes("SwapTotal:"),
    ) {
        eprintln!("kern: note: compose: {note}");
    }
    // THE DIFFERENCES FROM DOCKER THAT BREAK NOTHING AND THEREFORE SAY NOTHING.
    //
    // Each is a difference the compatibility measurement CANNOT see, because that measurement counts
    // a file as compatible when kern prints nothing about it - the tool is kern's own warnings, so it
    // is blind by construction to whatever kern does not know it does. A service holding a socket
    // with no daemon behind it, and services sharing one loopback, both come up green and behave
    // differently from Docker. Closing that gap is naming them; the numbers move or they do not.
    if let Some(note) = crate::compose::docker_socket_note(&boxes) {
        eprintln!("kern: warning: compose: {note}");
    }
    // A BRIDGE POD IS NOT A SHARED NAMESPACE, and this sentence is only true of one. It says the
    // stack's services share `127.0.0.1`; on a bridge each of them has its own, which is the whole
    // reason the wiring exists. Keyed on `no_pod` alone it fired on every bridge stack and told the
    // reader the opposite of what was happening: MEASURED on the corpus, 17 files gained that
    // difference under `--bridge` instead of losing it.
    if let Some(note) = crate::compose::wiring_note(
        if no_pod || want_bridge {
            crate::compose::StackNet::PerService
        } else {
            crate::compose::StackNet::Pod
        },
        boxes.len(),
    ) {
        eprintln!("kern: note: compose: {note}");
    }
    // Verbs that answer a question about the stack rather than changing it return here.
    // The read-only verbs answer questions about a bring-up, so they are told what that bring-up
    // would do, not which flag was typed: `--bridge` gives each service its own namespace exactly as
    // `--no-pod` does, and a check keyed on the flag refused files the bridge runs.
    // `privileged: true` IS DECIDED HERE, BEFORE ANY VERB, so `config` answers exactly what `up`
    // would do rather than describing a stack the bring-up will refuse to build that way. The grant
    // comes from the command line or the operator's own config, never from the file; without it the
    // field is cleared, so nothing downstream can emit the flag by accident.
    if let Some(note) = crate::commands::apply_privileged_grant(
        &mut boxes,
        allow_privileged || crate::commands::privileged_allowed_by_config(),
    ) {
        eprintln!("kern: note: compose: {note}");
    }
    // THE PRIVILEGED-PORT DECISION BELONGS BEFORE THE READ-ONLY VERBS, for `apply_privileged_grant`'s
    // reason directly above: `config` must answer what `up` would do. The collision check runs first
    // and on the ports THE FILE NAMES, so a file publishing 80 twice is refused saying 80 rather than
    // the port the shift would have moved both onto.
    check_port_collisions(&boxes)?;
    // WHAT HAPPENS TO A PRIVILEGED PORT IS DECIDED HERE, FOR THE WHOLE STACK, BEFORE ANYTHING RUNS.
    //
    // It used to be decided inside each box, which cannot see its peers: MEASURED on a two-service
    // file publishing `80` and `8080`, `web`'s 80 was moved onto the 8080 `other` had already bound
    // and `web` died with `Address already in use`, naming neither the move nor the service it
    // collided with. One plan over the union of the stack's ports cannot do that, and `config`
    // reports the same plan `up` will carry out.
    //
    // `refuse` refuses HERE too, for the reason the shift moved: at the box it is one service
    // failing after its peers have started, and the operator has to read a log to find out which.
    {
        let floor = crate::commands::unprivileged_port_start_at(
            "/proc/sys/net/ipv4/ip_unprivileged_port_start",
        );
        match crate::commands::privileged_port_policy() {
            Ok(true) => {
                let moved = crate::commands::shift_privileged_ports_across(&mut boxes, floor);
                if !moved.is_empty() {
                    let list = moved
                        .iter()
                        .map(|(svc, from, to)| format!("{svc} {from} -> {to}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    // THE ONE CLASS THE SHIFT BREAKS, named when it is actually in play. An ACME
                    // challenge is answered to a REMOTE certificate authority, which reaches the
                    // published address on 80 (HTTP-01) or 443 (TLS-ALPN) and never reads this
                    // note: Caddy's automatic HTTPS and Traefik's Let's Encrypt resolver both fail
                    // issuance on a moved port, and the error surfaces from the CA rather than from
                    // kern. Every other consequence of a shift is visible to whoever typed the
                    // command; this one is not.
                    let acme = if moved.iter().any(|(_, from, _)| *from == 80 || *from == 443) {
                        " A certificate authority cannot be redirected: if a service issues its own \
                         TLS certificates (Caddy's automatic HTTPS, Traefik with Let's Encrypt), \
                         ACME needs the CA to reach 80 or 443 themselves and issuance will fail \
                         here."
                    } else {
                        ""
                    };
                    // THE REMEDY THAT KEEPS THE FILE AS WRITTEN, named because a rootless peer
                    // names it and kern did not. podman refuses the same port with
                    // "you can add 'net.ipv4.ip_unprivileged_port_start=80' to /etc/sysctl.conf
                    // (currently 1024)", which tells the reader how to make their compose file work
                    // unchanged. kern moved the port and offered only `privileged_port = "refuse"`,
                    // which turns a moved port into a failed one: the two options it named were
                    // "different" and "broken", and the one that gives the file what it asked for
                    // was missing. The floor is read from the host, so the number in the sentence is
                    // this machine's and not a constant.
                    eprintln!(
                        "kern: note: this host binds from {floor} upward, so kern publishes these \
                         on a port it can bind: {list}. The service still listens where its own \
                         config says it does. To keep the port the file asks for, lower the floor on \
                         this host: `sudo sysctl -w net.ipv4.ip_unprivileged_port_start=80` (add it \
                         to /etc/sysctl.conf to survive a reboot), which is what a rootless daemon \
                         needs too. Set `[kern] privileged_port = \"refuse\"` to fail instead of \
                         moving them.{acme}"
                    );
                }
            }
            Ok(false) => {
                // ONE SENTENCE PER SERVICE, with all of its ports: caddy publishes 80 and 443, and
                // "caddy publishes 80; caddy publishes 443" reads like two different problems.
                let low: Vec<String> = boxes
                    .iter()
                    .filter_map(|b| {
                        let ports: Vec<String> = crate::commands::declared_host_ports(b)
                            .into_iter()
                            .filter(|p| *p < floor)
                            .map(|p| p.to_string())
                            .collect();
                        (!ports.is_empty())
                            .then(|| format!("{} publishes {}", b.service_name(), ports.join(", ")))
                    })
                    .collect();
                if !low.is_empty() {
                    return Err(Error::Compose(format!(
                        "{}, and this host only lets an unprivileged process bind from {floor} \
                         upward. `[kern] privileged_port = \"refuse\"` is set, so kern does not \
                         move it: publish a port at or above {floor}, or lower \
                         `net.ipv4.ip_unprivileged_port_start` on the host.",
                        low.join("; ")
                    )));
                }
            }
            Err(e) => eprintln!(
                "kern: warning: {e}; a privileged port is moved rather than refused, which is the \
                 default"
            ),
        }
    }
    // `ipv4_address:` IS A QUESTION `config` MUST ANSWER, and it was answered only at bring-up.
    //
    // MEASURED on the corpus: of the 29 files kern wires with relays, 19 pin a service with
    // `ipv4_address:` and for 16 of them `kern compose <file> config` said nothing at all. That key
    // is how those files address each other - ICS simulations, data diodes, router topologies - and
    // under the relay wiring a box claims only its OWN address, so the service answers there and a
    // peer connecting to it does not. A dry run that stays silent about it is the silence this
    // project treats as the expensive defect, not a missing feature.
    //
    // THE SAME SENTENCE, from the same function the bring-up calls: only the wiring selection is
    // repeated here, because at this point the file's wiring is known and the registry's is not.
    // The bring-up keeps its own call, where `use_pod` also reflects a stack that is already
    // running without a pod, and prints the subnet notes that belong to it.
    if matches!(action, ComposeAction::Config | ComposeAction::Systemd) {
        let pairs: Vec<(String, String)> = boxes
            .iter()
            .flat_map(|b| {
                b.net_ipv4
                    .iter()
                    .map(move |ip| (b.service.clone(), ip.clone()))
            })
            .collect();
        let note = if want_bridge {
            let mut declared: Vec<&str> = boxes
                .iter()
                .filter_map(|b| b.net_subnet.as_deref())
                .collect();
            declared.sort_unstable();
            declared.dedup();
            crate::compose::net_ipv4_bridge_note(bridge_cidr_for(&declared), &pairs)
        } else {
            crate::compose::net_ipv4_note(
                if no_pod {
                    crate::compose::StackNet::PerService
                } else {
                    crate::compose::StackNet::Pod
                },
                &pairs,
            )
        };
        if let Some(note) = note {
            eprintln!("kern: warning: compose: {note}");
        }
    }
    if run_terminal_verb(
        action,
        &mut boxes,
        &TerminalOpts {
            pod: &pod,
            file,
            tail,
            follow,
            all,
            services,
            own_namespaces: no_pod || want_bridge,
            wiring_from_flag,
            // A bridge stack has NO relays: its members meet on a real network. See the field's doc.
            relay_wiring: no_pod && !want_bridge,
            allow_device_grants,
            remove_volumes,
            remove_orphans,
            ps_quiet,
            ps_services,
            ps_format,
        },
    )? {
        return Ok(());
    }

    // A STACK'S MODE IS READ FROM THE REGISTRY, NOT FROM A FILE'S PRESENCE.
    //
    // The first version inferred it from the relay plan existing on disk, which is a presence test
    // standing in for a state: `down` removes that directory but a SIGKILL, an OOM or a reboot does
    // not, so a leftover file made the next `up` behave as though a stack were running when none was.
    // The registry holds facts about processes that exist, and a no-pod box carries an EMPTY pod
    // field (measured), so "some box of this stack is up and is in no pod" is the same question asked
    // of something that cannot be stale.
    let running_without_pod: Vec<String> = boxes
        .iter()
        .filter(|b| registry::find(&b.name).is_some_and(|i| i.pod.is_empty() && !b.net))
        .map(|b| b.service.clone())
        .collect();

    // `up` WITHOUT `--no-pod` ON SUCH A STACK IS AMBIGUOUS, so it is refused.
    //
    // It is either a forgotten flag or a deliberate move back into a pod, and nothing on disk can say
    // which. Both readings are defensible, which is exactly when inferring is wrong: one of them
    // silently changes the stack's network topology. `start` answers differently and carries the
    // mode, because "put back what was running" has only one reading.
    //
    // THIS SITS BEFORE THE RECONCILER, and the first version did not. Placed after it, `up` on a
    // stack whose definitions still match returns "already up to date" and exits 0 without ever
    // reaching the check, which is the same silent success it was written to prevent.
    if action == ComposeAction::Up && !no_pod && !running_without_pod.is_empty() {
        return Err(Error::Compose(format!(
            "this stack is already running WITHOUT a pod: {} {} up with no pod. `up` without \
             --no-pod would move {} back into one, and kern will not guess which you meant. Either \
             pass --no-pod to keep the stack as it is, or run `kern compose {file} down` first to \
             bring it up in a pod.",
            running_without_pod.join(", "),
            if running_without_pod.len() == 1 {
                "is"
            } else {
                "are"
            },
            if running_without_pod.len() == 1 {
                "it"
            } else {
                "them"
            },
        )));
    }

    // `external: true` MEANS "DO NOT CREATE IT", so a missing one is a refusal and not a warning.
    //
    // kern auto-creates a named volume on first use, which is the right answer for a volume the file
    // owns and the worst possible answer for this one: the key is written precisely when the data
    // belongs to something else, and handing the service a fresh empty directory instead lets it
    // start, find nothing, and initialise over the top of where the real data was supposed to be.
    // Docker refuses the stack; kern used to say nothing at all, because the top-level `volumes:`
    // block was skipped unread.
    //
    // ON THE MUTATING PATH ONLY, deliberately, and this is not the `config`-must-agree-with-`up`
    // class: the answer depends on which volumes exist ON THIS HOST rather than on anything in the
    // file, so it is not a fact `config` is being asked about. Docker draws the line in the same
    // place (`docker compose config` renders such a file, `up` refuses it).
    if let Some(msg) =
        missing_external_volumes(&boxes, |n| crate::volume::volumes_dir().join(n).exists())
    {
        return Err(Error::Compose(msg));
    }

    let mut levels = crate::compose::topo_levels(&boxes).map_err(Error::Compose)?;
    // `start` launches only what is NOT already running. Filtering the LEVELS (not `boxes`) keeps the
    // dependency graph exactly as computed - dropping a service from `boxes` would make its dependents
    // reference an unknown name - and keeps every level entry backed by a real box.
    // A SERVICE SELECTION NARROWS WHAT IS STARTED, and it did not before: `start b` on an a/b/c
    // stack launched all three, because the selector reached the read-only verbs and stopped there.
    // Filtered on the LEVELS for the same reason `start` is just below - dropping a service from
    // `boxes` would leave its dependents naming a box that is no longer there.
    //
    // `up` EXPANDS to what the named services depend on and the others do not, which is Docker
    // Compose's split: `up web` has to bring the `db` it declares or it starts something that cannot
    // work, while `start web` and `restart web` are instructions about web alone.
    if !services.is_empty() {
        // `--no-deps` TURNS THE EXPANSION OFF, which is what `up -d --no-deps --build web` is for:
        // redeploying one service without restarting the database under it. Honoured HERE and not
        // only in `run`, because a flag that parses and changes nothing is the defect this codebase
        // refuses everywhere else, and it would have been one the moment `run` introduced the flag.
        let wanted: std::collections::HashSet<String> = if action == ComposeAction::Up && !no_deps {
            crate::compose::with_dependencies(&boxes, services)
        } else {
            services.iter().cloned().collect()
        };
        for level in &mut levels {
            level.retain(|n| wanted.contains(n));
        }
    }
    if action == ComposeAction::Start {
        for level in &mut levels {
            level.retain(|n| !is_box_alive(n));
        }
        if levels.iter().all(|l| l.is_empty()) {
            println!("compose start: every service is already running");
            return Ok(());
        }
    }
    // DRIFT DETECTION. `up` on a running stack used to fail with "a box named 'x' is already
    // running", so an edit to the compose file was never applied and the user had to know to run
    // `down` first. Reconcile instead: a service whose definition still matches is LEFT ALONE (no
    // needless restart, no dropped connections), one whose definition changed is stopped here so the
    // launch loop below recreates it from the new definition.
    //
    // This is only safe because `up` now verifies the stack after bring-up: without that check a
    // service that dies immediately would be recreated on every invocation, silently, forever.
    if action == ComposeAction::Up {
        let mut kept = 0usize;
        let mut stale: Vec<String> = Vec::new();
        for level in &mut levels {
            level.retain(|n| {
                let Some(b) = boxes.iter().find(|b| &b.name == n) else {
                    return true;
                };
                match registry::find(n) {
                    None => true, // not running: launch it
                    Some(inst) => match reconcile_decision(&inst, &definition_hash(b)) {
                        Reconcile::UpToDate => {
                            kept += 1;
                            false
                        }
                        Reconcile::Recreate => {
                            stale.push(n.clone());
                            true
                        }
                    },
                }
            });
        }
        if !stale.is_empty() {
            let short: Vec<&str> = stale
                .iter()
                .map(|n| n.strip_prefix(&format!("{pod}-")).unwrap_or(n))
                .collect();
            println!("→ definition changed, recreating: {}", short.join(", "));
            // Stopped BEFORE the launch loop so the name is free when it is recreated.
            let _ = stop(&stale, false);
        }
        if kept > 0 && levels.iter().all(|l| l.is_empty()) {
            println!("compose up: {kept} service(s) already up to date");
            return Ok(());
        }
        if kept > 0 {
            println!("→ {kept} service(s) already up to date, left running");
        }
    }
    // Static rejection of conditions that can NEVER be satisfied - caught here, not left to time out
    // at runtime (adversarial-review 2d). `topo_order` above already rejects cycles and unknown deps.
    validate_conditions(&boxes)?;
    // Static rejection of DUPLICATE published host ports: the bring-up below is CONCURRENT per level,
    // so two services on the same host port would race for the bind - one wins, the other dies with
    // EADDRINUSE buried in its own log while `up` still reports success (a silent partial failure,
    // empirically confirmed). Caught here from the parsed file: deterministic, before any box starts.
    check_port_collisions(&boxes)?;
    // Self-gated (see its doc comment): `config` and `systemd` reach the SAME rejection through the
    // same call, so the dry run can never disagree with the bring-up about what is startable.
    // THE ARGUMENT IS "DOES EACH SERVICE HAVE ITS OWN NAMESPACE", not "was --no-pod typed". All
    // three checks below are about ONE SHARED NAMESPACE: two services cannot both bind a port, two
    // cannot set the same `net.*` sysctl differently, and one `/etc/hosts` cannot hold two entries
    // for a name. `--bridge` gives each service its own namespace, so none of the three applies, and
    // asking the raw flag refused a stack the bridge runs perfectly well.
    let own_namespaces = no_pod || want_bridge;
    check_pod_global_conflicts(&boxes, own_namespaces)?;
    // Self-explaining (see its doc): a device grant a compose file asked for needs a command-line
    // acknowledgement, because the file cannot reach the command line.
    if let Some(msg) = device_grant_problem(&boxes, allow_device_grants) {
        return Err(Error::Compose(msg));
    }
    // Softer sibling: two services whose IMAGES expose the same port without either DECLARING it (two
    // nginx on :80, two node apps on :3000). Best-effort and cache-only (never pulls just to warn),
    // a WARNING not an error because an image's EXPOSE is a hint, not a guaranteed bind.
    warn_image_expose_collisions(&boxes, own_namespaces);
    // THE ESCAPE HATCH SAYS WHAT IT COSTS. `--no-pod` is what the port-collision refusal sends people
    // to, and it is not free: MEASURED on the same two-service stack, `getent hosts db` answers
    // `127.0.0.1 db db` in a pod and NOTHING under `--no-pod`. Trading a loud refusal at bring-up for
    // a silent name-resolution failure inside a service, with nothing said in between, is the shape
    // this project treats as the expensive kind of defect. Once per bring-up, not once per service.
    // THE UNDECLARED-PORT NOTE BELONGS HERE, at config time: it follows from the file alone, and its
    // whole value is arriving before a service logs `Connection refused`.
    // THE RELAY WIRING, not "its own namespace": a relay is built per DECLARED port, and a bridge
    // builds none - its members reach any port of a peer by name. Printed for a bridge stack this
    // note tells an operator to declare a port that nothing needs.
    if let Some(note) = no_pod_undeclared_ports_note(&boxes, no_pod && !want_bridge) {
        eprintln!("{note}");
    }
    // The peer-names note does NOT belong here: it promises the colliding pairs, and those are
    // measured from the RUNNING services. Printed at this point it was separated from them by the
    // whole build, so it moved next to them; see the relay block below.
    // A pod shares ONE network namespace, so a `net.*` sysctl written on one service applies to every
    // service in the stack and the last one to start wins. The file makes it look per-service; say so
    // rather than let an operator tune one service and silently retune the others.
    if !no_pod && boxes.len() > 1 {
        for b in &boxes {
            for kv in b.sysctls.iter().filter(|s| s.starts_with("net.")) {
                let key = kv.split('=').next().unwrap_or(kv);
                eprintln!(
                    "kern: warning: compose: service '{}': sysctl '{key}' applies to the WHOLE pod (services \
                     share one network namespace) - the last service to start wins; use --no-pod for \
                     per-service network settings",
                    b.name
                );
            }
        }
    }
    let self_exe =
        std::env::current_exe().map_err(|e| Error::Compose(format!("locating kern: {e}")))?;
    // Docker's PROJECT DIRECTORY: every service's box runs with CWD = the compose file's dir, so a
    // relative `env_file: ./x.env`, `-v ./data:/d`, or `rootfs: ./root` resolves against it (as Docker
    // anchors them) instead of against kern's own CWD - which broke `up` from any other directory. The
    // box reads `env_file` before the systemd-scope re-exec, and `systemd-run --scope` keeps the cwd, so
    // both the pre- and post-re-exec resolutions land in the project dir.
    let project_dir = compose_dir(file);

    // Compose `build:` - build each service's image via `kern build` BEFORE the launch loop, so a box
    // with `build:` gets a real image to run. Four hardenings the adversarial review demanded, because
    // `build:` is the first place the YAML parser drives a privileged operation on host paths:
    //  1. `context`/`dockerfile` are CONFINED under the compose file's directory (traversal guard).
    //  2. `build.args` are already `${VAR}`-interpolated by the parser (never literal `${VAR}`).
    //  3. a build failure fails the WHOLE `up` with a linked message ("service X: build failed …"),
    //     since a box whose image never built can't start (and its depends_completed/healthy peers
    //     would hang) - fail-fast beats a half-up stack.
    //  4. `image:` + `build:` together = build AND tag as `image` (compose semantics); a `build:` with
    //     no `image:` gets a synthesized tag. We never silently use a stale registry image for a box
    //     the user meant to build locally.
    resolve_builds(&mut boxes, file, &self_exe)?;
    // Docker resolves a RELATIVE bind source (`./certs:/dst`, `.:/app`) against the compose file's
    // directory. kern's `-v` needs an absolute path or a named volume, so rewrite relative binds here
    // to absolute (confined under the compose dir - traversal guard, like a build context). A `named:`
    // source or an already-absolute `/host:/dst` passes through untouched.
    resolve_relative_binds(&mut boxes, file)?;

    // `run` DIVERGES HERE, after the builds and the bind resolution and before the bring-up: it
    // needs a service's fully resolved definition and none of the stack-wide launch that follows.
    // `exec` DIVERGES HERE for the same reason `run` does: it needs a service resolved to its box
    // and none of the stack-wide launch below. It is answered before the bring-up, not in the
    // terminal-verb function, because that function has no access to `run_cmd`.
    if action == ComposeAction::Exec {
        let Some(target) = services.first() else {
            return Err(Error::Compose(format!(
                "exec needs a service: `kern compose {file} exec <service> <command…>`"
            )));
        };
        let Some(b) = boxes.iter().find(|b| &b.name == target) else {
            return Err(Error::Compose(format!(
                "exec: no service '{target}' in {file}"
            )));
        };
        if registry::find_ref(&b.name).is_none() {
            return Err(Error::NotRunning(format!(
                "service '{}' is not running; `kern compose {file} up -d {}` first, or use \
                 `kern compose {file} run {} <command…>` for a one-off",
                b.service_name(),
                b.service_name(),
                b.service_name()
            )));
        }
        // `exec` REPLACES THIS PROCESS'S STATUS with the command's (it calls `process::exit` with
        // the code), which is Docker's behaviour: `compose exec -T web sh -c 'exit 7'` exits 7 there
        // and here. The service's own working directory is used, as Docker uses the container's.
        //
        // AND THE SERVICE'S OWN USER, which is the same rule applied to the same question. Docker's
        // `compose exec` runs as the user the service declares; this entered as box root, so a file
        // written from an `exec` landed owned by root inside a box whose workload runs as someone
        // else, and `whoami` answered differently here than there. MEASURED on a service with
        // `user: "5050"`: the workload reported 5050 and `compose exec ... id -u` reported 0.
        // `kern exec <box>` is unchanged and remains the root way in.
        return crate::commands::exec(
            &b.name,
            run_cmd,
            &[],
            b.workdir.as_deref(),
            unsafe { libc::isatty(0) } == 1,
            true,
        );
    }
    if action == ComposeAction::Run {
        return compose_run(
            &mut boxes,
            &pod,
            file,
            services,
            run_cmd,
            run_rm,
            no_deps,
            &self_exe,
            &project_dir,
        );
    }

    // A fresh epoch token for THIS `up`. Stamped into every `depends_completed` target's exit sidecar
    // and required to match on read, so a sidecar left by a previous `up` of the same stack can't
    // satisfy this run's wait (adversarial-review 1a). Uniqueness only needs to hold within this
    // process's lifetime; our pid + a monotonic-ish clock read is plenty and needs no rng/new deps.
    let up_token = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );

    // Auto-pod: a stack gets a shared network (name resolution + outbound) unless the user opts out
    // or every box already shares the host net (`--net`). Reuse an existing pod so `up` is
    // idempotent.
    //
    // THE COUNT IS NOT THE CONDITION. This read `boxes.len() >= 2`, because a pod's OTHER job is
    // letting services reach each other by name and one service has nobody to reach. But the pod is
    // also the only thing that attaches `pasta`, so a ONE-service stack came up with no egress at
    // all: not "no DNS", no route. MEASURED with the reporter's own file (one service, published
    // port, two binds): `curl http://1.1.1.1` failed in 0 ms, and the box's `/etc/resolv.conf` came
    // from the IMAGE and looked perfectly healthy, which is why it reads as a DNS fault. A single
    // service is the first thing anyone tries.
    let mut use_pod = !no_pod && boxes.iter().any(|b| !b.net);
    // `start` CARRIES THE MODE, from the same registry fact the refusal above uses.
    //
    // MEASURED, and it is the reason this exists rather than a precaution. Bring a stack up with
    // `--no-pod`, stop ONE service, and run `kern compose <file> start` (which is exactly what
    // `watch` does on every edit): without this, the flag is gone, the restarted service joins a pod
    // the others are not in, its peers' relays still point into the namespace it no longer has, and
    // `start` exits 0. A `nc` to the peer still CONNECTS, because the relay's listener is up in the
    // box that did not restart, so even a careful check reports success while no byte crosses.
    //
    // It is announced rather than applied in silence: a flag that takes effect without having been
    // typed is worth one line.
    if use_pod && !running_without_pod.is_empty() {
        use_pod = false;
        eprintln!(
            "kern: note: this stack is running without a pod ({} {} up with no pod); starting in \
             the same mode, so peers stay reachable",
            running_without_pod.join(", "),
            if running_without_pod.len() == 1 {
                "is"
            } else {
                "are"
            },
        );
    }
    let use_pod = use_pod;
    // THE BRIDGE WIRING: A POD THAT HOLDS A BRIDGE INSTEAD OF A LOOPBACK.
    //
    // WHY IT EXISTS. A shared namespace is fast and is the one thing kern does that Docker does not:
    // every service sees the same `127.0.0.1`, so two services cannot both bind a port and a port one
    // binds on the loopback is reachable by every peer. The wiring kern had for a private loopback
    // pays a TCP relay per ORDERED PAIR PER PORT, which is quadratic and takes a port the workload
    // may want. On a bridge each service keeps its own namespace and its own loopback and meets its
    // peers at their addresses: Docker's arrangement, one `veth` per service, no relay.
    //
    // MEASURED on Docker's own `nginx-golang`, which fails under BOTH older wirings because `proxy`
    // and `backend` each bind port 80 and neither declares it: in a shared namespace the second
    // cannot bind, and without a pod kern's own relay takes the port first.
    //
    // ONE NETWORK FOR NOW, and a file whose `networks:` SEGREGATE keeps the relay wiring, because one
    // bridge puts every service back on one network and would drop the separation the file asked
    // for. A bridge per compose network is the next step and is not this one.
    // THE FILE'S OWN NETWORK IS USED WHEN IT DECLARES ONE, and that is what makes `ipv4_address:`
    // honoured rather than approximated: the address the file pinned IS the address the service
    // answers on, which is Docker's arrangement. Without it kern invents a network, the declared
    // addresses fall outside it, and a peer that hard-codes one has no route.
    //
    // ONE BRIDGE CARRIES ONE NETWORK. A file that declares two subnets is told which one was taken,
    // because silently picking decides where a service answers.
    let declared: Vec<&str> = {
        let mut v: Vec<&str> = boxes
            .iter()
            .filter_map(|b| b.net_subnet.as_deref())
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    let bridge_cidr: Option<&str> = if want_bridge && use_pod {
        match declared.first() {
            // A subnet kern cannot build a bridge on (a /31, an IPv6 prefix, a typo) falls back to
            // kern's own rather than failing the stack: the addresses then do not match, and the
            // note below says so.
            Some(cidr) if kern_isolation::pod_bridge_parts(cidr).is_some() => {
                if declared.len() > 1 {
                    eprintln!(
                        "kern: note: compose: this file declares {} subnets and one bridge carries \
                         one: kern uses {cidr}. A service pinned inside another one keeps its \
                         address on its own loopback but is not reachable there by a peer",
                        declared.len()
                    );
                }
                Some(cidr)
            }
            Some(cidr) => {
                eprintln!(
                    "kern: note: compose: '{cidr}' is not a network kern can put a bridge on \
                     (expected an IPv4 network with a prefix between 8 and 30), so the stack meets \
                     on {COMPOSE_BRIDGE_CIDR} instead and an `ipv4_address:` from that subnet is \
                     not the address a peer reaches"
                );
                Some(COMPOSE_BRIDGE_CIDR)
            }
            None => Some(COMPOSE_BRIDGE_CIDR),
        }
    } else {
        None
    };

    // `ipv4_address:` ANSWERED HERE TOO, and for the same reason: the key is honoured in one wiring
    // and only half honoured in the other, so the parser cannot say which without knowing the
    // wiring. Pairs are (service, address); a service on two networks contributes two.
    let net_ipv4_pairs: Vec<(String, String)> = boxes
        .iter()
        .flat_map(|b| {
            b.net_ipv4
                .iter()
                .map(move |ip| (b.service.clone(), ip.clone()))
        })
        .collect();
    // THREE WIRINGS, THREE DIFFERENT FACTS about the same key, so the bridge gets its own sentence
    // rather than the pod's: there the address is an alias on a shared loopback and the PORT picks
    // the service, here it is the service's own address on the file's own network.
    let ipv4_note = match bridge_cidr {
        Some(cidr) => crate::compose::net_ipv4_bridge_note(cidr, &net_ipv4_pairs),
        None => crate::compose::net_ipv4_note(
            if no_pod {
                crate::compose::StackNet::PerService
            } else {
                crate::compose::StackNet::Pod
            },
            &net_ipv4_pairs,
        ),
    };
    if let Some(note) = ipv4_note {
        eprintln!("kern: warning: compose: {note}");
    }
    if want_bridge && !use_pod {
        eprintln!(
            "kern: note: --bridge needs a pod to hold the bridge, and this stack is wired without \
             one; it keeps the per-service relay wiring"
        );
    }
    // THE PRE-EXEC GATE IS ACTIVE EXACTLY WHEN PEER RELAYS WILL BE BUILT, and that condition is
    // written once here rather than re-derived at the three points that consume it. A stack with no
    // relays has no network to finish building, so its boxes exec the moment they are set up and the
    // gate costs nothing but the variable being unset.
    // THE GATE IS ABOUT NAMESPACES BEING BUILT FROM OUTSIDE, not about the pod. Two things are done
    // to a box while it is held: peer relays, and the NAT. A bridge stack has no relays but every
    // member gets its own NAT, and pasta configures an interface INSIDE the box's namespace from
    // outside it - a workload already running would see no route one instant and a route the next.
    // MEASURED: with the gate keyed on `!use_pod`, a bridge member came up with an address on the
    // bridge, reached its peers, and could not reach the internet at all.
    //
    // A ONE-SERVICE BRIDGE STACK IS HELD TOO. The `> 1` is a relay argument (one service has no
    // peers), and it does not carry over: one service still needs its route.
    let gate_active = bridge_cidr.is_some() || (!use_pod && boxes.len() > 1);
    // WHICH SERVICES GET EGRESS, decided once, from the file, before anything starts.
    //
    // In a pod this is empty: the pod itself carries one NAT for every member, and attaching a
    // second per box would put two default routes in one namespace.
    //
    // Without a pod each service has its own namespace, so egress is per service - which is the
    // first time `internal: true` can mean what it says in Compose. A service every one of whose
    // networks is marked internal gets NO NAT, and that is a real boundary: there is no route in its
    // namespace at all, not a filter that has to stay correct. Every other service gets one, which
    // is what Docker gives it.
    //
    // A SERVICE WITH `restart:` IS EXCLUDED, for the same reason it is excluded from the gate: it is
    // installed as a systemd unit and started later by the manager, so `up` never holds it and there
    // is no safe instant to attach a NAT to. It is already named in the bring-up note.
    // ON A BRIDGE EVERY MEMBER NEEDS ITS OWN NAT: the pod's single NAT lives in the holder's
    // namespace, which a bridge member is not in. The rule is about ONE SHARED NAMESPACE and not
    // about the word "pod", which is why the argument is the shared-namespace question.
    let outbound_for = outbound_targets(&boxes, use_pod && bridge_cidr.is_none(), use_pod);
    // Write ends, one per PREPARED box, held by `up` and keyed by box name so the release can be
    // ordered by dependency level.
    //
    // `OwnedFd` AND NOT A RAW `c_int`, because every early `return Err(...)` between here and the
    // release must close them. A closed write end is EOF on the box's side, and the box reads EOF as
    // REFUSAL: it never execs and leaves a "never released" record. That is fail-closed obtained
    // from the type system rather than from remembering to clean up on eleven error paths.
    let gates: std::sync::Mutex<Vec<(String, std::os::fd::OwnedFd)>> =
        std::sync::Mutex::new(Vec::new());
    if use_pod && crate::pod::holder_pid(&pod).is_none() {
        // Map a uid RANGE into the pod's shared user ns when ANY member needs it (`wants_uid_range`,
        // the single statement of that rule). A pod member setns's into the holder's user ns and writes
        // NO map of its own, so the holder's map is authoritative - `--uid-range` on the member alone is
        // a no-op, and the decision must be made HERE, before the holder unshares. A pod of only
        // single-uid rootfs services stays single-uid (faster). The pod reports an unavailable range
        // only if a member ASKED for it, matching the per-box rule.
        let pod_needs_range = if boxes.iter().any(|b| b.uid_range) {
            UidRange::Requested
        } else if boxes.iter().any(|b| b.wants_uid_range()) {
            UidRange::ImageDefault
        } else {
            UidRange::Off
        };
        // `internal: true`, HONOURED WHERE IT CAN BE. kern gives a stack ONE network namespace, so
        // the key is all-or-nothing: it maps onto the pod's existing `--no-outbound` only when EVERY
        // service is exclusively on networks the file marks internal. One service on an ordinary
        // network, or one with no `networks:` key at all, and the pod keeps its egress - because a
        // single netns cannot give one service the internet and deny it to another.
        //
        // MEASURED BEFORE THIS EXISTED, with a payload rather than a connection: a service on a
        // network marked `internal: true` reached 1.1.1.1:443 and 8.8.8.8:443 and resolved DNS,
        // exactly like one on an ordinary network. That is the declaration people use to keep a
        // database off the internet, so accepting it and doing nothing is the "runs and lies" failure
        // this codebase refuses everywhere else.
        //
        // The predicate is positive evidence per service (see `ComposeBox::only_internal_networks`),
        // so anything the parser cannot confirm leaves outbound ON. That direction is deliberate: a
        // stack that silently loses the internet fails in a way nobody attributes to a compose key
        // that used to be ignored.
        let stack_is_internal = kern_compose::stack_is_internal_only(&boxes);
        crate::pod::create_with_range(&pod, !stack_is_internal, pod_needs_range, bridge_cidr)?;
        // Feedback-first, and the counterpart of the rule just above: the pod's user namespace has ONE
        // map, the holder's, so a member that asked for the narrow one does not get it when a peer needs
        // the range. That is structural, not a bug to fix, but silently handing a service a WIDER map
        // than its file asked for is the "accepted it and did something else" failure this codebase
        // refuses. Name the services and the peer that decided it, so the reader can split the stack or
        // drop the peer's default instead of wondering why `uid_range = false` changed nothing.
        if !matches!(pod_needs_range, UidRange::Off) {
            let opted_out: Vec<&str> = boxes
                .iter()
                .filter(|b| b.uid_range_explicit_false)
                .map(|b| b.name.strip_prefix(&format!("{pod}-")).unwrap_or(&b.name))
                .collect();
            if !opted_out.is_empty() {
                let because: Vec<&str> = boxes
                    .iter()
                    .filter(|b| b.wants_uid_range())
                    .map(|b| b.name.strip_prefix(&format!("{pod}-")).unwrap_or(&b.name))
                    .collect();
                eprintln!(
                    "kern: note: {} asked for the single-uid map (`uid_range = false`), but a pod shares \
                     ONE user namespace and {} needs the range, so every member gets it. Split the stack \
                     or set `uid_range = false` on {} too if the narrow map is what you want.",
                    opted_out.join(", "),
                    because.join(", "),
                    because.join(", ")
                );
            }
        }
    }
    // Feedback-first: a `--net` (host-network) service in a podded stack is NOT on the pod net, so its
    // peers can't reach it by name - say so rather than let it silently not resolve.
    if use_pod {
        for b in boxes.iter().filter(|b| b.net) {
            eprintln!(
                "kern: note: service '{}' uses --net (host network) - it is NOT reachable by name inside pod '{pod}'",
                b.name
            );
        }
    }
    // THE TRADE IS STATED, NOT MADE IN SILENCE. A pod member is supervised IN-PROCESS and never by a
    // systemd unit: `start.rs` excludes it deliberately, because a unit that outlives the pod holder
    // cannot re-join the network namespace it was started in. So `restart: always`/`unless-stopped`
    // inside a pod restarts on ANY exit and does NOT survive a reboot, which is not what the same key
    // does under Docker.
    //
    // It is printed now because the auto-pod stopped requiring two services. While it did, only
    // multi-service stacks lost reboot-survival and nobody filed it; the same gap now reaches a
    // ONE-service stack, which is the first thing anyone writes. The gap is older than the change
    // that exposes it, and being consistent with an existing gap is not the same as it being
    // acceptable, so the operator is told rather than left to discover it after a reboot.
    if use_pod {
        // The unit name the `systemd` verb suggests, so the two commands can be pasted.
        let project_slug = pod.trim_start_matches("kern-");
        for b in boxes.iter().filter(|b| b.restart_always) {
            // THE PATH THAT KEEPS THE STACK, named first. This used to offer only "run it as a
            // standalone box", which trades the pod away: no peer-by-name, no shared egress, and
            // the file's `depends_on` stops meaning anything. The mechanism that keeps all of it is
            // the unit the `systemd` verb already emits, and the unit's own header prints the same
            // two commands. Docker survives a reboot because its daemon starts at boot and owns the
            // containers; kern has no daemon, so the unit IS the daemon's job.
            eprintln!(
                "kern: note: service '{}' sets `restart:` and is a pod member - kern supervises it \
                 in-process (restarted on ANY exit) but NOTHING brings it back after a REBOOT, \
                 because kern has no daemon that starts at boot. To keep this stack across reboots: \
                 `kern compose {file} systemd > ~/.config/systemd/user/kern-{}.service`, then \
                 `systemctl --user daemon-reload && systemctl --user enable --now kern-{}.service`, \
                 and `loginctl enable-linger` so the user manager starts without a login. A single \
                 service that needs no pod can instead be a standalone box: `kern box <name> \
                 --restart unless-stopped`.",
                b.name, project_slug, project_slug
            );
        }
    }

    // THE `--no-pod` ADDRESS PLAN, built before a single box starts.
    //
    // Without a pod each service holds only its own loopback, so peers are unreachable by name and by
    // address. Every service is given a stack-wide alias (127.0.0.2 upward) and every box is told, via
    // `--add-host`, to resolve its peers there and ITSELF at 127.0.0.1. The relays that make those
    // aliases answer are spawned after the boxes exist, in `peer_relays_for`.
    //
    // Built here rather than per box so a refusal (an unusable service name, a duplicate, a stack
    // larger than the address range) happens once and before anything is launched, instead of leaving
    // half a stack up behind an error about the other half.
    let address_plan: Vec<crate::nopod::Assigned> = if !use_pod && boxes.len() > 1 {
        // A UDP PORT GETS NO RELAY, AND THAT IS SAID RATHER THAN LEFT TO BE DISCOVERED. The relay is
        // a `SOCK_STREAM` pump, so a UDP peer is not addressed; filtering silently would make a
        // `statsd` or a DNS service unreachable under `--no-pod` with nothing having reported it,
        // which is the accepted-and-ignored shape this codebase treats as a defect of its own. A
        // service whose ONLY declared ports are UDP loses every peer, so it is named; one that also
        // has TCP ports keeps those, and the UDP ones are named per service.
        let mut udp_only: Vec<String> = Vec::new();
        let mut udp_ports: Vec<String> = Vec::new();
        let services: Vec<crate::nopod::ServiceInput> = boxes
            .iter()
            .map(|b| {
                let declared = declared_container_ports(b);
                let tcp: Vec<u16> = declared
                    .iter()
                    .filter(|(_, udp)| !*udp)
                    .map(|(p, _)| *p)
                    .collect();
                let udp: Vec<u16> = declared
                    .iter()
                    .filter(|(_, udp)| *udp)
                    .map(|(p, _)| *p)
                    .collect();
                if !udp.is_empty() {
                    let list = udp
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ");
                    if tcp.is_empty() {
                        udp_only.push(format!("{} ({list}/udp)", b.service));
                    } else {
                        udp_ports.push(format!("{} ({list}/udp)", b.service));
                    }
                }
                (
                    b.service.clone(),
                    b.name.clone(),
                    tcp,
                    b.networks.clone(),
                    b.net_aliases.clone(),
                )
            })
            .collect();
        for who in &udp_only {
            eprintln!(
                "kern: note: {who} declares only UDP ports, and a peer relay carries TCP, so no peer \
                 can reach it under --no-pod. Keep the stack in its pod if that service is talked to."
            );
        }
        for who in &udp_ports {
            eprintln!(
                "kern: note: {who} keeps its TCP ports reachable, but its UDP ports are not relayed."
            );
        }
        let plan = crate::nopod::assign_aliases(&services).map_err(Error::Compose)?;
        // THE PAIRS THE FILE ASKED TO SEPARATE, NAMED BEFORE ANYTHING STARTS. A removed edge shows
        // up as `bad address '<peer>'` in a service log, which is the same symptom as a typo or a
        // dead peer; saying it here is what makes it readable as enforcement. Printed before the
        // boxes so it precedes the failure it explains, unlike the unreachable-pair report, which
        // can only be measured from RUNNING services.
        let cut = crate::nopod::segregated_pairs(&crate::nopod::membership_of(&plan));
        if !cut.is_empty() {
            eprintln!(
                "kern: note: {} service pair(s) share no network, so they get no relay and do not \
                 resolve each other: {}",
                cut.len(),
                cut.join("; ")
            );
        }
        // THE MESH IS QUADRATIC, and the 253-service alias cap does not bound it: 253 services with
        // one port each is 63,756 relays and 127,513 processes, more than the `RLIMIT_NPROC` of the
        // machine this was measured on. Refused with the arithmetic, because the alternative is
        // failing somewhere in the middle with an errno from a fork nobody can attribute.
        //
        // CHECKED HERE, BEFORE A SINGLE BOX STARTS, and the first version checked it after. The relay
        // block runs once the boxes are up, so refusing there left the stack running with no relays
        // and an error, which is the worst of both: the user pays the bring-up and gets nothing. The
        // count follows from the file alone, so nothing has to run to know it.
        let n = crate::nopod::relay_plan(&plan).len();
        if n > kern_isolation::peer::MAX_RELAYS {
            return Err(Error::Compose(format!(
                "this stack needs {n} peer relays under --no-pod ({} services and their declared \
                 ports), which is {} processes: kern refuses past {}. A relay costs two processes and \
                 about 240 kB, and a mesh this wide is not what --no-pod is for. Keep the stack in \
                 its pod, where peers reach each other with no relays at all, or declare fewer ports.",
                plan.len(),
                2 * n + 1,
                kern_isolation::peer::MAX_RELAYS
            )));
        }
        plan
    } else {
        Vec::new()
    };

    // THE BRIDGE ADDRESS PLAN, built separately from the relay one and not by rewriting it.
    //
    // The relay plan carries decisions that only make sense with relays: a UDP port gets none and is
    // named, a wide mesh is refused by an arithmetic about processes. On a bridge there are no
    // relays, UDP works like everything else, and the cost is one `veth` per service. Reusing that
    // block would print warnings about a mechanism this wiring does not have.
    //
    // `assign_aliases` is still what validates the services (a name a hosts file can hold, no
    // duplicates), and only the ADDRESS is replaced afterwards: the alias field is a full 32-bit
    // address already, so a bridge address travels through `add_host_args` and `links` unchanged.
    let address_plan: Vec<crate::nopod::Assigned> = match bridge_cidr {
        None => address_plan,
        Some(cidr) => {
            let (gw, _, prefix) = kern_isolation::pod_bridge_parts(cidr).ok_or_else(|| {
                Error::Compose(format!("'{cidr}' is not a network kern can bridge"))
            })?;
            let first = u32::from(gw) + 1;
            let last = u32::from(gw) | (!0u32 >> prefix);
            let services: Vec<crate::nopod::ServiceInput> = boxes
                .iter()
                .map(|b| {
                    (
                        b.service_name().to_string(),
                        b.name.clone(),
                        declared_container_ports(b)
                            .iter()
                            .map(|(p, _)| *p)
                            .collect(),
                        b.networks.clone(),
                        b.net_aliases.clone(),
                    )
                })
                .collect();
            let mut plan = crate::nopod::assign_aliases(&services).map_err(Error::Compose)?;
            // The last address of the network is its broadcast and is not usable, so the count is
            // checked against what the network actually holds rather than against the plan's own cap.
            let room = (last - first) as usize;
            if plan.len() > room {
                return Err(Error::Compose(format!(
                    "a --bridge stack on {cidr} can address at most {room} services; this one has {}",
                    plan.len()
                )));
            }
            // THE ADDRESS THE FILE PINNED, WHERE IT PINNED ONE. `ipv4_address:` is the whole reason
            // the bridge uses the file's own subnet: taking the declared address makes the key
            // honoured exactly, and a peer that hard-codes it reaches the service.
            //
            // AN ADDRESS OUTSIDE THIS BRIDGE'S NETWORK IS NOT TAKEN, and the reader is told: it
            // would not be routable here, and putting it on the interface anyway would produce a
            // service that answers nowhere its peers can reach. A file with two subnets lands here.
            //
            // TWO SERVICES ON ONE ADDRESS is the file's own error and is refused: the second would
            // silently take the first's traffic.
            let mut taken: std::collections::HashSet<u32> = std::collections::HashSet::new();
            let mut outside: Vec<String> = Vec::new();
            for (i, a) in plan.iter_mut().enumerate() {
                let pinned = boxes
                    .iter()
                    .find(|b| b.service_name() == a.service)
                    .and_then(|b| b.net_ipv4.first())
                    .and_then(|ip| ip.parse::<std::net::Ipv4Addr>().ok())
                    .map(u32::from)
                    .filter(|v| {
                        let inside = *v >= first && *v < last;
                        if !inside {
                            outside.push(format!(
                                "{} at {}",
                                a.service,
                                std::net::Ipv4Addr::from(*v)
                            ));
                        }
                        inside
                    });
                if let Some(v) = pinned {
                    if !taken.insert(v) {
                        return Err(Error::Compose(format!(
                            "two services are pinned to {} with `ipv4_address:`; only one of them \
                             can answer there",
                            std::net::Ipv4Addr::from(v)
                        )));
                    }
                    a.alias = v;
                } else {
                    a.alias = first + i as u32;
                }
            }
            // A SECOND PASS FOR THE UNPINNED ONES, because the first pass may have handed an
            // allocated address to a service that a LATER service pinned. Without it two services
            // share an address and the file said nothing wrong.
            let mut next = first;
            for a in plan.iter_mut() {
                if taken.contains(&a.alias) {
                    continue;
                }
                while taken.contains(&next) && next < last {
                    next += 1;
                }
                if next >= last {
                    return Err(Error::Compose(format!(
                        "a --bridge stack on {cidr} ran out of addresses for {} services",
                        plan.len()
                    )));
                }
                a.alias = next;
                taken.insert(next);
                next += 1;
            }
            if !outside.is_empty() {
                let shown: Vec<&str> = outside.iter().map(String::as_str).collect();
                eprintln!(
                    "kern: warning: compose: `ipv4_address:` outside the bridge's network {cidr} is \
                     not taken ({}): the address would not be routable here, so the service gets one \
                     from {cidr} and its peers reach it there",
                    crate::compose::name_list(&shown)
                );
            }
            plan
        }
    };

    // Count what will actually be LAUNCHED, not how many services the file has: with drift
    // reconciliation the levels may already have been filtered down to the changed ones, and a
    // header promising more boxes than it starts is the kind of small untruth this codebase avoids.
    let total: usize = levels.iter().map(Vec::len).sum();
    kern_common::progress!(
        "→ bringing up {total} box(es) in {} dependency {}: {}",
        levels.len(),
        if levels.len() == 1 { "level" } else { "levels" },
        levels
            .iter()
            .map(|l| format!("[{}]", l.join(", ")))
            .collect::<Vec<_>>()
            .join(" → ")
    );
    // Bring each dependency LEVEL up CONCURRENTLY - every box in a level is independent (its deps live
    // in earlier levels) - with a barrier before the next level so `depends_on` still holds. Wall-clock
    // becomes Σ-per-LEVEL instead of Σ-per-box: a wide flat stack starts in one shot, not one-by-one.
    let started = std::sync::atomic::AtomicUsize::new(0);
    // Cap concurrent starts so a very WIDE level (100s of independent services) doesn't fork a
    // thundering herd of simultaneous overlay-mount/cgroup/userns setups (and reserve 100s of thread
    // stacks on a small board). A normal stack (≤cap services in a level) runs fully parallel as a
    // single chunk; a huge level is barriered into cap-sized chunks. I/O-bound starts want generous
    // concurrency (kern handles 200 parallel boxes), so cap = 4×CPUs clamped to [8, 32].
    // THE FOREIGN PEERS, READ BEFORE ANY BOX EXISTS, because their names have to be in
    // `/etc/hosts` from the first instruction the workload runs. Our OWN membership cannot be
    // registered yet - a member record whose box is not in the registry is pruned on the next read,
    // by us as much as by anyone - so the two halves of joining a network happen at two different
    // moments, and this is the first: read who is already there.
    //
    // A PEER'S ADDRESS IS STABLE FOR AS LONG AS IT IS ON THE NETWORK, so reading it before our boxes
    // exist is not a race with its owner: it was allocated when that box joined and is released only
    // when it leaves.
    let cross_hosts: std::collections::HashMap<String, Vec<String>> = {
        let mut map: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        if !external_nets.is_empty() {
            let peers = crate::network::peers_of(&external_nets, &pod);
            for b in &boxes {
                if b.external_networks.is_empty() || b.net {
                    // A service on the HOST network resolves what the host resolves; pointing its
                    // peers at a loopback alias would break that, which is the same reason the
                    // intra-stack hosts entries skip it.
                    continue;
                }
                let mut entries: Vec<String> = peers
                    .iter()
                    .filter(|(net, _, _)| b.external_networks.iter().any(|n| n == net))
                    .map(|(_, m, addr)| {
                        format!("{}:{}", m.service, std::net::Ipv4Addr::from(*addr))
                    })
                    .collect();
                entries.sort();
                entries.dedup();
                if !entries.is_empty() {
                    map.insert(b.name.clone(), entries);
                }
            }
        }
        map
    };
    // A SHARED REFERENCE, because the workers below are `move` closures: moving a map into one of
    // them would take it from every other worker and from the join step after the loop. The same
    // shape `address_plan` already uses, and for the same reason.
    let cross_hosts = &cross_hosts;

    let start_cap = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .saturating_mul(4)
        .clamp(8, 32);
    for level in &levels {
        for chunk in level.chunks(start_cap) {
            // One worker per service in this chunk; `thread::scope` joins them ALL (the barrier) before
            // we advance. Each worker runs the exact same start sequence the old serial loop did.
            let results: Vec<Result<(), Error>> = std::thread::scope(|scope| {
                let handles: Vec<_> = chunk
                    .iter()
                    .filter_map(|name| -> Option<_> {
                        // A LEVEL NAMES BOXES THAT ARE IN `boxes`, and this `unwrap` said so by
                        // aborting. `topo_levels` builds the levels FROM `boxes`, so the miss is
                        // unreachable today - which is the shape of a panic that ships. A box that
                        // is not there simply has nothing to start, and the level barrier below
                        // still waits for the ones that are.
                        let b = boxes.iter().find(|b| &b.name == name)?;
                        // `boxes` is no longer captured: it was here only to ask whether some peer
                        // waited on this box's completion, and every box gets the exit key now.
                        // REBOUND AS REFERENCES so the `move` closure borrows instead of taking
                        // ownership: every one of these is read by more than one worker and by the
                        // release loop after them, and a `move` that consumed one would compile only
                        // for the first spawn.
                        let (
                            started,
                            pod,
                            up_token,
                            self_exe,
                            project_dir,
                            address_plan,
                            gates,
                            outbound_for,
                        ) = (
                            &started,
                            &pod,
                            &up_token,
                            &self_exe,
                            &project_dir,
                            &address_plan[..],
                            &gates,
                            &outbound_for,
                        );
                        // `Some(...)`: `filter_map` wants an `Option`, and the `?` above is the
                        // miss. The spawn itself always succeeds.
                        Some(scope.spawn(move || -> Result<(), Error> {
                            // Conditional deps (healthy/completed) live in an earlier, already-started
                            // level; plain `depends_on` is honored by the level barrier itself.
                            //
                            // UNDER THE GATE THIS MOVES TO RELEASE. `service_healthy` asks about a
                            // workload, and under the gate no workload has run yet: waiting here would
                            // block forever on a health that cannot exist, which is the same deadlock
                            // the gate was added to remove, arriving through the other door. The wait
                            // is performed in the release loop, in dependency order, which is where
                            // "start only after the dependency is healthy" actually means something.
                            if !gate_active {
                                wait_for_conditions(b, pod, up_token, wait_timeout)?;
                            }
                            let n = started.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                            let dep = if b.depends_on.is_empty() {
                                String::new()
                            } else {
                                format!(" (after {})", b.depends_on.join(", "))
                            };
                            let src = b
                                .image
                                .as_deref()
                                .or(b.rootfs.as_deref())
                                .unwrap_or("(no source)");
                            kern_common::progress!(
                                "→ [{n}/{total}] starting '{}'  {src}{dep}",
                                b.name
                            );
                            let mut cmd = std::process::Command::new(self_exe);
                            // Anchor the box's relative paths (env_file/-v/rootfs) to the project dir.
                            cmd.current_dir(project_dir);
                            cmd.arg("box").arg(&b.name);
                            // Record the fingerprint WITH the box, so the next `up` can compare.
                            cmd.arg("--def-hash").arg(definition_hash(b));
                            b.push_box_flags(&mut cmd);
                            // DNS FOR A SERVICE THAT WILL GET A NAT, handed over as `--dns` at
                            // launch rather than as a file bound later.
                            //
                            // The pod binds a `resolv.conf` it wrote; a box outside a pod writes its
                            // own from these arguments, which is the mechanism `dns:` already uses.
                            // The CONTENT is the same function in both wirings, so a stack cannot
                            // resolve names differently depending on how it was started.
                            //
                            // Only when the file named none: an explicit `dns:` is the service's
                            // decision and must not be appended to, or a service that pinned one
                            // resolver would quietly get three.
                            if outbound_for.contains(&b.name) && b.dns.is_empty() {
                                for ns in crate::pod::host_nameservers() {
                                    cmd.arg("--dns").arg(ns);
                                }
                            }
                            // A box not on the host net joins the stack pod → reachable by name from peers.
                            //
                            // `network_mode: none` STAYS OUT TOO, for the opposite reason to `host`:
                            // that one already has the host's network, this one asked for none at
                            // all, and a pod would hand it both peers and egress.
                            if use_pod && !b.net && !b.net_none {
                                cmd.arg("--pod").arg(pod);
                                // ON A BRIDGE the box joins the pod's USER namespace and keeps its
                                // OWN network one, taking its address on the bridge. That is what
                                // gives it a `127.0.0.1` no peer can reach.
                                if let Some(cidr) = bridge_cidr {
                                    if let (Some((_, _, prefix)), Some(a)) = (
                                        kern_isolation::pod_bridge_parts(cidr),
                                        address_plan.iter().find(|a| a.service == b.service),
                                    ) {
                                        cmd.arg("--pod-bridge").arg(format!(
                                            "{}/{prefix}",
                                            std::net::Ipv4Addr::from(a.alias)
                                        ));
                                    }
                                }
                            }
                            // Without a pod, the same reachability is spelled out: every peer at its
                            // alias, this box at its own loopback. A box on the host net is skipped -
                            // it already resolves whatever the host resolves, and pointing its name
                            // at a loopback alias would break that.
                            if !b.net {
                                if let Some(entries) = crate::nopod::add_host_args(
                                    address_plan,
                                    &b.service,
                                    bridge_cidr.is_none(),
                                ) {
                                    for e in entries {
                                        cmd.arg("--add-host").arg(e);
                                    }
                                }
                                // `links:` ALIASES, IN EITHER MODE. A box on the host net is skipped
                                // for the same reason as above: it resolves what the host resolves,
                                // and a stack alias pointing at a loopback would break that.
                                for e in
                                    crate::nopod::link_host_args(&b.links, address_plan, use_pod)
                                {
                                    cmd.arg("--add-host").arg(e);
                                }
                            }
                            // AND THE PEERS ON AN `external:` NETWORK, which are services of OTHER
                            // projects. Their addresses are their identity on that network and were
                            // allocated when they joined it, so they are known before this box
                            // exists; the relay that makes each one answer is built below, while
                            // every box is still held at its gate.
                            if !b.net {
                                for e in cross_hosts.get(&b.name).into_iter().flatten() {
                                    cmd.arg("--add-host").arg(e);
                                }
                            }
                            // EVERY box gets the stack+run-scoped exit KEY, and that key is CLEARED
                            // before the spawn. Each box owns a unique one (it carries this `up`'s
                            // token), so concurrent workers never touch each other's.
                            //
                            // IT USED TO BE HANDED OUT ONLY TO A `depends_completed` TARGET, and that
                            // made the settle check below unable to tell success from failure. It asks
                            // `exit_of(key) != Some(0)` to spare a service that finished CLEANLY inside
                            // the window; with no key there is no file, `exit_of` answers `None`, and
                            // the carve-out could never fire for any service that was not some peer's
                            // completion target. MEASURED from a field report on 0.8.5: a one-shot
                            // service running `/bin/echo` and exiting 0 was reported as
                            // "died within 150ms of starting" and `up` exited 1, so a stack with a
                            // migration or a build step failed its CI run by succeeding. The exit code
                            // was already being recorded for `kern wait` under a different key the
                            // whole time; only compose's own key was withheld.
                            let key = exit_key(pod, up_token, &b.name);
                            registry::clear_exit(&key);
                            cmd.env("KERN_EXIT_KEY", &key);
                            // THE GATE PIPE. Both ends are created `CLOEXEC` so no other child of
                            // `up` (a health checker, a relay half, the timeout watchdog) can inherit
                            // the write end and keep the gate from closing when `up` dies. The READ
                            // end has its `CLOEXEC` cleared in the child, between fork and exec, so
                            // it survives into the box and nowhere else - which is why this is done
                            // in `pre_exec` rather than by creating the pipe without `CLOEXEC`: with
                            // concurrent workers a non-`CLOEXEC` read end would leak into every box
                            // started at the same moment.
                            let mut gate_rd: Option<std::os::fd::OwnedFd> = None;
                            // A BOX THAT WILL BE RUN BY SYSTEMD CANNOT BE GATED, AND MUST NOT BE
                            // GIVEN A GATE IT WILL NEVER READ.
                            //
                            // Outside a pod, a service that sets `restart:` is installed as a systemd
                            // unit: this launcher writes the unit and exits, and the box is started
                            // later by the manager, in a process that inherits nothing from here. A
                            // descriptor does not cross that boundary, so the gate's read end dies
                            // with the launcher while `up` still holds the write end and later writes
                            // to it. MEASURED, three runs of three: `EXIT=141` - SIGPIPE, because
                            // `main` sets `SIGPIPE` to `SIG_DFL` on purpose so `kern … | head`
                            // behaves like a Unix tool - and no peer payload delivered.
                            //
                            // The box is therefore left ungated. It starts when the manager starts
                            // it, which is also when it would have started without any of this, so
                            // nothing regresses for it; what it does not get is the guarantee that
                            // its peers' relays exist first. That limit is the manager's, not the
                            // gate's, and it is stated in the note below rather than papered over.
                            //
                            // A POD MEMBER IS NOT THAT CASE. `persistent_supervision` puts every pod
                            // member on the in-process supervisor whatever systemd offers (it needs
                            // the holder's namespace), so the descriptor does cross into the box and
                            // the gate works exactly as it does for any other member. Asking the
                            // question as "does it write `restart:`" instead of "will systemd start
                            // it" is what left every `restart:` service on a bridge with no NAT.
                            let gate_this = gate_active && (use_pod || !b.restart_always);
                            if gate_this {
                                let (rd, wr) = gate_pipe()?;
                                let raw = std::os::fd::AsRawFd::as_raw_fd(&rd);
                                // A RESERVED NUMBER, NOT WHATEVER `pipe2` HANDED OUT. The gate is
                                // read by the box's PID 1, hundreds of setup steps after the fork:
                                // mounts, the pivot, the uid map and the loopback all open and close
                                // descriptors, so the low number `pipe2` returned is long since
                                // recycled by the time it is read. MEASURED: the launcher passed
                                // `fd=3`, PID 1 resolved `gate=Some(3)` correctly, read one byte
                                // from whatever now sat on 3, and released itself instantly - the
                                // workload ran while the relays were still being built, and the
                                // number was right the whole time. `dup2` in the child pins it above
                                // everything kern opens; `shed_inherited_fds_keeping` covers the
                                // range and keeps exactly this one.
                                cmd.env("KERN_GATE_FD", GATE_FD.to_string());
                                // SAFETY: `pre_exec` runs between fork and exec in the child. The
                                // closure calls one async-signal-safe syscall on a descriptor the
                                // child inherited, allocates nothing and takes no lock.
                                unsafe {
                                    std::os::unix::process::CommandExt::pre_exec(
                                        &mut cmd,
                                        move || {
                                            // Pin to the reserved number, then clear CLOEXEC on the
                                            // pinned copy: `dup2` already returns a descriptor
                                            // WITHOUT `FD_CLOEXEC`, but the clear is kept explicit so
                                            // the invariant does not depend on that detail of dup2.
                                            if libc::dup2(raw, GATE_FD) < 0 {
                                                return Err(std::io::Error::last_os_error());
                                            }
                                            if libc::fcntl(GATE_FD, libc::F_SETFD, 0) < 0 {
                                                return Err(std::io::Error::last_os_error());
                                            }
                                            Ok(())
                                        },
                                    )
                                };
                                match gates.lock() {
                                    Ok(mut g) => g.push((b.name.clone(), wr)),
                                    // A poisoned lock means another worker panicked while holding it.
                                    // Dropping `wr` here closes it, the box reads EOF and refuses to
                                    // exec: the stack fails closed rather than starting half gated.
                                    Err(_) => return Err(Error::Compose(
                                        "internal: the pre-exec gate registry was poisoned by a \
                                             failed worker; no box was released"
                                            .to_string(),
                                    )),
                                }
                                // THE READ END STAYS OPEN UNTIL AFTER THE SPAWN. Closing it here
                                // closed the number the child was told to read, and every box failed
                                // with `Bad file descriptor (os error 9)`: `Command` does not
                                // duplicate the descriptor at configuration time, it inherits
                                // whatever is open at fork. It is dropped below, once the child has
                                // it, so the parent does not hold a pipe open for a box that is gone.
                                gate_rd = Some(rd);
                            }
                            cmd.arg("-d");
                            if !b.command.is_empty() {
                                cmd.arg("--").args(&b.command);
                            }
                            let status = cmd
                                .status()
                                .map_err(|e| Error::Compose(format!("starting '{}': {e}", b.name)));
                            // The child has the read end now (or the spawn failed and nobody will).
                            // Either way the parent must not keep it: a live read end in `up` means
                            // the pipe never reaches EOF, so a box whose launcher died would wait
                            // forever instead of refusing.
                            drop(gate_rd);
                            let status = status?;
                            if !status.success() {
                                return Err(Error::Compose(format!(
                                    "box '{}' failed to start",
                                    b.name
                                )));
                            }
                            Ok(())
                        }))
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| {
                        h.join().unwrap_or_else(|_| {
                            Err(Error::Compose("compose worker panicked".into()))
                        })
                    })
                    .collect()
            });
            // Abort the whole `up` on the first failure in this chunk (peers already started stay up,
            // like Docker's partial bring-up).
            for r in results {
                r?;
            }
        }
        // Register this level's pod aliases AFTER the barrier - serial, so the racy /etc/hosts
        // read-modify-write in `add_member` never runs concurrently, and the NEXT level resolves them.
        if use_pod {
            for name in level {
                // Same as above: the level was built from `boxes`, so a miss cannot happen and
                // aborting on it would be the only way it ever could.
                let Some(b) = boxes.iter().find(|b| &b.name == name) else {
                    continue;
                };
                if !b.net {
                    for alias in &b.net_aliases {
                        crate::pod::add_member(&pod, alias)?;
                    }
                }
            }
        }
    }
    // FAIL-CLOSED sul bring-up. Launching a box only proves the launcher returned; a service that
    // dies half a second later (an internal port already taken by a pod peer, a missing binary, a
    // config it reads at startup) left `up` printing "started" and exiting 0 while the stack was
    // already broken. That is the "reports success while losing something" class this codebase
    // refuses everywhere else.
    //
    // We wait for an EVENT, not for a duration: a settle window just long enough to observe an
    // IMMEDIATE failure (failed execve, failed bind, permissions), shared by the whole stack rather
    // than paid per service. A service that dies later is NOT `up`'s business - that is supervision,
    // and stretching this window to catch it would reintroduce the arbitrary wait it avoids.
    //
    // Healthy services are left RUNNING. A stack whose database holds data in a volume must not be
    // torn down because an unrelated service failed; the exit code and the message carry the failure.
    // PEER RELAYS, after the boxes exist and before the death report.
    //
    // They need every box's PID 1, which is recorded by its supervisor, so this cannot run earlier.
    // It runs before the death check so a stack that is up but unreachable is reported as the
    // reachability failure it is, rather than as whatever the first service does when its peer never
    // answers.
    //
    // The holder is a detached process that OWNS the relays: `up` exits, and relays forked here would
    // die with it through their own PDEATHSIG. `down` kills the holder, and every relay goes with it.
    // JOIN EVERY `external:` NETWORK AND WIRE BOTH DIRECTIONS, in the same window: every box of this
    // stack exists and is held at its pre-exec gate, so its PID 1 is recorded and no workload has run.
    //
    // WHY BOTH DIRECTIONS ARE OURS. A relay is two forked halves, each entering only its OWN box, so
    // building one INTO another project's box needs nothing from that project - measured before any
    // of this was written: two stacks brought up separately, a plan naming one box from each, and the
    // box in the second project read the first project's listener through an alias on its own
    // loopback. The other project's holder is never asked to adopt anything, and when this stack
    // goes down its relays go with it, which is right, because what they reached is going away too.
    //
    // MERGED INTO THE STACK'S OWN PLAN rather than given a second holder. One holder per stack is
    // what `down` kills and what heals a box that restarted; a second one would be a process nothing
    // in the teardown path knows about.
    let cross = if external_nets.is_empty()
        || !matches!(
            action,
            ComposeAction::Up | ComposeAction::Start | ComposeAction::Restart
        ) {
        crate::network::CrossPlan::default()
    } else {
        let mine: Vec<crate::network::Joining> = boxes
            .iter()
            .filter(|b| !b.external_networks.is_empty() && !b.net)
            .filter(|b| registry::find(&b.name).is_some())
            .map(|b| crate::network::Joining {
                box_name: b.name.clone(),
                service: b.service_name().to_string(),
                // TCP ONLY, and the same derivation the intra-stack plan uses: a relay carries TCP,
                // so a UDP port would be a peer that resolves and answers nothing. The intra-stack
                // path names those per service; here the set simply does not include them.
                ports: declared_container_ports(b)
                    .into_iter()
                    .filter(|(_, udp)| !*udp)
                    .map(|(p, _)| p)
                    .collect(),
                networks: b.external_networks.clone(),
            })
            .collect();
        crate::network::join_and_plan(&mine, &pod)?
    };
    for net in &cross.alone_on {
        eprintln!(
            "kern: note: compose: this stack is the only project on network '{net}' right \
             now, so there is nothing else to resolve yet. A stack that joins later is \
             wired to these services when it comes up"
        );
    }
    if !cross.foreign_hosts.is_empty() {
        // THE OTHER PROJECT'S BOXES LEARN OUR NAMES, written into the `/etc/hosts` they are already
        // running with. MEASURED: a write through `/proc/<pid1>/root/etc/hosts` is visible inside
        // immediately and `getent hosts` answers the new name on the next call, so no resolver and
        // no restart of the other stack is needed.
        for (box_name, line) in &cross.foreign_hosts {
            if let Err(e) = crate::network::add_foreign_host(box_name, line, &pod) {
                eprintln!(
                    "kern: warning: compose: '{box_name}' could not be told this stack's names                      ({e}); it can be reached from here, and cannot reach back by name"
                );
            }
        }
    }

    if !use_pod && !address_plan.is_empty() || !cross.relays.is_empty() {
        let mut relays = if address_plan.is_empty() || use_pod {
            Vec::new()
        } else {
            crate::nopod::relay_plan(&address_plan)
        };
        relays.extend(cross.relays.iter().cloned());
        if !relays.is_empty() {
            let dir = crate::relayhold::stack_dir(&pod)?;
            let report = crate::relayhold::spawn_holder(&dir, &relays)?;
            // THE NOTE AND THE PAIRS IT PROMISES, TOGETHER. It used to print before the build, and on
            // a stack that builds first that put minutes between a sentence saying a pair would be
            // named and the naming: reported from a real stack where the next line was
            // `building 'sidecar'` and the reader concluded nothing had been named.
            if let Some(note) = no_pod_peer_names_note(&boxes, no_pod) {
                eprintln!("{note}");
            }
            // WITH the pairs, for the same reason they are: this names the services whose bring-up
            // order kern does not control, and it is only actionable next to the relay report.
            if let Some(note) = no_pod_restart_gate_note(&boxes, no_pod) {
                eprintln!("{note}");
            }
            if report.up > 0 {
                // A `kern: note:` and NOT `progress!`, though it opens with the same arrow. Gating it
                // on a terminal was wrong and a test said so: with `--no-pod` the relays ARE the
                // mechanism peers reach each other by, so how many came up is state a reader needs,
                // not narration of a step kern is taking. The prefix keeps it out of a model's context
                // while a pipe still gets it, which is the split the two mechanisms exist to make.
                eprintln!(
                    "kern: note: {} peer relay(s) up: services reach each other by name without a pod",
                    report.up
                );
            }
            // THE BLOCKED PAIRS ARE NAMED BY THE HOLDER, which measured them, rather than guessed at
            // from the file before anything ran. A relay listens on `alias:port` inside the holder,
            // and MEASURED on one port: two specific binds on different addresses do not conflict,
            // while a specific bind and a WILDCARD bind refuse each other in both orders with or
            // without SO_REUSEADDR. So the pair is only lost when the holder binds `0.0.0.0`, which
            // is a fact about a running process and not about a declaration.
            // ITS OWN PREFIX, not `note:`, and that is not cosmetics. A field report: "we had
            // filtered it out of our own output. A message that named the pair would have been hard
            // to filter and harder to misread." They lost a debugging round with the line on screen,
            // because the general note and the named pair shared a prefix and one `grep -v` took
            // both. The note explains a model and can be skipped; this names TWO SERVICES OF YOURS,
            // RIGHT NOW, and is the only actionable half. Follows the `kern: pod:` / `kern: vdisk:`
            // convention already in this tree.
            for line in &report.blocked {
                eprintln!("kern: unreachable: {line}");
            }
        }
    }
    // RELEASE, IN DEPENDENCY ORDER, AFTER EVERY EDGE EXISTS.
    //
    // This is the second half of the pre-exec gate and the reason the first half is worth its cost.
    // Every box above is PREPARED: namespaces, cgroup, mounts, uid map, capability drop, Landlock and
    // seccomp are all done, PID 1 is registered, and the workload has not run. The relay block ran
    // against that, so by the time the first instruction of the first workload executes, every peer
    // alias it can resolve already answers.
    //
    // THE CONDITION WAITS HAPPEN HERE, not in the prepare loop, and the order is the reason. Under
    // the gate no workload has run, so `depends_on: condition: service_healthy` evaluated during
    // preparation would wait for a health that cannot exist - the same deadlock the gate removes,
    // through the other door. Waiting here, level by level, is what "start only after the dependency
    // is healthy" means when "start" is the release.
    //
    // LEVELS, IN ORDER, AND SEQUENTIALLY WITHIN A LEVEL. `topo_levels` already ordered them; a level
    // holds boxes with no dependency on each other, so releasing them one after another costs one
    // write each and needs no worker pool. The cost of a pool here would be paid on every stack to
    // save microseconds on none.
    //
    // A BOX WITH NO GATE IS NOT AN ERROR. `levels` may name a box that was filtered out of this run
    // by reconciliation, and `gates` only holds the ones this `up` prepared. The lookup misses and
    // the loop moves on, which is the same tolerance the prepare loop applies to the same case.
    if gate_active {
        let released = match gates.lock() {
            Ok(g) => g,
            Err(_) => {
                return Err(Error::Compose(
                    "internal: the pre-exec gate registry was poisoned; no box was released"
                        .to_string(),
                ))
            }
        };
        // EVERY NAT, BEFORE ANY RELEASE, AND ALL AT ONCE.
        //
        // OUTBOUND IS ATTACHED WHILE THE BOX IS STILL HELD, and that ordering is the whole
        // correctness argument. pasta configures an interface INSIDE the box's network namespace
        // from outside it; a workload that had already started would observe a namespace with no
        // route one instant and a route the next, which is precisely the half-built network the gate
        // exists to make impossible. Held at the gate, PID 1 has every namespace built, has run no
        // instruction, and its pid cannot be recycled. That held when this ran inside the release
        // loop and it holds harder here: no box in the stack is released until every NAT is up.
        //
        // WHY IT MOVED OUT OF THE LOOP, MEASURED. Attaching a NAT costs about 17 ms: pasta is spawned
        // and daemonizes, and its pidfile is polled for. Done once per service in a loop that is
        // sequential by construction, a stack of eight services spent about 140 ms of its bring-up
        // waiting for eight processes to say they were ready - which after the veth fix below was
        // the ENTIRE remaining cost of the bridge wiring, to the millisecond: eight services on a
        // bridge whose network is `internal: true` and takes no NAT came up in 173 ms against the
        // pod's 171, and with the NATs in 314.
        //
        // THE ATTACHES DO NOT DEPEND ON EACH OTHER: every box is prepared and held before this block
        // runs, so every PID 1 already exists, and each attach writes only into its own service's
        // directory. `depends_on` orders RELEASES, which is the loop below, and never orders the
        // wiring - a dependency waits for its dependency's health, and health needs a workload, and
        // no workload has run yet.
        //
        // THE WARNINGS ARE COLLECTED AND PRINTED IN FILE ORDER rather than as they happen, because
        // the order threads finish in is not a fact about the stack and a reader who ran the same
        // command twice would see the same failures in a different order.
        let mut outbound_warnings: Vec<String> = Vec::new();
        if !outbound_for.is_empty() {
            let attach = |b: &crate::compose::ComposeBox| -> Option<String> {
                let Some(pid1) = registry::find(&b.name).and_then(|i| i.live_pid1()) else {
                    return Some(format!(
                        "kern: warning: service '{}': no outbound - its PID 1 is not recorded yet, \
                         so there was no namespace to attach the NAT to",
                        b.service
                    ));
                };
                // The stack's own directory, which `down` already removes: the NAT's pid file and
                // identity record go with the stack rather than into a second lifetime somebody has
                // to own.
                let dir = match crate::relayhold::stack_dir(&pod) {
                    Ok(d) => d.join("outbound").join(&b.service),
                    Err(e) => {
                        return Some(format!(
                            "kern: warning: service '{}': no outbound - the stack directory is \
                             unavailable ({e})",
                            b.service
                        ))
                    }
                };
                // A FAILURE HERE IS NAMED AND NOT FATAL. The stack without egress is the behaviour
                // `--no-pod` had before this existed, so refusing to start would take away more than
                // the failure did; but a service that cannot reach the internet fails later, inside
                // its own code, where the reason is invisible - so it is said here, once, per box.
                crate::pod::attach_box_outbound(&dir, pid1)
                    .err()
                    .map(|why| {
                        format!(
                        "kern: warning: service '{}': no outbound - {why}. The box starts, and \
                         reaches its peers; it cannot reach the internet",
                        b.service
                    )
                    })
            };
            let subject: Vec<&crate::compose::ComposeBox> = boxes
                .iter()
                .filter(|b| outbound_for.contains(&b.name))
                .filter(|b| released.iter().any(|(n, _)| n == &b.name))
                .collect();
            // ONE THREAD EACH, SCOPED, so nothing outlives this block and no pool has to be owned.
            // A single subject is done inline: a thread to serialise on would be pure overhead, and
            // most stacks that get here have two or three services.
            if subject.len() < 2 {
                outbound_warnings.extend(subject.iter().filter_map(|b| attach(b)));
            } else {
                std::thread::scope(|scope| {
                    let handles: Vec<_> =
                        subject.iter().map(|b| scope.spawn(|| attach(b))).collect();
                    for h in handles {
                        // A PANIC IN ONE ATTACH IS NOT SILENCE. `join` returns `Err` only if the
                        // thread panicked, and swallowing that would turn a bug into a stack with
                        // no egress and no reason given.
                        match h.join() {
                            Ok(Some(w)) => outbound_warnings.push(w),
                            Ok(None) => {}
                            Err(_) => outbound_warnings.push(
                                "kern: warning: a NAT attachment panicked; that service has no \
                                 outbound"
                                    .to_string(),
                            ),
                        }
                    }
                });
            }
        }
        for w in &outbound_warnings {
            eprintln!("{w}");
        }
        for level in &levels {
            for name in level {
                let Some(b) = boxes.iter().find(|b| &b.name == name) else {
                    continue;
                };
                let Some((_, fd)) = released.iter().find(|(n, _)| n == name) else {
                    continue;
                };
                // The wait can fail (a dependency that died, a timeout). Returning here drops
                // `released`, which closes every remaining write end, and every still-prepared box
                // reads EOF and refuses to exec. The stack does not come up half-released.
                // Every NAT was attached above, before this loop, and the ordering argument that
                // used to live here is made there instead.
                wait_for_conditions(b, &pod, &up_token, wait_timeout)?;
                if !gate_release(fd) {
                    return Err(Error::Compose(format!(
                        "service '{}': the box was prepared but could not be released (it is no \
                         longer there) - no other service was released either",
                        b.service
                    )));
                }
            }
        }
    }
    // ONLY WHAT THIS INVOCATION STARTED. `boxes` is the whole file; `levels` is what was launched,
    // after `up web` narrowed it to web and its dependencies. See `settle_and_collect_dead`.
    let started: std::collections::HashSet<&str> =
        levels.iter().flatten().map(String::as_str).collect();
    let mine: Vec<&crate::compose::ComposeBox> = boxes
        .iter()
        .filter(|b| started.contains(b.name.as_str()))
        .collect();
    let dead = settle_and_collect_dead(&mine, &pod, &up_token);
    if !dead.is_empty() {
        // WHY IT DIED, WHEN KERN CAN SEE WHY. A service that binds a port another service in the same
        // network namespace already holds fails with `Address already in use` in its OWN logs, and
        // kern reported only that it "died within 150ms". The reader is then looking at nginx's
        // error with no reason to suspect the stack's wiring, which is the whole cause.
        //
        // MEASURED on Docker's own `nginx-golang` sample: `proxy` (nginx) and `backend` (a Go binary
        // built `FROM scratch`) BOTH bind port 80, and neither declares it anywhere kern can read.
        // Under Docker each service has its own network namespace and both bind it.
        for note in dead_service_port_notes(&dead, &boxes, use_pod, &address_plan) {
            eprintln!("kern: note: {note}");
        }
        return Err(Error::Compose(format!(
            "{} service(s) died within {BRING_UP_SETTLE_MS}ms of starting: {}\n  the rest of the \
             stack is still running; inspect with `kern compose {file} logs <service>`\n  (`up` \
             reports deaths at STARTUP; a service that dies later is not detected yet)",
            dead.len(),
            dead.join(", ")
        )));
    }
    println!("compose up: {total} box(es) started. track with `kern ps`.");
    if use_pod {
        // SAY WHETHER THERE IS EGRESS, not only whether services can find each other. `pod create`
        // distinguishes five outbound states and prints the one you got; this line reported name
        // resolution alone, so a stack with no internet and a stack with internet printed the SAME
        // sentence. On a REUSED pod there is no `create` line above this one, so this was the only
        // thing the operator saw. `DOCKER-COMPAT.md` promised "the bring-up line says which of the
        // two you got" and for compose it did not.
        // The SENTENCE comes from `pod`, not a flag decided here. This read `has_outbound()` and
        // printed "install `passt`/`pasta`" on every false, so a pod whose pasta was installed and
        // refused to start told its owner to install it (#6), two lines under kern's own correct
        // "pasta IS installed but did not start". Five states, one bool, wrong branch.
        // A BRIDGE MEMBER IS NOT IN THE POD'S NAMESPACE, so the pod's outbound is not its outbound.
        // `network_summary` answers about the namespace pasta runs in - the holder's - and printing
        // it here told the operator "services reach each other by name + outbound to the internet
        // (pasta)" about a stack whose members have NO default route at all. MEASURED inside a
        // bridge member of a 56-service stack: `ip route` shows the on-link `10.89.0.0/24` and
        // nothing else, and there is no `/etc/resolv.conf` - pgbouncer died in libevent's
        // `evdns_base_new` because of it. Saying what is true is the least this can do until a
        // member gets a route out.
        let net = if want_bridge {
            "each service has its own namespace and its own 127.0.0.1, meets its peers on the pod's \
             bridge, and reaches the internet through its own NAT (pasta)"
                .to_string()
        } else {
            crate::pod::network_summary(&pod)
        };
        println!("  pod '{pod}': {net}. tear down with `kern compose {file} down`.");
    }
    // ATTACHED `up`. Everything above is unchanged; this is the part `docker compose up` does next.
    // `--wait` BEFORE the attach decision: both spellings of `up` mean the same thing by it, and a
    // CI job that asked to wait must have waited by the time this call returns either way.
    if wait_ready {
        wait_until_ready(&mine, wait_timeout)?;
    }
    // `--abort-on-container-exit` / `--exit-code-from` take over from here: they wait for an exit
    // rather than returning, and they tear the stack down themselves, so neither `--wait` nor the
    // attach below has anything left to do.
    if abort_on_exit {
        return watch_and_abort(&mine, &boxes, &pod, exit_code_from);
    }
    if !detach {
        if should_attach(detach, unsafe { libc::isatty(1) } == 1) {
            return attach_to_stack(&mine, &boxes, &pod, file);
        }
        // THE SPLIT IS ANNOUNCED, because a command with two behaviours decided by a property of
        // the caller is exactly the shape this codebase refuses to leave silent. Docker attaches
        // either way (measured on 29.6.2: `timeout 5 sh -c 'docker compose up 2>&1 | cat'` exits
        // 124, and so does a plain redirect and a run with stdin closed; only `-d` exits 0), so
        // this line is where kern says it did something else and why the reader may not have
        // noticed.
        eprintln!(
            "kern: note: stdout is not a terminal, so `up` returned instead of streaming the \
             stack. `-d` says so explicitly; on a terminal it follows the logs and Ctrl-C stops \
             the stack, as `docker compose up` does."
        );
    }
    Ok(())
}

/// `compose run [--rm] [--no-deps] <service> [command…]`: a one-off box from a service definition.
///
/// THE VERB TWO INDEPENDENT REVIEWERS BOTH PUT FIRST. It is step 2 of nearly every project README
/// (`run --rm web python manage.py migrate`, `run --rm app npm test`, `run --rm db psql`), and
/// nothing kern had could stand in for it: the service's environment, volumes, working directory,
/// user and network, with a different command, once.
///
/// THE DEPENDENCIES ARE BROUGHT UP BY RE-INVOKING THIS BINARY, not by a second copy of the ordering
/// rules. `up -d <deps>` already expands the graph, waits on `service_healthy`, honours profiles and
/// creates the pod; a `run` that reimplemented any of that would drift from it on the first change.
/// The cost is one process, which is what every service in a stack already costs.
///
/// PORTS ARE NOT PUBLISHED, which is Docker's rule and not tidiness: the service's own box may be
/// running and holding those host ports, so publishing them would make `run` fail with a bind
/// conflict against the very stack it is meant to join.
///
/// THE EXIT CODE IS THE COMMAND'S. `run --rm web sh -c 'exit 7'` exits 7 under Docker (measured on
/// 29.6.2) and here, through [`Error::Workload`], so a CI job can tell a failing test suite from a
/// failing runtime.
#[allow(clippy::too_many_arguments)]
fn compose_run(
    boxes: &mut [crate::compose::ComposeBox],
    pod: &str,
    file: &str,
    selected: &[String],
    cmd: &[String],
    rm: bool,
    no_deps: bool,
    self_exe: &std::path::Path,
    project_dir: &std::path::Path,
) -> Result<(), Error> {
    let Some(target) = selected.first() else {
        return Err(Error::Compose(format!(
            "run needs a service: `kern compose {file} run <service> [command…]`"
        )));
    };
    let Some(idx) = boxes.iter().position(|b| &b.name == target) else {
        return Err(Error::Compose(format!(
            "run: no service '{target}' in {file}"
        )));
    };

    // 1. THE DEPENDENCIES, through `up` itself.
    let deps: Vec<String> = boxes
        .get(idx)
        .map(|b| b.depends_on.clone())
        .unwrap_or_default();
    if !no_deps && !deps.is_empty() {
        // The names as the FILE writes them: `up` maps its own selectors onto box names, and
        // `depends_on` holds file names.
        let mut up = std::process::Command::new(self_exe);
        up.current_dir(project_dir);
        up.arg("compose").arg(file).arg("up").arg("-d");
        for d in &deps {
            up.arg(d);
        }
        let st = up
            .status()
            .map_err(|e| Error::Compose(format!("run: starting dependencies: {e}")))?;
        if !st.success() {
            return Err(Error::Compose(format!(
                "run: the dependencies of '{}' did not come up",
                boxes.get(idx).map_or(target.as_str(), |b| b.service_name())
            )));
        }
    }

    // 2. THE ONE-OFF BOX. A distinct name, because the service's own box may be running and box
    // names are global. Docker's is `<project>-<service>-run-<hash>`; this is the same idea with the
    // pid, which is unique among live boxes by construction.
    let Some(b) = boxes.get_mut(idx) else {
        return Err(Error::Compose("run: the service disappeared".to_string()));
    };
    let one_off = format!("{}-run-{}", b.name, std::process::id());
    // See the doc: published ports belong to the service's own box, not to a one-off beside it.
    b.ports.clear();
    b.expose.clear();
    let mut c = std::process::Command::new(self_exe);
    c.current_dir(project_dir);
    c.arg("box").arg(&one_off);
    b.push_box_flags(&mut c);
    // Join the stack's pod when there IS one, so the one-off reaches `db` by name exactly as the
    // service would. There is none when the stack was never started and the target has no
    // dependencies, and then a one-off with no peers needs no network of its own.
    if crate::pod::holder_pid(pod).is_some() {
        c.arg("--pod").arg(pod);
    }
    // The command: what was typed, or the service's own when nothing was.
    let argv: &[String] = if cmd.is_empty() { &b.command } else { cmd };
    if !argv.is_empty() {
        c.arg("--");
        for a in argv {
            c.arg(a);
        }
    }
    // FOREGROUND, stdio inherited: this is an interactive one-off and its output is the point.
    let st = c
        .status()
        .map_err(|e| Error::Compose(format!("run: launching '{one_off}': {e}")))?;
    if rm {
        // Best effort, and after the fact: a foreground box leaves no running entry, so this only
        // reaps an exit record the run may have left. Never fails the command, whose status is the
        // workload's.
        crate::registry::clear_waitexit_pod(pod, std::slice::from_ref(&one_off));
    }
    match st.code() {
        Some(0) | None => Ok(()),
        Some(code) => Err(Error::Workload(code)),
    }
}

/// `--abort-on-container-exit` / `--exit-code-from S`: tear the stack down when a service exits,
/// and adopt a status.
///
/// THE CI LINE THIS EXISTS FOR is `up --exit-code-from tests`, which turns a test service's status
/// into the job's. MEASURED on Docker 29.6.2, three cases, all reproduced here:
///
///  * `--exit-code-from tests` with `tests` exiting 3: exit 3, and NO container left running.
///  * `--abort-on-container-exit` alone, same file: exit 3. The service that ended decides.
///  * `--exit-code-from db`, where `db` never exits on its own and `tests` exits 3: exit **137**.
///    The abort is what ended `db`, and 137 is what the abort left behind. The flag reports the
///    NAMED service's status, not the one that triggered the teardown.
///
/// A name the file does not define is refused, as Docker refuses it ("no such service").
///
/// THE LOGS ARE STREAMED while it waits, through the same multiplexer `up` attaches with, stopped
/// at the FIRST exit rather than the last. Streaming here cannot hang a script the way a plain
/// attached `up` could: this loop ends when a service exits, which is the flag's whole contract.
fn watch_and_abort(
    mine: &[&crate::compose::ComposeBox],
    all: &[crate::compose::ComposeBox],
    pod: &str,
    exit_code_from: Option<&str>,
) -> Result<(), Error> {
    // The named service must be one of the ones this invocation started.
    let named: Option<&crate::compose::ComposeBox> = match exit_code_from {
        Some(s) => {
            let found = mine
                .iter()
                .find(|b| b.service_name() == s || b.name == s)
                .copied();
            if found.is_none() {
                return Err(Error::Compose(format!(
                    "no such service: {s}. `--exit-code-from` names a service this `up` started: {}",
                    mine.iter()
                        .map(|b| b.service_name())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
            found
        }
        None => None,
    };

    // Stream until the first service ends. A service that has already gone contributes its log and
    // ends the follow on the first pass.
    let mut who = Vec::with_capacity(mine.len());
    for b in mine {
        let Some(ins) = registry::find_ref(&b.name) else {
            continue;
        };
        match crate::commands::Followed::open(
            b.service_name().to_string(),
            b.name.clone(),
            ins.pid,
            None,
        ) {
            Ok(Some(f)) => who.push(f),
            Ok(None) => {}
            Err(e) => eprintln!("kern: warning: {}: {e}", b.service_name()),
        }
    }
    if who.is_empty() {
        // NO LOG TO FOLLOW IS NOT A REASON TO ABORT AT ONCE. Every box could have been launched in
        // a way that left no log file, and tearing the stack down on the first pass would report a
        // status for a service that had not run. Poll the registry instead, which is the same
        // observable `follow_many` uses to decide a service is done.
        while mine
            .iter()
            .all(|b| crate::registry::find_ref(&b.name).is_some())
        {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    } else {
        crate::commands::follow_many(who, &crate::commands::FOLLOW_FOREVER, true)?;
    }

    // Whoever is gone now is who ended it. Read BEFORE the teardown, or every service looks exited.
    let first_gone: Option<String> = mine
        .iter()
        .find(|b| registry::find_ref(&b.name).is_none())
        .map(|b| b.name.clone());

    println!("compose up: a service exited, stopping the stack");
    let selected: Vec<String> = mine.iter().map(|b| b.name.clone()).collect();
    // KEEPING THE EXIT RECORDS, because the status being adopted may be one this very teardown is
    // about to produce: `--exit-code-from db`, where `db` never exits on its own, reports the 137
    // the stop leaves behind. Reaping inside the teardown made every one of these exit 0.
    let ((stopped, _pod_existed), names) =
        crate::commands::tear_down_stack_keeping(all, &selected, pod, false);
    println!("compose down: {stopped} box(es) stopped");

    // The status: the NAMED service's if one was named (137 when the teardown is what ended it),
    // otherwise the one that exited first.
    let want = named.map(|b| b.name.clone()).or(first_gone);
    let code = want.as_ref().and_then(|w| {
        crate::registry::list_exited()
            .into_iter()
            .find(|e| &e.name == w)
            .map(|e| e.code)
    });
    // The reap the teardown did not do. After this the stack is as `down` leaves it, so
    // `compose ps -a` is empty either way.
    crate::registry::clear_waitexit_pod(pod, &names);
    match code {
        Some(0) | None => Ok(()),
        Some(c) => Err(Error::Workload(c)),
    }
}

/// `--wait`: hold until every service this invocation started is ready, or say which one is not.
///
/// THE FOUR RULES ARE DOCKER'S, MEASURED on 29.6.2 rather than read off the documentation:
///
///  * a service WITH a healthcheck must reach `healthy`. One whose check flips at 6 s returned at
///    7 s with status 0.
///  * a service WITHOUT a healthcheck only has to be RUNNING: that case returned in 1 second.
///  * a service that has already EXITED fails the wait, even with status 0 (measured: `command:
///    ["true"]` and no healthcheck exits 1 after a second). "Ready" means still there, and a
///    one-shot that finished is not something a CI job can run against.
///  * `--wait-timeout 8` on a check that never passes exits 1 after 8 seconds.
///
/// The default bound is kern's own condition timeout, the same one `depends_on: service_healthy`
/// already waits under, so a stack cannot wait longer here than it would there. Docker's default is
/// unbounded; a CLI that hangs forever is the one shape this cannot take.
fn wait_until_ready(
    mine: &[&crate::compose::ComposeBox],
    timeout: Option<u64>,
) -> Result<(), Error> {
    use std::time::{Duration, Instant};
    let limit = timeout.unwrap_or(crate::commands::COMPOSE_CONDITION_TIMEOUT_SECS);
    let deadline = Instant::now() + Duration::from_secs(limit);
    for b in mine {
        let has_check = b.health_cmd.is_some() || !b.health_argv.is_empty();
        loop {
            // ORDER MATTERS: a box that is gone can still have a stale `healthy` sidecar from the
            // seconds before it exited, so liveness is read FIRST and decides.
            let alive = registry::find_ref(&b.name).is_some();
            if !alive {
                return Err(Error::Compose(format!(
                    "--wait: service '{}' is not running. A service that has exited is not ready, \
                     which is Docker's reading too: `up --wait` on a service whose command simply \
                     finished exits non-zero there as well.",
                    b.service_name()
                )));
            }
            if !has_check {
                break; // running is the whole requirement
            }
            match crate::commands::current_health(&b.name).as_str() {
                "healthy" => break,
                "unhealthy" => {
                    return Err(Error::Compose(format!(
                        "--wait: service '{}' is unhealthy. Its own check is failing; \
                         `kern compose <file> logs {}` has what it printed.",
                        b.service_name(),
                        b.service_name()
                    )));
                }
                _ => {}
            }
            if Instant::now() >= deadline {
                return Err(Error::Compose(format!(
                    "--wait: service '{}' did not become healthy within {limit}s (its check has \
                     not reported yet). Raise the bound with `--wait-timeout N`.",
                    b.service_name()
                )));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    println!("compose up: {} service(s) ready", mine.len());
    Ok(())
}

/// Does this `up` stream the stack, or return as soon as it is up?
///
/// A FUNCTION AND NOT AN INLINE `&&`, so the polarity is testable. Getting it backwards is a defect
/// with no visible symptom on the machine that writes it: an interactive `up` that returns looks
/// like the old behaviour, and a piped `up` that attaches hangs somebody else's script.
///
/// WHERE THIS DEVIATES FROM DOCKER, MEASURED rather than assumed. `docker compose up` attaches
/// whatever stdout is: on Docker 29.6.2, `timeout 5 sh -c 'docker compose up 2>&1 | cat'` exits
/// 124, a plain `> file` redirect exits 124, stdin closed exits 124, and only `-d` exits 0. kern
/// returns on a pipe, and says so on stderr.
///
/// THE REASON IS KERN'S OWN CONTRACT WITH SYSTEMD. `kern compose <file> systemd` emits a unit that
/// is `Type=oneshot` + `RemainAfterExit=yes`, which requires `up` to EXIT: a unit whose `ExecStart`
/// blocked would sit in `activating` until `TimeoutStartSec` and then fail, taking every deployed
/// stack with it. Docker's equivalent unit writes `-d` or uses `Type=simple`. The generated unit now
/// writes `-d` explicitly, so it no longer depends on this decision at all, and the deviation is
/// recorded in docs/RUNTIME-PARITY.md.
fn should_attach(detach: bool, stdout_is_tty: bool) -> bool {
    !detach && stdout_is_tty
}

/// Stream a just-started stack until it exits or Ctrl-C, then tear it down: `docker compose up`
/// without `-d`.
///
/// WHY A TERMINAL IS THE CONDITION, and why it is not a heuristic dressed up as one: the follow ends
/// only when every service exits or a signal arrives, so a caller that cannot send Ctrl-C would hang
/// forever. Every non-interactive caller kern already has - CI scripts, systemd units, the SDK,
/// `getkern.dev`'s own unit - reaches this code with a pipe or a file on fd 1 and keeps the exact
/// behaviour it had before. `-d` is the explicit form and works either way.
///
/// CTRL-C STOPS THE STACK, as it does under Docker, rather than detaching. Leaving it running would
/// strand a stack whose owner believes they cancelled it, and the next `up` would then fail on a box
/// name that is already taken. `kern attach` keeps the opposite meaning for a single box and says so
/// in its own message; the two are different verbs and each states which it is.
///
/// The teardown is `compose down`'s, through the shared [`tear_down_stack`], restricted to what THIS
/// invocation started - an `up web` that pulled in `db` stops both and nothing else.
fn attach_to_stack(
    mine: &[&crate::compose::ComposeBox],
    all: &[crate::compose::ComposeBox],
    pod: &str,
    file: &str,
) -> Result<(), Error> {
    let mut who = Vec::with_capacity(mine.len());
    for b in mine {
        // A service that exited during the settle window has no live pid to follow. It is not an
        // error: `settle_and_collect_dead` has already reported any death, and the rest of the
        // stack must still be followable.
        let Some(ins) = registry::find_ref(&b.name) else {
            continue;
        };
        // `None` replays the log from its start: the box was launched seconds ago, so this is
        // everything it has printed, which is what an attached `up` shows under Docker.
        match crate::commands::Followed::open(
            b.service_name().to_string(),
            b.name.clone(),
            ins.pid,
            None,
        ) {
            Ok(Some(f)) => who.push(f),
            Ok(None) => {}
            Err(e) => eprintln!("kern: warning: {}: {e}", b.service_name()),
        }
    }
    if who.is_empty() {
        return Ok(());
    }
    // The handler is armed AFTER the stack is up, so a Ctrl-C during bring-up keeps its default
    // disposition and kills this process without a half-built stack to tear down.
    let stop = crate::commands::arm_follow_interrupt();
    eprintln!(
        "kern: attached to {} service(s) - Ctrl-C stops the stack (`-d` returns instead)",
        who.len()
    );
    crate::commands::follow_many(who, stop, false)?;
    if !stop.load(std::sync::atomic::Ordering::Acquire) {
        // Every service exited on its own. Docker leaves the containers in place and returns 0; so
        // does kern, and `compose ps -a` still shows them.
        println!("compose up: every service exited. tear down with `kern compose {file} down`.");
        return Ok(());
    }
    println!("\ncompose up: stopping the stack");
    let selected: Vec<String> = mine.iter().map(|b| b.name.clone()).collect();
    let (stopped, pod_existed) = crate::commands::tear_down_stack(all, &selected, pod);
    if pod_existed {
        println!("compose down: {stopped} box(es) stopped, pod '{pod}' removed");
    } else {
        println!("compose down: {stopped} box(es) stopped");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose::ComposeBox;

    /// THE FOUR CASES OF THE ATTACH DECISION, because three of them are wrong in a way nobody on
    /// the machine that wrote them would notice.
    ///
    /// The one that costs the most is `(false, false)`: a piped `up` that attached would hang every
    /// script, and the unit `kern compose <file> systemd` emits is `Type=oneshot` +
    /// `RemainAfterExit=yes`, so it would sit in `activating` until `TimeoutStartSec` and fail.
    #[test]
    fn up_streams_on_a_terminal_and_returns_everywhere_else() {
        assert!(should_attach(false, true), "a bare `up` on a tty streams");
        assert!(
            !should_attach(false, false),
            "a bare `up` on a pipe must RETURN: a systemd unit is `oneshot` and needs the exit"
        );
        assert!(!should_attach(true, true), "`-d` wins on a tty");
        assert!(!should_attach(true, false), "`-d` wins on a pipe");
    }

    /// THE GENERATED UNIT DOES NOT DEPEND ON A DEFAULT. It is `Type=oneshot` + `RemainAfterExit`,
    /// which requires `up` to exit; written without `-d` it was one behaviour change away from
    /// hanging in `activating`, and that change was made in this same session.
    #[test]
    fn the_systemd_unit_asks_for_detach_explicitly() {
        let unit = crate::systemd::render_unit(&crate::systemd::UnitSpec {
            kern_bin: "/usr/local/bin/kern",
            compose_file: "/srv/app/compose.yaml",
            workdir: "/srv/app",
            project: "app",
            scope: crate::systemd::UnitScope::User,
        })
        .expect("the unit renders");
        assert!(
            unit.contains("compose") && unit.contains("up -d"),
            "ExecStart must spell `-d`, not rely on the default: {unit}"
        );
        assert!(
            unit.contains("Type=oneshot") && unit.contains("RemainAfterExit=yes"),
            "and the unit shape that REQUIRES the exit must still be the one asserted: {unit}"
        );
    }

    /// THE OVERRIDE FILE IS FOUND, and only where Docker finds one.
    ///
    /// MEASURED on Docker 29.6.2: `docker compose` (no `-f`) in a directory holding
    /// `docker-compose.yml` + `docker-compose.override.yml` merged both - the override's `command`,
    /// its extra port and its `environment` keys were all in `config`. kern loaded only the base and
    /// said nothing, so a project's dev overrides vanished in silence.
    ///
    /// The `COMPOSE_FILE` condition is NOT asserted here on purpose: it reads a process-wide
    /// environment variable, and these tests share one process with tests that read the same
    /// environment. Asserting it would mean mutating global state under a thread pool.
    #[test]
    fn the_default_override_is_discovered_beside_a_default_named_file() {
        let root = std::env::temp_dir().join(format!("kern-ovr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch dir");
        let write = |n: &str| {
            let p = root.join(n);
            std::fs::write(&p, "services: {}\n").expect("fixture");
            p.to_string_lossy().to_string()
        };
        let base = write("docker-compose.yml");
        let over = write("docker-compose.override.yml");

        assert_eq!(
            default_override_for(std::slice::from_ref(&base)).as_deref(),
            Some(over.as_str()),
            "a default-named file must pick up its sibling override, as `docker compose` does"
        );

        // Two files are already an explicit list; Docker adds nothing to one.
        assert_eq!(default_override_for(&[base.clone(), over]), None);

        // A file Docker would not have found without `-f` gets no override either.
        let odd = write("ci.yml");
        assert_eq!(default_override_for(&[odd]), None);

        // POSITIVE CONTROL: with the override removed, the same base file discovers nothing. Without
        // this the first assertion could pass on a function that returns a path it never checked.
        std::fs::remove_file(root.join("docker-compose.override.yml")).expect("removable");
        assert_eq!(
            default_override_for(std::slice::from_ref(&base)),
            None,
            "no override file, no override"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// THE READER IS TOLD WHY A SERVICE DIED, WHEN KERN CAN SEE WHY, and the two wirings need two
    /// different sentences because they fail for mirror reasons.
    ///
    /// MEASURED on Docker's own `nginx-golang`: `proxy` (nginx) and `backend` (a Go binary built
    /// `FROM scratch`) both bind port 80 and NEITHER declares it anywhere kern can read. In one
    /// shared namespace the second one to try cannot bind. Without a pod the mirror happens: kern
    /// binds port 80 inside `backend` to serve `proxy`'s alias, and `backend`'s own bind on
    /// `0.0.0.0:80` then fails, so the service kern killed is the one that declared nothing. Its own
    /// ports say nothing, and the relay plan says everything.
    #[test]
    fn a_service_that_died_on_a_port_is_told_which_port_and_which_wiring_took_it() {
        let plan = crate::nopod::assign_aliases(&[
            ("proxy".into(), "p-proxy".into(), vec![80], vec![], vec![]),
            ("backend".into(), "p-backend".into(), vec![], vec![], vec![]),
        ])
        .expect("a two-service plan");
        let mut boxes = crate::compose::parse(
            "services:\n  proxy:\n    image: nginx\n    ports: [\"80:80\"]\n  \
             backend:\n    image: alpine\n",
        )
        .expect("parses");
        for b in &mut boxes {
            b.service = b.name.clone();
            b.name = format!("p-{}", b.service);
        }

        // WITHOUT A POD: the dead service declared nothing, and the sentence still names the port,
        // because it comes from what kern bound rather than from the file.
        let notes = dead_service_port_notes(&["backend".into()], &boxes, false, &plan);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("port(s) 80"), "{}", notes[0]);
        assert!(notes[0].contains("peer's alias"), "{}", notes[0]);

        // THE CONTROL: a service kern bound nothing in gets no sentence, so the one above is about
        // the relay and not about dying.
        assert!(dead_service_port_notes(&["proxy".into()], &boxes, false, &plan).is_empty());

        // IN A POD the relay does not exist, so that sentence must not be said at all. The pod arm
        // needs a live member's socket table, which a unit test has no way to stand up; what is
        // asserted here is that the wrong sentence is never printed for the wrong wiring.
        let pod_notes = dead_service_port_notes(&["backend".into()], &boxes, true, &plan);
        assert!(
            pod_notes.iter().all(|n| !n.contains("peer's alias")),
            "{pod_notes:?}"
        );
    }

    /// `external: true` on a missing volume is a REFUSAL, and the existence test is injected so the
    /// decision can be asserted without creating volumes on the machine running the suite.
    #[test]
    fn a_missing_external_volume_is_refused_and_a_present_one_is_not() {
        let mut db = ComposeBox {
            name: "db".into(),
            external_volumes: vec!["pgdata".into()],
            ..Default::default()
        };
        // Present: kern must say nothing. This is the arm a mutation that inverts the filter breaks.
        assert_eq!(
            missing_external_volumes(std::slice::from_ref(&db), |_| true),
            None
        );
        // Absent: refused, naming the volume and the way out.
        let msg = missing_external_volumes(std::slice::from_ref(&db), |_| false)
            .expect("a missing external volume must be refused");
        assert!(msg.contains("pgdata"), "must name the volume: {msg}");
        assert!(
            msg.contains("kern volume create"),
            "must give the way out: {msg}"
        );
        assert!(
            msg.contains("this volume") && msg.contains("does not exist"),
            "singular for one: {msg}"
        );

        // A volume with no `external:` declaration reaches this at all only through that field, so a
        // stack that declares none is never refused however many volumes it mounts.
        db.external_volumes.clear();
        assert_eq!(missing_external_volumes(&[db], |_| false), None);
        assert_eq!(missing_external_volumes(&[], |_| false), None);

        // ONE VOLUME MOUNTED BY THREE SERVICES IS ONE PROBLEM. Naming it three times reads as three.
        let shared: Vec<ComposeBox> = ["a", "b", "c"]
            .iter()
            .map(|n| ComposeBox {
                name: (*n).to_string(),
                external_volumes: vec!["shared".into()],
                ..Default::default()
            })
            .collect();
        let msg = missing_external_volumes(&shared, |_| false).expect("still missing");
        assert_eq!(msg.matches("shared").count(), 1, "said once: {msg}");
        assert!(msg.contains("this volume"), "one volume, singular: {msg}");

        // Two distinct volumes: plural, sorted, both named.
        let two = vec![
            ComposeBox {
                name: "a".into(),
                external_volumes: vec!["zeta".into()],
                ..Default::default()
            },
            ComposeBox {
                name: "b".into(),
                external_volumes: vec!["alpha".into()],
                ..Default::default()
            },
        ];
        let msg = missing_external_volumes(&two, |_| false).expect("both missing");
        assert!(msg.contains("alpha, zeta"), "sorted and both: {msg}");
        assert!(msg.contains("these volumes"), "plural for two: {msg}");

        // The test is a MIXTURE, not "all present" or "all absent": only the absent one is named.
        let msg = missing_external_volumes(&two, |n| n == "zeta").expect("one still missing");
        assert!(msg.contains("alpha") && !msg.contains("zeta"), "{msg}");
    }

    /// THE CEILING IS A CEILING, and the truth table is the behaviour.
    ///
    /// A Docker container with no `mem_limit:` is bounded by the machine and nothing else; kern used
    /// to hand such a service `kern box`'s 512 MiB, so it died at a number written nowhere in the
    /// file. The default now matches Docker's bound, and `[kern] compose_memory_max` is the strict
    /// posture - as a CEILING, because a limit a downloaded file can raise by writing a bigger
    /// number is not a limit. Asserted here rather than at the call site for `internal_note`'s
    /// reason: a decision taken inline can be asserted by nothing.
    #[test]
    fn the_memory_ceiling_caps_a_bigger_request_and_never_raises_a_smaller_one() {
        const MIB: u64 = 1024 * 1024;
        let cap = |asked, ceiling, ram| crate::commands::service_memory_cap(asked, ceiling, ram);

        // NOTHING WRITTEN ANYWHERE: the machine's RAM, which is Docker's bound.
        assert_eq!(
            cap(None, None, Some(64 * MIB)),
            Some((64 * MIB).to_string())
        );
        // ...and when `/proc/meminfo` cannot be read, no flag at all: the box keeps its own default,
        // which is exactly what kern did before, so an unreadable host never fails in a NEW way.
        assert_eq!(cap(None, None, None), None);

        // THE OPERATOR'S CEILING BEATS THE MACHINE, and applies to a service that asked for nothing.
        assert_eq!(
            cap(None, Some(512 * MIB), Some(64 * MIB)),
            Some((512 * MIB).to_string())
        );

        // THE FILE ASKED AND THERE IS NO CEILING: forwarded verbatim, units and all.
        assert_eq!(cap(Some("256m"), None, Some(64 * MIB)), Some("256m".into()));

        // A BIGGER REQUEST IS CAPPED. This is the arm that makes the key a policy.
        assert_eq!(
            cap(Some("8g"), Some(512 * MIB), None),
            Some((512 * MIB).to_string())
        );
        // A SMALLER ONE IS LEFT ALONE: asking for less than the operator allows is allowed, and
        // raising it to the ceiling would hand a service memory its own file refused.
        assert_eq!(
            cap(Some("128m"), Some(512 * MIB), None),
            Some((128 * MIB).to_string())
        );

        // AN UNPARSEABLE `mem_limit:` IS FORWARDED, NOT SWALLOWED. Substituting the ceiling would
        // start the service on a limit nobody wrote; forwarded, the box's flag parser names it.
        assert_eq!(
            cap(Some("512 gigs"), Some(512 * MIB), None),
            Some("512 gigs".into())
        );
    }

    /// `"32m"` AND `"33554432"` ARE THE SAME LIMIT, and the first version of the caller compared the
    /// TEXT. Every service in a stack was then reported as capped the moment a ceiling existed,
    /// including ones already well under it, which sends an operator looking for a limit that was
    /// never applied. MEASURED before the fix: `mem_limit: 32m` under a 64 MiB ceiling was named.
    #[test]
    fn a_service_is_named_as_capped_only_when_the_number_actually_fell() {
        let moved = crate::commands::ceiling_moved;
        // Same value, different spelling: NOT a move.
        assert!(!moved(Some("32m"), &Some("33554432".into())));
        assert!(!moved(Some("512m"), &Some("512m".into())));
        // The ceiling brought it down: a move.
        assert!(moved(Some("8g"), &Some("67108864".into())));
        // The file wrote nothing, so the ceiling decided the number. It would otherwise have had the
        // host's RAM, so this is a move and is worth naming.
        assert!(moved(None, &Some("67108864".into())));
        // Nothing to apply at all: no move, and nothing to say.
        assert!(!moved(Some("32m"), &None));
        assert!(!moved(None, &None));
        // Never counted as a move UPWARDS: a ceiling only lowers, and a report of a raise would be
        // describing something the policy cannot do.
        assert!(!moved(Some("32m"), &Some("67108864".into())));
    }

    /// A CONFIG THAT WILL NOT LOAD MUST NOT WIDEN A LIMIT.
    ///
    /// The two wrong answers are not symmetric: falling back to the historic 512 MiB costs a service
    /// that needed more an error naming a cap, while falling through to "no ceiling" hands every
    /// stack on the machine the whole of its RAM because of a typo in `kern.toml`, silently. The
    /// same asymmetry `publish_policy` is built on, and the same one this project has already been
    /// bitten by once (that first version answered `None` on any config error and widened every
    /// published port to `0.0.0.0`).
    #[test]
    fn a_config_that_will_not_load_falls_back_to_the_box_default_and_never_to_no_ceiling() {
        let ceiling = crate::commands::compose_memory_ceiling;
        assert_eq!(
            ceiling(Err(())),
            Some(kern_isolation::DEFAULT_MEMORY_MAX),
            "a config that will not load must NOT leave the stack uncapped"
        );
        // The key absent is the shipped behaviour: no ceiling, so the host's RAM decides.
        assert_eq!(ceiling(Ok(None)), None);
        assert_eq!(ceiling(Ok(Some("64m"))), Some(64 * 1024 * 1024));
        // A value the config parser would have refused cannot reach here through the shipped path,
        // and if it did it must NOT read as "no ceiling": that is the fail-open shape again, one
        // layer down. It falls back to the same historic default an unloadable config does.
        assert_eq!(
            ceiling(Ok(Some("banane"))),
            Some(kern_isolation::DEFAULT_MEMORY_MAX)
        );
    }

    /// THE WHOLE POLICY IN ONE PLACE: what each service ends up with AND who gets named for it.
    ///
    /// Applied and reported were two loops apart before this was extracted, which is how a service
    /// came to be named as capped without its number changing.
    #[test]
    fn the_policy_caps_each_service_and_names_only_the_ones_it_moved() {
        const MIB: u64 = 1024 * 1024;
        let svc = |name: &str, mem: Option<&str>| ComposeBox {
            name: name.to_string(),
            service: name.to_string(),
            memory: mem.map(str::to_string),
            ..Default::default()
        };

        // NO CEILING: every service gets the host's RAM unless its file named a limit, and nothing
        // is reported, because kern then does what Docker does.
        let mut b = vec![svc("free", None), svc("asked", Some("256m"))];
        assert_eq!(
            apply_memory_policy(&mut b, (None, Some(64 * MIB)), None),
            None
        );
        assert_eq!(b[0].memory.as_deref(), Some("67108864"));
        assert_eq!(b[1].memory.as_deref(), Some("256m"), "verbatim");

        // A CEILING: it decides for the service that asked nothing, caps the one that asked for
        // more, and leaves the one that asked for less exactly where it was.
        let mut b = vec![
            svc("free", None),
            svc("big", Some("8g")),
            svc("small", Some("32m")),
        ];
        let note = apply_memory_policy(&mut b, (Some(64 * MIB), Some(999 * MIB)), None)
            .expect("a ceiling that moved two services owes a sentence");
        assert_eq!(b[0].memory.as_deref(), Some("67108864"));
        assert_eq!(b[1].memory.as_deref(), Some("67108864"));
        assert_eq!(b[2].memory.as_deref(), Some("33554432"), "never raised");
        assert!(note.contains("free, big"), "names the two it moved: {note}");
        assert!(
            !note.contains("small"),
            "and NOT the one already under it: {note}"
        );

        // A ceiling nothing sits above is a ceiling that moved nothing: silent.
        let mut b = vec![svc("small", Some("32m"))];
        assert_eq!(
            apply_memory_policy(&mut b, (Some(64 * MIB), None), None),
            None
        );

        // NEITHER CEILING NOR READABLE HOST: no `--memory` at all, so the box keeps its own default.
        // This is exactly what kern did before any of this, so an unreadable host never fails in a
        // new way.
        let mut b = vec![svc("free", None)];
        assert_eq!(apply_memory_policy(&mut b, (None, None), None), None);
        assert_eq!(b[0].memory, None);
    }

    /// A CEILING THAT BINDS IS NEVER SILENT, and one that does not bind says nothing.
    #[test]
    fn the_ceiling_note_fires_only_when_the_ceiling_moved_something() {
        const MIB: u64 = 1024 * 1024;
        assert_eq!(crate::commands::memory_ceiling_note(&[], 512 * MIB), None);
        let note = crate::commands::memory_ceiling_note(&["db", "web"], 512 * MIB)
            .expect("a ceiling that moved two services owes a sentence");
        assert!(note.contains("db, web"), "must name them: {note}");
        assert!(note.contains("512 MiB"), "and quote the ceiling: {note}");
        assert!(
            note.contains("these services run under"),
            "plural for two: {note}"
        );
        let one = crate::commands::memory_ceiling_note(&["db"], 64 * MIB).expect("one is enough");
        assert!(
            one.contains("this service runs under") && one.contains("64 MiB"),
            "singular, and the figure comes from the argument: {one}"
        );
    }

    fn svc(name: &str, container_name: Option<&str>) -> ComposeBox {
        ComposeBox {
            name: name.to_string(),
            container_name: container_name.map(str::to_string),
            ..Default::default()
        }
    }

    /// A `container_name` NAMES THE BOX AND NOTHING ELSE.
    ///
    /// A field report concluded the opposite - that kern used it as the service hostname too, so
    /// "every inter-service URL in the file silently stops resolving" - and deleted four
    /// `container_name` keys from a working file over it. Measured on a live pod, both names are in
    /// `/etc/hosts` and peers resolve the service name. The output was the whole defect: `config`
    /// printed the box name while claiming to print service names.
    ///
    /// This asserts the three things that were confused for one another, on one input.
    #[test]
    fn a_container_name_renames_the_box_and_leaves_the_service_name_resolving() {
        let mut boxes = vec![svc("keycloak", Some("myapp-keycloak")), svc("db", None)];
        let map = resolve_box_names(&mut boxes, "proj");

        // 1. The BOX takes the container_name; without one it is the project-scoped form.
        assert_eq!(boxes[0].name, "myapp-keycloak");
        assert_eq!(boxes[1].name, "proj-db");

        // 2. The SERVICE name is kept, which is what `config` reports and what a reader compares
        //    against their own file.
        assert_eq!(boxes[0].service, "keycloak");
        assert_eq!(boxes[1].service, "db");

        // 3. The service name is registered as a pod alias, which is what peers resolve. This is
        //    the claim the report got wrong, and it holds for the renamed box too.
        assert!(
            boxes[0].net_aliases.contains(&"keycloak".to_string()),
            "a renamed box must still answer to its service name: {:?}",
            boxes[0].net_aliases
        );
        assert!(boxes[1].net_aliases.contains(&"db".to_string()));

        // And the map the caller resolves command-line selectors through agrees with all of it.
        assert_eq!(
            map.get("keycloak").map(String::as_str),
            Some("myapp-keycloak")
        );
        assert_eq!(map.get("db").map(String::as_str), Some("proj-db"));
    }

    /// EVERY `depends_on` EDGE IS REWRITTEN WITH THE SAME TABLE.
    ///
    /// The edges name SERVICES in the file and must name BOXES afterwards, or the topological order,
    /// the conditional waits and the health lookups downstream all look up a name that no longer
    /// exists. All three edge lists go through it, not just the plain one.
    #[test]
    fn dependency_edges_are_rewritten_onto_box_names() {
        let mut api = svc("api", None);
        api.depends_on = vec!["db".into()];
        api.depends_healthy = vec!["keycloak".into()];
        api.depends_completed = vec!["migrate".into()];
        let mut boxes = vec![
            svc("keycloak", Some("myapp-keycloak")),
            svc("db", None),
            svc("migrate", Some("myapp-migrate")),
            api,
        ];
        resolve_box_names(&mut boxes, "proj");

        let api = &boxes[3];
        assert_eq!(api.depends_on, vec!["proj-db".to_string()]);
        assert_eq!(
            api.depends_healthy,
            vec!["myapp-keycloak".to_string()],
            "an edge onto a renamed service must follow the rename"
        );
        assert_eq!(api.depends_completed, vec!["myapp-migrate".to_string()]);

        // AN EDGE ONTO A SERVICE THAT IS NOT IN THE FILE still gets the scoped form rather than
        // being left bare: a bare name would collide with another project's box of that name.
        let mut orphan = svc("x", None);
        orphan.depends_on = vec!["nowhere".into()];
        let mut boxes = vec![orphan];
        resolve_box_names(&mut boxes, "proj");
        assert_eq!(boxes[0].depends_on, vec!["proj-nowhere".to_string()]);
    }

    /// The rewrite is IDEMPOTENT in the field it must not lose, and does not duplicate the alias.
    ///
    /// `net_aliases` is a list a user also writes into (`networks.<net>.aliases`), so pushing the
    /// service name must not add a second copy when it is already there.
    #[test]
    fn the_service_alias_is_added_once_and_a_user_alias_survives() {
        let mut b = svc("db", None);
        b.net_aliases = vec!["db".into(), "database".into()];
        let mut boxes = vec![b];
        resolve_box_names(&mut boxes, "proj");
        assert_eq!(
            boxes[0].net_aliases,
            vec!["db".to_string(), "database".to_string()],
            "the alias list must not gain a duplicate, and a user's own alias must survive"
        );
    }
}

#[cfg(test)]
mod outbound_tests {
    use super::outbound_targets;
    use crate::compose::ComposeBox;

    fn svc(name: &str) -> ComposeBox {
        ComposeBox {
            name: name.to_string(),
            service: name.to_string(),
            ..Default::default()
        }
    }

    /// WHO GETS A ROUTE OUT IS A SECURITY DECISION, so it is asserted rather than read.
    ///
    /// `internal: true` finally means something here: with one namespace per service, a service the
    /// file confines gets NO NAT, so there is no route out of its namespace at all. MEASURED end to
    /// end on a two-service stack: the public one reported two routes and reached `1.1.1.1:443`, the
    /// confined one reported zero and could not. The positive control matters as much as the
    /// assertion - a build that attached no NAT to anything would satisfy "the confined service has
    /// no route" while having removed the feature instead of enforcing the boundary.
    ///
    /// The exclusions fail differently and are asserted separately: a confined service must not have
    /// egress, a host-network service already has the host's own, and a `restart:` service can be
    /// given one exactly when kern supervises it in process - which is every POD member, and no
    /// standalone box, because that one is started later by systemd and never held at the gate.
    #[test]
    fn only_the_services_that_may_reach_out_are_given_a_nat() {
        let mut confined = svc("db");
        confined.only_internal_networks = true;
        let mut on_host = svc("edge");
        on_host.net = true;
        let mut managed = svc("cache");
        managed.restart_always = true;
        let plain = svc("web");
        let boxes = [plain, confined, on_host, managed];

        // Standalone (no pod): `restart:` means systemd starts it, so it cannot be held.
        let got = outbound_targets(&boxes, false, false);
        assert!(
            got.contains("web"),
            "an ordinary service reaches out: {got:?}"
        );
        assert!(
            !got.contains("db"),
            "a service confined to internal networks must get no NAT: {got:?}"
        );
        assert!(
            !got.contains("edge"),
            "a service on the host network already has the host's connectivity: {got:?}"
        );
        assert!(
            !got.contains("cache"),
            "a standalone `restart:` service is started by systemd and cannot be held while a NAT \
             is attached: {got:?}"
        );
        assert_eq!(got.len(), 1, "and nobody else: {got:?}");

        // ON A BRIDGE the members are pod members, and `persistent_supervision` puts every pod
        // member on the in-process supervisor whatever systemd offers - so a `restart:` service IS
        // held at the gate and does get a NAT. Excluding it is what left Sentry self-hosted, which
        // writes `restart: unless-stopped` on nearly every service, with no route out at all.
        let bridge = outbound_targets(&boxes, false, true);
        assert!(
            bridge.contains("cache") && bridge.contains("web"),
            "a bridge member with `restart:` is supervised in-process and gets its own NAT: \
             {bridge:?}"
        );
        assert!(
            !bridge.contains("db") && !bridge.contains("edge"),
            "the other two exclusions are unchanged by the wiring: {bridge:?}"
        );

        // In ONE SHARED namespace the pod carries the single NAT: a second per box would put two
        // default routes in one namespace.
        assert!(outbound_targets(&boxes, true, true).is_empty());
    }
}
