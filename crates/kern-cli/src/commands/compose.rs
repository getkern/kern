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
        for d in b
            .depends_on
            .iter_mut()
            .chain(b.depends_healthy.iter_mut())
            .chain(b.depends_completed.iter_mut())
        {
            *d = box_name(d);
        }
        b.name = box_name(&svc);
    }
    box_name_of
}

pub fn compose(o: ComposeOpts<'_>) -> Result<(), Error> {
    let ComposeOpts {
        files,
        action,
        no_pod,
        allow_device_grants,
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
    let mut boxes = crate::compose::parse_with_env(&text, &dotenv).map_err(Error::Compose)?;
    // Merge every additional `-f`, left to right (see `merge_stacks` for the exact rules).
    for extra in &files[1..] {
        let t = std::fs::read_to_string(extra)
            .map_err(|e| Error::Compose(format!("reading {extra}: {e}")))?;
        let over = crate::compose::parse_override(&t, &dotenv).map_err(Error::Compose)?;
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
        None => compose_pod_name(file),
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

    // A `--filter`/service selection narrows the read-only verbs to the named services; empty = all.
    // Validated up front so a typo names itself instead of silently matching nothing.
    //
    // `port` IS THE ONE VERB WHOSE POSITIONALS ARE NOT ALL SERVICE NAMES: it takes
    // `<service> <container-port>`. Running the port through this check reported a mistyped NUMBER as
    // an unknown service, which sends the reader to look for a service that was never meant to exist.
    // Only the first positional is a name here; the arm itself validates the port, and does it as a
    // port.
    let to_validate: &[String] = if action == ComposeAction::Port {
        services.get(..1).unwrap_or(&[])
    } else {
        services
    };
    for want in to_validate {
        if !boxes.iter().any(|b| &b.name == want) {
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
    // Verbs that answer a question about the stack rather than changing it return here.
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
            no_pod,
            allow_device_grants,
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
        let wanted: std::collections::HashSet<String> = if action == ComposeAction::Up {
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
    check_pod_global_conflicts(&boxes, no_pod)?;
    // Self-explaining (see its doc): a device grant a compose file asked for needs a command-line
    // acknowledgement, because the file cannot reach the command line.
    if let Some(msg) = device_grant_problem(&boxes, allow_device_grants) {
        return Err(Error::Compose(msg));
    }
    // Softer sibling: two services whose IMAGES expose the same port without either DECLARING it (two
    // nginx on :80, two node apps on :3000). Best-effort and cache-only (never pulls just to warn),
    // a WARNING not an error because an image's EXPOSE is a hint, not a guaranteed bind.
    warn_image_expose_collisions(&boxes, no_pod);
    // THE ESCAPE HATCH SAYS WHAT IT COSTS. `--no-pod` is what the port-collision refusal sends people
    // to, and it is not free: MEASURED on the same two-service stack, `getent hosts db` answers
    // `127.0.0.1 db db` in a pod and NOTHING under `--no-pod`. Trading a loud refusal at bring-up for
    // a silent name-resolution failure inside a service, with nothing said in between, is the shape
    // this project treats as the expensive kind of defect. Once per bring-up, not once per service.
    // THE UNDECLARED-PORT NOTE BELONGS HERE, at config time: it follows from the file alone, and its
    // whole value is arriving before a service logs `Connection refused`.
    if let Some(note) = no_pod_undeclared_ports_note(&boxes, no_pod) {
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

    // Auto-pod: a multi-service stack gets a shared network (name resolution + outbound) unless the
    // user opts out or every box already shares the host net (`--net`). Reuse an existing pod so
    // `up` is idempotent.
    let mut use_pod = !no_pod && boxes.len() >= 2 && boxes.iter().any(|b| !b.net);
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
        crate::pod::create_with_range(&pod, true, pod_needs_range)?;
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
        let services: Vec<(String, String, Vec<u16>)> = boxes
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
                (b.service.clone(), b.name.clone(), tcp)
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
                        let (started, pod, up_token, self_exe, project_dir, address_plan) = (
                            &started,
                            &pod,
                            &up_token,
                            &self_exe,
                            &project_dir,
                            &address_plan[..],
                        );
                        // `Some(...)`: `filter_map` wants an `Option`, and the `?` above is the
                        // miss. The spawn itself always succeeds.
                        Some(scope.spawn(move || -> Result<(), Error> {
                            // Conditional deps (healthy/completed) live in an earlier, already-started
                            // level; plain `depends_on` is honored by the level barrier itself.
                            wait_for_conditions(b, pod, up_token)?;
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
                            // A box not on the host net joins the stack pod → reachable by name from peers.
                            if use_pod && !b.net {
                                cmd.arg("--pod").arg(pod);
                            }
                            // Without a pod, the same reachability is spelled out: every peer at its
                            // alias, this box at its own loopback. A box on the host net is skipped -
                            // it already resolves whatever the host resolves, and pointing its name
                            // at a loopback alias would break that.
                            if !b.net {
                                if let Some(entries) =
                                    crate::nopod::add_host_args(address_plan, &b.service)
                                {
                                    for e in entries {
                                        cmd.arg("--add-host").arg(e);
                                    }
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
                            cmd.arg("-d");
                            if !b.command.is_empty() {
                                cmd.arg("--").args(&b.command);
                            }
                            let status = cmd.status().map_err(|e| {
                                Error::Compose(format!("starting '{}': {e}", b.name))
                            })?;
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
    if !use_pod && !address_plan.is_empty() {
        let relays = crate::nopod::relay_plan(&address_plan);
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
    let dead = settle_and_collect_dead(&boxes, &pod, &up_token);
    if !dead.is_empty() {
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
        println!(
            "  pod '{pod}': services reach each other by name. tear down with `kern compose {file} down`."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose::ComposeBox;

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
