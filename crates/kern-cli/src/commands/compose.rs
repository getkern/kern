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

pub fn compose(o: ComposeOpts<'_>) -> Result<(), Error> {
    let ComposeOpts {
        files,
        action,
        no_pod,
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
    let scoped = |svc: &str| format!("{pod}-{svc}");
    // Each service's BOX name: Docker's `container_name:` verbatim when set (so `docker exec <name>`
    // ports 1:1 to `kern exec <name>`), else the project-scoped `<pod>-<service>`. Built ONCE so the
    // box's own name and every `depends_on` edge that names a service map to the SAME box name.
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
    for want in services {
        if !boxes.iter().any(|b| &b.name == want) {
            return Err(Error::Compose(format!(
                "no service '{want}' in {file} (services: {})",
                boxes
                    .iter()
                    .map(|b| b.name.as_str())
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
        },
    )? {
        return Ok(());
    }

    let mut levels = crate::compose::topo_levels(&boxes).map_err(Error::Compose)?;
    // `start` launches only what is NOT already running. Filtering the LEVELS (not `boxes`) keeps the
    // dependency graph exactly as computed - dropping a service from `boxes` would make its dependents
    // reference an unknown name - and keeps every level entry backed by a real box.
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
    // Softer sibling: two services whose IMAGES expose the same port without either DECLARING it (two
    // nginx on :80, two node apps on :3000). Best-effort and cache-only (never pulls just to warn),
    // a WARNING not an error because an image's EXPOSE is a hint, not a guaranteed bind.
    warn_image_expose_collisions(&boxes, no_pod);
    // A pod shares ONE network namespace, so a `net.*` sysctl written on one service applies to every
    // service in the stack and the last one to start wins. The file makes it look per-service; say so
    // rather than let an operator tune one service and silently retune the others.
    if !no_pod && boxes.len() > 1 {
        for b in &boxes {
            for kv in b.sysctls.iter().filter(|s| s.starts_with("net.")) {
                let key = kv.split('=').next().unwrap_or(kv);
                eprintln!(
                    "kern compose: service '{}': sysctl '{key}' applies to the WHOLE pod (services \
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
    let use_pod = !no_pod && boxes.len() >= 2 && boxes.iter().any(|b| !b.net);
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

    // Count what will actually be LAUNCHED, not how many services the file has: with drift
    // reconciliation the levels may already have been filtered down to the changed ones, and a
    // header promising more boxes than it starts is the kind of small untruth this codebase avoids.
    let total: usize = levels.iter().map(Vec::len).sum();
    eprintln!(
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
                    .map(|name| {
                        let b = boxes.iter().find(|b| &b.name == name).unwrap();
                        let (started, pod, up_token, self_exe, boxes, project_dir) =
                            (&started, &pod, &up_token, &self_exe, &boxes, &project_dir);
                        scope.spawn(move || -> Result<(), Error> {
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
                            eprintln!("→ [{n}/{total}] starting '{}'  {src}{dep}", b.name);
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
                            // If a peer waits on THIS box's completion, hand it the stack+run-scoped exit
                            // KEY via env and CLEAR that exact key BEFORE the spawn. Each box owns a UNIQUE
                            // key (carries this `up`'s token), so concurrent workers never touch each
                            // other's - the review-round-2 invariant holds under parallelism too.
                            let is_completion_target = boxes
                                .iter()
                                .any(|other| other.depends_completed.iter().any(|d| d == &b.name));
                            if is_completion_target {
                                let key = exit_key(pod, up_token, &b.name);
                                registry::clear_exit(&key);
                                cmd.env("KERN_EXIT_KEY", &key);
                            }
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
                        })
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
                let b = boxes.iter().find(|b| &b.name == name).unwrap();
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
