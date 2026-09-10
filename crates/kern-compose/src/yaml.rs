//! A YAML-lite parser for `docker-compose.yml` → kern [`ComposeBox`](super::ComposeBox)es.
//!
//! **Why hand-rolled.** The whole compose surface is dependency-free by design (like the TOML parser
//! and the OCI tar vetter). We parse the SUBSET of compose that real stacks use and **degrade the long
//! tail with a warning** rather than promise full compatibility - the honest "drop-in-with-degrade"
//! posture. A field we can't map is warned about and skipped (or reconstructed), never silently
//! mis-converted: a mis-converted field is worse than a skipped one because it *runs and lies*.
//!
//! **Security posture (this is semi-trusted input - a compose from a third-party repo).**
//!  * Never a panic on any input: only `char_indices`/byte-safe slicing, iterative (no recursion → no
//!    stack overflow on deep nesting), and a nesting cap. Property-fuzzed (see `fuzz/`).
//!  * **Anchors and merge keys ARE expanded; the billion-laughs SHAPE is refused by form.** An alias
//!    used as a token inside an inline collection (`[*a]`, `{k: *a}`) is rejected outright, and that is
//!    exactly the construction a bomb needs (`&a [x,x]`, `&b [*a,*a]`, `&c [*b,*b]`…): measured, a
//!    ten-level bomb is refused in 3 ms at 6.7 MB RSS. What IS expanded is the useful subset - a
//!    block-style anchor, a merge key (`<<: *base`, `<<: [*a, *b]`), an alias as a whole value - and
//!    that expansion additionally spends from a node budget. An earlier version of this paragraph said
//!    anchors were never expanded at all, which was a stronger claim than the code makes and the wrong
//!    kind of claim to leave standing in a security note.
//!  * Every value is treated as a raw string - no numeric coercion, so YAML 1.1's sexagesimal trap
//!    (`22:22` → 1342) can't fire on a port.
//!  * `build:` `context`/`dockerfile` are paths the caller CONFINES under the compose dir (traversal).
//!
//! The grammar we accept: space-indented `key: value`, `- ` list items, inline `[…]`/`{…}`, `#`
//! comments, double/single quotes, **block scalars** (`|` keeps its line breaks, `>` folds them; both
//! are folded onto one logical line by `fold_multiline`), **block-style anchors and merge keys**
//! (`<<: *base`, `<<: [*a, *b]`), and an **alias used as a whole value**.
//!
//! ONE DELIBERATE LENIENCY, measured and left in place: an alias may appear BEFORE its anchor
//! (`<<: *base` above the `&base` that defines it). YAML requires the anchor first and a strict
//! reader refuses the document; this one collects every anchor before resolving, so a forward
//! reference resolves to what its author meant rather than being lost. Nothing is mis-converted and
//! nothing is silently dropped - the file is simply accepted where another runtime would refuse it,
//! which is the direction that costs the author an error elsewhere rather than a wrong box here.
//! Making it strict means either a line number on every node or a single ordered pass through the
//! resolver, and that is surgery on the one component in this crate that is property-fuzzed for
//! panic-freedom. Written down rather than changed on a whim.
//!
//! We REFUSE (with a clear error): tab indentation, type tags (`!!`), 2nd+ documents (`---`), a NUL
//! byte (U+0000) or a U+0001 anywhere in the file, and an **alias used as a token inside an inline
//! collection** (`[*a]`, `{k: *a}`) unless the line is a merge key. Each of those was verified against
//! this parser rather than assumed: an earlier version of this list named block scalars, anchors and
//! merge keys as refused, and all three are supported.

use super::{BuildDirective, ComposeBox, ABSENT_PROFILE_KINDS, PROFILE_KINDS};

/// Max indentation depth we track - a compose service tree is 3-4 deep; anything past this is refused
/// rather than parsed, bounding work and stack (we're iterative, but this caps pathological input).
/// What a compose file loses when kern ignores `networks:`, stated as a loss and not as a feature.
///
/// The line used to read "kern connects pod members by name (shared netns)". Every word of that is
/// true and it describes what the reader GAINS, so a reader who separated frontend from backend
/// concluded "convenient, they resolve each other" and moved on. What actually happened to their file
/// is the opposite, and it was MEASURED with a payload rather than a connection, because a connection
/// succeeding proves nothing about an arc:
///
/// * a service on `rete_a` read `TOKEN-BETA` off a service on `rete_b`. Docker refuses that; here the
///   two networks are one namespace, so segmentation put in the file to contain a compromised service
///   does not exist.
/// * a network marked `internal: true` reached `1.1.1.1:443` and `8.8.8.8:443` and resolved DNS,
///   exactly like an ordinary one - verified against a service on a normal network as the positive
///   control, and against the host, so "blocked" could not be a dead target. That is the declaration
///   people use to keep a database off the internet.
///
/// So the warning names both consequences and then names the tool kern actually has, because a
/// warning that leaves the reader without a remedy gets read once and skipped after that. Aliases are
/// mentioned in the same breath since they ARE honoured, and a reader who thinks nothing works would
/// rewrite a file that needs no rewriting.
const NETWORKS_IGNORED: &str = "'networks:' ignored - every service shares ONE namespace, so services you put on separate networks CAN reach each other. Names and aliases still resolve. Keep services that must not see each other in separate stacks, or run with --no-pod, where the memberships are enforced";

/// What `networks:` means under `--no-pod`, where it is NOT ignored.
///
/// The pod sentence is the exact opposite claim and would be FALSE here: without a pod each service
/// has its own namespace and reachability is built edge by edge, so two services with no network in
/// common get no relay and no hosts entry for each other. Saying "ignored" there would send a reader
/// to redesign a stack whose segmentation kern is already enforcing.
///
/// It names the DEFAULT rule too, because that is the half people get wrong: a service with no
/// `networks:` key is on the implicit `default` network, so it is segregated FROM the services that
/// name one. That is the Compose Specification's rule, NOT measured against a Docker daemon here
/// (none is installed on this host), and it surprises anyone who thinks an absent key means "all".
const NETWORKS_SEGREGATED: &str =
    "'networks:' is ENFORCED under --no-pod: each service has its own \
     namespace and only services sharing a network get a peer relay, so a service on no shared \
     network does not resolve its name at all. A service with no `networks:` key \
     is on the implicit `default` network, so it is separated from the services that name one";

/// The `internal: true` half of the networks warning, said ONLY when it is true.
///
/// It cannot live in [`NETWORKS_IGNORED`] because it is not always a fact: when EVERY service in the
/// file is exclusively on internal networks, the driver creates the pod with no outbound and the key
/// IS honoured. Printing "does NOT block outbound" there would be the parser contradicting what the
/// run then does, which is worse than the silence this warning replaced.
const INTERNAL_NOT_APPLIED: &str = "a network is marked `internal: true` but at least one \
     service is not confined to internal networks, and kern gives the stack ONE namespace - so \
     outbound and DNS stay open for every service. Put the confined services in their own stack, \
     use --egress-allow, or run with --no-pod, where no service reaches the internet at all";

/// `internal: true` with a namespace per service, where it is ENFORCED and not merely satisfied.
///
/// THIS SENTENCE USED TO SAY THE OPPOSITE HALF AND WAS RIGHT AT THE TIME. Before kern attached a NAT
/// per box, NO service outside a pod had egress, so the key was satisfied for the services that
/// asked and over-applied to the ones that had not - and that over-application was the part worth
/// warning about. With a NAT per box the two cases separate, and the sentence had to follow:
/// MEASURED on one stack, one run, `web` on a public network reached `1.1.1.1:443` and resolved a
/// name, while `db` on the internal one held only `lo` and the same connect was refused.
///
/// WHAT IT IS WORTH SAYING NOW is that the boundary is real and where it does NOT reach: a service
/// with `restart:` is installed as a systemd unit, `up` never holds it at the gate, and there is no
/// instant at which a NAT can be attached to it - so it gets none, whether or not its networks are
/// internal. That is named at bring-up per service as well.
const INTERNAL_SATISFIED_BY_NO_POD: &str = "a network is marked `internal: true`, and with a \
     namespace per service kern ENFORCES it: a service whose networks are all internal gets no NAT \
     at all, so there is no route out of its namespace rather than a filter. Services on other \
     networks keep their egress. A service with `restart:` that SYSTEMD starts gets no NAT either \
     way - kern cannot hold a box the manager launches later; a pod member with `restart:` is \
     supervised in-process instead, so it does get one";

const MAX_DEPTH: usize = 32;
/// Total nodes an anchor/alias/merge expansion may materialize. Every aliased clone spends from this
/// budget; exhausting it is the billion-laughs defence (a `&a [*a,*a]`…`&z [*y,*y]` bomb blows the
/// budget long before it blows memory), so anchors are supported WITHOUT reintroducing the DoS the
/// old blanket refusal guarded against. A real compose's `x-*` templates spend a handful.
const MAX_ANCHOR_NODES: usize = 10_000;

/// Parse a compose YAML document into boxes. Warnings for the degraded long tail go to stderr; the
/// return is the mappable boxes (or a hard error for a malformed / unsupported-structural document).
///
/// `pub(crate)`: reached only through the crate's one public door, [`super::parse`] (which sniffs
/// YAML vs TOML first). The `yaml` module itself is private, so this was never externally reachable -
/// the narrower marker just says so.
/// Test-only shim: the pre-`.env` one-argument entry point, so the existing suite keeps exercising
/// `parse` exactly as callers without a project `.env` reach it.
#[cfg(test)]
fn parse(text: &str) -> Result<Vec<ComposeBox>, String> {
    parse_with_env(
        text,
        &crate::DotEnv::default(),
        true,
        crate::StackNet::Pod,
        None,
    )
}

/// The `--no-pod` counterpart of [`parse`], for tests that assert what segregation changes.
#[cfg(test)]
fn parse_no_pod(text: &str) -> Result<Vec<ComposeBox>, String> {
    parse_with_env(
        text,
        &crate::DotEnv::default(),
        true,
        crate::StackNet::PerService,
        None,
    )
}

pub(crate) fn parse_with_env(
    text: &str,
    dotenv: &crate::DotEnv,
    require_runnable: bool,
    net: crate::StackNet,
    dir: Option<&std::path::Path>,
) -> Result<Vec<ComposeBox>, String> {
    // Fold multi-line block scalars (`|`/`>`) and multi-line flow collections onto single logical lines
    // first, so the rest of the pipeline stays line-at-a-time (block-scalar bodies become opaque values).
    let folded = fold_multiline(text)?;

    // Refuse structural YAML we deliberately don't support, BEFORE any parsing - so a billion-laughs
    // or a tab-indented file fails fast with a clear reason, never reaches the line scanner.
    prescreen(&folded)?;

    // Interpolate `${VAR}` / `${VAR:-default}` at the DOCUMENT level, like Docker - so it works
    // everywhere (ports, command, volumes, environment, build.args), not just in a couple of fields. A
    // per-field pass would miss `ports: ["${PORT}:80"]`; Docker substitutes over the whole file before
    // parsing, and so do we. Unset with no default → empty + warn (Docker semantics), never a literal
    // `${VAR}` left to confuse a downstream tool.
    let interpolated = interpolate_document(&folded, dotenv);
    // TAKEN, not read: draining here is what stops one document's missing variables being reported
    // against the next one parsed in this process. A mutation replacing the take with a clone leaves
    // the second parse refusing a variable its file never mentions, which the test pins.
    //
    // A separate clear on ENTRY was written first and then removed: nothing can run between the
    // interpolation and this line, so it was unreachable, and its comment claimed a failure mode the
    // control flow makes impossible. Defensive code whose justification is false is worse than none.
    let missing = take_required_unset();
    if !missing.is_empty() {
        return Err(format!(
            "{} required by this file with `${{VAR:?...}}` {} no value: {}. That form exists to STOP \
             the file being rendered without it - it is what a compose file writes for a password or \
             a token - so kern refuses rather than substituting an empty string. Set {} in your \
             shell or in the project `.env`.",
            if missing.len() == 1 {
                "a variable"
            } else {
                "variables"
            },
            if missing.len() == 1 { "has" } else { "have" },
            missing.join(", "),
            if missing.len() == 1 { "it" } else { "them" },
        ));
    }
    let text = interpolated.as_str();

    let lines = lex(text)?;
    let mut root = build_tree(&lines)?;
    // Expand YAML anchors (`&x`), aliases (`*x`) and merge keys (`<<: *x`) - the common `x-*` template
    // DRY pattern real compose files use - under a hard node budget (billion-laughs-safe). After this,
    // the tree holds only concrete values.
    resolve_anchors(&mut root)?;
    // Resolve `extends:` (a service inheriting another service's fields) - a real Compose feature the
    // `x-`/anchor pattern doesn't cover, since it references another SERVICE by name. Same-file only.
    resolve_extends(&mut root, dir, dotenv)?;

    // Top level must have `services:`. `volumes:`/`networks:`/`version:`/`name:` are recognized;
    // everything else at the top is warned and ignored.
    // Top-level `secrets:` definitions (`name -> file`) - collected first so a service's
    // `secrets: [name]` reference can be resolved to its file. Only the `file:`-backed form maps to
    // kern (`--secret <file>:<name>` → `/run/secrets/<name>`); `external:`/`environment:` secrets warn.
    let secret_files = collect_secret_files(&root);
    let secret_envs = collect_secret_envs(&root);
    let internal_networks = collect_internal_networks(&root);
    let network_subnets = collect_network_subnets(&root);
    // Collected first for the same reason as the secrets above: `volumes:` may sit below `services:`
    // in the file, and a service that mounts an external volume has to be marked whichever order the
    // two blocks appear in.
    let external_volumes = collect_external_volumes(&root)?;

    let mut boxes = Vec::new();

    let mut skipped_by_profile: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    // The PROFILE names that gated those services, kept apart from the service names. The two are
    // not interchangeable and the error below has to quote this set: a reader who copies the other
    // one gets a `COMPOSE_PROFILES` that activates nothing.
    let mut inactive_profiles: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut have_services = false;
    for (key, node) in &root.children {
        match key.as_str() {
            "services" => {
                have_services = true;
                for (name, svc) in &node.children {
                    // A duplicate service key is a real authoring mistake (two blocks, same name) -
                    // reject it rather than launch two boxes with the same name (which then collide at
                    // start with an opaque "already running", or silently shadow). Docker's YAML parser
                    // rejects duplicate mapping keys too.
                    // O(1) membership, not a scan of everything parsed so far: the scan made the
                    // whole parse quadratic in the number of services (measured 3x per doubling in
                    // the tail, and a 60k-service file never finished).
                    if !seen_names.insert(name.clone()) {
                        return Err(format!("duplicate service '{name}'"));
                    }
                    let mut b = service_to_box(
                        name,
                        svc,
                        &ServiceCtx {
                            secret_files: &secret_files,
                            secret_envs: &secret_envs,
                            internal_networks: &internal_networks,
                            net,
                            dir,
                            dotenv,
                        },
                    )?;
                    // The subnet of the FIRST network this service joins that declares one.
                    b.net_subnet = b.networks.iter().find_map(|n| {
                        network_subnets
                            .iter()
                            .find(|(name, _)| name == n)
                            .map(|(_, cidr)| cidr.clone())
                    });
                    // Docker profiles: a service with a non-empty profile list is INACTIVE unless one
                    // of its profiles is enabled via COMPOSE_PROFILES. A plain `up` starts only the
                    // profile-less services - so we SKIP an inactive one (never start it by accident),
                    // warning how to enable it. (kern has no `--profile` flag yet; COMPOSE_PROFILES is
                    // the env kern honors, matching Docker's env of the same name.)
                    if !b.profiles.is_empty() && !any_profile_active(&b.profiles) {
                        warn(&format!(
                            "service '{name}': skipped - profile(s) [{}] not active (set COMPOSE_PROFILES to enable)",
                            b.profiles.join(", ")
                        ));
                        // Remembered, so a `depends_on` pointing here can be told apart from one
                        // pointing at a name that was never defined at all. See the pruning below.
                        skipped_by_profile.insert(name.clone());
                        inactive_profiles.extend(b.profiles.iter().cloned());
                        continue;
                    }
                    boxes.push(b);
                }
            }
            "volumes" | "networks" | "version" | "name" | "configs" | "secrets" => {
                // `volumes:`/`secrets:` top-level are consumed elsewhere (volumes auto-created on `-v`
                // use; secrets pre-collected above). `networks:` is the one we actively warn about.
                if key == "networks" {
                    // `warn_once`: the same fact is also reachable from a per-service `networks:`,
                    // and a file with both would otherwise say it twice (plus once per service).
                    if let Some(n) = networks_note(net) {
                        warn_once(n);
                    }
                }
            }
            // `x-…` is the Compose Specification's EXTENSION mechanism, not an unknown key: it is
            // how the `x-common:` + anchors DRY idiom works, so warning about it means every file
            // using the most common pattern in the ecosystem gets a false alarm.
            other if other.starts_with("x-") => {}
            other => warn(&format!("top-level '{other}:' ignored (unsupported)")),
        }
    }
    if !have_services {
        return Err("no `services:` block found".to_string());
    }
    // `volumes_from:` RESOLVED AFTER THE LOOP, because the service it names may be defined below the
    // one that names it and a single-pass copy would then silently inherit nothing. Docker's `:ro`
    // suffix narrows every inherited entry rather than being dropped, and an entry that is already
    // read-only stays so: a copy may only ever be as permissive as its source.
    //
    // ONE LEVEL, NOT TRANSITIVE. Docker resolves chains; kern does not, and says so, because a chain
    // needs cycle detection and this parser has no case in a 259-file corpus that uses one. A
    // silently truncated chain would be worse than a named limit.
    let inherited: Vec<(usize, Vec<String>)> = boxes
        .iter()
        .enumerate()
        .filter(|(_, b)| !b.volumes_from.is_empty())
        .map(|(i, b)| {
            let mut add: Vec<String> = Vec::new();
            for entry in &b.volumes_from {
                let (svc, ro) = match entry.trim().split_once(':') {
                    Some((s, m)) => (s.trim(), m.trim().eq_ignore_ascii_case("ro")),
                    None => (entry.trim(), false),
                };
                match boxes.iter().find(|o| o.service == svc || o.name == svc) {
                    Some(src) => {
                        if !src.volumes_from.is_empty() {
                            warn(&format!(
                                "service '{}': 'volumes_from: {svc}' - '{svc}' itself inherits \
                                 volumes, and kern does not follow the chain: only what '{svc}' \
                                 declares directly is copied",
                                b.service_name()
                            ));
                        }
                        for v in &src.volumes {
                            let already_ro = v.ends_with(":ro");
                            add.push(if ro && !already_ro {
                                format!("{v}:ro")
                            } else {
                                v.clone()
                            });
                        }
                    }
                    None => warn(&format!(
                        "service '{}': 'volumes_from: {svc}' names no service in this file - ignored",
                        b.service_name()
                    )),
                }
            }
            (i, add)
        })
        .collect();
    for (i, add) in inherited {
        if let Some(b) = boxes.get_mut(i) {
            for v in add {
                if !b.volumes.contains(&v) {
                    b.volumes.push(v);
                }
            }
        }
    }
    // `network_mode: service:X` RESOLVED AFTER THE LOOP, for the reason `volumes_from` is: the
    // service it names may be written below the one that names it.
    //
    // WHAT IT RESOLVES INTO IS MEMBERSHIP. A container inside another's network namespace is on that
    // namespace's networks, so the sharer inherits the memberships of the service it names. Before
    // this it inherited nothing: a service with `network_mode:` has no `networks:` key of its own, so
    // it sat on the implicit `default` network while the service it named sat on another, and kern
    // read the pair as SEGREGATED - no relay, no hosts entry, no name resolution - in exactly the
    // file that asked the two to be one host.
    //
    // THE CHAIN IS FOLLOWED, unlike `volumes_from`, because it terminates in a single namespace and
    // truncating it would copy a membership that is itself a copy: `a` inside `b` inside `c` is one
    // namespace, `c`'s. The walk is bounded by the service count, so a file that points a service at
    // itself is reported instead of spinning.
    let shared = resolve_net_share(&boxes);
    for note in &shared.notes {
        warn(note);
    }
    for (i, nets) in shared.inherit {
        if let Some(b) = boxes.get_mut(i) {
            b.networks = nets;
        }
    }
    // AFTER the `volumes_from` inheritance above: an inherited mount of an external volume is still a
    // mount of an external volume, and marking before this pass would miss exactly those.
    mark_external_volumes(&mut boxes, &external_volumes);
    // SAID AFTER THE LOOP, because it is a fact about the WHOLE file. `internal: true` is
    // all-or-nothing under one namespace: it is honoured when every service is confined to internal
    // networks, and dropped otherwise. Deciding it per service would print "not applied" on a file
    // where it IS applied, one line per service, which is the shape of a warning nobody reads.
    if !internal_networks.is_empty() {
        if let Some(note) = internal_note(net, super::stack_is_internal_only(&boxes)) {
            warn_once(note);
        }
    }
    if boxes.is_empty() {
        // Distinguish "the block has nothing in it" from "everything in it is behind an inactive
        // profile". Hoppscotch puts EVERY service behind one, so a plain run legitimately starts
        // nothing (Docker behaves identically) and kern answered "`services:` is empty" about a file
        // that defines ten of them. Correct outcome, wrong noun: the reader goes looking for a
        // missing block instead of setting COMPOSE_PROFILES.
        if !skipped_by_profile.is_empty() {
            // The names quoted here are the PROFILES to activate, not the services that were
            // skipped. It listed the services before, and told the reader to put them in
            // COMPOSE_PROFILES: following the message exactly activated nothing, because a service
            // name is not a profile name. Measured on a real file: the message suggested
            // `hoppscotch-backend`, which does nothing, where `backend` is what works.
            let mut profiles: Vec<&str> = inactive_profiles.iter().map(String::as_str).collect();
            profiles.sort_unstable();
            let mut services: Vec<&str> = skipped_by_profile.iter().map(String::as_str).collect();
            services.sort_unstable();
            return Err(format!(
                "every service is behind an inactive profile: {} would run under COMPOSE_PROFILES={} \
                 (or `--profile <name>`), and nothing runs without one",
                services.join(", "),
                profiles.join(",")
            ));
        }
        return Err("`services:` is empty".to_string());
    }
    // A `depends_on` toward a service that was dropped as profile-inactive must not fail the topo sort
    // with "unknown box". Docker treats a dependency on an inactive-profile service as an error only
    // when the dependent is itself active; here we DROP the dangling edge with a warning (the depended
    // service simply isn't part of this run). Only prune names that vanished - a truly unknown name
    // still errors later in `topo_order`.
    // The comment above said a truly unknown name "still errors later in topo_order". It did not:
    // this loop pruned EVERY absent name, so `topo_order` never saw the typo and the ordering the
    // file asked for vanished with one vague line that even suggested looking at profiles. A
    // dependency on a name that was never defined is a mistake in the file (Docker refuses it); a
    // dependency on a service this run skipped for a profile is not. Only the second gets pruned.
    let present: std::collections::HashSet<String> = boxes.iter().map(|b| b.name.clone()).collect();
    for b in boxes.iter_mut() {
        let mut dropped = 0usize;
        let mut prune = |list: &mut Vec<String>| {
            list.retain(|d| {
                if present.contains(d) {
                    return true;
                }
                if skipped_by_profile.contains(d) {
                    dropped += 1;
                    return false;
                }
                true // unknown: kept, so `topo_order` reports it by name
            });
        };
        prune(&mut b.depends_on);
        prune(&mut b.depends_healthy);
        prune(&mut b.depends_completed);
        if dropped > 0 {
            warn(&format!(
                "service '{}': {dropped} dependency/ies dropped - the target is skipped by an inactive profile in this run",
                b.name
            ));
        }
    }
    // A service must resolve to something runnable: an `image` (or a `build:` that produces one). Catch
    // it HERE with a precise message, not later as an opaque "need --rootfs or --image" from the box -
    // parity with the TOML parser's image/rootfs check.
    for b in &boxes {
        let has_image = b.image.as_deref().is_some_and(|s| !s.is_empty());
        let has_rootfs = b.rootfs.as_deref().is_some_and(|s| !s.is_empty());
        // Skipped for an OVERRIDE layer: it restates only what it changes, so "nothing to run" is
        // asserted on the MERGED stack instead (see `parse_override` / `validate_runnable`).
        if require_runnable && !has_image && !has_rootfs && b.build.is_none() {
            return Err(format!(
                "service '{}' has no `image:`, `rootfs:` or `build:` (nothing to run)",
                b.name
            ));
        }
    }
    degrade_orphan_health_gates(&mut boxes);
    Ok(boxes)
}

/// Resolve `depends_healthy` edges that point at a box with NO `health_cmd` (typically because that
/// box's healthcheck wasn't convertible and we omitted it). Instead of letting `validate_conditions`
/// hard-abort the whole `up` with a message disconnected from the root cause, we DEGRADE the edge to a
/// plain `depends_on` (start-order) and warn ONCE with the causal chain - the honest drop-in-with-
/// degrade posture, and what the omit-healthcheck warning already promised. (Adversarial review: the
/// parser must not promise a degrade it doesn't deliver.)
fn degrade_orphan_health_gates(boxes: &mut [ComposeBox]) {
    // Which service names lack a health command (so a `service_healthy` gate toward them is unsatisfiable).
    let no_health: std::collections::HashSet<String> = boxes
        .iter()
        .filter(|b| !b.has_health())
        .map(|b| b.name.clone())
        .collect();
    for b in boxes.iter_mut() {
        let mut kept = Vec::new();
        for dep in std::mem::take(&mut b.depends_healthy) {
            if no_health.contains(&dep) {
                warn(&format!(
                    "service '{}': dependency '{dep}' has no usable healthcheck → its `service_healthy` gate is degraded to start-order (depends_on); verify that's acceptable",
                    b.name
                ));
                if !b.depends_on.contains(&dep) {
                    b.depends_on.push(dep);
                }
            } else {
                kept.push(dep);
            }
        }
        b.depends_healthy = kept;
    }
}

/// True if any of a service's `profiles` is enabled via `COMPOSE_PROFILES` (comma/space-separated,
/// Docker's env). The special profile `*` enables all. No env / empty → nothing profiled is active.
fn any_profile_active(profiles: &[String]) -> bool {
    let active = std::env::var("COMPOSE_PROFILES").unwrap_or_default();
    if active.trim().is_empty() {
        return false;
    }
    let set: Vec<&str> = active
        .split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if set.contains(&"*") {
        return true;
    }
    profiles.iter().any(|p| set.contains(&p.as_str()))
}

/// Private newline sentinel. A folded block scalar keeps its line breaks in a SINGLE-line value as
/// U+0001, decoded back to `\n` by [`scalar_str`]. This keeps block scalars inside the one-line-per-node
/// model without losing real newlines (the verbatim unquoting never expands a `\n` escape), and marks
/// a line as an opaque scalar so prescreen/lex don't scan its shell-script bytes as YAML structure.
const BLOCK_NL: char = '\u{1}';

/// Private marker for "a `${VAR}` with no default resolved to nothing", written by the interpolator
/// and erased by [`scalar_str`], so it never reaches a value.
///
/// It exists to keep two spellings apart that Docker treats differently and that interpolation
/// otherwise flattens into the same thing. MEASURED: `K:` and `K: ${UNSET}` both arrive at the
/// parser as `scalar: None`, and Docker passes the FIRST from the environment (omitting it when
/// nothing is bound) while setting the SECOND to the empty string. Sentry self-hosted needs both in
/// one file: `SENTRY_EVENT_RETENTION_DAYS:` must pick up its `.env` value, and a valueless key whose
/// name is bound nowhere must be absent, not empty - passed as empty, its config dies on
/// `value[0]` with `IndexError: string index out of range`.
const UNSET_MARK: char = '\u{2}';

/// Fold the multi-line YAML the line scanner can't span, before prescreen/lex:
///  * BLOCK SCALARS - `key: |`/`>` and the list form `- |`/`- >` (with `-`/`+`/indent indicators): the
///    indented body becomes ONE value; `|` (literal) keeps line breaks as [`BLOCK_NL`], `>` (folded)
///    joins with spaces; trailing blank lines are clipped. Comments inside the body are LITERAL (a `#`
///    in a shell script is kept), so the body lines are taken raw.
///  * MULTI-LINE FLOW - `key: [ … ]` / `{ … }` (or `- [ … ]`) spanning lines: joined onto one line.
///
/// Each consumed line is emitted BLANK so downstream error line numbers stay exact.
fn fold_multiline(text: &str) -> Result<String, String> {
    if text.contains(BLOCK_NL) {
        return Err("control character U+0001 is not allowed in a compose file".into());
    }
    // U+0000 is refused for a different reason than U+0001, which is only barred because it is the
    // sentinel above. Every consumer of a compose value downstream is a C string or a path, so a NUL
    // is either truncated silently or rejected far from the file that carries it. It was measured
    // reaching an image name intact and printing raw to the terminal. Refused here, at the same door.
    if text.contains('\0') {
        return Err("NUL byte (U+0000) is not allowed in a compose file".into());
    }
    let lines: Vec<&str> = text.lines().collect();
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        let raw = lines[i];
        let code = split_at_comment(raw).0;
        let indent = code.len() - code.trim_start_matches(' ').len();

        // Block scalar: gather the indented body (raw - comments literal) until a dedent.
        if let Some((prefix, folded, chomp)) = block_intro(code) {
            let mut body: Vec<String> = Vec::new();
            let mut base: Option<usize> = None;
            let mut j = i + 1;
            while j < lines.len() {
                let l = lines[j];
                if l.trim().is_empty() {
                    body.push(String::new());
                    j += 1;
                    continue;
                }
                let li = l.len() - l.trim_start_matches(' ').len();
                if li <= indent {
                    break;
                }
                let b = *base.get_or_insert(li);
                body.push(l[b.min(l.len())..].to_string());
                j += 1;
            }
            // COUNT the trailing blank lines before dropping them: the chomping indicator decides how
            // many come back. Dropping them all unconditionally is what made `|`, `|-` and `|+`
            // indistinguishable.
            let mut trailing_blanks = 0usize;
            while body.last().is_some_and(String::is_empty) {
                body.pop();
                trailing_blanks += 1;
            }
            // FOLDING IS PER LINE BREAK, not one separator for the whole body. In a `>` scalar a
            // break folds to a space only BETWEEN two lines that are both at the block's own
            // indentation and both non-empty; a break next to a MORE-INDENTED line, or next to a
            // blank one, is kept. Joining everything with spaces was measured to turn
            // `alp / <2 spaces>ine / fine` into `alp   ine fine`, one line where YAML says three:
            // a more-indented run inside a folded scalar is exactly how a shell snippet or a
            // formatted paragraph is embedded, and flattening it changes the text a service emits.
            //
            // The extra indentation is still IN the stored line (only the base indent was stripped
            // above), so "more indented" is "starts with a space" and needs no second pass.
            let joined = if folded {
                let mut acc =
                    String::with_capacity(body.iter().map(String::len).sum::<usize>() + body.len());
                for (idx, line) in body.iter().enumerate() {
                    if idx > 0 {
                        let prev = &body[idx - 1];
                        let keep_break = line.starts_with(' ')
                            || prev.starts_with(' ')
                            || line.is_empty()
                            || prev.is_empty();
                        acc.push(if keep_break { BLOCK_NL } else { ' ' });
                    }
                    acc.push_str(line);
                }
                acc
            } else {
                body.join(&BLOCK_NL.to_string())
            };
            // THE TRAILING BREAKS THE INDICATOR ASKED FOR. `-` none, default exactly one, `+` every
            // one that was there. An empty body gets none whatever the indicator says: there is no
            // content for a break to follow.
            let tail = if joined.is_empty() {
                0
            } else {
                match chomp {
                    Chomp::Strip => 0,
                    Chomp::Clip => 1,
                    Chomp::Keep => 1 + trailing_blanks,
                }
            };
            let mut value = joined;
            for _ in 0..tail {
                value.push(BLOCK_NL);
            }
            out.push(format!("{prefix}{value}"));
            for _ in (i + 1)..j {
                out.push(String::new());
            }
            i = j;
            continue;
        }

        // Multi-line flow collection on the SAME line: join until the brackets balance.
        if let Some((prefix, first)) = flow_intro(code) {
            let mut acc = first;
            let mut j = i;
            while !brackets_balanced(acc.trim()) && j + 1 < lines.len() {
                j += 1;
                acc.push(' ');
                acc.push_str(split_at_comment(lines[j]).0.trim());
            }
            out.push(format!("{prefix}{acc}"));
            for _ in (i + 1)..=j {
                out.push(String::new());
            }
            i = j + 1;
            continue;
        }

        // A bare `key:` whose value is a FLOW collection on the FOLLOWING line(s) - `command:` then an
        // indented `["postgres"]`. Fold it up (only a pure flow value with no top-level `:`, so a real
        // nested mapping/sequence is untouched).
        if let Some(prefix) = key_only(code) {
            let mut k = i + 1;
            while k < lines.len() && lines[k].trim().is_empty() {
                k += 1;
            }
            if let Some(nl) = lines.get(k) {
                let nc = split_at_comment(nl).0;
                let ni = nc.len() - nc.trim_start_matches(' ').len();
                let nv = nc.trim();
                // A SEQUENCE ENTRY IS NOT A VALUE TO FOLD UP. `ports:` followed by `- "80:80"`
                // is a block sequence, and folding it would produce `ports: - "80:80"`, which is a
                // plain scalar starting with a dash. `colon_index` is quote-aware, so `- "80:80"`
                // has no top-level colon and would have slipped past the guard below on its own.
                let is_seq = nv == "-" || nv.starts_with("- ") || nv.starts_with("-\t");
                let is_flow_open = nv.starts_with('[') || nv.starts_with('{');
                // A SCALAR on the following line is a value too, not only a flow collection. YAML
                // lets a mapping value start on the line after its key, and three shapes of that
                // reached this parser as `expected key: value` in a 240-file corpus of real compose
                // files: `postgres-data:` then `null` (with a blank line between), `args:` then the
                // bare alias `*appArgs`, and `ARGUMENTS:` then a double-quoted string spanning two
                // lines. All three are what PyYAML reads as one mapping entry.
                //
                // The guards are the ones the flow branch already needed, for the same reason: more
                // indented than the key (or it belongs to something else), no top-level colon (or it
                // is a nested mapping key, and an indentation typo must still fail loudly), not a
                // block scalar intro (`|`/`>` are handled above), and not a sequence entry.
                let is_scalar_value =
                    !is_seq && !is_flow_open && !nv.is_empty() && block_intro(nc).is_none();
                if ni > indent && (is_flow_open || is_scalar_value) && colon_index(nc).is_none() {
                    let mut acc = nv.to_string();
                    let mut j = k;
                    // Flow collections close on brackets; a quoted scalar closes on its quote. Both
                    // fold the line break to a space, which is what YAML does.
                    let unclosed = |v: &str| {
                        if is_flow_open {
                            !brackets_balanced(v)
                        } else {
                            has_unterminated_quote(v)
                        }
                    };
                    while unclosed(acc.trim()) && j + 1 < lines.len() {
                        j += 1;
                        acc.push(' ');
                        acc.push_str(split_at_comment(lines[j]).0.trim());
                    }
                    out.push(format!("{prefix}{acc}"));
                    for _ in (i + 1)..=j {
                        out.push(String::new());
                    }
                    i = j + 1;
                    continue;
                }
            }
        }

        // PLAIN multi-line scalar: `command: echo uno` continued by MORE-indented lines. Legal YAML
        // and the one multi-line form kern used to refuse outright ("expected `key: value`").
        //
        // A continuation line must NOT contain a top-level `: ` - in block context YAML forbids that
        // inside a plain scalar precisely because it is ambiguous with a mapping. Keeping that guard
        // means an over-indented KEY still fails loudly (an indentation typo cannot be swallowed into
        // the previous value), while genuine prose/command continuations fold. A `- ` line is a
        // sequence entry and also stops the fold.
        // A SEQUENCE ENTRY folds the same way, and used not to. The branch below only fired on a
        // `key: value` line, so `- EMAIL_BODY_TEXT="Im Anhang ...` continued on the next line died as
        // `expected key: value`. `flow_intro` already handles a `- ` entry whose value OPENS with a
        // quote; this one opens the quote in the MIDDLE (`KEY="text`), which YAML reads as a plain
        // scalar where the quote is an ordinary character, and plain scalars fold. Measured on
        // `emysliwietz/latex-email-daemon` from the corpus.
        let fold_value = match colon_index(code) {
            Some(ci) => Some(code[ci + 1..].trim()),
            None => code
                .trim_start()
                .strip_prefix("- ")
                .map(str::trim)
                .filter(|v| !v.is_empty()),
        };
        if let Some(value) = fold_value {
            let is_block = block_intro(code).is_some();
            let is_flow = value.starts_with('[') || value.starts_with('{');
            if !value.is_empty() && !is_block && !is_flow {
                let mut acc = String::new();
                let mut j = i;
                while j + 1 < lines.len() {
                    let nl = lines[j + 1];
                    if nl.trim().is_empty() {
                        break;
                    }
                    let nc = split_at_comment(nl).0;
                    let ni = nc.len() - nc.trim_start_matches(' ').len();
                    let nt = nc.trim();
                    // `- ` AND A BARE `-`, NOT ANY LEADING DASH. A block sequence entry is a dash
                    // followed by whitespace, or a dash alone on the line; `--source`, `-drive` and
                    // `-netdev` are plain scalars and YAML folds them. Breaking on the first `-`
                    // character refused exactly the continuations that carry command-line flags,
                    // which is the form every long `command:` and every QEMU argument list takes -
                    // the compose files complex enough to be worth proving kern handles.
                    //
                    // MEASURED against PyYAML on the case from `adrianursu/s7pot`: a real parser
                    // reads `command: python3 x.py` + `--source a.json` + `--output b.ndjson` as one
                    // scalar, kern answered `expected key: value` at the first continuation. Six
                    // files of a 240-compose corpus died here.
                    //
                    // AND THE COMMENT ABOVE ALREADY SAID `- `, WITH THE SPACE. The intent was written
                    // down correctly and the code did not implement it, which is why re-reading this
                    // function never found the defect: the prose and the predicate disagreed, and the
                    // prose is what a reader checks.
                    let is_seq_entry = nt == "-" || nt.starts_with("- ") || nt.starts_with("-\t");
                    if ni <= indent
                        || is_seq_entry
                        || colon_index(nc).is_some()
                        || block_intro(nc).is_some()
                    {
                        break;
                    }
                    acc.push(' ');
                    acc.push_str(nt);
                    j += 1;
                }
                if j > i {
                    out.push(format!("{}{acc}", raw.trim_end()));
                    for _ in (i + 1)..=j {
                        out.push(String::new());
                    }
                    i = j + 1;
                    continue;
                }
            }
        }

        out.push(raw.to_string());
        i += 1;
    }
    Ok(out.join("\n"))
}

/// A block-scalar introducer → (line prefix up to & including the `key:`/`- ` marker, is-folded `>`).
/// What a block scalar does with the line breaks at its END.
///
/// The indicator was PARSED AND DISCARDED: `|`, `|-` and `|+` all produced the same value, so an
/// author who wrote `+` on purpose got `-` behaviour and nothing said so. MEASURED on an
/// `environment` value of `ab`: all three yielded 2 bytes, where YAML says 3, 2 and 4.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Chomp {
    /// Default: exactly one trailing line break is kept.
    Clip,
    /// `-`: no trailing line break.
    Strip,
    /// `+`: every trailing line break is kept.
    Keep,
}

fn block_intro(code: &str) -> Option<(String, bool, Chomp)> {
    let indicator = |v: &str| -> Option<(bool, Chomp)> {
        let mut c = v.chars();
        let folded = match c.next()? {
            '|' => false,
            '>' => true,
            _ => return None,
        };
        // The rest is the (optional) chomping indicator and an explicit indentation digit, in either
        // order per the spec. The digit is read and ignored, as before: this parser derives the block
        // indentation from the first body line, which is what every real compose file relies on.
        let mut chomp = Chomp::Clip;
        for ch in c {
            match ch {
                '-' => chomp = Chomp::Strip,
                '+' => chomp = Chomp::Keep,
                d if d.is_ascii_digit() => {}
                _ => return None,
            }
        }
        Some((folded, chomp))
    };
    // A TAG MAY SIT BEFORE THE INDICATOR (`command: !!str |`). The tag is stripped for the scan and
    // kept out of the folded value, exactly as it is for a plain scalar; see `without_str_tag`.
    fn after_tag(v: &str) -> &str {
        without_str_tag(v).unwrap_or(v)
    }
    if let Some(ci) = colon_index(code) {
        if let Some((f, ch)) = indicator(after_tag(code[ci + 1..].trim())) {
            return Some((format!("{}: ", &code[..ci]), f, ch));
        }
    }
    let trimmed = code.trim_start();
    let indent = &code[..code.len() - trimmed.len()];
    if let Some(rest) = trimmed.strip_prefix("- ") {
        if let Some((f, ch)) = indicator(after_tag(rest.trim())) {
            return Some((format!("{indent}- "), f, ch));
        }
    }
    None
}

/// A bare `key:` (no inline value) → its `"key: "` prefix, for folding a following-line value onto it.
fn key_only(code: &str) -> Option<String> {
    let ci = colon_index(code)?;
    code[ci + 1..]
        .trim()
        .is_empty()
        .then(|| format!("{}: ", &code[..ci]))
}

/// A value that spans lines: a flow collection `[`/`{` unbalanced on its line, OR a quoted string whose
/// closing quote is on a later line (YAML folds the break to a space). → (prefix, opening fragment).
fn flow_intro(code: &str) -> Option<(String, String)> {
    let opens = |v: &str| {
        ((v.starts_with('[') || v.starts_with('{')) && !brackets_balanced(v))
            || ((v.starts_with('"') || v.starts_with('\'')) && has_unterminated_quote(v))
    };
    if let Some(ci) = colon_index(code) {
        let v = code[ci + 1..].trim();
        if opens(v) {
            return Some((format!("{}: ", &code[..ci]), v.to_string()));
        }
    }
    let trimmed = code.trim_start();
    let indent = &code[..code.len() - trimmed.len()];
    if let Some(rest) = trimmed.strip_prefix("- ") {
        let v = rest.trim();
        if opens(v) {
            return Some((format!("{indent}- "), v.to_string()));
        }
    }
    None
}

/// Reject structural YAML we don't support, up front, with a precise reason. This is the billion-laughs
/// / tab-indent / multi-doc guard - cheaper and safer than parsing-then-detecting.
/// Is this value introduced by the `!!str` tag, as a whole token?
///
/// `!!str` is the one explicit type tag this parser accepts, and refusing it was refusing a file
/// whose semantics it already implements: every value here is carried as a RAW STRING and coerced by
/// whoever consumes it, never by the parser, so "read this scalar as a string" asks for exactly what
/// already happens. Every other `!!` still fails - `!!float`, `!!int`, `!!binary` request a
/// conversion nothing here performs, and accepting one would mean accepting a file and then doing
/// something else with it.
///
/// A WHOLE TOKEN, not a prefix: `!!strange` is not `!!str`, and treating it as one would silently
/// swallow a tag kern cannot honour.
fn is_str_tag(v: &str) -> bool {
    without_str_tag(v).is_some()
}

/// The value with a leading `!!str` removed, or `None` when there is no such tag.
///
/// THE SAME TOKEN RULE AS [`is_str_tag`], in one function, because a second reader appeared: a block
/// scalar may carry the tag before its indicator (`command: !!str |`), and the indicator scan has to
/// look PAST the tag to find the `|`. Written as its own `strip_prefix` at that call site, the two
/// would have been free to disagree about what counts as the tag.
///
/// MEASURED DEFECT THIS EXISTS TO FIX: `command: !!str |` with a body was not folded at all, because
/// the scan required the value to BEGIN with `|`. The literal `|` then survived into the value, and
/// the service tried to execute a program called `|`. It was invisible while a string command was
/// wrapped in `sh -c`, where it merely became a shell syntax error at run time.
fn without_str_tag(v: &str) -> Option<&str> {
    let rest = v.strip_prefix("!!str")?;
    (rest.is_empty() || rest.starts_with(char::is_whitespace)).then(|| rest.trim_start())
}

/// The refusal for `!!str` applied to a list or a map, in one place because two call sites reach it
/// from opposite directions: the flow forms (`!!str [a, b]`, `!!str {a: b}`) are visible on the tag's
/// own line, the block form is only visible on the line AFTER it.
///
/// The message names the node kind rather than the tag, because the tag is not the mistake - `!!str`
/// over a scalar is accepted. Removing it is the fix in every case, so the message says so.
fn str_tag_on_collection(ln: usize) -> String {
    format!("line {ln}: `!!str` applies to a list/map (it can only tag a scalar); remove the tag")
}

fn prescreen(text: &str) -> Result<(), String> {
    let mut seen_content = false; // has a real (non-comment, non-marker) line appeared yet?
                                  // A `key: !!str` with NOTHING after the tag, remembered as (line number, indent width) until the
                                  // next content line tells us what the tag was actually applied to. `key: !!str` alone is an empty
                                  // string and legal; `key: !!str` followed by a deeper-indented block collection applies the tag to
                                  // a sequence or a map, which is not a scalar and not something this parser can honour. Only the
                                  // NEXT line distinguishes the two, so the decision has to wait for it. See `str_tag_on_collection`.
    let mut bare_str_tag: Option<(usize, usize)> = None;
    for (i, raw) in text.lines().enumerate() {
        let ln = i + 1;
        // Strip a trailing comment for this scan (a `#` inside quotes is handled by the lexer; here we
        // only need to catch structural markers, and those never live inside quotes in a real compose).
        let line = strip_comment_rough(raw);
        let t = line.trim_start();
        if t.is_empty() {
            continue;
        }
        // Tab INDENTATION is invalid YAML and a classic parser trap - refuse rather than guess. Only
        // the indentation, though: a tab is an ordinary character everywhere else, and the previous
        // rule ("this line has leading spaces AND contains a tab anywhere") refused
        // `image:<TAB>alpine`, which is valid, with a message that pointed at the indentation. A
        // script pasted into a block scalar is full of tabs and would have been refused for the same
        // reason. Measured before the fix: `image:\talpine` answered "line 3: tab indentation not
        // supported".
        let indent = &line[..line.len() - line.trim_start().len()];
        if indent.contains('\t') {
            return Err(format!(
                "line {ln}: tab indentation not supported (use spaces)"
            ));
        }
        // Resolve a `!!str` left pending by the previous line: if THIS line is nested under that key,
        // the tag sits on a block collection, not on a scalar. Deeper indentation is the test, and it
        // holds for both shapes a block collection can take (`  - a` and `  a: b`). A line at the same
        // indent or shallower ends the key, which means the tag was on an empty scalar - legal, and
        // what every YAML reader makes of `key: !!str` with nothing after it.
        if let Some((tag_ln, tag_indent)) = bare_str_tag.take() {
            if indent.len() > tag_indent {
                return Err(str_tag_on_collection(tag_ln));
            }
        }
        // A `---`/`...` marker: a LEADING one (only comments/blanks before it - as a licensed header
        // like Apache Airflow's produces) is a document-start and fine; one AFTER real content begins a
        // SECOND document, which we don't read.
        if t == "---" || t == "..." {
            if !seen_content {
                continue;
            }
            return Err(format!(
                "line {ln}: multi-document YAML not supported (kern reads one compose per file)"
            ));
        }
        seen_content = true;
        // A folded block scalar (`fold_multiline` marked it with U+0001) is an OPAQUE value - its bytes
        // are shell-script text, not YAML structure. Skip every value-scanning check for it.
        if line.contains(BLOCK_NL) {
            continue;
        }
        // Block-level anchors (`key: &c`), aliases (`key: *c`) and merge keys (`<<: *c` / `<<: [*a,*b]`)
        // ARE supported - `resolve_anchors` expands them after the tree is built, under a hard node
        // budget (`MAX_ANCHOR_NODES`) that defuses the billion-laughs bomb the old refusal guarded
        // against. Only anchors/aliases nested INSIDE a flow collection (`[*x]`, `{k: *x}`) remain
        // unsupported - `line_has_inline_anchor` below still refuses those.
        if let Some(v) = value_after_colon(line) {
            let vt = v.trim();
            if vt == "|"
                || vt == ">"
                || vt.starts_with("|-")
                || vt.starts_with(">-")
                || vt.starts_with("|+")
                || vt.starts_with(">+")
            {
                return Err(format!(
                    "line {ln}: block scalars (`|`/`>`) not supported (use a single-line value)"
                ));
            }
        }
        // An anchor/alias as a TOKEN inside an inline collection - `[*x]`, `[a, *x]`, `{k: *x}`. An alias
        // nested inside `[…]`/`{…}` would otherwise reach the box as the literal `*x`. EXCEPTION: a merge
        // key with an alias-LIST value (`<<: [*a, *b]`, and the `<< :` spacing) is the standard way to
        // merge several templates - `resolve_anchors` expands it, so it's allowed. Everything else with
        // an aliased flow token is refused.
        let is_merge_line = colon_index(line).map(|ci| line[..ci].trim()) == Some("<<");
        if !is_merge_line && line_has_inline_anchor(line) {
            return Err(format!(
                "line {ln}: an anchor or alias INSIDE a flow collection (`[*x]`, `{{k: *x}}`) is \
                 not expanded. Block-level anchors, aliases and merge keys are: write `<<: *x`, or \
                 the sequence as block items. If this line has no anchor in it, look for an \
                 unclosed `[` or `{{` earlier in the value: it makes a later `&` or `*` read as one"
            ));
        }
        // Explicit type tags (`!!str`, `!!float`, …) - refuse ONLY when the tag is at value position
        // (right after `key:`), not when `!!` appears inside a value's text (a `WARNING!!!` in a shell
        // command, an image tag, …), which is a plain scalar and perfectly fine.
        //
        // `!!str` IS THE EXCEPTION, and refusing it was refusing a file whose semantics this parser
        // already implements. Every value here is carried as a raw string and coerced by whoever
        // consumes it, never by the parser, so "read this scalar as a string" is a request for what
        // already happens. The tag is stripped and the value parsed as usual; every OTHER `!!` still
        // fails, because `!!float`, `!!int`, `!!binary` and friends ask for a conversion nothing here
        // performs, and accepting them would mean accepting a file and doing something else with it.
        //
        // And `!!str` is honoured only over a SCALAR, which is the only node a "read this as a string"
        // request means anything for. Over a collection it was accepted and then quietly meant
        // something else - the exact outcome this paragraph says it refuses. Measured against PyYAML
        // 6.0.1 before the guard existed:
        //
        //     command: !!str [sh, -c, "echo A"]   PyYAML ConstructorError   kern ACCEPTED, box DIED
        //     command: !!str {a: b}               PyYAML ConstructorError   kern ACCEPTED, box DIED
        //     command: !!str \n  - sh \n  - -c    PyYAML ConstructorError   kern ACCEPTED, box RAN
        //     command: !!str echo E               PyYAML 'echo E'           kern 'echo E'      OK
        //
        // The third line is the one that decided this: it SUCCEEDS, with the tag dropped and the
        // sequence read as a list, so nothing anywhere tells the author their file was reinterpreted.
        // The flow forms were not caught by the unbalanced-`[` guard below either, because that guard
        // asks whether the value STARTS with `[` and after a tag it starts with `!`.
        if let Some(v) = value_after_colon(line) {
            let v = v.trim_start();
            if v.starts_with("!!") && !is_str_tag(v) {
                return Err(format!("line {ln}: YAML type tags (`!!`) not supported"));
            }
            if is_str_tag(v) {
                let rest = v["!!str".len()..].trim();
                if rest.starts_with('[') || rest.starts_with('{') {
                    return Err(str_tag_on_collection(ln));
                }
                if rest.is_empty() {
                    // Nothing on this line to apply the tag to. Whether that is an empty scalar or a
                    // block collection is decided by the next content line, at the top of this loop.
                    bare_str_tag = Some((ln, indent.len()));
                }
            }
        }
        // Unbalanced inline collection at value position - a `[` / `{` that doesn't close on the same
        // line. Without this a `command: [unterminated` would be SILENTLY accepted as the single
        // element `[unterminated` (a lie: a malformed list treated as valid). Refuse it explicitly.
        if let Some(v) = value_after_colon(line) {
            let vt = v.trim();
            if (vt.starts_with('[') || vt.starts_with('{')) && !brackets_balanced(vt) {
                return Err(format!(
                    "line {ln}: unbalanced `[`/`{{` in an inline value (unterminated list/map)"
                ));
            }
            // A value that OPENS with a quote must close it on the line (`image: "alpine`). Without
            // this the stray-quoted value is taken literally and fails later with a confusing
            // downstream error (a garbage image name → "no layers in manifest"). Only enforce closure
            // when the value STARTS quoted - an unquoted scalar may legitimately contain a bare
            // apostrophe (`command: don't`), which is not an opened string.
            if (vt.starts_with('"') || vt.starts_with('\'')) && has_unterminated_quote(vt) {
                return Err(format!("line {ln}: unterminated quoted string"));
            }
        }
    }
    Ok(())
}

/// True if `s` opens a `"` or `'` quote that is never closed. Double-quoted strings honor a `\"`
/// escape (YAML basic strings); single-quoted YAML strings have no backslash escapes (a literal `\`),
/// so a `'` always closes them. Called only for a value that STARTS with a quote, so a bare apostrophe
/// in an unquoted scalar (`don't`) is not misread as an opened string.
fn has_unterminated_quote(s: &str) -> bool {
    let mut q: Option<char> = None;
    let mut esc = false;
    for c in s.chars() {
        match q {
            Some('"') => {
                if esc {
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else if c == '"' {
                    q = None;
                }
            }
            Some(_) => {
                if c == '\'' {
                    q = None;
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    q = Some(c);
                }
            }
        }
    }
    q.is_some()
}

/// Are `[`/`]` and `{`/`}` balanced in `s`, ignoring brackets inside quotes? Depth never goes negative
/// and returns to zero. Used to reject an inline collection that isn't closed on its line.
fn brackets_balanced(s: &str) -> bool {
    let mut depth = 0i32;
    let mut q: Option<char> = None;
    for c in s.chars() {
        if let Some(qc) = q {
            if c == qc {
                q = None;
            }
        } else {
            match c {
                '"' | '\'' => q = Some(c),
                '[' | '{' => depth += 1,
                ']' | '}' => {
                    depth -= 1;
                    if depth < 0 {
                        return false;
                    }
                }
                _ => {}
            }
        }
    }
    depth == 0 && q.is_none()
}

/// Byte index of the FIRST top-level key-terminating `:` in `line` (not inside quotes, followed by
/// end-of-line or whitespace), or `None`. The single source of truth for "where does the key end" -
/// both `value_after_colon` and `split_key` derive from it, so key/value slicing can't drift. `:` is
/// ASCII, so the returned index is always a char boundary.
fn colon_index(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut q = 0u8; // 0 = none, else the quote char
    for (i, &c) in bytes.iter().enumerate() {
        if q != 0 {
            if c == q {
                q = 0;
            }
        } else if c == b'"' || c == b'\'' {
            q = c;
        } else if c == b':'
            && (i + 1 >= bytes.len() || bytes[i + 1] == b' ' || bytes[i + 1] == b'\t')
        {
            return Some(i);
        }
    }
    None
}

/// The substring of `line` after the key-terminating `:` (see [`colon_index`]), or `None` if none.
fn value_after_colon(line: &str) -> Option<&str> {
    colon_index(line).map(|i| &line[i + 1..])
}

/// True if `line` contains a YAML anchor (`&x`) or alias (`*x`) as a structural TOKEN (`[*x]`,
/// `[a, *x]`, `{k: *x}`, `{&a k: v}`) - as opposed to a `&`/`*` that is ordinary scalar text
/// (`my*repo`, `2*2`, `a&b`, or anything inside quotes).
///
/// Closed BY CONSTRUCTION, not by enumerating openers. A `&`/`*` outside quotes starts a token - and
/// is therefore an anchor/alias - iff it is NOT preceded (ignoring spaces) by *scalar content*. The
/// complement is the whole trick: if the previous significant byte is scalar content (alphanumeric or
/// the plain-scalar punctuation `_ - . / %% @ + ~`), the `&`/`*` is part of a value; otherwise it opens
/// one - after a separator/opener (`[ { , :`), a `-` list marker, at line start, whatever. Defining
/// "starts a token" (rather than listing the openers that can precede one) means any present-or-future
/// flow separator is covered, and the fuzz can PROVE completeness (no unflagged token-opening `&`/`*`)
/// instead of trusting a hand-kept opener list - the same move as `IpAddr::is_loopback()` for the push
/// loopback check: a canonical definition, not a maintained enumeration.
fn line_has_inline_anchor(line: &str) -> bool {
    fn is_scalar_content(b: u8) -> bool {
        b.is_ascii_alphanumeric()
            || matches!(b, b'_' | b'-' | b'.' | b'/' | b'%' | b'@' | b'+' | b'~')
    }
    let mut q = 0u8; // active quote char, else 0
    let mut prev_content = false; // was the last non-space significant byte scalar content?
    let mut depth = 0i32; // flow-collection nesting: inside `[…]` / `{…}`
    for &c in line.as_bytes() {
        if q != 0 {
            if c == q {
                q = 0;
                prev_content = false; // a closing quote ends a scalar; the quote is not content
            }
            continue;
        }
        match c {
            b'"' | b'\'' => {
                q = c;
                prev_content = false; // an opening quote starts a NEW scalar, not a continuation
            }
            b' ' | b'\t' => {} // spaces don't change whether the last token was content
            b'[' | b'{' => {
                depth += 1;
                prev_content = false;
            }
            b']' | b'}' => {
                depth = (depth - 1).max(0);
                prev_content = true; // a closed collection is content-like
            }
            b'&' | b'*' => {
                // A token-opening `&`/`*` INSIDE a flow collection (`[*x]`, `{k: *x}`) is an anchor/alias
                // we still don't expand - refuse it. A block-level one (`<<: *c`, `key: *c`, `k: &c`) is
                // now supported (see `resolve_anchors`), so at depth 0 it is NOT flagged here.
                if !prev_content && depth > 0 {
                    return true;
                }
                prev_content = true;
            }
            other => prev_content = is_scalar_content(other),
        }
    }
    false
}

/// The code part of `line` with any trailing `#` comment removed (quote-aware, `#` at BOL or after
/// whitespace). A thin wrapper over the one comment scanner, [`split_at_comment`], so the prescreen,
/// the lexer, and the interpolation pass can never drift on where a comment starts.
fn strip_comment_rough(line: &str) -> &str {
    split_at_comment(line).0
}

/// One lexed line: its indentation (in spaces) and content (comment-stripped, right-trimmed).
struct Line {
    lineno: usize,
    indent: usize,
    content: String,
}

/// Lex the document into non-blank, comment-stripped lines with their space-indent measured.
fn lex(text: &str) -> Result<Vec<Line>, String> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let ln = i + 1;
        if raw.trim() == "---" || raw.trim() == "..." {
            continue; // document markers (prescreen already bounded to the first doc)
        }
        // A folded block scalar carries literal `#`s (shell comments) inside its U+0001-joined body -
        // do NOT run the comment scanner over it, or the body would be truncated at the first `#`.
        let stripped = if raw.contains(BLOCK_NL) {
            raw.to_string()
        } else {
            strip_comment_precise(raw)
        };
        if stripped.trim().is_empty() {
            continue;
        }
        let indent = stripped.len() - stripped.trim_start_matches(' ').len();
        out.push(Line {
            lineno: ln,
            indent,
            content: stripped.trim().to_string(),
        });
    }
    Ok(out)
}

/// The code part of `line` (comment removed), owned, with leading indentation preserved (the lexer
/// measures indent after). A thin wrapper over the one comment scanner, [`split_at_comment`].
fn strip_comment_precise(line: &str) -> String {
    split_at_comment(line).0.to_string()
}

/// A parsed node: a scalar value and/or child mappings and/or list items. YAML is a tree; we model the
/// slice we need - a mapping (`children`) whose values may be scalars, nested mappings, or sequences.
#[derive(Default, Clone)]
struct Node {
    /// Inline scalar on the same line as the key (`image: alpine` → `"alpine"`), if any.
    scalar: Option<String>,
    /// Child mappings, in document order (`key -> node`). Order-preserving for determinism.
    children: Vec<(String, Node)>,
    /// Sequence items (`- x`) as raw scalar strings, in order.
    items: Vec<String>,
    /// A YAML anchor `&name` declared on this node (stripped from the value at parse time). Resolved
    /// away by [`resolve_anchors`] into aliases (`*name`) and merge keys (`<<: *name`); never survives
    /// into a `ComposeBox`.
    anchor: Option<String>,
}

impl Node {
    fn child(&self, key: &str) -> Option<&Node> {
        self.children.iter().find(|(k, _)| k == key).map(|(_, n)| n)
    }
}

/// Build the mapping tree from lexed lines using an explicit indentation stack (iterative - no
/// recursion, so a deeply-nested document can't overflow the stack; `MAX_DEPTH` caps it anyway).
fn build_tree(lines: &[Line]) -> Result<Node, String> {
    let mut root = Node::default();
    // `path` = child-index chain from root to the CURRENTLY-OPEN mapping; `cols[k]` = the indentation
    // column of the key that opened `path[k]`. Invariant: a child at column C belongs to the deepest
    // open mapping whose opening column is < C. Before placing a line we pop every open level whose
    // column is >= C (they've ended). Iterative - deep nesting can't overflow the stack.
    let mut path: Vec<usize> = Vec::new();
    let mut cols: Vec<usize> = Vec::new();
    // A block-mapping list item being folded into an inline `{…}` string (long-form ports etc.):
    // (path to the owning node, index in its `items`, the dash column). `None` when no item-map is open.
    // Continuation lines (deeper `key: value`) append to it; anything else closes it (appends `}`).
    let mut item_map: Option<(Vec<usize>, usize, usize)> = None;

    for ln in lines {
        // Close an open block-mapping item if this line is NOT its continuation (same path, deeper
        // indent, `key: value`). Closing appends the `}` so `reconstruct_port_item` sees a valid inline.
        if let Some((im_path, im_idx, im_col)) = item_map.clone() {
            let is_continuation =
                im_path == path && ln.indent > im_col && colon_index(&ln.content).is_some();
            if !is_continuation {
                descend_mut(&mut root, &im_path).items[im_idx].push('}');
                item_map = None;
            } else {
                let acc = &mut descend_mut(&mut root, &path).items[im_idx];
                acc.push_str(", ");
                acc.push_str(&ln.content);
                continue;
            }
        }

        // A YAML sequence item is a dash FOLLOWED BY WHITESPACE (`- x`) or a bare `-` (empty). A dash
        // NOT followed by space is part of a key - e.g. `--net:` is a (bad) key, NOT the list item
        // `-net:`. Matching a bare `strip_prefix('-')` mis-parsed `--net:` as a list item; require the
        // space/EOL boundary. Decided BEFORE the dedent below, which needs to know.
        let is_list_item = ln.content == "-"
            || ln
                .content
                .strip_prefix('-')
                .is_some_and(|r| r.starts_with([' ', '\t']));

        // Dedent / sibling: pop levels whose opening column is >= this line's column.
        //
        // A LIST ITEM POPS ONLY ON A STRICTLY SMALLER COLUMN, because YAML lets a block sequence sit
        // at ITS KEY'S OWN indentation - the `-` is itself an indentation indicator:
        //
        //     ports:
        //     - "8080:80"
        //
        // That is not an exotic spelling. It is what `docker compose config` prints, what PyYAML and
        // every other dumper emit, and how a large share of hand-written files are written. Under the
        // `<=` rule the `ports:` level was popped by its own first item, so the items landed on the
        // PARENT mapping, where nothing reads them: the key parsed, the value vanished, and kern said
        // NOTHING. MEASURED on a two-service file written that way: `ports`, `depends_on`, `volumes`,
        // `environment` and `command` all silently empty, `kern compose config` printing a service
        // with no ports and no dependencies, exit 0. Found while running Zabbix, whose `healthcheck.
        // test` is written this way and was reported "not convertible" - the only visible symptom of
        // a defect that is otherwise completely quiet.
        let pop_at_equal = !is_list_item;
        while let Some(&c) = cols.last() {
            if ln.indent < c || (pop_at_equal && ln.indent == c) {
                path.pop();
                cols.pop();
            } else {
                break;
            }
        }
        if path.len() > MAX_DEPTH {
            return Err(format!(
                "line {}: nesting too deep (max {MAX_DEPTH})",
                ln.lineno
            ));
        }

        // List item: append to the mapping that opened the current level.
        if is_list_item {
            let item = ln.content[1..].trim();
            if item.is_empty() {
                // AN EMPTY ITEM IS NOT A SYNTAX ERROR, IN YAML OR IN COMPOSE, AND REFUSING IT COST A
                // WHOLE CLASS OF REAL FILES.
                //
                // YAML: a bare `-` is a NULL entry. PyYAML reads `a:\n  - \n  - x` as
                // `{'a': [None, 'x']}`, so the file kern was calling malformed is one a real parser
                // accepts without comment.
                //
                // Compose: an unset variable interpolates to the empty string, which is how the item
                // becomes empty in practice. `- ${DOCKERNETWORK}` with nothing in the environment is
                // the shape, and it is everywhere: seven files of a 240-compose corpus died here, all
                // of them `networks:`/`dns:`/`security_opt:` entries written against a `.env` the
                // reader does not have. Docker warns that the variable is not set and carries on.
                //
                // SKIPPED, NOT KEPT AS "". A network, a dns server or a security option named by the
                // empty string is not a thing that exists; carrying `""` downstream would turn a
                // clear parse-time complaint into an obscure runtime one. Dropping it is the reading
                // that matches YAML's `null` and leaves the rest of the file usable.
                warn(&format!(
                    "line {}: empty list item (an unset `${{VAR}}` or a bare `-`) - skipped",
                    ln.lineno
                ));
                continue;
            }
            let cur = descend_mut(&mut root, &path);
            // A list item that is itself a `key: value` (a block-mapping element, e.g. the long-form
            // `- target: 443` with `published: 8443` on the next deeper line) opens a mapping. Model it
            // WITHOUT a full list-of-maps type: start folding it into an inline `{k: v, …}` string that
            // `reconstruct_port_item` already parses; continuation lines append (see the loop top),
            // and it's closed with `}` when the mapping ends. A plain scalar item is pushed as-is.
            if colon_index(item).is_some() {
                cur.items.push(format!("{{{item}"));
                item_map = Some((path.clone(), cur.items.len() - 1, ln.indent));
            } else {
                cur.items.push(item.to_string());
            }
            continue;
        }

        // A bare `&anchor` on its OWN line anchors the currently-open mapping. This is the form Apache
        // Airflow (and others) use: `x-common:` then an indented `&common` then the mapping's keys -
        // the anchor decorates the node, not a `key: value`. `resolve_anchors` consumes it.
        if ln.content.starts_with('&') && colon_index(&ln.content).is_none() {
            let after = ln.content[1..].trim();
            let name_len = after.find(char::is_whitespace).unwrap_or(after.len());
            descend_mut(&mut root, &path).anchor = Some(after[..name_len].to_string());
            continue;
        }

        // `key:` or `key: value`.
        let (key, val) = split_key(&ln.content, ln.lineno)?;
        let mut node = Node::default();
        // Peel a leading anchor `&name` off the value. What remains is the real value - often empty
        // (`x-common: &common` then a nested mapping on the following lines), so it must reset `inline`
        // to `None` and let the key open a mapping as usual. `resolve_anchors` consumes `node.anchor`.
        let val = match val {
            Some(v) if v.trim_start().starts_with('&') => {
                let after = v.trim_start()[1..].trim_start();
                let name_len = after
                    .find(|c: char| c.is_whitespace())
                    .unwrap_or(after.len());
                node.anchor = Some(after[..name_len].to_string());
                Some(after[name_len..].trim_start())
            }
            other => other,
        };
        let inline = val.filter(|v| !v.is_empty());
        if let Some(v) = inline {
            let vt = v.trim();
            // ALWAYS keep the raw value as `scalar` - a converter that wants the verbatim value
            // (`environment`, where `CFG: {"k":"v"}` is a JSON string that must NOT be structured) reads
            // it as-is. ADDITIONALLY, for an inline TABLE (`{…}`), also parse it into `children`, so a
            // converter that wants structure (`healthcheck`/`depends_on`/`build`) reads children. Keeping
            // BOTH avoids the two-sided bug: an inline table was dropped when only-scalar (env/health/
            // conditions vanished), and a JSON env value was over-structured when only-children (the
            // env var came out empty). Each converter picks the representation it needs.
            node.scalar = Some(v.to_string());
            if vt.starts_with('{') {
                let parsed = parse_inline_table(vt);
                node.children = parsed.children;
            }
        }
        let cur = descend_mut(&mut root, &path);
        cur.children.push((key.to_string(), node));
        // No inline scalar → this key opens a nested mapping/sequence: push it as the new open level.
        if inline.is_none() {
            let idx = cur.children.len() - 1;
            path.push(idx);
            cols.push(ln.indent);
        }
    }
    // Close a block-mapping list item still open at end-of-document.
    if let Some((im_path, im_idx, _)) = item_map {
        descend_mut(&mut root, &im_path).items[im_idx].push('}');
    }
    Ok(root)
}

/// Walk `root` down the child-index `path`, returning `&mut` to the addressed node.
fn descend_mut<'a>(root: &'a mut Node, path: &[usize]) -> &'a mut Node {
    let mut cur = root;
    for &idx in path {
        cur = &mut cur.children[idx].1;
    }
    cur
}

/// Expand YAML anchors/aliases/merge keys in the built tree, in place - so no converter ever sees a raw
/// `*alias`. Pass 1 records every `&name` node (children-first, so a nested anchor is known before an
/// outer one merges it), stripping the marker. Pass 2 substitutes each `*name` value and folds each
/// `<<: *name` mapping, cloning the recorded node and resolving IT too - all spending one shared
/// `MAX_ANCHOR_NODES` budget, so a self-referential bomb is refused rather than followed.
fn resolve_anchors(root: &mut Node) -> Result<(), String> {
    let mut anchors: std::collections::HashMap<String, Node> = std::collections::HashMap::new();
    collect_anchors(root, &mut anchors);
    // Always apply - even with no anchors defined, a stray `*alias` must surface as a clear "unknown
    // anchor" error, never reach a box as the literal string `*alias`.
    let mut budget = MAX_ANCHOR_NODES;
    apply_anchors(root, &anchors, &mut budget)
}

/// Record `&name` → the node it decorates (its children already stripped of their own markers),
/// removing the marker from the live tree. Children-first so an inner anchor is registered first.
fn collect_anchors(node: &mut Node, anchors: &mut std::collections::HashMap<String, Node>) {
    for (_, child) in &mut node.children {
        collect_anchors(child, anchors);
    }
    if let Some(name) = node.anchor.take() {
        anchors.insert(name, node.clone());
    }
}

/// Nodes in a subtree (mappings + sequence items) - what an expansion spends from the budget.
fn count_nodes(node: &Node) -> usize {
    1 + node.items.len()
        + node
            .children
            .iter()
            .map(|(_, c)| count_nodes(c))
            .sum::<usize>()
}

fn spend(budget: &mut usize, n: usize) -> Result<(), String> {
    *budget = budget.checked_sub(n).ok_or_else(|| {
        "YAML anchor expansion too large (possible billion-laughs bomb) - refused".to_string()
    })?;
    Ok(())
}

/// The anchor names a merge value references: `*c` → `["c"]`, `[*a, *b]` → `["a","b"]`.
fn merge_alias_names(scalar: &str) -> Vec<String> {
    let s = scalar.trim();
    let inner = s
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(s);
    inner
        .split(',')
        .filter_map(|t| t.trim().strip_prefix('*'))
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .collect()
}

/// In-place alias substitution + `<<` merge, recursively, against the collected `anchors`.
fn apply_anchors(
    node: &mut Node,
    anchors: &std::collections::HashMap<String, Node>,
    budget: &mut usize,
) -> Result<(), String> {
    // Merge keys: fold each `<<: *name` (or `<<: [*a, *b]`) into this node. A key ALREADY on the node
    // wins over the merged one (YAML merge semantics); among sources the earlier alias wins. `<<` is
    // then dropped. `src` is resolved before merging, so its own aliases/merges are already gone.
    let mut i = 0;
    while i < node.children.len() {
        if node.children[i].0 == "<<" {
            let scalar = node.children[i].1.scalar.clone().unwrap_or_default();
            node.children.remove(i);
            for name in merge_alias_names(&scalar) {
                let src = anchors
                    .get(&name)
                    .ok_or_else(|| format!("unknown YAML anchor `*{name}` in a `<<` merge"))?;
                let mut src = src.clone();
                spend(budget, count_nodes(&src))?;
                apply_anchors(&mut src, anchors, budget)?;
                for (ck, cv) in src.children {
                    if !node.children.iter().any(|(ek, _)| *ek == ck) {
                        node.children.push((ck, cv));
                    }
                }
            }
            continue; // children[i] is now the next sibling
        }
        i += 1;
    }
    // Value aliases (`key: *name`) and recursion into ordinary children.
    for (_, child) in &mut node.children {
        let alias = child
            .scalar
            .as_deref()
            .and_then(|s| s.trim().strip_prefix('*').map(|n| n.trim().to_string()));
        if let Some(name) = alias {
            let src = anchors
                .get(&name)
                .ok_or_else(|| format!("unknown YAML anchor `*{name}`"))?;
            let mut src = src.clone();
            spend(budget, count_nodes(&src))?;
            apply_anchors(&mut src, anchors, budget)?;
            *child = src;
        } else {
            apply_anchors(child, anchors, budget)?;
        }
    }
    // Sequence-item aliases (`- *name`): inline a SCALAR anchor's value. An unknown alias, an alias to
    // a MAPPING (no scalar to inline), or an ANCHOR in list position (`- &x …`) are all hard errors -
    // never left as the literal `*name`/`&x` string (the silent mis-conversion the module forbids).
    for item in &mut node.items {
        let t = item.trim();
        if let Some(rest) = t.strip_prefix('*') {
            let name = rest.trim().to_string();
            let src = anchors
                .get(&name)
                .ok_or_else(|| format!("unknown YAML anchor `*{name}`"))?;
            let sc = src.scalar.clone().ok_or_else(|| {
                format!("YAML alias `*{name}` refers to a mapping - not usable as a list item")
            })?;
            *item = sc;
        } else if t.starts_with('&') {
            return Err("YAML anchors in a sequence item are not supported".to_string());
        }
    }
    Ok(())
}

/// Resolve Compose `extends:` - a service inheriting another service's fields, in this file
/// (`extends: base`, `extends: {service: base}`) or in ANOTHER (`extends: {file: b.yaml, service:
/// base}`). Merge is SHALLOW and the extending service WINS on a key conflict - the same rule kern
/// uses for `<<` merge - resolved transitively (A extends B extends C) with a cycle guard that spans
/// files.
///
/// CROSS-FILE USED TO BE A REFUSAL ("inline the base service"), and inlining is exactly what a
/// project cannot do when the base file is the thing it maintains. MEASURED on Zabbix's own stack:
/// 17 services, every one of them an `extends` into `compose_zabbix_components.yaml`, so the file
/// its maintainers run daily did not start at all. The refusal was honest and complete: it named
/// the construct and stopped, which is why this is a missing feature and not a defect.
///
/// `dir` is the directory of the file being parsed - `file:` resolves against it, per the
/// Specification, and against nothing else. With no directory (a string parsed in a test, stdin)
/// there is nothing to resolve from, and the refusal says that instead of guessing a cwd.
fn resolve_extends(
    root: &mut Node,
    dir: Option<&std::path::Path>,
    dotenv: &crate::DotEnv,
) -> Result<(), String> {
    // One cache and one chain for the whole pass: Zabbix's 17 services all extend into the SAME
    // file, and parsing it once per service would read and interpolate a 725-line document
    // seventeen times. The chain is shared for a stronger reason - a cycle can leave this file and
    // come back, and only a chain that crosses files can see it. Each service still starts from the
    // state it left (push/pop are symmetric), so sharing costs no accuracy.
    let mut loaded: Vec<(std::path::PathBuf, Node)> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    resolve_extends_in(root, dir, dotenv, &mut loaded, &mut seen)
}

fn resolve_extends_in(
    root: &mut Node,
    dir: Option<&std::path::Path>,
    dotenv: &crate::DotEnv,
    loaded: &mut Vec<(std::path::PathBuf, Node)>,
    seen: &mut Vec<String>,
) -> Result<(), String> {
    let Some(si) = root.children.iter().position(|(k, _)| k == "services") else {
        return Ok(());
    };
    // Nothing to resolve if no service uses `extends` - and that is almost every file. Without this
    // guard the pass still ran once per service, and each run scanned every service to find its index:
    // O(N^2) paid by files that never asked for the feature.
    if !root.children[si]
        .1
        .children
        .iter()
        .any(|(_, svc)| svc.children.iter().any(|(k, _)| k == "extends"))
    {
        return Ok(());
    }
    let names: Vec<String> = root.children[si]
        .1
        .children
        .iter()
        .map(|(k, _)| k.clone())
        .collect();
    for name in &names {
        resolve_service_extends(&mut root.children[si].1, name, seen, dir, dotenv, loaded)?;
    }
    Ok(())
}

/// The keys a service NEVER inherits through `extends`, per the Specification: they name OTHER
/// services, and copying them would give the extending service dependencies and links its author
/// never wrote - in a different file, against services that may not even exist there.
const EXTENDS_NOT_INHERITED: &[&str] = &["depends_on", "links", "external_links", "volumes_from"];

/// How deep an `extends` chain may go before it is treated as a mistake. A real chain is one or two
/// links; this exists so a hostile pair of files cannot drive unbounded recursion, and it is checked
/// in ADDITION to the exact-cycle guard (which catches the honest case with a better message).
const MAX_EXTENDS_DEPTH: usize = 32;

/// Load another compose file as a node tree, ready to be extended from: interpolated with the same
/// `.env`, folded, prescreened, anchor-expanded, and with its OWN `extends` already resolved
/// relative to ITS directory. Cached by path within one parse.
fn load_extends_base<'a>(
    path: &std::path::Path,
    dotenv: &crate::DotEnv,
    loaded: &'a mut Vec<(std::path::PathBuf, Node)>,
    seen: &mut Vec<String>,
) -> Result<&'a Node, String> {
    if let Some(i) = loaded.iter().position(|(p, _)| p == path) {
        return Ok(&loaded[i].1);
    }
    if seen.len() > MAX_EXTENDS_DEPTH {
        return Err(format!(
            "`extends` chains more than {MAX_EXTENDS_DEPTH} files deep - refusing to follow further"
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("`extends` reads {}: {e}", path.display()))?;
    let folded = fold_multiline(&text)?;
    prescreen(&folded)?;
    // The SAME `.env`, because a base file is written with the same variables as the file that
    // extends it - Zabbix's components file is `${ZABBIX_SERVER_PGSQL_IMAGE}` from end to end. A
    // `${VAR:?}` it requires is collected by the same thread-local and reported with the rest.
    let interpolated = interpolate_document(&folded, dotenv);
    let lines = lex(&interpolated)?;
    let mut root = build_tree(&lines)?;
    resolve_anchors(&mut root)?;
    // ITS extends, from ITS directory: a base file may extend a third file next to itself. The
    // cache and the chain travel with it, which is what makes a cycle through two files visible
    // instead of a recursion that runs until the stack ends (measured: it did).
    resolve_extends_in(&mut root, path.parent(), dotenv, loaded, seen)?;
    loaded.push((path.to_path_buf(), root));
    let last = loaded.len() - 1;
    Ok(&loaded[last].1)
}

/// What an `extends` names: a service, and the file it lives in when that is not this one.
#[derive(Debug, PartialEq, Eq)]
struct ExtendsTarget {
    service: String,
    /// `file:` verbatim, as written. Resolved against the EXTENDING file's directory by the caller,
    /// which is the only place that knows what that directory is.
    file: Option<String>,
}

/// The target of an `extends` node: the scalar short form (`extends: base`), or the map form's
/// `service:` plus optional `file:`.
fn extends_target(n: &Node) -> Result<ExtendsTarget, String> {
    // STRUCTURED form first. A flow mapping (`extends: {service: b}`) carries BOTH the expanded
    // `children` and the raw `{…}` text as a scalar; reading the scalar first took that raw text as a
    // service NAME and reported "unknown service '{file: base.yml, service: b}'" instead of resolving
    // it (or giving the honest cross-file message below).
    if n.children.is_empty() {
        if let Some(s) = n.scalar.as_deref().map(str::trim) {
            // The short form is a bare service name; a leftover `{…}` is a mapping we failed to expand,
            // never a name - fall through to the structured errors rather than inventing a target.
            if !s.is_empty() && !s.starts_with('{') {
                return Ok(ExtendsTarget {
                    service: s.to_string(),
                    file: None,
                });
            }
        }
    }
    let value_of = |key: &str| -> Option<String> {
        n.children
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.scalar.as_deref())
            .map(|s| scalar_str(s.trim()))
            .filter(|s| !s.is_empty())
    };
    let file = value_of("file");
    if let Some(service) = value_of("service") {
        return Ok(ExtendsTarget { service, file });
    }
    // A `file:` with no `service:` names a document, not a service: there is nothing to inherit.
    Err(
        "`extends` needs a service name (`extends: base`, `extends: {service: base}` or \
         `extends: {file: other.yaml, service: base}`)"
            .to_string(),
    )
}

/// Resolve one service's `extends`, first expanding the target (so chains fully flatten), then folding
/// the target's keys in where this service doesn't already define them.
///
/// `seen` carries the chain being resolved, so a cycle is named rather than followed - and it holds
/// `file#service` keys, because a cycle can leave this file and come back.
fn resolve_service_extends(
    services: &mut Node,
    name: &str,
    seen: &mut Vec<String>,
    dir: Option<&std::path::Path>,
    dotenv: &crate::DotEnv,
    loaded: &mut Vec<(std::path::PathBuf, Node)>,
) -> Result<(), String> {
    let Some(idx) = services.children.iter().position(|(k, _)| k == name) else {
        return Ok(());
    };
    let Some(ep) = services.children[idx]
        .1
        .children
        .iter()
        .position(|(k, _)| k == "extends")
    else {
        return Ok(());
    };
    let target = extends_target(&services.children[idx].1.children[ep].1)?;
    // The parent's keys, from this file or from the one it names.
    let parent = match &target.file {
        None => {
            if target.service == name || seen.iter().any(|s| s == name) {
                return Err(format!("circular `extends` involving service '{name}'"));
            }
            seen.push(name.to_string());
            let r = resolve_service_extends(services, &target.service, seen, dir, dotenv, loaded);
            seen.pop();
            r?;
            let Some(tidx) = services
                .children
                .iter()
                .position(|(k, _)| k == &target.service)
            else {
                return Err(format!(
                    "service '{name}' extends unknown service '{}'",
                    target.service
                ));
            };
            services.children[tidx].1.children.clone()
        }
        Some(f) => {
            // RESOLVED AGAINST THE EXTENDING FILE'S DIRECTORY, which the Specification requires and
            // a cwd would only accidentally match: `kern compose -f ../stack/compose.yaml` runs from
            // somewhere else entirely.
            let Some(dir) = dir else {
                return Err(format!(
                    "service '{name}' extends `{f}`, but this stack was not read from a file on \
                     disk, so there is no directory to resolve `{f}` against"
                ));
            };
            let path = dir.join(f);
            let key = format!("{}#{}", path.display(), target.service);
            if seen.contains(&key) {
                return Err(format!(
                    "circular `extends` involving service '{}' in {}",
                    target.service,
                    path.display()
                ));
            }
            seen.push(key);
            let base = load_extends_base(&path, dotenv, loaded, seen);
            let out = base.and_then(|root| {
                root.child("services")
                    .and_then(|s| s.child(&target.service))
                    .map(|svc| svc.children.clone())
                    .ok_or_else(|| {
                        format!(
                            "service '{name}' extends '{}' in {}, which has no such service",
                            target.service,
                            path.display()
                        )
                    })
            });
            seen.pop();
            out?
        }
    };
    // Drop the `extends` key now that it's being resolved, then fold the base in underneath.
    services.children[idx].1.children.remove(ep);
    let base: Vec<(String, Node)> = parent
        .into_iter()
        .filter(|(pk, _)| pk != "extends" && !EXTENDS_NOT_INHERITED.contains(&pk.as_str()))
        .collect();
    fold_base_into(&mut services.children[idx].1, base, "");
    Ok(())
}

/// Fold a base service's keys into the service extending it, by the Compose Specification's merge
/// rules: a mapping gains the base's missing entries and merges the conflicting ones, a sequence is
/// the base's items followed by the extending service's, and a scalar the extending service sets
/// wins outright.
///
/// IT USED TO BE "WHOLE KEY, CHILD WINS", which is right for a scalar and wrong for everything else.
/// MEASURED on Zabbix: `server-pgsql` extends `server` and then writes `networks: {backend:
/// {aliases: […]}}` purely to add an alias. Replacing the key dropped the `database` network the
/// base put it on, so kern reported that its Zabbix server and its PostgreSQL "share no network and
/// do not resolve each other" - a stack that cannot work, produced from a file that does.
///
/// `path` is the key path being merged (empty at the service level), for the one exception that
/// needs to know where it is: `healthcheck.test`.
fn fold_base_into(child: &mut Node, base: Vec<(String, Node)>, path: &str) {
    for (bk, bv) in base {
        let Some(pos) = child.children.iter().position(|(ck, _)| *ck == bk) else {
            child.children.push((bk, bv));
            continue;
        };
        // SHELL COMMANDS ARE REPLACED, NEVER APPENDED - the Specification names the three, and the
        // reason is plain: two concatenated argv run neither program.
        let full = if path.is_empty() {
            bk.clone()
        } else {
            format!("{path}.{bk}")
        };
        if matches!(full.as_str(), "command" | "entrypoint" | "healthcheck.test") {
            continue;
        }
        let slot = &mut child.children[pos].1;
        if !bv.children.is_empty() {
            fold_base_into(slot, bv.children, &full);
            continue;
        }
        if !bv.items.is_empty() {
            // The base's items first, then the extending service's - "appending values from the
            // overriding file to the previous one".
            let mut merged = bv.items;
            // UNIQUE RESOURCES: `volumes`, `secrets` and `configs` are keyed by their TARGET, so an
            // entry the extending service writes for a target REPLACES the base's rather than
            // mounting twice over the same path.
            if matches!(bk.as_str(), "volumes" | "secrets" | "configs") {
                let targets: Vec<String> = slot.items.iter().map(|i| mount_target(i)).collect();
                merged.retain(|b| !targets.contains(&mount_target(b)));
            } else {
                // Everything else appends, minus exact duplicates: a repeated `- backend` or
                // `- K=V` says nothing the first one did not.
                merged.retain(|b| !slot.items.contains(b));
            }
            merged.extend(std::mem::take(&mut slot.items));
            slot.items = merged;
            continue;
        }
        // A scalar the extending service already set: it wins, which is the one part of the old
        // rule that was right.
    }
}

/// The TARGET of a mount-shaped entry (`src:target[:opts]`, `target`, or `name:target`), which is
/// the key the Specification makes these sequences unique on. Bare entries (an anonymous volume, a
/// secret named without a target) are their own target.
fn mount_target(entry: &str) -> String {
    let e = scalar_str(entry.trim());
    match e.split(':').nth(1) {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => e,
    }
}

/// Split a `key: value` line into `(key, Some(value))` or a bare `key:` into `(key, Some(""))`.
/// Quote-aware on the key side so a quoted key with a `:` is handled; the value keeps its raw form
/// (unquoted here - `scalar_str` unquotes at use).
fn split_key(content: &str, lineno: usize) -> Result<(&str, Option<&str>), String> {
    let Some(colon) = colon_index(content) else {
        return Err(format!("line {lineno}: expected `key: value`"));
    };
    // Slice at the colon index directly - no length arithmetic, so no risk of an unsigned underflow
    // if the helpers ever change. `colon` and `colon + 1` are ASCII-`:` boundaries.
    let key = strip_quotes(content[..colon].trim());
    if key.is_empty() {
        return Err(format!("line {lineno}: empty key"));
    }
    Ok((key, Some(content[colon + 1..].trim())))
}

/// Strip one layer of matching single/double quotes from a scalar, if present. YAML single-quotes
/// don't process escapes; double-quotes do, but for compose values (paths, images, commands) we treat
/// the inner text verbatim - no numeric coercion, no escape expansion - which is exactly what we want
/// (verbatim → the sexagesimal trap can't fire, and argv values reach `kern box` unmodified).
fn strip_quotes(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// A scalar value as an owned, unquoted string, with the quoting style's escapes decoded.
///
/// YAML 1.2 gives the two quote styles different rules and the difference is not cosmetic: in a
/// DOUBLE-quoted scalar `\n` is a line feed, in a SINGLE-quoted one it is a backslash and an `n`.
/// This used to strip the quotes and stop, so `command: ["sh","-c","a\nb"]` handed the process a
/// literal `a\nb` where Docker Compose hands it two lines. The program then failed for a reason
/// nothing in the file explained.
///
/// Deliberate deviation, stated rather than hidden: an UNKNOWN escape (`\q`) is kept verbatim,
/// where a strict parser errors. Keeping it cannot change the meaning of any file that works
/// today, and this landed close to a release; erroring is the more correct behaviour and is the
/// thing to revisit, not a decision to leave undocumented.
fn scalar_str(s: &str) -> String {
    let t = s.trim();
    // `!!str` is stripped HERE, at the single place a scalar becomes a value, so every consumer sees
    // the same thing and none of them has to know the tag existed. See `is_str_tag` for why this one
    // tag is honoured and the others are refused.
    if let Some(rest) = t.strip_prefix("!!str") {
        if rest.is_empty() || rest.starts_with(char::is_whitespace) {
            return scalar_str(rest);
        }
    }
    let b = t.as_bytes();
    let dq = b.len() >= 2 && b[0] == b'"' && b[b.len() - 1] == b'"';
    let sq = b.len() >= 2 && b[0] == b'\'' && b[b.len() - 1] == b'\'';
    // Decode a folded block scalar's U+0001 line-break sentinel back to a real newline.
    if dq {
        decode_double_quoted(&t[1..t.len() - 1])
            .replace(BLOCK_NL, "\n")
            .replace(UNSET_MARK, "")
    } else if sq {
        // Single quotes take no backslash escapes at all; `''` is the only one, and it means `'`.
        t[1..t.len() - 1]
            .replace("''", "'")
            .replace(BLOCK_NL, "\n")
            .replace(UNSET_MARK, "")
    } else {
        t.replace(BLOCK_NL, "\n").replace(UNSET_MARK, "")
    }
}

/// Decode the escapes YAML 1.2 defines for a double-quoted scalar (§5.7), over the body with the
/// quotes already removed.
fn decode_double_quoted(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut it = body.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(e) = it.next() else {
            // A trailing lone backslash: keep it rather than swallow a character that is there.
            out.push('\\');
            break;
        };
        match e {
            '0' => out.push('\0'),
            'a' => out.push('\u{7}'),
            'b' => out.push('\u{8}'),
            't' | '\t' => out.push('\t'),
            'n' => out.push('\n'),
            'v' => out.push('\u{b}'),
            'f' => out.push('\u{c}'),
            'r' => out.push('\r'),
            'e' => out.push('\u{1b}'),
            ' ' => out.push(' '),
            '"' => out.push('"'),
            '/' => out.push('/'),
            '\\' => out.push('\\'),
            'N' => out.push('\u{85}'),
            '_' => out.push('\u{a0}'),
            'L' => out.push('\u{2028}'),
            'P' => out.push('\u{2029}'),
            'x' | 'u' | 'U' => {
                let want = match e {
                    'x' => 2,
                    'u' => 4,
                    _ => 8,
                };
                // Peek exactly `want` hex digits WITHOUT consuming on failure: a malformed `\uZZ`
                // stays verbatim instead of eating the characters after it.
                let rest: String = it.clone().take(want).collect();
                match u32::from_str_radix(&rest, 16)
                    .ok()
                    .filter(|_| rest.chars().count() == want)
                    .and_then(char::from_u32)
                {
                    Some(ch) => {
                        for _ in 0..want {
                            it.next();
                        }
                        out.push(ch);
                    }
                    None => {
                        out.push('\\');
                        out.push(e);
                    }
                }
            }
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    out
}

/// Parse a YAML inline table `{k: v, k2: {…}, k3: [a, b]}` into a [`Node`] with `children`. Values that
/// are themselves inline tables recurse; inline lists / scalars are stored as the child's `scalar`
/// (the value converters already parse a `[…]` scalar). Depth- and quote-aware comma split; slicing on
/// ASCII delimiters only. This is what makes `healthcheck: {…}` / `environment: {…}` / `depends_on:
/// {…}` all work from the inline form, uniformly.
fn parse_inline_table(s: &str) -> Node {
    let mut node = Node::default();
    let inner = s
        .trim()
        .strip_prefix('{')
        .and_then(|x| x.strip_suffix('}'))
        .unwrap_or(s);
    for entry in split_top_commas(inner) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some(colon) = colon_index_or_first(entry) else {
            continue;
        };
        let key = scalar_str(&entry[..colon]);
        if key.is_empty() {
            continue;
        }
        let val = entry[colon + 1..].trim();
        let mut child = Node::default();
        if val.starts_with('{') {
            child = parse_inline_table(val); // nested table (e.g. depends_on's `{condition: …}`)
        } else if !val.is_empty() {
            child.scalar = Some(val.to_string()); // scalar or inline list `[…]`
        }
        node.children.push((key, child));
    }
    node
}

/// The index of the first `:` in an inline-table entry that separates key from value - quote-aware so
/// a `:` inside a quoted key/value doesn't split early. Unlike `colon_index` (which requires the `:`
/// be followed by space/EOL, YAML block rule), an inline-table `{k:v}` may have no space, so we take
/// the first top-level unquoted `:`.
fn colon_index_or_first(s: &str) -> Option<usize> {
    let mut q: Option<char> = None;
    let mut depth = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            _ if Some(c) == q => q = None,
            '"' | '\'' if q.is_none() => q = Some(c),
            '{' | '[' if q.is_none() => depth += 1,
            '}' | ']' if q.is_none() => depth -= 1,
            ':' if q.is_none() && depth == 0 => return Some(i),
            _ => {}
        }
    }
    None
}

/// Is a node's scalar a YAML truthy (`true`/`yes`/`on`/`1`)? For boolean compose keys like `read_only`.
fn scalar_is_true(node: &Node) -> bool {
    node.scalar
        .as_deref()
        .map(scalar_str)
        .map(|s| matches!(s.to_ascii_lowercase().as_str(), "true" | "yes" | "on" | "1"))
        .unwrap_or(false)
}

/// Parse an inline YAML list `[a, b, "c d"]` OR a block list (already collected in `node.items`) into a
/// vec of unquoted strings. Depth-aware split so a nested `[]`/`{}` inside an item isn't broken on its
/// commas; quote-aware so a comma inside quotes is preserved.
fn parse_inline_list(s: &str) -> Vec<String> {
    let s = s.trim();
    let inner = s
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(s);
    split_top_commas(inner)
        .into_iter()
        .map(scalar_str)
        .filter(|x| !x.is_empty())
        .collect()
}

/// Which kind of quoted scalar the scanner is inside, if any.
///
/// AN ENUM AND NOT THE QUOTE CHARACTER. The state used to be `Option<char>`, which admits every
/// `char` in the language while only two are reachable, so the scanner needed a branch for a state
/// that cannot exist. The two variants also behave DIFFERENTLY, which is the actual reason to name
/// them: YAML escapes are not one rule.
#[derive(Clone, Copy)]
enum Quoted {
    /// `"…"`: backslash escapes, per YAML 1.2 §5.7.
    Double,
    /// `'…'`: no backslash escape exists; `''` is a literal quote.
    Single,
}

/// Split on top-level commas: a comma inside a quoted scalar or inside a nested `[...]`/`{...}` does
/// not split.
///
/// ## The defect this replaced
///
/// The scanner tracked quotes and NOT escapes. Inside `"…"`, a `\"` was read as the closing quote,
/// so the scanner believed it had left the string, and the next comma split the value in half.
///
/// It reached users through compose healthchecks, where it is expensive: `healthcheck.test` in the
/// `["CMD-SHELL", "…"]` form is taken as `rest.first()`, so a truncated split silently hands the
/// health-checker a FRAGMENT of the command. The fragment fails, the service is marked `unhealthy`
/// forever while answering traffic correctly, and `depends_on: condition: service_healthy` - the one
/// feature built to trust that verdict - never opens. Measured, two services differing only in the
/// health string, everything else identical:
///
/// ```text
/// test: ["CMD-SHELL", "exit 0"]                                       -> healthy
/// test: ["CMD-SHELL", "sh -c \"echo hi, there\" >/dev/null; exit 0"] -> unhealthy
/// ```
///
/// Both commands exit 0. The second contains an escaped quote followed by a comma, which is the
/// ordinary shape of a Python or shell one-liner, and it is why a simple `pg_isready` check passed
/// while a real one did not: the difference was never CMD-SHELL.
///
/// ## Why the two quote styles are not one rule
///
/// YAML gives them different escapes, and treating them alike would trade this defect for another:
///
///   * `"…"` takes backslash escapes. `\"` is a quote that does not close, and `\\` is a backslash
///     that does not escape the character after it.
///   * `'…'` takes NO backslash escape at all. The single escape is `''`, meaning one literal quote,
///     and a `\` inside is an ordinary character. Applying backslash logic here would make
///     `'C:\path\'` swallow the closing quote and run the scan off the end of the value.
///
/// `scalar_str` already draws this distinction when it DECODES a scalar; this is the same rule
/// applied where the scalar's BOUNDARIES are found. The two had to agree and did not.
///
/// Returns borrowed slices: the items are handed straight to `trim`/`split_once`/`scalar_str`, all of
/// which take `&str`, so the owned copy this used to build per item was never read as an owned value.
fn split_top_commas(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut q: Option<Quoted> = None;
    let mut start = 0usize;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        match q {
            Some(Quoted::Double) => {
                if c == '\\' {
                    // Consume the escaped character WHOLE. This is what makes `\"` not close the
                    // scalar, and equally what makes `\\` not turn the next `"` into an escape.
                    // A trailing lone backslash simply ends the iteration: `next()` yields `None`
                    // and the loop stops, so there is no index to run past.
                    let _ = it.next();
                } else if c == '"' {
                    q = None;
                }
            }
            Some(Quoted::Single) => {
                // A LONE `'` CLOSES, AND `''` NEEDS NO SPECIAL CASE HERE - which is not obvious and
                // is why it is written down rather than left as an omission.
                //
                // YAML's only escape inside single quotes is `''`, one literal quote, and the first
                // version of this consumed the pair to stay inside the scalar. That code could not
                // change a single answer: `''` is TWO quote characters, so reading it as
                // close-then-open leaves the scanner inside or outside at exactly the same
                // positions. Parity is preserved, every split decision is identical, and an
                // injected removal of it stayed green on 584 constructed inputs because there is
                // nothing to catch.
                //
                // Code that cannot affect the output is code a reader will believe does something,
                // and the comment on it claimed a correctness it was not providing. The pair DOES
                // matter where a scalar is DECODED - `scalar_str` turns `''` into `'` - and that is
                // the function that owns the rule. This one only finds boundaries.
                if c == '\'' {
                    q = None;
                }
            }
            None => {
                if c == '"' {
                    q = Some(Quoted::Double);
                } else if c == '\'' {
                    q = Some(Quoted::Single);
                } else if c == '[' || c == '{' {
                    depth += 1;
                } else if c == ']' || c == '}' {
                    // CLAMPED AT ZERO. An unmatched closer is malformed input, and letting the
                    // depth go negative would make every comma after it stop splitting - one stray
                    // character silently swallowing the rest of the line. Refusing to go below the
                    // top level costs nothing on well-formed input, where the counter is balanced.
                    if depth > 0 {
                        depth -= 1;
                    }
                } else if c == ',' && depth == 0 {
                    out.push(&s[start..i]);
                    // `len_utf8` and not `+ 1`: the comma is one byte, but deriving the step from
                    // the character is what keeps this correct if the separator ever is not.
                    start = i + c.len_utf8();
                }
            }
        }
    }
    out.push(&s[start..]);
    out
}

/// A list value for a compose key: either the inline `[…]` scalar or the block `- ` items.
/// Collect `networks.<net>.aliases` across every network of a service's `networks:` node (the map
/// form `networks: {net: {aliases: [db, …]}}`). The list form (`networks: [net]`) has no aliases →
/// empty. Order-stable and de-duplicated.
/// Parse a Docker duration (`10s`, `1m30s`, `2h`, `500ms`, or a bare number of seconds) into SECONDS.
///
/// Compose writes durations, kern's flag takes seconds. The combined forms are the ones that bite: a
/// naive "strip the last unit" reading turns `1m30s` into 0, which would silently mean "no graceful
/// phase" for a service whose author asked for ninety seconds.
///
/// Sub-second values round UP to 1 s: someone writing `500ms` asked for a graceful phase, and 0 would
/// remove it entirely. An unparsable value yields 0, which the caller reports through the flag's own
/// validation rather than guessing a default here.
fn duration_secs(v: &str) -> u64 {
    let t = v.trim();
    if let Ok(n) = t.parse::<u64>() {
        return n; // bare number = seconds
    }
    let (mut total, mut num, mut seen) = (0u64, 0u64, false);
    let mut chars = t.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(d) = c.to_digit(10) {
            num = num.saturating_mul(10).saturating_add(d as u64);
            seen = true;
            continue;
        }
        let unit_secs = match c {
            'h' => 3600,
            'm' => {
                // `ms` is milliseconds, `m` alone is minutes.
                if chars.peek() == Some(&'s') {
                    chars.next();
                    total = total.saturating_add(num.div_ceil(1000).max(1));
                    num = 0;
                    seen = false;
                    continue;
                }
                60
            }
            's' => 1,
            _ => return 0, // unknown unit: refuse to guess
        };
        total = total.saturating_add(num.saturating_mul(unit_secs));
        num = 0;
        seen = false;
    }
    // A trailing bare number (`1m30`) counts as seconds, matching the bare-number case above.
    if seen {
        total = total.saturating_add(num);
    }
    total
}

/// Split a YAML **flow mapping** (`{a: 1, b: {c: 2}}`) into its TOP-LEVEL `key → value` pairs.
///
/// The block form arrives as parsed `children`; the flow form arrives as one opaque scalar, and
/// treating it as a plain string is how `sysctls: {net.core.somaxconn: 1500}` reached the box as a
/// single unparsable argument. Real compose files use both spellings, so both must resolve to the
/// same thing.
///
/// Splitting tracks brace/bracket DEPTH, so a nested value (`nofile: {soft: 1, hard: 2}`) stays whole
/// and a comma inside it is not a separator. The key ends at the first TOP-LEVEL `:`, which keeps a
/// value that itself contains colons (a URL label, an IPv6 address) intact. Returns an empty vec for
/// anything that is not a flow mapping, so callers can fall through to their other forms.
fn parse_inline_map(s: &str) -> Vec<(String, String)> {
    let t = s.trim();
    let Some(body) = t.strip_prefix('{').and_then(|b| b.strip_suffix('}')) else {
        return Vec::new();
    };
    // Top-level comma split.
    let mut items: Vec<&str> = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (i, c) in body.char_indices() {
        match c {
            '{' | '[' => depth += 1,
            '}' | ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                items.push(&body[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    items.push(&body[start..]);

    let unquote = |v: &str| -> String {
        let v = v.trim();
        v.strip_prefix('"')
            .and_then(|r| r.strip_suffix('"'))
            .or_else(|| v.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')))
            .unwrap_or(v)
            .to_string()
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        // First TOP-LEVEL ':' separates key from value.
        let mut d = 0usize;
        let mut cut = None;
        for (i, c) in item.char_indices() {
            match c {
                '{' | '[' => d += 1,
                '}' | ']' => d = d.saturating_sub(1),
                ':' if d == 0 => {
                    cut = Some(i);
                    break;
                }
                _ => {}
            }
        }
        let Some(cut) = cut else { continue }; // no `k: v` shape - skip, never guess
        let k = unquote(&item[..cut]);
        if !k.is_empty() {
            out.push((k, unquote(&item[cut + 1..])));
        }
    }
    out
}

/// `extra_hosts:` → kern `--add-host` specs, normalised to `name:ip`.
///
/// Docker accepts three spellings and all three appear in real files:
///   `extra_hosts: ["api.local:10.0.0.5"]`   (list, colon)
///   `extra_hosts: ["api.local=10.0.0.5"]`   (list, equals - the newer spelling)
///   `extra_hosts: {api.local: 10.0.0.5}`    (mapping)
/// An entry with no separator cannot name a host AND an address, so it is dropped with a warning
/// instead of being forwarded: kern would refuse the whole box over one malformed line, and a stack
/// that fails to start is worse than one host alias missing (which the warning names precisely).
/// A `key: value` mapping (or an already-joined `key<sep>value` list) flattened to `key<sep>value`
/// strings. Used for `sysctls:`, which Docker accepts in both shapes.
fn collect_kv(node: &Node, sep: char) -> Vec<String> {
    // ONE source wins, in this order - they must never be summed. The lexer already expands a FLOW
    // mapping (`{a: 1}`) into `children`, while `list_value` still hands back the raw `{a: 1}` text:
    // consulting both appended that raw text as if it were an entry, and the box received
    // `--sysctl {net.core.somaxconn: 1500}` (a hard error) or an unusable label.
    if !node.children.is_empty() {
        return node
            .children
            .iter()
            .map(|(k, def)| {
                let v = def.scalar.as_deref().map(scalar_str).unwrap_or_default();
                format!("{k}{sep}{v}")
            })
            .collect();
    }
    if let Some(sc) = &node.scalar {
        let pairs = parse_inline_map(sc);
        if !pairs.is_empty() {
            return pairs
                .into_iter()
                .map(|(k, v)| format!("{k}{sep}{v}"))
                .collect();
        }
    }
    // List form: `- KEY=VALUE`.
    list_value(node)
        .into_iter()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .collect()
}

/// `ulimits:` → `NAME=SOFT:HARD` specs. Docker allows a scalar (`nofile: 1024`, meaning soft == hard)
/// and a mapping (`nofile: {soft: 20000, hard: 40000}`); a mapping missing one bound reuses the other,
/// which is what Docker does and keeps `soft <= hard` true by construction. Values are NOT validated
/// here - the box owns the resource-name table and the bounds check, so there is exactly one authority.
fn collect_ulimits(node: &Node, svc: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    // Flow mapping, flat (`{nofile: 1024}`) or nested (`{nofile: {soft: 1, hard: 2}}`). Silently
    // dropping it (the pre-fix behaviour) meant a limit the operator wrote was simply not in force.
    if node.children.is_empty() {
        if let Some(sc) = &node.scalar {
            for (name, val) in parse_inline_map(sc) {
                let inner = parse_inline_map(&val);
                if inner.is_empty() {
                    if !val.trim().is_empty() {
                        out.push(format!("{name}={}", val.trim()));
                    }
                    continue;
                }
                let get = |k: &str| {
                    inner
                        .iter()
                        .find(|(ik, _)| ik == k)
                        .map(|(_, v)| v.trim().to_string())
                        .filter(|v| !v.is_empty())
                };
                match (get("soft"), get("hard")) {
                    (Some(s), Some(h)) => out.push(format!("{name}={s}:{h}")),
                    (Some(s), None) => out.push(format!("{name}={s}")),
                    (None, Some(h)) => out.push(format!("{name}={h}")),
                    (None, None) => warn(&format!(
                    "service '{svc}': ulimits '{name}' has neither a value nor soft/hard - ignored"
                )),
                }
            }
            if !out.is_empty() {
                return out;
            }
        }
    }
    for (name, def) in &node.children {
        // Scalar form: `nofile: 1024`.
        if let Some(sc) = &def.scalar {
            let v = scalar_str(sc);
            if !v.trim().is_empty() {
                out.push(format!("{name}={}", v.trim()));
                continue;
            }
        }
        // Mapping form: `nofile: {soft: N, hard: M}`.
        let get = |k: &str| -> Option<String> {
            def.child(k)
                .and_then(|n| n.scalar.as_deref())
                .map(scalar_str)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        match (get("soft"), get("hard")) {
            (Some(s), Some(h)) => out.push(format!("{name}={s}:{h}")),
            (Some(s), None) => out.push(format!("{name}={s}")),
            (None, Some(h)) => out.push(format!("{name}={h}")),
            (None, None) => warn(&format!(
                "service '{svc}': ulimits '{name}' has neither a value nor soft/hard - ignored"
            )),
        }
    }
    out
}

fn collect_extra_hosts(node: &Node, svc: &str) -> Vec<String> {
    // Normalise `name=ip` / `name:ip` to kern's `name:ip`, splitting on the FIRST separator so an
    // IPv6 value keeps its colons.
    let norm = |entry: &str, out: &mut Vec<String>| {
        let entry = entry.trim();
        if entry.is_empty() {
            return;
        }
        let cut = match (entry.find('='), entry.find(':')) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => {
                warn(&format!(
                    "service '{svc}': extra_hosts entry '{entry}' has no ':' or '=' separator - ignored"
                ));
                return;
            }
        };
        let (host, ip) = (entry[..cut].trim(), entry[cut + 1..].trim());
        if host.is_empty() || ip.is_empty() {
            warn(&format!(
                "service '{svc}': extra_hosts entry '{entry}' is incomplete - ignored"
            ));
            return;
        }
        out.push(format!("{host}:{ip}"));
    };

    let mut out: Vec<String> = Vec::new();
    // ONE source, in precedence order - summing them would append the raw `{...}` text of a flow
    // mapping that the lexer has already expanded into `children`.
    if !node.children.is_empty() {
        for (host, def) in &node.children {
            let ip = def.scalar.as_deref().map(scalar_str).unwrap_or_default();
            if host.is_empty() || ip.trim().is_empty() {
                warn(&format!(
                    "service '{svc}': extra_hosts entry '{host}' has no address - ignored"
                ));
                continue;
            }
            out.push(format!("{host}:{}", ip.trim()));
        }
        return out;
    }
    if let Some(sc) = &node.scalar {
        let pairs = parse_inline_map(sc);
        if !pairs.is_empty() {
            for (host, ip) in pairs {
                if !host.is_empty() && !ip.trim().is_empty() {
                    out.push(format!("{host}:{}", ip.trim()));
                }
            }
            return out;
        }
    }
    for raw in list_value(node) {
        norm(&raw, &mut out);
    }
    out
}

/// The network names a service declares, in BOTH spellings compose allows.
///
/// The mapping form (`networks: {rete: {aliases: [...]}}`) puts the names in `children`; the list
/// form (`networks: [rete_a, rete_b]`) puts them in `items`. Reading only one of the two would make
/// the internal-network decision below depend on how the author wrote the file, and the list form is
/// the more common of the two.
fn collect_net_names(networks: &Node) -> Vec<String> {
    if !networks.children.is_empty() {
        return networks
            .children
            .iter()
            .map(|(n, _)| n.trim().to_string())
            .filter(|n| !n.is_empty())
            .collect();
    }
    list_value(networks)
        .into_iter()
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .collect()
}

/// The top-level networks marked `internal: true`.
///
/// Collected from the whole document before any service is read, the same way `collect_secret_files`
/// is, because the top-level `networks:` block may appear AFTER `services:` in the file and a
/// single-pass decision would then depend on key order.
/// Top-level `volumes:` entries declared `external: true`, as `compose key -> the name kern must
/// mount`.
///
/// THE MAP IS NOT AN IDENTITY, and treating it as one would make the check and the mount disagree.
/// A declaration may carry `name:` to point at a volume whose real name differs from the key the
/// services write (`pgdata: {external: true, name: prod_pgdata}`), and then the volume that has to
/// exist is `prod_pgdata` while every service says `pgdata`. Returning the pair lets the caller
/// rewrite the mount and check the same string.
///
/// `external:` also has a long form (`external: {name: x}`), which is deprecated by the Compose
/// Specification but still in the wild; it declares external-ness by its presence, so it counts.
///
/// THE OVERRIDE NAME IS VALIDATED AS A VOLUME NAME, and the first version was not. MEASURED: with
/// `name: /var/tmp/x` the rewrite produced the `-v` source `/var/tmp/x`, which kern's `-v` classifier
/// reads as a HOST PATH, and the box bind-mounted that directory and read a file out of it. A compose
/// file can already ask for a bind mount in the service's own `volumes:` list, so this granted no
/// capability the file did not have - but it moved the request out of the line a reader looks at and
/// into a top-level block, and Docker would refuse it outright (there `name:` is a volume name and
/// never a path). Refusing matches Docker and keeps the mount legible where it is written.
fn collect_external_volumes(
    root: &Node,
) -> Result<std::collections::HashMap<String, String>, String> {
    let mut out = std::collections::HashMap::new();
    let Some(vols) = root.child("volumes") else {
        return Ok(out);
    };
    for (key, def) in &vols.children {
        let Some(ext) = def.child("external") else {
            continue;
        };
        // `external: false` is the default written out, and it is NOT a declaration of external-ness.
        if ext.scalar.is_some() && !scalar_is_true(ext) {
            continue;
        }
        // `name:` at either level: the modern spelling is a sibling of `external:`, the deprecated
        // one is nested under it.
        let renamed = def
            .child("name")
            .or_else(|| ext.child("name"))
            .and_then(|n| n.scalar.as_deref())
            .map(scalar_str)
            .filter(|s| !s.is_empty());
        let key = key.trim().to_string();
        let real = renamed.unwrap_or_else(|| key.clone());
        if !kern_common::valid_resource_name(&real) {
            return Err(format!(
                "volume '{key}' declares `name: {real}`, which is not a volume name (letters, \
                 digits, `_`, `.` and `-` only, no leading `-` or `.`, at most 64 characters). \
                 `name:` renames the VOLUME; to mount a host path, write it in the service's own \
                 `volumes:` list, where a reader can see it."
            ));
        }
        out.insert(key, real);
    }
    Ok(out)
}

/// Mark (and, where `name:` renames them, rewrite) the mounts of volumes declared `external: true`.
///
/// AFTER THE WHOLE FILE IS READ, not while the service is converted: `volumes:` at the top level is
/// legal below `services:`, and `volumes_from` inheritance adds entries to a box after its own
/// conversion has finished. Running this before either would mark a subset and let the rest through,
/// which is the failure this exists to prevent.
fn mark_external_volumes(
    boxes: &mut [ComposeBox],
    external: &std::collections::HashMap<String, String>,
) {
    if external.is_empty() {
        return;
    }
    for b in boxes.iter_mut() {
        for v in &mut b.volumes {
            let Some((src, rest)) = v.split_once(':') else {
                continue;
            };
            let Some(real) = external.get(src) else {
                continue;
            };
            b.external_volumes.push(real.clone());
            if real != src {
                *v = format!("{real}:{rest}");
            }
        }
        b.external_volumes.sort();
        b.external_volumes.dedup();
    }
}

/// The subnet a top-level network declares, as `networks.<name>.ipam.config[].subnet`.
///
/// WHY IT IS READ AT ALL. A file that pins services with `ipv4_address:` declares the network those
/// addresses belong to, and kern used to invent its own bridge network instead: the declared
/// addresses then fell outside it and a peer that hard-coded one had no route. With the file's own
/// subnet on the bridge, the address the file wrote IS the address the service answers on, which is
/// exactly what Docker does and the only way this key is honoured rather than approximated.
///
/// THE FIRST `subnet` OF THE FIRST NETWORK THAT HAS ONE. A file may declare several networks with
/// several subnets; one bridge can carry one of them, so kern takes the first and the driver refuses
/// to use it when a service's address falls outside. Guessing which of several was meant would be a
/// silent choice about where a service answers.
fn collect_network_subnets(root: &Node) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let Some(nets) = root.child("networks") else {
        return out;
    };
    for (name, def) in &nets.children {
        let Some(ipam) = def.child("ipam") else {
            continue;
        };
        let Some(config) = ipam.child("config") else {
            continue;
        };
        // `config:` IS A SEQUENCE OF MAPPINGS, AND THIS PARSER FOLDS EACH ITEM INTO ONE INLINE
        // SCALAR: a block item `- subnet: 172.28.0.0/16` arrives as the text `{subnet:
        // 172.28.0.0/16}`, exactly as `reconstruct_volume_item` documents for the long-form volume.
        // Walking `children` finds nothing, which is what it did: the file's own network was never
        // read and the bridge got one kern invented.
        for item in list_value(config) {
            let inner = item.trim().trim_start_matches('{').trim_end_matches('}');
            for field in split_top_commas(inner) {
                let Some((k, v)) = field.split_once(':') else {
                    continue;
                };
                if k.trim() != "subnet" {
                    continue;
                }
                let v = scalar_str(v).trim().to_string();
                if !v.is_empty() {
                    out.push((name.trim().to_string(), v));
                    break;
                }
            }
            if out.last().is_some_and(|(n, _)| n == name.trim()) {
                break;
            }
        }
    }
    out
}

fn collect_internal_networks(root: &Node) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    if let Some(nets) = root.child("networks") {
        for (name, def) in &nets.children {
            if def.child("internal").is_some_and(scalar_is_true) {
                out.insert(name.trim().to_string());
            }
        }
    }
    out
}

/// The `networks:` sentence for the wiring this run will use.
///
/// A FUNCTION AND NOT TWO CALL SITES CHOOSING: the note is emitted from two places (the top-level
/// block and a per-service key), and the whole point of `warn_once` is that they agree. Two `if`s
/// would be two chances to say opposite things about one file.
/// Which `internal: true` sentence this run owes the reader, or `None` when it owes none.
///
/// A FUNCTION BECAUSE THE DECISION IS THE BEHAVIOUR, and a decision made inline at a `warn_once`
/// call can be asserted by nothing: a mutation that swapped the two sentences left the test suite
/// green, which is how this function came to exist. The same reasoning already produced
/// [`networks_note`] and the `returned rather than printed` notes in the driver.
///
/// The three arms are the whole truth table. In a pod with every service confined, the driver
/// creates the pod with `--no-outbound` and the key IS honoured, so there is nothing to say - and
/// saying "not applied" there would be the parser contradicting the run. In a pod with any service
/// outside, it is dropped. Without a pod it is always satisfied AND always over-applied, so the note
/// fires whenever the key appears at all.
#[must_use]
pub const fn internal_note(
    net: crate::StackNet,
    stack_internal_only: bool,
) -> Option<&'static str> {
    match net {
        crate::StackNet::Pod if stack_internal_only => None,
        crate::StackNet::Pod => Some(INTERNAL_NOT_APPLIED),
        crate::StackNet::PerService => Some(INTERNAL_SATISFIED_BY_NO_POD),
        // The driver has not chosen the wiring yet and will say this itself once it has.
        crate::StackNet::Undecided => None,
    }
}

#[must_use]
pub const fn networks_note(net: crate::StackNet) -> Option<&'static str> {
    match net {
        crate::StackNet::Pod => Some(NETWORKS_IGNORED),
        crate::StackNet::PerService => Some(NETWORKS_SEGREGATED),
        crate::StackNet::Undecided => None,
    }
}

/// The sentence a stack is owed about `ipv4_address:`, once the wiring is settled.
///
/// THE KEY IS HALF-CLOSED AND THE HALF DEPENDS ON THE WIRING, which is exactly why this cannot be
/// said by the parser. In one shared namespace every service's address lands on the one loopback, so
/// a peer that hard-codes the address reaches the service and the key is honoured: measured on a
/// two-service file, `web` connecting to `172.28.1.10:6000` read back what `db` was serving, three
/// runs out of three, where before the change there was no route at all. With a namespace per
/// service a box claims only its OWN address, so the service answers on it and a PEER still cannot
/// reach it. Saying "applied" in that case would be the same defect this branch exists to remove.
#[must_use]
pub fn net_ipv4_note(net: crate::StackNet, pairs: &[(String, String)]) -> Option<String> {
    if pairs.is_empty() {
        return None;
    }
    let rendered: Vec<String> = pairs.iter().map(|(a, b)| format!("{a} at {b}")).collect();
    let shown: Vec<&str> = rendered.iter().map(String::as_str).collect();
    let list = crate::name_list(&shown);
    match net {
        crate::StackNet::Pod => Some(format!(
            "`ipv4_address:` is applied here ({list}): each address is claimed as a /32 on the \
             stack's shared loopback, so a peer that connects to the literal address reaches the \
             service. In one namespace it is the PORT that selects the service and not the address, \
             so a stack whose services share an internal port is wired with a namespace per service \
             instead, where the two cannot be confused"
        )),
        crate::StackNet::PerService => Some(format!(
            "`ipv4_address:` is claimed only where each service itself runs ({list}), because this \
             stack has a namespace per service: the service answers on its own address, and a PEER \
             connecting to that literal address still has no route to it. Peers reach each other by \
             name, so use the service name rather than a fixed address, which also keeps the file \
             working under Docker"
        )),
        crate::StackNet::Undecided => None,
    }
}

/// The sentence a `--bridge` stack is owed about `ipv4_address:`, which is the one wiring that
/// honours the key exactly.
///
/// A THIRD SENTENCE AND NOT A THIRD ARM OF [`net_ipv4_note`], because it is not a variation on the
/// other two: in a pod the address is an alias on a shared loopback and the PORT selects the
/// service, with a namespace per service the peer has no route at all, and on a bridge the address
/// IS the service's address on a real network - the same thing Docker gives it. Folding three
/// different facts into one function keyed on an enum with two wiring values is how the first two
/// came to say each other's sentence.
#[must_use]
pub fn net_ipv4_bridge_note(cidr: &str, pairs: &[(String, String)]) -> Option<String> {
    if pairs.is_empty() {
        return None;
    }
    let rendered: Vec<String> = pairs.iter().map(|(a, b)| format!("{a} at {b}")).collect();
    let shown: Vec<&str> = rendered.iter().map(String::as_str).collect();
    Some(format!(
        "`ipv4_address:` is honoured exactly here ({}): the bridge carries this file's own network \
         {cidr}, so the address the file pinned IS the address the service answers on and a peer \
         that hard-codes it reaches that service and no other",
        crate::name_list(&shown)
    ))
}

/// The sentence a stack is owed about `network_mode: service:X`, once the wiring is settled.
///
/// A FUNCTION AND NOT AN INLINE `warn`, so a test can ask what the stack was told for a given
/// wiring. This key had a sentence at parse time and it was WRONG in the wiring kern now picks by
/// itself: it said "kern already does this" and pointed the reader at `--no-pod` as the case to
/// worry about, while kern selects that case from the file. MEASURED on the corpus: 75 files use the
/// key and 20 of them get the per-service wiring, so the reassurance was false for one file in four
/// that reads it.
///
/// THE TWO ARMS ARE DIFFERENT CLAIMS, not two phrasings. In one namespace the key is satisfied
/// exactly: the services do share a stack, a loopback and a route. In a namespace per service the
/// membership is inherited (so the pair resolves and gets a relay, which is the half kern can give)
/// and the rest is not, and the half that is missing is the reason people write this key: a service
/// pinned behind a VPN or proxy container egresses through it. Saying "not shared" without saying
/// where the traffic goes instead would leave the reader believing the safer of the two readings.
#[must_use]
pub fn net_share_note(net: crate::StackNet, pairs: &[(String, String)]) -> Option<String> {
    if pairs.is_empty() {
        return None;
    }
    let rendered: Vec<String> = pairs.iter().map(|(a, b)| format!("{a} -> {b}")).collect();
    let shown: Vec<&str> = rendered.iter().map(String::as_str).collect();
    let list = crate::name_list(&shown);
    match net {
        crate::StackNet::Pod => Some(format!(
            "'network_mode: service:' is satisfied here ({list}): every service in this stack shares \
             ONE network namespace, so each of these reaches the service it names on 127.0.0.1 and \
             leaves through the same route"
        )),
        crate::StackNet::PerService => Some(format!(
            "'network_mode: service:' is NOT given a shared namespace here ({list}), because this \
             stack is wired with one namespace per service. Each of these services inherits the \
             `networks:` of the one it names, so it resolves it by name and reaches it through a \
             relay. What one namespace would also give it does not have: 127.0.0.1 is not shared, \
             and its outbound traffic does NOT pass through the service it names, so a service put \
             behind a VPN or a proxy container this way reaches the network directly. `--pod` wires \
             the whole stack as one namespace, which does satisfy the key"
        )),
        crate::StackNet::Undecided => None,
    }
}

/// Name the per-service network sub-keys kern does NOT honour, one line per service.
///
/// SILENCE HERE WAS THE WORST DEFECT THIS PARSER HAD. MEASURED before this existed, on a file
/// pinning a service to a fixed address inside a declared subnet: kern printed nothing at all, the
/// service started, its name and its alias resolved, and a peer connecting to the literal
/// `172.28.1.10` got `FALLITO`. Under Docker that address answers. A difference nobody is told about
/// is exactly what this compose implementation refuses to ship, and it was being counted as a clean
/// file by the very measurement used to claim compatibility - the instrument was kern's own
/// warnings, so a gap kern did not know about was invisible to it.
///
/// WHAT KERN CAN AND CANNOT DO WITH THESE. `aliases` is honoured (extra names in the shared hosts
/// file, or extra `--add-host` entries without a pod). A fixed `ipv4_address`/`ipv6_address` is not:
/// a kern stack has no user-defined subnet to allocate it from - services meet on loopback in a pod
/// and on per-service loopback aliases without one - so the address simply does not exist anywhere.
/// `priority` orders which network's gateway a container defaults to, which needs more than one
/// gateway to mean anything. `link_local_ips` and `mac_address` need an interface kern does not give
/// a box.
///
/// NAMED, NOT REFUSED: every one of these files runs, reaches its peers by name and by alias, and
/// the only thing that does not work is a hard-coded address. Refusing the file would take away far
/// more than the gap costs.
fn unhonoured_net_keys(networks: &Node) -> Vec<&'static str> {
    /// The per-service `networks:` sub-keys kern cannot honour, in the order they are reported.
    ///
    /// A TABLE AND NOT A `matches!`, so the set is one list a reader can check against the Compose
    /// Specification rather than a pattern spread across a condition and a mapping.
    // `ipv4_address` LEFT THIS TABLE WHEN IT STOPPED BEING UNHONOURED. It is now claimed as a /32 on
    // the box's loopback, so the literal address exists; what a peer can do with it depends on the
    // wiring, and that sentence is said by the driver, where the wiring is known. `ipv6_address`
    // stays: kern claims no IPv6 address for a box.
    const UNHONOURED: [&str; 4] = ["ipv6_address", "link_local_ips", "priority", "gw_priority"];
    // ITERATED OVER THE TABLE, NOT OVER THE FILE, so the order of the report is the order of this
    // list and not the order the author happened to type the keys in. A message whose wording depends
    // on the input's layout is one that reads differently for two files that mean the same thing.
    UNHONOURED
        .iter()
        .copied()
        .filter(|u| {
            networks
                .children
                .iter()
                .any(|(_net, def)| def.children.iter().any(|(k, _)| k.trim() == *u))
        })
        .collect()
}

/// Say it, once per service, when there is something to say.
fn warn_unhonoured_net_keys(networks: &Node, service: &str) {
    let seen = unhonoured_net_keys(networks);
    if seen.is_empty() {
        return;
    }
    warn(&format!(
        "service '{service}': under `networks:` the key(s) {} are NOT applied - a kern stack has no \
         user-defined subnet to allocate an address from (services meet on loopback in a pod, and on \
         per-service loopback aliases without one), so a peer that connects to a hard-coded address \
         will not reach it. The service name and its `aliases:` DO resolve; use those instead of a \
         fixed address, which also keeps the file working under Docker",
        seen.iter()
            .map(|k| format!("`{k}`"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
}

/// The literal addresses a service is pinned to under `networks.<net>.ipv4_address`.
///
/// ONE PER NETWORK, IN FILE ORDER, and all of them: a service on two networks has two addresses and
/// keeping only the first would drop a peer's route without saying so. Validated as IPv4 literals
/// here rather than passed on as text, so a typo is caught while the file is being read instead of
/// by a box that cannot say which key it came from.
fn collect_net_ipv4(networks: &Node) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (_net, def) in &networks.children {
        let Some(node) = def.child("ipv4_address") else {
            continue;
        };
        let Some(v) = node.scalar.as_deref().map(scalar_str) else {
            continue;
        };
        let v = v.trim();
        if v.parse::<std::net::Ipv4Addr>().is_ok() && !out.iter().any(|o| o == v) {
            out.push(v.to_string());
        }
    }
    out
}

fn collect_net_aliases(networks: &Node) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (_net, def) in &networks.children {
        if let Some(aliases) = def.child("aliases") {
            for a in list_value(aliases) {
                let a = a.trim().to_string();
                if !a.is_empty() && !out.contains(&a) {
                    out.push(a);
                }
            }
        }
    }
    out
}

fn list_value(node: &Node) -> Vec<String> {
    if let Some(sc) = &node.scalar {
        if sc.trim_start().starts_with('[') {
            return parse_inline_list(sc);
        }
        // A bare scalar where a list is expected (`command: echo hi`) → single element.
        return vec![scalar_str(sc)];
    }
    node.items
        .iter()
        .map(|it| {
            // A block item may itself be an inline list element or a quoted string.
            scalar_str(it)
        })
        .collect()
}

/// `env_file:` in BOTH of its spellings: the short one (a path, or a list of paths) and the long one
/// the Specification added for optional files:
///
/// ```yaml
/// env_file:
///  - path: ./env_vars/.env_db
///    required: true
///  - path: ./env_vars/.env_db_override
///    required: false
/// ```
///
/// A `required: false` entry whose file is not there is DROPPED - that is the whole meaning of the
/// key, and it is how a project ships an override file the user may never create. Every other entry
/// is forwarded as a path, and a missing one still fails the box, loudly, as before.
///
/// IT USED TO BE READ AS A PATH, verbatim: kern handed `kern box --env-file` the string
/// `{path: ./env_vars/.env_db_pgsql, required: true}` and the box refused a file by that name.
/// MEASURED on Zabbix, where it stopped the database service and with it the stack.
///
/// `dir` is the compose file's own directory, which is what a relative path in it is relative to;
/// without one, the check falls back to the working directory, which is where kern was run from.
fn env_file_value(node: &Node, svc: &str, dir: Option<&std::path::Path>) -> Vec<String> {
    let mut out = Vec::new();
    for entry in list_value(node) {
        let e = entry.trim();
        // The long form arrives folded into `{path: …, required: …}` - the same shape the long-form
        // port takes, from the same folding in `build_tree`.
        let Some(inner) = e.strip_prefix('{').and_then(|r| r.strip_suffix('}')) else {
            out.push(entry);
            continue;
        };
        let mut path: Option<String> = None;
        let mut required = true; // the Specification's default
        for field in split_top_commas(inner) {
            let Some((k, v)) = field.split_once(':') else {
                continue;
            };
            match k.trim() {
                "path" => path = Some(scalar_str(v.trim())),
                "required" => required = !matches!(scalar_str(v.trim()).as_str(), "false" | "no"),
                // `format:` (the newer `raw` reader) is not implemented; a file kern reads with its
                // own rules is still read, so saying nothing here would be silent. Named below.
                other => warn(&format!(
                    "service '{svc}': env_file `{other}:` is not applied (kern reads the file with \
                     Docker's default rules)"
                )),
            }
        }
        let Some(p) = path else {
            warn(&format!(
                "service '{svc}': an `env_file:` entry has no `path:` - skipped"
            ));
            continue;
        };
        if !required {
            let full = match dir {
                Some(d) => d.join(&p),
                None => std::path::PathBuf::from(&p),
            };
            if !full.exists() {
                continue; // exactly what `required: false` asks for
            }
        }
        out.push(p);
    }
    out
}

/// A service's `secrets:` reference names. Short form is a list of names (`[db_pw, api_key]`); long
/// form is a list of maps each with a `source:` (`[{source: db_pw, target: …}]`) - we take `source`
/// (the target is always `/run/secrets/<source>` in kern). Returns the referenced secret names.
/// Also returns the `mode:` the long form declares, when it declares one; see [`secret_mode_of`].
fn secret_refs(
    node: &Node,
) -> (
    Vec<String>,
    Result<Option<String>, String>,
    Vec<&'static str>,
) {
    let mut out = Vec::new();
    let mut modes: Vec<String> = Vec::new();
    let mut unhonoured: Vec<&'static str> = Vec::new();
    for it in list_value(node) {
        let it = it.trim();
        if it.starts_with('{') {
            // long-form inline `{source: name, target: …}` - pull `source`.
            let n = parse_inline_table(it);
            if let Some(src) = n.child("source").and_then(|s| s.scalar.as_deref()) {
                out.push(scalar_str(src));
            }
            if let Some(m) = n.child("mode").and_then(|m| m.scalar.as_deref()) {
                modes.push(scalar_str(m));
            }
            // The long-syntax keys kern does NOT honour. Collected in the specification's own order
            // so a file declaring several reads back the way it was written.
            for k in UNHONOURED_SECRET_KEYS {
                if n.child(k).is_some() && !unhonoured.contains(k) {
                    unhonoured.push(k);
                }
            }
        } else if !it.is_empty() {
            out.push(scalar_str(it));
        }
    }
    // Block long-form (`- source: name` on its own lines) is handled too: `build_tree` folds each
    // block list item's `key: value` children into an inline `{source: name, …}` scalar, so it arrives
    // at the `{`-prefixed branch above. No separate code path needed.
    (out, secret_mode_of(&modes), unhonoured)
}

/// The service-`secrets:` long-syntax keys kern reads and does not apply, in the specification's
/// order.
///
/// NAMED RATHER THAN IMPLEMENTED, and the reason is the same one that put the mode on the BOX: none
/// of the three appears once in 259 real compose files, nor in any of Docker's own samples that use
/// secrets. Building a per-secret channel for them would be machinery with no reader; leaving them
/// silent would be the exact defect this branch exists to remove, because each one changes where the
/// file lands or who may read it, and a service that cannot find its secret fails inside its own
/// code with an error that points nowhere near the mount.
pub const UNHONOURED_SECRET_KEYS: &[&str] = &["target", "uid", "gid"];

/// The sentence a service is owed for the secret keys kern did not apply, or `None`.
///
/// A FUNCTION so the decision is assertable: printed inline at a `warn`, nothing can ask whether the
/// right keys were named, which is how the `internal:` note came to need one too.
pub fn unhonoured_secret_note(keys: &[&str]) -> Option<String> {
    if keys.is_empty() {
        return None;
    }
    Some(format!(
        "under `secrets:` the key(s) {} are NOT applied: kern delivers every secret at \
         `/run/secrets/<source>`, owned by the box's root, with the mode from `mode:` (default \
         0444). A service that opens the path `target:` names, or that expects the file to belong \
         to `uid:`/`gid:`, will not find it where it looks",
        keys.iter()
            .map(|k| format!("`{k}`"))
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// The ONE mode a service's secrets share, or a refusal when it declares more than one.
///
/// kern carries the mode PER BOX, and that is a measured choice rather than a shortcut: `mode:`
/// under a service's `secrets:` does not appear once in 259 real compose files, nor in any of
/// Docker's own eight samples that use secrets. Building a per-secret channel for a case that does
/// not occur is machinery with no reader.
///
/// A file that DOES declare two different modes for one service is refused rather than silently
/// given one of them. Two identical declarations are not a conflict and pass.
fn secret_mode_of(modes: &[String]) -> Result<Option<String>, String> {
    let mut seen: Vec<&str> = Vec::new();
    for m in modes {
        let m = m.trim().trim_start_matches("0o");
        if !seen.contains(&m) {
            seen.push(m);
        }
    }
    match seen.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some((*one).to_string())),
        many => Err(format!(
            "declares {} different `mode:` values for its secrets ({}), and kern applies ONE mode \
             per box. Give them the same mode, or split the service. (Measured: no `mode:` appears \
             in 259 real compose files, so this is refused rather than silently resolved.)",
            many.len(),
            many.join(", ")
        )),
    }
}

/// Collect top-level `secrets:` definitions into `name -> file` for the `file:`-backed form (the only
/// one kern maps: it delivers the file at `/run/secrets/<name>`). A secret with no `file:` (external,
/// or environment-backed) yields no entry → a service referencing it warns at conversion.
fn collect_secret_files(root: &Node) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    if let Some(sec) = root.child("secrets") {
        for (name, def) in &sec.children {
            if let Some(file) = def.child("file").and_then(|f| f.scalar.as_deref()) {
                out.insert(name.clone(), scalar_str(file));
            }
        }
    }
    out
}

/// Top-level secrets whose CONTENT comes from an environment variable
/// (`secrets: {db_pw: {environment: DB_PW}}`), as `secret name -> variable name`.
///
/// A SPECIFICATION FEATURE THAT WAS BEING SKIPPED, and skipping it breaks the stack rather than
/// degrading it: the service still reads `/run/secrets/<name>`, the file is not there, and the
/// workload fails inside its own code. MEASURED on a held-out corpus of 167 recent compose files: a
/// MySQL stack whose `MYSQL_PASSWORD_FILE` points at a secret declared this way.
///
/// THE VARIABLE NAME AND NOT ITS VALUE, because this runs while the document is being read and the
/// value belongs to the environment the driver will hand the box. Carrying the value from here
/// would put a secret in a struct that is cloned, printed by `config` and compared in tests.
fn collect_secret_envs(root: &Node) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    if let Some(sec) = root.child("secrets") {
        for (name, def) in &sec.children {
            if let Some(v) = def.child("environment").and_then(|f| f.scalar.as_deref()) {
                let v = scalar_str(v).trim().to_string();
                if !v.is_empty() {
                    out.insert(name.clone(), v);
                }
            }
        }
    }
    out
}

/// Convert one `services:` entry into a `ComposeBox`, applying every mapping rule + degrade-with-warn.
/// `secret_files` maps a top-level secret name to its backing file (for `secrets: [name]` refs).
/// What a service needs from the DOCUMENT around it to become a box: the tables collected from the
/// top-level blocks, the wiring the stack will be given, and where the file itself lives.
///
/// A struct because these six travel together and always will: every one of them is a fact about
/// the file rather than about the service, and passing them one by one made the signature grow a
/// parameter each time the parser learned to read another top-level block.
struct ServiceCtx<'a> {
    /// `secrets:` name -> the file backing it.
    secret_files: &'a std::collections::HashMap<String, String>,
    /// `secrets:` name -> the environment variable backing it.
    secret_envs: &'a std::collections::HashMap<String, String>,
    /// The networks declared `internal: true`.
    internal_networks: &'a std::collections::HashSet<String>,
    /// How the stack will be wired, which decides what `networks:` MEANS here.
    net: crate::StackNet,
    /// The compose file's own directory: what a relative `extends: {file:}` or `env_file:` is
    /// relative to. `None` when the document did not come from a file on disk.
    dir: Option<&'a std::path::Path>,
    /// The project `.env`, for the one lookup that is not interpolation: a bare `build.args` name.
    dotenv: &'a crate::DotEnv,
}

fn service_to_box(name: &str, svc: &Node, cx: &ServiceCtx) -> Result<ComposeBox, String> {
    let ServiceCtx {
        secret_files,
        secret_envs,
        internal_networks,
        net,
        dir,
        dotenv,
    } = *cx;
    kern_common::BoxName::parse(name)
        .map_err(|e| format!("service '{name}': invalid name: {e}"))?;
    let mut b = ComposeBox::new(name.to_string());
    // `entrypoint` + `command` are composed as `entrypoint ++ command` (Docker semantics) - but ONLY
    // after the whole service is parsed, since the two keys can appear in EITHER order in the file.
    // Merging inline (as before) was order-dependent: if `entrypoint` came first, `command` hadn't been
    // read yet, then `command` overwrote the merge → the entrypoint was dropped and the box tried to
    // exec the bare command as a program.
    // `cpu_quota` and `cpu_period` are ONE setting written as two keys, and they may appear in either
    // order, so they are collected here and divided after the loop - the same reason `entrypoint` and
    // `command` are composed after it.
    let (mut cpu_quota, mut cpu_period): (Option<f64>, Option<f64>) = (None, None);
    let mut entrypoint: Vec<String> = Vec::new();
    // Whether the entrypoint was written in SHELL form (a bare string `entrypoint: /init here` →
    // `sh -c "/init here"`) vs EXEC form (a list). It changes how `command` composes: Docker appends
    // `command` only to an EXEC-form entrypoint; a shell-form entrypoint is the whole command and
    // `command` is dropped (appending it would make the args shell positional params, not entrypoint
    // args - the box would run `/init here` and silently discard `command`). See the merge below.

    // A KEY WRITTEN TWICE IN ONE SERVICE IS REFUSED, not resolved to the last one.
    //
    // YAML mappings have no duplicate keys, and this file already refuses two services with one name
    // and two `x-kern-vcpu` in one service. `image` was the exception: MEASURED, a second `image` at
    // the bottom of a service silently won, which is the cheapest way to make a downloaded file run an
    // image other than the one a reader sees at the top. Three shapes of the same mistake had three
    // different answers; now they have one.
    //
    // Counted on the keys as the SERVICE carries them, after any merge key has been resolved, so a
    // local key that also exists in a merged base is not a duplicate - it is the override that
    // `<<:` exists for, and `ANC-01` asserts it still wins.
    {
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for (key, _) in &svc.children {
            if !seen.insert(key.as_str()) {
                return Err(format!(
                    "service '{name}': key '{key}' appears twice - a YAML mapping has no duplicate \
                     keys, so which one wins would be this parser's invention. Remove one."
                ));
            }
        }
    }
    for (key, node) in &svc.children {
        match key.as_str() {
            "image" => b.image = node.scalar.as_deref().map(scalar_str),
            // `rootfs`/`bind_rootfs` are kern-native keys (not Docker compose) - accepted so a kern
            // stack authored in YAML can use a host rootfs dir instead of an OCI image.
            "rootfs" => b.rootfs = node.scalar.as_deref().map(scalar_str),
            "bind_rootfs" => b.bind_rootfs = scalar_is_true(node),
            // Honour Docker's `container_name:` as the box's exact name (see `ComposeBox`), so
            // `docker exec <name>` ports 1:1. Trimmed; an empty value falls back to the default name.
            // VALIDATE it as a `BoxName` (like the service key at the top): it becomes `b.name` and is
            // printed to the operator by `compose up` BEFORE the spawned `kern box` could reject it, so
            // an unvalidated value from a third-party file (`container_name: "x\e[2J…"`) would inject
            // terminal-control bytes into the operator's screen. Reject at parse time instead.
            "container_name" => {
                let cn = node.scalar.as_deref().map(scalar_str);
                if let Some(cn) = cn.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    kern_common::BoxName::parse(cn).map_err(|e| {
                        format!("service '{name}': invalid container_name '{cn}': {e}")
                    })?;
                    b.container_name = Some(cn.to_string());
                }
            }
            "command" => b.command = command_value(node),
            "entrypoint" => {
                let (ep, _) = entrypoint_value(node);
                entrypoint = ep;
            }
            "environment" => b.env = kv_pairs_from(node, Some(dotenv)),
            "env_file" => b.env_file = env_file_value(node, name, dir),
            "ports" => {
                // A container-only entry joins the DECLARED space (what `expose:`/`port:` feed)
                // instead of being refused: same statement, one space, as everywhere else here.
                let mut declared = Vec::new();
                b.ports = ports_value(node, name, &mut declared);
                b.expose.extend(declared);
            }
            // `expose:` is Compose's spelling of "I listen here": the same pod port space as
            // `ports:` and `port:`, so it enters the same preflight. It injects nothing, since in
            // Docker the key only documents. The syntax is read by `parse_expose_entry`, shared with
            // the kern profile, so the same string means the same thing in both spellings.
            //
            // What DOES differ is the disposal of a malformed entry, deliberately: here it is warned
            // and skipped, in kern's own TOML it is refused with a line number. A
            // `docker-compose.yml` is someone else's file, and refusing a whole working stack over
            // one line of documentation would be the wrong trade; a kern profile is kern's format,
            // where a typo should be said at once. Same parser, different disposal, pinned by a test
            // that asserts BOTH spellings together so neither can drift in silence.
            //
            // RANGES (`3000-3005`) are declared unsupported rather than silently expanded: expanding
            // them would make the collision message unreadable, and nobody writes one for a service
            // that listens on a single port.
            "expose" => {
                for raw in list_value(node) {
                    match crate::parse_expose_entry(&raw) {
                        Ok(e) => b.expose.push(e),
                        Err(m) => warn(&format!("service '{name}': expose: {m} - ignored")),
                    }
                }
            }
            // `port:` is kern's own key, not a Compose Specification one: it declares the port this
            // service LISTENS on inside the shared namespace, so the preflight can see a service that
            // publishes nothing. Parsed here rather than passed through as text, so a malformed value
            // fails at the file that wrote it. An out-of-range or non-numeric value is warned and
            // ignored rather than fatal, for the same reason `expose:` is: this key is an addition to
            // a Docker file that is otherwise valid.
            "port" => match node.scalar.as_deref().map(scalar_str) {
                Some(v) => match v.trim().parse::<u16>() {
                    Ok(n) if n > 0 => b.port = Some(n),
                    _ => warn(&format!(
                        "service '{name}': port: '{v}' is not a port in 1..=65535 - ignored"
                    )),
                },
                None => warn(&format!("service '{name}': port: needs a number - ignored")),
            },
            // `tmpfs:` MAY ALREADY HAVE BEEN SET by its own key, and a long-form `type: tmpfs`
            // volume appends to it rather than replacing it: a file is allowed to write both.
            "volumes" => b.volumes = volumes_value(node, &mut b.tmpfs_from_volumes, name),
            "devices" => {
                let raw = list_value(node);
                b.devices = normalise_devices(&raw, name, &mut b.tun);
            }
            // `dns:` ACCEPTS A SCALAR OR A LIST in Docker, and `list_value` already normalises both
            // to a vector, so the three arms need no shape handling of their own.
            "links" => {
                let raw = list_value(node);
                b.links = normalise_links(&raw, &mut b.depends_on);
            }
            "dns" => b.dns = list_value(node),
            "dns_search" => b.dns_search = list_value(node),
            "dns_opt" | "dns_options" => b.dns_options = list_value(node),
            "depends_on" => apply_depends(&mut b, node),
            "healthcheck" => apply_healthcheck(&mut b, node, name),
            "restart" => apply_restart(&mut b, node, name),
            "user" => b.user = node.scalar.as_deref().map(scalar_str),
            "working_dir" | "workdir" => b.workdir = node.scalar.as_deref().map(scalar_str),
            "build" => b.build = Some(build_value(node, dotenv)),
            // Resource / capability / hardening keys - these map 1:1 to `kern box` flags the runtime
            // already enforces, so CONVERT them (not warn-and-ignore): a compose that sets `mem_limit`
            // or `read_only` must get those limits, else the stack "runs but without the constraints
            // the user asked for" - worse than a visible gap.
            "mem_limit" | "memory" => b.memory = node.scalar.as_deref().map(scalar_str),
            "memswap_limit" | "mem_swap_limit" => {
                b.swap_max = node.scalar.as_deref().map(scalar_str)
            }
            "cpus" => b.cpus = node.scalar.as_deref().map(scalar_str),
            "cpuset" => b.cpuset = node.scalar.as_deref().map(scalar_str),
            "pids_limit" => b.pids_limit = node.scalar.as_deref().map(scalar_str),
            // A SOFT FLOOR, NOT A CAP, and the difference is why kern has both. `mem_limit` becomes
            // `memory.max` and kills; this becomes `memory.low` and only changes who the kernel
            // reclaims from first. A file that sets only the reservation asked to be protected under
            // pressure, never to be bounded, and mapping it onto the cap would kill a service that
            // Docker would have let run.
            "mem_reservation" | "memory_reservation" => {
                b.memory_reservation = node.scalar.as_deref().map(scalar_str)
            }
            // DOCKER'S SCALE IS NOT CGROUP V2's, so the value is CONVERTED rather than forwarded.
            // Shares are 2..=262144 with 1024 normal; `cpu.weight` is 1..=10000 with 100 normal. The
            // mapping is the one systemd documents. A value outside Docker's range is named rather
            // than clamped: it is not a share, so guessing what it meant would be inventing intent.
            "cpu_shares" => match node
                .scalar
                .as_deref()
                .map(scalar_str)
                .and_then(|v| v.trim().parse::<u64>().ok())
            {
                Some(shares) if (2..=262_144).contains(&shares) => {
                    b.cpu_weight = Some(docker_shares_to_cpu_weight(shares).to_string());
                }
                _ => warn(&format!(
                    "service '{name}': 'cpu_shares:' needs a number in 2..=262144 (Docker's scale) - ignored"
                )),
            },
            // `cpu_quota`/`cpu_period` ARE `--cpus` WRITTEN THE LONG WAY. cgroup v2 spells the same
            // thing as one `cpu.max` line (`<quota> <period>`), and kern already computes that from
            // `--cpus`, so the pair is divided here rather than given a second mechanism that could
            // disagree with the first. A period of 0, or a quota without a period, is not a ratio:
            // Docker's own default period is 100000us and that is what a lone quota means.
            "cpu_quota" | "cpu_period" => {
                let v = node
                    .scalar
                    .as_deref()
                    .map(scalar_str)
                    .and_then(|v| v.trim().parse::<f64>().ok());
                match (key.as_str(), v) {
                    (_, None) | (_, Some(0.0)) => warn(&format!(
                        "service '{name}': '{key}:' needs a positive number of microseconds - ignored"
                    )),
                    ("cpu_quota", Some(q)) => cpu_quota = Some(q),
                    (_, Some(p)) => cpu_period = Some(p),
                }
            }
            // `pull_policy:` IS `--pull`, with Docker's vocabulary mapped onto kern's three values.
            // `build`/`daily`/`weekly` have no kern equivalent and are named, because a policy that
            // silently became "pull if missing" would change when a stack picks up a new image.
            // `platform:` IS SATISFIED OR IMPOSSIBLE, and which one is a fact about this machine.
            //
            // kern runs the host's architecture and emulates nothing, so a platform naming that
            // architecture is already what the box will be and there is nothing to do or say. One
            // naming a different architecture cannot be honoured at all, and that is worth a
            // sentence: the image would pull (registries serve multi-arch manifests) and the
            // workload would fail to exec with a message about a binary format, a long way from the
            // line that caused it.
            //
            // The OS half is checked too: `windows/amd64` on Linux is the same class of impossible.
            "platform" => {
                let v = node
                    .scalar
                    .as_deref()
                    .map(scalar_str)
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase();
                if !v.is_empty() && !platform_matches_host(&v) {
                    warn(&format!(
                        "service '{name}': 'platform: {v}' cannot be honoured - kern runs this \
                         machine's architecture ({}) and emulates nothing, so the image would pull \
                         and then fail to exec. Run this service on a matching host",
                        host_platform()
                    ));
                }
            }
            // `volumes_from:` IS A COPY OF ANOTHER SERVICE'S MOUNTS, resolved after every service is
            // parsed (the target may be defined below this one). Docker's `:ro` suffix narrows the
            // copy, so it is applied to each inherited entry rather than dropped.
            "volumes_from" => b.volumes_from = list_value(node),
            "pull_policy" => {
                let v = node
                    .scalar
                    .as_deref()
                    .map(scalar_str)
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase();
                match v.as_str() {
                    "always" => b.pull = Some("always".to_string()),
                    "never" => b.pull = Some("never".to_string()),
                    "missing" | "if_not_present" => b.pull = Some("missing".to_string()),
                    other => warn(&format!(
                        "service '{name}': 'pull_policy: {other}' has no kern equivalent - kern pulls \
                         when the image is absent (`missing`); use always/never/missing"
                    )),
                }
            }
            "hostname" => b.hostname = node.scalar.as_deref().map(scalar_str),
            "cap_add" => b.cap_add = list_value(node),
            "cap_drop" => b.cap_drop = list_value(node),
            "tmpfs" => b.tmpfs = tmpfs_value(node),
            "read_only" => b.read_only = scalar_is_true(node),
            // `privileged: true` has no kern equivalent (rootless by design) - warn, don't silently
            // pretend. The box runs UNprivileged; a workload needing real privilege will notice.
            // `privileged: true` IS RECORDED, NOT ANSWERED HERE. Whether kern gives it depends on
            // something the parser cannot see: whether the OPERATOR granted it, on the command line
            // or in their own config. The parser's old sentence ("no kern equivalent (rootless)")
            // was wrong on both halves - there is an equivalent, and it is not the file's to take.
            "privileged" => b.privileged = scalar_is_true(node),
            "secrets" => {
                // A service `secrets: [name, …]` (or long-form `{source: name, target: …}`) references
                // top-level secret definitions. Map each `file:`-backed one to `--secret <file>:<name>`
                // (kern delivers it at `/run/secrets/<name>`) - matching compose's mount point
                // exactly. `<file>` is relative → `compose()` makes it absolute (dir-confined).
                //
                // The MODE travels with them: the specification's default is world-readable, and a
                // long-form `mode:` overrides it. See `secret_mode_of` for why it is one per box.
                let (refs, mode, unhonoured) = secret_refs(node);
                match mode {
                    Ok(m) => b.secret_mode = m,
                    Err(why) => return Err(format!("service '{name}': {why}")),
                }
                if let Some(note) = unhonoured_secret_note(&unhonoured) {
                    warn(&format!("service '{name}': {note}"));
                }
                for entry in refs {
                    match (secret_files.get(&entry), secret_envs.get(&entry)) {
                        (Some(file), _) => b.secrets.push(format!("{file}:{entry}")),
                        // The VARIABLE travels, never the value: the driver puts the value in the
                        // box's environment, so it never appears in `argv` where `/proc/<pid>/cmdline`
                        // makes it world-readable.
                        (None, Some(var)) => b.secret_envs.push(format!("{entry}={var}")),
                        (None, None) => warn(&format!(
                            "service '{name}': secret '{entry}' has no top-level `file:` or \
                             `environment:` definition - skipped (an `external: true` secret has no \
                             daemon to come from here)"
                        )),
                    }
                }
            }
            "profiles" => b.profiles = list_value(node),
            // Docker Compose v3 puts the hard caps under `deploy.resources.limits` (memory/cpus/pids).
            // CONVERT them - kern enforces them exactly like its own `--memory`/`--cpus`/`--pids-limit`
            // flags, and Docker rootless famously IGNORES them without cgroup-v2+systemd, so this is a
            // place kern is *stronger*, not weaker. A silently-dropped cap is worse than a visible gap.
            "deploy" => apply_deploy(&mut b, node, name),
            // `networks:` itself is ignored (kern uses a shared-netns pod, not per-network bridges),
            // but a service's `networks.<net>.aliases` ARE honoured: each alias is another name the
            // service answers to inside the pod, so we collect them for `kern compose` to add to the
            // shared /etc/hosts. The map form (`networks: {net: {aliases: [db]}}`) carries them; the
            // list form (`networks: [net]`) has none.
            "networks" => {
                b.net_aliases = collect_net_aliases(node);
                b.networks = collect_net_names(node);
                b.net_ipv4 = collect_net_ipv4(node);
                warn_unhonoured_net_keys(node, name);
                // POSITIVE EVIDENCE ONLY: at least one network, and every one of them marked
                // `internal: true` at the top level. A name the file does not mark internal, or a
                // service with no networks at all, leaves this false and keeps the stack's outbound
                // ON. Uncertainty must not turn the internet off for a stack that needs it.
                let names = collect_net_names(node);
                b.only_internal_networks =
                    !names.is_empty() && names.iter().all(|n| internal_networks.contains(n));
                b.on_internal_network = names.iter().any(|n| internal_networks.contains(n));
                // Only RECORDED here, announced once for the whole document. A per-service
                // `networks:` used to pass in total silence when the file declared no top-level
                // block (Docker rejects such a file; kern accepted it and said nothing about the
                // segmentation it was dropping). Warning per service instead put eight identical
                // lines on a seven-service file, and stating the same fact in two places is the
                // exact defect class this codebase keeps paying for. One fact, one statement.
                // Not flagged when aliases came out of it: something WAS honoured, and "ignored"
                // would then be the lie.
                if b.net_aliases.is_empty() {
                    if let Some(n) = networks_note(net) {
                        warn_once(n);
                    }
                }
            }
            // `init: true` → `--init`. kern already ships the reaping PID 1; this only wires the
            // compose spelling to it.
            "init" => b.init = scalar_is_true(node),
            // `extra_hosts:` → one `--add-host name:ip` per entry. Docker accepts three spellings:
            // the list forms `"name:ip"` and `"name=ip"`, and the mapping form `name: ip`. All are
            // normalised to kern's `name:ip`. An entry without a separator is dropped with a warning
            // rather than forwarded, because kern would reject the whole box for one malformed line.
            "extra_hosts" => b.add_host = collect_extra_hosts(node, name),
            // `ulimits:` → `--ulimit NAME=SOFT:HARD`; `sysctls:` → `--sysctl KEY=VALUE`. Both are
            // forwarded VERBATIM to the box, which owns the validation (resource-name table, bounds,
            // key shape): one authority, so a compose file and a `kern box` flag can never disagree.
            // `labels:` → `--label k=v`. Descriptive metadata, but recorded so `kern ps --filter
            // label=` can select a stack's boxes - which is what compose users use labels FOR.
            "labels" => b.labels = collect_kv(node, '='),
            // Docker's shutdown contract. Without it every service is hard-killed: redis loses
            // whatever it had not saved and postgres does crash recovery on the next start.
            "stop_signal" => b.stop_signal = node.scalar.as_deref().map(scalar_str),
            "stop_grace_period" => {
                b.stop_grace_period = node
                    .scalar
                    .as_deref()
                    .map(scalar_str)
                    .map(|v| duration_secs(&v).to_string())
            }
            "ulimits" => b.ulimits = collect_ulimits(node, name),
            "sysctls" => b.sysctls = collect_kv(node, '='),
            // `shm_size` is RECOGNISED but intentionally not mapped, and that is a design decision worth
            // stating rather than a generic "unsupported": kern mounts `/dev/shm` UNSIZED and charges it
            // to the box memory cgroup, so `mem_limit`/`--memory` is the real bound (measured: a 32 MB
            // box admits ~30 MB into an unsized /dev/shm before ENOSPC). A fixed `shm_size` would either
            // be moot (below that bound) or reintroduce Docker's 64 MB default - the footgun that breaks
            // Postgres under load. Say why, so a reader does not think a feature is missing.
            // APPLIED NOW. The old note said kern bounds `/dev/shm` by the memory cgroup instead,
            // which is true and was the right answer for a file asking for LESS than that bound - a
            // fixed size would have been moot, or would have reintroduced Docker's 64 MB default,
            // the footgun that breaks Postgres under load.
            //
            // Real files ask for MORE. MEASURED on a neutral corpus of 259 compose files, the two
            // that set this key ask for `1g` and `8GB`, both above kern's 512 MiB default memory
            // cap: the file asked for more shared memory than the box had, and silently got less.
            // The value is forwarded; the memory cgroup still bounds the total, which is kern's own
            // guarantee and is not weakened by naming a size inside it.
            "shm_size" => b.shm_size = node.scalar.as_deref().map(scalar_str),
            // `tty:` IS SILENT, and `stdin_open:` speaks only when it is true. Both used to fall
            // into the generic "ignored (unsupported)" bucket below, which was wrong twice: it
            // fired on the KEY rather than the value, so `tty: false` warned about nothing at all,
            // and it told a user a feature was missing when nothing is missing for the thing they
            // are running.
            //
            // A compose service is always detached, and MEASURED on a detached box: stdin is
            // non-tty and at EOF, stdout is non-tty. `tty: true` therefore changes nothing kern
            // can act on, and a terminal is available on demand anyway: `kern exec -it <service>`
            // gives a real PTY inside the running box, which is more than `docker attach` offers.
            // It appears in thousands of compose files out of habit, on daemons that never read a
            // terminal, and warning all of them is noise. The reporter's own service is one:
            // measured, it serves HTTP 200 and stays up with both keys ignored.
            //
            // `stdin_open: true` is the one with a consequence worth naming, and only that one: a
            // program that waits on stdin gets EOF instead of a held-open pipe, so one written to
            // block there will exit at once. That is a real behaviour difference, so it is stated
            // as a behaviour rather than as a missing feature.
            "tty" => {}
            "stdin_open" => {
                if scalar_is_true(node) {
                    warn(&stdin_open_note(name));
                }
            }
            // `security_opt` IS MOSTLY ALREADY TRUE, AND SAYING "unsupported" ABOUT IT WAS A FALSE
            // STATEMENT ABOUT KERN'S OWN POSTURE.
            //
            // Measured inside a box, with and without this key: `NoNewPrivs: 1` and `Seccomp: 2`
            // (filter mode) on every box, unconditionally, with no flag to turn either off. In a
            // 240-file corpus of real compose files, 105 of the 203 `security_opt` values were
            // `no-new-privileges` - so the majority of this key asked for a property kern enforces
            // and could not disable if it wanted to, and kern answered "ignored (unsupported)".
            // A user reading that has been told their hardening was dropped when it was not.
            //
            // The other three forms are genuinely not honoured, and each is named on its own rather
            // than lumped together, because they fail differently: a custom seccomp profile is not
            // loaded (kern's own deny-by-default allowlist runs instead, which is not the same
            // policy), an AppArmor profile name is not applied (kern has its own posture), and an
            // SELinux label is not set at all.
            "security_opt" => {
                let mut already: Vec<&str> = Vec::new();
                let mut matched: Vec<&str> = Vec::new();
                let mut absent: Vec<String> = Vec::new();
                for raw in list_value(node) {
                    let v = raw.trim().to_string();
                    let (head, tail) = match v.split_once([':', '=']) {
                        Some((h, t)) => (h.trim().to_ascii_lowercase(), t.trim().to_string()),
                        None => (v.trim().to_ascii_lowercase(), String::new()),
                    };
                    // The value carries its own punctuation in real files (`unconfined;`,
                    // "unconfined`"): compare on the word rather than on the token.
                    let word = tail
                        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '/' && c != '-' && c != '_')
                        .to_ascii_lowercase();
                    match head.as_str() {
                        "no-new-privileges" => already.push("no-new-privileges"),
                        // THE ONLY ONE OF THE FOUR THAT IS STILL A DIFFERENCE, and it is one by
                        // design: the file asks for NO filter and kern keeps its deny-by-default
                        // allowlist on every box. Honouring it would let a downloaded file switch
                        // off the guard, which is the one thing this runtime does not do.
                        "seccomp" if word == "unconfined" => absent.push(
                            "seccomp=unconfined: kern keeps its deny-by-default allowlist on every \
                             box, because a file that can switch off the filter is not a filter. \
                             The workload runs; a syscall outside the allowlist does not"
                                .to_string(),
                        ),
                        "seccomp" => absent.push(format!(
                            "seccomp={tail}: a Docker seccomp profile is a JSON format kern does not \
                             read, so its own allowlist runs instead"
                        )),
                        // MEASURED, and the sentence this replaces was false: inside a box
                        // `/proc/self/attr/current` reads the same as the caller's, because kern
                        // applies no AppArmor profile of its own. A file asking for `unconfined`
                        // therefore gets exactly what it asked for.
                        "apparmor" if word == "unconfined" => {
                            matched.push("apparmor=unconfined");
                        }
                        // A NAMED PROFILE IS FORWARDED, which it never was. `kern box --apparmor`
                        // has existed all along; a profile the host has not loaded fails the box
                        // CLOSED, which is the flag's own documented behaviour and the right one.
                        "apparmor" if !word.is_empty() => b.apparmor = Some(word.clone()),
                        // `label=disable` asks for no SELinux labelling, and kern sets no SELinux
                        // label on anything: the outcome is what the key asks for.
                        "label" if word == "disable" => matched.push("label=disable"),
                        "label" => absent.push(format!(
                            "label={tail}: kern sets no SELinux label, so a label OTHER than \
                             `disable` cannot be applied"
                        )),
                        // An unresolved `${VAR}` or a spelling this parser does not know: name the
                        // value verbatim rather than guess what it asked for.
                        _ => absent.push(format!("{v}: no kern equivalent")),
                    }
                }
                if !already.is_empty() {
                    warn(&format!(
                        "service '{name}': 'security_opt: {}' is ALREADY ENFORCED - kern sets \
                         NoNewPrivs on every box and there is no way to switch it off",
                        already.join(", ")
                    ));
                }
                if !matched.is_empty() {
                    warn(&format!(
                        "service '{name}': 'security_opt: {}' is ALREADY WHAT KERN DOES - it loads \
                         no AppArmor profile of its own and sets no SELinux label, so the box runs \
                         as the key asks",
                        matched.join(", ")
                    ));
                }
                if !absent.is_empty() {
                    warn(&format!(
                        "service '{name}': 'security_opt:' not honoured - {}",
                        absent.join("; ")
                    ));
                }
            }
            // `network_mode` IS THE POD MODEL FOR FOUR VALUES OUT OF FIVE.
            //
            // 123 of the 156 `network_mode` values in the corpus are `service:X`, which asks for
            // exactly what a kern stack does by default: every service in the stack shares ONE
            // network namespace.
            //
            // THE PARSER NO LONGER ANSWERS `service:X` WITH A SENTENCE, because the sentence was
            // about a wiring the parser cannot know. It said "kern already does this, NOT satisfied
            // under --no-pod" at a point where nothing has decided whether this stack gets one
            // namespace or one per service, and kern now makes that choice ITSELF from the file.
            // MEASURED on the corpus: 75 files use the key, and in 20 of them kern selects the
            // per-service wiring, so the reassurance was false and pointed at a flag the reader
            // never passed. It is recorded as a field and answered where the wiring is known, which
            // is the same correction `networks:` already got two commits ago.
            "network_mode" => {
                let v = node
                    .scalar
                    .as_deref()
                    .map(scalar_str)
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let head = v.split(':').next().unwrap_or("").to_ascii_lowercase();
                match head.as_str() {
                    "service" => match v.split_once(':').map(|(_, t)| t.trim()) {
                        Some(target) if !target.is_empty() => {
                            b.net_share = Some(target.to_string())
                        }
                        // `network_mode: service` with nothing after it names no service. Docker
                        // rejects the value; kern reports it rather than recording an empty target
                        // that would silently match no service later.
                        _ => warn(&format!(
                            "service '{name}': 'network_mode: {v}' names no service - ignored"
                        )),
                    },
                    // `container:X` NAMES A CONTAINER, NOT A SERVICE, and kern has no container
                    // outside this file to join: the value is Docker's way of reaching something
                    // started elsewhere. Zero of the 240 corpus files use it, so this is the arm
                    // that reports rather than the arm that works.
                    "container" => warn(&format!(
                        "service '{name}': 'network_mode: {v}' names a container outside this file, \
                         and kern joins no namespace it did not create - ignored. If '{}' is a \
                         service in this file, write `network_mode: service:{}` instead",
                        v.split_once(':').map(|(_, t)| t.trim()).unwrap_or(""),
                        v.split_once(':').map(|(_, t)| t.trim()).unwrap_or("")
                    )),
                    // SAID WITHOUT NAMING A WIRING, which is the only way the parser can say it and
                    // be right. The sentence used to read "maps to the stack's pod - one shared
                    // namespace", and MEASURED on a file whose `networks:` segregate, kern printed
                    // that line and then, four lines below, that it was giving each service its own
                    // namespace. `bridge` and `default` ask for the stack's ordinary network, and
                    // that request is satisfied under both wirings: the service is wired like every
                    // peer that wrote no `network_mode` at all.
                    "bridge" | "default" => warn(&format!(
                        "service '{name}': 'network_mode: {v}' is the stack's own network, which is \
                         what a service that names no `network_mode` gets: kern wires it exactly \
                         like its peers"
                    )),
                    // APPLIED NOW, PER SERVICE, and the sentence that said otherwise was written
                    // when a stack was always one namespace. It is not: a service on the host
                    // network simply does not join the pod, which is exactly what Docker does with
                    // `network_mode: host` - the container leaves the compose network and its peers
                    // stop resolving it by name. kern already skips the pod join, the peer relays
                    // and the hosts entries for a box with `net`, so the whole semantics is one
                    // field.
                    //
                    // MEASURED as a gap on a neutral corpus of 259 real compose files: 6 of them
                    // use it, and it was the second most common remaining difference after the keys
                    // that ask kern to be less confining.
                    "host" => b.net = true,
                    // `none` IS THE ISOLATION KERN GIVES BY DEFAULT OUTSIDE A POD: loopback and
                    // nothing else. Expressed by keeping the box out of the pod and attaching no
                    // NAT to it, so there is no route out of its namespace rather than a filter.
                    "none" => b.net_none = true,
                    _ => warn(&format!(
                        "service '{name}': 'network_mode: {v}' has no kern equivalent"
                    )),
                }
            }
            // `logging` WITH A FILE DRIVER IS WHAT KERN ALREADY DOES. 86 of the 94 `logging` values
            // in the corpus are `json-file` or `local`, both of which mean "write this container's
            // output to a file on the host". kern captures stdout and stderr of every box and serves
            // them with `kern logs`. What is genuinely dropped is the ROTATION (`max-size`,
            // `max-file`) and every network driver, and those are named separately.
            "logging" => {
                let driver = node
                    .children
                    .iter()
                    .find(|(k, _)| k == "driver")
                    .and_then(|(_, n)| n.scalar.as_deref())
                    .map(scalar_str)
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase();
                // `max-size` AND `max-file` ARE APPLIED NOW, so this no longer says they are not.
                // kern's capture has always been a size-capped log with one rotated generation; the
                // two options set that cap and that generation count, which is the whole of what
                // the `json-file` driver's options mean. Docker counts the ACTIVE file in
                // `max-file` and so does kern's flag, so `max-file: "3"` bounds the capture at
                // three files on both runtimes.
                //
                // The VALUES are not parsed here: they travel as written and `kern box` refuses one
                // it cannot read, by name, before the box starts. A second size grammar in this
                // crate is how two parsers come to disagree about `10m`.
                let opts = node.child("options");
                let opt = |k: &str| -> Option<String> {
                    opts.and_then(|o| o.child(k))
                        .and_then(|n| n.scalar.as_deref())
                        .map(scalar_str)
                        .map(|v| v.trim().trim_matches('"').to_string())
                        .filter(|v| !v.is_empty())
                };
                let max_size = opt("max-size");
                let max_file = opt("max-file");
                let other_opts: Vec<String> = opts
                    .map(|o| {
                        o.children
                            .iter()
                            .map(|(k, _)| k.clone())
                            .filter(|k| k != "max-size" && k != "max-file")
                            .collect()
                    })
                    .unwrap_or_default();
                match driver.as_str() {
                    "json-file" | "local" | "" => {
                        b.log_max_size = max_size.clone();
                        b.log_max_file = max_file.clone();
                        // NAMED ONLY WHEN SOMETHING IS ACTUALLY LOST. An `options:` block holding
                        // nothing but the two kern applies is fully honoured, and a warning there
                        // would teach the reader to skip the line that reports a real gap.
                        if !other_opts.is_empty() {
                            warn(&format!(
                                "service '{name}': 'logging:' - kern applies max-size and max-file \
                                 to its own capture (`kern logs {name}`); {} {} no kern equivalent",
                                other_opts
                                    .iter()
                                    .map(|k| format!("'{k}'"))
                                    .collect::<Vec<_>>()
                                    .join(", "),
                                if other_opts.len() == 1 { "has" } else { "have" }
                            ));
                        } else if max_size.is_none() && max_file.is_none() {
                            warn(&format!(
                                "service '{name}': 'logging: {driver}' is what kern already does - \
                                 stdout/stderr are captured to a file, read them with `kern logs`"
                            ));
                        }
                    }
                    other_drv => warn(&format!(
                        "service '{name}': 'logging: {other_drv}' has no kern equivalent - output is \
                         captured locally and read with `kern logs`, never shipped to a log server"
                    )),
                }
            }
            // `ipc:` AND `pid:` ARE NAMESPACE REQUESTS, and kern's answer to each is a MEASURED fact
            // about this runtime rather than a policy sentence.
            //
            // Measured on this tree, three ways: a box's `/proc/self/ns/ipc` and `/proc/self/ns/pid`
            // both differ from the host's, so every box already gets a private IPC and PID
            // namespace and there is no flag to turn either off; and two members of the SAME stack
            // have distinct `ipc` and `pid` namespaces while sharing one `net` namespace, so a pod
            // is a network unit and nothing else. That last measurement is what makes
            // `ipc: service:X` and `pid: service:X` unsatisfiable here rather than incidental: a
            // kern stack has no mechanism that puts two services in one IPC or PID namespace.
            //
            // `private` is therefore ALREADY ENFORCED and says so; `host` and the sharing forms are
            // named as not applied, with the boundary that is kept instead, because a workload that
            // asked to see the host's processes and cannot will otherwise fail with a message about
            // something else entirely.
            "ipc" | "pid" => {
                let v = node
                    .scalar
                    .as_deref()
                    .map(scalar_str)
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let head = v.split(':').next().unwrap_or("").to_ascii_lowercase();
                let ns = if key == "ipc" { "IPC" } else { "PID" };
                match head.as_str() {
                    "private" | "" => warn(&format!(
                        "service '{name}': '{key}: {v}' is ALREADY ENFORCED - every kern box gets \
                         its own {ns} namespace and there is no way to switch it off"
                    )),
                    "host" => warn(&format!(
                        "service '{name}': '{key}: host' is NOT applied - the box keeps its own {ns} \
                         namespace, which is a real kernel boundary kern does not hand back. A \
                         workload that must see the host's {ns} objects has to run outside a box"
                    )),
                    _ => warn(&format!(
                        "service '{name}': '{key}: {v}' is NOT applied - services in a kern stack \
                         share ONE network namespace and nothing else (measured: two members of the \
                         same stack have distinct {ns} namespaces), so there is no way to put two \
                         of them in one {ns} namespace"
                    )),
                }
            }
            "configs" | "extends" | "domainname" => {
                warn(&format!("service '{name}': '{key}:' ignored (unsupported)"));
            }
            // kern's own TOML config spells these `health_cmd:` / `depends_healthy:`; a
            // docker-compose.yml has DIRECT equivalents. Name them rather than fall through to a
            // dead-end "unsupported": a dropped health/ordering directive is not cosmetic, so a user
            // who mixed the two syntaxes would otherwise bring a stack up with no health gate and only
            // a vague warning to explain why.
            "health_cmd" | "health_interval" | "health_retries" | "health_timeout"
            | "health_start_period" | "health_action" => warn(&format!(
                "service '{name}': '{key}:' is kern's TOML spelling - in a docker-compose.yml declare \
                 a `healthcheck:` block (test / interval / retries / timeout / start_period)"
            )),
            "depends_healthy" => warn(&format!(
                "service '{name}': 'depends_healthy:' is kern's TOML spelling - in a docker-compose.yml \
                 use `depends_on: {{ SERVICE: {{ condition: service_healthy }} }}`"
            )),
            "depends_completed" => warn(&format!(
                "service '{name}': 'depends_completed:' is kern's TOML spelling - in a docker-compose.yml \
                 use `depends_on: {{ SERVICE: {{ condition: service_completed_successfully }} }}`"
            )),
            // THREE EXTENSION FIELDS ARE READ, and the rest of the namespace is not.
            //
            // `x-` is the Compose Specification's own extension mechanism: a tool must ignore the
            // keys it does not understand, and Docker Compose v2 validates a file carrying these and
            // echoes them back unchanged (measured against 29.6.2), so one file still runs on both
            // runtimes. That is what makes reading them additive rather than a dialect.
            //
            // WHAT THEY BUY, checked field by field. A `vcpu` profile carries `numa`, `nice`,
            // `backend` and `extends`; a `vdisk` carries `size`, `persistent`, `backend`, `iops` and
            // `bandwidth`; a `vgpio` carries nineteen device classes. Compose expresses `cpus`,
            // `cpuset` and `mem_limit`, and nothing else on those lists.
            //
            // `vgpio` is the one with no equivalent anywhere: today a compose file reaches GPIO by
            // writing `devices: /dev/gpiochip0`, so the SERVICE FILE decides which hardware it may
            // touch. Here the service declares intent and `kern.toml` holds the grant, so the
            // operator decides what "leds" resolves to on this host - which matters precisely
            // because the grant is chip-granular rather than per-line.
            //
            // ALL THREE, NOT THE ONE WITH THE BEST STORY: a surface that reads one key and silently
            // drops its two obvious siblings teaches a pattern that then does nothing, which is the
            // same defect as a flag accepted and ignored.
            //
            // The value is pushed raw; `profile_tokens` adds the `kind:` prefix unless it is already
            // there, so `leds` and `vgpio:leds` name the same profile exactly as they do in the TOML
            // spelling. `x-kern-vgpu` is deliberately absent: there is no `vgpu` profile kind.
            // `--security-profile <untrusted>`: the opt-in bundle (seccomp allowlist + `--cap-drop
            // ALL` + `--read-only`). Compose has no way to say "this code is not trusted", and the
            // three flags it would take instead are easy to get half-right. The VALUE is not checked
            // here: `kern box` owns that vocabulary and already refuses an unknown one by name, and a
            // second copy of the list in this crate is how the two come to disagree. `kern compose
            // config` asks that same vocabulary, so a dry run refuses what the bring-up would.
            "x-kern-security-profile" => {
                b.security_profile = node.scalar.as_deref().map(scalar_str)
            }
            // ONE DOOR FOR THE WHOLE `x-kern-` NAMESPACE, so the set of keys we read is the set of
            // kinds we publish and cannot drift from it. `profile_list_mut` owns the kind → field
            // pairing; this function does not name a single field.
            //
            // AN UNRECOGNISED KEY IN OUR OWN NAMESPACE IS NAMED, not silently dropped. The spec says
            // a tool must ignore the `x-` fields it does not understand, and every other vendor's
            // prefix is left alone below - but `x-kern-` is ours, so silence here would mean a typo
            // does nothing at all and says nothing at all, which is the defect this whole mechanism
            // exists to avoid. A typo and a kind from a build kern does not have here are DIFFERENT
            // problems, so they get different sentences: see `unread_kern_key_note`.
            other if other.starts_with("x-kern-") => {
                // `strip_prefix`, not `trim_start_matches`: the latter strips the prefix REPEATEDLY,
                // so `x-kern-x-kern-vcpu` would be read as a `vcpu` key. The guard above already
                // proved the prefix is there, so the fallback is unreachable rather than a default.
                let kind = other.strip_prefix("x-kern-").unwrap_or(other);
                match b.profile_list_mut(kind) {
                    Some(list) => push_profile(list, node),
                    None => warn(&unread_kern_key_note(name, other, kind)),
                }
            }
            // A CASE VARIANT OF OUR OWN PREFIX IS NAMED, AND STILL NOT READ. YAML keys are
            // case-sensitive, so `X-KERN-VCPU` is genuinely a different key and reading it would be
            // kern claiming a namespace it does not own. But the person who typed it meant ours, and
            // silence would leave them with a key that does nothing and says nothing - which is the
            // whole reason the branch above exists. Warned, never honoured.
            other
                if other.len() > 7
                    && other[..7].eq_ignore_ascii_case("x-kern-")
                    && !other.starts_with("x-kern-") =>
            {
                warn(&format!(
                    "service '{name}': '{other}:' looks like a kern extension field but kern's keys \
                     are lower-case ('x-kern-...'), so this one is ignored"
                ))
            }
            // Every other vendor's service-level extension field: defined by the spec, ignored on
            // purpose, silently.
            other if other.starts_with("x-") => {}
            // KEYS DOCKER ITSELF IGNORES ON LINUX. `cpu_count`, `cpu_percent` and `isolation` are
            // Windows-container options: the Linux daemon does not act on them either, so kern
            // ignoring them is not a difference from Docker and reporting one is a false alarm. On
            // the corpus, `cpu_count` was the ONLY difference two files had.
            "cpu_count" | "cpu_percent" | "cpus_shares" | "isolation" => {}
            other => warn(&format!(
                "service '{name}': '{other}:' ignored (unsupported)"
            )),
        }
    }
    // Compose entrypoint + command AFTER the loop (order-independent). Docker's rule depends on the
    // entrypoint FORM:
    //  * EXEC-form entrypoint (a list) → final argv is `entrypoint ++ command`.
    //  * SHELL-form entrypoint (`entrypoint: /init here` → `sh -c "/init here"`) → the shell string IS
    //    the whole command; Docker IGNORES `command`. Appending it would put the args after
    //    `sh -c <string>`, where they become the shell's positional params ($0,$1…) - NOT arguments to
    //    the entrypoint - so the box would run `/init here` and silently discard `command` (a "runs and
    //    lies" mis-conversion the audit caught). We drop `command` with a warning instead.
    // THE PAIR BECOMES `cpus`, AND ONLY IF THE FILE DID NOT ALSO SAY `cpus`. A file that writes both
    // has said the same thing twice, and the explicit `cpus:` is the one a reader will believe.
    if let Some(q) = cpu_quota {
        // Docker's default period when only a quota is given.
        let p = cpu_period.unwrap_or(100_000.0);
        if b.cpus.is_none() && p > 0.0 {
            let cores = q / p;
            if cores > 0.0 {
                b.cpus = Some(format!("{cores}"));
            }
        }
    } else if cpu_period.is_some() {
        warn(&format!(
            "service '{name}': 'cpu_period:' without 'cpu_quota:' bounds nothing - ignored"
        ));
    }
    if !entrypoint.is_empty() {
        // FORWARDED AS AN OVERRIDE, not merged into `command`. The merge produced
        // `IMAGE_ENTRYPOINT ++ entrypoint ++ command` once the box prepended the image's own, which
        // is correct only for an image that has none - and an image with one is exactly when a file
        // writes `entrypoint:`. See `ComposeBox::entrypoint`.
        // A STRING `entrypoint` DOES NOT DROP `command`, and it used to.
        //
        // The rule that a shell-form entrypoint ignores the command is a DOCKERFILE rule, and it
        // holds there because `ENTRYPOINT some string` becomes `/bin/sh -c "some string"`, which has
        // no place to put arguments. The Compose Specification says explicitly that its own string
        // form does NOT run in a shell, so the premise is absent and so is the consequence: a string
        // entrypoint is an argv like any other, and `command` appends to it exactly as it does for a
        // list. kern dropped the command and warned about it, which silently discarded arguments a
        // file asked for.
        b.entrypoint = Some(entrypoint);
    }
    Ok(b)
}

/// Map Docker Compose v3 `deploy.resources.limits.{memory,cpus,pids}` onto kern's hard caps - the
/// runtime enforces them via `--memory`/`--cpus`/`--pids-limit`. `deploy.resources.reservations` are
/// soft best-effort hints with no kern equivalent, so they're left alone (a compose that only reserves
/// still runs, just uncapped - which is what a reservation means). Anything else under `deploy:`
/// (`replicas`, `restart_policy`, `placement`, …) is swarm/orchestration kern doesn't do; silently
/// skipped here rather than warned per-key, since a single-node `deploy:` block is common and mostly
/// inert for `kern compose`.
fn apply_deploy(b: &mut ComposeBox, node: &Node, name: &str) {
    // `deploy.replicas` / `deploy.mode`: kern runs ONE box per service. Docker would start N, so
    // ignoring this in silence means a stack that looks scaled and is not - the exact "runs but lies"
    // this parser refuses. Named, so the operator decides.
    for k in [
        "replicas",
        "mode",
        "placement",
        "update_config",
        "rollback_config",
        "endpoint_mode",
    ] {
        if node.child(k).is_some() {
            warn(&format!(
                "service '{name}': deploy.{k} ignored - kern runs one box per service (no orchestrator)"
            ));
        }
    }
    if let Some(rp) = node.child("restart_policy") {
        if rp.child("condition").is_some() {
            warn(&format!(
                "service '{name}': deploy.restart_policy ignored - use `restart:` (kern restarts on failure only)"
            ));
        }
    }
    let Some(limits) = node.child("resources").and_then(|r| r.child("limits")) else {
        return;
    };
    let mut mapped = false;
    // A cap written BOTH ways (`mem_limit:` and `deploy.resources.limits.memory:`) is a real
    // ambiguity in the file, not in the runtime: the two values are usually different because the
    // author believed only one of them applied. `deploy` wins (Compose v2's rule), and the conflict
    // is NAMED - silently applying one of two conflicting numbers is exactly the "runs but lies"
    // this parser refuses elsewhere.
    let clash = |field: &str, old: &Option<String>, new: &str| {
        if let Some(prev) = old {
            if prev != new {
                warn(&format!(
                    "service '{name}': {field} is set twice with different values ('{prev}' and \
                     '{new}' under deploy.resources.limits) - the deploy value wins"
                ));
            }
        }
    };
    if let Some(m) = limits.child("memory").and_then(|n| n.scalar.as_deref()) {
        let v = scalar_str(m);
        clash("mem_limit", &b.memory, &v);
        b.memory = Some(v);
        mapped = true;
    }
    if let Some(c) = limits.child("cpus").and_then(|n| n.scalar.as_deref()) {
        let v = scalar_str(c);
        clash("cpus", &b.cpus, &v);
        b.cpus = Some(v);
        mapped = true;
    }
    if let Some(p) = limits.child("pids").and_then(|n| n.scalar.as_deref()) {
        let v = scalar_str(p);
        clash("pids_limit", &b.pids_limit, &v);
        b.pids_limit = Some(v);
        mapped = true;
    }
    // Honesty: a `limits:` block that maps NOTHING (a mistyped key like `mem:`/`cpu:`) would leave the
    // service silently UNCAPPED - a "runs but lies" the trust model forbids. Say so out loud rather than
    // pretend the cap took. (An empty/whitespace `limits:` - no children - is a no-op, not a typo.)
    if !mapped && !limits.children.is_empty() {
        warn(&format!(
            "service '{name}': deploy.resources.limits set none of memory/cpus/pids - the service runs UNCAPPED (check the key names)"
        ));
    }
}

/// `command`: exec-form list → argv verbatim; shell-form string → `sh -c "<string>"` (Docker semantics).
fn command_value(node: &Node) -> Vec<String> {
    command_argv(node).0
}

/// Split a command STRING into an argv the way a shell would tokenise it, without running one.
///
/// Quotes GROUP and are removed; a backslash escapes the next character outside single quotes, which
/// is what lets `sh -c "npm ci && npm run dev"` arrive as three arguments with the `&&` intact
/// INSIDE the third. Everything else is separated on whitespace. There is no expansion of any kind:
/// `$VAR` was already substituted by the compose interpolation pass long before this runs, and a
/// `$` that survived it is a literal the workload is meant to see.
///
/// An unterminated quote yields what it has rather than an error: the file is malformed, and the
/// workload's own argument parser gives a better message about it than this function could.
fn split_argv(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut has) = (Vec::new(), String::new(), false);
    let mut quote: Option<char> = None;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            // Inside single quotes nothing is special, not even a backslash: shell rules.
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some(_), _) => cur.push(c),
            (None, '\'') | (None, '"') => {
                quote = Some(c);
                // An EMPTY quoted string is still an argument: `-c ""` passes one, and dropping it
                // would shift every argument after it by one position.
                has = true;
            }
            (None, '\\') => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                    has = true;
                }
            }
            (None, c) if c.is_whitespace() => {
                if has {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            (None, c) => {
                cur.push(c);
                has = true;
            }
        }
    }
    if has {
        out.push(cur);
    }
    out
}

/// The entrypoint argv. Shares one parser with `command`, so the two cannot drift.
fn entrypoint_value(node: &Node) -> (Vec<String>, bool) {
    command_argv(node)
}

/// Parse a `command`/`entrypoint` node into an argv. The second element of the pair is retained for
/// the callers' shape and is always `false`: see below for why there is no longer a shell form.
///
/// A BARE STRING IS SPLIT INTO AN ARGV, NOT WRAPPED IN A SHELL, and this is the one place where
/// Compose deliberately differs from a Dockerfile. The Compose Specification says it outright:
///
///   "Unlike the CMD instruction of an image, the shell-form syntax for `command` does not
///    implicitly run in the context of the SHELL instruction."
///
/// and tells the author to write the shell themselves when they want one:
///
///   "If you expect the command to rely on features of a shell environment such as environment
///    variables, then ensure the command is run within a shell: command: /bin/sh -c '...'"
///
/// MEASURED, AND THE WRAPPING BROKE A CANONICAL FILE. kern used to produce `sh -c "<string>"`, so
/// Docker's own `awesome-compose` WordPress sample - `command: '--default-authentication-plugin=…'`
/// on `mariadb` - ran `sh` with that string as an OPTION and the database died on every start with
/// `sh: 0: Illegal option --`. Two more files in the neutral corpus carry the same shape (a command
/// that begins with `-`), and they were broken in exactly the same way.
///
/// NOTHING THAT NEEDED A SHELL LOSES ONE. Of the 83 string commands in that corpus, 13 use shell
/// syntax and all but two of those already write `sh -c "…"` or `bash -c "…"` themselves, which is
/// what the specification asks for and which splitting preserves verbatim. The remaining two need no
/// shell at all: their metacharacters are inside quoted arguments.
fn command_argv(node: &Node) -> (Vec<String>, bool) {
    if let Some(sc) = &node.scalar {
        let sc = sc.trim();
        if sc.starts_with('[') {
            return (parse_inline_list(sc), false); // exec-form
        }
        if !sc.is_empty() {
            return (split_argv(&scalar_str(sc)), false);
        }
    }
    if !node.items.is_empty() {
        return (node.items.iter().map(|i| scalar_str(i)).collect(), false); // exec-form block list
    }
    (Vec::new(), false)
}

/// A `K=v` collection written in either compose shape - a list of `- K=v` and/or a map of `K: v` -
/// flattened to `["K=v", …]`. Shared by `environment` and `build.args`, which have the identical YAML
/// shape, so the two can't drift. `${VAR}` is already substituted document-wide (see
/// `interpolate_document`), so values are used verbatim here.
///
/// A list item with NO `=` (`- API_KEY`) is Docker's **host pass-through**: the value is taken from the
/// host environment. If the host has it, we emit `API_KEY=<host value>`; if not, we OMIT it (Docker
/// does too). Passing the bare `API_KEY` straight through was a bug - the box's `--env K=V` parser
/// rejected it and the whole service failed to start.
/// `environment:`/`build.args` as `K=V` strings, in every shape the Specification allows: a map, a
/// block list, a flow list, a list item that is itself a map, and a key with no value at all.
///
/// `dotenv` is the project `.env`, consulted for a BARE pass-through name after the process
/// environment.
///
/// `build.args` and `environment:` both pass one, and in both cases the reason is evidence rather
/// than symmetry. `args: [SENTRY_IMAGE]` against a `.env` that sets `SENTRY_IMAGE` is Sentry
/// self-hosted's own build - the image would otherwise be built `FROM` nothing. And its
/// `environment:` block says so in a comment, above the two keys it writes with no value:
///
/// ```yaml
///     # Leaving the value empty to just pass whatever is set
///     # on the host system (or in the .env file)
///     COMPOSE_PROFILES:
///     SENTRY_EVENT_RETENTION_DAYS:
/// ```
///
/// MEASURED before it was believed: with the shell alone, `SENTRY_EVENT_RETENTION_DAYS` reached the
/// box EMPTY and Sentry's own config died on `int("")` - `ValueError: invalid literal for int() with
/// base 10: ''` - on every start of the `web` service.
///
/// A variable the file never names still does not reach the box: this only resolves the two
/// spellings that ASK for a pass-through.
fn kv_pairs_from(node: &Node, dotenv: Option<&crate::DotEnv>) -> Vec<String> {
    let lookup = |name: &str| -> Option<String> {
        std::env::var(name)
            .ok()
            .or_else(|| dotenv.and_then(|d| d.get(name)).map(str::to_string))
    };
    let mut out = Vec::new();
    // A FLOW list (`environment: [A=1, B=2]`) arrives as one scalar, not as `items`: without this it
    // was dropped entirely, so a service silently ran with none of its environment. The block list
    // (`- A=1`) and the map form were already handled below.
    let flow: Vec<String> = node
        .scalar
        .as_deref()
        .filter(|sc| sc.trim_start().starts_with('['))
        .map(parse_inline_list)
        .unwrap_or_default();
    for it in node.items.iter().chain(flow.iter()) {
        let entry = scalar_str(it);
        let trimmed = entry.trim();
        if trimmed.starts_with('{') {
            // A list item written as `- KEY: value` (the map form leaked into the list form) was folded
            // into an inline-map item `{KEY: value}` by the tree builder. Docker PANICS on this mix
            // (`interface conversion: … not map`); we salvage each pair as `KEY=value` so the stack
            // still comes up.
            for (k, v) in parse_inline_table(trimmed).children {
                let raw = v.scalar.as_deref().map(scalar_str).unwrap_or_default();
                out.push(format!("{k}={raw}"));
            }
        } else if entry.contains('=') {
            out.push(entry);
        } else if let Some(val) = lookup(&entry) {
            // bare `- KEY` present in the environment → pass its value through.
            out.push(format!("{entry}={val}"));
        }
        // bare `- KEY` absent from the host env → omit (Docker semantics).
    }
    for (k, v) in &node.children {
        // `K:` with no value, or an explicit YAML null (`null` / `~`), means PASS THROUGH from the
        // host environment - Docker's rule, and the same thing the `- KEY` list form already did.
        // Emitting `K=null` instead handed the service the literal four-letter string, which is worse
        // than empty: it looks like a value. The check is on the RAW scalar, so a deliberate
        // `K: "null"` keeps its quotes and stays a real value.
        let literal_null = match v.scalar.as_deref() {
            // A value that is nothing but marks: a reference was written and resolved to nothing,
            // which Docker renders as the empty string.
            Some(sc) if !sc.is_empty() && sc.chars().all(|c| c == UNSET_MARK) => false,
            // A MISSING scalar asks for a PASSTHROUGH WHEN THERE IS SOMETHING TO PASS, and is an
            // empty value otherwise. The two spellings that reach here as `None` cannot be told
            // apart - MEASURED: a bare `K:` and `K: ${UNSET}` are both `scalar: None` after
            // interpolation, while `K: ""` is `Some("\"\"")` and `K: null` is `Some("null")` - and
            // Docker reads them differently: the first takes the value from the environment, the
            // second is the empty string.
            //
            // Told apart by [`UNSET_MARK`], which the interpolator leaves where a REFERENCE
            // resolved to nothing: a scalar of nothing but marks is the empty string Docker gives
            // `K: ${UNSET}`, and a truly absent scalar is the passthrough Docker gives `K:`. Sentry
            // self-hosted needs both in one file - `SENTRY_EVENT_RETENTION_DAYS:` picks up its
            // `.env` value, and a valueless key bound nowhere stays absent, because passed as empty
            // its config dies on `value[0]`.
            None => true,
            // NOT the empty string: interpolation runs over the whole document first, so
            // `X: ${UNSET}` arrives here as an empty scalar and Docker wants X set to EMPTY, not
            // omitted. Only an explicit YAML null (or no scalar at all) means passthrough.
            Some(sc) => matches!(sc.trim(), "null" | "Null" | "NULL" | "~"),
        };
        if literal_null {
            // Present in the host env → forward its value; absent → omit the variable entirely
            // (Docker semantics: an unresolved passthrough is not set, not set-to-empty).
            if let Some(val) = lookup(k) {
                out.push(format!("{k}={val}"));
            }
            continue;
        }
        let raw = v.scalar.as_deref().map(scalar_str).unwrap_or_default();
        out.push(format!("{k}={raw}"));
    }
    out
}

/// Substitute `${VAR}` and `${VAR:-default}` throughout the compose text from the host env, like
/// Docker's pre-parse interpolation. Handles `$$` → literal `$` (Docker's escape). An unset var with
/// no default → empty string + one warning (Docker semantics), never a leftover literal `${VAR}` that
/// would confuse a downstream tool. `$VAR` without braces and other `${...}` operators are left as-is.
///
/// COMMENT-AWARE: a `${VAR}` inside a trailing `#` comment is NOT substituted and raises no unset-var
/// warning (the comment text is dropped by the lexer anyway; interpolating it only produced spurious
/// stderr noise - audit finding). We split each line at its first unquoted `#`, interpolate the code
/// part, and re-attach the comment verbatim.
fn interpolate_document(text: &str, dotenv: &crate::DotEnv) -> String {
    if !text.contains('$') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    // `text.lines()` drops the line terminators; rebuild them. A trailing newline is preserved by
    // checking the original. We interpolate only the pre-comment part of each line.
    let ends_with_nl = text.ends_with('\n');
    let mut first = true;
    for line in text.lines() {
        if !first {
            out.push('\n');
        }
        first = false;
        let (code, comment) = split_at_comment(line);
        out.push_str(&interpolate_fragment(code, dotenv));
        out.push_str(comment); // verbatim - no interpolation, no warning
    }
    if ends_with_nl {
        out.push('\n');
    }
    out
}

/// Split a line into `(code, comment)` at the first unquoted `#` (the `#` and everything after it is
/// the comment). Quote-aware, matching the lexer's comment rule so we agree on where a value ends.
fn split_at_comment(line: &str) -> (&str, &str) {
    let bytes = line.as_bytes();
    let mut q = 0u8;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if q != 0 {
            if c == q {
                q = 0;
            }
        } else if c == b'"' || c == b'\'' {
            q = c;
        } else if c == b'#' && (i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
            return (&line[..i], &line[i..]);
        }
        i += 1;
    }
    (line, "")
}

/// Interpolate `${VAR}`/`${VAR:-default}`/`$$` in a single comment-free fragment. Slices are at
/// `${`/`}`/`$$` ASCII offsets, so multibyte values in the document are never sliced mid-char.
/// Erase [`UNSET_MARK`] from a string that is already a final value rather than a YAML scalar - the
/// `.env` reader, which has no absent-versus-empty distinction to make.
pub(crate) fn strip_unset_mark(s: &str) -> String {
    s.replace(UNSET_MARK, "")
}

pub(crate) fn interpolate_fragment(text: &str, dotenv: &crate::DotEnv) -> String {
    interpolate_depth(text, 0, dotenv)
}

/// Max nesting depth for `${A:-${B:-…}}` - a hard cap so an adversarial input can't drive unbounded
/// recursion. Real nesting is 1-2 deep; anything past this leaves the inner `${…}` un-substituted.
const MAX_INTERP_DEPTH: usize = 16;

/// The balanced-`}` index for a `${…}` body (the `inner` slice starts right after `${`). Counts nested
/// `${` so `${A:-${B}}` closes at the OUTER `}`, not the first. Returns `None` if unbalanced.
fn matching_brace_end(inner: &str) -> Option<usize> {
    let bytes = inner.as_bytes();
    let mut depth = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'}' if depth == 0 => return Some(i),
            b'}' => depth -= 1,
            b'$' if i + 1 < bytes.len() && bytes[i + 1] == b'{' => {
                depth += 1;
                i += 1; // skip the '{'
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn interpolate_depth(text: &str, depth: usize, dotenv: &crate::DotEnv) -> String {
    if !text.contains('$') {
        return text.to_string();
    }
    if depth >= MAX_INTERP_DEPTH {
        // Too deep - stop resolving and return the text as-is (bounded work, no leaked fragment).
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        if let Some(tail) = after.strip_prefix('$') {
            // `$$` → literal `$`.
            out.push('$');
            rest = tail;
            continue;
        }
        let Some(inner) = after.strip_prefix('{') else {
            // BARE `$NAME`, which Docker interpolates exactly like `${NAME}`. A name is
            // `[A-Za-z_][A-Za-z0-9_]*`; anything else after `$` (a digit, `(`, punctuation, end of
            // string) is NOT a reference and stays literal - so `$(date)` and `$1` in a shell command
            // are untouched, and `$$` above is still the escape for a literal `$`.
            let name_len = {
                let mut it = after.chars();
                match it.next() {
                    Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                        1 + it
                            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                            .map(char::len_utf8)
                            .sum::<usize>()
                    }
                    _ => 0,
                }
            };
            if name_len > 0 {
                out.push_str(&interpolate_expr(&after[..name_len], dotenv));
                rest = &after[name_len..];
            } else {
                out.push('$');
                rest = after;
            }
            continue;
        };
        let Some(end) = matching_brace_end(inner) else {
            // Unterminated `${` - kept literal, and SAID. The previous comment here assumed "a
            // downstream parse error will surface if it matters", and MEASURED it does not:
            // `image: "${NONCHIUSA"` parsed clean and the image name became the literal
            // `${NONCHIUSA`, so the only error arrived much later, from a registry, about a tag
            // nobody wrote. Someone who types `${` means interpolation, and turning that into a
            // literal is a reinterpretation - silent is what makes it a defect.
            //
            // A warning rather than a refusal: the same text can legitimately appear inside a block
            // scalar carrying a shell script, and interpolation runs over the whole document, so
            // refusing would reject files that work today. Warned once per distinct fragment.
            warn_once(&format!(
                "unterminated '${{' in a value - kept literally as written, NOT interpolated \
                 (close the brace, or write '$$' for a literal dollar): {}",
                &inner[..inner.len().min(40)]
            ));
            out.push_str("${");
            rest = inner;
            continue;
        };
        let expr = &inner[..end];
        // Nested interpolation `${A:-${B:-c}}` (Docker supports it): resolve any inner `${…}` in the
        // expression FIRST (bounded recursion, depth-capped), then evaluate the outer expression on the
        // resolved text. `matching_brace_end` found the BALANCED `}`, so `expr` holds the whole inner.
        let resolved = if expr.contains("${") {
            interpolate_depth(expr, depth + 1, dotenv)
        } else {
            expr.to_string()
        };
        out.push_str(&interpolate_expr(&resolved, dotenv));
        rest = &inner[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Evaluate the inside of a `${…}` against the host env, with Docker's full modifier set:
///   `${VAR}`            → the value, or empty + a warning if unset
///   `${VAR:-default}`   → default if VAR is unset OR empty; `${VAR-default}` → only if unset
///   `${VAR:+replace}`   → replace if VAR is set AND non-empty; `${VAR+replace}` → if set (even empty)
///   `${VAR:?message}`   → the value, else warn with message (VAR empty-or-unset); `${VAR?message}` → unset only
/// The `:` prefix means "treat empty like unset" (Docker semantics). Operators are matched longest-
/// first (`:-` before `-`) so the colon variant isn't shadowed.
fn interpolate_expr(expr: &str, dotenv: &crate::DotEnv) -> String {
    // Find the operator: the first of `:-`, `-`, `:+`, `+`, `:?`, `?` (a `:` binds to the following op).
    let ops: [(&str, char, bool); 6] = [
        (":-", '-', true),
        (":+", '+', true),
        (":?", '?', true),
        ("-", '-', false),
        ("+", '+', false),
        ("?", '?', false),
    ];
    let (var, op, arg, colon) = {
        let mut found = None;
        // Scan for the earliest operator position; among ops at the same position, the 2-char (colon)
        // form wins because we test it first in `ops`.
        for (tok, kind, is_colon) in ops {
            if let Some(pos) = expr.find(tok) {
                let better = match found {
                    None => true,
                    Some((_, p, _, _)) => pos < p || (pos == p && is_colon),
                };
                if better {
                    found = Some((kind, pos, is_colon, tok.len()));
                }
            }
        }
        match found {
            Some((kind, pos, is_colon, toklen)) => {
                (&expr[..pos], Some(kind), &expr[pos + toklen..], is_colon)
            }
            None => (expr, None, "", false),
        }
    };

    // Docker precedence: the process environment wins; a project `.env` is the fallback.
    let val = std::env::var(var)
        .ok()
        .or_else(|| dotenv.get(var).map(str::to_string));
    // "present" per the colon rule: with `:` an empty value counts as absent.
    let present = match &val {
        Some(v) => !(colon && v.is_empty()),
        None => false,
    };
    match op {
        Some('-') => {
            if present {
                val.unwrap_or_default()
            } else {
                arg.to_string()
            }
        }
        Some('+') => {
            if present {
                arg.to_string()
            } else {
                String::new()
            }
        }
        // `${VAR:?err}` / `${VAR?err}` IS A REFUSAL, and it was a warning.
        //
        // The whole point of the `?` form is that the file REFUSES to be rendered without the value:
        // it is what a compose file writes for a password or a token, and the Compose Specification
        // raises an error. kern warned and substituted the EMPTY STRING, so the stack came up with
        // `MYSQL_PASSWORD=` - a database initialised with a blank password, from a file whose author
        // wrote the one construct that exists to stop exactly that.
        //
        // MEASURED on the neutral corpus: five such files, all of them credentials.
        //
        // COLLECTED RATHER THAN RETURNED, which is deliberate. Interpolation runs over the whole
        // document through three recursive functions, and threading a `Result` through them would
        // stop at the FIRST missing variable; a reader with three unset secrets would then fix one,
        // rerun, and be told about the next. The whole list is worth more than the early exit, and
        // the collector is the same thread-local shape `warn_once` already uses in this file.
        Some('?') => val.filter(|_| present).unwrap_or_else(|| {
            let msg = if arg.is_empty() {
                "required but not set".to_string()
            } else {
                arg.to_string()
            };
            REQUIRED_UNSET.with(|r| r.borrow_mut().push(format!("{var} ({msg})")));
            String::new()
        }),
        _ => val.unwrap_or_else(|| {
            warn(&format!(
                "${{{var}}} is not set (no default) - substituted empty (set it in your shell, like Docker)"
            ));
            // The empty string Docker substitutes, carrying the mark that says a REFERENCE was
            // written here - which is what tells a valueless key apart from one whose value
            // resolved to nothing. `scalar_str` erases it at the single place a scalar becomes a
            // value, so no consumer ever sees it.
            UNSET_MARK.to_string()
        }),
    }
}

/// `ports`: each entry → a `--publish` string, RAW (no numeric coercion → the sexagesimal trap can't
/// fire). Long-form (`{target,published,...}`) is reconstructed from fields, not passed verbatim.
/// `/udp` (and any non-TCP proto) is refused-with-warning - kern publishes TCP only, and silently
/// dropping the proto would mislead. A plain `host:box` (no host-IP) publishes on kern's loopback
/// default, which differs from Docker's all-interfaces default → warn so a Docker user isn't surprised
/// their service "doesn't answer from outside".
/// Published port specs, plus (out-param) the container-only ones, which are DECLARED rather than
/// published: see the comment at the detection site.
fn ports_value(node: &Node, svc: &str, declared: &mut Vec<(u16, bool)>) -> Vec<String> {
    let mut out = Vec::new();
    let mut push_spec = |spec: String| {
        let (host_port, proto) = match spec.rsplit_once('/') {
            Some((p, proto)) => (p.to_string(), Some(proto.to_ascii_lowercase())),
            None => (spec.clone(), None),
        };
        // `/udp` is PUBLISHED, not dropped: `kern box -p host:box/udp` has a real UDP forwarder, and
        // silently skipping it here made the same mapping work through the CLI and vanish through
        // compose - two paths disagreeing about the same input. Any OTHER protocol has no forwarder,
        // so it is still refused, by name.
        let mut keep_proto = "";
        if let Some(pr) = &proto {
            match pr.as_str() {
                "tcp" => {}
                "udp" => keep_proto = "/udp",
                other => {
                    warn(&format!(
                        "service '{svc}': port '{spec}' uses /{other} - kern forwards TCP and UDP only, entry SKIPPED"
                    ));
                    return;
                }
            }
        }
        // host:box with no host-IP → kern binds loopback (secure default, unlike Docker's 0.0.0.0).
        let colons = host_port.matches(':').count();
        // CONTAINER-ONLY forms: `"8000"` and `":8000"`. Docker treats them identically (`config`
        // normalises both to `target: 8000` with no `published:`) and picks an EPHEMERAL host port at
        // `up`. kern has no ephemeral allocator, and inventing one would be worse than saying so: it
        // would publish a port the file never named, on a number nobody could predict.
        //
        // So the entry becomes a DECLARED port instead of a published one - the same space `expose:`
        // and `port:` feed - which is exactly what it means inside the pod: the service listens here.
        // Refusing it was the alternative, and it cost four real files (Supabase, Budibase, Jitsi,
        // OpenCTI) that reach this form through an unset `${VAR}` and that Docker accepts. Measured
        // against `docker compose config`, not assumed.
        let bare = host_port.strip_prefix(':').unwrap_or(&host_port);
        if colons == 0 || (colons == 1 && host_port.starts_with(':')) {
            match bare.parse::<u16>() {
                Ok(n) if n > 0 => {
                    declared.push((n, keep_proto == "/udp"));
                    // NAME THE PORT THAT IS IN THE FILE. This used to be a fixed sentence quoting
                    // `8000` whatever the file said, so a stack declaring only `9090` was told about
                    // a port that appears nowhere in it. A field test on `dev` had to go and prove
                    // that kern was not reading stale state from another file before it could be
                    // dismissed, which is the cost of an example that looks like an observation.
                    //
                    // Still `warn_once`, so the dedup is now per DISTINCT PORT rather than per file:
                    // a stack with one such port says it once, and each extra line names a different
                    // number and is therefore worth its own line.
                    warn_once(&container_only_port_note(n));
                }
                _ => warn(&format!(
                    "service '{svc}': port '{spec}' is not a port in 1..=65535, entry SKIPPED"
                )),
            }
            return;
        }
        // NO WARNING FOR A TWO-FIELD SPEC ANY MORE. It used to say the port was bound to 127.0.0.1
        // "unlike Docker", and that sentence stopped being true when the publish default became
        // `0.0.0.0`: a bare `8080:80` now binds what the file says it binds. It was also, by a wide
        // margin, the noisiest line this parser produced - MEASURED on a neutral corpus of 259
        // compose files, 203 of them (78%) triggered it, so it was both false and the first thing a
        // reader learned to skip. A host that configures the narrower posture is told once, by the
        // box that applies it, rather than once per port by a parser that cannot see the policy.
        out.push(format!("{host_port}{keep_proto}"));
    };

    // Block or inline list of entries.
    let entries: Vec<String> = if let Some(sc) = &node.scalar {
        if sc.trim_start().starts_with('[') {
            parse_inline_list(sc)
        } else {
            vec![scalar_str(sc)]
        }
    } else if !node.items.is_empty() {
        // Items may be scalars ("8080:80") or inline-table long-form ({target: 80, published: 8080}).
        node.items
            .iter()
            .map(|it| reconstruct_port_item(it, svc))
            .collect()
    } else {
        // A `ports:` whose entries are BLOCK mappings (a `- ` opening a nested mapping over several
        // lines, rather than an inline `{…}`) lands here with no scalar/items - a shape we don't
        // reconstruct. NEVER silently drop it: warn so the user knows a port wasn't published.
        if !node.children.is_empty() {
            warn(&format!(
                "service '{svc}': block-mapping long-form `ports` not supported - use inline `{{target: N, published: M}}` or a \"M:N\" string; entry SKIPPED"
            ));
        }
        Vec::new()
    };
    for e in entries {
        if !e.is_empty() {
            push_spec(e);
        }
    }
    out
}

/// Turn one `ports` list item into a `[ip:]host:box[/proto]` string. A plain scalar passes through; an
/// inline-table long-form (`{target: 80, published: 8080, protocol: udp}`) is REBUILT from its fields
/// (never passed verbatim - it's an object, not a string).
fn reconstruct_port_item(item: &str, svc: &str) -> String {
    let t = item.trim();
    if !t.starts_with('{') {
        return scalar_str(t);
    }
    let inner = t.trim_start_matches('{').trim_end_matches('}');
    let (mut target, mut published, mut proto, mut host_ip) =
        (String::new(), String::new(), String::new(), String::new());
    for field in split_top_commas(inner) {
        if let Some((k, v)) = field.split_once(':') {
            let (k, v) = (k.trim(), scalar_str(v));
            match k {
                "target" => target = v,
                "published" => published = v,
                "protocol" => proto = v,
                "host_ip" => host_ip = v,
                _ => {}
            }
        }
    }
    if target.is_empty() {
        warn(&format!(
            "service '{svc}': a long-form port has no `target` - skipped"
        ));
        return String::new();
    }
    let published = if published.is_empty() {
        target.clone()
    } else {
        published
    };
    let mut spec = if host_ip.is_empty() {
        format!("{published}:{target}")
    } else {
        format!("{host_ip}:{published}:{target}")
    };
    if !proto.is_empty() {
        spec.push('/');
        spec.push_str(&proto);
    }
    spec
}

/// `tmpfs`: FORWARDED UNTOUCHED, and that is the fix rather than laziness.
///
/// This used to pre-chew Docker's option list (`PATH:size=10M,mode=1770,uid=1000`) into kern's own
/// `PATH:size` spelling, which meant kern had TWO tmpfs grammars and this one had to guess which it
/// was looking at. It guessed by asking whether the suffix contained an `=` at all, so an option
/// list with none in it (`/run:rw`, `/run:exec`, `/run:noexec,nosuid`, all valid Docker) was handed
/// on as a SIZE and the service died with "bad size 'rw'". The same guess made `kern box --tmpfs
/// /run:size=64m` fail while the identical compose entry worked: one binary, two grammars,
/// disagreeing with itself.
///
/// `parse_tmpfs` now parses the option list itself, so there is one grammar and nothing to keep in
/// step. Found on 245 real compose files; `scripts/compose-corpus-gate.py` keeps it found.
fn tmpfs_value(node: &Node) -> Vec<String> {
    list_value(node)
}

/// Compose `devices:` - `HOST[:CONTAINER[:PERMS]]`, one entry per device node.
///
/// WHY THIS IS A BIND AND NOT A NEW GRANT. `-v` ALREADY passes a host device node into a box:
/// measured on this tree, `kern box --image alpine -v /dev/kvm:/dev/kvm` gives the workload
/// `crw-rw---- 10, 232 /dev/kvm`, a working character device, and the same for `/dev/net/tun`. So a
/// compose file could always reach a device by writing it under `volumes:`, and refusing the key
/// whose ONLY purpose is to say that was not withholding a privilege, it was withholding a spelling.
/// This routes `devices:` through the same mechanism, which is why it adds no attack surface: the
/// node arrives with the HOST's own owner and mode, and a caller who cannot open it on the host
/// cannot open it in the box either.
///
/// WHAT THAT CEILING IS, MEASURED, because "no new surface" is worth nothing unstated. Bound into a
/// box and read as the invoking user: `/dev/mem` (`root:kmem`, 0640) is denied, `/dev/kmsg` is
/// denied, and the raw disk `/dev/nvme0n1` is READABLE - on this host, because the invoking user is
/// in group `disk` and the node is `root:disk` 0660, so it is readable outside a box too. The
/// boundary a rootless kern box enforces is the INVOKING USER, never root: a `devices:` entry can
/// reach exactly what the person running `kern compose up` could already reach with `cat`. An
/// operator who does not want that reachable from a stack has to take it away from the user, which
/// is the same statement Docker's `--device` makes and the same one `-v` has always made here.
///
/// `/dev/net/tun` IS NOT ROUTED THERE. It is 37 of the 83 `devices:` values in a 240-file corpus,
/// and the node alone is not enough for it: creating the tunnel interface needs `CAP_NET_ADMIN`
/// inside the box's network namespace, which kern keeps only for `--tun` (see `cap_drop_mask`). A
/// bind would hand over the node and leave the workload unable to use it, which is the "runs and
/// lies" outcome this parser exists to prevent. Mapping it to `--tun` delivers the node AND the
/// capability. A file that renames the target (`/dev/net/tun:/dev/something`) falls through to the
/// bind, because `--tun` fixes the in-box path.
///
/// PERMS ARE HONOURED WHERE KERN HAS THEM AND NAMED WHERE IT DOES NOT. Docker's third field is a
/// cgroup device ACL of `r`/`w`/`m`; kern has read-only (`-v …:ro`) and nothing else, so a spec with
/// no `w` becomes `:ro` and one with `w` stays writable. `m` is mknod INSIDE the box, which a
/// rootless box cannot do at all; it is only named when the file asked for something other than
/// Docker's default `rwm`, since warning on the default would be noise on every entry.
///
/// A DEVICE THAT IS NOT ON THIS HOST IS NOT SILENTLY DROPPED. `kern box` refuses a `-v` whose source
/// does not exist, by name and without creating it (measured: `source /dev/vfio-inesistente: No such
/// file or directory`, and nothing appeared on the host). That is the same outcome Docker gives, and
/// it is the honest one: a stack that needs a device the host has not got has not started correctly
/// on either runtime.
/// Compose `links:` - `SERVICE[:ALIAS]` - normalised to `SERVICE:ALIAS`, with the ordering edge
/// pushed onto `depends_on`.
///
/// SHARED BY BOTH PARSERS for the same reason `normalise_devices` is: `links` must not come to mean
/// one thing in a `docker-compose.yml` and another in a `kern.toml`.
///
/// THE EDGE IS ADDED, NOT REPLACED, and duplicates are avoided: a file that writes both
/// `depends_on: [db]` and `links: [db]` must produce one edge, not two, or the level barrier waits
/// on a service twice and the topology report double-counts it.
/// This machine's `os/arch`, in Compose's spelling.
///
/// `std::env::consts` is the compiler's view of the target, which is exactly the right one: it is the
/// architecture the binary that will run the workload was built for, not what `uname` reports about a
/// kernel that may be running a 32-bit userland.
#[must_use]
fn host_platform() -> String {
    let arch = match std::env::consts::ARCH {
        // Compose spells these the way Docker does, which is not always Rust's spelling.
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{}/{arch}", std::env::consts::OS)
}

/// Does a compose `platform:` name this machine?
///
/// TOLERANT OF THE THREE SPELLINGS a file may use, because being wrong here means warning about a
/// platform that is in fact the one running: `amd64` alone (arch only), `linux/amd64`, and
/// `linux/amd64/v3` (the variant suffix, which kern neither selects nor refuses). An empty string is
/// not a platform and is handled by the caller.
#[must_use]
fn platform_matches_host(v: &str) -> bool {
    let host = host_platform();
    let (host_os, host_arch) = host.split_once('/').unwrap_or(("linux", ""));
    let parts: Vec<&str> = v.split('/').filter(|p| !p.is_empty()).collect();
    match parts.as_slice() {
        [arch] => *arch == host_arch,
        [os, arch] | [os, arch, _] => *os == host_os && *arch == host_arch,
        _ => false,
    }
}

/// Docker's `cpu_shares` (2..=262144, **1024 = normal**) to cgroup v2's `cpu.weight` (1..=10000,
/// **100 = normal**).
///
/// THE PROPERTY THAT DEFINES THIS MAPPING IS THAT NORMAL MAPS TO NORMAL: a share is a RATIO against
/// the default, so `1024` means "an ordinary slice" and must come out as `100`, the weight that means
/// the same thing. `weight = shares * 100 / 1024` is the only proportional map with that property,
/// and the clamp then absorbs both ends of Docker's range (2 would be 0, and 262144 would be 25600).
///
/// A FIRST VERSION MAPPED THE ENDPOINTS INSTEAD (`1 + (shares - 2) * 9999 / 262142`) and was WRONG in
/// exactly the case every real file hits: MEASURED inside a box, `cpu_shares: 1024` produced
/// `cpu.weight = 39`, so a service asking for an ordinary slice was given well under half of one,
/// silently. Endpoints are not the invariant; the default is.
///
/// Saturating arithmetic on `u64` throughout: the caller has already bounded the input, and a
/// conversion that could overflow in a release build is a conversion that produces a share nobody
/// asked for.
#[must_use]
pub(crate) fn docker_shares_to_cpu_weight(shares: u64) -> u64 {
    let s = shares.clamp(2, 262_144);
    (s.saturating_mul(100) / 1024).clamp(1, 10_000)
}

pub(crate) fn normalise_links(entries: &[String], depends_on: &mut Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(entries.len());
    for raw in entries {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        let (service, alias) = match entry.split_once(':') {
            Some((s, a)) if !s.trim().is_empty() && !a.trim().is_empty() => (s.trim(), a.trim()),
            // `db` alone: Docker aliases it under its own name, which is what a kern stack already
            // resolves. It is kept in the list anyway so the ordering edge below is added for it.
            _ => (entry, entry),
        };
        if !depends_on.iter().any(|d| d == service) {
            depends_on.push(service.to_string());
        }
        out.push(format!("{service}:{alias}"));
    }
    out
}

pub fn normalise_devices(entries: &[String], name: &str, tun: &mut bool) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(entries.len());
    for raw in entries {
        let entry = raw.trim().to_string();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.splitn(3, ':');
        let host = parts.next().unwrap_or("").trim().to_string();
        let target = parts.next().unwrap_or("").trim().to_string();
        let perms = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        if host.is_empty() {
            warn(&format!(
                "service '{name}': 'devices: {entry}' names no host device - ignored"
            ));
            continue;
        }
        // Docker defaults the in-box path to the host path when the entry has one field.
        let target = if target.is_empty() {
            host.clone()
        } else {
            target
        };
        if host == "/dev/net/tun" && target == "/dev/net/tun" {
            *tun = true;
            continue;
        }
        // Empty perms is Docker's `rwm`. `m` is only mentioned when it was asked for explicitly,
        // because every default entry carries it and a warning on every entry is a warning nobody
        // reads.
        if !perms.is_empty() && perms.contains('m') && perms != "rwm" {
            warn(&format!(
                "service '{name}': 'devices: {entry}' asks for mknod ('m') in the box - a rootless \
                 box has no CAP_MKNOD, so the node is bound in and cannot be re-created there"
            ));
        }
        let read_only = !perms.is_empty() && !perms.contains('w');
        if read_only {
            out.push(format!("{host}:{target}:ro"));
        } else {
            out.push(format!("{host}:{target}"));
        }
    }
    out
}

/// `volumes`: a short-form `src:dst[:ro]` entry passes through (kern's `-v` grammar matches compose's
/// short form); a LONG-form entry (`{type:, source:, target:, read_only:}`, which `build_tree` folds to
/// an inline `{…}` scalar) is reconstructed into `source:target[:ro]`. Passing the raw `{…}` to `-v`
/// was a bug - the box rejected it and the whole service failed to start.
fn volumes_value(node: &Node, tmpfs: &mut Vec<String>, service: &str) -> Vec<String> {
    list_value(node)
        .into_iter()
        .filter_map(|item| {
            if item.trim_start().starts_with('{') {
                reconstruct_volume_item(&item, tmpfs)
            } else {
                Some(anonymous_volume(&item, service))
            }
        })
        .collect()
}

/// A short-form entry that is JUST A PATH is Compose's ANONYMOUS VOLUME, and it needs a name here.
///
/// `volumes: ["/app/node_modules"]` asks for a fresh volume mounted at that path, and it is the most
/// common idiom in the Node ecosystem: it exists to stop a bind mount of the project directory from
/// hiding the `node_modules` the image built. MEASURED on a real repository
/// (`alitarhinisv/Notes-FE`): the entry reached `kern box` unchanged and was refused with
/// `bad -v '/app/node_modules' (expected src:dst[:ro])`, so a project that builds and runs under
/// Docker could not start at all.
///
/// THE NAME IS DERIVED, NOT RANDOM. Docker gives an anonymous volume a random id and Compose then
/// reuses it for the same service and path across `up`; a name built from those two facts reproduces
/// that reuse exactly, and does it without a registry of ids to keep. Everything outside
/// `[a-z0-9_-]` becomes `-`, because the result is a volume name and a path is full of separators.
///
/// An entry that already names a source is returned untouched: this is the ONLY shape that has no
/// source, so it is the only one to synthesise for.
fn anonymous_volume(item: &str, service: &str) -> String {
    let t = item.trim();
    // `src:dst`, `src:dst:ro`, or a Windows-style path: anything with a separator already has a
    // source. A leading `/` with no colon is the anonymous form.
    if t.contains(':') || !t.starts_with('/') {
        return t.to_string();
    }
    let sanitise = |s: &str| -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect::<String>()
            .trim_matches('-')
            .to_string()
    };
    let name = format!("anon-{}-{}", sanitise(service), sanitise(t));
    format!("{name}:{t}")
}

/// A compose long-form volume `{type: bind|volume, source: S, target: T, read_only: true}` → kern's
/// `S:T[:ro]`. An anonymous volume (no `source`) or an unsupported shape is dropped with a warning
/// rather than forwarded as a malformed `-v`. `type: tmpfs` has no `source`; we don't map it here
/// (kern has `--tmpfs`), so it's warned-and-skipped.
fn reconstruct_volume_item(item: &str, tmpfs: &mut Vec<String>) -> Option<String> {
    let inner = item.trim().trim_start_matches('{').trim_end_matches('}');
    let (mut source, mut target, mut read_only, mut vtype) =
        (String::new(), String::new(), false, String::new());
    // `tmpfs: {size: …, mode: …}` folds to `tmpfs.size` / `tmpfs.mode` here, because the whole long
    // form arrives as one inline scalar.
    let (mut tsize, mut tmode) = (String::new(), String::new());
    for field in split_top_commas(inner) {
        if let Some((k, v)) = field.split_once(':') {
            let (k, v) = (k.trim(), scalar_str(v));
            match k {
                "source" => source = v,
                "target" => target = v,
                "type" => vtype = v,
                "read_only" => read_only = v == "true",
                "tmpfs.size" | "size" => tsize = v,
                "tmpfs.mode" | "mode" => tmode = v,
                _ => {} // bind/volume sub-options (bind:, volume:, consistency:) - ignored
            }
        }
    }
    // A LONG-FORM `type: tmpfs` IS A `--tmpfs`, not a dropped entry.
    //
    // It has no `source` by definition, so the shared check below would have refused it and the
    // service would silently run without the scratch mount it asked for. It was previously
    // warned-and-skipped with a pointer to `--tmpfs`, which is the right flag and the wrong place
    // to make the reader go: kern now applies `size=` and `mode=`, so the whole of what this form
    // expresses can be delivered.
    if vtype == "tmpfs" && !target.is_empty() {
        let mut spec = target.clone();
        let mut opts: Vec<String> = Vec::new();
        if !tsize.is_empty() {
            opts.push(format!("size={tsize}"));
        }
        if !tmode.is_empty() {
            opts.push(format!("mode={tmode}"));
        }
        if read_only {
            opts.push("ro".to_string());
        }
        if !opts.is_empty() {
            spec.push(':');
            spec.push_str(&opts.join(","));
        }
        tmpfs.push(spec);
        return None;
    }
    if target.is_empty() || source.is_empty() {
        warn(&format!(
            "service volume long-form {{{inner}}} has no usable source+target ({}) - skipped",
            if vtype == "tmpfs" {
                "tmpfs: use kern --tmpfs"
            } else {
                "anonymous/unsupported"
            }
        ));
        return None;
    }
    Some(if read_only {
        format!("{source}:{target}:ro")
    } else {
        format!("{source}:{target}")
    })
}

/// `depends_on`: short list → start-order; long-form map with `condition:` → healthy/completed buckets.
fn apply_depends(b: &mut ComposeBox, node: &Node) {
    // Route one (dep, condition) into the right bucket.
    fn route(b: &mut ComposeBox, dep: &str, cond: &str) {
        match cond {
            "service_healthy" => b.depends_healthy.push(dep.to_string()),
            "service_completed_successfully" => b.depends_completed.push(dep.to_string()),
            "service_started" => b.depends_on.push(dep.to_string()),
            other => {
                warn(&format!(
                    "service '{}': depends_on '{dep}' condition '{other}' unknown → treated as start-order",
                    b.name
                ));
                b.depends_on.push(dep.to_string());
            }
        }
    }
    // Inline / block short list (`[a, b]` scalar or `- a` items) → start-order.
    if node.items.is_empty() && node.children.is_empty() {
        if node.scalar.is_some() {
            b.depends_on = list_value(node);
        }
        return;
    }
    if !node.items.is_empty() {
        b.depends_on = list_value(node);
        return;
    }
    // Long-form (block OR inline `{db: {condition: …}}` - both now parsed into `children` by
    // `parse_inline_table`): each child is a service with an optional `condition:` mapping.
    for (dep, spec) in &node.children {
        let cond = spec
            .child("condition")
            .and_then(|c| c.scalar.as_deref())
            .map(scalar_str)
            .unwrap_or_else(|| "service_started".to_string());
        route(b, dep, &cond);
    }
}

/// `healthcheck`: map `test` fedele (CMD exec → argv; CMD-SHELL / bare-string → `sh -c`), else OMIT +
/// warn (a half-converted health lies and breaks a downstream `depends_healthy`; `compose()` degrades
/// that gate with a linked warning). `interval`/`timeout`/`retries`/`start_period` map 1:1.
fn apply_healthcheck(b: &mut ComposeBox, node: &Node, svc: &str) {
    // `disable: true` → no health.
    if node
        .child("disable")
        .and_then(|d| d.scalar.as_deref())
        .map(scalar_str)
        .as_deref()
        == Some("true")
    {
        return;
    }
    let Some(test) = node.child("test") else {
        warn(&format!(
            "service '{svc}': healthcheck has no `test` - omitted"
        ));
        return;
    };
    match healthcheck_test(test) {
        // The FORM travels with the command: `CMD` is an argv kern execs, `CMD-SHELL` (and a bare
        // string) a line kern hands to `/bin/sh -c`. Flattening the first into the second is what
        // made every image without a shell permanently unhealthy - see `ComposeBox::health_argv`.
        Some(TestForm::Exec(argv)) => b.health_argv = argv,
        Some(TestForm::Shell(c)) => b.health_cmd = Some(c),
        None => {
            // Omit the health entirely rather than half-convert it (a partial health lies). Any
            // `depends_healthy` edge toward this box is degraded to start-order later in
            // `degrade_orphan_health_gates`, which emits the linked, direction-correct warning.
            warn(&format!(
                "service '{svc}': healthcheck `test` not convertible - omitted"
            ));
            return;
        }
    }
    if let Some(v) = node.child("interval").and_then(|n| n.scalar.as_deref()) {
        b.health_interval = parse_duration_secs(&scalar_str(v));
    }
    if let Some(v) = node.child("retries").and_then(|n| n.scalar.as_deref()) {
        // `retries` is a plain count (`--health-retries <n>`), no duration suffix.
        b.health_retries = Some(scalar_str(v));
    }
    // `timeout`/`start_period` map to `--health-{timeout,start-period} <seconds>` - an INTEGER count of
    // seconds. Docker writes them as durations (`30s`, `1m30s`, `0s`), so we must convert, not pass the
    // raw string: `--health-timeout 30s` fails the CLI's `u64` parse. Route them through the same
    // `parse_duration_secs` as `interval`; an unparseable/overflowing value is dropped (box default)
    // rather than forwarded to fail the child. (Found by an extreme test: `start_period: 0s` / any
    // `timeout: 30s`, the standard Docker form, aborted the box.)
    if let Some(v) = node.child("timeout").and_then(|n| n.scalar.as_deref()) {
        b.health_timeout = parse_duration_secs(&scalar_str(v)).map(|s| s.to_string());
    }
    if let Some(v) = node.child("start_period").and_then(|n| n.scalar.as_deref()) {
        // `start_period` reaches `--health-start-period <seconds>`, where 0 is MEANINGFUL ("no startup
        // grace") - so allow_zero=true, handling every zero spelling (`0s`, `0m`, `0h0m0s`) uniformly.
        b.health_start_period =
            parse_duration_secs_opt(&scalar_str(v), true).map(|s| s.to_string());
    }
}

/// A healthcheck `test`, with the form Docker wrote it in. The two are not interchangeable: the exec
/// form runs with NO shell, which is the only thing that works in an image that ships none.
#[derive(Debug, PartialEq, Eq)]
enum TestForm {
    /// `CMD-SHELL "…"`, or a bare string: run through `/bin/sh -c`.
    Shell(String),
    /// `CMD ["prog", "arg"]`: exec'd directly, argument boundaries intact.
    Exec(Vec<String>),
}

/// Convert a healthcheck `test` to a health command, or `None` if not faithfully convertible.
///  * `["CMD", "curl", "-f", "u"]`      → exec-form → the argv, KEPT as an argv (no shell, no join)
///  * `["CMD-SHELL", "curl -f u"]`      → shell-form → the shell string
///  * bare string `"curl -f u"`         → IMPLICIT CMD-SHELL (Docker) → the string (NEVER split-on-space)
///  * `["NONE"]`                        → no health → `None` (caller omits)
fn healthcheck_test(node: &Node) -> Option<TestForm> {
    // Inline / block list form.
    let list = if let Some(sc) = &node.scalar {
        let sc = sc.trim();
        if sc.starts_with('[') {
            Some(parse_inline_list(sc))
        } else if !sc.is_empty() {
            // Bare string = implicit CMD-SHELL. Return verbatim (the box wraps it in `sh -c`).
            return Some(TestForm::Shell(scalar_str(sc)));
        } else {
            None
        }
    } else if !node.items.is_empty() {
        Some(node.items.iter().map(|i| scalar_str(i)).collect())
    } else {
        None
    };
    let list = list?;
    let (head, rest) = list.split_first()?;
    match head.as_str() {
        "NONE" => None,
        "CMD-SHELL" => rest.first().cloned().map(TestForm::Shell),
        "CMD" => {
            if rest.is_empty() {
                None
            } else {
                // exec-form: the argv IS the check. It used to be joined with spaces and run through
                // `/bin/sh -c`, which fails outright in an image with no shell - and an image with
                // no shell is exactly the one that writes this form.
                Some(TestForm::Exec(rest.to_vec()))
            }
        }
        // A list whose first item isn't a known directive → treat the whole thing as a shell string
        // only if it's a single element; otherwise not faithfully convertible.
        _ if list.len() == 1 => Some(TestForm::Shell(list[0].clone())),
        _ => None,
    }
}

/// A compose duration (`30s`, `1m30s`, or a bare number of seconds) → whole seconds. Best-effort; a
/// form we don't understand - OR one that overflows - yields `None` (the box uses its default
/// interval).
///
/// The value is UNTRUSTED (a third-party `interval:`), so every step uses CHECKED arithmetic: a huge
/// digit-run like `6000000000000000h` must fall back to `None`, never panic (debug) or wrap to a
/// nonsense value (release). This is the parser's "never a panic, never a lie" contract on the one
/// compose field routed through here. (Found by the extreme audit; the older randomized fuzz never
/// emitted a long digit-run after `interval:`.)
fn parse_duration_secs(s: &str) -> Option<i64> {
    // Default policy: 0 means "unset -> box default" (used by `interval`/`timeout`, where a zero value
    // is meaningless).
    parse_duration_secs_opt(s, false)
}

/// The one duration parser. `allow_zero` selects the zero-policy AT THE COMPUTED TOTAL - so EVERY zero
/// spelling (`0`, `0s`, `0m`, `0h`, `0m0s`, `00s`) is treated identically, instead of a whitelist of
/// literal strings. `false` -> 0 collapses to `None` (unset -> default), for `interval`/`timeout`.
/// `true` -> 0 is a real value, for `start_period: 0s` ("no startup grace"). Closing the policy by
/// construction here (not by a maintained list of zero spellings) mirrors the anchor-guard rewrite.
fn parse_duration_secs_opt(s: &str, allow_zero: bool) -> Option<i64> {
    let s = s.trim();
    let total = if let Ok(n) = s.parse::<i64>() {
        n
    } else {
        let mut total: i64 = 0;
        let mut num = String::new();
        for c in s.chars() {
            if c.is_ascii_digit() {
                num.push(c);
            } else {
                let n: i64 = num.parse().ok()?; // >19 digits -> parse Err -> None (no panic)
                num.clear();
                let secs = match c {
                    's' => n,
                    'm' => n.checked_mul(60)?,
                    'h' => n.checked_mul(3600)?,
                    _ => return None,
                };
                total = total.checked_add(secs)?;
            }
        }
        if !num.is_empty() {
            total = total.checked_add(num.parse::<i64>().ok()?)?;
        }
        total
    };
    if allow_zero || total > 0 {
        Some(total)
    } else {
        None
    }
}

/// `restart`: `no`→off; `on-failure`→on (retry on non-zero exit); `always`/`unless-stopped`→restart on
/// ANY exit (kern supervises a pod member in-process for the stack's lifetime, not degraded to on-failure).
fn apply_restart(b: &mut ComposeBox, node: &Node, svc: &str) {
    let v = node.scalar.as_deref().map(scalar_str).unwrap_or_default();
    match v.as_str() {
        "" | "no" => b.restart = false,
        "on-failure" => b.restart = true,
        // `on-failure:N` caps the retries. kern already stops after a fixed number; honouring the
        // number the file asks for is the difference between "gives up eventually" and "gives up when
        // you said", which is what the syntax exists for.
        other if other.starts_with("on-failure:") => {
            b.restart = true;
            // `strip_prefix`, never `trim_start_matches`: the trim family removes the prefix AS
            // MANY TIMES AS IT FINDS IT, so `on-failure:on-failure:3` parsed as a clean retry count
            // of 3 - a malformed value accepted as a valid one. Stripping ONCE leaves
            // `on-failure:3`, which fails to parse and falls onto the warning right below, which is
            // where a value we cannot read belongs.
            b.restart_max = other
                .strip_prefix("on-failure:")
                .unwrap_or(other)
                .trim()
                .parse::<u32>()
                .ok()
                .map(|n| n.to_string());
            if b.restart_max.is_none() {
                warn(&format!(
                    "service '{svc}': restart '{other}' has no valid retry count - using the default cap"
                ));
            }
        }
        "always" | "unless-stopped" => {
            b.restart = true;
            b.restart_always = true;
        }
        other => {
            warn(&format!(
                "service '{svc}': unknown restart '{other}' - treated as on-failure"
            ));
            b.restart = true;
        }
    }
}

/// `build`: resolve to a [`BuildDirective`]. `context`/`dockerfile` are kept RELATIVE (the caller in
/// `compose()` confines them under the compose file's dir - traversal guard). `args` values are
/// already `${VAR}`-substituted document-wide.
fn build_value(node: &Node, dotenv: &crate::DotEnv) -> BuildDirective {
    // Short form: `build: ./dir`
    if let Some(sc) = &node.scalar {
        let sc = scalar_str(sc);
        if !sc.is_empty() {
            return BuildDirective {
                context: sc,
                dockerfile: None,
                args: Vec::new(),
                target: None,
            };
        }
    }
    // Long form: `build: {context:, dockerfile:, args:}`
    let context = node
        .child("context")
        .and_then(|n| n.scalar.as_deref())
        .map(scalar_str)
        .unwrap_or_else(|| ".".to_string());
    let dockerfile = node
        .child("dockerfile")
        .and_then(|n| n.scalar.as_deref())
        .map(scalar_str);
    // `args` is the same `- K=v` list / `K: v` map shape as `environment`.
    let args = node
        .child("args")
        .map(|n| kv_pairs_from(n, Some(dotenv)))
        .unwrap_or_default();
    let target = node
        .child("target")
        .and_then(|n| n.scalar.as_deref())
        .map(scalar_str)
        .filter(|t| !t.trim().is_empty());
    BuildDirective {
        context,
        dockerfile,
        args,
        target,
    }
}

/// What resolving every `network_mode: service:X` in a file comes to.
///
/// A RETURNED VALUE AND NOT A PAIR OF SIDE EFFECTS, because both halves are decisions a test has to
/// be able to interrogate. `warn` writes to stderr and returns nothing, so a resolution that warned
/// inline could be asserted by nothing at all: a cycle could stop being reported, or an inheritance
/// could start copying the wrong service's networks, and every test in this file would stay green.
#[derive(Debug, Default, PartialEq, Eq)]
struct SharedNamespaces {
    /// `(index into the boxes, the membership that box inherits)`, applied by the caller.
    inherit: Vec<(usize, Vec<String>)>,
    /// The sentences the file is owed, in the order the services appear in it.
    notes: Vec<String>,
}

/// Resolve `network_mode: service:X` into network membership, following the chain.
///
/// PURE, so the resolution can be asserted directly. The caller applies `inherit` and prints
/// `notes`; nothing here touches the boxes or stderr.
fn resolve_net_share(boxes: &[ComposeBox]) -> SharedNamespaces {
    let mut out = SharedNamespaces::default();
    for (i, b) in boxes.iter().enumerate() {
        let Some(first) = b.net_share.as_deref() else {
            continue;
        };
        let mut hops = 0usize;
        let mut cur = first.to_string();
        // The walk ends at the first service that does not itself name another, which is the
        // namespace everything in the chain lives in. Bounded by the service count so a file that
        // points a service at itself, or two at each other, is reported instead of spinning.
        let terminal = loop {
            match boxes.iter().position(|o| o.service == cur || o.name == cur) {
                None => {
                    out.notes.push(format!(
                        "service '{}': 'network_mode: service:{cur}' names no service in this file \
                         - ignored, and '{}' keeps its own network membership",
                        b.service_name(),
                        b.service_name()
                    ));
                    break None;
                }
                Some(j) => match boxes[j].net_share.as_deref() {
                    None => break Some(j),
                    Some(next) => {
                        hops += 1;
                        if hops > boxes.len() {
                            out.notes.push(format!(
                                "service '{}': 'network_mode: service:{first}' leads in a cycle - \
                                 ignored, and '{}' keeps its own network membership",
                                b.service_name(),
                                b.service_name()
                            ));
                            break None;
                        }
                        cur = next.to_string();
                    }
                },
            }
        };
        let Some(j) = terminal else { continue };
        let host = &boxes[j];
        // `network_mode:` AND `networks:` ARE MUTUALLY EXCLUSIVE in the specification, and Docker
        // refuses a service that writes both. kern reports instead of refusing, because refusing a
        // file the world already runs is the difference this work exists to remove, and it says
        // which of the two it kept: the one that describes where the service actually lives.
        if !b.networks.is_empty() && b.networks != host.networks {
            out.notes.push(format!(
                "service '{}': 'network_mode: service:{}' and 'networks:' are mutually exclusive \
                 (Docker refuses a service that writes both); kern keeps the namespace it names, so \
                 '{}' is on {}'s networks and not on the one it declares",
                b.service_name(),
                host.service_name(),
                b.service_name(),
                host.service_name()
            ));
        }
        // `host` AND `none` ARE NOT CARRIED ACROSS THE SHARE, they are named. Under Docker a
        // container in the namespace of one on the host network is itself on the host network, and
        // giving a box that posture because a downloaded file chained two keys is a widening kern
        // should not perform quietly. No corpus file chains them, so naming costs nothing here and
        // applying could surprise.
        if host.net || host.net_none {
            out.notes.push(format!(
                "service '{}': 'network_mode: service:{}' names a service that is itself on \
                 'network_mode: {}', and kern does not carry that across the share: '{}' stays an \
                 ordinary member of the stack's network",
                b.service_name(),
                host.service_name(),
                if host.net { "host" } else { "none" },
                b.service_name()
            ));
        }
        out.inherit.push((i, host.networks.clone()));
    }
    out
}

/// Emit a compat warning to stderr. Prefixed so it's clearly kern's compose-import voice, and so the
/// user sees exactly which part of their compose didn't map 1:1.
fn warn(msg: &str) {
    eprintln!("kern: warning: compose: {}", sanitize_for_terminal(msg));
}

/// The note for `stdin_open: true`, which is the only half of Docker's `-it` pair that changes
/// anything here.
///
/// A function rather than a fixed sentence, for the same reason as
/// [`container_only_port_note`]: it names the SERVICE, and the remedy it offers is a command the
/// reader can paste. MEASURED on a detached box, which is what every compose service is: stdin is
/// non-tty and at EOF, stdout is non-tty.
///
/// `tty:` gets no note at all. It changes nothing kern can act on for a detached service, a
/// terminal is available on demand through `kern exec -it`, and it sits in thousands of compose
/// files out of habit on daemons that never read one. Both keys used to produce
/// "ignored (unsupported)" off the KEY rather than the value, so `tty: false` warned about nothing
/// and a working daemon was told a feature was missing.
///
/// TWO SENTENCES, TWO REMEDIES, and the first version had one of each pointing at different
/// things. It told the reader what kern does about stdin and then offered `exec -it`, which
/// answers `tty:`. Somebody who wrote `stdin_open: true` ALONE was handed a PTY they never asked
/// for and nothing at all about the thing they did write. The remedy for a program that needs
/// input is to give it that input another way; the `exec -it` pointer stays because a reader who
/// typed `-it` is heading there, but as its own sentence.
///
/// NOT IMPLEMENTED, and that is a decision rather than a gap. Holding stdin open for a detached
/// box means leaking a pipe write end into the box, since kern exits and cannot hold it. That
/// turns "the program exits at once, in front of the person who just typed `compose up`, with the
/// reason one line away" into "the program blocks forever on a read that never returns, `kern ps`
/// says up, and nothing ever fires". A loud immediate failure traded for a silent permanent one.
/// It would also change shutdown: a program that exits cleanly on EOF would then have to be
/// killed, so `compose down` becomes SIGTERM-and-wait for that service.
fn stdin_open_note(service: &str) -> String {
    format!(
        "service '{service}': 'stdin_open: true' - a compose service runs detached, so its stdin is \
         at EOF rather than held open. A program that blocks on stdin will exit immediately; give \
         it its input as a file, an argument, or an environment variable instead. For an \
         interactive shell in the running service, `kern exec -it {service}`"
    )
}

/// `warn`, but the same text is printed once per run.
///
/// For facts that belong to the FILE rather than to a service: `networks:` is dropped for the whole
/// stack, so a seven-service file was getting eight lines saying it. Repeating one fact per service
/// trains the reader to skim past warnings, which is how the one that mattered gets missed.
/// The note for a compose entry that names a container port with no host port.
///
/// A function rather than a fixed sentence because the number in the message has to be the number in
/// the FILE. It used to read `a container-only port (\`8000\` / \`:8000\`) ...` whatever the file
/// said, so a stack declaring only `9090` was told about a port that appears nowhere in it. A field
/// test on the `dev` branch had to isolate the case and prove kern was not carrying stale state from
/// another file before it could dismiss it: that is the cost of an example that reads like an
/// observation.
fn container_only_port_note(port: u16) -> String {
    format!(
        "a container-only port (`{port}` / `:{port}`) is DECLARED, not published: kern assigns no \
         random host port. Write `HOST:{port}` to publish one"
    )
}

/// What to say about an `x-kern-…` key this build does not read.
///
/// TWO PROBLEMS, TWO SENTENCES. `x-kern-vgpi` is a typo: the fix is to correct the key, so the note
/// lists what kern does read. `x-kern-vgpu` is not a typo at all - it names a real profile kind that
/// this build has no `classify` token for - so telling its author about the spelling of `vdisk` sends
/// them looking for a mistake they did not make. Both are ignored either way; the difference is
/// entirely in what the reader is told to do next, which is the whole value of not being silent.
fn unread_kern_key_note(service: &str, key: &str, kind: &str) -> String {
    if ABSENT_PROFILE_KINDS.contains(&kind) {
        return format!(
            "service '{service}': '{key}:' names the '{kind}' profile kind, which this build of kern \
             does not have - the key is ignored, and the service runs without it"
        );
    }
    format!(
        "service '{service}': '{key}:' is not read by this build - kern reads {}, and \
         x-kern-security-profile",
        PROFILE_KINDS
            .iter()
            .map(|k| format!("x-kern-{k}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Record a `x-kern-<kind>` profile reference, ignoring an empty or non-scalar value.
///
/// A list or a mapping under one of these keys is not a profile name, and a blank string names
/// nothing: both are dropped rather than turned into a token that would then fail to resolve
/// against `kern.toml` with a confusing message about a profile nobody wrote.
fn push_profile(into: &mut Vec<String>, node: &Node) {
    if let Some(v) = node.scalar.as_deref().map(scalar_str) {
        if !v.trim().is_empty() {
            into.push(v);
        }
    }
}

thread_local! {
    /// Variables a document required with `${VAR:?err}` and did not get. Filled during
    /// interpolation, drained by `parse_with_env` into one refusal naming all of them.
    ///
    /// Thread-local for `warn_once`'s reason: kern is one process per invocation, and a test that
    /// parses several documents on its own thread must not see another test's leftovers.
    static REQUIRED_UNSET: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Take (and clear) the variables the document required and did not get.
fn take_required_unset() -> Vec<String> {
    REQUIRED_UNSET.with(|r| std::mem::take(&mut *r.borrow_mut()))
}

fn warn_once(msg: &str) {
    use std::cell::RefCell;
    use std::collections::HashSet;
    thread_local! {
        static SEEN: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
    }
    // Thread-local rather than global: kern is one process per invocation, and a test that parses
    // several documents on its own thread still sees each first occurrence.
    let fresh = SEEN.with(|s| s.borrow_mut().insert(msg.to_string()));
    if fresh {
        warn(msg);
    }
}

/// Neutralize control characters in a string bound for the user's terminal. `warn` interpolates
/// UNTRUSTED compose text (service names, keys, values, paths from a third-party file); without this a
/// hostile compose could inject ANSI escapes / cursor moves / carriage returns into a warning to spoof
/// or hide terminal output. Printable chars + space/tab pass; every other control char (incl. ESC
/// `\x1b`, CR, and other C0/C1) becomes its literal `\xNN` form. Centralized so EVERY `warn` is covered
/// by construction, not by escaping at each call site.
fn sanitize_for_terminal(msg: &str) -> String {
    msg.chars()
        .flat_map(|c| {
            if c == ' ' || c == '\t' || !c.is_control() {
                vec![c]
            } else {
                format!("\\x{:02x}", c as u32).chars().collect()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DIFFERENCE NOBODY IS TOLD ABOUT IS THE WORST DEFECT THIS PARSER CAN HAVE, AND IT HAD ONE.
    ///
    /// A service pinned to a fixed address inside a declared subnet used to produce NO output at
    /// all: MEASURED, the stack came up, the service's name and alias resolved, and a peer
    /// connecting to the literal `172.28.1.10` got nothing. Under Docker that address answers.
    ///
    /// WORSE, IT WAS INVISIBLE TO THE MEASUREMENT USED TO CLAIM COMPATIBILITY. That measurement
    /// counts a file as clean when kern says nothing about it, so a gap kern did not know it had
    /// could not appear in it: 7 of 259 corpus files carried this key, all 7 were counted as
    /// perfect, and closing the silence moved the measured rate from 95% to 93%. The number went
    /// DOWN because it had been wrong, which is the only direction an honest correction can go.
    ///
    /// `aliases` is deliberately NOT in the list: it IS honoured, and naming it would report a loss
    /// that does not happen.
    #[test]
    fn a_fixed_address_under_networks_is_named_and_an_alias_is_not() {
        let out = std::panic::catch_unwind(|| {
            let src = "services:\n  a:\n    image: alpine\n    networks:\n      front:\n        ipv4_address: 172.28.1.10\n        aliases: [alfa]\n";
            parse(src).expect("parses").remove(0)
        })
        .expect("no panic");
        // The alias is applied, so the service really is reachable by that name.
        assert_eq!(out.net_aliases, vec!["alfa".to_string()]);
        // And the network membership is recorded, which is what segregation reads.
        assert_eq!(out.networks, vec!["front".to_string()]);

        // WHAT THE NOTE NAMES IS A PURE FUNCTION OF THE NODE, so it is asserted directly instead of
        // through stderr - the same reason `internal_note` and `networks_note` are functions.
        let keys_for = |yaml: &str| -> Vec<&'static str> {
            let src =
                format!("services:\n  a:\n    image: alpine\n    networks:\n      front:\n{yaml}");
            let doc = fold_multiline(&src).expect("folds");
            let lines = lex(&doc).expect("lexes");
            let tree = build_tree(&lines).expect("tree");
            let svc = tree
                .child("services")
                .and_then(|s| s.child("a"))
                .and_then(|a| a.child("networks"))
                .expect("the networks node");
            unhonoured_net_keys(svc)
        };
        // `ipv4_address` LEFT THIS TABLE, ON PURPOSE. It is no longer unhonoured: the address is
        // claimed as a /32 on the box's loopback, so the literal address exists and, in one shared
        // namespace, a peer that hard-codes it reaches the service (measured: `web` read back what
        // `db` was serving at `172.28.1.10:6000`, three runs out of three). What it is worth depends
        // on the wiring, so the sentence moved to `net_ipv4_note` where the wiring is known.
        assert!(
            keys_for("        ipv4_address: 1.2.3.4\n").is_empty(),
            "an applied key must not be reported as unhonoured"
        );
        assert_eq!(
            keys_for("        ipv6_address: ::1\n"),
            vec!["ipv6_address"]
        );
        assert_eq!(keys_for("        priority: 10\n"), vec!["priority"]);
        assert_eq!(
            keys_for("        link_local_ips: [169.254.1.1]\n"),
            vec!["link_local_ips"]
        );
        // Several at once are reported together, in the table's order, so one line covers a service.
        assert_eq!(
            keys_for("        priority: 10\n        ipv4_address: 1.2.3.4\n"),
            vec!["priority"],
            "the applied key drops out and the unhonoured one still reports"
        );
        // THE SHAPES KERN DOES HONOUR MUST STAY SILENT, or the note becomes noise on every file that
        // uses an alias - which is most of them - and a noisy note is one nobody reads.
        assert!(keys_for("        aliases: [x]\n").is_empty());
        assert!(keys_for("").is_empty());
    }

    /// `network_mode:` IS APPLIED PER SERVICE, WHICH IT COULD NOT BE WHILE A STACK WAS ONE NAMESPACE.
    ///
    /// `host` means the service leaves the stack's network and takes the machine's, which is exactly
    /// what kern's `net` field already does: the box does not join the pod, gets no relay and no
    /// hosts entry, and its peers stop resolving it by name - the same consequences Docker's
    /// `network_mode: host` has. `none` is the opposite request and kern answers it by ALSO staying
    /// out of the pod and attaching no NAT, so the namespace holds loopback and nothing else.
    ///
    /// MEASURED end to end on one stack: the `host` service reported the machine's interfaces, the
    /// `none` service reported `lo` alone and its outbound connect was refused, and an ordinary
    /// service in the same file still reached the internet. Three services, one file, one run.
    ///
    /// `service:X` IS A FIELD TOO NOW, and it was the last one still answered with a sentence. It
    /// names a namespace, which is a fact about this file that survives the parse; what kern can do
    /// about it depends on a wiring the parser cannot see. `container:`/`bridge`/`default` stay
    /// notes: the first names something outside the file, the other two describe what kern provides.
    #[test]
    fn network_mode_host_and_none_become_fields_and_the_rest_stay_notes() {
        let svc = |mode: &str| {
            let src = format!("services:\n  a:\n    image: alpine\n    network_mode: {mode}\n");
            parse(&src).expect("parses").remove(0)
        };

        let host = svc("host");
        assert!(host.net, "`host` must set the field that leaves the pod");
        assert!(!host.net_none);

        let none = svc("none");
        assert!(none.net_none, "`none` must set its own field");
        assert!(
            !none.net,
            "and must NOT be confused with sharing the host's"
        );

        let shared = svc("service:db");
        assert_eq!(
            shared.net_share.as_deref(),
            Some("db"),
            "`service:X` must record the service it names, not answer with a sentence"
        );
        assert!(
            !shared.net && !shared.net_none,
            "and must not be confused with either of the postures that leave the stack"
        );

        // A value with nothing after the colon names no service: recording an empty target would
        // silently match nothing later, so it is reported and no field is set.
        let empty = svc("service:");
        assert_eq!(empty.net_share, None);

        // The wirings kern already provides, and the one that names a container outside this file.
        for inert in ["bridge", "default", "container:x"] {
            let b = svc(inert);
            assert!(
                !b.net && !b.net_none && b.net_share.is_none(),
                "'{inert}' must set no field"
            );
        }
    }

    /// `network_mode: service:X` MUST PUT THE SERVICE WHERE X LIVES, and before this it put it in
    /// the one place X provably was not.
    ///
    /// A service with `network_mode:` has no `networks:` key, so it landed on the implicit `default`
    /// network while the service it named sat on a declared one. kern then read the pair as
    /// SEGREGATED and gave it no relay, no hosts entry and no name resolution - for the one key in
    /// the whole file that asks two services to be a single host.
    ///
    /// MEASURED end to end, both directions, on the file this test encodes: with the fix, `sidecar`
    /// reached `db` by name and read back the string `db` was serving; the control in the same run,
    /// a service on another network, could not resolve the name at all (`nc: bad address 'db'`).
    /// Before the fix `sidecar` was in the control's position.
    #[test]
    fn network_mode_service_inherits_the_membership_of_the_service_it_names() {
        let src = "services:\n  \
                   web:\n    image: alpine\n    networks: [front]\n  \
                   db:\n    image: alpine\n    networks: [back]\n  \
                   sidecar:\n    image: alpine\n    network_mode: service:db\n";
        let boxes = parse(src).expect("parses");
        let by = |n: &str| {
            boxes
                .iter()
                .find(|b| b.service_name() == n)
                .unwrap_or_else(|| panic!("service '{n}' parsed"))
        };
        assert_eq!(
            by("sidecar").networks,
            vec!["back".to_string()],
            "the sharer must be on the networks of the service it names"
        );
        assert_eq!(
            by("sidecar").net_share.as_deref(),
            Some("db"),
            "and must keep the record of why, so the driver can say what the wiring gives"
        );
        // THE CONTROL, and it is what makes the assertion above mean anything: the inheritance is
        // targeted, not a blanket "put everyone together". `web` named no share and must be left
        // exactly where the file put it.
        assert_eq!(by("web").networks, vec!["front".to_string()]);
        assert_eq!(by("db").networks, vec!["back".to_string()]);
        // And the pair the file asked to be one host must now share a network, which is the whole
        // difference between a relay and silence.
        assert_eq!(by("sidecar").networks, by("db").networks);
    }

    /// A CHAIN TERMINATES IN ONE NAMESPACE, so the walk follows it instead of copying a copy.
    ///
    /// `a` inside `b` inside `c` is one namespace, `c`'s. Stopping at `b` would hand `a` whatever
    /// `b`'s membership happened to be at that moment, which is itself inherited: the resolution
    /// would depend on the order the services are written in. `volumes_from` stops at one level and
    /// says so, because a mount list can be truncated and still be a mount list; a namespace cannot.
    #[test]
    fn a_network_mode_chain_resolves_to_the_terminal_namespace() {
        let src = "services:\n  \
                   c:\n    image: alpine\n    networks: [deep]\n  \
                   b:\n    image: alpine\n    network_mode: service:c\n  \
                   a:\n    image: alpine\n    network_mode: service:b\n";
        let boxes = parse(src).expect("parses");
        for name in ["a", "b", "c"] {
            let b = boxes
                .iter()
                .find(|x| x.service_name() == name)
                .expect("service parsed");
            assert_eq!(
                b.networks,
                vec!["deep".to_string()],
                "'{name}' must end up on the terminal namespace's networks"
            );
        }
    }

    /// A CYCLE IS REPORTED AND CHANGES NOTHING, and the bound is what stops the walk.
    ///
    /// Two services naming each other have no terminal namespace to inherit, and a walk that
    /// followed the chain without a bound would not return. The count of services is the bound
    /// because a chain longer than that must repeat a service.
    #[test]
    fn a_network_mode_cycle_is_reported_and_changes_nothing() {
        let src = "services:\n  \
                   a:\n    image: alpine\n    network_mode: service:b\n  \
                   b:\n    image: alpine\n    network_mode: service:a\n";
        let boxes = parse(src).expect("parses");
        let shared = resolve_net_share(&boxes);
        assert!(
            shared.inherit.is_empty(),
            "a cycle must give nobody a membership: {:?}",
            shared.inherit
        );
        assert_eq!(shared.notes.len(), 2, "both services are owed a sentence");
        for n in &shared.notes {
            assert!(n.contains("cycle"), "the sentence must name the shape: {n}");
        }
        // A service naming ITSELF is the same defect with one service, and the same bound catches it.
        let self_ref = parse("services:\n  a:\n    image: alpine\n    network_mode: service:a\n")
            .expect("parses");
        let shared = resolve_net_share(&self_ref);
        assert!(shared.inherit.is_empty());
        assert_eq!(shared.notes.len(), 1);
    }

    /// A TARGET THAT IS NOT A SERVICE IS REPORTED, not silently treated as the implicit network.
    ///
    /// Zero of the 240 corpus files do this, which is exactly why it needs a test: the arm has no
    /// real file keeping it honest.
    #[test]
    fn a_network_mode_target_that_is_not_a_service_is_reported() {
        let src = "services:\n  \
                   a:\n    image: alpine\n    networks: [mine]\n    network_mode: service:ghost\n";
        let boxes = parse(src).expect("parses");
        let shared = resolve_net_share(&boxes);
        assert!(shared.inherit.is_empty(), "nothing to inherit from nothing");
        assert_eq!(shared.notes.len(), 1);
        assert!(
            shared.notes[0].contains("names no service in this file"),
            "{}",
            shared.notes[0]
        );
        // And the membership the file DID declare is left alone, so the service keeps working.
        assert_eq!(boxes[0].networks, vec!["mine".to_string()]);
    }

    /// THE REFUSAL MUST NOT NAME A FEATURE THIS PARSER SUPPORTS.
    ///
    /// Reported by an outside reviewer against the released binary: a malformed file of theirs was
    /// refused with "YAML anchors/aliases not supported (rewrite the value inline)", and anchors,
    /// aliases and merge keys all work - `DOCKER-COMPAT.md` lists them as supported and they verify
    /// four ways. The message sent the reader to rewrite the one construct that was never the
    /// problem. Only the FLOW form is unexpanded, and that is what the message says now.
    ///
    /// I could not reproduce the exact input in five attempts, so this test pins what IS
    /// verifiable: which forms parse, which one refuses, and that the refusal describes itself.
    #[test]
    fn the_anchor_refusal_names_the_flow_form_and_not_anchors_in_general() {
        // Block-level: a merge key, a sequence alias and a scalar alias all resolve.
        let ok = parse(
            "x-base: &base\n  image: alpine\nx-env: &envs\n  - FOO=1\nservices:\n  \
             a:\n    <<: *base\n    environment: *envs\n  b:\n    <<: *base\n",
        )
        .expect("block anchors, aliases and merge keys parse");
        assert_eq!(ok.len(), 2);
        assert_eq!(ok[0].image.as_deref(), Some("alpine"));
        assert_eq!(ok[1].image.as_deref(), Some("alpine"));

        // The flow form is the one that is refused, and the message says so instead of blaming
        // anchors as a whole.
        let err = parse("x: &a alpine\nservices:\n  s:\n    image: alpine\n    command: [*a]\n")
            .expect_err("an alias inside a flow collection is refused");
        assert!(err.contains("flow collection"), "{err}");
        assert!(
            !err.contains("anchors/aliases not supported"),
            "the message must not deny a feature this parser has: {err}"
        );
        // And it points a reader whose file is malformed for another reason at the real suspect.
        assert!(err.contains("unclosed"), "{err}");
    }

    /// `security_opt` IS ANSWERED BY VALUE, AND ANSWERING IT BY KEY SAID FALSE THINGS.
    ///
    /// MEASURED inside a box: `/proc/self/attr/current` reads the caller's own AppArmor context,
    /// because kern applies no profile of its own, and SELinux is not even mounted on the host this
    /// was written on. So `apparmor=unconfined` and `label=disable` ask for exactly what kern does,
    /// and the parser answered both with "not honoured", on 11 corpus files.
    ///
    /// A NAMED PROFILE IS FORWARDED, which it never was: `kern box --apparmor` has existed all
    /// along. `seccomp=unconfined` stays a difference on purpose - the file asks for NO filter, and
    /// a filter a downloaded file can switch off is not a filter.
    #[test]
    fn security_opt_is_answered_by_value_and_a_named_apparmor_profile_travels() {
        let one = |v: &str| {
            parse(&format!(
                "services:\n  a:\n    image: alpine\n    security_opt:\n      - {v}\n"
            ))
            .expect("parses")
            .remove(0)
        };
        // A named profile becomes a field, so `push_box_flags` can send `--apparmor`.
        assert_eq!(
            one("apparmor=docker-default").apparmor.as_deref(),
            Some("docker-default")
        );
        assert_eq!(
            one("apparmor:my-profile").apparmor.as_deref(),
            Some("my-profile")
        );
        // `unconfined` is NOT a profile name: asking the LSM to transition to a profile called
        // "unconfined" is a different request from applying none, which is what kern does.
        assert_eq!(one("apparmor=unconfined").apparmor, None);
        assert_eq!(one("apparmor:unconfined").apparmor, None);
        // Real files carry punctuation on the value; the word is what decides.
        assert_eq!(one("apparmor:unconfined;").apparmor, None);
        // Nothing else sets it.
        assert_eq!(one("label=disable").apparmor, None);
        assert_eq!(one("seccomp=unconfined").apparmor, None);
        assert_eq!(one("no-new-privileges=true").apparmor, None);
    }

    /// `privileged: true` IS A FIELD, AND THE PARSER DOES NOT DECIDE IT.
    ///
    /// Whether kern gives it depends on something the parser cannot see: whether the OPERATOR
    /// granted it. The sentence this replaces claimed there was "no kern equivalent (rootless)",
    /// which is wrong twice - `kern box --privileged --cap-add ALL` is the equivalent a rootless
    /// runtime can give, and it is not the file's to take.
    #[test]
    fn privileged_is_recorded_for_the_operator_to_decide() {
        let b = |v: &str| {
            parse(&format!(
                "services:\n  a:\n    image: alpine\n    privileged: {v}\n"
            ))
            .expect("parses")
            .remove(0)
        };
        assert!(b("true").privileged);
        assert!(!b("false").privileged);
        // Absent means absent, which is the control that makes the two above mean something.
        let none = parse("services:\n  a:\n    image: alpine\n")
            .expect("parses")
            .remove(0);
        assert!(!none.privileged);

        // THE FLAGS IT BECOMES, and both are needed: Docker's one key is two things here, every
        // capability the box's own user namespace can hold and the relaxed seccomp a nested runtime
        // needs. MEASURED end to end: `CapEff` goes from 00000110bd84efff to 000001ffffffffff, and
        // `Seccomp` stays 2 in both, because kern never runs a box without a filter.
        let mut cmd = std::process::Command::new("kern");
        b("true").push_box_flags(&mut cmd);
        let argv: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(argv.iter().any(|a| a == "--privileged"), "{argv:?}");
        assert!(
            argv.windows(2).any(|w| w == ["--cap-add", "ALL"]),
            "{argv:?}"
        );
        // And a service that never asked sends neither.
        let mut cmd = std::process::Command::new("kern");
        b("false").push_box_flags(&mut cmd);
        let argv: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(!argv.iter().any(|a| a == "--privileged"), "{argv:?}");
    }

    /// `ipv4_address:` IS READ, ONE PER NETWORK, AND ONLY IF IT IS AN ADDRESS.
    ///
    /// A service on two networks has two addresses and keeping the first would drop a peer's route
    /// with nothing said. A value that is not an IPv4 literal is not carried at all: it would reach
    /// `kern box --ip` and fail there, where nothing can point back at the key it came from.
    #[test]
    fn ipv4_address_is_collected_per_network_and_validated() {
        let one = parse(
            "services:\n  a:\n    image: alpine\n    networks:\n      net:\n        \
             ipv4_address: 172.28.1.10\n",
        )
        .expect("parses");
        assert_eq!(one[0].net_ipv4, vec!["172.28.1.10".to_string()]);

        let two = parse(
            "services:\n  a:\n    image: alpine\n    networks:\n      front:\n        \
             ipv4_address: 172.28.1.10\n      back:\n        ipv4_address: 10.5.0.7\n",
        )
        .expect("parses");
        assert_eq!(
            two[0].net_ipv4,
            vec!["172.28.1.10".to_string(), "10.5.0.7".to_string()],
            "a service on two networks keeps both addresses, in file order"
        );

        // Not an address: dropped here rather than carried to a flag that cannot name the key.
        for bad in ["172.28.1.999", "not-an-ip", "", "2001:db8::1"] {
            let b = parse(&format!(
                "services:\n  a:\n    image: alpine\n    networks:\n      net:\n        \
                 ipv4_address: {bad}\n"
            ))
            .expect("parses");
            assert!(b[0].net_ipv4.is_empty(), "{bad:?} must not be carried");
        }
        // THE CONTROL: a service with no such key carries nothing, so the assertions above are
        // about the key and not about the parser filling something in.
        let none =
            parse("services:\n  a:\n    image: alpine\n    networks: [net]\n").expect("parses");
        assert!(none[0].net_ipv4.is_empty());
    }

    /// THE `ipv4_address:` SENTENCE IS HONOURED IN ONE WIRING AND HALF-HONOURED IN THE OTHER.
    ///
    /// In one namespace every address lands on the one loopback and a peer that hard-codes it
    /// reaches the service. With a namespace per service a box claims only its own, so the service
    /// answers there and a PEER does not reach it. Calling both "applied" would put the file back in
    /// the position this work exists to remove.
    #[test]
    fn the_ipv4_sentence_promises_a_peer_route_only_where_there_is_one() {
        let pairs = vec![("db".to_string(), "172.28.1.10".to_string())];
        let pod = net_ipv4_note(crate::StackNet::Pod, &pairs).expect("owed");
        let per = net_ipv4_note(crate::StackNet::PerService, &pairs).expect("owed");
        assert!(pod.contains("is applied here"), "{pod}");
        assert!(
            pod.contains("reaches the service"),
            "the pod sentence must promise the peer route it delivers: {pod}"
        );
        assert!(per.contains("is claimed only where"), "{per}");
        assert!(
            per.contains("still has no route to it"),
            "the per-service sentence must say the peer route is NOT there: {per}"
        );
        assert!(
            !per.contains("is applied here"),
            "and must not claim the key is applied: {per}"
        );
        for s in [&pod, &per] {
            assert!(s.contains("db at 172.28.1.10"), "{s}");
        }
        assert_eq!(net_ipv4_note(crate::StackNet::Pod, &[]), None);
        assert_eq!(net_ipv4_note(crate::StackNet::Undecided, &pairs), None);
    }

    /// THE SENTENCE MUST SAY OPPOSITE THINGS IN THE TWO WIRINGS, because the two wirings make
    /// opposite things true, and the one it used to say was picked before the wiring was known.
    ///
    /// The old sentence claimed the key was satisfied and named `--no-pod` as the case to worry
    /// about. MEASURED on the corpus: 75 files use the key and kern selects the per-service wiring
    /// for 20 of them on its own, so the reassurance was false for one file in four that read it,
    /// and the flag it told the reader to avoid was one they never passed.
    #[test]
    fn the_net_share_sentence_says_opposite_things_in_the_two_wirings() {
        let pairs = vec![("client".to_string(), "vpn".to_string())];
        let pod = net_share_note(crate::StackNet::Pod, &pairs).expect("a pod stack is owed one");
        let per = net_share_note(crate::StackNet::PerService, &pairs)
            .expect("a per-service stack is owed one");
        assert!(
            pod.contains("is satisfied here"),
            "in one namespace the key IS satisfied: {pod}"
        );
        assert!(
            per.contains("is NOT given a shared namespace here"),
            "with a namespace per service it is not: {per}"
        );
        // THE HALF THAT MATTERS. People write this key to put a service behind a VPN or a proxy
        // container. A sentence that says "not shared" without saying where the traffic goes
        // instead leaves the reader with the safer of the two readings, which is the wrong one.
        assert!(
            per.contains("does NOT pass through the service it names"),
            "the per-service sentence must say where the traffic goes: {per}"
        );
        assert!(
            !pod.contains("does NOT pass through"),
            "and the pod sentence must not, because there it does: {pod}"
        );
        // Both name the pair, so a reader knows which services the sentence is about.
        for s in [&pod, &per] {
            assert!(s.contains("client -> vpn"), "{s}");
        }
        // Nothing to say when nothing asked, and nothing to say before the wiring is settled.
        assert_eq!(net_share_note(crate::StackNet::Pod, &[]), None);
        assert_eq!(net_share_note(crate::StackNet::Undecided, &pairs), None);
    }

    /// `shm_size:` IS FORWARDED NOW, AND THE OLD REASONING WAS RIGHT ABOUT THE WRONG DIRECTION.
    ///
    /// kern mounts `/dev/shm` unsized and charges it to the box's memory cgroup, so for a file
    /// asking for LESS than that bound a fixed size would be moot - and reintroducing Docker's 64 MB
    /// default is the footgun that breaks Postgres under load. Real files ask for MORE: measured on a
    /// neutral corpus of 259 compose files, the two that set the key ask for `1g` and `8GB`, both
    /// above kern's 512 MiB default memory cap, so the file asked for more shared memory than the box
    /// had and silently got less. Verified inside a box after the change: `shm_size: 1g` gives
    /// `/dev/shm` 1.0G.
    #[test]
    fn shm_size_reaches_the_box_instead_of_being_dropped() {
        let src = "services:\n  a:\n    image: alpine\n    shm_size: 1g\n";
        let b = parse(src).expect("parses").remove(0);
        assert_eq!(b.shm_size.as_deref(), Some("1g"));

        // A file that says nothing keeps kern's own behaviour: `/dev/shm` bounded by the memory
        // cgroup, with no fixed default to be surprised by.
        let plain = parse("services:\n  a:\n    image: alpine\n")
            .expect("parses")
            .remove(0);
        assert_eq!(plain.shm_size, None);
    }

    /// `${VAR:?err}` EXISTS TO STOP THE FILE BEING RENDERED, and kern substituted the empty string.
    ///
    /// MEASURED on the neutral corpus: five files use it and every one of them is a credential, so
    /// the old behaviour started a database with a blank password from a file whose author wrote the
    /// one construct that prevents exactly that.
    /// A STRING `command:` IS AN ARGV, NOT A SHELL LINE, and this is where Compose deliberately
    /// differs from a Dockerfile. The specification says the shell-form syntax "does not implicitly
    /// run in the context of the SHELL instruction" and tells the author to write `/bin/sh -c` when
    /// they want one.
    ///
    /// MEASURED: kern wrapped the string as `sh -c "<string>"`, so Docker's own `awesome-compose`
    /// WordPress sample (`command: '--default-authentication-plugin=…'` on `mariadb`) started `sh`
    /// with that string as an OPTION and the database died every time with
    /// `sh: 0: Illegal option --`. After the change the box runs
    /// `docker-entrypoint.sh --default-authentication-plugin=…` and MariaDB reports ready.
    /// A SECRET ONLY ROOT CAN READ IS UNREADABLE TO MOST DATABASE IMAGES.
    ///
    /// The Compose Specification says a service secret has "world-readable permissions (mode
    /// `0444`)"; kern wrote every secret `0400` into a `0700` directory. MEASURED on Docker's own
    /// `nginx-golang-postgres` sample, whose `db` declares `user: postgres`: the entrypoint died with
    /// `/run/secrets/db-password: Permission denied` on every start, the database never came up, and
    /// the `service_healthy` gate its backend waits on timed out after 120 s. With the mode fixed the
    /// same file comes up and the proxy answers 200 with rows from the database.
    /// A KEY KERN READS AND DOES NOT APPLY MUST BE NAMED.
    ///
    /// `target:`, `uid:` and `gid:` each change where the secret lands or who may read it, and kern
    /// honours none of them: it delivers every secret at `/run/secrets/<source>` owned by box root.
    /// Left silent, a service that opens the path `target:` names fails inside its own code with an
    /// error pointing nowhere near the mount - the exact shape this branch exists to remove.
    ///
    /// NAMED RATHER THAN IMPLEMENTED because none of the three appears once in 259 real compose
    /// files nor in Docker's own samples; see `UNHONOURED_SECRET_KEYS`.
    #[test]
    fn the_secret_keys_kern_does_not_apply_are_named_and_the_rest_stay_quiet() {
        let note = |y: &str| {
            let (_, _, un) = secret_refs(
                super::build_tree(&super::lex(y).unwrap())
                    .unwrap()
                    .child("x")
                    .unwrap(),
            );
            unhonoured_secret_note(&un)
        };
        // Short form and a long form using only what kern honours: nothing to say.
        assert_eq!(note("x:\n  - pw\n"), None);
        assert_eq!(note("x:\n  - source: pw\n    mode: 0400\n"), None);

        // Each unhonoured key on its own is named, and only itself.
        for (yaml, key, quiet) in [
            (
                "x:\n  - source: pw\n    target: /etc/pw\n",
                "`target`",
                "`uid`",
            ),
            (
                "x:\n  - source: pw\n    uid: \"1500\"\n",
                "`uid`",
                "`target`",
            ),
            (
                "x:\n  - source: pw\n    gid: \"1500\"\n",
                "`gid`",
                "`target`",
            ),
        ] {
            let n = note(yaml).unwrap_or_else(|| panic!("must be named: {yaml}"));
            assert!(n.contains(key), "must name {key}: {n}");
            assert!(!n.contains(quiet), "must NOT name {quiet}: {n}");
        }

        // All three at once: named in the specification's order, once each even across entries.
        let n = note("x:\n  - source: pw\n    target: /etc/pw\n    uid: \"1\"\n    gid: \"2\"\n  - source: other\n    uid: \"3\"\n")
            .expect("three keys must be named");
        assert!(
            n.contains("`target`, `uid`, `gid`"),
            "the specification's order, no repeats: {n}"
        );
    }

    #[test]
    fn a_service_secret_carries_the_specifications_mode_and_a_declared_one_wins() {
        let mode = |y: &str| parse(y).unwrap().into_iter().next().unwrap().secret_mode;
        let base = "services:\n  db:\n    image: alpine\n    secrets:";
        let tail = "\nsecrets:\n  pw:\n    file: ./p.txt\n  other:\n    file: ./o.txt\n";

        // Short form: the file declares no mode, so the SPEC's default applies. `None` here, and the
        // driver turns it into `SPEC_SECRET_MODE` at the one place that builds the command line.
        assert_eq!(mode(&format!("{base} [\"pw\"]{tail}")), None);
        // Long form with a mode: honoured VERBATIM. A leading `0` is kept because the value is read
        // back with `from_str_radix(.., 8)`, where `0440` and `440` are the same number - stripping
        // it would be a rewrite with no reader.
        assert_eq!(
            mode(&format!("{base} [{{source: pw, mode: 0440}}]{tail}")),
            Some("0440".to_string())
        );
        assert_eq!(
            mode(&format!("{base} [{{source: pw, mode: 0o400}}]{tail}")),
            Some("400".to_string())
        );
        // Two secrets asking for the SAME mode is not a conflict.
        assert_eq!(
            mode(&format!(
                "{base} [{{source: pw, mode: 0440}}, {{source: other, mode: 0440}}]{tail}"
            )),
            Some("0440".to_string())
        );

        // TWO DIFFERENT MODES ARE REFUSED, not silently resolved. kern carries one mode per box, and
        // picking one of two would give a secret a permission the file did not ask for.
        let err = parse(&format!(
            "{base} [{{source: pw, mode: 0400}}, {{source: other, mode: 0444}}]{tail}"
        ))
        .expect_err("two different modes for one service must be refused");
        assert!(
            err.contains("different"),
            "must say what the conflict is: {err}"
        );
        assert!(
            err.contains("400") && err.contains("444"),
            "and name both: {err}"
        );
    }

    #[test]
    fn a_string_command_is_split_into_an_argv_and_never_wrapped_in_a_shell() {
        let cmd = |y: &str| parse(y).unwrap().into_iter().next().unwrap().command;
        let svc = |c: &str| format!("services:\n  a:\n    image: alpine\n    command: {c}\n");

        // THE CASE THAT WAS BROKEN: an argument that begins with `-`.
        assert_eq!(
            cmd(&svc(
                "'--default-authentication-plugin=mysql_native_password'"
            )),
            ["--default-authentication-plugin=mysql_native_password"]
        );
        // No shell anywhere in the result: that is the whole claim.
        assert!(!cmd(&svc("'mysqld --skip-name-resolve'")).contains(&"sh".to_string()));
        assert_eq!(
            cmd(&svc("'mysqld --skip-name-resolve'")),
            ["mysqld", "--skip-name-resolve"]
        );

        // A FILE THAT ASKS FOR A SHELL STILL GETS ONE, because it writes the shell itself - which is
        // what the specification tells the author to do, and what most real files already do. The
        // quoted string must arrive as ONE argument with its `&&` intact.
        assert_eq!(
            cmd(&svc("'sh -c \"npm ci && npm run dev\"'")),
            ["sh", "-c", "npm ci && npm run dev"]
        );
        // Single quotes group too, and a quoted empty string is still an argument: dropping it would
        // shift every argument after it by one position.
        assert_eq!(cmd(&svc("\"a 'b c' '' d\"")), ["a", "b c", "", "d"]);
        // A backslash escapes outside quotes.
        assert_eq!(cmd(&svc("'a b\\ c'")), ["a", "b c"]);
        // Runs of whitespace separate, and never produce empty arguments.
        assert_eq!(cmd(&svc("'  a   b  '")), ["a", "b"]);

        // The list forms are untouched: they were always an argv.
        assert_eq!(
            cmd("services:\n  a:\n    image: alpine\n    command: [\"a\", \"b c\"]\n"),
            ["a", "b c"]
        );
        assert_eq!(
            cmd("services:\n  a:\n    image: alpine\n    command:\n      - a\n      - b c\n"),
            ["a", "b c"]
        );
    }

    /// A STRING `entrypoint:` DOES NOT DROP `command`, and it used to.
    ///
    /// That rule belongs to Dockerfiles, where `ENTRYPOINT some string` becomes `/bin/sh -c "…"` and
    /// has nowhere to put arguments. The Compose Specification says its own string form does not run
    /// in a shell, so the premise is absent and so is the consequence. kern cleared the command and
    /// warned, which silently discarded arguments the file asked for.
    #[test]
    fn a_string_entrypoint_keeps_the_command_and_appends_to_it() {
        let b = parse(
            "services:\n  a:\n    image: alpine\n    entrypoint: /entry.sh --flag\n    command: run --fast\n",
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
        assert_eq!(
            b.entrypoint.as_deref(),
            Some(&["/entry.sh".to_string(), "--flag".to_string()][..])
        );
        assert_eq!(b.command, ["run", "--fast"]);

        // A list entrypoint behaves identically, which is the point: there is now ONE rule.
        let b = parse(
            "services:\n  a:\n    image: alpine\n    entrypoint: [\"/entry.sh\"]\n    command: run\n",
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
        assert_eq!(
            b.entrypoint.as_deref(),
            Some(&["/entry.sh".to_string()][..])
        );
        assert_eq!(b.command, ["run"]);
    }

    #[test]
    fn a_required_variable_with_no_value_refuses_the_file() {
        let y = "services:\n  db:\n    image: alpine\n    environment:\n      - PW=${KERN_T_PW:?set KERN_T_PW}\n";
        let err = parse(y).expect_err("a required variable with no value must refuse");
        assert!(err.contains("KERN_T_PW"), "must name the variable: {err}");
        assert!(
            err.contains("set KERN_T_PW"),
            "and the file's own message: {err}"
        );

        // POSITIVE CONTROL: with a value the same file parses. Without this the assertion above
        // would hold for a build that refuses every file.
        // SAFETY: single-threaded test, and the variable is namespaced to this test.
        unsafe { std::env::set_var("KERN_T_PW", "s3cret") };
        assert!(
            parse(y).is_ok(),
            "the same file must parse once the value exists"
        );
        unsafe { std::env::remove_var("KERN_T_PW") };

        // EVERY missing variable, not just the first: a reader with three unset secrets should not
        // have to rerun three times to learn their names.
        let two = "services:\n  db:\n    image: alpine\n    environment:\n      - A=${KERN_T_A:?need A}\n      - B=${KERN_T_B:?need B}\n";
        let err = parse(two).expect_err("both are missing");
        assert!(
            err.contains("KERN_T_A") && err.contains("KERN_T_B"),
            "both names: {err}"
        );

        // THE COLLECTOR MUST NOT BLEED INTO THE NEXT DOCUMENT. A parse that fails leaves entries
        // behind unless they are cleared on entry, and the next file would be refused for a variable
        // it never mentions.
        let clean = "services:\n  db:\n    image: alpine\n";
        assert!(
            parse(clean).is_ok(),
            "a file mentioning no variable must parse after one that failed"
        );

        // `${VAR-default}` and `${VAR:-default}` are NOT this form and must keep working: only `?`
        // is a refusal.
        let dflt = "services:\n  db:\n    image: alpine\n    environment:\n      - A=${KERN_T_UNSET:-fallback}\n";
        assert!(parse(dflt).is_ok(), "a defaulted variable is not required");
    }

    #[test]
    fn an_external_volume_is_marked_on_every_service_that_mounts_it() {
        let y = "services:\n  db:\n    image: alpine\n    volumes: [\"pgdata:/var/lib/pg\", \"scratch:/tmp/s\"]\n  web:\n    image: alpine\n    volumes: [\"scratch:/tmp/s\"]\nvolumes:\n  pgdata:\n    external: true\n  scratch: {}\n";
        let boxes = parse(y).unwrap();
        // Only the one the file declared external. `scratch:` is kern's to create, and marking it
        // would turn an ordinary named volume into a refusal.
        assert_eq!(boxes[0].external_volumes, ["pgdata"]);
        assert!(boxes[1].external_volumes.is_empty());
        // The mount itself is untouched: it is an ordinary `-v` by the time the box sees it.
        assert!(boxes[0].volumes.contains(&"pgdata:/var/lib/pg".to_string()));
    }

    #[test]
    fn external_false_is_the_default_written_out_and_declares_nothing() {
        // `external: false` is what a generator emits for a volume it DOES own. Reading it as a
        // declaration would refuse a stack Docker starts, which is the opposite of this work.
        let y = "services:\n  db:\n    image: alpine\n    volumes: [\"d:/d\"]\nvolumes:\n  d:\n    external: false\n";
        let boxes = parse(y).unwrap();
        assert!(boxes[0].external_volumes.is_empty());
    }

    #[test]
    fn an_external_name_override_renames_the_mount_and_the_name_that_must_exist() {
        // `name:` points at a volume whose real name differs from the key services write. The check
        // and the mount have to be about the SAME string or kern verifies one volume and mounts
        // another. Both spellings: the modern sibling `name:` and the deprecated nested one.
        for y in [
            "services:\n  db:\n    image: alpine\n    volumes: [\"pgdata:/d\"]\nvolumes:\n  pgdata:\n    external: true\n    name: prod_pgdata\n",
            "services:\n  db:\n    image: alpine\n    volumes: [\"pgdata:/d\"]\nvolumes:\n  pgdata:\n    external:\n      name: prod_pgdata\n",
        ] {
            let boxes = parse(y).unwrap();
            assert_eq!(boxes[0].external_volumes, ["prod_pgdata"], "{y}");
            assert_eq!(boxes[0].volumes, ["prod_pgdata:/d"], "{y}");
        }
    }

    /// MEASURED HOLE, FOUND IN THIS SPRINT'S OWN SECURITY PASS: with `name: /var/tmp/x` the rewrite
    /// produced the `-v` source `/var/tmp/x`, kern's `-v` classifier read it as a HOST PATH, and the
    /// box bind-mounted that directory and read a file out of it. No capability was granted that the
    /// service's own `volumes:` list does not already have, but the request moved out of the line a
    /// reader looks at, and Docker refuses it outright (`name:` names a volume, never a path).
    #[test]
    fn an_external_name_that_is_not_a_volume_name_is_refused() {
        let file = |name: &str| {
            format!(
                "services:\n  db:\n    image: alpine\n    volumes: [\"v:/d\"]\nvolumes:\n  v:\n    external: true\n    name: {name}\n"
            )
        };
        // Absolute, relative and multi-component: each is a shape kern's `-v` classifier would read
        // as a path rather than a name, plus the two leading characters `valid_resource_name` bars.
        for bad in [
            "/var/tmp/x",
            "../../etc",
            "./x",
            "a/b",
            "..",
            "-lead",
            ".lead",
        ] {
            let err = parse(&file(bad)).expect_err(&format!("must be refused: {bad}"));
            assert!(
                err.contains("is not a volume name"),
                "and refused as a NAME problem, not something else: {bad} -> {err}"
            );
        }

        // POSITIVE CONTROL: an ordinary rename still works, and still renames. Without it the
        // assertions above would hold for a build that refuses every `name:`.
        let boxes = parse(&file("prod_pgdata")).expect("a real volume name is fine");
        assert_eq!(boxes[0].volumes, ["prod_pgdata:/d"]);
        assert_eq!(boxes[0].external_volumes, ["prod_pgdata"]);
    }

    #[test]
    fn a_top_level_volumes_block_below_services_is_still_read() {
        // The blocks are unordered in YAML, and collecting during the services loop would mark a
        // file written one way and miss the same file written the other.
        let below = "services:\n  db:\n    image: alpine\n    volumes: [\"v:/d\"]\nvolumes:\n  v:\n    external: true\n";
        let above = "volumes:\n  v:\n    external: true\nservices:\n  db:\n    image: alpine\n    volumes: [\"v:/d\"]\n";
        for y in [below, above] {
            assert_eq!(parse(y).unwrap()[0].external_volumes, ["v"], "{y}");
        }
    }

    #[test]
    fn a_volume_inherited_through_volumes_from_is_marked_too() {
        // `volumes_from` copies mounts into a box AFTER its own conversion, so a pass that ran
        // earlier would mark the source service and let the inheriting one through unchecked.
        let y = "services:\n  data:\n    image: alpine\n    volumes: [\"v:/d\"]\n  app:\n    image: alpine\n    volumes_from: [\"data\"]\nvolumes:\n  v:\n    external: true\n";
        let boxes = parse(y).unwrap();
        let app = boxes.iter().find(|b| b.name == "app").unwrap();
        assert_eq!(app.external_volumes, ["v"]);
    }

    /// A BARE PATH IS COMPOSE'S ANONYMOUS VOLUME, AND IT USED TO BE REFUSED OUTRIGHT.
    ///
    /// `volumes: ["/app/node_modules"]` is the commonest idiom in the Node ecosystem: it stops a bind
    /// mount of the project directory from hiding the `node_modules` the image built. MEASURED on a
    /// real repository (`alitarhinisv/Notes-FE`): the entry reached `kern box` unchanged and the box
    /// refused it with `bad -v '/app/node_modules' (expected src:dst[:ro])`, so a project that runs
    /// under Docker could not start at all.
    ///
    /// The name is DERIVED from the service and the path, not random, so the same service and path
    /// reuse the same volume across `up` - which is what Compose does with the id it remembers.
    #[test]
    fn a_bare_path_becomes_a_named_volume_and_every_other_shape_is_untouched() {
        // The anonymous form: a source is synthesised, the target is what the file wrote.
        let v = anonymous_volume("/app/node_modules", "web");
        let (src, dst) = v.split_once(':').expect("src:dst");
        assert_eq!(dst, "/app/node_modules");
        assert!(
            src.starts_with("anon-web-") && !src.contains('/'),
            "the synthesised source must be a volume NAME, not a path: {src}"
        );
        // Deterministic: the same service and path give the same volume, which is what makes it
        // survive a `down`/`up` the way Compose's remembered id does.
        assert_eq!(v, anonymous_volume("/app/node_modules", "web"));
        // And distinct per service and per path, or two services would share one volume.
        assert_ne!(v, anonymous_volume("/app/node_modules", "api"));
        assert_ne!(v, anonymous_volume("/app/.next", "web"));

        // Every shape that already names a source is returned byte-identical.
        for already in [
            ".:/app",
            "/h:/c",
            "/h:/c:ro",
            "named_vol:/data",
            "named_vol:/data:ro",
        ] {
            assert_eq!(anonymous_volume(already, "web"), already);
        }
        // A relative path with no colon is not the anonymous form (Compose requires an absolute
        // target), so it is left alone for the box to refuse with its own message.
        assert_eq!(anonymous_volume("data", "web"), "data");
    }

    /// `volumes_from:` COPIES, AND A COPY IS NEVER MORE PERMISSIVE THAN ITS SOURCE.
    ///
    /// Resolved after the whole file is parsed, because the named service may be defined BELOW the
    /// one that names it and a single-pass copy would inherit nothing while looking applied. The
    /// `:ro` suffix narrows every inherited entry, and an entry that was already read-only stays so:
    /// a copy that widened a mount would hand a service write access its source did not have.
    ///
    /// MEASURED end to end: the inheriting service saw both of its source's mounts and could write
    /// `/out`; the `:ro` one saw the same two and could not.
    #[test]
    fn volumes_from_copies_after_the_whole_file_and_never_widens_a_mount() {
        let svc = |src: &str| parse(src).expect("parses");

        // The source is defined BELOW the service that inherits it.
        let set = svc(
            "services:\n  user:\n    image: alpine\n    volumes_from: [data]\n  data:\n    image: alpine\n    volumes: [\"/h:/c\", \"/r:/ro:ro\"]\n",
        );
        let user = set.iter().find(|b| b.name == "user").expect("user");
        assert_eq!(
            user.volumes,
            vec!["/h:/c".to_string(), "/r:/ro:ro".to_string()]
        );

        // `:ro` narrows every entry, and does not double a suffix that is already there.
        let set = svc(
            "services:\n  data:\n    image: alpine\n    volumes: [\"/h:/c\", \"/r:/ro:ro\"]\n  user:\n    image: alpine\n    volumes_from: [\"data:ro\"]\n",
        );
        let user = set.iter().find(|b| b.name == "user").expect("user");
        assert_eq!(
            user.volumes,
            vec!["/h:/c:ro".to_string(), "/r:/ro:ro".to_string()]
        );

        // An entry the service already declares is not duplicated.
        let set = svc(
            "services:\n  data:\n    image: alpine\n    volumes: [\"/h:/c\"]\n  user:\n    image: alpine\n    volumes: [\"/h:/c\"]\n    volumes_from: [data]\n",
        );
        let user = set.iter().find(|b| b.name == "user").expect("user");
        assert_eq!(user.volumes, vec!["/h:/c".to_string()]);

        // A name that is not in the file inherits nothing rather than something arbitrary.
        let set = svc("services:\n  user:\n    image: alpine\n    volumes_from: [nosuch]\n");
        assert!(set[0].volumes.is_empty());
    }

    /// `platform:` IS EITHER ALREADY TRUE OR IMPOSSIBLE, and only the second is worth a sentence.
    ///
    /// kern runs the host's architecture and emulates nothing. A platform naming that architecture
    /// is what the box will be anyway, so warning about it would be noise on every ARM-targeted file
    /// running on ARM. One naming a different architecture cannot be honoured at all, and the failure
    /// it produces (the image pulls, then the workload will not exec) points nowhere near the line
    /// that caused it.
    #[test]
    fn a_platform_is_matched_against_this_machine_in_every_spelling() {
        let host = host_platform();
        let (os, arch) = host.split_once('/').expect("os/arch");

        // The three spellings a file may use, all of them this machine.
        assert!(platform_matches_host(arch), "bare arch: {arch}");
        assert!(platform_matches_host(&host), "os/arch: {host}");
        assert!(
            platform_matches_host(&format!("{host}/v8")),
            "a variant suffix is not a different platform"
        );

        // A different architecture, and a different OS with the right architecture.
        assert!(!platform_matches_host("s390x"));
        assert!(!platform_matches_host(&format!("{os}/s390x")));
        assert!(!platform_matches_host(&format!("windows/{arch}")));
        // Garbage is not this machine either.
        assert!(!platform_matches_host("a/b/c/d"));

        // And the spelling is Docker's, not Rust's: this is the whole reason for the mapping.
        if std::env::consts::ARCH == "x86_64" {
            assert_eq!(arch, "amd64");
        }
        if std::env::consts::ARCH == "aarch64" {
            assert_eq!(arch, "arm64");
        }
    }

    /// A SHARE IS A RATIO AGAINST THE DEFAULT, SO THE DEFAULT MUST MAP TO THE DEFAULT.
    ///
    /// Docker's `cpu_shares` is 2..=262144 with **1024 = normal**; cgroup v2's `cpu.weight` is
    /// 1..=10000 with **100 = normal**. A file writing `cpu_shares: 1024` is asking for an ordinary
    /// slice, and any mapping that does not return 100 for it has changed what the file said.
    ///
    /// MEASURED on the first version of this function, which mapped the ENDPOINTS onto each other
    /// instead: inside a box, `cpu_shares: 1024` produced `cpu.weight = 39`. The stack ran, nothing
    /// warned, and an ordinary service had been given well under half an ordinary slice. This test
    /// exists because the endpoints looked like the invariant and were not.
    #[test]
    fn docker_shares_map_normal_onto_normal_and_stay_inside_the_kernel_range() {
        // The one that matters: Docker's default is cgroup v2's default.
        assert_eq!(docker_shares_to_cpu_weight(1024), 100);
        // Proportional either side of it.
        assert_eq!(docker_shares_to_cpu_weight(2048), 200);
        assert_eq!(docker_shares_to_cpu_weight(512), 50);
        // Both ends of Docker's range land inside the kernel's, by clamping rather than by wrapping.
        assert_eq!(
            docker_shares_to_cpu_weight(2),
            1,
            "the minimum is a valid weight, not 0"
        );
        assert_eq!(docker_shares_to_cpu_weight(262_144), 10_000);
        // Out-of-range input cannot produce an out-of-range weight, in either direction.
        for s in [0_u64, 1, u64::MAX, 999_999_999] {
            let w = docker_shares_to_cpu_weight(s);
            assert!((1..=10_000).contains(&w), "shares {s} gave weight {w}");
        }
    }

    /// `cpu_quota` + `cpu_period` ARE `--cpus` WRITTEN THE LONG WAY, and the two keys may appear in
    /// either order.
    ///
    /// cgroup v2 spells both as one `cpu.max` line, which kern already computes from `cpus`, so the
    /// pair is divided rather than given a second mechanism. A lone quota means Docker's default
    /// period (100000us); a lone period bounds nothing and is named instead of being applied to a
    /// quota that does not exist.
    #[test]
    fn the_cpu_quota_period_pair_becomes_cpus_in_either_order() {
        let cpus = |body: &str| {
            let src = format!("services:\n  a:\n    image: alpine\n{body}");
            parse(&src).expect("parses").remove(0).cpus
        };
        // Half a core, written both ways round.
        assert_eq!(
            cpus("    cpu_quota: 50000\n    cpu_period: 100000\n").as_deref(),
            Some("0.5")
        );
        assert_eq!(
            cpus("    cpu_period: 100000\n    cpu_quota: 50000\n").as_deref(),
            Some("0.5")
        );
        // A lone quota takes Docker's default period.
        assert_eq!(cpus("    cpu_quota: 200000\n").as_deref(), Some("2"));
        // A lone period bounds nothing.
        assert_eq!(cpus("    cpu_period: 100000\n"), None);
        // An explicit `cpus:` wins: a file that said the same thing twice gets the one a reader
        // believes.
        assert_eq!(
            cpus("    cpus: 1.5\n    cpu_quota: 50000\n").as_deref(),
            Some("1.5")
        );
    }

    /// THE `networks:` SENTENCE MUST MATCH WHAT THE RUN ACTUALLY DOES, AND THE TWO WIRINGS DO
    /// OPPOSITE THINGS.
    ///
    /// In a pod every service shares one namespace, so services on separate networks CAN reach each
    /// other and the key is dropped. Without a pod the relay graph follows the memberships, so they
    /// CANNOT. One sentence cannot be true in both, and a parser that guessed would be wrong half
    /// the time - which is the reason the mode is a parameter rather than an assumption.
    ///
    /// The `--no-pod` sentence has to carry the `default` rule too: an absent `networks:` key is the
    /// implicit network, so a service without one is separated FROM the services that name one, and
    /// that is the half people get wrong.
    #[test]
    fn the_networks_sentence_states_what_the_chosen_wiring_does() {
        assert!(
            NETWORKS_IGNORED.contains("CAN reach each other"),
            "in a pod the key is dropped: {NETWORKS_IGNORED}"
        );
        assert!(
            NETWORKS_SEGREGATED.contains("ENFORCED") && NETWORKS_SEGREGATED.contains("default"),
            "without a pod it is applied, and the default rule must be stated: {NETWORKS_SEGREGATED}"
        );
        // The two must never be the same string, and the pod one must not claim enforcement.
        assert_ne!(NETWORKS_IGNORED, NETWORKS_SEGREGATED);
        assert!(!NETWORKS_IGNORED.contains("ENFORCED"));
        assert!(!NETWORKS_SEGREGATED.contains("CAN reach each other"));

        // And the selector hands out the one that matches the wiring.
        assert_eq!(networks_note(crate::StackNet::Pod), Some(NETWORKS_IGNORED));
        assert_eq!(
            networks_note(crate::StackNet::PerService),
            Some(NETWORKS_SEGREGATED)
        );
        // The driver says it when the wiring is chosen from the file, so the parser must not.
        assert_eq!(networks_note(crate::StackNet::Undecided), None);
        assert_eq!(internal_note(crate::StackNet::Undecided, false), None);
        assert_eq!(internal_note(crate::StackNet::Undecided, true), None);
    }

    /// `internal: true` IS SATISFIED WITHOUT A POD, AND OVER-APPLIED, AND BOTH HALVES ARE SAID.
    ///
    /// MEASURED in both wirings with a TCP connect rather than a route table: a pod member reaches
    /// `1.1.1.1:443`, a `--no-pod` box holds only `lo` and the same connect is refused. So the key is
    /// honoured for the services that asked - and for the ones that did not, which the Compose
    /// Specification would not. A note that stated only the first half would leave a stack calling an
    /// external API
    /// failing with nothing pointing at the network.
    ///
    /// The service membership itself is parsed identically in both modes: only what kern SAYS about
    /// it changes, and this asserts that the parsed fact does not move with the sentence.
    #[test]
    fn the_internal_sentence_matches_the_wiring_and_the_membership_does_not_move() {
        assert!(
            INTERNAL_NOT_APPLIED.contains("stay open for every service"),
            "the pod sentence: {INTERNAL_NOT_APPLIED}"
        );
        assert!(
            INTERNAL_SATISFIED_BY_NO_POD.contains("ENFORCES it")
                && INTERNAL_SATISFIED_BY_NO_POD.contains("keep their egress"),
            "the per-service sentence must say the boundary is real AND that other services still \
             reach out, or it repeats the claim that was true only before per-box NATs existed: \
             {INTERNAL_SATISFIED_BY_NO_POD}"
        );
        assert!(
            INTERNAL_SATISFIED_BY_NO_POD.contains("restart:"),
            "and it must name the one service kern cannot give a NAT to: {INTERNAL_SATISFIED_BY_NO_POD}"
        );
        assert_ne!(INTERNAL_NOT_APPLIED, INTERNAL_SATISFIED_BY_NO_POD);

        // THE WHOLE TRUTH TABLE, because asserting the two strings said nothing about which one is
        // chosen: a mutation that emitted the pod sentence outside a pod left this test green until
        // the decision was pulled out of the `warn_once` call.
        assert_eq!(
            internal_note(crate::StackNet::Pod, true),
            None,
            "in a pod with every service confined the key is HONOURED, so there is nothing to say"
        );
        assert_eq!(
            internal_note(crate::StackNet::Pod, false),
            Some(INTERNAL_NOT_APPLIED)
        );
        assert_eq!(
            internal_note(crate::StackNet::PerService, false),
            Some(INTERNAL_SATISFIED_BY_NO_POD)
        );
        assert_eq!(
            internal_note(crate::StackNet::PerService, true),
            Some(INTERNAL_SATISFIED_BY_NO_POD),
            "without a pod the sentence does not depend on whether the file confined everything"
        );

        let src = "networks:\n  back:\n    internal: true\n  front: {}\nservices:\n  db:\n    image: alpine\n    networks: [back]\n  web:\n    image: alpine\n    networks: [front, back]\n";
        let pod = parse(src).expect("parses in a pod");
        let nopod = parse_no_pod(src).expect("parses without one");
        for set in [&pod, &nopod] {
            assert_eq!(set[0].networks, vec!["back".to_string()]);
            assert_eq!(
                set[1].networks,
                vec!["front".to_string(), "back".to_string()]
            );
        }
        // `db` is only on internal networks, `web` is not - so the stack is not internal-only, in
        // either wiring. The mode changes the sentence, never the fact.
        assert!(pod[0].only_internal_networks && !pod[1].only_internal_networks);
        assert_eq!(
            nopod[0].only_internal_networks,
            pod[0].only_internal_networks
        );
    }

    /// `devices:` REACHES THE WORKLOAD, AND `/dev/net/tun` TAKES A DIFFERENT ROUTE THAN THE REST.
    ///
    /// The tun node is 37 of the 83 `devices:` values in a 240-file corpus and is the one entry a
    /// plain bind cannot serve: creating the tunnel interface needs `CAP_NET_ADMIN` inside the box's
    /// network namespace, which kern keeps for `--tun` and for nothing else. A bind would hand over
    /// the node and leave the workload unable to use it.
    ///
    /// Docker's third field is a cgroup ACL kern does not have, so the only part of it with a kern
    /// equivalent is honoured: no `w` means a read-only bind. `rwm` and an absent field are the same
    /// request and must produce the same entry.
    #[test]
    fn a_device_becomes_a_bind_except_the_tun_node_which_becomes_a_capability() {
        let norm = |v: &[&str]| {
            let owned: Vec<String> = v.iter().map(|s| (*s).to_string()).collect();
            let mut tun = false;
            let out = normalise_devices(&owned, "svc", &mut tun);
            (out, tun)
        };

        let (out, tun) = norm(&["/dev/net/tun:/dev/net/tun"]);
        assert!(tun, "the tun node must set --tun, not a bind");
        assert!(out.is_empty(), "and must not ALSO be bound: {out:?}");

        // Renamed target: `--tun` fixes the in-box path, so this one has to fall through to a bind.
        let (out, tun) = norm(&["/dev/net/tun:/dev/other"]);
        assert!(!tun, "a renamed tun target cannot be served by --tun");
        assert_eq!(out, vec!["/dev/net/tun:/dev/other".to_string()]);

        // One field: Docker defaults the in-box path to the host path.
        let (out, _) = norm(&["/dev/kvm"]);
        assert_eq!(out, vec!["/dev/kvm:/dev/kvm".to_string()]);

        // Permissions: no `w` is read-only, `rwm` and an absent field are both read-write.
        let (ro, _) = norm(&["/dev/kvm:/dev/kvm:r"]);
        assert_eq!(ro, vec!["/dev/kvm:/dev/kvm:ro".to_string()]);
        let (rw, _) = norm(&["/dev/kvm:/dev/kvm:rwm"]);
        assert_eq!(rw, vec!["/dev/kvm:/dev/kvm".to_string()]);
        assert_eq!(rw, norm(&["/dev/kvm:/dev/kvm"]).0);

        // An entry naming nothing is dropped rather than forwarded as a malformed `-v`.
        assert!(norm(&[""]).0.is_empty());
    }

    /// `devices:` MUST NOT DEPEND ON WHERE IT SITS IN THE SERVICE BLOCK.
    ///
    /// Its entries used to be pushed onto `volumes`, whose own key ASSIGNS the field, and the service
    /// keys are read in file order - so a `volumes:` written below a `devices:` erased it. MEASURED
    /// before the dedicated field existed: the identical string under `volumes:` gave the workload
    /// `crw-rw---- 10, 232 /dev/kvm` and under `devices:` gave `No such file or directory`, from the
    /// same binary in the same second. This asserts the property, in both orders, on the parser.
    #[test]
    fn devices_survive_a_volumes_key_written_after_them() {
        let both = |src: &str| -> Vec<String> {
            let s = parse(src).expect("parses");
            s[0].devices.clone()
        };
        let after = both(
            "services:\n  a:\n    image: alpine\n    devices: [\"/dev/kvm:/dev/kvm\"]\n    volumes: [\"/tmp:/tmp\"]\n",
        );
        let before = both(
            "services:\n  a:\n    image: alpine\n    volumes: [\"/tmp:/tmp\"]\n    devices: [\"/dev/kvm:/dev/kvm\"]\n",
        );
        assert_eq!(
            after,
            vec!["/dev/kvm:/dev/kvm".to_string()],
            "a devices: entry must survive a volumes: key written after it"
        );
        assert_eq!(after, before, "and the two orders must agree");
    }

    /// A LINK IS AN ALIAS AND AN ORDERING EDGE, and the edge must not be added twice.
    ///
    /// Docker's `links` predates user-defined networks and did both jobs. A file that writes both
    /// `depends_on: [db]` and `links: [db]` means one dependency, and two would make the level
    /// barrier wait on the same service twice and the topology report double-count it.
    #[test]
    fn a_link_adds_one_alias_and_one_ordering_edge() {
        let run = |entries: &[&str], mut deps: Vec<String>| {
            let owned: Vec<String> = entries.iter().map(|s| (*s).to_string()).collect();
            let links = normalise_links(&owned, &mut deps);
            (links, deps)
        };

        let (links, deps) = run(&["db:database"], Vec::new());
        assert_eq!(links, vec!["db:database".to_string()]);
        assert_eq!(deps, vec!["db".to_string()], "a link orders its target");

        // No alias: Docker aliases it under its own name, which the stack already resolves - but the
        // ordering edge is still owed.
        let (links, deps) = run(&["redis"], Vec::new());
        assert_eq!(links, vec!["redis:redis".to_string()]);
        assert_eq!(deps, vec!["redis".to_string()]);

        // Already a dependency: one edge, not two.
        let (_, deps) = run(&["db:database"], vec!["db".to_string()]);
        assert_eq!(deps, vec!["db".to_string()], "the edge must not duplicate");
    }

    /// AN `options:` BLOCK KERN FULLY HONOURS MUST NOT PRODUCE A WARNING.
    ///
    /// `max-size` and `max-file` are applied now; a line saying otherwise would be false, and a line
    /// printed on every `logging:` block is how a reader learns to skip the one that reports a real
    /// gap. What must still be named is the option kern has no equivalent for.
    #[test]
    fn logging_options_are_applied_and_only_the_unsupported_ones_are_named() {
        let svc = |body: &str| {
            let src = format!("services:\n  a:\n    image: alpine\n{body}");
            parse(&src).expect("parses").remove(0)
        };
        let b = svc("    logging:\n      driver: json-file\n      options:\n        max-size: \"10m\"\n        max-file: \"3\"\n");
        assert_eq!(b.log_max_size.as_deref(), Some("10m"));
        assert_eq!(b.log_max_file.as_deref(), Some("3"));

        // A driver kern does not have leaves both unset: rotating a capture that is not the one the
        // file asked for would be a different claim.
        let net =
            svc("    logging:\n      driver: gelf\n      options:\n        max-size: \"10m\"\n");
        assert_eq!(net.log_max_size, None);
    }

    /// A LONG-FORM `type: tmpfs` VOLUME IS A MOUNT, NOT A DROPPED ENTRY.
    ///
    /// It has no `source` by definition, so the shared long-form path refused it and the service ran
    /// without the scratch mount it asked for. It is kept in its OWN field rather than appended to
    /// `tmpfs`, because the `tmpfs:` key assigns that field and would erase it depending on key
    /// order - the same defect `devices` had.
    #[test]
    fn a_long_form_tmpfs_volume_becomes_a_tmpfs_mount_whatever_the_key_order() {
        let svc = |body: &str| {
            let src = format!("services:\n  a:\n    image: alpine\n{body}");
            parse(&src).expect("parses").remove(0)
        };
        let vol = "    volumes:\n      - type: tmpfs\n        target: /scratch\n        tmpfs:\n          size: 8388608\n";
        let key = "    tmpfs:\n      - /tmp:size=32m\n";

        let b = svc(&format!("{vol}{key}"));
        assert_eq!(
            b.tmpfs_from_volumes,
            vec!["/scratch:size=8388608".to_string()]
        );
        assert_eq!(b.tmpfs, vec!["/tmp:size=32m".to_string()]);
        // The other order must give the same two lists: neither may erase the other.
        let b2 = svc(&format!("{key}{vol}"));
        assert_eq!(b2.tmpfs_from_volumes, b.tmpfs_from_volumes);
        assert_eq!(b2.tmpfs, b.tmpfs);
        // And the long-form entry must NOT have become a bind, which is what would happen if it fell
        // through to the shared path with an empty source.
        assert!(
            b.volumes.is_empty(),
            "a tmpfs volume is not a bind: {:?}",
            b.volumes
        );
    }

    /// THE WARNING MAY NOT NAME A PORT THAT IS NOT IN THE FILE.
    ///
    /// The sentence used to quote `8000` as an example regardless of the entry that triggered it, so
    /// a file declaring only `9090` produced a line about port 8000. Reported from a field test on
    /// `dev`, which had to isolate the case to establish that kern was not reading stale state from
    /// a previous file. An example that reads like an observation costs the reader that
    /// investigation, every time.
    #[test]
    fn the_container_only_port_note_names_the_port_the_file_declared() {
        let note = container_only_port_note(9090);
        assert!(
            note.contains("`9090`") && note.contains("HOST:9090"),
            "the note must quote the port that triggered it, in both places: {note}"
        );
        assert!(
            !note.contains("8000"),
            "and it must not mention a port the file never named: {note}"
        );
        // Positive control: 8000 is not banned, it is simply no longer hardcoded.
        assert!(container_only_port_note(8000).contains("`8000`"));
        // The two are different sentences, which is the property the old literal could not have.
        assert_ne!(container_only_port_note(1), container_only_port_note(2));
    }

    /// A NUL BYTE IS REFUSED BY THE FILE, NOT BY WHATEVER SYSCALL TRIPS OVER IT LATER.
    ///
    /// U+0001 was already barred, but only because it is this module's private newline sentinel, so a
    /// reader could conclude control bytes in general were handled. They were not: measured, a U+0000
    /// travelled intact into an image name and printed raw to the operator's terminal. Everything that
    /// consumes a compose value downstream is a C string or a path, so a NUL is either truncated in
    /// silence or refused a long way from the file that carries it.
    ///
    /// The positive control is the same document without the byte: it must still parse, otherwise this
    /// would pass against a check that refused the shape rather than the NUL.
    #[test]
    fn a_nul_byte_is_refused_and_the_same_file_without_it_parses() {
        let clean = "services:\n  a:\n    image: alpine\n";
        let err = parse("services:\n  a:\n    image: alp\0ine\n")
            .expect_err("a NUL inside a value must be refused");
        assert!(
            err.contains("NUL") && err.contains("U+0000"),
            "the refusal must name the byte: {err}"
        );
        assert_eq!(
            parse(clean)
                .expect("the same file without the NUL must parse")
                .len(),
            1,
            "the check must bar the byte, not the document shape"
        );
    }

    /// A SERVICE MAY NAME A RESOURCE PROFILE THROUGH THE SPEC'S OWN EXTENSION FIELD.
    ///
    /// `x-kern-vcpu`, `x-kern-vdisk` and `x-kern-vgpio` resolve to the `vcpu:`/`vdisk:`/`vgpio:`
    /// tokens `kern box` already takes positionally, so the whole chain downstream - normalisation,
    /// argv, `kern.toml` lookup, `--config` - is the one the TOML spelling has always used.
    ///
    /// WHAT COMPOSE CANNOT SAY, which is the reason to read these at all and was checked field by
    /// field rather than assumed. A `vcpu` profile carries `numa`, `nice`, `backend` and `extends`; a
    /// `vdisk` carries `size`, `persistent`, `backend`, `iops` and `bandwidth`; a `vgpio` carries
    /// nineteen device classes. Compose expresses `cpus`, `cpuset` and `mem_limit`, and nothing else
    /// on that list. An earlier draft of this test asserted that only `vgpio` was read, on the
    /// grounds that `cpus`/`cpuset` were already honoured inline - that was two fields out of seven,
    /// and reading the other five is the difference between repetition and capability.
    ///
    /// ALL THREE OR NONE, and that is a correctness argument rather than tidiness: a surface that
    /// reads one key and silently drops its two obvious siblings teaches the reader a pattern that
    /// then does nothing, which is the same defect as a flag that is accepted and ignored.
    ///
    /// `x-` IS THE SPEC'S EXTENSION MECHANISM, not a private dialect: Docker Compose v2 validates a
    /// file carrying these keys and echoes them back unchanged, measured against 29.6.2, so one file
    /// still runs on both runtimes.
    #[test]
    fn a_service_names_a_resource_profile_through_the_extension_field() {
        for (key, want) in [
            ("x-kern-vcpu", "vcpu:ml"),
            ("x-kern-vdisk", "vdisk:scratch"),
            ("x-kern-vgpio", "vgpio:leds"),
        ] {
            let name = want.split_once(':').map(|(_, n)| n).unwrap_or_default();
            let y = format!("services:\n  app:\n    image: alpine\n    {key}: {name}\n");
            assert_eq!(
                boxes(&y)[0].profile_tokens(),
                vec![want.to_string()],
                "{key} must reach the positional profile token `kern box` already understands"
            );

            // A value that already carries its prefix means the same profile, which is the rule
            // `profile_tokens` documents for the TOML spelling; the YAML door must not differ.
            let y = format!("services:\n  app:\n    image: alpine\n    {key}: {want}\n");
            assert_eq!(boxes(&y)[0].profile_tokens(), vec![want.to_string()]);
        }

        // All three together, in the order the tokens are emitted rather than the order they appear.
        let b = &boxes(
            "services:\n  app:\n    image: alpine\n    x-kern-vgpio: leds\n    x-kern-vcpu: ml\n    x-kern-vdisk: scratch\n",
        )[0];
        assert_eq!(
            b.profile_tokens(),
            vec!["vcpu:ml", "vdisk:scratch", "vgpio:leds"]
        );
        // Reading a new key may not cost the rest of the service.
        assert_eq!(b.image.as_deref(), Some("alpine"));

        // NEGATIVE CONTROL: every OTHER extension field stays out of the profile list, so this is a
        // decision about three keys and not a door opened to the whole `x-` namespace.
        for key in ["x-kern-note", "x-kern-vgpu", "x-anything", "x-kern"] {
            let y = format!("services:\n  app:\n    image: alpine\n    {key}: v\n");
            assert!(
                boxes(&y)[0].profile_tokens().is_empty(),
                "{key} must not become a profile token"
            );
        }

        // `--security-profile` comes through as itself, not as a profile token: it is a bundle of
        // flags, not a `kern.toml` entry, so it must not end up in the positional list.
        let b = &boxes(
            "services:\n  app:\n    image: alpine\n    x-kern-security-profile: untrusted\n",
        )[0];
        assert_eq!(b.security_profile.as_deref(), Some("untrusted"));
        assert!(b.profile_tokens().is_empty());

        // THE KIND LIST IS THE ONE PLACE. `vgpu` is deliberately absent from it, because
        // `classify` does not know a `vgpu:` token in this build and the CLI would answer
        // `unexpected argument` on a token this crate had happily built. When it lands, it is one
        // entry here and one field - and this assertion is what makes that a decision rather than
        // something a future edit does by accident.
        assert_eq!(PROFILE_KINDS, ["vcpu", "vdisk", "vgpio"]);
    }

    /// EVERY PUBLISHED KIND HAS A FIELD, AND THEY ARE DIFFERENT FIELDS.
    ///
    /// `PROFILE_KINDS` says which `x-kern-<kind>` keys are read; `profile_list` says which list each
    /// one fills. Nothing in the type system ties them together, so a kind added to the array with no
    /// arm in that match would parse, resolve to nothing and say nothing - the accepted-and-ignored
    /// defect, arriving through the very mechanism built to prevent it. This is the tie.
    ///
    /// The DISTINCTNESS half matters just as much as the existence half: an arm that returns the
    /// wrong list (`"vdisk" => &self.vcpu`, one word wrong) still resolves for every kind, and would
    /// silently file every `x-kern-vdisk` under `vcpu:`. Filling one list at a time and reading all
    /// three back is what tells those two apart.
    #[test]
    fn every_published_profile_kind_has_its_own_field() {
        for kind in PROFILE_KINDS {
            let y = format!("services:\n  app:\n    image: alpine\n    x-kern-{kind}: only\n");
            assert_eq!(
                boxes(&y)[0].profile_tokens(),
                vec![format!("{kind}:only")],
                "x-kern-{kind} is published but does not reach its own list"
            );
        }
        // And a kind kern does NOT publish must resolve to no list at all, or the door above would
        // open on whatever the match's fallthrough happened to be.
        let mut b = ComposeBox::default();
        for kind in ABSENT_PROFILE_KINDS {
            assert!(
                b.profile_list_mut(kind).is_none(),
                "'{kind}' is not a kind this build has, so it must not resolve to a field"
            );
        }
    }

    /// A TYPO AND A KIND FROM ANOTHER BUILD GET DIFFERENT SENTENCES.
    ///
    /// Both are ignored, so the runtime behaviour is identical and only the words differ - which is
    /// the entire point: telling the author of `x-kern-vgpu` that kern reads `x-kern-vdisk` sends them
    /// hunting for a spelling mistake they did not make, while telling the author of `x-kern-vgpi`
    /// that their key belongs to a build kern does not have here is simply false.
    #[test]
    fn an_unread_extension_key_is_told_which_of_the_two_problems_it_is() {
        let typo = unread_kern_key_note("app", "x-kern-vgpi", "vgpi");
        let absent = unread_kern_key_note("app", "x-kern-vgpu", "vgpu");
        assert_ne!(typo, absent, "one sentence for two different problems");
        assert!(
            typo.contains("x-kern-vdisk") && typo.contains("x-kern-security-profile"),
            "a typo is told what kern does read: {typo}"
        );
        assert!(
            absent.contains("this build") && !absent.contains("x-kern-vdisk"),
            "a real kind kern lacks is told exactly that, and not to check its spelling: {absent}"
        );
        for note in [&typo, &absent] {
            assert!(note.contains("app"), "the service must be named: {note}");
        }
    }

    /// THE CHOMPING INDICATOR DECIDES THE TRAILING BREAKS, and it used to decide nothing.
    ///
    /// `|`, `|-` and `|+` all produced the same value: the parser dropped every trailing blank line
    /// and added nothing back. MEASURED on an `environment` value of `ab` delivered into a running
    /// box, all three arrived as 2 bytes where YAML says 3, 2 and 4. An indicator an author writes on
    /// purpose that changes nothing is the accepted-and-ignored shape, on a character whose only job
    /// is to say what the trailing breaks should be.
    ///
    /// All three in one test, because the bug was that they were indistinguishable: any two of them
    /// agreeing is the failure.
    #[test]
    fn the_chomping_indicator_decides_the_trailing_breaks() {
        let v = |ind: &str, body: &str| -> String {
            boxes(&format!(
                "services:\n  app:\n    image: alpine\n    hostname: {ind}\n{body}"
            ))[0]
                .hostname
                .clone()
                .unwrap_or_default()
        };
        assert_eq!(v("|", "      ab\n"), "ab\n", "clip keeps exactly one break");
        assert_eq!(v("|-", "      ab\n"), "ab", "strip keeps none");
        assert_eq!(
            v("|+", "      ab\n\n"),
            "ab\n\n",
            "keep keeps every break that was there"
        );
        // An empty body gets no trailing break whatever the indicator says: there is no content for a
        // break to follow, and inventing one would make `|+` on nothing produce a newline.
        assert_eq!(
            v("|+", "    command: [true]\n"),
            "",
            "nothing in, nothing out"
        );
    }

    /// A FOLDED SCALAR FOLDS ONLY THE BREAKS IT MAY FOLD.
    ///
    /// In `>` a line break becomes a space only between two lines that are both at the block's own
    /// indentation and both non-empty. A break next to a MORE-INDENTED line is kept, which is how a
    /// shell snippet or a formatted paragraph is embedded in a folded scalar.
    ///
    /// MEASURED before this: every break became a space, so `alp / <2 spaces>ine / fine` came out as
    /// the single line `alp   ine fine`. The service still ran; the text it emitted was a different
    /// text, which is the "runs and lies" shape rather than the "refuses" one.
    ///
    /// `|` is the control: it keeps every break, so a bug that collapsed both would pass a test that
    /// only looked at the folded case.
    #[test]
    fn a_folded_scalar_keeps_the_breaks_around_a_more_indented_line() {
        // The value a consumer sees carries REAL newlines: the sentinel is internal to the fold and
        // `scalar_str` decodes it on the way out. Asserting on the sentinel would pin the encoding
        // rather than the behaviour, and would pass a build that never decoded it.
        let folded_flat = boxes("services:\n  app:\n    image: >\n      alp\n      ine\n")[0]
            .image
            .clone()
            .unwrap_or_default();
        assert_eq!(
            folded_flat, "alp ine\n",
            "two lines at the block indent fold to one space"
        );

        let folded_deep =
            boxes("services:\n  app:\n    image: >\n      alp\n        ine\n      fine\n")[0]
                .image
                .clone()
                .unwrap_or_default();
        assert_eq!(
            folded_deep, "alp\n  ine\nfine\n",
            "a more-indented line keeps the breaks around it, and its own indentation"
        );

        let literal = boxes("services:\n  app:\n    image: |\n      alp\n      ine\n")[0]
            .image
            .clone()
            .unwrap_or_default();
        assert_eq!(
            literal,
            "alp\nine\n",
            "control: a literal block keeps every break, so a fix that collapsed both would fail here"
        );
    }

    /// A KEY WRITTEN TWICE IN ONE SERVICE IS REFUSED, and a MERGED key overridden locally is not.
    ///
    /// The two look identical after a merge is resolved and they are opposites. `image: a` twice is a
    /// file whose author cannot have meant both, and MEASURED before this the second one silently won:
    /// the cheapest way to make a downloaded file run an image other than the one a reader sees at the
    /// top. A local key that also exists in a merged base is the whole point of `<<:`.
    ///
    /// Both halves asserted here, because a check that refused the second case would break every file
    /// that uses a template, and a check that allowed the first is where this started.
    #[test]
    fn a_duplicate_key_is_refused_and_a_merge_override_is_not() {
        let dup = "services:\n  app:\n    image: alpine\n    command: [true]\n    image: adminer\n";
        let err = parse(dup).expect_err("a service with two `image` keys must be refused");
        assert!(
            err.contains("appears twice") && err.contains("image"),
            "the refusal must name the key: {err}"
        );

        // The override, which must NOT read as a duplicate: `command` is written once in the service
        // and once in the base it merges.
        let merged = concat!(
            "x-base: &base\n",
            "  image: alpine\n",
            "  command: [echo, DALBASE]\n",
            "services:\n",
            "  app:\n",
            "    <<: *base\n",
            "    command: [echo, LOCALE]\n",
        );
        let boxes = parse(merged).expect("a merge override is not a duplicate");
        assert_eq!(
            boxes[0].command,
            vec!["echo".to_string(), "LOCALE".to_string()],
            "the local key must win over the merged one"
        );
    }

    /// THE PREFIX IS STRIPPED ONCE.
    ///
    /// `trim_start_matches` strips a prefix REPEATEDLY, so with it `x-kern-x-kern-vcpu` resolved to
    /// the `vcpu` field: a key nobody defined, quietly setting a profile. `strip_prefix` removes one.
    #[test]
    fn a_doubled_extension_prefix_is_not_a_profile_key() {
        let b = &boxes(
            "services:\n  app:\n    image: alpine\n    x-kern-x-kern-vcpu: ml\n    x-kern-vcpu: real\n",
        )[0];
        assert_eq!(
            b.profile_tokens(),
            vec!["vcpu:real"],
            "only the single-prefix key may name a profile"
        );
    }

    fn boxes(y: &str) -> Vec<ComposeBox> {
        parse(y).unwrap()
    }

    #[test]
    fn minimal_services_map_to_boxes() {
        let y = "services:\n  web:\n    image: nginx:alpine\n    command: [\"nginx\", \"-g\", \"daemon off;\"]\n";
        let b = boxes(y);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].name, "web");
        assert_eq!(b[0].image.as_deref(), Some("nginx:alpine"));
        assert_eq!(b[0].command, ["nginx", "-g", "daemon off;"]);
    }

    /// RENAMED FROM `command_shell_form_wraps_in_sh_c`, because the behaviour it pinned was wrong.
    ///
    /// A string `command:` is an ARGV under the Compose Specification, which says the shell-form
    /// syntax "does not implicitly run in the context of the SHELL instruction". The wrapping this
    /// test used to require is what broke Docker's own WordPress sample; the full reasoning and the
    /// measurement are on `a_string_command_is_split_into_an_argv_and_never_wrapped_in_a_shell`.
    #[test]
    fn command_shell_form_is_an_argv_not_a_shell_line() {
        let y = "services:\n  a:\n    image: alpine\n    command: echo hello world\n";
        assert_eq!(boxes(y)[0].command, ["echo", "hello", "world"]);
    }

    #[test]
    fn environment_map_and_list_and_interpolation() {
        std::env::set_var("KERN_TEST_IMPORT_VAR", "resolved");
        let y = "services:\n  a:\n    image: alpine\n    environment:\n      FOO: bar\n      BAZ: ${KERN_TEST_IMPORT_VAR}\n      MISS: ${KERN_TEST_UNSET_XYZ:-fallback}\n";
        let env = &boxes(y)[0].env;
        assert!(env.contains(&"FOO=bar".to_string()));
        assert!(env.contains(&"BAZ=resolved".to_string()));
        assert!(env.contains(&"MISS=fallback".to_string()));
        std::env::remove_var("KERN_TEST_IMPORT_VAR");
    }

    #[test]
    fn unresolvable_var_substitutes_empty_never_literal() {
        // Docker semantics: an unset `${VAR}` with no default → EMPTY string, never a literal `${VAR}`
        // reaching the box (which would make an app fail three levels down with a confusing config).
        let y = "services:\n  a:\n    image: alpine\n    environment:\n      X: ${KERN_DEFINITELY_UNSET_ABC}\n";
        let env = &boxes(y)[0].env;
        assert!(
            !env.iter().any(|e| e.contains("${")),
            "literal ${{}} must never reach the box: {env:?}"
        );
        assert!(
            env.contains(&"X=".to_string()),
            "unresolvable var → empty value: {env:?}"
        );
    }

    #[test]
    fn interpolation_is_document_wide_not_just_env() {
        // The bug the field-test found: `${VAR}` in `ports` (not just environment) must interpolate,
        // like Docker's pre-parse substitution.
        std::env::set_var("KERN_TEST_PORT", "9099");
        let y = "services:\n  a:\n    image: alpine\n    command: [\"true\"]\n    ports:\n      - \"${KERN_TEST_PORT}:80\"\n";
        assert_eq!(boxes(y)[0].ports, ["9099:80"]);
        std::env::remove_var("KERN_TEST_PORT");
    }

    #[test]
    fn depends_on_conditions_route_to_buckets() {
        let y = "services:\n  db:\n    image: postgres\n    healthcheck:\n      test: [\"CMD\", \"pg_isready\"]\n  app:\n    image: alpine\n    depends_on:\n      db:\n        condition: service_healthy\n      migrate:\n        condition: service_completed_successfully\n  migrate:\n    image: alpine\n";
        let app = boxes(y).into_iter().find(|b| b.name == "app").unwrap();
        assert_eq!(app.depends_healthy, ["db"]);
        assert_eq!(app.depends_completed, ["migrate"]);
    }

    #[test]
    fn inline_table_depends_on_routes_conditions() {
        // The copy-pasted one-liner form `depends_on: {x: {condition: ...}}` lands in `scalar`, not
        // `children` - it MUST still route to the right bucket. The bug: it was dropped, so a
        // `service_completed_successfully` gate silently became no-dependency and the dependent
        // started regardless of the init's exit.
        let y = "services:\n  db:\n    image: r\n    healthcheck:\n      test: [\"CMD\",\"redis-cli\",\"ping\"]\n  m:\n    image: a\n  app:\n    image: a\n    depends_on: {db: {condition: service_healthy}, m: {condition: service_completed_successfully}}\n";
        let app = boxes(y).into_iter().find(|b| b.name == "app").unwrap();
        assert_eq!(app.depends_healthy, ["db"]);
        assert_eq!(app.depends_completed, ["m"]);
        assert!(app.depends_on.is_empty());
        // Bare inline `{x: {}}` (no condition) → start-order.
        let y2 = "services:\n  x:\n    image: a\n  app:\n    image: a\n    depends_on: {x: {}}\n";
        let app2 = boxes(y2).into_iter().find(|b| b.name == "app").unwrap();
        assert_eq!(app2.depends_on, ["x"]);
    }

    #[test]
    fn entrypoint_and_command_compose_order_independent() {
        // THE TWO ARE NO LONGER MERGED, and the expected outcome changed with that.
        //
        // They used to be concatenated into `command`, which the box then prepended the IMAGE's own
        // entrypoint to: `IMAGE_ENTRYPOINT ++ entrypoint ++ command`, correct only for an image
        // that has no entrypoint. `entrypoint:` is forwarded as `--entrypoint` now, so it REPLACES
        // the image's, and `command` stays its argument list.
        //
        // What this case guarded is unchanged and still guarded: the assignment must happen AFTER
        // the whole service is parsed, or a later `command:` key overwrites what the earlier
        // `entrypoint:` key set. Both key orders are asserted for exactly that.
        let ep_first = "services:\n  a:\n    image: alpine\n    entrypoint: [\"echo\", \"P\"]\n    command: [\"x\", \"y\"]\n";
        let cmd_first = "services:\n  a:\n    image: alpine\n    command: [\"x\", \"y\"]\n    entrypoint: [\"echo\", \"P\"]\n";
        for y in [ep_first, cmd_first] {
            let b = &boxes(y)[0];
            assert_eq!(
                b.entrypoint.as_deref(),
                Some(&["echo".to_string(), "P".to_string()][..]),
                "for:\n{y}"
            );
            assert_eq!(b.command, ["x", "y"], "for:\n{y}");
        }
    }

    /// REWRITTEN, because the rule it pinned was a DOCKERFILE rule and Compose says it does not
    /// apply. `ENTRYPOINT some string` in a Dockerfile becomes `/bin/sh -c "…"`, which has nowhere to
    /// put arguments, so `CMD` is dropped there. The Compose Specification says its own string form
    /// does NOT run in a shell, so a string entrypoint is an argv and `command` appends to it exactly
    /// as it does for a list. kern used to clear the command and warn, silently discarding arguments
    /// the file asked for. See `a_string_entrypoint_keeps_the_command_and_appends_to_it`.
    #[test]
    fn a_string_entrypoint_is_an_argv_and_keeps_its_command() {
        let y = "services:\n  a:\n    image: x\n    entrypoint: /init here\n    command: run now\n";
        let b = &boxes(y)[0];
        assert_eq!(
            b.entrypoint.as_deref(),
            Some(&["/init".to_string(), "here".to_string()][..])
        );
        assert_eq!(
            b.command,
            ["run", "now"],
            "`command` appends to a string entrypoint, as it does to a list one"
        );
        // EXEC-form (list): the entrypoint overrides and `command` remains its arguments.
        let y2 = "services:\n  a:\n    image: x\n    entrypoint: [\"/bin/entry\"]\n    command: [\"arg1\"]\n";
        let b2 = &boxes(y2)[0];
        assert_eq!(
            b2.entrypoint.as_deref(),
            Some(&["/bin/entry".to_string()][..])
        );
        assert_eq!(b2.command, ["arg1"]);
        // A string entrypoint with no command: still an argv, and still no shell.
        let y3 = "services:\n  a:\n    image: x\n    entrypoint: /init here\n";
        assert_eq!(
            boxes(y3)[0].entrypoint.as_deref(),
            Some(&["/init".to_string(), "here".to_string()][..]),
            "a string entrypoint is tokenised, never handed to a shell"
        );
    }

    #[test]
    fn interpolation_nested_resolves_like_docker() {
        std::env::remove_var("KERN_NX_A");
        std::env::remove_var("KERN_NX_B");
        // Nested default `${A:-${B:-c}}` resolves the inner first, then the outer (Docker parity).
        assert_eq!(
            interpolate_document(
                "x=${KERN_NX_A:-${KERN_NX_B:-deep}}",
                &crate::DotEnv::default()
            ),
            "x=deep"
        );
        // `${A${B}}`: the inner `${B}` resolves (unset -> empty), leaving `${A}` -> empty. No stray `}`
        // leaks (the balanced-brace scan closes at the OUTER `}`).
        // `${A${B}}`: the inner `${B}` resolves (unset -> empty), leaving `${A}` -> empty. The
        // result carries `UNSET_MARK`, the private character that records "a reference resolved to
        // nothing" so a valueless key can be told from a value that vanished; `scalar_str` erases it
        // before anything reads the value.
        assert_eq!(
            interpolate_document("x=${A${B}}", &crate::DotEnv::default()),
            format!("x={UNSET_MARK}")
        );
        assert_eq!(
            scalar_str(&interpolate_document("${A${B}}", &crate::DotEnv::default())),
            "",
            "the mark never survives into a value"
        );
        // A normal `${VAR:-def}` still works.
        assert_eq!(
            interpolate_document("x=${UNSET_XYZ_KERN:-def}", &crate::DotEnv::default()),
            "x=def"
        );
        // Adversarial deep nesting terminates (depth cap), never hangs.
        let deep = "${".repeat(100) + "X" + &"}".repeat(100);
        let _ = interpolate_document(&deep, &crate::DotEnv::default());
    }

    #[test]
    fn interpolation_full_modifier_set_matches_docker() {
        // Docker's modifier set (found missing by an extreme vs-Docker test): `:-`/`-` default,
        // `:+`/`+` replacement, `:?`/`?` required, with the `:` meaning "treat empty like unset".
        // Use process-unique var names so the test is deterministic regardless of the ambient env.
        std::env::set_var("KERN_T_SET", "val");
        std::env::set_var("KERN_T_EMPTY", "");
        std::env::remove_var("KERN_T_UNSET");
        let i = |e: &str| interpolate_expr(e, &crate::DotEnv::default());
        // default `:-` : applies on unset OR empty
        assert_eq!(i("KERN_T_SET:-def"), "val");
        assert_eq!(i("KERN_T_EMPTY:-def"), "def"); // empty → default (the `:` rule)
        assert_eq!(i("KERN_T_UNSET:-def"), "def");
        // default `-` : applies only on unset (empty is kept)
        assert_eq!(i("KERN_T_EMPTY-def"), ""); // empty is "set" → kept
        assert_eq!(i("KERN_T_UNSET-def"), "def");
        // replace `:+` : replaces when set AND non-empty
        assert_eq!(i("KERN_T_SET:+rep"), "rep");
        assert_eq!(i("KERN_T_EMPTY:+rep"), ""); // empty → not replaced
        assert_eq!(i("KERN_T_UNSET:+rep"), "");
        // replace `+` : replaces when set (even empty)
        assert_eq!(i("KERN_T_EMPTY+rep"), "rep");
        assert_eq!(i("KERN_T_UNSET+rep"), "");
        // required `:?` : value if present, else empty (+warning)
        assert_eq!(i("KERN_T_SET:?needed"), "val");
        assert_eq!(i("KERN_T_UNSET:?needed"), "");
        // plain `${VAR}` unchanged
        assert_eq!(i("KERN_T_SET"), "val");
        std::env::remove_var("KERN_T_SET");
        std::env::remove_var("KERN_T_EMPTY");
    }

    #[test]
    fn interpolation_skips_comments() {
        // Audit regression: a `${VAR}` inside a trailing comment must not be interpolated (no spurious
        // unset-var warning, comment text left verbatim). The value part is still interpolated.
        assert_eq!(
            interpolate_document(
                "image: x  # see ${SOME_UNSET_XYZ}",
                &crate::DotEnv::default()
            ),
            "image: x  # see ${SOME_UNSET_XYZ}"
        );
        assert_eq!(
            interpolate_document(
                "cmd: ${UNSET_XYZ_KERN:-run}  # ${ALSO_UNSET}",
                &crate::DotEnv::default()
            ),
            "cmd: run  # ${ALSO_UNSET}"
        );
        // A `#` inside quotes is NOT a comment - interpolation applies across it.
        assert_eq!(
            interpolate_document("v: \"${UNSET_XYZ_KERN:-a#b}\"", &crate::DotEnv::default()),
            "v: \"a#b\""
        );
    }

    #[test]
    fn compose_secrets_map_to_run_secrets() {
        // A service `secrets: [s]` + top-level `secrets: {s: {file: ./f}}` → `--secret ./f:s`.
        let y = "services:\n  a:\n    image: alpine\n    secrets: [\"s\"]\nsecrets:\n  s:\n    file: ./mysecret.txt\n";
        assert_eq!(boxes(y)[0].secrets, ["./mysecret.txt:s"]);
        // A referenced secret with no top-level `file:` def → skipped (warned), not a bogus entry.
        let y2 = "services:\n  a:\n    image: alpine\n    secrets: [\"ghost\"]\n";
        assert!(boxes(y2)[0].secrets.is_empty());
    }

    #[test]
    fn duplicate_service_key_is_rejected() {
        // Two service blocks with the same name is an authoring mistake - reject, don't launch two
        // boxes with a colliding name (opaque "already running" later) or silently shadow.
        let y = "services:\n  a:\n    image: alpine\n  a:\n    image: nginx\n";
        let err = match parse(y) {
            Err(e) => e,
            Ok(_) => panic!("expected duplicate-service error"),
        };
        assert!(err.contains("duplicate service"), "got: {err}");
    }

    #[test]
    fn inline_table_environment_and_healthcheck_parse() {
        // Systemic inline-table fix: `environment: {K: v}` and `healthcheck: {test: […]}` in the
        // one-liner form must parse (they used to sit unparsed in `scalar` and get dropped).
        let y = "services:\n  a:\n    image: alpine\n    environment: {FOO: bar, BAZ: qux}\n    healthcheck: {test: [\"CMD\", \"true\"], interval: 2s, retries: 3}\n";
        let b = &boxes(y)[0];
        assert!(b.env.contains(&"FOO=bar".to_string()));
        assert!(b.env.contains(&"BAZ=qux".to_string()));
        // `["CMD", "true"]` is the EXEC form: an argv, not a shell string.
        assert_eq!(b.health_argv, vec!["true".to_string()]);
        assert_eq!(b.health_cmd, None);
        assert_eq!(b.health_interval, Some(2));
    }

    #[test]
    fn kern_toml_health_keys_in_yaml_are_ignored_not_applied() {
        // A user who copies kern's TOML spelling (`health_cmd:` / `depends_healthy:`) into a
        // docker-compose.yml gets a GUIDED warning pointing at the docker equivalent - and, critically,
        // the key stays IGNORED, not applied: the box gets no health gate or ordering edge from it (the
        // docker spellings `healthcheck:` / `depends_on: {condition: service_healthy}` are the supported
        // ones). Locks that the guidance arm never starts honoring the TOML key on the YAML path.
        let y = concat!(
            "services:\n",
            "  cache:\n",
            "    image: alpine\n",
            "    health_cmd: \"true\"\n",
            "    health_interval: 2\n",
            "  web:\n",
            "    image: alpine\n",
            "    depends_healthy: [\"cache\"]\n",
            "    depends_completed: [\"cache\"]\n",
        );
        let bs = boxes(y);
        let cache = bs.iter().find(|b| b.name == "cache").expect("cache box");
        let web = bs.iter().find(|b| b.name == "web").expect("web box");
        // The kern-TOML health keys did NOT populate the box (docker `healthcheck:` is the way in YAML):
        assert_eq!(cache.health_cmd, None);
        assert_eq!(cache.health_interval, None);
        // The kern-TOML dependency conditions created NO ordering/health edge:
        assert!(web.depends_healthy.is_empty());
        assert!(web.depends_completed.is_empty());
    }

    #[test]
    fn healthcheck_durations_convert_to_bare_seconds() {
        // Extreme-test regression: `--health-timeout`/`--health-start-period` are integer SECONDS in
        // the CLI, but Docker writes them as durations (`30s`, `1m`, `0s`). Passing the raw `"30s"`
        // aborted the box ("usage: --health-start-period <seconds>"). They must convert like `interval`.
        let y = "services:\n  a:\n    image: x\n    healthcheck:\n      test: t\n      interval: 2s\n      timeout: 30s\n      start_period: 1m30s\n      retries: 4\n";
        let b = &boxes(y)[0];
        assert_eq!(b.health_interval, Some(2));
        assert_eq!(b.health_timeout.as_deref(), Some("30")); // 30s → "30", not "30s"
        assert_eq!(b.health_start_period.as_deref(), Some("90")); // 1m30s → 90
        assert_eq!(b.health_retries.as_deref(), Some("4")); // a plain count, unchanged
                                                            // `start_period` 0 (no grace) is legitimate and must reach the box as `0`, not be dropped -
                                                            // for EVERY zero spelling, not just `0s` (the old literal whitelist dropped `0m`/`0h`).
        for zero in ["0s", "0m", "0h", "0", "0h0m0s"] {
            let y0 = format!("services:\n  a:\n    image: x\n    healthcheck:\n      test: t\n      start_period: {zero}\n");
            assert_eq!(
                boxes(&y0)[0].health_start_period.as_deref(),
                Some("0"),
                "start_period: {zero}"
            );
        }
        // interval/timeout keep the opposite policy: a zero duration is "unset -> default" (dropped).
        let yt =
            "services:\n  a:\n    image: x\n    healthcheck:\n      test: t\n      timeout: 0m\n";
        assert_eq!(boxes(yt)[0].health_timeout, None);
    }

    #[test]
    fn env_value_with_braces_is_not_over_parsed() {
        // The DUAL of the inline-table fix (review P1): a `{`-containing value in `environment` (a JSON
        // config, very common) must stay a verbatim STRING, not be structured into a table (which made
        // the env var come out empty). Both quoted and raw forms keep the value.
        let y = "services:\n  a:\n    image: alpine\n    environment:\n      CFG: {key: val}\n      JSON: \"{\\\"k\\\":\\\"v\\\"}\"\n";
        let env = &boxes(y)[0].env;
        assert!(
            env.iter()
                .any(|e| e.starts_with("CFG=") && e.contains("key")),
            "CFG lost: {env:?}"
        );
        assert!(
            env.iter()
                .any(|e| e.starts_with("JSON=") && e.contains("k")),
            "JSON lost: {env:?}"
        );
        // And the structural inline forms STILL parse (depends/healthcheck read children).
        let y2 = "services:\n  db:\n    image: r\n    healthcheck:\n      test: [\"CMD\",\"true\"]\n  app:\n    image: a\n    depends_on: {db: {condition: service_healthy}}\n";
        let app = boxes(y2).into_iter().find(|b| b.name == "app").unwrap();
        assert_eq!(app.depends_healthy, ["db"]);
    }

    #[test]
    fn env_list_form_host_passthrough() {
        // Extreme vs-Docker regression: a list-form env with a bare `- KEY` (no `=`) is Docker's host
        // pass-through. Passing the bare `KEY` to `--env K=V` aborted the whole box. Now: present in
        // the host → `KEY=<value>`; absent → omitted (never a malformed `--env`).
        std::env::set_var("KERN_T_PASS", "host_val");
        std::env::remove_var("KERN_T_ABSENT");
        let y = "services:\n  a:\n    image: x\n    environment:\n      - PLAIN=v\n      - EQ=a=b=c\n      - KERN_T_PASS\n      - KERN_T_ABSENT\n";
        let env = &boxes(y)[0].env;
        assert!(env.contains(&"PLAIN=v".to_string()), "{env:?}");
        assert!(env.contains(&"EQ=a=b=c".to_string()), "{env:?}"); // only the FIRST `=` splits K/V
        assert!(env.contains(&"KERN_T_PASS=host_val".to_string()), "{env:?}");
        assert!(
            !env.iter().any(|e| e.starts_with("KERN_T_ABSENT")),
            "absent passthrough must be omitted, not a bare/malformed entry: {env:?}"
        );
        std::env::remove_var("KERN_T_PASS");
    }

    #[test]
    fn volume_long_form_reconstructs_to_src_dst() {
        // Extreme vs-Docker regression: a long-form volume (`{type,source,target,read_only}`) was
        // passed to the box's `-v` verbatim as `{…}`, which was rejected → the whole service failed.
        // Now reconstructed to `source:target[:ro]`.
        let y = "services:\n  a:\n    image: x\n    volumes:\n      - type: bind\n        source: ./data\n        target: /data\n        read_only: true\n";
        assert_eq!(boxes(y)[0].volumes, ["./data:/data:ro"]);
        // Without read_only → no :ro suffix.
        let y2 = "services:\n  a:\n    image: x\n    volumes:\n      - type: volume\n        source: myvol\n        target: /store\n";
        assert_eq!(boxes(y2)[0].volumes, ["myvol:/store"]);
        // Short form still passes through untouched.
        let y3 = "services:\n  a:\n    image: x\n    volumes:\n      - ./h:/c:ro\n";
        assert_eq!(boxes(y3)[0].volumes, ["./h:/c:ro"]);
        // A long-form with no source (anonymous/tmpfs) is dropped, not forwarded as a bad `-v`.
        let y4 =
            "services:\n  a:\n    image: x\n    volumes:\n      - {type: tmpfs, target: /tmp}\n";
        assert!(boxes(y4)[0].volumes.is_empty());
    }

    /// `tmpfs:` entries reach the box VERBATIM, and that is the contract now.
    ///
    /// This test used to assert the opposite: that this layer rewrote Docker's option list into
    /// kern's `PATH:size` spelling. That rewriting is gone, and its removal is the fix. It decided
    /// which of the two grammars it was holding by asking whether the suffix contained an `=` at
    /// all, so a list with none in it (`/run:rw`, `/run:exec`, `/run:noexec,nosuid`, every one of
    /// them valid Docker) was forwarded as a SIZE and the service died with "bad size 'rw'". The
    /// same guess made `kern box --tmpfs /run:size=64m` fail while the identical compose entry
    /// worked, which is one binary disagreeing with itself.
    ///
    /// `parse_tmpfs` in kern-cli parses the option list, once, for both. The only thing left to
    /// assert here is that nothing is touched on the way, because anything this layer "helpfully"
    /// normalises is a second grammar growing back.
    #[test]
    fn tmpfs_entries_are_forwarded_verbatim() {
        let t = |y: &str| boxes(y)[0].tmpfs.clone();
        for entry in [
            "/scratch:size=10M,mode=1770,uid=1000",
            "/run",
            "/t:64m",
            "/t:mode=1777",
            "/run:rw,noexec,nosuid,size=64m",
            "/run:exec",
            "/run:ro",
        ] {
            let y = format!("services:\n  a:\n    image: x\n    tmpfs:\n      - {entry}\n");
            assert_eq!(
                t(&y),
                [entry],
                "tmpfs entries must reach --tmpfs unmodified; rewriting one here recreates the \
                 second grammar this removed"
            );
        }
        // The scalar (non-list) spelling reaches it the same way.
        assert_eq!(
            t("services:\n  a:\n    image: x\n    tmpfs: /run\n"),
            ["/run"]
        );
    }

    #[test]
    fn warn_sanitizes_terminal_control_chars() {
        // Hacker-mode regression: a hostile compose key/value must not inject ANSI escapes into a
        // warning. ESC, CR, and other control chars are neutralized to `\xNN`; printable text passes.
        assert_eq!(sanitize_for_terminal("evil\x1b[31mKEY"), "evil\\x1b[31mKEY");
        assert_eq!(sanitize_for_terminal("a\rb\nc"), "a\\x0db\\x0ac");
        assert_eq!(
            sanitize_for_terminal("normal service 'x': ok"),
            "normal service 'x': ok"
        );
        // A unicode value passes through (only CONTROL chars are escaped, not multibyte text).
        assert_eq!(sanitize_for_terminal("café→🦀"), "café→🦀");
    }

    /// TWO ALARMING WARNINGS FOR A STACK THAT HAD NOTHING WRONG WITH IT.
    ///
    /// `stdin_open:` and `tty:` both produced "ignored (unsupported)", matched on the KEY, so
    /// `tty: false` warned about nothing and a working daemon was told a feature was missing.
    /// Reported as getkern#7 against a service that, measured, serves HTTP 200 and stays up with
    /// both keys ignored.
    #[test]
    fn tty_is_silent_and_stdin_open_speaks_only_when_it_is_true() {
        // Both keys parse, in both boolean spellings, and neither breaks the service.
        for v in ["true", "false", "yes", "no"] {
            let y = format!("services:\n  s:\n    image: x\n    tty: {v}\n    stdin_open: {v}\n");
            let boxes = parse(&y).unwrap_or_else(|e| panic!("tty/stdin_open {v} broke parse: {e}"));
            assert_eq!(boxes.len(), 1, "the service must survive {v}");
            assert_eq!(boxes[0].name, "s");
        }

        // The note names the service in both places, and offers a command rather than a verdict.
        let n = stdin_open_note("paseo");
        assert!(
            n.contains("'paseo'") && n.contains("kern exec -it paseo"),
            "{n}"
        );
        assert!(n.contains("EOF"), "it must say what actually differs: {n}");
        // AND IT ANSWERS THE KEY THE READER WROTE. The first version's only remedy was `exec -it`,
        // which answers `tty:`, so somebody who wrote `stdin_open: true` alone was handed a PTY
        // they had not asked for and nothing at all about stdin. A program that needs input needs
        // another way in, and that is the sentence this asserts exists.
        assert!(
            n.contains("as a file, an argument, or an environment variable"),
            "the stdin half needs its own remedy, not the tty one: {n}"
        );
        // NOT "unsupported": nothing is missing, the behaviour is different and that is the point.
        assert!(!n.contains("unsupported"), "{n}");
        assert!(!n.contains("ignored"), "{n}");
        // It is per-service, which a fixed sentence could not be.
        assert_ne!(stdin_open_note("a"), stdin_open_note("b"));

        // `tty` HAS NO NOTE TO GET WRONG: the arm is empty on purpose, so there is no `tty_note`
        // to assert against here. Nor does the loop above prove silence, only that parsing
        // survives: `warn` writes to stderr, which a unit test in this crate cannot capture. The
        // silence is asserted where stderr is readable, in `scripts/acceptance-matrix.sh`.
    }

    #[test]
    fn profiled_service_is_inactive_unless_enabled() {
        // Extreme vs-Docker regression: a `profiles:`-tagged service was warn-and-ignored but STILL
        // STARTED - a service that should be OFF ran. Now it is dropped from the run unless one of its
        // profiles is active via COMPOSE_PROFILES (Docker semantics: a plain `up` = profile-less only).
        let y = "services:\n  always:\n    image: x\n  dbg:\n    image: x\n    profiles: [debug]\n";
        // Ensure no ambient profile leaks in.
        std::env::remove_var("COMPOSE_PROFILES");
        let names: Vec<String> = parse(y).unwrap().into_iter().map(|b| b.name).collect();
        assert_eq!(names, ["always"], "profiled 'dbg' must be dropped");
        // Enable it.
        std::env::set_var("COMPOSE_PROFILES", "debug");
        let names2: Vec<String> = parse(y).unwrap().into_iter().map(|b| b.name).collect();
        assert!(
            names2.contains(&"dbg".to_string()),
            "profile active → dbg present"
        );
        // A depends_on toward a dropped profiled service must NOT fail the topo - the edge is pruned.
        std::env::remove_var("COMPOSE_PROFILES");
        let y2 = "services:\n  app:\n    image: x\n    depends_on: [dbg]\n  dbg:\n    image: x\n    profiles: [debug]\n";
        let parsed = parse(y2).expect("dangling profiled dependency must be pruned, not error");
        let app = parsed.iter().find(|b| b.name == "app").unwrap();
        assert!(app.depends_on.is_empty(), "edge to dropped 'dbg' pruned");
        std::env::remove_var("COMPOSE_PROFILES");
    }

    #[test]
    fn partial_stack_failure_honors_depends_chain() {
        // Review P3 (the untested angle): a failed service must not start its dependents, but the
        // parser-level guarantee is that the dependency edge exists. (Runtime behaviour - independent
        // services start, dependents don't - is verified live; here we assert the edge is recorded so
        // `validate`/`wait` can enforce it.)
        let y = "services:\n  bad:\n    image: a\n    command: [\"false\"]\n  dep:\n    image: a\n    depends_on: {bad: {condition: service_completed_successfully}}\n";
        let dep = boxes(y).into_iter().find(|b| b.name == "dep").unwrap();
        assert_eq!(dep.depends_completed, ["bad"]);
    }

    #[test]
    fn healthcheck_cmd_exec_vs_shell_vs_bare() {
        // THE EXEC FORM STAYS AN ARGV. It used to be joined into "pg_isready -U app" and run through
        // `/bin/sh -c`, which is a check no shell-less image can ever pass - and `CMD` is the form
        // such an image writes. Measured on Supabase: PostgREST answers `postgrest --ready` every
        // time through `kern exec`, and reported `unhealthy` for as long as the wrapper was there.
        let y = "services:\n  a:\n    image: alpine\n    healthcheck:\n      test: [\"CMD\", \"pg_isready\", \"-U\", \"app\"]\n";
        let b = &boxes(y)[0];
        assert_eq!(b.health_argv, ["pg_isready", "-U", "app"]);
        assert_eq!(b.health_cmd, None, "the exec form is not a shell string");
        // An argument WITH A SPACE keeps its boundary; joining made it two arguments.
        let ys = "services:\n  a:\n    image: alpine\n    healthcheck:\n      test: [\"CMD\", \"probe\", \"a b\"]\n";
        assert_eq!(boxes(ys)[0].health_argv, ["probe", "a b"]);
        let y2 = "services:\n  a:\n    image: alpine\n    healthcheck:\n      test: [\"CMD-SHELL\", \"pg_isready || exit 1\"]\n";
        assert_eq!(
            boxes(y2)[0].health_cmd.as_deref(),
            Some("pg_isready || exit 1")
        );
        assert!(
            boxes(y2)[0].health_argv.is_empty(),
            "the shell form is not an argv"
        );
        let y3 =
            "services:\n  a:\n    image: alpine\n    healthcheck:\n      test: curl -f localhost\n";
        // bare string = implicit CMD-SHELL → verbatim, NEVER split on spaces
        assert_eq!(
            boxes(y3)[0].health_cmd.as_deref(),
            Some("curl -f localhost")
        );
    }

    #[test]
    fn healthcheck_test_reads_present_representation_not_expected() {
        // Review P1 "third state": `healthcheck.test` is SOMETIMES a string (CMD-SHELL) and SOMETIMES a
        // list (exec). With the dual scalar+children representation, the converter must read whichever
        // is PRESENT for the value's form, not blindly the same one - else the block/inline × list/bare
        // matrix drops or mis-parses a cell. All four cells must resolve to the same command.
        //
        // The command is the same in all four; the FORM is not, and both halves are asserted: a
        // list cell must land in `health_argv` (exec, no shell) and a string cell in `health_cmd`.
        let cases = [
            // (yaml, argv, shell)
            ("services:\n  a:\n    image: r\n    healthcheck:\n      test: [\"CMD\",\"redis-cli\",\"ping\"]\n", true), // block list
            ("services:\n  a:\n    image: r\n    healthcheck: {test: [\"CMD\",\"redis-cli\",\"ping\"]}\n", true), // inline list
            ("services:\n  a:\n    image: r\n    healthcheck:\n      test: \"redis-cli ping\"\n", false), // block bare-string
            ("services:\n  a:\n    image: r\n    healthcheck: {test: \"redis-cli ping\"}\n", false), // inline bare-string
        ];
        for (y, exec) in cases {
            let b = &boxes(y)[0];
            if exec {
                assert_eq!(b.health_argv, ["redis-cli", "ping"], "for:\n{y}");
                assert_eq!(b.health_cmd, None, "for:\n{y}");
            } else {
                assert_eq!(b.health_cmd.as_deref(), Some("redis-cli ping"), "for:\n{y}");
                assert!(b.health_argv.is_empty(), "for:\n{y}");
            }
            // Whichever form, the box HAS a check: this is the question every `service_healthy`
            // gate asks, and answering it from `health_cmd` alone degraded a real gate.
            assert!(b.has_health(), "for:\n{y}");
        }
    }

    /// A COMMA INSIDE AN ESCAPED QUOTE MUST NOT SPLIT, and it did.
    ///
    /// The scanner tracked quotes and not escapes, so `\"` read as the closing quote and the next
    /// comma cut the value in half. The cases below are the shapes that reach it from a real file.
    #[test]
    fn a_comma_inside_a_quoted_scalar_never_splits_it() {
        // The exact defect: an escaped quote, then a comma.
        assert_eq!(
            split_top_commas(r#""CMD-SHELL", "echo \"hi, there\"""#),
            vec![r#""CMD-SHELL""#, r#" "echo \"hi, there\"""#]
        );
        // An ODD number of escaped quotes was the case that broke; an even number used to
        // self-correct, which is why this went unnoticed for so long. Both must hold.
        assert_eq!(
            split_top_commas(r#""a", "x \" y, z""#),
            vec![r#""a""#, r#" "x \" y, z""#]
        );
        assert_eq!(
            split_top_commas(r#""a", "x \" y \" z, w""#),
            vec![r#""a""#, r#" "x \" y \" z, w""#]
        );
        // `\\` is a literal backslash, so the `"` after it DOES close the scalar and the comma
        // after that DOES split. Getting this wrong in the other direction merges two items.
        assert_eq!(
            split_top_commas(r#""a\\", "b""#),
            vec![r#""a\\""#, r#" "b""#]
        );
        // A plain comma inside quotes, no escapes involved.
        assert_eq!(
            split_top_commas(r#""a,b", "c""#),
            vec![r#""a,b""#, r#" "c""#]
        );
    }

    /// SINGLE QUOTES TAKE NO BACKSLASH ESCAPE, and treating them like double quotes would be a
    /// second defect wearing the first one's clothes.
    ///
    /// YAML 1.2 gives `'…'` exactly one escape, `''`, meaning a literal quote. A backslash inside is
    /// an ordinary character, so a Windows path ending in one must not swallow the closing quote.
    #[test]
    fn single_quotes_follow_yamls_rule_and_not_the_double_quoted_one() {
        // `''` is a literal quote and does NOT close: the comma stays inside.
        assert_eq!(
            split_top_commas("'a''b, c', 'd'"),
            vec!["'a''b, c'", " 'd'"]
        );
        // A backslash is ORDINARY here. If it were treated as an escape, the closing quote would be
        // consumed and the following comma would stop splitting.
        assert_eq!(
            split_top_commas(r"'C:\path\', 'next'"),
            vec![r"'C:\path\'", " 'next'"]
        );
        // And a double quote inside single quotes is just a character.
        assert_eq!(
            split_top_commas(r#"'say "hi, x"', 'b'"#),
            vec![r#"'say "hi, x"'"#, " 'b'"]
        );
    }

    /// THE SCANNER MUST NOT PANIC OR RUN PAST THE END ON MALFORMED INPUT.
    ///
    /// A compose file is third-party text. Every shape here is one a hostile or merely broken file
    /// can contain, and none of them may abort the parse or lose the rest of the line.
    #[test]
    fn the_scanner_is_total_on_malformed_input() {
        // A trailing lone backslash inside a string: the escape has nothing to consume.
        assert_eq!(split_top_commas(r#""a\"#), vec![r#""a\"#]);
        assert_eq!(split_top_commas(r#""a", "b\"#), vec![r#""a""#, r#" "b\"#]);
        // An unterminated string swallows the rest, which is what a quote means.
        assert_eq!(split_top_commas(r#""a, b"#), vec![r#""a, b"#]);
        assert_eq!(split_top_commas("'a, b"), vec!["'a, b"]);
        // AN UNMATCHED CLOSER MUST NOT POISON THE REST OF THE LINE. Without the clamp the depth
        // goes negative and every later comma stops splitting: one stray character silently
        // swallowing everything after it.
        assert_eq!(split_top_commas("a], b, c"), vec!["a]", " b", " c"]);
        assert_eq!(split_top_commas("a}, b"), vec!["a}", " b"]);
        // Nesting still suppresses splitting at depth.
        assert_eq!(split_top_commas("a, [b, c], d"), vec!["a", " [b, c]", " d"]);
        assert_eq!(
            split_top_commas("{k: 1, j: 2}, x"),
            vec!["{k: 1, j: 2}", " x"]
        );
        // Degenerate inputs.
        assert_eq!(split_top_commas(""), vec![""]);
        assert_eq!(split_top_commas(","), vec!["", ""]);
        assert_eq!(split_top_commas("a,"), vec!["a", ""]);
        // Multi-byte characters on both sides of a separator: the byte offsets must land on
        // character boundaries or the slicing panics.
        assert_eq!(split_top_commas("caffè, però"), vec!["caffè", " però"]);
        assert_eq!(
            split_top_commas(r#""caffè \" x, y", "però""#),
            vec![r#""caffè \" x, y""#, r#" "però""#]
        );
    }

    /// A DETERMINISTIC SWEEP WHOSE GROUND TRUTH COMES FROM CONSTRUCTION.
    ///
    /// `split_top_commas` is a hand-written parser over a format with quotes and escapes, and the
    /// defect it shipped with - `\"` read as a closing quote - is the same family as a size parser
    /// accepting a value it then mis-reads: output that does not correspond to input. The cases
    /// above cover the shapes somebody thought of; this covers the combinations nobody did.
    ///
    /// ## The property this does NOT use, and why
    ///
    /// The first version of this asserted that the pieces rejoined with commas reproduce the input.
    /// It passed. It also passed with the depth counter removed, with the escape handling removed,
    /// and with the scanner advancing by one byte instead of one character - THREE injected defects,
    /// three greens. The property is a tautology for a comma splitter: rejoining with commas
    /// rebuilds the input wherever you split, so it constrains nothing about the decision being
    /// made. A sweep of 2801 inputs that cannot fail is worth less than one case that can.
    ///
    /// ## What replaces it
    ///
    /// The inputs are BUILT from atoms whose answer is known by construction: each atom is a string
    /// that contains no top-level comma, so joining N of them with commas must return exactly those
    /// N atoms. No oracle to write, nothing circular, and the assertion is about WHICH commas split
    /// rather than about the bytes surviving. Every atom below carries the feature that decides the
    /// scanner's state, and a comma hidden behind it.
    #[test]
    fn only_top_level_commas_split_over_every_combination_of_atoms() {
        // Each atom contains a comma that must NOT split, behind a different mechanism.
        const ATOMS: &[&str] = &[
            "\"a,b\"",        // a comma inside double quotes
            "'c,d'",          // a comma inside single quotes
            "[1, 2]",         // a comma inside brackets
            "{k: 1, j: 2}",   // a comma inside braces
            r#""x\", y""#,    // a comma after an ESCAPED quote: the defect that shipped
            "'p''q, r'",      // a comma after `''`, the only escape single quotes have
            r"'C:\path\, x'", // a backslash inside single quotes is ORDINARY, not an escape
            "plain",          // no mechanism at all
            "caffè, però",    // multi-byte on both sides of a comma... which DOES split
        ];
        // The last atom is the exception and is handled apart: it has a top-level comma on purpose,
        // to prove the sweep is not simply refusing to split anything.
        let safe = &ATOMS[..ATOMS.len() - 1];

        let mut checked = 0usize;
        for len in 1..=3usize {
            let total = safe.len().pow(len as u32);
            for n in 0..total {
                let mut chosen: Vec<&str> = Vec::with_capacity(len);
                let mut rest = n;
                for _ in 0..len {
                    chosen.push(safe[rest % safe.len()]);
                    rest /= safe.len();
                }
                let input = chosen.join(",");
                let got = split_top_commas(&input);
                assert_eq!(
                    got, chosen,
                    "input {input:?} split at a comma that is not top-level"
                );
                checked += 1;
            }
        }
        assert_eq!(
            checked,
            8 + 64 + 512,
            "the sweep did not cover what it claims to: a sweep that shrinks silently stops finding things"
        );

        // THE CONTROL IN THE OTHER DIRECTION. Without this the whole case would pass against a
        // scanner that never splits at all, which is the mirror of the tautology it replaced.
        assert_eq!(split_top_commas("caffè, però"), vec!["caffè", " però"]);
        assert_eq!(split_top_commas("a,b,c"), vec!["a", "b", "c"]);
        assert_eq!(
            split_top_commas(r#""a,b",plain,[1, 2]"#),
            vec!["\"a,b\"", "plain", "[1, 2]"]
        );
    }

    /// THE DEFECT AS A USER MEETS IT: through `healthcheck.test`.
    ///
    /// `CMD-SHELL` takes `rest.first()`, so a split in the wrong place hands the health-checker a
    /// FRAGMENT. The service then reads `unhealthy` forever while answering correctly, and
    /// `depends_on: condition: service_healthy` never opens. This asserts the whole command
    /// survives, which is the property that matters rather than the splitting itself.
    #[test]
    fn a_healthcheck_command_survives_its_own_quoting() {
        let cases = [
            (
                "services:\n  a:\n    image: r\n    healthcheck:\n      test: [\"CMD-SHELL\", \"sh -c \\\"echo hi, there\\\" >/dev/null; exit 0\"]\n",
                "sh -c \"echo hi, there\" >/dev/null; exit 0",
            ),
            // The reporter's shape: a Python one-liner, which carries both an escaped quote and the
            // comma of an `import a,b`.
            (
                "services:\n  a:\n    image: r\n    healthcheck:\n      test: [\"CMD-SHELL\", \"python -c \\\"import sys,os; sys.exit(0)\\\"\"]\n",
                "python -c \"import sys,os; sys.exit(0)\"",
            ),
            // And the simple form that already worked, so a fix that broke it would show here.
            (
                "services:\n  a:\n    image: r\n    healthcheck:\n      test: [\"CMD-SHELL\", \"pg_isready -U postgres\"]\n",
                "pg_isready -U postgres",
            ),
        ];
        for (y, expected) in cases {
            assert_eq!(
                boxes(y)[0].health_cmd.as_deref(),
                Some(expected),
                "the health command was truncated for:\n{y}"
            );
        }
        // EXEC FORM WITH A COMMA IN AN ARGUMENT, and it stays ONE argument. The joined version read
        // `sh -c echo a,b`, which - run through a second shell - executes `echo` with no operand and
        // `a,b` as `$0`: the check silently stopped being the check that was written.
        let y = "services:\n  a:\n    image: r\n    healthcheck:\n      test: [\"CMD\", \"sh\", \"-c\", \"echo a,b\"]\n";
        assert_eq!(boxes(y)[0].health_argv, ["sh", "-c", "echo a,b"]);
    }

    #[test]
    fn ports_reconstructs_and_warns() {
        let y = "services:\n  a:\n    image: alpine\n    ports:\n      - \"8080:80\"\n";
        assert_eq!(boxes(y)[0].ports, ["8080:80"]);
    }

    /// A BLOCK SEQUENCE AT ITS KEY'S OWN INDENTATION IS THE SAME SEQUENCE, and kern used to drop it
    /// entirely, in silence.
    ///
    /// YAML lets the `-` sit at the key's column (the dash is itself an indentation indicator), and
    /// that is not a curiosity: it is what `docker compose config` prints, what every YAML dumper
    /// emits, and how a large share of hand-written files look. kern's dedent rule popped the key's
    /// level when it saw an item at the same column, so the items landed on the parent mapping,
    /// where nothing reads them. The key parsed, the value vanished, nothing was warned, exit 0.
    ///
    /// MEASURED: 16 files of a 240-file corpus write at least one sequence this way - `volumes` 20
    /// times, `cap_add` 14, `security_opt` 12, `devices` 11, `ports` 10, `depends_on` 4. Every one
    /// of them was counted COMPATIBLE by the compat-rate script, because a rate that reads kern's
    /// own silence cannot see what kern never noticed.
    ///
    /// Found by running Zabbix, where the only visible symptom was `healthcheck test not
    /// convertible` on five services.
    #[test]
    fn a_sequence_at_its_keys_own_indentation_is_not_dropped() {
        let y = concat!(
            "services:\n",
            "  web:\n",
            "    image: nginx\n",
            "    ports:\n",
            "    - \"8080:80\"\n",
            "    - \"8443:443\"\n",
            "    environment:\n",
            "    - K=V\n",
            "    depends_on:\n",
            "    - db\n",
            "    command:\n",
            "    - nginx\n",
            "    - -g\n",
            "    - daemon off;\n",
            "    healthcheck:\n",
            "      test:\n",
            "      - CMD-SHELL\n",
            "      - curl -f localhost || exit 1\n",
            "  db:\n",
            "    image: alpine\n",
        );
        let bs = boxes(y);
        let web = bs.iter().find(|b| b.name == "web").expect("web");
        assert_eq!(web.ports, ["8080:80", "8443:443"]);
        assert_eq!(web.env, ["K=V"]);
        assert_eq!(web.depends_on, ["db"]);
        assert_eq!(web.command, ["nginx", "-g", "daemon off;"]);
        assert_eq!(
            web.health_cmd.as_deref(),
            Some("curl -f localhost || exit 1")
        );
        // The service AFTER the compact block is still its own service: the dedent must still end
        // the sequence when a key at a smaller column arrives.
        assert_eq!(bs.len(), 2);
        assert_eq!(bs[1].image.as_deref(), Some("alpine"));

        // THE DEEPER STYLE MUST NOT HAVE MOVED. It is the same file with two more spaces, and a fix
        // that traded one spelling for the other would be no fix at all.
        let deep = concat!(
            "services:\n",
            "  web:\n",
            "    image: nginx\n",
            "    ports:\n",
            "      - \"8080:80\"\n",
            "    depends_on:\n",
            "      - db\n",
            "  db:\n",
            "    image: alpine\n",
        );
        let bs = boxes(deep);
        assert_eq!(bs[0].ports, ["8080:80"]);
        assert_eq!(bs[0].depends_on, ["db"]);
        assert_eq!(bs.len(), 2);

        // A list of MAPPINGS in the compact style (the long-form port) folds the same way.
        let maps = concat!(
            "services:\n",
            "  web:\n",
            "    image: nginx\n",
            "    ports:\n",
            "    - target: 80\n",
            "      published: 8080\n",
            "    - target: 443\n",
            "      published: 8443\n",
        );
        assert_eq!(boxes(maps)[0].ports, ["8080:80", "8443:443"]);

        // COLUMN ZERO is the boundary the rule has to survive, because there the pop-at-equal has
        // nothing left to pop: a top-level key whose items sit at its own indentation (`include:`
        // is written this way in the spec's own examples) is followed by `services:` at the same
        // column 0. Asked for by a reviewer as the case a dedent rule is most likely to get wrong.
        let top = concat!(
            "include:\n",
            "- ./other.yml\n",
            "services:\n",
            "  web:\n",
            "    image: nginx\n",
            "volumes:\n",
            "- data\n",
            "networks:\n",
            "  default:\n",
            "    driver: bridge\n",
        );
        let bs = boxes(top);
        assert_eq!(bs.len(), 1, "services after a column-0 sequence");
        assert_eq!(bs[0].name, "web");
        assert_eq!(bs[0].image.as_deref(), Some("nginx"));
    }

    #[test]
    fn ports_long_form_rebuilt_from_fields() {
        let y = "services:\n  a:\n    image: alpine\n    ports:\n      - {target: 80, published: 8080}\n";
        assert_eq!(boxes(y)[0].ports, ["8080:80"]);
    }

    #[test]
    fn ports_udp_is_published_not_silently_tcp() {
        // `kern box -p host:box/udp` has a real UDP forwarder, so compose must PUBLISH udp rather
        // than drop it: the same mapping working through the CLI and vanishing through compose was
        // two paths disagreeing about one input. What it must never do is convert it to TCP.
        let y = "services:\n  a:\n    image: alpine\n    ports:\n      - \"5353:5353/udp\"\n";
        assert_eq!(boxes(y)[0].ports, ["5353:5353/udp"]);
        // A protocol with no forwarder is still refused rather than silently treated as TCP.
        let sctp = "services:\n  a:\n    image: alpine\n    ports:\n      - \"5353:5353/sctp\"\n";
        assert!(
            boxes(sctp)[0].ports.is_empty(),
            "sctp has no forwarder: skipped, never tcp"
        );
    }

    #[test]
    fn restart_always_is_honored_on_any_exit() {
        let y = "services:\n  a:\n    image: alpine\n    restart: always\n";
        let b = &boxes(y)[0];
        assert!(
            b.restart && b.restart_always,
            "`always` restarts on ANY exit (not degraded to on-failure)"
        );
    }

    #[test]
    fn build_short_and_long_form() {
        let y = "services:\n  a:\n    build: ./svc\n";
        let bd = boxes(y)[0].build.clone().unwrap();
        assert_eq!(bd.context, "./svc");
        let y2 =
            "services:\n  a:\n    build:\n      context: ./svc\n      dockerfile: Custom.file\n";
        let bd2 = boxes(y2)[0].build.clone().unwrap();
        assert_eq!(bd2.context, "./svc");
        assert_eq!(bd2.dockerfile.as_deref(), Some("Custom.file"));
    }

    /// A KEY WITH NO VALUE TAKES ITS VALUE FROM THE ENVIRONMENT, WHICH INCLUDES THE PROJECT `.env`.
    ///
    /// Sentry self-hosted writes it with the reason in a comment above the keys - "Leaving the value
    /// empty to just pass whatever is set on the host system (or in the .env file)" - and its `.env`
    /// sets both. Read as an empty value instead, `SENTRY_EVENT_RETENTION_DAYS=` reached the box and
    /// Sentry's own config died on `int("")` at every start of the `web` service.
    ///
    /// The other half is pinned by `unresolvable_var_substitutes_empty_never_literal`: an unset
    /// `${VAR}` is indistinguishable from a bare key here (both `scalar: None`) and must stay the
    /// empty string Docker gives it. Deciding by whether the name is BOUND is what satisfies both.
    #[test]
    fn a_valueless_key_passes_the_environment_through_including_the_dotenv() {
        let de = crate::parse_dotenv("SENTRY_EVENT_RETENTION_DAYS=90\n");
        let y = concat!(
            "services:\n",
            "  web:\n",
            "    image: x\n",
            "    environment:\n",
            "      SENTRY_EVENT_RETENTION_DAYS:\n",
            "      NON_LEGATO_DA_NESSUNA_PARTE:\n",
        );
        let boxes = parse_with_env(y, &de, false, crate::StackNet::Pod, None).expect("parses");
        let env = &boxes[0].env;
        assert!(
            env.contains(&"SENTRY_EVENT_RETENTION_DAYS=90".to_string()),
            "the .env value must be passed through: {env:?}"
        );
        // Bound NOWHERE: Docker does not pass the variable at all, and neither does kern. Passed as
        // an empty string it is worse than absent - Sentry's own config reads `value[0]` on it and
        // dies with `IndexError: string index out of range`.
        assert!(
            !env.iter()
                .any(|e| e.starts_with("NON_LEGATO_DA_NESSUNA_PARTE")),
            "a valueless key bound nowhere is omitted, not passed empty: {env:?}"
        );
        // ...while a value that RESOLVED to nothing is the empty string, which is the other half of
        // the same distinction.
        let y2 =
            "services:\n  web:\n    image: x\n    environment:\n      K: ${KERN_UNSET_ABC_XYZ}\n";
        let b2 = parse_with_env(y2, &de, false, crate::StackNet::Pod, None).expect("parses");
        assert!(
            b2[0].env.contains(&"K=".to_string()),
            "an unset reference is Docker's empty string: {:?}",
            b2[0].env
        );
    }

    /// A BARE BUILD ARG TAKES ITS VALUE FROM THE PROJECT `.env` TOO, not from the shell alone.
    ///
    /// `args: [SENTRY_IMAGE]` against a `.env` that sets `SENTRY_IMAGE` is Sentry self-hosted's own
    /// build, and its Dockerfile is `ARG SENTRY_IMAGE` / `FROM ${SENTRY_IMAGE}`: with the value
    /// unresolved the image is built `FROM` nothing. MEASURED - kern stopped with `Dockerfile line
    /// 2: FROM needs an image reference` while `docker compose build` builds it.
    ///
    /// The shell still wins, and `environment:` is deliberately NOT changed: no measurement says a
    /// bare name there reads the `.env`, and putting a value into a container that Docker may not
    /// put there is the kind of guess this parser does not make.
    #[test]
    fn a_bare_build_arg_resolves_from_the_project_env() {
        let de = crate::parse_dotenv("SENTRY_IMAGE=ghcr.io/getsentry/sentry:nightly\n");
        let y = concat!(
            "services:\n",
            "  web:\n",
            "    build:\n",
            "      context: ./sentry\n",
            "      args:\n",
            "      - SENTRY_IMAGE\n",
            "      - EXPLICIT=1\n",
            "      - ASSENTE_OVUNQUE\n",
        );
        let boxes =
            parse_with_env(y, &de, false, crate::StackNet::Pod, None).expect("parses with .env");
        let args = boxes[0].build.clone().expect("build directive").args;
        assert!(
            args.contains(&"SENTRY_IMAGE=ghcr.io/getsentry/sentry:nightly".to_string()),
            "the bare name must resolve from the .env: {args:?}"
        );
        assert!(args.contains(&"EXPLICIT=1".to_string()));
        // Unresolvable anywhere: Docker leaves such an arg UNSET rather than setting it empty, so
        // the Dockerfile's own `ARG x=default` still applies.
        assert!(
            !args.iter().any(|a| a.starts_with("ASSENTE_OVUNQUE")),
            "an unresolved passthrough must not be forwarded at all: {args:?}"
        );
        // Without a `.env` the same file resolves nothing, which is what made this visible.
        let bare = parse_with_env(
            y,
            &crate::DotEnv::default(),
            false,
            crate::StackNet::Pod,
            None,
        )
        .expect("parses");
        let args = bare[0].build.clone().expect("build directive").args;
        assert!(
            !args.iter().any(|a| a.starts_with("SENTRY_IMAGE")),
            "no .env and no shell value: nothing to pass through ({args:?})"
        );
    }

    #[test]
    fn rejects_anchors_aliases_tabs_multidoc_blockscalar() {
        // Block-level anchors are SUPPORTED now (see yaml_anchors_and_merge_keys_expand_with_override):
        // an anchored service with no alias just parses.
        assert!(parse("services:\n  a: &anchor\n    image: alpine\n").is_ok());
        // A block-level alias to an UNDEFINED anchor is still an error - a clear "unknown anchor", never
        // the literal `*alias` reaching the box.
        assert!(parse("services:\n  a:\n    image: *alias\n").is_err());
        assert!(parse("services:\n\timage: alpine\n").is_err()); // tab
        assert!(
            parse("services:\n  a:\n    image: alpine\n---\nservices:\n  b:\n    image: x\n")
                .is_err()
        );
        assert!(parse("services:\n  a:\n    command: |\n      echo hi\n").is_err());
        // block scalar
        // Audit regression: an anchor/alias in LIST-ITEM position must be refused too - it used to
        // slip past both the `t`-prefix check (line starts with `- `) and `value_after_colon` (a list
        // item has no `:`), reaching the box as the literal `*boom`. `after_seq_markers` closes it.
        assert!(
            parse("services:\n  a:\n    image: alpine\n    command:\n      - *boom\n").is_err()
        );
        assert!(
            parse("services:\n  a:\n    image: alpine\n    command:\n      - &x hi\n").is_err()
        );
        // A hyphen that is NOT a sequence marker (a value that begins with '-', e.g. a flag) must NOT
        // be mistaken for one and must still parse.
        assert!(
            parse("services:\n  a:\n    image: alpine\n    command:\n      - --version\n").is_ok()
        );
        // An anchor/alias as a structural token must be refused in EVERY inline position - the two
        // positional checks only see line-start / after-`:`. `line_has_inline_anchor` closes this by
        // construction (a token-opening `&`/`*` outside quotes), not by an opener list, so a value
        // (`[*x]`), a nested value (`{test: [*x]}`), AND a KEY (`{&a k: v}`) are all caught.
        assert!(parse("services:\n  a:\n    image: alpine\n    command: [*boom, x]\n").is_err());
        assert!(
            parse("services:\n  a:\n    image: alpine\n    healthcheck: {test: *boom}\n").is_err()
        );
        assert!(parse("services:\n  a:\n    image: alpine\n    environment: {K: &a v}\n").is_err());
        // Anchor as a MAP KEY, and alias NESTED inside a `{…}`-wrapped `[…]` - the cases an opener
        // list ("preceded by `[{,:`") had to reason about; the token-start definition covers them.
        assert!(parse("services:\n  a:\n    image: x\n    environment: {&a k: v}\n").is_err());
        assert!(parse("services:\n  a:\n    image: x\n    healthcheck: {test: [*a]}\n").is_err());
        // No FALSE POSITIVES: a `*`/`&` preceded by scalar content (a glob, arithmetic, an `&` in a
        // value, or anything inside quotes) is NOT a token-opening anchor and must still parse.
        assert!(parse("services:\n  a:\n    image: my*repo/x\n").is_ok());
        assert!(parse("services:\n  a:\n    image: x\n    command: [\"echo\", \"2*2\"]\n").is_ok());
        assert!(parse("services:\n  a:\n    image: x\n    environment: {K: \"v*v\"}\n").is_ok());
        assert!(
            parse("services:\n  a:\n    image: x\n    environment: {URL: \"a&b=c\"}\n").is_ok()
        );
    }

    #[test]
    fn inline_anchor_detection_matches_an_independent_oracle() {
        // Completeness PROOF (not enumeration): generate lines with `&`/`*` in every position among a
        // small alphabet, and check `line_has_inline_anchor` against an INDEPENDENT oracle written a
        // different way - a right-to-left scan that, for each unquoted `&`/`*`, walks back over spaces
        // and asks "is the previous significant char scalar content?". If the two ever disagree, either
        // the guard misses a token-opening anchor (a hole) or over-flags a scalar (a false positive).
        fn oracle(line: &str) -> bool {
            let b = line.as_bytes();
            // Mark which byte offsets are inside quotes (single OR double, no escapes in YAML flow).
            let mut inq = vec![false; b.len()];
            let (mut q, mut i) = (0u8, 0usize);
            while i < b.len() {
                if q != 0 {
                    inq[i] = true; // the closing quote itself counts as "in quote" for this mark
                    if b[i] == q {
                        q = 0;
                    }
                } else if b[i] == b'"' || b[i] == b'\'' {
                    q = b[i];
                    inq[i] = true;
                }
                i += 1;
            }
            // Flow-collection depth entering each byte (outside quotes). A token-opening `&`/`*` is only
            // refused when it sits INSIDE a `[…]`/`{…}` - block-level anchors/aliases are supported.
            let mut depth_at = vec![0i32; b.len()];
            let mut d = 0i32;
            for (idx, &c) in b.iter().enumerate() {
                depth_at[idx] = d;
                if inq[idx] {
                    continue;
                }
                match c {
                    b'[' | b'{' => d += 1,
                    b']' | b'}' => d = (d - 1).max(0),
                    _ => {}
                }
            }
            let is_content = |c: u8| {
                c.is_ascii_alphanumeric()
                    || matches!(c, b'_' | b'-' | b'.' | b'/' | b'%' | b'@' | b'+' | b'~')
            };
            for (idx, &c) in b.iter().enumerate() {
                if (c == b'&' || c == b'*') && !inq[idx] {
                    // Walk left over spaces to the previous significant, non-quoted byte. A `&`/`*` is
                    // itself "already inside a value" if IT was preceded by content, so we treat a
                    // preceding `&`/`*` as content too (skip past it and keep looking) - a `b&*` run is
                    // one plain scalar, not two anchors. This mirrors the guard's forward `prev_content`
                    // latch; writing the walk L→R-independently (here R→L) is what makes it a check.
                    let mut j = idx;
                    let prev_is_content = loop {
                        if j == 0 {
                            break false; // line start → opens a token
                        }
                        j -= 1;
                        if b[j] == b' ' || b[j] == b'\t' {
                            continue;
                        }
                        if inq[j] && (b[j] == b'"' || b[j] == b'\'') {
                            break false; // a quote is a scalar boundary, not content
                        }
                        if b[j] == b'&' || b[j] == b'*' {
                            continue; // part of the same scalar run - keep walking back
                        }
                        if !inq[j] && (b[j] == b']' || b[j] == b'}') {
                            break true; // a CLOSED flow collection is content-like (the guard latches
                                        // prev_content=true on `]`/`}`), so a following `&`/`*` is not
                                        // a token opener
                        }
                        break !inq[j] && is_content(b[j]);
                    };
                    if !prev_is_content && depth_at[idx] > 0 {
                        return true;
                    }
                }
            }
            false
        }
        let alphabet: [u8; 14] = *b"&* \t[]{}:,\"'ab";
        let mut state: u64 = 0xDEAD_BEEF_CAFE_1234;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as usize
        };
        for _ in 0..50_000 {
            let len = next() % 14;
            let mut line = String::new();
            for _ in 0..len {
                line.push(alphabet[next() % alphabet.len()] as char);
            }
            assert_eq!(
                line_has_inline_anchor(&line),
                oracle(&line),
                "guard vs oracle disagree on {line:?}"
            );
        }
    }

    #[test]
    fn no_services_is_an_error() {
        assert!(parse("version: \"3\"\nvolumes:\n  data:\n").is_err());
    }

    #[test]
    fn yaml_anchors_and_merge_keys_expand_with_override() {
        // The DRY pattern real compose files use: an `x-*` template anchored with `&`, merged into
        // services with `<<: *name`, plus a per-service key that OVERRIDES a merged one.
        let y = r#"x-common: &common
  restart: always
  environment:
    - SHARED=yes

services:
  a:
    <<: *common
    image: alpine
    command: echo a
  b:
    <<: *common
    image: nginx
    restart: "no"
"#;
        let b = boxes(y);
        assert_eq!(b.len(), 2);
        let a = b.iter().find(|x| x.name == "a").unwrap();
        assert_eq!(a.image.as_deref(), Some("alpine"));
        assert!(a.restart, "a inherits `restart: always` from the merge");
        assert_eq!(a.env, ["SHARED=yes"]);
        let bb = b.iter().find(|x| x.name == "b").unwrap();
        assert_eq!(bb.image.as_deref(), Some("nginx"));
        assert!(
            !bb.restart,
            "b's own `restart: no` WINS over the merged `always`"
        );
        assert_eq!(bb.env, ["SHARED=yes"], "b still inherits the merged env");
    }

    #[test]
    fn yaml_value_alias_expands() {
        let y =
            "x-img: &img alpine:3.19\nservices:\n  a:\n    image: *img\n    command: \"true\"\n";
        assert_eq!(boxes(y)[0].image.as_deref(), Some("alpine:3.19"));
    }

    #[test]
    fn unknown_alias_is_a_clear_error_not_a_silent_literal() {
        assert!(parse("services:\n  a:\n    image: alpine\n    command: *nope\n").is_err());
    }

    #[test]
    fn billion_laughs_bomb_is_refused_by_the_budget_not_followed() {
        // A block-level alias-of-alias chain that would expand to 10^4 nodes: each level references the
        // previous anchor ten times. The node budget must REFUSE it (bounded time/memory), not
        // materialize the bomb. (Flow-collection aliases like `&b [*a,*a]` are refused earlier still.)
        let mut y = String::from("x-a0: &a0\n  k: v\n");
        for lvl in 1..=4 {
            y.push_str(&format!("x-a{lvl}: &a{lvl}\n"));
            for k in 0..10 {
                y.push_str(&format!("  k{k}: *a{}\n", lvl - 1));
            }
        }
        y.push_str("services:\n  boom:\n    image: alpine\n    command: *a4\n");
        assert!(
            parse(&y).is_err(),
            "billion-laughs must be refused by the node budget"
        );
    }

    #[test]
    fn block_scalar_literal_list_form_keeps_newlines() {
        // Apache Airflow's form: a `- |` list-item block scalar carrying a multi-line shell script,
        // whose `#` comments are LITERAL and whose line breaks are preserved.
        let y = "services:\n  a:\n    image: alpine\n    command:\n      - -c\n      - |\n        echo one   # not a yaml comment\n        echo two\n";
        let c = &boxes(y)[0].command;
        assert_eq!(c[0], "-c");
        assert_eq!(
            // The trailing newline is YAML's default ("clip") chomping: a block scalar keeps
            // exactly one. This expectation used to omit it, pinning a deviation the parser has
            // since stopped making - `|`, `|-` and `|+` all produced the same value, so an
            // indicator an author wrote on purpose did nothing.
            c[1],
            "echo one   # not a yaml comment\necho two\n",
            "literal | keeps newlines, the inline #, and one trailing break"
        );
    }

    #[test]
    fn block_scalar_folded_joins_with_spaces() {
        let y = "services:\n  a:\n    image: alpine\n    command: >\n      echo\n      hello\n      world\n";
        // Folded `>` gives one line, which is then tokenised like any other string command. The
        // trailing newline is clip chomping and is whitespace, so it separates rather than
        // surviving inside the last argument: the shell wrapper that used to keep it is gone.
        assert_eq!(boxes(y)[0].command, ["echo", "hello", "world"]);
    }

    #[test]
    fn multi_line_flow_and_following_line_flow_value() {
        // Sentry's forms: a `[ … ]` split across lines, and a flow value on the line AFTER the key.
        let a = "services:\n  a:\n    image: alpine\n    command: [\n      \"postgres\",\n      \"-c\",\n    ]\n";
        assert_eq!(boxes(a)[0].command, ["postgres", "-c"]);
        let b = "services:\n  a:\n    image: alpine\n    command:\n      [\"postgres\"]\n";
        assert_eq!(boxes(b)[0].command, ["postgres"]);
    }

    #[test]
    fn a_value_may_start_on_the_line_after_its_key() {
        // YAML lets a mapping value begin on the next, more-indented line. Three real shapes from a
        // 240-compose corpus arrived here as `expected key: value`: a quoted scalar spanning two
        // lines (`dteslya/libvirt-in-docker`, a QEMU argument list), a bare alias
        // (`anyenvs/dotfiles`), and a plain scalar after a BLANK line
        // (`DanielMabbett/terraform-provider-jenkinsci`).
        let y = "services:\n  a:\n    image: alpine\n    environment:\n      ARGS:\n        \"-drive file=/seed.iso\n        -netdev tap\"\n";
        let e = &boxes(y)[0].env;
        assert!(
            e.iter()
                .any(|kv| kv == "ARGS=-drive file=/seed.iso -netdev tap"),
            "the two lines fold to one scalar with a single space, as PyYAML reads them: {e:?}"
        );
    }

    #[test]
    fn a_nested_sequence_is_not_folded_up_into_its_key() {
        // THE GUARD ON THE RULE ABOVE, and it is not hypothetical: `colon_index` is quote-aware, so
        // `- "80:80"` carries no top-level colon and would have satisfied every other condition. Fold
        // it and `ports:` becomes the plain scalar `- "80:80"`, i.e. the stack loses its port and
        // says nothing. A dash entry stops the fold.
        // A COLON-FREE SEQUENCE IS THE CASE THAT DISCRIMINATES. `- "8080:80"` is stopped by the
        // `colon_index` guard anyway, so a test written on `ports:` stays green with the dash check
        // removed and proves nothing - measured by mutation before this line was rewritten. `command:`
        // followed by `- echo` has no colon anywhere, so the dash check is the only thing between a
        // two-element argv and the plain scalar `- echo`.
        let y = "services:\n  a:\n    image: alpine\n    command:\n      - echo\n      - ciao\n";
        let c = &boxes(y)[0].command;
        assert_eq!(c.len(), 2, "the sequence stays a sequence: {c:?}");
        assert_eq!(c[0], "echo");
        assert_eq!(c[1], "ciao");
    }

    #[test]
    fn a_sequence_entry_folds_its_continuation_line() {
        // `flow_intro` already handled a `- ` entry whose value OPENS with a quote. This one opens the
        // quote in the middle (`KEY="text`), which YAML reads as a plain scalar where the quote is an
        // ordinary character - and plain scalars fold. From `emysliwietz/latex-email-daemon`.
        let y = "services:\n  a:\n    image: alpine\n    environment:\n      - BODY=\"Riga uno.\n        Riga due.\"\n";
        let e = &boxes(y)[0].env;
        assert!(
            e.iter().any(|kv| kv == "BODY=\"Riga uno. Riga due.\""),
            "the continuation folds with one space: {e:?}"
        );
    }

    #[test]
    fn an_empty_list_item_is_skipped_not_refused() {
        // A bare `-` is a NULL entry in YAML (PyYAML: `{'a': [None, 'x']}`), and in compose it is what
        // an unset `${VAR}` leaves behind. Seven corpus files died on it, all of them `networks:`/
        // `dns:`/`security_opt:` written against a `.env` the reader does not have. Refusing the file
        // was refusing what every real parser accepts; the entry is dropped rather than kept as "",
        // because nothing is named by the empty string.
        let y = "services:\n  a:\n    image: alpine\n    environment:\n      - \n      - REALE=1\n";
        let e = &boxes(y)[0].env;
        assert_eq!(
            e.len(),
            1,
            "the empty entry is gone, the real one stays: {e:?}"
        );
        assert_eq!(e[0], "REALE=1");
    }

    #[test]
    fn multi_line_quoted_scalar_folds_to_a_space() {
        // Appwrite's form: a single-quoted list item whose closing quote is on the NEXT line - YAML
        // folds the line break to a space.
        let y = "services:\n  a:\n    image: alpine\n    command:\n      - -c\n      - 'curl http://x/health\n          >/dev/null'\n";
        let c = &boxes(y)[0].command;
        assert_eq!(c[0], "-c");
        assert_eq!(c[1], "curl http://x/health >/dev/null");
    }

    #[test]
    fn multi_alias_merge_and_bare_anchor_line_the_airflow_sentry_forms() {
        // Real files (Apache Airflow, Sentry, Penpot) put the anchor on its OWN line and merge SEVERAL
        // templates at once: `<<: [*a, *b]`. A per-service key still wins over every merged one.
        let y = "\
x-a:
  &a
  restart: always
  environment:
    - A=1
x-b: &b
  environment:
    - B=2
services:
  web:
    <<: [*a, *b]
    image: nginx
    environment:
      - C=3
";
        let w = &boxes(y)[0];
        assert!(w.restart, "web inherits `restart: always` from *a");
        assert_eq!(
            w.env,
            ["C=3"],
            "web's own `environment` wins over both merges"
        );
    }

    #[test]
    fn leading_document_marker_after_comments_is_ok_but_a_second_doc_is_not() {
        // Airflow's file opens with a licensed comment header, then a `---` document-start - fine.
        let y = "# a licensed header\n#\n---\nservices:\n  a:\n    image: alpine\n";
        assert_eq!(boxes(y)[0].name, "a");
        // A `---` AFTER real content still begins a second document, which we don't read.
        assert!(
            parse("services:\n  a:\n    image: alpine\n---\nservices:\n  b:\n    image: x\n")
                .is_err()
        );
    }

    #[test]
    fn service_without_image_or_build_is_rejected_at_parse() {
        // Field-test edge: a service with neither image nor build must fail at parse with a precise
        // message, not later as an opaque "need --rootfs or --image" from the box.
        let err = parse("services:\n  a:\n    command: [\"echo\", \"hi\"]\n").unwrap_err();
        assert!(err.contains("no `image:`"), "got: {err}");
        // An empty image string counts as absent.
        assert!(parse("services:\n  a:\n    image: \"\"\n").is_err());
    }

    #[test]
    fn unbalanced_inline_collection_is_rejected() {
        // `command: [unterminated` must NOT be silently accepted as the element `[unterminated`.
        assert!(parse("services:\n  a:\n    image: x\n    command: [unterminated\n").is_err());
        assert!(parse("services:\n  a:\n    image: x\n    environment: {K: v\n").is_err());
        // A balanced inline list is fine.
        assert!(parse("services:\n  a:\n    image: x\n    command: [a, b]\n").is_ok());
    }

    #[test]
    fn double_dash_key_is_a_name_not_a_list_item() {
        // `--net:` starts with `-` but is a (bad) KEY, not the list item `-net:`. It must be validated
        // as a service name (→ invalid), not mis-parsed as a sequence element.
        let err = parse("services:\n  --net:\n    image: alpine\n").unwrap_err();
        assert!(
            err.contains("invalid name") || err.contains("--net"),
            "got: {err}"
        );
        // A real list item (`- x`) still parses.
        let b = parse("services:\n  a:\n    image: x\n    command:\n      - echo\n      - hi\n")
            .unwrap();
        assert_eq!(b[0].command, ["echo", "hi"]);
    }

    #[test]
    fn orphan_health_gate_degrades_to_start_order() {
        // db's healthcheck is NONE → omitted → no health_cmd. app's `service_healthy` gate toward db
        // must DEGRADE to depends_on (start-order), NOT leave an unsatisfiable depends_healthy that
        // aborts the up (the reviewer's D1: no promise of a degrade that doesn't happen).
        let y = "services:\n  db:\n    image: alpine\n    healthcheck:\n      test: [\"NONE\"]\n  app:\n    image: alpine\n    depends_on:\n      db:\n        condition: service_healthy\n";
        let app = parse(y)
            .unwrap()
            .into_iter()
            .find(|b| b.name == "app")
            .unwrap();
        assert!(
            app.depends_healthy.is_empty(),
            "orphan gate must not remain in depends_healthy"
        );
        assert_eq!(
            app.depends_on,
            ["db"],
            "gate must be degraded to start-order"
        );
    }

    #[test]
    fn deploy_resources_limits_map_to_hard_caps() {
        // Docker Compose v3 puts hard caps under `deploy.resources.limits` - kern must CONVERT them to
        // its own enforced caps (Docker rootless ignores them). `reservations` are soft → left alone.
        let y = "services:\n  app:\n    image: alpine\n    deploy:\n      resources:\n        limits:\n          memory: 128M\n          cpus: \"0.5\"\n          pids: 100\n        reservations:\n          memory: 64M\n";
        let app = parse(y)
            .unwrap()
            .into_iter()
            .find(|b| b.name == "app")
            .unwrap();
        assert_eq!(app.memory.as_deref(), Some("128M"));
        assert_eq!(app.cpus.as_deref(), Some("0.5"));
        assert_eq!(app.pids_limit.as_deref(), Some("100"));
    }

    #[test]
    fn unterminated_quote_errors_bare_apostrophe_ok() {
        // An opening quote with no close is a CLEAR parse error, not a confusing downstream failure.
        let bad = "services:\n  a:\n    image: \"alpine\n    command: [\"true\"]\n";
        let e = parse(bad).unwrap_err();
        assert!(
            e.contains("unterminated quoted"),
            "want a clear error, got: {e}"
        );
        // But a bare apostrophe in an UNQUOTED scalar (`it's-fine`) is valid and must parse.
        let ok = "services:\n  a:\n    image: alpine\n    hostname: it's-fine\n";
        assert!(
            parse(ok).is_ok(),
            "a bare apostrophe in an unquoted scalar must parse"
        );
    }

    /// YAML 1.2 gives the two quote styles different escape rules, and a compose file relies on it:
    /// `"a\\nb"` is two lines, `'a\\nb'` is five characters. kern used to strip the quotes and hand
    /// the program the backslash, so a command written the way Docker's docs write it ran as one
    /// line and failed for a reason nothing in the file explained. Asserted on the DECODED scalar,
    /// because the file parses either way: only the value distinguishes the two behaviours.
    #[test]
    fn double_quoted_scalars_decode_escapes_and_single_quoted_do_not() {
        assert_eq!(scalar_str(r#""a\nb""#), "a\nb");
        assert_eq!(scalar_str(r#""a\tb""#), "a\tb");
        assert_eq!(scalar_str(r#""a\\b""#), "a\\b");
        assert_eq!(scalar_str(r#""say \"hi\"""#), "say \"hi\"");
        assert_eq!(scalar_str(r#""\u00e9""#), "\u{e9}");
        assert_eq!(scalar_str(r#""\x41""#), "A");

        // Single quotes take NO backslash escapes; `''` is the only one and it means `'`.
        assert_eq!(scalar_str("'a\\nb'"), "a\\nb");
        assert_eq!(scalar_str("'it''s'"), "it's");

        // Unquoted is untouched.
        assert_eq!(scalar_str("a\\nb"), "a\\nb");

        // An unknown or malformed escape is kept verbatim and consumes nothing after it.
        assert_eq!(scalar_str(r#""a\qb""#), "a\\qb");
        assert_eq!(scalar_str(r#""\uZZ12""#), "\\uZZ12");
    }

    #[test]
    fn deploy_limits_typo_maps_no_cap_and_does_not_lie() {
        // A mistyped limits key (`mem:` not `memory:`) must NOT silently apply a cap - it maps nothing
        // (and apply_deploy warns the service runs uncapped). Better a visible gap than a runs-but-lies.
        let y = "services:\n  app:\n    image: alpine\n    deploy:\n      resources:\n        limits:\n          mem: 64m\n";
        let app = parse(y)
            .unwrap()
            .into_iter()
            .find(|b| b.name == "app")
            .unwrap();
        assert!(
            app.memory.is_none(),
            "a mistyped limits key must not silently map a cap"
        );
    }

    #[test]
    fn container_name_is_captured_and_empty_falls_back() {
        // Docker's `container_name:` is captured (compose() then names the box this exactly, so
        // `docker exec <name>` ports 1:1); an empty value falls back to the default project name.
        let y = "services:\n  db:\n    image: alpine\n    container_name: usbim-postgres\n  bare:\n    image: alpine\n    container_name: \"\"\n";
        let boxes = parse(y).unwrap();
        assert_eq!(
            boxes
                .iter()
                .find(|b| b.name == "db")
                .unwrap()
                .container_name
                .as_deref(),
            Some("usbim-postgres")
        );
        assert!(
            boxes
                .iter()
                .find(|b| b.name == "bare")
                .unwrap()
                .container_name
                .is_none(),
            "an empty container_name must fall back to the default <project>-<service> name"
        );
    }

    #[test]
    fn healthy_gate_kept_when_dep_has_health() {
        // The degrade must NOT fire when the dep DOES have a usable healthcheck.
        let y = "services:\n  db:\n    image: alpine\n    healthcheck:\n      test: [\"CMD\", \"true\"]\n  app:\n    image: alpine\n    depends_on:\n      db:\n        condition: service_healthy\n";
        let app = parse(y)
            .unwrap()
            .into_iter()
            .find(|b| b.name == "app")
            .unwrap();
        assert_eq!(app.depends_healthy, ["db"]);
        assert!(app.depends_on.is_empty());
    }

    #[test]
    fn randomized_fuzz_never_panics_incl_multibyte_and_deep() {
        // Property: parse() NEVER panics on ANY input - Err or Ok only. Covers the two classes plain
        // examples miss: MULTIBYTE at a slice boundary (byte-safe slicing / char_indices) and DEEP
        // NESTING (iterative + MAX_DEPTH → no stack overflow). Deterministic LCG, reproducible.
        let alphabet: [&str; 18] = [
            ":",
            " ",
            "-",
            "[",
            "]",
            "{",
            "}",
            "\"",
            "'",
            "\n",
            "services",
            "image",
            "a",
            "é",
            "→",
            "🦀",
            // A long digit-run + a duration suffix - the class the audit found `parse_duration_secs`
            // could overflow-panic on (e.g. reaching `interval: 9999999999999999h`).
            "9999999999999999",
            "h",
        ];
        let mut state: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as usize
        };
        for _ in 0..20_000 {
            let len = next() % 60;
            let mut s = String::new();
            for _ in 0..len {
                s.push_str(alphabet[next() % alphabet.len()]);
            }
            let _ = parse(&s); // must not panic for any input
        }
        // Explicit deep nesting (2000 levels of `  key:`) - must be refused (MAX_DEPTH) or parsed, no
        // stack overflow.
        let mut deep = String::from("services:\n");
        for i in 0..2000 {
            deep.push_str(&" ".repeat(2 + i % 40));
            deep.push_str("k:\n");
        }
        let _ = parse(&deep);
        // Billion-laughs shape - must be refused by the anchor prescreen, not expanded.
        assert!(parse("services:\n  a: &x [*x, *x]\n").is_err());
    }

    #[test]
    fn duration_overflow_falls_back_to_none_not_panic() {
        // Audit regression: an unbounded untrusted `interval:` must never overflow-panic (debug) nor
        // wrap to a nonsense value (release) - a form that overflows falls back to None (box default).
        assert_eq!(parse_duration_secs("30s"), Some(30));
        assert_eq!(parse_duration_secs("1m30s"), Some(90));
        assert_eq!(parse_duration_secs("2h"), Some(7200));
        assert_eq!(parse_duration_secs("6000000000000000h"), None); // n*3600 overflows → None
        assert_eq!(parse_duration_secs("200000000000000000m"), None); // n*60 overflows → None
        assert_eq!(parse_duration_secs("9223372036854775807s5s"), None); // total add overflows → None
        assert_eq!(parse_duration_secs("99999999999999999999"), None); // >i64 bare number → None
                                                                       // And through the real public entry point, as a healthcheck.interval - parse must not panic.
        let y = "services:\n  a:\n    image: x\n    healthcheck:\n      test: t\n      interval: 6000000000000000h\n";
        let _ = parse(y); // Ok or Err, never a panic
    }

    #[test]
    fn extends_same_file_short_and_map_form() {
        // `extends: base` (short) and `extends: {service: base}` (map) both inherit the base's fields;
        // the extending service wins on a key conflict.
        let short = parse(
            "services:\n  base:\n    image: alpine\n    read_only: true\n  w:\n    extends: base\n",
        )
        .unwrap();
        let w = short.iter().find(|b| b.name == "w").unwrap();
        assert_eq!(w.image.as_deref(), Some("alpine"));
        assert!(w.read_only);
        // Map form + child override: child keeps its own read_only=false, inherits image.
        let mapf = parse("services:\n  base:\n    image: alpine\n    read_only: true\n  w:\n    extends:\n      service: base\n    read_only: false\n").unwrap();
        let w = mapf.iter().find(|b| b.name == "w").unwrap();
        assert_eq!(w.image.as_deref(), Some("alpine"));
        assert!(!w.read_only);
        // Transitive chain a<-b<-c.
        assert!(parse(
            "services:\n  a:\n    image: alpine\n  b:\n    extends: a\n  c:\n    extends: b\n"
        )
        .is_ok());
        // Cycle, unknown target, and cross-file each give a clear error (never an opaque "no image").
        assert!(parse(
            "services:\n  a:\n    extends: b\n    image: x\n  b:\n    extends: a\n    image: y\n"
        )
        .unwrap_err()
        .contains("circular"));
        assert!(parse("services:\n  w:\n    extends: ghost\n    image: x\n")
            .unwrap_err()
            .contains("unknown service"));
        // A cross-file extends with NO directory to resolve against says exactly that, instead of
        // guessing a working directory. (With a directory it works: the test below.)
        let err = parse("services:\n  w:\n    extends:\n      file: base.yml\n      service: b\n")
            .unwrap_err();
        assert!(err.contains("no directory to resolve"), "{err}");
    }

    /// `extends: {file: other.yaml, service: base}` - the Specification's cross-file form, which
    /// used to be a refusal ("inline the base service").
    ///
    /// MEASURED on Zabbix's own stack: 17 services, every one of them extending into
    /// `compose_zabbix_components.yaml`, so the file its maintainers publish and run did not start
    /// at all. The cases below are that file's shape reduced: a base in a sibling file, a local
    /// override on top, a chain that leaves the file and comes back, and the relationship keys the
    /// Specification does NOT inherit.
    #[test]
    fn extends_reaches_into_another_file_and_stops_at_relationships() {
        let dir = std::env::temp_dir().join(format!("kern-extends-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let at = |text: &str| {
            parse_with_env(
                text,
                &crate::DotEnv::default(),
                true,
                crate::StackNet::Pod,
                Some(dir.as_path()),
            )
        };

        std::fs::write(
            dir.join("components.yaml"),
            concat!(
                "services:\n",
                "  server-base:\n",
                "    image: base-image\n",
                "    read_only: true\n",
                "    environment:\n",
                "    - FROM_BASE=1\n",
                // Never inherited: it names a service that need not exist in the other file.
                "    depends_on:\n",
                "    - a-service-only-this-file-has\n",
            ),
        )
        .expect("write base");

        let boxes = at(concat!(
            "services:\n",
            "  zabbix-server:\n",
            "    extends:\n",
            "      file: components.yaml\n",
            "      service: server-base\n",
            "    image: my-own-image\n",
        ))
        .expect("cross-file extends resolves");
        let b = &boxes[0];
        assert_eq!(
            b.image.as_deref(),
            Some("my-own-image"),
            "the extending service wins"
        );
        assert!(b.read_only, "a key only the base sets is inherited");
        assert_eq!(b.env, ["FROM_BASE=1"]);
        assert!(
            b.depends_on.is_empty(),
            "`depends_on` is a relationship: it names services of the OTHER file and is not \
             inherited (got {:?})",
            b.depends_on
        );

        // A CHAIN THAT LEAVES THE FILE AND COMES BACK is a cycle, and must be named as one rather
        // than followed until something else breaks.
        std::fs::write(
            dir.join("loop.yaml"),
            concat!(
                "services:\n",
                "  there:\n",
                "    extends:\n",
                "      file: loop.yaml\n",
                "      service: there\n",
                "    image: x\n",
            ),
        )
        .expect("write loop");
        let err = at(concat!(
            "services:\n",
            "  here:\n",
            "    extends:\n",
            "      file: loop.yaml\n",
            "      service: there\n",
        ))
        .unwrap_err();
        assert!(err.contains("circular"), "{err}");

        // A file that is not there names itself in the error, with the path it looked at.
        let err = at("services:\n  w:\n    extends:\n      file: nope.yaml\n      service: b\n")
            .unwrap_err();
        assert!(err.contains("nope.yaml"), "{err}");

        // A service the base file does not define is named too, rather than reported as "no image".
        let err = at(concat!(
            "services:\n",
            "  w:\n",
            "    extends:\n",
            "      file: components.yaml\n",
            "      service: ghost\n",
        ))
        .unwrap_err();
        assert!(err.contains("no such service"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mixed_list_map_environment_is_salvaged_not_a_panic() {
        // Docker PANICS on `- KEY: value` (list/map mix); kern reads the intent as `KEY=value` and the
        // stack still comes up. A normal `- K=v` alongside it is unaffected.
        let b = parse("services:\n  w:\n    image: alpine\n    environment:\n      - MYSQL_DATABASE: nextcloud\n      - NORMAL=ok\n").unwrap();
        assert_eq!(b[0].env, vec!["MYSQL_DATABASE=nextcloud", "NORMAL=ok"]);
    }

    #[test]
    fn network_aliases_are_collected_map_form_only() {
        // The map form `networks: {net: {aliases: [db]}}` yields the aliases; the list form has none.
        // (kern ignores the network itself - shared-netns pod - but honours the alias names so a peer
        // can reach the service by alias too.)
        let y = "services:\n  postgres:\n    image: x\n    networks:\n      usbim:\n        aliases:\n          - db\n          - primary\n  rest:\n    image: y\n    networks:\n      - usbim\n";
        let b = parse(y).unwrap();
        assert_eq!(
            b.iter().find(|x| x.name == "postgres").unwrap().net_aliases,
            vec!["db", "primary"]
        );
        assert!(b
            .iter()
            .find(|x| x.name == "rest")
            .unwrap()
            .net_aliases
            .is_empty());
    }

    #[test]
    fn utf8_bom_is_stripped() {
        // A leading BOM (Windows editors) must not hide the `services:` block.
        let b = super::super::parse("\u{feff}services:\n  w:\n    image: alpine\n").unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].image.as_deref(), Some("alpine"));
    }

    /// A continuation line that begins with `-` is a plain scalar, not a sequence entry.
    ///
    /// The predicate used to break on the first `-` character, which refused exactly the
    /// continuations that carry command-line flags: `--source`, `-drive`, `-netdev`. Six files of a
    /// 240-compose corpus died on it, and the case is the ordinary long `command:`.
    ///
    /// THE COMMENT ABOVE THE PREDICATE ALREADY SAID `- `, WITH THE SPACE. Prose and code disagreed,
    /// and prose is what a reader checks, which is why re-reading the function never found it. The
    /// assertions below pin both directions so they cannot drift apart again.
    #[test]
    fn a_continuation_starting_with_a_dash_folds_and_a_real_sequence_entry_does_not() {
        // Cross-checked against PyYAML, which reads this as one scalar:
        // 'python3 /a/b.py --source /c/d.json --output /c/e.ndjson'
        let folded = fold_multiline(
            "services:\n  a:\n    image: alpine\n    command: python3 /a/b.py\n               \
             --source /c/d.json\n               --output /c/e.ndjson\n",
        )
        .expect("a plain multi-line scalar must parse");
        assert!(
            folded.contains("command: python3 /a/b.py --source /c/d.json --output /c/e.ndjson"),
            "the flag continuations must fold into one scalar, got:\n{folded}"
        );

        // A REAL sequence entry still stops the fold: `- ` and a bare `-`. Without this the fix
        // would swallow a list into the previous value, which is the opposite defect.
        let seq = fold_multiline(
            "services:\n  a:\n    image: alpine\n    command: echo uno\n      - due\n",
        )
        .expect("parse");
        assert!(
            !seq.contains("echo uno - due"),
            "`- due` is a sequence entry and must not fold, got:\n{seq}"
        );

        // And the guard that predates this fix is untouched: a `key: value` continuation still stops
        // the fold, so an over-indented key cannot be swallowed into the value above it.
        let keyed = fold_multiline(
            "services:\n  a:\n    image: alpine\n    command: echo uno\n      chiave: valore\n",
        )
        .expect("parse");
        assert!(
            !keyed.contains("echo uno chiave: valore"),
            "an over-indented key must not fold, got:\n{keyed}"
        );
    }

    /// `internal: true` is honoured only on positive evidence for EVERY service, and never guessed.
    ///
    /// kern gives a stack ONE network namespace, so the key is all-or-nothing: it maps onto the pod's
    /// `--no-outbound` when every service is confined to internal networks, and is dropped otherwise.
    /// Both directions are pinned because the wrong one is costly in opposite ways: honouring it too
    /// eagerly takes the internet away from a stack that needs it, and never honouring it accepts a
    /// declaration people use to keep a database off the internet and does nothing with it.
    ///
    /// The list spelling is tested alongside the mapping one because reading only `children` would
    /// make the decision depend on how the author wrote the file, and the list form is the common one.
    #[test]
    fn internal_networks_are_recognised_only_on_positive_evidence() {
        let all_internal = "services:\n  a:\n    image: alpine\n    networks: [priv]\n  \
             b:\n    image: alpine\n    networks:\n      priv:\n        aliases: [x]\n\
             networks:\n  priv:\n    internal: true\n";
        let boxes = parse(all_internal).expect("parse");
        assert_eq!(boxes.len(), 2);
        assert!(
            super::super::stack_is_internal_only(&boxes),
            "both spellings of `networks:` must count as confined"
        );

        // One service on an ordinary network: the whole stack keeps its egress.
        let mixed = "services:\n  a:\n    image: alpine\n    networks: [priv]\n  \
             b:\n    image: alpine\n    networks: [pub]\n\
             networks:\n  priv:\n    internal: true\n  pub:\n    driver: bridge\n";
        let boxes = parse(mixed).expect("parse");
        assert!(!super::super::stack_is_internal_only(&boxes));

        // A service with NO `networks:` key is not confined, whatever the file declares elsewhere.
        let bare = "services:\n  a:\n    image: alpine\n\
             networks:\n  priv:\n    internal: true\n";
        let boxes = parse(bare).expect("parse");
        assert!(!boxes[0].only_internal_networks);

        // A network the file does NOT mark internal never counts, even if another one is.
        let unmarked = "services:\n  a:\n    image: alpine\n    networks: [pub]\n\
             networks:\n  priv:\n    internal: true\n  pub:\n    driver: bridge\n";
        let boxes = parse(unmarked).expect("parse");
        assert!(!boxes[0].only_internal_networks);

        // And `internal: false` is not `internal:` present - the value decides, not the key.
        let explicit_false = "services:\n  a:\n    image: alpine\n    networks: [priv]\n\
             networks:\n  priv:\n    internal: false\n";
        let boxes = parse(explicit_false).expect("parse");
        assert!(!boxes[0].only_internal_networks);
    }

    /// `!!str` is honoured; every other explicit tag is still refused.
    ///
    /// Accepting it is not laxity: this parser carries every value as a raw string and lets the
    /// consumer coerce, so `!!str` asks for what already happens and refusing it rejected a file
    /// whose semantics kern implements. The other direction is the half that matters - `!!float`
    /// asks for a conversion nothing here performs, and accepting it would mean taking the file and
    /// doing something else with it.
    #[test]
    fn only_the_str_tag_is_honoured_and_it_is_matched_as_a_whole_token() {
        let boxes =
            parse("services:\n  a:\n    image: alpine\n    environment:\n      X: !!str 123\n")
                .expect("`!!str` must parse");
        assert!(
            boxes[0].env.iter().any(|e| e == "X=123"),
            "the tag must be stripped and the value kept, got {:?}",
            boxes[0].env
        );

        for tag in ["!!float 1.5", "!!int 3", "!!binary aGk=", "!!strange 1"] {
            let text =
                format!("services:\n  a:\n    image: alpine\n    environment:\n      X: {tag}\n");
            assert!(
                parse(&text).is_err(),
                "`{tag}` must still be refused: nothing here performs that conversion"
            );
        }
    }

    /// `!!str` over a LIST or a MAP is refused, and over every shape of scalar it is still honoured.
    ///
    /// Accepting the tag opened this, and the reason it is a defect and not a curiosity is the third
    /// refusal below: `command: !!str` over a block sequence was accepted, the tag silently dropped,
    /// the sequence read as a list, and THE BOX STARTED. A file was taken and something else was done
    /// with it, with nothing anywhere saying so - the exact outcome `is_str_tag`'s own comment claims
    /// to refuse. The two flow forms did fail, but late and mutely: the box died 150 ms in and the
    /// message named no cause the file could explain. They also slipped past the unbalanced-`[` guard,
    /// which asks whether a value STARTS with `[` and after a tag it starts with `!`.
    ///
    /// Measured against PyYAML 6.0.1: all four refusals below are `ConstructorError`/`ParserError`
    /// there, and all three acceptances load.
    ///
    /// The `pending` case is the one that fixes the rule's shape. `key: !!str` with nothing after it
    /// is an EMPTY STRING and legal, so "nothing follows the tag" cannot be the test; only the next
    /// content line separates the empty scalar from the block collection. A guard that refused on the
    /// bare tag alone would reject the last case here, which is why it is asserted.
    #[test]
    fn the_str_tag_is_refused_over_a_collection_and_kept_over_every_scalar() {
        let svc = |v: &str| format!("services:\n  a:\n    image: alpine\n{v}");

        for (what, body) in [
            ("flow sequence", "    command: !!str [sh, -c, echo]\n"),
            ("flow map", "    command: !!str {a: b}\n"),
            (
                "block sequence",
                "    command: !!str\n      - sh\n      - -c\n",
            ),
            ("block map", "    labels: !!str\n      a: b\n"),
        ] {
            let err = parse(&svc(body)).err().unwrap_or_else(|| {
                panic!("`!!str` over a {what} must be refused, it was accepted")
            });
            assert!(
                err.contains("list/map"),
                "the {what} refusal must name the node kind, not just the tag, got {err:?}"
            );
        }

        // Plain scalar: the case the tag was accepted for. The tag being stripped shows up as the
        // argv being `echo hi` and not `!!str echo hi`.
        let b = parse(&svc("    command: !!str echo hi\n")).expect("`!!str` over a scalar parses");
        assert_eq!(
            b[0].command,
            vec!["echo", "hi"],
            "the tag must be stripped before the value is tokenised"
        );

        // A TAG BEFORE A BLOCK INDICATOR, which is the case that was broken.
        //
        // The fold scan required the value to BEGIN with `|`, so `!!str |` was not folded at all: the
        // literal `|` survived into the value and the service tried to execute a program called `|`
        // (measured: `kern: cannot start '|' in box`). It was invisible while a string command was
        // wrapped in `sh -c`, where it was merely a shell syntax error at run time, and the previous
        // assertion here - "some argument contains the body" - passed on that wrapped form.
        //
        // Asserted as the WHOLE argv now, because "contains" is what let the `|` through.
        let b = parse(&svc("    command: !!str |\n      echo hi\n")).expect("`!!str |` parses");
        assert_eq!(
            b[0].command,
            vec!["echo", "hi"],
            "a tagged block scalar must fold, and its indicator must never reach the argv"
        );
        // The untagged form must keep behaving identically: one rule, two spellings.
        let plain = parse(&svc("    command: |\n      echo hi\n")).expect("`|` parses");
        assert_eq!(plain[0].command, b[0].command);
        // And the folded indicator too, tagged.
        let folded =
            parse(&svc("    command: !!str >\n      echo hi\n")).expect("`!!str >` parses");
        assert_eq!(folded[0].command, vec!["echo", "hi"]);

        // Bare tag, then a SIBLING key: an empty scalar, not a collection. This is the positive
        // control for the lookahead - refusing every bare `!!str` would fail here.
        parse(&svc("    command: !!str\n    entrypoint: /bin/sh\n"))
            .expect("`!!str` with nothing after it is an empty string, not a collection");
    }
}
