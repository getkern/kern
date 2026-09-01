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
    parse_with_env(text, &crate::DotEnv::default(), true)
}

pub(crate) fn parse_with_env(
    text: &str,
    dotenv: &crate::DotEnv,
    require_runnable: bool,
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
    let text = interpolated.as_str();

    let lines = lex(text)?;
    let mut root = build_tree(&lines)?;
    // Expand YAML anchors (`&x`), aliases (`*x`) and merge keys (`<<: *x`) - the common `x-*` template
    // DRY pattern real compose files use - under a hard node budget (billion-laughs-safe). After this,
    // the tree holds only concrete values.
    resolve_anchors(&mut root)?;
    // Resolve `extends:` (a service inheriting another service's fields) - a real Compose feature the
    // `x-`/anchor pattern doesn't cover, since it references another SERVICE by name. Same-file only.
    resolve_extends(&mut root)?;

    // Top level must have `services:`. `volumes:`/`networks:`/`version:`/`name:` are recognized;
    // everything else at the top is warned and ignored.
    // Top-level `secrets:` definitions (`name -> file`) - collected first so a service's
    // `secrets: [name]` reference can be resolved to its file. Only the `file:`-backed form maps to
    // kern (`--secret <file>:<name>` → `/run/secrets/<name>`); `external:`/`environment:` secrets warn.
    let secret_files = collect_secret_files(&root);

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
                    let b = service_to_box(name, svc, &secret_files)?;
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
                    warn_once(
                        "'networks:' ignored - kern connects pod members by name (shared netns)",
                    );
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
        .filter(|b| b.health_cmd.is_none())
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
                if ni > indent
                    && (nv.starts_with('[') || nv.starts_with('{'))
                    && colon_index(nc).is_none()
                {
                    let mut acc = nv.to_string();
                    let mut j = k;
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
        if let Some(ci) = colon_index(code) {
            let value = code[ci + 1..].trim();
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
                    if ni <= indent
                        || nt.starts_with('-')
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
    if let Some(ci) = colon_index(code) {
        if let Some((f, ch)) = indicator(code[ci + 1..].trim()) {
            return Some((format!("{}: ", &code[..ci]), f, ch));
        }
    }
    let trimmed = code.trim_start();
    let indent = &code[..code.len() - trimmed.len()];
    if let Some(rest) = trimmed.strip_prefix("- ") {
        if let Some((f, ch)) = indicator(rest.trim()) {
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
fn prescreen(text: &str) -> Result<(), String> {
    let mut seen_content = false; // has a real (non-comment, non-marker) line appeared yet?
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
                "line {ln}: YAML anchors/aliases not supported (rewrite the value inline)"
            ));
        }
        // Explicit type tags (`!!str`, `!!float`, …) - refuse ONLY when the tag is at value position
        // (right after `key:`), not when `!!` appears inside a value's text (a `WARNING!!!` in a shell
        // command, an image tag, …), which is a plain scalar and perfectly fine.
        if value_after_colon(line).is_some_and(|v| v.trim_start().starts_with("!!")) {
            return Err(format!("line {ln}: YAML type tags (`!!`) not supported"));
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

        // Dedent / sibling: pop levels whose opening column is >= this line's column. A list item (`-`)
        // lives AT its key's child-indent, so the same rule applies.
        while let Some(&c) = cols.last() {
            if ln.indent <= c {
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

        // List item: append to the mapping that opened the current level. A YAML sequence item is a
        // dash FOLLOWED BY WHITESPACE (`- x`) or a bare `-` (empty). A dash NOT followed by space is
        // part of a key - e.g. `--net:` is a (bad) key, NOT the list item `-net:`. Matching a bare
        // `strip_prefix('-')` mis-parsed `--net:` as a list item; require the space/EOL boundary.
        let is_list_item = ln.content == "-"
            || ln
                .content
                .strip_prefix('-')
                .is_some_and(|r| r.starts_with([' ', '\t']));
        if is_list_item {
            let item = ln.content[1..].trim();
            if item.is_empty() {
                return Err(format!("line {}: empty list item", ln.lineno));
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

/// Resolve Compose `extends:` - a service inheriting another service's fields. Same-file only
/// (`extends: base` or `extends: {service: base}`); a `{file: …}` cross-file extends is a clear error
/// (inline the service instead). Merge is SHALLOW and the extending service WINS on a key conflict -
/// the same rule kern uses for `<<` merge - resolved transitively (A extends B extends C) with a
/// cycle guard.
fn resolve_extends(root: &mut Node) -> Result<(), String> {
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
        resolve_service_extends(&mut root.children[si].1, name, &mut Vec::new())?;
    }
    Ok(())
}

/// The target service name of an `extends` node: the scalar short form, or the `service:` key of the
/// map form. A `file:` key (cross-file) is rejected clearly.
fn extends_target(n: &Node) -> Result<String, String> {
    // STRUCTURED form first. A flow mapping (`extends: {service: b}`) carries BOTH the expanded
    // `children` and the raw `{…}` text as a scalar; reading the scalar first took that raw text as a
    // service NAME and reported "unknown service '{file: base.yml, service: b}'" instead of resolving
    // it (or giving the honest cross-file message below).
    if n.children.is_empty() {
        if let Some(s) = n.scalar.as_deref().map(str::trim) {
            // The short form is a bare service name; a leftover `{…}` is a mapping we failed to expand,
            // never a name - fall through to the structured errors rather than inventing a target.
            if !s.is_empty() && !s.starts_with('{') {
                return Ok(s.to_string());
            }
        }
    }
    if n.children.iter().any(|(k, _)| k == "file") {
        return Err(
            "cross-file `extends: {file: …}` isn't supported yet - inline the base service into this \
             compose file"
                .to_string(),
        );
    }
    if let Some((_, sv)) = n.children.iter().find(|(k, _)| k == "service") {
        if let Some(s) = sv.scalar.as_deref().map(str::trim) {
            if !s.is_empty() {
                return Ok(s.to_string());
            }
        }
    }
    Err(
        "`extends` needs a service name (`extends: base` or `extends: {service: base}`)"
            .to_string(),
    )
}

/// Resolve one service's `extends`, first expanding the target (so chains fully flatten), then folding
/// the target's keys in where this service doesn't already define them.
fn resolve_service_extends(
    services: &mut Node,
    name: &str,
    seen: &mut Vec<String>,
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
    if target == name || seen.iter().any(|s| s == name) {
        return Err(format!("circular `extends` involving service '{name}'"));
    }
    seen.push(name.to_string());
    resolve_service_extends(services, &target, seen)?;
    seen.pop();
    let Some(tidx) = services.children.iter().position(|(k, _)| k == &target) else {
        return Err(format!(
            "service '{name}' extends unknown service '{target}'"
        ));
    };
    let parent = services.children[tidx].1.children.clone();
    // Drop the `extends` key now that it's being resolved, then fold in the parent's keys the child
    // doesn't already set (child wins - Compose's override semantics).
    services.children[idx].1.children.remove(ep);
    for (pk, pv) in parent {
        if pk == "extends" {
            continue;
        }
        if !services.children[idx]
            .1
            .children
            .iter()
            .any(|(ck, _)| *ck == pk)
        {
            services.children[idx].1.children.push((pk, pv));
        }
    }
    Ok(())
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
    let b = t.as_bytes();
    let dq = b.len() >= 2 && b[0] == b'"' && b[b.len() - 1] == b'"';
    let sq = b.len() >= 2 && b[0] == b'\'' && b[b.len() - 1] == b'\'';
    // Decode a folded block scalar's U+0001 line-break sentinel back to a real newline.
    if dq {
        decode_double_quoted(&t[1..t.len() - 1]).replace(BLOCK_NL, "\n")
    } else if sq {
        // Single quotes take no backslash escapes at all; `''` is the only one, and it means `'`.
        t[1..t.len() - 1].replace("''", "'").replace(BLOCK_NL, "\n")
    } else {
        t.replace(BLOCK_NL, "\n")
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

/// A service's `secrets:` reference names. Short form is a list of names (`[db_pw, api_key]`); long
/// form is a list of maps each with a `source:` (`[{source: db_pw, target: …}]`) - we take `source`
/// (the target is always `/run/secrets/<source>` in kern). Returns the referenced secret names.
fn secret_refs(node: &Node) -> Vec<String> {
    let mut out = Vec::new();
    for it in list_value(node) {
        let it = it.trim();
        if it.starts_with('{') {
            // long-form inline `{source: name, target: …}` - pull `source`.
            let n = parse_inline_table(it);
            if let Some(src) = n.child("source").and_then(|s| s.scalar.as_deref()) {
                out.push(scalar_str(src));
            }
        } else if !it.is_empty() {
            out.push(scalar_str(it));
        }
    }
    // Block long-form (`- source: name` on its own lines) is handled too: `build_tree` folds each
    // block list item's `key: value` children into an inline `{source: name, …}` scalar, so it arrives
    // at the `{`-prefixed branch above. No separate code path needed.
    out
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

/// Convert one `services:` entry into a `ComposeBox`, applying every mapping rule + degrade-with-warn.
/// `secret_files` maps a top-level secret name to its backing file (for `secrets: [name]` refs).
fn service_to_box(
    name: &str,
    svc: &Node,
    secret_files: &std::collections::HashMap<String, String>,
) -> Result<ComposeBox, String> {
    kern_common::BoxName::parse(name)
        .map_err(|e| format!("service '{name}': invalid name: {e}"))?;
    let mut b = ComposeBox::new(name.to_string());
    // `entrypoint` + `command` are composed as `entrypoint ++ command` (Docker semantics) - but ONLY
    // after the whole service is parsed, since the two keys can appear in EITHER order in the file.
    // Merging inline (as before) was order-dependent: if `entrypoint` came first, `command` hadn't been
    // read yet, then `command` overwrote the merge → the entrypoint was dropped and the box tried to
    // exec the bare command as a program.
    let mut entrypoint: Vec<String> = Vec::new();
    // Whether the entrypoint was written in SHELL form (a bare string `entrypoint: /init here` →
    // `sh -c "/init here"`) vs EXEC form (a list). It changes how `command` composes: Docker appends
    // `command` only to an EXEC-form entrypoint; a shell-form entrypoint is the whole command and
    // `command` is dropped (appending it would make the args shell positional params, not entrypoint
    // args - the box would run `/init here` and silently discard `command`). See the merge below.
    let mut entrypoint_is_shell_form = false;

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
                let (ep, shell_form) = entrypoint_value(node);
                entrypoint = ep;
                entrypoint_is_shell_form = shell_form;
            }
            "environment" => b.env = kv_pairs(node),
            "env_file" => b.env_file = list_value(node),
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
            "volumes" => b.volumes = volumes_value(node),
            "depends_on" => apply_depends(&mut b, node),
            "healthcheck" => apply_healthcheck(&mut b, node, name),
            "restart" => apply_restart(&mut b, node, name),
            "user" => b.user = node.scalar.as_deref().map(scalar_str),
            "working_dir" | "workdir" => b.workdir = node.scalar.as_deref().map(scalar_str),
            "build" => b.build = Some(build_value(node)),
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
            "hostname" => b.hostname = node.scalar.as_deref().map(scalar_str),
            "cap_add" => b.cap_add = list_value(node),
            "cap_drop" => b.cap_drop = list_value(node),
            "tmpfs" => b.tmpfs = tmpfs_value(node, name),
            "read_only" => b.read_only = scalar_is_true(node),
            // `privileged: true` has no kern equivalent (rootless by design) - warn, don't silently
            // pretend. The box runs UNprivileged; a workload needing real privilege will notice.
            "privileged" => {
                if scalar_is_true(node) {
                    warn(&format!(
                        "service '{name}': 'privileged: true' has no kern equivalent (rootless) - running unprivileged"
                    ));
                }
            }
            "secrets" => {
                // A service `secrets: [name, …]` (or long-form `{source: name, target: …}`) references
                // top-level secret definitions. Map each `file:`-backed one to `--secret <file>:<name>`
                // (kern delivers it at `/run/secrets/<name>`, mode 0400) - matching compose's mount
                // point exactly. `<file>` is relative → `compose()` makes it absolute (dir-confined).
                for entry in secret_refs(node) {
                    match secret_files.get(&entry) {
                        Some(file) => b.secrets.push(format!("{file}:{entry}")),
                        None => warn(&format!(
                            "service '{name}': secret '{entry}' has no top-level `file:` definition - skipped (external/env secrets aren't supported)"
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
                // Only RECORDED here, announced once for the whole document. A per-service
                // `networks:` used to pass in total silence when the file declared no top-level
                // block (Docker rejects such a file; kern accepted it and said nothing about the
                // segmentation it was dropping). Warning per service instead put eight identical
                // lines on a seven-service file, and stating the same fact in two places is the
                // exact defect class this codebase keeps paying for. One fact, one statement.
                // Not flagged when aliases came out of it: something WAS honoured, and "ignored"
                // would then be the lie.
                if b.net_aliases.is_empty() {
                    warn_once(
                        "'networks:' ignored - kern connects pod members by name (shared netns)",
                    );
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
            "shm_size" => warn(&format!(
                "service '{name}': 'shm_size:' ignored on purpose - kern bounds /dev/shm by the memory \
                 cgroup (mem_limit / --memory), not a fixed size, so there is no 64 MB shm footgun"
            )),
            "configs" | "logging" | "extends" | "stdin_open" | "tty" | "domainname" => {
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
    if !entrypoint.is_empty() {
        // FORWARDED AS AN OVERRIDE, not merged into `command`. The merge produced
        // `IMAGE_ENTRYPOINT ++ entrypoint ++ command` once the box prepended the image's own, which
        // is correct only for an image that has none - and an image with one is exactly when a file
        // writes `entrypoint:`. See `ComposeBox::entrypoint`.
        if entrypoint_is_shell_form {
            if !b.command.is_empty() {
                warn(&format!(
                    "service '{name}': a shell-form `entrypoint` ignores `command` (Docker semantics) - `command` dropped; use an exec-form (list) entrypoint to pass args"
                ));
            }
            // `command_argv` ALREADY wrapped the shell form as `sh -c "<string>"`, so wrapping it
            // again here would produce `sh -c sh -c …`. Only `command` is dropped, which is the
            // Docker rule the warning above states.
            b.command.clear();
            b.entrypoint = Some(entrypoint);
        } else {
            b.entrypoint = Some(entrypoint);
        }
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

/// The entrypoint argv PLUS whether it was shell-form (a bare string) - the merge with `command`
/// branches on it (see `service_to_box`). Shares one parser with `command`, so the two can't drift.
fn entrypoint_value(node: &Node) -> (Vec<String>, bool) {
    command_argv(node)
}

/// Parse a `command`/`entrypoint` node → `(argv, is_shell_form)`. `is_shell_form` is true only for a
/// bare (non-`[`) scalar string, which we wrap as `sh -c "<string>"`; a list (inline or block) is
/// exec-form (`false`).
fn command_argv(node: &Node) -> (Vec<String>, bool) {
    if let Some(sc) = &node.scalar {
        let sc = sc.trim();
        if sc.starts_with('[') {
            return (parse_inline_list(sc), false); // exec-form
        }
        if !sc.is_empty() {
            // shell-form: a bare string is run via a shell, like Docker.
            return (
                vec!["sh".to_string(), "-c".to_string(), scalar_str(sc)],
                true,
            );
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
fn kv_pairs(node: &Node) -> Vec<String> {
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
        } else if let Ok(val) = std::env::var(&entry) {
            // bare `- KEY` present in the host env → pass its value through.
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
            // A MISSING scalar is left as an empty value, not a passthrough: interpolation runs over
            // the document first, so `X: ${UNSET}` reaches us indistinguishable from a bare `X:`, and
            // Docker sets the first to empty. The `- KEY` list form remains the spelling that means
            // "take it from the host", and it already did.
            None => false,
            // NOT the empty string: interpolation runs over the whole document first, so
            // `X: ${UNSET}` arrives here as an empty scalar and Docker wants X set to EMPTY, not
            // omitted. Only an explicit YAML null (or no scalar at all) means passthrough.
            Some(sc) => matches!(sc.trim(), "null" | "Null" | "NULL" | "~"),
        };
        if literal_null {
            // Present in the host env → forward its value; absent → omit the variable entirely
            // (Docker semantics: an unresolved passthrough is not set, not set-to-empty).
            if let Ok(val) = std::env::var(k) {
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
fn interpolate_fragment(text: &str, dotenv: &crate::DotEnv) -> String {
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
        Some('?') => val.filter(|_| present).unwrap_or_else(|| {
            let msg = if arg.is_empty() {
                "required but not set".to_string()
            } else {
                arg.to_string()
            };
            warn(&format!("${{{var}}}: {msg} - substituted empty"));
            String::new()
        }),
        _ => val.unwrap_or_else(|| {
            warn(&format!(
                "${{{var}}} is not set (no default) - substituted empty (set it in your shell, like Docker)"
            ));
            String::new()
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
        if colons == 1 {
            warn(&format!(
                "service '{svc}': port '{host_port}' bound to 127.0.0.1 (kern is loopback-default, unlike Docker); use 0.0.0.0:{host_port} to expose on all interfaces"
            ));
        }
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

/// `tmpfs`: kern's `--tmpfs` grammar is `PATH[:size]`, but Docker allows a comma-separated option list
/// `PATH:size=10M,mode=1770,uid=1000`. We keep the `size=` option (kern supports a size cap) and
/// DROP the rest with a warning, rather than forwarding the whole option string to `--tmpfs` (which
/// rejected it → the whole service failed to start). A plain `PATH` or `PATH:64m` passes through.
fn tmpfs_value(node: &Node, svc: &str) -> Vec<String> {
    list_value(node)
        .into_iter()
        .map(|entry| {
            let Some((path, opts)) = entry.split_once(':') else {
                return entry; // bare `PATH`
            };
            // If `opts` isn't Docker option syntax (no `=`, e.g. a bare `64m`), keep it as the size.
            if !opts.contains('=') {
                return entry;
            }
            let mut size = None;
            let mut dropped = Vec::new();
            for opt in opts.split(',') {
                match opt.split_once('=') {
                    Some(("size", v)) => size = Some(v.to_string()),
                    _ => dropped.push(opt.to_string()),
                }
            }
            if !dropped.is_empty() {
                warn(&format!(
                    "service '{svc}': tmpfs '{path}' options {} not supported by kern --tmpfs (size only) - dropped",
                    dropped.join(",")
                ));
            }
            match size {
                Some(s) => format!("{path}:{s}"),
                None => path.to_string(),
            }
        })
        .collect()
}

/// `volumes`: a short-form `src:dst[:ro]` entry passes through (kern's `-v` grammar matches compose's
/// short form); a LONG-form entry (`{type:, source:, target:, read_only:}`, which `build_tree` folds to
/// an inline `{…}` scalar) is reconstructed into `source:target[:ro]`. Passing the raw `{…}` to `-v`
/// was a bug - the box rejected it and the whole service failed to start.
fn volumes_value(node: &Node) -> Vec<String> {
    list_value(node)
        .into_iter()
        .filter_map(|item| {
            if item.trim_start().starts_with('{') {
                reconstruct_volume_item(&item)
            } else {
                Some(item)
            }
        })
        .collect()
}

/// A compose long-form volume `{type: bind|volume, source: S, target: T, read_only: true}` → kern's
/// `S:T[:ro]`. An anonymous volume (no `source`) or an unsupported shape is dropped with a warning
/// rather than forwarded as a malformed `-v`. `type: tmpfs` has no `source`; we don't map it here
/// (kern has `--tmpfs`), so it's warned-and-skipped.
fn reconstruct_volume_item(item: &str) -> Option<String> {
    let inner = item.trim().trim_start_matches('{').trim_end_matches('}');
    let (mut source, mut target, mut read_only, mut vtype) =
        (String::new(), String::new(), false, String::new());
    for field in split_top_commas(inner) {
        if let Some((k, v)) = field.split_once(':') {
            let (k, v) = (k.trim(), scalar_str(v));
            match k {
                "source" => source = v,
                "target" => target = v,
                "type" => vtype = v,
                "read_only" => read_only = v == "true",
                _ => {} // bind/volume sub-options (bind:, volume:, consistency:) - ignored
            }
        }
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
    let cmd = healthcheck_test(test);
    match cmd {
        Some(c) => b.health_cmd = Some(c),
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

/// Convert a healthcheck `test` to a health command, or `None` if not faithfully convertible.
///  * `["CMD", "curl", "-f", "u"]`      → exec-form → `curl -f u` (argv joined for `--health-cmd`)
///  * `["CMD-SHELL", "curl -f u"]`      → shell-form → the shell string
///  * bare string `"curl -f u"`         → IMPLICIT CMD-SHELL (Docker) → the string (NEVER split-on-space)
///  * `["NONE"]`                        → no health → `None` (caller omits)
fn healthcheck_test(node: &Node) -> Option<String> {
    // Inline / block list form.
    let list = if let Some(sc) = &node.scalar {
        let sc = sc.trim();
        if sc.starts_with('[') {
            Some(parse_inline_list(sc))
        } else if !sc.is_empty() {
            // Bare string = implicit CMD-SHELL. Return verbatim (the box wraps it in `sh -c`).
            return Some(scalar_str(sc));
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
        "CMD-SHELL" => rest.first().cloned(),
        "CMD" => {
            if rest.is_empty() {
                None
            } else {
                // exec-form: join argv into a command line the health-checker runs.
                Some(rest.join(" "))
            }
        }
        // A list whose first item isn't a known directive → treat the whole thing as a shell string
        // only if it's a single element; otherwise not faithfully convertible.
        _ if list.len() == 1 => Some(list[0].clone()),
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
fn build_value(node: &Node) -> BuildDirective {
    // Short form: `build: ./dir`
    if let Some(sc) = &node.scalar {
        let sc = scalar_str(sc);
        if !sc.is_empty() {
            return BuildDirective {
                context: sc,
                dockerfile: None,
                args: Vec::new(),
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
    let args = node.child("args").map(kv_pairs).unwrap_or_default();
    BuildDirective {
        context,
        dockerfile,
        args,
    }
}

/// Emit a compat warning to stderr. Prefixed so it's clearly kern's compose-import voice, and so the
/// user sees exactly which part of their compose didn't map 1:1.
fn warn(msg: &str) {
    eprintln!("kern compose: {}", sanitize_for_terminal(msg));
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

    #[test]
    fn command_shell_form_wraps_in_sh_c() {
        let y = "services:\n  a:\n    image: alpine\n    command: echo hello world\n";
        assert_eq!(boxes(y)[0].command, ["sh", "-c", "echo hello world"]);
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

    #[test]
    fn shell_form_entrypoint_ignores_command_like_docker() {
        // Audit regression: a SHELL-form entrypoint (`sh -c "<string>"`) must NOT have `command`
        // appended - the args would become the shell's positional params and `command` would be
        // silently discarded. Docker ignores `command` for a shell-form entrypoint; so do we (+warn).
        let y = "services:\n  a:\n    image: x\n    entrypoint: /init here\n    command: run now\n";
        let b = &boxes(y)[0];
        assert_eq!(
            b.entrypoint.as_deref(),
            Some(&["sh".to_string(), "-c".to_string(), "/init here".to_string()][..])
        );
        assert!(
            b.command.is_empty(),
            "`command` is dropped, as Docker drops it"
        );
        // EXEC-form (list): the entrypoint overrides and `command` remains its arguments.
        let y2 = "services:\n  a:\n    image: x\n    entrypoint: [\"/bin/entry\"]\n    command: [\"arg1\"]\n";
        let b2 = &boxes(y2)[0];
        assert_eq!(
            b2.entrypoint.as_deref(),
            Some(&["/bin/entry".to_string()][..])
        );
        assert_eq!(b2.command, ["arg1"]);
        // Shell-form alone: the wrapper `command_argv` built, and NOT a second one on top of it.
        let y3 = "services:\n  a:\n    image: x\n    entrypoint: /init here\n";
        assert_eq!(
            boxes(y3)[0].entrypoint.as_deref(),
            Some(&["sh".to_string(), "-c".to_string(), "/init here".to_string()][..]),
            "a shell form must be wrapped exactly once, never `sh -c sh -c`"
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
        assert_eq!(
            interpolate_document("x=${A${B}}", &crate::DotEnv::default()),
            "x="
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
        assert_eq!(b.health_cmd.as_deref(), Some("true"));
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

    #[test]
    fn tmpfs_options_keep_size_drop_the_rest() {
        // Extreme vs-Docker regression: Docker's `- /scratch:size=10M,mode=1770,uid=1000` option list
        // was passed whole to `--tmpfs`, which took the entire `size=10M,mode=...` as the size and
        // aborted the box. Now we keep `size=` and drop the rest with a warning.
        let y = "services:\n  a:\n    image: x\n    tmpfs:\n      - /scratch:size=10M,mode=1770,uid=1000\n";
        assert_eq!(boxes(y)[0].tmpfs, ["/scratch:10M"]);
        // A bare path passes through.
        assert_eq!(
            boxes("services:\n  a:\n    image: x\n    tmpfs: /run\n")[0].tmpfs,
            ["/run"]
        );
        // The kern-native `PATH:64m` (size without `key=`) is untouched.
        assert_eq!(
            boxes("services:\n  a:\n    image: x\n    tmpfs:\n      - /t:64m\n")[0].tmpfs,
            ["/t:64m"]
        );
        // Options with NO size → just the path.
        assert_eq!(
            boxes("services:\n  a:\n    image: x\n    tmpfs:\n      - /t:mode=1777\n")[0].tmpfs,
            ["/t"]
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
        let y = "services:\n  a:\n    image: alpine\n    healthcheck:\n      test: [\"CMD\", \"pg_isready\", \"-U\", \"app\"]\n";
        assert_eq!(boxes(y)[0].health_cmd.as_deref(), Some("pg_isready -U app"));
        let y2 = "services:\n  a:\n    image: alpine\n    healthcheck:\n      test: [\"CMD-SHELL\", \"pg_isready || exit 1\"]\n";
        assert_eq!(
            boxes(y2)[0].health_cmd.as_deref(),
            Some("pg_isready || exit 1")
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
        let cases = [
            // (yaml, expected)
            ("services:\n  a:\n    image: r\n    healthcheck:\n      test: [\"CMD\",\"redis-cli\",\"ping\"]\n", "redis-cli ping"), // block list
            ("services:\n  a:\n    image: r\n    healthcheck: {test: [\"CMD\",\"redis-cli\",\"ping\"]}\n", "redis-cli ping"), // inline list
            ("services:\n  a:\n    image: r\n    healthcheck:\n      test: \"redis-cli ping\"\n", "redis-cli ping"), // block bare-string
            ("services:\n  a:\n    image: r\n    healthcheck: {test: \"redis-cli ping\"}\n", "redis-cli ping"), // inline bare-string
        ];
        for (y, expected) in cases {
            assert_eq!(
                boxes(y)[0].health_cmd.as_deref(),
                Some(expected),
                "for:\n{y}"
            );
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
            // Exec form with a comma in an argument.
            (
                "services:\n  a:\n    image: r\n    healthcheck:\n      test: [\"CMD\", \"sh\", \"-c\", \"echo a,b\"]\n",
                "sh -c echo a,b",
            ),
        ];
        for (y, expected) in cases {
            assert_eq!(
                boxes(y)[0].health_cmd.as_deref(),
                Some(expected),
                "the health command was truncated for:\n{y}"
            );
        }
    }

    #[test]
    fn ports_reconstructs_and_warns() {
        let y = "services:\n  a:\n    image: alpine\n    ports:\n      - \"8080:80\"\n";
        assert_eq!(boxes(y)[0].ports, ["8080:80"]);
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
        // folded `>` → one line; a scalar command is wrapped in `sh -c`. The trailing newline is
        // clip chomping, which this expectation used to omit.
        assert_eq!(boxes(y)[0].command, ["sh", "-c", "echo hello world\n"]);
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
        assert!(
            parse("services:\n  w:\n    extends:\n      file: base.yml\n      service: b\n")
                .unwrap_err()
                .contains("cross-file")
        );
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
}
