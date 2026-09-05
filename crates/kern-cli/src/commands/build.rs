//! `kern build` and the build-history verbs (`builds`, `build logs|inspect|rm|prune`).
//!
//! The Dockerfile front end: parse a spec, run each stage in a box, and cache the layers. Split out
//! of `commands/mod.rs` for size; helpers shared with the image and box paths (the layer cache, the
//! puller) stay in the parent and are reached through `use super::*`.

use super::*;

/// One build record as a JSON object - the single emitter for both `kern builds --json` (an array of
/// these) and `kern build inspect --json` (one of these), so the two can't drift on fields or escaping.
fn build_json(r: &crate::builds::Record) -> String {
    format!(
        "{{\"id\":{},\"tag\":{},\"status\":{},\"duration_ms\":{},\"started\":{},\"size_bytes\":{},\"warnings\":{},\"dockerfile\":{},\"context\":{},\"error\":{}}}",
        json_str(&r.id),
        json_str(&r.tag),
        json_str(r.label()),
        r.duration_ms,
        r.started,
        r.size,
        r.warnings,
        json_str(&r.dockerfile),
        json_str(&r.context),
        json_str(&r.error),
    )
}

/// `kern builds [<tag>] [--status S] [-n N] [--json]` - the build history: one row per past `kern
/// build`, newest first (the kern analogue of Docker Desktop's "Builds" panel / `docker buildx
/// history`). Optional query: `<tag>` keeps builds whose tag contains the substring, `--status`
/// filters by outcome, `-n` caps to the N newest.
pub fn builds_list(
    json: bool,
    filter: Option<&str>,
    status: Option<&str>,
    limit: Option<usize>,
) -> Result<(), Error> {
    let status = match status {
        Some(s) => Some(crate::builds::Status::filter_label(s).ok_or(Error::Usage(
            "build --status ok|warn|failed|running|interrupted",
        ))?),
        None => None,
    };
    let recs = crate::builds::query(filter, status, limit);
    if json {
        let out = kern_common::json_array(&recs, build_json);
        println!("{out}");
    } else if recs.is_empty() {
        // Distinguish "history is empty" from "your query matched nothing" - else a filter that finds
        // nothing looks like you've never built.
        if filter.is_some() || status.is_some() || limit.is_some() {
            println!("no builds match - run `kern builds` to see the full history");
        } else {
            println!("no builds yet - build one with `kern build -t <name> .`");
        }
    } else {
        let p = crate::ui::Palette::detect();
        // Size TAG to its widest value (capped) so STATUS stays aligned.
        let tw = recs
            .iter()
            .map(|r| r.tag.chars().count())
            .chain(std::iter::once(3))
            .max()
            .unwrap_or(3)
            .min(30);
        println!(
            "{d}{:<18} {:<tw$} {:<11} {:>8} {:>9}  CREATED{z}",
            "ID",
            "TAG",
            "STATUS",
            "TIME",
            "SIZE",
            d = p.d,
            z = p.z
        );
        let now = registry::now_unix();
        for r in &recs {
            let sc = match r.status {
                crate::builds::Status::Ok => p.g,
                crate::builds::Status::Warn => p.y,
                crate::builds::Status::Failed => p.r,
                crate::builds::Status::Running => p.d,
            };
            let id = format!("{}{}{:<18}{}", p.b, p.c, r.id, p.z);
            // Show the warning count inline (Docker's `⚠️ N`): a `warn` row reads `warn 2`. Other
            // outcomes just show their label; `warn` ⟺ warnings>0, so the number is unambiguous.
            let label = if r.status == crate::builds::Status::Warn && r.warnings > 0 {
                format!("warn {}", r.warnings)
            } else {
                r.label().to_string()
            };
            let status = format!("{sc}{:<11}{}", label, p.z);
            println!(
                "{id} {:<tw$} {status} {:>8} {:>9}  {}",
                truncate(&r.tag, tw),
                // ELAPSED, NOT `duration_ms`. That field is written at finalize, so a build in
                // flight has zero in it, and `0ms` next to a live process is the same false report
                // as calling it interrupted. `elapsed_ms` counts up while it runs.
                fmt_dur(r.elapsed_ms(now)),
                human_bytes(r.size),
                fmt_age(now.saturating_sub(r.started)),
            );
        }
    }
    Ok(())
}

/// `kern build logs <id>` - the captured transcript of a past build.
pub fn build_logs(id: &str) -> Result<(), Error> {
    if crate::builds::get(id).is_none() {
        return Err(Error::Build(format!("no build '{id}'")));
    }
    match crate::builds::read_log(id) {
        Some(s) => print!("{s}"),
        None => println!("(no transcript captured for build '{id}')"),
    }
    Ok(())
}

/// `kern build inspect <id> [--json]` - full detail for one past build.
pub fn build_inspect(id: &str, json: bool) -> Result<(), Error> {
    let r = crate::builds::get(id).ok_or_else(|| Error::Build(format!("no build '{id}'")))?;
    if json {
        println!("{}", build_json(&r));
    } else {
        let p = crate::ui::Palette::detect();
        // Free-text fields (tag/dockerfile/context/error) are scrubbed of terminal escapes - a record
        // with a crafted tag can't inject an escape sequence into a terminal that runs `inspect` (same
        // guard the `builds` table and `--json` already apply).
        let s = crate::ui::scrub;
        println!("{}{}build {}{}", p.b, p.c, r.id, p.z);
        println!("  tag        {}", s(&r.tag));
        println!("  status     {}", r.label());
        println!(
            "  duration   {}",
            fmt_dur(r.elapsed_ms(crate::registry::now_unix()))
        );
        println!("  size       {}", human_bytes(r.size));
        println!("  warnings   {}", r.warnings);
        println!("  dockerfile {}", s(&r.dockerfile));
        println!("  context    {}", s(&r.context));
        if !r.error.is_empty() {
            println!("  error      {}", s(&r.error));
        }
        println!("  logs       kern build logs {}", r.id);
    }
    Ok(())
}

/// `kern build rm <id>...` - delete build-history records.
pub fn build_rm(ids: &[String]) -> Result<(), Error> {
    for id in ids {
        // Three outcomes, three messages. "removed" used to be printed whenever the record had
        // existed, whether or not the removal succeeded.
        match crate::builds::remove(id) {
            Ok(true) => println!("removed build '{id}'"),
            Ok(false) => eprintln!("kern: no build '{id}'"),
            Err(e) => eprintln!("kern: build '{id}' could NOT be removed: {e}"),
        }
    }
    Ok(())
}

/// `kern build prune [--keep N]` - keep the N newest build records, delete the rest.
pub fn build_prune(keep: usize) -> Result<(), Error> {
    let n = crate::builds::prune(keep);
    println!("pruned {n} build record(s); kept the {keep} newest");
    Ok(())
}

/// `kern build -t <name> [-f Dockerfile] [--build-arg K=V] [<context>]` - build a local image from a
/// **subset** of Dockerfile (see [`crate::dockerfile`]). `FROM` pulls the base into a mutable build
/// rootfs; `RUN` executes inside a `kern box` (bind-mounted rootfs + host net); `COPY`/`ADD` copy
/// from the context (symlink-safe both sides); `ENV`/`WORKDIR`/`USER`/`CMD`/`ENTRYPOINT` accumulate
/// into the image config. The result is stored in the image cache so `kern box --image <name>` runs
/// it with no pull (reusing the P1 config sidecar). Daemonless, dependency-free (curl/tar/cp).
pub fn build(args: BuildArgs) -> Result<(), Error> {
    let tag = args
        .tag
        .filter(|t| !t.is_empty())
        .ok_or(Error::Usage("build needs -t <name[:tag]>"))?;
    let ctx = std::fs::canonicalize(args.context)
        .map_err(|e| Error::Build(format!("build context '{}': {e}", args.context)))?;
    if !ctx.is_dir() {
        return Err(Error::Build(format!(
            "build context '{}' is not a directory",
            args.context
        )));
    }
    // A `COPY`/`ADD` reads from the context root into the image, so `kern build <runtime>/kern` would
    // copy a peer's ssh keys, secrets and posture records into a published image. Refuse a context that
    // resolves onto the registry, the same inverted guard `-v`/`--secret`/`--env-file` apply.
    if crate::registry::path_overlaps_trusted_state(&ctx) {
        return Err(Error::Build(format!(
            "build context '{}' resolves onto the kern registry - refusing (a COPY would read another \
             box's secrets/state into the image)",
            args.context
        )));
    }
    let dfpath = match args.file {
        Some(f) => PathBuf::from(f),
        None => ctx.join("Dockerfile"),
    };
    // `-f <path>` reads a host file whose CONTENT becomes build INSTRUCTIONS (a `RUN`/`COPY`/`ADD` run
    // against the box) - the same host-content-reaches-the-box class as `--env-file`, in a MORE powerful
    // form (commands, not values). Guard it against the registry (a `key=value` record parses far enough
    // to carry a line) the same inverted way `-v`/`--secret`/`--env-file`/context do, and read the
    // canonical path so a symlink can't redirect it after the check.
    let dfcanon = std::fs::canonicalize(&dfpath)
        .map_err(|e| Error::Build(format!("cannot read {}: {e}", dfpath.display())))?;
    if crate::registry::path_overlaps_trusted_state(&dfcanon) {
        return Err(Error::Build(format!(
            "Dockerfile '{}' resolves onto the kern registry - refusing (its lines run as build steps)",
            dfpath.display()
        )));
    }
    let text = std::fs::read_to_string(&dfcanon)
        .map_err(|e| Error::Build(format!("cannot read {}: {e}", dfpath.display())))?;
    let mut bmap = std::collections::HashMap::new();
    for ba in args.build_args {
        let (k, v) = ba
            .split_once('=')
            .ok_or(Error::Usage("--build-arg expects K=V"))?;
        bmap.insert(k.to_string(), v.to_string());
    }
    let instrs = crate::dockerfile::parse(&text, &bmap).map_err(Error::Build)?;

    let cache = cache_dir();
    own_only_dir(&cache).map_err(|e| Error::Oci(format!("cache dir: {e}")))?;
    // A private, mutable build tree, cleaned up on every exit (a stale one from a crashed build is
    // cleared first). Keyed by pid so concurrent builds don't collide.
    let work = cache.join(format!(".build-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| Error::Sandbox(format!("build dir: {e}")))?;
    // Multi-stage (a second `FROM`, or any `COPY --from`) is orchestrated across stages; a single-stage
    // build goes straight to `build_run`, byte-for-byte unchanged.
    let multi = instrs
        .iter()
        .skip(1)
        .any(|i| matches!(i, crate::dockerfile::Instr::From { .. }))
        || instrs
            .iter()
            .any(|i| matches!(i, crate::dockerfile::Instr::Copy { from: Some(_), .. }));

    // ── Build history ──
    // Mint an id, lint the Dockerfile (advisory → drives the `warn` status), and pre-write a `running`
    // record so a build killed mid-flight (Ctrl-C) still leaves an "interrupted" trace. `Capture`
    // redirects stderr into the record's log for the build's lifetime (teed live to the terminal), so
    // `kern build logs <id>` shows the real transcript incl. child RUN output.
    let started = registry::now_unix();
    let id = crate::builds::new_id(started, std::process::id());
    let warns = crate::dockerfile::lint(&instrs);
    let mut rec = crate::builds::Record {
        id: id.clone(),
        tag: tag.to_string(),
        dockerfile: dfpath.display().to_string(),
        context: ctx.display().to_string(),
        started,
        duration_ms: 0,
        status: crate::builds::Status::Running,
        warnings: warns.len() as u32,
        size: 0,
        // Recorded at the same moment as the pid, so the pair identifies THIS process and a later
        // reader cannot mistake a recycled pid for a build still in flight.
        pid_starttime: registry::proc_starttime(std::process::id() as i32),
        error: String::new(),
    };
    let _ = crate::builds::write(&rec);
    let capture = crate::builds::Capture::start(&id);
    for w in &warns {
        if !args.quiet {
            // `kern: warning:`, like every other diagnostic: the SDK separates kern's voice from
            // the workload's by that prefix, and a bare `warning:` is invisible to it.
            eprintln!("kern: warning: {w}");
        }
    }
    let t0 = std::time::Instant::now();
    let result = if multi {
        build_multi_stage(args.quiet, tag, &ctx, &work, &instrs)
    } else {
        build_run(args.quiet, tag, &ctx, &work, &instrs)
    };
    remove_build_tree(&work); // overlay leaves mode-000 workdirs; force-clean so nothing leaks
                              // Finalize the record: outcome from `result`, size read back the way `images()` computes it. Drop
                              // the capture (restores stderr) before appending the summary so it lands after the transcript.
    rec.duration_ms = t0.elapsed().as_millis() as u64;
    match &result {
        Ok(()) => {
            rec.status = if rec.warnings > 0 {
                crate::builds::Status::Warn
            } else {
                crate::builds::Status::Ok
            };
            rec.size = image_size(&cache, &sanitize_ref(&rec.tag));
        }
        Err(e) => {
            rec.status = crate::builds::Status::Failed;
            rec.error = e.to_string();
        }
    }
    drop(capture);
    let _ = crate::builds::write(&rec);
    crate::builds::append_log(
        &id,
        &format!(
            "--- {} in {}ms · {} ---",
            rec.label(),
            rec.duration_ms,
            rec.tag
        ),
    );
    result
}

fn build_multi_stage(
    quiet: bool,
    tag: &str,
    ctx: &std::path::Path,
    work: &std::path::Path,
    instrs: &[crate::dockerfile::Instr],
) -> Result<(), Error> {
    use crate::dockerfile::Instr;
    // Split into stages at each FROM. `stages[i]` = the instruction slice for stage i (starts with FROM).
    let from_idxs: Vec<usize> = instrs
        .iter()
        .enumerate()
        .filter(|(_, x)| matches!(x, Instr::From { .. }))
        .map(|(i, _)| i)
        .collect();
    let n = from_idxs.len();
    // Stage names in order, for resolving `--from=<name>` (mirrors the parser).
    let stage_names: Vec<Option<String>> = from_idxs
        .iter()
        .map(|&i| match &instrs[i] {
            Instr::From { as_name, .. } => as_name.clone(),
            _ => None,
        })
        .collect();
    let pid = std::process::id();
    // Temp tags for the non-final stages, cleaned up at the end (whatever happens).
    let mut stage_tags: Vec<String> = Vec::with_capacity(n);
    let cleanup_stage_tags = |tags: &[String]| {
        for t in tags {
            let _ = drop_cached_image(t);
        }
    };

    // WHOLE-BUILD flat cache. Intermediate stages get throwaway pid-based temp tags (below) that are
    // deleted at the end, so they can't cache individually - but we CAN cache the final result: key the
    // whole multi-stage build by ALL instructions (every FROM ref, RUN, COPY dst - captured by `Debug`)
    // + the bytes of every context COPY source (`.dockerignore`-aware). If the final tag already holds
    // exactly this build, skip it entirely. Content-addressed → any change to any stage / file / FROM
    // rebuilds; never serves a stale image. Only hits when the final image is FLAT (`<safe>` dir); a
    // LAYERED final stage already caches per-layer, and the `is_dir` guard means a stale `.flatkey`
    // there can't false-hit. (Base-image *tag mutation* isn't detected - same as Docker's own build.)
    let ms_ig = crate::dockerignore::DockerIgnore::load(ctx);
    let ms_ctx_root = std::fs::canonicalize(ctx).unwrap_or_else(|_| ctx.to_path_buf());
    let ms_key = flat_image_key("multistage", instrs, ctx, &ms_ctx_root, ms_ig.as_ref());
    if flat_cache_hit(tag, &ms_key) {
        if !quiet {
            kern_common::progress!("  [cached · multi-stage image unchanged]");
        }
        announce_built(tag);
        return Ok(());
    }

    for si in 0..n {
        let start = from_idxs[si];
        let end = from_idxs.get(si + 1).copied().unwrap_or(instrs.len());
        let is_last = si == n - 1;
        let stage_tag = if is_last {
            tag.to_string()
        } else {
            format!("{STAGE_TAG_PREFIX}{pid}-{si}")
        };

        // Prepare this stage's rewritten instructions + sub-context (all the `COPY --from` handling and
        // its cleanup live in the helper, so this loop stays a straight-line `?`).
        let subctx = work.join(format!("from-{si}"));
        let prep = match prepare_stage(&instrs[start..end], &stage_tags, &stage_names, si, &subctx)
        {
            Ok(p) => p,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&subctx);
                cleanup_stage_tags(&stage_tags);
                return Err(e);
            }
        };
        let StagePrep {
            stage_instrs,
            pulled_from_stage,
            stage_uses_context,
        } = prep;

        // Choose the stage's build context WITHOUT copying the (possibly huge) real context unless the
        // stage actually COPYs from it (Finding B): the common `FROM alpine` + only `COPY --from` case
        // builds against the small sub-context alone. Cases:
        //  - no --from pull:            use the real ctx directly (byte-identical to single-stage).
        //  - --from pull, no ctx COPY:  build against the sub-context only (no full-context copy).
        //  - --from pull AND ctx COPY:  graft the sub-context onto a copy of the real ctx (rare).
        let stage_ctx = if !pulled_from_stage {
            ctx.to_path_buf()
        } else if !stage_uses_context {
            subctx.clone()
        } else {
            let merged = work.join(format!("ctx-{si}"));
            let _ = std::fs::remove_dir_all(&merged);
            copy_tree(ctx, &merged)?;
            // Overlay the pulled files on top of the real context (an explicit COPY --from wins on a
            // name clash, which is the intent).
            merge_context(&subctx, &merged)?;
            merged
        };

        let stage_work = work.join(format!("s{si}"));
        let _ = std::fs::create_dir_all(&stage_work);
        if let Err(e) = build_run(quiet, &stage_tag, &stage_ctx, &stage_work, &stage_instrs) {
            cleanup_stage_tags(&stage_tags);
            return Err(e);
        }
        if !is_last {
            stage_tags.push(stage_tag);
        }
    }
    cleanup_stage_tags(&stage_tags);
    // Stamp the whole-build key on the final tag so the NEXT identical multi-stage build hits the cache
    // above (overwrites the last stage's per-stage key that its `build_run` wrote). Harmless on a
    // layered final image - the `is_dir` guard in `flat_cache_hit` never false-hits on it.
    write_flat_key(tag, &ms_key);
    Ok(())
}

/// The build body - separated so [`build`] can always clean up the work tree, success or error.
///
/// Prefers a **layered** build: the base stays a shared read-only overlay lower, and RUN/COPY writes
/// accumulate in a persistent upper (the diff) - so the base is **never copied** (closing the
/// base-copy bottleneck). The image is stored as its diff + a `<tag>.base` marker, and
/// Why a build took the FLAT path (copy the base) instead of the layered one (overlay).
///
/// One message used to cover all three, and it named the least likely of them. See where this is
/// decided for the cost of that.
#[derive(Clone, Copy)]
pub(crate) enum FlatReason {
    /// `KERN_BUILD_FLAT=1`: the operator asked for it. Nothing is unavailable.
    Forced,
    /// The unprivileged overlay mount is refused by this kernel. The base is copied because there is
    /// no other way to build here.
    NoUnprivilegedOverlay,
    /// The mount works and kern will not use it: this kernel does not record overlay OPAQUE markers,
    /// so a file deleted in one build step would come back in a `COPY --from` or a push. Measured on
    /// tegra 5.15. The flat path deletes for real, which closes the leak by construction.
    OpaqueNotHonoured,
}

impl FlatReason {
    /// The clause the build line prints, worded to complete `[flat · ___, copying the base]`.
    pub(crate) const fn why(self) -> &'static str {
        match self {
            Self::Forced => "KERN_BUILD_FLAT=1",
            Self::NoUnprivilegedOverlay => "unprivileged overlay unavailable",
            Self::OpaqueNotHonoured => {
                "this kernel does not record overlay opaque markers, so a layered build could \
                 resurrect a deleted file"
            }
        }
    }
}

/// [`resolve_image`] stacks it back over the (re-resolvable) base at run. Where unprivileged overlay
/// isn't usable (probed once), it falls back to a **flat** build: copy the base, RUN over a bind
/// mount, store a full rootfs - exactly as before, at the cost of the base copy.
fn build_run(
    quiet: bool,
    tag: &str,
    ctx: &std::path::Path,
    work: &std::path::Path,
    instrs: &[crate::dockerfile::Instr],
) -> Result<(), Error> {
    use crate::dockerfile::Instr;
    let self_exe = std::env::current_exe()
        .map_err(|e| Error::Sandbox(format!("cannot locate the kern binary: {e}")))?;
    let total = instrs.len();

    // FROM is always the first instruction (the parser guarantees it). Resolve the base to an overlay
    // lower (a single dir, or a colon chain for a layered base).
    let Some(Instr::From {
        image: base_ref, ..
    }) = instrs.first()
    else {
        return Err(Error::Sandbox("internal: build has no FROM".into()));
    };
    // `build_run` builds ONE stage. A multi-stage Dockerfile is orchestrated by `build_multi_stage`,
    // which calls us once per stage with a single-stage slice - so we never see a second FROM here.
    if !quiet {
        kern_common::progress!("[1/{total}] FROM {base_ref}");
    }
    let (base_lower, base_cfg) = resolve_image(base_ref)?;
    let mut config = base_cfg;

    // Choose the build strategy: layered (overlay, no base copy) unless the user forces a flat build
    // (`KERN_BUILD_FLAT=1`, an escape hatch for a misbehaving overlay) or the probe says overlay
    // isn't usable here. A layered base can only be built on with overlay (cp can't duplicate a colon
    // chain), so require overlay in that case.
    //
    // SECURITY (opaque-dir leak, fail-CLOSED across kernels): a layered build represents `rm -rf dir &&
    // mkdir dir` as an OPAQUE directory in the upper layer - a file the delete hid stays out of the
    // merged view ONLY IF the kernel actually records the opaque. On some rootless overlay kernels it
    // does NOT (measured: tegra 5.15 silently omits it → a secret `rm`'d in a build step reappears in a
    // `COPY --from`/push; rpi/android hard-fail the delete). Where the opaque isn't honoured, layered is
    // UNSAFE, so we fall back to the FLAT build - which copies the base and deletes files for real (no
    // opaque marker involved), closing the leak by construction on every kernel. `probe_opaque_honored`
    // tests this once, in-process, and only matters on the (older/vendor) kernels that lack it; on a
    // modern kernel it's a sub-ms no-op that returns true.
    // WHICH of the three reasons put this build on the flat path, because they are not the same
    // fact and the single message they all produced said the wrong thing for two of them:
    //
    //   * the operator FORCED it - nothing is unavailable;
    //   * the unprivileged overlay mount is refused by this kernel - the message was true here;
    //   * the mount works and kern REFUSES to use it, because this kernel does not record overlay
    //     opaque markers and a layered build would let a file deleted in a step reappear in a
    //     `COPY --from` or a push. That is a deliberate security fallback, and reporting it as a
    //     missing capability hides a decision kern made on the operator's behalf behind an apparent
    //     limitation of their machine. A field report measured 2m49s of base copying on WSL2 and
    //     concluded the cost "may be our host, not kern"; with one message for three causes there
    //     was no way for them to tell which one they had.
    //
    // Evaluated in the same order as the `&&` chain it replaces, so the expensive probe still runs
    // only when the cheap check has not already decided.
    let flat_because = if std::env::var_os("KERN_BUILD_FLAT").is_some() {
        Some(FlatReason::Forced)
    } else if !probe_overlay(&self_exe, &base_lower, work) {
        Some(FlatReason::NoUnprivilegedOverlay)
    } else if !probe_opaque_honored() {
        Some(FlatReason::OpaqueNotHonoured)
    } else {
        None
    };
    let layered = flat_because.is_none();
    if !layered && base_lower.contains(':') {
        return Err(Error::Sandbox(
            "cannot build FROM a layered image without unprivileged overlay + honoured opaque dirs on \
             this kernel (needed to avoid a deleted-file leak); rebuild on a newer kernel"
                .into(),
        ));
    }
    // Layered mode: per-unit **cached** layers (each RUN batch / COPY / WORKDIR is a content-addressed
    // overlay layer reused on an unchanged rebuild). Feedback-first: name the strategy so a silent flat
    // fallback (slower + a full base copy) never looks like "layered but big".
    if layered {
        if !quiet {
            kern_common::progress!("  [layered · base shared, no copy]");
        }
        return build_layered_cached(quiet, tag, ctx, work, instrs, base_ref, &base_lower, config);
    }
    // From here on this is the FLAT fallback only (layered returned above). The whole image is a full
    // copy of the base that COPY/WORKDIR/RUN mutate in place; a bind-mounted box runs each RUN.
    //
    // FLAT CACHE: the flat path has no per-layer cache, so without this an UNCHANGED rebuild (the common
    // case on WSL / kernels without unprivileged overlay) redoes the whole base-copy + RUN + COPY. Key
    // the finished image by its content and, if the tag already holds exactly that image, skip the
    // build. Content-addressed (`flat_image_key`), so a changed Dockerfile / build-arg / copied file
    // busts the key and rebuilds - it never serves a stale image.
    let ig = crate::dockerignore::DockerIgnore::load(ctx);
    let ctx_root = std::fs::canonicalize(ctx).unwrap_or_else(|_| ctx.to_path_buf());
    let flat_key = flat_image_key(&base_lower, instrs, ctx, &ctx_root, ig.as_ref());
    if flat_cache_hit(tag, &flat_key) {
        if !quiet {
            kern_common::progress!("  [cached · flat image unchanged]");
        }
        announce_built(tag);
        return Ok(());
    }
    // A real flat build (cache miss) - now note the base copy (slower than layered).
    if !quiet {
        // AND WHAT THE COPY WILL COST, which is a property of the filesystem and was never stated.
        // `copy_tree` passes `--reflink=auto`: on btrfs/xfs/bcachefs the base is cloned and the line
        // below is nearly free, everywhere else it is a full byte copy of the whole base image. A
        // field report measured 2m49s and 1.9 GB per build and could not tell whether that was kern
        // or their host. It is neither; it is whether this filesystem does copy-on-write.
        let cow = supports_reflink(work);
        kern_common::progress!(
            "  [flat · {}, copying the base{}]",
            flat_because.map_or("no layered build", FlatReason::why),
            match cow {
                Some(true) => " (cloned: this filesystem does copy-on-write)",
                // Short and on ONE line, deliberately. The first version wrapped this with a `\`
                // continuation and `cargo fmt` joined it back with the indentation inside the
                // literal, so the user would have read "the whole base is<35 spaces>re-read".
                // `scripts/flat-continuation.py` caught it on the same file it was written into.
                Some(false) => " in full: no copy-on-write here, so the whole base is re-copied",
                None => "",
            }
        );
    }
    let write_dir = work.join("rootfs");
    copy_tree(std::path::Path::new(&base_lower), &write_dir)?;
    // DNS for RUN: seed the host resolv.conf into the copied rootfs so apk/apt resolve; stripped
    // before finalize (if we created it) so the host's DNS servers aren't baked into the image.
    let seeded_resolv = seed_resolv_conf(&write_dir);

    let announce = |s: usize, what: String| {
        if !quiet {
            kern_common::progress!("[{s}/{total}] {what}");
        }
    };
    let mut cmd_from_dockerfile = false;
    let mut i = 1; // instrs[0] is the FROM handled above
    while i < instrs.len() {
        let step = i + 1;
        match &instrs[i] {
            Instr::From { .. } => i += 1, // only one FROM in single-stage (parser+guard enforced)
            Instr::Run(argv) => {
                // Batch CONSECUTIVE shell-form RUNs into ONE box, so the per-box overhead (fork+exec
                // + overlay mount) is paid once, not per step. Each original RUN still runs in its own
                // `/bin/sh -c` subshell, chained with `&&` (fail-fast, and Docker's per-RUN cwd reset).
                // An exec-form RUN (`RUN ["a","b"]`) or any non-RUN instruction ends the batch.
                let mut scripts: Vec<&str> = Vec::new();
                let mut j = i;
                while let Some(Instr::Run(a)) = instrs.get(j) {
                    match run_shell_script(a) {
                        Some(s) => {
                            announce(j + 1, format!("RUN {s}"));
                            scripts.push(s);
                            j += 1;
                        }
                        None => break,
                    }
                }
                let (run_argv, next) = if scripts.is_empty() {
                    announce(step, format!("RUN {}", display_run(argv))); // exec-form: run alone
                    (argv.clone(), i + 1)
                } else {
                    (combine_run_scripts(&scripts), j)
                };
                run_build_step(
                    &self_exe,
                    false, // flat fallback: bind-mount the copied rootfs
                    &base_lower,
                    work,
                    &write_dir,
                    &config,
                    &run_argv,
                    step,
                )?;
                i = next;
            }
            Instr::Copy {
                srcs,
                dst,
                from: _,
                chmod,
            } => {
                announce(step, format!("COPY {} {dst}", srcs.join(" ")));
                // Expand `*`/`?`/`[…]` globs against the context (Docker does), so `COPY *.txt /d/`
                // copies each match; a literal source passes through. Errors if a glob matches nothing.
                let srcs = expand_copy_srcs(ctx, srcs)?;
                // Copying multiple sources requires a directory destination (else each would clobber
                // the same name) - error rather than silently keep only the last, like Docker.
                if srcs.len() > 1
                    && !(dst.ends_with('/') || write_dir.join(dst.trim_start_matches('/')).is_dir())
                {
                    return Err(Error::Sandbox(format!(
                        "COPY with multiple sources needs a directory destination (end '{dst}' with '/')"
                    )));
                }
                for s in &srcs {
                    copy_into_rootfs(
                        ctx,
                        s,
                        &write_dir,
                        dst,
                        config.workdir.as_deref(),
                        &[],
                        chmod.as_deref(),
                    )?;
                }
                i += 1;
            }
            Instr::AddUrl {
                url,
                dst,
                checksum,
                chmod,
            } => {
                announce(step, format!("ADD {url} {dst}"));
                let dl = work.join(format!("addurl{step}"));
                let name = fetch_add_url(url, checksum.as_deref(), &dl)?;
                apply_chmod(&dl.join(&name), chmod.as_deref())?;
                copy_into_rootfs(
                    &dl,
                    &name,
                    &write_dir,
                    dst,
                    config.workdir.as_deref(),
                    &[],
                    None,
                )?;
                i += 1;
            }
            Instr::WriteFile {
                content,
                dst,
                chmod,
            } => {
                announce(step, format!("COPY (inline heredoc) {dst}"));
                let dl = work.join(format!("inline{step}"));
                write_inline_file(&dl, content)?;
                apply_chmod(&dl.join("f"), chmod.as_deref())?;
                copy_into_rootfs(
                    &dl,
                    "f",
                    &write_dir,
                    dst,
                    config.workdir.as_deref(),
                    &[],
                    None,
                )?;
                i += 1;
            }
            Instr::Env(k, v) => {
                set_config_env(&mut config.env, k, v);
                i += 1;
            }
            Instr::Workdir(d) => {
                let wd = resolve_workdir(config.workdir.as_deref(), d);
                mkdir_in_rootfs(&write_dir, &wd)?;
                config.workdir = Some(wd);
                i += 1;
            }
            Instr::User(u) => {
                config.user = Some(u.clone());
                i += 1;
            }
            Instr::Cmd(_) | Instr::Entrypoint(_) => {
                apply_cmd_entrypoint(&mut config, &instrs[i], &mut cmd_from_dockerfile);
                i += 1;
            }
            Instr::Expose(p) => {
                announce(
                    step,
                    format!("EXPOSE {p} (informational - publish with -p at run)"),
                );
                i += 1;
            }
        }
    }
    // Undo the seed so host DNS isn't baked in. EXACT, not a delete: a base that shipped an empty
    // `/etc/resolv.conf` (every Debian and Ubuntu image does) gets its empty file back rather than
    // losing it. See `seed_resolv_conf`.
    restore_resolv_conf(&write_dir, &seeded_resolv);

    // Finalize: commit the new form FIRST (clearing only THIS mode's prior target so the rename can
    // land), THEN drop the OTHER mode's stale artifacts and the sentinel - so a failed rename never
    // leaves the tag with neither the old nor the new image.
    let cache = cache_dir();
    let safe = sanitize_ref(tag);
    // Flat fallback (build_run is only reached when NOT layered - layered returns early above).
    let flat = cache.join(&safe);
    let _ = std::fs::remove_dir_all(&flat);
    std::fs::rename(&write_dir, &flat)
        .map_err(|e| Error::Sandbox(format!("finalize image '{tag}': {e}")))?;
    // Drop any stale LAYERED form of this tag (single-diff or multi-layer).
    let _ = std::fs::remove_dir_all(cache.join(format!("{safe}.diff")));
    let _ = std::fs::remove_file(cache.join(format!("{safe}.base")));
    let _ = std::fs::remove_file(cache.join(format!("{safe}.layers")));
    write_image_config(&cache.join(format!("{safe}.image")), &config)
        .map_err(|e| Error::Sandbox(format!("image config for '{tag}': {e}")))?;
    let _ = std::fs::write(cache.join(format!("{safe}.ok")), tag.as_bytes());
    // Record the content key so the NEXT identical build hits the flat cache above and skips the rebuild.
    write_flat_key(tag, &flat_key);
    announce_built(tag);
    Ok(())
}

/// Layered build with a Docker-style **per-unit layer cache**. Each unit - a batched RUN, a COPY, a
/// WORKDIR - is a content-addressed overlay layer keyed by the running chain key (which folds in the
/// previous key + the instruction + its context: ENV/WORKDIR/USER for RUN, the copied file contents
/// for COPY). An unchanged unit is a **cache hit** → its cached layer is stacked as a lower and the
/// unit is NOT re-executed; the first changed unit (and everything after) is a miss and re-runs.
/// Config-only instructions produce no layer: ENV/USER advance the key (they change a later RUN's
/// output), but CMD/ENTRYPOINT/EXPOSE do NOT (they only set config, never the filesystem). The tag
/// stores its base ref + ordered layer keys (`<tag>.layers`); [`resolve_image`] stacks them at run.
#[allow(clippy::too_many_arguments)]
fn build_layered_cached(
    quiet: bool,
    tag: &str,
    ctx: &std::path::Path,
    work: &std::path::Path,
    instrs: &[crate::dockerfile::Instr],
    base_ref: &str,
    base_lower: &str,
    mut config: kern_oci::ImageConfig,
) -> Result<(), Error> {
    use crate::dockerfile::Instr;
    let self_exe = std::env::current_exe()
        .map_err(|e| Error::Sandbox(format!("cannot locate the kern binary: {e}")))?;
    let lc = layer_cache_dir();
    own_only_dir(&lc).map_err(|e| Error::Sandbox(format!("layer cache: {e}")))?;
    let total = instrs.len();
    let announce = |s: usize, what: String| {
        if !quiet {
            kern_common::progress!("[{s}/{total}] {what}");
        }
    };
    // Overlay lower chain (base first); a layer dir is appended per fs-unit. `key` is the running
    // chained key; `layer_keys` are the produced layers in order (→ the tag's `.layers` manifest).
    let mut chain: Vec<String> = vec![base_lower.to_string()];
    // Seed the chain key from the RESOLVED base lower (content-addressed for a locally-built base:
    // its colon-chain of layer keys), not just the ref string - so rebuilding the base busts a child.
    let mut key = layer_key("", base_lower);
    let mut layer_keys: Vec<String> = Vec::new();
    let mut cmd_from_dockerfile = false;
    let mut unit = 0usize;
    // `.dockerignore`/`.kernignore` and the canonical context root are BUILD-INVARIANT - load + resolve
    // them ONCE here instead of re-opening/re-parsing/re-canonicalizing on every COPY instruction.
    let ig = crate::dockerignore::DockerIgnore::load(ctx);
    let ctx_root = std::fs::canonicalize(ctx).unwrap_or_else(|_| ctx.to_path_buf());
    let mut i = 1;
    while i < instrs.len() {
        // The overlay `lowerdir=` string (all layers + base) must fit ~one kernel page. Stop with a
        // clear message BEFORE the chain overflows and the mount fails with a cryptic EINVAL.
        if chain_lower(&chain).len() > MAX_LOWERDIR_BYTES {
            return Err(Error::Sandbox(
                "build has too many layers to overlay - squash consecutive RUN/COPY steps or reduce \
                 the number of instructions"
                    .into(),
            ));
        }
        let step = i + 1;
        match &instrs[i] {
            Instr::From { .. } => i += 1,
            Instr::Run(argv) => {
                // Batch consecutive shell-form RUNs (one box + one cache unit); an exec-form RUN or a
                // non-RUN ends the batch.
                let mut scripts: Vec<&str> = Vec::new();
                let mut j = i;
                while let Some(Instr::Run(a)) = instrs.get(j) {
                    match run_shell_script(a) {
                        Some(s) => {
                            scripts.push(s);
                            j += 1;
                        }
                        None => break,
                    }
                }
                let (run_argv, next, body) = if scripts.is_empty() {
                    (argv.clone(), i + 1, argv.join("\u{0}"))
                } else {
                    (combine_run_scripts(&scripts), j, scripts.join("\u{0}"))
                };
                // The key folds in the ENV/WORKDIR/USER the box runs with (they change the result).
                key = layer_key(
                    &key,
                    &format!(
                        "RUN\u{0}{body}\u{0}ENV\u{0}{}\u{0}WD\u{0}{}\u{0}U\u{0}{}",
                        config.env.join("\u{1}"),
                        config.workdir.as_deref().unwrap_or(""),
                        config.user.as_deref().unwrap_or(""),
                    ),
                );
                let hit = layer_cached(&lc, &key);
                let mark = if hit { " (cached)" } else { "" };
                if scripts.is_empty() {
                    announce(step, format!("RUN {}{mark}", display_run(argv)));
                } else {
                    for (k, s) in scripts.iter().enumerate() {
                        announce(i + 1 + k, format!("RUN {s}{mark}"));
                    }
                }
                if !hit {
                    let fresh = work.join(format!("u{unit}"));
                    let _ = std::fs::remove_dir_all(&fresh);
                    run_build_step(
                        &self_exe,
                        true,
                        &chain_lower(&chain),
                        &fresh,
                        &fresh,
                        &config,
                        &run_argv,
                        step,
                    )?;
                    let content = build_upper_dir(&fresh);
                    let _ = std::fs::remove_file(content.join("etc/resolv.conf")); // no host DNS baked in
                    commit_layer(&content, &lc, &key)?;
                    unit += 1;
                }
                chain.push(lc.join(&key).to_string_lossy().into_owned());
                layer_keys.push(key.clone());
                i = next;
            }
            Instr::Copy {
                srcs,
                dst,
                from: _,
                chmod,
            } => {
                // Expand `*`/`?`/`[…]` globs against the context before hashing, so the cache key
                // reflects the ACTUAL matched files (a new match must miss the cache).
                let expanded = expand_copy_srcs(ctx, srcs)?;
                // Hash only what a real COPY would keep: apply the context `.dockerignore` (loaded once
                // above, matched against the CANONICAL context root, like `copy_into_rootfs`) so an
                // ignored `node_modules`/`.git`/secret neither busts the key nor gets hashed at all.
                let content: Vec<String> = expanded
                    .iter()
                    .map(|s| content_hash(&ctx.join(s), &ctx_root, ig.as_ref()))
                    .collect();
                // `chmod` is part of the cache key: two builds identical but for `--chmod` must NOT
                // share a layer (else the second would inherit the first's mode).
                key = layer_key(
                    &key,
                    &format!(
                        "COPY\u{0}{dst}\u{0}CHMOD\u{0}{}\u{0}WD\u{0}{}\u{0}{}",
                        chmod.as_deref().unwrap_or(""),
                        config.workdir.as_deref().unwrap_or(""),
                        content.join(","),
                    ),
                );
                let hit = layer_cached(&lc, &key);
                announce(
                    step,
                    format!(
                        "COPY {} {dst}{}",
                        srcs.join(" "),
                        if hit { " (cached)" } else { "" }
                    ),
                );
                if !hit {
                    let fresh = work.join(format!("u{unit}"));
                    let _ = std::fs::remove_dir_all(&fresh);
                    own_only_dir(&fresh)
                        .map_err(|e| Error::Sandbox(format!("build layer: {e}")))?;
                    if expanded.len() > 1
                        && !(dst.ends_with('/')
                            || chain_has_dir(&chain, dst.trim_start_matches('/')))
                    {
                        return Err(Error::Sandbox(format!(
                            "COPY with multiple sources needs a directory destination (end '{dst}' with '/')"
                        )));
                    }
                    for s in &expanded {
                        copy_into_rootfs(
                            ctx,
                            s,
                            &fresh,
                            dst,
                            config.workdir.as_deref(),
                            &chain,
                            chmod.as_deref(),
                        )?;
                    }
                    commit_layer(&fresh, &lc, &key)?;
                    unit += 1;
                }
                chain.push(lc.join(&key).to_string_lossy().into_owned());
                layer_keys.push(key.clone());
                i += 1;
            }
            Instr::AddUrl {
                url,
                dst,
                checksum,
                chmod,
            } => {
                // Key on url + checksum + chmod + dst: with a `--checksum` this layer is fully
                // content-addressed; without one, the URL string identifies it (a changed remote
                // won't bust the cache - the documented BuildKit behaviour, so pin with --checksum).
                key = layer_key(
                    &key,
                    &format!(
                        "ADDURL\u{0}{url}\u{0}{}\u{0}{}\u{0}{dst}\u{0}WD\u{0}{}",
                        checksum.as_deref().unwrap_or(""),
                        chmod.as_deref().unwrap_or(""),
                        config.workdir.as_deref().unwrap_or(""),
                    ),
                );
                let hit = layer_cached(&lc, &key);
                announce(
                    step,
                    format!("ADD {url} {dst}{}", if hit { " (cached)" } else { "" }),
                );
                if !hit {
                    let fresh = work.join(format!("u{unit}"));
                    let _ = std::fs::remove_dir_all(&fresh);
                    own_only_dir(&fresh)
                        .map_err(|e| Error::Sandbox(format!("build layer: {e}")))?;
                    let dl = work.join(format!("addurl{unit}"));
                    let name = fetch_add_url(url, checksum.as_deref(), &dl)?;
                    apply_chmod(&dl.join(&name), chmod.as_deref())?;
                    copy_into_rootfs(
                        &dl,
                        &name,
                        &fresh,
                        dst,
                        config.workdir.as_deref(),
                        &chain,
                        None,
                    )?;
                    commit_layer(&fresh, &lc, &key)?;
                    unit += 1;
                }
                chain.push(lc.join(&key).to_string_lossy().into_owned());
                layer_keys.push(key.clone());
                i += 1;
            }
            Instr::WriteFile {
                content,
                dst,
                chmod,
            } => {
                // Content-addressed: the full body (+ chmod) is folded into the layer key (layer_key
                // hashes its whole repr), so editing the heredoc or its mode busts the cache.
                key = layer_key(
                    &key,
                    &format!(
                        "WRITEFILE\u{0}{dst}\u{0}{}\u{0}WD\u{0}{}\u{0}{content}",
                        chmod.as_deref().unwrap_or(""),
                        config.workdir.as_deref().unwrap_or(""),
                    ),
                );
                let hit = layer_cached(&lc, &key);
                announce(
                    step,
                    format!("COPY (inline) {dst}{}", if hit { " (cached)" } else { "" }),
                );
                if !hit {
                    let fresh = work.join(format!("u{unit}"));
                    let _ = std::fs::remove_dir_all(&fresh);
                    own_only_dir(&fresh)
                        .map_err(|e| Error::Sandbox(format!("build layer: {e}")))?;
                    let dl = work.join(format!("inline{unit}"));
                    write_inline_file(&dl, content)?;
                    apply_chmod(&dl.join("f"), chmod.as_deref())?;
                    copy_into_rootfs(
                        &dl,
                        "f",
                        &fresh,
                        dst,
                        config.workdir.as_deref(),
                        &chain,
                        None,
                    )?;
                    commit_layer(&fresh, &lc, &key)?;
                    unit += 1;
                }
                chain.push(lc.join(&key).to_string_lossy().into_owned());
                layer_keys.push(key.clone());
                i += 1;
            }
            Instr::Workdir(d) => {
                let wd = resolve_workdir(config.workdir.as_deref(), d);
                key = layer_key(&key, &format!("WD\u{0}{wd}"));
                let hit = layer_cached(&lc, &key);
                announce(
                    step,
                    format!("WORKDIR {wd}{}", if hit { " (cached)" } else { "" }),
                );
                if !hit {
                    let fresh = work.join(format!("u{unit}"));
                    let _ = std::fs::remove_dir_all(&fresh);
                    own_only_dir(&fresh)
                        .map_err(|e| Error::Sandbox(format!("build layer: {e}")))?;
                    mkdir_in_rootfs(&fresh, &wd)?;
                    commit_layer(&fresh, &lc, &key)?;
                    unit += 1;
                }
                chain.push(lc.join(&key).to_string_lossy().into_owned());
                layer_keys.push(key.clone());
                config.workdir = Some(wd);
                i += 1;
            }
            Instr::Env(k, v) => {
                set_config_env(&mut config.env, k, v);
                key = layer_key(&key, &format!("ENV\u{0}{k}={v}"));
                i += 1;
            }
            Instr::User(u) => {
                config.user = Some(u.clone());
                key = layer_key(&key, &format!("USER\u{0}{u}"));
                i += 1;
            }
            // CMD/ENTRYPOINT/EXPOSE change only the image CONFIG, never the filesystem - they persist
            // via `config`/`.image` and are reapplied on resolve. So they do NOT advance the layer key
            // (editing a CMD must not bust the cached RUN/COPY layers). ENV/USER above DO advance it,
            // because they change a subsequent RUN's output.
            Instr::Cmd(_) | Instr::Entrypoint(_) => {
                apply_cmd_entrypoint(&mut config, &instrs[i], &mut cmd_from_dockerfile);
                i += 1;
            }
            Instr::Expose(p) => {
                announce(
                    step,
                    format!("EXPOSE {p} (informational - publish with -p at run)"),
                );
                i += 1;
            }
        }
    }
    // Finalize: write the tag's layer manifest (base ref + ordered layer keys) + config sidecar +
    // sentinel; clear any prior form of this tag (flat dir, old .diff/.base) first.
    let cache = cache_dir();
    let safe = sanitize_ref(tag);
    let mut manifest = String::from(base_ref);
    manifest.push('\n');
    for k in &layer_keys {
        manifest.push_str(k);
        manifest.push('\n');
    }
    let _ = std::fs::remove_dir_all(cache.join(&safe));
    let _ = std::fs::remove_dir_all(cache.join(format!("{safe}.diff")));
    let _ = std::fs::remove_file(cache.join(format!("{safe}.base")));
    std::fs::write(cache.join(format!("{safe}.layers")), manifest)
        .map_err(|e| Error::Sandbox(format!("finalize image '{tag}': {e}")))?;
    write_image_config(&cache.join(format!("{safe}.image")), &config)
        .map_err(|e| Error::Sandbox(format!("image config for '{tag}': {e}")))?;
    let _ = std::fs::write(cache.join(format!("{safe}.ok")), tag.as_bytes());
    announce_built(tag);
    Ok(())
}
