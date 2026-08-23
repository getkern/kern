//! Image verbs: `pull`, `push`, `images`, `image rm`, `search`, `save`, `load`, `tag`, `commit`.
//!
//! Everything that moves an image between a registry, the local layer cache and a tarball. Split out
//! of `commands/mod.rs` for size, not for boundary: the parent still owns the box lifecycle these
//! verbs feed, so any helper BOTH sides call stays there and this module reaches it through
//! `use super::*` - the dependency runs child to parent, never back.

use super::*;

pub fn images(json: bool) -> Result<(), Error> {
    let rows = image_entries();

    if json {
        let out = kern_common::json_array(&rows, |e| {
            format!(
                "{{\"image\":{},\"size_bytes\":{},\"pulled\":{},\"dangling\":{}}}",
                json_str(&e.name),
                e.size,
                e.pulled,
                e.dangling
            )
        });
        println!("{out}");
    } else if rows.is_empty() {
        println!("no images cached yet - pull one with `kern pull <image>` (or `kern box <name> --image <image>`)");
    } else {
        let p = crate::ui::Palette::detect();
        println!(
            "{d}{:<30} {:>9}  PULLED{z}",
            "REPOSITORY",
            "SIZE",
            d = p.d,
            z = p.z
        );
        let now = registry::now_unix();
        let mut dangling = 0usize;
        for e in &rows {
            // `truncate` also strips escapes - the `.ok` sentinel content is untrusted.
            let repo = format!("{}{}{:<30}{}", p.b, p.c, truncate(&e.name, 30), p.z);
            // A dangling image shows an explicit `dangling` (yellow), never a `0 B` that reads as "empty".
            let size = if e.dangling {
                dangling += 1;
                format!("{}{:>9}{}", p.y, "dangling", p.z)
            } else {
                format!("{:>9}", human_bytes(e.size))
            };
            println!("{repo} {size}  {}", fmt_age(now.saturating_sub(e.pulled)));
        }
        if dangling > 0 {
            // `kern rmi <image>` and nothing else. This line used to offer `kern gc` as an
            // alternative and `kern gc` does not touch a dangling entry: it prunes, sweeps orphaned
            // build layers and box scratch, removes retired `--pull always` dirs and stale wait
            // records, and leaves the image list exactly as it found it. Verified on a real
            // dangling `ubuntu:latest`: it survived `gc` and went on the first `rmi`.
            //
            // Naming a command that does not work is worse here than naming none, because of what
            // the reader reaches for next: `kern gc --images` is not a bigger version of the same
            // reclaim, it calls `remove_tree_forced` on the whole cache. Someone chasing one broken
            // entry down that path deletes every image they have.
            println!(
                "{d}{dangling} dangling (missing layers) - reclaim with {z}{c}kern rmi <image>{z}",
                d = p.d,
                z = p.z,
                c = p.c
            );
        }
    }
    Ok(())
}

/// `kern rmi <image>...` - remove one or more cached images by ref (or sanitized stem). Per-image
/// feedback: what it freed on success; any unknown ref is collected and the command FAILS (non-zero
/// exit, one error listing them) so `kern rmi x && …` can't proceed on a no-op - matching `docker rmi`.
pub fn image_rm(refs: &[String]) -> Result<(), Error> {
    if refs.is_empty() {
        return Err(Error::Usage(
            "rmi <image>... - name at least one image (see `kern images`)",
        ));
    }
    let cache = cache_dir();
    let p = crate::ui::Palette::detect();
    let mut missing: Vec<&str> = Vec::new();
    for r in refs {
        match remove_image(&cache, r) {
            Some(freed) => {
                println!(
                    "{}removed{} image '{r}', freed {}",
                    p.g,
                    p.z,
                    human_bytes(freed)
                )
            }
            None => missing.push(r),
        }
    }
    if !missing.is_empty() {
        return Err(Error::Oci(format!(
            "no such image: {} - `kern images` lists cached images",
            missing.join(", ")
        )));
    }
    Ok(())
}

/// `kern search <query> [--json]` - search Docker Hub (the same registry `kern pull` uses) for
/// public images. Prints name, stars, whether it's an official image, and the description.
pub fn search(query: &str, json: bool) -> Result<(), Error> {
    let results = kern_oci::search(query, 25).map_err(|e| Error::Oci(e.to_string()))?;
    if json {
        let out = kern_common::json_array(&results, |r| {
            format!(
                "{{\"name\":{},\"description\":{},\"stars\":{},\"official\":{}}}",
                json_str(&r.name),
                json_str(&r.description),
                r.stars,
                r.official
            )
        });
        println!("{out}");
    } else if results.is_empty() {
        println!("no images found for '{query}'");
    } else {
        let p = crate::ui::Palette::detect();
        let gl = crate::ui::Glyphs::detect();
        println!(
            "{d}{:<32} {:>6} {:<8} DESCRIPTION{z}",
            "NAME",
            "STARS",
            "OFFICIAL",
            d = p.d,
            z = p.z
        );
        for r in &results {
            // NAME bold-cyan, OFFICIAL a green check, DESCRIPTION dim - all on PLAIN-padded cells so
            // alignment holds. Both name and description are untrusted (registry data) → escapes stripped.
            let name = format!("{}{}{:<32}{}", p.b, p.c, truncate(&r.name, 32), p.z);
            let official = if r.official {
                format!("{}{:<8}{}", p.g, gl.ok, p.z)
            } else {
                format!("{:<8}", "")
            };
            let desc = format!("{}{}{}", p.d, truncate(&r.description, 46), p.z);
            println!("{name} {:>6} {official} {desc}", r.stars);
        }
        println!("\npull one with:  kern pull <NAME>");
    }
    Ok(())
}

/// `kern pull <image>` - fetch an OCI image into the **image cache**, the store `--image`, `tag`,
/// `push`, `save` and `images` all read. `--dest <dir>` instead extracts a plain rootfs directory,
/// for `--rootfs` and for copying to an air-gapped host.
///
/// The default used to be the rootfs directory, in the CURRENT directory, which left three problems
/// that were measured rather than argued:
///
/// * `pull X` then `box --image X` **re-downloaded**, because the two verbs wrote to different
///   stores. Anyone pulling before going offline arrived offline without the image.
/// * every pull dropped an extracted rootfs wherever it ran. Two such directories were sitting
///   untracked in a working tree when this was found.
/// * `kern images` did not list what had just been pulled, and `tag`/`push`/`save` could not see it.
///   `examples/tag-and-push-local.sh` says "make sure we have a source image cached" above its
///   `kern pull`, and then failed with "no such image" on a clean cache. It passed only when some
///   earlier command happened to have cached the ref.
///
/// The cache fill goes through [`resolve_image_depth`], the same function `box --image` uses, so
/// there is ONE definition of the cache path, the lock, the staging swap, the `.ok` completeness
/// sentinel and the `.image` config sidecar. A second implementation here would be free to drift.
pub fn pull(image: &str, dest: Option<&str>, platform: Option<&str>) -> Result<(), Error> {
    // `--platform` cannot go to the cache: the cache key is `sanitize_ref(image)`, derived from the
    // REFERENCE alone with no platform component, and the cache path fetches the host arch. Storing a
    // foreign-arch rootfs under a host-arch key is cache poisoning, a class already fixed once in this
    // codebase. Refuse and name the flag that does work, rather than quietly writing the wrong bytes
    // or quietly falling back to a directory now that a bare pull no longer produces one.
    if platform.is_some() && dest.is_none() {
        return Err(Error::Oci(
            "--platform needs --dest <dir>: the image cache holds this host's architecture only \
             (its key carries no platform), so a foreign-arch image cannot live in it. Extract it to \
             a directory and run it with --rootfs, or on a matching host pull without --platform."
                .into(),
        ));
    }
    let Some(d) = dest else {
        return pull_into_cache(image);
    };
    let dest = PathBuf::from(d);
    // `--platform os/arch`: fetch a specific arch from a multi-arch index (default = this host). A
    // foreign arch pulls fine (for inspection/export); a heads-up if it can't run natively here.
    let plat = match platform {
        Some(p) => Some(kern_oci::Platform::parse(p).map_err(|e| Error::Oci(e.to_string()))?),
        None => None,
    };
    println!("pulling {image} -> {}", dest.display());
    kern_oci::pull(image, &dest, plat.as_ref()).map_err(|e| Error::Oci(e.to_string()))?;
    if let Some(p) = &plat {
        if !p.is_host() {
            eprintln!(
                "note: pulled linux/{} - it won't run natively on this {} host without a qemu-user + binfmt handler",
                p.as_oci_arch(),
                kern_oci::Platform::host().as_oci_arch()
            );
        }
    }
    println!(
        "done. run it: kern box <name> --rootfs {} -- /bin/sh",
        dest.display()
    );
    Ok(())
}

/// Fill the image cache for `image`, then say what happened. The whole body of work (lock, staging,
/// atomic swap, the `.ok` sentinel, the `.image` sidecar, the concurrent re-check) belongs to
/// [`resolve_image_depth`]; this only decides the POLICY and reports the outcome.
///
/// [`PullPolicy::Missing`], not `Always`: there is no blob cache, so `Always` re-downloads every byte
/// on every invocation (measured on this machine: 4.1 s then 3.3 s for the same alpine, both full
/// transfers). Re-fetching bytes already on disk is the wrong default for a tool whose argument is
/// that it does not waste anything, and "make sure it is cached" is what a pull is for. A deliberate
/// refresh is `kern box --image <ref> --pull always`, which the message points at.
fn pull_into_cache(image: &str) -> Result<(), Error> {
    let p = crate::ui::Palette::detect();
    // Was it already there? Asked BEFORE the fetch, so the message can distinguish "downloaded" from
    // "already had it" rather than guessing from a timing or a side effect.
    // The completeness sentinel is `<sanitized>.ok` NEXT TO the `<sanitized>/` directory, not inside
    // it: an entry mid-extraction has the directory and no sentinel, which is what makes a partial
    // pull read as absent.
    let key = sanitize_ref(image);
    // "Already cached" must mean RUNNABLE, not "a sentinel file exists". Asked with the same predicate
    // the pull itself uses, so the message cannot claim a hit the resolver treated as a miss.
    let had = cache_entry_complete(&cache_dir(), &key);
    let (path, _cfg) = resolve_image_depth(image, 0, PullPolicy::Missing)?;
    println!(
        "{g}{}{z} {image}",
        if had { "already cached" } else { "pulled" },
        g = p.g,
        z = p.z
    );
    println!(
        "{d}  run it:  kern box <name> --image {image} -- /bin/sh{z}",
        d = p.d,
        z = p.z
    );
    println!(
        "{d}  cached at {path}  ·  `kern images` lists it  ·  refresh with `--pull always`{z}",
        d = p.d,
        z = p.z
    );
    Ok(())
}

/// `kern push <local-ref> [as <remote-ref>]` - publish a locally-cached image to a registry as a
/// single-layer OCI image. The image must be present in the cache (pull/build it first). A push to a
/// private repo needs `kern login`. The rootfs is materialized (flat cache dir, or the overlay chain
/// squashed) and packed into one layer.
pub fn push(local_ref: &str, remote_ref: Option<&str>) -> Result<(), Error> {
    let remote = remote_ref.unwrap_or(local_ref);
    // Materialize the image to a single rootfs directory. A flat pulled image IS a cache dir; a
    // layered/built image is squashed into a temp dir via its overlay chain so we push one layer.
    let (rootfs, config, cleanup) = materialize_image(local_ref)?;
    let cfg = kern_oci::ImageConfigOut {
        entrypoint: config.entrypoint,
        cmd: config.cmd,
        env: config.env,
        workdir: config.workdir,
        user: config.user,
    };
    // Scratch dir for the layer/config blobs, cleaned up on exit.
    let work = cache_dir().join(format!(".push-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| Error::Oci(format!("push work dir: {e}")))?;

    let result =
        kern_oci::push(remote, &rootfs, &cfg, &work).map_err(|e| Error::Oci(e.to_string()));

    let _ = std::fs::remove_dir_all(&work);
    if let Some(tmp) = cleanup {
        remove_build_tree(&tmp); // squashed rootfs (overlay merge) → force-clean mode-000 dirs
    }
    result
}

pub fn save(image: &str, out: Option<&str>) -> Result<(), Error> {
    // `-o` writes a tar to a host path: refuse a registry destination, or `save img -o <runtime>/kern/…`
    // would clobber a peer's posture record (same WRITE class as `kern cp` box→host).
    if let Some(o) = out {
        crate::secret::guard_host_write_path(o, "save -o")?;
    }
    let (rootfs, config, cleanup) = materialize_image(image)?;
    let cfg = kern_oci::ImageConfigOut {
        entrypoint: config.entrypoint,
        cmd: config.cmd,
        env: config.env,
        workdir: config.workdir,
        user: config.user,
    };
    let work = cache_dir().join(format!(".save-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| Error::Oci(format!("save work dir: {e}")))?;
    // `docker load` REJECTS a bare repo with no tag ("invalid tag 'alpine'"), so the RepoTag must be a
    // full `repo:tag` - normalise a tagless ref to `…:latest` (matching how `docker save alpine` writes
    // `alpine:latest`). Keeps kern↔docker save/load interop working for the common `kern save alpine`.
    let repo_tag = ensure_repo_tag(image);
    let result = kern_oci::save(
        &rootfs,
        &cfg,
        std::slice::from_ref(&repo_tag),
        out.map(std::path::Path::new),
        &work,
    )
    .map_err(|e| Error::Oci(e.to_string()));
    let _ = std::fs::remove_dir_all(&work);
    if let Some(tmp) = cleanup {
        remove_build_tree(&tmp);
    }
    if result.is_ok() {
        // On stderr so a `kern save img > img.tar` (stdout) stream stays clean.
        eprintln!(
            "✓ saved '{image}'{}",
            out.map(|o| format!(" → {o}")).unwrap_or_default()
        );
    }
    result
}

/// `kern load [-i file]` - import an image from a `docker save`-format tar (kern's OR docker's), file
/// or stdin. Every tar is vetted + extracted through the SAME hardened path as `pull` (an archive is
/// as untrusted as a registry image).
pub fn load(input: Option<&str>) -> Result<(), Error> {
    let cache = cache_dir();
    own_only_dir(&cache).map_err(|e| Error::Oci(format!("cache dir: {e}")))?;
    let work = cache.join(format!(".load-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let loaded = kern_oci::load(input.map(std::path::Path::new), &work)
        .map_err(|e| Error::Oci(e.to_string()));
    let loaded = match loaded {
        Ok(l) => l,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&work);
            return Err(e);
        }
    };
    for img in &loaded {
        let Some(primary) = img.repo_tags.first() else {
            eprintln!("kern: loaded an untagged image (skipped - no name to reference it by)");
            continue;
        };
        let safe = sanitize_ref(primary);
        let dest = cache.join(&safe);
        let _ = std::fs::remove_dir_all(&dest);
        // Place the assembled rootfs as the image's cache dir + write the sentinel and config sidecar,
        // the exact on-disk shape of a flat pulled image (so `box --image <tag>` / `images` see it).
        std::fs::rename(&img.rootfs, &dest).map_err(|e| Error::Oci(format!("load rootfs: {e}")))?;
        std::fs::write(cache.join(format!("{safe}.ok")), primary.as_bytes())
            .map_err(|e| Error::Oci(format!("load sentinel: {e}")))?;
        write_image_config(&cache.join(format!("{safe}.image")), &img.config)
            .map_err(|e| Error::Oci(format!("load image config: {e}")))?;
        println!("loaded '{primary}'");
        // Extra RepoTags become aliases (content-shared where possible), like `docker load`.
        for t in img.repo_tags.iter().skip(1) {
            if tag(primary, t).is_ok() {
                println!("loaded '{t}'");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&work);
    Ok(())
}

/// `kern tag <src> <dst>` - give a cached image a second name, so `build -t x` then `tag x y:1.0` then
/// `push y:1.0` works like Docker. Content-addressed: the shared `L/` build layers are NOT duplicated -
/// a layered image's `.layers` manifest is copied and simply references the same layer keys (which `gc`
/// keeps alive while ANY `.layers` names them). A flat/single-diff image's rootfs dir IS copied (it's the
/// image's own bytes). Both names are `sanitize_ref`'d, so a `dst` like `../../etc` can't escape the cache
/// (it maps to a safe key) - the same collision-free key rule as every other cache path.
pub fn tag(src: &str, dst: &str) -> Result<(), Error> {
    let cache = cache_dir();
    own_only_dir(&cache).map_err(|e| Error::Oci(format!("cache dir: {e}")))?;
    let src_safe = sanitize_ref(src);
    let dst_safe = sanitize_ref(dst);
    if src_safe == dst_safe {
        return Ok(()); // tagging to the same key is a no-op (not an error, like Docker)
    }
    // The `.ok` marker is the "this image exists" sentinel - its absence means not cached.
    let src_ok = cache.join(format!("{src_safe}.ok"));
    if !src_ok.exists() {
        return Err(Error::Oci(format!(
            "no such image '{src}' - `kern images` lists cached images"
        )));
    }
    // Clear any PRIOR image at `dst` FIRST (all forms) - otherwise re-tagging over an existing image
    // would leave stale files from the old one (a hybrid rootfs) or a mismatched sidecar. Like Docker,
    // a tag REPLACES the destination. The `.ok` marker is written LAST (below), so an interrupted
    // re-tag can't leave a half-image that `images`/`push` treats as valid.
    //
    // This ran AFTER the `.image` copy and deleted the sidecar that copy had just written, so every
    // tagged image lost its entrypoint/cmd/env/workdir/user: `kern tag app app2` produced an `app2`
    // that refused to run with "this image declares no entrypoint or command". The clear has to come
    // before anything is written to `dst`, not after.
    if src_safe != dst_safe {
        let _ = std::fs::remove_file(cache.join(format!("{dst_safe}.ok")));
        for suffix in ["", ".diff", ".layers", ".base", ".image"] {
            let p = cache.join(format!("{dst_safe}{suffix}"));
            let _ = std::fs::remove_dir_all(&p);
            let _ = std::fs::remove_file(&p);
        }
    }
    // Copy the config sidecar (best-effort: an old image may predate it).
    let cp_file = |suffix: &str| -> Result<(), Error> {
        let from = cache.join(format!("{src_safe}{suffix}"));
        if from.exists() {
            std::fs::copy(&from, cache.join(format!("{dst_safe}{suffix}")))
                .map_err(|e| Error::Oci(format!("tag {suffix}: {e}")))?;
        }
        Ok(())
    };
    cp_file(".image")?;
    // Copy the rootfs form. Exactly one of these exists per image (mirrors `materialize_image`):
    //  - flat pulled image:  `<safe>/`         → copy the dir (the image's own bytes)
    //  - single-diff build:  `<safe>.diff/`    → copy the dir
    //  - multi-layer build:  `<safe>.layers` (+ `.base`) → copy the manifest files; `L/` layers are
    //    shared/content-addressed and referenced, never duplicated.
    let flat = cache.join(&src_safe);
    let diff = cache.join(format!("{src_safe}.diff"));
    let layers = cache.join(format!("{src_safe}.layers"));
    if flat.is_dir() {
        copy_tree(&flat, &cache.join(&dst_safe))?;
    } else if layers.exists() {
        cp_file(".layers")?;
        cp_file(".base")?;
    } else if diff.is_dir() {
        // A single-diff image is `<safe>.diff/` stacked over its `<safe>.base` marker (the base ref) -
        // `resolve_image` needs BOTH, so copy the diff dir AND the base marker, or the tag would fail to
        // resolve (no `.base` → fall through to a re-pull).
        copy_tree(&diff, &cache.join(format!("{dst_safe}.diff")))?;
        cp_file(".base")?;
    } else {
        return Err(Error::Oci(format!(
            "image '{src}' is cached but has no rootfs form - try re-pulling"
        )));
    }
    // Write the `.ok` marker LAST (so an interrupted tag leaves no half-image that `images`/`push` sees),
    // storing the human `dst` ref as its content (what `kern images` displays).
    std::fs::write(cache.join(format!("{dst_safe}.ok")), dst.as_bytes())
        .map_err(|e| Error::Oci(format!("tag marker: {e}")))?;
    println!("tagged '{src}' → '{dst}'");
    Ok(())
}

/// `kern commit <box> <image>`: snapshot a RUNNING box's current filesystem into a reusable local
/// image, so an expensive setup (apt/pip installs, warmed caches, compiled artifacts) is baked once and
/// the next `kern box --image <image>` starts warm. This is kern's answer to a "resume the session"
/// workflow WITHOUT CRIU: it captures the FILESYSTEM, not live memory, so processes restart fresh (write
/// state to disk if you need it back). Docker's `commit`, daemonless.
///
/// The box's kernel-MERGED overlay view is read straight from `/proc/<pid1>/root` (the same confined
/// handle `kern cp` uses), so overlay whiteouts and opaque dirs are already resolved by the kernel, no
/// manual layer-flattening. The copy stays on the rootfs's own filesystem, so every separate mount (the
/// box's `/proc`, `/sys`, `/dev`, `/dev/shm`, and every `-v` volume / workspace / secret) is skipped
/// automatically: the snapshot is the image content, never a bind-mounted host path.
///
/// Consistency under active writes: where the box has a dedicated cgroup (systemd-user delegation, or
/// root), commit FREEZES it for the snapshot so files are captured whole. Where it does NOT (a host
/// without cgroup delegation), the freeze is a no-op and a file the workload is actively rewriting can be
/// captured MID-WRITE, i.e. TRUNCATED to a valid prefix, not byte-corrupted (a `commit` of a box in the
/// middle of `echo … > big` may yield a shorter `big`). It is never a torn mix of old+new bytes; for a
/// structured file (a DB, a tar) that truncation still means "quiesce the box, or use --memory-backed
/// scratch, before committing under heavy write load". Freeze support is what the boards/prod provide.
pub fn commit(box_ref: &str, image: &str) -> Result<(), Error> {
    let inst = registry::find_ref(box_ref).ok_or_else(|| {
        Error::Sandbox(format!("no running box '{box_ref}'; `kern ps` lists them"))
    })?;
    // PID 1 inside the box: the registry value when known, else the supervisor's sole child.
    let pid1 = if inst.pid1 > 0 {
        inst.pid1
    } else {
        registry::child_of(inst.pid).ok_or_else(|| {
            Error::Sandbox(format!(
                "box '{box_ref}' has no resolvable init pid (is it still running?)"
            ))
        })?
    };
    let root = std::path::PathBuf::from(format!("/proc/{pid1}/root"));
    std::fs::metadata(&root).map_err(|e| {
        Error::Sandbox(format!(
            "box '{box_ref}' is not accessible ({e}); is it running?"
        ))
    })?;
    // The set of NESTED mount points to skip: the box's `/proc`, `/sys/fs/cgroup`, `/dev` (+ its device
    // nodes and `/dev/shm`), and every `-v` volume / workspace / secret. Read from the box's own mount
    // table so nothing outside the image's own filesystem is baked in (a secret in a volume must never
    // land in the committed image). NOT filterable by `st_dev`: overlayfs (xino=off) reports a different
    // device per underlying layer, so the rootfs itself spans several devices.
    let skip = box_mount_points(pid1);

    let cache = cache_dir();
    own_only_dir(&cache).map_err(|e| Error::Oci(format!("cache dir: {e}")))?;
    let dst_safe = sanitize_ref(image);
    // Replace any prior image at this ref (all rootfs forms + sidecars), exactly like `tag`. The `.ok`
    // marker is written LAST, so an interrupted commit never leaves a half-image that `images` trusts.
    let _ = std::fs::remove_file(cache.join(format!("{dst_safe}.ok")));
    for suffix in ["", ".diff", ".layers", ".base", ".image"] {
        let p = cache.join(format!("{dst_safe}{suffix}"));
        let _ = std::fs::remove_dir_all(&p);
        let _ = std::fs::remove_file(&p);
    }
    let out = cache.join(&dst_safe);
    // Freeze the box for the snapshot so the workload cannot swap a file between our metadata read and the
    // content copy (a commit-time TOCTOU): a frozen cgroup runs no task. Best-effort and RAII: a box with
    // no dedicated cgroup simply isn't frozen (as `pause` reports), and the guard thaws on EVERY exit,
    // including the `?` early return from the copy below.
    let _freeze = FreezeGuard::freeze(inst.cgroup_pid());
    copy_rootfs_snapshot(&root, &out, &skip)?;
    drop(_freeze); // thaw before the (non-filesystem) config/marker writes below

    // A minimal runtime config: default the command to a shell so `kern box --image <image>` works with
    // no args, while `--image <image> -- <cmd>` still overrides it. (The base image's entrypoint/env are
    // OCI metadata, not part of the rootfs, so a filesystem snapshot can't recover them; pass what you
    // need explicitly; this matches `docker commit` without `--change`.)
    let cfg = kern_oci::ImageConfig {
        entrypoint: Vec::new(),
        cmd: vec!["/bin/sh".to_string()],
        env: Vec::new(),
        workdir: None,
        user: None,
        exposed_ports: Vec::new(),
    };
    write_image_config(&cache.join(format!("{dst_safe}.image")), &cfg)
        .map_err(|e| Error::Oci(format!("commit image config: {e}")))?;
    std::fs::write(cache.join(format!("{dst_safe}.ok")), image.as_bytes())
        .map_err(|e| Error::Oci(format!("commit marker: {e}")))?;
    println!("committed box '{box_ref}' → image '{image}'  (run: kern box <name> --image {image})");
    Ok(())
}
