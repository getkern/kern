//! The image cache: the layer store, and everything that fills, reads or reaps it.
//!
//! A SUPPORT module, not a verb. `build`, `images`, `start` and `system` all reach into the same
//! store, so putting these next to one verb would make the others depend on a sibling. They live
//! here, the parent re-exports them to the crate, and every call site resolves exactly as before -
//! `commands::pull_to_cache` still names this function.
//!
//! Contents: reference resolution and the on-disk layout, the puller, the content hash that keys a
//! build layer, the flat-image fast path, the sweepers for orphaned layers and retired images, and
//! the OCI config accessors (`Config.User`, `Cmd`/`Entrypoint`).

use super::*;

/// Does kern turn the subordinate uid range on for this box BY DEFAULT, because it is an OCI image
/// box? The single statement of that rule on the box side: the real run and the `--show-config` dry
/// run both call it, so the dry run cannot report a range the box will not get, or miss one it will.
/// It reported `uid_range: false` for every image box for exactly as long as this was written twice.
pub(crate) fn image_default_uid_range(args: &BoxRunArgs) -> bool {
    args.image.is_some() && !args.no_uid_range
}

/// Resolve the box's effective command from the user's `-- CMD` and the image's OCI config, docker-
/// style: the image `Entrypoint` is prepended to either the user's command or (if none) the image's
/// `Cmd`; a shell is the fallback when nothing is set anywhere. `--ssh` with no command keeps the box
/// alive instead (the sshd is a child of PID 1, which would otherwise exit). For `--rootfs` the
/// config is empty, so this reduces to the user's command or a shell - the prior behaviour.
pub(crate) fn resolve_image_command(
    user_command: &[String],
    ssh: bool,
    img: &kern_oci::ImageConfig,
) -> Vec<String> {
    if user_command.is_empty() && ssh {
        return vec!["sleep".to_string(), "infinity".to_string()];
    }
    let args: Vec<String> = if user_command.is_empty() {
        img.cmd.clone()
    } else {
        user_command.to_vec()
    };
    let mut full = img.entrypoint.clone();
    full.extend(args);
    if full.is_empty() {
        // The image told us NOTHING to run and the caller gave no command. That is not "run a
        // shell": it means the cached image config is missing (an entry pulled by an older kern, or
        // a pull that never wrote its sidecar). Falling back silently produced a box that exec'd
        // `/bin/sh`, exited immediately under `-d`, and left no log at all - a failure with no
        // trace, which is exactly what this codebase refuses.
        //
        // The fallback stays (a shell is still the useful thing for an interactive box), but it is
        // now announced, with the way to fix the cache entry.
        if user_command.is_empty() {
            eprintln!(
                "kern: this image declares no entrypoint or command in kern's cache, so the box runs \
                 `{DEFAULT_SHELL}` - which exits at once when detached. Repair the cache entry with \
                 `--pull always`, or pass the command explicitly after `--`."
            );
        }
        full.push(DEFAULT_SHELL.to_string());
    }
    full
}

/// Serialize an image's OCI runtime config to a small tab-delimited sidecar (one directive per line)
/// so `kern box --image` can reapply it on a cache hit without re-pulling. Kept OUTSIDE the rootfs
/// (a sibling of the cache dir) so the file never appears inside the box.
/// Write an image's config sidecar (`<ref>.image`): entrypoint, cmd, env, workdir, user.
///
/// FALLIBLE. It returned `()` and discarded the write, which is not the same trade as the `.ok`
/// sentinel written beside it. A missing SENTINEL means the image is not recognised and the next run
/// re-pulls or rebuilds it: wasteful, self-correcting, and visible. A missing CONFIG means the image
/// IS recognised and simply has no entrypoint, no env and no user, so the box silently falls back to
/// a shell and the workload runs with a different identity and environment than the image declares.
/// That is a wrong state, not lost work, and every caller now refuses rather than publishing it.
pub(crate) fn write_image_config(
    path: &std::path::Path,
    c: &kern_oci::ImageConfig,
) -> std::io::Result<()> {
    let mut s = String::new();
    let mut line = |k: &str, v: &str| {
        // A value with an embedded newline can't round-trip line-based; such values don't occur in
        // real image configs, so skip one defensively rather than corrupt the file.
        if !v.contains('\n') {
            s.push_str(k);
            s.push('\t');
            s.push_str(v);
            s.push('\n');
        }
    };
    for a in &c.entrypoint {
        line("entrypoint", a);
    }
    for a in &c.cmd {
        line("cmd", a);
    }
    for e in &c.env {
        line("env", e);
    }
    if let Some(w) = &c.workdir {
        line("workdir", w);
    }
    if let Some(u) = &c.user {
        line("user", u);
    }
    for (port, udp) in &c.exposed_ports {
        line(
            "expose",
            &format!("{port}/{}", if *udp { "udp" } else { "tcp" }),
        );
    }
    std::fs::write(path, s)
}

/// Read back a [`write_image_config`] sidecar. A missing/garbled file yields the default config.
pub(crate) fn read_image_config(path: &std::path::Path) -> kern_oci::ImageConfig {
    let mut c = kern_oci::ImageConfig::default();
    let Ok(body) = std::fs::read_to_string(path) else {
        return c;
    };
    for l in body.lines() {
        let Some((k, v)) = l.split_once('\t') else {
            continue;
        };
        match k {
            "entrypoint" => c.entrypoint.push(v.to_string()),
            "cmd" => c.cmd.push(v.to_string()),
            "env" => c.env.push(v.to_string()),
            "workdir" => c.workdir = Some(v.to_string()),
            "user" => c.user = Some(v.to_string()),
            "expose" => {
                if let Some((num, proto)) = v.split_once('/') {
                    if let Ok(port) = num.parse::<u16>() {
                        c.exposed_ports
                            .push((port, proto.eq_ignore_ascii_case("udp")));
                    }
                }
            }
            _ => {}
        }
    }
    c
}

/// Look up `name` in a colon-line account file (`passwd`/`group`) inside the image rootfs and return the
/// matched line's colon-separated FIELDS, read and scanned ONCE. `lower` is the box's lower spec - a
/// single dir for a flat image, or an overlay chain `top:…:base`; the file is read from the FIRST layer
/// that has it (top-most wins, as the merged view would). `None` if no layer has the file or it has no
/// matching entry - the caller then keeps box-root behaviour. Returning the whole entry lets
/// `resolve_image_user` take uid (field 2) AND primary gid (field 3) from ONE passwd read, not two.
///
/// CONFINED to the rootfs: this reads PRE-PIVOT, on the host, so a hostile image whose `/etc/passwd` is a
/// symlink to a host path (`/etc/passwd`, `../../../etc/passwd`) would otherwise make kern read a host
/// file. That leaks nothing to the box (only a uid is extracted) and grants nothing (the image controls
/// `USER` anyway), but kern must not follow an image symlink onto host paths - the same confinement the
/// `-v` guard enforces. Canonicalize the target and require it stays under the canonical layer; a symlink
/// that escapes is treated as "no file in this layer" (try the next, else fall back to box-root). An
/// in-rootfs symlink (a real distro layout) still resolves, since its target stays under the layer.
pub(crate) fn image_account_entry(lower: &str, file: &str, name: &str) -> Option<Vec<String>> {
    use std::path::Path;
    for layer in lower.split(':') {
        let (Ok(target), Ok(base)) = (
            std::fs::canonicalize(Path::new(layer).join(file)),
            std::fs::canonicalize(layer),
        ) else {
            continue; // no such file in this layer (or an unresolvable path); try the next
        };
        if !target.starts_with(&base) {
            continue; // the image symlinked the account file OUT of the rootfs - do not read host paths
        }
        let Ok(text) = std::fs::read_to_string(&target) else {
            continue;
        };
        for line in text.lines() {
            if line.split(':').next() == Some(name) {
                return Some(line.split(':').map(str::to_string).collect());
            }
        }
        return None; // the file exists in this (top-most) layer but has no such entry - authoritative
    }
    None
}

/// Resolve an image's `config.User` spec (`user[:group]`, each a NAME or a number) to `(uid, gid)` using
/// the image's OWN `/etc/passwd` and `/etc/group`, exactly as Docker does. The rootfs is already
/// extracted on the host pre-pivot, so `USER memcache` no longer forces the box to run as root: it maps
/// to that account's uid/gid. Docker's rule - a bare user takes its primary group from the passwd entry;
/// an explicit `:group` overrides it. Returns `None` (caller keeps box-root, with a note) if the account
/// isn't in the image, so an image referencing a host-provided name still degrades honestly.
pub(crate) fn resolve_image_user(spec: &str, lower: &str) -> Option<(u32, u32)> {
    let (user, group) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    // The user half yields both a uid and (for a bare `USER name`) the default gid from its ONE passwd
    // line: fields are `name:x:uid:gid:…`, so index 2 is the uid and 3 the primary gid.
    let (uid, passwd_gid) = match user.parse::<u32>() {
        Ok(n) => (n, n),
        Err(_) => {
            let e = image_account_entry(lower, "etc/passwd", user)?;
            (e.get(2)?.parse().ok()?, e.get(3)?.parse().ok()?)
        }
    };
    let gid = match group {
        None => passwd_gid,
        // `group` fields are `name:x:gid:…`, so index 2 is the gid.
        Some(g) => match g.parse::<u32>() {
            Ok(n) => n,
            Err(_) => image_account_entry(lower, "etc/group", g)?
                .get(2)?
                .parse()
                .ok()?,
        },
    };
    Some((uid, gid))
}

/// `kern gc [--images]` - `prune` the dead-box sidecars, and with `--images` also reclaim the pulled
/// OCI image cache. Never touches a running box or a partially-in-use image dir.
/// Remove retired (`<ref>.old-*`) and abandoned staging (`<ref>.pull-*`) image dirs left by a
/// `--pull always` swap. Returns the count removed. Fail-safe on two axes. First: it only runs when no
/// REGISTERED box is live (a foreground/detached box may still reference a retired dir via its overlay
/// mount, and stays registered for the whole mount lifetime). Second: it skips a leftover whose creator
/// pid is still alive (an in-flight concurrent pull). Per-dir errors are swallowed so one stuck dir
/// never aborts the sweep. Known residual: an interactive `-it` box is not registered, so a concurrent
/// `--pull always` and `gc` racing the exact image it holds could still yank a lower it opens lazily;
/// tracked separately (interactive-box registration).
pub(crate) fn sweep_retired_images() -> usize {
    if !registry::list().is_empty() {
        return 0; // a live (registered) box might still reference a retired image dir
    }
    let cache = cache_dir();
    let mut n = 0usize;
    if let Ok(rd) = std::fs::read_dir(&cache) {
        for e in rd.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            // Only `<ref>.old-<pid>` / `<ref>.pull-<pid>` swap leftovers (take the LAST marker).
            let Some((_, pid_str)) = name
                .rsplit_once(".old-")
                .or_else(|| name.rsplit_once(".pull-"))
            else {
                continue;
            };
            // Skip a leftover whose creator process is still ALIVE: a `.pull-<pid>` may be an in-flight
            // concurrent `--pull always` writing its staging dir. A parse failure or a dead pid falls
            // through to deletion; pid reuse only delays cleanup, it never deletes early.
            if let Ok(pid) = pid_str.parse::<i32>() {
                if pid > 0 && unsafe { libc::kill(pid, 0) } == 0 {
                    continue;
                }
            }
            if e.path().is_dir() && std::fs::remove_dir_all(e.path()).is_ok() {
                n += 1;
            }
        }
    }
    n
}

/// Delete build-layer dirs in `L/` not referenced by any `<tag>.layers` manifest. Returns
/// `(count, bytes_freed)`. Only touches `L/<32hex>` entries, never a pulled/built image itself.
pub(crate) fn sweep_orphan_layers(cache: &std::path::Path) -> (usize, u64) {
    // The cache is a PARAMETER, not `cache_dir()`. `remove_image` already takes one so it can be
    // driven against a temp tree by a test, and this call ignored it and swept the real user cache -
    // so a unit test deleting from a fabricated cache reached into the developer's layer store.
    let lc = cache.join("L");
    // Collect every layer key still referenced by some image's `.layers` manifest. This set is used
    // to decide what to DELETE, so it must be COMPLETE: if we can't read a manifest (transient IO /
    // permission error), a layer referenced only by it would look orphaned and be wrongly deleted.
    // Fail closed - abort the whole sweep (delete nothing) rather than sweep on a partial set.
    let mut referenced = std::collections::HashSet::new();
    if let Ok(rd) = std::fs::read_dir(cache) {
        for e in rd.flatten() {
            if e.path().extension().and_then(|s| s.to_str()) == Some("layers") {
                match std::fs::read_to_string(e.path()) {
                    Ok(body) => {
                        for k in body.lines().skip(1).map(str::trim) {
                            referenced.insert(k.to_string());
                        }
                    }
                    Err(_) => return (0, 0), // incomplete reference set → don't risk deleting live layers
                }
            }
        }
    }
    let (mut count, mut freed) = (0usize, 0u64);
    let Ok(rd) = std::fs::read_dir(&lc) else {
        return (0, 0);
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        // Only reap `<32hex>` layer dirs (and their `.ok`); a `.ok` is handled with its dir.
        let key = name.strip_suffix(".ok").unwrap_or(&name);
        if key.len() != 32
            || !key.bytes().all(|b| b.is_ascii_hexdigit())
            || referenced.contains(key)
        {
            continue;
        }
        if e.path().is_dir() {
            freed += dir_size(&e.path());
            if std::fs::remove_dir_all(e.path()).is_ok() {
                count += 1;
            }
        } else {
            let _ = std::fs::remove_file(e.path()); // an orphaned `.ok`
        }
    }
    (count, freed)
}

/// On-disk `(size_bytes, dangling)` of cached image `<stem>`, computed in ONE pass - a flat pulled
/// image (`<stem>/`) or single-diff build (`<stem>.diff/`) is sized by its dir and never dangles; a
/// multi-layer build sums its referenced `L/<key>` dirs AND dangles if any is missing (a present but
/// 0-byte layer is a valid EMPTY build, not dangling); a sentinel with no payload at all dangles. Both
/// `kern images` and the build-history record read this, so size and health can't drift, and each
/// manifest/layer is stat'd once. The layer cache is `<cache>/L` (== [`layer_cache_dir`] when `cache`
/// is [`cache_dir`]), derived from the arg so it stays consistent with the entry and is testable.
pub(crate) fn image_stat(cache: &std::path::Path, stem: &str) -> (u64, bool) {
    // The sentinel is written once, AFTER extraction completes, so its mtime is exactly "this image's
    // content version": it is the right thing to stamp the memoised size against.
    let sentinel = cache.join(format!("{stem}.ok"));
    let flat = cache.join(stem);
    if flat.is_dir() {
        return (dir_size_cached(&flat, &sentinel), false);
    }
    let diff = cache.join(format!("{stem}.diff"));
    if diff.is_dir() {
        return (dir_size_cached(&diff, &sentinel), false);
    }
    match std::fs::read_to_string(cache.join(format!("{stem}.layers"))) {
        Ok(body) => {
            let lc = cache.join("L");
            let (mut size, mut dangling) = (0u64, false);
            for key in body
                .lines()
                .skip(1) // line 0 is the base ref, not an `L/` key
                .map(str::trim)
                .filter(|k| !k.is_empty())
            {
                let d = lc.join(key);
                if d.is_dir() {
                    // Stamped against the layer directory itself, not the image sentinel: an `L/` layer
                    // is SHARED between images, so keying it per-image would recompute it once per
                    // referrer and cache the same bytes several times over.
                    size += dir_size_cached(&d, &d);
                } else {
                    dangling = true; // a referenced layer is gone → the image can't be assembled
                }
            }
            (size, dangling)
        }
        Err(_) => (0, true), // no flat / no diff / no manifest → nothing to run
    }
}

/// A stem is a real [`sanitize_ref`] token only when it's non-empty and every byte is `[A-Za-z0-9_-]`.
/// Delete paths gate on this so a **planted** `.ok` filename can never steer a removal outside the
/// cache: e.g. a file literally named `...ok` has `Path::file_stem() == ".."`, which unchecked would
/// make `cache.join(stem)` resolve to the cache's PARENT - `is_safe_stem` rejects it (`.` isn't allowed).
pub(crate) fn is_safe_stem(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The on-disk artifacts of cached image `<stem>`: the flat rootfs dir, a single-diff dir, and the
/// `.layers`/`.base`/`.image`/`.ok`/`.lock` sidecars. ONE place owns this list so every remover (`rmi`,
/// untag, temp-stage drop) deletes the SAME set and can't drift - a leaked `.base`/`.image` would
/// otherwise linger and misclassify a later same-name pull. Best-effort; a missing artifact is fine.
/// `stem` MUST already be a [`sanitize_ref`] token (see [`is_safe_stem`]) - never raw user input.
pub(crate) fn drop_image_artifacts(cache: &std::path::Path, stem: &str) {
    force_remove_dir_all(&cache.join(stem));
    force_remove_dir_all(&cache.join(format!("{stem}.diff")));
    for suffix in [
        ".layers",
        ".base",
        ".image",
        ".ok",
        ".lock",
        ".flatkey",
        ".size",
        ".diff.size",
    ] {
        let _ = std::fs::remove_file(cache.join(format!("{stem}{suffix}")));
    }
}

/// `remove_dir_all`, retried after restoring owner write+search on the tree.
///
/// An image layer can carry a directory with no owner write bit (`dr-xr-xr-x` is ordinary in
/// Fedora-based images: `quay.io/podman/stable` has hundreds). Unlinking a file needs write on its
/// PARENT, so `remove_dir_all` stops at the first such directory and leaves the rest on disk.
/// `rmi` then reported the size it had measured BEFORE deleting: measured on that image, it said
/// "freed 600.5M" and left **456 MB** behind. Saying a thing happened when it did not is the
/// costliest kind of defect here, and on an SD-card board it is the difference between a full disk
/// and an empty one.
///
/// We own the cache (0700, created by us), so restoring `u+rwX` on our own copy changes nothing an
/// image can observe: the extracted modes are a property of the layer, not of a running box, and
/// this path runs only when that copy is being destroyed.
pub(crate) fn force_remove_dir_all(path: &std::path::Path) {
    // The SAME walk `remove_tree_forced` performs, with the error discarded: callers here are
    // best-effort cleanups where a leftover is not worth failing a command over. There used to be two
    // copies of the chmod-descend logic, one of which also swallowed the reason it failed, which is
    // how `kern gc --images` reported success over an untouched cache. One implementation now, two
    // call styles.
    let _ = remove_tree_forced(path);
}

/// Delete one cached image, resolved by its ref (as shown in `kern images`) OR its sanitized stem, then
/// sweep any `L/` layers left referenced by no remaining image (shared layers survive). Returns bytes
/// freed, or `None` if nothing matched. Resolution scans the `.ok` sentinels and prefers an exact REF
/// (sentinel content) match over a stem match, so an image whose ref happens to equal another's stem
/// can't be deleted by accident. Entries with an unsafe stem or an unreadable sentinel are skipped - a
/// crafted name never steers the delete, and an empty `want` matches nothing.
pub(crate) fn remove_image(cache: &std::path::Path, want: &str) -> Option<u64> {
    if want.is_empty() {
        return None;
    }
    let want_norm = kern_oci::normalize_ref(want);
    // ALL ref matches, not the first. One reference can map to more than one cache entry: an image
    // pulled as `alpine` by a kern older than 0.6.23 sits under a different key than the same image
    // pulled as `alpine:latest`, and both normalize to one reference. They are the same image, so
    // `rmi alpine` removes both and reports the total. Removing one and leaving the other listed
    // under an identical name would look like the delete had failed.
    let mut by_ref: Vec<String> = Vec::new();
    let mut by_stem = None;
    if let Ok(rd) = std::fs::read_dir(cache) {
        for e in rd.flatten() {
            let path = e.path();
            if path.extension().and_then(|s| s.to_str()) != Some("ok") {
                continue;
            }
            let Some(st) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if !is_safe_stem(st) {
                continue; // a planted `...ok` (stem `..`) is never a delete target
            }
            if st == want {
                by_stem = Some(st.to_string());
            }
            // Only a READABLE sentinel counts as a ref match - never default to matching "".
            // BOTH sides get their implied tag first: the sentinel records the reference as it was
            // first written, which is `alpine` for a `--image alpine` pull and `provalocale:latest`
            // for a `load`. Comparing the raw strings meant `rmi provalocale` could not delete an
            // image that `kern images` was listing right in front of you.
            if let Ok(content) = std::fs::read_to_string(&path) {
                if kern_oci::normalize_ref(content.trim()) == want_norm {
                    by_ref.push(st.to_string());
                }
            }
        }
    }
    // A ref match still wins over a stem match, so an image whose ref equals another's stem cannot be
    // deleted by accident.
    let stems: Vec<String> = if by_ref.is_empty() {
        vec![by_stem?]
    } else {
        by_ref
    };
    // Each image's OWN on-disk payload (flat + single-diff), measured before removal. A multi-layer
    // image owns no dir here - its bytes live in the shared `L/` cache, accounted by the orphan sweep
    // below.
    let mut freed = 0u64;
    for stem in &stems {
        let flat = cache.join(stem);
        let diff = cache.join(format!("{stem}.diff"));
        if flat.is_dir() {
            freed += dir_size(&flat);
        }
        if diff.is_dir() {
            freed += dir_size(&diff);
        }
        drop_image_artifacts(cache, stem);
    }
    // Reclaim layers this image was the last to reference (the sweep fails closed, so a shared layer is
    // never dropped while another image's manifest still names it).
    let (_, layer_freed) = sweep_orphan_layers(cache);
    Some(freed + layer_freed)
}

/// On-disk size of cached image `<stem>` - the size half of [`image_stat`]. Used by the build-history
/// record (which needs only the size, not the health flag).
pub(crate) fn image_size(cache: &std::path::Path, stem: &str) -> u64 {
    image_stat(cache, stem).0
}

/// Recursive on-disk size of `dir` in bytes (best-effort). Uses the no-follow dirent file type, so
/// symlinks are neither followed nor counted.
/// `dir_size`, memoised in a sidecar next to the directory.
///
/// `kern images` walked every byte of the cache on every invocation: 40 ms on a 2.6 GB cache of 53
/// images and 74271 files, against 1.4 ms with a single image, and `du -s` over the same tree takes
/// 76 ms. It is the same work, done again each time, for a number that CANNOT have changed: an
/// extracted image is immutable once its `.ok` sentinel is written.
///
/// INVARIANT, stated because everything here rests on it and nothing enforced it: **nothing writes
/// into an image directory after its `.ok` sentinel exists.** Extraction completes, then the sentinel
/// is written; a re-pull rewrites both. A caller that added to a cached directory WITHOUT rewriting
/// the sentinel would be served a stale total forever - verified by adding 3 MB to an extracted
/// alpine and watching `kern images` keep reporting 8.0M. No such caller exists today; if one is
/// added, it must touch the sentinel, and this comment is the only thing that says so.
///
/// So the total is cached in `<dir>.size` as `<stamp> <bytes>`, where `stamp` is the mtime of the
/// thing that changes when the content does. A re-pull rewrites the sentinel, the stamp no longer
/// matches, and the size is recomputed. Anything unreadable, malformed or stale simply recomputes:
/// the cache can only ever save work, never change an answer.
pub(crate) fn dir_size_cached(dir: &std::path::Path, stamp_of: &std::path::Path) -> u64 {
    // mtime in WHOLE SECONDS plus the sentinel's SIZE. The mtime alone left a second, unwritten
    // precondition: that every rewrite of `.ok` lands in a different second from the last. Two
    // commands in a row can break that - `kern rmi alpine && kern pull alpine` inside one second
    // rewrites the sentinel with the same mtime, and the sidecar from the OLD image stays valid. The
    // size closes it: a rewritten sentinel almost always differs in length, and when it does not, it
    // is the same reference for the same image.
    let md = std::fs::metadata(stamp_of).ok();
    let stamp = md
        .as_ref()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let slen = md.as_ref().map(|m| m.len()).unwrap_or(0);
    let side = std::path::PathBuf::from(format!("{}.size", dir.display()));
    if stamp != 0 {
        if let Ok(body) = std::fs::read_to_string(&side) {
            // THREE fields now: `<mtime> <sentinel-size> <bytes>`. Reading two left `b` holding the
            // size instead of the total - a shape the old two-field file would also have parsed, which
            // is why the format check is positional and strict rather than lenient.
            let mut it = body.split_whitespace();
            if let (Some(s), Some(sl), Some(b)) = (it.next(), it.next(), it.next()) {
                if s.parse::<u64>() == Ok(stamp) && sl.parse::<u64>() == Ok(slen) {
                    if let Ok(bytes) = b.parse::<u64>() {
                        return bytes;
                    }
                }
            }
        }
    }
    let bytes = dir_size(dir);
    if stamp != 0 {
        let _ = std::fs::write(&side, format!("{stamp} {slen} {bytes}\n"));
    }
    bytes
}

pub(crate) fn dir_size(dir: &std::path::Path) -> u64 {
    let mut total = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            match e.file_type() {
                Ok(ft) if ft.is_dir() => total += dir_size(&e.path()),
                Ok(ft) if ft.is_file() => total += e.metadata().map_or(0, |m| m.len()),
                _ => {}
            }
        }
    }
    total
}

/// Materialize an image reference to `(rootfs_dir, config, cleanup)`. `cleanup` is `Some(tmp)` when we
/// created a temporary squashed rootfs (layered image) that the caller must remove; `None` when the
/// rootfs is the persistent flat cache dir (do NOT delete it). Errors if the image isn't cached.
pub(crate) fn materialize_image(
    image: &str,
) -> Result<(PathBuf, kern_oci::ImageConfig, Option<PathBuf>), Error> {
    let cache = cache_dir();
    let safe = sanitize_ref(image);
    let flat = cache.join(&safe);
    // Flat pulled image: the cache dir is the rootfs, pushed in place (no copy).
    if flat.is_dir()
        && !cache.join(format!("{safe}.layers")).exists()
        && !cache.join(format!("{safe}.base")).exists()
    {
        let config = read_image_config(&cache.join(format!("{safe}.image")));
        return Ok((flat, config, None));
    }
    // Layered/built image: squash the overlay chain into a fresh temp rootfs so we push one layer.
    //
    // WHITEOUT/OPAQUE INVARIANT (a leak-of-deleted-secrets if broken): a hand-rolled bottom-up `cp -a`
    // of the RAW layer dirs re-includes a file that a higher layer DELETED - a per-file `.wh.` whiteout
    // OR (the case a naive squash misses) an OPAQUE directory (`rm -rf dir && mkdir dir`, marked by the
    // `overlay.opaque` xattr, NOT a `.wh.` file). A secret `rm`'d in a build step then resurfaces in the
    // pushed image. So we DON'T hand-roll the merge: we copy from the KERNEL-MERGED overlay view (see
    // [`merged_view_extract`]), where the kernel has already applied opaque + whiteout + redirect_dir +
    // metacopy - the only correct reader. The chain is `top:…:base`; a single-layer image can't have a
    // cross-layer opaque, so it's copied directly (below); a ≥2-layer chain goes through the merged view.
    let (lower, config) = resolve_image(image)?;
    let chain: Vec<String> = lower.split(':').map(str::to_string).collect();
    let tmp = cache.join(format!(".push-squash-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| Error::Oci(format!("squash dir: {e}")))?;
    if chain.len() >= 2 {
        // ≥2 stacked layers → cross-layer opaque is possible → read the kernel-merged view.
        merged_view_extract(&chain, None, &tmp).inspect_err(|_| {
            remove_build_tree(&tmp);
        })?;
    } else {
        // A single layer is already its own merged rootfs - copy it directly (no opaque to honour).
        let ok = std::process::Command::new("cp")
            .arg("-a")
            .arg("--reflink=auto")
            .arg("--")
            .arg(format!("{}/.", chain[0]))
            .arg(&tmp)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            remove_build_tree(&tmp);
            return Err(Error::Oci(format!("squashing image '{image}' failed")));
        }
        // Defence-in-depth on the direct path: strip any surviving OCI whiteout marker file so a
        // `.wh.<name>` can never be pushed as a literal file. (The merged-view path can't produce one -
        // the kernel already resolved whiteouts - so it's only needed here.)
        strip_whiteout_markers(&tmp);
    }
    Ok((tmp.clone(), config, Some(tmp)))
}

/// Resolve `--image <ref>` to an overlay `(lowerdir, config)`. A pulled (flat) image is a single
/// cache dir. A locally-built (**layered**) image - marked by a `<ref>.base` sidecar - is its
/// `<ref>.diff` layer stacked over its base, resolved RECURSIVELY (the base may itself be layered)
/// and re-pulled if the base was pruned, so layered images are prune-safe. The returned `lowerdir`
/// may be a colon-joined chain (top layer first, exactly overlayfs's ordering).
pub(crate) fn resolve_image(image: &str) -> Result<(String, kern_oci::ImageConfig), Error> {
    resolve_image_depth(image, 0, PullPolicy::Missing)
}

pub(crate) fn resolve_image_depth(
    image: &str,
    depth: u32,
    policy: PullPolicy,
) -> Result<(String, kern_oci::ImageConfig), Error> {
    // Bound the chain so a self-referential build (`FROM` its own tag) can't recurse forever.
    if depth > 128 {
        return Err(Error::Oci(
            "image layer chain too deep (a build FROM its own tag?)".into(),
        ));
    }
    let cache = cache_dir();
    // `scratch` is Docker's reserved EMPTY base (no layers, empty config): materialize a shared empty
    // directory as the overlay lower so `FROM scratch` builds - the standard base for minimal images
    // (a single static binary, distroless-style, sentry's `FROM scratch AS odiff-*`).
    if image == "scratch" {
        let empty = cache.join(".scratch-empty");
        own_only_dir(&empty).map_err(|e| Error::Oci(format!("scratch base: {e}")))?;
        return Ok((
            empty.to_string_lossy().into_owned(),
            kern_oci::ImageConfig::default(),
        ));
    }
    let safe = sanitize_ref(image);
    // A cache-built (multi-layer) image: `<tag>.layers` = base ref, then one layer key per line.
    let layers_file = cache.join(format!("{safe}.layers"));
    if layers_file.exists() {
        let body = std::fs::read_to_string(&layers_file)
            .map_err(|e| Error::Oci(format!("read layers of '{image}': {e}")))?;
        let mut lines = body.lines();
        let base_ref = lines.next().unwrap_or("").trim();
        // Base layers of a built image are used as-is; `--pull always` never force-repulls them.
        let (base_lower, _) = resolve_image_depth(base_ref, depth + 1, PullPolicy::Missing)?;
        let lc = layer_cache_dir();
        let mut chain = vec![base_lower];
        for k in lines.map(str::trim).filter(|k| !k.is_empty()) {
            // A layer key MUST be 32 lowercase hex (what we write). Reject anything else so a corrupt
            // or (once layered images are shippable) hostile manifest can't turn a key into a `/etc`,
            // `../…`, or `:`/`,`-bearing path that escapes `L/` or injects an overlay mount option.
            if k.len() != 32 || !k.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::Oci(format!("corrupt layer manifest for '{image}'")));
            }
            chain.push(lc.join(k).to_string_lossy().into_owned());
        }
        let lower = chain_lower(&chain);
        if lower.len() > MAX_LOWERDIR_BYTES {
            return Err(Error::Oci(format!(
                "image '{image}' has too many layers to overlay (rebuild with fewer steps)"
            )));
        }
        let config = read_image_config(&cache.join(format!("{safe}.image")));
        return Ok((lower, config));
    }
    // Legacy single-diff (P3.5) image: `<tag>.base` + `<tag>.diff`.
    let base_marker = cache.join(format!("{safe}.base"));
    if base_marker.exists() {
        let base_ref = std::fs::read_to_string(&base_marker)
            .map_err(|e| Error::Oci(format!("read base of '{image}': {e}")))?
            .trim()
            .to_string();
        let (base_lower, _) = resolve_image_depth(&base_ref, depth + 1, PullPolicy::Missing)?;
        let diff = cache.join(format!("{safe}.diff"));
        let config = read_image_config(&cache.join(format!("{safe}.image")));
        // Top (this image's diff) first, then the base chain - overlayfs shadows left-to-right.
        return Ok((format!("{}:{base_lower}", diff.to_string_lossy()), config));
    }
    pull_to_cache(image, policy)
}

/// Is the FLAT cache entry for `safe` complete, i.e. actually runnable?
///
/// ONE definition, used by every gate in [`pull_to_cache`] and by the `already cached` message, because
/// this question was being asked four times with three different answers. The completeness of an entry
/// is three files, not one:
///
/// * `<safe>.ok` - the sentinel, written LAST, so an interrupted extraction reads as absent;
/// * `<safe>.image` - the config sidecar; without it the box loses the image's entrypoint, env and
///   user and silently falls back to a shell;
/// * `<safe>/` - the rootfs itself, which is what the overlay lower actually mounts.
///
/// The third was missing everywhere. A sentinel whose directory had been pruned or cleaned by hand made
/// `kern pull` print "already cached" and "run it: …" while `kern images` said `dangling` about the
/// same ref at the same instant (`image_stat` already knew: no flat dir, no diff, no manifest means
/// nothing to run), and `kern box --image <ref>` then died with `mount(overlay) failed: No such file or
/// directory`, naming neither the image nor the cause. Reproduced with a `node:20-slim` whose rootfs
/// was gone.
///
/// Keeping it in one function also closes a `--pull never` hole: with the sentinel present and the
/// sidecar missing, the old top-of-function check passed, the fast path was skipped, and control fell
/// into the fetch block - so `--pull never` went to the network.
pub(crate) fn cache_entry_complete(cache: &std::path::Path, safe: &str) -> bool {
    if !cache.join(format!("{safe}.ok")).exists() || !cache.join(format!("{safe}.image")).exists() {
        return false;
    }
    let dir = cache.join(safe);
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return false; // not a directory, or unreadable: not something to hand to overlayfs
    };
    // A directory holding ONLY kern's own prefetch blobs (`.kern-layer-*`) is an extraction that
    // downloaded and never merged - which is what an interrupted pull used to leave behind a stale
    // sentinel. An EMPTY directory is accepted: a completed extraction removes each blob as it
    // consumes it, so "no entries at all" means the image genuinely had nothing, and rejecting it
    // would re-pull that image on every single invocation, forever.
    !rd.flatten()
        .any(|e| e.file_name().to_string_lossy().starts_with(".kern-"))
}

/// Pull `image` into a local cache and return `(rootfs path, its OCI runtime config)`. Reuse is gated
/// on a sibling completion sentinel (`<ref>.ok`), not "directory is non-empty" - so an interrupted
/// pull (or a stray file) never makes a partial/poisoned rootfs look valid; we re-pull cleanly. The
/// image config is persisted to a `<ref>.image` sidecar (outside the rootfs) so a cache hit reapplies
/// it without re-pulling.
pub(crate) fn pull_to_cache(
    image: &str,
    policy: PullPolicy,
) -> Result<(String, kern_oci::ImageConfig), Error> {
    use std::os::unix::io::AsRawFd;
    let cache = cache_dir();
    let safe = sanitize_ref(image);
    let dir = cache.join(&safe);
    let sentinel = cache.join(format!("{safe}.ok"));
    let cfgfile = cache.join(format!("{safe}.image"));
    // `--pull never`: fail closed BEFORE creating the cache dir or a lock file. `scratch`/`.layers`/
    // `.base` already returned in `resolve_image_depth`, so reaching here with no sentinel means this
    // registry image is genuinely not cached. Lock-free with zero fs side-effects (matches the old
    // pre-check); the `.image` sidecar layout stays owned by this one function.
    if policy == PullPolicy::Never && !cache_entry_complete(&cache, &safe) {
        return Err(Error::Oci(format!(
            "image '{image}' is not usable locally (no complete cache entry: it needs its rootfs, its \
             sentinel and its config sidecar) and `--pull never` was given"
        )));
    }
    own_only_dir(&cache).map_err(|e| Error::Oci(format!("cache dir: {e}")))?;
    // A cache entry is COMPLETE only with its sentinel, its config sidecar AND the rootfs they
    // describe. An entry written before the sidecar existed stayed broken forever otherwise: the
    // sentinel short-circuited every later pull, the config read back empty, and a box with no
    // explicit command exec'd a shell that exits at once when detached, leaving no log.
    //
    // The ROOTFS check closes the symmetric hole. A sentinel whose `<ref>/` directory is gone - the
    // image was pruned, the cache was cleaned by hand, a filesystem was reset - made `kern pull` print
    // "already cached" and "run it: kern box ...", and `kern images` said `dangling` about the same
    // ref at the same moment, because `image_stat` already knows that no flat dir, no diff and no
    // manifest means nothing to run. `kern box --image <ref>` then died with
    // `mount(overlay) failed: No such file or directory`, naming neither the image nor the cause.
    // Reproduced on a developer machine with `node:20-slim`. Treating it as a miss re-fetches and
    // repairs it, once, without the user having to know that `--pull always` was the way out.
    if policy != PullPolicy::Always && cache_entry_complete(&cache, &safe) {
        // fast path: already cached (and not a forced `--pull always` re-fetch)
        return Ok((
            dir.to_string_lossy().into_owned(),
            read_image_config(&cfgfile),
        ));
    }
    // Serialize concurrent pulls of the SAME image: take an exclusive lock, then re-check the
    // sentinel (another process may have completed the pull while we waited). Different images
    // use different lock files, so they still pull in parallel.
    let lock = std::fs::File::create(cache.join(format!("{safe}.lock")))
        .map_err(|e| Error::Oci(format!("pull lock: {e}")))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(Error::Oci("could not acquire pull lock".into()));
    }
    if policy == PullPolicy::Always {
        // `--pull always`: fetch into a scratch dir, then swap it in with an atomic `rename`. A box
        // already using `dir` as its overlay lower is UNDISTURBED: overlayfs pinned that dentry at
        // mount time, so renaming the path out from under it is invisible to the live box. The retired
        // dir is left for `kern gc` (a live box still holds its inodes on demand; deleting it now would
        // yank files overlayfs opens lazily). Fail-safe: on any error `dir` is left untouched/restored.
        let pid = std::process::id();
        let staging = cache.join(format!("{safe}.pull-{pid}"));
        let _ = std::fs::remove_dir_all(&staging);
        std::fs::create_dir_all(&staging).map_err(|e| Error::Oci(format!("cache dir: {e}")))?;
        eprintln!("→ re-pulling image '{image}' (--pull always)");
        let config = match kern_oci::pull(image, &staging, None) {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(Error::Oci(e.to_string()));
            }
        };
        if dir.exists() {
            let retired = cache.join(format!("{safe}.old-{pid}"));
            let _ = std::fs::remove_dir_all(&retired);
            // Atomic swap: exchange `dir` <-> `staging` in ONE syscall so `dir` is NEVER momentarily
            // absent for a concurrent reader. A two-step rename leaves a window in which a fast-path
            // box (which resolves `dir` WITHOUT the pull lock) could mount an absent `dir` -> ENOENT.
            // After the exchange, `staging` holds the retired image.
            let cd = cstring(&dir.to_string_lossy())?;
            let cs = cstring(&staging.to_string_lossy())?;
            // Invoke `renameat2` via the raw syscall, NOT `libc::renameat2`: the wrapper is absent from
            // the musl `libc` bindings (the aarch64/x86_64-musl RELEASE build fails to link it), while
            // `SYS_renameat2` + `RENAME_EXCHANGE` are defined for every Linux target. Same ABI, portable.
            let exchanged = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    libc::AT_FDCWD,
                    cd.as_ptr(),
                    libc::AT_FDCWD,
                    cs.as_ptr(),
                    libc::RENAME_EXCHANGE,
                )
            } == 0;
            if exchanged {
                let _ = std::fs::rename(&staging, &retired); // old content aside for `kern gc`
            } else {
                // RENAME_EXCHANGE unsupported (pre-3.15 kernel / a fs without it): fall back to the
                // two-step rename. The residual window is two rename syscalls; the flock already
                // serializes same-image writers, so only a fast-path reader could observe it.
                std::fs::rename(&dir, &retired)
                    .map_err(|e| Error::Oci(format!("cache swap (retire): {e}")))?;
                if let Err(e) = std::fs::rename(&staging, &dir) {
                    // Put the previous image back. If THAT also fails, `dir` is gone; clear the sentinel
                    // so the cache reads as "not present" and a later run re-pulls, instead of the fast
                    // path serving a missing `dir` -> permanent ENOENT until `gc --images`.
                    if std::fs::rename(&retired, &dir).is_err() {
                        let _ = std::fs::remove_file(&sentinel);
                    }
                    return Err(Error::Oci(format!("cache swap (install): {e}")));
                }
            }
        } else {
            std::fs::rename(&staging, &dir)
                .map_err(|e| Error::Oci(format!("cache install: {e}")))?;
        }
        // Config follows the rootfs swap. The `<ref>.image` sidecar is a separate path, so a lock-free
        // fast-path reader that starts the SAME image in the tiny window between the `dir` swap and
        // this write could pair the new rootfs with the old config. Harmless for a same-tag refresh
        // (identical config); a genuinely different image at the same tag is a known concurrency edge
        // of `--pull always` (don't re-pull a tag while concurrently starting it).
        write_image_config(&cfgfile, &config)
            .map_err(|e| Error::Oci(format!("image config for '{image}': {e}")))?;
        let _ = std::fs::write(&sentinel, image.as_bytes());
        return Ok((dir.to_string_lossy().into_owned(), config));
    }
    // Reached when the entry is missing OR incomplete. Same predicate as the fast path above, so the
    // two cannot disagree about what "cached" means - which is exactly what let a sentinel without a
    // rootfs skip both the fast path AND this fetch, and fall through to a `return Ok` naming a
    // directory that does not exist.
    if !cache_entry_complete(&cache, &safe) {
        // Only `missing` reaches here uncached (`never` failed closed at the top; `always` returned in
        // its own branch). Re-checked under the lock: a concurrent pull may have finished while we
        // waited, in which case the entry is now complete and we skip the fetch.
        // Name the reason accurately: a blob-only directory EXISTS, so testing `is_dir()` here
        // reported "without its config" for an entry whose config was present and whose rootfs was
        // never merged. Each arm now tests the thing it names.
        let rootfs_usable = std::fs::read_dir(&dir).is_ok_and(|rd| {
            !rd.flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with(".kern-"))
        });
        if !sentinel.exists() {
            eprintln!("→ image '{image}' not cached - pulling once (reused after)");
        } else if !rootfs_usable {
            eprintln!("→ image '{image}' is cached without a usable rootfs - re-fetching it once");
        } else {
            eprintln!("→ image '{image}' is cached without its config - re-fetching it once");
        }
        // INVALIDATE THE ENTRY BEFORE TOUCHING THE ROOTFS. The sentinel is written LAST precisely so
        // that an interrupted extraction reads as absent - but that only holds when there was no
        // sentinel to begin with. On a REPAIR (a stale sentinel whose rootfs was pruned or cleaned by
        // hand) the old sentinel and sidecar survive, so an interruption partway leaves a directory
        // holding nothing but prefetch blobs behind a sentinel that still says "complete", and the
        // next resolve hands that empty rootfs to overlayfs. Reproduced by interrupting a repair with
        // a closed pipe (`kern pull … | head -3` → SIGPIPE mid-extraction).
        //
        // Clearing both first makes an interrupted repair read exactly like an interrupted first pull:
        // incomplete, therefore re-fetched. A missing file is already the desired state; anything else
        // means we cannot guarantee the invalidation, and continuing would rebuild the same trap.
        for stale in [&sentinel, &cfgfile] {
            match std::fs::remove_file(stale) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(Error::Oci(format!(
                        "cannot invalidate the stale cache entry {}: {e}",
                        stale.display()
                    )))
                }
            }
        }
        // Clear any partial extraction (and any prefetch blobs left by an interrupted run). Not
        // discarded: extracting on top of content this run did not produce is how a partial layer set
        // becomes an image that looks whole.
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Error::Oci(format!(
                    "cannot clear the partial image dir {}: {e}",
                    dir.display()
                )))
            }
        }
        std::fs::create_dir_all(&dir).map_err(|e| Error::Oci(format!("cache dir: {e}")))?;
        // The `box --image` cache path pulls the host arch; `box --platform` (foreign-arch box) is
        // Slice B, deferred with the multi-stage work - so no platform override here yet.
        //
        // Remove the directory we just created if the pull fails, the way the `--pull always` branch
        // above already does for its staging dir. A `?` here left one empty directory per failed pull:
        // a bad tag, an image that does not exist, and a Ctrl-C mid-download each produced one, and 24
        // had accumulated in this cache. They are invisible to `kern images` (which keys off the
        // sentinel) and only `kern gc --images` reaps them, so nothing ever told the user they were
        // there. Deleting only what this branch created: the `--dest <dir>` path deliberately does NOT
        // do this, because that directory is the caller's.
        let config = match kern_oci::pull(image, &dir, None) {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(Error::Oci(e.to_string()));
            }
        };
        write_image_config(&cfgfile, &config)
            .map_err(|e| Error::Oci(format!("image config for '{image}': {e}")))?;
        let _ = std::fs::write(&sentinel, image.as_bytes());
    }
    // lock released when `lock` drops
    Ok((
        dir.to_string_lossy().into_owned(),
        read_image_config(&cfgfile),
    ))
}

/// Image cache root: `$XDG_CACHE_HOME/kern/images` → `$HOME/.cache/kern/images` (both user-owned
/// and persistent) → `/tmp/kern-cache-<uid>/images` (created mode 0700, last resort).
pub(crate) fn cache_dir() -> PathBuf {
    if let Some(x) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(x).join("kern/images");
    }
    if let Some(h) = std::env::var_os("HOME") {
        return PathBuf::from(h).join(".cache/kern/images");
    }
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/tmp/kern-cache-{uid}/images"))
}

/// The content-addressed build **layer cache** (`<image cache>/L`): each `kern build` unit (a RUN
/// batch, a COPY, a WORKDIR) is stored here under its cache key so an unchanged rebuild reuses it
/// instead of re-executing - Docker-style layer caching, mounted back as an overlay lower.
pub(crate) fn layer_cache_dir() -> PathBuf {
    cache_dir().join("L")
}

/// A 128-bit FNV-1a cache key (32 hex) over `prev-key` then `repr` - the chained key that makes a
/// layer's identity depend on everything before it, so a change busts that layer and all after it.
/// Non-crypto: this is a LOCAL, first-party cache, and a collision only mis-reuses the user's OWN
/// layer (2^-128); it is never a trust boundary.
pub(crate) fn layer_key(prev: &str, repr: &str) -> String {
    let (mut a, mut b): (u64, u64) = (0xcbf2_9ce4_8422_2325, 0x9e37_79b9_7f4a_7c15);
    for byte in prev.bytes().chain([0u8]).chain(repr.bytes()) {
        a = (a ^ byte as u64).wrapping_mul(0x0000_0100_0000_01b3);
        b = (b ^ byte as u64)
            .wrapping_mul(0x0000_0100_0000_01b3)
            .rotate_left(13);
    }
    format!("{a:016x}{b:016x}")
}

/// Hash a COPY/ADD source's tree (paths + file bytes + symlink targets, order-stable) into the
/// layer key, so editing a copied file busts the cache. Best-effort: an unreadable entry still
/// contributes a marker so its absence/failure changes the key.
///
/// `ig` (the context's `.dockerignore`, matched relative to `ctx_root`) is applied to a dir source's
/// DESCENDANTS exactly as `copy_into_rootfs` does, so the key reflects only what actually gets copied,
/// a change to an ignored `node_modules`/`.git`/secret neither busts the cache nor costs a hash pass
/// (previously this walk hashed the WHOLE context on every build). Fail-OPEN: if a path can't be made
/// context-relative we hash it anyway - worst case a spurious rebuild, never a stale/wrong layer.
pub(crate) fn content_hash(
    path: &std::path::Path,
    ctx_root: &std::path::Path,
    ig: Option<&crate::dockerignore::DockerIgnore>,
) -> String {
    fn feed(h: &mut u64, bytes: &[u8]) {
        for &b in bytes {
            *h = (*h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    // Does the context ignore exclude this descendant? Mirrors `copy_dir_filtered`: prune a dir only
    // when no `!` re-include could match inside it, else exclude a leaf. The ROOT source is never
    // filtered here (a single-file `COPY secret.txt` isn't ignore-gated, matching the copy path).
    fn skip(
        ctx_root: &std::path::Path,
        p: &std::path::Path,
        is_dir: bool,
        ig: Option<&crate::dockerignore::DockerIgnore>,
    ) -> bool {
        let Some(ig) = ig else { return false };
        let Ok(rel) = p.strip_prefix(ctx_root) else {
            return false; // fail-open: can't match → hash it (extra rebuild at worst)
        };
        let rel = rel.to_string_lossy().replace('\\', "/");
        if rel.is_empty() {
            return false;
        }
        if is_dir {
            ig.can_prune_dir(&rel)
        } else {
            ig.excluded(&rel)
        }
    }
    fn walk(
        h: &mut u64,
        p: &std::path::Path,
        rel: &str,
        ctx_root: &std::path::Path,
        ig: Option<&crate::dockerignore::DockerIgnore>,
    ) {
        match std::fs::symlink_metadata(p) {
            Ok(m) if m.file_type().is_symlink() => {
                feed(h, b"L");
                feed(h, rel.as_bytes());
                if let Ok(t) = std::fs::read_link(p) {
                    feed(h, t.to_string_lossy().as_bytes());
                }
            }
            Ok(m) if m.is_dir() => {
                feed(h, b"D");
                feed(h, rel.as_bytes());
                // (name, is_dir) straight from readdir: `DirEntry::file_type()` reads d_type from the
                // readdir buffer (no extra stat on Linux ext4/xfs/btrfs/tmpfs), and a symlink reports
                // is_dir()==false so it's routed through the leaf `excluded` check exactly like
                // `copy_dir_filtered` - avoids the second `symlink_metadata` per child.
                let mut names: Vec<(std::ffi::OsString, bool)> = std::fs::read_dir(p)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(|e| {
                        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                        (e.file_name(), is_dir)
                    })
                    .collect();
                names.sort();
                for (n, child_is_dir) in names {
                    let child = p.join(&n);
                    // Skip ignored descendants (dir prune / leaf exclude) so the key mirrors the copy;
                    // `skip` is a no-op when no ignore file is present (the common case pays nothing).
                    if skip(ctx_root, &child, child_is_dir, ig) {
                        continue;
                    }
                    walk(
                        h,
                        &child,
                        &format!("{rel}/{}", n.to_string_lossy()),
                        ctx_root,
                        ig,
                    );
                }
            }
            Ok(m) if m.is_file() => {
                use std::os::unix::fs::PermissionsExt;
                feed(h, b"F");
                feed(h, rel.as_bytes());
                // Fold in the file MODE: a `cp -a` COPY preserves it, so a chmod-only change (e.g.
                // adding +x to an entrypoint) must bust the cache or the layer ships the old mode.
                feed(h, &(m.permissions().mode() & 0o7777).to_le_bytes());
                // Stream the file in a fixed buffer instead of slurping it whole: a large COPY source
                // (a big binary, node_modules) otherwise spikes RAM by its full size, on EVERY build
                // (this runs to compute the cache key, even on a cache hit). Byte-identical hash → same key.
                match std::fs::File::open(p) {
                    Ok(mut f) => {
                        use std::io::Read;
                        let mut buf = [0u8; 64 * 1024];
                        loop {
                            match f.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => feed(h, &buf[..n]),
                                // Retry EINTR like `fs::read` did - a stray signal mid-read must
                                // not flap the cache key of an unchanged file.
                                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                                Err(_) => {
                                    feed(h, b"?");
                                    break;
                                }
                            }
                        }
                    }
                    Err(_) => feed(h, b"?"),
                }
            }
            Ok(_) => {
                // A non-regular node (fifo/socket/device/block): `copy_dir_filtered` SKIPS these, so we
                // must NOT open it - a writer-less FIFO would block the whole cache-key computation.
                // Feed just a type marker so a regular↔special transition still busts the key.
                feed(h, b"O");
                feed(h, rel.as_bytes());
            }
            Err(_) => feed(h, b"?"),
        }
    }
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    walk(&mut h, path, "", ctx_root, ig);
    format!("{h:016x}")
}

/// A completed layer's sentinel exists (`<key>.ok`) → it's a cache hit.
pub(crate) fn layer_cached(lc: &std::path::Path, key: &str) -> bool {
    lc.join(format!("{key}.ok")).exists()
}

/// Commit a freshly-built layer's content dir into the layer cache under `key` (atomic rename +
/// completion sentinel). A concurrent build that produced the same key first simply wins the race.
pub(crate) fn commit_layer(
    content: &std::path::Path,
    lc: &std::path::Path,
    key: &str,
) -> Result<(), Error> {
    let dest = lc.join(key);
    if !dest.exists() {
        // Ignore a rename race (another build committed the identical key first) - content is equal.
        let _ = std::fs::rename(content, &dest);
    }
    // Only mark the layer complete once its content dir is actually in place - otherwise a failed
    // rename (e.g. ENOSPC) would leave a sentinel with no dir → a poisoned "hit" that later fails
    // to mount. A missing sentinel just means the next build re-runs the unit (safe).
    if dest.exists() {
        let _ = std::fs::write(lc.join(format!("{key}.ok")), b"");
    }
    Ok(())
}

/// `true` if `rel` resolves to a directory anywhere in the overlay `chain` (layer dirs + base),
/// searched top-first - used by COPY to decide "into a dir" vs "as a file" against the MERGED image
/// (a lower layer may hold the dir). Build layers never delete, so the first hit wins.
pub(crate) fn chain_has_dir(chain: &[String], rel: &str) -> bool {
    if rel.is_empty() {
        return true;
    }
    chain.iter().rev().any(|d| {
        std::fs::symlink_metadata(std::path::Path::new(d).join(rel))
            .map(|m| m.is_dir())
            .unwrap_or(false)
    })
}

/// A filesystem-safe directory name for an image reference.
pub(crate) fn sanitize_ref(image: &str) -> String {
    // The reference gets its implied tag FIRST, so `alpine` and `alpine:latest` are one key and not
    // two. They used to be two, and it cost: the same 8.7 MB cached twice, `rmi alpine` leaving
    // `alpine:latest` behind, `gc` blind to the pair, and a `save`+`load` round trip renaming an
    // image so the reference that worked before it stopped resolving after. Every caller of this
    // function keys a cache dir, a sidecar or a lookup on the result, so normalizing here fixes all
    // of them at once instead of at each site (which is how they drifted apart to begin with).
    // A digest ref is left alone by `normalize_ref`: it pins harder than a tag.
    let image = &kern_oci::normalize_ref(image);
    // A filesystem-safe, COLLISION-FREE cache key. Map anything outside `[A-Za-z0-9_-]` to `_` - so
    // `/`, `:`, and crucially any `.`/`..` can't build a traversal like `cache/..` (which a later
    // `remove_dir_all` would then wipe) - then append a short hash of the FULL ref so distinct images
    // (`foo/bar` vs `foo_bar`) can never share a cache dir / config sidecar.
    let base: String = image
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{base}-{:016x}", fnv1a(image))
}

/// FNV-1a 64-bit - a fast non-cryptographic hash, used ONLY to make [`sanitize_ref`] cache keys
/// collision-free (never for anything security-sensitive).
pub(crate) fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Remove a cached image (all sidecar forms) by ref - used to drop the internal temp stage images a
/// multi-stage build creates. Best-effort.
pub(crate) fn drop_cached_image(image: &str) -> Result<(), Error> {
    // `sanitize_ref` yields an `is_safe_stem` token, so this shares the single artifact-remover with
    // `rmi` (they can't drift on which sidecars make up an image).
    drop_image_artifacts(&cache_dir(), &sanitize_ref(image));
    Ok(())
}

/// A flat-build cache HIT: `tag` holds a flat image (its `<safe>` rootfs dir exists) whose stored
/// content key matches `key`. Shared by the single-stage and multi-stage build paths so they can't
/// drift on the suffix or the `is_dir` guard.
pub(crate) fn flat_cache_hit(tag: &str, key: &str) -> bool {
    let cache = cache_dir();
    let safe = sanitize_ref(tag);
    cache.join(&safe).is_dir()
        && std::fs::read_to_string(cache.join(format!("{safe}.flatkey")))
            .ok()
            .as_deref()
            == Some(key)
}

/// Record a flat-build content key on `tag` so the next identical build hits [`flat_cache_hit`].
pub(crate) fn write_flat_key(tag: &str, key: &str) {
    let _ = std::fs::write(
        cache_dir().join(format!("{}.flatkey", sanitize_ref(tag))),
        key,
    );
}

/// A content-addressed key for a FLAT-built image: an opaque `domain` tag (the resolved base lower for
/// a single-stage flat build, a constant like `"multistage"` for the whole-build multi-stage key -
/// which domain-separates the two on the same tag) + EVERY instruction (derived `Debug`
/// captures all fields - build-args are already `${VAR}`-baked into `instrs` at parse time, so a
/// build-arg change shows here; RUN argv, ENV, CMD, WORKDIR, heredoc bodies and ADD URLs are all in) +
/// the byte hashes of the context files a COPY would keep (honouring `.dockerignore`, which the paths
/// in `Debug` alone don't capture). The flat executor has no per-layer cache, so an UNCHANGED rebuild -
/// the common case on WSL / older kernels without unprivileged overlay - can reuse the tag's existing
/// image instead of redoing the base-copy + RUN + COPY. Content-addressed, so it NEVER reuses a stale
/// image: any change to the Dockerfile, a build-arg, or a copied file busts the key. (An `ADD <url>` is
/// keyed by its URL like Docker - a changed remote file isn't caught without `--checksum`, exactly
/// Docker's own ADD-url cache semantics.)
pub(crate) fn flat_image_key(
    domain: &str,
    instrs: &[crate::dockerfile::Instr],
    ctx: &std::path::Path,
    ctx_root: &std::path::Path,
    ig: Option<&crate::dockerignore::DockerIgnore>,
) -> String {
    use crate::dockerfile::Instr;
    let mut acc = format!("{domain}\0{instrs:?}");
    for instr in instrs {
        // Only a context COPY (`from: None`) reads build-context files whose BYTES aren't in `Debug`;
        // fold their content hash in so an edit to a copied file busts the key.
        if let Instr::Copy {
            srcs, from: None, ..
        } = instr
        {
            if let Ok(expanded) = expand_copy_srcs(ctx, srcs) {
                for s in &expanded {
                    acc.push('\0');
                    acc.push_str(&content_hash(&ctx.join(s), ctx_root, ig));
                }
            }
        }
    }
    format!("{:016x}", fnv1a(&acc))
}

/// Join an overlay lower `chain` (base first) into a `lowerdir=` string (TOP layer first, base last).
pub(crate) fn chain_lower(chain: &[String]) -> String {
    chain.iter().rev().cloned().collect::<Vec<_>>().join(":")
}
