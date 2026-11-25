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
///
/// The `will_be_single_uid` heads-up in `start` reads this too, which is the other reason the third
/// condition belongs HERE and not at a call site: a box that silently stopped getting the range
/// would otherwise keep the warning that says it is getting one.
pub(crate) fn image_default_uid_range(args: &BoxRunArgs) -> bool {
    args.image.is_some() && !args.no_uid_range && !range_buys_nothing(args)
}

/// Does the COMMAND LINE ask for the subordinate uid range: `--uid-range`, `--ssh`, or a numeric
/// non-root `--user` (its uid must be mapped in)? The dry run reports it as `uid_range_source:
/// request`, and `box_run` starts the id map early on it; one statement so the two cannot disagree.
///
/// A FLOOR, NEVER A CEILING: a `--user` given by NAME, or an image whose `USER` is non-root, is only
/// known after the image is read and can still turn the range on. `box_run` decides the real map
/// from the resolved user; what reads this only acts on the cases already certain.
pub(crate) fn uid_range_asked_by_args(args: &BoxRunArgs) -> bool {
    args.uid_range
        || args.ssh_port.is_some()
        || parse_user(args.run_as)
            .ok()
            .flatten()
            .is_some_and(|(u, _)| u != 0)
}

/// Would the sub-uid range buy this box anything at all, given the capabilities it will actually
/// hold? When it would not, the default is dropped and the box skips two setuid helper execs.
///
/// WHAT IT IS WORTH. `parent:idmap` is 876 us with the range and 22 us without, and the whole box
/// goes 4008 -> 3029 us: a paired difference of 985 us, 25%, interval [-1025, -931] at n=300,
/// measured on 2026-09-20. It is the largest single item in a cold image box, and it is why
/// `--rootfs` (which never maps a range) starts a millisecond ahead of `--image`.
///
/// THE RULE, and both halves were measured rather than argued:
///
///   * `ALL` among the dropped capabilities means the thing the range exists for is already refused.
///     Inside a box, `chown` to another uid FAILS under `--cap-drop ALL` whether the range is mapped
///     or not, and an identity change is refused identically both ways. Without `--cap-drop ALL` the
///     same `chown` SUCCEEDS with the range and fails without it, which is the control that makes
///     the first half mean something: the range is doing real work in the default posture.
///   * ANY `--cap-add` puts it back. `--cap-drop ALL --cap-add CHOWN` is the discriminating case:
///     measured, that `chown` succeeds with the range and fails without. A capability handed back is
///     a capability that can use the range, so any add at all cancels this, which is the
///     conservative reading rather than the precise one. Being wrong here costs a silent failure in
///     someone's entrypoint; being conservative costs 985 us on a command nobody has typed yet.
///
/// `--security-profile=untrusted` promotes itself to `cap-drop ALL` in `start`, and is spelled out
/// again here because this function runs BEFORE that promotion. The two must agree: a test pins them
/// together, because a profile that stopped implying the drop would silently re-cost the millisecond.
///
/// THE `CAP_` PREFIX IS DELIBERATELY NOT STRIPPED, which is where the SDK's version of this rule and
/// this one legitimately differ. The Python binding normalises `CAP_ALL` because a caller can pass
/// any string; this CLI does not have that problem, because `caps::resolve` REFUSES `CAP_ALL` by
/// name (measured: all of `CAP_ALL`, `cap_all` and `Cap_All` exit 1 with "unknown capability"). So
/// the only spellings that can reach here are `ALL` and `all`, and matching more would advertise a
/// form the flag rejects. Same comparison as the profile promotion in `start`, on purpose.
///
/// ⛔ NOT A SECURITY BOUNDARY, and nothing here relaxes one. The box gets the same capabilities
/// either way; what changes is whether kern spends a millisecond installing a mapping that the
/// capability set makes unusable. An explicit `--uid-range`, `--user <non-root>` or `--ssh` asks for
/// the range in as many words and wins over this, because those are requests and this is a default.
///
/// 🚨 THE RULE HAS A CONSUMER IT CANNOT SEE: `kern exec -u <non-root>`, which arrived after this was
/// written. Every item in the list above is decided at START, and that one happens LATER, in another
/// process, against a box whose map is already installed - so there is nothing to retrofit. A field
/// report measured the consequence: `kern box b --cap-drop ALL -d` then `kern exec -u nobody b` is
/// refused, because uid 65534 is not in `0 1000 1`. The same box with `--uid-range` works.
///
/// This is NOT fixed by widening the rule, because kern cannot know at start whether an `exec -u`
/// will come, and installing the range for every cap-dropped box would charge the 985 us to the
/// boxes that never exec. It is fixed where the reader meets it: `describe_id_map` names this cause
/// when the box holds no capabilities, and `kern box --help` says so on both flags. If a third
/// consumer appears, add it to this list first.
///
/// 🚨 THE THIRD CONSUMER APPEARED, AND UNLIKE THE OTHER TWO IT IS A BOUNDARY. The paragraph above
/// said this relaxes nothing, because the range only buys what the capability set already refuses.
/// `setgroups` is the counter-example, and it was in neither list. The kernel will not accept an
/// unprivileged single-gid map until `/proc/self/setgroups` is `deny`, and after `deny` setgroups is
/// EPERM for the life of the namespace, so a single-uid box CANNOT drop the caller's inherited
/// supplementary groups. With the range, `newgidmap` is the privileged writer, `deny` is never
/// needed, and the clear in `drop_caps_around_identity` succeeds. Measured 2026-11-11 on a host file
/// the group class decides (`/var/log/kern.log.2.gz`, `syslog:adm 0640`, no ACL, no `other` bit,
/// caller in `adm`), bound with `-v`, with the host itself as the positive control:
///
///   default box                        DENIED    host Groups empty
///   --cap-drop ALL                     READ_OK   host Groups: all 14 of the caller's
///   --security-profile untrusted       READ_OK   host Groups: all 14 of the caller's
///   --cap-drop ALL --uid-range         DENIED    the range IS the mechanism
///   --cap-drop ALL --cap-add CHOWN     DENIED    any add already cancelled the rule
///   host, as the caller                READ_OK   the group is what grants it
///
/// So the two surfaces that most explicitly promise a tighter box, one of them named `untrusted`,
/// gave it more of the caller's host group reach than the default. The clear is what the range buys,
/// and it is worth exactly as much as there is to clear: nothing when the caller carries no
/// supplementary group beyond its primary gid, and a real boundary otherwise. That is the condition
/// now, so the 985 us is still saved on a caller with no groups (a dedicated service account, which
/// is where start latency is spent) and is spent wherever there is something to drop. Erring here
/// costs a silent relaxation rather than a silent entrypoint failure, so the reading is the
/// conservative one: any inherited group at all installs the range.
fn range_buys_nothing(args: &BoxRunArgs) -> bool {
    range_buys_nothing_for(
        matches!(args.security_profile, Some(SecurityProfile::Untrusted)),
        args.cap_drop,
        args.cap_add,
        caller_inherits_groups(),
    )
}

/// The same rule over the four inputs it actually reads, so a test can state every half.
///
/// NOT `&BoxRunArgs`, which has nearly two hundred fields and no `Default`: a rule whose test costs
/// that much to write is a rule that goes untested, and this one was. `inherits_groups` is the only
/// input that is not an argument, and it is the one whose absence was the defect.
pub(crate) fn range_buys_nothing_for(
    untrusted: bool,
    cap_drop: &[String],
    cap_add: &[String],
    inherits_groups: bool,
) -> bool {
    let drops_all = untrusted || cap_drop.iter().any(|d| d.eq_ignore_ascii_case("ALL"));
    drops_all && cap_add.is_empty() && !inherits_groups
}

/// Does this process carry a supplementary group that a box would inherit and that `setgid` does not
/// already cover?
///
/// The primary gid is excluded because it is not the leak: `setgid` puts the box's gid 0 at the
/// caller's primary gid on BOTH maps, so clearing it changes nothing. Everything else in the list is
/// an unmapped kgid inside the box, unnameable through `getgroups` there, and still counted by every
/// permission check outside it.
///
/// ONE SPELLING of "the groups this caller carries": [`crate::gpu_grant::Caller::current`] is the
/// only `getgroups` reader in this crate and asks the kernel in the documented two-call form. It
/// lives next to the GPU resolver because that is where the question was first asked; it is not a
/// GPU fact, and a second reader here is exactly the duplication that produced this defect.
fn caller_inherits_groups() -> bool {
    let primary = unsafe { libc::getgid() };
    crate::gpu_grant::Caller::current()
        .gids
        .iter()
        .any(|gid| *gid != primary)
}

/// Resolve the box's effective command from the user's `-- CMD` and the image's OCI config, docker-
/// style: the image `Entrypoint` is prepended to either the user's command or (if none) the image's
/// `Cmd`; a shell is the fallback when nothing is set anywhere. `--ssh` with no command keeps the box
/// alive instead (the sshd is a child of PID 1, which would otherwise exit). For `--rootfs` the
/// config is empty, so this reduces to the user's command or a shell - the prior behaviour.
///
/// ## The override, and why it is HERE
///
/// `entrypoint` is `--entrypoint`, and it is the whole of Docker's rule:
///
///   * `None` - not given. The image's `Entrypoint` stands, and the image's `Cmd` is the default
///     argument list.
///   * `Some(ep)` - the image's `Entrypoint` is REPLACED by `ep`, and the image's `Cmd` IS DISCARDED.
///     That second half is the part that is easy to miss and that Docker documents explicitly:
///     "passing `--entrypoint` will clear out any default command set on the image". Keeping the
///     `Cmd` would append the image's own arguments to a program that never expected them.
///   * `Some(&[])` - an empty override CLEARS the entrypoint, which is compose's `entrypoint: []`.
///     The command then runs as argv[0] with nothing in front of it.
///
/// ## Why it could not be done above this function
///
/// Both callers that already offered an override faked it by PREPENDING to the user's command: the
/// `docker` shim (removed on 2026-09-19) did `command.insert(0, ep)` and the compose parser did
/// `b.command = entrypoint ++ command`. That composes to `IMAGE_ENTRYPOINT ++ override ++ args`, which is correct only for an
/// image that has no `Entrypoint` - and an image with one is exactly when an override is needed.
/// Measured against `quay.io/keycloak/keycloak:26.1`, whose entrypoint is `kc.sh`: asking for a
/// shell produced `kc.sh sh -c …` and the image answered `Unknown option: 'sh'`. A field report hit
/// that and could not get a shell inside the image to diagnose a crash loop.
///
/// One mechanism, at the bottom, so the flag and compose cannot disagree about it.
pub(crate) fn resolve_image_command(
    user_command: &[String],
    ssh: bool,
    img: &kern_oci::ImageConfig,
    entrypoint: Option<&[String]>,
) -> Vec<String> {
    if user_command.is_empty() && ssh {
        return vec!["sleep".to_string(), "infinity".to_string()];
    }
    // The image's `Cmd` is a default for ITS OWN entrypoint. Once that entrypoint is replaced, the
    // default belongs to a program that is no longer being run.
    let args: Vec<String> = if user_command.is_empty() && entrypoint.is_none() {
        img.cmd.clone()
    } else {
        user_command.to_vec()
    };
    let mut full: Vec<String> = match entrypoint {
        Some(ep) => ep.to_vec(),
        None => img.entrypoint.clone(),
    };
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
/// The sidecar's FORMAT version, stamped on write and required on read.
///
/// WHY IT EXISTS, measured. `StartInterval` was added to the parser and to this sidecar on 14/09, and
/// a later pass found the fix reaching a freshly pulled image and NOT an image already in the
/// cache: same binary, same digest, 302 s against 6 s, the only difference being a sidecar written by
/// a kern that did not know the field. A missing line is indistinguishable from an image that declares
/// nothing, so the absence cannot be repaired by reading it harder. `kern compose pull` does not help
/// either, because a digest-pinned ref is already satisfied.
///
/// So the version decides: an entry stamped with anything older has its sidecar REFRESHED once, by
/// [`refresh_image_config`], which re-reads the config blob and leaves the rootfs alone. `3`: the
/// image's `VOLUME` paths (`volume` lines), which a box now mounts anonymous volumes at.
///
/// ⛔ NOT A CACHE MISS. The first version of this treated an old stamp as an incomplete entry, which
/// sent it down the repair path - and that path clears the image dir first. An image whose layers
/// hold subuid-owned files (postgres, mysql, redis, nginx) cannot have that directory removed by the
/// user that pulled it: `remove_dir_all` returns EPERM, and the entry was then unusable until
/// `--pull always`. Measured by a later pass on a 66-image, 22 GB cache. The rootfs was never
/// the stale part.
pub(crate) const IMAGE_CFG_FMT: u32 = 3;

pub(crate) fn write_image_config(
    path: &std::path::Path,
    c: &kern_oci::ImageConfig,
) -> std::io::Result<()> {
    let mut s = format!("fmt\t{IMAGE_CFG_FMT}\n");
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
    for l in &c.labels {
        line("label", l);
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
    for v in &c.volumes {
        line("volume", v);
    }
    for (port, udp) in &c.exposed_ports {
        line(
            "expose",
            &format!("{port}/{}", if *udp { "udp" } else { "tcp" }),
        );
    }
    if let Some(d) = &c.digest {
        line("digest", d);
    }
    // ADDITIVE, no format bump: an entry written before it has no line and reads as `None` (an
    // unknown repository digest, `<none>` as Docker prints it); a bump would send every old entry
    // down the repair path for a field nothing depends on.
    if let Some(d) = &c.repo_digest {
        line("repodigest", d);
    }
    if let Some(a) = &c.architecture {
        line("arch", a);
    }
    // One `history` line per step, its five fields tab-separated and escaped (a `created_by` holds
    // tabs and newlines as a matter of course): created, made-a-layer, compressed size, created_by,
    // comment. ADDITIVE like `repodigest`: an older entry has none and lists no history.
    for h in &c.history {
        line(
            "history",
            &format!(
                "{}\t{}\t{}\t{}\t{}",
                history_escape(h.created.as_deref().unwrap_or_default()),
                if h.empty_layer { 0 } else { 1 },
                h.layer_size.map_or_else(String::new, |n| n.to_string()),
                history_escape(&h.created_by),
                history_escape(h.comment.as_deref().unwrap_or_default()),
            ),
        );
    }
    if let Some(sig) = &c.stop_signal {
        line("stopsignal", sig);
    }
    // THE SIDECAR IS THE ONLY COPY, so a field missing here is a field the box never sees. The
    // healthcheck round-trips as one `test` line per argv element plus its numbers, which keeps the
    // format line-based and keeps `Test` order - the first element decides how the rest is read.
    if let Some(h) = &c.healthcheck {
        for a in &h.test {
            line("hctest", a);
        }
        for (k, v) in [
            ("hcinterval", h.interval_ns),
            ("hctimeout", h.timeout_ns),
            ("hcstart", h.start_period_ns),
            ("hcstartint", h.start_interval_ns),
        ] {
            if let Some(v) = v {
                line(k, &v.to_string());
            }
        }
        if let Some(r) = h.retries {
            line("hcretries", &r.to_string());
        }
    }
    std::fs::write(path, s)
}

/// A history field on one sidecar line: `\\`, tab, newline and CR escaped, so a line stays a line.
fn history_escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for ch in v.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

fn history_unescape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut it = v.chars();
    while let Some(ch) = it.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match it.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
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
            "label" => c.labels.push(v.to_string()),
            "workdir" => c.workdir = Some(v.to_string()),
            // Re-checked on read: the sidecar is a file in the caller's cache, not the registry's
            // word, and the box mounts a volume at each path.
            "volume"
                if kern_oci::volume_path_is_valid(v)
                    && c.volumes.len() < kern_oci::MAX_IMAGE_VOLUMES =>
            {
                c.volumes.push(v.to_string());
            }
            "user" => c.user = Some(v.to_string()),
            "expose" => {
                if let Some((num, proto)) = v.split_once('/') {
                    if let Ok(port) = num.parse::<u16>() {
                        c.exposed_ports
                            .push((port, proto.eq_ignore_ascii_case("udp")));
                    }
                }
            }
            "stopsignal" => c.stop_signal = Some(v.to_string()),
            "digest" => c.digest = Some(v.to_string()),
            "repodigest" => c.repo_digest = Some(v.to_string()),
            "history" => {
                let f: Vec<&str> = v.split('\t').collect();
                if let [created, layer, size, by, comment] = f.as_slice() {
                    let opt = |x: &str| (!x.is_empty()).then(|| history_unescape(x));
                    c.history.push(kern_oci::HistoryEntry {
                        created: opt(created),
                        created_by: history_unescape(by),
                        comment: opt(comment),
                        empty_layer: *layer == "0",
                        layer_size: size.parse().ok(),
                    });
                }
            }
            "arch" => c.architecture = Some(v.to_string()),
            "hctest" => c
                .healthcheck
                .get_or_insert_with(Default::default)
                .test
                .push(v.to_string()),
            // ⛔ EVERY KEY `write_image_config` WRITES MUST BE LISTED HERE. `hcstartint` was written
            // and not listed, so it fell through to `_ => {}` and the inner arm that parses it was
            // unreachable: a cached image's `StartInterval` was read back as absent while the same
            // image pulled fresh honoured it. Measured by a later pass as 300 s against 6 s with an
            // IDENTICAL sidecar on disk, which is what pointed at the reader instead of the writer.
            "hcinterval" | "hctimeout" | "hcstart" | "hcstartint" | "hcretries" => {
                // A number line WITHOUT a `hctest` line describes a check that has no command, which
                // is not a check: `healthcheck_after` refuses an empty `Test` for the same reason.
                if let Some(h) = c.healthcheck.as_mut() {
                    match k {
                        "hcinterval" => h.interval_ns = v.parse().ok(),
                        "hctimeout" => h.timeout_ns = v.parse().ok(),
                        "hcstart" => h.start_period_ns = v.parse().ok(),
                        "hcstartint" => h.start_interval_ns = v.parse().ok(),
                        _ => h.retries = v.parse().ok(),
                    }
                }
            }
            _ => {}
        }
    }
    c
}

/// Is this sidecar's format the one this kern writes? A file with no `fmt` line predates the stamp.
pub(crate) fn image_config_is_current(path: &std::path::Path) -> bool {
    let Ok(body) = std::fs::read_to_string(path) else {
        return false;
    };
    body.lines()
        .filter_map(|l| l.strip_prefix("fmt\t"))
        .filter_map(|v| v.trim().parse::<u32>().ok())
        .any(|v| v >= IMAGE_CFG_FMT)
}

/// Bring a sidecar written by an older kern up to [`IMAGE_CFG_FMT`], WITHOUT touching the rootfs.
///
/// A config blob is a few kilobytes named by the manifest, so this is three small requests (~2 s on
/// Docker Hub) against a re-pull of the whole image, and it is the only part that was ever stale. It
/// is announced, because 2 s on a path that usually costs milliseconds should say why.
///
/// STAMPED EITHER WAY, so an entry costs at most ONE round trip. With no network the old config is
/// written back under the current stamp and the box runs exactly as the previous kern ran it; the
/// note names `--pull always`, which is the full repair. Retrying on every start instead would put a
/// 10 s connect timeout in front of every `kern box --image` on a machine that is offline.
///
/// Lock-free like the fast path that calls it: the write goes to a temp file and is renamed over the
/// sidecar, so a concurrent reader sees the old file or the new one, never half of one.
fn refresh_image_config(
    image: &str,
    cache: &std::path::Path,
    safe: &str,
    cfgfile: &std::path::Path,
) {
    eprintln!(
        "kern: note: image '{image}' was cached by an older kern - re-reading its config once (no layers)"
    );
    let scratch = cache.join(format!("{safe}.cfg-{}", std::process::id()));
    let fetched = kern_oci::fetch_image_config(image, &scratch, None);
    let _ = std::fs::remove_dir_all(&scratch);
    let config = match fetched {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "kern: note: could not re-read the config of '{image}' ({e}); keeping the cached one \
                 - `--pull always` re-fetches the image"
            );
            read_image_config(cfgfile)
        }
    };
    replace_image_config(cache, safe, cfgfile, &config);
}

/// Replace an image's config sidecar in one `rename`, so a box starting meanwhile reads the old file
/// or the new one, never half of one. Best effort: on failure the old file stays.
pub(crate) fn replace_image_config(
    cache: &std::path::Path,
    safe: &str,
    cfgfile: &std::path::Path,
    config: &kern_oci::ImageConfig,
) {
    let tmp = cache.join(format!("{safe}.image-{}", std::process::id()));
    if write_image_config(&tmp, config).is_err() || std::fs::rename(&tmp, cfgfile).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Where the account files (`etc/passwd`, `etc/group`) are read from.
///
/// Two sources and one set of lookups, so `kern box` resolving an image's `USER` and `kern exec
/// --user` resolving a name inside a running box cannot drift into two answers for the same spec.
pub(crate) enum Accounts<'a> {
    /// The image's layers on the host, TOP first: one entry for a flat image, several for a built one.
    /// Read PRE-PIVOT at box start, where no merged root exists yet.
    Layers(&'a [String]),
    /// A RUNNING box's two files, read ONCE by [`Accounts::of_box_root`]: `docker exec --user`
    /// resolves against the container's CURRENT files, so an account the box created after it
    /// started is found, and a passwd the box rewrote is the one that answers.
    Read {
        passwd: Option<String>,
        group: Option<String>,
    },
}

/// An account file larger than this is not parsed, from either source. It matters most for a running
/// box, whose own code writes the file kern reads; a directory-sized passwd is a few MB.
const ACCOUNT_FILE_MAX: u64 = 8 << 20;

impl Accounts<'_> {
    /// A running box's `/etc/passwd` and `/etc/group`, through `openat2(RESOLVE_IN_ROOT)` on `root`
    /// (an `O_PATH` dirfd on `/proc/<pid1>/root`, see [`crate::openat2::box_root_fd`]). An absolute
    /// symlink there means the BOX's path, which is what it means to the box; `canonicalize` cannot
    /// do that one, because `/proc/<pid>/root` of a box in its own mount namespace reads back as `/`
    /// and a path built on it is the HOST's `/etc/passwd` (measured: a box linking its passwd to a host
    /// file got `kern exec -u victim` running as the uid that host file gave). A missing file is
    /// `None`; one that is there and unusable (not a regular file, past the bound, not UTF-8) or a
    /// resolution that failed (no `openat2` before Linux 5.6) is the error, named.
    pub(crate) fn of_box_root(
        root: std::os::fd::BorrowedFd<'_>,
    ) -> std::io::Result<Accounts<'static>> {
        let read = |file: &str| {
            crate::openat2::read_regular_in_root(root, file, ACCOUNT_FILE_MAX)
                .map_err(|e| std::io::Error::new(e.kind(), format!("/{file}: {e}")))
        };
        Ok(Accounts::Read {
            passwd: read("etc/passwd")?,
            group: read("etc/group")?,
        })
    }

    /// The whole text of `file`, from the FIRST layer that has a readable one (top-most wins, as the
    /// merged view would), or from what was read off a running box. `None` when there is none.
    ///
    /// The layers are read on the host, CONFINED: a hostile image whose `/etc/passwd` is a symlink to
    /// a host path (`/etc/passwd`, `../../../etc/passwd`) would otherwise make kern read a host file,
    /// so the target is canonicalized and must stay under the canonical layer, and one that escapes
    /// counts as "no file in this layer". An in-rootfs symlink (a real distro layout) still resolves.
    ///
    /// Only a REGULAR file of bounded size, without blocking: an image can put a FIFO at
    /// `/etc/passwd`, and a plain read of one waits for a writer that never comes. MEASURED on 0.30.2
    /// with an image built `RUN rm /etc/passwd && mkfifo /etc/passwd` / `USER nobody`: `kern box
    /// --image` never started it (killed at 20 s). A layer whose file is not a readable regular one is
    /// skipped, as an unreadable one always was, so the layer under it answers: that image now runs as
    /// alpine's `nobody`, 65534, which is the image's own account either way.
    fn text(&self, file: &str) -> Option<std::borrow::Cow<'_, str>> {
        use std::borrow::Cow;
        match self {
            Accounts::Layers(lower) => {
                use std::os::unix::fs::OpenOptionsExt;
                use std::path::Path;
                lower.iter().find_map(|layer| {
                    let target = std::fs::canonicalize(Path::new(layer).join(file)).ok()?;
                    let base = std::fs::canonicalize(layer).ok()?;
                    if !target.starts_with(&base) {
                        return None;
                    }
                    let f = std::fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(crate::openat2::READ_UNTRUSTED)
                        .open(&target)
                        .ok()?;
                    crate::openat2::read_regular(&f, ACCOUNT_FILE_MAX)
                        .ok()
                        .map(Cow::Owned)
                })
            }
            Accounts::Read { passwd, group } => match file {
                "etc/passwd" => passwd.as_deref().map(Cow::Borrowed),
                "etc/group" => group.as_deref().map(Cow::Borrowed),
                _ => None,
            },
        }
    }

    /// The colon-separated FIELDS of the first line of `file` whose column `key_field` is `key`.
    /// `key_field` is `0` for a name and `2` for the numeric id, which is what a NUMERIC spec needs.
    /// `None` when there is no file or no such line; a file with no match is authoritative, and the
    /// layers below it are not consulted, as the merged view would not.
    pub(crate) fn entry(&self, file: &str, key: &str, key_field: usize) -> Option<Vec<String>> {
        let text = self.text(file)?;
        text.lines()
            .find(|line| line.split(':').nth(key_field) == Some(key))
            .map(|line| line.split(':').map(str::to_string).collect())
    }
}

/// A user spec's two halves, `<user>[:<group>]`, each non-empty, or `None`. ONE RULE for `kern box
/// --user`, an image's `USER` and `kern exec -u`: an empty half is not "the default", it is a typo.
pub(crate) fn split_user_spec(spec: &str) -> Option<(&str, Option<&str>)> {
    let (user, group) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    (!user.is_empty() && group.is_none_or(|g| !g.is_empty())).then_some((user, group))
}

/// `--group-add` / compose `group_add:`, as gids: a number as it is, a name from the IMAGE's
/// `/etc/group`, which is where docker resolves it. A name the image does not have is refused with
/// docker's own sentence rather than dropped: a group the file asked for and the box does not carry
/// fails later as an EACCES nobody can trace back to it.
pub(crate) fn group_add_gids(names: &[String], accounts: &Accounts) -> Result<Vec<u32>, String> {
    let mut out: Vec<u32> = Vec::new();
    for name in names {
        let gid = match name.parse::<u32>() {
            Ok(g) => g,
            Err(_) => accounts
                .entry("etc/group", name, 0)
                .and_then(|f| f.get(2).and_then(|g| g.parse::<u32>().ok()))
                .ok_or_else(|| {
                    format!(
                        "Unable to find group {name}: no matching entries in group file (the \
                         image's /etc/group; `--group-add` also takes a numeric gid)"
                    )
                })?,
        };
        if !out.contains(&gid) {
            out.push(gid);
        }
    }
    Ok(out)
}

/// The SUPPLEMENTARY groups an image's `config.User` spec puts the workload in, from the image's own
/// `/etc/group`.
///
/// EMPTY WHEN THE SPEC NAMES A GROUP, and that is the rule Docker and podman follow rather than a
/// choice made here: runc's `GetExecUser` fills the supplementary set only for a user given WITHOUT
/// a group. CONFIRMED ON DOCKER 29.6.2 with an image whose `/etc/group` reads `root:x:0:app`: a bare
/// `USER 1000` gives `groups=0(root),1000(app)` and an explicit `--user 1000:1000` gives
/// `groups=1000(app)`. MEASURED first with podman 4.9.3 on the dev host, three cases: the kibana image (`User "1000"`,
/// no group) gives `uid=1000 gid=1000 groups=1000,0`; the elasticsearch image (`User "1000:0"`)
/// gives `groups=0` and nothing more; and an explicit `--user 1000:1000` on the kibana image gives
/// `groups=1000`. kern granted none of them, which cost Elastic's own compose file its Kibana - the
/// certificates its `setup` service writes are `root:root` mode 640 and readable only through
/// group 0, where `root:x:0:kibana` puts it.
///
/// The PRIMARY gid is not repeated here: `setgid` already sets it.
pub(crate) fn supplementary_gids(spec: &str, accounts: &Accounts) -> Vec<u32> {
    if spec.contains(':') {
        return Vec::new();
    }
    // The account NAME, which is what a group's member list holds. A numeric spec has to be turned
    // into its name first, and an uid with no passwd entry has no memberships to find.
    let name = match spec.parse::<u32>() {
        Ok(n) => match accounts.entry("etc/passwd", &n.to_string(), 2) {
            Some(e) => e.first().cloned().unwrap_or_default(),
            None => return Vec::new(),
        },
        Err(_) => spec.to_string(),
    };
    if name.is_empty() {
        return Vec::new();
    }
    let Some(text) = accounts.text("etc/group") else {
        return Vec::new();
    };
    // A SET FOR THE DUPLICATES AND A CEILING ON THE COUNT, both because the file is the image's and
    // the image is untrusted. `/etc/group` is read up to `ACCOUNT_FILE_MAX`, which is room for some
    // hundreds of thousands of lines naming the same user: a `contains` scan per line is quadratic in
    // that, in the host CLI, before the box has started. And `setgroups` refuses a list past
    // `NGROUPS_MAX` (65536) with `EINVAL`, which `set_user` can only report as "outside this box's gid
    // map" - a sentence that would be wrong about its own cause. Order is kept (the file's), which is
    // the order podman passes too.
    const NGROUPS_MAX: usize = 65536;
    let mut out: Vec<u32> = Vec::new();
    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut over = false;
    for line in text.lines() {
        // `name:x:gid:member,member`
        let f: Vec<&str> = line.split(':').collect();
        let (Some(gid), Some(members)) = (f.get(2), f.get(3)) else {
            continue;
        };
        if !members.split(',').any(|m| m.trim() == name) {
            continue;
        }
        if let Ok(g) = gid.parse::<u32>() {
            if seen.insert(g) {
                if out.len() == NGROUPS_MAX {
                    over = true;
                    break;
                }
                out.push(g);
            }
        }
    }
    if over {
        eprintln!(
            "kern: warning: this image's /etc/group puts '{name}' in more than {NGROUPS_MAX} \
             groups, which is more than the kernel accepts: the workload gets the first \
             {NGROUPS_MAX}. A file readable only through one of the others will fail with EACCES."
        );
    }
    out
}

/// The HOME the workload's uid has in the image's own `/etc/passwd` (field 6), or `/` when the image
/// has no entry for it.
///
/// kern set `HOME=/root` for every box whatever user it ran as, and that is not a cosmetic default:
/// a Python console script installed with `pip install --user` lives under `$HOME/.local`, so an
/// image that puts its tools there loses them entirely. MEASURED on `apache/airflow:3.3.1`, whose
/// passwd says `airflow:x:50000:0:…:/home/airflow`: podman runs `airflow version` and prints 3.3.1,
/// kern ran the same command in the same image as the same uid and got
/// `ModuleNotFoundError: No module named 'airflow'`, because with `HOME=/root` the interpreter's
/// user site-packages directory is `/root/.local/...`, which does not exist.
///
/// `/` for an unknown uid is runc's default user, and it is what Docker actually does: measured on
/// Docker 29.6.2, `--user 1234 -w /opt/wd` prints `HOME=/`, while podman substitutes the image's
/// WorkingDir for the same input (`HOME=/opt/airflow` for `--user 1000` on the airflow image). This
/// is the one rule here taken from Docker over podman, and both halves are now measured rather than
/// argued: a known uid gives its passwd home under all three.
pub(crate) fn user_home(uid: u32, accounts: &Accounts) -> String {
    accounts
        .entry("etc/passwd", &uid.to_string(), 2)
        .and_then(|e| e.get(5).cloned())
        .filter(|h| h.starts_with('/'))
        .unwrap_or_else(|| "/".to_string())
}

/// Resolve an image's `config.User` spec (`user[:group]`, each a NAME or a number) to `(uid, gid)` using
/// the image's OWN `/etc/passwd` and `/etc/group`, exactly as Docker does. The rootfs is already
/// extracted on the host pre-pivot, so `USER memcache` no longer forces the box to run as root: it maps
/// to that account's uid/gid. Docker's rule - a bare user takes its primary group from the passwd entry;
/// an explicit `:group` overrides it. Returns `None` (caller keeps box-root, with a note) if the account
/// isn't in the image, so an image referencing a host-provided name still degrades honestly.
pub(crate) fn resolve_user(spec: &str, accounts: &Accounts) -> Option<(u32, u32)> {
    let (user, group) = split_user_spec(spec)?;
    // The user half yields both a uid and (for a bare `USER name`) the default gid from its ONE passwd
    // line: fields are `name:x:uid:gid:…`, so index 2 is the uid and 3 the primary gid.
    let (uid, passwd_gid) = match user.parse::<u32>() {
        // A NUMERIC user takes its primary group from the image's passwd entry FOR THAT UID, and
        // the ROOT group when the image has no entry for it. It does NOT take the uid as its gid,
        // which is what this did.
        //
        // ## What that cost
        //
        // `quay.io/keycloak/keycloak:26.1` declares `USER 1000` numerically and its passwd says
        // `keycloak:x:1000:0:` - primary group 0. Its own tree is laid out for that:
        // `/opt/keycloak/lib/quarkus` is `drwxrwxr-x root root`, writable by the OWNER and by GROUP
        // 0 and by nobody else. Run with gid 1000, the process cannot write its own installation.
        //
        // Keycloak's startup runs a Quarkus augmentation that writes into its runner JAR, so the
        // failure surfaced far from its cause: `jdk.nio.zipfs` opens a JAR it cannot write as a
        // READ-ONLY zip filesystem, and the first `Files.createDirectory` inside it throws
        // `ReadOnlyFileSystemException`. The box then restart-looped. A field report reported that
        // exception and could not get past it; its author guessed at disk exhaustion, and this host
        // reproduced the same crash with 3.2 GB free, which ruled that out.
        //
        // Three facts agree on gid 0 being right: the image's own passwd, the group bits on its own
        // directories, and the report's baseline that the identical file runs healthy under Docker
        // Compose.
        Ok(n) => {
            let gid = accounts
                .entry("etc/passwd", &n.to_string(), 2)
                .and_then(|e| e.get(3)?.parse().ok())
                .unwrap_or(0);
            (n, gid)
        }
        Err(_) => {
            let e = accounts.entry("etc/passwd", user, 0)?;
            (e.get(2)?.parse().ok()?, e.get(3)?.parse().ok()?)
        }
    };
    let gid = match group {
        None => passwd_gid,
        // `group` fields are `name:x:gid:…`, so index 2 is the gid.
        Some(g) => match g.parse::<u32>() {
            Ok(n) => n,
            Err(_) => accounts.entry("etc/group", g, 0)?.get(2)?.parse().ok()?,
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
            // `force_remove_dir_all`, not `remove_dir_all`: a retired image keeps its own ownership,
            // and on a host with a subordinate range a Debian base carries `drwx------ _apt`, which
            // this user cannot empty. MEASURED: two `.old-<pid>` copies (357 MB) survived every
            // sweep, reported by nothing.
            if e.path().is_dir() && force_remove_dir_all(&e.path()).is_ok() {
                n += 1;
            }
        }
    }
    n
}

/// Image cache entries no ref can reach any more, and the bytes they hold.
///
/// WHAT MAKES ONE. The cache key is `sanitize_ref(<ref>)`, and that function has changed: an entry
/// written by an older kern sits under a key today's kern never computes, so nothing resolves it,
/// nothing refreshes it and no sweep collects it. MEASURED by a later pass: `alpine` under
/// two keys, one from July and one from September, listed by `kern images` as two `alpine:latest`
/// (56 days ago beside 4 hours ago) with only the second reachable.
///
/// THE TEST IS EXACT, not a heuristic: the entry's own `.ok` sentinel holds the ref it was pulled
/// for, so re-sanitising that ref says what its key WOULD be today. If that differs from the key it
/// actually sits under, no invocation of kern can ever name it. An entry whose sentinel is missing or
/// unreadable is left alone - it might be mid-pull, and this must never race a writer.
///
/// SKIPPED ENTIRELY WHILE A BOX IS REGISTERED, for the reason `sweep_retired_images` documents: a
/// live box holds its lower dir's inodes through an overlay mount and opens files from it lazily.
pub(crate) fn sweep_unreachable_images(cache: &std::path::Path) -> (usize, u64) {
    if !registry::list().is_empty() {
        return (0, 0);
    }
    let (mut n, mut freed) = (0usize, 0u64);
    let Ok(rd) = std::fs::read_dir(cache) else {
        return (0, 0);
    };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(key) = name.to_str() else { continue };
        // Only a `<key>.ok` sentinel names an entry; everything else here is a sidecar or a dir.
        let Some(stem) = key.strip_suffix(".ok") else {
            continue;
        };
        // A BUILT image is keyed by its tag and has no registry ref to re-derive, and the layer
        // store under `L/` is swept by `sweep_orphan_layers`. Only a flat pulled entry is decided
        // here, which is the population the key change affected.
        if !cache.join(stem).is_dir() || cache.join(format!("{stem}.layers")).exists() {
            continue;
        }
        let Ok(reference) = std::fs::read_to_string(e.path()) else {
            continue;
        };
        let reference = reference.trim();
        if reference.is_empty() || sanitize_ref(reference) == stem {
            continue; // reachable: this is the key kern computes for that ref today
        }
        let dir = cache.join(stem);
        let bytes = dir_size(&dir);
        // The rootfs can hold subuid-owned directories, exactly like the repair path, so it goes
        // through the ONE hard-removal spelling: chmod what we own, then retry as root of an
        // id-mapped namespace for what we do not.
        let _ = crate::commands::remove_tree_mapped(&dir);
        if dir.exists() {
            continue; // could not reclaim it; leave every sidecar in place so the state stays whole
        }
        for side in [
            ".ok", ".image", ".size", ".lock", ".diff", ".base", ".owners",
        ] {
            let _ = std::fs::remove_file(cache.join(format!("{stem}{side}")));
        }
        n += 1;
        freed += bytes;
    }
    (n, freed)
}

/// One layer whose directory outlived the sweep that tried to remove it.
///
/// Its sentinel is gone either way (the sweep removes that FIRST), so a stuck layer is debris on
/// disk and can never be a build-cache hit. What is left is bytes nobody can reclaim from here, and
/// the reason, which is almost always a subuid-owned file an unprivileged user cannot unlink.
pub(crate) struct StuckLayer {
    /// The `<32hex>` layer key, so the entry can be named and found.
    pub(crate) key: String,
    /// Size measured BEFORE the attempt: bytes still on disk.
    pub(crate) bytes: u64,
    /// The first failure, already annotated by [`force_remove_dir_all`] with the path and its owner.
    pub(crate) why: std::io::Error,
}

/// What a layer sweep did: what it removed, what that was worth to the caller, and what it could not
/// remove.
///
/// IT RETURNS THE FAILURES INSTEAD OF DROPPING THEM. The pair this replaced was `(count, bytes)`,
/// which has no room for "and these three are still there", so the loop below had no choice but to
/// discard a failed removal in silence. `force_remove_dir_all`, 130 lines down this same file,
/// already carries the rule in its own doc comment: *a caller that genuinely does not care can still
/// ignore the result, but it has to say so*.
#[derive(Default)]
pub(crate) struct LayerSweep {
    /// Layer directories actually gone from disk.
    pub(crate) removed: usize,
    /// Bytes reclaimed, counted per the caller's `charge` filter.
    pub(crate) freed: u64,
    /// Layers whose directory survived. Empty on every ordinary sweep, so it allocates nothing.
    pub(crate) stuck: Vec<StuckLayer>,
}

impl LayerSweep {
    /// Bytes still on disk under the layers that could not be removed.
    pub(crate) fn stuck_bytes(&self) -> u64 {
        self.stuck
            .iter()
            .fold(0u64, |a, s| a.saturating_add(s.bytes))
    }

    /// The sentence a caller prints when a sweep could not reclaim everything, or `None` when it
    /// could - which is every ordinary sweep.
    ///
    /// ONE SPELLING, TWO CALLERS. `gc` and `image_prune` report the same fact about the same sweep,
    /// and two copies of a sentence are two sentences that drift: this repository has paid for that
    /// shape before, in a census that carried its own copy of a sidecar list. It also makes the
    /// wording testable without a filesystem that can produce an unremovable tree, which an
    /// unprivileged test cannot create - the real cause is a subuid-owned file.
    ///
    /// The KEY is in the sentence, not only the errno: a reader told "Permission denied" has to find
    /// which of the cache's layers it was, and `L/<key>` is a path they can look at.
    pub(crate) fn stuck_note(&self, what: &str) -> Option<String> {
        let first = self.stuck.first()?;
        Some(format!(
            "kern: note: {} orphaned {what}{} could not be removed, {} still on disk. First: L/{}: {}",
            self.stuck.len(),
            if self.stuck.len() == 1 { "" } else { "s" },
            human_bytes(self.stuck_bytes()),
            first.key,
            first.why
        ))
    }
}

/// Delete build-layer dirs in `L/` not referenced by any `<tag>.layers` manifest. Only touches
/// `L/<32hex>` entries, never a pulled/built image itself.
pub(crate) fn sweep_orphan_layers(cache: &std::path::Path) -> LayerSweep {
    sweep_orphan_layers_charged(cache, None)
}

/// [`sweep_orphan_layers`], with a say over WHICH of the layers it reclaims are charged to the
/// caller's number.
///
/// THE SWEEP IS CACHE-WIDE AND THE REPORT WAS NOT. `remove_image` returns the bytes `kern rmi`
/// prints as "freed N", and it added everything this sweep reclaimed - including layers orphaned by
/// some EARLIER removal that nobody had swept yet. MEASURED on a working cache: two names of one
/// image, `rmi` of the first printed `freed 140.3M` and `rmi` of the second printed `freed 140.3M`
/// again, while `du` on the layer store showed it unchanged across both. The bytes were real debris
/// and the sweep was right to take it; the sentence attributing it to the image just named was not.
///
/// `charge = Some(keys)` counts only the reclaimed layers whose key is in `keys`, which for a
/// removal is the set that image's own manifest named. Everything orphaned is still DELETED - the
/// sweep's job is the cache's health, not the caller's arithmetic - and the returned count is the
/// total reclaimed, so `gc` keeps reporting the whole cleanup. `None` charges everything, which is
/// what `gc` means by the same number.
pub(crate) fn sweep_orphan_layers_charged(
    cache: &std::path::Path,
    charge: Option<&std::collections::HashSet<String>>,
) -> LayerSweep {
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
                    // Incomplete reference set → don't risk deleting live layers. Nothing was
                    // touched, so nothing is stuck either.
                    Err(_) => return LayerSweep::default(),
                }
            }
        }
    }
    let Ok(rd) = std::fs::read_dir(&lc) else {
        return LayerSweep::default();
    };
    // THE KEYS ARE READ BEFORE ANYTHING IS DELETED, and that is not tidiness. POSIX leaves `readdir`
    // unspecified when the directory being walked is modified during the walk, and the loop that
    // used to live here unlinked entries from the very directory it was streaming. A removal can
    // therefore make the stream skip a LATER entry, and the two entries of one layer (`<key>` and
    // `<key>.ok`) are independent entries: skipping the second is how a sentinel outlives the
    // directory it stands for. Reading the list first costs one set on a cold path and the question
    // stops existing. Both entries fold to one key, so each layer is handled exactly once.
    let mut keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        // Only reap `<32hex>` layer dirs and their `.ok`; anything else in `L/` is not ours to judge.
        let key = name.strip_suffix(".ok").unwrap_or(&name);
        if key.len() != 32
            || !key.bytes().all(|b| b.is_ascii_hexdigit())
            || referenced.contains(key)
        {
            continue;
        }
        keys.insert(key.to_string());
    }
    let mut swept = LayerSweep::default();
    for key in keys {
        // ⛔ THE SENTINEL GOES FIRST, AND THE ORDER IS THE WHOLE FIX. `layer_cached` reads `<key>.ok`
        // plus `<key>/` being a directory, so a layer is a build-cache HIT while both exist. Removing
        // the directory first and the sentinel after leaves a window - and on the one host shape that
        // matters it is not a window but the normal outcome: a layer carrying a file owned by a
        // mapped subuid cannot be fully unlinked by this user, so the removal takes what it can and
        // leaves the rest. The directory survives, PARTIALLY EMPTIED, with its sentinel intact, and
        // the next build reads that as a complete layer. MEASURED from outside against v0.32.0: a
        // layer from `RUN useradd -m -u 10001 app` kept `home/app` and `sys/` while `etc/passwd` was
        // gone, `compose build` printed `built`, and the box died with "user 'app' has no account in
        // the image's /etc/passwd" - an error naming a subsystem that was not at fault.
        //
        // Sentinel first makes that unreachable by construction, for every exit path including a
        // crash between the two statements: what is left is a directory with no sentinel, which is a
        // MISS, and a miss only ever costs a rebuild. This is the discipline `drop_image_artifacts`
        // already applies to images, where `.ok` and `.image` go before the payload.
        let _ = std::fs::remove_file(lc.join(format!("{key}.ok")));
        let dir = lc.join(&key);
        if !dir.is_dir() {
            // Either an orphaned sentinel whose layer is already gone - the file above was the whole
            // entry - or a `<32hex>` that is not a directory at all. Nothing kern writes takes that
            // second shape, and the loop this replaced removed it anyway through its `else` arm; it
            // is still removed, so `gc` reclaims exactly what it used to and the change of shape
            // cannot quietly narrow what a sweep reaches.
            let _ = std::fs::remove_file(&dir);
            continue;
        }
        // Sized BEFORE the attempt and charged only when the attempt succeeded: a directory that
        // could not be removed is still on disk, and counting it is how a "freed" number comes to
        // describe bytes that are still there.
        let sz = dir_size(&dir);
        // `force_remove_dir_all`, NOT `std::fs::remove_dir_all`, and for the reason that function's
        // own doc comment records: a layer is unpacked with the image's own ownership, so it holds
        // directories this process does not own and cannot chmod, and unlinking inside one needs
        // write permission ON IT. Six other removers in this tree already take that path; this one
        // did not, which is why a layer the image path would have reclaimed was left behind here.
        match force_remove_dir_all(&dir) {
            Ok(()) => {
                swept.removed += 1;
                if charge.is_none_or(|keys| keys.contains(key.as_str())) {
                    swept.freed = swept.freed.saturating_add(sz);
                }
            }
            // REPORTED, NOT DISCARDED. The previous shape was `if remove(..).is_ok() { count += 1 }`
            // with no other arm, so an unremovable layer was invisible: not freed, not counted, not
            // named, and still on disk. The caller decides what to say; it can no longer fail to know.
            Err(why) => swept.stuck.push(StuckLayer {
                key,
                bytes: sz,
                why,
            }),
        }
    }
    swept
}

/// On-disk `(size_bytes, dangling)` of cached image `<stem>`, computed in ONE pass - a flat pulled
/// image (`<stem>/`) or single-diff build (`<stem>.diff/`) is sized by its dir and never dangles; a
/// multi-layer build sums its referenced `L/<key>` dirs AND dangles if any is missing (a present but
/// 0-byte layer is a valid EMPTY build, not dangling); a sentinel with no payload at all dangles. Both
/// `kern images` and the build-history record read this, so size and health can't drift, and each
/// manifest/layer is stat'd once. The layer cache is `<cache>/L` (== [`layer_cache_dir`] when `cache`
/// is [`cache_dir`]), derived from the arg so it stays consistent with the entry and is testable.
pub(crate) fn image_stat(cache: &std::path::Path, stem: &str) -> (u64, bool) {
    image_stat_memo(cache, stem, &mut std::collections::HashMap::new())
}

/// [`image_stat`], sharing one layer-size map across a SWEEP of images.
///
/// The on-disk sidecar is keyed by the layer, which is right, but it is still a file: an image
/// whose base layer is shared with twelve others re-reads that one sidecar thirteen times in a
/// single listing. Measured on a host with 316 images over 364 distinct layers, one sweep followed
/// 889 layer references. `memo` holds each layer's answer - `Some(bytes)` present, `None` missing -
/// for the lifetime of the sweep and no longer, so a layer that changes between two of them is
/// re-read. The single-image form above passes a throwaway map and so behaves exactly as before.
pub(crate) fn image_stat_memo(
    cache: &std::path::Path,
    stem: &str,
    memo: &mut std::collections::HashMap<std::path::PathBuf, Option<u64>>,
) -> (u64, bool) {
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
                let known = match memo.get(&d) {
                    Some(v) => *v,
                    None => {
                        // Stamped against the layer directory itself, not the image sentinel: an `L/`
                        // layer is SHARED between images, so keying it per-image would recompute it
                        // once per referrer and cache the same bytes several times over.
                        let v = d.is_dir().then(|| dir_size_cached(&d, &d));
                        memo.insert(d, v);
                        v
                    }
                };
                match known {
                    Some(bytes) => size += bytes,
                    None => dangling = true, // a referenced layer is gone → the image can't be assembled
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
///
/// Returns whether every artifact is GONE. The two directories can fail (see `force_remove_dir_all`),
/// and a caller that prints "freed N bytes" has to know: this used to be a `()` and the two results
/// were discarded, which is how `rmi` came to report a removal it had not performed.
pub(crate) fn drop_image_artifacts(cache: &std::path::Path, stem: &str) -> bool {
    let root = force_remove_dir_all(&cache.join(stem));
    let diff = force_remove_dir_all(&cache.join(format!("{stem}.diff")));
    for e in [&root, &diff].into_iter().flat_map(|r| r.as_ref().err()) {
        eprintln!("kern: warning: {e}");
    }
    let complete = root.is_ok() && diff.is_ok();
    for suffix in CACHE_SIDECARS {
        let _ = std::fs::remove_file(cache.join(format!("{stem}{suffix}")));
    }
    complete
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
pub(crate) fn force_remove_dir_all(path: &std::path::Path) -> std::io::Result<()> {
    // The SAME walk `remove_tree_forced` performs, plus the id-mapped retry: a layer unpacked with
    // the image's own ownership leaves directories this process does not own and cannot chmod, and
    // unlinking inside one needs write permission ON IT. See `remove_tree_mapped`.
    //
    // THE ERROR IS RETURNED NOW, NOT DISCARDED. This function's own doc comment above explains that
    // reporting a removal that did not happen is the costliest defect on this path, and it then
    // swallowed exactly that: MEASURED, `kern rmi kibana:7.16.1` printed "freed 1.1G" and left 85
    // entries behind. A caller that genuinely does not care can still ignore the result, but it has
    // to say so.
    remove_tree_mapped(path)
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
    // THE LAYER KEYS THESE STEMS NAME, read BEFORE their manifests are removed, so the sweep below
    // can charge this removal for its OWN layers and no others. A manifest that cannot be read
    // contributes nothing to the set: an unreadable one means this removal cannot claim those bytes,
    // which is the conservative direction for a number a person reads as "space I got back".
    let mut mine: std::collections::HashSet<String> = std::collections::HashSet::new();
    for stem in &stems {
        if let Ok(body) = std::fs::read_to_string(cache.join(format!("{stem}.layers"))) {
            mine.extend(body.lines().skip(1).map(|l| l.trim().to_string()));
        }
    }
    for stem in &stems {
        let flat = cache.join(stem);
        let diff = cache.join(format!("{stem}.diff"));
        if flat.is_dir() {
            freed += dir_size(&flat);
        }
        if diff.is_dir() {
            freed += dir_size(&diff);
        }
        // THE MEASURED SIZE IS ONLY FREED IF THE REMOVAL FINISHED. This function's caller prints
        // "freed N", and the size was measured BEFORE the delete: counting it after a partial removal
        // is how `rmi` came to say "freed 1.1G" over 85 surviving entries. Re-measure what is left
        // and subtract it, so the number is the difference that actually happened.
        if !drop_image_artifacts(cache, stem) {
            for d in [&flat, &diff] {
                if d.is_dir() {
                    freed = freed.saturating_sub(dir_size(d));
                }
            }
        }
    }
    // Reclaim layers this image was the last to reference (the sweep fails closed, so a shared layer is
    // never dropped while another image's manifest still names it). The sweep still takes every
    // orphan it finds; only the ones THIS image named are charged to the number the caller prints.
    // THE STUCK LAYERS ARE NOT REPORTED HERE, deliberately. `rmi`'s sentence is about the image the
    // caller named; debris the sweep could not reclaim belongs to the cache's health, which is what
    // `gc` and `image_prune` report and what the paragraph above already says about the arithmetic.
    // It is ignored by NAME rather than by a `_`, so the next reader sees a decision and not an
    // oversight.
    let swept = sweep_orphan_layers_charged(cache, Some(&mine));
    Some(freed + swept.freed)
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
            //
            // `h1` FIRST: a sidecar written before hardlinks were counted once holds a total that is
            // wrong for every image with hardlinks (busybox: 100x), so one without the marker is
            // recomputed instead of believed.
            let mut it = body.split_whitespace();
            if let (Some("h1"), Some(s), Some(sl), Some(b)) =
                (it.next(), it.next(), it.next(), it.next())
            {
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
        let _ = std::fs::write(&side, format!("h1 {stamp} {slen} {bytes}\n"));
    }
    bytes
}

/// The bytes of the regular files under `dir`, A FILE ONCE HOWEVER MANY NAMES IT HAS.
///
/// A hardlink is one file: busybox is one 1 MB binary under ~400 names, and adding each name's
/// length made `kern images` say 394.6M for an image `du` measures at 4.4M (and `rmi` report
/// "freed 830.0M" for two of them). Counted per `(dev, inode)` now, which is the image's real size
/// and the one other tools print for it. Symlinks are not followed, and the walk is iterative.
pub(crate) fn dir_size(dir: &std::path::Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let mut total = 0;
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            // The dirent carries the type, so a directory costs no `stat`; only files do.
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                stack.push(e.path());
            } else if ft.is_file() {
                let Ok(md) = e.metadata() else { continue };
                if md.nlink() > 1 && !seen.insert((md.dev(), md.ino())) {
                    continue;
                }
                total += md.len();
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
    if flat.is_dir() && !built_here(&cache, &safe) {
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
    // metacopy - the only correct reader. The chain is TOP first; a single-layer image can't have a
    // cross-layer opaque, so it's copied directly (below); a ≥2-layer chain goes through the merged view.
    // The layer COUNT picks that branch. The old split could only OVER-count (a `:` in a path looked
    // like a boundary), so it sent a one-layer image through the merged view rather than the reverse:
    // that was an availability failure, never a leak.
    let (chain, config) = resolve_image(image)?;
    let tmp = cache.join(format!(".push-squash-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| Error::Oci(format!("squash dir: {e}")))?;
    if chain.len() >= 2 {
        // ≥2 stacked layers → cross-layer opaque is possible → read the kernel-merged view.
        merged_view_extract(&chain, crate::commands::Extract::Whole, &tmp).inspect_err(|_| {
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
/// and re-pulled if the base was pruned, so layered images are prune-safe.
///
/// The layers come back as a LIST, TOP first (overlayfs's shadowing order), one path per entry. It
/// used to be one `:`-joined string, and every reader cut it back apart at every `:` - including the
/// `:` in a cache path such as `colon:cache`, which turned one real directory into two that did not
/// exist. A list is joined exactly once, escaped, by [`kern_isolation::overlay_lowerdir`] at the mount.
pub(crate) fn resolve_image(image: &str) -> Result<(Vec<String>, kern_oci::ImageConfig), Error> {
    resolve_image_depth(image, 0, PullPolicy::Missing)
}

pub(crate) fn resolve_image_depth(
    image: &str,
    depth: u32,
    policy: PullPolicy,
) -> Result<(Vec<String>, kern_oci::ImageConfig), Error> {
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
            vec![empty.to_string_lossy().into_owned()],
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
        // `<base ref>`, or `<base ref> <os>/<arch>` for an image built for another platform: its base
        // is that platform's, whatever platform is asking now.
        let first = lines.next().unwrap_or("").trim();
        let (base_ref, base_platform) = match first.split_once(' ') {
            Some((r, p)) => (
                r.trim(),
                Some(kern_oci::Platform::parse(p).map_err(|e| {
                    Error::Oci(format!("corrupt layer manifest for '{image}': {e}"))
                })?),
            ),
            None => (first, None),
        };
        // Base layers of a built image are used as-is; `--pull always` never force-repulls them.
        let (base_lower, _) = match base_platform {
            Some(p) => with_image_platform(Some(p), || {
                resolve_image_depth(base_ref, depth + 1, PullPolicy::Missing)
            })?,
            None => resolve_image_depth(base_ref, depth + 1, PullPolicy::Missing)?,
        };
        let lc = layer_cache_dir();
        // This image's own layers, in manifest order: oldest first.
        let mut own: Vec<String> = Vec::new();
        for k in lines.map(str::trim).filter(|k| !k.is_empty()) {
            // A layer key MUST be 32 lowercase hex (what we write). Reject anything else so a corrupt
            // or (once layered images are shippable) hostile manifest can't turn a key into a `/etc`,
            // `../…`, or `:`/`,`-bearing path that escapes `L/` or injects an overlay mount option.
            if k.len() != 32 || !k.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::Oci(format!("corrupt layer manifest for '{image}'")));
            }
            own.push(lc.join(k).to_string_lossy().into_owned());
        }
        // TOP FIRST: this image's layers newest first, then the base's, which is already top first.
        let lower: Vec<String> = own.into_iter().rev().chain(base_lower).collect();
        // Measured on the string the kernel will receive, escaping included: that is what has to fit.
        if kern_isolation::overlay_lowerdir(&lower).len() > MAX_LOWERDIR_BYTES {
            return Err(Error::Oci(format!(
                "image '{image}' has too many layers to overlay (rebuild with fewer steps)"
            )));
        }
        let config = read_image_config(&cache.join(format!("{safe}.image")));
        refuse_other_platform(image, &config)?;
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
        let mut lower = vec![diff.to_string_lossy().into_owned()];
        lower.extend(base_lower);
        return Ok((lower, config));
    }
    // A pulled image is ONE directory.
    pull_to_cache(image, policy).map(|(dir, config)| (vec![dir], config))
}

/// The platform a build is producing, when it is not this machine's: images resolved while it is set
/// are that platform's (see [`pull_to_cache`]). `None` is the host, which is every run and every
/// build that does not say `--platform`.
static IMAGE_PLATFORM: std::sync::Mutex<Option<kern_oci::Platform>> = std::sync::Mutex::new(None);

/// The platform images resolve for now, `None` for this machine's.
pub(crate) fn image_platform() -> Option<kern_oci::Platform> {
    IMAGE_PLATFORM.lock().ok().and_then(|g| g.clone())
}

/// Run `f` with images resolving for `p` (the host's own platform counts as none), and put back
/// whatever was set before, so a base resolved for its own platform cannot change the caller's.
pub(crate) fn with_image_platform<T>(p: Option<kern_oci::Platform>, f: impl FnOnce() -> T) -> T {
    let p = p.filter(|p| !p.is_host());
    let before = IMAGE_PLATFORM
        .lock()
        .map(|mut g| std::mem::replace(&mut *g, p))
        .unwrap_or(None);
    let out = f();
    if let Ok(mut g) = IMAGE_PLATFORM.lock() {
        *g = before;
    }
    out
}

/// The cache entry `image` resolves to for the platform images resolve for now
/// ([`image_platform`]): its plain entry for this machine; for another platform that platform's own
/// entry, except a FLAT image built here for it, which lives under its plain name and says which
/// architecture it is. ONE rule for the pull, `inspect` and `image history`, so the three cannot
/// answer about different entries.
pub(crate) fn cache_entry_for(cache: &std::path::Path, image: &str) -> String {
    let plain = sanitize_ref(image);
    let Some(p) = image_platform() else {
        return plain;
    };
    let stem = platform_stem(&plain, &p);
    let built_for_it = !cache_entry_complete(cache, &stem)
        && cache_entry_complete(cache, &plain)
        && read_image_config(&cache.join(format!("{plain}.image")))
            .architecture
            .as_deref()
            == Some(p.arch.as_str());
    if built_for_it {
        plain
    } else {
        stem
    }
}

/// The cache name of `safe` for another platform: its own entry, in the cache's `[A-Za-z0-9_-]`.
pub(crate) fn platform_stem(safe: &str, p: &kern_oci::Platform) -> String {
    format!("{safe}{}", platform_suffix(p))
}

/// `__<os>_<arch>`, what tells a platform's cache entry and variant tag from the plain name: ONE
/// spelling for both, so a variant and its cache entry cannot disagree on which platform they are.
pub(crate) fn platform_suffix(p: &kern_oci::Platform) -> String {
    let clean = |s: &str| -> String {
        s.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect()
    };
    format!("__{}_{}", clean(&p.os), clean(&p.arch))
}

/// A locally built image used while another platform is being built must be that platform's: an
/// amd64 stage under an arm64 build would give the arm64 image amd64 binaries, which runs here and
/// fails on the machine it was built for.
fn refuse_other_platform(image: &str, config: &kern_oci::ImageConfig) -> Result<(), Error> {
    let Some(p) = image_platform() else {
        return Ok(());
    };
    let have = config
        .architecture
        .clone()
        .unwrap_or_else(|| kern_oci::Platform::host().as_oci_arch().to_string());
    if have == p.arch {
        return Ok(());
    }
    // Bare (`Cli`): the same refusal for a build's FROM and a `run --platform`, and a build's hint
    // about FROM and COPY paths answered neither.
    Err(Error::Cli(format!(
        "'{image}' is a local image for {have}, not {}/{}: build it for that platform first \
         (`kern build --platform {}/{} -t {image} ...`)",
        p.os, p.arch, p.os, p.arch
    )))
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
/// Every file kern writes BESIDE an image's directory, as one list.
///
/// ONE PLACE OWNS IT, which the remover below already argued for ("every remover deletes the SAME set
/// and can't drift") and which a second reader then proved by drifting: `kern images`' orphan census
/// carried its own two-element copy and counted the rest as leftovers a reader should go looking for.
/// That cost two rounds of the same defect, `.lock` and then `.size`, each found by a count saying
/// "2 entries" over one leftover image. `.layers`, `.base`, `.flatkey` and `.diff.size` are the four
/// that would have been round three: `drop_image_artifacts` removes `.ok` and `.image` FIRST, so an
/// interrupted delete leaves exactly them.
pub(crate) const CACHE_SIDECARS: [&str; 11] = [
    // A multi-platform image's variants (`kern build --platform a,b`).
    ".platforms",
    // Extracted with the image's setuid bits (`record_setuid_kept`).
    ".setuid",
    ".layers",
    ".base",
    ".image",
    ".ok",
    ".lock",
    ".flatkey",
    ".size",
    ".diff.size",
    ".owners",
];

/// The uid map an extraction gave its files, as recorded beside a cache entry (`<stem>.owners`).
///
/// ONLY ROOT CAN DISAGREE WITH ITSELF. A non-root caller has always extracted through the box's own
/// map, so its entries are consistent whatever they say. Root extracted with the tar's raw owners
/// until the fix in `kern-oci`'s `unpack_as_root`, while its boxes use its subordinate range: an
/// entry from then is unusable for any image whose files belong to a non-root user (MEASURED in the
/// field: apt's `_apt` directory, every `apt-get install`).
pub(crate) fn owner_map_signature() -> &'static str {
    // ONCE PER PROCESS: the answer cannot change while kern runs, and as root it asks the id-map
    // helpers and reads `/etc/passwd`, `/etc/subuid` and `/etc/subgid`, two to four times per pull.
    static SIGNATURE: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
    SIGNATURE.get_or_init(|| {
        // REAL ROOT ONLY: uid 0 of a mapped namespace (how `kern save` re-runs itself) extracts and
        // reads through that map and was always consistent. MEASURED by the suite: treating it as
        // root asked for a re-fetch of a locally built image, which no registry has.
        if !kern_isolation::is_initial_root() {
            "caller"
        } else if kern_isolation::id_range_available() {
            "root-range"
        } else {
            "root-single"
        }
    })
}

/// Whose uid map a cache entry's files were written under, for [`seal_entry`].
pub(crate) enum Owners<'a> {
    /// This process wrote them (a pull, a load, a build, a commit).
    ThisProcess,
    /// They are another entry's files, shared (a tag): that entry's mark travels with them.
    CopyOf(&'a str),
}

/// Finish a cache entry: its marks first, then the `.ok` sentinel LAST, so no reader ever sees an
/// entry complete without what describes it.
///
/// ONE WRITER FOR EVERY WAY AN IMAGE ENTERS THE CACHE, pull, load, build, tag and commit. Only a pull
/// wrote the owner mark, so as root every other entry read as "unpacked by an older kern", was sent
/// to the registry to be repaired and failed there: MEASURED, `kern box --image <built>` as root
/// answered "cannot access 'library/<tag>' on registry-1.docker.io". The pull itself wrote its
/// sentinel BEFORE its marks; here the order is one, for all of them.
pub(crate) fn seal_entry(
    cache: &std::path::Path,
    safe: &str,
    reference: &str,
    owners: Owners,
    setuid_kept: bool,
) -> std::io::Result<()> {
    match owners {
        Owners::ThisProcess => record_owner_map(cache, safe),
        // A source without a mark gives a tag without one, which reads exactly as the source does.
        Owners::CopyOf(src) => match std::fs::read(cache.join(format!("{src}.owners"))) {
            Ok(mark) => std::fs::write(cache.join(format!("{safe}.owners")), mark)?,
            Err(_) => {
                let _ = std::fs::remove_file(cache.join(format!("{safe}.owners")));
            }
        },
    }
    if setuid_kept {
        record_setuid_kept(cache, safe);
    }
    std::fs::write(cache.join(format!("{safe}.ok")), reference.as_bytes())
}

/// Record the uid map this extraction used, beside the entry's sentinel.
fn record_owner_map(cache: &std::path::Path, safe: &str) {
    let _ = std::fs::write(
        cache.join(format!("{safe}.owners")),
        owner_map_signature().as_bytes(),
    );
}

/// Mark a cache entry as extracted with the image's setuid/setgid bits (see `kern_oci::SetuidBits`).
/// An entry without the mark was extracted by a kern that cleared them: its `sudo` cannot raise.
pub(crate) fn record_setuid_kept(cache: &std::path::Path, safe: &str) {
    let _ = std::fs::write(cache.join(format!("{safe}.setuid")), SETUID_MARK);
}

/// What [`record_setuid_kept`] writes. `v2`: an entry marked by the first binaries that kept the bits
/// could still have lost them afterwards, because `kern save` and `kern push` then cleared every
/// setuid bit IN the cache entry of a pulled image (MEASURED: `/usr/bin/su` of python:3.12-slim). The
/// export no longer touches the tree, so only this mark vouches for the bits. `v3`: the image's file
/// capabilities are kept too (`kern_oci` extracts `security.capability`), which a `v2` entry lost.
const SETUID_MARK: &[u8] = b"kept v3\n";

/// What marks an entry whose re-extraction failed (a loaded image no registry has): asked once.
const SETUID_GIVEN_UP: &[u8] = b"not repairable v3\n";

/// The `v2` marks: an entry that has its setuid bits (and may lack only file capabilities). Read as
/// "setuid kept" by [`stripped_setuid`], so a hardened image whose `su` is `0755` ON PURPOSE is not
/// re-pulled for it. MEASURED when `v3` landed without this: the sandbox image (`su` 0755 by design)
/// was downloaded again, 34 s, on its first start, and came back 0755.
const SETUID_MARK_V2: &[u8] = b"kept v2\n";
const SETUID_GIVEN_UP_V2: &[u8] = b"not repairable v2\n";

/// Whether an entry was extracted with the image's setuid/setgid bits ([`record_setuid_kept`]).
fn setuid_kept(cache: &std::path::Path, safe: &str) -> bool {
    std::fs::read(cache.join(format!("{safe}.setuid"))).is_ok_and(|m| m == SETUID_MARK)
}

/// Programs an image ships setuid when it ships them at all. One of them present WITHOUT the bit, in
/// an entry with no [`record_setuid_kept`] mark, is an entry an older kern stripped.
const USUALLY_SETUID: [&str; 6] = [
    "usr/bin/sudo",
    "usr/bin/su",
    "bin/su",
    "usr/bin/passwd",
    "usr/bin/newgrp",
    "bin/mount",
];

/// Programs an image gives a privilege when it ships them: setuid or a file capability, depending on
/// the distribution (Alpine's are `cap_setuid=ep`/`cap_setgid=ep`, Debian's setuid). One present with
/// NEITHER, in an entry without the current mark, is an entry an older kern stripped of its caps.
const USUALLY_PRIVILEGED: [&str; 2] = ["usr/bin/newuidmap", "usr/bin/newgidmap"];

/// What an older kern stripped from a cached image: setuid bits or file capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stripped {
    Setuid(&'static str),
    Capability(&'static str),
}

impl Stripped {
    fn path(self) -> &'static str {
        match self {
            Self::Setuid(p) | Self::Capability(p) => p,
        }
    }

    fn what(self) -> &'static str {
        match self {
            Self::Setuid(_) => "setuid bits",
            Self::Capability(_) => "file capabilities",
        }
    }
}

/// Does the file at `path` carry a `security.capability` attribute (not following a symlink)?
fn has_file_capability(path: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(p) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: a NUL-terminated path and a zero-length query (the size only).
    unsafe {
        libc::lgetxattr(
            p.as_ptr(),
            c"security.capability".as_ptr(),
            std::ptr::null_mut(),
            0,
        ) > 0
    }
}

/// What an older kern stripped from a cached image ([`Stripped`]), or `None`. Asked only of an entry
/// without the current mark, so a current one costs a single read.
fn stripped_privileges(cache: &std::path::Path, safe: &str) -> Option<Stripped> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(r) = stripped_setuid(cache, safe) {
        return Some(Stripped::Setuid(r));
    }
    if built_here(cache, safe) {
        return None;
    }
    let mark = std::fs::read(cache.join(format!("{safe}.setuid"))).unwrap_or_default();
    if mark == SETUID_MARK || mark == SETUID_GIVEN_UP {
        return None;
    }
    let dir = cache.join(safe);
    USUALLY_PRIVILEGED
        .iter()
        .copied()
        .find(|rel| {
            let p = dir.join(rel);
            std::fs::symlink_metadata(&p).is_ok_and(|m| {
                m.is_file() && m.permissions().mode() & 0o6000 == 0 && !has_file_capability(&p)
            })
        })
        .map(Stripped::Capability)
}

/// A program in a cached image that an older kern left without its setuid bit, or `None`. Asked only
/// of an entry without the current mark, so a current one costs a single read.
fn stripped_setuid(cache: &std::path::Path, safe: &str) -> Option<&'static str> {
    use std::os::unix::fs::PermissionsExt;
    // A BUILT IMAGE IS NOT ON ANY REGISTRY: its bits are whatever its own build wrote, and the
    // re-extraction this answer triggers is a pull that can only fail, or fetch a stranger's image of
    // the same name.
    if built_here(cache, safe) {
        return None;
    }
    let mark = std::fs::read(cache.join(format!("{safe}.setuid"))).unwrap_or_default();
    if [
        SETUID_MARK,
        SETUID_GIVEN_UP,
        SETUID_MARK_V2,
        SETUID_GIVEN_UP_V2,
    ]
    .contains(&mark.as_slice())
    {
        return None;
    }
    let dir = cache.join(safe);
    USUALLY_SETUID.iter().copied().find(|rel| {
        std::fs::symlink_metadata(dir.join(rel))
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o4000 == 0)
    })
}

/// Was this entry built on this machine (`kern build`, `commit`): layers of its own over a base,
/// recorded by `<ref>.layers` or the older `<ref>.base`. Such an entry is on no registry, so nothing
/// that repairs a cache entry by asking a registry may touch it.
fn built_here(cache: &std::path::Path, safe: &str) -> bool {
    cache.join(format!("{safe}.layers")).exists() || cache.join(format!("{safe}.base")).exists()
}

/// Does a cache entry's ownership match the map this caller's boxes use? Always for a non-root
/// caller; for root, only an entry extracted under the same map and recorded so.
pub(crate) fn owners_match(cache: &std::path::Path, safe: &str) -> bool {
    owners_match_for(owner_map_signature(), cache, safe)
}

/// [`owners_match`] with the caller's signature as a parameter, so root's answer is testable.
fn owners_match_for(want: &str, cache: &std::path::Path, safe: &str) -> bool {
    want == "caller"
        || std::fs::read_to_string(cache.join(format!("{safe}.owners")))
            .is_ok_and(|got| got.trim() == want)
}
/// Image `safe` (a [`sanitize_ref`] stem) is in the cache whole, pulled or built.
///
/// A BUILT IMAGE HAS NO `<ref>/` DIRECTORY. `cache_entry_complete` describes a PULLED image, whose
/// rootfs is that directory; a layered build is a `.layers` manifest over `L/` (and a legacy one a
/// `.diff`), so it always read as absent. MEASURED with kern 0.30.0: `kern inspect` of a built
/// image answered "nothing named ... `kern pull` fetches one" while `kern images` listed it on the
/// line above. Present here means what `kern images` already means: the sentinel and the config
/// sidecar exist and no layer it references is missing.
pub(crate) fn image_present(cache: &std::path::Path, safe: &str) -> bool {
    let built = cache.join(format!("{safe}.layers")).exists()
        || cache.join(format!("{safe}.diff")).is_dir();
    if built {
        cache.join(format!("{safe}.ok")).exists()
            && cache.join(format!("{safe}.image")).exists()
            && !image_stat(cache, safe).1
    } else {
        cache_entry_complete(cache, safe)
    }
}

pub(crate) fn cache_entry_complete(cache: &std::path::Path, safe: &str) -> bool {
    if !cache.join(format!("{safe}.ok")).exists() || !cache.join(format!("{safe}.image")).exists() {
        return false;
    }
    if !owners_match(cache, safe) {
        return false;
    }
    // The sidecar's FORMAT is deliberately NOT part of this: an old stamp means the config must be
    // re-read (`refresh_image_config`), never that the rootfs must be re-extracted. Answering "not
    // complete" here sends the entry to the repair path, which clears the image dir - EPERM on any
    // image whose layers hold subuid-owned files. See `IMAGE_CFG_FMT`.
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
    // ANOTHER PLATFORM IS ANOTHER IMAGE: its own cache entry and its own download, so an arm64
    // `alpine` fetched for a `--platform linux/arm64` build never replaces the amd64 one a box runs.
    let platform = image_platform();
    let safe = cache_entry_for(&cache, image);
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
    // ⛔ AN ENTRY AN OLDER KERN LEFT WITHOUT ITS SETUID BITS IS RE-EXTRACTED, ONCE, as docker's
    // image would have them: its `sudo` cannot work otherwise, and nothing in the entry can give the
    // bits back (the layers are gone). Said before it happens, because it is a download. Under
    // `--pull never` there is no registry to ask, so the entry is used as it is and the line says how
    // to repair it.
    if policy != PullPolicy::Always && cache_entry_complete(&cache, &safe) {
        if let Some(gone) = stripped_privileges(&cache, &safe) {
            let (rel, what) = (gone.path(), gone.what());
            if policy == PullPolicy::Never {
                eprintln!(
                    "kern: note: image '{image}' was cached by an older kern, which cleared {what} \
                     (/{rel} has none), so a program in it that raises a user or a capability \
                     cannot; `--pull never` leaves it so, and one start without it re-extracts the \
                     image"
                );
            } else {
                kern_common::progress!(
                    "→ re-extracting image '{image}': it was cached by an older kern, which cleared \
                     {what} (/{rel} has none)"
                );
                // BEST EFFORT: a loaded image may exist on no registry. Then the entry is used as it
                // is, and marked so that later starts do not ask the network again.
                match pull_to_cache(image, PullPolicy::Always) {
                    Ok(done) => return Ok(done),
                    Err(e) => {
                        eprintln!(
                            "kern: note: image '{image}' could not be re-extracted ({e}); it runs as \
                             cached, without its {what}, until it is pulled again"
                        );
                        let _ =
                            std::fs::write(cache.join(format!("{safe}.setuid")), SETUID_GIVEN_UP);
                    }
                }
            }
        }
    }
    if policy != PullPolicy::Always && cache_entry_complete(&cache, &safe) {
        // fast path: already cached (and not a forced `--pull always` re-fetch)
        // `--pull never` means NO registry, and the refresh is a registry read: an entry kept by an
        // older kern stays as it is under that flag, which is what the flag asks for.
        if policy != PullPolicy::Never
            && !built_here(&cache, &safe)
            && !image_config_is_current(&cfgfile)
        {
            refresh_image_config(image, &cache, &safe, &cfgfile);
        }
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
        // THE SAME IMAGE IS NOT DOWNLOADED AGAIN, as docker does not: the manifest is read, and when
        // the config digest it names is the one this cache holds, the entry is current. See
        // `kern_oci::remote_config_digest` for the measurement. An entry recorded before the digest
        // was kept, or a registry that cannot answer, takes the full re-pull below, as before.
        if cache_entry_complete(&cache, &safe) {
            let mut held = read_image_config(&cfgfile);
            if let (Some(local), Ok(remote)) = (
                held.digest.clone(),
                kern_oci::remote_digests_for(image, platform.as_ref()),
            ) {
                // An entry an older kern extracted without setuid bits is NOT up to date, whatever
                // its digest: re-extracting is the only way to get them back (see `SetuidBits`).
                if local == remote.config && setuid_kept(&cache, &safe) {
                    // The same image, and the manifest just read names its repository digest:
                    // recorded when it is new (an entry from before it was kept, or a tag whose
                    // index moved while this platform's image stayed the same).
                    if remote.repo.is_some() && remote.repo != held.repo_digest {
                        held.repo_digest = remote.repo;
                        replace_image_config(&cache, &safe, &cfgfile, &held);
                    }
                    kern_common::progress!("✓ image '{image}' is up to date (--pull always)");
                    return Ok((dir.to_string_lossy().into_owned(), held));
                }
            }
        }
        // `--pull always`: fetch into a scratch dir, then swap it in with an atomic `rename`. A box
        // already using `dir` as its overlay lower is UNDISTURBED: overlayfs pinned that dentry at
        // mount time, so renaming the path out from under it is invisible to the live box. The retired
        // dir is left for `kern gc` (a live box still holds its inodes on demand; deleting it now would
        // yank files overlayfs opens lazily). Fail-safe: on any error `dir` is left untouched/restored.
        let pid = std::process::id();
        let staging = cache.join(format!("{safe}.pull-{pid}"));
        let _ = force_remove_dir_all(&staging);
        std::fs::create_dir_all(&staging).map_err(|e| Error::Oci(format!("cache dir: {e}")))?;
        kern_common::progress!("→ re-pulling image '{image}' (--pull always)");
        let config = match kern_oci::pull(
            image,
            &staging,
            platform.as_ref(),
            kern_oci::SetuidBits::Keep,
        ) {
            Ok(c) => c,
            Err(e) => {
                let _ = force_remove_dir_all(&staging);
                return Err(Error::Oci(e.to_string()));
            }
        };
        if dir.exists() {
            let retired = cache.join(format!("{safe}.old-{pid}"));
            let _ = force_remove_dir_all(&retired);
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
        let _ = seal_entry(&cache, &safe, image, Owners::ThisProcess, true);
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
        // A FIRST PULL IS PROGRESS; A REPAIR IS A DIAGNOSTIC, and the two do not share a channel.
        // "not cached" happens for every image nobody has pulled yet, so it is gated on a terminal
        // like the rest of the pull's narration. The other two say the cache entry is DAMAGED and
        // that kern is re-fetching to repair it, which is not an expected state and is the thing
        // `pentest/pentest-cache-edge.sh` asserts kern says: gating them on a terminal made a
        // corrupted entry re-fetch in silence under an SDK, which is exactly where nobody is
        // watching a terminal. Caught by that suite, not by a later pass.
        if !sentinel.exists() {
            kern_common::progress!("→ image '{image}' not cached - pulling once (reused after)");
        } else if !owners_match(&cache, &safe) {
            eprintln!(
                "kern: note: image '{image}' was unpacked by an older kern whose file owners do not \
                 match the uid map a box gets when kern runs as root - re-fetching it once"
            );
        } else if !rootfs_usable {
            eprintln!(
                "kern: note: image '{image}' is cached without a usable rootfs - re-fetching it once"
            );
        } else {
            eprintln!(
                "kern: note: image '{image}' is cached without its config - re-fetching it once"
            );
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
        // THE LAYERS AN INTERRUPTED PULL COMPLETED ARE KEPT, as docker keeps them: moved aside if
        // they match their digest, put back after the clear below, and not downloaded again. See
        // `kern_oci::salvage_layer_blobs`. Only downloaded blobs: no extracted content survives.
        let keep = cache.join(format!("{safe}.keep-{}", std::process::id()));
        let (reused, reused_bytes) = kern_oci::salvage_layer_blobs(&dir, &keep);
        // Clear any partial extraction (and any prefetch blobs left by an interrupted run). Not
        // discarded: extracting on top of content this run did not produce is how a partial layer set
        // becomes an image that looks whole.
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // AN IMAGE'S OWN LAYERS ARE OWNED BY SUBORDINATE UIDS, so the user that pulled it cannot
            // remove its directory: postgres, mysql, redis and nginx all land here. That made a
            // repair leave the entry unusable until `--pull always`, which is worse than the damage
            // it was repairing. The range that created those files can delete them; it is the same
            // helper `kern gc` already uses for a `--uid-range` box's leftovers.
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                let _ = crate::commands::remove_tree_mapped(&dir);
                if dir.exists() {
                    return Err(Error::Oci(format!(
                        "cannot clear the image dir {}, as this user or as root over your \
                         subordinate uid range: {e}",
                        dir.display()
                    )));
                }
            }
            Err(e) => {
                return Err(Error::Oci(format!(
                    "cannot clear the partial image dir {}: {e}",
                    dir.display()
                )))
            }
        }
        std::fs::create_dir_all(&dir).map_err(|e| Error::Oci(format!("cache dir: {e}")))?;
        if reused > 0 {
            restore_kept_blobs(&keep, &dir);
            eprintln!(
                "kern: note: image '{image}': reusing {reused} layer(s), {} MB, that an interrupted \
                 pull had completed",
                reused_bytes / 1_000_000
            );
        }
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
        let config = match kern_oci::pull(
            image,
            &dir,
            platform.as_ref(),
            kern_oci::SetuidBits::Keep,
        ) {
            Ok(c) => c,
            Err(e) => {
                // A FAILED PULL KEEPS THE LAYERS IT COMPLETED for the next attempt, and says so,
                // because they are bytes on disk under no image name: `kern gc --images` reclaims them.
                let (kept, kept_bytes) = kern_oci::salvage_layer_blobs(&dir, &keep);
                let _ = std::fs::remove_dir_all(&dir);
                if kept > 0 && std::fs::create_dir_all(&dir).is_ok() {
                    restore_kept_blobs(&keep, &dir);
                    eprintln!(
                        "kern: note: image '{image}': kept {kept} downloaded layer(s), {} MB, for the \
                         next attempt (`kern gc --images` removes them)",
                        kept_bytes / 1_000_000
                    );
                }
                let _ = std::fs::remove_dir_all(&keep);
                return Err(Error::Oci(e.to_string()));
            }
        };
        write_image_config(&cfgfile, &config)
            .map_err(|e| Error::Oci(format!("image config for '{image}': {e}")))?;
        let _ = seal_entry(&cache, &safe, image, Owners::ThisProcess, true);
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
    crate::kern_xdg_root("XDG_CACHE_HOME", ".cache").map_or_else(
        || {
            let uid = unsafe { libc::getuid() };
            PathBuf::from(format!("/tmp/kern-cache-{uid}/images"))
        },
        |r| r.join("images"),
    )
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
    // `kern build --no-cache`: nothing is reused, as docker's builder reuses nothing.
    if crate::commands::buildmounts::no_cache() {
        return false;
    }
    // BOTH, and the directory is not redundant. The sentinel says "a layer with this key was
    // completed"; the directory IS the layer. They can disagree - anything that removes the
    // directory without removing the marker leaves the marker standing over nothing. The build then
    // treated it as a hit, pushed a path that is not there onto the overlay chain, and died with
    // `mount(overlay) failed: No such file or directory` - an errno that names neither the cache nor
    // the missing layer, several steps away from the cause. Measured: a half-completed cache wipe
    // cost an hour of debugging aimed at the wrong subsystem. Checking both turns that into an
    // ordinary cache MISS: the layer is rebuilt and nobody notices.
    //
    // ⛔ AND THE CASE THIS TEST CANNOT SEE IS A PARTIALLY EMPTIED DIRECTORY, which is why the fix
    // for it is not here. This comment used to name the right cause and the wrong consequence: it
    // said a partial `rm -rf` stopped by a subuid-owned file "leaves the marker standing over
    // nothing". It does not. Such a removal unlinks everything it CAN and leaves exactly what it
    // cannot, so the directory is still a directory, `is_dir()` is still true, the sentinel is still
    // there, and the hit is false. MEASURED from outside against v0.32.0 on a layer from
    // `RUN useradd -m -u 10001 app`: `home/app` and `sys/` survived, `etc/passwd` did not,
    // `compose build` printed `built`, and the box failed for a reason that named `/etc/passwd`.
    //
    // No cheap test distinguishes a partial layer from a whole one - that is a walk of the tree on
    // every cache hit, on the hottest path a build has - so the invariant is imposed where the
    // damage is done instead: `sweep_orphan_layers_charged` removes the sentinel BEFORE it touches
    // the directory, so every removal kern performs, complete or not, interrupted or not, leaves a
    // directory with no sentinel. That is a miss, and a miss is always safe; a false hit never is.
    // What remains outside that guarantee is someone else's `rm -rf` inside kern's own 0700 cache,
    // which is not a state this function can be asked to detect.
    lc.join(format!("{key}.ok")).exists() && lc.join(key).is_dir()
}

/// Commit a freshly-built layer's content dir into the layer cache under `key` (atomic rename +
/// completion sentinel). A concurrent build that produced the same key first simply wins the race.
pub(crate) fn commit_layer(
    content: &std::path::Path,
    lc: &std::path::Path,
    key: &str,
) -> Result<(), Error> {
    let dest = lc.join(key);
    // `--no-cache` REPLACES WHAT THE KEY HELD: the step ran again because it was asked to (an
    // `apt-get update` for today's packages), so its new result is the layer, and the cache holds
    // it afterwards, as docker's does. Kept otherwise, the rebuilt content was thrown away and the
    // image got yesterday's. The old directory is renamed to an unreferenced random key, which a box
    // already using it keeps (the mount holds it) and `kern gc` reclaims.
    if dest.exists() && crate::commands::buildmounts::no_cache() {
        if let Some(aside) = random_layer_key() {
            let _ = std::fs::rename(&dest, lc.join(aside));
        }
    }
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

/// A fresh 32-hex name in the layer store's own shape, from the kernel's random source.
fn random_layer_key() -> Option<String> {
    use std::io::Read;
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .ok()?;
    Some(b.iter().map(|x| format!("{x:02x}")).collect())
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

/// Put the blobs [`kern_oci::salvage_layer_blobs`] moved aside back into `dir`, and remove the
/// holding directory. Best effort: a blob that cannot be moved back is downloaded again.
fn restore_kept_blobs(keep: &std::path::Path, dir: &std::path::Path) {
    if let Ok(rd) = std::fs::read_dir(keep) {
        for e in rd.flatten() {
            let _ = std::fs::rename(e.path(), dir.join(e.file_name()));
        }
    }
    let _ = std::fs::remove_dir_all(keep);
}

/// `rel` with every symlink the MERGED image holds along it resolved, as the image itself would see the
/// path: a relative link from its own directory, an absolute one from the image's root, `..` never
/// above that root. The topmost layer holding a name decides it (build layers never delete). Bounded at
/// 40 links, the kernel's own limit; past it the path is returned as far as it got. `chain` is
/// BOTTOM first, the reverse of the TOP-first lists [`resolve_image`] returns.
///
/// ⛔ WHY: `COPY x /bin/x` on `ubuntu:24.04`, where `/bin -> usr/bin`, created a real `/bin` directory
/// in the new layer that hid the image's `/bin` symlink, and with it `/bin/sh`: every later `RUN` died
/// with "cannot start '/bin/sh' in box". MEASURED in the field on speaches' Dockerfile
/// (`COPY --from=ghcr.io/astral-sh/uv:0.10 /uv /bin/uv`), then reproduced in two lines on this host,
/// where docker built the same file and left `/bin -> usr/bin` with `/usr/bin/x` beside `sh`.
pub(crate) fn chain_resolve(chain: &[String], rel: &str) -> String {
    let mut pending: std::collections::VecDeque<String> = rel
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .map(str::to_string)
        .collect();
    let mut out: Vec<String> = Vec::new();
    let mut links = 0u32;
    while let Some(part) = pending.pop_front() {
        if part == ".." {
            out.pop();
            continue;
        }
        let mut cand = out.clone();
        cand.push(part.clone());
        let cand_rel = cand.join("/");
        let top = chain.iter().rev().find_map(|d| {
            let path = std::path::Path::new(d).join(&cand_rel);
            std::fs::symlink_metadata(&path).ok().map(|m| (m, path))
        });
        match top {
            Some((m, path)) if m.file_type().is_symlink() && links < 40 => {
                links += 1;
                let Ok(target) = std::fs::read_link(&path) else {
                    out.push(part);
                    continue;
                };
                let t = target.to_string_lossy().into_owned();
                if t.starts_with('/') {
                    out.clear();
                }
                let mut next: std::collections::VecDeque<String> = t
                    .split('/')
                    .filter(|s| !s.is_empty() && *s != ".")
                    .map(str::to_string)
                    .collect();
                next.extend(pending.drain(..));
                pending = next;
            }
            _ => out.push(part),
        }
    }
    out.join("/")
}

/// The mode `rel` already has in the merged view BELOW this layer, or `None` if no layer has it as a
/// real directory.
///
/// Scans the chain top-down (`.rev()`, same order as [`chain_has_dir`]) because that is what overlay
/// does: the highest layer holding the name is the one whose mode is visible. Symlinks are skipped by
/// [`kern_oci::dir_mode`]'s no-follow open, so a layer that shipped `tmp -> /elsewhere` contributes no
/// mode instead of leaking the target's.
pub(crate) fn chain_dir_mode(chain: &[String], rel: &str) -> Option<u32> {
    if rel.is_empty() {
        return None;
    }
    chain
        .iter()
        .rev()
        .find_map(|d| kern_oci::dir_mode(&std::path::Path::new(d).join(rel)))
}

/// The repository a kept box's image is pinned under: `kern-pin/<hex of its id>`.
///
/// WHY A KEPT BOX PINS ITS IMAGE. Docker's container runs the image it was created from until it is
/// removed, whatever its tag names later; kern's cache is keyed by NAME, and a rebuild or a pull of
/// the tag replaced the entry, so the next run of a kept box mounted its layer (a DELTA of the old
/// content) on the new one. A pin is a second name for the same content, made with hard links (no
/// data is copied: measured 6 ms for `alpine:3.21`, 10 ms for `nginx:alpine` and `docker:28-dind`,
/// once per distinct content, not per box), so it outlives the tag's next content.
pub(crate) const PIN_REPO: &str = "kern-pin/";

/// The pin reference of the image whose id is `image_id` (`sha256:<hex>` or the bare hex).
pub(crate) fn pin_ref(image_id: &str) -> String {
    format!(
        "{PIN_REPO}{}",
        image_id.strip_prefix("sha256:").unwrap_or(image_id)
    )
}

/// Whether a reference, as an image listing shows it, is a pin: kern's own, never a user's image.
pub(crate) fn is_pin_ref(reference: &str) -> bool {
    reference.starts_with(PIN_REPO)
}

/// The id a pin stands for, from its NAME (`kern-pin/<hex>[:tag]` gives `sha256:<hex>`), `None`
/// for any other reference. NOT the pin's own content: a built image's pin has its base line
/// rewritten to the base's pin, so its bytes, and an id hashed from them, differ from the image it
/// keeps. MEASURED before: a kept box replayed from such a pin recorded that other id, and the pin
/// its record should have released stayed in the cache after `kern rm`.
pub(crate) fn pin_id_of(reference: &str) -> Option<String> {
    let r = kern_oci::normalize_ref(reference);
    let hex = r.strip_prefix(PIN_REPO)?;
    let hex = hex.split(':').next().unwrap_or(hex);
    (!hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| format!("sha256:{hex}"))
}

/// The id (`sha256:<hex>`) of the cached image `image` as a kept box records it, without making the
/// pin: one `stat` and a hash of its config, for the box's start path. A pin's id is the one in its
/// name. `None` when the image is not in the cache.
pub(crate) fn kept_image_id(image: &str) -> Option<String> {
    if let Some(id) = pin_id_of(image) {
        return Some(id);
    }
    let cache = cache_dir();
    let stem = cache_entry_for(&cache, image);
    image_present(&cache, &stem).then(|| kern_compat::image_id_for_entry(&cache, &stem, image))
}

/// Make the pin of `image` (whose id is `id`) in a process of its own, so a box does not wait for
/// it. MEASURED on the start path: the first kept box of `nginx:alpine` took 13 to 24 ms more than
/// the next one (2127 entries linked), every container kern's Docker API makes being a kept one.
/// The pin is made only if the tag still names `id` when that process runs (`pin_image_if`), so a
/// rebuild in between cannot pin other content; until it exists, a run with the tag unchanged mounts
/// the tag, which IS that content.
///
/// ⛔ A DOUBLE FORK, AND NO THREAD AND NO EXEC. A thread to reap a spawned child made this process
/// multi-threaded, and the box's `unshare(CLONE_NEWUSER)` then failed with EINVAL: MEASURED, every
/// first kept box of an image refused to start. The middle child exits at once and is reaped here
/// (well under a millisecond); the grandchild, reparented to the init, closes every descriptor it
/// inherited (a pipe a client reads to EOF must not wait for it) and makes the pin.
pub(crate) fn pin_in_background(image: &str, id: &str) {
    if id.is_empty() || pin_id_of(image).is_some() {
        return;
    }
    let cache = cache_dir();
    if image_present(&cache, &sanitize_ref(&pin_ref(id))) {
        return;
    }
    // SAFETY: `fork` in the box's launcher, which is single-threaded (the box's own `unshare` needs
    // it to be). The children run this crate's code and `_exit`; they never return into the caller.
    let middle = unsafe { libc::fork() };
    match middle {
        -1 => {}
        0 => {
            // SAFETY: as above; the middle child forks once more and leaves.
            if unsafe { libc::fork() } == 0 {
                detach_from_the_caller();
                pin_image_if(image, id);
            }
            // SAFETY: `_exit` skips the caller's atexit handlers and buffered output, which belong
            // to the launcher, not to this child.
            unsafe { libc::_exit(0) };
        }
        pid => {
            let mut status = 0;
            // SAFETY: waiting for the child this function just forked.
            unsafe { libc::waitpid(pid, &mut status, 0) };
        }
    }
}

/// The grandchild's stdio on `/dev/null` and every other inherited descriptor closed.
fn detach_from_the_caller() {
    // SAFETY: plain syscalls on descriptors this process owns; a failure leaves the default.
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
        if null >= 0 {
            for fd in 0..3 {
                libc::dup2(null, fd);
            }
        }
        libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32);
        libc::setsid();
    }
}

/// Pin `image` if the tag still names `id`. Silent: no one reads its output.
pub(crate) fn pin_image_if(image: &str, id: &str) {
    if kept_image_id(image).as_deref() == Some(id) {
        let _ = pin_image(image);
    }
}

/// Pin the cached image `image` for a kept box, and return its id (`sha256:<hex>`), or `None` when
/// the image is not in the cache. BEST EFFORT on the pin itself: a pin that cannot be made (a
/// directory the owner cannot read, a full disk) leaves the id returned anyway, so the box records
/// what it was created from and a later run REFUSES a changed tag instead of mounting the layer on
/// it. A built image's BASE is pinned too and its manifest points at the base's pin, so a re-pull of
/// the base does not move it either.
pub(crate) fn pin_image(image: &str) -> Option<String> {
    pin_image_depth(&cache_dir(), image, 0)
}

fn pin_image_depth(cache: &std::path::Path, image: &str, depth: u32) -> Option<String> {
    let stem = cache_entry_for(cache, image);
    if !image_present(cache, &stem) {
        return None;
    }
    if let Some(id) = pin_id_of(image) {
        return Some(id); // already a pin: nothing to make, and the id it stands for
    }
    let id = kern_compat::image_id_for_entry(cache, &stem, image);
    let pin = pin_ref(&id);
    let pin_stem = sanitize_ref(&pin);
    if image_present(cache, &pin_stem) {
        return Some(id);
    }
    // A partial pin from an interrupted attempt has no `.ok` and is not an image: clear it first.
    drop_image_artifacts(cache, &pin_stem);
    if let Err(e) = link_entry(cache, &stem, &pin_stem, &pin, depth) {
        drop_image_artifacts(cache, &pin_stem);
        eprintln!(
            "kern: note: could not keep a copy of {image} for this box ({e}); it runs as it is, and \
             a later run refuses if the tag then names other content"
        );
    }
    Some(id)
}

/// A second cache entry `dst` (reference `dst_ref`) for the entry `src`: the same files by hard link
/// (a flat or single-diff image), or the same manifest with its base pinned (a layered build, whose
/// `L/` layers are already shared by key). The `.ok` sentinel is written LAST, so an interrupted
/// copy is not an image.
fn link_entry(
    cache: &std::path::Path,
    src: &str,
    dst: &str,
    dst_ref: &str,
    depth: u32,
) -> Result<(), Error> {
    if depth > 128 {
        return Err(Error::Oci("image base chain too deep to pin".into()));
    }
    let cp = |suffix: &str| -> Result<(), Error> {
        let from = cache.join(format!("{src}{suffix}"));
        if from.exists() {
            std::fs::copy(&from, cache.join(format!("{dst}{suffix}")))
                .map_err(|e| Error::Oci(format!("pin {suffix}: {e}")))?;
        }
        Ok(())
    };
    cp(".image")?;
    cp(".platforms")?;
    cp(".setuid")?;
    let flat = cache.join(src);
    let diff = cache.join(format!("{src}.diff"));
    let layers = cache.join(format!("{src}.layers"));
    if flat.is_dir() {
        link_tree(&flat, &cache.join(dst))?;
    } else if layers.exists() {
        let body = std::fs::read_to_string(&layers)
            .map_err(|e| Error::Oci(format!("pin: read layers: {e}")))?;
        let rebased = rebase_on_pin(cache, &body, depth)?;
        std::fs::write(cache.join(format!("{dst}.layers")), rebased)
            .map_err(|e| Error::Oci(format!("pin .layers: {e}")))?;
        cp(".base")?;
    } else if diff.is_dir() {
        link_tree(&diff, &cache.join(format!("{dst}.diff")))?;
        let base = std::fs::read_to_string(cache.join(format!("{src}.base"))).unwrap_or_default();
        let rebased = rebase_on_pin(cache, &base, depth)?;
        std::fs::write(cache.join(format!("{dst}.base")), rebased)
            .map_err(|e| Error::Oci(format!("pin .base: {e}")))?;
    } else {
        return Err(Error::Oci("the image has no rootfs form".into()));
    }
    seal_entry(cache, dst, dst_ref, Owners::CopyOf(src), false)
        .map_err(|e| Error::Oci(format!("pin marker: {e}")))
}

/// A manifest whose first line names the base (`<ref>` or `<ref> <os>/<arch>`), with that base
/// pinned and named by its pin; the rest of the text unchanged. A base that cannot be pinned keeps
/// its name.
fn rebase_on_pin(cache: &std::path::Path, body: &str, depth: u32) -> Result<String, Error> {
    let (first, rest) = body.split_once('\n').unwrap_or((body, ""));
    let first = first.trim();
    if first.is_empty() || first == "scratch" {
        return Ok(body.to_string());
    }
    let (base_ref, platform) = match first.split_once(' ') {
        Some((r, p)) => (r.trim(), Some(p.trim())),
        None => (first, None),
    };
    let parsed = match platform {
        Some(p) => Some(
            kern_oci::Platform::parse(p)
                .map_err(|e| Error::Oci(format!("pin: corrupt base platform: {e}")))?,
        ),
        None => None,
    };
    let base_id = with_image_platform(parsed, || pin_image_depth(cache, base_ref, depth + 1));
    let Some(base_id) = base_id.filter(|id| image_present(cache, &sanitize_ref(&pin_ref(id))))
    else {
        return Ok(body.to_string());
    };
    let line = match platform {
        Some(p) => format!("{} {p}", pin_ref(&base_id)),
        None => pin_ref(&base_id),
    };
    Ok(if body.contains('\n') {
        format!("{line}\n{rest}")
    } else {
        line
    })
}

/// `src` recreated at `dst` with every file a hard link to the original (no data copied), every
/// symlink re-made, every directory made with its mode once its entries are in (an image directory
/// may have no owner write bit, `dr-xr-xr-x` is ordinary). Not through a symlink: the walk reads
/// links as links.
fn link_tree(src: &std::path::Path, dst: &std::path::Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let err = |what: &str, p: &std::path::Path, e: std::io::Error| {
        Error::Oci(format!("pin: {what} {}: {e}", p.display()))
    };
    let meta = std::fs::symlink_metadata(src).map_err(|e| err("stat", src, e))?;
    std::fs::create_dir(dst).map_err(|e| err("mkdir", dst, e))?;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| err("chmod", dst, e))?;
    for entry in std::fs::read_dir(src).map_err(|e| err("read", src, e))? {
        let entry = entry.map_err(|e| err("read", src, e))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type().map_err(|e| err("stat", &from, e))?;
        if ft.is_dir() {
            link_tree(&from, &to)?;
        } else if ft.is_symlink() {
            let target = std::fs::read_link(&from).map_err(|e| err("readlink", &from, e))?;
            std::os::unix::fs::symlink(target, &to).map_err(|e| err("symlink", &to, e))?;
        } else {
            std::fs::hard_link(&from, &to).map_err(|e| err("link", &from, e))?;
        }
    }
    std::fs::set_permissions(
        dst,
        std::fs::Permissions::from_mode(meta.permissions().mode()),
    )
    .map_err(|e| err("chmod", dst, e))
}

/// Drop the pin of `image_id` when no kept box records that id and no other pin builds on it, then
/// the pins of its own base chain by the same rule. Called when a kept box is removed.
pub(crate) fn release_pin(image_id: &str) {
    if image_id.is_empty() {
        return;
    }
    let cache = cache_dir();
    let mut next = Some(pin_ref(image_id));
    let mut hops = 0u32;
    while let Some(pin) = next.take() {
        hops += 1;
        if hops > 128 {
            return;
        }
        let id = format!("sha256:{}", pin.trim_start_matches(PIN_REPO));
        let used_by_a_box = crate::keepbox::list_matching(|_| true)
            .iter()
            .any(|k| k.meta.image_id == id);
        let stem = sanitize_ref(&pin);
        if used_by_a_box || pin_is_a_base(&cache, &stem, &pin) {
            return;
        }
        // Its base, read before the entry goes: the next pin to consider.
        let base_line = std::fs::read_to_string(cache.join(format!("{stem}.layers")))
            .or_else(|_| std::fs::read_to_string(cache.join(format!("{stem}.base"))))
            .unwrap_or_default();
        drop_image_artifacts(&cache, &stem);
        next = base_line
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().next())
            .filter(|r| is_pin_ref(r))
            .map(str::to_string);
    }
}

/// Whether another pin's manifest names `pin` as its base.
fn pin_is_a_base(cache: &std::path::Path, stem: &str, pin: &str) -> bool {
    let Ok(rd) = std::fs::read_dir(cache) else {
        return false;
    };
    // `sanitize_ref` writes the `/` of `kern-pin/` as `_`: every pin's stem starts so.
    let prefix = "kern-pin_";
    rd.flatten().any(|e| {
        let name = e.file_name();
        let Some(n) = name.to_str() else {
            return false;
        };
        let Some(other) = n
            .strip_suffix(".layers")
            .or_else(|| n.strip_suffix(".base"))
        else {
            return false;
        };
        other != stem
            && other.starts_with(prefix)
            && std::fs::read_to_string(e.path())
                .ok()
                .and_then(|b| {
                    b.lines()
                        .next()
                        .map(|l| l.split_whitespace().next() == Some(pin))
                })
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

/// An overlay `chain` (base first) in the order a mount takes it: TOP layer first, base last.
///
/// A list, not the `:`-joined string this used to return: a layer path may contain a `:`, and the
/// one place a list becomes `lowerdir=` text is [`kern_isolation::overlay_lowerdir`], which escapes.
pub(crate) fn chain_top_first(chain: &[String]) -> Vec<String> {
    chain.iter().rev().cloned().collect()
}

#[cfg(test)]
mod owner_map_tests {
    use super::owners_match_for;

    /// ⛔ AN ENTRY ROOT UNPACKED BEFORE THE FIX IS NOT REUSED BY ROOT, and nobody else is affected:
    /// a non-root caller's entries were always consistent, so no record is asked of them.
    #[test]
    fn root_reuses_only_an_entry_unpacked_under_its_own_map() {
        let dir = std::env::temp_dir().join(format!("kern-owners-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        assert!(
            owners_match_for("caller", &dir, "img"),
            "a non-root caller needs no record"
        );
        assert!(
            !owners_match_for("root-range", &dir, "img"),
            "no record: unpacked before the fix"
        );
        std::fs::write(dir.join("img.owners"), b"root-single").expect("w");
        assert!(!owners_match_for("root-range", &dir, "img"), "another map");
        std::fs::write(dir.join("img.owners"), b"root-range").expect("w");
        assert!(owners_match_for("root-range", &dir, "img"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod chain_resolve_tests {
    use super::chain_resolve;

    /// A destination under a symlinked directory lands where the link points, as docker puts it:
    /// relative and absolute links, a link in a lower layer, `..` that cannot leave the root, a loop.
    #[test]
    fn a_path_is_resolved_through_the_images_symlinks() {
        let base = std::env::temp_dir().join(format!("kern-chain-resolve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let low = base.join("low");
        let high = base.join("high");
        std::fs::create_dir_all(low.join("usr/bin")).expect("dir");
        std::fs::create_dir_all(low.join("usr/lib")).expect("dir");
        std::fs::create_dir_all(&high).expect("dir");
        std::os::unix::fs::symlink("usr/bin", low.join("bin")).expect("link");
        std::os::unix::fs::symlink("/usr/lib", high.join("lib")).expect("link");
        std::os::unix::fs::symlink("loop", high.join("loop")).expect("link");
        let chain = vec![
            low.to_string_lossy().into_owned(),
            high.to_string_lossy().into_owned(),
        ];
        assert_eq!(chain_resolve(&chain, "bin/uv"), "usr/bin/uv");
        assert_eq!(chain_resolve(&chain, "/bin"), "usr/bin");
        assert_eq!(chain_resolve(&chain, "lib/x.so"), "usr/lib/x.so");
        assert_eq!(chain_resolve(&chain, "usr/local/bin/x"), "usr/local/bin/x");
        assert_eq!(
            chain_resolve(&chain, "../../etc/x"),
            "etc/x",
            "never above the root"
        );
        let looped = chain_resolve(&chain, "loop/x");
        assert!(
            looped.ends_with('x'),
            "a loop ends, it does not hang: {looped}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}

#[cfg(test)]
mod built_here_tests {
    use super::*;

    /// A built image keeps whatever bits its build wrote: it is never sent to a registry to be
    /// "repaired", which could only fail or fetch a stranger's image of the same name.
    #[test]
    fn a_built_image_is_never_re_extracted_from_a_registry() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kern-built-here-{}", std::process::id()));
        let su = dir.join("img/usr/bin/su");
        std::fs::create_dir_all(su.parent().expect("parent")).expect("dirs");
        std::fs::write(&su, b"x").expect("su");
        std::fs::set_permissions(&su, std::fs::Permissions::from_mode(0o755)).expect("mode");
        // Pulled, without its setuid bit: an older kern's entry, re-extracted.
        assert_eq!(stripped_setuid(&dir, "img"), Some("usr/bin/su"));
        // The same entry built here: left alone, in both spellings of "built".
        for marker in ["img.layers", "img.base"] {
            std::fs::write(dir.join(marker), b"x").expect("marker");
            assert_eq!(stripped_setuid(&dir, "img"), None, "{marker}");
            std::fs::remove_file(dir.join(marker)).expect("unmark");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An entry an older kern extracted without file capabilities: `newuidmap` with neither setuid nor
    /// `security.capability` is re-extracted once; setuid (Debian's) is not missing anything; the
    /// current mark asks nothing.
    #[test]
    fn an_entry_whose_newuidmap_lost_its_capability_is_re_extracted() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kern-fcap-{}", std::process::id()));
        let nu = dir.join("img/usr/bin/newuidmap");
        std::fs::create_dir_all(nu.parent().expect("parent")).expect("dirs");
        std::fs::write(&nu, b"x").expect("newuidmap");
        std::fs::set_permissions(&nu, std::fs::Permissions::from_mode(0o755)).expect("mode");
        std::fs::write(dir.join("img.setuid"), b"kept v2\n").expect("v2 mark");
        assert_eq!(
            stripped_privileges(&dir, "img"),
            Some(Stripped::Capability("usr/bin/newuidmap"))
        );
        // A v2 entry's setuid bits are its image's: a `su` without one is a hardened image, not a
        // stripped one, and is not re-pulled for it.
        let su = dir.join("img/usr/bin/su");
        std::fs::write(&su, b"x").expect("su");
        std::fs::set_permissions(&su, std::fs::Permissions::from_mode(0o755)).expect("su mode");
        std::fs::remove_file(&nu).expect("no newuidmap");
        assert_eq!(
            stripped_privileges(&dir, "img"),
            None,
            "a v2 entry's su is the image's"
        );
        std::fs::write(&nu, b"x").expect("newuidmap again");
        std::fs::set_permissions(&nu, std::fs::Permissions::from_mode(0o755)).expect("mode");
        std::fs::set_permissions(&nu, std::fs::Permissions::from_mode(0o4755)).expect("setuid");
        assert_eq!(
            stripped_privileges(&dir, "img"),
            None,
            "setuid needs no capability"
        );
        std::fs::set_permissions(&nu, std::fs::Permissions::from_mode(0o755)).expect("mode");
        record_setuid_kept(&dir, "img");
        assert_eq!(stripped_privileges(&dir, "img"), None, "the current mark");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod pin_tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// A pin stands for the id in its NAME, whatever its own bytes hash to; nothing else is a pin.
    #[test]
    fn a_pin_names_the_id_it_keeps() {
        let hex = "0b9b40070c39aa00000000000000000000000000000000000000000000000000";
        assert_eq!(
            pin_id_of(&pin_ref(&format!("sha256:{hex}"))),
            Some(format!("sha256:{hex}"))
        );
        assert_eq!(
            pin_id_of(&format!("kern-pin/{hex}:latest")),
            Some(format!("sha256:{hex}"))
        );
        assert_eq!(pin_id_of("alpine:3.21"), None);
        assert_eq!(pin_id_of("kern-pin/not-hex"), None);
        assert!(is_pin_ref(&kern_oci::normalize_ref(&pin_ref(hex))));
    }

    /// A kept box's image is pinned by hard links (the same inodes, no data copied), a built image's
    /// base with it, the pin outlives the tag's entry, no listing shows it, and it goes with the
    /// last box that uses it.
    #[test]
    fn a_pin_shares_the_bytes_survives_the_tag_and_is_released() {
        let _g = crate::env_guard();
        let home = std::env::temp_dir().join(format!("kern-pin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        struct Restore(
            Vec<(&'static str, Option<std::ffi::OsString>)>,
            std::path::PathBuf,
        );
        impl Drop for Restore {
            fn drop(&mut self) {
                for (k, v) in &self.0 {
                    match v {
                        Some(v) => crate::set_global_env(k, v),
                        None => crate::unset_global_env(k),
                    }
                }
                let _ = std::fs::remove_dir_all(&self.1);
            }
        }
        let keys = ["XDG_CACHE_HOME", "XDG_DATA_HOME"];
        let _restore = Restore(
            keys.iter().map(|k| (*k, crate::global_env(k))).collect(),
            home.clone(),
        );
        for k in keys {
            let d = home.join(k);
            assert!(std::fs::create_dir_all(d.join("kern")).is_ok());
            crate::set_global_env(k, &d);
        }
        let cache = cache_dir();
        assert!(std::fs::create_dir_all(&cache).is_ok());
        // A flat image `base:1` with a file and a read-only directory, and a build `app:1` on it.
        let base = sanitize_ref("base:1");
        let root = cache.join(&base);
        assert!(std::fs::create_dir_all(root.join("ro")).is_ok());
        assert!(std::fs::write(root.join("ro/f"), "one").is_ok());
        assert!(std::fs::set_permissions(
            root.join("ro"),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o555)
        )
        .is_ok());
        assert!(std::fs::write(cache.join(format!("{base}.image")), "{\"config\":{}}").is_ok());
        assert!(std::fs::write(cache.join(format!("{base}.ok")), "base:1").is_ok());
        let app = sanitize_ref("app:1");
        assert!(std::fs::write(cache.join(format!("{app}.layers")), "base:1\n").is_ok());
        assert!(std::fs::write(
            cache.join(format!("{app}.image")),
            "{\"config\":{\"Cmd\":[\"x\"]}}"
        )
        .is_ok());
        assert!(std::fs::write(cache.join(format!("{app}.ok")), "app:1").is_ok());

        let Some(app_id) = pin_image("app:1") else {
            panic!("a cached image is pinned");
        };
        let app_pin = sanitize_ref(&pin_ref(&app_id));
        assert!(image_present(&cache, &app_pin), "the pin is an image");
        let first =
            std::fs::read_to_string(cache.join(format!("{app_pin}.layers"))).unwrap_or_default();
        let base_ref = first.lines().next().unwrap_or_default().to_string();
        assert!(
            is_pin_ref(&base_ref),
            "the base is named by its pin: {first:?}"
        );
        let base_pin = sanitize_ref(&base_ref);
        let ino = |p: &std::path::Path| std::fs::metadata(p).map(|m| m.ino()).unwrap_or(0);
        assert_eq!(
            ino(&root.join("ro/f")),
            ino(&cache.join(&base_pin).join("ro/f")),
            "the base's file is the same inode, not a copy"
        );
        // The pins are not listed; the user's two images are.
        let (listing, _) = crate::commands::image_entries_in(&cache, crate::listing::Detail::Read);
        let names: Vec<&str> = listing.records.iter().map(|e| e.name.as_str()).collect();
        assert!(names.iter().all(|n| !is_pin_ref(n)), "{names:?}");
        assert_eq!(names.len(), 2, "{names:?}");
        // The tag's entry goes (a re-pull replaces it); the pin keeps the bytes.
        assert!(drop_image_artifacts(&cache, &base));
        assert_eq!(
            std::fs::read_to_string(cache.join(&base_pin).join("ro/f"))
                .ok()
                .as_deref(),
            Some("one")
        );
        // No kept box records the id: the pin and its base pin are released.
        release_pin(&app_id);
        assert!(
            !image_present(&cache, &app_pin),
            "the pin went with its last user"
        );
        assert!(
            !cache.join(&base_pin).exists(),
            "and the base's pin, which only it used"
        );
    }
}
