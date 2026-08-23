//! `kern config …` and `kern validate`: the profile file's CRUD and its checker.
//!
//! Split out of `commands/mod.rs`, which holds every verb's implementation and is the largest file in
//! the tree. These verbs share nothing with the box lifecycle beyond the parent module's helpers, which
//! a child module still sees, so the move costs no visibility and no call site: `mod.rs` re-exports
//! this module and `commands::config_add` resolves exactly as before.

use super::*;

/// `kern config [list|edit|setup|probe|clear]` - dispatch the config-management subcommands. Bare
/// `kern config` is `list`, which the parser resolves; listing is read-only and a missing config is
/// not an error.
pub fn config_cmd(sub: &str, force: bool, json: bool) -> Result<(), Error> {
    match sub {
        "list" if json => config_list_json(),
        "list" => config_list(),
        "edit" => config_edit(),
        "setup" => config_setup(force),
        "probe" => config_probe(),
        "clear" => config_clear(force),
        // Not `_ => config_list()`. A catch-all here made this function's idea of the verb set
        // implicit, so a verb the parser started accepting without a case here would have listed the
        // profiles and exited 0 instead of saying it does not exist. Bare `kern config` reaches this
        // as "list" because the parser defaults it, not because anything unrecognised falls through.
        _ => Err(Error::Usage(CONFIG_USAGE)),
    }
}

/// `kern config add <kind:name> [--field value …] [--replace]` - the CLI twin of `kern top`'s profile
/// forms. Builds the profile through the SAME `config` schema (validation + surgical, atomic write),
/// so a profile made from the CLI is byte-for-byte what the TUI would write, and vice-versa.
pub fn config_add(args: &[String]) -> Result<(), Error> {
    let token = args.first().ok_or(Error::Usage(CONFIG_ADD_USAGE))?;
    let (kind, name) = parse_profile_token(token, CONFIG_ADD_USAGE)?;
    let allowed = crate::config::profile_fields(&kind);
    // `--update` (alias `--replace`): edit an existing profile IN PLACE, keeping every field you don't
    // pass - the field-surgical merge does that; the only keys touched are the flags given here.
    // Without it, a duplicate name is refused.
    let update = args.iter().any(|a| a == "--update" || a == "--replace");
    let mut pairs: Vec<(String, String)> = Vec::new();
    // Override a repeated flag in place (last wins), else append.
    let mut set_pair = |k: &str, v: String| match pairs.iter_mut().find(|(pk, _)| pk == k) {
        Some(slot) => slot.1 = v,
        None => pairs.push((k.to_string(), v)),
    };

    // Map `--field value` flags onto the pairs; `--persistent` is a bare bool. An unknown flag is
    // rejected (not silently dropped) so a typo can't quietly produce an empty profile.
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        if a == "--update" || a == "--replace" {
            i += 1;
            continue;
        }
        let raw = a.strip_prefix("--").ok_or_else(|| {
            Error::Config(format!(
                "unexpected argument '{a}' (flags look like --cpus 4)"
            ))
        })?;
        // Accept both `--flag value` and `--flag=value` (GNU/Docker style).
        let (field, inline) = match raw.split_once('=') {
            Some((f, v)) => (f, Some(v)),
            None => (raw, None),
        };
        // Profile field names match the CLI flags 1:1 (`--cpus` = the core quota, `--cpuset` = the
        // pin list), so no remapping is needed - a `config add vcpu:x --cpus 2` sets the same field a
        // `kern box --cpus 2` user expects. The one alias: accept Docker's long `--cpuset-cpus`
        // spelling for the `cpuset` field, matching `kern box --cpuset-cpus`.
        let field = if kind == "vcpu" && field == "cpuset-cpus" {
            "cpuset"
        } else {
            field
        };
        if allowed.iter().all(|f| *f != field) {
            return Err(Error::Config(format!(
                "{kind} has no --{field}; valid flags: {}",
                allowed
                    .iter()
                    .map(|f| format!("--{f}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            )));
        }
        // `--persistent` is a bare boolean switch (Docker-style, like `-d`) - it never consumes the
        // next token; `--persistent=false` explicitly turns it off.
        if field == "persistent" {
            set_pair("persistent", inline.unwrap_or("true").to_string());
            i += 1;
            continue;
        }
        // `--flag=value` carries its value inline; `--flag value` takes the next token.
        let value = match inline {
            Some(v) => {
                i += 1;
                v.to_string()
            }
            None => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| Error::Config(format!("--{field} needs a value")))?
                    .clone();
                i += 2;
                v
            }
        };
        set_pair(field, value);
    }

    // `backend` is mandatory on every profile (it names the host resource being sliced) and each kind
    // has exactly one sentinel meaning "the whole host". Making a person type the only value they
    // could type turned creating a profile into an error message. The writer picks the sentinel and
    // writes it EXPLICITLY into the block, so the file still carries no ambiguous default, a
    // hand-edited block with no backend still fails loudly, and the choice is printed rather than
    // silent. Never on `--update`: injecting it there would rewrite a `backend = "cpu:0"` the caller
    // never mentioned.
    let mut defaulted: Option<&str> = None;
    if !update && !pairs.iter().any(|(k, _)| k == "backend") {
        let sentinel = if kind == "vdisk" {
            crate::config::BACKEND_RAM
        } else {
            crate::config::BACKEND_HOST
        };
        pairs.push(("backend".to_string(), sentinel.to_string()));
        defaulted = Some(sentinel);
    }

    let refs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let body = crate::config::profile_block(&name, &refs).map_err(Error::Config)?;
    // The flags passed here are the fields this command controls; the merge keeps every other key in
    // the block. Update edits in place (orig = the name, skipping the collision guard); a plain add
    // refuses to clobber an existing profile.
    let managed: Vec<&str> = refs.iter().map(|(k, _)| *k).collect();
    let orig = update.then_some(name.as_str());
    crate::config::save_named_block(&kind, orig, &name, &managed, &body).map_err(Error::Config)?;
    let p = crate::ui::Palette::detect();
    println!(
        "{g}{}{z} {kind}:{name}   {d}attach with `{kind}:{name}`{z}",
        if update { "updated" } else { "added" },
        g = p.g,
        z = p.z,
        d = p.d
    );
    if let Some(sentinel) = defaulted {
        // Name what the sentinel actually means for THIS kind - `ram` is a RAM-backed tmpfs, not
        // "the whole host", and a vdisk sized past RAM is exactly where that distinction bites.
        let meaning = match kind.as_str() {
            "vdisk" => "a RAM-backed tmpfs, ephemeral",
            "vgpio" => "the host's own device nodes",
            _ => "the whole host CPU",
        };
        println!(
            "{d}backend = \"{sentinel}\" ({meaning}) - pass --backend to slice a declared resource instead{z}",
            d = p.d,
            z = p.z
        );
    }
    Ok(())
}

/// `kern config rm <kind:name>` - delete a resource profile (the CLI twin of the TUI's `d`elete).
pub fn config_rm(args: &[String]) -> Result<(), Error> {
    let token = args.first().ok_or(Error::Usage(CONFIG_RM_USAGE))?;
    let (kind, name) = parse_profile_token(token, CONFIG_RM_USAGE)?;
    crate::config::delete_named_block(&kind, &name).map_err(Error::Config)?;
    let p = crate::ui::Palette::detect();
    println!("{d}removed{z} {kind}:{name}", d = p.d, z = p.z);
    Ok(())
}

/// The default `kern.toml` path, or an error if `$HOME`/`$XDG_CONFIG_HOME` is unset.
fn config_path() -> Result<PathBuf, Error> {
    crate::config::active_path()
        .ok_or_else(|| Error::Config("no config path (set $HOME or $XDG_CONFIG_HOME)".into()))
}

fn config_setup(force: bool) -> Result<(), Error> {
    let path = config_path()?;
    if path.exists() && !force {
        return Err(Error::Config(format!(
            "{} already exists - pass --force to overwrite",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::Config(format!("config dir: {e}")))?;
    }
    // `--force` overwrites a config a person may have hand-written over months. Keep the previous
    // file next to it and SAY where it went: a destructive verb that leaves no way back is how the
    // one irreplaceable file in this tool gets lost, and `--force` is typed far more casually than
    // its consequence deserves. Best-effort by design - a failed copy must not block the write, so
    // the outcome is reported rather than assumed.
    let existed = path.exists();
    let mut saved: Option<std::path::PathBuf> = None;
    if existed {
        let bak = path.with_extension("toml.bak");
        if std::fs::copy(&path, &bak).is_ok() {
            saved = Some(bak);
        }
    }
    let toml = tailored_kern_toml(&detect_host());
    std::fs::write(&path, &toml)
        .map_err(|e| Error::Config(format!("writing {}: {e}", path.display())))?;
    println!(
        "wrote a starter config to {} (tailored to this host - `kern config edit` to tweak)",
        path.display()
    );
    match saved {
        Some(bak) => println!("the previous config is at {}", bak.display()),
        None if existed => println!("note: the previous config could not be backed up"),
        None => {}
    }
    Ok(())
}

/// `kern config edit` - open `kern.toml` in `$EDITOR` (seeding a starter file first if none exists).
fn config_edit() -> Result<(), Error> {
    let path = config_path()?;
    if !path.exists() {
        config_setup(false)?;
    }
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "vi".into());
    let status = std::process::Command::new(&editor)
        .arg(&path)
        .status()
        .map_err(|e| Error::Config(format!("launching {editor}: {e}")))?;
    if !status.success() {
        return Err(Error::Config(format!("{editor} exited non-zero")));
    }
    // Validate what the user just edited, so a typo is caught now rather than at the next run.
    match crate::config::parse(&std::fs::read_to_string(&path).unwrap_or_default()) {
        Ok(_) => println!("saved {} (valid)", path.display()),
        Err(e) => eprintln!("kern: warning: {} has an error: {e}", path.display()),
    }
    Ok(())
}

/// `kern config clear [--yes]` - remove the `kern.toml` (destructive → needs `--yes`).
fn config_clear(yes: bool) -> Result<(), Error> {
    let path = config_path()?;
    if !path.exists() {
        println!("no kern.toml to clear");
        return Ok(());
    }
    if !yes {
        return Err(Error::Config(format!(
            "would remove {} - pass --yes to confirm",
            path.display()
        )));
    }
    std::fs::remove_file(&path)
        .map_err(|e| Error::Config(format!("removing {}: {e}", path.display())))?;
    println!("removed {}", path.display());
    Ok(())
}

/// `kern config probe` - read-only inventory of host resources you can *declare* in a profile: CPUs,
/// RAM, and any GPIO/I2C/SPI/disk devices present. Doesn't touch the config; it just tells you what's
/// available to reference.
fn config_probe() -> Result<(), Error> {
    let p = crate::ui::Palette::detect();
    let row = |k: &str, v: &str| println!("{d}{k:<14}{z} {v}", d = p.d, z = p.z);
    let h = detect_host();
    // Clamp long inventories (a server can expose 20+ i2c buses) so one row can't dominate the panel;
    // the full set is a `ls /dev` away and rarely all relevant.
    let list = |v: &[String]| match v.len() {
        0 => "-".to_string(),
        n if n <= 8 => v.join(", "),
        n => format!("{}, … (+{} more)", v[..8].join(", "), n - 8),
    };
    println!("{b}host resources{z}", b = p.b, z = p.z);
    row(
        "cpus",
        &format!("{} (cpuset range 0-{})", h.ncpu, h.ncpu.saturating_sub(1)),
    );
    row("memory", &h.ram);
    // Disks get their own formatter (name/size/type/model), joined and clamped like the bus lists.
    let disks = match h.disks.len() {
        0 => "-".to_string(),
        n if n <= 4 => h
            .disks
            .iter()
            .map(disk_label)
            .collect::<Vec<_>>()
            .join("  ·  "),
        n => format!(
            "{}  ·  … (+{} more)",
            h.disks[..4]
                .iter()
                .map(disk_label)
                .collect::<Vec<_>>()
                .join("  ·  "),
            n - 4
        ),
    };
    row("disks", &disks);
    row("gpiochips", &list(&h.gpiochips));
    row("i2c buses", &list(&h.i2c));
    row("spi devices", &list(&h.spi));
    println!(
        "{d}`kern config setup` writes a kern.toml tailored to these - or `kern examples`{z}",
        d = p.d,
        z = p.z
    );
    Ok(())
}

/// `kern config list --json`: every declared profile, with the SAME attachability verdict the human
/// listing prints.
///
/// `attachable` is the field that matters. The human listing gained "cannot attach: <why>" because
/// `kern validate` and `kern config list` disagreed about one file: the listing showed a profile as
/// healthy while validate refused it. Emitting the profiles here without the verdict would recreate
/// that split for scripts, which are the readers least able to notice it.
pub fn config_list_json() -> Result<(), Error> {
    let Some(path) = crate::config::active_path().filter(|p| p.exists()) else {
        // No config is not an error and not a sentence: an empty profile list with a null path is
        // the same shape a caller handles when a config exists but declares nothing.
        println!("{{\"path\":null,\"profiles\":[]}}");
        return Ok(());
    };
    let cfg = crate::config::load(None).map_err(Error::Config)?;
    let mut items: Vec<String> = Vec::new();
    let mut push = |section: &str, name: &str| {
        let bad = crate::config::validate_profile_refs(&cfg, section, name).err();
        items.push(format!(
            "{{\"kind\":{},\"name\":{},\"attachable\":{},\"reason\":{}}}",
            json_str(section),
            json_str(name),
            bad.is_none(),
            bad.as_ref()
                .map_or_else(|| "null".to_string(), |w| json_str(w)),
        ));
    };
    for e in &cfg.vcpu {
        push("vcpu", &e.name);
    }
    for e in &cfg.vgpio {
        push("vgpio", &e.name);
    }
    for e in &cfg.vdisk {
        push("vdisk", &e.name);
    }
    println!(
        "{{\"path\":{},\"profiles\":[{}]}}",
        json_str(&path.to_string_lossy()),
        items.join(",")
    );
    Ok(())
}

pub fn config_list() -> Result<(), Error> {
    let p = crate::ui::Palette::detect();
    let Some(path) = crate::config::active_path().filter(|p| p.exists()) else {
        println!(
            "{d}no kern.toml - run `kern examples` to see the format{z}",
            d = p.d,
            z = p.z
        );
        return Ok(());
    };
    let cfg = crate::config::load(None).map_err(Error::Config)?;
    println!("{d}{}{z}", path.display(), d = p.d, z = p.z);
    // A listed profile that cannot be attached is the trap this guards: `kern validate` reports it
    // (naming file, profile and fix) while the listing used to show it as healthy, so two read verbs
    // over the same file gave two verdicts because one of them never asked. Same rule, one call.
    let mut unattachable = 0usize;
    let mut line = |section: &str, name: &str, detail: String| {
        let bad = crate::config::validate_profile_refs(&cfg, section, name).err();
        if bad.is_some() {
            unattachable += 1;
        }
        println!(
            "  {b}{c}{section}:{name}{z}  {d}{detail}{z}{}",
            match &bad {
                Some(why) => format!("  {r}cannot attach: {why}{z}", r = p.r, z = p.z),
                None => String::new(),
            },
            b = p.b,
            c = p.c,
            d = p.d,
            z = p.z
        );
    };
    for e in &cfg.vcpu {
        let mut parts = Vec::new();
        if let Some(q) = e.cpus {
            parts.push(format!("{q} cores"));
        }
        if let Some(c) = &e.cpuset {
            parts.push(format!("pin {c}"));
        }
        if let Some(m) = &e.memory {
            parts.push(m.clone());
        }
        line("vcpu", &e.name, parts.join(", "));
    }
    for e in &cfg.vgpio {
        // DECLARED devices, not just pins: a profile carrying `i2c = ["/dev/i2c-5"]` reported
        // "0 pin(s)", identical to one that grants nothing, in the one command that answers
        // "what do my profiles hand out?".
        let (devs, lines) = e.declared_grants();
        line(
            "vgpio",
            &e.name,
            format!(
                "backend {}, {devs} device(s), {lines} line(s)",
                if e.backend.is_empty() {
                    "(unset)"
                } else {
                    &e.backend
                }
            ),
        );
    }
    for e in &cfg.vdisk {
        line(
            "vdisk",
            &e.name,
            e.size.as_deref().unwrap_or("-").to_string(),
        );
    }
    if cfg.vcpu.is_empty() && cfg.vgpio.is_empty() && cfg.vdisk.is_empty() {
        println!("{d}(no vcpu/vgpio/vdisk profiles){z}", d = p.d, z = p.z);
    } else if unattachable > 0 {
        println!(
            "{d}{unattachable} profile(s) cannot attach - run `kern validate` for the full report{z}",
            d = p.d,
            z = p.z
        );
    }
    Ok(())
}

pub fn validate(path: Option<&str>) -> Result<(), Error> {
    let target = match path {
        Some(p) => std::path::PathBuf::from(p),
        None => crate::config::active_path().ok_or_else(|| {
            Error::Config("no config path in effect (set $HOME or KERN_CONFIG)".to_string())
        })?,
    };
    let text = std::fs::read_to_string(&target)
        .map_err(|e| Error::Config(format!("{}: {e}", target.display())))?;
    // Strip a UTF-8 BOM (editors on Windows add it): it's a legal file marker, not content, and would
    // otherwise make the first line fail the strict check below.
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    // `validate` must be STRICTER than `load`: the config parser deliberately SKIPS lines it can't
    // model (forward-compat with foreign TOML), so a garbage file would otherwise pass as "valid, 0
    // profiles". A validator's whole job is to catch broken syntax, so here we reject any non-blank,
    // non-comment line that is neither a `[section]` header nor a `key = value` - the same thing a real
    // TOML parser (and `kern compose`) would flag. (Deep help/command audit.)
    let mut in_array = false; // inside a multi-line `key = [ … ]` value (its continuation lines are ok)
    for (i, raw) in text.lines().enumerate() {
        let line = kern_common::toml_lite::strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        // Track a multi-line array by net bracket balance across lines: a `key = [` with more `[` than
        // `]` opens it; a line that closes the balance ends it. While open, continuation lines (values,
        // inline tables `{…}`, a closing `]`) are legitimate and not checked as top-level statements.
        // Count only brackets OUTSIDE quotes, so a `name = "has ] bracket"` value doesn't spuriously
        // open/close an array (which would make the validator silently skip the following lines).
        let (opens, closes) = brackets_outside_quotes(line);
        if in_array {
            if closes >= opens && line.contains(']') {
                in_array = false;
            }
            continue;
        }
        let is_section = line.starts_with('[') && line.ends_with(']') && !line.contains('=');
        // A `key = value` line must have a NON-EMPTY key before the first `=`. `= orphan` (empty key)
        // is not valid TOML - the bare `contains('=')` check let it slip through.
        let is_kv = line
            .split_once('=')
            .is_some_and(|(k, _)| !k.trim().is_empty());
        if is_kv && opens > closes {
            in_array = true; // `key = [` (array not closed on this line)
            continue;
        }
        if !is_section && !is_kv {
            return Err(Error::Config(format!(
                "{}: line {}: not valid TOML - expected `[section]` or `key = value`, got `{}`",
                target.display(),
                i + 1,
                line.chars().take(40).collect::<String>()
            )));
        }
    }
    let cfg = crate::config::parse(text)
        .map_err(|e| Error::Config(format!("{}: {e}", target.display())))?;
    // Every virtual profile's `backend` is MANDATORY and must resolve (a declared physical id, or the
    // reserved `host`/`ram`). Enforce it for ALL profiles here so `kern validate` rejects a
    // missing/dangling backend that `parse` alone (syntax only) would pass as "valid".
    for e in &cfg.vcpu {
        crate::config::validate_profile_refs(&cfg, "vcpu", &e.name).map_err(|m| {
            Error::Config(format!("{}: [[vcpu]] '{}': {m}", target.display(), e.name))
        })?;
    }
    for e in &cfg.vgpio {
        crate::config::validate_profile_refs(&cfg, "vgpio", &e.name).map_err(|m| {
            Error::Config(format!("{}: [[vgpio]] '{}': {m}", target.display(), e.name))
        })?;
    }
    for e in &cfg.vdisk {
        crate::config::validate_profile_refs(&cfg, "vdisk", &e.name).map_err(|m| {
            Error::Config(format!("{}: [[vdisk]] '{}': {m}", target.display(), e.name))
        })?;
    }
    let p = crate::ui::Palette::detect();
    println!(
        "{g}valid{z} {} {d}-{z} {} vcpu, {} vgpio, {} vdisk profile(s)",
        target.display(),
        cfg.vcpu.len(),
        cfg.vgpio.len(),
        cfg.vdisk.len(),
        g = p.g,
        d = p.d,
        z = p.z
    );
    // Warn about a `[[vcpu]]` that carries NO limit at all (none of cpus/cpuset/numa/nice/memory): it
    // parses fine but has zero effect - attaching it is a silent no-op, exactly the "looks configured,
    // does nothing" trap. The file is still valid (parses), so this is a warning, not error.
    for e in &cfg.vcpu {
        let has_effect = e.cpus.is_some()
            || e.cpuset.is_some()
            || e.numa.is_some()
            || e.nice != 0
            || e.memory.is_some();
        if !has_effect {
            eprintln!(
                "{y}warning{z}: vcpu profile '{}' sets no limit (cpus/cpuset/numa/nice/memory) - attaching it does nothing",
                e.name,
                y = p.y,
                z = p.z
            );
        }
    }
    Ok(())
}
