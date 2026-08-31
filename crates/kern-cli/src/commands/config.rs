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
    // ── THE PHYSICAL BLOCK IS MATERIALISED, not replaced by a sentinel ─────────────────────────
    //
    // THIS USED TO WRITE `backend = "host"`, and kern emitted TWO CONVENTIONS from one tool:
    // `config setup` writes the physical blocks and points at them by id, `config add` wrote the
    // sentinel. Two files generated by kern read differently, and whoever opened one had no way to
    // tell which of the two shapes was the intended one.
    //
    // THE SENTINEL STAYS LEGAL, and that is not an oversight: it says something an id cannot. `ram`
    // on a `[[vdisk]]` is a tmpfs, which is not a poorer `[[disk]]` but a different backend. What
    // changed is that kern no longer PICKS it on behalf of someone who said nothing: whoever wants
    // it writes it.
    //
    // THE BLOCK WRITTEN IS MINIMAL, the id alone: see `save_physical_block` for why inventing a
    // capacity would be worse than leaving it undeclared.
    let mut materialised: Option<(&str, String)> = None;
    if !update && !pairs.iter().any(|(k, _)| k == "backend") {
        let (phys, id) = crate::config::physical_for(&kind);
        // ONLY IF ABSENT. Rewriting an existing block would erase the fields the operator put in
        // it, and what this command was asked to add is a PROFILE.
        if !crate::config::physical_block_exists(phys, &id).map_err(Error::Config)? {
            crate::config::save_physical_block(phys, &id).map_err(Error::Config)?;
            materialised = Some((phys, id.clone()));
        }
        pairs.push(("backend".to_string(), id));
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
    if let Some((phys, id)) = &materialised {
        println!(
            "{d}wrote [[{phys}]] {id} - the physical resource this profile slices; \
             `kern config edit` to describe it{z}",
            d = p.d,
            z = p.z
        );
    }
    Ok(())
}

/// One size field found on a physical block: where it is, and what it says.
///
/// A NAMED STRUCT AND NOT A FOUR-TUPLE. The tuple was `(&str, String, &str, String)`, whose two
/// halves are `&'static str` and whose other two were owned copies of strings the config already
/// holds - allocated per field, read once, dropped. Borrowing removes both copies, and at four
/// elements a tuple's positions stop being readable at the call site anyway.
struct PhysicalSize<'a> {
    /// The block's section name as it is spelled in the file, without brackets: `cpu`, `disk`.
    section: &'static str,
    /// The block's own id.
    block: &'a str,
    /// The field on it: `memory`, `size`, `bandwidth`.
    field: &'static str,
    /// What the file says, trimmed and known non-empty.
    raw: &'a str,
}

/// Every size field declared on a PHYSICAL block, with where it sits.
///
/// A TABLE AND NOT A PER-FAMILY CHECK, because the defect was that nobody looked at them: an
/// enumerated list can be read and what is missing from it can be seen, three scattered `if`s
/// cannot. Empty is excluded here: "field absent" and "field written wrong" are two things, and the
/// first one is legitimate.
fn physical_size_fields<'a>(cfg: &'a crate::config::KernConfig) -> Vec<PhysicalSize<'a>> {
    let mut out = Vec::new();
    // The lifetime is named because the closure's two borrowed parameters and the `Vec` it pushes
    // into must all be tied to `cfg`; inference cannot relate a closure's arguments to the
    // function's return on its own.
    let mut push =
        |section: &'static str, block: &'a str, field: &'static str, v: Option<&'a str>| {
            if let Some(raw) = v.map(str::trim).filter(|s| !s.is_empty()) {
                out.push(PhysicalSize {
                    section,
                    block,
                    field,
                    raw,
                });
            }
        };
    for e in &cfg.cpu {
        push("cpu", &e.id, "memory", e.memory.as_deref());
    }
    for e in &cfg.disk {
        push("disk", &e.name, "size", e.size.as_deref());
        push("disk", &e.name, "bandwidth", e.bandwidth.as_deref());
    }
    out
}

/// A binary size out of an optional field, discarding the empty one.
fn opt_size(v: Option<&str>) -> Option<u64> {
    v.map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(kern_common::parse_binary_size)
}

/// One slice asking for more than the resource it names DECLARES.
pub(crate) struct OverBudget {
    pub(crate) family: &'static str,
    pub(crate) profile: String,
    pub(crate) field: &'static str,
    /// WHO DECLARED THE CEILING, as a phrase that completes `... is more than the N ___ declares`.
    ///
    /// It held the backend id and the template said "its backend '{}' declares", which is true for
    /// every row whose ceiling comes from the block the backend names, and FALSE for the one whose
    /// ceiling comes from somewhere else: a `backend = "ram"` volume is bounded by the host's RAM,
    /// and `ram` declares nothing. Printing "its backend 'ram' declares 31G" would have been a
    /// sentence this file can prove wrong. The attribution travels with the row instead.
    pub(crate) declared_by: String,
    pub(crate) asked: String,
    pub(crate) declared: String,
    pub(crate) consequence: &'static str,
}

/// Every slice that overruns the budget declared by the resource it names.
///
/// ## Why it exists in this shape
///
/// The check existed for ONE pair, `[[vgpu]] vram` against `[[gpu]] vram`, and it was correct. The
/// defect was that it was one pair: enumerate the families and there are SEVEN of the same shape,
/// and six went unchecked. `[[vcpu]] cpus = 99` against a `[[cpu]] cores = 8` validated in silence,
/// and so did `memory`, and a `[[vdisk]]`'s `size`, `iops` and `bandwidth` against its `[[disk]]`.
/// Adding the missing case would have left five holes and the next family would have opened a
/// sixth: the fix is a table of the pairs, not a second `if`.
///
/// ## What it is NOT
///
/// It is not a threshold. There is no "this looks too big" anywhere in it: one number from the file
/// is compared against another number FROM THE SAME FILE. Where the operator has not declared the
/// physical budget, kern does not know it and says nothing, rather than inventing a limit. This
/// project has already withdrawn two arbitrary thresholds for firing on correct values.
///
/// ## Why a warning and not a refusal
///
/// The physical declaration is advisory: it is there so a configuration can be written on a machine
/// that does not have the device. An operator whose `[[cpu]] cores` is stale relative to the machine
/// they upgraded has the file wrong, not the workload, and refusing would take a working system
/// offline over a second-hand number of kern's.
pub(crate) fn over_declared_budget(cfg: &crate::config::KernConfig) -> Vec<OverBudget> {
    let mut out = Vec::new();

    // ── vcpu against cpu ───────────────────────────────────────────────────────────────────────
    for e in &cfg.vcpu {
        let Some(backend) = e.backend.as_deref() else {
            continue;
        };
        let Some(cpu) = cfg.cpu.iter().find(|c| c.id == backend) else {
            continue;
        };
        // CORES ARE A FLOAT, not a binary size: `cpus = 0.5` is legal and it is half a core.
        // Comparing them as bytes would give zero on both sides.
        if let (Some(asked), Some(have)) = (e.cpus, cpu.cores) {
            if asked > have {
                out.push(OverBudget {
                    family: "[[vcpu]]",
                    profile: e.name.clone(),
                    field: "cpus",
                    declared_by: format!("its backend '{backend}'"),
                    asked: fmt_cores(asked),
                    declared: fmt_cores(have),
                    consequence: "the cgroup quota is capped by the cores the machine actually has, so this profile would not slow the workload down at all",
                });
            }
        }
        if let (Some(asked), Some(have)) = (
            opt_size(e.memory.as_deref()),
            opt_size(cpu.memory.as_deref()),
        ) {
            if asked > have {
                out.push(OverBudget {
                    family: "[[vcpu]]",
                    profile: e.name.clone(),
                    field: "memory",
                    declared_by: format!("its backend '{backend}'"),
                    asked: kern_common::fmt_bytes(asked),
                    declared: kern_common::fmt_bytes(have),
                    consequence: "the ceiling is bounded by the RAM the machine has, so this profile would cap nothing",
                });
            }
        }
    }

    // ── vdisk against disk ─────────────────────────────────────────────────────────────────────
    //
    // A `[[disk]]`'s backend key is its `name`, not an `id` field as in the other families. Looking
    // it up by `id` would have compiled and matched nothing, ever: a check green by absence, which
    // is how these break.
    // ── the `ram` sentinel, which is NOT a [[disk]] and was therefore checked by nothing ───────
    //
    // A `[[vdisk]]` may set `backend = "ram"`, which is a tmpfs and not a poorer disk. There is no
    // `[[disk]]` named `ram` and there cannot be: an id equal to a reserved sentinel is refused, so
    // the lookup below finds nothing, takes the `continue`, and every RAM-backed volume walked out
    // of this table unchecked. Measured before this was written: `size = "500g"` against a
    // `[[cpu]] memory = "31g"` validated clean.
    //
    // A tmpfs IS charged to the memory cgroup of the box that mounts it, and that is a measurement
    // rather than a reading of the code. On this host, one box, one variable:
    //
    //     --memory 256m, write 512 MiB into the volume -> killed, exit 137
    //     --memory 2g,   the same write                -> 536870912 bytes copied
    //
    // So the ceiling a RAM-backed volume can never pass is RAM, and the largest `[[cpu]] memory`
    // this file declares is the most generous reading of what this machine has. Compared against the
    // LARGEST and not against each: a volume is not bound to one `[[cpu]]`, so exceeding the biggest
    // is the only statement that holds however the profiles are paired at launch.
    // Borrowed, not cloned: `cfg` outlives this function's loop, so the id travels as a `&str` and
    // the whole scan allocates nothing. It was an owned `String` cloned once per vdisk, which is a
    // copy per iteration for a value that never changes.
    let declared_ram: Option<(u64, &str)> = cfg
        .cpu
        .iter()
        .filter_map(|c| opt_size(c.memory.as_deref()).map(|b| (b, c.id.as_str())))
        .max_by_key(|(b, _)| *b);
    for e in &cfg.vdisk {
        if e.backend == crate::config::BACKEND_RAM {
            if let (Some(asked), Some((have, by))) = (opt_size(e.size.as_deref()), declared_ram) {
                if asked > have {
                    out.push(OverBudget {
                        family: "[[vdisk]]",
                        profile: e.name.clone(),
                        field: "size",
                        declared_by: format!("the RAM [[cpu]] '{by}'"),
                        asked: kern_common::fmt_bytes(asked),
                        declared: kern_common::fmt_bytes(have),
                        consequence: "a RAM-backed volume is a tmpfs charged to the memory of the box that mounts it, so one larger than the RAM this file declares can never be filled",
                    });
                }
            }
            // The other two fields do not apply: a tmpfs has no device to throttle.
            continue;
        }
        let Some(disk) = cfg.disk.iter().find(|d| d.name == e.backend) else {
            continue;
        };
        if let (Some(asked), Some(have)) =
            (opt_size(e.size.as_deref()), opt_size(disk.size.as_deref()))
        {
            if asked > have {
                out.push(OverBudget {
                    family: "[[vdisk]]",
                    profile: e.name.clone(),
                    field: "size",
                    declared_by: format!("its backend '{}'", e.backend),
                    asked: kern_common::fmt_bytes(asked),
                    declared: kern_common::fmt_bytes(have),
                    consequence: "a volume cannot be larger than the disk it sits on, so the quota would never be the thing that stops a write",
                });
            }
        }
        if let (Some(asked), Some(have)) = (e.iops, disk.iops) {
            if asked > have {
                out.push(OverBudget {
                    family: "[[vdisk]]",
                    profile: e.name.clone(),
                    field: "iops",
                    declared_by: format!("its backend '{}'", e.backend),
                    asked: asked.to_string(),
                    declared: have.to_string(),
                    consequence: "the device cannot serve more than it declares, so this throttle would never engage",
                });
            }
        }
        if let (Some(asked), Some(have)) = (
            opt_size(e.bandwidth.as_deref()),
            opt_size(disk.bandwidth.as_deref()),
        ) {
            if asked > have {
                out.push(OverBudget {
                    family: "[[vdisk]]",
                    profile: e.name.clone(),
                    field: "bandwidth",
                    declared_by: format!("its backend '{}'", e.backend),
                    asked: kern_common::fmt_bytes(asked),
                    declared: kern_common::fmt_bytes(have),
                    consequence: "the device cannot move more than it declares, so this throttle would never engage",
                });
            }
        }
    }

    out
}

/// A core count as an operator would write it: `4` and not `4.0`, while `0.5` stays `0.5`.
fn fmt_cores(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{} core(s)", v as i64)
    } else {
        format!("{v} core(s)")
    }
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
    row(
        "memory",
        &h.ram_bytes
            .map(super::human_bytes)
            .unwrap_or_else(|| "?".to_string()),
    );
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

    // ── AND EVERY PROFILE IS RESOLVED, not merely checked for its references ───────────────────
    //
    // THE CONTRACT WAS BROKEN, and it showed on a three-line file:
    //
    //     kern validate file.toml   -> valid
    //     kern run --config file... -> error: bad memory '1.5g' in [[vcpu]] 'x'
    //
    // The checks above look at REFERENCES, that is, that `backend` names something that exists. The
    // parser then accepts any string in a field carrying a unit (`memory`, `size`, `bandwidth`) and
    // any number in `cpus`: it is the RESOLVER that says whether `1.5g` is a size this parser reads
    // and whether `cpus = -1` means anything. While `validate` stopped at the references, those
    // values got "valid" here and a refusal at launch.
    //
    // Whoever holds only `validate` - a CI pipeline, an editor - found out when the workload
    // started. A validator that approves what execution refuses is worse than no validator: it
    // gives a guarantee it does not have.
    for e in &cfg.vcpu {
        crate::config::resolve_vcpu(&cfg, &e.name)
            .map_err(|m| Error::Config(format!("{}: {m}", target.display())))?;
    }
    for e in &cfg.vgpio {
        crate::config::resolve_vgpio(&cfg, &e.name)
            .map_err(|m| Error::Config(format!("{}: {m}", target.display())))?;
    }
    for e in &cfg.vdisk {
        crate::config::resolve_vdisk(&cfg, &e.name)
            .map_err(|m| Error::Config(format!("{}: {m}", target.display())))?;
    }
    // ── AND THE PHYSICAL BLOCKS' OWN FIELDS, which were not validated AT ALL ───────────────────
    //
    // `[[cpu]] memory = "nonsense"` got "valid". No resolver reads that field, because the resolvers
    // resolve PROFILES and nobody looked at the block. What follows is the part that matters: the
    // budget comparison below uses `parse_binary_size`, which answers `None` on a string it does not
    // understand, and a `None` SKIPS the comparison. A budget written wrong was not an error, it was
    // a check switched off in silence.
    //
    // THE NUMERIC FIELDS GET THE SAME RULE AS A PROFILE'S, and the asymmetry was found by the edge
    // cases, not by a re-reading. On a PROFILE, `cpus = 0` and `cpus = -1` are refused by name; on
    // the same number declared on a BLOCK nobody looked, and `cores = -8` produced a warning that
    // reads as a malfunction: "asks for 1 core(s), more than -8 core(s)". A resource declaring zero
    // or less is not a resource anyone can slice: it is a field left half-written.
    //
    // `inf` and `nan` do not reach this far, the number parser stops them first. The check is made
    // anyway, because depending on where another layer stops is how these holes open.
    for e in &cfg.cpu {
        if let Some(c) = e.cores {
            if !c.is_finite() || c <= 0.0 {
                return Err(Error::Config(format!(
                    "{}: [[cpu]] '{}': cores must be a positive number of cores (got {c})",
                    target.display(),
                    e.id
                )));
            }
        }
    }
    for e in &cfg.disk {
        if e.iops == Some(0) {
            return Err(Error::Config(format!(
                "{}: [[disk]] '{}': iops is zero, which declares a disk that serves nothing - \
                 remove the field to leave it undeclared",
                target.display(),
                e.name
            )));
        }
    }

    for f in physical_size_fields(&cfg) {
        if kern_common::parse_binary_size(f.raw).is_none() {
            let (section, block, field, raw) = (f.section, f.block, f.field, f.raw);
            return Err(Error::Config(format!(
                "{}: [[{section}]] '{block}': bad {field} '{raw}' (try `2g`, `512m`; decimals like \
                 `1.5g` are not a size this parser reads)",
                target.display()
            )));
        }
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

    // A SLICE BIGGER THAN THE RESOURCE THIS SAME FILE DECLARES.
    //
    // See [`over_declared_budget`]: a warning and not a refusal, because the physical declaration is
    // advisory and an operator with a stale number has the file wrong, not the workload.
    for o in over_declared_budget(&cfg) {
        // THE FIELD LEADS AND THE VALUE CARRIES ITS OWN UNIT. A first wording read "asks for 99
        // core(s) of cpus", because the field name was appended to a value that already spelled the
        // unit out. The form below reads the same way for all seven pairs, sizes and counts alike.
        println!(
            "{y}warning{z} {} '{}': {} = {} is more than the {} {} declares - {}",
            o.family,
            o.profile,
            o.field,
            o.asked,
            o.declared,
            o.declared_by,
            o.consequence,
            y = p.y,
            z = p.z
        );
    }
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

#[cfg(test)]
mod tests {
    /// Write a case file, validate it, and hand back the outcome as a string.
    ///
    /// One helper for every case: what differs between them is the CONTENT, and writing the file out
    /// six times would bury that.
    ///
    /// A DIFFERENT FILE PER CALL, where the first draft used one. This binary's tests run in
    /// PARALLEL: two cases writing the same path trample each other, and the effect is a test that
    /// is green alone and red alongside the others, which is the worst way to fail because it looks
    /// like a defect in the product. The counter makes the name unique without leaning on the clock,
    /// which at this granularity repeats.
    fn validated(text: &str) -> Result<(), String> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("kern-cfgcase-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("the case directory");
        let f = dir.join(format!("case-{}.toml", N.fetch_add(1, Ordering::Relaxed)));
        std::fs::write(&f, text).expect("writing the case file");
        let r = super::validate(Some(f.to_str().expect("utf-8"))).map_err(|e| format!("{e:?}"));
        let _ = std::fs::remove_file(&f);
        r
    }

    /// THE PHYSICAL BLOCKS' FIELDS WERE NOT VALIDATED AT ALL.
    ///
    /// `[[cpu]] memory = "nonsense"` got "valid". What follows is what makes it serious: the budget
    /// comparison uses `parse_binary_size`, which answers `None` on a string it does not understand,
    /// and a `None` SKIPS the comparison. A budget written wrong was not an error, it was a check
    /// switched off in silence.
    #[test]
    fn a_physical_block_with_a_bad_size_is_refused_naming_the_field() {
        for (text, want) in [
            (
                "[[cpu]]\nid = \"cpu:0\"\nmemory = \"nonsense\"\n",
                "bad memory",
            ),
            ("[[cpu]]\nid = \"cpu:0\"\nmemory = \"1.5g\"\n", "bad memory"),
            (
                "[[disk]]\nid = \"d0\"\npath = \"/tmp\"\nsize = \"-5\"\n",
                "bad size",
            ),
            (
                "[[disk]]\nid = \"d0\"\npath = \"/tmp\"\nbandwidth = \"abc\"\n",
                "bad bandwidth",
            ),
        ] {
            let e = validated(text).expect_err("a budget that is not a size must be refused");
            assert!(e.contains(want), "expected {want:?}, got {e}");
        }
        // THE POSITIVE CONTROL: the same fields written well must pass, or the loop above would be
        // green against a validator that refuses everything.
        validated("[[cpu]]\nid = \"cpu:0\"\nmemory = \"16g\"\n").expect("16g is a size");
        validated("[[disk]]\nid = \"d0\"\npath = \"/tmp\"\nsize = \"100g\"\n").expect("so is 100g");
        // AND AN ABSENT OR EMPTY FIELD IS NOT AN ERROR: "undeclared" and "declared wrong" are two
        // things, and only the second one is a defect.
        validated("[[cpu]]\nid = \"cpu:0\"\n").expect("a block with no budget is legitimate");
        validated("[[cpu]]\nid = \"cpu:0\"\nmemory = \"\"\n").expect("and so is an empty field");
        validated("[[cpu]]\nid = \"cpu:0\"\nmemory = \"   \"\n").expect("whitespace included");
    }

    /// THE SAME RULE HOLDS FOR NUMBERS, and it did not.
    ///
    /// On a PROFILE, `cpus = 0` and `cpus = -1` were refused by name; on the same number declared on
    /// a BLOCK nobody looked. `cores = -8` then produced a warning that reads as a malfunction:
    /// "asks for 1 core(s), more than -8 core(s)". The edge cases found the asymmetry, not a
    /// re-reading.
    #[test]
    fn a_physical_block_with_a_nonsense_count_is_refused_like_a_profile_is() {
        for (text, want) in [
            (
                "[[cpu]]\nid = \"cpu:0\"\ncores = -8\n",
                "cores must be a positive",
            ),
            (
                "[[cpu]]\nid = \"cpu:0\"\ncores = 0\n",
                "cores must be a positive",
            ),
            (
                "[[disk]]\nid = \"d0\"\npath = \"/tmp\"\niops = 0\n",
                "iops is zero",
            ),
        ] {
            let e = validated(text).expect_err("a nonsense count must be refused");
            assert!(e.contains(want), "expected {want:?}, got {e}");
        }
        // The positive control, for the same reason as above.
        validated("[[cpu]]\nid = \"cpu:0\"\ncores = 8\n").expect("eight cores are eight cores");
        validated("[[disk]]\nid = \"d0\"\npath = \"/tmp\"\niops = 1000\n")
            .expect("and a thousand iops is a thousand iops");
    }

    /// `kern validate` MUST REFUSE WHAT THE LAUNCH REFUSES, and it did not.
    ///
    /// Measured on a three-line file: `validate` said "valid" and `kern run` on that same file
    /// answered `bad memory '1.5g' in [[vcpu]] 'x'`. The checks that existed looked at REFERENCES
    /// (that `backend` names something that exists); nobody called the resolvers, and those are what
    /// decide whether a value carrying a unit is readable and whether a number means anything.
    ///
    /// THE CASE RUNS THE REAL VERB ON A FILE ON DISK. Calling the resolvers directly would have been
    /// simpler and would have proved the wrong thing: it passes against a `validate` that never
    /// invokes them, which is the defect itself.
    #[test]
    fn validate_refuses_what_the_launch_refuses() {
        let dir = std::env::temp_dir().join(format!("kern-validate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("the case directory");
        for (name, text, want) in [
            (
                "vcpu.toml",
                "[[cpu]]\nid = \"cpu:0\"\ncores = 8\n[[vcpu]]\nname = \"x\"\nbackend = \"cpu:0\"\nmemory = \"1.5g\"\n",
                "bad memory",
            ),
            (
                "vdisk.toml",
                "[[disk]]\nid = \"d0\"\npath = \"/tmp\"\n[[vdisk]]\nname = \"x\"\nbackend = \"d0\"\nsize = \"1.5g\"\n",
                "bad size",
            ),
        ] {
            let f = dir.join(name);
            std::fs::write(&f, text).expect("writing the case file");
            let e = super::validate(Some(f.to_str().expect("a utf-8 path")))
                .expect_err("validate must refuse what the launch refuses");
            let msg = format!("{e:?}");
            assert!(msg.contains(want), "{name}: expected {want:?}, got {msg}");
        }
        // THE POSITIVE CONTROL: a good file must stay valid, or the two assertions above would pass
        // against a `validate` that refuses everything.
        let ok = dir.join("ok.toml");
        std::fs::write(
            &ok,
            "[[cpu]]\nid = \"cpu:0\"\ncores = 8\n[[vcpu]]\nname = \"x\"\nbackend = \"cpu:0\"\nmemory = \"2g\"\n",
        )
        .expect("writing the good file");
        super::validate(Some(ok.to_str().expect("a utf-8 path")))
            .expect("a valid file must stay valid");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
