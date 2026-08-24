//! Verbs that read or steer a box that is already running: `ps`, `stats`, `inspect`, `logs`,
//! `attach`, `top`, `diff`, `history`, `wait`, `rename`, `recover`, `stop`, `pause`.
//!
//! None of them start a box; they read the registry, the cgroup and the box's own files, or send it a
//! signal. Split out of `commands/mod.rs`, which keeps the start path (`box_run` and its
//! supervision) and every helper both sides call, reached here through `use super::*`.

use super::*;

pub fn ps(
    json: bool,
    quiet: bool,
    all: bool,
    filters: &[(String, String)],
    format: Option<&str>,
) -> Result<(), Error> {
    // Validate every filter once, fail-fast on an unsupported key or status value.
    for (k, v) in filters {
        match k.as_str() {
            "name" | "id" | "label" | "pod" => {}
            "status" => {
                if !matches!(
                    v.as_str(),
                    "running"
                        | "paused"
                        | "orphaned"
                        | "exited"
                        | "created"
                        | "dead"
                        | "restarting"
                ) {
                    return Err(Error::Usage(
                        "ps --filter status=: running | paused | orphaned | exited \
                         (created/dead/restarting match nothing - kern has no such state)",
                    ));
                }
            }
            _ => {
                return Err(Error::Usage(
                    "ps --filter: supported keys are name=, status=, id=, label=, pod=",
                ))
            }
        }
    }
    let boxes: Vec<registry::Instance> = registry::list()
        .into_iter()
        .filter(|b| ps_matches(b, filters))
        .collect();
    // `-a`/`--all` (or an explicit `status=exited`) also surfaces boxes that have exited but whose
    // `waitexit` breadcrumb `gc` has not yet reaped - Docker's `ps -a`. A `status=running` query never
    // wants them, and `exited_matches` (which honours the same status filter) excludes anything the
    // status asked against, so this gate is only "should we even read the exited set at all". `dead`
    // is NOT here: kern has no dead state, so `status=dead` matches nothing (like `created`).
    let want_exited = all || filters.iter().any(|(k, v)| k == "status" && v == "exited");
    // An exited box did not keep its labels (they lived in the pruned instance record; the breadcrumb
    // carries only name/pod/command). Say so rather than let `label=` silently match zero exited rows -
    // the same "no accept-and-ignore on an explicit filter" rule as `status=dead`.
    if want_exited && filters.iter().any(|(k, _)| k == "label") {
        eprintln!(
            "kern: note: --filter label= does not apply to exited boxes (labels are not retained past exit)"
        );
    }
    let exited: Vec<registry::ExitedBox> = if want_exited {
        // Exclude any pid that is ALSO a live box: between a box's `waitexit` write (its last act) and
        // its instance-record unregister there is a window where both artefacts exist; without this a
        // box could momentarily appear in BOTH sections of one `ps -a`.
        // Dedup on the FULL (pid, starttime) identity, not pid alone: a fresh live box that recycled a
        // within-window exited box's pid must not hide that exited row (different starttime).
        let live: std::collections::HashSet<(i32, u64)> =
            boxes.iter().map(|b| (b.pid, b.starttime)).collect();
        registry::list_exited()
            .into_iter()
            .filter(|e| !live.contains(&(e.pid, e.starttime)) && exited_matches(e, filters))
            .collect()
    } else {
        Vec::new()
    };
    // `-q`/`--quiet`: names only, one per line - scriptable, e.g. `kern stop $(kern ps -q)`. An exited
    // box's name is already scrubbed at the source (`list_exited`), so it is safe to print raw here.
    if quiet {
        for b in &boxes {
            println!("{}", b.name);
        }
        for e in &exited {
            println!("{}", e.name);
        }
        return Ok(());
    }
    // `--format '{{.Field}}'`: render each box through the bounded template (no Go-template logic).
    if let Some(tmpl) = format {
        let now = registry::now_unix();
        for b in &boxes {
            println!("{}", render_ps_format(tmpl, b, now)?);
        }
        for e in &exited {
            println!("{}", render_ps_format(tmpl, e, now)?);
        }
        return Ok(());
    }
    if json {
        let mut items: Vec<String> = boxes
            .iter()
            .map(|b| {
                format!(
                    "{{\"name\":{},\"pid\":{},\"pod\":{},\"rootfs\":{},\"command\":{},\"started\":{},\"ports\":{},\"health\":{}}}",
                    json_str(&b.name),
                    b.pid,
                    json_str(&b.pod),
                    json_str(&b.rootfs),
                    json_str(&b.command),
                    b.started,
                    json_str(&b.ports),
                    json_str(&registry::health_of(&b.name, b.pid)),
                )
            })
            .collect();
        // Exited rows carry the fields a dead box still has plus `exit_code`; `started`/`ports`/`rootfs`
        // are gone with the box, so they are simply absent rather than emitted as a lie.
        for e in &exited {
            items.push(format!(
                "{{\"name\":{},\"pid\":{},\"pod\":{},\"command\":{},\"exit_code\":{},\"exited_ago\":{},\"health\":{}}}",
                json_str(&e.name),
                e.pid,
                json_str(&e.pod),
                json_str(&e.command),
                e.code,
                e.exited_ago,
                json_str("exited"),
            ));
        }
        // Frame through the shared helper (the sole owner of the `[ , ]` array grammar), so a live-only
        // listing stays byte-for-byte what it was before `-a` existed and this isn't a re-rolled array.
        println!("{}", kern_common::json_array(&items, |s| s.clone()));
    } else {
        // Build rows first so the PORTS column can size to its widest value (a published mapping
        // like `127.0.0.1:8080->80` is wider than the "PORTS" header) - keeps COMMAND aligned.
        let now = registry::now_unix();
        let rows: Vec<(&registry::Instance, u64, String, String)> = boxes
            .iter()
            .map(|b| {
                let up = now.saturating_sub(b.started);
                // A frozen box (`kern pause`) is reported as "paused" here - otherwise it looks
                // identical to a running one in `ps`. `-` when no health check is configured.
                let health = box_status(b, "-");
                let ports = if b.ports.is_empty() {
                    "-".to_string()
                } else {
                    b.ports.clone()
                };
                (b, up, health, ports)
            })
            .collect();
        let pw = rows
            .iter()
            .map(|(_, _, _, p)| p.chars().count())
            .chain(std::iter::once(5)) // len("PORTS")
            .max()
            .unwrap_or(5);
        // On a TTY, truncate COMMAND to the remaining width so a long command never wraps (like
        // `docker ps`); piped/non-TTY prints it whole so scripts get the full line.
        let tty = std::io::stdout().is_terminal();
        let width = crate::ui::term_width(libc::STDOUT_FILENO);
        let p = crate::ui::Palette::detect();
        // The visible width before COMMAND is fixed (16+1+7+1+7+2+9+1+pw+1 = 45+pw), so the budget
        // is computed arithmetically - colour codes never enter the count.
        let prefix_w = 45 + pw;
        println!(
            "{d}{:<16} {:>7} {:>7}  {:<9} {:<pw$} COMMAND{z}",
            "NAME",
            "PID",
            "UPTIME",
            "HEALTH",
            "PORTS",
            d = p.d,
            z = p.z
        );
        // The ONE column skeleton every row is emitted through - live OR exited - so a width change
        // can't desync the two paths. Callers pass their own pre-coloured, pre-padded NAME and STATUS
        // cells (they differ: tree connector vs raw name, health string vs `exit <code>`) and the raw
        // COMMAND, which is UNTRUSTED argv: scrubbed of terminal-control sequences (the guard inspect/
        // --format/--json also apply - raw would let `$'\e[2J'` clear the screen on every `kern ps`,
        // and an exited box's stored command would re-fire until `gc`), then TTY-truncated so it never
        // wraps.
        let emit_row = |name_cell: &str,
                        pid: i32,
                        time_cell: &str,
                        status_cell: &str,
                        ports: &str,
                        cmd: &str| {
            let safe = crate::ui::scrub(cmd);
            let cmd = if tty {
                truncate(&safe, width.saturating_sub(prefix_w).max(8))
            } else {
                safe
            };
            println!("{name_cell} {pid:>7} {time_cell:>7}  {status_cell} {ports:<pw$} {cmd}");
        };
        // One LIVE box row. `connector` is a tree glyph ("├─ "/"└─ ") drawn INSIDE the 16-wide NAME cell
        // for a pod member, or "" for a standalone box - so every PID column still lines up.
        let print_row =
            |b: &registry::Instance, up: u64, health: &str, ports: &str, connector: &str| {
                let cw = connector.chars().count();
                // Inside a pod's tree the `<pod>-` prefix is redundant - the pod is the line above -
                // so the member shows the SERVICE name the compose file uses. The registry keeps the
                // full, project-scoped name; this is display only, and a standalone box (no pod) is
                // printed whole.
                let shown = crate::ui::display_box_name(&b.name, &b.pod);
                // dim connector, then reset, then the standard bold-cyan NAME padded to fill the cell.
                let name = format!(
                    "{d}{connector}{z}{b}{c}{:<nw$}{z}",
                    shown,
                    d = p.d,
                    z = p.z,
                    b = p.b,
                    c = p.c,
                    nw = 16usize.saturating_sub(cw),
                );
                let hc = match health {
                    "healthy" => p.g,
                    "unhealthy" => p.r,
                    _ => p.d,
                };
                let status_cell = format!("{hc}{:<9}{}", health, p.z);
                emit_row(
                    &name,
                    b.pid,
                    &format!("{up}s"),
                    &status_cell,
                    ports,
                    &b.command,
                );
            };
        // Standalone boxes (no pod) print flat, exactly like before. Pod members are grouped under a
        // header line - the `kern ps` mirror of Docker Desktop's collapsed compose-project rows.
        for (b, up, health, ports) in rows.iter().filter(|(b, ..)| b.pod.is_empty()) {
            print_row(b, *up, health, ports, "");
        }
        // Group the rest by pod, pods in name order, members in start order (rows already are).
        let mut pods: std::collections::BTreeMap<
            &str,
            Vec<&(&registry::Instance, u64, String, String)>,
        > = std::collections::BTreeMap::new();
        for row in rows.iter().filter(|(b, ..)| !b.pod.is_empty()) {
            pods.entry(row.0.pod.as_str()).or_default().push(row);
        }
        for (pod, members) in &pods {
            // Pod header: bold accent name + a dim "(N boxes)" tag. `kern stop <pod>` acts on the whole
            // group - the header is the "root" the user stops or removes.
            let n = members.len();
            let plural = if n == 1 { "box" } else { "boxes" };
            println!(
                "{b}{y}{pod}{z} {d}(pod · {n} {plural}){z}",
                b = p.b,
                y = p.y,
                d = p.d,
                z = p.z,
            );
            for (i, (b, up, health, ports)) in members.iter().enumerate() {
                let connector = if i + 1 == n { "└─ " } else { "├─ " };
                print_row(b, *up, health, ports, connector);
            }
        }
        // Exited boxes (only when `-a`/`status=exited`): a flat section under a dim header, driven off
        // the SAME `emit_row` as the live rows so they cannot desync. STATUS is `exit <code>` (green at
        // 0, red otherwise); the time cell is how long AGO it exited. The full `<pod>-<service>` name is
        // kept - there is no pod tree here to supply the context.
        if !exited.is_empty() {
            let n = exited.len();
            let plural = if n == 1 { "box" } else { "boxes" };
            println!("{d}exited{z} {d}({n} {plural}){z}", d = p.d, z = p.z);
            for e in &exited {
                let hc = if e.code == 0 { p.g } else { p.r };
                // name is already scrubbed at the source (`list_exited`), so it is safe in the cell.
                let name = format!("{b}{c}{:<16}{z}", e.name, b = p.b, c = p.c, z = p.z);
                let status_cell = format!("{hc}{:<9}{}", format!("exit {}", e.code), p.z);
                emit_row(
                    &name,
                    e.pid,
                    &fmt_uptime(e.exited_ago),
                    &status_cell,
                    "-",
                    &e.command,
                );
            }
        }
    }
    Ok(())
}

/// `kern stats [--json]` - current memory + cumulative CPU time per running box (from cgroup).
pub fn stats(json: bool, names: &[String]) -> Result<(), Error> {
    let mut boxes = registry::list();
    // `stats <name>...` filters to the named boxes; a requested name that isn't running is reported
    // (not silently dropped - that would look like a box with no stats).
    if !names.is_empty() {
        // name-or-PID (NAME wins globally - an all-digit box name is never shadowed by a coincidental pid).
        let live: Vec<String> = boxes.iter().map(|b| b.name.clone()).collect();
        let hit = |b: &registry::Instance, n: &str| -> bool {
            n == b.name || (!live.iter().any(|m| m == n) && n.parse::<i32>().ok() == Some(b.pid))
        };
        for want in names {
            if !boxes.iter().any(|b| hit(b, want)) {
                eprintln!("kern: no running box '{want}'");
            }
        }
        boxes.retain(|b| names.iter().any(|n| hit(b, n)));
    }
    if json {
        // `null` (not 0) when the box has no dedicated cgroup to read - "unknown", not "zero".
        let num = json_num;
        let out = kern_common::json_array(&boxes, |b| {
            format!(
                "{{\"name\":{},\"pid\":{},\"mem_bytes\":{},\"cpu_usec\":{}}}",
                json_str(&b.name),
                b.pid,
                num(registry::mem_bytes(b.cgroup_pid())),
                num(registry::cpu_usec(b.cgroup_pid()))
            )
        });
        println!("{out}");
    } else {
        let p = crate::ui::Palette::detect();
        println!(
            "{d}{:<16} {:>8} {:>9} {:>9}{z}",
            "NAME",
            "PID",
            "MEM",
            "CPU",
            d = p.d,
            z = p.z
        );
        for b in &boxes {
            let mem = registry::mem_bytes(b.cgroup_pid()).map_or("-".into(), human_bytes);
            let cpu = registry::cpu_usec(b.cgroup_pid())
                .map_or("-".into(), |u| format!("{:.1}s", u as f64 / 1e6));
            let name = format!("{}{}{:<16}{}", p.b, p.c, b.name, p.z);
            println!("{name} {:>8} {:>9} {:>9}", b.pid, mem, cpu);
        }
    }
    Ok(())
}

/// `kern inspect <name> [--json]` - full detail for one running box: its identity (pid, pid1,
/// rootfs, command, ports, uptime) plus live resource readings (mem/cpu/tasks) and health. A
/// superset of one `ps`+`stats` row for a single box. Untrusted fields (rootfs, command) are
/// scrubbed of terminal-escape sequences before display, exactly like the status panel and tables.
/// Errors with a `kern ps` hint if no live box has that name.
pub fn inspect(name: &str, json: bool) -> Result<(), Error> {
    let b = registry::find_ref(name)
        .ok_or_else(|| Error::NotRunning(format!("no running box named '{name}'")))?;
    let health = registry::health_of(&b.name, b.pid);
    let mem = registry::mem_bytes(b.cgroup_pid());
    let cpu = registry::cpu_usec(b.cgroup_pid());
    let tasks = registry::tasks(b.cgroup_pid());
    let up = registry::now_unix().saturating_sub(b.started);
    if json {
        // `null` (not 0) for a resource the box has no dedicated cgroup to read - "unknown".
        let num = json_num;
        println!(
            "{{\"name\":{},\"pid\":{},\"pid1\":{},\"rootfs\":{},\"command\":{},\"started\":{},\"uptime\":{},\"ports\":{},\"health\":{},\"mem_bytes\":{},\"cpu_usec\":{},\"tasks\":{},\"pod\":{},\"egress\":{},\"landlock_rw\":{},\"memory_max\":{},\"pids_max\":{}}}",
            json_str(&b.name),
            b.pid,
            b.pid1,
            json_str(&b.rootfs),
            json_str(&b.command),
            b.started,
            up,
            json_str(&b.ports),
            json_str(&health),
            num(mem),
            num(cpu),
            num(tasks),
            json_str(&b.pod),
            json_str(&b.egress),
            json_str(&b.landlock_rw),
            num(b.memory_max),
            num(b.pids_max),
        );
    } else {
        let p = crate::ui::Palette::detect();
        let row = |k: &str, v: &str| println!("{d}{k:<8}{z} {v}", d = p.d, z = p.z);
        // Bold-cyan name header, matching the panel/tables. The name is charset-validated by
        // `BoxName`; rootfs/command are untrusted, so they go through `scrub`.
        println!("{}{}{}{}", p.b, p.c, b.name, p.z);
        row("pid", &b.pid.to_string());
        if b.pid1 != 0 {
            row("pid1", &b.pid1.to_string());
        }
        row("uptime", &fmt_uptime(up));
        row("rootfs", &crate::ui::scrub(&b.rootfs));
        row("command", &crate::ui::scrub(&b.command));
        row("ports", if b.ports.is_empty() { "-" } else { &b.ports });
        row("health", if health.is_empty() { "-" } else { &health });
        row("mem", &mem.map_or("-".into(), human_bytes));
        row(
            "cpu",
            &cpu.map_or("-".into(), |u| format!("{:.1}s", u as f64 / 1e6)),
        );
        row("tasks", &tasks.map_or("-".into(), |t| t.to_string()));
        // Configured caps (the REQUESTED limits, distinct from the live usage above, which reads `-`
        // when the box has no dedicated cgroup) and the 0.6.7 isolation policies, shown when set.
        row("mem-cap", &b.memory_max.map_or("-".into(), human_bytes));
        row(
            "pids-cap",
            &b.pids_max.map_or("-".into(), |v| v.to_string()),
        );
        if !b.pod.is_empty() {
            row("pod", &b.pod);
        }
        if !b.egress.is_empty() {
            row("egress", &crate::ui::scrub(&b.egress));
        }
        if !b.landlock_rw.is_empty() {
            row("landlock", &crate::ui::scrub(&b.landlock_rw));
        }
    }
    Ok(())
}

/// `kern recover` - reconcile the runtime state: drop registry entries for boxes whose process is
/// gone (a crash/kill that skipped the supervisor's cleanup) and remove the orphaned overlay scratch
/// they left behind. Never touches a live box.
pub fn recover() -> Result<(), Error> {
    let (recovered, freed) = sweep_orphan_scratch();
    let p = crate::ui::Palette::detect();
    if recovered == 0 {
        println!(
            "{}nothing to recover - runtime state is consistent{}",
            p.d, p.z
        );
    } else {
        println!(
            "{g}recovered{z} {recovered} orphaned box scratch dir(s), freed {}",
            human_bytes(freed),
            g = p.g,
            z = p.z
        );
    }
    Ok(())
}

/// `kern rename <old> <new>` - give a running box a new name (Docker parity). The box keeps running
/// under the new name; its pid is unchanged. Refuses an invalid name or one already held by a live
/// box. Foreground/detached boxes only (an interactive `-it` box is not registered).
pub fn rename(old: &str, new: &str) -> Result<(), Error> {
    let parsed = BoxName::parse(new).map_err(Error::InvalidBox)?;
    let new = parsed.as_str();
    let Some(inst) = registry::find_ref(old) else {
        return Err(Error::NotRunning(format!("no running box named '{old}'")));
    };
    if inst.name == new {
        return Ok(()); // already named that - a no-op, not an error
    }
    if registry::find_ref(new).is_some() {
        return Err(Error::AlreadyRunning(format!(
            "a box named '{new}' is already running"
        )));
    }
    registry::rename(&inst.name, new, inst.pid)
        .map_err(|e| Error::Sandbox(format!("rename '{}' to '{new}': {e}", inst.name)))?;
    let p = crate::ui::Palette::detect();
    println!("{}renamed{} {} → {new}", p.g, p.z, inst.name);
    Ok(())
}

/// `kern wait <box>...` - block until each box exits, then print its exit code, one per line, in
/// argument order (Docker `wait`). A box that has ALREADY exited answers at once from its exit
/// record, for as long as `kern ps -a` still lists it; past that window, and for an interactive
/// `-it` box (never registered, no supervisor to record a code), there is nothing to answer with.
/// The command itself returns 0 unless a name doesn't resolve. Polls the registry every 100 ms - no
/// daemon, no busy-spin.
pub fn wait(names: &[String]) -> Result<(), Error> {
    for name in names {
        let Some(inst) = registry::find_ref(name) else {
            // Not running: answer from the exit record if the box left one, which is Docker's
            // behaviour (`docker wait` on a stopped container returns its code at once) and the one
            // `kern ps -a` already implies - it lists that box WITH its code, so refusing to say the
            // same number here was an inconsistency in our own surface, not ephemerality. Newest
            // first, so a recycled name answers about the run that just ended. Outside the `ps -a`
            // window there is nothing left to read and the error below is the honest answer.
            if let Some(exited) = registry::list_exited()
                .into_iter()
                .find(|e| e.name == *name)
            {
                println!("{}", exited.code);
                continue;
            }
            return Err(Error::NotRunning(format!(
                "no running box named '{name}' and no exit record for one (kern keeps no stopped boxes; the record is dropped by `prune`/`gc`, and an hour after the box exited)"
            )));
        };
        // Block on the EXACT (name,pid) pair leaving the registry, so a reused pid or name can't make
        // a still-live box read as gone. The supervisor (self-exit) and `stop`/`kill` both write the
        // `(pid,starttime)`-keyed exit sidecar before the box leaves `list()`, so once the pair is gone
        // the code is already recorded. The read is NON-consuming, so parallel/repeat waiters all see it.
        while registry::pair_alive(&inst.name, inst.pid) {
            unsafe { libc::usleep(100_000) }; // 100 ms poll
        }
        match registry::box_exit(inst.pid, inst.starttime) {
            Some(code) => println!("{code}"),
            None => {
                // Gone but no recorded code: a foreground/-it box (no supervisor to capture it), or a
                // crash/OOM that killed the supervisor before it could record. Name the likely cause so
                // the empty stdout reads as expected, not a bug; don't invent a 0.
                eprintln!(
                    "kern: box '{}' exited without a recorded exit code (a foreground or -it box has no supervisor to capture one)",
                    inst.name
                );
            }
        }
    }
    Ok(())
}

/// `kern diff <box>` - list filesystem changes vs the box's image (Docker `diff`). Walks the box's
/// overlay UPPER (writable) layer: `C <path>` = a path created or modified, `D <path>` = a deletion
/// (an overlayfs whiteout). Deletions (`D`) are exact; kern does not distinguish brand-new (`A`) from
/// modified (`C`) without diffing against the base image, so both surface as `C`. Likewise a directory
/// wholly replaced in the box (`rm -rf d && mkdir d`, an overlayfs *opaque* dir) shows as `C d` without
/// a per-file `D` for the wiped lower contents. Only overlay boxes have an upper: a `--bind-rootfs` box
/// writes through to its source (nothing to diff) and a `--read-only` box has an empty upper (no changes).
pub fn diff(name: &str, json: bool) -> Result<(), Error> {
    let Some(inst) = registry::find_ref(name) else {
        return Err(Error::NotRunning(format!("no running box named '{name}'")));
    };
    // `rootfs` is `<scratch>/<name>-<pid>/merged`; the writable upper is its sibling `upper`.
    let merged = std::path::Path::new(&inst.rootfs);
    let is_overlay = merged.file_name().and_then(|s| s.to_str()) == Some("merged");
    let upper = merged.parent().map(|s| s.join("upper"));
    match (is_overlay, upper) {
        (true, Some(u)) if u.is_dir() => {
            let mut out: Vec<(char, String)> = Vec::new();
            walk_diff(&u, &u, 0, &mut out);
            out.sort_by(|a, b| a.1.cmp(&b.1));
            if out.len() >= DIFF_MAX_ENTRIES {
                eprintln!("kern: diff truncated at {DIFF_MAX_ENTRIES} entries (upper too large)");
            }
            if json {
                // `json_str` and NOT `ui::scrub` here. The two do different jobs and the JSON path
                // needs the first: scrub DELETES control bytes, which silently changes a filename,
                // and a consumer that then tries to `rm` what it was told exists would miss. Escaping
                // preserves the byte and still cannot forge a line or reach a terminal, because the
                // whole value stays inside one JSON string.
                let buf = kern_common::json_array(&out, |(kind, path)| {
                    format!(
                        "{{\"change\":{},\"path\":{}}}",
                        json_str(&kind.to_string()),
                        json_str(path),
                    )
                });
                println!("{buf}");
                return Ok(());
            }
            for (kind, path) in &out {
                // The path comes from an UNTRUSTED box-controlled filename: scrub control bytes so a
                // name like `a\nD /etc/shadow` or an ANSI-escape filename can't forge a diff line or
                // inject into the operator's terminal (same guard `ps --format` applies).
                println!("{kind} {}", crate::ui::scrub(path));
            }
            Ok(())
        }
        _ => Err(Error::Sandbox(format!(
            "box '{}' has no overlay to diff - it uses --bind-rootfs, which writes straight through \
             to the source directory (nothing is layered to compare)",
            inst.name
        ))),
    }
}

/// `kern history [-n N]` - the most recent boxes, reconstructed from their captured log files
/// (`<name>-<pid>.log`): name, pid, when it last ran, and whether it's still running. A lightweight
/// audit trail without a separate history store (prune/gc remove these, so it's "recent", not "all").
pub fn history(count: usize) -> Result<(), Error> {
    let dir = registry::logs_dir().map_err(|e| Error::Sandbox(format!("logs dir: {e}")))?;
    let mut rows: Vec<(String, i32, u64, bool)> = Vec::new(); // name, pid, mtime, alive
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let fname = e.file_name();
            let fname = fname.to_string_lossy();
            let Some(stem) = fname.strip_suffix(".log") else {
                continue;
            };
            // `<name>-<pid>` - split on the LAST '-' (a name may contain '-').
            let Some((name, pid_s)) = stem.rsplit_once('-') else {
                continue;
            };
            let Ok(pid) = pid_s.parse::<i32>() else {
                continue;
            };
            let mtime = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            let alive = unsafe { libc::kill(pid, 0) } == 0;
            rows.push((name.to_string(), pid, mtime, alive));
        }
    }
    rows.sort_by_key(|b| std::cmp::Reverse(b.2)); // newest first
    rows.truncate(count);
    let p = crate::ui::Palette::detect();
    if rows.is_empty() {
        println!("{}no box history yet{}", p.d, p.z);
        return Ok(());
    }
    let now = registry::now_unix();
    println!(
        "{d}{:<20} {:>8} {:>12}  STATUS{z}",
        "NAME",
        "PID",
        "WHEN",
        d = p.d,
        z = p.z
    );
    for (name, pid, mtime, alive) in &rows {
        let status = if *alive {
            format!("{}running{}", p.g, p.z)
        } else {
            format!("{}exited{}", p.d, p.z)
        };
        println!(
            "{b}{c}{:<20}{z} {:>8} {:>12}  {status}",
            truncate(name, 20),
            pid,
            fmt_age(now.saturating_sub(*mtime)),
            b = p.b,
            c = p.c,
            z = p.z
        );
    }
    Ok(())
}

/// `kern logs <name>` - print the captured stdout/stderr of the most recent box named `name`.
pub fn logs(name: &str, tail: Option<usize>, follow: bool) -> Result<(), Error> {
    use std::io::{Read, Seek, SeekFrom, Write};
    // Accept a `kern ps` PID too: a live box's pid resolves to its name; a name (incl. a stopped box,
    // whose log file persists) is used as-is.
    let by_pid = registry::find_ref(name).map(|i| i.name);
    let name = by_pid.as_deref().unwrap_or(name);
    let Some(path) = newest_log(name)? else {
        return Err(Error::NotRunning(format!("no logs for box '{name}'")));
    };
    let mut f =
        std::fs::File::open(&path).map_err(|e| Error::Sandbox(format!("opening log: {e}")))?;
    // `--tail N` seeks a bounded window near EOF (cost O(bytes shown), not O(file size)); a plain
    // `logs` reads the whole file. Either way `f` ends positioned at EOF so `--follow` streams NEW
    // appends without re-printing. (Narrow race on `--tail N -f` of an actively-appending box: a line
    // written between the tail read and the re-seek to EOF can be skipped - acceptable for a log tail.)
    let shown: Vec<u8> = match tail {
        Some(n) => {
            let t = tail_file(&mut f, n)?;
            if follow {
                f.seek(SeekFrom::End(0))
                    .map_err(|e| Error::Sandbox(format!("seeking log: {e}")))?;
            }
            t
        }
        None => {
            let mut content = Vec::new();
            f.read_to_end(&mut content)
                .map_err(|e| Error::Sandbox(format!("reading log: {e}")))?;
            content
        }
    };
    {
        let out = std::io::stdout();
        let mut lock = out.lock();
        lock.write_all(&shown)
            .map_err(|e| Error::Sandbox(format!("writing log: {e}")))?;
        let _ = lock.flush();
    }
    if follow {
        // Only a live box appends more output; a stopped box's log is already complete.
        if let Some(bx) = registry::find_ref(name) {
            return follow_log(f, name, bx.pid);
        }
    }
    Ok(())
}

/// `kern attach <name>` - stream a running (detached) box's output live until it exits or you press
/// Ctrl-C (which **detaches** without stopping the box; a detached box has no stdin, so this is
/// output-only). Prints the log so far, then follows appends by polling the file, and stops when the
/// box leaves the registry.
pub fn attach(name: &str) -> Result<(), Error> {
    let bx = registry::find_ref(name);
    let Some(bx) = bx else {
        return Err(Error::NotRunning(format!("no running box named '{name}'")));
    };
    let Some(path) = newest_log(name)? else {
        return Err(Error::NotRunning(format!(
            "box '{name}' has no log to attach to (only detached boxes log to a file)"
        )));
    };
    eprintln!(
        "kern: attached to '{name}' (pid {}) - Ctrl-C detaches (box keeps running)",
        bx.pid
    );
    let f = std::fs::File::open(&path).map_err(|e| Error::Sandbox(format!("opening log: {e}")))?;
    // Print the log so far (from offset 0), then poll appends until the box exits (shared with `logs -f`).
    follow_log(f, name, bx.pid)?;
    eprintln!("kern: box '{name}' exited");
    Ok(())
}

/// `kern top` - live, auto-refreshing view of running boxes (name, pid, uptime, mem, cpu%).
/// Reads the registry + each box's cgroup every second; exit with Ctrl-C.
/// `kern top` - an interactive task-manager TUI (tabs, live refresh, keyboard nav) when stdout is
/// a terminal; a one-shot table when piped. The implementation lives in [`crate::tui`].
pub fn top() -> Result<(), Error> {
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() {
        crate::tui::run()
    } else {
        crate::tui::snapshot()
    }
}

pub fn stop(names: &[String], all: bool) -> Result<(), Error> {
    let dir = registry::dir().map_err(|e| Error::Sandbox(format!("registry: {e}")))?;
    let running = registry::list();
    let mut targets: Vec<_> = if all {
        running.clone()
    } else {
        boxes_matching_refs(running.clone(), names)
    };
    // A persistent (`--restart always`) box is supervised by systemd and may be momentarily down
    // between restarts - not in the registry, but its unit still exists and would resurrect it at
    // reboot. Collect those so stop reliably removes them too: for explicit names, the requested
    // ones; for `--all`, every `kern-*.service` in the user unit dir not already a live target.
    let managed_only: Vec<String> = if all {
        user_systemd_dir()
            .ok()
            .and_then(|d| std::fs::read_dir(d).ok())
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter_map(|f| {
                Some(
                    f.strip_prefix("kern-")?
                        .strip_suffix(".service")?
                        .to_string(),
                )
            })
            // The name only makes a file a CANDIDATE. Ownership is read from the file itself, or
            // `stop --all` removes units it never wrote - see `is_kern_managed_unit`.
            .filter(|n| managed_unit_path(n).is_some_and(|p| is_kern_managed_unit(&p)))
            .filter(|n| !targets.iter().any(|b| &b.name == n))
            .collect()
    } else {
        names
            .iter()
            .filter(|n| !targets.iter().any(|b| &b.name == *n))
            .filter(|n| managed_unit_path(n).is_some_and(|p| is_kern_managed_unit(&p)))
            .cloned()
            .collect()
    };
    if targets.is_empty() && managed_only.is_empty() {
        return Err(Error::NotRunning(if all {
            "no running boxes to stop".to_string()
        } else {
            let listed = names
                .iter()
                .map(|n| format!("'{n}'"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("no running box named {listed}")
        }));
    }
    // A target that could not actually be stopped (orphan cgroup not reaped, a SIGKILL that did not
    // land in time) or a named ref that matched nothing is a real failure, not a note on stderr:
    // collect the reasons and return them as ONE `Err` at the end so the command exits NON-ZERO and
    // `kern top` (which reuses this fn with stderr muted) can show the reason. Same rule and shape as
    // `pause`, kept identical so the partial-failure convention is not re-derived per command.
    let mut failures: Vec<String> = Vec::new();
    // Wait on the SHORTEST grace first. Phase 1 signals every box at once, so this reorders no
    // shutdown - what it reorders is which confirmation kern waits for first, and that is what
    // decides when each box is SIGKILLed. The loop is sequential, so a member whose turn comes after
    // a longer-lived one has already spent its own grace and is killed at once: MEASURED on a
    // four-service stack asking 1, 2, 4 and 6 s, all hanging in their handler, the 1 s service was
    // killed at 6201 ms and the 4 s one at 6201. Ascending, each waits only the difference from the
    // one before it, so every member is killed on its own grace and the stack still finishes in
    // max(grace). `sort_by_key` is stable, so boxes asking the same grace keep the caller's order.
    targets.sort_by_key(|b| b.stop_grace);
    // PHASE 1: send every box its stop signal BEFORE waiting on any of them, and share ONE deadline.
    // Stopping serially made each box burn its own full grace in turn, so an N-service stack of
    // workloads that ignore SIGTERM took N x grace (measured: 20 s for two `sh -c sleep` services).
    // Docker stops a project in parallel; so do we. The per-box wait below then sees processes that
    // have already been signalled and, for the ones that exit, returns at once.
    // When the signal went out. Each box's own grace is measured from here, so a member that asked
    // for less is not held to the longest grace in the stack - see `remaining_grace_ms`.
    let signalled_at = std::time::Instant::now();
    // Hold every target's reaper BEFORE a single signal goes out, so each box's exit status is still
    // readable when its wait returns. Kept alive to the end of the teardown loop and released by
    // `Drop`; a box with no grace has nothing to observe and holds nothing. See `ReaperHold`.
    let _holds: Vec<ReaperHold> = targets
        .iter()
        .map(|b| {
            // Only where an interrupted `stop` is RECOVERABLE. A held reaper is resumed by `Drop`,
            // which a SIGKILL of this process skips, and a box with a dedicated cgroup survives that:
            // its supervisor is gone, so `kern ps` shows it ORPHANED and the next `kern stop` reaps
            // the whole cgroup (verified: `stopped 'victim2' (was orphaned; reaped via cgroup.kill)`,
            // no stopped process and no stray left). A box with NO dedicated cgroup - `cgroup` is
            // empty exactly there - has no such handle: it would vanish from `ps` with its runner
            // stopped for good, where before this hold existed the runner simply died and the init
            // reparented and reaped itself. An exit code is not worth turning a self-healing case
            // into a leak, so those boxes keep the unguarded read.
            if b.stop_grace > 0 && !b.orphaned && !b.cgroup.is_empty() {
                ReaperHold::new(b.pid, b.pid1)
            } else {
                ReaperHold(None)
            }
        })
        .collect();
    for b in &targets {
        if b.stop_grace > 0 {
            let sig = if b.stop_signal > 0 {
                b.stop_signal
            } else {
                libc::SIGTERM
            };
            if b.pid1 > 0 {
                let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, b.pid1, 0) as i32 };
                unsafe { signal_box(fd, b.pid1, sig) };
                if fd >= 0 {
                    unsafe { libc::close(fd) };
                }
            }
            // The group carries the signal to the box's OTHER processes, not just its init: they
            // inherit the supervisor's process group, so a shell blocked in `sleep` wakes now
            // instead of when its child happens to finish. MEASURED: dropping this turned a 3 ms
            // stop into 65 ms for exactly that shape of workload. The box's own runner is in that
            // group too and would die here - which is why `stop` holds it first, see `ReaperHold`.
            if b.pid > 1 {
                unsafe { libc::kill(-b.pid, sig) };
            }
        }
    }

    for b in &targets {
        // ORPHANED box: its supervisor is already dead (that is what makes it orphaned), so the
        // pid-based kill below has nothing to signal - the box's PID 1 and its `-p` forwarder are
        // reachable ONLY through the recorded cgroup. `reap_orphan` SIGKILLs that whole cgroup at once
        // (`cgroup.kill`), which frees the host port the forwarder was holding, and drops the record.
        // Without this branch `kern stop <name>` answered "no running box" while the port stayed bound.
        if b.orphaned {
            let reaped = registry::reap_orphan(b);
            registry::set_box_exit(b.pid, b.starttime, 137, &b.name, &b.pod, &b.command);
            registry::clear_health(&b.name, b.pid);
            cleanup_box_scratch(&b.rootfs);
            if reaped {
                println!(
                    "stopped '{}' (was orphaned; reaped via cgroup.kill)",
                    b.name
                );
            } else {
                failures.push(format!(
                    "'{}' was orphaned but its cgroup could not be reaped (already gone?)",
                    b.name
                ));
            }
            continue;
        }
        // A persistent box: tell systemd to stop AND disable the unit (so it neither restarts now
        // nor comes back at reboot), then remove it. Killing the process instead would just trip
        // systemd's `Restart=always`. Otherwise kill the box's PID-namespace init directly - see
        // `kill_box`; a bare `kill(-pid)` reaches only a detached, `setsid`-ed supervisor's group,
        // never a foreground box whose init isn't in that group.
        // Capture the box's exact direct-path cgroup dir NOW, while pid1 is still alive and a member of
        // it (`/proc/<pid1>/cgroup`). After the SIGKILL below the pid1 lingers as a zombie, so the general
        // orphan-sweep would skip the dir until it's reaped; we `rmdir` the (now-empty) dir ourselves right
        // after. No-op for a systemd-scope box (not a `kern-box-*` leaf → `None`). See `box_cgroup_dir`.
        let box_cgroup = (b.pid1 > 0)
            .then(|| kern_isolation::box_cgroup_dir(b.pid1))
            .flatten();
        // Recovery path for a box left FROZEN by a `commit` that died past its signal trap (SIGKILL / OOM
        // / panic=abort): thaw it before killing. SIGKILL is honoured on a frozen cgroup-v2 task anyway,
        // but thawing first guarantees prompt delivery and means a stuck-frozen box is never unrecoverable
        // without the user knowing about `cgroup.freeze`. Best-effort; a non-frozen box is unaffected.
        if let Some(cg) = &box_cgroup {
            let _ = std::fs::write(cg.join("cgroup.freeze"), "0");
        }
        let outcome = if stop_managed_unit(&b.name) {
            // systemd owns the lifecycle and has torn the unit down: gone, but its exit code went to
            // the journal, not to us, so it records like any teardown we did not observe.
            Teardown::Gone(None)
        } else {
            // Honour the shutdown contract the box was STARTED with: the registry carries it, so a
            // later `kern stop` (a different process) sends the same signal and waits the same grace.
            // An older entry (0/0) keeps the historical immediate SIGKILL.
            kill_box_graceful(
                b.pid,
                b.pid1,
                if b.stop_signal > 0 {
                    b.stop_signal
                } else {
                    libc::SIGTERM
                },
                // What is LEFT of this box's own grace, counted from the phase-1 signal.
                remaining_grace_ms(b.stop_grace, signalled_at.elapsed()),
            )
        };
        // A `stop` signals the supervisor's group, so the supervisor never records its own exit code.
        // We record it here - BEFORE removing the instance file - so `kern wait` on a stopped box
        // answers like Docker instead of "no exit code recorded". The code is the box's REAL one when
        // it shut itself down inside the grace: a workload that traps the signal and exits 0 has to
        // read as `exited (0)`, not as the SIGKILL we never sent it. See `Teardown`.
        registry::set_box_exit(
            b.pid,
            b.starttime,
            outcome.exit_code(),
            &b.name,
            &b.pod,
            &b.command,
        );
        let _ = std::fs::remove_file(dir.join(format!("{}-{}", b.name, b.pid)));
        registry::clear_health(&b.name, b.pid); // a SIGKILL skips the supervisor's own cleanup
        cleanup_box_scratch(&b.rootfs);
        if outcome.confirmed() {
            // Eagerly rmdir the box's now-empty cgroup dir (captured above) - the SIGKILL skipped the
            // supervisor's RAII guard, so it would otherwise linger until `gc`/the next box start. rmdir is
            // empty-only, so a (vanishingly unlikely) reused-pid live box is safe. Covers `compose down`
            // too - it tears the stack down via this same `stop`.
            //
            // EXCEPT a `.scope`: on the systemd-scope path the box's cgroup IS a transient unit, and
            // that dir belongs to systemd's bookkeeping, not to ours. `--collect` removes the unit
            // (and its cgroup) when its last process exits, so racing it here would win nothing and
            // could leave the manager tearing down a cgroup that is already gone.
            if let Some(cg) = &box_cgroup {
                let is_unit = cg
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".scope"));
                if !is_unit {
                    let _ = std::fs::remove_dir(cg);
                }
            }
            println!("stopped '{}' (pid {})", b.name, b.pid);
        } else {
            // Don't report success while alive: the SIGKILL went out but the box wasn't confirmed
            // gone within the grace window. Surface it honestly instead of printing `stopped`.
            failures.push(format!(
                "sent SIGKILL to '{}' (pid {}) but it did not exit in time",
                b.name, b.pid
            ));
        }
    }
    for n in &managed_only {
        stop_managed_unit(n);
        println!("stopped '{n}' (systemd-managed)");
    }
    // Stopping a pod means removing its "root" too (like Docker Desktop's stop-the-project): once every
    // member of a pod is stopped, tear the pod down - its holder process, network namespace and shared
    // hosts/resolv files. This fires whether the pod was named directly (`kern stop <pod>`), swept by
    // `--all`, or emptied by stopping its last member - matching `compose down`'s cleanup.
    let stopped_pods: std::collections::BTreeSet<&str> = targets
        .iter()
        .map(|b| b.pod.as_str())
        .filter(|p| !p.is_empty())
        .collect();
    // A pod survives iff some running member's pid ISN'T among the stopped targets. Compute the set of
    // surviving pods in ONE pass with a pid HashSet - the naive `for pod { running.any(!targets.any) }`
    // is O(pods·running·targets) (≈O(N³) on `stop --all` with many boxes); this is O(N).
    let target_pids: std::collections::HashSet<i32> = targets.iter().map(|b| b.pid).collect();
    let survivors: std::collections::HashSet<&str> = running
        .iter()
        .filter(|b| !b.pod.is_empty() && !target_pids.contains(&b.pid))
        .map(|b| b.pod.as_str())
        .collect();
    for pod in stopped_pods {
        if !survivors.contains(pod) {
            let (existed, _) = crate::pod::teardown(pod);
            if existed {
                println!("removed pod '{pod}'");
            }
        }
    }
    // Don't silently ignore refs that matched no running box (and no managed unit). A ref matched a
    // target by NAME, by its PID, or by its POD name (same rule as the selection above), so check all
    // three - else `kern stop <pid|pod>` acts AND then wrongly warns the ref "isn't a box".
    if !all {
        let live_names = live_name_set(&running);
        for n in names {
            let matched = targets.iter().any(|b| ref_matches(b, n, &live_names));
            if !matched && !managed_only.contains(n) {
                failures.push(format!("no running box '{n}'"));
            }
        }
    }
    if !failures.is_empty() {
        return Err(Error::Sandbox(format!(
            "could not stop: {}",
            failures.join("; ")
        )));
    }
    Ok(())
}

/// `kern pause <name>...` / `kern unpause <name>...` - freeze / thaw a running box via the cgroup v2
/// **freezer** (`cgroup.freeze`), which suspends every process in the box's cgroup atomically (no
/// signal races, and a paused box can't be woken by `SIGCONT` from inside). Needs the box to have a
/// dedicated cgroup (a `systemd --user` scope, the default when present); without one there's nothing
/// to freeze and we say so rather than pretend. `freeze=true` pauses, `false` resumes.
pub fn pause(names: &[String], all: bool, freeze: bool) -> Result<(), Error> {
    let verb = if freeze { "pause" } else { "unpause" };
    let running = registry::list();
    // Captured before `running` is consumed - the unmatched-ref report below needs the full live-name
    // set to apply the same NAME-wins rule as selection (a pod/pid ref must not be called "not a box").
    let live_names = live_name_set(&running);
    let targets: Vec<_> = if all {
        running
    } else {
        boxes_matching_refs(running, names)
    };
    if targets.is_empty() {
        return Err(Error::NotRunning(format!("no running box to {verb}")));
    }
    // A box that MATCHED but could not actually be (un)frozen - it has no dedicated cgroup (freeze is
    // a cgroup-v2 operation that needs a delegated scope), or the `cgroup.freeze` write errored - is a
    // real failure, not a success with a note on stderr. Collect the reasons (plus any named ref that
    // matched no live box) into ONE returned error so the command exits NON-ZERO (a scripted
    // `kern pause X && next` must not run `next` when the freeze never happened) AND the message is
    // self-contained: the `kern top` TUI reuses this fn with stdout/stderr muted, so a "see above"
    // pointer would dangle - the reason must travel IN the error, which the TUI shows in its overlay.
    // Successes still stream to stdout so an `--all` reports each box as it goes.
    let mut failures: Vec<String> = Vec::new();
    for b in &targets {
        match registry::box_cgroup(b.cgroup_pid()) {
            Some(cg) => {
                let path = cg.join("cgroup.freeze");
                match std::fs::write(&path, if freeze { "1" } else { "0" }) {
                    Ok(()) => println!("{}d '{}' (pid {})", verb, b.name, b.pid),
                    Err(e) => failures.push(format!("'{}': {e}", b.name)),
                }
            }
            None => failures.push(format!(
                "'{}' has no dedicated cgroup (freeze needs a systemd --user scope)",
                b.name
            )),
        }
    }
    if !all {
        for n in names {
            // Same NAME-or-PID-or-POD rule as `stop`: a `kern pause <pod>` froze every member, so the
            // pod ref matched - don't then wrongly report it as "no running box".
            if !targets.iter().any(|b| ref_matches(b, n, &live_names)) {
                failures.push(format!("no running box named '{n}'"));
            }
        }
    }
    if !failures.is_empty() {
        return Err(Error::Sandbox(format!(
            "could not {verb}: {}",
            failures.join("; ")
        )));
    }
    Ok(())
}
